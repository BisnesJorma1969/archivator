"""Build streams, transform independent chunks, and publish a complete archive."""

import os
import shutil
import tarfile
from pathlib import Path

from .common import ArchiveError, BUFFER_SIZE, Hashes, WORK_DIR, sha256, write_json, write_jsonl
from .external import ZstdWriter, create_parity, encrypt, executable, normalize_certificate
from .filesystem import check_unchanged, empty_destination, ensure_disjoint, public_entry, scan
from .format import Settings, chunk_name, new_id, parity_prefix, recovery_blocks
from .metadata import completion_digest, completion_names, store_metadata
from .progress import progress


class ParityWriter:
    """Collect completed chunks until a data parity set is full."""

    def __init__(self, archive, archive_id, settings):
        self.archive = archive
        self.archive_id = archive_id
        self.settings = settings
        self.staging = archive / ".tmp"
        self.parity_id = new_id()
        self.members = []
        self.manifests = []
        self.parity_files = []

    def publish(self, path):
        os.replace(path, self.archive / path.name)

    def add(self, path, stream, offset, length, hashes, encrypted):
        name = chunk_name(self.archive_id, self.parity_id, len(self.members),
                          stream, offset, length, encrypted)
        member = {
            "filename": name, "chunk": len(self.members), "stream": stream,
            "offset": offset, "length": length, "stored_length": path.stat().st_size,
            "plaintext_sha256": hashes["sha256"], "plaintext_sha512": hashes["sha512"],
            "stored_sha256": sha256(path),
        }
        os.replace(path, self.archive / name)
        self.members.append(member)
        print(f"Stored chunk: {length:,} plaintext bytes -> {member['stored_length']:,} stored bytes", flush=True)
        if len(self.members) == self.settings.parity_members:
            self.finish_set()

    def finish_set(self):
        if not self.members:
            return
        prefix = parity_prefix(self.archive_id, self.parity_id)
        blocks = recovery_blocks([member["stored_length"] for member in self.members],
                                 self.settings.slice_size)
        # Only this set is visible to PAR2. Staging may be removed after failure;
        # already-published data remains identifiable but is not marked complete.
        directory = self.staging / "parity"
        directory.mkdir()
        for index, member in enumerate(self.members, 1):
            progress.update(f"Staging data for PAR2: chunk {index}/{len(self.members)}")
            shutil.copyfile(self.archive / member["filename"], directory / member["filename"])
        files = create_parity(directory, prefix, [member["filename"] for member in self.members],
                              self.settings.slice_size, blocks)
        for path in files:
            self.parity_files.append(path.name)
            self.publish(path)
        shutil.rmtree(directory)
        manifest = {
            "version": 1, "archive": self.archive_id, "parity": self.parity_id,
            "slice_size": self.settings.slice_size, "recovery_blocks": blocks,
            "recovery_bytes": blocks * self.settings.slice_size,
            "member_count": len(self.members), "members": self.members,
        }
        path = self.staging / (prefix + "_manifest.json")
        write_json(path, manifest)
        self.manifests.append(path.name)
        self.publish(path)
        self.members = []
        self.parity_id = new_id()


class StreamWriter:
    """A file-like sink shared by direct-file reads and tarfile's streaming writer."""

    def __init__(self, parity, stream, certificate):
        self.parity = parity
        self.stream = stream
        self.certificate = certificate
        self.size = 0
        self.hashes = Hashes()
        self.chunk_hashes = Hashes()
        self.chunk_length = 0
        self.compressed = None

    def write(self, data):
        length = len(data)
        remaining = memoryview(data)
        while remaining:
            if self.compressed is None:
                self.compressed = ZstdWriter(self.parity.staging / "chunk.zst")
            count = min(len(remaining), self.parity.settings.chunk_size - self.chunk_length)
            piece = remaining[:count]
            progress.update(f"Compressing stream: {self.size:,} plaintext bytes read; "
                            f"current chunk {self.chunk_length:,}/{self.parity.settings.chunk_size:,} bytes")
            self.compressed.write(piece)
            self.hashes.update(piece)
            self.chunk_hashes.update(piece)
            self.chunk_length += count
            self.size += count
            remaining = remaining[count:]
            if self.chunk_length == self.parity.settings.chunk_size:
                self.finish_chunk()
        return length

    def finish_chunk(self):
        if not self.chunk_length:
            return
        self.compressed.finish()
        self.compressed = None
        path = self.parity.staging / "chunk.zst"
        if self.certificate:
            encrypted = self.parity.staging / "chunk.zst.cms"
            encrypt(path, encrypted, self.certificate)
            path.unlink()
            path = encrypted
        self.parity.add(path, self.stream, self.size - self.chunk_length, self.chunk_length,
                        self.chunk_hashes.values(), bool(self.certificate))
        self.chunk_length = 0
        self.chunk_hashes = Hashes()

    def close(self):
        # Cleanup does not publish a partial chunk when a source read failed.
        if self.compressed:
            self.compressed.close()


class HashingReader:
    """tarfile reads through this wrapper so original-file hashes need no second pass."""

    def __init__(self, source):
        self.source = source
        self.hashes = Hashes(lookup=True)

    def read(self, count):
        data = self.source.read(count)
        self.hashes.update(data)
        return data


def tar_info(entry):
    info = tarfile.TarInfo(entry["path"])
    info.mode = entry["mode"]
    seconds, nanoseconds = divmod(abs(entry["mtime_ns"]), 1000000000)
    sign = "-" if entry["mtime_ns"] < 0 else ""
    info.mtime = entry["mtime_ns"] // 1000000000
    info.pax_headers = {"mtime": f"{sign}{seconds}.{nanoseconds:09d}"}
    if entry["type"] == "directory":
        info.type = tarfile.DIRTYPE
    elif entry["type"] == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = entry["symlink_target"]
    else:
        info.size = entry["size"]
    return info


def bundles(entries, settings):
    pending = []
    size = 0
    for entry in entries:
        if entry["type"] == "file" and entry["size"] >= settings.large_file_size:
            continue
        entry_size = entry.get("size", 0)
        if pending and (size + entry_size > settings.tar_size or len(pending) >= settings.tar_entries):
            yield pending
            pending, size = [], 0
        pending.append(entry)
        size += entry_size
    if pending:
        yield pending


def write_tar(source, entries, sink):
    inventory = []
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as output:
        for index, entry in enumerate(entries, 1):
            progress.update(f"Packing TAR entry {index:,}/{len(entries):,}: {entry['path']!r}")
            path = source / entry["path"]
            check_unchanged(path, entry)
            record = public_entry(entry)
            if entry["type"] == "file":
                with path.open("rb") as original:
                    reader = HashingReader(original)
                    output.addfile(tar_info(entry), reader)
                    record.update(reader.hashes.values())
            else:
                output.addfile(tar_info(entry))
            check_unchanged(path, entry)
            inventory.append(record)
    return inventory


def finalize_metadata(archive, archive_id, metadata_names, parity_files, slice_size,
                      parity_checksums=None, metadata_id=None):
    staging = archive / ".tmp"
    metadata_names = [store_metadata(archive / name) for name in metadata_names]
    index_name = f"archive-{archive_id}_checksums.json"
    checksums = {name: sha256(archive / name) for name in sorted(metadata_names + parity_files)}
    if parity_checksums:
        checksums.update(parity_checksums)
    write_json(staging / index_name, checksums)
    os.replace(staging / index_name, archive / index_name)
    index_name = store_metadata(archive / index_name)
    metadata_names = sorted(metadata_names + [index_name])
    metadata_id = metadata_id or new_id()
    prefix = parity_prefix(archive_id, metadata_id, metadata=True)
    directory = staging / "metadata"
    directory.mkdir()
    for index, name in enumerate(metadata_names, 1):
        progress.update(f"Staging metadata for PAR2: file {index}/{len(metadata_names)}")
        shutil.copyfile(archive / name, directory / name)
    blocks = recovery_blocks([(directory / name).stat().st_size for name in metadata_names], slice_size)
    files = create_parity(directory, prefix, metadata_names, slice_size, blocks)
    parity_hashes = {}
    for path in files:
        parity_hashes[path.name] = sha256(path)
        os.replace(path, archive / path.name)
    shutil.rmtree(directory)
    complete = {
        "version": 1, "archive": archive_id,
        "checksum_index": index_name, "checksum_index_sha256": sha256(archive / index_name),
        "metadata_prefix": prefix, "metadata_members": metadata_names,
        "metadata_slice_size": slice_size, "metadata_recovery_blocks": blocks,
        "metadata_parity": parity_hashes,
    }
    complete["marker_sha256"] = completion_digest(complete)
    # Both small bootstrap copies stay readable without a decompressor. Publish
    # them only after all protected metadata and recovery files are in place.
    for complete_name in completion_names(archive_id):
        write_json(staging / complete_name, complete)
        os.replace(staging / complete_name, archive / complete_name)


def backup(source, archive, certificate=None, settings=None):
    settings = settings or Settings()
    source, archive = Path(source).absolute(), Path(archive).absolute()
    ensure_disjoint(source, archive)
    if WORK_DIR.resolve().is_relative_to(source.resolve()):
        raise ArchiveError("Source must not contain the PoC work directory")
    executable("par2")
    executable("zstd")
    if certificate:
        certificate = Path(certificate).absolute()
        executable("openssl")
    entries = scan(source)
    files = [entry for entry in entries if entry["type"] == "file"]
    print(f"Source: {len(files):,} files, {sum(entry['size'] for entry in files):,} bytes", flush=True)
    empty_destination(archive)
    staging = archive / ".tmp"
    staging.mkdir()
    archive_id = new_id()
    parity = ParityWriter(archive, archive_id, settings)
    metadata = []
    streams = []
    try:
        fingerprint = None
        if certificate:
            name = f"archive-{archive_id}_recipient.pem"
            fingerprint = normalize_certificate(certificate, staging / name)
            parity.publish(staging / name)
            certificate = archive / name
            metadata.append(name)

        for group in bundles(entries, settings):
            print(f"Packing TAR stream: {len(group):,} entries", flush=True)
            stream_id = new_id()
            sink = StreamWriter(parity, stream_id, certificate)
            try:
                inventory = write_tar(source, group, sink)
                sink.finish_chunk()
            finally:
                sink.close()
            name = f"archive-{archive_id}_stream-{stream_id}_files.jsonl"
            write_jsonl(staging / name, inventory)
            parity.publish(staging / name)
            metadata.append(name)
            streams.append({"stream": stream_id, "type": "tar", "inventory": name,
                            "entry_count": len(inventory), "size": sink.size, **sink.hashes.values()})

        for entry in entries:
            if entry["type"] != "file" or entry["size"] < settings.large_file_size:
                continue
            path = source / entry["path"]
            print(f"Archiving large file: {entry['path']!r} ({entry['size']:,} bytes)", flush=True)
            check_unchanged(path, entry)
            stream_id = new_id()
            sink = StreamWriter(parity, stream_id, certificate)
            try:
                with path.open("rb") as original:
                    while data := original.read(BUFFER_SIZE):
                        sink.write(data)
                check_unchanged(path, entry)
                sink.finish_chunk()
            finally:
                sink.close()
            streams.append({**public_entry(entry), "stream": stream_id, **sink.hashes.values()})

        parity.finish_set()
        for index, entry in enumerate(entries, 1):
            progress.update(f"Checking source remained unchanged: {index:,}/{len(entries):,} entries")
            check_unchanged(source / entry["path"], entry)
        catalog_name = f"archive-{archive_id}_streams.jsonl"
        write_jsonl(staging / catalog_name, streams)
        parity.publish(staging / catalog_name)
        format_name = f"archive-{archive_id}_format.txt"
        fields = {
            "format": "archivator", "version": "1", "archive": archive_id,
            "compression": "zstd", "encryption": "cms-aes-256-gcm" if certificate else "none",
            "chunk-size": settings.chunk_size, "parity": "par2-v2",
            "parity-data-members": settings.parity_members, "parity-slice-size": settings.slice_size,
        }
        if fingerprint:
            fields["recipient-sha256"] = fingerprint
        with open(staging / format_name, "w", encoding="ascii", newline="\n") as output:
            for key, value in fields.items():
                output.write(f"{key}={value}\n")
        parity.publish(staging / format_name)
        metadata.extend([catalog_name, format_name, *parity.manifests])
        finalize_metadata(archive, archive_id, metadata, parity.parity_files, settings.slice_size)
    finally:
        progress.update("Removing backup temporary files")
        shutil.rmtree(staging)
    return archive_id
