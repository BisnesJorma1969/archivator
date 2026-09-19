"""Directory-local input, bounded streams/groups, and protected local metadata."""

import json
import os
import shutil
import tarfile
from pathlib import Path
from itertools import chain

from .common import ArchiveError, BUFFER_SIZE, Hashes, WORK_DIR, sha256, write_json, write_jsonl
from .external import ZstdWriter, create_parity, encrypt, executable, normalize_certificate
from .filesystem import check_unchanged, directory_batches, empty_destination, ensure_disjoint, public_entry
from .format import Settings, chunk_name, metadata_prefix, new_id, parity_prefix
from .limits import ceil_div, check_files, input_limit, parity_plan, stored_bound
from .metadata import MetadataWriter, json_bytes, store_metadata
from .progress import progress


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


def with_parents(entries):
    result = {}
    for entry in entries:
        for parent in entry.get("_parents", []):
            result.setdefault(parent["path"], parent)
        result[entry["path"]] = entry
    return list(result.values())


def inventory_bound(entries, stream=None):
    # Digests are not known until reading the file. Reserve all five hex digests
    # and their JSON keys; JSON escaping of source paths is already included.
    return 1024 + len(json_bytes(stream)) + sum(
        len(json_bytes(public_entry(entry))) + 512 for entry in with_parents(entries))


class ParityWriter:
    """One stream at a time. Groups close on byte budgets, never member counts."""

    def __init__(self, archive, archive_id, settings, catalog, stream, entries,
                 certificate=None, encryption_overhead=0):
        self.archive = archive
        self.archive_id = archive_id
        self.settings = settings
        self.catalog = catalog
        self.stream = stream
        self.entries = entries
        self.certificate = certificate
        self.encryption_overhead = encryption_overhead
        self.staging = archive / ".tmp"
        self.parity_id = new_id()
        self.members = []
        self.input_bytes = input_limit(min(settings.max_file_bytes, settings.max_group_bytes // 4),
                                       encryption_overhead)

    def source_name(self):
        prefix = parity_prefix(self.archive_id, self.parity_id)
        role = f"inventory_stream-{self.stream['stream']}" if self.stream else "entries"
        return prefix + "_metadata_" + role + ".jsonl.zst" + (".cms" if self.certificate else "")

    def manifest(self, members, source_digest):
        return {"version": 1, "archive": self.archive_id, "parity": self.parity_id,
                "compression": "zstd", "encryption": "cms-aes-256-gcm" if self.certificate else "none",
                "settings": vars(self.settings), "members": members,
                "source_metadata": self.source_name(), "source_sha256": source_digest}

    def fits(self, members, private_size=None):
        settings = self.settings
        private_size = private_size or inventory_bound(self.entries, self.stream)
        source_length = stored_bound(private_size, self.encryption_overhead)
        manifest_bytes = json.dumps(self.manifest(members, "0" * 64), ensure_ascii=True, indent=2, sort_keys=True)
        manifest_length = stored_bound(len(manifest_bytes.encode("ascii")) + 1)
        lengths = {member["filename"]: member["stored_length"] for member in members}
        lengths[self.source_name()] = source_length
        prefix = parity_prefix(self.archive_id, self.parity_id)
        lengths[prefix + "_manifest.json.zst"] = manifest_length
        if max(lengths.values()) > settings.max_file_bytes:
            return False
        try:
            plan = parity_plan(lengths, settings.slice_size, settings.max_file_bytes)
            if sum(lengths.values()) + plan.total_bytes > settings.max_group_bytes:
                return False
            # The identical central copies need their own parity and a receipt.
            # Reserve a bounded hash map for this set and the previous set.
            receipt_size = 4096 + len(json_bytes(self.catalog.previous)) + (plan.volumes + 1) * 300
            central = {self.source_name(): source_length,
                       prefix + "_manifest.json.zst": manifest_length,
                       metadata_prefix(self.archive_id, self.parity_id) + "_checksums.json.zst": stored_bound(receipt_size)}
            for path in self.catalog.extra:
                role = "recipient.pem" if path.suffix == ".pem" else "format.txt"
                central[metadata_prefix(self.archive_id, self.parity_id) + "_" + role] = path.stat().st_size
            if max(central.values()) > settings.max_file_bytes:
                return False
            protection = parity_plan(central, settings.slice_size, settings.max_file_bytes)
            return sum(central.values()) + protection.total_bytes <= settings.max_group_bytes
        except ArchiveError:
            return False

    def candidate(self, size, number=0, offset=0, length=1):
        stream_id = self.stream["stream"] if self.stream else "0" * 32
        return {"filename": chunk_name(self.archive_id, self.parity_id, number, stream_id,
                                        offset, length, bool(self.certificate)),
                "chunk": number, "stream": stream_id, "offset": offset, "length": length,
                "stored_length": size, "stored_sha256": "0" * 64,
                "plaintext_sha256": "0" * 64, "plaintext_sha512": "0" * 128}

    def add(self, path, offset, length, hashes):
        candidate = self.candidate(path.stat().st_size, len(self.members), offset, length)
        if not self.fits(self.members + [candidate]):
            if self.stream["type"] == "tar":
                raise ArchiveError("TAR exceeded its precomputed group budget")
            self.finish_set()
            candidate = self.candidate(path.stat().st_size, 0, offset, length)
            if not self.fits([candidate]):
                raise ArchiveError("Byte limits cannot hold one data chunk with its metadata and parity")
        candidate.update(plaintext_sha256=hashes["sha256"], plaintext_sha512=hashes["sha512"],
                         stored_sha256=sha256(path))
        shard = self.archive / self.parity_id[:2]
        shard.mkdir(exist_ok=True)
        os.replace(path, shard / candidate["filename"])
        self.members.append(candidate)
        print(f"Stored chunk: {length:,} plaintext bytes -> {candidate['stored_length']:,} stored bytes", flush=True)

    def finish_set(self, allow_empty=False):
        if not self.members and not allow_empty:
            return
        shard = self.archive / self.parity_id[:2]
        shard.mkdir(exist_ok=True)
        prefix = parity_prefix(self.archive_id, self.parity_id)
        source_name = self.source_name().removesuffix(".cms").removesuffix(".zst")
        records = [{"stream": self.stream}] + [public_entry(entry) for entry in with_parents(self.entries)]
        write_jsonl(self.staging / source_name, records)
        stored = store_metadata(self.staging / source_name, self.staging, self.certificate)
        check_files([self.staging / stored], self.settings.max_file_bytes, self.settings.max_group_bytes)
        os.replace(self.staging / stored, shard / stored)
        manifest = self.manifest(self.members, sha256(shard / stored))
        manifest_name = prefix + "_manifest.json"
        write_json(self.staging / manifest_name, manifest)
        manifest_name = store_metadata(self.staging / manifest_name, self.staging)
        check_files([self.staging / manifest_name], self.settings.max_file_bytes, self.settings.max_group_bytes)
        os.replace(self.staging / manifest_name, shard / manifest_name)
        names = [member["filename"] for member in self.members] + [stored, manifest_name]
        lengths = {name: (shard / name).stat().st_size for name in names}
        plan = parity_plan(lengths, self.settings.slice_size, self.settings.max_file_bytes)
        if sum(lengths.values()) + plan.total_bytes > self.settings.max_group_bytes:
            raise ArchiveError("Group metadata and PAR2 exceed the byte budget")
        print(f"Protecting group {self.parity_id}: {len(self.members):,} chunks, "
              f"{sum(lengths.values()):,} stored bytes; {plan.blocks:,} PAR2 slices", flush=True)
        directory = self.staging / "parity"
        directory.mkdir()
        files = create_parity(shard, prefix, names, self.settings.slice_size, plan.blocks,
                              directory, plan.volumes)
        total = check_files([*(shard / name for name in names), *files],
                            self.settings.max_file_bytes, self.settings.max_group_bytes)
        parity_hashes = {}
        for path in files:
            parity_hashes[path.name] = sha256(path)
            os.replace(path, shard / path.name)
        directory.rmdir()
        self.catalog.add(self.parity_id, [shard / stored, shard / manifest_name], parity_hashes)
        print(f"Finished group: {total:,}/{self.settings.max_group_bytes:,} bytes including metadata and PAR2", flush=True)
        self.members = []
        self.parity_id = new_id()


class StreamWriter:
    """Independent zstd/CMS chunks with a conservative plaintext input ceiling."""

    def __init__(self, parity):
        self.parity = parity
        self.size = 0
        self.hashes = Hashes(lookup=True)
        self.chunk_hashes = Hashes()
        self.chunk_length = 0
        self.compressed = None

    def write(self, data):
        length = len(data)
        remaining = memoryview(data)
        while remaining:
            if self.compressed is None:
                self.compressed = ZstdWriter(self.parity.staging / "chunk.zst")
            count = min(len(remaining), self.parity.input_bytes - self.chunk_length)
            piece = remaining[:count]
            progress.update(f"Compressing stream: {self.size:,} plaintext bytes; "
                            f"current chunk {self.chunk_length:,}/{self.parity.input_bytes:,}")
            self.compressed.write(piece)
            self.hashes.update(piece)
            self.chunk_hashes.update(piece)
            self.chunk_length += count
            self.size += count
            remaining = remaining[count:]
            if self.chunk_length == self.parity.input_bytes:
                self.finish_chunk()
        return length

    def finish_chunk(self):
        if not self.chunk_length:
            return
        self.compressed.finish()
        self.compressed = None
        path = self.parity.staging / "chunk.zst"
        if self.parity.certificate:
            encrypted = self.parity.staging / "chunk.zst.cms"
            encrypt(path, encrypted, self.parity.certificate)
            path.unlink()
            path = encrypted
        check_files([path], self.parity.settings.max_file_bytes, self.parity.settings.max_group_bytes)
        self.parity.add(path, self.size - self.chunk_length, self.chunk_length, self.chunk_hashes.values())
        self.chunk_length = 0
        self.chunk_hashes = Hashes()

    def close(self):
        if self.compressed:
            self.compressed.close()


class HashingReader:
    def __init__(self, source):
        self.source = source
        self.hashes = Hashes(lookup=True)

    def read(self, count):
        data = self.source.read(count)
        self.hashes.update(data)
        return data


def tar_bytes(entries):
    total = 1024  # End-of-archive records, then tarfile's 10 KiB record padding.
    for entry in with_parents(entries):
        total += len(tar_info(entry).tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape"))
        total += ceil_div(entry.get("size", 0), 512) * 512
    return ceil_div(total, tarfile.RECORDSIZE) * tarfile.RECORDSIZE


def write_tar(source, entries, sink):
    inventory = []
    entries = with_parents(entries)
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as output:
        for index, entry in enumerate(entries, 1):
            progress.update(f"Packing TAR entry {index:,}/{len(entries):,}: {entry['path']!r}")
            path = source / entry["path"]
            if "_identity" in entry:
                check_unchanged(path, entry)
            record = public_entry(entry)
            if entry["type"] == "file":
                with path.open("rb") as original:
                    reader = HashingReader(original)
                    output.addfile(tar_info(entry), reader)
                    record.update(reader.hashes.values())
            else:
                output.addfile(tar_info(entry))
            if "_identity" in entry:
                check_unchanged(path, entry)
            inventory.append(record)
    return inventory


def backup(source, archive, certificate=None, settings=None):
    settings = settings or Settings()
    source, archive = Path(source).absolute(), Path(archive).absolute()
    ensure_disjoint(source, archive)
    if WORK_DIR.resolve().is_relative_to(source.resolve()):
        raise ArchiveError("Source must not contain the PoC work directory")
    executable("par2")
    executable("zstd")
    batches = directory_batches(source)
    first_batch = next(batches)  # Validate the root directory before creating output.
    empty_destination(archive)
    staging = archive / ".tmp"
    staging.mkdir(mode=0o700)
    archive_id = new_id()
    catalog = MetadataWriter(archive, archive_id, settings)
    overhead = 0
    fingerprint = None
    try:
        if certificate:
            normalized = staging / f"archive-{archive_id}_metadata_recipient.pem"
            fingerprint = normalize_certificate(Path(certificate).absolute(), normalized)
            certificate = normalized
            catalog.extra.append(normalized)
            # Measure this certificate's CMS wrapper, allowing DER length fields
            # to grow. This also handles unusually long certificate issuer names.
            probe = staging / "probe"
            probe.write_bytes(b"")
            probe.chmod(0o600)
            encrypt(probe, staging / "probe.cms", certificate)
            overhead = (staging / "probe.cms").stat().st_size + 64
            probe.unlink()
            (staging / "probe.cms").unlink()
        format_path = staging / f"archive-{archive_id}_metadata_format.txt"
        format_path.write_text("format=archivator\nversion=1\ncompression=zstd\n"
                               "parity=par2-v2\n" + "\n".join(f"{k}={v}" for k, v in vars(settings).items()) + "\n")
        if fingerprint:
            with format_path.open("a") as output:
                output.write(f"recipient-sha256={fingerprint}\n")
        catalog.extra.append(format_path)

        def writer(stream, entries):
            return ParityWriter(archive, archive_id, settings, catalog, stream, entries, certificate, overhead)

        def direct(entry, accompanying=()):
            print(f"Archiving file: {entry['path']!r} ({entry['size']:,} bytes)", flush=True)
            stream = {**public_entry(entry), "stream": new_id()}
            group = writer(stream, list(accompanying) + [entry])
            sink = StreamWriter(group)
            check_unchanged(source / entry["path"], entry)
            try:
                with (source / entry["path"]).open("rb") as original:
                    while data := original.read(BUFFER_SIZE):
                        sink.write(data)
                check_unchanged(source / entry["path"], entry)
                sink.finish_chunk()
                stream.update(sink.hashes.values())
                # A final metadata-only group carries the full hash if an exact
                # chunk boundary already closed the preceding data group.
                group.finish_set(allow_empty=True)
            finally:
                sink.close()

        def flush(entries):
            if not entries:
                return
            files = [entry for entry in entries if entry["type"] == "file"]
            others = [entry for entry in entries if entry["type"] != "file"]
            if len(files) == 1:
                direct(files[0], others)
            elif not files:
                group = writer(None, entries)
                if not group.fits([]):
                    raise ArchiveError("Source metadata cannot fit the configured byte limits")
                for entry in entries:
                    check_unchanged(source / entry["path"], entry)
                group.finish_set(allow_empty=True)
            else:
                print(f"Packing TAR stream: {len(files):,} files", flush=True)
                stream = {"stream": new_id(), "type": "tar", "size": tar_bytes(entries)}
                group = writer(stream, entries)
                sink = StreamWriter(group)
                try:
                    inventory = write_tar(source, entries, sink)
                    sink.finish_chunk()
                    stream.update(size=sink.size, **sink.hashes.values())
                    group.entries = inventory
                    group.finish_set()
                finally:
                    sink.close()

        pending = []
        pending_paths = set()
        pending_tar_bytes = 0
        pending_inventory_bytes = 1024
        planner = writer({"stream": "0" * 32, "type": "tar"}, [])

        def append_if_fits(entry):
            nonlocal pending_tar_bytes, pending_inventory_bytes
            additions = [item for item in with_parents([entry]) if item["path"] not in pending_paths]
            tar_growth = sum(len(tar_info(item).tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape"))
                             + ceil_div(item.get("size", 0), 512) * 512 for item in additions)
            inventory_growth = sum(len(json_bytes(public_entry(item))) + 512 for item in additions)
            size = ceil_div(pending_tar_bytes + tar_growth + 1024, tarfile.RECORDSIZE) * tarfile.RECORDSIZE
            chunks = []
            for offset in range(0, size, planner.input_bytes):
                length = min(planner.input_bytes, size - offset)
                chunks.append(planner.candidate(stored_bound(length, overhead), len(chunks), offset, length))
                if len(chunks) > 32768:
                    return False
            if not planner.fits(chunks, pending_inventory_bytes + inventory_growth):
                return False
            pending.append(entry)
            pending_paths.update(item["path"] for item in additions)
            pending_tar_bytes += tar_growth
            pending_inventory_bytes += inventory_growth
            return True

        threshold = input_limit(min(settings.max_file_bytes, settings.max_group_bytes // 4), overhead)
        for directory, children in chain([first_batch], batches):
            # A TAR remains open across directory boundaries. Look ahead through
            # this directory only, taking the first candidate that fits.
            candidates = [directory] + [entry for entry in children if entry["type"] != "directory"]
            while candidates:
                chosen = None
                for index, entry in enumerate(candidates):
                    if entry["type"] == "file" and entry["size"] >= threshold:
                        direct(entry)
                        chosen = index
                        break
                    if append_if_fits(entry):
                        chosen = index
                        break
                if chosen is not None:
                    candidates.pop(chosen)
                elif pending:
                    flush(pending)
                    pending = []
                    pending_paths.clear()
                    pending_tar_bytes = 0
                    pending_inventory_bytes = 1024
                else:
                    entry = candidates.pop(0)
                    if entry["type"] == "file":
                        direct(entry)
                    else:
                        flush([entry])
        flush(pending)
        catalog.finish()
    finally:
        progress.update("Removing backup temporary files")
        shutil.rmtree(staging)
    return archive_id
