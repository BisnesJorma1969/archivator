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


def inventory_bound(sources):
    # Reserve digests even before reading a file. The bound must stay unchanged
    # when a completed stream receives its real digests in an open group.
    digests = {"crc32", "md5", "sha1", "sha256", "sha512"}
    total = 1024
    for stream, entries in sources.values():
        for record in [stream or {}] + with_parents(entries):
            unsigned = {key: value for key, value in record.items()
                        if not key.startswith("_") and key not in digests}
            total += len(json_bytes(unsigned)) + 600
    return total


class ParityWriter:
    """One bounded recovery group; placement and lifetime belong to GroupQueue."""

    def __init__(self, archive, archive_id, settings, catalog,
                 certificate=None, encryption_overhead=0):
        self.archive = archive
        self.archive_id = archive_id
        self.settings = settings
        self.catalog = catalog
        self.sources = {}
        self.certificate = certificate
        self.encryption_overhead = encryption_overhead
        self.staging = archive / ".tmp"
        self.parity_id = new_id()
        self.members = []
        self.input_bytes = input_limit(min(settings.max_file_bytes, settings.max_group_bytes // 4),
                                       encryption_overhead, settings.compression)

    def source_name(self):
        prefix = parity_prefix(self.archive_id, self.parity_id)
        name = prefix + "_metadata_index-files.jsonl"
        if self.settings.compression:
            name += ".zst"
        return name + ".cms" if self.certificate else name

    def manifest(self, members, source_digest):
        return {"version": 1, "archive": self.archive_id, "parity": self.parity_id,
                "compression": "zstd" if self.settings.compression else "none",
                "encryption": "cms-aes-256-gcm" if self.certificate else "none",
                "settings": vars(self.settings),
                "members": members,
                "source_metadata": self.source_name(), "source_sha256": source_digest}

    def fits(self, members, sources, private_size=None):
        return self.budget(members, sources, private_size) is not None

    def budget(self, members, sources, private_size=None):
        """Stored data plus conservative metadata/PAR2 bytes, or no feasible fit."""
        settings = self.settings
        private_size = private_size or inventory_bound(sources)
        source_length = stored_bound(private_size, self.encryption_overhead, settings.compression)
        manifest_bytes = json.dumps(self.manifest(members, "0" * 64), ensure_ascii=True, indent=2, sort_keys=True)
        manifest_length = stored_bound(len(manifest_bytes.encode("ascii")) + 1, compression=settings.compression)
        lengths = {member["filename"]: member["stored_length"] for member in members}
        lengths[self.source_name()] = source_length
        prefix = parity_prefix(self.archive_id, self.parity_id)
        suffix = ".zst" if settings.compression else ""
        lengths[prefix + "_metadata_index-chunks.json" + suffix] = manifest_length
        if max(lengths.values()) > settings.max_file_bytes:
            return None
        try:
            plan = parity_plan(lengths, settings.slice_size, settings.max_file_bytes, settings.par2)
            total = sum(lengths.values()) + plan.total_bytes
            if total > settings.max_group_bytes:
                return None
            # The identical central copies need their own parity and a receipt.
            # Reserve a bounded hash map for this set and the previous set.
            receipt_size = 4096 + len(json_bytes(self.catalog.previous)) + (plan.volumes + 1) * 300
            receipt_name = metadata_prefix(self.archive_id, self.parity_id) + "_checksums.json" + suffix
            central = {self.source_name(): source_length,
                       prefix + "_metadata_index-chunks.json" + suffix: manifest_length,
                       receipt_name: stored_bound(receipt_size, compression=settings.compression)}
            for path in self.catalog.extra:
                role = "recipient.pem" if path.suffix == ".pem" else "format.txt"
                central[metadata_prefix(self.archive_id, self.parity_id) + "_" + role] = path.stat().st_size
            if max(central.values()) > settings.max_file_bytes:
                return None
            protection = parity_plan(central, settings.slice_size, settings.max_file_bytes, settings.par2)
            if sum(central.values()) + protection.total_bytes > settings.max_group_bytes:
                return None
            return total
        except ArchiveError:
            return None

    def candidate(self, stream, size, number=0, offset=0, length=1):
        stream_id = stream["stream"]
        kind = "tar" if stream["type"] == "tar" else "raw"
        return {"filename": chunk_name(self.archive_id, self.parity_id, number, stream_id,
                                        offset, length, bool(self.certificate), kind, self.settings.compression),
                "chunk": number, "stream": stream_id, "kind": kind, "offset": offset, "length": length,
                "stored_length": size, "stored_sha256": "0" * 64,
                "plaintext_sha256": "0" * 64, "plaintext_sha512": "0" * 128}

    def proposed(self, chunks, stream, entries):
        key = stream["stream"] if stream else None
        if key is None and key in self.sources:
            entries = self.sources[key][1] + entries
        sources = {**self.sources, key: (stream, entries)}
        members = list(self.members)
        for chunk in chunks:
            member = self.candidate(stream, chunk["stored_length"], len(members),
                                    chunk["offset"], chunk["length"])
            member.update(stored_sha256=chunk["stored_sha256"],
                          plaintext_sha256=chunk["plaintext_sha256"],
                          plaintext_sha512=chunk["plaintext_sha512"])
            members.append(member)
        return members, sources

    def can_add(self, chunks, stream, entries):
        members, sources = self.proposed(chunks, stream, entries)
        return self.fits(members, sources)

    def append(self, chunks, stream, entries):
        members, sources = self.proposed(chunks, stream, entries)
        if not self.fits(members, sources):
            raise ArchiveError("Group cannot hold the selected content with metadata and parity")
        shard = self.archive / self.parity_id[:2]
        if chunks:
            shard.mkdir(exist_ok=True)
        for chunk, member in zip(chunks, members[len(self.members):]):
            os.replace(chunk["path"], shard / member["filename"])
            print(f"Stored chunk: {member['length']:,} plaintext bytes -> "
                  f"{member['stored_length']:,} stored bytes; group {self.parity_id}", flush=True)
        self.members = members
        self.sources = sources

    def finish_set(self):
        if not self.sources:
            return
        shard = self.archive / self.parity_id[:2]
        shard.mkdir(exist_ok=True)
        prefix = parity_prefix(self.archive_id, self.parity_id)
        source_name = self.source_name().removesuffix(".cms").removesuffix(".zst")

        def records():
            yield {"streams": [stream for stream, _ in self.sources.values() if stream is not None]}
            for stream_id, (_, entries) in self.sources.items():
                for entry in with_parents(entries):
                    yield {"stream": stream_id, "entry": public_entry(entry)}

        write_jsonl(self.staging / source_name, records())
        stored = store_metadata(self.staging / source_name, self.staging, self.certificate, self.settings.compression)
        check_files([self.staging / stored], self.settings.max_file_bytes, self.settings.max_group_bytes)
        os.replace(self.staging / stored, shard / stored)
        manifest = self.manifest(self.members, sha256(shard / stored))
        manifest_name = prefix + "_metadata_index-chunks.json"
        write_json(self.staging / manifest_name, manifest)
        manifest_name = store_metadata(self.staging / manifest_name, self.staging, compression=self.settings.compression)
        check_files([self.staging / manifest_name], self.settings.max_file_bytes, self.settings.max_group_bytes)
        os.replace(self.staging / manifest_name, shard / manifest_name)
        names = [member["filename"] for member in self.members] + [stored, manifest_name]
        lengths = {name: (shard / name).stat().st_size for name in names}
        plan = parity_plan(lengths, self.settings.slice_size, self.settings.max_file_bytes, self.settings.par2)
        if sum(lengths.values()) + plan.total_bytes > self.settings.max_group_bytes:
            raise ArchiveError("Group metadata and PAR2 exceed the byte budget")
        protection = f"{plan.blocks:,} PAR2 slices" if self.settings.par2 else "PAR2 disabled"
        print(f"Finalizing group {self.parity_id}: {len(self.members):,} chunks, "
              f"{sum(lengths.values()):,} stored bytes; {protection}", flush=True)
        directory = self.staging / "parity"
        directory.mkdir()
        files = []
        if self.settings.par2:
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
        print(f"Finished group: {total:,}/{self.settings.max_group_bytes:,} bytes including metadata and enabled parity", flush=True)
        self.members = []
        self.sources = {}


class GroupQueue:
    """One active group and a bounded, oldest-first list of waiting groups."""

    def __init__(self, make_group):
        self.make_group = make_group
        self.planner = make_group()  # Empty-group feasibility, never published.
        self.settings = self.planner.settings
        self.active = None
        self.waiting = []

    def used_bytes(self, group):
        budget = group.budget(group.members, group.sources)
        # A changed central receipt reservation can also prevent further additions.
        return self.settings.max_group_bytes if budget is None else budget

    def close_on_miss(self, group):
        return self.used_bytes(group) * 100 >= self.settings.max_group_bytes * self.settings.group_close_percent

    def retire_active(self):
        if self.active is None:
            return
        group = self.active
        self.active = None
        if self.close_on_miss(group):
            group.finish_set()
            return
        self.waiting.append(group)
        if len(self.waiting) > self.settings.waiting_groups:
            # max() keeps the first (oldest) group when byte budgets tie.
            fullest = max(self.waiting, key=self.used_bytes)
            self.waiting.remove(fullest)
            fullest.finish_set()
        print(f"Group queue: {len(self.waiting)}/{self.settings.waiting_groups} waiting", flush=True)

    def place(self, chunks, stream, entries):
        """Admit an entire RAW file, one complete TAR, or metadata-only entries."""
        for group in list(self.waiting):
            if group.can_add(chunks, stream, entries):
                group.append(chunks, stream, entries)
                return
            if self.close_on_miss(group):
                self.waiting.remove(group)
                group.finish_set()
        if self.active is not None and self.active.can_add(chunks, stream, entries):
            self.active.append(chunks, stream, entries)
            return
        self.retire_active()
        self.active = self.make_group()
        self.active.append(chunks, stream, entries)

    def start_large_file(self):
        # The file has exceeded an EMPTY group's budget, not merely the space
        # left in a populated group. Its first fragment must start fresh.
        for group in list(self.waiting):
            if self.close_on_miss(group):
                self.waiting.remove(group)
                group.finish_set()
        self.retire_active()
        self.active = self.make_group()

    def append_fragment(self, chunk, stream, entries):
        if not self.active.can_add([chunk], stream, entries):
            self.active.finish_set()
            self.active = self.make_group()
        self.active.append([chunk], stream, entries)
        # The final group stays active when the file ends; subsequent whole
        # files/TARs may fill its remainder. Intermediate groups never wait.

    def finish(self):
        for group in self.waiting:
            group.finish_set()
        self.waiting.clear()
        if self.active is not None:
            self.active.finish_set()
            self.active = None


class StreamWriter:
    """Independent zstd/CMS chunks with a conservative plaintext input ceiling."""

    def __init__(self, queue, stream, entries):
        self.queue = queue
        self.parity = queue.planner
        self.chunks = []
        self.spanning = False
        self.stream = stream
        self.entries = entries
        self.size = 0
        self.hashes = Hashes(lookup=True)
        self.chunk_hashes = Hashes()
        self.chunk_length = 0
        self.chunk_output = None
        self.tar_entry = 0
        self.tar_entries = 0

    def report_progress(self):
        kind = "TAR" if self.stream["type"] == "tar" else "RAW"
        entries = f"entry {self.tar_entry:,}/{self.tar_entries:,}; " if kind == "TAR" else ""
        progress.update(
            f"Encoding {kind} {self.stream['stream'][:8]}: {entries}"
            f"{self.size:,}/{self.stream['size']:,} plaintext bytes; "
            f"chunk {self.chunk_length:,}/{self.parity.input_bytes:,} bytes")

    def write(self, data):
        length = len(data)
        if self.stream["type"] == "tar" and self.size + length > self.parity.input_bytes:
            raise ArchiveError("A complete TAR must fit in one independent chunk")
        remaining = memoryview(data)
        while remaining:
            if self.chunk_output is None:
                path = self.parity.staging / "chunk"
                if self.parity.settings.compression:
                    self.chunk_output = ZstdWriter(path)
                else:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    self.chunk_output = os.fdopen(descriptor, "wb")
            count = min(len(remaining), self.parity.input_bytes - self.chunk_length)
            piece = remaining[:count]
            self.chunk_output.write(piece)
            self.hashes.update(piece)
            self.chunk_hashes.update(piece)
            self.chunk_length += count
            self.size += count
            self.report_progress()
            remaining = remaining[count:]
            if self.chunk_length == self.parity.input_bytes and self.stream["type"] != "tar":
                self.finish_chunk()
        return length

    def finish_chunk(self):
        if not self.chunk_length:
            return
        if self.parity.settings.compression:
            self.chunk_output.finish()
        else:
            self.chunk_output.close()
        self.chunk_output = None
        path = self.parity.staging / "chunk"
        if self.parity.certificate:
            encrypted = self.parity.staging / "chunk.cms"
            encrypt(path, encrypted, self.parity.certificate)
            path.unlink()
            path = encrypted
        check_files([path], self.parity.settings.max_file_bytes, self.parity.settings.max_group_bytes)
        offset = self.size - self.chunk_length
        staged = self.parity.staging / f"buffer-{self.stream['stream']}-{offset}"
        if self.parity.certificate:
            staged = staged.with_name(staged.name + ".cms")
        os.replace(path, staged)
        hashes = self.chunk_hashes.values()
        chunk = {"path": staged, "offset": offset, "length": self.chunk_length,
                 "stored_length": staged.stat().st_size, "stored_sha256": sha256(staged),
                 "plaintext_sha256": hashes["sha256"], "plaintext_sha512": hashes["sha512"]}
        if self.spanning:
            self.queue.append_fragment(chunk, self.stream, self.entries)
        else:
            self.chunks.append(chunk)
            if not self.parity.can_add(self.chunks, self.stream, self.entries):
                if self.stream["type"] == "tar":
                    raise ArchiveError("A complete TAR and its metadata cannot fit an empty group")
                self.spanning = True
                self.queue.start_large_file()
                for pending in self.chunks:
                    self.queue.append_fragment(pending, self.stream, self.entries)
                self.chunks.clear()
            else:
                progress.update(f"Buffered stream {self.stream['stream']}: {len(self.chunks):,} stored chunks")
        self.chunk_length = 0
        self.chunk_hashes = Hashes()

    def finish(self):
        self.stream.update(self.hashes.values())
        self.finish_chunk()
        if not self.spanning:
            self.queue.place(self.chunks, self.stream, self.entries)
            self.chunks.clear()

    def close(self):
        if self.chunk_output:
            self.chunk_output.close()


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
    sink.tar_entries = len(entries)
    with tarfile.open(fileobj=sink, mode="w|", format=tarfile.PAX_FORMAT) as output:
        for index, entry in enumerate(entries, 1):
            sink.tar_entry = index
            sink.report_progress()
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
    if settings.par2:
        executable("par2")
    if settings.compression:
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
        format_path.write_text("format=archivator\nversion=1\n"
                               f"parity={'par2-v2' if settings.par2 else 'none'}\n"
                               + "\n".join(f"{k}={v}" for k, v in vars(settings).items()) + "\n")
        if fingerprint:
            with format_path.open("a") as output:
                output.write(f"recipient-sha256={fingerprint}\n")
        catalog.extra.append(format_path)

        def writer():
            return ParityWriter(archive, archive_id, settings, catalog, certificate, overhead)

        queue = GroupQueue(writer)

        def direct(entry, accompanying=()):
            print(f"Archiving RAW stream: {entry['size']:,} plaintext bytes", flush=True)
            stream = {**public_entry(entry), "stream": new_id()}
            entries = list(accompanying) + [entry]
            sink = StreamWriter(queue, stream, entries)
            check_unchanged(source / entry["path"], entry)
            try:
                with (source / entry["path"]).open("rb") as original:
                    while data := original.read(BUFFER_SIZE):
                        sink.write(data)
                check_unchanged(source / entry["path"], entry)
                sink.finish()
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
                for entry in entries:
                    check_unchanged(source / entry["path"], entry)
                queue.place([], None, entries)
            else:
                print(f"Packing TAR stream: {len(files):,} files", flush=True)
                stream = {"stream": new_id(), "type": "tar", "size": tar_bytes(entries)}
                sink = StreamWriter(queue, stream, entries)
                try:
                    inventory = write_tar(source, entries, sink)
                    sink.entries = inventory
                    sink.finish()
                finally:
                    sink.close()

        pending = []
        pending_paths = set()
        pending_tar_bytes = 0
        pending_inventory_bytes = 2048
        planner = queue.planner
        planned_stream = {"stream": "0" * 32, "type": "tar"}

        def append_if_fits(entry):
            nonlocal pending_tar_bytes, pending_inventory_bytes
            additions = [item for item in with_parents([entry]) if item["path"] not in pending_paths]
            tar_growth = sum(len(tar_info(item).tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape"))
                             + ceil_div(item.get("size", 0), 512) * 512 for item in additions)
            inventory_growth = sum(len(json_bytes(public_entry(item))) + 600 for item in additions)
            size = ceil_div(pending_tar_bytes + tar_growth + 1024, tarfile.RECORDSIZE) * tarfile.RECORDSIZE
            if size > planner.input_bytes:
                return False
            chunk = planner.candidate(planned_stream, stored_bound(size, overhead, settings.compression), length=size)
            if not planner.fits([chunk], {}, pending_inventory_bytes + inventory_growth):
                return False
            pending.append(entry)
            pending_paths.update(item["path"] for item in additions)
            pending_tar_bytes += tar_growth
            pending_inventory_bytes += inventory_growth
            return True

        threshold = min(settings.large_file_bytes or planner.input_bytes, planner.input_bytes)
        for directory, children in chain([first_batch], batches):
            # Collect one complete TAR, continuing across directory boundaries.
            # Look ahead through this directory only for the first fitting entry.
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
                    pending_inventory_bytes = 2048
                else:
                    entry = candidates.pop(0)
                    if entry["type"] == "file":
                        direct(entry)
                    else:
                        flush([entry])
        flush(pending)
        queue.finish()
        catalog.finish()
    finally:
        progress.update("Removing backup temporary files")
        shutil.rmtree(staging)
    return archive_id
