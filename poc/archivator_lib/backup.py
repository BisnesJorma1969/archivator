"""Directory-local input, bounded datasets/datagroups, and protected local metadata."""

import json
import os
import shutil
import tarfile
from pathlib import Path
from itertools import chain

from .common import ArchiveError, BUFFER_SIZE, Hashes, WORK_DIR, sha256, write_json, write_jsonl
from .external import ZstdWriter, create_parity, encrypt, executable, normalize_certificate
from .filesystem import check_unchanged, directory_batches, empty_destination, ensure_disjoint, public_entry
from .format import Settings, datafile_name, metadata_prefix, new_id, datagroup_prefix, spare_metadata_name, stored_path
from .limits import ceil_div, check_files, input_limit, parity_plan, plan_reservation, stored_bound
from .metadata import MetadataWriter, json_bytes, store_metadata
from .progress import progress
from .seal import seal_reservation, write_seal


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
    # when a completed dataset receives its real digests in an open datagroup.
    digests = {"crc32", "md5", "sha1", "sha256", "sha512"}
    total = 1024
    for dataset, entries in sources.values():
        for record in [dataset or {}] + with_parents(entries):
            unsigned = {key: value for key, value in record.items()
                        if not key.startswith("_") and key not in digests}
            total += len(json_bytes(unsigned)) + 600
    return total


class DatagroupWriter:
    """One bounded recovery datagroup; placement and lifetime belong to DatagroupQueue."""

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
        self.datagroup_id = new_id()
        self.supergroup_id = catalog.supergroups.id
        self.members = []
        self.planning_only = False
        self.input_bytes = input_limit(min(settings.max_file_bytes, settings.max_datagroup_bytes // 4),
                                       encryption_overhead, settings.compression)

    def source_name(self):
        prefix = datagroup_prefix(self.archive_id, self.supergroup_id, self.datagroup_id)
        name = prefix + "_metadata_index-files.jsonl"
        if self.settings.compression:
            name += ".zst"
        return name + ".cms" if self.certificate else name

    def manifest(self, members, source_digest):
        return {"version": 1, "archive": self.archive_id, "datagroup": self.datagroup_id, "supergroup": self.supergroup_id,
                "compression": "zstd" if self.settings.compression else "none",
                "encryption": "cms-aes-256-gcm" if self.certificate else "none",
                "settings": vars(self.settings),
                "par2": plan_reservation(self.settings.max_file_bytes) if self.settings.datagroup_par2 else None,
                "members": members,
                "source_metadata": self.source_name(), "source_sha256": source_digest}

    def fits(self, members, sources, private_size=None):
        reservation = self.reservation(members, sources, private_size)
        return (reservation is not None and self.catalog.supergroups.fits(
            self.datagroup_id, reservation[1], alone=self.planning_only))

    def budget(self, members, sources, private_size=None):
        reservation = self.reservation(members, sources, private_size)
        return reservation[0] if reservation is not None else None

    def reservation(self, members, sources, private_size=None):
        """Stored data plus conservative metadata/PAR2 bytes, or no feasible fit."""
        settings = self.settings
        private_size = private_size or inventory_bound(sources)
        source_length = stored_bound(private_size, self.encryption_overhead, settings.compression)
        manifest_bytes = json.dumps(self.manifest(members, "0" * 64), ensure_ascii=True, indent=2, sort_keys=True)
        manifest_length = stored_bound(len(manifest_bytes.encode("ascii")) + 1, compression=settings.compression)
        lengths = {member["filename"]: member["stored_length"] for member in members}
        lengths[self.source_name()] = source_length
        prefix = datagroup_prefix(self.archive_id, self.supergroup_id, self.datagroup_id)
        suffix = ".zst" if settings.compression else ""
        lengths[prefix + "_metadata_index-datafiles.json" + suffix] = manifest_length
        if max(lengths.values()) > settings.max_file_bytes:
            return None
        seal_name, seal_size = seal_reservation(self.archive_id, self.supergroup_id, self.datagroup_id,
                                               len(members), settings.max_datagroup_bytes)
        if seal_size > settings.max_file_bytes:
            return None
        try:
            plan = parity_plan(lengths, settings.max_file_bytes, settings.datagroup_par2,
                               max_set_bytes=settings.max_datagroup_bytes - seal_size,
                               loss_count=settings.datagroup_loss_files, bitrot_percent=settings.datagroup_bitrot_percent)
            total = sum(lengths.values()) + plan.total_bytes + seal_size
            if total > settings.max_datagroup_bytes:
                return None
            # The identical central copies need their own parity and a receipt.
            # Reserve a bounded hash map for this set and the previous set.
            receipt_size = 8192 + len(json_bytes(self.catalog.previous)) + (plan.volumes + 1) * 400
            receipt_name = metadata_prefix(self.archive_id, self.supergroup_id, self.datagroup_id) + "_checksums.json" + suffix
            central = {spare_metadata_name(self.source_name()): source_length,
                       spare_metadata_name(prefix + "_metadata_index-datafiles.json" + suffix): manifest_length,
                       receipt_name: stored_bound(receipt_size, compression=settings.compression)}
            if max(central.values()) > settings.max_file_bytes:
                return None
            protection = parity_plan(central, settings.max_file_bytes, settings.datagroup_par2,
                                     max_set_bytes=settings.max_datagroup_bytes,
                                     loss_count=settings.datagroup_loss_files, bitrot_percent=settings.datagroup_bitrot_percent)
            if sum(central.values()) + protection.total_bytes > settings.max_datagroup_bytes:
                return None
            return total, {**lengths, **central, seal_name: seal_size}
        except ArchiveError:
            return None

    def candidate(self, dataset, size, offset=0, length=1):
        dataset_id = dataset["dataset"]
        kind = "tar" if dataset["type"] == "tar" else "raw"
        return {"filename": datafile_name(self.archive_id, self.datagroup_id, dataset_id,
                                        offset, length, bool(self.certificate), kind, self.settings.compression, supergroup=self.supergroup_id),
                "dataset": dataset_id, "kind": kind, "offset": offset, "length": length,
                "stored_length": size, "stored_sha256": "0" * 64,
                "plaintext_sha256": "0" * 64, "plaintext_sha512": "0" * 128}

    def proposed(self, chunks, dataset, entries):
        key = dataset["dataset"] if dataset else None
        if key is not None and key in self.sources and self.sources[key][0] is not dataset:
            raise ArchiveError("Dataset ID collision; refusing to replace an existing dataset")
        if key is None and key in self.sources:
            entries = self.sources[key][1] + entries
        sources = {**self.sources, key: (dataset, entries)}
        members = list(self.members)
        for chunk in chunks:
            member = self.candidate(dataset, chunk["stored_length"],
                                    chunk["offset"], chunk["length"])
            member.update(stored_sha256=chunk["stored_sha256"],
                          plaintext_sha256=chunk["plaintext_sha256"],
                          plaintext_sha512=chunk["plaintext_sha512"])
            members.append(member)
        return members, sources

    def can_add(self, chunks, dataset, entries):
        members, sources = self.proposed(chunks, dataset, entries)
        return self.fits(members, sources)

    def append(self, chunks, dataset, entries):
        members, sources = self.proposed(chunks, dataset, entries)
        reservation = self.reservation(members, sources)
        if reservation is None or not self.catalog.supergroups.fits(self.datagroup_id, reservation[1]):
            raise ArchiveError("Datagroup/supergroup cannot hold the selected content with metadata and parity")
        self.catalog.supergroups.reserve(self.datagroup_id, reservation[1])
        datagroup_directory = stored_path(self.archive, self.source_name()).parent
        if chunks:
            datagroup_directory.mkdir(parents=True, exist_ok=True)
        for chunk, member in zip(chunks, members[len(self.members):]):
            if (datagroup_directory / member["filename"]).exists():
                raise ArchiveError("Chunk filename collision; refusing to overwrite stored data")
            os.replace(chunk["path"], datagroup_directory / member["filename"])
            print(f"Stored chunk: {member['length']:,} plaintext bytes -> "
                  f"{member['stored_length']:,} stored bytes; datagroup {self.datagroup_id}", flush=True)
        self.members = members
        self.sources = sources

    def finish_set(self):
        if not self.sources:
            return
        datagroup_directory = stored_path(self.archive, self.source_name()).parent
        datagroup_directory.mkdir(parents=True, exist_ok=True)
        prefix = datagroup_prefix(self.archive_id, self.supergroup_id, self.datagroup_id)
        source_name = self.source_name().removesuffix(".cms").removesuffix(".zst")
        if (datagroup_directory / self.source_name()).exists():
            raise ArchiveError("Datagroup ID collision; refusing to overwrite metadata")

        def records():
            yield {"datasets": [dataset for dataset, _ in self.sources.values() if dataset is not None]}
            for dataset_id, (_, entries) in self.sources.items():
                for entry in with_parents(entries):
                    yield {"dataset": dataset_id, "entry": public_entry(entry)}

        write_jsonl(self.staging / source_name, records())
        stored = store_metadata(self.staging / source_name, self.staging, self.certificate, self.settings.compression)
        check_files([self.staging / stored], self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        os.replace(self.staging / stored, datagroup_directory / stored)
        manifest = self.manifest(self.members, sha256(datagroup_directory / stored))
        manifest_name = prefix + "_metadata_index-datafiles.json"
        # Plan against an upper bound including the plan fields themselves.
        # Keeping this geometry after compression makes regeneration deterministic.
        stored_manifest_name = manifest_name + (".zst" if self.settings.compression else "")
        lengths = {member["filename"]: member["stored_length"] for member in self.members}
        lengths[stored] = (datagroup_directory / stored).stat().st_size
        manifest_size = len(json.dumps(manifest, ensure_ascii=True, indent=2, sort_keys=True).encode("ascii")) + 1
        lengths[stored_manifest_name] = stored_bound(manifest_size, compression=self.settings.compression)
        _, seal_size = seal_reservation(self.archive_id, self.supergroup_id, self.datagroup_id,
                                        len(self.members), self.settings.max_datagroup_bytes)
        plan = parity_plan(lengths, self.settings.max_file_bytes, self.settings.datagroup_par2,
                           max_set_bytes=self.settings.max_datagroup_bytes - seal_size,
                           loss_count=self.settings.datagroup_loss_files, bitrot_percent=self.settings.datagroup_bitrot_percent)
        manifest["par2"] = plan.record() if self.settings.datagroup_par2 else None
        write_json(self.staging / manifest_name, manifest)
        manifest_name = store_metadata(self.staging / manifest_name, self.staging, compression=self.settings.compression)
        check_files([self.staging / manifest_name], self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        os.replace(self.staging / manifest_name, datagroup_directory / manifest_name)
        names = [member["filename"] for member in self.members] + [stored, manifest_name]
        lengths = {name: (datagroup_directory / name).stat().st_size for name in names}
        if sum(lengths.values()) + plan.total_bytes + seal_size > self.settings.max_datagroup_bytes:
            raise ArchiveError("Datagroup metadata and PAR2 exceed the byte budget")
        protection = f"{plan.blocks:,} PAR2 recovery blocks of {plan.slice_size:,} bytes" if self.settings.datagroup_par2 else "PAR2 disabled"
        print(f"Finalizing datagroup {self.datagroup_id}: {len(self.members):,} chunks, "
              f"{sum(lengths.values()):,} stored bytes; {protection}", flush=True)
        directory = self.staging / "parity"
        directory.mkdir()
        files = []
        if self.settings.datagroup_par2:
            files = create_parity(datagroup_directory, prefix, names, plan.slice_size, plan.blocks,
                                  directory, plan.volumes)
        total = check_files([*(datagroup_directory / name for name in names), *files],
                            self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        parity_hashes = {}
        for path in files:
            parity_hashes[path.name] = sha256(path)
            os.replace(path, datagroup_directory / path.name)
        directory.rmdir()
        seal = write_seal(datagroup_directory, self.archive_id, self.supergroup_id, self.datagroup_id,
                          [member["filename"] for member in self.members], [stored, manifest_name], list(parity_hashes))
        total = check_files([*(datagroup_directory / name for name in [*names, *parity_hashes]), seal],
                            self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        central = self.catalog.add(self.supergroup_id, self.datagroup_id,
                                   [datagroup_directory / stored, datagroup_directory / manifest_name], parity_hashes, seal)
        names.append(seal.name)
        self.catalog.supergroups.add(self.datagroup_id, [datagroup_directory / name for name in names] + central,
                                     {member["filename"]: member["stored_sha256"] for member in self.members})
        print(f"Finished datagroup: {total:,}/{self.settings.max_datagroup_bytes:,} bytes including metadata and enabled parity", flush=True)
        self.members = []
        self.sources = {}


class DatagroupQueue:
    """One active datagroup and a bounded, oldest-first list of waiting datagroups."""

    def __init__(self, make_datagroup):
        self.make_datagroup = make_datagroup
        self.planner = make_datagroup()  # Empty-datagroup feasibility, never published.
        self.planner.planning_only = True
        self.settings = self.planner.settings
        self.active = None
        self.waiting = []
        self.created = 0

    def new_datagroup(self):
        # All active/waiting datagroups belong to this one bounded supergroup.
        if self.created == self.settings.supergroup_datagroups:
            self.finish()
            self.planner.catalog.supergroups.finish()
            self.created = 0
        self.created += 1
        return self.make_datagroup()

    def fresh_for(self, chunks, dataset, entries):
        candidate = self.new_datagroup()
        if candidate.can_add(chunks, dataset, entries):
            return candidate
        # A byte/index/PAR2 limit may close a supergroup before its group count.
        # Nothing from this candidate has been published or reserved yet.
        self.finish()
        self.planner.catalog.supergroups.finish()
        self.created = 0
        candidate = self.new_datagroup()
        if not candidate.can_add(chunks, dataset, entries):
            raise ArchiveError("Content and its metadata/PAR2 cannot fit an empty datagroup/supergroup")
        return candidate

    def used_bytes(self, datagroup):
        budget = datagroup.budget(datagroup.members, datagroup.sources)
        # A changed central receipt reservation can also prevent further additions.
        return self.settings.max_datagroup_bytes if budget is None else budget

    def close_on_miss(self, datagroup):
        return self.used_bytes(datagroup) * 100 >= self.settings.max_datagroup_bytes * self.settings.datagroup_close_percent

    def retire_active(self):
        if self.active is None:
            return
        datagroup = self.active
        self.active = None
        if self.close_on_miss(datagroup):
            datagroup.finish_set()
            return
        self.waiting.append(datagroup)
        if len(self.waiting) > self.settings.waiting_datagroups:
            # max() keeps the first (oldest) datagroup when byte budgets tie.
            fullest = max(self.waiting, key=self.used_bytes)
            self.waiting.remove(fullest)
            fullest.finish_set()
        print(f"Datagroup queue: {len(self.waiting)}/{self.settings.waiting_datagroups} waiting", flush=True)

    def place(self, chunks, dataset, entries):
        """Admit an entire RAW file, one complete TAR, or metadata-only entries."""
        for datagroup in list(self.waiting):
            if datagroup.can_add(chunks, dataset, entries):
                datagroup.append(chunks, dataset, entries)
                return
            if self.close_on_miss(datagroup):
                self.waiting.remove(datagroup)
                datagroup.finish_set()
        if self.active is not None and self.active.can_add(chunks, dataset, entries):
            self.active.append(chunks, dataset, entries)
            return
        self.retire_active()
        self.active = self.fresh_for(chunks, dataset, entries)
        self.active.append(chunks, dataset, entries)

    def start_large_file(self):
        # The file has exceeded an EMPTY datagroup's budget, not merely the space
        # left in a populated datagroup. Its first fragment must start fresh.
        for datagroup in list(self.waiting):
            if self.close_on_miss(datagroup):
                self.waiting.remove(datagroup)
                datagroup.finish_set()
        self.retire_active()
        self.active = self.new_datagroup()

    def append_fragment(self, chunk, dataset, entries):
        if not self.active.can_add([chunk], dataset, entries):
            self.active.finish_set()
            self.active = None
            self.active = self.fresh_for([chunk], dataset, entries)
        self.active.append([chunk], dataset, entries)
        # The final datagroup stays active when the file ends; subsequent whole
        # files/TARs may fill its remainder. Intermediate datagroups never wait.

    def finish(self):
        for datagroup in self.waiting:
            datagroup.finish_set()
        self.waiting.clear()
        if self.active is not None:
            self.active.finish_set()
            self.active = None


class DatasetWriter:
    """Independent zstd/CMS chunks with a conservative plaintext input ceiling."""

    def __init__(self, queue, dataset, entries):
        self.queue = queue
        self.planner = queue.planner
        self.chunks = []
        self.spanning = False
        self.dataset = dataset
        self.entries = entries
        self.size = 0
        self.hashes = Hashes(lookup=True)
        self.chunk_hashes = Hashes()
        self.chunk_length = 0
        self.chunk_output = None
        self.tar_entry = 0
        self.tar_entries = 0

    def report_progress(self):
        kind = "TAR" if self.dataset["type"] == "tar" else "RAW"
        entries = f"entry {self.tar_entry:,}/{self.tar_entries:,}; " if kind == "TAR" else ""
        progress.update(
            f"Encoding {kind} {self.dataset['dataset'][:8]}: {entries}"
            f"{self.size:,}/{self.dataset['size']:,} plaintext bytes; "
            f"chunk {self.chunk_length:,}/{self.planner.input_bytes:,} bytes")

    def write(self, data):
        length = len(data)
        if self.dataset["type"] == "tar" and self.size + length > self.planner.input_bytes:
            raise ArchiveError("A complete TAR must fit in one independent chunk")
        remaining = memoryview(data)
        while remaining:
            if self.chunk_output is None:
                path = self.planner.staging / "chunk"
                if self.planner.settings.compression:
                    self.chunk_output = ZstdWriter(path)
                else:
                    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    self.chunk_output = os.fdopen(descriptor, "wb")
            count = min(len(remaining), self.planner.input_bytes - self.chunk_length)
            piece = remaining[:count]
            self.chunk_output.write(piece)
            self.hashes.update(piece)
            self.chunk_hashes.update(piece)
            self.chunk_length += count
            self.size += count
            self.report_progress()
            remaining = remaining[count:]
            if self.chunk_length == self.planner.input_bytes and self.dataset["type"] != "tar":
                self.finish_chunk()
        return length

    def finish_chunk(self):
        if not self.chunk_length:
            return
        if self.planner.settings.compression:
            self.chunk_output.finish()
        else:
            self.chunk_output.close()
        self.chunk_output = None
        path = self.planner.staging / "chunk"
        if self.planner.certificate:
            encrypted = self.planner.staging / "chunk.cms"
            encrypt(path, encrypted, self.planner.certificate)
            path.unlink()
            path = encrypted
        check_files([path], self.planner.settings.max_file_bytes, self.planner.settings.max_datagroup_bytes)
        offset = self.size - self.chunk_length
        staged = self.planner.staging / f"buffer-{self.dataset['dataset']}-{offset}"
        if self.planner.certificate:
            staged = staged.with_name(staged.name + ".cms")
        os.replace(path, staged)
        hashes = self.chunk_hashes.values()
        chunk = {"path": staged, "offset": offset, "length": self.chunk_length,
                 "stored_length": staged.stat().st_size, "stored_sha256": sha256(staged),
                 "plaintext_sha256": hashes["sha256"], "plaintext_sha512": hashes["sha512"]}
        if self.spanning:
            self.queue.append_fragment(chunk, self.dataset, self.entries)
        else:
            self.chunks.append(chunk)
            if not self.planner.can_add(self.chunks, self.dataset, self.entries):
                if self.dataset["type"] == "tar":
                    raise ArchiveError("A complete TAR and its metadata cannot fit an empty datagroup")
                self.spanning = True
                self.queue.start_large_file()
                for pending in self.chunks:
                    self.queue.append_fragment(pending, self.dataset, self.entries)
                self.chunks.clear()
            else:
                progress.update(f"Buffered dataset {self.dataset['dataset']}: {len(self.chunks):,} stored chunks")
        self.chunk_length = 0
        self.chunk_hashes = Hashes()

    def finish(self):
        self.dataset.update(self.hashes.values())
        self.finish_chunk()
        if not self.spanning:
            self.queue.place(self.chunks, self.dataset, self.entries)
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
            catalog.bootstrap_files.append(normalized)
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
        with format_path.open("a", encoding="utf-8") as output:
            output.write("\n" + Path(__file__).with_name("recovery.txt").read_text(encoding="utf-8"))
        check_files([format_path], settings.max_file_bytes, settings.max_datagroup_bytes)
        catalog.bootstrap_files.append(format_path)

        def writer():
            return DatagroupWriter(archive, archive_id, settings, catalog, certificate, overhead)

        queue = DatagroupQueue(writer)

        def direct(entry, accompanying=()):
            print(f"Archiving RAW dataset: {entry['size']:,} plaintext bytes", flush=True)
            dataset = {**public_entry(entry), "dataset": new_id()}
            entries = list(accompanying) + [entry]
            sink = DatasetWriter(queue, dataset, entries)
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
                print(f"Packing TAR dataset: {len(files):,} files", flush=True)
                dataset = {"dataset": new_id(), "type": "tar", "size": tar_bytes(entries)}
                sink = DatasetWriter(queue, dataset, entries)
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
        planned_dataset = {"dataset": "a" * 20, "type": "tar"}

        def append_if_fits(entry):
            nonlocal pending_tar_bytes, pending_inventory_bytes
            additions = [item for item in with_parents([entry]) if item["path"] not in pending_paths]
            tar_growth = sum(len(tar_info(item).tobuf(tarfile.PAX_FORMAT, "utf-8", "surrogateescape"))
                             + ceil_div(item.get("size", 0), 512) * 512 for item in additions)
            inventory_growth = sum(len(json_bytes(public_entry(item))) + 600 for item in additions)
            size = ceil_div(pending_tar_bytes + tar_growth + 1024, tarfile.RECORDSIZE) * tarfile.RECORDSIZE
            if size > planner.input_bytes:
                return False
            chunk = planner.candidate(planned_dataset, stored_bound(size, overhead, settings.compression), length=size)
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
        catalog.supergroups.finish()
        catalog.finish()
    finally:
        progress.update("Removing backup temporary files")
        shutil.rmtree(staging)
    return archive_id
