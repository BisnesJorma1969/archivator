"""Validate protected catalogs, repair groups, and discover independent local sets."""

import os
import re
import shutil
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .common import ArchiveError, IntegrityError, read_json, read_jsonl, scratch, sha256, write_json
from .external import check_parity, create_parity
from .filesystem import relative_path
from .format import (ARCHIVE_NAME, ID, Settings, archive_filename, group_metadata, metadata_prefix,
                     parity_prefix, parse_chunk, primary_metadata_name, spare_metadata_name, stored_path)
from .limits import parity_plan
from .metadata import catalog_root_digest, catalog_root_names, unpack_metadata
from .progress import progress


class ArchiveFiles(dict):
    """Unique basename lookup, independent of archive directory layout."""

    def __init__(self, root):
        super().__init__()
        self.root = Path(root)

    def add(self, name, path):
        if name in self:
            raise IntegrityError(f"Duplicate archive filename in hierarchy: {name}")
        self[name] = path


def discover(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ArchiveError(f"Archive location must be a directory: {root}")
    archives = {}
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        progress.update(f"Discovering archives: {len(archives)} IDs")
        subdirectories[:] = sorted(name for name in subdirectories if name != ".tmp")
        for name in sorted(names):
            match = ARCHIVE_NAME.match(name)
            if match:
                files = archives.setdefault(match[1], ArchiveFiles(root))
                files.add(name, Path(directory) / name)
    if not archives:
        raise IntegrityError("No archive files found")
    return archives


@dataclass
class Archive:
    id: str
    files: dict
    catalog_root: dict | None
    metadata: Path
    checksums: dict = field(default_factory=dict)
    format: dict = field(default_factory=dict)
    streams: list = field(default_factory=list)
    manifests: list = field(default_factory=list)
    entries: list = field(default_factory=list)
    candidates: dict = field(default_factory=dict)
    metadata_damage: list = field(default_factory=list)
def select(archives, archive_id, allow_all=False):
    if archive_id:
        if archive_id not in archives:
            raise ArchiveError(f"Archive ID not found: {archive_id}")
        return [archive_id]
    if len(archives) > 1 and not allow_all:
        raise ArchiveError("Multiple archive IDs found; select one with --archive-id: "
                           + ", ".join(sorted(archives)))
    return sorted(archives)


def stage_existing(files, names, destination, expected=None, writable=True, archive_layout=False):
    """Link read-only inputs; copy damaged/unknown members before scratch repair."""
    expected = expected or {}
    destination.mkdir(parents=True, exist_ok=True)
    for index, name in enumerate(names, 1):
        progress.update(f"Preparing recovery inputs: {index:,}/{len(names):,} files")
        target = stored_path(destination, name) if archive_layout else destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        path = files.get(name)
        if path is None:
            continue
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"Archive member is not a regular file: {path}")
        # PAR2 reads recovery volumes but never edits them. Regeneration first
        # unlinks staged volumes. Healthy data members are also read-only inputs.
        read_only = not writable or name.endswith(".par2")
        if not read_only and name in expected:
            read_only = sha256(path) == expected[name]
        if read_only:
            try:
                os.link(path, target)
                continue
            except OSError:
                # Cross-filesystem, read-only, and non-hardlink-capable archives
                # still work. Never use a symlink or repair an alias to bad data.
                pass
        progress.update(f"Copying recovery input: {index:,}/{len(names):,} files")
        shutil.copyfile(path, target)


def mismatches(directory, expected, archive_layout=False):
    damaged = []
    for name, digest in expected.items():
        path = stored_path(directory, name) if archive_layout else directory / name
        if not path.is_file() or sha256(path) != digest:
            damaged.append(name)
    return damaged


def remove_repair_backups(directory, members, previous_names):
    """Discard only backups PAR2 just created, after recovered hashes pass."""
    if previous_names is None:
        return
    for path in directory.rglob("*"):
        original, separator, number = path.name.rpartition(".")
        if (path.relative_to(directory) not in previous_names and original in members
                and separator and number.isdecimal() and path.is_file() and not path.is_symlink()):
            path.unlink()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)


def validate_entries(entries):
    by_path = {}
    for entry in entries:
        path = relative_path(entry["path"])
        if entry["path"] in by_path:
            raise IntegrityError(f"Duplicate source path: {entry['path']!r}")
        if entry["type"] not in ("file", "directory", "symlink"):
            raise IntegrityError(f"Unsupported entry type: {entry['type']!r}")
        if not isinstance(entry["mode"], int) or not 0 <= entry["mode"] <= 0o7777:
            raise IntegrityError("Invalid source mode")
        if not isinstance(entry["mtime_ns"], int):
            raise IntegrityError("Invalid source timestamp")
        if entry["type"] == "file":
            if not isinstance(entry["size"], int) or entry["size"] < 0 or not valid_digest(entry["sha256"]):
                raise IntegrityError("Invalid file size or checksum")
        if entry["type"] == "symlink":
            if not isinstance(entry["symlink_target"], str) or "\x00" in entry["symlink_target"]:
                raise IntegrityError("Invalid symlink target")
        by_path[path.as_posix()] = entry
    if "." not in by_path or by_path["."]["type"] != "directory":
        raise IntegrityError("Missing source root directory")
    for entry in entries:
        for parent in relative_path(entry["path"]).parents:
            if parent.as_posix() not in by_path or by_path[parent.as_posix()]["type"] != "directory":
                raise IntegrityError(f"Missing or non-directory ancestor: {parent}")




def read_catalog_root(archive_id, files):
    valid, damaged = [], []
    for name in catalog_root_names(archive_id):
        path = files.get(name)
        try:
            if path is None or path.is_symlink():
                raise IntegrityError("Missing marker")
            marker = read_json(path)
            if (marker["version"] != 1 or marker["archive"] != archive_id
                    or marker["marker_sha256"] != catalog_root_digest(marker)
                    or not isinstance(marker["groups"], int) or marker["groups"] < 1):
                raise IntegrityError("Invalid marker")
            settings = Settings(**marker["settings"])
            validate_link(marker["last"], archive_id, settings.par2)
            valid.append(marker)
        except (OSError, ArchiveError, KeyError, TypeError, ValueError):
            damaged.append(name)
    if not valid:
        raise IntegrityError("No valid catalog-root marker copy")
    if any(marker != valid[0] for marker in valid[1:]):
        raise IntegrityError("Valid catalog-root marker copies disagree; cannot choose a checksum root")
    return valid[0], damaged


def validate_link(link, archive_id, par2):
    if not re.fullmatch(ID, link["parity"]) or not valid_digest(link["receipt_sha256"]):
        raise IntegrityError("Invalid metadata chain link")
    validate_parity_hashes(link["parity_hashes"], metadata_prefix(archive_id, link["parity"]), par2)


def validate_parity_hashes(hashes, prefix, enabled):
    if not enabled:
        if hashes != {}:
            raise IntegrityError("Unexpected PAR2 checksums when PAR2 is disabled")
        return
    if not isinstance(hashes, dict) or len(hashes) < 2:
        raise IntegrityError("Missing PAR2 checksums")
    for name, digest in hashes.items():
        if not re.fullmatch(re.escape(prefix) + r"(?:\.vol[0-9]+\+[0-9]+)?\.par2", name) or not valid_digest(digest):
            raise IntegrityError("Invalid PAR2 checksum record")


def healthy_copy(files, name, digest=None):
    names = [name]
    if group_metadata(name):
        primary = primary_metadata_name(name)
        names.append(spare_metadata_name(name) if name == primary else primary)
    for candidate in names:
        path = files.get(candidate)
        if path is not None and path.is_file() and not path.is_symlink():
            if digest is None or sha256(path) == digest:
                return path
    return None


def protected_hashes(manifest):
    return {**{member["filename"]: member["stored_sha256"] for member in manifest["members"]},
            manifest["source_metadata"]: manifest["source_sha256"],
            manifest["_name"]: manifest["_sha256"]}


def validate_manifest(manifest, archive_id, name, digest):
    parity_id = manifest["parity"]
    if not re.fullmatch(ID, parity_id):
        raise IntegrityError("Invalid parity ID")
    prefix = parity_prefix(archive_id, parity_id)
    settings = Settings(**manifest["settings"])
    suffix = ".zst" if settings.compression else ""
    compression = "zstd" if settings.compression else "none"
    if (manifest["version"] != 1 or manifest["archive"] != archive_id
            or name != prefix + "_metadata_index-chunks.json" + suffix or manifest["compression"] != compression):
        raise IntegrityError("Inconsistent group manifest")
    if manifest["encryption"] not in ("none", "cms-aes-256-gcm"):
        raise IntegrityError("Unsupported encryption")
    encrypted = manifest["encryption"] != "none"
    source_name = archive_filename(manifest["source_metadata"], archive_id)
    if source_name != prefix + "_metadata_index-files.jsonl" + suffix + (".cms" if encrypted else ""):
        raise IntegrityError("Invalid private metadata filename")
    if not valid_digest(manifest["source_sha256"]):
        raise IntegrityError("Invalid source metadata checksum")
    streams = {}
    for number, member in enumerate(manifest["members"]):
        expected = {"archive": archive_id, "parity": parity_id, "chunk": number,
                    "stream": member["stream"], "offset": member["offset"],
                    "length": member["length"], "encrypted": encrypted, "kind": member["kind"],
                    "compressed": settings.compression}
        if parse_chunk(member["filename"]) != expected or member["chunk"] != number:
            raise IntegrityError("Chunk filename/manifest mismatch")
        if member["offset"] < 0 or member["length"] <= 0 or not 0 < member["stored_length"] <= settings.max_file_bytes:
            raise IntegrityError("Invalid chunk size or offset")
        if not valid_digest(member["stored_sha256"]) or not valid_digest(member["plaintext_sha256"]):
            raise IntegrityError("Invalid chunk checksum")
        if not re.fullmatch(r"[0-9a-f]{128}", member["plaintext_sha512"]):
            raise IntegrityError("Invalid chunk SHA-512")
        previous = streams.get(member["stream"])
        if previous is not None and (member["kind"] != "raw" or previous["kind"] != "raw"
                                     or member["offset"] != previous["offset"] + previous["length"]):
            raise IntegrityError("Non-contiguous RAW chunks or repeated TAR stream within a group")
        streams[member["stream"]] = member
    manifest.update(_name=name, _sha256=digest)
    return manifest


def repair_verified_set(directory, prefix, hashes, settings, parity_hashes, replenish=False):
    """PAR2 writes only here: scratch copies or explicitly selected in-place files."""
    damaged = mismatches(directory, hashes)
    if not settings.par2:
        if damaged:
            raise IntegrityError(f"Unrecoverable files in {prefix}: PAR2 is disabled")
        return [], []
    parity_damage = mismatches(directory, parity_hashes) if parity_hashes else []
    status = check_parity(directory, prefix)
    previous = None
    if damaged:
        previous = {path.relative_to(directory) for path in directory.rglob("*")}
        if status != 1 or check_parity(directory, prefix, repair=True) != 0:
            raise IntegrityError(f"Unrecoverable files in {prefix}")
    if mismatches(directory, hashes):
        raise IntegrityError("Repaired files failed stored SHA-256 verification")
    remove_repair_backups(directory, hashes, previous)
    if replenish and (parity_damage or status in (2, 4)):
        lengths = {name: (directory / name).stat().st_size for name in hashes}
        plan = parity_plan(lengths, settings.slice_size, settings.max_file_bytes)
        for path in directory.glob(prefix + "*.par2"):
            path.unlink()
        create_parity(directory, prefix, list(hashes), settings.slice_size, plan.blocks, volumes=plan.volumes)
        if parity_hashes and mismatches(directory, parity_hashes):
            raise IntegrityError("Regenerated PAR2 differs from recorded checksums")
    return damaged, parity_damage


def load_central(archive, original, in_place):
    link = archive.catalog_root["last"]
    settings = Settings(**archive.catalog_root["settings"])
    seen = set()
    for number in range(archive.catalog_root["groups"]):
        if link is None:
            raise IntegrityError("Metadata chain ended early")
        validate_link(link, archive.id, settings.par2)
        parity_id = link["parity"]
        if parity_id in seen:
            raise IntegrityError("Metadata chain contains a cycle")
        seen.add(parity_id)
        prefix = metadata_prefix(archive.id, parity_id)
        group_prefix = parity_prefix(archive.id, parity_id)
        suffix = ".zst" if settings.compression else ""
        receipt_name = prefix + "_checksums.json" + suffix
        print(f"Checking metadata set {number + 1}/{archive.catalog_root['groups']}: {parity_id}", flush=True)
        if in_place:
            directory = original.root / "metadata" / parity_id[:2]
            directory.mkdir(parents=True, exist_ok=True)
        else:
            directory = archive.metadata / f"central-{parity_id}"
            names = {name for name in original if name.startswith(prefix)}
            names.update(spare_metadata_name(name) for name in original
                         if name.startswith(group_prefix + "_") and group_metadata(name))
            expected = {receipt_name: link["receipt_sha256"]}
            receipt_copy = healthy_copy(original, receipt_name, link["receipt_sha256"])
            if receipt_copy:
                trusted = read_json(unpack_metadata(receipt_copy, archive.metadata))
                expected.update({name: record["sha256"] for name, record in trusted["members"].items()})
            names.update(expected)
            selected = dict(original)
            for name in names:
                archive_filename(name, archive.id)
                good = healthy_copy(original, name, expected.get(name))
                if good:
                    selected[name] = good
            stage_existing(selected, sorted(names), directory, expected)
        receipt_path = directory / receipt_name
        expected_receipt = {receipt_name: link["receipt_sha256"]}
        receipt_damage = mismatches(directory, expected_receipt)
        receipt_previous = None
        if receipt_damage:
            before = {path.relative_to(directory) for path in directory.rglob("*")}
            receipt_previous = before
            if not settings.par2 or check_parity(directory, prefix) != 1 or check_parity(directory, prefix, repair=True) != 0:
                raise IntegrityError("Metadata checksum receipt cannot be recovered")
            if mismatches(directory, expected_receipt):
                raise IntegrityError("Recovered metadata receipt checksum mismatch")
            remove_repair_backups(directory, expected_receipt, before)
        receipt = read_json(unpack_metadata(receipt_path, archive.metadata))
        if receipt["version"] != 1 or receipt["archive"] != archive.id or receipt["parity"] != parity_id:
            raise IntegrityError("Invalid metadata receipt")
        hashes = dict(expected_receipt)
        for name, record in receipt["members"].items():
            archive_filename(name, archive.id)
            if not (group_metadata(name) and name.startswith(group_prefix + "_")
                    and name == spare_metadata_name(name)
                    or name in (prefix + "_format.txt", prefix + "_recipient.pem")):
                raise IntegrityError("Invalid central metadata member")
            if not valid_digest(record["sha256"]) or not 0 < record["size"] <= settings.max_file_bytes:
                raise IntegrityError("Invalid metadata checksum or size")
            hashes[name] = record["sha256"]
        # A healthy redundant copy is useful even if this central recovery set
        # has too little parity left. Never overwrite an archive input in verify.
        original_damage = mismatches(directory, hashes)
        for name in original_damage:
            good = healthy_copy(original, name, hashes[name])
            if good is not None and good != directory / name:
                (directory / name).unlink(missing_ok=True)
                shutil.copyfile(good, directory / name)
        try:
            damage, parity_damage = repair_verified_set(directory, prefix, hashes, settings,
                                                         link["parity_hashes"], in_place)
        except IntegrityError:
            missing = mismatches(directory, hashes)
            if not settings.par2 or not missing or any(not group_metadata(name) for name in missing):
                raise
            # The local data set protects the same metadata bytes. It remains
            # useful when the central copy and its own parity were both lost.
            local = original.root / parity_id[:2] if in_place else archive.metadata / f"rescue-{parity_id}"
            if not in_place:
                names = [name for name in original if name.startswith(group_prefix)
                         and name == primary_metadata_name(name)]
                stage_existing(original, names, local)
            local_previous = {path.relative_to(local) for path in local.rglob("*")}
            if check_parity(local, group_prefix) != 1 or check_parity(local, group_prefix, repair=True) != 0:
                raise IntegrityError("Neither local nor central PAR2 can recover group metadata")
            for name in missing:
                path = local / primary_metadata_name(name)
                if not path.is_file() or sha256(path) != hashes[name]:
                    raise IntegrityError("Local metadata recovery failed checksum validation")
                (directory / name).unlink(missing_ok=True)
                shutil.copyfile(path, directory / name)
            manifest_name = group_prefix + "_metadata_index-chunks.json" + suffix
            local_manifest = read_json(unpack_metadata(local / manifest_name, archive.metadata))
            manifest_digest = hashes[spare_metadata_name(manifest_name)]
            local_manifest = validate_manifest(local_manifest, archive.id, manifest_name, manifest_digest)
            local_hashes = protected_hashes(local_manifest)
            if not mismatches(local, local_hashes):
                remove_repair_backups(local, local_hashes, local_previous)
            damage, parity_damage = repair_verified_set(directory, prefix, hashes, settings,
                                                         link["parity_hashes"], in_place)
        remove_repair_backups(directory, hashes, receipt_previous)
        archive.metadata_damage.extend(receipt_damage + original_damage + damage + parity_damage)
        archive.checksums.update(hashes)
        validate_parity_hashes(receipt["data_parity"], group_prefix, settings.par2)
        archive.checksums.update(receipt["data_parity"])
        for name in receipt["members"]:
            archive.files[name] = directory / name
            if group_metadata(name):
                primary = primary_metadata_name(name)
                # Payload manifests and local PAR2 keep referencing primary names.
                archive.files[primary] = directory / name
                for copy_name in (primary, name):
                    path = original.get(copy_name)
                    if path is None or not path.is_file() or path.is_symlink() or sha256(path) != hashes[name]:
                        archive.metadata_damage.append(copy_name)
        name = group_prefix + "_metadata_index-chunks.json" + suffix
        spare = spare_metadata_name(name)
        manifest = read_json(unpack_metadata(directory / spare, archive.metadata))
        manifest = validate_manifest(manifest, archive.id, name, hashes[spare])
        if manifest["settings"] != archive.catalog_root["settings"]:
            raise IntegrityError("Group settings disagree with catalog-root marker")
        archive.manifests.append(manifest)
        link = receipt["previous"]
    if link is not None:
        raise IntegrityError("Metadata chain exceeds the catalog-root marker's group count")
    archive.manifests.reverse()


def load_local(archive, original, in_place):
    """A surviving group can explain itself without the archive-wide catalog."""
    groups = {}
    selected = dict(original)
    for name, path in original.items():
        match = re.match(rf"archive-{archive.id}_parity-({ID})(?:_|\.)", name)
        if match:
            # A spare is the same stored content, but local PAR2 expects the
            # primary basename. Only metadata aliases are copied when needed.
            primary = primary_metadata_name(name) if group_metadata(name) else name
            selected.setdefault(primary, path)
            groups.setdefault(match[1], set()).add(primary)
    if not groups:
        raise IntegrityError("No local recovery groups found")
    print("Archive-wide metadata is unavailable; recovering independent local groups. "
          "Original backup completeness cannot be proved.", flush=True)
    archive.metadata_damage.append("archive-wide catalog unavailable")
    for parity_id, names in sorted(groups.items()):
        names = sorted(names)
        prefix = parity_prefix(archive.id, parity_id)
        if in_place:
            directory = original.root / parity_id[:2]
            directory.mkdir(parents=True, exist_ok=True)
            for name in names:
                if group_metadata(name) and not (directory / name).exists():
                    shutil.copyfile(selected[name], directory / name)
        else:
            directory = archive.metadata / f"local-{parity_id}"
            stage_existing(selected, names, directory, writable=False)
        has_parity = any(name.endswith(".par2") for name in names)
        status = check_parity(directory, prefix) if has_parity else 4
        previous = None
        if status == 1:
            previous = {path.relative_to(directory) for path in directory.rglob("*")}
            if not in_place:
                for name in names:
                    if not name.endswith(".par2"):
                        (directory / name).unlink(missing_ok=True)
                stage_existing(selected, [name for name in names if not name.endswith(".par2")], directory)
            if check_parity(directory, prefix, repair=True) != 0:
                raise IntegrityError(f"Cannot recover local metadata for {parity_id}")
        manifests = [path for path in directory.glob(prefix + "_metadata_index-chunks.json*")
                     if path.name in (prefix + "_metadata_index-chunks.json",
                                      prefix + "_metadata_index-chunks.json.zst")]
        if len(manifests) > 1:
            raise IntegrityError("Ambiguous local manifests")
        name = manifests[0].name if manifests else ""
        if not name:
            raise IntegrityError(f"No usable local manifest for {parity_id}; use filename-only scan")
        manifest = read_json(unpack_metadata(directory / name, archive.metadata))
        manifest = validate_manifest(manifest, archive.id, name, sha256(directory / name))
        archive.manifests.append(manifest)
        hashes = protected_hashes(manifest)
        if previous is not None and not mismatches(directory, hashes):
            remove_repair_backups(directory, hashes, previous)
        for path in directory.iterdir():
            if path.is_file() and not path.name.endswith(".par2"):
                archive.files[path.name] = path


def load_sources(archive, key, certificate):
    streams, entries = {}, {}
    for manifest in archive.manifests:
        if manifest["encryption"] != "none" and key is None:
            continue  # Verify/repair need no names or decryption key.
        name = manifest["source_metadata"]
        path = archive.files[name]
        if sha256(path) != manifest["source_sha256"]:
            raise IntegrityError("Source metadata checksum mismatch")
        records = read_jsonl(unpack_metadata(path, archive.metadata, key, certificate))
        group_streams = {}
        for stream in records[0]["streams"]:
            stream_id = stream["stream"]
            if (not re.fullmatch(ID, stream_id) or stream["type"] not in ("tar", "file")
                    or stream_id in group_streams):
                raise IntegrityError("Invalid or duplicate source stream")
            if not isinstance(stream["size"], int) or stream["size"] < 0:
                raise IntegrityError("Invalid source size")
            group_streams[stream_id] = stream
        inventories = {stream_id: [] for stream_id in group_streams}
        for record in records[1:]:
            stream_id, entry = record["stream"], record["entry"]
            if stream_id is not None:
                if stream_id not in group_streams:
                    raise IntegrityError("Inventory refers to an unknown stream")
                inventories[stream_id].append(entry)
            stream = group_streams.get(stream_id)
            # The final group adds the full hash of a split RAW file.
            if stream and stream["type"] == "file" and entry["path"] == stream["path"]:
                continue
            old = entries.setdefault(entry["path"], entry)
            if old != entry:
                raise IntegrityError(f"Conflicting source metadata: {entry['path']!r}")
        for member in manifest["members"]:
            if member["stream"] not in group_streams:
                raise IntegrityError("Source stream and chunk IDs disagree")
        for stream_id, stream in group_streams.items():
            members = [member for member in manifest["members"] if member["stream"] == stream_id]
            kind = "tar" if stream["type"] == "tar" else "raw"
            if any(member["kind"] != kind for member in members):
                raise IntegrityError("Source stream type and filename disagree")
            if stream["type"] == "tar":
                if (len(members) != 1 or members[0]["offset"] != 0
                        or members[0]["length"] != stream["size"]):
                    raise IntegrityError("TAR stream is not one complete chunk")
            elif stream["size"] == 0:
                if members:
                    raise IntegrityError("Empty file has payload chunks")
            else:
                if not members or members[-1]["offset"] + members[-1]["length"] > stream["size"]:
                    raise IntegrityError("Invalid RAW stream range")
                end = members[-1]["offset"] + members[-1]["length"]
                partial = members[0]["offset"] != 0 or end != stream["size"]
                if partial and manifest["members"][0]["stream"] != stream_id:
                    raise IntegrityError("A spanning RAW file must start in an empty group")
                if end < stream["size"] and len(group_streams) != 1:
                    raise IntegrityError("An intermediate RAW group must not contain other streams")
            old = streams.get(stream_id)
            if old and any(old.get(field) != stream.get(field) for field in ("type", "size", "path")):
                raise IntegrityError("Conflicting stream descriptions")
            if old is None or "sha256" in stream:
                streams[stream_id] = stream
            if stream["type"] == "tar":
                if old is not None:
                    raise IntegrityError("TAR stream occurs in multiple groups")
                stream["inventory"] = inventories[stream_id]
    for stream in streams.values():
        if stream["type"] == "file":
            entries[stream["path"]] = stream
        if archive.catalog_root and (not valid_digest(stream.get("sha256"))
                                 or not re.fullmatch(r"[0-9a-f]{128}", stream.get("sha512", ""))):
            raise IntegrityError("Missing completed stream checksum")
    archive.streams = list(streams.values())
    archive.entries = list(entries.values())
    if archive.entries:
        # In an isolated fragment, the full-file hash may be unavailable; chunk
        # checksums still apply, and restore will skip incomplete streams.
        validation = [{**entry, "sha256": entry.get("sha256", "0" * 64)} for entry in archive.entries]
        validate_entries(validation)


@contextmanager
def open_archive(archive_id, files, in_place=False, key=None, certificate=None):
    with scratch("metadata-") as temporary:
        try:
            marker_names = catalog_root_names(archive_id)
            catalog_root, marker_damage = (None, [])
            if any(name in files for name in marker_names):
                catalog_root, marker_damage = read_catalog_root(archive_id, files)
            archive = Archive(archive_id, dict(files), catalog_root, Path(temporary))
            archive.metadata_damage.extend(marker_damage)
            if catalog_root:
                load_central(archive, files, in_place)
            else:
                load_local(archive, files, in_place)
            modes = {(manifest["encryption"], manifest["compression"], manifest["settings"]["par2"])
                     for manifest in archive.manifests}
            if len(modes) != 1:
                raise IntegrityError("Groups disagree about compression, encryption, or PAR2")
            encryption, compression, par2 = modes.pop()
            archive.format = {"encryption": encryption, "compression": compression, "par2": par2}
            for manifest in archive.manifests:
                prefix = parity_prefix(archive_id, manifest["parity"])
                archive.candidates[manifest["parity"]] = list(protected_hashes(manifest)) + [
                    name for name in files if name.startswith(prefix + ".") and name.endswith(".par2")]
            load_sources(archive, key, certificate)
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise IntegrityError(f"Malformed archive metadata: {error}") from error
        except FileNotFoundError as error:
            raise IntegrityError(f"Missing archive metadata: {error.filename}") from error
        yield archive


def stage_set(archive, manifest, directory, writable=True):
    names = archive.candidates[manifest["parity"]]
    stage_existing(archive.files, names, directory, protected_hashes(manifest), writable)


def inspect_set(archive, manifest, directory):
    prefix = parity_prefix(archive.id, manifest["parity"])
    hashes = protected_hashes(manifest)
    damage = mismatches(directory, hashes)
    parity_hashes = {name: digest for name, digest in archive.checksums.items()
                     if name.startswith(prefix + ".") and name.endswith(".par2")}
    parity_damage = mismatches(directory, parity_hashes)
    if not manifest["settings"]["par2"]:
        return damage, [], 2 if damage else 0
    status = check_parity(directory, prefix)
    if not parity_hashes and status in (2, 4):
        parity_damage.append(prefix + ".par2 (unverified)")
    return damage, parity_damage, status


def recover_set(archive, manifest, directory, replenish=False):
    prefix = parity_prefix(archive.id, manifest["parity"])
    parity_hashes = {name: digest for name, digest in archive.checksums.items()
                     if name.startswith(prefix + ".") and name.endswith(".par2")}
    return repair_verified_set(directory, prefix, protected_hashes(manifest),
                               Settings(**manifest["settings"]), parity_hashes, replenish)


def verify(root, archive_id=None):
    archives = discover(root)
    result = 0
    for selected in select(archives, archive_id, allow_all=True):
        try:
            with open_archive(selected, archives[selected]) as archive:
                damaged = bool(archive.metadata_damage)
                unrecoverable = False
                if damaged:
                    print(f"{selected}: metadata/redundancy damage ({len(archive.metadata_damage)} records)")
                for index, manifest in enumerate(archive.manifests, 1):
                    print(f"Checking recovery set {index}/{len(archive.manifests)}", flush=True)
                    with scratch("verify-") as temporary:
                        directory = Path(temporary)
                        stage_set(archive, manifest, directory, writable=False)
                        data_damage, parity_damage, status = inspect_set(archive, manifest, directory)
                    if data_damage or parity_damage:
                        damaged = True
                        recoverable = not data_damage or status == 1
                        unrecoverable |= not recoverable
                        print(f"{manifest['parity']}: {'repairable' if recoverable else 'unrecoverable'}; "
                              f"{len(data_damage)} members, {len(parity_damage)} PAR2 files damaged/missing")
                label = "unrecoverable" if unrecoverable else "damage detected; repairable sets checked" if damaged else "intact"
                print(f"{selected}: {label}")
                result |= int(damaged)
        except IntegrityError as error:
            print(f"{selected}: unrecoverable/incomplete: {error}")
            result = 1
    return result


def prepare_in_place(root, archive_id, files):
    """Normalize scattered files with renames, preserving the two metadata roles."""
    base = Path(root)
    device = base.stat().st_dev
    moves = []
    for name, path in files.items():
        target = stored_path(base, name)
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"Archive member is not a regular file: {path}")
        if path.stat().st_dev != device:
            raise ArchiveError("In-place repair requires one filesystem")
        destinations = [target]
        if group_metadata(name):
            destinations.append(stored_path(base, primary_metadata_name(name)))
        for destination in destinations:
            for parent in [destination.parent, *destination.parent.parents]:
                if parent == base.parent:
                    break
                if parent.is_symlink() or parent.exists() and not parent.is_dir():
                    raise ArchiveError(f"Recovery directory must be a directory, not a link: {parent}")
        moves.append((path, target))
    for source, target in moves:
        if source != target:
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                raise IntegrityError(f"Recovery destination already exists: {target}")
            source.rename(target)


def repair(root, archive_id=None):
    archives = discover(root)
    selected = select(archives, archive_id)[0]
    prepare_in_place(root, selected, archives[selected])
    files = discover(root)[selected]
    completed = 0
    try:
        with open_archive(selected, files, in_place=True) as archive:
            for index, manifest in enumerate(archive.manifests, 1):
                print(f"Repairing group {index}/{len(archive.manifests)} in place", flush=True)
                directory = Path(root) / manifest["parity"][:2]
                directory.mkdir(exist_ok=True)
                # Restore the intentionally duplicated metadata from a surviving
                # catalog copy if needed. Data/PAR2 are never staged or copied.
                for name, digest in protected_hashes(manifest).items():
                    if not group_metadata(name):
                        continue
                    path = directory / name
                    if not path.is_file() or sha256(path) != digest:
                        good = archive.files.get(name)
                        if good and good != path and sha256(good) == digest:
                            path.unlink(missing_ok=True)
                            shutil.copyfile(good, path)
                recover_set(archive, manifest, directory, replenish=True)
                completed += 1
            if archive.catalog_root:
                for name in catalog_root_names(selected):
                    path = Path(root) / "metadata" / name
                    if name in archive.metadata_damage:
                        write_json(path, archive.catalog_root)
            else:
                print("Local groups repaired; no catalog-root marker invented for an unproven full archive.")
    except (ArchiveError, OSError):
        print(f"In-place repair stopped after {completed} groups; changes already made remain.", flush=True)
        raise
    print(f"{selected}: repair complete ({completed} groups)")
