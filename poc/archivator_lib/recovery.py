"""Read-only verification and explicit, set-by-set archive repair."""

import os
import re
import shutil
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .backup import finalize_metadata
from .common import ArchiveError, IntegrityError, read_json, read_jsonl, scratch, sha256
from .external import check_parity, create_parity
from .filesystem import relative_path
from .format import ARCHIVE_NAME, ID, archive_filename, new_id, parity_prefix, parse_chunk


@dataclass
class Archive:
    id: str
    files: dict
    complete: dict
    metadata: Path
    checksums: dict
    format: dict
    streams: list
    manifests: list
    entries: list
    candidates: dict
    metadata_damage: list


def discover(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ArchiveError(f"Archive location must be a directory: {root}")
    archives = {}
    # Enumerate names once. Never open unrelated archive contents, and never
    # let PAR2 search this potentially mixed hierarchy directly.
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        subdirectories[:] = sorted(name for name in subdirectories if name != ".tmp")
        for name in sorted(names):
            match = ARCHIVE_NAME.match(name)
            if not match:
                continue
            archive = archives.setdefault(match[1], {})
            if name in archive:
                raise IntegrityError(f"Duplicate archive filename in hierarchy: {name}")
            archive[name] = Path(directory) / name
    if not archives:
        raise IntegrityError("No archive files found")
    return archives


def select(archives, archive_id, allow_all=False):
    if archive_id:
        if archive_id not in archives:
            raise ArchiveError(f"Archive ID not found: {archive_id}")
        return [archive_id]
    if len(archives) > 1 and not allow_all:
        raise ArchiveError("Multiple archive IDs found; select one with --archive-id: "
                           + ", ".join(sorted(archives)))
    return sorted(archives)


def copy_existing(files, names, destination):
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = files.get(name)
        if path is None:
            continue
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"Archive member is not a regular file: {path}")
        shutil.copyfile(path, destination / name)


def mismatches(directory, expected):
    damaged = []
    for name, digest in expected.items():
        path = directory / name
        if not path.is_file() or sha256(path) != digest:
            damaged.append(name)
    return damaged


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)


def validate_complete(complete, archive_id):
    if complete["version"] != 1 or complete["archive"] != archive_id:
        raise IntegrityError("Unsupported or inconsistent completion marker")
    prefix = complete["metadata_prefix"]
    if not re.fullmatch(rf"archive-{archive_id}_parity-{ID}_metadata", prefix):
        raise IntegrityError("Invalid metadata recovery prefix")
    names = complete["metadata_members"]
    if not isinstance(names, list) or len(set(names)) != len(names):
        raise IntegrityError("Invalid metadata member list")
    for name in names:
        archive_filename(name, archive_id)
    if complete["checksum_index"] != f"archive-{archive_id}_checksums.json":
        raise IntegrityError("Invalid checksum index filename")
    if complete["checksum_index"] not in names or not valid_digest(complete["checksum_index_sha256"]):
        raise IntegrityError("Missing checksum index reference")
    if len(complete["metadata_parity"]) != 5:
        raise IntegrityError("Expected five metadata PAR2 files")
    for name, digest in complete["metadata_parity"].items():
        archive_filename(name, archive_id)
        if not re.fullmatch(re.escape(prefix) + r"(?:\.vol[0-9]+\+[0-9]+)?\.par2", name):
            raise IntegrityError("Invalid metadata PAR2 filename")
        if not valid_digest(digest):
            raise IntegrityError("Invalid metadata PAR2 checksum")
    if complete["metadata_slice_size"] <= 0 or complete["metadata_slice_size"] % 4:
        raise IntegrityError("Invalid metadata PAR2 slice size")


def read_format(path, archive_id):
    fields = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, value = line.split("=", 1)
        if key in fields:
            raise IntegrityError(f"Duplicate format field: {key}")
        fields[key] = value
    required = {"format": "archivator", "version": "1", "archive": archive_id,
                "compression": "gzip", "parity": "par2-v2"}
    if any(fields.get(key) != value for key, value in required.items()):
        raise IntegrityError("Unsupported or inconsistent archive format")
    if fields["encryption"] not in ("none", "cms-aes-256-gcm"):
        raise IntegrityError("Unsupported encryption")
    for key in ("chunk-size", "parity-data-members", "parity-slice-size"):
        fields[key] = int(fields[key])
        if fields[key] <= 0:
            raise IntegrityError(f"Invalid format setting: {key}")
    return fields


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


def read_catalog(metadata, archive_id):
    streams = read_jsonl(metadata / f"archive-{archive_id}_streams.jsonl")
    entries = []
    stream_ids = set()
    for stream in streams:
        stream_id = stream["stream"]
        if not re.fullmatch(ID, stream_id) or stream_id in stream_ids:
            raise IntegrityError("Invalid or duplicate stream ID")
        stream_ids.add(stream_id)
        if not isinstance(stream["size"], int) or stream["size"] <= 0:
            raise IntegrityError("Invalid stream length")
        if not valid_digest(stream["sha256"]) or not re.fullmatch(r"[0-9a-f]{128}", stream["sha512"]):
            raise IntegrityError("Invalid stream checksum")
        if stream["type"] == "tar":
            name = f"archive-{archive_id}_stream-{stream_id}_files.jsonl"
            if stream["inventory"] != name:
                raise IntegrityError("Inventory filename does not match stream")
            inventory = read_jsonl(metadata / name)
            if stream["entry_count"] != len(inventory):
                raise IntegrityError("Inventory entry count mismatch")
            entries.extend(inventory)
        elif stream["type"] == "file":
            entries.append(stream)
        else:
            raise IntegrityError("Unknown stream type")
    validate_entries(entries)
    return streams, entries


def read_manifests(metadata, archive_id, names, streams, fields):
    manifests = []
    stream_chunks = {stream["stream"]: [] for stream in streams}
    encrypted = fields["encryption"] != "none"
    for name in sorted(names):
        if not name.endswith("_manifest.json"):
            continue
        manifest = read_json(metadata / name)
        prefix = parity_prefix(archive_id, manifest["parity"])
        if name != prefix + "_manifest.json" or manifest["version"] != 1 or manifest["archive"] != archive_id:
            raise IntegrityError("Inconsistent parity-set manifest")
        members = manifest["members"]
        if not 0 < len(members) <= fields["parity-data-members"] or len(members) != manifest["member_count"]:
            raise IntegrityError("Invalid parity member count")
        if manifest["slice_size"] != fields["parity-slice-size"] or manifest["slice_size"] % 4:
            raise IntegrityError("Inconsistent PAR2 slice size")
        if not 4 <= manifest["recovery_blocks"] <= 32768:
            raise IntegrityError("Invalid recovery block count")
        if manifest["recovery_bytes"] != manifest["slice_size"] * manifest["recovery_blocks"]:
            raise IntegrityError("Inconsistent recovery capacity")
        numbers = set()
        for member in members:
            coordinates = parse_chunk(member["filename"])
            expected = {"archive": archive_id, "parity": manifest["parity"], "encrypted": encrypted,
                        "chunk": member["chunk"], "stream": member["stream"],
                        "offset": member["offset"], "length": member["length"]}
            if coordinates != expected or member["chunk"] in numbers:
                raise IntegrityError("Chunk filename/manifest mismatch")
            numbers.add(member["chunk"])
            if member["stream"] not in stream_chunks or not 0 < member["length"] <= fields["chunk-size"]:
                raise IntegrityError("Invalid chunk stream or length")
            if not valid_digest(member["stored_sha256"]) or not valid_digest(member["plaintext_sha256"]):
                raise IntegrityError("Invalid chunk checksum")
            if not re.fullmatch(r"[0-9a-f]{128}", member["plaintext_sha512"]):
                raise IntegrityError("Invalid chunk SHA-512")
            if not isinstance(member["stored_length"], int) or member["stored_length"] <= 0:
                raise IntegrityError("Invalid stored length")
            stream_chunks[member["stream"]].append(member)
        if numbers != set(range(len(members))):
            raise IntegrityError("Invalid chunk numbering")
        manifests.append(manifest)
    for stream in streams:
        offset = 0
        chunks = sorted(stream_chunks[stream["stream"]], key=lambda member: member["offset"])
        for number, member in enumerate(chunks):
            if member["offset"] != offset:
                raise IntegrityError("Overlapping or missing plaintext ranges")
            if number < len(chunks) - 1 and member["length"] != fields["chunk-size"]:
                raise IntegrityError("Short non-final chunk")
            offset += member["length"]
        if offset != stream["size"]:
            raise IntegrityError("Chunk ranges do not cover the stream")
    return manifests


def load_metadata(archive_id, files, directory):
    complete_name = f"archive-{archive_id}_complete.json"
    if complete_name not in files:
        raise IntegrityError(f"Archive {archive_id} is incomplete: no completion marker")
    copy_existing(files, [complete_name], directory)
    complete = read_json(directory / complete_name)
    validate_complete(complete, archive_id)
    names = complete["metadata_members"]
    copy_existing(files, names + list(complete["metadata_parity"]), directory)
    # Record damage before scratch repair so verify cannot hide a broken archive.
    original_hashes = {name: sha256(directory / name) for name in names if (directory / name).is_file()}
    parity_damage = mismatches(directory, complete["metadata_parity"])
    status = check_parity(directory, complete["metadata_prefix"])
    if status == 1 and check_parity(directory, complete["metadata_prefix"], repair=True) != 0:
        raise IntegrityError("Metadata repair failed")
    index_name = complete["checksum_index"]
    if mismatches(directory, {index_name: complete["checksum_index_sha256"]}):
        raise IntegrityError("Checksum index is missing/damaged and cannot be recovered")
    checksums = read_json(directory / index_name)
    for name, digest in checksums.items():
        archive_filename(name, archive_id)
        if not valid_digest(digest):
            raise IntegrityError("Invalid metadata checksum")
    expected_metadata = {name for name in checksums if not name.endswith(".par2")}
    if expected_metadata != set(names) - {index_name}:
        raise IntegrityError("Completion marker and checksum index disagree")
    metadata_hashes = {name: checksums[name] for name in expected_metadata}
    metadata_hashes[index_name] = complete["checksum_index_sha256"]
    if mismatches(directory, metadata_hashes):
        raise IntegrityError("Archive metadata is unrecoverable or its checksums disagree with PAR2")
    damage = parity_damage + [name for name, digest in metadata_hashes.items() if original_hashes.get(name) != digest]
    fields = read_format(directory / f"archive-{archive_id}_format.txt", archive_id)
    streams, entries = read_catalog(directory, archive_id)
    manifests = read_manifests(directory, archive_id, names, streams, fields)
    candidates = {}
    for name in files:
        match = re.match(rf"archive-{archive_id}_parity-({ID})(?:_|\.)", name)
        if match:
            candidates.setdefault(match[1], []).append(name)
    return Archive(archive_id, files, complete, directory, checksums, fields,
                   streams, manifests, entries, candidates, damage)


@contextmanager
def open_archive(archive_id, files):
    with scratch("metadata-") as temporary:
        try:
            archive = load_metadata(archive_id, files, Path(temporary))
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise IntegrityError(f"Malformed archive metadata: {error}") from error
        except FileNotFoundError as error:
            raise IntegrityError(f"Missing archive metadata: {error.filename}") from error
        yield archive


def copy_set(archive, manifest, directory):
    names = archive.candidates.get(manifest["parity"], [])
    copy_existing(archive.files, names, directory)


def inspect_set(archive, manifest, directory):
    prefix = parity_prefix(archive.id, manifest["parity"])
    data_hashes = {member["filename"]: member["stored_sha256"] for member in manifest["members"]}
    data_damage = mismatches(directory, data_hashes)
    for member in manifest["members"]:
        path = directory / member["filename"]
        if path.is_file() and path.stat().st_size != member["stored_length"]:
            if member["filename"] not in data_damage:
                data_damage.append(member["filename"])
    parity_hashes = {name: digest for name, digest in archive.checksums.items()
                     if name.startswith(prefix + ".") and name.endswith(".par2")}
    if len(parity_hashes) != 5:
        raise IntegrityError("Checksum index must describe five PAR2 files per set")
    parity_damage = mismatches(directory, parity_hashes)
    status = check_parity(directory, prefix)
    return data_damage, parity_damage, status


def recover_set(archive, manifest, directory, replenish=False):
    data_damage, parity_damage, status = inspect_set(archive, manifest, directory)
    prefix = parity_prefix(archive.id, manifest["parity"])
    if data_damage:
        if status != 1 or check_parity(directory, prefix, repair=True) != 0:
            raise IntegrityError(f"Unrecoverable data in parity set {manifest['parity']}")
    hashes = {member["filename"]: member["stored_sha256"] for member in manifest["members"]}
    if mismatches(directory, hashes):
        raise IntegrityError("Repaired data failed stored SHA-256 verification")
    # Intact data can replenish even a completely lost parity set. A restore
    # need not replenish partially damaged volumes once PAR2 verifies the data.
    if (replenish and parity_damage) or status in (2, 4):
        for path in directory.glob(prefix + "*.par2"):
            path.unlink()
        create_parity(directory, prefix, list(hashes), manifest["slice_size"], manifest["recovery_blocks"])
    if check_parity(directory, prefix) != 0:
        raise IntegrityError("Recovered set failed final PAR2 verification")
    return data_damage, parity_damage


def verify(root, archive_id=None):
    archives = discover(root)
    result = 0
    for selected in select(archives, archive_id, allow_all=True):
        try:
            with open_archive(selected, archives[selected]) as archive:
                damaged = bool(archive.metadata_damage)
                unrecoverable = False
                if archive.metadata_damage:
                    print(f"{selected}: repairable metadata/protection damage ({len(archive.metadata_damage)} files)")
                for manifest in archive.manifests:
                    with scratch("verify-") as temporary:
                        directory = Path(temporary)
                        copy_set(archive, manifest, directory)
                        data_damage, parity_damage, status = inspect_set(archive, manifest, directory)
                    if data_damage or parity_damage:
                        damaged = True
                        recoverable = not data_damage or status == 1
                        unrecoverable |= not recoverable
                        label = "repairable" if recoverable else "unrecoverable"
                        print(f"{selected} parity {manifest['parity']}: {label}; "
                              f"{len(data_damage)} data and {len(parity_damage)} PAR2 files damaged/missing")
                label = "unrecoverable" if unrecoverable else "repairable" if damaged else "intact"
                print(f"{selected}: {label}")
                if damaged:
                    result = 1
        except IntegrityError as error:
            print(f"{selected}: unrecoverable/incomplete: {error}")
            result = 1
    return result


def publish_repair(source, destination):
    temporary = destination.parent / ".tmp"
    if temporary.is_symlink():
        raise ArchiveError(f"Repair staging must not be a symlink: {temporary}")
    temporary.mkdir(exist_ok=True)
    staged = temporary / (destination.name + "." + new_id() + ".repair")
    try:
        with source.open("rb") as original, staged.open("xb") as output:
            shutil.copyfileobj(original, output)
        os.replace(staged, destination)
    finally:
        if staged.exists():
            staged.unlink()
        try:
            temporary.rmdir()
        except OSError:
            pass


def repair(root, archive_id=None):
    archives = discover(root)
    selected = select(archives, archive_id)[0]
    with open_archive(selected, archives[selected]) as archive:
        complete_name = f"archive-{selected}_complete.json"
        base = archive.files[complete_name].parent
        changed = bool(archive.metadata_damage)
        completed_sets = 0
        try:
            for manifest in archive.manifests:
                with scratch("repair-") as temporary:
                    directory = Path(temporary)
                    copy_set(archive, manifest, directory)
                    data_damage, parity_damage = recover_set(archive, manifest, directory, replenish=True)
                    names = list(data_damage)
                    if parity_damage:
                        prefix = parity_prefix(selected, manifest["parity"])
                        names.extend(path.name for path in directory.glob(prefix + "*.par2"))
                    for name in names:
                        destination = archive.files.get(name, base / name)
                        publish_repair(directory / name, destination)
                        archive.files[name] = destination
                    if names:
                        changed = True
                        completed_sets += 1
                        print(f"{selected}: repaired parity set {manifest['parity']}")
            if changed:
                with scratch("finalize-") as temporary:
                    directory = Path(temporary)
                    (directory / ".tmp").mkdir()
                    metadata_names = [name for name in archive.complete["metadata_members"]
                                      if name != archive.complete["checksum_index"]]
                    for name in metadata_names:
                        shutil.copyfile(archive.metadata / name, directory / name)
                    parity_checksums = {name: sha256(archive.files[name]) for name in archive.checksums
                                        if name.endswith(".par2")}
                    metadata_id = archive.complete["metadata_prefix"].split("_parity-")[1].split("_")[0]
                    finalize_metadata(directory, selected, metadata_names, [],
                                      archive.complete["metadata_slice_size"], parity_checksums, metadata_id)
                    # Publish the new checksum root last, just as backup does.
                    for path in sorted(directory.iterdir()):
                        if path.is_file() and path.name != complete_name:
                            publish_repair(path, archive.files.get(path.name, base / path.name))
                    publish_repair(directory / complete_name, base / complete_name)
        except (ArchiveError, OSError):
            if completed_sets:
                print(f"Repair stopped after {completed_sets} repaired sets; those improvements remain.")
            raise
    if verify(root, selected) != 0:
        raise IntegrityError("Archive is still damaged after repair")
    print(f"{selected}: repair complete" if changed else f"{selected}: no repair needed")
