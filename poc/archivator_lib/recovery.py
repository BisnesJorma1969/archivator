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
from .format import ARCHIVE_NAME, ID, archive_filename, parity_prefix, parse_chunk
from .metadata import completion_digest, completion_names, unpack_metadata
from .progress import progress


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
    progress.update(f"Discovering archive files in {str(root)!r}")
    if root.is_symlink() or not root.is_dir():
        raise ArchiveError(f"Archive location must be a directory: {root}")
    archives = {}
    # Enumerate names once; operations select files belonging to one archive/set.
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        progress.update(f"Discovering archives: {len(archives)} IDs found; scanning {directory!r}")
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


def stage_existing(files, names, destination, expected=None, writable=True):
    """Link read-only inputs; copy damaged/unknown members before scratch repair."""
    expected = expected or {}
    destination.mkdir(parents=True, exist_ok=True)
    for index, name in enumerate(names, 1):
        progress.update(f"Preparing recovery inputs: {index}/{len(names)}; {name!r}")
        path = files.get(name)
        if path is None:
            continue
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"Archive member is not a regular file: {path}")
        target = destination / name
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
        progress.update(f"Copying recovery input: {index}/{len(names)}; {name!r}")
        shutil.copyfile(path, target)


def mismatches(directory, expected):
    damaged = []
    for name, digest in expected.items():
        path = directory / name
        if not path.is_file() or sha256(path) != digest:
            damaged.append(name)
    return damaged


def remove_repair_backups(directory, members, previous_names):
    """Discard only backups PAR2 just created, after recovered hashes pass."""
    if previous_names is None:
        return
    for path in directory.iterdir():
        original, separator, number = path.name.rpartition(".")
        if (path.name not in previous_names and original in members
                and separator and number.isdecimal() and path.is_file() and not path.is_symlink()):
            path.unlink()


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)


def validate_complete(complete, archive_id):
    if complete["marker_sha256"] != completion_digest(complete):
        raise IntegrityError("Completion marker checksum mismatch")
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
    if complete["checksum_index"] != f"archive-{archive_id}_checksums.json.zst":
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
    logical_names = [name.removesuffix(".zst") for name in names]
    if len(set(logical_names)) != len(logical_names):
        raise IntegrityError("Duplicate compressed/uncompressed metadata member")


def read_completion(archive_id, files):
    valid = []
    damaged = []
    for name in completion_names(archive_id):
        path = files.get(name)
        if path is None or path.is_symlink() or not path.is_file():
            damaged.append(name)
            continue
        try:
            complete = read_json(path)
            validate_complete(complete, archive_id)
        except (IntegrityError, KeyError, TypeError, ValueError, AttributeError):
            damaged.append(name)
            continue
        valid.append(complete)
    if not valid:
        raise IntegrityError(f"Archive {archive_id} is incomplete/unusable: no valid completion marker copy")
    if any(complete != valid[0] for complete in valid[1:]):
        raise IntegrityError("Valid completion marker copies disagree; cannot choose a checksum root")
    return valid[0], damaged


def read_format(path, archive_id):
    fields = {}
    for line in path.read_text(encoding="ascii").splitlines():
        key, value = line.split("=", 1)
        if key in fields:
            raise IntegrityError(f"Duplicate format field: {key}")
        fields[key] = value
    required = {"format": "archivator", "version": "1", "archive": archive_id,
                "compression": "zstd", "parity": "par2-v2"}
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
        name = name.removesuffix(".zst")
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


def load_metadata(archive_id, files, directory, in_place=False):
    print(f"Loading and checking metadata for archive {archive_id}", flush=True)
    complete, marker_damage = read_completion(archive_id, files)
    names = complete["metadata_members"]
    index_name = complete["checksum_index"]
    cached_checksums = None
    if in_place:
        stored = next(files[name].parent for name in completion_names(archive_id)
                      if name not in marker_damage)
    else:
        stored = directory
        expected = {index_name: complete["checksum_index_sha256"]}
        index_path = files.get(index_name)
        if index_path and not index_path.is_symlink() and index_path.is_file():
            if sha256(index_path) == complete["checksum_index_sha256"]:
                cached_checksums = read_json(unpack_metadata(index_path, directory))
                expected.update(cached_checksums)
        # If the checksum index itself needs recovery, other metadata cannot yet
        # be classified as healthy. Copy those unknown members before repairing.
        stage_existing(files, names + list(complete["metadata_parity"]), directory, expected)
    # Record damage before any repair so verify cannot hide a broken archive.
    original_hashes = {name: sha256(stored / name) for name in names if (stored / name).is_file()}
    parity_damage = mismatches(stored, complete["metadata_parity"])
    status = check_parity(stored, complete["metadata_prefix"])
    previous_names = None
    if status == 1:
        previous_names = {path.name for path in stored.iterdir()}
        if check_parity(stored, complete["metadata_prefix"], repair=True) != 0:
            raise IntegrityError("Metadata repair failed")
    if mismatches(stored, {index_name: complete["checksum_index_sha256"]}):
        raise IntegrityError("Checksum index is missing/damaged and cannot be recovered")
    checksums = cached_checksums if cached_checksums is not None else read_json(
        unpack_metadata(stored / index_name, directory))
    for name, digest in checksums.items():
        archive_filename(name, archive_id)
        if not valid_digest(digest):
            raise IntegrityError("Invalid metadata checksum")
    expected_metadata = {name for name in checksums if not name.endswith(".par2")}
    if expected_metadata != set(names) - {index_name}:
        raise IntegrityError("Completion marker and checksum index disagree")
    metadata_hashes = {name: checksums[name] for name in expected_metadata}
    metadata_hashes[index_name] = complete["checksum_index_sha256"]
    if mismatches(stored, metadata_hashes):
        raise IntegrityError("Archive metadata is unrecoverable or its checksums disagree with PAR2")
    remove_repair_backups(stored, metadata_hashes, previous_names)
    damage = marker_damage + parity_damage + [name for name, digest in metadata_hashes.items()
                                            if original_hashes.get(name) != digest]
    for name in names:
        if name != index_name:
            unpack_metadata(stored / name, directory)
    fields = read_format(stored / f"archive-{archive_id}_format.txt", archive_id)
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
def open_archive(archive_id, files, in_place=False):
    with scratch("metadata-") as temporary:
        try:
            archive = load_metadata(archive_id, files, Path(temporary), in_place)
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise IntegrityError(f"Malformed archive metadata: {error}") from error
        except FileNotFoundError as error:
            raise IntegrityError(f"Missing archive metadata: {error.filename}") from error
        yield archive


def stage_set(archive, manifest, directory, writable=True):
    names = archive.candidates.get(manifest["parity"], [])
    expected = {member["filename"]: member["stored_sha256"] for member in manifest["members"]}
    # Only data and recovery files are inputs; the manifest was already parsed.
    names = [name for name in names if name in expected or name.endswith(".par2")]
    stage_existing(archive.files, names, directory, expected, writable)


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
    previous_names = None
    if data_damage:
        previous_names = {path.name for path in directory.iterdir()}
        if status != 1 or check_parity(directory, prefix, repair=True) != 0:
            raise IntegrityError(f"Unrecoverable data in parity set {manifest['parity']}")
    hashes = {member["filename"]: member["stored_sha256"] for member in manifest["members"]}
    if mismatches(directory, hashes):
        raise IntegrityError("Repaired data failed stored SHA-256 verification")
    remove_repair_backups(directory, hashes, previous_names)
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
                        label = "repairable" if recoverable else "unrecoverable"
                        print(f"{selected} parity {manifest['parity']}: {label}; "
                              f"{len(data_damage)} data and {len(parity_damage)} PAR2 files damaged/missing")
                if unrecoverable:
                    label = "unrecoverable; insufficient recovery data"
                elif damaged:
                    label = "repairable; damage detected, recovery is possible"
                else:
                    label = "intact; all stored data, metadata, and recovery files verified"
                print(f"{selected}: {label}")
                if damaged:
                    result = 1
        except IntegrityError as error:
            print(f"{selected}: unrecoverable/incomplete: {error}")
            result = 1
    return result


def prepare_in_place(archive_id, files):
    """Put scattered members beside a valid marker using same-filesystem renames."""
    _, damaged_markers = read_completion(archive_id, files)
    base = next(files[name].parent for name in completion_names(archive_id)
                if name not in damaged_markers)
    device = base.stat().st_dev
    staging = base / ".tmp"
    if staging.is_symlink() or (staging.exists() and not staging.is_dir()):
        raise ArchiveError(f"Repair staging must be a directory, not a link: {staging}")
    # PAR2 stores basenames and needs one target directory. Check all moves before
    # changing anything; never turn a cross-filesystem rename into a hidden copy.
    for path in files.values():
        if path.is_symlink() or not path.is_file():
            raise IntegrityError(f"Archive member is not a regular file: {path}")
        if path.stat().st_dev != device:
            raise ArchiveError("In-place repair requires the selected archive on one filesystem")
    for name, path in files.items():
        if path.parent != base:
            progress.update(f"Moving scattered archive member into repair directory: {name!r}")
            path.rename(base / name)
            files[name] = base / name
    return base


def repair(root, archive_id=None):
    archives = discover(root)
    selected = select(archives, archive_id)[0]
    files = archives[selected]
    base = prepare_in_place(selected, files)
    completed_sets = 0
    changed = False
    try:
        with open_archive(selected, files, in_place=True) as archive:
            changed = bool(archive.metadata_damage)
            for index, manifest in enumerate(archive.manifests, 1):
                print(f"Checking/repairing recovery set {index}/{len(archive.manifests)} in place", flush=True)
                data_damage, parity_damage = recover_set(archive, manifest, base, replenish=True)
                if data_damage or parity_damage:
                    changed = True
                    completed_sets += 1
                    print(f"{selected}: repaired parity set {manifest['parity']}", flush=True)
            if changed:
                staging = base / ".tmp"
                staging.mkdir(exist_ok=True)
                metadata_names = [name for name in archive.complete["metadata_members"]
                                  if name != archive.complete["checksum_index"]]
                parity_checksums = {name: sha256(base / name) for name in archive.checksums
                                    if name.endswith(".par2")}
                metadata_id = archive.complete["metadata_prefix"].split("_parity-")[1].split("_")[0]
                finalize_metadata(base, selected, metadata_names, [],
                                  archive.complete["metadata_slice_size"], parity_checksums, metadata_id)
                if not any(staging.iterdir()):
                    staging.rmdir()
        # Re-read the resulting checksum root and verify in place too. Calling
        # the read-only verify workflow here would unnecessarily stage inputs.
        with open_archive(selected, discover(root)[selected], in_place=True) as archive:
            if archive.metadata_damage:
                raise IntegrityError("Archive metadata is still damaged after repair")
            for manifest in archive.manifests:
                data_damage, parity_damage, status = inspect_set(archive, manifest, base)
                if data_damage or parity_damage or status != 0:
                    raise IntegrityError("Archive is still damaged after repair")
    except (ArchiveError, OSError):
        print(f"In-place repair stopped after {completed_sets} completed sets; changes already made remain.",
              flush=True)
        raise
    print(f"{selected}: repair complete" if changed else f"{selected}: no repair needed")
