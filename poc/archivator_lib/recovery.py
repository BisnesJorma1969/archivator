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
from .format import ARCHIVE_NAME, ID, Settings, archive_filename, metadata_prefix, parity_prefix, parse_chunk, stored_path
from .limits import parity_plan
from .metadata import completion_digest, completion_names, unpack_metadata
from .progress import progress


class ArchiveFiles(dict):
    """Basename lookup with the two intentional copies of group metadata."""

    def __init__(self, root):
        super().__init__()
        self.root = Path(root)
        self.copies = {}

    def add(self, name, path):
        copies = self.copies.setdefault(name, [])
        if copies and (len(copies) >= 2 or not group_metadata(name)):
            raise IntegrityError(f"Duplicate archive filename in hierarchy: {name}")
        copies.append(path)
        self.setdefault(name, path)


def group_metadata(name):
    return bool(re.fullmatch(rf"archive-{ID}_parity-{ID}_(?:manifest\.json\.zst|metadata_[a-z0-9_.-]+)", name))


def discover(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ArchiveError(f"Archive location must be a directory: {root}")
    archives = {}
    for directory, subdirectories, names in os.walk(root, followlinks=False):
        progress.update(f"Discovering archives: {len(archives)} IDs; scanning {directory!r}")
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
    complete: dict | None
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
        progress.update(f"Preparing recovery inputs: {index}/{len(names)}; {name!r}")
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
        progress.update(f"Copying recovery input: {index}/{len(names)}; {name!r}")
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




def read_completion(archive_id, files):
    valid, damaged = [], []
    for name in completion_names(archive_id):
        path = files.get(name)
        try:
            if path is None or path.is_symlink():
                raise IntegrityError("Missing marker")
            marker = read_json(path)
            if (marker["version"] != 1 or marker["archive"] != archive_id
                    or marker["marker_sha256"] != completion_digest(marker)
                    or not isinstance(marker["groups"], int) or marker["groups"] < 1):
                raise IntegrityError("Invalid marker")
            Settings(**marker["settings"])
            validate_link(marker["last"], archive_id)
            valid.append(marker)
        except (OSError, ArchiveError, KeyError, TypeError, ValueError):
            damaged.append(name)
    if not valid:
        raise IntegrityError("No valid completion marker copy")
    if any(marker != valid[0] for marker in valid[1:]):
        raise IntegrityError("Valid completion marker copies disagree; cannot choose a checksum root")
    return valid[0], damaged


def validate_link(link, archive_id):
    if not re.fullmatch(ID, link["parity"]) or not valid_digest(link["receipt_sha256"]):
        raise IntegrityError("Invalid metadata chain link")
    validate_parity_hashes(link["parity_hashes"], metadata_prefix(archive_id, link["parity"]))


def validate_parity_hashes(hashes, prefix):
    if not isinstance(hashes, dict) or len(hashes) < 2:
        raise IntegrityError("Missing PAR2 checksums")
    for name, digest in hashes.items():
        if not re.fullmatch(re.escape(prefix) + r"(?:\.vol[0-9]+\+[0-9]+)?\.par2", name) or not valid_digest(digest):
            raise IntegrityError("Invalid PAR2 checksum record")


def healthy_copy(files, name, digest=None):
    copies = getattr(files, "copies", {}).get(name, [files.get(name)])
    for path in copies:
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
    if (manifest["version"] != 1 or manifest["archive"] != archive_id
            or name != prefix + "_manifest.json.zst" or manifest["compression"] != "zstd"):
        raise IntegrityError("Inconsistent group manifest")
    settings = Settings(**manifest["settings"])
    if manifest["encryption"] not in ("none", "cms-aes-256-gcm"):
        raise IntegrityError("Unsupported encryption")
    encrypted = manifest["encryption"] != "none"
    source_name = archive_filename(manifest["source_metadata"], archive_id)
    if not source_name.startswith(prefix + "_metadata_") or source_name.endswith(".cms") != encrypted:
        raise IntegrityError("Invalid private metadata filename")
    if not valid_digest(manifest["source_sha256"]):
        raise IntegrityError("Invalid source metadata checksum")
    streams = set()
    for number, member in enumerate(manifest["members"]):
        expected = {"archive": archive_id, "parity": parity_id, "chunk": number,
                    "stream": member["stream"], "offset": member["offset"],
                    "length": member["length"], "encrypted": encrypted}
        if parse_chunk(member["filename"]) != expected or member["chunk"] != number:
            raise IntegrityError("Chunk filename/manifest mismatch")
        if member["offset"] < 0 or member["length"] <= 0 or not 0 < member["stored_length"] <= settings.max_file_bytes:
            raise IntegrityError("Invalid chunk size or offset")
        if not valid_digest(member["stored_sha256"]) or not valid_digest(member["plaintext_sha256"]):
            raise IntegrityError("Invalid chunk checksum")
        if not re.fullmatch(r"[0-9a-f]{128}", member["plaintext_sha512"]):
            raise IntegrityError("Invalid chunk SHA-512")
        streams.add(member["stream"])
    if len(streams) > 1:
        raise IntegrityError("A parity group must not mix streams")
    manifest.update(_name=name, _sha256=digest)
    return manifest


def repair_verified_set(directory, prefix, hashes, settings, parity_hashes, replenish=False):
    """PAR2 writes only here: scratch copies or explicitly selected in-place files."""
    damaged = mismatches(directory, hashes)
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
    link = archive.complete["last"]
    settings = Settings(**archive.complete["settings"])
    seen = set()
    for number in range(archive.complete["groups"]):
        if link is None:
            raise IntegrityError("Metadata chain ended early")
        validate_link(link, archive.id)
        parity_id = link["parity"]
        if parity_id in seen:
            raise IntegrityError("Metadata chain contains a cycle")
        seen.add(parity_id)
        prefix = metadata_prefix(archive.id, parity_id)
        group_prefix = parity_prefix(archive.id, parity_id)
        receipt_name = prefix + "_checksums.json.zst"
        print(f"Checking metadata set {number + 1}/{archive.complete['groups']}: {parity_id}", flush=True)
        if in_place:
            directory = original.root / "metadata" / parity_id[:2]
            directory.mkdir(parents=True, exist_ok=True)
        else:
            directory = archive.metadata / f"central-{parity_id}"
            names = [name for name in original if name.startswith(prefix)
                     or (name.startswith(group_prefix + "_") and group_metadata(name))
                     or name.endswith(("_metadata_format.txt", "_metadata_recipient.pem"))]
            expected = {receipt_name: link["receipt_sha256"]}
            receipt_copy = healthy_copy(original, receipt_name, link["receipt_sha256"])
            if receipt_copy:
                trusted = read_json(unpack_metadata(receipt_copy, archive.metadata))
                expected.update({name: record["sha256"] for name, record in trusted["members"].items()})
            selected = dict(original)
            for name, digest in expected.items():
                good = healthy_copy(original, name, digest)
                if good:
                    selected[name] = good
            stage_existing(selected, names, directory, expected)
        receipt_path = directory / receipt_name
        expected_receipt = {receipt_name: link["receipt_sha256"]}
        receipt_damage = mismatches(directory, expected_receipt)
        receipt_previous = None
        if receipt_damage:
            before = {path.relative_to(directory) for path in directory.rglob("*")}
            receipt_previous = before
            if check_parity(directory, prefix) != 1 or check_parity(directory, prefix, repair=True) != 0:
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
            if not missing or any(not group_metadata(name) for name in missing):
                raise
            # The local data set protects the same metadata bytes. It remains
            # useful when the central copy and its own parity were both lost.
            local = original.root / parity_id[:2] if in_place else archive.metadata / f"rescue-{parity_id}"
            if not in_place:
                names = [name for name in original if name.startswith(group_prefix)]
                stage_existing(original, names, local)
            local_previous = {path.relative_to(local) for path in local.rglob("*")}
            if check_parity(local, group_prefix) != 1 or check_parity(local, group_prefix, repair=True) != 0:
                raise IntegrityError("Neither local nor central PAR2 can recover group metadata")
            for name in missing:
                path = local / name
                if not path.is_file() or sha256(path) != hashes[name]:
                    raise IntegrityError("Local metadata recovery failed checksum validation")
                (directory / name).unlink(missing_ok=True)
                shutil.copyfile(path, directory / name)
            manifest_name = group_prefix + "_manifest.json.zst"
            local_manifest = read_json(unpack_metadata(local / manifest_name, archive.metadata))
            local_manifest = validate_manifest(local_manifest, archive.id, manifest_name, hashes[manifest_name])
            local_hashes = protected_hashes(local_manifest)
            if not mismatches(local, local_hashes):
                remove_repair_backups(local, local_hashes, local_previous)
            damage, parity_damage = repair_verified_set(directory, prefix, hashes, settings,
                                                         link["parity_hashes"], in_place)
        remove_repair_backups(directory, hashes, receipt_previous)
        archive.metadata_damage.extend(receipt_damage + original_damage + damage + parity_damage)
        archive.checksums.update(hashes)
        validate_parity_hashes(receipt["data_parity"], group_prefix)
        archive.checksums.update(receipt["data_parity"])
        for name in receipt["members"]:
            archive.files[name] = directory / name
            if group_metadata(name):
                copies = original.copies.get(name, [])
                if len(copies) < 2 or any(not path.is_file() or path.is_symlink() or sha256(path) != hashes[name]
                                          for path in copies):
                    archive.metadata_damage.append(name)
        name = group_prefix + "_manifest.json.zst"
        manifest = read_json(unpack_metadata(directory / name, archive.metadata))
        archive.manifests.append(validate_manifest(manifest, archive.id, name, hashes[name]))
        link = receipt["previous"]
    if link is not None:
        raise IntegrityError("Metadata chain exceeds the completion marker's group count")
    archive.manifests.reverse()


def load_local(archive, original, in_place):
    """A surviving group can explain itself without the archive-wide catalog."""
    groups = {}
    for name in original:
        match = re.match(rf"archive-{archive.id}_parity-({ID})(?:_|\.)", name)
        if match:
            groups.setdefault(match[1], []).append(name)
    if not groups:
        raise IntegrityError("No local recovery groups found")
    print("Archive-wide metadata is unavailable; recovering independent local groups. "
          "Original backup completeness cannot be proved.", flush=True)
    archive.metadata_damage.append("archive-wide catalog unavailable")
    for parity_id, names in sorted(groups.items()):
        prefix = parity_prefix(archive.id, parity_id)
        if in_place:
            directory = original.root / parity_id[:2]
        else:
            directory = archive.metadata / f"local-{parity_id}"
            stage_existing(original, names, directory, writable=False)
        status = check_parity(directory, prefix)
        previous = None
        if status == 1:
            previous = {path.relative_to(directory) for path in directory.rglob("*")}
            if not in_place:
                for name in names:
                    if not name.endswith(".par2"):
                        (directory / name).unlink(missing_ok=True)
                stage_existing(original, [name for name in names if not name.endswith(".par2")], directory)
            if check_parity(directory, prefix, repair=True) != 0:
                raise IntegrityError(f"Cannot recover local metadata for {parity_id}")
        name = prefix + "_manifest.json.zst"
        if not (directory / name).is_file():
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
        stream = records[0]["stream"]
        if stream is not None:
            stream_id = stream["stream"]
            if not re.fullmatch(ID, stream_id) or stream["type"] not in ("tar", "file"):
                raise IntegrityError("Invalid source stream")
            if not isinstance(stream["size"], int) or stream["size"] < 0:
                raise IntegrityError("Invalid source size")
            if any(member["stream"] != stream_id for member in manifest["members"]):
                raise IntegrityError("Source stream and chunk IDs disagree")
            old = streams.get(stream_id)
            if old and any(old.get(field) != stream.get(field) for field in ("type", "size", "path")):
                raise IntegrityError("Conflicting stream descriptions")
            if old is None or "sha256" in stream:
                streams[stream_id] = stream
            if stream["type"] == "tar":
                if old is not None:
                    raise IntegrityError("TAR stream spans multiple groups")
                stream["inventory"] = records[1:]
        for entry in records[1:]:
            # A direct stream's full hash is added once its last group is read.
            if stream and stream["type"] == "file" and entry["path"] == stream["path"]:
                continue
            old = entries.setdefault(entry["path"], entry)
            if old != entry:
                raise IntegrityError(f"Conflicting source metadata: {entry['path']!r}")
    for stream in streams.values():
        if stream["type"] == "file":
            entries[stream["path"]] = stream
        if archive.complete and (not valid_digest(stream.get("sha256"))
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
            marker_names = completion_names(archive_id)
            complete, marker_damage = (None, [])
            if any(name in files for name in marker_names):
                complete, marker_damage = read_completion(archive_id, files)
            archive = Archive(archive_id, dict(files), complete, Path(temporary))
            archive.metadata_damage.extend(marker_damage)
            if complete:
                load_central(archive, files, in_place)
            else:
                load_local(archive, files, in_place)
            encryption = {manifest["encryption"] for manifest in archive.manifests}
            if len(encryption) != 1:
                raise IntegrityError("Groups disagree about encryption")
            archive.format = {"encryption": encryption.pop()}
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
    for name, copies in files.copies.items():
        local = stored_path(base, name)
        central = base / "metadata" / local.parent.name / name
        ordered = sorted(copies, key=lambda path: "metadata" in path.relative_to(base).parts)
        for number, path in enumerate(ordered):
            is_central = group_metadata(name) and (number > 0 or
                         len(copies) == 1 and "metadata" in path.relative_to(base).parts)
            target = central if is_central else local
            if path.is_symlink() or not path.is_file():
                raise IntegrityError(f"Archive member is not a regular file: {path}")
            if path.stat().st_dev != device:
                raise ArchiveError("In-place repair requires one filesystem")
            destinations = [target, local] if group_metadata(name) else [target]
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
            if archive.complete:
                for name in completion_names(selected):
                    path = Path(root) / "metadata" / name
                    if name in archive.metadata_damage:
                        write_json(path, archive.complete)
            else:
                print("Local groups repaired; no completion marker invented for an unproven full archive.")
    except (ArchiveError, OSError):
        print(f"In-place repair stopped after {completed} groups; changes already made remain.", flush=True)
        raise
    print(f"{selected}: repair complete ({completed} groups)")
