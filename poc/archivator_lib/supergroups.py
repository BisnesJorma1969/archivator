"""Bounded, independent PAR2 sets protecting complete groups, not their PAR2 files."""

import hashlib
import json
import os
import re
import shutil
import struct
from contextlib import contextmanager
from pathlib import Path

from .common import BUFFER_SIZE, ArchiveError, IntegrityError, read_json, scratch, sha256, write_json
from .external import check_parity, create_parity
from .format import (ID, Settings, archive_filename, group_prefix, metadata_prefix,
                     new_id, spare_metadata_name, stored_path,
                     supergroup_prefix)
from .limits import ceil_div, check_files, parity_plan, stored_bound
from .metadata import catalog_root_digest, store_metadata, unpack_metadata
from .progress import progress


def index_name(archive_id, supergroup_id, compression):
    return supergroup_prefix(archive_id, supergroup_id) + "_metadata_index-groups.json" + (".zst" if compression else "")


def arrange_parity(root, paths, settings):
    """Pack recovery files into numbered media directories, without padding."""
    part = used = 0
    result = []
    for path in sorted(paths, key=lambda item: item.name):
        size = path.stat().st_size
        check_files([path], settings.max_file_bytes, settings.max_group_bytes)
        if used + size > settings.max_group_bytes:
            part += 1
            used = 0
        target = root / f"{part:04d}" / path.name
        target.parent.mkdir(parents=True, exist_ok=True)
        if path != target:
            os.replace(path, target)
        result.append(target)
        used += size
    return result


class SupergroupWriter:
    def __init__(self, root, archive_id, settings):
        self.root = root
        self.archive_id = archive_id
        self.settings = settings
        self.id = new_id()
        self.groups = []
        self.previous = None
        self.count = 0

    def add(self, group_id, paths, known_hashes):
        if not (self.settings.par2 and self.settings.supergroup_par2):
            return
        members = {}
        for path in paths:
            if path.suffix == ".par2":
                raise ArchiveError("Supergroup inputs must not contain group PAR2")
            digest = known_hashes.get(path.name)
            members[path.name] = {"size": path.stat().st_size, "sha256": digest or sha256(path)}
        self.groups.append({"group": group_id, "members": members})

    def finish(self):
        if not self.groups:
            self.id = new_id()
            return
        settings = self.settings
        name = index_name(self.archive_id, self.id, settings.compression)
        record = {"version": 1, "archive": self.archive_id, "supergroup": self.id,
                  "settings": vars(settings), "groups": self.groups, "previous": self.previous}
        # Reserve the plan and self-checksum fields before choosing slice/volume
        # counts. PAR2's exact output is checked again after generation.
        size = len(json.dumps(record, ensure_ascii=True, indent=2, sort_keys=True).encode("ascii")) + 2048
        index_bound = stored_bound(size, compression=settings.compression)
        if index_bound > settings.max_file_bytes or 2 * index_bound > settings.max_group_bytes:
            raise ArchiveError("Supergroup index exceeds byte limits; reduce --supergroup-groups")
        lengths = {str(stored_path(self.root, filename).relative_to(self.root)): item["size"]
                   for group in self.groups for filename, item in group["members"].items()}
        lengths[str(stored_path(self.root, name).relative_to(self.root))] = index_bound
        slice_size = settings.slice_size
        while True:
            group_blocks = [sum(ceil_div(item["size"], slice_size) for item in group["members"].values())
                            for group in self.groups]
            total_blocks = sum(group_blocks) + ceil_div(index_bound, slice_size)
            blocks = max(ceil_div(total_blocks, 5),
                         ceil_div(max(group_blocks) * settings.supergroup_margin_percent, 100),
                         max(group_blocks) + 1)
            if total_blocks <= 32768 and blocks <= 32768:
                plan = parity_plan(lengths, slice_size, settings.max_file_bytes, blocks=blocks)
                break
            slice_size *= 2
            if slice_size >= settings.max_file_bytes:
                raise ArchiveError("Supergroup PAR2 capacity exceeds file limit; reduce --supergroup-groups")
        record["par2"] = {"slice_size": slice_size, "blocks": blocks, "volumes": plan.volumes}
        record["marker_sha256"] = catalog_root_digest(record)
        target = stored_path(self.root, name)
        if target.exists():
            raise ArchiveError("Supergroup ID collision; refusing to overwrite its index")
        target.parent.mkdir(parents=True, exist_ok=True)
        plain = target.with_suffix("") if settings.compression else target
        write_json(plain, record)
        store_metadata(plain, self.root / ".tmp", compression=settings.compression)
        spare = stored_path(self.root, spare_metadata_name(name))
        spare.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(target, spare)
        check_files([target, spare], settings.max_file_bytes, settings.max_group_bytes)
        print(f"Protecting supergroup {self.id}: {len(self.groups)} groups; "
              f"{blocks:,} recovery blocks of {slice_size:,} bytes", flush=True)
        staging = self.root / ".tmp" / "supergroup-parity"
        staging.mkdir()
        prefix = supergroup_prefix(self.archive_id, self.id)
        paths = create_parity(self.root, prefix, list(lengths), slice_size, blocks, staging, plan.volumes)
        paths = arrange_parity(self.root / self.id / "parity", paths, settings)
        staging.rmdir()
        self.previous = {"supergroup": self.id, "sha256": sha256(target),
                         "parity_hashes": {path.name: sha256(path) for path in paths}}
        self.count += 1
        self.groups = []
        self.id = new_id()


def par2_members(paths, archive_id, supergroup_id):
    """Read standard PAR2 file-description packets when both indexes are lost.

    This decodes no FEC: par2cmdline does all repair. Packet MD5s reject damaged
    headers/records, and canonical-path checks prevent unsafe recovery paths.
    """
    members = {}
    expected = None
    set_id = None
    for path in paths:
        with path.open("rb") as source:
            size = path.stat().st_size
            while source.tell() + 64 <= size:
                start = source.tell()
                header = source.read(64)
                if header[:8] != b"PAR2\0PKT":
                    # Resynchronise after arbitrary corruption, not just bit flips.
                    source.seek(start + 1)
                    block = source.read(1024 * 1024)
                    position = block.find(b"PAR2\0PKT")
                    source.seek(start + 1 + (position if position >= 0 else max(1, len(block) - 7)))
                    continue
                length = struct.unpack_from("<Q", header, 8)[0]
                if length < 64 or length % 4 or start + length > size:
                    source.seek(start + 1)
                    continue
                kind = header[48:64].rstrip(b"\0")
                if kind not in (b"PAR 2.0\0Main", b"PAR 2.0\0FileDesc"):
                    source.seek(start + length)
                    continue
                if length > 16 * 1024 * 1024:
                    source.seek(start + 1)
                    continue
                body = source.read(length - 64)
                if hashlib.md5(header[32:] + body).digest() != header[16:32]:
                    source.seek(start + 1)
                    continue
                if set_id is not None and header[32:48] != set_id:
                    raise IntegrityError("Conflicting supergroup PAR2 recovery sets")
                set_id = header[32:48]
                if kind == b"PAR 2.0\0Main":
                    if len(body) < 12:
                        continue
                    count = struct.unpack_from("<I", body, 8)[0]
                    if count > 32768 or len(body) < 12 + 16 * count:
                        raise IntegrityError("Invalid PAR2 source file count")
                    expected = {body[12 + i * 16:28 + i * 16] for i in range(count)}
                elif len(body) >= 56:
                    relative = body[56:].rstrip(b"\0").decode("ascii")
                    name = Path(relative).name
                    archive_filename(name, archive_id)
                    if not name.startswith(supergroup_prefix(archive_id, supergroup_id) + "_"):
                        raise IntegrityError("Supergroup PAR2 refers to another supergroup")
                    if name.endswith(".par2") or stored_path(Path("."), name).as_posix() != relative:
                        raise IntegrityError("Invalid supergroup PAR2 member path")
                    members[body[:16]] = (name, {
                        "md5": body[16:32].hex(),
                        "size": struct.unpack_from("<Q", body, 48)[0],
                    })
                if expected and expected <= members.keys():
                    return dict(members[file_id] for file_id in sorted(expected))
    raise IntegrityError("No complete, valid supergroup PAR2 file list survives")


class SupergroupRecovery:
    """Keep only indexes in memory; stage one supergroup only when needed."""

    def __init__(self, archive_id, files, cache, in_place=False):
        self.archive_id = archive_id
        self.files = files.copy()
        self.original = files.copy()
        self.root = files.root
        self.cache = cache / "supergroups"
        self.cache.mkdir()
        self.in_place = in_place
        self.records = {}
        self.by_group = {}
        self.links = {}
        self.damage = []

    def parity_files(self, supergroup_id):
        prefix = supergroup_prefix(self.archive_id, supergroup_id)
        pattern = re.compile(re.escape(prefix) + r"(?:\.vol[0-9]+\+[0-9]+)?\.par2")
        return [path for name, path in self.files.items()
                if pattern.fullmatch(name) and path.is_file() and not path.is_symlink()]

    def valid_index(self, path, supergroup_id, digest=None):
        if path is None or not path.is_file() or path.is_symlink():
            raise IntegrityError("Missing supergroup index")
        if digest is not None and sha256(path) != digest:
            raise IntegrityError("Supergroup index checksum mismatch")
        record = read_json(unpack_metadata(path, self.cache))
        if (record["version"] != 1 or record["archive"] != self.archive_id
                or record["supergroup"] != supergroup_id
                or record["marker_sha256"] != catalog_root_digest(record)):
            raise IntegrityError("Invalid supergroup index")
        settings = Settings(**record["settings"])
        if not settings.par2 or not settings.supergroup_par2:
            raise IntegrityError("Unexpected supergroup protection")
        if not 1 <= len(record["groups"]) <= settings.supergroup_groups:
            raise IntegrityError("Invalid supergroup group count")
        groups = set()
        names = set()
        for group in record["groups"]:
            gid = group["group"]
            if not isinstance(gid, str) or not re.fullmatch(ID, gid) or gid in groups:
                raise IntegrityError("Invalid or duplicate group in supergroup")
            groups.add(gid)
            for name, item in group["members"].items():
                archive_filename(name, self.archive_id)
                prefixes = (group_prefix(self.archive_id, supergroup_id, gid),
                            metadata_prefix(self.archive_id, supergroup_id, gid))
                if (not name.startswith(tuple(prefix + "_" for prefix in prefixes))
                        or name.endswith(".par2") or name in names
                        or not isinstance(item["size"], int) or not 0 <= item["size"] <= settings.max_file_bytes
                        or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])):
                    raise IntegrityError("Invalid protected supergroup member")
                stored_path(Path("."), name)
                names.add(name)
        plan = record["par2"]
        if (not isinstance(plan["slice_size"], int) or plan["slice_size"] <= 0 or plan["slice_size"] % 4
                or not 1 <= plan["blocks"] <= 32768 or not 1 <= plan["volumes"] <= plan["blocks"]):
            raise IntegrityError("Invalid supergroup PAR2 plan")
        return record

    def load(self, catalog_root):
        self.expected_count = catalog_root["supergroups"] if catalog_root else None
        pending = []
        if catalog_root and catalog_root["last_supergroup"]:
            pending.append(catalog_root["last_supergroup"])
        pattern = re.compile(rf"archive-{self.archive_id}_supergroup-({ID})(?:_metadata_index-groups|\.)")
        discovered = {match[1] for name in self.files if (match := pattern.match(name))}
        visited = set()
        while pending or discovered - visited:
            link = pending.pop() if pending else {"supergroup": min(discovered - visited)}
            sid = link["supergroup"]
            if not isinstance(sid, str) or not re.fullmatch(ID, sid):
                raise IntegrityError("Invalid supergroup chain link")
            if sid in visited:
                raise IntegrityError("Supergroup chain contains a cycle or duplicate")
            visited.add(sid)
            self.links[sid] = link
            prefix = supergroup_prefix(self.archive_id, sid)
            record = None
            for compressed in (False, True):
                primary = index_name(self.archive_id, sid, compressed)
                for name in (primary, spare_metadata_name(primary)):
                    try:
                        candidate = self.valid_index(self.files.get(name), sid, link.get("sha256"))
                    except (ArchiveError, OSError, ValueError, TypeError, KeyError):
                        continue
                    if record is not None and record != candidate:
                        raise IntegrityError("Conflicting supergroup indexes")
                    record = candidate
                    self.files[primary] = self.files[name]
            if record is None:
                try:
                    record = self.bootstrap(sid, link.get("sha256"))
                except (ArchiveError, OSError, ValueError, TypeError, KeyError) as error:
                    self.damage.append(prefix + " (index unavailable)")
                    print(f"Supergroup {sid}: index recovery unavailable: {error}", flush=True)
                    continue
            self.records[sid] = record
            for group in record["groups"]:
                gid = group["group"]
                if gid in self.by_group:
                    raise IntegrityError("Group belongs to more than one supergroup")
                self.by_group[gid] = sid
            if record["previous"] is not None:
                pending.append(record["previous"])
            primary = index_name(self.archive_id, sid, record["settings"]["compression"])
            digest = link.get("sha256") or sha256(self.files[primary])
            for name in (primary, spare_metadata_name(primary)):
                path = self.original.get(name)
                if path is None or not path.is_file() or sha256(path) != digest:
                    self.damage.append(name)
            hashes = link.get("parity_hashes", {})
            if hashes:
                from .recovery import validate_parity_hashes
                validate_parity_hashes(hashes, prefix, True)
                for name, digest in hashes.items():
                    path = self.files.get(name)
                    if path is None or not path.is_file() or sha256(path) != digest:
                        self.damage.append(name)
            elif len(self.parity_files(sid)) != record["par2"]["volumes"] + 1:
                self.damage.append(prefix + " (missing PAR2 files)")
        if catalog_root and len(self.records) != catalog_root["supergroups"]:
            self.damage.append("incomplete supergroup catalog")

    def protected(self, record):
        hashes = {name: item["sha256"] for group in record["groups"] for name, item in group["members"].items()}
        name = index_name(self.archive_id, record["supergroup"], record["settings"]["compression"])
        hashes[name] = self.links[record["supergroup"]].get("sha256") or sha256(self.files[name])
        return hashes

    def save_metadata(self, base, names):
        for name in names:
            if "_chunk-" in name or name.endswith(".par2"):
                continue
            source = stored_path(base, name)
            if not source.is_file():
                continue
            target = source if self.in_place else self.cache / name
            if target != source:
                shutil.copyfile(source, target)
            self.files[name] = target

    def local_first(self, base, group_ids, supergroup_id):
        for gid in group_ids:
            for prefix in (group_prefix(self.archive_id, supergroup_id, gid),
                           metadata_prefix(self.archive_id, supergroup_id, gid)):
                directory = stored_path(base, prefix + ".par2").parent
                if not directory.exists():
                    continue
                status = check_parity(directory, prefix)
                if status == 1:
                    print(f"Repairing group {gid} before supergroup recovery", flush=True)
                    check_parity(directory, prefix, repair=True)

    @contextmanager
    def parity_directory(self, sid):
        """par2cmdline discovers recovery volumes beside the chosen index.

        Explicit repair may rename volumes temporarily, never copy/link them.
        The common directory remains discoverable even after an interruption.
        """
        paths = self.parity_files(sid)
        moved = []
        try:
            for path in paths:
                target = stored_path(self.root, path.name)
                target.parent.mkdir(parents=True, exist_ok=True)
                if path != target:
                    if target.exists():
                        raise IntegrityError("Duplicate supergroup recovery volume")
                    path.rename(target)
                    moved.append((path, target))
                self.files[path.name] = target
            yield [self.files[path.name] for path in paths]
        finally:
            for original, target in reversed(moved):
                if target.exists():
                    target.rename(original)
                    self.files[original.name] = original

    @contextmanager
    def workspace(self, sid, names, hashes=None):
        from .recovery import stage_existing
        if self.in_place:
            # Recover intentional metadata duplicates without attempting FEC.
            for name in names:
                if "_chunk-" in name or name.endswith(".par2"):
                    continue
                target = stored_path(self.root, name)
                source = self.files.get(name)
                digest = (hashes or {}).get(name)
                if (source and source != target and source.is_file() and digest
                        and sha256(source) == digest
                        and (not target.is_file() or sha256(target) != digest)):
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.unlink(missing_ok=True)
                    shutil.copyfile(source, target)
            with self.parity_directory(sid):
                yield self.root
            return
        prefix = supergroup_prefix(self.archive_id, sid)
        # Include group/central PAR2 as well: fix locally recoverable failures
        # before charging any remaining damage against the outer capacity.
        extras = [name for name in self.files if name.startswith(prefix + "_") and name.endswith(".par2")]
        extras.extend(path.name for path in self.parity_files(sid))
        with scratch("supergroup-") as temporary:
            base = Path(temporary)
            stage_existing(self.files, list(dict.fromkeys([*names, *extras])), base,
                           hashes, archive_layout=True)
            yield base

    def bootstrap(self, sid, digest):
        """Both index copies may be recovered using PAR2's own file inventory."""
        paths = self.parity_files(sid)
        names = par2_members(paths, self.archive_id, sid)
        prefix = supergroup_prefix(self.archive_id, sid)
        self.damage.append(prefix + " (both index copies lost)")
        verified = {}
        if not self.in_place:
            # PAR2's own whole-file checksums identify healthy inputs even when
            # our SHA-256 inventory is lost. Only damaged/unknown inputs need
            # writable copies; do not copy an entire intact supergroup.
            for number, (name, info) in enumerate(names.items(), 1):
                path = self.files.get(name)
                if path is None or not path.is_file() or path.stat().st_size != info["size"]:
                    continue
                md5 = hashlib.md5(usedforsecurity=False)
                sha = hashlib.sha256()
                with path.open("rb") as source:
                    while data := source.read(BUFFER_SIZE):
                        progress.update(f"Checking PAR2 source checksums: {number:,}/{len(names):,} files")
                        md5.update(data)
                        sha.update(data)
                if md5.hexdigest() == info["md5"]:
                    verified[name] = sha.hexdigest()
        with self.workspace(sid, names, verified) as base:
            gids = {match[1] for name in names if (match := re.search(rf"_group-({ID})_", name))}
            self.local_first(base, gids, sid)
            directory = stored_path(base, prefix + ".par2").parent
            if check_parity(directory, prefix, data_directory=base) == 1:
                check_parity(directory, prefix, repair=True, data_directory=base)
            for name in names:
                if "_metadata_index-groups.json" in name:
                    record = self.valid_index(stored_path(base, name), sid, digest)
                    self.save_metadata(base, names)
                    return record
        raise IntegrityError("Supergroup index could not be reconstructed")

    @contextmanager
    def recover(self, sid):
        from .recovery import mismatches, remove_repair_backups
        record = self.records[sid]
        hashes = self.protected(record)
        with self.workspace(sid, hashes, hashes) as base:
            # Restrict backup-file bookkeeping to this supergroup's source
            # directories, not the potentially enormous archive as a whole.
            directories = {stored_path(base, name).parent for name in hashes}
            before = {directory: {Path(path.name) for path in directory.iterdir()}
                      if directory.is_dir() else set() for directory in directories}
            self.local_first(base, [group["group"] for group in record["groups"]], sid)
            damage = mismatches(base, hashes, archive_layout=True)
            if damage:
                prefix = supergroup_prefix(self.archive_id, sid)
                directory = stored_path(base, prefix + ".par2").parent
                print(f"Recovering supergroup {sid}: {len(damage)} remaining damaged/missing files", flush=True)
                if check_parity(directory, prefix, data_directory=base) != 1:
                    raise IntegrityError(f"Insufficient supergroup PAR2 for {sid}")
                if check_parity(directory, prefix, repair=True, data_directory=base) != 0:
                    raise IntegrityError(f"Supergroup PAR2 recovery failed for {sid}")
            if mismatches(base, hashes, archive_layout=True):
                raise IntegrityError("Supergroup recovery failed stored SHA-256 checks")
            for directory, previous_names in before.items():
                remove_repair_backups(directory, hashes, previous_names)
            yield base

    def recover_metadata(self):
        """Retain repaired metadata only; discard each bounded payload workspace."""
        for sid, record in self.records.items():
            hashes = self.protected(record)
            damaged = [name for name, digest in hashes.items() if "_chunk-" not in name and
                       (name not in self.files or not self.files[name].is_file() or sha256(self.files[name]) != digest)]
            if not damaged:
                continue
            self.damage.extend(damaged)
            try:
                with self.recover(sid) as base:
                    self.save_metadata(base, hashes)
            except IntegrityError as error:
                print(f"Supergroup metadata recovery incomplete: {error}", flush=True)

    def restore_group(self, group_id, directory):
        sid = self.by_group.get(group_id)
        if sid is None:
            raise IntegrityError(f"No usable supergroup protects group {group_id}")
        prefix = group_prefix(self.archive_id, sid, group_id)
        with self.recover(sid) as base:
            for name, digest in self.protected(self.records[sid]).items():
                if not name.startswith(prefix + "_") or "-spare.json" in name:
                    continue
                target = directory / name
                if target.is_file() and sha256(target) == digest:
                    continue
                source = stored_path(base, name)
                if source != target:
                    target.unlink(missing_ok=True)
                    shutil.copyfile(source, target)

    def repair_all(self):
        if self.expected_count is not None and len(self.records) != self.expected_count:
            raise IntegrityError("Missing supergroup indexes prevent complete redundancy repair")
        for sid, record in self.records.items():
            settings = Settings(**record["settings"])
            hashes = self.protected(record)
            with self.recover(sid) as base:
                self.save_metadata(base, hashes)
            name = index_name(self.archive_id, sid, settings.compression)
            primary = stored_path(self.root, name)
            spare = stored_path(self.root, spare_metadata_name(name))
            for path in (primary, spare):
                if not path.is_file() or sha256(path) != hashes[name]:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    source = self.files[name]
                    if source == path:
                        raise IntegrityError("No healthy supergroup index copy")
                    path.unlink(missing_ok=True)
                    shutil.copyfile(source, path)
            prefix = supergroup_prefix(self.archive_id, sid)
            paths = self.parity_files(sid)
            expected = self.links[sid].get("parity_hashes", {})
            damaged = not expected or any(name not in self.files or not self.files[name].is_file()
                          or sha256(self.files[name]) != digest for name, digest in expected.items())
            with self.parity_directory(sid) as gathered:
                directory = stored_path(self.root, prefix + ".par2").parent
                status = check_parity(directory, prefix, data_directory=self.root) if gathered else 2
            if damaged or len(paths) != record["par2"]["volumes"] + 1 or status:
                plan = record["par2"]
                names = [str(stored_path(self.root, name).relative_to(self.root)) for name in hashes]
                print(f"Regenerating supergroup PAR2 {sid} from verified inputs", flush=True)
                with scratch("supergroup-parity-") as temporary:
                    fresh = create_parity(self.root, prefix, names, plan["slice_size"], plan["blocks"],
                                          Path(temporary), plan["volumes"])
                    for path in fresh:
                        if expected and expected.get(path.name) != sha256(path):
                            raise IntegrityError("Regenerated supergroup PAR2 differs from recorded checksums")
                    for path in paths:
                        path.unlink()
                    paths = arrange_parity(self.root / sid / "parity", fresh, settings)
            else:
                paths = arrange_parity(self.root / sid / "parity", paths, settings)
            self.files.update({path.name: path for path in paths})
