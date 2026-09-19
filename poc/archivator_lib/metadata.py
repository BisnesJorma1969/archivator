"""Compressed metadata, identical catalog copies, and bounded checksum roots."""

import hashlib
import json
import os
import shutil
from pathlib import Path

from .common import ArchiveError, IntegrityError, sha256, write_json
from .external import decrypt, encrypt, executable, run, create_parity
from .format import metadata_prefix, spare_metadata_name, stored_path
from .limits import check_files, parity_plan

UNCOMPRESSED_METADATA_SUFFIXES = (
    "_metadata_catalog-root.json", "_metadata_catalog-root-spare.json",
    "_format.txt", "_recipient.pem",
)


class ConflictingRoots(IntegrityError):
    """Two self-consistent roots cannot be resolved by an unsigned PAR2 set."""


def catalog_root_names(archive_id):
    return [f"archive-{archive_id}_metadata_catalog-root.json",
            f"archive-{archive_id}_metadata_catalog-root-spare.json"]


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def catalog_root_digest(root):
    payload = {key: value for key, value in root.items() if key != "marker_sha256"}
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def store_metadata(path, staging=None, certificate=None, compression=True):
    """Optionally compress by role, then optionally encrypt source-name metadata exactly once."""
    path = Path(path)
    if path.suffix in (".zst", ".cms") or path.name.endswith(UNCOMPRESSED_METADATA_SUFFIXES):
        return path.name
    staging = staging or path.parent / ".tmp"
    staging.mkdir(mode=0o700, exist_ok=True)
    encoded = path
    if compression:
        encoded = staging / (path.name + ".zst")
        run([executable("zstd"), "-q", "-3", "--single-thread", "--check",
             str(path), "-o", str(encoded)], activity="Compressing metadata")
    encoded.chmod(0o600)
    if certificate:
        encrypted = encoded.with_name(encoded.name + ".cms")
        encrypt(encoded, encrypted, certificate)
        if encoded != path:
            encoded.unlink()
        encoded = encrypted
    destination = path.with_name(encoded.name)
    if encoded != destination:
        os.replace(encoded, destination)
    if destination != path:
        path.unlink()
    return destination.name


def unpack_metadata(path, destination=None, key=None, certificate=None):
    """Only verified bytes reach here; decrypted metadata stays in private scratch."""
    path = Path(path)
    destination = Path(destination or path.parent)
    compressed = path
    if path.suffix == ".cms":
        if key is None:
            raise ArchiveError("Encrypted source metadata requires --decrypt-key")
        compressed = destination / path.with_suffix("").name
        decrypt(path, compressed, key, certificate)
    if compressed.suffix != ".zst":
        return compressed
    target = destination / compressed.with_suffix("").name
    target.unlink(missing_ok=True)
    run([executable("zstd"), "-qd", str(compressed), "-o", str(target)],
        activity="Decompressing verified metadata")
    if path.suffix == ".cms":
        compressed.unlink()
    return target


class MetadataWriter:
    """One small central recovery set per data group, linked by SHA-256.

    Each protected receipt covers the preceding receipt and its PAR2 files.
    Only the final link lives in the two small catalog-root markers. Thus neither
    a million groups nor their checksum list makes a giant bootstrap file.
    """

    def __init__(self, archive, archive_id, settings):
        self.archive = archive
        self.archive_id = archive_id
        self.settings = settings
        self.previous = None
        self.count = 0
        self.extra = []
        from .supergroups import SupergroupWriter
        self.supergroups = SupergroupWriter(archive, archive_id, settings)

    def add(self, supergroup_id, group_id, metadata, group_parity):
        prefix = metadata_prefix(self.archive_id, supergroup_id, group_id)
        destination = stored_path(self.archive, prefix + "_checksums.json").parent
        destination.mkdir(parents=True, exist_ok=True)
        members = {}
        check_files([*metadata, *self.extra], self.settings.max_file_bytes, self.settings.max_group_bytes)
        for path in [*metadata, *self.extra]:
            name = path.name
            if path in self.extra:
                role = "recipient.pem" if path.suffix == ".pem" else "format.txt"
                name = prefix + "_" + role
            else:
                name = spare_metadata_name(name)
            target = destination / name
            # This is the requested second metadata copy, not PAR2 staging.
            shutil.copyfile(path, target)
            members[name] = {"sha256": sha256(path), "size": path.stat().st_size}
        receipt = {
            "version": 1, "archive": self.archive_id, "group": group_id, "supergroup": supergroup_id,
            "previous": self.previous, "members": members,
            "group_parity": group_parity,
        }
        name = prefix + "_checksums.json"
        staging_root = self.archive / ".tmp"
        write_json(staging_root / name, receipt)
        name = store_metadata(staging_root / name, staging_root, compression=self.settings.compression)
        check_files([staging_root / name], self.settings.max_file_bytes, self.settings.max_group_bytes)
        os.replace(staging_root / name, destination / name)
        lengths = {name: (destination / name).stat().st_size for name in [*members, name]}
        plan = parity_plan(lengths, self.settings.slice_size, self.settings.max_file_bytes, self.settings.par2)
        if sum(lengths.values()) + plan.total_bytes > self.settings.max_group_bytes:
            raise ArchiveError("Central metadata recovery set exceeds group budget")
        staging = self.archive / ".tmp" / "central-parity"
        staging.mkdir()
        files = []
        if self.settings.par2:
            files = create_parity(destination, prefix, list(lengths), self.settings.slice_size,
                                  plan.blocks, staging, plan.volumes)
        check_files([*(destination / name for name in lengths), *files],
                    self.settings.max_file_bytes, self.settings.max_group_bytes)
        hashes = {}
        for path in files:
            hashes[path.name] = sha256(path)
            os.replace(path, destination / path.name)
        staging.rmdir()
        self.previous = {"group": group_id, "supergroup": supergroup_id, "receipt_sha256": sha256(destination / name),
                         "parity_hashes": hashes}
        self.count += 1
        self.extra = []
        return [destination / name for name in lengths]

    def finish(self):
        marker = {"version": 1, "archive": self.archive_id, "groups": self.count,
                  "settings": vars(self.settings), "last": self.previous,
                  "supergroups": self.supergroups.count, "last_supergroup": self.supergroups.previous}
        marker["marker_sha256"] = catalog_root_digest(marker)
        directory = self.archive / "metadata"
        directory.mkdir(exist_ok=True)
        paths = [self.archive / ".tmp" / name for name in catalog_root_names(self.archive_id)]
        for path in paths:
            write_json(path, marker)
        check_files(paths, self.settings.max_file_bytes, self.settings.max_group_bytes)
        if self.settings.par2:
            from .bootstrap import create_root_parity
            parity = create_root_parity(self.archive / ".tmp", self.archive_id, self.settings)
            for path in parity:
                os.replace(path, directory / path.name)
        for path in paths:
            os.replace(path, directory / path.name)
