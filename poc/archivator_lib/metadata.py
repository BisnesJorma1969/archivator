"""Compressed metadata, identical catalog copies, and bounded checksum roots."""

import hashlib
import json
import os
import shutil
from pathlib import Path

from .common import ArchiveError, IntegrityError, sha256, write_json
from .external import decrypt, encrypt, executable, run, create_parity
from .format import metadata_prefix, spare_metadata_name, stored_path
from .limits import check_files, parity_plan, plan_reservation, stored_bound

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
    if path.suffix.lower() == ".cms":
        if key is None:
            raise ArchiveError("Encrypted source metadata requires --decrypt-key")
        compressed = destination / path.with_suffix("").name.lower()
        decrypt(path, compressed, key, certificate)
    if compressed.suffix.lower() != ".zst":
        return compressed
    target = destination / compressed.with_suffix("").name.lower()
    target.unlink(missing_ok=True)
    run([executable("zstd"), "-qd", str(compressed), "-o", str(target)],
        activity="Decompressing verified metadata")
    if path.suffix.lower() == ".cms":
        compressed.unlink()
    return target


class MetadataWriter:
    """One small central recovery set per datagroup, linked by SHA-256.

    Each protected receipt covers the preceding receipt and its PAR2 files.
    Only the final link lives in the two small catalog-root markers. Thus neither
    a million datagroups nor their checksum list makes a giant bootstrap file.
    """

    def __init__(self, archive, archive_id, settings):
        self.archive = archive
        self.archive_id = archive_id
        self.settings = settings
        self.previous = None
        self.count = 0
        self.bootstrap_files = []
        from .supergroups import SupergroupWriter
        self.supergroups = SupergroupWriter(archive, archive_id, settings)

    def add(self, supergroup_id, datagroup_id, metadata, datagroup_parity):
        prefix = metadata_prefix(self.archive_id, supergroup_id, datagroup_id)
        destination = stored_path(self.archive, prefix + "_checksums.json").parent
        destination.mkdir(parents=True, exist_ok=True)
        members = {}
        check_files(metadata, self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        for path in metadata:
            name = spare_metadata_name(path.name)
            target = destination / name
            # This is the requested second metadata copy, not PAR2 staging.
            shutil.copyfile(path, target)
            members[name] = {"sha256": sha256(path), "size": path.stat().st_size}
        receipt = {
            "version": 1, "archive": self.archive_id, "datagroup": datagroup_id, "supergroup": supergroup_id,
            "previous": self.previous, "members": members,
            "datagroup_parity": datagroup_parity,
            "par2": plan_reservation(self.settings.max_file_bytes) if self.settings.par2 else None,
        }
        name = prefix + "_checksums.json"
        staging_root = self.archive / ".tmp"
        stored_name = name + (".zst" if self.settings.compression else "")
        lengths = {name: item["size"] for name, item in members.items()}
        receipt_size = len(json.dumps(receipt, ensure_ascii=True, indent=2, sort_keys=True).encode("ascii")) + 1
        lengths[stored_name] = stored_bound(receipt_size, compression=self.settings.compression)
        plan = parity_plan(lengths, self.settings.max_file_bytes, self.settings.par2,
                           max_set_bytes=self.settings.max_datagroup_bytes)
        receipt["par2"] = plan.record() if self.settings.par2 else None
        write_json(staging_root / name, receipt)
        name = store_metadata(staging_root / name, staging_root, compression=self.settings.compression)
        check_files([staging_root / name], self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        os.replace(staging_root / name, destination / name)
        lengths = {name: (destination / name).stat().st_size for name in [*members, name]}
        if sum(lengths.values()) + plan.total_bytes > self.settings.max_datagroup_bytes:
            raise ArchiveError("Central metadata recovery set exceeds datagroup budget")
        staging = self.archive / ".tmp" / "central-parity"
        staging.mkdir()
        files = []
        if self.settings.par2:
            files = create_parity(destination, prefix, list(lengths), plan.slice_size,
                                  plan.blocks, staging, plan.volumes)
        check_files([*(destination / name for name in lengths), *files],
                    self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        hashes = {}
        for path in files:
            hashes[path.name] = sha256(path)
            os.replace(path, destination / path.name)
        staging.rmdir()
        self.previous = {"datagroup": datagroup_id, "supergroup": supergroup_id, "receipt_sha256": sha256(destination / name),
                         "parity_hashes": hashes}
        self.count += 1
        return [destination / name for name in lengths]

    def finish(self):
        marker = {"version": 1, "archive": self.archive_id, "datagroups": self.count,
                  "settings": vars(self.settings), "last": self.previous,
                  "supergroups": self.supergroups.count, "last_supergroup": self.supergroups.previous,
                  "bootstrap_files": {path.name: {"size": path.stat().st_size, "sha256": sha256(path)}
                                      for path in self.bootstrap_files}}
        marker["par2"] = plan_reservation(self.settings.max_file_bytes) if self.settings.par2 else None
        marker["marker_sha256"] = "0" * 64
        if self.settings.par2:
            from .bootstrap import root_lengths
            plan = parity_plan(root_lengths(self.archive_id, marker), self.settings.max_file_bytes,
                               max_set_bytes=self.settings.max_datagroup_bytes, protect_all=True)
            marker["par2"] = plan.record()
        marker["marker_sha256"] = catalog_root_digest(marker)
        directory = self.archive
        paths = [self.archive / ".tmp" / name for name in catalog_root_names(self.archive_id)]
        for path in paths:
            write_json(path, marker)
        check_files([*paths, *self.bootstrap_files], self.settings.max_file_bytes, self.settings.max_datagroup_bytes)
        if self.settings.par2:
            from .bootstrap import create_root_parity
            parity = create_root_parity(self.archive / ".tmp", self.archive_id, self.settings)
            for path in parity:
                os.replace(path, directory / path.name)
        for path in [*self.bootstrap_files, *paths]:
            os.replace(path, directory / path.name)
