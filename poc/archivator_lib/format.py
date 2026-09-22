"""Version 1 filenames and the fixed PoC defaults."""

import re
import secrets
from base64 import b32encode
from dataclasses import dataclass
from pathlib import Path

from .common import ArchiveError, IntegrityError

ID = r"[a-z2-7]{20}"
ARCHIVE_NAME = re.compile(rf"archive-({ID})_")
DATAFILE_NAME = re.compile(
    rf"archive-(?P<archive>{ID})_supergroup-(?P<supergroup>{ID})_datagroup-(?P<datagroup>{ID})_"
    rf"dataset-(?P<dataset>{ID})_"
    r"(?:offset-(?P<offset>[0-9]{20})_)?length-(?P<length>[0-9]{12})"
    r"\.(?P<kind>raw|tar)(?P<compressed>\.zst)?(?P<encrypted>\.cms)?"
)


@dataclass(frozen=True)
class Settings:
    max_file_bytes: int = 256 * 1024 * 1024 - 1
    max_datagroup_bytes: int = 14 * 1024 * 1024 * 1024
    large_file_bytes: int | None = None
    waiting_datagroups: int = 4
    datagroup_close_percent: int = 95
    compression: bool = True
    par2: bool = True
    supergroup_par2: bool = True
    supergroup_datagroups: int = 5
    datagroup_loss_files: int = 0
    datagroup_bitrot_percent: int = 2
    supergroup_loss_datagroups: int = 1
    supergroup_bitrot_percent: int = 2

    @property
    def datagroup_par2(self):
        return self.par2 and bool(self.datagroup_loss_files or self.datagroup_bitrot_percent)

    @property
    def outer_par2(self):
        return self.par2 and self.supergroup_par2 and bool(self.supergroup_loss_datagroups or self.supergroup_bitrot_percent)

    def __post_init__(self):
        if not isinstance(self.compression, bool) or not isinstance(self.par2, bool):
            raise ArchiveError("Compression and PAR2 settings must be booleans")
        if not isinstance(self.supergroup_par2, bool):
            raise ArchiveError("Supergroup PAR2 setting must be a boolean")
        if not isinstance(self.supergroup_datagroups, int) or self.supergroup_datagroups < 1:
            raise ArchiveError("Supergroup datagroup count must be a positive integer")
        if any(type(value) is not int or value < 0
               for value in (self.datagroup_loss_files, self.supergroup_loss_datagroups)):
            raise ArchiveError("Loss counts must be nonnegative integers")
        if any(type(value) is not int or not 0 <= value <= 100
               for value in (self.datagroup_bitrot_percent, self.supergroup_bitrot_percent)):
            raise ArchiveError("Bitrot percentages must be integers from 0 to 100")
        limits = (self.max_file_bytes, self.max_datagroup_bytes)
        if self.large_file_bytes is not None:
            limits += (self.large_file_bytes,)
        if any(not isinstance(value, int) or value <= 0 for value in limits):
            raise ArchiveError("All byte limits must be positive integers")
        if not isinstance(self.waiting_datagroups, int) or self.waiting_datagroups < 0:
            raise ArchiveError("Waiting datagroup count must be a nonnegative integer")
        if not isinstance(self.datagroup_close_percent, int) or not 1 <= self.datagroup_close_percent <= 100:
            raise ArchiveError("Datagroup closing percentage must be an integer from 1 to 100")


def new_id():
    return b32encode(secrets.token_bytes(12)).decode("ascii").rstrip("=").lower()


def datafile_name(archive, datagroup, dataset, offset, length, encrypted, kind="raw", compressed=True, *, supergroup):
    if kind not in ("raw", "tar") or (kind == "tar" and offset != 0):
        raise ArchiveError("A TAR chunk must be a complete archive without an offset")
    coordinates = f"offset-{offset:020d}_" if kind == "raw" else ""
    name = (
        f"archive-{archive}_supergroup-{supergroup}_datagroup-{datagroup}_"
        f"dataset-{dataset}_{coordinates}length-{length:012d}.{kind}"
    )
    if compressed:
        name += ".zst"
    name = name + ".cms" if encrypted else name
    stored_path(Path("."), name)
    return name


def parse_datafile(name):
    name = name.lower()
    match = DATAFILE_NAME.fullmatch(name)
    if not match:
        raise IntegrityError(f"Invalid chunk filename: {name!r}")
    result = match.groupdict()
    if (result["offset"] is not None) != (result["kind"] == "raw"):
        raise IntegrityError("Only RAW chunk filenames must have an offset")
    result["offset"] = result["offset"] or "0"
    for field in ("offset", "length"):
        result[field] = int(result[field])
    result["encrypted"] = bool(result["encrypted"])
    result["compressed"] = bool(result["compressed"])
    return result


def datagroup_prefix(archive, supergroup, datagroup):
    return f"archive-{archive}_supergroup-{supergroup}_datagroup-{datagroup}"


def datagroup_metadata(name):
    return bool(re.fullmatch(rf"archive-{ID}_supergroup-{ID}_datagroup-{ID}_metadata_index-"
                             r"(?:datafiles(?:-spare)?\.json(?:\.zst)?|"
                             r"files(?:-spare)?\.jsonl(?:\.zst)?(?:\.cms)?)", name))


def primary_metadata_name(name):
    return name.replace("-spare.json", ".json", 1)


def spare_metadata_name(name):
    return primary_metadata_name(name).replace(".json", "-spare.json", 1)


def stored_path(root, name):
    relative = relative_stored_path(name)
    # A volume-root path also needs the three characters in X:\ and its NUL.
    if len(relative.as_posix()) > 256 or len(name) > 255:
        raise IntegrityError("Archive filename or relative path exceeds portable length limits")
    return Path(root) / relative


def relative_stored_path(name):
    """Canonical data/metadata destinations, also used for scratch recovery."""
    root = Path(".")
    match = re.match(rf"archive-{ID}_supergroup-({ID})(?:_|\.)", name)
    if not match:
        return root / name
    supergroup = match[1]
    base = root / "data" / supergroup[:2] / supergroup
    central = root / "metadata" / supergroup[:2] / supergroup
    datagroup = re.search(rf"_datagroup-({ID})(?:_|\.)", name)
    if datagroup:
        if (name != primary_metadata_name(name)
                or re.search(r"_metadata(?:\.vol[0-9]+\+[0-9]+)?\.par2$", name)
                or "_metadata_checksums.json" in name):
            return central / datagroup[1] / name
        return base / datagroup[1] / name
    if "_index-datagroups-spare.json" in name:
        return central / name
    if name.endswith(".par2"):
        return base / "parity" / name
    return base / "metadata" / name


def metadata_prefix(archive, supergroup, datagroup):
    # Reuse the datagroup's ID; central metadata protection needs no new ID.
    return datagroup_prefix(archive, supergroup, datagroup) + "_metadata"


def supergroup_prefix(archive, supergroup):
    return f"archive-{archive}_supergroup-{supergroup}"


def archive_filename(name, archive):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_.+\-]+", name):
        raise IntegrityError(f"Unsafe archive filename: {name!r}")
    if not name.startswith(f"archive-{archive}_"):
        raise IntegrityError(f"Filename belongs to another archive: {name!r}")
    return name
