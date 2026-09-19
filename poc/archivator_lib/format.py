"""Version 1 filenames and the fixed PoC defaults."""

import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from .common import ArchiveError, IntegrityError

ID = r"[0-9a-f]{32}"
ARCHIVE_NAME = re.compile(rf"archive-({ID})_")
CHUNK_NAME = re.compile(
    rf"archive-(?P<archive>{ID})_parity-(?P<parity>{ID})_"
    rf"chunk-(?P<chunk>[0-9]{{4,}})_stream-(?P<stream>{ID})_"
    r"(?:offset-(?P<offset>[0-9]{20})_)?length-(?P<length>[0-9]{12})"
    r"\.(?P<kind>raw|tar)(?P<compressed>\.zst)?(?P<encrypted>\.cms)?"
)


@dataclass(frozen=True)
class Settings:
    max_file_bytes: int = 256 * 1024 * 1024 - 1
    max_group_bytes: int = 14 * 1024 * 1024 * 1024
    slice_size: int = 1024 * 1024
    large_file_bytes: int | None = None
    waiting_groups: int = 4
    group_close_percent: int = 95
    compression: bool = True
    par2: bool = True

    def __post_init__(self):
        if not isinstance(self.compression, bool) or not isinstance(self.par2, bool):
            raise ArchiveError("Compression and PAR2 settings must be booleans")
        limits = (self.max_file_bytes, self.max_group_bytes, self.slice_size)
        if self.large_file_bytes is not None:
            limits += (self.large_file_bytes,)
        if any(not isinstance(value, int) or value <= 0 for value in limits):
            raise ArchiveError("All byte limits must be positive integers")
        if self.slice_size % 4:
            raise ArchiveError("PAR2 slice size must be a multiple of four")
        if not isinstance(self.waiting_groups, int) or self.waiting_groups < 0:
            raise ArchiveError("Waiting group count must be a nonnegative integer")
        if not isinstance(self.group_close_percent, int) or not 1 <= self.group_close_percent <= 100:
            raise ArchiveError("Group closing percentage must be an integer from 1 to 100")


def new_id():
    return secrets.token_hex(16)


def chunk_name(archive, parity, chunk, stream, offset, length, encrypted, kind="raw", compressed=True):
    if kind not in ("raw", "tar") or (kind == "tar" and offset != 0):
        raise ArchiveError("A TAR chunk must be a complete archive without an offset")
    coordinates = f"offset-{offset:020d}_" if kind == "raw" else ""
    name = (
        f"archive-{archive}_parity-{parity}_chunk-{chunk:04d}_"
        f"stream-{stream}_{coordinates}length-{length:012d}.{kind}"
    )
    if compressed:
        name += ".zst"
    return name + ".cms" if encrypted else name


def parse_chunk(name):
    match = CHUNK_NAME.fullmatch(name)
    if not match:
        raise IntegrityError(f"Invalid chunk filename: {name!r}")
    result = match.groupdict()
    if (result["offset"] is not None) != (result["kind"] == "raw"):
        raise IntegrityError("Only RAW chunk filenames must have an offset")
    result["offset"] = result["offset"] or "0"
    for field in ("chunk", "offset", "length"):
        result[field] = int(result[field])
    result["encrypted"] = bool(result["encrypted"])
    result["compressed"] = bool(result["compressed"])
    return result


def parity_prefix(archive, parity):
    return f"archive-{archive}_parity-{parity}"


def group_metadata(name):
    return bool(re.fullmatch(rf"archive-{ID}_parity-{ID}_metadata_index-"
                             r"(?:chunks(?:-spare)?\.json(?:\.zst)?|"
                             r"files(?:-spare)?\.jsonl(?:\.zst)?(?:\.cms)?)", name))


def primary_metadata_name(name):
    return name.replace("-spare.json", ".json", 1)


def spare_metadata_name(name):
    return primary_metadata_name(name).replace(".json", "-spare.json", 1)


def stored_path(root, name):
    """Canonical destinations; discovery also accepts flat or mixed layouts."""
    root = Path(root)
    match = re.match(rf"archive-{ID}_parity-({ID})(?:_|\.)", name)
    if match:
        if group_metadata(name) and name != primary_metadata_name(name):
            return root / "metadata" / match[1][:2] / name
        return root / match[1][:2] / name
    match = re.match(rf"archive-{ID}_metadata_parity-({ID})(?:_|\.)", name)
    if match:
        return root / "metadata" / match[1][:2] / name
    return root / "metadata" / name


def metadata_prefix(archive, parity):
    # Reuse the data group's ID; metadata protection needs no new random ID.
    return f"archive-{archive}_metadata_parity-{parity}"


def archive_filename(name, archive):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_.+\-]+", name):
        raise IntegrityError(f"Unsafe archive filename: {name!r}")
    if not name.startswith(f"archive-{archive}_"):
        raise IntegrityError(f"Filename belongs to another archive: {name!r}")
    return name
