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
    r"offset-(?P<offset>[0-9]{20})_length-(?P<length>[0-9]{12})"
    r"\.zst(?P<encrypted>\.cms)?"
)


@dataclass(frozen=True)
class Settings:
    max_file_bytes: int = 256 * 1024 * 1024 - 1
    max_group_bytes: int = 14 * 1024 * 1024 * 1024
    slice_size: int = 1024 * 1024

    def __post_init__(self):
        if any(not isinstance(value, int) or value <= 0 for value in vars(self).values()):
            raise ArchiveError("All byte limits must be positive integers")
        if self.slice_size % 4:
            raise ArchiveError("PAR2 slice size must be a multiple of four")


def new_id():
    return secrets.token_hex(16)


def chunk_name(archive, parity, chunk, stream, offset, length, encrypted):
    name = (
        f"archive-{archive}_parity-{parity}_chunk-{chunk:04d}_"
        f"stream-{stream}_offset-{offset:020d}_length-{length:012d}.zst"
    )
    return name + ".cms" if encrypted else name


def parse_chunk(name):
    match = CHUNK_NAME.fullmatch(name)
    if not match:
        raise IntegrityError(f"Invalid chunk filename: {name!r}")
    result = match.groupdict()
    for field in ("chunk", "offset", "length"):
        result[field] = int(result[field])
    result["encrypted"] = bool(result["encrypted"])
    return result


def parity_prefix(archive, parity):
    return f"archive-{archive}_parity-{parity}"


def stored_path(root, name):
    """Canonical destinations; discovery also accepts flat or mixed layouts."""
    root = Path(root)
    match = re.match(rf"archive-{ID}_parity-({ID})(?:_|\.)", name)
    if match:
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
