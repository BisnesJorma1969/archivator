"""Version 1 filenames and the fixed PoC defaults."""

import re
import secrets
from dataclasses import dataclass

from .common import ArchiveError, IntegrityError

ID = r"[0-9a-f]{32}"
ARCHIVE_NAME = re.compile(rf"archive-({ID})_")
CHUNK_NAME = re.compile(
    rf"archive-(?P<archive>{ID})_parity-(?P<parity>{ID})_"
    rf"chunk-(?P<chunk>[0-9]{{4}})_stream-(?P<stream>{ID})_"
    r"offset-(?P<offset>[0-9]{20})_length-(?P<length>[0-9]{12})"
    r"\.zst(?P<encrypted>\.enc)?"
)


@dataclass(frozen=True)
class Settings:
    chunk_size: int = 256 * 1024 * 1024
    large_file_size: int = 256 * 1024 * 1024
    tar_size: int = 1024 * 1024 * 1024
    tar_entries: int = 100000
    parity_members: int = 8
    slice_size: int = 1024 * 1024

    def __post_init__(self):
        if any(value <= 0 for value in vars(self).values()):
            raise ArchiveError("All internal size settings must be positive")
        if self.slice_size % 4:
            raise ArchiveError("PAR2 slice size must be a multiple of four")
        if self.parity_members > 10000:
            raise ArchiveError("Too many members for four-digit chunk numbers")


def new_id():
    return secrets.token_hex(16)


def chunk_name(archive, parity, chunk, stream, offset, length, encrypted):
    name = (
        f"archive-{archive}_parity-{parity}_chunk-{chunk:04d}_"
        f"stream-{stream}_offset-{offset:020d}_length-{length:012d}.zst"
    )
    return name + ".enc" if encrypted else name


def parse_chunk(name):
    match = CHUNK_NAME.fullmatch(name)
    if not match:
        raise IntegrityError(f"Invalid chunk filename: {name!r}")
    result = match.groupdict()
    for field in ("chunk", "offset", "length"):
        result[field] = int(result[field])
    result["encrypted"] = bool(result["encrypted"])
    return result


def parity_prefix(archive, parity, metadata=False):
    prefix = f"archive-{archive}_parity-{parity}"
    return prefix + "_metadata" if metadata else prefix


def recovery_blocks(lengths, slice_size):
    total = sum(lengths)
    largest = max(lengths)
    # Integer ceilings avoid rounding down at large sizes. Four blocks allow
    # four volumes even for tiny sets; one extra block covers additional damage.
    twenty_percent = (total + 5 * slice_size - 1) // (5 * slice_size)
    largest_plus_quarter = (5 * largest + 4 * slice_size - 1) // (4 * slice_size)
    largest_blocks = (largest + slice_size - 1) // slice_size
    return max(4, twenty_percent, largest_plus_quarter, largest_blocks + 1)


def archive_filename(name, archive):
    if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9_.+\-]+", name):
        raise IntegrityError(f"Unsafe archive filename: {name!r}")
    if not name.startswith(f"archive-{archive}_"):
        raise IntegrityError(f"Filename belongs to another archive: {name!r}")
    return name
