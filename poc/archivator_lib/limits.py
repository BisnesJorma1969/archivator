"""Conservative byte budgets for independently compressed files and PAR2 sets."""

from dataclasses import dataclass

from .common import ArchiveError


def ceil_div(value, divisor):
    return (value + divisor - 1) // divisor


def stored_bound(plaintext, encryption_overhead=0, compression=True):
    if not compression:
        return plaintext + encryption_overhead
    # zstd can store incompressible blocks verbatim. This deliberately generous
    # allowance covers block/frame headers and checksums, including tiny frames.
    return plaintext + ceil_div(plaintext, 128) + 1024 + encryption_overhead


def input_limit(output_limit, encryption_overhead=0, compression=True):
    available = output_limit - (1024 if compression else 0) - encryption_overhead
    if available <= 0:
        raise ArchiveError("File limit leaves no room for compression/encryption headers")
    return available * 128 // 129 if compression else available


def recovery_blocks(lengths, slice_size):
    largest = max(lengths)
    return max(ceil_div(sum(lengths), 5 * slice_size),
               ceil_div(5 * largest, 4 * slice_size),
               ceil_div(largest, slice_size) + 1)


@dataclass(frozen=True)
class ParityPlan:
    blocks: int
    volumes: int
    total_bytes: int
    largest_file: int


def parity_plan(members, slice_size, max_file_bytes, enabled=True, blocks=None):
    """Bound par2cmdline's uniform-volume output, including repeated packets.

    members maps stored relative names to byte lengths. Recovery packets use
    68 header bytes. Critical packets are repeated bit_length(blocks_in_volume)
    times; the index has one copy. Allow 1024 bytes for each creator packet.
    The final output is checked as well, before anything is published.
    """
    if not enabled:
        return ParityPlan(0, 0, 0, 0)
    lengths = list(members.values())
    slices = sum(ceil_div(length, slice_size) for length in lengths)
    if blocks is None:
        blocks = recovery_blocks(lengths, slice_size)
    if slices > 32768 or blocks > 32768:
        raise ArchiveError("PAR2 block capacity exceeded; close the group or increase slice size")
    critical = 76 + 16 * len(members)
    for name, length in members.items():
        critical += 120 + ceil_div(len(name.encode("utf-8")), 4) * 4
        critical += 80 + 20 * ceil_div(length, slice_size)
    index_size = critical + 1024
    if index_size > max_file_bytes:
        raise ArchiveError("PAR2 index would exceed the file limit")

    def volume_size(count):
        return count * (slice_size + 68) + count.bit_length() * critical + 1024

    if volume_size(1) > max_file_bytes:
        raise ArchiveError("A PAR2 slice and its metadata do not fit the file limit")
    low, high = 1, blocks
    while low < high:
        middle = (low + high) // 2
        if volume_size(ceil_div(blocks, middle)) <= max_file_bytes:
            high = middle
        else:
            low = middle + 1
    volumes = low
    base, extra = divmod(blocks, volumes)
    total = index_size + extra * volume_size(base + 1) + (volumes - extra) * volume_size(base)
    return ParityPlan(blocks, volumes, total, max(index_size, volume_size(ceil_div(blocks, volumes))))


def check_files(paths, max_file_bytes, max_group_bytes):
    total = 0
    for path in paths:
        if not path.name.isascii() or len(path.name) > 255:
            raise ArchiveError("Output filename exceeds portable ASCII component limits")
        size = path.stat().st_size
        if size > max_file_bytes:
            raise ArchiveError(f"Output exceeds file limit: {path.name} ({size:,} > {max_file_bytes:,})")
        total += size
    if total > max_group_bytes:
        raise ArchiveError(f"Output group exceeds byte limit ({total:,} > {max_group_bytes:,})")
    return total
