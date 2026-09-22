"""Conservative byte budgets for independently compressed files and PAR2 sets."""

from dataclasses import dataclass

from .common import ArchiveError, IntegrityError


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


# PAR2's GF(2^16) implementation limits source and recovery block counts.
MAX_PAR2_BLOCKS = 32768
MIN_SLICE_SIZE = 4096
# A performance target, not a format limit or a cap on member count.
TARGET_SOURCE_BLOCKS = 2048


@dataclass(frozen=True)
class ParityPlan:
    slice_size: int
    blocks: int
    volumes: int
    total_bytes: int
    largest_file: int

    def record(self):
        return {"slice_size": self.slice_size, "blocks": self.blocks, "volumes": self.volumes}


def plan_reservation(max_file_bytes):
    """Upper-width fields let metadata reserve its own plan before serialization."""
    return {"slice_size": max_file_bytes, "blocks": MAX_PAR2_BLOCKS, "volumes": MAX_PAR2_BLOCKS}


def validate_parity_record(record, enabled=True):
    if not enabled:
        if record is not None:
            raise IntegrityError("Unexpected PAR2 plan when parity is disabled")
        return
    if not isinstance(record, dict) or set(record) != {"slice_size", "blocks", "volumes"}:
        raise IntegrityError("Invalid PAR2 plan")
    if (any(type(value) is not int for value in record.values())
            or record["slice_size"] < MIN_SLICE_SIZE or record["slice_size"] % 4
            or not 1 <= record["blocks"] <= MAX_PAR2_BLOCKS
            or not 1 <= record["volumes"] <= record["blocks"]):
        raise IntegrityError("Invalid PAR2 block size, recovery count or volume count")


def recovery_blocks(members, slice_size, groups=None, loss_count=0, bitrot_percent=2, protect_all=False):
    """Whole-file/group losses plus a separate slice budget for bitrot.

    Whole losses use per-file rounded source blocks. Bitrot is a percentage of
    stored input bytes, rounded up once; it is not a percentage of flipped bits.
    """
    counts = {name: ceil_div(length, slice_size) for name, length in members.items()}
    total = sum(counts.values())
    if protect_all:
        return total + 1
    units = ([sum(counts[name] for name in group) for group in groups]
             if groups is not None else list(counts.values()))
    lost = sum(sorted(units, reverse=True)[:loss_count])
    bitrot = ceil_div(sum(members.values()) * bitrot_percent, 100 * slice_size)
    # There is no additional source loss to cover once every source block is lost.
    return min(total, lost + bitrot)


def volume_plan(members, slice_size, max_file_bytes, blocks, volumes=None):
    """Bound uniform PAR2 volumes, including headers and repeated critical packets."""
    slices = sum(ceil_div(length, slice_size) for length in members.values())
    if slices > MAX_PAR2_BLOCKS or blocks > MAX_PAR2_BLOCKS:
        raise ArchiveError("PAR2 source/recovery block capacity exceeded")
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
    if volumes is None:
        low, high = 1, blocks
        while low < high:
            middle = (low + high) // 2
            if volume_size(ceil_div(blocks, middle)) <= max_file_bytes:
                high = middle
            else:
                low = middle + 1
        volumes = low
    largest_file = max(index_size, volume_size(ceil_div(blocks, volumes)))
    if largest_file > max_file_bytes:
        raise ArchiveError("Recorded PAR2 volume exceeds the file limit")
    base, extra = divmod(blocks, volumes)
    total = index_size + extra * volume_size(base + 1) + (volumes - extra) * volume_size(base)
    return ParityPlan(slice_size, blocks, volumes, total, largest_file)


def parity_plan(members, max_file_bytes, enabled=True, *, max_set_bytes=None,
                groups=None, loss_count=0, bitrot_percent=2, protect_all=False, record=None):
    """Choose practical dynamic slices, or reproduce a recorded set exactly.

    Doubling is bounded by the output file ceiling. All source files, including
    metadata, count separately; a short final file still consumes a whole slice.
    A failed plan is a grouping boundary, never permission to lower redundancy.
    """
    if not enabled or (not protect_all and loss_count == 0 and bitrot_percent == 0):
        return ParityPlan(0, 0, 0, 0, 0)
    if not members or any(length < 0 or length > max_file_bytes for length in members.values()):
        raise ArchiveError("PAR2 member exceeds the file limit or the set is empty")
    if record is not None:
        validate_parity_record(record)
        candidates = [record["slice_size"]]
    else:
        candidates = []
        size = MIN_SLICE_SIZE
        while size < max_file_bytes:
            candidates.append(size)
            size *= 2
        # Starting near a modest source-block count avoids huge Reed-Solomon
        # matrices. Try coarser slices first; finer ones remain available when
        # an output-file or media ceiling prevents the preferred geometry.
        preferred = max(MIN_SLICE_SIZE, ceil_div(sum(members.values()), TARGET_SOURCE_BLOCKS))
        candidates = ([size for size in candidates if size >= preferred]
                      + [size for size in reversed(candidates) if size < preferred])
    reason = "File limit leaves no room for a PAR2 slice"
    for size in candidates:
        required = recovery_blocks(members, size, groups, loss_count, bitrot_percent, protect_all)
        blocks = record["blocks"] if record is not None else required
        if blocks < required:
            raise ArchiveError("Recorded PAR2 plan does not meet redundancy requirements")
        try:
            plan = volume_plan(members, size, max_file_bytes, blocks,
                               record["volumes"] if record is not None else None)
            if max_set_bytes is not None and sum(members.values()) + plan.total_bytes > max_set_bytes:
                raise ArchiveError("Protected inputs and PAR2 exceed the recovery-set byte limit")
            return plan
        except ArchiveError as error:
            reason = str(error)
    raise ArchiveError(f"No feasible PAR2 geometry: {reason}")


def check_files(paths, max_file_bytes, max_datagroup_bytes):
    total = 0
    for path in paths:
        if not path.name.isascii() or len(path.name) > 255:
            raise ArchiveError("Output filename exceeds portable ASCII component limits")
        size = path.stat().st_size
        if size > max_file_bytes:
            raise ArchiveError(f"Output exceeds file limit: {path.name} ({size:,} > {max_file_bytes:,})")
        total += size
    if total > max_datagroup_bytes:
        raise ArchiveError(f"Output datagroup exceeds byte limit ({total:,} > {max_datagroup_bytes:,})")
    return total
