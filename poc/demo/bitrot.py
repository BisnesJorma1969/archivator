#!/usr/bin/env python3
"""Damage archive data, metadata, and PAR2 files with realistic corruption patterns."""

import argparse
import bisect
import hashlib
import json
import math
import os
import random
import shutil
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from poc.archivator_lib.common import ArchiveError, IntegrityError, sha256
from poc.archivator_lib.format import parity_prefix
from poc.archivator_lib.recovery import discover, open_archive

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "work" / "demo"
DAMAGE_TYPES = ("bitflip", "zero", "copy", "delete", "insert")
SECTOR_SIZE = 512
BUFFER_SIZE = 1024 * 1024


def percentage(value):
    value = float(value)
    if not math.isfinite(value) or not 0 <= value <= 100:
        raise ValueError("Percentage must be finite and between 0 and 100")
    return value


def read_region(path, offset, length):
    with open(path, "rb") as source:
        source.seek(offset)
        data = source.read(length)
    if len(data) != length:
        raise ArchiveError(f"Archive changed while planning damage: {path}")
    return data


def zero_sectors(data, stride):
    result = bytearray(data)
    for offset in range(0, len(result), stride):
        length = min(SECTOR_SIZE, len(result) - offset)
        result[offset:offset + length] = bytes(length)
    return bytes(result)


def plan_change(path, block, slice_size, damage, sources, rng):
    operation = rng.choice(DAMAGE_TYPES) if damage == "mixed" else damage
    start = block * slice_size
    end = min(path.stat().st_size, start + slice_size)
    if operation == "bitflip":
        offset = rng.randrange(start, end)
        length = 1
    else:
        # Sector runs stay inside the selected original block. Short final
        # sectors are valid, including metadata files smaller than one sector.
        sectors = (end - start + SECTOR_SIZE - 1) // SECTOR_SIZE
        offset = start + rng.randrange(sectors) * SECTOR_SIZE
        remaining_sectors = (end - offset + SECTOR_SIZE - 1) // SECTOR_SIZE
        length = min(end - offset, rng.randint(1, remaining_sectors) * SECTOR_SIZE)
    change = {"filename": path.name, "path": str(path), "block": block,
              "operation": operation, "offset": offset, "length": length}
    original = read_region(path, offset, length)
    if operation == "zero":
        change["sector_stride"] = rng.choice((1, 2, 4)) * SECTOR_SIZE
        replacement = zero_sectors(original, change["sector_stride"])
    elif operation in ("copy", "insert"):
        donor = rng.choice(sources)
        length = min(length, donor.stat().st_size)
        donor_offset = rng.randrange((donor.stat().st_size - length) // SECTOR_SIZE + 1) * SECTOR_SIZE
        replacement = read_region(donor, donor_offset, length)
        original = original[:length]
        change.update(length=length, source_path=str(donor), source_offset=donor_offset,
                      source_sha256=hashlib.sha256(replacement).hexdigest())
    if operation in ("zero", "copy") and replacement == original:
        # Overwriting zeros with zeros, or copying identical bytes, is not damage.
        # Record a real bit flip instead of claiming a no-op corrupted a block.
        change = {"filename": path.name, "path": str(path), "block": block,
                  "operation": "bitflip", "offset": offset, "length": 1}
        original = original[:1]
    if change["operation"] == "bitflip":
        change.update(before=original[0], after=original[0] ^ (1 << rng.randrange(8)))
    change["original_sha256"] = hashlib.sha256(original).hexdigest()
    return change


def sample_blocks(paths, slice_size, percent, rng, damage, sources):
    """Sample a flat block space without allocating a list of every block."""
    ends = []
    total = 0
    for path in paths:
        total += (path.stat().st_size + slice_size - 1) // slice_size
        ends.append(total)
    count = min(total, math.ceil(total * percent / 100))
    changes = []
    for block in sorted(rng.sample(range(total), count)):
        file_index = bisect.bisect_right(ends, block)
        preceding_blocks = ends[file_index - 1] if file_index else 0
        block_in_file = block - preceding_blocks
        path = paths[file_index]
        changes.append(plan_change(path, block_in_file, slice_size, damage, sources, rng))
    return total, changes


def plan_archive(root, percent, rng, include_bootstrap, damage):
    archives = discover(root)
    groups = []
    for archive_id in sorted(archives):
        with open_archive(archive_id, archives[archive_id]) as archive:
            if archive.metadata_damage:
                raise IntegrityError("Start from an intact archive; repair or recreate it before another bitrot run")
            expected = dict(archive.checksums)
            expected.update(archive.complete["metadata_parity"])
            expected[archive.complete["checksum_index"]] = archive.complete["checksum_index_sha256"]
            for manifest in archive.manifests:
                for member in manifest["members"]:
                    expected[member["filename"]] = member["stored_sha256"]
            for name, digest in expected.items():
                path = archive.files.get(name)
                if path is None or path.is_symlink() or not path.is_file() or sha256(path) != digest:
                    raise IntegrityError(f"Archive is already damaged: {name}; repair or recreate it first")

            sources = [archive.files[name] for name in sorted(expected)
                       if archive.files[name].stat().st_size]
            pools = []
            for manifest in archive.manifests:
                prefix = parity_prefix(archive_id, manifest["parity"])
                names = [member["filename"] for member in manifest["members"]]
                pools.append(("data", manifest["parity"], manifest["slice_size"], names))
                parity_names = [name for name in archive.checksums
                                if name.startswith(prefix + ".") and name.endswith(".par2")]
                pools.append(("data_parity", manifest["parity"], manifest["slice_size"], parity_names))
            metadata_slice = archive.complete["metadata_slice_size"]
            pools.append(("metadata", "metadata", metadata_slice, archive.complete["metadata_members"]))
            pools.append(("metadata_parity", "metadata", metadata_slice, list(archive.complete["metadata_parity"])))
            if include_bootstrap:
                pools.append(("bootstrap", "bootstrap", metadata_slice, [f"archive-{archive_id}_complete.json"]))
            for category, parity, slice_size, names in pools:
                paths = [archive.files[name] for name in sorted(names)]
                total, changes = sample_blocks(paths, slice_size, percent, rng, damage, sources)
                groups.append({
                    "archive": str(root), "archive_id": archive_id, "parity": parity,
                    "category": category, "block_size": slice_size, "eligible_blocks": total,
                    "selected_blocks": len(changes),
                    "actual_percent": 100 * len(changes) / total if total else 0,
                    "changes": changes,
                })
    return groups


def copy_bytes(source, output, length):
    while length:
        data = source.read(min(length, BUFFER_SIZE))
        if not data:
            raise ArchiveError("Archive changed while applying damage")
        output.write(data)
        length -= len(data)


def rewrite_file(path, output, changes):
    # Offsets always refer to the original file, even after earlier insertions
    # and deletions. Donor files also remain original until all rewrites finish.
    with open(path, "rb") as source:
        for change in sorted(changes, key=lambda item: item["offset"]):
            copy_bytes(source, output, change["offset"] - source.tell())
            original = source.read(change["length"])
            if hashlib.sha256(original).hexdigest() != change["original_sha256"]:
                raise ArchiveError(f"Archive changed after planning: {path}")
            operation = change["operation"]
            if operation == "bitflip":
                output.write(bytes([change["after"]]))
            elif operation == "zero":
                output.write(zero_sectors(original, change["sector_stride"]))
            elif operation in ("copy", "insert"):
                replacement = read_region(change["source_path"], change["source_offset"], change["length"])
                if hashlib.sha256(replacement).hexdigest() != change["source_sha256"]:
                    raise ArchiveError(f"Copy source changed after planning: {change['source_path']}")
                output.write(replacement)
                if operation == "insert":
                    output.write(original)
            elif operation != "delete":
                raise ValueError(f"Unknown damage operation: {operation}")
            # Deletion omits this region; subsequent original bytes move left.
        shutil.copyfileobj(source, output, BUFFER_SIZE)


def apply_changes(groups):
    by_file = {}
    for group in groups:
        for change in group["changes"]:
            by_file.setdefault(change["path"], []).append(change)
    staged = []
    try:
        for name, changes in by_file.items():
            path = Path(name)
            # Stage beside the original so replacement works across filesystems.
            # All rewrites finish before publishing, keeping copy donors pristine.
            with tempfile.NamedTemporaryFile(prefix=".bitrot-", dir=path.parent, delete=False) as output:
                temporary = Path(output.name)
                staged.append((path, temporary))
                rewrite_file(path, output, changes)
            shutil.copystat(path, temporary)
        for path, temporary in staged:
            os.replace(temporary, path)
    finally:
        for _, temporary in staged:
            temporary.unlink(missing_ok=True)


def bitrot(archives, percent=1, seed=20260918, include_bootstrap=False, dry_run=False,
           report_path=None, damage="mixed"):
    percent = percentage(percent)
    if damage not in ("mixed", *DAMAGE_TYPES):
        raise ValueError(f"Unknown damage type: {damage}")
    roots = [Path(path).absolute() for path in archives]
    if not roots:
        raise ValueError("At least one archive directory is required")
    if len(set(path.resolve() for path in roots)) != len(roots):
        raise ValueError("An archive directory was supplied more than once")
    for first in roots:
        for second in roots:
            if first != second and first.resolve().is_relative_to(second.resolve()):
                raise ValueError("Archive directory arguments must not overlap")
    if report_path is None:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        report_path = DEFAULT_ROOT / f"bitrot-{stamp}.json"
    report_path = Path(report_path).absolute()
    if any(report_path.resolve().is_relative_to(root.resolve()) for root in roots):
        raise ValueError("Keep the damage report outside the archives being damaged")
    if report_path.exists():
        raise ValueError(f"Report already exists: {report_path}")
    rng = random.Random(seed)
    groups = []
    for root in roots:
        print(f"Checking and planning {root}", flush=True)
        groups.extend(plan_archive(root, percent, rng, include_bootstrap, damage))
    report = {"version": 1, "seed": seed, "requested_percent": percent, "damage": damage,
              "unit": "selected original PAR2-sized file regions", "include_bootstrap": include_bootstrap,
              "status": "dry-run" if dry_run else "planned", "groups": groups}
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # Save the full plan before touching any archive, so interrupted runs still
    # have a record of intended damage. Only a completed run changes status to applied.
    with report_path.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    if not dry_run:
        apply_changes(groups)
        report["status"] = "applied"
        with report_path.open("w", encoding="utf-8") as output:
            json.dump(report, output, indent=2)
            output.write("\n")
    for group in groups:
        print(f"{Path(group['archive']).name} {group['category']} {group['parity']}: "
              f"{group['selected_blocks']}/{group['eligible_blocks']} original regions "
              f"({group['actual_percent']:.2f}%)")
    counts = Counter(change["operation"] for group in groups for change in group["changes"])
    print(f"{'Planned' if dry_run else 'Applied'} damage: "
          + (", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "none"))
    print(f"Damage report: {report_path}")
    print("Percentages select original regions, not exact lost recovery blocks. Insert/delete shifts later offsets.")
    print("Small pools round upward. Recovery depends on each set's remaining PAR2 capacity.")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="*", type=Path, help="Default: poc/work/demo/archive1, archive2, archive3")
    parser.add_argument("--percent", type=float, default=1,
                        help="Percent of original PAR2-sized regions in each pool (default: 1)")
    parser.add_argument("--seed", type=int, default=20260918)
    parser.add_argument("--damage", choices=("mixed", *DAMAGE_TYPES), default="mixed",
                        help="Mixed faults or one specific pattern (default: mixed)")
    parser.add_argument("--include-bootstrap", action="store_true", help="Also damage unprotected complete.json; recovery may fail")
    parser.add_argument("--dry-run", action="store_true", help="Write a damage plan without changing archives")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    archives = args.archives or [DEFAULT_ROOT / f"archive{number}" for number in (1, 2, 3)]
    try:
        bitrot(archives, args.percent, args.seed, args.include_bootstrap, args.dry_run, args.report, args.damage)
    except (ArchiveError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
