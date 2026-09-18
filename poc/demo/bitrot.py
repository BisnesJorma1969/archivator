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
from poc.archivator_lib.metadata import completion_names
from poc.archivator_lib.recovery import discover, open_archive
from poc.archivator_lib.progress import progress

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "work" / "demo"
DAMAGE_TYPES = ("bitflip", "zero", "copy", "delete", "insert")
MAX_FAULT_SIZE = 4 * 1024 * 1024
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


def plan_change(path, offset, length, operation, sources, rng):
    change = {"filename": path.name, "path": str(path), "operation": operation,
              "offset": offset, "length": length}
    original = read_region(path, offset, length)
    if operation == "zero":
        replacement = bytes(length)
    elif operation in ("copy", "insert"):
        donors = [source for source in sources if source.stat().st_size >= length]
        donor = rng.choice(donors)
        donor_offset = rng.randrange(donor.stat().st_size - length + 1)
        replacement = read_region(donor, donor_offset, length)
        change.update(source_path=str(donor), source_offset=donor_offset,
                      source_sha256=hashlib.sha256(replacement).hexdigest())
    if operation in ("zero", "copy") and replacement == original:
        # A no-op is not damage. Flip bits across the same byte budget instead.
        change = {"filename": path.name, "path": str(path), "operation": "bitflip",
                  "offset": offset, "length": length}
    if change["operation"] == "bitflip":
        change["xor_mask"] = 1 << rng.randrange(8)
    change["original_sha256"] = hashlib.sha256(original).hexdigest()
    return change


def sample_bytes(paths, budget, damage, rng):
    """Allocate one byte budget across non-overlapping, randomly located faults."""
    sources = [path for path in paths if path.stat().st_size]
    available = [(path, 0, path.stat().st_size) for path in sources]
    styles = {}
    remaining = budget
    changes = []
    while remaining:
        # Pick among the still-available bytes, so large files are more likely
        # to be hit than tiny ones. No PAR2 boundaries or per-set quotas apply.
        ends = []
        total = 0
        for _, start, end in available:
            total += end - start
            ends.append(total)
        index = bisect.bisect_right(ends, rng.randrange(total))
        path, start, end = available.pop(index)
        max_run = rng.choices((1, 4096, 65536, MAX_FAULT_SIZE), weights=(1, 4, 10, 85), k=1)[0]
        length = rng.randint(1, min(remaining, end - start, max_run))
        offset = rng.randint(start, end - length)
        if path not in styles:
            styles[path] = rng.choice(DAMAGE_TYPES) if damage == "mixed" else damage
        changes.append(plan_change(path, offset, length, styles[path], sources, rng))
        if start < offset:
            available.append((path, start, offset))
        if offset + length < end:
            available.append((path, offset + length, end))
        remaining -= length
        progress.update(f"Planning corruption: {budget - remaining:,}/{budget:,} bytes allocated")
    return changes


def plan_archive(root, percent, rng, include_bootstrap, damage):
    archives = discover(root)
    summaries = []
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

            # Categories describe the report only. They do not get separate budgets.
            categories = []
            for manifest in archive.manifests:
                prefix = parity_prefix(archive_id, manifest["parity"])
                names = [member["filename"] for member in manifest["members"]]
                categories.append(("data", manifest["parity"], names))
                parity_names = [name for name in archive.checksums
                                if name.startswith(prefix + ".") and name.endswith(".par2")]
                categories.append(("data_parity", manifest["parity"], parity_names))
            categories.append(("metadata", "metadata", archive.complete["metadata_members"]))
            categories.append(("metadata_parity", "metadata", list(archive.complete["metadata_parity"])))
            markers = completion_names(archive_id)
            if include_bootstrap:
                categories.append(("bootstrap", "bootstrap", markers))
            by_name = {}
            archive_groups = []
            for category, parity, names in categories:
                group = {"archive": str(root), "archive_id": archive_id,
                         "category": category, "parity": parity, "changes": []}
                archive_groups.append(group)
                for name in names:
                    by_name[name] = group
            paths = [archive.files[name] for name in sorted(by_name)]
            total_bytes = sum(archive.files[name].stat().st_size for name in [*expected, *markers])
            eligible_bytes = sum(path.stat().st_size for path in paths)
            requested_bytes = round(total_bytes * percent / 100)
            budget = min(requested_bytes, eligible_bytes)
            changes = sample_bytes(paths, budget, damage, rng)
            for change in changes:
                by_name[change["filename"]]["changes"].append(change)
            for group in archive_groups:
                group["affected_bytes"] = sum(change["length"] for change in group["changes"])
            groups.extend(archive_groups)
            summaries.append({
                "archive": str(root), "archive_id": archive_id, "original_bytes": total_bytes,
                "eligible_bytes": eligible_bytes, "requested_bytes": requested_bytes,
                "affected_bytes": budget, "actual_percent": 100 * budget / total_bytes,
                "files_affected": len({change["filename"] for change in changes}),
            })
    return summaries, groups


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
                # One bit per byte, so both isolated flips and bursts have an
                # honest affected-byte count without millions of JSON records.
                table = bytes(value ^ change["xor_mask"] for value in range(256))
                output.write(original.translate(table))
            elif operation == "zero":
                output.write(bytes(change["length"]))
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
        for index, (name, changes) in enumerate(by_file.items(), 1):
            progress.update(f"Staging damaged file {index}/{len(by_file)}: {Path(name).name!r}")
            path = Path(name)
            # Stage beside the original so replacement works across filesystems.
            # All rewrites finish before publishing, keeping copy donors pristine.
            with tempfile.NamedTemporaryFile(prefix=".bitrot-", dir=path.parent, delete=False) as output:
                temporary = Path(output.name)
                staged.append((path, temporary))
                rewrite_file(path, output, changes)
            shutil.copystat(path, temporary)
        for index, (path, temporary) in enumerate(staged, 1):
            progress.update(f"Publishing damaged file {index}/{len(staged)}: {path.name!r}")
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
    summaries = []
    for root in roots:
        print(f"Checking and planning {root}", flush=True)
        archive_summaries, archive_groups = plan_archive(root, percent, rng, include_bootstrap, damage)
        summaries.extend(archive_summaries)
        groups.extend(archive_groups)
    report = {"version": 1, "seed": seed, "requested_percent": percent, "damage": damage,
              "unit": "bytes overwritten, bit-flipped, deleted, or inserted", "include_bootstrap": include_bootstrap,
              "status": "dry-run" if dry_run else "planned", "archives": summaries, "groups": groups}
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
    for summary in summaries:
        print(f"{Path(summary['archive']).name} ({summary['archive_id']}): "
              f"{summary['affected_bytes']:,}/{summary['original_bytes']:,} bytes affected "
              f"({summary['actual_percent']:.4f}%), {summary['files_affected']} files")
    for group in groups:
        if group["changes"]:
            print(f"  {group['category']} {group['parity']}: {group['affected_bytes']:,} bytes, "
                  f"{len(group['changes'])} faults")
    counts = Counter(change["operation"] for group in groups for change in group["changes"])
    print(f"{'Planned' if dry_run else 'Applied'} damage: "
          + (", ".join(f"{name}={count}" for name, count in sorted(counts.items())) or "none"))
    print(f"Damage report: {report_path}")
    print("Insertion/deletion counts the bytes added/removed, not the length of the shifted remainder.")
    print("Damage is randomly distributed; recovery depends on each set's remaining PAR2 capacity.")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="*", type=Path, help="Default: poc/work/demo/archive1, archive2, archive3")
    parser.add_argument("--percent", type=float, default=1,
                        help="Percent of each original backup's total stored bytes to damage (default: 1)")
    parser.add_argument("--seed", type=int, default=20260918)
    parser.add_argument("--damage", choices=("mixed", *DAMAGE_TYPES), default="mixed",
                        help="Mixed faults or one specific pattern (default: mixed)")
    parser.add_argument("--include-bootstrap", action="store_true",
                        help="Also damage both completion-marker copies; recovery fails if neither survives")
    parser.add_argument("--dry-run", action="store_true", help="Write a damage plan without changing archives")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    archives = args.archives or [DEFAULT_ROOT / f"archive{number}" for number in (1, 2, 3)]
    with progress.reporting("bitrot"):
        try:
            bitrot(archives, args.percent, args.seed, args.include_bootstrap, args.dry_run, args.report, args.damage)
        except (ArchiveError, OSError, ValueError) as error:
            print(f"Error: {error}", file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
