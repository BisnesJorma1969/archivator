#!/usr/bin/env python3
"""Intentionally flip bits in archive data, protected metadata, and PAR2 files."""

import argparse
import bisect
import json
import math
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from poc.archivator_lib.common import ArchiveError, IntegrityError, sha256
from poc.archivator_lib.format import parity_prefix
from poc.archivator_lib.recovery import discover, open_archive

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "work" / "demo"


def percentage(value):
    value = float(value)
    if not math.isfinite(value) or not 0 <= value <= 100:
        raise ValueError("Percentage must be finite and between 0 and 100")
    return value


def sample_blocks(paths, slice_size, percent, rng):
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
        start = block_in_file * slice_size
        end = min(path.stat().st_size, start + slice_size)
        offset = rng.randrange(start, end)
        with path.open("rb") as source:
            source.seek(offset)
            before = source.read(1)[0]
        after = before ^ (1 << rng.randrange(8))
        changes.append({"filename": path.name, "path": str(path), "block": block_in_file,
                        "offset": offset, "before": before, "after": after})
    return total, changes


def plan_archive(root, percent, rng, include_bootstrap):
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
                total, changes = sample_blocks(paths, slice_size, percent, rng)
                groups.append({
                    "archive": str(root), "archive_id": archive_id, "parity": parity,
                    "category": category, "block_size": slice_size, "eligible_blocks": total,
                    "selected_blocks": len(changes),
                    "actual_percent": 100 * len(changes) / total if total else 0,
                    "changes": changes,
                })
    return groups


def apply_changes(groups):
    by_file = {}
    for group in groups:
        for change in group["changes"]:
            by_file.setdefault(change["path"], []).append(change)
    # Check every selected byte before starting. Reusing a seed cannot silently
    # toggle an already-damaged archive back to health: preflight requires clean input.
    for name, changes in by_file.items():
        with open(name, "rb") as source:
            for change in changes:
                source.seek(change["offset"])
                if source.read(1) != bytes([change["before"]]):
                    raise ArchiveError(f"Archive changed after planning: {name}")
    for name, changes in by_file.items():
        with open(name, "r+b") as output:
            for change in changes:
                output.seek(change["offset"])
                output.write(bytes([change["after"]]))


def bitrot(archives, percent=1, seed=20260918, include_bootstrap=False, dry_run=False, report_path=None):
    percent = percentage(percent)
    roots = [Path(path).absolute() for path in archives]
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
        groups.extend(plan_archive(root, percent, rng, include_bootstrap))
    report = {"version": 1, "seed": seed, "requested_percent": percent,
              "unit": "PAR2-sized file blocks", "include_bootstrap": include_bootstrap,
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
              f"{group['selected_blocks']}/{group['eligible_blocks']} blocks "
              f"({group['actual_percent']:.2f}%)")
    print(f"{'Planned' if dry_run else 'Applied'} one bit flip per selected block. Report: {report_path}")
    print("Small pools round upward. Recovery depends on each set's remaining PAR2 capacity.")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="*", type=Path, help="Default: poc/work/demo/archive1, archive2, archive3")
    parser.add_argument("--percent", type=float, default=1, help="Percent of blocks in each data/metadata/parity pool (default: 1)")
    parser.add_argument("--seed", type=int, default=20260918)
    parser.add_argument("--include-bootstrap", action="store_true", help="Also damage unprotected complete.json; recovery may fail")
    parser.add_argument("--dry-run", action="store_true", help="Write a damage plan without changing archives")
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    archives = args.archives or [DEFAULT_ROOT / f"archive{number}" for number in (1, 2, 3)]
    try:
        bitrot(archives, args.percent, args.seed, args.include_bootstrap, args.dry_run, args.report)
    except (ArchiveError, OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
