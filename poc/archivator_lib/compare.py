"""Compare all supported entries, reporting every difference found."""

import os
import sys
import time
from pathlib import Path

from .common import sha256
from .filesystem import check_unchanged, scan
from .progress import progress


def compare(source, target):
    source, target = Path(source), Path(target)
    original = {entry["path"]: entry for entry in scan(source)}
    restored = {entry["path"]: entry for entry in scan(target)}
    differences = []
    for name in sorted(original.keys() - restored.keys()):
        differences.append(f"Missing: {name!r}")
    for name in sorted(restored.keys() - original.keys()):
        differences.append(f"Unexpected: {name!r}")
    shared = sorted(original.keys() & restored.keys())
    file_names = [name for name in shared
                  if original[name]["type"] == restored[name]["type"] == "file"]
    total_bytes = sum(original[name]["size"] + restored[name]["size"] for name in file_names)
    files_done = 0
    bytes_read = 0
    started = time.monotonic()
    activity = "Checking metadata"

    def report_read(count=0):
        nonlocal bytes_read
        bytes_read += count
        elapsed = time.monotonic() - started
        speed = bytes_read / elapsed / (1024 * 1024) if elapsed else 0
        # Count reads from both trees, without resetting for each file or side.
        progress.update(
            f"Files {files_done:,}/{len(file_names):,} checked; "
            f"read {bytes_read / (1024 * 1024):,.1f}/{total_bytes / (1024 * 1024):,.1f} MiB; "
            f"{speed:,.1f} MiB/s avg; {activity}")

    print(f"Comparing {len(shared):,} shared entries, {len(file_names):,} file pairs; "
          f"{total_bytes:,} bytes to read across source and target", flush=True)
    for name in shared:
        activity = f"Checking metadata: {name!r}"
        report_read()
        left, right = original[name], restored[name]
        if left["type"] != right["type"]:
            differences.append(f"Type differs: {name!r}")
            continue
        if left["type"] == "file":
            if left["size"] != right["size"]:
                differences.append(f"Size differs: {name!r}")
            activity = f"SHA-256 source: {name!r}"
            report_read()
            source_hash = sha256(source / name, on_read=report_read)
            activity = f"SHA-256 target: {name!r}"
            report_read()
            target_hash = sha256(target / name, on_read=report_read)
            if source_hash != target_hash:
                differences.append(f"Content differs (SHA-256): {name!r}")
            check_unchanged(source / name, left)
            check_unchanged(target / name, right)
            files_done += 1
        if left["type"] == "symlink" and left["symlink_target"] != right["symlink_target"]:
            differences.append(f"Symlink target differs: {name!r}")
        if os.name == "posix":
            if left["mode"] != right["mode"]:
                differences.append(f"Mode differs: {name!r}")
            if left["mtime_ns"] != right["mtime_ns"]:
                differences.append(f"Mtime differs: {name!r}")
        elif left["mtime_ns"] != right["mtime_ns"]:
            print(f"Warning: platform timestamp difference: {name!r}", file=sys.stderr)
    for difference in differences:
        print(difference)
    elapsed = time.monotonic() - started
    speed = bytes_read / elapsed / (1024 * 1024) if elapsed else 0
    activity = "Comparison complete"
    report_read()
    print(f"Compared {files_done:,} file pairs; read {bytes_read:,} bytes in {elapsed:.2f}s "
          f"({speed:,.1f} MiB/s average, source + target)")
    print(f"{len(differences)} differences" if differences else "Trees are identical")
    return 1 if differences else 0
