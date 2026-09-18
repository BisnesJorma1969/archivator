"""Compare all supported entries, reporting every difference found."""

import os
import sys
from pathlib import Path

from .common import sha256
from .filesystem import check_unchanged, scan


def compare(source, target):
    source, target = Path(source), Path(target)
    original = {entry["path"]: entry for entry in scan(source)}
    restored = {entry["path"]: entry for entry in scan(target)}
    differences = []
    for name in sorted(original.keys() - restored.keys()):
        differences.append(f"Missing: {name!r}")
    for name in sorted(restored.keys() - original.keys()):
        differences.append(f"Unexpected: {name!r}")
    for name in sorted(original.keys() & restored.keys()):
        left, right = original[name], restored[name]
        if left["type"] != right["type"]:
            differences.append(f"Type differs: {name!r}")
            continue
        if left["type"] == "file":
            if left["size"] != right["size"]:
                differences.append(f"Size differs: {name!r}")
            if sha256(source / name) != sha256(target / name):
                differences.append(f"Content differs (SHA-256): {name!r}")
            check_unchanged(source / name, left)
            check_unchanged(target / name, right)
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
    print(f"{len(differences)} differences" if differences else "Trees are identical")
    return 1 if differences else 0
