"""Source scanning and ordinary local-filesystem operations."""

import os
import stat
import sys
from pathlib import Path, PurePosixPath

from .common import ArchiveError, IntegrityError
from .progress import progress


def ensure_disjoint(first, second):
    first, second = Path(first).resolve(), Path(second).resolve()
    if first.is_relative_to(second) or second.is_relative_to(first):
        raise ArchiveError(f"Directories must not overlap: {first} and {second}")


def empty_destination(path):
    path = Path(path)
    if path.is_symlink():
        raise ArchiveError(f"Destination must not be a symbolic link: {path}")
    if path.exists():
        if not path.is_dir() or any(path.iterdir()):
            raise ArchiveError(f"Destination must be absent or an empty directory: {path}")
    else:
        path.mkdir(parents=True)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def scan(root):
    root = Path(root)
    progress.update(f"Scanning {str(root)!r}: 0 entries")
    if root.is_symlink() or not root.is_dir():
        raise ArchiveError(f"Source must be a directory, not a symlink: {root}")
    entries = []
    pending = [root]
    while pending:
        path = pending.pop()
        progress.update(f"Scanning: {len(entries):,} entries found; {str(path)!r}")
        info = path.lstat()
        relative = path.relative_to(root).as_posix()
        entry = {
            "path": relative,
            "mode": stat.S_IMODE(info.st_mode),
            "mtime_ns": info.st_mtime_ns,
            "_identity": identity(info),
        }
        if stat.S_ISDIR(info.st_mode):
            entry["type"] = "directory"
            with os.scandir(path) as children:
                names = sorted(child.name for child in children)
            pending.extend(path / name for name in reversed(names))
        elif stat.S_ISREG(info.st_mode):
            entry["type"] = "file"
            entry["size"] = info.st_size
        elif stat.S_ISLNK(info.st_mode):
            entry["type"] = "symlink"
            entry["symlink_target"] = os.readlink(path)
        else:
            raise ArchiveError(f"Unsupported source entry: {relative!r}")
        entries.append(entry)
    return entries


def check_unchanged(path, entry):
    if identity(path.lstat()) != entry["_identity"]:
        raise ArchiveError(f"Source changed during backup: {entry['path']!r}")


def public_entry(entry):
    return {key: value for key, value in entry.items() if not key.startswith("_")}


def relative_path(value):
    if not isinstance(value, str) or not value or "\x00" in value:
        raise IntegrityError(f"Invalid source path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise IntegrityError(f"Unsafe source path: {value!r}")
    # Backslashes and drive prefixes are ordinary POSIX names, but separators
    # or drive changes on Windows. Do not reinterpret them on that target.
    if os.name == "nt" and ("\\" in value or ":" in value):
        raise IntegrityError(f"Path cannot be represented on this target: {value!r}")
    return path


def restore_metadata(root, entries):
    files = [entry for entry in entries if entry["type"] != "directory"]
    directories = [entry for entry in entries if entry["type"] == "directory"]
    directories.sort(key=lambda entry: len(relative_path(entry["path"]).parts), reverse=True)
    # Creating children changes directory mtimes. Restrictive directory modes
    # must also wait until their children have been created and verified.
    for index, entry in enumerate(files + directories, 1):
        progress.update(f"Applying modes and timestamps: {index:,}/{len(entries):,} entries; {entry['path']!r}")
        path = root / entry["path"]
        symlink = entry["type"] == "symlink"
        if not symlink:
            os.chmod(path, entry["mode"])
        elif os.chmod in os.supports_follow_symlinks:
            os.chmod(path, entry["mode"], follow_symlinks=False)
        elif stat.S_IMODE(path.lstat().st_mode) != entry["mode"]:
            print(f"Warning: target cannot preserve symlink mode for {entry['path']!r}", file=sys.stderr)
        if not symlink or os.utime in os.supports_follow_symlinks:
            try:
                os.utime(path, ns=(entry["mtime_ns"], entry["mtime_ns"]), follow_symlinks=False)
            except (NotImplementedError, OverflowError):
                print(f"Warning: target cannot preserve timestamp for {entry['path']!r}", file=sys.stderr)
            else:
                if path.lstat().st_mtime_ns != entry["mtime_ns"]:
                    print(f"Warning: target timestamp precision/range loss for {entry['path']!r}", file=sys.stderr)
        else:
            print(f"Warning: target cannot preserve symlink timestamp for {entry['path']!r}", file=sys.stderr)
