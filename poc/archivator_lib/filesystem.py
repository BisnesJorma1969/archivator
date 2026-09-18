"""Source scanning and ordinary local-filesystem operations."""

import os
import stat
from pathlib import Path, PurePosixPath

from .common import ArchiveError, IntegrityError


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
    if root.is_symlink() or not root.is_dir():
        raise ArchiveError(f"Source must be a directory, not a symlink: {root}")
    entries = []
    pending = [root]
    while pending:
        path = pending.pop()
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
