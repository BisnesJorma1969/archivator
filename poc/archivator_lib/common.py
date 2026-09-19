"""Small shared helpers for checksums, metadata files, and scratch space."""

import binascii
import hashlib
import json
import tempfile
from pathlib import Path

from .progress import progress

BUFFER_SIZE = 1024 * 1024
WORK_DIR = Path(__file__).resolve().parents[1] / "work"


class ArchiveError(Exception):
    """An operational failure that should be explained without a traceback."""


class IntegrityError(ArchiveError):
    """Missing, damaged, inconsistent, or unrecoverable archive content."""


class Hashes:
    """Update the requested checksums together, without rereading input."""

    def __init__(self, lookup=False):
        self.digests = {
            "sha256": hashlib.sha256(),
            "sha512": hashlib.sha512(),
        }
        self.lookup = lookup
        if lookup:
            self.digests["md5"] = hashlib.md5(usedforsecurity=False)
            self.digests["sha1"] = hashlib.sha1(usedforsecurity=False)
        self.crc32 = 0

    def update(self, data):
        for digest in self.digests.values():
            digest.update(data)
        if self.lookup:
            self.crc32 = binascii.crc32(data, self.crc32)

    def values(self):
        result = {name: digest.hexdigest() for name, digest in self.digests.items()}
        if self.lookup:
            result["crc32"] = f"{self.crc32:08x}"
        return result


def file_hashes(path, lookup=False):
    hashes = Hashes(lookup)
    total = Path(path).stat().st_size
    completed = 0
    progress.update(f"Hashing file: 0/{total:,} bytes")
    with open(path, "rb") as source:
        while data := source.read(BUFFER_SIZE):
            hashes.update(data)
            completed += len(data)
            progress.update(f"Hashing file: {completed:,}/{total:,} bytes")
    return hashes.values()


def sha256(path, on_read=None):
    """Hash a file; callers may report cumulative progress across multiple files."""
    digest = hashlib.sha256()
    if on_read is None:
        total = Path(path).stat().st_size
        progress.update(f"Checking SHA-256: 0/{total:,} bytes")
    completed = 0
    with open(path, "rb") as source:
        while data := source.read(BUFFER_SIZE):
            digest.update(data)
            if on_read is not None:
                on_read(len(data))
            else:
                completed += len(data)
                progress.update(f"Checking SHA-256: {completed:,}/{total:,} bytes")
    return digest.hexdigest()


def write_json(path, value):
    progress.update("Writing metadata")
    with open(path, "w", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, ensure_ascii=True, indent=2, sort_keys=True)
        output.write("\n")


def read_json(path):
    progress.update("Reading metadata")
    try:
        with open(path, encoding="utf-8") as source:
            return json.load(source)
    except (ValueError, UnicodeError) as error:
        raise IntegrityError(f"Invalid JSON in {path.name}: {error}") from error


def write_jsonl(path, entries):
    with open(path, "w", encoding="utf-8", newline="\n") as output:
        for index, entry in enumerate(entries, 1):
            progress.update(f"Writing inventory: {index:,} entries")
            output.write(json.dumps(entry, ensure_ascii=True, sort_keys=True) + "\n")


def read_jsonl(path):
    progress.update("Reading inventory")
    try:
        with open(path, encoding="utf-8") as source:
            return [json.loads(line) for line in source if line.strip()]
    except (ValueError, UnicodeError) as error:
        raise IntegrityError(f"Invalid JSON lines in {path.name}: {error}") from error


def scratch(prefix):
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    return tempfile.TemporaryDirectory(prefix=prefix, dir=WORK_DIR)
