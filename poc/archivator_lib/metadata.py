"""Stored metadata compression and the two completion-marker copies."""

import hashlib
import json
import os

from .external import executable, run

METADATA_COMPRESSION_MIN = 64 * 1024


def completion_names(archive_id):
    return [f"archive-{archive_id}_complete.json",
            f"archive-{archive_id}_complete-copy.json"]


def completion_digest(complete):
    # Exclude only the digest itself, so the checksum has no circular dependency.
    payload = {key: value for key, value in complete.items() if key != "marker_sha256"}
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True,
                         separators=(",", ":")).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def store_metadata(path):
    """Return the stored filename, leaving only the useful representation."""
    if path.suffix == ".zst" or path.stat().st_size < METADATA_COMPRESSION_MIN:
        return path.name
    compressed = path.parent / ".tmp" / (path.name + ".zst")
    compressed.parent.mkdir(exist_ok=True)
    run([executable("zstd"), "-q", "-3", "--single-thread", "--check",
         str(path), "-o", str(compressed)], activity=f"Compressing metadata: {path.name!r}")
    if compressed.stat().st_size < path.stat().st_size:
        os.replace(compressed, path.with_name(compressed.name))
        path.unlink()
        return compressed.name
    compressed.unlink()
    return path.name


def unpack_metadata(path):
    """Expand already verified stored metadata only in recovery scratch space."""
    if path.suffix != ".zst":
        return path
    target = path.with_suffix("")
    run([executable("zstd"), "-qd", str(path), "-o", str(target)],
        activity=f"Decompressing verified metadata: {path.name!r}")
    return target
