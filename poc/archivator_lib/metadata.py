"""Stored metadata compression and the two completion-marker copies."""

import hashlib
import json
import os

from .external import executable, run

# These bootstrap/inspection files remain directly readable. All other metadata
# is zstd-compressed, regardless of size or compression ratio.
UNCOMPRESSED_METADATA_SUFFIXES = (
    "_complete.json", "_complete-copy.json", "_format.txt", "_recipient.pem",
)


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
    """Apply the fixed metadata policy and return the stored filename."""
    if path.suffix == ".zst" or path.name.endswith(UNCOMPRESSED_METADATA_SUFFIXES):
        return path.name
    compressed = path.parent / ".tmp" / (path.name + ".zst")
    compressed.parent.mkdir(exist_ok=True)
    run([executable("zstd"), "-q", "-3", "--single-thread", "--check",
         str(path), "-o", str(compressed)], activity=f"Compressing metadata: {path.name!r}")
    os.replace(compressed, path.with_name(compressed.name))
    path.unlink()
    return compressed.name


def unpack_metadata(path, destination=None):
    """Expand already verified stored metadata only in recovery scratch space."""
    if path.suffix != ".zst":
        return path
    target = (destination or path.parent) / path.with_suffix("").name
    run([executable("zstd"), "-qd", str(path), "-o", str(target)],
        activity=f"Decompressing verified metadata: {path.name!r}")
    return target
