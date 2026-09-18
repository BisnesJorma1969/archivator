"""Reconstruct verified streams and restore their original filesystem entries."""

import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from .common import ArchiveError, BUFFER_SIZE, Hashes, IntegrityError, WORK_DIR, file_hashes, read_jsonl, scratch
from .external import decrypt, executable
from .filesystem import empty_destination, ensure_disjoint, relative_path, restore_metadata
from .recovery import copy_set, discover, open_archive, recover_set, select


def unpack_chunk(directory, member, output, encrypted, key, certificate):
    stored = directory / member["filename"]
    compressed = stored
    if encrypted:
        compressed = directory / "decrypted.zst"
        decrypt(stored, compressed, key, certificate)
    hashes = Hashes()
    length = 0
    with tempfile.TemporaryFile(dir=directory) as errors, subprocess.Popen(
            [executable("zstd"), "-q", "-d", "-c", "--", str(compressed)],
            stdout=subprocess.PIPE, stderr=errors) as process:
        try:
            while data := process.stdout.read(min(BUFFER_SIZE, member["length"] - length + 1)):
                length += len(data)
                if length > member["length"]:
                    raise IntegrityError("Decompressed chunk exceeds its declared length")
                hashes.update(data)
                output.write(data)
            if process.wait():
                errors.seek(0)
                message = errors.read().decode("utf-8", errors="replace").strip()
                raise IntegrityError(f"Invalid zstd chunk {member['filename']}: {message}")
        finally:
            # Stop decoding immediately on length or output failures.
            if process.poll() is None:
                process.kill()
    if length != member["length"]:
        raise IntegrityError("Decompressed chunk length mismatch")
    if (hashes.values()["sha256"] != member["plaintext_sha256"]
            or hashes.values()["sha512"] != member["plaintext_sha512"]):
        raise IntegrityError("Plaintext chunk checksum mismatch")
    if encrypted:
        compressed.unlink()


def extract_tar(path, target, inventory):
    expected = {entry["path"]: entry for entry in inventory}
    seen = set()
    try:
        with tarfile.open(path, "r:") as bundle:
            for member in bundle:
                name = relative_path(member.name).as_posix()
                if name not in expected or name in seen:
                    raise IntegrityError(f"Unexpected or duplicate TAR entry: {name!r}")
                seen.add(name)
                entry = expected[name]
                destination = target / name
                if entry["type"] == "directory":
                    if not member.isdir():
                        raise IntegrityError(f"TAR type mismatch: {name!r}")
                elif entry["type"] == "symlink":
                    if not member.issym() or member.linkname != entry["symlink_target"]:
                        raise IntegrityError(f"TAR symlink mismatch: {name!r}")
                    # All symlinks are created after all regular files. No TAR
                    # entry can redirect a later write outside the target tree.
                else:
                    if not member.isfile() or member.size != entry["size"]:
                        raise IntegrityError(f"TAR file type/size mismatch: {name!r}")
                    hashes = Hashes(lookup=True)
                    with bundle.extractfile(member) as source, destination.open("xb") as output:
                        while data := source.read(BUFFER_SIZE):
                            hashes.update(data)
                            output.write(data)
                    for algorithm, digest in hashes.values().items():
                        if entry.get(algorithm) != digest:
                            raise IntegrityError(f"Extracted file {algorithm} mismatch: {name!r}")
        if seen != set(expected):
            raise IntegrityError("TAR is missing inventory entries")
    except tarfile.TarError as error:
        raise IntegrityError(f"Invalid TAR stream: {error}") from error


def finish_stream(path, stream, archive, target):
    if path.stat().st_size != stream["size"]:
        raise IntegrityError("Reconstructed stream length mismatch")
    hashes = file_hashes(path)
    if hashes["sha256"] != stream["sha256"] or hashes["sha512"] != stream["sha512"]:
        raise IntegrityError("Reconstructed whole-stream checksum mismatch")
    if stream["type"] == "file":
        with path.open("rb") as source, (target / stream["path"]).open("xb") as output:
            shutil.copyfileobj(source, output, BUFFER_SIZE)
    else:
        inventory = read_jsonl(archive.metadata / stream["inventory"])
        extract_tar(path, target, inventory)
    path.unlink()


def restore(root, target, archive_id=None, key=None, certificate=None):
    root, target = Path(root).absolute(), Path(target).absolute()
    ensure_disjoint(root, target)
    if WORK_DIR.resolve().is_relative_to(root.resolve()) or WORK_DIR.resolve().is_relative_to(target.resolve()):
        raise ArchiveError("Archive and target must not contain the PoC work directory")
    archives = discover(root)
    selected = select(archives, archive_id)[0]
    with open_archive(selected, archives[selected]) as archive:
        encrypted = archive.format["encryption"] != "none"
        if encrypted and not key:
            raise ArchiveError("Encrypted archive requires --decrypt-key")
        if key:
            key = Path(key).absolute()
        if certificate:
            certificate = Path(certificate).absolute()
        empty_destination(target)
        directories = [entry for entry in archive.entries if entry["type"] == "directory" and entry["path"] != "."]
        directories.sort(key=lambda entry: len(relative_path(entry["path"]).parts))
        for entry in directories:
            (target / entry["path"]).mkdir()

        streams = {stream["stream"]: stream for stream in archive.streams}
        remaining = dict.fromkeys(streams, 0)
        for manifest in archive.manifests:
            for member in manifest["members"]:
                remaining[member["stream"]] += 1
        stream_order = {stream["stream"]: index for index, stream in enumerate(archive.streams)}
        # Process sets by logical stream position, not their random IDs or the
        # directory listing. Completed streams can then leave scratch promptly.
        manifests = sorted(archive.manifests, key=lambda manifest: min(
            (stream_order[member["stream"]], member["offset"]) for member in manifest["members"]))
        with scratch("streams-") as temporary:
            stream_directory = Path(temporary)
            for index, manifest in enumerate(manifests, 1):
                print(f"Restoring recovery set {index}/{len(manifests)}", flush=True)
                with scratch("restore-set-") as set_temporary:
                    directory = Path(set_temporary)
                    copy_set(archive, manifest, directory)
                    data_damage, _ = recover_set(archive, manifest, directory)
                    if data_damage:
                        print(f"Recovered {len(data_damage)} damaged/missing data chunks in scratch.", flush=True)
                    for member in manifest["members"]:
                        path = stream_directory / member["stream"]
                        mode = "r+b" if path.exists() else "w+b"
                        with path.open(mode) as output:
                            output.seek(member["offset"])
                            unpack_chunk(directory, member, output, encrypted, key, certificate)
                        remaining[member["stream"]] -= 1
                        if remaining[member["stream"]] == 0:
                            finish_stream(path, streams[member["stream"]], archive, target)
        for entry in archive.entries:
            if entry["type"] == "symlink":
                os.symlink(entry["symlink_target"], target / entry["path"])
        restore_metadata(target, archive.entries)
    print(f"Restore complete: {target}; content checksums verified. Archive files were not modified.")
