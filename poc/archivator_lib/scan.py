"""Filename-only recovery indexes and best-effort restore without archive metadata."""

import json
import re
import shutil
import tarfile
import tempfile
from pathlib import Path

from .common import ArchiveError, BUFFER_SIZE, IntegrityError, scratch
from .external import ZstdWriter, check_parity, executable, run
from .filesystem import empty_destination, relative_path
from .format import CHUNK_NAME, ID, parse_chunk, parity_prefix
from .progress import progress
from .recovery import discover, select, stage_existing

DATA_PARITY_NAME = re.compile(
    rf"archive-(?P<archive>{ID})_parity-(?P<parity>{ID})"
    r"(?:\.vol[0-9]+\+[0-9]+)?\.par2")


def index_names(names, archive_id):
    """Validate portable basenames and derive all coordinates from them."""
    groups = {}
    chunks = {}
    for name in names:
        if not isinstance(name, str):
            raise IntegrityError("Scan index filenames must be strings")
        if CHUNK_NAME.fullmatch(name):
            entry = parse_chunk(name)
            if entry["length"] <= 0:
                raise IntegrityError(f"Invalid chunk length: {name}")
            entry["filename"] = name
            chunks[name] = entry
        else:
            match = DATA_PARITY_NAME.fullmatch(name)
            if not match:
                raise IntegrityError(f"Invalid recovery filename: {name!r}")
            entry = match.groupdict()
        if entry["archive"] != archive_id:
            raise IntegrityError("Scan index mixes archive IDs")
        group = groups.setdefault(entry["parity"], [])
        if name in group:
            raise IntegrityError(f"Duplicate scan index filename: {name}")
        group.append(name)
    return groups, chunks


def stream_problem(chunks):
    """A contiguous observed range is not proof that the stream's tail survived."""
    kinds = {chunk["kind"] for chunk in chunks}
    if len(kinds) != 1:
        return "inconsistent RAW/TAR types"
    if "tar" in kinds and len(chunks) != 1:
        return "a TAR stream must be one complete chunk"
    end = 0
    encryption = set()
    for chunk in sorted(chunks, key=lambda item: (item["offset"], item["filename"])):
        if chunk["offset"] > end:
            return f"missing bytes {end:,}..{chunk['offset'] - 1:,}"
        if chunk["offset"] < end:
            return f"overlapping chunk at offset {chunk['offset']:,}"
        end += chunk["length"]
        encryption.add(chunk["encrypted"])
    if len(encryption) != 1:
        return "inconsistent encryption flags"
    return None


def scan(root, output, archive_id=None):
    archives = discover(root)
    selected = select(archives, archive_id)[0]
    names = []
    for name, path in sorted(archives[selected].items()):
        if path.is_symlink() or not path.is_file():
            continue
        if CHUNK_NAME.fullmatch(name) or DATA_PARITY_NAME.fullmatch(name):
            names.append(name)
        elif "_chunk-" in name:
            print(f"Ignoring unrecognized chunk filename: {name!r}", flush=True)
    if not names:
        raise IntegrityError("No recognizable data chunks or data PAR2 files found")
    groups, chunks = index_names(names, selected)
    streams = {}
    for chunk in chunks.values():
        streams.setdefault(chunk["stream"], []).append(chunk)
    for stream, members in sorted(streams.items()):
        problem = stream_problem(members)
        print(f"Stream {stream}: {len(members):,} chunks; "
              f"{problem or 'no detected gaps in the observed range'}", flush=True)
    output = Path(output)
    if not output.name.endswith(".json.zst"):
        raise ArchiveError("Scan index filename must end in .json.zst")
    output.parent.mkdir(parents=True, exist_ok=True)
    # No archive contents, metadata, hashes, or PAR2 packets are read by scan.
    index = {"format": "archivator-scan", "version": 1, "archive": selected, "files": names}
    writer = ZstdWriter(output)
    try:
        writer.write((json.dumps(index, indent=2, sort_keys=True) + "\n").encode("ascii"))
        writer.finish()
    except BaseException:
        output.unlink(missing_ok=True)
        raise
    finally:
        writer.close()
    print(f"Scan complete: {len(chunks):,} chunks, {len(groups):,} parity sets; index: {output}")
    print("Filename-only index: original large-file paths, hashes, and final stream lengths are unknown.")
    print("Missing tail chunks or entirely missing streams cannot always be detected.")
    return selected


def read_index(path):
    try:
        index = json.loads(run([executable("zstd"), "-qdc", "--", str(path)],
                               activity="Reading filename-only recovery index"))
        if index["format"] != "archivator-scan" or index["version"] != 1:
            raise IntegrityError("Unsupported scan index")
        if not isinstance(index["archive"], str) or not re.fullmatch(ID, index["archive"]):
            raise IntegrityError("Invalid archive ID in scan index")
        if not isinstance(index["files"], list) or not index["files"]:
            raise IntegrityError("Scan index must list data chunks or data PAR2 files")
        groups, chunks = index_names(index["files"], index["archive"])
        return index["archive"], groups, chunks
    except (KeyError, TypeError, ValueError) as error:
        raise IntegrityError(f"Malformed scan index: {error}") from error


def recover_scanned_set(files, names, directory, archive_id, parity_id):
    # Verify read-only links first. Without manifests, a repair-needed set has
    # no trusted per-file hashes, so copy its data before allowing PAR2 writes.
    stage_existing(files, names, directory, writable=False)
    prefix = parity_prefix(archive_id, parity_id)
    status = check_parity(directory, prefix)
    if status == 1:
        data_names = [name for name in names if CHUNK_NAME.fullmatch(name)]
        for name in data_names:
            (directory / name).unlink(missing_ok=True)
        stage_existing(files, data_names, directory, writable=True)
        try:
            status = check_parity(directory, prefix, repair=True)
        except IntegrityError as error:
            print(f"PAR2 could not finish set {parity_id}: {error}", flush=True)
            status = 2
    if status:
        print(f"Set {parity_id}: no usable full-set PAR2 verification; checking surviving chunks individually.",
              flush=True)
    return status == 0


def publish_stream(path, target, stream, kind):
    """The filename declares the format; a RAW source can itself contain a TAR."""
    if kind == "raw":
        destination = target / f"stream-{stream}.raw"
        with path.open("rb") as source, destination.open("xb") as output:
            shutil.copyfileobj(source, output, BUFFER_SIZE)
        return
    bundle = tarfile.open(path, "r:")
    with bundle:
        members = bundle.getmembers()
        names = {}
        for member in members:
            name = relative_path(member.name)
            if str(name) in names or not (member.isfile() or member.isdir() or member.issym()):
                raise IntegrityError(f"Unsupported or duplicate TAR entry: {member.name!r}")
            if str(name) == "." and not member.isdir():
                raise IntegrityError("TAR root entry is not a directory")
            names[str(name)] = member
        for name in names:
            for parent in relative_path(name).parents:
                if str(parent) in names and not names[str(parent)].isdir():
                    raise IntegrityError(f"Non-directory TAR ancestor: {parent}")
        end = max((member.offset_data + (member.size + 511) // 512 * 512 for member in members), default=0)
        with path.open("rb") as source:
            source.seek(end)
            if source.read(1024) != bytes(1024):
                raise IntegrityError("Recognized TAR stream is missing its end markers")
        # Per-stream directories prevent collisions without an authoritative catalog.
        with tempfile.TemporaryDirectory(prefix=".scan-extract-", dir=target) as temporary:
            progress.update(f"Extracting recovered TAR stream {stream}: {len(members):,} entries")
            bundle.extractall(temporary, members=members, filter="data")
            Path(temporary).rename(target / f"stream-{stream}")
    # Keep the independent TAR available for recovery with ordinary tools.
    with path.open("rb") as source, (target / f"stream-{stream}.tar").open("xb") as output:
        shutil.copyfileobj(source, output, BUFFER_SIZE)


def restore_scanned(root, target, index_path, archive_id, key, certificate):
    from .restore import unpack_chunk

    selected, groups, known = read_index(index_path)
    if archive_id is not None and archive_id != selected:
        raise ArchiveError("Selected archive ID does not match scan index")
    archives = discover(root)
    if selected not in archives:
        raise IntegrityError("Scan index archive is not present in the supplied directory")
    files = archives[selected]
    if any(chunk["encrypted"] for chunk in known.values()) and not key:
        raise ArchiveError("Encrypted archive requires --decrypt-key")
    empty_destination(target)
    print("Filename-only restore: using chunk lengths, zstd checks, CMS authentication, and available PAR2.")
    print("Original metadata hashes and final stream lengths are unavailable; completeness is not guaranteed.")
    restored = skipped = 0
    unresolved_sets = []
    with scratch("scan-streams-") as temporary:
        decoded = Path(temporary)
        usable = {}
        for number, (parity_id, names) in enumerate(sorted(groups.items()), 1):
            print(f"Recovering scanned set {number}/{len(groups)}: {parity_id}", flush=True)
            with scratch("scan-set-") as set_temporary:
                directory = Path(set_temporary)
                verified = recover_scanned_set(files, names, directory, selected, parity_id)
                recovered = []
                for path in sorted(directory.iterdir()):
                    if not CHUNK_NAME.fullmatch(path.name):
                        continue
                    chunk = parse_chunk(path.name)
                    if chunk["archive"] != selected or chunk["parity"] != parity_id:
                        raise IntegrityError("PAR2 recovered a chunk belonging to a different set")
                    if chunk["length"] <= 0:
                        raise IntegrityError("PAR2 recovered a chunk with an invalid declared length")
                    chunk["filename"] = path.name
                    known[path.name] = chunk
                    recovered.append(chunk)
                if (not recovered and not verified) or (not verified and any(name.endswith(".par2") for name in names)):
                    unresolved_sets.append(parity_id)
                for chunk in recovered:
                    if chunk["encrypted"] and not key:
                        raise ArchiveError("Encrypted chunks recovered by PAR2 require --decrypt-key")
                    plaintext = decoded / (chunk["filename"] + ".plain")
                    try:
                        with plaintext.open("xb") as output:
                            # Missing metadata is explicit here; normal restore
                            # always requires its authoritative SHA-256/SHA-512.
                            unpack_chunk(directory, chunk, output, chunk["encrypted"], key, certificate,
                                         verify_hashes=False)
                    except IntegrityError as error:
                        plaintext.unlink(missing_ok=True)
                        print(f"Unreadable chunk {chunk['filename']}: {error}", flush=True)
                    else:
                        usable[chunk["filename"]] = plaintext
        streams = {}
        for chunk in known.values():
            streams.setdefault(chunk["stream"], []).append(chunk)
        for stream, chunks in sorted(streams.items()):
            chunks.sort(key=lambda chunk: (chunk["offset"], chunk["filename"]))
            problem = stream_problem(chunks)
            if not problem and any(chunk["filename"] not in usable for chunk in chunks):
                problem = "a required chunk is missing or unreadable"
            if problem:
                skipped += 1
                print(f"Skipping stream {stream}: {problem}", flush=True)
                continue
            assembled = decoded / "assembled"
            progress.update(f"Assembling recovered stream {stream}: {len(chunks):,} chunks")
            with assembled.open("wb") as output:
                for chunk in chunks:
                    with usable[chunk["filename"]].open("rb") as source:
                        shutil.copyfileobj(source, output, BUFFER_SIZE)
                    usable[chunk["filename"]].unlink()
            try:
                publish_stream(assembled, target, stream, chunks[0]["kind"])
            except (IntegrityError, tarfile.TarError) as error:
                skipped += 1
                print(f"Skipping stream {stream}: {error}", flush=True)
            else:
                restored += 1
                print(f"Recovered stream {stream} ({assembled.stat().st_size:,} bytes)", flush=True)
            assembled.unlink()
    print(f"Filename-only restore: {restored:,} streams recovered; {skipped:,} skipped; "
          f"{len(unresolved_sets):,} unresolved parity sets. Archive files unchanged.")
    print("Original backup completeness remains unverified without the catalog.")
    return 1 if skipped or unresolved_sets or not restored else 0
