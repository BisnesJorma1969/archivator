"""Small, independent PAR2 set for catalog roots and public bootstrap files."""

import hashlib
import json
import os
from pathlib import Path

from .common import IntegrityError, read_json, scratch
from .external import check_parity, create_parity
from .format import Settings
from .limits import ceil_div, check_files, parity_plan
from .metadata import ConflictingRoots, catalog_root_names

# Bootstrap files are tiny; using data-sized slices needlessly costs megabytes.
ROOT_SLICE_SIZE = 4096


def root_prefix(archive_id):
    return f"archive-{archive_id}_metadata_catalog-root"


def auxiliary_names(archive_id):
    return [f"archive-{archive_id}_metadata_format.txt",
            f"archive-{archive_id}_metadata_recipient.pem"]


def encoded_root(marker):
    return (json.dumps(marker, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")


def root_lengths(archive_id, marker):
    lengths = dict.fromkeys(catalog_root_names(archive_id), len(encoded_root(marker)))
    lengths.update({name: item["size"] for name, item in marker["bootstrap_files"].items()})
    return lengths


def root_plan(lengths, settings):
    # Recover all bootstrap inputs, including BOTH roots, plus one damaged slice.
    blocks = sum(ceil_div(length, ROOT_SLICE_SIZE) for length in lengths.values()) + 1
    return parity_plan(lengths, ROOT_SLICE_SIZE, settings.max_file_bytes, blocks=blocks)


def create_root_parity(directory, archive_id, settings, output=None):
    marker = read_json(directory / catalog_root_names(archive_id)[0])
    lengths = root_lengths(archive_id, marker)
    plan = root_plan(lengths, settings)
    if sum(lengths.values()) + plan.total_bytes > settings.max_datagroup_bytes:
        raise IntegrityError("Bootstrap metadata and PAR2 exceed the datagroup limit")
    files = create_parity(directory, root_prefix(archive_id), list(lengths), ROOT_SLICE_SIZE,
                          plan.blocks, output, plan.volumes)
    check_files([*(directory / name for name in lengths), *files],
                settings.max_file_bytes, settings.max_datagroup_bytes)
    return files


def recover_root(archive_id, files, temporary, in_place=False):
    """PAR2 bootstraps the catalog without trusting any external settings."""
    from .recovery import read_catalog_root, stage_existing, remove_repair_backups, mismatches
    roots = catalog_root_names(archive_id)
    names = roots + auxiliary_names(archive_id)
    prefix = root_prefix(archive_id)
    parity_names = [name for name in files if name.startswith(prefix + ".") and name.endswith(".par2")]
    if not any(name in files for name in roots) and not parity_names:
        return None, []
    directory = files.root if in_place else temporary / "bootstrap"
    directory.mkdir(parents=True, exist_ok=True)
    if not in_place:
        stage_existing(files, [*names, *parity_names], directory, writable=False)
    previous = {path.relative_to(directory) for path in directory.iterdir()}
    try:
        marker, damage = read_catalog_root(archive_id, files)
    except ConflictingRoots:
        raise
    except IntegrityError:
        if not parity_names:
            raise
        damage = list(roots)
        if not in_place:
            # Without a usable root, all bootstrap inputs are untrusted. Never
            # let PAR2 write through links to damaged archive originals.
            for name in names:
                (directory / name).unlink(missing_ok=True)
            stage_existing(files, names, directory)
        if check_parity(directory, prefix) != 1 or check_parity(directory, prefix, repair=True) != 0:
            raise IntegrityError("Neither catalog-root copy nor its PAR2 can recover the checksum root")
        marker, _ = read_catalog_root(archive_id, {name: directory / name for name in roots})
    settings = Settings(**marker["settings"])
    encoded = encoded_root(marker)
    hashes = dict.fromkeys(roots, hashlib.sha256(encoded).hexdigest())
    hashes.update({name: item["sha256"] for name, item in marker["bootstrap_files"].items()})
    damaged = mismatches(directory, hashes)
    damage.extend(name for name in damaged if name not in damage)
    # A valid root reconstructs its identical partner without using parity.
    for name in roots:
        if name in damaged:
            (directory / name).unlink(missing_ok=True)
            (directory / name).write_bytes(encoded)
    bad_auxiliary = mismatches(directory, hashes)
    if bad_auxiliary and settings.par2 and check_parity(directory, prefix) == 1:
        if not in_place:
            for name in bad_auxiliary:
                (directory / name).unlink(missing_ok=True)
            stage_existing(files, bad_auxiliary, directory, hashes)
        check_parity(directory, prefix, repair=True)
    remaining = mismatches(directory, hashes)
    if remaining and in_place:
        raise IntegrityError("Bootstrap auxiliary files cannot be recovered")
    if not remaining:
        remove_repair_backups(directory, hashes, previous)
    for name in marker["bootstrap_files"]:
        if name not in remaining:
            files[name] = directory / name
    if settings.par2:
        plan = root_plan(root_lengths(archive_id, marker), settings)
        if check_parity(directory, prefix) or len(parity_names) != plan.volumes + 1:
            damage.append(prefix + " (root PAR2 damage)")
    return marker, damage


def repair_root(archive_id, files, marker):
    settings = Settings(**marker["settings"])
    directory = files.root
    encoded = encoded_root(marker)
    for name in catalog_root_names(archive_id):
        path = directory / name
        if not path.is_file() or path.read_bytes() != encoded:
            path.write_bytes(encoded)
    if not settings.par2:
        return
    prefix = root_prefix(archive_id)
    plan = root_plan(root_lengths(archive_id, marker), settings)
    paths = list(directory.glob(prefix + "*.par2"))
    if check_parity(directory, prefix) == 0 and len(paths) == plan.volumes + 1:
        return
    with scratch("root-parity-") as temporary:
        fresh = create_root_parity(directory, archive_id, settings, Path(temporary))
        for path in paths:
            path.unlink()
        for path in fresh:
            os.replace(path, directory / path.name)
