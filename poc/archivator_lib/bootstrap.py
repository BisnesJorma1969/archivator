"""Independent PAR2 protection for both catalog-root copies."""

import json
import os
from pathlib import Path

from .common import IntegrityError, scratch
from .external import check_parity, create_parity
from .format import Settings
from .limits import ceil_div, check_files, parity_plan
from .metadata import ConflictingRoots, catalog_root_names


def root_prefix(archive_id):
    return f"archive-{archive_id}_metadata_catalog-root"


def root_plan(lengths, settings):
    # This tiny set must recover BOTH root copies, plus one damaged slice.
    blocks = sum(ceil_div(length, settings.slice_size) for length in lengths.values()) + 1
    return parity_plan(lengths, settings.slice_size, settings.max_file_bytes, blocks=blocks)


def create_root_parity(directory, archive_id, settings, output=None):
    names = catalog_root_names(archive_id)
    lengths = {name: (directory / name).stat().st_size for name in names}
    plan = root_plan(lengths, settings)
    if sum(lengths.values()) + plan.total_bytes > settings.max_group_bytes:
        raise IntegrityError("Catalog-root metadata and PAR2 exceed the group limit")
    files = create_parity(directory, root_prefix(archive_id), names, settings.slice_size,
                          plan.blocks, output, plan.volumes)
    check_files([*(directory / name for name in names), *files],
                settings.max_file_bytes, settings.max_group_bytes)
    return files


def recover_root(archive_id, files, temporary, in_place=False):
    """Root PAR2 must work before any settings or checksum chain can be read."""
    from .recovery import read_catalog_root, stage_existing, remove_repair_backups
    names = catalog_root_names(archive_id)
    prefix = root_prefix(archive_id)
    parity_names = [name for name in files if name.startswith(prefix + ".") and name.endswith(".par2")]
    if not any(name in files for name in names) and not parity_names:
        return None, []
    directory = files.root / "metadata" if in_place else temporary / "bootstrap"
    directory.mkdir(parents=True, exist_ok=True)
    if not in_place:
        stage_existing(files, [*names, *parity_names], directory, writable=False)
    try:
        marker, damage = read_catalog_root(archive_id, files)
    except ConflictingRoots:
        raise
    except IntegrityError:
        if not parity_names:
            raise
        damage = list(names)
        if not in_place:
            # Unknown/corrupt roots must not remain hardlinks during repair.
            for name in names:
                (directory / name).unlink(missing_ok=True)
            stage_existing(files, names, directory)
        previous = {path.relative_to(directory) for path in directory.iterdir()}
        if check_parity(directory, prefix) != 1 or check_parity(directory, prefix, repair=True) != 0:
            raise IntegrityError("Neither catalog-root copy nor its PAR2 can recover the checksum root")
        candidates = {name: directory / name for name in names}
        marker, _ = read_catalog_root(archive_id, candidates)
        remove_repair_backups(directory, names, previous)
    settings = Settings(**marker["settings"])
    if settings.par2:
        size = len((json.dumps(marker, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii"))
        lengths = dict.fromkeys(names, size)
        plan = root_plan(lengths, settings)
        if check_parity(directory, prefix) or len(parity_names) != plan.volumes + 1:
            damage.append(prefix + " (root PAR2 damage)")
    return marker, damage


def repair_root(archive_id, files, marker):
    from .common import write_json
    settings = Settings(**marker["settings"])
    directory = files.root / "metadata"
    names = catalog_root_names(archive_id)
    encoded = (json.dumps(marker, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii")
    for name in names:
        path = directory / name
        if not path.is_file() or path.read_bytes() != encoded:
            write_json(path, marker)
    if not settings.par2:
        return
    prefix = root_prefix(archive_id)
    plan = root_plan({name: (directory / name).stat().st_size for name in names}, settings)
    paths = list(directory.glob(prefix + "*.par2"))
    if check_parity(directory, prefix) == 0 and len(paths) == plan.volumes + 1:
        return
    with scratch("root-parity-") as temporary:
        fresh = create_root_parity(directory, archive_id, settings, Path(temporary))
        for path in paths:
            path.unlink()
        for path in fresh:
            os.replace(path, directory / path.name)
