"""Small datagroup closing summaries and listing-only checks, not content verification."""

import hashlib
import json
import re

from .common import IntegrityError
from .format import DATAFILE_NAME, ID, datagroup_metadata, datagroup_prefix, primary_metadata_name, stored_path
from .limits import MAX_PAR2_BLOCKS

GROUP = rf"archive-(?P<archive>{ID})_supergroup-(?P<supergroup>{ID})_datagroup-(?P<datagroup>{ID})"
SEAL_NAME = re.compile(GROUP + r"_sealed_data-(?P<data_files>[0-9]{1,20})-(?P<data_bytes>[0-9]{1,20})"
                       r"_metadata-(?P<metadata_files>[0-9]{1,20})-(?P<metadata_bytes>[0-9]{1,20})"
                       r"_parity-(?P<parity_files>[0-9]{1,20})-(?P<parity_bytes>[0-9]{1,20})\.json")
GROUP_NAME = re.compile(GROUP + r"(?:_|\.)")
LOCAL_PARITY = re.compile(GROUP + r"(?:\.vol[0-9]+\+[0-9]+)?\.par2")
ROLES = ("data", "metadata", "parity")


def seal_name(archive, supergroup, datagroup, counts):
    name = datagroup_prefix(archive, supergroup, datagroup) + "_sealed"
    for role in ROLES:
        name += f"_{role}-{counts[role]['files']}-{counts[role]['bytes']}"
    name += ".json"
    stored_path(".", name)  # The summary obeys the same portable path limits.
    return name


def seal_record(name):
    match = SEAL_NAME.fullmatch(name)
    if not match:
        raise IntegrityError("Invalid datagroup closing-summary filename")
    record = {"version": 1, **{field: match[field] for field in ("archive", "supergroup", "datagroup")}}
    for role in ROLES:
        record[role] = {field: int(match[f"{role}_{field}"]) for field in ("files", "bytes")}
        if record[role]["files"] == 0 and record[role]["bytes"] != 0:
            raise IntegrityError("Closing summary gives bytes for an empty category")
    return record


def seal_bytes(name):
    return (json.dumps(seal_record(name), sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def seal_reservation(archive, supergroup, datagroup, data_count, max_bytes):
    # Its final name includes actual PAR2 output sizes, unknown until PAR2 ends.
    # Reserve the largest counters that can fit the group, not an extra data copy.
    counts = {"data": {"files": data_count, "bytes": max_bytes if data_count else 0},
              "metadata": {"files": 2, "bytes": max_bytes},
              "parity": {"files": MAX_PAR2_BLOCKS + 1, "bytes": max_bytes}}
    name = seal_name(archive, supergroup, datagroup, counts)
    return name, len(seal_bytes(name))


def write_seal(directory, archive, supergroup, datagroup, data_names, metadata_names, parity_names):
    counts = {}
    for role, names in zip(ROLES, (data_names, metadata_names, parity_names)):
        counts[role] = {"files": len(names), "bytes": sum((directory / name).stat().st_size for name in names)}
    name = seal_name(archive, supergroup, datagroup, counts)
    path = directory / name
    with path.open("xb") as output:
        output.write(seal_bytes(name))
    return path


def restore_seal(receipt, archive, original, in_place):
    """The protected receipt binds the canonical reconstruction bytes to their hash."""
    item = receipt["seal"]
    name = item["filename"]
    record = seal_record(name)
    if any(record[field] != receipt[field] for field in ("archive", "supergroup", "datagroup")):
        raise IntegrityError("Closing summary belongs to another datagroup")
    content = seal_bytes(name)
    if len(content) != item["size"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
        raise IntegrityError("Closing summary and protected receipt disagree")
    from .common import sha256
    path = original.get(name)
    if path is None or path.is_symlink() or not path.is_file() or sha256(path) != item["sha256"]:
        archive.metadata_damage.append(name)
        target = stored_path(original.root, name) if in_place else archive.metadata / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.unlink(missing_ok=True)
        with target.open("xb") as output:
            output.write(content)
        archive.files[name] = target
    archive.checksums[name] = item["sha256"]


def quick_check(root, archive_id=None):
    """Only names and stat sizes are inspected. No metadata or payload is opened."""
    from .recovery import discover, select
    archives = discover(root)
    failures = 0
    total = 0
    for aid in select(archives, archive_id, allow_all=True):
        groups = {}
        for name, path in archives[aid].items():
            match = GROUP_NAME.match(name)
            if not match:
                continue
            key = (match["supergroup"], match["datagroup"])
            group = groups.setdefault(key, {"seals": [], "unexpected": [],
                                           **{role: {"files": 0, "bytes": 0} for role in ROLES}})
            if SEAL_NAME.fullmatch(name):
                group["seals"].append((name, path))
                continue
            if DATAFILE_NAME.fullmatch(name):
                role = "data"
            elif datagroup_metadata(name) and name == primary_metadata_name(name):
                role = "metadata"
            elif LOCAL_PARITY.fullmatch(name):
                role = "parity"
            elif (datagroup_metadata(name) or "_metadata_checksums.json" in name
                  or re.search(r"_metadata(?:\.vol[0-9]+\+[0-9]+)?\.par2$", name)):
                continue  # Central metadata and its parity are a separate set.
            else:
                group["unexpected"].append(name)
                continue
            if path.is_symlink() or not path.is_file():
                group["unexpected"].append(name)
                continue
            group[role]["files"] += 1
            group[role]["bytes"] += path.stat().st_size
        for (sid, gid), group in sorted(groups.items()):
            total += 1
            problems = []
            if len(group["seals"]) != 1:
                problems.append(f"expected one closing summary, found {len(group['seals'])}")
            else:
                name, path = group["seals"][0]
                expected = seal_record(name)
                if path.is_symlink() or not path.is_file() or path.stat().st_size != len(seal_bytes(name)):
                    problems.append("closing-summary type or size mismatch")
                for role in ROLES:
                    if group[role] != expected[role]:
                        problems.append(f"{role}: {group[role]['files']}/{expected[role]['files']} files, "
                                        f"{group[role]['bytes']:,}/{expected[role]['bytes']:,} bytes")
            if group["unexpected"]:
                problems.append(f"{len(group['unexpected'])} unexpected datagroup files")
            failures += bool(problems)
            print(f"Datagroup {gid}: " + ("; ".join(problems) if problems else "counts and sizes match"), flush=True)
    print(f"Listing-only check: {total} datagroups found; {failures} with discrepancies.")
    print("No contents or hashes checked. Entirely absent datagroups cannot be detected without a trusted inventory.")
    return 1 if failures or not total else 0
