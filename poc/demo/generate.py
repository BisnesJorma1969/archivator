#!/usr/bin/env python3
"""Generate three synthetic workloads; never overwrite an existing demo."""

import argparse
import json
import math
import os
import random
import subprocess
import sys
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from poc.archivator_lib.common import ArchiveError
from poc.archivator_lib.external import executable

DEFAULT_ROOT = Path(__file__).resolve().parents[1] / "work" / "demo"
KIB = 1024
MIB = 1024 * KIB
BUFFER_SIZE = 64 * KIB
TIMESTAMP = 1756684800  # Fixed timestamps keep repeated generations comparable.

# Synthetic assumptions, not measurements of an actual office. Modern document
# containers are already compressed, so most of their payload is high entropy.
# extension, weight, median KiB, lognormal sigma, min/max KiB, random-byte fraction
OFFICE_PROFILES = [
    ("docx", 30, 64, 1.0, 4, 4096, (0.65, 0.95)),
    ("xlsx", 20, 96, 1.1, 8, 8192, (0.55, 0.90)),
    ("pdf", 25, 180, 1.0, 8, 12288, (0.65, 0.98)),
    ("pptx", 10, 512, 1.1, 32, 16384, (0.70, 0.98)),
    ("csv", 8, 64, 1.2, 1, 2048, (0.0, 0.0)),
    ("txt", 7, 16, 1.0, 1, 512, (0.0, 0.0)),
]
DEPARTMENTS = ["Finance", "Operations", "People", "Sales", "Engineering", "Legal"]
PROJECTS = ["Atlas", "Cedar", "Harbor", "Orion", "Summit", "Willow"]
TITLES = {
    "docx": ["Meeting minutes", "Project proposal", "Supplier agreement", "Quarterly review"],
    "xlsx": ["Annual budget", "Sales forecast", "Expense report", "Headcount plan"],
    "pdf": ["Purchase invoice", "Signed contract", "Product specification", "Board report"],
    "pptx": ["Customer briefing", "Strategy workshop", "Project kickoff", "Quarterly results"],
    "csv": ["Invoice export", "Inventory extract", "Customer list", "Timesheet export"],
    "txt": ["Release notes", "Workshop notes", "Action items", "Support transcript"],
}


def random_size(rng, median, sigma, minimum, maximum):
    size = int(rng.lognormvariate(math.log(median), sigma))
    return max(minimum, min(maximum, size))


def repeat_to_length(pattern, length):
    return (pattern * ((length + len(pattern) - 1) // len(pattern)))[:length]


def compressed_size(data):
    result = subprocess.run(
        [executable("zstd"), "-q", "-3", "--single-thread", "--check", "-c"],
        input=data, capture_output=True, check=True)
    return len(result.stdout)


def write_payload(path, size, rng, random_fraction, pattern):
    path.parent.mkdir(parents=True, exist_ok=True)
    remaining = size
    with path.open("xb") as output:
        while remaining:
            count = min(remaining, BUFFER_SIZE)
            random_bytes = int(count * random_fraction)
            # Generate fresh noise every time, not a repeated random block that
            # would accidentally make a supposedly compressed document compressible.
            output.write(rng.randbytes(random_bytes))
            output.write(repeat_to_length(pattern, count - random_bytes))
            remaining -= count
    os.utime(path, (TIMESTAMP, TIMESTAMP))


def office_pattern(extension, index, rng):
    if extension == "csv":
        lines = ["invoice,customer,department,amount,status\n"]
        for row in range(120):
            lines.append(f"INV-{index:06d}-{row:03d},Customer {rng.randrange(200):03d},"
                         f"{rng.choice(DEPARTMENTS)},{rng.randrange(100, 90000) / 100:.2f},approved\n")
        return "".join(lines).encode()
    if extension == "txt":
        lines = [f"{rng.choice(PROJECTS)}: review item {row:03d}; "
                 "owner Operations; status complete; follow up at the next planning meeting.\n"
                 for row in range(80)]
        return "".join(lines).encode()
    return (f"SYNTHETIC {extension.upper()} PAYLOAD {index:06d}; "
            "content size and entropy only, not an application-readable document.\n").encode()


def generate_office(root, count, rng):
    extensions = Counter()
    sizes = []
    samples = {}
    profiles = rng.choices(OFFICE_PROFILES, weights=[profile[1] for profile in OFFICE_PROFILES], k=count)
    for index, profile in enumerate(profiles, 1):
        extension, _, median, sigma, minimum, maximum, entropy = profile
        size = random_size(rng, median * KIB, sigma, minimum * KIB, maximum * KIB)
        date = datetime(2023, 1, 1) + timedelta(days=rng.randrange(975))
        directory = root / rng.choice(DEPARTMENTS) / str(date.year) / rng.choice(PROJECTS)
        name = (f"{rng.choice(TITLES[extension])} - {date:%Y-%m-%d} - "
                f"v{rng.randrange(1, 7):02d} - {index:06d}.{extension}")
        path = directory / name
        write_payload(path, size, rng, rng.uniform(*entropy), office_pattern(extension, index, rng))
        sizes.append(size)
        extensions[extension] += 1
        # A few small samples describe the workload; this is not a throughput benchmark.
        if len(samples.setdefault(extension, [])) < 8:
            with path.open("rb") as source:
                sample = source.read(BUFFER_SIZE)
            samples[extension].append(compressed_size(sample) / len(sample))
        if index % 2000 == 0:
            print(f"source1: {index:,}/{count:,} office files", flush=True)
    sizes.sort()
    return {
        "files": count, "bytes": sum(sizes), "extensions": dict(extensions),
        "size_bytes": {"minimum": sizes[0], "median": sizes[len(sizes) // 2],
                       "p95": sizes[int((len(sizes) - 1) * 0.95)], "maximum": sizes[-1]},
        "sample_zstd_ratios": {extension: round(sum(values) / len(values), 3)
                               for extension, values in samples.items()},
    }


def split_budget(total, count, rng):
    weights = [rng.uniform(0.7, 1.3) for _ in range(count)]
    sizes = [int(total * weight / sum(weights)) for weight in weights]
    sizes[-1] += total - sum(sizes)
    return sizes


def generate_sql(root, total_bytes, rng):
    backup_bytes = total_bytes * 3 // 4
    sizes = split_budget(backup_bytes, 3, rng) + split_budget(total_bytes - backup_bytes, 9, rng)
    databases = ["SalesLedger", "Warehouse", "ServiceDesk"]
    for index, size in enumerate(sizes):
        database = databases[index % len(databases)]
        if index < 3:
            name = f"{database}_full_2026-09-01_020000.bak"
        else:
            hour = 3 + (index - 3) // 3
            name = f"{database}_log_2026-09-01_{hour:02d}0000.trn"
        pattern = (f"SYNTHETIC SQL BACKUP {database}; page 000031; "
                   "transaction committed; account 001284; amount 120.00; "
                   "row data and unused page space; NOT A RESTORABLE DATABASE BACKUP.\n").encode()
        write_payload(root / database / name, size, rng, rng.uniform(0.35, 0.65), pattern)
        print(f"source2: {name} ({size / MIB:,.1f} MiB)", flush=True)
    return {"files": len(sizes), "bytes": sum(sizes), "extensions": {"bak": 3, "trn": 9},
            "file_sizes": sizes, "random_byte_fraction": [0.35, 0.65]}


def generate_logs(root, count, rng):
    total = 0
    services = ["api", "billing", "scheduler", "web", "warehouse", "sync"]
    for index in range(count):
        size = random_size(rng, 2 * KIB, 1.1, 256, 64 * KIB)
        service = rng.choice(services)
        host = f"{service}-{rng.randrange(1, 17):02d}"
        day = rng.randrange(1, 29)
        path = root / service / host / f"2026-08-{day:02d}" / f"{service}-{index:07d}.txt"
        line = (f"2026-08-{day:02d} 12:00:00 INFO {host} worker=04 "
                "request completed status=200 duration_ms=12 rows=24 retry=0\n").encode()
        write_payload(path, size, rng, 0, line)
        total += size
        if (index + 1) % 10000 == 0:
            print(f"source3: {index + 1:,}/{count:,} log files", flush=True)
    return {"files": count, "bytes": total, "extensions": {"txt": count}}


def generate(root=DEFAULT_ROOT, office_files=12000, log_files=60000, sql_mib=3072, seed=20260918):
    if min(office_files, log_files, sql_mib) <= 0:
        raise ValueError("File counts and SQL MiB must be positive")
    executable("zstd")
    root = Path(root).absolute()
    if root.is_symlink() or (root.exists() and any(root.iterdir())):
        raise ValueError(f"Use an absent or empty demo directory: {root}")
    root.mkdir(parents=True, exist_ok=True)
    for number in (1, 2, 3):
        (root / f"source{number}").mkdir()
    print(f"Generating in {root}; seed={seed}", flush=True)
    report = {
        "version": 1, "seed": seed, "synthetic": True,
        "settings": {"office_files": office_files, "log_files": log_files, "sql_mib": sql_mib},
        "sources": {},
    }
    # Independent seeds mean changing one workload's file count does not change the others.
    report["sources"]["source1"] = generate_office(root / "source1", office_files, random.Random(seed))
    report["sources"]["source2"] = generate_sql(root / "source2", sql_mib * MIB, random.Random(seed + 1))
    report["sources"]["source3"] = generate_logs(root / "source3", log_files, random.Random(seed + 2))
    for number in (1, 2, 3):
        for directory, _, _ in os.walk(root / f"source{number}", topdown=False):
            os.utime(directory, (TIMESTAMP, TIMESTAMP))
    with (root / "generation.json").open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
        output.write("\n")
    for name, summary in report["sources"].items():
        print(f"{name}: {summary['files']:,} files, {summary['bytes'] / MIB:,.1f} MiB")
    print("Sources ready. See the root README for backup, bitrot, restore, and compare commands.")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--office-files", type=int, default=12000)
    parser.add_argument("--log-files", type=int, default=60000)
    parser.add_argument("--sql-mib", type=int, default=3072, help="Total size of the three .bak and nine .trn files")
    parser.add_argument("--seed", type=int, default=20260918)
    args = parser.parse_args(argv)
    try:
        generate(args.root, args.office_files, args.log_files, args.sql_mib, args.seed)
    except (ArchiveError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
