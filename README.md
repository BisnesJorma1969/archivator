# Archivator PoC

Local backup, PAR2 recovery, restore, and comparison. Run these commands from the
repository root on **Ubuntu 26.04**, using Bash.

## Install

```bash
sudo apt update
sudo apt install -y python3 openssl par2 coreutils zstd
```

`par2` is in Ubuntu's Universe repository. Python uses only the standard library;
no virtual environment is needed.

## Generate, back up, damage, and restore

Allow roughly **30 GiB free** for sources, archives, restored files, and scratch.
Everything generated stays under gitignored `poc/work/`.

| Source | Default generated workload |
| --- | --- |
| `source1` | 12,000 office-like files, varied sizes and compressibility, about 2.8 GiB |
| `source2` | Three `.bak` and nine `.trn` files, semi-compressible, 3 GiB total |
| `source3` | 60,000 small, highly compressible `.txt` logs, about 210 MiB |

These are synthetic payloads with believable names, not valid Office documents
or database backups. Start with an absent/empty `poc/work/demo/`.

```bash
set -e
python3 poc/demo/generate.py

for n in 1 2 3; do
    ./poc/archivator backup "poc/work/demo/source$n" "poc/work/demo/archive$n"
done

# Intentionally corrupt data, metadata, and both kinds of PAR2 files.
python3 poc/demo/bitrot.py --percent 1

for n in 1 2 3; do
    status=0
    ./poc/archivator verify "poc/work/demo/archive$n" || status=$?
    test "$status" -eq 1   # Damage must be detected, even when repairable.
    ./poc/archivator restore "poc/work/demo/archive$n" "poc/work/demo/target$n"
    ./poc/archivator compare "poc/work/demo/source$n" "poc/work/demo/target$n"
done
```

Verify should report repairable damage; all three restores and comparisons must
succeed. Restore recovers in scratch without modifying the damaged archives.

Bitrot flips one bit in each selected **PAR2-sized block**, rounding upward in
each data/metadata/parity pool. Its JSON report records the actual percentages.
Use `--dry-run` to preview. The unprotected completion marker is excluded by
default; `--include-bootstrap` also damages it and can prevent automatic recovery.

Optionally repair the archives in place and verify they are clean:

```bash
for n in 1 2 3; do
    ./poc/archivator repair "poc/work/demo/archive$n"
    ./poc/archivator verify "poc/work/demo/archive$n"
done
```

Automated tests: `python3 -m unittest discover -s poc/tests -t . -v`.

See [demo options](poc/demo/README.md), [encryption and CLI usage](poc/README.md),
[manual recovery](poc/FORMAT.md), and
[mandatory production checksum requirements](POC.md#24-mandatory-checksum-requirements-for-a-real-implementation).
