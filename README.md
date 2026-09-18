# Archivator PoC

The goal is compressed, optionally encrypted backups that tolerate bitrot and
missing data through PAR2 parity. Backups are split into manageable chunks, with
parity protecting both stored data and recovery metadata.

They should remain restorable **decades from now**, using off-the-shelf Linux
tools—zstd, OpenSSL, PAR2, tar, and coreutils—even if Archivator itself is no longer
available.

Run the PoC commands below from the repository root on **Ubuntu 26.04**, using Bash.

## Install

This is the dependency list for the CLI, demo, automated tests, and manual recovery.

```bash
sudo apt update
sudo apt install -y python3 zstd openssl par2 coreutils tar
```

| Package | Requirement / purpose |
| --- | --- |
| `python3` | Python 3.11+; standard library only, no virtual environment needed |
| `zstd` | Data and metadata compression/decompression; `--single-thread` and `--check` support |
| `openssl` | OpenSSL 3.x with CMS AES-GCM, for encryption and encrypted tests |
| `par2` | par2cmdline with `-t` and `-T` thread controls, for recovery |
| `coreutils` | GNU `dd` and `sha256sum`, used by independent recovery tests and manual recovery |
| `tar` | Listing and extracting reconstructed TAR streams during manual recovery |

`par2` is in Ubuntu's Universe repository. Run the install commands once before
following any of the guides below.

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
python3 poc/demo/generate.py
```

Back up `source1`:

```bash
./poc/archivator backup poc/work/demo/source1 poc/work/demo/archive1
```

Intentionally damage its data, metadata, and PAR2 files:

```bash
python3 poc/demo/bitrot.py poc/work/demo/archive1 --percent 1
```

This damages roughly **1% of the backup's total stored size**, randomly choosing
files, byte ranges, and fault styles: bit flips, zeroing, copied data, insertion,
or deletion. `--dry-run` previews the plan; the report shows affected bytes and
the actual percentage. See [damage options](poc/demo/README.md#bitrot-options).
The damager accepts arbitrary files and already-damaged archives without validating
their format or metadata.

You can also manually delete any chosen data chunks (`*_chunk-*.zst` or `.zst.enc`) and
`.par2` files before verifying. There is no fixed safe file count: **each recovery
set needs at least as many surviving valid PAR2 recovery blocks as missing or
damaged data blocks**. Deleting PAR2 files reduces that capacity. Automatic
recovery needs at least one intact marker: `*_complete.json` or `*_complete-copy.json`.

Check the damaged archive:

```bash
./poc/archivator verify poc/work/demo/archive1
```

A nonzero exit status is expected for damage. Continue below when verify reports
**repairable**. Random damage or additional deletions can exhaust a recovery set,
in which case it reports **unrecoverable**.

Restore and compare:

```bash
./poc/archivator restore poc/work/demo/archive1 poc/work/demo/target1
./poc/archivator compare poc/work/demo/source1 poc/work/demo/target1
```

The final result should be **Trees are identical**. Restore leaves the damaged
archive unchanged. For the other workloads, repeat these commands with `source2`,
`archive2`, `target2`, or with `source3`, `archive3`, `target3`. Generate only once.

Optionally repair the archive in place and verify it is intact:

```bash
./poc/archivator repair poc/work/demo/archive1
./poc/archivator verify poc/work/demo/archive1
```

## Automated tests

```bash
python3 -m unittest discover -s poc/tests -t . -v
```

See [demo options](poc/demo/README.md), [CLI and encryption reference](poc/README.md),
[manual recovery](poc/FORMAT.md), and
[mandatory production checksum requirements](POC.md#24-mandatory-checksum-requirements-for-a-real-implementation).
