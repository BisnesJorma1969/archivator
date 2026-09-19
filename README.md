# Archivator PoC

The goal is compressed, optionally encrypted backups that tolerate bitrot and
missing data through PAR2 parity. Backups are split into manageable chunks, with
parity protecting both stored data and recovery metadata.

They should remain restorable **decades from now**, using off-the-shelf Linux
tools—zstd, OpenSSL, PAR2, tar, and coreutils—even if Archivator itself is no longer
available. **Loss of separate metadata must not mean loss of file contents.**
The minimum for manual data recovery should be the intact backup data files,
retaining their chunk filenames, and the private decryption key when encrypted.
Everything else should use standard formats and tooling wherever possible.
Metadata may still be needed to recover original paths for standalone direct-file
streams and to verify that a backup is complete.

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
following any of the guides below. For the CLI alone, Python is mandatory;
zstd, OpenSSL, and PAR2 are needed only when using their respective features.

## Generate, back up, damage, and restore

Allow roughly **40 GiB free** for sources, archives, restored files, and scratch.
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

### Back up

Choose **one** backup mode for `source1`. `archive1` must be absent or empty.

**Without encryption:**

```bash
./poc/archivator backup poc/work/demo/source1 poc/work/demo/archive1
```

**With encryption:** create a disposable RSA private key and public certificate
once, then use the certificate for backup. Reuse the same pair for later runs;
do not overwrite a private key needed by existing backups. The PoC uses an
unencrypted private-key file; keep it outside the archive directory.

```bash
openssl req -x509 -newkey rsa:3072 -noenc \
  -keyout poc/work/recipient-key.pem \
  -out poc/work/recipient.pem \
  -subj '/CN=Archivator test' -days 1

./poc/archivator backup poc/work/demo/source1 poc/work/demo/archive1 \
  --encrypt-cert poc/work/recipient.pem
```

Compression and PAR2 default to enabled; encryption defaults to disabled.
Use `--no-compression` or `--no-par2` independently with either backup command.
For a plain archive with all three disabled:

```bash
./poc/archivator backup poc/work/demo/source1 poc/work/demo/archive1 \
  --no-compression --no-encryption --no-par2
```

This is another **alternative**, not a second backup into the same directory.
Without PAR2, checksums detect damage but cannot repair lost/corrupt payloads;
the repairable-damage walkthrough below assumes PAR2 is enabled.

Payload names distinguish complete TARs (`.tar.zst.cms`) from direct file bytes
(`.raw.zst.cms`); omit `.cms` without encryption and `.zst` without compression. Each TAR chunk can be extracted
independently. Source-name inventories are also encrypted (`.jsonl.zst.cms`). Each datagroup
keeps its metadata beside the data; byte-identical `-spare` copies are under `metadata/`.
Compression and PAR2 settings apply to both locations. Each datagroup has its own
directory under `data/<supergroup-prefix>/<supergroup-id>/`; `metadata/` mirrors
that hierarchy for spare indexes. Catalog roots, format text, the public certificate
and bootstrap PAR2 are at the archive root. Keep passing `archive1`; discovery is recursive.

Defaults: **268435455 bytes per stored file** and **15032385536 bytes per datagroup**,
including metadata and PAR2. Override with `--max-file-bytes` and
`--max-datagroup-bytes`, using exact bytes. No filesystem/media overhead is guessed.
A **datagroup** is one bounded data/metadata/PAR2 media unit. A **supergroup** contains
up to **5 datagroups**, with separate PAR2 sized for **110% of the largest protected
datagroup**, at least 20% overall. This protects against losing a whole datagroup plus
some additional damage. `--supergroup-datagroups` and `--supergroup-margin-percent`
are configurable; `--no-supergroup-par2` keeps only datagroup/metadata protection.
`--no-par2` disables every PAR2 layer. See [protection rules](POC.md#supergroup-protection-and-bounded-work).

Placement defaults to one active datagroup plus four waiting datagroups and a 95%
close-on-miss threshold; see the [queue options](poc/README.md#commands).

### Damage and verify (both modes)

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

You can also manually delete any chosen data chunks (`*_chunk-*.zst` or `.zst.cms`) and
`.par2` files before verifying. There is no fixed safe file count: **each recovery
set needs at least as many surviving valid PAR2 recovery blocks as missing or
damaged data blocks**. Deleting PAR2 files reduces that capacity. You can also
delete one chosen `data/<prefix>/<supergroup-id>/<datagroup-id>/` directory:
supergroup PAR2 can recover that datagroup while enough outer recovery blocks survive.
Do not delete the entire supergroup directory when testing a single-datagroup loss.
Both `*_metadata_catalog-root.json` and its `-spare` copy have their own PAR2
protection; either copy or sufficient bootstrap PAR2 is enough to start recovery.

Check the damaged archive:

```bash
./poc/archivator verify poc/work/demo/archive1
```

A nonzero exit status is expected for damage. Continue below when verify reports
**repairable**. Random damage or additional deletions can exhaust a recovery set,
in which case it reports **unrecoverable**.

### Restore and compare

Use the restore command matching your backup mode.

**Without encryption:**

```bash
./poc/archivator restore poc/work/demo/archive1 poc/work/demo/target1
```

**With encryption:**

```bash
./poc/archivator restore poc/work/demo/archive1 poc/work/demo/target1 \
  --decrypt-key poc/work/recipient-key.pem
```

Then compare (both modes):

```bash
./poc/archivator compare poc/work/demo/source1 poc/work/demo/target1
```

The final result should be **Trees are identical**. Restore leaves the damaged
archive unchanged. For the other workloads, repeat these commands with `source2`,
`archive2`, `target2`, or with `source3`, `archive3`, `target3`. Generate only once.

Optionally repair the archive in place and verify it is intact. Neither command
needs the private key:

```bash
./poc/archivator repair poc/work/demo/archive1
./poc/archivator verify poc/work/demo/archive1
```

Without central metadata, surviving datagroups can still restore their complete streams.
If local metadata is also lost, use [filename-only scan and recovery](poc/README.md#filename-only-recovery).
It can recover surviving streams without rebuilding the original metadata first.

## Automated tests

```bash
python3 -m unittest discover -s poc/tests -t . -v
```

See [demo options](poc/demo/README.md), [CLI and encryption reference](poc/README.md),
[manual recovery](poc/FORMAT.md), and
[mandatory production checksum requirements](POC.md#12-mandatory-checksum-requirements-for-a-real-implementation).
