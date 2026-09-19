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
Metadata may still be needed to recover original paths for standalone large-file
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

Encrypted data chunks end in `.zst.cms`. Metadata remains unencrypted.
Data chunks, data PAR2, and each data group's manifest share a two-character
shard directory from that group's ID. Other metadata and metadata PAR2 stay at
the archive root. Keep using `archive1` as the command argument; discovery is recursive.

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
damaged data blocks**. Deleting PAR2 files reduces that capacity. Automatic
recovery needs at least one intact marker: `*_metadata_complete.json` or `*_metadata_complete-copy.json`.

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

If metadata is lost, use [filename-only scan and recovery](poc/README.md#filename-only-recovery).
It can recover surviving streams without rebuilding the original metadata first.

## Automated tests

```bash
python3 -m unittest discover -s poc/tests -t . -v
```

See [demo options](poc/demo/README.md), [CLI and encryption reference](poc/README.md),
[manual recovery](poc/FORMAT.md), and
[mandatory production checksum requirements](POC.md#24-mandatory-checksum-requirements-for-a-real-implementation).
