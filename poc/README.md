# CLI reference

A local-filesystem implementation of [the specification](../POC.md), using Python's
standard library, ordinary zstd, OpenSSL CMS AES-256-GCM, and PAR2.

For installation and the runnable test workflow, use the [root README](../README.md).
This page describes command behavior and options. Commands use `./poc/archivator`
from the repository root; `--help` lists their arguments.

## Destinations and scratch

`work/` is gitignored. Test fixtures and restore scratch are created there and
cleaned up after use. Keep sufficient space there for a parity set, metadata, and
unfinished streams; backup temporary files instead live in `ARCHIVE_DIR/.tmp/`.

Backup and restore destinations must be absent or empty. Source and destination
must not overlap. The source, archive being read, or restore target must not
contain the work directory itself; individual directories *under* `work/` are fine.

## Encryption options

To enable encryption in the root README's workflow, add these options to its
backup and restore commands:

| Command | Option |
| --- | --- |
| `backup` | `--encrypt-cert poc/work/recipient.pem` |
| `restore` | `--decrypt-key poc/work/recipient-key.pem --decrypt-cert poc/work/recipient.pem` |

The remaining steps are identical. For a disposable test certificate and
unencrypted test private key:

```sh
mkdir -p poc/work
openssl req -x509 -newkey rsa:3072 -noenc \
  -keyout poc/work/recipient-key.pem \
  -out poc/work/recipient.pem \
  -subj '/CN=Archivator test' -days 1
```

Encryption requires an RSA key of at least 3072 bits. Each `.zst.enc` chunk uses
CMS AES-256-GCM with RSA-OAEP, SHA-256, and MGF1-SHA-256.
The archive stores only the normalized public certificate and its SHA-256
fingerprint. Catalogs, inventories, paths, sizes, and checksums remain plaintext.
Only compressed chunk contents are encrypted. The PoC's CLI accepts private keys
without a passphrase; it does not prompt for passwords or manage keys.
Plaintext staging uses owner-only directories and compressed/decrypted chunk files.
See [intentional cryptographic limitations](../POC.md#25-cryptographic-limitations-and-production-requirements)
for key management, metadata authentication, and post-quantum requirements.

## Commands and exit codes

Commands announce major stages and emit a status line to stderr every five seconds
while running, including during quiet zstd, OpenSSL, and PAR2 operations. Status
shows elapsed time, the current activity, and byte/entry counts where available.
Compare shows completed/total file pairs, cumulative MiB read from both trees,
average read/hash throughput, and the current source or target filename. These
are five-second snapshots, not a delay between files. It reads every matching
regular file on both sides; the final summary includes total bytes and duration.
It is an activity indicator, not an estimated completion percentage. Lines are
flushed immediately and also appear when output is redirected.

| Command | Meaning |
| --- | --- |
| `backup SOURCE_DIR ARCHIVE_DIR` | Create an archive from the source tree. |
| `verify ARCHIVE_DIR` | Check every archive, report intact/repairable/unrecoverable, and never modify archive files. |
| `repair ARCHIVE_DIR` | Recover stored chunks and metadata, and replenish lost/damaged PAR2 protection. |
| `restore ARCHIVE_DIR RESTORE_DIR` | Repair scratch copies automatically, validate stored and plaintext content, then restore the tree. |
| `compare SOURCE_DIR RESTORE_DIR` | Compare paths, types, file contents, and supported filesystem metadata. |

Verify returns **1 for any damage**, even when everything is recoverable. Its
output distinguishes data loss from damage that can be repaired. Verification
checks stored bytes and PAR2 capacity; it does not decrypt encrypted chunks or
promise that a particular private key will work. Restore verifies CMS
authentication, zstd, chunk hashes, whole-stream hashes, and TAR entry hashes.

Verify can recover metadata in scratch to finish its diagnosis. Restore never
requires archive write access. Neither writes repairs back. Only `repair` does.
Repair operates directly on stored data and metadata, with no staging copies or
links. If a later set fails, earlier changes remain and the command reports this.
It publishes refreshed
checksum metadata and both completion-marker copies after all sets are usable.

For read-only verification/restore, recovery scratch uses hard links for read-only
inputs. Before scratch repair, damaged data is copied, never repaired through a
hard link. If the checksum index is damaged, metadata whose health cannot yet be
established is copied too. Unsupported or cross-filesystem hard links fall back
to ordinary copies; no copy-on-write cloning is used.

Directories can contain multiple archives or nested archive directories. Names
are indexed once, then only the relevant parity set is read. Verify checks
all discovered IDs and reports incomplete archives. Repair and restore require
`--archive-id ID` when more than one ID exists; verify also accepts that selector.
Duplicate identical filenames anywhere in the selected hierarchy are ambiguous
and rejected. Moving directories or changing archive-file mtimes is harmless.
For in-place repair, scattered files of the selected archive are gathered beside
its valid completion marker using renames. This requires one filesystem; repair
does not fall back to copying across filesystems. Other archives are not moved.

Exit codes for all commands:

- `0`: success / intact archive / identical trees
- `1`: integrity, recovery, or comparison failure
- `2`: usage or operational failure

Backup cannot be resumed. Without either valid completion-marker copy, an archive
is incomplete. A failed restore may leave verified files and partial output in its
destination; use a fresh empty destination for a retry. Neither command silently
treats partial work as success.

## Filesystem conventions

Directories, regular files, and symlinks are supported. Special files are rejected.
Hard-linked source files are archived as independent regular files. Ownership,
ACLs, extended attributes, and alternate data streams are not preserved.

Modes and timestamps use ordinary platform APIs. Directory metadata is restored
last. Known timestamp precision/range loss or unsupported symlink metadata is
reported as a warning, without emulation. Compare checks modes and exact mtimes on
POSIX; on other platforms timestamp differences are warnings and POSIX modes are
not compared. Data, path, type, size, and symlink-target mismatches always fail.
Unrepresentable target paths and unavailable symlink creation fail explicitly.
Integration testing is performed on Linux; Windows/macOS execution is not claimed
as tested.

## Code map

`archivator_lib/` contains small modules with concrete responsibilities:

- `cli.py`: argument parsing and exit codes
- `progress.py`: periodic status display; does not parallelize archive processing
- `filesystem.py`, `common.py`, `format.py`: scanning, checksums, names, and defaults
- `external.py`: streaming zstd compression, OpenSSL, and PAR2 subprocesses
- `metadata.py`: fixed per-role zstd compression and completion-marker checksums
- `backup.py`: TAR/direct streams, independent chunks, parity, and finalization
- `recovery.py`: archive discovery, metadata validation, verify, and explicit repair
- `restore.py`, `compare.py`: reconstruction, safe extraction, and tree comparison

Production settings are fixed to the specification. Tests pass a small `Settings`
instance directly; there are no tuning flags, parallel workers, or plugin layers.
Source changes observable through ordinary stat checks abort backup; this is not a
filesystem snapshot implementation.

## Test coverage

The test command is in the [root README](../README.md#automated-tests).

The suite uses real zstd, OpenSSL, and PAR2 and does not silently skip missing dependencies.
It covers all twenty required scenarios, a 2,001-file multi-TAR round trip,
encrypted and unencrypted loss/corruption, strict verification, explicit repair,
metadata recovery, read-only archives, CLI exit codes, and unsafe extraction.
It also reconstructs an encrypted direct-file stream using only PAR2, OpenSSL,
zstd, GNU dd, and sha256sum, without calling the PoC restore implementation.

See [FORMAT.md](FORMAT.md) for format details and manual recovery commands.

## Checksum scope

The PoC does not provide uniform MD5/SHA-1/CRC coverage for direct-file sources,
cloud-compatible stored-object checksums, or fixed upload-block checksums. These
are [mandatory requirements for a real implementation](../POC.md#24-mandatory-checksum-requirements-for-a-real-implementation),
with 8 MiB upload blocks selected for that future work.
