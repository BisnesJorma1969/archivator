# Archivator PoC

A local-filesystem implementation of [the specification](../POC.md), using Python's
standard library, ordinary gzip, OpenSSL CMS AES-256-GCM, and PAR2.

## Requirements and entry points

- Python 3.11 or newer
- OpenSSL 3.x with CMS AES-GCM support
- par2cmdline with `-t` and `-T` thread controls
- For the independent manual-recovery test: `gzip`, GNU `dd`, and `sha256sum`

On Debian/Ubuntu, install the external tools with:

```sh
sudo apt-get install python3 openssl par2 coreutils gzip
```

Run from the repository root; no Python package installation is needed:

```sh
./poc/archivator --help
python3 -m poc --help
```

To use the short `archivator` command, add this repository's `poc/` directory to
your `PATH`. The implementation finds external tools on `PATH`. It also accepts
tools extracted under `poc/work/tools/usr/bin/`, which is how PAR2 was installed
in the development container without changing system packages:

```sh
mkdir -p poc/work
cd poc/work
apt-get download par2
dpkg-deb -x par2_*.deb tools
```

`work/` is gitignored. Test fixtures and restore scratch are created there and
cleaned up after use. Keep sufficient space there for a parity set, metadata, and
unfinished streams; backup temporary files instead live in `ARCHIVE_DIR/.tmp/`.

## Quick start

Run these commands from the repository root, with fresh archive/restore paths:

```sh
mkdir -p poc/work/example/original
printf 'hello\n' > poc/work/example/original/hello.txt

./poc/archivator backup poc/work/example/original poc/work/example/archive
./poc/archivator verify poc/work/example/archive
./poc/archivator restore poc/work/example/archive poc/work/example/restored
./poc/archivator compare poc/work/example/original poc/work/example/restored
```

Backup and restore destinations must be absent or empty. Source and destination
must not overlap. The source, archive being read, or restore target must not
contain the work directory itself; individual directories *under* `work/` are fine.

### Encryption

For a disposable test certificate and unencrypted test private key:

```sh
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout poc/work/example/recipient-key.pem \
  -out poc/work/example/recipient.pem \
  -subj '/CN=Archivator test' -days 1

./poc/archivator backup poc/work/example/original poc/work/example/encrypted \
  --encrypt-cert poc/work/example/recipient.pem

./poc/archivator restore poc/work/example/encrypted poc/work/example/decrypted \
  --decrypt-key poc/work/example/recipient-key.pem \
  --decrypt-cert poc/work/example/recipient.pem

./poc/archivator compare poc/work/example/original poc/work/example/decrypted
```

The archive stores only the normalized public certificate and its SHA-256
fingerprint. Catalogs, inventories, paths, sizes, and checksums remain plaintext.
Only compressed chunk contents are encrypted. The PoC's CLI accepts private keys
without a passphrase; it does not prompt for passwords or manage keys.

## Verify, repair, and restore

| Command | Meaning |
| --- | --- |
| `verify ARCHIVE_DIR` | Check every archive, report intact/repairable/unrecoverable, and never modify archive files. |
| `repair ARCHIVE_DIR` | Recover stored chunks and metadata, and replenish lost/damaged PAR2 protection. |
| `restore ARCHIVE_DIR RESTORE_DIR` | Repair scratch copies automatically, validate stored and plaintext content, then restore the tree. |

Verify returns **1 for any damage**, even when everything is recoverable. Its
output distinguishes data loss from damage that can be repaired. Verification
checks stored bytes and PAR2 capacity; it does not decrypt encrypted chunks or
promise that a particular private key will work. Restore verifies CMS
authentication, gzip, chunk hashes, whole-stream hashes, and TAR entry hashes.

Example after deliberately deleting or corrupting a recoverable chunk:

```sh
./poc/archivator verify poc/work/example/archive    # expected exit 1
./poc/archivator restore poc/work/example/archive poc/work/example/recovered
./poc/archivator compare poc/work/example/original poc/work/example/recovered

./poc/archivator repair poc/work/example/archive
./poc/archivator verify poc/work/example/archive    # expected exit 0
```

Verify can recover metadata in scratch to finish its diagnosis. Restore never
requires archive write access. Neither writes repairs back. Only `repair` does.
Repair commits verified improvements one parity set at a time; if a later set
fails, earlier repairs remain and the command reports this. It publishes refreshed
checksum metadata and the completion marker after all sets are usable.

Directories can contain multiple archives or nested archive directories. Names
are indexed once, then only the relevant parity set is copied/read. Verify checks
all discovered IDs and reports incomplete archives. Repair and restore require
`--archive-id ID` when more than one ID exists; verify also accepts that selector.
Duplicate identical filenames anywhere in the selected hierarchy are ambiguous
and rejected. Moving directories or changing archive-file mtimes is harmless.

Exit codes for all commands:

- `0`: success / intact archive / identical trees
- `1`: integrity, recovery, or comparison failure
- `2`: usage or operational failure

A failed backup has no completion marker and cannot be resumed. A failed restore
may leave verified files and partial output in its destination; use a fresh empty
destination for a retry. Neither command silently treats partial work as success.

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
- `filesystem.py`, `common.py`, `format.py`: scanning, checksums, names, and defaults
- `external.py`: OpenSSL and PAR2 command argument lists
- `backup.py`: TAR/direct streams, independent chunks, parity, and finalization
- `recovery.py`: archive discovery, metadata validation, verify, and explicit repair
- `restore.py`, `compare.py`: reconstruction, safe extraction, and tree comparison

Production settings are fixed to the specification. Tests pass a small `Settings`
instance directly; there are no tuning flags, parallel workers, or plugin layers.
Source changes observable through ordinary stat checks abort backup; this is not a
filesystem snapshot implementation.

## Tests

```sh
python3 -m unittest discover -s poc/tests -t . -v
```

The suite uses real OpenSSL/PAR2 and does not silently skip missing dependencies.
It covers all twenty required scenarios, a 2,001-file multi-TAR round trip,
encrypted and unencrypted loss/corruption, strict verification, explicit repair,
metadata recovery, read-only archives, CLI exit codes, and unsafe extraction.
It also reconstructs an encrypted direct-file stream using only PAR2, OpenSSL,
gzip, GNU dd, and sha256sum, without calling the PoC restore implementation.

See [FORMAT.md](FORMAT.md) for format details and manual recovery commands.
