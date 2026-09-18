# Minimal Archivator PoC

This document describes the implemented PoC. See [poc/README.md](poc/README.md)
for setup and usage, and [poc/FORMAT.md](poc/FORMAT.md) for manual recovery.

## 1. Goal

Build a minimal local-filesystem proof of concept.

It must:

```text
source directory
    -> archive directory
    -> restored directory
```

and prove that the restored tree is identical to the source.

Support optional encryption.

Use PAR2 for corruption detection/recovery.

No cloud support. No networking. No workers. No benchmarking.

Implementation, tests, and detailed usage documentation live under `poc/`. The root
`README.md` provides a minimal Ubuntu 26.04 demo. Synthetic workload generation
and block-based bitrot tools live under `poc/demo/`. Generated development data,
test certificates, and verification/repair/restore scratch use gitignored `poc/work/`.

Keep code human-readable: straightforward functions and control flow, descriptive
names, comments for non-obvious reasoning, and no unnecessary abstractions.

---

## 2. Runtime dependencies

Use:

```text
python 3.11+
zstd
openssl 3.x
par2cmdline
```

Python stdlib otherwise.

OpenSSL must support CMS AES-GCM. The par2cmdline build must support `-t` and `-T`;
both main processing and file hashing are limited to one thread.

Executables are found on `PATH`, with `poc/work/tools/usr/bin/` as a local fallback.
The independent manual-recovery test also needs GNU `dd` and `sha256sum`.
Integration testing is performed on Linux; Windows/macOS execution is not claimed
as tested.

Do not implement custom cryptography or custom parity.

---

## 3. CLI

Run `./poc/archivator` or `python3 -m poc` from the repository root. The examples
use `archivator`, which is available when this repository's `poc/` is on `PATH`.
No Python package installation is required.

```bash
archivator backup SOURCE_DIR ARCHIVE_DIR
archivator backup SOURCE_DIR ARCHIVE_DIR --encrypt-cert recipient.pem

archivator verify ARCHIVE_DIR
archivator verify ARCHIVE_DIR --archive-id ID

archivator repair ARCHIVE_DIR
archivator repair ARCHIVE_DIR --archive-id ID

archivator restore ARCHIVE_DIR RESTORE_DIR
archivator restore ARCHIVE_DIR RESTORE_DIR --archive-id ID
archivator restore ARCHIVE_DIR RESTORE_DIR \
    --decrypt-key recipient-key.pem \
    --decrypt-cert recipient.pem

archivator compare SOURCE_DIR RESTORE_DIR
```

`verify`, `repair`, and `restore` accept optional `--archive-id ID`. Without a
selector, verify checks all discovered archive IDs and reports incomplete
archives. Repair and restore require a selector when multiple IDs are present.

Exit codes:

```text
0 = success / intact archive / identical trees
1 = integrity, recovery, or comparison failure
2 = usage or operational failure
```

Verify exits `1` for any detected damage, including recoverable damage or lost
parity protection. Repair and restore may succeed after automatically recovering
damage; unresolved corruption, missing data, decryption failure, or hash mismatch
must never silently succeed. See section 18 for the differences between commands.

Backup and restore destinations must be absent or empty and cannot be symlinks.
Backup source/archive and restore archive/target directories must not overlap.
The backup source and the archive/target supplied to restore must not contain
`poc/work/` itself; individual directories under `poc/work/` are fine.

---

# 4. Core terminology

Use these terms consistently:

**archive**
: One complete backup set.

**stream**
: One logical byte stream. Either:

* one sufficiently large original file, or
* one generated TAR containing many smaller files.

**chunk**
: One independently compressed/encrypted piece of a stream.

**parity set**
: Several stored chunks protected together by one PAR2 recovery set.

**offset**
: Byte offset within the original uncompressed stream.

Do not use `object`, `job`, or cloud terminology in the archive format.

---

# 5. IDs

Generate independent random 128-bit IDs:

```text
archive id
stream id
parity set id
```

Represent as 32 lowercase hexadecimal characters:

```text
6f31a8e18788456d942aab685383e21c
```

Use `secrets.token_hex(16)`.

No timestamps, source names, job names or destination names in archive data filenames.

Human-friendly names may be used for the outer directory, but must have no recovery significance.

---

# 6. Archive filename rules

Archive-generated filenames use only:

```text
a-z
0-9
-
_
.
```

`_` separates fields.

`-` separates field name from value.

Standard PAR2 recovery filenames may additionally contain `+`.

No spaces. No Unicode. Lowercase only.

Example encrypted chunk:

```text
archive-<aid>_parity-<pid>_chunk-0003_stream-<sid>_offset-00000000000805306368_length-000268435456.zst.cms
```

Unencrypted:

```text
archive-<aid>_parity-<pid>_chunk-0003_stream-<sid>_offset-00000000000805306368_length-000268435456.zst
```

PAR2:

```text
archive-<aid>_parity-<pid>.par2
archive-<aid>_parity-<pid>.vol000+032.par2
```

Parity-set convenience manifest:

```text
archive-<aid>_parity-<pid>_manifest.json
```

The metadata recovery set has a distinct role suffix:

```text
archive-<aid>_parity-<pid>_metadata.par2
archive-<aid>_parity-<pid>_metadata.vol000+032.par2
```

Chunk numbers use four decimal digits and are local to a parity set. Plaintext
offsets use twenty decimal digits and plaintext lengths twelve.

A chunk copied out of its original directory must still identify:

```text
archive
parity set
chunk number
stream
plaintext offset
plaintext length
```

Archive-file filesystem timestamps have no recovery significance. Directory
hierarchies may be moved or nested while preserving archive filenames. Readers
index filenames once and reject duplicate archive filenames in the searched
hierarchy rather than choosing one arbitrarily.

---

# 7. Source scanning

Recursively scan `SOURCE_DIR`.

PoC supports:

```text
directories
regular files
symbolic links
```

Reject:

```text
devices
sockets
fifos
other special files
```

Record original relative paths as JSON strings so arbitrary Unicode, tabs, newlines, spaces etc. can be represented safely.

Use relative POSIX-style paths in metadata, including `.` for the source root.
Scan with `lstat`; record symlinks without traversing them. The source root itself
must be a directory, not a symlink. Hard-linked files become independent regular
files; hard-link relationships and ownership are not preserved.

Abort on source changes observable through ordinary stat checks. This is not a
filesystem snapshot implementation.

---

# 8. Small-file bundling

Do not send millions of small files individually through the chunk pipeline.

Files smaller than:

```text
256 MiB
```

are candidates for TAR bundling.

Create POSIX/PAX TAR streams.

Target:

```text
~1 GiB source data per TAR
maximum 100000 entries per TAR
```

Do not split an individual source file between TARs.

Directories and symlinks, including the source root, are bundled with small files
and count toward the entry limit. The source-data size target counts file content,
not TAR headers/padding. Even an empty source produces a TAR with root metadata.

A TAR bundle receives a normal random stream ID and then enters exactly the same chunk pipeline as a large file.

Create a plaintext inventory:

```text
archive-<aid>_stream-<sid>_files.jsonl
```

Each original entry records as applicable:

```text
path
type
size
mode
mtime_ns
symlink_target

crc32
md5
sha1
sha256
sha512
```

Hashes other than SHA-256/SHA-512 are primarily lookup aids.

SHA-256 is the normal authoritative content checksum.

Hash file contents while building the TAR. Do not reread merely to calculate another hash.

Checksums are lowercase hexadecimal strings; ZIP-compatible CRC32 has eight
digits. Non-file entries have metadata but no file-content hashes.

---

# 9. Large files

Files >= 256 MiB become streams directly.

Do not TAR them merely for packaging.

Their original path and metadata are recorded in the archive catalog.

Record `mode`, `mtime_ns`, `size`, SHA-256, and SHA-512. The additional lookup
checksums listed for TAR inventory files are not generated for direct streams.

---

# 10. Chunking

Each stream is divided into fixed plaintext ranges.

PoC default:

```text
chunk size = 256 MiB
```

Tests use smaller internal `Settings` for chunk, large-file threshold, TAR,
parity-member, and slice sizes. The CLI exposes no tuning flags.

Chunks are independent.

For every chunk record:

```text
stream id
plaintext offset
plaintext length
plaintext sha256
plaintext sha512
stored sha256
```

The format must not depend on chunks being processed or restored in directory-listing order.

---

# 11. Compression

Compress every chunk independently with standard zstd:

```text
plaintext chunk
    -> zstd
```

Do not zstd an entire 40 TB stream as one compression stream.

Each `.zst` must be independently decompressible with ordinary `zstd`.

Use `zstd -q -3 --single-thread --check -c`: level 3, one thread for compression
and I/O, and a frame content checksum. No dictionaries are required. Frames do
not store source filenames or timestamps. Stream input and output through bounded
buffers; do not hold an entire chunk in memory.

[Zstd command documentation](https://github.com/facebook/zstd/blob/dev/programs/zstd.1.md)

---

# 12. Optional encryption

Encryption is a transform, not an intrinsic archive requirement.

Without encryption:

```text
plaintext
-> zstd
-> stored chunk
```

With encryption:

```text
plaintext
-> zstd
-> CMS AES-256-GCM
-> stored chunk
```

Use OpenSSL CMS with an X.509 recipient certificate.

Use binary CMS AuthEnvelopedData with AES-256-GCM and DER encoding, via
`openssl cms -encrypt -binary -aes-256-gcm -outform DER`.

Each chunk is encrypted independently.

Do not use:

```text
openssl enc
password-derived archive encryption
one encryption stream spanning multiple chunks
custom crypto formats
```

Store a normalized public certificate as `archive-<aid>_recipient.pem`, and its
SHA-256 fingerprint as `recipient-sha256` in `format.txt`. Certificate
normalization never copies a private-key PEM block into the archive metadata.

The decrypting private key is supplied externally and is never stored by the
encryption pipeline. The CLI accepts keys without a passphrase and does not prompt
for passwords. `--decrypt-key` is required for encrypted restore;
`--decrypt-cert` is optional.

Only compressed chunk contents are encrypted. Catalogs, inventories, original
paths, metadata, and checksums remain plaintext. Verify and repair do not need a
private key and do not validate plaintext or CMS authentication; restore does.

---

# 13. PAR2 grouping

PAR2 grouping occurs **after compression/encryption**.

Parity operates on the exact bytes stored in the archive.

Chunks from different streams may share a parity set.

Example:

```text
parity set X:

chunk 0 -> tar stream A
chunk 1 -> tar stream B
chunk 2 -> large file C offset 0
chunk 3 -> large file C offset 256 MiB
...
```

This is intentional.

Target:

```text
8 data chunks per parity set
PAR2 slice size = 1 MiB
```

A parity set does not cross archive boundaries.

---

# 14. PAR2 redundancy

Normal redundancy target:

```text
20% of total stored data in the parity set
```

But every set must also tolerate complete loss of at least one largest data member plus some additional corruption.

Calculate:

```text
target_recovery_bytes =
    max(
        total_stored_bytes * 0.20,
        largest_stored_member_bytes * 1.25
    )
```

Convert to whole recovery blocks, rounding upward, with two additional minimums:

```text
recovery_blocks = max(
    ceil(target_recovery_bytes / slice_size),
    ceil(largest_stored_member_bytes / slice_size) + 1,
    4
)
```

The extra block preserves the additional-corruption margin after slice rounding;
four blocks allow four nonempty recovery volumes even for tiny/compressible sets.
Use the same rule for the separate metadata recovery set. Slice sizes must be
positive multiples of four. Creation fails if the recovery-block count exceeds
par2cmdline's supported 32768-block limit; there is no automatic size adjustment.

This deliberately gives the final short parity set a higher percentage of redundancy.

Do not pad the final parity set with fake/random data.

Create:

```text
1 PAR2 index file
4 approximately uniform recovery-volume files
```

Use normal PAR2 format and filenames.

Create with an explicit slice size and recovery-block count, and `-u -n4` for
approximately uniform volumes. Verify newly generated sets before publishing
their PAR2 files.

Do not use exponentially increasing Usenet-style recovery-volume sizes.

---

# 15. Parity-set manifest

For each data parity set create:

```text
archive-<aid>_parity-<pid>_manifest.json
```

It contains these JSON fields:

```text
version
archive
parity
slice_size
recovery_blocks
recovery_bytes
member_count

members: array containing, for each chunk:
    filename
    chunk
    stream
    offset
    length
    stored_length
    plaintext_sha256
    plaintext_sha512
    stored_sha256
```

This manifest is convenience metadata.

PAR2 remains authoritative for identifying its protected file content.

Automation requires the manifest and validates its filename coordinates,
membership, hashes, and complete non-overlapping stream ranges. Data manifests
are themselves protected by the metadata recovery set. Metadata-set parameters
are recorded in the completion marker, not another self-protected manifest.

---

# 16. Archive catalog

Create:

```text
archive-<aid>_format.txt
archive-<aid>_streams.jsonl
```

`format.txt` contains simple `key=value` fields such as:

```text
format=archivator
version=1
archive=<aid>
compression=zstd
encryption=none
chunk-size=268435456
parity=par2-v2
parity-data-members=8
parity-slice-size=1048576
```

Encrypted archives use `encryption=cms-aes-256-gcm` and also record
`recipient-sha256=<lowercase hexadecimal certificate fingerprint>`.

`streams.jsonl` maps stream IDs to their meaning.

Direct file:

```json
{
  "stream": "...",
  "type": "file",
  "path": "database/example.bak",
  "size": 536870912,
  "mode": 420,
  "mtime_ns": 1700000000123456789,
  "sha256": "...",
  "sha512": "..."
}
```

TAR:

```json
{
  "stream": "...",
  "type": "tar",
  "inventory": "archive-..._stream-..._files.jsonl",
  "entry_count": 12345,
  "size": 987654321,
  "sha256": "...",
  "sha512": "..."
}
```

Metadata protection has a non-circular dependency order:

1. `archive-<aid>_checksums.json` maps exact filenames to SHA-256 values for the
   format, catalogs, inventories, optional certificate, data-set manifests, and
   all data-set PAR2 files.
2. A separate PAR2 metadata recovery set protects the ordinary metadata and
   checksum index. Data-set PAR2 files are checksummed by the index but are not
   members of this metadata recovery set.
3. `archive-<aid>_complete.json` is the completion marker, atomically published
   last. It contains:

   ```text
   version
   archive
   checksum_index
   checksum_index_sha256
   metadata_prefix
   metadata_members
   metadata_slice_size
   metadata_recovery_blocks
   metadata_parity: map of metadata PAR2 filenames to SHA-256 values
   ```

The completion marker is the unprotected bootstrap root: it is neither signed
nor self-checksummed. Missing or malformed markers cause automated verify,
repair, and restore to fail as incomplete/unusable archives. Manual recovery can
still use surviving PAR2 files and catalogs. The checksum index's own SHA-256 is
in the marker, avoiding a self-checksum cycle.

Recover and validate metadata in scratch before interpreting data manifests.

---

# 17. Backup algorithm

Conceptually:

```text
scan source

classify:
    small files, directories, symlinks -> TAR streams
    large files -> direct streams

for each stream:
    produce plaintext chunks

    for each chunk:
        determine current parity set and local chunk number
        calculate plaintext hashes
        zstd
        optionally CMS-encrypt
        calculate stored SHA-256
        write completed chunk to temp filename
        atomically rename to final filename
        record completed member in current parity set

    whenever parity set reaches 8 chunks:
        generate PAR2 in temporary staging
        verify PAR2 set
        publish PAR2 files and parity-set manifest

    publish the TAR inventory, if this is a TAR stream

finalize short parity set using increased redundancy rule

check source entries for observable changes
write archive catalog and format

write checksum index
protect metadata and checksum index with PAR2

write archive-<aid>_complete.json last
```

Never create zero-byte placeholders for future final archive files.

Incomplete backup files belong only under:

```text
ARCHIVE_DIR/.tmp/
```

The implementation processes TAR streams before direct-file streams, using the
same chunk/parity pipeline. It reads file data incrementally; scans and metadata
are retained in memory. It is not a bounded-memory metadata database.

Normal exception cleanup removes backup staging. Already-published chunks and
metadata may remain after failure, but without a completion marker the archive
is incomplete. Abrupt termination may leave `.tmp/`; cross-run resume is not
implemented. Use a fresh empty destination for a new backup.

---

# 18. Verify, repair, and restore

## 18.1 Verify

Never modify archive files. Recursively index archive filenames once, excluding
`.tmp/`, then operate on the selected archive IDs and small candidate sets in
`poc/work/` scratch. Do not open unrelated archives' content for a selected ID.

Recover metadata in scratch when necessary, retaining the original damage report.
For each data set, compare stored lengths/SHA-256 and PAR2-file SHA-256 values,
and run PAR2 verification to determine whether damaged data is recoverable.
Data chunks are not repaired by `verify`.

Report archive status as intact, repairable, or unrecoverable, with per-set damage
details. Lost or damaged parity protection is damage even when all data is intact;
it is repairable by regenerating parity from validated data. No private key is
required, and verification does not decompress chunks or check plaintext hashes.

Return `0` only if intact, `1` for integrity damage or incomplete archives, and
`2` for usage/operational failures. Scratch repairs never turn a damaged original
archive into a successful verification result.

## 18.2 Repair

`repair` is the only recovery command that writes back to the archive. It requires
write access but no private key.

Recover metadata and data sets in scratch. Validate recovered stored content;
regenerate missing/damaged PAR2 files to restore the original protection. Intact
stored data can regenerate a completely lost parity set. Unrecoverable data or
metadata causes a hard failure.

Publish validated replacements one set at a time, using adjacent `.tmp/` staging
and atomic per-file replacement. This is not an all-or-nothing archive transaction:
if a later operation fails, earlier verified repairs remain, and completed-set
progress is reported. After the sets are usable, refresh checksums and metadata
PAR2, publish the updated completion marker last, and verify the archive again.

## 18.3 Restore

Never assume the archive filesystem is writable.

Recover and validate metadata first. Require an absent or empty target and reject
unsafe source paths, duplicate entries, missing/non-directory ancestors, and
overlapping or missing chunk ranges before reconstructing content.

For each parity set:

```text
identify files by archive id + parity set id
copy that small candidate set to restore scratch
run par2 verify
if required:
    run par2 repair
```

If all stored members are intact but the available PAR2 files cannot verify the
set, regenerate parity in scratch and verify it. There is no write-back to the
archive, and no need to replenish otherwise unnecessary parity during restore.

Do not scan unrelated terabytes of archive file contents.

Filename grouping provides the candidate set.

PAR2 decides which blocks are actually valid.

After successful PAR2 verification:

```text
for each stored chunk:
    verify stored SHA-256
    CMS decrypt if required
    gunzip
    write plaintext to scratch stream at filename/manifest offset
    verify plaintext length, SHA-256, and SHA-512
```

After a stream is reconstructed:

```text
verify whole-stream length, SHA-256, and SHA-512
```

If stream type is `file`:

```text
write it to its original relative path
```

If stream type is `tar`:

```text
extract expected PAX TAR entries without following symlinks
verify entry types, sizes, symlink targets, and all file hashes against files.jsonl
```

Create directories first, then regular files, and symlinks only after all streams
have been validated. Reject unexpected TAR entries, traversal paths, duplicate
entries, and TAR hardlinks masquerading as regular files.

Apply source modes and timestamps through ordinary platform APIs. Restore
directory metadata deepest-first, with the source root last. Warn about known
target timestamp precision/range loss or unsupported symlink metadata; do not
emulate unavailable precision. Unrepresentable paths, unavailable symlink
creation, and other operational failures remain errors.

Never silently continue after failed verification.

Scratch is cleaned up on normal exit/error. A failed restore can leave verified
files or partial output in its target; retry into a fresh empty directory.

---

# 19. Manual recovery requirement

The format must remain understandable without this Python program.

A technician should be able to do approximately:

```bash
par2 verify archive-..._parity-....par2
par2 repair archive-..._parity-....par2 archive-..._parity-...*

openssl cms ...
zstd -dc ...
sha256sum ...
```

and reconstruct streams using offsets encoded in filenames.

The custom PoC is automation.

It must not be the only implementation capable of recovery.

The automated suite independently reconstructs an encrypted direct-file stream
with PAR2, OpenSSL, zstd, GNU `dd`, and `sha256sum`, without invoking the PoC's
restore code. Step-by-step commands are in [poc/FORMAT.md](poc/FORMAT.md).

---

# 20. Compare command

`compare SOURCE RESTORED` recursively compares:

```text
path set
entry type
regular-file size
regular-file SHA-256
symlink targets
```

On POSIX also compare:

```text
mode
mtime_ns (exact equality)
```

On non-POSIX platforms, do not compare POSIX modes; report timestamp differences
as warnings. A precision warning during restore does not relax subsequent exact
POSIX timestamp comparison. Content, path, type, size, and symlink-target
differences always fail comparison.

Report all differences found.

Exit:

```text
0 = identical
1 = differences
2 = operational failure
```

---

# 21. Required tests

Automate at least:

1. Empty tree.
2. Tiny files.
3. Thousands of small files producing multiple TAR streams.
4. Large file spanning multiple chunks.
5. One stream spanning multiple parity sets.
6. One parity set containing chunks from multiple streams.
7. Final parity set containing fewer than 8 chunks.
8. Unicode and awkward original filenames.
9. Symlinks.
10. Unencrypted backup → restore → compare success.
11. Encrypted backup → restore → compare success.
12. Flip bytes inside one stored encrypted/compressed chunk → PAR2 repairs → restore succeeds.
13. Delete one complete stored chunk → PAR2 repairs → restore succeeds.
14. Damage both data and one PAR2 recovery volume while remaining recovery capacity is sufficient.
15. Damage beyond available recovery capacity → hard failure.
16. Wrong private key → hard failure.
17. Rename/copy archive hierarchy while preserving actual archive filenames → recovery still works.
18. Mix unrelated archive files in one directory → archive IDs prevent confusion.
19. Randomize filesystem enumeration order → result unchanged.
20. Verify reconstructed output against original tree byte-for-byte.

Tests should use small internal chunk/slice sizes so they run without generating huge test data.

The stdlib `unittest` suite also covers strict verification statuses, explicit
repair, parity-only damage, lost metadata/checksum indexes, read-only archives,
CLI exit codes, unsafe extraction, source changes, and metadata precision warnings.
The multi-TAR test uses 2,001 small files. External-tool integration tests use real
OpenSSL and PAR2 rather than silently skipping missing dependencies.

Run from the repository root:

```sh
python3 -m unittest discover -s poc/tests -t . -v
```

---

# 22. Explicitly out of scope

Do not implement:

```text
Azure
AWS/S3
networking
multiple output targets
parallel workers
distributed orchestration
incremental backups
deduplication
immutable object-store semantics
cross-run resume
automatic media distribution
signing
key escrow
ACL/xattr/ADS preservation
ownership and hard-link relationship preservation
custom PAR2
custom cryptography
performance tuning
benchmarking
GUI
daemon/service
```

Keep filesystem I/O reasonably isolated so a later Azure/S3 adapter can replace it, but do not build a plugin framework yet.

---

# 23. PoC acceptance criterion

With the CLI on `PATH` and fresh archive/restore destinations, this must work:

```bash
set -e

archivator backup ./original ./archive \
    --encrypt-cert ./recipient.pem

# deliberately delete/corrupt recoverable archive chunks/parity files

# Damage is recoverable, but strict verification must return 1.
verify_status=0
archivator verify ./archive || verify_status=$?
test "$verify_status" -eq 1

archivator restore ./archive ./recovered \
    --decrypt-key ./recipient-key.pem \
    --decrypt-cert ./recipient.pem

archivator compare ./original ./recovered
```

The verify report must say the damage is repairable. Restore and the final
compare must exit `0`; neither command repairs the original archive in place.

Explicit repair must then restore clean verification:

```bash
archivator repair ./archive
archivator verify ./archive
```

Both commands must exit `0`, including when parity protection needed replenishing.

The same test must also pass with encryption disabled.

That is the PoC. Anything not required to prove this path should wait.

---

## 24. Mandatory checksum requirements for a real implementation

The following gaps are recognized and intentionally **not implemented in this
PoC**. Cloud support is outside this PoC's scope.

### Current coverage

| Bytes being checked | Implemented checksums |
| --- | --- |
| Source files inside TAR streams | MD5, SHA-1, SHA-256, SHA-512, ZIP-compatible CRC32 |
| Direct-file sources | SHA-256, SHA-512 only |
| Plaintext chunks and whole streams | SHA-256, SHA-512 |
| Stored chunks after compression and optional encryption | SHA-256 only |
| Ordinary metadata and PAR2 files | SHA-256 through the checksum hierarchy |
| Completion marker | No independent checksum or PAR2 protection |
| Cloud upload blocks and multipart/composite checksums | Not recorded |

### Requirements beyond the PoC

1. **Consistent source-file lookup checksums.** Record MD5, SHA-1, SHA-2 digests,
   and relevant CRCs for every source file, including direct files. Calculate them
   together during the source read. MD5, SHA-1, and CRCs serve compatibility and
   lookup, not authoritative integrity or authentication. The PoC's CRC32 is
   ZIP-compatible.
   [Python CRC32 documentation](https://docs.python.org/3/library/binascii.html#binascii.crc32)
2. **Stored-object checksums.** Checksum the exact bytes written after compression
   and encryption, separately from plaintext. Retain modern authoritative hashes
   and the additional algorithms and encodings needed to compare directly with
   S3/Azure checksums. Cover every stored object, not only payload chunks. Define
   a non-circular integrity/bootstrap design for checksum metadata itself.
3. **Fixed upload blocks.** Use **8 MiB upload-checksum blocks**, independently of
   256 MiB plaintext compression chunks and 1 MiB PAR2 slices. Record each block's
   offset, actual length (including the final short block), algorithm, and digest
   over stored bytes. The uploader must use exactly those boundaries. Handle
   provider part-count/object-size limits explicitly; do not silently resize parts
   while retaining incompatible recorded checksums. No upload blocks are currently
   calculated or uploaded by this PoC.
4. **Provider checksum semantics.** Distinguish whole-object digests from
   multipart/composite values, record the composition rules and wire encoding,
   and select algorithms explicitly in upload requests. S3 checksum support and
   full-object versus composite behavior depend on the algorithm and upload mode;
   a multipart ETag is not a full-file MD5. Azure Put Block supports transactional
   MD5 or CRC64 validation, which is not the same as a persisted full-blob digest.
   Do not treat Azure ETags as content hashes.
   [S3 checksum documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity-upload.html),
   [S3 multipart limits](https://docs.aws.amazon.com/AmazonS3/latest/userguide/qfacts.html),
   [Azure Put Block](https://learn.microsoft.com/en-us/rest/api/storageservices/put-block)

Provider-native CRC variants, cloud-compatible encodings, multipart composition,
and fixed upload-block checksum generation are mandatory production work, deferred
here to preserve the PoC's scope and standard-library-only Python implementation.
