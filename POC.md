# Minimal Archivator PoC

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

---

## 2. Runtime dependencies

Use:

```text
python 3.11+
openssl 3.x
par2cmdline
```

Python stdlib otherwise.

Do not implement custom cryptography or custom parity.

---

## 3. CLI

```bash
archivator backup SOURCE_DIR ARCHIVE_DIR
archivator backup SOURCE_DIR ARCHIVE_DIR --encrypt-cert recipient.pem

archivator verify ARCHIVE_DIR

archivator restore ARCHIVE_DIR RESTORE_DIR
archivator restore ARCHIVE_DIR RESTORE_DIR \
    --decrypt-key recipient-key.pem \
    --decrypt-cert recipient.pem

archivator compare SOURCE_DIR RESTORE_DIR
```

Exit non-zero on any corruption, missing data, decryption failure, hash mismatch, PAR2 failure, or tree mismatch.

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
archive-<aid>_parity-<pid>_chunk-0003_stream-<sid>_offset-00000000003221225472_length-001073741824.gz.cms
```

Unencrypted:

```text
archive-<aid>_parity-<pid>_chunk-0003_stream-<sid>_offset-00000000003221225472_length-001073741824.gz
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

A file copied out of its original directory must still identify:

```text
archive
parity set
chunk number
stream
plaintext offset
plaintext length
```

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

crc16_ccitt_false
crc32
md5
sha1
sha256
sha512
```

Hashes other than SHA-256/SHA-512 are primarily lookup aids.

SHA-256 is the normal authoritative content checksum.

Hash file contents while building the TAR. Do not reread merely to calculate another hash.

---

# 9. Large files

Files >= 256 MiB become streams directly.

Do not TAR them merely for packaging.

Their original path and metadata are recorded in the archive catalog.

---

# 10. Chunking

Each stream is divided into fixed plaintext ranges.

PoC default:

```text
chunk size = 256 MiB
```

Tests may use a smaller internal setting.

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

Compress every chunk independently with standard gzip:

```text
plaintext chunk
    -> gzip
```

Do not gzip an entire 40 TB stream as one compression stream.

Each `.gz` must be independently decompressible with ordinary `gzip`.

---

# 12. Optional encryption

Encryption is a transform, not an intrinsic archive requirement.

Without encryption:

```text
plaintext
-> gzip
-> stored chunk
```

With encryption:

```text
plaintext
-> gzip
-> CMS AES-256-GCM
-> stored chunk
```

Use OpenSSL CMS with an X.509 recipient certificate.

Each chunk is encrypted independently.

Do not use:

```text
openssl enc
password-derived archive encryption
one encryption stream spanning multiple chunks
custom crypto formats
```

Store the public recipient certificate and its fingerprint in archive metadata.

Never store the private key in the archive.

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

Convert that to PAR2 recovery-block count using the configured PAR2 slice size.

This deliberately gives the final short parity set a higher percentage of redundancy.

Do not pad the final parity set with fake/random data.

Create:

```text
1 PAR2 index file
4 approximately uniform recovery-volume files
```

Use normal PAR2 format and filenames.

Do not use exponentially increasing Usenet-style recovery-volume sizes.

---

# 15. Parity-set manifest

For each parity set create:

```text
archive-<aid>_parity-<pid>_manifest.json
```

It contains:

```text
format version
archive id
parity set id
PAR2 slice size
recovery capacity
expected data-member count

for every member:
    exact archive filename
    chunk number
    stream id
    plaintext offset
    plaintext length
    stored length
    plaintext sha256
    stored sha256
```

This manifest is convenience metadata.

PAR2 remains authoritative for identifying its protected file content.

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
compression=gzip
encryption=none
chunk-size=268435456
parity=par2-v2
parity-data-members=8
parity-slice-size=1048576
```

`streams.jsonl` maps stream IDs to their meaning.

Direct file:

```json
{
  "stream": "...",
  "type": "file",
  "path": "database/example.bak",
  "size": 123456789,
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

Metadata itself must also have SHA-256 checksums.

For the PoC, protect final archive metadata using a separate PAR2 metadata recovery set.

---

# 17. Backup algorithm

Conceptually:

```text
scan source

classify:
    small files -> TAR streams
    large files -> direct streams

for each stream:
    produce plaintext chunks

    for each chunk:
        calculate plaintext hashes
        gzip
        optionally CMS-encrypt
        calculate stored SHA-256
        write completed chunk to temp filename
        atomically rename to final filename
        assign to current parity set

    whenever parity set reaches 8 chunks:
        generate PAR2
        generate parity-set manifest
        verify PAR2 set

finalize short parity set using increased redundancy rule

write archive catalogs/inventories

protect metadata with PAR2

write archive COMPLETE marker last
```

Never create zero-byte placeholders for future final archive files.

Incomplete work belongs only under:

```text
ARCHIVE_DIR/.tmp/
```

---

# 18. Restore algorithm

Never assume the archive filesystem is writable.

For each parity set:

```text
identify files by archive id + parity set id
copy that small candidate set to restore scratch
run par2 verify
if required:
    run par2 repair
```

Do not scan unrelated terabytes of archive files.

Filename grouping provides the candidate set.

PAR2 decides which blocks are actually valid.

After successful PAR2 verification:

```text
for each stored chunk:
    verify stored SHA-256
    CMS decrypt if required
    gunzip
    verify plaintext SHA-256
    write bytes to stream at filename/manifest offset
```

After a stream is reconstructed:

```text
verify whole-stream SHA-256
```

If stream type is `file`:

```text
write it to its original relative path
```

If stream type is `tar`:

```text
extract PAX TAR
verify extracted entries against files.jsonl
```

Restore directories, symlinks and basic POSIX metadata.

Never silently continue after failed verification.

---

# 19. Manual recovery requirement

The format must remain understandable without this Python program.

A technician should be able to do approximately:

```bash
par2 verify archive-..._parity-....par2
par2 repair archive-..._parity-....par2 archive-..._parity-...*

openssl cms ...
gzip -dc ...
sha256sum ...
```

and reconstruct streams using offsets encoded in filenames.

The custom PoC is automation.

It must not be the only implementation capable of recovery.

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
mtime
```

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

This must work:

```bash
archivator backup ./original ./archive \
    --encrypt-cert ./recipient.pem

# deliberately delete/corrupt recoverable archive chunks/parity files

archivator verify ./archive

archivator restore ./archive ./recovered \
    --decrypt-key ./recipient-key.pem \
    --decrypt-cert ./recipient.pem

archivator compare ./original ./recovered
```

Final command must exit `0`.

The same test must also pass with encryption disabled.

That is the PoC. Anything not required to prove this path should wait.

---

## Implementation clarifications

* Implementation and its documentation live under `poc/`; root `README.md` stays empty.
* Generated development data and restore scratch use gitignored `poc/work/`.
  Incomplete backup files still belong under `ARCHIVE_DIR/.tmp/`.
* `verify` never changes the archive. It reports whether damage is recoverable,
  but exits non-zero for any damage, including lost parity protection.
* `repair ARCHIVE_DIR [--archive-id ID]` repairs data and metadata and restores
  missing/damaged parity protection. Restore repairs scratch copies automatically.
* Verify checks all complete archives by default. Restore and repair require
  `--archive-id ID` when multiple archive IDs are present. Incomplete archives
  are reported, not silently ignored.
* Archive-file filesystem timestamps have no recovery significance. Preserve
  source metadata through ordinary target-system APIs; warn about known precision
  loss or unsupported metadata rather than implementing timestamp emulation.
* Prioritize readable code: straightforward functions and control flow, descriptive
  names, comments for non-obvious reasoning, and no unnecessary abstractions.
