# Minimal Archivator PoC

This document describes the implemented PoC. See [README.md](README.md) for
Ubuntu 26.04 setup and the demo, [poc/README.md](poc/README.md) for CLI usage,
and [poc/FORMAT.md](poc/FORMAT.md) for manual recovery.

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
and byte-budget bitrot tools live under `poc/demo/`. Generated development data,
test certificates, and verification/repair/restore scratch use gitignored `poc/work/`.

Keep code human-readable: straightforward functions and control flow, descriptive
names, comments for non-obvious reasoning, and no unnecessary abstractions.

---

## 2. Dependencies and tool execution

The [root README install section](README.md#install) is the single dependency
list for the CLI, demo, automated tests, and manual recovery on Ubuntu 26.04.

Executables are found on `PATH`, with `poc/work/tools/usr/bin/` as a local fallback.
PAR2 main processing and file hashing are limited to one thread each.
Integration testing is performed on Linux; Windows/macOS execution is not claimed
as tested.

Do not implement custom cryptography or custom parity.

---

## 3. CLI

Command signatures and options are in the [CLI reference](poc/README.md).
The [root README](README.md) contains the runnable workflow.

`verify`, `repair`, `restore`, and `scan` accept optional `--archive-id ID`. Without a
selector, verify checks all discovered archive IDs and reports incomplete
archives. Repair, normal restore, and scan require a selector when multiple IDs
are present. `restore --scan-index INDEX.json.zst` takes its ID from that index.

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
archive-<aid>_parity-<pid>_chunk-0003_stream-<sid>_offset-00000000000805306368_length-000268435456.zst.enc
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
archive-<aid>_parity-<pid>_manifest.json.zst
```

Archive-level metadata, completion markers, and metadata PAR2 share the prefix
`archive-<aid>_metadata_` and live at the archive root. Data-set manifests instead
share their data group's prefix and shard. Stream inventories use
`metadata_inventory_stream-<sid>.jsonl.zst`: these contain file descriptions,
not file contents.

The metadata recovery set has its own parity-set ID:

```text
archive-<aid>_metadata_parity-<pid>.par2
archive-<aid>_metadata_parity-<pid>.vol000+032.par2
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

Output is sharded under `ARCHIVE_DIR/<first-two-parity-ID-characters>/` using the
existing random data parity-set ID, not a new ID or hash. Data chunks, their PAR2
files, and their one-per-group manifest share that data set's shard. All other
metadata, including inventories, certificates, completion markers, and metadata
PAR2, stays at the archive root. Create a directory only when publishing files
into it; never pre-create all 256 possible shards. Multiple sets may share a
directory. Catalogs identify files by basename. Data PAR2 records shard-relative
basenames; metadata PAR2 records archive-relative paths, including the sharded
manifests it protects. Readers discover flat, nested, and mixed layouts and
arrange recovery inputs in the expected locations.

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

Create an unencrypted, zstd-compressed JSON-lines inventory:

```text
archive-<aid>_metadata_inventory_stream-<sid>.jsonl.zst
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

Use OpenSSL CMS with an X.509 recipient certificate containing an RSA encryption
key of at least **3072 bits**. Reject weaker RSA keys and other key types before
packing source data.

Use binary CMS AuthEnvelopedData with AES-256-GCM and DER encoding, via
`openssl cms -encrypt -binary -aes-256-gcm -outform DER`, with
`-recip recipient.pem -keyopt rsa_padding_mode:oaep -keyopt rsa_oaep_md:sha256
-keyopt rsa_mgf1_md:sha256`. RSA-OAEP transports the random per-chunk content key;
both OAEP and MGF1 explicitly use SHA-256.
[OpenSSL CMS options](https://docs.openssl.org/3.5/man1/openssl-cms/)

Each chunk is encrypted independently and stored with the **`.zst.enc`** suffix.
OpenSSL generates the content key and GCM nonce; restore checks authentication
before decompression and removes failed decryption output.

Backup creates its `.tmp` staging directory with owner-only access (`0700`) and
compressed plaintext chunks with owner-only read/write access (`0600`), independent
of a permissive caller umask. Restore uses owner-only scratch directories and
sets decryption output to `0600` before invoking OpenSSL. No streaming encryption
pipeline is required for this PoC.

Do not use:

```text
openssl enc
password-derived archive encryption
one encryption stream spanning multiple chunks
custom crypto formats
```

Store a normalized public certificate as `archive-<aid>_metadata_recipient.pem`, and its
SHA-256 fingerprint as `recipient-sha256` in `metadata_format.txt`. Certificate
normalization never copies a private-key PEM block into the archive metadata.

The decrypting private key is supplied externally and is never stored by the
encryption pipeline. The CLI accepts keys without a passphrase and does not prompt
for passwords. `--decrypt-key` is required for encrypted restore;
`--decrypt-cert` is optional.

Only compressed chunk contents are encrypted. Catalogs, inventories, original
paths, metadata, and checksums remain unencrypted, even when compressed. Verify and repair do not need a
private key and do not validate plaintext or CMS authentication; restore does.
Deferred security requirements are recorded in
[section 25](#25-cryptographic-limitations-and-production-requirements).

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

During backup, PAR2 reads the explicitly named stored data or metadata files
directly. Only generated PAR2 output goes into `.tmp/`; source members are not
copied or linked. An explicit PAR2 base directory keeps member names portable.

Do not use exponentially increasing Usenet-style recovery-volume sizes.

---

# 15. Parity-set manifest

For each data parity set create:

```text
archive-<aid>_parity-<pid>_manifest.json.zst
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
archive-<aid>_metadata_format.txt
archive-<aid>_metadata_streams.jsonl.zst
```

`metadata_format.txt` contains simple `key=value` fields such as:

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

`metadata_streams.jsonl` maps stream IDs to their meaning.

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
  "inventory": "archive-..._metadata_inventory_stream-....jsonl",
  "entry_count": 12345,
  "size": 987654321,
  "sha256": "...",
  "sha512": "..."
}
```

Metadata storage is fixed by file role, not size or compression ratio:

| Metadata | Storage |
| --- | --- |
| Completion-marker copies, `metadata_format.txt`, public `metadata_recipient.pem` | Uncompressed for bootstrap and inspection |
| Stream catalogs, file inventories, data-set manifests, checksum index | Always zstd-compressed, with `.zst` appended |

Use the same zstd level 3, single-threaded, checksummed frames as data chunks.
Only the compressed representation of compressed metadata is retained, even for
tiny files or when compression increases size. Catalog references use logical
names; the checksum index and completion markers record exact stored names.

Metadata protection has a non-circular dependency order:

1. `archive-<aid>_metadata_checksums.json.zst` maps exact filenames to SHA-256 values for the
   format, catalogs, inventories, optional certificate, data-set manifests, and
   all data-set PAR2 files.
2. A separate PAR2 metadata recovery set protects the ordinary metadata and
   checksum index. Data-set PAR2 files are checksummed by the index but are not
   members of this metadata recovery set.
3. `archive-<aid>_metadata_complete.json` and `archive-<aid>_metadata_complete-copy.json` are identical
   completion-marker copies, each atomically published after all protected files.
   Each contains:

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
   marker_sha256
   ```

The markers are bootstrap roots outside PAR2. `marker_sha256` hashes canonical
ASCII JSON of all fields except itself (sorted keys, compact separators), detecting
payload corruption without a checksum cycle. This is not a signature. Either
valid copy suffices; verify still reports a damaged/missing copy and repair
replenishes it. With no valid copy, automatic recovery fails. Conflicting valid
copies are rejected rather than guessed; interruption between marker updates
during repair can require manual intervention. Copies in one directory do not
protect against loss of that entire storage location. Manual recovery can still
use surviving PAR2 files and catalogs.

Checksums and metadata PAR2 cover the stored, possibly compressed bytes. Recover
and validate those bytes before decompression and interpretation. Verify/restore
recover in scratch; explicit repair recovers stored metadata in place. Decoded
metadata remains temporary scratch data in all cases. The
checksum index's own stored-byte SHA-256 is in both markers.

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

compress metadata according to its fixed file role
write and compress checksum index
protect metadata and checksum index with PAR2

write both completion-marker copies last
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
Read-only inputs are hard-linked into scratch where supported, otherwise copied.
Metadata requiring scratch repair follows the isolation rules used by restore.

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

Recover stored metadata and data sets in place, without input copies or links.
Validate recovered stored content;
regenerate missing/damaged PAR2 files to restore the original protection. Intact
stored data can regenerate a completely lost parity set. Unrecoverable data or
metadata causes a hard failure.

If selected archive files are scattered, gather data chunks, data PAR2, and
data-set manifests into their data shards, and other metadata into the supplied
archive root. Use same-filesystem renames, never copies or links. This supplies
the relative paths recorded by both kinds of PAR2. Reject cross-filesystem layouts
before moving anything. Other archive IDs are left alone.

This is not an all-or-nothing transaction: failure can leave partial changes.
Report completed sets; delete only newly created PAR2 backup files after recovered
hashes pass. After the sets are usable, refresh checksums and metadata PAR2,
publish both updated completion-marker copies last, and verify directly in place.
Only newly generated outputs use `.tmp/`; decoded metadata uses temporary scratch.

## 18.3 Restore

Never assume the archive filesystem is writable.

Recover and validate metadata first. Require an absent or empty target and reject
unsafe source paths, duplicate entries, missing/non-directory ancestors, and
overlapping or missing chunk ranges before reconstructing content.

For each parity set:

```text
identify files by archive id + parity set id
hard-link read-only inputs into restore scratch
copy damaged stored data before any repair
run par2 verify
if required:
    run par2 repair
```

If all stored members are intact but the available PAR2 files cannot verify the
set, regenerate parity in scratch and verify it. There is no write-back to the
archive, and no need to replenish otherwise unnecessary parity during restore.

Healthy data is identified by its stored SHA-256 before linking. PAR2 volumes are
read-only inputs; regeneration unlinks their scratch names before writing new
volumes. If a damaged checksum index prevents classifying metadata, copy the
unknown metadata members too. Where hard links are unavailable, use ordinary
copies. Do not use symlinks or copy-on-write clones for this staging.

Do not scan unrelated terabytes of archive file contents.

Filename grouping provides the candidate set.

PAR2 decides which blocks are actually valid.

After successful PAR2 verification:

```text
for each stored chunk:
    verify stored SHA-256
    CMS decrypt if required
    zstd decompress
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
verify entry types, sizes, symlink targets, and all file hashes against the stream inventory
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

## 18.4 Filename-only scan and recovery

`scan ARCHIVE_DIR INDEX.json.zst` recursively indexes recognizable data chunk and
data PAR2 filenames, ignoring separate metadata and reading no archive contents.
The minimal compressed JSON index contains `format=archivator-scan`, `version=1`,
the archive ID, and a list of portable basenames. Coordinates and encryption flags
come only from filenames. No IDs or hashes are generated. Existing output indexes
are not overwritten; duplicate filenames are rejected rather than guessed.

Use the normal restore command with `--scan-index INDEX.json.zst` to select this
explicit recovery mode. It does not manufacture completion markers, inventories,
or authoritative hashes. Other archive files remain untouched. The index selects
one archive even when the search directory contains multiple archives.

Restore stages sets read-only first. If PAR2 reports repairable damage, copy the
set's data into scratch before repair because no trusted per-file hashes remain
to classify individual members. Successful PAR2 recovery can reveal missing chunk
filenames and entire previously unknown streams. Decode with the same CMS and
bounded zstd pipeline, checking frame integrity and declared plaintext length;
only unavailable manifest SHA-256/SHA-512 checks are omitted in this explicit mode.

After recovery, **skip whole streams** with gaps, overlaps, mixed encryption
flags, or unavailable/undecodable chunks. Do not write fragments or fill holes.
Recovered non-TAR bytes use `stream-<id>.bin`; recognized TAR bytes are retained as
`stream-<id>.tar` and safely extracted into separate `stream-<id>/` directories.
Original stream type is unknown: a standalone source file could itself be TAR,
so its bytes must not be discarded after extraction. Reject unsafe TAR paths,
special files, hard links, duplicate entries, non-directory ancestors, and missing
TAR end markers. No authoritative catalog means no automatic cross-stream merge.

Filename-only recovery cannot prove final stream lengths or detect entirely lost
streams. Missing tail chunks may be indistinguishable from a shorter intact file.
Report this limitation, missing original filenames/attributes, and unavailable
metadata checksums explicitly. Return `1` if any streams were skipped, parity sets
remain unresolved, or no streams were recovered; `0` means no detected failures,
not verified completeness of the original backup. Normal restore remains strict.
The runnable commands are in the [CLI reference](poc/README.md#filename-only-recovery).

---

# 19. Manual recovery requirement

The format must remain understandable without this Python program.

A technician must be able to reconstruct streams using standard tools and offsets
encoded in filenames. The custom PoC is automation; it must not be the only
implementation capable of recovery.

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

After scanning, announce the number of shared entries, comparable regular-file
pairs, and bytes to read across both trees. The five-second heartbeat reports
completed/total file pairs, cumulative MiB read, average MiB/s, and the current
source or target filename. Counters do not reset per file. Print total bytes read,
comparison duration, and average throughput at completion. This is progress
reporting, not per-file throttling; both copies are read fully for SHA-256.

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
zstd, OpenSSL, and PAR2 rather than silently skipping missing dependencies.
Demo tests also cover byte-budget corruption, zeroed runs, internal byte
insertion/deletion, original-offset damage reports, and mixed metadata/PAR2 damage.

The test command is in the [root README](README.md#automated-tests).

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

The [root README](README.md) contains the runnable acceptance workflow.
It must satisfy these conditions with encryption both enabled and disabled:

- Backup publishes a complete archive.
- Recoverable data, metadata, and parity damage is detected; verify reports
  repairable damage and exits `1`.
- Restore recovers in scratch without changing the damaged archive, and exits `0`.
- Compare reports an identical source and restored tree, and exits `0`.
- Explicit repair replenishes protection and exits `0`; subsequent verification
  reports an intact archive and exits `0`.

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
| Completion-marker copies | SHA-256 of canonical payload; duplicated, outside PAR2 |
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

---

## 25. Cryptographic limitations and production requirements

The PoC uses AES-256-GCM with RSA-OAEP/SHA-256 and RSA keys of at least 3072 bits.
RSA-3072 provides approximately 128-bit classical security; AES-256 does not make
the entire construction 256-bit secure or post-quantum secure.
[NIST key-strength guidance, Table 2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf)

The following gaps are recognized; their production remedies are intentionally
**not implemented in this PoC**:

1. **Private-key management.** The CLI accepts externally supplied, unencrypted
   private keys only. Password handling, encrypted-key support, key stores/HSMs,
   rotation, escrow, and recovery procedures are production work. Keep the private
   key separate from the archive; the PoC neither stores it nor manages its permissions.
2. **Recipient trust.** Key type and size are checked, but certificate identity,
   chain, validity, and revocation are not. Self-signed test certificates are
   supported. The operator must supply the intended public certificate through a
   trusted channel. Its fingerprint inside unsigned archive metadata is not a
   trust anchor. Production needs an explicit trust/pinning policy, with long-term
   decryption remaining possible after a certificate expires.
3. **Archive authenticity and context binding.** Metadata and completion markers
   are unsigned. SHA-256 and PAR2 detect/repair accidental damage, not malicious
   replacement. Chunk GCM tags do not authenticate the backup's author or bind
   external archive IDs, stream IDs, offsets, and catalogs. Anyone with the public
   certificate can construct a replacement encrypted archive. Production needs a
   trusted authenticated manifest/signature covering those relationships and an
   explicit rollback policy.
4. **Metadata confidentiality.** Paths, sizes, inventories, and checksums remain
   readable; compression is not encryption. Production must define which metadata
   is confidential and how it is protected without preventing recovery bootstrap.
5. **Plaintext on disk.** Staging/scratch permissions restrict access to the running
   user, but cleanup is not secure erasure. Crashes, snapshots, filesystem journals,
   privileged users, and storage remnants are not addressed. Use encrypted working
   storage when the threat model includes offline disk access; a production design
   must explicitly cover plaintext staging and restore destinations.
6. **Post-quantum key establishment.** RSA remains vulnerable to a sufficiently
   capable quantum computer, including later decryption of archives collected now.
   Ubuntu 26.04 provides OpenSSL 3.5.x: it has ML-KEM primitives, but CMS KEM recipient
   support was added in OpenSSL 3.6. This is not an AES algorithm substitution:
   supported CMS tooling, recipient-key/certificate handling, and interoperability
   testing are required. A standardized post-quantum key-establishment design is
   mandatory production work for long-lived confidential archives, deferred here.
   [Ubuntu OpenSSL package](https://packages.ubuntu.com/en/resolute/openssl),
   [OpenSSL CMS KEM support](https://docs.openssl.org/3.6/man3/CMS_get0_RecipientInfos/),
   [ML-KEM in CMS (RFC 9936)](https://www.rfc-editor.org/rfc/rfc9936.html),
   [NIST post-quantum guidance](https://www.nist.gov/cybersecurity-and-privacy/what-post-quantum-cryptography)
