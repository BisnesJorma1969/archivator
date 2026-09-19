# Minimal Archivator PoC

This document describes the implemented PoC. The [root README](README.md) is the
single Ubuntu 26.04 install/demo guide. See [CLI reference](poc/README.md) and
[format and manual recovery](poc/FORMAT.md) for details.

## 1. Goal and scope

Compressed, optionally encrypted, bitrot-tolerant backups, split into manageable
files and protected by standard PAR2. Restore with ordinary Linux tools even
decades later, without Archivator: PAR2, OpenSSL CMS, zstd, tar, and coreutils.
Loss of metadata does not by itself destroy payload bytes. Intact chunk filenames
supply their format and plaintext lengths, plus offsets for RAW chunks; encrypted payload also needs the
private key. Separate metadata supplies original direct-file names, attributes,
and authoritative completeness/checksum information.

The PoC proves `source directory → archive directory → restored directory`, with
`compare` checking the resulting tree. No cloud integration, networking, workers,
custom crypto, custom parity, resume protocol, or filesystem snapshots.

Compression, encryption and PAR2 are independently optional, in all eight
combinations. Defaults: zstd and PAR2 enabled, encryption disabled. Backup uses
`--compression` / `--no-compression`, `--par2` / `--no-par2`, and
`--encrypt-cert CERT.pem` / `--no-encryption` (omitting the certificate also disables
it). Compression controls payload and metadata; PAR2 controls local and central
protection. Readers discover modes from filenames and validated metadata.
Only enabled features require their external executables.

Implementation is under `poc/`; generated data and scratch use ignored
`poc/work/`. Keep code straightforward and human-readable.

## 2. Terminology and identifiers

| Term | Meaning |
| --- | --- |
| Archive | A complete backup, identified by an archive ID |
| Stream | Plaintext bytes of one original file or one ordinary POSIX/PAX TAR |
| Chunk | One complete TAR or a range of RAW file bytes, optionally compressed and/or encrypted |
| Group | Whole streams, or a spanning RAW file's range optionally followed by whole streams, plus metadata and optional PAR2 |
| Central metadata set | Identical metadata copies and their checksum receipt, optionally protected by separate PAR2 |

Archive IDs, stream IDs, and data-group IDs are random 128-bit identifiers, not
content hashes. Each is 32 lowercase hexadecimal digits. Central metagroup PAR2
**reuses its data group's ID**; no extra random metadata or shard IDs are generated.

A TAR is exactly one chunk. Several complete TARs and whole RAW files may share
one data group, including RAW files made of several chunks. A RAW file that cannot
fit an empty group starts fresh and spans as many groups as needed. Its final
group can accept subsequent whole files/TARs. A group describing a fragment is independently
interpretable and repairable, but cannot reproduce absent fragments.

## 3. Hard byte limits

| Setting / backup option | Default |
| --- | ---: |
| `max_file_bytes` / `--max-file-bytes` | 268435455 (256 MiB − 1 byte) |
| `max_group_bytes` / `--max-group-bytes` | 15032385536 (14 GiB) |
| `large_file_bytes` / `--large-file-bytes` | Automatic: the derived safe input ceiling |
| `waiting_groups` / `--waiting-groups` | 4, in addition to one active group |
| `group_close_percent` / `--group-close-percent` | 95, applied when the next whole unit does not fit |
| Internal PAR2 `slice_size` | 1048576 (1 MiB) |

These are exact byte counts. The program does not interpret media marketing
capacities, estimate formatting overhead, or subtract filesystem space. For a
FAT32 file ceiling, specify **4294967295** bytes. The user supplies a suitable
usable group capacity for the destination medium.

The file ceiling applies to **every final file**: plain or encoded payload, manifests,
inventories, checksum receipts, bootstrap files, PAR2 indexes, and volumes.
The group ceiling includes data, local metadata, and **all PAR2 overhead**.
Central metadata recovery sets obey the same two ceilings. The two catalog-root
copies form a separate small bootstrap set and are checked together.

The implementation reserves compression expansion, measured CMS wrapper space,
PAR2 packet headers and repeated critical packets, and metadata before admitting
input. Disabled features reserve no transform or PAR2 overhead. It checks actual output lengths before publishing. Limits are ceilings,
not targets: groups may close early, and compressed files need not have equal
sizes. Impossible combinations of limits fail explicitly rather than producing
an oversized completed archive.

The derived input chunk ceiling allows for incompressible zstd output and the
recipient's CMS wrapper. It also leaves room for a small group by limiting the
stored chunk allowance to at most one quarter of the group budget. No padding or
alignment is added between compression frames, CMS, and PAR2 slices.

The large-file threshold is a routing policy, not a chunk-size limit. It can be
set lower than the derived safe ceiling; higher values are capped at that ceiling.
Lowering it does not shrink RAW chunks. TAR admission additionally reserves the
actual TAR/PAX headers, member padding, end markers and final record padding.

## 4. Source traversal and TAR collection

Visit directories recursively, listing and optionally alphabetizing only the
current directory. There is no full-source pre-scan, global size sort, or second
whole-tree validation pass. Supported inputs are directories, regular files,
and symbolic links, using `lstat` without following links. Reject special files.

Keep the active directory lists, current TAR inventory and bounded open-group
inventories in memory, not the entire source tree or payload bytes. Write group
catalogs as groups close. Observable source
changes abort backup; ordinary stat checks are not a snapshot guarantee.

Files at least as large as the effective large-file threshold go directly to
the RAW handler. Smaller files are TAR candidates, not guaranteed to fit. Try the first fitting
candidate in the current directory, looking through its whole remaining list
when useful. Do not read file contents to estimate compression. Account for PAX
headers, 512-byte member padding, end records, metadata, encryption, and parity.

**Do not close a pending TAR at a directory boundary.** Continue collecting from
the next directory. Close when capacity requires it or traversal finishes. No
search into future directories just to fill a gap, no optimal packing, and no
reopening completed TARs. The two handlers are logical paths, not concurrent
workers.

A TAR must have at least two regular files. A singleton takes the direct-file
path before TAR bytes are written; directories and symlinks do not count as its
companion. Empty files, directories, symlinks, and the root `.` are retained.
Metadata-only entries may accompany data or form their own group; they need no
artificial TAR or data chunk.

Never split an original large file into custom TAR members. TARs remain ordinary
TARs; direct streams remain the original file bytes.

## 5. Chunks and transforms

With compression enabled, each chunk is an independent zstd frame, level 3,
`--single-thread --check`, no dictionary or embedded source name. Otherwise its
encoded input is unchanged TAR or RAW bytes. I/O uses bounded buffers. Encryption
wraps the resulting bytes in binary CMS AuthEnvelopedData, DER encoding.
Names are **`.tar[.zst][.cms]`** or **`.raw[.zst][.cms]`**; the optional suffixes
record the enabled transforms, in that order. Source inventories use
`.jsonl[.zst][.cms]`. A plain `.tar` is directly readable by tar; `.raw` holds
original file bytes.

Each TAR chunk is a complete ordinary archive, never a slice of a larger TAR.
No original member crosses a TAR-chunk boundary. Its filename omits `offset`;
`length` includes the entire uncompressed TAR, including headers and padding.
RAW chunk names include both the original file offset and the chunk length.
The filename length is counted from bytes actually written. TAR records are
10,240 bytes here: member padding and final record rounding can make well-filled
TARs exactly the same length. Directory-local lookahead often reaches the same
record-aligned input ceiling; no extra padding fills unused chunk capacity.

Use AES-256-GCM, an RSA recipient key of at least 3072 bits, RSA-OAEP/SHA-256 and
MGF1-SHA-256. OpenSSL generates content keys/nonces. Reject weak or unsuitable
recipient keys before reading file contents. Normalize the public certificate;
never copy a private-key PEM block into the archive.

Encrypt source-path inventories as well as payload. Public manifests contain
only technical IDs, coordinates, sizes, algorithms, and checksums of stored
files. They enable verification/PAR2 repair without a private key. Source
metadata is optionally compressed first, encrypted once, and **that exact ciphertext** is
copied to the central metadata directory.

Private keys remain external. Decrypt in owner-only scratch, authenticate before
decompression, and remove output on authentication failure. Backup staging is
`0700`; staged plaintext and decryption output are `0600`. Cleanup is not
secure erasure. Production limitations remain in section 13.

## 6. Group sizing and parity

Placement uses **actual stored chunk sizes**, with conservative
metadata/PAR2 reservations. A whole RAW file, however many chunks it contains,
stays in one group whenever it fits an empty group. It is never split across
groups merely because the current group already contains other data.

The queue has **one active group and at most four waiting groups** by default:

1. Try each waiting group, oldest first, then the active group. Add a complete
   RAW file or complete TAR only if the whole unit fits.
2. When a unit does not fit a group, close that group if its budget is at least
   **95%** of the group limit. A smaller group may remain waiting.
3. If a new group would exceed the waiting limit, close the fullest candidate;
   equal budgets close the oldest. There is no age counter or timeout.
4. If a RAW file exceeds an empty group's budget, start it in a fresh group.
   Close intermediate groups as they fill. Its last group stays active and may
   accept subsequent whole RAW files/TARs under the same queue rules.
5. Close every remaining group at the end of backup. Closed groups are never
   reopened, moved between groups, or given regenerated parity just to improve fill.

`--waiting-groups` accepts zero or more. `--group-close-percent` accepts 1–100;
100 avoids early percentage-based closure. The percentage is **not a fill cap**:
an already 95%-full group still accepts a whole unit that fits. Fill is measured
using stored payload plus reserved metadata and PAR2, not plaintext input size.
No artificial zero padding is written to fill chunks or groups.

While deciding placement, completed chunks of the current RAW file wait in
private staging until EOF or until they exceed one empty group's budget. At
most one group-sized candidate plus one crossing chunk needs buffering; payload
stays on disk. The file is read/compressed/encrypted once, and buffered chunks
are renamed into their selected shard, not copied or recompressed. After a file
is known to span groups, subsequent chunks are placed as they finish.

Waiting groups retain their already stored data and bounded inventories; their
final metadata and PAR2 are produced only on closure. More waiting groups trade
additional metadata memory and delayed protection for potentially better fill.
Group closure order need not follow input order: IDs and RAW offsets determine
reconstruction, and the central checksum chain follows closure order.

TAR collection uses a conservative plaintext bound so each complete TAR fits
one file; it does not try to fill a compressed chunk to its byte ceiling.
Metadata reservations and PAR2 limits may still close groups early. No arbitrary
chunk-count or filename-width limit is used. PAR2's own 32768 source/recovery-block limits
also constrain admission when PAR2 is enabled; slice sizes are positive multiples of four.

With PAR2 disabled, groups retain both metadata copies and all checksums, but
contain no PAR2 files and have no parity reservation or PAR2 block-capacity limit.
Checksum receipts carry empty group-hash maps. Missing/corrupt payloads cannot
be reconstructed; repair may still recover an intentional metadata duplicate
from its healthy counterpart and never invents parity for a non-PAR2 archive.

With PAR2 enabled, protect **stored** chunks and transformed metadata together.
For protected member lengths `lengths` and slice size `s`:

```text
recovery_blocks = max(
    ceil(sum(lengths) / (5 * s)),
    ceil(5 * max(lengths) / (4 * s)),
    ceil(max(lengths) / s) + 1
)
```

This gives a normal 20% recovery target, at least 125% of the largest stored
member, and an extra slice after rounding. Short/final groups may significantly
exceed 20%; calculate from **actual protected bytes**, never the nominal maximum
group capacity. Do not pad with fake data or rebalance completed groups.

Use one PAR2 index and enough uniform recovery volumes to fit the file ceiling;
neither four volumes nor a particular volume byte size is required. Budget
recovery packet headers and repeated critical packets as well as parity payload.
The calculation follows [par2cmdline's packet allocation](https://github.com/Parchive/par2cmdline/blob/master/src/par2creator.cpp).
Generate PAR2 directly from named stored inputs, without staging copies or links,
and verify generated parity before publication.

Recovery capacity is **per set**, not archive-wide. A missing file costs all its
slices; damage across many slices can cost more capacity than its byte percentage
suggests. Lost recovery volumes remove capacity too. Required critical PAR2
metadata must also survive. An index can be replaced by a surviving volume.

## 7. Metadata order, copies, and completeness

For each group:

1. Finish independent stored chunks.
2. Write the group's streams/source inventory; compress and/or encrypt as requested.
3. Write the public group manifest, optionally compressing it, referencing stored inventory and
   chunk SHA-256 values. It carries settings and plaintext chunk checksums.
4. When enabled, generate group PAR2 over **chunks + stored inventory + stored manifest**.
5. Make byte-identical inventory/manifest copies under `metadata/`, adding
   `-spare` before `.json`/`.jsonl` in their filenames.
6. Write a central checksum receipt (compressed when enabled) covering these
   copies and any finished group PAR2 files; add central PAR2 when enabled.

The local manifest never hashes PAR2 generated from itself. Each central receipt
also records the previous central receipt's stored SHA-256 and PAR2 hashes. The
last link, group count, and settings go into two identical self-checksummed
**catalog-root markers**, one primary and one `-spare`, published last. These are
small checksum-chain roots, not copies of the complete catalog. This bounded chain avoids one unbounded archive-wide
checksum list or marker. Each central recovery set is independently bounded.

The first central set additionally protects a small uncompressed format note and
normalized public recipient certificate when encrypted. These and catalog-root
markers are the explicit uncompressed roles. Inventories, manifests, and receipts
use zstd when compression is enabled, regardless of size or compression ratio;
otherwise they remain JSON/JSONL, with CMS wrapping source inventories if encrypted.

The inventory's first JSONL record is `{"streams": [...]}`, describing all streams
in the group. Subsequent records are `{"stream": "<id>", "entry": {...}}`, linking
original filesystem entries and required ancestors to their stream. For TARs these
are the TAR members. For RAW streams they identify the original file and its
ancestors. Metadata-only entries use a null stream ID. Repeated ancestor descriptions
must agree. Direct-stream groups carry the full source size from the start;
whole-file hashes become available in the final group. Earlier groups still
have independent plaintext/stored chunk hashes.

Record CRC32 (ZIP-compatible), MD5, SHA-1, SHA-256, and SHA-512 while reading
source files. SHA-256/SHA-512 are authoritative integrity checks; older digests
are lookup aids. Every stored chunk has a separate SHA-256. Receipts and marker
links cover metadata and PAR2 without circular hashing. Cloud checksum semantics
and fixed upload-block digests remain deferred in section 12.

## 8. Naming and layout

See [FORMAT.md](poc/FORMAT.md) for the complete filename table.

```text
ARCHIVE/
  <gid[:2]>/
    archive-<aid>_group-<gid>_chunk-...tar[.zst][.cms]
    archive-<aid>_group-<gid>_chunk-...raw[.zst][.cms]
    archive-<aid>_group-<gid>_metadata_index-chunks.json[.zst]
    archive-<aid>_group-<gid>_metadata_index-files.jsonl[.zst][.cms]
    archive-<aid>_group-<gid>.par2
    archive-<aid>_group-<gid>.vol...par2
  metadata/
    <gid[:2]>/
      archive-<aid>_group-<gid>_metadata_index-chunks-spare.json[.zst]
      archive-<aid>_group-<gid>_metadata_index-files-spare.jsonl[.zst][.cms]
      archive-<aid>_metadata_group-<gid>_checksums.json[.zst]
      archive-<aid>_metadata_group-<gid>.par2
      archive-<aid>_metadata_group-<gid>.vol...par2
    archive-<aid>_metadata_catalog-root.json
    archive-<aid>_metadata_catalog-root-spare.json
```

Only populated shard directories are created. Many groups can share a shard.
PAR2 files in this layout exist only when enabled. Group IDs and the `group-`
name component remain in use without PAR2. PAR2 stores basenames relative to its shard. Chunk numbers are local to a group,
zero-padded to **at least** four digits, without a four-digit maximum. Offsets
and lengths are plaintext byte coordinates, not compressed/encrypted coordinates.
Only RAW filenames have offsets; both formats have lengths.

Readers discover files recursively in flat, nested, or mixed layouts. Group indexes
have distinct primary and `-spare` basenames with identical bytes. Use recorded
checksums to select good bytes and report missing/damaged redundancy. Every
basename is unique, so the entire archive can be flattened without collisions.
Duplicate basenames are rejected. Local PAR2 protects primary names; central
PAR2 protects spare names, and recovery maps copies to the required names. Archive-file mtimes and enumeration order have no recovery significance.

## 9. Verify, repair, and restore

- `verify` checks stored checksums and PAR2 capacity, without needing a key.
  Any damage, including metadata copies or parity only, returns 1. It can repair
  metadata in scratch to complete its diagnosis, never changing the archive.
- `repair` changes stored inputs **in place**. No staging copies/hardlinks of
  data or parity. Scattered inputs are gathered with same-filesystem renames.
  Replacing a missing/damaged intentional metadata duplicate can copy its healthy
  counterpart. Regenerate missing PAR2 from intact inputs only for PAR2-enabled archives. Completed changes
  remain if a later set fails.
- `restore` uses read-only hardlinks for healthy inputs and ordinary copies for
  damaged/unknown inputs before scratch PAR2 repair; no CoW. Failed/cross-device
  hardlinks fall back to ordinary copies. Archives are never modified.

A valid catalog-root marker anchors the full catalog. Either marker copy suffices;
conflicting valid copies are rejected. A surviving local group can also be
restored without the central directory/markers. Report that original backup
completeness cannot be proved, and return 1 for that partial-catalog mode.
Streams with detected gaps are skipped entirely; never fabricate holes or
publish a fragment as a complete file. If a group cannot be fully repaired, restore
still checks its surviving chunks against stored hashes and restores complete
healthy streams. A lost TAR does not prevent restoring its healthy siblings.
Skipped streams produce exit 1; a partial RAW file is never published.

Normal restore checks stored bytes, CMS authentication, zstd integrity, plaintext
chunk lengths/hashes, whole-stream hashes when available, and TAR member hashes.
Validate relative paths, types, symlink targets, duplicates, and ancestors before
creating outputs. Reject traversal and TAR hardlinks/special entries. Create
symlinks after regular files; restore directory metadata deepest-first, root last.

Source/target overlap, symlink destinations, nonempty targets, and invalid source
roots are rejected. Preserve POSIX modes and nanosecond mtimes where supported;
report platform precision/representation limits. Ownership, ACLs, xattrs, source
hard-link relationships, alternate streams, and snapshots are not preserved.
Compare checks paths, types, file SHA-256, sizes, symlinks, POSIX modes and mtimes.

## 10. Filename-only scan

`scan` reads names and file types only, never archive contents, checksums, or PAR2
packets. It writes a separate `.json` or `.json.zst` index of surviving chunk/group-PAR2 names.
Restore with `--scan-index` uses those coordinates and available PAR2, checks
CMS/zstd/declared lengths, and skips streams with detected gaps or bad chunks.

Without source metadata, RAW streams use `stream-<id>.raw`. Filename-declared
TARs are kept as `stream-<id>.tar` and also extracted under `stream-<id>/`.
RAW contents are never guessed to be TARs, even if the original file was a TAR.
Missing RAW tails or whole streams cannot always be detected. Exit 0 in filename-only
mode means no detected failure, not proof of original backup completeness.

## 11. CLI, progress, tests, and demo

See the single [CLI reference](poc/README.md). Exit codes are 0 for success,
1 for integrity/comparison failure or unproven partial-catalog restore, and 2 for
usage/operational failure. Major stages print immediately; an activity heartbeat
appears every five seconds, including while external tools run. It is not a delay
between files or a fabricated completion percentage. Routine status omits
source/member names and combines TAR entry/byte counters in one message. Errors,
warnings, and comparison differences retain actionable filenames.

Tests use small explicit settings and real zstd/OpenSSL/PAR2. All eight feature
combinations are covered, including dependency-free operation when all are disabled. They cover hard
limits, singleton fallback, cross-directory TARs, independent groups, ciphertext
metadata copies, catalog loss, corruption/repair, read-only restore, unsafe paths,
and recovery with ordinary tools. No demo generation is needed to run the core
regression fixtures.

The separate demo generates office-like documents, SQL-like backups, and highly
compressible logs. Its damager uses a percentage of actual stored bytes, randomly
choosing files, ranges, and bit flips/zero/copy/insertion/deletion faults. It does
not validate archive formats or require pristine inputs. See [demo options](poc/demo/README.md).

---

## 12. Mandatory checksum requirements for a real implementation

The PoC deliberately does not implement cloud-native checksum variants,
provider encodings/composition, or upload-block digests. These are mandatory for
any real implementation:

1. **Source lookup checksums.** CRC32, MD5, SHA-1, SHA-256 and SHA-512 are already
   recorded for regular source files. Older hashes are lookup aids, not security
   primitives; CRC32 matches ZIP. Maintain this uniform coverage in production.
2. **Stored-object checksums.** Checksum the exact bytes written after compression
   and encryption, separately from plaintext. Retain modern authoritative hashes
   and the additional algorithms and encodings needed to compare directly with
   S3/Azure checksums. Cover every stored object, not only payload chunks. Define
   a non-circular integrity/bootstrap design for checksum metadata itself.
3. **Fixed upload blocks.** Use **8 MiB upload-checksum blocks**, independently of
   variable-sized stored chunks and 1 MiB PAR2 slices. Record each block's
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

## 13. Cryptographic limitations and production requirements

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
3. **Archive authenticity and context binding.** Metadata and catalog-root markers
   are unsigned. SHA-256 and PAR2 detect/repair accidental damage, not malicious
   replacement. Chunk GCM tags do not authenticate the backup's author or bind
   external archive IDs, stream IDs, offsets, and catalogs. Anyone with the public
   certificate can construct a replacement encrypted archive. Production needs a
   trusted authenticated manifest/signature covering those relationships and an
   explicit rollback policy.
4. **Metadata confidentiality policy.** Source paths and inventories are encrypted
   when payload is encrypted. Technical IDs, sizes, layout, stored checksums,
   and group relationships remain public. Production must assess this remaining
   information leakage against its threat model.
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
