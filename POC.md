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
it). Compression controls payload and metadata; PAR2 controls datagroup, supergroup, central metadata, and catalog-root
protection. `--no-supergroup-par2` disables only the outer layer. Readers discover modes from filenames and validated metadata.
Only enabled features require their external executables.

Implementation is under `poc/`; generated data and scratch use ignored
`poc/work/`. Keep code straightforward and human-readable.

## 2. Terminology and identifiers

| Term | Meaning |
| --- | --- |
| Archive | A complete backup, identified by an archive ID |
| Stream | Plaintext bytes of one original file or one ordinary POSIX/PAX TAR |
| Chunk | One complete TAR or a range of RAW file bytes, optionally compressed and/or encrypted |
| Datagroup | Whole streams, or a spanning RAW file's range optionally followed by whole streams, plus metadata and optional PAR2 |
| Supergroup | A bounded set of datagroups, with separate cross-datagroup PAR2 when enabled |
| Datagroup parity | PAR2 over one datagroup's stored chunks and primary metadata |
| Supergroup parity | PAR2 over several datagroups' stored data and metadata, excluding every datagroup/central PAR2 file |
| Central metadata set | Identical metadata copies and their checksum receipt, optionally protected by separate PAR2 |

Archive, supergroup, datagroup, and stream IDs are random 96-bit identifiers, not
content hashes. Each is 20 lowercase base32 characters (`a-z`, `2-7`, without padding). Central metadata PAR2
**reuses its datagroup's ID**; no extra random metadata or shard IDs are generated.

A TAR is exactly one chunk. Several complete TARs and whole RAW files may share
one datagroup, including RAW files made of several chunks. A RAW file that cannot
fit an empty datagroup starts fresh and spans as many datagroups as needed. Its final
datagroup can accept subsequent whole files/TARs. A datagroup describing a fragment is independently
interpretable and repairable, but cannot reproduce absent fragments.

## 3. Hard byte limits

| Setting / backup option | Default |
| --- | ---: |
| `max_file_bytes` / `--max-file-bytes` | 268435455 (256 MiB − 1 byte) |
| `max_datagroup_bytes` / `--max-datagroup-bytes` | 15032385536 (14 GiB) |
| `large_file_bytes` / `--large-file-bytes` | Automatic: the derived safe input ceiling |
| `waiting_datagroups` / `--waiting-datagroups` | 4, in addition to one active datagroup |
| `datagroup_close_percent` / `--datagroup-close-percent` | 95, applied when the next whole unit does not fit |
| `supergroup_datagroups` / `--supergroup-datagroups` | 5 |
| `supergroup_margin_percent` / `--supergroup-margin-percent` | 110 |
| `supergroup_par2` / `--[no-]supergroup-par2` | Enabled when PAR2 is enabled |
| PAR2 slice size (all sets, automatic) | Smallest feasible power-of-two size, starting at 4096 bytes |

These are exact byte counts. The program does not interpret media marketing
capacities, estimate formatting overhead, or subtract filesystem space. For a
FAT32 file ceiling, specify **4294967295** bytes. The user supplies a suitable
usable datagroup capacity for the destination medium.

The file ceiling applies to **every final file**: plain or encoded payload, manifests,
inventories, checksum receipts, bootstrap files, PAR2 indexes, and volumes.
The datagroup ceiling includes data, local metadata, and **all PAR2 overhead**.
Central metadata recovery sets obey the same two ceilings. The two catalog-root
copies, format note, optional public certificate and their PAR2 form a separate
small bootstrap set and are checked together.
Supergroup recovery files are packed without padding into numbered parity-media
directories; each directory obeys `max_datagroup_bytes`. Its two index copies are
checked together as another metadata set. Every individual file obeys the file cap.

The implementation reserves compression expansion, measured CMS wrapper space,
PAR2 packet headers and repeated critical packets, and metadata before admitting
input. Disabled features reserve no transform or PAR2 overhead. It checks actual output lengths before publishing. Limits are ceilings,
not targets: datagroups may close early, and compressed files need not have equal
sizes. Impossible combinations of limits fail explicitly rather than producing
an oversized completed archive.

The derived input chunk ceiling allows for incompressible zstd output and the
recipient's CMS wrapper. It also leaves room for a small datagroup by limiting the
stored chunk allowance to at most one quarter of the datagroup budget. No padding or
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

Keep the active directory lists, current TAR inventory and bounded open-datagroup
inventories in memory, not the entire source tree or payload bytes. Write datagroup
catalogs as datagroups close. Observable source
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
Metadata-only entries may accompany data or form their own datagroup; they need no
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

## 6. Datagroup sizing and parity

Placement uses **actual stored chunk sizes**, with conservative
metadata/PAR2 reservations. A whole RAW file, however many chunks it contains,
stays in one datagroup whenever it fits an empty datagroup. It is never split across
datagroups merely because the current datagroup already contains other data.

The queue has **one active datagroup and at most four waiting datagroups** by default:

1. Try each waiting datagroup, oldest first, then the active datagroup. Add a complete
   RAW file or complete TAR only if the whole unit fits.
2. When a unit does not fit a datagroup, close that datagroup if its budget is at least
   **95%** of the datagroup limit. A smaller datagroup may remain waiting.
3. If a new datagroup would exceed the waiting limit, close the fullest candidate;
   equal budgets close the oldest. There is no age counter or timeout.
4. If a RAW file exceeds an empty datagroup's budget, start it in a fresh datagroup.
   Close intermediate datagroups as they fill. Its last datagroup stays active and may
   accept subsequent whole RAW files/TARs under the same queue rules.
5. Close every remaining datagroup at the end of backup. Closed datagroups are never
   reopened, moved between datagroups, or given regenerated parity just to improve fill.

`--waiting-datagroups` accepts zero or more. `--datagroup-close-percent` accepts 1–100;
100 avoids early percentage-based closure. The percentage is **not a fill cap**:
an already 95%-full datagroup still accepts a whole unit that fits. Fill is measured
using stored payload plus reserved metadata and PAR2, not plaintext input size.
No artificial zero padding is written to fill chunks or datagroups.

While deciding placement, completed chunks of the current RAW file wait in
private staging until EOF or until they exceed one empty datagroup's budget. At
most one datagroup-sized candidate plus one crossing chunk needs buffering; payload
stays on disk. The file is read/compressed/encrypted once, and buffered chunks
are renamed into their selected shard, not copied or recompressed. After a file
is known to span datagroups, subsequent chunks are placed as they finish.

Waiting datagroups retain their already stored data and bounded inventories; their
final metadata and PAR2 are produced only on closure. More waiting datagroups trade
additional metadata memory and delayed protection for potentially better fill.
Datagroup closure order need not follow input order: IDs and RAW offsets determine
reconstruction, and the central checksum chain follows closure order.

TAR collection uses a conservative plaintext bound so each complete TAR fits
one file; it does not try to fill a compressed chunk to its byte ceiling.
Metadata reservations and PAR2 limits may still close datagroups early. No arbitrary
chunk-count or filename-width limit is used. PAR2's own 32768 source/recovery-block limits
also constrain admission when PAR2 is enabled; slice sizes are positive multiples of four.

With PAR2 disabled, datagroups retain both metadata copies and all checksums, but
contain no PAR2 files and have no parity reservation or PAR2 block-capacity limit.
Checksum receipts carry empty parity-hash maps. Missing/corrupt payloads cannot
be reconstructed; repair may still recover an intentional metadata duplicate
from its healthy counterpart and never invents parity for a non-PAR2 archive.

With PAR2 enabled, protect **stored** chunks and transformed metadata together.
For protected member lengths `lengths` and the selected slice size `s`:

```text
source_blocks = [ceil(length / s) for length in lengths]
recovery_blocks = max(
    ceil(sum(source_blocks) / 5),
    ceil(5 * max(source_blocks) / 4),
    max(source_blocks) + 1
)
```

This gives at least 20% of source blocks, at least 125% of the largest stored
member's blocks, and at least one more block than that member occupies. Short/final datagroups may significantly
exceed 20%; calculate from the protected files (with conservative metadata-size
reservations), never the nominal maximum datagroup capacity. Do not pad with fake data or rebalance completed datagroups.

Every PAR2 set uses the same dynamic planner, including central and root metadata.
Try 4 KiB, 8 KiB, 16 KiB, and so on; select the smallest size that satisfies the
32768 source-block and recovery-block limits, output-file ceiling, and applicable
recovery-set byte budget. Each file's partial last block counts independently.
No fixed data or metadata slice size is configured. A larger slice trades finer
repair granularity for fewer source blocks; it never lowers the redundancy target.
All slice sizes are multiples of PAR2's required four bytes.

The chosen `par2` record (`slice_size`, `blocks`, `volumes`) lives in the existing
datagroup index, central receipt, supergroup index, or catalog root. It is `null`
when that set is disabled. Metadata reserves space for its own plan before
serialization/compression; the resulting conservative geometry is kept for exact
PAR2 regeneration, rather than recalculated from smaller compressed metadata.

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

### Supergroup protection and bounded work

A supergroup contains at most `supergroup_datagroups` datagroups (default 5). All active
and waiting datagroups belong to that same supergroup. Before creating a datagroup beyond
that limit, close every waiting/active datagroup and finish the supergroup. No tails
are collected across supergroup boundaries. No padding is added.

Finish each datagroup's primary metadata, datagroup PAR2, and central metadata set first.
Then finish the supergroup's public `index-datagroups` and generate its PAR2 directly
from the stored inputs, without input copies or hardlinks. Protected inputs are
chunks, both datagroup-index copies and central checksum receipts, plus the
supergroup index. The archive-wide format note and public certificate belong to
the separate root bootstrap set. **No datagroup or central `.par2`
file is protected by supergroup PAR2.** They can be regenerated from repaired inputs.
The supergroup index gets an identical `-spare` copy under central `metadata/`.
It contains generated archive names, hashes, sizes and datagroup membership, not source
paths; encrypted source inventories stay encrypted throughout parity processing.

For the outer slice size, sum `ceil(stored_file_bytes / slice_size)` separately
for every protected file in each datagroup. Recovery blocks are the maximum of:

- 20% of total source blocks (including the reserved supergroup-index size);
- `supergroup_margin_percent` (default 110%) of the largest datagroup's block count;
- one block more than that largest datagroup.

Round upward and use the same dynamic planner as every other set. Each outer
PAR2 index/volume must fit both the file ceiling and a single parity medium.
All metadata/packet overhead and file/media limits still apply.
The final short supergroup uses only its actual members, never the maximum datagroup
capacity. A one-datagroup tail consequently has roughly another full data copy's worth
of outer parity, not five datagroups' worth. Before admitting content, reserve the outer index and PAR2 geometry for **all**
finished, active and waiting datagroups. If no feasible geometry fits, close the
current datagroup or supergroup early and retry in an empty one. Thus PAR2 and
index limits can reduce the effective capacity below either configured maximum.
No tails cross that boundary. Content that cannot fit even an empty recovery
window fails explicitly; limits and redundancy are never silently relaxed.

Indexes form their own backward SHA-256 chain, including the preceding set's
PAR2 hashes. The catalog-root stores both chains' last links and counts. Missing
supergroup-index copies can be reconstructed from standard PAR2 file-description
packets and par2cmdline; no custom erasure coding is implemented.

Recovery first fixes locally recoverable datagroups, then charges remaining damage
against their supergroup. The layers' recovery-block counts are **not additive**.
Supergroup failure does not discard unrelated intact datagroups or complete streams.
Verify reports redundancy loss even if all payloads remain usable. Explicit repair
regenerates datagroup, central, supergroup and root PAR2 from verified inputs as needed.

Backup's outer protection window and a recovery workspace are bounded by one
supergroup. Already published local output remains the archive, not a staging copy.
Restore retains only the selected datagroup's repaired payload when leaving an outer
workspace; metadata can stay cached. Cloud upload/eviction is not implemented.
The current RAW restore still assembles an entire original stream in scratch;
filename-only restore also retains decoded streams. Streaming destination writes
and bounded catalog pagination remain necessary before production-scale restores.

## 7. Metadata order, copies, and completeness

For each datagroup:

1. Finish independent stored chunks.
2. Write the datagroup's streams/source inventory; compress and/or encrypt as requested.
3. Write the public datagroup manifest, optionally compressing it, referencing stored inventory and
   chunk SHA-256 values. It carries settings and plaintext chunk checksums.
4. When enabled, generate datagroup PAR2 over **chunks + stored inventory + stored manifest**.
5. Make byte-identical inventory/manifest copies under `metadata/`, adding
   `-spare` before `.json`/`.jsonl` in their filenames.
6. Write a central checksum receipt (compressed when enabled) covering these
   copies and any finished datagroup PAR2 files; add central PAR2 when enabled.

The local manifest never hashes PAR2 generated from itself. Each central receipt
also records the previous central receipt's stored SHA-256 and PAR2 hashes. The
last link, datagroup count, and settings go into two identical self-checksummed
**catalog-root markers**, one primary and one `-spare`, published last. These are
small checksum-chain roots, not copies of the complete catalog. This bounded chain avoids one unbounded archive-wide
checksum list or marker. Each central recovery set is independently bounded.
The two catalog-root copies, a small format note and the normalized public
recipient certificate (when encrypted) live at the archive root. They share one
bootstrap PAR2 set using the shared **dynamic slice planner**, sized for every protected input's
rounded block count plus one extra block. All bootstrap inputs may therefore be
lost together while sufficient parity survives. Bootstrap PAR2 is generated
before publishing the roots; PAR2 needs no readable root/settings to recover them.
The root's `bootstrap_files` map records the auxiliary files' stored sizes and
SHA-256 values. Neither the private key nor original source paths occur here.

Catalog roots, format text and the PEM certificate are the explicit uncompressed
metadata roles. Inventories, manifests, supergroup indexes and receipts use zstd
when compression is enabled, regardless of size or compression ratio. Otherwise
they remain JSON/JSONL. CMS wraps source-name inventories when encryption is enabled.

The inventory's first JSONL record is `{"streams": [...]}`, describing all streams
in the datagroup. Subsequent records are `{"stream": "<id>", "entry": {...}}`, linking
original filesystem entries and required ancestors to their stream. For TARs these
are the TAR members. For RAW streams they identify the original file and its
ancestors. Metadata-only entries use a null stream ID. Repeated ancestor descriptions
must agree. Direct-stream datagroups carry the full source size from the start;
whole-file hashes become available in the final datagroup. Earlier datagroups still
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
  archive-<aid>_metadata_catalog-root.json
  archive-<aid>_metadata_catalog-root-spare.json
  archive-<aid>_metadata_catalog-root*.par2
  archive-<aid>_metadata_format.txt
  archive-<aid>_metadata_recipient.pem                 # when encrypted
  data/<sgid[:2]>/<sgid>/
    <gid>/                                           # one complete datagroup
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>_chunk-...tar[.zst][.cms]
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>_chunk-...raw[.zst][.cms]
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>_metadata_index-chunks.json[.zst]
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>_metadata_index-files.jsonl[.zst][.cms]
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>*.par2
    metadata/
      archive-<aid>_supergroup-<sgid>_metadata_index-datagroups.json[.zst]
    parity/<media-number>/
      archive-<aid>_supergroup-<sgid>*.par2
  metadata/<sgid[:2]>/<sgid>/
    archive-<aid>_supergroup-<sgid>_metadata_index-datagroups-spare.json[.zst]
    <gid>/
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>_metadata_index-*-spare.json*[.zst][.cms]
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>_metadata_checksums.json[.zst]
      archive-<aid>_supergroup-<sgid>_datagroup-<gid>_metadata*.par2
```

Only populated directories are created. Shards reuse the first two characters
of the supergroup ID in both trees; every datagroup has its own full-ID directory.
The two trees are collections, not single media units. Each datagroup directory,
each central metadata set, the root bootstrap set, each numbered parity-media
directory and the supergroup index pair obey their respective complete byte
budgets, including every metadata/PAR2 byte. No metadata file is exempt from the
individual file limit. Oversized indivisible metadata fails explicitly before
publication; it is not silently allowed to exceed a cap.

Names always order identities first: archive, supergroup, datagroup (when present),
then role. `metadata` therefore always follows the complete identity prefix.
PAR2 files exist only when enabled. IDs and directories remain without PAR2.
Datagroup/central PAR2 stores local basenames; supergroup PAR2 stores canonical
paths relative to ARCHIVE. Chunk numbers restart per datagroup and are padded to
at least four digits, without a four-digit maximum. Only RAW filenames carry
offsets; both RAW and TAR names record plaintext lengths.

Discovery accepts flat, nested and mixed layouts, including names/directories
whose ASCII letter case changed during transport. Generated names remain
lowercase. Two archive basenames differing only by case are rejected as ambiguous;
source filenames inside inventories/TARs keep their exact original case.
Verify/restore never rename inputs; explicit repair normalizes recovered paths.
Primary/spare indexes have distinct basenames and identical bytes, so flattening
needs no renaming. Recorded checksums select healthy copies.

Generated components are at most 255 ASCII bytes and archive-relative paths at
most 256 characters. The latter is a portability policy, not a FAT32/ext3 limit:
adding `X:\` and the terminating NUL fits conventional Windows MAX_PATH=260 when
archive contents are copied to a volume root. Arbitrarily deep external prefixes
are outside this guarantee. Archive-file mtimes and discovery order do not matter.

## 9. Verify, repair, and restore

- `verify` checks stored checksums and PAR2 capacity, without needing a key.
  Any damage, including metadata copies or parity only, returns 1. It can repair
  metadata in scratch to complete its diagnosis, never changing the archive.
- `repair` changes stored inputs **in place**. No staging copies/hardlinks of
  data or parity. Scattered inputs are gathered with same-filesystem renames.
  Supergroup volumes on separate parity media are temporarily gathered by rename
  beside their index for par2cmdline, then returned to their media directories.
  Replacing a missing/damaged intentional metadata duplicate can copy its healthy
  counterpart. Regenerate missing PAR2 from intact inputs only for PAR2-enabled archives. Completed changes
  remain if a later set fails.
- `restore` uses read-only hardlinks for healthy inputs and ordinary copies for
  damaged/unknown inputs before scratch PAR2 repair; no CoW. Failed/cross-device
  hardlinks fall back to ordinary copies. Archives are never modified.

A valid catalog-root marker anchors the full catalog. Either marker copy suffices;
if both are damaged/missing, bootstrap PAR2 restores them before reading settings.
Even with bootstrap PAR2,
conflicting valid copies are rejected. A surviving local datagroup can also be
restored without the central directory/markers. Report that original backup
completeness cannot be proved, and return 1 for that partial-catalog mode.
Streams with detected gaps are skipped entirely; never fabricate holes or
publish a fragment as a complete file. If a datagroup cannot be fully repaired, restore
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
packets. It writes a separate `.json` or `.json.zst` index of surviving chunk/datagroup-PAR2 names.
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
limits, singleton fallback, cross-directory TARs, independent datagroups, ciphertext
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
   variable-sized stored chunks and independently sized PAR2 slices. Record each block's
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
   and datagroup relationships remain public. Production must assess this remaining
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
