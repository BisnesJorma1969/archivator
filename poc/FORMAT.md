# Archive format and manual recovery

The [specification](../POC.md) describes the implementation. Installation and demo
commands live only in the [root README](../README.md).

## Names and layout

`aid`, `sgid`, `gid`, and `sid` are archive, supergroup, datagroup, and stream IDs:
independent random 96-bit values expressed as 20 lowercase base32 characters (`a-z`, `2-7`, no `=` padding). They are
identifiers, not hashes. Central metadata protection reuses its datagroup's ID.

A **datagroup** is one bounded media unit of chunks, metadata and datagroup PAR2. A
**supergroup** contains up to five datagroups by default, with its own separate PAR2
protecting their data and metadata but not their datagroup/central PAR2 files.

A **stream** is either an ordinary POSIX/PAX TAR or one original file's raw bytes.
One TAR is one complete chunk. Multiple whole TARs and whole RAW files can share
a datagroup, including RAW files with several chunks. A RAW file spans datagroups only
when it cannot fit an empty one; it starts in a fresh datagroup. Intermediate datagroups
contain only that file, while its final datagroup can accept subsequent whole streams.
A TAR contains at least two regular files; a singleton is RAW.
Directories/symlinks alone need only inventory records, not payload chunks.

A datagroup lives under `ARCHIVE/data/<sgid[:2]>/<sgid>/<gid>/`: copying or
removing that directory selects exactly one data-media unit. Byte-identical
`-spare` indexes and their central PAR2 set live under
`ARCHIVE/metadata/<sgid[:2]>/<sgid>/<gid>/`.
The supergroup index is in `data/<sgid[:2]>/<sgid>/metadata/`, its spare in
`metadata/<sgid[:2]>/<sgid>/`, and outer PAR2 in
`data/<sgid[:2]>/<sgid>/parity/<media-number>/`.
Catalog-root copies, format text, optional public certificate and their shared
bootstrap PAR2 are directly under `ARCHIVE/`. Only populated directories are
created. IDs and data/metadata directories remain when PAR2 is disabled.
All identity fields precede the role: archive, supergroup, datagroup, then metadata
or chunk details. There is no different identity order for metadata parity.

For compactness in this table, `G` means
`archive-<aid>_supergroup-<sgid>_datagroup-<gid>`, `M` means
`G_metadata`, and `S` means
`archive-<aid>_supergroup-<sgid>`.

| Filename | Role |
| --- | --- |
| `G_chunk-<n>_stream-<sid>_length-<length>.tar[.zst][.cms]` | One complete TAR |
| `G_chunk-<n>_stream-<sid>_offset-<offset>_length-<length>.raw[.zst][.cms]` | Whole original file bytes or one fragment |
| `G_metadata_index-chunks.json[.zst]` | Public chunk coordinates, settings, stored/plaintext hashes |
| `G_metadata_index-files.jsonl[.zst][.cms]` | Private source names/attributes for RAW and TAR |
| `G_metadata_index-chunks-spare.json[.zst]` | Identical central chunk-index copy |
| `G_metadata_index-files-spare.jsonl[.zst][.cms]` | Identical central source-index copy |
| `G.par2`, `G.vol<start>+<count>.par2` | Datagroup PAR2 over chunks and primary metadata |
| `M_checksums.json[.zst]` | Central receipt, datagroup-PAR2 hashes and preceding central link |
| `M.par2`, `M.vol<start>+<count>.par2` | PAR2 over central metadata copies and receipt |
| `archive-<aid>_metadata_format.txt`, `archive-<aid>_metadata_recipient.pem` | Uncompressed root-level format note and optional public certificate; bootstrap-PAR2 protected |
| `S_metadata_index-datagroups.json[.zst]` | Protected supergroup members, sizes, hashes, PAR2 parameters and preceding supergroup link |
| `S_metadata_index-datagroups-spare.json[.zst]` | Identical central supergroup-index copy |
| `S.par2`, `S.vol<start>+<count>.par2` | Cross-datagroup PAR2, including the primary supergroup index |
| `archive-<aid>_metadata_catalog-root.json`, `..._metadata_catalog-root-spare.json` | Identical uncompressed checksum roots |
| `archive-<aid>_metadata_catalog-root.par2`, `..._metadata_catalog-root.vol<start>+<count>.par2` | Independent protection for both roots, format note and optional certificate; all input blocks plus one dynamically sized slice |

**Inventories are metadata, not compressed file content.** Stream IDs inside
the inventory match the payload chunk names. TAR entries list members; RAW entries
identify the original file and ancestors. Every data
datagroup has its own manifest and inventory, including datagroups carrying different
pieces of one large direct stream. The `stream` term is used consistently for
both types.

`index-chunks` is the public technical index of stored chunks. `index-files`
describes original paths and attributes for both RAW files and TAR members, so
it is encrypted whenever the payload is encrypted. These are datagroup-level roles,
not separate indexes for RAW and TAR content.

Generated names contain lowercase ASCII letters, digits, `_`, `-`, `.`, and
PAR2's `+`. Chunk numbers restart at zero per datagroup and are padded to at least
four decimal digits, with no four-digit maximum. Offsets use twenty digits and
lengths twelve; both refer to **uncompressed plaintext**, never ciphertext.
Offsets occur only in RAW names. TAR length includes headers, member padding,
end markers and final record padding. Internally its chunk offset is always zero.
Names remain meaningful when copied into a flat directory, including supergroup
membership. Datagroup/central PAR2 records basenames; supergroup PAR2 records canonical
paths relative to ARCHIVE. Recovery reconstructs those paths when needed.
Generated components are at most 255 ASCII bytes; full paths relative to ARCHIVE
are at most 256 characters, including directories. This is our portability policy,
not a filesystem path limit: `X:\` plus the terminating NUL still fits Windows
MAX_PATH=260. External destination prefixes are outside this bound; copying the
contents to a volume root needs no renaming.
See Microsoft's [component limits](https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison#limits)
and [conventional path limit](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation). Discovery is recursive; archive-file mtimes and enumeration order do
not matter. Discovery matches generated names without ASCII case sensitivity;
source names inside TARs/inventories remain case-sensitive. Read-only operations
never rename input files. Explicit repair normalizes the layout. Every stored
file has a unique basename, including the two metadata copies. Flattening the archive therefore needs no collision handling. Duplicate
basenames are rejected, including names differing only by letter case. A spare manifest still references primary filenames;
recovery maps the byte-identical spare to the primary name when needed.

## Contents and dependency order

With compression enabled, each chunk is one zstd level-3 frame with a content
checksum and no dictionary. Otherwise it contains plain TAR/RAW bytes.
Encrypted chunks and inventories wrap either form in binary CMS AuthEnvelopedData,
DER encoding, AES-256-GCM, RSA≥3072, RSA-OAEP/SHA-256 and MGF1-SHA-256.
Encryption appends `.cms`; compression appends `.zst` before it. Decrypt/authenticate
first, then decompress if applicable. Metadata JSON/JSONL follows the same
compression setting; only source-name inventories are encrypted.

The public manifest contains `version`, `archive`, `supergroup`, `datagroup`, `compression`,
`encryption`, `settings`, `par2`, `members`, `source_metadata`, and `source_sha256`.
Each chunk member records `filename`, `chunk`, `stream`, `kind` (`tar` or `raw`), `offset`, `length`,
`stored_length`, `stored_sha256`, `plaintext_sha256`, and `plaintext_sha512`.
It contains no original source names. `compression` is `zstd` or `none`;
`settings.compression` and `settings.par2` are booleans.

The inventory is JSONL: first `{"streams": [...]}`, followed by
`{"stream": "<id>", "entry": {...}}` records. Stream type is `file` or `tar`;
entries outside a byte stream use a null stream ID, and metadata-only datagroups
have an empty streams list. Original entries
include `path`, `type`, `mode`, `mtime_ns`, and, where applicable, `size` or
`symlink_target`. File checksums are CRC32, MD5, SHA-1, SHA-256, SHA-512. TAR hashes
are calculated while writing members. A direct stream's final datagroup records its
whole-file hashes, unknown when earlier datagroups are written. Each datagroup repeats
required ancestor-directory information, including root `.`.

Names are JSON strings, including escaped Unicode, tabs, newlines and filesystem
surrogate escapes. CRC32 matches ZIP. Digests are lowercase hex. SHA-256/SHA-512
are integrity checks; the older digests are lookup aids.

When PAR2 is enabled, local stored metadata is finished **before datagroup PAR2**, so the same recovery set
can recreate a missing manifest/inventory. Make its identical central copies,
then write the central receipt with the finished datagroup-PAR2 hashes. Central PAR2
protects that receipt and the copies. No manifest hashes its own PAR2.

Each receipt includes its own `par2` geometry and links backward to the preceding central receipt's SHA-256 and PAR2
hashes. Catalog-root markers hold the last central and supergroup links, counts,
`settings`, root `par2` geometry, and a `bootstrap_files` map of format/certificate names, sizes and SHA-256 values,
so they do not grow with the archive's datagroup count. `marker_sha256` hashes
canonical ASCII JSON, sorted keys and compact separators, excluding that field.
These files contain the checksum-chain root, not the full catalog. The `-spare`
file is byte-identical to the primary. Markers are published last, after generating their own bootstrap PAR2, and are not signed. Without PAR2,
the copies, receipts, and checksum chain still exist; parity-hash maps are empty.

### Why separate metadata files?

The public chunk index supports verification/repair without a private key. The
JSONL source inventory contains names, attributes and required file checksums,
so it is encrypted with the payload. Its identical spare avoids encrypting the
same inventory twice. The receipt is written after local PAR2 and records its
hashes without a circular dependency. Supergroup indexes and catalog roots
provide separate, bounded recovery entry points. These roles remain ordinary
JSON/JSONL, zstd, CMS, TXT and PEM rather than a custom container.

With both PAR2 levels enabled, each datagroup has five JSON/JSONL files (two
primary indexes, two spares and a receipt), plus two PAR2 sets. At least one index
and one recovery volume per set means **at least nine auxiliary files per
datagroup**. Each supergroup adds two indexes and its PAR2 set (at least four
files). Bootstrap adds two roots, format text, an optional public certificate
and its PAR2 set (at least five files, or six when encrypted). Larger parity sets
need more volumes to respect the file cap. Disabled PAR2 contributes no files.
Very compressible small-file workloads can have larger inventories than compressed
payload: per-source cryptographic checksums do not compress like repetitive logs.

## Sizing and recovery capacity

Defaults are **268435455 bytes per final file** and **15032385536 bytes per datagroup**.
Both include format overhead; a datagroup includes its metadata and PAR2. Central
metadata sets, the entire root bootstrap set, each numbered outer parity-media
directory and the supergroup index pair obey the same caps. Collection directories
(`data/`, `metadata/`, shards and supergroups) can span many media units. Every
final metadata/PAR2 file must fit individually; an oversized indivisible index
fails explicitly, never bypassing the limit. Compression expansion and CMS wrappers are reserved
before selecting plaintext chunk sizes; final sizes are checked before publication.
Complete TAR admission counts TAR/PAX headers and all padding before applying
the zstd/CMS bound. Datagroups accumulate actual stored chunk sizes with conservative
metadata/parity reservations. The optional `--large-file-bytes` routing threshold
can be lower than the safe input ceiling without reducing RAW chunk sizes.

Whole RAW files and whole TARs are placed through one active datagroup and a bounded
queue, defaulting to four waiting datagroups and a 95% close-on-miss threshold.
See the [queue rules](../POC.md#6-datagroup-sizing-and-parity). These are writer policies,
not a required restore order. No artificial chunk/datagroup padding is used.

All PAR2 sets choose their slice size dynamically: try 4 KiB, 8 KiB, 16 KiB,
and so on until source/recovery counts (each at most 32768), file limits, and
applicable media budgets fit. Count each protected file's partial final block
separately. Datagroup and central recovery is the maximum of 20% of source blocks,
125% of the largest member's blocks, and one block more than that member.
Short/final sets may have much more than 20% parity; nominal maximum capacity
never sets the recovery amount. Packet headers and repeated critical metadata
consume space as well.

Supergroup recovery is at least 110% of the largest datagroup's source-block count,
at least 20% of the total, and at least one block beyond the largest datagroup.
Its index and all open/waiting datagroups are included in admission reservations.
If no legal geometry fits, close the datagroup or supergroup early. Configured
capacities/counts are ceilings, not mandatory fill levels. Never lower redundancy
to fit. Recovery files are packed into numbered, byte-bounded media directories.
Bootstrap PAR2 protects every input block plus one, using the same dynamic planner.

Each set's existing technical metadata stores `par2: {slice_size, blocks, volumes}`
(or `null` when disabled). These are the actual generation parameters; retain them
when regenerating parity, even if conservative metadata-size reservations resulted
in extra recovery blocks. No global fixed slice size is stored in `settings`.
See the [complete protection rules](../POC.md#supergroup-protection-and-bounded-work).

There is no globally safe number of deletable files. Each set must retain enough
valid recovery blocks for **all** its damaged/missing source slices; deleting
PAR2 volumes removes capacity. Losing the index is harmless if a usable volume
contains the needed critical metadata.

## Manual recovery with ordinary tools

Work in an empty scratch directory. Replace the uppercase placeholders below
with actual paths and IDs. Do not run manual repair against read-only originals.
The commands below show the compressed, encrypted, PAR2-protected case. Skip PAR2
commands if disabled; checksums alone detect corruption but cannot repair payloads.

### 1. Recover a local datagroup

Copy **all** files for the chosen datagroup: chunks, manifest, inventory, and PAR2.
It does not need the central `metadata/` directory.

```bash
aid=REPLACE_WITH_ARCHIVE_ID
sgid=REPLACE_WITH_SUPERGROUP_ID
gid=REPLACE_WITH_DATAGROUP_ID
archive=/absolute/path/to/archive
scratch=/absolute/path/to/manual-scratch
mkdir -p "$scratch"
cp "$archive/data/${sgid:0:2}/$sgid/$gid"/archive-"$aid"_supergroup-"$sgid"_datagroup-"$gid"* "$scratch/"
cd "$scratch"
base="archive-${aid}_supergroup-${sgid}_datagroup-${gid}"
par2 verify "$base.par2"
par2 repair "$base.par2"
```

If the index is absent, give `par2` a surviving `.vol...par2` instead. Repeat for
other datagroups needed by the desired direct-file stream. A TAR needs only its own
datagroup. Public manifests can be inspected with `zstd -dc "$base"_metadata_index-chunks.json.zst`.
Without compression, read the `.json` manifest directly.
Check stored SHA-256 values before decoding payload.

For central metadata recovery, copy that set's files from `metadata/<sgid[:2]>/<sgid>/<gid>/`
into scratch and run the same PAR2 commands against its `archive-<aid>_supergroup-<sgid>_datagroup-<gid>_metadata` prefix. Its protected receipt identifies the previous central set. Either valid
catalog-root marker supplies the final checksum root.

### Whole-datagroup or catalog-root loss

If datagroup PAR2 is insufficient, copy the selected supergroup's `data/<sgid[:2]>/<sgid>/` and
`metadata/<sgid[:2]>/<sgid>/` trees into a scratch archive root, retaining these relative
paths. Gather its outer `.par2` files from all numbered parity-media directories
into one scratch parity directory beside their index: par2cmdline discovers
recovery volumes there. Do not gather the datagroup/central PAR2 into that directory.
Run `par2 repair -B/absolute/path/to/scratch-root /absolute/path/to/parity/S.par2`,
substituting the actual supergroup prefix for `S`. An intact recovery volume can
replace a missing index. This reconstructs stored ciphertext and metadata without
a private key. Datagroup PAR2 is not an outer input; recreate it from recovered inputs
if needed. Archivator `repair` also regenerates missing redundancy automatically.

For lost bootstrap files, gather any surviving root JSONs, format text, public
certificate and all
`archive-<aid>_metadata_catalog-root*.par2` into one scratch directory and run
`par2 repair` against that index (or a surviving volume). Both root JSON files can
be reconstructed before any settings or checksum chain is read. The same set
recovers the format text and public certificate; it contains no private key.

### 2. Inspect source metadata

Unencrypted inventory: `zstd -dc ACTUAL_INVENTORY.jsonl.zst`.
For encrypted inventory, use the same CMS decryption below as for a chunk, then
`zstd -dc` the authenticated result. It reveals original paths/attributes and,
for TAR streams, their complete member inventory. A private key suffices; the
public recipient certificate is optional for decryption. Without compression,
read the `.jsonl` file or authenticated decrypted bytes directly.

### 3. Decode each chunk

```bash
chunk=REPLACE_WITH_ACTUAL_CHUNK_FILENAME
openssl cms -decrypt -binary -inform DER \
  -in "$chunk" -out chunk.zst \
  -inkey /absolute/path/to/recipient-key.pem
zstd -dc chunk.zst > chunk.plain
sha256sum chunk.plain
```

For unencrypted data use `zstd -dc "$chunk" > chunk.plain` instead. Check the
plaintext length and hashes against the manifest when available, and the length
in the filename otherwise. Without compression, decrypt a `.cms` file straight
to `chunk.plain`; with neither transform, the stored chunk itself is plaintext.
Do not pass uncompressed bytes through zstd.

### 4. Extract a TAR or assemble a RAW file

A `.tar[.zst][.cms]` chunk already contains a **complete TAR**. No concatenation or
offset calculation is needed:

```bash
tar -tvf chunk.plain
mkdir -p extracted
tar -xpf chunk.plain -C extracted
```

Each TAR can be extracted independently, even when another chunk is lost beyond
PAR2 recovery. Multiple TAR chunks may be extracted into the same destination.

For a `.raw[.zst][.cms]` chunk, the filename supplies its original file position:

```bash
offset_field=${chunk#*_offset-}
offset_field=${offset_field%%_length-*}
offset=$((10#$offset_field))
dd if=chunk.plain of=reconstructed-stream bs=1M \
  oflag=seek_bytes seek="$offset" conv=notrunc status=none
```

Start with an absent `reconstructed-stream`; repeat for every chunk of the same
RAW stream, using its numeric offset, never directory order. Check final size and
whole-stream SHA-256 from the source metadata when available. The result is the
original file, with no TAR wrapper. A singleton RAW stream needs only its one chunk.

Restore direct-file attributes from its inventory. Missing fragments of a large
file cannot be recovered merely by possessing another datagroup from that stream.
If all metadata is unavailable, intact chunks (plus decryption key) still yield
payload bytes; original direct-file names and definitive completeness may be
unknown. [Filename-only scan](README.md#filename-only-recovery) automates this
fallback, skipping detected incomplete streams instead of inventing holes.

Cloud-native checksum encodings/composition and fixed 8 MiB upload-block digests
remain [mandatory production work](../POC.md#12-mandatory-checksum-requirements-for-a-real-implementation).
