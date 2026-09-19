# Archive format and manual recovery

The [specification](../POC.md) describes the implementation. Installation and demo
commands live only in the [root README](../README.md).

## Names and layout

`aid`, `sgid`, `gid`, and `sid` are archive, supergroup, group, and stream IDs:
independent random 96-bit values expressed as 24 lowercase hex digits. They are
identifiers, not hashes. Central metadata protection reuses its group's ID.

A **group** is one bounded media unit of chunks, metadata and group PAR2. A
**supergroup** contains up to five groups by default, with its own separate PAR2
protecting their data and metadata but not their group/central PAR2 files.

A **stream** is either an ordinary POSIX/PAX TAR or one original file's raw bytes.
One TAR is one complete chunk. Multiple whole TARs and whole RAW files can share
a group, including RAW files with several chunks. A RAW file spans groups only
when it cannot fit an empty one; it starts in a fresh group. Intermediate groups
contain only that file, while its final group can accept subsequent whole streams.
A TAR contains at least two regular files; a singleton is RAW.
Directories/symlinks alone need only inventory records, not payload chunks.

A group lives under `ARCHIVE/<sgid>/<gid[:2]>/`. Byte-identical `-spare` group
indexes and central PAR2 live under `ARCHIVE/metadata/<sgid>/<gid[:2]>/`.
The supergroup's index is under `<sgid>/metadata/`, its spare under
`metadata/<sgid>/`, and its PAR2 under `<sgid>/parity/<media-number>/`.
Only populated directories are created. A two-character shard can contain several
groups. Archive catalog-root copies and their own PAR2 live in `ARCHIVE/metadata/`.
IDs and group/supergroup directories remain in use when PAR2 is disabled.

For compactness in this table, `G` means
`archive-<aid>_supergroup-<sgid>_group-<gid>`, `M` means
`archive-<aid>_supergroup-<sgid>_metadata_group-<gid>`, and `S` means
`archive-<aid>_supergroup-<sgid>`.

| Filename | Role |
| --- | --- |
| `G_chunk-<n>_stream-<sid>_length-<length>.tar[.zst][.cms]` | One complete TAR |
| `G_chunk-<n>_stream-<sid>_offset-<offset>_length-<length>.raw[.zst][.cms]` | Whole original file bytes or one fragment |
| `G_metadata_index-chunks.json[.zst]` | Public chunk coordinates, settings, stored/plaintext hashes |
| `G_metadata_index-files.jsonl[.zst][.cms]` | Private source names/attributes for RAW and TAR |
| `G_metadata_index-chunks-spare.json[.zst]` | Identical central chunk-index copy |
| `G_metadata_index-files-spare.jsonl[.zst][.cms]` | Identical central source-index copy |
| `G.par2`, `G.vol<start>+<count>.par2` | Group PAR2 over chunks and primary metadata |
| `M_checksums.json[.zst]` | Central receipt, group-PAR2 hashes and preceding central link |
| `M.par2`, `M.vol<start>+<count>.par2` | PAR2 over central metadata copies and receipt |
| `M_format.txt`, `M_recipient.pem` | First central set's format note and optional public certificate |
| `S_metadata_index-groups.json[.zst]` | Protected supergroup members, sizes, hashes, PAR2 parameters and preceding supergroup link |
| `S_metadata_index-groups-spare.json[.zst]` | Identical central supergroup-index copy |
| `S.par2`, `S.vol<start>+<count>.par2` | Cross-group PAR2, including the primary supergroup index |
| `archive-<aid>_metadata_catalog-root.json`, `..._metadata_catalog-root-spare.json` | Identical uncompressed checksum roots |
| `archive-<aid>_metadata_catalog-root.par2`, `..._metadata_catalog-root.vol<start>+<count>.par2` | Independent protection sufficient for both root copies plus a slice |

**Inventories are metadata, not compressed file content.** Stream IDs inside
the inventory match the payload chunk names. TAR entries list members; RAW entries
identify the original file and ancestors. Every data
group has its own manifest and inventory, including groups carrying different
pieces of one large direct stream. The `stream` term is used consistently for
both types.

`index-chunks` is the public technical index of stored chunks. `index-files`
describes original paths and attributes for both RAW files and TAR members, so
it is encrypted whenever the payload is encrypted. These are group-level roles,
not separate indexes for RAW and TAR content.

Generated names contain lowercase ASCII letters, digits, `_`, `-`, `.`, and
PAR2's `+`. Chunk numbers restart at zero per group and are padded to at least
four decimal digits, with no four-digit maximum. Offsets use twenty digits and
lengths twelve; both refer to **uncompressed plaintext**, never ciphertext.
Offsets occur only in RAW names. TAR length includes headers, member padding,
end markers and final record padding. Internally its chunk offset is always zero.
Names remain meaningful when copied into a flat directory, including supergroup
membership. Group/central PAR2 records basenames; supergroup PAR2 records canonical
paths relative to ARCHIVE. Recovery reconstructs those paths when needed.
Generated components are at most 255 ASCII bytes; full paths relative to ARCHIVE
are at most 240 characters, including directories. External destination prefixes
are outside this bound; copying the contents to a volume root needs no renaming.
See Microsoft's [component limits](https://learn.microsoft.com/en-us/windows/win32/fileio/filesystem-functionality-comparison#limits)
and [conventional path limit](https://learn.microsoft.com/en-us/windows/win32/fileio/maximum-file-path-limitation). Discovery is recursive; archive-file mtimes and enumeration order do
not matter. Every stored file has a unique basename, including the two metadata
copies. Flattening the archive therefore needs no collision handling. Duplicate
basenames are rejected. A spare manifest still references primary filenames;
recovery maps the byte-identical spare to the primary name when needed.

## Contents and dependency order

With compression enabled, each chunk is one zstd level-3 frame with a content
checksum and no dictionary. Otherwise it contains plain TAR/RAW bytes.
Encrypted chunks and inventories wrap either form in binary CMS AuthEnvelopedData,
DER encoding, AES-256-GCM, RSA≥3072, RSA-OAEP/SHA-256 and MGF1-SHA-256.
Encryption appends `.cms`; compression appends `.zst` before it. Decrypt/authenticate
first, then decompress if applicable. Metadata JSON/JSONL follows the same
compression setting; only source-name inventories are encrypted.

The public manifest contains `version`, `archive`, `supergroup`, `group`, `compression`,
`encryption`, `settings`, `members`, `source_metadata`, and `source_sha256`.
Each chunk member records `filename`, `chunk`, `stream`, `kind` (`tar` or `raw`), `offset`, `length`,
`stored_length`, `stored_sha256`, `plaintext_sha256`, and `plaintext_sha512`.
It contains no original source names. `compression` is `zstd` or `none`;
`settings.compression` and `settings.par2` are booleans.

The inventory is JSONL: first `{"streams": [...]}`, followed by
`{"stream": "<id>", "entry": {...}}` records. Stream type is `file` or `tar`;
entries outside a byte stream use a null stream ID, and metadata-only groups
have an empty streams list. Original entries
include `path`, `type`, `mode`, `mtime_ns`, and, where applicable, `size` or
`symlink_target`. File checksums are CRC32, MD5, SHA-1, SHA-256, SHA-512. TAR hashes
are calculated while writing members. A direct stream's final group records its
whole-file hashes, unknown when earlier groups are written. Each group repeats
required ancestor-directory information, including root `.`.

Names are JSON strings, including escaped Unicode, tabs, newlines and filesystem
surrogate escapes. CRC32 matches ZIP. Digests are lowercase hex. SHA-256/SHA-512
are integrity checks; the older digests are lookup aids.

When PAR2 is enabled, local stored metadata is finished **before group PAR2**, so the same recovery set
can recreate a missing manifest/inventory. Make its identical central copies,
then write the central receipt with the finished group-PAR2 hashes. Central PAR2
protects that receipt and the copies. No manifest hashes its own PAR2.

Each receipt links backward to the preceding central receipt's SHA-256 and PAR2
hashes. Catalog-root markers hold the last central and supergroup links, counts, and settings,
so they do not grow with the archive's group count. `marker_sha256` hashes
canonical ASCII JSON, sorted keys and compact separators, excluding that field.
These files contain the checksum-chain root, not the full catalog. The `-spare`
file is byte-identical to the primary. Markers are published last, after generating their own bootstrap PAR2, and are not signed. Without PAR2,
the copies, receipts, and checksum chain still exist; parity-hash maps are empty.

## Sizing and recovery capacity

Defaults are **268435455 bytes per final file** and **15032385536 bytes per group**.
Both include format overhead; a group includes its metadata and PAR2. Central
sets obey the same limits. Compression expansion and CMS wrappers are reserved
before selecting plaintext chunk sizes; final sizes are checked before publication.
Complete TAR admission counts TAR/PAX headers and all padding before applying
the zstd/CMS bound. Groups accumulate actual stored chunk sizes with conservative
metadata/parity reservations. The optional `--large-file-bytes` routing threshold
can be lower than the safe input ceiling without reducing RAW chunk sizes.

Whole RAW files and whole TARs are placed through one active group and a bounded
queue, defaulting to four waiting groups and a 95% close-on-miss threshold.
See the [queue rules](../POC.md#6-group-sizing-and-parity). These are writer policies,
not a required restore order. No artificial chunk/group padding is used.

Group and central PAR2 use 1 MiB slices by default. Recovery is the maximum of 20% of actual
protected bytes, 125% of the largest member, and one slice more than that member
occupies, rounded up to whole slices. Short/final sets may have much more than
20% parity; the calculation never uses nominal maximum group capacity. Volume
count varies to keep indexes/volumes within the file limit. Packet headers and
repeated critical metadata also consume space.

Supergroup PAR2 uses at least 110% of the largest group's source-block count,
at least 20% of the total, and at least one block beyond the largest group.
Counts round separately per protected file; outer slices double if needed to fit
PAR2's block limit. The index records the exact parameters. Recovery files are
packed into numbered media directories within the same byte limit as a group.
A final short supergroup uses actual members, not nominal maximum capacity.
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

### 1. Recover a local group

Copy **all** files for the chosen group: chunks, manifest, inventory, and PAR2.
It does not need the central `metadata/` directory.

```bash
aid=REPLACE_WITH_ARCHIVE_ID
sgid=REPLACE_WITH_SUPERGROUP_ID
gid=REPLACE_WITH_GROUP_ID
archive=/absolute/path/to/archive
scratch=/absolute/path/to/manual-scratch
mkdir -p "$scratch"
cp "$archive/$sgid/${gid:0:2}"/archive-"$aid"_supergroup-"$sgid"_group-"$gid"* "$scratch/"
cd "$scratch"
base="archive-${aid}_supergroup-${sgid}_group-${gid}"
par2 verify "$base.par2"
par2 repair "$base.par2"
```

If the index is absent, give `par2` a surviving `.vol...par2` instead. Repeat for
other groups needed by the desired direct-file stream. A TAR needs only its own
group. Public manifests can be inspected with `zstd -dc "$base"_metadata_index-chunks.json.zst`.
Without compression, read the `.json` manifest directly.
Check stored SHA-256 values before decoding payload.

For central metadata recovery, copy that set's files from `metadata/<sgid>/<gid[:2]>`
into scratch and run the same PAR2 commands against its `archive-<aid>_supergroup-<sgid>_metadata_group-<gid>` prefix. Its protected receipt identifies the previous central set. Either valid
catalog-root marker supplies the final checksum root.

### Whole-group or catalog-root loss

If group PAR2 is insufficient, copy the selected supergroup's `<sgid>/` and
`metadata/<sgid>/` trees into a scratch archive root, retaining these relative
paths. Gather its outer `.par2` files from all numbered parity-media directories
into one scratch parity directory beside their index: par2cmdline discovers
recovery volumes there. Do not gather the group/central PAR2 into that directory.
Run `par2 repair -B/absolute/path/to/scratch-root /absolute/path/to/parity/S.par2`,
substituting the actual supergroup prefix for `S`. An intact recovery volume can
replace a missing index. This reconstructs stored ciphertext and metadata without
a private key. Group PAR2 is not an outer input; recreate it from recovered inputs
if needed. Archivator `repair` also regenerates missing redundancy automatically.

For lost catalog-root copies, gather both surviving root copies and all
`archive-<aid>_metadata_catalog-root*.par2` into one scratch directory and run
`par2 repair` against that index (or a surviving volume). Both root JSON files can
be reconstructed before any settings or checksum chain is read.

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
file cannot be recovered merely by possessing another group from that stream.
If all metadata is unavailable, intact chunks (plus decryption key) still yield
payload bytes; original direct-file names and definitive completeness may be
unknown. [Filename-only scan](README.md#filename-only-recovery) automates this
fallback, skipping detected incomplete streams instead of inventing holes.

Cloud-native checksum encodings/composition and fixed 8 MiB upload-block digests
remain [mandatory production work](../POC.md#12-mandatory-checksum-requirements-for-a-real-implementation).
