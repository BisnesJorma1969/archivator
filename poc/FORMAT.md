# Archive format and manual recovery

The [specification](../POC.md) describes the implementation. Installation and demo
commands live only in the [root README](../README.md).

## Names and layout

`aid`, `pid`, and `sid` are archive, data parity-group, and stream IDs: independent
random 128-bit values expressed as 32 lowercase hex digits. They are identifiers,
not hashes. Central metadata parity reuses `pid`; it gets no extra random ID.

A **stream** is either an ordinary POSIX/PAX TAR or one original file's raw bytes.
One TAR is one complete chunk. Multiple whole TARs and whole RAW files can share
a group, including RAW files with several chunks. A RAW file spans groups only
when it cannot fit an empty one; it starts in a fresh group. Intermediate groups
contain only that file, while its final group can accept subsequent whole streams.
A TAR contains at least two regular files; a singleton is RAW.
Directories/symlinks alone need only inventory records, not payload chunks.

The local group lives under `ARCHIVE/<pid[:2]>/`. Its identical metadata copies
and separate central PAR2 live under `ARCHIVE/metadata/<pid[:2]>/`. Only populated
shards are created; several groups can share one shard. Catalog-root markers live
under `ARCHIVE/metadata/`. Optional `.zst` and `.cms` suffixes describe the enabled
transforms. PAR2 files exist only when enabled; group IDs and the `parity-` name
component are used regardless.

| Filename after `archive-<aid>_` | Role |
| --- | --- |
| `parity-<pid>_chunk-<n>_stream-<sid>_length-<length>.tar[.zst][.cms]` | One complete, independently extractable TAR |
| `parity-<pid>_chunk-<n>_stream-<sid>_offset-<offset>_length-<length>.raw[.zst][.cms]` | Original file bytes: a whole file or a fragment |
| `parity-<pid>_metadata_index-chunks.json[.zst]` | Public group structure, settings, chunk hashes and stored-inventory hash; local plus identical central copy |
| `parity-<pid>_metadata_index-files.jsonl[.zst][.cms]` | Group's stream descriptions and original source entries; local plus identical central copy |
| `parity-<pid>.par2`, `parity-<pid>.vol<start>+<count>.par2` | PAR2 over local payload **and metadata** |
| `metadata_parity-<pid>_checksums.json[.zst]` | Central receipt: metadata-copy hashes/lengths, data-PAR2 hashes, previous central link |
| `metadata_parity-<pid>.par2`, `metadata_parity-<pid>.vol<start>+<count>.par2` | PAR2 over that central set's metadata copies and receipt |
| `metadata_parity-<pid>_format.txt` | Small uncompressed format/settings note, in the first central set |
| `metadata_parity-<pid>_recipient.pem` | Optional normalized public certificate, in the first central set |
| `metadata_catalog-root.json`, `metadata_catalog-root-spare.json` | Identical uncompressed catalog-root markers |

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
Names remain meaningful when copied into a flat directory. PAR2 records relative
basenames. Discovery is recursive; archive-file mtimes and enumeration order do
not matter. Two group-metadata copies are intentional, other duplicates are not.

## Contents and dependency order

With compression enabled, each chunk is one zstd level-3 frame with a content
checksum and no dictionary. Otherwise it contains plain TAR/RAW bytes.
Encrypted chunks and inventories wrap either form in binary CMS AuthEnvelopedData,
DER encoding, AES-256-GCM, RSA≥3072, RSA-OAEP/SHA-256 and MGF1-SHA-256.
Encryption appends `.cms`; compression appends `.zst` before it. Decrypt/authenticate
first, then decompress if applicable. Metadata JSON/JSONL follows the same
compression setting; only source-name inventories are encrypted.

The public manifest contains `version`, `archive`, `parity`, `compression`,
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

When PAR2 is enabled, local stored metadata is finished **before data PAR2**, so the same recovery set
can recreate a missing manifest/inventory. Make its identical central copies,
then write the central receipt with the finished data-PAR2 hashes. Central PAR2
protects that receipt and the copies. No manifest hashes its own PAR2.

Each receipt links backward to the preceding central receipt's SHA-256 and PAR2
hashes. Catalog-root markers hold only the last link, group count, and settings,
so they do not grow with the archive's group count. `marker_sha256` hashes
canonical ASCII JSON, sorted keys and compact separators, excluding that field.
These files contain the checksum-chain root, not the full catalog. The `-spare`
file is byte-identical to the primary. Markers are published last, are outside PAR2, and are not signed. Without PAR2,
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

When enabled, PAR2 uses 1 MiB slices by default. Recovery is the maximum of 20% of actual
protected bytes, 125% of the largest member, and one slice more than that member
occupies, rounded up to whole slices. Short/final sets may have much more than
20% parity; the calculation never uses nominal maximum group capacity. Volume
count varies to keep indexes/volumes within the file limit. Packet headers and
repeated critical metadata also consume space.

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
pid=REPLACE_WITH_GROUP_ID
archive=/absolute/path/to/archive
scratch=/absolute/path/to/manual-scratch
mkdir -p "$scratch"
cp "$archive/${pid:0:2}"/archive-"$aid"_parity-"$pid"* "$scratch/"
cd "$scratch"
base="archive-${aid}_parity-${pid}"
par2 verify "$base.par2"
par2 repair "$base.par2"
```

If the index is absent, give `par2` a surviving `.vol...par2` instead. Repeat for
other groups needed by the desired direct-file stream. A TAR needs only its own
group. Public manifests can be inspected with `zstd -dc "$base"_metadata_index-chunks.json.zst`.
Without compression, read the `.json` manifest directly.
Check stored SHA-256 values before decoding payload.

For central metadata recovery, copy that set's files from `metadata/<pid[:2]>`
into scratch and run the same PAR2 commands against its `metadata_parity-<pid>`
prefix. Its protected receipt identifies the previous central set. Either valid
catalog-root marker supplies the final checksum root.

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
