# Version 1 archive and manual recovery

The authoritative design is [POC.md](../POC.md). This document describes the
concrete bootstrap files and recovery procedure implemented by this PoC.

## Names and contents

All archive IDs, stream IDs, and parity-set IDs are independent random 128-bit
values written as 32 lowercase hexadecimal digits. Archive-generated names use
lowercase ASCII; standard PAR2 volume names additionally contain `+`.

Archive-level metadata and its PAR2 files share the prefix `archive-<aid>_metadata`
and live at the archive root. Files containing `_chunk-` hold the actual backed-up
content. A stream inventory describes files; it is not payload.

Data chunks, their PAR2 files, and their one-per-set manifest are stored under
`<archive-root>/<first-two-data-parity-ID-characters>/`, sharing the prefix
`archive-<aid>_parity-<pid>`. Shards are created only when populated; different
sets may share a shard. No additional ID or hash is calculated.
Catalogs identify files by basename, and readers find them recursively in any
layout. Data PAR2 records basenames relative to its shard; metadata PAR2 records
archive-relative paths, including sharded manifests. Recovery arranges inputs
in those locations, in scratch for restore/verify or by renames for in-place repair.

| Filename suffix after `archive-<aid>_` | Contents |
| --- | --- |
| `metadata_format.txt` | Version, transforms, chunk/parity settings, optional certificate fingerprint |
| `metadata_streams.jsonl.zst` | TAR/direct-file stream meaning, length, SHA-256/SHA-512 |
| `metadata_inventory_stream-<sid>.jsonl.zst` | Original paths, types, metadata, and small-file checksums |
| `metadata_recipient.pem` | Optional normalized public X.509 certificate |
| `parity-<pid>_manifest.json.zst` | One manifest beside each data set: chunk coordinates, hashes, lengths, and recovery capacity; protected by metadata PAR2 |
| `parity-<pid>_chunk-<number>_stream-<sid>_offset-<offset>_length-<length>.zst[.enc]` | Independent stored chunk |
| `parity-<pid>.par2` and `.vol<start>+<count>.par2` | Data PAR2 index and four approximately uniform volumes |
| `metadata_checksums.json.zst` | SHA-256 map for ordinary metadata and data-set PAR2 files |
| `metadata.par2` and `metadata.vol<start>+<count>.par2` | One metadata recovery set per archive; no separate set ID |
| `metadata_complete.json`, `metadata_complete-copy.json` | Identical, self-checksummed bootstrap copies |

The two completion-marker copies, `metadata_format.txt`, and `metadata_recipient.pem` always stay
uncompressed for bootstrap and inspection. All other metadata is always compressed
with the same zstd settings as data chunks, regardless of size or compression ratio;
no uncompressed copies are retained. Catalog references retain logical filenames;
the checksum index and completion markers list exact stored filenames. Metadata
is not encrypted.

Chunk numbers are four decimal digits, local to a parity set. Offsets are twenty
decimal digits and lengths twelve. Offsets/lengths always describe **uncompressed
plaintext stream bytes**, never compressed bytes. Directory order is irrelevant.

TAR streams use POSIX/PAX. The inventory includes the source root as path `.` so
even empty trees retain root metadata. Original names are JSON strings, including
escaped tabs, newlines, Unicode, and filesystem surrogate escapes. File digests are
lowercase hex; ZIP-compatible CRC32 uses eight digits. SHA-256 is the
normal authoritative content digest; restore also verifies recorded SHA-512.

Each chunk is an independent zstd frame, compressed at level 3 with
`--single-thread --check` and no dictionary. Frames contain no source filename or
timestamp. Encrypted chunks wrap that zstd data in binary OpenSSL CMS
AuthEnvelopedData with AES-256-GCM and DER encoding, stored as `.zst.enc`.
The recipient uses RSA of at least 3072 bits with RSA-OAEP, SHA-256, and
MGF1-SHA-256. These algorithm parameters are encoded in CMS. Encryption does not
change plaintext stream coordinates. No private key is copied into archive metadata.

## Recovery capacity and metadata bootstrap

For each data parity set, compute the larger of 20% of total stored data and 125%
of the largest member. Round up to whole PAR2 slices. Also require at least four
recovery blocks and at least one more block than the largest member occupies;
these minimums preserve the four-volume and additional-corruption requirements
for small or strongly compressed sets. Metadata uses the same capacity rule.

Checksums have a deliberately non-circular dependency order:

1. `metadata_checksums.json.zst` covers catalogs, inventories, format, certificate, manifests,
   and the five PAR2 files for each data set.
2. A separate metadata PAR2 set protects those metadata files and the checksum
   index. Data-set PAR2 files are checksummed but are not metadata PAR2 members.
3. Both completion-marker copies record the metadata member list, metadata parity prefix and
   parameters, checksum-index SHA-256, and hashes of all five metadata PAR2 files.
   Each is atomically published after the protected files. `marker_sha256` is the
   SHA-256 of canonical ASCII JSON excluding that field, with sorted keys and
   compact separators.

This lets the reader recover a missing/damaged catalog or checksum index before
interpreting data manifests. It also detects damaged parity files when all data
is intact. Checksums and PAR2 cover stored bytes, before metadata decompression.
The markers are outside PAR2 and are not signed. Either valid copy enables
automatic recovery; verify reports a missing/damaged copy and repair replaces it.
If neither survives, manual recovery can still use PAR2 files and catalogs.
If metadata itself is unavailable, [filename-only scan and recovery](README.md#filename-only-recovery)
can reconstruct surviving streams using the same standard formats without
inventing a complete archive manifest.
Conflicting valid copies are rejected; interruption between marker updates during
repair can require manual intervention. Two copies in the same directory do not
protect against losing the entire storage location.

PAR2 identifies protected content; manifests automate selection and carry the
additional SHA-256/SHA-512 checks. After repair, stored bytes must still match
their recorded content hashes. All archive-file filesystem mtimes are ignored.

Version 1 does not record cloud-compatible checksum variants or fixed upload-block
digests. Direct-file sources also lack the MD5/SHA-1/CRC lookup digests recorded
for TAR-contained files. Consistent source checksums, stored-object compatibility,
and separate 8 MiB upload-checksum blocks are
[mandatory production requirements](../POC.md#24-mandatory-checksum-requirements-for-a-real-implementation),
not features of this format.

## Manual recovery with ordinary tools

Install the tools using the [Ubuntu 26.04 setup](../README.md#install). Work on
copies. The examples below use Bash; replace the IDs, paths, and filenames with
those from the archive.

### 1. Recover catalogs if necessary

Copy the metadata members named in either completion-marker copy and their metadata
PAR2 files to scratch, keeping data-set manifests under their two-character data
shards and other metadata at the scratch root. Run PAR2 from that root.
If both markers are lost, metadata PAR2 filenames still have
the `archive-<aid>_metadata` prefix and contain the protected member names.

```sh
par2 verify archive-<aid>_metadata.par2
par2 repair archive-<aid>_metadata.par2
```

These angle-bracket filenames are notation, not literal shell commands. Use actual
filenames. If an index is missing, pass any surviving volume from that set instead.
Check the recovered stored-file hashes against the checksum index (whose stored
hash is in either marker). For compressed metadata, decompress only after repair
and stored-byte verification, using `zstd -dk ACTUAL_METADATA_FILENAME.zst` in
scratch. Start with the checksum index if it is compressed. Read the recovered
catalog to find stream IDs and their destination paths.

### 2. Recover a data parity set

For a selected data set, copy only its candidate chunks and PAR2 files to scratch:

```bash
aid=REPLACE_WITH_ARCHIVE_ID
pid=REPLACE_WITH_PARITY_SET_ID
archive=/absolute/path/to/archive
scratch=/absolute/path/to/manual-scratch
mkdir -p "$scratch"
shard=${pid:0:2}
cp "$archive/$shard"/archive-"$aid"_parity-"$pid"* "$scratch/"
cd "$scratch"

base="archive-${aid}_parity-${pid}"
par2 verify "$base.par2"   # nonzero can mean repair is possible
par2 repair "$base.par2"
par2 verify "$base.par2"
```

Repeat for every parity set containing pieces of the desired stream. Keep chunks
from unrelated archive IDs separate. Use `sha256sum` to check stored chunks
against their manifest values before decoding.

### 3. Decode and place each chunk

For an encrypted chunk:

```bash
chunk=REPLACE_WITH_ACTUAL_CHUNK_FILENAME
openssl cms -decrypt -binary -inform DER \
  -in "$chunk" -out chunk.zst \
  -inkey /absolute/path/to/recipient-key.pem \
  -recip /absolute/path/to/recipient.pem
zstd -dc chunk.zst > chunk.plain
sha256sum chunk.plain
```

For an unencrypted chunk, use `zstd -dc "$chunk" > chunk.plain` directly. Check
the plaintext checksum and byte length against its manifest. Do not concatenate
pieces in directory-listing order.

Extract the decimal byte offset from the filename and write the bytes there:

```bash
offset_field=${chunk#*_offset-}
offset_field=${offset_field%%_length-*}
offset=$((10#$offset_field))
dd if=chunk.plain of=reconstructed-stream bs=1M \
  oflag=seek_bytes seek="$offset" conv=notrunc status=none
```

Start with an absent `reconstructed-stream` and write every chunk belonging to
that stream. Then check its size and whole-stream SHA-256 from `metadata_streams.jsonl`:

```sh
wc -c reconstructed-stream
sha256sum reconstructed-stream
```

A direct-file stream is the original file content. A TAR stream can be listed
and extracted with ordinary TAR tools into an empty directory:

```sh
tar -tvf reconstructed-stream
mkdir extracted
tar -xpf reconstructed-stream -C extracted
```

Validate extracted entries against the inventory. The inventory's `mtime_ns` is
the exact source value when the target can represent it; the PAX TAR also carries
timestamps for ordinary-tool recovery. Apply direct-file and root metadata from
the catalog/inventory using the target system's normal tools.
