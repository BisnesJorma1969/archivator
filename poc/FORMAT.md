# Version 1 archive and manual recovery

The authoritative design is [POC.md](../POC.md). This document describes the
concrete bootstrap files and recovery procedure implemented by this PoC.

## Names and contents

All archive IDs, stream IDs, and parity-set IDs are independent random 128-bit
values written as 32 lowercase hexadecimal digits. Archive-generated names use
lowercase ASCII; standard PAR2 volume names additionally contain `+`.

| Filename suffix after `archive-<aid>_` | Contents |
| --- | --- |
| `format.txt` | Version, transforms, chunk/parity settings, optional certificate fingerprint |
| `streams.jsonl` | TAR/direct-file stream meaning, length, SHA-256/SHA-512 |
| `stream-<sid>_files.jsonl` | Original paths, types, metadata, and small-file checksums |
| `recipient.pem` | Optional normalized public X.509 certificate |
| `parity-<pid>_manifest.json` | Chunk coordinates, hashes, lengths, and recovery capacity |
| `parity-<pid>_chunk-<number>_stream-<sid>_offset-<offset>_length-<length>.gz[.cms]` | Independent stored chunk |
| `parity-<pid>.par2` and `.vol<start>+<count>.par2` | Data PAR2 index and four approximately uniform volumes |
| `checksums.json` | SHA-256 map for ordinary metadata and data-set PAR2 files |
| `parity-<pid>_metadata.par2` and `_metadata.vol<start>+<count>.par2` | Separate metadata recovery set |
| `complete.json` | Final checksum root and completion marker |

Chunk numbers are four decimal digits, local to a parity set. Offsets are twenty
decimal digits and lengths twelve. Offsets/lengths always describe **uncompressed
plaintext stream bytes**, never compressed bytes. Directory order is irrelevant.

TAR streams use POSIX/PAX. The inventory includes the source root as path `.` so
even empty trees retain root metadata. Original names are JSON strings, including
escaped tabs, newlines, Unicode, and filesystem surrogate escapes. File digests are
lowercase hex; CRC16-CCITT-FALSE is four digits and CRC32 eight. SHA-256 is the
normal authoritative content digest; restore also verifies recorded SHA-512.

Each chunk is gzip-compressed independently with an empty gzip filename and zero
gzip timestamp. Encrypted chunks wrap that gzip data in binary OpenSSL CMS
AuthEnvelopedData with AES-256-GCM and DER encoding. Encryption does not change
plaintext stream coordinates. No private key is copied into archive metadata.

## Recovery capacity and metadata bootstrap

For each data parity set, compute the larger of 20% of total stored data and 125%
of the largest member. Round up to whole PAR2 slices. Also require at least four
recovery blocks and at least one more block than the largest member occupies;
these minimums preserve the four-volume and additional-corruption requirements
for small or strongly compressed sets. Metadata uses the same capacity rule.

Checksums have a deliberately non-circular dependency order:

1. `checksums.json` covers catalogs, inventories, format, certificate, manifests,
   and the five PAR2 files for each data set.
2. A separate metadata PAR2 set protects those metadata files and the checksum
   index. Data-set PAR2 files are checksummed but are not metadata PAR2 members.
3. `complete.json` records the metadata member list, metadata parity prefix and
   parameters, checksum-index SHA-256, and hashes of all five metadata PAR2 files.
   It is atomically published last.

This lets the reader recover a missing/damaged catalog or checksum index before
interpreting data manifests. It also detects damaged parity files when all data
is intact. The completion marker is the unprotected bootstrap root, not a
self-checksummed or signed file. A missing/malformed marker is treated as an
incomplete archive; manual recovery can still use the PAR2 files and catalogs.

PAR2 identifies protected content; manifests automate selection and carry the
additional SHA-256/SHA-512 checks. After repair, stored bytes must still match
their recorded content hashes. All archive-file filesystem mtimes are ignored.

## Manual recovery with ordinary tools

Work on copies. The examples below use Bash and GNU coreutils; replace the IDs,
paths, and filenames with those from the archive. Tools may need to be added to
`PATH` if installed locally under `work/tools/usr/bin/`.

### 1. Recover catalogs if necessary

Copy the metadata members named in `complete.json` and their metadata PAR2 files
to a scratch directory. If the marker is lost, metadata PAR2 filenames still have
the `_metadata` role suffix and contain the protected member names.

```sh
par2 verify archive-<aid>_parity-<pid>_metadata.par2
par2 repair archive-<aid>_parity-<pid>_metadata.par2
```

These angle-bracket filenames are notation, not literal shell commands. Use actual
filenames. If an index is missing, pass any surviving volume from that set instead.
Read the recovered catalog to find stream IDs and their destination paths.

### 2. Recover a data parity set

For a selected data set, copy only its candidate chunks and PAR2 files to scratch:

```bash
aid=REPLACE_WITH_ARCHIVE_ID
pid=REPLACE_WITH_PARITY_SET_ID
archive=/absolute/path/to/archive
scratch=/absolute/path/to/manual-scratch
mkdir -p "$scratch"
cp "$archive"/archive-"$aid"_parity-"$pid"* "$scratch/"
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
  -in "$chunk" -out chunk.gz \
  -inkey /absolute/path/to/recipient-key.pem \
  -recip /absolute/path/to/recipient.pem
gzip -dc chunk.gz > chunk.plain
sha256sum chunk.plain
```

For an unencrypted chunk, use `gzip -dc "$chunk" > chunk.plain` directly. Check
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
that stream. Then check its size and whole-stream SHA-256 from `streams.jsonl`:

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
