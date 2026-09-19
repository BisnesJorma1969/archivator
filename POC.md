# Minimal Archivator PoC

This document describes the implemented PoC. The [root README](README.md) is the
single Ubuntu 26.04 install/demo guide. See [CLI reference](poc/README.md) and
[format and manual recovery](poc/FORMAT.md) for details.

## 1. Goal and scope

Compressed, optionally encrypted, bitrot-tolerant backups, split into manageable
files and protected by standard PAR2. Restore with ordinary Linux tools even
decades later, without Archivator: PAR2, OpenSSL CMS, zstd, tar, and coreutils.
Loss of metadata does not by itself destroy payload bytes. Intact chunk filenames
supply their plaintext offsets and lengths; encrypted payload also needs the
private key. Separate metadata supplies original direct-file names, attributes,
and authoritative completeness/checksum information.

The PoC proves `source directory → archive directory → restored directory`, with
`compare` checking the resulting tree. No cloud integration, networking, workers,
custom crypto, custom parity, resume protocol, or filesystem snapshots.

Implementation is under `poc/`; generated data and scratch use ignored
`poc/work/`. Keep code straightforward and human-readable. No compatibility or
migration layer is part of this greenfield format.

## 2. Terminology and identifiers

| Term | Meaning |
| --- | --- |
| Archive | A complete backup, identified by an archive ID |
| Stream | Plaintext bytes of one original file or one ordinary POSIX/PAX TAR |
| Chunk | An independently zstd-compressed, optionally CMS-encrypted stream range |
| Data parity group | Chunks from **one stream**, local source metadata, public manifest, and PAR2 |
| Central metadata set | Identical metadata copies and their checksum receipt, protected by separate PAR2 |

Archive IDs, stream IDs, and data-group IDs are random 128-bit identifiers, not
content hashes. Each is 32 lowercase hexadecimal digits. Central metadata PAR2
**reuses its data group's ID**; no extra random metadata or shard IDs are generated.

A TAR belongs wholly to one data group. A large direct-file stream can span many
groups. A group describing a fragment of a large file is independently
interpretable and repairable, but cannot reproduce absent fragments.

## 3. Hard byte limits

| Setting / backup option | Default |
| --- | ---: |
| `max_file_bytes` / `--max-file-bytes` | 268435455 (256 MiB − 1 byte) |
| `max_group_bytes` / `--max-group-bytes` | 15032385536 (14 GiB) |
| Internal PAR2 `slice_size` | 1048576 (1 MiB) |

These are exact byte counts. The program does not interpret media marketing
capacities, estimate formatting overhead, or subtract filesystem space. For a
FAT32 file ceiling, specify **4294967295** bytes. The user supplies a suitable
usable group capacity for the destination medium.

The file ceiling applies to **every final file**: `.zst`, `.zst.cms`, manifests,
inventories, checksum receipts, bootstrap files, PAR2 indexes, and volumes.
The group ceiling includes data, local metadata, and **all PAR2 overhead**.
Central metadata recovery sets obey the same two ceilings. The two completion
copies form a separate small bootstrap set and are checked together.

The implementation reserves compression expansion, measured CMS wrapper space,
PAR2 packet headers and repeated critical packets, and metadata before admitting
input. It checks actual output lengths before publishing. Limits are ceilings,
not targets: groups may close early, and compressed files need not have equal
sizes. Impossible combinations of limits fail explicitly rather than producing
an oversized completed archive.

The derived input chunk ceiling allows for incompressible zstd output and the
recipient's CMS wrapper. It also leaves room for a small group by limiting the
stored chunk allowance to at most one quarter of the group budget. No padding or
alignment is added between compression frames, CMS, and PAR2 slices.

## 4. Source traversal and TAR collection

Visit directories recursively, listing and optionally alphabetizing only the
current directory. There is no full-source pre-scan, global size sort, or second
whole-tree validation pass. Supported inputs are directories, regular files,
and symbolic links, using `lstat` without following links. Reject special files.

Keep the active directory lists and the current bounded TAR inventory in memory,
not the entire source tree. Write group catalogs progressively. Observable source
changes abort backup; ordinary stat checks are not a snapshot guarantee.

Files at least as large as the derived plaintext chunk ceiling go directly to
the direct-file handler. Smaller files are TAR candidates. Try the first fitting
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
A group with only filesystem metadata needs no artificial TAR or data chunk.

Never split an original large file into custom TAR members. TARs remain ordinary
TARs; direct streams remain the original file bytes.

## 5. Chunks and transforms

Each chunk is an independent zstd frame, level 3, `--single-thread --check`, no
dictionary or embedded source name. Compression/decompression use bounded I/O
buffers. Encrypted frames are binary CMS AuthEnvelopedData in DER, with suffix
**`.zst.cms`**. Unencrypted frames end in `.zst`.

Use AES-256-GCM, an RSA recipient key of at least 3072 bits, RSA-OAEP/SHA-256 and
MGF1-SHA-256. OpenSSL generates content keys/nonces. Reject weak or unsuitable
recipient keys before reading file contents. Normalize the public certificate;
never copy a private-key PEM block into the archive.

Encrypt source-path inventories as well as payload. Public manifests contain
only technical IDs, coordinates, sizes, algorithms, and checksums of stored
files. They enable verification/PAR2 repair without a private key. Source
metadata is compressed first, encrypted once, and **that exact ciphertext** is
copied to the central metadata directory.

Private keys remain external. Decrypt in owner-only scratch, authenticate before
decompression, and remove output on authentication failure. Backup staging is
`0700`; compressed plaintext and decryption output are `0600`. Cleanup is not
secure erasure. Production limitations remain in section 13.

## 6. Group sizing and parity

A group never mixes streams. Direct streams close a group before the next stored
chunk would exceed the byte/metadata/PAR2 budget. TAR admission uses conservative
bounds so its entire stream and inventory fit one group. No arbitrary chunk-count
or filename-width limit is used. PAR2's own 32768 source/recovery-block limits
also constrain admission; slice sizes are positive multiples of four.

Protect **stored** chunks and already compressed/encrypted metadata together.
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
2. Write the stream/source inventory, compress it, and encrypt it when requested.
3. Write and compress the public group manifest, referencing stored inventory and
   chunk SHA-256 values. It carries settings and plaintext chunk checksums.
4. Generate data PAR2 over **chunks + stored inventory + stored manifest**.
5. Make identical inventory/manifest copies under `metadata/`.
6. Write a compressed central checksum receipt covering these copies and the
   finished data PAR2 files; protect the copies and receipt with central PAR2.

The local manifest never hashes PAR2 generated from itself. Each central receipt
also records the previous central receipt's stored SHA-256 and PAR2 hashes. The
last link and group count go into two identical self-checksummed completion
markers, published last. This bounded chain avoids one unbounded archive-wide
checksum list or marker. Each central recovery set is independently bounded.

The first central set additionally protects a small uncompressed format note and
normalized public recipient certificate when encrypted. These and completion
markers are the explicit uncompressed roles. Inventories, manifests, and receipts
always use zstd, regardless of size or compression ratio.

The inventory's first JSONL record describes its stream; subsequent records
list original filesystem entries and required ancestors. For TARs it lists TAR
members. For direct streams it identifies the original file and needed directory
metadata. Metadata-only groups use a null stream. Repeated ancestor descriptions
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
  <pid[:2]>/
    archive-<aid>_parity-<pid>_chunk-...zst[.cms]
    archive-<aid>_parity-<pid>_manifest.json.zst
    archive-<aid>_parity-<pid>_metadata_inventory_stream-<sid>.jsonl.zst[.cms]
    archive-<aid>_parity-<pid>.par2
    archive-<aid>_parity-<pid>.vol...par2
  metadata/
    <pid[:2]>/
      (identical copies of that group's manifest and inventory)
      archive-<aid>_metadata_parity-<pid>_checksums.json.zst
      archive-<aid>_metadata_parity-<pid>.par2
      archive-<aid>_metadata_parity-<pid>.vol...par2
    archive-<aid>_metadata_complete.json
    archive-<aid>_metadata_complete-copy.json
```

Only populated shard directories are created. Many groups can share a shard.
PAR2 stores basenames relative to its shard. Chunk numbers are local to a group,
zero-padded to **at least** four digits, without a four-digit maximum. Offsets
and lengths are plaintext byte coordinates, not compressed/encrypted coordinates.

Readers discover files recursively in flat, nested, or mixed layouts. Exactly two
copies of group metadata are intentional; use recorded checksums to select good
bytes and report missing/damaged redundancy. Other duplicate basenames are
rejected. Archive-file mtimes and enumeration order have no recovery significance.

## 9. Verify, repair, and restore

- `verify` checks stored checksums and PAR2 capacity, without needing a key.
  Any damage, including metadata copies or parity only, returns 1. It can repair
  metadata in scratch to complete its diagnosis, never changing the archive.
- `repair` changes stored inputs **in place**. No staging copies/hardlinks of
  data or parity. Scattered inputs are gathered with same-filesystem renames.
  Replacing a missing/damaged intentional metadata duplicate can copy its healthy
  counterpart. Regenerate missing PAR2 from intact inputs. Completed changes
  remain if a later set fails.
- `restore` uses read-only hardlinks for healthy inputs and ordinary copies for
  damaged/unknown inputs before scratch PAR2 repair; no CoW. Failed/cross-device
  hardlinks fall back to ordinary copies. Archives are never modified.

A valid completion marker anchors the full catalog. Either marker copy suffices;
conflicting valid copies are rejected. A surviving local group can also be
restored without the central directory/markers. Report that original backup
completeness cannot be proved, and return 1 for that partial-catalog mode.
Streams with detected gaps are skipped entirely; never fabricate holes or
publish a fragment as a complete file. TARs wholly inside surviving groups retain
standard-tool recoverability.

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
packets. It writes a separate `.json.zst` index of surviving chunk/data-PAR2 names.
Restore with `--scan-index` uses those coordinates and available PAR2, checks
CMS/zstd/declared lengths, and skips streams with detected gaps or bad chunks.

Without source metadata, direct streams use `stream-<id>.bin`. Recognized safe
TARs are kept as `stream-<id>.tar` and also extracted under `stream-<id>/`.
Missing tails or whole streams cannot always be detected. Exit 0 in filename-only
mode means no detected failure, not proof of original backup completeness.

## 11. CLI, progress, tests, and demo

See the single [CLI reference](poc/README.md). Exit codes are 0 for success,
1 for integrity/comparison failure or unproven partial-catalog restore, and 2 for
usage/operational failure. Major stages print immediately; an activity heartbeat
appears every five seconds, including while external tools run. It is not a delay
between files or a fabricated completion percentage.

Tests use small explicit settings and real zstd/OpenSSL/PAR2. They cover hard
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
3. **Archive authenticity and context binding.** Metadata and completion markers
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
