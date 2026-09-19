# PoC command reference

Use the [root README](../README.md) for the single Ubuntu 26.04 installation and
backup/damage/restore walkthrough. Python uses only the standard library.

## Commands

| Command | Purpose |
| --- | --- |
| `backup SOURCE ARCHIVE [--encrypt-cert CERT.pem | --no-encryption] [--[no-]compression] [--[no-]par2] [--max-file-bytes BYTES] [--max-group-bytes BYTES] [--large-file-bytes BYTES] [--waiting-groups COUNT] [--group-close-percent PERCENT]` | Create a backup in an absent/empty directory |
| `verify ARCHIVE [--archive-id ID]` | Check stored bytes and PAR2 capacity without changing the archive |
| `repair ARCHIVE [--archive-id ID]` | Repair archive files in place, without a private key |
| `restore ARCHIVE TARGET [--archive-id ID] [--decrypt-key KEY.pem] [--decrypt-cert CERT.pem] [--scan-index INDEX.json[.zst]]` | Restore into an absent/empty directory; archive remains unchanged |
| `scan ARCHIVE INDEX.json[.zst] [--archive-id ID]` | Build a filename-only recovery index |
| `compare SOURCE TARGET` | Compare paths, types, contents, and supported filesystem metadata |

Compression, encryption, and PAR2 are independent:

| Feature | Enable | Disable | Default |
| --- | --- | --- | --- |
| zstd (payload and metadata) | `--compression` | `--no-compression` | Enabled |
| CMS (payload and source-name inventory) | `--encrypt-cert CERT.pem` | `--no-encryption`, or omit certificate | Disabled |
| PAR2 (data and central metadata) | `--par2` | `--no-par2` | Enabled |

All eight combinations work. Verify, repair, and restore read these choices from
the archive; no matching switches are needed. Only enabled features require their
external executable. Disabling PAR2 retains stored/plaintext checksums, metadata
copies and the checksum chain, but cannot reconstruct damaged payloads. Repair
can still replace a bad metadata copy from its healthy counterpart; it does not
add PAR2 to an archive created without it. Groups, IDs and byte caps remain in use.

Run these through `./poc/archivator`. Backup limits default to **268435455 bytes
per stored file** and **15032385536 bytes per group**. Group sizes include metadata,
PAR2 indexes, recovery volumes, and their packet overhead. The same ceilings
apply to central metadata protection. Supply exact bytes, not media labels; no
filesystem overhead is guessed. See [sizing rules](../POC.md#3-hard-byte-limits).

`--large-file-bytes` routes files at or above the given source size directly to
RAW. Its default is the derived safe input ceiling; a higher value is capped
there. A lower threshold does not change RAW chunk sizes. Smaller files are TAR
candidates, subject to space for complete TAR headers/padding and zstd/CMS overhead.

`--waiting-groups` defaults to **4**, plus one active group; zero disables waiting.
`--group-close-percent` defaults to **95** and accepts 1–100. A group meeting this
threshold closes when the next whole unit does not fit, not immediately upon
reaching the threshold. Waiting groups are tried oldest-first; when slots run
out, the fullest is closed (oldest on a tie). There is no age counter or artificial
zero padding. Full [placement rules](../POC.md#6-group-sizing-and-parity) include
metadata/PAR2 reservations and bounded on-disk buffering of the current RAW file.

Payload names end in `.tar[.zst][.cms]` or `.raw[.zst][.cms]`; source-name metadata
uses `.jsonl[.zst][.cms]`. Only RAW filenames have offsets; both have plaintext lengths.
Each TAR payload is a whole archive, not a fragment. Verification and
PAR2 repair operate on stored ciphertext and require no key. Restore requires
`--decrypt-key` and validates CMS authentication before decompression.

Each command announces major stages and reports its current activity every five
seconds, including while external tools are running. This is a heartbeat, **not
a five-second delay per file**. TAR encoding reports entry and plaintext-byte
counters together; RAW encoding reports plaintext/chunk bytes. Compare reports
cumulative files, bytes, and rate. Routine status never lists source/member names.
Actionable failures, warnings, and comparison differences retain filenames for
diagnosis, so error logs may contain sensitive paths.

### Exit codes

- `0`: success, intact archive, or identical trees.
- `1`: integrity/comparison failure, or restore with an incomplete/unproven catalog.
- `2`: usage or operational failure.

Verify returns 1 for **any** damage, including repairable corruption, missing
metadata copies, or lost parity. Its report distinguishes repairable and
unrecoverable data. It does not prove that a private key works. Restore also
checks plaintext lengths/hashes, complete stream hashes when available, and TAR
member checksums.

## Recovery behavior

Data groups contain whole TARs/RAW files, or a spanning RAW file's range, plus
their own metadata, compressed and PAR2-protected when enabled. Each TAR is exactly
one chunk; a whole RAW file may contain several. A file that cannot fit an empty
group starts fresh and spans groups. Its final group may accept subsequent whole
files/TARs. Groups accumulate actual stored chunk sizes, reserving metadata and
parity. Each group has byte-identical `-spare` metadata copies under `metadata/`, with
separate PAR2 protection there when enabled. The public manifest,
`metadata_index-chunks.json[.zst]`, describes stored chunks; the
`metadata_index-files.jsonl[.zst][.cms]` inventory describes original RAW files and
TAR members and is encrypted when encryption is enabled.
The word **stream** means a TAR's bytes or a direct file's bytes, not a group.

Normal restore uses the complete, protected central catalog. With the central
catalog/markers absent, normal restore can also use standalone local groups.
It restores complete streams, skips detected gaps, and returns 1 because it cannot
prove the original backup is complete. A large file's fragment is independently
repairable, not a complete file. No zero-filled holes or fabricated completion
markers are produced.

If PAR2 cannot repair a whole group, restore still recovers complete streams from
its individually verified surviving chunks. Missing/damaged streams are skipped,
and restore returns 1. Losing one TAR does not discard the group's other TARs.

Verify/restore can recover metadata in private scratch. Healthy inputs are
read-only hardlinks where possible; damaged/unknown inputs are ordinary copies
before PAR2 repair. Unsupported/cross-filesystem hardlinks fall back to copies.
No copy-on-write cloning is used. Neither operation changes archive files.

Explicit repair operates in place. Data and PAR2 files are never copied or
hardlinked into repair staging. Restoring one intentional metadata duplicate
from the other can copy its verified bytes. Scattered inputs are normalized by
same-filesystem renames; an unavailable cross-filesystem rename is not silently
replaced with a copy. Earlier repairs remain if a later group fails.

Discovery supports flat, sharded, nested, and mixed layouts. Each group index has a primary and a byte-identical
`-spare` copy, named before `.json`/`.jsonl` and any transform suffixes. Every
basename is unique even when flattened; duplicate basenames are rejected.
Checksums select usable primary/spare bytes regardless of directory placement. Verify checks all discovered archive IDs by default.
Repair, restore, and scan require `--archive-id` when several archives are present.
Archive-file mtimes and directory order are irrelevant.

Either self-checksummed catalog-root copy anchors the central catalog.
Conflicting valid copies are rejected. Backup cannot resume, and failed work is
not marked complete. A failed restore can leave verified files or partial scratch
output in its destination; retry into a fresh empty directory.

## Filename-only recovery

If even local metadata is unavailable, scan surviving chunk and group-PAR2 names.
This reads no archive contents, hashes, or PAR2 packets and never changes the
archive. The separate index must not already exist. Choose `.json` for an uncompressed
index requiring no zstd executable, or `.json.zst` for a compressed one.

```bash
./poc/archivator scan poc/work/demo/archive1 poc/work/recovery1.json.zst
./poc/archivator restore poc/work/demo/archive1 poc/work/recovered1 \
  --scan-index poc/work/recovery1.json.zst
```

For encrypted data, add `--decrypt-key poc/work/recipient-key.pem` to restore.
The index selects its archive ID; optional `--archive-id` must agree.

Restore tries available PAR2 in scratch, including recovery of filenames missing
when scanned. It checks declared plaintext lengths and any zstd frames or CMS tags present.
Plain chunks without PAR2 have no content integrity check in filename-only recovery.
Streams with detected gaps, overlaps, unreadable chunks, or malformed declared
TARs are skipped entirely. Other streams continue.

| Output | Meaning |
| --- | --- |
| `stream-<id>.raw` | Reconstructed RAW file bytes; original direct-file name unknown |
| `stream-<id>.tar` | Complete TAR bytes, identified by the payload filename |
| `stream-<id>/` | Safely extracted view of that TAR |

RAW streams are not automatically extracted even if their contents are a TAR.
Without authoritative source metadata, missing RAW tail chunks or entire streams may
be undetectable. Exit 0 means no **detected** gaps/decoding failures, not proof of
original completeness. Exit 1 means skipped streams, unresolved PAR2 sets, or no
recoverable stream. Extraction rejects unsafe paths, duplicates, special files,
and hardlinks and uses Python's explicit `data` filter.

## Filesystem conventions

Directories, regular files, symlinks, and empty files are supported. Source
hardlinks become independent files. Ownership, ACLs, xattrs, alternate streams,
and snapshots are outside this PoC. Modes and nanosecond mtimes use ordinary OS
APIs; unsupported symlink metadata or timestamp precision is reported. Directory
attributes are applied last, deepest-first. Compare requires exact POSIX modes
and mtimes; unsupported platforms get explicit precision warnings, not emulation.

Only Linux is integration-tested. Source changes observable through stat checks
abort backup. Source/archive/target overlap and symlink/nonempty destinations are
rejected. Paths may be under `poc/work/`, but must not contain `poc/work/` itself.

## Code and tests

- `backup.py`, `filesystem.py`: directory-local selection, TAR/direct streams, and publication.
- `limits.py`, `format.py`: byte budgets, PAR2 sizing, filenames and settings.
- `external.py`: zstd, CMS and PAR2 subprocesses.
- `metadata.py`, `recovery.py`: metadata copies/checksum chain, validation and repair.
- `restore.py`, `scan.py`, `compare.py`: reconstruction, fallback recovery and comparison.
- `cli.py`, `progress.py`, `common.py`: command handling and shared small helpers.

The [root README](../README.md#automated-tests) has the test command. Tests use real
standard tools, small fixtures, encrypted/plain round trips, hard-limit checks,
metadata loss, standalone groups, and manual recovery without Archivator restore.

Cloud-native checksums, wire encodings, multipart composition and **8 MiB upload
block digests** are not implemented. They remain [mandatory production work](../POC.md#12-mandatory-checksum-requirements-for-a-real-implementation).
