# Demo options and workload reference

Follow the [Ubuntu 26.04 install instructions](../../README.md#install) first.
The [root README](../../README.md) contains the runnable backup/damage/restore/compare workflow. Both scripts use Python's
standard library; generation also uses the mandatory `zstd` executable for sample
compression ratios. Sources, reports, and scratch belong under ignored `poc/work/`.

## Workload generation

Defaults: seed `20260918`, 12,000 office-like files, 3 GiB of SQL-like backups,
and 60,000 text logs. Output goes to `poc/work/demo/source1`, `source2`, `source3`.
`generation.json` records parameters, counts, sizes, office size quantiles, and
sample zstd level-3 compression ratios. Existing nonempty output directories are
refused.

Office filenames include departments, projects, dates, and document versions.
Sizes follow bounded lognormal distributions; these are illustrative workload
assumptions, not measured office-population statistics:

| Extension | Share | Median size | Size bounds | Random-byte fraction |
| --- | --- | --- | --- | --- |
| `.docx` | 30% | 64 KiB | 4–4,096 KiB | 65–95% |
| `.xlsx` | 20% | 96 KiB | 8–8,192 KiB | 55–90% |
| `.pdf` | 25% | 180 KiB | 8–12,288 KiB | 65–98% |
| `.pptx` | 10% | 512 KiB | 32–16,384 KiB | 70–98% |
| `.csv` | 8% | 64 KiB | 1–2,048 KiB | Structured text |
| `.txt` | 7% | 16 KiB | 1–512 KiB | Repeated text |

The three `.bak` files receive 75% of the SQL byte budget; nine `.trn` files
receive 25%. Sizes vary within each group. Payloads mix 35–65% fresh random bytes
with repeated record-like bytes. Default `.bak` files exceed the PoC's 256 MiB
direct-file threshold and span multiple chunks.

Logs have service/host/date paths and repeated log lines. Their lognormal sizes
have a 2 KiB median and are bounded to 256 bytes–64 KiB. All source3 files are
`.txt`; repetitive payloads are intentionally very compressible.

**Office and SQL files are synthetic, not application-readable documents or
restorable database backups.** Random bytes are freshly generated, not a repeated
random buffer; no sparse files are used. Generation streams bounded buffers.
Seeds and fixed filesystem timestamps make workloads repeatable with the same
settings and Python version. Compression ratios are approximate, not guarantees.

### Generator options

Options for `poc/demo/generate.py`:

| Option | Default | Meaning |
| --- | --- | --- |
| `--root` | `poc/work/demo` | Absent or empty output directory |
| `--office-files` | `12000` | Number of source1 files |
| `--log-files` | `60000` | Number of source3 files |
| `--sql-mib` | `3072` | Total source2 payload size in MiB |
| `--seed` | `20260918` | Repeatable workload seed |

Change the counts and SQL size for smaller or larger workloads. A custom root
also changes the paths to use in the main workflow.

## Bitrot options

Options for `poc/demo/bitrot.py`:

| Argument / option | Default | Meaning |
| --- | --- | --- |
| Archive directories | `poc/work/demo/archive1`, `archive2`, `archive3` | Explicit paths select only those archives |
| `--percent` | `1` | Percentage of each backup's total stored bytes to damage |
| `--seed` | `20260918` | Repeatable damage selection for the same intact archives |
| `--damage` | `mixed` | `mixed`, `bitflip`, `zero`, `copy`, `delete`, or `insert` |
| `--dry-run` | Off | Write the damage plan without modifying archives |
| `--report` | Timestamped JSON under `poc/work/demo/` | Must be outside archives and not already exist |
| `--include-bootstrap` | Off | Also damage the unprotected completion marker; automatic recovery may fail |

### Damage model

The byte budget is `round(original_backup_bytes * percent / 100)`, calculated
separately for each archive ID before damage. It includes stored data, metadata,
and PAR2 files. For example, 2% of a 100 GiB backup means 2 GiB subjected to faults.
Zero percent does nothing. There are no per-file or per-recovery-set quotas.

Files are selected with probability proportional to their remaining eligible
bytes. Each chosen file gets a random fault style in `mixed` mode. Fault locations
and lengths are random, from isolated bytes through runs up to 4 MiB; ranges do
not overlap in the original files. Larger files are more likely to be hit. Small
metadata files are eligible but are not guaranteed to be selected on every run.

- `bitflip`: flip one bit in each selected byte. A one-byte fault changes one bit;
  longer ranges model bursts of bit errors.
- `zero`: overwrite selected runs with zero bytes.
- `copy`: overwrite with real bytes from another position in the same file or
  another file in that archive.
- `delete`: remove bytes and shift the remainder left, including internal
  deletion and tail truncation.
- `insert`: insert copied archive bytes and shift the remainder right, including
  internal insertion rather than only appending to the file.

The budget counts bytes overwritten, bit-flipped, deleted, or inserted. Insertion
and deletion count the bytes added/removed, not the entire shifted remainder.
Overwrites can happen to preserve individual byte values; a wholly unchanged
zero/copy run falls back to bit flips across that same budget. Copy sources always
refer to the intact pre-damage files.

The report gives the original backup size, requested and applied byte budgets,
actual percentage, files affected, and each fault's type, original offset, length,
and copy source. Faults are not aligned to PAR2 slices. A random distribution can
exhaust one recovery set even when the archive-wide percentage is small; verify
reports whether the particular damage is recoverable.

Protected catalogs, manifests, inventories, and the checksum index are eligible
metadata. `complete.json` is the **unprotected bootstrap** and is preserved by
default. If the requested budget exceeds eligible bytes, it is capped and the
actual percentage is reported. Add `--include-bootstrap` to test its damage as well; automatic recovery
may then fail even with surviving PAR2 data. High percentages can also exhaust
recovery capacity. See [manual recovery](../FORMAT.md).

All input archives are checked before any changes. Already damaged archives are
refused; repair or recreate them before another run. This prevents the same seed
from toggling old damage away. Reports record fault types, original offsets and
lengths, region hashes, copy sources, and bit-flip values. Changed files are staged
beside their originals before replacement, requiring temporary free space up to
the total size of affected files plus inserted bytes. A report is saved with status
`planned` before mutation and marked `applied` only after completion; interruption
can leave partial damage and `.bitrot-*` staging files. Sources are never changed.
Keep archives otherwise idle while running the demo.
