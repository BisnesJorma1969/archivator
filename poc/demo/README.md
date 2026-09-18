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
| `--percent` | `1` | Percentage of blocks selected in each pool |
| `--seed` | `20260918` | Repeatable damage selection for the same intact archives |
| `--damage` | `mixed` | `mixed`, `bitflip`, `zero`, `copy`, `delete`, or `insert` |
| `--dry-run` | Off | Write the damage plan without modifying archives |
| `--report` | Timestamped JSON under `poc/work/demo/` | Must be outside archives and not already exist |
| `--include-bootstrap` | Off | Also damage the unprotected completion marker; automatic recovery may fail |

### Damage model

`mixed` randomly chooses a fault for each selected original region:

- `bitflip`: change one random bit.
- `zero`: overwrite a run of 512-byte sectors, either contiguous or every second
  or fourth sector. A final partial sector is allowed.
- `copy`: overwrite a sector-sized run with real bytes from another position in
  the same archive file or another file in that archive.
- `delete`: remove bytes and shift the remainder left. This can shorten a file
  internally or truncate its tail, not just remove an entire file.
- `insert`: insert copied archive bytes and shift the remainder right, making
  the file oversized. The insertion need not be at the beginning or end.

Copy sources always refer to the intact pre-damage files. A zero/copy operation
that would leave bytes unchanged is recorded as a bit flip instead. The generator
models 512-byte sectors; it does not detect the physical storage's sector size.

Selection is separate for each data set's data and PAR2 pools, plus each archive's
protected metadata and metadata-PAR2 pools. A pool's selected count is
`ceil(block_count * percent / 100)`. Consequently every nonempty pool receives at
least one fault for a positive percentage, so even small metadata sets are tested.
Small pools can have actual percentages much higher than requested; the report
shows both block counts and actual percentages. Zero percent does nothing.

Regions start at each original file's offset zero, using the set's recorded PAR2
slice size (normally 1 MiB); the final short region counts too. Each selected
region receives one fault, with sector runs bounded to that original region.
Insertions and deletions shift later bytes, so selected-region percentages are
not exact lost-block percentages. PAR2 must locate surviving content after shifts.
For PAR2 files these are physical byte windows, not packet boundaries: one fault
can invalidate multiple packets. Recovery depends on each set's remaining capacity,
not the archive-wide average.

Protected catalogs, manifests, inventories, and the checksum index are eligible
metadata. `complete.json` is the **unprotected bootstrap** and is preserved by
default. Add `--include-bootstrap` to test its damage as well; automatic recovery
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
