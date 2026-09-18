# Synthetic recovery demo

The [root README](../../README.md) contains the Ubuntu 26.04 setup and complete
three-source backup/damage/restore/compare workflow. Both scripts use Python's
standard library; generation also uses the mandatory `zstd` executable for sample
compression ratios. Sources, reports, and scratch belong under ignored `poc/work/`.

## Workload generation

```bash
python3 poc/demo/generate.py
```

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

Smaller run (use the same backup/restore loop with `demo-small` paths):

```bash
python3 poc/demo/generate.py --root poc/work/demo-small \
    --office-files 1000 --log-files 5000 --sql-mib 1024 --seed 42
```

Larger run:

```bash
python3 poc/demo/generate.py --root poc/work/demo-large \
    --office-files 20000 --log-files 200000 --sql-mib 6144
```

## Controlled bitrot

```bash
python3 poc/demo/bitrot.py poc/work/demo/archive1 poc/work/demo/archive2 \
    poc/work/demo/archive3 --percent 1 --seed 42 --dry-run \
    --report poc/work/preview.json
```

Omit `--dry-run` to apply damage. With no directory arguments the script selects
`poc/work/demo/archive1`, `archive2`, and `archive3`. Reports must be outside the
archives and must not already exist; the default report gets a unique timestamp.

Selection is separate for each data set's data and PAR2 pools, plus each archive's
protected metadata and metadata-PAR2 pools. A pool's selected count is
`ceil(block_count * percent / 100)`. Consequently every nonempty pool receives at
least one flip for a positive percentage, so even small metadata sets are tested.
Small pools can have actual percentages much higher than requested; the report
shows both block counts and actual percentages. Zero percent does nothing.

Blocks start at each file's offset zero, using the set's recorded PAR2 slice size
(normally 1 MiB); the final short block counts too. Exactly one random bit is
flipped per selected block. For PAR2 files these are physical byte windows, not
PAR2 packet boundaries: one damaged window can invalidate multiple packets.
Recovery depends on each set's remaining capacity, not the archive-wide average.

Protected catalogs, manifests, inventories, and the checksum index are eligible
metadata. `complete.json` is the **unprotected bootstrap** and is preserved by
default. Add `--include-bootstrap` to test its damage as well; automatic recovery
may then fail even with surviving PAR2 data. High percentages can also exhaust
recovery capacity. See [manual recovery](../FORMAT.md).

All input archives are checked before any flips. Already damaged archives are
refused; repair or recreate them before another run. This prevents the same seed
from toggling old damage away. Reports record filenames, block numbers, offsets,
and old/new bytes. A report is saved with status `planned` before mutation and
marked `applied` only after completion; interruption can leave partial damage.
Sources are never changed. Keep archives otherwise idle while running the demo.
