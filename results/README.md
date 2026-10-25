# Benchmark results

`results/final/` is the retained benchmark run. Its manifest records 216/216 successful harness invocations, 15/15 completed cache replays, 9,812.4 seconds elapsed, exact dependency commits, package versions, CPU and host details. The performance data were collected in the native WSL2 replica (`in_pinned_image: false`). The pinned Docker image was subsequently built and checked separately on the student's Windows host; it did not rerun these performance measurements.

The student reports mentor approval for dataset sizes 10/100/1,000, separated reporting of measured signature material and locally encoded DNS response lengths (network traffic is not captured), and the labeled N=1,000 extrapolations. Plain SLH-DSA and MTL batch-one N=1,000 totals scale samples of 100 records per trial; full-batch MTL processes all 1,000 records. See `docs/PS036-COMPLIANCE.md` and `docs/FINAL-AUDIT-2026-10-25.md` for the evidence mapping and final handoff checklist.

Every run writes to a new, empty directory. `make bench` refuses a non-empty path. Reports read only files listed in the run manifest and verify their SHA-256 hashes. Interrupted runs in `results/runs/` remain incomplete and are not reportable.

A run directory contains:

| Path | Contents |
|---|---|
| `manifest.json` | Configuration, plan, source revision if available, CPU, kernel, package versions, binary and fixture hashes, output hashes |
| `schedule.csv` | Order, start time and duration of every harness invocation |
| `raw/*.csv`, `raw/*.meta.json` | One row per (trial, record) from `harness/bench`, with per-invocation metadata |
| `cache/*.csv`, `cache/*.summary.json` | Per-query log and totals from each resolver cache replay |
| `tables/*.csv` | Every table in the report |
| `charts/*.png` | Report figures |
| `summary.json` | Machine-readable version of the report |
| `report.md` | Full benchmark report |

To run a new benchmark, use a fresh output directory and the pinned environment:

```sh
make plan
make bench RUN=results/new-run
make report RUN=results/new-run
make readme RUN=results/new-run
```
