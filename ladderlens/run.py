"""Execute a plan: interleaved benchmark rounds, then the cache replays."""
from __future__ import annotations

import csv
import json
import random
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config, fixtures, harness, manifest
from .plan import config_digest


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


class RunDirectoryError(RuntimeError):
    """The requested run directory already holds files."""


def _prepare(out: Path) -> None:
    """Create a fresh run directory. Never write into one that already has content:
    runs are not resumed or merged, so earlier measurements cannot mix with new ones."""
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise RunDirectoryError(
            f"refusing to write into {out}: it already contains files. Runs are never resumed or "
            f"merged. Choose a new directory (for example RUN=results/runs/<name>), or move the old "
            f"run away first.")
    (out / "raw").mkdir(parents=True, exist_ok=True)
    (out / "cache").mkdir(parents=True, exist_ok=True)


def _record(produced: dict, kind: str, csv_path: Path, sidecar: str) -> None:
    """Record a finished invocation: its CSV and sidecar file names and their SHA-256."""
    produced[kind].append(csv_path.name)
    for f in (csv_path, Path(str(csv_path)[:-4] + sidecar)):
        produced["sha256"][f"{kind}/{f.name}"] = manifest.sha256(f)


def _quarantine(path: Path, failed_dir: Path) -> None:
    """Move a failed invocation's partial output out of raw/ so analysis never reads it."""
    failed_dir.mkdir(exist_ok=True)
    for f in (path, path.with_suffix(".meta.json"), Path(str(path)[:-4] + ".summary.json")):
        if f.exists():
            shutil.move(str(f), failed_dir / f.name)


def main(cfg: dict, plan_path: Path, out: Path | None) -> tuple[Path, list[dict]]:
    """Run the plan. A failed invocation is recorded and skipped; the run continues.

    Returns the run directory and the list of failures (empty when all succeeded).
    """
    if not plan_path.exists():
        raise SystemExit(f"{plan_path} not found; run `make plan` and review it first")
    plan = json.loads(plan_path.read_text())
    if plan.get("config_sha256") != config_digest(cfg):
        raise SystemExit(
            f"{plan_path} was made with a different configuration (or before plans recorded one). "
            "Its cells would not match configs/benchmark.toml — dataset sizes, arms or sample counts "
            "could silently differ from what the run manifest says was configured. Run `make plan` "
            "again and review it.")
    fmeta = fixtures.ensure(cfg)
    records = config.fixture_path(cfg)
    w = cfg["workload"]
    out = out or config.RESULTS / "runs" / _stamp()
    _prepare(out)

    man = manifest.collect(cfg, fmeta)
    man["run_id"] = uuid.uuid4().hex
    man["status"] = "running"
    man["plan"] = plan
    (out / "manifest.json").write_text(json.dumps(man, indent=2) + "\n")

    # Interleaving: in round r every cell that still needs a trial runs once, in a
    # freshly shuffled order, so slow drift on the machine is spread across arms.
    rng = random.Random(w["seed"])
    rounds = max(c["trials"] for c in plan["cells"])
    schedule, failures = [], []
    produced = {"raw": [], "cache": [], "sha256": {}}
    started = time.time()
    done, total = 0, sum(c["trials"] for c in plan["cells"])
    for r in range(1, rounds + 1):
        cells = [c for c in plan["cells"] if c["trials"] >= r]
        rng.shuffle(cells)
        for pos, c in enumerate(cells, 1):
            t0 = time.time()
            path = out / "raw" / f"{c['arm']}_n{c['n']}_t{r:03d}.csv"
            status, error = "ok", ""
            try:
                harness.bench(c["arm"], c["n"], path, records=records, sample=c["records_per_trial"],
                              trial_base=r, seed=w["seed"], algorithm=w["algorithm"])
                _record(produced, "raw", path, ".meta.json")
            except harness.HarnessError as err:
                status, error = "failed", str(err).splitlines()[-1][:300]
                _quarantine(path, out / "raw" / "failed")
                failures.append({"kind": "bench", "arm": c["arm"], "n": c["n"], "trial": r, "error": str(err)})
            dt = time.time() - t0
            done += 1
            schedule.append({"round": r, "position": pos, "arm": c["arm"], "n": c["n"],
                             "start_utc": datetime.fromtimestamp(t0, timezone.utc).isoformat(timespec="seconds"),
                             "seconds": round(dt, 3), "status": status, "error": error})
            eta = (time.time() - started) / done * (total - done)
            flag = "" if status == "ok" else "  FAILED (recorded, continuing)"
            print(f"[{done}/{total}] round {r} {c['arm']:5} N={c['n']:<5} {dt:7.1f} s  eta {eta / 60:5.1f} min{flag}",
                  flush=True)

    schedule_path = out / "schedule.csv"
    with open(schedule_path, "w", newline="") as f:
        wr = csv.DictWriter(f, fieldnames=list(schedule[0]))
        wr.writeheader()
        wr.writerows(schedule)
    produced["schedule"] = [schedule_path.name]
    produced["sha256"][f"schedule/{schedule_path.name}"] = manifest.sha256(schedule_path)

    cache_planned = cache_done = 0
    c = cfg.get("cache")
    if c:
        jobs = []
        for seed in c["seeds"]:
            for ttl in c["ttls"]:
                jobs.append((f"ttl{ttl}_s{seed}", dict(ttl=ttl, seed=seed)))
            if c.get("growth_every"):
                jobs.append((f"growth_s{seed}", dict(ttl=0, seed=seed, growth_every=c["growth_every"],
                                                     growth_size=c["growth_size"])))
        cache_planned = len(jobs)
        for name, kw in jobs:
            path = out / "cache" / f"{name}.csv"
            try:
                harness.cachesim(path, records=records, initial=c["initial"], queries=c["queries"],
                                 zipf=c["zipf"], algorithm=w["algorithm"], **kw)
                _record(produced, "cache", path, ".summary.json")
                cache_done += 1
            except harness.HarnessError as err:
                _quarantine(path, out / "cache" / "failed")
                failures.append({"kind": "cachesim", "name": name, "error": str(err)})
                print(f"cache replay {name} FAILED (recorded, continuing)", flush=True)
        print(f"cache replays done ({len(jobs)} runs)", flush=True)

    man["finished_utc"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    man["wall_seconds"] = round(time.time() - started, 1)
    man["failures"] = failures
    man["outputs"] = produced
    # Reconcile what the plan asked for with what actually produced measurements.
    bench_ok = sum(1 for s in schedule if s["status"] == "ok")
    man["trials"] = {"planned": total, "attempted": len(schedule), "completed": bench_ok,
                     "failed": len(schedule) - bench_ok}
    man["cache_runs"] = {"planned": cache_planned, "completed": cache_done}
    # A run with failed invocations is reportable but never "complete": it must not be
    # presentable as a full experiment (see analysis.validate_run and report.update_readme).
    man["status"] = "complete" if not failures else "complete_with_failures"
    (out / "manifest.json").write_text(json.dumps(man, indent=2) + "\n")
    if failures:
        print(f"run finished with {len(failures)} failed invocation(s): {bench_ok}/{total} trials and "
              f"{cache_done}/{cache_planned} cache replays produced measurements. Details in "
              f"{out / 'manifest.json'}")
    else:
        print(f"run complete: {out} ({bench_ok}/{total} trials, {cache_done}/{cache_planned} cache replays)")
    return out, failures
