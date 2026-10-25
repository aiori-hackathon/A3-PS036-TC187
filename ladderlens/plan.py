"""Pilot measurement and trial planning.

`plan` times a handful of real operations, then decides how many trials each
(arm, dataset size) cell gets so the full benchmark fits the configured time
budget. Nothing is benchmarked for the record here; the pilot only sizes the run.
"""
from __future__ import annotations

import hashlib
import json
import math
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import config, fixtures, harness


def config_digest(cfg: dict) -> str:
    """SHA-256 of the configuration a plan was made with.

    `make bench` refuses a plan made under a different configuration: the run would
    otherwise benchmark cells (sizes, arms, sample counts) that the recorded
    configuration does not describe, and the manifest would carry both without
    either being wrong on its own.
    """
    body = {k: v for k, v in cfg.items() if not k.startswith("_")}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()


def pilot(cfg: dict) -> dict:
    """Per-operation costs in seconds, from one short run of each arm."""
    rec = config.fixture_path(cfg)
    alg = cfg["workload"]["algorithm"]
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        p = harness.bench("plain", 2, tmp / "plain.csv", records=rec, algorithm=alg)
        m = harness.bench("mtl", 10, tmp / "mtl.csv", records=rec, algorithm=alg)
        dp, dm = harness.read_bench([p]), harness.read_bench([m])
        wall_p = harness.read_meta(p)["wall_time_ns"]
        wall_m = harness.read_meta(m)["wall_time_ns"]
    s = 1e-9
    plain_work = dp.keygen_ns.iloc[0] + dp.sign_ns.sum() + dp.verify_cold_ns.sum()
    mtl_work = (dm.keygen_ns.iloc[0] + dm.ladder_sign_ns.iloc[0] + dm.sign_ns.sum()
                + dm.verify_cold_ns.sum() + dm.ladder_verify_ns.iloc[0] + dm.verify_warm_ns.sum())
    t = {
        "keygen": dp.keygen_ns.median() * s,
        "sign": dp.sign_ns.median() * s,
        "verify": dp.verify_cold_ns.median() * s,
        "mtl_keygen": dm.keygen_ns.iloc[0] * s,
        "ladder_sign": dm.ladder_sign_ns.iloc[0] * s,
        "append": dm.sign_ns.median() * s,
        "verify_cold": dm.verify_cold_ns.median() * s,
        "ladder_verify": dm.ladder_verify_ns.iloc[0] * s,
        "verify_warm": dm.verify_warm_ns.median() * s,
        "process_overhead": max(wall_p - plain_work, wall_m - mtl_work) * s,
    }
    return {k: float(v) for k, v in t.items()}


def trial_seconds(arm: str, n: int, k: int, t: dict) -> float:
    if arm == "plain":
        return t["keygen"] + k * (t["sign"] + t["verify"]) + t["process_overhead"]
    if arm == "mtl1":
        return k * (t["mtl_keygen"] + t["sign"] + t["verify"]) + t["process_overhead"]
    return (t["mtl_keygen"] + t["ladder_sign"] + n * (t["append"] + t["verify_cold"] + t["verify_warm"])
            + t["ladder_verify"] + t["process_overhead"])


def cache_seconds(cfg: dict, t: dict) -> float:
    c = cfg.get("cache")
    if not c:
        return 0.0
    per_query = 2 * t["verify_warm"] + 2 * t["append"]
    base = t["mtl_keygen"] + t["ladder_sign"] + c["initial"] * t["append"] + c["queries"] * per_query
    runs = len(c["seeds"]) * len(c["ttls"])
    misses = sum(math.ceil(c["queries"] / ttl) if ttl else 1 for ttl in c["ttls"]) * len(c["seeds"])
    events = (c["queries"] - 1) // c["growth_every"] if c.get("growth_every") else 0
    growth = len(c["seeds"]) * (base + events * (t["ladder_sign"] + 2 * t["verify_cold"])) if events else 0
    return runs * base + misses * t["verify_cold"] + growth


def make_plan(cfg: dict, timings: dict) -> dict:
    sizes = cfg["workload"]["sizes"]
    arms = cfg["arms"]["enabled"]
    tmax, tmin = cfg["trials"]["max"], cfg["trials"]["min"]
    b = cfg["budget"]
    budget = b["minutes"] * 60 - cache_seconds(cfg, timings)

    cells = []
    for arm in arms:
        for n in sizes:
            k = n if arm == "mtl" else min(n, b["max_records_per_trial"])
            cells.append({"arm": arm, "n": n, "records_per_trial": k, "trials": tmax})

    def cost(c):
        return trial_seconds(c["arm"], c["n"], c["records_per_trial"], timings)

    def total():
        return sum(cost(c) * c["trials"] for c in cells)

    per_record = [c for c in cells if c["arm"] != "mtl"]
    if total() > budget and per_record:
        fixed = sum(cost(c) * c["trials"] for c in cells if c["arm"] == "mtl")
        scale = max(0.0, (budget - fixed) / sum(cost(c) * tmax for c in per_record))
        for c in per_record:
            c["trials"] = max(tmin, min(tmax, math.floor(tmax * scale)))
    # Still over budget at the minimum trial count: shrink the sample, largest cells first.
    for c in sorted(per_record, key=cost, reverse=True):
        while total() > budget and c["records_per_trial"] > b["min_records_per_trial"]:
            c["records_per_trial"] = max(b["min_records_per_trial"], c["records_per_trial"] // 2)

    for c in cells:
        c["extrapolated"] = c["records_per_trial"] < c["n"]
        c["seconds_per_trial"] = round(cost(c), 3)
        c["seconds"] = round(cost(c) * c["trials"], 1)
    est = total() + cache_seconds(cfg, timings)
    return {
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "config_path": cfg.get("_path"),
        "config_sha256": config_digest(cfg),
        "pilot_seconds": {k: round(v, 6) for k, v in timings.items()},
        "budget_seconds": b["minutes"] * 60,
        "estimated_seconds": round(est, 1),
        "cache_seconds": round(cache_seconds(cfg, timings), 1),
        "within_budget": bool(est <= b["minutes"] * 60),
        "cells": cells,
    }


def main(cfg: dict, out: Path) -> dict:
    fixtures.ensure(cfg)
    plan = make_plan(cfg, pilot(cfg))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(plan, indent=2) + "\n")
    p = plan["pilot_seconds"]
    print(f"pilot: SLH-DSA sign {p['sign']:.3f} s, verify {p['verify'] * 1e3:.2f} ms, "
          f"MTL append {p['append'] * 1e6:.1f} us, warm verify {p['verify_warm'] * 1e6:.1f} us")
    print(f"{'arm':6} {'N':>6} {'records':>8} {'trials':>7} {'est. s':>9}")
    for c in plan["cells"]:
        mark = "  (extrapolated)" if c["extrapolated"] else ""
        print(f"{c['arm']:6} {c['n']:>6} {c['records_per_trial']:>8} {c['trials']:>7} {c['seconds']:>9.0f}{mark}")
    verdict = "within" if plan["within_budget"] else "OVER"
    print(f"cache runs ~{plan['cache_seconds']:.0f} s; total ~{plan['estimated_seconds'] / 60:.0f} min "
          f"({verdict} the {plan['budget_seconds'] // 60} min budget). Plan written to {out}")
    return plan
