"""Aggregation of raw harness output into the tables used by the report.

Tags used throughout:
  measured      read directly from a harness run
  extrapolated  a total scaled up from a sampled subset of records (N / K)
  analytical    computed from measured inputs with a stated formula
  spec          taken from a specification, not measured
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from . import harness, manifest
from .stats import describe, mann_whitney

NS = 1e-9


class RunIntegrityError(RuntimeError):
    """A run directory is incomplete or holds files the run did not record."""


def validate_run(run: Path) -> dict:
    """Return the manifest of a finished run whose files are exactly those it recorded.

    The report never globs a directory blindly: a file that the run did not list in
    manifest.json (for example left over from an earlier run) is an error, and so is
    a listed file that is missing.
    """
    man_path = run / "manifest.json"
    if not man_path.exists():
        raise RunIntegrityError(f"{run} has no manifest.json; it is not a LadderLens run directory")
    man = json.loads(man_path.read_text())
    status = man.get("status")
    if status not in ("complete", "complete_with_failures") or "outputs" not in man:
        raise RunIntegrityError(f"{run} is not a finished run (status: {man.get('status', 'unknown')}); "
                                "it cannot be reported on. Runs are not resumed; start a new run in a "
                                "new directory.")
    hashes = man["outputs"].get("sha256")
    if not hashes:
        raise RunIntegrityError(f"{run} records no file hashes (made by an older LadderLens). Re-run into a new "
                                "directory to report on it.")
    for kind, sidecar in (("raw", ".meta.json"), ("cache", ".summary.json")):
        listed = set()
        for name in man["outputs"].get(kind, []):
            listed |= {name, name[:-4] + sidecar}
        found = {p.name for p in (run / kind).iterdir() if p.is_file()} if (run / kind).is_dir() else set()
        extra, missing = sorted(found - listed), sorted(listed - found)
        if extra:
            raise RunIntegrityError(f"{run / kind} holds files this run did not produce: {', '.join(extra[:5])}"
                                    f"{' ...' if len(extra) > 5 else ''}. Refusing to mix runs.")
        if missing:
            raise RunIntegrityError(f"{run / kind} is missing files the run recorded: {', '.join(missing[:5])}")
        for name in sorted(listed):
            key = f"{kind}/{name}"
            if key not in hashes:
                raise RunIntegrityError(f"{key} has no recorded hash in manifest.json")
            if manifest.sha256(run / kind / name) != hashes[key]:
                raise RunIntegrityError(f"{key} does not match the hash recorded when the run produced it; "
                                        "it was modified or replaced. Refusing to report on it.")
    # schedule.csv records order, start time and outcome of every invocation. It is part
    # of the evidence behind the report, so a run that does not list a hashed schedule is
    # not reportable: its trial counts and ordering could not be checked at all.
    if not man["outputs"].get("schedule"):
        raise RunIntegrityError(f"{run} records no schedule.csv in manifest.json; the order, timing "
                                "and outcome of its invocations cannot be checked. Refusing to report on it.")
    for name in man["outputs"].get("schedule") or []:
        key = f"schedule/{name}"
        if not (run / name).exists():
            raise RunIntegrityError(f"{run / name} is missing; the run recorded it in manifest.json")
        if key not in hashes:
            raise RunIntegrityError(f"{key} has no recorded hash in manifest.json")
        if manifest.sha256(run / name) != hashes[key]:
            raise RunIntegrityError(f"{key} does not match the hash recorded when the run produced it; "
                                    "it was modified or replaced. Refusing to report on it.")
    return man


def run_config(man: dict, current: dict) -> tuple[dict, bool]:
    """The configuration a run was produced with, and whether `current` differs from it.

    A run's measurements belong to the configuration recorded in its manifest. Reporting
    with today's configuration file would silently attach a different seed, zone or set
    of DNS limits to older numbers.
    """
    recorded = man.get("config")
    if not recorded:
        return current, False
    return {**recorded, "_path": man.get("config_path")}, \
        {k: v for k, v in current.items() if not k.startswith("_")} != recorded


def load_run(run: Path) -> tuple[pd.DataFrame, list[dict], dict]:
    man = validate_run(run)
    paths = [run / "raw" / name for name in sorted(man["outputs"]["raw"])]
    if not paths:
        raise RunIntegrityError(f"{run} has no successful benchmark output")
    df = harness.read_bench(paths)
    metas = [harness.read_meta(p) for p in paths]
    return df, metas, man


def noise_floor_ns(metas: list[dict]) -> float:
    return float(np.median([m["timer_overhead_ns"] for m in metas]))


def sizes(df: pd.DataFrame) -> pd.DataFrame:
    """Signature bytes per answer, by dataset size. All measured."""
    rows = []
    for n, g in df.groupby("batch_size"):
        m = g[g.arm == "mtl"]
        p = g[g.arm == "plain"]
        b = g[g.arm == "mtl1"]
        rows.append({
            "n": int(n),
            "plain_signature": _one(p.signature_bytes),
            "mtl1_full_signature": _one(b.signature_bytes),
            "mtl_condensed_min": _agg(m.condensed_bytes, "min"),
            "mtl_condensed_median": _agg(m.condensed_bytes, "median"),
            "mtl_condensed_max": _agg(m.condensed_bytes, "max"),
            "mtl_signed_ladder": _one(m.signed_ladder_bytes),
            "mtl_full_signature_max": _agg(m.signature_bytes, "max"),
            "public_key": _one(g.public_key_bytes),
        })
    return pd.DataFrame(rows)


def _one(s: pd.Series):
    s = s.dropna()
    return int(s.iloc[0]) if len(s) else None


def _agg(s: pd.Series, how: str):
    s = s.dropna()
    return float(getattr(s, how)()) if len(s) else None


def trial_totals(df: pd.DataFrame) -> pd.DataFrame:
    """Cost of signing / verifying all N records in one trial.

    Sampled cells (K < N records processed) are scaled by N / K and flagged as
    extrapolated; per-record signing cost does not depend on N in arms A and B.
    """
    rows = []
    for (arm, n, trial), g in df.groupby(["arm", "batch_size", "trial"]):
        k = int(g.processed.iloc[0])
        scale = n / k
        first = g.iloc[0]
        rows.append({
            "arm": arm, "n": int(n), "trial": int(trial), "records_measured": k,
            "extrapolated": k < n,
            "sign_s": (g.sign_ns.sum() * scale + (first.ladder_sign_ns if arm == "mtl" else 0)) * NS,
            "keygen_s": first.keygen_ns * (scale if arm == "mtl1" else 1) * NS,
            "verify_cold_s": g.verify_cold_ns.sum() * scale * NS,
            "verify_warm_s": (first.ladder_verify_ns + g.verify_warm_ns.sum()) * NS if arm == "mtl" else np.nan,
        })
    t = pd.DataFrame(rows)
    t["sign_per_record_s"] = t.sign_s / t.n
    return t


def summarise_totals(t: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for (arm, n), g in t.groupby(["arm", "n"]):
        for metric in ("sign_s", "sign_per_record_s", "keygen_s", "verify_cold_s", "verify_warm_s"):
            d = describe(g[metric])
            if d["count"]:
                rows.append({"arm": arm, "n": n, "metric": metric,
                             "tag": "extrapolated" if g.extrapolated.any() else "measured", **d})
    return pd.DataFrame(rows)


def per_record(df: pd.DataFrame) -> pd.DataFrame:
    """Distribution of single-operation latencies (one value per record per trial)."""
    rows = []
    for (arm, n), g in df.groupby(["arm", "batch_size"]):
        for metric in ("sign_ns", "verify_cold_ns", "verify_warm_ns"):
            d = describe(g[metric])
            if d["count"]:
                rows.append({"arm": arm, "n": int(n), "metric": metric, "tag": "measured", **d})
        if arm == "mtl":
            per_trial = g.drop_duplicates("trial")
            for metric in ("ladder_sign_ns", "ladder_verify_ns"):
                rows.append({"arm": arm, "n": int(n), "metric": metric, "tag": "measured",
                             **describe(per_trial[metric])})
            rows.append({"arm": arm, "n": int(n), "metric": "first_append_ns", "tag": "measured",
                         **describe(g[g.record_index == 0].sign_ns)})
    return pd.DataFrame(rows)


def _trial_medians(d: pd.DataFrame, arm: str, column: str) -> pd.Series:
    """One value per trial: the median of `column` over that trial's records."""
    return d[d.arm == arm].groupby("trial")[column].median()


def comparisons(df: pd.DataFrame, t: pd.DataFrame) -> list[dict]:
    """Mann-Whitney U tests for the headline differences, per dataset size.

    The unit of comparison is the trial: records inside one trial share a key and
    a moment on the machine, so they are not independent observations. Each
    verification test therefore compares per-trial medians, and the signing test
    compares per-trial batch totals.
    """
    out = []
    for n in sorted(df.batch_size.unique()):
        d = df[df.batch_size == n]
        plain_v = _trial_medians(d, "plain", "verify_cold_ns")
        if len(plain_v) and (d.arm == "mtl").any():
            for label, column in (("MTL warm", "verify_warm_ns"), ("MTL cold", "verify_cold_ns")):
                other = _trial_medians(d, "mtl", column)
                out.append({"n": int(n), "what": f"verify time per answer: plain vs {label} (per-trial medians)",
                            **mann_whitney(plain_v, other),
                            "median_a": float(plain_v.median()), "median_b": float(other.median()), "unit": "ns"})
        tn = t[t.n == n]
        a, b = tn[tn.arm == "plain"].sign_s, tn[tn.arm == "mtl"].sign_s
        if len(a) and len(b):
            out.append({"n": int(n), "what": "batch signing time: plain vs MTL",
                        **mann_whitney(a, b), "median_a": float(a.median()), "median_b": float(b.median()),
                        "unit": "s", "note": "plain total extrapolated" if tn[tn.arm == "plain"].extrapolated.any() else ""})
    return out


def medians(df: pd.DataFrame, n: int) -> dict:
    """Median single-operation costs (seconds) at one dataset size."""
    d = df[df.batch_size == n]
    p, m = d[d.arm == "plain"], d[d.arm == "mtl"]
    return {
        "plain_sign": p.sign_ns.median() * NS if len(p) else np.nan,
        "plain_verify": p.verify_cold_ns.median() * NS if len(p) else np.nan,
        "mtl_ladder_sign": m.ladder_sign_ns.median() * NS if len(m) else np.nan,
        "mtl_append": m.sign_ns.median() * NS if len(m) else np.nan,
        "mtl_cold": m.verify_cold_ns.median() * NS if len(m) else np.nan,
        "mtl_ladder_verify": m.ladder_verify_ns.median() * NS if len(m) else np.nan,
        "mtl_warm": m.verify_warm_ns.median() * NS if len(m) else np.nan,
    }


def breakeven_bytes(sz: pd.DataFrame) -> pd.DataFrame:
    """Signature bytes for k answers served under one ladder (analytical, measured inputs).

    MTL, following the draft's retrieval rule: the first answer costs a condensed
    response plus a full re-query (p + p + L); each later answer costs p.
        mtl(k)   = L + (k + 1) * p
        plain(k) = k * s
    Break-even k* = (L + p) / (s - p).
    """
    rows = []
    for r in sz.itertuples():
        s, L, p = r.plain_signature, r.mtl_signed_ladder, r.mtl_condensed_median
        if not (s and L and p):
            continue
        rows.append({"n": r.n, "plain_signature": s, "ladder": L, "condensed_median": p,
                     "break_even_answers": (L + p) / (s - p)})
    return pd.DataFrame(rows)


def verify_curve(df: pd.DataFrame, n: int, ks) -> pd.DataFrame:
    """Time to verify k answers covered by one ladder (analytical, measured medians)."""
    m = medians(df, n)
    ks = np.asarray(ks, dtype=float)
    return pd.DataFrame({
        "k": ks,
        "plain": ks * m["plain_verify"],
        "mtl_cold": ks * m["mtl_cold"],
        "mtl_warm": m["mtl_ladder_verify"] + ks * m["mtl_warm"],
    })
