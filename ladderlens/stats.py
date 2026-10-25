"""Descriptive statistics and tests used in the report."""
from __future__ import annotations

import numpy as np
from scipy import stats as sps

BOOTSTRAP_MIN_N = 20
BOOTSTRAP_RESAMPLES = 2000


def describe(values, seed: int = 0) -> dict:
    """Median-centred summary. A bootstrap 95% CI of the median is given only when
    there are at least 20 observations; below that it would not be meaningful."""
    x = np.asarray(values, dtype=float)
    x = x[~np.isnan(x)]
    n = int(x.size)
    if n == 0:
        return {"count": 0}
    q1, med, q3, p95, p99 = np.percentile(x, [25, 50, 75, 95, 99])
    out = {
        "count": n,
        "median": float(med),
        "iqr": float(q3 - q1),
        "p95": float(p95),
        "p99": float(p99),
        "mean": float(x.mean()),
        "min": float(x.min()),
        "max": float(x.max()),
    }
    if n >= BOOTSTRAP_MIN_N:
        rng = np.random.default_rng(seed)
        chunk = max(1, min(BOOTSTRAP_RESAMPLES, 4_000_000 // n))
        meds = np.concatenate([
            np.median(rng.choice(x, size=(min(chunk, BOOTSTRAP_RESAMPLES - i), n), replace=True), axis=1)
            for i in range(0, BOOTSTRAP_RESAMPLES, chunk)
        ])
        out["ci95_low"], out["ci95_high"] = (float(v) for v in np.percentile(meds, [2.5, 97.5]))
    return out


def mann_whitney(a, b) -> dict:
    """Two-sided Mann-Whitney U on two independent samples."""
    a = np.asarray(a, dtype=float)
    b = np.asarray(b, dtype=float)
    a, b = a[~np.isnan(a)], b[~np.isnan(b)]
    if a.size < 3 or b.size < 3:
        return {"n_a": int(a.size), "n_b": int(b.size), "p_value": None}
    res = sps.mannwhitneyu(a, b, alternative="two-sided")
    return {"n_a": int(a.size), "n_b": int(b.size), "u": float(res.statistic), "p_value": float(res.pvalue)}
