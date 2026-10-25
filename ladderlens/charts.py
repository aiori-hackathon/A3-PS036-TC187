"""Report figures. One function per chart; each writes a PNG and returns its path."""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

INK = "#1f2933"
MUTED = "#7b8794"
COLORS = {"plain": "#c2410c", "mtl1": "#a16207", "mtl": "#0f766e", "mtl_warm": "#0f766e",
          "mtl_cold": "#5b8a87", "analytical": "#6d28d9"}
LIMIT_STYLE = dict(color=MUTED, linestyle="--", linewidth=0.9)

plt.rcParams.update({
    "font.size": 10, "axes.edgecolor": MUTED, "axes.labelcolor": INK, "xtick.color": INK,
    "ytick.color": INK, "axes.spines.top": False, "axes.spines.right": False,
    "axes.titleweight": "semibold", "axes.titlesize": 11, "figure.dpi": 150,
})


def _save(fig, path: Path) -> Path:
    fig.tight_layout()
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)
    return path


def answer_sizes(sz: pd.DataFrame, limits, path: Path) -> Path:
    """Signature bytes carried per answer, against UDP payload limits."""
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    labels, vals, cols = [], [], []
    plain = sz.plain_signature.dropna()
    if len(plain):
        labels.append("A  plain SLH-DSA"); vals.append(plain.iloc[0]); cols.append(COLORS["plain"])
    for r in sz.itertuples():
        if r.mtl_full_signature_max:
            labels.append(f"C  MTL full, N={r.n}"); vals.append(r.mtl_full_signature_max); cols.append(COLORS["mtl_cold"])
    for r in sz.itertuples():
        if r.mtl_condensed_max:
            labels.append(f"C  MTL condensed, N={r.n}"); vals.append(r.mtl_condensed_max); cols.append(COLORS["mtl"])
    y = np.arange(len(labels))[::-1]
    ax.barh(y, vals, color=cols, height=0.62)
    for yi, v in zip(y, vals):
        ax.text(v + 60, yi, f"{v:,.0f} B", va="center", fontsize=8.5, color=INK)
    for lim in limits:
        ax.axvline(lim, **LIMIT_STYLE)
    ax.text(0.99, 0.02, "dashed: UDP payload limits " + ", ".join(f"{l:,}" for l in sorted(limits)) + " B",
            transform=ax.transAxes, ha="right", va="bottom", fontsize=7.5, color=MUTED)
    ax.set_yticks(y, labels)
    ax.set_xlabel("signature bytes per answer (largest record)")
    ax.set_title("Signature size per answer vs UDP payload limits")
    ax.set_xlim(0, max(vals) * 1.15)
    return _save(fig, path)


def response_sizes(dns_sizes: pd.DataFrame, limits, path: Path) -> Path:
    """Median encoded response per format, with the min-max range as a bar."""
    variants = [v for v in ("plain", "mtl1", "mtl_cold", "mtl_warm") if v in set(dns_sizes.variant)]
    names = {"plain": "A plain", "mtl1": "B MTL N=1", "mtl_cold": "C full", "mtl_warm": "C condensed"}
    ns = sorted(dns_sizes.n.unique())
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    width = 0.8 / len(variants)
    for j, v in enumerate(variants):
        xs, med, lo, hi = [], [], [], []
        for i, n in enumerate(ns):
            g = dns_sizes[(dns_sizes.n == n) & (dns_sizes.variant == v)].response_bytes
            if len(g):
                xs.append(i - 0.4 + width * (j + 0.5))
                med.append(g.median()); lo.append(g.median() - g.min()); hi.append(g.max() - g.median())
        ax.errorbar(xs, med, yerr=[lo, hi], fmt="o", ms=5, capsize=3, color=COLORS[v], label=names[v])
    for lim in limits:
        ax.axhline(lim, **LIMIT_STYLE)
    ax.text(0.99, 0.62, "dashed: UDP payload limits " + ", ".join(f"{l:,}" for l in sorted(limits)) + " B",
            transform=ax.transAxes, ha="right", va="center", fontsize=7.5, color=MUTED)
    ax.set_yscale("log")
    ax.set_ylim(150, 14000)
    ax.set_xticks(range(len(ns)), [f"N={n:,}" for n in ns])
    ax.set_ylabel("DNS response bytes (log)")
    ax.set_title("Encoded DNS response size by signature format (median, min to max)")
    ax.legend(fontsize=8, frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.12))
    return _save(fig, path)


def signing(summary: pd.DataFrame, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    s = summary[summary.metric == "sign_per_record_s"]
    styles = {"plain": ("-", "o"), "mtl1": ("--", "s"), "mtl": ("-", "o")}
    for arm, label in (("plain", "A plain"), ("mtl1", "B MTL N=1"), ("mtl", "C MTL batch")):
        g = s[s.arm == arm].sort_values("n")
        if not len(g):
            continue
        ls, mk = styles[arm]
        ax.plot(g.n, g["median"] * 1e3, linestyle=ls, color=COLORS[arm], label=label)
        for r in g.itertuples():
            hollow = r.tag == "extrapolated"
            ax.scatter([r.n], [r.median * 1e3], marker=mk, s=30, zorder=3, color=COLORS[arm],
                       facecolors="white" if hollow else COLORS[arm])
    ax.scatter([], [], marker="o", facecolors="white", color=MUTED, label="hollow: extrapolated total")
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("dataset size N (records)")
    ax.set_ylabel("signing time per record (ms, median)")
    ax.set_title("Amortised signing cost per record")
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, path)


def verification(curve: pd.DataFrame, measured: pd.DataFrame, n: int, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    ax.plot(curve.k, curve.plain * 1e3, color=COLORS["plain"], label="A plain (k signatures)")
    ax.plot(curve.k, curve.mtl_cold * 1e3, color=COLORS["mtl_cold"], linestyle="--",
            label="C cold (full signature each time)")
    ax.plot(curve.k, curve.mtl_warm * 1e3, color=COLORS["mtl"], label="C warm (ladder once, then paths)")
    m = measured[(measured.n == n)]
    for arm, col, metric in (("mtl", COLORS["mtl"], "verify_warm_s"), ("plain", COLORS["plain"], "verify_cold_s")):
        g = m[(m.arm == arm) & (m.metric == metric)]
        if len(g) and g.iloc[0].tag == "measured":
            ax.scatter([n], [g.iloc[0]["median"] * 1e3], color=col, zorder=3, s=22)
    ax.set_xscale("log"); ax.set_yscale("log")
    ax.set_xlabel("answers verified from one batch (k)")
    ax.set_ylabel("total verification time (ms)")
    ax.set_title(f"Cold vs warm verification (lines analytical; dots measured, k = N = {n})", fontsize=10)
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, path)


def breakeven(be: pd.DataFrame, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    k = np.arange(1, 11)
    s = be.plain_signature.iloc[0]
    ax.plot(k, k * s / 1e3, color=COLORS["plain"], marker="o", ms=3, label="A plain: k · s")
    shades = ["#99d5cf", "#2fa39a", "#0f766e", "#0b4f4a"]
    for i, r in enumerate(be.itertuples()):
        ax.plot(k, (r.ladder + (k + 1) * r.condensed_median) / 1e3, marker="o", ms=3,
                color=shades[i % len(shades)], label=f"C MTL, N={r.n}: L + (k+1) · p")
    ax.set_xlabel("answers served under one cached ladder (k)")
    ax.set_ylabel("cumulative signature bytes (thousands)")
    ax.set_title("Byte break-even (analytical, measured L and p)")
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, path)


def cache_hits(cache: pd.DataFrame, path: Path) -> Path:
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    t = cache[cache.kind == "ttl"].copy()
    t["ttl_label"] = t.ttl.map(lambda v: "none" if v == 0 else f"{v:,}")
    order = sorted(t.ttl.unique(), key=lambda v: (v == 0, v))
    labels = ["none" if v == 0 else f"{v:,}" for v in order]
    xs = np.arange(len(order))
    meas = [t[t.ttl == v].hit_rate_measured.mean() for v in order]
    anal = [t[t.ttl == v].hit_rate_analytical.mean() for v in order]
    ax.bar(xs - 0.18, meas, width=0.36, color=COLORS["mtl"], label="measured (replay)")
    ax.bar(xs + 0.18, anal, width=0.36, color=COLORS["analytical"], alpha=0.7, label="analytical")
    lo = min(meas + anal)
    ax.set_ylim(max(0, lo - 0.02), 1.0005)
    ax.set_xticks(xs, labels)
    ax.set_xlabel("ladder cache lifetime (queries)")
    ax.set_ylabel("ladder cache hit rate")
    ax.set_title("Resolver ladder cache: measured vs analytical")
    ax.legend(frameon=False, fontsize=8)
    return _save(fig, path)
