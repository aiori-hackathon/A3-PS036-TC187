"""LadderLens dashboard: an interactive view of one benchmark run.

    pip install -r requirements-dashboard.txt
    streamlit run dashboard/app.py -- results/final

Reads only files written by `make report`; computes nothing that is not already
in the run directory except the explorer curves, which are labelled analytical.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]


def pick_run() -> Path | None:
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    if args:
        return Path(args[0])
    candidates = [ROOT / "results" / "final"] + sorted((ROOT / "results" / "runs").glob("*"), reverse=True)
    return next((c for c in candidates if (c / "summary.json").exists()), None)


st.set_page_config(page_title="LadderLens", layout="wide")
run = pick_run()
if run is None or not (run / "summary.json").exists():
    st.title("LadderLens")
    st.info("No report found. Run `make bench` and `make report`, then start the dashboard again.")
    st.stop()

summary = json.loads((run / "summary.json").read_text())
tables = run / "tables"
sizes = pd.DataFrame(summary["sizes"])
fit = pd.DataFrame(summary["dns_fit"])
totals = pd.DataFrame(summary["totals"])
cache = pd.DataFrame(summary["cache"])

st.title("LadderLens")
st.caption(f"Run `{run.name}` · generated {summary['generated_utc']} · "
           "tags: measured, extrapolated, analytical, spec")

tab_sizes, tab_time, tab_explore, tab_cache = st.tabs(
    ["Sizes and UDP fit", "Timing", "Break-even explorer", "Resolver cache"])

with tab_sizes:
    st.subheader("Signature bytes per answer (measured)")
    st.dataframe(sizes, hide_index=True, width="stretch")
    st.subheader("Encoded DNS responses (analytical)")
    limit = st.select_slider("UDP payload limit (bytes)", options=[512, 1232, 1400, 1472], value=1232)
    view = fit[["n", "variant", "median", "max", f"fits_{limit}"]].rename(columns={f"fits_{limit}": "share that fits"})
    st.dataframe(view, hide_index=True, width="stretch")
    if (run / "charts" / "dns_response_sizes.png").exists():
        st.image(str(run / "charts" / "dns_response_sizes.png"))

with tab_time:
    st.subheader("Batch totals over trials")
    metric = st.selectbox("Metric", ["sign_s", "sign_per_record_s", "verify_cold_s", "verify_warm_s", "keygen_s"])
    cols = [c for c in ("arm", "n", "tag", "count", "median", "iqr", "p95", "ci95_low", "ci95_high") if c in totals]
    st.dataframe(totals[totals.metric == metric][cols], hide_index=True, width="stretch")
    for name in ("signing.png", "verification.png"):
        if (run / "charts" / name).exists():
            st.image(str(run / "charts" / name))

with tab_explore:
    st.subheader("Bytes for k answers under one ladder (analytical, measured inputs)")
    be = pd.DataFrame(summary["breakeven"])
    if be.empty:
        st.info("Break-even needs plain and MTL results in the same run.")
    else:
        n = st.selectbox("Dataset size N", be.n.tolist(), index=len(be) - 1)
        row = be[be.n == n].iloc[0]
        kmax = st.slider("Answers served under one ladder (k)", 2, 200, 20)
        requery = st.checkbox("First answer includes the condensed attempt and full re-query (draft 6.2)", True)
        k = np.arange(1, kmax + 1)
        L, p, s = row.ladder, row.condensed_median, row.plain_signature
        mtl = L + (k + (1 if requery else 0)) * p
        chart = pd.DataFrame({"k": k, "plain SLH-DSA": k * s, f"MTL N={n}": mtl}).set_index("k")
        st.line_chart(chart, y_label="cumulative signature bytes")
        kstar = (L + (p if requery else 0)) / (s - p)
        st.metric("Break-even answers", f"{kstar:.2f}")
        st.caption(f"s = {s:,.0f} B, L = {L:,.0f} B, p = {p:,.0f} B (median condensed), all measured.")

with tab_cache:
    st.subheader("Ladder cache: measured replay vs analytical model")
    if cache.empty:
        st.info("No cache replays in this run.")
    else:
        st.dataframe(cache[["kind", "ttl", "seed", "queries", "misses", "misses_analytical",
                            "hit_rate_measured", "hit_rate_analytical", "bytes_per_query", "peak_cache_bytes",
                            "hits_on_older_ladder", "compat_fail"]], hide_index=True, width="stretch")
        if (run / "charts" / "cache_hits.png").exists():
            st.image(str(run / "charts" / "cache_hits.png"))
