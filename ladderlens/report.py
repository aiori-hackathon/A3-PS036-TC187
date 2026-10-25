"""Build tables, charts, summary.json and report.md for one benchmark run."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from . import analysis, cachemodel, charts, dnssize
from .config import ARM_LABEL


def fmt_time(s) -> str:
    if s is None or (isinstance(s, float) and np.isnan(s)):
        return "n/a"
    if s >= 1:
        return f"{s:,.2f} s"
    if s >= 1e-3:
        return f"{s * 1e3:,.1f} ms"
    return f"{s * 1e6:,.1f} µs"


def fmt_bytes(b) -> str:
    return "n/a" if b is None or (isinstance(b, float) and np.isnan(b)) else f"{b:,.0f} B"


def pct(x: float) -> str:
    return f"{100 * x:.0f}%"


def cache_table(run: Path, man: dict) -> pd.DataFrame:
    rows = []
    for name in sorted(man["outputs"].get("cache", [])):
        s = json.loads((run / "cache" / (name[:-4] + ".summary.json")).read_text())
        kind = "growth" if s["growth_events"] else "ttl"
        exp = cachemodel.expected_misses(s)
        rows.append({
            "kind": kind, "ttl": s["ttl_queries"], "seed": s["seed"], "queries": s["queries"],
            "initial_records": s["initial_records"], "final_records": s["final_records"],
            "hits": s["hits"], "misses": s["misses"], "hit_rate_measured": s["hits"] / s["queries"],
            "misses_analytical": exp, "hit_rate_analytical": 1 - exp / s["queries"],
            "bytes_delivered": s["bytes_delivered"], "bytes_per_query": s["bytes_delivered"] / s["queries"],
            "peak_cache_bytes": s["peak_cache_bytes"], "hits_on_older_ladder": s["hits_on_older_ladder"],
            "compat_fail": s["compat_fail"], "ladder_signs": s["ladder_signs"],
            "verify_per_hit_s": s["verify_hit_ns"] / max(s["hits"], 1) * 1e-9,
            "verify_per_miss_s": s["verify_miss_ns"] / max(s["misses"], 1) * 1e-9,
        })
    return pd.DataFrame(rows)


def build(cfg: dict, run: Path) -> Path:
    run = Path(run)
    df, metas, man = analysis.load_run(run)
    # Report with the configuration the run recorded, never with a config file that may
    # have been edited since (different seed, zone, dataset sizes or DNS limits).
    cfg, drifted = analysis.run_config(man, cfg)
    tables, figs = run / "tables", run / "charts"
    tables.mkdir(exist_ok=True)
    figs.mkdir(exist_ok=True)
    limits = cfg["dns"]["limits"]
    sizes_n = sorted(int(n) for n in df.batch_size.unique())
    nmax = sizes_n[-1]

    sz = analysis.sizes(df)
    totals = analysis.trial_totals(df)
    tsum = analysis.summarise_totals(totals)
    prec = analysis.per_record(df)
    comps = analysis.comparisons(df, totals)
    floor = analysis.noise_floor_ns(metas)
    dns_sizes = dnssize.analyse(cfg, df)
    fit = dnssize.fit(dns_sizes, limits)
    be = analysis.breakeven_bytes(sz)
    curve = analysis.verify_curve(df, nmax, np.unique(np.logspace(0, np.log10(max(nmax, 10) * 10), 60).astype(int)))
    cache = cache_table(run, man)

    for name, frame in (("sizes", sz), ("trial_totals", totals), ("totals_summary", tsum),
                        ("per_record_summary", prec), ("dns_response_sizes", dns_sizes), ("dns_fit", fit),
                        ("breakeven_bytes", be), ("verify_curve", curve), ("cache", cache)):
        frame.to_csv(tables / f"{name}.csv", index=False)

    charts.answer_sizes(sz, limits, figs / "answer_sizes.png")
    charts.response_sizes(dns_sizes, limits, figs / "dns_response_sizes.png")
    charts.signing(tsum, figs / "signing.png")
    charts.verification(curve, tsum, nmax, figs / "verification.png")
    if len(be):
        charts.breakeven(be, figs / "breakeven.png")
    if len(cache) and (cache.kind == "ttl").any():
        charts.cache_hits(cache, figs / "cache_hits.png")

    summary = {
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run": run.name,
        "noise_floor_ns": floor,
        "sizes": sz.to_dict("records"),
        "totals": tsum.to_dict("records"),
        "per_record": prec.to_dict("records"),
        "comparisons": comps,
        "dns_fit": fit.to_dict("records"),
        "breakeven": be.to_dict("records"),
        "cache": cache.to_dict("records"),
    }
    (run / "summary.json").write_text(json.dumps(summary, indent=2, default=float) + "\n")
    text = render(cfg, run, man, metas, sz, tsum, prec, comps, floor, fit, be, cache, limits, drifted)
    (run / "report.md").write_text(text, encoding="utf-8")
    return run / "report.md"


README_START = "<!-- results:start -->"
README_END = "<!-- results:end -->"


def update_readme(run: Path, readme: Path) -> None:
    """Replace the results block in README.md with the summary of `run`."""
    man = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    if man.get("status") != "complete":
        raise SystemExit(f"{run} is '{man.get('status')}', not a complete run; refusing to copy "
                         "partial results into README.md. Fix the failing invocations and run again "
                         "into a new directory.")
    text = readme.read_text(encoding="utf-8")
    if README_START not in text or README_END not in text:
        raise SystemExit(f"{readme} has no results markers")
    report = (run / "report.md").read_text(encoding="utf-8")
    summary = report.split("## Summary\n", 1)[1].split("\n## ", 1)[0].strip()
    rel = run.resolve().relative_to(readme.parent.resolve())
    block = (f"{README_START}\nFrom the final run ([full report]({rel.as_posix()}/report.md), "
             f"[raw data and manifest]({rel.as_posix()}/)):\n\n{summary}\n{README_END}")
    head, rest = text.split(README_START, 1)
    readme.write_text(head + block + rest.split(README_END, 1)[1], encoding="utf-8", newline="\n")


def _get(t: pd.DataFrame, arm: str, n: int, metric: str, field: str = "median"):
    g = t[(t.arm == arm) & (t.n == n) & (t.metric == metric)]
    return (g.iloc[0][field] if field in g.columns else None, g.iloc[0]["tag"]) if len(g) else (None, None)


def headline(sz, tsum, prec, fit, cache, edns_payload: int = 1232) -> list[str]:
    """A few sentences built only from the tables below, each with its tag."""
    out = []
    n = int(sz.n.max())
    mtl_s, mtl_tag = _get(tsum, "mtl", n, "sign_s")
    pl_s, pl_tag = _get(tsum, "plain", n, "sign_s")
    if mtl_s and pl_s:
        out.append(f"Signing {n:,} RRsets took {fmt_time(mtl_s)} as one MTL batch ({mtl_tag}) against "
                   f"{fmt_time(pl_s)} with plain SLH-DSA ({pl_tag}): one SLH-DSA signature instead of {n:,}.")
    pv = _get(prec, "plain", n, "verify_cold_ns")[0]
    mw = _get(prec, "mtl", n, "verify_warm_ns")[0]
    lv = _get(prec, "mtl", n, "ladder_verify_ns")[0]
    if pv and mw and lv:
        out.append(f"With the ladder cached, a resolver verifies an answer in {fmt_time(mw * 1e-9)} against "
                   f"{fmt_time(pv * 1e-9)} for plain SLH-DSA (measured); the ladder itself costs "
                   f"{fmt_time(lv * 1e-9)} to check once.")
    f = fit[fit.n == n].set_index("variant") if len(fit) else None
    if f is not None and {"mtl_warm", "mtl_cold", "plain"} <= set(f.index):
        out.append(f"At N = {n:,}, every condensed answer encodes to at most {fmt_bytes(f.loc['mtl_warm', 'max'])} "
                   f"and fits {edns_payload:,} B; an answer without a cached ladder needs up to "
                   f"{fmt_bytes(f.loc['mtl_cold', 'max'])}, more than plain SLH-DSA "
                   f"({fmt_bytes(f.loc['plain', 'max'])}). The saving depends on ladder reuse (analytical).")
    if len(cache):
        t = cache[(cache.kind == "ttl") & (cache.ttl > 0)]
        if len(t):
            r = t[t.ttl == t.ttl.max()]
            out.append(f"In the resolver replay with a {int(r.ttl.iloc[0]):,}-query ladder lifetime, "
                       f"{r.hit_rate_measured.mean():.2%} of answers were served from the cached ladder at "
                       f"{fmt_bytes(r.bytes_per_query.mean())} of signature per query (measured; model "
                       f"{r.hit_rate_analytical.mean():.2%}).")
    return out


def render(cfg, run, man, metas, sz, tsum, prec, comps, floor, fit, be, cache, limits, drifted=False) -> str:
    m0 = metas[0]
    host = man.get("host", {})
    cpu = host.get("cpu", {})
    plan = man.get("plan", {})
    L = []
    w = L.append

    w(f"# LadderLens results: `{run.name}`\n")
    w("Generated by `make report`. Every number carries one tag: **measured** (read from a harness run), "
      "**extrapolated** (a measured per-record cost scaled to N), **analytical** (computed from measured "
      "inputs with the formula stated next to it) or **spec** (from a specification). "
      "Raw data, the manifest and every table are in this directory.\n")

    w("## Summary\n")
    for line in headline(sz, tsum, prec, fit, cache, cfg["dns"]["edns_payload"]):
        w(f"- {line}")
    w("")

    if man.get("status") == "complete_with_failures":
        w("**This run is not complete.** Some invocations failed, so the measurements below cover "
          "fewer trials than planned. They are reported as partial results, with the missing trials "
          "listed per cell; no value was imputed.\n")

    w("## Configuration\n")
    if drifted:
        w(f"`{cfg.get('_path') or 'the configuration file'}` has changed since this run. Every figure "
          "below uses the configuration recorded in the run's `manifest.json`, not the current file.\n")
    w("| | |\n|---|---|")
    w(f"| Algorithm | `{m0['algorithm']}` (underlying `{m0['oqs_algorithm']}`) |")
    w(f"| MTL reference | {m0['mtl_lib_version']}, commit `{(m0.get('mtl_ref_commit') or 'not recorded')[:12]}`, "
      f"built with `{m0.get('mtl_cflags') or 'not recorded'}` |")
    w(f"| liboqs / OpenSSL | {m0['liboqs_version']} / {m0['openssl_version']} |")
    w(f"| CPU | {cpu.get('model', m0['cpu_model'])}, {cpu.get('logical_cpus', '?')} logical CPUs, "
      f"ISA {', '.join(cpu.get('isa', [])) or 'n/a'} |")
    w(f"| Kernel / pinned image | {m0['kernel']} / {'yes' if host.get('in_pinned_image') else 'no'} |")
    git = man.get("git", {})
    w(f"| Repository commit | `{(git.get('commit') or 'unknown')[:12]}`{' (uncommitted changes)' if git.get('dirty') else ''} |")
    fx = man.get("fixture") or {}
    w(f"| Workload | synthetic zone `{fx.get('origin', '?')}`, seed {fx.get('seed', '?')}, "
      f"RRset signing input {fx.get('message_bytes_min', '?')} to {fx.get('message_bytes_max', '?')} bytes, "
      f"fixture sha256 `{(fx.get('sha256') or '?')[:16]}` |")
    w(f"| Timer | CLOCK_MONOTONIC, noise floor {floor:.0f} ns per read (median) |")
    wall = man.get("wall_seconds")
    budget_min = (man.get("config", {}).get("budget") or {}).get("minutes")
    if wall:
        est = plan.get("estimated_seconds")
        est_note = f" (plan estimated {est / 60:,.0f} min)" if est else ""
        w(f"| Wall clock | {wall / 60:,.1f} min for the whole run{est_note} |")
    w("")
    if wall and budget_min and wall > budget_min * 60:
        w(f"**The run exceeded the {budget_min} min budget** by {(wall - budget_min * 60) / 60:,.1f} min. "
          "The pilot timings that sized the plan were not reproduced under sustained load, so the "
          "planned trial counts took longer than estimated. No trial was dropped, shortened or "
          "imputed: the sample is exactly the one the plan lists. The pilot timings and the estimate "
          "are in `manifest.json` under `plan`; the time of every invocation is in `schedule.csv`.\n")
    if plan.get("cells"):
        w("Trials per cell (from the plan; arms interleaved in shuffled order every round):\n")
        done = tsum[tsum.metric == "sign_s"].set_index(["arm", "n"])["count"].to_dict()
        w("| Arm | N | Trials planned | Trials completed | Records timed per trial |\n|---|---:|---:|---:|---:|")
        for c in plan["cells"]:
            note = " (totals extrapolated)" if c.get("extrapolated") else ""
            got = int(done.get((c["arm"], c["n"]), 0))
            w(f"| {ARM_LABEL[c['arm']]} | {c['n']:,} | {c['trials']} | {got} | {c['records_per_trial']:,}{note} |")
        w("")
        missing = [(c, int(done.get((c["arm"], c["n"]), 0))) for c in plan["cells"]]
        missing = [(c, got) for c, got in missing if got < c["trials"]]
        if missing:
            w("**Fewer trials produced measurements than were planned:** " + "; ".join(
                f"{ARM_LABEL[c['arm']]} N={c['n']:,}: {got} of {c['trials']}" for c, got in missing)
              + ". Every figure below uses the completed trials only; no trial was imputed or "
                "substituted.\n")
    fails = man.get("failures") or []
    if fails:
        w(f"**{len(fails)} harness invocation(s) failed** and were excluded; their partial output is in "
          "`raw/failed/` or `cache/failed/`, and each error is listed in `manifest.json`.\n")

    w("## What \"transmitted bytes\" means here\n")
    w("Three different quantities are easy to confuse, so they are kept apart:\n")
    w("1. **Signature material** (measured): the bytes of the plain signature, condensed signature, full "
      "signature or signed ladder that the reference library produces for an answer.")
    w("2. **Encoded DNS response** (analytical): the size of a complete DNS response carrying that "
      "signature, built and encoded locally with dnspython.")
    w("3. **Network traffic**: not measured. No server, resolver or network path is involved (PS-036 "
      "scope), so UDP/IP headers, fragmentation and TCP fallback are outside these figures.\n")

    w("## Signature size per answer (measured)\n")
    w("| N | A plain | B MTL N=1 (full) | C condensed min / median / max | C signed ladder | C full (max) |")
    w("|---:|---:|---:|---:|---:|---:|")
    for r in sz.itertuples():
        cond = (f"{fmt_bytes(r.mtl_condensed_min)} / {fmt_bytes(r.mtl_condensed_median)} / "
                f"{fmt_bytes(r.mtl_condensed_max)}") if r.mtl_condensed_max else "n/a"
        w(f"| {r.n:,} | {fmt_bytes(r.plain_signature)} | {fmt_bytes(r.mtl1_full_signature)} | {cond} | "
          f"{fmt_bytes(r.mtl_signed_ladder)} | {fmt_bytes(r.mtl_full_signature_max)} |")
    w("\n![Signature size per answer](charts/answer_sizes.png)\n")

    w("## DNS response size (analytical: exact encoding of a constructed response)\n")
    w("Question, answer RRset, one RRSIG and an EDNS(0) OPT record with DO set, encoded by dnspython. "
      "MTL signatures carry the one-octet MTL-Type prefix of draft-fregly-dnsop-slh-dsa-mtl-dnssec-06.\n")
    head = " | ".join(f"≤ {l:,} B" for l in limits)
    w(f"| N | Format | Median | Max | {head} |")
    w("|---:|---|---:|---:|" + "---:|" * len(limits))
    for r in fit.itertuples():
        cells = " | ".join(pct(getattr(r, f"fits_{l}")) for l in limits)
        w(f"| {r.n:,} | {dnssize.VARIANTS[r.variant]} | {fmt_bytes(r.median)} | {fmt_bytes(r.max)} | {cells} |")
    w("\n![DNS response sizes](charts/dns_response_sizes.png)\n")

    w("## Signing time\n")
    w("Batch signing time covers every record in the dataset; key generation is reported separately. "
      "Medians over trials, with a bootstrap 95% CI where a cell has at least 20 trials.\n")
    w("| Arm | N | Trials | Batch signing (median) | 95% CI | Per record | Key generation | Tag |")
    w("|---|---:|---:|---:|---:|---:|---:|---|")
    for arm in ("plain", "mtl1", "mtl"):
        for n in sorted(tsum.n.unique()):
            g = tsum[(tsum.arm == arm) & (tsum.n == n)]
            if not len(g):
                continue
            s = g[g.metric == "sign_s"].iloc[0]
            per = g[g.metric == "sign_per_record_s"].iloc[0]["median"]
            kg = g[g.metric == "keygen_s"].iloc[0]["median"]
            ci = f"{fmt_time(s['ci95_low'])} to {fmt_time(s['ci95_high'])}" if not pd.isna(s.get("ci95_low", np.nan)) else "n < 20"
            w(f"| {ARM_LABEL[arm]} | {n:,} | {int(s['count'])} | {fmt_time(s['median'])} | {ci} | {fmt_time(per)} | "
              f"{fmt_time(kg)} | {s['tag']} |")
    w("\n![Signing cost per record](charts/signing.png)\n")

    w("## Verification time (measured)\n")
    w("Single-operation latencies, verified on a context rebuilt from the public key only.\n")
    w("| N | A plain verify | C cold (full signature) | C ladder check (once per batch) | C warm (per record) | "
      "Warm p99 | Samples A / C warm |")
    w("|---:|---:|---:|---:|---:|---:|---:|")
    for n in sorted(prec.n.unique()):
        pv = _get(prec, "plain", n, "verify_cold_ns")[0]
        mc = _get(prec, "mtl", n, "verify_cold_ns")[0]
        mw, _ = _get(prec, "mtl", n, "verify_warm_ns")
        p99 = _get(prec, "mtl", n, "verify_warm_ns", "p99")[0]
        lv = _get(prec, "mtl", n, "ladder_verify_ns")[0]
        lvn = lv * 1e-9 if lv else None
        na = _get(prec, "plain", n, "verify_cold_ns", "count")[0]
        nc = _get(prec, "mtl", n, "verify_warm_ns", "count")[0]
        counts = f"{int(na or 0):,} / {int(nc or 0):,}"
        w(f"| {n:,} | {fmt_time(pv * 1e-9 if pv else None)} | {fmt_time(mc * 1e-9 if mc else None)} | "
          f"{fmt_time(lvn)} | {fmt_time(mw * 1e-9 if mw else None)} | {fmt_time(p99 * 1e-9 if p99 else None)} | {counts} |")
    w("\n![Cold vs warm verification](charts/verification.png)\n")

    if comps:
        w("## Statistical comparisons\n")
        w("Two-sided Mann-Whitney U on per-trial values (one value per trial), because records inside a trial "
          "are not independent. A p-value needs at least three trials per side.\n")
        w("| N | Comparison | Median A | Median B | n A / n B | p-value |")
        w("|---:|---|---:|---:|---:|---:|")
        for c in comps:
            fmt = (lambda v: fmt_time(v * 1e-9)) if c["unit"] == "ns" else fmt_time
            p = "n/a" if c.get("p_value") is None else f"{c['p_value']:.2g}"
            note = f" ({c['note']})" if c.get("note") else ""
            w(f"| {c['n']:,} | {c['what']}{note} | {fmt(c['median_a'])} | {fmt(c['median_b'])} | "
              f"{c['n_a']} / {c['n_b']} | {p} |")
        w("")

    if len(be):
        w("## Byte break-even (analytical)\n")
        w("Signature bytes for k answers under one ladder. MTL pays a condensed response plus a full re-query "
          "for the first answer, then one condensed signature per answer: `L + (k+1)·p`; plain pays `k·s`. "
          "Break-even `k* = (L + p) / (s − p)`, with s, L and p measured.\n")
        w("| N | s (plain) | L (signed ladder) | p (median condensed) | Break-even answers |")
        w("|---:|---:|---:|---:|---:|")
        for r in be.itertuples():
            w(f"| {r.n:,} | {fmt_bytes(r.plain_signature)} | {fmt_bytes(r.ladder)} | {fmt_bytes(r.condensed_median)} | "
              f"{r.break_even_answers:.2f} |")
        w("\n![Break-even](charts/breakeven.png)\n")

    if len(cache):
        w("## Cache usage: measured replay vs analytical model\n")
        w("One resolver replays a Zipf query stream against the reference library and caches the latest "
          "verified signed ladder. Retrieval follows the draft: condensed first, full re-query on a miss. "
          "Measured columns come from the replay; the analytical column is the model in "
          "`ladderlens/cachemodel.py`.\n")
        w("| Run | Queries | Records | Misses measured (mean) | Misses analytical | Hit rate measured | "
          "Signature bytes per query | Peak cache | Older-ladder hits | Compat failures |")
        w("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        keyed = sorted(cache.groupby(["kind", "ttl"]), key=lambda kv: (kv[0][0] == "growth", kv[0][1] == 0, kv[0][1]))
        for key, g in keyed:
            kind, ttl = key
            label = ("growth, no expiry" if kind == "growth" else
                     ("no expiry" if ttl == 0 else f"TTL {ttl:,} queries"))
            recs = f"{int(g.initial_records.iloc[0]):,} to {int(g.final_records.iloc[0]):,}" if kind == "growth" \
                else f"{int(g.initial_records.iloc[0]):,}"
            w(f"| {label} | {int(g.queries.iloc[0]):,} | {recs} | {g.misses.mean():.1f} | "
              f"{g.misses_analytical.mean():.1f} | {g.hit_rate_measured.mean():.4f} | "
              f"{fmt_bytes(g.bytes_per_query.mean())} | {fmt_bytes(g.peak_cache_bytes.max())} | "
              f"{int(g.hits_on_older_ladder.sum())} | {int(g.compat_fail.sum())} |")
        s = sz.plain_signature.dropna()
        if len(s):
            w(f"\nFor reference, plain SLH-DSA delivers {fmt_bytes(s.iloc[0])} per query on the same stream "
              "(analytical: one signature per answer). The resolver's cache usage is the stored signed ladder "
              "(peak cache column); older-ladder hits are answers whose new authentication path verified "
              "against a ladder cached before the zone grew.\n")
        if (cache.kind == "ttl").any():
            w("![Cache hit rate](charts/cache_hits.png)\n")

    w("## Notes\n")
    w(f"- Per-operation figures below {10 * floor:.0f} ns (ten timer reads) would be within timer noise; "
      "check the per-record tables before quoting very small values.")
    fa = prec[(prec.metric == "first_append_ns")]
    if len(fa):
        w(f"- The first append on a new MTL tree includes one-time allocation (median "
          f"{fmt_time(fa['median'].median() * 1e-9)}). It is part of every batch total and is why "
          "per-record figures are reported as medians.")
    if (tsum.tag == "extrapolated").any():
        w("- Rows tagged extrapolated time a subset of K records per trial and scale the total by N/K. "
          "Per-record cost in arms A and B does not depend on N, so the scaling is linear by construction.")
    w("- Arm B needs a new key per record because the MTL public API cannot reset a tree; its key "
      "generation time is reported separately and never included in signing time.")
    w("- Responses in the DNS section are constructed and encoded, not captured from a server; "
      "no resolver or network is involved (PS-036 scope).")
    w("")
    return "\n".join(L) + "\n"
