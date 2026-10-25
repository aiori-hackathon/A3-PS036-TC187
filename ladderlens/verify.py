"""`make verify`: correctness and determinism checks for the pinned environment.

Timings are never checked here (they vary by machine). Sizes are deterministic
for a given algorithm and MTL version, so they are checked exactly.
"""
from __future__ import annotations

import json
import math
import tempfile
from pathlib import Path

import pandas as pd

from . import config, dnssize, fixtures, harness
from .analysis import sizes as size_table

COLUMNS = ["trial", "arm", "batch_size", "processed", "record_index", "record_len", "seed", "algorithm",
           "keygen_count", "keygen_ns", "sign_ns", "ladder_sign_ns", "verify_cold_ns", "ladder_verify_ns",
           "verify_warm_ns", "signature_bytes", "condensed_bytes", "signed_ladder_bytes", "public_key_bytes"]

_failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"  {'ok  ' if ok else 'FAIL'}  {label}{(': ' + detail) if detail else ''}")
    if not ok:
        _failures.append(label)


def condensed_max(n: int, sec: int = 16) -> int:
    """Maximum condensed signature size, draft-harvey-cfrg-mtl-mode-09 section 12."""
    return 28 + 3 * sec + sec * math.floor(math.log2(n))


def main(cfg: dict) -> int:
    expected = json.loads((config.ROOT / "tests" / "expected_sizes.json").read_text())
    alg = cfg["workload"]["algorithm"]
    config.RESULTS.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="verify-", dir=config.RESULTS))
    print(f"verification artifacts: {work.relative_to(config.ROOT).as_posix()}")
    fixtures.ensure(cfg)
    rec = config.fixture_path(cfg)

    print("cryptographic self-test (harness/selftest.c)")
    rc, lines = harness.selftest(alg)
    cases = [ln for ln in lines if ln.startswith(("ok ", "FAIL "))]
    for ln in cases:
        status, _, label = ln.partition(" ")
        check(label.strip(), status == "ok")
    check("self-test ran every case and exited cleanly", rc == 0 and len(cases) > 0, f"{len(cases)} cases")

    print("harness output")
    runs = {
        "mtl_1": harness.bench("mtl", 1, work / "mtl_n1.csv", records=rec, algorithm=alg),
        "mtl_10": harness.bench("mtl", 10, work / "mtl_n10.csv", records=rec, algorithm=alg),
        "mtl_100": harness.bench("mtl", 100, work / "mtl_n100.csv", records=rec, algorithm=alg),
        "mtl_1000": harness.bench("mtl", 1000, work / "mtl_n1000.csv", records=rec, algorithm=alg),
        "plain_2": harness.bench("plain", 2, work / "plain_n2.csv", records=rec, algorithm=alg),
        "mtl1_2": harness.bench("mtl1", 2, work / "mtl1_n2.csv", records=rec, algorithm=alg),
        "sample": harness.bench("plain", 10, work / "plain_n10_k2.csv", records=rec, sample=2, algorithm=alg),
    }
    frames = {k: pd.read_csv(v, comment="#") for k, v in runs.items()}
    for k, d in frames.items():
        check(f"{k}: CSV parses with the documented 19 columns", list(d.columns) == COLUMNS)
    check("sampled run times K=2 of N=10 records", len(frames["sample"]) == 2
          and set(frames["sample"].processed) == {2})

    print("signature sizes (exact)")
    sz = size_table(pd.concat(frames.values(), ignore_index=True)).set_index("n")
    e = expected["sizes"]
    check("plain SLH-DSA signature", sz.loc[2, "plain_signature"] == e["plain_signature"],
          f"{int(sz.loc[2, 'plain_signature'])} B")
    check("public key", sz.loc[2, "public_key"] == e["public_key"], f"{int(sz.loc[2, 'public_key'])} B")
    check("MTL batch-of-one full signature", sz.loc[2, "mtl1_full_signature"] == e["mtl"]["1"]["full_max"],
          f"{int(sz.loc[2, 'mtl1_full_signature'])} B")
    for n in (1, 10, 100, 1000):
        exp = e["mtl"][str(n)]
        row = sz.loc[n]
        got = (row.mtl_signed_ladder, row.mtl_condensed_min, row.mtl_condensed_max, row.mtl_full_signature_max)
        want = (exp["ladder"], exp["condensed_min"], exp["condensed_max"], exp["full_max"])
        check(f"MTL N={n}: ladder, condensed min/max, full max", tuple(int(x) for x in got) == tuple(want),
              f"{tuple(int(x) for x in got)}")
        check(f"MTL N={n}: condensed max equals draft section 12 bound", int(row.mtl_condensed_max) == condensed_max(n),
              f"bound {condensed_max(n)} B")

    print("verification paths")
    m = frames["mtl_10"]
    check("every record verified cold and warm", m.verify_cold_ns.notna().all() and m.verify_warm_ns.notna().all())
    check("warm path skips the per-record SLH-DSA check", m.verify_warm_ns.median() < m.verify_cold_ns.median() / 10)
    check("arms A and B report no warm path", frames["plain_2"].verify_warm_ns.isna().all()
          and frames["mtl1_2"].verify_warm_ns.isna().all())

    print("cache replay")
    t = harness.cachesim(work / "cache_ttl.csv", records=rec, initial=64, queries=600, zipf=1.0, ttl=100,
                         seed=7, algorithm=alg)
    s = harness.read_cache_summary(t)
    check("TTL 100 over 600 queries gives exactly 6 misses", s["misses"] == 6, f"{s['misses']}")
    check("hits + misses = queries", s["hits"] + s["misses"] == s["queries"])
    g = harness.cachesim(work / "cache_growth.csv", records=rec, initial=64, queries=600, zipf=1.0, ttl=0,
                         growth_every=100, growth_size=8, seed=7, algorithm=alg)
    s = harness.read_cache_summary(g)
    check("append-only growth: no backward-compatibility failures", s["compat_fail"] == 0,
          f"{s['hits_on_older_ladder']} answers verified on an older ladder")

    print("DNS encoding")
    import dns.dnssec
    import dns.name
    import dns.rdataclass
    import dns.rdatatype
    from dns.rdtypes.ANY.RRSIG import RRSIG

    zone = dns.name.from_text(cfg["workload"]["origin"])
    recs = fixtures.generate(200, cfg["workload"]["seed"], cfg["workload"]["origin"])
    same = 0
    for r in recs:
        rr = r.rrset
        tmpl = RRSIG(dns.rdataclass.IN, dns.rdatatype.RRSIG, rr.rdtype, fixtures.PLACEHOLDER_ALGORITHM,
                     len(rr.name) - 1, rr.ttl, fixtures.EXPIRATION, fixtures.INCEPTION, fixtures.KEY_TAG, zone, b"")
        same += dns.dnssec._make_rrsig_signature_data(rr, tmpl) == r.message
    check("fixture signing input matches dnspython's DNSSEC encoding", same == len(recs), f"{same}/{len(recs)} RRsets")
    plain = dnssize.response_bytes(recs[0].rrset, zone, e["plain_signature"], 1232)
    warm = dnssize.response_bytes(recs[0].rrset, zone, 1 + e["mtl"]["1"]["condensed_max"], 1232)
    check("plain response exceeds 1,232 B; condensed response fits", plain > 1232 and warm <= 1232,
          f"{plain:,} B vs {warm:,} B")

    final = config.RESULTS / "final" / "summary.json"
    if final.exists():
        print("committed final results")
        fs = {r["n"]: r for r in json.loads(final.read_text())["sizes"]}
        for n, exp in e["mtl"].items():
            if int(n) in fs and fs[int(n)].get("mtl_signed_ladder"):
                check(f"results/final N={n} ladder matches", fs[int(n)]["mtl_signed_ladder"] == exp["ladder"])

    print()
    if _failures:
        print(f"verify: {len(_failures)} check(s) failed")
        return 1
    print("verify: all checks passed")
    return 0
