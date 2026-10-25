"""Short narrated walk-through used by scripts/demo.sh (about two minutes)."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

import dns.name

from . import config, dnssize, fixtures, harness


def say(title: str) -> None:
    print(f"\n== {title}", flush=True)


def main(cfg: dict) -> int:
    w = cfg["workload"]
    alg = w["algorithm"]
    config.RESULTS.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="demo-", dir=config.RESULTS))

    say("Environment")
    print(f"algorithm      {alg}")
    commit = os.environ.get("MTL_REF_COMMIT")
    if commit:
        print(f"MTL reference  commit {commit[:12]}, built with {os.environ.get('MTL_CFLAGS')}")
    else:
        print("MTL reference  not running in the pinned image; versions are recorded in each result")

    say("1. A synthetic signed zone")
    meta = fixtures.ensure(cfg)
    rec = config.fixture_path(cfg)
    print(f"{meta['records']} RRsets ({', '.join(f'{k} {v}' for k, v in meta['types'].items())}); "
          f"signing input {meta['message_bytes_min']} to {meta['message_bytes_max']} bytes per RRset")

    n = 100
    say(f"2. Arm C: sign {n} RRsets as one MTL batch (one SLH-DSA signature in total)")
    mtl = harness.read_bench([harness.bench("mtl", n, out / "mtl.csv", records=rec, algorithm=alg)])
    sign_total = (mtl.sign_ns.sum() + mtl.ladder_sign_ns.iloc[0]) / 1e9
    print(f"batch signed in {sign_total:.2f} s; ladder {int(mtl.signed_ladder_bytes.iloc[0]):,} B; "
          f"condensed signatures {int(mtl.condensed_bytes.min())} to {int(mtl.condensed_bytes.max())} B")

    say("3. Arm A: the same zone with plain SLH-DSA (5 of the 100 RRsets timed)")
    plain = harness.read_bench([harness.bench("plain", n, out / "plain.csv", records=rec, sample=5, algorithm=alg)])
    per = plain.sign_ns.median() / 1e9
    print(f"{per:.2f} s per signature, so about {per * n:.0f} s for all {n} (extrapolated); "
          f"each signature {int(plain.signature_bytes.iloc[0]):,} B")

    say("4. What one DNS answer weighs")
    zone = dns.name.from_text(w["origin"])
    rr = fixtures.generate(1, w["seed"], w["origin"])[0].rrset
    rows = [("plain SLH-DSA", int(plain.signature_bytes.iloc[0])),
            ("MTL full (no ladder cached)", 1 + int(mtl.signature_bytes.max())),
            ("MTL condensed (ladder cached)", 1 + int(mtl.condensed_bytes.max()))]
    for label, sig in rows:
        size = dnssize.response_bytes(rr, zone, sig, cfg["dns"]["edns_payload"])
        print(f"{label:31} {size:>6,} B  {'fits' if size <= 1232 else 'exceeds'} 1,232 B")
    print(f"verify: plain {plain.verify_cold_ns.median() / 1e6:.2f} ms, MTL cold "
          f"{mtl.verify_cold_ns.median() / 1e6:.2f} ms, MTL warm {mtl.verify_warm_ns.median() / 1e3:.1f} µs per record")

    say("5. One resolver, 2,000 queries, the zone grows twice")
    s = harness.read_cache_summary(harness.cachesim(
        out / "cache.csv", records=rec, initial=n, queries=2000, zipf=1.0, ttl=0, growth_every=800,
        growth_size=20, seed=1, algorithm=alg))
    print(f"{s['hits']:,} hits, {s['misses']} ladder fetches, {s['bytes_delivered'] / s['queries']:.0f} B of "
          f"signature per query (plain: {int(plain.signature_bytes.iloc[0]):,} B); "
          f"{s['hits_on_older_ladder']} answers verified on an older ladder after growth")

    say("Next")
    print("make plan && make bench RUN=results/new-run && make report RUN=results/new-run")
    print(f"Demo artifacts: {out.relative_to(config.ROOT).as_posix()}")
    return 0
