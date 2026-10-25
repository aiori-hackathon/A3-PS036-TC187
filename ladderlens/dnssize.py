"""DNS response sizes for each signature format, encoded with dnspython.

Responses are constructed, not captured: question + answer RRset + one RRSIG
+ EDNS(0) OPT with the DO bit, encoded with name compression. Only the RRSIG
signature field differs between formats. Following
draft-fregly-dnsop-slh-dsa-mtl-dnssec-06 section 4, an MTL signature in an
RRSIG carries a one-octet MTL-Type prefix (0 condensed, 1 full); plain SLH-DSA
carries the signature alone. Sizes are exact for the constructed message and
tagged analytical because no server produced them.
"""
from __future__ import annotations

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.rrset
import numpy as np
import pandas as pd
from dns.rdtypes.ANY.RRSIG import RRSIG

from . import fixtures

VARIANTS = {
    "plain": "A: plain SLH-DSA",
    "mtl1": "B: MTL full, batch of one",
    "mtl_cold": "C: MTL full (no ladder)",
    "mtl_warm": "C: MTL condensed (ladder cached)",
}


def response_bytes(rrset: dns.rrset.RRset, zone: dns.name.Name, sig_len: int, payload: int) -> int:
    q = dns.message.make_query(rrset.name, rrset.rdtype, use_edns=0, payload=payload, want_dnssec=True)
    r = dns.message.make_response(q, our_payload=payload)
    sig = RRSIG(dns.rdataclass.IN, dns.rdatatype.RRSIG, rrset.rdtype, fixtures.PLACEHOLDER_ALGORITHM,
                len(rrset.name) - 1, rrset.ttl, fixtures.EXPIRATION, fixtures.INCEPTION,
                fixtures.KEY_TAG, zone, b"\x00" * sig_len)
    r.answer.append(rrset)
    r.answer.append(dns.rrset.from_rdata(rrset.name, rrset.ttl, sig))
    # A real server would truncate or fall back to TCP above the payload limit; here we
    # want the full encoded size, so lift the limit for encoding only.
    return len(r.to_wire(max_size=65535))


def analyse(cfg: dict, df: pd.DataFrame) -> pd.DataFrame:
    w = cfg["workload"]
    payload = cfg["dns"]["edns_payload"]
    zone = dns.name.from_text(w["origin"])
    sizes = sorted(df.batch_size.unique())
    recs = fixtures.generate(int(max(sizes)), w["seed"], w["origin"])
    plain = df[df.arm == "plain"].signature_bytes.dropna()
    mtl1 = df[df.arm == "mtl1"].signature_bytes.dropna()
    rows = []
    for n in sizes:
        m = df[(df.arm == "mtl") & (df.batch_size == n)].drop_duplicates("record_index")
        cond = dict(zip(m.record_index, m.condensed_bytes))
        ladder = int(m.signed_ladder_bytes.iloc[0]) if len(m) else None
        for i in range(int(n)):
            rr = recs[i].rrset
            sig = {}
            if len(plain):
                sig["plain"] = int(plain.iloc[0])
            if len(mtl1):
                sig["mtl1"] = 1 + int(mtl1.iloc[0])
            if i in cond and ladder:
                sig["mtl_warm"] = 1 + int(cond[i])
                sig["mtl_cold"] = 1 + int(cond[i]) + ladder
            for variant, length in sig.items():
                rows.append({"n": int(n), "variant": variant, "record_index": i,
                             "rrtype": dns.rdatatype.to_text(rr.rdtype), "signature_field": length,
                             "response_bytes": response_bytes(rr, zone, length, payload)})
    return pd.DataFrame(rows)


def fit(sizes: pd.DataFrame, limits) -> pd.DataFrame:
    rows = []
    order = {v: i for i, v in enumerate(VARIANTS)}
    groups = sorted(sizes.groupby(["n", "variant"]), key=lambda kv: (kv[0][0], order[kv[0][1]]))
    for (n, variant), g in groups:
        x = g.response_bytes.to_numpy()
        row = {"n": n, "variant": variant, "median": float(np.median(x)), "p95": float(np.percentile(x, 95)),
               "max": int(x.max())}
        for lim in limits:
            row[f"fits_{lim}"] = float((x <= lim).mean())
        rows.append(row)
    return pd.DataFrame(rows)
