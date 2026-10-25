"""Synthetic DNSSEC zone fixtures.

Each record in a fixture is one RRset, stored as the exact byte string that a
DNSSEC signer signs for it: the RRSIG RDATA without the signature field,
followed by the RRset in canonical form and order (RFC 4034, section 3.1.8.1
and section 6). The zone is generated deterministically from a seed, so the
same seed always yields the same bytes.
"""
from __future__ import annotations

import hashlib
import json
import random
import struct
from dataclasses import dataclass
from pathlib import Path

import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.rdataset
import dns.rrset

MAGIC = b"LLRECS01"

# Placeholder for the RRSIG algorithm field. The SLH-DSA-MTL DNSSEC draft leaves
# the number TBD (draft-fregly-dnsop-slh-dsa-mtl-dnssec-06, section 5). The
# field is one octet whatever its value, so the choice does not affect any size.
PLACEHOLDER_ALGORITHM = 200
KEY_TAG = 36036
TTL = 3600
INCEPTION = 1793491200   # 2026-10-31T00:00:00Z
EXPIRATION = 1796083200  # 2026-11-30T00:00:00Z

# Rough mix of record types in a signed zone. Workload choice, not a measurement.
TYPE_MIX = (("A", 0.40), ("AAAA", 0.25), ("TXT", 0.20), ("MX", 0.15))


@dataclass
class Record:
    name: dns.name.Name
    rrset: dns.rrset.RRset
    message: bytes  # bytes signed for this RRset


def _rdatas(rng: random.Random, rtype: str, origin: dns.name.Name, i: int) -> list[str]:
    if rtype == "A":
        return [f"192.0.2.{rng.randrange(1, 255)}" for _ in range(rng.randint(1, 3))]
    if rtype == "AAAA":
        return [f"2001:db8::{rng.randrange(1, 0xffff):x}" for _ in range(rng.randint(1, 2))]
    if rtype == "MX":
        return [f"{10 * (k + 1)} mx{k}.{origin}" for k in range(rng.randint(1, 2))]
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789=-"
    text = "".join(rng.choice(alphabet) for _ in range(rng.randint(16, 120)))
    return [f'"v=ll1 id={i} {text}"']


def signing_data(rrset: dns.rrset.RRset, signer: dns.name.Name) -> bytes:
    """RRSIG RDATA (signature excluded) || canonical RRset, per RFC 4034 3.1.8.1."""
    labels = len(rrset.name) - 1  # absolute name, root label not counted
    head = struct.pack(
        "!HBBIIIH",
        rrset.rdtype,
        PLACEHOLDER_ALGORITHM,
        labels,
        rrset.ttl,
        EXPIRATION,
        INCEPTION,
        KEY_TAG,
    )
    data = head + signer.canonicalize().to_wire()
    owner = rrset.name.canonicalize().to_wire()
    fixed = struct.pack("!HHI", rrset.rdtype, rrset.rdclass, rrset.ttl)
    for rd in sorted(r.to_digestable() for r in rrset):
        data += owner + fixed + struct.pack("!H", len(rd)) + rd
    return data


def generate(count: int, seed: int, origin: str) -> list[Record]:
    rng = random.Random(seed)
    zone = dns.name.from_text(origin)
    types, weights = zip(*TYPE_MIX)
    out = []
    for i in range(count):
        rtype = rng.choices(types, weights)[0]
        name = dns.name.from_text(f"host-{i:05d}", zone)
        rds = [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), t, origin=zone, relativize=False)
               for t in _rdatas(rng, rtype, zone, i)]
        rrset = dns.rrset.from_rdata_list(name, TTL, rds)
        out.append(Record(name, rrset, signing_data(rrset, zone)))
    return out


def write(records: list[Record], path: Path, seed: int, origin: str) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    blob = bytearray(MAGIC + struct.pack("!I", len(records)))
    for r in records:
        blob += struct.pack("!I", len(r.message)) + r.message
    path.write_bytes(blob)

    with open(path.with_suffix(".zone"), "w") as f:
        f.write(f"; LadderLens fixture, seed {seed}. Generated; do not edit.\n$ORIGIN {origin}\n")
        for r in records:
            f.write(r.rrset.to_text(origin=dns.name.from_text(origin)) + "\n")

    lengths = [len(r.message) for r in records]
    types: dict[str, int] = {}
    for r in records:
        t = dns.rdatatype.to_text(r.rrset.rdtype)
        types[t] = types.get(t, 0) + 1
    meta = {
        "path": str(path.name),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "records": len(records),
        "seed": seed,
        "origin": origin,
        "rrsig_algorithm_placeholder": PLACEHOLDER_ALGORITHM,
        "message_bytes_min": min(lengths),
        "message_bytes_median": sorted(lengths)[len(lengths) // 2],
        "message_bytes_max": max(lengths),
        "types": types,
    }
    path.with_suffix(".json").write_text(json.dumps(meta, indent=2) + "\n")
    return meta


def ensure(cfg: dict, count: int | None = None) -> dict:
    """Create the configured fixture if it is missing or too small."""
    from . import config

    path = config.fixture_path(cfg)
    need = count or config.fixture_size(cfg)
    meta_path = path.with_suffix(".json")
    if path.exists() and meta_path.exists():
        meta = json.loads(meta_path.read_text())
        w = cfg["workload"]
        # The seed is in the file name but the origin is not: a cached fixture from a
        # different origin (or a hand-edited one) must not be reused silently.
        if (meta["records"] >= need and meta.get("seed") == w["seed"]
                and meta.get("origin") == w["origin"]
                and hashlib.sha256(path.read_bytes()).hexdigest() == meta["sha256"]):
            return meta
    w = cfg["workload"]
    return write(generate(need, w["seed"], w["origin"]), path, w["seed"], w["origin"])
