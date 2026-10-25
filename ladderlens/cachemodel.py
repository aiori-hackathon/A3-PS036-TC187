"""Analytical expectations for the cache replay, to set beside the measured replay.

The model uses the same workload as harness/cachesim.c: Zipf(s) popularity by a
seeded rank permutation (same generator), ladder TTL counted in queries, and
append-only growth. Expected misses:

  no growth, TTL T > 0   ceil(Q / T)
  no growth, no expiry   1
  growth, no expiry      exact expectation over the cached ladder's lag, from a
                         small Markov chain: in each interval the resolver misses
                         at most once, with probability 1 - (1 - u)^L, where u is
                         the popularity mass of records its ladder does not cover
                         and L is the number of queries in the interval.
"""
from __future__ import annotations

import math

import numpy as np

MASK = (1 << 64) - 1


class SplitMix64:
    def __init__(self, seed: int):
        self.state = (seed or 1) & MASK

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return z ^ (z >> 31)


def ranks(pool: int, seed: int) -> np.ndarray:
    rng = SplitMix64(seed)
    perm = list(range(pool))
    for i in range(pool - 1, 0, -1):
        j = rng.next() % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    rank = np.empty(pool, dtype=np.int64)
    rank[np.asarray(perm)] = np.arange(pool)
    return rank


def expected_misses(s: dict) -> float:
    q, ttl, n0 = s["queries"], s["ttl_queries"], s["initial_records"]
    g, a, events = s["growth_every"], s["growth_size"], s["growth_events"]
    if not events:
        return float(math.ceil(q / ttl)) if ttl else 1.0
    if ttl:
        raise ValueError("TTL combined with growth is not modelled")
    w = 1.0 / np.power(ranks(n0 + events * a, s["seed"]) + 1.0, s["zipf_s"])
    # state[j]: probability the cached ladder covers the records published after event j
    state = np.zeros(events + 1)
    state[0] = 1.0
    misses = 1.0  # cold start at query 0
    for k in range(1, events + 1):
        published = n0 + k * a
        total = w[:published].sum()
        length = min(g, q - k * g)
        nxt = np.zeros_like(state)
        for j in range(k):
            if state[j] == 0:
                continue
            u = w[n0 + j * a:published].sum() / total
            p_miss = 1.0 - (1.0 - u) ** length
            misses += state[j] * p_miss
            nxt[k] += state[j] * p_miss
            nxt[j] += state[j] * (1.0 - p_miss)
        state = nxt
    return float(misses)
