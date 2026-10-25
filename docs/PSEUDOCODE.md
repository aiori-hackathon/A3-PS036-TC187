# Pseudocode

A compact outline of the benchmark, for the PS-036 prototype demonstration. The real code is in `harness/bench.c`, `harness/cachesim.c` and `ladderlens/`.

## One benchmark trial

```text
input:  rrsets[0..N-1]      bytes a DNSSEC signer signs for each RRset
        arm in {plain, mtl1, mtl}

if arm == plain:                                   # Arm A: without MTL
    (pk, sk) = SLH_DSA.keygen()                    # timed as keygen
    for each r in rrsets:
        sig = SLH_DSA.sign(sk, r)                  # timed: sign
        assert SLH_DSA.verify(pk, r, sig)          # timed: verify (cold)
        record |sig|

if arm == mtl1:                                    # Arm B: MTL, batch of one
    for each r in rrsets:
        key = MTL.new_key()                        # timed as keygen
        h = MTL.append(key, r)                     # timed: sign ...
        full = MTL.full_signature(key, h)          # ... includes one SLH-DSA signature
        v = MTL.verifier(public_key(key))
        assert MTL.verify(v, r, full)              # timed: verify (cold)
        record |full|, |condensed part|, |ladder part|

if arm == mtl:                                     # Arm C: MTL, batch of N
    key = MTL.new_key()                            # timed as keygen
    for each r in rrsets:
        h[r] = MTL.append(key, r)                  # timed: sign (per record)
    ladder = MTL.signed_ladder(key)                # timed: the only SLH-DSA signature
    for each r in rrsets:
        c[r] = MTL.condensed_signature(key, h[r])  # timed: added to sign (per record)
    v = MTL.verifier(public_key(key))

    for each r in rrsets:                          # cold: nothing cached
        assert MTL.verify(v, r, c[r] || ladder)    # timed: SLH-DSA check + path

    assert MTL.verify_ladder(v, ladder)            # timed once: SLH-DSA check
    for each r in rrsets:                          # warm: ladder already trusted
        assert MTL.verify(v, r, c[r], ladder)      # timed: path hashing only

    record |c[r]| for every r, |ladder|

write one CSV row per (trial, record) and a metadata file for the run
```

## A full run

```text
plan  = pilot(each arm) -> trials and sample size per (arm, N) within the time budget
for round in 1..max_trials:
    cells = [c in plan if c.trials >= round]
    shuffle(cells)                                 # interleave arms against drift
    for c in cells:
        run one trial of c.arm at size c.N         # a fresh process each time
run the cache replays
report: statistics, DNS response sizes, break-even, verification curves, cache model
```

## Resolver cache replay

```text
signer: append the first N0 RRsets, sign the ladder
resolver: cache = empty

for q in 0..Q-1:
    if growth is on and q is a multiple of G:
        signer appends A more RRsets and signs a new ladder

    r = zipf_choice(published RRsets)
    c = signer.condensed_signature(r)              # against the current ladder
    deliver c                                      # first answer is always condensed

    if cache holds a ladder that covers r and has not expired:
        if MTL.verify(resolver, r, c, cache):      # older ladders still work
            hit; continue
        count a compatibility failure
    miss: deliver c || signer.ladder               # full re-query, as in the draft
          MTL.verify(resolver, r, full)            # SLH-DSA check
          cache = signer.ladder

report: hits, misses by cause, signature bytes delivered, ladder bytes held,
        older-ladder hits, compatibility failures, verification time
```
