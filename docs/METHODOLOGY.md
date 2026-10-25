# Methodology

This document states exactly what LadderLens measures, how, and what each reported number means. Code references point to the files that implement each step.

## 1. Scope

The supplied official PS-036 statement (`docs/reference/PS-036.pdf`) requires a benchmark of a supplied MTL implementation for one PQC algorithm at three dataset sizes, comparing signing time, verification time and transmitted bytes with and without MTL, and separating measured cache usage from analytical estimates. The requirement-to-evidence assessment is in `docs/PS036-COMPLIANCE.md`. The statement also excludes new cryptography, a resolver written from scratch, Internet deployment and security proofs. LadderLens stays within that scope: the C programs call the reference library's public API and liboqs, and every DNS message is constructed locally.

| Item | Choice |
|---|---|
| Algorithm | SLH-DSA-SHA2-128s-MTL-SHA2-128 (underlying signature: SLH-DSA-SHA2-128s, FIPS 205) |
| Reference implementation | Verisign MTL v1.3.1, commit `7cef0191`. The `MTLLIB_1_3_1` tag points at older v1.2.1 code, so the build pins the commit, not the tag. |
| Dependencies | liboqs 0.16.0 (`5a1a854`), OpenSSL 3.6.0 (`7b371d8`), each SHA-checked during the image build |
| Dataset sizes | 10, 100 and 1,000 RRsets (`configs/benchmark.toml`) |

## 2. Workload

`ladderlens/fixtures.py` generates a synthetic zone (`bench.example.`) from a seed. Each RRset is one of A, AAAA, TXT or MX, drawn with fixed weights (40/25/20/15 percent), with one to three records per RRset. The mix is a workload choice, not a measurement of any real zone.

For every RRset the fixture stores the byte string a DNSSEC signer signs: the RRSIG RDATA without its signature field, followed by the RRset in canonical form and order (RFC 4034, sections 3.1.8.1 and 6). `make verify` checks this encoding against dnspython's own DNSSEC implementation. The RRSIG algorithm field holds a placeholder value, because the SLH-DSA-MTL DNSSEC draft leaves the number to be assigned; the field is one octet regardless, so the value changes no size.

Benchmark cells of size N use the first N RRsets of the same fixture, so all arms and sizes sign identical data.

## 3. Arms

| Arm | What one trial does | Implementation |
|---|---|---|
| A, `plain` | One SLH-DSA key pair; sign and verify each RRset with liboqs | `harness/bench.c`, `run_plain` |
| B, `mtl1` | For each RRset: new MTL key, append, full signature (condensed signature plus a one-leaf signed ladder), verify | `run_mtl1` |
| C, `mtl` | One MTL key; append all N RRsets; sign the ladder once; produce one condensed signature per RRset; verify cold and warm | `run_mtl` |

Arm A is the workload without MTL. Arm B exists because the draft describes a full MTL signature as a drop-in replacement for a conventional one; it shows MTL's overhead when nothing is shared. The MTL public API cannot reset a tree, so arm B needs a new key per RRset; its key generation is timed separately and never included in signing time.

## 4. What is timed

Each library call is bracketed by `clock_gettime(CLOCK_MONOTONIC)`. Message concatenation, the input message buffers and file output are outside the timed regions. Arm B's `sign_ns` also contains its full-signature buffer allocation and length query (both inside the bracketed region, together well under a microsecond against a signature of about 0.7 s); arm C allocates its condensed-signature buffers outside the timed region.

| Column | Arm A | Arm B | Arm C |
|---|---|---|---|
| `keygen_ns` (per trial) | one key pair | sum over all keys | one key |
| `sign_ns` (per RRset) | `OQS_SIG_sign` | append + full signature | append + condensed signature |
| `ladder_sign_ns` (per trial) | | | the one ladder signature |
| `verify_cold_ns` (per RRset) | `OQS_SIG_verify` | full signature | full signature (ladder checked every time) |
| `ladder_verify_ns` (per trial) | | | ladder checked once |
| `verify_warm_ns` (per RRset) | | | condensed signature against the checked ladder |

Verification always uses a context rebuilt from the public key with `mtllib_pubkey_from_buffer`, not the signer's context. In the warm path the library parses the supplied ladder and checks the authentication path without any SLH-DSA operation (`mtl-ref/src/mtllib.c`, ladder branch of `mtllib_verify_with_ctx_str`).

Before any measurement each process performs one untimed sign and verify, so lazy initialisation inside OpenSSL and liboqs is not charged to the first recorded operation. The first append on each new MTL tree still includes a one-time allocation inside the library. It is a real cost of building a batch, so it stays in record 0's figure and in every batch total; the report lists it separately and uses medians for per-record figures.

The timer's own cost (median of 10,001 back-to-back reads) is recorded in every metadata file as the noise floor.

## 5. Trials, interleaving and sampling

`make plan` times a short pilot of the plain and batch arms, and derives the batch-of-one arm from their measured per-record costs (a key generation plus one SLH-DSA signature per record, plus the fixed process overhead it measures directly). It assigns up to `trials.max` trials per cell (30 by default) and reduces the per-record arms toward `trials.min` if the total exceeds `budget.minutes`. Arms A and B time at most `budget.max_records_per_trial` evenly spaced RRsets per trial. Their per-record cost does not depend on N, so a total over N RRsets is the measured per-record mean multiplied by N; such totals are tagged **extrapolated**. Arm C always processes the whole batch, because a batch cannot be sampled. For N=1,000 the retained run measured K=100 for A and B and scales each trial total by N/K=10. The bootstrap interval is over repeated trial totals; it does not add a separate RRset-sampling uncertainty estimate, and the fixed evenly spaced subset is a workload assumption. Arm C measured all N records directly.

`make bench` executes the plan in rounds. In round r, every cell that still needs a trial runs once, as a separate process, in an order reshuffled with a seeded generator. Slow drift on the machine (thermal state, noisy neighbours) is therefore spread across arms instead of landing on one. The order and start time of every invocation are written to `schedule.csv`.

## 6. Statistics

Per-record latencies and per-trial totals are summarised by median, interquartile range, p95, p99, mean, minimum and maximum (`ladderlens/stats.py`). A bootstrap 95% confidence interval for the median (2,000 resamples, fixed seed) is reported only when a cell has at least 20 observations. Headline differences are tested with a two-sided Mann–Whitney U test on per-trial values: per-trial medians for verification, per-trial batch totals for signing. Records inside one trial share a key and a moment on the machine, so they are not treated as independent observations. Raw rows are never averaged inside the harness.

## 7. Correctness checks

`harness/selftest.c` runs before every benchmark check in `make verify`. It signs eight records with the reference library and expects valid plain and MTL signatures to be accepted, and every one of these to be rejected: an altered message, an altered plain signature, an altered authentication path (last and inner byte), an altered ladder signature, a full signature carrying an altered ladder, a ladder signed by another key, a condensed signature checked against another key's ladder, truncated, empty and malformed signatures, and a record the ladder does not cover. Each case runs in its own process, so a crash on malformed input would be reported as a crash rather than hidden.

The benchmark itself stops a trial on any rejected verification (`harness/bench.c` exits with the record and status). The runner records such a failure, moves its partial output to `raw/failed/`, and continues; the report lists failures and the number of completed trials per cell.

## 8. Transmitted bytes

Three quantities are kept apart. **Signature material** is measured: the bytes the library produces per answer. **Encoded DNS response size** is analytical: a complete response is built and encoded locally. **Network traffic** (IP and UDP headers, fragmentation, TCP fallback) is not measured, because no server or network is involved.

**Signature bytes** come straight from the harness: the plain signature, the full MTL signature, the condensed signature and the signed ladder, per RRset. They are deterministic for a given algorithm and library version, and `make verify` checks them exactly. The largest condensed signature at each N equals the bound in draft-harvey-cfrg-mtl-mode-09, section 12.

**DNS response bytes** (`ladderlens/dnssize.py`) are computed by building, for every RRset, a complete response: question, answer RRset, one RRSIG and an EDNS(0) OPT record with the DO bit, encoded by dnspython with name compression. Following draft-fregly-dnsop-slh-dsa-mtl-dnssec-06, section 4, an MTL signature in an RRSIG is prefixed by a one-octet MTL-Type (0 condensed, 1 full). Sizes are exact for the constructed message and tagged **analytical**, because no server produced them. They are compared against 512, 1,232 (DNS Flag Day 2020), 1,400 (the RFC 9715 recommendation) and 1,472 bytes (Ethernet MTU over IPv4).

## 9. Cache usage

PS-036 asks for directly measured cache usage kept apart from analytical estimates. Both are produced.

**Measured: resolver replay** (`harness/cachesim.c`). One signer and one public-key-only resolver run against the reference library. Queries pick RRsets with Zipf popularity (exponent `cache.zipf`, rank order from a seeded permutation). Retrieval follows draft-fregly-dnsop-slh-dsa-mtl-dnssec-06, section 6.2: the resolver first receives a condensed signature. If its cached ladder covers the record and has not expired, it verifies against the cache (a hit). Otherwise it re-queries for the full signature, verifies it and caches the new ladder (a miss), so a miss delivers a condensed and a full signature. The replay records every query and reports hits, misses by cause, signature bytes delivered, the ladder bytes held (cache usage) and verification time.

Two variants run for each seed:

- **TTL sweep.** The ladder expires after a fixed number of queries.
- **Append-only growth.** Every `growth_every` queries the signer appends `growth_size` RRsets and signs a new ladder. Answers for older records then carry authentication paths computed against the new ladder. The replay checks each one against the older cached ladder, which the MTL draft says must work (section 6.8). Successes are counted as older-ladder hits and failures as compatibility failures.

**Analytical: model** (`ladderlens/cachemodel.py`). With a TTL of T queries and no growth, misses are exactly ⌈Q/T⌉. With growth, the expected number of misses is computed exactly from a small Markov chain over how far the cached ladder lags behind the signer. It uses the same Zipf weights and the same permutation generator as the replay. The report sets measured and analytical columns side by side. The 99.98% hit-rate result is a deterministic synthetic replay outcome (`hits / 20,000` queries, TTL=5,000, Zipf exponent 1.0, one of three seeds); it is not production resolver telemetry.

## 10. Models built on measured inputs

- **Byte break-even.** For k answers served under one ladder, MTL delivers `L + (k + 1)·p` signature bytes (condensed attempt and full re-query for the first answer, then one condensed signature per answer) and plain SLH-DSA delivers `k·s`. The break-even point is `k* = (L + p) / (s − p)`, with s, L and p measured.
- **Cold versus warm verification.** The time to verify k answers covered by one ladder is `k·t_cold` cold and `t_ladder + k·t_warm` warm, from measured medians; the measured batch totals at k = N are plotted on the same axes.

## 11. Tags

| Tag | Meaning |
|---|---|
| measured | read directly from a harness or replay run |
| extrapolated | a measured per-record cost multiplied by N because only K < N records were timed |
| analytical | computed from measured inputs with the formula stated beside it |
| spec | taken from a specification |

## 12. Environment and reproducibility

The Docker image (`docker/Dockerfile`) builds every dependency from source at a pinned commit and fails if a commit does not match. MTL's own `configure.ac` forces `-g -O0`; the image overrides this with `-O2 -g -fPIC` so the library code is measured as it would be deployed. In a development check the difference was about 12 percent on MTL's per-record operations and negligible for SLH-DSA operations, which live in liboqs. The flags are recorded in every result.

Every run writes `manifest.json`: configuration, plan, repository commit and whether the tree was clean, CPU model and instruction-set flags, logical CPUs, memory, frequency governor where visible, kernel, Python package versions, SHA-256 of both harness binaries and of the fixture. Each harness invocation also writes a metadata file with library versions, pinned commits, compiler flags and the timer noise floor.

The retained final run used one fixed 4-core WSL2 host and the pinned OpenSSL, liboqs and MTL source commits, but it did **not** run inside the pinned Docker image or Codespaces (`manifest.json` records `in_pinned_image: false`). It completed all 216 planned harness trials and 15 cache replays in 163.5 minutes, exceeding the plan's 120-minute estimate by 43.5 minutes. Treat its results as a native-replica benchmark, not as validation of the Docker image. Shared CI runners are used only for correctness checks; CI for this source version has not been run.

The cryptographic source commits and Python analysis packages are pinned, but the Dockerfile uses the Fedora 42 base by tag and installs operating-system packages without exact version pins. Rebuilding later is therefore not guaranteed to produce a bit-for-bit identical image, even though the cryptographic source commits are checked during build.

Each run gets a new directory. `make bench` refuses a directory that already has files, and the run lists every file it produced in `manifest.json` (with `status: complete` at the end). For every file a successful invocation wrote (the CSV and its `.meta.json` or `.summary.json`), the manifest also stores a SHA-256 hash. The report reads only those files and stops if the directory holds anything else, is missing a listed file, holds a file whose hash no longer matches, or belongs to an unfinished run, so measurements and metadata from different runs can never be combined.

## 13. Known limitations

- The replay models one resolver and one zone; it does not model networks, other resolvers or DNS caching of the records themselves.
- Responses are encoded locally; no name server or resolver software is exercised.
- Arm B pays one key generation per RRset because of an API limitation, as described above.
- Changing or deleting signed records is not supported by the reference implementation, so zone churn beyond appending is not measured.
- Results compare arms on one virtual machine. Absolute times on other hardware will differ; the ratios between arms are the robust result.
