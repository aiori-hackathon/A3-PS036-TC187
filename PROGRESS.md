# LadderLens — PROGRESS

## Phase 0: Recon ✅ COMPLETE

**Date**: 2026-10-04

### What was done
- Cloned Verisign MTL reference implementation (v1.3.1) to `mtl-ref/`
- Analyzed entire codebase: C library (src/), CLI tools (examples/), Docker setup, test suite
- Read all 57 supported PQC algorithm configurations
- Studied the C API for signing (mtllib_sign_append, mtllib_sign_get_signed_ladder, mtllib_sign_get_condensed_sig) and verification (mtllib_verify, mtllib_verify_signed_ladder)
- Produced feasibility table covering all planned features
- Selected algorithm: **SLH-DSA-SHA2-128s-MTL-SHA2-128**
- Computed key sizing analysis: condensed sigs ~25-80× smaller than raw PQC sigs **(ESTIMATE ONLY — UNVERIFIED; see "Corrections to Phase 0 estimates" under Phase 1A. Do not cite until confirmed by 1B measurements.)**
- Proposed repo structure, pinned Docker environment, and benchmark design

### Files changed
| File | Action |
|---|---|
| `mtl-ref/` | Cloned from github.com/verisign/MTL |
| `PROGRESS.md` | Created (this file) |

### Key findings
1. Batch size is fully configurable (number of messages passed = batch size)
2. Incremental tree update exists but no partial re-sign — must re-sign entire ladder
3. CLI tools exist but a thin C harness is needed for precise microsecond-level timing
4. Docker images from Verisign pin OpenSSL 3.6.0 + liboqs 0.16.0
5. Zone-update churn is unsupported by the reference implementation

### Next: Phase 1 (Mandatory Core)
Awaiting approval to proceed.

---

## Phase 1: Mandatory Core

### Step 1A: Environment — ✅ COMPLETE (verified by GitHub Actions CI on ubuntu runners, NOT on the local machine)

**Date**: 2026-10-04

**Status**: COMPLETE. The pinned image built and the smoke test passed in CI (run #1 and run #2, both `success`). The local dev machine still has no Docker/WSL — **all verification was done by GitHub Actions on ubuntu runners, not locally**. Measured sizes below exist; timings do NOT (1B measures timing). This supersedes the earlier "written, untested" markers kept below as history.

#### What was done
- Recorded the MTL reference commit: `mtl-ref` HEAD = `7cef0191da55048111d252a567b7614672424ed3` (tag `MTLLIB_1_3_1` + 5, "Merge pull request #13 from verisign/v1.3.1"; version string hardcoded v1.3.1 at `mtl-ref/src/mtl.h:41`).
- Resolved exact upstream commit SHAs for dependency pins: OpenSSL 3.6.0 → `7b371d80d959ec9ab4139d09d78e83c090de9779`, liboqs 0.16.0 → `5a1a854b0dc9f2141bdc771c555ee60c37950183` (both verified via GitHub refs API).
- Wrote `docker/Dockerfile`: multi-stage; all three pinned components (OpenSSL 3.6.0, liboqs 0.16.0, MTL v1.3.1) are cloned from upstream and SHA-verified at build time with build-failing `test` checks; runtime image adds python3 + the lockfile install; pins recorded as ENV vars; numbered RUN layers for diagnosability.
- Wrote `.github/workflows/build.yml`: build + smoke run — the verification path for 1A. Hardened 2026-10-04: `runs-on` pinned to `ubuntu-24.04` (ubuntu-latest migrates to Ubuntu 26 on 19 Oct 2026) and `actions/checkout` bumped to current major v7 (latest release v7.0.1, verified via API).
- Wrote `requirements-lock.txt` (exact pins, cp313 wheels): dnspython 2.7.0, numpy 2.2.6, scipy 1.15.3, pandas 2.2.3, matplotlib 3.10.3.
- Wrote `Makefile` (`build`, `smoke`, `shell`, `clean`) and `scripts/smoke_test.sh` (keygen → mtlsign batch-of-1 → verify condensed-with-ladder AND verify full-sig, then `stat`-prints measured byte sizes; exits non-zero on rejection per `mtl-ref/examples/mtlverify.c:198`).
- Initialized git repo at project root (`main` branch), pushed to https://github.com/adityaa925/ladderlens. `mtl-ref/` is deliberately NOT committed (standalone 1.5 MB reference clone; the build fetches MTL itself, so the clone is not needed to build). `.gitattributes` forces LF so Windows checkouts can't break the Linux build.
- Commits: `6a426a1`, `cef94b9`, `2628c6a`, then the in-build MTL fetch change (see `git log --oneline`).

#### Verification results (GitHub Actions)
- **Run #1** (commit `2628c6a`): `success` — https://github.com/adityaa925/ladderlens/actions/runs/37196496927
- **Run #2** (commit `c1619be`, self-fetching MTL at pinned SHA): `success`, ~8 min (created 11:02:25Z, completed 11:10:39Z UTC) — https://github.com/adityaa925/ladderlens/actions/runs/37197359486
- Both runs: checkout → `docker build` (SHA-verifies OpenSSL 3.6.0 / liboqs 0.16.0 / MTL v1.3.1) → smoke test printed two "Signature ACCEPTED" lines + measured sizes.

#### Measured sizes (CI run #2, batch of 1 record, SLH-DSA-SHA2-128s-MTL-SHA2-128)
**Batch of 1 only — sizes for larger batches to be measured in 1B. File sizes measured by `stat` on the reference CLI's outputs; no timings measured yet.**

| Component (reference CLI output file) | Measured size |
|---|---|
| Public key (`smoke_key.pub`) | 32 B |
| Full signature, no ladder (`msg1.bin.full_sig`) | 8,004 B |
| Condensed signature (`msg1.bin.condensed_sig`) | 76 B |
| Signed ladder (`smoke_key.key.ladder`) | 7,928 B |

Observed identity: 8,004 B = 76 B + 7,928 B, consistent with the reference's reconstruct formula (full sig = condensed sig + ladder, `mtl-ref/examples/mtlsign.c:220-225`).

**Cold-start note (measured):** delivering one record to a verifier with NO cached ladder costs the condensed signature **plus** the signed ladder = **8,004 B** — the 7,928 B ladder alone already exceeds the 1,232 B safe-DNS-UDP size from PS-036, so a cold start would fall back to TCP. Warm path (ladder already cached) carries only the 76 B condensed signature per record. These are batch-of-1 measured file sizes; do not extrapolate to larger batches.

#### Corrections to Phase 0 estimates (2026-10-04, post-CI)
- The ~7,856 B "one PQC signature" figure in the original plan was a **spec-based estimate**. The **measured** full per-record signature (condensed + ladder, batch of 1) is **8,004 B**. Decomposition of the 7,928 B signed ladder into underlying-signature vs ladder-structure bytes is not yet measured; confirm in 1B.
- The "condensed sigs ~25-80× smaller" claim (Phase 0) is an **unverified estimate**; ratios will only be stated after 1B measures non-MTL per-record signatures and batch sweeps. Until then, reports must use only the measured batch-of-1 values above.

#### Decision recorded (user, 2026-10-04)
Docker and WSL are NOT installable on the dev machine. 1A is marked "written, untested"; do NOT mark complete or claim the build works. CI workflow added as the verification path. Dockerfile kept simple and heavily commented (numbered RUN layers) so failures are easy to locate.

#### Push-coverage check + mtl-ref decision (user request, 2026-10-04)
- All 9 project files confirmed committed and pushed (`git ls-files`; `main` up to date with `origin/main` @ `2628c6a`). Only `.freebuff/` (local tool state) is untracked, intentionally.
- `mtl-ref/` confirmed on disk: 29 C/H files, `MTL_LIB_VERSION "v1.3.1"` at src/mtl.h:41, clone @ `7cef0191…`, 1.5 MB — but NOT in the GitHub repo (excluded by `.gitignore:15`), which is why the push was ~10 KiB.
- Decision: Dockerfile fetches MTL itself at pinned SHA `7cef0191…` with a SHA-verify `test` step (same clone+verify pattern as OpenSSL/liboqs) so `make build` works from a clean clone of this repo with zero extra steps. Vendoring was rejected: it would delete the clone's provenance (.git) and the build still needs the network for the other two deps. CI pre-clone step removed; `.dockerignore` now excludes `mtl-ref` entirely.
- Status unchanged: 1A remains "written, untested" pending CI logs.

#### CLI facts confirmed from source (file:line)
- `mtlkeygen <name> <alg>` writes `<name>.key` + `<name>.pub` — examples/mtlkeygen.c:164-170
- `mtlsign <key>.key <msg>...` writes `<key>.key.ladder`, `<msg>.condensed_sig`, `<msg>.full_sig`, updates key state — examples/mtlsign.c:161-233
- `mtlverify <alg> <key>.pub <msg> <sig> [<ladder>]` prints ACCEPTED, exit 0 only on success — examples/mtlverify.c:185-198
- `make install` installs mtlkeygen/mtlsign/mtlverify — examples/Makefile.am:2
- MTL lib links liboqs + OpenSSL EVP; base deps per mtl-ref/docker/Dockerfile_pqc_base:50,59 (openssl-3.6.0, liboqs 0.16.0)

#### Next: 1B (C harness) — NOT STARTED, awaiting user "continue"
## Phase 2: Tier 1 Extras — NOT STARTED
## Phase 3: Tier 2 Extras — NOT STARTED
## Phase 4: Presentation Layer — NOT STARTED
## Phase 5: Demo and Honesty Pass — NOT STARTED
