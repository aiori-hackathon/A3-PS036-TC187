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
- Computed key sizing analysis: condensed sigs ~25-80× smaller than raw PQC sigs
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

### Step 1A: Environment — ARTIFACTS COMMITTED, BUILD EXECUTION BLOCKED ON DOCKER

**Date**: 2026-10-04

#### What was done
- Recorded the MTL reference commit: `mtl-ref` HEAD = `7cef0191da55048111d252a567b7614672424ed3` (tag `MTLLIB_1_3_1` + 5, "Merge pull request #13 from verisign/v1.3.1"; version string hardcoded v1.3.1 at `mtl-ref/src/mtl.h:41`).
- Resolved exact upstream commit SHAs for dependency pins: OpenSSL 3.6.0 → `7b371d80d959ec9ab4139d09d78e83c090de9779`, liboqs 0.16.0 → `5a1a854b0dc9f2141bdc771c555ee60c37950183` (both verified via GitHub refs API).
- Wrote `docker/Dockerfile`: multi-stage, pinned by SHA with build-failing `test` checks; MTL built from the vendored `mtl-ref/` tree (no network fetch for MTL); runtime image adds python3 + the lockfile install; pins recorded as ENV vars.
- Wrote `requirements-lock.txt` (exact pins, cp313 wheels): dnspython 2.7.0, numpy 2.2.6, scipy 1.15.3, pandas 2.2.3, matplotlib 3.10.3.
- Wrote `Makefile` (`build`, `smoke`, `shell`, `clean`) and `scripts/smoke_test.sh` (keygen → mtlsign batch-of-1 → verify condensed-with-ladder AND verify full-sig, then `stat`-prints measured byte sizes; exits non-zero on rejection per `mtl-ref/examples/mtlverify.c:198`).
- Initialized git repo at project root (`main` branch). `mtl-ref/` is deliberately NOT committed (nested standalone clone, pinned by SHA; re-clone step to be documented in README in 1D). `.gitattributes` forces LF so Windows checkouts can't break the Linux build.
- Commit: `6a426a1`.

#### Verify (once Docker is available)
```
make build   # docker build -f docker/Dockerfile -t ladderlens:latest .
make smoke   # runs scripts/smoke_test.sh with SLH-DSA-SHA2-128s-MTL-SHA2-128
```
Expected: two "Signature ACCEPTED" lines, then measured sizes for pubkey, full_sig, condensed_sig, signed ladder.

#### BLOCKER (needs user decision)
This Windows machine has NO Docker, NO WSL, NO podman, NO make (only Git Bash + MinGW GCC 6.3 + Python 3.13/3.14). The 1A proof (sign+verify, print sizes) therefore has NOT been executed here. Options: (a) install Docker Desktop or WSL2, (b) user runs `make build && make smoke` elsewhere and shares output, (c) agree a native-build fallback (deviates from pinned-container env).

#### CLI facts confirmed from source (file:line)
- `mtlkeygen <name> <alg>` writes `<name>.key` + `<name>.pub` — examples/mtlkeygen.c:164-170
- `mtlsign <key>.key <msg>...` writes `<key>.key.ladder`, `<msg>.condensed_sig`, `<msg>.full_sig`, updates key state — examples/mtlsign.c:161-233
- `mtlverify <alg> <key>.pub <msg> <sig> [<ladder>]` prints ACCEPTED, exit 0 only on success — examples/mtlverify.c:185-198
- `make install` installs mtlkeygen/mtlsign/mtlverify — examples/Makefile.am:2
- MTL lib links liboqs + OpenSSL EVP; base deps per mtl-ref/docker/Dockerfile_pqc_base:50,59 (openssl-3.6.0, liboqs 0.16.0)

#### Next: 1B (C harness) — awaiting user go-ahead
## Phase 2: Tier 1 Extras — NOT STARTED
## Phase 3: Tier 2 Extras — NOT STARTED
## Phase 4: Presentation Layer — NOT STARTED
## Phase 5: Demo and Honesty Pass — NOT STARTED
