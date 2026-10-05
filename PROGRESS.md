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

### Step 1B: C harness — WRITTEN (rewritten 2026-10-05 after type-error review); CI correctness run happens on next push; NOT yet run for real measurements

**Date**: 2026-10-04; **updated 2026-10-05**

#### Update 2026-10-05 (rewrite + build-path fixes, found by re-review before CI)
- **`harness/bench.c` REWRITTEN.** The first draft had real compile-breaking type errors (garbled from interrupted turns): `&msg[i]` (a `uint8_t(*)[64]`) was passed where `MTLLIB_BUFFER **` is required, a use-after-free read of `tctx->algo_params` after `mtllib_key_free`, and wrong handle types. The rewrite is a clean implementation with every call site citing file+line.
- **API conventions now verified against the implementations** (not just headers): all three sig getters (`mtllib_sign_get_condensed_sig` / `_signed_ladder` / `_full_sig`, mtl-ref/src/mtllib.c) APPEND into a caller-pre-initialized `MTLLIB_BUFFER` sized by the matching `*_length()` API — same pattern `mtllib_sign_get_full_sig` itself uses; `mtllib_buffer_free` (mtllib_buffer.c:85) frees the struct AND internal data but never external (caller-referenced) data, which non-MTL warm-verify uses to view ladder/condensed bytes without copying. `mtllib_verify` returns `MTLLIB_OK` (0) or `MTLLIB_OK_VALIDATED_LADDER` (1) (mtllib_status.h:43,46) — both accepted, anything else fails loudly; the harness also cross-checks the verify out-param `condensed_len` against the measured condensed size on every verify.
- **Dockerfile fix (required for 1B):** the runtime stage had NO compiler (gcc was builder-only), so `make harness` (which compiles `harness/bench.c` inside `ladderlens:latest` at run time) would have failed with `gcc: not found`. Step 12 now installs `gcc` alongside python3. Header pins (MTL_REF_COMMIT/OPENSSL_SHA/LIBOQS_SHA) were already ENV-set in the runtime image and are what the harness metadata reports.
- **Makefile `harness` target fixed:** bogus `.gitignore` prerequisite → `harness/bench.c`; `-O0` → `-O2`; dropped `-Werror` for the first CI pass (cannot compile locally; warnings will be reviewed from CI output and -Werror re-added after); harness git commit baked in via `-DHARNESS_COMMIT="$(git rev-parse --short HEAD)"` so every metadata JSON records the harness version.
- **CI step now exercises the real workflow:** runs `make harness` + `make harness-run ARGS=... OUTPUT=...` (previously it inlined a divergent gcc command). Params unchanged: both modes, N in {1,10}, 3 trials, 1 warmup, seed 1, first 6 CSV lines printed, plus one metadata JSON printed. CORRECTNESS ONLY — runner timings are noisy (shared VMs) and will never be reported as measurements.
- CSV schema unchanged (19 columns, one row per trial per record; REPEATED-vs-PER-ROW convention documented in bench.c header and the CSV comment header).

#### What was done (2026-10-04, original write)
- Wrote `harness/bench.c`: C harness linking libmtl directly (installed Verisign MTL v1.3.1 in the pinned container; -lmtllib -loqs -lcrypto). ALL MTL API calls go through the PUBLIC API in `mtl-ref/src/mtllib.h`/`mtl-ref/src/mtllib.c`, cited by file:line in the source header. CLI: `--algorithm`, `--batch-size N`, `--trials T`, `--warmups W`, `--seed S`, `--mode {nonmtl,mtl}`, `--output path.csv`. CLOCK_MONOTONIC nanosecond timing.
- Output: one CSV (one row per trial per record; 19 columns — see header comment in bench.c for the full schema and the REPEATED-vs-PER-ROW counting convention) + one JSON metadata file (`<output>.meta.json`: CPU model, kernel, compiler, harness commit, OpenSSL/liboqs/MTL commit pins + version strings, algorithm key/sig sizes, wall time).
- Non-MTL mode: signs each record as an independent batch-of-1 MTL operation with a FRESH keypair per record (mtllib_key_new per record) — because the MTL PUBLIC API has no reset-tree or raw-sign-with-existing-key operation (the tree in one MTLLIB_CTX only grows via mtl_hash_and_append, mtl-ref/src/mtl.c). This OVERESTIMATES true per-record signing (which reuses one zone key, no ladder). sign_time EXCLUDES keygen (keygen timed separately as keygen_time_ns); the overestimate is in keygen_time_ns (N keygens vs 1). The per-record SIGNING and VERIFY comparisons stay meaningful; the central finding (MTL amortises 1 OQS signature across N records vs N for non-MTL) holds.
- Cold vs warm verification: cold = verify each record via the full signature (condensed || ladder) with NO pre-cached ladder (mtllib_verify, mtl-ref/src/mtllib.c:855, re-parses+re-verifies the ladder each call); warm = pre-validate the ladder once via mtllib_verify_signed_ladder (mtl-ref/src/mtllib.c:1059) then per-record mtllib_verify with separate condensed + ladder buffer (mtl-ref/src/mtllib.c:935, parse+authpath, no OQS per record). The library does NOT cache a parsed ladder on the MTLLIB_CTX across calls (always re-parses via mtl_ladder_from_buffer, mtl-ref/src/mtl_buffer.c:231), so warm per-record cost is parse+authpath (cheap) and the saving vs cold is the avoided per-record OQS ladder verify.
- Records: 64 bytes, deterministic from seed via a NON-cryptographic LCG (no hashing of content) — stated in source + metadata.
- Added `make harness` (builds harness/bench inside the pinned container) and `make harness-run ARGS=... OUTPUT=...` targets to the root Makefile.
- Added a CI step (`build-and-smoke` job) that builds + runs the harness with TINY params for CORRECTNESS ONLY: MTL & non-MTL, N in {1,10}, 3 trials, 1 warmup, seed 1; prints the first 6 lines of each CSV. NOT a benchmark; tiny enough to be fast.

#### CI run #4 (commit 1e04598): harness build FAILED — root cause found in MTL build files, fixed (2026-10-05)
- **Failure**: `harness/bench.c:102:10: fatal error: mtllib.h: No such file or directory` (gcc had only `-I/usr/local/include -L/usr/local/lib64 -lmtllib`).
- **Root cause (from mtl-ref build files, not guessed)**:
  - Headers are installed under `$(includedir)/$(PACKAGE)`: `mtl-ref/src/Makefile.am:7` declares `pkginclude_HEADERS`, and `mtl-ref/configure.ac:3` is `AC_INIT([mtllib], ...)` ⇒ PACKAGE=mtllib ⇒ headers live at **/usr/local/include/mtllib/**, not /usr/local/include/ directly.
  - `libmtllib` is **noinst and static-only** (`mtl-ref/src/Makefile.am:1,3`: `noinst_LTLIBRARIES = libmtllib.la` + `-static`) and is NEVER installed. The installed shared library is **libmtlslib** (`mtl-ref/src/Makefile.am:5`: `lib_LTLIBRARIES = libmtlslib.la`, same 9 source files ⇒ same public API) at /usr/local/lib64/libmtlslib.so.
  - Checked for the second trap: `mtl_error.h:41` includes the generated `mtllib_config.h` (not installed), but `mtl_error.h` is included only by `.c` files, so the installed header chain (mtllib.h → mtl.h/mtllib_buffer.h/mtllib_status.h) is self-contained.
- **Fix (Makefile `harness` target only; bench.c untouched)**: `-I/usr/local/include/mtllib -I/usr/local/include` and `-lmtlslib` (not `-lmtllib`); comments in the target cite the build files above.
- **Diagnostic added to CI** before the harness build: `find / \( -name mtllib.h -o -name 'libmtl*' \)` inside the image, so the next log shows ground truth even if the analysis is wrong.
- **CI speed**: image build now uses `docker/setup-buildx-action@v4` + `docker/build-push-action@v7` (current majors, verified via API) with `cache-from/to: type=gha, mode=max` and `load: true` — re-runs after small changes should take minutes instead of ~11.

#### NOT done (awaits your "continue")
- Real measurements: the harness has NOT been run for real benchmarking; the tiny CI correctness run above happens on the NEXT push (this machine still has no Docker, so harness compilation itself is first verified by that CI run). No measured times exist. Step (c) below (measure ONE sign op, estimate runtime, propose trial counts) is NOT done.

#### Step (c) plan (to do on your "continue"; NOT started)
- Run the harness for ONE sign op in both modes at N=1 and N=100 (single trial, no warmups), print the per-op times, and report them here.
- From those, estimate total runtime for N in {10,100,1000} with 30 trials + 5 warmups for BOTH modes, accounting for non-MTL's N keygens per trial (likely infeasible for non-MTL at N=1000).
- Propose concrete trial counts per (mode, N) and ask for your approval BEFORE any large run.
- Do NOT run the full benchmark until you approve.

#### Next: your "continue" → step (c) measure-one-sign → propose trial counts → your approval → full run
## Phase 2: Tier 1 Extras — NOT STARTED
## Phase 3: Tier 2 Extras — NOT STARTED
## Phase 4: Presentation Layer — NOT STARTED
## Phase 5: Demo and Honesty Pass — NOT STARTED
