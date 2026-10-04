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

## Phase 1: Mandatory Core — NOT STARTED
## Phase 2: Tier 1 Extras — NOT STARTED
## Phase 3: Tier 2 Extras — NOT STARTED
## Phase 4: Presentation Layer — NOT STARTED
## Phase 5: Demo and Honesty Pass — NOT STARTED
