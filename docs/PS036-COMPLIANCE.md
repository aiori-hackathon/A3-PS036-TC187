# PS-036 page 1 compliance review

**Review date:** 25 October 2026  
**Authority:** supplied official `docs/reference/PS-036.pdf`, page 1 only. Per the student's direction, page 2 is excluded from this technical review.

## Technical requirements

| PS-036 requirement | Status | Evidence and scope |
|---|---|---|
| Use one supported PQC signature algorithm | **PASS** | `configs/benchmark.toml` selects SLH-DSA-SHA2-128s; the plain arm uses liboqs and the MTL arm uses the pinned Verisign MTL reference. |
| Use one mentor-tested MTL reference implementation | **PASS (student-reported approval)** | Verisign MTL v1.3.1 is pinned to commit `7cef0191da55048111d252a567b7614672424ed3` and called through its public API. The student confirmed mentor approval; no separate written approval artifact is included. |
| Test three dataset sizes | **PASS** | N=10, 100 and 1,000 RRsets are configured, generated from the deterministic fixture, and present in the retained run. The student reports mentor approval of these sizes. |
| Compare equivalent workloads with and without MTL where supported | **PASS, with labeled extrapolation** | Plain SLH-DSA, MTL batch-of-one and full-batch MTL use the same fixture records. At N=1,000 the first two arms time 100 records and scale totals; full-batch MTL directly processes all 1,000. |
| Run repeated trials under pinned software and hardware | **PASS, environment disclosed** | The retained run contains 216 successful trials and 15 cache replays. Its manifest records the exact cryptographic source commits, package versions, CPU and WSL2 host. The pinned Docker image was separately built and checked on 25 October; the retained performance dataset itself was collected in the native WSL2 replica (`in_pinned_image: false`). |
| Measure signing time, verification time and transmitted bytes | **PASS under the mentor-approved interpretation** | Signing and verification timings and signature material are measured. Complete DNS response sizes are calculated by exact local encoding of constructed messages. No live network traffic is captured; the report keeps these scopes distinct. |
| Record and report configuration and workload parameters | **PASS, with source-revision limit** | Configuration, schedule, manifest, dependency versions, host data, raw outputs and report are retained. The source checkout had no Git metadata, so the run's source commit is `unknown`. |
| Separate directly measured cache usage from analytical estimates | **PASS** | The C replay invokes the MTL reference API over synthetic query streams; measured counters are compared with a separate analytical model. This is a synthetic workload, not production DNS telemetry. |
| Defer if the required implementation and test fixtures are unavailable | **NOT TRIGGERED** | The reference implementation and deterministic fixture generator are present and were used. |
| Add no new cryptography, resolver implementation from scratch, Internet deployment or claimed security proof | **PASS** | LadderLens measures existing libraries. The cache replay is a benchmark simulator; no production resolver, deployment or security proof is claimed. |

## Expected outcomes

| Expected outcome | Status | Evidence |
|---|---|---|
| Pinned benchmark environment | **PASS** | `docker/Dockerfile`; successful Docker Desktop build and checks recorded in `docs/validation/2026-10-25/`. |
| Benchmark harness | **PASS** | C signing/cache harness and Python planning, validation, analysis and reporting pipeline; Docker verification log passes. |
| MTL and non-MTL configurations | **PASS** | Arms A, B and C in configuration and shared fixture path. |
| Three dataset-size test cases | **PASS** | N=10, 100 and 1,000 in configuration, raw results and report. |
| Repeated-trial measurements | **PASS, with environment disclosure** | 216/216 scheduled trials completed; the performance run was native WSL2, while Docker image checks were separate. |
| Signing and verification results | **PASS** | Full report, charts, raw CSV data and metadata are retained. Extrapolated totals remain labeled. |
| Transmitted-byte comparison | **PASS under approved interpretation** | Signature material is measured; complete DNS messages are locally encoded and calculated; network traffic is explicitly outside the measurement. |
| Cache-use measurements and analytical estimates | **PASS** | Fifteen cache replays and corresponding analytical comparisons are retained. |
| Reproducible results report | **PASS, with source provenance qualification** | `results/final/report.md`, raw data, manifest, config and dependency pins are included; Git commit metadata is unavailable in this source copy. |
| Technical demonstration | **PASS (runnable demo); live presentation not evidenced** | The Docker-based demo passed; the source script and pseudocode are included. No separate record of a judge-facing presentation is retained. |

## Final technical assessment

The project meets the page 1 technical requirements with the explicit measurement and provenance qualifications above. Docker image build, harness compilation, smoke, `make verify` and `make test` passed on the student's host according to the retained 25 October evidence; the full verify and test logs are included. The final performance measurements remain the separately identified native WSL2 run. This page 1 review does not verify GitHub collaboration/ownership steps, team identity, video upload, mentoring attendance or a live presentation; those organizer actions are tracked separately in `docs/FINAL-AUDIT-2026-10-25.md`.
