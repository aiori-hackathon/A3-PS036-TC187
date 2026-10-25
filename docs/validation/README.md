# Validation record

The dated sections below preserve historical state at the time they were written. The **final audit rerun** below is the latest status for the current source. Older sections may describe superseded code and must not be used as current verification.

## 2026-10-25: initial student-host Docker run (superseded by final audit rerun below)

The student built and ran the pinned Docker image from MSYS2 UCRT64 using Docker Desktop 29.9.2. `make build` completed and exported `ladderlens:latest`; `make -B harness` invoked the three containerized C compiler commands without errors; `make smoke` passed (full output not retained); captured `make verify` output records all checks passing, including 19 cryptographic self-test cases; and captured `make test` output records 20 tests passed, 0 failures, 0 skips, including end-to-end. The full outputs are preserved as `2026-10-25/33-docker-make-verify.log` and `2026-10-25/31-docker-make-test.log`. Full build/harness/smoke logs were not retained; see `2026-10-25/32-docker-desktop-validation-summary.md` for the evidence breakdown. Pyparsing deprecation warnings appeared during tests but were non-fatal.

This validates the pinned image build and checks, but it does not rerun the retained performance benchmark inside Docker. `results/final/` remains the native WSL2 run and is still accurately marked `in_pinned_image: false`.

Command output behind the "checked" entries in the README's project status. Logs are copied unedited, except that the absolute path of the working directory was removed.

## 2026-10-23: local replica of the pinned build

**Environment.** Docker was not available, and the image's Fedora base cannot be pulled from this machine, so the pinned stack was rebuilt natively with the Dockerfile's own steps: OpenSSL 3.6.0 (`7b371d8`), liboqs 0.16.0 (`5a1a854`, all algorithms) and Verisign MTL v1.3.1 (`7cef019`, built with `-O2 -g -fPIC`). Each commit was checked, and everything was installed to `/usr/local` with libraries in `lib64` as in the image. The `make` targets ran in in-image mode (`LADDERLENS_IMAGE=1`, with the image's environment variables) and Python packages at the versions in `requirements-lock.txt`.

Differences from the image: Ubuntu 24.04 with gcc 13 and Python 3.12 instead of Fedora 42 and Python 3.13; OpenSSL and liboqs built without their test binaries; one virtual CPU (Intel Xeon, 2.1 GHz).

| Log | Command | Observed result |
|---|---|---|
| `01-make-help.log` | `make help` | target list printed |
| `02-make-harness.log` | `make harness` | bench, cachesim and selftest built, no warnings |
| `03-make-smoke.log` | `make smoke` | reference CLI: both signatures ACCEPTED; 32 / 8,004 / 76 / 7,928 B |
| `04-make-verify.log` | `make verify` | 47 of 47 checks passed, including 19 of 19 self-test cases |
| `05-make-test.log` | `make test` | 8 of 8 unit tests passed, including the end-to-end run-directory test |
| `06-make-demo.log` | `make demo` | completed |
| `07-make-plan.log` | `make plan` | 9 cells, 28 to 30 trials, estimate about 118 minutes |
| `08-make-bench-interrupted.log` | `make bench RUN=results/runs/20261023-replica-full` | **interrupted** after 15 of 258 invocations when the machine stopped background work; not a result |
| `09-report-refuses-interrupted-run.log` | `make report` on that run | refused: run not complete |
| `10-bench-refuses-nonempty-dir.log` | `make bench` into the same directory | refused: directory not empty |

Logs 09 and 10 show the run-directory rules working on a real interrupted run: its partial data cannot enter a report, and a new run cannot be written over it.

**Not covered here:** building the Docker image, the CI workflow, the Codespaces container, and the final benchmark in the pinned environment. No final results exist yet.

## 2026-10-23, second pass: manifest hashes and source-only packaging

Same replica as above. Run after adding SHA-256 checks for every file a run writes.

| Log | Command | Observed result |
|---|---|---|
| `2026-10-23-pass2/01-make-harness.log` | `make harness` (clean build) | built, no warnings |
| `2026-10-23-pass2/02-make-smoke.log` | `make smoke` | both signatures ACCEPTED |
| `2026-10-23-pass2/03-make-verify.log` | `make verify` | 47 of 47 checks passed, including 19 of 19 self-test cases |
| `2026-10-23-pass2/04-make-test.log` | `make test` | 14 of 14 passed: missing, unexpected and modified metadata, modified measurements and cache summaries, and hash-less manifests are rejected; a real run with edited metadata is refused |
| `2026-10-23-pass2/05-make-demo.log` | `make demo` | completed |

The same `make harness`, `make verify` and `make test` were repeated from a fresh unzip of the source-only package (no Git metadata); see the hand-off notes for that result.

Still not covered: the Docker image build, CI, Codespaces, and the full benchmark. No final results exist.

## 2026-10-24: final run artifacts and current-session audit

The paragraph above describes the 23 October validation only. A later full run is retained in `../../results/final/`. Its `manifest.json` reports 216/216 harness invocations successful, 15/15 cache runs, and 9,812.4 seconds elapsed. It records the exact dependency commits, but also explicitly records `host.in_pinned_image: false` and `LADDERLENS_IMAGE: null`; this was a native Ubuntu/WSL2 replica, not the Docker image.

From the Windows audit session, `ladderlens.analysis.validate_run(Path("results/final"))` accepted the run. An independent SHA-256 pass matched all 463 manifest entries to the 432 raw CSV/metadata files, 30 cache CSV/summary files and root `schedule.csv`. Parsing the raw CSVs independently reproduced the reported N=1,000 signing medians: 944.852 seconds for plain SLH-DSA (21 trials, extrapolated from 100 records/trial) and 0.929 seconds for batched MTL (30 trials, all 1,000 records measured). The schedule has 216 `ok` rows.

Current-session command results:

| Command/check | Result |
|---|---|
| `python -m unittest discover -s tests -v` (Python 3.14.2 on Windows) | 19 passed, 1 errored: end-to-end test cannot execute the Linux harness binary (`WinError 193`). The full output is `09-windows-python-tests.log`. |
| `make build`, `make smoke`, `make verify`, `make test`, `make demo`, `make plan` | Not executable in this session: `make` and Docker are unavailable; WSL invocation returns `Wsl/E_ACCESSDENIED`. Prior logs are historical evidence, not a rerun here. |
| `results/final/` integrity and selected raw totals | Passed as described above. |
| `python -m compileall -q ladderlens tests dashboard` | Passed; syntax compilation only. |
| `docs/LadderLens-PS036.pdf` | 8 landscape pages; reopened with pypdf/pdfplumber, key values extracted, rendered and visually inspected. |
| Pinned Docker build, CI, Codespaces, dashboard | Not run. No Docker engine, authorized repository, Codespace or dashboard dependency is available. |

The supplied `docs/validation/2026-10-24/` directory originally contained `01-environment.log`, `03-make-verify.log`, `07-make-plan.log` and `08-report-refuses-interrupted-run.log`. This audit added `09-windows-python-tests.log` and `10-independent-final-run-check.log`. The `04-make-test.log` and `06-sanitizers.log` cited in the earlier `docs/AUDIT.md` were not present in the supplied files, so those specific claims cannot be substantiated from the package. No official PS-036 statement, mentor response, editable presentation or supplied PDF was supplied; this audit generated the provisional PDF documented above.

The run took 163.5 minutes against a 120-minute estimate. The 1,000-record plain and batch-one totals are extrapolated. The student reports mentor approval of the dataset sizes, current separated byte interpretation, and extrapolation; written approval is not retained in this workspace. The included report and PDF remain provisional pending official PS-036/team details and actual Docker validation.

- `12-docker-validation-status.log`: Docker verification was blocked on the Windows host (Docker and GNU Make absent; WSL access denied); records the Dockerfile liboqs path fix and local-only checks. `11-windows-unit-tests.log` preserves the 19-pass/one-skip portable test result.

## Latest verification pass — 24 October 2026

The Dockerfile now explicitly installs liboqs into `/usr/local/lib64` and points
CMake at the OpenSSL built in the image. This aligns with the MTL link/runtime
layout but has **not** been exercised by an image build. The Windows end-to-end
test now skips the Linux ELF harness explicitly; the full local suite reports
19 passed and one skipped. Python `compileall` passed. The retained final run
still validates locally: 463 manifest hashes, 216 successful scheduled trials,
15 completed cache runs; its manifest says it was not inside the pinned image.
See `docs/FINAL-VERIFICATION.md` for the task register and exact remaining gates.

- 13-release-archive-tests.log: portable unit test output from extracted clean release archive (19 passed, one end-to-end test skipped because harness binaries are excluded). 14-release-archive-validation.log: extraction count and 463-hash retained-run integrity result; explicitly not Docker validation.


## 2026-10-24: organizer outline-aligned PDF

The public AIORI-3 guideline links an 11-section proposed presentation outline. `docs/LadderLens-PS036-structured-provisional.pdf` is a separate 11-page provisional deck following those sections; the earlier `docs/LadderLens-PS036.pdf` was preserved. The updated PDF was reopened and checked for 11 pages, required section headings, current approval status, Docker disclosures and key result values, then rendered to PNG and visually inspected. It does not resolve the missing PS-036 statement or team details; methodology approval is student-reported, with no written message retained in this workspace.


The later follow-up added `15-structured-pdf-validation.log` and the `docs/INDEPENDENT-AUDIT.md` register. The latest release package is tracked in the audit's final package validation record; earlier archive logs are retained as history and do not describe the latest archive.


The current audit added `16-current-windows-tests.log`; `17-release-final4-tests.log` records the extracted package test, compileall and retained-run integrity checks; `18-release-final4-inventory.log` records the direct ZIP inventory, required-file and sensitive-pattern checks. Docker remains explicitly unverified.

`19-release-final5-validation.log` records the complete extracted-copy check and checksum for the 560-entry final5 source package.

`20-binary-provenance-check.log` records that local harness ELF hashes match the retained run manifest, while preserving the limitation that the source revision is unknown.

## 24 October approval-status refresh

The student reported mentor approval of the configured RRset sizes, separated byte reporting, and N=1,000 extrapolation. This confirmation is treated as actionable. The current PS-036 review covers page 1 only at the student's direction; page 2 is excluded. The 24 October Docker-unavailable status below is historical and superseded by the 25 October validation section above. See `24-pdf-approval-status-refresh.log` for the historical PDF update.

`21-post-approval-windows-tests.log` preserves an initial test attempt that failed because the sandbox's default temporary directory was inaccessible. Rerunning with `TEMP` and `TMP` under the workspace passed 19 tests with one Linux-only integration test skipped; `22-post-approval-windows-tests-workspace-temp.log` contains that output and the compileall status. `23-docker-make-command-attempts.log` records that all five requested Make targets and `docker --version` could not execute because those commands are unavailable. This is not Docker validation.

`CLAIMS-AND-FAIRNESS-AUDIT.md` documents workflow comparability and claim classifications. No benchmark measurements or charts changed because the approved interpretation matches the retained methodology.

The final13 corrected-scope source archive was independently extracted and checked after creation. It is superseded by final15, which includes the updated Docker validation records. These archives exclude scratch results and generated Linux binaries; source archive checks are distinct from the Docker validation itself.

## 2026-10-25: final audit rerun on current source

Current-source Docker checks passed: build (`34`), C harness compilation (`35`), smoke (`36`), verification (`42`), unit plus end-to-end suite (`45`, 21/21), and technical demo (`44`). Windows system Python ran 21 tests (20 passed, Linux-only integration skipped) and `compileall` passed (`46`). The bundled Codex Python interpreter could not import SciPy and is not the project's pinned test environment. The retained `results/final/` run validates with 463 hashes and 216 scheduled rows, but its manifest explicitly says performance measurements ran outside the pinned Docker image on native WSL2, with no source commit recorded. No new long performance run was made.

`docs/FINAL-AUDIT-2026-10-25.md` is the authoritative verdict and page 1 compliance matrix. Team identity was supplied and added to a visually checked 11-page PDF at `output/pdf/AIORI-3-PS036-Nexora.pdf`; the original provisional deck remains preserved. External organizer/repository/video/demo actions are still outstanding. The audit also discloses that earlier pre-fix `make verify`/`make demo` invocations overwrote the old scratch folders `results/verify` and `results/demo`; the current commands now preserve old outputs by using unique directories. The authoritative `results/final/` data was not touched.

## Page 1 of supplied PS-036 statement

The student supplied the official `PS-036.pdf` on 24 October 2026. A copy is retained at `docs/reference/PS-036.pdf`; page 1 requirement-to-evidence mapping is in `docs/PS036-COMPLIANCE.md`. At the student's direction, page 2 is their work and is excluded from this review. Current pinned Docker build and requested checks passed on 25 October; a runnable technical demo passes, while live presentation evidence is not available in this workspace.
