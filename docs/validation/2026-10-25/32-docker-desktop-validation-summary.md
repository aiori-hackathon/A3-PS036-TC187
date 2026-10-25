# Docker Desktop validation summary - 25 October 2026

## Results

| Command | Result | Evidence retained |
|---|---|---|
| `make build` | Passed; Docker exported `ladderlens:latest` and returned to the prompt. | Terminal screenshot in chat; full text log not retained. BuildKit showed earlier layers as cached after the interrupted first attempt. |
| `make -B harness CURDIR='D:/Akshat/LadderLens_v6/LadderLens_v6/main'` | Passed; Docker ran GCC for `bench`, `cachesim`, and `selftest` with no compiler errors. | Command output in chat; full log not retained. |
| `make smoke` | Passed. | Student confirmed success in chat; full output not retained. |
| `make verify CURDIR='D:/Akshat/LadderLens_v6/LadderLens_v6/main'` | Passed; 19/19 cryptographic self-test cases plus harness parsing, signature sizes, verification paths, cache replay, DNS encoding and committed-result checks all passed. | Full output preserved in `33-docker-make-verify.log`. |
| `make test CURDIR='D:/Akshat/LadderLens_v6/LadderLens_v6/main'` | **20 tests passed, 0 failures, 0 skipped**, including end-to-end. | Full pasted terminal output is preserved in `31-docker-make-test.log`. |

Docker Desktop reported Server Version 29.9.2, Linux engine on WSL2, 4 CPUs and 3.71 GiB available memory. The Docker image build and test commands ran on this host. The `make test` output contained Pyparsing deprecation warnings emitted by Matplotlib; they were non-fatal.

## Path workaround used in MSYS2 UCRT64

MSYS2 was converting Linux container paths such as `/work` into Windows paths. After confirming the host bind mount, commands were run with `MSYS2_ARG_CONV_EXCL='*'` and an explicit Windows `CURDIR` argument. This allowed Docker to bind the project directory at `/work` inside the container.

## Scope limit

This validates the current pinned image build, harness compilation, smoke check, verification check and Python test suite as stated above. Full logs are now preserved for verify and test; full output logs for build, harness and smoke were not retained. It does not rerun `results/final/` performance measurements in Docker; those results remain from the native WSL2 run and correctly retain `in_pinned_image: false`. Remote CI and a live technical presentation were not checked.
