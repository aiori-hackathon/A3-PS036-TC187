# LadderLens: MTL-mode DNSSEC signature benchmark (AIORI-3, PS-036)
#
# Every target runs inside the pinned image. On a host, commands are wrapped in
# `docker run`; inside the image (Codespaces dev container, or `make shell`) the
# image sets LADDERLENS_IMAGE=1 and the same targets run directly.

IMAGE      := ladderlens:latest
DOCKERFILE := docker/Dockerfile
CONFIG     ?= configs/benchmark.toml
RUN        ?=

ifeq ($(LADDERLENS_IMAGE),1)
  IN_IMAGE :=
else
  IN_IMAGE := docker run --rm -v "$(CURDIR)":/work -w /work $(IMAGE)
endif

PY      := $(IN_IMAGE) python3 -m ladderlens --config $(CONFIG)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
CFLAGS  := -O2 -g -Wall -Wextra
INCLUDE := -I/usr/local/include/mtllib -I/usr/local/include
LIBS    := -L/usr/local/lib64 -lmtlslib -loqs -lcrypto -lm

.PHONY: help build smoke harness fixtures verify test plan bench report readme demo dashboard shell clean

help:
	@echo "make build       build the pinned image (OpenSSL 3.6.0, liboqs 0.16.0, MTL v1.3.1)"
	@echo "make verify      crypto self-test, correctness and exact-size checks (about two minutes)"
	@echo "make test        unit tests (run-directory safety, report integrity)"
	@echo "make demo        short narrated end-to-end run"
	@echo "make plan        time a pilot and plan trials within the budget in $(CONFIG)"
	@echo "make bench       run the plan; choose a fresh RUN=results/<name> directory"
	@echo "make report      tables, charts and report.md for RUN (default: latest run)"
	@echo "make readme      write the summary of RUN (default: results/final) into README.md"
	@echo "make dashboard   interactive view of a run (needs requirements-dashboard.txt)"

build:
	docker build -f $(DOCKERFILE) -t $(IMAGE) .

smoke:
	$(IN_IMAGE) /bin/sh scripts/smoke_test.sh

# The library headers install under include/mtllib, and the installed shared
# library is libmtlslib (mtl-ref src/Makefile.am: lib_LTLIBRARIES).
harness: harness/bin/bench harness/bin/cachesim harness/bin/selftest

harness/bin/%: harness/%.c harness/common.h
	@mkdir -p harness/bin
	$(IN_IMAGE) gcc $(CFLAGS) $(INCLUDE) -DHARNESS_COMMIT=$(COMMIT) "-DHARNESS_CFLAGS=$(CFLAGS)" \
		-o $@ $< $(LIBS)

fixtures:
	$(PY) fixtures

verify: harness
	$(PY) verify

test: harness
	$(IN_IMAGE) python3 -m unittest discover -s tests -v

plan: harness
	$(PY) plan

bench: harness
	$(PY) run $(if $(RUN),--out $(RUN))

report:
	$(PY) report $(RUN)

readme:
	$(PY) report $(if $(RUN),$(RUN),results/final) --readme

demo: harness
	$(IN_IMAGE) /bin/sh scripts/demo.sh

dashboard:
	streamlit run dashboard/app.py -- $(RUN)

shell:
	docker run --rm -it -v "$(CURDIR)":/work -w /work $(IMAGE)

clean:
	rm -rf harness/bin results/verify
