# LadderLens — PS-036 MTL vs per-record PQC signature benchmark
IMAGE      := ladderlens:latest
DOCKERFILE := docker/Dockerfile
ALG        := SLH-DSA-SHA2-128s-MTL-SHA2-128

.PHONY: build smoke harness harness-run shell clean

## build: create the pinned benchmark image (OpenSSL 3.6.0, liboqs 0.16.0, MTL v1.3.1)
build:
	docker build -f $(DOCKERFILE) -t $(IMAGE) .

## smoke: 1A proof — sign + verify one message with $(ALG) and print measured sizes
smoke:
	docker run --rm -v "$(CURDIR)":/work $(IMAGE) /bin/sh /work/scripts/smoke_test.sh "$(ALG)"

## harness: build the 1B C benchmark harness INSIDE the pinned container
#   (the harness source lives on the host under harness/; gcc runs in the container
#   which has the installed libmtl + liboqs + libcrypto and a C compiler).
#   HARNESS_COMMIT is baked in so every CSV's metadata records which harness built it.
#
#   Paths (found via CI run #4 failure + mtl-ref build files):
#   - Headers: src/Makefile.am:7 pkginclude_HEADERS -> $(includedir)/$(PACKAGE)
#     with PACKAGE=mtllib (configure.ac:3 AC_INIT) => /usr/local/include/mtllib/
#     (NOT /usr/local/include directly). Installed headers are self-contained:
#     the only header including the generated mtllib_config.h is mtl_error.h
#     (mtl-ref/src/mtl_error.h:41), which is included only by .c files.
#   - Library: libmtllib is noinst + static-only (src/Makefile.am:1,3) and is
#     NEVER installed; the installed shared library is libmtlslib
#     (src/Makefile.am:5 lib_LTLIBRARIES, same 9 source files => same public API)
#     at /usr/local/lib64/libmtlslib.so (configure --libdir). Link -lmtlslib.
# Real file target: rebuilds ONLY when harness/bench.c is newer than the binary.
# (When `harness` was a phony prerequisite of harness-run, make recompiled the
# binary on every run — 5 builds per CI job. Root-caused after CI run #10.)
harness: harness/bench

harness/bench: harness/bench.c
	docker run --rm -v "$(CURDIR)":/work -w /work $(IMAGE) \
		gcc -O2 -g -Wall -Wextra \
			-I/usr/local/include/mtllib -I/usr/local/include \
			-DHARNESS_COMMIT="$$(git rev-parse --short HEAD 2>/dev/null || echo unknown)" \
			-o harness/bench harness/bench.c \
			-L/usr/local/lib64 -lmtlslib -loqs -lcrypto

## harness-run: run the harness (must be built via make harness first).
##   make harness-run ARGS="--algorithm SLH-DSA-SHA2-128s-MTL-SHA2-128 --batch-size 10 --trials 3 --warmups 1 --seed 42 --mode mtl" OUTPUT="results/raw/mtl_n10_t3_w1.csv"
harness-run: harness/bench
	@mkdir -p "$$(dirname $(OUTPUT))"
	docker run --rm -v "$(CURDIR)":/work -w /work $(IMAGE) \
		/work/harness/bench $(ARGS) --output "$(OUTPUT)"

## shell: interactive shell in the image with the repo mounted at /work
shell:
	docker run --rm -it -v "$(CURDIR)":/work $(IMAGE)

clean:
	-docker rmi $(IMAGE)
