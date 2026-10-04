# LadderLens — pinned benchmark environment for hackathon problem PS-036
#
# STATUS: WRITTEN, UNTESTED. Verification happens in GitHub Actions
# (.github/workflows/build.yml) because the dev machine has no Docker/WSL.
#
# Pinned components (commit SHAs verified against upstream git tags):
#   OpenSSL 3.6.0   commit 7b371d80d959ec9ab4139d09d78e83c090de9779  (tag openssl-3.6.0)
#   liboqs  0.16.0  commit 5a1a854b0dc9f2141bdc771c555ee60c37950183  (tag 0.16.0)
#   MTL     v1.3.1  vendored copy of github.com/verisign/MTL in ../mtl-ref at commit
#                   7cef0191da55048111d252a567b7614672424ed3
#                   (MTLLIB_1_3_1 + 5 commits, "Merge pull request #13 from verisign/v1.3.1";
#                    library version string hardcoded as v1.3.1 in mtl-ref/src/mtl.h:41)
#
# Base image is release-pinned fedora-minimal:42 — same base family and the
# same two dependency versions the reference implementation builds
# (mtl-ref/docker/Dockerfile_pqc_base lines 50 and 59).
#
# Build:  make build    (= docker build -f docker/Dockerfile -t ladderlens:latest .)
# Smoke:  make smoke
#
# Every build step is a separate RUN layer so a CI failure points at exactly
# one step in the log.

FROM registry.fedoraproject.org/fedora-minimal:42 AS builder

ARG OPENSSL_TAG=openssl-3.6.0
ARG OPENSSL_SHA=7b371d80d959ec9ab4139d09d78e83c090de9779
ARG LIBOQS_TAG=0.16.0
ARG LIBOQS_SHA=5a1a854b0dc9f2141bdc771c555ee60c37950183
ARG MTL_SHA=7cef0191da55048111d252a567b7614672424ed3

# --- Step 1: C toolchain. Failure here = package/mirror problem. -------------
RUN microdnf -y install gcc gcc-c++ make cmake git perl autoconf automake libtool && \
    microdnf clean all

# Make the linker find what we install into /usr/local/lib64 in later steps.
RUN echo "/usr/local/lib64" > /etc/ld.so.conf.d/crypto.conf

WORKDIR /usr/local/app

# --- Step 2: fetch OpenSSL 3.6.0. Failure here = network or tag vanished. ----
RUN git clone --depth 1 --branch "${OPENSSL_TAG}" https://github.com/openssl/openssl.git

# --- Step 3: prove we got the exact pinned commit. Failure = wrong code. -----
RUN test "$(git -C openssl rev-parse HEAD)" = "${OPENSSL_SHA}"

# --- Step 4: build + install OpenSSL. perl is required by OpenSSL's build. ---
RUN cd openssl && ./config && make -j"$(nproc)" && make install_sw

# --- Step 5: fetch liboqs 0.16.0. --------------------------------------------
RUN git clone --depth 1 --branch "${LIBOQS_TAG}" https://github.com/open-quantum-safe/liboqs.git

# --- Step 6: prove we got the exact pinned commit. ---------------------------
RUN test "$(git -C liboqs rev-parse HEAD)" = "${LIBOQS_SHA}"

# --- Step 7: build + install liboqs (shared libs, into /usr/local). ----------
RUN mkdir -p liboqs/build && cd liboqs/build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j"$(nproc)" && make install

# --- Step 8: MTL v1.3.1 from the vendored tree (no network fetch for MTL). ---
# Build context must contain mtl-ref/ (CI clones it at the pinned commit first).
COPY mtl-ref/ /usr/local/app/mtl-ref/
RUN test -d mtl-ref/src

# --- Step 9: generate the Autotools build system. ----------------------------
RUN cd mtl-ref && autoreconf --install

# --- Step 10: configure + build + install libmtllib and the CLI tools. ------
# Tools land in /usr/local/bin (mtlkeygen, mtlsign, mtlverify).
RUN cd mtl-ref && ./configure --libdir=/usr/local/lib64 && \
    make -j"$(nproc)" && make install

# ==========================================================================
# Runtime image: libraries + CLI tools + Python analysis stack. No compilers.
# ==========================================================================
FROM registry.fedoraproject.org/fedora-minimal:42

LABEL org.opencontainers.image.title="LadderLens benchmark environment"
LABEL org.opencontainers.image.description="OpenSSL 3.6.0 + liboqs 0.16.0 + Verisign MTL v1.3.1 (mtl-ref 7cef0191)"

# --- Step 11: runtime OS deps (python for analysis; nothing else). -----------
RUN echo "/usr/local/lib64" > /etc/ld.so.conf.d/crypto.conf && \
    microdnf -y install python3 python3-pip && \
    microdnf clean all

# --- Step 12: bring in everything built above (libs, headers, CLI tools). ----
COPY --from=builder /usr/local/ /usr/local/
COPY requirements-lock.txt /tmp/requirements-lock.txt

# --- Step 13: register shared libs + install exact Python pins. --------------
RUN ldconfig && \
    python3 -m pip install --no-cache-dir -r /tmp/requirements-lock.txt && \
    rm /tmp/requirements-lock.txt

# Record the exact pins inside the image so a running container can report them
ENV MTL_REF_COMMIT=7cef0191da55048111d252a567b7614672424ed3 \
    OPENSSL_SHA=7b371d80d959ec9ab4139d09d78e83c090de9779 \
    LIBOQS_SHA=5a1a854b0dc9f2141bdc771c555ee60c37950183

WORKDIR /work
CMD ["/bin/bash"]
