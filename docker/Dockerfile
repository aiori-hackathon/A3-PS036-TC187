# LadderLens — pinned benchmark environment for hackathon problem PS-036
#
# Pinned components (commit SHAs verified against upstream git tags):
#   OpenSSL 3.6.0   commit 7b371d80d959ec9ab4139d09d78e83c090de9779  (tag openssl-3.6.0)
#   liboqs  0.16.0  commit 5a1a854b0dc9f2141bdc771c555ee60c37950183  (tag 0.16.0)
#   MTL     v1.3.1  vendored copy of github.com/verisign/MTL in ../mtl-ref at commit
#                   7cef0191da55048111d252a567b7614672424ed3
#                   (MTLLIB_1_3_1 + 5 commits, "Merge pull request #13 from verisign/v1.3.1";
#                    library version string hardcoded as v1.3.1 in mtl-ref/src/mtl.h:41)
#
# The base image is release-pinned (fedora-minimal:42), matching the reference
# implementation's own Dockerfiles, which use fedora-minimal and build the same
# two dependency versions (mtl-ref/docker/Dockerfile_pqc_base lines 50 and 59).
#
# Build:  make build    (= docker build -f docker/Dockerfile -t ladderlens:latest .)
# Smoke:  make smoke

FROM registry.fedoraproject.org/fedora-minimal:42 AS builder

ARG OPENSSL_TAG=openssl-3.6.0
ARG OPENSSL_SHA=7b371d80d959ec9ab4139d09d78e83c090de9779
ARG LIBOQS_TAG=0.16.0
ARG LIBOQS_SHA=5a1a854b0dc9f2141bdc771c555ee60c37950183
ARG MTL_SHA=7cef0191da55048111d252a567b7614672424ed3

RUN microdnf -y install gcc gcc-c++ make cmake git perl \
        autoconf automake libtool && \
    microdnf clean all

RUN echo "/usr/local/lib64" > /etc/ld.so.conf.d/crypto.conf

WORKDIR /usr/local/app

# --- OpenSSL 3.6.0, pinned by commit SHA (fail the build on mismatch) --------
RUN git clone --depth 1 --branch "${OPENSSL_TAG}" https://github.com/openssl/openssl.git && \
    cd openssl && \
    test "$(git rev-parse HEAD)" = "${OPENSSL_SHA}" && \
    ./config && \
    make -j"$(nproc)" && \
    make install_sw

# --- liboqs 0.16.0, pinned by commit SHA (fail the build on mismatch) --------
RUN git clone --depth 1 --branch "${LIBOQS_TAG}" https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && \
    test "$(git rev-parse HEAD)" = "${LIBOQS_SHA}" && \
    mkdir -p build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local .. && \
    make -j"$(nproc)" && \
    make install

# --- MTL v1.3.1 from the vendored reference tree (no network fetch) ----------
COPY mtl-ref/ /usr/local/app/mtl-ref/
RUN cd mtl-ref && \
    autoreconf --install && \
    ./configure --libdir=/usr/local/lib64 && \
    make -j"$(nproc)" && \
    make install

# --- Runtime image ------------------------------------------------------------
FROM registry.fedoraproject.org/fedora-minimal:42

LABEL org.opencontainers.image.title="LadderLens benchmark environment"
LABEL org.opencontainers.image.description="OpenSSL 3.6.0 + liboqs 0.16.0 + Verisign MTL v1.3.1 (mtl-ref 7cef0191)"

RUN echo "/usr/local/lib64" > /etc/ld.so.conf.d/crypto.conf && \
    microdnf -y install python3 python3-pip && \
    microdnf clean all

COPY --from=builder /usr/local/ /usr/local/
COPY requirements-lock.txt /tmp/requirements-lock.txt
RUN ldconfig && \
    python3 -m pip install --no-cache-dir -r /tmp/requirements-lock.txt && \
    rm /tmp/requirements-lock.txt

# Record the exact pins inside the image so a running container can report them
ENV MTL_REF_COMMIT=7cef0191da55048111d252a567b7614672424ed3 \
    OPENSSL_SHA=7b371d80d959ec9ab4139d09d78e83c090de9779 \
    LIBOQS_SHA=5a1a854b0dc9f2141bdc771c555ee60c37950183

WORKDIR /work
CMD ["/bin/bash"]
