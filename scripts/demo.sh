#!/bin/sh
# LadderLens demonstration: one zone, one MTL batch against plain SLH-DSA, the
# resulting DNS answer sizes, and a short resolver cache replay. About two
# minutes. Run with `make demo` (builds the harness first).
set -eu
cd "$(dirname "$0")/.."
exec python3 -m ladderlens demo
