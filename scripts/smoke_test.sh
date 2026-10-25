#!/bin/sh
# Smoke test with the reference implementation's own CLI tools (make smoke).
#
# Generates a key, signs one message as a batch of one, verifies it twice
# (condensed signature with the ladder supplied, then the full signature alone)
# and prints the byte size of every file the tools write. mtlverify exits
# non-zero on rejection (mtl-ref/examples/mtlverify.c), so `set -e` fails the run.
#
#   mtlkeygen <name> <algorithm>                       -> <name>.key, <name>.pub
#   mtlsign <key>.key <msg>...                         -> <key>.key.ladder, <msg>.condensed_sig, <msg>.full_sig
#   mtlverify <alg> <key>.pub <msg> <sig> [<ladder>]   -> "Signature ACCEPTED", exit 0
set -eu

ALG="${1:-SLH-DSA-SHA2-128s-MTL-SHA2-128}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "algorithm: $ALG"
echo "pins: MTL $MTL_REF_COMMIT, OpenSSL $OPENSSL_SHA, liboqs $LIBOQS_SHA"

mtlkeygen smoke_key "$ALG" > /dev/null
printf 'LadderLens smoke test message\n' > msg1.bin
mtlsign smoke_key.key msg1.bin > /dev/null

echo "verify condensed signature with ladder:"
mtlverify "$ALG" smoke_key.pub msg1.bin msg1.bin.condensed_sig smoke_key.key.ladder
echo "verify full signature:"
mtlverify "$ALG" smoke_key.pub msg1.bin msg1.bin.full_sig

echo "sizes (bytes):"
stat -c '%8s  %n' smoke_key.pub msg1.bin.full_sig msg1.bin.condensed_sig smoke_key.key.ladder
echo "smoke test passed"
