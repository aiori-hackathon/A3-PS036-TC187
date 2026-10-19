#!/bin/sh
# LadderLens 1A smoke test — runs INSIDE the pinned container (make smoke).
#
# Purpose: prove the environment can sign and verify one message with
# SLH-DSA-SHA2-128s-MTL-SHA2-128 using the Verisign MTL v1.3.1 reference CLI,
# and print the measured byte sizes of every component it writes.
#
# Every number printed here is a measured byte count (stat) of a file produced
# by the reference implementation. Nothing is averaged, estimated or claimed.
#
# Tool usage (from mtl-ref/examples/*/print_usage):
#   mtlkeygen <name> <algorithm_str>            -> <name>.key, <name>.pub
#   mtlsign <key>.key <msg>...                  -> <key>.key.ladder, <msg>.condensed_sig, <msg>.full_sig
#   mtlverify <alg> <key>.pub <msg> <sig> [<ladder>] -> "Signature ACCEPTED" + exit 0
set -eu

ALG="${1:-SLH-DSA-SHA2-128s-MTL-SHA2-128}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"

echo "== LadderLens 1A smoke test =="
echo "algorithm: $ALG"
echo "container pins: MTL_REF_COMMIT=$MTL_REF_COMMIT OPENSSL_SHA=$OPENSSL_SHA LIBOQS_SHA=$LIBOQS_SHA"
echo

echo "--- keygen ---"
mtlkeygen smoke_key "$ALG" > /dev/null

printf 'LadderLens smoke test message #1 (PS-036)\n' > msg1.bin

echo "--- sign: batch of 1 record (mtllib_sign_append -> get_signed_ladder -> get_condensed_sig) ---"
mtlsign smoke_key.key msg1.bin > /dev/null

echo "--- verify: condensed signature + cached ladder ---"
mtlverify "$ALG" smoke_key.pub msg1.bin msg1.bin.condensed_sig smoke_key.key.ladder

echo "--- verify: full signature, no ladder ---"
mtlverify "$ALG" smoke_key.pub msg1.bin msg1.bin.full_sig

echo
echo "--- measured sizes (bytes) ---"
stat -c '%s  %n' msg1.bin smoke_key.pub msg1.bin.full_sig msg1.bin.condensed_sig smoke_key.key.ladder

echo
echo "SMOKE TEST PASSED"
