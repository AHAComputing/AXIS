#!/bin/sh
# Build the Armv9.4-A reference model that `asl_check.py` measures AXIS against.
#
# The model is the Sail translation of Arm's own ASL specification, published
# by Arm and the University of Cambridge in `rems-project/sail-arm` under the
# BSD 3-Clause Clear licence, as a GENERATED C emulator. Building it needs a C
# compiler, GMP and zlib -- and Sail's small C runtime library -- but no OCaml
# toolchain, which is why this route and not ASLRef or ASLi.
#
# Nothing here enters the repository. The model is 166 MB of C and belongs to
# its authors; it is fetched and built into a cache directory, and the gate
# declines when it is absent rather than failing.
#
# Pinned: the snapshot and the runtime it was generated against must agree,
# and a model that moved underneath the gate would change what it measures.
#
# Usage: tools/asl_model_build.sh [cache-dir]    (default ~/.cache/axis/asl)
# Then:  AXIS_ASL_MODEL=<cache-dir>/armv9  (or leave it at the default)
set -eu

SAIL_ARM_REV=1bf2e5574ba9d704639a28401b6a387dcb113cae   # arm-v9.4-a snapshot of model f7e11ae
SAIL_REV=0.17.1                                         # the Sail it was generated with
SNAPSHOT_SHA256_PREFIX=44b10531cb18ebba

CACHE=${1:-${HOME}/.cache/axis/asl}
mkdir -p "$CACHE"
cd "$CACHE"

if [ ! -d sail-arm ]; then
  git clone -q --filter=blob:none --no-checkout https://github.com/rems-project/sail-arm.git sail-arm
fi
( cd sail-arm
  git sparse-checkout set --no-cone /arm-v9.4-a/snapshots/c /arm-v9.4-a/LICENSE
  git checkout -q "$SAIL_ARM_REV" )
if [ ! -d sail ]; then
  git clone -q --depth 1 --branch "$SAIL_REV" https://github.com/rems-project/sail.git sail
fi

SNAP=sail-arm/arm-v9.4-a/snapshots/c
GOT=$(shasum -a 256 "$SNAP/armv9.c.gz" | cut -c1-16)
if [ "$GOT" != "$SNAPSHOT_SHA256_PREFIX" ]; then
  echo "snapshot checksum $GOT is not the pinned $SNAPSHOT_SHA256_PREFIX" >&2
  exit 1
fi
gunzip -kf "$SNAP/armv9.c.gz"

GMP=$(brew --prefix gmp 2>/dev/null || echo /usr)
# The generated C nests brackets far deeper than clang's default of 256 allows
# (the Makefile assumes gcc). One translation unit of 166 MB: expect 5-20
# minutes and 2 GB of memory.
cc -O1 -fbracket-depth=4096 -DHAVE_SETCONFIG -w "$SNAP/armv9.c" sail/lib/*.c \
   -I sail/lib -I "$GMP/include" -L "$GMP/lib" -lgmp -lz -o armv9
echo "built $CACHE/armv9"
