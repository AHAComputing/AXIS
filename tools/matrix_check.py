#!/usr/bin/env python3
"""Three index functions, proved against each other. Gate.

A tile is a vector with a second index. `vrows`, `vcols` and `vtranspose` are
static maps from an output lane to an input lane, and the risk with a static
map is that it is wrong the same way everywhere -- a backend comparison cannot
see that, because every backend reads the same map.

So the maps are checked against **each other**, through identities that only
hold if all three are right:

  1. **a transpose undoes the transpose of the other shape.** T2(T8(m)) = m
     over a two-by-eight tile, and T4(T4(m)) = m over a square one. ⚠️ The
     square case alone is not enough, and that is not a guess: a transpose that
     used the ROW count where the column count belongs passed this gate until
     the non-square pair existed, because in a four-by-four tile the two
     numbers are equal;
  2. **transposing an outer product swaps its operands.** T(a x b) = b x a,
     which ties `vrows` and `vcols` to `vtranspose` and to each other -- a
     swapped row and column index passes the first property and fails this one;
  3. **transposing a row broadcast gives a column broadcast.** T(rows(a)) =
     cols(a), the same tie stated without the multiply, so an error in the
     element operator cannot hide an error in the index;
  4. **rows and columns actually differ.** Without this the three above hold
     for a pair of identical maps, and the whole thing proves nothing;
  5. **and they are the right way round.** ⚠️ The identities above are
     SYMMETRIC: swapping `vrows` and `vcols` relabels every one of them and
     they all still hold -- measured, by injecting exactly that swap and
     watching the gate pass. So orientation needs an absolute statement rather
     than a relative one: the first row of a row broadcast is constant, and the
     first column of a column broadcast is. A swap makes both of those false.

And one static property, because the arithmetic silently wraps otherwise:

  6. **a column count that does not divide the lanes is refused** with the
     reason, rather than describing rows of different lengths.

Injection-checked: making `vcols` a copy of `vrows` fails 2 and 3, swapping the
two fails 5, and transposing with the row count where the column count belongs
fails 1. The last two were written as claims first and found to be FALSE -- the
gate passed both -- which is why properties 1 and 5 look the way they do.

Usage: tools/matrix_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
COLUMNS = 4


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


def evaluate(golden, mnemonic: str, values: dict[str, int]) -> list[int]:
    """Every lane of an instantiated instruction, in lane order.

    Each lane is its own instruction and names exactly the operand lanes it
    reads, so the driver supplies them by name rather than guessing a layout.
    """
    lanes = {}
    for name, entry in golden.AXIS_SPECS.items():
        if entry.get("scalable_origin") != mnemonic:
            continue
        missing = [param for param, _ in entry["params"] if param not in values]
        if missing:
            # An index that left the vector. The elaborator refuses this now,
            # so reaching it means something upstream let one through -- worth
            # a diagnosis rather than a KeyError from the driver.
            raise LookupError(f"{name} reads {', '.join(missing)}, which no lane supplies")
        arguments = [values[param] for param, _ in entry["params"]]
        lanes[entry["scalable_lane"]] = entry["eval"](*arguments)
    return [lanes[index] for index in sorted(lanes)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_matrix_"))
    golden_path = workdir / "golden_model.py"
    result = run([*axis_prefix(), "emit-golden-python", str(args.axis_file),
                  "-o", str(golden_path)])
    if result.returncode != 0:
        print(f"FAIL the golden model could not be emitted: {result.stderr.strip()[:200]}")
        return 1
    spec = importlib.util.spec_from_file_location("axis_golden_matrix", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    needed = ("SMOPA", "TILE_TRANSPOSE", "TILE_ROWS", "TILE_COLS",
              "TILE_T_8", "TILE_T_2")
    present = {entry.get("scalable_origin") for entry in golden.AXIS_SPECS.values()}
    if not all(name in present for name in needed):
        print("no tile index functions in this corpus")
        return DECLINED

    rng = random.Random(0x7111)
    failures = 0
    differed = 0
    lanes = COLUMNS * COLUMNS

    try:
        for _ in range(args.cases):
            vector_a = [rng.getrandbits(32) for _ in range(COLUMNS)]
            vector_b = [rng.getrandbits(32) for _ in range(COLUMNS)]
            tile = [rng.getrandbits(32) for _ in range(lanes)]

            def named(prefix, source):
                return {f"{prefix}__l{index}": value for index, value in enumerate(source)}

            # 1. a transpose undoes the transpose of the other shape
            once = evaluate(golden, "TILE_TRANSPOSE", named("zn", tile))
            twice = evaluate(golden, "TILE_TRANSPOSE", named("zn", once))
            if twice != tile:
                failures += 1
                if failures <= 4:
                    print("FAIL transposing a square tile twice changed it")
            wide = evaluate(golden, "TILE_T_8", named("zn", tile))
            back = evaluate(golden, "TILE_T_2", named("zn", wide))
            if back != tile:
                failures += 1
                if failures <= 4:
                    print("FAIL a two-by-eight transposed and transposed back changed")

            # 2. transposing an outer product swaps its operands
            product = evaluate(golden, "SMOPA", {**named("zn", vector_a), **named("zm", vector_b)})
            swapped = evaluate(golden, "SMOPA", {**named("zn", vector_b), **named("zm", vector_a)})
            if evaluate(golden, "TILE_TRANSPOSE", named("zn", product)) != swapped:
                failures += 1
                if failures <= 4:
                    print("FAIL T(a x b) is not b x a")

            # 3. transposing a row broadcast gives a column broadcast
            rows = evaluate(golden, "TILE_ROWS", named("zn", vector_a))
            cols = evaluate(golden, "TILE_COLS", named("zn", vector_a))
            if evaluate(golden, "TILE_TRANSPOSE", named("zn", rows)) != cols:
                failures += 1
                if failures <= 4:
                    print("FAIL T(rows(a)) is not cols(a)")

            # 4. and the two broadcasts are not the same map
            if rows != cols:
                differed += 1

            # 5. and they are the right way round. The identities are symmetric
            #    under a swap, so orientation is stated absolutely: a row broadcast
            #    holds one value along each row, a column broadcast one value down
            #    each column.
            if len(set(rows[:COLUMNS])) != 1 or rows[0] != vector_a[0]:
                failures += 1
                if failures <= 4:
                    print("FAIL the first row of a row broadcast is not a[0] repeated")
            if len(set(cols[index * COLUMNS] for index in range(COLUMNS))) != 1:
                failures += 1
                if failures <= 4:
                    print("FAIL the first column of a column broadcast is not constant")
    except LookupError as error:
        # An index that left the vector. The elaborator refuses that now,
        # so reaching here means one got through -- reported rather than
        # raised, because a gate that crashes says less than one that fails.
        print(f"FAIL {error}")
        failures += 1

    if not differed:
        print("rows and columns never differed; the identities hold over one map twice")
        failures += 1

    # 5. a column count that does not divide the lanes is refused
    ragged = workdir / "ragged.axisl"
    ragged.write_text(RAGGED_DOCUMENT)
    refused = run([*axis_prefix(), "check", str(ragged)])
    message = refused.stdout + refused.stderr
    if refused.returncode == 0:
        print("FAIL a tile of 16 lanes in columns of 3 was accepted")
        failures += 1
    elif "whole number of rows" not in message:
        print(f"FAIL refused for the wrong reason: {message.strip()[:160]}")
        failures += 1

    print(f"{args.cases} tiles: transpose is an involution, T(a x b) = b x a, "
          f"T(rows) = cols")
    print(f"  rows and columns differed : {differed}/{args.cases} case(s)")
    print("matrix: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


RAGGED_DOCUMENT = """(axis-module ragged
  (version "0.1.0") (target rvmt) (description "columns that do not divide the lanes")
  (defisa r (base rv64im) (word-bits 64) (vector-bits 512)
    (registers "z[16]:i512" "pc:i64")
    (features simd scalable custom) (memory-model rvwmo) (endianness little))
  (defformat R (bits 32) (fields (opcode 6 0) (zd 11 7) (func3 14 12)
    (zn 19 15) (zm 24 20) (func7 31 25)))
  (definstruction ragged
    (mnemonic RAGGED) (isa r) (category simd) (format R)
    (opcode 11) (func3 0) (func7 0) (encoding (zm 0))
    (operands (zd reg i32 out) (zn reg i32 in))
    (asm "ragged $zd, $zn")
    (semantics "Sixteen lanes in columns of three")
    (formal (vrows vni32 3 zn))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 1.0) (power-estimate-mw 1.0) (expected-speedup 1.0)
    (rationale "must be refused")))
"""


if __name__ == "__main__":
    sys.exit(main())
