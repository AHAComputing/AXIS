#!/usr/bin/env python3
"""An access map is a generalisation, so it must reproduce what it generalises. Gate.

Stage S5 gave a scalable load three address functions: unit, strided, indexed.
A tile wants rows at one stride and elements at another; an im2col window wants
three dimensions. `(dim <extent> <stride>) ...` is the mechanism that replaces
adding a form per shape -- and the risk with a mechanism like that is that it
quietly means something slightly different from the forms it was meant to
subsume.

So the first thing checked is exactly that:

  1. **one dimension at the element size is the unit stride.** Every address of
     `(vaddr_map vni32 base (dim 16 4))` equals the corresponding address of
     `(vaddr vni32 base)`;
  2. **one dimension at a register stride is the strided form.** The same
     against `(vaddr_strided vni32 base step)`.

Both of those were proven in S5, so the general form is held against machinery
that is already trusted rather than against a restatement of itself.

Then the shapes that are new:

  3. **the tile and window maps match an independent enumeration.** The
     reference decomposes the lane and sums index times stride in Python, from
     the dimensions read out of the document -- not from the emitted
     expression, which is the thing under test;
  4. **the extra dimensions do something.** The tile map must differ from BOTH
     one-dimensional maps on some input, and the window map from the tile map.
     A second dimension whose stride happened to make it collapse would pass
     every property above;
  5. **extents that do not multiply to the lane count are refused** with the
     arithmetic, rather than addressing a rectangle that is not there.

Injection-checked: decomposing the lane innermost-first, dropping the extent
product check, and ignoring every dimension after the first -- each fails a
different property.

Usage: tools/access_map_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
MASK = (1 << 64) - 1


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


def dimensions_of(source: str, mnemonic: str) -> list[tuple[int, str]]:
    """The `(dim <extent> <stride>)` list a map was written with."""
    block = re.search(rf"\(mnemonic {mnemonic}\).*?\(formal (.*?)\)\n    \(latency",
                      source, re.S)
    if not block:
        return []
    return [(int(extent), stride)
            for extent, stride in re.findall(r"\(dim (\d+) (\S+?)\)", block.group(1))]


def addresses(golden, mnemonic: str, values: dict[str, int]) -> list[int]:
    """Every lane's address, in lane order."""
    lanes = {}
    for entry in golden.AXIS_SPECS.values():
        if entry.get("scalable_origin") != mnemonic:
            continue
        lanes[entry["scalable_lane"]] = entry["eval"](
            *[values[param] for param, _ in entry["params"]]
        )
    return [lanes[index] for index in sorted(lanes)]


def reference(dims: list[tuple[int, str]], values: dict[str, int], base: int,
              count: int) -> list[int]:
    """The addresses the dimensions describe, enumerated independently."""
    out = []
    for lane in range(count):
        offset = 0
        inner = count
        for extent, stride in dims:
            inner //= extent
            index = (lane // max(inner, 1)) % extent
            width = int(stride) if stride.isdigit() else values[stride]
            offset += index * width
        out.append((base + offset) & MASK)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=32)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    workdir = Path(tempfile.mkdtemp(prefix="axis_amap_"))
    golden_path = workdir / "golden_model.py"
    result = run([*axis_prefix(), "emit-golden-python", str(args.axis_file),
                  "-o", str(golden_path)])
    if result.returncode != 0:
        print(f"FAIL the golden model could not be emitted: {result.stderr.strip()[:200]}")
        return 1
    spec = importlib.util.spec_from_file_location("axis_golden_amap", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    present = {entry.get("scalable_origin") for entry in golden.AXIS_SPECS.values()}
    needed = ("ADDR_UNIT", "ADDR_STRIDED", "MAP_UNIT", "MAP_STRIDED",
              "MAP_TILE", "MAP_WINDOW")
    if not all(name in present for name in needed):
        print("no access maps in this corpus")
        return DECLINED

    rng = random.Random(0xA117)
    failures = 0
    tile_differed = window_differed = 0
    lanes = 16

    for _ in range(args.cases):
        # ⚠️ Bases and strides are kept well inside 32 bits on purpose. These
        # instructions write their address to a register whose width comes from
        # the shape -- `vni32`, so 32 bits -- and an address past that is
        # truncated. Truncation is not what this gate is about, and driving
        # into it would make every comparison a question about the destination
        # rather than about the map. The first version used 40-bit bases and
        # spent its first run measuring exactly that.
        base = rng.getrandbits(20) << 8
        step = (rng.getrandbits(8) | 4) & ~3
        values = {"rs1": base, "rs2": step}

        unit = addresses(golden, "ADDR_UNIT", values)
        strided = addresses(golden, "ADDR_STRIDED", values)
        map_unit = addresses(golden, "MAP_UNIT", values)
        map_strided = addresses(golden, "MAP_STRIDED", values)
        tile = addresses(golden, "MAP_TILE", values)
        window = addresses(golden, "MAP_WINDOW", values)

        # 1 and 2: the general form reproduces the special ones
        if map_unit != unit:
            failures += 1
            if failures <= 4:
                print(f"FAIL a one-dimensional map at the element size is not the unit stride")
        if map_strided != strided:
            failures += 1
            if failures <= 4:
                print("FAIL a one-dimensional map at a register stride is not the strided form")

        # 3: the new shapes against an independent enumeration
        for mnemonic, got in (("MAP_TILE", tile), ("MAP_WINDOW", window)):
            want = reference(dimensions_of(source, mnemonic), values, base, lanes)
            if got != want:
                failures += 1
                if failures <= 4:
                    print(f"FAIL {mnemonic}: {[hex(a) for a in got[:4]]} against "
                          f"{[hex(a) for a in want[:4]]}")

        # 4: the extra dimensions are not decoration
        if tile != unit and tile != strided:
            tile_differed += 1
        if window != tile:
            window_differed += 1

    if not tile_differed:
        print("the tile map never differed from a one-dimensional one")
        failures += 1
    if not window_differed:
        print("the window map never differed from the tile map")
        failures += 1

    # 5: a rectangle that is not there
    ragged = workdir / "ragged.axisl"
    ragged.write_text(RAGGED_DOCUMENT)
    refused = run([*axis_prefix(), "check", str(ragged)])
    message = refused.stdout + refused.stderr
    if refused.returncode == 0:
        print("FAIL extents of 3 x 4 over 16 lanes were accepted")
        failures += 1
    elif "and the shape has 16" not in message:
        print(f"FAIL refused for the wrong reason: {message.strip()[:160]}")
        failures += 1

    print(f"{args.cases} bases: a map of one dimension is the unit and strided forms, "
          f"of two is a tile, of three a window")
    print(f"  tile differs from one dimension : {tile_differed}/{args.cases}")
    print(f"  window differs from the tile    : {window_differed}/{args.cases}")
    print("access map: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


RAGGED_DOCUMENT = """(axis-module ragged
  (version "0.1.0") (target rvmt) (description "extents that miss the lane count")
  (defisa r (base rv64im) (word-bits 64) (vector-bits 512)
    (registers "z[16]:i512" "x[32]:i64" "pc:i64")
    (features simd scalable custom) (memory-model rvwmo) (endianness little))
  (defformat R (bits 32) (fields (opcode 6 0) (zd 11 7) (func3 14 12)
    (rs1 19 15) (rs2 24 20) (func7 31 25)))
  (definstruction ragged
    (mnemonic RAGGED) (isa r) (category custom) (format R)
    (opcode 11) (func3 0) (func7 0)
    (operands (zd reg i64 out) (rs1 reg i64 in) (rs2 reg i64 in))
    (asm "ragged $zd, $rs1, $rs2")
    (semantics "Three rows of four over sixteen lanes")
    (formal (vaddr_map vni32 rs1 (dim 3 rs2) (dim 4 4)))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 1.0) (power-estimate-mw 1.0) (expected-speedup 1.0)
    (rationale "must be refused")))
"""


if __name__ == "__main__":
    sys.exit(main())
