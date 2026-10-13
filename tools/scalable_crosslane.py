#!/usr/bin/env python3
"""Check cross-lane operations against the architecture (stage S6).

Backend agreement cannot see any of this. Every backend derives its answer from
the same description, so a permute table that is wrong in the same way
everywhere passes all of them -- the point stage S4 established and measured.
This states the tables independently.

  reductions  fold every lane, left to right. The order is stated because
              floating-point addition is not associative, so an FP reduction
              has no value at all until it is pinned; the integer operators are
              associative and indifferent.
  permutes    a static map from an output lane to an input lane. Each output
              lane is exactly one input operand's lane, so the check is direct:
              the emitted expression must name that symbol and no other.

Usage: tools/scalable_crosslane.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import math
import struct
import importlib.util
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# Permutes: mnemonic -> (operand names in order, function from (lane, count) to
# (which operand, which lane)). Written from what the operation means.
def zip1(lane, count):    return (lane % 2, lane // 2)
def zip2(lane, count):    return (lane % 2, count // 2 + lane // 2)
def uzp1(lane, count):    return (0, 2 * lane) if 2 * lane < count else (1, 2 * lane - count)
def uzp2(lane, count):    return (0, 2 * lane + 1) if 2 * lane + 1 < count else (1, 2 * lane + 1 - count)
def trn1(lane, count):    return (0, lane) if lane % 2 == 0 else (1, lane - 1)
def trn2(lane, count):    return (0, lane + 1) if lane % 2 == 0 else (1, lane)
def ext1(lane, count):    return (0, lane + 1) if lane + 1 < count else (1, lane + 1 - count)
def slideup1(lane, count):   return (0, lane - 1) if lane >= 1 else (1, lane)
def slidedown1(lane, count): return (0, lane + 1) if lane + 1 < count else (1, lane)
def slideup2(lane, count):   return (0, lane - 2) if lane >= 2 else (1, lane)
def slidedown2(lane, count): return (0, lane + 2) if lane + 2 < count else (1, lane)

PERMUTES = {
    "VZIP1_S": (("zn", "zm"), zip1),
    "VZIP2_S": (("zn", "zm"), zip2),
    "VUZP1_S": (("zn", "zm"), uzp1),
    "VUZP2_S": (("zn", "zm"), uzp2),
    "VTRN1_S": (("zn", "zm"), trn1),
    "VTRN2_S": (("zn", "zm"), trn2),
    "VEXT1_S": (("zn", "zm"), ext1),
    "VSLIDEUP2_S": (("zn", "zb"), slideup2),
    "VSLIDEDOWN2_S": (("zn", "zb"), slidedown2),
    "VZIP1_H": (("zn", "zm"), zip1),
    "ZIP1_S": (("zn", "zm"), zip1),
    "ZIP2_S": (("zn", "zm"), zip2),
    "UZP1_S": (("zn", "zm"), uzp1),
    "UZP2_S": (("zn", "zm"), uzp2),
    "TRN1_S": (("zn", "zm"), trn1),
    "TRN2_S": (("zn", "zm"), trn2),
    "EXT_S": (("zn", "zm"), ext1),
    "VSLIDEUP_VI": (("vs2", "vb"), slideup1),
    "VSLIDEDOWN_VI": (("vs2", "vb"), slidedown1),
}

# Reductions: mnemonic -> (operand, fold over lane values, element width).
def mask(value, width): return value & ((1 << width) - 1)

REDUCTIONS = {
    "VREDSUM_S": ("zn", lambda a, b: a + b, 32),
    "VREDAND_S": ("zn", lambda a, b: a & b, 32),
    "VREDXOR_S": ("zn", lambda a, b: a ^ b, 32),
    "VREDMINU_B": ("zn", min, 8),
    "ADDV_S": ("zn", lambda a, b: a + b, 32),
    "EORV_S": ("zn", lambda a, b: a ^ b, 32),
    "VREDSUM_VS": ("vs2", lambda a, b: a + b, 32),
}


def f32(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]


def f32_bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def fold_sequential(lanes: list[float]) -> float:
    """Left to right, rounding at every step. RVV's `vfredosum`."""
    accumulated = lanes[0]
    for value in lanes[1:]:
        accumulated = f32(f32_bits(accumulated + value))
    return accumulated


def fold_pairwise(lanes: list[float]) -> float:
    """A balanced tree. SVE's FADDV, and a different value from the left fold.

    Split rounding up, matching the elaborator -- which only matters for an odd
    lane count, and is written here as a claim about the architecture rather
    than copied from the implementation it checks.
    """
    if len(lanes) == 1:
        return lanes[0]
    mid = (len(lanes) + 1) // 2
    return f32(f32_bits(fold_pairwise(lanes[:mid]) + fold_pairwise(lanes[mid:])))


# The float reductions are checked separately, because they are the only ones
# whose *order* is observable. Every integer reduction here folds an
# associative operator, so reversing the fold cannot change the answer -- a
# reference built only from those would pass a right-to-left fold, which is the
# one thing `vfredosum` exists to rule out. Measured: it did, until this was
# added.
#
# `VFREDUSUM_S` is deliberately absent. Its order is whichever realisation the
# ISA declares, so a fixed reference here would be checking the document's
# declaration against itself; `tools/reduction_order_check.py` is its gate, and
# it sweeps both realisations rather than pinning one.
ORDERED = {
    "VFREDOSUM_S": ("zn", 32, fold_sequential),
    "VFREDPSUM_S": ("zn", 32, fold_pairwise),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_x_"))
    golden_path = workdir / "golden_model.py"
    subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(args.axis_file),
         "-o", str(golden_path)],
        check=True, cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location("axis_golden_x", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)
    specs = golden.AXIS_SPECS

    checks = failures = 0

    # --- permutes: each output lane must name exactly one input lane --------
    lanes_of: dict[str, dict[int, dict]] = {}
    for name, entry in specs.items():
        origin = entry.get("scalable_origin")
        if origin in PERMUTES:
            lanes_of.setdefault(origin, {})[entry["scalable_lane"]] = entry
    for origin, (operands, pick) in PERMUTES.items():
        lanes = lanes_of.get(origin)
        if not lanes:
            print(f"skip {origin}: no lanes found")
            continue
        count = len(lanes)
        for lane, entry in sorted(lanes.items()):
            which, source = pick(lane, count)
            want = f"{operands[which]}__l{source}"
            got = entry["formal_semantics"]
            checks += 1
            if got != want:
                failures += 1
                if failures <= 8:
                    print(f"FAIL {origin} lane {lane}: reads {got}, want {want}")

    # --- reductions: fold the lanes independently ---------------------------
    random.seed(0x5E6)
    for mnemonic, (operand, fold, width) in REDUCTIONS.items():
        entry = specs.get(mnemonic)
        if entry is None:
            print(f"skip {mnemonic}: not present")
            continue
        names = [name for name, _ in entry["params"]]
        count = sum(1 for name in names if name.startswith(f"{operand}__l"))
        if count == 0:
            print(f"FAIL {mnemonic}: no lane operands")
            failures += 1
            continue
        for _ in range(args.cases):
            values = {name: random.getrandbits(w) for name, w in entry["params"]}
            got = entry["eval"](*[values[name] for name in names])
            want = values[f"{operand}__l0"]
            for lane in range(1, count):
                want = mask(fold(want, values[f"{operand}__l{lane}"]), width)
            checks += 1
            if got != want:
                failures += 1
                if failures <= 8:
                    print(f"FAIL {mnemonic}: got 0x{got:x} want 0x{want:x}")

    for mnemonic, (operand, width, reference) in ORDERED.items():
        entry = specs.get(mnemonic)
        if entry is None:
            print(f"skip {mnemonic}: not present")
            continue
        names = [name for name, _ in entry["params"]]
        count = sum(1 for name in names if name.startswith(f"{operand}__l"))
        ordered_checks = 0
        for _ in range(args.cases * 4):
            values = {name: random.getrandbits(w) for name, w in entry["params"]}
            # Random bit patterns are a poor test of *order*: they are mostly
            # huge or tiny, one term dominates, and the fold is associative in
            # practice. Values spread across a few binary exponents lose low
            # bits when added in one order and not another, which is the whole
            # phenomenon `vfredosum` exists to pin down. Measured: with random
            # patterns a reversed association was caught in 2 cases out of 552;
            # with these it is caught in hundreds.
            lanes = []
            for lane in range(count):
                exponent = random.randint(-4, 24)
                magnitude = math.ldexp(1.0 + random.random(), exponent)
                value = f32(f32_bits(magnitude if random.random() < 0.5 else -magnitude))
                values[f"{operand}__l{lane}"] = f32_bits(value)
                lanes.append(value)
            # Skip inputs that are not finite: a NaN result compares by payload,
            # which is not what this check is about.
            if any(value != value or value in (float("inf"), float("-inf"))
                   for value in lanes):
                continue
            accumulated = reference(lanes)
            if accumulated != accumulated or abs(accumulated) == float("inf"):
                continue
            got = entry["eval"](*[values[name] for name in names])
            checks += 1
            ordered_checks += 1
            if got != f32_bits(accumulated):
                failures += 1
                if failures <= 8:
                    print(
                        f"FAIL {mnemonic}: got 0x{got:x} "
                        f"want 0x{f32_bits(accumulated):x}"
                    )
        if ordered_checks == 0:
            print(f"{mnemonic}: no finite cases reached; order was not tested")
            failures += 1
        else:
            print(f"  {mnemonic}: {ordered_checks} ordered folds checked")

    # --- dynamic gather: evaluated, not compared as symbols -----------------
    # A static permute reads a known lane, so checking it is a name comparison.
    # A gather reads a lane chosen at runtime, so the reference has to compute.
    # Both architectures' dynamic permute, which is one operator: RVV gathers
    # 32-bit elements four at a time and SVE's table lookup gathers sixteen
    # bytes, so the same select tree is checked four deep and sixteen deep.
    for mnemonic, (source, index) in {"VRGATHER_VV": ("vs2", "vs1"),
                                      "TBL_Z_B": ("zn", "zm")}.items():
        lanes = {
            entry["scalable_lane"]: entry
            for entry in specs.values()
            if entry.get("scalable_origin") == mnemonic
        }
        if not lanes:
            print(f"skip {mnemonic}: not present")
            continue
        count = len(lanes)
        in_range = out_of_range = 0
        for lane, entry in sorted(lanes.items()):
            names = [name for name, _ in entry["params"]]
            for _ in range(args.cases):
                values = {name: random.getrandbits(w) for name, w in entry["params"]}
                # Indices must land inside the vector often enough to test the
                # gather at all: a random 64-bit index is essentially always out
                # of range, and a run that never selected a real lane would pass
                # while checking only the zero fallback.
                for other in range(count):
                    values[f"{index}__l{other}"] = random.randint(0, count)
                chosen = values[f"{index}__l{lane}"]
                if chosen < count:
                    want = values[f"{source}__l{chosen}"]
                    in_range += 1
                else:
                    want = 0
                    out_of_range += 1
                got = entry["eval"](*[values[name] for name in names])
                checks += 1
                if got != want:
                    failures += 1
                    if failures <= 8:
                        print(
                            f"FAIL {mnemonic} lane {lane}: index {chosen} "
                            f"gave 0x{got:x}, want 0x{want:x}"
                        )
        print(f"  {mnemonic}: {in_range} in-range, {out_of_range} out-of-range")
        if not in_range or not out_of_range:
            print(f"{mnemonic}: only one side of the range was reached")
            failures += 1

    # --- compress: the output position is decided by the mask ---------------
    # `mask_operand`, not `mask`: the module already has a `mask()` helper that
    # the reduction fold uses, and shadowing it broke that check rather than
    # this one.
    for mnemonic, (source, mask_operand, background) in {
        "VCOMPRESS_S": ("zn", "pg", "zb")
    }.items():
        lanes = {
            entry["scalable_lane"]: entry
            for entry in specs.values()
            if entry.get("scalable_origin") == mnemonic
        }
        if not lanes:
            print(f"skip {mnemonic}: not present")
            continue
        count = len(lanes)
        packed = fell_through = 0
        for lane, entry in sorted(lanes.items()):
            names = [name for name, _ in entry["params"]]
            for _ in range(args.cases):
                values = {name: random.getrandbits(w) for name, w in entry["params"]}
                # Masks must be 0/1 per lane and must sometimes select fewer
                # elements than there are output lanes: a mask that is always
                # full would never reach the background, and one that is always
                # empty would never test the packing.
                for other in range(count):
                    values[f"{mask_operand}__l{other}"] = random.randint(0, 1)
                active = [values[f"{source}__l{j}"]
                          for j in range(count) if values[f"{mask_operand}__l{j}"]]
                if lane < len(active):
                    want = active[lane]
                    packed += 1
                else:
                    want = values[f"{background}__l{lane}"]
                    fell_through += 1
                got = entry["eval"](*[values[name] for name in names])
                checks += 1
                if got != want:
                    failures += 1
                    if failures <= 8:
                        print(
                            f"FAIL {mnemonic} lane {lane}: got 0x{got:x} want 0x{want:x} "
                            f"(mask {[values[f'{mask_operand}__l{j}'] for j in range(count)]})"
                        )
        print(f"  {mnemonic}: {packed} packed, {fell_through} fell through to the background")
        if not packed or not fell_through:
            print(f"{mnemonic}: only one side of the mask was reached")
            failures += 1

    # --- the mask family: all comparisons against a prefix count ------------
    # Stated as what each one *means*, independently of the prefix helper the
    # elaborator shares between them -- a shared helper is exactly the thing a
    # common bug would hide behind.
    MASKS = {
        "VIOTA_M": lambda bits, i: sum(bits[:i]),
        "VMSBF_M": lambda bits, i: int(sum(bits[: i + 1]) == 0),
        "VMSIF_M": lambda bits, i: int(sum(bits[:i]) == 0),
        "VMSOF_M": lambda bits, i: int(sum(bits[:i]) == 0 and bits[i] == 1),
        # SVE's break-after and break-before are the same two operations under
        # different names, so they are stated the same way. If the shared
        # operator ever stopped meaning both, one of these would fail.
        "BRKA_P": lambda bits, i: int(sum(bits[:i]) == 0),
        "BRKB_P": lambda bits, i: int(sum(bits[: i + 1]) == 0),
    }
    for mnemonic, expected in MASKS.items():
        lanes = {
            entry["scalable_lane"]: entry
            for entry in specs.values()
            if entry.get("scalable_origin") == mnemonic
        }
        if not lanes:
            print(f"skip {mnemonic}: not present")
            continue
        count = len(lanes)
        saw_set = saw_clear = 0
        for lane, entry in sorted(lanes.items()):
            names = [name for name, _ in entry["params"]]
            for _ in range(args.cases):
                bits = [random.randint(0, 1) for _ in range(count)]
                source = "pn" if mnemonic.startswith("BRK") else "vs2"
                values = {f"{source}__l{j}": bits[j] for j in range(count)}
                for name, width in entry["params"]:
                    values.setdefault(name, random.getrandbits(width))
                got = entry["eval"](*[values[name] for name in names])
                want = expected(bits, lane)
                checks += 1
                saw_set += any(bits)
                saw_clear += not any(bits)
                if got != want:
                    failures += 1
                    if failures <= 8:
                        print(f"FAIL {mnemonic} lane {lane}: mask {bits} gave {got}, want {want}")
        if not saw_set or not saw_clear:
            print(f"{mnemonic}: masks were never both empty and non-empty")
            failures += 1

    for mnemonic, expected in {
        "VCPOP_M": lambda bits, count: sum(bits),
        "CNTP_S": lambda bits, count: sum(bits),
        "VFIRST_M": lambda bits, count: (
            bits.index(1) if any(bits) else (1 << 32) - 1
        ),
    }.items():
        entry = specs.get(mnemonic)
        if entry is None:
            print(f"skip {mnemonic}: not present")
            continue
        names = [name for name, _ in entry["params"]]
        count = sum(1 for name in names
                    if name.startswith("vs2__l") or name.startswith("pn__l"))
        empty = 0
        for _ in range(args.cases * 2):
            bits = [random.randint(0, 1) for _ in range(count)]
            empty += not any(bits)
            source = "pn" if mnemonic == "CNTP_S" else "vs2"
            values = {f"{source}__l{j}": bits[j] for j in range(count)}
            for name, width in entry["params"]:
                values.setdefault(name, random.getrandbits(width))
            got = entry["eval"](*[values[name] for name in names])
            want = expected(bits, count)
            checks += 1
            if got != want:
                failures += 1
                if failures <= 8:
                    print(f"FAIL {mnemonic}: mask {bits} gave {got}, want {want}")
        if mnemonic == "VFIRST_M" and not empty:
            # -1 for an empty mask is the case worth reaching; a run that never
            # produced one would leave it untested.
            print(f"{mnemonic}: no empty mask, so the -1 result was never checked")
            failures += 1

    if not checks:
        print("SKIP: no cross-lane instructions")
        return 0
    print(f"{checks} cross-lane checks, {failures} failures")
    print("cross-lane == architecture: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
