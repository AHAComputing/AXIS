#!/usr/bin/env python3
"""Check saturating arithmetic and float predicates against the architecture.

These are written compositionally in the corpus -- an unsigned add saturates
when its sum falls below either operand, a signed one when the operands share a
sign the result does not -- which puts the overflow rule where it can be read
and argued with. It also puts it where it can be *wrong* in the same way in
every backend, so it needs a statement of what saturation means that the
description did not write.

Both properties have a boundary that a uniform-random run mostly misses:
saturation is rare among random 32-bit pairs, and an ordered float comparison
differs from an unordered one only on NaN. So the inputs are drawn against those
boundaries and both sides are required to occur.

Usage: tools/saturating_check.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import importlib.util
import math
import random
import struct
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
MASK32 = (1 << 32) - 1


def signed(value: int) -> int:
    return value - (1 << 32) if value >> 31 else value


def sat_addu(a, b):
    total = a + b
    return MASK32 if total > MASK32 else total


def sat_subu(a, b):
    return 0 if a < b else a - b


def sat_add(a, b):
    total = signed(a) + signed(b)
    if total > 0x7FFFFFFF:
        return 0x7FFFFFFF
    if total < -0x80000000:
        return 0x80000000
    return total & MASK32


def sat_sub(a, b):
    total = signed(a) - signed(b)
    if total > 0x7FFFFFFF:
        return 0x7FFFFFFF
    if total < -0x80000000:
        return 0x80000000
    return total & MASK32


SATURATING = {
    "VSADDU_VV": sat_addu,
    "VSSUBU_VV": sat_subu,
    "VSADD_VV": sat_add,
    "VSSUB_VV": sat_sub,
}


def f32(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits & MASK32))[0]


FLOAT_PREDICATES = {
    "VMFEQ_VV": lambda x, y: int(x == y),
    "VMFLT_VV": lambda x, y: int(x < y),
    "VMFLE_VV": lambda x, y: int(x <= y),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_sat_"))
    golden_path = workdir / "golden_model.py"
    subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(args.axis_file),
         "-o", str(golden_path)],
        check=True, cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location("axis_golden_sat", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)
    specs = golden.AXIS_SPECS

    random.seed(0x5A7)
    checks = failures = 0

    def lanes_of(origin):
        return sorted(
            (entry["scalable_lane"], entry)
            for entry in specs.values()
            if entry.get("scalable_origin") == origin
        )

    for mnemonic, model in SATURATING.items():
        lanes = lanes_of(mnemonic)
        if not lanes:
            print(f"skip {mnemonic}: not present")
            continue
        saturated = normal = 0
        for lane, entry in lanes:
            names = [name for name, _ in entry["params"]]
            for _ in range(args.cases):
                # Half the cases near the boundary, where saturation actually
                # happens; uniform 32-bit pairs almost never overflow.
                if random.random() < 0.5:
                    edge = random.choice(
                        [0, 1, 0x7FFFFFFF, 0x80000000, MASK32, MASK32 - 1]
                    )
                    a = (edge + random.randint(-2, 2)) & MASK32
                    b = (random.choice(
                        [0, 1, 0x7FFFFFFF, 0x80000000, MASK32]
                    ) + random.randint(-2, 2)) & MASK32
                else:
                    a, b = random.getrandbits(32), random.getrandbits(32)
                values = {name: random.getrandbits(w) for name, w in entry["params"]}
                values[f"vs1__l{lane}"], values[f"vs2__l{lane}"] = a, b
                want = model(a, b)
                got = entry["eval"](*[values[name] for name in names])
                checks += 1
                plain = {
                    "VSADDU_VV": (a + b) & MASK32,
                    "VSSUBU_VV": (a - b) & MASK32,
                    "VSADD_VV": (a + b) & MASK32,
                    "VSSUB_VV": (a - b) & MASK32,
                }[mnemonic]
                if want == plain:
                    normal += 1
                else:
                    saturated += 1
                if got != want:
                    failures += 1
                    if failures <= 8:
                        print(
                            f"FAIL {mnemonic} lane {lane}: {hex(a)},{hex(b)} "
                            f"gave 0x{got:x} want 0x{want:x}"
                        )
        print(f"  {mnemonic}: {saturated} saturated, {normal} in range")
        if not saturated or not normal:
            print(f"{mnemonic}: only one side of the boundary was reached")
            failures += 1

    for mnemonic, model in FLOAT_PREDICATES.items():
        lanes = lanes_of(mnemonic)
        if not lanes:
            print(f"skip {mnemonic}: not present")
            continue
        with_nan = 0
        for lane, entry in lanes:
            names = [name for name, _ in entry["params"]]
            for _ in range(args.cases):
                def draw():
                    pick = random.random()
                    if pick < 0.2:
                        return random.choice([0x7FC00000, 0x7F800000, 0xFF800000, 0])
                    return struct.unpack(
                        "<I", struct.pack("<f", math.ldexp(1.0 + random.random(),
                                                           random.randint(-4, 6)))
                    )[0]
                a, b = draw(), draw()
                values = {name: random.getrandbits(w) for name, w in entry["params"]}
                values[f"vs1__l{lane}"], values[f"vs2__l{lane}"] = a, b
                x, y = f32(a), f32(b)
                if x != x or y != y:
                    with_nan += 1
                want = model(x, y)
                got = entry["eval"](*[values[name] for name in names])
                checks += 1
                if got != want:
                    failures += 1
                    if failures <= 8:
                        print(f"FAIL {mnemonic} lane {lane}: {x} vs {y} gave {got} want {want}")
        print(f"  {mnemonic}: {with_nan} case(s) involving NaN")
        if not with_nan:
            # An ordered comparison differs from an unordered one only on NaN,
            # so a run without any tests nothing about the ordering.
            print(f"{mnemonic}: no NaN reached, so orderedness was never tested")
            failures += 1

    # --- the sticky flag ----------------------------------------------------
    # A saturating instruction records saturation in vxsat and leaves it set:
    # new = old | saturated. The distinguishing case is old = 1 with no
    # saturation, where a plain assignment would clear a flag that must stay
    # set -- so that case is required to occur rather than hoped for.
    lift = json.loads(subprocess.run(
        [*axis_prefix(), "emit-lift-json", str(args.axis_file)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT,
    ).stdout)
    sticky_models = {
        "VSADDU_VV_X": lambda a, b: int(sat_addu(a, b) != (a + b) & MASK32),
        "VSSUBU_VV_X": lambda a, b: int(sat_subu(a, b) != (a - b) & MASK32),
        "VSADD_VV_X": lambda a, b: int(sat_add(a, b) != (a + b) & MASK32),
    }
    stuck = flagged = 0
    for instruction in lift["instructions"]:
        origin = instruction.get("scalable_origin")
        model = sticky_models.get(origin)
        if model is None:
            continue
        lane = instruction["scalable_lane"]
        setstate = next((e for e in instruction.get("effects") or []
                         if e.get("kind") == "setstate"), None)
        if setstate is None:
            print(f"FAIL {instruction['mnemonic']}: no sticky state write")
            failures += 1
            continue
        for _ in range(args.cases):
            a, b = (random.choice([0, 1, 0x7FFFFFFF, 0x80000000, MASK32])
                    + random.randint(-2, 2)) & MASK32, random.getrandbits(32)
            old = random.randint(0, 1)
            env = {f"vs1__l{lane}": a, f"vs2__l{lane}": b, "vxsat": old}
            saturated = model(a, b)
            want = old | saturated
            got = golden._eval_axis_expr(setstate["value"], env, setstate["eval_width"])
            checks += 1
            if saturated:
                flagged += 1
            if old and not saturated:
                stuck += 1
            if got != want:
                failures += 1
                if failures <= 8:
                    print(
                        f"FAIL {origin} lane {lane}: vxsat {old} with "
                        f"{'a saturating' if saturated else 'a normal'} case gave "
                        f"{got}, want {want}"
                    )
    if sticky_models:
        print(f"  vxsat: {flagged} saturating case(s), {stuck} where an already-set "
              f"flag had to survive")
        if not stuck:
            print("vxsat: never tested that a set flag survives a non-saturating case")
            failures += 1
        if not flagged:
            print("vxsat: never tested that saturation sets the flag")
            failures += 1

    if not checks:
        print("SKIP: no saturating or float-predicate instructions")
        return 0
    print(f"{checks} checks, {failures} failures")
    print("saturation and float predicates == architecture: "
          + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
