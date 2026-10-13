#!/usr/bin/env python3
"""Check limb storage against a reference that does not use limbs.

`exec_wide_check.py` proves the executors honour the published register-class
table: it reads the same table they do, applies the same stitch, and compares.
That catches an executor that stitches wrongly and cannot catch a *layout* that
is wrong, because both sides split a register into limbs the same way.

So this reference does not split. A 128-bit register is one number here, a view
is a bit range of it, and limbs appear exactly once -- at the ABI boundary,
where the contract is:

    slot base + k holds bits [64k, 64k + 64) of the register,
    base = class_offset + index * (register_bits / 64)

Everything else is stated in whole-register terms: reading view (w, off) yields
bits [off, off + w); writing it replaces those bits and either keeps or zeroes
the *register's* other bits. An implementation that zeroes only the slot it
touched, or reads a straddling view from one slot, disagrees here.

Usage: tools/limb_check.py <input.axisl> [--lang c|rust]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exec_wide_check as wide           # for emit/load/build_and_run only

AXIS_ROOT = Path(__file__).resolve().parent.parent

# The architecture these classes describe: (register bits, class offset in the
# flat file, view width, view offset, preserves). Written here from what the
# views mean, not read back from the table under test.
ARCHITECTURE = {
    "v128_s0":    (128, 0, 32,  0, True),
    "v128_s1":    (128, 0, 32, 32, True),
    "v128_d1":    (128, 0, 64, 64, True),
    "v128_cross": (128, 0, 32, 48, True),
    "v128_z0":    (128, 0, 32,  0, False),
}

# What each instruction computes, from its value, at 64 bits. The corpus is
# small and fixed, so the semantics are stated rather than derived -- a
# reference that read the description back would be checking it against itself.
SEMANTICS = {
    "VMOV_S0": lambda v: v,
    "VMOV_S1": lambda v: v,
    "VMOV_D1": lambda v: v,
    "VMOV_X": lambda v: v,
    "VMOV_Z0": lambda v: v,
    "VADD_XD": lambda v: (v + 1) & ((1 << 64) - 1),
    "VADD_DX": lambda v: (v + 1) & ((1 << 64) - 1),
}


def view_read(register: int, kind: str) -> int:
    """Bits [offset, offset + width) of the whole register."""
    _bits, _base, width, offset, _preserves = ARCHITECTURE[kind]
    return (register >> offset) & ((1 << width) - 1)


def view_write(register: int, kind: str, value: int) -> int:
    """The whole register afterwards.

    Not the slot, and not the limb: a zeroing view leaves the register's other
    bits zero however far away they are, which is the whole reason this is
    stated over the register rather than over storage.
    """
    bits, _base, width, offset, preserves = ARCHITECTURE[kind]
    value &= (1 << width) - 1
    cover = ((1 << width) - 1) << offset
    kept = (register & ~cover) if preserves else 0
    return (kept | (value << offset)) & ((1 << bits) - 1)


# Every view above names one register file, so the storage layout is a property
# of the file rather than of the view -- asserted rather than assumed, because
# using a *view's* layout to place a register works by coincidence while they
# all agree and stops the moment one does not.
FILE_BITS, FILE_BASE = {(bits, base) for bits, base, *_ in ARCHITECTURE.values()}.pop()
assert len({(bits, base) for bits, base, *_ in ARCHITECTURE.values()}) == 1
LIMBS = FILE_BITS // 64


def to_slots(register: int, index: int, regs: list) -> None:
    """Place a whole register into the flat array -- the one place limbs live."""
    for k in range(LIMBS):
        regs[FILE_BASE + index * LIMBS + k] = (register >> (64 * k)) & ((1 << 64) - 1)


def slot_span(index: int) -> range:
    return range(FILE_BASE + index * LIMBS, FILE_BASE + (index + 1) * LIMBS)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=4)
    parser.add_argument("--lang", default="c", choices=("c", "rust", "python"))
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_limb_"))
    wide.emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    if args.lang == "python":
        wide.emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
        wide.emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    else:
        wide.emit(args.axis_file, "emit-exec-c", workdir / "axis_exec.h")
        wide.emit(args.axis_file, "emit-lift-c", workdir / "axis_lift.h")
        wide.emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    wide.emit(args.axis_file, "emit-roundtrip-json", fixtures_path)
    sys.path.insert(0, str(workdir))
    lift = wide.load(workdir / "axis_lift.py", "axis_lift_limb")
    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])

    slots = lift.REGISTER_FILE_SLOTS
    random.seed(0x11B5)
    cases, straddling, zeroing, skipped = [], 0, 0, 0
    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = lift.decode(word, test.get("isa"))
        if entry is None:
            continue
        kinds = {op["name"]: op["kind"] for op in entry["operands"]}
        if any(k not in ARCHITECTURE for k in kinds.values()):
            skipped += 1
            continue
        if test["mnemonic"] not in SEMANTICS:
            skipped += 1
            continue
        fx = {o["name"]: o["value"] for o in test["operands"]}
        src = next(op["name"] for op in entry["operands"] if op["role"] == "in")
        dst = next(op["name"] for op in entry["operands"] if op["role"] == "out")

        for _ in range(args.cases):
            # One value per *storage*, keyed by register number: the views all
            # name the same file, so rd and rs at the same index alias.
            whole = {}
            for name, kind in kinds.items():
                whole.setdefault(fx[name], random.getrandbits(
                    ARCHITECTURE[kind][0]))
            regs = [0] * slots
            for index, value in whole.items():
                to_slots(value, index, regs)

            read = view_read(whole[fx[src]], kinds[src])
            computed = SEMANTICS[test["mnemonic"]](read)
            after = dict(whole)
            after[fx[dst]] = view_write(after[fx[dst]], kinds[dst], computed)

            expected = [0] * slots
            for index, value in after.items():
                to_slots(value, index, expected)
            checks = [(slot, expected[slot])
                      for index in after for slot in slot_span(index)]

            _b, _o, width, offset, preserves = ARCHITECTURE[kinds[dst]]
            if offset % 64 and offset % 64 + width > 64:
                straddling += 1
            if not preserves and ARCHITECTURE[kinds[dst]][0] > 64:
                zeroing += 1
            cases.append({
                "mnemonic": test["mnemonic"], "word": word,
                "isa": entry.get("isa") or "", "pc": 0, "regs": regs,
                "seed": [], "state": [], "reg_checks": checks,
                "mem_checks": [], "state_write": None, "next_pc": None,
                "trap": None, "result": None, "slots": slots,
            })

    if not cases:
        print("SKIP: no instruction uses a class this reference states")
        return 0

    if args.lang == "python":
        # The Python executor is driven in-process rather than compiled: it
        # mutates a slot -> value map, which is the same flat file the compiled
        # executors take as an array.
        executor = wide.load(workdir / "axis_exec.py", "axis_exec_limb")
        failures = 0
        for case in cases:
            regs = dict(enumerate(case["regs"]))
            out = executor.step(case["word"], regs, isa=case["isa"] or None)
            if out is None:
                print(f"FAIL {case['mnemonic']} undecodable")
                failures += 1
                continue
            for slot, value in case["reg_checks"]:
                if regs.get(slot, 0) != value:
                    print(f"FAIL {case['mnemonic']} slot {slot}: "
                          f"{regs.get(slot, 0):#x} != {value:#x}")
                    failures += 1
        returncode = 1 if failures else 0
    else:
        result = wide.build_and_run(cases, workdir, args.axis_file, args.lang)
        failures = sum(1 for line in result.stdout.splitlines()
                       if line.startswith("FAIL"))
        returncode = result.returncode
    print(f"{len(cases)} cases against a whole-register reference, "
          f"{failures} failures")
    print(f"  {straddling} write a view across a limb boundary, "
          f"{zeroing} zero a register wider than one limb"
          + (f", {skipped} fixture(s) outside this reference" if skipped else ""))
    ok = returncode == 0
    # Both are the reason limbs exist. Without them this reduces to the
    # single-slot check it was written to be independent of.
    if not straddling:
        print("no straddling write: the stitch is untested")
        ok = False
    if not zeroing:
        print("no multi-limb zeroing write: the write policy is untested")
        ok = False
    label = {"rust": "Rust", "python": "Python"}.get(args.lang, "C")
    print(f"limbs == whole-register reference ({label}): "
          + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
