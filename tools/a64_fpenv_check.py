#!/usr/bin/env python3
"""Prove AArch64's FPCR and FPSR mean what AArch64 says they mean.

The `_rm` and `_fx` operators are ISA-neutral by construction: one takes the
rounding mode as an integer, the other returns the exception word as one. That
neutrality is the thing worth checking, because the two ports differ.

The **mode** ports for free. `_rm` takes the encoding AArch64 already uses --
00 nearest, 01 toward +infinity, 10 toward -infinity, 11 toward zero -- so
`FPCR.RMode` reaches it through a field extraction and nothing else. RISC-V is
the ISA that maps, and does: its RTZ is 1 and it passes 3.

The **exception word** does not. `_fx` returns RISC-V's `fflags` order, invalid
at bit 4 down to inexact at bit 0, and AArch64's FPSR is that reversed. The
corpus states the reversal as an ordinary expression, and a reversal stated
once, read by six backends, is exactly what a differential cannot check: every
backend would agree about the wrong order.

So this gate asks the two questions separately. For the mode it requires the
IEEE relations between directions rather than restating a rounding algorithm --
toward +infinity lands at or above nearest, toward zero agrees with the
direction that faces zero, and an inexact result actually moves. For the flags
it requires each condition to land on the AArch64 bit, by number.

Usage: tools/a64_fpenv_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import importlib.util
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# FPCR.RMode, in bits 23:22.
RN, RP, RM, RZ = 0, 1, 2, 3
MODE_NAMES = {RN: "nearest", RP: "toward +inf", RM: "toward -inf", RZ: "toward zero"}

# FPSR exception bits, by position. The whole point of the gate is that these
# are *not* fflags' positions.
IOC, DZC, OFC, UFC, IXC = 1 << 0, 1 << 1, 1 << 2, 1 << 3, 1 << 4
FPSR_NAMES = {IOC: "IOC", DZC: "DZC", OFC: "OFC", UFC: "UFC", IXC: "IXC"}


def d(value: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def f(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits & 0xFFFFFFFFFFFFFFFF))[0]


INF = d(float("inf"))
NINF = d(float("-inf"))
HUGE = d(1.7976931348623157e308)
TINY = d(5e-324)


def fpcr_for(mode: int) -> int:
    """A control register selecting `mode` and nothing else."""
    return mode << 22


def resolve(lift, *candidates: str) -> str:
    """The first candidate this corpus actually defines.

    The focused corpus prefixes its mnemonics; the translation seed spells them
    the way AArch64 does. The rules being checked are the same either way, so
    the gate asks the corpus which names it uses rather than owning a list.
    """
    have = {entry["mnemonic"] for entry in lift.AXIS_LIFT_TABLE}
    for name in candidates:
        if name in have:
            return name
    raise SystemExit(f"none of {candidates} is defined by this corpus")


def bind(lift, mnemonic: str, values) -> dict:
    """Witness values against the instruction's inputs, positionally.

    The two corpora name these operands differently -- `vn`/`vm` in the focused
    one, `rn`/`rm` in the translation seed, which spells them the way AArch64
    does. Position is what the witnesses actually mean.
    """
    entry = next(e for e in lift.AXIS_LIFT_TABLE if e["mnemonic"] == mnemonic)
    inputs = [op["name"] for op in entry["operands"] if op.get("role") == "in"]
    if len(inputs) != len(values):
        raise SystemExit(
            f"{mnemonic} takes {len(inputs)} inputs, witness gives {len(values)}"
        )
    return dict(zip(inputs, values))


def effects_of(lift, mnemonic: str):
    entry = next(e for e in lift.AXIS_LIFT_TABLE if e["mnemonic"] == mnemonic)
    return entry["effects"]


def value_of(golden, lift, mnemonic: str, values, fpcr: int) -> int:
    """The register this instruction writes, with FPCR in force."""
    for eff in effects_of(lift, mnemonic):
        if eff["kind"] == "set":
            env = bind(lift, mnemonic, values)
            env["fpcr"] = fpcr
            return golden._eval_axis_expr(eff["value"], env, eff["eval_width"])
    raise AssertionError(f"{mnemonic} writes no register")


def fpsr_of(golden, lift, mnemonic: str, values, fpcr: int = 0) -> int:
    """The FPSR this instruction accrues, starting from clear."""
    state = golden.apply_state_effects(
        mnemonic, bind(lift, mnemonic, values), {"fpsr": 0, "fpcr": fpcr}
    )
    return state.get("fpsr", 0)


def check_modes(golden, lift, name) -> int:
    """FPCR selects a direction, and the four directions relate as IEEE says."""
    failures = 0

    # Operand pairs whose exact result is not representable, so the direction
    # is observable at all -- one positive, one negative, because toward-zero
    # agrees with a different neighbour in each sign.
    cases = [
        ("1.0 / 3.0", name("A64_FDIV_D"), (d(1.0), d(3.0)), +1),
        ("-1.0 / 3.0", name("A64_FDIV_D"), (d(-1.0), d(3.0)), -1),
        ("1.0 / 49.0", name("A64_FDIV_D"), (d(1.0), d(49.0)), +1),
        ("sqrt 2.0", name("A64_FSQRT_D"), (d(2.0),), +1),
    ]

    for label, mnemonic, operands, sign in cases:
        got = {mode: f(value_of(golden, lift, mnemonic, operands, fpcr_for(mode)))
               for mode in (RN, RP, RM, RZ)}

        # The two directed modes must straddle: rounding up is never below
        # rounding down, and for an inexact result they differ.
        if not got[RP] > got[RM]:
            print(f"FAIL {label}: toward +inf ({got[RP]!r}) is not above "
                  f"toward -inf ({got[RM]!r}) -- the field is not selecting")
            failures += 1

        # Nearest lands on one of the two neighbours the directed modes found.
        if got[RN] not in (got[RP], got[RM]):
            print(f"FAIL {label}: nearest ({got[RN]!r}) is neither neighbour "
                  f"({got[RM]!r}, {got[RP]!r})")
            failures += 1

        # Toward zero is toward -inf for a positive result and toward +inf for
        # a negative one. This is the pair a swapped 01/11 encoding breaks.
        want_rz = got[RM] if sign > 0 else got[RP]
        if got[RZ] != want_rz:
            facing = "toward -inf" if sign > 0 else "toward +inf"
            print(f"FAIL {label}: toward zero ({got[RZ]!r}) does not agree with "
                  f"{facing} ({want_rz!r})")
            failures += 1

    # And a mode the corpus does not read would make all four equal, which the
    # straddle above already catches -- but say it directly, because that is the
    # failure a corpus gets by forgetting the FPCR term entirely.
    spread = {value_of(golden, lift, name("A64_FDIV_D"),
                       (d(1.0), d(3.0)), fpcr_for(mode))
              for mode in (RN, RP, RM, RZ)}
    if len(spread) < 2:
        print("FAIL: every FPCR mode gives the same result -- the control "
              "register is not being read")
        failures += 1
    return failures


def check_flags(golden, lift, name) -> int:
    """Each condition lands on the AArch64 bit, which is not the fflags bit."""
    failures = 0
    cases = [
        ("invalid: inf - inf", name("A64_FSUB_D"), (INF, INF), IOC),
        ("invalid: sqrt of a negative", name("A64_FSQRT_D"), (d(-1.0),), IOC),
        ("divide by zero", name("A64_FDIV_D"), (d(1.0), d(0.0)), DZC),
        ("overflow", name("A64_FMUL_D"), (HUGE, HUGE), OFC | IXC),
        ("underflow", name("A64_FMUL_D"), (TINY, TINY), UFC | IXC),
        ("inexact", name("A64_FDIV_D"), (d(1.0), d(3.0)), IXC),
        ("exact: 1.0 + 1.0", name("A64_FADD_D"), (d(1.0), d(1.0)), 0),
        ("exact: 2.0 * 4.0", name("A64_FMUL_D"), (d(2.0), d(4.0)), 0),
    ]
    for label, mnemonic, operands, want in cases:
        got = fpsr_of(golden, lift, mnemonic, operands)
        if got != want:
            names = "|".join(n for b, n in FPSR_NAMES.items() if want & b) or "none"
            shown = "|".join(n for b, n in FPSR_NAMES.items() if got & b) or "none"
            print(f"FAIL {label}: FPSR {got:#07b} ({shown}) != {want:#07b} ({names})")
            failures += 1

    # Accrual: the register only gains bits, which is what makes MSR the way to
    # clear it.
    divide = name("A64_FDIV_D")
    state = golden.apply_state_effects(
        divide, bind(lift, divide, (d(1.0), d(0.0))), {"fpsr": IXC, "fpcr": 0}
    )
    if state["fpsr"] != (IXC | DZC):
        print(f"FAIL accrual: {state['fpsr']:#07b} lost a bit that was already set")
        failures += 1

    # And a write replaces rather than accrues, or nothing could clear it.
    clear = name("A64_MSR_FPSR")
    state = golden.apply_state_effects(
        clear, bind(lift, clear, (0,)), {"fpsr": IOC | IXC, "fpcr": 0}
    )
    if state["fpsr"] != 0:
        print(f"FAIL clear: MSR left {state['fpsr']:#07b}")
        failures += 1
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "aarch64_fp_env.axisl")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_a64fp_"))
    for command, name in (("emit-golden-python", "golden_model.py"),
                          ("emit-lift-python", "axis_lift.py")):
        subprocess.run([*axis_prefix(), command, str(args.axis_file),
                        "-o", str(workdir / name)], check=True, cwd=AXIS_ROOT)

    def load(name, path):
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    golden = load("golden", workdir / "golden_model.py")
    lift = load("axis_lift", workdir / "axis_lift.py")

        # One resolver, shared by both halves.
    def name(prefixed: str) -> str:
        return resolve(lift, prefixed, prefixed[len("A64_"):])

    failures = check_modes(golden, lift, name) + check_flags(golden, lift, name)
    print("FPCR selects the direction and FPSR accrues in AArch64's order: "
          + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
