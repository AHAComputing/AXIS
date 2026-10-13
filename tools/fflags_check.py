#!/usr/bin/env python3
"""Prove `fflags` accrues the exceptions RISC-V says each operation raises.

The differential ladder proves the backends agree about the flags. It cannot
prove they are right: the rule is stated once, in the corpus, and every backend
reads that one statement, so a comparison that signalled on the wrong kind of
NaN would be emitted identically by all of them and every gate would pass. The
rules are an *external* fact, so this gate restates them from the RISC-V spec
and requires the corpus to match.

Two halves, because witnesses and properties fail differently. The table drives
named cases whose expected flags are written out by hand -- the sNaN that FEQ
must signal on and the qNaN it must not, the conversion that saturates and the
one that merely rounds. The property sweep then requires, over random patterns,
the invariants no finite table can show: that an ordering comparison signals on
*every* NaN and an equality on exactly the signalling ones, that a widening
conversion is never inexact, that underflow and overflow never appear without
inexact, and that no conversion ever divides by zero.

Scope: the golden model, which is the corpus's most direct reading. That the C
header, the executors, the Rust module and the SMT encoding agree with it is
what the rest of the ladder is for -- `c_vs_golden` and `exec_wide_check` drive
these same instructions over tens of thousands of random patterns, NaNs and
saturating magnitudes among them.

Usage: tools/fflags_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

NV, DZ, OF, UF, NX = 16, 8, 4, 2, 1

# Single- and double-precision patterns. A NaN is signalling when the
# mantissa's top bit is clear, which is the only thing telling the two apart.
QNAN32, SNAN32, INF32 = 0x7fc00000, 0x7f800001, 0x7f800000
QNAN64 = 0x7ff8000000000000
SNAN64 = 0x7ff0000000000001


def s(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def d(value: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def u32(value: int) -> int:
    return value & 0xffffffff


# (mnemonic, operands, expected flags, why). Written from the spec, not from
# the corpus: this is the half that would catch the corpus stating a rule that
# is self-consistent and wrong.
def witnesses(FMA="FMADD_S"):
    one, two = s(1.0), s(2.0)
    return [
        # Ordering comparisons signal on any NaN; equality only on signalling.
        ("FLT_S", {"rs1": one, "rs2": two}, 0, "ordered operands"),
        ("FLT_S", {"rs1": QNAN32, "rs2": one}, NV, "any NaN is unordered"),
        ("FLT_S", {"rs1": one, "rs2": SNAN32}, NV, "signalling NaN"),
        ("FLE_S", {"rs1": QNAN32, "rs2": one}, NV, "any NaN is unordered"),
        ("FEQ_S", {"rs1": one, "rs2": two}, 0, "ordered operands"),
        ("FEQ_S", {"rs1": QNAN32, "rs2": one}, 0, "equality against qNaN is false, not invalid"),
        ("FEQ_S", {"rs1": SNAN32, "rs2": one}, NV, "signalling NaN"),
        ("FLT_D", {"rs1": QNAN64, "rs2": d(1.0)}, NV, "any NaN is unordered"),
        ("FEQ_D", {"rs1": QNAN64, "rs2": d(1.0)}, 0, "equality against qNaN is false, not invalid"),
        ("FEQ_D", {"rs1": SNAN64, "rs2": d(1.0)}, NV, "signalling NaN"),
        # FMIN/FMAX take IEEE minNum/maxNum: a quiet NaN is absorbed.
        ("FMIN_S", {"rs1": QNAN32, "rs2": one}, 0, "qNaN operand is absorbed"),
        ("FMIN_S", {"rs1": SNAN32, "rs2": one}, NV, "signalling NaN"),
        ("FMAX_D", {"rs1": d(1.0), "rs2": SNAN64}, NV, "signalling NaN"),
        # Float to integer: NaN, infinity and out-of-range all saturate, which
        # RISC-V reports as invalid -- and never together with inexact.
        ("FCVT_W_S", {"rs1": s(1.0)}, 0, "exact"),
        ("FCVT_W_S", {"rs1": s(1.5)}, NX, "fraction discarded"),
        ("FCVT_W_S", {"rs1": s(-1.5)}, NX, "fraction discarded"),
        ("FCVT_W_S", {"rs1": s(-2.0 ** 31)}, 0, "the most negative int32 is exact"),
        ("FCVT_W_S", {"rs1": s(2.0 ** 31)}, NV, "one past the largest int32"),
        ("FCVT_W_S", {"rs1": INF32}, NV, "infinity saturates"),
        ("FCVT_W_S", {"rs1": QNAN32}, NV, "NaN converts to zero, invalidly"),
        ("FCVT_WU_S", {"rs1": s(-1.0)}, NV, "negative, below the unsigned range"),
        ("FCVT_WU_S", {"rs1": s(-0.5)}, NX, "truncates to zero: in range, inexact"),
        ("FCVT_WU_S", {"rs1": s(3.25)}, NX, "fraction discarded"),
        # Integer to float: inexact exactly when the significand is too narrow.
        ("FCVT_S_W", {"rs1": 3}, 0, "small integers are exact"),
        ("FCVT_S_W", {"rs1": 1 << 24}, 0, "a power of two is exact at any width"),
        ("FCVT_S_W", {"rs1": (1 << 24) + 1}, NX, "25 significant bits, binary32 holds 24"),
        ("FCVT_S_W", {"rs1": u32(-((1 << 24) + 1))}, NX, "25 significant bits, negative"),
        ("FCVT_D_W", {"rs1": (1 << 24) + 1}, 0, "binary64 holds 53"),
        # Float to float: widening is exact, narrowing rounds.
        ("FCVT_D_S", {"rs1": s(1.5)}, 0, "widening is exact"),
        ("FCVT_D_S", {"rs1": QNAN32}, 0, "a quiet NaN widens quietly"),
        ("FCVT_D_S", {"rs1": SNAN32}, NV, "a signalling NaN signals"),
        ("FCVT_S_D", {"rs1": d(1.5)}, 0, "representable in binary32"),
        ("FCVT_S_D", {"rs1": d(0.1)}, NX, "not representable in binary32"),
        ("FCVT_S_D", {"rs1": d(1e300)}, OF | NX, "beyond binary32's range"),
        ("FCVT_S_D", {"rs1": d(1e-300)}, UF | NX, "below binary32's subnormals"),
        ("FCVT_S_D", {"rs1": SNAN64}, NV, "a signalling NaN signals"),
        # Arithmetic. These four are regressions the differential ladder found
        # only once the executor drew from FP classes rather than uniform bits,
        # and each is a rule the corpus cannot state wrongly without saying
        # something false about IEEE-754.
        ("FADD_S_RNE", {"rs1": INF32, "rs2": INF32 | 0x80000000}, NV,
         "infinity plus its negation has no value"),
        ("FSUB_S_RNE", {"rs1": INF32, "rs2": INF32}, NV,
         "infinity minus itself has no value"),
        ("FADD_S_RNE", {"rs1": INF32, "rs2": INF32}, 0,
         "like signs are an infinity, and exact"),
        (FMA, {"rs1": INF32, "rs2": 0, "rs3": QNAN32}, NV,
         "an invalid product signals whatever the addend is (IEEE-754 7.2)"),
        (FMA, {"rs1": 0, "rs2": INF32, "rs3": s(1.0)}, NV,
         "zero times infinity has no value"),
        (FMA, {"rs1": SNAN32, "rs2": s(1.0), "rs3": s(1.0)}, NV,
         "a signalling NaN signals -- and stops signalling if read back "
         "through a float, which is how this was missed"),
        (FMA, {"rs1": QNAN32, "rs2": s(1.0), "rs3": s(1.0)}, 0,
         "a quiet NaN propagates quietly"),
        # Tininess is detected BEFORE rounding: the exact sum here is just under
        # the smallest normal and rounds up to it, so the rounded result is not
        # tiny but the exact one was. IEEE-754 permits either rule and requires
        # an implementation to say which; this witness is where AXIS says it.
        (FMA, {"rs1": 0x00800000, "rs2": 0x80000001, "rs3": 0x00800000},
         UF | NX, "tiny before rounding, inexact, so underflow"),
        # Square root of an infinity is that infinity, exactly. The golden
        # model formed a Fraction of the result to ask whether it was exact,
        # and Fraction(inf) raises -- outside the handler that caught the same
        # throw elsewhere, so this crashed rather than answered.
        ("FSQRT_S_RNE", {"rs1": INF32}, 0, "the square root of infinity is exact"),
        ("FSQRT_S_RNE", {"rs1": INF32 | 0x80000000}, NV,
         "the square root of a negative has no value"),
        ("FSQRT_S_RNE", {"rs1": s(4.0)}, 0, "an exact root signals nothing"),
        ("FSQRT_S_RNE", {"rs1": s(2.0)}, NX, "an irrational root is inexact"),
    ]


def is_nan(pattern: int, bits: int) -> bool:
    exponent = 0xff if bits == 32 else 0x7ff
    shift = 23 if bits == 32 else 52
    mantissa = (1 << shift) - 1
    return (pattern >> shift) & exponent == exponent and pattern & mantissa != 0


def is_snan(pattern: int, bits: int) -> bool:
    quiet = 1 << (22 if bits == 32 else 51)
    return is_nan(pattern, bits) and pattern & quiet == 0


def flags(golden, mnemonic: str, operands: dict) -> int:
    """The `fflags` this instruction accrues, starting from clear."""
    state = golden.apply_state_effects(mnemonic, operands, {"fflags": 0, "frm": 0})
    return state.get("fflags", 0)


PATTERNS = 4000


def properties(golden) -> int:
    """The invariants no finite table can show."""
    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        if failures < 10:
            print(f"FAIL {message}")
        failures += 1

    def sample(bits: int) -> int:
        # Half uniform, half drawn from the shapes that decide these rules:
        # NaNs of both kinds, infinities, and magnitudes near the integer
        # boundaries where a conversion starts to saturate.
        if random.random() < 0.5:
            return random.getrandbits(bits)
        if bits == 32:
            return random.choice([
                QNAN32, SNAN32, INF32, INF32 | 0x80000000,
                s(random.uniform(-3e9, 3e9)), s(random.uniform(-2.0, 2.0)),
                s(2.0 ** 31), s(-(2.0 ** 31)), 0, 0x80000000, 1,
            ])
        return random.choice([
            QNAN64, SNAN64, d(float("inf")), d(float("-inf")),
            d(random.uniform(-3e9, 3e9)), d(random.uniform(-2.0, 2.0)),
            d(random.uniform(-1e-310, 1e-310)), d(1e300), 0, 1,
        ])

    for _ in range(PATTERNS):
        for suffix, bits in (("S", 32), ("D", 64)):
            a, b = sample(bits), sample(bits)
            unordered = is_nan(a, bits) or is_nan(b, bits)
            signalling = is_snan(a, bits) or is_snan(b, bits)

            for mnemonic in (f"FLT_{suffix}", f"FLE_{suffix}"):
                got = flags(golden, mnemonic, {"rs1": a, "rs2": b})
                want = NV if unordered else 0
                if got != want:
                    fail(f"{mnemonic}({a:#x}, {b:#x}): {got} != {want} "
                         f"(an ordering comparison signals on every NaN)")

            got = flags(golden, f"FEQ_{suffix}", {"rs1": a, "rs2": b})
            want = NV if signalling else 0
            if got != want:
                fail(f"FEQ_{suffix}({a:#x}, {b:#x}): {got} != {want} "
                     f"(equality signals on signalling NaNs only)")

            for mnemonic in (f"FMIN_{suffix}", f"FMAX_{suffix}"):
                got = flags(golden, mnemonic, {"rs1": a, "rs2": b})
                want = NV if signalling else 0
                if got != want:
                    fail(f"{mnemonic}({a:#x}, {b:#x}): {got} != {want} "
                         f"(minNum/maxNum absorb a quiet NaN)")

            # Conversions: shape invariants that hold whatever the value.
            for mnemonic in (f"FCVT_W_{suffix}", f"FCVT_WU_{suffix}",
                             f"FCVT_D_{suffix}" if suffix == "S" else f"FCVT_S_{suffix}"):
                got = flags(golden, mnemonic, {"rs1": a})
                if got & ~(NV | OF | UF | NX):
                    fail(f"{mnemonic}({a:#x}): {got} sets a bit outside NV/OF/UF/NX")
                if got & DZ:
                    fail(f"{mnemonic}({a:#x}): a conversion cannot divide by zero")
                if got & (OF | UF) and not got & NX:
                    fail(f"{mnemonic}({a:#x}): {got} claims overflow or underflow "
                         f"without inexact")

            # Float to integer saturates or rounds, never both.
            for mnemonic in (f"FCVT_W_{suffix}", f"FCVT_WU_{suffix}"):
                got = flags(golden, mnemonic, {"rs1": a})
                if got & NV and got != NV:
                    fail(f"{mnemonic}({a:#x}): {got} is both saturated and inexact")

            # Widening loses nothing, so only a signalling NaN says anything.
            if suffix == "S":
                got = flags(golden, "FCVT_D_S", {"rs1": a})
                want = NV if is_snan(a, 32) else 0
                if got != want:
                    fail(f"FCVT_D_S({a:#x}): {got} != {want} (widening is exact)")

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_fflags_"))
    output = workdir / "golden_model.py"
    subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(args.axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location("golden", output)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    failures = 0
    # RV32 spells the flag-accruing fused multiply-add with its rounding mode;
    # RV64 has a bare one. Ask the corpus rather than assume.
    FMA = next((name for name in ("FMADD_S", "FMADD_S_RNE")
                if name in golden.STATE_EFFECTS), "FMADD_S")
    table = witnesses(FMA)
    for mnemonic, operands, want, why in table:
        if mnemonic not in golden.STATE_EFFECTS:
            print(f"FAIL {mnemonic}: accrues no state, so it cannot accrue {why}")
            failures += 1
            continue
        got = flags(golden, mnemonic, operands)
        if got != want:
            shown = ", ".join(f"{k}={v:#x}" for k, v in operands.items())
            print(f"FAIL {mnemonic}({shown}): fflags {got} != {want} -- {why}")
            failures += 1

    failures += properties(golden)

    print(f"{len(table)} witnesses and {PATTERNS} random pattern pairs checked")
    print("fflags agrees with RISC-V's exception rules: "
          + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
