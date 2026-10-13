#!/usr/bin/env python3
"""bfloat16 rounds correctly, against exact arithmetic rather than itself. Gate.

bf16 expands at elaboration into integer bit work -- widening is a shift,
narrowing is an add and a shift -- so every backend consumes ordinary integer
semantics and they agree with each other for free. That agreement is therefore
worth nothing here: they are all consuming the same expansion. What has to be
checked is whether the expansion is RIGHT.

    (x + 0x7fff + ((x >> 16) & 1)) >> 16

is round-to-nearest-even and it is not obvious. The oracle for it is exact
rational arithmetic: decode the f32 exactly, find the two bf16 values it lies
between, compare against their midpoint as a Fraction, and break a tie towards
the even pattern. Nothing in that shares a line with the trick it checks.

Four properties:

  1. **widening is exact**, over all 65536 bf16 patterns -- the widened value
     equals the one decoded from the bf16's own sign, exponent and fraction,
     computed as a Fraction. This is what "bf16 is f32's top half" means and
     the gate that would notice if it stopped being true. And it reads only the
     low half of the register it is given, which a 16-bit sweep cannot see:
     every such pattern has a zero high half, so the mask is unchecked until
     something puts junk above it;
  2. **narrowing is correctly rounded**, over patterns chosen to land on both
     sides of every boundary, against the rational oracle;
  3. **round trip**: bf16 -> f32 -> bf16 is the identity on every pattern that
     is not a NaN, and every NaN lands on the canonical one;
  4. **the outcomes occur**: round up, round down, tie-to-even, overflow to
     infinity, and NaN. Without this the second holds vacuously -- and ties are
     the case the `& 1` exists for, so a run that never tied would be proving
     the half of the expression that is obvious.

Injection-checked: dropping the `& 1` tie term, rounding by truncation, and
answering NaN with the rounding arithmetic instead of selecting the canonical
pattern -- the first two fail the rounding property, the third the round trip.

⚠️ A fourth injection -- widening without masking to 16 bits -- does NOT fail,
and the claim that it would was removed rather than kept as decoration. The
mask is redundant at i32: the shift moves anything above bit 15 past bit 31,
where the evaluation width discards it. That was found by running the
injection rather than by reading the expression, which is the only reason it
is known.

Usage: tools/bf16_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import subprocess
import sys
import tempfile
from fractions import Fraction
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
CANONICAL_NAN = 0x7FC0


def bf16_value(pattern: int, virtual: bool = False):
    """The exact value of a bf16 magnitude pattern, as a Fraction.

    `virtual` extends the format one exponent past its top so a midpoint
    against "the next value after the largest finite" can be computed -- which
    is what decides whether an f32 overflows to infinity or rounds back down.
    """
    exponent = (pattern >> 7) & 0xFF
    fraction = pattern & 0x7F
    if exponent == 0xFF and not virtual:
        return None if fraction == 0 else "nan"
    if exponent == 0:
        return Fraction(fraction, 1 << 7) * Fraction(1, 1 << 126)
    scale = Fraction(2) ** (exponent - 127)
    return (1 + Fraction(fraction, 1 << 7)) * scale


def f32_value(pattern: int):
    """The exact value of an f32 pattern: a Fraction, None for infinity, or
    the string 'nan'."""
    exponent = (pattern >> 23) & 0xFF
    fraction = pattern & 0x7F_FFFF
    if exponent == 0xFF:
        return None if fraction == 0 else "nan"
    if exponent == 0:
        return Fraction(fraction, 1 << 23) * Fraction(1, 1 << 126)
    scale = Fraction(2) ** (exponent - 127)
    return (1 + Fraction(fraction, 1 << 23)) * scale


def round_to_bf16(pattern: int) -> tuple[int, str]:
    """The correctly rounded bf16 of an f32 pattern, and which case it was.

    Independent of the expansion under test: it compares against a midpoint
    computed in exact rational arithmetic and breaks a tie towards the even
    pattern, which is the definition of round-to-nearest-even.
    """
    sign = pattern >> 31
    magnitude = pattern & 0x7FFF_FFFF
    value = f32_value(magnitude)
    if value == "nan":
        return CANONICAL_NAN, "nan"
    if value is None:
        return (sign << 15) | 0x7F80, "infinity"
    low = magnitude >> 16
    high = low + 1
    low_value = bf16_value(low, virtual=True)
    high_value = bf16_value(high, virtual=True)
    midpoint = (low_value + high_value) / 2
    if value < midpoint:
        chosen, case = low, "down"
    elif value > midpoint:
        chosen, case = high, "up"
    else:
        chosen, case = (low if low % 2 == 0 else high), "tie"
    if ((chosen >> 7) & 0xFF) == 0xFF:
        case = "overflow"
    return (sign << 15) | chosen, case


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=40000)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_bf16_"))
    golden_path = workdir / "golden_model.py"
    subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(args.axis_file), "-o", str(golden_path)],
        check=True, cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location("axis_golden_bf16", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    if "BFCVT" not in golden.AXIS_SPECS or "BFWIDEN" not in golden.AXIS_SPECS:
        print("no bf16 conversions in this corpus")
        return DECLINED
    narrow = golden.AXIS_SPECS["BFCVT"]["eval"]
    widen = golden.AXIS_SPECS["BFWIDEN"]["eval"]

    failures = 0

    # --- 1. widening is exact --------------------------------------------
    for pattern in range(65536):
        got = widen(pattern) & 0xFFFF_FFFF
        want_value = bf16_value(pattern & 0x7FFF)
        got_value = f32_value(got & 0x7FFF_FFFF)
        same_sign = (pattern >> 15) == (got >> 31)
        if isinstance(want_value, str) or isinstance(got_value, str):
            agrees = want_value == got_value
        elif want_value is None or got_value is None:
            agrees = want_value is None and got_value is None
        else:
            agrees = want_value == got_value
        if not (agrees and same_sign):
            failures += 1
            if failures <= 5:
                print(f"FAIL widen 0x{pattern:04x} -> 0x{got:08x}: {got_value} != {want_value}")

    # --- 1b. widening reads the low half and nothing above it ------------
    # A bf16 sits in the low half of a register whose high half is whatever was
    # there. The expansion masks before it shifts, and without this the mask is
    # unchecked: every pattern below 65536 has a zero high half, so dropping
    # the mask changes nothing a 16-bit sweep can see. The injection that
    # removes it passed this gate until this property existed.
    for pattern in range(0, 65536, 97):
        for junk in (0x0001_0000, 0xDEAD_0000, 0xFFFF_0000):
            if (widen(pattern | junk) & 0xFFFF_FFFF) != (widen(pattern) & 0xFFFF_FFFF):
                failures += 1
                if failures <= 5:
                    print(f"FAIL widen reads above its half: 0x{pattern | junk:08x}")

    # --- 3. round trip ---------------------------------------------------
    for pattern in range(65536):
        back = narrow(widen(pattern)) & 0xFFFF
        expected = CANONICAL_NAN if ((pattern >> 7) & 0xFF) == 0xFF and (pattern & 0x7F) else pattern
        if back != expected:
            failures += 1
            if failures <= 8:
                print(f"FAIL round trip 0x{pattern:04x} -> 0x{back:04x}, want 0x{expected:04x}")

    # --- 2 and 4. narrowing, and the cases it must reach -----------------
    outcomes = {"up": 0, "down": 0, "tie": 0, "overflow": 0, "nan": 0, "infinity": 0}
    rng = random.Random(0xBF16)
    inputs = []
    # Every pattern whose dropped bits are exactly the midpoint, so ties are
    # reached deliberately rather than by luck -- one per exponent, both signs.
    for exponent in range(1, 255):
        for sign in (0, 1):
            for keep in (0x00, 0x01):
                inputs.append((sign << 31) | (exponent << 23) | (keep << 16) | 0x8000)
    inputs += [0x7F80_0000, 0xFF80_0000, 0x7FC0_0001, 0x7F80_0001, 0x7F7F_FFFF, 0x0000_0001]
    # The overflow band: above the midpoint between the largest finite bf16
    # (0x7f7f, which is f32 0x7f7f0000) and the infinity past it, an f32 rounds
    # to infinity. Reached deliberately, since a random 32-bit pattern lands in
    # this band about once in 2^16 draws -- and once is not a check.
    for low in (0x8001, 0x9000, 0xC000, 0xFFFF):
        for sign in (0x0000_0000, 0x8000_0000):
            inputs.append(sign | 0x7F7F_0000 | low)
    while len(inputs) < args.cases:
        inputs.append(rng.getrandbits(32))

    for pattern in inputs:
        want, case = round_to_bf16(pattern)
        outcomes[case] = outcomes.get(case, 0) + 1
        got = narrow(pattern) & 0xFFFF
        if got != want:
            failures += 1
            if failures <= 8:
                print(f"FAIL narrow 0x{pattern:08x} -> 0x{got:04x}, want 0x{want:04x} ({case})")

    print(f"65536 widenings and {len(inputs)} narrowings, against exact rational rounding")
    print("  narrowing outcomes reached : "
          + ", ".join(f"{name} {count}" for name, count in outcomes.items()))
    missing = [name for name, count in outcomes.items() if count == 0]
    if missing:
        print(f"never reached: {', '.join(missing)}; the rounding check is vacuous there")
        failures += 1
    print("bf16: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
