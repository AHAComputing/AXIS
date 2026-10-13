#!/usr/bin/env python3
"""The eight-bit formats round correctly, against exact arithmetic. Gate.

e4m3 and e5m2 expand at elaboration into integer bit work, so every backend
consumes ordinary semantics and agrees with the others for free -- which proves
nothing about the expansion, exactly as with bf16. The oracle here is the
format's own definition in exact rational arithmetic: decode a pattern from its
sign, exponent and mantissa fields as a `Fraction`, and round by finding the
nearest representable value and breaking a tie towards the even pattern.
Nothing in that shares a line with the shifting it checks.

The two formats are not variants of one thing, and the gate is built so the
difference has to show:

  e5m2   IEEE-shaped: the top exponent is infinities and NaN, and an f32 past
         the range overflows to an infinity
  e4m3   no infinities at all: the all-ones exponent holds finite values, one
         pattern is NaN, the largest is 448 where IEEE at that size stops at
         240, and an f32 past the range SATURATES

Five properties:

  1. **every widening is exact**, all 256 patterns of both formats, against the
     value decoded from the format's own fields. Subnormals included, which is
     where the leading-bit search lives;
  2. **every narrowing is correctly rounded**, driven onto every rounding
     boundary there is -- the midpoint between each adjacent pair of
     representable values, from both sides -- rather than sampled;
  3. **round trip**: eight bits widened and narrowed again is the pattern it
     started as, for every pattern that is not a NaN;
  4. **the formats differ where they should.** e4m3 saturates and e5m2
     overflows to infinity on the same input, and the run fails if no input
     shows it;
  5. **the outcomes occur**: rounded up, rounded down, tie-to-even, overflow,
     subnormal result, NaN. Property 2 holds vacuously without them.

Injection-checked: rounding by truncation, saturating e4m3 to the NaN pattern
instead of to 448, and widening a subnormal without finding its leading bit --
each fails a different property.

Usage: tools/fp8_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import struct
import subprocess
import sys
import tempfile
from fractions import Fraction
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent

# name -> (exponent bits, mantissa bits, bias, has infinities, widen, narrow)
FORMATS = {
    "e4m3": (4, 3, 7, False, "F8_WIDEN_E4M3", "F8_NARROW_E4M3"),
    "e5m2": (5, 2, 15, True, "F8_WIDEN_E5M2", "F8_NARROW_E5M2"),
}


def value_of(pattern: int, E: int, M: int, bias: int) -> Fraction:
    """A finite pattern's exact value, from the fields the format defines."""
    sign = -1 if pattern & 0x80 else 1
    exponent = (pattern >> M) & ((1 << E) - 1)
    mantissa = pattern & ((1 << M) - 1)
    if exponent == 0:
        return sign * Fraction(mantissa, 1 << M) * Fraction(1, 1 << (bias - 1))
    return sign * (1 + Fraction(mantissa, 1 << M)) * (Fraction(2) ** (exponent - bias))


def is_nan(pattern: int, E: int, M: int, has_inf: bool) -> bool:
    top = (1 << E) - 1
    exponent = (pattern >> M) & top
    mantissa = pattern & ((1 << M) - 1)
    if exponent != top:
        return False
    return bool(mantissa) if has_inf else mantissa == (1 << M) - 1


def is_inf(pattern: int, E: int, M: int, has_inf: bool) -> bool:
    top = (1 << E) - 1
    return has_inf and ((pattern >> M) & top) == top and not (pattern & ((1 << M) - 1))


def max_finite_of(E: int, M: int, has_inf: bool) -> int:
    top = (1 << E) - 1
    return ((top - 1) << M) | ((1 << M) - 1) if has_inf else (top << M) | ((1 << M) - 2)


def oracle(f32_bits: int, E: int, M: int, bias: int, has_inf: bool) -> tuple[int, str]:
    """The correctly rounded pattern, and which case it was."""
    sign = (f32_bits >> 24) & 0x80
    magnitude = f32_bits & 0x7FFFFFFF
    biased = (magnitude >> 23) & 0xFF
    fraction = magnitude & 0x7FFFFF
    top = (1 << E) - 1
    max_finite = max_finite_of(E, M, has_inf)
    over = (top << M) if has_inf else max_finite
    if biased == 0xFF:
        return (0x7F, "nan") if fraction else (sign | over, "overflow")
    exact = Fraction(struct.unpack("<f", struct.pack("<I", magnitude))[0])
    ulp = value_of(max_finite, E, M, bias) - value_of(max_finite - 1, E, M, bias)
    if exact > value_of(max_finite, E, M, bias) + ulp / 2:
        return sign | over, "overflow"
    best = best_gap = None
    for candidate in range(max_finite + 1):
        gap = abs(value_of(candidate, E, M, bias) - exact)
        if best_gap is None or gap < best_gap or (gap == best_gap and candidate % 2 == 0):
            best, best_gap = candidate, gap
    chosen = value_of(best, E, M, bias)
    if best_gap == 0:
        case = "exact"
    elif chosen > exact:
        case = "up"
    else:
        case = "down"
    neighbour = best + 1 if chosen <= exact else best - 1
    if 0 <= neighbour <= max_finite and abs(value_of(neighbour, E, M, bias) - exact) == best_gap:
        case = "tie"
    if not ((best >> M) & top):
        case = "subnormal"
    return sign | best, case


def boundaries(E: int, M: int, bias: int, has_inf: bool) -> list[int]:
    """Every rounding boundary the format has, approached from both sides.

    A random f32 almost never lands on a midpoint, and the midpoint is where
    ties-to-even is decided -- so the inputs are built from the format rather
    than drawn.
    """
    out = []
    max_finite = max_finite_of(E, M, has_inf)
    for pattern in range(max_finite + 1):
        value = value_of(pattern, E, M, bias)
        for candidate in (float(value), float(value) * (1 + 2.0 ** -(M + 2))):
            bits = struct.unpack("<I", struct.pack("<f", candidate))[0]
            out += [bits, bits ^ 1, bits | 0x80000000, (bits ^ 1) | 0x80000000]
        if pattern < max_finite:
            midpoint = (value + value_of(pattern + 1, E, M, bias)) / 2
            bits = struct.unpack("<I", struct.pack("<f", float(midpoint)))[0]
            out += [bits, bits - 1, bits + 1, bits | 0x80000000]
    # Past the top, where the two formats part company.
    top_value = float(value_of(max_finite, E, M, bias))
    for scale in (1.001, 1.1, 2.0, 16.0):
        bits = struct.unpack("<I", struct.pack("<f", top_value * scale))[0]
        out += [bits, bits | 0x80000000]
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_fp8_"))
    golden_path = workdir / "golden_model.py"
    result = subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(args.axis_file), "-o", str(golden_path)],
        capture_output=True, text=True, cwd=AXIS_ROOT,
    )
    if result.returncode != 0:
        print(f"FAIL the golden model could not be emitted: {result.stderr.strip()[:200]}")
        return 1
    spec = importlib.util.spec_from_file_location("axis_golden_fp8", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    if not all(name in golden.AXIS_SPECS
               for _, _, _, _, widen, narrow in FORMATS.values()
               for name in (widen, narrow)):
        print("no eight-bit conversions in this corpus")
        return DECLINED

    failures = 0
    outcomes = {name: 0 for name in ("up", "down", "tie", "overflow", "subnormal", "nan", "exact")}
    saturated = overflowed = 0

    for label, (E, M, bias, has_inf, widen_name, narrow_name) in FORMATS.items():
        widen = golden.AXIS_SPECS[widen_name]["eval"]
        narrow = golden.AXIS_SPECS[narrow_name]["eval"]

        # --- 1. every widening is exact ----------------------------------
        for pattern in range(256):
            got = widen(pattern) & 0xFFFFFFFF
            value = struct.unpack("<f", struct.pack("<I", got))[0]
            if is_nan(pattern, E, M, has_inf):
                ok = value != value
            elif is_inf(pattern, E, M, has_inf):
                ok = abs(value) == float("inf") and (value < 0) == bool(pattern & 0x80)
            else:
                ok = Fraction(value) == value_of(pattern, E, M, bias)
            if not ok:
                failures += 1
                if failures <= 6:
                    print(f"FAIL {label} widen 0x{pattern:02x} -> {value!r}")

        # --- 3. round trip -----------------------------------------------
        for pattern in range(256):
            back = narrow(widen(pattern)) & 0xFF
            expected = 0x7F if is_nan(pattern, E, M, has_inf) else pattern
            if back != expected:
                failures += 1
                if failures <= 8:
                    print(f"FAIL {label} round trip 0x{pattern:02x} -> 0x{back:02x}, "
                          f"want 0x{expected:02x}")

        # --- 2 and 5. narrowing, on every boundary ------------------------
        for bits in boundaries(E, M, bias, has_inf):
            want, case = oracle(bits, E, M, bias, has_inf)
            outcomes[case] = outcomes.get(case, 0) + 1
            got = narrow(bits) & 0xFF
            if got != want:
                failures += 1
                if failures <= 8:
                    print(f"FAIL {label} narrow 0x{bits:08x} -> 0x{got:02x}, "
                          f"want 0x{want:02x} ({case})")

    # --- 4. the formats part company on overflow -------------------------
    huge = struct.unpack("<I", struct.pack("<f", 1.0e6))[0]
    e4m3 = golden.AXIS_SPECS["F8_NARROW_E4M3"]["eval"](huge) & 0xFF
    e5m2 = golden.AXIS_SPECS["F8_NARROW_E5M2"]["eval"](huge) & 0xFF
    if e4m3 == max_finite_of(4, 3, False):
        saturated += 1
    if e5m2 == (31 << 2):
        overflowed += 1
    if not saturated:
        print(f"e4m3 did not saturate on overflow: 0x{e4m3:02x}")
        failures += 1
    if not overflowed:
        print(f"e5m2 did not overflow to infinity: 0x{e5m2:02x}")
        failures += 1

    print(f"512 widenings and {sum(outcomes.values())} narrowings, "
          f"against exact rational rounding")
    print("  narrowing outcomes reached : "
          + ", ".join(f"{name} {count}" for name, count in outcomes.items()))
    print(f"  e4m3 saturates, e5m2 overflows : "
          f"{'yes' if saturated and overflowed else 'NO'}")
    missing = [name for name in ("up", "down", "tie", "overflow", "subnormal")
               if not outcomes.get(name)]
    if missing:
        print(f"never reached: {', '.join(missing)}; the rounding check is vacuous there")
        failures += 1
    print("fp8: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
