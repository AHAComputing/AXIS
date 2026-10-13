#!/usr/bin/env python3
"""Half precision, over every pattern there is. Gate.

f16 is where the two-format assumption broke, and it broke quietly: the C and
Rust backends resolved a 16-bit float to single precision because they chose the
format by comparing the width against 32. `ir::FLOAT_FORMATS` replaced that
comparison with a table, and this is what turns the third row into evidence.

The backends do not agree by computing the same way, which is the point:

  golden model   Python's struct 'e' -- IEEE half, natively
  C, Rust        single precision, rounded to half in software

The software path is not a fallback. Double rounding from p' bits to p is
innocuous when p' >= 2p + 2, and f32's 24 bits meet that bound exactly for
f16's 11 -- so computing in single and rounding once more is the correctly
rounded half result. That is a theorem about the formats; this is the
measurement that AXIS implemented it.

Four properties:

  1. **every half pattern agrees, in both backends.** All 65536, through each
     unary half operation the corpus offers -- not sampled, because a rounding
     bug lives in a thin band of patterns and a sample walks past it;
  2. **widening is exact.** h -> s -> h is the identity on every non-NaN
     pattern, and every NaN lands on the canonical one. A conversion that lost
     a subnormal or flushed one would show here and nowhere else;
  3. **narrowing rounds correctly**, over patterns chosen to land in every
     outcome: rounded up, rounded down, tie-to-even, overflow to infinity, and
     a subnormal result;
  4. **those five outcomes actually occur.** Without this the third holds
     vacuously -- a run that never reached a tie proves nothing about ties.

Injection-checked: rounding half away from zero instead of to even, flushing
subnormal results to zero, and widening with a shift instead of a
renormalisation -- each fails a different property.

Usage: tools/half_exhaustive_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent

# The unary half operations this drives exhaustively, as mnemonic -> emitted
# identifier. Every one takes a single half pattern and returns one word.
UNARY = ("FCVT_S_H", "FNEG_H", "FSQRT_H", "FCVT_W_H")
# The same generator runs in Python and in both drivers, so the narrowing cases
# are identical everywhere without shipping 65536 literals through a compiler.
LCG_MUL, LCG_ADD = 1103515245, 12345


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def narrowing_inputs(count: int) -> list[int]:
    """f32 patterns for the narrowing conversion, spread across half's range.

    Random 32-bit patterns are almost all outside half's exponent range, so
    they would prove only that overflow works. These walk half's own range and
    the bits just under it, which is where rounding and subnormals live.
    """
    values = []
    state = 0x1234_5678
    for index in range(count):
        state = (state * LCG_MUL + LCG_ADD) & 0xFFFF_FFFF
        # An exponent spanning half's whole range and a little past its top,
        # with a full 24-bit significand, so the bits that fall off the end are
        # the ones that decide the rounding -- and some values overflow, which
        # the first version of this range never did. The gate said so.
        exponent = 100 + (state >> 24) % 50
        mantissa = state & 0x7F_FFFF
        sign = (state >> 23) & 1
        values.append((sign << 31) | (exponent << 23) | mantissa)
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--narrowing", type=int, default=65536)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_half_"))
    golden_path = workdir / "golden_model.py"
    header_path = workdir / "axis_semantics.h"
    rust_path = workdir / "axis_semantics.rs"
    emit(args.axis_file, "emit-golden-python", golden_path)
    emit(args.axis_file, "emit-semantics-c", header_path)
    emit(args.axis_file, "emit-semantics-rust", rust_path)

    spec = importlib.util.spec_from_file_location("axis_golden_half", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    unary = [name for name in UNARY if name in golden.AXIS_SPECS]
    if not unary or "FCVT_H_S" not in golden.AXIS_SPECS:
        print("no half-precision corpus here")
        return DECLINED

    narrowing = narrowing_inputs(args.narrowing)
    calls = [f"axis_eval_{name.lower()}" for name in unary]

    # --- C ---------------------------------------------------------------
    c_body = "\n".join(
        f'    printf("%u ", (unsigned){call}(bits));' for call in calls
    )
    main_c = workdir / "main.c"
    main_c.write_text(
        '#include <stdio.h>\n#include "axis_semantics.h"\n\n'
        "int main(void) {\n"
        "  for (uint32_t bits = 0; bits < 65536u; bits++) {\n"
        f"{c_body}\n"
        '    printf("\\n");\n'
        "  }\n"
        "  uint32_t state = 0x12345678u;\n"
        f"  for (int i = 0; i < {args.narrowing}; i++) {{\n"
        f"    state = state * {LCG_MUL}u + {LCG_ADD}u;\n"
        "    uint32_t exponent = 100u + (state >> 24) % 50u;\n"
        "    uint32_t value = ((state >> 23) & 1u) << 31 | (exponent << 23)\n"
        "                     | (state & 0x7fffffu);\n"
        '    printf("%u\\n", (unsigned)axis_eval_fcvt_h_s(value));\n'
        "  }\n"
        "  return 0;\n}\n"
    )
    binary = workdir / "half_c"
    subprocess.run(["cc", "-std=c11", "-Wall", "-Werror", "-o", str(binary),
                    str(main_c), "-lm"], check=True, cwd=workdir)
    c_out = subprocess.run([str(binary)], capture_output=True, text=True,
                           check=True).stdout.split("\n")

    # --- Rust ------------------------------------------------------------
    rust_out = None
    if shutil.which("rustc"):
        rust_body = "\n".join(
            f'        print!("{{}} ", {call}(bits));' for call in calls
        )
        driver = rust_path.read_text() + (
            "\nfn main() {\n"
            "    for bits in 0u32..65536u32 {\n"
            f"{rust_body}\n"
            '        println!();\n'
            "    }\n"
            "    let mut state: u32 = 0x12345678;\n"
            f"    for _ in 0..{args.narrowing} {{\n"
            f"        state = state.wrapping_mul({LCG_MUL}).wrapping_add({LCG_ADD});\n"
            "        let exponent = 100u32 + (state >> 24) % 50;\n"
            "        let value = ((state >> 23) & 1) << 31 | (exponent << 23)\n"
            "                    | (state & 0x7fffff);\n"
            '        println!("{}", axis_eval_fcvt_h_s(value));\n'
            "    }\n}\n"
        )
        driver_path = workdir / "driver.rs"
        driver_path.write_text(driver)
        rust_binary = workdir / "half_rust"
        subprocess.run(["rustc", "--edition", "2021", "-A", "warnings",
                        "-o", str(rust_binary), str(driver_path)],
                       check=True, cwd=workdir)
        rust_out = subprocess.run([str(rust_binary)], capture_output=True,
                                  text=True, check=True).stdout.split("\n")

    # --- 1. every half pattern, both backends ----------------------------
    failures = 0
    checks = 0
    for bits in range(65536):
        want = [golden.AXIS_SPECS[name]["eval"](bits) for name in unary]
        got_c = [int(field) for field in c_out[bits].split()]
        if got_c != want:
            failures += 1
            if failures <= 5:
                print(f"FAIL C at half 0x{bits:04x}: {got_c} != {want}")
        if rust_out is not None:
            got_rust = [int(field) for field in rust_out[bits].split()]
            if got_rust != want:
                failures += 1
                if failures <= 5:
                    print(f"FAIL Rust at half 0x{bits:04x}: {got_rust} != {want}")
        checks += 1

    # --- 2. widening is exact --------------------------------------------
    widen = golden.AXIS_SPECS["FCVT_S_H"]["eval"]
    narrow = golden.AXIS_SPECS["FCVT_H_S"]["eval"]
    canonical = 0x7E00
    round_trip = 0
    for bits in range(65536):
        back = narrow(widen(bits)) & 0xFFFF
        expected = canonical if (bits & 0x7C00) == 0x7C00 and (bits & 0x3FF) else bits
        if back != expected:
            failures += 1
            if failures <= 8:
                print(f"FAIL round trip 0x{bits:04x} -> 0x{back:04x}, want 0x{expected:04x}")
        round_trip += 1

    # --- 3 and 4. narrowing rounds, and reaches every outcome ------------
    outcomes = {"up": 0, "down": 0, "tie": 0, "overflow": 0, "subnormal": 0}
    base = 65536
    for index, value in enumerate(narrowing):
        want = narrow(value)
        got_c = int(c_out[base + index])
        if got_c != want:
            failures += 1
            if failures <= 8:
                print(f"FAIL C narrowing 0x{value:08x}: 0x{got_c:x} != 0x{want:x}")
        if rust_out is not None:
            got_rust = int(rust_out[base + index])
            if got_rust != want:
                failures += 1
                if failures <= 8:
                    print(f"FAIL Rust narrowing 0x{value:08x}: 0x{got_rust:x} != 0x{want:x}")
        checks += 1

        half = want & 0xFFFF
        exact = struct.unpack("<f", struct.pack("<I", value))[0]
        if (half & 0x7C00) == 0x7C00 and not (half & 0x3FF):
            outcomes["overflow"] += 1
            continue
        if not (half & 0x7C00):
            outcomes["subnormal"] += 1
        again = struct.unpack("<e", struct.pack("<H", half))[0]
        # A tie is the dropped bits being exactly half of the last kept place.
        # Thirteen bits fall off a normal half; a subnormal drops more, so the
        # count is taken where the place value is known.
        dropped = value & 0x1FFF
        if (half & 0x7C00) and dropped == 0x1000:
            outcomes["tie"] += 1
        elif abs(again) > abs(exact):
            outcomes["up"] += 1
        elif abs(again) < abs(exact):
            outcomes["down"] += 1

    print(f"{checks} exhaustive checks over {len(unary)} unary half operation(s)"
          + ("" if rust_out is not None else " (Rust skipped: no rustc)"))
    print(f"  half -> single -> half is the identity : {round_trip} pattern(s)")
    print("  narrowing outcomes reached            : "
          + ", ".join(f"{name} {count}" for name, count in outcomes.items()))

    missing = [name for name, count in outcomes.items() if count == 0]
    if missing:
        print(f"narrowing never reached: {', '.join(missing)}; the rounding check is vacuous there")
        failures += 1
    print("half precision: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
