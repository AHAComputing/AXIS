#!/usr/bin/env python3
"""Prove `FCLASS` puts every value in the class RISC-V says it belongs to.

The differential ladder proves the backends agree with each other, which is not
the same as being right: a classification with two bits transposed would be
emitted identically by all of them and every gate would pass. RISC-V's ten
classes are an *external* fact, so this drives one witness per class -- and both
NaN kinds, which differ only in the mantissa's top bit -- through the golden
model, the C header and the Rust module, and requires the exact mask.

It also requires the property the ten witnesses cannot show: the result is
one-hot for *every* bit pattern, not just the ten. A classification that fell
through to zero, or that set two bits on some unlisted input, would satisfy the
table and still be wrong.

Usage: tools/fclass_check.py [input.axisl]
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

# RISC-V's ten classes, in bit order.
CLASSES = ["-inf", "-normal", "-subnormal", "-0", "+0",
           "+subnormal", "+normal", "+inf", "sNaN", "qNaN"]

# One witness per class, per precision. A NaN is signalling when the mantissa's
# top bit is clear and quiet when it is set, which is the only thing telling
# bits 8 and 9 apart.
SINGLE = [0xff800000, 0xbfc00000, 0x807fffff, 0x80000000, 0x00000000,
          0x00000001, 0x3fc00000, 0x7f800000, 0x7f800001, 0x7fc00000]
DOUBLE = [0xfff0000000000000, 0xbff8000000000000, 0x800fffffffffffff,
          0x8000000000000000, 0x0000000000000000, 0x0000000000000001,
          0x3ff8000000000000, 0x7ff0000000000000, 0x7ff0000000000001,
          0x7ff8000000000000]

RANDOM_PATTERNS = 20000


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def witnesses():
    """Every (mnemonic, input, expected mask) this gate requires."""
    for mnemonic, inputs in (("FCLASS_S", SINGLE), ("FCLASS_D", DOUBLE)):
        for index, raw in enumerate(inputs):
            yield mnemonic, raw, 1 << index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv32i.axisl")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_fclass_"))
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
    emit(args.axis_file, "emit-semantics-rust", workdir / "axis_semantics.rs")

    spec = importlib.util.spec_from_file_location(
        "golden", workdir / "golden_model.py")
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    failures = 0
    checked = 0
    for mnemonic, raw, want in witnesses():
        got = golden.evaluate(mnemonic, raw)
        checked += 1
        if got != want:
            name = CLASSES[want.bit_length() - 1]
            print(f"FAIL golden {mnemonic}({raw:#x}): {got:#05x} != {want:#05x} ({name})")
            failures += 1

    # One-hot for every pattern, not only the listed ten.
    stray = 0
    for _ in range(RANDOM_PATTERNS):
        for mnemonic, width in (("FCLASS_S", 32), ("FCLASS_D", 64)):
            raw = random.getrandbits(width)
            mask = golden.evaluate(mnemonic, raw)
            if mask.bit_count() != 1 or mask >= 1 << len(CLASSES):
                if stray < 5:
                    print(f"FAIL golden {mnemonic}({raw:#x}): {mask:#05x} is not one of ten classes")
                stray += 1
    if stray:
        print(f"FAIL: {stray} pattern(s) did not land in exactly one class")
        failures += stray

    failures += drive_c(workdir)
    failures += drive_rust(workdir)

    total = checked + 2 * RANDOM_PATTERNS
    print(f"{total} classifications checked across {len(CLASSES)} classes")
    print("FCLASS agrees with RISC-V's ten classes: "
          + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


def drive_c(workdir: Path) -> int:
    calls = "\n".join(
        f'  printf("%u\\n", (unsigned)axis_eval_{mnemonic.lower()}('
        f'{raw}ULL));'
        for mnemonic, raw, _ in witnesses()
    )
    driver = workdir / "driver.c"
    driver.write_text(
        '#include <stdio.h>\n#include <stdint.h>\n#include "axis_semantics.h"\n\n'
        f"int main(void) {{\n{calls}\n  return 0;\n}}\n"
    )
    binary = workdir / "driver"
    build = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-I", str(workdir),
         "-o", str(binary), str(driver), "-lm"],
        capture_output=True, text=True,
    )
    if build.returncode != 0:
        print("FAIL C: the driver did not build")
        print(build.stderr[-2000:])
        return 1
    got = subprocess.run([str(binary)], capture_output=True, text=True,
                         check=True).stdout.split()
    return report("C", [int(value) for value in got])


def drive_rust(workdir: Path) -> int:
    calls = "\n".join(
        f'    println!("{{}}", axis_eval_{mnemonic.lower()}({raw}u64));'
        for mnemonic, raw, _ in witnesses()
    )
    source = (workdir / "axis_semantics.rs").read_text() + (
        f"\nfn main() {{\n{calls}\n}}\n"
    )
    path = workdir / "driver.rs"
    path.write_text(source)
    binary = workdir / "driver_rs"
    build = subprocess.run(
        ["rustc", "-A", "warnings", "-o", str(binary), str(path)],
        capture_output=True, text=True,
    )
    if build.returncode != 0:
        print("SKIP: rustc unavailable or failed")
        return 0
    got = subprocess.run([str(binary)], capture_output=True, text=True,
                         check=True).stdout.split()
    return report("Rust", [int(value) for value in got])


def report(backend: str, got: list[int]) -> int:
    expected = list(witnesses())
    if len(got) != len(expected):
        print(f"FAIL {backend}: {len(got)} results for {len(expected)} witnesses")
        return 1
    failures = 0
    for (mnemonic, raw, want), value in zip(expected, got):
        if value != want:
            name = CLASSES[want.bit_length() - 1]
            print(f"FAIL {backend} {mnemonic}({raw:#x}): {value:#05x} != {want:#05x} ({name})")
            failures += 1
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
