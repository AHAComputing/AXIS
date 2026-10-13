#!/usr/bin/env python3
"""Prove that fused and unfused multiply-add stay distinct in every backend.

`fma(a, b, c)` rounds once; `(a * b) + c` rounds twice. On most inputs the two
agree, which is exactly why the distinction is easy to lose: a C or Rust
compiler is permitted to contract a multiply and an add into an FMA, and an
optimizer that does so silently turns the second form into the first.

This drives the witness where they provably differ --
a = 1 + 2^-52, b = 1 - 2^-52, c = -1, whose exact product 1 - 2^-104 rounds to
1.0 in binary64, so the unfused form cancels to +0.0 while the fused form keeps
-2^-104 -- through the golden model, the C header, and the Rust module, and
requires two things of each: agreement with the golden model on both
instructions, and disagreement between the two instructions.

The second requirement is the point. Without it a backend that contracted
everything would still pass every other gate.

Usage: tools/fp_fusion_check.py [input.axisl]
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

FUSED = "FMADD_D"
UNFUSED = "FMULADD_D"


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def bits(value: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "fp_scalar.axisl")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_fpfuse_"))
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
    emit(args.axis_file, "emit-semantics-rust", workdir / "axis_semantics.rs")

    spec = importlib.util.spec_from_file_location(
        "golden", workdir / "golden_model.py")
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    # The operands are (fd, fn1, fm) and the semantics are fn1 * fm + fd, so the
    # accumulator is the first argument.
    a, b, c = 1.0 + 2.0 ** -52, 1.0 - 2.0 ** -52, -1.0
    operands = (bits(c), bits(a), bits(b))

    want_fused = golden.evaluate(FUSED, *operands)
    want_unfused = golden.evaluate(UNFUSED, *operands)

    failures = 0
    if want_fused == want_unfused:
        print(f"FAIL golden: fused and unfused agree ({want_fused:#018x}); "
              "the witness no longer distinguishes them")
        failures += 1
    else:
        print(f"golden: fused {want_fused:#018x} != unfused {want_unfused:#018x}")

    args_text = ", ".join(f"{value}ULL" for value in operands)
    driver_c = workdir / "driver.c"
    driver_c.write_text(
        '#include <stdio.h>\n#include <stdint.h>\n#include "axis_semantics.h"\n\n'
        "int main(void) {\n"
        f"  printf(\"%llu %llu\\n\", (unsigned long long)axis_eval_{FUSED.lower()}({args_text}),\n"
        f"         (unsigned long long)axis_eval_{UNFUSED.lower()}({args_text}));\n"
        "  return 0;\n}\n"
    )
    binary = workdir / "driver"
    # Defensive only: the generated header round-trips the intermediate product
    # through a bit pattern and a NaN test, which no compiler can fuse across.
    # Compiling this witness with `-ffp-contract=fast` keeps the two distinct,
    # so the flag guards consumer code rather than AXIS's own output.
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-ffp-contract=off",
         "-I", str(workdir), "-o", str(binary), str(driver_c), "-lm"],
        check=True,
    )
    got_fused, got_unfused = (
        int(field) for field in
        subprocess.run([str(binary)], capture_output=True, text=True,
                       check=True).stdout.split()
    )
    failures += report("C", got_fused, got_unfused, want_fused, want_unfused)

    rust_main = (workdir / "axis_semantics.rs").read_text() + (
        "\nfn main() {\n"
        f"    println!(\"{{}} {{}}\", axis_eval_{FUSED.lower()}({args_rust(operands)}),\n"
        f"             axis_eval_{UNFUSED.lower()}({args_rust(operands)}));\n"
        "}\n"
    )
    rust_path = workdir / "driver.rs"
    rust_path.write_text(rust_main)
    rust_binary = workdir / "driver_rs"
    compile_rust = subprocess.run(
        ["rustc", "-A", "warnings", "-o", str(rust_binary), str(rust_path)],
        capture_output=True, text=True,
    )
    if compile_rust.returncode != 0:
        print("SKIP: rustc unavailable or failed")
    else:
        got_fused, got_unfused = (
            int(field) for field in
            subprocess.run([str(rust_binary)], capture_output=True, text=True,
                           check=True).stdout.split()
        )
        failures += report("Rust", got_fused, got_unfused, want_fused, want_unfused)

    print("fused != unfused in every backend: PASS" if failures == 0
          else "fused != unfused in every backend: FAIL")
    return 1 if failures else 0


def args_rust(operands) -> str:
    return ", ".join(f"{value}u64" for value in operands)


def report(backend: str, got_fused: int, got_unfused: int,
           want_fused: int, want_unfused: int) -> int:
    failures = 0
    if got_fused != want_fused:
        print(f"FAIL {backend} fused: {got_fused:#018x} != golden {want_fused:#018x}")
        failures += 1
    if got_unfused != want_unfused:
        print(f"FAIL {backend} unfused: {got_unfused:#018x} != golden {want_unfused:#018x}")
        failures += 1
    if got_fused == got_unfused:
        print(f"FAIL {backend}: the two instructions agree, so the multiply-add "
              "was contracted and the distinction was lost")
        failures += 1
    if failures == 0:
        print(f"{backend}: fused {got_fused:#018x} != unfused {got_unfused:#018x}")
    return failures


if __name__ == "__main__":
    raise SystemExit(main())
