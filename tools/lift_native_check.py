#!/usr/bin/env python3
"""Differential check: the generated C and Rust lifters vs the encode fixtures.

Emits `axis_roundtrip_tests.json`, `axis_lift.h`, and `axis_lift.rs` from the
same .axisl source, compiles each lifter with a generated driver, and requires
every fixture to lift back to the encoded mnemonic and operand values. This is
the compiled sibling of `lift_roundtrip.py`, proving the C and Rust lifters
agree with the Python lifter and the encoder.

Usage: tools/lift_native_check.py <input.axisl>

Requires: cargo (run from the AXIS repo root). Skips C if `cc` is missing and
Rust if `rustc` is missing; fails only on an actual mismatch.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def c_driver(tests: list) -> str:
    lines = [
        '#include <stdio.h>',
        '#include <string.h>',
        '#include "axis_lift.h"',
        "",
        "static long op_value(const axis_lifted *l, const char *name, int *valid) {",
        "  for (int i = 0; i < l->entry->operand_count; ++i) {",
        "    if (strcmp(l->entry->operands[i].name, name) == 0) {",
        "      *valid = l->operand_valid[i];",
        "      return (long)l->operands[i];",
        "    }",
        "  }",
        "  *valid = 0;",
        "  return -1;",
        "}",
        "",
        "int main(void) {",
        "  int failures = 0, checks = 0, valid = 0; long got = 0;",
        "  axis_lifted l;",
    ]
    for test in tests:
        word = int(test["encoded"], 16)
        isa = test.get("isa", "")
        lines.append(f"  if (!axis_lift_in_isa({word}u, \"{isa}\", &l) || strcmp(l.entry->mnemonic, "
                     f"\"{test['mnemonic']}\") != 0) {{ printf(\"FAIL decode {test['mnemonic']}\\n\"); failures++; }}")
        for operand in test["operands"]:
            lines.append(
                f"  got = op_value(&l, \"{operand['name']}\", &valid); checks++;"
                f" if (!valid || got != {operand['value']}L) {{ printf("
                f"\"FAIL {test['mnemonic']}.{operand['name']} got %ld want {operand['value']}\\n\", got); failures++; }}"
            )
    lines += [
        '  printf("%d checks, %d failures\\n", checks, failures);',
        "  return failures == 0 ? 0 : 1;",
        "}",
        "",
    ]
    return "\n".join(lines)


def rust_driver(tests: list) -> str:
    lines = [
        'include!("axis_lift.rs");',
        "",
        "fn op_value(l: &Lifted, name: &str) -> Option<u32> {",
        "    l.entry.operands.iter().position(|o| o.name == name).and_then(|i| l.operands[i])",
        "}",
        "",
        "fn main() {",
        "    let mut failures = 0i32;",
        "    let mut checks = 0i32;",
    ]
    for test in tests:
        word = int(test["encoded"], 16)
        isa = test.get("isa")
        isa_arg = f'Some("{isa}")' if isa else "None"
        lines.append(f"    match lift_in_isa({word}, {isa_arg}) {{")
        lines.append(f"        Some(l) => {{")
        lines.append(f"            if l.entry.mnemonic != \"{test['mnemonic']}\" {{ "
                     f"println!(\"FAIL decode {test['mnemonic']}\"); failures += 1; }}")
        for operand in test["operands"]:
            lines.append(
                f"            checks += 1; if op_value(&l, \"{operand['name']}\") != Some({operand['value']}) "
                f"{{ println!(\"FAIL {test['mnemonic']}.{operand['name']}\"); failures += 1; }}"
            )
        lines.append("        }")
        lines.append(f"        None => {{ println!(\"FAIL decode {test['mnemonic']}\"); failures += 1; }}")
        lines.append("    }")
    lines += [
        '    println!("{} checks, {} failures", checks, failures);',
        "    std::process::exit(if failures == 0 { 0 } else { 1 });",
        "}",
        "",
    ]
    return "\n".join(lines)


def run_driver(label: str, build_cmd: list, binary: Path) -> int:
    subprocess.run(build_cmd, check=True)
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    print(f"{label}: {result.stdout.strip()}")
    print(f"{label} == fixtures: {'PASS' if result.returncode == 0 else 'FAIL'}")
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_liftn_"))
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)
    emit(args.axis_file, "emit-lift-c", workdir / "axis_lift.h")
    emit(args.axis_file, "emit-lift-rust", workdir / "axis_lift.rs")
    tests = json.loads(fixtures_path.read_text()).get("tests", [])
    if not tests:
        print("no encodable fixtures to check")
        return 0

    rc = 0
    if shutil.which("cc"):
        (workdir / "c_driver.c").write_text(c_driver(tests))
        rc |= run_driver(
            "C lifter",
            ["cc", "-std=c11", "-Wall", "-Werror", "-I", str(workdir),
             "-o", str(workdir / "c_driver"), str(workdir / "c_driver.c")],
            workdir / "c_driver",
        )
    else:
        print("SKIP C: cc not found")

    if shutil.which("rustc"):
        (workdir / "rust_driver.rs").write_text(rust_driver(tests))
        rc |= run_driver(
            "Rust lifter",
            ["rustc", "--edition", "2021", "-A", "warnings",
             "-o", str(workdir / "rust_driver"), str(workdir / "rust_driver.rs")],
            workdir / "rust_driver",
        )
    else:
        print("SKIP Rust: rustc not found")

    return 1 if rc else 0


if __name__ == "__main__":
    sys.exit(main())
