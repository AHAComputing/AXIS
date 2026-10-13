#!/usr/bin/env python3
"""Differential check: the generated Rust semantics interpreter vs the golden model.

Emits `axis_semantics.rs` and `golden_model.py` from the same .axisl source,
compiles the Rust interpreter with a generated driver via rustc, drives both
with the golden model's own deterministic `sample_vectors` (plus randomized
vectors), and requires bit-identical results. The Rust sibling of
`c_vs_golden.py`.

Usage: tools/rust_vs_golden.py <input.axisl> [--cases N]

Requires: cargo (run from the AXIS repo root) and rustc on PATH.
"""

from __future__ import annotations

import argparse
import importlib.util
import random
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



def emitted_ident(name: str) -> str:
    """The identifier the emitters give this definition.

    `src/emit/common.rs::python_ident`: lowercase alphanumerics, everything else
    an underscore. Spelling it `name.lower()` here instead meant that an
    instruction whose mnemonic is not already an identifier -- `CONSTRAINED-EXTEND`
    is the one in the corpus -- was looked up under a name no backend emits, and
    skipped with "no C function emitted" while the function sat in the header
    under its sanitised name. One definition, proven by nothing on three
    backends, and the skip line said so every run.
    """
    ident = "".join(c.lower() if c.isalnum() and c.isascii() else "_" for c in name)
    return f"_{ident}" if not ident or ident[0].isdigit() else ident


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64,
                        help="vectors per function (spec samples + random)")
    args = parser.parse_args()

    if not shutil.which("rustc"):
        print("SKIP: rustc not found")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="axis_rvg_"))
    golden_path = workdir / "golden_model.py"
    rs_path = workdir / "axis_semantics.rs"
    emit(args.axis_file, "emit-golden-python", golden_path)
    emit(args.axis_file, "emit-semantics-rust", rs_path)

    spec = importlib.util.spec_from_file_location("axis_golden", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    rs_text = rs_path.read_text()
    random.seed(0x2057)
    cases = []
    for name, entry in golden.AXIS_SPECS.items():
        fn_name = f"axis_eval_{emitted_ident(name)}"
        # One evaluation type per function: u32, or u64 when any operand or the
        # result is wider. The driver's literals must match the signature.
        widest = max([width for _, width in entry["params"]]
                     + [entry.get("result_width", 32)])
        suffix = "u128" if widest > 64 else ("u64" if widest > 32 else "u32")
        if f"pub fn {fn_name}(" not in rs_text:
            print(f"skip {name}: no Rust function emitted")
            continue
        vectors = list(golden.sample_vectors(name, count=args.cases // 2))
        for _ in range(args.cases - len(vectors)):
            vectors.append(tuple(
                random.getrandbits(width) for _, width in entry["params"]
            ))
        for values in vectors:
            expected = entry["eval"](*values)
            arg_text = ", ".join(f"{value}{suffix}" for value in values)
            cases.append(
                f'    {{ let got = {fn_name}({arg_text});\n'
                f'      if got != {expected}{suffix} {{\n'
                f'        println!("FAIL {name}({values}) got {{:#018x}} want {expected:#018x}", got);\n'
                f"        failures += 1;\n"
                f"      }}\n"
                f"      checks += 1; }}\n"
            )

    if not cases:
        # Nothing to compare is not the same as nothing comparing. A
        # description with no pure value semantics -- one whose instructions
        # are all behaviors -- has nothing this driver could ever check, and
        # says so the way every other gate says it, with a SKIP and a zero
        # exit. A description that *has* specs and got no function out of the
        # backend is the other thing entirely, and stays a failure.
        if not golden.AXIS_SPECS:
            print("SKIP: no pure value semantics to compare")
            return 0
        print(f"no comparable functions found: {len(golden.AXIS_SPECS)} spec(s) "
              f"in the golden model and no function emitted for any of them")
        return 1

    # Append a main() driver to the generated module and compile as a binary.
    driver = rs_text + (
        "\nfn main() {\n    let mut checks = 0i64;\n    let mut failures = 0i64;\n"
        + "".join(cases)
        + '    println!("{} checks, {} failures", checks, failures);\n'
        "    std::process::exit(if failures == 0 { 0 } else { 1 });\n}\n"
    )
    driver_path = workdir / "driver.rs"
    driver_path.write_text(driver)
    binary = workdir / "driver"
    subprocess.run(
        ["rustc", "--edition", "2021", "-A", "warnings",
         "-o", str(binary), str(driver_path)],
        check=True,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    print(result.stdout.strip())
    ok = result.returncode == 0
    print("Rust == golden model: PASS" if ok else "Rust == golden model: FAIL")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
