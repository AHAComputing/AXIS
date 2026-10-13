#!/usr/bin/env python3
"""Differential check: the generated C semantics interpreter vs the golden model.

Emits `axis_semantics.h` and `golden_model.py` from the same .axisl source,
drives both with the golden model's own deterministic `sample_vectors` (plus
extra randomized vectors), and requires bit-identical results.

Usage: tools/c_vs_golden.py <input.axisl> [--cases N]

Requires: cargo (run from the AXIS repo root), a C compiler on PATH (cc).
"""

from __future__ import annotations

import argparse
import importlib.util
import random
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

    workdir = Path(tempfile.mkdtemp(prefix="axis_cvg_"))
    golden_path = workdir / "golden_model.py"
    header_path = workdir / "axis_semantics.h"
    emit(args.axis_file, "emit-golden-python", golden_path)
    emit(args.axis_file, "emit-semantics-c", header_path)

    spec = importlib.util.spec_from_file_location("axis_golden", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    header = header_path.read_text()
    random.seed(0xC051)
    cases = []
    total = 0
    for name, entry in golden.AXIS_SPECS.items():
        fn_name = f"axis_eval_{emitted_ident(name)}"
        # A function evaluates in one type: uint32_t, or uint64_t when any
        # operand or the result is wider. The driver must match the emitted
        # signature, not assume the narrow one.
        widest = max([width for _, width in entry["params"]]
                     + [entry.get("result_width", 32)])
        wide128 = widest > 64
        ctype = "axis_u128" if wide128 else ("uint64_t" if widest > 32 else "uint32_t")
        suffix = "ULL" if widest > 32 else "u"
        printf_spec = "0x%016llx" if widest > 32 else "0x%08x"
        cast = "(unsigned long long)" if widest > 32 else ""
        if f"{ctype} {fn_name}(" not in header:
            print(f"skip {name}: no C function emitted")
            continue
        vectors = list(golden.sample_vectors(name, count=args.cases // 2))
        for _ in range(args.cases - len(vectors)):
            vectors.append(tuple(
                random.getrandbits(width) for _, width in entry["params"]
            ))
        def wide_literal(value: int) -> str:
            """C has no 128-bit literal, so one is built from its halves --
            the same construction the emitter uses for a wide constant."""
            return (f"((((axis_u128)UINT64_C(0x{value >> 64:x})) << 64)"
                    f" | (axis_u128)UINT64_C(0x{value & ((1 << 64) - 1):x}))")

        for values in vectors:
            expected = entry["eval"](*values)
            if wide128:
                arg_text = ", ".join(wide_literal(value) for value in values)
                # No printf conversion takes a 128-bit value, so a mismatch
                # reports its halves.
                report = (
                    f'      printf("FAIL {name} got 0x%016llx%016llx want 0x{expected:032x}\\n",\n'
                    f'             (unsigned long long)(uint64_t)(got >> 64),\n'
                    f'             (unsigned long long)(uint64_t)got);\n'
                )
                cases.append(
                    f'  {{ {ctype} got = {fn_name}({arg_text});\n'
                    f'    if (got != {wide_literal(expected)}) {{\n{report}'
                    f"      failures++;\n    }}\n    checks++; }}\n"
                )
            else:
                arg_text = ", ".join(f"{value}{suffix}" for value in values) or ""
                cases.append(
                    f'  {{ {ctype} got = {fn_name}({arg_text});\n'
                    f'    if (got != {expected}{suffix}) {{\n'
                    f'      printf("FAIL {name}({values}) got {printf_spec} want 0x{expected:x}\\n", {cast}got);\n'
                    f"      failures++;\n"
                    f"    }}\n"
                    f"    checks++; }}\n"
                )
            total += 1

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

    main_c = workdir / "main.c"
    main_c.write_text(
        '#include <stdio.h>\n#include "axis_semantics.h"\n\n'
        "int main(void) {\n  int failures = 0;\n  int checks = 0;\n"
        + "".join(cases)
        + '  printf("%d checks, %d failures\\n", checks, failures);\n'
        "  return failures == 0 ? 0 : 1;\n}\n"
    )
    binary = workdir / "c_vs_golden"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-o", str(binary), str(main_c), "-lm"],
        check=True,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    print(result.stdout.strip())
    print("C == golden model: PASS" if result.returncode == 0 else "C == golden model: FAIL")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
