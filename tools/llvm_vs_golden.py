#!/usr/bin/env python3
"""Differential check: the generated LLVM IR semantics vs the golden model.

Emits `axis_semantics.ll` and `golden_model.py` from the same .axisl source,
compiles the LLVM IR with clang against a generated C driver, drives every
`axis_eval_*` function with the golden model's own deterministic
`sample_vectors` (plus randomized vectors), and requires bit-identical results.
This is the LLVM-IR sibling of `c_vs_golden.py`.

Usage: tools/llvm_vs_golden.py <input.axisl> [--cases N]

Requires: cargo (run from the AXIS repo root) and a clang that can compile
textual LLVM IR (`.ll`). Exits 0 with a SKIP notice if clang cannot.
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


def clang_handles_ll(clang: str, workdir: Path) -> bool:
    probe = workdir / "probe.ll"
    probe.write_text("define i32 @axis_probe() {\nentry:\n  ret i32 7\n}\n")
    obj = workdir / "probe.o"
    result = subprocess.run(
        [clang, "-c", str(probe), "-o", str(obj)],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0



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
    parser.add_argument("--clang", default="clang", help="clang executable")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_lvg_"))
    if not clang_handles_ll(args.clang, workdir):
        print(f"SKIP: {args.clang} cannot compile textual LLVM IR here")
        return 0

    golden_path = workdir / "golden_model.py"
    ll_path = workdir / "axis_semantics.ll"
    emit(args.axis_file, "emit-golden-python", golden_path)
    emit(args.axis_file, "emit-llvm-ir", ll_path)

    spec = importlib.util.spec_from_file_location("axis_golden", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    ll_text = ll_path.read_text()
    random.seed(0x11FA)
    decls: list[str] = []
    cases: list[str] = []
    total = 0
    for name, entry in golden.AXIS_SPECS.items():
        fn_name = f"axis_eval_{emitted_ident(name)}"
        # A function evaluates in one type -- i32, i64, or i128 -- from its
        # widest operand or result. The C driver has to agree with the emitted
        # signature; only the throwaway driver uses `unsigned __int128`, never
        # a shipped artifact.
        widest = max([width for _, width in entry["params"]]
                     + [entry.get("result_width", 32)])
        if widest > 64:
            # Only the driver uses the extension; the emitted .ll uses i128.
            ctype, llvm_type = "unsigned __int128", "i128"
        elif widest > 32:
            ctype, llvm_type = "uint64_t", "i64"
        else:
            ctype, llvm_type = "uint32_t", "i32"
        suffix = "" if widest > 64 else ("ULL" if widest > 32 else "u")
        if f"define {llvm_type} @{fn_name}(" not in ll_text:
            print(f"skip {name}: no LLVM function emitted")
            continue
        arity = len(entry["params"])
        param_decl = ", ".join([ctype] * arity) or "void"
        decls.append(f"extern {ctype} {fn_name}({param_decl});")

        vectors = list(golden.sample_vectors(name, count=args.cases // 2))
        for _ in range(args.cases - len(vectors)):
            vectors.append(tuple(
                random.getrandbits(width) for _, width in entry["params"]
            ))
        for values in vectors:
            expected = entry["eval"](*values)
            def literal(value: int) -> str:
                if widest <= 64:
                    return f"{value}{suffix}"
                lo, hi = value & ((1 << 64) - 1), value >> 64
                return (f"((((unsigned __int128){hi}ULL) << 64) | "
                        f"(unsigned __int128){lo}ULL)")
            arg_text = ", ".join(literal(value) for value in values)
            if widest > 64:
                # printf has no 128-bit conversion; compare as one value and
                # report the two halves.
                printf_spec = "0x%016llx%016llx"
                cast = ("(unsigned long long)(got >> 64), "
                        "(unsigned long long)(got & ~(unsigned __int128)0 >> 64)")
            else:
                printf_spec = "0x%016llx" if widest > 32 else "0x%08x"
                cast = "(unsigned long long)got" if widest > 32 else "got"
            cases.append(
                f'  {{ {ctype} got = {fn_name}({arg_text});\n'
                f'    if (got != {literal(expected)}) {{\n'
                f'      printf("FAIL {name}({values}) got {printf_spec} want 0x{expected:x}\\n", {cast});\n'
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
        "#include <stdio.h>\n#include <stdint.h>\n\n"
        + "\n".join(decls)
        + "\n\nint main(void) {\n  int failures = 0;\n  int checks = 0;\n"
        + "".join(cases)
        + '  printf("%d checks, %d failures\\n", checks, failures);\n'
        "  return failures == 0 ? 0 : 1;\n}\n"
    )
    binary = workdir / "llvm_vs_golden"
    subprocess.run(
        [args.clang, "-Wno-override-module", "-o", str(binary),
         str(main_c), str(ll_path)],
        check=True,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    print(result.stdout.strip())
    ok = result.returncode == 0
    print("LLVM IR == golden model: PASS" if ok else "LLVM IR == golden model: FAIL")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
