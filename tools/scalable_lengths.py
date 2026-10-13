#!/usr/bin/env python3
"""Prove a scalable document at several vector lengths.

A scalable description is length-agnostic; its *proof* is not, because neither
backend can be. SMT-LIB has no scalable bitvector sort at all -- `(_ BitVec n)`
with a variable `n` is not a sort -- and LLVM's `<vscale x N x iW>` cannot be
legalized on a host without SVE. So the ladder does with vector length what it
already does with widths: instantiate at concrete values and prove each one.

This runs the backend-vs-golden checks over a set of lengths by rewriting the
document's `(vector-bits N)`. Agreement at 128 alone would not distinguish a
correct instantiation from one that happens to work at four lanes.

Usage: tools/scalable_lengths.py <input.axisl> [--lengths 128,256,512]
                                 [--backends llvm,smt,c,rust]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent))
from axis_cli import DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
TOOLS = {
    "llvm": "llvm_vs_golden.py",
    "smt": "smt_vs_golden.py",
    "c": "c_vs_golden.py",
    "rust": "rust_vs_golden.py",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--lengths", default="128,256,512")
    parser.add_argument("--backends", default="llvm,smt,c")
    args = parser.parse_args()

    source = args.axis_file.read_text()
    if not re.search(r"\(vector-bits \d+\)", source):
        print("no `(vector-bits N)` to vary")
        return DECLINED
    backends = [name.strip() for name in args.backends.split(",") if name.strip()]
    unknown = [name for name in backends if name not in TOOLS]
    if unknown:
        print(f"unknown backend(s): {', '.join(unknown)}")
        return 1

    workdir = Path(tempfile.mkdtemp(prefix="axis_svl_"))
    failures = []
    for length in [int(value) for value in args.lengths.split(",")]:
        variant = workdir / f"vl{length}.axisl"
        variant.write_text(
            re.sub(r"\(vector-bits \d+\)", f"(vector-bits {length})", source)
        )
        for backend in backends:
            result = subprocess.run(
                [sys.executable, str(AXIS_ROOT / "tools" / TOOLS[backend]), str(variant)],
                capture_output=True,
                text=True,
                cwd=AXIS_ROOT,
            )
            tail = (result.stdout.strip().splitlines() or ["(no output)"])[-1]
            print(f"  VL={length:<4} {backend:<5} {tail}")
            if result.returncode != 0:
                failures.append(f"VL={length} {backend}")

    print(
        f"scalable at lengths {args.lengths}: "
        + ("PASS" if not failures else f"FAIL ({', '.join(failures)})")
    )
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
