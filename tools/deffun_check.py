#!/usr/bin/env python3
"""A function called computes what the same function inlined does. Gate.

`deffun` (docs/lisp_design.md) is emitted once by every backend and called;
`defsem` is substituted where it is used. Every other gate compares the
backends with each other through a golden model that now CALLS the function
too, so a mistake every backend shared in how a call is made -- an argument
read at the wrong width, a parameter bound to the wrong argument, a result not
narrowed -- would pass them all. Inlining is the path every corpus has proven,
so it is the reference here: the corpus is read a second time with each
`deffun` turned into a `defsem`, and the golden model of each must give the
same answer for every instruction on the same operands.

Random operands, and the edges -- 0, 1, all ones, the sign bit -- because a
width mistake shows at the ends of a range first.

Usage: tools/deffun_check.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import importlib.util
import inspect
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402

EDGES = (0, 1, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF)


def golden(source: Path, work: Path, tag: str):
    out = work / f"golden_{tag}.py"
    subprocess.run([*axis_prefix(), "emit-golden-python", str(source), "-o", str(out)], check=True)
    spec = importlib.util.spec_from_file_location(f"axis_golden_{tag}", out)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=200)
    args = parser.parse_args()

    text = args.axis_file.read_text()
    count = len(re.findall(r"\(deffun\s", text))
    if not count:
        print("SKIP: the description defines no deffun")
        return 0
    work = Path(tempfile.mkdtemp(prefix="axis_deffun_"))
    inlined = work / "inlined.axisl"
    inlined.write_text(re.sub(r"\(deffun(\s)", r"(defsem\1", text))
    called_model = golden(args.axis_file, work, "called")
    inlined_model = golden(inlined, work, "inlined")

    rng = random.Random(0xDEF)
    checks = failures = 0
    names = sorted(name for name in dir(called_model) if name.startswith("eval_"))
    for name in names:
        called, reference = getattr(called_model, name), getattr(inlined_model, name, None)
        if reference is None:
            failures += 1
            print(f"FAIL {name}: missing from the inlined model")
            continue
        arity = len(inspect.signature(called).parameters)
        for case in range(args.cases):
            operands = [rng.choice(EDGES) if case % 4 == 0 else rng.getrandbits(64) for _ in range(arity)]
            try:
                got = called(*operands)
            except NotImplementedError:
                continue
            want = reference(*operands)
            checks += 1
            if got != want:
                failures += 1
                if failures <= 6:
                    print(f"FAIL {name}{tuple(operands)}: called {got:#x}, inlined {want:#x}")
    print(f"{count} deffun(s), {len(names)} instruction(s), {checks} checks, {failures} failures")
    print("called == inlined: " + ("PASS" if checks and not failures else "FAIL"))
    return 0 if checks and not failures else 1


if __name__ == "__main__":
    sys.exit(main())
