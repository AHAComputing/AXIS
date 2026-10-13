#!/usr/bin/env python3
"""Prove a loop-defined operation equals the built-in it reimplements.

Most gates in this ladder sample: they drive both sides with vectors and compare
results. This one proves. `cpop` is already a primitive operator, so a loop that
computes a population count has a reference *inside the language*, and the SMT
backend can decide whether the two agree for every input at once -- assert they
differ and require `unsat`.

That is a stronger claim than any amount of sampling, and it is available only
because both sides are describable in the same language. Where a loop has no
built-in counterpart, sampling against the golden model is all there is.

The tool also checks that it *can* tell two things apart: a pair known to differ
must come back `sat`. A prover that answered `unsat` to everything -- a
malformed query, a name that does not resolve -- would otherwise report every
equivalence as proven.

Usage: tools/loop_equivalence.py <input.axisl>
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# (loop-defined, reference, must-be-equal). The last pair is expected to
# *differ*: it is what shows the prover can still say no.
PAIRS = [
    ("CPOP_LOOP_S", "CPOP_PRIM_S", True),
    ("CPOP_LOOP_H", "CPOP_PRIM_H", True),
    ("CPOP_LOOP_S", "PARITY_LOOP_S", False),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--z3", default="z3")
    args = parser.parse_args()

    smt = subprocess.run(
        [*axis_prefix(), "emit-smt2", str(args.axis_file)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT,
    ).stdout

    widths = {
        name: int(width)
        for name, width in re.findall(
            r"\(define-fun axis_instr_(\w+) \(\(\w+ \(_ BitVec (\d+)\)\)\)", smt
        )
    }
    workdir = Path(tempfile.mkdtemp(prefix="axis_loopeq_"))
    proved = differed = failures = 0

    for left, right, expect_equal in PAIRS:
        low, row = left.lower(), right.lower()
        if low not in widths or row not in widths:
            print(f"skip {left} vs {right}: not both present")
            continue
        if widths[low] != widths[row]:
            print(f"FAIL {left} vs {right}: widths {widths[low]} and {widths[row]}")
            failures += 1
            continue
        width = widths[low]
        query = workdir / f"{low}_vs_{row}.smt2"
        query.write_text(
            smt
            + f"\n(declare-fun axis_eq_input () (_ BitVec {width}))\n"
            + f"(assert (not (= (axis_instr_{low} axis_eq_input)"
            + f" (axis_instr_{row} axis_eq_input))))\n(check-sat)\n"
        )
        result = subprocess.run(
            [args.z3, str(query)], capture_output=True, text=True
        )
        verdict = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else "(none)"
        if verdict not in ("sat", "unsat"):
            print(f"FAIL {left} vs {right}: solver said {verdict!r}")
            failures += 1
            continue
        equal = verdict == "unsat"
        if equal != expect_equal:
            failures += 1
            print(
                f"FAIL {left} vs {right}: "
                f"{'equal' if equal else 'differ'}, expected "
                f"{'equal' if expect_equal else 'differ'}"
            )
        elif expect_equal:
            proved += 1
            print(f"  proved {left} == {right} for all {width}-bit inputs")
        else:
            differed += 1
            print(f"  confirmed {left} != {right}, so the prover can still say no")

    if not proved:
        print("nothing was proved equal")
        failures += 1
    if not differed:
        print("no pair was shown to differ; an always-unsat prover would look identical")
        failures += 1
    print("loop == built-in: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
