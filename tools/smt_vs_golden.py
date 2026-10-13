#!/usr/bin/env python3
"""Differentially check AXIS SMT semantics against the generated golden model.

For every instruction/accelerator with formal_semantics, this emits both
`golden_model.py` and `semantics.smt2` from the same .axisl source, evaluates
the golden model on edge-case and random input vectors, and asks z3 to prove
the SMT define-fun returns the same value (by asserting inequality and
requiring unsat).

Usage: tools/smt_vs_golden.py <input.axisl> [--cases N]

Requires: cargo (run from the AXIS repo root), python3, z3 on PATH.
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

EDGE_VALUES = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF,
               0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

# Operand *pairs* that put a float sum exactly halfway between two
# representables. The edge values above go into every parameter at once, so
# they can never make a tie -- and a tie is the only place ties-to-even and
# ties-away differ, so without these a rounding mode that confused the two
# passed every vector. Measured: breaking RMM to behave as RNE left this gate
# green until these were added.
#
# 1.0 + 2^-24 is a tie in binary32 and 1.0 + 2^-53 in binary64, with their
# negatives for the other sign. A third operand of 1.0 makes the same tie
# reachable through the fused multiply-adds, where the product is the addend.
FP_TIE_VECTORS = [
    [0x3F800000, 0x33800000, 0x3F800000],
    [0xBF800000, 0xB3800000, 0x3F800000],
    [0x3FF0000000000000, 0x3CA0000000000000, 0x3FF0000000000000],
    [0xBFF0000000000000, 0xBCA0000000000000, 0x3FF0000000000000],
    # Integers that expose *double* rounding on the way to a binary32. Each
    # sits one unit above the midpoint between two representables, so it rounds
    # up -- but rounding it to a double's 53 bits first lands it exactly on that
    # midpoint, where ties-to-even takes it back down. The window is one in
    # 2**39, so no random draw reaches it, and z3's `to_fp` rounds once and
    # disagrees the moment a backend rounds twice. Signed and unsigned, both
    # signs: the RV64 long conversions are the first instructions that can ask.
    [9223372586610589697, 0x3F800000, 0x3F800000],
    [4611686293305294849, 0x3F800000, 0x3F800000],
    [(-4611686293305294849) & 0xFFFFFFFFFFFFFFFF, 0x3F800000, 0x3F800000],
    [9223372586610589697 ^ 0x8000000000000000, 0x3F800000, 0x3F800000],
]

DEFINE_FUN = re.compile(
    r"\(define-fun\s+(axis_(?:instr|accel)_\w+)\s+\((.*?)\)\s+\(_ BitVec (\d+)\)",
    re.DOTALL,
)
PARAM = re.compile(r"\(\s*(\w+)\s+\(_ BitVec (\d+)\)\s*\)")


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
    )


def load_golden(path: Path):
    spec = importlib.util.spec_from_file_location("axis_golden", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    parser.add_argument("--cases", type=int, default=25,
                        help="random vectors per function on top of edge values")
    args = parser.parse_args()

    # With no argument, every corpus that emits SMT definitions. The backend was
    # emitted for twenty-two of them and gated on five, so four hundred
    # definitions -- a hundred and forty-six of them RV64I's -- were generated
    # and never compared against anything. Sweeping by default is what stops a
    # corpus being added and nobody remembering to gate it.
    targets = args.axis_files or sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    failures = 0
    checked = 0
    for target in targets:
        result = check_one(target, args.cases, named=bool(args.axis_files))
        if result is None:
            continue
        checked += 1
        failures += result
    print(f"{checked} corpus/corpora with SMT definitions")
    print("SMT == golden model: " + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


def check_one(axis_file: Path, cases: int, named: bool) -> int | None:
    workdir = Path(tempfile.mkdtemp(prefix="axis_diff_"))
    golden_path = workdir / "golden_model.py"
    smt_path = workdir / "semantics.smt2"
    emit(axis_file, "emit-golden-python", golden_path)
    emit(axis_file, "emit-smt2", smt_path)

    golden = load_golden(golden_path)
    smt_source = smt_path.read_text()

    functions = []
    for match in DEFINE_FUN.finditer(smt_source):
        smt_name, params_text, out_width = match.groups()
        params = [(name, int(width)) for name, width in PARAM.findall(params_text)]
        suffix = smt_name.split("_", 2)[2]
        eval_fn = getattr(golden, f"eval_{suffix}", None)
        if eval_fn is None:
            print(f"skip {smt_name}: no golden eval_{suffix}")
            continue
        functions.append((smt_name, eval_fn, params, int(out_width)))

    if not functions:
        # A corpus with nothing to compare is skipped, not failed: sweeping
        # every example means meeting descriptions that are all effects.
        if named:
            print("no formal_semantics functions found")
            return 1
        return None

    random.seed(0xA1B2)
    queries = []
    query_labels = []
    total = 0
    for smt_name, eval_fn, params, out_width in functions:
        vectors = []
        for _ in range(cases):
            vectors.append([random.getrandbits(width) for _, width in params])
        for edge in EDGE_VALUES:
            vectors.append([edge & ((1 << width) - 1) for _, width in params])
        for tie in FP_TIE_VECTORS:
            vectors.append([tie[index % len(tie)] & ((1 << width) - 1)
                            for index, (_, width) in enumerate(params)])
        for values in vectors:
            try:
                expected = eval_fn(*values)
            except NotImplementedError:
                continue
            arg_text = " ".join(
                f"(_ bv{value} {width})"
                for value, (_, width) in zip(values, params)
            )
            # A function of nothing is applied by its bare name: `(f)` is not
            # SMT-LIB. SVE's PFALSE and SETFFR are the first such instructions.
            call = f"({smt_name} {arg_text})" if params else smt_name
            queries.append(
                f"(push 1)(assert (not (= {call} "
                f"(_ bv{expected} {out_width}))))(check-sat)(pop 1)"
            )
            query_labels.append(f"{smt_name}{tuple(values)}")
            total += 1

    query_path = workdir / "query.smt2"
    query_path.write_text(smt_source + "\n" + "\n".join(queries) + "\n")
    result = subprocess.run(["z3", str(query_path)], capture_output=True, text=True)
    answers = result.stdout.split()
    mismatches = sum(1 for answer in answers if answer != "unsat")
    ok = mismatches == 0 and len(answers) == total

    print(f"  {axis_file.name}: {len(functions)} functions, {total} cases, "
          f"{mismatches} mismatches")
    if not ok and result.stderr:
        print(result.stderr[:500], file=sys.stderr)
    if mismatches:
        bad = [
            label
            for label, answer in zip(query_labels, answers)
            if answer != "unsat"
        ]
        print("first mismatches: " + ", ".join(bad[:10]))
    if named:
        print("SMT == golden model: PASS" if ok else "SMT == golden model: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
