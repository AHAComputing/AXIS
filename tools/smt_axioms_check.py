#!/usr/bin/env python3
"""An intrinsic axiom pins its intrinsic to what the instruction computes.

`emit-smt-axioms` declares each intrinsic as an *uninterpreted* function and
constrains it with a universally quantified equality. That is the shape a
verifier needs when it reasons over slices containing intrinsic calls -- a
`define-fun` is inlined, and after inlining the symbol it was asked about is
gone -- and it is what `pce/aha/optisynth/adl_bridge.py` builds today by
re-parsing the `formal_semantics` string out of the bundle.

This gate proves the emitted axioms against the golden model, the way
`smt_vs_golden.py` proves the `define-fun` file: the two sides are AXIS's Rust
lowering and a generated Python evaluator, and they share no code.

**The axiom shape has a failure mode `define-fun` does not, and it is checked
first.** Definitions cannot contradict each other; a set of quantified
assertions can. An unsatisfiable axiom set proves *everything* -- every
refutation query comes back `unsat`, and a gate that only asked refutation
questions would report a perfect score for a file that says nothing. So the
axioms are asked for `check-sat` on their own before any instruction is
checked, and a file that is not satisfiable fails here rather than passing
loudly.

Coverage, per `docs/gate_coverage.md`: a corpus whose instructions are all
effects emits no axioms and is skipped when swept, failed when named.

Usage: tools/smt_axioms_check.py [input.axisl ...] [--cases N]
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
EDGE_VALUES = [0, 1, 2, 0x7F, 0x80, 0xFF, 0x7FFF, 0x8000, 0xFFFF,
               0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]

# `; axis: <ident>` immediately above the declaration is the join key the
# emitter writes: `llvm.pce.<mnemonic-lower>` is not invertible back to the
# golden model's `eval_<ident>`, because one lowercases a mnemonic and the
# other sanitises it.
DECLARATION = re.compile(r"; axis: (\w+)\n\(declare-fun \|([^|]+)\| (.*)\)\n")
SORT = re.compile(r"\(_ BitVec (\d+)\)")


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(output)],
                   cwd=AXIS_ROOT, check=True, capture_output=True)


def load_golden(path: Path):
    spec = importlib.util.spec_from_file_location("axis_golden", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Every axiom is `forall x. f(x) = body`, which is exactly the shape
# `macro-finder` turns back into a definition. Without it z3 instantiates
# quantifiers per query and rv32i's hundred and fifty intrinsics take minutes
# instead of a tenth of a second. The emitted file says so in its header, for
# the consumer that will meet the same wall.
PREAMBLE = "(set-option :smt.macro-finder true)\n"


def z3_answers(text: str, workdir: Path, name: str) -> list[str]:
    path = workdir / name
    path.write_text(PREAMBLE + text)
    result = subprocess.run(["z3", str(path)], capture_output=True, text=True)
    return result.stdout.split()


def check_one(axis_file: Path, cases: int, named: bool) -> int | None:
    workdir = Path(tempfile.mkdtemp(prefix="axis_axioms_"))
    golden_path = workdir / "golden_model.py"
    axioms_path = workdir / "axioms.smt2"
    emit(axis_file, "emit-golden-python", golden_path)
    emit(axis_file, "emit-smt-axioms", axioms_path)
    golden = load_golden(golden_path)
    axioms = axioms_path.read_text()

    functions = []
    for ident, symbol, signature in DECLARATION.findall(axioms):
        # `((_ BitVec 32) (_ BitVec 32)) (_ BitVec 32)`: the parameter sorts
        # and then the result. Taking the result off the end rather than
        # matching nested parentheses, because a regex that tries to balance
        # them is the version of this that quietly matched zero parameters and
        # called the golden model with none.
        sorts = [int(width) for width in SORT.findall(signature)]
        if not sorts:
            print(f"     skip {symbol}: no bit-vector signature")
            continue
        widths, out_width = sorts[:-1], sorts[-1]
        eval_fn = getattr(golden, f"eval_{ident}", None)
        if eval_fn is None:
            # An intrinsic the golden model has no evaluator for cannot be
            # compared against anything, and saying so beats counting it.
            print(f"     skip {symbol}: no golden eval_{ident}")
            continue
        functions.append((symbol, eval_fn, widths, out_width))

    if not functions:
        if named:
            print(f"FAIL {axis_file.name}: emits no intrinsic axioms to check")
            return 1
        return None

    # First, and before anything is proved *from* them: are the axioms
    # satisfiable at all? An unsatisfiable set entails every query, so a
    # contradiction here would read as a perfect score below.
    consistency = z3_answers(axioms + "\n(check-sat)\n", workdir, "consistency.smt2")
    if consistency[:1] != ["sat"]:
        print(f"FAIL {axis_file.name}: the axiom set is not satisfiable "
              f"({consistency[:1] or ['no answer']}); every query it entails would "
              f"come back unsat and prove nothing")
        return 1

    random.seed(0xA1B2)
    queries, labels = [], []
    for symbol, eval_fn, widths, out_width in functions:
        vectors = [[random.getrandbits(width) for width in widths]
                   for _ in range(cases)]
        vectors += [[edge & ((1 << width) - 1) for width in widths]
                    for edge in EDGE_VALUES]
        for values in vectors:
            try:
                expected = eval_fn(*values)
            except NotImplementedError:
                continue
            arguments = " ".join(f"(_ bv{value} {width})"
                                 for value, width in zip(values, widths))
            queries.append(
                f"(push 1)(assert (not (= (|{symbol}| {arguments}) "
                f"(_ bv{expected} {out_width}))))(check-sat)(pop 1)")
            labels.append(f"{symbol}{tuple(values)}")

    answers = z3_answers(axioms + "\n" + "\n".join(queries) + "\n",
                         workdir, "query.smt2")
    mismatches = [label for label, answer in zip(labels, answers)
                  if answer != "unsat"]
    if len(answers) != len(queries):
        print(f"FAIL {axis_file.name}: z3 answered {len(answers)} of "
              f"{len(queries)} queries")
        return 1
    if mismatches:
        print(f"FAIL {axis_file.name}: {len(mismatches)} axiom(s) disagree with the "
              f"golden model, first {mismatches[0]}")
        return 1
    print(f"     {axis_file.name}: {len(functions)} axiom(s), {len(queries)} vector(s), "
          f"consistent and equal to the golden model")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    parser.add_argument("--cases", type=int, default=20,
                        help="random vectors per intrinsic on top of the edges")
    args = parser.parse_args()

    targets = args.axis_files or sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    failures = checked = 0
    for target in targets:
        result = check_one(target, args.cases, named=bool(args.axis_files))
        if result is None:
            continue
        checked += 1
        failures += result
    print(f"{checked} corpus/corpora with intrinsic axioms")
    if not checked:
        print("no corpus emitted an axiom: there is nothing here to prove")
        return DECLINED
    print("intrinsic axioms == golden model: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
