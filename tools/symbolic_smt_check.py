#!/usr/bin/env python3
"""The symbolic backend's SMT text means what its terms mean. Proven, not sampled.

`symbolic_check.py` binds a term's variables to one concrete input and compares
numbers. That says the TERM is right; it says nothing about `smt()`, the
rendering a caller hands to a solver -- and a rendering that is wrong only for
inputs nobody drew is exactly the kind of thing a solver is for.

⚠️ The reference is `emit-smt2`, whose `axis_instr_*` functions are already
proven equal to the golden model. So this asks a solver whether the two
spellings of one instruction can EVER differ:

    (assert (distinct (axis_instr_add rs1 rs2) <the symbolic term>))
    (check-sat)                 ; unsat, for every input, or it is not equal

which is a proof over all inputs rather than agreement on one. A term the
backend declines to render is counted by name; an instruction `emit-smt2`
itself declines is not a question this can ask.

Needs `z3` on the path. Without it the gate declines rather than passing.

Usage: tools/symbolic_smt_check.py [input.axisl] [--timeout SECONDS]
"""
from __future__ import annotations

import argparse
import importlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ARTIFACTS = (
    ("emit-lift-python", "axis_lift.py"),
    ("emit-golden-python", "golden_model.py"),
    ("emit-symbolic-python", "axis_symbolic.py"),
    ("emit-smt2", "axis.smt2"),
)

#: `(define-fun axis_instr_name ((a (_ BitVec 64)) ...) (_ BitVec 64)`
SIGNATURE = re.compile(
    r"^\(define-fun (axis_instr_\w+) \(([^\n]*)\) \(_ BitVec (\d+)\)", re.M)
PARAMETER = re.compile(r"\((\w+) \(_ BitVec (\d+)\)\)")


def proven(smt2: str) -> dict[str, tuple[list[tuple[str, int]], int]]:
    """Every function `emit-smt2` defines, with its parameters and width."""
    out = {}
    for match in SIGNATURE.finditer(smt2):
        name, parameters, width = match.group(1), match.group(2), int(match.group(3))
        out[name] = ([(p, int(bits)) for p, bits in PARAMETER.findall(parameters)],
                     width)
    return out


#: A top-level definition in `emit-smt2`'s output, which starts each at column 0.
DEFINITION = re.compile(r"^\(define-fun (\S+) ", re.M)
REFERENCE = re.compile(r"\baxis_\w+")


class Prelude:
    """`emit-smt2`'s output, handed to the solver a function at a time.

    ⚠️ Each query used to carry the WHOLE file. That was free while the file
    was small; AArch64's half-precision forms took it from 18 MB to 54 MB, and
    z3 then spent longer reading definitions no query called than the ten
    seconds each question gets -- so every AArch64 instruction came back
    `timeout`, the constant-only FMOV included, and the gate failed on proofs
    it had never been given time to try. A query now carries the function it
    asks about and what that function calls, in the file's own order.
    """

    def __init__(self, smt2: str):
        starts = [(match.start(), match.group(1)) for match in DEFINITION.finditer(smt2)]
        self.head = smt2[:starts[0][0]] if starts else smt2
        self.order: dict[str, int] = {}
        self.text: dict[str, str] = {}
        for index, (start, name) in enumerate(starts):
            end = starts[index + 1][0] if index + 1 < len(starts) else len(smt2)
            self.order[name] = index
            self.text[name] = smt2[start:end]
        self.calls = {name: {ref for ref in REFERENCE.findall(body)
                             if ref != name and ref in self.text}
                      for name, body in self.text.items()}

    def needed_by(self, name: str, rendered: str) -> str:
        """`name`, whatever the rendering against it calls, and their callees."""
        seen = set()
        stack = [name, *(ref for ref in REFERENCE.findall(rendered) if ref in self.text)]
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(self.calls.get(current, ()))
        return self.head + "".join(self.text[n] for n in sorted(seen, key=self.order.get))


def ask(z3: str, script: str, workdir: Path, index: int, timeout: int) -> str:
    """One query, answered by the solver: `unsat` is the proof."""
    path = workdir / f"query{index}.smt2"
    path.write_text(script)
    try:
        done = subprocess.run([z3, "-smt2", f"-T:{timeout}", str(path)],
                              capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return "timeout"
    return (done.stdout.strip().splitlines() or ["(no answer)"])[0]


def value_of(entry):
    """The expression `emit-smt2`'s function computes, and the width it is at.

    Most instructions carry it in `semantics`. One described by effects carries
    it in a single unguarded `set` -- which is what a floating-point
    instruction looks like, its `fflags` write beside it.
    """
    if entry.get("semantics"):
        return entry["semantics"], None
    sets = [effect for effect in (entry.get("effects") or [])
            if effect["kind"] == "set" and not effect.get("guard")]
    others = [effect for effect in (entry.get("effects") or [])
              if effect["kind"] not in ("set", "setstate")]
    if len(sets) == 1 and not others:
        return sets[0]["value"], sets[0].get("eval_width")
    return None, None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    parser.add_argument("--timeout", type=int, default=10)
    args = parser.parse_args()

    z3 = shutil.which("z3")
    if z3 is None:
        print("no solver on the path: SKIP")
        return DECLINED

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for command, name in ARTIFACTS:
            subprocess.run([*axis_prefix(), command, str(args.axis_file),
                            "-o", str(workdir / name)], check=True,
                           capture_output=True, cwd=AXIS_ROOT)
        sys.path.insert(0, str(workdir))
        lift = importlib.import_module("axis_lift")
        golden = importlib.import_module("golden_model")
        sym = importlib.import_module("axis_symbolic")
        smt2 = (workdir / "axis.smt2").read_text()
        functions = proven(smt2)
        prelude = Prelude(smt2)

        equal = failures = unrendered = unasked = unknown = unexpressed = 0
        reasons: dict[str, str] = {}
        for entry in lift.AXIS_LIFT_TABLE:
            ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
            name = f"axis_instr_{ident}"
            if name not in functions:
                continue                  # `emit-smt2` declined it, with a reason
            text, inner = value_of(entry)
            if not text:
                # ⚠️ Counted, not skipped. `emit-smt2` defines a function for
                # this instruction and this backend had nothing to compare
                # against it, which is a gap rather than a non-question -- and
                # while it was silent, every floating-point instruction in the
                # corpus went unasked, because their value lives in a `set`
                # effect rather than in `semantics`.
                unexpressed += 1
                continue
            parameters, width = functions[name]
            env = {parameter: sym.var(parameter, bits)
                   for parameter, bits in parameters}
            try:
                term = sym.evaluate(golden._parse(golden._tokenize(text)), env,
                                    inner or entry.get("state_width") or width)
                rendered = sym.smt(sym._widen(term, width))
            except sym.Declined as why:
                unrendered += 1
                reasons.setdefault(str(why), entry["mnemonic"])
                continue
            named = sym.variables(term)
            if any(v not in dict(parameters) for v in named):
                # A term that reads something the function does not take --
                # architectural state, a pc -- is not the same question.
                unasked += 1
                continue

            lines = [prelude.needed_by(name, rendered)]
            for parameter, bits in parameters:
                lines.append(f"(declare-const {parameter} (_ BitVec {bits}))")
            call = f"({name} {' '.join(p for p, _ in parameters)})"
            lines.append(f"(assert (distinct {call} {rendered}))")
            lines.append("(check-sat)")
            answer = ask(z3, "\n".join(lines), workdir, equal + failures, args.timeout)
            if answer == "unsat":
                equal += 1
            elif answer == "sat":
                failures += 1
                if failures <= 4:
                    print(f"FAIL {entry['mnemonic']}: the rendering and "
                          f"`{name}` can differ")
            else:
                unknown += 1
                reasons.setdefault(f"solver said `{answer}`", entry["mnemonic"])
                # Named like a failure, since it fails the gate like one: the
                # reasons below are cut to four and sort a timeout last.
                if unknown <= 4:
                    print(f"UNKNOWN {entry['mnemonic']}: the solver said `{answer}`")

    print(f"{equal} instruction(s) proven equal to `emit-smt2`, {failures} not; "
          f"{unknown} the solver could not answer")
    print(f"  {unrendered} term(s) this backend does not render, "
          f"{unasked} that read something the function does not take, "
          f"{unexpressed} the backend has no single value for")
    if reasons:
        for why, mnemonic in sorted(reasons.items())[:4]:
            print(f"    {why} (e.g. {mnemonic})")
    if not equal:
        print("symbolic SMT == proven SMT: SKIP (nothing was asked)")
        return DECLINED
    print("symbolic SMT == proven SMT:", "FAIL" if failures or unknown else "PASS")
    return FAILED if failures or unknown else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
