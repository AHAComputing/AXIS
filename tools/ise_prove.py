#!/usr/bin/env python3
"""Prove a mined extension computes what the instructions it replaces computed.

`ise_mine.py` composes a run of instructions into one semantics tree. That
composition is the part of a mining pipeline most likely to be quietly wrong --
an operand bound to the wrong value, a width dropped, two instructions ordered
by their addresses rather than their dataflow -- and the failure mode is a
plausible extension that computes something else.

So it is checked rather than trusted, and checked through a different path than
it was built. Two sides:

* **The proposal.** The composed tree is written out as an AXIS instruction and
  AXIS lowers *that* to SMT, exactly as it lowers any instruction.
* **The original.** The same run is composed again, this time by substituting
  AXIS's own `axis_instr_*` definitions for the instructions it covers.

One side goes tree -> description -> SMT; the other goes SMT -> SMT. They are
built by different code and must agree for every input, which is a question for
a solver rather than for a test vector.

An unprovable candidate is reported as unprovable. It is not dropped and it is
not counted as proven: a mining report whose obligations were quietly skipped
is a list of guesses.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def smt_definitions(axis_file: Path) -> dict:
    """`mnemonic -> (parameters, body)` from AXIS's own SMT emitter."""
    text = subprocess.run([*axis_prefix(), "emit-smt2", str(axis_file)],
                          capture_output=True, text=True, check=True,
                          cwd=AXIS_ROOT).stdout
    found = {}
    for match in re.finditer(
            r"\(define-fun (axis_\w+) \((.*?)\) \(_ BitVec (\d+)\)\n(.*?)\)\n\n",
            text + "\n\n", re.S):
        name, params, width, body = match.groups()
        arguments = re.findall(r"\((\w+) \(_ BitVec (\d+)\)\)", params)
        found[name] = (arguments, int(width), body.strip())
    return found, text


def proposal_source(name: str, semantics: str, operands: list, width: int,
                    immediates: list, state: list) -> str:
    """A one-instruction AXIS description carrying the composed semantics.

    Written as a `behavior` with one register write rather than a `formal`.
    Both are values and `pure_value_semantics` reads either, but only a
    behavior may use an architecture's own operators -- a formal is validated
    against the shared IR, which has no `a64_shift_reg` on purpose. Since the
    composition comes from instructions that were themselves described as
    behaviors, the proposal is written the way the code it replaces was.

    This is the artifact the mining is *for*: a proposal in the language every
    other emitter reads, so a candidate that proves out can go straight to a
    decoder, a compiler backend and a simulator without being retyped.
    """
    # Registers read through the register file; immediates carried in the
    # instruction word, at the width the field they came from has.
    reads = "\n      ".join(
        [f"({op} reg i{width} in)" for op in operands]
        + [f"({name} imm i{bits} in)" for name, bits in immediates])
    # An extension that replaces instructions reading architectural state reads
    # it too, so the proposal declares an ISA carrying exactly those registers.
    # AXIS then appends them to the signature the same way it does for the
    # instructions being replaced -- the proposal is described the way the code
    # it replaces was described.
    isa = ""
    isa_line = ""
    if state:
        registers = " ".join(f'"{n}:i{bits}"' for n, bits in state)
        isa = f"""  (defisa {name}_isa
    (role source)
    (word-bits {width})
    (registers {registers}))

"""
        isa_line = f"    (isa {name}_isa)\n"
    return f"""(axis-module {name}_proposal
  (version "1.0")
  (target rvmt)
  (description "Mined extension candidate")

{isa}  (definstruction {name}
{isa_line}
    (mnemonic {name.upper()})
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 1)
    (operands
      (rd reg i{width} out)
      {reads}
    )
    (semantics "mined from a real binary")
    (behavior (set rd {semantics}))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
    (rationale "Candidate mined by ise_mine.py; equivalence discharged by ise_prove.py")
  )
)
"""


def render_definition(name, definition) -> str:
    """One `define-fun`, as AXIS emitted it."""
    parameters, width, body = definition
    arguments = " ".join(f"({p} (_ BitVec {w}))" for p, w in parameters)
    return f"(define-fun {name} ({arguments}) (_ BitVec {width})\n  {body})"


def compose_smt(candidate, definitions, width, state_names=()):
    """The run, composed out of AXIS's per-instruction SMT definitions.

    The shape string records what each operand of each step was bound to -- an
    input, a constant, or an earlier step -- which is enough to build the call
    tree without re-deriving the dataflow. Returns None when a step has no SMT
    definition or a width that does not match, which is a decline rather than
    an approximation: extending a value to make the query type-check would be
    inventing semantics the description never stated.
    """
    steps = candidate["shape"].split(" ; ")
    bound = {}
    last = None
    for step in steps:
        head = re.match(r"^t(\d+)=(\w+)\((.*)\)$", step)
        if head is None:
            return None
        index, mnemonic, arguments = head.groups()
        name = f"axis_instr_{mnemonic.lower()}"
        if name not in definitions:
            return None
        parameters, result_width, _body = definitions[name]
        if result_width != width:
            return None
        widths = {parameter: int(w) for parameter, w in parameters}
        given = {}
        for argument in arguments.split(",") if arguments else []:
            key, _, value = argument.partition("=")
            if value.startswith("t"):
                given[key] = bound[int(value[1:])]
            elif value.startswith("a") or value.startswith("k"):
                given[key] = value
            else:
                # An immediate has the width the *field* has, not the machine's:
                # `c.slli`'s shift amount is six bits, and stating it at
                # sixty-four is a type error the solver would refuse.
                bits = widths.get(key, width)
                given[key] = f"(_ bv{int(value) & ((1 << bits) - 1)} {bits})"
        ordered = []
        for parameter, declared in parameters:
            part = given.get(parameter)
            if part is None and parameter in state_names:
                # A trailing state parameter -- the same `nzcv` every
                # instruction in the run reads, and the same one the proposal
                # reads. One constant, shared, is what makes them comparable.
                part = parameter
            if part is None:
                return None
            # A value flowing between instructions is a machine word. A
            # parameter narrower than that would need an extract, which is a
            # claim about which bits the extension keeps -- so it is declined
            # rather than guessed.
            # A register value is a machine word; an immediate is whatever
            # width its field is, and the proposal declares it that way. A
            # register parameter narrower than the machine would need an
            # extract -- a claim about which bits the extension keeps -- so it
            # is declined rather than guessed.
            if part.startswith("a") and int(declared) != width:
                return None
            ordered.append(part)
        bound[int(index)] = f"({name} {' '.join(ordered)})"
        last = bound[int(index)]
    return last


def discharge(query: str, workdir: Path, index: int) -> str:
    """`unsat` (the two agree), `sat` (a counterexample), or the solver's word."""
    path = workdir / f"query{index}.smt2"
    path.write_text(query)
    result = subprocess.run(["z3", "-smt2", str(path)], capture_output=True,
                            text=True)
    return (result.stdout or result.stderr).strip().splitlines()[0] \
        if (result.stdout or result.stderr).strip() else "no answer"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidates", type=Path)
    parser.add_argument("--top", type=int, default=8)
    parser.add_argument("--width", type=int, default=64,
                        help="the machine width the obligation is stated at")
    parser.add_argument("--out", type=Path, default=None,
                        help="write the proven proposals here, as AXIS descriptions")
    args = parser.parse_args()

    if subprocess.run(["which", "z3"], capture_output=True).returncode != 0:
        print("SKIP: z3 is not installed")
        return DECLINED

    report = json.loads(args.candidates.read_text())
    axis_file = Path(report["description"])
    definitions, _text = smt_definitions(axis_file)
    workdir = Path(tempfile.mkdtemp(prefix="axis_iseprove_"))

    proven = refuted = declined = 0
    for index, candidate in enumerate(report["candidates"][:args.top]):
        label = "+".join(candidate["mnemonics"])
        operands = candidate["operands"]
        # The width the candidate computes at, taken from the instructions it
        # covers rather than assumed. AArch64 has 32-bit and 64-bit forms of
        # everything, and stating a W-form's obligation at 64 bits asks the
        # solver a question about a function it does not have.
        widths = {definitions[f"axis_instr_{m.lower()}"][1]
                  for m in candidate["mnemonics"]
                  if f"axis_instr_{m.lower()}" in definitions}
        if len(widths) != 1:
            print(f"  DECLINE {label}: "
                  + ("an instruction with no SMT definition" if not widths
                     else f"mixed widths {sorted(widths)}"))
            declined += 1
            continue
        width = widths.pop()
        # The state the run reads, with the widths the originals declare it at.
        # `pc` is not among them: AXIS does not carry it as architectural state,
        # and an extension that fused a pc-relative instruction would compute a
        # different address wherever it was placed -- so a candidate reading it
        # is declined rather than proposed.
        wanted = candidate.get("state", [])
        state = []
        for name in wanted:
            found = next((bits for m in candidate["mnemonics"]
                          for p, bits in definitions.get(
                              f"axis_instr_{m.lower()}", ((), 0, ""))[0]
                          if p == name), None)
            if found is None:
                break
            state.append((name, int(found)))
        if len(state) != len(wanted):
            print(f"  DECLINE {label}: reads `{wanted[len(state)]}`, which is not "
                  f"architectural state a proposal can declare")
            declined += 1
            continue
        right = compose_smt(candidate, definitions, width,
                            {name for name, _bits in state})
        if right is None or not candidate.get("formal_semantics") \
                or not (operands or candidate.get("immediates")):
            print(f"  DECLINE {label}: no SMT composition at {width} bits")
            declined += 1
            continue

        name = f"mined{index}"
        source = proposal_source(name, candidate["formal_semantics"], operands,
                                 width, candidate.get("immediates", []), state)
        (workdir / f"{name}.axisl").write_text(source)
        check = subprocess.run([*axis_prefix(), "emit-smt2",
                                str(workdir / f"{name}.axisl")],
                               capture_output=True, text=True, cwd=AXIS_ROOT)
        if check.returncode != 0:
            print(f"  DECLINE {label}: the proposal is not a description AXIS "
                  f"accepts ({check.stderr.strip().splitlines()[0][:80] if check.stderr.strip() else 'no message'})")
            declined += 1
            continue
        left_definitions, left_text = smt_definitions(workdir / f"{name}.axisl")
        left_name = f"axis_instr_{name}"
        if left_name not in left_definitions:
            print(f"  DECLINE {label}: AXIS emitted no SMT for the proposal")
            declined += 1
            continue

        declares = "\n".join(
            [f"(declare-const {op} (_ BitVec {width}))" for op in operands]
            + [f"(declare-const {name} (_ BitVec {bits}))"
               for name, bits in candidate.get("immediates", []) + state])
        left_call = (f"({left_name} "
                     + " ".join(operands
                                + [n for n, _b in candidate.get("immediates", [])]
                                + [n for n, _b in state]) + ")")
        # Only what the claim mentions. Emitting the whole file pulls in the
        # floating-point definitions, and `RNE` is not a term `QF_BV` has.
        needed = [f"axis_instr_{m.lower()}" for m in candidate["mnemonics"]]
        # An instruction body may call an architecture's own operator --
        # `axis_a64_shift_reg_64` and friends -- so those definitions come
        # first. Leaving them out produced a query that named a constant the
        # solver had never heard of, which is an error and not an answer.
        # ⚠️ Named by what they ARE, not by what they are not. This used to take
        # every definition that was not an instruction, and when the SMT file
        # grew a third family -- `axis_effect_*`, one per part of a behavior --
        # it swept those in too and pulled floating-point rounding modes into a
        # `QF_BV` query, which the solver answers with an error rather than an
        # answer.
        helpers = [name for name in definitions if name.startswith("axis_a64_")]
        helpers += [name for name in left_definitions
                    if name.startswith("axis_a64_") and name not in helpers]
        body = [render_definition(n, definitions.get(n) or left_definitions[n])
                for n in helpers]
        body.append(render_definition(left_name, left_definitions[left_name]))
        body += [render_definition(n, definitions[n]) for n in dict.fromkeys(needed)
                 if n in definitions]
        query = ("(set-logic QF_BV)\n" + "\n".join(body)
                 + f"\n{declares}\n(assert (not (= {left_call} {right})))\n"
                 f"(check-sat)\n")
        answer = discharge(query, workdir, index)
        if answer == "unsat":
            print(f"  PROVEN  {label} -> {name} ({candidate['saved']} saved, "
                  f"{len(operands)} input(s))")
            proven += 1
            if args.out:
                args.out.mkdir(parents=True, exist_ok=True)
                (args.out / f"{name}.axisl").write_text(source)
        elif answer == "sat":
            print(f"  REFUTED {label}: the proposal is not what those "
                  f"instructions compute")
            refuted += 1
        else:
            print(f"  DECLINE {label}: the solver said {answer!r}")
            declined += 1

    print(f"{proven} proven, {refuted} refuted, {declined} declined")
    # A refutation is a defect in the composition; a decline is a limit that is
    # named. Only the first fails the gate.
    ok = refuted == 0 and proven > 0
    print("mined extensions == the code they replace: "
          + ("PASS" if ok else "FAIL"))
    return PASSED if ok else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
