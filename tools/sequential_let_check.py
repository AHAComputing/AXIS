#!/usr/bin/env python3
"""A later binding sees the earlier ones. Gate.

`let` in AXIS semantics takes a list of bindings and one body. Until now the
bindings were SIMULTANEOUS: each one's expression was elaborated against the
scope OUTSIDE the `let`, so a binding could not name the binding above it.
Descriptions that needed a chain of steps had to nest single-binding `let`s
into a staircase, and the corpus is full of them. Sequential bindings let the
same computation be written flat -- a dataflow block of named steps that is
still one pure expression underneath, which is the shape a saturating or
lane-selecting operator wants.

The obvious way to test that is to check the flat form PARSES. That gate would
measure almost nothing. Parsing is the front end; the meaning is decided later,
where `let` is inlined into the typed IR, and an inliner that substituted in
the wrong order would sail through a parse check.

So the discriminator here is SHADOWING, and it is silent:

    (let ((rs2    (add i32 rs1 rs2))
          (scaled (mul i32 rs2 3)))
      scaled)

`rs2` is also an operand. Under sequential bindings the second `rs2` is the
sum; under simultaneous bindings it is the operand. BOTH READINGS PARSE. They
just compute different functions, so nothing short of evaluating the thing can
tell them apart -- which is exactly what a gate should be made of.

The check is then a proof rather than a sample. `emit-smt2` lowers each variant
to a bit-vector function and z3 answers over ALL 2^64 input pairs:

  * **flat == staircase.** The staircase is unambiguous -- nesting forces the
    order -- so this pins the flat form's meaning to the only reading that was
    ever expressible. Proved, not sampled;
  * **flat != the simultaneous reading.** Spelled out as its own instruction.
    If this came back unsat the discriminator would be measuring nothing, so
    it is asserted rather than assumed;
  * **the golden Python model agrees**, over a sample. A proof about the SMT
    backend is a proof about the SMT backend; a second, independently emitted
    evaluator is what makes it a statement about the language.

Vacuity guards: every variant must be non-constant and must actually depend on
both operands (a chain of steps that ignores its inputs proves nothing), and a
missing z3 DECLINES by name rather than passing quietly.

Usage: tools/sequential_let_check.py
"""
from __future__ import annotations

import importlib
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Each variant is one instruction in a single module, so `emit-smt2` runs once
#: and every `define-fun` lands in the same SMT script.
VARIANTS = {
    # The shadowing discriminator, written flat. Only sequential bindings make
    # the second `rs2` mean the sum.
    "shflat": """(let ((rs2 (add i32 rs1 rs2))
            (scaled (mul i32 rs2 3)))
        scaled)""",
    # The same thing nested. Nesting cannot be read any other way.
    "shnest": """(let ((rs2 (add i32 rs1 rs2)))
        (let ((scaled (mul i32 rs2 3)))
          scaled))""",
    # What SIMULTANEOUS bindings would have computed: `rs2` is the operand.
    "shpar": """(let ((scaled (mul i32 rs2 3)))
        scaled)""",
    # A real dataflow block: signed saturating add as five named steps, each
    # naming the ones before it. This is the shape the NEON saturating lane
    # operators need, and it is unwritable without sequential bindings.
    "satflat": """(let ((sum (add i32 rs1 rs2))
            (same_sign (icmp_eq i32 (and i32 (xor i32 rs1 rs2) 0x80000000) 0))
            (flipped (icmp_ne i32 (and i32 (xor i32 rs1 sum) 0x80000000) 0))
            (overflowed (and i32 same_sign flipped))
            (limit (select i32 (icmp_eq i32 (and i32 (lshr i32 rs1 31) 1) 1)
                               0x80000000 0x7fffffff)))
        (select i32 overflowed limit sum))""",
    # The staircase it replaces.
    "satnest": """(let ((sum (add i32 rs1 rs2)))
        (let ((same_sign (icmp_eq i32 (and i32 (xor i32 rs1 rs2) 0x80000000) 0)))
          (let ((flipped (icmp_ne i32 (and i32 (xor i32 rs1 sum) 0x80000000) 0)))
            (let ((overflowed (and i32 same_sign flipped)))
              (let ((limit (select i32 (icmp_eq i32 (and i32 (lshr i32 rs1 31) 1) 1)
                                       0x80000000 0x7fffffff)))
                (select i32 overflowed limit sum))))))""",
}

#: (flat, unambiguous staircase) -- these must be proved equal.
EQUAL = [("shflat", "shnest"), ("satflat", "satnest")]
#: (flat, the reading simultaneous bindings would have given) -- must differ,
#: or the shadowing discriminator is not discriminating.
DIFFER = [("shflat", "shpar")]


def corpus() -> str:
    body = []
    for index, (name, formal) in enumerate(VARIANTS.items()):
        body.append(f"""  (definstruction {name}
    (mnemonic {name.upper()}) (category custom) (format R)
    (opcode 11) (func3 {index}) (func7 1)
    (operands (rd reg i32 out) (rs1 reg i32 in) (rs2 reg i32 in))
    (asm "{name} $rd, $rs1, $rs2")
    (semantics "sequential-binding probe")
    (formal {formal})
    (latency 1) (throughput 1.0) (area-estimate-um2 1.0)
    (power-estimate-mw 1.0) (expected-speedup 1.0) (rationale "gate probe"))""")
    return ("(axis-module sequential_let_probe\n"
            '  (version "1.0")\n  (target rvmt)\n'
            '  (description "sequential let binding gate")\n'
            + "\n".join(body) + ")\n")


def emit(axis_file: Path, command: str, out: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   check=True, capture_output=True, text=True, cwd=AXIS_ROOT)


def main() -> int:
    try:
        import z3  # noqa: F401
    except ImportError:
        print("  DECLINED no z3 python module on this host; the equality of "
              "two readings of `let` is a proof, and there is no solver to "
              "run it")
        return 0
    import z3

    work = Path(tempfile.mkdtemp(prefix="axis_seqlet_"))
    src = work / "probe.axisl"
    src.write_text(corpus())

    checks = failures = 0

    # ⚠️ The flat variants must genuinely chain, or this whole file is a test
    # of nothing. Assert it against the source text rather than trusting the
    # table above to have stayed the shape it was written in.
    checks += 1
    for flat, _ in EQUAL:
        text = VARIANTS[flat]
        head = text.split("\n")[0]
        bound = head.split("((")[1].split(" ")[0]
        rest = "\n".join(text.split("\n")[1:])
        if bound not in rest:
            print(f"  FAIL `{flat}` never names its first binding `{bound}` "
                  f"again, so it does not test sequential binding at all")
            failures += 1
            break

    check = subprocess.run([*axis_prefix(), "check", str(src)],
                           capture_output=True, text=True, cwd=AXIS_ROOT)
    checks += 1
    if check.returncode != 0:
        print(f"  FAIL the probe does not validate: "
              f"{(check.stderr or check.stdout).strip()[:200]}")
        return report(checks, failures + 1)

    emit(src, "emit-smt2", work / "sem.smt2")
    emit(src, "emit-golden-python", work / "golden_model.py")
    sys.path.insert(0, str(work))
    golden = importlib.import_module("golden_model")

    smt = (work / "sem.smt2").read_text()
    rs1, rs2 = z3.BitVecs("rs1 rs2", 32)

    def fn(name: str):
        solver_src = smt + f"\n(assert (= (_ bv0 32) (axis_instr_{name} rs1 rs2)))\n"
        # Parse the script with the two operands declared, then recover the
        # asserted application as a z3 expression.
        decls = "(declare-fun rs1 () (_ BitVec 32))\n(declare-fun rs2 () (_ BitVec 32))\n"
        parsed = z3.parse_smt2_string(decls + solver_src)
        return parsed[-1].arg(1)

    body = {name: fn(name) for name in VARIANTS}
    chained = {name for pair in EQUAL for name in pair}

    # ⚠️ Vacuity: a variant that ignores an operand, or is constant, would make
    # every equality below true for uninteresting reasons.
    for name, expr in body.items():
        checks += 1
        s = z3.Solver()
        a1, a2, b1, b2 = z3.BitVecs("a1 a2 b1 b2", 32)
        lhs = z3.substitute(expr, (rs1, a1), (rs2, a2))
        rhs = z3.substitute(expr, (rs1, b1), (rs2, b2))
        s.add(lhs != rhs)
        if s.check() != z3.sat:
            print(f"  FAIL `{name}` is a constant function; proving anything "
                  f"about it proves nothing")
            failures += 1
            continue
        # ⚠️ Operand dependence is asked only of the CHAINED variants. The
        # simultaneous reading is expected to drop an operand -- that is the
        # shadowing signature, and demanding otherwise would reject the
        # control for behaving exactly as predicted.
        if name not in chained:
            continue
        for operand, other in ((a1, a2), (a2, a1)):
            s = z3.Solver()
            free = b1 if operand is a1 else b2
            pair = ((rs1, a1), (rs2, a2))
            alt = ((rs1, free), (rs2, a2)) if operand is a1 else ((rs1, a1), (rs2, free))
            s.add(z3.substitute(expr, *pair) != z3.substitute(expr, *alt))
            if s.check() != z3.sat:
                print(f"  FAIL `{name}` does not depend on one of its "
                      f"operands, so a chain of steps is not being exercised")
                failures += 1
                break

    # THE PROOF: flat and staircase agree on every input.
    for flat, nest in EQUAL:
        checks += 1
        s = z3.Solver()
        s.add(body[flat] != body[nest])
        verdict = s.check()
        if verdict == z3.sat:
            m = s.model()
            print(f"  FAIL `{flat}` and `{nest}` compute different functions; "
                  f"a flat block does not mean what its staircase means "
                  f"(rs1={m.eval(rs1)}, rs2={m.eval(rs2)})")
            failures += 1
        elif verdict != z3.unsat:
            print(f"  FAIL z3 could not decide `{flat}` == `{nest}`: {verdict}")
            failures += 1

    # THE DISCRIMINATOR: the simultaneous reading is a different function, so
    # the proof above had something to prove.
    for flat, par in DIFFER:
        checks += 1
        s = z3.Solver()
        s.add(body[flat] != body[par])
        if s.check() != z3.sat:
            print(f"  FAIL `{flat}` and `{par}` are the same function, so "
                  f"shadowing does not distinguish sequential bindings from "
                  f"simultaneous ones and this gate measures nothing")
            failures += 1

    # A SECOND EVALUATOR. The proof is about the SMT backend; the golden model
    # is emitted independently, so agreement makes it a claim about `let`.
    sample = [(0, 0), (1, 2), (0x7fffffff, 1), (0x80000000, 0xffffffff),
              (0xdeadbeef, 0x12345678), (3, 0x7ffffffd), (0xffffffff, 1),
              (0x40000000, 0x40000000), (0x80000000, 0x80000000), (5, 7)]
    def evaluate(name, a, b):
        # ⚠️ An evaluator that RAISES is a failure, not a crash. A model that
        # cannot resolve a name a later binding introduced is precisely the
        # regression this file exists to report, and a traceback would lose
        # every check after it.
        try:
            return getattr(golden, f"eval_{name}")(a, b)
        except Exception as error:
            return error

    for flat, nest in EQUAL:
        for a, b in sample:
            checks += 1
            lhs = evaluate(flat, a, b)
            rhs = evaluate(nest, a, b)
            if isinstance(lhs, Exception) or isinstance(rhs, Exception):
                bad = lhs if isinstance(lhs, Exception) else rhs
                which = flat if isinstance(lhs, Exception) else nest
                print(f"  FAIL golden model cannot evaluate `{which}` at "
                      f"({a:#x}, {b:#x}): {type(bad).__name__}: {bad}")
                failures += 1
                continue
            if lhs != rhs:
                print(f"  FAIL golden model: {flat}({a:#x}, {b:#x})={lhs:#x} "
                      f"but {nest}(...)={rhs:#x}")
                failures += 1
    # And the golden model must see the shadowing the way z3 does.
    for flat, par in DIFFER:
        checks += 1
        if all(evaluate(flat, a, b) == evaluate(par, a, b)
               for a, b in sample):
            print(f"  FAIL golden model cannot tell `{flat}` from `{par}` on "
                  f"any sampled input; the second evaluator is not confirming "
                  f"the proof")
            failures += 1

    return report(checks, failures)


def report(checks: int, failures: int) -> int:
    verdict = "PASS" if failures == 0 else "FAIL"
    print(f"a later binding sees the earlier ones: {verdict} "
          f"({checks} checks, {failures} failure(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
