#!/usr/bin/env python3
"""A lane body reads the lanes it names. Gate.

A vector operator used to have to be ONE ATOM from a closed list -- `add`,
`min`, `icmp_ult`. That list is not a description of what lanes can do, it is
a description of what had somewhere to be written down. A saturating add, a
lane-wise shift by a signed amount, anything built of several steps, was not
expressible: not because lanes could not carry it, but because a lane operator
had no body. `vmap` gives it one:

    (vmap v2i16 ((a rs1) (b rs2))
      (let ((sum (add i16 a b)) ...)
        (select i16 overflowed limit sum)))

Which moves the risk. The closed list was safe BECAUSE it was closed: every
operator on it was known to be lane-local, and the expansion masked its
operands and its result. An arbitrary body is not known to be anything. The
two properties that used to hold by construction now have to be proved:

  * **lane-local** -- the high lane of the result does not depend on the low
    lane of any input. Proved over all inputs, not sampled, because a leak
    that needs one specific bit pattern is exactly the leak a sample misses;
  * **contained** -- a body that computes WIDER than its lane has its result
    confined anyway. The probe for this multiplies at `i32` inside an `i16`
    lane, and the gate separately proves that body really does exceed the lane
    for some input. A containment check over a body that never overflows is a
    containment check over nothing.

A cross-lane body -- `zip1`, `uzp1`, a pairwise add -- cannot be lane-local,
because crossing lanes is what it is for. The property that replaces
lane-locality there is SUPPORT: which input lanes an output lane actually
reads, computed by perturbing one input lane at a time and asking whether any
output moved. That is the emitted function's real dependence rather than a
reading of the formula, and it catches the failure a shuffle is most likely to
have -- an output lane wired to nothing, which looks like a correct answer for
the other three lanes.

Two more, because they are claims the implementation makes in prose:

  * **`vmap` agrees with the closed list it generalises.** The lane-parallel
    and lane-compare expansions stay in place; if `vmap` computed something
    else, one of the two is wrong and the corpus would quietly hold both;
  * **lane bindings are hygienic.** They are emitted as a `let` around the
    body rather than substituted into it, precisely so a body may rebind a
    lane name. A body whose own binding shadows `a` must see ITS `a`. This is
    what substitution would have got wrong, so it is measured rather than
    asserted in a comment.

Usage: tools/lane_body_check.py
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

LANES, ELEM = 2, 16
TOTAL = LANES * ELEM

VARIANTS = {
    # The closed-vocabulary expansion, and the same thing said with a body.
    "vadd": "(add v2i16 rs1 rs2)",
    "mapadd": "(vmap v2i16 ((a rs1) (b rs2)) (add i16 a b))",
    # A compare widens 0-or-1 to the whole lane. The closed form does that
    # itself; a body has to say so, and the two must still agree.
    "vcmp": "(icmp_ult v2i16 rs1 rs2)",
    "mapcmp": "(vmap v2i16 ((a rs1) (b rs2)) (mul i16 (icmp_ult i16 a b) 0xffff))",
    # ⚠️ Computes at i32 inside an i16 lane, so only the expansion's own mask
    # keeps it off the neighbouring lane.
    "wide": "(vmap v2i16 ((a rs1) (b rs2)) (mul i32 a b))",
    # ⚠️ A wide RIGHT shift, which is what the INPUT mask is for. `wide`
    # above does not catch a missing input mask: the low bits of a product do
    # not depend on the high bits of its factors, so an unmasked lane
    # multiplies the wrong numbers and still lands on the right answer. A
    # right shift at i32 pulls the neighbouring lane's bits straight down into
    # this one, and nothing downstream can put them back.
    "wideshr": "(vmap v2i16 ((a rs1) (b rs2)) (lshr i32 a 4))",
    # The same exposure for a comparison: unmasked, lane 0 would compare whole
    # registers rather than lanes, and the answer is a full-lane mask either
    # way -- so only the operands can reveal it.
    "widecmp": "(vmap v2i16 ((a rs1) (b rs2)) (mul i16 (icmp_ult i32 a b) 0xffff))",
    # Hygiene: the body rebinds `a`. Its own binding must win.
    "shadow": """(vmap v2i16 ((a rs1) (b rs2))
        (let ((a (add i16 a b)))
          (mul i16 a 3)))""",
    # What the shadowing body means, written without shadowing.
    "shadowref": "(vmap v2i16 ((a rs1) (b rs2)) (mul i16 (add i16 a b) 3))",
    # ⚠️ CROSS-LANE. These are NOT lane-local, by construction -- that is the
    # point of them -- so they are held to a different property below.
    "zip1": """(vmap v4i8 ((x (lane rs1 (/ lane-index 2)))
                (y (lane rs2 (/ lane-index 2))))
        (select i8 (icmp_eq i8 (and i8 lane-index 1) 0) x y))""",
    "uzp1": """(vmap v4i8 ((x (lane rs1 (% (* lane-index 2) 4)))
                (y (lane rs2 (% (* lane-index 2) 4))))
        (select i8 (icmp_ult i8 lane-index 2) x y))""",
    "addp": """(vmap v4i8 ((lo (lane rs1 (* (% lane-index 2) 2)))
                (hi (lane rs1 (+ (* (% lane-index 2) 2) 1)))
                (qlo (lane rs2 (* (% lane-index 2) 2)))
                (qhi (lane rs2 (+ (* (% lane-index 2) 2) 1))))
        (select i8 (icmp_ult i8 lane-index 2) (add i8 lo hi) (add i8 qlo qhi)))""",
    # A real saturating lane operator -- the thing that was unwritable.
    "sqadd": """(vmap v2i16 ((a rs1) (b rs2))
        (let ((sum (add i16 a b))
              (same_sign (icmp_eq i16 (and i16 (xor i16 a b) 0x8000) 0))
              (flipped (icmp_ne i16 (and i16 (xor i16 a sum) 0x8000) 0))
              (overflowed (and i16 same_sign flipped))
              (limit (select i16 (icmp_eq i16 (and i16 (lshr i16 a 15) 1) 1)
                                 0x8000 0x7fff)))
          (select i16 overflowed limit sum)))""",
}

#: Pairs that must denote the same function over every input.
EQUAL = [("mapadd", "vadd"), ("mapcmp", "vcmp"), ("shadow", "shadowref")]
#: Every lane-local `vmap` variant. Cross-lane bodies are excluded here and
#: held to the support property instead -- asking a shuffle to be lane-local
#: would be asking it not to shuffle.
MAPPED = ["mapadd", "mapcmp", "wide", "wideshr", "widecmp", "shadow",
          "shadowref", "sqadd"]
#: Cross-lane variants and the EXACT set of input lanes each output lane must
#: read, straight from the ARM definitions.
#:
#: ⚠️ Exact, and not a bound on how many. A bound was the first version of
#: this check and it missed both mutations written against it: ignoring the
#: requested lane entirely, and reading one lane along. Both leave every output
#: lane reading exactly one lane of one source, which is all a count can see. A
#: permutation is WHICH lane, so that is what is written down.
CROSS = {
    # out[i] = i even ? rs1[i/2] : rs2[i/2]
    "zip1": {0: {("rs1", 0)}, 1: {("rs2", 0)},
             2: {("rs1", 1)}, 3: {("rs2", 1)}},
    # out[i] = i < 2 ? rs1[2i] : rs2[2i - 4]
    "uzp1": {0: {("rs1", 0)}, 1: {("rs1", 2)},
             2: {("rs2", 0)}, 3: {("rs2", 2)}},
    # out[i] sums an adjacent pair, the first two from rs1 and the rest rs2
    "addp": {0: {("rs1", 0), ("rs1", 1)}, 1: {("rs1", 2), ("rs1", 3)},
             2: {("rs2", 0), ("rs2", 1)}, 3: {("rs2", 2), ("rs2", 3)}},
}
#: Cross-lane probes are 4x8, not 2x16.
CROSS_LANES, CROSS_ELEM = 4, 8


def corpus() -> str:
    body = []
    for index, (name, formal) in enumerate(VARIANTS.items()):
        body.append(f"""  (definstruction {name}
    (mnemonic {name.upper()}) (category custom) (format R)
    (opcode 11) (func3 {index % 8}) (func7 {1 + index // 8})
    (operands (rd reg i32 out) (rs1 reg i32 in) (rs2 reg i32 in))
    (asm "{name} $rd, $rs1, $rs2")
    (semantics "lane body probe")
    (formal {formal})
    (latency 1) (throughput 1.0) (area-estimate-um2 1.0)
    (power-estimate-mw 1.0) (expected-speedup 1.0) (rationale "gate probe"))""")
    return ("(axis-module lane_body_probe\n"
            '  (version "1.0")\n  (target rvmt)\n'
            '  (description "lane body gate")\n' + "\n".join(body) + ")\n")


def main() -> int:
    try:
        import z3
    except ImportError:
        print("  DECLINED no z3 python module on this host; lane-locality is a "
              "statement about every input and there is no solver to prove it")
        return 0

    work = Path(tempfile.mkdtemp(prefix="axis_lanebody_"))
    src = work / "probe.axisl"
    src.write_text(corpus())

    checks = failures = 0
    check = subprocess.run([*axis_prefix(), "check", str(src)],
                           capture_output=True, text=True, cwd=AXIS_ROOT)
    checks += 1
    if check.returncode != 0:
        message = "\n".join(
            line for line in (check.stdout + check.stderr).splitlines()
            if "error" in line.lower() and not line.startswith(" "))
        print(f"  FAIL the probe does not validate: "
              f"{(message or check.stdout + check.stderr).strip()[:300]}")
        return report(checks, failures + 1)

    for command, out in (("emit-smt2", "sem.smt2"),
                         ("emit-golden-python", "golden_model.py")):
        subprocess.run([*axis_prefix(), command, str(src), "-o", str(work / out)],
                       check=True, capture_output=True, text=True, cwd=AXIS_ROOT)
    sys.path.insert(0, str(work))
    golden = importlib.import_module("golden_model")
    smt = (work / "sem.smt2").read_text()
    decls = ("(declare-fun rs1 () (_ BitVec 32))\n"
             "(declare-fun rs2 () (_ BitVec 32))\n")
    rs1, rs2 = z3.BitVecs("rs1 rs2", TOTAL)

    def body_of(name: str):
        script = decls + smt + f"\n(assert (= (_ bv0 32) (axis_instr_{name} rs1 rs2)))\n"
        return z3.parse_smt2_string(script)[-1].arg(1)

    body = {name: body_of(name) for name in VARIANTS}

    def lane(expr, index: int):
        return z3.Extract(index * ELEM + ELEM - 1, index * ELEM, expr)

    # THE GENERALISATION IS FAITHFUL: a body says what the closed list said.
    for mapped, closed in EQUAL:
        checks += 1
        s = z3.Solver()
        s.add(body[mapped] != body[closed])
        verdict = s.check()
        if verdict == z3.sat:
            m = s.model()
            print(f"  FAIL `{mapped}` and `{closed}` compute different "
                  f"functions (rs1={m.eval(rs1)}, rs2={m.eval(rs2)})")
            failures += 1
        elif verdict != z3.unsat:
            print(f"  FAIL z3 could not decide `{mapped}` == `{closed}`: {verdict}")
            failures += 1

    # ⚠️ Vacuity for the containment probe: `wide` must actually exceed its
    # lane for some input, or proving it is contained proves nothing.
    checks += 1
    a, b = z3.BitVecs("a b", ELEM)
    s = z3.Solver()
    s.add(z3.ZeroExt(ELEM, a) * z3.ZeroExt(ELEM, b) > z3.BitVecVal((1 << ELEM) - 1, TOTAL))
    if s.check() != z3.sat:
        print("  FAIL the containment probe cannot overflow its lane, so "
              "containment is being proved over a body that never needed it")
        failures += 1

    # LANE-LOCAL: perturbing one lane's inputs leaves the other lane's output
    # alone. Proved over all inputs.
    other1, other2 = z3.BitVecs("other1 other2", TOTAL)
    for name in MAPPED:
        expr = body[name]
        for observed in range(LANES):
            checks += 1
            # Replace every lane EXCEPT `observed` with unrelated bits.
            keep = z3.BitVecVal(((1 << ELEM) - 1) << (observed * ELEM), TOTAL)
            mixed1 = (rs1 & keep) | (other1 & ~keep)
            mixed2 = (rs2 & keep) | (other2 & ~keep)
            perturbed = z3.substitute(expr, (rs1, mixed1), (rs2, mixed2))
            s = z3.Solver()
            s.add(lane(expr, observed) != lane(perturbed, observed))
            verdict = s.check()
            if verdict == z3.sat:
                m = s.model()
                print(f"  FAIL `{name}` lane {observed} changes when another "
                      f"lane's input changes: rs1={m.eval(rs1)}, "
                      f"rs2={m.eval(rs2)}, other=({m.eval(other1)}, "
                      f"{m.eval(other2)})")
                failures += 1
            elif verdict != z3.unsat:
                print(f"  FAIL z3 could not decide lane-locality of `{name}` "
                      f"lane {observed}: {verdict}")
                failures += 1

    # ⚠️ Vacuity for lane-locality: a constant function is trivially local.
    for name in MAPPED:
        checks += 1
        s = z3.Solver()
        p, q, r, t = z3.BitVecs("p q r t", TOTAL)
        s.add(z3.substitute(body[name], (rs1, p), (rs2, q))
              != z3.substitute(body[name], (rs1, r), (rs2, t)))
        if s.check() != z3.sat:
            print(f"  FAIL `{name}` is constant, so lane-locality holds for "
                  f"reasons that have nothing to do with lanes")
            failures += 1

    # A PERMUTATION MOVES LANES AND INVENTS NONE. A cross-lane body cannot be
    # lane-local, so the property that replaces it is SUPPORT: which input
    # lanes an output lane actually reads. Computed by perturbing one input
    # lane at a time and asking z3 whether any output changed -- so it is the
    # real dependence of the emitted function, not a reading of the formula.
    for name, expected in CROSS.items():
        expr = body[name]
        support: dict[int, set[tuple[str, int]]] = {}
        for observed in range(CROSS_LANES):
            found: set[tuple[str, int]] = set()
            for source, register in (("rs1", rs1), ("rs2", rs2)):
                for candidate in range(CROSS_LANES):
                    bits = ((1 << CROSS_ELEM) - 1) << (candidate * CROSS_ELEM)
                    fresh = z3.BitVec(f"fresh_{name}_{source}_{candidate}", TOTAL)
                    changed = (register & ~z3.BitVecVal(bits, TOTAL)) | (fresh & bits)
                    perturbed = z3.substitute(expr, (register, changed))
                    probe = z3.Solver()
                    probe.add(
                        z3.Extract(
                            observed * CROSS_ELEM + CROSS_ELEM - 1,
                            observed * CROSS_ELEM,
                            expr,
                        )
                        != z3.Extract(
                            observed * CROSS_ELEM + CROSS_ELEM - 1,
                            observed * CROSS_ELEM,
                            perturbed,
                        )
                    )
                    if probe.check() == z3.sat:
                        found.add((source, candidate))
            support[observed] = found
        for observed, found in support.items():
            checks += 1
            # An output lane that reads NOTHING is a lane the expansion
            # dropped -- the failure a shuffle is most likely to have, and the
            # one that looks like a correct answer for three lanes out of four.
            if found != expected[observed]:
                missing = sorted(expected[observed] - found)
                extra = sorted(found - expected[observed])
                detail = []
                if missing:
                    detail.append(f"does not read {missing}")
                if extra:
                    detail.append(f"also reads {extra}")
                print(f"  FAIL `{name}` output lane {observed} "
                      f"{' and '.join(detail) or 'reads nothing'}")
                failures += 1
        # ⚠️ Vacuity: a "permutation" whose expected map is the identity would
        # be an ordinary lane-local map, and the cross-lane machinery would go
        # untested while this loop reported success.
        checks += 1
        if all(found == {("rs1", observed)} for observed, found in expected.items()):
            print(f"  FAIL `{name}` is declared to read lane i from rs1 for "
                  f"every output lane i, so nothing crosses lanes and this "
                  f"check has nothing to measure")
            failures += 1

    # A SECOND EVALUATOR, independently emitted, over the interesting corners
    # of a saturating add -- the operator the whole mechanism exists for.
    def s16(value: int) -> int:
        value &= 0xffff
        return value - 0x10000 if value & 0x8000 else value

    def reference(x: int, y: int) -> int:
        out = 0
        for index in range(LANES):
            lhs, rhs = s16(x >> (index * ELEM)), s16(y >> (index * ELEM))
            clamped = max(-0x8000, min(0x7fff, lhs + rhs))
            out |= (clamped & 0xffff) << (index * ELEM)
        return out

    saturating = [(0x7fff7fff, 0x00010001), (0x80008000, 0xffffffff),
                  (0x7fff8000, 0x00018000), (0x00000000, 0x00000000),
                  (0x12345678, 0x7fff7fff), (0x80007fff, 0x80007fff)]
    for x, y in saturating:
        checks += 1
        got = golden.eval_sqadd(x, y)
        want = reference(x, y)
        if got != want:
            print(f"  FAIL golden model sqadd({x:#010x}, {y:#010x}) = "
                  f"{got:#010x}, reference says {want:#010x}")
            failures += 1
    # ⚠️ And the reference must disagree with a NON-saturating add somewhere,
    # or it is not testing saturation at all.
    checks += 1
    if all(reference(x, y) == ((x + y) & 0xffff) | (((x >> 16) + (y >> 16)) & 0xffff) << 16
           for x, y in saturating):
        print("  FAIL no probed input actually saturates, so the reference "
              "agreeing proves only that addition works")
        failures += 1

    return report(checks, failures)


def report(checks: int, failures: int) -> int:
    verdict = "PASS" if failures == 0 else "FAIL"
    print(f"a lane body reads the lanes it names: {verdict} "
          f"({checks} checks, {failures} failure(s))")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
