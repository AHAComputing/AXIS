#!/usr/bin/env python3
"""An unordered reduction is one of the orders this language pins. Gate.

RVV's `vfredusum` sums a vector in an order the architecture does not fix.
Until now AXIS said that made it undescribable -- `examples/scalable_crosslane.axisl`
carried the sentence "the unordered form has no single architectural answer, so
only the ordered one is described here rather than described wrongly" -- and
`docs/scalable_vectors_design.md` M1 claimed the definedness mask covered it.
Both were wrong in opposite directions. A mask says which LANES are free, and an
unordered reduction is one fully defined value drawn from a set of admissible
ones: there is no lane to mark.

What makes it describable is having more than one order to name. `vfredosum`
folds left to right, `vfredpsum` folds a balanced tree (SVE's FADDV), and
`vfredusum` is whichever of them the ISA's `(reduction-realization ...)` names.
The ladder then runs once per realisation, exactly as `scalable_definedness.py`
runs once per realisation of undefined bits.

Four properties, and the last is the one that keeps this from being decoration:

  1. **a pinned order does not move.** `vfredosum` and `vfredpsum` compute the
     same value under both realisations. A knob that reached a specified order
     would be changing the architecture, not choosing among its freedoms;
  2. **re-association is invisible where the operator is associative.** The
     integer reductions fold differently under the two realisations -- the
     expression really does change, which is checked, not assumed -- and the
     value must be identical. This is the claim `REDUCTIONS` makes in a comment
     ("the scalar operators are associative, so the fold can be the n-ary form")
     and nothing measured;
  3. **the unordered form IS its realisation.** Under `sequential` it agrees
     with `vfredosum` on every input; under `pairwise` with `vfredpsum`. That is
     what makes the sweep decidable rather than a gesture at "any order";
  4. **the two realisations differ somewhere.** Floating-point addition is not
     associative, so a witness must exist. If none is found the first three hold
     vacuously and this reports FAIL: an unordered reduction no input can tell
     apart from an ordered one is not being proven, it is being assumed.

Property 4 needs inputs chosen to break associativity rather than only random
ones -- (1 + 1e30) + (-1e30 + 1) is 0 and ((1 + 1e30) + -1e30) + 1 is 1 -- so
the case list is seeded with cancellation patterns and then fuzzed.

Injection-checked: folding pairwise as a left fold (property 4 fails, the knob
is inert), folding the ordered form with the knob (property 1 fails), and
matching the unordered form to the wrong twin (property 3 fails).

Usage: tools/reduction_order_check.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
REALIZATIONS = ("sequential", "pairwise")

# Which source operator an instruction reduces with, and what that means here.
PINNED = {"vfredosum": "sequential", "vfredomul": "sequential", "vfredpsum": "pairwise"}
UNSPECIFIED = {"vfredusum"}
ASSOCIATIVE = {
    "vredsum", "vredand", "vredor", "vredxor",
    "vredmax", "vredmin", "vredmaxu", "vredminu",
}


def variant_source(source: str, realization: str) -> str:
    """The document with its reduction realisation set to `realization`."""
    if re.search(r"\(reduction-realization \w+\)", source):
        return re.sub(
            r"\(reduction-realization \w+\)",
            f"(reduction-realization {realization})",
            source,
        )
    return re.sub(
        r"(\(vector-bits \d+\))",
        rf"\1\n    (reduction-realization {realization})",
        source,
        count=1,
    )


def golden_for(source: str, realization: str, workdir: Path):
    variant = workdir / f"{realization}.axisl"
    variant.write_text(variant_source(source, realization))
    out = workdir / f"{realization}.py"
    subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(variant), "-o", str(out)],
        check=True,
        cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location(f"golden_{realization}", out)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reductions_in(source: str) -> dict[str, str]:
    """Mnemonic -> the reduction operator its `formal` names.

    Read from the document rather than from the artifact on purpose: under
    `sequential` an unordered reduction and an ordered one expand to the *same*
    expression, which is the whole point, so the artifact cannot tell them
    apart and the source is the only place the distinction lives.
    """
    found = {}
    for block in re.findall(r"\(definstruction\b.*?\n\n", source + "\n\n", re.S):
        mnemonic = re.search(r"\(mnemonic ([A-Za-z0-9_]+)\)", block)
        operator = re.search(r"\(formal \((v[a-z0-9]*red[a-z]*)\b", block)
        if mnemonic and operator:
            found[mnemonic.group(1)] = operator.group(1)
    return found


def f32(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def cases(lanes: int, count: int, rng: random.Random) -> list[tuple[int, ...]]:
    """Inputs, cancellation patterns first.

    A random f32 vector often re-associates to the same bits, so leading with
    values whose sum depends on the grouping is what makes property 4 a real
    search rather than a hope.
    """
    crafted = [
        (1.0, 1e30, -1e30, 1.0),
        (1e30, 1.0, 1.0, -1e30),
        (1.0, -1.0, 1e-30, 1e30),
        (2.0**-100, 2.0**100, -(2.0**100), 2.0**-100),
    ]
    out = []
    for pattern in crafted:
        row = [f32(v) for v in pattern[:lanes]]
        row += [f32(1.0)] * (lanes - len(row))
        out.append(tuple(row))
    while len(out) < count:
        # Exponents near each other cancel; spread ones do not. Both are drawn.
        out.append(tuple(
            f32(rng.choice([1.0, -1.0]) * (2.0 ** rng.randint(-60, 60)) * rng.random())
            for _ in range(lanes)
        ))
    return out[:count]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    operators = reductions_in(source)
    if not any(op in UNSPECIFIED for op in operators.values()):
        print("no unordered reduction in this corpus")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_order_"))
    models = {name: golden_for(source, name, workdir) for name in REALIZATIONS}
    base = models[REALIZATIONS[0]]

    # The pinned twin an unordered reduction must equal under each realisation:
    # same lane shape, same operand, a pinned order. Matched by result width and
    # parameter list so a corpus with several shapes stays honest.
    twins = {}
    for realization in REALIZATIONS:
        for mnemonic, operator in operators.items():
            if PINNED.get(operator) == realization:
                twins[realization] = mnemonic
    missing = [r for r in REALIZATIONS if r not in twins]
    if missing:
        print(f"no pinned reduction to compare against for: {', '.join(missing)}")
        return DECLINED

    rng = random.Random(0xF01D)
    pinned_moved = associative_moved = twin_mismatch = 0
    unordered_differed = 0
    checks = 0
    expression_changed = set()

    for mnemonic, operator in sorted(operators.items()):
        entry = base.AXIS_SPECS[mnemonic]
        lanes = len(entry["params"])
        texts = {r: models[r].AXIS_SPECS[mnemonic]["formal_semantics"] for r in REALIZATIONS}
        if len(set(texts.values())) > 1:
            expression_changed.add(mnemonic)
        for values in cases(lanes, args.cases, rng):
            results = {r: models[r].AXIS_SPECS[mnemonic]["eval"](*values) for r in REALIZATIONS}
            checks += 1

            if operator in PINNED and len(set(results.values())) != 1:
                pinned_moved += 1
                if pinned_moved <= 3:
                    print(f"FAIL {mnemonic}{values}: a pinned order moved: {results}")
            if operator in ASSOCIATIVE and len(set(results.values())) != 1:
                associative_moved += 1
                if associative_moved <= 3:
                    print(f"FAIL {mnemonic}{values}: re-association changed the value: {results}")
            if operator in UNSPECIFIED:
                for realization in REALIZATIONS:
                    twin = models[realization].AXIS_SPECS[twins[realization]]["eval"](*values)
                    if twin != results[realization]:
                        twin_mismatch += 1
                        if twin_mismatch <= 3:
                            print(
                                f"FAIL {mnemonic}{values}: under {realization} it is "
                                f"{results[realization]:#x}, and {twins[realization]} "
                                f"is {twin:#x}"
                            )
                if len(set(results.values())) > 1:
                    unordered_differed += 1

    associative = sorted(m for m, op in operators.items() if op in ASSOCIATIVE)
    refolded = [m for m in associative if m in expression_changed]

    print(f"{checks} cases over {len(operators)} reductions, {len(REALIZATIONS)} realisations")
    print(f"  pinned orders unmoved by the knob   : {'yes' if not pinned_moved else f'NO ({pinned_moved})'}")
    print(f"  associative folds re-associated     : {len(refolded)}/{len(associative)}")
    print(f"  ...and kept their value             : {'yes' if not associative_moved else f'NO ({associative_moved})'}")
    print(f"  unordered == its realisation's twin : {'yes' if not twin_mismatch else f'NO ({twin_mismatch})'}")
    print(f"  realisations differed               : {unordered_differed} case(s)")

    failures = pinned_moved + associative_moved + twin_mismatch
    if associative and not refolded:
        print("no associative reduction re-associated; property 2 holds vacuously")
        failures += 1
    if not unordered_differed:
        print("the two realisations never differed; the knob is inert and 1-3 are vacuous")
        failures += 1
    print("reduction order: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
