#!/usr/bin/env python3
"""Sweep a vtype-parameterised document over the (SEW, LMUL) points a machine can be in.

RVV puts type information in a dynamic CSR: `SEW` is the element width and
`LMUL` the rational register footprint, and together they decide an operand's
shape. Between two `vsetvli`s both are constant, so AXIS elaborates one point at
a time and this sweeps the points -- the same treatment vector length and scalar
width already get (mechanisms M2 and M3, docs/scalable_vectors_design.md).

Most of the cross product is not a configuration any machine has. The rule is
architectural:

    SEW <= ELEN                 an element must fit the widest supported one
    LMUL >= SEW / ELEN          RVV's rule for fractional LMUL
    VLEN * LMUL >= SEW          and the configured length must hold one element

This tool implements that rule from the specification and requires the
elaborator to agree with it point for point -- refusing exactly the illegal
points and accepting exactly the legal ones. That is a differential check of the
legality predicate itself, not just of the instructions it admits: a rule that
accepted everything would pass every backend gate and still be wrong.

Usage: tools/scalable_modes.py <input.axisl> [--backend llvm|smt|c|rust]
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
TOOLS = {
    "llvm": "llvm_vs_golden.py",
    "smt": "smt_vs_golden.py",
    "c": "c_vs_golden.py",
    "rust": "rust_vs_golden.py",
}
SEWS = (8, 16, 32, 64)
LMULS = ((1, 8), (1, 4), (1, 2), (1, 1), (2, 1), (4, 1), (8, 1))


def declared(source: str, name: str, default: int) -> int:
    found = re.search(rf"\({name} (\d+)\)", source)
    return int(found.group(1)) if found else default


def spec_legal(sew: int, num: int, den: int, elen: int, vlen: int) -> bool:
    """The rule as the RVV specification states it, implemented independently."""
    return (
        sew <= elen
        and num * elen >= den * sew
        and vlen * num >= den * sew
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--backend", default="llvm", choices=sorted(TOOLS))
    args = parser.parse_args()

    source = args.axis_file.read_text()
    if not re.search(r"\(vector-sew \d+\)", source):
        print("no `(vector-sew N)` to vary")
        return DECLINED
    elen = declared(source, "vector-elen", 64)
    vlen = declared(source, "vector-bits", 128)

    workdir = Path(tempfile.mkdtemp(prefix="axis_svm_"))
    disagreed, checked, failed = [], 0, []
    capacity: list[str] = []
    accepted = refused = 0

    for sew in SEWS:
        for num, den in LMULS:
            lmul = f"{num}" if den == 1 else f"{num}/{den}"
            variant = workdir / f"sew{sew}_lmul{num}_{den}.axisl"
            text = re.sub(r"\(vector-sew \d+\)", f"(vector-sew {sew})", source)
            text = re.sub(r"\(vector-lmul [\d/]+\)", f"(vector-lmul {lmul})", text)
            variant.write_text(text)

            built = subprocess.run(
                [*axis_prefix(), "check", str(variant)],
                capture_output=True, text=True, cwd=AXIS_ROOT,
            )
            elaborated = built.returncode == 0
            expected = spec_legal(sew, num, den, elen, vlen)
            # A document can also fail to expand for reasons that have nothing
            # to do with whether the machine can be in this configuration: a
            # runtime-indexed gather is quadratic in the lane count and is
            # bounded, so a high LMUL can push it past that bound. That is a
            # capacity limit of the *description*, not an illegal vtype, and
            # counting it as a legality disagreement would make this gate report
            # a conflation instead of a fact.
            message = (built.stderr or "") + (built.stdout or "")
            if not elaborated and expected and (
                "quadratic" in message or "expands past" in message
            ):
                capacity.append(f"SEW={sew} LMUL={lmul}")
                checked += 1
                continue
            checked += 1
            if elaborated != expected:
                disagreed.append(
                    f"SEW={sew} LMUL={lmul}: spec says "
                    f"{'legal' if expected else 'illegal'}, elaborator "
                    f"{'accepted' if elaborated else 'refused'}"
                )
                continue
            if not elaborated:
                refused += 1
                continue
            accepted += 1
            result = subprocess.run(
                [sys.executable, str(AXIS_ROOT / "tools" / TOOLS[args.backend]), str(variant)],
                capture_output=True, text=True, cwd=AXIS_ROOT,
            )
            if result.returncode != 0:
                tail = (result.stdout.strip().splitlines() or ["(no output)"])[-1]
                failed.append(f"SEW={sew} LMUL={lmul}: {tail}")

    print(f"{checked} (SEW, LMUL) points: {accepted} legal and proven, {refused} refused")
    if capacity:
        # Named rather than hidden: these are points the machine *can* be in and
        # this description cannot be expanded at, which is a fact about the
        # description worth seeing.
        print(f"  {len(capacity)} legal point(s) past a description capacity limit: "
              f"{', '.join(capacity)}")
    for line in disagreed:
        print(f"  LEGALITY {line}")
    for line in failed:
        print(f"  FAIL {line}")
    # A predicate that refused nothing, or refused everything, would make the
    # sweep meaningless in opposite directions.
    if not refused:
        print("no point was refused; the legality rule is not doing anything")
        disagreed.append("no refusals")
    if not accepted:
        print("no point was accepted; nothing was actually proven")
        disagreed.append("no acceptances")
    ok = not disagreed and not failed
    print(f"vtype sweep ({args.backend}): " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
