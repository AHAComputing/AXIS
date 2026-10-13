#!/usr/bin/env python3
"""Check that unspecified lanes are unspecified in the way the architecture says.

RVV's tail-agnostic policy leaves elements past `vl` architecturally
unspecified: an implementation may leave them undisturbed or write all-ones, and
both are correct. A bit-exact ladder cannot compare contents it does not
constrain -- but the *region* that is unconstrained is specified exactly, and
that is what this checks (mechanism M1, docs/scalable_vectors_design.md).

Three properties, run over every realisation of the undefined bits:

  1. the definedness mask is identical under every realisation -- it is the
     architectural part, so nothing about it may depend on the free bits;
  2. defined lanes agree under every realisation -- nothing downstream depends
     on the undefined bits, which is strictly stronger than picking one
     realisation and declaring it the answer; and
  3. some undefined lane actually *differs* between realisations. Without this
     the first two hold vacuously: a knob that changes nothing would prove
     insensitivity to nothing.

Property 3 is why this tool exists rather than a flag on an existing gate.

Usage: tools/scalable_definedness.py <input.axisl> [--cases N]
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
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
REALIZATIONS = ("compute", "ones", "zeros")


def golden_for(source: str, realization: str, workdir: Path, tag: str):
    variant = workdir / f"{tag}.axisl"
    if re.search(r"\(unspecified-realization \w+\)", source):
        text = re.sub(
            r"\(unspecified-realization \w+\)",
            f"(unspecified-realization {realization})",
            source,
        )
    else:
        text = re.sub(
            r"(\(vector-bits \d+\))",
            rf"\1\n    (unspecified-realization {realization})",
            source,
            count=1,
        )
    variant.write_text(text)
    out = workdir / f"{tag}.py"
    subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(variant), "-o", str(out)],
        check=True,
        cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location(f"golden_{tag}", out)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=48)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    workdir = Path(tempfile.mkdtemp(prefix="axis_def_"))
    models = {
        name: golden_for(source, name, workdir, name) for name in REALIZATIONS
    }
    base = models["compute"]

    partial = {
        name: entry
        for name, entry in base.AXIS_SPECS.items()
        if entry.get("defined_by")
    }
    if not partial:
        print("no partly-specified instructions found")
        return DECLINED

    random.seed(0xDEF1)
    mask_mismatch = value_mismatch = 0
    undefined_seen = undefined_differed = 0
    checks = 0

    for name, entry in sorted(partial.items()):
        mask_name = entry["defined_by"]
        # Drive the active length into a range that actually reaches the tail.
        # Which operand that is comes from the artifact, not from its spelling:
        # a gate that never reaches an undefined lane passes vacuously, which is
        # exactly what property 3 below exists to notice.
        defined_operand = entry.get("defined_operand") or ""
        params = entry["params"]
        lanes = sum(
            1 for other in base.AXIS_SPECS.values()
            if other.get("scalable_origin") == entry.get("scalable_origin")
            and other.get("defined_by")
        )
        for _ in range(args.cases):
            values = tuple(
                random.randint(0, max(lanes, 1))
                if param == defined_operand
                else random.getrandbits(width)
                for param, width in params
            )
            masks = {r: models[r].AXIS_SPECS[mask_name]["eval"](*values)
                     for r in REALIZATIONS}
            results = {r: models[r].AXIS_SPECS[name]["eval"](*values)
                       for r in REALIZATIONS}
            checks += 1

            # 1. the mask is architectural, so it cannot vary with the free bits
            if len(set(masks.values())) != 1:
                mask_mismatch += 1
                if mask_mismatch <= 3:
                    print(f"FAIL {name}: mask differs by realisation: {masks}")
                continue

            if masks["compute"]:
                # 2. a defined lane must not depend on how undefined bits are filled
                if len(set(results.values())) != 1:
                    value_mismatch += 1
                    if value_mismatch <= 3:
                        print(f"FAIL {name}{values}: defined lane differs: {results}")
            else:
                # 3. an undefined lane should be free to differ, and must
                #    actually do so somewhere or the knob proves nothing
                undefined_seen += 1
                if len(set(results.values())) > 1:
                    undefined_differed += 1

    print(f"{checks} cases over {len(partial)} partly-specified lanes")
    print(f"  mask stable under every realisation : {'yes' if not mask_mismatch else f'NO ({mask_mismatch})'}")
    print(f"  defined lanes agree everywhere      : {'yes' if not value_mismatch else f'NO ({value_mismatch})'}")
    print(f"  undefined lanes exercised           : {undefined_seen} ({undefined_differed} differed)")

    failures = mask_mismatch + value_mismatch
    if not undefined_seen:
        print("no undefined lane was reached; the check would hold vacuously")
        failures += 1
    elif not undefined_differed:
        print("undefined lanes never differed between realisations; the knob is inert")
        failures += 1
    print("definedness: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
