#!/usr/bin/env python3
"""Check where each lane element claims to sit, against where it should.

Lane-indexed instantiation names elements, not registers, and for most of this
design that is the point -- nothing downstream ever sees a vector, which is what
kept four predicted costs from materialising. The price was that the
element-to-register packing was not expressed anywhere, so `LMUL > 1` register
grouping had nothing to say about *which* registers a group covers.

It is now published per operand: `packing.register` is how many registers past
the encoded one the element sits, and `packing.element` is its index within that
register. Both follow from the architecture:

    per_register = VLEN / element_width
    register     = lane / per_register
    element      = lane % per_register

That formula is implemented here, independently of the elaborator, and every
published pair must match it. The check is only meaningful where grouping
actually happens, so the corpus is also instantiated at a higher LMUL and an
operand landing past the first register is required.

Usage: tools/lane_packing_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def lift(path: Path) -> dict:
    return json.loads(subprocess.run(
        [*axis_prefix(), "emit-lift-json", str(path)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT,
    ).stdout)


def check(document: dict, vlen: int, label: str) -> tuple[int, int, int]:
    checks = failures = grouped = 0
    for instruction in document["instructions"]:
        if instruction.get("scalable_lane") is None:
            continue
        for operand in instruction["operands"]:
            packing = operand.get("packing")
            if packing is None:
                continue
            # The operand's own lane, not the instruction's: a reduction is
            # one instruction whose operands span every lane.
            lane = packing["lane"]
            width = operand["width"]
            if width == 0 or vlen < width:
                continue
            per_register = vlen // width
            want_register = lane // per_register
            want_element = lane % per_register
            checks += 1
            if packing["register"] > 0:
                grouped += 1
            if (packing["register"], packing["element"]) != (want_register, want_element):
                failures += 1
                if failures <= 8:
                    print(
                        f"FAIL {label} {instruction['mnemonic']} {operand['name']}: "
                        f"claims register+{packing['register']} element "
                        f"{packing['element']}, want register+{want_register} "
                        f"element {want_element}"
                    )
    return checks, failures, grouped


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    found = re.search(r"\(vector-bits (\d+)\)", source)
    if not found:
        print("SKIP: no `(vector-bits N)`")
        return 0
    vlen = int(found.group(1))

    checks, failures, grouped = check(lift(args.axis_file), vlen, "as written")

    # Grouping only shows up above LMUL 1, and a corpus written at LMUL 1 would
    # report every element in register 0 -- true, and no test of the rule.
    #
    # A document with no LMUL at all is a different case, not a weaker one. An
    # SVE Z register holds every element of its operand, so nothing ever leaves
    # the first register and there is no grouping to test. Demanding it there
    # would be demanding the architecture be something else.
    groups = bool(re.search(r"\(vector-lmul [\d/]+\)", source))
    if groups:
        workdir = Path(tempfile.mkdtemp(prefix="axis_pack_"))
        variant = workdir / "lmul4.axisl"
        variant.write_text(re.sub(r"\(vector-lmul [\d/]+\)", "(vector-lmul 4)", source))
        more, bad, spread = check(lift(variant), vlen, "at LMUL=4")
        checks += more
        failures += bad
        grouped += spread

    if not checks:
        print("SKIP: no lane operands publish a packing")
        return 0
    print(f"{checks} packing positions checked, {failures} failures")
    print(f"  {grouped} landed past the first register")
    if groups and not grouped:
        print("no operand ever left the first register, so grouping was not tested")
        failures += 1
    elif not groups:
        print("  (no LMUL declared, so there is no register grouping to reach)")
    print("lane packing == architecture: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
