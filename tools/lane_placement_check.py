#!/usr/bin/env python3
"""Check where lane operands say their elements live, as a property.

Stage S2 of docs/scalable_execution.md. Instantiation stamps each lane operand
with a placement -- how many 64-bit slots its register spans, which bits inside
it the element occupies -- and every executor reads those numbers rather than
recomputing them. A reference that recomputed the same arithmetic would agree
with a wrong stamp as readily as with a right one, so this states what a
placement has to *satisfy* instead:

    tiles       the elements of one instruction cover their registers exactly
                once, in lane order and with no gap and no overlap
    fits        no element reaches past the register it names
    strides     the register spans as few whole slots as hold VL bits, and the
                lanes of one register share that stride
    groups      a lane moves to the next register only when the previous one is
                full -- which is what register grouping is

Together those pin the placement: given VL and the element width, exactly one
assignment satisfies all four. None of them mentions `lane * width`, which is
the expression under test.

Usage: tools/lane_placement_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
SLOT_BITS = 64


def vector_bits(axis_file: Path) -> int:
    """VL, read from the description rather than from the artifact under test."""
    text = axis_file.read_text()
    match = re.search(r"\(vector-bits\s+(\d+)\)", text)
    if match is None:
        raise SystemExit(f"{axis_file.name}: no (vector-bits ...) to check against")
    return int(match.group(1))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    vl = vector_bits(args.axis_file)
    result = subprocess.run(
        [*axis_prefix(), "emit-lift-json", str(args.axis_file)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT,
    )
    entries = json.loads(result.stdout)["instructions"]

    # The element map: for each element width, where each lane sits. Built
    # across the whole corpus rather than per instruction -- an instruction
    # need not read every element (`LASTB` reads one, a gather reads them out
    # of order), so tiling is a property of the map, not of any one operand
    # list.
    seen: dict[int, dict[int, tuple[int, int]]] = collections.defaultdict(dict)
    conflicts = []
    for entry in entries:
        if not entry.get("scalable_origin"):
            continue
        for operand in entry["operands"]:
            placement = operand.get("placement")
            if placement is None:
                continue
            width = placement["width"]
            lane = operand["packing"]["lane"]
            where = (operand["packing"]["register"], placement["offset"])
            if seen[width].setdefault(lane, where) != where:
                conflicts.append((entry["mnemonic"], operand["name"], width, lane,
                                  seen[width][lane], where, placement["stride"]))

    strides = {(placement["width"], placement["stride"])
               for entry in entries if entry.get("scalable_origin")
               for operand in entry["operands"]
               if (placement := operand.get("placement")) is not None}

    if not seen:
        print("no lane operand carries a placement: nothing to check -> FAIL")
        return DECLINED

    failures = 0

    def fail(message: str) -> None:
        nonlocal failures
        failures += 1
        if failures <= 8:
            print(f"FAIL {message}")

    # consistent: one lane of one width is one place, whatever names it.
    for mnemonic, name, width, lane, first, second, _ in conflicts:
        fail(f"{mnemonic}.{name}: lane {lane} of a {width}-bit element is at "
             f"{first} here and {second} elsewhere")

    # strides: as few whole slots as hold VL bits, and the same for every width.
    want = -(-vl // SLOT_BITS)
    for width, stride in sorted(strides):
        if stride != want:
            fail(f"a {width}-bit shape strides {stride} slots for a {vl}-bit "
                 f"register, expected {want}")

    per_register = {}
    grouped = 0
    for width, lanes in sorted(seen.items()):
        capacity = vl // width if width else 0
        if capacity == 0:
            fail(f"a {width}-bit element does not fit a {vl}-bit register")
            continue
        per_register[width] = capacity
        # grid: an element starts at a multiple of its own size, and fits.
        for lane, (register, offset) in sorted(lanes.items()):
            if width and offset % width:
                fail(f"lane {lane}: a {width}-bit element at bit {offset} is "
                     f"not aligned to its own size")
            if offset + width > vl:
                fail(f"lane {lane}: a {width}-bit element at bit {offset} runs "
                     f"past {vl} bits")
        # injective: two lanes are never the same element.
        places = collections.Counter(lanes.values())
        for where, count in places.items():
            if count > 1:
                fail(f"{count} lanes of a {width}-bit shape share element "
                     f"{where}")
        # tiles: the lanes present in one register cover it without gap or
        # overlap, once every lane of that register has appeared somewhere.
        by_register = collections.defaultdict(dict)
        for lane, (register, offset) in lanes.items():
            by_register[register][lane] = offset
        if len(by_register) > 1:
            grouped += 1
        for register, offsets in sorted(by_register.items()):
            if len(offsets) != capacity:
                continue                     # partial coverage, reported below
            covered = sorted(offsets.values())
            if covered != [index * width for index in range(capacity)]:
                fail(f"a {width}-bit register {register} is covered by "
                     f"{covered[:4]}..., which is not a tiling")
        # order: lane numbering runs with element position.
        ordered = [offsets for _, offsets in sorted(lanes.items())]
        for register in sorted(by_register):
            lanes_here = sorted(by_register[register])
            positions = [by_register[register][lane] for lane in lanes_here]
            if positions != sorted(positions):
                fail(f"a {width}-bit register {register} numbers its lanes "
                     f"against element order: {positions[:6]}")
        # groups: a lane is in a later register only once the earlier ones are
        # full, which is what register grouping means.
        for lane, (register, _offset) in sorted(lanes.items()):
            if register != lane // capacity:
                fail(f"lane {lane} of a {width}-bit shape is in register "
                     f"{register}; {capacity} elements per register puts it in "
                     f"{lane // capacity}")
                break
        _ = ordered

    widths = ", ".join(f"{width}b x{count}" for width, count in sorted(per_register.items()))
    print(f"{sum(len(lanes) for lanes in seen.values())} lane placements over "
          f"{len(seen)} element widths, {failures} failures")
    print(f"  VL {vl}, {widths}; {grouped} width(s) span more than one register")
    ok = failures == 0
    # A corpus with one element width and one register would satisfy all of
    # this without the placement ever having to be interesting.
    if len(seen) < 2:
        print("only one element width: the placement is barely constrained")
        ok = False
    print("lane placement == architecture: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
