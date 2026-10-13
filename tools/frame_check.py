#!/usr/bin/env python3
"""A declared frame is one the instruction set can address (stage F1).

`docs/frame_design.md` §1: a consumer of this description already writes the
frame by hand. `pce/hardware/grv/grv_linked_execution.py` checks a prologue
against hand-encoded words -- `addi sp, sp, -16 / sw ra, 12(sp) /
sw s0, 8(sp) / addi s0, sp, 16` -- with `saved_ra_offset` and
`saved_s0_offset` carried as struct fields in a second repository. Those
offsets are a *function* of the save order and the slot size, and F1 moves the
function into the description.

Two questions here, and the second is why the stage exists.

**Is the published slot table the layout?** The manifest publishes computed
offsets rather than a rule, so a consumer reads offsets instead of deriving
them. This re-derives them, the way `mapping_legality_check.py` re-derives the
modulo tables the validator already computed. Slots must also be distinct and
inside the frame: two registers in one slot is a frame that loses one of them.

**Can the machine reach it?** This is the join. AXIS knows the exact immediate
range of every instruction -- `llvm_backend.md` §9's rule that an immediate
carries the range its semantics states -- so the store named to save a
register either reaches the top of the largest declared frame or it does not.
A platform declaring a 4096-byte maximum frame on a machine whose store
reaches 2047 from a base register is stating something its own instruction set
refutes. A compiler meets that as a scratch-register scramble or a miscompile;
a description can meet it as a contradiction.

The range comes from the emitted LLVM target, where §9's rule already writes it
as an `ImmLeaf` predicate on the operand. Reading it there rather than
recomputing it keeps one derivation of "what this immediate may hold" -- and
that one is already gated, by `llvm_patterns_check.py` against the golden model
and by `llvm_target_check.py` against the encode table.

Coverage, per `docs/gate_coverage.md`: a corpus whose ABIs declare no frame
fails as vacuous.

Usage: tools/frame_check.py [input.axisl]
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
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent


def immediate_ranges(target: str) -> dict[str, tuple[int, int]]:
    """Every immediate predicate the target defines, as an inclusive range.

    Only the two shapes a frame offset can be: a signed or unsigned run of low
    bits. A masked predicate (RISC-V's `LUI`) is not a range and is left out,
    so an instruction typed by one is reported as having no stated range rather
    than being given a wrong one.
    """
    ranges: dict[str, tuple[int, int]] = {}
    for name, bits in re.findall(
            r"def (\w+) : Operand<\w+>, ImmLeaf<\w+, \[\{return isInt<(\d+)>", target):
        ranges[name] = (-(1 << (int(bits) - 1)), (1 << (int(bits) - 1)) - 1)
    for name, bits in re.findall(
            r"def (\w+) : Operand<\w+>, ImmLeaf<\w+, \[\{return isUInt<(\d+)>", target):
        ranges[name] = (0, (1 << int(bits)) - 1)
    return ranges


def operand_predicate(target: str, mnemonic: str) -> str | None:
    """The predicate def typing `mnemonic`'s immediate operand, if it has one."""
    match = re.search(rf"^def {mnemonic} : \w+Inst<\(outs[^)]*\), \(ins ([^)]*)\)",
                      target, re.M)
    if match is None:
        return None
    for operand in match.group(1).split(","):
        klass = operand.strip().split(":")[0]
        if klass and not klass.endswith("Regs"):
            return klass
    return None


REGION_ORDER = ("outgoing", "locals", "spill", "saved")


def class_widths(target: str) -> dict[str, int]:
    """Each register class's value width in bytes, from the emitted target.

    `def RV_GPRRegs : RegisterClass<"RV32I", [i32], 32, ...>` -- the value type
    list is what the class holds *in this document*, which is not the class
    table's declared width: `rv_gpr` covers RV32 and RV64 and takes its width
    from the operands. Reading it here rather than assuming a pointer width is
    what lets a spill slot be checked against the register it has to hold.
    """
    widths: dict[str, int] = {}
    for name, types in re.findall(
            r"def (\w+)Regs : RegisterClass<\"[^\"]*\", \[([^\]]*)\]", target):
        bits = [int(match) for match in re.findall(r"i(\d+)", types)]
        if bits:
            widths[name.lower()] = max(bits) // 8
    return widths


def check_regions(name: str, frame: dict, target: str) -> list[str]:
    """F4/F5: the regions, the spill geometry, and the pointer discipline.

    No region has a size, and that is the line the stage draws: how many spill
    slots a function needs is the register allocator's decision, made per
    function. What the platform decides is the order, and the order has
    consequences a document can contradict.
    """
    failures: list[str] = []
    regions = [region.lower() for region in frame.get("regions", [])]
    if regions:
        if len(set(regions)) != len(regions):
            failures.append(f"{name}: a region is listed twice in {regions}")
        if any(region not in REGION_ORDER for region in regions):
            failures.append(f"{name}: {regions} names a region that is not one of "
                            f"{list(REGION_ORDER)}")
        elif "saved" not in regions:
            failures.append(f"{name}: the region order does not include `saved`")
        else:
            highest = regions[-1] if frame["saved_area"] == "top" else regions[0]
            if highest != "saved":
                failures.append(
                    f"{name}: the saved area is at the {frame['saved_area']} of the "
                    f"frame and the region order puts `{highest}` there")
            if "outgoing" in regions and regions[0] != "outgoing":
                failures.append(
                    f"{name}: outgoing arguments are not at the frame base, where the "
                    f"callee's own stack pointer finds them")

    widths = class_widths(target)
    for slot in frame.get("spill", []):
        klass, size, align = slot["class"], slot["bytes"], slot["align"]
        needed = widths.get(klass.lower())
        if needed is None:
            failures.append(f"{name}: `{klass}` has no registers in this target, so a "
                            f"spill slot for it holds nothing")
        elif size < needed:
            failures.append(
                f"{name}: a {size}-byte spill slot for `{klass}`, whose registers are "
                f"{needed} bytes wide")
        if align <= 0 or align & (align - 1) or size % align:
            failures.append(
                f"{name}: `{klass}` spills {size} bytes aligned to {align}; consecutive "
                f"slots of that size would not all be aligned")

    # The implication the pointer discipline turns on: realignment moves the
    # frame away from the incoming stack pointer, dynamic allocation moves the
    # stack pointer away from the frame, and both together leave neither able
    # to reach a local.
    realigns = frame.get("realignment") == "allowed"
    dynamic = frame.get("dynamic_allocation") == "allowed"
    if realigns and dynamic and frame.get("base_pointer") is None:
        failures.append(
            f"{name}: allows realignment and dynamic allocation with no base pointer")
    return failures


def check_frame(name: str, frame: dict, target: str) -> list[str]:
    failures: list[str] = []
    slot_bytes = frame["slot_bytes"]
    top = frame["saved_area"] == "top"
    limit = frame["max_frame_bytes"]

    seen: dict[int, list] = {}
    for rank, slot in enumerate(frame["slots"]):
        expected = limit - (rank + 1) * slot_bytes if top else rank * slot_bytes
        if slot["rank"] != rank or slot["offset"] != expected:
            failures.append(
                f"{name}: slot {rank} for {slot['register']} is published at "
                f"{slot['offset']}, and the layout puts it at {expected}")
        if not 0 <= slot["offset"] <= limit - slot_bytes:
            failures.append(
                f"{name}: slot for {slot['register']} at {slot['offset']} does not fit "
                f"inside a {limit}-byte frame")
        seen.setdefault(slot["offset"], []).append(slot["register"])
    for offset, registers in seen.items():
        if len(registers) > 1:
            failures.append(
                f"{name}: {registers} share the slot at {offset}; a frame that puts two "
                f"registers in one place loses one of them")
    if frame["saved_bytes"] != len(frame["slots"]) * slot_bytes:
        failures.append(
            f"{name}: saved area is published as {frame['saved_bytes']} bytes for "
            f"{len(frame['slots'])} slots of {slot_bytes}")

    # The join: can the named instructions reach what the frame declares?
    ranges = immediate_ranges(target)
    highest = max((slot["offset"] for slot in frame["slots"]), default=0)
    for mnemonic, needed, what in (
            (frame["save"], highest, "the outermost slot"),
            (frame["restore"], highest, "the outermost slot"),
            (frame["adjust"], -limit if frame["growth"] == "down" else limit,
             "the frame adjustment")):
        predicate = operand_predicate(target, mnemonic.upper())
        if predicate is None or predicate not in ranges:
            failures.append(
                f"{name}: `{mnemonic}` has no immediate with a stated range, so nothing "
                f"says it can reach {what} at {needed}")
            continue
        low, high = ranges[predicate]
        if not low <= needed <= high:
            failures.append(
                f"{name}: `{mnemonic}` encodes {low}..{high} and {what} is at {needed}; "
                f"the instruction set does not reach the frame this abi declares")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv32i.axisl")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axis_frame_") as workdir:
        manifest = Path(workdir) / "manifest.json"
        target = Path(workdir) / "target.td"
        for command, out in (("emit-json", manifest), ("emit-llvm-target", target)):
            subprocess.run([*axis_prefix(), command, str(args.axis_file), "-o", str(out)],
                           cwd=AXIS_ROOT, check=True, capture_output=True)
        payload = json.loads(manifest.read_text())
        target_text = target.read_text()

    failures: list[str] = []
    frames = 0
    for abi in payload.get("abis", []):
        frame = abi.get("frame")
        if frame is None:
            continue
        frames += 1
        found = check_frame(abi["name"], frame, target_text)
        found.extend(check_regions(abi["name"], frame, target_text))
        failures.extend(found)
        if not found:
            print(f"     {abi['name']}: {len(frame['slots'])} saved slot(s), outermost "
                  f"at {max(slot['offset'] for slot in frame['slots'])} of a "
                  f"{frame['max_frame_bytes']}-byte frame, all reachable; "
                  f"{len(frame.get('regions', []))} region(s), "
                  f"{len(frame.get('spill', []))} spill geometry(ies)")

    for message in failures:
        print(f"FAIL {message}")
    if not frames:
        print("no abi in this corpus declares a frame: there is no layout to re-derive "
              "and no offset to reach")
        return DECLINED
    print("frame layout: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
