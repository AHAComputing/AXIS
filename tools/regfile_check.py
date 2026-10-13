#!/usr/bin/env python3
"""The register file's storage is the description's, and everyone agrees. Gate.

Six things index the register file -- the Python lifter, three executors, the
stencil emitter and the pack -- and each computed `offset + index_offset +
index` for itself, off a table that says where a class starts and a constant
that says every file has thirty-two registers. Two of those derivations have
been wrong: the stencil indexed the file raw for two years, so a translated
`c.sub` wrote `x1` where the architecture says `x9`, and every check indexed it
raw on both sides and agreed.

`emit-regfile-json` publishes the layout once, derived from the description's
own encodings rather than from a constant. This gate holds it to three things:

1. **Every register the description can name has storage.** For each class, the
   top slot its widest selector reaches is within what the pack allocates. A
   file sized by a constant is right until an encoding has a six-bit selector,
   and then it is silently short.

2. **Nobody's arithmetic disagrees.** For every class and every index it can
   name, the layout's `base + (index_offset + index) * stride` is the slot the
   generated lifter puts that operand in. Two derivations of one fact, compared
   rather than assumed.

3. **No two files share storage by accident.** ⚠️ This is the one that found
   something. Views of one file overlap on purpose -- that is what a view is,
   and the class table now says which storage each class views. Two classes
   that name DIFFERENT storage and overlap anyway are a description in which
   writing `v1` changes `r2`: `simd_fp_lanes` addressed one register file at
   two strides, so its 64-bit lane instructions and its 128-bit ones disagreed
   about where the same register lived, and every differential gate passed
   because both sides of each comparison made the same assumption.

Usage: tools/regfile_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def overlap_probe(work: Path) -> tuple[int, int]:
    """A description that DOES overlap, so the detector is exercised.

    ⚠️ Without this the overlap check is a guard nobody has ever seen fire.
    Every corpus is clean -- one of them stopped being dirty when this gate was
    written -- so disabling the detector entirely would pass, which is the
    shape of every gate that measures less than its name claims. The probe is a
    description using two classes that name DIFFERENT storage at the same base:
    `reg` strides one slot per register and `reg128` strides two, so `v1` is
    slot 1 to one of them and slots 2-3 to the other.
    """
    source = (AXIS_ROOT / "examples" / "effects_pure.axisl").read_text()
    probe = work / "overlap_probe.axisl"
    probe.write_text(source.replace("(rd reg i32 out)", "(rd reg128 i128 out)", 1))
    try:
        layout = json.loads(run([*axis_prefix(), "emit-regfile-json",
                                 str(probe)]).stdout)
    except subprocess.CalledProcessError as error:
        said = (error.stderr or error.stdout or str(error)).strip()
        print(f"  FAIL overlap probe: the description did not build -- "
              f"{said[:200]}")
        return 1, 1
    if not layout["overlaps"]:
        print(f"  FAIL overlap probe: `reg` and `reg128` share slot 2 and "
              f"nothing reported it -- the detector cannot fire")
        return 1, 1
    print(f"  overlap probe: reported {layout['overlaps'][0]}, as it should")
    return 1, 0


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    name = axis_file.stem
    layout = json.loads(run([*axis_prefix(), "emit-regfile-json",
                             str(axis_file)]).stdout)
    if not layout["files"]:
        print(f"  {name}: DECLINED the description names no register class")
        return 0, 0
    run([*axis_prefix(), "emit-lift-python", str(axis_file),
         "-o", str(work / f"rf_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"rf_{name}")

    checks = failures = 0
    slots = layout["slots"]

    for file in layout["files"]:
        # 1. Storage exists for every register the description can name.
        checks += 1
        if file["top"] > slots:
            print(f"  FAIL {name}: {file['class']} reaches slot "
                  f"{file['top'] - 1} and the file is {slots} slot(s)")
            failures += 1

        # 2. The layout's arithmetic is the lifter's.
        #    ⚠️ `register_slot` is what every consumer actually calls, so this
        #    compares the published layout against the thing it describes
        #    rather than against a second copy of itself.
        for index in (0, 1, file["registers"] - 1):
            checks += 1
            want = file["base"] + (file["index_offset"] + index) * file["stride"]
            got = lift.register_slot(file["class"], index)
            if got != want:
                print(f"  FAIL {name}: {file['class']}[{index}] is slot {got} "
                      f"to the lifter and {want} to the layout")
                failures += 1

    # ⚠️ How many registers a file has, against the ENCODINGS. The layout
    # derives this from the selector's width and a constant 32 would agree with
    # it for every class whose selector is five bits -- which is all but one.
    # RISC-V's compressed forms name eight registers with three bits, so that
    # is where a constant shows.
    #
    # ⚠️ And against the registers NO selector reaches. SVE's FFR is predicate
    # register 16: `(fixed 16)`, named by no bits of any word, so the file
    # holds more than its four-bit selector counts. Such a file has to hold
    # the highest fixed index, and no more than the next power of two does --
    # "selected by 4 bits, 32 registers" was this gate failing a description
    # that was right.
    widest: dict[str, int] = {}
    pinned: dict[str, int] = {}
    for entry in lift.AXIS_LIFT_TABLE:
        for operand in entry["operands"]:
            if operand["kind"] not in {file["class"] for file in layout["files"]}:
                continue
            # A field is a tuple in the Python table: (insn_lo, op_lo, width).
            bits = sum(field[2] for field in operand["fields"])
            if bits:
                widest[operand["kind"]] = max(widest.get(operand["kind"], 0), bits)
            elif operand.get("fixed") is not None:
                pinned[operand["kind"]] = max(pinned.get(operand["kind"], 0), operand["fixed"])
    for file in layout["files"]:
        bits = widest.get(file["class"])
        if bits is None or bits >= 32:
            continue
        checks += 1
        want = 1 << bits
        beyond = pinned.get(file["class"], -1)
        while want <= beyond:
            want <<= 1
        if file["registers"] != want:
            print(f"  FAIL {name}: {file['class']} is selected by {bits} bit(s)"
                  + (f", with register {beyond} named by no bits," if beyond >= 1 << bits else "")
                  + f" and the layout gives it {file['registers']} register(s), not {want}")
            failures += 1

    # 3. No two files share storage by accident.
    checks += 1
    if layout["overlaps"]:
        for one, other in layout["overlaps"]:
            print(f"  FAIL {name}: {one} and {other} name different storage "
                  f"and share slots -- writing one changes the other")
        failures += 1

    # ⚠️ The lane stride, against the consumer that uses it. An operand with a
    # view reaches `slot_base + number * stride`, which is a different path
    # through the executor from the class arithmetic above -- and the file has
    # to hold both, so the wider one is what `top` was computed from.
    for file in layout["files"]:
        if not file["lane_stride"]:
            continue
        checks += 1
        reach = (file["base"]
                 + (file["index_offset"] + file["registers"]) * file["lane_stride"])
        if reach > slots:
            print(f"  FAIL {name}: {file['class']} lane-strides to slot "
                  f"{reach - 1} and the file is {slots} slot(s)")
            failures += 1
        # ⚠️ And the row's own `top` has to cover it. Without this the layout
        # could report a file ending where its class arithmetic ends while its
        # operands reach further -- which is a row that is wrong about the
        # thing it exists to state, and which the two bounds above both miss
        # because the allocation is sized from the operands either way.
        checks += 1
        if file["top"] < reach:
            print(f"  FAIL {name}: {file['class']} says it ends at "
                  f"{file['top']} and its lane stride reaches {reach}")
            failures += 1

    # A file whose registers do not fit its own stride is a layout that cannot
    # be right, whatever anything else says.
    for file in layout["files"]:
        checks += 1
        if file["stride"] < 1 or file["registers"] < 1:
            print(f"  FAIL {name}: {file['class']} has stride "
                  f"{file['stride']} and {file['registers']} register(s)")
            failures += 1
        checks += 1
        if file["bits"] > max(file["stride"], file["lane_stride"]) * 64:
            print(f"  FAIL {name}: {file['class']} is {file['bits']} bits and "
                  f"its stride holds {file['stride'] * 64}")
            failures += 1

    if not failures:
        print(f"  {name}: {len(layout['files'])} file(s) in {slots} slot(s), "
              f"{checks} checks")
    sys.modules.pop(f"rf_{name}", None)
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    checks = failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        did, bad = overlap_probe(Path(tmp))
        checks += did
        failures += bad
        for corpus in corpora:
            try:
                did, bad = check(corpus, Path(tmp))
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("the layout == what indexes it: SKIP")
        return DECLINED
    print(f"the layout == what indexes it: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
