#!/usr/bin/env python3
"""Check register views against the architectures they describe.

`exec_wide_check.py` proves the executors *honour* the register-class table: it
reads the same table they do, applies the same extract/insert, and compares. That
is worth having and it cannot notice a table that is wrong -- both sides move
together. Injecting "x86's AL zeroes the rest of RAX" leaves it passing with zero
failures, because the reference dutifully zeroes too.

So the views are stated here from the architecture, and the published table has to
match. Three things per view, and only the first was ever expressible before:

    width    how many bits it exposes
    offset   where it starts -- AH is at bit 8
    policy   what a write does to the bits outside it

The policy is where architectures genuinely disagree, and where one of them
disagrees with itself: writing x86's EAX zeroes the upper half of RAX while
writing AL preserves it. A model that can only mask-and-overwrite expresses the
first and silently mis-describes the second.

Usage: tools/register_slice_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# (width, offset, preserves, limbs) -- written from what each architecture does,
# not read back from the table under test. `limbs` is how many 64-bit slots one
# register of the class occupies: a general-purpose register is one, and a
# 128-bit vector register is two, which is what lets a view straddle.
ARCHITECTURE = {
    # AArch64: a W write zeroes the upper half of its X register.
    "a64_gpr32": (32, 0, False, 1),
    "a64_gpr32sp": (32, 0, False, 1),
    "a64_gpr64": (None, 0, False, 1),
    "a64_gpr64sp": (None, 0, False, 1),
    # RISC-V has one view per file.
    "rv_gpr": (None, 0, False, 1),
    "rv_fpr": (None, 0, False, 1),
    # x86: the 32-bit view zeroes, and the narrower ones preserve. AH starts at
    # bit 8, which is the case no width-only model can hold.
    "x86_r64": (None, 0, False, 1),
    "x86_r32": (32, 0, False, 1),
    "x86_r16": (16, 0, True, 1),
    "x86_r8lo": (8, 0, True, 1),
    "x86_r8hi": (8, 8, True, 1),
    # A 128-bit vector file, whose views are the three positions a limb
    # implementation has to distinguish -- inside a limb, exactly one limb, and
    # across the boundary -- plus one that zeroes, which on a register of more
    # than one limb has to clear the limbs the write never touched. That last
    # is what an x86 VEX write does to the upper half of a YMM register.
    "v128_s0": (32, 0, True, 2),
    "v128_s1": (32, 32, True, 2),
    "v128_d1": (64, 64, True, 2),
    "v128_cross": (32, 48, True, 2),
    "v128_z0": (32, 0, False, 2),
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_slice_"))
    lift_py = workdir / "axis_lift.py"
    subprocess.run(
        [*axis_prefix(), "emit-lift-python", str(args.axis_file),
         "-o", str(lift_py)],
        check=True, cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location("axis_lift_slice", lift_py)
    lift = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lift)

    checks = failures = 0
    preserving = offset_views = straddling = 0
    for name, (width, offset, preserves, limbs) in sorted(ARCHITECTURE.items()):
        row = lift.REGISTER_CLASSES.get(name)
        if row is None:
            print(f"FAIL {name}: not in the published table")
            failures += 1
            continue
        got = (row[2], row[4], row[5], row[6])
        checks += 1
        if preserves:
            preserving += 1
        if offset:
            offset_views += 1
        if width and offset % 64 and offset % 64 + width > 64:
            straddling += 1
        if got != (width, offset, preserves, limbs):
            failures += 1
            print(
                f"FAIL {name}: table says width={got[0]} offset={got[1]} "
                f"preserves={got[2]} limbs={got[3]}, architecture says "
                f"width={width} offset={offset} preserves={preserves} "
                f"limbs={limbs}"
            )

    print(f"{checks} register views checked, {failures} failures")
    print(f"  {preserving} preserve their surrounding bits, {offset_views} start "
          f"above bit 0, {straddling} cross a limb boundary")
    # Both properties have to be represented, or the check reduces to the
    # width-only model this replaced.
    if not preserving:
        print("no view preserves; the write policy is untested")
        failures += 1
    if not offset_views:
        print("no view starts above bit 0; the offset is untested")
        failures += 1
    if not straddling:
        print("no view crosses a limb boundary; the storage layout is untested")
        failures += 1
    print("register views == architecture: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
