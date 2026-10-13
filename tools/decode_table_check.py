#!/usr/bin/env python3
"""Prove the decode table selects one instruction per word.

`decode_table.json` is the table a decoder is built from, and it ships in the
bundle. Two tools read it and neither decodes with it, so nothing checked the
one property it exists to have: that a word picks out exactly one instruction.

It did not always. Two instructions may legitimately carry one match and one
mask -- the validator permits it when their ISAs differ, when their modes are
disjoint, when their units sit in disjoint packet slots, or when a decode
predicate separates them -- and the table published only the match, the mask and
(sometimes) the ISA. So `SCALAR_OP` and `TENSOR_OP` were one word with two
meanings to anyone reading the file, and a packet corpus's `VBRZ` and `VSTW`
likewise. The table carries `modes` and `unit` now, and this gate is what says
they are enough.

The check is the decoder a consumer would write: for every roundtrip fixture,
find the entries whose match the word satisfies, then separate them the way the
validator does. What survives must be one instruction -- counting all lanes of a
scalable instruction as the one instruction they are.

Entries carrying a decode predicate are excluded from the contenders rather than
evaluated: this gate does not implement `decode_constraint`, so it does not get
to call an entry ambiguous on the strength of not having read it.

Usage: tools/decode_table_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
# Everything from the lane marker on belongs to elaboration: `ADD_U_S__l0__defined`
# is one definedness variant of one lane of one instruction.
LANE = re.compile(r"__l\d+.*$")


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def separated(left: dict, right: dict) -> bool:
    """Whether the validator's rules keep these two off the same word."""
    if left.get("isa") != right.get("isa"):
        return True
    modes_l, modes_r = left.get("modes"), right.get("modes")
    if modes_l and modes_r and not set(modes_l) & set(modes_r):
        return True
    # Differing units are separated in a corpus that validated: validation only
    # permits the shared word when modes, slots, or a predicate divide the two,
    # so a corpus that parsed has already established it. Assuming this of an
    # unchecked corpus would be unsound.
    unit_l, unit_r = left.get("unit"), right.get("unit")
    return bool(unit_l and unit_r and unit_l != unit_r)


def check(axis_file: Path) -> tuple[int, int]:
    workdir = Path(tempfile.mkdtemp(prefix="axis_decode_"))
    table_path = workdir / "decode_table.json"
    fixtures_path = workdir / "roundtrip.json"
    emit(axis_file, "emit-decode-json", table_path)
    emit(axis_file, "emit-roundtrip-json", fixtures_path)

    entries = json.loads(table_path.read_text())["instructions"]
    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])
    plain = [e for e in entries
             if not e.get("decode_constraint") and not e.get("decode_requires")]

    failures = 0
    checked = 0
    for fixture in fixtures:
        word = int(fixture["encoded"], 16)
        want = LANE.sub("", fixture["mnemonic"])
        # The table holds one entry per *encoding*, so a scalable instruction
        # appears once under its base name while the fixtures name each lane.
        mine = next((e for e in entries
                     if LANE.sub("", e["mnemonic"]) == want), None)
        if mine is None:
            print(f"FAIL {fixture['mnemonic']}: assembled by a fixture but absent "
                  f"from the decode table")
            failures += 1
            continue
        if mine.get("decode_constraint") or mine.get("decode_requires"):
            continue
        checked += 1

        hits = [e for e in plain
                if word & int(e["mask"], 16) == int(e["match"], 16)
                and not separated(mine, e)]
        names = {LANE.sub("", e["mnemonic"]) for e in hits}
        if len(names) != 1:
            shown = ", ".join(sorted(names)) or "none"
            print(f"FAIL {fixture['mnemonic']} ({word:#010x}): the table selects "
                  f"{len(names)} instruction(s) ({shown})")
            failures += 1
        elif want not in names:
            print(f"FAIL {word:#010x}: the table selects {sorted(names)[0]}, the "
                  f"fixture assembled {want}")
            failures += 1

    return checked, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    args = parser.parse_args()
    checked, failures = check(args.axis_file)
    print(f"{checked} word(s) decoded from the table, {failures} failure(s)")
    print("decode table selects one instruction: "
          + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
