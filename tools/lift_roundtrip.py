#!/usr/bin/env python3
"""Roundtrip check: AXIS instruction -> encoded bits -> lift -> recovered IR.

Emits `axis_roundtrip_tests.json` (deterministic encode fixtures) and the
standalone `axis_lift.py` lifter from the same .axisl source, then for every
fixture lifts the encoded word and requires the recovered mnemonic and operand
values to match what was encoded. This closes the decode/lift direction the
same way `roundtrip_check.py` closes encode/decode.

Usage: tools/lift_roundtrip.py <input.axisl>

Requires: cargo (run from the AXIS repo root).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_lift_"))
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    lifter_path = workdir / "axis_lift.py"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)
    emit(args.axis_file, "emit-lift-python", lifter_path)

    spec = importlib.util.spec_from_file_location("axis_lift", lifter_path)
    lifter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifter)

    fixtures = json.loads(fixtures_path.read_text())
    tests = fixtures.get("tests", [])
    checks = 0
    failures = 0
    for test in tests:
        word = int(test["encoded"], 16)
        lifted = lifter.lift(word, test.get("isa"))
        if lifted is None:
            print(f"FAIL {test['mnemonic']}: word {test['encoded']} did not decode")
            failures += 1
            continue
        if lifted["mnemonic"] != test["mnemonic"]:
            print(f"FAIL {test['encoded']}: decoded {lifted['mnemonic']} "
                  f"want {test['mnemonic']}")
            failures += 1
            continue
        for operand in test["operands"]:
            got = lifted["operands"].get(operand["name"])
            if got != operand["value"]:
                print(f"FAIL {test['mnemonic']}.{operand['name']}: "
                      f"lifted {got} want {operand['value']}")
                failures += 1
            checks += 1

    print(f"{len(tests)} instructions, {checks} operand checks, {failures} failures")
    ok = failures == 0 and (tests or True)
    print("lift roundtrip: PASS" if ok else "lift roundtrip: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
