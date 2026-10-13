#!/usr/bin/env python3
"""Check predication against the architecture, not against itself.

Every backend derives its answer from the same description, so the
backend-vs-golden gates prove the *implementations* agree and cannot notice a
description that is uniformly wrong. An inverted merge sense inverts every
backend identically and passes all of them. This tool states what predication
means, independently, and requires the description to match:

  merging, lane active    the predicated result equals the plain operation
  merging, lane inactive  it equals the destination it merged into
  zeroing, lane inactive  it is zero
  vwhilelt                lane l is active exactly while base + l < count

The first two are what pin the *sense* of the predicate, which is the part a
differential gate structurally cannot see. The pairing below is the independent
statement; everything else is read from the artifact.

Usage: tools/scalable_predication.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent

# (predicated mnemonic, unpredicated counterpart, predicate operand, merged-into
# operand or None for a zeroing form).
MERGING = [
    ("SVADD_M_S", "SVADD_S", "pg", "zd"),
    ("SVMUL_M_H", "SVMUL_H", "pg", "zd"),
    ("SVSUB_M_B", "SVSUB_B", "pg", "zd"),
    ("SVFADD_M_S", "SVFADD_S", "pg", "zd"),
    ("SVADD_Z_S", "SVADD_S", "pg", None),
]
WHILE = [("SVWHILELT_S", "base", "count")]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_pred_"))
    golden_path = workdir / "golden_model.py"
    subprocess.run(
        [*axis_prefix(), "emit-golden-python", str(args.axis_file),
         "-o", str(golden_path)],
        check=True, cwd=AXIS_ROOT,
    )
    spec = importlib.util.spec_from_file_location("axis_golden_pred", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)
    specs = golden.AXIS_SPECS

    def lanes_of(origin: str) -> dict[int, dict]:
        return {
            entry["scalable_lane"]: entry
            for entry in specs.values()
            if entry.get("scalable_origin") == origin
            and not entry.get("defined_by")
            and "__defined" not in entry.get("scalable_origin", "")
        }

    random.seed(0x9EED)
    checks = failures = 0

    def report(label: str, got, want) -> None:
        nonlocal checks, failures
        checks += 1
        if got != want:
            failures += 1
            if failures <= 6:
                print(f"FAIL {label}: got 0x{got:x} want 0x{want:x}")

    for predicated, plain, pg_name, merged_into in MERGING:
        pred_lanes, plain_lanes = lanes_of(predicated), lanes_of(plain)
        if not pred_lanes or not plain_lanes:
            print(f"skip {predicated}: no lanes found")
            continue
        for lane, entry in sorted(pred_lanes.items()):
            reference = plain_lanes.get(lane)
            if reference is None:
                print(f"skip {predicated} lane {lane}: no counterpart")
                continue
            names = [name for name, _ in entry["params"]]
            widths = dict(entry["params"])
            for _ in range(args.cases):
                values = {name: random.getrandbits(width)
                          for name, width in entry["params"]}
                plain_args = [values[name] for name, _ in reference["params"]]
                expected_active = reference["eval"](*plain_args)

                for active in (1, 0):
                    values[f"{pg_name}__l{lane}"] = active
                    got = entry["eval"](*[values[name] for name in names])
                    if active:
                        want = expected_active
                    elif merged_into is None:
                        want = 0
                    else:
                        want = values[f"{merged_into}__l{lane}"] \
                            if f"{merged_into}__l{lane}" in values \
                            else values.get(merged_into, 0)
                    report(f"{predicated} lane {lane} pg={active}", got, want)

    for mnemonic, base_name, count_name in WHILE:
        for lane, entry in sorted(lanes_of(mnemonic).items()):
            names = [name for name, _ in entry["params"]]
            width = dict(entry["params"]).get(base_name, 32)
            limit = max(len(lanes_of(mnemonic)) * 2, 4)
            for _ in range(args.cases):
                values = {name: random.getrandbits(w) for name, w in entry["params"]}
                values[base_name] = random.randint(0, limit)
                values[count_name] = random.randint(0, limit)
                got = entry["eval"](*[values[name] for name in names])
                total = (values[base_name] + lane) % (1 << width)
                want = 1 if total < values[count_name] else 0
                report(f"{mnemonic} lane {lane}", got, want)

    if not checks:
        print("nothing was checked")
        return DECLINED
    print(f"{checks} predication checks, {failures} failures")
    print("predication == architecture: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
