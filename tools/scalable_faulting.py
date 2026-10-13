#!/usr/bin/env python3
"""Check fault suppression against the architecture (mechanism M5).

A predicated load must not fault on lanes it does not perform, and that is the
one thing the `vmerge`-as-select design cannot express: a select computes every
lane and discards some, and computing a lane is exactly what faults. So the
condition reaches the access itself, as the effect's guard.

Two forms, and the difference between them is the whole point:

  vload_nf  each lane is judged on its own -- SVE's non-faulting LDNF1
  vload_ff  lane l is performed only if every lane before it was accessible
            too, so the load stops at the first fault -- SVE's LDFF1 and
            RVV's vle*ff

This states both independently and evaluates the emitted guard numerically. It
also requires the two to *disagree* somewhere: a contiguous region starting at
the base makes them identical, so a run that never places the hole anywhere else
would pass while testing nothing about the cumulative rule.

Usage: tools/scalable_faulting.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# The independent statement: form and element size in bytes.
FAULTING = {
    "VLDNF_S": ("nf", 4),
    "VLDFF_S": ("ff", 4),
    "VLDNF_H": ("nf", 2),
    "LDNF1_S": ("nf", 4),
    "LDFF1_S": ("ff", 4),
    "VLE32FF_V": ("ff", 4),
}


def tokenize(text: str) -> list[str]:
    return text.replace("(", " ( ").replace(")", " ) ").split()


def parse(tokens: list[str], pos: int = 0):
    if tokens[pos] != "(":
        return tokens[pos], pos + 1
    items, pos = [], pos + 1
    while tokens[pos] != ")":
        item, pos = parse(tokens, pos)
        items.append(item)
    return items, pos + 1


def evaluate(node, bindings: dict[str, int]) -> int:
    """Small enough to share no code with the emitter it checks."""
    if isinstance(node, str):
        if node in bindings:
            return bindings[node]
        return int(node, 16) if node.startswith("0x") else int(node)
    op = node[0]
    # A guard's comparisons are untyped; arithmetic inside them is not.
    args = node[1:] if op.startswith("icmp") or op in ("and", "or", "not") else node[2:]
    values = [evaluate(item, bindings) for item in args]
    if op == "and":
        return int(all(values))
    if op == "or":
        return int(any(values))
    if op == "not":
        return int(not values[0])
    if op == "icmp_uge":
        return int(values[0] >= values[1])
    if op == "icmp_ult":
        return int(values[0] < values[1])
    if op == "add":
        return sum(values)
    if op == "mul":
        result = 1
        for value in values:
            result *= value
        return result
    raise SystemExit(f"guard uses `{op}`, which this reference does not model")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=96)
    args = parser.parse_args()

    lift = json.loads(subprocess.run(
        [*axis_prefix(), "emit-lift-json", str(args.axis_file)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT,
    ).stdout)

    groups: dict[str, dict[int, dict]] = {}
    for instruction in lift["instructions"]:
        origin = instruction.get("scalable_origin")
        if origin in FAULTING:
            groups.setdefault(origin, {})[instruction["scalable_lane"]] = instruction
    if not groups:
        print("SKIP: no fault-suppressing loads")
        return 0

    random.seed(0xFA17)
    checks = failures = 0
    suppressed = 0
    nf_ff_differed = 0

    for origin, lanes in sorted(groups.items()):
        form, bytes_per = FAULTING[origin]
        count = len(lanes)
        guards = {}
        for lane, instruction in sorted(lanes.items()):
            guard = instruction["effects"][0].get("guard")
            if guard is None:
                print(f"FAIL {instruction['mnemonic']}: no accessibility guard")
                failures += 1
                continue
            guards[lane], _ = parse(tokenize(guard))

        for _ in range(args.cases):
            base = random.randrange(0x1000, 0x100000, bytes_per)
            span = count * bytes_per
            # Place the accessible window so it sometimes starts after the base:
            # a window that begins at the base makes nf and ff agree, and then
            # the cumulative rule is never exercised.
            lo = base + random.randint(-1, count) * bytes_per
            hi = lo + random.randint(0, count + 1) * bytes_per
            bindings = {"rs1": base, "rn": base, "mem_lo": lo, "mem_hi": hi}

            reachable = [
                lo <= base + lane * bytes_per
                and base + lane * bytes_per + bytes_per <= hi
                for lane in range(count)
            ]
            for lane in range(count):
                if lane not in guards:
                    continue
                if form == "nf":
                    want = reachable[lane]
                else:
                    want = all(reachable[: lane + 1])
                got = bool(evaluate(guards[lane], bindings))
                checks += 1
                if not want:
                    suppressed += 1
                if reachable[lane] and not all(reachable[: lane + 1]):
                    nf_ff_differed += 1
                if got != want:
                    failures += 1
                    if failures <= 6:
                        print(
                            f"FAIL {origin} lane {lane}: base={hex(base)} "
                            f"lo={hex(lo)} hi={hex(hi)} guard={int(got)} want={int(want)}"
                        )
            del span

    print(f"{checks} guard checks over {len(groups)} loads, {failures} failures")
    print(f"  lanes suppressed                : {suppressed}")
    print(f"  lanes where nf and ff disagree  : {nf_ff_differed}")
    if not suppressed:
        print("no lane was ever suppressed; the guards were never exercised")
        failures += 1
    if not nf_ff_differed:
        print("first-fault never differed from non-faulting; the cumulative rule is untested")
        failures += 1
    print("fault suppression == architecture: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
