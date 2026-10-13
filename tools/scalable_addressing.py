#!/usr/bin/env python3
"""Check that lane l of a scalable load reads the address the architecture says.

Stage S1 recorded a limit: a pure lane function is a function of its parameters,
so `(add i32 zn__l0 zm__l0)` and `(add i32 zn__l1 zm__l1)` are the same function
and no differential gate can tell lane 0 from lane 1. Lane identity simply is
not expressed in pure semantics.

An address cannot hide that way. Lane l of a unit-stride load reads
`base + l*bytes` and of a strided load reads `base + l*step`, and both name the
lane explicitly. So this is where the mapping finally becomes checkable -- and
per the rule S4 established, checking it needs a reference the description did
not write. The expected address is computed here, from the architecture, and the
emitted one is evaluated numerically rather than compared as text so that a
different but equivalent spelling does not read as a failure.

Usage: tools/scalable_addressing.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# The independent statement: for each vector load, its addressing mode and, for
# unit stride, the element size in bytes. Written from what the instruction
# means, not read back from the artifact under test.
# The independent statement: for each vector access, its addressing mode, the
# element size in bytes for unit stride, and which operands carry the base and
# the stride. Naming the base explicitly matters -- a store's value operand is
# an input too, so "the first input" is not the base and inferring it from the
# address under test would be circular.
ADDRESSING = {
    "VLD_B": ("unit", 1, "rs1", None),
    "VLD_H": ("unit", 2, "rs1", None),
    "VLD_S": ("unit", 4, "rs1", None),
    "VLD_D": ("unit", 8, "rs1", None),
    "VLDS_S": ("strided", None, "rs1", "rs2"),
    "VLDS_H": ("strided", None, "rs1", "rs2"),
    "VST_B": ("unit", 1, "rs1", None),
    "VST_H": ("unit", 2, "rs1", None),
    "VST_S": ("unit", 4, "rs1", None),
    "VST_D": ("unit", 8, "rs1", None),
    "VSTS_S": ("strided", None, "rs1", "rs2"),
    # SVE contiguous forms; the base operand is spelled rn there.
    "LD1_B": ("unit", 1, "rn", None),
    "LD1_H": ("unit", 2, "rn", None),
    "LD1_S": ("unit", 4, "rn", None),
    "LD1_D": ("unit", 8, "rn", None),
    "ST1_B": ("unit", 1, "rn", None),
    "ST1_H": ("unit", 2, "rn", None),
    "ST1_S": ("unit", 4, "rn", None),
    "ST1_D": ("unit", 8, "rn", None),
    # Fault-first and non-faulting loads address contiguously like LD1; what
    # differs is what happens when an element is inaccessible, which is
    # `scalable_faulting.py`'s business rather than this one's.
    # LDFF1 is scalar plus scalar: element l at base + (Xm << log2 bytes) +
    # l*bytes -- an `offset`, which seeding a base alone leaves random, and a
    # first active element at a random address is read even by a first-fault
    # load.
    **{f"LDNF1_{s}": ("unit", n, "rn", None) for s, n in (("B", 1), ("H", 2), ("S", 4), ("D", 8))},
    **{f"LDFF1_{s}": ("offset", n, "rn", "rm") for s, n in (("B", 1), ("H", 2), ("S", 4), ("D", 8))},
    # RVV contiguous and strided forms.
    "VLE32_V": ("unit", 4, "rs1", None),
    "VSE32_V": ("unit", 4, "rs1", None),
    "VLSE32_V": ("strided", None, "rs1", "rs2"),
    # Gather and scatter: the offset is the lane's own index element, so the
    # step operand names the index *vector* and the reference reads its lane.
    "VLUXEI32_V": ("indexed", None, "rs1", "vs2"),
    "VSUXEI32_V": ("indexed", None, "rs1", "vs2"),
}

# Segment loads: field count, element bytes, base operand. Field f of element l
# is at base + (l*nf + f)*bytes, so each effect in the lane is checked against
# its own field index.
SEGMENTS = {
    "VLD2_S": (2, 4, "rs1"),
    "VLD3_S": (3, 4, "rs1"),
    "VLD4_S": (4, 4, "rs1"),
    "LD2_S": (2, 4, "rn"),
    "VLSEG2E32_V": (2, 4, "rs1"),
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
    """A deliberately small evaluator: enough for an address, and nothing that
    shares code with the emitter it is checking."""
    if isinstance(node, str):
        if node in bindings:
            return bindings[node]
        return int(node, 16) if node.startswith("0x") else int(node)
    op = node[0]
    args = [evaluate(item, bindings) for item in node[2:]]
    if op == "add":
        return sum(args)
    if op == "mul":
        result = 1
        for value in args:
            result *= value
        return result
    if op == "sub":
        return args[0] - args[1]
    raise SystemExit(f"address uses `{op}`, which this reference does not model")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64)
    args = parser.parse_args()

    lift = json.loads(subprocess.run(
        [*axis_prefix(), "emit-lift-json", str(args.axis_file)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT,
    ).stdout)

    random.seed(0xADD8)
    checks = failures = 0
    covered: set[str] = set()

    for instruction in lift["instructions"]:
        origin = instruction.get("scalable_origin")
        if origin is None:
            continue
        lane = instruction["scalable_lane"]
        effects = instruction.get("effects") or []

        if origin in SEGMENTS:
            nf, bytes_per, base_name = SEGMENTS[origin]
            covered.add(origin)
            if len(effects) != nf:
                print(f"FAIL {instruction['mnemonic']}: {len(effects)} fields, want {nf}")
                failures += 1
                continue
            for field, effect in enumerate(effects):
                found = re.match(r"\(load \S+ \S+ (.*)\)$", effect["value"])
                if not found:
                    print(f"FAIL {instruction['mnemonic']} field {field}: not a load")
                    failures += 1
                    continue
                address, _ = parse(tokenize(found.group(1)))
                for _ in range(args.cases // 4 or 1):
                    bindings = {base_name: random.getrandbits(32)}
                    got = evaluate(address, bindings)
                    want = bindings[base_name] + (lane * nf + field) * bytes_per
                    checks += 1
                    if got != want:
                        failures += 1
                        if failures <= 6:
                            print(
                                f"FAIL {instruction['mnemonic']} field {field}: "
                                f"{got} want {want}"
                            )
            continue

        mode = ADDRESSING.get(origin)
        if mode is None:
            continue
        if len(effects) != 1:
            print(f"FAIL {instruction['mnemonic']}: expected one effect, got {len(effects)}")
            failures += 1
            continue
        effect = effects[0]
        # A load carries its address inside the loaded value; a store carries it
        # in the location. Same address function either way -- which is the
        # point of putting the shape in `vaddr` for stores.
        if effect["kind"] == "store":
            address_text = effect["addr"]
        else:
            found = re.match(r"\(load \S+ \S+ (.*)\)$", effect["value"])
            if not found:
                print(f"FAIL {instruction['mnemonic']}: not a load: {effect['value']}")
                failures += 1
                continue
            address_text = found.group(1)
        address, _ = parse(tokenize(address_text))
        # The artifact spells direction as `role`, not `output`. Reading the
        # field the artifact publishes rather than the one that seems likely is
        # the whole lesson of this repository's drift bugs.
        names = [operand["name"] for operand in instruction["operands"]
                 if operand["role"] != "out"]
        kind, bytes_per, base_name, step_name = mode
        covered.add(origin)

        for _ in range(args.cases):
            bindings = {name: random.getrandbits(32) for name in names}
            got = evaluate(address, bindings)
            base = bindings[base_name]
            if kind == "unit":
                want = base + lane * bytes_per
            elif kind == "offset":
                want = base + (bindings[step_name] << (bytes_per.bit_length() - 1)) + lane * bytes_per
            elif kind == "indexed":
                # Element l reads base + index[l] -- its *own* index lane, which
                # is why gather is an ordinary address function and not a
                # cross-lane operation.
                want = base + bindings[f"{step_name}__l{lane}"]
            else:
                want = base + lane * bindings[step_name]
            checks += 1
            if got != want:
                failures += 1
                if failures <= 6:
                    print(
                        f"FAIL {instruction['mnemonic']}: lane {lane} address "
                        f"{got} want {want} (from {address_text})"
                    )

    if not checks:
        print("SKIP: no scalable load addresses to check")
        return 0
    print(f"{checks} address checks over {len(covered)} vector accesses, {failures} failures")
    print("lane addressing == architecture: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
