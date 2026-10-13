#!/usr/bin/env python3
"""Check statement-level loops against what the instruction means.

A block copy writes only memory, and the executor harnesses cannot reach it: the
roundtrip fixtures they drive are generated from instructions that write a
*register*, so an instruction whose whole effect is on memory produces none and
the gates skip. That is worth knowing on its own -- it is the same coverage hole
that leaves vector stores unexecuted -- and it means this construct needs a
reference of its own.

So the shapes are stated here and the emitted effects checked against them: how
many accesses, at which addresses, of which width, reading from where. Both the
store address and the address inside the loaded value are evaluated numerically
rather than compared as text.

Usage: tools/blockmem_check.py <input.axisl> [--cases N]
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

# mnemonic -> (count, width, store address, loaded address or None for a fill)
BLOCKS = {
    "MEMCPY16": (16, 8, lambda i, rd, rs: rd + i, lambda i, rd, rs: rs + i),
    "MEMCPY8_W": (8, 32, lambda i, rd, rs: rd + 4 * i, lambda i, rd, rs: rs + 4 * i),
    "MEMSET32": (32, 8, lambda i, rd, rs: rd + i, None),
    "MEMCPY_REV8": (8, 8, lambda i, rd, rs: rd + i, lambda i, rd, rs: rs + (7 - i)),
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
    if isinstance(node, str):
        if node in bindings:
            return bindings[node]
        return int(node, 16) if node.startswith("0x") else int(node)
    op, args = node[0], [evaluate(item, bindings) for item in node[2:]]
    if op == "add":
        return sum(args)
    if op == "sub":
        return args[0] - args[1]
    if op == "mul":
        result = 1
        for value in args:
            result *= value
        return result
    raise SystemExit(f"address uses `{op}`, which this reference does not model")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=32)
    args = parser.parse_args()

    lift = json.loads(subprocess.run(
        [*axis_prefix(), "emit-lift-json", str(args.axis_file)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT,
    ).stdout)
    by_name = {i["mnemonic"]: i for i in lift["instructions"]}

    random.seed(0xB10C)
    checks = failures = 0
    covered = []

    for mnemonic, (count, width, store_at, load_at) in BLOCKS.items():
        instruction = by_name.get(mnemonic)
        if instruction is None:
            print(f"skip {mnemonic}: not present")
            continue
        effects = instruction.get("effects") or []
        covered.append(mnemonic)
        if len(effects) != count:
            print(f"FAIL {mnemonic}: {len(effects)} effects, want {count}")
            failures += 1
            continue
        for index, effect in enumerate(effects):
            if effect.get("kind") != "store" or effect.get("width") != width:
                print(
                    f"FAIL {mnemonic}[{index}]: kind {effect.get('kind')} "
                    f"width {effect.get('width')}, want store/{width}"
                )
                failures += 1
                continue
            store_expr, _ = parse(tokenize(effect["addr"]))
            load_expr = None
            if load_at is not None:
                found = re.match(r"\(load \S+ \S+ (.*)\)$", effect["value"])
                if not found:
                    print(f"FAIL {mnemonic}[{index}]: value is not a load")
                    failures += 1
                    continue
                load_expr, _ = parse(tokenize(found.group(1)))
            elif effect["value"] != "rs":
                print(f"FAIL {mnemonic}[{index}]: fill stores {effect['value']}, want rs")
                failures += 1
                continue

            for _ in range(args.cases):
                bindings = {"rd": random.getrandbits(32), "rs": random.getrandbits(32)}
                got = evaluate(store_expr, bindings)
                want = store_at(index, bindings["rd"], bindings["rs"])
                checks += 1
                if got != want:
                    failures += 1
                    if failures <= 6:
                        print(f"FAIL {mnemonic}[{index}] store address {got} want {want}")
                if load_expr is not None:
                    got = evaluate(load_expr, bindings)
                    want = load_at(index, bindings["rd"], bindings["rs"])
                    checks += 1
                    if got != want:
                        failures += 1
                        if failures <= 6:
                            print(f"FAIL {mnemonic}[{index}] load address {got} want {want}")

    if not covered:
        print("SKIP: no block-memory instructions")
        return 0
    print(f"{checks} address checks over {len(covered)} block operations, {failures} failures")
    print("block memory == architecture: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
