#!/usr/bin/env python3
"""Group the instructions a target emits no pattern for, by what they *are*.

`llvm_target_check.py` already prints a census by decline *message*. This is
the other axis, and the one that keeps being needed: what the behaviors those
instructions carry actually look like.

The difference is not cosmetic. Four times in one session a decline message was
read as a cause and the estimate that followed was wrong:

  * "490 declines are a result plus NZCV, flag-setting is next" -- they were
    writeback stores and atomic read-modify-writes. Flag-setting was 16.
  * "pre/post-index addressing is C++ glue, out of reach" -- `TargetSelectionDAG.td`
    defines `pre_store`.
  * "344 writeback stores are reachable" -- 16 were. The other 320 were atomics,
    which are also reachable, but are not that.
  * "a narrow atomic is not one node" -- an emitter's own invented limit, and
    LLVM's AArch64 backend writes those patterns.

Every one of those was corrected by grouping the *behaviors* instead, which had
to be hand-written each time. A message is what an emitter chose to say; a
shape is what the description states, and only the second is evidence about
what is reachable.

Usage:
  tools/decline_census.py examples/aarch64_translation_seed.axisl
  tools/decline_census.py examples/rv64i.axisl --shape store   # one group's members
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file),
                    "-o", str(output)],
                   cwd=AXIS_ROOT, check=True, capture_output=True)


def declines(target_text: str) -> dict[str, str]:
    """{MNEMONIC: reason} for every instruction the target emitted nothing for."""
    out = {}
    for line in target_text.splitlines():
        found = re.fullmatch(r"// (\S+): (.*); no pattern", line)
        if found:
            out[found.group(1)] = found.group(2)
    return out


def shape(entry: dict) -> str:
    """What one instruction's behavior *is*, as a short key.

    Ordered by how much it decides: the locations written first, because that
    is what picks a SelectionDAG node at all; then the properties that pick
    between the nodes of that kind.
    """
    effects = entry.get("effects") or []
    if not effects:
        # A `formal_semantics` instruction has no effect list -- it states one
        # expression and the lift table carries it as a tree. Calling that "no
        # behavior" is the exact error this file exists to prevent: it put 46
        # instructions that describe themselves perfectly well under a heading
        # saying they describe nothing.
        formal = entry.get("semantics")
        if not formal:
            return "no semantics of any kind"
        operators = sorted(set(re.findall(r'"op": "(\w+)"', json.dumps(formal))))
        return "formal: " + (",".join(operators) if operators else "a bare value")
    kinds = collections.Counter(effect.get("kind", "?") for effect in effects)
    parts = [
        "+".join(f"{kind}x{count}" if count > 1 else kind
                 for kind, count in sorted(kinds.items()))
    ]
    if any(effect.get("atomic") for effect in effects):
        parts.append("atomic")
    orders = {effect.get("memory_order") for effect in effects}
    orders.discard(None)
    orders.discard("relaxed")
    if orders:
        parts.append("ordered:" + ",".join(sorted(orders)))
    if any(effect.get("guard") for effect in effects):
        parts.append("guarded")
    # A register written that is also the address read: base writeback, which
    # is a different node from either half on its own.
    written = {effect.get("dest") for effect in effects if effect.get("kind") == "set"}
    addressed = {effect.get("addr") for effect in effects if effect.get("kind") == "store"}
    if written & addressed:
        parts.append("writeback")
    # The helpers a behavior names decide whether it lowers at all.
    helpers = sorted({name for name in
                      re.findall(r"\((a64_\w+|[a-z][\w]*)\s", json.dumps(effects))
                      if name.startswith("a64_")})
    if helpers:
        parts.append("via:" + ",".join(helpers))
    widths = {operand["width"] for operand in entry.get("operands", [])
              if operand.get("kind") not in (None, "imm")}
    if len(widths) > 1:
        parts.append("mixed-widths")
    return " ".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--shape", default="",
                        help="list the instructions in groups matching this substring")
    parser.add_argument("--top", type=int, default=14, help="how many groups to show")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_declines_"))
    emit(args.axis_file, "emit-llvm-target", workdir / "target.td")
    emit(args.axis_file, "emit-lift-json", workdir / "lift.json")
    refused = declines((workdir / "target.td").read_text())
    table = json.loads((workdir / "lift.json").read_text())
    entries = table["instructions"] if isinstance(table, dict) else table

    groups: dict[str, list[tuple[str, str]]] = collections.defaultdict(list)
    for entry in entries:
        mnemonic = entry.get("mnemonic")
        if mnemonic not in refused:
            continue
        groups[shape(entry)].append((mnemonic, refused[mnemonic]))

    if args.shape:
        for key in sorted(groups):
            if args.shape.lower() not in key.lower():
                continue
            print(f"{key}  ({len(groups[key])})")
            for mnemonic, reason in sorted(groups[key]):
                print(f"    {mnemonic:28} {reason}")
        return 0

    total = sum(len(members) for members in groups.values())
    print(f"{total} instruction(s) with no pattern, in {len(groups)} shape(s)")
    print()
    ranked = sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    for key, members in ranked[:args.top]:
        # The reasons a shape is refused under. More than one means the
        # emitter is describing several causes with one word, or one cause
        # with several -- either way it is worth seeing side by side.
        reasons = collections.Counter(reason for _, reason in members)
        head = ", ".join(f"{reason} ({count})" for reason, count
                         in reasons.most_common(2))
        print(f"{len(members):5d}  {key}")
        print(f"       e.g. {sorted(members)[0][0]} -- {head}")
    if len(ranked) > args.top:
        rest = sum(len(members) for _, members in ranked[args.top:])
        print(f"{rest:5d}  in {len(ranked) - args.top} further shape(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
