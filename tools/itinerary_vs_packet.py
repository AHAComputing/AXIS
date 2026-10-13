#!/usr/bin/env python3
"""The schedule the compiler reads agrees with the packet the machine accepts.

`packet_schedule_manifest.json` is what an LLVM `SchedMachineModel` /
`DFAPacketizer` consumes; `packet_manifest.json` plus `decode_packet` is what
the machine actually does. Both are derived from one slot/unit resolution, and
this requires them to answer the same question the same way:

  **given a multiset of instructions, can they issue in one packet?**

Two derivations, in opposite directions, and both halves are required:

  * *sound* -- every group the itinerary calls schedulable must really pack and
    decode back to that group. A scheduler whose table is too permissive emits
    packets the machine rejects.
  * *complete* -- every group that packs must be called schedulable. A table
    that is too strict silently costs issue width, which no test of correctness
    would ever catch.

Deciding schedulability from the itinerary is bipartite matching, not counting:
a group of two `mul`s is not legal on a machine with three ALUs and one
multiplier however many free slots there are. Counting per unit is exactly the
plausible-but-wrong implementation this gate exists to reject, so it is checked
against here as well -- if counting and matching agree on every group the
corpus can build, the corpus is too weak to tell them apart and the run fails
as vacuous.

Usage: tools/itinerary_vs_packet.py [input.axisl] [--groups N] [--seed S]
"""

from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import random
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def can_match(masks: list[int], width: int) -> bool:
    """Can each instruction take a distinct slot its mask allows?

    Bipartite matching by augmenting paths. Small by construction -- an issue
    width is a handful of slots -- so the simple algorithm is the right one.
    """
    if len(masks) > width:
        return False
    taken: dict[int, int] = {}

    def assign(index: int, seen: set[int]) -> bool:
        for slot in range(width):
            if not (masks[index] >> slot) & 1 or slot in seen:
                continue
            seen.add(slot)
            if slot not in taken or assign(taken[slot], seen):
                taken[slot] = index
                return True
        return False

    for index in range(len(masks)):
        if not assign(index, set()):
            return False
    return True


def can_count(masks: list[int], width: int, units: list[str]) -> bool:
    """The plausible-but-wrong rule: enough of each unit, ignoring which slots.

    Kept so the gate can prove the corpus distinguishes it from matching.
    """
    if len(masks) > width:
        return False
    capacity = Counter()
    for mask in set(masks):
        capacity[mask] = bin(mask).count("1")
    need = Counter(units)
    per_unit_mask = dict(zip(units, masks))
    return all(need[unit] <= capacity[per_unit_mask[unit]] for unit in need)


def schedulable(group: list[dict], packet: dict) -> bool:
    """The itinerary's answer: can the group be matched to distinct slots?

    There is deliberately no separate branch check. `at_most_one` is enforced
    *statically* -- `validate` rejects a packet whose declaration lets two
    slots transfer control -- so in any document that validates, every branch
    contends for the same slot and matching already refuses two of them. A
    predicate here would read as coverage and could never fire; the manifest
    still publishes `branches` because a scheduler needs to know a terminator,
    not because it is what makes a group illegal.

    Measured rather than assumed: emitting `branches: false` for every
    instruction leaves this gate passing, which is what says the check would
    have been dead.
    """
    width = packet["issue_width"]
    if len(group) > width:
        return False
    return can_match([int(one["slot_mask"], 16) for one in group], width)


def packs(group: list[dict], packet: dict, fixtures: dict, lift, name: str,
          isa: str | None) -> bool:
    """The machine's answer: some slot assignment encodes and decodes back."""
    width = packet["issue_width"]
    for slots in itertools.permutations(range(width), len(group)):
        words: list[int] = []
        placed = sorted(zip(slots, group))
        if any(not (int(one["slot_mask"], 16) >> slot) & 1 for slot, one in placed):
            continue
        # A group shorter than the packet is padded with whatever each
        # remaining slot can legally hold, since a container is fixed-length.
        filler = {}
        for slot in range(width):
            if slot in slots:
                continue
            for candidate in packet["itineraries"]:
                if (int(candidate["slot_mask"], 16) >> slot) & 1 \
                        and candidate["mnemonic"] in fixtures:
                    filler[slot] = candidate
                    break
            if slot not in filler:
                break
        if len(filler) + len(slots) != width:
            continue
        chosen = dict(placed) | filler
        words = [int(fixtures[chosen[slot]["mnemonic"]]["encoded"], 16)
                 for slot in range(width)]
        decoded = lift.decode_packet(words, name, isa)
        if decoded is None or len(decoded) != width:
            continue
        got = Counter(one["entry"]["mnemonic"] for one in decoded)
        want = Counter(chosen[slot]["mnemonic"] for slot in range(width))
        if got == want:
            return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "vliw_packet.axisl")
    parser.add_argument("--groups", type=int, default=400)
    parser.add_argument("--seed", type=int, default=20260827)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_itin_"))
    emit(args.axis_file, "emit-vliw-itinerary", workdir / "itinerary.json")
    emit(args.axis_file, "emit-packet-json", workdir / "packet.json")
    emit(args.axis_file, "emit-roundtrip-json", workdir / "roundtrip.json")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    lift = load_module(workdir / "axis_lift.py", "axis_lift")

    itinerary = json.loads((workdir / "itinerary.json").read_text())
    fixtures = {test["mnemonic"]: test
                for test in json.loads((workdir / "roundtrip.json").read_text())["tests"]}
    rng = random.Random(args.seed)

    if not itinerary["packets"]:
        print(f"{args.axis_file.name}: declares no packet, nothing to schedule")
        return 0

    failures: list[str] = []
    checked = 0
    counting_differed = 0
    for packet in itinerary["packets"]:
        name = packet["name"]
        isa = packet["isa"] or None
        width = packet["issue_width"]
        pool = [one for one in packet["itineraries"] if one["mnemonic"] in fixtures]
        if not pool:
            print(f"{name}: no encodable instruction, nothing to schedule")
            continue

        groups: list[tuple] = []
        for size in range(1, width + 1):
            every = list(itertools.combinations_with_replacement(pool, size))
            groups.extend(every if len(every) <= args.groups
                          else rng.sample(every, args.groups))

        for group in groups:
            group = list(group)
            checked += 1
            said = schedulable(group, packet)
            does = packs(group, packet, fixtures, lift, name, isa)
            if said != does:
                failures.append(
                    f"{name}: {[one['mnemonic'] for one in group]} -- itinerary says "
                    f"{'schedulable' if said else 'not schedulable'}, the machine "
                    f"{'packs it' if does else 'does not'}")
            # Does this corpus distinguish matching from counting at all?
            counted = can_count([int(one["slot_mask"], 16) for one in group], width,
                                [one["unit"] for one in group])
            if counted != can_match([int(one["slot_mask"], 16) for one in group], width):
                counting_differed += 1

    for failure in failures[:10]:
        print(f"FAIL {failure}")
    if len(failures) > 10:
        print(f"... and {len(failures) - 10} more")

    print(f"{checked} group(s) decided both ways")
    if counting_differed == 0:
        print("FAIL: no group distinguished slot matching from per-unit counting, "
              "so this corpus cannot tell a correct itinerary from a permissive one")
        failures.append("vacuous")
    else:
        print(f"{counting_differed} group(s) where counting units would have "
              f"disagreed with matching slots")

    print("itinerary == packet legality: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
