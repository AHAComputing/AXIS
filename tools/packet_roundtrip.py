#!/usr/bin/env python3
"""Pack issue packets, decode them back, and check what the run covered.

A packet is a container of syllables (`docs/vliw_spatial_design.md` §3), so the
thing that can go wrong is not the encoding of any one instruction -- the
existing roundtrip gate proves that -- but the *container*: which slot a
syllable lands in, whether the end rule takes the right number of them, and
whether a slot's unit set is what actually narrows the decode.

Three things are checked, and each can fail:

1. **Pack/unpack.** For every legal assignment of instructions to slots, encode
   the syllables, pack them, and require `decode_packet` to return the same
   (slot, mnemonic, operand values) it was given.
2. **Position resolves ambiguity.** Two instructions held by disjoint slots may
   carry one bit pattern. For every such pair the corpus contains, plain
   `decode` must report ambiguity (it has no position to go on) and the two
   slots must each resolve it to their own instruction. A packet layer that
   ignored slots would pass step 1 and fail here.
3. **Junk is rejected or legal.** Random containers must either fail to decode
   or produce a group in which every syllable's unit is one the slot holds.

And it reports what the run covered, per `docs/gate_coverage.md`: a gate that
packed only ALU syllables would say "300 packets" and prove nothing about the
memory slot, so a slot or a declared unit class that never carried a syllable
fails the run rather than going unmentioned.

Usage: tools/packet_roundtrip.py <input.axisl> [--packets N] [--seed N]
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
from pathlib import Path

from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(output)],
                   check=True, cwd=AXIS_ROOT)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def fixture_for(fixtures: list[dict]) -> dict[str, dict]:
    """One encodable fixture per mnemonic."""
    return {test["mnemonic"]: test for test in fixtures}


def check(axis_file: Path, packet_count: int, seed: int) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        emit(axis_file, "emit-packet-json", workdir / "packet_manifest.json")
        emit(axis_file, "emit-roundtrip-json", workdir / "roundtrip.json")
        emit(axis_file, "emit-lift-python", workdir / "axis_lift.py")
        manifest = json.loads((workdir / "packet_manifest.json").read_text())
        fixtures = fixture_for(json.loads((workdir / "roundtrip.json").read_text())["tests"])
        lift = load_module(workdir / "axis_lift.py", "axis_lift")

        if not manifest["packets"]:
            print(f"{axis_file.name}: declares no packet, so there is no "
                  f"container to roundtrip -> FAIL")
            return False

        rng = random.Random(seed)
        failures: list[str] = []
        packed = 0
        slots_covered: set[str] = set()
        units_covered: set[str] = set()

        for packet in manifest["packets"]:
            name, slots = packet["name"], packet["slots"]
            isa = packet["isa"] or None
            # What each slot can hold, as fixtures we can actually encode.
            choices = []
            for slot in slots:
                holdable = [one for one in packet["instructions"]
                            if slot["index"] in one["slots"] and one["mnemonic"] in fixtures]
                choices.append(holdable)
            if any(not holdable for holdable in choices):
                empty = [slot["name"] for slot, holdable in zip(slots, choices) if not holdable]
                print(f"{axis_file.name}: packet `{name}` slots {empty} can hold no "
                      f"encodable instruction -> FAIL")
                return False

            # Every assignment when that is small, a sample when it is not.
            every = list(itertools.product(*choices))
            groups = every if len(every) <= packet_count else rng.sample(every, packet_count)

            for group in groups:
                words = [int(fixtures[one["mnemonic"]]["encoded"], 16) for one in group]
                decoded = lift.decode_packet(words, name, isa)
                packed += 1
                if decoded is None:
                    failures.append(f"{name}: packed group "
                                    f"{[one['mnemonic'] for one in group]} did not decode")
                    continue
                if len(decoded) != len(group):
                    failures.append(f"{name}: packed {len(group)} syllables, "
                                    f"decoded {len(decoded)}")
                    continue
                for slot, expected, actual in zip(slots, group, decoded):
                    slots_covered.add(f"{name}.{slot['name']}")
                    units_covered.add(expected["unit"])
                    if actual["slot"] != slot["name"]:
                        failures.append(f"{name}: syllable landed in slot "
                                        f"{actual['slot']}, packed into {slot['name']}")
                    if actual["entry"]["mnemonic"] != expected["mnemonic"]:
                        failures.append(f"{name}.{slot['name']}: packed "
                                        f"{expected['mnemonic']}, decoded "
                                        f"{actual['entry']['mnemonic']}")
                        continue
                    # The operands have to survive the container too: a packer
                    # that shifted a syllable by a slot would still decode to
                    # the right mnemonic whenever the neighbours agree.
                    lifted = lift.lift_entry(actual["word"], actual["entry"])
                    fixture = fixtures[expected["mnemonic"]]
                    for operand in fixture["operands"]:
                        got = lifted["operands"].get(operand["name"])
                        if got is not None and got != operand["value"]:
                            failures.append(
                                f"{name}.{slot['name']}: {expected['mnemonic']} operand "
                                f"{operand['name']} packed {operand['value']}, decoded {got}")

            # 2. Position is what resolves a shared encoding.
            shared = 0
            by_word: dict[tuple[str, str], list[dict]] = {}
            for one in packet["instructions"]:
                by_word.setdefault((one["match"], one["mask"]), []).append(one)
            for (match, _mask), sharers in by_word.items():
                for left, right in itertools.combinations(sharers, 2):
                    if set(left["slots"]) & set(right["slots"]):
                        continue
                    shared += 1
                    word = int(fixtures[left["mnemonic"]]["encoded"], 16) \
                        if left["mnemonic"] in fixtures else int(match, 16)
                    if lift.decode(word, isa) is not None:
                        failures.append(
                            f"{name}: {left['mnemonic']} and {right['mnemonic']} share a "
                            f"word, so plain decode must report ambiguity")
                    for one in (left, right):
                        slot = slots[one["slots"][0]]
                        entry = lift.decode_slot(word, {"name": slot["name"],
                                                        "width": slot["width"],
                                                        "units": tuple(slot["units"])}, isa)
                        if entry is None or entry["mnemonic"] != one["mnemonic"]:
                            failures.append(
                                f"{name}.{slot['name']}: shared word resolved to "
                                f"{entry['mnemonic'] if entry else None}, "
                                f"want {one['mnemonic']}")

            # 3. Junk either fails to decode or decodes slot-legally.
            #
            # Random words are almost all rejected, which exercises only half
            # of that sentence. So half the junk is a legal container with its
            # *operand* bits scrambled: those still decode, and the slot
            # legality of what they decode to is the half a run of pure noise
            # would never reach.
            junk_rejected = junk_decoded = 0
            masks = {one["mnemonic"]: int(one["mask"], 16)
                     for one in packet["instructions"]}
            for index in range(packet_count):
                if index % 2 == 0:
                    words = [rng.getrandbits(slot["width"]) for slot in slots]
                else:
                    base = [choices[slot["index"]][rng.randrange(len(choices[slot["index"]]))]
                            for slot in slots]
                    words = []
                    for one in base:
                        word = int(fixtures[one["mnemonic"]]["encoded"], 16)
                        noise = rng.getrandbits(32) & ~masks[one["mnemonic"]]
                        words.append((word & masks[one["mnemonic"]]) | noise)
                decoded = lift.decode_packet(words, name, isa)
                if decoded is None:
                    junk_rejected += 1
                    continue
                junk_decoded += 1
                for slot, actual in zip(slots, decoded):
                    if actual["entry"].get("unit", "") not in slot["units"]:
                        failures.append(
                            f"{name}.{slot['name']}: decoded "
                            f"{actual['entry']['mnemonic']} of unit "
                            f"{actual['entry'].get('unit')}, which the slot does not hold")

            print(f"{axis_file.name}: packet `{name}`: {packed} packed, "
                  f"{shared} shared-encoding pairs resolved by position, "
                  f"{junk_rejected} containers rejected and {junk_decoded} "
                  f"accepted slot-legally of {packet_count} perturbed")
            # Neither half of "rejected or slot-legal" may go unexercised.
            if junk_rejected == 0 or junk_decoded == 0:
                failures.append(
                    f"{name}: perturbation covered only one outcome "
                    f"({junk_rejected} rejected, {junk_decoded} accepted)")

        declared_slots = {f"{packet['name']}.{slot['name']}"
                          for packet in manifest["packets"] for slot in packet["slots"]}
        declared_units = {unit for packet in manifest["packets"]
                          for slot in packet["slots"] for unit in slot["units"]}
        missing_slots = sorted(declared_slots - slots_covered)
        missing_units = sorted(declared_units - units_covered)
        print(f"{axis_file.name}: slots covered {len(slots_covered)}/{len(declared_slots)}, "
              f"unit classes {len(units_covered)}/{len(declared_units)}")
        # A slot no syllable was packed into is a slot this run says nothing
        # about, and saying nothing is what a green gate must not do.
        if missing_slots:
            failures.append(f"slots never packed: {missing_slots}")
        if missing_units:
            failures.append(f"unit classes never packed: {missing_units}")

        for failure in failures[:20]:
            print(f"  {failure}")
        status = "PASS" if not failures else "FAIL"
        print(f"{axis_file.name}: {packed} packets, {len(failures)} failures -> {status}")
        return not failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--packets", type=int, default=64,
                        help="assignments to pack per packet when not exhaustive")
    parser.add_argument("--seed", type=int, default=20260826)
    args = parser.parse_args()
    ok = all(check(source, args.packets, args.seed) for source in args.sources)
    print("PACKET ROUNDTRIP PASSED" if ok else "PACKET ROUNDTRIP FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
