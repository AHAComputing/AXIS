#!/usr/bin/env python3
"""An elastic mapping's result does not depend on its timing (stage G4b.2).

G3 (`fabric_vs_scalar.py`) fixes the timing and asks whether the mapping
computes what its scalar sequence computes. That claim has no content once a
value's arrival is a window rather than a cycle, so elastic carries the classic
correctness condition for elastic circuits instead, and it is the stronger one:

    the result does not depend on the timing.

So this gate does the opposite of G3's. It **varies** the delays -- each token
on each channel draws its own, independently, from that channel's window -- and
requires every draw to produce the answer the scalar sequence produces. The
scalar reference is G3's own `run_scalar`, imported rather than reimplemented:
it is timing-free by construction, which is exactly what an elastic mapping
must agree with.

What can fail. A channel that preserves order delivers its tokens in the order
they entered however long each takes, so the pairing a consumer sees is
delay-independent -- that is what `(order preserving)` *means*, and a
description that says it earns a pass here. A channel declared `(order
unordered)` may let a later token overtake an earlier one, and then which value
a consumer reads depends on the draw. A kernel that needs correspondence and a
channel that does not promise it is a mapping whose result depends on its
timing, and this is the gate that says so.

Vacuity, per `docs/gate_coverage.md`: a run where the drawn delays never
differed varied nothing, and a corpus with no elastic mapping has nothing to
vary. Both fail rather than passing quietly.

Usage: tools/elastic_vs_scalar.py [input.axisl] [--iterations N] [--trials T]
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import fabric_vs_scalar as g3

AXIS_ROOT = Path(__file__).resolve().parent.parent


def deliveries(route: dict, channel: dict, entries: dict[int, int],
               rng: random.Random) -> tuple[dict[int, int], list[int]]:
    """Which token each consuming iteration reads, and the delays drawn.

    `entries` is the cycle each iteration's token entered the channel. A
    preserving channel hands them on in that order whatever the delays; an
    unordered one hands them on in arrival order, so a token with a short draw
    can overtake one with a long draw.
    """
    low, high = channel["latency_min"], channel["latency_max"]
    drawn = {step: rng.randint(low, high) for step in entries}
    if channel["order"] == "preserving":
        order = sorted(entries)
    else:
        order = sorted(entries, key=lambda step: (entries[step] + drawn[step], step))
    # Position i in the delivered stream is the token `order[i]` carries.
    return {position: step for position, step in enumerate(order)}, list(drawn.values())


def ring_seed(mapping, channels) -> dict[tuple[int, str], int]:
    """The values a cycle starts holding, from its channels' initial tokens.

    A route that reaches back `distance` iterations reads, at iteration zero,
    something produced before the run began. On a ring that is the initial
    token; without it every operation on the cycle waits for a value only the
    cycle produces, and nothing fires at all.
    """
    seed: dict[tuple[int, str], int] = {}
    for route in mapping["route"]:
        channel = channels.get(route.get("channel", ""))
        if channel is None or not route["distance"]:
            continue
        for step in range(1, route["distance"] + 1):
            seed[(-step, route["from"])] = channel.get("initial", 0)
    return seed


def run_elastic(mapping, channels, golden, inputs, iterations, rng):
    """The dataflow with arrival drawn from each channel's window.

    An operation fires when its inputs are present rather than at a cycle, so
    there is no schedule here at all -- what a consumer reads is the token its
    channel delivered, and the question is whether that depends on the draw.
    """
    place = {one["id"]: one for one in mapping["place"]}
    routed = {(route["to"], route["operand"]): route for route in mapping["route"]}
    produced: dict[tuple[int, str], int] = dict(ring_seed(mapping, channels))
    drawn: list[int] = []

    # Every token that will cross each elastic route, and when it entered.
    delivery: dict[tuple[str, str], dict[int, int]] = {}
    for (to, operand), route in routed.items():
        if not route.get("channel"):
            continue
        channel = channels[route["channel"]]
        entries = {step: step for step in range(iterations)}
        order, draws = deliveries(route, channel, entries, rng)
        delivery[(to, operand)] = order
        drawn.extend(draws)

    for step in range(iterations):
        for op_id in mapping["scalar_order"]:
            op = place[op_id]
            arguments = []
            for name in op["inputs"]:
                route = routed.get((op_id, name))
                if route is None:
                    arguments.append(inputs[(step, op_id, name)])
                    continue
                position = step - route["distance"]
                source_step = delivery.get((op_id, name), {}).get(position, position)
                arguments.append(produced.get((source_step, route["from"])))
            if any(argument is None for argument in arguments):
                continue
            produced[(step, op_id)] = golden.evaluate(op["mnemonic"], *arguments)
    return produced, drawn


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "cgra_fabric.axisl")
    parser.add_argument("--iterations", type=int, default=6)
    parser.add_argument("--trials", type=int, default=32)
    parser.add_argument("--seed", type=int, default=20260901)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_g4b2_"))
    g3.emit(args.axis_file, "emit-mapping-json", workdir / "mapping.json")
    g3.emit(args.axis_file, "emit-json", workdir / "document.json")
    g3.emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    golden = g3.load_module(workdir / "golden_model.py", "golden_model")

    payload = json.loads((workdir / "mapping.json").read_text())
    channels = {one["name"]: one for one in payload.get("channels", [])}
    document = json.loads((workdir / "document.json").read_text())
    inputs_of = {one["mnemonic"]: [operand["name"] for operand in one["operands"]
                                   if operand["input"]]
                 for one in document["instructions"]}

    elastic = [mapping for mapping in payload.get("mappings", [])
               if any(route.get("channel") for route in mapping["route"])]
    rng = random.Random(args.seed)
    failures = compared = 0
    draws_seen: set[tuple[int, ...]] = set()

    for mapping in elastic:
        for one in mapping["place"]:
            one["inputs"] = inputs_of[one["mnemonic"]]
        free = [(one["id"], name) for one in mapping["place"] for name in one["inputs"]
                if not any(route["to"] == one["id"] and route["operand"] == name
                           for route in mapping["route"])]
        for _ in range(args.trials):
            inputs = {(step, op_id, name): rng.getrandbits(32)
                      for step in range(args.iterations) for op_id, name in free}
            reference = g3.run_scalar(mapping, golden, inputs, args.iterations,
                                      seed=ring_seed(mapping, channels))
            produced, drawn = run_elastic(mapping, channels, golden, inputs,
                                          args.iterations, rng)
            draws_seen.add(tuple(drawn))
            compared += 1
            shared = set(reference) & set(produced)
            wrong = [key for key in sorted(shared) if reference[key] != produced[key]]
            if wrong:
                failures += 1
                if failures <= 4:
                    key = wrong[0]
                    print(f"FAIL {mapping['name']}: iteration {key[0]} of {key[1]} "
                          f"gave 0x{produced[key]:x} under delays {drawn}, where the "
                          f"scalar sequence gives 0x{reference[key]:x}")

    print(f"{len(elastic)} elastic mapping(s), {compared} timing draw(s) compared, "
          f"{len(draws_seen)} distinct")
    if not elastic:
        print("no elastic mapping in this corpus: there is no timing to vary, so this "
              "run proves nothing about the check")
        failures += 1
    elif len(draws_seen) < 2:
        print("every run drew the same delays: nothing was varied, so agreement is "
              "not evidence")
        failures += 1
    print("elastic == scalar under any timing: " + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
