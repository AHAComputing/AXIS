#!/usr/bin/env python3
"""A mapping computes what its scalar sequence computes.

This is the stage where a CGRA description stops being merely well-formed. G1
says the fabric is a grid, G2 says the schedule uses nothing twice; neither
says the mapping is *right*. Here the mapping runs as a cycle-by-cycle
dataflow over the fabric and its `equivalent-to` sequence runs straight
through, and the two must agree over random inputs.

Both sides evaluate the **same** per-operation semantics, out of the same
golden model. So what is under test is not the arithmetic -- that is proven
elsewhere, several ways -- but the placement, the routing and the timing,
which is exactly what a mapping adds.

The interpreter is written to be able to fail. A PE holds one result, and a
later iteration landing on it overwrites what an earlier one left; a link
carries one value per cycle. Those are the conditions G2's modulo checks
exist to prevent, so a legal mapping agrees and an illegal one need not --
which is what makes agreement evidence rather than tautology. It runs several
iterations in steady state, because a schedule whose II is shorter than an
operation's latency only goes wrong once iterations overlap, and one iteration
would never show it.

Usage: tools/fabric_vs_scalar.py [input.axisl] [--iterations N] [--trials T]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import subprocess
import sys
import tempfile
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


class Fabric:
    """A grid whose PEs publish a result at a cycle and whose links carry one
    value per cycle.

    A PE's output is a *timeline*, not a slot. That matters once iterations
    overlap: a route entering a link at cycle C picks up whatever its source PE
    most recently finished at or before C, which may be this iteration's value
    or the previous one's. Which it is, is decided entirely by the schedule --
    so this is the model that can catch a mapping whose timing silently reads
    the wrong iteration, and a slot per PE would instead report every pipelined
    schedule as broken.
    """

    def __init__(self) -> None:
        self.timeline: dict[tuple[int, int], list[tuple[int, int, str]]] = {}
        self.busy: dict[tuple, str] = {}
        self.faults: list[str] = []

    def publish(self, position, ready, value, owner):
        self.timeline.setdefault(position, []).append((ready, value, owner))

    def latest(self, position, cycle):
        """What this PE most recently finished at or before `cycle`."""
        candidates = [entry for entry in self.timeline.get(position, []) if entry[0] <= cycle]
        if not candidates:
            return None
        return max(candidates, key=lambda entry: entry[0])

    def cross(self, link, cycle, owner):
        key = (link, cycle)
        if key in self.busy and self.busy[key] != owner:
            self.faults.append(
                f"link {link[0]}->{link[1]} carries {self.busy[key]} and {owner} at cycle {cycle}")
        self.busy[key] = owner


def run_mapping(mapping, fabric_links, latency_of, golden, inputs, iterations):
    """The dataflow: each iteration's operations fire at `cycle + k*ii`.

    Returns the value each operation produced, per iteration, and which
    iteration each routed value actually came from.
    """
    ii = mapping["ii"]
    place = {one["id"]: one for one in mapping["place"]}
    routed = {(route["to"], route["operand"]): route for route in mapping["route"]}
    machine = Fabric()
    produced: dict[tuple[int, str], int] = {}

    schedule = sorted(
        ((one["cycle"] + step * ii, step, one["id"])
         for step in range(iterations) for one in place.values()),
        key=lambda entry: (entry[0], entry[2]),
    )
    for cycle, step, op_id in schedule:
        op = place[op_id]
        arguments = []
        for name in op["inputs"]:
            route = routed.get((op_id, name))
            if route is None:
                arguments.append(inputs[(step, op_id, name)])
                continue
            via = [tuple(position) for position in route["via"]]
            # The value entered the link in the *producer's* iteration, which
            # is `distance` iterations before this one. Indexing the route by
            # the consumer's iteration reads a value that has not been sent
            # yet -- and for a same-iteration route the two happen to coincide,
            # which is why only a software-pipelined mapping catches it.
            entry = route["cycle"] + (step - route["distance"]) * ii
            if step - route["distance"] < 0:
                arguments.append(None)
                continue
            held = machine.latest(via[0], entry)
            if held is None:
                # Nothing has been computed there yet -- the pipeline's prologue,
                # where a consumer runs before its producer ever has. Those
                # iterations are excluded from the comparison rather than fudged.
                arguments.append(None)
                continue
            flight = 0
            for source, target in zip(via, via[1:]):
                machine.cross((source, target), entry + flight,
                              f"{route['from']}->{route['to']}#{step}")
                flight += fabric_links[(source, target)]
            arguments.append(held[1])
        if any(argument is None for argument in arguments):
            continue
        value = golden.evaluate(op["mnemonic"], *arguments)
        machine.publish(tuple(op["pe"]), cycle + latency_of[op["mnemonic"]], value,
                        f"{op_id}#{step}")
        produced[(step, op_id)] = value
    return produced, machine.faults


def run_scalar(mapping, golden, inputs, iterations, seed=None):
    """The same operations, in the order the mapping says it equals.

    `seed` pre-populates results from before iteration zero, which is what an
    elastic ring's initial token is: a value the cycle starts holding, without
    which nothing on it can ever fire. A statically timed mapping passes none
    and behaves as it always has.
    """
    place = {one["id"]: one for one in mapping["place"]}
    routed = {(route["to"], route["operand"]): route for route in mapping["route"]}
    produced: dict[tuple[int, str], int] = dict(seed or {})
    for step in range(iterations):
        values: dict[str, int] = {}
        for op_id in mapping["scalar_order"]:
            op = place[op_id]
            arguments = []
            for name in op["inputs"]:
                route = routed.get((op_id, name))
                if route is None:
                    arguments.append(inputs[(step, op_id, name)])
                    continue
                # `distance` iterations back, which is what a software-pipelined
                # loop means: the scalar sequence reads the value the earlier
                # iteration produced, not this one's.
                source = step - route["distance"]
                # The lookup decides, not the sign: a negative iteration is
                # absent for a statically timed mapping, where the prologue is
                # excluded, and *present* for an elastic ring, where it is the
                # initial token the buffer was primed with. Testing `source < 0`
                # first made a primed ring look like an empty prologue and
                # produced nothing at all.
                if (source, route["from"]) not in produced:
                    arguments.append(None)
                    continue
                arguments.append(produced[(source, route["from"])])
            if any(argument is None for argument in arguments):
                continue
            value = golden.evaluate(op["mnemonic"], *arguments)
            values[op_id] = value
            produced[(step, op_id)] = value
    return produced


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "cgra_fabric.axisl")
    parser.add_argument("--iterations", type=int, default=6)
    parser.add_argument("--trials", type=int, default=64)
    parser.add_argument("--seed", type=int, default=20260827)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_g3_"))
    emit(args.axis_file, "emit-mapping-json", workdir / "mapping.json")
    emit(args.axis_file, "emit-fabric-json", workdir / "fabric.json")
    emit(args.axis_file, "emit-json", workdir / "document.json")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    golden = load_module(workdir / "golden_model.py", "golden_model")

    mappings = json.loads((workdir / "mapping.json").read_text())["mappings"]
    fabrics = {f["name"]: f for f in json.loads((workdir / "fabric.json").read_text())["fabrics"]}
    document = json.loads((workdir / "document.json").read_text())
    # An instruction's input operands, in the order its evaluator takes them.
    latency_of = {one["mnemonic"]: one["latency_cycles"] for one in document["instructions"]}
    inputs_of = {
        one["mnemonic"]: [operand["name"] for operand in one["operands"]
                          if operand["input"]]
        for one in document["instructions"]
    }

    if not mappings:
        print(f"{args.axis_file.name}: declares no mapping, nothing to execute")
        return 0

    rng = random.Random(args.seed)
    failures: list[str] = []
    overlapped = 0
    carried = 0
    compared = 0
    elastic_skipped = []
    for mapping in mappings:
        # An elastic mapping is not this gate's. What this one proves is that a
        # *fixed* schedule computes what the scalar sequence computes; when a
        # route's arrival is a window rather than a cycle, that claim has no
        # content, and running the fixed-timing simulation over it would report
        # a pass about a machine the description does not describe. The
        # obligation elastic carries instead -- the result does not depend on
        # the timing -- is `elastic_vs_scalar.py`'s, and the half decidable
        # without executing anything is `elastic_deadlock_check.py`'s.
        if any(route.get("channel") for route in mapping["route"]):
            elastic_skipped.append(mapping["name"])
            continue
        name, ii = mapping["name"], mapping["ii"]
        fabric = fabrics[mapping["fabric"]]
        links = {((l["from"][0], l["from"][1]), (l["to"][0], l["to"][1])): l["latency"]
                 for l in fabric["links"]}
        for one in mapping["place"]:
            one["inputs"] = inputs_of[one["mnemonic"]]

        # Does an iteration still have work in flight when the next issues?
        span = max(one["cycle"] for one in mapping["place"]) + 1
        if span > ii:
            overlapped += 1
        if any(route["distance"] > 0 for route in mapping["route"]):
            carried += 1

        free = [(one["id"], name)
                for one in mapping["place"] for name in one["inputs"]
                if not any(route["to"] == one["id"] and route["operand"] == name
                           for route in mapping["route"])]
        # Where a free operand's value comes from. Without a live-in it is an
        # anonymous number, which is what this gate always used and is enough
        # to check placement and timing. With one it is a *register* or a
        # constant -- and two operands naming one register must see one value,
        # which anonymous inputs could not require. That is the property the
        # bindings add, so it is the one drawn for here.
        bound = {(live["op"], live["operand"]): live for live in mapping.get("live_in", [])}
        for _ in range(args.trials):
            registers: dict[int, int] = {}

            def value_for(step: int, op_id: str, operand: str) -> int:
                live = bound.get((op_id, operand))
                if live is None:
                    return rng.getrandbits(32)
                if live["kind"] == "const":
                    return live["value"] & 0xFFFFFFFF
                # One register, one value -- per iteration, since a kernel
                # reads the file once at the top of each.
                key = (step, live["index"])
                if key not in registers:
                    registers[key] = rng.getrandbits(32)
                return registers[key]

            values = {(step, op_id, operand): value_for(step, op_id, operand)
                      for step in range(args.iterations) for op_id, operand in free}
            spatial, faults = run_mapping(mapping, links, latency_of, golden, values,
                                          args.iterations)
            scalar = run_scalar(mapping, golden, values, args.iterations)
            compared += 1
            for fault in faults[:3]:
                failures.append(f"{name}: {fault}")
            differing = [key for key in scalar
                         if key in spatial and spatial[key] != scalar[key]]
            if differing:
                key = differing[0]
                failures.append(
                    f"{name}: iteration {key[0]} operation {key[1]} -- fabric "
                    f"{spatial.get(key)}, scalar {scalar[key]}")
                break

    for failure in failures[:10]:
        print(f"FAIL {failure}")
    print(f"{compared} run(s) of {args.iterations} iterations compared, "
          f"{len(mappings) - len(elastic_skipped)} mapping(s)")
    if elastic_skipped:
        print(f"  {len(elastic_skipped)} elastic mapping(s) left to the elastic gates: "
              f"{', '.join(elastic_skipped)}")
    if overlapped == 0:
        print("FAIL: no mapping's schedule outlives its II, so iterations never overlap "
              "and this corpus cannot tell a pipelined machine from a serial one")
        failures.append("vacuous")
    else:
        print(f"{overlapped} mapping(s) whose iterations overlap in steady state")
    if carried == 0:
        print("FAIL: no mapping carries a value across an iteration, so this corpus "
              "cannot tell a software-pipelined schedule from one whose dataflow fits "
              "inside a single iteration")
        failures.append("vacuous")
    else:
        print(f"{carried} mapping(s) with a cross-iteration dependence")

    print("fabric dataflow == scalar sequence: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
