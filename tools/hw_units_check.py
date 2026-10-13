#!/usr/bin/env python3
"""The netlists AXIS emits, and the units it merges them into, compute what the
golden model says. Gate.

`emit-hw-pyrtl` ships a circuit per instruction and, beside them, the
functional units those circuits were merged into: one adder where thirty
instructions add, a mux on each input they do not already agree about, and a
`sel` input that says which instruction is running. Three things could be
wrong with that and each is checked here against the golden model, on the
golden model's own vectors:

  1. **An instruction's own netlist.** The lowering narrows widths by demand
     and rewrites as it builds; a rewrite that is wrong is a wrong circuit.
  2. **The same instruction, selected in its unit.** Merging rebinds operators
     and rewires their inputs. The other operands of the unit are driven with
     noise, and so are the bits of a port above the operand that shares it --
     a unit that only works when the wires it does not read are quiet is not a
     unit.
  3. **The account.** Every instruction the golden model evaluates is either
     built or DECLINED BY NAME, and every built one is in exactly one unit.
     ⚠️ Declined is counted apart from wrong and never folded into a pass:
     `--expect-declined` pins the number, so a generator that quietly builds
     less fails here instead of passing on what is left.

`--measure` also synthesises each unit and its unmerged baseline to gates with
PyRTL and requires the merged one to be smaller -- the area the plan claims is
a model (`emit-hw-json` says `"calibrated": false`), and a model that ranks
two netlists the wrong way round is the thing worth catching.

`--plan FILE` builds the units a plan proposes instead of AXIS's own, and
holds them to exactly the same things. That is the acceptance test for
anything that proposes plans: it may be wrong about what is small, and this is
what stops it being wrong about what is computed.

Usage: tools/hw_units_check.py <input.axisl> [--cases N] [--expect-declined N]
                               [--plan FILE] [--measure] [--measure-limit AREA]

Requires `pyrtl`; exits with a SKIP notice without it.
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
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path, plan: Path | None = None) -> None:
    # A proposed plan reaches only the commands that build units; the golden
    # model is the description's and no plan touches it.
    extra = ["--hw-plan", str(plan.resolve())] if plan and command.startswith("emit-hw") else []
    subprocess.run([*axis_prefix(), command, str(axis_file), *extra, "-o", str(output)],
                   check=True, capture_output=True, cwd=AXIS_ROOT)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def mask(width: int) -> int:
    return (1 << max(width, 1)) - 1


def vectors_for(golden, name: str, cases: int, rng: random.Random) -> list[tuple[int, ...]]:
    params = golden.AXIS_SPECS[name]["params"]
    vectors = list(golden.sample_vectors(name, count=max(2, cases // 2)))
    while len(vectors) < cases:
        vectors.append(tuple(rng.getrandbits(max(width, 1)) for _, width in params))
    return vectors


def check_instructions(pyrtl, golden, rtl, cases: int, rng: random.Random) -> tuple[int, int, int]:
    """Each instruction's own netlist against the golden model."""
    built = compared = failures = 0
    for name, entry in rtl.INSTRUCTIONS.items():
        spec = golden.AXIS_SPECS[name]
        with pyrtl.temp_working_block():
            inputs = [pyrtl.Input(bitwidth=width, name=f"in{i}")
                      for i, (_, width) in enumerate(entry["inputs"])]
            out = pyrtl.Output(bitwidth=entry["output_width"], name="answer")
            out <<= getattr(rtl, entry["builder"])(*inputs)
            built += 1
            sim = pyrtl.Simulation()
            for vector in vectors_for(golden, name, cases, rng):
                sim.step({f"in{i}": value & mask(width)
                          for i, (value, (_, width)) in enumerate(zip(vector, entry["inputs"]))})
                got = sim.inspect("answer")
                want = golden.evaluate(name, *vector) & mask(spec["result_width"])
                compared += 1
                if got != want:
                    print(f"  FAIL {name}{vector}: the netlist says {got:#x}, "
                          f"the golden model {want:#x}")
                    failures += 1
                    break
    return built, compared, failures


def check_units(pyrtl, golden, rtl, cases: int, rng: random.Random) -> tuple[int, int]:
    """Each instruction, selected in its unit, with noise on every wire it
    does not read."""
    compared = failures = 0
    for unit_name, unit in rtl.UNITS.items():
        with pyrtl.temp_working_block():
            ports = {name: pyrtl.Input(bitwidth=width, name=f"p_{i}")
                     for i, (name, width) in enumerate(unit["inputs"])}
            port_name = {name: f"p_{i}" for i, (name, _) in enumerate(unit["inputs"])}
            widths = dict(unit["inputs"])
            args = [ports[name] for name, _ in unit["inputs"]]
            if unit["select_width"]:
                args.insert(0, pyrtl.Input(bitwidth=unit["select_width"], name="sel"))
            out = pyrtl.Output(bitwidth=unit["output_width"], name="answer")
            out <<= getattr(rtl, unit["builder"])(*args)
            sim = pyrtl.Simulation()
            for code, member in enumerate(unit["members"]):
                spec = golden.AXIS_SPECS[member]
                operands = rtl.INSTRUCTIONS[member]["inputs"]
                for vector in vectors_for(golden, member, cases, rng):
                    # Noise everywhere, then the operands laid over it: an
                    # operand narrower than its port keeps noise above it.
                    drive = {port_name[name]: rng.getrandbits(width)
                             for name, width in unit["inputs"]}
                    for (name, width), value in zip(operands, vector):
                        noise = drive[port_name[name]] & ~mask(width)
                        drive[port_name[name]] = (noise | (value & mask(width))) & mask(widths[name])
                    if unit["select_width"]:
                        drive["sel"] = code
                    sim.step(drive)
                    got = sim.inspect("answer")
                    want = golden.evaluate(member, *vector) & mask(spec["result_width"])
                    compared += 1
                    if got != want:
                        print(f"  FAIL {member}{vector} in unit {unit_name} (sel={code}): "
                              f"the unit says {got:#x}, the golden model {want:#x}")
                        failures += 1
                        break
    return compared, failures


def check_pipelines(pyrtl, golden, rtl, cases: int, rng: random.Random) -> tuple[int, int]:
    """Each unit in time: a different instruction issued EVERY cycle, idle
    cycles of noise among them, and each result required exactly as many cycles
    later as the description says the instruction takes.

    ⚠️ Back to back, because one instruction at a time would pass a unit whose
    stages leak into each other -- a register missing on one path reads the
    NEXT instruction's operand, and only a next instruction shows it.
    """
    compared = failures = 0
    for unit_name, unit in rtl.UNITS.items():
        registers = unit["latency"] - 1
        with pyrtl.temp_working_block():
            port_name = {name: f"p_{i}" for i, (name, _) in enumerate(unit["inputs"])}
            widths = dict(unit["inputs"])
            args = [pyrtl.Input(bitwidth=1, name="valid")]
            if unit["select_width"]:
                args.append(pyrtl.Input(bitwidth=unit["select_width"], name="sel"))
            args += [pyrtl.Input(bitwidth=width, name=port_name[name])
                     for name, width in unit["inputs"]]
            valid_out, result = getattr(rtl, unit["pipelined_builder"])(*args)
            out = pyrtl.Output(bitwidth=unit["output_width"], name="answer")
            out <<= result
            done = pyrtl.Output(bitwidth=1, name="done")
            done <<= valid_out
            issues = [(code, member, vector)
                      for code, member in enumerate(unit["members"])
                      for vector in vectors_for(golden, member, cases, rng)]
            rng.shuffle(issues)
            # An idle cycle in four, and enough at the end to drain the unit.
            stream = [issue for one in issues
                      for issue in ([one] if rng.random() < 0.75 else [None, one])]
            stream += [None] * (registers + 1)
            sim = pyrtl.Simulation()
            expected: list[int | None] = []
            for issue in stream:
                drive = {port_name[name]: rng.getrandbits(width)
                         for name, width in unit["inputs"]}
                drive["valid"] = 0
                if unit["select_width"]:
                    drive["sel"] = rng.getrandbits(unit["select_width"])
                want = None
                if issue is not None:
                    code, member, vector = issue
                    for (name, width), value in zip(rtl.INSTRUCTIONS[member]["inputs"], vector):
                        noise = drive[port_name[name]] & ~mask(width)
                        drive[port_name[name]] = (noise | (value & mask(width))) & mask(widths[name])
                    drive["valid"] = 1
                    if unit["select_width"]:
                        drive["sel"] = code
                    want = (golden.evaluate(member, *vector)
                            & mask(golden.AXIS_SPECS[member]["result_width"]))
                expected.append(want)
                sim.step(drive)
                if len(expected) <= registers:
                    continue
                due = expected[len(expected) - 1 - registers]
                compared += 1
                if sim.inspect("done") != (due is not None):
                    print(f"  FAIL unit {unit_name}: valid is not {registers} cycle(s) behind")
                    failures += 1
                    break
                if due is not None and sim.inspect("answer") != due:
                    print(f"  FAIL unit {unit_name}: {registers} cycle(s) after an issue the "
                          f"result is {sim.inspect('answer'):#x}, the golden model says {due:#x}")
                    failures += 1
                    break
    return compared, failures


def gate_count(pyrtl, build) -> int:
    """Gates after PyRTL's own synthesis and optimisation of what `build`
    wires up."""
    with pyrtl.temp_working_block():
        build()
        pyrtl.synthesize()
        pyrtl.optimize()
        return sum(1 for net in pyrtl.working_block().logic if net.op in "&|^~n")


def measure_units(pyrtl, rtl, plan: dict, limit: float) -> int:
    """The merged unit against its members side by side under one result mux,
    both synthesised. Returns how many units came out larger merged."""
    failures = 0
    for unit_plan in plan["units"]:
        name = unit_plan["name"]
        unit = rtl.UNITS[name]
        area = unit_plan["area"]
        if len(unit["members"]) < 2:
            continue
        if area["identical_shared"] > limit:
            print(f"  unit {name}: not measured (model area "
                  f"{area['identical_shared']:.0f} is over --measure-limit)")
            continue

        def wire(merged: bool, unit=unit):
            ports = {pname: pyrtl.Input(bitwidth=width, name=f"p_{i}")
                     for i, (pname, width) in enumerate(unit["inputs"])}
            sel = pyrtl.Input(bitwidth=unit["select_width"], name="sel")
            out = pyrtl.Output(bitwidth=unit["output_width"], name="answer")
            if merged:
                out <<= getattr(rtl, unit["builder"])(sel, *[ports[n] for n, _ in unit["inputs"]])
                return
            result = pyrtl.Const(0, bitwidth=unit["output_width"])
            for code, member in enumerate(unit["members"]):
                entry = rtl.INSTRUCTIONS[member]
                value = getattr(rtl, entry["builder"])(*[ports[n] for n, _ in entry["inputs"]])
                result = pyrtl.select(sel == code, value.zero_extended(unit["output_width"]), result)
            out <<= result

        apart = gate_count(pyrtl, lambda: wire(False))
        merged = gate_count(pyrtl, lambda: wire(True))
        verdict = "smaller" if merged < apart else "NOT SMALLER"
        print(f"  unit {name}: {merged} gates merged, {apart} apart ({verdict}); "
              f"the model said {area['merged']:.0f} against {area['identical_shared']:.0f}")
        if merged >= apart and area["merged"] < area["identical_shared"]:
            failures += 1
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=16)
    parser.add_argument("--seed", type=int, default=20261004)
    parser.add_argument("--expect-declined", type=int, default=None,
                        help="exactly this many instructions may have no circuit")
    parser.add_argument("--plan", type=Path, default=None,
                        help="build the units of this plan (--hw-plan) instead of AXIS's own")
    parser.add_argument("--measure", action="store_true",
                        help="synthesise each unit and require merging to have paid")
    parser.add_argument("--measure-limit", type=float, default=15000.0,
                        help="skip measuring units whose model area is above this")
    args = parser.parse_args()
    try:
        import pyrtl
    except Exception:  # noqa: BLE001
        print("pyrtl is not installed: SKIP")
        return DECLINED
    rng = random.Random(args.seed)
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        emit(args.axis_file, "emit-golden-python", work / "golden_model.py")
        emit(args.axis_file, "emit-hw-pyrtl", work / "axis_hw.py", args.plan)
        emit(args.axis_file, "emit-hw-json", work / "axis_hw.json", args.plan)
        golden = load(work / "golden_model.py", "golden_model")
        rtl = load(work / "axis_hw.py", "axis_hw")
        plan = json.loads((work / "axis_hw.json").read_text())

        # The account. Every instruction the golden model evaluates is built
        # or declined by name, with the interface the golden model has.
        for name, spec in golden.AXIS_SPECS.items():
            if spec.get("kind", "instruction") != "instruction":
                continue
            if (name in rtl.INSTRUCTIONS) == (name in rtl.DECLINED):
                print(f"  FAIL {name}: neither built nor declined, or both")
                failures += 1
                continue
            entry = rtl.INSTRUCTIONS.get(name)
            if entry and (list(map(tuple, entry["inputs"])) != list(map(tuple, spec["params"]))
                          or entry["output_width"] != spec["result_width"]):
                print(f"  FAIL {name}: the netlist's interface is not the golden model's")
                failures += 1
        housed: dict[str, int] = {}
        for unit in rtl.UNITS.values():
            for member in unit["members"]:
                housed[member] = housed.get(member, 0) + 1
        for name in rtl.INSTRUCTIONS:
            if housed.get(name, 0) != 1:
                print(f"  FAIL {name}: in {housed.get(name, 0)} units, not one")
                failures += 1
        if {u["name"] for u in plan["units"]} != set(rtl.UNITS):
            print("  FAIL the plan and the netlist name different units")
            failures += 1

        reasons: dict[str, int] = {}
        for reason in rtl.DECLINED.values():
            reasons[reason] = reasons.get(reason, 0) + 1
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1])[:6]:
            print(f"  {count} instruction(s) have no circuit -- {reason}")
        if args.expect_declined is not None and len(rtl.DECLINED) != args.expect_declined:
            print(f"  FAIL {len(rtl.DECLINED)} instruction(s) declined, and this corpus "
                  f"is expected to have {args.expect_declined}")
            failures += 1

        # ⚠️ A run that built nothing proves nothing, and says so.
        if not rtl.INSTRUCTIONS:
            print("no instruction has a circuit: SKIP")
            return FAILED if failures else DECLINED

        built, compared, wrong = check_instructions(pyrtl, golden, rtl, args.cases, rng)
        failures += wrong
        print(f"{built} netlist(s) built, {compared} vector(s) simulated, {wrong} disagreeing")
        unit_compared, wrong = check_units(pyrtl, golden, rtl, args.cases, rng)
        failures += wrong
        shape = ", ".join(f"{name} ({len(unit['members'])})" for name, unit in rtl.UNITS.items())
        print(f"{len(rtl.UNITS)} unit(s) [{shape}], {unit_compared} vector(s) simulated, "
              f"{wrong} disagreeing")
        piped, wrong = check_pipelines(pyrtl, golden, rtl, args.cases, rng)
        failures += wrong
        timing = ", ".join(f"{name} {unit['latency']}" for name, unit in rtl.UNITS.items())
        print(f"pipelined at the declared latency [{timing}], a new instruction every cycle: "
              f"{piped} cycle(s) checked, {wrong} disagreeing")
        for unit in plan["units"]:
            area, depth = unit["area"], unit["depth"]
            if len(unit["members"]) > 1:
                print(f"  unit {unit['name']}: model area {area['merged']:.0f} merged, "
                      f"{area['identical_shared']:.0f} unmerged, {area['separate']:.0f} apart; "
                      f"depth {depth['merged']:.0f} against {depth['slowest_member']:.0f}")
            timing = unit["timing"]
            if timing["cycles_at_budget"] > timing["latency"]:
                # Not a failure of the hardware: the description promises a
                # latency the datapath cannot keep at the cycle its ALU implies.
                print(f"  unit {unit['name']}: declared {timing['latency']} cycle(s), and its "
                      f"stages are {timing['stage_delay']:.0f} gates deep -- at the "
                      f"{plan['cost_model']['cycle_budget']:.0f}-gate cycle it needs "
                      f"{timing['cycles_at_budget']}")
        if args.measure:
            failures += measure_units(pyrtl, rtl, plan, args.measure_limit)
    print("netlists and units == golden model:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
