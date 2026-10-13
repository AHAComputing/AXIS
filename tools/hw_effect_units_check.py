#!/usr/bin/env python3
"""A unit with effects in it computes what each member does. Gate.

`emit-hw-effect-pyrtl` builds functional units whose members may be values or
instructions stated as effects -- a branch, a load, a store, a write to a
flag word -- each output a SLOT: `w0` for the first register written, `pc`,
`st0_addr`, `ld_addr`, `s_<state>`, and `<slot>_en` saying whether it is
written. The merger shares operators across members and across slots, so a
unit is a different circuit from its members side by side.

For every unit and every member, selected, on random inputs with noise on the
ports the member does not read and above the bits it reads, this compares
each slot the member drives with the member's OWN netlist (`build_unit`'s
inputs: `INSTRUCTIONS` and `EFFECTS` from `emit-hw-pyrtl`, which
`hw_units_check.py` and `hw_effects_check.py` hold to the golden model), and
requires every slot it does not drive to say so: its enable is 0. A slot it
drives with no guard has its enable at 1.

Then each unit's pipelined builder, fed a new instruction every cycle with
some cycles empty: every slot must leave `latency - 1` cycles later with what
the combinational unit gave for those inputs, and its valid bit with the one
that went in.

Usage: tools/hw_effect_units_check.py <input.axisl> [--cases N] [--seed S]
"""
from __future__ import annotations

import argparse
import importlib.util
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
LOAD = "%load"


def emit(axis_file: Path, command: str, out: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   check=True, capture_output=True, cwd=AXIS_ROOT)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=24)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()
    try:
        import pyrtl
    except ImportError:
        print("SKIP: pyrtl is not installed")
        return DECLINED

    work = Path(tempfile.mkdtemp(prefix="axis_effunits_"))
    emit(args.axis_file, "emit-hw-pyrtl", work / "hw.py")
    emit(args.axis_file, "emit-hw-effect-pyrtl", work / "units.py")
    own = load(work / "hw.py", f"axis_hw_{args.axis_file.stem}")
    units = load(work / "units.py", f"axis_effunits_{args.axis_file.stem}")
    rng = random.Random(args.seed)

    failures = compared = members = pipelined = 0
    effect_members = 0
    for name, unit in units.EFFECT_UNITS.items():
        slot_width = dict(unit["slots"])
        with pyrtl.temp_working_block():
            ports = {port: pyrtl.Input(bitwidth=width, name=f"p_{i}")
                     for i, (port, width) in enumerate(unit["inputs"])}
            sel = pyrtl.Input(bitwidth=max(unit["select_width"], 1), name="sel")
            args_ = [ports[port] for port, _ in unit["inputs"]]
            if unit["select_width"]:
                args_.insert(0, sel)
            built = getattr(units, unit["builder"])(*args_)
            for slot, wire in built.items():
                out = pyrtl.Output(bitwidth=slot_width[slot], name=f"u_{slot}")
                out <<= wire
            # Each member's own netlist, on the same ports.
            expect = {}
            for code, (mnemonic, kind, drives) in enumerate(unit["members"]):
                if kind == "value":
                    entry = own.INSTRUCTIONS[mnemonic]
                    result = getattr(own, entry["builder"])(
                        *[ports[port][:width] for port, width in entry["inputs"]])
                    wires = {"result": result}
                else:
                    entry = own.EFFECTS[mnemonic]
                    call = [ports[port][:width] for port, width in entry["inputs"]]
                    if entry["load"]:
                        call.append(ports[LOAD][:entry["load"]["width"]])
                    made = getattr(own, entry["builder"])(*call)
                    wires = {"load_addr": made["load_addr"], "effects": made["effects"]}
                for slot, source, index in drives:
                    if source == "result":
                        wire = wires["result"]
                    elif source == "load_addr":
                        wire = wires["load_addr"]
                    else:
                        wire = wires["effects"][index][source]
                    label = f"m{code}_{slot}"
                    o = pyrtl.Output(bitwidth=len(wire), name=label)
                    o <<= wire
                    expect[(code, slot)] = label
            sim = pyrtl.Simulation()
            for case in range(args.cases):
                for code, (mnemonic, kind, drives) in enumerate(unit["members"]):
                    values = {f"p_{i}": rng.getrandbits(width) for i, (_, width) in enumerate(unit["inputs"])}
                    values["sel"] = code if unit["select_width"] else 0
                    sim.step(values)
                    driven = {slot for slot, _, _ in drives}
                    guarded = {slot[:-3] for slot, _, _ in drives if slot.endswith("_en")}
                    for slot, width in unit["slots"]:
                        got = sim.inspect(f"u_{slot}")
                        if (code, slot) in expect:
                            want = sim.inspect(expect[(code, slot)])
                            ok = got == want & ((1 << width) - 1)
                            what = f"{slot} = {got:#x}, its own netlist {want:#x}"
                        elif slot.endswith("_en"):
                            base = slot[:-3]
                            want = 1 if base in driven and base not in guarded else 0
                            ok = got == want
                            what = f"{slot} = {got}, and it {'writes' if want else 'does not write'} {base}"
                        else:
                            continue    # a value nobody reads: its enable says so
                        compared += 1
                        if not ok:
                            failures += 1
                            if failures <= 8:
                                print(f"  FAIL {name}: {mnemonic} -> {what}")
        members += len(unit["members"])
        effect_members += sum(1 for _, kind, _ in unit["members"] if kind == "effect")

        # The unit in time: a new instruction every cycle, some cycles
        # empty, and every slot leaving `latency - 1` cycles later with what
        # the combinational unit gives for those inputs -- which the loop
        # above held to the members.
        lag = unit["latency"] - 1
        with pyrtl.temp_working_block():
            ports = {port: pyrtl.Input(bitwidth=width, name=f"p_{i}")
                     for i, (port, width) in enumerate(unit["inputs"])}
            sel = pyrtl.Input(bitwidth=max(unit["select_width"], 1), name="sel")
            valid = pyrtl.Input(bitwidth=1, name="valid")
            args_ = [ports[port] for port, _ in unit["inputs"]]
            if unit["select_width"]:
                args_.insert(0, sel)
            now = getattr(units, unit["builder"])(*args_)
            done, later = getattr(units, unit["pipelined_builder"])(valid, *args_)
            for slot, width in unit["slots"]:
                for prefix, wire in (("c", now[slot]), ("q", later[slot])):
                    o = pyrtl.Output(bitwidth=width, name=f"{prefix}_{slot}")
                    o <<= wire
            o = pyrtl.Output(bitwidth=1, name="done")
            o <<= done
            sim = pyrtl.Simulation()
            history = []
            for step in range(args.cases * len(unit["members"]) + lag):
                code = rng.randrange(len(unit["members"]))
                values = {f"p_{i}": rng.getrandbits(width) for i, (_, width) in enumerate(unit["inputs"])}
                values["sel"] = code if unit["select_width"] else 0
                values["valid"] = 0 if rng.random() < 0.2 else 1
                sim.step(values)
                history.append((values["valid"], {slot: sim.inspect(f"c_{slot}") for slot, _ in unit["slots"]}))
                if step < lag:
                    continue
                was_valid, was = history[step - lag]
                compared += 1
                if sim.inspect("done") != was_valid:
                    failures += 1
                    print(f"  FAIL {name} pipelined: valid {sim.inspect('done')} {lag} cycle(s) "
                          f"after {was_valid}")
                    continue
                if not was_valid:
                    continue
                for slot, _ in unit["slots"]:
                    compared += 1
                    if sim.inspect(f"q_{slot}") != was[slot]:
                        failures += 1
                        if failures <= 8:
                            print(f"  FAIL {name} pipelined: {slot} = {sim.inspect(f'q_{slot}'):#x}, "
                                  f"{lag} cycle(s) after the unit gave {was[slot]:#x}")
        pipelined += 1
    print(f"  {len(units.EFFECT_UNITS)} unit(s), {pipelined} pipelined, {members} member(s) of "
          f"which {effect_members} stated as effects, {compared} slot comparisons, "
          f"{failures} failure(s)")
    ok = failures == 0 and effect_members > 0
    print("units with effects == their members: " + ("PASS" if ok else "FAIL"))
    return PASSED if ok else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
