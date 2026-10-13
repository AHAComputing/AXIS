#!/usr/bin/env python3
"""The netlists of instructions stated as EFFECTS do what the golden model
says. Gate.

A branch, a jump, a load and a store have no single value. `emit-hw-pyrtl`
gives each a builder returning one wire per thing it does: the value of every
effect, the guard that says whether it happens, the address of a store, and --
for a load -- the address it reads, with what was read coming back in as an
input.

Each of those is held to the golden model's own evaluator, on the expressions
`emit-lift-json` publishes for the effect:

  * every effect's **value** and **guard**;
  * a store's **address**;
  * a load's **address** -- the one the golden model asks its memory for -- and
    then the value, with exactly what that memory returned driven in.

⚠️ Effects happen IN ORDER. A pre-indexed store is `rn = rn + imm; Mem[rn] =
rt`, and the address is the updated base: the executors evaluate effects one
after another against a register file they have already written. So the
reference here is evaluated the same way -- after each register or state
write, later effects read the new value. The first version of this gate
evaluated every effect against the registers as they stood before the
instruction, the netlists were lowered the same way, and the two agreed with
each other and disagreed with the executor on every writeback form.

⚠️ Memory here is a function of the address, different at every address and
width. A netlist that read the wrong address, or the right one at the wrong
width, gets different data and a different value; a memory of zeros would
have agreed with anything.

Usage: tools/hw_effects_check.py <input.axisl> [--cases N] [--expect-built N]

Requires `pyrtl`; exits with a SKIP notice without it.
"""

from __future__ import annotations

import argparse
import hashlib
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


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(output)],
                   check=True, capture_output=True, cwd=AXIS_ROOT)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def mask(width: int) -> int:
    return (1 << max(width, 1)) - 1


def memory(addr: int, width_bits: int) -> int:
    """What memory holds: a different value at every address and width."""
    digest = hashlib.sha256(f"{addr}:{width_bits}".encode()).digest()
    return int.from_bytes(digest[:16], "little") & mask(width_bits)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=24)
    parser.add_argument("--seed", type=int, default=20261005)
    parser.add_argument("--expect-built", type=int, default=None,
                        help="exactly this many effect instructions have a netlist")
    args = parser.parse_args()
    try:
        import pyrtl
    except Exception:  # noqa: BLE001
        print("pyrtl is not installed: SKIP")
        return DECLINED
    rng = random.Random(args.seed)
    failures = compared = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        emit(args.axis_file, "emit-golden-python", work / "golden_model.py")
        emit(args.axis_file, "emit-hw-pyrtl", work / "axis_hw.py")
        emit(args.axis_file, "emit-lift-json", work / "lift.json")
        golden = load_module(work / "golden_model.py", "golden_model")
        rtl = load_module(work / "axis_hw.py", "axis_hw")
        lifted = {one["mnemonic"]: one
                  for one in json.loads((work / "lift.json").read_text())["instructions"]}

        reasons: dict[str, int] = {}
        for reason in rtl.EFFECTS_DECLINED.values():
            reasons[reason] = reasons.get(reason, 0) + 1
        for reason, count in sorted(reasons.items(), key=lambda kv: -kv[1])[:6]:
            print(f"  {count} effect instruction(s) have no circuit -- {reason}")
        if args.expect_built is not None and len(rtl.EFFECTS) != args.expect_built:
            print(f"  FAIL {len(rtl.EFFECTS)} effect instruction(s) built, and this corpus is "
                  f"expected to have {args.expect_built}")
            failures += 1
        if not rtl.EFFECTS:
            print("no effect instruction has a circuit: SKIP")
            return FAILED if failures else DECLINED

        for mnemonic, entry in rtl.EFFECTS.items():
            published = lifted[mnemonic]["effects"] or []
            kinds = [one["kind"] for one in published]
            if kinds != [one["kind"] for one in entry["effects"]]:
                print(f"  FAIL {mnemonic}: the netlist's effects are not the ones published")
                failures += 1
                continue
            with pyrtl.temp_working_block():
                inputs = [pyrtl.Input(bitwidth=width, name=f"in{i}")
                          for i, (_, width) in enumerate(entry["inputs"])]
                wires = list(inputs)
                if entry["load"]:
                    wires.append(pyrtl.Input(bitwidth=entry["load"]["width"], name="load"))
                built = getattr(rtl, entry["builder"])(*wires)
                probes: dict[str, int] = {}

                def probe(name: str, wire) -> None:
                    if wire is not None:
                        out = pyrtl.Output(bitwidth=len(wire), name=name)
                        out <<= wire
                        probes[name] = len(wire)

                probe("load_addr", built["load_addr"])
                for index, effect in enumerate(built["effects"]):
                    for part in ("value", "guard", "addr"):
                        probe(f"{part}{index}", effect[part])
                sim = pyrtl.Simulation()
                for _ in range(args.cases):
                    env = {name: rng.getrandbits(width) for name, width in entry["inputs"]}
                    asked: list[tuple[int, int]] = []

                    def reader(addr: int, width_bits: int) -> int:
                        asked.append((addr, width_bits))
                        return memory(addr, width_bits)

                    golden_env = {**env, "__mem__": reader}
                    want: dict[str, int] = {}
                    for index, effect in enumerate(published):
                        happens = True
                        if effect.get("guard"):
                            happens = golden._eval_axis_expr(
                                effect["guard"], golden_env, effect["guard_width"]) != 0
                            want[f"guard{index}"] = int(happens)
                        if effect["kind"] == "store":
                            want[f"addr{index}"] = golden._eval_axis_expr(
                                effect["addr"], golden_env, effect["addr_width"])
                        want[f"value{index}"] = golden._eval_axis_expr(
                            effect["value"], golden_env, effect["eval_width"],
                            effect.get("load_address_width"))
                        # What this effect wrote is what the next one reads.
                        written = effect.get("dest") if effect["kind"] == "set" else (
                            effect.get("state") if effect["kind"] == "setstate" else None)
                        if written is not None and happens:
                            golden_env[written] = want[f"value{index}"] & mask(effect["width"])
                    drive = {f"in{i}": env[name] for i, (name, _) in enumerate(entry["inputs"])}
                    if entry["load"]:
                        # The address first, with nothing known about the data;
                        # then the data the golden model's memory gave back.
                        sim.step({**drive, "load": 0})
                        want["load_addr"] = asked[0][0] if asked else None
                        if not asked or asked[0][1] != entry["load"]["width"]:
                            print(f"  FAIL {mnemonic}: the golden model reads {asked}, the "
                                  f"netlist {entry['load']['width']} bits")
                            failures += 1
                            break
                        drive["load"] = memory(*asked[0])
                    sim.step(drive)
                    compared += 1
                    wrong = [name for name in probes
                             if sim.inspect(name) != want[name] & mask(probes[name])]
                    if wrong:
                        name = wrong[0]
                        print(f"  FAIL {mnemonic} {env}: `{name}` is {sim.inspect(name):#x}, "
                              f"the golden model says {want[name] & mask(probes[name]):#x}")
                        failures += 1
                        break
    kinds: dict[str, int] = {}
    for entry in rtl.EFFECTS.values():
        for effect in entry["effects"]:
            kinds[effect["kind"]] = kinds.get(effect["kind"], 0) + 1
    shape = ", ".join(f"{count} {kind}" for kind, count in sorted(kinds.items()))
    print(f"{len(rtl.EFFECTS)} effect netlist(s) built [{shape}], {compared} vector(s) simulated, "
          f"{failures} disagreeing")
    print("effect netlists == golden model:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
