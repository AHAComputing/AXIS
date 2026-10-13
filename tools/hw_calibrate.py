#!/usr/bin/env python3
"""Hold AXIS's hardware cost model to synthesis.

`emit-hw-json` prices every instruction's netlist and every functional unit:
an area in NAND2 equivalents, a depth in gate delays. Unit grouping, operator
sharing and anything that searches over plans read those numbers, so they have
to be an area and a delay, not only an order.

This synthesises the same circuits -- the PyRTL `emit-hw-pyrtl` ships, through
Yosys and ABC to a standard-cell library (`tools/hw_synth.py`) -- and compares,
at three levels:

  1. **operators**, alone, at 8, 16, 32 and 64 bits. These are what the model's
     constants were fitted on, so this level says the constants in the binary
     are still the fit. The model's side is `cost_model.operators` in the
     JSON: the shipped model, not a copy of its formulas.
  2. **instructions**: each built netlist. Not fitted on; this is where
     composition shows -- an instruction is several operators, the model adds
     them up, and synthesis does not.
  3. **units**: each merged unit, and its members side by side under one
     result mux. Besides the numbers, the ORDER: where the model says merging
     is smaller, synthesis has to agree, because that order is what the
     merger decides on.

A ratio is model over measured. Each level is held to a band on the typical
ratio (the geometric mean) and on the worst one, over circuits large enough
for a ratio to mean something. The bands are what the model achieves today,
with headroom for ABC's run-to-run noise, so the gate fails when the model
drifts from the netlists and not when it is merely imperfect.

Usage: tools/hw_calibrate.py [input.axisl ...] [--limit AREA] [--no-operators]
                             [--fetch] [--table]

Requires `pyrtl`, `yosys` and the reference library; exits with a SKIP notice
without them (`--fetch` downloads the library once).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402
from hw_synth import Synth  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_INPUTS = ["examples/rv32i.axisl", "examples/zbb_like.axisl", "examples/rv64i.axisl"]

# A ratio is only asked of a circuit at least this large and this deep. Below
# it a row of XORs is one cell library choice away from 30% off, and a path of
# two gates is mostly the output's load.
MIN_AREA = 150.0
MIN_DELAY_PS = 800.0

# A saving the model claims below this share of a unit's area is one it cannot
# tell from none: it prices a unit's members apart about this much too high,
# because synthesis shares between operators the model prices one at a time.
# The merger has a margin of its own (`SHARING_MARGIN`, per class of operator,
# fitted on what this gate measured), so a unit that reaches here merged and
# comes out larger synthesised is that margin having been set too low.
MARGIN = 0.15

# (typical, worst): the geometric-mean ratio must be within `typical` of 1 and
# every ratio within `worst`, as factors.
BANDS = {
    "operators": {"area": (1.10, 1.35), "delay": (1.10, 1.45)},
    "instructions": {"area": (1.20, 1.60), "delay": (1.25, 1.80)},
    # A unit is where the model is furthest out, and always on the high side:
    # it is mostly muxes, and synthesis folds a mux into the logic either side
    # of it in ways a price per node cannot follow.
    "units": {"area": (1.45, 1.60), "delay": (1.30, 1.80)},
}


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(output)],
                   check=True, capture_output=True, cwd=AXIS_ROOT)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def operator_builders(pyrtl, rtl) -> dict:
    """Each operator of `cost_model.operators`, built alone from the prelude
    the emitted netlists are made of."""
    I, C = pyrtl.Input, pyrtl.Const

    def out(value):
        value = pyrtl.as_wires(value)
        wire = pyrtl.Output(len(value), "o")
        wire <<= value

    def bits(n):
        return n.bit_length() - 1

    return {
        "not": lambda n: out(~I(n, "a")),
        "and": lambda n: out(I(n, "a") & I(n, "b")),
        "xor": lambda n: out(I(n, "a") ^ I(n, "b")),
        "mux": lambda n: out(pyrtl.select(I(1, "s"), I(n, "a"), I(n, "b"))),
        "eq": lambda n: out(I(n, "a") == I(n, "b")),
        "eq_const": lambda n: out(I(n, "a") == C(0, n)),
        "add": lambda n: out(rtl._addsub(I(n, "a"), I(n, "b"), C(0, 1), n)),
        "sub": lambda n: out(rtl._addsub(I(n, "a"), I(n, "b"), C(1, 1), n)),
        "addsub": lambda n: out(rtl._addsub(I(n, "a"), I(n, "b"), I(1, "s"), n)),
        "mul": lambda n: out(rtl._mul(I(n, "a"), I(n, "b"), n)),
        "mulwide": lambda n: out(rtl._mulwide(I(n, "a"), I(n, "b"), I(1, "sa"), I(1, "sb"), n)),
        "mulwide_unsigned": lambda n: out(rtl._mulwide(I(n, "a"), I(n, "b"), C(0, 1), C(0, 1), n)),
        "divrem": lambda n: out(rtl._divrem(I(n, "a"), I(n, "b"), I(1, "s"), n)),
        "divrem_unsigned": lambda n: out(rtl._divrem(I(n, "a"), I(n, "b"), C(0, 1), n)),
        "shift": lambda n: out(rtl._shr(I(n, "a"), I(bits(n), "m"), I(1, "f"), n)),
        "shift_short": lambda n: out(rtl._shr(I(n, "a"), I(bits(n) - 2, "m"), I(1, "f"), n)),
        "shift_over": lambda n: out(rtl._shr(I(n, "a"), I(bits(n) + 2, "m"), I(1, "f"), n)),
        "rotate": lambda n: out(rtl._ror(I(n, "a"), I(bits(n), "m"), n)),
        "clz": lambda n: out(rtl._clz(I(n, "a"), n, bits(n) + 1)),
        "cpop": lambda n: out(rtl._cpop(I(n, "a"), n, bits(n) + 1)),
    }


class Level:
    """One level's rows, and what its ratios come to."""

    def __init__(self, name: str, ps_per_gate: float):
        self.name = name
        self.ps_per_gate = ps_per_gate
        self.rows: list[tuple[str, float, float, float, float]] = []
        self.skipped: list[str] = []

    def add(self, label: str, model: tuple[float, float], measured: tuple[float, float]) -> None:
        self.rows.append((label, model[0], measured[0], model[1] * self.ps_per_gate, measured[1]))

    def ratios(self, what: str) -> list[tuple[str, float]]:
        found = []
        for label, model_area, area, model_ps, ps in self.rows:
            if what == "area" and area >= MIN_AREA and model_area > 0:
                found.append((label, model_area / area))
            if what == "delay" and ps >= MIN_DELAY_PS and model_ps > 0:
                found.append((label, model_ps / ps))
        return found

    def table(self) -> None:
        print(f"  {'':28s} {'model':>9s} {'synth':>9s} {'ratio':>6s}   "
              f"{'model ps':>9s} {'synth ps':>9s} {'ratio':>6s}")
        for label, model_area, area, model_ps, ps in self.rows:
            area_ratio = f"{model_area / area:6.2f}" if area else "     -"
            delay_ratio = f"{model_ps / ps:6.2f}" if ps else "     -"
            print(f"  {label:28s} {model_area:9.0f} {area:9.0f} {area_ratio}   "
                  f"{model_ps:9.0f} {ps:9.0f} {delay_ratio}")

    def verdict(self) -> list[str]:
        """Print the summary; return what is out of band."""
        failures = []
        for what in ("area", "delay"):
            ratios = self.ratios(what)
            if not ratios:
                continue
            typical_band, worst_band = BANDS[self.name][what]
            typical = math.exp(sum(math.log(r) for _, r in ratios) / len(ratios))
            low = min(ratios, key=lambda item: item[1])
            high = max(ratios, key=lambda item: item[1])
            print(f"  {self.name} {what}: {len(ratios)} compared, typical ratio {typical:.2f}, "
                  f"from {low[1]:.2f} ({low[0]}) to {high[1]:.2f} ({high[0]})")
            if not 1 / typical_band <= typical <= typical_band:
                failures.append(f"{self.name} {what}: typical ratio {typical:.2f} is outside "
                                f"a factor of {typical_band}")
            for label, ratio in (low, high):
                if not 1 / worst_band <= ratio <= worst_band:
                    failures.append(f"{self.name} {what}: {label} is off by {ratio:.2f}, "
                                    f"outside a factor of {worst_band}")
        return failures


def wire_instruction(pyrtl, rtl, entry) -> None:
    inputs = [pyrtl.Input(bitwidth=width, name=f"in{i}")
              for i, (_, width) in enumerate(entry["inputs"])]
    out = pyrtl.Output(bitwidth=entry["output_width"], name="answer")
    out <<= getattr(rtl, entry["builder"])(*inputs)


def wire_unit(pyrtl, rtl, unit, merged: bool) -> None:
    """The unit as merged, or its members' own circuits under one result mux:
    the two things the merger chooses between."""
    ports = {name: pyrtl.Input(bitwidth=width, name=f"p_{i}")
             for i, (name, width) in enumerate(unit["inputs"])}
    sel = pyrtl.Input(bitwidth=max(unit["select_width"], 1), name="sel")
    out = pyrtl.Output(bitwidth=unit["output_width"], name="answer")
    if merged:
        args = [ports[name] for name, _ in unit["inputs"]]
        if unit["select_width"]:
            args.insert(0, sel)
        out <<= getattr(rtl, unit["builder"])(*args)
        return
    values = []
    for code, member in enumerate(unit["members"]):
        entry = rtl.INSTRUCTIONS[member]
        value = getattr(rtl, entry["builder"])(*[ports[name][:width] for name, width in entry["inputs"]])
        values.append((value.zero_extended(unit["output_width"]), code))

    # The result mux the merger builds (`Merger::choose`): a balanced tree,
    # each level steered by whether a member of its left half is running. The
    # baseline has to be muxed the way the unit is, or the comparison is of
    # two mux styles and not of merging: a priority chain of the same inputs
    # is a third smaller and twice as slow.
    def choose(group):
        if len(group) == 1:
            return group[0][0]
        left, right = group[:len(group) // 2], group[len(group) // 2:]
        steer = None
        for _, code in left:
            running = sel == code
            steer = running if steer is None else steer | running
        return pyrtl.select(steer, choose(left), choose(right))

    out <<= choose(values)


def calibrate(pyrtl, synth: Synth, axis_file: Path, args, first: bool) -> list[str]:
    failures: list[str] = []
    with tempfile.TemporaryDirectory(prefix="axis_calibrate_") as tmp:
        work = Path(tmp)
        emit(axis_file, "emit-hw-pyrtl", work / "hw.py")
        emit(axis_file, "emit-hw-json", work / "hw.json")
        plan = json.loads((work / "hw.json").read_text())
        rtl = load(work / "hw.py", f"axis_hw_{axis_file.stem}")
    cost = plan["cost_model"]
    if not cost.get("calibrated"):
        return [f"{axis_file.name}: the cost model does not claim to be calibrated"]
    ps_per_gate = cost["ps_per_gate"]
    levels = []

    # The operators are the model's, not the corpus's: once is enough.
    if first and not args.no_operators:
        level = Level("operators", ps_per_gate)
        builders = operator_builders(pyrtl, rtl)
        for row in cost["operators"]:
            label = f"{row['operator']}/{row['width']}"
            if row["area"] > args.limit:
                level.skipped.append(label)
                continue
            build = builders[row["operator"]]
            level.add(label, (row["area"], row["delay"]),
                      synth.measure(pyrtl, lambda: build(row["width"])))
        levels.append(level)

    level = Level("instructions", ps_per_gate)
    for entry in plan["instructions"]:
        if entry["status"] != "built":
            continue
        if entry["area"] > args.limit:
            level.skipped.append(entry["mnemonic"])
            continue
        built = rtl.INSTRUCTIONS[entry["mnemonic"]]
        level.add(entry["mnemonic"], (entry["area"], entry["depth"]),
                  synth.measure(pyrtl, lambda: wire_instruction(pyrtl, rtl, built)))
    levels.append(level)

    level = Level("units", ps_per_gate)
    for unit_plan in plan["units"]:
        name, area = unit_plan["name"], unit_plan["area"]
        unit = rtl.UNITS[name]
        if area["merged"] > args.limit:
            level.skipped.append(name)
            continue
        merged = synth.measure(pyrtl, lambda: wire_unit(pyrtl, rtl, unit, True))
        level.add(name, (area["merged"], unit_plan["depth"]["merged"]), merged)
        if len(unit["members"]) < 2 or area["identical_shared"] > args.limit:
            continue
        apart = synth.measure(pyrtl, lambda: wire_unit(pyrtl, rtl, unit, False))
        claimed = 1 - area["merged"] / area["identical_shared"]
        found = 1 - merged[0] / apart[0]
        print(f"  unit {name}: merging saves {found:+.0%} synthesised "
              f"({merged[0]:.0f} against {apart[0]:.0f}); the model said {claimed:+.0%} "
              f"({area['merged']:.0f} against {area['identical_shared']:.0f})")
        # The order is what the merger acts on, and the model is only owed
        # agreement where it claims more than it is known to be wrong by: a
        # saving inside MARGIN is one it cannot tell from none.
        if claimed > MARGIN and found <= 0:
            failures.append(f"unit {name}: the model says merging saves {claimed:.0%} and "
                            f"synthesis says it costs {-found:.0%}")
        elif found < -0.01:
            print(f"    ⚠️ merged anyway: the model's {claimed:.0%} is inside its own error "
                  f"and synthesis says merging costs {-found:.0%}")
    levels.append(level)

    for level in levels:
        if args.table:
            level.table()
        failures += level.verdict()
        if level.skipped:
            print(f"  {level.name}: {len(level.skipped)} over --limit and not synthesised "
                  f"({', '.join(level.skipped[:6])}{', ...' if len(level.skipped) > 6 else ''})")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("inputs", nargs="*", type=Path)
    parser.add_argument("--limit", type=float, default=15000.0,
                        help="do not synthesise anything the model prices above this "
                             "(a 64-bit unrolled divider takes ABC most of an hour)")
    parser.add_argument("--no-operators", action="store_true")
    parser.add_argument("--fetch", action="store_true",
                        help="download the reference library if it is not cached")
    parser.add_argument("--table", action="store_true", help="print every row")
    args = parser.parse_args()

    try:
        import pyrtl
    except ImportError:
        print("SKIP hardware cost calibration: pyrtl is not installed")
        return 0
    try:
        synth = Synth.find(fetch=args.fetch)
    except Exception as error:  # a failed download is a skip with its reason
        print(f"SKIP hardware cost calibration: {error}")
        return 0
    if synth is None:
        print("SKIP hardware cost calibration: needs yosys and the reference cell library "
              "(tools/hw_calibrate.py --fetch gets the library)")
        return 0

    inputs = args.inputs or [AXIS_ROOT / name for name in DEFAULT_INPUTS]
    failures: list[str] = []
    for index, axis_file in enumerate(inputs):
        print(f"{axis_file.name}:")
        failures += [f"{axis_file.name}: {failure}"
                     for failure in calibrate(pyrtl, synth, axis_file.resolve(), args, index == 0)]
    if failures:
        for failure in failures:
            print(f"FAIL {failure}")
        return 1
    print(f"PASS hardware cost calibration: the model is within its bands of {synth.describe()} "
          f"on {len(inputs)} corpus(es)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
