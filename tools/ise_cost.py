#!/usr/bin/env python3
"""Build each proven extension, and say what it costs and what it is worth.

`ise_mine.py` ranks a candidate by the cycles of the chain it replaces, less
what the extension itself takes -- and what the extension takes was a
parameter, `--extension-latency`, because nothing had been built. `ise_prove.py`
writes each proven candidate as an AXIS instruction. An AXIS instruction has a
netlist (`emit-hw-json`), the netlist has a calibrated area and depth
(`tools/hw_calibrate.py`), and the description it was mined from has units the
netlist could join. So the parameter is no longer one.

For each proven proposal this reports:

  * **alone**: the netlist's area and depth, and the fewest cycles that depth
    fits in at the cycle the base description's own units are grouped by;
  * **in the machine**: the proposal added to the base description, and a
    core for each latency worth considering -- the fewest it fits in, and the
    latency of each slower unit it could ride. Each core's view is planned
    (`emit-hw-json --core`) and the report
    is what changed: which unit took it, the area the machine grew by (the
    MARGINAL area, which is what an extension costs a core that already has
    an adder and a multiplier), and what it did to that unit's stage delay;
  * **worth**: occurrences times the cycles the chain loses at that latency.

The options are not ranked into one. A multiply-accumulate that fits in two
cycles as a multiplier of its own, or in three on the multiplier that is
already there for a fortieth of the area, is a decision, and this prints both.

`--check` holds every proposal's netlist to the golden model
(`hw_units_check.py`), which closes the chain: the code equals the proposal
(`ise_prove.py`, for every input) and the proposal equals the circuit.
`--synth` synthesises each netlist and prints the measured area and delay
beside the model's.

Usage: tools/ise_cost.py candidates.json proposals_dir [--check] [--synth]
                         [--json out.json]
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import math
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
TOOLS = AXIS_ROOT / "tools"

# A unit already past the cycle is not made worse by a stage that grows less
# than this.
STAGE_GROWTH = 1.05


def hw_plan(axis_file: Path, core: str | None = None) -> dict | None:
    """The hardware plan, as the description states it or as `core` sees it."""
    result = subprocess.run([*axis_prefix(), "emit-hw-json", str(axis_file),
                             *(["--core", core] if core else [])],
                            capture_output=True, text=True, cwd=AXIS_ROOT)
    return json.loads(result.stdout) if result.returncode == 0 else None


def hw_effect_plan(axis_file: Path, core: str | None = None) -> dict | None:
    """The units with instructions stated as effects in them
    (`emit-hw-effect-json`): where an extension that is an effect goes."""
    result = subprocess.run([*axis_prefix(), "emit-hw-effect-json", str(axis_file),
                             *(["--core", core] if core else [])],
                            capture_output=True, text=True, cwd=AXIS_ROOT)
    return json.loads(result.stdout) if result.returncode == 0 else None


def core_text(name: str, isa: str | None, latency: tuple[str, int] | None = None,
              clock: dict | None = None) -> str:
    """A core that says nothing but, at most, how long one instruction takes.

    An option is a machine, and a machine is a `defcore`: the extension at two
    cycles and at three are two cores over one description
    (`docs/core_timing_design.md`), not two descriptions.
    """
    implements = f" (implements {isa})" if isa else ""
    # On the miner's as-built clock every other instruction is at its floor
    # too (`ise_mine.py --as-built`): one clock for the chain and the
    # extension.
    entries = ([f"({latency[0]} {latency[1]})"] if latency else []) \
        + (["(* derived)"] if clock else [])
    cycle = f" (cycle (gates {clock['cycle_gates']}))" if clock else ""
    timing = f" (timing (latency {' '.join(entries)}))" if entries else ""
    return f"  (defcore {name} (kind rvmt){implements}{cycle}{timing})\n"


def instruction_of(proposal: str, isa: str | None = None) -> str | None:
    """The proposal's `definstruction`. One that reads state brings an ISA of
    its own declaring exactly that state; in the base description it belongs
    to the base's ISA, which has it. Without a base ISA to name, None."""
    start = proposal.index("  (definstruction")
    text = proposal[start:proposal.rstrip().rindex(")")]
    if "(defisa " in proposal:
        if not isa:
            return None
        text = re.sub(r"\(isa \w+\)", f"(isa {isa})", text, count=1)
    return text


def with_forms(base: str, *forms: str) -> str:
    """`base` with more forms before its closing parenthesis."""
    return base.rstrip()[:-1] + "\n" + "\n".join(forms) + "\n)\n"


def reference_bodies(description: str) -> str:
    """The base description's `deffun`s, as text.

    A proposal mined from AArch64 calls that architecture's own operators --
    `a64_shift_reg`, `a64_cond_holds` -- and a netlist cannot be lowered from a
    name. The description says what each means in a `deffun`
    (`docs/hardware_design.md` §2.6); the proposal is costed with those beside
    it, as it would be inside the description.
    """
    bodies, at = [], 0
    while (start := description.find("(deffun ", at)) >= 0:
        depth, end = 0, start
        for end in range(start, len(description)):
            depth += {"(": 1, ")": -1}.get(description[end], 0)
            if depth == 0:
                break
        bodies.append(description[start:end + 1])
        at = end + 1
    return "\n  ".join(bodies)


def alone(proposal_file: Path, mnemonic: str, bodies: str, workdir: Path):
    """(plan entry, the file it came from): the proposal's own netlist, as a
    value or -- when it reads state -- as an effect."""
    text = proposal_file.read_text()
    if bodies:
        text = text.rstrip()[:-1] + "\n  " + bodies + "\n)\n"
    path = workdir / proposal_file.name
    path.write_text(text)
    plan = hw_plan(path)
    if plan is None:
        return None, path
    for entry in plan["instructions"] + plan["effects"]:
        if entry["mnemonic"] == mnemonic:
            return entry, path
    return None, path


def isa_of(base_text: str, mnemonic: str) -> str | None:
    """The ISA the base description puts `mnemonic` in, or None."""
    at = base_text.find(f"(mnemonic {mnemonic})")
    if at < 0:
        return None
    start = base_text.rfind("(definstruction", 0, at)
    found = re.search(r"\(isa (\w[\w.-]*)\)", base_text[start:at + 400])
    return found.group(1) if found else None


def units_of(plan: dict) -> dict:
    return {unit["name"]: unit for unit in plan["units"]}


def machine_area(plan: dict) -> float:
    return sum(unit["area"]["merged"] for unit in plan["units"])


def options_for(base_text: str, base: dict, instruction: str, mnemonic: str,
                fewest: int, isa: str | None, workdir: Path,
                clock: dict | None = None, based: Path | None = None,
                fewest_only: bool = False) -> tuple[list[dict], str]:
    """The proposal in the base description, at each latency worth trying:
    one description, and a core for each."""
    base_units = units_of(base)
    latencies = [fewest] if fewest_only else sorted(
        {fewest} | {unit["timing"]["latency"] for unit in base["units"]
                    if unit["timing"]["latency"] > fewest})
    path = workdir / f"with_{mnemonic.lower()}.axisl"
    path.write_text(with_forms(
        base_text, instruction,
        *(core_text(f"ise_l{latency}", isa, (mnemonic, latency), clock) for latency in latencies)))
    options = []
    effect_base = None
    for latency in latencies:
        plan = hw_plan(path, f"ise_l{latency}")
        if plan is None:
            return [], "AXIS does not accept it in the base description"
        unit = next((u for u in plan["units"] if mnemonic in u["members"]), None)
        if unit is None:
            # Built as an effect -- it reads or writes state, or its operators
            # are stated by reference bodies. The units effects join are
            # `emit-hw-effect-json`'s, and the machine is measured there.
            if effect_base is None:
                effect_base = hw_effect_plan(based, "ise_base") if based else None
            effects = hw_effect_plan(path, f"ise_l{latency}")
            if effect_base is None or effects is None:
                return [], "it is built as an effect, and AXIS planned no units with effects in them"
            unit = next((u for u in effects["units"]
                         if any(m["mnemonic"] == mnemonic for m in u["members"])), None)
            if unit is None:
                return [], "it is built as an effect, and no unit with effects took it"
            before = next((u for u in effect_base["units"] if u["name"] == unit["name"]), None)
            options.append({
                "latency": latency,
                "unit": unit["name"],
                "joins": before is not None,
                "marginal_area": effects["machine_area"] - effect_base["machine_area"],
                "stage_delay": unit["depth"] / max(unit["latency"], 1),
                "stage_delay_before": (before["depth"] / max(before["latency"], 1)) if before else None,
            })
            continue
        before = base_units.get(unit["name"])
        options.append({
            "latency": latency,
            "unit": unit["name"],
            "joins": before is not None,
            "marginal_area": machine_area(plan) - machine_area(base),
            "stage_delay": unit["timing"]["stage_delay"],
            "stage_delay_before": before["timing"]["stage_delay"] if before else None,
        })
    return options, ""


def synthesise(proposal_file: Path, mnemonic: str, workdir: Path):
    """(area, ps) of the proposal's netlist through Yosys, or None."""
    try:
        import pyrtl
        from hw_synth import Synth
    except ImportError:
        return None
    synth = Synth.find()
    if synth is None:
        return None
    emitted = workdir / f"{mnemonic.lower()}_hw.py"
    subprocess.run([*axis_prefix(), "emit-hw-pyrtl", str(proposal_file), "-o", str(emitted)],
                   check=True, capture_output=True, cwd=AXIS_ROOT)
    spec = importlib.util.spec_from_file_location(f"axis_ise_{mnemonic.lower()}", emitted)
    rtl = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rtl)
    entry = rtl.INSTRUCTIONS[mnemonic]

    def build():
        inputs = [pyrtl.Input(bitwidth=width, name=f"in{i}")
                  for i, (_, width) in enumerate(entry["inputs"])]
        out = pyrtl.Output(bitwidth=entry["output_width"], name="answer")
        out <<= getattr(rtl, entry["builder"])(*inputs)

    return synth.measure(pyrtl, build)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("candidates", type=Path)
    parser.add_argument("proposals", type=Path, help="the directory ise_prove.py --out wrote")
    parser.add_argument("--check", action="store_true",
                        help="hold each proposal's netlist to the golden model")
    parser.add_argument("--synth", action="store_true",
                        help="synthesise each netlist and print the measurement")
    parser.add_argument("--fewest-only", action="store_true",
                        help="try only the fewest cycles each extension fits in, not every "
                             "slower unit's latency -- one plan of the machine per extension")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()

    report = json.loads(args.candidates.read_text())
    description = Path(report["description"])
    if not description.is_absolute():
        description = AXIS_ROOT / description
    base_text = description.read_text()
    isa, clock = report.get("isa"), report.get("clock")
    workdir = Path(tempfile.mkdtemp(prefix="axis_isecost_"))
    # The machine the extension is added to: the description as a core that
    # says nothing sees it -- the same instructions every option's core does.
    based = workdir / f"{description.stem}_base.axisl"
    based.write_text(with_forms(base_text, core_text("ise_base", isa, None, clock)))
    base = hw_plan(based, "ise_base")
    if base is None:
        print(f"FAIL {description.name} has no hardware plan to add an extension to")
        return FAILED
    budget = base["cost_model"]["cycle_budget"]
    bodies = reference_bodies(base_text)

    print(f"{description.name}: {machine_area(base):.0f} NAND2 in "
          f"{len(base['units'])} unit(s), a cycle of {budget:.0f} gate delays "
          f"({budget * base['cost_model']['ps_per_gate'] / 1000:.1f} ns in "
          f"{base['cost_model']['reference'].split(',')[1].strip()})")

    rows, built, declined, unchecked = [], 0, 0, 0
    for path in sorted(args.proposals.glob("mined*.axisl"),
                       key=lambda p: int(re.search(r"\d+", p.stem).group())):
        index = int(re.search(r"\d+", path.stem).group())
        candidate = report["candidates"][index]
        label = "+".join(candidate["mnemonics"])
        mnemonic = path.stem.upper()
        entry, costed = alone(path, mnemonic, bodies, workdir)
        if not entry or entry["status"] != "built":
            reason = entry["reason"] if entry else "AXIS did not accept the proposal"
            print(f"  DECLINE {label}: no netlist ({reason})")
            declined += 1
            continue
        built += 1
        fewest = max(1, math.ceil(entry["depth"] / budget))
        chain, seen = candidate["critical_path_cycles"], candidate["occurrences"]
        row = {"proposal": path.stem, "replaces": candidate["mnemonics"],
               "occurrences": seen, "chain_cycles": chain,
               "area": entry["area"], "depth": entry["depth"], "fewest_cycles": fewest,
               "options": []}
        print(f"  {path.stem}: {label}, seen {seen}, a chain of {chain} cycle(s)")
        line = (f"    alone: {entry['area']:.0f} NAND2, {entry['depth']:.1f} gate delays "
                f"-- {fewest} cycle(s)")
        if args.synth:
            measured = synthesise(costed, mnemonic, workdir) if "area" in entry else None
            if measured:
                row["synthesised"] = {"area": measured[0], "delay_ps": measured[1]}
                line += f"; synthesised {measured[0]:.0f} NAND2, {measured[1] / 1000:.2f} ns"
        print(line)
        if args.check:
            check = subprocess.run(
                [sys.executable,
                 str(TOOLS / ("hw_effects_check.py" if "effects" in entry
                              else "hw_units_check.py")), str(costed),
                 *([] if "effects" in entry else ["--expect-declined", "0"])],
                capture_output=True, text=True, cwd=AXIS_ROOT)
            row["netlist_equals_golden"] = check.returncode == PASSED
            if check.returncode != PASSED:
                print(f"    FAIL the netlist is not the proposal: "
                      f"{check.stdout.strip().splitlines()[-1][:120]}")
                unchecked += 1

        # A proposal that reads state belongs in the ISA of the instructions it
        # replaces, which declares that state.
        home = isa or next((found for m in candidate["mnemonics"]
                            if (found := isa_of(base_text, m))), None)
        instruction = instruction_of(path.read_text(), home)
        if instruction is None:
            print("    in the machine: not priced -- the proposal reads state through an "
                  "ISA of its own")
        else:
            options, why_not = options_for(base_text, base, instruction, mnemonic, fewest,
                                           isa, workdir, clock, based, args.fewest_only)
            if why_not:
                print(f"    in the machine: not priced -- {why_not}")
            for option in options:
                removed = seen * max(chain - option["latency"], 0)
                option["cycles_removed"] = removed
                # A stage past the cycle, and longer than the unit's was: the
                # extension is then paid for by every instruction, in clock.
                before = option["stage_delay_before"] or 0.0
                option["lengthens_cycle"] = (
                    option["stage_delay"] > budget
                    and option["stage_delay"] > before * STAGE_GROWTH)
                row["options"].append(option)
                if removed == 0 and option["latency"] > fewest:
                    continue        # slower than the chain it replaces
                where = (f"joins `{option['unit']}`" if option["joins"]
                         else f"a unit of its own, `{option['unit']}`")
                note = ""
                if option["lengthens_cycle"]:
                    note = (f"; ⚠️ that unit's stage becomes {option['stage_delay']:.1f} gate "
                            f"delays" + (f" from {before:.1f}" if before else "")
                            + f", against a cycle of {budget:.0f}")
                print(f"    at {option['latency']} cycle(s): {where}, "
                      f"+{option['marginal_area']:.0f} NAND2, removes {removed} cycle(s)"
                      f"{note}")
        rows.append(row)

    # One line a reader can act on: the most each built extension removes
    # WITHOUT lengthening the cycle, and what the machine grows by for it.
    print(f"{'removes':>8} {'+NAND2':>8} {'cycles':>6}  extension")
    ranked, only_slower = [], []
    for row in rows:
        paying = [o for o in row["options"] if o["cycles_removed"] > 0]
        fitting = [o for o in paying if not o["lengthens_cycle"]]
        if fitting:
            best = max(fitting, key=lambda o: (o["cycles_removed"], -o["marginal_area"]))
            ranked.append((best["cycles_removed"], best["marginal_area"], best["latency"], row))
        elif paying:
            only_slower.append(row)
    for removed, area, latency, row in sorted(ranked, key=lambda r: (-r[0], r[1])):
        print(f"{removed:>8} {area:>8.0f} {latency:>6}  {'+'.join(row['replaces'])}")
    for row in only_slower:
        print(f"{'-':>8} {'-':>8} {'-':>6}  {'+'.join(row['replaces'])}: pays only by "
              f"lengthening the cycle")

    if args.json:
        args.json.write_text(json.dumps({
            "schema": "axis.ise-costs.v1",
            "description": str(description),
            "cost_model": {k: v for k, v in base["cost_model"].items() if k != "operators"},
            "machine_area": machine_area(base),
            "extensions": rows,
        }, indent=2))

    print(f"{built} built, {declined} declined by name"
          + (f", {unchecked} whose netlist is not the proposal" if unchecked else ""))
    ok = built > 0 and unchecked == 0
    print("mined extensions, built and priced: " + ("PASS" if ok else "FAIL"))
    return PASSED if ok else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
