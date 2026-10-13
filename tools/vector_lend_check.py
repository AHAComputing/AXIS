#!/usr/bin/env python3
"""A vector unit lends its idle lanes. Gate.

`(accepts alu)` on a unit with lanes (docs/vector_units_design.md, VU3) lets
another unit's instructions issue on the lanes it is not using. An instruction
tries its own unit first and borrows only when that has no copy free; a vector
instruction's lanes are its own.

RVV's vector instructions are put on `vec` and its one scalar instruction on
`alu` -- one copy -- and run on machines that differ only in whether `vec`
accepts `alu`. Each figure is the cycles the second half of a program costs:

  * **scalars alone**: one a cycle on the machine that keeps its lanes; on
    the one that lends two, three a cycle -- its own unit and both lanes;
  * **a vector instruction reserves its lanes whole**: alternating with
    128-bit adds that take both lanes, the scalars get none, and lending
    changes nothing;
  * **what a vector instruction leaves, scalars take**: on four lanes, one
    128-bit add and three scalars issue together -- one scalar on its own
    unit, two on the lanes the add left -- where the machine that keeps its
    lanes takes three cycles for the scalars;
  * and on every machine the execution-driven core and its trace-driven twin
    agree cycle for cycle, replay nothing, and leave the functional model's
    registers.

Usage: tools/vector_lend_check.py
"""
from __future__ import annotations

import argparse
import importlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from vector_pipeline_check import ENTRY, HARNESS  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "rvv.axisl"
ISA = "rvv"
ALU = "(alu (count 1) (pipelined true))"
MACHINES = {
    "keeps2": f"{ALU} (vec (count 1) (pipelined true) (lanes 2))",
    "lends2": f"{ALU} (vec (count 1) (pipelined true) (lanes 2) (accepts alu))",
    "keeps4": f"{ALU} (vec (count 1) (pipelined true) (lanes 4))",
    "lends4": f"{ALU} (vec (count 1) (pipelined true) (lanes 4) (accepts alu))",
}
#: (program, machine) -> cycles its second half costs.
EXPECT = {
    ("SCALAR", "keeps2"): 12, ("SCALAR", "lends2"): 4,
    ("MIXED", "keeps2"): 12, ("MIXED", "lends2"): 12,
    ("GROUP", "keeps4"): 24, ("GROUP", "lends4"): 8,
}

CORE = """
  (defcore ln_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob 64) (issue-queue 64) (commit-width 8))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 8) (depth 2)){execute}
    (units {unit}))
"""


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text().replace("(latency ", "(unit vec) (latency ")
    # The one scalar instruction goes to the scalar unit.
    scalar = re.search(r"\(definstruction vsetvli\b.*?\(unit vec\)", source, re.S)
    if not scalar:
        print("  vector lending: DECLINED no scalar instruction to lend a lane to")
        return 0, 0
    source = source[:scalar.end() - len("(unit vec)")] + "(unit alu)" + source[scalar.end():]
    cores = "".join(CORE.format(engine=engine, name=name, isa=ISA, unit=unit,
                                execute=" (engine execute)" if engine == "x" else "")
                    for name, unit in MACHINES.items() for engine in ("x", "t"))
    end = source.rstrip().rfind(")")
    corpus = work / "ln.axisl"
    corpus.write_text(source[:end] + cores + ")\n")

    def run_cmd(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=AXIS_ROOT)

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "ln_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("ln_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    fixture = {test["mnemonic"]: int(test["encoded"], 16) for test in tests}
    if "VSETVLI" not in fixture or "VADD_VV__l0" not in fixture:
        sys.modules.pop("ln_lift", None)
        print("  vector lending: DECLINED no scalar instruction or vector add")
        return 0, 0

    def word(mnemonic, **operands):
        value = fixture[mnemonic]
        for operand, number in operands.items():
            value = lift.place_operand(value, by_mnemonic[mnemonic], operand, number)
        return value

    # Independent of one another: every destination its own register, every
    # source one nothing here writes.
    scalar_op = lambda i: word("VSETVLI", rd=4 + i % 24, avl=1)  # noqa: E731
    vector_op = lambda i: word("VADD_VV__l0", vd=4 + i % 24, vs1=1, vs2=2)  # noqa: E731
    programs = {}
    for half in (1, 2):
        programs[f"SCALAR{half}"] = [scalar_op(i) for i in range(12 * half)]
        programs[f"MIXED{half}"] = [op(i) for i in range(12 * half) for op in (vector_op, scalar_op)]
        programs[f"GROUP{half}"] = [op(4 * i + k) for i in range(8 * half)
                                    for k, op in enumerate((vector_op, scalar_op, scalar_op,
                                                            scalar_op))]
    state_slots = list(getattr(lift, "STATE_SLOTS", []))
    sys.modules.pop("ln_lift", None)

    on = {"SCALAR": ("keeps2", "lends2"), "MIXED": ("keeps2", "lends2"),
          "GROUP": ("keeps4", "lends4")}
    runs = [f'  go("{label}_FUNC", NULL, {label}, {len(ws)});' for label, ws in programs.items()]
    runs += [f'  go("{label}_{engine.upper()}_{name}", "ln_{engine}_{name}", {label}, {len(ws)});'
             for label, ws in programs.items() for name in on[label[:-1]] for engine in ("x", "t")]
    body = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "isa": ISA,
        "state": ", ".join('{"%s", 0, %du}' % (n, w) for n, w in state_slots) or "{0, 0, 0u}",
        "states": len(state_slots),
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in ws)}, 0u }};"
            for label, ws in programs.items()),
        "runs": "\n".join(runs),
    }
    root = work / "packs" / manifest["name"]
    (work / "ln.c").write_text(body)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "ln"),
             str(work / "ln.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / "ln")], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL vector lending: the harness exited {done.returncode}")
        return 0, 1
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 17 and parts[1] == "steps":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL vector lending: {message}")
        failures += 1

    for label, ws in programs.items():
        func = said.get(f"{label}_FUNC")
        for name in on[label[:-1]]:
            x, t = said.get(f"{label}_X_{name}"), said.get(f"{label}_T_{name}")
            checks += 1
            if not (func and x and t):
                fail(f"{label} on `{name}` reported nothing on some engine")
                return checks, failures
            checks += 1
            if not (x["steps"] == t["steps"] == func["steps"] == len(ws)
                    and x["mark"] == t["mark"] == func["mark"]):
                fail(f"{label} on `{name}`: the engines retired "
                     f"{[func['steps'], t['steps'], x['steps']]} of {len(ws)} or left different "
                     f"registers")
            checks += 1
            if x["replays"] or x["cycles"] != t["cycles"]:
                fail(f"{label} on `{name}`: {x['cycles']} cycles execution-driven with "
                     f"{x['replays']} replay(s), {t['cycles']} trace-driven; the two lend the "
                     f"same lanes")
    if failures:
        return checks, failures

    def more(kind, name):
        return said[f"{kind}2_X_{name}"]["cycles"] - said[f"{kind}1_X_{name}"]["cycles"]

    for (kind, name), expected in EXPECT.items():
        checks += 1
        if more(kind, name) != expected:
            fail(f"the second half of {kind} cost {more(kind, name)} cycles on `{name}` "
                 f"({MACHINES[name]}); {expected}")
    if not failures:
        print("  vector lending: " + "; ".join(
            f"{kind.lower()} {more(kind, keep)} keeping, {more(kind, lend)} lending"
            for kind, (keep, lend) in on.items())
            + f"; both engines cycle for cycle; {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", action="store_true")
    parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL vector lending: {said[:400]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a vector unit lends its idle lanes: SKIP")
        return DECLINED
    print(f"a vector unit lends its idle lanes: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
