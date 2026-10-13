#!/usr/bin/env python3
"""A unit that names a length takes lanes for the elements worked on. Gate.

`(length vl)` on a unit with lanes (docs/vector_units_design.md, VU2) says
which operand carries the element count. An instruction with such an operand
takes lanes for that many elements, not for its whole register.

RVV's instructions are put on one unit of ONE 64-bit lane, so a full 128-bit
register is two beats, and run on that machine with and without the length
named. The tail-agnostic add takes its length from a register; the programs
first make registers holding 1, 2, 3 and 4. Each figure is the cycles eight
more adds cost:

  * **one or two 32-bit elements fill one lane: one beat**, eight cycles;
    **three or four fill two: two beats**, sixteen -- the count rounds up to
    lanes, not to the register;
  * **an add with no length operand takes its whole register**, sixteen, on
    the same unit; and so does one told a length far past it;
  * **a unit that names no length takes the whole register whatever the
    operand holds**: sixteen at every length;
  * and on both machines the execution-driven core and its trace-driven twin
    agree cycle for cycle, replay nothing, and leave the functional model's
    registers -- the length is read when the instruction issues on one and
    before it steps on the other, and they are the same number.

Usage: tools/vector_length_check.py
"""
from __future__ import annotations

import argparse
import importlib
import json
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
SHORT, LONG = 8, 16
MACHINES = {
    "named": "(vec (count 1) (pipelined true) (lanes 1) (length vl))",
    "whole": "(vec (count 1) (pipelined true) (lanes 1))",
}
#: Scalar registers the prefix leaves 1, 2, 3 and 4 in.
LENGTH_REG = {1: 6, 2: 7, 3: 8, 4: 5}
#: Cycles eight more adds cost on `named`, by length; None is the add with no
#: length operand.
EXPECT = {1: 8, 2: 8, 3: 16, 4: 16, None: 16}

CORE = """
  (defcore vl_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob 64) (issue-queue 64) (commit-width 8))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 8) (depth 2)){execute}
    (units {unit}))
"""


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text().replace("(latency ", "(unit vec) (latency ")
    cores = "".join(CORE.format(engine=engine, name=name, isa=ISA, unit=unit,
                                execute=" (engine execute)" if engine == "x" else "")
                    for name, unit in MACHINES.items() for engine in ("x", "t"))
    end = source.rstrip().rfind(")")
    corpus = work / "vl.axisl"
    corpus.write_text(source[:end] + cores + ")\n")

    def run_cmd(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=AXIS_ROOT)

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "vl_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("vl_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    fixture = {test["mnemonic"]: int(test["encoded"], 16) for test in tests}
    needed = ("VSETVLI", "VMSEQ_VV__l0", "VMV_X_S", "VADD_VV__l0", "VADD_VV_TA__l0", "VREDSUM_VS")
    if any(m not in fixture for m in needed):
        sys.modules.pop("vl_lift", None)
        print(f"  vector length: DECLINED no {[m for m in needed if m not in fixture]}")
        return 0, 0

    def word(mnemonic, **operands):
        value = fixture[mnemonic]
        for operand, number in operands.items():
            value = lift.place_operand(value, by_mnemonic[mnemonic], operand, number)
        return value

    # ⚠️ The lengths are MADE, not seeded: the set-length instruction gives 4,
    # a compare of a register with itself gives lanes of 1, and adding those
    # gives 2 and 3. The harness fills every register with a large pattern,
    # and a length taken from one of those is clamped to the register -- four
    # elements whatever was asked, which is no test of a length.
    prefix = [
        word("VSETVLI", rd=LENGTH_REG[4], avl=1),
        word("VMSEQ_VV__l0", vd=27, vs1=1, vs2=1),
        word("VMV_X_S", rd=LENGTH_REG[1], vs2=27),
        word("VADD_VV__l0", vd=28, vs1=27, vs2=27),
        word("VMV_X_S", rd=LENGTH_REG[2], vs2=28),
        word("VADD_VV__l0", vd=29, vs1=27, vs2=28),
        word("VMV_X_S", rd=LENGTH_REG[3], vs2=29),
    ]
    programs = {}
    for count in (SHORT, LONG):
        for length, register in LENGTH_REG.items():
            programs[f"L{length}_{count}"] = prefix + [
                word("VADD_VV_TA__l0", vd=9 + i, vl=register, vs1=1, vs2=2) for i in range(count)]
        # ⚠️ And a length far past the register -- whatever the harness left
        # in register 1. It is clamped to the elements there are: unclamped,
        # the count times the element width wraps, and what is left of it can
        # look like one lane's worth.
        programs[f"HUGE_{count}"] = prefix + [
            word("VADD_VV_TA__l0", vd=9 + i, vl=1, vs1=1, vs2=2) for i in range(count)]
        # ⚠️ LATE: a chain of slow reductions FIRST, each reading the last.
        # They are older than everything else and still running when the adds
        # issue, so nothing behind them has committed -- the length register's
        # value exists only as a write in the window. A pipeline that read the
        # committed register found the harness's pattern there, and every
        # other program here let it: their lengths had long since committed.
        # Here it disagrees with the trace-driven window by four cycles.
        programs[f"LATE_{count}"] = (
            [word("VREDSUM_VS", vd=20, vs2=20) for _ in range(8)] + prefix
            + [word("VADD_VV_TA__l0", vd=9 + i, vl=LENGTH_REG[1], vs1=1, vs2=2)
               for i in range(count)])
        programs[f"PLAIN_{count}"] = prefix + [
            word("VADD_VV__l0", vd=9 + i, vs1=1, vs2=2) for i in range(count)]
    state_slots = list(getattr(lift, "STATE_SLOTS", []))
    length_slots = {length: lift.register_slot("reg", register)
                    for length, register in LENGTH_REG.items()}
    sys.modules.pop("vl_lift", None)

    runs = [f'  go("{label}_FUNC", NULL, {label}, {len(ws)});' for label, ws in programs.items()]
    runs += [f'  go("{label}_{engine.upper()}_{name}", "vl_{engine}_{name}", {label}, {len(ws)});'
             for label, ws in programs.items() for name in MACHINES for engine in ("x", "t")]
    # The lengths the prefix made, read back from the functional run.
    probe = "\n".join(f'  printf("LENGTH {length} %llu\\n", (unsigned long long)LAST[{slot}]);'
                      for length, slot in length_slots.items())
    body = (HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "isa": ISA,
        "state": ", ".join('{"%s", 0, %du}' % (n, w) for n, w in state_slots) or "{0, 0, 0u}",
        "states": len(state_slots),
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in ws)}, 0u }};"
            for label, ws in programs.items()),
        "runs": "\n".join(runs) + "\n" + probe,
    })
    # Keep the registers of the last run for the probe.
    body = body.replace("static uint64_t OVERRUN, LOSSY, EVENTS;",
                        "static uint64_t OVERRUN, LOSSY, EVENTS;\nstatic uint64_t LAST[4096];")
    body = body.replace("    uint64_t v = S->reg(m, i);\n",
                        "    uint64_t v = S->reg(m, i);\n    if (i < 4096) { LAST[i] = v; }\n", 1)
    root = work / "packs" / manifest["name"]
    (work / "vl.c").write_text(body)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "vl"),
             str(work / "vl.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / "vl")], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL vector length: the harness exited {done.returncode}")
        return 0, 1
    said, made = {}, {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 17 and parts[1] == "steps":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
        elif len(parts) == 3 and parts[0] == "LENGTH":
            made[int(parts[1])] = int(parts[2])
    if "--dump" in sys.argv:
        print("   ", made)
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL vector length: {message}")
        failures += 1

    checks += 1
    if made != {length: length for length in LENGTH_REG}:
        fail(f"the prefix left {made} in the length registers; 1, 2, 3 and 4, or every figure "
             f"below is about some other length")
        return checks, failures
    for label, ws in programs.items():
        func = said.get(f"{label}_FUNC")
        for name in MACHINES:
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
                     f"{x['replays']} replay(s), {t['cycles']} trace-driven; one reads the "
                     f"length when the instruction issues and the other before it steps, and "
                     f"they are the same number")
    if failures:
        return checks, failures

    def more(label, name):
        return said[f"{label}_{LONG}_X_{name}"]["cycles"] - said[f"{label}_{SHORT}_X_{name}"]["cycles"]

    checks += 1
    if more("HUGE", "named") != EXPECT[4]:
        fail(f"{LONG - SHORT} more adds told a length far past their register cost "
             f"{more('HUGE', 'named')} cycles on `named`; a register holds four elements, so "
             f"{EXPECT[4]}")
    # LATE is held by the two engines agreeing, above: the trace-driven window
    # has the length from the functional state, and the execution-driven one
    # has to find the same number in the window. What eight more adds cost
    # says nothing there -- they issue in the reductions' gaps, and the chain
    # is what the run takes.
    for length, expected in EXPECT.items():
        label = "PLAIN" if length is None else f"L{length}"
        what = "with no length operand" if length is None else f"of {length} element(s)"
        checks += 1
        if more(label, "named") != expected:
            fail(f"{LONG - SHORT} more adds {what} on `named` {MACHINES['named']} cost "
                 f"{more(label, 'named')} cycles; {expected}")
        checks += 1
        if more(label, "whole") != EXPECT[None]:
            fail(f"{LONG - SHORT} more adds {what} on `whole` {MACHINES['whole']} cost "
                 f"{more(label, 'whole')} cycles; a unit that names no length takes the whole "
                 f"register, {EXPECT[None]}")
    if not failures:
        print("  vector length: 8 more adds on one 64-bit lane cost "
              + ", ".join(f"{more(f'L{n}', 'named')} at length {n}" for n in LENGTH_REG)
              + f", {more('PLAIN', 'named')} with no length; {more('L1', 'whole')} at any length "
              f"where the unit names none; both engines cycle for cycle; {checks} checks")
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
            print(f"  FAIL vector length: {said[:400]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a unit that names a length works on that many elements: SKIP")
        return DECLINED
    print(f"a unit that names a length works on that many elements: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
