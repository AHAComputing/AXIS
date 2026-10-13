#!/usr/bin/env python3
"""A unit has lanes. Gate.

`(lanes N)` on a `defcore` unit makes one copy of it N lanes of 64 bits
(docs/vector_units_design.md, VU1). An instruction takes as many lanes as the
widest register it names is limbs -- a 128-bit vector, two. Narrower than the
unit, several share a copy in a cycle; wider, it takes every lane for
ceil(need / N) beats and completes that many cycles less one later.

`scalable_basic`'s instructions -- 128-bit vectors, so two lanes each -- are
put on one unit, `vec`, and run on machines that differ only in it. Every
figure is the cycles EIGHT MORE instructions cost, so what the front end and
the drain cost cancels:

  * **independent adds**: one a cycle on a unit with no lanes, and on one of
    two lanes -- exactly as wide as the instruction; **two a cycle on four
    lanes**, where two instructions share the copy; **one every two cycles on
    one lane**, where each takes two beats; and two a cycle on two copies of
    two lanes;
  * **a chain of adds**, each reading the last: one a cycle wherever the
    instruction fits -- lanes do not speed up a dependence -- and one every
    two cycles on one lane, since a second beat is a cycle later a result:
    on two copies of one lane too, where the other copy is free and only the
    late result holds the next link;
  * **a lane is sixty-four bits, not an element**: sixteen byte lanes cost
    what four word lanes cost;
  * and on every machine the execution-driven core and its trace-driven twin
    agree cycle for cycle, replay nothing, and leave the functional model's
    registers.

Usage: tools/vector_unit_check.py
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
CORPUS = AXIS_ROOT / "examples" / "scalable_basic.axisl"
ISA = "sve_like"
SHORT, LONG = 8, 16
#: name -> the unit clause. `plain` declares no lanes: a unit as it always was.
MACHINES = {
    "plain": "(vec (count 1) (pipelined true))",
    "one": "(vec (count 1) (pipelined true) (lanes 1))",
    "two": "(vec (count 1) (pipelined true) (lanes 2))",
    "four": "(vec (count 1) (pipelined true) (lanes 4))",
    "pair": "(vec (count 2) (pipelined true) (lanes 2))",
    # ⚠️ Two copies of ONE lane: a chain's next link finds the other copy
    # free, so only the result arriving a beat late holds it back. On one copy
    # the copy being held hid that -- a second beat that delayed nothing passed
    # every machine above, and mutation testing said so.
    "twin": "(vec (count 2) (pipelined true) (lanes 1))",
}
#: What eight more instructions cost: (independent, chained).
EXPECT = {"plain": (8, 8), "one": (16, 16), "two": (8, 8), "four": (4, 8), "pair": (4, 8),
          "twin": (8, 16)}

CORE = """
  (defcore vu_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob 64) (issue-queue 64) (commit-width 8))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 8) (depth 2)){execute}
    (units {unit}))
"""


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text()
    # Every instruction on the one unit: the corpus names none.
    source = source.replace("(latency ", "(unit vec) (latency ")
    cores = "".join(CORE.format(engine=engine, name=name, isa=ISA, unit=unit,
                                execute=" (engine execute)" if engine == "x" else "")
                    for name, unit in MACHINES.items() for engine in ("x", "t"))
    end = source.rstrip().rfind(")")
    corpus = work / "vu.axisl"
    corpus.write_text(source[:end] + cores + ")\n")

    def run_cmd(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=AXIS_ROOT)

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "vu_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("vu_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    fixture = {test["mnemonic"]: int(test["encoded"], 16) for test in tests}

    def add(mnemonic, dest, a, b):
        entry = by_mnemonic[mnemonic]
        word = fixture[mnemonic]
        for operand, value in (("zd", dest), ("zn", a), ("zm", b)):
            word = lift.place_operand(word, entry, operand, value)
        return word

    words, bytes_ = "SVADD_S__l0", "SVADD_B__l0"
    if words not in fixture or bytes_ not in fixture:
        sys.modules.pop("vu_lift", None)
        print("  vector units: DECLINED no 32-bit and 8-bit lane add")
        return 0, 0
    lanes_of = lambda m: sum(1 for e in lift.AXIS_LIFT_TABLE  # noqa: E731
                             if e["mnemonic"].rsplit("__l", 1)[0] == m.rsplit("__l", 1)[0])
    programs = {}
    for count in (SHORT, LONG):
        programs[f"INDEP{count}"] = [add(words, 8 + i, 1, 2) for i in range(count)]
        programs[f"CHAIN{count}"] = [add(words, 8, 8, 1) for _ in range(count)]
        programs[f"BYTES{count}"] = [add(bytes_, 8 + i, 1, 2) for i in range(count)]
    lane_counts = (lanes_of(words), lanes_of(bytes_))
    state_slots = list(getattr(lift, "STATE_SLOTS", []))
    sys.modules.pop("vu_lift", None)

    runs = [f'  go("{label}_FUNC", NULL, {label}, {len(ws)});' for label, ws in programs.items()]
    runs += [f'  go("{label}_{engine.upper()}_{name}", "vu_{engine}_{name}", {label}, {len(ws)});'
             for label, ws in programs.items() for name in MACHINES for engine in ("x", "t")]
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
    (work / "vu.c").write_text(body)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "vu"),
             str(work / "vu.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / "vu")], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL vector units: the harness exited {done.returncode}")
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
        print(f"  FAIL vector units: {message}")
        failures += 1

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
                     f"{[func['steps'], t['steps'], x['steps']]} of {len(ws)} instructions or "
                     f"left different registers")
            checks += 1
            if x["replays"] or x["cycles"] != t["cycles"]:
                fail(f"{label} on `{name}`: {x['cycles']} cycles execution-driven with "
                     f"{x['replays']} replay(s), {t['cycles']} trace-driven; the two issue "
                     f"through the same lanes")
    if failures:
        return checks, failures

    def more(kind, name):
        return said[f"{kind}{LONG}_X_{name}"]["cycles"] - said[f"{kind}{SHORT}_X_{name}"]["cycles"]

    for name, (independent, chained) in EXPECT.items():
        checks += 1
        if more("INDEP", name) != independent:
            fail(f"{LONG - SHORT} more independent 128-bit adds on `{name}` "
                 f"{MACHINES[name]} cost {more('INDEP', name)} cycles; {independent}")
        checks += 1
        if more("CHAIN", name) != chained:
            fail(f"{LONG - SHORT} more chained 128-bit adds on `{name}` {MACHINES[name]} cost "
                 f"{more('CHAIN', name)} cycles; {chained}")
        checks += 1
        if more("BYTES", name) != more("INDEP", name):
            fail(f"{lane_counts[1]} byte lanes cost {more('BYTES', name)} cycles on `{name}` "
                 f"where {lane_counts[0]} word lanes cost {more('INDEP', name)}; a lane of a "
                 f"unit is sixty-four bits, not an element")
    if not failures:
        print("  vector units: 8 more independent 128-bit adds cost "
              + ", ".join(f"{more('INDEP', n)} on `{n}`" for n in MACHINES)
              + "; chained "
              + ", ".join(f"{more('CHAIN', n)}" for n in MACHINES)
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
            print(f"  FAIL vector units: {said[:400]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a unit has lanes: SKIP")
        return DECLINED
    print(f"a unit has lanes: {'FAIL' if failures else 'PASS'} ({checks} checks, "
          f"{failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
