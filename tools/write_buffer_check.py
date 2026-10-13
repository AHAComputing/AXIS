#!/usr/bin/env python3
"""A store buffer in front of a cache that is busy. Gate.

A blocking cache (docs/blocking_cache_design.md) takes one request a cycle
and none while a miss is on its way, and a store retired INTO it: the store
waited at the head of the window for its line, and everything behind it. A
store buffer (docs/memory_model_design.md, WM1) is the write buffer that
cache did not have. Held here, on machines alike but for the buffer:

  * **commit does not wait for a store's line**: four stores to four cold
    lines retire at once into a buffer of eight, and a miss apart with none
    or into a buffer of one;
  * **the cache is as busy as it was**: stores to a new line each, round a
    loop, are a miss and a cycle each whatever the buffer -- one miss at a
    time, in order, so a buffer told to drain in any order drains as one
    told to drain in order;
  * **a load is next, not a store that has retired**: behind four buffered
    misses a load of a line the core holds waits for the one on its way and
    not for the four;
  * **what orders memory still waits**: a fence after the four stores
    retires when the buffer is empty;
  * **a core that has stopped still drains**: two cores beside each other
    each write their four stores and finish;
  * every program leaves what it leaves with no buffer, with no replays.

Usage: tools/write_buffer_check.py
"""
from __future__ import annotations

import importlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from lsq_check import Assembler  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402
from xmode_check import random_program  # noqa: E402
from mcx_check import (BASE, CODE, COUNTER, DATA, ENTRY, HARNESS, MAXC, MINUS_ONE,  # noqa: E402
                       ONE, OUT, OUT2, REGION)
from store_buffer_check import ADDED, FENCE  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "issue_width.axisl"
ISA = "iw32"
MISS = 10
SEEDS = 6
SHORT, LONG = 24, 48
STRIDE, SLOW, HOLD = 25, 24, 22
HELD = 1024

CACHE = f"""
  (defmemory wbd (kind cache) (size-bytes 4096) (line-bytes 64) (ways 1)
    (width-bits 32) (latency-cycles {MISS}) (blocking true))
"""

CORE = """
  (defcore wb_{name} (kind rvmt) (memory wbd) (implements {isa}) (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)){buffer}
    (engine execute)
    (units (alu (count 4) (pipelined true)) (mul (count 2) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 2) (pipelined true))))
"""

MACHINES = {
    "none": "",
    "eight": "\n    (store-buffer (entries 8))",
    "one": "\n    (store-buffer (entries 1))",
    "two": "\n    (store-buffer (entries 2))",
    "two_any": "\n    (store-buffer (entries 2) (drain any))",
    "eight_any": "\n    (store-buffer (entries 8) (drain any))",
}


def build_programs(asm: Assembler, bnz):
    add, mul = asm.fast_add, asm.slow
    fence = asm._word(FENCE, imm=0)  # noqa: SLF001
    # A line's length in a register: one and one, doubled five times.
    line = [asm.op(add, STRIDE, ONE, ONE)] + [asm.op(add, STRIDE, STRIDE, STRIDE)] * 5
    body = [asm.st(ONE, BASE, 0), asm.op(add, BASE, BASE, STRIDE), asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
    burst = [asm.st(ONE, BASE, 64 * k) for k in range(4)]
    # A load of a line the core holds, through an address late enough that
    # the second of the buffered misses is on its way, and a chain on what
    # it reads.
    late = ([asm.op(mul, SLOW, BASE, ONE)] + [asm.op(mul, SLOW, SLOW, ONE)] * 7
            + [asm.ld(OUT, SLOW, HELD)] + [asm.op(mul, OUT, OUT, ONE)] * 4)
    hold = [asm.ld(HOLD, BASE, HELD)] + [asm.op(mul, 30, 30, 30)] * 6
    programs = {
        "STORES": line + body + [bnz(COUNTER, 0, -4 * len(body)), 0],
        "BURST": burst + [0],
        "FENCED": burst + [fence, 0],
        "BEHIND": hold + burst + late + [0],
        # The same with nothing for the load to be behind.
        "AHEAD": hold + [asm.st(ONE, BASE, HELD + 4 * (k + 1)) for k in range(4)] + late + [0],
    }
    rng = random.Random(8642)
    for k in range(SEEDS):
        programs[f"R{k}"] = random_program(asm, bnz, rng, rng.randrange(8, 24))
    return programs


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text()
    end = source.rstrip().rfind(")")

    def run_cmd(cmd, check=True):
        return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=AXIS_ROOT)

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {message}")
        failures += 1

    corpus = work / "wb.axisl"
    corpus.write_text(source[:end] + ADDED + CACHE
                      + "".join(CORE.format(name=n, isa=ISA, buffer=b) for n, b in MACHINES.items()) + ")\n")
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "wb_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("wb_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None or FENCE not in asm.tests:
        sys.modules.pop("wb_lift", None)
        print(f"  wb: DECLINED {asm.missing() or 'no branch, or no fence'}")
        return 0, 0
    programs = build_programs(asm, bnz)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    sys.modules.pop("wb_lift", None)

    plan = [(label, trips) for label in programs for trips in ((SHORT, LONG) if label == "STORES" else (5,))]
    runs = [f'  alone("{label}_{trips}_{machine}", "wb_{machine}", 0, {label}, {len(programs[label])}, {trips}u);'
            for label, trips in plan for machine in MACHINES]
    expect = [f"{label}_{trips}_{machine}.0" for label, trips in plan for machine in MACHINES]
    # Two cores, each with its own four stores: one that has stopped goes on
    # asking the cache for what it holds.
    for machine in MACHINES:
        runs.append("  { static const uint32_t *const w[] = { BURST, BURST }; static const int32_t n[] = { "
                    f"{len(programs['BURST'])}, {len(programs['BURST'])} }}; "
                    f'together("PAIR_{machine}", "wb_{machine}", 2, w, n, 0, 5u, 0u); }}')
        expect.extend(f"PAIR_{machine}.{c}" for c in (0, 1))
    code = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "code": CODE,
        "data": DATA, "region": REGION, "maxc": MAXC,
        "base": slot(BASE), "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
        "out": slot(OUT), "out2": slot(OUT2), "isa": f'"{ISA}"',
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs),
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(code)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / name), str(work / f"{name}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True, timeout=900)
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 15 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])
    checks += 1
    if done.returncode != 0 or any(tag not in said for tag in expect):
        fail(f"the harness exited {done.returncode}, or some run reported nothing: "
             f"{[t for t in expect if t not in said][:4]}")
        return checks, failures

    checks += 1
    replayed = sorted(tag for tag, row in said.items() if row["replays"])
    if replayed:
        fail(f"the golden model disagreed with the pipeline (replays) in {replayed[:6]}")
    for label, trips in plan:
        for machine in MACHINES:
            mine, plain = said[f"{label}_{trips}_{machine}.0"], said[f"{label}_{trips}_none.0"]
            checks += 1
            if (mine["steps"], mine["mark"]) != (plain["steps"], plain["mark"]):
                fail(f"{label} on wb_{machine} left other registers or memory than on wb_none")

    for machine in MACHINES:
        for c in (0, 1):
            checks += 1
            if said[f"PAIR_{machine}.{c}"]["steps"] != said[f"BURST_5_{machine}.0"]["steps"]:
                fail(f"core {c} of two on wb_{machine} retired {said[f'PAIR_{machine}.{c}']['steps']} "
                     f"instructions of BURST, not {said[f'BURST_5_{machine}.0']['steps']}")
    took = lambda label, machine, trips=5: said[f"{label}_{trips}_{machine}.0"]["cycles"]  # noqa: E731
    # The cache is as busy as it was: a miss and a cycle a store, in order.
    for machine in MACHINES:
        grew = took("STORES", machine, LONG) - took("STORES", machine, SHORT)
        checks += 1
        if grew != (LONG - SHORT) * (MISS + 1):
            fail(f"{LONG - SHORT} more stores, a new line each, took {grew} cycles on wb_{machine}; "
                 f"a miss of {MISS} and a cycle each -- {(LONG - SHORT) * (MISS + 1)}")
    # Commit does not wait for a store's line.
    checks += 1
    if took("BURST", "eight") + 3 * MISS > took("BURST", "none"):
        fail(f"four stores to four cold lines took {took('BURST', 'eight')} cycles into a buffer of eight "
             f"and {took('BURST', 'none')} with none; they retire at once, three misses sooner or more")
    checks += 1
    if took("BURST", "one") < took("BURST", "eight") + 2 * MISS:
        fail(f"four stores into a buffer of one took {took('BURST', 'one')} cycles, and "
             f"{took('BURST', 'eight')} into eight; each waits for the one before to be written")
    checks += 1
    if took("BURST", "two_any") != took("BURST", "two"):
        fail(f"four stores took {took('BURST', 'two_any')} cycles into a buffer of two draining in any "
             f"order and {took('BURST', 'two')} in order; one miss at a time is in order")
    # A load is next, not a store that has retired.
    checks += 1
    if took("BEHIND", "eight") + 2 * MISS > took("BEHIND", "none"):
        fail(f"a load behind four stores that miss took {took('BEHIND', 'eight')} cycles with a buffer "
             f"of eight and {took('BEHIND', 'none')} with none; it waits for one miss, not four")
    checks += 1
    if took("BEHIND", "eight_any") != took("BEHIND", "eight"):
        fail(f"a load behind four stores that miss took {took('BEHIND', 'eight_any')} cycles with a buffer "
             f"draining in any order and {took('BEHIND', 'eight')} in order; a cache that is busy is asked "
             f"for one store, not for all it will hold")
    checks += 1
    if took("BEHIND", "eight") <= took("AHEAD", "eight"):
        fail(f"a load behind four buffered misses took {took('BEHIND', 'eight')} cycles, no more than "
             f"the {took('AHEAD', 'eight')} with nothing in its way; the cache is busy with the first")
    # What orders memory still waits.
    checks += 1
    if took("FENCED", "eight") < took("BURST", "eight") + 3 * MISS:
        fail(f"a fence after four stores that miss took {took('FENCED', 'eight')} cycles, and the "
             f"stores alone {took('BURST', 'eight')}; it retires when the buffer is empty")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_wb_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL wb: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a store buffer in front of a cache that is busy: SKIP")
        return DECLINED
    print(f"a store buffer in front of a cache that is busy: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
