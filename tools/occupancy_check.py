#!/usr/bin/env python3
"""The wrong path holds what it uses. Gate.

Until its branch resolves a machine does not know a path is wrong, so
wrong-path instructions enter the window like any others (docs/ooo_design.md,
W2): an entry, a queue slot, a physical register; issued when ready and a unit
is free, behind everything older; gone when the branch resolves. Two machines
identical but for whether the wrong path is executed, with ONE multiplier that
is not pipelined -- a unit that stays held for a multiply's whole latency:

  * **a unit taken while nothing older wanted it is still held when something
    older does**: the branch waits on multiply, add, multiply; a wrong-path
    multiply takes the unit during the add, and the second multiply -- older,
    and now ready -- waits out the rest of it. Exactly latency - 1 cycles;
  * **a wrong path that wants nothing the program wants costs nothing**: the
    same program with an add where the wrong-path multiply was costs exactly
    what no wrong path costs;
  * **the unit is still held after the squash**: a branch that resolves at
    once, a wrong-path multiply issued beside it, and a multiply first on the
    right path -- which arrives, a refill later, to a unit that is not free
    yet. Exactly latency - 1 - depth cycles;
  * **a load touches the cache when it ISSUES**: a wrong-path load whose
    address is ready prefetches what the right path loads later -- one data
    miss fewer -- and one whose address is a multiply behind the branch's own
    operand has not issued when the branch resolves, and prefetches nothing;
  * **a miss is the wrong-path load's own latency**: a second load through
    what the first one missed on is still waiting when the branch resolves;
  * **the squash gives back what the wrong path took**: more wrong-path
    writes than the machine has spare registers cost the right path nothing
    -- and a wrong-path load behind them never gets a register, never enters
    the window, and prefetches nothing;
  * **a unit that aborts gives it back** (W4): on a twin whose multiplier is
    declared `(abort true)`, a multiply first on the right path arrives to a
    free unit, and an OLDER multiply that becomes ready the cycle the branch
    resolves waits one cycle -- the one the squash arrives in -- where a unit
    that holds makes it wait latency - 1. Nothing is aborted before the
    squash, and the engine that executes its own wrong path saves the same;
  * and on every program every machine retires the same instructions and
    leaves the same registers and memory.

Usage: tools/occupancy_check.py [corpus.axisl ...]
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
from lsq_check import Assembler, run_cmd  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402
from redirect_check import (BASE, COUNTER, DATA, LINE, MINUS_ONE, ONE, POINTER, STEP,  # noqa: E402
                            harness_run, layout, twin_of)

AXIS_ROOT = Path(__file__).resolve().parent.parent


def build_programs(asm: Assembler, bnz):
    add, mul = asm.fast_add, asm.slow
    pad = asm.op(add, 30, 1, 1)

    def jump(at, to, reg=ONE):
        return bnz(reg, 0, 4 * (to - at))

    def held(wrong):
        # multiply, add, multiply, branch -- taken, and cold, so guessed not.
        # Word 4 is the first of the wrong path.
        return layout({0: asm.op(mul, 20, ONE, ONE), 1: asm.op(add, 21, 20, 20),
                       2: asm.op(mul, 22, 21, ONE), 3: jump(3, 8, 22), 4: wrong,
                       8: asm.op(add, 25, 1, 1), 9: asm.op(add, 26, 1, 1)}, 10, pad) + [0]

    programs = {"HELD": held(asm.op(mul, 24, ONE, ONE)), "FREE": held(asm.op(add, 24, ONE, ONE))}
    # AFTER: the branch is ready when it arrives; the wrong path's multiply
    # issues beside it and the right path's first instruction is a multiply.
    programs["AFTER"] = layout({0: jump(0, 8), 1: asm.op(mul, 24, ONE, ONE),
                                8: asm.op(mul, 25, ONE, ONE), 9: asm.op(add, 26, 25, 25)},
                               10, pad) + [0]
    # ⚠️ OLDER (W4): an add, a multiply of what it made, and a branch that is
    # ready when it arrives. The wrong path's multiply issues beside the
    # branch, the cycle the add does -- the older multiply is not ready yet --
    # and the branch resolves the cycle the older multiply becomes ready. A
    # unit that holds makes it wait out the wrong path's; one that aborts is
    # free the cycle AFTER the squash, which is one cycle late and no more.
    programs["OLDER"] = layout({0: asm.op(add, 21, ONE, ONE), 1: asm.op(mul, 22, 21, ONE),
                                2: jump(2, 8), 3: asm.op(mul, 24, ONE, ONE), 4: 0,
                                8: asm.op(add, 25, 1, 1), 9: asm.op(add, 26, 1, 1)},
                               10, pad) + [0]
    # REACHED / UNREACHED: the branch waits on two multiplies. The wrong
    # path loads the line the right path loads later -- from a base that is
    # ready, or from one a third multiply makes out of the branch's own
    # operand, which cannot land before the branch has resolved.
    # ⚠️ The wrong path ENDS after its load, at a word that does not decode.
    # Left to run, it fell through into the right path's own load two words
    # on -- base ready, issued at once -- and the "unreached" line was
    # prefetched by the instruction this program exists to keep it from.
    head = {0: asm.op(mul, 20, ONE, ONE), 1: asm.op(mul, 20, 20, ONE), 2: jump(2, 8, 20),
            5: 0}
    tail = {8: asm.ld(23, BASE, 0), 9: asm.op(add, 26, 23, 23)}
    programs["REACHED"] = layout({**head, 3: asm.op(add, 22, BASE, 0), 4: asm.ld(21, 22, 0),
                                  **tail}, 10, pad) + [0]
    programs["UNREACHED"] = layout({**head, 3: asm.op(mul, 22, 20, BASE), 4: asm.ld(21, 22, 0),
                                    **tail}, 10, pad) + [0]
    # ⚠️ CHASE: a wrong-path load that MISSES, and a second through what it
    # loaded -- memory is zero there, so through address 0, which the right
    # path loads later. The miss is the first load's own latency: the second
    # is still waiting for the line when the branch resolves. A wrong path
    # whose misses cost it nothing chased the pointer and prefetched.
    programs["CHASE"] = layout({**head, 3: asm.ld(21, BASE, LINE), 4: asm.ld(22, 21, 0),
                                8: asm.ld(23, 0, 0), 9: asm.op(add, 26, 23, 23)},
                               10, pad) + [0]
    # CROWD: a wrong path of more writes than the machine has spare
    # registers, then a right path that writes too. Every register the wrong
    # path took has to come back when it is squashed. ⚠️ SIXTEEN WORDS, the
    # halt included: one instruction-cache line. A longer one ran eight cycles
    # FASTER with the wrong path than without -- it had fetched the second
    # line early -- and a cost of minus eight says nothing about registers.
    crowd = {0: asm.op(mul, 20, ONE, ONE), 1: jump(1, 11, 20)}
    crowd.update({k: asm.op(add, 10 + k, ONE, ONE) for k in range(2, 11)})
    crowd.update({k: asm.op(add, 10 + k, ONE, ONE) for k in range(11, 15)})
    programs["CROWD"] = layout(crowd, 15, pad) + [0]
    # ⚠️ STARVED: the same crowd, and then a load -- which needs a register
    # for what it loads, and there is none left: the wrong path's own writes
    # hold them all, and nothing on a wrong path ever retires to give one
    # back. So the load never enters the window, and prefetches nothing.
    # Without this a wrong path that took no registers at all passed CROWD --
    # it had none to return -- and mutation testing said so.
    starved = {0: asm.op(mul, 20, ONE, ONE), 1: asm.op(mul, 20, 20, ONE), 2: jump(2, 14, 20),
               12: asm.ld(21, BASE, 0), 13: 0, 14: asm.ld(23, BASE, 0)}
    starved.update({k: asm.op(add, 8 + k, ONE, ONE) for k in range(3, 12)})
    programs["STARVED"] = layout(starved, 15, pad) + [0]
    return programs


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = [c for c in facts.get("cores", [])
             if c.get("front_end") and c.get("engine") != "execute"]

    def serial(core):
        return next((u for u in core.get("units") or [] if not u.get("pipelined")
                     and (u.get("count") or 1) == 1), None)

    holds = next((c for c in cores if c["front_end"]["wrong_path_execute"] and c.get("memory")
                  and serial(c) and twin_of(cores, c, wrong_path_execute=False)), None)
    if not holds:
        print(f"  {name}: DECLINED no wrong-path-executing core with one unpipelined unit "
              f"and a twin")
        return 0, 0
    machines = {"HOLDS": holds, "NOT": twin_of(cores, holds, wrong_path_execute=False)}
    depth = holds["front_end"]["depth"]
    # ⚠️ W4: the same machine with a unit that ABORTS at a squash, and the pair
    # on the engine that executes its own wrong path.
    same = ("memory", "issue_width", "rob", "issue_queue", "commit_width", "branch_penalty",
            "predictor", "predictor_entries", "lsq", "rename", "front_end")

    def aborting(of, among):
        plain = lambda core: [{k: v for k, v in u.items() if k != "abort"}  # noqa: E731
                              for u in core.get("units") or []]
        return next((c for c in among if c is not of and plain(c) == of.get("units")
                     and any(u.get("abort") and not u.get("pipelined") for u in c["units"])
                     and all(c.get(k) == of.get(k) for k in same)), None)

    executing = [c for c in facts.get("cores", [])
                 if c.get("front_end") and c.get("engine") == "execute"]
    xholds = next((c for c in executing if serial(c) and c.get("memory")
                   and aborting(c, executing)), None)
    others = {"ABORTS": aborting(holds, cores), "XHOLDS": xholds,
              "XABORTS": xholds and aborting(xholds, executing)}
    if not all(others.values()):
        print(f"  {name}: DECLINED no twin of {holds['name']} whose unpipelined unit aborts, "
              f"or no such pair that executes its own wrong path")
        return 0, 0

    module = f"oc_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in facts["instructions"]}
    latency_of = {m: entry.get("latency_cycles", 1) for m, entry in by_mnemonic.items()}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no branch'}")
        return 0, 0
    # ⚠️ The slow instruction has to be the one the unpipelined unit runs, or
    # nothing here contends for anything.
    latency = asm.cost(asm.slow)
    if by_mnemonic[asm.slow].get("unit") != serial(holds)["name"] or latency - 1 - depth <= 0:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED the slowest arithmetic does not run on the unpipelined "
              f"unit, or the refill outlasts it")
        return 0, 0
    programs = build_programs(asm, bnz)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF,
             slot(BASE): DATA, slot(POINTER): DATA, slot(STEP): LINE}
    lines = [f'  go("{p}_{t}_0", "{c["name"]}", {p}, {len(programs[p])}, 0u);'
             for p in programs for t, c in {**machines, **others}.items()]
    said = harness_run(work, manifest, name, isa, seeds, programs, lines, 8)
    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    if said is None:
        fail("the harness did not run")
        return 1, failures

    def get(program, tag, key="cycles"):
        return said[f"{program}_{tag}_0"][key]

    for program in programs:
        rows = [said.get(f"{program}_{t}_0") for t in machines]
        checks += 1
        if any(r is None for r in rows):
            fail(f"{program} reported nothing on some machine")
            return checks, failures
        checks += 1
        if len({(r["steps"], r["mark"]) for r in rows}) != 1:
            fail(f"{program} retired different instructions or left different registers or "
                 f"memory on the two machines: {[r['steps'] for r in rows]}; the wrong path "
                 f"must leave nothing behind")
        checks += 1
        if get(program, "NOT", "wrong") or not get(program, "HOLDS", "wrong"):
            fail(f"{program}: {get(program, 'HOLDS', 'wrong')} wrong-path instructions on "
                 f"{holds['name']} and {get(program, 'NOT', 'wrong')} on its twin; the branch "
                 f"must mispredict, and only one machine runs the wrong path")
        checks += 1
        if any(said.get(f"{program}_{t}_0", {}).get(k) != rows[0][k]
               for t in others for k in ("steps", "mark")):
            fail(f"{program} retired different instructions or left different registers or "
                 f"memory on a machine whose unit aborts, or on the engine that executes its "
                 f"own wrong path")
    if failures:
        return checks, failures

    def cost(program, tag="HOLDS"):
        return get(program, tag) - get(program, "NOT")

    # ---- W4: a unit that aborts gives back what a squashed instruction held
    checks += 1
    if cost("OLDER") != latency - 1:
        fail(f"a wrong-path multiply issued a cycle before an older one was ready cost "
             f"{cost('OLDER')} cycles on {holds['name']}; the older multiply waits out the "
             f"wrong path's, exactly {latency - 1}")
    checks += 1
    if cost("OLDER", "ABORTS") != 1:
        fail(f"the same on {others['ABORTS']['name']}, whose multiplier aborts, cost "
             f"{cost('OLDER', 'ABORTS')} cycles; the unit is free the cycle after the squash "
             f"-- the cycle the squash arrives in is still the wrong path's -- so exactly 1")
    checks += 1
    if cost("AFTER", "ABORTS") != 0:
        fail(f"a wrong-path multiply issued beside its branch cost the right path's first "
             f"multiply {cost('AFTER', 'ABORTS')} cycles on {others['ABORTS']['name']}; the "
             f"squash aborted it, and the right path is a refill behind, so nothing")
    checks += 1
    if cost("HELD", "ABORTS") != cost("HELD"):
        fail(f"a wrong-path multiply holding the unit while its branch is still unresolved "
             f"cost {cost('HELD', 'ABORTS')} cycles on {others['ABORTS']['name']} and "
             f"{cost('HELD')} on {holds['name']}; nothing is aborted before the squash, so "
             f"the same")
    for program in programs:
        checks += 1
        if program not in ("OLDER", "AFTER") and get(program, "ABORTS") != get(program, "HOLDS"):
            fail(f"{program} took {get(program, 'ABORTS')} cycles on "
                 f"{others['ABORTS']['name']} and {get(program, 'HOLDS')} on {holds['name']}; "
                 f"no squashed instruction of it holds a unit, so the same")
    # ⚠️ OLDER only, across engines: what waits there is already in the window.
    # AFTER's multiply arrives a refill later, and the execution-driven
    # engine's refill is a cycle longer than a multiply outlasts.
    xsaved = get("OLDER", "XHOLDS") - get("OLDER", "XABORTS")
    saved = cost("OLDER") - cost("OLDER", "ABORTS")
    checks += 1
    if xsaved != saved or saved <= 0:
        fail(f"aborting saved the older multiply {xsaved} cycles on the engine that executes "
             f"its own wrong path ({xholds['name']} against {others['XABORTS']['name']}) and "
             f"{saved} on the trace-driven pair; a squash is the same squash on both")
    checks += 1
    if cost("HELD") != latency - 1:
        fail(f"a wrong-path multiply that took the only multiplier while the branch's chain "
             f"was adding cost {cost('HELD')} cycles; the chain's next multiply waits out the "
             f"rest of it, exactly {latency - 1}")
    checks += 1
    if cost("FREE") != 0:
        fail(f"a wrong path of adds beside a chain of multiplies cost {cost('FREE')} cycles; "
             f"it wants nothing the program wants, so nothing")
    checks += 1
    if cost("AFTER") != latency - 1 - depth:
        fail(f"a wrong-path multiply issued beside its branch cost the right path's first "
             f"multiply {cost('AFTER')} cycles; the unit is held past the squash and the "
             f"refill is {depth}, so exactly {latency - 1 - depth}")
    checks += 1
    if get("REACHED", "HOLDS", "dmiss") != get("REACHED", "NOT", "dmiss") - 1:
        fail(f"a wrong-path load whose address was ready: {get('REACHED', 'HOLDS', 'dmiss')} "
             f"data misses against {get('REACHED', 'NOT', 'dmiss')}; it issued, so it "
             f"prefetched -- exactly one fewer")
    checks += 1
    if get("UNREACHED", "HOLDS", "dmiss") != get("UNREACHED", "NOT", "dmiss"):
        fail(f"a wrong-path load a multiply behind the branch's operand: "
             f"{get('UNREACHED', 'HOLDS', 'dmiss')} data misses against "
             f"{get('UNREACHED', 'NOT', 'dmiss')}; it had not issued when the branch resolved, "
             f"so it touched nothing")
    checks += 1
    if get("CHASE", "HOLDS", "dmiss") != get("CHASE", "NOT", "dmiss"):
        fail(f"a wrong-path load through a pointer another wrong-path load missed on: "
             f"{get('CHASE', 'HOLDS', 'dmiss')} data misses against "
             f"{get('CHASE', 'NOT', 'dmiss')}; the miss is the first load's own latency, so "
             f"the second had not issued when the branch resolved")
    checks += 1
    if cost("CROWD") != 0:
        fail(f"a wrong path of more writes than the machine has spare registers cost the "
             f"right path {cost('CROWD')} cycles; the squash gives every one back")
    checks += 1
    if (get("STARVED", "HOLDS", "dmiss") != get("STARVED", "NOT", "dmiss")
            or get("STARVED", "HOLDS", "wrong") < 10):
        fail(f"a wrong-path load behind more writes than the machine has spare registers: "
             f"{get('STARVED', 'HOLDS', 'dmiss')} data misses against "
             f"{get('STARVED', 'NOT', 'dmiss')}, {get('STARVED', 'HOLDS', 'wrong')} wrong-path "
             f"instructions fetched; the load is fetched and never gets a register, so it "
             f"prefetches nothing")
    checks += 1
    if get("UNREACHED", "HOLDS", "wrong") < 2:
        fail(f"the unreached load's wrong path counted {get('UNREACHED', 'HOLDS', 'wrong')} "
             f"instructions; the load has to have been FETCHED for not issuing it to mean "
             f"anything")
    if not failures:
        print(f"  {name}: a held multiplier cost {cost('HELD')} cycles (latency {latency} - 1), "
              f"a wrong path of adds {cost('FREE')}, a multiply held past the squash "
              f"{cost('AFTER')} (refill {depth}); a ready wrong-path load prefetched "
              f"({get('REACHED', 'HOLDS', 'dmiss')} vs {get('REACHED', 'NOT', 'dmiss')} misses), "
              f"one behind a multiply did not ({get('UNREACHED', 'HOLDS', 'dmiss')} vs "
              f"{get('UNREACHED', 'NOT', 'dmiss')}); a multiplier that aborts cost an older "
              f"multiply {cost('OLDER', 'ABORTS')} cycle where one that holds cost "
              f"{cost('OLDER')}, on both engines; {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "issue_width.axisl"]
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp))
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("the wrong path holds what it uses: SKIP")
        return DECLINED
    print(f"the wrong path holds what it uses: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
