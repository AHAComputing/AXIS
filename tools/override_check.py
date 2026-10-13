#!/usr/bin/env python3
"""A predictor overridden at decode. Gate.

A predictor worth having does not answer in the cycle fetch needs an answer
in. `(branch ... (overrides (predictor bimodal) (entries N) (cycles C)))`
(docs/ooo_design.md, D3) gives fetch a quick predictor to follow and lets the
core's own speak C cycles later, at decode. Where the two disagree the front
end is redirected there, and the instructions fetched meanwhile are thrown
away. Two machines on each engine, identical but for the clause, with gshare
over a bimodal table:

  * **a branch guessed not taken is redirected at decode**: a branch that
    alternates is one bimodal counters never call taken and gshare learns.
    Every taken trip is fetched past and sent to its target C cycles later --
    exactly C cycles a trip, and nothing on the trips both call not taken;
  * **a branch guessed taken is sent back**: a branch taken three trips in
    four is one bimodal counters always call taken and gshare learns the
    fourth of. That trip is fetched at its target and sent back to the
    fall-through, C cycles later;
  * **it costs time, never accuracy**: what the machine predicted is the
    core's predictor's answer, so the two machines mispredict exactly as
    often, on every program and at every length;
  * **while decode looks, fetch runs on**: a branch in the last word of a
    line that the quick predictor calls not taken is fetched past, into the
    next line, which is asked for then -- so the program, sent to that line
    by decode, does not miss on it and waits no longer than a machine that
    was never wrong about the branch;
  * **the two engines agree** what an override costs.

Usage: tools/override_check.py [corpus.axisl ...]
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
from redirect_check import (COUNTER, DATA, LINE, MINUS_ONE, ONE, POINTER,  # noqa: E402
                            SCRATCH_LINK, STEP, direct_jump_encoder, harness_run, layout)

AXIS_ROOT = Path(__file__).resolve().parent.parent
SHORT, LONG = 16, 32
# ALT's pair, MOST's four, and the scratch each rotates through.
FLIP, FLOP, RING, SCRATCH = 14, 15, (17, 18, 19, 20), 13


def build_programs(asm: Assembler, bnz, jump):
    add = asm.fast_add
    pad = asm.op(add, 30, 1, 1)
    move = lambda to, frm: asm.op(add, to, frm, 0)  # noqa: E731
    programs = {}
    # ⚠️ ADDS ONLY, and a chain one add long: the loop has to be bound by its
    # front end for a cycle lost there to be a cycle of the program's. A
    # value flipped by a multiply made the loop four cycles a trip in the
    # back end, and an override cost it nothing at all.
    # ALT: two registers swapped every trip, and a branch on one of them --
    # taken, not, taken, not -- over one instruction.
    programs["ALT"] = [move(SCRATCH, FLIP), move(FLIP, FLOP), move(FLOP, SCRATCH),
                       bnz(FLIP, 0, 8), asm.op(add, 16, 16, ONE),
                       asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -24),
                       asm.op(add, 21, 1, 1), 0]
    # MOST: four registers rotated every trip, three of them one -- taken,
    # taken, not, taken.
    a, b, c, d = RING
    programs["MOST"] = [move(SCRATCH, a), move(a, b), move(b, c), move(c, d), move(d, SCRATCH),
                        bnz(a, 0, 8), asm.op(add, 16, 16, ONE),
                        asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -32),
                        asm.op(add, 21, 1, 1), 0]
    # ⚠️ AHEAD: ALT's branch in the LAST word of a line, over the first half
    # of the next; that line jumps to one FOUR lines on -- the same set of a
    # four-line cache, so each evicts the other every trip -- and the loop
    # closes from there. Told "not taken", fetch runs on into the next line
    # while decode looks, and asks for it: when decode sends the program to
    # the middle of that same line, the line is already on its way. So the
    # program does not miss on it, and the two cycles decode took were spent
    # inside a wait the other machine has too.
    # ⚠️ A program in three lines measured nothing: by the time gshare had
    # learned the branch, the wrong paths of its first mispredicts had put
    # every line in the cache, and nothing fetched ahead was ever new.
    per_line = LINE // 4
    away = 5 * per_line
    programs["AHEAD"] = layout({0: move(SCRATCH, FLIP), 1: move(FLIP, FLOP), 2: move(FLOP, SCRATCH),
                                per_line - 1: bnz(FLIP, 0, 4 * (per_line // 2 + 1)),
                                per_line: asm.op(add, 16, 16, ONE),
                                2 * per_line - 1: jump(SCRATCH_LINK, 4 * (away - 2 * per_line + 1)),
                                away: asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                                away + 1: bnz(COUNTER, 0, -4 * (away + 1)),
                                away + 2: asm.op(add, 21, 1, 1)},
                               away + 3, pad) + [0]
    # ⚠️ LATE: a loop that loads a new line every trip, and loads the NEXT
    # trip's line where it falls through -- so a wrong path down the fall
    # through prefetches for the trip after. Its branch is always taken and
    # resolves at once. gshare meets it with a new history every trip until
    # its history is full, and calls it not taken each time; bimodal counters
    # have called it taken since the third. Those trips are mispredicts on
    # both machines -- and on the one that waits for decode to say "not
    # taken", the wrong path starts too late to load anything.
    programs["LATE"] = [asm.ld(21, POINTER, 0), asm.op(add, POINTER, POINTER, STEP),
                        asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -12),
                        asm.ld(22, POINTER, 0), 0]
    return programs


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = [c for c in facts.get("cores", []) if c.get("front_end")]

    def twin(core):
        return next((c for c in cores if c is not core and not c.get("overrides")
                     and all(c.get(k) == core.get(k) for k in core if k not in ("name", "overrides"))),
                    None)

    def pair(executing):
        return next(((c, twin(c)) for c in cores if c.get("overrides") and twin(c)
                     and (c.get("engine") == "execute") == executing
                     and c["front_end"]["icache"]
                     and (executing or c["front_end"]["wrong_path_execute"])), (None, None))

    (tover, tnot), (xover, xnot) = pair(False), pair(True)
    if not (tover and xover):
        print(f"  {name}: DECLINED no core with an overridden predictor and a twin without, "
              f"on each engine")
        return 0, 0
    machines = {"TOVER": tover, "TNOT": tnot, "XOVER": xover, "XNOT": xnot}
    cycles = tover["overrides"]["cycles"]
    if xover["overrides"] != tover["overrides"] or tover["predictor"] != "gshare":
        print(f"  {name}: DECLINED the two engines' overridden predictors differ, or what "
              f"overrides is not gshare")
        return 0, 0

    module = f"ov_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    jump = direct_jump_encoder(lift, tests)
    if asm.missing() or bnz is None or jump is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no branch or direct jump'}")
        return 0, 0
    programs = build_programs(asm, bnz, jump)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF,
             slot(0): 0, slot(FLIP): 0, slot(FLOP): 1, slot(16): 0,
             slot(POINTER): DATA, slot(STEP): LINE,
             **{slot(r): v for r, v in zip(RING, (1, 1, 1, 0))}}
    lines = [f'  go("{p}_{t}_{trips}", "{c["name"]}", {p}, {len(programs[p])}, {trips}u);'
             for p in programs for t, c in machines.items() for trips in (SHORT, LONG)]
    said = harness_run(work, manifest, name, isa, seeds, programs, lines, 8)
    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    if said is None:
        fail("the harness did not run")
        return 1, failures

    def get(program, tag, key, trips=LONG):
        return said[f"{program}_{tag}_{trips}"][key]

    def grew(program, tag, key="cycles"):
        return get(program, tag, key, LONG) - get(program, tag, key, SHORT)

    for program in programs:
        for trips in (SHORT, LONG):
            rows = [said.get(f"{program}_{t}_{trips}") for t in machines]
            checks += 1
            if any(r is None for r in rows):
                fail(f"{program} reported nothing on some machine")
                return checks, failures
            checks += 1
            if len({(r["steps"], r["mark"]) for r in rows}) != 1:
                fail(f"{program} retired different instructions or left different registers "
                     f"or memory on different machines: {[r['steps'] for r in rows]}")
            # ⚠️ TIME, NEVER ACCURACY: the quick predictor decides nothing.
            # ⚠️ Not LATE on the engine that fetches what it predicts: there a
            # predictor is trained when a branch COMMITS, so a fetch held two
            # cycles at decode asks a table that has learned two cycles more.
            # Its warm-up mispredicts differ by that, and by nothing the quick
            # predictor said.
            for over, base in (("TOVER", "TNOT"), ("XOVER", "XNOT")):
                if program == "LATE" and over == "XOVER":
                    continue
                checks += 1
                if get(program, over, "miss", trips) != get(program, base, "miss", trips):
                    fail(f"{program}, {trips} trips: {get(program, over, 'miss', trips)} "
                         f"mispredicts on {machines[over]['name']} and "
                         f"{get(program, base, 'miss', trips)} on {machines[base]['name']}; "
                         f"what is predicted is the core's predictor's answer on both, so "
                         f"the same")
    if failures:
        return checks, failures

    more = LONG - SHORT
    for over, base in (("TOVER", "TNOT"), ("XOVER", "XNOT")):
        for program, each, what in (
                ("ALT", 2, "taken every other trip, which bimodal counters never call taken: "
                           "fetched past and redirected to its target at decode"),
                ("MOST", 4, "taken three trips in four, which bimodal counters always call "
                            "taken: fetched at its target on the fourth and sent back")):
            checks += 1
            if grew(program, over, "miss") != 0:
                fail(f"{program} mispredicted {grew(program, over, 'miss')} more times over "
                     f"{more} more trips on {machines[over]['name']}; gshare has to have "
                     f"learned the branch for an override to be what is measured")
            cost = grew(program, over) - grew(program, base)
            checks += 1
            if cost != cycles * more // each:
                fail(f"a branch {what}: {more} more trips cost {cost} cycles more on "
                     f"{machines[over]['name']} than on {machines[base]['name']}; one trip in "
                     f"{each} is overridden and each costs exactly {cycles}, so "
                     f"{cycles * more // each}")
        saved = grew("AHEAD", base, "imiss") - grew("AHEAD", over, "imiss")
        checks += 1
        if saved != more // 2:
            fail(f"a branch in the last word of a line, guessed not taken and redirected at "
                 f"decode into a line the cache has lost: {more} more trips missed "
                 f"{grew('AHEAD', over, 'imiss')} more times on {machines[over]['name']} and "
                 f"{grew('AHEAD', base, 'imiss')} on {machines[base]['name']}; fetch ran on "
                 f"into that line while decode looked and asked for it, so the program does "
                 f"not miss there -- one fewer every other trip, {more // 2}")
        checks += 1
        if grew("AHEAD", over) != grew("AHEAD", base):
            fail(f"the same {more} trips took {grew('AHEAD', over)} cycles on "
                 f"{machines[over]['name']} and {grew('AHEAD', base)} on "
                 f"{machines[base]['name']}; the line arrives when it was asked for, which is "
                 f"the cycle after the branch on both, so decode's {cycles} cycles cost "
                 f"nothing more")
        # ⚠️ A MISPREDICT'S WRONG PATH STARTS AT DECODE when decode is what sent
        # fetch down it. The quick predictor was right those trips, which is
        # worth nothing: the machine follows the other one.
        late = get("LATE", over, "dmiss", SHORT) - get("LATE", base, "dmiss", SHORT)
        checks += 1
        if late <= 0 or get("LATE", base, "dmiss", SHORT) >= SHORT:
            fail(f"a loop whose fall-through loads the next trip's line, mispredicted not "
                 f"taken while gshare's history fills: {get('LATE', over, 'dmiss', SHORT)} "
                 f"data misses on {machines[over]['name']} and "
                 f"{get('LATE', base, 'dmiss', SHORT)} on {machines[base]['name']} over "
                 f"{SHORT} trips; the wrong path prefetches on the machine that follows its "
                 f"one predictor at fetch, and starts {cycles} cycles too late on the one "
                 f"that waits for decode -- some fewer than {SHORT}, and more than that")
    checks += 1
    if any(grew(p, "TOVER") - grew(p, "TNOT") != grew(p, "XOVER") - grew(p, "XNOT")
           for p in ("ALT", "MOST")):
        fail("an override costs the two engines different cycles")
    if not failures:
        print(f"  {name}: {more // 2} decode redirects of a branch guessed not taken cost "
              f"{grew('ALT', 'TOVER') - grew('ALT', 'TNOT')} cycles, {more // 4} of a branch "
              f"guessed taken {grew('MOST', 'TOVER') - grew('MOST', 'TNOT')}, exactly {cycles} "
              f"each on both engines; no mispredict more or fewer; fetch running on asked "
              f"for {grew('AHEAD', 'TNOT', 'imiss') - grew('AHEAD', 'TOVER', 'imiss')} lines "
              f"the program then did not miss on; {checks} checks")
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
        print("a predictor overridden at decode: SKIP")
        return DECLINED
    print(f"a predictor overridden at decode: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
