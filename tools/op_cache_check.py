#!/usr/bin/env python3
"""Two ways round decode: a micro-op cache and a loop buffer. Gate.

`(front-end ... (op-cache (entries N) (ways W) (window B) (width K) (depth
D)))` and `(loop-buffer (ops N) (width K) (depth D))`
(docs/micro_ops_design.md, U2). Code a machine has decoded before is not
fetched and decoded again. One machine -- four instructions wide at fetch,
eight behind it, four stages from fetch to dispatch -- and what it is with
each, on a loop of fourteen instructions the back end never holds up:

  * **decoded once, delivered wide**: the loop is four fetch groups a trip
    decoded and two from a cache that delivers eight micro-ops a cycle;
  * **a loop the buffer holds does not stop at its branch**: from the buffer
    it is fourteen micro-ops a trip at eight a cycle, the next trip's first
    six in the cycle of this one's last;
  * **a loop the buffer does not hold is decoded**: one of eighteen micro-ops
    in a buffer of sixteen costs what it costs with no buffer;
  * **code never seen is decoded**: a straight line run once costs the same
    with a micro-op cache as without;
  * **a cache that holds one window finds nothing in a loop of two**: each
    window puts the other out, and the loop costs what it costs decoded;
  * **fewer stages are a shorter refill**: with a cache no wider than decode,
    every mispredict of a branch the predictor cannot learn costs exactly the
    stages saved, and nothing else differs;
  * **what comes from the cache is not fetched**: a loop in two lines of one
    instruction-cache set misses twice a trip decoded and never from the
    micro-op cache;
  * **the engine that fetches what it predicts agrees**, cycle for cycle;
  * and every program retires the same instructions and leaves the same
    registers and memory on every machine.

Usage: tools/op_cache_check.py [corpus.axisl ...]
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
from redirect_check import (BASE, COUNTER, DATA, LINE, MINUS_ONE, ONE,  # noqa: E402
                            SCRATCH_LINK, direct_jump_encoder, harness_run, layout)

import redirect_check  # noqa: E402

# This gate reads micro-ops from the CACHE where the front-end gates read
# wrong-path instructions, and from the LOOP BUFFER where they read
# target-buffer misses (pack ABI 10).
for old, new in (("wrong %%llu", "cached %%llu"), ("btb %%llu", "looped %%llu"),
                 ("(unsigned long long)S->wrong_path_instructions(m)",
                  "(unsigned long long)S->op_cache_ops(m)"),
                 ("(unsigned long long)S->btb_misses(m)",
                  "(unsigned long long)S->loop_buffer_ops(m)")):
    assert old in redirect_check.HARNESS
    redirect_check.HARNESS = redirect_check.HARNESS.replace(old, new)

AXIS_ROOT = Path(__file__).resolve().parent.parent
SHORT, LONG = 16, 32
FLIP, FLOP, SCRATCH = 14, 15, 13


def load_and_add(lift, tests):
    """A load with an add in it: (mnemonic, out, address, addend)."""
    tested = {t["mnemonic"] for t in tests}
    for entry in lift.AXIS_LIFT_TABLE:
        effects = entry.get("effects") or []
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        outs = [o for o in entry["operands"] if o["role"] == "out"]
        if (entry["mnemonic"] in tested and len(effects) == 1 and len(regs) == 2
                and len(outs) == 1 and (effects[0].get("value_ast") or {}).get("op") == "add"
                and '"load"' in json.dumps(effects)):
            value = effects[0]["value_ast"]
            addend = next((o["name"] for o in regs if {"symbol": o["name"]} in value["args"]), None)
            address = next((o["name"] for o in regs if o["name"] != addend), None)
            if addend and address:
                return entry["mnemonic"], outs[0]["name"], address, addend
    return None


def build_programs(asm: Assembler, bnz, jump, icache_lines, cracked):
    add = asm.fast_add
    apart = lambda k: asm.op(add, 20 + k % 4, ONE, ONE)  # noqa: E731
    move = lambda to, frm: asm.op(add, to, frm, 0)  # noqa: E731
    pad = asm.op(add, 30, 1, 1)

    def loop(body):
        return ([apart(k) for k in range(body)]
                + [asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -4 * (body + 1)),
                   asm.op(add, 24, 1, 1), 0])

    programs = {"LOOP": loop(12), "BIG": loop(16), "ONCE": [apart(k) for k in range(64)] + [0]}
    # ⚠️ SPIN: a loop that is exactly ONE window and closes with a JUMP, run
    # until the harness stops it. Nothing in it is ever mispredicted, so fetch
    # is never redirected and never leaves the window: the only way back in
    # is its own jump, and that has to be a lookup, or the loop is decoded
    # for ever having missed once on the way in. A loop closed by a branch
    # was rescued by that branch's first, cold, mispredict.
    programs["SPIN"] = [apart(k) for k in range(7)] + [jump(SCRATCH_LINK, -28), 0]
    # ALT: a branch taken every other trip, over one instruction -- which two
    # bit counters never learn, so it mispredicts every time it is taken.
    programs["ALT"] = [move(SCRATCH, FLIP), move(FLIP, FLOP), move(FLOP, SCRATCH),
                       bnz(FLIP, 0, 8), asm.op(add, 16, 16, ONE),
                       asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -24),
                       asm.op(add, 24, 1, 1), 0]
    # ⚠️ SPLIT: a loop in two lines that share a set of the instruction cache
    # -- its first half, a jump as many lines on as the cache has, and the
    # jump back that closes it. Decoded, each line puts the other out every
    # trip. Two windows of a micro-op cache with room for both hold them.
    per_line = LINE // 4
    far = icache_lines * per_line
    programs["SPLIT"] = layout({0: apart(0), 1: apart(1), 2: jump(SCRATCH_LINK, 4 * (far - 2)),
                                far: asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                                far + 1: bnz(COUNTER, 0, -4 * (far + 1)),
                                far + 2: asm.op(add, 24, 1, 1)},
                               far + 3, pad) + [0]
    # ⚠️ CRACKED: four load-and-adds, a counter and a branch -- six
    # instructions, and ten micro-ops on a machine that cracks the four. What
    # comes from the micro-op cache is counted in micro-ops.
    if cracked:
        mnemonic, out, address, addend = cracked
        programs["CRACKED"] = ([asm._word(mnemonic, **{out: 20 + k, address: BASE, addend: ONE})
                                for k in range(4)]
                               + [asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -20),
                                  asm.op(add, 24, 1, 1), 0])
    return programs


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = [c for c in facts.get("cores", []) if c.get("front_end")]
    name = axis_file.stem

    def fe(core):
        return core["front_end"]

    def bare(core):
        return {k: v for k, v in fe(core).items() if k not in ("op_cache", "loop_buffer")}

    def of(base, executing, want):
        """The core that is `base` with this op cache or loop buffer and nothing else."""
        return next((c for c in cores if (c.get("engine") == "execute") == executing
                     and bare(c) == bare(base) and want(fe(c))
                     and all(c.get(k) == base.get(k) for k in base
                             if k not in ("name", "front_end"))), None)

    def family(executing):
        for base in cores:
            f = fe(base)
            if ((base.get("engine") == "execute") != executing or "op_cache" in f
                    or "loop_buffer" in f or not f["icache"]):
                continue
            wide = of(base, executing, lambda g: "loop_buffer" not in g and g.get("op_cache")
                      and g["op_cache"]["width"] > g["fetch_width"]
                      and g["op_cache"]["entries"] > 2)
            loops = of(base, executing, lambda g: "op_cache" not in g and g.get("loop_buffer"))
            if wide and loops:
                return {"PLAIN": base, "CACHE": wide, "LOOPS": loops,
                        "SHORT": of(base, executing, lambda g: "loop_buffer" not in g
                                    and g.get("op_cache")
                                    and g["op_cache"]["width"] == g["fetch_width"]
                                    and g["op_cache"]["depth"] < g["depth"]),
                        "TINY": of(base, executing, lambda g: "loop_buffer" not in g
                                   and g.get("op_cache") and g["op_cache"]["entries"] == 1)}
        return None

    trace, executes = family(False), family(True)
    if not trace or not trace["SHORT"] or not trace["TINY"]:
        print(f"  {name}: DECLINED no core with an icache and its four twins: a micro-op cache "
              f"wider than decode, one no wider, one of a single window, and a loop buffer")
        return 0, 0
    machines = dict(trace)
    if executes:
        machines.update({f"X{tag}": core for tag, core in executes.items() if core})
    base = trace["PLAIN"]
    fw, stages = fe(base)["fetch_width"], fe(base)["depth"]
    cache, buffer = fe(trace["CACHE"])["op_cache"], fe(trace["LOOPS"])["loop_buffer"]
    memories = {m["name"]: m for m in facts.get("memories", [])}
    icache = memories.get(fe(base)["icache"]) or {}
    icache_lines = (icache.get("size_bytes") or 0) // LINE
    # ⚠️ The arithmetic below is the front end's alone: a back end at least as
    # wide as either path delivers, and a loop of 14 that fits the buffer and
    # is two windows of the cache.
    behind = min(base.get("issue_width") or 1, base.get("commit_width") or 1)
    if (icache.get("line_bytes") != LINE or (icache.get("ways") or 1) != 1 or icache_lines < 2
            or behind < max(cache["width"], buffer["width"]) or buffer["ops"] not in (14, 15, 16, 17)
            or cache["window"] * 2 < 14 * 4 or cache["window"] >= 14 * 4):
        print(f"  {name}: DECLINED the cores are not the ones this gate's arithmetic is in")
        return 0, 0

    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    module = f"oc_{name}"
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
    uarch = json.loads(run_cmd([*axis_prefix(), "emit-uarch-json", str(axis_file)]).stdout)
    plans = {row["core"]: {c["mnemonic"]: len(c["micro_ops"]) for c in row.get("cracked", [])}
             for row in uarch.get("timing", [])}
    cracked = load_and_add(lift, tests)
    if cracked and any(plans.get(c["name"], {}).get(cracked[0]) != 2 for c in machines.values()):
        cracked = None
    programs = build_programs(asm, bnz, jump, icache_lines, cracked)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)
    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF, slot(0): 0,
             slot(FLIP): 0, slot(FLOP): 1, slot(BASE): DATA}
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

    def get(program, tag, key="cycles", trips=LONG):
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
    if failures:
        return checks, failures

    more = LONG - SHORT
    body = 14
    decoded = more * -(-body // fw)
    cached = more * -(-body // cache["width"])
    streamed = more * body // buffer["width"]
    for prefix in ("", "X") if executes else ("",):
        who = lambda tag: machines[prefix + tag]["name"]  # noqa: E731
        checks += 1
        if grew("LOOP", prefix + "PLAIN") != decoded:
            fail(f"{more} more trips of a loop of {body} took {grew('LOOP', prefix + 'PLAIN')} "
                 f"cycles on {who('PLAIN')}; decoded {fw} a cycle with a group ending at its "
                 f"branch, {-(-body // fw)} a trip -- {decoded}")
        checks += 1
        if grew("LOOP", prefix + "CACHE") != cached:
            fail(f"the same took {grew('LOOP', prefix + 'CACHE')} cycles on {who('CACHE')}; "
                 f"from the micro-op cache {cache['width']} a cycle, "
                 f"{-(-body // cache['width'])} a trip -- {cached}")
        checks += 1
        if grew("LOOP", prefix + "LOOPS") != streamed:
            fail(f"the same took {grew('LOOP', prefix + 'LOOPS')} cycles on {who('LOOPS')}; "
                 f"from the loop buffer {buffer['width']} a cycle with no break at the branch, "
                 f"{body} micro-ops a trip -- {streamed}")
        checks += 1
        if grew("BIG", prefix + "LOOPS") != grew("BIG", prefix + "PLAIN"):
            fail(f"{more} more trips of a loop of 18 took {grew('BIG', prefix + 'LOOPS')} "
                 f"cycles on {who('LOOPS')} and {grew('BIG', prefix + 'PLAIN')} on "
                 f"{who('PLAIN')}; a buffer of {buffer['ops']} does not hold it, so the same")
        checks += 1
        if get("ONCE", prefix + "CACHE") != get("ONCE", prefix + "PLAIN"):
            fail(f"a straight line run once took {get('ONCE', prefix + 'CACHE')} cycles on "
                 f"{who('CACHE')} and {get('ONCE', prefix + 'PLAIN')} on {who('PLAIN')}; "
                 f"nothing was in the cache, so the same")
        saved = grew("SPLIT", prefix + "PLAIN", "imiss") - grew("SPLIT", prefix + "CACHE", "imiss")
        checks += 1
        if saved != 2 * more or grew("SPLIT", prefix + "CACHE", "imiss"):
            fail(f"a loop in two lines of one instruction-cache set: {more} more trips missed "
                 f"{grew('SPLIT', prefix + 'PLAIN', 'imiss')} more times on {who('PLAIN')} and "
                 f"{grew('SPLIT', prefix + 'CACHE', 'imiss')} on {who('CACHE')}; decoded, each "
                 f"line puts the other out, and from the micro-op cache nothing is fetched -- "
                 f"{2 * more} and 0")
    # ⚠️ THE COUNTS A HOST READS (pack ABI 10): of the micro-ops the program
    # retired, how many came from the cache and how many from the buffer.
    # Every one of a loop the machine has learned, and none on a machine
    # with neither.
    for prefix in ("", "X") if executes else ("",):
        who = lambda tag: machines[prefix + tag]["name"]  # noqa: E731
        got = {tag: (grew("LOOP", prefix + tag, "cached"), grew("LOOP", prefix + tag, "looped"))
               for tag in ("PLAIN", "CACHE", "LOOPS")}
        checks += 1
        if got != {"PLAIN": (0, 0), "CACHE": (more * body, 0), "LOOPS": (0, more * body)}:
            fail(f"{more} more trips of a loop of {body}: (from the cache, from the buffer) "
                 f"micro-ops {got['PLAIN']} on {who('PLAIN')}, {got['CACHE']} on "
                 f"{who('CACHE')}, {got['LOOPS']} on {who('LOOPS')}; none, all {more * body} "
                 f"from the cache, all {more * body} from the buffer")
        if "CRACKED" in programs:
            checks += 1
            if grew("CRACKED", prefix + "CACHE", "cached") != more * 10:
                fail(f"{more} more trips of six instructions that are ten micro-ops: "
                     f"{grew('CRACKED', prefix + 'CACHE', 'cached')} from the cache on "
                     f"{who('CACHE')}; counted in micro-ops, {more * 10}")
    for prefix in ("", "X") if executes else ("",):
        trips = get("SPIN", prefix + "PLAIN", "steps") // 8
        gained = get("SPIN", prefix + "PLAIN") - get("SPIN", prefix + "CACHE")
        checks += 1
        if cache["window"] != 32 or trips < 100 or gained < trips - 8:
            fail(f"{trips} trips of a loop that is one window, closed by a jump, took "
                 f"{get('SPIN', prefix + 'PLAIN')} cycles on {machines[prefix + 'PLAIN']['name']} "
                 f"and {get('SPIN', prefix + 'CACHE')} on {machines[prefix + 'CACHE']['name']}; "
                 f"the jump lands in the window fetch was already in, which is a lookup all "
                 f"the same -- two groups a trip decoded and one from the cache, so about "
                 f"{trips} fewer")
    # ⚠️ IN MICRO-OPS: six instructions that are ten micro-ops are two cycles
    # of a cache eight wide. Counted as instructions they were one.
    checks += 1
    if "CRACKED" not in programs:
        fail("no load-and-add these cores crack in two: nothing here tells a micro-op from "
             "an instruction")
    else:
        for prefix in ("", "X") if executes else ("",):
            took = grew("CRACKED", prefix + "CACHE")
            checks += 1
            if took != more * -(-10 // cache["width"]):
                fail(f"{more} more trips of six instructions that are ten micro-ops took "
                     f"{took} cycles on {machines[prefix + 'CACHE']['name']}; the micro-op "
                     f"cache delivers {cache['width']} MICRO-OPS a cycle, so "
                     f"{-(-10 // cache['width'])} a trip -- {more * -(-10 // cache['width'])}")
    checks += 1
    if grew("LOOP", "TINY") != decoded:
        fail(f"{more} more trips of a loop of two windows took {grew('LOOP', 'TINY')} cycles "
             f"on {machines['TINY']['name']}, whose micro-op cache holds one; each window puts "
             f"the other out, so it is decoded every time -- {decoded}")
    # ⚠️ FEWER STAGES: every mispredict refills through the cache's stages
    # instead of the front end's, and with a cache no wider than decode that
    # is all that differs.
    refilled = {}
    for prefix in ("", "X"):
        if prefix + "SHORT" not in machines:
            continue
        plain_name, short_name = machines[prefix + "PLAIN"]["name"], machines[prefix + "SHORT"]["name"]
        wrong = grew("ALT", prefix + "PLAIN", "miss")
        short = fe(machines[prefix + "SHORT"])["op_cache"]
        checks += 1
        if wrong <= 0 or grew("ALT", prefix + "SHORT", "miss") != wrong:
            fail(f"the alternating branch mispredicted {wrong} more times on {plain_name} and "
                 f"{grew('ALT', prefix + 'SHORT', 'miss')} on {short_name} over {more} more "
                 f"trips; some, and the same")
        refilled[prefix] = grew("ALT", prefix + "PLAIN") - grew("ALT", prefix + "SHORT")
        checks += 1
        if refilled[prefix] != wrong * (stages - short["depth"]):
            fail(f"{wrong} more mispredicts cost {refilled[prefix]} cycles more on "
                 f"{plain_name} than on {short_name}; each refills through {stages} stages "
                 f"instead of {short['depth']} -- {wrong * (stages - short['depth'])}")
    wrong = grew("ALT", "PLAIN", "miss")
    if executes:
        checks += 1
        if any(grew("LOOP", tag) != grew("LOOP", "X" + tag) for tag in ("PLAIN", "CACHE", "LOOPS")):
            fail("the loop costs the two engines different cycles on some path")
    if not failures:
        print(f"  {name}: {more} more trips of a loop of {body}: {grew('LOOP', 'PLAIN')} cycles "
              f"decoded, {grew('LOOP', 'CACHE')} from the micro-op cache, "
              f"{grew('LOOP', 'LOOPS')} from the loop buffer"
              f"{', on both engines' if executes else ''}; {wrong} mispredicts "
              f"{refilled['']} cycles cheaper through fewer "
              f"stages; {checks} checks")
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
        print("two ways round decode: SKIP")
        return DECLINED
    print(f"two ways round decode: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
