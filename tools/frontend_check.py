#!/usr/bin/env python3
"""Instructions have to be fetched before they can run. Gate.

`(front-end (fetch-width F) (depth D))` on a `defcore` says how instructions
reach dispatch: F a cycle, in groups a predicted-taken branch ends, arriving D
cycles after they were fetched (docs/ooo_design.md, O6). `(btb N)
(btb-penalty M)` says how a taken branch finds its target: from a buffer of N
entries at fetch, or M cycles later from decode (O7). Five machines identical
in everything a program executes on hold each number to a program only it can
explain:

  * **depth is a latency, not a rate**: on straight-line code a front end six
    stages deeper costs exactly six cycles more -- the first instruction
    arrives six later and so does everything behind it;
  * **width bounds throughput**: fetching one a cycle, N instructions cannot
    finish before N + D cycles, however wide the back end;
  * **a taken branch ends the fetch group**: five instructions an iteration
    on a four-wide front end are two groups, so each extra iteration costs
    exactly two cycles, where fetching straight across the branch would cost
    a cycle and a quarter;
  * **a mispredict's refill is the depth**: the front end idles exactly
    (penalty + depth) per mispredict, so the stall and the count are one
    claim, and the deeper machine pays exactly the difference on the first
    fill and again on every one;
  * **a BTB pays for aliasing per iteration**: two taken branches sharing a
    one-entry buffer miss on every iteration, a buffer big enough for both
    misses a constant -- none, here: the direction predictor mispredicts a
    cold branch first, and the buffer learns its target from that -- and
    every miss costs exactly the declared penalty;
  * **the architecture is untouched**.

Usage: tools/frontend_check.py [corpus.axisl ...]
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

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
TRIPS = (8, 16)
STRAIGHT = 24
ONE, MINUS_ONE, COUNTER = 8, 7, 9
#: The indirect jump's target register and the sum of its two targets.
JR_TARGET, JR_SUM = 21, 23
#: Where the jump goes: the fifth and sixth words of its program. ⚠️ NOT the
#: fourth, which is the jump's own fall-through: a jump to the next word is
#: indistinguishable from a branch not taken, and a first version sent every
#: other jump there -- measuring direction mispredicts and no BTB at all.
JR_A, JR_B = ENTRY + 16, ENTRY + 20

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];

static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MEMORY[(a + i) %% IMAGE] << (8 * i);
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) MEMORY[(a + i) %% IMAGE] = (uint8_t)(v >> (8 * i));
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

static void go(const char *tag, const char *core, const uint32_t *words, int32_t count,
               uint32_t trips) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  }
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
%(seeds)s
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)(trips * (uint32_t)count + (uint32_t)count + 8u));
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  printf("%%s cycles %%llu steps %%llu miss %%llu stalls %%llu btb %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->mispredicts(m), (unsigned long long)S->front_end_stalls(m),
         (unsigned long long)S->btb_misses(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->btb_misses) { printf("NOFRONTEND\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def branch_encoder(lift, tests):
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        imms = [o for o in entry["operands"] if o["role"] == "in" and o["kind"] == "imm"]
        if (any(e.get("kind") == "setpc" for e in entry.get("effects") or [])
                and len(regs) == 2 and len(imms) == 1):
            def encode(a, b, offset, test=test, entry=entry, regs=regs, imm=imms[0]):
                word = lift.place_operand(int(test["encoded"], 16), entry, regs[0]["name"], a)
                word = lift.place_operand(word, entry, regs[1]["name"], b)
                return lift.place_operand(word, entry, imm["name"], offset & ((1 << 13) - 1))
            return encode
    return None


def jump_encoder(lift, tests):
    """An unconditional jump to a register: one register in, a link out."""
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        effects = entry.get("effects") or []
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        imms = [o for o in entry["operands"] if o["role"] == "in" and o["kind"] == "imm"]
        if (any(e.get("kind") == "setpc" and "when" not in json.dumps(e) for e in effects)
                and len(regs) == 1 and len(outs) == 1 and len(imms) == 1
                and regs[0]["name"] in json.dumps(effects)):
            def encode(link, target, test=test, entry=entry, reg=regs[0], out=outs[0], imm=imms[0]):
                word = lift.place_operand(int(test["encoded"], 16), entry, out["name"], link)
                word = lift.place_operand(word, entry, reg["name"], target)
                return lift.place_operand(word, entry, imm["name"], 0)
            return encode
    return None


def build_programs(asm: Assembler, bnz):
    add = asm.fast_add
    straight = [asm.op(add, 10 + k % 12, 1, 2) for k in range(STRAIGHT)]
    # ⚠️ A loop of FIVE: three independent adds, the count, the branch back.
    # One more than a fetch group, so a front end that ends the group at the
    # taken branch needs two fetch cycles an iteration, and one that fetched
    # straight across it would need a cycle and a quarter. A first version had
    # three instructions an iteration -- and ran one a cycle whatever the
    # front end did, because the counter is a one-cycle dependence carried
    # round the loop and that, not fetch, was the bound.
    loop = [asm.op(add, 16, 1, 2), asm.op(add, 17, 1, 2), asm.op(add, 18, 1, 2),
            asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -16),
            asm.op(add, 15, 1, 1)]
    # ⚠️ TWO taken branches an iteration: one that always jumps over an
    # instruction, and the one back. In a one-entry target buffer they evict
    # each other every time.
    two = [asm.op(add, 14, 14, 1), bnz(ONE, 0, 8), asm.op(add, 16, 16, 1),
           asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -16),
           asm.op(add, 15, 1, 1)]
    # ⚠️ A MISPREDICT WAITS FOR ITS BRANCH. The same cold taken branch --
    # mispredicted, since a cold counter says "not taken" -- once on a
    # register that is ready and once on one two multiplies away. Fetch cannot
    # restart until the branch knows where it goes, so the late one refills
    # later. Every other branch here resolved at once, and a front end that
    # restarted before resolution passed them all -- mutation testing said so.
    def resolving(reg):
        return [asm.op(asm.slow, 20, 1, 1), asm.op(asm.slow, 20, 20, 20), bnz(reg, 0, 8),
                asm.op(add, 25, 1, 1), asm.op(add, 26, 1, 1), asm.op(add, 27, 26, 26),
                asm.op(add, 28, 27, 27)]
    # ⚠️ AN INDIRECT JUMP WHOSE TARGET ALTERNATES. A target buffer holds the
    # target a branch took last time, so a jump that alternates between two
    # misses every iteration even in a buffer with room to spare.
    # x21 flips between A and B: x21 = (A + B) - x21, the minus as a multiply
    # by minus one.
    jr = [asm.op(asm.slow, 24, JR_TARGET, MINUS_ONE), asm.op(add, JR_TARGET, JR_SUM, 24),
          asm.jump(0, JR_TARGET), asm.op(add, 29, 1, 1),   # never reached
          asm.op(add, 16, 1, 2), asm.op(add, 17, 1, 2),
          asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -28),
          asm.op(add, 15, 1, 1)]
    return {"STRAIGHT": straight, "LOOP": loop, "TWO": two,
            "SLOWBRANCH": resolving(20), "FASTBRANCH": resolving(1), "JR": jr}


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    # ⚠️ TRACE-DRIVEN cores only: this gate's arithmetic -- a perfect target
    # buffer when none is declared, a refill paid from the predicted path the
    # trace names -- is the trace engine's. An execution-driven core learns
    # every target, and when the corpus grew one with a 64-entry BTB it became
    # this gate's "big BTB" and the counts stopped meaning anything.
    fronted = [core for core in facts.get("cores", [])
               if core.get("front_end") and core.get("engine") != "execute"]

    def same(a, b):
        keys = ("issue_width", "units", "rob", "issue_queue", "commit_width",
                "branch_penalty", "predictor", "predictor_entries", "lsq", "rename")
        return all(a.get(k) == b.get(k) for k in keys)

    def find(**want):
        return next((core for core in fronted
                     if all(core["front_end"].get(k) == v for k, v in want.items())), None)

    base = find(fetch_width=4, btb=0)
    machines = {"BASE": base}
    if base:
        depth = base["front_end"]["depth"]
        machines["DEEP"] = next((c for c in fronted if same(c, base)
                                 and c["front_end"]["fetch_width"] == 4
                                 and c["front_end"]["btb"] == 0
                                 and c["front_end"]["depth"] > depth), None)
        machines["NARROW"] = next((c for c in fronted if same(c, base)
                                   and c["front_end"]["fetch_width"] == 1
                                   and c["front_end"]["depth"] == depth), None)
        btbs = sorted((c for c in fronted if same(c, base) and c["front_end"]["btb"]
                       and c["front_end"]["depth"] == depth
                       and c["front_end"]["fetch_width"] == 4),
                      key=lambda c: c["front_end"]["btb"])
        machines["SMALLBTB"] = btbs[0] if btbs and btbs[0]["front_end"]["btb"] == 1 else None
        machines["BIGBTB"] = btbs[-1] if len(btbs) > 1 and btbs[-1]["front_end"]["btb"] >= 2 else None
        machines["STARVED"] = next((c for c in fronted if same(c, base)
                                    and c["front_end"]["buffer"]
                                    and c["front_end"]["buffer"]
                                    < c["front_end"]["fetch_width"] * c["front_end"]["depth"]),
                                   None)
    missing = [tag for tag, core in machines.items() if core is None]
    if not base or missing:
        print(f"  {name}: DECLINED no {', '.join(missing) or 'four-wide front-end'} core")
        return 0, 0

    module = f"fe_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    asm.jump = jump_encoder(lift, tests)
    if asm.fast_add is None or bnz is None or asm.jump is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED no two-register add or two-register branch")
        return 0, 0
    programs = build_programs(asm, bnz)
    kind = next(o["kind"] for o in asm.by_mnemonic[asm.fast_add]["operands"]
                if o["role"] in ("out", "inout"))
    slot = lambda i: lift.register_slot(kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    runs = [f'  go("{program}_{tag}_{trips}", "{core["name"]}", {program}, '
            f'(int32_t)(sizeof {program} / sizeof {program}[0]), {trips}u);'
            for program in programs for tag, core in machines.items() for trips in TRIPS]
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY,
        "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
        "seeds": f"  S->set_reg(m, {slot(JR_TARGET)}, {JR_B}u);\n"
                 f"  S->set_reg(m, {slot(JR_SUM)}, {JR_A + JR_B}u);",
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs),
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / name), str(work / f"{name}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}")
        return 0, 1
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 13 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    low, high = TRIPS
    for program in programs:
        for trips in TRIPS:
            rows = [said.get(f"{program}_{tag}_{trips}") for tag in machines]
            checks += 1
            if any(row is None for row in rows):
                fail(f"{program} at {trips} trips reported nothing on some machine")
                continue
            checks += 1
            if len({(row["steps"], row["mark"]) for row in rows}) != 1:
                fail(f"{program} at {trips} trips retired different instructions or left "
                     f"different registers on different machines")
    if failures:
        return checks, failures

    def get(program, tag, trips=low, key="cycles"):
        return said[f"{program}_{tag}_{trips}"][key]

    depth = base["front_end"]["depth"]
    deep = machines["DEEP"]["front_end"]["depth"]
    # ⚠️ DEPTH IS A LATENCY, NOT A RATE.
    checks += 1
    if get("STRAIGHT", "DEEP") - get("STRAIGHT", "BASE") != deep - depth:
        fail(f"{STRAIGHT} straight-line instructions cost {get('STRAIGHT', 'BASE')} at depth "
             f"{depth} and {get('STRAIGHT', 'DEEP')} at depth {deep}; with nothing to refill, "
             f"depth is paid once, so the two must differ by exactly {deep - depth}")
    # ⚠️ WIDTH BOUNDS THROUGHPUT.
    checks += 1
    floor = STRAIGHT + depth
    if get("STRAIGHT", "NARROW") < floor:
        fail(f"{STRAIGHT} instructions fetched one a cycle at depth {depth} cannot finish "
             f"before {floor}; the machine reported {get('STRAIGHT', 'NARROW')}")
    checks += 1
    if get("STRAIGHT", "BASE") >= get("STRAIGHT", "NARROW"):
        fail(f"fetching four a cycle cost {get('STRAIGHT', 'BASE')} and one a cycle "
             f"{get('STRAIGHT', 'NARROW')}; the width is not being read")
    # ⚠️ A TAKEN BRANCH ENDS THE FETCH GROUP: five instructions an iteration
    # on a four-wide fetch are two groups, so each extra iteration costs
    # exactly two cycles once the loop is predicted.
    width = base["front_end"]["fetch_width"]
    groups = -(-5 // width)
    checks += 1
    per = get("LOOP", "BASE", high) - get("LOOP", "BASE", low)
    if per != groups * (high - low):
        fail(f"{high - low} more iterations of a five-instruction loop cost {per} more cycles "
             f"on a {width}-wide front end; the taken branch ends each iteration's second group, "
             f"so they must cost exactly {groups * (high - low)}")
    # ⚠️ A MISPREDICT'S REFILL IS THE DEPTH, and the front end says so.
    for program in ("LOOP", "TWO"):
        for tag in ("BASE", "DEEP"):
            for trips in TRIPS:
                row = said[f"{program}_{tag}_{trips}"]
                fe = machines[tag]["front_end"]
                checks += 1
                if row["stalls"] != row["miss"] * (fe["depth"] + machines[tag]["branch_penalty"]):
                    fail(f"{program} on {machines[tag]['name']} at {trips} trips: {row['miss']} "
                         f"mispredicts idled the front end {row['stalls']} cycles, not "
                         f"{row['miss']} x depth {fe['depth']}")
    # And the deeper machine pays the difference on every one of them, and on
    # the first fill: exactly (deeper) x (mispredicts + 1).
    for program in ("LOOP", "TWO"):
        for trips in TRIPS:
            checks += 1
            extra = get(program, "DEEP", trips) - get(program, "BASE", trips)
            refills = get(program, "BASE", trips, "miss") + 1
            if extra != (deep - depth) * refills:
                fail(f"{program} at {trips} trips, with {refills - 1} mispredicts, cost {extra} "
                     f"more at depth {deep} than at {depth}; the first fill and every refill are "
                     f"{deep - depth} deeper, so exactly {(deep - depth) * refills}")
    # ⚠️ A MISPREDICT WAITS FOR ITS BRANCH: the late one refills later by at
    # least the time its operand took, on a front end deep enough that the
    # refill, not the multiplies, is the program's tail.
    slow_lat = asm.cost(asm.slow)
    checks += 1
    later = get("SLOWBRANCH", "DEEP") - get("FASTBRANCH", "DEEP")
    if later < 2 * slow_lat:
        fail(f"a mispredicted branch on a register two {asm.slow}s away cost {later} more "
             f"than the same branch on a ready one; fetch restarts when the branch resolves, "
             f"at least {2 * slow_lat} later")
    # ⚠️ A BTB HOLDS THE LAST TARGET: an indirect jump that alternates misses
    # every iteration, even in a buffer with room to spare.
    jr = [get("JR", "BIGBTB", t, "btb") for t in TRIPS]
    checks += 1
    if jr[1] - jr[0] != high - low:
        fail(f"an indirect jump alternating between two targets missed a "
             f"{machines['BIGBTB']['front_end']['btb']}-entry BTB {jr[0]} and {jr[1]} times at "
             f"{low} and {high} trips; the buffer holds the last target, so every extra "
             f"iteration misses once")
    # ⚠️ A BUFFER SMALLER THAN THE PIPELINE STARVES IT: at most `buffer`
    # instructions reach dispatch per `depth` cycles.
    fe = machines["STARVED"]["front_end"]
    floor = -(-STRAIGHT // fe["buffer"]) * fe["depth"]
    checks += 1
    if get("STRAIGHT", "STARVED") < floor:
        fail(f"{STRAIGHT} instructions through a front end {fe['depth']} deep that holds "
             f"{fe['buffer']} cannot finish before {floor}; the machine reported "
             f"{get('STRAIGHT', 'STARVED')}")
    # ⚠️ A BTB PAYS FOR ALIASING PER ITERATION.
    small = [get("TWO", "SMALLBTB", t, "btb") for t in TRIPS]
    big = [get("TWO", "BIGBTB", t, "btb") for t in TRIPS]
    checks += 1
    if big[0] != big[1]:
        fail(f"a {machines['BIGBTB']['front_end']['btb']}-entry BTB missed {big[0]} and {big[1]} "
             f"times at {low} and {high} trips of two taken branches; with room for both, what "
             f"it misses is a constant")
    checks += 1
    if small[1] - small[0] < 2 * (high - low) - 2:
        fail(f"a one-entry BTB missed {small[0]} and {small[1]} times at {low} and {high} trips "
             f"of two taken branches; they evict each other, so it must miss about twice an "
             f"iteration")
    # ⚠️ And each miss costs exactly the declared penalty in time.
    penalty = machines["SMALLBTB"]["front_end"]["btb_penalty"]
    for i, trips in enumerate(TRIPS):
        checks += 1
        extra = get("TWO", "SMALLBTB", trips) - get("TWO", "BIGBTB", trips)
        if extra != (small[i] - big[i]) * penalty:
            fail(f"at {trips} trips the aliasing BTB missed {small[i] - big[i]} more times and "
                 f"cost {extra} more cycles; at a penalty of {penalty} that is exactly "
                 f"{(small[i] - big[i]) * penalty}")
    for tag in ("BASE", "DEEP", "NARROW", "STARVED"):
        checks += 1
        if any(get(p, tag, t, "btb") for p in programs for t in TRIPS):
            fail(f"{machines[tag]['name']} declares no BTB and reported BTB misses")

    if not failures:
        print(f"  {name}: straight line {get('STRAIGHT', 'BASE')} at depth {depth}, "
              f"{get('STRAIGHT', 'DEEP')} at {deep}, {get('STRAIGHT', 'NARROW')} fetching one; "
              f"a 5-instruction loop {per} cycles per {high - low} iterations; BTB misses "
              f"{small[0]}/{small[1]} aliasing vs {big[0]}/{big[1]}; {checks} checks")
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
        print("instructions are fetched before they run: SKIP")
        return DECLINED
    print(f"instructions are fetched before they run: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
