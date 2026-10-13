#!/usr/bin/env python3
"""A cracked instruction is several micro-ops. Gate.

`(timing (micro-ops (MNEMONIC (unit cycles) ...)))` (docs/micro_ops_design.md,
U1): a core divides an instruction into micro-ops, each with its own entry in
the window, its own unit and its own latency. The core says the unit and the
cycles; what each micro-op reads, writes and loads is derived from the
instruction's effects. Two machines identical but for the clause, and two
instructions -- a load with an add in it, and a load that moves its base on:

  * **a result that reads no load waits for no load**: a chain of
    load-and-move-the-base through one base register runs at an ADD a link
    cracked, and at the whole instruction a link uncracked;
  * **a load does not wait for what is added to it**: a chain of
    load-and-add through the sum runs at an add a link cracked -- the loads,
    whose address is ready, are all made early;
  * **a micro-op is a place in every width**: independent load-and-adds
    start, issue and retire half as many a cycle cracked as uncracked;
  * **and is on the unit the core gave it**: with the add on a unit the
    machine has one of, one load-and-add finishes a cycle;
  * **a result computed from a load waits for the load**: one cold
    load-and-add ahead of a chain of multiplies costs the same cracked as
    not;
  * **the plan a core publishes is the plan derived**: which micro-op reads
    and writes what, and which loads, is in `emit-uarch-json` and is what the
    two instructions' effects say;
  * **the engine that executes them agrees**: on a pair that executes what
    it fetches, the same cycles -- and no replay, which is the golden model
    disagreeing with what a micro-op computed;
  * and every program retires the same instructions and leaves the same
    registers and memory on every machine.

Usage: tools/micro_ops_check.py [corpus.axisl ...]
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
import redirect_check  # noqa: E402
from redirect_check import BASE, DATA, ONE, harness_run  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402

# This gate reads REPLAYS where the front-end gates read target-buffer misses:
# an engine that executes micro-ops answers to the golden model for them.
assert "btb %%llu" in redirect_check.HARNESS and "S->btb_misses(m)" in redirect_check.HARNESS
# ... and data-cache HITS where they read instruction-cache misses: an access
# is one micro-op's, and made once.
assert "imiss %%llu" in redirect_check.HARNESS and "S->icache_misses(m)" in redirect_check.HARNESS
# ... and MICRO-OPS retired where they read mispredicts (pack ABI 10).
assert "miss %%llu btb" in redirect_check.HARNESS and "S->mispredicts(m)" in redirect_check.HARNESS
redirect_check.HARNESS = (redirect_check.HARNESS.replace("btb %%llu", "replays %%llu")
                          .replace("(unsigned long long)S->btb_misses(m)",
                                   "(unsigned long long)S->replays(m)")
                          .replace(" miss %%llu ", " uops %%llu ")
                          .replace("(unsigned long long)S->mispredicts(m)",
                                   "(unsigned long long)S->micro_ops(m)")
                          .replace("imiss %%llu", "dhits %%llu")
                          .replace("(unsigned long long)S->icache_misses(m)",
                                   "(unsigned long long)S->cache_hits(m)"))

AXIS_ROOT = Path(__file__).resolve().parent.parent
# ⚠️ Chains LONGER than a cold miss. The first load of every program misses,
# and at 8 and 16 links the whole of a cracked chain ran inside that miss:
# the machine was waiting to retire, not for the chain, and 8 more links cost
# 4 cycles -- the commit width.
SHORT, LONG = 24, 48
SUM, FIRST = 20, 21


def effects_of(entry):
    return entry.get("effects") or []


def find(lift, tests):
    """(load-and-add, load-and-move): by what their effects are."""
    tested = {t["mnemonic"] for t in tests}
    add = move = None
    for entry in lift.AXIS_LIFT_TABLE:
        if entry["mnemonic"] not in tested:
            continue
        effects = effects_of(entry)
        regs_in = [o for o in entry["operands"]
                   if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        outs = [o for o in entry["operands"] if o["role"] == "out"]
        both = [o for o in entry["operands"] if o["role"] == "inout"]
        text = json.dumps(effects)
        if (len(effects) == 1 and effects[0].get("kind") == "set" and '"load"' in text
                and (effects[0].get("value_ast") or {}).get("op") == "add"
                and len(regs_in) == 2 and len(outs) == 1 and add is None):
            value = effects[0]["value_ast"]
            addend = next((o["name"] for o in regs_in
                           if {"symbol": o["name"]} in value.get("args", [])), None)
            address = next((o["name"] for o in regs_in if o["name"] != addend), None)
            if addend and address:
                add = (entry["mnemonic"], outs[0]["name"], address, addend)
        elif (len(effects) == 2 and all(e.get("kind") == "set" for e in effects)
              and len(outs) == 1 and len(both) == 1 and not regs_in and move is None):
            imm = next((o["name"] for o in entry["operands"] if o["kind"] == "imm"), None)
            if imm:
                move = (entry["mnemonic"], outs[0]["name"], both[0]["name"], imm)
    return add, move


def find_by_register(lift, tests):
    """A load that moves its base on by a register: (mnemonic, out, base, by)."""
    tested = {t["mnemonic"] for t in tests}
    for entry in lift.AXIS_LIFT_TABLE:
        effects = effects_of(entry)
        regs_in = [o for o in entry["operands"]
                   if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        outs = [o for o in entry["operands"] if o["role"] == "out"]
        both = [o for o in entry["operands"] if o["role"] == "inout"]
        if (entry["mnemonic"] in tested and len(effects) == 2
                and all(e.get("kind") == "set" for e in effects)
                and len(outs) == 1 and len(both) == 1 and len(regs_in) == 1):
            return entry["mnemonic"], outs[0]["name"], both[0]["name"], regs_in[0]["name"]
    return None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    uarch = json.loads(run_cmd([*axis_prefix(), "emit-uarch-json", str(axis_file)]).stdout)
    plans = {row["core"]: {c["mnemonic"]: c["micro_ops"] for c in row.get("cracked", [])}
             for row in uarch.get("timing", [])}
    every = facts.get("cores", [])

    def twin_of(core):
        return next((c for c in every if c is not core and not plans.get(c["name"])
                     and all(c.get(k) == core.get(k) for k in core if k != "name")), None)

    def pair(executing):
        return next(((c, twin_of(c)) for c in every
                     if plans.get(c["name"]) and c.get("memory") and twin_of(c)
                     and (c.get("engine") == "execute") == executing), (None, None))

    cores = [c for c in every if c.get("engine") != "execute"]
    (cracks, plain), (xcracks, xplain) = pair(False), pair(True)
    name = axis_file.stem
    if not plain:
        print(f"  {name}: DECLINED no core that cracks an instruction, with a twin that does not")
        return 0, 0
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    module = f"mo_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in facts["instructions"]}
    latency_of = {m: entry.get("latency_cycles", 1) for m, entry in by_mnemonic.items()}
    asm = Assembler(lift, tests, latency_of)
    add, move = find(lift, tests)
    bnz = branch_encoder(lift, tests)
    by_register = find_by_register(lift, tests)
    plan = plans[cracks["name"]]
    if asm.missing() or bnz is None or not add or not move or add[0] not in plan or move[0] not in plan:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no cracked load-and-add and load-and-move'}")
        return 0, 0
    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    # ---- the plan: derived, and what the effects say ----------------------
    def shape(ops):
        return [(bool(o["accesses"]), sorted(o["reads"]), sorted(o["writes"]), o["after"])
                for o in ops]

    a_name, a_out, a_addr, a_addend = add
    m_name, m_out, m_base, m_imm = move
    want_add = [(True, [a_addr], [], []), (False, [a_addend], [a_out], [0])]
    want_move = [(True, [m_base], [m_out], []), (False, sorted([m_base, m_imm]), [m_base], [])]
    for mnemonic, want, why in (
            (a_name, want_add, "the load reads the address and writes nothing a register "
                               "holds; the add reads the addend, writes the result, and waits "
                               "for the load"),
            (m_name, want_move, "the load reads the base and writes what it loaded; the add "
                                "reads the base and the offset, writes the base, and waits "
                                "for nothing")):
        checks += 1
        if shape(plan[mnemonic]) != want:
            fail(f"{cracks['name']} publishes {mnemonic} as {shape(plan[mnemonic])}; its "
                 f"effects say {want} -- {why}")
    if failures:
        sys.modules.pop(module, None)
        return checks, failures
    # ⚠️ The arithmetic below is in THESE numbers: a load-and-add whose two
    # micro-ops' cycles sum to the whole instruction's -- they run one after
    # the other -- and a load-and-move whose load takes what the instruction
    # does, its add running beside it. So the two machines differ in what
    # waits for what and in nothing else.
    cycles = {m: [o["latency"] for o in plan[m]] for m in (a_name, m_name)}
    whole = {m: latency_of[m] for m in (a_name, m_name)}
    width = cracks.get("issue_width") or 1
    if (sum(cycles[a_name]) != whole[a_name] or cycles[m_name][0] != whole[m_name] or width % 2
            or (cracks.get("commit_width") or width) != width):
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED the micro-ops' cycles do not sum to their instruction's, or "
              f"the widths are odd or differ")
        return 0, 0

    def chain_move(n):
        return [asm._word(m_name, **{m_out: FIRST + k % 4, m_base: BASE, m_imm: 0})
                for k in range(n)] + [0]

    def chain_add(n):
        return [asm._word(a_name, **{a_out: SUM, a_addr: BASE, a_addend: SUM})
                for _ in range(n)] + [0]

    def apart(n):
        return [asm._word(a_name, **{a_out: FIRST + k % 4, a_addr: BASE, a_addend: ONE})
                for k in range(n)] + [0]

    # ⚠️ WAITS: one load-and-add, cold, and eight multiplies of its sum. The
    # sum is ready when the load AND the add are done, cracked or not -- the
    # same cycle, since the two micro-ops' cycles are the instruction's. An
    # add that did not wait for its load handed the multiplies a sum ten
    # cycles early, and no chain above can see that: they retire behind the
    # load either way.
    programs = {"WAITS": [asm._word(a_name, **{a_out: SUM, a_addr: BASE, a_addend: ONE})]
                + [asm.op(asm.slow, SUM, SUM, ONE)] * 8 + [0]}
    # ⚠️ MIXED: a loop that stores a word, loads-and-adds that same word, moves
    # a base on past it, and branches. Nothing here is measured in cycles. On
    # a machine that orders no memory the load-and-add's load runs ahead of
    # the store and is squashed when the store executes -- from the FIRST
    # micro-op of its instruction, which is not the one that loaded -- and
    # the loop's branch mispredicts with cracked instructions on both sides of
    # it. An instruction left half in the window by either would retire wrong
    # registers, or not at all.
    programs["MIXED"] = [asm.op(asm.slow, SUM, SUM, ONE), asm.st(SUM, BASE, 0),
                         asm._word(a_name, **{a_out: SUM, a_addr: BASE, a_addend: SUM}),
                         asm._word(m_name, **{m_out: FIRST, m_base: FIRST + 1, m_imm: 4}),
                         asm.op(asm.fast_add, 9, 9, 7), bnz(9, 0, -20),
                         asm._word(a_name, **{a_out: FIRST + 2, a_addr: BASE, a_addend: ONE}), 0]
    # ⚠️ SELF: a load that moves its base on INTO the register it loads to.
    # The add micro-op executes the instruction on the registers as they were
    # before it; one that saw its sibling's load already laid over the base
    # moved on from what was loaded, and the golden model said so.
    programs["SELF"] = [asm._word(m_name, **{m_out: FIRST + 1, m_base: FIRST + 1, m_imm: 4})] * 4 + [0]
    # ⚠️ STEP: four loads that move their base on by four, into registers of
    # their own. Not a chain -- BASE moves on by nothing, so that no load
    # misses, and a base that was never written back looked no different.
    programs["STEP"] = [asm._word(m_name, **{m_out: FIRST, m_base: FIRST + 1, m_imm: 4})] * 4 + [0]
    # ⚠️ LATE: a load that moves its base on by a register eight multiplies
    # away, and adds of what it loaded meanwhile. The loading micro-op has
    # long finished when the add can start, and what it loaded is in use: it
    # must still be in the window -- an instruction retires whole.
    if by_register and by_register[0] in plan:
        x_name, x_out, x_base, x_by = by_register
        programs["LATE"] = ([asm.op(asm.slow, 10, ONE, ONE)] + [asm.op(asm.slow, 10, 10, ONE)] * 7
                            + [asm._word(x_name, **{x_out: FIRST, x_base: FIRST + 1, x_by: 10})]
                            + [asm.op(asm.fast_add, FIRST + 2, FIRST, ONE)]
                            + [asm.op(asm.fast_add, FIRST + 2, FIRST + 2, ONE)] * 6 + [0])
    for tag, build, scale in (("BASE", chain_move, 1), ("SUM", chain_add, 1),
                              ("APART", apart, width)):
        for n in (SHORT, LONG):
            programs[f"{tag}{n}"] = build(n * scale)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)
    seeds = {"counter": slot(9), slot(ONE): 1, slot(7): 0xFFFFFFFF, slot(BASE): DATA,
             slot(SUM): 3, slot(FIRST + 1): DATA}
    machines = {"CRACKS": cracks, "PLAIN": plain}
    # A third machine whose add micro-op is on a unit it has ONE of.
    def elsewhere(core):
        ops = plans.get(core["name"], {}).get(a_name) or []
        units = {u["name"]: u.get("count") or 1 for u in core.get("units") or []}
        return (len(ops) == 2 and units.get(ops[1]["unit"]) == 1
                and all(core.get(k) == plain.get(k) for k in plain if k != "name"))
    scarce = next((c for c in cores if c is not cracks and elsewhere(c)), None)
    if scarce:
        machines["SCARCE"] = scarce
    # And the pair that EXECUTES its micro-ops, if the corpus has one whose
    # plan is the same plan.
    if xcracks and plans[xcracks["name"]] == plans[cracks["name"]] and all(
            xcracks.get(k) == cracks.get(k) for k in ("issue_width", "commit_width", "units")):
        machines["XCRACKS"], machines["XPLAIN"] = xcracks, xplain
    lines = [f'  go("{p}_{t}_0", "{c["name"]}", {p}, {len(programs[p])}, 6u);'
             for p in programs for t, c in machines.items()]
    said = harness_run(work, manifest, name, isa, seeds, programs, lines, 8)
    if said is None:
        fail("the harness did not run")
        return checks + 1, failures

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
                 f"memory on the two machines: {[r['steps'] for r in rows]}")
    if failures:
        return checks, failures

    def grew(tag, machine):
        return get(f"{tag}{LONG}", machine) - get(f"{tag}{SHORT}", machine)

    more = LONG - SHORT
    pairs = [("CRACKS", "PLAIN")] + ([("XCRACKS", "XPLAIN")] if "XCRACKS" in machines else [])
    for cracked, whole_tag in pairs:
        on, off = machines[cracked]["name"], machines[whole_tag]["name"]
        for tag, mnemonic, link, what in (
                ("BASE", m_name, cycles[m_name][1],
                 "its next link reads the base, which the add micro-op wrote without waiting "
                 "for the load"),
                ("SUM", a_name, cycles[a_name][1],
                 "its next link reads the sum, and every load was made early -- its address "
                 "was ready")):
            checks += 1
            if grew(tag, whole_tag) != more * whole[mnemonic]:
                fail(f"{more} more links of a chain of {mnemonic} took {grew(tag, whole_tag)} "
                     f"cycles on {off}; uncracked, each link is the whole instruction, "
                     f"{whole[mnemonic]} -- {more * whole[mnemonic]}")
            checks += 1
            if grew(tag, cracked) != more * link:
                fail(f"{more} more links of a chain of {mnemonic} took {grew(tag, cracked)} "
                     f"cycles on {on}; {what}, so each link is {link} -- {more * link}")
        checks += 1
        if grew("APART", whole_tag) != more or grew("APART", cracked) != 2 * more:
            fail(f"{more * width} more independent {a_name} took {grew('APART', whole_tag)} "
                 f"cycles on {off} and {grew('APART', cracked)} on {on}; a machine {width} "
                 f"wide starts {width} instructions a cycle or {width} micro-ops, and these "
                 f"are two each -- {more} and {2 * more}")
        checks += 1
        if get("WAITS", cracked) != get("WAITS", whole_tag):
            fail(f"one cold {a_name} and eight multiplies of its sum took "
                 f"{get('WAITS', cracked)} cycles on {on} and {get('WAITS', whole_tag)} on "
                 f"{off}; the add waits for the load, and their cycles are the "
                 f"instruction's, so the same")
    # ⚠️ THE GOLDEN MODEL AGREED with every micro-op: an engine that executes
    # them computes each one's part from what the window had made when IT
    # issued, and a part computed from the wrong registers is a replay.
    for tag in ("XCRACKS", "XPLAIN"):
        if tag not in machines:
            continue
        checks += 1
        replayed = {p: get(p, tag, "replays") for p in programs
                    if p != "MIXED" and get(p, tag, "replays")}
        if replayed:
            fail(f"{machines[tag]['name']} replayed {replayed}; nothing in these programs is "
                 f"speculated, so the golden model disagreed with what a micro-op computed")
    # ⚠️ THE COUNT A HOST READS (pack ABI 10): micro-ops the program retired.
    # One an instruction on a machine that cracks nothing; two for each of
    # these on one that cracks them, on either engine.
    for tag, core in machines.items():
        each = 1 if tag in ("PLAIN", "XPLAIN") else 2
        for program in ("BASE", "SUM", "APART"):
            if tag == "SCARCE" and program == "BASE":
                continue
            for n in (SHORT, LONG):
                key = f"{program}{n}"
                checks += 1
                if get(key, tag, "uops") != each * get(key, tag, "steps"):
                    fail(f"{core['name']} reports {get(key, tag, 'uops')} micro-ops for "
                         f"{key}, which retired {get(key, tag, 'steps')} instructions; "
                         f"{each} each -- {each * get(key, tag, 'steps')}")
    # ⚠️ AN ACCESS IS MADE ONCE: by the micro-op it was given to.
    if "XCRACKS" in machines:
        twice = {p: (get(p, "XCRACKS", "dhits"), get(p, "XPLAIN", "dhits")) for p in programs
                 if p != "MIXED" and get(p, "XCRACKS", "dhits") != get(p, "XPLAIN", "dhits")}
        checks += 1
        if twice:
            fail(f"{machines['XCRACKS']['name']} and its twin count different data-cache hits "
                 f"{twice}; a cracked instruction's load is one micro-op's, and is made once")
    # ⚠️ ITS OWN UNIT: with the add on the one multiplier, one a cycle.
    if scarce:
        checks += 1
        if grew("APART", "SCARCE") != more * width:
            fail(f"{more * width} more independent {a_name} took {grew('APART', 'SCARCE')} "
                 f"cycles on {scarce['name']}, whose add micro-op is on a unit it has one of; "
                 f"one finishes a cycle, so {more * width}")
    checks += 1
    if "XCRACKS" in machines and "LATE" not in programs:
        fail("no cracked load that moves its base on by a register: nothing here keeps a "
             "second micro-op waiting after the first has finished")
    checks += 1
    if "XCRACKS" in machines and not get("MIXED", "XCRACKS", "wrong"):
        fail(f"the mixed loop squashed nothing on {machines['XCRACKS']['name']}; it has to "
             f"mispredict with cracked instructions in the window to say they leave it whole")
    if not failures:
        print(f"  {name}: {more} more links through a base cost {grew('BASE', 'CRACKS')} cycles "
              f"cracked and {grew('BASE', 'PLAIN')} not, through a sum {grew('SUM', 'CRACKS')} "
              f"and {grew('SUM', 'PLAIN')}; {more * width} more independent ones "
              f"{grew('APART', 'CRACKS')} and {grew('APART', 'PLAIN')}; {checks} checks")
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
        print("a cracked instruction is several micro-ops: SKIP")
        return DECLINED
    print(f"a cracked instruction is several micro-ops: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
