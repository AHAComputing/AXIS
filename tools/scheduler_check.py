#!/usr/bin/env python3
"""The scheduler has limits of its own. Gate.

Four things a window said nothing about (docs/scheduler_design.md, S1-S3):
`(window ... (dispatch-width N) (schedule N))`, `(bypass (FROM TO N) ...)`
and a unit's `(queue N)`. One machine, and what it is with each, on each
engine:

  * **what enters the window a cycle is its own number**: independent adds
    start four a cycle on a machine four wide, and two on one that dispatches
    two;
  * **a dependent issues no sooner than the loop allows**: a chain of
    one-cycle adds runs at two cycles a link through a two-cycle
    wakeup-and-select loop -- and a chain of three-cycle multiplies, which
    the loop is shorter than, at three as before;
  * **a result costs cycles to cross units**: a chain that alternates a
    multiply and an add pays the multiplier-to-adder bypass once a pair --
    and a chain of adds alone, or of multiplies alone, pays nothing;
  * **a unit's queue is a door**: with room for two to wait for the
    multiplier, a chain of multiplies lets one more in only as one issues --
    so a chain of adds behind them starts three cycles later for every
    multiply more, where a machine with one queue for everything starts it a
    dispatch group later;
  * and every program retires the same instructions and leaves the same
    registers and memory on every machine.

Usage: tools/scheduler_check.py [corpus.axisl ...]
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
from redirect_check import DATA, ONE, harness_run  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
SHORT, LONG = 32, 64
A, B, C = 20, 21, 22


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = [c for c in facts.get("cores", []) if c.get("front_end")]
    name = axis_file.stem
    said = ("dispatch_width", "schedule", "bypass")

    def plain_units(core):
        return [{k: v for k, v in u.items() if k != "queue"} for u in core.get("units") or []]

    def differs_only(core, base, what):
        """`core` is `base` but for the one scheduler clause `what`."""
        if core is base or any(core.get(k) != base.get(k) for k in base
                               if k not in ("name", "units", *said)):
            return False
        if plain_units(core) != plain_units(base):
            return False
        queued = [u for u in core["units"] if u.get("queue")]
        has = {k for k in said if core.get(k)} | ({"queue"} if queued else set())
        return has == {what}

    def family(executing):
        for base in cores:
            if ((base.get("engine") == "execute") != executing or any(base.get(k) for k in said)
                    or any(u.get("queue") for u in base.get("units") or [])):
                continue
            found = {what: next((c for c in cores if differs_only(c, base, what)), None)
                     for what in (*said, "queue")}
            if all(found.values()):
                def also(key):
                    # The same machine saying `key` and nothing else of its own.
                    return next((c for c in cores if c is not base and c.get(key)
                                 and c.get("rename_width", 1) == 1
                                 and all(c.get(k) == base.get(k) for k in base if k != "name")
                                 and set(c) - set(base) == {key}), None)
                return {"PLAIN": base, "NARROW": found["dispatch_width"], "LOOP": found["schedule"],
                        "BYPASS": found["bypass"], "QUEUE": found["queue"],
                        "SHARED": also("queues"), "RENAME": also("rename_width"),
                        "RENAME2": next((c for c in cores if c.get("rename_width") == 2
                                         and all(c.get(k) == base.get(k) for k in base if k != "name")
                                         and set(c) - set(base) == {"rename_width"}), None),
                        "POSITION": next((c for c in cores if c.get("select") == "position"
                                          and all(c.get(k) == base.get(k) for k in base if k != "name")
                                          and set(c) - set(base) == {"select"}), None)}
        return None

    trace, executes = family(False), family(True)
    if trace and not (trace["SHARED"] and trace["RENAME"] and trace["POSITION"]):
        trace = None
    if executes and not (executes["SHARED"] and executes["RENAME"] and executes["POSITION"]):
        executes = None
    if not trace:
        print(f"  {name}: DECLINED no core with a twin for each of a dispatch width, a schedule "
              f"loop, a bypass and a unit queue")
        return 0, 0
    machines = dict(trace)
    if executes:
        machines.update({f"X{tag}": core for tag, core in executes.items()})

    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    module = f"sc_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in facts["instructions"]}
    latency_of = {m: entry.get("latency_cycles", 1) for m, entry in by_mnemonic.items()}
    asm = Assembler(lift, tests, latency_of)
    if asm.missing():
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing()}")
        return 0, 0
    add, mul = asm.fast_add, asm.slow
    base = trace["PLAIN"]
    width = base.get("issue_width") or 1
    narrow = trace["NARROW"]["dispatch_width"]
    loop = trace["LOOP"]["schedule"]
    crossing = trace["BYPASS"]["bypass"][0]
    queued = next(u for u in trace["QUEUE"]["units"] if u.get("queue"))
    slow, quick = asm.cost(mul), asm.cost(add)
    # ⚠️ The arithmetic below is in THESE: a one-cycle add and a multiply
    # longer than the loop, on their own units; the bypass from the
    # multiplier's to the adder's; the queue on the multiplier's, which there
    # is one of; and a front end no narrower than the window's door.
    if (quick != 1 or slow <= loop or by_mnemonic[mul].get("unit") != crossing[0]
            or by_mnemonic[add].get("unit") != crossing[1] or queued["name"] != crossing[0]
            or (queued.get("count") or 1) != 1 or base["front_end"]["fetch_width"] < width
            or narrow >= width or width % narrow):
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED the cores are not the ones this gate's arithmetic is in")
        return 0, 0

    def chain(op, n):
        return [asm.op(op, A, A, ONE)] * n + [0]

    programs = {}
    for n in (SHORT, LONG):
        programs[f"APART{n}"] = [asm.op(add, A + k % 4, ONE, ONE) for k in range(n)] + [0]
        programs[f"ADDS{n}"] = chain(add, n)
        programs[f"MULS{n}"] = chain(mul, n)
        programs[f"MIX{n}"] = [asm.op(mul, A, A, ONE), asm.op(add, A, A, ONE)] * (n // 2) + [0]
    # ⚠️ ONEWAY / OTHERWAY: a bypass has a DIRECTION. Any chain that goes
    # round crosses as often one way as the other, and a bypass read backwards
    # cost every pair above exactly the same. So: a chain of multiplies and
    # ONE add of what they made, which crosses from the multiplier to the
    # adder once; and a chain of adds and one multiply, which crosses the
    # other way, where there is no bypass.
    programs["ONEWAY"] = chain(mul, 8)[:-1] + [asm.op(add, A, A, ONE), 0]
    programs["OTHERWAY"] = chain(add, 24)[:-1] + [asm.op(mul, A, A, ONE), 0]
    # ⚠️ DOOR: a chain of multiplies, then a chain of adds longer than all of
    # them. What is measured is when the adds START, which is when the last
    # multiply got in.
    tail = 3 * slow * 4
    for k in (4, 8):
        programs[f"DOOR{k}"] = chain(mul, k)[:-1] + [asm.op(add, B, B, ONE)] * tail + [0]
    # ⚠️ DOORL: the same door, with LOADS waiting -- each on the one before,
    # through a pointer that points at itself. A machine whose multiplier has
    # a queue of its own lets them all in; one where the multiplier and the
    # load unit share a queue lets one more in only as one issues.
    shared = trace["SHARED"]["queues"][0]
    reads = asm.cost(asm.load[0])
    for k in (4, 8):
        programs[f"DOORL{k}"] = ([asm.st(C, C, 0)] + [asm.ld(C, C, 0)] * k
                                 + [asm.op(add, B, B, ONE)] * tail + [0])
    # ⚠️ OLDER / YOUNGER (S8): two multiplies of one product, ready the same
    # cycle, and one multiplier. The first enters with the product's own
    # multiplies and an add, in the fourth slot; the second enters a cycle
    # later, into the first slot, which the head of the chain gave up when it
    # issued. By age the older goes first; by position, the younger. A long
    # chain of adds hangs off one of them: off the older in one program, off
    # the younger in the other.
    head = [asm.op(mul, A, A, ONE), asm.op(mul, A, A, ONE), asm.op(add, 26, ONE, ONE)]
    for tag, hung in (("OLDER", 24), ("YOUNGER", 25)):
        programs[tag] = (head + [asm.op(mul, 24, A, ONE), asm.op(mul, 25, A, ONE)]
                         + [asm.op(add, hung, hung, ONE)] * 20 + [0])
    # ⚠️ BOTH: a load and a multiply that issue at once, then a load and a
    # multiply that each wait on those -- one of each waiting -- and then one
    # more load. A queue the two units share is full, of one of each, and the
    # third load gets in when one of them issues -- the multiply; the load
    # ahead is behind a cold miss -- and the adds behind it with it. A queue that counted only its own unit's saw one
    # load waiting and let the third straight in.
    filler = asm.op(add, 26, ONE, ONE)
    programs["BOTH"] = ([asm.ld(C, C, 0), asm.op(mul, A, A, ONE), filler, filler,
                         asm.ld(C, C, 0), asm.op(mul, A, A, ONE), asm.ld(C, C, 0)]
                        + [asm.op(add, B, B, ONE)] * tail + [0])
    # ⚠️ PAIRS: an instruction with TWO results -- what it loaded, and its
    # base moved on -- which a rename width of two gives a register to one of
    # a cycle. Counted as one instruction each, two went in.
    two = next((e for e in lift.AXIS_LIFT_TABLE
                if e["mnemonic"] in {t["mnemonic"] for t in tests}
                and len(e.get("effects") or []) == 2
                and all(x.get("kind") == "set" for x in e["effects"])
                and [o["role"] for o in e["operands"]].count("inout") == 1
                and any(o["kind"] == "imm" for o in e["operands"])), None)
    # ⚠️ ...each followed by an ADD, which has one. Two results and one are
    # three, more than a cycle renames: so one instruction a cycle. Counting
    # INSTRUCTIONS renamed -- one each -- let the pair in together, and a
    # program of two-result instructions alone could not tell: the check asks
    # how many results the next one has either way.
    if two:
        names = {o["role"] if o["kind"] != "imm" else "imm": o["name"] for o in two["operands"]}
        for n in (SHORT, LONG):
            programs[f"PAIRS{n}"] = [
                word for k in range(n // 2) for word in (
                    asm._word(two["mnemonic"], **{names["out"]: 24, names["inout"]: 16 + k % 4,
                                                 names["imm"]: 0}),
                    asm.op(add, 25, ONE, ONE))] + [0]
    # STORES: instructions that write no register, which a rename width does
    # not count.
    for n in (SHORT, LONG):
        programs[f"STORES{n}"] = [asm.st(ONE, C, 8)] * n + [0]
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
    sys.modules.pop(module, None)
    seeds = {"counter": slot(9), slot(ONE): 1, slot(A): 1, slot(B): 1, slot(C): DATA,
             **{slot(16 + k): DATA + 64 * (k + 1) for k in range(4)}}
    lines = [f'  go("{p}_{t}_0", "{c["name"]}", {p}, {len(programs[p])}, 0u);'
             for p in programs for t, c in machines.items()]
    out = harness_run(work, manifest, name, isa, seeds, programs, lines, 8)
    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    if out is None:
        fail("the harness did not run")
        return 1, failures

    def get(program, tag, key="cycles"):
        return out[f"{program}_{tag}_0"][key]

    for program in programs:
        rows = [out.get(f"{program}_{t}_0") for t in machines]
        checks += 1
        if any(r is None for r in rows):
            fail(f"{program} reported nothing on some machine")
            return checks, failures
        checks += 1
        if len({(r["steps"], r["mark"]) for r in rows}) != 1:
            fail(f"{program} retired different instructions or left different registers or "
                 f"memory on different machines: {[r['steps'] for r in rows]}")
    if failures:
        return checks, failures

    def grew(tag, machine):
        return get(f"{tag}{LONG}", machine) - get(f"{tag}{SHORT}", machine)

    more = LONG - SHORT
    for prefix in ("", "X") if executes else ("",):
        who = lambda tag: machines[prefix + tag]["name"]  # noqa: E731
        want = {
            # (program, machine): cycles for `more` more, and why
            ("APART", "PLAIN"): (more // width, f"{width} enter the window a cycle"),
            ("APART", "NARROW"): (more // narrow, f"{narrow} enter the window a cycle"),
            ("ADDS", "PLAIN"): (more * quick, "an add a link, issued back to back"),
            ("ADDS", "LOOP"): (more * loop, f"a dependent issues {loop} cycles after its producer "
                                            f"issued, however short the producer"),
            ("MULS", "PLAIN"): (more * slow, "a multiply a link"),
            ("MULS", "LOOP"): (more * slow, f"a multiply is longer than a loop of {loop}"),
            ("MIX", "PLAIN"): (more // 2 * (slow + quick), "a multiply and an add a pair"),
            ("MIX", "BYPASS"): (more // 2 * (slow + quick + crossing[2]),
                                f"and {crossing[2]} for the product to reach the adder"),
            ("ADDS", "BYPASS"): (more * quick, "nothing crosses from the multiplier"),
            ("MULS", "BYPASS"): (more * slow, "nothing crosses to the adder"),
        }
        for (program, tag), (cycles, why) in want.items():
            checks += 1
            if grew(program, prefix + tag) != cycles:
                fail(f"{more} more of {program} took {grew(program, prefix + tag)} cycles on "
                     f"{who(tag)}; {why} -- {cycles}")
        checks += 1
        if (get("ONEWAY", prefix + "BYPASS") - get("ONEWAY", prefix + "PLAIN") != crossing[2]
                or get("OTHERWAY", prefix + "BYPASS") != get("OTHERWAY", prefix + "PLAIN")):
            fail(f"one add of a chain of multiplies cost "
                 f"{get('ONEWAY', prefix + 'BYPASS') - get('ONEWAY', prefix + 'PLAIN')} cycles "
                 f"more on {who('BYPASS')} than on {who('PLAIN')}, and one multiply of a chain "
                 f"of adds "
                 f"{get('OTHERWAY', prefix + 'BYPASS') - get('OTHERWAY', prefix + 'PLAIN')}; the "
                 f"bypass is from the multiplier to the adder and not back -- {crossing[2]} "
                 f"and 0")
        later = {tag: get("DOOR8", prefix + tag) - get("DOOR4", prefix + tag)
                 for tag in ("PLAIN", "QUEUE")}
        checks += 1
        if later["PLAIN"] != 4 // width:
            fail(f"4 more multiplies ahead of a long chain of adds cost {later['PLAIN']} cycles "
                 f"on {who('PLAIN')}; they wait in the one queue and the adds start a dispatch "
                 f"group later -- {4 // width}")
        checks += 1
        if later["QUEUE"] != 4 * slow:
            fail(f"the same cost {later['QUEUE']} cycles on {who('QUEUE')}, where "
                 f"{queued['queue']} may wait for the multiplier; one more gets in only as one "
                 f"issues, {slow} cycles apart, and the adds are behind them -- {4 * slow}")
        # ⚠️ WAITING, not in flight: the multiply that is executing has left
        # the queue. Of four, one issues at once and two wait, so the fourth
        # gets in one multiply later -- not two, as it would if the one
        # executing still held a place.
        held = get("DOOR4", prefix + "QUEUE") - get("DOOR4", prefix + "PLAIN")
        checks += 1
        if held != slow * (4 - 1 - queued["queue"]):
            fail(f"4 multiplies ahead of a long chain of adds cost {held} cycles more on "
                 f"{who('QUEUE')} than on {who('PLAIN')}; one issues at once and "
                 f"{queued['queue']} wait, so the last gets in "
                 f"{4 - 1 - queued['queue']} multiply later -- {slow * (4 - 1 - queued['queue'])}")
        # ⚠️ S5: a queue the multiplier and the load unit SHARE. Multiplies
        # fill it as they fill a queue of the multiplier's own; and so do
        # loads, which a queue of the multiplier's own never sees.
        late = {tag: (get("DOOR8", prefix + tag) - get("DOOR4", prefix + tag),
                      get("DOORL8", prefix + tag) - get("DOORL4", prefix + tag))
                for tag in ("PLAIN", "QUEUE", "SHARED")}
        want_late = {"PLAIN": (4 // width, 4 // width), "QUEUE": (4 * slow, 4 // width),
                     "SHARED": (4 * slow, 4 * reads)}
        checks += 1
        if (shared["size"] != queued["queue"] or sorted(shared["units"]) != sorted({crossing[0], by_mnemonic[asm.load[0]].get("unit")})
                or late != want_late):
            fail(f"4 more multiplies, and 4 more loads, ahead of a long chain of adds cost "
                 f"{late['PLAIN']} cycles on {who('PLAIN')}, {late['QUEUE']} on {who('QUEUE')} "
                 f"and {late['SHARED']} on {who('SHARED')}, where the multiplier and the load "
                 f"unit share a queue of {shared['size']}; a queue of the multiplier's own "
                 f"never sees a load, a shared one fills with either -- {want_late}")
        both = {tag: get("BOTH", prefix + tag) - get("BOTH", prefix + "PLAIN") for tag in ("QUEUE", "SHARED")}
        checks += 1
        if both["QUEUE"] != 0 or both["SHARED"] != slow:
            fail(f"a load and a multiply waiting, and one more load: {both['SHARED']} cycles "
                 f"more than {who('PLAIN')} on {who('SHARED')} and {both['QUEUE']} on "
                 f"{who('QUEUE')}; the shared queue is full of one of each and the load waits "
                 f"at the door until one of them issues -- the multiply, {slow} cycles on; the "
                 f"load ahead is behind a cold miss -- and a queue of the multiplier's own "
                 f"has room: {slow}, and 0")
        if "PAIRS32" in programs and machines.get(prefix + "RENAME2"):
            checks += 1
            if (grew("PAIRS", prefix + "RENAME2") != more
                    or grew("PAIRS", prefix + "PLAIN") >= more):
                fail(f"{more} more instructions of two results each took "
                     f"{grew('PAIRS', prefix + 'RENAME2')} cycles on {who('RENAME2')}, which "
                     f"renames 2 a cycle, and {grew('PAIRS', prefix + 'PLAIN')} on "
                     f"{who('PLAIN')}; two results are the whole width, so one a cycle -- "
                     f"{more}, and fewer")
        else:
            checks += 1
            fail("no instruction of two results, or no core renaming two a cycle: nothing "
                 "here tells a result from an instruction")
        # ⚠️ S6: one RESULT renamed a cycle. Adds enter one at a time; stores,
        # which write no register, as fast as they ever did.
        renames = machines[prefix + "RENAME"]["rename_width"]
        checks += 1
        if (grew("APART", prefix + "RENAME") != more // renames
                or grew("STORES", prefix + "RENAME") != grew("STORES", prefix + "PLAIN")):
            fail(f"{more} more independent adds took {grew('APART', prefix + 'RENAME')} cycles "
                 f"on {who('RENAME')}, which renames {renames} a cycle, and {more} more stores "
                 f"{grew('STORES', prefix + 'RENAME')} against {who('PLAIN')}'s "
                 f"{grew('STORES', prefix + 'PLAIN')}; an add needs a register and a store "
                 f"does not -- {more // renames}, and the same")
        # ⚠️ S8: BY POSITION, the younger multiply has the lower slot. Whatever
        # hangs off the one that loses is a cycle later.
        swing = (get("OLDER", prefix + "POSITION") - get("OLDER", prefix + "PLAIN"),
                 get("YOUNGER", prefix + "POSITION") - get("YOUNGER", prefix + "PLAIN"))
        checks += 1
        if swing != (1, -1):
            fail(f"two multiplies ready together for one multiplier: a chain off the older "
                 f"cost {swing[0]} cycles more on {who('POSITION')} than on {who('PLAIN')}, and "
                 f"a chain off the younger {swing[1]}; the younger entered into a slot the "
                 f"head of the chain had given up, below the older's, so by position it goes "
                 f"first -- 1 and -1")
    if executes:
        checks += 1
        differ = [(p, t) for p in ("APART", "ADDS", "MULS", "MIX") for t in trace
                  if grew(p, t) != grew(p, "X" + t)]
        if differ:
            fail(f"the two engines disagree on {differ}")
    if not failures:
        print(f"  {name}: {more} more independent adds {grew('APART', 'PLAIN')} cycles, "
              f"{grew('APART', 'NARROW')} dispatching {narrow}; an add chain "
              f"{grew('ADDS', 'PLAIN')}, {grew('ADDS', 'LOOP')} through a loop of {loop}; "
              f"multiply-add pairs {grew('MIX', 'PLAIN')}, {grew('MIX', 'BYPASS')} across a "
              f"bypass of {crossing[2]}; 4 more multiplies at a queue of {queued['queue']} hold "
              f"the adds back {get('DOOR8', 'QUEUE') - get('DOOR4', 'QUEUE')} cycles"
              f"{'; both engines' if executes else ''}; {checks} checks")
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
                text = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {text[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("the scheduler has limits of its own: SKIP")
        return DECLINED
    print(f"the scheduler has limits of its own: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
