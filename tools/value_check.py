#!/usr/bin/env python3
"""A load's value, predicted. Gate.

`(value-prediction (entries N) (confidence K))` (docs/scheduler_design.md,
S4): a load at one pc that has read the same value K times running is
predicted to read it again. What depends on it does not wait for it, and the
load runs to check. Two machines identical but for the clause, on each engine:

  * **a chain through memory is gone**: a loop that chases a pointer which
    points at itself runs at the load's latency a trip unpredicted, and at
    the loop's own a trip once the load is predicted -- every load of it
    predicted, and none wrong;
  * **a value that keeps changing is never predicted**: the same loop round
    a ring of four costs the two machines the same, and nothing is predicted;
  * **a wrong value is paid for**: a field that is the same three trips in
    four is trusted just in time to be wrong -- one mispredict every four
    trips, no prediction right, and each costs the machine a refetch behind
    the load;
  * and every program retires the same instructions and leaves the same
    registers and memory on every machine.

Usage: tools/value_check.py [corpus.axisl ...]
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
import redirect_check  # noqa: E402
from redirect_check import COUNTER, DATA, LINE, MINUS_ONE, ONE, harness_run  # noqa: E402

# This gate reads values predicted RIGHT where the front-end gates read
# wrong-path instructions, and predicted WRONG where they read target-buffer
# misses (pack ABI 11).
for old, new in (("wrong %%llu", "right %%llu"), ("btb %%llu", "bad %%llu"),
                 ("(unsigned long long)S->wrong_path_instructions(m)",
                  "(unsigned long long)S->value_predictions(m)"),
                 ("(unsigned long long)S->btb_misses(m)",
                  "(unsigned long long)S->value_mispredicts(m)")):
    assert old in redirect_check.HARNESS
    redirect_check.HARNESS = redirect_check.HARNESS.replace(old, new)

AXIS_ROOT = Path(__file__).resolve().parent.parent
SHORT, LONG = 24, 40
P, V = 21, 22                      # the pointer being chased, and a field of its node
NODES = (14, 15, 16, 17)           # registers holding four nodes' addresses
SAME, OTHER = 18, 19               # a field's usual value, and its odd one out
STEP = 27                          # a line, to walk by
DONE, AGAIN = 23, 24               # whether the field has been changed, and the trips after


def build_programs(asm: Assembler, bnz):
    add = asm.fast_add
    count = [asm.op(add, COUNTER, COUNTER, MINUS_ONE)]

    def loop(prologue, body):
        words = prologue + body + count
        return words + [bnz(COUNTER, 0, -4 * (len(body) + 1)), 0]

    a, b, c, d = NODES
    ring = [asm.st(b, a, 0), asm.st(c, b, 0), asm.st(d, c, 0), asm.st(a, d, 0)]
    fields = [asm.st(SAME, a, 4), asm.st(SAME, b, 4), asm.st(SAME, c, 4), asm.st(OTHER, d, 4)]
    # ⚠️ TURN: a field read every trip, the same for as many trips as the
    # harness asks -- long trusted -- and then the program changes it and
    # goes round again. The first read after is predicted, and wrong. An
    # engine that trains its table when a load RETIRES has several reads in
    # flight by then, so a short pattern says different things on the two
    # engines; one turn, after a long run, is wrong on both.
    turn = [asm.st(SAME, a, 4),
            asm.ld(V, a, 4), asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -8),
            bnz(DONE, 0, 20), asm.op(add, DONE, ONE, 0), asm.st(OTHER, a, 4),
            asm.op(add, COUNTER, AGAIN, 0), bnz(ONE, 0, -28),
            asm.op(add, 25, 1, 1), 0]
    # ⚠️ USED: a field read into a register, and that register added to --
    # so each trip leaves in it something that is NOT what the next load
    # reads. What depends on a predicted load has to see the PREDICTED value;
    # a pointer at itself never told, since the register held it already.
    # ⚠️ Its ADDRESS comes off a multiply: the add, which waits for nothing,
    # issues before the load can. A load whose address was ready issued first
    # in the same cycle -- it is older -- and the add then saw what it had
    # really read, predicted or not.
    used = loop([asm.st(SAME, a, 4)],
                [asm.op(asm.slow, 10, a, ONE), asm.ld(V, 10, 4), asm.op(add, V, V, ONE)])
    # ⚠️ WALK (S7): a pointer walked a line at a time. Each trip stores the
    # next node's address in this one and then reads it back -- through a
    # multiply, so that the chain from one trip's pointer to the next is
    # longer than a trip of the loop. The value read is never the last one;
    # it is always the last one plus a line.
    walk = loop([], [asm.op(asm.slow, 10, P, ONE), asm.op(add, 26, 10, STEP),
                     asm.st(26, 10, 0), asm.ld(P, 10, 0)])
    return {
        "TURN": turn,
        "WALK": walk,
        "USED": used,
        # SELF: one node, pointing at itself.
        "SELF": loop([asm.st(a, a, 0)], [asm.ld(P, P, 0)]),
        # RING: four nodes in a ring -- the pointer read is never the last one.
        "RING": loop(ring, [asm.ld(P, P, 0)]),
        # FIELD: the ring, and a field of each node: the same in three, not
        # in the fourth. The pointer is never predicted; the field is, after
        # two the same -- which is the trip before the odd one.
        "FIELD": loop(ring + fields, [asm.ld(P, P, 0), asm.ld(V, P, 4)]),
    }


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = [c for c in facts.get("cores", []) if c.get("front_end")]
    name = axis_file.stem

    def pair(executing):
        for core in cores:
            if (not core.get("value_prediction") or core["value_prediction"].get("kind")
                    or (core.get("engine") == "execute") != executing):
                continue
            twin = next((c for c in cores if c is not core and not c.get("value_prediction")
                         and all(c.get(k) == core.get(k) for k in core
                                 if k not in ("name", "value_prediction"))), None)
            if twin and core.get("memory"):
                return core, twin
        return None, None

    (predicts, plain), (xpredicts, xplain) = pair(False), pair(True)
    if not plain:
        print(f"  {name}: DECLINED no core that predicts values, with a twin that does not")
        return 0, 0
    machines = {"PREDICTS": predicts, "PLAIN": plain}
    if xplain:
        machines.update({"XPREDICTS": xpredicts, "XPLAIN": xplain})

    def striding(of, twin):
        return next((c for c in cores if (c.get("value_prediction") or {}).get("kind") == "stride"
                     and c["value_prediction"]["entries"] == of["value_prediction"]["entries"]
                     and c["value_prediction"]["confidence"] == of["value_prediction"]["confidence"]
                     and all(c.get(k) == twin.get(k) for k in twin if k != "name")), None)

    strides = striding(predicts, plain)
    if strides:
        machines["STRIDES"] = strides
        if xplain and striding(xpredicts, xplain):
            machines["XSTRIDES"] = striding(xpredicts, xplain)
    trusted = predicts["value_prediction"]["confidence"]

    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    module = f"vp_{name}"
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
    load = asm.cost(asm.load[0])
    # ⚠️ The arithmetic below: a load slower than a trip of the loop, a field
    # trusted after two the same, and a ring of four.
    if load < 2 or trusted != 2:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED the load is no slower than the loop, or a value is not "
              f"trusted after two")
        return 0, 0
    programs = build_programs(asm, bnz)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)
    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF, slot(0): 0,
             slot(P): DATA, slot(SAME): 7, slot(OTHER): 9, slot(DONE): 0, slot(AGAIN): 12, slot(STEP): LINE,
             **{slot(r): DATA + k * LINE for k, r in enumerate(NODES)}}
    lines = [f'  go("{p}_{t}_{trips}", "{c["name"]}", {p}, {len(programs[p])}, {trips}u);'
             for p in programs for t, c in machines.items() for trips in (SHORT, LONG)]
    out = harness_run(work, manifest, name, isa, seeds, programs, lines, 8)
    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    if out is None:
        fail("the harness did not run")
        return 1, failures

    def get(program, tag, key="cycles", trips=LONG):
        return out[f"{program}_{tag}_{trips}"][key]

    def grew(program, tag, key="cycles"):
        return get(program, tag, key, LONG) - get(program, tag, key, SHORT)

    for program in programs:
        for trips in (SHORT, LONG):
            rows = [out.get(f"{program}_{t}_{trips}") for t in machines]
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
    costs = {}
    for prefix in ("", "X") if xplain else ("",):
        on, off = machines[prefix + "PREDICTS"]["name"], machines[prefix + "PLAIN"]["name"]
        checks += 1
        if grew("SELF", prefix + "PLAIN") != more * load:
            fail(f"{more} more trips chasing a pointer that points at itself took "
                 f"{grew('SELF', prefix + 'PLAIN')} cycles on {off}; each load waits for the "
                 f"one before it, {load} a trip -- {more * load}")
        checks += 1
        if grew("SELF", prefix + "PREDICTS") != more:
            fail(f"the same took {grew('SELF', prefix + 'PREDICTS')} cycles on {on}; the "
                 f"pointer is predicted and nothing waits for the load, so the loop runs at "
                 f"its own trip a cycle -- {more}")
        checks += 1
        if (grew("SELF", prefix + "PREDICTS", "right"), grew("SELF", prefix + "PREDICTS", "bad")) != (more, 0):
            fail(f"{on} predicted {grew('SELF', prefix + 'PREDICTS', 'right')} of those loads "
                 f"right and {grew('SELF', prefix + 'PREDICTS', 'bad')} wrong; every one, and "
                 f"none -- {more} and 0")
        checks += 1
        if (grew("RING", prefix + "PREDICTS") != grew("RING", prefix + "PLAIN")
                or get("RING", prefix + "PREDICTS", "right") or get("RING", prefix + "PREDICTS", "bad")):
            fail(f"{more} more trips round a ring of four took "
                 f"{grew('RING', prefix + 'PREDICTS')} cycles on {on} and "
                 f"{grew('RING', prefix + 'PLAIN')} on {off}, with "
                 f"{get('RING', prefix + 'PREDICTS', 'right')} loads predicted right and "
                 f"{get('RING', prefix + 'PREDICTS', 'bad')} wrong; the pointer is never what "
                 f"it was, so the same, and none")
        checks += 1
        if (grew("USED", prefix + "PREDICTS") != grew("USED", prefix + "PLAIN")
                or grew("USED", prefix + "PREDICTS", "right") != more
                or get("USED", prefix + "PREDICTS", "bad")):
            fail(f"{more} more trips of a field read and then added to took "
                 f"{grew('USED', prefix + 'PREDICTS')} cycles on {on} and "
                 f"{grew('USED', prefix + 'PLAIN')} on {off}, with "
                 f"{grew('USED', prefix + 'PREDICTS', 'right')} predicted right and "
                 f"{get('USED', prefix + 'PREDICTS', 'bad')} wrong; the add sees the value "
                 f"predicted, not what the last trip left, so the same cycles -- nothing is "
                 f"computed twice -- and {more} right, 0 wrong")
        # ⚠️ ONE TURN: wrong once where the table learns as the program goes,
        # and at least once where it learns behind it.
        turned = get("TURN", prefix + "PREDICTS", "bad")
        checks += 1
        if (turned != 1 if not prefix else turned < 1) or get("TURN", prefix + "PLAIN", "bad"):
            fail(f"a field changed once after {LONG} trips the same: {turned} mispredicts on "
                 f"{on}; the first read after is predicted and wrong -- "
                 f"{'exactly 1' if not prefix else 'at least 1'}")
        if not prefix:
            # The short pattern is exact only where training is in program
            # order: trusted after two the same, which is the trip before the
            # odd one.
            wrong = grew("FIELD", "PREDICTS", "bad")
            checks += 1
            if wrong != more // 4 or grew("FIELD", "PREDICTS", "right"):
                fail(f"a field the same three trips in four: {wrong} mispredicts and "
                     f"{grew('FIELD', 'PREDICTS', 'right')} right over {more} more trips on "
                     f"{on}; it is trusted after two the same, which is the trip before the "
                     f"odd one -- {more // 4} and 0")
            costs[prefix] = grew("FIELD", "PREDICTS") - grew("FIELD", "PLAIN")
            checks += 1
            if wrong and (costs[prefix] <= 0 or costs[prefix] % wrong):
                fail(f"{wrong} values predicted wrong cost {on} {costs[prefix]} cycles over "
                     f"{off}; each is a refetch behind its load, the same every time, and not "
                     f"free")
    # ⚠️ S7: a STRIDE. Last value never predicts a pointer that walks; a
    # stride predicts every one, and the chain through the load -- the load
    # and the multiply its address comes off -- is gone. Trace-driven, where
    # a load does not wait for the store it reads.
    checks += 1
    if "STRIDES" not in machines:
        fail("no core that predicts by stride, with this one's table: nothing here tells a "
             "stride from a last value")
    else:
        chain = load + asm.cost(asm.slow)
        got = {tag: (grew("WALK", tag), grew("WALK", tag, "right"), get("WALK", tag, "bad"))
               for tag in ("PLAIN", "PREDICTS", "STRIDES")}
        trip = grew("WALK", "STRIDES")
        checks += 1
        if (got["PLAIN"] != (more * chain, 0, 0) or got["PREDICTS"] != (more * chain, 0, 0)
                or got["STRIDES"][1:] != (more, 0) or not more <= trip < more * chain):
            fail(f"{more} more trips walking a pointer a line at a time: (cycles, right, "
                 f"wrong) {got['PLAIN']} on {plain['name']}, {got['PREDICTS']} predicting the "
                 f"last value on {predicts['name']}, {got['STRIDES']} by stride on "
                 f"{machines['STRIDES']['name']}; the load and the multiply are {chain} a "
                 f"trip, a value that walks is never its last, and a stride predicts every "
                 f"one -- ({more * chain}, 0, 0) twice, then fewer cycles with {more} right")
        for tag in ("SELF", "USED"):
            checks += 1
            if grew(tag, "STRIDES") != grew(tag, "PREDICTS"):
                fail(f"{tag} took {grew(tag, 'STRIDES')} cycles more by stride and "
                     f"{grew(tag, 'PREDICTS')} by last value; a value that does not change is "
                     f"a stride of nothing, so the same")
    if not failures:
        each = {p: costs[p] // (more // 4) for p in costs}
        print(f"  {name}: {more} more trips of a pointer at itself {grew('SELF', 'PLAIN')} "
              f"cycles unpredicted and {grew('SELF', 'PREDICTS')} predicted; a ring of four "
              f"never predicted; a field wrong one trip in four costs {each['']} cycles a "
              f"time; a field changed once is wrong {get('TURN', 'PREDICTS', 'bad')} time"
              f"{' (' + str(get('TURN', 'XPREDICTS', 'bad')) + ' executing)' if xplain else ''}; "
              f"{checks} checks")
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
        print("a load's value, predicted: SKIP")
        return DECLINED
    print(f"a load's value, predicted: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
