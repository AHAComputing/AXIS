#!/usr/bin/env python3
"""A load that bets it misses a store pays when it loses, and a machine that
remembers pays once. Gate.

`(disambiguation speculative)` lets a load issue past an older store whose
address is not known yet. When the store's address resolves over a load that
has already issued, the load read memory before the store wrote it: it and
everything younger are squashed and wait `(replay N)` cycles to go again.
`(disambiguation store-sets)` bets the same way and learns from losing: a load
and a store that collided share a set, and the next load from that address
waits for the next store from this one (docs/ooo_design.md, O5).

The program is a loop around a store whose address comes late -- the base plus
a zero two multiplies take to produce -- and a load that either reads what the
store wrote (ALIAS) or reads somewhere else (DISJOINT). What it holds:

  * **the bet is free when it wins**: on DISJOINT, speculating costs exactly
    what the oracle costs -- to the cycle, at both trip counts -- and so does
    the store-set machine; the conservative machine, which waits for every
    address, costs more;
  * **the bet is paid for every time it loses**: on ALIAS, speculation
    violates once per iteration, so its violations grow by exactly the extra
    iterations;
  * **a squash costs at least its replay**, even to work that never read the
    load: everything younger is thrown away and restarts `replay` cycles
    after the violation;
  * **store sets pay once**: their violations are the same number at both
    trip counts, and what they cost over the oracle does not grow either --
    the learning is a constant, not a rate;
  * **the policies that never bet never lose**: conservative and perfect
    report no violations at all;
  * **the architecture is untouched**: squashing and replaying is timing, so
    every machine leaves the same registers.

Usage: tools/speculation_check.py [corpus.axisl ...]
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
from lsq_check import BASE, DATA, Assembler, pick, run_cmd  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
TRIPS = (8, 16)
#: Registers the harness seeds beyond the base.
VALUE, MINUS_ONE, COUNTER = 2, 7, 9

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
  S->set_reg(m, %(base)d, %(data)du);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)(trips * (uint32_t)count + 8u));
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  printf("%%s cycles %%llu steps %%llu violations %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->memory_violations(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->memory_violations) { printf("NOVIOLATIONS\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def loop(asm: Assembler, lift, tests, offset):
    """A store to a late address, a load from `offset`, round and round."""
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    branch = None
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        imms = [o for o in entry["operands"] if o["role"] == "in" and o["kind"] == "imm"]
        if (any(e.get("kind") == "setpc" for e in entry.get("effects") or [])
                and len(regs) == 2 and len(imms) == 1):
            branch = (test, entry, regs, imms[0])
            break
    if branch is None:
        return None
    test, entry, regs, imm = branch
    body = [
        asm.op(asm.slow, 12, 1, 0),              # 0, slowly
        asm.op(asm.slow, 12, 12, 12),            # still 0, more slowly
        asm.op(asm.fast_add, 10, BASE, 12),      # the base, late
        asm.st(VALUE, 10, 64),                   # a store whose address is late
        asm.ld(11, BASE, offset),                # a load whose address is not
        asm.op(asm.fast_add, 14, 14, 11),        # something that uses it
        asm.op(asm.fast_add, COUNTER, COUNTER, MINUS_ONE),
    ]
    back = -4 * len(body)
    word = lift.place_operand(int(test["encoded"], 16), entry, regs[0]["name"], COUNTER)
    word = lift.place_operand(word, entry, regs[1]["name"], 0)
    word = lift.place_operand(word, entry, imm["name"], back & ((1 << 13) - 1))
    # One instruction after, so the loop's exit has a successor to pay for it.
    return body + [word, asm.op(asm.fast_add, 15, 1, 1)]


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    machines = {
        "CONS": pick(cores, disambiguation="conservative", forwarding=True, loads=0, stores=0),
        "PERF": pick(cores, disambiguation="perfect", forwarding=True, loads=0, stores=0),
        "SPEC": pick(cores, disambiguation="speculative", forwarding=True, loads=0, stores=0),
        "SETS": pick(cores, disambiguation="store-sets", forwarding=True, loads=0, stores=0),
    }
    # A second speculating machine, identical but for its replay.
    spec = machines["SPEC"]
    machines["SLOW"] = next((core for core in cores if spec and core is not spec
                             and core.get("lsq") and core["lsq"].get("disambiguation") == "speculative"
                             and core["lsq"].get("replay") != spec["lsq"].get("replay")
                             and {**core["lsq"], "replay": 0} == {**spec["lsq"], "replay": 0}
                             and core.get("units") == spec.get("units")
                             and core.get("rob") == spec.get("rob")), None)
    missing = [tag for tag, core in machines.items() if core is None]
    if missing:
        print(f"  {name}: DECLINED no {', '.join(missing)} core")
        return 0, 0

    module = f"spec_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    why = asm.missing()
    programs = {}
    if not why:
        for label, offset in (("ALIAS", 64), ("DISJOINT", 256)):
            words = loop(asm, lift, tests, offset)
            if words is None:
                why = "no two-register branch to loop with"
                break
            programs[label] = words
        # ⚠️ One violation, and a long chain behind it that does NOT depend on
        # the load. A squash throws away everything younger than the load, not
        # only what read it -- the machine cannot tell which is which until it
        # re-executes -- so the chain restarts `replay` cycles after the
        # violation. Both a machine that squashed only the load and one that
        # replayed for free passed every loop here; mutation testing said so.
        if not why:
            programs["SQUASH"] = [
                asm.op(asm.slow, 12, 1, 0), asm.op(asm.slow, 12, 12, 12),
                asm.op(asm.fast_add, 10, BASE, 12), asm.st(VALUE, 10, 64),
                asm.ld(11, BASE, 64),
                asm.op(asm.slow, 16, 1, 1)] + [asm.op(asm.slow, 16, 16, 16) for _ in range(5)]
    base_slot = lift.register_slot(asm.kind, BASE) if not why else 0
    slot = (lambda i: lift.register_slot(asm.kind, i)) if not why else None
    isa = next((t.get("isa") for t in tests if asm.load and t["mnemonic"] == asm.load[0]), "") or ""
    sys.modules.pop(module, None)
    if why:
        print(f"  {name}: DECLINED {why}")
        return 0, 0

    runs = [f'  go("{program}_{tag}_{trips}", "{core["name"]}", {program}, '
            f'(int32_t)(sizeof {program} / sizeof {program}[0]), {trips}u);'
            for program in programs for tag, core in machines.items() for trips in TRIPS]
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "entry": ENTRY, "data": DATA, "base": base_slot,
        "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
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
        if len(parts) == 9 and parts[1] == "cycles":
            said[parts[0]] = {"cycles": int(parts[2]), "steps": int(parts[4]),
                              "violations": int(parts[6]), "mark": int(parts[8])}

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    low, high = TRIPS
    for program in ("ALIAS", "DISJOINT"):
        for trips in TRIPS:
            rows = [said.get(f"{program}_{tag}_{trips}") for tag in machines]
            checks += 1
            if any(row is None for row in rows):
                fail(f"{program} at {trips} trips reported nothing on some machine")
                continue
            checks += 1
            if len({row["steps"] for row in rows}) != 1 or len({row["mark"] for row in rows}) != 1:
                fail(f"{program} at {trips} trips retired different instructions or left "
                     f"different registers on different machines; a squash changed a result")
        checks += 1
        if said.get(f"{program}_PERF_{high}", {}).get("steps", 0) <= \
                said.get(f"{program}_PERF_{low}", {}).get("steps", 0):
            fail(f"{program}: {high} trips retired no more than {low}; the loop did not loop")
    if failures:
        return checks, failures

    def get(program, tag, trips, key="cycles"):
        return said[f"{program}_{tag}_{trips}"][key]

    # ⚠️ The policies that never bet never lose.
    for program in programs:
        for tag in ("CONS", "PERF"):
            for trips in TRIPS:
                checks += 1
                if get(program, tag, trips, "violations"):
                    fail(f"{machines[tag]['name']} reported {get(program, tag, trips, 'violations')} "
                         f"violations on {program}; a machine that never issues past an unknown "
                         f"address cannot be wrong about one")
    # ⚠️ THE BET IS FREE WHEN IT WINS, to the cycle.
    for tag in ("SPEC", "SETS"):
        for trips in TRIPS:
            checks += 1
            if get("DISJOINT", tag, trips) != get("DISJOINT", "PERF", trips) \
                    or get("DISJOINT", tag, trips, "violations"):
                fail(f"a load that never meets the store cost {get('DISJOINT', tag, trips)} on "
                     f"{machines[tag]['name']} ({get('DISJOINT', tag, trips, 'violations')} "
                     f"violations) and {get('DISJOINT', 'PERF', trips)} on the oracle at {trips} "
                     f"trips; a bet that always wins must cost nothing")
    checks += 1
    if get("DISJOINT", "CONS", high) <= get("DISJOINT", "PERF", high):
        fail(f"conservative cost {get('DISJOINT', 'CONS', high)} and the oracle "
             f"{get('DISJOINT', 'PERF', high)} on a load that never meets a late-address store; "
             f"waiting for an address has to cost something")
    # ⚠️ THE BET IS PAID FOR EVERY TIME IT LOSES.
    grew = get("ALIAS", "SPEC", high, "violations") - get("ALIAS", "SPEC", low, "violations")
    checks += 1
    if grew != high - low:
        fail(f"speculation violated {get('ALIAS', 'SPEC', low, 'violations')} times at {low} "
             f"trips and {get('ALIAS', 'SPEC', high, 'violations')} at {high}; a load that always "
             f"meets its store loses the bet once per iteration")
    checks += 1
    if get("ALIAS", "SPEC", high) <= get("ALIAS", "PERF", high):
        fail(f"speculation cost {get('ALIAS', 'SPEC', high)} and the oracle "
             f"{get('ALIAS', 'PERF', high)} on a loop where the bet always loses")
    # ⚠️ A SQUASH COSTS AT LEAST ITS REPLAY, to work that never read the load.
    replay = machines["SPEC"]["lsq"].get("replay", 0)
    checks += 1
    if get("SQUASH", "SPEC", low, "violations") != 1:
        fail(f"one store over one load violated {get('SQUASH', 'SPEC', low, 'violations')} "
             f"times on {machines['SPEC']['name']}")
    checks += 1
    lost = get("SQUASH", "SPEC", low) - get("SQUASH", "PERF", low)
    if lost < replay:
        fail(f"a violation with a chain behind it cost {lost} cycles over the oracle, less than "
             f"the declared replay of {replay}; everything younger than the load is squashed "
             f"and waits that long, whether or not it read the load")

    # ⚠️ And EXACTLY its replay: two machines differing only in the declared
    # replay differ by exactly that on one squash with a chain behind it.
    slow_replay = machines["SLOW"]["lsq"].get("replay", 0)
    checks += 1
    if get("SQUASH", "SLOW", low) - get("SQUASH", "SPEC", low) != slow_replay - replay:
        fail(f"one squash cost {get('SQUASH', 'SPEC', low)} at a replay of {replay} and "
             f"{get('SQUASH', 'SLOW', low)} at {slow_replay}; the restarted chain is the "
             f"program's tail, so the two must differ by exactly {slow_replay - replay}")

    # ⚠️ STORE SETS PAY ONCE: in violations, and in cycles over the oracle.
    checks += 1
    sets_low, sets_high = (get("ALIAS", "SETS", t, "violations") for t in TRIPS)
    if sets_low != sets_high or sets_low == 0:
        fail(f"store sets violated {sets_low} times at {low} trips and {sets_high} at {high}; "
             f"they must lose at least once to learn, and never again")
    checks += 1
    over_low = get("ALIAS", "SETS", low) - get("ALIAS", "PERF", low)
    over_high = get("ALIAS", "SETS", high) - get("ALIAS", "PERF", high)
    if over_low != over_high:
        fail(f"store sets cost {over_low} over the oracle at {low} trips and {over_high} at "
             f"{high}; learning is a constant, and a cost that grows is a machine still losing")

    if not failures:
        print(f"  {name}: aliasing loop at {low}/{high} trips -- speculation violates "
              f"{get('ALIAS', 'SPEC', low, 'violations')}/{get('ALIAS', 'SPEC', high, 'violations')} "
              f"({get('ALIAS', 'SPEC', high)} cycles), store sets "
              f"{sets_low}/{sets_high} ({get('ALIAS', 'SETS', high)}), oracle "
              f"{get('ALIAS', 'PERF', high)}; disjoint: speculation = oracle = "
              f"{get('DISJOINT', 'PERF', high)}, conservative {get('DISJOINT', 'CONS', high)}; "
              f"one squash costs {lost} at a replay of {replay}; "
              f"{checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
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
        print("a bet on memory is paid for when lost: SKIP")
        return DECLINED
    print(f"a bet on memory is paid for when lost: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
