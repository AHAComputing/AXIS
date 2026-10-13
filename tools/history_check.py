#!/usr/bin/env python3
"""A predictor with history learns a pattern; one without cannot. Gate.

A two-bit counter per branch address learns a HABIT: a branch that usually
goes one way. It cannot learn a PATTERN. A branch that alternates -- taken,
not, taken, not -- moves its counter up one and down one forever: from
cold it rocks between its two lowest states and is wrong on every taken
outcome, and between the middle two it is wrong on every outcome at all. `(predictor gshare) (history N)` folds the last N outcomes into the
index (docs/ooo_design.md, O3), so the same branch gets one counter for "the
last time I went" and another for "the last time I did not", and each of
those is a habit.

The program is a loop whose body holds an alternating branch: a register
multiplied by minus one each iteration flips between 1 and -1, and the branch
compares it with 1. What it holds:

  * **the counter per address pays per iteration**: its mispredicts on the
    alternating branch grow with the trip count, at least one for every two
    iterations it is asked to run;
  * **a history too short to see the pattern does not learn it**: one bit,
    inside a loop, is always the loop's own branch -- so a gshare that reads
    one bit scales like the counter per address, and the declared length is
    a number the predictor provably reads;
  * **history stops the scaling**: gshare's mispredicts are the SAME number
    at both trip counts -- warm-up and the loop's exit, and nothing that
    grows. That the cost stops scaling is the property; a predictor that
    helped proportionally would be a faster machine rather than a
    predicting one;
  * **the front end agrees**: on a machine that issues in order, every
    mispredict idles fetch for exactly the declared penalty, so the stall
    and the count are one claim, not two;
  * **the loop actually looped**, the same instructions on every machine and
    more of them when asked for more iterations.

Usage: tools/history_check.py [corpus.axisl ...]
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

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
TRIPS = (16, 32)
#: Registers the harness seeds.
FLIP, MINUS_ONE, ONE, COUNTER, SINK, AFTER = 6, 7, 8, 9, 10, 11

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

static const uint32_t LOOP[] = { %(loop)s };

static void go(const char *tag, const char *core, uint32_t trips) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  for (uint32_t i = 0; i < sizeof LOOP / sizeof LOOP[0]; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(LOOP[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0); }
  S->set_reg(m, %(flip)d, 1u);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(counter)d, trips);
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)(trips * 6u + 8u));
  printf("%%s cycles %%llu steps %%llu miss %%llu stalls %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->mispredicts(m),
         (unsigned long long)(S->front_end_stalls ? S->front_end_stalls(m) : 0));
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->mispredicts) { printf("NOPREDICT\n"); return 0; }
%(runs)s
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def build_loop(lift, tests, latency_of):
    """A loop around a branch that alternates, from the corpus's own words."""
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    branch = None
    arithmetic = {}
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        effects = entry.get("effects") or []
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        imms = [o for o in entry["operands"] if o["role"] == "in" and o["kind"] == "imm"]
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        if any(e.get("kind") == "setpc" for e in effects) and len(regs) == 2 and len(imms) == 1:
            branch = branch or (test, entry, regs, imms[0])
        if not effects and len(outs) == 1 and len(regs) == 2 and not imms:
            arithmetic[test["mnemonic"]] = (test, entry, outs[0], regs)
    if branch is None or len(arithmetic) < 2:
        return None, None, "no two-register branch, or fewer than two two-register operations"
    test, entry, regs, imm = branch
    isa = test.get("isa") or ""

    def op(mnemonic, dest, a, b):
        t, e, out, ins = arithmetic[mnemonic]
        word = lift.place_operand(int(t["encoded"], 16), e, out["name"], dest)
        word = lift.place_operand(word, e, ins[0]["name"], a)
        return lift.place_operand(word, e, ins[1]["name"], b)

    def br(a, b, offset):
        word = lift.place_operand(int(test["encoded"], 16), entry, regs[0]["name"], a)
        word = lift.place_operand(word, entry, regs[1]["name"], b)
        return lift.place_operand(word, entry, imm["name"], offset & ((1 << 13) - 1))

    # ⚠️ THE FLIP is a multiply by minus one, which the corpus has; an add
    # would need a register holding -2x to do the same, and nothing here does.
    # It has to be the multiplier, not whatever is slowest: the instruction
    # must compute a product.
    def computes(mnemonic, operator):
        tree = arithmetic[mnemonic][1].get("semantics_ast") or {}
        return tree.get("op") == operator and [a.get("symbol") for a in tree.get("args", [])] \
            == [o["name"] for o in arithmetic[mnemonic][3]]

    flip = next((m for m in arithmetic if computes(m, "mul")), None)
    add = next((m for m in arithmetic if computes(m, "add")), None)
    if flip is None or add is None:
        return None, None, "no multiply to flip a sign with, or no add to count with"
    back = -16
    loop = [
        op(flip, FLIP, FLIP, MINUS_ONE),        # 1, -1, 1, -1, ...
        br(FLIP, ONE, 8),                       # taken on -1: T, N, T, N
        op(add, SINK, SINK, ONE),               # skipped when taken
        op(add, COUNTER, COUNTER, MINUS_ONE),
        br(COUNTER, 0, back),                   # back while the counter is not zero
        # ⚠️ One instruction after, because a redirect is paid by a successor
        # and the loop's exit is a mispredict with nothing behind it otherwise.
        op(add, AFTER, ONE, ONE),
    ]
    checked = lift.lift(loop[4], isa or None)
    if checked is None or checked["operands"].get(imm["name"]) not in (back, back & ((1 << 13) - 1)):
        return None, None, f"{test['mnemonic']}'s offset will not hold {back}"
    return loop, isa, None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    # Trace-driven cores only: an execution-driven gshare predicts ahead of
    # what has retired, and this gate's stall/count identity is the in-order
    # trace front end's.
    cores = [core for core in cores if core.get("engine") != "execute"]
    gshares = sorted((core for core in cores if core.get("predictor") == "gshare"),
                     key=lambda core: core.get("predictor_history", 0))

    def twin_of(core):
        keys = ("issue_width", "units", "rob", "branch_penalty", "predictor_entries", "lsq")
        return next((other for other in cores if other.get("predictor") == "bimodal"
                     and all(other.get(k) == core.get(k) for k in keys)), None)

    # ⚠️ The longest history THAT HAS A BIMODAL TWIN. "The longest history"
    # alone became a gshare with a bigger table when the corpus grew one for
    # TAGE, and this gate quietly declined -- the second time a new core has
    # switched a gate off by out-ranking the one it compared.
    history = next((core for core in reversed(gshares) if twin_of(core)), None)
    # ⚠️ And one whose history is too short to see an alternation inside a
    # loop: the outcome just before the alternating branch is always the
    # loop's own, so one bit cannot tell the phases apart.
    short = next((core for core in gshares if core.get("predictor_history") == 1), None)

    def twin(core):
        keys = ("issue_width", "units", "rob", "branch_penalty", "predictor_entries", "lsq")
        return (core.get("predictor") == "bimodal"
                and all(core.get(k) == history.get(k) for k in keys))

    counter = next((core for core in cores if twin(core)), None) if history else None
    if history is None or counter is None or short is None or short is history:
        print(f"  {name}: DECLINED no gshare core with a bimodal twin and a one-bit sibling")
        return 0, 0
    if history.get("rob"):
        print(f"  {name}: DECLINED `{history['name']}` has a window; the stall/count "
              f"identity holds for an in-order front end only")
        return 0, 0

    module = f"hist_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    loop, isa, why = build_loop(lift, tests, latency_of)
    sys.modules.pop(module, None)
    if loop is None:
        print(f"  {name}: DECLINED {why}")
        return 0, 0

    runs = [f'  go("{tag}_{trips}", "{core["name"]}", {trips}u);'
            for tag, core in (("COUNT", counter), ("HIST", history), ("SHORT", short))
            for trips in TRIPS]
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "entry": ENTRY,
        "isa": f'"{isa}"' if isa else "NULL",
        "loop": ", ".join(f"{w}u" for w in loop),
        "flip": FLIP, "minus": MINUS_ONE, "one": ONE, "counter": COUNTER,
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
                              "miss": int(parts[6]), "stalls": int(parts[8])}

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    low, high = TRIPS
    for tag in ("COUNT", "HIST", "SHORT"):
        for trips in TRIPS:
            checks += 1
            if f"{tag}_{trips}" not in said:
                fail(f"{tag} at {trips} trips reported nothing")
    if failures:
        return checks, failures
    # The loop looped, identically on both machines.
    for trips in TRIPS:
        checks += 1
        if said[f"COUNT_{trips}"]["steps"] != said[f"HIST_{trips}"]["steps"]:
            fail(f"{trips} trips retired {said[f'COUNT_{trips}']['steps']} and "
                 f"{said[f'HIST_{trips}']['steps']} instructions on the two machines")
    checks += 1
    if said[f"HIST_{high}"]["steps"] <= said[f"HIST_{low}"]["steps"]:
        fail(f"{high} trips retired no more than {low}; the loop did not loop")
    if failures:
        return checks, failures

    # ⚠️ A counter per address pays for the pattern every iteration.
    grew = said[f"COUNT_{high}"]["miss"] - said[f"COUNT_{low}"]["miss"]
    checks += 1
    if grew < (high - low) // 2:
        fail(f"bimodal's mispredicts grew by {grew} from {low} to {high} trips of an "
             f"alternating branch; a counter per address cannot learn a pattern, and must "
             f"pay at least once every two iterations")
    # ⚠️ A history too SHORT to span the pattern is no history: the declared
    # length is a number the predictor has to read, and a machine that used
    # more bits than it declared would learn what this one cannot.
    grew_short = said[f"SHORT_{high}"]["miss"] - said[f"SHORT_{low}"]["miss"]
    checks += 1
    if grew_short < (high - low) // 2:
        fail(f"gshare with one bit of history mispredicted {grew_short} more times from "
             f"{low} to {high} trips; inside a loop that bit is always the loop's own "
             f"branch, so it cannot tell the two phases apart -- it learned something it "
             f"cannot see")
    # ⚠️ History stops the scaling.
    checks += 1
    if said[f"HIST_{high}"]["miss"] != said[f"HIST_{low}"]["miss"]:
        fail(f"gshare mispredicted {said[f'HIST_{low}']['miss']} times at {low} trips and "
             f"{said[f'HIST_{high}']['miss']} at {high}; with history the alternation is two "
             f"habits, and what it costs must stop growing")
    # And the front end agrees with the count.
    penalty = history.get("branch_penalty", 0)
    for key, row in said.items():
        checks += 1
        if row["stalls"] != row["miss"] * penalty:
            fail(f"{key}: {row['miss']} mispredicts at a penalty of {penalty} idled the "
                 f"front end {row['stalls']} cycles, not {row['miss'] * penalty}")
    checks += 1
    if said[f"HIST_{high}"]["cycles"] >= said[f"COUNT_{high}"]["cycles"]:
        fail(f"gshare took {said[f'HIST_{high}']['cycles']} cycles and bimodal "
             f"{said[f'COUNT_{high}']['cycles']} on {high} trips; fewer mispredicts must "
             f"be less time")

    if not failures:
        print(f"  {name}: an alternating branch over {low} and {high} trips -- bimodal "
              f"{said[f'COUNT_{low}']['miss']} and {said[f'COUNT_{high}']['miss']} mispredicts, "
              f"gshare {said[f'HIST_{low}']['miss']} either way ("
              f"{said[f'SHORT_{low}']['miss']} and {said[f'SHORT_{high}']['miss']} with one bit "
              f"of history); {checks} checks")
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
        print("history learns a pattern: SKIP")
        return DECLINED
    print(f"history learns a pattern: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
