#!/usr/bin/env python3
"""What a predictor buys is visible only over a loop. Gate.

`(branch (penalty N))` says what a redirect costs. `(predictor bimodal
(entries M))` says how often the machine pays it -- and the two are different
questions. A branch executed once is a cold miss whatever the machine keeps, so
a predictor cannot be measured on straight-line code at all: it has to be asked
about a branch that repeats.

⚠️ NO PREDICTOR is the predictor that always guesses "not taken". A machine
without one is not a special case in the model; it is the degenerate
configuration, mispredicting on exactly the taken branches. That is what keeps
the model that came before this a configuration of the model that came after,
and `branch_check.py` still holds that end of it.

The program is a countdown loop, built from the corpus's own instructions: a
register decremented by one that was seeded with minus one, and a branch back
while it differs from a register seeded with zero. What it holds:

  * **a machine that does not guess pays per iteration**: the loop costs one
    mispredict for every taken branch, so its cost scales with the trip count;
  * **a machine that guesses pays a constant**: two to warm the counter up and
    one when the loop finally exits -- three, whether the loop ran eight times
    or sixteen. THIS is the property. A predictor that helped proportionally
    would be a faster machine, not a predicting one;
  * **the difference is exactly the penalty per mispredict avoided**, so the
    cycle count and the mispredict count agree rather than being two
    independent claims;
  * **the loop actually looped**: the same trip count retires the same
    instructions on both machines, and more of them when asked for more
    iterations.

Usage: tools/predictor_check.py [corpus.axisl ...]
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
TRIPS = (8, 16)
#: Registers the harness seeds: a counter, a minus one, and a zero.
COUNTER, MINUS_ONE, ZERO = 1, 2, 3

HARNESS = r"""
/* A countdown loop, run on a machine that guesses and one that does not. */
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
  S->set_reg(m, %(counter)d, trips);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(zero)d, 0);
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)(trips * 4u + 8u));
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


def build_loop(lift, tests):
    """`counter += -1; branch back while counter != zero`.

    ⚠️ Assembled from the corpus's own fixtures, with no instruction invented
    for the occasion -- the decrement is an ordinary add of a register the
    harness seeded with minus one. A loop built from a special instruction
    would be a loop no description has to contain.
    """
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    branch = adder = None
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        redirects = any(effect.get("kind") == "setpc"
                        for effect in (entry.get("effects") or []))
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        imms = [o for o in entry["operands"]
                if o["role"] == "in" and o["kind"] == "imm"]
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        if redirects and len(regs) == 2 and len(imms) == 1:
            branch = branch or (test, entry, regs, imms[0])
        if (not redirects and not entry.get("effects")
                and len(outs) == 1 and len(regs) == 2 and not imms):
            adder = adder or (test, entry, outs[0], regs)
    if branch is None or adder is None:
        return None, None, ("no branch comparing two registers and no "
                            "two-register add to count down with")

    test, entry, regs, imm = branch
    isa = test.get("isa") or ""
    add_test, add_entry, add_dest, add_regs = adder

    decrement = lift.place_operand(int(add_test["encoded"], 16), add_entry,
                                   add_dest["name"], COUNTER)
    decrement = lift.place_operand(decrement, add_entry, add_regs[0]["name"], COUNTER)
    decrement = lift.place_operand(decrement, add_entry, add_regs[1]["name"], MINUS_ONE)

    # ⚠️ A SECOND branch in the body, one that never goes anywhere. Its only
    # job is to have a different address from the one that does: with a single
    # branch in the program, any index at all -- including a constant -- gives
    # the same answer, and a table that put every branch on one counter passed
    # unnoticed. Two branches with opposite habits interfere if they share a
    # counter, which is the whole reason a table has a size.
    never = lift.place_operand(int(test["encoded"], 16), entry,
                               regs[0]["name"], ZERO)
    never = lift.place_operand(never, entry, regs[1]["name"], ZERO)
    never = lift.place_operand(never, entry, imm["name"], 8)

    # The back branch is two instructions on, and goes back to the decrement.
    back = (1 << 13) - 8
    jump = lift.place_operand(int(test["encoded"], 16), entry, regs[0]["name"], COUNTER)
    jump = lift.place_operand(jump, entry, regs[1]["name"], ZERO)
    jump = lift.place_operand(jump, entry, imm["name"], back)
    checked = lift.lift(jump, isa or None)
    if checked is None or checked["operands"].get(imm["name"]) != back:
        return None, None, f"{test['mnemonic']}'s offset will not hold {back}"
    # ⚠️ One instruction AFTER the loop, because a redirect is paid by a
    # successor. The branch that leaves the loop is the one a predictor gets
    # wrong, and with nothing behind it that mispredict costs nothing -- the
    # cycle count and the mispredict count then disagree by exactly one
    # penalty, which is a real discrepancy about a program that ends badly
    # rather than anything about predicting.
    after = lift.place_operand(int(add_test["encoded"], 16), add_entry,
                               add_dest["name"], 5)
    after = lift.place_operand(after, add_entry, add_regs[0]["name"], ZERO)
    after = lift.place_operand(after, add_entry, add_regs[1]["name"], ZERO)
    return [decrement, never, jump, after], isa, None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    blind = guessing = None
    for core in facts.get("cores", []):
        if not core.get("branch_penalty"):
            continue
        if core.get("predictor"):
            guessing = guessing or core
        else:
            blind = blind or core
    if blind is None or guessing is None:
        print(f"  {name}: DECLINED needs one core that predicts and one that "
              f"does not, both with a branch penalty")
        return 0, 0
    if blind["branch_penalty"] != guessing["branch_penalty"]:
        print(f"  {name}: DECLINED the two cores declare different penalties, "
              f"so a difference between them is not the predictor")
        return 0, 0
    penalty = blind["branch_penalty"]

    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"pr_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"pr_{name}")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    loop, isa, why = build_loop(lift, tests)
    sys.modules.pop(f"pr_{name}", None)
    if loop is None:
        print(f"  {name}: DECLINED {why}")
        return 0, 0

    runs = []
    for trips in TRIPS:
        runs.append(f'  go("BLIND{trips}", "{blind["name"]}", {trips}u);')
        runs.append(f'  go("GUESS{trips}", "{guessing["name"]}", {trips}u);')

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "entry": ENTRY,
        "isa": f'"{isa}"' if isa else "NULL",
        "loop": ", ".join(f"{w}u" for w in loop),
        "runs": "\n".join(runs),
        "counter": COUNTER, "minus": MINUS_ONE, "zero": ZERO,
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
    if "NOPREDICT" in done.stdout:
        print(f"  FAIL {name}: the simulator library reports no mispredicts")
        return 0, 1

    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 9 and parts[1] == "cycles":
            said[parts[0]] = (int(parts[2]), int(parts[4]), int(parts[6]),
                              int(parts[8]))

    checks = failures = 0
    for trips in TRIPS:
        for tag in (f"BLIND{trips}", f"GUESS{trips}"):
            checks += 1
            if tag not in said:
                print(f"  FAIL {name}: {tag} reported nothing")
                failures += 1
    if failures:
        return checks, failures

    # ⚠️ The loop has to have LOOPED. A program that fell out of its first
    # iteration mispredicts once on each machine and agrees beautifully.
    for trips in TRIPS:
        # Three instructions per iteration -- a decrement and two branches --
        # and the one the loop falls into.
        want_steps = 3 * trips + 1
        for tag in (f"BLIND{trips}", f"GUESS{trips}"):
            checks += 1
            if said[tag][1] != want_steps:
                print(f"  FAIL {name}: {tag} retired {said[tag][1]} "
                      f"instruction(s); {trips} iterations of a two-instruction "
                      f"loop is {want_steps}")
                failures += 1
    if failures:
        return checks, failures

    # A machine that does not guess pays once per taken branch.
    for trips in TRIPS:
        checks += 1
        if said[f"BLIND{trips}"][2] != trips - 1:
            print(f"  FAIL {name}: without a predictor, {trips} iterations "
                  f"take {trips - 1} taken branches and so {trips - 1} "
                  f"mispredicts; the machine reported "
                  f"{said[f'BLIND{trips}'][2]}")
            failures += 1

    # ⚠️ THE PROPERTY: a machine that guesses pays a CONSTANT. Two to warm the
    # counter and one to leave the loop, whether it ran eight times or sixteen.
    guessed = {trips: said[f"GUESS{trips}"][2] for trips in TRIPS}
    checks += 1
    if len(set(guessed.values())) != 1:
        print(f"  FAIL {name}: a predicting machine mispredicted {guessed} "
              f"across trip counts {list(TRIPS)}; what a predictor buys is "
              f"that the cost stops scaling with the loop")
        failures += 1
    checks += 1
    if set(guessed.values()) != {3}:
        print(f"  FAIL {name}: a two-bit counter starting at zero mispredicts "
              f"twice warming up and once on the exit -- three; the machine "
              f"reported {sorted(set(guessed.values()))}")
        failures += 1

    # ⚠️ The mispredicts and the FRONT-END IDLE are the same claim. Measured
    # against idle rather than against total cycles, because a pipeline keeps
    # retiring what is already in flight while the front end waits: a
    # mispredict costs the full penalty in fetch and rather less in time, and
    # the declaration is about the first.
    for trips in TRIPS:
        for tag in (f"BLIND{trips}", f"GUESS{trips}"):
            checks += 1
            want = said[tag][2] * penalty
            if said[tag][3] != want:
                print(f"  FAIL {name}: {tag} mispredicted {said[tag][2]} "
                      f"time(s) at a declared penalty of {penalty}, so the "
                      f"front end should have idled {want} cycles; the machine "
                      f"reported {said[tag][3]}")
                failures += 1
        # And guessing well has to save TIME, not only idle cycles.
        checks += 1
        if said[f"GUESS{trips}"][0] >= said[f"BLIND{trips}"][0]:
            print(f"  FAIL {name}: at {trips} iterations guessing cost "
                  f"{said[f'GUESS{trips}'][0]} cycles and not guessing "
                  f"{said[f'BLIND{trips}'][0]}; a predictor that saves no time "
                  f"is not worth its table")
            failures += 1

    if not failures:
        print(f"  {name}: {TRIPS[0]} and {TRIPS[1]} iterations cost "
              f"{said[f'BLIND{TRIPS[0]}'][2]} and {said[f'BLIND{TRIPS[1]}'][2]} "
              f"mispredicts without a predictor and 3 with one either way, "
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
        print("a predictor is worth a loop: SKIP")
        return DECLINED
    print(f"a predictor is worth a loop: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
