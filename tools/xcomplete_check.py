#!/usr/bin/env python3
"""The execution-driven engine does what the trace engine does, and its
exceptions are precise. Gate.

E3 (docs/ooo_design.md) closes what E1 left to the trace engine:

  * **memory policy without a trace**: loads and stores are known when they
    DECODE, from the effects the description declares, so a load can be held
    behind older stores before anything has executed. A loop whose late store
    aliases its load every iteration: speculation violates at least once per
    extra iteration, store sets violate a constant -- once collided, the pair
    waits -- and conservative never does. On the same loop without the alias,
    waiting costs conservative cycles that speculation does not pay, and
    speculation never violates;
  * **the queues bind**: independent loads behind a slow head cost more with
    two load-queue entries than with as many as the window;
  * **in order, timed both ways**: the in-order execution-driven core is its
    trace-driven twin cycle for cycle on code with nothing to speculate about,
    and on seeded random programs it is the golden model, with zero replays;
  * **precise traps**: a trap the host resumes after and a trap the host
    redirects to a handler are each taken exactly once, at commit -- counted
    as traps, never as replays -- with registers and memory the golden
    model's; a trap fetched down a wrong path is never taken, and the host's
    trap hook is called exactly as often as the functional simulator calls it.

Usage: tools/xcomplete_check.py [corpus.axisl ...] [--seeds N]
"""
from __future__ import annotations

import argparse
import importlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from lsq_check import Assembler, run_cmd  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402
from xmode_check import anchor_programs, random_program  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
DATA = 0x4000
HANDLER = 0x800
BASE, ONE, MINUS_ONE, COUNTER = 5, 8, 7, 9

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];
static int TRAPS, REDIRECT;

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
/* The host resumes after a trap -- at the next word, or at a handler. */
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; TRAPS++; *stop = 0; return REDIRECT ? %(handler)du : pc + 4u;
}

static void go(const char *tag, const char *core, const uint32_t *words, int32_t count,
               uint32_t trips, int redirect, const uint32_t *handler, int32_t hcount) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  TRAPS = 0; REDIRECT = redirect;
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) { MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b)); }
  }
  for (int32_t i = 0; i < hcount; ++i) {
    for (uint32_t b = 0; b < 4; ++b) { MEMORY[%(handler)d + 4 * i + b] = (uint8_t)(handler[i] >> (8 * b)); }
  }
  for (uint32_t a = 0; a < 256u; ++a) { MEMORY[%(data)du + a] = (uint8_t)(a * 37u + 11u); }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core[0] ? core : NULL)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->set_reg(m, %(base)d, %(data)du);
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
  S->count_cycles(m, 1);
  S->run(m, 20000u);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = %(data)du; a < %(data)du + 512u; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu replays %%llu viol %%llu traps %%llu hooked %%d mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->replays(m), (unsigned long long)S->memory_violations(m),
         (unsigned long long)S->traps(m), TRAPS, (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->traps) { printf("NOENGINE\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def trap_encoder(lift, tests):
    """The instruction whose only effect is a trap."""
    by = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    for test in tests:
        entry = by.get(test["mnemonic"])
        effects = (entry or {}).get("effects") or []
        if entry and effects and all(e.get("kind") == "trap" for e in effects):
            return int(test["encoded"], 16)
    return None


def check(axis_file: Path, work: Path, seeds: int) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])

    def execd(c):
        return c.get("engine") == "execute"

    def lsq_of(c, **want):
        l = c.get("lsq") or {}
        return execd(c) and l and all(l.get(k) == v for k, v in want.items())

    base = next((c for c in cores if execd(c) and not c.get("lsq") and c.get("rob")
                 and not (c.get("front_end") or {}).get("icache")
                 and not (c.get("front_end") or {}).get("ras") and c.get("predictor") == "bimodal"
                 and not c.get("memory")), None)
    cons = next((c for c in cores if lsq_of(c, disambiguation="conservative")), None)
    sets = next((c for c in cores if lsq_of(c, disambiguation="store-sets")), None)
    tight = next((c for c in cores if lsq_of(c, disambiguation="speculative") and c["lsq"]["loads"]), None)
    iexec = next((c for c in cores if execd(c) and not c.get("rob")), None)
    ifetch = None
    if iexec:
        keys = [k for k in iexec if k not in ("name", "engine", "vendor")]
        ifetch = next((c for c in cores if not execd(c) and all(c.get(k) == iexec.get(k) for k in keys)), None)
    missing = [n for n, c in (("speculative", base), ("conservative", cons), ("store-sets", sets),
                              ("bounded-queue", tight), ("in-order execution-driven", iexec),
                              ("in-order trace twin", ifetch)) if c is None]
    if missing:
        print(f"  {name}: DECLINED no {', '.join(missing)} core")
        return 0, 0

    module = f"xc_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    trap = trap_encoder(lift, tests)
    if asm.missing() or bnz is None or trap is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no branch or no trap instruction'}")
        return 0, 0
    add, mul = asm.fast_add, asm.slow

    def late_loop(offset):
        """Each iteration: a store whose address two multiplies produce, then a
        load at `offset` from the base, then work on what it loaded."""
        body = [asm.op(mul, 12, 0, 0), asm.op(mul, 12, 12, 12), asm.op(add, 13, BASE, 12),
                asm.st(1, 13, 0), asm.ld(14, BASE, offset), asm.op(mul, 15, 14, 14),
                asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
        body.append(bnz(COUNTER, 0, -4 * len(body)))
        return body + [asm.op(add, 21, 1, 1), 0]

    programs = {"ALIAS": late_loop(0), "APART": late_loop(64)}
    head = [asm.op(mul, 16, ONE, ONE)] + [asm.op(mul, 16, 16, 16) for _ in range(3)]
    programs["LOADS"] = head + [asm.ld(10 + k, BASE, 4 * k) for k in range(8)] + [0]
    anchors = anchor_programs(asm)
    rng = random.Random(4321)
    randoms = {f"R{k}": random_program(asm, bnz, rng, rng.randrange(8, 24)) for k in range(seeds)}
    # Traps: one in the middle of straight-line work; one fetched only down
    # the wrong path of a slow, cold, taken branch.
    programs["TRAP"] = [asm.op(add, 20, 1, 1), asm.op(add, 21, 20, 20), trap,
                        asm.op(add, 22, 21, 21), asm.op(add, 23, 22, 22), 0]
    programs["WRONGTRAP"] = [asm.op(mul, 20, ONE, ONE), asm.op(mul, 20, 20, 20),
                             bnz(20, 0, 8), trap, asm.op(add, 22, 1, 1),
                             asm.op(add, 23, 22, 22), 0]
    handler = [asm.op(add, 24, 1, 1), asm.op(add, 25, 24, 24), 0]
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
    sys.modules.pop(module, None)

    allp = {**programs, **anchors, **randoms, "HANDLER": handler}
    runs = []

    def run(tag, core, label, trips=1, redirect=0):
        runs.append(f'  go("{tag}", "{core}", {label}, {len(allp[label])}, {trips}u, {redirect}, '
                    f'HANDLER, {len(handler)});')

    for trips in (8, 16):
        for key, core in (("SPEC", base), ("SETS", sets), ("CONS", cons)):
            run(f"ALIAS{trips}_{key}", core["name"], "ALIAS", trips)
            run(f"APART{trips}_{key}", core["name"], "APART", trips)
        run(f"ALIAS{trips}_F", "", "ALIAS", trips)
    for key, core in (("SPEC", base), ("TIGHT", tight)):
        run(f"LOADS_{key}", core["name"], "LOADS")
    for label in anchors:
        run(f"{label}_IX", iexec["name"], label)
        run(f"{label}_IT", ifetch["name"], label)
    for label in randoms:
        run(f"{label}_IX", iexec["name"], label, 5)
        run(f"{label}_F", "", label, 5)
    for redirect in (0, 1):
        run(f"TRAP{redirect}_X", base["name"], "TRAP", 1, redirect)
        run(f"TRAP{redirect}_F", "", "TRAP", 1, redirect)
    run("WRONGTRAP_X", base["name"], "WRONGTRAP")
    run("WRONGTRAP_F", "", "WRONGTRAP")
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "data": DATA,
        "handler": HANDLER,
        "base": slot(BASE), "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in allp.items()),
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
        if len(parts) == 15 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    def get(key, field="cycles"):
        return said[key][field]

    expected = [r.split('"')[1] for r in runs]
    checks += 1
    if any(k not in said for k in expected):
        fail(f"no report for {[k for k in expected if k not in said][:5]}")
        return checks, failures
    for key, row in said.items():
        if key.endswith(("_SPEC", "_SETS", "_CONS", "_TIGHT", "_IX", "_X")):
            checks += 1
            if row["replays"]:
                fail(f"{key}: {row['replays']} replay(s)")
    # Every engine and policy leaves the golden model's architecture.
    for trips in (8, 16):
        checks += 1
        marks = {get(f"ALIAS{trips}_{k}", "mark") for k in ("SPEC", "SETS", "CONS", "F")}
        if len(marks) != 1:
            fail(f"the aliasing loop at {trips} trips left different state under different policies")
    # ⚠️ MEMORY POLICY WITHOUT A TRACE.
    grew = get("ALIAS16_SPEC", "viol") - get("ALIAS8_SPEC", "viol")
    checks += 1
    if grew < 8:
        fail(f"speculation violated {get('ALIAS8_SPEC', 'viol')} and {get('ALIAS16_SPEC', 'viol')} "
             f"times at 8 and 16 trips of a store aliasing a load every iteration; it bets every "
             f"time, so at least once an extra iteration")
    checks += 1
    if get("ALIAS8_SETS", "viol") != get("ALIAS16_SETS", "viol") or not get("ALIAS8_SETS", "viol"):
        fail(f"store sets violated {get('ALIAS8_SETS', 'viol')} and {get('ALIAS16_SETS', 'viol')} "
             f"times; they collide, learn, and never again")
    for trips in (8, 16):
        checks += 1
        if get(f"ALIAS{trips}_CONS", "viol") or get(f"APART{trips}_CONS", "viol"):
            fail(f"conservative violated at {trips} trips; it never lets a load pass an unexecuted store")
        checks += 1
        if get(f"APART{trips}_SPEC", "viol"):
            fail(f"speculation violated on a loop whose load never meets its store")
    checks += 1
    if get("APART16_CONS") <= get("APART16_SPEC"):
        fail(f"a load that never meets a late store cost {get('APART16_CONS')} conservative and "
             f"{get('APART16_SPEC')} speculative; waiting for an address must cost something")
    # ⚠️ THE QUEUES BIND.
    checks += 1
    if get("LOADS_TIGHT") <= get("LOADS_SPEC"):
        fail(f"eight loads behind a slow head cost {get('LOADS_TIGHT')} with two load-queue entries "
             f"and {get('LOADS_SPEC')} with the window; loads are known at decode, so the queue binds")
    # ⚠️ IN ORDER, TIMED BOTH WAYS.
    for label in anchors:
        checks += 1
        if (get(f"{label}_IX"), get(f"{label}_IX", "mark")) != (get(f"{label}_IT"), get(f"{label}_IT", "mark")):
            fail(f"{label}: the in-order core cost {get(f'{label}_IX')} execution-driven and "
                 f"{get(f'{label}_IT')} trace-driven, or left different registers")
    for label in randoms:
        checks += 1
        if (get(f"{label}_IX", "steps"), get(f"{label}_IX", "mark")) != (get(f"{label}_F", "steps"), get(f"{label}_F", "mark")):
            fail(f"{label}: the in-order execution-driven core is not the golden model")
    # ⚠️ PRECISE TRAPS.
    for redirect in (0, 1):
        x, f = said[f"TRAP{redirect}_X"], said[f"TRAP{redirect}_F"]
        how = "redirected to a handler" if redirect else "resumed after"
        checks += 1
        if (x["steps"], x["mark"], x["hooked"]) != (f["steps"], f["mark"], f["hooked"]):
            fail(f"a trap {how}: execution-driven retired {x['steps']}, called the hook "
                 f"{x['hooked']} times; the golden model {f['steps']} and {f['hooked']}")
        checks += 1
        if x["traps"] != 1 or x["replays"]:
            fail(f"a trap {how}: {x['traps']} trap(s) and {x['replays']} replay(s); one trap, "
                 f"taken at commit, and never a replay")
    x, f = said["WRONGTRAP_X"], said["WRONGTRAP_F"]
    checks += 1
    if x["traps"] or x["hooked"] != f["hooked"] or x["mark"] != f["mark"]:
        fail(f"a trap fetched only down a wrong path: {x['traps']} taken, hook called {x['hooked']} "
             f"times against {f['hooked']}; nothing on a wrong path traps")

    if not failures:
        print(f"  {name}: aliasing loop violations 8/16 trips -- speculative "
              f"{get('ALIAS8_SPEC', 'viol')}/{get('ALIAS16_SPEC', 'viol')}, store sets "
              f"{get('ALIAS8_SETS', 'viol')}/{get('ALIAS16_SETS', 'viol')}, conservative 0; "
              f"waiting costs {get('APART16_CONS')} vs {get('APART16_SPEC')}; two-entry queue "
              f"{get('LOADS_TIGHT')} vs {get('LOADS_SPEC')}; in order cycle-exact and {seeds} random "
              f"programs exact; traps precise; {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--seeds", type=int, default=16)
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "issue_width.axisl"]
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp), args.seeds)
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("the execution-driven engine is complete: SKIP")
        return DECLINED
    print(f"the execution-driven engine is complete: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
