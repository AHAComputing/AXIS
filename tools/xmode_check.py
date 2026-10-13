#!/usr/bin/env python3
"""An execution-driven core runs the program the golden model runs, and on code
with nothing to speculate about, it is the trace-driven core. Gate.

`(engine execute)` on a `defcore` (docs/ooo_design.md, E1): the front end
fetches the PREDICTED path, instructions execute when they issue -- through the
generated executor, on the values older in-flight instructions produced --
branches resolve when they execute, wrong-path work occupies the window until
it is squashed, and every commit steps the golden functional model and checks
what the pipeline computed against it. A disagreement is a REPLAY.

  * **the anchor**: on programs with no branch and no memory, the
    execution-driven core costs exactly what its trace-driven twin costs,
    cycle for cycle -- one pipeline, timed two ways, agreeing where there is
    nothing to speculate about;
  * **the judge agrees**: seeded random programs -- loops, data-dependent
    forward branches, loads and stores into one region -- retire the same
    instructions and leave the same registers and the same memory as the
    functional simulator, with ZERO replays. Every dependence in this corpus
    is declared, so a replay is the engine failing to honour one;
  * **wrong paths are real**: a program that mispredicts squashes work that
    was fetched and executed down the wrong path;
  * **memory order is real**: a store whose address comes late, over a load
    of the same word that already executed, is a violation the engine
    catches -- and the architecture is still the golden model's.

Usage: tools/xmode_check.py [corpus.axisl ...] [--seeds N]
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

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
DATA = 0x4000
BASE, ONE, MINUS_ONE, COUNTER = 5, 8, 7, 9

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
  printf("%%s cycles %%llu steps %%llu miss %%llu replays %%llu squashed %%llu wrong %%llu "
         "violations %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->mispredicts(m), (unsigned long long)S->replays(m),
         (unsigned long long)S->squashed(m), (unsigned long long)S->wrong_path_instructions(m),
         (unsigned long long)S->memory_violations(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->replays) { printf("NOENGINE\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def anchor_programs(asm: Assembler):
    add, mul = asm.fast_add, asm.slow
    return {
        "ADDS": [asm.op(add, 10 + k % 12, 1, 2) for k in range(32)],
        "MULS": [asm.op(mul, 10 + k % 12, 1, 2) for k in range(16)],
        "CHAIN": [asm.op(mul, 10, 1, 1)] + [asm.op(mul, 10, 10, 10) for _ in range(7)],
        "MIX": [asm.op(mul if k % 3 == 2 else add, 10 + k % 6, 10 + (k + 1) % 6, 1)
                for k in range(30)],
    }


def random_program(asm: Assembler, bnz, rng: random.Random, body_len: int):
    """A loop whose body mixes arithmetic, forward branches on data, loads
    and stores into one 256-byte region. The counter is never written by the
    body, so the loop terminates."""
    add, mul = asm.fast_add, asm.slow
    work = list(range(10, 20))  # registers the body may clobber
    body = []
    while len(body) < body_len:
        kind = rng.choice(["add", "add", "mul", "load", "store", "branch"])
        if kind == "add":
            body.append(asm.op(add, rng.choice(work), rng.choice(work + [1, 2]), rng.choice(work + [1])))
        elif kind == "mul":
            body.append(asm.op(mul, rng.choice(work), rng.choice(work + [1]), rng.choice(work + [2])))
        elif kind == "load":
            body.append(asm.ld(rng.choice(work), BASE, 4 * rng.randrange(64)))
        elif kind == "store":
            body.append(asm.st(rng.choice(work + [1]), BASE, 4 * rng.randrange(64)))
        else:
            skip = rng.randrange(1, 4)
            body.append(bnz(rng.choice(work), rng.choice(work + [0]), 4 * (skip + 1)))
    # Branch targets must stay inside the body: pad so a skip past the end
    # lands on the counter update.
    body += [asm.op(add, 20, 20, 1) for _ in range(3)]
    body.append(asm.op(add, COUNTER, COUNTER, MINUS_ONE))
    body.append(bnz(COUNTER, 0, -4 * len(body)))
    return body + [asm.op(add, 21, 1, 1), 0]


def check(axis_file: Path, work: Path, seeds: int) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    execute = next((c for c in cores if c.get("engine") == "execute"), None)
    twin = None
    if execute:
        keys = [k for k in execute if k not in ("name", "engine", "vendor")]
        twin = next((c for c in cores if c.get("engine") != "execute"
                     and all(c.get(k) == execute.get(k) for k in keys)), None)
    if not execute or not twin:
        print(f"  {name}: DECLINED no execution-driven core with a trace-driven twin")
        return 0, 0

    module = f"xm_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no branch'}")
        return 0, 0
    anchors = anchor_programs(asm)
    rng = random.Random(1234)
    randoms = {f"R{k}": random_program(asm, bnz, rng, rng.randrange(8, 24)) for k in range(seeds)}
    # A late store over an already-executed load of the same word: the
    # store's address is the base plus a zero two multiplies take to produce.
    late = [asm.op(asm.slow, 12, 0, 0), asm.op(asm.slow, 12, 12, 12),
            asm.op(asm.fast_add, 13, BASE, 12), asm.st(1, 13, 8), asm.ld(14, BASE, 8),
            asm.op(asm.fast_add, 15, 14, 14), 0]
    # ⚠️ Two shapes random programs did not reach -- mutation testing said so.
    # FORWARD: commit is held behind a slow chain, so a store and a load of
    # the same word are both in flight together; the load must take the
    # store's bytes, not memory's.
    mul, add = asm.slow, asm.fast_add
    forward = [asm.op(mul, 16, ONE, ONE), asm.op(mul, 16, 16, 16), asm.op(mul, 16, 16, 16),
               asm.st(1, BASE, 40), asm.ld(14, BASE, 40), asm.op(add, 15, 14, 14), 0]
    # SURVIVOR: a slow chain writes x16, then a mispredicted branch -- cold,
    # taken, resolved at once -- squashes what came after it. The chain
    # survives the squash still executing, and the correct path's reader of
    # x16 must still wait for it: the rename map has to be rebuilt from who
    # is left, not forgotten.
    survivor = [asm.op(mul, 16, 1, 1), asm.op(mul, 16, 16, 1), asm.op(mul, 16, 16, 1),
                bnz(ONE, 0, 8), asm.op(add, 17, 1, 1),
                asm.op(add, 18, 16, 16), asm.op(add, 19, 18, 1), 0]
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    # A countdown loop, for what prediction buys in this engine: the
    # direction predictor and the target buffer both learn at commit, and
    # fetch follows what they learned -- so the loop's mispredicts must stop
    # growing with its trip count. Correctness never needed either one, so a
    # front end that never predicted taken passed everything else.
    loop = [asm.op(add, 20, 20, 1), asm.op(add, COUNTER, COUNTER, MINUS_ONE),
            bnz(COUNTER, 0, -8), asm.op(add, 21, 1, 1), 0]
    targeted = {"LATE": late, "FORWARD": forward, "SURVIVOR": survivor}
    programs = {**anchors, **randoms, **targeted}
    runs = []
    for label in anchors:
        for tag, core in (("X", execute["name"]), ("T", twin["name"])):
            runs.append(f'  go("{label}_{tag}", "{core}", {label}, {len(anchors[label])}, 1u);')
    for label in list(randoms) + list(targeted):
        for tag, core in (("X", execute["name"]), ("F", "")):
            runs.append(f'  go("{label}_{tag}", "{core}", {label}, {len(programs[label])}, 5u);')
    programs["LOOP"] = loop
    for trips in (8, 32):
        runs.append(f'  go("LOOP{trips}_X", "{execute["name"]}", LOOP, {len(loop)}, {trips}u);')
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "data": DATA,
        "base": slot(BASE), "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
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
        print(f"  FAIL {name}: the harness exited {done.returncode}: {done.stderr[-300:]}")
        return 0, 1
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 17 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])
        if done.stderr:
            print(done.stderr[-4000:])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    # ⚠️ THE ANCHOR, cycle for cycle.
    for label in anchors:
        x, t = said.get(f"{label}_X"), said.get(f"{label}_T")
        checks += 1
        if x is None or t is None:
            fail(f"{label} reported nothing")
            continue
        checks += 1
        if (x["steps"], x["mark"]) != (t["steps"], t["mark"]):
            fail(f"{label}: the execution-driven core retired {x['steps']} and the trace-driven "
                 f"{t['steps']}, or left different registers")
        checks += 1
        if x["cycles"] != t["cycles"]:
            fail(f"{label}, with no branch and no memory: {x['cycles']} cycles execution-driven "
                 f"and {t['cycles']} trace-driven; with nothing to speculate about, one pipeline "
                 f"timed two ways must agree exactly")
    # ⚠️ THE JUDGE AGREES, with zero replays.
    replays = 0
    for label in list(randoms) + list(targeted):
        x, f = said.get(f"{label}_X"), said.get(f"{label}_F")
        checks += 1
        if x is None or f is None:
            fail(f"{label} reported nothing")
            continue
        checks += 1
        if (x["steps"], x["mark"]) != (f["steps"], f["mark"]):
            fail(f"{label}: execution-driven retired {x['steps']} instructions and the functional "
                 f"simulator {f['steps']}, or they left different registers or memory")
        replays += x["replays"]
        checks += 1
        if x["replays"]:
            fail(f"{label}: {x['replays']} replay(s) -- commits where the golden model disagreed "
                 f"with what the pipeline computed; every dependence here is declared, so each "
                 f"is a dependence the engine did not honour")
    checks += 1
    short, long_ = said.get("LOOP8_X", {}).get("miss"), said.get("LOOP32_X", {}).get("miss")
    if short is None or short != long_:
        fail(f"a countdown loop mispredicted {short} times at 8 trips and {long_} at 32 on the "
             f"execution-driven core; what it learns at commit, fetch must follow")
    squashed = sum(said[f"{l}_X"]["wrong"] for l in randoms if f"{l}_X" in said)
    checks += 1
    if not squashed:
        fail("no random program squashed any wrong-path work; the engine is not fetching "
             "down predicted paths")
    checks += 1
    if not said.get("LATE_X", {}).get("violations"):
        fail("a store with a late address over an already-executed load of the same word was "
             "not caught as a violation")

    if not failures:
        print(f"  {name}: {len(anchors)} branch-free programs cycle-exact against the trace-driven "
              f"twin; {len(randoms)} random programs identical to the golden model with 0 replays, "
              f"{squashed} wrong-path instructions squashed; a late store caught "
              f"({said['LATE_X']['violations']} violation); {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--seeds", type=int, default=24)
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
        print("the execution-driven core runs the golden model's program: SKIP")
        return DECLINED
    print(f"the execution-driven core runs the golden model's program: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
