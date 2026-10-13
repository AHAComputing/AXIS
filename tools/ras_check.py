#!/usr/bin/env python3
"""A return goes back where its call came from, and a stack knows where. Gate.

`(front-end ... (ras N))` keeps a return-address stack (docs/ooo_design.md,
O9). What a call and a return ARE is derived, not marked: a call is a jump
that links into the link register the ISA's `defabi` names, and a return is
an indirect jump through that register that does not link. Two machines
identical but for the stack:

  * **a function called from two places**: a target buffer holds the last
    target a return took, so a return alternating between two call sites
    misses every time -- exactly twice an iteration -- while the stack, which
    pushed where each call came from, misses a constant number of times
    whatever the trip count;
  * **calls nested deeper than the stack**: twelve levels, each saving the
    link register to memory; the stack holds the last eight return
    addresses, so it saves exactly eight of the twelve cold returns the
    buffer-only machine misses -- no more, which is what a stack of eight is;
  * **the calls were recognised as calls**: the stack predicts nothing unless
    the classification found them, so a machine that derived no calls would
    agree with the buffer-only one;
  * **the architecture is untouched**, registers and memory both.

Usage: tools/ras_check.py [corpus.axisl ...]
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
from frontend_check import branch_encoder, jump_encoder  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
DATA = 0x4000
TRIPS = (8, 16)
DEPTH = 12
BASE, MINUS_ONE, COUNTER, ONE3 = 5, 7, 9, 3
FUNC = 16          # the register holding the called function's address
FIRST_TARGET = 16  # NEST: registers 16.. hold each level's address

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

typedef struct { int32_t slot; uint64_t value; } seed;

static void go(const char *tag, const char *core, const uint32_t *words, int32_t count,
               uint64_t start, const seed *seeds, int32_t nseeds, uint64_t steps) {
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
  S->reset(m, start, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  for (int32_t i = 0; i < nseeds; ++i) { S->set_reg(m, seeds[i].slot, seeds[i].value); }
  S->count_cycles(m, 1);
  S->run(m, steps);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = %(data)du; a < %(data)du + 256u; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu miss %%llu target %%llu stalls %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->mispredicts(m), (unsigned long long)S->target_mispredicts(m),
         (unsigned long long)S->front_end_stalls(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->target_mispredicts) { printf("NORAS\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def two_callers(asm, bnz):
    """F at the front; main calls it from two sites, round and round."""
    add, call = asm.fast_add, asm.jump
    words = [
        asm.op(add, 21, 21, ONE3),            # 0  F: some work
        call(0, 1),                           # 1     return: through the link register, no link
        call(1, FUNC),                        # 2  main: call F from site A
        asm.op(add, 20, 20, ONE3),            # 3
        call(1, FUNC),                        # 4  call F from site B
        asm.op(add, COUNTER, COUNTER, MINUS_ONE),  # 5
        bnz(COUNTER, 0, -16),                 # 6  back to 2
        asm.op(add, 15, 1, 1),                # 7
    ]
    return words, ENTRY + 8, {FUNC: ENTRY}, 9


def nest(asm):
    """Twelve levels, each saving the link register before calling deeper."""
    add, call = asm.fast_add, asm.jump
    words, seeds = [], {}
    # Level k (1-based) starts at word 4*(k-1): save ra, call k+1, restore, return.
    for k in range(1, DEPTH + 1):
        seeds[FIRST_TARGET + k - 1] = ENTRY + 16 * (k - 1)
        if k < DEPTH:
            words += [asm.st(1, BASE, 4 * k), call(1, FIRST_TARGET + k),
                      asm.ld(1, BASE, 4 * k), call(0, 1)]
        else:
            words += [asm.op(add, 22, 22, ONE3), call(0, 1),
                      asm.op(add, 0, 0, 0), asm.op(add, 0, 0, 0)]
    main = len(words)
    words += [call(1, FIRST_TARGET), asm.op(add, 15, 1, 1)]
    steps = 4 * (DEPTH - 1) + 2 + 2
    return words, ENTRY + 4 * main, seeds, steps


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    stacked = next((c for c in cores if (c.get("front_end") or {}).get("ras")), None)
    bare = None
    if stacked:
        want = {**stacked["front_end"], "ras": 0}
        bare = next((c for c in cores if c.get("front_end") == want
                     and all(c.get(k) == stacked.get(k) for k in
                             ("issue_width", "units", "rob", "commit_width", "branch_penalty",
                              "predictor", "predictor_entries", "lsq"))), None)
    if not stacked or not bare:
        print(f"  {name}: DECLINED no core with a return stack and a twin without one")
        return 0, 0
    ras = stacked["front_end"]["ras"]

    module = f"ras_{name}"
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
    why = asm.missing() or (None if bnz and asm.jump else "no branch or register jump")
    if why:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {why}")
        return 0, 0
    kind = asm.kind
    slot = lambda i: lift.register_slot(kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    two, two_start, two_seeds, per_trip = two_callers(asm, bnz)
    deep, deep_start, deep_seeds, deep_steps = nest(asm)
    sys.modules.pop(module, None)

    def seeds_c(label, seeds, extra):
        rows = [f"{{ {slot(r)}, {v}u }}" for r, v in {**extra, **seeds}.items()]
        return f"  static const seed {label}[] = {{ {', '.join(rows)} }};"

    common = {BASE: DATA, MINUS_ONE: 0xFFFFFFFF, ONE3: 1}
    programs = [f"  static const uint32_t TWO[] = {{ {', '.join(f'{w}u' for w in two)} }};",
                f"  static const uint32_t NEST[] = {{ {', '.join(f'{w}u' for w in deep)} }};",
                seeds_c("NEST_SEEDS", deep_seeds, common)]
    runs = []
    for trips in TRIPS:
        programs.append(seeds_c(f"TWO_SEEDS_{trips}", two_seeds, {**common, COUNTER: trips}))
        for tag, core in (("RAS", stacked), ("BARE", bare)):
            runs.append(f'  go("TWO_{tag}_{trips}", "{core["name"]}", TWO, {len(two)}, '
                        f'{two_start}u, TWO_SEEDS_{trips}, {len(common) + 2}, '
                        f'{per_trip * trips + 1}u);')
    for tag, core in (("RAS", stacked), ("BARE", bare)):
        runs.append(f'  go("NEST_{tag}", "{core["name"]}", NEST, {len(deep)}, {deep_start}u, '
                    f'NEST_SEEDS, {len(common) + len(deep_seeds)}, {deep_steps}u);')
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "data": DATA,
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(programs), "runs": "\n".join(runs),
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
    groups = [[f"TWO_{t}_{trips}" for t in ("RAS", "BARE")] for trips in TRIPS]
    groups.append(["NEST_RAS", "NEST_BARE"])
    for keys in groups:
        checks += 1
        rows = [said.get(k) for k in keys]
        if any(r is None for r in rows):
            fail(f"{keys} reported nothing")
        elif len({(r["steps"], r["mark"]) for r in rows}) != 1:
            fail(f"{keys} retired different instructions or left different state")
    if failures:
        return checks, failures
    # The loop looped and the nest nested.
    checks += 1
    if said[f"TWO_RAS_{high}"]["steps"] != (high * 9 + 1) or said["NEST_RAS"]["steps"] != deep_steps:
        fail(f"the programs did not run their whole course: "
             f"{said[f'TWO_RAS_{high}']['steps']} of {high * 9 + 1} and "
             f"{said['NEST_RAS']['steps']} of {deep_steps} steps")

    def target(key):
        return said[key]["target"]

    # ⚠️ A WRONG TARGET IS A REDIRECT: counted among the mispredicts, and paid
    # for in front-end idle exactly as a wrong direction is. A return stack
    # whose misses were only counted passed every other check here --
    # mutation testing said so.
    for key, row in said.items():
        machine = stacked if "_RAS" in key else bare
        refill = machine["front_end"]["depth"] + machine["branch_penalty"]
        checks += 1
        if row["target"] > row["miss"]:
            fail(f"{key}: {row['target']} target mispredicts and only {row['miss']} "
                 f"mispredicts; every wrong target is a redirect too")
        checks += 1
        if row["stalls"] != row["miss"] * refill:
            fail(f"{key}: {row['miss']} redirects idled the front end {row['stalls']} cycles, "
                 f"not {row['miss']} x {refill}")

    # ⚠️ TWO CALLERS: the buffer misses every return, the stack a constant.
    checks += 1
    grew = target(f"TWO_BARE_{high}") - target(f"TWO_BARE_{low}")
    if grew != 2 * (high - low):
        fail(f"without a return stack, a function called from two alternating sites mispredicted "
             f"{grew} more return targets over {high - low} more iterations; a target buffer "
             f"holds the last one, so it misses both returns every iteration -- "
             f"{2 * (high - low)}")
    checks += 1
    if target(f"TWO_RAS_{high}") != target(f"TWO_RAS_{low}"):
        fail(f"with a return stack the same program mispredicted {target(f'TWO_RAS_{low}')} and "
             f"{target(f'TWO_RAS_{high}')} targets at {low} and {high} trips; the stack pushed "
             f"where each call came from, so what it pays must not grow")
    checks += 1
    if said[f"TWO_RAS_{high}"]["cycles"] >= said[f"TWO_BARE_{high}"]["cycles"]:
        fail(f"the return stack cost {said[f'TWO_RAS_{high}']['cycles']} cycles and the buffer "
             f"alone {said[f'TWO_BARE_{high}']['cycles']}; fewer redirects must be less time")
    # ⚠️ NESTED DEEPER THAN THE STACK: it saves exactly its depth.
    checks += 1
    saved = target("NEST_BARE") - target("NEST_RAS")
    if saved != min(ras, DEPTH):
        fail(f"{DEPTH} nested calls: the return stack of {ras} mispredicted "
             f"{target('NEST_RAS')} targets and the buffer alone {target('NEST_BARE')}; the "
             f"stack holds the last {ras} return addresses, so it saves exactly "
             f"{min(ras, DEPTH)} of the cold returns, and it saved {saved}")

    if not failures:
        print(f"  {name}: two callers over {low}/{high} trips -- return targets missed "
              f"{target(f'TWO_BARE_{low}')}/{target(f'TWO_BARE_{high}')} without a stack, "
              f"{target(f'TWO_RAS_{low}')}/{target(f'TWO_RAS_{high}')} with {ras}; {DEPTH} nested "
              f"calls -- {target('NEST_BARE')} vs {target('NEST_RAS')}, the stack saving {saved}; "
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
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("a return goes back where its call came from: SKIP")
        return DECLINED
    print(f"a return goes back where its call came from: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
