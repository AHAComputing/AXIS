#!/usr/bin/env python3
"""An execution-driven core's wrong path is the real one. Gate.

E2 (docs/ooo_design.md): on a core with `(engine execute)` nothing forks or
reconstructs a wrong path -- the front end fetches the predicted path and the
pipeline executes it, so whatever a wrong path does to the machine it does for
real. Held against the trace engine's answers to the same programs:

  * **the wrong path, natively**: O12's programs, which the trace engine
    needed a forked functional side to answer, give the same cache results on
    an execution-driven core -- a wrong-path load prefetches (one miss fewer)
    and pollutes (one more), a stored pointer is reloaded and followed
    (two fewer), a wrong-path jump prefetches the code it reaches -- with the
    golden model agreeing at every commit and the counters counting only what
    committed;
  * **the return stack is repaired**: a call fetched down a mispredicted path
    pushes the stack, and after the squash the next return is exactly as
    predictable as it is when no such call was ever fetched; two callers
    alternating cost a constant number of wrong targets;
  * **history is speculative**: an alternating branch in a loop costs the same
    mispredicts at 16 trips and at 32 -- each prediction moved the history on
    and every squash put it back, so the history a branch is predicted with
    is the program's.

Usage: tools/xspec_check.py [corpus.axisl ...]
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
import wrongpath_check  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
DATA = 0x4000

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
               uint64_t start, const seed *seeds, int32_t nseeds) {
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
  if (!S->select_core(m, core[0] ? core : NULL)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, start, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  for (int32_t i = 0; i < nseeds; ++i) { S->set_reg(m, seeds[i].slot, seeds[i].value); }
  S->count_cycles(m, 1);
  S->run(m, 5000u);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = 0; a < IMAGE; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu miss %%llu target %%llu replays %%llu dmiss %%llu imiss %%llu "
         "viol %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->mispredicts(m), (unsigned long long)S->target_mispredicts(m),
         (unsigned long long)S->replays(m), (unsigned long long)S->cache_misses(m),
         (unsigned long long)S->icache_misses(m), (unsigned long long)S->memory_violations(m),
         (unsigned long long)mark);
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


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    memories = {m["name"]: m for m in facts.get("memories", [])}

    def fe(core):
        return core.get("front_end") or {}

    def execd(core):
        return core.get("engine") == "execute"

    xahead = next((c for c in cores if execd(c) and c.get("memory") and fe(c).get("icache")), None)
    stays = runs = None
    if xahead:
        def twin(extra):
            want = {**fe(xahead), **extra}
            return next((c for c in cores if not execd(c) and fe(c) == want
                         and c.get("memory") == xahead.get("memory")), None)
        stays = twin({})
        runs = twin({"wrong_path_execute": True})
    xret = next((c for c in cores if execd(c) and fe(c).get("ras")), None)
    xcor = next((c for c in cores if execd(c) and c.get("predictor") == "gshare"), None)
    missing = [n for n, c in (("execution-driven cached", xahead), ("trace twin", stays),
                              ("shadow twin", runs), ("execution-driven return stack", xret),
                              ("execution-driven gshare", xcor)) if c is None]
    if missing:
        print(f"  {name}: DECLINED no {', '.join(missing)} core")
        return 0, 0
    alias = memories[xahead["memory"]]["size_bytes"]

    module = f"xs_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    call = jump_encoder(lift, tests)
    if asm.missing() or bnz is None or call is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no branch or register jump'}")
        return 0, 0
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    add, mul = asm.fast_add, asm.slow
    W = wrongpath_check
    wp = W.build_programs(asm, bnz, alias)
    wp_seeds = {W.BASE: DATA, W.FAR: DATA + alias, W.ONE: 1, W.POINTER: DATA + W.POINTEE}

    # ⚠️ RETURN STACK REPAIR. F starts a slow branch that is taken and cold --
    # mispredicted -- so fetch runs down its fall-through, where WRONGCALL has
    # a call to G: fetched, so the stack is pushed, and squashed. F's return
    # must still find its caller on top. NOCALL is the same program without
    # that call.
    #
    # ⚠️ G is LONG, so the wrong path never reaches its return before the
    # outer branch resolves: a first version gave G one instruction, the wrong
    # path popped what it had pushed, and a stack that was never repaired came
    # out right by luck -- mutation testing said so.
    F, MAIN, G, G_LEN = 0, 7, 9, 40
    def repair(with_call):
        w = [asm.op(mul, 20, 8, 8), asm.op(mul, 20, 20, 20), bnz(20, 0, 4 * (5 - 2)),
             call(1, 23) if with_call else asm.op(add, 24, 1, 1), asm.op(add, 24, 1, 1),
             asm.op(add, 21, 21, 1), call(0, 1),
             call(1, 22), 0]
        w += [asm.op(add, 25, 25, 1) for _ in range(G_LEN)] + [call(0, 1)]
        return w
    repair_seeds = {8: 1, 22: ENTRY + 4 * F, 23: ENTRY + 4 * G}
    # Two callers, alternating, of one function (as ras_check builds it).
    two = [asm.op(add, 21, 21, 3), call(0, 1), call(1, 16), asm.op(add, 20, 20, 3),
           call(1, 16), asm.op(add, 9, 9, 7), bnz(9, 0, -16), asm.op(add, 15, 1, 1), 0]
    # ⚠️ SPECULATIVE HISTORY: an alternating branch in a loop.
    alt = [asm.op(mul, 12, 12, 7), bnz(12, 15, 8), asm.op(add, 14, 14, 1),
           asm.op(add, 9, 9, 7), bnz(9, 0, -16), asm.op(add, 13, 1, 1), 0]
    # ⚠️ And the same loop with a MEMORY VIOLATION every iteration: a store
    # whose address two multiplies produce, over a load of the same word that
    # has already read. Its squash -- not a branch's -- removes the branches
    # fetched behind it, and only putting the history back as it was before
    # the squashed load keeps the pattern. Resolution repairs history on its
    # own, so a squash that forgot to passed every branch-only program.
    alt_violating = [asm.op(mul, 12, 12, 7), asm.op(mul, 16, 0, 0), asm.op(mul, 16, 16, 16),
                     asm.op(add, 17, 5, 16), asm.st(1, 17, 0), asm.ld(18, 5, 0),
                     bnz(12, 15, 8), asm.op(add, 14, 14, 1),
                     asm.op(add, 9, 9, 7), bnz(9, 0, -36), asm.op(add, 13, 1, 1), 0]
    alt_seeds = {12: 1, 7: 0xFFFFFFFF, 15: 1}
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
    sys.modules.pop(module, None)

    programs, runs_c, seeds_c = {}, [], []

    def seeded(label, seeds):
        rows = [f"{{ {slot(r)}, {v}u }}" for r, v in seeds.items()]
        seeds_c.append(f"  static const seed {label}[] = {{ {', '.join(rows)} }};")
        return len(rows)

    n = seeded("WP_SEEDS", wp_seeds)
    for label, words in wp.items():
        programs[label] = words
        for tag, core in (("X", xahead), ("T", stays), ("S", runs)):
            runs_c.append(f'  go("{label}_{tag}", "{core["name"]}", {label}, {len(words)}, '
                          f'{ENTRY}u, WP_SEEDS, {n});')
    n = seeded("REPAIR_SEEDS", repair_seeds)
    for label, with_call in (("WRONGCALL", True), ("NOCALL", False)):
        programs[label] = repair(with_call)
        for tag, core in (("X", xret), ("F", {"name": ""})):
            runs_c.append(f'  go("{label}_{tag}", "{core["name"]}", {label}, {len(programs[label])}, '
                          f'{ENTRY + 4 * MAIN}u, REPAIR_SEEDS, {n});')
    programs["TWO"] = two
    programs["ALT"] = alt
    programs["VIOL"] = alt_violating
    for trips in (8, 16):
        n = seeded(f"TWO_SEEDS_{trips}", {16: ENTRY, 3: 1, 7: 0xFFFFFFFF, 9: trips})
        runs_c.append(f'  go("TWO{trips}_X", "{xret["name"]}", TWO, {len(two)}, {ENTRY + 8}u, '
                      f'TWO_SEEDS_{trips}, {n});')
    for trips in (16, 32):
        n = seeded(f"ALT_SEEDS_{trips}", {**alt_seeds, 9: trips, 5: DATA})
        runs_c.append(f'  go("ALT{trips}_X", "{xcor["name"]}", ALT, {len(alt)}, {ENTRY}u, '
                      f'ALT_SEEDS_{trips}, {n});')
        runs_c.append(f'  go("VIOL{trips}_X", "{xcor["name"]}", VIOL, {len(alt_violating)}, '
                      f'{ENTRY}u, ALT_SEEDS_{trips}, {n});')
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY,
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            [f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
             for label, words in programs.items()] + seeds_c),
        "runs": "\n".join(runs_c),
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
        if len(parts) == 19 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    def get(key, field="dmiss"):
        return said[key][field]

    groups = [[f"{l}_{t}" for t in ("X", "T", "S")] for l in wp]
    groups += [[f"{l}_X", f"{l}_F"] for l in ("WRONGCALL", "NOCALL")]
    for keys in groups:
        checks += 1
        if any(k not in said for k in keys):
            fail(f"{keys} reported nothing")
            continue
        checks += 1
        if len({(said[k]["steps"], said[k]["mark"]) for k in keys}) != 1:
            fail(f"{keys} retired different instructions or left different state")
    for key, row in said.items():
        if key.endswith("_X") or "_X" in key:
            checks += 1
            if row["replays"]:
                fail(f"{key}: {row['replays']} replay(s); the golden model disagreed with the "
                     f"pipeline")
    if failures:
        return checks, failures

    # ⚠️ THE WRONG PATH, NATIVELY: the trace engine's answers, without a fork.
    # ⚠️ Not STORE's "exactly two fewer": O12's shadow ran its wrong path in
    # program order, so its reload always saw its own store. This engine lets
    # the wrong-path reload issue before the store executes -- speculative
    # disambiguation -- and here it does: it reads memory, the dereference
    # goes nowhere, and the violation that would replay it comes after the
    # branch has squashed the whole path. X's line is prefetched, the pointee's
    # is not, and that is the engine's answer rather than an error in it. The
    # in-flight forwarding it skipped is xmode_check's FORWARD program.
    expect = {"PREFETCH": ("dmiss", -1), "POLLUTE": ("dmiss", +1)}
    for label, (field, delta) in expect.items():
        checks += 1
        if get(f"{label}_X", field) != get(f"{label}_T", field) + delta:
            fail(f"{label}: the execution-driven core missed {get(f'{label}_X', field)} times and "
                 f"the trace core with no wrong path {get(f'{label}_T', field)}; its own wrong "
                 f"path should make that {delta:+d}, as the forked one does "
                 f"({get(f'{label}_S', field)})")
    checks += 1
    if get("STORE_X") > get("STORE_T") - 1:
        fail(f"a wrong path that stores and reloads: {get('STORE_X')} misses execution-driven and "
             f"{get('STORE_T')} with no wrong path; the wrong path's own accesses must prefetch "
             f"at least the stored line")
    checks += 1
    if get("FOLLOW_X", "imiss") >= get("FOLLOW_T", "imiss"):
        fail(f"a wrong-path jump to code run later: {get('FOLLOW_X', 'imiss')} instruction misses "
             f"execution-driven and {get('FOLLOW_T', 'imiss')} with no wrong path; the jump the "
             f"wrong path took must have prefetched")
    # ⚠️ THE RETURN STACK IS REPAIRED.
    checks += 1
    if get("WRONGCALL_X", "target") != get("NOCALL_X", "target"):
        fail(f"a call fetched down a mispredicted path: {get('WRONGCALL_X', 'target')} wrong "
             f"targets with it and {get('NOCALL_X', 'target')} without; the squash must put the "
             f"return stack back as it was")
    checks += 1
    if get("TWO8_X", "target") != get("TWO16_X", "target"):
        fail(f"two callers alternating: {get('TWO8_X', 'target')} and {get('TWO16_X', 'target')} "
             f"wrong targets at 8 and 16 trips; the stack pushes where each call came from")
    # ⚠️ HISTORY IS SPECULATIVE.
    checks += 1
    if get("ALT16_X", "miss") != get("ALT32_X", "miss"):
        fail(f"an alternating branch cost {get('ALT16_X', 'miss')} and {get('ALT32_X', 'miss')} "
             f"mispredicts at 16 and 32 trips on execution-driven gshare; with history moved on "
             f"at each prediction and repaired at each squash, what it pays stops growing")

    checks += 1
    if get("VIOL16_X", "miss") != get("VIOL32_X", "miss"):
        fail(f"the alternating loop with a memory violation every iteration cost "
             f"{get('VIOL16_X', 'miss')} and {get('VIOL32_X', 'miss')} mispredicts at 16 and 32 "
             f"trips; a violation's squash must put the history back too")

    # And exactly what the same loop costs without them: a squash that
    # restores history leaves prediction untouched, whatever it squashed.
    for trips in (16, 32):
        checks += 1
        if get(f"VIOL{trips}_X", "miss") != get(f"ALT{trips}_X", "miss"):
            fail(f"at {trips} trips the alternating loop mispredicted {get(f'ALT{trips}_X', 'miss')} "
                 f"times and the same loop with a violation every iteration "
                 f"{get(f'VIOL{trips}_X', 'miss')}; a violation's squash must leave the branch "
                 f"history as it found it")

    if not failures:
        print(f"  {name}: the wrong path natively -- prefetch {get('PREFETCH_X')} vs "
              f"{get('PREFETCH_T')}, pollution {get('POLLUTE_X')} vs {get('POLLUTE_T')}, pointer "
              f"{get('STORE_X')} vs {get('STORE_T')}, jump {get('FOLLOW_X', 'imiss')} vs "
              f"{get('FOLLOW_T', 'imiss')}; a wrong-path call leaves {get('WRONGCALL_X', 'target')} "
              f"= {get('NOCALL_X', 'target')} wrong targets; alternating "
              f"{get('ALT16_X', 'miss')}/{get('ALT32_X', 'miss')}; 0 replays; {checks} checks")
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
        print("the execution-driven wrong path is the real one: SKIP")
        return DECLINED
    print(f"the execution-driven wrong path is the real one: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
