#!/usr/bin/env python3
"""The wrong path runs, touches the caches, and leaves nothing else behind.
Gate.

`(front-end ... (wrong-path-execute true))` (docs/ooo_design.md, O12): at a
mispredict the functional side forks, runs down the path the prediction
pointed at with its stores held back and its traps swallowed, and is restored
exactly; as much of that run as the machine could reach before resolution
then touches the caches -- down the path it really took, with its loads and
stores. Three machines identical but for the wrong path -- one that executes
it, one where it touches nothing, one that only fetches it in line order:

  * **a wrong-path load prefetches**: the correct path later loads what the
    wrong path loaded, and misses exactly once fewer;
  * **a wrong-path load pollutes**: the wrong path loads a line that evicts
    one the correct path reloads, which then misses exactly once more;
  * **a wrong-path store never lands, and the wrong path sees it**: the
    wrong path stores a pointer, reloads it and loads through it, so the
    line it points at is prefetched -- while the correct path, loading the
    same word, sees memory as it was, every register and every byte the same
    on all three machines;
  * **a wrong-path instruction that does not decode ends the run**: nothing
    after it ran, the host heard nothing, and exactly the instructions
    before it count;
  * **the executed path follows its own branches**: a jump on the wrong path
    to code the correct path runs later prefetches that code's line, which
    fetching in line order cannot reach;
  * **the wrong path mispredicts too**: a branch on it the predictor gets
    wrong sends fetch down a detour until that branch resolves, and then the
    path resumes where the branch really went -- both sides reach the cache,
    and the detour's stores go when it does;
  * **a detour is a wrong path** (W5): a branch on a detour the predictor
    gets wrong has a detour of its own, squashed when IT resolves, and each
    path resumes where its branch went -- three levels reach the cache;
  * **touched, never charged**: a wrong path the correct path never meets
    costs exactly what no wrong path costs;
  * **only the executing machine reports a wrong path at all**.

Usage: tools/wrongpath_check.py [corpus.axisl ...]
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

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
DATA = 0x4000
BASE, FAR, ONE, VALUE, POINTER = 5, 6, 8, 2, 10
#: Where POINTER points: another line of the data cache from X's.
POINTEE = 2048

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];
static int TRAPS;

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
  (void)c; (void)cause; TRAPS++; *stop = 1; return pc;
}

static void go(const char *tag, const char *core, const uint32_t *words, int32_t count) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  TRAPS = 0;
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
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->set_reg(m, %(base)d, %(data)du);
  S->set_reg(m, %(far)d, %(data)du + %(alias)du);
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(pointer)d, %(data)du + %(pointee)du);
  S->count_cycles(m, 1);
  S->run(m, 1000u);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = 0; a < IMAGE; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu dmiss %%llu imiss %%llu wrong %%llu traps %%d mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->cache_misses(m), (unsigned long long)S->icache_misses(m),
         (unsigned long long)S->wrong_path_instructions(m), TRAPS, (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->wrong_path_instructions) { printf("NOWRONGPATH\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def layout(words: dict, length: int, filler):
    """A program as {index: word}; every other index up to `length` is filler."""
    return [words.get(i, filler) for i in range(length)]


def build_programs(asm: Assembler, bnz, alias):
    add, mul = asm.fast_add, asm.slow
    pad = asm.op(add, 30, 1, 1)
    head = {0: asm.op(mul, 20, ONE, ONE), 1: asm.op(mul, 20, 20, 20), 2: asm.op(mul, 20, 20, 20)}

    def jump(at, to, reg=ONE):
        return bnz(reg, 0, 4 * (to - at))

    programs = {}
    # PREFETCH: the wrong path (4..) loads A; the correct path (8..) loads A.
    programs["PREFETCH"] = layout({**head, 3: jump(3, 8, 20),
                                   4: asm.ld(21, BASE, 0), 5: jump(5, 12), 6: pad, 7: pad,
                                   8: asm.ld(22, BASE, 0), 9: asm.op(add, 23, 22, 22),
                                   10: jump(10, 12), 11: pad, 12: asm.op(add, 24, 1, 1),
                                   13: asm.op(add, 25, 1, 1)}, 14, pad) + [0]
    # POLLUTE: B is loaded first; the wrong path loads the line `alias` bytes
    # on, which a direct-mapped cache of that size keeps in B's set; the
    # correct path reloads B.
    programs["POLLUTE"] = layout({0: asm.ld(23, BASE, 0), 1: head[0], 2: head[1], 3: head[2],
                                  4: jump(4, 9, 20),
                                  5: asm.ld(21, FAR, 0), 6: jump(6, 13), 7: pad, 8: pad,
                                  9: asm.ld(22, BASE, 0), 10: pad, 11: jump(11, 13), 12: pad,
                                  13: asm.op(add, 24, 1, 1), 14: asm.op(add, 25, 1, 1)},
                                 15, pad) + [0]
    # STORE: the wrong path stores a POINTER to X, reloads it, and loads
    # through it. Only if a wrong-path load sees the wrong path's own store
    # does the dereference reach the pointer's line. The correct path then
    # loads X -- which must still hold what memory held, not the pointer --
    # and the pointed-to line.
    programs["STORE"] = layout({**head, 3: jump(3, 8, 20),
                                4: asm.st(POINTER, BASE, 64), 5: asm.ld(21, BASE, 64),
                                6: asm.ld(22, 21, 0), 7: jump(7, 12),
                                8: asm.ld(23, BASE, 64), 9: asm.ld(24, POINTER, 0),
                                10: jump(10, 12), 11: pad, 12: asm.op(add, 25, 23, 24),
                                13: asm.op(add, 26, 1, 1)}, 14, pad) + [0]
    # UNDECODED: one wrong-path load, then a word that decodes to nothing.
    programs["UNDECODED"] = layout({**head, 3: jump(3, 8, 20),
                                    4: asm.ld(21, BASE, 0), 5: 0, 6: asm.ld(21, BASE, 128),
                                    7: pad, 8: asm.op(add, 24, 1, 1), 9: asm.op(add, 25, 1, 1)},
                                   10, pad) + [0]
    # FOLLOW: the wrong path jumps to F, six lines away; the correct path
    # jumps there later. In line order, fetch never gets that far.
    far = 96
    programs["FOLLOW"] = layout({**head, 3: jump(3, 8, 20),
                                 4: jump(4, far), 5: pad, 6: pad, 7: pad,
                                 8: asm.op(add, 24, 1, 1), 9: asm.op(add, 25, 1, 1),
                                 10: jump(10, far), 11: pad,
                                 far: asm.op(add, 26, 1, 1), far + 1: asm.op(add, 27, 1, 1)},
                                far + 2, pad) + [0]
    # ⚠️ DETOUR (W3): the wrong path has a branch of its own, and the
    # predictor has never seen it -- so the front end falls through it while
    # the wrong path "really" jumps. The fall-through, a detour, loads A and
    # stores a pointer over X; then the branch resolves, the detour is
    # squashed, and the path resumes where the branch went: it loads X -- as
    # memory has it, not as the detour stored it -- and loads through that.
    # The right path then loads A, X, and the word the clean X points near.
    # Five multiplies hold the outer branch long enough for all of it.
    # ⚠️ NOT also the word the stored pointer leads to: with both, a resumed
    # path that saw the detour's store prefetched the one instead of the
    # other, the count was the same, and mutation testing said so.
    chain = {0: asm.op(mul, 20, ONE, ONE)}
    chain.update({k: asm.op(mul, 20, 20, ONE) for k in range(1, 5)})
    programs["DETOUR"] = layout({**chain, 5: jump(5, 20, 20),
                                 6: asm.op(mul, 24, ONE, ONE), 7: asm.op(mul, 24, 24, ONE),
                                 8: jump(8, 14, 24),
                                 9: asm.ld(21, BASE, 0), 10: asm.st(POINTER, BASE, 128), 11: 0,
                                 14: asm.ld(22, BASE, 128), 15: asm.ld(23, 22, 256), 16: 0,
                                 20: asm.ld(25, BASE, 0), 21: asm.ld(26, BASE, 128),
                                 22: asm.ld(27, 0, 256)},
                                23, pad) + [0]
    # REFILL: the same, the outer branch held by three multiplies and an add
    # instead of five multiplies. The detour's branch resolves in time; the
    # path resumes a refill later, and its second load -- through the first --
    # is one cycle short of issuing when the outer branch resolves.
    programs["REFILL"] = list(programs["DETOUR"])
    programs["REFILL"][3] = asm.op(add, 20, 20, 0)
    programs["REFILL"][4] = pad
    # ⚠️ NESTED (W5): a detour with a branch of its own. The outer branch
    # waits on eight multiplies. Its wrong path is four multiplies and a
    # branch B1 on them, cold, so fetch falls through into B1's detour: one
    # multiply and a branch B2 on it, cold again, and B2's own detour loads A.
    # B2 resolves first; the path it took loads X, still inside B1's detour.
    # Then B1 resolves, and the path IT took loads Y. The right path loads all
    # three. One level of detour followed B2 where it went and never saw A.
    outer = {0: asm.op(mul, 20, ONE, ONE)}
    outer.update({k: asm.op(mul, 20, 20, ONE) for k in range(1, 8)})
    inner = {9: asm.op(mul, 24, ONE, ONE)}
    inner.update({k: asm.op(mul, 24, 24, ONE) for k in range(10, 13)})
    programs["NESTED"] = layout({**outer, 8: jump(8, 40, 20),
                                 **inner, 13: jump(13, 30, 24),
                                 14: asm.op(mul, 25, ONE, ONE), 15: jump(15, 22, 25),
                                 16: asm.ld(21, BASE, 0), 17: 0,
                                 22: asm.ld(22, BASE, 64), 23: 0,
                                 30: asm.ld(23, BASE, 128), 31: 0,
                                 40: asm.ld(26, BASE, 0), 41: asm.ld(27, BASE, 64),
                                 42: asm.ld(28, BASE, 128)},
                                43, pad) + [0]
    # ⚠️ DEEP (W5): a detour is no longer than the machine has room left for.
    # The outer branch waits on eight multiplies; its wrong path is six more
    # and a branch B1 on them, cold; and B1's detour is a straight line of
    # adds longer than anything holds. What is in flight ahead of the detour
    # is still in flight beside it, so the detour stops at what the fetch
    # buffer and the window hold LESS those seven -- and when B1 resolves, the
    # path it took is two more instructions and a word that does not decode.
    # A detour given the whole machine again ran seven further.
    slow = {9: asm.op(mul, 24, ONE, ONE)}
    slow.update({k: asm.op(mul, 24, 24, ONE) for k in range(10, 15)})
    programs["DEEP"] = layout({**outer, 8: jump(8, 120, 20),
                               **slow, 15: jump(15, 100, 24),
                               100: pad, 101: pad, 102: 0,
                               120: asm.op(add, 26, 1, 1), 121: asm.op(add, 27, 1, 1)},
                              122, pad) + [0]
    return programs


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

    runs = next((c for c in cores if fe(c).get("wrong_path_execute") and c.get("memory")), None)
    stays = reads = None
    if runs:
        base = {**fe(runs), "wrong_path_execute": False}

        def twin(extra):
            return next((c for c in cores if fe(c) == {**base, **extra}
                         and all(c.get(k) == runs.get(k) for k in
                                 ("memory", "issue_width", "units", "rob", "predictor",
                                  "predictor_entries", "branch_penalty"))), None)
        stays, reads = twin({}), twin({"wrong_path_fetch": True})
    if not runs or not stays or not reads:
        print(f"  {name}: DECLINED no wrong-path-executing core with both twins")
        return 0, 0
    dcache = memories.get(runs["memory"]) or {}
    if (dcache.get("ways") or 1) != 1 or not dcache.get("size_bytes"):
        print(f"  {name}: DECLINED the data cache is not direct-mapped")
        return 0, 0
    alias = dcache["size_bytes"]

    module = f"wp_{name}"
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
    programs = build_programs(asm, bnz, alias)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    machines = {"RUNS": runs, "STAYS": stays, "READS": reads}
    lines = [f'  go("{p}_{t}", "{c["name"]}", {p}, {len(w)});'
             for p, w in programs.items() for t, c in machines.items()]
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "data": DATA,
        "base": slot(BASE), "far": slot(FAR), "one": slot(ONE), "alias": alias,
        "pointer": slot(POINTER), "pointee": POINTEE,
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(lines),
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

    for program in programs:
        rows = [said.get(f"{program}_{t}") for t in machines]
        checks += 1
        if any(r is None for r in rows):
            fail(f"{program} reported nothing on some machine")
            continue
        checks += 1
        if len({(r["steps"], r["mark"], r["traps"]) for r in rows}) != 1:
            fail(f"{program} retired different instructions, left different registers or "
                 f"memory, or trapped differently on different machines: "
                 f"{[(r['steps'], r['traps']) for r in rows]}; the wrong path must leave "
                 f"nothing behind")
        for tag in ("STAYS", "READS"):
            checks += 1
            if said[f"{program}_{tag}"]["wrong"]:
                fail(f"{program} on {machines[tag]['name']} reported wrong-path instructions; "
                     f"only a machine that executes the wrong path runs any")
    if failures:
        return checks, failures

    def get(program, tag, key="dmiss"):
        return said[f"{program}_{tag}"][key]

    checks += 1
    if get("PREFETCH", "RUNS") != get("PREFETCH", "STAYS") - 1:
        fail(f"a wrong-path load of what the correct path loads later: {get('PREFETCH', 'RUNS')} "
             f"data misses executing the wrong path and {get('PREFETCH', 'STAYS')} not; it "
             f"prefetches, exactly one fewer")
    checks += 1
    if get("POLLUTE", "RUNS") != get("POLLUTE", "STAYS") + 1:
        fail(f"a wrong-path load evicting a line the correct path reloads: "
             f"{get('POLLUTE', 'RUNS')} data misses executing the wrong path and "
             f"{get('POLLUTE', 'STAYS')} not; it pollutes, exactly one more")
    # ⚠️ TOUCHED, NEVER CHARGED: a wrong path whose lines the correct path
    # never meets costs exactly nothing in time -- the redirect already is
    # what it cost. A wrong path whose misses were charged to the next
    # correct-path instruction passed every miss count here; mutation testing
    # said so.
    checks += 1
    if get("UNDECODED", "RUNS", "cycles") != get("UNDECODED", "STAYS", "cycles"):
        fail(f"a wrong path the correct path never meets cost {get('UNDECODED', 'RUNS', 'cycles')} "
             f"cycles executed and {get('UNDECODED', 'STAYS', 'cycles')} not; its misses are "
             f"touched, never charged")
    checks += 1
    if get("UNDECODED", "RUNS", "wrong") != 1:
        fail(f"a wrong path of one load and then a word that does not decode counted "
             f"{get('UNDECODED', 'RUNS', 'wrong')} wrong-path instructions; the run ends at the "
             f"word, so exactly one")
    # ⚠️ THE WRONG PATH READS ITS OWN STORES: the pointer it stored is the
    # pointer it reloads, so its dereference prefetches the pointed-to line
    # as well as X's -- exactly two fewer misses. A shadow that read memory
    # instead would load through zero and prefetch only X.
    checks += 1
    if get("STORE", "RUNS") != get("STORE", "STAYS") - 2:
        fail(f"a wrong path that stores a pointer, reloads it and loads through it: "
             f"{get('STORE', 'RUNS')} data misses executing it and {get('STORE', 'STAYS')} not; "
             f"its reload must see its own store, so both X's line and the pointee's are "
             f"prefetched -- exactly two fewer")
    checks += 1
    if not (get("FOLLOW", "RUNS", "imiss") < get("FOLLOW", "READS", "imiss")
            == get("FOLLOW", "STAYS", "imiss")):
        fail(f"a wrong-path jump to code run later: instruction misses "
             f"{get('FOLLOW', 'RUNS', 'imiss')} executing the wrong path, "
             f"{get('FOLLOW', 'READS', 'imiss')} fetching it in line order, "
             f"{get('FOLLOW', 'STAYS', 'imiss')} neither; only execution follows the jump")

    # ⚠️ THE WRONG PATH MISPREDICTS TOO (W3). All three of the right path's
    # loads were made already: A by the detour, X by the path resumed after
    # it, and the word X points near by the load through it -- through X as
    # memory has it, because a detour's stores go when it does. A resumed path
    # that read the detour's pointer would have loaded somewhere else.
    checks += 1
    if get("DETOUR", "STAYS") != 3 or get("DETOUR", "RUNS") != 0:
        fail(f"a wrong path with a mispredicted branch of its own: {get('DETOUR', 'RUNS')} "
             f"data misses executing it and {get('DETOUR', 'STAYS')} not; the detour, the "
             f"resumed path and its load through X as memory has it prefetch all three of "
             f"the right path's lines -- 0 and 3")

    # ⚠️ AND THE RESUMED PATH PAYS A REFILL: with the outer branch resolving
    # sooner, the load through X has not issued -- one more miss -- where a
    # path that resumed the cycle its branch resolved would have made it.
    checks += 1
    if get("REFILL", "STAYS") != 3 or get("REFILL", "RUNS") != 1:
        fail(f"the same wrong path under an outer branch that resolves sooner: "
             f"{get('REFILL', 'RUNS')} data misses executing it and {get('REFILL', 'STAYS')} "
             f"not; the path resumes a refill after its own branch resolves, so its load "
             f"through X is too late -- 1 and 3")

    # ⚠️ A DETOUR IS A WRONG PATH (W5), and its branches have detours of their
    # own: A is loaded two detours deep, X by the path the inner branch took,
    # Y by the path the outer one took.
    checks += 1
    if get("NESTED", "STAYS") != 3 or get("NESTED", "RUNS") != 0:
        fail(f"a wrong-path branch whose detour has a mispredicted branch of its own: "
             f"{get('NESTED', 'RUNS')} data misses executing it and {get('NESTED', 'STAYS')} "
             f"not; the inner detour, the path its branch took and the path the outer one "
             f"took prefetch all three of the right path's lines -- 0 and 3")

    # ⚠️ AND NO LONGER THAN THE ROOM LEFT: everything the machine holds, once,
    # and then the two instructions of the path the inner branch took.
    front = fe(runs)
    holds = (front.get("buffer") or front["fetch_width"] * (front["depth"] + 1)) + runs["rob"]
    checks += 1
    if get("DEEP", "RUNS", "wrong") != holds + 2:
        fail(f"a wrong-path branch whose detour is a straight line longer than the machine: "
             f"{get('DEEP', 'RUNS', 'wrong')} wrong-path instructions; the detour shares "
             f"the fetch buffer and the window with what came before it, {holds} in all, "
             f"and the path its branch took is 2 more -- {holds + 2}")

    if not failures:
        print(f"  {name}: prefetch {get('PREFETCH', 'RUNS')} vs {get('PREFETCH', 'STAYS')} data "
              f"misses, pollution {get('POLLUTE', 'RUNS')} vs {get('POLLUTE', 'STAYS')}; a "
              f"wrong-path store left memory alone; an undecodable word stopped the run after "
              f"{get('UNDECODED', 'RUNS', 'wrong')}; following a wrong-path jump "
              f"{get('FOLLOW', 'RUNS', 'imiss')} instruction misses vs "
              f"{get('FOLLOW', 'READS', 'imiss')} in line order; {checks} checks")
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
        print("the wrong path leaves nothing but its cache lines: SKIP")
        return DECLINED
    print(f"the wrong path leaves nothing but its cache lines: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
