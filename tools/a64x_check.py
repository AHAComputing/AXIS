#!/usr/bin/env python3
"""AArch64 on the execution-driven engine. Gate.

A64-1 (docs/ooo_design.md): the engine's first real ISA. An AArch64 program
reads and writes more than its operands -- a compare writes NZCV and a select
reads it, a BL writes X30 that no operand names, SP is register 31 of one
class and architectural state of the ISA, and a 128-bit destination is two
register slots. The engine has to know all of that when it DECODES, or the
golden model finds out at commit and the pipeline replays.

The corpus declares an ISA and no core, and AArch64 microarchitecture does not
belong in this repository. So the core here is the gate's own and neutral --
the same window, front end and predictor as `issue_width`'s `executes` --
composed onto the ISA in a temporary file, with the AAPCS64 call standard's
link register beside it (the return stack finds calls and returns through
it), and a twin with no return stack.

Held:

  * **straight-line code**: seeded random programs drawn from every
    instruction the 64-bit C executor runs -- integer, flag-setting,
    conditional, loads and stores of every width, atomics, exclusives,
    scalar and vector floating point -- leave exactly the golden model's
    registers, state and memory, with zero replays;
  * **flags**: a countdown loop -- SUBS, work, B.NE -- whose branch reads the
    flags its compare wrote, and a chain of compares and conditional selects:
    zero replays;
  * **calls**: BL to a function that RETs, from two alternating sites: zero
    replays (RET waits for the X30 its BL wrote), no wrong return targets
    with a return stack, and some without one;
  * **the stack**: SP decremented, stored through, loaded through and
    incremented again in a loop -- SP is state reached through register 31;
    and a load through SP behind a compare into XZR -- register 31 of the
    other class -- takes exactly the cycles of a load through X19;
  * **wide registers**: a Q load and a later 128-bit vector write to the same
    register, in either order of execution: zero replays;
  * **one timing**: on the programs with no branch to guess and no store to
    order -- the flag chain, the two loads, the wide pair -- the trace-driven
    twin takes exactly the execution-driven core's cycles: its dependences
    are the same state, link and alias dependences (A64-2).

Usage: tools/a64x_check.py [--seeds N] [--dump]
"""
from __future__ import annotations

import argparse
import collections
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

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl"
ISA = "aarch64_base"
CODE = 0xC000
FUNC = 0xE000

# Composed onto the ISA in a temporary file: neutral, the gate's own.
ADDITIONS = """
  (defabi a64x_aapcs64
    (isa aarch64_base)
    (pointer-bits 64)
    (stack-alignment 16)
    (stack-pointer (a64_gpr64sp 31))
    (frame-pointer (a64_gpr64 29))
    (link-register (a64_gpr64 30))
    (arguments (a64_gpr64 0 7))
    (returns (a64_gpr64 0 1))
    (callee-saved (a64_gpr64 19 29) (a64_gpr64sp 19 29))
    (caller-saved (a64_gpr64 0 18) (a64_gpr64 30) (a64_gpr64sp 0 18) (a64_gpr64sp 30))
    (reserved (a64_gpr64 31) (a64_gpr64sp 31)))
  (defcore a64x_ras
    (kind rvmt)
    (implements aarch64_base)
    (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2) (ras 8))
    (engine execute))
  (defcore a64x_trace
    (kind rvmt)
    (implements aarch64_base)
    (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2) (ras 8)))
  (defcore a64x_noras
    (kind rvmt)
    (implements aarch64_base)
    (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2))
    (engine execute))
"""

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"
extern const axis_sim_pack *%(sim)s(void);
#define IMAGE (1u << 16)
#define CODE %(code)du
/* Exact memory: the first 64 KiB flat, everything else a byte table keyed by
   the whole address -- no two addresses alias, as none do on the machine. */
#define FAR (1u << 20)
static uint8_t MEMORY[IMAGE];
static uint64_t FAR_AT[FAR]; static uint8_t FAR_V[FAR], FAR_USED[FAR];
static uint8_t *far(uint64_t a, int make) {
  uint32_t h = (uint32_t)((a * 0x9E3779B97F4A7C15ull) >> 44);
  for (uint32_t k = 0; k < FAR; ++k, h = (h + 1u) & (FAR - 1u)) {
    if (!FAR_USED[h]) { if (!make) { return 0; } FAR_USED[h] = 1; FAR_AT[h] = a; FAR_V[h] = (uint8_t)(a * 37u + 11u); return &FAR_V[h]; }
    if (FAR_AT[h] == a) { return &FAR_V[h]; }
  }
  return 0;
}
static uint8_t byte_at(uint64_t a) {
  if (a < IMAGE) { return MEMORY[a]; }
  uint8_t *p = far(a, 0);
  return p ? *p : (uint8_t)(a * 37u + 11u);
}
static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) { v |= (uint64_t)byte_at(a + i) << (8 * i); }
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) {
    uint64_t at = a + i; uint8_t b = (uint8_t)(v >> (8 * i));
    if (at < CODE) { MEMORY[at] = b; }
    else if (at >= IMAGE) { uint8_t *p = far(at, 1); if (p) { *p = b; } }
  }
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}
static const axis_pack_state_entry STATE[] = { %(state)s };

static void go(const char *tag, const char *core, const uint32_t *w, int32_t n,
               const uint32_t *f, int32_t fn, uint64_t sp) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  memset(FAR_USED, 0, sizeof FAR_USED);
  for (uint32_t a = 0; a < CODE; ++a) { MEMORY[a] = (uint8_t)(a * 37u + 11u); }
  for (int32_t i = 0; i < n; ++i) { for (uint32_t b = 0; b < 4; ++b) { MEMORY[CODE + 4u * (uint32_t)i + b] = (uint8_t)(w[i] >> (8 * b)); } }
  for (int32_t i = 0; i < fn; ++i) { for (uint32_t b = 0; b < 4; ++b) { MEMORY[%(func)du + 4u * (uint32_t)i + b] = (uint8_t)(f[i] >> (8 * b)); } }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (core[0] && !S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  axis_pack_state_entry state[sizeof STATE / sizeof STATE[0]];
  memcpy(state, STATE, sizeof state);
  for (size_t i = 0; i < sizeof state / sizeof state[0]; ++i) {
    if (!strcmp(state[i].name, "sp")) { state[i].value = sp; }
  }
  S->reset(m, CODE, "%(isa)s", state, (int32_t)(sizeof state / sizeof state[0]));
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, (0x1111u * (uint64_t)(i + 1)) %% 0xB000u); }
  S->count_cycles(m, core[0] != 0);
  S->run(m, 20000u);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = 0; a < CODE; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  for (uint32_t h = 0; h < FAR; ++h) { if (FAR_USED[h]) { mark ^= FAR_AT[h] * 31u + FAR_V[h]; mark *= 1099511628211ull; } }
  printf("%%s steps %%llu cycles %%llu replays %%llu targets %%llu mispredicts %%llu status %%d mark %%llu\n", tag,
         (unsigned long long)S->steps(m), (unsigned long long)S->cycles(m),
         (unsigned long long)S->replays(m), (unsigned long long)S->target_mispredicts(m),
         (unsigned long long)S->mispredicts(m), (int)S->status(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->run_cores) { printf("NOENGINE\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


class A64:
    """Words from the corpus's own test encodings, with operands placed."""

    def __init__(self, lift, tests):
        self.lift = lift
        self.by = {e["mnemonic"]: e for e in lift.AXIS_LIFT_TABLE if e.get("isa") == ISA}
        self.word = {t["mnemonic"]: int(t["encoded"], 16) for t in tests
                     if (t.get("isa") or ISA) == ISA}

    def missing(self, needed):
        return [m for m in needed if m not in self.by or m not in self.word]

    def __call__(self, mnemonic, **operands):
        word = self.word[mnemonic]
        # place_operand masks each field, so a negative branch offset lands as
        # its two's complement.
        for name, value in operands.items():
            word = self.lift.place_operand(word, self.by[mnemonic], name, value)
        return word


NEEDED = ["B", "BL", "RET", "B_COND", "SUBS_X_IMM", "MOVZ_X", "ADD_X_IMM_SP", "CSEL_X",
          "MADD_X", "LDR_X_UNSIGNED", "STR_X_UNSIGNED", "SUB_X_IMM_SP", "LDR_Q_UNSIGNED",
          "ADD_V_Q0"]
NE, GT = 1, 12
TWINNED = ("FLAGS", "SPLOAD", "XLOAD", "WIDE")


def kinds(entry):
    return {x.get("kind") for x in (entry.get("effects") or [])}


def check(work: Path, seeds: int) -> tuple[int, int]:
    source = CORPUS.read_text()
    end = source.rstrip().rfind(")")
    corpus = work / "a64x.axisl"
    corpus.write_text(source[:end] + ADDITIONS + ")\n")

    def run_cmd(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=True)

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "a64x_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("a64x_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    asm = A64(lift, tests)
    gone = asm.missing(NEEDED)
    if gone:
        print(f"  a64x: DECLINED no {', '.join(gone)}")
        return 0, 0
    state = ",".join('{"%s", 0, %du}' % (n, w) for n, w in lift.STATE_SLOTS)
    root = work / "packs" / manifest["name"]

    def harness(runs, programs):
        body = HARNESS % {
            "sim": manifest["libraries"]["sim"]["entry"], "code": CODE, "func": FUNC, "isa": ISA,
            "state": state,
            "programs": "\n".join("  static const uint32_t %s[] = { %s, 0u };"
                                  % (label, ", ".join("%du" % w for w in words))
                                  for label, words in programs.items()),
            "runs": "\n".join(runs)}
        (work / "h.c").write_text(body)
        run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "h"),
                 str(work / "h.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
                 str(root / "lib" / manifest["libraries"]["exec"]["static"])])
        out = subprocess.run([str(work / "h")], capture_output=True, text=True, timeout=1800).stdout
        said = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 15 and parts[1] == "steps":
                said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
        return said

    def go(tag, core, label, programs, func="NOFUNC", sp=0x8000):
        flen = len(programs.get(func, [])) + 1
        return (f'  go("{tag}", "{core}", {label}, {len(programs[label]) + 1}, {func}, {flen}, '
                f"{sp}u);")

    # Every straight-line instruction the 64-bit C executor runs: one at a
    # time through the functional simulator, kept if it retires.
    pool = sorted((m, w) for m, w in asm.word.items()
                  if m in asm.by and not kinds(asm.by[m]) & {"setpc", "trap", "send"})
    singles = {f"S{k}": [w] for k, (_, w) in enumerate(pool)}
    said = harness([go(label, "", label, singles) for label in singles], {**singles, "NOFUNC": [0]})
    # Retired, then halted on the word after it (status 2, undecoded) -- not
    # stopped by a trap, which would end every random program it landed in.
    runnable = [pool[k] for k in range(len(pool))
                if said.get(f"S{k}", {}).get("steps") == 1 and said[f"S{k}"]["status"] == 2]
    if len(runnable) < 100:
        print(f"  a64x: FAIL only {len(runnable)} of {len(pool)} straight-line instructions run")
        return 1, 1

    rng = random.Random(1357)
    programs = {f"R{k}": [w for _, w in (rng.choice(runnable) for _ in range(rng.randrange(20, 60)))]
                for k in range(seeds)}
    # Flags: a countdown whose branch reads the compare's NZCV, around work.
    body = [asm("SUBS_X_IMM", rd=1, rn=1, imm=1, sh=0), asm("MADD_X", rd=2, rn=2, rm=3, ra=4),
            asm("MADD_X", rd=3, rn=3, rm=2, ra=5)]
    body.append(asm("B_COND", imm=-len(body), cond=NE))
    programs["COUNT"] = [asm("MOVZ_X", rd=1, imm=12, hw=0)] + body
    # Compares feeding selects, each select's sources the last one's result.
    chain = []
    for k in range(12):
        chain += [asm("SUBS_X_IMM", rd=6, rn=7 + k % 3, imm=0x111 * (k + 1), sh=0),
                  asm("CSEL_X", rd=7 + (k + 1) % 3, rn=7 + k % 3, rm=10, cond=GT if k % 2 else NE)]
    programs["FLAGS"] = chain
    # Calls: two sites, alternating, into one function.
    rel = lambda at, to: (to - at) // 4  # noqa: E731
    main = [asm("MOVZ_X", rd=1, imm=8, hw=0)]
    loop = len(main)
    for site in range(2):
        at = CODE + 4 * len(main)
        main.append(asm("BL", imm=rel(at, FUNC)))
        main.append(asm("ADD_X_IMM_SP", rd=11 + site, rn=11 + site, imm=1, sh=0))
    main.append(asm("SUBS_X_IMM", rd=1, rn=1, imm=1, sh=0))
    main.append(asm("B_COND", imm=loop - len(main), cond=NE))
    programs["CALLS"] = main
    programs["FUNC"] = [asm("MADD_X", rd=13, rn=13, rm=3, ra=4),
                        asm("ADD_X_IMM_SP", rd=14, rn=14, imm=3, sh=0), asm("RET", rn=30)]
    # The stack: push, store, load, pop -- SP is register 31's alias.
    stack = [asm("SUB_X_IMM_SP", rd=31, rn=31, imm=16, sh=0),
             asm("STR_X_UNSIGNED", rt=2, rn=31, imm=0),
             asm("LDR_X_UNSIGNED", rt=15, rn=31, imm=0),
             asm("ADD_X_IMM_SP", rd=31, rn=31, imm=16, sh=0),
             asm("ADD_X_IMM_SP", rd=2, rn=15, imm=5, sh=0),
             asm("SUBS_X_IMM", rd=1, rn=1, imm=1, sh=0)]
    stack.append(asm("B_COND", imm=-len(stack), cond=NE))
    programs["STACK"] = [asm("MOVZ_X", rd=1, imm=10, hw=0)] + stack
    # Wide: a Q load into v2, then a 128-bit add into v2 that reads neither of
    # its sources from it -- the add may execute first.
    programs["WIDE"] = [asm("MADD_X", rd=16, rn=3, rm=3, ra=4), asm("MADD_X", rd=16, rn=16, rm=16, ra=4),
                        asm("LDR_Q_UNSIGNED", rt=2, rn=31, imm=1),
                        asm("ADD_V_Q0", rd=2, rn=3, rm=4)] * 3
    # SP is not XZR: a compare (SUBS into register 31 of the plain class)
    # behind a slow chain, then a load through SP (register 31 of the SP
    # class). The two share a slot number and nothing else, so the load must
    # take exactly as long as one through X19.
    slow = [asm("MADD_X", rd=16, rn=3, rm=3, ra=4)] + [asm("MADD_X", rd=16, rn=16, rm=16, ra=4)] * 7
    for label, base in (("SPLOAD", 31), ("XLOAD", 19)):
        programs[label] = slow + [asm("SUBS_X_IMM", rd=31, rn=16, imm=1, sh=0),
                                  asm("LDR_X_UNSIGNED", rt=17, rn=base, imm=0),
                                  asm("ADD_X_IMM_SP", rd=18, rn=17, imm=1, sh=0)]
    programs["NOFUNC"] = [0]

    runs = []
    for label in programs:
        if label in ("FUNC", "NOFUNC"):
            continue
        func = "FUNC" if label == "CALLS" else "NOFUNC"
        runs.append(go(f"{label}_F", "", label, programs, func))
        runs.append(go(f"{label}_X", "a64x_ras", label, programs, func))
    runs.append(go("CALLS_N", "a64x_noras", "CALLS", programs, "FUNC"))
    # The trace-driven twin, on the programs with no branch to guess and no
    # store to order: the two engines' arithmetic is the same arithmetic.
    for label in TWINNED:
        runs.append(go(f"{label}_T", "a64x_trace", label, programs))
    said = harness(runs, programs)
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL a64x: {message}")
        failures += 1

    labels = [label for label in programs if label not in ("FUNC", "NOFUNC")]
    for label in labels:
        checks += 1
        f, x = said.get(f"{label}_F"), said.get(f"{label}_X")
        if not f or not x:
            fail(f"{label}: no report")
            continue
        for field in ("steps", "mark", "status"):
            if f[field] != x[field]:
                fail(f"{label}: {field} {x[field]} execution-driven, {f[field]} functional")
        if x["replays"]:
            fail(f"{label}: {x['replays']} replay(s)")
    for label, least in (("COUNT", 12 * 4), ("FLAGS", 24), ("CALLS", 8 * 2 * 5), ("STACK", 10 * 7),
                         ("WIDE", 12)):
        checks += 1
        if said.get(f"{label}_F", {}).get("steps", 0) < least:
            fail(f"{label}: {said.get(f'{label}_F', {}).get('steps')} steps -- the program did not run "
                 f"as written")
    checks += 1
    sp_cycles, x_cycles = said.get("SPLOAD_X", {}).get("cycles"), said.get("XLOAD_X", {}).get("cycles")
    if sp_cycles is None or sp_cycles != x_cycles:
        fail(f"a load through SP takes {sp_cycles} cycles behind a compare into XZR, one through "
             f"X19 {x_cycles} -- SP waited for XZR's writer")
    for label in TWINNED:
        checks += 1
        x, t = said.get(f"{label}_X", {}).get("cycles"), said.get(f"{label}_T", {}).get("cycles")
        if x is None or x != t:
            fail(f"{label}: {x} cycles execution-driven, {t} trace-driven -- one engine's dependences "
                 f"are not the other's")
    ras, noras = said.get("CALLS_X", {}), said.get("CALLS_N", {})
    checks += 2
    if ras.get("targets", 1):
        fail(f"CALLS: {ras.get('targets')} wrong return target(s) with a return stack")
    if not noras.get("targets"):
        fail("CALLS: no wrong return targets without a return stack -- the returns were never predicted")
    if noras.get("replays"):
        fail(f"CALLS without a return stack: {noras['replays']} replay(s)")
    steps = sum(said[f"R{k}_F"]["steps"] for k in range(seeds) if f"R{k}_F" in said)
    print(f"  a64x: {len(runnable)} straight-line instructions; {seeds} random programs "
          f"({steps} instructions), flags, calls, stack and wide registers -- the golden model's, "
          f"0 replays; return targets {ras.get('targets')} with a return stack, "
          f"{noras.get('targets')} without")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=48)
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            checks, failures = check(Path(tmp), args.seeds)
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL a64x: {said[:400]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("AArch64 runs execution-driven: SKIP")
        return DECLINED
    print(f"AArch64 runs execution-driven: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
