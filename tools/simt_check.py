#!/usr/bin/env python3
"""The SIMT engine executes a warp the way its threads, run alone, would. Gate.

`emit-pack-simt-c` (docs/simt_design.md) generates a machine that runs warps
of lanes in lockstep under a mask, splitting and rejoining around divergent
branches. Two things can be wrong with such a machine, and each needs its own
witness:

* **What it computes.** THE JUDGE: a race-free program -- every thread writes
  only its own memory -- must leave each thread's registers and memory exactly
  as running that thread ALONE leaves them. The lone run is not a SIMT machine
  at all: the generated executor steps one thread, the warp operations doing
  only their per-lane halves. So a reconvergence stack that runs a group
  twice, never, or with the wrong mask, a predicate that keeps the wrong
  lanes, a join that pops early -- each changes some thread's result, and the
  judge needs no model of the warp to see it. Excluded from the comparison,
  and only these: the token registers (a SPLIT hands its lanes the stack
  depth, which a lone thread has no stack to give) and the saved-mask
  register (a warp's mask is not a lone thread's).

* **What it costs.** Four invariants with exact expected values, each the
  arithmetic of one mechanism:
    UNIFORM   straight-line code costs the same on 1 lane and on 8;
    NARROW    an ALU of 2 lanes under an 8-lane warp takes 4 cycles an op;
    DIVERGE   both sides of a divergent branch are paid: B + 3 more warp
              instructions than when every lane takes one side;
    COALESCE  8 lanes reading consecutive words are 1 line, 8 lanes 64 bytes
              apart are 8.

Programs are random and STRUCTURED, the shape a divergence pass emits:
if/else regions bracketed by SPLIT/JOIN (nested), and loops whose trip count
differs per thread, narrowed by PRED at the latch.

Usage: tools/simt_check.py [examples/simt_core.axisl] [--seeds N]
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

AXIS_ROOT = Path(__file__).resolve().parent.parent
DATA = 0x4000          # thread t's 256-byte region is DATA + 256*t
TABLE = 0x2000         # read-only: thread t's loop trip count at TABLE + 4*t
TOKENS = range(20, 28) # one token register per nesting depth
SAVED = 28             # the saved mask
ONE = 30               # the constant 1
COMPARED = list(range(1, 20)) + [29, 31]  # all but tokens, the saved mask, ONE
REFUSES = {"sm_w1l8u"}     # a core whose memory system maps none of the data

HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axis_pack.h"
#include "axis_simt.h"
const axis_lift_pack *axis_lift_pack_@IDENT@(void);
const axis_exec_pack *axis_exec_pack_@IDENT@(void);
#define MEM (1u << 20)
static uint8_t mem[MEM];
static uint32_t lanes_g;
static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; uint64_t v = 0; if (a + w / 8 <= MEM) memcpy(&v, mem + a, w / 8); return v; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; if (a + w / 8 <= MEM) memcpy(mem + a, &v, w / 8); }
static uint32_t fe(void *c, uint64_t pc, int *ok) { (void)c; uint32_t w = 0; *ok = pc + 4 <= MEM; if (*ok) memcpy(&w, mem + pc, 4); return w; }
static axis_simt_machine *M;
static uint64_t sys_simt(void *c, uint32_t w, uint32_t l, uint32_t i) {
  (void)c;
  if (i == 0) return (uint64_t)w * lanes_g + l;
  if (i == 1) return axis_simt_warp_mask(M, w);
  if (i == 2) return lanes_g;
  return 0;
}
/* SIMT_FAULT=1: a lane's first access to each 64 bytes of the data faults
   once. The lane stays at the instruction, as it was, and runs it again when
   its path next runs -- the access then succeeds. */
static uint8_t touched[64][64][(1u << 20) / 64 / 8];
static int faulting(void *c, uint32_t w, uint32_t l, uint64_t a, int write) {
  (void)c; (void)write;
  if (a < @DATA@ || a >= MEM || w >= 64 || l >= 64) return 0;
  uint64_t k = a / 64;
  if (touched[w][l][k / 8] >> (k % 8) & 1) return 0;
  touched[w][l][k / 8] |= (uint8_t)(1u << (k % 8));
  return 1;
}
static void load(const char *path) {
  FILE *f = fopen(path, "rb"); if (!f) { perror(path); exit(2); }
  size_t n = fread(mem, 1, MEM, f); (void)n; fclose(f);
}
static void dump(uint32_t t, const uint64_t *regs) {
  printf("T %u", t);
  for (int r = 0; r < 32; ++r) printf(" %llx", (unsigned long long)(regs[r] & 0xffffffffu));
  for (int k = 0; k < 64; ++k) { uint32_t v; memcpy(&v, mem + @DATA@ + 256u * t + 4u * k, 4); printf(" %x", v); }
  printf("\n");
}
int main(int argc, char **argv) {
  load(argv[2]);
  if (!strcmp(argv[1], "simt")) {
    axis_simt_hooks h = { rd, wr, fe, sys_simt, NULL, NULL, getenv("SIMT_FAULT") ? faulting : NULL };
    char err[256];
    M = axis_simt_create(argv[3], &h, err, sizeof err);
    if (!M) { printf("ERROR %s\n", err); return 1; }
    lanes_g = axis_simt_lanes(M);
    uint32_t warps = axis_simt_warps(M);
    uint64_t all = lanes_g >= 64 ? ~0ull : ((1ull << lanes_g) - 1);
    for (uint32_t w = 0; w < warps; ++w) axis_simt_start_warp(M, w, 0, all);
    int r = axis_simt_run(M, 2000000);
    if (r != 0) { printf("ERROR %s\n", r < 0 ? axis_simt_error(M) : "cycle limit"); return 1; }
    const axis_simt_counters *c = axis_simt_stats(M);
    printf("STATS sleeps=%llu dormant=%llu faults=%llu cycles=%llu warp_instrs=%llu lane_instrs=%llu mem_lines=%llu divergent=%llu implicit_splits=%llu mispredicts=%llu store_waits=%llu misses=%llu prefetches=%llu prefetch_useful=%llu l2_hits=%llu l2_misses=%llu bop_offset=%llu bop_rounds=%llu\n",
           (unsigned long long)c->sleeps, (unsigned long long)c->dormant_cycles,
           (unsigned long long)c->faults, (unsigned long long)c->cycles, (unsigned long long)c->warp_instrs, (unsigned long long)c->lane_instrs,
           (unsigned long long)c->mem_lines, (unsigned long long)c->divergent_splits,
           (unsigned long long)c->implicit_splits, (unsigned long long)c->mispredicts,
           (unsigned long long)c->store_waits, (unsigned long long)c->cache_misses, (unsigned long long)c->prefetches,
           (unsigned long long)c->prefetch_useful, (unsigned long long)c->l2_hits, (unsigned long long)c->l2_misses,
           (unsigned long long)c->bop_offset, (unsigned long long)c->bop_rounds);
    for (uint32_t w = 0; w < warps; ++w)
      for (uint32_t l = 0; l < lanes_g; ++l) {
        uint64_t regs[32];
        for (int s = 0; s < 32; ++s) regs[s] = axis_simt_reg(M, w, l, s);
        dump(w * lanes_g + l, regs);
      }
    return 0;
  }
  /* lone <threads> <lanes>: each thread by itself, through the executor. */
  const axis_lift_pack *L = axis_lift_pack_@IDENT@();
  const axis_exec_pack *E = axis_exec_pack_@IDENT@();
  uint32_t threads = (uint32_t)atoi(argv[3]);
  lanes_g = (uint32_t)atoi(argv[4]);
  int32_t ns = E->state_slots(), slots = E->register_slots();
  static uint8_t image[MEM];
  memcpy(image, mem, MEM);
  for (uint32_t t = 0; t < threads; ++t) {
    /* the program and tables as they were: each thread starts from them */
    uint64_t *regs = calloc((size_t)slots, sizeof *regs);
    axis_pack_state_entry *st = calloc((size_t)ns, sizeof *st);
    for (int32_t s = 0; s < ns; ++s) { st[s].name = E->state_name(s); st[s].width = E->state_width(s); }
    axis_pack_mem pm = { rd, wr, NULL };
    uint64_t pc = 0;
    for (long step = 0;; ++step) {
      if (step > 1000000) { printf("ERROR thread %u does not end\n", t); return 1; }
      int ok = 1; uint32_t word = fe(NULL, pc, &ok);
      axis_pack_lifted lf;
      if (!L->lift(word, "st32", &lf) || lf.index < 0) { printf("ERROR undecodable at %llx\n", (unsigned long long)pc); return 1; }
      const char *mn = L->mnemonic(lf.index);
      if (!strcmp(mn, "STCSRR")) {
        uint32_t rdi = 0, imm = 0;
        for (int32_t o = 0; o < lf.operand_count; ++o) {
          if (!strcmp(L->operand_name(lf.index, o), "rd")) rdi = lf.operands[o];
          if (!strcmp(L->operand_name(lf.index, o), "imm")) imm = lf.operands[o];
        }
        uint64_t v = imm == 0 ? t : imm == 1 ? 1 : imm == 2 ? lanes_g : 0;
        if (rdi) regs[rdi] = v;
        pc += 4;
        continue;
      }
      if (!strcmp(mn, "STWSYNC")) { pc += 4; continue; }
      axis_pack_exec_result r;
      E->step(word, "st32", regs, slots, &pm, pc, st, ns, &r);
      if (!r.ok || r.trapped) { printf("ERROR %s at %llx\n", r.trap_cause ? r.trap_cause : "not ok", (unsigned long long)pc); return 1; }
      if (!strcmp(mn, "STTMC")) {
        uint64_t arg = 0;
        for (int32_t s = 0; s < ns; ++s) if (!strcmp(st[s].name, "simt_arg")) arg = st[s].value;
        if (!(arg & 1)) break;  /* the thread's own lane leaves the mask */
      }
      pc = r.next_pc;
    }
    dump(t, regs);
    free(regs); free(st);
  }
  return 0;
}
"""


class Assembler:
    """Words from the corpus's own instructions, with operands placed."""

    def __init__(self, lift, tests):
        self.lift = lift
        self.by = {e["mnemonic"]: e for e in lift.AXIS_LIFT_TABLE}
        self.base = {t["mnemonic"]: int(t["encoded"], 16) for t in tests}

    def w(self, mnemonic, **operands):
        word = self.base[mnemonic]
        for name, value in operands.items():
            word = self.lift.place_operand(word, self.by[mnemonic], name, value)
        return word


def generate(asm: Assembler, rng: random.Random, threads: int, implicit: bool = False):
    """A structured random program, and the trip-count table it reads.

    `implicit`: the same program with no SPLIT, JOIN or PRED -- plain
    branches, for a core that finds divergence itself."""
    code = []
    W = asm.w
    # x5..x16 are the body's; x17 and x18 belong to loops (scratch and
    # counter) and x19 to predicates, so no body can clobber a trip count.
    work = list(range(5, 17))
    emit = code.append
    emit(W("STCSRR", rd=1, imm=0))                      # x1 = thread id
    emit(W("STADDI", rd=ONE, rs1=0, imm=1))
    emit(W("STADDI", rd=3, rs1=0, imm=256))
    emit(W("STMUL", rd=2, rs1=1, rs2=3))
    emit(W("STADDI", rd=3, rs1=0, imm=1024))
    emit(W("STADDI", rd=4, rs1=0, imm=16))
    emit(W("STMUL", rd=3, rs1=3, rs2=4))                # x3 = 0x4000
    emit(W("STADD", rd=2, rs1=2, rs2=3))                # x2 = this thread's region
    for r in work:                                       # thread-dependent values
        emit(W("STADDI", rd=r, rs1=1, imm=rng.randrange(-8, 9)))

    def straight(n):
        for _ in range(n):
            k = rng.choice(["add", "mul", "addi", "ld", "st"])
            a, b, d = rng.choice(work), rng.choice(work + [1]), rng.choice(work)
            if k == "add":
                emit(W("STADD", rd=d, rs1=a, rs2=b))
            elif k == "mul":
                emit(W("STMUL", rd=d, rs1=a, rs2=b))
            elif k == "addi":
                emit(W("STADDI", rd=d, rs1=a, imm=rng.randrange(-64, 64)))
            elif k == "ld":
                emit(W("STLW", rd=d, rs1=2, imm=4 * rng.randrange(64)))
            else:
                emit(W("STSW", rs1=2, rs2=a, imm=4 * rng.randrange(64)))

    def region(depth):
        straight(rng.randrange(1, 4))
        roll = rng.random()
        if depth < len(TOKENS) - 1 and roll < 0.45:
            # if/else on a thread-dependent predicate: x1 - k is zero for one
            # thread, a work register for a data-dependent split
            p = 19
            if rng.random() < 0.5:
                emit(W("STADDI", rd=p, rs1=1, imm=-rng.randrange(threads)))
            else:
                emit(W("STMUL", rd=p, rs1=rng.choice(work[:-1]), rs2=rng.choice(work[:-1])))
            tok = TOKENS[depth]
            if not implicit:
                emit(W("STSPLIT", rd=tok, rs1=p))
            branch_at = len(code)
            emit(0)                                      # stbne p, x0, THEN
            region(depth + 1)                            # else
            jump_at = len(code)
            emit(0)                                      # stbne ONE, x0, JOIN
            then_at = len(code)
            region(depth + 1)                            # then
            join_at = len(code)
            if not implicit:
                emit(W("STJOIN", rs1=tok))
            else:
                emit(W("STADDI", rd=tok, rs1=0, imm=0))  # the join point is still an instruction
            code[branch_at] = W("STBNE", rs1=p, rs2=0, imm=(4 * (then_at - branch_at)) & 0x1fff)
            code[jump_at] = W("STBNE", rs1=ONE, rs2=0, imm=(4 * (join_at - jump_at)) & 0x1fff)
            straight(rng.randrange(0, 3))
        elif depth < 3 and roll < 0.7:
            # a loop whose trip count is the thread's own (1..4)
            c = 18
            # TABLE >> 4, times 16: a 12-bit immediate is signed, and TABLE / 4
            # (2048) wrapped to -2048 -- every trip count read 0, and a loop
            # that decrements past 0 runs 2^32 times.
            emit(W("STADDI", rd=c, rs1=0, imm=TABLE >> 4))
            emit(W("STADDI", rd=4, rs1=0, imm=16))
            emit(W("STMUL", rd=c, rs1=c, rs2=4))
            emit(W("STADD", rd=17, rs1=1, rs2=1))
            emit(W("STADD", rd=17, rs1=17, rs2=17))
            emit(W("STADD", rd=c, rs1=c, rs2=17))
            emit(W("STLW", rd=c, rs1=c, imm=0))
            emit(W("STCSRR", rd=SAVED, imm=1))
            top = len(code)
            straight(rng.randrange(1, 5))
            emit(W("STADDI", rd=c, rs1=c, imm=-1))
            if not implicit:
                emit(W("STPRED", rs1=c, rs2=SAVED))
            emit(W("STBNE", rs1=c, rs2=0, imm=(4 * (top - len(code))) & 0x1fff))
        else:
            straight(rng.randrange(1, 4))

    for _ in range(rng.randrange(2, 5)):
        region(0)
    emit(W("STTMC", rs1=0))
    assert 4 * len(code) <= TABLE, f"program of {len(code)} words runs into the table"
    table = [rng.randrange(1, 5) for _ in range(threads)]
    return code, table


def image(code, table):
    blob = bytearray(DATA + 256 * 64)
    for k, word in enumerate(code):
        blob[4 * k:4 * k + 4] = word.to_bytes(4, "little")
    for t, n in enumerate(table):
        blob[TABLE + 4 * t:TABLE + 4 * t + 4] = n.to_bytes(4, "little")
    return bytes(blob)


def run(binary, *args, env=None):
    import os
    out = subprocess.run([str(binary), *map(str, args)], capture_output=True, text=True, timeout=120,
                         env={**os.environ, **(env or {})})
    return out.stdout


def threads_of(text):
    rows, stats = {}, {}
    for line in text.splitlines():
        if line.startswith("ERROR"):
            raise RuntimeError(line)
        if line.startswith("STATS"):
            stats = dict(kv.split("=") for kv in line.split()[1:])
            stats = {k: int(v) for k, v in stats.items()}
        elif line.startswith("T "):
            p = line.split()
            rows[int(p[1])] = ([p[2 + r] for r in range(32)], p[34:])
    return rows, stats


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus", nargs="?", default=str(AXIS_ROOT / "examples/simt_core.axisl"))
    ap.add_argument("--seeds", type=int, default=40)
    ap.add_argument("--keep", help="build in this directory and leave it, to debug a failure")
    a = ap.parse_args()
    corpus = Path(a.corpus)
    with tempfile.TemporaryDirectory(prefix="simt_check_") as tmp:
        work = Path(a.keep) if a.keep else Path(tmp)
        work.mkdir(parents=True, exist_ok=True)
        manifest = build_pack.build(corpus, work / "packs", only={"lift", "exec", "simt"})
        if "simt" not in manifest["libraries"]:
            print(f"{DECLINED}: no SIMT core in {corpus}")
            return 0
        name = manifest["name"]
        root = work / "packs" / name
        ident = build_pack.pack_ident(name)
        src = work / "harness.c"
        src.write_text(HARNESS.replace("@IDENT@", ident).replace("@DATA@", str(DATA)))
        binary = work / "harness"
        libs = [root / "lib" / f"libaxis_{f}_{ident}.a" for f in ("simt", "exec", "lift")]
        subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), str(src), *map(str, libs),
                        "-o", str(binary)], check=True)
        facts = json.loads(subprocess.run([*axis_prefix(), "emit-json", str(corpus)], capture_output=True,
                                          text=True, check=True, cwd=AXIS_ROOT).stdout)
        cores = {c["name"]: c["simt"] for c in facts["cores"] if c.get("simt")}
        module = f"sc_{ident}"
        subprocess.run([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / f"{module}.py")],
                       check=True, cwd=AXIS_ROOT, capture_output=True)
        sys.path.insert(0, str(work))
        lift = importlib.import_module(module)
        tests = json.loads(subprocess.run([*axis_prefix(), "emit-roundtrip-json", str(corpus)], capture_output=True,
                                          text=True, check=True, cwd=AXIS_ROOT).stdout)["tests"]
        asm = Assembler(lift, tests)
        failures = []

        # ---- the judge ----
        rng = random.Random(2026)
        judged = diverged = implicit_splits = 0
        for seed in range(a.seeds):
            for core, shape in cores.items():
                if core in REFUSES:
                    continue  # built to refuse what the judge's programs do (MEMSYS)
                threads = shape["warps"] * shape["lanes"]
                implicit = bool(shape.get("implicit")) or core.startswith(("si_", "so_i_"))
                code, table = generate(asm, rng, threads, implicit)
                prog = work / f"p{seed}_{core}.bin"
                prog.write_bytes(image(code, table))
                try:
                    simt, stats = threads_of(run(binary, "simt", prog, core))
                    lone, _ = threads_of(run(binary, "lone", prog, threads, shape["lanes"]))
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    failures.append(f"seed {seed} {core}: {error}")
                    continue
                diverged += stats.get("divergent", 0)
                implicit_splits += stats.get("implicit_splits", 0)
                for t in range(threads):
                    a_regs, a_mem = simt[t]
                    b_regs, b_mem = lone[t]
                    bad = [r for r in COMPARED if a_regs[r] != b_regs[r]]
                    if bad or a_mem != b_mem:
                        failures.append(f"seed {seed} {core} thread {t}: "
                                        + (f"x{bad[0]} simt={a_regs[bad[0]]} alone={b_regs[bad[0]]}" if bad else "memory differs"))
                        break
                judged += threads
        print(f"  judge: {a.seeds} programs x {len(cores) - len(REFUSES)} cores, {judged} threads, "
              f"{diverged} divergent splits, {implicit_splits} implicit -- {'agree' if not failures else 'DISAGREE'}")

        # ---- the judge again, with faults ----
        # Every lane's first access to each 64 bytes of its data faults once
        # (SIMT_FAULT): the lane must leave the instruction as it found it,
        # stay behind while the rest of its warp goes on, and finish exactly
        # as it would alone. Implicit cores only: a fault is a divergence.
        fault_cores = [c for c, s in cores.items() if s.get("implicit") or c.startswith(("si_", "so_i_"))]
        before, faults, fjudged = len(failures), 0, 0
        for seed in range(min(a.seeds, 10)):
            for core in fault_cores:
                shape = cores[core]
                threads = shape["warps"] * shape["lanes"]
                code, table = generate(asm, rng, threads, True)
                prog = work / f"f{seed}_{core}.bin"
                prog.write_bytes(image(code, table))
                try:
                    simt, stats = threads_of(run(binary, "simt", prog, core, env={"SIMT_FAULT": "1"}))
                    lone, _ = threads_of(run(binary, "lone", prog, threads, shape["lanes"]))
                except (RuntimeError, subprocess.TimeoutExpired) as error:
                    failures.append(f"fault seed {seed} {core}: {error}")
                    continue
                faults += stats.get("faults", 0)
                for t in range(threads):
                    (a_regs, a_mem), (b_regs, b_mem) = simt[t], lone[t]
                    bad = [r for r in COMPARED if a_regs[r] != b_regs[r]]
                    if bad or a_mem != b_mem:
                        failures.append(f"fault seed {seed} {core} thread {t}: "
                                        + (f"x{bad[0]} simt={a_regs[bad[0]]} alone={b_regs[bad[0]]}" if bad else "memory differs"))
                        break
                fjudged += threads
        # Directed: a load whose destination is its own base register. If a
        # faulting lane's registers were not put back, its retry would load
        # from wherever the faulted attempt left the base (random programs
        # never do this, so they cannot see it).
        W = asm.w
        own = [W("STCSRR", rd=1, imm=0), W("STADDI", rd=3, rs1=0, imm=256), W("STMUL", rd=5, rs1=1, rs2=3),
               W("STADDI", rd=3, rs1=0, imm=DATA // 16), W("STADDI", rd=4, rs1=0, imm=16),
               W("STMUL", rd=3, rs1=3, rs2=4), W("STADD", rd=5, rs1=5, rs2=3),
               W("STADD", rd=6, rs1=5, rs2=0),
               # faults (the region's first access); a retry from a base left
               # at 0 would read the program's second word, which is not 0
               W("STLW", rd=5, rs1=5, imm=4), W("STSW", rs1=6, rs2=5, imm=8), W("STTMC", rs1=0)]
        for core in ("si_w1l8", "so_i_w4l8"):
            shape = cores[core]
            threads = shape["warps"] * shape["lanes"]
            prog = work / f"own_{core}.bin"
            prog.write_bytes(image(own, [1] * 64))
            simt, stats = threads_of(run(binary, "simt", prog, core, env={"SIMT_FAULT": "1"}))
            lone, _ = threads_of(run(binary, "lone", prog, threads, shape["lanes"]))
            faults += stats.get("faults", 0)
            for t in range(threads):
                if simt[t][1] != lone[t][1] or any(simt[t][0][r] != lone[t][0][r] for r in COMPARED):
                    failures.append(f"fault: a load into its own base register, {core} thread {t}: differs from alone")
                    break
        ok = len(failures) == before and faults > 0
        print(f"  FAULT     {fjudged} threads on {len(fault_cores)} implicit cores, {faults} faulting accesses "
              f"retried, and a load into its own base register -- {'agree' if ok else 'DISAGREE'}")
        if faults == 0:
            failures.append("FAULT: nothing faulted")

        # ---- the invariants ----
        W = asm.w
        def stats_of(code, core):
            prog = work / f"inv_{core}.bin"
            prog.write_bytes(image(code + [W("STTMC", rs1=0)], [1] * 64))
            return threads_of(run(binary, "simt", prog, core))[1]

        # WINDOW: a load that misses (20 cycles), an add that needs it, then
        # 20 adds that need nothing. In order, the dependent add holds the
        # warp for the miss. A 32-entry window runs the 20 under it; a
        # 4-entry one fills behind the load and is in order again.
        slow = [W("STLW", rd=5, rs1=0, imm=2040), W("STADD", rd=6, rs1=5, rs2=5)]
        slow += [W("STADDI", rd=7 + k % 8, rs1=0, imm=k) for k in range(20)]
        w_in, w_4, w_32 = (stats_of(slow, core)["cycles"] for core in ("sc_w1l1", "so_r4", "so_r32"))
        ok = w_32 + 15 <= w_in and abs(w_4 - w_in) <= 4
        print(f"  WINDOW    a miss, its dependent, 20 independent adds: in order {w_in} cycles, "
              f"a 32-entry window {w_32}, a 4-entry one {w_4} -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("WINDOW")
        # CHAIN: 16 multiplies, each needing the last. No window makes a chain faster.
        chain = [W("STADDI", rd=5, rs1=0, imm=3)] + [W("STMUL", rd=5, rs1=5, rs2=5) for _ in range(16)]
        c_in, c_32 = stats_of(chain, "sc_w1l1")["cycles"], stats_of(chain, "so_r32")["cycles"]
        ok = abs(c_in - c_32) <= 2
        print(f"  CHAIN     16 dependent multiplies: in order {c_in} cycles, a 32-entry window {c_32} -- "
              f"{'equal' if ok else 'DIFFER'}")
        if not ok:
            failures.append("CHAIN")

        # MEMORY: a value carried through memory -- store it, load it back,
        # add to it, eight times. The load needs no register the store
        # writes, so a window with no memory order starts every load at once.
        carried = []
        for _ in range(8):
            carried += [W("STSW", rs1=0, rs2=5, imm=2040), W("STLW", rd=5, rs1=0, imm=2040),
                        W("STADDI", rd=5, rs1=5, imm=1)]
        m_free, m_order = stats_of(carried, "so_r32"), stats_of(carried, "so_r32m")
        ok = m_order["store_waits"] == 8 and m_free["store_waits"] == 0 and m_order["cycles"] >= m_free["cycles"] + 8
        print(f"  MEMORY    a value through memory 8 times: {m_free['cycles']} cycles with no memory order, "
              f"{m_order['cycles']} with it ({m_order['store_waits']} loads waited for a store) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("MEMORY")
        # PREDICT: a loop of 32 trips. No predictor waits for all 32 branches;
        # two-bit counters miss a few while they learn and at the exit;
        # a perfect one misses none.
        loop = [W("STADDI", rd=18, rs1=0, imm=32), W("STADDI", rd=5, rs1=5, imm=1), W("STADDI", rd=18, rs1=18, imm=-1),
                W("STBNE", rs1=18, rs2=0, imm=(-8) & 0x1fff)]
        p_none, p_bim, p_perf = (stats_of(loop, core) for core in ("so_r32", "so_r32b", "so_r32p"))
        ok = (p_none["mispredicts"] == 32 and 1 <= p_bim["mispredicts"] <= 4 and p_perf["mispredicts"] == 0
              and p_none["cycles"] > p_bim["cycles"] >= p_perf["cycles"])
        print(f"  PREDICT   a 32-trip loop: no predictor {p_none['cycles']} cycles, two-bit counters "
              f"{p_bim['cycles']} ({p_bim['mispredicts']} misses), perfect {p_perf['cycles']} -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("PREDICT")

        # DIVERGE-PREDICT: a 16-trip loop whose body branches on the thread
        # id -- lane 0 one way, the other lanes the other -- so the warp splits
        # every trip. Without a divergence predictor the front end waits out
        # every split; with one it learns in two trips that this branch splits.
        div = [W("STCSRR", rd=1, imm=0), W("STADDI", rd=18, rs1=0, imm=16)]
        top = len(div)
        branch = len(div)
        div += [0]                                          # stbne x1, x0, JOIN (patched)
        div += [W("STADDI", rd=5, rs1=5, imm=1), W("STADDI", rd=6, rs1=6, imm=1)]
        join = len(div)
        div += [W("STADDI", rd=7, rs1=7, imm=1), W("STADDI", rd=18, rs1=18, imm=-1)]
        div += [W("STBNE", rs1=18, rs2=0, imm=(4 * (top - len(div))) & 0x1fff)]
        div[branch] = W("STBNE", rs1=1, rs2=0, imm=(4 * (join - branch)) & 0x1fff)
        d_off, d_on = stats_of(div, "so_i_l8"), stats_of(div, "so_i_l8d")
        ok = (d_on["implicit_splits"] == d_off["implicit_splits"] > 0 and d_on["cycles"] < d_off["cycles"])
        print(f"  DIVPRED   a loop that splits every trip ({d_off['implicit_splits']} splits): "
              f"{d_off['cycles']} cycles without a divergence predictor, {d_on['cycles']} with one -- "
              f"{'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("DIVPRED")

        # PROGRESS: seven lanes spin on a flag that lane 0 sets, and the spin
        # loop sits at a LOWER pc than lane 0's code. Lowest-pc-first runs the
        # spinners for ever; a machine that sets a path aside after N
        # instructions in a row lets lane 0 store the flag, and the warp ends.
        spin = [W("STADDI", rd=30, rs1=0, imm=1), 0]          # 1: to START (patched)
        top = len(spin)
        spin += [W("STLW", rd=5, rs1=0, imm=2040), 0,         # 3: flag set -> END (patched)
                 W("STBNE", rs1=30, rs2=0, imm=(4 * (top - 4)) & 0x1fff)]
        start = len(spin)
        spin += [W("STCSRR", rd=1, imm=0), W("STBNE", rs1=1, rs2=0, imm=(4 * (top - (start + 1))) & 0x1fff),
                 W("STADDI", rd=6, rs1=0, imm=1), W("STSW", rs1=0, rs2=6, imm=2040)]
        end = len(spin)
        spin[1] = W("STBNE", rs1=30, rs2=0, imm=(4 * (start - 1)) & 0x1fff)
        spin[3] = W("STBNE", rs1=5, rs2=0, imm=(4 * (end - 3)) & 0x1fff)
        def outcome(code, core):
            prog = work / f"prog_{core}.bin"
            prog.write_bytes(image(code + [W("STTMC", rs1=0)], [1] * 64))
            text = run(binary, "simt", prog, core)
            return None if "cycle limit" in text else threads_of(text)[1]
        g_off, g_on, g_rx = outcome(spin, "si_w1l8"), outcome(spin, "si_w1l8p"), outcome(spin, "si_w1l8r")
        ok = g_off is None and g_on is not None and g_rx is not None
        print(f"  PROGRESS  seven lanes spin below the lane that frees them: "
              f"{'never ends' if g_off is None else str(g_off['cycles']) + ' cycles'} by lowest pc alone, "
              f"{'never ends' if g_on is None else str(g_on['cycles']) + ' cycles'} with (progress 16), "
              f"{'never ends' if g_rx is None else str(g_rx['cycles']) + ' cycles'} with the spin's load a (relax ...) hint -- "
              f"{'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("PROGRESS")

        # EVENTS: 15 threads (all of warp 1, and warp 0 but its lane 0) wait for
        # a flag that thread 0 sets after 40 instructions of work, then sends
        # an event. A waiter checks the flag, finds it clear and waits. With
        # events, each waiter sleeps exactly once and warp 1 -- every path
        # asleep -- issues nothing until the send; set aside for progress
        # instead, the waiters keep polling and warp 1 keeps issuing.
        ev = [W("STADDI", rd=30, rs1=0, imm=1), 0]          # 1: to START (patched)
        top = len(ev)
        ev += [W("STLW", rd=5, rs1=0, imm=2040), 0,          # 3: flag set -> END (patched)
               W("STWFE"), W("STBNE", rs1=30, rs2=0, imm=(4 * (top - 5)) & 0x1fff)]
        start = len(ev)
        ev += [W("STCSRR", rd=1, imm=0), W("STBNE", rs1=1, rs2=0, imm=(4 * (top - (start + 1))) & 0x1fff)]
        ev += [W("STADDI", rd=7, rs1=7, imm=1) for _ in range(40)]
        ev += [W("STADDI", rd=6, rs1=0, imm=1), W("STSW", rs1=0, rs2=6, imm=2040), W("STSEV")]
        end = len(ev)
        ev[1] = W("STBNE", rs1=30, rs2=0, imm=(4 * (start - 1)) & 0x1fff)
        ev[3] = W("STBNE", rs1=5, rs2=0, imm=(4 * (end - 3)) & 0x1fff)
        e_on, e_poll = outcome(ev, "si_w2l8e"), outcome(ev, "si_w2l8p")
        # Asleep, a waiter issues nothing: warp 0 is 4 instructions together,
        # 3 to the waiters' sleep, 43 of thread 0's, its TMC, 3 after the wake
        # and theirs (55); warp 1 is 4 + 3 + 3 + 1 (11). 66 at most.
        ok = (e_on is not None and e_poll is not None and e_on["sleeps"] == 15 and e_on["dormant"] > 0
              and e_on["warp_instrs"] <= 66 and e_on["warp_instrs"] < e_poll["warp_instrs"])
        print(f"  EVENTS    15 threads wait on one: "
              + (f"{e_on['sleeps']} sleeps, warp 1 asleep {e_on['dormant']} cycles, {e_on['warp_instrs']} warp "
                 f"instructions; polling, {e_poll['warp_instrs']}" if e_on and e_poll else "did not finish")
              + f" -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("EVENTS")

        # SMTISSUE: lane 0 and lanes 1-7 run two separate 32-trip loops, and
        # there is no branch predictor, so every trip waits out its branch.
        # One path at a time, the warp waits out 64 branches; as SMT threads,
        # one path's wait is the other's turn, and the loops overlap.
        two = [W("STADDI", rd=30, rs1=0, imm=1), W("STCSRR", rd=1, imm=0), 0]   # 2: lanes 1-7 -> A (patched)
        b_top = len(two) + 1
        two += [W("STADDI", rd=18, rs1=0, imm=32), W("STADDI", rd=5, rs1=5, imm=1), W("STADDI", rd=18, rs1=18, imm=-1)]
        two += [W("STBNE", rs1=18, rs2=0, imm=(4 * (b_top - len(two))) & 0x1fff), 0]   # then to END (patched)
        b_out = len(two) - 1
        a_at = len(two)
        two += [W("STADDI", rd=18, rs1=0, imm=32), W("STADDI", rd=6, rs1=6, imm=1), W("STADDI", rd=18, rs1=18, imm=-1)]
        two += [W("STBNE", rs1=18, rs2=0, imm=(4 * (a_at + 1 - len(two))) & 0x1fff)]
        end = len(two)
        two[2] = W("STBNE", rs1=1, rs2=0, imm=(4 * (a_at - 2)) & 0x1fff)
        two[b_out] = W("STBNE", rs1=30, rs2=0, imm=(4 * (end - b_out)) & 0x1fff)
        s_one, s_smt, s_cap = stats_of(two, "so_i_l8n"), stats_of(two, "so_i_l8ns"), stats_of(two, "so_i_l8ns1")
        # One issue a cycle: the instructions themselves take warp_instrs
        # cycles either way. What SMT can remove is the waiting -- at least
        # half of it, with two paths taking turns. With one front end (a path
        # waiting on its branch holds the warp) the waiting is back.
        n_ins = s_one["warp_instrs"]
        w_one, w_smt, w_cap = (x["cycles"] - n_ins for x in (s_one, s_smt, s_cap))
        ok = s_smt["warp_instrs"] == n_ins and w_smt <= 0.5 * w_one and w_cap >= 0.8 * w_one
        print(f"  SMTISSUE  two paths, 32 unpredicted trips each, {n_ins} warp instructions: {s_one['cycles']} cycles "
              f"one path at a time ({w_one} waiting), {s_smt['cycles']} as SMT threads ({w_smt} waiting), "
              f"{s_cap['cycles']} with one front end ({w_cap} waiting) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("SMTISSUE")
        # ... and registers renamed per lane: lane 0 and lanes 1-7 each run a
        # chain of 16 dependent multiplies on the SAME register. Renamed per
        # lane the two chains overlap; renamed per warp register, the second
        # waits for the first (about twice one chain).
        def chain16(rd):
            return [W("STADDI", rd=rd, rs1=0, imm=3)] + [W("STMUL", rd=rd, rs1=rd, rs2=rd) for _ in range(16)]
        one_chain = stats_of(chain16(7), "so_i_l8ns")["cycles"]
        rn = [W("STADDI", rd=30, rs1=0, imm=1), W("STCSRR", rd=1, imm=0), 0]       # 2: lanes 1-7 -> A (patched)
        rn += chain16(7) + [0]                                                    # then to END (patched)
        b_out = len(rn) - 1
        a_at = len(rn)
        rn += chain16(7)
        end = len(rn)
        rn[2] = W("STBNE", rs1=1, rs2=0, imm=(4 * (a_at - 2)) & 0x1fff)
        rn[b_out] = W("STBNE", rs1=30, rs2=0, imm=(4 * (end - b_out)) & 0x1fff)
        two_chains = stats_of(rn, "so_i_l8ns")["cycles"]
        # Overlapped: one chain, plus the other's 17 dispatches (one issue a
        # cycle), plus the divergent branch's wait (no predictor, penalty 6):
        # about one chain + 35. Serialised: about two chains.
        ok = two_chains <= one_chain + 35 < 2 * one_chain
        print(f"  RENAME    two paths, a 16-multiply chain each on one register: one chain {one_chain} cycles, "
              f"both {two_chains} -- {'overlap' if ok else 'SERIALISED'}")
        if not ok:
            failures.append("RENAME")

        # BARRIER: a warp arrives at a barrier when all of it does. In each of
        # two warps, lane 0 goes (lowest pc first) to a barrier while lanes 1-7
        # each store 77 to their own word, work, and stop. After the barrier,
        # lane 0 adds lane 1's words of both warps (threads 1 and 9) and
        # stores the sum: 154 if the barrier waited for every lane, 0 if it
        # counted a warp as arrived when its first path did.
        def data_addr(rd, scratch):  # rd = DATA + 256 * tid (x1 = tid)
            return [W("STADDI", rd=scratch, rs1=0, imm=256), W("STMUL", rd=rd, rs1=1, rs2=scratch),
                    W("STADDI", rd=scratch, rs1=0, imm=DATA // 16), W("STADDI", rd=29, rs1=0, imm=16),
                    W("STMUL", rd=scratch, rs1=scratch, rs2=29), W("STADD", rd=rd, rs1=rd, rs2=scratch)]
        def data_base(rd):  # rd = DATA
            return [W("STADDI", rd=rd, rs1=0, imm=DATA // 16), W("STADDI", rd=29, rs1=0, imm=16),
                    W("STMUL", rd=rd, rs1=rd, rs2=29)]
        br = [W("STADDI", rd=30, rs1=0, imm=1), W("STCSRR", rd=1, imm=0), 0]   # 2: to START (patched)
        l0 = len(br)
        br += [W("STADDI", rd=11, rs1=0, imm=0), W("STADDI", rd=12, rs1=0, imm=2), W("STBAR", rs1=11, rs2=12)]
        br += data_base(3) + [W("STLW", rd=5, rs1=3, imm=256),                   # thread 1's word
                              W("STADDI", rd=13, rs1=3, imm=2047), W("STLW", rd=6, rs1=13, imm=257)]  # thread 9's
        br += data_addr(4, 7) + [W("STADD", rd=5, rs1=5, rs2=6), W("STSW", rs1=4, rs2=5, imm=0), W("STTMC", rs1=0)]
        start = len(br)
        br += [W("STBNE", rs1=1, rs2=0, imm=8), W("STBNE", rs1=30, rs2=0, imm=(4 * (l0 - (start + 1))) & 0x1fff)]
        br += [W("STADDI", rd=2, rs1=1, imm=-8), W("STBNE", rs1=2, rs2=0, imm=8),
               W("STBNE", rs1=30, rs2=0, imm=(4 * (l0 - (start + 4))) & 0x1fff)]
        br += data_addr(4, 7) + [W("STADDI", rd=5, rs1=0, imm=77), W("STSW", rs1=4, rs2=5, imm=0)]
        br += [W("STADDI", rd=8, rs1=8, imm=1) for _ in range(20)]
        br[2] = W("STBNE", rs1=30, rs2=0, imm=(4 * (start - 2)) & 0x1fff)
        prog = work / "barrier.bin"
        prog.write_bytes(image(br + [W("STTMC", rs1=0)], [1] * 64))
        rows_b, st_b = threads_of(run(binary, "simt", prog, "si_w2l8e"))
        got = (int(rows_b[0][1][0], 16), int(rows_b[8][1][0], 16))
        ok = got == (154, 154)
        print(f"  BARRIER   lane 0 of two warps at a barrier while lanes 1-7 still work: it read {got[0]} and {got[1]} "
              f"(154 if the barrier waited for every lane) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("BARRIER")

        # A stream: each lane loads 8 bytes apart, so a warp's load is one
        # line, and the loop walks 128 lines (8 KiB, twice the L1).
        def stream(passes, lines=128):
            code = [W("STCSRR", rd=1, imm=0), W("STADDI", rd=3, rs1=0, imm=8), W("STMUL", rd=8, rs1=1, rs2=3),
                    W("STADDI", rd=3, rs1=0, imm=1024), W("STADDI", rd=4, rs1=0, imm=16), W("STMUL", rd=3, rs1=3, rs2=4),
                    W("STADD", rd=8, rs1=8, rs2=3)]                      # x8 = DATA + 8 * tid
            for _ in range(passes):
                code += [W("STADD", rd=2, rs1=8, rs2=0), W("STADDI", rd=18, rs1=0, imm=lines)]
                top = len(code)
                code += [W("STLW", rd=5, rs1=2, imm=0), W("STADD", rd=6, rs1=6, rs2=5), W("STADDI", rd=2, rs1=2, imm=64),
                         W("STADDI", rd=18, rs1=18, imm=-1)]
                code += [W("STBNE", rs1=18, rs2=0, imm=(4 * (top - len(code))) & 0x1fff)]
            return code
        # MEMSYS (U2): a SIMT core that is a port of a described memory system
        # runs the stream exactly as its twin with a private cache of the same
        # shape does -- the same misses, to the cycle -- twice over, so that
        # the second pass meets lines the first left behind.
        m_own, m_sys = stats_of(stream(2), "sm_w1l8p"), stats_of(stream(2), "sm_w1l8")
        ok = (m_own["misses"] == m_sys["misses"] > 0 and m_own["cycles"] == m_sys["cycles"])
        print(f"  MEMSYS    a 128-line stream twice: private cache {m_own['cycles']} cycles, {m_own['misses']} misses; "
              f"as a port of a described memory system {m_sys['cycles']} cycles, {m_sys['misses']} misses -- "
              f"{'equal' if ok else 'DIFFER'}")
        # ... and an access outside the system's address map is refused: a
        # memory system charges an unmapped address nothing, and a run on free
        # memory looks like a fast machine.
        prog = work / "unmapped.bin"
        prog.write_bytes(image(stream(1) + [W("STTMC", rs1=0)], [1] * 64))
        refused = "outside memory system" in run(binary, "simt", prog, "sm_w1l8u")
        ok = ok and refused
        print(f"  MEMSYS    an access past the system's address map: {'refused' if refused else 'NOT REFUSED'}")
        if not ok:
            failures.append("MEMSYS")
        # PREFETCH: the stride prefetcher must engage on the stream (prefetches
        # issued, and used) and make it faster than the same cache without.
        s_tf, s_pf = stats_of(stream(1), "sc_tf"), stats_of(stream(1), "sc_pf")
        ok = (s_pf["prefetch_useful"] > 64 and s_pf["misses"] < s_tf["misses"] // 2 and s_pf["cycles"] < s_tf["cycles"])
        print(f"  PREFETCH  a 128-line stream: {s_tf['cycles']} cycles, {s_tf['misses']} misses without a prefetcher; "
              f"{s_pf['cycles']} cycles, {s_pf['misses']} misses with one ({s_pf['prefetches']} fetched, "
              f"{s_pf['prefetch_useful']} used) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("PREFETCH")
        # PREFETCH4: four warps run interleaved streams. Thread t loads 8
        # bytes at 8t, so warp w's load is line w; each step moves every warp
        # on by four lines. Each warp's load has a stride of 4 lines, and the
        # warps' lines never coincide: the table must keep an entry per warp.
        def stream4():
            code = stream(1)
            return [W("STADDI", rd=2, rs1=2, imm=256) if word == W("STADDI", rd=2, rs1=2, imm=64) else word for word in code]
        s_p4 = stats_of(stream4(), "sc_pf4")
        ok = s_p4["prefetch_useful"] > 4 * 64
        print(f"  PREFETCH4 four warps, four streams: {s_p4['prefetches']} fetched, {s_p4['prefetch_useful']} used -- "
              f"{'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("PREFETCH4")
        # BESTOFF: a 1,024-line stream, long enough for learning phases to
        # finish. It starts as next-line (offset 1); a phase must pick an
        # offset at least as far ahead, since a miss is 20 cycles and the loop
        # walks a line in about five.
        s_bo, s_tfl = stats_of(stream(1, 1024), "sc_bo"), stats_of(stream(1, 1024), "sc_tf")
        s_bo4, s_tf4 = stats_of(stream4(), "sc_bo4"), stats_of(stream4(), "sc_tf4")
        ok = (s_bo["bop_rounds"] >= 1 and s_bo["bop_offset"] >= 2 and s_bo["misses"] < s_tfl["misses"] // 4
              and s_bo["cycles"] < s_tfl["cycles"] and s_bo4["misses"] < s_tf4["misses"] // 2 and s_bo4["cycles"] < s_tf4["cycles"])
        print(f"  BESTOFF   best-offset, 1,024-line stream: {s_bo['cycles']} cycles, {s_bo['misses']} misses "
              f"(without: {s_tfl['cycles']}, {s_tfl['misses']}), {s_bo['bop_rounds']} phases, offset {s_bo['bop_offset']}; "
              f"four warps: {s_bo4['misses']} misses (without: {s_tf4['misses']}) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("BESTOFF")
        s_nl = stats_of(stream(1), "sc_nl")
        ok = s_nl["prefetch_useful"] > 64 and s_nl["misses"] < s_tf["misses"] // 2 and s_nl["cycles"] < s_tf["cycles"]
        print(f"  NEXTLINE  the same stream, next-line prefetch: {s_nl['cycles']} cycles, {s_nl['misses']} misses "
              f"({s_nl['prefetches']} fetched, {s_nl['prefetch_useful']} used) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("NEXTLINE")
        # L2: the same stream twice. The second pass misses the 4 KiB L1 and
        # hits a 64 KiB L2.
        t_tf, t_l2 = stats_of(stream(2), "sc_tf"), stats_of(stream(2), "sc_l2")
        ok = t_l2["l2_hits"] >= 120 and t_l2["cycles"] < t_tf["cycles"]
        print(f"  L2        the stream twice: {t_tf['cycles']} cycles with one level; {t_l2['cycles']} with an L2 "
              f"({t_l2['l2_hits']} hits, {t_l2['l2_misses']} misses) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("L2")

        straight = [W("STADDI", rd=5 + k % 10, rs1=0, imm=k) for k in range(24)]
        s1, s8 = stats_of(straight, "sc_w1l1"), stats_of(straight, "sc_w1l8")
        ok = s1["cycles"] == s8["cycles"]
        print(f"  UNIFORM   24 independent ops: 1 lane {s1['cycles']} cycles, 8 lanes {s8['cycles']} -- {'equal' if ok else 'DIFFER'}")
        if not ok:
            failures.append("UNIFORM")

        n = 24
        wide, narrow = stats_of(straight, "sc_w1l8"), stats_of(straight, "sc_w1l8n")
        expect = 3 * n
        got = narrow["cycles"] - wide["cycles"]
        ok = got == expect
        print(f"  NARROW    {n} ALU ops, 8 lanes on a 2-lane ALU: +{got} cycles, expected +{expect} (3 per op) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("NARROW")

        def ifelse(pred_imm, A, B):
            code = [W("STCSRR", rd=1, imm=0), W("STADDI", rd=ONE, rs1=0, imm=1),
                    W("STADDI", rd=19, rs1=1, imm=pred_imm)]
            code.append(W("STSPLIT", rd=20, rs1=19))
            br = len(code); code.append(0)
            code += [W("STADDI", rd=5, rs1=5, imm=1)] * B
            jmp = len(code); code.append(0)
            then = len(code)
            code += [W("STADDI", rd=6, rs1=6, imm=1)] * A
            join = len(code)
            code.append(W("STJOIN", rs1=20))
            code[br] = W("STBNE", rs1=19, rs2=0, imm=(4 * (then - br)) & 0x1fff)
            code[jmp] = W("STBNE", rs1=ONE, rs2=0, imm=(4 * (join - jmp)) & 0x1fff)
            return code
        A, B = 5, 7
        # pred = tid + 1: never zero, every lane takes THEN; pred = tid - 3:
        # zero for lane 3 only -- a divergent split, one lane on ELSE.
        try:
            uni = stats_of(ifelse(1, A, B), "sc_w1l8")
            div = stats_of(ifelse(-3, A, B), "sc_w1l8")
        except RuntimeError as error:
            failures.append(f"DIVERGE: {error}")
            uni = div = {"warp_instrs": 0, "divergent": -1}
        got = div["warp_instrs"] - uni["warp_instrs"]
        ok = got == B + 3 and div["divergent"] == 1 and uni["divergent"] == 0
        print(f"  DIVERGE   then {A}, else {B}: +{got} warp instructions when one lane takes else, expected +{B + 3} -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("DIVERGE")

        # ORDER: the smaller group runs first (Vortex's policy; it is what a
        # mutation running the larger first changed, and race-free programs
        # cannot see it). A deliberate race makes it visible: every lane
        # stores its id to ONE word in both arms, so the group that runs
        # second has the last word -- lane 3 alone on ELSE is the smaller.
        race = ifelse(-3, 0, 0)
        shared = [W("STADDI", rd=3, rs1=0, imm=1024), W("STADDI", rd=4, rs1=0, imm=16),
                  W("STMUL", rd=3, rs1=3, rs2=4), W("STSW", rs1=3, rs2=1, imm=0)]
        race = race[:4] + race[4:5] + shared + race[5:6] + shared + race[6:]
        # the two branches were placed for empty arms: recompute their offsets
        br, jmp, join = 4, 4 + 1 + len(shared), 4 + 2 + 2 * len(shared)
        race[br] = W("STBNE", rs1=19, rs2=0, imm=(4 * (jmp + 1 - br)) & 0x1fff)
        race[jmp] = W("STBNE", rs1=ONE, rs2=0, imm=(4 * (join - jmp)) & 0x1fff)
        prog = work / "order.bin"
        prog.write_bytes(image(race + [W("STTMC", rs1=0)], [1] * 64))
        out = run(binary, "simt", prog, "sc_w1l8")
        rows, _ = threads_of(out)
        last = int(rows[0][1][0], 16)  # thread 0's region starts at DATA = the shared word
        ok = last == 7
        print(f"  ORDER     one lane on ELSE, seven on THEN, all storing to one word: last writer {last}, "
              f"expected 7 (the smaller group first) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("ORDER")

        def loads(stride_shift):
            code = [W("STCSRR", rd=1, imm=0), W("STADDI", rd=3, rs1=0, imm=1 << stride_shift),
                    W("STMUL", rd=2, rs1=1, rs2=3), W("STADDI", rd=3, rs1=0, imm=1024),
                    W("STADDI", rd=4, rs1=0, imm=16), W("STMUL", rd=3, rs1=3, rs2=4),
                    W("STADD", rd=2, rs1=2, rs2=3)]
            return code + [W("STLW", rd=5 + k, rs1=2, imm=0) for k in range(4)]
        dense, sparse = stats_of(loads(2), "sc_w1l8"), stats_of(loads(6), "sc_w1l8")
        ok = dense["mem_lines"] == 4 and sparse["mem_lines"] == 32
        print(f"  COALESCE  4 loads x 8 lanes: consecutive words {dense['mem_lines']} lines (expected 4), "
              f"64 bytes apart {sparse['mem_lines']} (expected 32) -- {'ok' if ok else 'WRONG'}")
        if not ok:
            failures.append("COALESCE")

        sys.modules.pop(module, None)
        for f in failures[:12]:
            print(f"    {f}")
        print(f"{PASSED if not failures else FAILED}: simt_check ({len(failures)} failure(s))")
        return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
