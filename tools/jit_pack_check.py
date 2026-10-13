#!/usr/bin/env python3
"""The JIT library against the executor beside it, in one binary. Gate.

A pack's sixth library translates instructions into machine code by copying
stencils and patching operand holes. Nothing about that is checkable by
inspection: the bytes came out of a compiler, the patcher rewrites two
instruction fields by hand, and the only way to know it is right is to run what
it produced and ask whether the registers landed where the architecture says.

So this runs both: the same instruction through `axis_exec_pack->step`, which
the ladder already holds to the golden model, and through
`axis_jit_pack->translate` plus a call into the result. The executor is the
reference and the JIT is the claim. They start from one register file and must
end with the same one.

⚠️ Blocks, not only single instructions. A stencil that works alone and a block
that works are different claims -- the whole design rests on falling out of one
stencil into the next with the register file the previous one left, which a
one-instruction test cannot see.

Usage: tools/jit_pack_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: How long a block to translate in one go, and how many.
BLOCK = 8
BLOCKS = 24

HARNESS = r"""
/* The pack's JIT against the pack's executor. Three libraries, one process. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "axis_pack.h"
#include "axis_lift.h"
#include "axis_semantics.h"
#include "axis_exec.h"

extern const axis_jit_pack *%(jit)s(void);
extern const axis_exec_pack *%(exec)s(void);
extern const axis_asm_pack *%(asm)s(void);
extern const axis_lift_pack *%(lift)s(void);

#define SLOTS 256
#define MAXVALS 8
#define MAXOPS %(block)d
#define POOL 8192
/* The machine the translated code runs on. ⚠️ Big and ZEROED, because a
   translated load computes its address with no bound applied -- the library
   says as much -- so the harness gives it somewhere every address a seeded
   register can name will land. */
#define MACHINE_BYTES (1 << 20)
#define MACHINE_MASK (MACHINE_BYTES - 1)
#define LONGOPS 256

/* ⚠️ Aligned to the widest atomic a description can have. Translated code
   performs a 128-bit compare-and-swap with the instruction the architecture
   provides -- `casp` -- and that faults unless its address is 16-aligned. The
   address is `MACHINE + rn`, so the base has to be aligned or the harness dies
   on a program the interpreter runs happily. */
static _Alignas(16) uint8_t MACHINE[MACHINE_BYTES];
static uint64_t SCRATCH[64];
static uint64_t STATE_SLOTS_[64];

/* ⚠️ The executor reads and writes MIRROR, the translated code writes MACHINE,
   and the two are seeded identically. Same addressing on both sides, with no
   masking: a mask would hide exactly the disagreement this looks for -- a
   store that went somewhere else. */
static _Alignas(16) uint8_t MIRROR[MACHINE_BYTES];
static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) {
    v |= (uint64_t)MIRROR[(a + i) & MACHINE_MASK] << (8 * i);
  }
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) {
    MIRROR[(a + i) & MACHINE_MASK] = (uint8_t)(v >> (8 * i));
  }
}

/* ⚠️ Addresses this harness can answer for. A translated load computes its
   address with no bound applied -- the contract says so -- so a register that
   might be one holds a small aligned value, and the machine is a megabyte so
   any immediate an instruction adds still lands inside it. Seeding the wide
   patterns everywhere took a bus error on the first atomic. */
static void seed_registers(uint64_t *regs, int32_t count, int32_t k, int effectful) {
  for (int32_t i = 0; i < count; ++i) {
    /* ⚠️ Sixteen, not eight. An address is `MACHINE + rn`, and AArch64's
       128-bit compare-and-swap faults unless that is 16-aligned -- the
       architecture requires it, so a program that misaligns `casp` is not a
       hard case this gate should cover, it is an illegal one. The interpreter
       does not fault, because it reaches memory through a hook that takes any
       address, so the two engines would be compared on a program neither
       machine would run. */
    regs[i] = effectful ? (uint64_t)(((i * 16) + k * 64) & 0x3FF0)
                        : 0x1111u * (uint64_t)(i + 1) + (uint64_t)k;
  }
}

/* ⚠️ `seed_registers`, not `seed`. A function named `seed` sat where an array
   named `seed` had been, and `memcpy(got, seed, sizeof got)` copied the
   function's ADDRESS into the register file -- which compiles, because a
   function name decays to a pointer, and then a translated load followed a
   garbage register into a wild address. */
static void seed_memory(int32_t k) {
  for (size_t i = 0; i < MACHINE_BYTES; ++i) {
    MACHINE[i] = MIRROR[i] = (uint8_t)((i * 7 + k * 31) & 0xFF);
  }
  memset(SCRATCH, 0, sizeof SCRATCH);
}

/* ⚠️ Architectural state, seeded so a guard can come out TRUE. Held at zero,
   `sc.w`'s reservation never matched, its store never happened, and the
   library could have pointed `state` at memory or `scratch` at `state`
   without a single answer changing. The reservation is aimed at an address
   the harness seeds, so about half of these succeed. */
/* ⚠️ `effectful` bounds these the way `seed_registers` bounds a register, and
   for the same reason. A state slot can be an ADDRESS BASE: AArch64 spells the
   stack pointer as index 31 of `a64_gpr64sp`, which aliases the `sp` slot, so
   `swp x0, x1, [sp]` reads memory at whatever this function put there. The
   executor tolerates any address because its hooks mask; translated code uses
   the address raw, which is the contract, and the harness is the host that has
   to answer for it. Before stencils could reach an aliased register this could
   not arise, and the first one that did took the process with it. */
static void seed_state(int32_t k, uint64_t base, int32_t bits, int32_t count,
                       axis_pack_state_entry *ps, int effectful) {
  for (int32_t i = 0; i < count && i < 64; ++i) {
    const char *name = ps[i].name ? ps[i].name : "";
    uint64_t value;
    if (strstr(name, "address")) { value = base; }
    else if (strstr(name, "size")) { value = (k & 1) ? 4u : 8u; }
    else if (strstr(name, "valid")) { value = 1u; }
    else if (effectful) { value = (uint64_t)(((i * 8) + k * 64) & 0x3FF8); }
    else { value = (uint64_t)(i * 0x11 + k); }
    if (ps[i].width && ps[i].width < 64) { value &= (1ull << ps[i].width) - 1; }
    ps[i].value = value;
    if (bits == 32) { ((uint32_t *)STATE_SLOTS_)[i] = (uint32_t)value; }
    else { STATE_SLOTS_[i] = value; }
  }
}

static int state_agrees(int32_t bits, int32_t count,
                        const axis_pack_state_entry *ps, int32_t *where) {
  for (int32_t i = 0; i < count && i < 64; ++i) {
    uint64_t mine = (bits == 32) ? ((const uint32_t *)STATE_SLOTS_)[i]
                                 : STATE_SLOTS_[i];
    uint64_t theirs = ps[i].value;
    if (ps[i].width && ps[i].width < 64) {
      mine &= (1ull << ps[i].width) - 1;
      theirs &= (1ull << ps[i].width) - 1;
    }
    if (mine != theirs) { *where = i; return 0; }
  }
  return 1;
}

static const axis_jit_pack *J;
static const axis_exec_pack *X;
static const axis_asm_pack *A;
static const axis_lift_pack *L;

typedef struct {
  uint32_t word; const char *isa; const char *mnemonic;
  int32_t stencil; uint64_t values[MAXVALS]; int32_t n; int effectful;
  /* ⚠️ Whether it may redirect the pc. A block is straight-line code, so a
     branch can only be its LAST instruction -- everything after a taken one
     runs regardless, and the executor reference stops there while the block
     does not. The simulator enforces exactly this; a gate that composed
     blocks without it was comparing a translated block against a reference
     that had gone somewhere else. */
  int branches;
  /* Which registers it reads and which it writes, by index. ⚠️ A block may
     only carry a memory instruction whose address registers still hold what
     the harness seeded: a translated load has no bound to fall back on, so an
     earlier op in the block writing its base is a wild address rather than a
     wrong answer. The same rule `jit_stencil.py` found the hard way. */
  uint8_t reads[8]; int32_t read_count;
  uint8_t writes[4]; int32_t write_count;
} built;

/* Whether this op can go in a block whose earlier ops wrote `written`. An
   instruction that only computes always can; one that reaches memory can only
   while the registers it reads still hold what the harness seeded. */
static int vouched(const void *op, const uint8_t *written);
static built BUILT[POOL];
static int32_t built_count = 0;
/* ⚠️ Which stencils actually ran. A gate that reports "394 instructions" and
   not WHICH is one that can go green about a stencil it never touched --
   `docs/gate_coverage.md` is the record of that happening twice in one day. */
static uint8_t COVERED[4096];
/* How far each stencil got, so an uncovered one is reported with its cause
   rather than as a bare absence: 1 tried, 2 assembled, 3 lifted under its own
   name, 4 the executor ran it, 5 translated and compared. */
static uint8_t REACHED[4096];
static const char *const STAGE[] = {
  "the assembler has no instruction of that name",
  "no operand values this gate tries satisfy its encoding",
  "the word it assembles to lifts as a different instruction",
  "its holes name operands the lifted word does not carry",
  "the executor would not run it, so there is no reference",
};

static void reached(int32_t stencil, int stage) {
  if (stencil >= 0 && stencil < 4096 && REACHED[stencil] < stage) {
    REACHED[stencil] = (uint8_t)stage;
  }
}

/* A field the description sign extends is worth that much as a value; the
   executor decodes it that way, so the stencil must be handed it that way. */
static int vouched(const void *raw, const uint8_t *written) {
  const built *b = (const built *)raw;
  if (b->branches) { return 0; }
  if (!b->effectful) { return 1; }
  for (int32_t i = 0; i < b->read_count; ++i) {
    if (written[b->reads[i]]) { return 0; }
  }
  return 1;
}

/* ⚠️ Memory, not only registers. A store that went to the wrong address
   leaves every register right, which is exactly how the symbolic backend's
   twin of this bug survived. Compared over the range the harness seeds
   addresses into rather than the whole machine, which would be a megabyte a
   run. */
#define WATCHED (1 << 16)
static int memory_agrees(size_t *where) {
  for (size_t i = 0; i < WATCHED; ++i) {
    if (MACHINE[i] != MIRROR[i]) { *where = i; return 0; }
  }
  return 1;
}

static uint64_t sext(uint32_t field, uint32_t bits) {
  if (bits == 0 || bits >= 64) { return (uint64_t)field; }
  uint64_t value = (uint64_t)field & ((1ull << bits) - 1u);
  uint64_t sign = 1ull << (bits - 1);
  return (value ^ sign) - sign;
}

/* ⚠️ Register indices worth trying, not just convenient ones. `0` is RISC-V's
   hardwired zero and `31` is AArch64's, and a stencil that ignored them agreed
   with the executor on every other index -- which is what an earlier version
   of this gate measured. */
static const uint32_t REGS[] = { 1, 0, 31, 8, 2, 15 };
static const uint32_t IMMS[] = { 1, 0, 3, 2, 7, 4 };
#define VARIANTS 6

int main(void) {
  J = %(jit)s(); X = %(exec)s(); A = %(asm)s(); L = %(lift)s();
  static uint8_t *page; size_t page_size = 1 << 16;
  page = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (page == MAP_FAILED) { printf("NOPAGE\n"); return 0; }
  printf("HOST %%s %%d\n", J->host, J->count());

  int32_t nostencil = 0, unbound = 0, refused = 0;
  for (int32_t i = 0; i < A->count() && built_count < POOL; ++i) {
    const char *mnemonic = A->mnemonic(i);
    int32_t stencil = J->stencil_for(mnemonic);
    if (stencil < 0) { nostencil++; continue; }
    /* ⚠️ The instruction's own ISA, not NULL. A corpus can hold an accelerator
       whose encoding overlaps the base one it accelerates, and a lift with no
       ISA named answers with whichever matched first -- which looked like 17
       stencils this gate could not reach. */
    const char *isa = NULL;
    for (int32_t li = 0; li < L->count(); ++li) {
      const char *ln = L->mnemonic(li);
      if (ln && !strcmp(ln, mnemonic)) { isa = L->isa(li); break; }
    }
    int32_t nops = A->operand_count(i);
    if (nops > 16) { continue; }
    for (int32_t v = 0; v < VARIANTS && built_count < POOL; ++v) {
      uint32_t fields[16];
      for (int32_t o = 0; o < nops; ++o) {
        const char *kind = A->operand_kind(i, o);
        int is_imm = kind && !strcmp(kind, "imm");
        fields[o] = is_imm ? IMMS[(v + o) %% VARIANTS] : REGS[(v + o) %% VARIANTS];
      }
      uint32_t word = 0;
      reached(stencil, 1);
      if (!A->assemble(i, fields, &word)) { refused++; continue; }
      reached(stencil, 2);

      /* ⚠️ The values that go to the JIT come from LIFTING the word, not from
         what was handed to the assembler. The executor sees only the word, so
         anything the encoding does not carry -- a field narrower than the
         number, an immediate the description shifts -- would otherwise be a
         disagreement this gate blamed on the JIT. Both sides decode the same
         word or the comparison means nothing. */
      axis_pack_lifted lifted;
      if (!L->lift(word, isa, &lifted) || lifted.index < 0) { refused++; continue; }
      const char *lifted_name = L->mnemonic(lifted.index);
      if (!lifted_name || strcmp(lifted_name, mnemonic)) { refused++; continue; }
      reached(stencil, 3);

      int32_t holes = J->holes(stencil);
      int32_t wanted = J->values(stencil);
      if (wanted > MAXVALS) { unbound++; continue; }
      built *b = &BUILT[built_count];
      b->effectful = J->effectful(stencil);
      /* The lift table says whether control may leave here, which is the same
         question the simulator asks of the same field. */
      b->branches = L->ends_block(lifted.index) == 1;
      int ok = 1;
      int32_t filled = 0;
      for (int32_t h = 0; h < holes && ok; ++h) {
        const char *want = J->hole(stencil, h);
        /* The machine's own parts are the library's to fill. */
        /* ⚠️ Every machine part, by name. A part this list does not know is a
           hole the harness tries to bind to an operand, fails, and reports as
           an instruction whose holes name nothing -- which is what the memory
           window looked like when it arrived. */
        if (want && (!strcmp(want, "regs") || !strcmp(want, "mem")
                     || !strcmp(want, "out") || !strcmp(want, "state")
                     || !strcmp(want, "pc") || !strcmp(want, "mask"))) { continue; }
        ok = 0;
        for (int32_t o = 0; o < lifted.operand_count && o < AXIS_PACK_MAX_OPERANDS; ++o) {
          const char *name = L->operand_name(lifted.index, o);
          if (!want || !name || strcmp(want, name) || !lifted.operand_valid[o]) { continue; }
          const char *kind = L->operand_kind(lifted.index, o);
          uint32_t signed_bits = 0;
          for (int32_t a = 0; a < nops; ++a) {
            const char *an = A->operand_name(i, a);
            if (an && !strcmp(an, name)) { signed_bits = A->operand_signed_bits(i, a); break; }
          }
          b->values[filled++] = (kind && !strcmp(kind, "imm"))
              ? sext(lifted.operands[o], signed_bits)
              : (uint64_t)lifted.operands[o];
          ok = 1; break;
        }
      }
      if (!ok || filled != wanted) { unbound++; continue; }
      reached(stencil, 4);
      b->read_count = b->write_count = 0;
      for (int32_t o = 0; o < lifted.operand_count && o < AXIS_PACK_MAX_OPERANDS; ++o) {
        const char *kind = L->operand_kind(lifted.index, o);
        const char *role = L->operand_role(lifted.index, o);
        if (!kind || !strcmp(kind, "imm") || !lifted.operand_valid[o]) { continue; }
        uint8_t index = (uint8_t)(lifted.operands[o] & 0xFF);
        if (role && (!strcmp(role, "out") || !strcmp(role, "inout"))
            && b->write_count < 4) {
          b->writes[b->write_count++] = index;
        }
        if (role && strcmp(role, "out") && b->read_count < 8) {
          b->reads[b->read_count++] = index;
        }
      }
      b->word = word; b->isa = isa; b->mnemonic = mnemonic;
      b->stencil = stencil; b->n = filled;
      built_count++;
    }
  }

  axis_pack_state_entry ps[64];
  int32_t ns = X->state_slots(); if (ns > 64) ns = 64;
  for (int32_t i = 0; i < ns; ++i) {
    ps[i].name = X->state_name(i); ps[i].value = 0; ps[i].width = X->state_width(i);
  }
  axis_pack_mem pm = { rd, wr, NULL };
  /* How wide a scratch or state slot is on this machine -- 64 here, 32 on a
     32-bit description, and the library is what says which. */
  int32_t word = 64;
  for (int32_t i = 0; i < J->count(); ++i) {
    if (J->word_bits(i)) { word = J->word_bits(i); break; }
  }

  int32_t singles = 0, wrong = 0, declined = 0;
  for (int32_t k = 0; k < built_count; ++k) {
    built *b = &BUILT[k];
    uint64_t start[SLOTS];
    seed_registers(start, SLOTS, k, b->effectful);
    seed_memory(k);
    seed_state(k, start[1], word, ns, ps, b->effectful);

    uint64_t want[SLOTS]; memcpy(want, start, sizeof want);
    axis_pack_exec_result pr;
    X->step(b->word, b->isa, want, X->register_slots(), &pm, 0x40u, ps, ns, &pr);
    /* An instruction the executor will not run is no reference at all --
       counted and named, never silently compared against an untouched file. */
    if (!pr.ok || pr.trapped) { declined++; continue; }
    reached(b->stencil, 5);

    uint64_t got[SLOTS]; memcpy(got, start, sizeof got);
    size_t used = 0;
    axis_jit_op op = { b->stencil, b->values, b->n, 0x40u };
    axis_jit_machine machine = { (uint64_t)(uintptr_t)got,
                                 (uint64_t)(uintptr_t)MACHINE,
                                 (uint64_t)(uintptr_t)SCRATCH,
                                 (uint64_t)(uintptr_t)STATE_SLOTS_,
                                 MACHINE_MASK };
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE)) { printf("NOPAGE\n"); return 0; }
    printf("TRANSLATING %%s\n", b->mnemonic); fflush(stdout);
    if (!J->translate(&op, 1, page, page_size, (uint64_t)(uintptr_t)page,
                      &machine, &used)) {
      printf("UNTRANSLATED %%s\n", b->mnemonic); wrong++; continue;
    }
    if (mprotect(page, page_size, PROT_READ | PROT_EXEC)) { printf("NOPAGE\n"); return 0; }
    __builtin___clear_cache((char *)page, (char *)page + used);
    printf("RUNNING %%s %%zu\n", b->mnemonic, used); fflush(stdout);
    ((void (*)(void))(uintptr_t)page)();
    singles++;
    if (b->stencil >= 0 && b->stencil < 4096) { COVERED[b->stencil] = 1; }
    int bad = 0;
    for (int32_t i = 0; i < SLOTS && !bad; ++i) {
      if (got[i] != want[i]) {
        if (wrong < 6) printf("DIFF %%s word 0x%%08x slot %%d jit=0x%%llx exec=0x%%llx\n",
                              b->mnemonic, b->word, i, (unsigned long long)got[i],
                              (unsigned long long)want[i]);
        wrong++; bad = 1;
      }
    }
    size_t at = 0;
    int32_t slot = 0;
    if (!bad && !memory_agrees(&at)) {
      if (wrong < 6) printf("DIFF %%s word 0x%%08x byte 0x%%zx jit=0x%%02x exec=0x%%02x\n",
                            b->mnemonic, b->word, at, MACHINE[at], MIRROR[at]);
      wrong++; bad = 1;
    }
    if (!bad && !state_agrees(word, ns, ps, &slot)) {
      if (wrong < 6) printf("DIFF %%s word 0x%%08x state %%s\n",
                            b->mnemonic, b->word, ps[slot].name);
      wrong++;
    }
  }
  printf("SINGLE %%d %%d %%d %%d %%d\n", singles, wrong, unbound, nostencil, declined);
  int32_t covered = 0, missed = 0;
  for (int32_t i = 0; i < J->count() && i < 4096; ++i) {
    if (COVERED[i]) { covered++; continue; }
    missed++;
    if (missed <= 8) {
      printf("UNCOVERED %%s: %%s\n", J->mnemonic(i), STAGE[REACHED[i] < 5 ? REACHED[i] : 4]);
    }
  }
  printf("COVERED %%d %%d\n", covered, J->count());

  /* Blocks. A stencil that works alone and a block that works are different
     claims: the block rests on falling out of one stencil into the next with
     the register file the previous one left. */
  int32_t blocks = 0, block_wrong = 0;
  for (int32_t p = 0; p < %(programs)d && built_count > 0; ++p) {
    axis_jit_op ops[MAXOPS];
    int32_t chosen[MAXOPS];
    int32_t n = 0;
    uint8_t written[256] = {0};
    for (int32_t i = 0; i < MAXOPS; ++i) {
      int32_t k = (p * 7 + i * 13) %% built_count;
      if (!vouched(&BUILT[k], written)) { continue; }
      for (int32_t w = 0; w < BUILT[k].write_count; ++w) {
        written[BUILT[k].writes[w]] = 1;
      }
      chosen[n] = k;
      ops[n].stencil = BUILT[k].stencil;
      ops[n].values = BUILT[k].values;
      ops[n].value_count = BUILT[k].n;
      ops[n].pc = 0x40u + 4u * (uint64_t)i;
      n++;
    }
    int touches = 0;
    for (int32_t i = 0; i < n; ++i) touches |= BUILT[chosen[i]].effectful;
    uint64_t start[SLOTS];
    seed_registers(start, SLOTS, p + 1, touches);
    seed_memory(p + 1);
    seed_state(p + 1, start[1], word, ns, ps, 1);

    uint64_t want[SLOTS]; memcpy(want, start, sizeof want);
    int usable = 1;
    for (int32_t i = 0; i < n && usable; ++i) {
      axis_pack_exec_result pr;
      /* ⚠️ The same pc the translated op was given. Stepping every
         instruction of a block at one address, while the JIT advances it,
         differs by exactly four per instruction -- visible only in an
         instruction that READS the pc, which is how this was found. */
      X->step(BUILT[chosen[i]].word, BUILT[chosen[i]].isa, want, X->register_slots(),
              &pm, ops[i].pc, ps, ns, &pr);
      usable = pr.ok && !pr.trapped;
    }
    if (!usable) { continue; }

    uint64_t got[SLOTS]; memcpy(got, start, sizeof got);
    size_t used = 0;
    if (mprotect(page, page_size, PROT_READ | PROT_WRITE)) { printf("NOPAGE\n"); return 0; }
    axis_jit_machine machine = { (uint64_t)(uintptr_t)got,
                                 (uint64_t)(uintptr_t)MACHINE,
                                 (uint64_t)(uintptr_t)SCRATCH,
                                 (uint64_t)(uintptr_t)STATE_SLOTS_,
                                 MACHINE_MASK };
    if (!J->translate(ops, n, page, page_size, (uint64_t)(uintptr_t)page,
                      &machine, &used)) {
      printf("UNTRANSLATED block %%d\n", p); block_wrong++; continue;
    }
    if (mprotect(page, page_size, PROT_READ | PROT_EXEC)) { printf("NOPAGE\n"); return 0; }
    __builtin___clear_cache((char *)page, (char *)page + used);
    ((void (*)(void))(uintptr_t)page)();
    blocks++;
    int bad = 0;
    for (int32_t i = 0; i < SLOTS && !bad; ++i) {
      if (got[i] != want[i]) {
        if (block_wrong < 6) printf("DIFFBLOCK %%d slot %%d jit=0x%%llx exec=0x%%llx\n",
                                    p, i, (unsigned long long)got[i],
                                    (unsigned long long)want[i]);
        block_wrong++; bad = 1;
      }
    }
    size_t at = 0;
    int32_t slot = 0;
    if (!bad && !memory_agrees(&at)) {
      if (block_wrong < 6) printf("DIFFBLOCK %%d byte 0x%%zx jit=0x%%02x exec=0x%%02x\n",
                                  p, at, MACHINE[at], MIRROR[at]);
      block_wrong++; bad = 1;
    }
    if (!bad && !state_agrees(word, ns, ps, &slot)) {
      if (block_wrong < 6) printf("DIFFBLOCK %%d state %%s\n", p, ps[slot].name);
      block_wrong++;
    }
  }
  printf("BLOCK %%d %%d %%d\n", blocks, block_wrong, %(programs)d);

  /* ⚠️ One LONG block, and not for volume. A short block's operand slots sit
     within a page of the code that reaches them, so the `adrp` page delta is
     zero and patching it wrong is invisible -- which is what a mutation of
     `axis_jit_page21` proved: the shift could be off by one and every short
     block still agreed. This block's code is kilobytes, so its first
     instructions reach their slots pages away. */
  static axis_jit_op longops[LONGOPS];
  static int32_t longchosen[LONGOPS];
  static uint8_t long_written[256];
  int32_t ln = 0;
  for (int32_t i = 0; i < LONGOPS && built_count > 0; ++i) {
    int32_t k = (i * 11) %% built_count;
    if (!vouched(&BUILT[k], long_written)) { continue; }
    for (int32_t w = 0; w < BUILT[k].write_count; ++w) {
      long_written[BUILT[k].writes[w]] = 1;
    }
    longchosen[ln] = k;
    longops[ln].stencil = BUILT[k].stencil;
    longops[ln].values = BUILT[k].values;
    longops[ln].value_count = BUILT[k].n;
    ln++;
  }
  int32_t pages = 0, long_wrong = 0;
  size_t long_used = 0;
  if (ln > 1) {
    static uint64_t start[SLOTS], want[SLOTS], got[SLOTS];
    int touches = 0;
    for (int32_t i = 0; i < ln; ++i) touches |= BUILT[longchosen[i]].effectful;
    seed_registers(start, SLOTS, 3, touches);
    seed_memory(3);
    seed_state(3, start[1], word, ns, ps, 1);
    memcpy(want, start, sizeof want);
    int usable = 1;
    for (int32_t i = 0; i < ln && usable; ++i) {
      axis_pack_exec_result pr;
      X->step(BUILT[longchosen[i]].word, BUILT[longchosen[i]].isa, want,
              X->register_slots(), &pm, longops[i].pc, ps, ns, &pr);
      usable = pr.ok && !pr.trapped;
    }
    memcpy(got, start, sizeof got);
    size_t used = 0;
    if (usable) {
      if (mprotect(page, page_size, PROT_READ | PROT_WRITE)) { printf("NOPAGE\n"); return 0; }
      axis_jit_machine machine = { (uint64_t)(uintptr_t)got,
                                   (uint64_t)(uintptr_t)MACHINE,
                                   (uint64_t)(uintptr_t)SCRATCH,
                                   (uint64_t)(uintptr_t)STATE_SLOTS_,
                                 MACHINE_MASK };
      if (!J->translate(longops, ln, page, page_size, (uint64_t)(uintptr_t)page,
                        &machine, &used)) {
        printf("UNTRANSLATED long\n"); long_wrong++; usable = 0;
      }
    }
    if (usable) {
      if (mprotect(page, page_size, PROT_READ | PROT_EXEC)) { printf("NOPAGE\n"); return 0; }
      __builtin___clear_cache((char *)page, (char *)page + used);
      ((void (*)(void))(uintptr_t)page)();
      /* How far the first instruction had to reach: the claim this block is
         here to make. One page or less and it makes no claim at all. */
      pages = (int32_t)(used / 4096u);
      long_used = used;
      int bad = 0;
      for (int32_t i = 0; i < SLOTS && !bad; ++i) {
        if (got[i] != want[i]) {
          printf("DIFFLONG slot %%d jit=0x%%llx exec=0x%%llx\n", i,
                 (unsigned long long)got[i], (unsigned long long)want[i]);
          long_wrong++; bad = 1;
        }
      }
      size_t at = 0;
      if (!bad && !memory_agrees(&at)) {
        printf("DIFFLONG byte 0x%%zx jit=0x%%02x exec=0x%%02x\n",
               at, MACHINE[at], MIRROR[at]);
        long_wrong++;
      }
    }
  }
  printf("LONG %%d %%d %%d\n", ln, long_wrong, pages);
  printf("LONGBYTES %%zu\n", long_used);
  printf("REFUSED %%d\n", refused);
  return 0;
}
"""


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    """One corpus: build the pack, run both libraries, compare. (checks, failures)."""
    manifest = build_pack.build(axis_file, work / "packs")
    name = manifest["name"]
    if "jit" not in manifest["libraries"]:
        print(f"  {name}: no JIT library -- "
              f"{manifest['declined'].get('jit', 'not built')}")
        return 0, 0
    source = HARNESS % {
        "jit": manifest["libraries"]["jit"]["entry"],
        "exec": manifest["libraries"]["exec"]["entry"],
        "asm": manifest["libraries"]["asm"]["entry"],
        "lift": manifest["libraries"]["lift"]["entry"],
        "block": BLOCK,
        "programs": BLOCKS,
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
         "-o", str(work / name), str(work / f"{name}.c"),
         *(str(root / "lib" / manifest["libraries"][f]["static"])
           for f in ("jit", "exec", "asm", "lift"))])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    out = done.stdout
    if done.returncode < 0:
        # Translated code that jumps or reads somewhere wild takes the harness
        # with it. That is a failure of the JIT, not of the machine it ran on,
        # and it is worth saying which rather than reporting "nothing ran".
        # ⚠️ And what it was doing. A crash reported as a bare signal number is
        # the least useful thing this gate can say: the harness names each
        # instruction as it translates and runs it, so the last line before the
        # death is the one to look at, and throwing that away meant bisecting
        # the emitter to find out what every run already knew.
        said = [line for line in out.splitlines()
                if line.startswith(("TRANSLATING", "RUNNING"))]
        print(f"  FAIL {name}: the harness died on signal {-done.returncode} "
              f"running translated code"
              + (f", last: {said[-1]}" if said else ", having run nothing"))
        return 0, 1
    if "NOPAGE" in out:
        print(f"  {name}: this host would not give the harness executable memory")
        return 0, 0
    failures = checks = 0
    for line in out.splitlines():
        if line.startswith(("DIFF ", "DIFFBLOCK ", "DIFFLONG ", "UNTRANSLATED ")):
            print(f"  FAIL {name}: {line}")
        elif line.startswith("SINGLE "):
            ran, wrong, unbound, none, declined = (int(x) for x in line.split()[1:])
            checks += ran
            failures += wrong
            print(f"  {name}: {ran} instruction(s) translated and run, {wrong} wrong; "
                  f"{none} with no stencil, {unbound} whose holes no operand names, "
                  f"{declined} the executor would not run")
        elif line.startswith("BLOCK "):
            ran, wrong, asked = (int(x) for x in line.split()[1:])
            checks += ran
            failures += wrong
            print(f"  {name}: {ran} of {asked} block(s) of {BLOCK} run, {wrong} wrong")
        elif line.startswith("UNCOVERED "):
            print(f"  FAIL {name}: never ran {line.split(' ', 1)[1]}")
        elif line.startswith("COVERED "):
            ran, total = (int(x) for x in line.split()[1:])
            failures += total - ran
            print(f"  {name}: {ran} of {total} stencils in the table were run")
        elif line.startswith("LONGBYTES "):
            print(f"  {name}: the long block is {line.split()[1]} byte(s)")
        elif line.startswith("LONG "):
            ran, wrong, pages = (int(x) for x in line.split()[1:])
            checks += 1 if ran > 1 else 0
            failures += wrong
            # ⚠️ One page, not two. The claim is that the FIRST stencil's
            # operand slots sit in a different page from its code, which is
            # when `adrp`'s delta stops being zero -- the slots follow the
            # code, so a block bigger than a page makes it. Demanding two was
            # a proxy that started failing when three times as many
            # instructions had stencils and the block that fits in the pool
            # got shorter. Measured, not assumed: with a 6980-byte block, an
            # `axis_jit_page21` whose shift is off by one is still caught.
            if ran > 1 and pages < 1:
                print(f"  FAIL {name}: the long block fits in one page, so no "
                      f"stencil reaches its operands across one")
                failures += 1
            else:
                print(f"  {name}: one block of {ran} across {pages} pages, {wrong} wrong")
        elif line.startswith("HOST "):
            print(f"  {name}: {line.split()[2]} stencils for {line.split()[1]}")
    if not checks:
        print(f"  FAIL {name}: nothing ran")
        failures += 1
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "rv64i.axisl"]
    total = failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for corpus in corpora:
            checks, bad = check(corpus, work)
            total += checks
            failures += bad
    print(f"{total} translation(s) run against the executor beside them, "
          f"{failures} disagreeing")
    return 1 if failures or not total else 0


if __name__ == "__main__":
    raise SystemExit(main())
