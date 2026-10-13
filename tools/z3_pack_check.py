#!/usr/bin/env python3
"""The solver library hands back the term the executor computes. Gate.

`libaxis_z3_<name>` binds `emit-smt2`'s proven definitions into a caller's Z3
context and applies them to the caller's own terms. The semantics are not this
library's -- that file's gates prove them against the golden model -- so what
is left to check is everything AROUND them, and all of it can be wrong
quietly: which function a mnemonic names, what order its operands are in, what
sorts they have, and whether `apply` substitutes into the right places.

⚠️ So the check is a differential, not a proof. Apply each instruction to
CONCRETE bit-vector terms, ask the solver to simplify the result to a number,
and compare that number against the pack's executor running the same
instruction with the same operand values. An operand order that is wrong by
two positions produces a perfectly well-formed term, and only a comparison
against something that runs can see it.

Usage: tools/z3_pack_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

HARNESS = r"""
/* The pack's solver terms against the pack's executor, in one process. */
#include <stdio.h>
#include <string.h>
#include <z3.h>
#include "axis_pack.h"
#include "axis_lift.h"
#include "axis_semantics.h"
#include "axis_exec.h"

extern const axis_z3_pack *%(z3)s(void);
extern const axis_exec_pack *%(exec)s(void);
extern const axis_lift_pack *%(lift)s(void);

#define SLOTS 256
#define CASES 4

static uint8_t MEM[8192];
/* What the executor's own hooks saw, so a store's terms have something to be
   right about. */
static struct { uint64_t addr, value; uint32_t width; } WROTE[8];
static int32_t wrote_count = 0;
static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MEM[(a + i) %% sizeof MEM] << (8 * i);
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  if (wrote_count < 8) {
    WROTE[wrote_count].addr = a; WROTE[wrote_count].value = v;
    WROTE[wrote_count].width = w; wrote_count++;
  }
  for (uint32_t i = 0; i < w / 8; ++i) MEM[(a + i) %% sizeof MEM] = (uint8_t)(v >> (8 * i));
}

static const struct { uint32_t word; const char *isa; const char *mnemonic; } WORDS[] = {
  %(words)s
};
static const int32_t WORD_COUNT = %(count)d;

/* Bind one term's parameters by name, the way the value pass does: an
   operand's value, a state slot, the pc, or an operand's value on entry. */
static int bind_term(const axis_z3_pack *Z, const axis_exec_pack *X,
                     const axis_lift_pack *L, void *handle, int32_t term,
                     const axis_pack_lifted *lifted, const uint64_t *regs,
                     uint64_t pc, Z3_context ctx, Z3_ast *operands) {
  int32_t arity = Z->arity(handle, term);
  for (int32_t k = 0; k < arity; ++k) {
    const char *want = Z->operand_name(handle, term, k);
    uint32_t wide = Z->operand_bits(handle, term, k);
    if (!want || wide > 64u) { return -1; }
    uint64_t value = 0;
    int found = 0;
    const char *entry = strncmp(want, "__input_", 8) ? want : want + 8;
    for (int32_t o = 0; o < lifted->operand_count && !found; ++o) {
      const char *name = L->operand_name(lifted->index, o);
      if (!name || strcmp(name, entry) || !lifted->operand_valid[o]) { continue; }
      const char *kind = L->operand_kind(lifted->index, o);
      if (kind && !strcmp(kind, "imm")) { value = (uint64_t)lifted->operands[o]; }
      else {
        uint32_t slot = L->register_slot(lifted->index, o, lifted->operands[o]);
        value = slot < SLOTS ? regs[slot] : 0u;
      }
      found = 1;
    }
    if (!found && !strcmp(want, "pc")) { value = pc; found = 1; }
    for (int32_t st = 0; st < X->state_slots() && !found; ++st) {
      const char *name = X->state_name(st);
      if (name && !strcmp(name, want)) { value = 0u; found = 1; }
    }
    if (!found) { return -1; }
    operands[k] = Z3_mk_unsigned_int64(ctx, value, Z3_mk_bv_sort(ctx, wide));
  }
  return arity;
}

/* One term, applied and folded to a number. */
static int fold_term(const axis_z3_pack *Z, void *handle, int32_t term,
                     Z3_context ctx, Z3_ast *operands, int32_t arity,
                     uint64_t *answer) {
  Z3_ast built = (Z3_ast)Z->apply(handle, term, (void *const *)operands, arity);
  if (!built) { return 0; }
  Z3_ast folded = Z3_simplify(ctx, built);
  return Z3_get_numeral_uint64(ctx, folded, (unsigned long long *)answer);
}

int main(void) {
  const axis_z3_pack *Z = %(z3)s();
  const axis_exec_pack *X = %(exec)s();
  const axis_lift_pack *L = %(lift)s();
  Z3_config config = Z3_mk_config();
  Z3_context ctx = Z3_mk_context(config);
  Z3_del_config(config);
  void *handle = Z->open(ctx);
  if (!handle) { printf("NOHANDLE\n"); return 0; }
  printf("BOUND %%d %%s\n", Z->count(handle), Z->solver);

  int32_t asked = 0, wrong = 0, unnamed = 0, unmatched = 0;
  for (int32_t w = 0; w < WORD_COUNT; ++w) {
    int32_t index = Z->index_of(handle, WORDS[w].mnemonic);
    if (index < 0) { unnamed++; continue; }
    /* ⚠️ An instruction is not one term. This is its VALUE; its effects are
       checked further down, each part its own term. */
    int32_t index_term = Z->value_term(handle, index);
    if (index_term < 0) { unnamed++; continue; }
    axis_pack_lifted lifted;
    if (!L->lift(WORDS[w].word, WORDS[w].isa[0] ? WORDS[w].isa : NULL, &lifted)
        || lifted.index < 0) { unmatched++; continue; }
    int32_t arity = Z->arity(handle, index_term);

    for (int32_t c = 0; c < CASES; ++c) {
      /* The operand VALUES the executor will see: a register's contents for a
         register operand, the field itself for an immediate. */
      uint64_t regs[SLOTS];
      for (int32_t i = 0; i < SLOTS; ++i) {
        regs[i] = 0x2468u * (uint64_t)(i + 1) + 0x9e3779b9u * (uint64_t)(c + 1);
      }
      /* ⚠️ Bound BY NAME, and each parameter can be either kind. An
         instruction's SMT function takes its operands and any architectural
         state it reads -- `csrrw.frm` takes `rs1` and `frm` -- and binding by
         position handed a register's contents to a rounding mode. */
      /* ⚠️ An operand can be wider than a slot: a vector register is two of
         them, low limb first, which is how the file stores it. Passing one
         slot into a 128-bit sort zero-extended it and the top half of every
         vector answer came out zero. */
      uint64_t values[16][AXIS_PACK_MAX_LIMBS];
      uint32_t taken[16];
      int ok = 1;
      for (int32_t k = 0; k < arity && ok; ++k) {
        const char *want = Z->operand_name(handle, index_term, k);
        if (!want) { ok = 0; break; }
        ok = 0;
        for (int32_t o = 0; o < lifted.operand_count; ++o) {
          const char *name = L->operand_name(lifted.index, o);
          if (!name || strcmp(name, want) || !lifted.operand_valid[o]) { continue; }
          const char *kind = L->operand_kind(lifted.index, o);
          uint32_t wide = Z->operand_bits(handle, index_term, k);
          taken[k] = wide > 64u ? (wide + 63u) / 64u : 1u;
          if (taken[k] > AXIS_PACK_MAX_LIMBS) { break; }
          for (uint32_t limb = 0; limb < taken[k]; ++limb) { values[k][limb] = 0u; }
          if (kind && !strcmp(kind, "imm")) {
            values[k][0] = (uint64_t)lifted.operands[o];
          } else {
            /* ⚠️ The SLOT, not the field. A compressed register field's 1 is
               `x9`, and reading the file with the field is a wrong answer
               that looks like arithmetic. */
            uint32_t slot = L->register_slot(lifted.index, o, lifted.operands[o]);
            for (uint32_t limb = 0; limb < taken[k]; ++limb) {
              values[k][limb] = (slot + limb) < SLOTS ? regs[slot + limb] : 0u;
            }
          }
          ok = 1; break;
        }
        for (int32_t st = 0; st < X->state_slots() && !ok; ++st) {
          const char *name = X->state_name(st);
          if (name && !strcmp(name, want)) {
            taken[k] = 1; values[k][0] = 0u; ok = 1;
          }
        }
      }
      if (!ok) { unmatched++; break; }

      /* The term, applied to those values as constants. */
      Z3_ast operands[16];
      for (int32_t k = 0; k < arity; ++k) {
        uint32_t wide = Z->operand_bits(handle, index_term, k);
        if (wide <= 64u) {
          operands[k] = Z3_mk_unsigned_int64(ctx, values[k][0], Z3_mk_bv_sort(ctx, wide));
          continue;
        }
        /* High limb first, as `concat` reads: the file keeps them low first. */
        Z3_ast built = NULL;
        for (uint32_t limb = 0; limb < taken[k]; ++limb) {
          uint32_t here = wide - limb * 64u;
          if (here > 64u) { here = 64u; }
          Z3_ast piece = Z3_mk_unsigned_int64(ctx, values[k][limb],
                                              Z3_mk_bv_sort(ctx, here));
          built = built ? Z3_mk_concat(ctx, piece, built) : piece;
        }
        operands[k] = built;
      }
      /* ⚠️ The TERM, not the instruction. They are different indices now that
         an instruction has a value and a list of effects, and passing one for
         the other applied some other instruction's term -- which folds to a
         number, looks like arithmetic, and disagrees. */
      Z3_ast term = (Z3_ast)Z->apply(handle, index_term, (void *const *)operands, arity);
      if (!term) { printf("DIFF %%s: apply refused %%d operand(s)\n",
                          WORDS[w].mnemonic, arity); wrong++; break; }
      /* ⚠️ A value can be wider than a word -- a vector register is 128 bits
         -- and the executor reports those as limbs. Folding the whole term to
         one `uint64` silently dropped the top half and compared the wrong
         number against the wrong one. Each limb is extracted and folded on its
         own. */
      uint32_t bits = Z->value_bits(handle, index_term);
      uint32_t limbs = bits > 64u ? (bits + 63u) / 64u : 1u;
      uint64_t theirs[AXIS_PACK_MAX_LIMBS];
      int folded_all = 1;
      for (uint32_t limb = 0; limb < limbs && limb < AXIS_PACK_MAX_LIMBS; ++limb) {
        uint32_t high = (limb + 1u) * 64u - 1u;
        if (high >= bits) { high = bits - 1u; }
        Z3_ast piece = bits > 64u
            ? Z3_simplify(ctx, Z3_mk_extract(ctx, high, limb * 64u, term))
            : Z3_simplify(ctx, term);
        if (!Z3_get_numeral_uint64(ctx, piece, (unsigned long long *)&theirs[limb])) {
          folded_all = 0;
          break;
        }
      }
      if (!folded_all) {
        printf("DIFF %%s: a term did not fold to a number\n", WORDS[w].mnemonic);
        wrong++; break;
      }

      /* And what the executor makes of the same instruction. */
      axis_pack_state_entry ps[64];
      int32_t ns = X->state_slots(); if (ns > 64) ns = 64;
      for (int32_t i = 0; i < ns; ++i) {
        ps[i].name = X->state_name(i); ps[i].value = 0; ps[i].width = X->state_width(i);
      }
      axis_pack_mem pm = { rd, wr, NULL };
      axis_pack_exec_result pr;
      X->step(WORDS[w].word, WORDS[w].isa[0] ? WORDS[w].isa : NULL, regs,
              X->register_slots(), &pm, 0x40u, ps, ns, &pr);
      if (!pr.ok || pr.trapped || !pr.wrote) { unmatched++; break; }
      asked++;
      uint64_t mask = bits >= 64 ? ~0ull : ((1ull << bits) - 1u);
      uint32_t reported = pr.result_limbs ? pr.result_limbs : 1u;
      int bad = 0;
      for (uint32_t limb = 0; limb < limbs && !bad; ++limb) {
        uint64_t mine = limb < reported
            ? (pr.result_limbs ? pr.result_limb[limb] : pr.result) : 0u;
        uint64_t his = theirs[limb] & (limb + 1u == limbs ? mask : ~0ull);
        if (limb + 1u != limbs) { his = theirs[limb]; }
        if (mine != his) {
          if (wrong < 6) {
            printf("DIFF %%s limb %%u: solver %%#llx, executor %%#llx\n",
                   WORDS[w].mnemonic, limb, (unsigned long long)his,
                   (unsigned long long)mine);
          }
          bad = 1;
        }
      }
      if (bad) { wrong++; break; }
    }
  }
  /* ⚠️ And the EFFECTS, which are the point. A branch's condition and target,
     a store's address and value: none of them is the instruction's value, and
     a symbolic engine needs them more than it needs the arithmetic. Each is
     checked against what the machine did with the same operands. */
  int32_t parts = 0, part_wrong = 0, guarded = 0, untestable = 0;
  int32_t shadowed_count = 0, termless = 0, later = 0, multi = 0;
  for (int32_t w = 0; w < WORD_COUNT; ++w) {
    int32_t index = Z->index_of(handle, WORDS[w].mnemonic);
    if (index < 0 || Z->effect_count(handle, index) < 1) { continue; }
    axis_pack_lifted lifted;
    if (!L->lift(WORDS[w].word, WORDS[w].isa[0] ? WORDS[w].isa : NULL, &lifted)
        || lifted.index < 0) { continue; }

   /* ⚠️ Twice: once with the registers all different, once with them all
      holding one value. A borrow out of a subtract differs from no borrow
      only when the two operands are EQUAL -- `bvuge` could be `bvugt` and
      nothing noticed, because a fixture names `rn` and `rm` and they never
      held the same number. */
   for (int32_t round = 0; round < 2; ++round) {
    uint64_t regs[SLOTS];
    for (int32_t i = 0; i < SLOTS; ++i) {
      regs[i] = 0x2468u * (uint64_t)(i + 1) + 0x1234u;
      /* Small and aligned, so a store's address lands in the harness's memory
         and the executor's own hooks can report where it went. */
      if (i < 64) { regs[i] = (uint64_t)((i * 16) & 0x7F8); }
      /* ⚠️ And some that CARRY. A flag word's C and V bits are what an
         operation carried out of itself, and values in the middle of the
         range never do: `bvult result lhs` could be `bvule` and every answer
         still matched. The high slots hold all-ones, the sign bit, and their
         neighbours. */
      /* ⚠️ In the LOW slots, where the fixtures actually look. A fixture names
         register 1 or 2, so edge values parked in the high ones were never
         read and the carry stayed untested. The executor's memory hooks wrap,
         so a wild address here costs nothing. */
      if (i < 8) {
        /* ⚠️ Values a 32-bit register file can hold. Seeding 2**63 into
           RV32I's `x1` is not a hard case, it is an illegal one: the executor
           reads the slot whole and the term truncates to the operand's sort,
           and they disagree about a machine state that cannot arise. These
           still carry and overflow at 32 bits, which is where the flag words
           of both machines are exercised. */
        static const uint64_t EDGES[] = {
          0xFFFFFFFFull, 0xFFFFFFFEull, 0x80000000ull, 0x7FFFFFFFull,
          0u, 1u, 0xFFFFull, 0x8000ull,
        };
        regs[i] = EDGES[i %% 8];
      }
      if (round) { regs[i] = 0x80000000ull; }
    }
    axis_pack_state_entry ps[64];
    int32_t ns = X->state_slots(); if (ns > 64) ns = 64;
    for (int32_t i = 0; i < ns; ++i) {
      ps[i].name = X->state_name(i); ps[i].value = 0; ps[i].width = X->state_width(i);
    }
    axis_pack_mem pm = { rd, wr, NULL };
    axis_pack_exec_result pr;
    wrote_count = 0;
    uint64_t pc = 0x40u;
    /* ⚠️ A snapshot, because `step` writes into the array it is given. Binding
       a term's operands from the registers AFTER it ran fed a post-indexed
       store the base it had just updated -- an address off by the very
       increment the instruction makes. Reads before writes, again. */
    uint64_t before[SLOTS];
    memcpy(before, regs, sizeof before);
    X->step(WORDS[w].word, WORDS[w].isa[0] ? WORDS[w].isa : NULL, regs,
            X->register_slots(), &pm, pc, ps, ns, &pr);
    if (!pr.ok || pr.trapped) { continue; }

    if (Z->effect_count(handle, index) > 1) { multi++; }
    /* ⚠️ The directory, checked against the file's own naming. A term for
       effect 2's value is called `axis_effect_<name>_2_value`, so a directory
       that handed out effect 0's parts for every effect -- which every
       individual part then passes, because each is right about ITS effect --
       says so in the name. */
    char ident[96];
    size_t at = 0;
    for (const char *c = WORDS[w].mnemonic; *c && at + 1 < sizeof ident; ++c) {
      char lower = (*c >= 'A' && *c <= 'Z') ? (char)(*c - 'A' + 'a') : *c;
      ident[at++] = (lower >= 'a' && lower <= 'z') || (lower >= '0' && lower <= '9')
          ? lower : '_';
    }
    ident[at] = 0;
    for (int32_t e = 0; e < Z->effect_count(handle, index); ++e) {
      static const char *const PARTS[] = { "guard", "addr", "value" };
      for (int32_t part = 0; part < 3; ++part) {
        int32_t t = Z->effect_term(handle, index, e, PARTS[part]);
        if (t < 0) { continue; }
        char expected[160], instead[160];
        snprintf(expected, sizeof expected, "axis_effect_%%s_%%d_%%s", ident, e,
                 PARTS[part]);
        /* An effect whose value IS the instruction's value points at that
           function rather than at a second name for the same term. */
        snprintf(instead, sizeof instead, "axis_instr_%%s", ident);
        const char *have = Z->term_name(handle, t);
        if (!have || (strcmp(have, expected) && strcmp(have, instead))) {
          if (part_wrong < 6) {
            printf("DIFFEFFECT %%s: effect %%d's %%s is term `%%s`, which is "
                   "named for something else\n", WORDS[w].mnemonic, e,
                   PARTS[part], have ? have : "(none)");
          }
          part_wrong++;
        }
      }
    }
    for (int32_t e = 0; e < Z->effect_count(handle, index); ++e) {
      const char *kind = Z->effect_kind(handle, index, e);
      /* ⚠️ Effects are SEQUENTIAL: each sees the operands as the ones before
         it left them. This harness binds the values the instruction started
         with, which is right until an earlier effect has written one of them
         -- `amoxor.w` stores `rd ^ rs2` where `rd` is what the load just put
         there. Those are counted rather than compared against the wrong
         state, which is what binding the post-state did: it fixed the atomics
         and broke every writeback form instead. */
      int shadowed = 0;
      for (int32_t before_e = 0; before_e < e && !shadowed; ++before_e) {
        const char *written = Z->effect_place(handle, index, before_e);
        if (!written) { continue; }
        for (int32_t part = 0; part < 3 && !shadowed; ++part) {
          static const char *const PARTS[] = { "guard", "addr", "value" };
          int32_t t = Z->effect_term(handle, index, e, PARTS[part]);
          if (t < 0) { continue; }
          for (int32_t k = 0; k < Z->arity(handle, t) && !shadowed; ++k) {
            const char *name = Z->operand_name(handle, t, k);
            if (name && !strcmp(name, written)) { shadowed = 1; }
          }
        }
      }
      if (shadowed) { shadowed_count++; continue; }
      int32_t guard = Z->effect_term(handle, index, e, "guard");
      int32_t addr = Z->effect_term(handle, index, e, "addr");
      int32_t value = Z->effect_term(handle, index, e, "value");
      Z3_ast operands[16];
      /* A guard that folds to zero means this effect did not happen, and
         nothing about it is then checkable against a machine that did not do
         it. Counted, so a run that only ever saw guards fail says so. */
      if (guard >= 0) {
        int32_t arity = bind_term(Z, X, L, handle, guard, &lifted, before, pc, ctx, operands);
        uint64_t held = 0;
        if (arity < 0 || !fold_term(Z, handle, guard, ctx, operands, arity, &held)) {
          untestable++; continue;
        }
        guarded++;
        if (!held) { continue; }
      }
      if (!kind) { continue; }
      if (!strcmp(kind, "store")) {
        if (addr < 0 || value < 0) { termless++; continue; }
        if (wrote_count < 1) { untestable++; continue; }
        int32_t arity = bind_term(Z, X, L, handle, addr, &lifted, before, pc, ctx, operands);
        uint64_t where = 0;
        if (arity < 0 || !fold_term(Z, handle, addr, ctx, operands, arity, &where)) {
          untestable++; continue;
        }
        arity = bind_term(Z, X, L, handle, value, &lifted, before, pc, ctx, operands);
        uint64_t what = 0;
        if (arity < 0 || !fold_term(Z, handle, value, ctx, operands, arity, &what)) {
          untestable++; continue;
        }
        parts += 2;
        if (e > 0) { later++; }
        uint32_t bits = Z->value_bits(handle, value);
        uint64_t mask = bits >= 64 ? ~0ull : ((1ull << bits) - 1u);
        int matched = 0;
        for (int32_t k = 0; k < wrote_count; ++k) {
          if (WROTE[k].addr == where && (WROTE[k].value & mask) == (what & mask)) {
            matched = 1;
          }
        }
        if (!matched) {
          if (part_wrong < 6) {
            printf("DIFFEFFECT %%s store: terms say %%#llx <- %%#llx, machine wrote "
                   "%%#llx <- %%#llx\n", WORDS[w].mnemonic,
                   (unsigned long long)where, (unsigned long long)(what & mask),
                   (unsigned long long)(wrote_count ? WROTE[0].addr : 0),
                   (unsigned long long)(wrote_count ? WROTE[0].value : 0));
          }
          part_wrong++;
        }
      } else if (!strcmp(kind, "setpc")) {
        if (value < 0) { termless++; continue; }
        int32_t arity = bind_term(Z, X, L, handle, value, &lifted, before, pc, ctx, operands);
        uint64_t target = 0;
        if (arity < 0 || !fold_term(Z, handle, value, ctx, operands, arity, &target)) {
          untestable++; continue;
        }
        parts++;
        if (e > 0) { later++; }
        if (target != pr.next_pc) {
          if (part_wrong < 6) {
            printf("DIFFEFFECT %%s setpc: term says %%#llx, machine went to %%#llx\n",
                   WORDS[w].mnemonic, (unsigned long long)target,
                   (unsigned long long)pr.next_pc);
          }
          part_wrong++;
        }
      } else if (!strcmp(kind, "setstate")) {
        /* ⚠️ Architectural state, which is where AArch64's flag words land.
           Without this the helpers that compute them -- `a64_add_nzcv` and
           friends -- were rendered and never once compared against a machine
           that had run the instruction. */
        const char *place = Z->effect_place(handle, index, e);
        int32_t slot = -1;
        for (int32_t st = 0; st < ns && place; ++st) {
          const char *name = X->state_name(st);
          if (name && !strcmp(name, place)) { slot = st; }
        }
        if (value < 0) { termless++; continue; }
        if (slot < 0) { untestable++; continue; }
        int32_t arity = bind_term(Z, X, L, handle, value, &lifted, before, pc, ctx, operands);
        uint64_t wrote = 0;
        if (arity < 0 || !fold_term(Z, handle, value, ctx, operands, arity, &wrote)) {
          untestable++; continue;
        }
        parts++;
        if (e > 0) { later++; }
        uint32_t bits = ps[slot].width ? ps[slot].width : 64u;
        uint64_t mask = bits >= 64 ? ~0ull : ((1ull << bits) - 1u);
        if ((wrote & mask) != (ps[slot].value & mask)) {
          if (part_wrong < 6) {
            printf("DIFFEFFECT %%s state %%s: term says %%#llx, machine %%#llx\n",
                   WORDS[w].mnemonic, place, (unsigned long long)(wrote & mask),
                   (unsigned long long)(ps[slot].value & mask));
          }
          part_wrong++;
        }
      } else if (!strcmp(kind, "set")) {
        /* ⚠️ Only the write the executor REPORTS. A post-indexed load writes
           two registers -- the loaded value and the updated base -- and the
           result carries one of them; comparing the other against it is
           comparing two different writes. The effect says which operand it
           lands in, so the two can be matched by slot. */
        const char *place = Z->effect_place(handle, index, e);
        int32_t slot = -1;
        for (int32_t o = 0; o < lifted.operand_count && place; ++o) {
          const char *name = L->operand_name(lifted.index, o);
          if (name && !strcmp(name, place) && lifted.operand_valid[o]) {
            slot = (int32_t)L->register_slot(lifted.index, o, lifted.operands[o]);
          }
        }
        if (value < 0) { termless++; continue; }
        if (!pr.wrote || slot < 0 || slot != (int32_t)pr.dest_slot) {
          untestable++; continue;
        }
        int32_t arity = bind_term(Z, X, L, handle, value, &lifted, before, pc, ctx, operands);
        uint64_t written = 0;
        if (arity < 0 || !fold_term(Z, handle, value, ctx, operands, arity, &written)) {
          untestable++; continue;
        }
        parts++;
        if (e > 0) { later++; }
        uint32_t bits = Z->value_bits(handle, value);
        uint64_t mask = bits >= 64 ? ~0ull : ((1ull << bits) - 1u);
        if ((written & mask) != (pr.result & mask)) {
          if (part_wrong < 6) {
            printf("DIFFEFFECT %%s set: term says %%#llx, machine wrote %%#llx\n",
                   WORDS[w].mnemonic, (unsigned long long)(written & mask),
                   (unsigned long long)(pr.result & mask));
          }
          part_wrong++;
        }
      }
    }
   }
  }
  printf("EFFECTS %%d %%d %%d %%d %%d %%d %%d %%d\n", parts, part_wrong, guarded,
         untestable, shadowed_count, termless, later, multi);

  /* ⚠️ What it does with a question it should refuse. `apply` promises NULL
     for a wrong arity or a mismatched sort -- never a term that means
     something else -- and nothing exercised that while every call was
     well-formed. `Z3_substitute` does not refuse; it hands back a term in an
     error state that a caller would carry into a solver. */
  int32_t refusals = 0, accepted = 0;
  for (int32_t i = 0; i < Z->count(handle) && i < 32; ++i) {
    int32_t arity = Z->arity(handle, i);
    if (arity < 1) { continue; }
    Z3_ast wrong_sort[16];
    for (int32_t k = 0; k < arity; ++k) {
      uint32_t bits = Z->operand_bits(handle, i, k);
      /* One bit wider than asked for, which is a different sort. */
      wrong_sort[k] = Z3_mk_unsigned_int64(ctx, 1u, Z3_mk_bv_sort(ctx, bits + 1u));
    }
    if (Z->apply(handle, i, (void *const *)wrong_sort, arity)) { accepted++; }
    else { refusals++; }
    if (Z->apply(handle, i, (void *const *)wrong_sort, arity - 1)) { accepted++; }
    else { refusals++; }
  }
  printf("REFUSED %%d %%d\n", refusals, accepted);
  printf("ASKED %%d %%d %%d %%d\n", asked, wrong, unnamed, unmatched);
  Z->close(handle);
  Z3_del_context(ctx);
  return 0;
}
"""


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs")
    name = manifest["name"]
    if "z3" not in manifest["libraries"]:
        print(f"  {name}: no solver library -- "
              f"{manifest['declined'].get('z3', 'not built')}")
        return 0, 0
    tests = json.loads(run([*axis_prefix(), "emit-roundtrip-json",
                            str(axis_file)]).stdout)["tests"]
    rows = ",\n  ".join(
        f'{{ {int(t["encoded"], 16)}u, "{t.get("isa", "")}", "{t["mnemonic"]}" }}'
        for t in tests)
    source = HARNESS % {
        "z3": manifest["libraries"]["z3"]["entry"],
        "exec": manifest["libraries"]["exec"]["entry"],
        "lift": manifest["libraries"]["lift"]["entry"],
        "words": rows,
        "count": len(tests),
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    headers, libraries_at = build_pack.solver_paths()
    run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-I", str(headers),
         "-o", str(work / name), str(work / f"{name}.c"),
         *(str(root / "lib" / manifest["libraries"][f]["static"])
           for f in ("z3", "exec", "lift")),
         f"-L{libraries_at}", "-lz3"])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode < 0:
        print(f"  FAIL {name}: the harness died on signal {-done.returncode}")
        return 0, 1
    checks = failures = 0
    for line in done.stdout.splitlines():
        if line.startswith(("DIFF", "NOHANDLE")):
            print(f"  FAIL {name}: {line}")
            failures += 1
        elif line.startswith("BOUND "):
            bound, solver = line.split()[1:]
            print(f"  {name}: {bound} instruction(s) bound into {solver}")
        elif line.startswith("EFFECTS "):
            (parts, bad, guarded, untestable, shadowed, termless,
             later, multi) = (int(x) for x in line.split()[1:])
            checks += parts
            failures += bad
            print(f"  {name}: {parts} effect part(s) folded and matched against the "
                  f"machine, {bad} wrong; {guarded} guard(s) decided it")
            print(f"    {termless} part(s) the SMT backend declines, {shadowed} an "
                  f"earlier effect in the same instruction shadows, {untestable} "
                  f"the executor reports nothing about")
            print(f"    {later} of them belonged to an effect after the first, "
                  f"across {multi} instruction(s) that have more than one")
            # ⚠️ An instruction's SECOND effect is where the directory can be
            # wrong without anything noticing: pointing every part at effect 0
            # passed while only single-effect instructions were checked.
            if multi and not later:
                print(f"  FAIL {name}: nothing checked an effect after the first")
                failures += 1
            # ⚠️ A run with no effect parts is a run that checked the arithmetic
            # and none of what an instruction DOES.
            if not parts:
                print(f"  FAIL {name}: not one effect part was checked")
                failures += 1
        elif line.startswith("REFUSED "):
            refused, accepted = (int(x) for x in line.split()[1:])
            print(f"  {name}: {refused} ill-formed call(s) refused, {accepted} taken")
            if accepted:
                print(f"  FAIL {name}: it took a call it promises to refuse")
                failures += accepted
            if not refused:
                print(f"  FAIL {name}: nothing tried an ill-formed call")
                failures += 1
        elif line.startswith("ASKED "):
            asked, wrong, unnamed, unmatched = (int(x) for x in line.split()[1:])
            checks += asked
            failures += wrong
            print(f"  {name}: {asked} term(s) folded and matched against the "
                  f"executor, {wrong} wrong; {unnamed} the SMT backend declines, "
                  f"{unmatched} whose operands do not line up")
    if not checks:
        print(f"  FAIL {name}: nothing was asked")
        failures += 1
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "rv64i.axisl"]
    if build_pack.solver_paths() is None:
        print("no solver on this host: SKIP")
        return DECLINED
    total = failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for corpus in corpora:
            checks, bad = check(corpus, work)
            total += checks
            failures += bad
    print(f"{total} proven term(s) applied through the library and checked "
          f"against the executor, {failures} disagreeing")
    # ⚠️ A failure is never a SKIP. A mutation that made every question
    # unanswerable reported "nothing was asked" and returned DECLINED, which
    # the ladder reads as a corpus with nothing to say rather than a broken
    # library.
    if not total and not failures:
        print("solver terms == executor: SKIP")
        return DECLINED
    print("solver terms == executor:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
