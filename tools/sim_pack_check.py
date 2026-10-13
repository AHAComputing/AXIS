#!/usr/bin/env python3
"""The simulator library runs a program; the executor beside it agrees. Gate.

The six libraries before this one answer questions about an instruction. This
one RUNS: it fetches from the host, decides what a trap does, and reports what
each instruction did. So the property is not "one word came out right" but "the
machine went where the architecture says, for as long as it ran".

⚠️ The reference is the pack's own executor, stepping the same words the
simulator fetched, in the same order, from the same registers. The ladder
already holds `emit-sim-c` to the executor; this holds the LIBRARY to it,
through the contract a consumer actually links -- which is a different claim,
because everything between them is adapter code: an opaque machine the library
allocates, five hooks in the host's direction, and an event copied field by
field into the contract's shape.

What is compared, per instruction: the pc it was fetched from, the mnemonic it
decoded to, where it went next, whether it wrote and what -- and, at the end of
the run, every register, every state slot, and the bytes of memory.

Usage: tools/sim_pack_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
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

#: Where the program sits.
#:
#: ⚠️ Above every address the seeded registers can compute. A register seeded
#: `0x1111 * (i + 1)` reaches about 0x40000 -- wrapped into a 64K image, any of
#: it -- so a loop of stores at 0x100 eventually overwrites its own code. The
#: interpreter re-decodes and halts on the corrupted word; a translated block
#: was built once and keeps running the program that used to be there. That
#: divergence is real, and it is the self-modifying-code limit written down in
#: this file rather than a gate finding: a gate that tests it by accident is
#: testing whether the JIT invalidates, which it does not claim to.
CODE = 0x8000
LENGTH = 24

HARNESS = r"""
/* The pack's simulator against the pack's executor, in one process. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "axis_pack.h"
#include "axis_lift.h"
#include "axis_semantics.h"
#include "axis_exec.h"

extern const axis_sim_pack *%(sim)s(void);
extern const axis_exec_pack *%(exec)s(void);
extern const axis_jit_pack *%(jit)s(void);

#define SLOTS 256
#define IMAGE (1 << 16)
/* ⚠️ Addresses a store can reach, kept well below the code. A register seeded
   `0x1111 * (i + 1)` spans the whole image, so a loop of stores eventually
   overwrites the program -- and then the interpreter re-decodes and halts on
   the corrupted word while a translated block, built once, keeps running the
   program that used to be there. That divergence is real and is the
   self-modifying-code limit, which this gate does not claim to test: it is
   here to compare two engines on the same program, and a program that rewrites
   itself is not one of those. Twelve bits of data, a 12-bit immediate of
   headroom, and the code at 0x8000. */
/* ⚠️ The window a DATA access lands in, and it is below the code. A guest can
   reach its own text -- `adrp` builds an address out of the pc, so no seeding
   keeps a store away from it -- and then the interpreter re-decodes the changed
   word while a translated block, built once from the old bytes, keeps running
   the program that used to be there. Both engines are right, about different
   programs.
   The window is the same one translated code is given, so the two mask
   identically; the code sits above it and no store can name it. The
   self-modifying case is a real limit, written down in `docs/jit_stencils.md`
   rather than tripped over here. */
#define DATA (1 << 14)
#define AXIS_SEED(i) (uint64_t)((0x1111u * ((uint64_t)(i) + 1)) & 0x0FFFu)
/* ⚠️ Every retire event of the run, not a prefix of it. The executor replays
   what this holds and the FINAL register files are then compared -- so a run
   longer than the trace compares a simulator that took a thousand steps
   against an executor that took two hundred and fifty-six, and reports the
   difference as a disagreement. The two numbers are one number, and the
   assertion below says so. */
#define TRACE 4096

static const axis_sim_pack *S;
static const axis_exec_pack *X;

static uint8_t MEMORY[IMAGE];      /* the simulator's */
static uint8_t MIRROR[IMAGE];      /* the executor's, seeded the same */

static const uint32_t PROGRAM[] = { %(program)s };
static const int32_t PROGRAM_LEN = %(length)d;
static const char *ISA = %(isa)s;

/* What the simulator reported, in order. */
static struct { uint64_t pc; uint32_t word; const char *mnemonic;
                uint64_t next_pc; int32_t wrote; uint32_t slot;
                uint64_t result; const char *trap; int32_t accesses;
                int32_t reads; } SEEN[TRACE];
static int32_t seen_count = 0;

static uint64_t sim_read(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MEMORY[(a + i) & (DATA - 1u)] << (8 * i);
  return v;
}
static void sim_write(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) MEMORY[(a + i) & (DATA - 1u)] = (uint8_t)(v >> (8 * i));
}
/* ⚠️ Fetch is not read. The host serves instructions from the image and
   refuses anything outside the program, which is what ends the run. */
static uint32_t sim_fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c;
  if (pc < %(code)du || pc >= %(code)du + 4u * (uint64_t)PROGRAM_LEN) {
    if (ok) { *ok = 0; }
    return 0u;
  }
  if (ok) { *ok = 1; }
  uint32_t word = 0;
  for (uint32_t i = 0; i < 4; ++i) word |= (uint32_t)MEMORY[(pc + i) %% IMAGE] << (8 * i);
  return word;
}
static uint64_t sim_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause;
  if (stop) { *stop = 1; }     /* this host stops on a trap, and says so */
  return pc;
}
static void sim_retire(void *c, const axis_pack_sim_event *e) {
  (void)c;
  if (seen_count >= TRACE) { return; }
  SEEN[seen_count].pc = e->pc; SEEN[seen_count].word = e->word;
  SEEN[seen_count].mnemonic = e->mnemonic; SEEN[seen_count].next_pc = e->next_pc;
  SEEN[seen_count].wrote = e->wrote; SEEN[seen_count].slot = e->write_slot;
  SEEN[seen_count].result = e->result; SEEN[seen_count].trap = e->trap_cause;
  SEEN[seen_count].accesses = e->access_count; SEEN[seen_count].reads = e->read_count;
  seen_count++;
}

/* ⚠️ The SAME window as the simulator's `sim_read` and `sim_write`. These
   wrapped at IMAGE while those masked to DATA, and every corpus kept its
   addresses under 16 KiB until one whose programs are only adds and
   loads-and-stores walked a pointer past it: the simulator stored at 0x2058,
   the executor at 0x6058, and the gate reported the untouched seed byte as a
   disagreement between two engines that had agreed. */
static uint64_t mirror_read(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MIRROR[(a + i) & (DATA - 1u)] << (8 * i);
  return v;
}
static void mirror_write(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) MIRROR[(a + i) & (DATA - 1u)] = (uint8_t)(v >> (8 * i));
}

int main(void) {
  S = %(sim)s(); X = %(exec)s();
  int32_t slots = S->register_slots();
  if (slots > SLOTS) { slots = SLOTS; }
  if (slots != X->register_slots()) {
    printf("DISAGREE slots %%d != %%d\n", slots, X->register_slots()); return 0;
  }
  int32_t ns = S->state_slots();
  if (ns != X->state_slots()) { printf("DISAGREE state %%d != %%d\n", ns, X->state_slots()); return 0; }
  for (int32_t i = 0; i < ns; ++i) {
    const char *a = S->state_name(i), *b = X->state_name(i);
    if (!a || !b || strcmp(a, b)) { printf("DISAGREE state name %%d\n", i); return 0; }
  }
  printf("SLOTS %%d %%d\n", slots, ns);

  for (size_t i = 0; i < IMAGE; ++i) MEMORY[i] = MIRROR[i] = (uint8_t)((i * 11 + 3) & 0xFF);
  /* ⚠️ A pristine copy. Both reference runs WRITE to their memories, so
     restoring a later run from either of them starts it where the last one
     finished -- which showed up as a byte neither engine had touched. */
  static uint8_t INITIAL[IMAGE];
  for (int32_t i = 0; i < PROGRAM_LEN; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(code)d + 4 * i + b] = MIRROR[%(code)d + 4 * i + b] =
          (uint8_t)(PROGRAM[i] >> (8 * b));
    }
  }

  memcpy(INITIAL, MEMORY, sizeof INITIAL);
  axis_pack_state_entry state[64];
  for (int32_t i = 0; i < ns && i < 64; ++i) {
    state[i].name = S->state_name(i); state[i].width = S->state_width(i);
    state[i].value = (uint64_t)(i + 1);
  }

  axis_pack_sim_hooks hooks = { sim_read, sim_write, sim_fetch, sim_trap,
                                sim_retire, NULL };
  void *machine = S->create(&hooks);
  if (!machine) { printf("NOMACHINE\n"); return 0; }
  S->reset(machine, %(code)du, ISA, state, ns);
  for (int32_t i = 0; i < slots; ++i) {
    S->set_reg(machine, i, AXIS_SEED(i));
  }
  int32_t status = S->run(machine, TRACE / 2);
  printf("RAN %%llu %%d %%s\n", (unsigned long long)S->steps(machine), status,
         S->halt_reason(machine) ? S->halt_reason(machine) : "-");

  /* The reference: the executor, stepping what the simulator said it ran. */
  uint64_t regs[SLOTS];
  for (int32_t i = 0; i < slots; ++i) regs[i] = AXIS_SEED(i);
  axis_pack_state_entry mirror_state[64];
  for (int32_t i = 0; i < ns && i < 64; ++i) {
    mirror_state[i].name = X->state_name(i); mirror_state[i].width = X->state_width(i);
    mirror_state[i].value = (uint64_t)(i + 1);
  }
  axis_pack_mem pm = { mirror_read, mirror_write, NULL };
  int32_t wrong = 0;
  uint64_t pc = %(code)du;
  for (int32_t k = 0; k < seen_count; ++k) {
    if (SEEN[k].pc != pc) {
      printf("DIFF step %%d fetched %%#llx, executor at %%#llx\n", k,
             (unsigned long long)SEEN[k].pc, (unsigned long long)pc);
      wrong++; break;
    }
    axis_pack_exec_result pr;
    X->step(SEEN[k].word, ISA, regs, slots, &pm, pc, mirror_state, ns, &pr);
    if (SEEN[k].trap) {
      /* The host stopped it; the executor says the same instruction trapped. */
      if (!pr.trapped) { printf("DIFF step %%d trapped only in the simulator\n", k); wrong++; }
      break;
    }
    /* ⚠️ A word that decodes to nothing is where the run ENDS, and the two
       agreeing about that is the check rather than a failure: the simulator
       reports an event with no mnemonic, the executor refuses the same word.
       Only one of them saying so is the disagreement. */
    if (!SEEN[k].mnemonic || !pr.ok) {
      if ((SEEN[k].mnemonic != NULL) != (pr.ok != 0)) {
        printf("DIFF step %%d: simulator %%s, executor %%s\n", k,
               SEEN[k].mnemonic ? SEEN[k].mnemonic : "(undecoded)",
               pr.ok ? "ran it" : "refused it");
        wrong++;
      }
      break;
    }
    if (SEEN[k].wrote != pr.wrote || (pr.wrote && (SEEN[k].slot != pr.dest_slot
                                                   || SEEN[k].result != pr.result))) {
      printf("DIFF step %%d wrote %%d slot %%u value %%#llx, executor %%d %%u %%#llx\n",
             k, SEEN[k].wrote, SEEN[k].slot, (unsigned long long)SEEN[k].result,
             pr.wrote, pr.dest_slot, (unsigned long long)pr.result);
      wrong++; break;
    }
    if (SEEN[k].next_pc != pr.next_pc) {
      printf("DIFF step %%d goes to %%#llx, executor to %%#llx\n", k,
             (unsigned long long)SEEN[k].next_pc, (unsigned long long)pr.next_pc);
      wrong++; break;
    }
    pc = pr.next_pc;
  }

  int32_t decoded = 0, touched = 0, watched = 0;
  for (int32_t k = 0; k < seen_count; ++k) {
    decoded += SEEN[k].mnemonic != NULL;
    touched += SEEN[k].accesses > 0;
    watched += SEEN[k].reads > 0;
  }
  /* The trace is the whole run or the comparison below is not valid. */
  if (seen_count >= TRACE) { printf("DIFF the trace filled at %%d event(s)\n", TRACE); wrong++; }
  for (int32_t i = 0; i < slots && !wrong; ++i) {
    if (S->reg(machine, i) != regs[i]) {
      printf("DIFF register %%d: simulator %%#llx, executor %%#llx\n", i,
             (unsigned long long)S->reg(machine, i), (unsigned long long)regs[i]);
      wrong++;
    }
  }
  for (int32_t i = 0; i < ns && !wrong; ++i) {
    if (S->state_value(machine, i) != mirror_state[i].value) {
      printf("DIFF state %%s: simulator %%#llx, executor %%#llx\n", S->state_name(i),
             (unsigned long long)S->state_value(machine, i),
             (unsigned long long)mirror_state[i].value);
      wrong++;
    }
  }
  for (size_t i = 0; i < IMAGE && !wrong; ++i) {
    if (MEMORY[i] != MIRROR[i]) {
      printf("DIFF byte %%#zx: simulator %%#02x, executor %%#02x\n", i, MEMORY[i], MIRROR[i]);
      wrong++;
    }
  }
  printf("RETIRED %%d %%d %%d\n", seen_count, decoded, wrong);

  /* ⚠️ And the same program again, translated. The two engines share nothing
     but the description: one interprets, the other copies stencils and runs
     them. A host that turns translation on is promised the same machine, so
     what is compared is every register, every state slot, every byte of
     memory, and where it stopped. */
  const axis_jit_pack *J = %(jit)s();
  axis_pack_sim_hooks quiet = { sim_read, sim_write, sim_fetch, sim_trap,
                                NULL, NULL };
  void *fast = S->create(&quiet);
  int32_t translated_wrong = 0;
  uint64_t translated_count = 0, blocks = 0;
  if (!fast) { printf("NOFAST\\n"); return 0; }
  /* ⚠️ What the INTERPRETED simulator left, not what the executor left. The
     two references are not the same memory: the executor stepped the same
     words but the comparison here is between the two engines of one library.
     Comparing against the executor's copy reported a difference in a byte
     neither engine had touched. */
  static uint8_t INTERPRETED[IMAGE];
  memcpy(INTERPRETED, MEMORY, sizeof INTERPRETED);
  memcpy(MEMORY, INITIAL, sizeof MEMORY);
  axis_pack_state_entry fast_state[64];
  for (int32_t i = 0; i < ns && i < 64; ++i) {
    fast_state[i].name = S->state_name(i); fast_state[i].width = S->state_width(i);
    fast_state[i].value = (uint64_t)(i + 1);
  }
  S->reset(fast, %(code)du, ISA, fast_state, ns);
  for (int32_t i = 0; i < slots; ++i) {
    S->set_reg(fast, i, AXIS_SEED(i));
  }
  axis_sim_jit options = { 1, 16, (uint64_t)(uintptr_t)MEMORY, DATA };
  if (!S->jit(fast, J, &options)) {
    printf("NOJIT\\n");
  } else {
    int32_t fast_status = S->run(fast, TRACE / 2);
    translated_count = S->translated(fast);
    blocks = S->blocks_built(fast);
    if (fast_status != status) {
      printf("DIFF translated run stopped %%d, interpreted %%d\n", fast_status, status);
      translated_wrong++;
    }
    if (S->pc(fast) != S->pc(machine)) {
      printf("DIFF translated run ended at %%#llx, interpreted at %%#llx\n",
             (unsigned long long)S->pc(fast), (unsigned long long)S->pc(machine));
      translated_wrong++;
    }
    for (int32_t i = 0; i < slots && !translated_wrong; ++i) {
      if (S->reg(fast, i) != S->reg(machine, i)) {
        printf("DIFF translated register %%d: %%#llx, interpreted %%#llx\n", i,
               (unsigned long long)S->reg(fast, i),
               (unsigned long long)S->reg(machine, i));
        translated_wrong++;
      }
    }
    for (size_t i = 0; i < IMAGE && !translated_wrong; ++i) {
      if (MEMORY[i] != INTERPRETED[i]) {
        printf("DIFF translated byte %%#zx: %%#02x, interpreted %%#02x\n", i,
               MEMORY[i], INTERPRETED[i]);
        translated_wrong++;
      }
    }
  }
  /* How much of this program the translator could take at all, so "nothing
     was translated" can tell a JIT that did not fire from a corpus with
     nothing to fire on. */
  int32_t stencilled = 0;
  for (int32_t i = 0; i < PROGRAM_LEN; ++i) {
    axis_lifted probe;
    if (!axis_lift_in_isa(PROGRAM[i], ISA, &probe) || !probe.entry) { continue; }
    if (J->stencil_for(probe.entry->mnemonic) >= 0) { stencilled++; }
  }
  printf("TRANSLATED %%llu %%llu %%d %%d\n", (unsigned long long)translated_count,
         (unsigned long long)blocks, translated_wrong, stencilled);

  /* ⚠️ And what it cost. The whole argument for translating is that a block
     runs more than once; a gate that only proved the two agree would leave
     "fast" as an adjective. Both engines run the same loop for the same
     number of steps, from the same start. If translation is not faster, this
     prints that. */
  const uint64_t BUDGET = 200000;
  double slow_seconds = 0.0, fast_seconds = 0.0;
  uint64_t timed_translated = 0, timed_steps = 0, timed_blocks = 0;
  uint64_t timed_reached[2] = { 0, 0 };
  int32_t timed_halt[2] = { 0, 0 };
  uint64_t timed_pc[2] = { 0, 0 };
  for (int32_t pass = 0; pass < 2; ++pass) {
    void *one = S->create(&quiet);
    if (!one) { break; }
    memcpy(MEMORY, INITIAL, sizeof MEMORY);
    S->reset(one, %(code)du, ISA, fast_state, ns);
    for (int32_t i = 0; i < slots; ++i) { S->set_reg(one, i, AXIS_SEED(i)); }
    if (pass) { S->jit(one, J, &options); }
    struct timespec started, ended;
    clock_gettime(CLOCK_MONOTONIC, &started);
    S->run(one, BUDGET);
    clock_gettime(CLOCK_MONOTONIC, &ended);
    double seconds = (double)(ended.tv_sec - started.tv_sec)
                   + (double)(ended.tv_nsec - started.tv_nsec) / 1e9;
    /* ⚠️ Both passes' step counts, because the same program under the same
       budget must take the same number of steps whichever engine runs it. The
       timed runs are long and unchecked otherwise: the correctness run above
       compares states over a short limit, and a branch that goes somewhere
       else after ten thousand iterations would not appear in it. */
    timed_reached[pass] = S->steps(one);
    timed_halt[pass] = S->status(one);
    timed_pc[pass] = S->pc(one);
    if (pass) {
      fast_seconds = seconds;
      /* ⚠️ What the TIMED run translated. The correctness run above reports
         its own figure over a handful of steps, and a reader was left to
         assume the timed one looked like it -- so a speedup could be read as
         a fact about the translator when it was a fact about how much of
         this particular loop the translator took. */
      timed_translated = S->translated(one);
      timed_blocks = S->blocks_built(one);
      timed_steps = S->steps(one);
    } else { slow_seconds = seconds; }
    S->destroy(one);
  }
  printf("SPEED %%.6f %%.6f %%llu\n", slow_seconds, fast_seconds,
         (unsigned long long)BUDGET);
  printf("TIMEDMIX %%llu %%llu %%llu\n", (unsigned long long)timed_translated,
         (unsigned long long)timed_steps, (unsigned long long)timed_blocks);
  if (timed_reached[0] != timed_reached[1] || timed_halt[0] != timed_halt[1]) {
    printf("DIFFTIMED interpreted ran %%llu step(s) and stopped %%d, "
           "translated ran %%llu and stopped %%d (pc %%#llx vs %%#llx)\n",
           (unsigned long long)timed_reached[0], timed_halt[0],
           (unsigned long long)timed_reached[1], timed_halt[1],
           (unsigned long long)timed_pc[0], (unsigned long long)timed_pc[1]);
  }
  S->destroy(fast);
  /* ⚠️ What the run actually exercised. An event carries what an instruction
     touched -- the thing a timing model is here for -- and a gate that never
     ran one that touched memory would be testing a stepper. */
  printf("TOUCHED %%d %%d\n", touched, watched);
  S->destroy(machine);
  return 0;
}
"""


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def stencilled(table: Path) -> set[str]:
    """Which mnemonics the TRANSLATOR has a stencil for.

    ⚠️ From `axis_jit_table.h` -- the artifact the simulator itself consults --
    rather than from `emit-stencil-ll`. The two differ: the emitter writes a
    stencil, and the table then declines the ones whose relocations this
    patcher cannot apply. Reading the emitter's list made this gate name one
    instruction as breaking a loop that was really broken by twenty.
    """
    text = table.read_text()
    inside = text.split("AXIS_JIT_STENCILS[] = {", 1)
    if len(inside) < 2:
        return set()
    have = set()
    for line in inside[1].splitlines():
        line = line.strip()
        if line.startswith("};"):
            break
        if line.startswith('{ "'):
            have.add(line.split('"')[1])
    return have


def program(axis_file: Path, rng: random.Random,
            lift=None, golden=None, translatable=None) -> tuple[list[int], str]:
    """A program out of the corpus's own fixtures, ending in a branch BACK.

    ⚠️ The loop is the point. A straight-line program is a JIT's worst case:
    it pays for translation and then never runs the block again, so a gate
    built on one would be measuring the cost and none of the benefit. The
    last instruction is a taken backward branch, so the machine runs the same
    blocks until the step limit stops it -- which is what a JIT is for, and
    also what makes "the two engines agree" worth asserting over a long run
    rather than a short one.
    """
    tests = json.loads(run([*axis_prefix(), "emit-roundtrip-json",
                            str(axis_file)]).stdout)["tests"]
    # ⚠️ No branches in the BODY. A fixture branch jumps wherever its own
    # immediate says, which is usually out of a program this short -- and the
    # run then ends before the loop at the bottom is ever reached.
    straight = set()
    if lift is not None:
        for entry in lift.AXIS_LIFT_TABLE:
            # ⚠️ And nothing the executor will not run. An instruction that
            # names an implementation routine stops the machine dead -- the
            # run ended after nine instructions with `unimplemented`, and a
            # program that stops has no loop to be fast in.
            if entry.get("implementation"):
                continue
            if not any(effect["kind"] in ("setpc", "trap")
                       for effect in (entry.get("effects") or [])):
                straight.add(entry["mnemonic"])
    usable = [t for t in tests
              if int(t["encoded"], 16) >> 16
              and (not straight or t["mnemonic"] in straight)]
    # ⚠️ Instructions a stencil can carry, ASKED rather than guessed. This used
    # to be "no effects, or one unguarded register write", which was the
    # translator's limit at the time -- and stayed here after the translator
    # grew past it, so a gate measuring a JIT kept drawing its program from the
    # small corner the JIT had once been confined to. The artifact says which
    # instructions it has stencils for; reading that costs one emitter call and
    # cannot go stale.
    plain = {name for name in straight} & (translatable or straight)
    simple = [t for t in usable if t["mnemonic"] in plain]
    # ⚠️ The ISA is chosen FIRST, from whichever has the most to offer. Drawing
    # instructions and then keeping the ones that happened to share an ISA left
    # AArch64 with eight instructions out of twenty-four, three of them
    # translatable and none of them adjacent -- so no block could form and the
    # gate measured a JIT that never ran.
    counted: dict[str, int] = {}
    for test in simple or usable:
        counted[test.get("isa") or ""] = counted.get(test.get("isa") or "", 0) + 1
    isa = max(counted, key=counted.get) if counted else ""
    simple = [t for t in simple if (t.get("isa") or "") == isa]
    within = [t for t in usable if (t.get("isa") or "") == isa]
    chosen = [rng.choice(simple or within or tests) if rng.random() < 0.9
              else rng.choice(within or tests) for _ in range(LENGTH)]
    words = [int(t["encoded"], 16) for t in chosen]
    if lift is not None:
        back = loop_branch(lift, golden, isa, len(words))
        if back is not None:
            words.append(back)
    return words, isa


def loop_branch(lift, golden, isa: str, ahead: int):
    """A branch back to the top of the program, or None if the corpus has none.

    Built through the lifter's own field placement, and then decoded again to
    be sure it is still the instruction it was meant to be.
    """
    # ⚠️ Unconditional first. RISC-V loops with `beq x0, x0` -- a comparison
    # that is always true -- and AArch64 with `b`, whose condition codes come
    # from NZCV rather than from registers the harness can set. Asking for one
    # shape found a loop on one architecture and none on the other.
    def guarded(entry):
        return any(effect["kind"] == "setpc" and effect.get("guard")
                   for effect in (entry.get("effects") or []))

    def branching(entry):
        return any(effect["kind"] == "setpc"
                   for effect in (entry.get("effects") or []))

    ordered = sorted((entry for entry in lift.AXIS_LIFT_TABLE
                      if (entry.get("isa") or "") == isa and branching(entry)),
                     key=guarded)
    for entry in ordered:
        names = [operand["name"] for operand in entry["operands"]]
        if not any(name == "imm" for name in names) or len(names) > 3:
            continue
        if any(effect["kind"] not in ("setpc", "set")
               for effect in (entry.get("effects") or [])):
            continue
        word = entry["match"]
        ok = True
        offset = branch_offset(golden, entry, ahead, CODE + 4 * ahead, CODE)
        for operand in entry["operands"]:
            if operand["role"] == "enc" or not operand["fields"]:
                continue
            if operand["kind"] == "imm":
                value = offset if offset is not None else 0
            else:
                value = 0          # a register compared against itself: taken
            word = lift.place_operand(word, entry, operand["name"], value)
        decoded = lift.decode(word, isa or None)
        if ok and offset is not None and decoded is not None \
                and decoded["mnemonic"] == entry["mnemonic"]:
            return word
    return None


def branch_offset(golden, entry, ahead: int, at: int, target: int):
    """The immediate that makes this branch land on `target`, or None.

    ⚠️ Asked rather than assumed. One architecture counts a branch's immediate
    in bytes and another in instructions -- AArch64's `b` shifts it by two --
    and a harness that picked one built a loop on RISC-V and a jump into
    nowhere on AArch64. The description says which: its `setpc` expression is
    evaluated for each candidate, and the one that lands on the target is the
    answer.
    """
    setpc = next((effect for effect in (entry.get("effects") or [])
                  if effect["kind"] == "setpc"), None)
    if not setpc or not setpc.get("value"):
        return None
    for candidate in (-4 * ahead, -ahead, -2 * ahead, -8 * ahead):
        environment = {"pc": at, "imm": candidate & ((1 << 64) - 1)}
        for operand in entry["operands"]:
            environment.setdefault(operand["name"], 0)
            environment.setdefault(f"__input_{operand['name']}", 0)
        try:
            landed = golden._eval_axis_expr(setpc["value"], environment,
                                            setpc.get("eval_width") or 64)
        except Exception:
            continue
        if landed == target:
            return candidate & ((1 << 64) - 1)
    return None


def check(axis_file: Path, work: Path, rng: random.Random) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs")
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: no simulator library")
        return 0, 1
    sys.path.insert(0, str(work))
    subprocess.run([*axis_prefix(), "emit-lift-python", str(axis_file),
                    "-o", str(work / "axis_lift.py")], check=True,
                   capture_output=True, cwd=AXIS_ROOT)
    import importlib
    lift = importlib.import_module("axis_lift")
    subprocess.run([*axis_prefix(), "emit-golden-python", str(axis_file),
                    "-o", str(work / "golden_model.py")], check=True,
                   capture_output=True, cwd=AXIS_ROOT)
    golden = importlib.import_module("golden_model")
    # The table the simulator will consult, read once and used both to draw the
    # program and to say what breaks it.
    have = stencilled(work / "packs" / name / "include" / "axis_jit_table.h")
    words, isa = program(axis_file, rng, lift, golden, have)
    # ⚠️ The loop itself, when something disagrees. A gate that says "register 1
    # differs" over a program it does not print leaves the reader to reproduce
    # a random draw before they can start.
    def spell(word):
        entry = lift.decode(word, isa or None)
        return entry["mnemonic"] if entry else f"0x{word:08x}"
    loop = [spell(word) for word in words]
    if len(words) < 4:
        print(f"  {name}: not enough fixtures to make a program")
        return 0, 0
    # ⚠️ What BREAKS the runs, by name. A block stops at the first instruction
    # with no stencil and needs two to be worth building, so three scattered
    # refusals can cut a loop of twenty-four into pieces too short to translate
    # -- which is the difference between "the JIT is slow" and "the JIT was
    # given four instructions at a time", and only one of those is about the
    # JIT.
    breaks = []
    for word in words:
        entry = lift.decode(word, isa)
        name_of = entry["mnemonic"] if entry else None
        if name_of and name_of not in have and name_of not in breaks:
            breaks.append(name_of)
    if breaks:
        print(f"  {name}: {len(breaks)} instruction(s) in the loop have no "
              f"stencil and end a block: {', '.join(breaks[:6])}")
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "jit": manifest["libraries"]["jit"]["entry"],
        "exec": manifest["libraries"]["exec"]["entry"],
        "program": ", ".join(f"{word}u" for word in words),
        "length": len(words),
        "isa": f'"{isa}"' if isa else "NULL",
        "code": CODE,
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
         "-o", str(work / name), str(work / f"{name}.c"),
         *(str(root / "lib" / manifest["libraries"][f]["static"])
           for f in ("sim", "exec", "jit"))])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode < 0:
        print(f"  FAIL {name}: the harness died on signal {-done.returncode}")
        return 0, 1
    checks = failures = 0
    timing = None
    for line in done.stdout.splitlines():
        if line.startswith(("DIFF", "DISAGREE", "NOMACHINE")):
            print(f"  FAIL {name}: {line}")
            if line.startswith("DIFF translated"):
                print(f"         the loop was: {', '.join(loop)}")
            failures += 1
        elif line.startswith("RAN "):
            steps, status, reason = line.split(maxsplit=3)[1:]
            print(f"  {name}: ran {steps} instruction(s), stopped {status} ({reason})")
        elif line.startswith("TRANSLATED "):
            ran, blocks, bad, offered = (int(x) for x in line.split()[1:])
            checks += ran
            failures += bad
            print(f"  {name}: {ran} instruction(s) ran as translated code across "
                  f"{blocks} block(s), {bad} disagreeing with the interpreter; "
                  f"{offered} of the program had a stencil at all")
            # ⚠️ A run that translated nothing is the interpreter tested twice
            # -- unless the program held nothing the translator takes, which is
            # a fact about the corpus and not a failure.
            if not ran and offered > 1:
                print(f"  FAIL {name}: nothing was translated, though {offered} "
                      f"instruction(s) have stencils")
                failures += 1
        elif line.startswith("SPEED "):
            interpreted, translated, budget = line.split()[1:]
            timing = (float(interpreted), float(translated), budget)
        elif line.startswith("TIMEDMIX "):
            ran, steps, blocks = (int(x) for x in line.split()[1:])
            share = (100.0 * ran / steps) if steps else 0.0
            # ⚠️ No ratio when nothing was translated. Two interpreted runs
            # timed against each other produce a number that looks like a JIT
            # result and is a measurement of scheduler noise -- and this draw
            # produces one whenever the program has no backward branch to loop
            # on, which is a property of the fixtures rather than of the
            # translator.
            budget_steps = int(timing[2]) if timing else 0
            # ⚠️ And long enough to time. A program with no backward branch
            # halts after its own length -- twenty-four steps, a tenth of a
            # millisecond -- and dividing one such run by another reports
            # scheduler noise to two decimal places.
            if timing and ran and steps * 2 >= budget_steps:
                slow, quick, _ = timing
                ratio = (slow / quick) if quick > 0 else 0.0
                print(f"  {name}: {budget_steps} steps in {slow * 1e3:.1f} ms "
                      f"interpreted, {quick * 1e3:.1f} ms translated "
                      f"-- {ratio:.2f}x")
            elif timing:
                why = ("translated none of them" if not ran
                       else f"stopped after {steps} of {budget_steps}")
                print(f"  {name}: no speedup reported -- this program ran "
                      f"{steps} step(s) and {why}, so there is nothing here "
                      f"a ratio would be about")
            print(f"  {name}: of the timed run, {ran} of {steps} step(s) "
                  f"({share:.0f}%) ran as translated code across {blocks} "
                  f"block(s)")
        elif line.startswith("TOUCHED "):
            touched, watched = (int(x) for x in line.split()[1:])
            print(f"  {name}: {touched} event(s) that touched memory, "
                  f"{watched} that named the registers they read")
            if not watched:
                print(f"  FAIL {name}: no event said what it read")
                failures += 1
        elif line.startswith("RETIRED "):
            retired, decoded, wrong = (int(x) for x in line.split()[1:])
            checks += retired
            failures += wrong
            print(f"  {name}: {retired} retire event(s), {decoded} that decoded, "
                  f"{wrong} disagreeing with the executor")
            # ⚠️ A machine that stopped at once proves nothing about running.
            if retired < 2:
                print(f"  FAIL {name}: it retired {retired} instruction(s)")
                failures += 1
    if not checks:
        print(f"  FAIL {name}: nothing ran")
        failures += 1
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "rv64i.axisl"]
    rng = random.Random(0x51AA)
    total = failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for corpus in corpora:
            checks, bad = check(corpus, work, rng)
            total += checks
            failures += bad
    print(f"{total} instruction(s) run by the simulator library and checked "
          f"against the executor, {failures} disagreeing")
    if not total:
        print("simulator library == executor: SKIP")
        return DECLINED
    print("simulator library == executor:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
