#!/usr/bin/env python3
"""Decode knows where a direct branch goes. Gate.

A direct branch's target is its own address plus a field of its word
(docs/ooo_design.md, D1 and W1): no register is read, so a front end that has
decoded the word knows where it goes. Two consequences, one per engine.

**Execution-driven (D1).** A branch predicted taken whose target the buffer
does not hold is redirected at DECODE, `btb-penalty` cycles after the fetch --
not at execution, as a mispredict:

  * **a cold direct jump is no mispredict**: a straight line of direct jumps
    mispredicts nothing, misses the target buffer once each, and costs
    exactly what its trace-driven twin costs, cycle for cycle;
  * **a register is not a field**: the same line through indirect jumps
    mispredicts every one -- decode cannot read a register;
  * **an evicted target costs the penalty, not a refill**: two taken branches
    thrashing a one-entry buffer mispredict no more often as the loop runs
    longer, and each further miss costs exactly `btb-penalty`.

**Trace-driven (W1).** A branch guessed TAKEN that falls through has a wrong
path the trace never saw -- its target. Decode names it:

  * **either way a branch is wrong, the other side runs**: both sides of the
    loop branch load the line a pointer names, so every mispredict -- cold
    and taken, or trained and falling through -- prefetches the next load.
    Data misses saved are exactly the mispredicts;
  * **decode's time is the wrong path's too**: when the buffer holds another
    branch, the wrong path starts `btb-penalty` later and the machine fetches
    exactly `fetch-width x btb-penalty` fewer instructions down it;
  * **fetching in line order reaches the target's lines**: code the program
    runs later, one line past the target, is in the instruction cache when it
    gets there.

**Both (D2).** While decode looks for the target, fetch runs on past the
branch: **the lines after a decoded jump are in the instruction cache** when
the program comes back to them -- one miss fewer than on a machine whose
buffer is never missed, on each engine.

**A line asked for is on its way (D4).** That fetch waits on a line it
misses and asks for nothing past it; the line arrives a cache latency after
it was asked for, and the program, coming to it sooner, waits for what is left:

  * **decode's cycles are spent inside the miss**: a jump in the last word of
    a line into the next reaches it in exactly the cycles a machine that
    decodes nothing takes, with one miss fewer;
  * **a squashed path's fill goes on**: a branch whose wrong path misses on
    the line its right path lands in costs the same whether it waits on an
    add or a multiply;
  * **nothing is asked for past a missing line**: fetching eight words a
    cycle past a jump reaches a line and a half, and only the first is
    fetched.

**A wrong path's jumps are predicted like any others (W5, W6).** Through a
register no buffer holds, fetch runs on into what follows the jump and the
path resumes where it went; a direct jump the buffer lost costs decode's time
on a wrong path too; what a wrong path, or a detour of one, pushed on the
return stack goes when it does. And the PROGRAM's jump through a register no
buffer holds -- or its return to an empty stack -- has the fall-through for
its wrong path, on both engines.

And the generated source says how many direct branches it lowered a target
for and names any it declined: a decline is a failure here.

Usage: tools/redirect_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import re
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
ONE, MINUS_ONE, COUNTER, BASE, POINTER, STEP = 8, 7, 9, 5, 11, 12
#: Not the ABI's link register: a jump that links here is not a call.
SCRATCH_LINK = 30
# The ABI's link register: a jump through it that links nothing is a return.
LINK = 1
#: The registers the indirect jumps go through.
JR_FIRST = 21
JUMPS = 4
TRIPS = 8
LINE = 64

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
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->set_reg(m, %(counter)d, trips);
%(seeds)s
  S->count_cycles(m, 1);
  S->run(m, 4000u);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = 0; a < IMAGE; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu miss %%llu btb %%llu dmiss %%llu imiss %%llu wrong %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->mispredicts(m), (unsigned long long)S->btb_misses(m),
         (unsigned long long)S->cache_misses(m), (unsigned long long)S->icache_misses(m),
         (unsigned long long)S->wrong_path_instructions(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->wrong_path_instructions || !S->btb_misses) { printf("NOFRONTEND\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def direct_jump_encoder(lift, tests):
    """An unconditional jump to pc plus a field: no register in, a link out."""
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        effects = entry.get("effects") or []
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        imms = [o for o in entry["operands"] if o["role"] == "in" and o["kind"] == "imm"]
        if (any(e.get("kind") == "setpc" and "when" not in json.dumps(e) for e in effects)
                and not regs and len(outs) == 1 and len(imms) == 1):
            def encode(link, offset, test=test, entry=entry, out=outs[0], imm=imms[0]):
                word = lift.place_operand(int(test["encoded"], 16), entry, out["name"], link)
                return lift.place_operand(word, entry, imm["name"], offset & ((1 << 21) - 1))
            return encode
    return None


def layout(words: dict, length: int, filler):
    return [words.get(i, filler) for i in range(length)]


def harness_run(work, manifest, name, isa, seeds, programs, runs, fields):
    """Compile and run the harness; {tag: {field: value}}, or None."""
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY,
        "counter": seeds.pop("counter"),
        "seeds": "\n".join(f"  S->set_reg(m, {slot}, {value}u);" for slot, value in seeds.items()),
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
        return None
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 1 + 2 * fields and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])
    return said


def build_programs(asm: Assembler, bnz, jump, far):
    add, mul = asm.fast_add, asm.slow
    pad = asm.op(add, 30, 1, 1)
    programs = {}
    # JUMPS: a straight line of direct jumps, each over two instructions that
    # never run. JRS: the same line, each jump through a register instead.
    direct, indirect = {}, {}
    for k in range(JUMPS):
        direct[4 * k] = indirect[4 * k] = asm.op(add, 14 + k, 1, 2)
        direct[4 * k + 1] = jump(SCRATCH_LINK, 12)
        indirect[4 * k + 1] = asm.jump(SCRATCH_LINK, JR_FIRST + k)
    programs["JUMPS"] = layout(direct, 4 * JUMPS + 2, pad) + [0]
    programs["JRS"] = layout(indirect, 4 * JUMPS + 2, pad) + [0]
    # TWO: frontend_check's loop -- a branch that always skips one
    # instruction, and the branch back. In a one-entry buffer each evicts the
    # other.
    programs["TWO"] = [asm.op(add, 14, 14, 1), bnz(ONE, 0, 8), asm.op(add, 16, 16, 1),
                       asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -16),
                       asm.op(add, 15, 1, 1), 0]
    # ⚠️ EXIT: BOTH SIDES OF THE BRANCH LOAD THE LINE THE POINTER NAMES. Taken,
    # the loop loads it and moves the pointer on; falling through, the code
    # after the loop loads it. So whichever way the branch is mispredicted,
    # the wrong path loads what the right path loads next -- and a machine
    # that runs the wrong path saves one data miss per mispredict, with no
    # arithmetic about which mispredicts were which. The branch waits on two
    # multiplies, so the wrong path's load has issued long before it resolves.
    programs["EXIT"] = [asm.ld(21, POINTER, 0), asm.op(add, POINTER, POINTER, STEP),
                        asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                        asm.op(mul, 20, COUNTER, ONE), asm.op(mul, 20, 20, ONE),
                        bnz(20, 0, -20),
                        asm.ld(22, POINTER, 0), asm.op(add, 23, 22, 22), 0]
    # EVICTED: the same loop behind a branch that always skips an instruction,
    # which in a one-entry buffer evicts the loop branch every iteration. ONE
    # multiply, so the wrong path is cut short by resolution and not by how
    # much the machine can hold.
    # ⚠️ TWELVE PADS before the multiply (W5): the wrong path of the exit is
    # the loop again, and its own loop branch -- taken, and not in a one-entry
    # buffer -- costs decode's time ON the wrong path too. A loop the wrong
    # path got round inside the window measured that as well: 18 fewer, not
    # 12. This one is longer than what the machine that decodes fetches
    # before the branch resolves -- and loads ONE line, every time: a load
    # missing each iteration backs the window up behind it, and how long the
    # branch then waits to enter depends on how fast fetch was feeding it.
    programs["EVICTED"] = [bnz(ONE, 0, 8), pad,
                           asm.ld(21, BASE, 0), asm.op(add, POINTER, POINTER, STEP),
                           asm.op(add, COUNTER, COUNTER, MINUS_ONE), *([pad] * 12),
                           asm.op(mul, 20, COUNTER, ONE),
                           bnz(20, 0, -4 * 18),
                           asm.ld(22, POINTER, 0), asm.op(add, 23, 22, 22), 0]
    # ⚠️ QUICK: the evicted loop again, its branch on the counter itself --
    # resolved a cycle after it issues. With the target in the buffer the
    # wrong path's load is fetched with the branch and issues before the
    # branch resolves; with the target to be DECODED, the branch has resolved
    # before decode has found it, and there is no wrong path to speak of.
    programs["QUICK"] = [bnz(ONE, 0, 8), pad,
                         asm.ld(21, POINTER, 0), asm.op(add, POINTER, POINTER, STEP),
                         asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                         bnz(COUNTER, 0, -20),
                         asm.ld(22, POINTER, 0), asm.op(add, 23, 22, 22), 0]
    # ⚠️ FAR: the loop branch's target is `far` words away -- lines the
    # fall-through never comes near -- and jumps straight back. The exit jumps
    # to the line AFTER the target's, and fetching the wrong path in line
    # order from the target runs on into that line. Direct jumps, not
    # always-taken branches: a cold branch would mispredict and fetch the line
    # itself. ⚠️ `far` is TWO lines more than the instruction cache holds, and
    # the branch waits on ONE multiply: the target's line and the one after
    # it then share no set with the loop's line or the one after that, which
    # is as far as a cold mispredict's fall-through fetch gets. Twice this
    # measured nothing -- a target in the loop's own set, then one in the set
    # the cold wrong path polluted -- each time one miss saved, one caused.
    after = far + LINE // 4
    programs["FAR"] = layout({0: asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                              1: asm.op(mul, 20, COUNTER, ONE), 2: pad,
                              3: bnz(20, 0, 4 * (far - 3)),
                              4: jump(SCRATCH_LINK, 4 * (after - 4)),
                              far: asm.op(add, 16, 1, 2), far + 1: jump(SCRATCH_LINK, -4 * (far + 1)),
                              after: asm.op(add, 15, 1, 1), after + 1: asm.op(add, 17, 1, 1)},
                             after + 2, pad) + [0]
    # ⚠️ BUBBLE: a direct jump two words from the end of a line, to a line
    # that jumps back to the line AFTER the first. The target buffer holds
    # neither jump, so each is redirected at decode -- and while decode
    # looked, fetch ran on past the first jump into the line the program
    # comes back to. No branch here mispredicts on either engine.
    per_line = LINE // 4
    programs["BUBBLE"] = layout({0: asm.op(add, 14, 1, 2),
                                 per_line - 2: jump(SCRATCH_LINK, 4 * (per_line + 10)),
                                 per_line: asm.op(add, 15, 1, 1), per_line + 1: 0,
                                 2 * per_line + 8: asm.op(add, 16, 1, 2),
                                 2 * per_line + 9: jump(SCRATCH_LINK, -4 * (per_line + 9))},
                                2 * per_line + 10, pad) + [0]
    # ⚠️ WJR (W5): a wrong path with a jump through a REGISTER. A machine whose
    # buffer holds every target knows where it goes; one whose buffer does not
    # hold this jump has nowhere to send fetch but on, so the word after the
    # jump -- a load of A -- is fetched and issued before the jump has read
    # its register, and the path then resumes where the jump went, at a load
    # of X. The right path loads both. Five multiplies hold the outer branch.
    chain = {0: asm.op(mul, 13, ONE, ONE)}
    chain.update({k: asm.op(mul, 13, 13, ONE) for k in range(1, 5)})
    programs["WJR"] = layout({**chain, 5: bnz(13, 0, 4 * (24 - 5)),
                              6: asm.jump(SCRATCH_LINK, JR_FIRST + 3),
                              7: asm.ld(14, BASE, 0), 8: 0,
                              16: asm.ld(15, BASE, LINE), 17: 0,
                              24: asm.ld(16, BASE, 0), 25: asm.ld(17, BASE, LINE)},
                             26, pad) + [0]
    # ⚠️ WBTB (W5): a wrong path with a DIRECT jump the buffer does not hold,
    # to a load of what the right path loads. Decode finds the target -- on a
    # wrong path as on the right one, `btb-penalty` cycles later -- and the
    # outer branch, waiting on one add, has resolved by then. With the target
    # in the buffer the load is fetched with the jump and issues in time.
    programs["WBTB"] = layout({0: asm.op(add, 13, ONE, ONE), 1: bnz(13, 0, 4 * (24 - 1)),
                               2: jump(SCRATCH_LINK, 4 * (16 - 2)),
                               16: asm.ld(14, BASE, 0), 17: 0,
                               24: asm.ld(15, BASE, 0), 25: asm.op(add, 16, 15, 15)},
                              26, pad) + [0]
    # ⚠️ WLATE (W5): a DETOUR that starts at a target decode had to find. The
    # loop's first branch T is taken every trip -- on the counter, so trained
    # taken -- and a jump behind it keeps it out of a one-entry buffer. At the
    # exit the loop branch is guessed taken and its wrong path is the loop
    # again: T, guessed taken, and this time the counter is zero. So fetch
    # goes to T's target -- once decode has found it -- and the load there is
    # of the line the exit loads. With every target in the buffer that load
    # issues before the loop branch resolves; found by decode, it is fetched
    # too late. The loop branch waits on a multiply and an add: long enough
    # for a detour that started on time, not for one that started at decode.
    programs["WLATE"] = layout({0: bnz(17, 0, 32), 1: 0,
                                8: asm.ld(14, POINTER, 0), 9: asm.op(add, POINTER, POINTER, STEP),
                                10: asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                                11: asm.op(add, 17, COUNTER, 0),
                                12: jump(SCRATCH_LINK, 8), 13: 0,
                                14: asm.op(mul, 13, COUNTER, ONE), 15: asm.op(add, 13, 13, 0),
                                16: bnz(13, 0, -64),
                                17: asm.ld(15, POINTER, 0), 18: asm.op(add, 16, 15, 15)},
                               19, pad) + [0]
    # ⚠️ RJR (W6): the program's own jump through a register no buffer holds
    # -- to the front end not a branch, so it fetches what follows: a load of
    # A, issued while the jump waits on a multiply for its target. The right
    # path loads A. An engine that fetches what it predicts always did this;
    # a trace had "nowhere to have gone".
    programs["RJR"] = layout({0: asm.op(mul, 13, JR_FIRST + 1, ONE),
                              1: asm.jump(SCRATCH_LINK, 13), 2: asm.ld(14, BASE, 0), 3: 0,
                              9: asm.ld(15, BASE, 0), 10: asm.op(add, 16, 15, 15)},
                             11, pad) + [0]
    # ⚠️ RRET (W6): the same, the jump a RETURN -- through the link register,
    # linking nothing -- on a machine with a return stack and nothing on it.
    programs["RRET"] = layout({0: asm.op(mul, LINK, JR_FIRST + 1, ONE),
                               1: asm.jump(SCRATCH_LINK, LINK), 2: asm.ld(14, BASE, 0), 3: 0,
                               9: asm.ld(15, BASE, 0), 10: asm.op(add, 16, 15, 15)},
                              11, pad) + [0]
    # ⚠️ WCALL (W5): a wrong path that CALLS, and a right path that returns.
    # The call pushed where to come back to; the shadow is discarded, and the
    # return stack with it. So the right path's return finds the stack empty
    # and fetch runs on past it, into a load of what the program loads later.
    # A stack the wrong path's call was left on sent fetch to the word after
    # that call instead -- which does not decode, and loads nothing.
    programs["WCALL"] = layout({0: asm.op(mul, 13, ONE, ONE), 1: asm.op(mul, 13, 13, ONE),
                                2: bnz(13, 0, 4 * (8 - 2)),
                                3: jump(LINK, 8), 4: 0, 5: 0,
                                8: asm.op(mul, LINK, JR_FIRST + 3, ONE),
                                9: asm.jump(SCRATCH_LINK, LINK), 10: asm.ld(14, BASE, 0), 11: 0,
                                16: asm.ld(15, BASE, 0), 17: asm.op(add, 16, 15, 15)},
                               18, pad) + [0]
    # ⚠️ WDCALL (W5): the same, a level down. The wrong path's own branch is
    # cold, and its detour calls; then the branch resolves, the detour goes --
    # its push with it -- and the path the branch took returns, to a stack
    # that is empty again, so fetch runs on into the load.
    programs["WDCALL"] = layout({**chain, 5: bnz(13, 0, 4 * (24 - 5)),
                                 6: asm.op(mul, 17, ONE, ONE), 7: bnz(17, 0, 4 * (12 - 7)),
                                 8: jump(LINK, 8), 9: 0, 10: 0,
                                 12: asm.jump(SCRATCH_LINK, LINK), 13: asm.ld(14, BASE, 0), 14: 0,
                                 24: asm.ld(15, BASE, 0), 25: asm.op(add, 16, 15, 15)},
                                26, pad) + [0]
    # ⚠️ NEXT (D4): a direct jump in the LAST word of a line, into the next --
    # the line fetch runs into while decode looks. That fetch
    # misses, and the fill it starts lands a cache latency later; the program,
    # redirected there by decode, waits for what is left of it. A machine that
    # decodes nothing asks for the line the cycle after the jump too, so the
    # two reach it together: decode's cycles were spent inside the miss.
    # ⚠️ Over ONE word of that line, not to its first: to a trace a jump to
    # the next instruction is a branch that fell through.
    programs["NEXT"] = layout({0: asm.op(add, 14, 1, 2), per_line - 1: jump(SCRATCH_LINK, 8),
                               per_line + 1: asm.op(add, 15, 1, 1),
                               per_line + 2: asm.op(add, 16, 15, 15)}, per_line + 3, pad) + [0]
    # ⚠️ FILLA / FILLB (D4): a branch in the last word of a line, cold and
    # taken, over the first four words of the next. Its wrong path is the fall
    # through -- the next line, which misses -- and its right path lands in
    # the same line. The branch waits on an add (A) or a multiply (B): either
    # way it resolves before the line arrives, so the two cost the same.
    for tag, op in (("FILLA", add), ("FILLB", mul)):
        programs[tag] = layout({0: asm.op(add, 14, 1, 2),
                                per_line - 2: asm.op(op, 20, ONE, ONE),
                                per_line - 1: bnz(20, 0, 20),
                                per_line + 4: asm.op(add, 15, 1, 1),
                                per_line + 5: asm.op(add, 16, 15, 15)}, per_line + 6, pad) + [0]
    # ⚠️ SKIPS (D4): a jump in the last word of line 0 to line 3, which jumps
    # back to line 2. Fetching eight words a cycle for three cycles reaches
    # past line 1 into line 2 -- but line 1 is not in the cache, and fetch
    # waits for it: line 2 is never asked for, and the program misses on it.
    programs["SKIPS"] = layout({0: asm.op(add, 14, 1, 2),
                                per_line - 1: jump(SCRATCH_LINK, 4 * (2 * per_line + 1)),
                                2 * per_line: asm.op(add, 15, 1, 1),
                                2 * per_line + 1: asm.op(add, 16, 15, 15), 2 * per_line + 2: 0,
                                3 * per_line: asm.op(add, 17, 1, 2),
                                3 * per_line + 1: jump(SCRATCH_LINK, -4 * (per_line + 1))},
                               3 * per_line + 2, pad) + [0]
    return programs


def twin_of(cores, core, **front):
    """The core that differs from `core` in engine and these front-end fields."""
    want = {**core["front_end"], **front}
    keys = ("memory", "issue_width", "units", "rob", "issue_queue", "commit_width",
            "branch_penalty", "predictor", "predictor_entries", "lsq", "rename")
    return next((c for c in cores if c is not core and (c.get("front_end") or {}) == want
                 and c.get("engine") != "execute"
                 and all(c.get(k) == core.get(k) for k in keys)), None)


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    source = run_cmd([*axis_prefix(), "emit-pack-sim-c", str(axis_file)]).stdout
    said_targets = re.search(r"/\* direct-targets: (\d+) lowered, (\d+) declined(?:: ([^*]*))? \*/", source)
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = [c for c in facts.get("cores", []) if c.get("front_end")]
    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    # ⚠️ EVERY corpus is held to this, core or no core: a direct branch whose
    # target could not be lowered has no decode-time target, silently.
    checks += 1
    if not said_targets:
        fail("the generated simulator does not say how many direct targets it lowered")
        return checks, failures
    lowered, declined = int(said_targets.group(1)), int(said_targets.group(2))
    if declined:
        fail(f"{declined} direct branch(es) have no decode-time target: "
             f"{(said_targets.group(3) or '').strip()}")

    def fe(core):
        return core["front_end"]

    executing = [c for c in cores if c.get("engine") == "execute"]
    tracing = [c for c in cores if c.get("engine") != "execute"]
    xbig = next((c for c in executing if fe(c)["btb"] >= 2 and fe(c)["btb_penalty"]
                 and twin_of(tracing, c)), None)
    xsmall = next((c for c in executing if fe(c)["btb"] == 1 and fe(c)["btb_penalty"]), None)
    runs = next((c for c in tracing if fe(c)["wrong_path_execute"] and not fe(c)["btb"]
                 and c.get("memory") and twin_of(tracing, c, wrong_path_execute=False)
                 and twin_of(tracing, c, wrong_path_execute=False, wrong_path_fetch=True)), None)
    runsbtb = runs and twin_of(tracing, runs, btb=1, btb_penalty=next(
        (fe(c)["btb_penalty"] for c in tracing if fe(c)["wrong_path_execute"] and fe(c)["btb"] == 1), 0))
    xdec = next((c for c in executing if fe(c)["icache"] and fe(c)["btb_penalty"]), None)
    xnot = xdec and next((c for c in executing if c is not xdec
                          and fe(c) == {**fe(xdec), "btb": 0, "btb_penalty": 0}
                          and all(c.get(k) == xdec.get(k) for k in
                                  ("memory", "issue_width", "units", "rob", "predictor"))), None)
    # D4: a core on each engine whose fetch, while decode looks, reaches past a
    # whole line -- and holds that much.
    def reaches(core):
        f = fe(core)
        words = f["fetch_width"] * f["btb_penalty"]
        return (f["icache"] and words > LINE // 4
                and (f["buffer"] or f["fetch_width"] * (f["depth"] + 1)) >= words
                and (core.get("engine") == "execute" or f["wrong_path_execute"]))

    returns = next((c for c in tracing if fe(c)["ras"] and fe(c)["wrong_path_execute"]
                    and not fe(c)["btb"] and c.get("memory")), None)
    xwide = next((c for c in executing if reaches(c)), None)
    twide = next((c for c in tracing if reaches(c)), None)
    if not (xbig and xsmall and runs and runsbtb and xnot and xwide and twide and returns):
        print(f"  {name}: {lowered} direct target(s) lowered, none declined; no cores to time "
              f"them on")
        return checks, failures
    machines = {"XBIG": xbig, "TBIG": twin_of(tracing, xbig), "XSMALL": xsmall,
                "RUNS": runs, "STAYS": twin_of(tracing, runs, wrong_path_execute=False),
                "READS": twin_of(tracing, runs, wrong_path_execute=False, wrong_path_fetch=True),
                "RUNSBTB": runsbtb, "XDEC": xdec, "XNOT": xnot, "XWIDE": xwide, "TWIDE": twide,
                "RETURNS": returns}
    penalty = fe(xsmall)["btb_penalty"]
    if fe(xbig)["btb_penalty"] != penalty or fe(xbig)["depth"] != fe(xsmall)["depth"]:
        print(f"  {name}: DECLINED the two execution-driven target buffers differ in more "
              f"than their size")
        return 0, 0
    memories = {m["name"]: m for m in facts.get("memories", [])}
    icache = memories.get(fe(runs)["icache"]) or {}
    icache_lines = (icache.get("size_bytes") or 0) // LINE
    if icache.get("line_bytes") != LINE or (icache.get("ways") or 1) != 1 or icache_lines < 4:
        print(f"  {name}: DECLINED the instruction cache is not direct-mapped, {LINE}-byte "
              f"lines, four or more")
        return 0, 0

    module = f"rd_{name}"
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
    jump = direct_jump_encoder(lift, tests)
    if asm.missing() or bnz is None or asm.jump is None or jump is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no branch, indirect jump or direct jump'}")
        return 0, 0
    far = (icache_lines + 2) * LINE // 4
    programs = build_programs(asm, bnz, jump, far)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF,
             slot(BASE): DATA, slot(POINTER): DATA, slot(STEP): LINE}
    for k in range(JUMPS):
        seeds[slot(JR_FIRST + k)] = ENTRY + 4 * (4 * k + 4)
    plan = {"JUMPS": ("XBIG", "TBIG"), "JRS": ("XBIG", "TBIG"),
            "TWO": ("XSMALL", "XBIG"), "EXIT": ("RUNS", "STAYS", "RUNSBTB"),
            "EVICTED": ("RUNS", "RUNSBTB"), "QUICK": ("RUNS", "RUNSBTB"),
            "FAR": ("STAYS", "READS"), "BUBBLE": ("RUNS", "RUNSBTB", "XNOT", "XDEC"),
            "NEXT": ("RUNS", "RUNSBTB", "XNOT", "XDEC"), "FILLA": ("XNOT", "XDEC"),
            "FILLB": ("XNOT", "XDEC"), "SKIPS": ("XWIDE", "TWIDE"),
            "WJR": ("RUNS", "STAYS", "RUNSBTB"), "WBTB": ("RUNS", "STAYS", "RUNSBTB"),
            "RJR": ("RUNS", "RUNSBTB", "XBIG"), "RRET": ("RUNS", "RETURNS"),
            "WCALL": ("RUNS", "RETURNS"), "WDCALL": ("RUNS", "RETURNS"),
            "WLATE": ("RUNS", "RUNSBTB")}
    lines = [f'  go("{p}_{t}_{trips}", "{machines[t]["name"]}", {p}, {len(programs[p])}, {trips}u);'
             for p, tags in plan.items() for t in tags
             for trips in ((TRIPS, 2 * TRIPS) if p == "TWO" else (TRIPS,))]
    said = harness_run(work, manifest, name, isa, seeds, programs, lines, 8)
    if said is None:
        fail("the harness did not run")
        return checks, failures

    def get(program, tag, key, trips=TRIPS):
        return said[f"{program}_{tag}_{trips}"][key]

    for program, tags in plan.items():
        rows = [said.get(f"{program}_{t}_{TRIPS}") for t in tags]
        checks += 1
        if any(r is None for r in rows):
            fail(f"{program} reported nothing on some machine")
            return checks, failures
        checks += 1
        if len({(r["steps"], r["mark"]) for r in rows}) != 1:
            fail(f"{program} retired different instructions or left different registers or "
                 f"memory on different machines: {[r['steps'] for r in rows]}")
    if failures:
        return checks, failures

    # ---- D1: the execution-driven front end redirects at decode -----------
    checks += 1
    if get("JUMPS", "XBIG", "miss") != 0 or get("JUMPS", "XBIG", "btb") != JUMPS:
        fail(f"{JUMPS} cold direct jumps on {xbig['name']}: {get('JUMPS', 'XBIG', 'miss')} "
             f"mispredicts and {get('JUMPS', 'XBIG', 'btb')} target-buffer misses; decode reads "
             f"the target out of the word, so none and {JUMPS}")
    checks += 1
    if get("JUMPS", "XBIG", "cycles") != get("JUMPS", "TBIG", "cycles"):
        fail(f"{JUMPS} cold direct jumps took {get('JUMPS', 'XBIG', 'cycles')} cycles on "
             f"{xbig['name']} and {get('JUMPS', 'TBIG', 'cycles')} on its trace-driven twin "
             f"{machines['TBIG']['name']}; a decode redirect is the same {penalty} cycles on both")
    checks += 1
    if get("JRS", "XBIG", "miss") != JUMPS:
        fail(f"{JUMPS} cold indirect jumps on {xbig['name']} mispredicted "
             f"{get('JRS', 'XBIG', 'miss')} times; a target in a register is not known until "
             f"the jump executes, so {JUMPS}")
    grew = {tag: {key: get("TWO", tag, key, 2 * TRIPS) - get("TWO", tag, key)
                  for key in ("cycles", "miss", "btb")} for tag in ("XSMALL", "XBIG")}
    checks += 1
    if grew["XSMALL"]["miss"] != 0:
        fail(f"two branches thrashing a one-entry buffer on {xsmall['name']}: "
             f"{grew['XSMALL']['miss']} more mispredicts over {TRIPS} more iterations; an "
             f"evicted target is found at decode, not at execution, so none")
    more = grew["XSMALL"]["btb"] - grew["XBIG"]["btb"]
    checks += 1
    if more <= 0:
        fail(f"the one-entry buffer on {xsmall['name']} missed no more often than "
             f"{xbig['name']}'s as the loop ran longer ({grew['XSMALL']['btb']} vs "
             f"{grew['XBIG']['btb']}); nothing was evicted, so nothing was measured")
    checks += 1
    if grew["XSMALL"]["cycles"] - grew["XBIG"]["cycles"] != penalty * more:
        fail(f"{more} more target-buffer misses on {xsmall['name']} cost "
             f"{grew['XSMALL']['cycles'] - grew['XBIG']['cycles']} cycles; each is a decode "
             f"redirect of exactly {penalty}, so {penalty * more}")

    # ---- W1: a branch guessed taken that falls through has a wrong path ---
    saved = get("EXIT", "STAYS", "dmiss") - get("EXIT", "RUNS", "dmiss")
    checks += 1
    if get("EXIT", "RUNS", "miss") < 2:
        fail(f"the loop branch mispredicted {get('EXIT', 'RUNS', 'miss')} times; it has to be "
             f"wrong both ways -- cold and taken, trained and falling through -- to say "
             f"anything")
    checks += 1
    if saved != get("EXIT", "RUNS", "miss"):
        fail(f"a branch with the same load on both sides: {get('EXIT', 'RUNS', 'miss')} "
             f"mispredicts saved {saved} data misses on {runs['name']}; every mispredict runs "
             f"the other side, the last one -- guessed taken, falling through -- included")
    fewer = get("EVICTED", "RUNS", "wrong") - get("EVICTED", "RUNSBTB", "wrong")
    width = fe(runs)["fetch_width"]
    checks += 1
    if fewer != width * fe(runsbtb)["btb_penalty"]:
        fail(f"a taken guess whose target the buffer had lost: {runsbtb['name']} fetched "
             f"{fewer} fewer wrong-path instructions than {runs['name']}; decode finds the "
             f"target {fe(runsbtb)['btb_penalty']} cycles after the fetch, so exactly "
             f"{width * fe(runsbtb)['btb_penalty']}")
    # ⚠️ A TARGET THE BUFFER HOLDS costs decode nothing: one branch in a
    # one-entry buffer is never evicted, so its wrong path starts with the
    # fetch, as it does with a perfect buffer.
    checks += 1
    if get("EXIT", "RUNSBTB", "wrong") != get("EXIT", "RUNS", "wrong"):
        fail(f"a taken guess whose target the buffer holds: {runsbtb['name']} fetched "
             f"{get('EXIT', 'RUNSBTB', 'wrong')} wrong-path instructions and {runs['name']} "
             f"{get('EXIT', 'RUNS', 'wrong')}; nothing was decoded, so the same")
    checks += 1
    if (get("QUICK", "RUNS", "miss") != get("QUICK", "RUNSBTB", "miss")
            or get("QUICK", "RUNSBTB", "dmiss") != get("QUICK", "RUNS", "dmiss") + 1):
        fail(f"a taken guess that resolves before decode has found its target: "
             f"{get('QUICK', 'RUNSBTB', 'dmiss')} data misses on {runsbtb['name']} and "
             f"{get('QUICK', 'RUNS', 'dmiss')} on {runs['name']}, mispredicting "
             f"{get('QUICK', 'RUNSBTB', 'miss')} and {get('QUICK', 'RUNS', 'miss')} times; the "
             f"wrong path that starts {fe(runsbtb)['btb_penalty']} cycles late loads nothing, "
             f"so exactly one more")
    checks += 1
    if get("FAR", "READS", "imiss") != get("FAR", "STAYS", "imiss") - 1:
        fail(f"code one line past the loop branch's target, run after the loop: "
             f"{get('FAR', 'READS', 'imiss')} instruction misses fetching the wrong path in "
             f"line order and {get('FAR', 'STAYS', 'imiss')} without; the taken guess's wrong "
             f"path starts at the target, so exactly one fewer")

    # ---- D2: while decode looks, fetch runs on ----------------------------
    for late, base in (("RUNSBTB", "RUNS"), ("XDEC", "XNOT")):
        checks += 1
        if get("BUBBLE", late, "miss") or get("BUBBLE", base, "miss"):
            fail(f"direct jumps mispredicted on {machines[late]['name']} or "
                 f"{machines[base]['name']}; the bubble program measures decode, not a wrong "
                 f"path")
        checks += 1
        if get("BUBBLE", late, "imiss") != get("BUBBLE", base, "imiss") - 1:
            fail(f"a jump decoded two words before the line the program comes back to: "
                 f"{get('BUBBLE', late, 'imiss')} instruction misses on "
                 f"{machines[late]['name']} and {get('BUBBLE', base, 'imiss')} on "
                 f"{machines[base]['name']}, which decodes nothing; fetch ran on into that "
                 f"line while decode looked, so exactly one fewer")

    # ---- W5: a wrong path's jumps are predicted like any others -----------
    checks += 1
    if ((get("WJR", "STAYS", "dmiss"), get("WJR", "RUNS", "dmiss"),
         get("WJR", "RUNSBTB", "dmiss")) != (2, 1, 0)):
        fail(f"a wrong path with a jump through a register, a load after it and a load "
             f"where it goes: {get('WJR', 'STAYS', 'dmiss')} data misses with no wrong path, "
             f"{get('WJR', 'RUNS', 'dmiss')} on {runs['name']} whose buffer holds every "
             f"target, {get('WJR', 'RUNSBTB', 'dmiss')} on {runsbtb['name']} whose buffer "
             f"does not hold the jump; fetch runs on past a jump it cannot predict and the "
             f"path resumes where the jump went, so 2, 1 and 0")
    checks += 1
    if ((get("WBTB", "STAYS", "dmiss"), get("WBTB", "RUNS", "dmiss"),
         get("WBTB", "RUNSBTB", "dmiss")) != (1, 0, 1)):
        fail(f"a wrong path with a direct jump to a load, under a branch that resolves at "
             f"once: {get('WBTB', 'STAYS', 'dmiss')} data misses with no wrong path, "
             f"{get('WBTB', 'RUNS', 'dmiss')} on {runs['name']}, "
             f"{get('WBTB', 'RUNSBTB', 'dmiss')} on {runsbtb['name']}, whose buffer does not "
             f"hold the jump; decode takes {fe(runsbtb)['btb_penalty']} cycles to find the "
             f"target on a wrong path too, and the load is not fetched in time -- 1, 0 and 1")
    checks += 1
    if (get("WLATE", "RUNSBTB", "dmiss") != get("WLATE", "RUNS", "dmiss") + 1
            or get("WLATE", "RUNSBTB", "miss") != get("WLATE", "RUNS", "miss")):
        fail(f"a wrong-path branch guessed taken that falls through, its target's load the "
             f"line the right path loads next: {get('WLATE', 'RUNS', 'dmiss')} data misses on "
             f"{runs['name']} and {get('WLATE', 'RUNSBTB', 'dmiss')} on {runsbtb['name']}, "
             f"whose buffer does not hold it; a detour to a target decode had to find starts "
             f"{fe(runsbtb)['btb_penalty']} cycles later and its load is not fetched in time "
             f"-- exactly one more")
    # ---- W6: an indirect jump no buffer holds runs on -----------------------
    checks += 1
    if ((get("RJR", "RUNSBTB", "miss"), get("RJR", "RUNSBTB", "dmiss")) != (1, 0)
            or not get("RJR", "RUNSBTB", "wrong")):
        fail(f"a jump through a register the buffer does not hold, with a load after it of "
             f"what the right path loads: {get('RJR', 'RUNSBTB', 'miss')} mispredicts, "
             f"{get('RJR', 'RUNSBTB', 'dmiss')} data misses and "
             f"{get('RJR', 'RUNSBTB', 'wrong')} wrong-path instructions on "
             f"{runsbtb['name']}; fetch had nowhere to go but on, so the load ran -- 1, 0 and "
             f"some")
    checks += 1
    if (get("RJR", "RUNS", "miss"), get("RJR", "RUNS", "dmiss")) != (0, 1):
        fail(f"the same on {runs['name']}, whose buffer holds every target: "
             f"{get('RJR', 'RUNS', 'miss')} mispredicts and {get('RJR', 'RUNS', 'dmiss')} data "
             f"misses; nothing ran on, so 0 and 1")
    checks += 1
    if ((get("RJR", "XBIG", "miss"), get("RJR", "XBIG", "dmiss"))
            != (get("RJR", "RUNSBTB", "miss"), get("RJR", "RUNSBTB", "dmiss"))):
        fail(f"the same on {xbig['name']}, which fetches what it predicts: "
             f"{get('RJR', 'XBIG', 'miss')} mispredicts and {get('RJR', 'XBIG', 'dmiss')} data "
             f"misses against {runsbtb['name']}'s {get('RJR', 'RUNSBTB', 'miss')} and "
             f"{get('RJR', 'RUNSBTB', 'dmiss')}; the two engines agree where a jump with no "
             f"prediction sends fetch")

    checks += 1
    if ((get("RRET", "RETURNS", "miss"), get("RRET", "RETURNS", "dmiss")) != (1, 0)
            or not get("RRET", "RETURNS", "wrong")):
        fail(f"a return with nothing on the stack, and a load after it of what the right "
             f"path loads: {get('RRET', 'RETURNS', 'miss')} mispredicts, "
             f"{get('RRET', 'RETURNS', 'dmiss')} data misses and "
             f"{get('RRET', 'RETURNS', 'wrong')} wrong-path instructions on "
             f"{returns['name']}; an empty stack predicts nothing, so fetch ran on and the "
             f"load ran -- 1, 0 and some")
    checks += 1
    if (get("RRET", "RUNS", "miss"), get("RRET", "RUNS", "dmiss")) != (0, 1):
        fail(f"the same on {runs['name']}, which has no stack and a buffer that holds every "
             f"target: {get('RRET', 'RUNS', 'miss')} mispredicts and "
             f"{get('RRET', 'RUNS', 'dmiss')} data misses; nothing ran on, so 0 and 1")

    for program, where in (("WCALL", "the wrong path"), ("WDCALL", "a detour of the wrong path")):
        checks += 1
        if get(program, "RETURNS", "dmiss") != 0 or get(program, "RUNS", "dmiss") != 1:
            fail(f"a call on {where}, then a return with a load after it: "
                 f"{get(program, 'RETURNS', 'dmiss')} data misses on {returns['name']} and "
                 f"{get(program, 'RUNS', 'dmiss')} on {runs['name']}, which has no stack; "
                 f"what {where} pushed goes when it does, so the return finds the stack "
                 f"empty and fetch runs on into the load -- 0 and 1")

    # ---- D4: a line asked for is not there until it arrives --------------
    for late, base in (("RUNSBTB", "RUNS"), ("XDEC", "XNOT")):
        checks += 1
        if get("NEXT", late, "miss") or get("NEXT", base, "miss"):
            fail(f"a direct jump to the next line mispredicted on {machines[late]['name']} or "
                 f"{machines[base]['name']}; the program measures a fill, not a wrong path")
        checks += 1
        if get("NEXT", late, "imiss") != get("NEXT", base, "imiss") - 1:
            fail(f"a jump in the last word of a line to the line after it: "
                 f"{get('NEXT', late, 'imiss')} instruction misses on "
                 f"{machines[late]['name']} and {get('NEXT', base, 'imiss')} on "
                 f"{machines[base]['name']}; fetch asked for the line while decode looked, "
                 f"so the program does not miss on it -- exactly one fewer")
        checks += 1
        if get("NEXT", late, "cycles") != get("NEXT", base, "cycles"):
            fail(f"the same jump took {get('NEXT', late, 'cycles')} cycles on "
                 f"{machines[late]['name']} and {get('NEXT', base, 'cycles')} on "
                 f"{machines[base]['name']}, which decodes nothing; both ask for the line the "
                 f"cycle after the jump and it arrives a cache latency later, so the same -- "
                 f"a line fetched while decode looked is not simply there")
    for tag in ("XNOT", "XDEC"):
        checks += 1
        if get("FILLA", tag, "miss") != 1 or get("FILLB", tag, "miss") != 1:
            fail(f"the fill programs' branch mispredicted {get('FILLA', tag, 'miss')} and "
                 f"{get('FILLB', tag, 'miss')} times on {machines[tag]['name']}; it has to be "
                 f"wrong once for its wrong path to ask for the line")
        checks += 1
        if get("FILLA", tag, "cycles") != get("FILLB", tag, "cycles"):
            fail(f"a branch whose wrong path misses on the line its right path lands in took "
                 f"{get('FILLA', tag, 'cycles')} cycles waiting on an add and "
                 f"{get('FILLB', tag, 'cycles')} waiting on a multiply, on "
                 f"{machines[tag]['name']}; either way it resolves before the line arrives, "
                 f"and the line arrives when it was asked for, so the same")
    for tag in ("XWIDE", "TWIDE"):
        checks += 1
        if get("SKIPS", tag, "miss") or get("SKIPS", tag, "imiss") != 3:
            fail(f"a jump at the end of a line, then the line two past it: "
                 f"{get('SKIPS', tag, 'imiss')} instruction misses and "
                 f"{get('SKIPS', tag, 'miss')} mispredicts on {machines[tag]['name']}; fetch "
                 f"waited on the line between and never asked for that one, so the program "
                 f"misses on all 3 lines it runs")

    if not failures:
        print(f"  {name}: {lowered} direct targets lowered; {JUMPS} cold direct jumps "
              f"{get('JUMPS', 'XBIG', 'miss')} mispredicts, {get('JUMPS', 'XBIG', 'cycles')} = "
              f"{get('JUMPS', 'TBIG', 'cycles')} cycles on both engines, {JUMPS} indirect "
              f"{get('JRS', 'XBIG', 'miss')}; {more} more evictions cost exactly {penalty} each; "
              f"{get('EXIT', 'RUNS', 'miss')} mispredicts saved {saved} data misses; a decoded "
              f"target reached {fewer} fewer wrong-path instructions; {checks} checks")
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
        print("decode knows where a direct branch goes: SKIP")
        return DECLINED
    print(f"decode knows where a direct branch goes: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
