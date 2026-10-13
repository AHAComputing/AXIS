#!/usr/bin/env python3
"""Run a program through the generated C simulator and the Python executor.

`emit-sim-c` emits a machine: fetch from the pc, execute every lane of the word,
follow the pc it computes, and hand the host a hook table for memory, traps and
retirement. What that adds over the executor is the *loop* -- so this checks the
loop, by running a program to completion on both sides and comparing the whole
architectural delta: registers, memory, pc, step count and how it stopped.

The program branches. A straight-line one would pass on a simulator that ignored
`next_pc` entirely, which is the loop's only interesting property.

The reference is the Python executor, which makes this a chain link rather than
a fresh witness: whole-register model -> Python executor -> C executor ->
simulator. Said plainly because the gate proves agreement, not correctness.

Usage: tools/sim_vs_executor.py <input.axisl> [--programs N] [--length L]
"""

from __future__ import annotations

import argparse
import importlib.util
import collections
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llvm_effects_check import ByteMemory  # noqa: E402
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
MEMORY_BYTES = 1 << 14
# Where the program is loaded, and where its data lives. Far enough apart that a
# store cannot rewrite the instruction stream, which would make the two sides
# disagree for a reason that is not the loop.
TEXT_BASE = 0x0
DATA_BASE = 0x2000
REG_LIMIT = 1 << 10


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file),
                    "-o", str(output)], check=True, cwd=AXIS_ROOT)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def build_program(usable, isa, rng, length, plant=(), at_end=False, avoid=()):
    """A body of words the machine can actually run, drawn from the corpus.

    A uniform draw is a poor way to reach a branch. RV64I describes 337
    instructions and a handful of them redirect the pc, so eight programs of ten
    words can miss every one -- and did, the day the C extension was described
    and nineteen more non-branches joined the pool. The vacuity guard caught it,
    which is the guard working, but a test that reaches the loop only when the
    dice agree is not testing the loop. So one word of the program is planted
    rather than drawn.
    """
    # ⚠️ `avoid` is skipped PAST, not drawn around: the draw is the same draw,
    # and a word that may not be used is replaced by the next in the pool that
    # may. Drawing from a smaller pool instead moved every draw after it, in
    # every corpus -- and a corpus that had been reaching its branch by the
    # luck of those draws stopped.
    def pick():
        at = rng.randrange(len(usable))
        for step in range(len(usable)):
            entry = usable[(at + step) % len(usable)]
            if entry.get("mnemonic") not in avoid:
                return entry
        return usable[at]

    words = [int(pick()["encoded"], 16) for _ in range(length)]
    if plant:
        where = length - 1 if at_end else rng.randrange(length)
        words[where] = int(plant[rng.randrange(len(plant))]["encoded"], 16)
    return words


def redirects_pc(lift):
    """The mnemonics whose description sets the pc."""
    return {entry.get("mnemonic") for entry in lift.AXIS_LIFT_TABLE
            for effect in entry.get("effects") or []
            if effect.get("kind") == "setpc"}


def raises_trap(lift):
    """The mnemonics that raise a trap, grouped by the cause they raise.

    Grouped rather than pooled because the guard is written per cause. Twenty
    RV64I instructions can trap and eighteen of them are the dynamic-rounding
    FP forms, which raise only when the rounding mode says so; drawing from the
    pool reaches `ebreak` about one time in ten. Drawing from each cause in turn
    reaches all of them.
    """
    causes: dict = collections.defaultdict(set)
    for entry in lift.AXIS_LIFT_TABLE:
        for effect in entry.get("effects") or []:
            if effect.get("kind") == "trap":
                causes[effect.get("cause")].add(entry.get("mnemonic"))
    return causes


PROBE = r'''#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "axis_sim.h"

static uint32_t WORDS[] = {%(words)s};
static const size_t WORD_COUNT = sizeof(WORDS) / sizeof(WORDS[0]);
static size_t CURRENT = 0;
static uint8_t MEM[4096];

static uint64_t p_read(void *c, uint64_t a, uint32_t w) { (void)c; (void)a; (void)w; return 0; }
static void p_write(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; (void)a; (void)v; (void)w; }
static uint32_t p_fetch(void *c, uint64_t pc, int *ok) {
  (void)c; if (pc) { *ok = 0; return 0; } *ok = 1; return WORDS[CURRENT];
}
static uint64_t p_trap(void *c, const char *cause, uint64_t pc, int *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

int main(void) {
  static axis_state64_entry state[] = {%(state)s};
  memset(MEM, 0, sizeof MEM);
  for (CURRENT = 0; CURRENT < WORD_COUNT; ++CURRENT) {
    axis_sim sim;
    axis_sim_hooks hooks = { p_read, p_write, p_fetch, p_trap, NULL, NULL };
    axis_sim_init(&sim, &hooks, state, sizeof state / sizeof state[0]);
    sim.isa = %(isa)s;
    axis_sim_step(&sim);
    printf("P %%zu %%d\n", CURRENT, (int)sim.status);
  }
  return 0;
}
'''


def executable(fixtures, lift, workdir, isa):
    """Split the corpus into what this build runs and what it declines.

    Measured by asking the machine, one word at a time, rather than inferred: a
    word can decode and still have no 64-bit C evaluator -- the directed
    rounding-mode FP forms do not, which `docs/simd_fp_design.md` records -- and
    that is a property of the build, not of the program. The machine reports it
    as `unsupported` rather than as a hole in the instruction stream, and this
    names what it left out instead of quietly drawing around it.
    """
    candidates = [f for f in fixtures
                  if lift.decode_lanes(int(f["encoded"], 16), f.get("isa"))]
    if not candidates:
        return [], []
    source = PROBE % {
        "words": ",".join(f'{int(f["encoded"], 16)}u' for f in candidates),
        "state": ",".join(f'{{"{n}", 0, {w}u}}' for n, w in lift.STATE_SLOTS) or "{0}",
        "isa": f'"{isa}"' if isa else "NULL",
    }
    (workdir / "probe.c").write_text(source)
    subprocess.run(["cc", "-std=c11", "-DAXIS_IMPL_STUBS", "-I", str(workdir), "-o",
                    str(workdir / "probe"), str(workdir / "probe.c"), "-lm"],
                   check=True)
    result = subprocess.run([str(workdir / "probe")], capture_output=True,
                            text=True, check=True)
    # 2 is AXIS_SIM_UNSUPPORTED: decoded, and this build has no evaluator.
    status = {int(parts[1]): int(parts[2])
              for parts in (line.split() for line in result.stdout.splitlines())
              if parts and parts[0] == "P"}
    runs = [f for i, f in enumerate(candidates) if status.get(i) != 3]
    declined = sorted({f["mnemonic"] for i, f in enumerate(candidates)
                       if status.get(i) == 3})
    return runs, declined


def trace_line(lift, word, isa, pc, out, reads, writes, accesses):
    """One `axis.trace.v1` line, built from what the executor reported.

    Written here rather than shared with the C formatter on purpose: two
    independent constructions of the same bytes is the whole point. A shared
    formatter would agree with itself.
    """
    parts = [f"{pc:x} {word:08x} {out.get('mnemonic') or '?'}"]
    if reads:
        parts.append(" r=" + ",".join(f"{slot:x}" for slot in reads))
    if writes:
        parts.append(" w=" + ",".join(f"{slot:x}" for slot in writes))
    if out.get("writes"):
        parts.append(f" v={(out.get('result') or 0):x}")
    for is_write, addr, width, value in accesses:
        parts.append(f" m={'w' if is_write else 'r'}:{addr:x}:{width}:{value:x}")
    parts.append(f" n={out.get('next_pc', pc + 4):x}")
    if out.get("trap"):
        parts.append(f" t={out['trap']}")
    return "".join(parts)


class TapMemory:
    """A memory that records what passed through it, in order."""

    def __init__(self, inner):
        self.inner = inner
        self.log = []

    def read(self, addr, width):
        value = self.inner.read(addr, width)
        self.log.append((0, addr, width, value))
        return value

    def write(self, addr, value, width):
        self.inner.write(addr, value, width)
        self.log.append((1, addr, width, value & ((1 << width) - 1)))

    @property
    def data(self):
        return self.inner.data


def qualified_slot(lift, operand, decoded):
    """Which architectural register an operand names, as its first slot.

    A register *number* is ambiguous across files -- RISC-V's x5 and f5 are both
    5 -- and a dependence is between registers, not numbers. For a lane operand
    this is the register rather than the element, because two elements of one
    vector register are one register.
    """
    number = decoded + operand.get("register_bias", 0)
    if operand.get("view_width"):
        return operand["slot_base"] + number * max(operand.get("stride", 1), 1)
    return lift.register_slot(operand["kind"], number)


def touched(lift, word, isa):
    """The registers this word reads and writes, over every lane of it.

    A scalable word is its lanes, and a widening one writes a register group --
    lane 8's destination is a register past lane 0's. Naming only the decoded
    entry's would report whichever lane the executor happened to finish on.
    """
    reads, writes = [], []
    for entry in lift.decode_lanes(word, isa):
        bound = {}
        for operand in entry["operands"]:
            fields = operand["fields"]
            bound[operand["name"]] = lift._extract(word, fields) if fields else operand.get("fixed")
        for operand in entry["operands"]:
            source = operand.get("derived_from")
            if source:
                bound[operand["name"]] = bound[source] + operand["derived_add"]
        for operand in entry["operands"]:
            if not lift.is_register_operand(operand["kind"]):
                continue
            raw = bound.get(operand["name"])
            if raw is None:
                continue
            slot = qualified_slot(lift, operand, raw)
            if operand["role"] in ("in", "inout") and slot not in reads:
                reads.append(slot)
            if operand["role"] in ("out", "inout") and slot not in writes:
                writes.append(slot)
    return reads, writes


def python_run(words, regs, image, lift, executor, limit, isa):
    """The same program, stepped by the proven executor.

    Fetch is `words[pc / ILEN]`, which is the C harness's fetch hook written in
    Python: the loop being checked is the C one, so the reference's loop has to
    be the simplest thing that could serve.
    """
    memory = TapMemory(ByteMemory(image))
    state = {name: 0 for name, _width in lift.STATE_SLOTS}
    pc, steps, halted = 0, 0, None
    trace = []
    while steps < limit:
        index = pc // executor.ILEN
        if pc % executor.ILEN or index < 0 or index >= len(words):
            halted = "fetch"
            break
        memory.log.clear()
        reads, writes = touched(lift, words[index], isa)
        out = executor.step(words[index], regs, mem=memory, pc=pc, isa=isa,
                            state=state)
        if out is None:
            halted = "undecoded"
            break
        trace.append(trace_line(lift, words[index], isa, pc, out, reads, writes,
                                list(memory.log)))
        steps += 1
        if out.get("trap"):
            halted = out["trap"]
            # The machine's pc is 64 bits wide and wraps; Python's does not, and
            # a backward branch past zero would otherwise be compared as a
            # negative number against the same address written as an unsigned.
            pc = out.get("next_pc", pc + executor.ILEN) & 0xFFFFFFFFFFFFFFFF
            break
        pc = out.get("next_pc", pc + executor.ILEN) & 0xFFFFFFFFFFFFFFFF
    if halted is None:
        halted = "step limit"
    return {"regs": dict(regs), "mem": bytes(memory.data), "pc": pc,
            "steps": steps, "halt": halted, "state": state, "trace": trace}


HARNESS = r'''#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "axis_sim.h"

static uint32_t WORDS[] = {%(words)s};
static const size_t WORD_COUNT = sizeof(WORDS) / sizeof(WORDS[0]);
static uint8_t MEM[%(mem_bytes)d];

static uint64_t host_read(void *ctx, uint64_t addr, uint32_t width) {
  (void)ctx; uint64_t v = 0; uint32_t n = width / 8;
  if (addr + n > sizeof MEM) { return 0; }
  for (uint32_t i = 0; i < n; ++i) { v |= (uint64_t)MEM[addr + i] << (8 * i); }
  return v;
}
static void host_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {
  (void)ctx; uint32_t n = width / 8;
  if (addr + n > sizeof MEM) { return; }
  for (uint32_t i = 0; i < n; ++i) { MEM[addr + i] = (uint8_t)(value >> (8 * i)); }
}
/* Fetch is not a data read: the program lives in its own array, which is also
 * how a store cannot rewrite the instruction stream. */
static uint32_t host_fetch(void *ctx, uint64_t pc, int *ok) {
  (void)ctx;
  if (pc %% (uint64_t)AXIS_EXEC_ILEN || pc / AXIS_EXEC_ILEN >= WORD_COUNT) { *ok = 0; return 0; }
  *ok = 1; return WORDS[pc / AXIS_EXEC_ILEN];
}
/* A trap halts: the description said one happened and nothing has said what a
 * handler would do. The reference stops there too. */
static uint64_t host_trap(void *ctx, const char *cause, uint64_t pc, int *stop) {
  (void)ctx; (void)cause; *stop = 1; return pc;
}
static uint64_t RETIRED = 0;
static void host_retire(void *ctx, const axis_sim_event *event) {
  (void)ctx; RETIRED++;
  /* ⚠️ Sized by what the formatter says it wrote, not by a guess. A fixed
   * 512 bytes held any instruction until a kernel launch made 54 accesses,
   * and the line was cut at the 23rd -- a truncated trace compared against a
   * whole one, reported as a disagreement about the machine. */
  char stack[512];
  int need = axis_sim_trace_line(event, stack, sizeof stack);
  char *line = stack;
  if (need >= (int)sizeof stack) {
    line = malloc((size_t)need + 1);
    if (!line) { abort(); }
    axis_sim_trace_line(event, line, (size_t)need + 1);
  }
  printf("T %%s\n", line);
  if (line != stack) { free(line); }
}

int main(void) {
  static axis_state64_entry state[] = {%(state)s};
  axis_sim sim;
  axis_sim_hooks hooks = { host_read, host_write, host_fetch, host_trap,
                           host_retire, NULL };
  axis_sim_init(&sim, &hooks, state, sizeof state / sizeof state[0]);
  sim.isa = %(isa)s;
  memcpy(MEM, (const uint8_t[]){%(image)s}, sizeof MEM);
  %(seed)s
  axis_sim_run(&sim, %(limit)d);
  printf("HALT %%s\n", sim.halt_reason ? sim.halt_reason : "?");
  printf("PC %%llu\n", (unsigned long long)sim.pc);
  printf("STEPS %%llu\n", (unsigned long long)sim.steps);
  printf("RETIRED %%llu\n", (unsigned long long)RETIRED);
  for (size_t i = 0; i < AXIS_SIM_REG_SLOTS; ++i) {
    printf("R %%zu %%llu\n", i, (unsigned long long)sim.regs[i]);
  }
  for (size_t i = 0; i < sizeof MEM; ++i) {
    if (MEM[i]) { printf("M %%zu %%u\n", i, MEM[i]); }
  }
  for (size_t i = 0; i < sim.state.count; ++i) {
    printf("S %%s %%llu\n", sim.state.entries[i].name,
           (unsigned long long)sim.state.entries[i].value);
  }
  return 0;
}
'''


#: Corpora this gate cannot yet drive, each with the reason. ⚠️ A name here is
#: a corpus the sweep INTENDED to check and did not, which is the number that
#: used to go missing entirely -- the gate ran on five of fifty-six and nothing
#: said so.
UNREACHED = {
    # ⚠️ Measured, not guessed. `VSTW` and `VBRZ` encode to the same word and
    # are told apart by the UNIT that issues them -- `mem` against `br`, which
    # is the packet slot the syllable sits in. Asked without one the decoder
    # correctly answers nothing, and this harness has no way to say: it steps a
    # word at a time with no notion of which slot it came from.
    #
    # The first two entries here were `scalable_memory` and `scalable_vtype`,
    # with reasons about lane addressing and `vsetvli` that were invented
    # rather than measured. Both were the same one-line bug -- a trace record
    # bounded per entry instead of per word -- and both pass now. A reason
    # nobody checked is worth less than no reason at all.
    "vliw_packet": "two syllables share an encoding and are told apart by the "
                   "unit that issues them; this harness steps a word at a time "
                   "and cannot say which slot it came from",
}


def sweep_all(args) -> int:
    """Every corpus, with what happened to each.

    One gate rather than fifty-six: the ladder pays for a process per corpus
    either way, and the number worth reporting is how many of the descriptions
    this machine can actually run -- not whether one of them passed.
    """
    root = AXIS_ROOT / "examples"
    passed, failed, skipped, unreached = [], [], [], []
    for path in sorted(root.glob("*.axisl")):
        name = path.stem
        if name in UNREACHED:
            unreached.append(name)
            continue
        done = subprocess.run(
            [sys.executable, str(Path(__file__)), str(path),
             "--programs", str(args.programs), "--length", str(args.length)],
            capture_output=True, text=True, cwd=AXIS_ROOT)
        tail = done.stdout.splitlines()[-1] if done.stdout else ""
        if "SKIP" in done.stdout:
            skipped.append(name)
        elif tail.endswith("PASS"):
            passed.append(name)
        else:
            failed.append(name)
            print(f"FAIL {name}")
            for line in done.stdout.splitlines()[-4:]:
                print(f"    {line}")
    print(f"{len(passed)} corpus(es) the simulator and the executor agree on, "
          f"{len(failed)} disagree, {len(skipped)} with no fixture to run")
    for name in unreached:
        print(f"  not driven: {name} -- {UNREACHED[name]}")
    print("simulator == executor, every corpus:",
          "FAIL" if failed else "PASS")
    return 1 if failed else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?")
    parser.add_argument("--programs", type=int, default=8)
    parser.add_argument("--length", type=int, default=10)
    parser.add_argument("--limit", type=int, default=64)
    parser.add_argument("--seed", type=lambda s: int(s, 0), default=0x5140)
    parser.add_argument("--all", action="store_true",
                        help="run every corpus in examples/ and report the counts")
    args = parser.parse_args()
    if args.all:
        return sweep_all(args)
    if args.axis_file is None:
        parser.error("a corpus, or --all")

    workdir = Path(tempfile.mkdtemp(prefix="axis_sim_"))
    for command, name in (("emit-lift-python", "axis_lift.py"),
                          ("emit-golden-python", "golden_model.py"),
                          ("emit-exec-python", "axis_exec.py"),
                          ("emit-lift-c", "axis_lift.h"),
                          ("emit-semantics-c", "axis_semantics.h"),
                          ("emit-exec-c", "axis_exec.h"),
                          ("emit-sim-c", "axis_sim.h")):
        emit(args.axis_file, command, workdir / name)
    fixtures_path = workdir / "fixtures.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)
    sys.path.insert(0, str(workdir))
    lift = load(workdir / "axis_lift.py", "axis_lift")
    load(workdir / "golden_model.py", "golden_model")
    executor = load(workdir / "axis_exec.py", "axis_exec")
    fixtures = json.loads(fixtures_path.read_text())["tests"]

    rng = random.Random(args.seed)
    slots = lift.REGISTER_FILE_SLOTS
    # What this corpus can even exercise. `setpc` is how a description redirects
    # the pc, and a `trap` effect is how it raises one.
    can_branch = any(effect.get("kind") == "setpc"
                     for entry in lift.AXIS_LIFT_TABLE
                     for effect in entry.get("effects") or [])
    trap_causes = {effect.get("cause") for entry in lift.AXIS_LIFT_TABLE
                   for effect in entry.get("effects") or []
                   if effect.get("kind") == "trap"}
    can_trap = bool(trap_causes)
    # ⚠️ One pool per ISA, and every word of a program drawn from ONE of them.
    # This used to take a single ISA -- the first fixture's -- and then draw
    # from every fixture in the corpus. On a single-ISA corpus that is the same
    # thing, which is why it went unnoticed: the four this gate is registered
    # for describe one machine each. AArch64 describes two, `aarch64_base` and
    # `accelerator_scalar64`, so 435 of its 917 words were handed to a decoder
    # told they were something else. They did not decode, the executor halted
    # `undecoded` where the simulator retired a `?`, and every such program was
    # a disagreement about a question neither had been asked properly.
    isas = sorted({f.get("isa") for f in fixtures}, key=lambda name: name or "")
    pools: list = []
    declined: list = []
    for isa in isas:
        mine = [f for f in fixtures if f.get("isa") == isa]
        runs, left = executable(mine, lift, workdir, isa)
        declined.extend(left)
        if runs:
            pools.append((isa, runs))
    declined = sorted(set(declined))
    if not pools:
        print("SKIP: no fixture this machine can run")
        return 0
    # The branch words this build can actually run, so half the programs are
    # guaranteed to contain one instead of hoping the draw supplies it. Per
    # pool, because a branch from one ISA is not a branch the other decodes.
    redirecting, raising = redirects_pc(lift), raises_trap(lift)
    plans = []
    for isa, runs in pools:
        by_cause = {cause: [f for f in runs if f.get("mnemonic") in names]
                    for cause, names in raising.items()}
        raising_any = {name for names in raising.values() for name in names}
        plans.append({
            "isa": isa,
            "usable": runs,
            "branchy": [f for f in runs if f.get("mnemonic") in redirecting],
            "by_cause": by_cause,
            "causes": sorted(c for c, group in by_cause.items() if group),
            "trapping": bool(raising_any & {f.get("mnemonic") for f in runs}),
            # The pool a branch program draws from: everything that cannot
            # trap, so an unrelated trap does not end the program before the
            # branch it was built to take.
            "untrapping": [f for f in runs if f.get("mnemonic") not in raising_any],
        })
    failures = branched = traced = 0
    halts: set[str] = set()
    for program_index in range(args.programs):
        # A branch in the odd programs, a trap in the even ones, taking the
        # causes in turn. The trap goes in the last slot so the program still
        # runs its whole body first -- a trap planted in the middle would test
        # the hook and nothing after it.
        # Round robin rather than a draw: with two ISAs and eight programs a
        # random pick reaches both about nine times in ten, and a gate that
        # covers a machine nine runs in ten is a gate that does not cover it.
        plan = plans[program_index % len(plans)]
        isa, usable = plan["isa"], plan["usable"]
        # ⚠️ A BRANCH is guarded the same way a TRAP is. `lisp_behaviors` writes
        # `(when (eq rs1 rs2) (setpc ...))` and `(when (eq rs1 rs2) (trap ...))`,
        # so the register seeding that makes one fire makes the other fire too --
        # and the trap halts the program. Giving both to the same programs meant
        # the branch-planted ones had random registers and never branched, while
        # the trap-planted ones stopped at the first drawn trap, before any
        # branch. The corpus described a loop, the gate could not reach it, and
        # the vacuity guard said so for as long as this ran on corpora whose
        # branches are unconditional.
        #
        # So the two get their own programs. A branch program seeds every
        # register alike AND draws from a pool with the trap-raisers removed;
        # a trap program keeps both.
        trapping = plan["trapping"]
        branch_turn = program_index % 2 == 1 or not plan["causes"]
        if branch_turn:
            plant, at_end = plan["branchy"], False
            pool = plan["untrapping"] or usable
        else:
            cause = plan["causes"][(program_index // 2) % len(plan["causes"])]
            plant, at_end = plan["by_cause"][cause], True
            # ⚠️ And a trap program draws nothing that can send the pc away: the
            # trap is in the LAST slot so that the body runs first, and a body
            # with a jump in it never gets there. With few instructions most
            # draws had none; three more in one corpus, and all four of its
            # trap programs left by a jump before the trap -- "halts seen:
            # fetch" -- and the gate said, rightly, that the hook was untested.
            leaving = {f.get("mnemonic") for f in plan["branchy"]}
            pool = usable
        words = build_program(pool, isa, rng, args.length, plant, at_end,
                              () if branch_turn else leaving)
        image = bytes(rng.getrandbits(8) for _ in range(MEMORY_BYTES))
        # Every register the same, for both. A guard comparing two of them is
        # otherwise taken about once in a thousand, and the guarded branch and
        # the guarded trap are the two things that make this a machine rather
        # than a harness.
        shared = rng.randrange(REG_LIMIT) & ~7
        regs = {i: shared for i in range(slots)}
        if trapping and branch_turn and not plan["untrapping"]:
            # Nothing to draw that cannot trap, so equal registers would halt
            # this program too. Fall back to a random seed and let the vacuity
            # guard say the loop went untested, which is the truth.
            regs = {i: rng.randrange(REG_LIMIT) & ~7 for i in range(slots)}
        want = python_run(words, dict(regs), image, lift, executor, args.limit, isa)
        halts.add(want["halt"])
        if want["steps"] and want["pc"] != want["steps"] * executor.ILEN:
            branched += 1

        seed = "\n  ".join(f"sim.regs[{i}] = {v}ull;" for i, v in sorted(regs.items()))
        source = HARNESS % {
            "words": ",".join(f"{w}u" for w in words),
            "mem_bytes": MEMORY_BYTES,
            "image": ",".join(str(b) for b in image),
            "state": ",".join(f'{{"{n}", 0, {w}u}}' for n, w in lift.STATE_SLOTS)
                     or "{0}",
            "isa": f'"{isa}"' if isa else "NULL",
            "seed": seed,
            "limit": args.limit,
        }
        (workdir / "harness.c").write_text(source)
        subprocess.run(["cc", "-std=c11", "-DAXIS_IMPL_STUBS", "-I", str(workdir), "-o",
                        str(workdir / "harness"), str(workdir / "harness.c"), "-lm"],
                       check=True)
        result = subprocess.run([str(workdir / "harness")], capture_output=True,
                                text=True, check=True)
        got = {"regs": {}, "mem": {}, "state": {}, "trace": []}
        for line in result.stdout.splitlines():
            head, _, rest = line.partition(" ")
            if head == "HALT":
                got["halt"] = rest
            elif head == "PC":
                got["pc"] = int(rest)
            elif head in ("STEPS", "RETIRED"):
                got[head.lower()] = int(rest)
            elif head == "R":
                index, value = rest.split()
                got["regs"][int(index)] = int(value)
            elif head == "M":
                addr, value = rest.split()
                got["mem"][int(addr)] = int(value)
            elif head == "S":
                name, value = rest.split()
                got["state"][name] = int(value)
            elif head == "T":
                got["trace"].append(rest)

        for label, mine, theirs in (
                ("halt", got["halt"], want["halt"]),
                ("pc", got["pc"], want["pc"]),
                ("steps", got["steps"], want["steps"])):
            if mine != theirs:
                failures += 1
                print(f"FAIL {label}: simulator {mine!r} != executor {theirs!r}")
        # The trace, line for line. Two independent constructions of the same
        # bytes -- the machine formats its own event, the reference builds one
        # from what the executor reported -- so a shared formatter could not
        # hide a disagreement about what an instruction did.
        if got["trace"] != want["trace"]:
            failures += 1
            pairs = list(zip(got["trace"], want["trace"]))
            differing = next((i for i, (a, b) in enumerate(pairs) if a != b),
                             min(len(got["trace"]), len(want["trace"])))
            print(f"FAIL trace line {differing}:")
            if differing < len(got["trace"]):
                print(f"    simulator {got['trace'][differing]}")
            if differing < len(want["trace"]):
                print(f"    executor  {want['trace'][differing]}")
        traced += len(got["trace"])
        # Retire fires once per instruction, which is what makes the machine
        # observable; a hook that never fired would be invisible otherwise.
        if got["retired"] != got["steps"]:
            failures += 1
            print(f"FAIL retire fired {got['retired']} times for "
                  f"{got['steps']} steps")
        for index in range(slots):
            if got["regs"].get(index, 0) != want["regs"].get(index, 0):
                failures += 1
                print(f"FAIL reg {index}: simulator {got['regs'].get(index, 0):#x}"
                      f" != executor {want['regs'].get(index, 0):#x}")
                break
        want_mem = {i: b for i, b in enumerate(want["mem"]) if b}
        if got["mem"] != want_mem:
            differing = sorted(set(got["mem"]) ^ set(want_mem))[:1] or [
                next(i for i in got["mem"] if got["mem"][i] != want_mem.get(i))]
            failures += 1
            print(f"FAIL memory at {differing[0]:#x}")

    print(f"{args.programs} programs of {args.length} words, {failures} failures")
    print(f"  {traced} trace line(s) compared byte for byte")
    print(f"  {branched} redirected the pc; halts seen: "
          f"{', '.join(sorted(halts))}")
    if declined:
        shown = ", ".join(declined[:4])
        more = f" (+{len(declined) - 4} more)" if len(declined) > 4 else ""
        print(f"  {len(declined)} instruction(s) this build cannot evaluate, "
              f"left out: {shown}{more}")
    ok = failures == 0
    # Coverage of what this corpus offers, rather than of a fixed list. A
    # description with no branch cannot exercise the pc path and should not be
    # asked to; one that has branches and never took one proves nothing about
    # the loop, since a straight-line program passes on a simulator that ignores
    # `next_pc` entirely.
    if not traced:
        print("no trace line was compared: the retire record is untested")
        ok = False
    if can_branch and not branched:
        print("the corpus branches and no program did: the loop is untested")
        ok = False
    if can_trap and not (halts & trap_causes):
        print(f"the corpus raises {sorted(trap_causes)} and no program did: "
              f"the trap hook is untested")
        ok = False
    print("simulator == executor: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
