# A functional ISA simulator

Status: **built.** `emit-sim-c` exists and is not this: it is a block
interpreter over pre-decoded straight-line words, on the 32-bit ABI, with no
fetch, no architectural state, no branching within a block, and a register model
that predates register classes (`strcmp(kind, "reg")`). It was a JIT on-ramp.
This is a machine.

## 1. What a functional simulator is, that an executor is not

`axis_exec_step64` executes *a word you hand it* against a register file you own.
Everything else a simulator does, the caller currently does:

| | executor | simulator |
|---|---|---|
| where the next word comes from | caller | fetch, from the pc |
| what the pc becomes | returned | applied, and followed |
| memory | a callback pair | the same callback pair |
| a trap | reported | delivered to a handler that decides what happens next |
| stopping | caller counts | a halt condition the host owns |
| observing | caller diffs registers | a retire hook per instruction |

So the simulator is a loop plus a **hook table**, and the design question is
which hooks — too few and the host cannot model its machine, too many and every
one is a thing that must be proven.

## 2. The hooks, and why each one exists

```c
typedef struct axis_sim_hooks {
  /* Memory. The same pair the wide executor already takes, because the
     instruction semantics do their own accesses through it. */
  uint64_t (*read)(void *ctx, uint64_t addr, uint32_t width);
  void     (*write)(void *ctx, uint64_t addr, uint64_t value, uint32_t width);

  /* Fetch. Separate from `read` because an instruction fetch is not a data
     access: a host may serve it from a different space, log it differently, or
     refuse it. Returning 0 in `ok` halts the machine at this pc. */
  uint32_t (*fetch)(void *ctx, uint64_t pc, int *ok);

  /* A trap the description raised. The host decides what happens next: return
     the pc to continue from, or leave `*stop` set to halt. Without this a
     simulator can only stop on a trap, which is not what a machine does. */
  uint64_t (*trap)(void *ctx, const char *cause, uint64_t pc, int *stop);

  /* Retire. Called after each instruction with what it did. This is what makes
     the simulator observable -- tracing, instruction counting, a debugger --
     without the loop having to know why anyone is watching. */
  void (*retire)(void *ctx, const axis_sim_event *event);

  void *ctx;
} axis_sim_hooks;
```

`fetch` and `trap` are the two that decide whether this is a machine or a
harness. Everything else could be bolted on outside the loop.

**Not hooks, deliberately:**

* *Interrupts.* An interrupt is a host decision to redirect the pc, which the
  host can do between steps by writing `sim->pc`. A hook would add a place for
  the loop to be wrong without adding anything the host cannot already do.
* *System calls.* `ECALL` is a trap with a cause. Giving it its own hook would
  mean the loop deciding which traps are system calls, which is the
  description's business, not the loop's.
* *MMIO.* An address range the host recognises inside `read`/`write`.

## 3. What the loop does

    fetch(pc) -> word
    execute every lane of the word          (axis_exec_step64)
    apply: registers and memory already written by the executor
           state written through the state array
           pc <- next_pc, or trap(cause) -> pc
    retire(event)

The executor already writes registers, memory and state; the simulator's own
state is the pc, the step count, and the halt reason. That is the whole of it,
and it is deliberately small: everything hard is in the executor, which is
proven, and everything host-specific is behind a hook.

## 4. What the gate has to be

Not "it runs" — a simulator that executes nothing runs fine. The gate is a
**program**: a block of real instructions, including branches and memory, run to
completion by the C simulator and by the Python executor stepping the same
words, compared on the whole architectural delta — registers, memory, pc, step
count, and the trap that stopped it.

That makes the reference the Python executor, which is a chain link rather than
a fresh witness. The chain is: whole-register model (`scalable_exec_check`) ->
Python executor -> C executor (`--lang c`) -> simulator. Each link is a
differential gate; the first is a model. Worth saying plainly, since the
simulator's own gate proves agreement, not correctness.

The program has to *branch*, or the loop's only interesting property -- that the
pc it computes is the pc it fetches from next -- is untested. A straight-line
program would pass on a simulator that ignored `next_pc` entirely.

## 5. Built

`emit-sim-c` emits a machine over the proven wide executor, with the hook table
above. The loop is small on purpose: the executor writes registers, memory and
state, so the simulator's own state is the pc, the step count and the halt
reason. Four gates run whole programs against the Python executor and compare
registers, memory, pc, step count and halt reason.

### Two answers where there was one

`!ok` from the executor used to be one thing. It is two, and a host needs to
tell them apart:

* `AXIS_SIM_UNDECODED` — the word decodes to nothing. A hole in the program.
* `AXIS_SIM_UNSUPPORTED` — it decodes and this build has no evaluator for it.
  A hole in the *build*: the directed rounding-mode FP forms have no 64-bit C
  evaluator, which `docs/simd_fp_design.md` §8 records for the other backends
  too. 30 of RV64I's instructions, named by the gate rather than drawn around.

Neither is handed to the trap hook, because neither is a trap the description
raised, and inventing a cause it never named would be worse than reporting the
pc it happened at.

### Two C bugs the simulator found

Both in the area the C arm of `scalable_exec_check` had *declined* — which is
the argument for declining by name rather than skipping quietly, since the
decline is what said where to look next.

* **Effect handlers wrote whole registers.** A lane writes one element; the
  handlers used the class-based helpers rather than the operand's placement, so
  every program containing a vector load or store diverged from the executor.
  Single instructions passed: it took a program to show it, because the pure
  path was already right and the corpus's memory forms only appear in sequences.
* Earlier, and on the way in: **the wide C comparison masked one side**. See
  the commit; it is the same class of defect one level down.

### What the gate measures, and what it does not

The reference is the Python executor, so this is a chain link: whole-register
model → Python executor → C executor → simulator. It proves agreement, not
correctness, and the first link is the only model in it.

Coverage follows the corpus rather than a fixed list. A description with no
branch cannot exercise the pc path and is not asked to; one that branches and
never took one fails, because a straight-line program passes on a simulator that
ignores `next_pc` entirely. The same for traps. Measured on four injected loop
bugs -- ignoring `next_pc`, never retiring, not halting on a trap, not counting
steps -- each caught by the corpus that can see it and not by the one that
cannot.

### And then it was pointed at a fifth corpus

The gate ran on four corpora: RV64I, traps, SVE, RVV. AArch64 was not among
them, and the first run against it failed sixteen times out of eight programs.
Two defects, one behind the other.

**A program has to stay inside one ISA.** `build_program` took a single ISA --
the first fixture's -- and then drew words from every fixture in the corpus. On
a corpus describing one machine that is the same thing, which is exactly why
four corpora never showed it. AArch64 describes two, `aarch64_base` and
`accelerator_scalar64`, so 435 of its 917 words were handed to a decoder told
they were something else. They did not decode; the executor halted `undecoded`
where the simulator retired a `?`; and every such program was scored as a
disagreement about a question neither machine had been asked properly. There is
a pool per ISA now, and programs take the pools in turn rather than by a draw --
with two ISAs and eight programs a random pick reaches both about nine times in
ten, and a gate that covers a machine nine runs in ten does not cover it.

**Then the real one: both executors kept half of every 128-bit value.**
`axis_mem64`'s read returns a `uint64_t`. `axis_read_operand64` returns one.
Rust's twin is `u64`. So `LDUR_Q` was emitted as `mem->read(..., 128u)` into a
64-bit variable, wrote a 64-bit value into a 128-bit register, and reported
`ok`. `BSL_V` states itself as `formal` rather than as a behavior and reached
the eval path instead, where it was evaluated at 64 bits with the other half
dropped -- so the guard had to go on both paths.

Being unable to perform these is a limit, and a fine one. Answering them wrongly
is not. No effect function and no evaluator is emitted for them now, which is
the existing way an executor says it cannot evaluate something -- the same path
the directed rounding-mode forms take -- and a host sees `unsupported` instead
of a number that is half right. Exactly **20** instructions, in both executors.

⚠️ That number is the tell. `exec_wide_check` has been reporting "20 case(s)
past the 64-bit register slot, not executed" all along, beside "1778 executed at
64 bits". It knew the population precisely and declined to execute it, and the
gate is called `A64 wide C exec`. The truncation was not hiding; it was in the
one place nothing compared, under a name that said the opposite. A gate that
finds two defects the first time it is pointed at a corpus was pointed at too
few corpora, so AArch64 is registered now.

### And then the other fifty-one

Pointing it at a fifth corpus found two defects. Pointing it at all of them
found three more, and each was in something else.

**A guarded branch and a guarded trap are the same guard.** `lisp_behaviors`
writes `(when (eq rs1 rs2) (setpc ...))` and `(when (eq rs1 rs2) (trap ...))`,
so the register seeding that makes one fire makes the other fire too. The
harness gave both to the same programs: the branch-planted ones had random
registers and never branched, and the trap-planted ones stopped at the first
drawn trap, before any branch. The corpus described a loop and the gate could
not reach it. Branch programs now seed every register alike and draw from a pool
with the trap-raisers removed; trap programs keep both.

**A 128-bit value in a 64-bit register.** `simd_q_lanes` and `simd_fp_lanes`
declared `i128` operands in the `reg` class, which is one 64-bit slot. Nothing
said so, because nothing executed them: `exec_wide_check` counted all eight as
past its driver's width, and `wide_arith_check` was registered only for AArch64.

⚠️ The executor sizes a wide access from the OPERAND's declared width, so it
wrote two slots into a one-slot register -- `VADD_4S vd=1` wrote `regs[1]` and
`regs[2]`, and `regs[2]` was its own source operand. Measured:

```
    regs[1] = 0x0000000055540005   <- CHANGED
    regs[2] = 0x0000000055540007   <- CHANGED     (before)
    regs[2] = 0x00000000aaaa0002                  (after)
```

Three things followed. The generated read and write clamp to the class's limb
count, so no generated access leaves the register it names. Validation refuses
an operand wider than its class -- ⚠️ except a lane operand, whose value sits
inside the register at a position VL decides, which no compile-time class can
state; checking those refused six legal `(SEW, LMUL)` points that the RVV sweep
proves legal. And the two corpora name `reg128`, which holds what they said they
held.

**A reference that gave the less true answer.** An instruction naming an
implementation routine made the C executor call it and report `unimplemented`,
while the Python executor -- which knew nothing about routines -- fell through
to `undecoded`. Two backends disagreeing about why they stopped, with the
reference wrong. The lift table carries the implementation now and the reference
declines by name.

**One more thing that only agreed because both sides were truncated.**
`exec_vs_golden`'s `register_view` returned the first slot for a class with no
view, so a 128-bit register read back as 64 bits and matched a golden answer
nobody had narrowed. It held for as long as the only wide corpora declared their
operands in a one-limb class: two errors cancelling, and the second fix exposed
the first.

### A reason nobody checked is worth less than no reason

Three corpora went into the sweep's not-driven list with reasons about lane
addressing, `vsetvli` and packet fetch width. ⚠️ **Two of those reasons were
invented.** I had not measured them; they were plausible readings of a failure I
had glanced at.

Both were the same one-line bug, and it was in the trace record. `#define
AXIS_SIM_MAX_READS` was computed from the widest single *entry*'s operand count,
and `axis_sim_note` silently dropped anything past it. For `scalable_vtype` that
bound was **2**, and `VNSRA_WV` -- which narrows, so each source spans a register
pair over four lanes -- recorded two of its four reads and said nothing. The
values agreed; only the dependence set was short.

The *accesses* bound beside it had already been fixed this way, with a comment
saying "a bound taken from one entry truncated a sixteen-lane load to its first
two accesses". The register bound was left behind. It is per word now, and
`axis_sim_note` returns whether the slot fit, so the next description that
outgrows the bound is found rather than quietly under-reported.

`vliw_packet` is genuinely not driven, and the reason is not the one I wrote
either. `VSTW` and `VBRZ` encode to the **same word** and are told apart by the
unit that issues them -- `mem` against `br`, which is the packet slot the
syllable occupies. Asked without one, the decoder correctly answers nothing.
This harness steps a word at a time and has no notion of which slot it came
from. That is a real limitation of the harness, measured rather than guessed.

The gate runs on **every** corpus in one pass: 51 agree, 4 have no fixture this
machine can run, and 1 is named as not driven. A name there is a corpus the
sweep intended to check and did not, which is the number that used to go missing
entirely -- and the reason beside it has to be one somebody checked.

## 6. Traces, for a timing model

A cycle-accurate model needs to know *when* things happen and must not need to
know what an instruction computes. If it carries its own functional model, that
is a second implementation of the ISA which can disagree with the description --
the failure this repo exists to prevent. So the machine emits what a timing
model consumes and nothing more: a retire record per instruction.

    <pc> <word> <mnemonic> r=<slot>[,<slot>] w=<slot>:<value>
    m=<r|w>:<addr>:<width>:<value>[ ...] n=<next_pc>[ t=<cause>]

`axis.trace.v1`. Absent fields are omitted rather than emitted empty, so a line
says only what happened. The formatter is generated with the machine, because a
trace whose format each consumer invents is a trace no two of them can compare.

Two design choices worth stating:

* **Memory accesses come from wrapping the host's own hooks**, not from the
  executor. The effect handlers already go through that pair, so a wrapper sees
  every access and nothing about what is proven changes.
* **Source registers come from the same decode**, not from the result. Which
  registers an instruction reads is a fact about the instruction; the executor's
  answer is the same either way, so asking it would have meant changing the
  thing under test to observe it.

### The gate

The same program, traced by the machine and by a reference that builds its own
lines from what the Python executor reported, compared **byte for byte**. Two
independent constructions on purpose: a shared formatter would agree with
itself. Injecting a dropped read, a dropped access, or a flipped read/write flag
each fails it.

### Two bugs it found immediately

* **The C lifter did not know about lanes.** The executor had been taught that
  several matches from one scalable origin are one instruction; `axis_lift_*`
  had not, so a scalable word lifted to nothing and its trace lost every source
  register while executing perfectly well. The rule now lives in all three
  places that decode.
* **The access bound was per entry, not per word.** A scalable instruction
  retires once and makes an access per lane, so a sixteen-lane load truncated to
  its first two accesses. The bound is now the whole lane group's.

### Registers, named so a dependence can be found

A trace whose registers are *numbers* is useless to the thing it exists for.
RISC-V's `x5` and `f5` are both 5, so a read of one and a write of the other
look like a dependence that is not there. The trace names the slot each register
*starts at*, which is unique across files -- and for a lane operand that is the
register rather than the element, because two elements of one vector register
are one register.

It names **every** register the word touches, over every lane. A widening
multiply writes a register group: lane 8's destination is a register past lane
0's, and a dependence on the second half of that group is a dependence. The
first version reported one destination, which meant whichever lane the executor
happened to finish on -- the two sides disagreed about `VWMUL_VV` and that is
how it surfaced.

    r=<slot>[,<slot>]   read, deduplicated, in first-touch order
    w=<slot>[,<slot>]   written, the same
    v=<value>           the value the executor reported, when it wrote

Three injections, and the split says something: dropping a written register
fails everywhere; collecting only the decoded lane passes on RV64I and fails on
RVV; reporting a register *number* instead of a qualified slot fails on RVV and
-- on RV64I -- **passes at `--length 6` and fails at `--length 8`**. RV64I has
two register files, so it can see that bug; whether it does depends on whether
the sample happened to include a floating-point instruction. The same injection,
the same corpus, a different verdict from one more instruction per program.
That is `docs/gate_coverage.md`'s argument in miniature, found by accident while
checking something else.

### What a retire trace cannot do

It has no wrong-path instructions, because those never retire -- a model that
wants misprediction cost needs a fetch-side trace or the ability to drive the
machine down a path it will discard. 

## Cycles, to a first order

Every instruction in every corpus carries a `latency` and a `throughput`, and
until now nothing read them. A number beside the semantics that nothing reads
is free text, and a co-design result built on one is a quotation of its author.

The simulator has a scoreboard now: in order, single issue, keyed on the
registers each instruction names.

```
issue    = max(issue_free, max over sources of ready[slot])
ready[d] = issue + latency          for each destination
issue_free = issue + ceil(1000 / throughput_milli)
```

Eight chained `MUL`s, which RV64I declares at three cycles, take **22** cycles;
the same eight with no dependence between them take **8**. The ratio is the
number the designer wrote, which is the point: the declaration is now
load-bearing.

⚠️ **It is first-order and the name says so.** No memory hierarchy, no branch
prediction, no superscalar issue, no forwarding network beyond "the value is
ready when the latency says". What it can tell you is a dependent chain from an
independent stream, which an instruction count cannot do at all. What it cannot
tell you is what a real pipeline does, and a gate that pretended otherwise
would be the more expensive mistake.

⚠️ **Counted on the interpreted path only.** Translated bytes call nothing, so
a run with the JIT enabled reports no cycles -- the same trade the retire hook
makes, and said rather than silently leaving the figure at zero. Counting also
means *stepping*: the fast path hands a whole run to `axis_sim_run`, which never
returns between instructions, so a scoreboard hung on the step wrapper saw
nothing and reported zero cycles for a program that plainly took some.

`tools/cycle_check.py` holds it by **properties**, not by a second copy of the
arithmetic -- that would be a model agreeing with itself. A chain costs its
latency each; the same instructions independent cost their issue interval; the
ratio is the declared latency; and cycles never run ahead of instructions at
throughput 1. Three mutations, three caught: every instruction at latency one,
a dependence that does not delay issue, an issue port that is never busy.

## A program, not an instruction

Every library here answers a question about an instruction. `tools/run_workload.py`
runs a **program**: it loads an image, starts at its entry point, and runs until
the program stops itself.

```
$ tools/run_workload.py examples/rv64i.axisl big.elf --isa rv64i --cycles
big.elf: 513 instruction(s) retired, stopped 1 ecall
  513 cycle(s) by the description's own latencies (1.00 per instruction)
  2.9 ms, 0.17 MIPS

$ tools/run_workload.py examples/rv64i.axisl big.elf --isa rv64i --jit
big.elf: 513 instruction(s) retired, stopped 1 ecall
  496 instruction(s) ran as translated code across 17 block(s)
  1.9 ms, 0.27 MIPS
```

⚠️ That is the shape a co-design question has. *Is this extension worth it* is
not a question about one instruction, and until something could load and run a
workload the stack could only answer the first kind.

`tools/axis_image.py` reads ELF64 program headers -- **segments and an entry
point**, which is a different question from the one `binary_coverage.py` asks of
the same format. That reads *sections*, to say which bytes a description
decodes. Two readers because they are two questions; sharing one would make a
coverage report depend on a program being loadable.

### The ABI, which is one sentence

A program stops by **trapping** -- `ecall`, `brk` -- and the host agrees that a
trap ends the run. No file descriptors, no heap, no arguments. A workload that
needs those needs a syscall layer, and that is a decision about what the machine
promises rather than a missing feature here.

### What the gate holds, and the byte that hid

`tools/workload_check.py` builds a program out of the corpus's own fixtures --
no cross-compiler in the loop, so the expected counts are arithmetic rather than
observation -- writes it as an ELF, and requires: the loader puts the bytes
where the file says and nowhere else, the machine starts at the entry point, the
program runs exactly as many instructions as it contains, it stops because it
asked rather than because a limit ran out, and the cycles are at least the
instructions.

⚠️ Checking the *contents* was not enough. A loader that drops a segment's last
byte is invisible whenever that byte is zero -- and RISC-V's `ecall` is
`0x00000073`, so the program this gate builds ends in one. The mutation passed
until the gate also compared the segment's **length**.
