# Vector units in the pack simulator

Status: **VM1–VM3 and VU1–VU4 implemented** (a vector instruction is one
instruction in the pipeline, Arm's SVE and SME included; a unit has lanes, may
count them by the elements worked on, may lend the idle ones, and may be one
unit shared by several cores). Companion to
`docs/ooo_design.md`, whose window, units and engines this extends, and to
`docs/spatial_backend_design.md`, whose candidates VU3–VU4 would let the
generated simulator run. `docs/pack_simulator.md` is the overview of the
simulator these units live in.

## 1. What was asked, and what was found first

The request: vector, SVE-, SME- and RVV-like execution units in the cycle-level
simulator. Before a unit can be modelled, a vector instruction has to get
through the pipeline as what it is — and it did not. Measured, with a neutral
core composed onto each scalable corpus (2026-10-05):

| corpus | what happened |
|---|---|
| `sme` (and so `sve`) | **the simulator pack does not compile**: an instruction reads 21 registers and makes 256 memory accesses, and the pack contract's retire event carries 16 of each (`AXIS_PACK_MAX_TOUCH`, `AXIS_PACK_MAX_ACCESS`) |
| `scalable_memory`, `rvv` | ran, right answers, but the execution-driven engine **replayed** vector stores: a window entry held four accesses, a vector store makes one per lane |
| `rvv` | a reduction replayed: it ran ahead of the widening multiply that feeds it |
| `simd_q_lanes` | stops as unsupported: values wider than the 64-bit executor's word |
| `scalable_basic`, `_predicate`, `_crosslane`, `_vtype`, `matrix` | ran on both engines with no replay — on the fixture words. Random programs then found five more missed dependences |

On every corpus that ran, all three engines left the golden model's registers
and memory: the execution-driven engine's commit check is what turned each
missed dependence into a replay instead of a wrong answer. But a replay is the
engine's mistake, and a timing model that makes them is timing something else.

No vector instruction in any corpus names a unit, and no vector corpus
declares a core: to the pipeline a 512-bit multiply and a scalar add are the
same one-entry, one-unit, declared-latency instruction. That is the gap the
VU stages are for.

## 2. VM1 — every lane's accesses

A scalable word is elaborated into one decode entry per lane, and the executor
runs them all for one instruction. A vector load therefore calls the memory
hook once per lane.

* **How many accesses a window entry holds is the description's.**
  `AXIS_SIM_OOO_MEM` was 4; it is now the most accesses any instruction of the
  description makes (`AXIS_SIM_MAX_ACCESSES`), between 4 and 64. A scalar
  description keeps 4.
* **Adjacent accesses are one access.** A load that continues the one before
  it extends its range; a store that continues the one before it is laid on
  its end, up to eight bytes an entry. The pipeline's record of a store and
  the golden model's at commit go through one function
  (`axis_x_note_store`), so the two lists compare entry for entry. What stays
  apart is what is apart: a gather's lanes.
* The trace-driven window's access list (`axis_sim_note_access`) coalesces the
  same way, so its load/store ordering is over ranges, not lanes.

⚠️ This changes one thing for scalar code: an instruction that makes two
adjacent accesses — AArch64's `LDP` — is now one 16-byte access in the window
and in the external model's event, where it was two of 8. The bytes ordered
against are the same.

## 3. VM2 — every lane's registers

A window entry is built from a word's first decode entry, whose operands name
where each register *starts*. Five things that is not, each found as a replay:

1. **A view names bits, and past the first sixty-four they are in the next
   slot.** Lane 2 of a 128-bit register reads its second limb. A reduction
   names all four lanes of its source as operands; all four mapped to the first
   slot.
2. **A machine renames the register, not the slot.** Whoever writes any of a
   register produces all of it: every destination operand now registers every
   slot of its register, so a reader of the second limb waits for the write.
   The extra slots take no further physical register from a rename pool.
3. **The other lanes name other registers.** A widening multiply's upper lanes
   write the register *after* the one its first lane names; a narrowing shift's
   read it. The slots every lane of a word reads and writes are collected once
   per word (`axis_x_lane_line_of`) and added to what the first lane gave.
4. **A write of part of a register reads the rest.** A reduction puts its sum
   in element 0 and keeps the others, so the register it produces is made from
   the one before it. So is a register written **under a guard** — a
   non-faulting load's lanes past the fault keep what they held. The
   description says which sets are guarded (`AXIS_SIM_KEEPS`); the operand
   says `out`, and the pipeline reads it anyway.
5. **A producer is waited for once.** A compress names four lanes of its
   source and four of its predicate before its third register; eight entries
   of the same two producers left the third no room.

How many registers an entry reads and writes is the description's too
(`AXIS_SIM_OOO_SRC`, `_DST`, `AXIS_SIM_X_WRITES`: 8, or
`AXIS_SIM_MAX_READS` if larger, at most 64).

All of it is in the three places an entry is built — execution-driven
dispatch, the trace-driven window's accounting, and the wrong path's dispatch —
from the same per-word facts, which is what lets the two timing engines be
held to each other.

### What holds them: `vector_pipeline_check.py`

Seven scalable corpora (`scalable_basic`, `_predicate`, `_crosslane`,
`_memory`, `_vtype`, `rvv`, `matrix`), each with an execution-driven core and
its trace-driven twin composed onto its ISA. Every fixture word once; then
seeded random programs of 40 instructions with the registers re-placed among
six, so instructions feed one another; and one such program with no store in
it. On each:

* functional, trace-driven and execution-driven retire every instruction and
  leave the same registers, state and memory;
* the execution-driven engine replays **nothing**;
* where no instruction stores, the two timed engines agree **cycle for
  cycle**.

And one directed program where the corpus has the instructions for it: a
vector store whose data is late, then a 16-lane load that starts seven bytes
before it, so only the load's later lanes meet the store. The load runs first
and is **squashed** for it — once, with no replay.

At the default 6 seeds: 273 checks, 0 failures. At 24 (before the directed
program was added): 863, 0.

**Mutations: 8 of 12 caught, and what the other four say.**

* Caught: a destination registering only its first slot (on either engine),
  only the first lane's registers, a guarded write not read, producers waited
  for twice, and the trace-driven window given the first lane only — that last
  by the two engines disagreeing on cycles, with nothing replayed.
* **Four accesses an entry, or no coalescing of stores: either alone
  survives.** At 128 bits a coalesced store is two entries and an uncoalesced
  one sixteen, so each is enough without the other. Together they are caught,
  and so are four accesses with no coalescing of *loads* — by the directed
  program, which exists because the random ones never caught it: their loads
  and stores go wherever the registers point and almost never meet.
* **A view's offset ignored survives**, and is redundant here: once every
  destination registers every slot of its register, reading the first slot
  finds the same producer the second would.
* **A partial write not read survives because nothing does one.** Every
  reduction in these corpora writes a whole slot. The rule is kept for what it
  says about a register; no gate holds it.

The gate's own memory had to be made exact first. These programs' base
registers hold whatever earlier instructions left in them; a memory that
wrapped those addresses into a small image made two addresses one byte —
which the pipeline, ordering loads against stores by address, rightly did not
— and one store landed on the program itself, which then stopped after four
instructions on every engine alike. `docs/ooo_design.md` §18 records the same
mistake for AArch64.

## 4. What is not here

* ~~SVE and SME do not build as simulator packs.~~ They do since VM3 (§6).
* **A store wider than 64 entries of eight bytes**, and scattered accesses
  past 64, still overflow a window entry and replay.
* **Values wider than the executor's word** (`simd_q_lanes`) stop a program as
  unsupported on every engine.
* **A register group takes one physical register.** A widening multiply writes
  two registers and is charged one from the rename pool.
* **A vector access touches the cache once per lane**, so a 16-lane load of
  one line counts sixteen hits. No vector corpus has a core with a cache yet.

## 5. VU1 — a unit has lanes

```lisp
(units (vec (count 1) (pipelined true) (lanes 4)))
```

`(lanes N)` on a unit was already in the language: the SIMT cores of
`docs/simt_design.md` declare it, and a warp instruction occupies a unit for
⌈warp lanes / unit lanes⌉ cycles. On every other core it was refused. It is
now read there too, as the same idea about a different width:

* One copy of the unit is **N lanes of 64 bits**.
* An instruction takes as many lanes as **the widest register it names is
  limbs**: a scalar one, a 128-bit vector two, a 512-bit one eight. That is a
  fact about the word, kept with its other per-word facts (§3).
* **Narrower than the unit, instructions share a copy**: two 128-bit adds
  issue in one cycle on four lanes.
* **Wider, an instruction takes every lane for ⌈need / N⌉ beats** — the
  512-bit instruction on a 256-bit datapath — and completes that many cycles
  less one later. The copy is held for the beats.
* A unit with no `lanes` is what it was: one instruction a copy.

A lane is sixty-four bits, not an element: sixteen byte lanes cost what four
word lanes cost. A unit narrower than a limb is not expressible; that would be
a `lane-bits` clause, and nothing asks for it yet.

**One rule for every kind of core**, agreed with the SIMT work: a unit's
`lanes` is how many 64-bit slices it processes a cycle, and an issue demands
limbs × the threads it serves. Here that is one thread. A fused warp
instruction serves every member that holds it, which reproduces
`docs/simt_design.md`'s reading — eight scalar lanes over a two-lane unit is
four beats — and a warp of vector instructions multiplies the two. The thread
count arrives with the warp contexts; nothing here guards on the kind of core.

At most sixteen lanes a copy are modelled, and validation refuses more rather
than timing them as sixteen. `(inflight N)` stays a warp machine's.

**No pack ABI change, and no new syntax.** The lanes each unit declares are in
a table of the simulator's own, beside the contract's unit table rather than
in it. Both timing engines and the wrong path issue through the same lanes.

### What holds it: `vector_unit_check.py`

`scalable_basic`'s instructions — 128-bit, so two lanes each — are put on one
unit and run on six machines that differ only in it. Each figure is what
**eight more** instructions cost, so the front end and the drain cancel:

| unit | independent adds | a chain of adds |
|---|---|---|
| no `lanes` | 8 | 8 |
| `(lanes 1)` | 16 — two beats each | 16 — a second beat is a cycle later a result |
| `(lanes 2)` | 8 — exactly as wide as the instruction | 8 |
| `(lanes 4)` | 4 — two share the copy | 8 — lanes do not speed up a dependence |
| `(count 2) (lanes 2)` | 4 | 8 |
| `(count 2) (lanes 1)` | 8 — two beats each, on two copies | 16 — the other copy is free; the late result is what waits |

Byte-lane adds cost exactly what word-lane adds cost on every machine, and on
every machine the execution-driven core and its trace-driven twin agree cycle
for cycle with nothing replayed.

7/7 mutations caught: no beats, lanes not shared, every instruction one lane
wide, lanes never held, beats that hold the unit but not the result, beats
that delay the result but not the unit, and the trace-driven window left
without the width. The fifth survived until the last machine was added: on a
single copy, holding the copy for the beats delays the next link by exactly as
much as the late result would.

## 6. VM3 — SVE and SME on the pipeline

Two things stood between Arm's corpora and a simulator at all.

**The retire event refused them at compile time.** The pack contract's event
carries a fixed number of register reads, writes and memory accesses, and two
static assertions required that no instruction of the description could exceed
them — rightly refusing a trace that quietly lost entries. But the bound they
tested is a static one, 256 accesses for SME, where its widest store really
makes sixteen; and a description with one instruction over the bound had no
simulator, timed or not. The event now **says what it could not carry**:
`read_count`, `write_count` and `access_count` are how many entries the arrays
hold, never more than their size, and `reads_total`, `writes_total` and
`accesses_total` how many there were. A total above its count is an event that
lost entries. `AXIS_PACK_MAX_TOUCH` goes from 16 to 64. This is **pack ABI
6**: the event grew, at its end.

**A window entry was sized in registers, and an instruction touches slots.**
`AXIS_SIM_MAX_READS` counts registers; an SME outer product writes a whole ZA
tile — sixteen rows of eight limbs. Sized from registers, every tile write
overflowed its entry: 11 of SME's 16 fixture instructions replayed. The
generator now counts, per word and over all its lanes, the distinct slots its
operands' views fall on (`AXIS_SIM_WORD_SLOTS`: 160 for SME, 8 for RVV, 5 for
AArch64's base, 2 for a scalar machine), and the entry's source, destination
and write lists are that long, to at most 256.

### What holds it

`vector_pipeline_check.py` now runs `sme` with the other seven, and `sve` as a
gate of its own: **1086 instructions**, every one once and then in random
programs, on both timing engines — the three engines agree, nothing replays,
store-free programs match cycle for cycle. The functional run's retire events
are watched: none counts more entries than its arrays hold, and none says it
lost any.

⚠️ That last is the honest limit of this stage: **no instruction in any corpus
is wider than the event now**, so an event that does say it lost entries has
never been produced, and nothing holds what a consumer sees then.

## 7. VU2 — a unit that names a length

```lisp
(units (vec (count 1) (pipelined true) (lanes 1) (length vl)))
```

A register is how much an instruction *could* work on. RVV says how much it
*does*: a tail-agnostic add of four elements told to do two is half a register
of work. `(length NAME)` names the operand that carries the element count, and
an instruction with an operand of that name takes lanes for
⌈min(count, elements) × element width / 64⌉ — at least one, at most its
register's.

* **The count is the instruction's own operand**, read where the instruction
  reads it. A value in the word is known when it dispatches. A register is
  read when the instruction may issue — its producer has landed, since it is a
  source like any other — as the newest older write to it in the window, or
  what has committed. The trace-driven window takes it from the functional
  state *before* the step: the instruction may write the register it took its
  length from.
* **It rounds up to lanes, not to the register**: one or two 32-bit elements
  fill one 64-bit lane, three fill two.
* **It is clamped to the elements there are.** A length past the register is
  the register; unclamped, count × width wraps.
* An instruction with no such operand takes its whole register, on the same
  unit. A unit that names no length takes the whole register whatever any
  operand holds.

Validation refuses a length on a unit with no lanes, on a warp machine, and
one that no instruction issuing to the unit carries: a length nothing carries
cannot change a cycle.

⚠️ **A length that is architectural STATE is not read.** RVV's `vl` is a CSR;
in `rvv.axisl` the tail policies take their length as an operand, and no
instruction's semantics read the `vl` state `VSETVLI` writes. A unit timing by
a state its instructions do not read would be timing something the
description does not say. When a corpus's instructions read it, this stage has
the place for it. On the wrong path, a length in a register is not known —
the shadow does not keep it — and the instruction takes its whole register.

No pack ABI change.

### What holds it: `vector_length_check.py`

RVV's instructions on one unit of ONE lane, so a full 128-bit register is two
beats, with and without the length named. The programs first *make* registers
holding 1, 2, 3 and 4 — the harness's own values are far past any register,
and a length taken from one is clamped, which tests nothing. What eight more
adds cost:

| | `(lanes 1) (length vl)` | `(lanes 1)` |
|---|---|---|
| 1 element | 8 | 16 |
| 2 elements | 8 | 16 |
| 3 elements | 16 | 16 |
| 4 elements | 16 | 16 |
| a length far past the register | 16 | 16 |
| an add with no length operand | 16 | 16 |

on both engines cycle for cycle, with nothing replayed. One more program puts
a chain of slow reductions first, so that when the adds issue nothing behind
it has committed and the length exists only as a write in the window; there
the two engines agreeing is the whole check.

5/6 mutations caught: the length ignored, rounded down, counted in elements
rather than bits, the trace-driven window given none, and — only by that last
program, added for it — the length read from committed state instead of the
window, which then disagrees with the trace-driven twin by four cycles. The sixth, the clamp removed, survives: past the register, count ×
width is large and the register's own width bounds it, unless the product
wraps to something small, which no register these programs can make does.

## 8. VU3 — a vector unit lends its idle lanes

```lisp
(units (alu (count 1) (pipelined true))
       (vec (count 1) (pipelined true) (lanes 4) (accepts alu)))
```

A vector unit's lanes are adders whether or not a vector instruction is using
them. `(accepts NAME...)` on a unit with lanes lets the named units'
instructions issue on the lanes it has idle — arms E and F of
`docs/spatial_backend_design.md`, in the generated simulator.

* **Its own unit first.** An instruction borrows a lane only when its own unit
  has no copy free this cycle: lending adds throughput, never moves work.
* **As many lanes as it is wide**: one for a scalar.
* **A vector instruction's lanes are its own.** Issue is oldest first, so one
  older than a borrower has already taken what it wanted; while it holds them
  they are not lent.
* **Held as the lender holds them**: a cycle if it is pipelined, the latency if
  not. The latency is the instruction's own.
* The port an instruction issues through is still its own unit's. A lane and a
  port are separate resources; a lender with ports of its own is not modelled.

Validation refuses `accepts` on a unit with no lanes, on a warp machine,
naming a unit the core does not have, or naming itself.

No pack ABI change.

### What holds it: `vector_lend_check.py`

RVV's vector instructions on `vec`, its one scalar instruction on a single
`alu`, on machines that differ only in whether `vec` accepts `alu`. What the
second half of each program costs:

| | keeps its lanes | lends them |
|---|---|---|
| 12 more scalars, two lanes | 12 | 4 — its own unit and both lanes |
| 12 more (128-bit add, scalar) pairs, two lanes | 12 | 12 — the add takes both |
| 8 more (128-bit add, three scalars) groups, four lanes | 24 | 8 — two scalars on what the add left |

on both engines cycle for cycle, with nothing replayed. 4/4 mutations caught:
no borrowing, borrowed lanes not held, a scalar borrowing the whole unit, and
lanes lent while reserved.

Not held: a lender that is not pipelined, and a borrower wider than one lane —
every machine here is pipelined and every borrower a scalar.

## 9. VU4 — one unit, several cores

```lisp
(units (alu (count 2) (pipelined true))
       (sme (count 1) (pipelined true) (lanes 8) (transport 2) (switch 6)))
```
```c
S->share_unit(core1, core0, "sme");   /* pack ABI 8 */
```

An SME unit is not a core's: several cores around it send it work. Arm C of
`docs/spatial_backend_design.md` — the specialist pool — in the generated
simulator. This is not the hardware contexts of
`docs/unified_engine_design.md`, where threads share one core's *everything*:
here each machine is a core of its own, with its own window, front end and
other units, and exactly one named unit is a single set of copies and lanes
between them.

**Which machines share is the host's to say**, as which cores run over one
memory is (`run_cores`) and which are contexts of one core (`share_core`).
**What sharing costs is the unit's**, in the description:

* `(transport N)` — every result of the shared unit arrives N cycles later:
  the way there and back. The unit is no busier for it.
* `(switch N)` — changing which core the unit serves takes N cycles, during
  which it serves nobody: SME's streaming-mode entry. The first core to use
  an idle unit changes nothing and pays nothing.

Neither is read on a unit nobody shares.

**Whose turn it is.** Cores tick one after another within a cycle, so "first
come" would be "first ticked", every cycle, and the second core would never be
served. A turn is `switch + 1` operations — long enough that changing owner is
not all the unit does. The core being served goes on while its turn lasts, and
after it only if nobody else is waiting; another core takes over when the turn
is spent, or at once if the owner has stopped asking. Waiting is having asked
this cycle or the last. The result does not depend on which core ticks first.

**The party to a share is a core**: a machine, or — for the contexts of a
shared core (`share_core`) — their group. A core's contexts already settle
among themselves who issues; to another core they are one requester. A share
asked through any context is the core's, and a unit that saw each context as
a core would give a core of two contexts two turns in three.

`share_unit` refuses a machine that has started, two contexts of one core, a
unit either core lacks, and two cores that do not declare the unit alike —
count, lanes, pipelining and both costs. A core is shared before its units
are: `share_core` refuses a machine that has already shared one. A shared unit lends no lanes (VU3):
whose turn it is is about its own instructions. The machines must run in step.

### What holds it: `vector_share_check.py`

Two execution-driven machines, each with its own program of 128-bit adds on a
two-lane unit. What 12 more adds cost a core:

| | cycles |
|---|---|
| each core its own unit, both busy | 12 |
| one unit shared, both busy | 24 each — turn about |
| one unit shared, the other core idle | 12 — all of it |
| shared with `(transport 2)`, independent adds | 12 — the unit is as busy as it was |
| a chain of adds on its own unit | 12 |
| the same chain through a unit two cycles away | 36 — three a link |
| shared with `(switch 2)`, both busy | 24 adds between them in 40: turns of three, two cycles to change |
| shared with `(switch 2)`, alone | exactly what no switch cost takes |

| a core of two contexts sharing with a second core | the second core's 12 more adds cost 24 — half the unit, not a third |
| the same, the unit's last add | when all 36 more have been done: never idle while wanted |

Every two-machine run is made twice, with the cores ticked in either order,
and the figures swap exactly. Each core ends with the registers its program gives
alone, and nothing replays.

8/8 mutations caught: no turns, an owner that never yields, a turn of one
operation, a switch that costs nothing, a switch that delays the result but
does not hold the unit, a switch charged on first use, no transport, and
machines that were never really joined.

## 10. What is left

Nothing further is planned here. What a shared unit does not yet do: charge a
lender's borrowed lanes to a turn, or cost anything to *leave* (SMSTOP). How a
core's contexts split the turns their core gets is the core's arbitration:
each context leads its core one cycle in as many as it has contexts, whatever
else runs in the same call. `contexts_check.py` holds that, not a gate here.
