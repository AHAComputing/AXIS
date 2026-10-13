# Mining instruction-set extensions from real binaries

## 1. The question, and why AXIS can ask it

Which *sequences* of instructions recur often enough, and compute something
small enough, that one instruction should replace them? Answering it honestly
needs three things that usually have to be built and trusted separately, and
that AXIS already has:

* **A decoder that reads the whole binary.** A miner that skips what it cannot
  decode reports the frequency of what it understood, which is a statement
  about the miner. AXIS decodes 100% of a compiled RV64GC object and 98.48% of
  eight AArch64 system binaries, with every remaining miss shown to be data.
* **Semantics that compose.** The lift table carries `semantics_ast` as a tree
  over operand *names*, so a run of instructions composes by substitution
  rather than by pattern-matching disassembly text.
* **A way to check the composition.** `emit-smt2` gives one `define-fun` per
  instruction, so "this extension equals those four" is a proof obligation.

## 2. The pipeline

```
binary ─► lifter (blocks) ─► thread ─► cones ─► compose ─► propose ─► prove
```

**Blocks** come from the lifter, not from a guess: a run that crosses a branch
is not a block, and an extension mined across one would replace instructions
that do not always run. A word the description does not cover ends the lifter's
walk, which is right for a region and wrong for a survey -- so `ise_mine.py`
restarts after it and *counts* what it skipped.

**Threading** resolves each instruction's register reads to what produced them,
at *instruction* granularity. `lift_block` threads at operator granularity,
which is right for a dataflow consumer and wrong here: an extension replaces
whole instructions, and its proof obligation is written in terms of theirs.

An instruction that is not a pure single-result computation -- a load, a store,
a branch -- does not end the block. Its results become **opaque sources**: a
cone may read them and may not absorb them. Ending the block instead measured
seven instructions in an object with hundreds, which is the difference between
a survey and an anecdote.

**Cones** grow backwards from a root while the input count stays inside a
budget. The budget is the architectural constraint that makes this a real
question: an extension reads its operands through the register file the machine
already has, so two inputs and one output is the classic shape and anything
wider needs justifying.

**Canonicalisation** renames inputs by first appearance, so the same shape on
different registers is one candidate -- and *immediates are renamed too*. They
were kept as written at first, on the reasoning that `x << 7` and `x << 3` are
different extensions. At corpus scale that reasoning is wrong in a way the
corpus makes obvious: `sub sp, sp, #48` then `add x0, sp, #32` recurs 45 times
across the system binaries with *those* constants and hundreds of times with
others, and one instruction per pair of constants is not an extension, it is a
table. The shape is the candidate; the constants are its operands, and the
proposal declares them as immediate operands at the width their field has.

That also fixes the budget. An immediate reaches the machine through the
instruction word rather than the register file, so it costs no read port --
and the budget it was being counted against is a count of ports. Counting it
there refused two-register extensions for carrying a constant.

**Composition** substitutes each instruction's semantics tree into the next.
That is the whole of it -- a tree walk, not a pattern match.

**Proposal** writes the composed tree out as an AXIS instruction. This is what
the mining is *for*: a candidate that proves out is already in the language
every other emitter reads, so it can go straight to a decoder, a compiler
backend and a simulator without being retyped.

## 3. The obligation

The composition is the part most likely to be quietly wrong -- an operand bound
to the wrong value, a width dropped, two instructions ordered by their addresses
rather than their dataflow -- and its failure mode is a plausible extension that
computes something else. So it is checked through a different path than it was
built:

* **The proposal.** The composed tree becomes an AXIS instruction and AXIS
  lowers *that* to SMT, exactly as it lowers any instruction.
* **The original.** The same run is composed again, by substituting AXIS's own
  `axis_instr_*` definitions for the instructions it covers.

One side goes tree → description → SMT; the other SMT → SMT. Different code,
same claim, checked for every input by a solver rather than by test vectors.

Both mutations tried were caught: binding a step's operand to the wrong
producer (4 of 6 refuted), and composing an immediate one off (3 of 6 refuted).
The candidates that survived each mutation are the two-instruction cones where
the mutation happens to be a no-op -- which is worth knowing about the *test*,
not just the tool.

## 4. What it declines, and why that is the point

* **A width that does not compose.** `srliw` narrows to 32 bits inside a 64-bit
  run. Inserting the narrowing would be inventing which bits the extension
  keeps, so the candidate is named and counted rather than approximated.
* **An instruction with effects.** A load or a store could be part of an
  extension, but its obligation would have to talk about memory, and this rung
  states obligations over values.
* **A word the description does not cover.** Counted, per section.

A refutation is a defect in the mining. A decline is a limit with a name. Only
the first fails the gate, and a run that proves nothing fails too -- an
obligation set that quietly empties itself is not a clean run.

## 5. What it found

On four kernels compiled `-O2` for RV64GC, from 30 threaded instructions in 16
blocks: 8 distinct candidates at two inputs, led by the `mixhash` chain
(`h += h<<3; h ^= h>>11`), which is a **one-input** extension. At three inputs
(`--max-inputs 3`) the first is multiply-accumulate (`MUL` then `C_ADD`, in
`dot` and in `saxpy`) -- the miner rediscovers the extension every DSP has,
from a binary, without being told to look for it.

⚠️ **For a while it found that at two inputs, and it was wrong.** A value the
miner may read and not absorb -- a load's result -- was named by how many
minable instructions preceded it, so two loads with nothing between them were
one value. `ld a4; ld a5; mul a4, a5, a4` was mined as a square;
multiply-accumulate, which reads three registers, was reported as reading two;
and the proof agreed, because the proof composes the original from the same
names the proposal was built from. It checks that the composition is the
instructions', not that the instructions' operands are the code's. What showed
it was writing an occurrence down by register, for the rewriter of §8,
which now fails on it. The
corpus counts below were made before the fix and have not been recounted; a
shape whose inputs are loads may be over-counted or under-sized in them.

At corpus scale, over twenty-four AArch64 system binaries -- 13,721 blocks and
17,826 threaded instructions -- the shape that dominates is `ADRP` then
`ADD`, at **1007 occurrences**: PC-relative address materialisation, the
commonest pair in AArch64 code and a real proposal. It is *declined* at the
proof, and correctly: `ADRP` reads the pc, so a `define-fun` over an
instruction's operands has nowhere to bind it, and an extension that fused it
would compute a different address wherever it was placed.

What does prove, from five of those binaries: frame setup (`sub sp` then `orr`,
116 occurrences; `sub sp` then `add`, 108) and 64-bit constant materialisation
(`movz` then `movk`, 15).

**Values that read architectural state prove too.** A conditional select reads
NZCV, and for a while that meant no SMT definition at all -- a function over an
instruction's operands has nowhere to bind it. The state is a parameter now
(see `docs/pce_migration.md`), so the miner carries the state names a composed
run reads, and the proposal declares an ISA holding exactly those registers:
the extension is described the way the code it replaces was described. With
that, `csel`, `csinc` and `csneg` candidates discharge -- twenty proven from
the top twenty-eight of a two-binary run, where four had proven before.

The obligation holds them to *one* NZCV. Making the composition read a
different one than the proposal does refutes exactly those four candidates and
nothing else, which is the check having teeth where it matters rather than in
general.

It also found something about the corpus rather than the code: `c.addw` was
undescribed, so the walk stopped in the middle of `mixhash`. It is described
now, and checked against llvm-mc.

## 6. Ranking by cycles, not by instructions

Instructions removed is a poor proxy for what an extension is worth: replacing
a three-cycle multiply and a one-cycle add is not the same saving as replacing
two moves. Nor do the instructions a cone covers all run one after another --
two that read the same registers issue together on any machine wide enough.
What an extension actually removes is the *chain*.

So the miner walks the cone in dependence order and takes the longest path,
charging each step the `latency` its description states. That number is a fact
the description carries, not an estimate. What the extension itself would cost
is *not* a fact -- nothing has been synthesised -- so it stays a parameter,
`--extension-latency`, and the report says out loud which number is the
assumption:

```
cycles removed assumes the extension costs 1 cycle(s); the chain is the description's
 cycles   saved   seen  path  in  shape
     14      14      7     3   1  ADRP ; ADD_X_IMM_SP ; ORR_X_SHIFTED
     12      18      6     3   1  ADRP ; ADD_X_IMM_SP ; ADD_X_IMM_SP ; CSEL_X
```

The two lines disagree, and that is the point of the change. The four-step
candidate removes *more instructions* -- 18 against 14 -- but fewer cycles,
because its two address computations run side by side and only one of them is
on the critical path. Ranking by count put it first; ranking by cycles does
not.

## 7. Built, and priced

`--extension-latency` was the one number in the ranking that was an
assumption, and §6 said so: nothing had been synthesised. A proven proposal is
an AXIS instruction, though, and an AXIS instruction has a netlist with a
calibrated area and depth (`docs/hardware_design.md` §5). `tools/ise_cost.py`
takes the proposals `ise_prove.py --out` writes and asks three things of each.

**Alone.** Its netlist's area and depth, and the fewest cycles the depth fits
in at the cycle the base description's units are grouped by. `--check` holds
the netlist to the golden model, which closes the chain: the code equals the
proposal for every input (§3), and the proposal equals the circuit.

**In the machine.** The proposal is added to the description it was mined
from, at each latency worth trying -- the fewest it fits in, and the latency of
every slower unit it could ride -- and AXIS plans the units again. What is
reported is what changed: the unit that took it, the area the machine grew by,
and that unit's stage delay. The marginal area is the number an extension
costs a core that already has an adder and a multiplier, and it is not the
netlist's.

**Worth.** Occurrences times the cycles the chain loses at that latency.

On the four kernels, against RV64I:

```
mined0: MUL+C_ADD, seen 2, a chain of 4 cycle(s)          (--max-inputs 3)
  alone: 21011 NAND2, 83.5 gate delays -- 2 cycle(s)
  at 2 cycle(s): a unit of its own, `mul_l2`, +21011 NAND2, removes 4 cycle(s)
  at 3 cycle(s): joins `mul`, +1146 NAND2, removes 2 cycle(s)
mined0: C_SLLI+C_XOR+SLLI+C_ADDW, seen 1, a chain of 4 cycle(s)
  alone: 1342 NAND2, 43.5 gate delays -- 1 cycle(s)
  at 1 cycle(s): joins `alu`, +1127 NAND2, removes 3 cycle(s); ⚠️ that unit's
                 stage becomes 65.8 gate delays from 47.3, against a cycle of 45
  at 2 cycle(s): joins `alu_l2`, +1395 NAND2, removes 2 cycle(s)
```

Both are the report doing what an assumed latency could not.
Multiply-accumulate does not fit in one cycle, which is what the ranking
assumed: it is two as a second multiplier, or three on the multiplier already
there for an eighteenth of the area. And the `mixhash` chain *does* fit in one
cycle alone -- but in the ALU it puts a shifter behind an adder, and the unit
every other instruction runs through is then 40% deeper. Ranked by cycles
removed without lengthening the cycle, it is a two-cycle instruction, not a
one-cycle one. The options are printed, not collapsed: which of them to take
is a decision about the core.

The same six netlists synthesised (`--synth`, the flow the cost model is
calibrated against) put the model between 0.94 and 1.16 of the measured area,
on circuits it was not fitted on.

The gate (`ise_check.py`) requires every proven proposal to be built or
declined by name, every netlist to equal its proposal, and at least one
extension to cost less than half in the machine what it costs alone -- a
report that prices everything as a unit of its own has not asked the question.

## 8. Run

Everything above is a claim about a program nobody ran. `tools/ise_run.py`
puts the extension in the program and runs both, one extension at a time.

**Encode.** A proposal gets a real instruction word: an opcode no instruction
of the description can decode as, found from the description's own decode
table, and a field per operand. One whose operands do not fit is declined by
name -- and three of the nine mined from the kernels are: two registers, a
destination and two six-bit shift amounts are 27 bits, and a 32-bit word has
25 after its opcode. The top-ranked `mixhash` chains were never instructions.

**Rewrite.** At each occurrence the root becomes the extension. A covered
instruction is *removed* only when everything that reads what it wrote is
itself covered, and its register is dead where the function returns;
otherwise it stays and the occurrence is worth less than the count said. An
occurrence is declined when an input it read early is overwritten before the
root. Branches are re-encoded for the new layout. Register reads and writes,
control flow and the field encoder all come from the description; the calling
convention is the one thing that does not, and is a table in the tool.

**Run.** Both programs, on the pack simulator built from the description plus
the extension, with the same inputs. Return value and every byte of data
memory must be equal, and the difference in cycles is the measurement.

```
mined0: MUL+ADD, at 2 cycle(s)
  dot: 13 -> 12 instruction(s); 426 -> 366 executed, 546 -> 366 cycle(s), 33.0% fewer
    it ran 60 time(s) and saved 3.0 cycle(s) each; the chain less the latency is 2
  saxpy: 15 -> 14 instruction(s); 546 -> 486 executed, 666 -> 546 cycle(s), 18.0% fewer
    it ran 60 time(s) and saved 2.0 cycle(s) each; the chain less the latency is 2
mined1: SLLI+ADD, at 1 cycle(s)
  dot: 13 -> 12 instruction(s); 426 -> 425 executed, 546 -> 545 cycle(s), 0.2% fewer
mined5: MUL+ADDW, at 2 cycle(s)
  clampsum: 11 -> 10 instruction(s); 506 -> 406 executed, 706 -> 406 cycle(s), 42.5% fewer
```

Three things the ranking could not have said:

* **Occurrences are not executions.** `SLLI`+`ADD` is the most frequent shape
  in the object, three occurrences, and ranked first for it. Each is loop
  setup and runs once: a fifth of a percent. Multiply-accumulate occurs twice
  and runs every iteration.
* **The chain less the latency is a bound, in both directions.** In `dot` the
  accumulator is next read an iteration later, the two-cycle extension's
  latency overlaps the loop's other work, and an occurrence saves three
  cycles, not two. In `saxpy` the result is stored at once, the latency is
  exposed, and it saves two.
* **What can be removed depends on who else reads it.** With two result
  registers live at return, `mixhash`'s last shift may be a result and none of
  that chain can go; told the function returns one (`--results 1`), four
  instructions become one.

⚠️ **This is the only check of the miner's operands against the code.** The
proof of §3 composes the original from the candidate's own names. With the
defect of §5 put back, the proof passes and this reports `dot` 33% faster
*and a different result*.

The gate (`ise_check.py`) requires every rewritten function to return what the
original returns, and a loop to get shorter by its trip count.

## 9. What this is not, yet

* **The machine it runs on is the description's default one**: in order, one
  instruction issued a cycle, latencies charged where a reader waits. No
  `defcore` is given for RV64I, so nothing here is a wide or out-of-order
  machine, where a shorter chain is worth something different again.
* **Two clocks, unless asked for one.** By default a chain is charged the
  latencies the description declares and an extension the cycles its netlist
  needs. `--as-built` on `ise_mine.py` charges every instruction its netlist's
  floor at the planner's cycle -- a core with `(latency (* derived))`
  (`docs/core_timing_design.md`) -- and `ise_cost.py` and `ise_run.py` read
  the same clock from the candidates. On it RV64I's multiplier is two cycles,
  multiply-accumulate's chain is three, and the extension at its own floor of
  two joins the multiplier that is there (+1146 NAND2) instead of needing a
  second one (+21011) -- the choice §7 printed was an artefact of the declared
  three. Run, `dot` goes from 487 cycles to 368.
* **Whole words, leaf functions, RV64.** The rewriter lays out 32-bit
  instructions and declines a function with a compressed one, a call, or a
  pc-relative value. One calling convention is in its table.
* **An AArch64 extension is priced through units with effects in them**
  (`docs/hardware_design.md` §3.5). One that reads the flags is placed in the
  ISA of the instructions it replaces, which declares them; one built as an
  effect is found in `emit-hw-effect-json`'s units and the machine measured
  there. From `/bin/ls`: `CSEL_X`+`ADD_X_IMM_SP`, seen 8 times, is 1990 NAND2
  alone and +562 in the one-cycle ALU it joins; a four-instruction mask chain
  is 7805 alone and +6785 in the two-cycle one. Planning the seed takes
  minutes, and `--fewest-only` plans it once per extension.
* **One extension at a time.** Two that would share an operator between them
  are each priced against the machine without the other.
* **The pc.** `adrp` reads it, and AXIS does not carry the pc as architectural
  state -- rightly: an extension that fused a pc-relative instruction would
  compute a different address wherever it was placed. So `ADRP` + `ADD`, the
  most frequent shape in the corpus at 834 occurrences over two binaries, is
  declined by name. That is a fact about the instruction, not a gap in the
  tool.
* **No memory in the obligation**, so the extensions it can propose are pure
  value computations.
