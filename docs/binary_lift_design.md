# Lifting a binary to IR (X1–X3)

Status: **6 stages implemented** (X1, an effect carries its tree; X2, a block
lifter; X3, live-outs as a fact; X4, the blocks a binary contains; X5, the
terminator; X6, one register however many names it has). §4 says what is still
not modelled, and it is the caller's rather
than a gap. The lift table
publishes 414
effect value trees for `rv32i`, a checked number
(`tools/doc_facts_check.py`). It counts `value_ast` fields, which are per
EFFECT and not per instruction -- the prose used to call them instruction ASTs,
which is a different and smaller quantity. Giving the load-reserved family the
fences its `.aq`/`.rl` forms carry added four.

## 1. What `lift` returns today, and what a miner needs

```python
lift(word) -> {"mnemonic": "LW", "operands": {"rd": 5, "rs1": 2, "imm": 16},
               "reads": [...], "writes": [...],
               "semantics": "(load i32 signed (add i32 rs1 (sext i32 12 imm)))"}
```

Concrete operand values, and the semantics **as text**. Every consumer that
wants to reason about what the instruction computes has to parse that string —
which is the situation [`pce_migration.md`](pce_migration.md) §4 describes for
OptiSynth, and the reason the axiom artifact exists.

A region miner needs three things this does not give:

* the operation **tree**, not its rendering;
* the tree for **behaviors**, not only for pure values. `semantics.json`
  carries an `ast`, but it is built from `formal_semantics`, which is empty for
  every load, store and branch — which is most of what a binary contains;
* **dataflow between instructions.** `add x5, x1, x2` then `mul x6, x5, x3` is
  one graph, and finding that edge means resolving each read to the last write
  of the same architectural location.

## 2. Why AXIS should produce the graph, not the ingredients

The alternative is that AXIS publishes per-instruction trees and the miner
builds the graph. That is the AST argument again, one level up: a graph
constructed downstream is a graph this repository's ladder cannot check, and
the errors it would make — a missed def-use edge, a register aliased across a
class boundary, a live-out dropped — are silent and exactly the class AXISMINE
has already been bitten by.

If AXIS emits the graph, there is a differential available and it is a strong
one: **evaluate the IR and compare against the executor** on the same words and
the same initial state. Those are two independent implementations — a graph
walk and `axis_exec.run` — and they share the description, not the code.

## 3. The stages

- **X1 — an effect carries its tree.** _Done._ Every effect in the lift table
  carries `value_ast`, plus `addr_ast` and `guard_ast` where those exist —
  behaviors included, which is the half `semantics.json` cannot reach. A pure
  instruction's `semantics` in that table was already a tree; what was missing
  was the behaviors, which is most of a binary.

  **The gate is a consumer.** `tools/lift_ast_check.py` writes the tree-walking
  evaluator a consumer would write, knowing nothing of AXIS's internals and
  reading only the published JSON, and requires it to agree with the generated
  executor. If the walk gets the right answer the artifact is sufficient; if it
  cannot, that is the finding. It fails loudly on an operator it has not
  implemented, naming it, because a walker that silently skipped what it lacked
  would report a perfect score for whatever subset it happened to cover.

  767 trees over every corpus, no disagreements. Constructs it has not
  implemented are declined and named — `a64_shift_reg`, `a64_extend_reg`,
  `a64_cond_holds`, `let`, `a64_wmask` and the rest — and so are 159 scalable
  lane groups, which belong to `scalable_exec_check.py`.

- **X2 — a block lifter.** _Done._ `lift_block(words, pc)` returns a dataflow
  graph: each instruction's tree instantiated with the register indices decode
  chose, each read threaded to the last write of that location, and the block's
  live-ins and live-outs named. `addi x5, x1, 7` then `add x6, x5, x2` becomes
  one graph whose second `add` takes the first's *node*, not a fresh input —
  and nothing about a single instruction can tell you whether that edge was
  made.

  `tools/lift_block_check.py` evaluates the graph over random initial state and
  compares against the executor on the same words: 1640 blocks of six
  instructions over every corpus, no disagreements.

  Two bugs, both found by that comparison and both about width:

  * **an input node takes the register's width, not its first reader's.** A
    location read at 32 bits by one instruction and at 64 by the next is one
    location, and sizing its node by whichever read came first truncated the
    other — every W-form agreed in its low half and disagreed above it;
  * **§5's symbol rule survives the graph.** Turning a symbol into a valued
    node loses the fact that it is read at the reading node's width, so the
    evaluator masks each argument to the consuming node before using it.

- **X3 — live-outs are a fact, not a convention.** _Done._ The graph names its
  live-outs and the gate requires them to be exactly what the block wrote — no
  fewer, so a miner cannot think a region produces less than it does, and no
  more, so it cannot think a region produces something it does not. This is the
  predicate `AXISMINE .4` reports missing on the consumer side, where
  `region_is_expressible` never looks at live-outs and 23 of 31 mined regions
  have more than one.

  Checking it needed the write **set**, not a register diff. `run` returns a
  file, and a write of zero to a register holding zero leaves no trace in it —
  so the first version of this check reported the graph wrong for being right.
  The gate steps the block and collects what each instruction reported writing.

- **X4 — the blocks a binary actually contains.** _Done._ X2's gate built its
  blocks only from pure register-writers: `if entry.get("effects"): continue`
  excluded every load and every store. The memory path was implemented and
  checked by nothing — and a block mined from a real binary is mostly memory,
  which is the whole of `AXISMINE .2`.

  The gate now builds blocks holding loads and stores, threads one memory model
  through both sides, and compares what each leaves behind. **The counts are
  reported because a widened filter that admitted memory instructions and never
  built a block containing one would be coverage on paper**: of 52 blocks, 37
  write memory and 45 read it, and the gate fails if either is zero. A store
  address four bytes off is caught, naming both sides.

  This is also where the graph's memory *ordering* stops being a comment.
  Nodes are valued in id order, which is construction order, which is program
  order — so a load sees the stores before it, every store aliases every other,
  and nothing is reordered. A consumer that can prove more is welcome to; a
  producer that assumed more would be wrong.

  One inaccuracy fixed on the way: a guarded effect was declined with the
  reason `effect kind \`setpc\``, which names the kind rather than the guard
  and sends a reader looking in the wrong place. It now says
  `` its `setpc` is guarded ``.

- **X5 — the terminator, present and unresolved.** _Done._ `lift_block`
  declined every guarded effect, so **every conditional branch was declined** —
  and a basic block ends in a branch by definition, which left a graph with no
  terminator and a consumer with no way to know its region is
  control-flow-bounded.

  The refusal was half right, and the half worth keeping is that *whether a
  branch was taken is a fact about the run, not about the block*. So the guard
  and the target are nodes, the block carries a `terminator` naming both, and
  nothing claims to know which way it went:

  ```
  terminator {'pc': 8, 'mnemonic': 'BEQ', 'kind': 'conditional',
              'guard': 19, 'target': 17}
  ```

  Every other guarded effect stays declined — a conditionally written flag is
  not a terminator, and flattening it would be the mistake this stage avoided.

  Building it corrected something the graph had been wrong about: `pc` was an
  opaque input, so every branch target was unevaluable. A lifted block *knows*
  each instruction's address, so `pc` is a constant there now.

  Gate: evaluate the guard and the target and require them to predict what
  execution did — the taken target, or the fall-through. 28 of 46 blocks end in
  a branch, and the gate fails if none does. Flipping the guard's sense is
  caught in both directions.

- **X6 — one register, however many names it has.** _Done._ The block graph
  keyed dataflow by `(class, index)`. x86's `x86_r8hi`, `x86_r8lo`, `x86_r16`,
  `x86_r32` and `x86_r64` are five **views of one register** and all map to one
  slot; AArch64's `a64_gpr32` is the low half of `a64_gpr64`. Keyed by class, a
  write through one view was invisible to a read through another, and the graph
  described a machine with five independent registers.

  Location identity is the **storage** now. A read extracts the window, a write
  inserts into it — preserving the rest or zeroing it, whichever the class's
  write policy says, which is what `x86_r16` and `x86_r32` genuinely differ
  about. Both are built from ordinary `and`/`or`/`shl`/`lshr` nodes, so the
  graph needs no evaluator it did not already have.

  **Sweeping is what found it.** The gates defaulted to three corpora and
  passed; asked for all 55, `regslice.axisl` disagreed immediately, and so did
  `lisp_lowerings` and the AArch64 seed — 422 disagreements over the sweep, of
  which this was the largest cause. That is `gate_coverage.md` §5c's argument
  about pairs nobody wrote down, arriving in gates written after it, and the
  defaults are now every corpus.

  Two gate bugs came with it, both about seeding rather than the artifact: the
  tree walker seeded a raw slot where a windowed class needed its window
  (`limbs.axisl`, six instructions), and seeding two views of one register
  overwrote rather than merged.

  **Two shapes are declined, named.** A scalable lane group and a reduction
  belong to `scalable_exec_check.py`, which `gate_coverage.md` §5c already
  says; and a live-out wider than a slot is held by the executor either in one
  integer or split across limbs, which is a fact about the class that this
  comparison does not yet distinguish. Guessing produced a wrong answer in each
  direction on different corpora, so it is skipped and counted rather than
  compared wrongly.

## 4. What is still not modelled

Nothing about *which* block comes next. The terminator names a target; whether
control reaches it, and what the binary's basic blocks and functions are, stay
the caller's. Those are facts about a program, and this describes a machine.

## 5. Two rules a tree implies, learned from the gate

Both were found by the walker disagreeing with the executor, which is the point
of writing the walker rather than reasoning about the format.

**A symbol is read at the width of the node reading it, not at its own.** RV64's
`SRLW` is `(sext i64 32 (srl i32 rs1 ...))`: `rs1` is a 64-bit operand and the
shift reads its low 32. A walker returning the operand's declared width made
every W-form and every 32-bit divide disagree.

**A load has three widths and they are not the same one.** `(load i8 signed
addr)` inside a 32-bit `set` reads *eight* bits from memory, produces a
*thirty-two*-bit value, and computes its address at *sixty-four*. Collapsing
them onto the node's own type is two separate wrong answers: the address
`x2 + 3` masked to eight bits became 194 instead of `0x8e97...02`, so a byte
load missed the byte store that had just written that address and read zero;
and the result masked to eight threw away the sign extension, giving `0xfe`
where the machine gives `0xfffffffe`. A *store* had neither, because an effect
publishes `addr_width` beside `eval_width` and the store path uses it — a load
rides inside a value tree, where the only width in plain sight is the loaded
one. The effect also publishes `load_address_width`.

Both were found the same way, and it is worth saying how, because the gate had
been green over them for a long time. `lift_block_check.py` drew six random
instructions per block and skipped any block containing an operator its walker
does not implement — `a64_shift_reg`, `a64_extend_reg`, `a64_wmask`, `let`. On
AArch64 that left **three of forty blocks actually evaluated**, and whether the
terminator was checked at all came down to a coin flip. Drawing only from
instructions the walker can evaluate takes it to forty of forty, and the two
width bugs surface immediately — on the unmodified corpus, at three of four
random seeds. A gate that samples can be green because it looked away.

**The walker implements the architecture's operators, and the gate is what
says it got them right.** `a64_shift_reg`, `a64_extend_reg`, `a64_cond_holds`,
`a64_wmask`, the three bitfield moves, the high multiplies and `let` were named
and unimplemented, which cost 110 AArch64 instructions -- and cost more once
`lift_block_check` began drawing only from instructions it can evaluate, because
then an unimplemented operator is not a skipped tree but a whole class of block
that never forms. Implemented from the architecture rather than by copying the
emitter, so the two stay independent derivations: **96 trees walked became 198
on that corpus and 275 became 393 over all of them, at 0 disagreements.**

Twice the first version was wrong and the differential said so, which is the
argument for having it. The bitfield moves need *two* masks -- `wmask` says
which bits the rotated source contributes, `tmask` how far the field extends --
and a single "field of this width" shortcut differs from both exactly when the
field wraps: eight instructions disagreed. Then `BFM` alone still disagreed,
because `tmask` applies to the **result** as well and the destination keeps its
own bits outside both masks; leaving that out put a bit of the rotated source
into bit 63 of a field ending at bit 1.

**A block is one ISA, and the gate has to say which.** `lift_block` has always
taken an `isa`; `lift_block_check` never passed one, and a word that two ISAs of
one description share is ambiguous without it -- so the lifter correctly answered
nothing and the gate read that as "no instruction decodes it". It cost **203 of
`aarch64_translation_seed`'s 884 instructions**, and asking properly takes the
instructions a block can be built from there from **300 to 431**. Mixing two
ISAs in one block was never right either: a program is one ISA, and this corpus
describes a source and a target that deliberately share encodings.

This is the same fact that makes `ret` decode as nothing without an ISA, met a
third time -- once in the bound decoder, once in the coverage tool, and here in
the gate that had been quietly declining a quarter of the corpus because of it.

**Shifts saturate; they do not wrap.** An amount at or beyond the width gives
zero, or the sign for an arithmetic right shift. Where an architecture masks its
shift amount the *description* says so — `SRLW` carries `(and rs2 0x1f)`
precisely because RV64's W-forms mask — and where it does not, as in `SRAX`, the
operator saturates. A consumer assuming the RISC-V hardware convention would
mis-model every unmasked shift, silently, and get the right answer for all the
masked ones.

## 6. What this is not

Not a decompiler, and not a control-flow recovery pass. A block is a sequence
of words the caller supplies; where blocks begin and end, which branches are
taken, and what the binary's functions are remain the caller's, because they
are facts about a *program* and AXIS describes a *machine*.

Not an optimiser. The graph is what the instructions say, in the order they say
it. Constant folding, dead-code elimination and rewriting are things a consumer
may do to it and AXIS has no opinion about — with one exception it cannot avoid:
a read threaded to a write is already a decision, and §3's gate is what keeps
that decision honest.

## 7. Invariants

- A consumer that only wants what `lift` returned before gets byte-identical
  output; the tree is additive.
- The graph is checked against execution, never against another AXIS artifact
  built from the same lowering. Two derivations from one source prove nothing.
