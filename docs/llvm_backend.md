# A real LLVM backend, generated

Status: **L1, L2, L3 and L4 built.** The corpora declare 1 calling convention.

## 1. What exists today is not a backend

`emit-tablegen` emits, for every instruction in every corpus:

    class XZBB_TESTInst<bits<7> funct7, bits<3> funct3, bits<7> opcode, ...>
      : RVInst<outs, ins, opcodestr, argstr, [], InstFormatR> {
      let Inst{31-25} = funct7;  ...
    }

Three things are wrong with that as a target:

* It inherits `RVInst` and allocates `GPR` — it is a **patch into the RISC-V
  backend**, so it cannot exist without one, and it describes AArch64 and RVV
  corpora as RISC-V R-format.
* The encoding is the flat `opcode`/`func3`/`func7` sugar, **not** the layout
  the proven encoder uses. AXIS knows where every field of every format lives;
  this emitter ignores it.
* Nothing checks it. `tablegen_validate.py` declines this file by name.

So the first job is not "improve the .td" but "emit a target instead of a
patch".

## 2. What is derivable from an ISA description, and what is not

A backend is not one artifact. Split it by what it needs to know:

| Layer | Needs | Derivable from AXIS |
|---|---|---|
| Register info | files, widths, sub-register views, reserved regs | **yes** — `RegisterClass` has all of it |
| Instruction formats + encoding | field placement per format | **yes** — this is `InstructionLayout`, already proven by roundtrip |
| Asm strings | mnemonic + operand order | **yes** |
| Disassembler | the same layout, read backwards | **yes** |
| ISel patterns | semantics as a DAG | **yes** — `emit-llvm-patterns`, now semantically gated |
| Calling convention | an ABI | **no** |
| Frame lowering, prologue/epilogue | an ABI | **no** |
| Legalization / type actions | target policy | **partly** — legal types follow from the register classes; the rest is policy |

The line is sharp and worth stating plainly: **AXIS describes an instruction
set, not a platform.** Which register holds the first argument, which are
callee-saved, how a stack frame is laid out — none of that is a property of the
ISA, and a description that guessed would be inventing an ABI rather than
generating one. So "compile C to this target" is *not* reachable from the
description as it stands; it needs an ABI section, which is a description
change, not an emitter change.

What *is* reachable is the whole MC layer plus instruction selection — which is
the majority of the generated code in a real backend, and the part where a
mistake is silent.

## 3. The gate that matters

`llvm-tblgen` exiting 0 proves the file parses and type-checks. That is worth
having, and it is not evidence about *meaning* — the same trap the ISel patterns
were in until last commit.

The real gate is differential, and it is available because the environment has
LLVM's own generators and libraries:

    AXIS's proven encoder            vs   LLVM's --gen-emitter tables
    AXIS's proven decoder            vs   LLVM's --gen-disassembler tables

Same instruction, same operands, same 32 bits — or the generated backend is
lying about the machine AXIS describes. This is the strongest gate in the repo's
shape, because the two sides share *no* code: one is AXIS's Rust, the other is
LLVM's C++ generated from AXIS's TableGen by LLVM's own tools.

## 4. Stages

| Stage | Delivers | Gate |
|---|---|---|
| L1 | a self-contained target tree (`<X>.td`, RegisterInfo, InstrFormats, InstrInfo) | **built** — LLVM's real generators run: `--gen-register-info`, `--gen-instr-info`, `--gen-emitter`, `--gen-disassembler`, `--gen-asm-writer` |
| L2 | the MC differential | **built** — LLVM's generated encoder == AXIS's encoder, over every instruction and random operands |
| L3 | ISel patterns in-tree, typed against our own classes | **built** — `--gen-dag-isel` builds a matcher over them, and every pattern is a DAG `llvm_patterns_check.py` proves against the golden model |
| L4 | a declared calling convention | **built** — `--gen-callingconv` runs over it, and LLVM's generated register lists are compared against the declaration |

L1 without L2 would be exactly the mistake §3 describes, so L2 is not optional
polish — it is the reason for L1.

## 5. What L1 has to get right

* **Registers, not register classes.** LLVM needs a `def` per register with a
  `HWEncoding`; AXIS has a class with a count. The flat file offset does not
  appear in TableGen — it is AXIS's own storage layout, not the machine's.
* **Views are sub-registers.** `a64_gpr32` is not a separate file; it is the low
  32 bits of `a64_gpr64`, which LLVM spells as a `SubRegIndex` and a
  `RegisterClass` over the same registers. A view whose `view_offset` is
  non-zero (x86's `AH`) is a sub-register at an offset, which LLVM also spells.
* **`zero_index` and `alias` are reserved.** XZR and SP must exist as registers
  and must be out of the allocation order, or LLVM will allocate them.
* **Non-encodable instructions are skipped by name.** `is_encodable()` already
  says which; a target that silently dropped them would claim coverage it does
  not have.

## 6. Built: L1 and L2

`emit-llvm-target` emits the tree; `tools/llvm_target_check.py` runs LLVM's
five generators over it, **compiles the encoder they produce**, and executes it
against `emit-encode-c` on the same instructions and the same operand values.
Twelve corpora, 1715 instructions in the largest.

The two sides share no code. One is AXIS's Rust, by way of a header-only encode
table that `roundtrip_check.py` proves against the decoder. The other is C++
that LLVM's TableGen wrote from the `.td` this repo emits. They agree on every
bit of every instruction of every corpus.

The operand *order* is not assumed either: LLVM's generated switch names the
operand behind each `MI.getOperand(N)` in a comment, so the mapping is read out
of LLVM's own output rather than from what the emitter intended.

### What the generators found

Three things, none of which the old emitter could have surfaced because nothing
ever ran a generator over it.

* **A document can hold more than one decode context.** The AArch64 seed
  describes `aarch64_base` and `accelerator_scalar64`, and they reuse bit
  patterns freely — 271 pairs of them. That is legal in AXIS and impossible in
  one LLVM decoder table, so an ISA is a `DecoderNamespace`, which is exactly
  the mechanism real backends use for the same reason.
* **Lanes and definedness masks are not instructions.** A scalable instruction
  is instantiated per lane and every lane shares one encoded word;
  `scalable_origin` already says so, and `ast.rs` already calls them
  "alternatives competing for a bit pattern". Emitting them all handed LLVM N
  identical encodings. This is the **seventh** place that rule now lives — the
  executor, three decoders, the trace, the target — and each time it was
  missing the symptom was different.
* **A derived operand is not an operand.** CASP encodes the first register of
  each pair; the second is that register plus one, so no format field binds it
  and LLVM has nothing to decode into. They are omitted and named in a comment.
  LLVM would spell the pair as one operand of a pair class, which is a
  modelling change rather than an emitter fix — see §8.

Two overlaps survive that are *not* cross-ISA: `DSB` against `SSBB` and
`PSSBB`, which AXIS separates with a decode constraint (`option != 0, != 4`)
because SSBB really is DSB #0. LLVM's decoder resolves them by specificity, so
they need nothing here — but the constraint is a fact the `.td` does not carry,
and a target that had to decide would need it.

### What the gate found about itself

Before it counted, the gate compared **68 of AArch64's 854 instructions zero
times** and said PASS. Their decode constraints (`a64_shifted_reg`,
`ADD_X_SHIFT0` pinning its shift, `SBFM_W` pinning N) inspect the raw operand
value, and uniform 32-bit draws never satisfy them. Half the draws now fit the
operand's encoded field — which is what a caller supplies and what a constraint
can accept — and half do not, which is what proves the two encoders mask alike.
The gate fails if any instruction is never encoded.

That is `docs/gate_coverage.md`'s argument arriving unprompted for the third
time, and it was found by writing the counter rather than by reasoning.

### Injections

| injected | result |
|---|---|
| a field's bit range shifted by one | rejected by tblgen itself — invalid bit range |
| a fixed field's value flipped in one bit | every comparison mismatches, all corpora |
| an operand bound from the wrong slice of its value | RV64I 120, AArch64 16, **RVV 0** |
| the lane rule removed | `--gen-disassembler` conflict on SVE and RVV, **RV64I unaffected** |

The last two are the same lesson twice: a corpus with no scattered immediate
cannot see a slicing bug, and a corpus with no scalable instruction cannot see
a lane bug. Neither gate is weaker for it; a single-corpus ladder would have
been.

## 7. Built: L3

`emit-llvm-target` now emits `def : Pat<...>` for its own instructions: the
leaves typed by this target's register classes, the RHS the instruction def.
`llvm_target_check.py` runs `--gen-dag-isel` over them, which is what turns a
pattern into a matcher — and a pattern naming an operand the instruction does
not have, or typing one wrongly, fails there.

The DAG is not built twice. `emit-llvm-patterns` maps a DAG to an
`llvm.axis.*` intrinsic and `emit-llvm-target` maps the same DAG to an
instruction; both call one `llvm_pattern_dag`, parameterised only by how a leaf
is spelled — `i64:$rs1` for the intrinsic hints, `GPRRegs:$rs1` for a real
selection.

### Sharing a function is not evidence

That last paragraph is an argument, and the gate does not accept it. The two
callers pass different leaf spellings and the target applies four further
conditions of its own, any of which could have been a *transform* rather than a
filter. So the check compares the conclusion: every DAG in the target file must
be, after leaf spellings are stripped, a DAG `emit-llvm-patterns` also emits —
and those are the DAGs `llvm_patterns_check.py` evaluates against the generated
golden model. The proof of meaning carries across the join, not across the
shared call.

Patterns that file emits and the target declines are expected — the target
additionally requires a single result, register operands, no derived operands
and a bounded commutation count — so they are counted rather than passed over.

### What L3 found

* **A Pat's operand order was unchecked, and reversing it passed everything.**
  Selection supplies the RHS operands positionally into `InOperandList`, and
  §6's differential proves slot N of that list is AXIS operand N — so
  `(sub $rs1, $rs2)` selecting `(SUB $rs2, $rs1)` is a subtraction with its
  operands swapped that encodes to the bits of a valid SUB. tblgen sees two
  operands of the right class and builds the matcher. The MC differential
  compares encodings and never looks at a pattern. The golden cross-check
  above compares the *LHS* and never looks at the RHS. Injecting the reversal
  passed all three; the gate now checks the RHS names against the
  instruction's own `ins` list. Both orders come from one iteration over the
  operands, and "it is the same loop" was exactly the reasoning that did not
  hold.

* **A guard that could not fire.** A check stood here rejecting instructions
  whose operand register classes disagreed with the pattern's root type. It
  fired on 250 AArch64 instructions — until the reasons were ordered so the
  more specific one won, at which point it fired zero times on all twelve
  corpora with every pattern count unchanged. It is dead by construction, not
  merely in practice: `class_value_widths` reads a class's value types off the
  operands that name it, so once `llvm_pattern_dag` has accepted the widths
  the agreement is a theorem. Removed. A guard that cannot fire reads as
  coverage the file does not have — the same complaint §6 makes about the 68
  instructions compared zero times.

* **Commutation is exponential and one pattern found the cliff.** TableGen
  enumerates every commutation of every commutative node. AArch64's RBIT
  spells bit reversal as a butterfly of nested `or`/`and` — 91 commutative
  nodes for `RBIT_W`, 187 for `RBIT_X` — and one such pattern takes
  `--gen-instr-info` from one second to over two minutes. Such a pattern could never fire anyway:
  LLVM canonicalises bit reversal to `bitreverse` long before selection. The
  limit is 6, and the count is named in the decline.

* **A constant needs its type.** `(and $rs1, 65535)` draws "Could not infer
  all types in pattern" from real generators — LLVM does not tie a shift
  amount's type to the shifted value's — so constants are emitted as
  `(i32 65535)`, which is what LLVM's own targets write. Nothing before L3 ran
  a generator over these patterns, so nothing had said so.

### Injections

| injected | result |
|---|---|
| a Pat naming an instruction def that does not exist | tblgen: `Variable not defined: 'ADD_NOPE'` |
| a Pat's RHS operand order reversed | **passed every gate that existed**; now 8 patterns named against their `ins` lists |
| a shift mask changed from 31 to 30 in the target only | 3 DAGs differ from the golden-checked one |
| a pattern invented, with untyped leaves, where semantics gave none | tblgen: `Node 'RS1' in output pattern but not input pattern` |
| a pattern invented on the real operands where semantics gave none | 6 instructions selected that `emit-llvm-patterns` has no pattern for |
| an immediate predicate widened by four bits | golden model disagrees on 4 instructions |
| an immediate predicate's signedness flipped | golden model disagrees on 4 instructions |
| LSR and ASR swapped in the `a64_shift_reg` reduction | golden model disagrees on 8 instructions |
| the shift-amount mask dropped from that reduction | **not caught, correctly** — those inputs are poison; 512 cases skipped |
| every state clobber dropped | **passed every gate that existed**; now 116 instructions named against the lift table |
| an immediate mask widened to admit unencoded bits | **passed the golden model, which cannot see encodability**; now 9 predicates named against the encode table |
| a state clobber declared that the behavior does not have | 724 instructions named — caught only after iterating declarations, not writes |
| the decode constraint ignored, predicate taken from the field | **not caught** — `uimm2` is a subset of a two-bit field, so the subset invariant has no objection |
| a selector pinned to a value the decoder rejects (ROR) | **passed the golden model**, which evaluates the rotate happily; now 12 patterns named against their operand's predicate |
| two instructions given one pattern (ADD and ADDS) | **not caught by anything** — both DAGs are correct, and neither file compares one instruction's pattern with another's; now 62 named |
| a scaled offset divided by the wrong power of two | **not catchable** — the golden check had no memory, so every load pattern was declined rather than evaluated; now 4 named |
| a load's signedness flipped (`sextloadi8` for `zextloadi8`) | same, and now 2 named |
| a store's value and address swapped | 3 named |
| a truncating store widened | 2 named, and correctly not the store that truncates nothing |

### Immediates carry the range their semantics states

An immediate operand was declined outright at first, on the grounds that a
predicate saying which values encode had to be invented. It does not: the
description already writes it. RISC-V's `ADDI` is

    (formal (add i32 rs1 (sext i32 12 imm)))

and that `sext ... 12` *is* the statement that this immediate is a signed
12-bit value. It reaches the emitter intact as
`Ext { op: Sext, from_bits: 12, arg: Sym("imm") }`.

The important part is that an extension over an immediate is **not a DAG
node**. `(sext_inreg $imm, i12)` is untypeable — `i12` is not a legal MVT —
which is precisely why every `addi`-shaped instruction in the corpus had no
pattern, in both files, for a reason that read like an operator gap. Over an
encoded immediate the extension is a *range*, and LLVM spells a range as a
predicate on the operand:

    def simm12i32 : Operand<i32>, ImmLeaf<i32, [{return isInt<12>(Imm);}]>;
    def : Pat<(i32 (add RV_GPRRegs:$RS1, simm12i32:$IMM)),
              (ADDI RV_GPRRegs:$RS1, simm12i32:$IMM)>;

One def serves both roles on purpose. A Pat supplies its RHS operands
positionally into `InOperandList`, so the operand list is typed by the same
`simm12i32` — a pattern matching `simm12` into a slot typed `AXISimm` would be
selecting into an operand with no range at all. Over a *register* the same
extension is still `sext_inreg`; the caller decides, because only it knows
which symbols are immediates.

**The range is cross-checked, not assumed.** Two independent facts have to
agree before a predicate is written: the semantics says how many bits are
meaningful, and the layout says which bits are encoded. Unless the encoding
carries exactly those bits starting at the operand's bit 0, there is no
predicate and the instruction is declined by name. `LUI` is the case that
makes it concrete — its immediate is encoded from bit 12 up, so its low bits
are not in the instruction, and it keeps `AXISimm` and gets no pattern.

That guard is not decoration. Widening the emitted predicate by four bits, and
separately flipping its signedness, are both caught by
`llvm_patterns_check.py` against the golden model — because a predicate that
accepts more than the field can hold is exactly the claim "LLVM may select
this instruction for values it cannot encode", and the golden model disagrees
for those values.

Checking it required a change to that tool. It drew every operand as a full
`width`-bit random, which for a predicated immediate asks the pattern about
values the instruction cannot encode — and it disagreed for exactly those, as
it should. Immediates are now drawn from the range their predicate states,
which is a genuine narrowing of the sample space for those operands and worth
saying: those are the only values that reach the instruction.

`llvm_target_check.py` keeps the predicate when it normalises a DAG for the
cross-check, rather than stripping it with the register classes. Stripping it
would have let a target claiming `simm16` agree with a golden `simm12`.

### A description states itself in two places

`formal_semantics` is not the only place a description says what an
instruction computes, and for AArch64 it is not the usual one. 811 of that
corpus's 1715 instructions carry a structured `behavior` instead — the form
that can also express flags, memory and control flow, which the pure-value
language cannot:

    (behavior (set rd (a64_shift_reg i64 rn 0 rm)))     ; LSLV

`effects.rs` has always treated a behavior as authoritative exactly when
`formal_semantics` is empty, and `emit-llvm-ir` has always lowered from it.
The pattern builder read only the other one, and reported its absence as if
the instruction said nothing — which is why 765 of AArch64's declines read "no
formal_semantics" for instructions that describe themselves perfectly well.

So the inference is shared now, in `effects.rs`: the pure value expression an
instruction computes, from whichever place states it. A behavior qualifies
only in the shape one value can hold — a single unguarded effect writing one
of this instruction's output registers. A flag write beside the result, a
guard, a memory access, an effect of an atomic group: each is a real effect,
each is declined by name, and none is silently reduced to its first effect.

**The golden model had the same blind spot,** and finding it was the point of
sharing the inference rather than fixing the pattern builder alone. Its
generated evaluator for such an instruction raised `has no AXIS
formal_semantics`, and `AXIS_SPECS` held **2 entries for the whole 854-instruction
corpus**. Patterns derived from behaviors would have had nothing to be checked
against — the L3 invariant above, silently void for every one of them. The
evaluator now lowers from the same shared inference. `AXIS_SPECS` is
deliberately left alone: ten other tools iterate it, and this is a pattern-gate
fix, not a licence to widen their surface.

The two sides stay independent, which is the whole value. `pure_value_semantics`
returns the expression *unreduced*: the golden model implements
`a64_shift_reg` itself in Python, while the pattern builder reduces it in Rust
to a DAG node. Same description, two implementations, compared.

### Reducing a helper, only where it collapses

`a64_shift_reg(w, value, shift, amount)` selects between LSL/LSR/ASR/ROR on its
`shift` argument. Where that argument is an operand the instruction encodes a
*dynamic* shift kind and there is no SelectionDAG node for "one of four
shifts", so it stays unreduced and declined — 64 of the 80 uses, the
shifted-register `ADD`/`SUB`/`AND`/`ORR`/`EOR` forms. Their
`(requires (a64-shifted-reg i64 shift imm6))` is a legality predicate, not a
pin; despite the `ADD_X_SHIFT0` name the shift really is live.

Where it is a literal — LSLV/LSRV/ASRV/RORV — it collapses to one node:

| selector | reduction |
|---|---|
| `0` | `(shl v (and a w-1))` |
| `1` | `(lshr v (and a w-1))` |
| `2` | `(ashr v (and a w-1))` |
| `3` | `(ror v (and a w-1))` |

transcribed from the golden model's own definition, mask included. Swapping
LSR and ASR in it is caught on 8 instructions. The reduction lives in the
pattern path, not in `lower()`: `lower()` feeds the executors, SMT and golden
model, all of which are already proven, and none of them should move for a
pattern-yield feature.

**Dropping the amount mask is *not* caught, and that is correct.** The gate
reports `512 case(s) skipped: LLVM leaves the DAG undefined there` — an
out-of-range shift amount is poison, so the mask is unobservable through the
golden model. It is kept because it is what the description says and what real
backends write, not because anything proves it.

### Flag-setting, without knowing what a flag is

490 of AArch64's declines were behaviors with more than one effect, and the
commonest shape by far is a result *and* an `nzcv` write. A `Pat` holds one
value, so the reflex is to call these multi-result instructions and reach for
glue. They are not. The state write is not part of the value — it is a
**clobber**, and LLVM already has a spelling for that.

The technique is arch-agnostic in the literal sense that no part of it knows
what a flag is:

* **Declared scalar state becomes a register.** An ISA declares
  `"nzcv:i4"` beside `"x[31]:i64"` in its register list; a behavior writes it
  through `Loc::State`. Every such location becomes a `Register` and a class.
  On the AArch64 seed that is `nzcv`, `fpcr`, `fpsr`, `tpidr_el0`,
  `tpidrro_el0` and three exclusive-monitor locations; on RISC-V it is the
  exclusive monitor and `vxsat`. The rule named none of them.
* **A write becomes `Defs`, a read becomes `Uses`.** 116 AArch64 instructions
  declare a clobber they previously hid; `ADC`'s carry read becomes
  `Uses = [NZCV]`.
* **The value pattern is then honest.** `pure_value_semantics` partitions the
  state effects out and requires what remains to be the single register write.
  A pattern matching only the sum is correct *because* the clobber is declared:
  the allocator no longer keeps a live value in a register the instruction
  destroys.

The state locations are taken from the behaviors, not from `isa.registers`.
AArch64's `sp` is in the register list *and* inside the `a64_gpr64sp` class, so
emitting from the declaration would define one machine register twice. What a
behavior names through `Loc::State` is exactly the set with no operand to
carry it.

A four-bit state gets an `i32` class, because LLVM needs a legal type and its
own AArch64 target does the same thing with the same register.

**Two shapes stay declined, and should.** An instruction whose behavior writes
*only* state is a compare — `CMP`, `CMN`, `TST` — with no destination to select
on, which is a property of the instruction. And a conditionally written flag
(`CCMN` writes NZCV from the comparison or from a literal) is not the
unconditional clobber `Defs` describes, so it is declined rather than
flattened.

### The clobber had to be gated, and nothing was gating it

Dropping every `Defs` from the emitter passed **every** gate in this file:
tblgen accepts an instruction that lies about what it writes, the encoder
differential compares bits, and the golden model compares the destination
value. The one fact that makes flag-setting patterns safe was asserted by the
emitter alone.

It is now checked against a different emitter's view of the same behavior:
`emit-llvm-target` walks the effect locations, `emit-lift-json` publishes the
same behavior as an effect list, and the two must name the same states. Both
directions matter — iterating the *declarations* rather than the writes is what
catches a spurious clobber, since checking only instructions known to write
state skips exactly the instructions that should write none.

Writing that check found a real defect in itself: keyed on the raw mnemonic it
joined nothing for RVV, whose scalable lanes are `__l0` while a TableGen def is
uppercased — so three saturating instructions read as declaring a clobber they
did not have. The join now spells the mnemonic the way the target does.

### What flag-setting did *not* unlock

Zero new patterns at the time, and every flag-setting instruction was blocked
by something else. What the census says now, for the same five:

| instruction | blocked by, then | and now |
|---|---|---|
| `ADDS_X_SHIFT0` | `shift` — a dynamic shift-kind selector | `ADD_X_SHIFT0`'s pattern, which writes no state |
| `ADDS_X_IMM` | `imm` with no stated range, beside an `sh` selector | `ADD_X_IMM_SP`'s pattern, which is always present |
| `SUBS_W_EXT` | `option` — a dynamic extension-kind selector | mixed operand widths |
| `ADCS_X` | reads `nzcv`, which is a register and not an operand | unchanged |
| `CMP_X_SHIFT0` | writes only state — no destination | unchanged |

Three of the five now compute a DAG and lose it to the plain form, which is the
right outcome and not a block: a flag-setting instruction is worth selecting
for its *flags*, and its value is the plain instruction's. That is what makes
the remaining flag-setting work smaller than its headline ever suggested — the
value half is covered, and what is missing is a comparison feeding a branch.

So the modelling was right and the diagnosis was wrong: flags were never what
stopped these. What stops them is operand modelling — selector operands that
choose a shift or extension *kind*, and multi-part immediates — plus, for
`ADC`, a value that depends on a physical register, which needs glue rather
than a leaf. The work still pays: 116 instructions now declare clobbers they
were hiding, which is a correctness fact the target simply lacked, and the
patterns will follow when the operands are modelled.

### The encoding states a range even when nothing else does

174 AArch64 immediates and 16 RISC-V ones were declined for having no stated
range, and that read like a description gap: write the ranges and the patterns
follow. Only 18 of them had a decode constraint to write one from, so the gap
looked large and mostly unclosable.

It was the wrong reading. A field width is not a predicate — that part was
right, and it is why a signed 12-bit immediate cannot be inferred from twelve
bits of field. But the *layout* says something a width does not. The encoder
writes an operand's bits `[op_lo, op_lo + width)` into the instruction and the
decoder reads them back, so a value with a bit set anywhere else is one this
instruction cannot represent. That set is exact, it is not a guess, and
`roundtrip_check.py` already proves the layout it comes from.

RISC-V's `LUI` is the case that makes it concrete. Its operand is a full
32-bit value of which only bits 31:12 are in the instruction:

    def maskimmfffff000i32 : Operand<i32>,
      ImmLeaf<i32, [{return ((uint64_t)Imm & ~(uint64_t)4294963200ULL) == 0;}]>;

The same rule reaches a different answer for a branch offset — `maskimm1ffe`,
because the target is two-byte aligned so bit 0 is not encoded and cannot be
set. Nothing in the rule knows what a branch is.

The order of trust is what keeps this honest. A range the *semantics* states
wins: `(sext i32 12 imm)` means signed, and no layout can say that. Only when
the description states nothing does the encoding answer, and then it answers
with the encodable set rather than a rounded-up width.

**An immediate's declared width is not a value width.** Requiring every operand
to share the root width — right for registers, since a DAG leaf carries the
root's type — declined 178 instructions for the crime of having an immediate at
all: AArch64 spells a 12-bit immediate `i12` beside its `i64` registers. Only
register operands are held to it now, and what an immediate may hold is said by
its predicate.

## 9. Built: L4, and the line §2 draws

§2 says an ABI is not derivable, and that stands. Nothing here infers a
convention. What changed is that a description can now *declare* one, which is
a different act: RISC-V's ILP32 puts the first argument in x10 because a
committee said so, and the only honest way for a tool to know it is to be told.

```lisp
(defabi ilp32
  (isa rv32i)
  (pointer-bits 32) (stack-alignment 16)
  (stack-pointer (rv_gpr 2)) (frame-pointer (rv_gpr 8)) (link-register (rv_gpr 1))
  (arguments (rv_gpr 10 17))
  (returns (rv_gpr 10 11))
  (callee-saved (rv_gpr 8 9) (rv_gpr 18 27))
  (caller-saved (rv_gpr 1) (rv_gpr 5 7) (rv_gpr 10 17) (rv_gpr 28 31))
  (reserved (rv_gpr 0) (rv_gpr 2) (rv_gpr 3) (rv_gpr 4)))
```

Registers are named by class and index, because that is what AXIS has: §5's
first bullet says LLVM needs a `def` per register while AXIS has a class with a
count, and inventing architectural names here would have been the same mistake
in the other direction.

### What a declaration can be held to

Being told a convention does not mean accepting anything. Four rules are
contradictions rather than preferences, and each is a mistake a compiler acts
on silently:

* **The partition.** `reserved`, `callee-saved` and `caller-saved` cover every
  register of every class the ABI puts in a role, exactly once. A register in
  none of them is one a compiler cannot know whether to save across a call; a
  register in two is a contradiction between two statements the same document
  made. This is the rule with the most reach — dropping one register from the
  callee-saved run is caught, and that is a one-character edit.
* **An argument never lands in a reserved register.** Passing a value in the
  stack pointer, or in a register that discards what is written to it, is not
  something anyone can implement.
* **An allocatable stack pointer is not a stack pointer**, so the stack pointer
  is reserved.
* **A frame pointer the callee does not preserve is not a frame pointer**, so
  it is callee-saved.

What is *not* checked, and cannot be: whether the convention matches any real
platform's. AXIS has no way to know that ILP32 is ILP32. A description may
declare a convention nobody else implements — that is what describing a new
machine means — and the question this gate answers is whether whatever it
declared holds together. `tools/abi_check.py` re-derives all of it from
`axis.manifest.v1`, and eleven injections are rejected: a register with no
role, a register with two, an argument in the stack pointer, an argument named
twice, an allocatable stack pointer, a frame pointer nobody preserves, a link
register that discards, a stack alignment that is not a power of two, a pointer
width that is not, a class in no role, and an index past the end of the file.

### The differential, in L2's shape

`emit-llvm-target` emits `CC_<ABI>`, `RetCC_<ABI>` and `CSR_<ABI>` into the
same target file, and `llvm_target_check.py` runs `--gen-callingconv` over it
— the generator that would build this in a real backend. Then it compares the
register lists in LLVM's generated C++ against the declaration in the manifest.

The two sides share no code, which is L2's argument again: one is a Lisp
declaration, the other is C++ that LLVM's TableGen wrote. **Order is compared,
not membership.** An argument list is an ordered thing — `a0` first is what
makes it `a0`, and LLVM assigns positionally — so a convention with the same
registers in a different order is a different convention that would pass every
comparison of sets. Reversing the list, dropping one register from it, and
writing the callee-saved set into the return slot are each caught.

A callee-saved register that does not exist is caught by tblgen itself
(`Variable not defined: 'RV_GPR99'`), which is the right layer for it.

### Two things this does not deliver

Frame lowering and struct passing. `CalleeSavedRegs` is what a prologue reads,
but *emitting* a prologue needs stack-frame layout, spill slots and a red-zone
policy, none of which the register-level declaration states. Aggregate passing
— by value, by reference, split across registers and stack — is platform policy
with no register-level statement either, and inventing a rule for it would be
exactly what §2 rules out. Both are reachable from here and neither is
guessable, which is the same distinction this document has been drawing since
§2.

### The golden model cannot check this one

Widening a mask to admit bits the instruction does not encode was injected, and
`llvm_patterns_check.py` **passed it**. That is not a hole in the gate; it is
the gate being asked the wrong question. It evaluates *values*, and a value
with an unencodable bit set evaluates identically on both sides. Encodability
is simply not something a value model can see.

So the mask is checked where the answer lives: against the encode table's own
account of where an operand's bits go. `emit-llvm-target` derives the mask from
the layout, `emit-encode-json` publishes the same layout as slices, and the two
must agree. Re-injected, it names nine predicates across RISC-V, `LUI` and the
branch offsets among them. 537 predicates are checked this way on the AArch64
seed alone.

### A third dead guard

With every immediate carrying a predicate, the "immediate with no range"
decline stopped firing anywhere — and it stood *before* the semantics check, so
while it lived it took the credit for 174 AArch64 instructions of which 158
said nothing at all. It is removed: an instruction that reaches it is
`is_encodable()`, so every operand has bindings, and an immediate with bindings
always has a predicate. The `untypable operand` check below still catches an
operand with neither a class nor a predicate, and it runs after the semantics,
so it cannot mis-attribute.

That is the third guard in this work that overstated its cause, and the second
that could not fire at all.

### A field says how many bits; a constraint says which values

`ADD_X_SHIFT0` holds its shift kind in a two-bit field, so a predicate taken
from the encoding accepted four values. Its decode constraint permits three —
`a64_shifted_reg` renders to `shift < 3`, because that instruction encodes LSL,
LSR and ASR and *not* ROR. The target was claiming an encoding the decoder
rejects. That was live in the tree, not injected.

`DecodeConstraint::legal_values` now reads the exact set a constraint permits,
and the predicate is the intersection of that with what the encoding carries.
Two distinctions the data forced, neither expressible as a bit width:

* **A bound need not be a power of two.** `a64_extended_reg(amount)` permits
  `amount < 5`; a `uimm3` accepts 5, 6 and 7. It becomes `uimmlt5`.
* **A legal set need not be a range.** The extend kinds are
  `any(uimm_eq(option,2), uimm_eq(option,3), uimm_eq(option,6),
  uimm_eq(option,7))` — an enumeration with holes, which becomes
  `imm2_3_6_7`. A disjunction only constrains when *every* branch does; one
  branch that says nothing lets the whole say nothing, and there is a test for
  exactly that.

The gate moved from equality to **subset**, deliberately. A predicate may now
accept less than the field holds, because refusing an encodable value only
costs a selection while accepting an uncarriable one is the error. Widening a
mask is still caught, on nine predicates.

**This narrowing is not gated, and saying so is the point.** Ignoring the
constraint entirely was injected and both gates passed — `uimm2` *is* a subset
of a two-bit field, so the subset invariant has no objection. Catching it needs
the checker to decide which values a constraint permits, which means either
duplicating that rule in Python or publishing the legal set as an artifact.
Neither is done. A golden test pins the narrowed predicates against
regression; nothing proves them differentially.

### Three patterns that could never fire

`SLLI`, `SRLI` and `SRAI` each carried

    def : Pat<(i32 (shl RV_GPRRegs:$RS1, (and uimm5i32:$RS2, (i32 31)))), ...

`uimm5` already bounds the operand below 32, and LLVM folds `(and 5, 31)` to
`5` long before selection — the DAG for `shl x, 5` never contains the `and`
node the pattern demands. Dead, and counted in the yield.

A mask is dropped only when the operand's predicate already enforces it, which
is why the discrimination lands in the right place: an immediate shift loses
its mask, a *register* shift keeps it, because LLVM really does write
`(and rs2, 31)` there. The rule reads the predicate rather than the operator,
so nothing about it is RISC-V-specific.

The lesson generalises past the fix. A pattern count is not a coverage number:
these three were emitted, type-checked, agreed with the golden model, and
matched nothing. Everything the gates ask about a pattern is about what it
*means*, and nothing asks whether it can ever fire.

### Memory: the target never said it touched any

The AArch64 seed carries some 500 loads and stores, and the emitted target
declared **zero** `mayLoad`, `mayStore` or `hasSideEffects`. Every one of them
read to LLVM as arithmetic over registers.

That is not a missing optimisation, it is a licence to miscompile: LLVM may
reorder such an instruction against the loads and stores around it, sink it
across a barrier, or delete it when its result is unused. Nothing else in the
file implies otherwise — an operand list carries a memory *address*, and an
address is just an integer.

The facts were already computed. `effect_summary` is what the lift table
publishes and what the LLVM intrinsic emitter uses for its memory attributes;
the target simply never asked. 456 `mayLoad`, 412 `mayStore` and 41
`hasSideEffects` on the AArch64 seed, and nothing in the rule inspects a
mnemonic.

`hasSideEffects` is worth a note: TableGen infers it from an instruction's
patterns, and these instructions mostly have none, so the inference has nothing
to work from. Where the behavior says an instruction traps, orders memory, or
writes the PC, the target says so rather than relying on a default.

### Base writeback was already right, which is why it is now checked

A post-index load writes the loaded value *and* the updated base:

    def LDR_X_POST : ... (outs $RT, $RN), (ins $RN_tied, uimm9i64:$IMM) ...
      let Constraints = "$RN = $RN_tied";

That was correct before this work, and the check that says so was written
anyway, because the two halves come from different places and could drift: the
tie is derived from the operand's *declared role*, the write from the
*behavior*. Joining them found no disagreement across the corpora — 656
AArch64 instructions declare every register their behavior writes.

It did surface one thing, and surfacing it is the point. CASP writes `rs2`, the
second register of a pair, which is *derived* from the first — no field binds
it, so LLVM has nothing to decode into and cannot see the write. That is the
pair class §8 names, and the gate now counts it (16 writes) rather than leaving
it as prose. A documented gap that no check mentions decays into a forgotten
one.

### Injections

| injected | result |
|---|---|
| `mayLoad` dropped | 456 instructions named against the lift table |
| a spurious `mayStore` on every load | 120 instructions named |
| the writeback output dropped | caught — the behavior writes a register the instruction no longer declares |

Both directions again, deliberately. A missing flag lets LLVM move something it
must not; a spurious one blocks motion that is legal, which costs performance
silently and is the sort of thing nobody ever notices.

### What memory still cannot select

Declaring the effects is not the same as selecting on them, and the patterns
are a separate question with three different answers:

* **A simple load** — one value effect whose expression is a `load`. That is an
  ISD node and a plain `Pat` holds it; this is built, and the section below
  says what it took. `LDR_X_UNSIGNED` was the wrong example: its offset is
  scaled, so it *was* the one shape of simple load still out of reach — and
  scaled offsets are built too.
* **A store** — the effect's location is memory, not a register, so there is no
  result and a store `Pat` is a different shape. Built; the section below says
  what the shape cost.
* **A pre- or post-index access** — two value effects, and LLVM selects these
  through addressing modes in `ISelDAGToDAG` C++ rather than through TableGen
  patterns. Not reachable from a description; it belongs with the C++ glue in
  §8.

So the "writes N values" declines are not one problem, and counting them rather
than characterising them showed they were not mostly what this section assumed:
the pre- and post-index family — the third bullet, the one out of reach — was
the bulk of them.

**That number has since moved, and the paragraph that used to give it is a
lesson rather than a figure.** It read "344 are a store with base writeback and
48 a load pair: 392 of the 400", and claim resolution later reattributed most
of that row, leaving 104 in the census and 40 in the `setx2` shapes. The
grouping still holds; the counts did not, and they sat here wrong because
nothing recomputed them. The census table is checked now — see the section that
carries it — and these sentences give no count for that reason.

### A selector operand gets one pattern per value it encodes

`a64_shift_reg(w, value, shift, amount)` chooses between LSL, LSR, ASR and ROR
on its third argument. There is no SelectionDAG node for "one of four shifts",
so while that argument is a live operand the instruction has no pattern at all
— which is what declined every shifted-register `ADD`, `SUB`, `AND`, `ORR` and
`EOR` in the corpus, and with them the flag-setting arithmetic.

It has one pattern *per shift kind*, and the description says which kinds it
encodes:

    def : Pat<(i64 (add $RN, (shl $RM, uimm6i64:$IMM6))),
              (ADD_X_SHIFT0 $RN, $RM, (i64 0), uimm6i64:$IMM6)>;   // LSL
    ...                                          (i64 1) ...       // LSR
    ...                                          (i64 2) ...       // ASR

and no fourth, because `a64_shifted_reg` permits `shift < 3`. AArch64's
shifted-register `ADD` genuinely cannot encode a rotate. Nothing in the emitter
knows that; it reads the constraint.

This is why the earlier pieces had to come first. The specialised DAG is
`(shl $RM, uimm6i64:$IMM6)` — no mask — because the redundant-mask fold
removes one the operand's own predicate already enforces; without it every one
of these would have been a pattern that could never fire, exactly like `SLLI`.

**Both files specialise, over the same list.** The target selects an
instruction and the intrinsic hints name an intrinsic, but if only one of them
specialised the other would have nothing to check these against — the L3
invariant is that every target DAG is one `llvm_patterns_check.py` proves. The
pinned value travels in the argument list (`(int_axis_add_x_shift0 $rn, $rm, 0,
$imm6)`) so the golden model is asked about the form the pattern is actually
for, rather than about a random shift kind. 105 patterns evaluated on the
AArch64 seed, none disagreeing.

### The golden model does not know what the decoder rejects

Emitting the ROR variant anyway was injected, and **everything passed**. The
golden model evaluates `a64_shift_reg(w, rm, 3, imm6)` as a rotate quite
happily, because it models what the semantics *computes*, not what the decoder
*accepts*. The encoder differential compares bits for operand values it is
given. Neither asks whether `shift = 3` is a value this instruction can hold.

What catches it is joining the pinned literal to its own operand's predicate:
`uimmlt3i64` does not accept 3, and the pattern says 3. Twelve patterns named.
That works only because the predicate was already narrowed by the same decode
constraint two sections up — the earlier fix is what makes this one possible,
and on its own it looked like housekeeping.

It also closes part of the gap left open there. Ignoring the constraint when
building predicates is still unchecked in general, but a *pattern* that pins an
operand to a forbidden value is now caught.

### A load is peeled, not lowered

`Sem` is pure arithmetic, and every backend that matches on it — C, Rust, SMT,
the three executors — would have to learn a memory node to put a load there. It
does not need to. A load can only be the *root* of a value, so peeling it above
the lowering leaves an address, which is arithmetic, to the builder that
already exists:

    def : Pat<(i32 (sextloadi8 (add RV_GPRRegs:$RS1, simm12i32:$IMM))),
              (LB RV_GPRRegs:$RS1, simm12i32:$IMM)>;

A narrow load is `sextloadiN`/`zextloadiN` rather than a `load` and an extend,
because the combiner folds the extension into the load long before selection —
the unfolded pair would be a pattern that never fires.

### The offset was unsigned, and only the behavior knew otherwise

`LW` says `(set rd (load i32 signed (add rs1 (sext i32 12 imm))))` and has no
`formal_semantics`. The range inference read only the latter, found nothing,
and fell through to the encoding — which says a twelve-bit *field*. So the
target declared `uimm12i32` for an immediate the description sign extends:
`lw x1, -4(x2)` is ordinary RISC-V and the operand list refused it, along with
half the legal encodings of every load and store in the ISA.

Nothing caught this either, and the reason is the one from two sections up in a
new place. The golden model is not asked about an operand list. The encoder
differential compares bits for operand values it is *given*, and it is given
values the predicate admits — so a predicate that is too narrow simply narrows
what gets tested.

35 operand lists corrected: 7 on RV32I, 8 on RV64I, and 20 on the AArch64
seed, where they are the `LDUR` family and `ADR`/`ADRP`. AArch64's unscaled
loads take a signed nine-bit offset — that is the whole point of `LDUR` beside
`LDR` — and the target had been saying `uimm9i64`, so `ldur x0, [x1, #-8]` was
not an encoding it admitted.

### Not every load is a `load`

RISC-V's `LR.W` loads *and* records a reservation. `pure_value_semantics` sets
architectural state aside as a clobber — which is what lets `ADDS` have a value
pattern at all, and LLVM does see the clobber as `Defs` — but a reservation is
not a flag. A `load` node has nowhere to carry it, so selecting `LR.W` for an
ordinary load would claim a plain access, and LLVM would be free to delete a
reservation it cannot see. An ordering is the same story one level down: a
`Pat` cannot say `acquire`, so `LR.W.AQ` selected as a `load` drops the fence
the architecture promised. Both are declined by name.

### Two instructions, one pattern

`ADD` and `ADDS` compute the same expression and differ only in NZCV. With the
state write set aside as a clobber, their value patterns are *identical* — and
so are `SUB`/`SUBS`, `AND`/`ANDS`, and their W forms and accelerator twins.
TableGen would take one of them by an ordering rule the description has never
said anything about, and if it took the flag-setting form then every plain add
in the program would destroy NZCV.

Nothing was checking. Both DAGs are correct; `llvm_patterns_check.py` evaluates
each against the golden model and each passes. The check that was missing does
not look at a pattern at all — it looks at *two* of them, and asks whether one
left-hand side is claimed twice.

Between rivals, the instruction that writes no state is the pattern: a
flag-setting form is worth selecting for its flags, and this is not that. 18
resolved that way on the AArch64 seed. Nothing here knows what a flag is —
an ISA declares scalar state, a behavior writes it, and that is the whole rule.

Where the rule does not decide, both are dropped and both are named. RISC-V's
`FLS` and `LW` reduce to the same left-hand side, because the FP register file
is typed as integer in this description, and choosing the float load for an
integer one puts the value in the wrong register file.

### A pattern that can never fire

AArch64's unsigned-offset `LDR` scales its immediate, so its address reduces to
`(shl uimm12i64:$IMM, (i64 3))` — a shift of one constant by another. No
selected DAG has ever contained one: the combiner folded it long before. The
`ADD` immediate forms are the same shape, `(mul uimm1i64:$SH, (i64 12))`, and
so is `LUI`, whose whole value is an expression over its own immediate.

A node whose every leaf is a constant is now declined by name. This is the
`SLLI` failure mode found by hand earlier, stated as a rule instead: such a
pattern is not wrong, it is *dead*, and a dead pattern reads as coverage.

It declined 28 on the AArch64 seed, and they were not one thing. Four were
scaled load offsets, which the next section reaches. Eight are `ADD`/`SUB`
immediate-with-shift, whose scale is `(mul sh 12)` — an operand, so the
selector machinery has to specialise it before the scale is a constant at all.
The rest genuinely have no pattern of this shape: `MOVZ`/`MOVN` build a whole
value out of their own immediate, and LLVM materialises constants itself;
`EXTR` is a funnel shift, which is `fshr` and not this.

### A scaled offset matches the value and encodes the quotient

AArch64's unsigned-offset `LDR` addresses `rn + imm * 8` and encodes the
twelve-bit `imm`. Selection sees the *byte* offset, because that is what a
`load` node's address is — so the pattern matches a multiple of eight and the
instruction is handed the quotient:

    def uimm12s8i64 : Operand<i64>,
      ImmLeaf<i64, [{return (Imm & 7) == 0 && isUInt<12>((Imm >> 3));}]>;

    def : Pat<(i64 (load (add A64_GPR64SPRegs:$RN, uimm12s8i64:$IMM))),
              (LDR_X_UNSIGNED A64_GPR64SPRegs:$RN, (Div8XForm uimm12s8i64:$IMM))>;

Both halves of the predicate carry weight. The range is the field's, shifted;
the divisibility is what keeps an offset the instruction cannot represent from
being divided into one it can, which would silently address somewhere else.

**The instruction's own operand list is untouched.** It still takes the field,
`uimm12i64`, and the scale lives only in the pattern. That is deliberate: the
`ins` list is what the MC layer assembles and what the encoder differential
feeds, and re-typing it would have changed the question those are asking
rather than added one.

The scale is read from the behavior's `(shl imm 3)` and nowhere else — there is
no table of mnemonics to access sizes here, and there should not be, because
that would be a second description that could disagree with the first. Both
pattern files call the same `scaled_immediates`, for the same reason the
selector specialisations do.

### An ISA is a subtarget feature

Every remaining ambiguity had one cause: the AArch64 seed describes two ISAs —
the architecture and the accelerator it lowers to — and both were emitted into
one selection namespace, so `LSLV_X` and `ACCEL_LSLV64` claimed the same DAG.

The decoder had already met this. It treats an ISA as a `DecoderNamespace`,
because two decode contexts legitimately reuse bit patterns and without that
the seed collides in 271 pairs. Selection needs the same fact said a second
way: the first ISA declared is the machine that is always there, and every
other one is present only on a subtarget that has it. That is a
`SubtargetFeature`, and its instructions — and their patterns — carry the
predicate over it:

    def FeatureACCELERATOR_SCALAR64 : SubtargetFeature<"accelerator_scalar64", ...>;
    def HasACCELERATOR_SCALAR64 : Predicate<"Subtarget->hasACCELERATOR_SCALAR64()">;

The pattern needs it as much as the instruction does. A `Pat` without one would
let the selector choose an instruction the subtarget does not have.

That alone does not break the tie, though — where the feature *is* on, both
instructions exist and both patterns match. So between two rivals that are
otherwise equal, ISel takes the one that is always present, and the accelerator
is reached the way the description already says to reach it: `deflowering`,
which the seed states 425 times, with `requires` conditions like `(< $out 31)`
that a `Pat` cannot express at all. A pattern preferring the accelerator by
`AddedComplexity` would have been that condition dropped.

Naming is `tablegen_ident`'s, which uppercases — `hasACCELERATOR_SCALAR64` is
not what an LLVM backend would call it by hand. One naming rule that the
decoder namespaces, register classes and instruction defs all share is worth
more than a prettier identifier here and a second convention to keep in step.

### The load patterns were not proved, and now they are

The loads landed with the target's own gates behind them — the encoder
differential, the pattern-claimed-once check, the operand-order check — and not
the one that matters most. `llvm_patterns_check.py` evaluates a pattern's DAG
and compares it against the golden model, and its evaluator had no memory node,
so every `load`, `sextloadiN` and `zextloadiN` pattern was *declined* by it.
Seven on RV32I, fourteen on the AArch64 seed. The stated invariant is that
every target DAG is one that file proves, and for loads it was not.

Nothing said so. A decline is a line of output, the gate still passed, and the
count of patterns went up — which is exactly how a hole stays open.

What closes it is a memory both sides read. The point is not what it holds but
that it is the same function of the address on either side: a load pattern is
right exactly when its address computation matches the instruction's, so give
the two the same memory and any disagreement is a disagreement about the
address. The generated golden model already reads through a `__mem__` reader in
its environment; it is the per-instruction wrappers that build one without it,
and the checker owns the module it loaded, so the reader goes in on the way
past rather than through a signature every other consumer would have to grow.

All 29 RV32I patterns and all 97 on the seed now evaluate, none declined.

**Injected, both directions.** A scale off by one names exactly the four scaled
loads — `LDR_X_UNSIGNED`, `LDRSW_X_UNSIGNED` and their accelerator twins — and
nothing else. A load's signedness flipped names `LBU` and `LHU`. Neither was
catchable at all before this: the address arithmetic a scaled offset introduces
is precisely what a check with no memory cannot see, so the section above and
this one had to arrive together, and the first of them landed a commit early.

### A store has no result, and still has a pattern

`pure_value_semantics` declines a store by name, because a store computes no
value. It is still a pattern, in a shape none of the single-result machinery
applies to — asked before that machinery declines it for lacking what a store
never has:

    def : Pat<(store (i32 RV_GPRRegs:$RS2), (add RV_GPRRegs:$RS1, simm12i32:$IMM)),
              (SW RV_GPRRegs:$RS1, RV_GPRRegs:$RS2, simm12i32:$IMM)>;

Value first, then address, which is LLVM's order and not the description's. A
narrow store is `truncstoreiN`, the same fold `sextloadiN` is one direction
over.

Three things it needed that a load did not, and each was found by something
refusing it rather than by design.

**The stored value carries its type.** A store has no result, so nothing else
in the pattern pins one, and `rv_gpr` holds both `i32` and `i64` here because
the document names operands of both widths. tblgen says "Could not infer all
types in pattern" rather than guessing — the MC gate earning its place, since
nothing in AXIS could have known.

**A store has two widths.** The value is typed by the register it comes out of
and the address by the machine's pointer, and conflating them produced a
pattern for `FSD` — a 64-bit float store whose base register RV32I declares as
64 bits — that contradicted the target's own pointer type. tblgen reports that
as "Type set is empty for each HW mode", which names no cause at all. An
address wider than the machine's word is now declined by name, because it is
not an address this machine forms.

**Its offset was unsigned, again.** `SW` sign extends `imm` and the target said
`uimm12i32`. The same defect as the loads', one level further along: the range
inference reads `pure_value_semantics`, and a store has none, so it found
nothing and fell through to the encoding. Reading the store's own two
expressions fixes the operand list and the pattern's two halves together —
before it, the LHS said `simm12i32` and the RHS said `uimm12i32` for one
operand of one pattern.

### Proving a store

The loads shipped a commit before the check that proves them. Not this time.

A store is compared differently from everything else: not one number against
another, but *where* it writes and *what* — the two children of the node, and
the two things a pattern can get wrong. The golden model gains a `store_*`
beside its `eval_*`, returning the address, the value and the access width,
under its own name so nothing reading `eval_*` today sees a different shape.
The value is compared only as far as it is written: a `truncstorei8` pattern is
right about the low eight bits and says nothing about the rest.

The claimed-once check also had to learn the shape. It matched a root of
`(iN ...)`, which is a value pattern's; a store's root is the node itself, so
the store patterns were outside the one check that would have caught two of
them claiming one left-hand side.

**Injected.** The value and address swapped names `SH`, `SW` and `FSS`. A
truncating store's width doubled names `SB` and `SH` — and not `SW`, correctly,
which stores a whole register and has no truncate to get wrong.

It also found a real one, which is the better argument for it. The checker drew
every operand at the pattern's width — the first type in the text, which for a
store is the *value's*. AArch64's `STUR` stores a `W` register through an `X`
address, so its nine-bit signed offset was drawn masked to 32 bits: the pattern
got `0xffffff64` and the instruction sign-extended to 64 and got `-156`. The
two differed by exactly 2^32, which reads as a wraparound bug and is not one.
An operand is drawn at the width of its own leaf now, not the pattern's.

### What a resultless instruction types its operands at

Four gates failed the first time the stores ran across every corpus, and three
of the four were not about stores.

`operand_type` takes the width to type an immediate at from the instruction's
*result*, and falls back to 32. A store has no result, so RV64I's `SD` got an
`Operand<i32>` slot — and then a pattern passing it an `i64` immediate, which
tblgen rejects as "Type set is empty for each HW mode", naming the pattern and
not the operand list that caused it. The machine's word is what an operand of a
resultless instruction is typed at, and the predicate *definitions* had to
learn the same rule or the operand list names one that was never emitted.

The bug predates the stores. It was invisible while no resultless instruction
had a pattern, because nothing else in the file mentioned that operand's type.

The other two: an immediate in a store's *address* is typed at the address's
width and not the value's, which is the same `W`-through-`X` fact the checker
tripped on. And a scalable instruction's semantics names per-lane symbols
(`zs__l0`) that its encoded operand list does not carry, so `rvv` and `sve`
emitted patterns passing operands the instruction does not have — declined by
name, the way every other stage takes lane 0 as the representative.

### A load has two widths, and so does everything that types its operands

AArch64 reads a byte into a `W` register through an `X` address. The pattern
builder required every register operand to be the *result's* width, so that
whole family declined — 52 instructions on the seed, `LDRB_W_UNSIGNED` through
`LDR_W_UNSIGNED` and their accelerator twins — for a mismatch that is the
architecture and not a limit of the builder:

    def : Pat<(i32 (zextloadi8 (add A64_GPR64SPRegs:$RN, uimm12i64:$IMM))),
              (LDRB_W_UNSIGNED A64_GPR64SPRegs:$RN, uimm12i64:$IMM)>;

The stores had already had to learn this. What the loads added is that the same
fact reaches four more places, and it took each of them refusing in turn to
find them all — the operand list, the pattern's right-hand side, the predicate
*definitions*, and the checker.

**One rule, after three special cases.** An operand is typed at the width of
the half of the semantics it appears in: an address by the address, everything
else by the result. That is `operand_root_width`, and it exists because the
same defect had been fixed three times in three places — RV64I's `SD`, a
store's offset, a load's offset — and each time tblgen reported it as "Type set
is empty for each HW mode", naming the pattern and never the operand list that
caused it.

**The intrinsic hints never said what a pattern produces.** Their leaves are
typed by width, so the checker took the width from the first leaf — which is
the *address's* for a load whose address is wider than its result. Sixteen
patterns then compared the wrong number and disagreed with the golden model.
The root carries its type now, as the target's always has.

**And the golden model had the same confusion.** It evaluated a load's address
at the result's width, so `LDRB_W`'s address wrapped at 32 bits. The evaluator
has always taken a `load_address_width`; nothing had ever passed it, and the
frontend had been resolving it all along. Right for every load whose base is as
wide as its destination, which until now was every load with a pattern.

24 mixed-width declines remain and they are a different thing: `UMADDL`
multiplies two `W` registers into an `X`, which needs a width-changing node
rather than two widths in one pattern.

### A scale that is an operand, and the census that found it

AArch64's `ADD` immediate shifts by `sh * 12`, where `sh` chooses between
shifting by nothing and by twelve. That is a selector said in the open rather
than through a helper, and the machinery for both halves already existed: pin
the selector and the scale is a constant, which is a form that has a pattern.
Composing them took three small things, and each was a place the two pieces
had been written past each other.

**A narrow field enumerates its own selector.** `selector_specializations`
asked only the decode constraint, and `sh` has none — its *one-bit field* says
two values and says them exactly. The bound is two bits, because an operand a
pattern specialises over is a choice and a choice is small; without one a
twelve-bit immediate becomes four thousand patterns.

**Pinning leaves arithmetic where a scale needs a number.** `sh = 1` gives
`(shl imm (mul 1 12))`, which the combiner would fold and the pattern builder
would not. Constant subtrees are folded now — and identities with them, because
`sh = 0` gives `(shl imm 0)`, which is `imm`, and left standing it is a node
with two constant leaves that the constant-folded check then declines. The
unshifted half of every `ADD` immediate had no pattern while the shifted half
did.

**The scale is the specialisation's, not the instruction's.** Computed once for
the whole instruction, `sh = 1` inherited `sh = 0`'s scale — a pattern
selecting the shift-by-12 form for a plain `rn + imm`, multiplying the offset
by 4096. Both files had it, and **only the golden model named it**; nothing
structural would have. It is the third time a scale has been wrong in a way
that no amount of reading the emitted `.td` would show.

AArch64 70 → 174, and the constant-folded declines 24 → 4. What is left there
is honest: `EXTR` is a funnel shift whose rotate amount is arithmetic over its
own immediate. `LUI` and `MOVZ` now decline as *bare values* instead — their
whole result is one immediate, and LLVM materialises constants itself. That is
a better reason than the one they had, and it came free.

### The declines are printed now

Twice this work carried a claim that a gate was not checking: the load patterns
the golden check was declining rather than evaluating, and 62 AArch64 patterns
that were duplicates of each other. Both were found by reading what a checker
*declined*, never by reading a green line.

So `llvm_target_check.py` prints the census on every run — the count with no
pattern, the number of distinct reasons, and the top few. It is what pointed at
the W-register loads (52 under one reason), and what showed the 28
constant-folded declines were four different things. A reason that changes, or
a count that grows, is now visible without anyone thinking to look.

### The extension-kind selector, and what the census pointed at

§8 named `a64_extend_reg` as the last selector gap on the day the first one was
closed, and it stayed named for the rest of this work. What moved it was the
census: 82 declines read "semantics did not lower", and grouping them by the
operator their behavior actually uses showed **34 of the 82 were this one
helper**. One string had been hiding six causes.

The reduction is the same shape as `a64_shift_reg`'s. The option chooses a
source width *and* a signedness — `8 << (option & 3)` bits, sign-extended when
bit 2 is set — and then shifts left. Pinned, that is an extension of a register
and a shift, both of which the builder already had: unsigned is a mask, signed
is `sext_inreg`.

    (add $RN, (shl (and $RM, (i64 255)), $IMM3))          // UXTB
    (add $RN, (shl (sext_inreg $RM, i8), $IMM3))          // SXTB

**A helper's selector enumerates its whole field.** `option` is three bits and
needs all eight; the two-bit bound added for `ADD`'s shift selector would have
refused it. A helper's selector is a *choice* by construction — there is no
node for "one of these", which is the whole reason it is being specialised — so
the bound is only for an operand that merely appears in a shift amount.

**Two encodings of one behavior get one pattern.** At 64 bits UXTX and SXTX
extend nothing, so both reduce to `(add $RN, (shl $RM, $IMM3))`. That is the
architecture rather than a mistake, and the claimed-once check caught it as
`ADD_X_EXT, ADD_X_EXT all claim ...` — an instruction colliding with itself.
The first specialisation is taken; which encoding it selects is a choice the
description does not make.

**And the two-file comparison was weaker than it read.** It keyed each file's
patterns by mnemonic, so an instruction with several kept only the *last* —
comparing one arbitrary member of each set against another. It agreed for as
long as both files emitted the same list in the same order, and stopped the
moment the target dropped a duplicate specialisation the intrinsic file kept.
Every DAG is compared now, against the set the other file proves. On the
AArch64 seed that is 211 rather than 93.

### The one extension that changes width

`UMADDL` multiplies two `W` registers into an `X`. Its semantics says so —
`(add ra (mul (zext i64 32 rn) (zext i64 32 rm)))` — and the builder declined
it for "mixed or non-standard operand widths", because a register operand
narrower than the pattern looked like a mismatch rather than the widening the
description had just described.

The distinction is one line and it is not the one the first attempt made.
Whether an extension is a real width change is not "is `from_bits` less than
the pattern's width" — `a64_extend_reg` reduces to `(zext i64 8 rm)` over a
*64-bit* register, which is a mask and stays one. It is whether the **register
named is narrower than the pattern**:

    (mul (zext A64_GPR32Regs:$RN), (zext A64_GPR32Regs:$RM))    // UMADDL
    (shl (and A64_GPR64Regs:$RM, (i64 255)), $IMM3)             // UXTB

Getting it wrong cost twelve patterns before it gained eight, and the count is
what showed it: the first cut turned every in-place extension into a `zext` of
the wide register. The rule belongs in the *leaf*, which is the only place that
knows an operand's declared width, and not in the DAG builder, which does not.

**And a decline that named the wrong cause.** `LDAR` is a load-acquire, and its
expression carries the order — `(load i32 unsigned acquire rn)`. `peel_load`
matched only the three-argument form, so an ordered load was not recognised as
a load at all and fell through to decline for the *width of its address*, which
the load path handles perfectly well. The order is accepted by shape now and
refused by `load_pattern_objection`, which reads it from the effect. Eight
instructions that were miscounted under a cause they do not have.

**And the mirror, which is the same fact from the other side.** A register
*wider* than the pattern is a truncation: `ADD_W_EXT` adds an extended `X`
register to a `W` one and writes a `W`, so the 64-bit source comes down first.
The register keeps its own class — it is the value that narrows, not the
register file.

    (shl (and (trunc A64_GPR64Regs:$RM), (i32 65535)), $IMM3)

Mixed-width declines 24 → **0**. No instruction on any corpus is now refused
for the widths of its operands, and the test says exactly that rather than
naming a survivor — a decline asserted by name outlives the gap it described,
which is how a stale census happens in the first place.

### Writeback and atomics: two nodes the description already described

The two largest causes on the seed were counted as one for most of this work,
and both turned out to be reachable after being called out of reach.

**A store that advances its base** is `pre_store`/`post_store` — one result,
the updated base, and three operands. Which of the two it is comes from the
*order of the effects*: pre-index updates the base before the store, post-index
after, and both write the same two places with the same two expressions. The
ordered effect list is the only thing that separates them, which is what that
ordering is for. The instruction side was already right — `(outs $RN)`, `(ins
$RT, $RN_tied, $IMM)` and the tie have been emitted since the writeback check
was written, and nothing had asked them for a pattern.

**An atomic read-modify-write** is one node for both halves, and its result is
the *old* value — which is exactly what the register half of the description
holds. The operation is read from the stored expression by `atomicrmw_operation`,
which the IR emitter has always used and the target never called. The ordering
combines the two halves the description states separately: acquire is about the
read and release about the write, so AArch64's `LDADD`/`LDADDA`/`LDADDL`/
`LDADDAL` fall out as monotonic/acquire/release/acq_rel rather than being
tabulated.

    def : Pat<(post_store (i64 $RT), $RN_tied, simm9i64:$IMM), (STR_X_POST ...)>;
    def : Pat<(atomic_swap_i32_monotonic $RN, $RS), (SWP_W $RS, $RN)>;

Both were called unreachable in this document before they were tried. The
indexed stores were "C++ addressing modes, out of reach", asserted three times
without opening `TargetSelectionDAG.td`, which is on the same machine and
defines `pre_store`. Then the estimate of what that unlocked was 344, from a
census category that put atomic read-modify-writes and writeback stores in one
bucket because both write a register and memory; it was 16, and the other 320
were the atomics, which are also reachable. Four reachability judgements in this
work have been wrong, all four from reading a decline message rather than the
shape underneath it.

### The line that hid three of them

    DAG nodes exercised: ..., trunc, atomic_swap_i32_monotonic, ...

That list is read off the pattern *text*. A node `llvm_patterns_check.py`
cannot evaluate appears in it while every pattern using that node is
**declined** — counted in a line further down, under a `PASS`. Three families
shipped or nearly shipped behind it: the loads, whose gap took a commit to
notice; the truncations, reported here as "453 evaluated, 0 disagree" when the
patterns that commit added were not among them; and the atomics, 144 of them.

So the count of what was *evaluated* is printed beside the count of what
exists, and a decline is a census under a header that says these are not
checked against anything:

    613 pattern(s), 613 evaluated, 15136 evaluation(s), 0 disagree

`trunc`, `zext`, `sext` and the atomic nodes are implemented, and the two
numbers agree. The atomic comparison checks three things — where it read, what
it returned, and what it left behind — and immediately found the golden model
truncating a 64-bit address to 32, which is the load-address-width defect fixed
twice before, in the one place it had not been.

**Injected.** An `add` emitted as `sub` names `LDADD_W`, `LDADD_X`, `LDADDA_W`
and the rest, with the address and the returned value matching and only what is
left behind differing. Swapping pre-index for post-index names the store forms,
with the writeback matching and only the address differing.

### A narrow atomic keeps its register and names its memory

The node's name carries the *memory* width and the operands keep the
register's: `(atomic_load_add_i8 GPR64sp:$Rn, GPR32:$Rs)` is a byte atomic in a
`W` register, and it is how LLVM's own AArch64 backend writes one. Requiring
the two to agree — which this emitter did, in a check of its own invention —
declined every byte and halfword atomic on the seed, 144 of them, for a
mismatch that is not one. That is the fourth reachability limit here that was
asserted rather than checked, and the fourth that was wrong.

The golden model caught the thing that actually *was* wrong:

    FAIL LDUMAXB: pattern reads 0x9d ... and leaves 0x73,
                  instruction reads 0x9d ... and leaves 0x9d

A narrow atomic operates at the memory width. Handing `umax` a whole 32-bit
register makes it pick the operand whenever the upper bits are set, and no
amount of reading the emitted `.td` would show it — the pattern text is right
and only its meaning was wrong.

**And the root carries its type**, which only RV32I found. `rv_gpr` holds both
`i32` and `i64` there because the document names operands of both, so the
atomic's result type was ambiguous and tblgen said "Could not infer all types
in pattern". AArch64's classes are single-typed, so every per-corpus check
during development passed; the full ladder is what caught it, on the corpus
that was not being looked at.

### The census that should have existed first

`llvm_target_check.py` prints a census of declines by *message*. That is what
an emitter chose to say, and four times in this work it was read as a cause and
the estimate that followed was wrong:

| claimed | actual |
|---|---|
| "490 declines are a result plus NZCV; flag-setting is next" | writeback stores and atomics. Flag-setting is 16 |
| "pre/post-index addressing is C++ glue, out of reach" | `TargetSelectionDAG.td` defines `pre_store` |
| "344 writeback stores are reachable" | 16. The other 320 were atomics — also reachable, but not that |
| "a narrow atomic is not one node" | an invented limit; LLVM's own AArch64 backend writes those patterns |

Every one was corrected by grouping the *behaviors* instead — which had to be
hand-written, as a throwaway script, five separate times. So it is a tool:

    $ tools/decline_census.py examples/aarch64_translation_seed.axisl
    1455 instruction(s) with no pattern, in 116 shape(s)
       29  set+store atomic mixed-widths
       22  setx2 mixed-widths
       16  set via:a64_cond_holds
       16  setpc guarded

A shape is what the description states: the locations a behavior writes, then
what picks between the nodes of that kind — atomicity, ordering, whether a
register written is the address read, which helpers it names, whether the
widths differ. `--shape writeback` or `--shape cond_holds` lists the members.
Each group also shows the *messages* its members were refused under, because
one shape under several messages means the emitter is describing one cause
several ways, and one message over several shapes is how all four errors above
happened.

It found a lie in itself on the first run: 46 instructions filed as "no
behavior" were `formal_semantics` ones, which have no effect list because they
state one expression instead. Putting instructions that describe themselves
perfectly well under a heading saying they describe nothing is the exact error
the tool exists to prevent, so it is worth saying that it made it.

### The yield, plainly

586 patterns across twelve corpora, every left-hand side claimed exactly
once, and every one of them evaluated against the golden model — the gate says so rather than the prose. AArch64 has no ambiguity
left at all. Four remain in RISC-V, and they are not this cause: `LW`/`FLS` and
`LD`/`FLD` are one ISA, and they collide because the FP register file is typed
as integer in that description. That is a value-type question, not a subtarget
one, and it is in §8.

### Two declines that were wider than their reasons

`sdnode_name` refuses an operator by naming why, which is the right shape and
is what made the refusals auditable at all. Auditing them found two that
refused more than their stated reason covered.

**`Op::Mulh | Op::Mulhu | Op::Mulhsu`** were declined together, under the note
that "`mulhs`/`mulhu` exist as ISD nodes but the mixed form does not". That is
the reason for **`mulhsu`** — a signed multiplicand with an unsigned multiplier
is a RISC-V idea and SelectionDAG has no name for it — and it was being applied
to its two siblings, which map exactly onto nodes LLVM already has.

**The integer comparisons** were declined because "a comparison produces an i1
that has to be widened, which is two nodes rather than the one a pattern
matches". True of the value, not of the pattern: LLVM's own RISC-V backend
writes `Pat<(setlt GPR:$rs1, GPR:$rs2), (SLT ...)>` and lets type legalisation
widen the i1 into the register the instruction writes.

Both emit now. `llvm-tblgen` builds a matcher containing all of them: rv32i
went 66 → 72 selectable instructions, rv64i 110 → 116, twelve patterns across
the corpora. The remaining declines audited clean and stay — **division**,
because `sdiv`/`udiv` are undefined on a zero divisor where RISC-V defines −1,
so a pattern would be *wrong* rather than missing; **floating point**, because
AXIS's canonical-NaN rule is not expressible in a pattern and one would claim
more than the instruction guarantees; **dynamic rounding**, because the
constrained intrinsics take rounding as static metadata.

⚠️ **A pattern emitted but unverified is a step backwards.** Both new node
families arrived in the target, reached the matcher, and were `DECLINED` by
`llvm_patterns_check` — its evaluator had never heard of `mulhs` or `setlt`, so
the instructions became selectable and unchecked in the same change. The
evaluator learned them, from LLVM's definitions rather than from AXIS's. 586
patterns, 586 evaluated, none disagreeing. **Emitting more patterns is only a
gain when the gate that checks their meaning grows with them**, and the gate
reporting those two as declined rather than passing them is the only reason
that was visible.

The path there was not monotonic, and the intermediate number is the honest
part of the story. It was 151 before any of this; the loads and the signedness
fix took RISC-V up (RV32I 23 → 27, RV64I 20 → 26) while the three new refusals
took AArch64 down to 21, because 44 of its 93 were ambiguous, 18 were a
flag-setting form holding the plain form's pattern, and 28 were constant-folded
and could never have fired. Subtarget features then returned the 22 the
ambiguity had been costing the base ISA, the scaled offsets four more, the
stores twelve, the W-register loads eleven, and the immediate-with-shift
specialisations a hundred and four, the extension kinds thirty-seven, the
widening multiplies and truncations twenty-four net, the writeback stores
eight, and the atomics a hundred and forty-four, so AArch64 finished at 384.
RISC-V's A extension came along with the last of those: RV32I 31 -> 67,
RV64I 32 -> 104.

The 565th arrived later and from an unexpected direction: RVV's `vsetvli` was
described against the vector format, so its scalar operands bound to no field
and it was not encodable — and an instruction with no encoding gets no pattern,
whatever its semantics say. Giving it a format its operands fit made it
selectable as `(umin $avl, VLMAX)` with `Defs = [VL]`, by the same rule that
makes a flag-setting instruction selectable: the state write is a clobber
declared to LLVM, not part of the value. Nothing about the pattern emitter
changed.

So the count passed its starting point only at the end, and 151 → 564 understates
the change: the 151 included 62 patterns that would not have selected what they
claimed. The 151
included 62 patterns that would not have selected what they claimed.

Five corpora emit none at all; for those the ISel gate passes vacuously, which
is worth saying rather than reading a green line as coverage.

Every decline is named, and the census is now honest about *why* — which it
was not. Whether an instruction says what it computes is asked before any
question about a pattern's shape, because an instruction that states nothing
fails every shape check and whichever ran first took the credit:

| cause | before ordering | after |
|---|---|---|
| not a single-result instruction | 253 | **6** |
| an immediate with no range | 174 | **140** |

That is the same fault as the register-class guard two sections up, found for
the third time in one session, and it matters more than a tidy table: a census
that overstates a cause points the next piece of work at the wrong gap. It
very nearly sent this one at "AArch64 has 174 closable immediates" when it has
16.

The real map of AArch64, once the causes are attributed correctly. This table
is **recomputed by `tools/doc_facts_check.py`**, labels included, so a reworded
reason or a shifted count fails a gate rather than sitting here:

### A later effect may read what an earlier one wrote

`llvm_effect_expr` checked every symbol against the instruction's **input
operands** before rewriting it to the SSA value that holds it. That order is
deliberate and stays -- a renamed symbol is a temp and would not be in the
allowed set -- but the allowed set was too small. A destination an earlier
effect wrote lives in `renames`, and a later effect is entitled to read it.

RISC-V's `fls` is the case: it loads 32 bits into `rd` and then NaN-boxes what
it loaded, `rd | ~ones(32)`. `rd` is an output, so it was not an allowed symbol,
and the instruction was withheld -- though the temp holding the loaded value had
just been emitted three lines above. Declaring `rd` as `inout` makes it lower
and says something false: the instruction does not read the register's entry
value, it reads its own intermediate.

The set is `symbols` plus whatever `renames` binds now, which is sound because a
name in `renames` is defined by construction. `fls` lowers, and the lifter sweep
executes it against the executor -- 195 instructions compared becomes 197, no
disagreements. That verification matters here: `llvm_effects_check` cannot check
it, because `fls` writes the same register twice and a final register file
cannot say which write produced it, so it is one of the 24 cases that gate skips.

RV64I is 211 of 338 lowered now. What remains is 126 directed-rounding forms --
blocked by LLVM discarding the mode, which `fp_rounding_check` re-measures every
run rather than trusting -- and `fence_i`, an instruction barrier with no
`fence` that means it. Neither is a gap this backend can close alone.

### A store's value may be a load

Four instructions in `blockmem` carried the same message for a different cause:
a store whose *value* is a load, which is memory to memory in one effect. The
store arm lowered its value with `llvm_effect_expr`, and `load` is not an
operator the pure IR has -- while the register-set arm had peeled a load into a
memory read plus an extend all along. Using `llvm_effect_value` there is the
same peeling for the same reason, and an ordinary value falls through unchanged.

**Lowering them found a bug in the executor.** Three of the four then disagreed
with the Python reference, and the reference was the one that was wrong:
`memcpy16` read byte 313 as byte 57, which is `313 & 0xff`. A stored value that
is a load has an address as wide as the machine and an element as narrow as a
byte, and the `store` branch evaluated that address at the *element* width. The
`set` branch had always passed `load_address_width`; the `store` branch never
did. `memcpy8_w` passed throughout and hid it: its element is 32 bits, wide
enough for the addresses the harness draws.

Nothing had noticed because the two blind spots lined up. The LLVM backend
refused a store whose value is a load, so it never disagreed with the executor
about one -- a backend that declines and a reference that is wrong about the
same construct agree perfectly, by never being asked.

The fifth, `cgra_enter` in `cgra_fabric`, stays withheld and now says why in its
own terms: it reads a register the description names itself, `getreg reg 3`
rather than an operand, and this ABI passes memory, the pc, the result and
architectural state -- no register file.

| cause | count |
|---|---|
| non-standard result width | 657 |
| claimed by an instruction that is always present | 212 |
| not a single-result instruction | 156 |
| behavior writes N values beside its state; one value cannot hold them | 111 |
| claimed by an instruction that writes no state | 98 |
| semantics did not lower: unsupported formal_semantics operator X | 53 |
| behavior writes only architectural state | 45 |
| no SelectionDAG pattern for these operators | 35 |
| semantics names X, which is not an operand | 32 |
| the access is guarded | 32 |
| everything else, in 18 further reasons | 118 |

### What the unpatterned population actually is

"Describe the rest" is the obvious next move and it is mostly wrong. Counting
rv32i's 164 unpatterned instructions by kind says so:

| count | kind | describable as a pattern? |
|---|---|---|
| ~120 | floating point with explicit rounding — `FADD`×12, `FDIV`×12, `FMADD`×12 … | **no**: the canonical-NaN rule is not expressible, and rounding is static metadata on a constrained intrinsic |
| 22 | CSR reads and writes | **no**: a compiler does not choose `CSRRW` to compute something |
| 8 | `LR`/`SC` | **no**: a reservation pair is not a single-node match |
| **6** | conditional branches | **yes** — LLVM spells it `brcond` |

The twelve-fold repetition is the rounding-mode cross product, and it is the
single largest reason the raw number looks alarming. **Roughly nine in ten of
the unpatterned instructions are correctly unpatterned**, and a plan that set
out to describe them all would have spent its effort making patterns that claim
more than the instructions guarantee.

The conditional branches are the real population, and AXIS already describes
them in exactly `brcond`'s shape: `(when (icmp_eq rs1 rs2) (setpc (add pc
(sext 13 imm))))` is a condition and a place to go.
`effects::conditional_branch_semantics` recognises that shape and refuses the
neighbours by name — an unconditional jump is `br` and not this, an indirect
branch computes its target from a register and `brcond` cannot say that, and a
target assembled from several operands leaves no honest way to choose which one
a pattern hands LLVM. It finds 6 in rv32i, 8 in rv64i and 18 in the AArch64
seed.

⚠️ **The census names them now; the pattern is not emitted yet, and the reason
is specific.** A `brcond` binds its target as `bb:$imm`, which requires the
operand to be `Operand<OtherVT>` — real RISC-V declares `simm13_lsb0` exactly
that way. AXIS derives an immediate's operand class from its field mask and
*deduplicates by name*, so `maskimm1ffei32` is shared between a branch offset
and any ordinary immediate with the same mask, and one class cannot be both
`i32` and `OtherVT`. Branch targets need their own class name before a pattern
can exist.

⚠️ And AArch64's branches are a second shape, not the same one late: their
condition is `(icmp_ne (a64_cond_holds nzcv cond) 0)`, which reads
architectural flags rather than operands. `setcc` on two registers cannot say
that, and pretending otherwise would be a pattern about a machine this is not.

Until then the census says *conditional branch* rather than filing them under a
heading about value semantics — which is the whole discipline of this table.
A census that overstates a cause points the next piece of work at the wrong
gap, and these had been counted as instructions that failed to state what they
compute, when what they state is where to go.

**Almost half of these are not gaps.** 310 of the 693 — the two "claimed by"
rows — are one instruction losing a DAG to another that has it: `ADDS`'s value
is `ADD`'s, and a flag-setting or optional-ISA form is declined so that exactly
one def claims each left-hand side. The DAG is emitted; a second copy of it
would be the duplication `check_no_pattern_claimed_twice` exists to refuse. A
reader counting declines as missing coverage would be overstating the gap by
the largest row in the table.

The gaps are what remains: 104 behaviors holding more than one value, 52
operators that do not lower, 42 writing only state, and the guarded and
non-operand rows beneath them. `tools/decline_census.py` groups the same
instructions by what their behaviors *are* rather than by the message, which is
the axis to read when choosing what to build — it is how the pre- and
post-index family, the `a64_cond_holds` sixteen and the `a64_wmask` twelve were
each identified.

### This table has been wrong twice, differently

The first time it read "490 of 809 declines are multi-effect behaviors,
overwhelmingly a result plus NZCV", which stopped being true the moment
architectural state was separated out as a clobber, and "flag-setting is next"
was repeated as the plan across a whole session.

The second time it read "400 declines are pre- and post-index addressing, the
largest cause on the seed" — with a sub-table attributing 344 of them to stores
with base writeback — under a sentence promising it was *"printed on every run
now, so this table is what the gate says rather than what someone remembered"*.
It was not: the gate printed a census and nothing compared the two. Claim
resolution landed afterwards and reattributed most of that row, and the table
went on saying 400 while the gate said 104.

Twice is a pattern, and the fix is the one this repository already applies to
every other number it states. The table above is checked now — by identity on
the labels, not just the counts, because a renamed cause is a changed census.
A document that says its numbers are computed and is not made to prove it will
say that again.

## 8. What is not built, by name

Counts are the AArch64 seed's, and they are the by-shape numbers
`tools/decline_census.py --top 200` prints. **They are not checked** — the
census two sections up is, but an entry here is a judgement about which shapes
belong together, and a judgement is not a number a gate can recompute. Read
them as measured-when-written, and re-measure before planning against one — the
first of them had already drifted from 64 to 40 by the time this line was
added.

The list is ordered by size, which is not the order it was written in: three of
the entries that used to head it are built, and the two that head it now were
never the plan.

* **A load with writeback, and a load pair.** 40 declines — the `setx2` shapes,
  22 of them with mixed operand widths. An indexed *load*
  produces two results — the value and the updated base — and a `Pat` produces
  one, so LLVM selects these in `ISelDAGToDAG` C++. This is the part of the
  writeback family that is genuinely out of reach; the stores are built.
* **Condition codes.** `a64_cond_holds` selects on NZCV — 16 declines where it
  is the whole of the instruction's value, and 18 more where it appears beside
  a flag write or a guarded branch. A
  pattern cannot name a physical register as a leaf, and this is the same
  obstacle as `ADC`'s carry one level up. It is also the *whole* of the
  flag-setting gap that remains, because a flag-setting instruction's value is
  the plain instruction's and is already covered: what is missing is a
  comparison feeding a branch.
* **`a64_wmask` and the bitfield helpers.** `a64_wmask`, `a64_ubfm` and
  `a64_sbfm` compute a mask from `immr`/`imms` by an algorithm rather than by
  an expression — 20 declines where one of them is the whole value, 6 more
  beside a flag write. LLVM spells their results as its own
  `logical_imm` and `bfm` operand classes with C++ decoders behind them, which
  is a description of an *encoding* and not of a DAG.
* **A float register file that says so.** _Closed._ AXIS models a float as its
  bit pattern, so an FP operand is declared as an integer and it is why
  `FSGNJ` — integer bit operations on an FP register — has patterns at all.
  The class used to come out `[i32, i64]` and `FLS` loading a float reduced to
  the same DAG as `LW` loading an integer, so both were dropped for the
  collision: 4 declines, described here as "the last ambiguities in any
  corpus" and as needing a change to what AXIS can *say*.
  It did need one, and it was not the one this paragraph expected. RISC-V's
  `f` file is 64 bits wide whenever `D` is present — FLEN comes from the
  extensions, not from XLEN — and RV32's description called it 32 bits for its
  F instructions and 64 for its D ones. One file, two widths. Once a register
  class could declare its file's own width, the operands agreed, the class
  came out `[i64]`, and the collision was never real: a single load writes 64
  bits and NaN-boxes them. `LW` has its pattern. No corpus has a collision
  left.
* **A guarded behavior.** 18 declines. A conditionally written result is a
  `select` LLVM would have to see, and the effect model puts the condition
  outside the expression.
* **A value that depends on a physical register.** `ADC` takes its carry from
  `nzcv`. The read is declared as `Uses`, but a pattern cannot name a register
  as a leaf; LLVM threads these with glue.
* **A pair class.** CASP's second register is dropped from the operand list
  rather than modelled as half of a register pair. The encoding is right — it
  is not encoded — but a backend that allocated registers would need the pair
  class, and that is a register-model change.
* **The C++ glue.** `TargetMachine`, `MCTargetDesc` registration, `AsmPrinter`,
  `ISelLowering`. Mechanical, large, and unprovable without an LLVM source
  build, which this environment does not have.
* **An ABI, and therefore compiling C.** Calling convention, callee-saved
  registers, frame layout. Not properties of an instruction set, and AXIS does
  not describe them. This is a description change, not an emitter change, and
  until it exists "generate a backend that compiles C" is not reachable — the
  MC layer and instruction selection are.
* **Register widths in the value type.** A class's value types are read off
  the operands that name it, so a 64-bit file whose operands are 32 bits wide
  is `[i32, i64]` rather than `[i64]` — which is what makes a pattern over it
  typeable at all. That is still an integer story: a vector class is given the
  element view's MVT, and a scalable register has no fixed one.
