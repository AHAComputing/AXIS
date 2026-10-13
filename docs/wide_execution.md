# Executing at 64 Bits

Status: **implemented for pure semantics and effects** — `tools/exec_wide_check.py`,
driving C and Rust.

## 1. The gap

`tools/exec_c_check.py` drives the generated C executor through its compact
32-bit ABI and skips any instruction whose operands or state are wider. The skip
carried a reason:

> The compact ABI is 32-bit. An instruction whose operands are wider belongs to
> the separately checked wide executor.

For AArch64 that was true — `tools/aarch64_native_state_check.py` drives the
wide ABI with hand-written cases. For everything else it was not. RV64I's 216
instructions, and every 64-bit corpus after it, went unexecuted by C or Rust
entirely: the compact check skipped them and no wide check covered them.

The skip was accurate about itself and wrong about the world, which is the
failure mode a comment cannot catch. What made it visible was asking how many
gates the phrase "separately checked" actually pointed at: one, for one
architecture.

## 2. What was missing was a driver

Nothing needed generating. The emitted header has always had the general entry
point:

```c
axis_exec_step64(uint32_t word, const char *isa, uint64_t *regs,
                 size_t reg_count, const axis_mem64 *mem, uint64_t pc,
                 axis_state64 *state)
```

`tools/exec_wide_check.py` drives it with the same roundtrip fixtures the
compact check uses, against the same golden model. RV64I: **122 instructions
executed at 64 bits**, where previously none were.

## 3. Two bugs it found immediately

**The wide executor did not recognise most register classes.** It decided
whether an operand was a register with

```c
strstr(op->kind, "reg") || strncmp(op->kind, "a64_gpr", 7) == 0
```

which matches `"reg"` and AArch64's classes, and **not** `"rv_gpr"`. So every
RISC-V register operand was passed to the evaluator as its raw *index*: `ADDI`
with `rs1 = 2, imm = 3` returned 5. The compact path had always used
`axis_reg_class_of(op->kind)`, the generated table, and the wide path had a
substring test — two answers to one question, which is the shape of nearly every
defect in this repository. The wide path now reads the table.

The bug was invisible for as long as the wide path had exactly one user, and
that user's register classes both happened to be special-cased by name.

**My driver disagreed about the zero register.** RISC-V's `x0` reads as zero and
discards writes, and a driver that fills it with a random value expects results
the executor will never produce. The rule is in `REGISTER_CLASSES`; reading it
from there rather than knowing it is the same discipline the executor needs.

## 4. Declines are not disagreements

`axis_exec_eval64` covers 61 of RV64I's instructions and has no case for
high-half multiply or the directed-rounding FP forms. Reporting those as
failures would make a gate that can only pass by the executor growing features,
so they are counted and named: **122 executed, 86 declined, 0 failures**.

Naming them is the useful part. The declines are a list of what the wide C
executor cannot yet do, which is a fact about the executor rather than about any
description.

That list has since gone to zero, and a count of zero is worth *enforcing*
rather than reporting: §8c.

## 5. Effects at 64 bits

The effect path is the reason the wide ABI exists. The compact ABI has nowhere
to put architectural **state**, so `exec_c_check.py` skips any instruction that
touches it — which means RISC-V's reservation state and AArch64's flags have
only ever been executed through bespoke harnesses.

The wide driver runs them: registers, memory, state, next-pc and traps, all
compared against the golden model evaluated effect by effect in order. RV64I
goes from 122 executed to **346**, and block-memory copies execute for the first
time in any C executor.

Three things it needed that the compact path did not:

* **State, seeded rather than zeroed.** Zero is also what a broken state read
  produces, so every declared state slot gets a random value.
* **`setpc` evaluated at the ISA word.** The compact driver hardcodes 32, which
  truncates a 64-bit branch target — precisely the case this path exists for.
* **Only the surviving write asserted.** RISC-V's `FL.S` loads a 32-bit float
  and then NaN-boxes it into the same register: two effects, one destination.
  Asserting both intermediate values fails against a correct executor. The same
  applies to two stores to one address.

It also surfaced a limitation shared by both emitters: **a store whose value is
a load is not lowered into an effect function at all.** `MEMSET32` stores a
register and is emitted; the three block *copies* are not, by either the compact
or the wide emitter. The driver reports them as declines rather than passing
over them.

Verified by injection: a wrong `next_pc` gives 213 failures, and a store that
drops its value gives 119.

## 7. Rust at 64 bits

`--lang rust` drives `step64` in the generated Rust executor, from the *same*
reference data as the C path. That sharing is deliberate: the hard part of this
check is the reference — sequencing effects, keeping only surviving writes,
honouring the hardwired zero register — and two copies of it would be two things
to keep in agreement. Only the rendered driver differs.

It found the same bug twice over. The Rust wide path decided whether an operand
was a register with `operand.kind == "reg" || kind.starts_with("a64_gpr")` —
character for character the same mistake the C wide path had, in the parallel
emitter, and invisible for the same reason: no driver had ever reached either.
Both now consult the generated register-class table.

It also found a gap the C side did not have. `rust_wide_expr` handled `icmp_eq`
and `icmp_ne` but none of the ordered comparisons, so `SLT`, `SLTI`, `SLTU` and
`SLTIU` had no wide Rust evaluation and declined. With those added the two
executors agree exactly — **346 executed, 86 declined, 0 failures** on both,
which is a better signal than either number alone: the same instructions run,
and the same ones are declined, in two independently generated backends.

## 8. What the executors decline, and why

The drivers name what they decline rather than only counting it, and the list is
now short enough to be a statement about the executors:

| Declined | Count | Reason |
|---|---|---|
| directed-rounding FP (`_RTZ`, `_RDN`, `_RUP`) | 30 | Rust and LLVM cannot express a rounding mode; recorded in `simd_fp_design.md` §8 |

That is the whole list, and it is now a *limit* rather than a mixture of limits
and gaps. Two things came off it.

**FP conversions** needed one thing the other operators did not. Every other
case in the wide lowering treats its arguments as expressions, but a conversion
branches on the *source* width as a number — whether the input is a single or a
double decides which helper reads its bits — so the literal has to be read off
the argument before that argument is lowered. With that, all ten convert.

**High-half multiply** used to be on the list. It needs an intermediate twice the
evaluation width, which `uint64_t` cannot hold — but `unsigned __int128` in C and
`i128` in Rust can, and the AArch64 `smulh`/`umulh` helpers had relied on the
former since they were described.

Together the two took both executors from 346 to **372 executed, 30 declined, 0
failures**, and they remain identical to each other at every step. That equality
is the number worth watching: the same instructions run and the same ones are
declined in two independently generated backends, so a divergence shows up as it
happens rather than as drift.

The C half of that list is now empty; see §8c. The two executors are no longer
identical, and the reason they differ is the one thing they cannot share.

## 8c. The C list is now empty, and that is checked

The row above says Rust and LLVM cannot express a rounding mode. True — and C
can, through `fesetround`: the `axis_fp*_rm` helpers have been in
`axis_semantics.h` since F3, and `fp_rounding.axisl` proves them against the
golden model on the *pure* path. The wide effect path simply had no arm for
them, and nothing said so, because a decline is not a failure.

What that cost was not thirty instructions. Every RISC-V FP instruction with a
rounding mode — static or dynamic — accrues `fflags`, which makes it effectful,
which is why the compact driver declines it for touching state. Ninety
mnemonics per RISC-V corpus were therefore executed by **no compiled executor at
all**, and both drivers reported that honestly as a decline. Adding the arm:

| | before | after |
|---|---|---|
| RV32I | 132 executed, 180 declined | **312 executed, 0 declined** |
| RV64I | 444 executed, 180 declined | **624 executed, 0 declined** |

Zero failures in both, so the lowering agrees with a golden model that decides
the same roundings from exact rationals.

Every corpus this ladder gates now declines nothing in C — AArch64's 1708
fixtures included. So the driver checks it: `--max-declines` defaults to **0 for
C** and to unlimited for Rust, which declines the directed-rounding and
exception-accruing families because it has no access to the floating-point
environment at all. Dropping the arm again turns 90 silent declines into a red
gate, which is the difference between reporting coverage and holding it.

The default lives in the driver rather than as a flag on each of the eleven C
gates, because a twelfth would not know to carry it — which is exactly how the
claim would quietly stop being made.

## 8a. The register slot is 64 bits, and the gate now says so

The emitted executors hold registers in `uint64_t` slots. Pointing this driver
at the 128-bit Q-register corpus reported **16 executed, 0 declined, 0 failures**
— and that was not evidence of anything. The driver generates 64-bit register
values, so the upper half of every 128-bit operand was zero, and both sides
agreed about a case neither was exercising.

It now declines instead:

```
8 case(s) past the 64-bit register slot, not executed: VADD_16B, VADD_4S, ...
SKIP: nothing wide to execute (0 narrow, 8 past the register slot)
```

Which is worth more than the pass was. The gap is named, and the slot width is a
single constant in the driver rather than a `64` spelled inline — when the
storage widens, one place decides which instructions become runnable.

**Superseded.** The paragraph below argued for a fourth ABI; `docs/limbs.md` builds limb storage instead, which removes the ceiling rather than moving it. A register now occupies several 64-bit slots, so the ABI is unchanged and the slot width is no longer what bounds a register's width — a *value*'s width is, and under lane-indexed instantiation every value is ≤ 64 bits. What follows is kept because its reasoning about the cost of a wider tier is why limbs were chosen over one.

**Widening it is a fourth ABI, not a type swap.** `uint64_t *regs` appears in
only five places per language, which makes it look small. It is not: a 128-bit
register read has to *produce* a 128-bit value, so the masks, the result field,
the memory interface and every effect function widen with it. The two shapes
available are a separate `axis_exec_step128` tier mirroring the 32/64 split, or
making the wide tier's slot type a per-document choice — `axis_u128` when the
document needs more than 64 bits, `uint64_t` otherwise. The second matches how
the 128-bit semantics prelude already decides, and keeps every 64-bit document
byte-identical.

## 8b. "Narrow" is not the same as "the compact check has it"

This driver skipped every instruction whose widths are all ≤ 32, on the ground
that the compact check covers those. It covers the ones it can *run*, and it
cannot run one that touches architectural state — its ABI has no state
argument — nor, since A6, one that reads a register its operands do not name.
Those were skipped by both drivers, each in the belief the other had them: a
narrow state-touching instruction, which is RV32's `LR_W`/`SC_W` and their
ordering variants and most of Zicsr, was executed by no compiled executor at
all. Neither driver was lying about its counts. Nobody was measuring
reachability across the pair.

The skip now applies only where the compact check actually runs the
instruction. Twenty-eight more RV32 fixtures execute, and they found two
defects in the code under test:

* **A memory address did not wrap at its own width.** Every operator masks its
  result, so this could not show while every address was arithmetic. `lr.w rd,
  (rs1)` addresses with a bare operand, and a 32-bit machine's address held in
  a 64-bit slot reached memory with whatever the upper half contained. The
  golden model and the Python executor wrap it; the wide C and Rust emitters
  now mask an address to the width the description evaluates it at, which is
  the identity on a 64-bit machine.
* **A condition was not tested at its width.** The golden model masks the
  operands of every width-sensitive operator — `lshr` masks its value, the
  comparisons mask both sides — and did not mask a `select`'s condition. The
  congruent operators (`or`, `xor`, `add`) return their result unmasked, so an
  `or` whose low 32 bits are zero and whose upper half is not took the true
  branch in the model and the false one in C.

The second needed a third change to be reachable at all. A store-conditional's
reservation check is three comparisons or-ed together; random state satisfies
it with probability 2⁻⁴¹, so the store path of every `sc.w` in the corpus had
never been executed and never could have been. On one trial the driver now
seeds each state slot with a value the effects compare that slot *against*,
read off the expressions — nothing here knows what a reservation is, only that
a description comparing a slot with something has named the value that makes
the comparison hold. All four `sc.w` variants now store, which is also what
covers the address fix on the store side.

## 8d. The counter has a width, and three executors did not use it

This driver used to take the ISA word from a `word_bits` key the roundtrip
fixtures do not publish, so it defaulted to 64 for every corpus, and it drew a
program counter of 40 random bits whatever machine it was driving -- a value a
32-bit machine cannot hold. On the other side, none of the three executors
wrapped the counter at all: `pc + ILEN` was computed in the 64-bit slot it is
carried in, and a `setpc` was left to whatever width its own expression
happened to mask at.

The two errors hid each other. Every `setpc` in every corpus is arithmetic --
`(add pc imm)`, `(and (add rs1 imm) ~1)` -- and an operator masks its own
result, so a branch target was right by accident; and a counter never near the
top of its space never wraps, so the fall-through was right by never being
asked. Nothing was wrong until an address was one word from the end.

What closed it:

* The width comes from the lift entry's `state_width`, per instruction, which
  the JSON and Python lift tables have always published -- for the instructions
  that *named* an ISA. Twenty-one corpora do not name one, having only one to
  name, so the field was absent for all of them and so was the answer. One rule
  now decides which ISA an instruction belongs to (`ast::instruction_isa`): the
  one it names, or the only one the document declares.
* The C and Rust lift tables carry `state_width` too, which they did not; the
  four lift artifacts are one table again.
* All three executors wrap the counter at that width -- the fall-through and a
  `setpc` alike, masked where the counter is written rather than trusted to the
  target's own arithmetic.
* Every driver draws the counter from the machine's own space, and from the top
  of it on the trial where the fall-through happens. A guarded fixture spends
  trial 0 on the taken branch, so the wrap is trial 1's; an unguarded one has a
  single trial and takes the top.

`examples/effects_branch.axisl` gains the instruction that can tell the
difference: an indirect branch whose target is a bare register, so no operator
masks it. It also writes a branch-target state slot, which is what brings it
into this driver's reach -- a narrow instruction is left to the compact check
unless it touches state, and the compact ABI is 32 bits wide, where the wrap is
structural rather than decided.

Dropping either mask now fails a gate: the fall-through on RV32I, the target on
`effects_branch`.

## 8e. Two C paths, one language, and the seam between them

`exec_c_check` drives the compact 32-bit executor and this file drives the wide
one, and the split meant an instruction was checked by *whichever its width
selected* -- against the golden model, but never against the other backend. The
two are not one check run twice: they are independently generated C, one whose
arithmetic is `uint32_t` and one whose arithmetic is explicit masks over
`uint64_t`. A rule can be in one and not the other, and three were:

* **A signed guard, emitted as an unsigned comparison** in the compact path.
  `blt` and `bge` took the wrong edge whenever their operands differed in sign.
  The wide path had `axis_signed64`; the compact path had `<`.
* **An arithmetic shift of a narrow lane, left unsigned** in the wide path.
  `axis_ashr64` sign-extended through a cast that knows 32 and 64, and a value
  masked to 16 bits is never negative as an `int64_t` -- so every `sra` over a
  SIMD lane was a logical shift. `axis_sdiv64` had the same shape, and so did
  AArch64's register ASR. All three now read the sign at the width they are
  given, which the compact runtime's `axis_sem_signed` has always done.
* **Four operators the compact path had and the wide one did not**: `rol`,
  `ror`, `ctz`, `cpop`. The wide runtime had `clz` and stopped there, so Zbb's
  rotates and counts were declined by one executor and run by the other.

And one that is neither backend's vocabulary but the seam's: **a value is taken
at the width the instruction writes.** Every operator masks its own result, so
this shows only on an expression that applies none -- an identity, `(formal
rs1)` -- where a 32-bit machine returned all 64 bits of the slot its register is
carried in. `examples/policy_icount.axisl` is the corpus that has one.

So the skip is gone. This driver runs every instruction the ABI can hold, and
the corpora that found the three defects are gated on both drivers. One
exclusion remains and it is not a width: a scalable instruction belongs to
`scalable_exec_check.py`, which reads and writes element-sized views over the
limbs of a register whose size is `VL`, where this driver models a register as
a 64-bit slot. Every entry in a scalable corpus carries the origin it is a lane
of -- reductions included, which is why the flag and not the operand kind is
what this reads.

RV32I goes from 324 executed to 494, and every corpus in the repository now
runs through both C paths with nothing declined.

## 9. What this does not cover

* **Scalable corpora.** SVE and RVV report nothing to execute, and correctly:
  lane instantiation renames an operand to `zd__l0`, which matches no format
  field, so lane instructions are not encodable and produce no fixtures. They
  are checked by reading their emitted effects instead.
