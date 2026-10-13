# Lifting binary code to LLVM IR

## 1. What this is

`src/lifter.rs` takes bytes and produces an LLVM module: basic blocks of native
instructions, real `br` edges between them, and a landing pad for every way
control can leave. It is reached from the CLI as

```
axis lift-blocks <desc.axisl> --binary <file> --addr <hex> [--isa <name>]
axis lift-llvm   <desc.axisl> --binary <file> --addr <hex> [--isa <name>]
```

the first printing where the blocks are and the second the module.

The pieces already existed and did not meet. `emit-decode-abi-c` walks a stream
and says what each word is. `emit-llvm-ir` lowers one instruction's semantics to
native LLVM. `lift_block` in the generated Python lifter turns a straight-line
run of words into a dataflow graph -- and says outright that where blocks begin
and end is a fact about a *program*, not about a machine, so the caller supplies
it. Nothing was that caller. This is.

## 2. What it does not invent

Three things are deliberately borrowed rather than rewritten, because a second
implementation of any of them is a second place to be wrong:

* **The decode** is `layout_for`, the same function every emitter uses, so an
  instruction's mask, match, width and operand fields are what the description
  states. Checked against the proven decoder over a compiled object: 70 of 70
  instructions, no disagreements.
* **The semantics** are `emit::llvm`'s. `llvm_effect_expr` takes the symbols an
  expression may use and a map from each to the SSA value holding it; the lifter
  binds the operands and writes the results, and the arithmetic in between is
  the lowering that is already proven equal to the golden model. Two functions
  were factored out of `emit::llvm` for this rather than copied -- the load
  peeling (`llvm_effect_value`) and the module preamble -- and one predicate
  (`llvm_effect_refusal`) so that both agree about what LLVM cannot express.
* **The refusals** are the same set `emit-llvm-ir` withholds functions for. An
  instruction it declines is one a region declines, and the region stops there.

## 3. What it adds

What decode makes possible and a per-instruction handler cannot have:

* **The register index is a constant.** A handler takes the register number as
  an argument and computes where to look. Here `x5` is slot 5, folded before the
  optimizer runs.
* **The control flow is real.** A branch whose target is a closed function of
  the pc and the immediates becomes a `br` to another block. Everything else --
  a register-held target, an operator the folder does not know -- is *indirect*,
  which ends the block at an exit rather than drawing an edge that may not
  exist. Being wrong that way costs a block boundary; being wrong the other way
  invents control flow the program does not have.
* **An indirect target is still computed.** Not foldable is not unknowable: the
  jump goes through a register, so the address is computed at run time and
  reported in `%status[0]`. The caller learns where control went, not merely
  that it left.

Block recovery was checked against `llvm-objdump` over a compiled RISC-V object:
12 direct branch targets, all 12 agreeing, none missing and none invented.

## 4. The module

```llvm
define void @axis_region_<base>(iW* %regs, i8* %mem, iW* %status, iW* %state)
```

`%regs` is the flat register file the other backends use, `%mem` a byte buffer,
`%state` the architectural state in the lifter's published order, and
`%status[0]` receives the address control left for. The module carries its own
semantics helpers, so it is self-contained.

Optimized, a lifted loop becomes what the source was: `icmp slt` for a `blez`,
`shl` for the shift, a `phi` for the induction variable, and `readonly` /
`writeonly` inferred on the pointers.

## 5. What it declines, and why that is the point

A region containing an instruction LLVM IR cannot express is lifted up to that
instruction and leaves there, naming it. On RV64I that is 199 of 337 -- the
atomics, the barriers LLVM cannot order, and the dynamic-rounding floating-point
forms, which take their mode from `fcsr` and so need an environment emitted IR
cannot set. None of these are defects: the same instructions are withheld from
`axis_semantics.ll` for the same reasons, and a lifter that lowered them anyway
would not produce wrong IR, it would panic in `llvm_convert`.

Two more declines are the region's own:

* **An operand wider than the machine.** A block has one type. RV32 with the D
  extension is a 32-bit machine with 64-bit floating-point registers, and
  lowering its integer arithmetic at 64 bits emitted `zext i64 %t to i64`, which
  LLVM refuses to parse. The machine width is stated by the ISA, so it is read
  rather than inferred from the widest operand present.
* **A word no row matches**, which ends the walk.

## 5a. Reaching it from a compiled consumer

The lifter is Rust, but for a while the only door onto it was the `axis`
command -- so every consumer spawned a process, re-parsed the whole
description, and read the answer back as text. That is fine for a person at a
terminal and wrong for a program: the per-instruction sweep spent most of its
time parsing a nine-hundred-instruction description, once per instruction.

The crate now builds a `staticlib` and a `cdylib` alongside the `rlib`, and
`include/axis_lift.h` declares a C ABI over it:

```c
axis_lifter *axis_lift_open(const char *axisl_path);
intptr_t     axis_lift_blocks(const axis_lifter *, const unsigned char *bytes,
                              intptr_t count, uint64_t address, const char *isa,
                              char *out, intptr_t capacity);
intptr_t     axis_lift_llvm(...);           /* same shape */
intptr_t     axis_lift_support(const axis_lifter *, char *out, intptr_t cap);
void         axis_lift_close(axis_lifter *);
```

A description is parsed once into a handle; the handle answers. Every query
returns the number of bytes the answer needs, so a caller asks with no buffer,
allocates once, and asks again -- and the second call returning a different
length is itself an error, because a caller that trusts a returned length is
the one that overflows when it is wrong. Nothing allocates on the caller's
behalf and nothing but the handle outlives a call. The boundary catches panics,
since the lowering can still panic on a shape it has not met and a panic across
a C frame is undefined behaviour.

`lift_abi_check.py` compiles a C program against the library and requires the
same bytes to give byte-identical answers through the ABI and through the
command. Two doors onto one lifter is two things that can drift apart.

The module also splits where it repeats. `axis_lift_preamble` returns the part
that does not depend on the bytes -- the semantics helpers, thirty thousand
lines for AArch64 and identical for every region -- and `axis_lift_llvm_blocks`
returns a region's block functions without it. A consumer lifting a binary asks
for the preamble once and appends each region's blocks; `axis_lift_llvm` is the
two together, for a caller that wants one self-contained module and does not
care. The ABI gate requires the split to compose back byte-for-byte into the
whole, since two ways of building a module is two things that can drift apart.

Binding it from Python (`tools/axis_lift_ffi.py`) took the AArch64
per-instruction sweep from 1047 seconds to 119, with the same instructions
compared -- 744 of them at the time -- and the same zero disagreements: 1047 to 183 by not spawning a process
per instruction, and 183 to 119 by not re-emitting the preamble per region. The
sweep also stopped doing string surgery on the module to separate the two,
which is now an API.

## 5b. What the lifter is for

`docs/ise_mining_design.md` describes the first consumer: mining
instruction-set extensions out of compiled objects. It uses the block
discovery here, the lift table's semantics trees, and `emit-smt2` -- decode,
block, thread, compose, propose, prove -- and it is the reason block boundaries
have to be the lifter's rather than a guess. A run that crosses a branch is not
a block, and an extension mined across one would replace instructions that do
not always run.

## 6. The gate

`tools/lift_region_check.py` builds a region from real encodings, lifts it,
JITs it, and requires the register file, the memory, and the address it left
from to agree with the Python executor -- itself proven equal to the golden
model. It found three things the reading above did not:

* **`jalr` read its own link register.** The terminator's target was computed
  after the instruction's writes landed, so `jalr x31, x31, imm` jumped to the
  address it had just stored. Every read of an instruction now happens before
  every write of it.
* **An indirect jump reported the wrong address.** It stored the fall-through
  where it should have stored the computed target.
* **A conditional exit needs its guard**, and the guard needs the values the
  branch read rather than the ones the block ended with.

Three things in the harness itself, worth naming because each looked like the
lifter disagreeing with the executor:

* The lift table carries no instruction *width* -- that lives in the decode
  table -- so defaulting to four bytes laid every compressed instruction out in
  twice its space and everything after it moved.
* A generated 32-bit encoding whose low half matches a compressed instruction
  decodes as the compressed one, correctly, and then the layout is two bytes
  wide for a word that needs four. The decode has to agree with what was
  generated, not merely be liftable.
* The executor advances the pc by one fixed `ILEN`, because a word is what it is
  handed. A region is bytes. A compressed branch whose target happens to be
  `pc + ILEN` is genuinely indistinguishable from one not taken, so that case is
  declined rather than guessed.

## 7. AArch64: every instruction, but not yet every region

The class features the lowering was missing are implemented: a view with a
write policy (writing `w0` zeroes the upper half of `x0`), a class held as
several limbs, and an alias that sends an index to a name rather than to the
file. With them, **823 AArch64 instructions lift and run exactly as the
executor runs them** -- every one the lifter accepts, each in a region of its
own, checked by `lift each: A64`.

Eight more are 128 bits wide. A region has one type -- the machine's word --
so an operand wider than it was refused outright, and that refused the wrong
thing: a value wider than the machine cannot be *computed* in such a block, but
`ldr q0, [x1]` computes nothing. It is two loads eight bytes apart into the two
slots the register occupies in the file. `emit::llvm` had already drawn that
line for its effect functions, in `behavior_is_whole_limbs`, so the lifter asks
the same predicate rather than a new one, and refuses only what fails it: the
twelve vector-arithmetic instructions, which state no behavior at all because
128-bit arithmetic is what a region genuinely cannot do.

Getting that wrong once is worth recording, because the two numbers involved
look alike: how many machine words a value is, and how many slots its register
occupies in the file. On AArch64 they agree -- a 128-bit V register is two
64-bit slots, and 128/64 is also two -- so counting *words* got `ldr q0` right
by luck and every AArch64 gate stayed green. RISC-V's `rv_fpr` holds 64 bits in
one slot, so on RV32 a 64-bit `fld` is not two limbs of anything; it is a
single slot wider than the block's only type, which a region cannot hold.
Counting words split it across `f0` and `f1` while the executor kept one
64-bit value in `f0`, and `lift region: RV32I` said so. The rule asks the
register class now: a wide operand lifts only when its class holds it in
`limbs` slots of exactly one machine word each.

Three regions are planted rather than drawn to check it, because a draw of six
instructions out of seven hundred will not produce them: a wide value out of
memory and back, then the low limb of the register the wide load just wrote,
read through the 64-bit view of the same class; the pair forms, four limbs each
way; and a narrow write followed by a wide read, where writing `d1` zeroes the
rest of `v1` and the wide store has to see that zero. Each runs at an aligned
address and an unaligned one, since a plain load states `align 1`. Dropping
either limb of the store fails all six runs, and dropping a limb of the load
fails the four that contain one -- which is the gate having teeth in the place
it claims them.

What stays refused is the twelve vector-arithmetic instructions, and the
reason is worth stating precisely, because two different reasons look alike
here. They carry no `behavior` and no `formal` -- only prose saying "128 bits
wide, so no behavior is stated" -- so nothing has been withheld from the
lifter; there is nothing to withhold. Describing them is the work, and it
splits: `AND_V`, `ORR_V` and `BSL_V` are bitwise, so they *are* whole limbs and
would need only the predicate widened from "a plain load or a plain register
read" to "an operation independent across limbs". `ADD_V` and the compares take
a lane width from the `size` operand, and at `size = 0` a 128-bit add is
sixteen independent byte adds -- not two 64-bit ones, and not something a
region whose one type is the word can do without the masking the predicate
exists to rule out.

### A paired compare-and-swap is one `cmpxchg`, not four effects

`CASP` swaps two consecutive registers against two consecutive words as a
single transaction, and AXIS says so directly: four effects inside one
`atomic-group`, a load into each half and a store of each source guarded by
*both* halves having matched. The fusion took exactly two effects, so all
sixteen paired forms were refused with "the read-modify-write fusion does not
take it".

The lowering is one `cmpxchg` at twice the element width -- `i128` for the
64-bit pair, `i64` for the 32-bit one -- which is what the hardware does, since
`casp` operates on a register pair as one quantity. Lowering the four effects
separately would let one half succeed and the other fail, which the instruction
cannot do and a one-threaded gate cannot see; that is the same reason the
two-effect fusion exists, one word further along.

Three things had to move with it:

* **An `atomic-group` is a reason to fuse, not to refuse.** `llvm_effect_refusal`
  asked about the group *before* trying the fusion, where
  `emit_llvm_effect_function` had always asked after. Both ask after now.
* **A derived operand is not an absent one.** `CASP` names a pair with one
  field: `rs2` is `rs + 1`, and the word says so only by saying `rs`.
  `extract_operand` reads bindings, a derived operand has none, and it answered
  **0** -- a register, and a plausible one, so a paired swap would have written
  its high half into `x0` and looked almost right. These sixteen are the only
  instructions in the corpus with a derived operand, and the lifter refused all
  of them until now, so nothing had ever asked.
* **A paired atomic needs twice its element's alignment.** The harness aligned
  drawn addresses to the effect's width, 8 bytes, and arm64 wants 16 for a
  `casp`. The process died with SIGBUS, which says nothing about which
  instruction was wrong.

And the sweep could not have caught any of it, because it never ran these:
its entry filter required every non-immediate operand to have encoding fields,
which is exactly what a derived operand does not have. All sixteen were dropped
before `takes` was consulted, so they did not even appear in the refusal count.
They are compared now -- 788 instructions become 811 -- and swapping the two
halves of the fused result fails all eight `CASP` forms, which is the check
having teeth where the mistake would be invisible.

### What to do about the exclusive monitor depends on what the artifact is for

The load- and store-exclusive pairs were refused together, under one reason --
"the exclusive monitor is state LLVM has no counterpart for". That is too
absolute, and stating it that way hid that the two halves are not the same
question.

**A load-exclusive is exact, for every consumer.** `LDXP` is two atomic loads
and three writes to the monitor -- its address, its size, its valid bit -- and
the monitor is ordinary architectural state that this description already
declares and every executor already carries. There is nothing to approximate.
The pair is one transaction, so it lowers to one `load atomic` at twice the
element width, which LLVM selects `ldxp` for on AArch64: the instruction being
lifted. The eight forms lift and agree.

**A guarded store needs no block after all.** That was the reasoning for
sixteen refusals -- eight RISC-V `sc.w`/`sc.d` and eight AArch64 `stlxr` forms
-- and it rested on two options, both bad: branch, which needs a block a
one-entry, one-exit shape cannot hold, or read the old value and select, which
writes the same bytes back, and a store of the same bytes is still a store to
anything else watching.

There is a third. `llvm.masked.store` with a false mask performs **no store**.
Not a store of the old value -- no store. That is exactly what a guarded store
needs, it is one instruction, and it needs no block. All sixteen lift now: RV64I
goes from 135 refusals to 127 and AArch64 from 48 to 40.

Verifying them took planting, because the random sweep cannot. A `sc.w` whose
reservation does not hold is indistinguishable from an `sc.w` that was never
lowered, and a random `exclusive_address` never equals a random `rs1`, so the
sweep only ever exercised the branch that does nothing. Two planted regions fix
that: `lr.w` then `sc.w` at the same address, where the store must happen, and
the same pair at different addresses, where it must not. Forcing the mask true
passes the first and fails the second, which is the pair earning its place.

### The reservation records what it observed

A translator that maps `lr`/`sc` to a compare-and-swap needs the value the
reservation captured, and the monitor recorded only its address, size and valid
bit. `exclusive_value` is that value, written at all 20 reservation sites across
the three corpora that model a monitor.

The simulator never reads it -- it still models the monitor exactly, which is
the point of keeping the two answers apart -- so adding it changes no executor's
behaviour. It exists for the lifter.

**Adding it found the same bug in three emitters.** A state write's value may be
a LOAD, and `Loc::State` lowered its value as a pure-IR expression in LLVM, in
C, and in Rust -- and `load` is not an operator the pure IR has. All three had a
store arm that peels a load correctly, sitting immediately beside the state arm
that does not. The eight `LDXR` forms declined in LLVM and vanished from the C
executor; Rust was worse, emitting a function that silently recorded the wrong
value, which `A64 native wide exec` caught as `FAIL Rust LDXR W reservation`.

That is the third appearance of one gap. A store's value may be a load, a state
write's value may be a load, and the register-set arm has peeled one since the
beginning. Each was found by needing it rather than by looking, which is the
argument for the accounting gates: they make an emitter say what it cannot do,
so the next one of these is a refusal with a name rather than an absence.

**A store-exclusive is still a choice where the monitor is concerned.** `STXP` tests
the monitor, stores only if it held, and reports which. For a *simulator* the
right answer is to model it exactly, which AXIS already does -- the executors
run these, and the description states the guard in terms of the monitor state.
For a *translator* the usual answer is different: recognise the ll/sc idiom
over the loop it sits in and emit a native compare-and-swap, which is faster
and not the same thing, since a compare-and-swap succeeds where hardware would
spuriously fail. Neither is wrong; they answer different questions.

### The translator maps it, the simulator models it

Both answers now exist, and which one a consumer gets depends on which artifact
it asked for. The executors -- C, Rust, Python -- model the monitor exactly, as
they always have. The lifter emits a compare-and-swap against the value
`exclusive_value` captured:

```llvm
  %expected = select i1 %holds, i64 %captured, i64 %cannot_match
  %paired   = cmpxchg i32* %ptr, i32 %expected, i32 %desired acq_rel acquire
  %ok       = extractvalue { i32, i1 } %paired, 1
  %flag     = select i1 %ok, i64 0, i64 1
```

The `select` is what removes the branch. When the monitor does not hold, the
expected value is one memory cannot be holding -- the current word plus one --
so the swap fails without anything having to jump over it. The flag is zero on
success, which is what both `sc.w` and `stxr` report and what makes a retry
loop terminate.

The shape is matched in one place. `is_store_conditional` asks whether a
behaviour is a flag write, then a store guarded on `exclusive_address` and
`exclusive_valid`, and both `refusal` and the lowering ask it -- so the lifter
cannot turn an instruction away as an atomic the fusion declines and then also
lower it, or describe the shape twice and let the two descriptions drift. A
description opts in by publishing `exclusive_value`; without that slot there is
nothing to compare against and the masked store remains the answer.

**Where the two differ, on purpose.** A plain store to the reserved address
between the `lr` and the `sc` leaves the monitor valid, so the model stores and
the compare-and-swap, seeing changed memory, does not. Both readings are
allowed -- RISC-V permits an implementation to keep the reservation, and AArch64
is explicit that a store by the same PE may leave the monitor set -- and the
simulator takes the permissive one while the translator takes the one that is
safe against another hart.

That divergence is planted rather than hoped for, on both architectures, and it
is required: `PLANTED_DIVERGENT` names the slot that must differ, states that
memory must differ too, and **fails if they agree**. An exemption that stops
being needed is describing a divergence that no longer exists, which is a lie of
the same kind as an unexpected disagreement. The planted run prints the ones it
actually ran, so a RISC-V corpus does not report AArch64's exemption.

Everything else about the pair agrees exactly, which is the whole of what a
single-threaded differential sweep can establish.

**The alignment this needed was not in the description.** `sc.w`'s store is
written as an ordinary guarded store -- nothing in it says atomic -- but the
lifted form is a `cmpxchg` and inherits the hardware's alignment rule, and
RISC-V requires a reservation address to be naturally aligned in any case. The
sweep took the description at its word, handed the compare-and-swap a 1-aligned
address, and the process died with SIGBUS. `atomic_alignment` counts the
guarded reservation store at its own width now, and planted regions containing
an atomic are aligned even in their "unaligned" run -- that label is about limb
offsets, not about feeding an atomic an address the architecture forbids. It
had been passing on luck: Apple silicon has FEAT_LSE2 and tolerates an
unaligned atomic that stays inside a 16-byte granule, so the fault waited for
an address that happened to cross one.

### Saying it properly

That gap is closed. It needed the ordering to have somewhere to go, which took
three changes before a single description could be corrected.

**A lone atomic access is not a read-modify-write.** The lifter refused any
instruction with an atomic effect that the fusion did not take, on the reasoning
that lowering it separately would emit a load and a store where the machine
performs one transaction. True of a *pair*; false of one access. `load atomic`
and `store atomic` are single LLVM instructions that say exactly what the
machine does. The check counts atomic effects now rather than asking whether
there are any, and the whole load-reserved family stopped being refused the
moment it started admitting it was atomic.

**An atomic load was read plainly.** `llvm_effect_value` matched `atomic_load`
and then called the ordinary read, which states `align 1` and no ordering. It
was unreachable while every atomic shape was refused earlier, and reachable the
instant the refusal narrowed. It emits `load atomic ... align N` now -- the
alignment stated, because LLVM rejects `align 1` on an atomic and the hardware
rejects the address.

**A lifted fence emitted nothing.** The barrier arm dropped every barrier, on
the reasoning that the region does not reorder. The region does not; the machine
it is compiled for does, against threads the region knows nothing about. A
lifted `fence` that fences nothing is not a lifted `fence`. Barriers that order
memory emit `fence` now, and the ones that order the pipeline instead still emit
nothing, for the reason `fence_ordering` already gave.

**Then the descriptions.** All sixteen RISC-V forms and the eight AArch64
singles. `lr.w.aq` is an acquire load and `sc.w.rl` a release store, which is
what the codebase already says about atomics generally -- acquire is about the
read and release about the write. The four forms whose annotation the access
cannot carry -- `lr.rl`, `lr.aqrl`, `sc.aq`, `sc.aqrl`, the two of which RISC-V
itself advises against -- state the remaining half as a full fence, before the
load or after the store. That is **conservative**, stronger than the
architecture strictly requires, and it is labelled as such in each `semantics`
string rather than left to be discovered. An overstatement that says it is one
is not the same as the understatement that was there before, which said nothing
and was silent about it.

Eight instructions now lower eight different ways, where before they lowered
identically:

```
lr.w       load atomic i32 ... monotonic          sc.w       cmpxchg ... monotonic monotonic
lr.w.aq    load atomic i32 ... acquire            sc.w.aq    cmpxchg ... monotonic monotonic + fence
lr.w.rl    fence + load atomic ... monotonic      sc.w.rl    cmpxchg ... release monotonic
lr.w.aqrl  fence + load atomic ... acquire        sc.w.aqrl  cmpxchg ... release monotonic + fence
```

**The compare-and-swap was overstating too.** It emitted `acq_rel acquire` for
every store-conditional. Invisible while all four `sc.w` forms were described
identically; a claim the moment they were not. It takes the ordering from the
store now. The acquire half of an `lr`/`sc` pair belongs to the `lr`, which
lifts on its own and says so.

**And the asm was wrong.** All four `lr.w` forms printed `lr.w`, so the
disassembly threw away bits the encoding had recorded correctly -- `lr.w.aqrl`
was indistinguishable from `lr.w` in text. Twelve mnemonics print their suffix
now. AArch64 never had this, because it spells ordering in the mnemonic:
`ldxr` and `ldaxr` are different instructions, not one instruction with a bit.

**What the corpora caught.** Changing `LDAXR_W` and leaving `ACCEL_LDAXR32`
alone broke the lowering-equivalence proof, which is the pair refusing to be
half-updated. And marking the family atomic made `peel_load` stop recognising
it as a load at all, so the TableGen backend's named decline -- "no pattern,
because the load writes architectural state" -- vanished from the output
instead of changing. It is recognised and refused by name again, the same rule
`LDAR` was already there for. A decline is only useful if it names the cause.

**One hole this opened, closed.** `llvm.masked.store` is not atomic. A guarded
atomic store that is not a store-conditional would have lowered through it and
lost the atomicity silently, so it is refused with that as the reason. No
corpus has one; the refusal is there because the shape is now describable.

Narrowing that rule reached RISC-V too, and by more than AArch64. Its atomics
are written inside an explicit `atomic-group` -- the same thing AArch64 spells
as two effects marked atomic -- and the lifter's copy of the group check
refused all of them for the spelling. RV64I goes from 122 instructions compared
to 195, and from 208 refusals to 136.

### A fusion may consume a prefix

`AtomicPair` has carried a `consumed` count since it was introduced and nothing
read it. `CASP` is the whole instruction, so it never mattered; `LDXP` is its
two loads with the monitor after them, and a fusion that could not say "these
two, and you do the rest" had no way to be expressed. Both the effect emitter
and the lifter honour it now, and each keeps writing architectural state after
the fused part.

Emitting the loads and dropping the monitor is a lifted `ldxp` that leaves no
trace for a `stxp` to test -- and the sweep could not see it, because it
compared registers, memory and the pc and **not** architectural state. Any
instruction whose only effect beyond its registers was a state write was
unverified there. It compares state now, and dropping the monitor fails all six
runnable load-exclusive forms by name.

### A wide value is computed at its own width, and packed only at the file

The twelve vector-arithmetic instructions were refused for being 128 bits wide,
and the refusal was right about the obstacle and wrong about the remedy. A
region's own type is the machine word -- its register file, memory pointer and
status are all that wide -- but the *value* it computes need not be. LLVM has
`i128`, the lifted preamble already carries the `axis_sem128_*` helpers, and
the register file holds such a value in whole machine-word limbs. So the block
computes at the value's width and packs at the boundary, which is what every
value backend here already does.

That is not the same as carrying the value *as* limbs through the arithmetic.
Limbs are a storage layout, and the whole-limb path above exists only because
*moving* a wide value needs no arithmetic at all; asking them to add would be a
second representation of a wide number for every backend to agree on. Joining
at the read and splitting at the write costs four instructions and keeps one.

Computed wide does not mean written wide, which `ADDP_D` established by
failing: it reads a 128-bit register and writes a 64-bit one -- a view of the
same class, whose policy zeroes the rest. Splitting that answer into limbs put
the bits above the value into the register's high slot where the executor had
put the zero the policy demands. A destination the machine word can hold goes
through the ordinary write, which knows about views and policies; only a wider
one is written as limbs.

All twelve lift and agree, and joining the limbs high-half-first fails six of
them by name.

### The sweep counted what it reached, not what it set out to

Adding those eight exposed a hole in the gate that measured them. The
per-instruction sweep drew *one* random encoding per instruction, and a random
immediate can turn one encoding into another instruction -- `STR_Q_REG` decodes
back to itself about half the time. A draw that missed was dropped in silence,
so the sweep's "769 instructions compared" was a count of what it happened to
reach. One seed checked `STR_Q_REG` and the next did not, with nothing in the
output saying which. It redraws now, up to forty times, and names anything it
still cannot draw.

The same silence hid something worse. `refusal` documents itself as *the single
place that decides*, and twice it was not:

* **A guarded store.** A store-conditional writes only if the monitor holds.
  Elsewhere a guarded write is a `select` between the new value and the old,
  but for memory that is a store where the machine performs none -- and a store
  of the same bytes is still a store to anything else watching. It needs a
  branch, and a block with one entry and one exit has nowhere to put one. Eight
  store-exclusives were called `ok` and then failed at lowering. The refusal
  applies only when the atomic fusion does *not* take the instruction: a
  `cmpxchg` **is** a guarded store, and refusing every one of them refused 32
  compare-and-swaps that lower correctly as one LLVM instruction.

* **The long tail.** Below the named shapes sits everything `llvm_effect_body`
  only discovers when it tries -- an operator with no LLVM form, a value
  reading state the instruction has no parameter for. RISC-V's `FLS` is one.
  Predicting that tail with a second predicate is exactly how the two drifted,
  so the refusal now asks by *doing it*: it runs the real lowering and throws
  the text away. A probe that runs the same code cannot disagree with it.

An instruction the lifter accepts and then cannot lift now fails the sweep
rather than printing a note. Removing either fix turns the gate red, which is
the point of writing it down here.

Eighteen others arrived by asking a better question. The lifter chose its
path on `behavior.is_some()`, but a behavior that is one pure write to the
output operand is *promoted* by the parser into `formal_semantics` and left in
place, so such an instruction carries both and the formal is the authority.
`MADD_X`, `FABS_D`, and the `FCVTZS` and `SCVTF` families went down the effect
path, whose first question is which of the two is authoritative -- and were
refused with "no authoritative behavior" for having a formal. The question the
lifter should have asked, and now asks, is `behavior_is_authoritative`.

Finding that took abandoning hypotheses for a method. Three guesses about which
*shape* was at fault had already been wrong; what worked was lifting each
instruction alone, which turns "a region disagrees" into "this instruction
disagrees". Two real bugs came out of it, and both were in the region lowering:

* **A pre-indexed store addressed the wrong base.** `stp x1, x2, [x3, #imm]!`
  writes x3 and then stores at the *updated* x3. The effect-function path
  rebinds an operand after writing it -- "later effects read the value this one
  wrote" -- and the region had dropped that, so it stored at the old address.
  Rebinding by operand *name* is what makes both cases right at once: a
  pre-indexed store reads `rn` after writing `rn`, while `jalr rd, rs1` jumps
  through `rs1`, which nothing rebinds even when `rd` names the same register.
* **`sp` had two homes.** The executor keeps AArch64's stack pointer under a
  name in its register map, because encoding 31 means `sp` for some classes and
  the zero register for others. The region put it in `%state`. A store through
  `sp` then addressed whatever the other side had left at slot 31 -- four
  billion bytes out, which took the process down. It now goes one slot past the
  register file, which is where `jit_llvm.py` settled for the same collision.

Two more were in the harness, and both looked like the lifter being wrong: the
alias slot was never seeded on the reference side, so every register file
differed at exactly one slot; and an atomic address was not aligned, which on
arm64 does not fault -- it **spins**, and a hung sweep looks like a slow one.

### 7a. Lifting by block

The region is no longer one function with `br` edges between its blocks. Each
basic block is its own function:

```text
define void @axis_block_<addr>(iW* %regs, i8* %mem, iW* %status, iW* %state)
```

It runs the block and stores in `%status[0]` the address control goes to next --
a folded branch target, a computed indirect one, or the address after the block.
Composing them is the caller's, which is what `lift_block` said from the start:
where blocks begin and end, and which branch is taken, are facts about a
program. It is also the shape a translator wants, and it removes a whole class
of error by construction: an edge the lifter guessed cannot be wrong if the
lifter does not draw one. A conditional exit is a `select` between two
addresses rather than a branch, so a block has one entry and one exit and needs
no control flow of its own.

With that, **AArch64 regions agree with the executor** -- 26 regions at the
default seed, and every seed from 1 to 5 -- as do RV64I, RV32I and the two
effect corpora. `lift region: A64` is in the ladder.

Two things had to be fixed in the harness first, and neither was in the lifter:

* **A region drawn from two instruction sets is not a region.** This corpus
  describes a source encoding space and a target one, and the same word decodes
  to a different instruction in each. The generator mixed them, so the lifter
  read the bytes under one ISA and found instructions nobody had generated.
* **Every region lifted at address 0 defines `axis_block_0`.** A JIT holding
  several engines resolves that name to whichever registered it first, so a
  later region ran an earlier one's code. Each region now has an address range
  of its own. The tell was that shrinking the region could not reproduce the
  failure -- when a smaller case passes and the larger one fails on the *same*
  inputs, the failure is not in the program.

### 7b. The reference was fine; the harness called it two ways

For a while this section recorded an open finding: the Python executor
apparently did not give the same answer twice for the same region. It gave the
same answer every time. The driver was calling it with two different argument
lists.

`python_region` takes the aliased register's slot and name as its last two
parameters, defaulted so that a corpus without an aliasing class need not pass
them. The region comparison passed nine positional arguments and stopped, so
those two defaulted to `None`; the stability check beside it passed all eleven.
One call therefore treated AArch64's `sp` as an ordinary slot of the register
file and the other treated it as a name -- and the two disagreed exactly when a
region touched `sp`, which is why it looked rare and looked like atomics.

Worth writing down, because the wrong conclusion was reached honestly and held
for a while. Five candidates had been eliminated by test -- the JIT, module
state, the lift table, a clean-process replay, and the inputs -- and the last
one was wrong: a fingerprint was taken over the *variables in scope* rather
than over the arguments the call actually received. The variables were
identical. The calls were not. A test of the inputs has to be a test of the
call.

What found it was tracing both runs and diffing them step by step. The traces
parted at the first step, before any instruction had run, with the register
maps differing in every entry -- which is not what a wrong instruction looks
like. One map held ninety-seven integer keys and the other ninety-six plus
`'sp'`.

The stability check stays, and now guards something real: it is what turned a
silent disagreement between two callers into a visible count.

### 7c. What is still missing

The reference's non-determinism above, which is the one open item.

`lift region: *` now gates RV64I, RV32I, AArch64 and the two effect corpora,
and `lift each: *` gates every instruction of RV64I and AArch64 individually.

Both mutations tried -- dropping a class's `index_offset` from the slot
computation, and swapping the arms of a conditional branch -- were caught.
