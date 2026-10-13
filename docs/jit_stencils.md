# A stencil JIT: compile ahead, patch at translation time

Status: **built** (J1–J6).

## 1. Why, given there is already an LLVM JIT

`tools/jit_llvm.py` builds LLVM IR for a *block* and compiles it with MCJIT at
run time. The generated code is good; the compile is the cost, and it is paid
per distinct block. A simulator that translates a program once and runs it a
billion times does not care. One that meets new code constantly — the usual
case — spends its life in LLVM.

The technique the day job used, and the one to build here, moves the compile
before run time: emit one **stencil** per instruction with its operands left as
holes, compile all of them once, and at translation time *copy the bytes and
patch the holes*. Translation becomes `memcpy` plus a handful of stores. This is
copy-and-patch; CPython 3.13's JIT is built the same way.

It fits AXIS unusually well because the hard part is already done and proven:
each instruction has an `axis_eval_*` or `axis_eff_*` handler that five backends
agree on. A stencil is that handler with the operand *indices* left blank.

## 1a. The sixth pack library

There was no stencil library for a reason worth keeping written down, because it
is not the one it looks like.

It is **not** that stencils are host-specific. Every other pack library is too:
a `.a` is host machine code, and `build_pack.py` already runs the host's `cc`.
Nor is object parsing the problem -- that happens at build time and yields plain
data -- and the patcher is `#if defined(__aarch64__)` C like any JIT's inner
loop.

⚠️ The reason was that **the stencil module was assembled inside this gate**.
`stencil_ir()` took the output of `emit-llvm-ir` and regex-rewrote it: handlers
made `internal alwaysinline`, then each wrapped in a function whose operands
come from hole symbols. That is AXIS's job done in a test, so there was no
artifact for a library to be built from.

`emit-stencil-ll` emits it now, and `libaxis_jit_<name>` is built from it. The
split is the point:

| half | who | why |
|---|---|---|
| the patcher, the vtable, the table's *shape* | `emit-pack-jit-c` | derived from the description, like every other library |
| each stencil's bytes, its relocation sites, its holes | `tools/jit_table.py` | what a *compiler* made of the description, on one host |

Nothing else in a pack has that second half. AXIS cannot emit machine code it
did not compile, and the build cannot invent a contract, so neither side
describes the other: `emit-pack-jit-c` declares `axis_jit_stencil` and the build
fills an array of them. If the two drift the library does not compile.

A pack built where those bytes do not run says so by name -- `pack.json` carries
`declined.jit` with the host that was refused -- rather than by the library
quietly being absent.

### What the table says it patches

`tools/jit_table.py` reports which machine part each stencil actually binds,
counted from the relocations that survived compilation:

```
157 stencils, 22272 bytes of code, 1780 relocations, 0 declined
  patched by part: regs 157, mem 90, out 91, pc 91, value 157
```

⚠️ `state 0`, and it is not a rounding error: not one stencil in these corpora
reads architectural state, so every `state` hole is optimised away. Pointing
`machine.state` at the wrong buffer changes no answer here, which a mutation
confirmed -- so the count is printed rather than assumed, and a description
whose handlers do read state will show a number there.

### What the stencils had to learn to be shippable

Running a translated block against the *executor beside it* (`jit_pack_check.py`)
immediately said the stencils were wrong in a way five years of the earlier gate
could not see: they indexed the register file with the raw field.

* `c.sub` names `x8`-`x15` with three bits (`rv_gpr_c`, `index_offset: 8`). The
  stencil wrote `x1`.
* RISC-V's `x0` reads as zero and discards writes. The stencil wrote it.

The old gate indexed the file raw **on both sides**, so both were wrong together
and agreed -- the exact failure this ladder exists to catch. `emit-stencil-ll`
now does the lifter's own arithmetic, `offset + index_offset + index`, and
handles a hardwired zero branchlessly (a `select`, because a branch inside a
stencil is a relocation the patcher would have to understand). A class that
needs more than that -- an alias to a state slot, a preserved view, more than
one slot per register -- gets **no stencil at all**, named in the table's
declines.

## 2. What a hole is

A hole is a symbol the stencil references. The compiler, not knowing its
address, emits a relocation; the object file's relocation table then tells us
**where in the emitted bytes that value is referenced and how it is encoded**.
At translation time we write the real value there.

That is the whole trick, and its one assumption is that the value can be encoded
where the relocation points. Which is a property of the target, so it was
measured rather than assumed.

## 3. What this host actually emits

`arm64-apple-darwin`, the host these gates run on. A hole used as an integer:

| declaration | code model | emitted |
|---|---|---|
| `external global` | any | `adrp x8, sym@GOTPAGE` + `ldr x8, [x8, sym@GOTPAGEOFF]` |
| `external dso_local` | small | `adrp x8, sym@PAGE` + `add x8, x8, sym@PAGEOFF` |
| `external dso_local` | large | back to the GOT |

**There is no arbitrary immediate to patch.** The best case is `adrp`+`add`,
which materialises a *page-relative address*: `(PC & ~0xFFF) + (imm21 << 12) +
imm12`. To make that equal a register index of, say, 5, the patcher would need
`5 - (PC & ~0xFFF)` to fit a signed 21-bit page offset — ±4 GB. It does not; the
code buffer sits tens of terabits away from address 5.

Mach-O arm64 has no `MOVW_UABS` relocation kind either — ELF/aarch64 does
(`R_AARCH64_MOVW_UABS_G0..G3`), and x86-64 has `movabs` with a full 64-bit
immediate. So **immediate patching is available on x86-64 and on ELF aarch64,
and not on Mach-O arm64.** The day job was almost certainly x86-64.

## 4. The mechanism that works everywhere, and where it differs

Split holes by what the value *is*:

* **Address holes** — the next stencil to run, a handler to call, the operand
  block. These are addresses, so every target can patch them: `BRANCH26` for a
  call, `PAGE21`/`PAGEOFF12` for a pointer on arm64, RIP-relative or `movabs` on
  x86-64. True code patching, portable.
* **Value holes** — register indices, immediates, widths. These are *not*
  addresses. Where the target can encode an arbitrary immediate we patch the
  code; where it cannot, the stencil reads them from an **operand block** placed
  next to the code, and we patch the block. One load per operand.

So the portable core is: patch addresses in code, patch values in a data block,
and let a target that can do better do better. The arm64 build uses the operand
block; an x86-64 build can patch `movabs` immediates directly, and the *only*
part that differs is the patcher.

That is a weaker claim than "patch the code", and it is the true one on this
host. Stating it the other way and discovering it during the build would have
been worse.

## 5. Shape

Ahead of time, once per document:

    for each instruction entry:
        emit an LLVM function: load operands (indices from the operand block),
        call the proven handler, store the destination
    compile all of them to one object file
    read the relocation table -> per stencil: code bytes, hole sites

At translation time, per block:

    buffer = concat(stencil bytes for each word)
    operands = the decoded values, laid out per stencil
    patch each hole site to point at its slot in `operands`
    make the buffer executable, jump in

## 6. Stages, each ending at a gate

| Stage | Delivers | Gate |
|---|---|---|
| J1 | Stencils emitted and compiled; relocations extracted | every stencil has exactly the holes its operands imply |
| J2 | One instruction patched and run | the patched stencil's register delta == the executor's |
| J3 | Blocks: stencils chained, pc followed | a program's architectural delta == the simulator's |
| J4 | The reason for all of it | translation cost vs the MCJIT path, measured |

J4 is not a nicety. The entire argument for stencils over the existing JIT is
translation *speed*; if it is not faster to translate, the extra machinery has
bought nothing and the honest thing is to say so.

## 7. What this does not attempt

* **Register allocation across instructions.** Each stencil loads what it needs
  from the register file and stores back. That is what makes stencils
  composable, and it is also why the generated code is worse than the MCJIT
  path's. Stencils trade code quality for translation speed; a design that
  claimed both would be describing something else.
* **Control flow inside a block.** A branch ends the block and returns to the
  loop, as it does in the existing JIT.
* **Deoptimisation, inline caches, profile feedback.** Not needed to answer the
  question this is asked to answer.

## 8. Built

`tools/jit_stencil.py` emits one stencil per instruction, compiles them all
once, reads the relocation table back, and translates blocks by copying bytes
and filling holes.

| stage | result |
|---|---|
| J1 | every stencil carries exactly the holes its operands imply; all relocations are `PAGE21`+`PAGEOFF12` pairs |
| J2 | patched stencils agree with the golden model — 44 on zbb, 240 on RV32I, 296 on RV64I |
| J3 | blocks of 8 compose and agree; stencils fall through into each other |
| J4 | translation vs compiling the same block: **148x** (zbb), **395x** (RV64I) |

### What the ratio does and does not say

Translation is ~50–85 µs for an eight-instruction block; compiling the same
block through the path `jit_llvm.py` uses is 7 ms (zbb) to 757 ms (RV64I, whose
semantics module is far larger). The comparison is like-for-like in *structure* —
the existing JIT parses the semantics module per block too, because each block's
module redefines the handlers — and unfair in the stencil path's disfavour: the
patching loop is Python, while LLVM is C++. A C implementation of the same
patching would be far below a microsecond.

What it does not say is anything about the *quality* of the generated code.
Every stencil loads its operands from the register file and stores its result
back, because that is what makes them composable. The MCJIT path keeps values in
registers across an entire block. Stencils buy translation speed and pay for it
in execution speed; a design claiming both would be describing something else.

### Two findings, neither in the stencils

* **`inout` destinations were never written by the JIT *or* its reference.**
  Fixing the block lowering to write them (needed for SVE's predicated forms)
  made the A64 JIT gate fail — because the reference still took only `role ==
  "out"`. Before that, both sides skipped `MOVK`'s destination and the gate
  agreed about doing nothing. Now both write it.
* **The `c-sim` fuzz backend used the block API the machine replaced.** Ported
  to the machine, with a fetch hook that hands words in sequence: which words
  the machine sees is the host's policy, and that fuzz's policy is a
  straight-line block. All four backends agree again.

### Where the mechanism is host-specific

The hole sites and the patcher are. `MachO` reads this host's object format;
`patch_page21`/`patch_pageoff12` encode this host's address materialisation. A
different host needs both replaced and nothing else — the stencil IR, the hole
convention, and the block layout are unchanged. That boundary is where a port
starts, and it is small on purpose.

## 9. J5: mixed mode, which is what a JIT actually runs in

Stencils that only cover pure arithmetic are a demonstration. A JIT meets real
programs, and real programs are mostly memory and branches. So the executor runs
mixed: a run of stencilable words becomes one patched block, the first word that
is not ends it and is stepped by the proven executor, and translation resumes
after it.

Falling out of translated code costs nothing to arrange, and that is a
consequence of the shape rather than a trick. Every stencil loads its operands
from the register file and stores its result back, so the block and the
interpreter are looking at the same slots — the handoff is a pointer, not a
transfer.

    RV32I   88 instructions translated, 104 stepped, 0 disagreements
    RV64I   74 instructions translated, 118 stepped, 0 disagreements

Roughly 40% of these corpora is stencilable today; the rest is effectful, whose
handlers take the memory hooks and an effect scratch array — more holes than J1
built, and the next thing to build.

**Both halves have to happen.** A run that translated everything proves nothing
about coming back to the interpreter; one that stepped everything proves nothing
at all. The gate fails on either, which is why `zbb_like` is not a mixed-mode
gate: it is pure arithmetic end to end, and reports `192 translated, 0 stepped`.

Three injected handoff bugs — not writing the register file back after a stepped
instruction, not reading it in before one, and not running the translated block
— each caught.

### Two operand-order bugs, both in the driver

* A register hole's slot holds a *slot*, not an index. A class carries an offset
  into the flat file, so RISC-V's `f5` is slot 37, and a stencil that indexes
  the file directly needs the patcher to write where the register is.
* The holes are declared inputs-first-then-destination; operands are declared
  destination-first. Feeding them in declaration order put `rd` where `rs1`
  belonged, which showed up as diverging *memory* — a store to an address
  computed from the wrong register.

Both are driver bugs that look exactly like patcher bugs, which is the recurring
hazard of a differential gate whose two sides are written by the same hand.

## 10. J6: memory stencils, emitted and run

An effect stencil wraps `axis_eff_*` the way a pure one wraps `axis_eval_*`: the
machine pointers -- register file, memory, the effect scratch array, state, pc
-- arrive as holes, the handler does its own accesses, and the stencil commits
the register write the handler reports, guarded by the `wrote` slot because a
guarded `set` decides that at run time.

87 emit for RV64I, and they run. Mixed mode now translates loads, stores and
atomics as well as arithmetic:

    RV32I   205 instructions translated, 179 stepped, 0 disagreements
    RV64I   184 instructions translated, 200 stepped, 0 disagreements

What is still stepped is branches and traps, which end a block in any JIT.

A hole the stencil has no use for is optimised away, relocation and all -- an
instruction whose handler never touches architectural state has no `state` load
left to name -- so the check asks for the holes a stencil cannot do without: its
operands, its destination, and the register file they index.

### The fault that was not what it looked like

Running them faulted, and every reading of the evidence said "wild address": the
process died with no output, only on longer runs, and only with memory in the
mix. Three guards were built on that reading -- filter fixtures whose immediate
sign-extends negative, refuse a memory op whose address registers were written
earlier in the block, require those registers to still hold seeded values. Each
removed the failures at one program count and left them at a higher one, which
should have been the clue: a guard that keeps *narrowing* a fault is usually
guarding the wrong thing.

What it actually was: `AMOSWAP_D_RL` with its base register holding **35354** --
comfortably inside a one-megabyte buffer, and not 8-byte aligned. **arm64
atomics fault on unaligned addresses.** RISC-V requires natural alignment of its
AMOs too, so this is the guest's rule as much as the host's; the interpreter
never noticed because it reads bytes, and `jit_llvm.py` already had a comment
saying exactly this about its own generated programs.

The diagnosis took four measurements, and the useful ones were the ones that
*failed to reproduce*: every effect stencil run alone passed, the failing
sequence run in isolation passed, and one-instruction-per-block still faulted --
which ruled out composition and pointed back at the values. Naming the
instruction was what ended it.

The driver now seeds registers eight-byte aligned, as `jit_llvm.py` does, and
refuses to translate an atomic whose base is not naturally aligned. Three
injected effect-stencil bugs -- not committing the register write, ignoring the
`wrote` guard, reading the wrong scratch slot -- each caught.

### On the way

Two more width bugs, the same shape as the one RV64I found in the evaluators:
effect handlers are width-parameterised too (`i32` for RV32I, `i64` for RV64I),
and both the call and the scratch array follow. And the register file arrives
through a hole now rather than in `x0` -- the concatenated block had been
assuming the argument register survived every stencil, which the compiler never
promised and which happened to hold.

## The stack pointer is a register, and it was three fifths of AArch64

A stencil indexes a flat array of 64-bit slots. The class table knows about more
than that, and each thing it knows that a stencil could not say was a stencil
not emitted. One of those rules cost more than all the others together:

```
  436  `a64_gpr64sp` aliases a state slot
   79  it writes the state slot `nzcv`
   59  it writes 2 registers, and a stencil carries one
   25  it writes the pc
   42  a vector class takes 2 slots per register
    8  `a64_gpr32sp` aliases a state slot
```

⚠️ **444 of 734 declines were the alias rule.** AArch64 spells the stack
pointer as index 31 of a register class that names the `sp` state slot, so every
stack-relative add, load, store and compare -- three fifths of the architecture
-- was refused for a rule that costs a compare and a `select`. Reading it is
selecting between the register file and a state slot; writing it is selecting
the **address** and storing once, which keeps the stencil branchless, because a
branch in a stencil is a relocation the patcher would have to understand.

AArch64 went from **183 stencils to 627**, and the gate from 985 translations
compared against the executor to 3539, all agreeing.

### What it had been hiding

Two bugs, both invisible while these instructions had no stencils:

- **The view was never applied on a read.** `a64_gpr32` is the W half of an X,
  and the stencil handed the whole X to a handler expecting thirty-two bits. It
  looked right for as long as every operand of a stencilled instruction shared
  one width; `add x0, sp, w8, sxtx` is the shape that does not.
- **The gate's own state was unbounded.** It seeds registers inside its memory
  buffer precisely so a translated load cannot walk off, and `sp` is not in the
  register file -- so the first stencilled `swp x0, x1, [sp]` took the process
  with it. The harness is the host, and the host answers for every address.

### Declines say why now

`emit-stencil-ll` refused silently, so the only way to learn why two thirds of
an architecture had no stencil was to guess from class names -- and the first
guess blamed `rv_fpr` for 137 instructions that are really refused for writing a
state slot. The module now ends with one `; declined <name>: <reason>` line per
instruction, and `jit_pack_check.py` names the last instruction it was running
when translated code takes the harness down, instead of reporting a bare signal.

### What a translated block does with state now

`state_words` was passed to every translation and never filled: no stencil read
it, so pointing it anywhere changed no answer. Now that stencils reach `sp`
through it, the simulator copies the machine's named entries into the flat array
before a block and reads them back after, masking each to its declared width --
a stencil writes a whole word, and a four-bit flag slot keeps four.

⚠️ **One retreat stands.** A stencil that touches memory *and* reads state can
compute an address from state, and a host bounds its registers but not its state
slots. The simulator interprets those rather than translate them, which is
slower and always safe. That is a placeholder for a memory manager, not an
answer: the general fix is for translated code to have a window it cannot leave.

## A window translated code cannot leave

`memory_base` in the JIT contract was a **promise, not a bound**. Translated
code computes an address and uses it — there is no call in the emitted bytes to
put a check in — so a host that named a buffer was answering for every address
the program could reach. It could not, twice in one day: a stencilled
`swp x0, x1, [sp]` took one harness down and a translated store took another.

Every interpreter here already masks. The executors reach memory through a host
hook, and every host in this repository writes `buffer[(addr + i) & MASK]`.
Translated code did not, and that is the whole of the difference — so now it
does:

```llvm
%mask = load i64, i64* @AXIS_HOLE_memory_mask
%inside = and i64 %addr, %mask
%p = getelementptr i8, i8* %mem, i64 %inside
```

`axis_jit_machine` carries `memory_mask`; a window of `n` bytes is `n - 1` with
`n` a power of two. An address outside it **wraps to inside it**, which is what
the interpreter does — so the two engines agree about a program that runs off
the end, instead of one of them dying. A window that is not a power of two is
declined by name: that is not a thing a single `and` can express, and rounding
it up would mean writing outside the buffer the host named.

⚠️ **Zero means one byte, not "unbounded".** A host that wants the old behaviour
asks for it: all ones.

### How it arrives, and what that cost

One module-level global, `internal` and all-ones in `emit-llvm-ir` — masking by
all-ones is the identity and the optimiser deletes it, so every consumer of that
module is unchanged — rewritten to an external declaration in
`emit-stencil-ll`, which is what turns it into a relocation. A relocation named
`AXIS_HOLE_..._mask` is a hole the table already knows how to fill, by the same
naming rule every other machine part uses. No signature changed.

Three things had to learn something, and each had been quietly wrong before:

- **The hole collector read only the stencil's body.** An effect stencil *calls*
  `axis_eff_<ident>`, which is `alwaysinline`, so the handler's references are
  relocations inside the stencil's bytes but are nowhere in the stencil's IR.
  Every load and store in the table was declined for referring to its own
  machine until both collectors — the emitter's and the Python twin's — looked
  at the handler too.

- ⚠️ **The patcher assumed PAGEOFF12 always lands on an `add`.** `ADD
  (immediate)` takes the low twelve bits as bytes; `LDR`/`STR` with an unsigned
  offset take them **scaled** by the access size. The compiler picks the load
  form whenever a stencil reads a *value* out of a hole rather than an
  *address*, which no stencil had done before — and the unscaled patch produced
  a slot eight times too far away, which is plausible enough to run and wrong
  every time. Both patchers now read the instruction and refuse a form they do
  not know, rather than writing bytes that look fine.

- **The slot array was only 4-aligned.** A slot read by `ldr x` needs its offset
  to be a multiple of eight, and the code before it is a whole number of
  instructions — so half the blocks could not be translated at all until the
  slots were aligned to the slot size.

### What it bought

The simulator's retreat is gone. A stencil that touched memory *and* read state
used to be refused, because it can compute an address from state and a host
bounds its registers but not its state slots — which on AArch64 meant every
stack-relative load and store, since `sp` **is** a state slot. Addresses are
bounded now, so there is nothing left to be unable to answer for.

## Every register an instruction writes

A stencil committed write 0 and refused anything with more — "one register
write; more is more holes". The handler had never been the limit: the scratch
`EFFECT_OUT_SLOTS` describes carries **four** writes, the handler fills them,
and the lift table publishes each one with the operand it lands in. Only the
stencil's commit was single.

It commits all of them now, each with its own `dest` hole and its own pair of
scratch slots, each with its own class rules — a hardwired zero discards, an
aliased index goes to the state slot, a guard decides at run time. That was 68
of AArch64's declines: every load pair, store pair and writeback form it has.

⚠️ The order is the **effect list's**, not the operand list's. An instruction's
output operands in declaration order are usually the same sequence and are not
the same fact: the handler fills slot `k` from the `k`-th register-writing
effect. The table reads that from the lift table rather than inferring it, which
is what `EFFECT_OUT_SLOTS`'s note about mapping writes to registers "without
guessing" is for.

### AArch64 stencil coverage, by what was fixed

| | stencils |
|---|---|
| before | 183 |
| aliased registers (`sp`) | 627 |
| state writes (`nzcv`, `fpsr`) | 727 |
| every register written | **800** |

What is left: 48 vector-class instructions whose registers take two slots, 25
that write the pc — a block ends there by construction — and 19 with no lowered
effect handler.

⚠️ One decline was **lying**. "It writes the state slot `fpsr`" kept being
reported after state writes started working, because the reason function still
had an arm for it: ten instructions named a cause that had stopped being true,
which is worse than naming none, since a reader acts on it. The reason a decline
gives has to be rechecked whenever the rule it describes is relaxed.

### An atomic is aligned or it faults

`CASP_X` gets a stencil now — it writes two registers — and it took the JIT gate
down. AArch64's 128-bit compare-and-swap **requires** a 16-byte-aligned address;
the interpreter never notices, because it reaches memory through a host hook
that takes any address, and the description models the access without an
alignment rule the hardware has.

So the harness seeds 16-aligned addresses, and its buffers say `_Alignas(16)`.
A program that misaligns `casp` is not a hard case worth covering: it is one
neither machine would run, and comparing two engines on it says nothing.

## A register that takes two slots

`stencil_class_objection` refused any class with more than one slot per
register, which on AArch64 was every vector instruction — 48 of them. The
refusal stood in for two different facts, and separating them was most of the
fix.

**How many slots a register takes** is arithmetic the stencils simply did not
do. They spelled `base + index`, which is the scalar case; the general one is
`offset + (index_offset + index) * limbs`, the same thing the lifter does and
the register layout publishes. Striding by the class's limb count is one `mul`,
and with it `a64_vreg64` — two slots per register, sixty-four bits of value —
needs nothing else.

**How many slots its value takes** is still a refusal, and a different one. An
operand wider than a slot arrives at the handler as limbs, so a stencil that
passed one word would hand a 128-bit instruction half its input. `a64_vreg128`
is declined by name for that, and says so.

⚠️ **The rest of the register becomes zero.** `ldr d1` writes the low half of
`v1` and the architecture clears the high half; the executors do it and the
stencils did not, so a translated `ldr d` left whatever the high slot held while
every gate agreed about the low one. Under the commit condition — a write that
did not fire clears nothing — and in both stencil shapes: `ucvtf d0, w1` is the
pure-value twin of `ldr d0`, and was found one gate run after it.

AArch64 is **828 stencils** now, from 183 where this started. What is left: 25
that write the pc, where a block ends by construction; 20 whose value is wider
than a slot; 19 with no lowered effect handler; and a handful of barriers.

## A block ends on its branch, and the branch is in it

25 instructions were declined for writing the pc. A block is straight-line
code, so everything after a taken branch runs regardless — which is why blocks
stopped one instruction *short* of the branch and left it to the interpreter.

The stencil needs nothing new. Every handler already computes where the machine
goes next into the scratch — `pc + 4` when nothing branches, the target when
something does, a `select` when a guard decides — so a block that ends on a
branch has the answer sitting in slot 2. What was needed was for the simulator
to **take** it, instead of adding `4 * count`, and to end a block at the first
instruction whose `ends_block` says control may leave. Both halves are one
field each.

⚠️ **That was one interpreted step per loop iteration.** A 25-instruction loop
that translated 24 of them still paid a decode, a dispatch and a block lookup
every time round.

| corpus | translated | speedup |
|---|---|---|
| RV64I | 92% | 11.2x |
| RV32I | 84% | 6.2x |
| AArch64 seed | 96% | **24.0x** |

### What the gates had been leaning on

Letting a branch into a block broke three assumptions that had held only
because no branch ever had a stencil:

- **The JIT gate composed blocks out of arbitrary instructions.** With a branch
  in the middle, the executor reference goes where the branch says and the
  block runs on — so the gate must apply the same rule the simulator does. It
  asks the lift pack's `ends_block`, which is the same field the simulator
  asks.
- **The Python twin required every stencil to have a register-file hole.**
  `c.j` takes an immediate and redirects the pc: it indexes no register file, so
  that load is optimised away like any other unused machine pointer.
- ⚠️ **The simulator gate compared a 1024-step run against a 256-event trace.**
  The executor replays what the trace holds and the *final* register files are
  then compared, so any run longer than the trace compared two machines that
  had taken different numbers of steps. The two numbers are one number now, and
  the harness asserts it rather than leaving it to a constant.

### Two things the loop was hiding

Raising that limit was what made the next two visible, and neither is about
branches:

- **The timed runs were never compared.** Two passes of 200,000 steps, and
  nothing checked that they took the same number of steps or stopped for the
  same reason. They now do, and it caught the next item immediately.
- ⚠️ **The program was overwriting its own code.** A guest reaches its own text
  through `adrp`, which builds an address out of the pc, so no seeding keeps a
  store away from it. The interpreter re-decodes the changed word and halts; a
  translated block, built once from the old bytes, keeps running the program
  that used to be there. Both engines are right, about different programs. The
  harness gives data a window below the code — the same window translated code
  is masked into — so the comparison is between two engines rather than two
  programs. The self-modifying case remains a real limit: blocks are
  invalidated on `reset` and nothing else.

## A register the instruction names, not the word

`bl` writes x30 whatever its encoding says, and that was a decline: "it writes
`reg` 30 implicitly". The handler had been reporting it all along — the link
value goes into write slot 0 like any other write — and what the stencil had no
answer for was *where it lands*, because there is no operand to hole.

There does not need to be one. A fixed register's index is the description's, so
its slot is a constant the emitter can compute: `offset + (index_offset + index)
* limbs`, with the write discarded outright when that index is the class's
hardwired zero. No hole, no relocation, no patch.

⚠️ **Two counters, not one.** The scratch slot is per *write*; the hole name is
per *operand* write. An instruction with a fixed write followed by an operand
write would otherwise call its second hole `dest1` while the table — which lists
operand writes — called it `dest0`, and the two would bind different registers.

That leaves AArch64 at **855 stencils**, from 183. What is declined now is
declined for a reason that is about the description rather than the stencil:

| | |
|---|---|
| 20 | `a64_vreg128` carries 128 bits, and a stencil passes one slot |
| 19 | no lowered effect handler for it |
| 8 | no value expression this build lowers |
| 14 | barriers, which have no bytes to emit |
| 1 | it traps |

## A value wider than a slot

A 128-bit register's value reaches the handler as **limbs**, low first — the ABI
has always said so, `effect_params` has always emitted one parameter each, and
`llvm_effects_check` has always counted write positions in limbs. Only the
stencil passed one word, so `a64_vreg128` was declined.

Three counters had to become the same counter:

- the **arguments**: one per slot of value, read from consecutive register
  slots, because a register's limbs are consecutive;
- the **scratch budget**: counted in slots of value rather than in effects, so
  a pair of `ldr q` cannot overrun a scratch of four;
- the **commit**: one scratch position per limb, landing in one register slot
  per limb — iterating effects committed the low limb and left the high one
  sitting in the scratch, which is a `ldr q0` that loaded half a register.

⚠️ And the zeroing starts **where the value ends**, not at limb one. A
full-width write fills the register and has nothing left to clear; clearing
from one would wipe the high limb it had just written.

### Where the split stayed

The **pure-value** path still declines a wide operand, by name. It hands the
eval function a single word and commits a single word; joining two slots into
an `i128` and splitting the answer back is a shape it does not have. The moment
the class objection stopped refusing these, it emitted `trunc i64 ... to i128`
— a cast that is not a truncation — and the module stopped parsing. Saying so
is better than growing a second lowering there for four instructions.

AArch64 finishes at **863 stencils**, from 183. Everything still declined is
declined for a reason about the description or the contract: 19 with no lowered
effect handler, 14 barriers with no bytes to emit, 8 with no value expression,
4 wide pure-value instructions, and one that traps.
