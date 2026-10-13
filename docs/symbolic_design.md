# Symbolic execution over the generated semantics

Status: **a machine** (no solver in the loop): registers, a pc, memory,
architectural state, traps, floating point, and every path a branch can take.

## 1. Why it is one more backend rather than a new model

`emit-smt2` has always been a symbolic backend of a kind: it defines each
instruction's pure value semantics as an SMT-LIB function, proven equal to the
golden model. What it does not define is everything *around* a value -- a
guard, a memory access, two writes, the pc -- and it says so, instruction by
instruction:

```
; axis_instr_beq: behavior is guarded
; axis_instr_jal: behavior writes 2 values beside its state; one value cannot hold them
; axis_instr_auipc: unknown formal_semantics symbol `pc`
```

196 of RV64I's 338. A symbolic *executor* needs the other 142, because a branch
is exactly the thing worth asking a solver about.

`emit-symbolic-python` walks the same effects the executors run and evaluates
them to **terms**: a register holds an expression, memory holds expressions, a
guarded effect contributes a path constraint, and a `setpc` records a target
kept as a term rather than a decision. It re-describes nothing; it is one more
reading of the table five other backends already read, which is the only reason
it can be trusted without a second proof of what the instructions mean.

## 2. Checked without a solver

⚠️ The property that makes this testable needs no solver at all. Run a program
concretely from random inputs; run it symbolically from free variables; bind
those variables to the concrete inputs and evaluate the terms. Every register
must come out the same.

A solver answers questions about *all* inputs. Agreement on one is what says
the terms mean what the instructions do -- and it is the thing a symbolic
executor gets wrong, because a term that is merely well-formed solves to a
confident wrong answer.

720 runs over RV64I, 412 over RV32I, register for register, no disagreements.

## 2a. A machine, not a stepper

A symbolic executor that runs one instruction is a term builder. What makes it
the thing Triton and angr are is that it *runs*: it fetches from its own
memory, follows the pc, and forks where a branch does.

```python
state = sym.State(slots, image, pc=0x100, code=(0x100, 0x118))
found = sym.explore(state, steps=12, paths=16,
                    stop=lambda m: not inside(m.pc))
for path in found["finished"]:
    print(sym.path_smt(path))        # the constraints, for a solver
```

| piece | what it is |
|---|---|
| `State.regs` | one term per slot, free variables to begin with |
| `State.pc` | a term, concrete while the trace knows where it is |
| `State.mem` | an **array** term: `select` to read a byte, `store` to write one |
| `State.state` | declared architectural state, free variables like the rest |
| `State.path` | the constraints this path needed |
| `successors()` | one state, or two where a guarded `setpc` forks |
| `explore()` | breadth-first over paths, with step and path budgets |
| `path_smt()` | the path as SMT-LIB, for something that does have a solver |

⚠️ **Memory is an array, not a byte map.** A map can only answer at an address
it knows, so a load from a computed address had to be concretised or declined
-- and every register starts free, so nearly every address is computed. As an
array term a store is a new memory *value*, and whether two symbolic addresses
alias is a question about terms rather than a decision made on the caller's
behalf. Concretising is still there behind `model=` for callers who want one
run instead of all of them, and it still records `addr = value` on the path.

⚠️ **A guarded write is an `ite`, not a constraint.** Asserting the guard says
the write happened, which is a decision and the wrong one half the time. The
register, or the byte, keeps its old value under the guard -- exactly what the
executor leaves. Only a guarded `setpc` becomes a constraint, because that is
the one place where the two directions are different *paths* rather than
different values.

⚠️ **A store might hit the program.** A machine that ignored that would fetch
bytes it had already overwritten. Declaring `code=(lo, hi)` does not make the
question go away: every store to a symbolic address then records `addr < lo or
addr >= hi` on the path, so the assumption is one a solver can refute. Without
a declared range, a fetch past a symbolic store is declined by name.

## 2b. Exactly one path, checked without a solver

The property a machine has that an instruction does not: explore once from free
inputs, then bind concrete ones.

* **Exactly one** explored path may hold. Two means the fork invented a way the
  machine cannot go; none means it lost the way the machine did go.
* That path's registers, pc, architectural state and memory must equal the
  concrete machine's, byte for byte.

`symbolic_machine_check.py` runs it: 8 programs a corpus at a time, 48 concrete
inputs, 24 forks, 36 stores landing on an address another store had already
used.

⚠️ Each of those numbers is a coverage assertion, not a statistic, and each was
added because a mutation survived without it:

| mutation | survived until |
|---|---|
| `ite(guard, new, old)` → `new` | a corpus with a guarded **non-branch** write was gated (`effects_guarded_set`; rv64i has none) |
| a load returns the **oldest** store for an address | addresses were drawn from a pool of four, so two stores could meet |
| the `adrp`-style byte order of a load | -- caught from the start |
| `ILEN = 4` → `8` | -- caught from the start |
| a guarded `setstate` ignores its guard | **nothing**: every guarded `setstate` in every corpus sits on a floating-point instruction with a `trap` effect, both already declined. So the `ite` was removed and the case is declined by name rather than carried as code no gate can reach. |

Two harness bugs it found on the way, both of which look exactly like a
symbolic executor being wrong:

* **A `bytearray` is not memory.** Python slice assignment past the end
  *appends*, so a store to a wild address landed quietly at the end of the
  image and read back as zero. Both gates use a sparse dict now.
* **Later effects see earlier writes.** `amoxor.w` is `rd = atomic_load(rs1)`
  then `store rs1, rd ^ rs2`: the store names a register the same instruction
  just wrote. Evaluating it against the old environment stored the wrong bytes
  and left every register right -- which is why a gate that compared only
  registers never saw it.

## 2c. The SMT text, proven rather than sampled

`concrete()` says what a term *means*; `smt()` is what a caller hands to a
solver, and until there was a gate for it nothing checked the two agreed. There
is one now, and the reference is `emit-smt2`, whose `axis_instr_*` functions are
already proven equal to the golden model:

```smt2
(assert (distinct (axis_instr_fadd_s_rtz rs1 rs2) <the symbolic term>))
(check-sat)     ; unsat -- they cannot differ, for any input
```

That is a proof over all inputs rather than agreement on one, and it is what
made writing a **second spelling of floating point** safe. The FP rendering had
been declined on purpose: `emit-smt2` renders these into SMT-LIB's
FloatingPoint theory and a second version would be unproven the moment it
differed by a rounding mode or a NaN. With the solver holding the two together,
it is written -- every rounding mode, `fp.fma`, `fp.sqrt`, the compares, and
`fneg` on the bits rather than through the theory.

**178 of RV64I's instructions are proven equal**, 150 of RV32I's, 137 of
AArch64's. The 18 left are `fcvt_*`, which `emit-smt2` renders through helper
functions this does not emit.

⚠️ What the gate found the moment it existed: `smt()` produced text no solver
would parse. Indexed operators were printed as plain applications -- `(extract
7 0 x)` rather than `((_ extract 7 0) x)` -- and SMT-LIB's `Bool` was being
crossed with `(_ BitVec 1)`, which this representation does not distinguish. A
rendering that had been shipped, read, and never once parsed.

## 2d. Both directions of "the paths are right"

| gate | asks | answered by |
|---|---|---|
| `symbolic_machine_check` | is every **real run** in the path set? | random inputs: exactly one path holds for each |
| `symbolic_path_check` | is every **listed path** real? | a solver: an input satisfying the path, run on the machine |

The second is the one a symbolic executor exists for, and it is the only check
of `path_smt`. For each path the solver is asked for a model; the concrete
machine is then run on **that** input and must take that path -- same trap,
same pc, same registers, same state.

⚠️ Comparing where it stopped is not enough. Every path through a program whose
branches jump forward ends at the same address, so two deliberately broken
forks -- the taken path carrying `not g`, and the fall-through carrying no
constraint at all -- passed until the registers were compared too.

A path whose constraints are unsatisfiable is **infeasible**, not a failure:
the explorer forks without asking whether a branch can be taken, so some paths
it lists cannot happen. AArch64 produces one per run or so; they are counted.

⚠️ The programs hold no loads. A model has to fix memory as well as registers,
and constraining an array byte by byte is a different piece of work.

### Calling `emit-smt2`'s helpers rather than restating them

AArch64's condition codes and bitfield masks are algorithms, not expressions,
and `emit-smt2` writes each once as a function the rest of its file calls. The
symbolic runtime now carries those same definitions (`SMT_PRELUDE`, emitted by
the same Rust) and *calls* them, so `b.eq`'s condition reaches a solver without
a second opinion about what it means. Before that, seven of AArch64's paths per
run could not be rendered at all.

What still cannot: `a64_add_nzcv` and friends, which `emit-smt2` spells inline
rather than as helpers. Writing them here is now a safe thing to do -- §2c's
gate would prove them -- and it is simply not done yet.

## 3. Concretising an address, and saying so

Every register starts as a free variable, so every address an instruction
computes is symbolic, and a purely symbolic memory declines nearly everything:
278 of 336 instructions before this existed.

So an address is concretised against a model when one is supplied -- and the
assumption is **recorded** as a constraint, `addr = value`, on the path. That is
what a symbolic executor does in practice, and the constraint is what keeps the
resulting term true: a caller that solves the path sees exactly which address it
was solved for.

## 4. Floating point, delegated rather than re-described

**All 328 of RV64I's instructions execute symbolically, and 240 of RV32I's.**
The list that used to stand here -- 156 declines, ~70 of them floating point --
is empty for both.

⚠️ The FP semantics are **not written here**. What `fadd_rm` means -- each
rounding mode, subnormals, the canonical NaN, ties away from zero -- is settled
in the golden model, with a `Fraction`-exact reference behind it and five other
backends proven against it. A symbolic executor that wrote its own IEEE-754
would be a second opinion about the same instruction, which is the one thing
this repo never wants. So the **term** is symbolic and only its evaluation goes
to the model: `("axis_fp", width, op, atom, *args)` rebuilds the expression it
came from with its arguments as the numbers they evaluate to.

That bought three things at once:

| was declined | now |
|---|---|
| ~70 floating-point instructions | run, every rounding mode and conversion |
| 18 `effect trap` (the dynamic-rounding forms) | a trap is a **path outcome**: a guarded trap forks, and the trapping path stops where the executor stops |
| 10 `effect barrier` | a no-op, as it is in the executor, which is single-threaded |

The integer leftovers went with them -- `mulh`/`mulhu`/`mulhsu` as a double-width
multiply with the high half extracted, `sdiv`/`srem` as the theory's operators
with the description's own zero rule written out, `ones` as `~(allones << n)`
so a symbolic count works, and `let` as an environment.

⚠️ **`smt()` refuses floating point.** `emit-smt2` already renders these into
SMT-LIB's FloatingPoint theory and those functions are *proven* equal to the
golden model; a second spelling written here would be unproven the moment it
differed by a rounding mode or a NaN. Executing floating point does not need
it -- only handing a path to a solver does, and that says so by name.

⚠️ Declared architectural state is not a decline. `frm` and `exclusive_address`
are free variables, exactly as a register is. A symbol the description does
*not* declare still is, because inventing a variable for it would hide a gap.

## 4a. A register file is not an array of words

⚠️ Treating it as one passed every RISC-V gate and got **544 of AArch64's
instructions wrong**, which is what the corpus said the moment it was asked.
What a class can do, and what this now does:

| the class says | modelled as |
|---|---|
| a **view** -- `W0` is the low half of `X0` | a read masks to the view; a write masks, then **clears the whole register**, which can be a limb away |
| **limbs** -- a `D` register sits inside a 128-bit one | every limb of the register is written, the rest with zero |
| a **hardwired zero** -- `x0`, `XZR` | reads as zero, writes discarded |
| an **alias** -- `SP` encoded as 31 | kept beside the file under its name, exactly where the executor keeps it |
| an **index offset** -- a compressed field's 0 is `x8` | the lifter's own `register_slot` |
| **preserving** views (x86's `AL`), 128-bit registers, operand-placed lanes | declined by name |

`aarch64_translation_seed` runs 888 of its 908 instructions; the 20 that remain
are `a64_vreg128`, a register wider than a slot, which wants the limb-valued
terms `docs/limbs.md` describes.

### What is still refused

`a64_vreg128` (above), and nothing else in these corpora. The AArch64 helper
operators -- `a64_shift_reg`, `a64_wmask`, `a64_cond_holds`, the NZCV family --
are **delegated** like floating point: each decodes an encoding or consults a
table, where a hand-written term goes wrong quietly and the model's version is
already proven. The list is explicit, not a fallback; sending anything unknown
to the model would turn a gap into a silent answer.

### Coverage the gates now assert, because a mutation survived without it

| what | added after |
|---|---|
| each fixture is also run at register index **0 and 31** | writing the hardwired zero, and sending `SP` to the numbered file, both passed |
| two of every twelve cases hold all registers at **0** and at **64** | a rotate by a whole turn was only tested when the dice said so |
| writes to a zero register and to an aliased one are **counted**, and zero is a failure | the same two |
| one ISA per program in the machine gate | forty-one of forty-eight inputs were being skipped in silence, because an accelerator's encoding decoded as something else |
| two stores per program, with zero offsets | AArch64's stores never met on one address, so aliasing went untested |

### One mutation that survives, and why it is not a gap

Turning the guarded `setstate` back into a plain assignment passes every gate.
(So does dropping the second remainder in `ror`, which SMT's shift semantics
make redundant -- that one was removed rather than kept.)
That is an *equivalent* mutant here rather than a hole: every guarded
`setstate` in these corpora is on an FP instruction whose guard is `frm < 5`,
the exact negation of the `trap`'s `frm >= 5` -- and when the guard is false
the effect walk has already stopped at the trap. The `ite` is written anyway,
because the next description's guard need not be a trap's negation, and this
paragraph is what stands in for a gate until one is.

## 5. Bugs worth recording

**The gate bound state to its post-value.** `CSRRWI_FRM` reads the old rounding
mode into its destination and then writes a new one, and the concrete executor
*mutates* the state dict it is handed. Binding `state_frm` from that dict after
the step made the symbolic answer disagree by exactly the value the instruction
had written. Reads before writes, in the harness this time.

**Architectural state did not survive an instruction boundary.** `fflags`
accumulates: `(or i5 fflags (fadd_fx f32 rs1 rs2))`. A second FP instruction
read the *initial* free variable rather than what the first had written, and
dropped its flags. One instruction at a time could never see it -- each run
starts fresh -- and it took a program with two FP instructions and a state
comparison to show a single bit missing.

**FP arguments must not be narrowed to the operator's width.** The golden model
leaves a leaf unmasked and masks inside each operator, because a conversion is
told its source width separately: `(fcvt_f2u i32 32 rs1)` reads a 32-bit float
out of a 64-bit register. Narrowing `rs1` to the result width turned every
double into its low half, and the answer was a plausible number rather than an
error.

**A `bytearray` is not memory, twice.** The first time it appended past the
end; the second, byte addresses did not wrap. A load at the top of the address
space reads its last byte and then address 0 -- which is what the symbolic
side's `bvadd` does, while Python's `addr + 1` kept counting and read zero. And
the wrap belongs to the *host*: the executor masks an address to the width the
description gives it, then hands it over, so byte offsets are added at 64 bits
whatever width the address was computed at. Getting that backwards made RV32I's
atomics disagree with the machine they model.

**`udiv` mapped straight to `bvudiv`.** SMT-LIB leaves division by zero to the
solver -- all ones -- and the description's answer is zero. It took a register
index that made both operands the same zero register to show it.

**The gate could not tell signed from unsigned.** Register values were drawn
small and aligned so a computed address landed inside the image -- so lowering
`min`/`max` as `minu`/`maxu` passed. Values with the high bit set are drawn now,
and an address off the end reads zero on both sides, so they cost nothing.
⚠️ RV64I still cannot catch it: it has no `min` fixture, and the ones it has are
AMO forms that decline for other reasons. `zbb_like` catches it, which is why
the gate runs there too.
