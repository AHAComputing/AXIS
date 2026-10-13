# AXIS Effects Design

Status: **5 stages implemented** (E1-E5). First-class **effects** cover memory
loads/stores, control flow, traps, fixed-register writes, named scalar state,
and register *reads* by index. Legacy infix syntax and Lisp `behavior` forms
parse once into the canonical `Instruction.behavior` tree; validators and
generators never reparse the retained compatibility text.

The E3 and E4 entries below carried "Open: control flow in the compiled C
executor" and the same for traps long after both compiled executors had them --
`emit-exec-c` writes `r->next_pc` and `r->trapped`, `emit-exec-rust` does the
same, and `effects_branch` and `effects_trap` are gated on C and Rust as well as
Python. The count in this line is computed from the staging list
(`tools/doc_facts_check.py`) so the next one cannot go stale in silence.

## 1. Motivation and honest scope

Today an instruction's semantics are **pure**: a single `formal_semantics`
expression over operand values, implicitly assigned to the one output operand.
This covers the URV extension-unit op set (pure by design) and is proven across
five backends (golden / C / SMT / LLVM / Rust). It cannot describe an
instruction that touches memory, changes control flow, or traps.

The one real effectful instruction in the examples is RVMT's `TLS_LOAD`
(`rd = load_tls(rs1 + imm)`), which today carries only **free-text** semantics
and is therefore decoded but not liftable/executable.

Reality check on demand: the live consumers are pure (URV) or compat-frozen
(RVMT), so effects are **forward-looking** rather than pulled by an urgent
consumer. Effects buy three things:

1. **Faithful description** of load/store/branch/trap instructions instead of
   free text — so they become liftable, executable, and provable like the rest.
2. **Full-system simulation** — the on-ramp to the simulator-IR interpreter
   wave and to binary-analysis integrations (angr/Ghidra-style lifting) that
   need memory and control-flow effects.
3. **Honest compiler metadata** — LLVM intrinsics can carry correct memory
   attributes (`IntrReadMem`/`IntrWriteMem`/`IntrHasSideEffects`) instead of
   defaulting everything to `IntrNoMem`.

Because this is a language step beyond current live demand, it is staged so the
pure path is never disturbed and the effect machinery can be adopted
incrementally.

## 2. Model: a statement/effect layer over the pure `Sem` IR

Keep `Sem` (in `src/ir.rs`) as the **pure expression IR** — it already lowers to
every backend. Add an **effect statement layer** on top:

> An instruction's behavior is an **ordered list of guarded effects**. Each
> effect writes one **state location**; its value, address, and guard are pure
> `Sem` expressions. Reads of non-operand state (memory, PC) are new `Sem`
> leaves.

A bare `formal_semantics: <expr>` **desugars** to a single effect
`set <output-operand> = <expr>`. So every existing pure instruction is a
one-effect program, and all pure backends stay byte-identical.

## 3. State model

The machine state an effect program can touch:

- **Registers** — existing `reg` operands. Read as a `Sem::Sym`, written as a
  `Set` target. Operands marked `:inout` are both read and written, supporting
  architectural writeback forms without duplicating an encoded register field.
  Implicit architectural destinations use
  `setreg(kind, index, value)`—for example, AArch64 `BL` writes its return
  address with `setreg(a64_gpr64, 30, pc + 4)`. Custom targets can state the
  width explicitly with `setreg(reg, 30, i64, pc + 4)`. The read side is
  `getreg(kind, index)`, an expression leaf: the same read an input operand
  performs — same class rules, same hardwired zero, same file offset — with the
  index fixed by the description rather than selected by decode. A machine
  whose kernel reads the shared register file itself, as an ADRES mode switch
  does, has no operand to carry that value, and until this existed had to take
  it in one and claim the instruction supplied it. The two halves read one
  table of classes, so a register that can be written can be read.
- **Memory** — a byte-addressed space. Read via a new `load` expression leaf;
  written via a `store` effect. Carries width ∈ {8,16,32,64}, signedness (for
  loads), and endianness (default little; RISC-V).
- **PC** — read via a `pc` expression leaf; control flow is `set pc = <expr>`.
  When no effect writes `pc`, the default next PC is `pc + ilen`.
- **Named scalar state** — ISA-declared locations such as AArch64 `nzcv:i4`.
  `setstate(name, value, iW)` writes them, and their names are available to
  subsequent effect expressions and guards.
- **Trap** — a `trap(cause)` effect that aborts the remaining effects and
  records a trap cause (an enum: `illegal`, `misaligned`, `access`, `ecall`, …).
- **CSR and FP state** — the same mechanism as any other named scalar state,
  which is why it needed no new one: RISC-V's `frm` and `fflags` and AArch64's
  `FPCR`/`FPSR` are declared by their ISA and written with `setstate`. This line
  said "(Later)" until long after F3 and Zicsr landed.

## 4. IR extensions (`src/ir.rs`)

Two new **pure-expression leaves** (so reads compose with existing operators):

```rust
pub enum Sem {
    // ... existing: Sym, Int, App, Ext ...
    Load { addr: Box<Sem>, width: u32, signed: bool, endian: Endian },
    Pc,
}
```

A new **effect statement** type, separate from `Sem`:

```rust
pub enum Loc { Reg(String), Mem { addr: Box<Sem>, width: u32, endian: Endian }, Pc, Trap }

pub struct Effect {
    pub loc: Loc,
    pub value: EffectExpr,          // expression + evaluation width
    pub guard: Option<EffectExpr>,  // comparison + operand evaluation width
}

pub struct Behavior { pub effects: Vec<Effect> }   // ordered
```

The frontend parses the statement list once, resolves evaluation widths from
explicit type atoms, operands, and destination contexts, and stores the result
on `Instruction.behavior`. Load access width, load-address evaluation width,
loaded-value width, and destination width remain distinct. Backend lowering
uses these stored widths rather than choosing an ambient width independently.

## 5. Language surface

Add an `effects:` field: a comma-separated list of statement s-expressions
(commas never appear inside an s-expression, so this reuses the operand-list
splitting the parser already has). Statement forms:

```text
(set   <reg>            <expr>)              ; register write
setstate(<name>, <expr>, iW)                 ; named scalar state write
(store <addr> <expr>    iW [relaxed|release]); memory write + ordering
(barrier <architectural-kind> <option>)       ; synchronization event
(setpc <expr>)                               ; branch/jump target
(trap  <cause>)                              ; abort with cause
(when  <cond> <stmt>)                        ; guarded statement
```

Expression leaves gain `pc`,
`(load iW signed|unsigned [relaxed|acquire] <addr>)`, and
`(getreg <class> <index>)`.

A `getreg` makes an instruction effectful in the sense that decides which
backends run it: it reads something the operand list does not carry, so — like
a load — the behavior stays an effect program rather than folding into
`formal_semantics`, and the pure value backends skip it. The compact executor
ABI declines it too, its effect lowering going through the pure IR, which has
no node for the read; the wide ABIs and the golden model perform it. The
registers a behavior reads this way are published in the lift table as
`reads_registers`, because an instruction's dependencies are its operands
except when they are not.

Example — a signed word load and a conditional branch:

```text
instruction lw_tls {
  operands: [rd:reg:32:out, rs1:reg:32, imm:imm:12]
  effects: [ (set rd (load i32 signed (add i32 rs1 (sext i32 12 imm)))) ]
}

instruction beq {
  operands: [rs1:reg:32, rs2:reg:32, imm:imm:13]
  effects: [ (when (icmp_eq i1 rs1 rs2) (setpc (add i32 pc (sext i32 13 imm)))) ]
}
```

`formal_semantics: <expr>` stays as sugar for `effects: [(set <output> <expr>)]`;
an instruction supplies at most one of the two.

## 6. Validation (`src/validate.rs`, `src/ir.rs`)

- Each `set` target names an `output` operand; each `store`/`load` width ∈
  {8,16,32,64}; endian ∈ {le,be}; `trap` cause in the known set.
- Guards/`icmp_*` are i1; addresses and values validate as `Sem` in scope
  (operands + `pc`).
- A `Behavior` is well-formed iff every effect lowers and its targets resolve.
- Derive an **effect summary** per instruction — `reads_mem`, `writes_mem`,
  `writes_pc`, `may_trap` — for downstream metadata (LLVM purity, scheduling,
  the lift table).

## 7. Per-backend impact

| Backend | Effectful handling |
|---|---|
| `golden_model.py`, `axis_semantics.{h,rs}` | eval becomes `step(state)` applying the effect list; `state` = regfile + `mem_read/mem_write` callbacks + `pc` + `trap`. Pure (single `set`) instructions unchanged. |
| `axis_exec.{py,h}` (+ Rust exec) | `step(word, state)` gains a memory model and pc; dispatch applies effects. Pure path unchanged. |
| lift table / lifters | add the effect summary + structured effects; decode already carries operand extraction. |
| SMT (`semantics.smt2`) | pure-only; effectful instructions skipped (documented) — memory needs array theory, out of scope now. |
| LLVM IR (`axis_semantics.ll`) | `load`/`store` lower to LLVM `load`/`store` against a memory `ptr` param; effectful functions take that param; branches lower to a returned next-pc. |
| LLVM intrinsics / patterns | effectful intrinsics carry memory attributes instead of `IntrNoMem`; the existing purity gate becomes an attribute selector. |
| PyRTL | memory/queue interface generation — deferred (already a later wave). |

### 7a. A value wider than a register slot

`%out` is an array of register slots, and a slot is 64 bits. So the effect ABI
has no place to put a 128-bit number -- and it does not need one, because the
register file has no place for it either: `a64_vreg128` is two limbs of 64, and
that is what the hardware, the C executor and the Rust simulator all hold.

The eight AArch64 Q-register loads and stores are therefore emitted as limb
operations rather than as `i128` arithmetic. `ldr q0, [x1]` is two `i64` loads
eight bytes apart reporting into write slots 0 and 1; `str q0, [x1]` takes two
`i64` parameters -- `%rt` and `%rt.limb1`, low first -- and stores them eight
bytes apart. The IR this produces is the IR `ldp`/`stp` already produced, which
is the point: they are the same operation written two ways, and there was never
a reason for one of them to be expressible and the other withheld.

The split is offered only where the description is already limb-shaped: a
register set whose value is a load of exactly the destination's width, or a
store whose value is a plain register read. A 128-bit value that is *computed*
still gets the refusal it had, because that would need arithmetic the ABI
cannot carry rather than a move it can. Emitting it as two limbs would be
inventing a carry the description never wrote.

Finding this meant fixing the reference first. `_write_reg` stored a 128-bit
value in a single slot -- correct only because Python's integers are unbounded
-- while `_read_reg` masked to 64 on the way out, so a value written to a
vector register came back halved. Neither had ever been observed, because every
gate declined these instructions for being too wide, so the only thing checking
the reference was other code that shared the assumption. Both now span limbs.

The gate that proves the lowering is `llvm_effects_check`, against the Python
executor. It was made to see limbs at three points, none of which are optional:
a wide operand contributes two arguments rather than one, a wide destination
occupies two write positions rather than one, and the high limb is seeded from
the full 64-bit range rather than the small values an address wants -- without
that last one, a lowering that stored the low limb twice would agree with the
reference on every case. Both mutations were injected and both were caught.

## 8. Differential checking

Effectful execution must be provable like the pure path. Add an effectful
example (a load, a store, a conditional branch, and `TLS_LOAD` re-expressed with
formal effects). The harness builds a **machine state** (register file + a
memory dict + pc), runs the effectful instructions through the golden / C / Rust
step functions and a Python reference, and requires the final **registers,
memory, and pc** to agree. This extends `exec_vs_golden.py`/`exec_c_check.py`
from "result register" to "full state delta".

## 9. Staging (each independently landable and proven)

- **E1 — IR + grammar + validation.** _Done._ The infix effect grammar
  (`src/effects.rs`: tokenizer + precedence-climbing parser → `SemanticExpr`,
  plus `Loc`/`Effect`/`Behavior`), the `effects:` field, and desugaring of a
  single register `set` into `formal_semantics`. Pure instructions stay
  byte-identical (`examples/effects_pure.axisl` is proven across the C/Rust/SMT
  differential harnesses); guardrails reject `effects`+`formal_semantics`
  together and `set` to a non-output operand. Memory/control-flow/trap effects
  and multi-effect programs are the next stages.
- **E2 — memory execution.** _Done._ Loads and stores. A memory-load register write
  (`set rd = load(iW, signed|unsigned, addr)`) stays in the effect layer (empty
  `formal_semantics`; loads are not added to the pure `Sem`, so no emitter
  churn). The golden runtime's `_eval` gained a `load` case reading `env['__mem__']`
  (gated on the document having an effect, so load-free artifacts stay
  byte-identical); the lift table carries the effect; and `axis_exec.py`'s
  `step(word, regs, mem)` evaluates the address, reads memory, and writes the
  destination. `tools/exec_vs_golden.py` proves the decode→address→read→writeback
  plumbing against a reference on random memory (`examples/effects_mem.axisl`).
  Stores (`store(addr, value, iW)`, a `Loc::Mem` write target) and multi-effect
  programs followed: the lift table carries an ordered effect list
  (`set`/`store`), `axis_exec.py`'s `step(word, regs, mem)` applies it against a
  memory model with `read`/`write`, and `exec_vs_golden` checks the full
  register+memory delta (`examples/effects_store.axisl`). The compiled C executor
  (`axis_exec.h`) also gained the memory path: an `axis_mem` callback ABI plus
  per-instruction effect functions (`axis_exec_eff_*`) that reuse `c_lower` for
  pure address/value subexpressions and the `axis_sem_*` extend helpers, dispatched
  by `axis_exec_apply`; `exec_c_check.py` proves the full register+memory delta.
  E2 is complete bar a Rust executor (needs a Rust lifter/exec harness first).
- **E3 — control flow.** _Done._ `pc` is in scope for effect
  expressions; `setpc(target)` writes the branch target and `when <cond>:` guards
  any statement (`==`/`!=` → `icmp_eq`/`icmp_ne`, evaluated by the golden runtime,
  gated on effects). `axis_exec.py`'s `step(word, regs, mem, pc)` returns
  `next_pc` (fall-through `pc + ILEN` unless a `setpc` fires); `exec_vs_golden`
  checks the full register+memory+pc delta and runs guarded fixtures twice
  (forced-equal and random) to exercise taken/not-taken (`examples/effects_branch.axisl`).
  The compiled executors followed: `axis_exec.h` and `axis_exec.rs` both write
  `next_pc`, and `exec_c_check`/`exec_rust_check` compare it on the same corpus.
  The counter wraps at the ISA's word -- the fall-through and a `setpc` alike,
  masked where the counter is written rather than left to whatever width the
  target's own arithmetic happened to mask at (`wide_execution.md` §8d).
- **E4 — traps.** _Done._ A `trap(cause)` effect (cause ∈ `illegal`,
  `misaligned`, `access`, `ecall`, `ebreak`) aborts the remaining effects and is
  reported as `step`'s `trap`; guarded by `when`, it is a predicated exception.
  `exec_vs_golden` includes the trap cause in the full-state check
  (`examples/effects_trap.axisl`), and so do `exec_c_check` and
  `exec_rust_check`: both compiled executors abort the effect list and report
  the cause.
- **E5 — LLVM + metadata.** _Done._ The lift effect summary: `axis_lift_table.json`
  carries the ordered `effects` program itself — rendered by the same emitter as
  the Python lifter, so the JSON artifact cannot fall behind the executable one
  — plus a per-instruction `effect_summary` (`reads_memory`, `writes_memory`,
  `writes_state`, `writes_pc`, `may_trap`, `barrier`) derived from the typed
  behavior. `reads_memory` walks the whole expression rather than its head,
  because an atomic read-modify-write nests its load inside the stored value.
  This is the flag set section 6 calls for and the input an honest
  `IntrNoMem`/`IntrReadMem`/`IntrWriteMem` selector needs.

  _LLVM effect lowering done._ `axis_semantics.ll` now carries
  `define void @axis_eff_<name>(i8* %mem, iW %pc, iW* %out, iW %<input>…)`
  per effectful instruction, where `W` is the instruction's own evaluation
  width — 32, or 64 for a 64-bit ISA. Loads and stores become native LLVM
  `load`/`store` against a flat little-endian byte buffer — the point of the
  exercise, since memory stops being an opaque call and becomes visible to the
  optimizer — guards become real `br` edges, and a trap stores its 1-based
  `TRAP_CAUSES` id and returns, aborting later effects exactly as the C and
  Python executors do. `%out` is an `i32` array: written value, write flag,
  next pc (pre-set to the `pc + 4` fall-through), trap id. Accesses are
  emitted `align 1` because the byte-addressed model promises no alignment.
  `tools/llvm_effects_check.py` proves the full register/memory/pc/trap delta
  against `axis_exec.py` under the same byte-addressed memory both sides use,
  and catches an injected miscompile (a wrong fall-through, and a store
  narrowed to a byte).

  _64-bit surface done._ The whole ABI widens together: pc, `%out`, and every
  operand. The width is the widest of the operands, the ISA word, and each
  effect's own value, address, and guard — the effects have to be in that max,
  because an AArch64 `B` sign-extends its displacement to the 64-bit pc while
  its only operand is a 26-bit immediate, and an operands-only check emits a
  silently truncating i32 body. `effect_eval_width` is that one decision, read
  both by the emitter and by the prelude selector, so a body cannot call an
  `@axis_sem64_*` helper the module never defined.

  _AArch64 operators done, except the bitmask family._ `a64_add_nzcv`,
  `a64_sub_nzcv`, `a64_adc_nzcv`, `a64_sbc_nzcv`, `a64_logic_nzcv`,
  `a64_cond_holds`, `a64_shift_reg`, `a64_extend_reg`, `a64_umulh` and
  `a64_smulh` lower to an LLVM prelude ported from the proven C helpers, so the
  flag writers, the conditional selects, and the shifted- and extended-register
  forms are covered. AArch64 effect functions: 525 → 695, over 16680 effect
  executions.

  These operators are deliberately not in `ir::Op`. That enum is the portable
  semantic core five backends agree on, and a flag nibble is not shared
  semantics; C and Rust already pattern-match the operator and call a helper.
  LLVM now does the same, with a twist that avoided duplicating the lowering:
  each application is emitted as a call and *replaced by a fresh symbol bound to
  the temp holding its result*, so what reaches the typed IR is portable
  semantics again. The substitution reuses the rename map that already threads
  register writes forward.

  Each helper was checked against the golden model standalone — 36000
  comparisons across the ten, driven from a small C program — before being wired
  into the emitter. Hand-written LLVM IR is exactly the kind of code where a
  short feedback loop is worth building first; finding a carry-bit bug through
  the full differential gate would have meant minutes per attempt instead of
  seconds. The one subtlety worth naming: the carry out of an addition is
  `result < a` at 64 bits and `sum > mask` below it, because at the full width
  the sum wraps rather than exceeding the mask.

  The bitmask-immediate family — `a64_wmask` and the bitfield moves `a64_ubfm`,
  `a64_sbfm`, `a64_bfm` — followed, and with it every operator-shaped gap is
  closed: **725 of 775** AArch64 effect functions, and the only remaining
  withholding reason is fixed registers, barriers, and atomic groups. That
  family matters out of proportion to its instruction count, because AArch64
  encodes `AND`/`ORR`/`EOR` with an immediate through `wmask`, and every
  immediate `LSL`/`LSR`/`ASR`/`UXTB`/`SXTH` as a `UBFM`/`SBFM` alias. The decode
  finds the highest set bit of a 7-bit field, which is a leading-zero count, and
  `replicate` is a loop — a phi in SSA.

  An unsupported operator returns nothing rather than being left in place, which
  matters more than it sounds: leaving it produced an expression that still
  looked like it needed hoisting, and the emitter asked again until the stack ran
  out.

  Building this turned up a divergence between two already-proven backends. The
  C helper rotates the whole `width`-bit source by `immr`, which is what ARM's
  pseudocode says; the golden model rotates *per element* when the encoded
  element size is smaller than the register. They agree on every
  architecturally legal encoding — 18805 checked, no mismatches — and differ
  only where `immr` or `imms` exceeds the register width, which no legal
  instruction encodes and no fixture therefore carries. That is why the ladder
  never caught it: coverage is fixture-driven, and fixtures are legal by
  construction. The LLVM helpers follow the C rule, so they agree with both
  where the architecture defines an answer. Worth recording as a limit of the
  method rather than a bug in either backend: differential testing proves
  agreement over the inputs it drives, and undefined encodings are outside
  that.

  _Architectural state done._ Effect functions take an `iW* %state` array,
  indexed by the ISA's declared scalar state in the order the lifter publishes
  as `STATE_SLOTS` (`sp`, `nzcv`, `fpcr`, `fpsr`, `tpidr_el0`, …, each with its
  width). Every effect function takes it, not only the ones that use it, so a
  caller implements one calling convention rather than a signature that varies
  by instruction. A read loads its slot once at entry and joins the same rename
  map that threads register writes forward, so a write is visible to the effects
  after it — the mutable state map the executors have, expressed in SSA.

  That is what unblocks AArch64's flag-reading instructions: `adc` takes its
  carry-in from NZCV. Flag *writers* need more than the ABI — their value is
  `a64_add_nzcv` and friends, ISA-specific operators with real content that the
  LLVM prelude does not implement yet — so `adds`/`subs`/`ands` remain withheld
  on the operator rather than on the ABI.

  The gate seeds state with non-zero values before each case and compares it
  after, because an instruction that reads NZCV and one that ignores it agree on
  an all-zero state: a handler that dropped the read would have passed. Reading
  or writing the wrong slot is caught (1411 failures for a misdirected write).
  Comparing all nine slots in every case turned out to generate a C driver clang
  spent over ten minutes on, so only the slots a case changed are compared by
  name, plus a sum over the array — the same shape as the memory-image check.

  _Atomics done._ The LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN,
  SWP, and CAS families lower to native `atomicrmw` and `cmpxchg` — 288 and 32
  of them — in all four widths and all four orderings.

  AXIS models an atomic read-modify-write as two effects: a register set from an
  `atomic_load`, then an atomic store whose value may depend on what was loaded.
  Emitting those as a separate load and store would produce the same answer on
  one thread, and this gate runs one thread, so it could not tell the
  difference. That is the argument for fusing rather than against it: a split
  lowering would be wrong in exactly the way nothing here can observe. The pair
  is recognized structurally and becomes one instruction, or it is withheld.
  What the differential check proves is the value semantics; indivisibility and
  ordering are carried by construction, in the choice of a single LLVM atomic
  instruction and its ordering, and are not observable from a single thread.

  Orderings pair off the way AArch64's A and L bits do — a relaxed load with a
  release store is `release`, an acquire load with a relaxed store is `acquire`,
  both is `acq_rel`, neither is `monotonic`. A `cmpxchg`'s failure ordering is
  dropped to the strongest LLVM allows there (`acquire`, else `monotonic`).

  Two things this surfaced. `LDCLR` spells its bit-clear as `and(loaded, not
  rs)`, so the complement is a plain instruction before the atomic one and the
  operation is an ordinary `and`. And an atomic access must be naturally
  aligned: AArch64 takes an alignment fault otherwise, which LLVM's atomics
  inherit from the hardware, and driving them at a random byte address crashed
  the harness outright. AXIS does not model that fault, so the gate generates
  addresses the architecture allows rather than comparing two backends on
  behaviour neither defines.

  Coverage worth recording, because the first version of it was nearly empty: a
  compare-and-swap only stores when memory still holds what the comparison
  register held, which against random memory is never. Swapping `cmpxchg`'s
  expected and new operands showed up in **2** cases out of 11544. Half the
  cases now load the comparison register with what is actually at the address,
  and the same injection is caught 1819 times.

  The AArch64 seed went from **zero** effect functions to 481 proven ones —
  every unsigned, unscaled, indexed, and acquire/release load and store form,
  `ldp`/`stp` including the writeback variants, the whole atomic surface,
  `adr`/`adrp`, and every branch form — checked over 11544 effect executions
  against the Python executor.

  `%out` carries up to `effects::EFFECT_MAX_WRITES` register writes as
  `[value0, wrote0, next_pc, trap, value1, wrote1, …]`. The first four slots are
  the layout every earlier consumer already read, so a caller that only handles
  single-write instructions is unchanged. Write `k` is the `k`-th
  register-writing effect, and the lift table publishes those in order with
  their destination operand, so a consumer maps writes to registers without
  guessing. The slot count is emitted as `EFFECT_OUT_SLOTS` rather than left for
  each caller to know: a function writes only the slots its instruction needs,
  and a short array is a stack overrun rather than a wrong answer.

  AArch64 `ldp` with writeback writes three registers, the most any instruction
  in the corpus needs. Its base update is the *first* effect, which is why a
  single-`result` view of the delta is not just incomplete but misleading — the
  one value it reports is not the one a caller would guess.

  _Fixed registers and data barriers done._ A fixed register write reports
  through the same slot machinery as any other; what makes it addressable is
  that the lift table publishes the *index* (AArch64 `BL` writes x30), so a
  consumer mapping write `k` to the k-th register-writing effect finds a
  constant where an operand name would otherwise be. A data barrier becomes a
  real `fence`: LLVM's fence carries an ordering but no domain, so every
  shareability option lowers to the strongest ordering — stronger than the
  architecture asks is conservative, never wrong, and a consumer that needs the
  domain has the option value in the artifacts.

  **733 of 775** AArch64 effect functions now, and the 42 that remain are two
  groups, neither of them a missing helper:

  * The pair exclusives and pair compare-and-swaps — `LDXP`/`STXP`,
    `LDAXP`/`STLXP`, `CASP` — which act on two registers as one transaction and
    need a two-register atomic primitive.
  * The instruction and speculation barriers — `ISB`, `CSDB`, `SSBB`, `PSSBB`,
    `SB` — which constrain the pipeline rather than the memory model. LLVM has
    nothing that says so, and lowering them to a memory fence would claim
    something the architecture does not, so they are withheld with the reason
    named.

  The *single-register* exclusives came for free with the state array:
  `LDXR`/`STXR` and their acquire/release forms set and test the monitor through
  `exclusive_address`, `exclusive_size` and `exclusive_valid`, which are ISA
  state like any other, so they needed no new mechanism.

  Withheld, with a comment rather than an approximation:

  * Named state, fixed registers, barriers, and atomic groups, as before — a
    state *write* has nowhere to go in this ABI.
  * A value that *reads* named state. This was a latent bug the widening
    exposed: the withholding rule tested `effect.loc`, so AArch64 `adc`, whose
    carry-in comes from `nzcv`, lowered to a reference to an SSA value nobody
    defined. Every symbol is now checked against what the ABI actually passes
    in — the input operands plus `%pc` — via the same `ir::check_symbols` the
    typed IR uses.
  * More than one register write. `ldp`/`stp` and the indexed *loads* update a
    base register as well as their data register, and `%out` carries one write.

  That last rule mattered more than it looks. The differential gate compares a
  single `result` register, so before this the post-indexed forms were *passing
  while dropping their base-register write entirely* — a gate that would have
  accepted almost any lowering of them. It now requires the executor's own
  register delta to be single-valued for every case it drives, so the rule is
  checked rather than trusted; removing it is caught as 48 named instructions
  rather than a silent pass.

  A later effect *reading* a register an earlier one wrote was withheld too, at
  first: a pre-indexed store is `rn = rn + imm; Mem64[rn] = rt`, and the address
  is the *updated* base, which the executors see because they evaluate effects
  in order against a mutable register file. That one turned out not to need an
  ABI at all. Each register write records the SSA value holding its result, and
  the effects after it lower against that instead of the parameter — a rename on
  the typed IR (`rename_symbols`), before lowering, so one code path still
  produces the output. Removing the threading is caught as 2002 failures.

  The multi-write ABI that paragraph called open is built: `%out` is a list of
  writes, `effects::EFFECT_MAX_WRITES` bounds it at four, and the bound has a
  reason — AArch64's `ldp` with writeback writes both data registers and the
  base, which is the most any described instruction needs. The 19 `ldp`/`stp`
  forms in `examples/aarch64_translation_seed.axisl` are what waited on it.

  The in-process LLVM JIT (`tools/jit_llvm.py`) consumes these handlers, so it
  now executes the 32-bit effect surface as well as the pure one: it threads
  the pc through a block, commits a register write only when the handler
  reports one, and exits early on a trap, checked against `axis_exec.py` on the
  full register/memory/pc/trap delta.

  _Intrinsic memory attributes done._ `emit-llvm-intrinsics` selects
  `IntrNoMem`/`IntrReadMem`/`IntrWriteMem` from the same summary instead of
  assuming purity, and never marks an effectful intrinsic `IntrSpeculatable`
  because a memory access can fault. The summary and the attributes come from
  one function (`effects::effect_summary`), so the artifact a consumer reads
  and the attributes a compiler trusts cannot drift apart. Control flow, traps,
  barriers, and guarded register writes are withheld with the reason named in
  the file: an intrinsic call always produces its result, so a conditional
  write has no honest declaration. `tools/tablegen_validate.py` confirms the
  records are valid TableGen across the RV32 and AArch64 corpora (419 records
  for the seed).

  _JIT done._ `tools/jit_llvm.py` builds blocks at the ISA's width, so the
  in-process LLVM JIT executes AArch64: a 64-bit register file, pc and status,
  every reported register write committed, and the state array threaded through.
  Because a compiled block knows each register index as a *constant*, AArch64's
  encoding-31 rule — the zero register for the plain classes, the stack pointer
  for the `sp` ones — is decided at build time rather than tested at run time,
  and a W-form read masks to 32 bits statically. A handler emitted at a
  different width than the block has its scalar arguments narrowed and its
  result widened; an effect handler cannot be adapted that way, because its
  `out` and `state` arrays *are* that width, so those are left out.

  Atomics are also left out, unlike in `llvm_effects_check`. An atomic access
  must be naturally aligned or the hardware faults, and that gate arranges
  aligned addresses because it drives one instruction at a time with a known
  register value. A block computes addresses from a register file earlier
  instructions have already modified, so an unaligned `atomicrmw` takes SIGBUS
  and kills the process rather than reporting a mismatch. Their value semantics
  are proven by the other gate; this one proves block composition.

  Three harness bugs surfaced getting there, all of the same shape — a
  reference that quietly did something other than what it was being compared
  against. The executor was called without an ISA, and this corpus describes two
  encoding spaces, so the same word decoded to a different instruction. The
  operand canonicalization replaced the value map wholesale, dropping operands
  the lifter reports as `None`. And the generator drew random field values
  without checking that the word decodes back: AArch64 leaves `shift = 3`
  undefined for the shifted-register forms, and the reference refuses such a
  word while a block calls the handler directly — comparing an implementation
  against nothing.

W/X AArch64 `LDXR`/`STXR`, `LDAXR`/`STLXR`, `LDXP`/`STXP`, and
`LDAXP`/`STLXP` use named reservation-address/size/valid state and guarded
store effects, including success status and reservation clearing. Pair loads
reserve 8 or 16 bytes and pair stores commit both adjacent addresses inside
one atomic group; a scalar-sized reservation cannot satisfy a paired store.
`CLREX #imm4` invalidates the same named monitor state without a memory access;
the implementation-hint operand remains encoded and is forwarded to targets.
`LDARB`/`LDARH`/`LDAR` and `STLRB`/`STLRH`/`STLR` apply acquire or release
ordering to ordinary B/H/W/X accesses without establishing or consuming a
reservation.
`barrier(kind, option)` / `(barrier kind option)` is a distinct typed effect.
AArch64 `DMB`, `DSB`, and `ISB` retain their raw four-bit option and barrier
kind through lift metadata and lowering equivalence; their accelerator targets
carry the same event. `SB`, `CSDB`, `SSBB`, and `PSSBB` are distinct typed
speculation events. `SSBB` and `PSSBB` occupy `DSB #0` and `DSB #4`, so the
generic DSB declaration excludes those values and constraint-aware overlap
validation proves the alias decode space disjoint. Single-threaded generated
executors evaluate the option and otherwise perform no state mutation, leaving
actual ordering/completion enforcement to a concurrency-aware backend.

System-state transfer begins with AArch64 `MRS Xt, NZCV` and `MSR NZCV, Xt`.
The existing named `nzcv:i4` state remains canonical: reads place it in
`Xt[31:28]`, while writes extract those four bits. This keeps flag consumers
and producers on one typed state location instead of duplicating NZCV as a
special register-file value.
The EL0-accessible user system registers `FPCR`, `FPSR`, `TPIDR_EL0`, and
`TPIDRRO_EL0` extend the same mechanism: each is an ISA-declared scalar state
whose `MRS` reads it into `Xt` and whose `MSR` writes it back at the
architectural width (32-bit `FPCR`/`FPSR` truncate a 64-bit source);
read-only `TPIDRRO_EL0` declares no write form. Their accelerator
counterparts and lowerings carry the same state names.

A read of one of these is a bare state atom rather than an operand, which
makes the general rule explicit: **whether the executors run a behavior is the
frontend's decision, not a property backends re-derive.** `desugar_effects`
folds a behavior into `formal_semantics` only when the whole instruction lowers
into the pure `Sem` IR over its own operands, so a retained behavior with empty
`formal_semantics` must be emitted as effects
(`effects::behavior_is_authoritative`). Backends that instead asked
`is_effectful` — a symbol allowlist built for the desugaring fast path —
dropped reads of every state the list did not name, leaving those instructions
with neither semantics nor effects and therefore no-ops in the generated
lifters and executors.
Load/store effects retain relaxed, acquire, or release ordering in lift and
translation artifacts. This models local
exclusive-monitor behavior for deterministic translation and execution;
inter-core invalidation and enforcement of weak-memory ordering remain outside
the current executor model.

W/X AArch64 `SWP`, `SWPA`, `SWPL`, and `SWPAL` use `atomic_load` plus
`atomic_store`. Acquire ordering belongs to the load half and release ordering
to the store half, allowing all four ordering combinations. Atomicity is
orthogonal to the relaxed/acquire/release order field and is retained by lift
metadata, translation manifests, canonical Lisp, and lowering equivalence.
Generated single-core executors apply the pair in effect order; consumers with
concurrent memory must implement the marked pair as one indivisible transaction.

Lisp `(atomic-group id ...)` makes that transaction boundary structural rather
than inferred from adjacency. Each canonical effect carries its non-zero group
id through lift metadata, lowering equivalence, and translation effect-order
manifests. Groups are contiguous ordered regions with at least two effects and
an atomic memory access. Deterministic executors have no interleaving within an
instruction; concurrent runtimes must use the group boundary as their locking
or transactional commit scope. Guard predicates may combine equality leaves
with `and`, `or`, and `not`, which is sufficient to express paired CAS success.
W/X `CASP`, `CASPA`, `CASPL`, and `CASPAL` apply this model to two adjacent
loads and two conditional stores. Derived `rs2`/`rt2` selectors encode the
architectural `+1` register rule, while masked decode constraints require the
encoded first selectors to be even. Source and accelerator forms share the
same four-effect transaction and are proven equivalent by explicit lowerings.

W/X `LDADD`, `LDADDA`, `LDADDL`, and `LDADDAL` reuse the loaded result in the
subsequent atomic-store expression. Effect-local values therefore remain in
scope across ordered effects even when encoded source and destination registers
alias; generated C and Rust snapshot physical inputs and retain semantic results.

Relaxed W/X `LDCLR`, `LDEOR`, and `LDSET` use the same result-carrying atomic
pair for bit clear (`old & ~value`), exclusive-or, and set updates.
The B/H/W/X `LDSMAX`, `LDSMIN`, `LDUMAX`, and `LDUMIN` families use typed
signed or unsigned comparisons at the memory-access width. All acquire/release
combinations retain their ordering metadata, and native C/Rust effect emitters
apply the same width-masked comparison rules as the Python executor.

**Non-goals for now:** inter-core memory ordering, SMT of memory (which needs
array theory, and the emitted `.smt2` has no `Array` in it), and variable-length
encodings. CSRs and floating point were on this list and are not any more: 12
Zicsr instructions and the whole F3 effect layer describe them, with the
rounding mode read from state and the exception flags accrued into it.

## 10. Invariants

- The pure path is a strict subset: pure instructions produce byte-identical
  artifacts across every backend after E1–E5.
- `Sem` stays the pure expression IR; effects are a separate ordered layer.
- Effect summaries drive **honest** metadata — an instruction is only marked
  `IntrNoMem` when its effect list is a single register `set`.

## 11. `send`: the effect that leaves no address behind

Added because a consumer hit the wall and named it: *"AXIS has no
send/message/event effect, which is why ACORE.10 could take UpDown's posted
stores but not its event-driven core."* That was a correct reading of the
vocabulary. There were seven statements -- `set`, `setreg`, `setstate`, `store`,
`barrier`, `setpc`, `trap` -- and nothing in them expresses a machine that posts
a message to another machine.

```lisp
(send rs1 rs2 i32)                       ; port, value, width
(send (add i32 rs1 (sext i32 12 imm)) rs1 i32)
(when (ne rs2 0) (send rs1 rs2 i32))     ; posted only when it fires
```

### It is a store whose destination is a channel

That framing is the whole design, and it is what made the extension small. A
posted message does exactly what a store does: evaluate two expressions, emit
one ordered event, continue. So it rides the machinery that already exists --
the same three-part shape (`where`, `what`, `how wide`), the same guard, the
same ordering within an instruction's effect list, the same host interface, the
same differential gates. `Loc::Port` sits beside `Loc::Mem` and the thirteen
`match` sites the compiler named were each a small answer.

⚠️ **No ordering argument.** A store takes `relaxed|release`; a send does not. A
posted message is posted, and an ISA that orders its sends against its stores
says so with `(barrier ...)`, which is the effect that already means that. A
second ordering vocabulary here would be two spellings of one architectural
fact.

### What it deliberately is not

**Receiving.** A core that blocks until a message arrives is not describing an
instruction's effect -- it is describing when the machine runs at all, which is
an execution model. The send half is what an event-driven ISA's *instruction*
does, and it is the half that can be checked against a golden model today. The
receive half needs a scheduling model before it can mean anything, and an effect
whose meaning every backend has to guess is worse than no effect.

### Held the way everything else is

`send` is observable or it is nothing: an effect no gate can hold is an effect
this language cannot afford. So `axis_mem64` gained a `send` hook (appended, so
every existing host still initialises correctly), `WideMemory` gained
`send64` with a default that does nothing, and the golden model emits
`send_<name>(operands) -> (port, value, width)` beside `store_<name>`.

`tools/send_check.py` compares the **ordered log**, not a final state -- a
message is not readable back, so the observable is *which port, what value, how
wide, in what order*. Two backends that posted the same two messages in the
other order leave identical machines behind, and that is a difference this gate
is there to see. Three mutations, three caught: the port and payload swapped,
the guard ignored, the port unmasked.

⚠️ The gate's own seeds needed fixing before it measured anything. Registers
were `seed + i`, which is never zero for `i > 0`, so a guard testing its payload
against zero was true in every case and "posted" was never told apart from
"evaluated". They are `seed * (i + 1)` now, and one seed is zero.

### Where it declines, and why each one is named

| | |
|---|---|
| JIT stencil | *it posts a message, which needs a call* -- a stencil is machine code with no call in it |
| LLVM IR | no spelling: not a store, not a fence, and an invented intrinsic is a name with nothing behind it |
| binary lifter | **refused**, not skipped -- IR for a program that communicates, with the communication missing, reads as a correct lift of a different program |
| narrow (32-bit) executor | `None`, so the wide executor takes it |

The extension cost three instructions in `examples/effects_send.axisl`, thirteen
`match` arms, one hook on each host interface -- and it crossed all 56 corpora
and every backend with exactly one number to update in a document.
