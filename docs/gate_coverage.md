# What a gate covered, not just whether it passed

Status: **measured**, and the answer was not the one predicted.

## 1. Why

Twice in one session, the same gate reported PASS about something it had never
run. The scalable JIT gate compiled no load, and later compiled no gather —
both times because it sampled instructions from a pool and the sample happened
to miss a whole class. Neither was visible in its output. Both were found only
because an *injection* disagreed between two corpora, and the only explanation
was that one of them had never compiled the broken thing.

That is not a bug in those runs. It is a property of every gate that draws a
random program from a pool of instructions, and this repo has five:

| gate | draws |
|---|---|
| `exec_fuzz` (cross-executor fuzz) | random programs over the corpus |
| `jit_llvm` (4 JIT gates) | random blocks, pure and effectful |
| `jit_c` | random blocks |
| `llvm_effects_check` | random operand values per instruction |
| `exec_vs_golden` | random register files per fixture |

Their summaries say how *much* they did — "300 programs x 16 instrs", "12
blocks" — and not *what*. A run of 300 programs that never selected a store is
indistinguishable in the output from one that exercised every instruction.

## 2. The two questions that are not the same

**Did it run enough?** — answered today, by counts.

**Did it run everything the corpus offers?** — not answered anywhere.

The second is the one that matters for a differential gate, because the
consequence of missing a class is not a weaker result. It is a *green* result
about code that was never executed, which is worse than a red one.

## 3. What to add

For each sampling gate, two lines and one condition:

    report   the dimensions covered, as sets: which mnemonics, which effect
             kinds, which addressing modes, which operand shapes
    fail     when a run covers materially less than the corpus offers

"Materially less" needs care. Requiring every mnemonic in every run would make
the gates flaky and slow for no gain — a corpus with 500 lane instructions does
not need each one in each block. The dimension that matters is the *class*: a
load, a store, a branch, a trap, an atomic, a multi-write. Missing an entire
class is a hole; missing one of forty adds is not.

This is the shape now applied to every sampling gate:

* `scalable_exec_check` reports `addressing covered: indexed, segment, strided,
  unit` and fails when a form the corpus offers never ran. Its class is the
  addressing mode, since a gather and a unit load are both a `set` and take
  different paths.
* `jit_stencil` forces one word of every shape into every block, and fails if a
  run is all-translated or all-stepped.
* `jit_llvm` reports instruction coverage and requires effect-class coverage
  (§4).
* `exec_fuzz` and `jit_c` do the same, over the effect classes of the corpus
  they draw from.

An earlier version of this section claimed the `scalable_exec_check` condition
already existed. It did not: the gate printed the addressing modes and required
nothing, so the sentence described an intent that had never been written down
in code. It was found by measuring adherence to this document rather than by
reading it, which is the same way everything else here was found -- and is the
argument for the rule applying to this document too.

## 4. What it found

The prediction, written before measuring: *"`jit_llvm`'s pure path is the most
likely to be silently narrow; `exec_fuzz` probably fine."* Half right, and
wrong in the more interesting direction.

| gate | corpus | instructions covered |
|---|---|---|
| `exec_fuzz` | fuzz_mix | 6/6 |
| `jit_c` | fuzz_mix | 6/6 |
| `jit_llvm` pure | AArch64 | 51/65 |
| `jit_llvm` effects | AArch64 | **89/413** |
| `llvm_effects_check` | any | all, by construction |
| `exec_vs_golden` | any | all, by construction |

The last two iterate every fixture and sample *values*, not instructions, so
their instruction coverage is complete and always was.

The A64 JIT gate compiles a fifth of the effectful instructions it is pointed
at. 324 of them have never been through it.

### And yet it is not holed

By *class*, the same run covers **11 of 11**. Every effect shape the corpus
offers -- store, branch, trap, guarded write, multi-write, and the combinations
-- gets compiled by at least one instruction.

That is the difference between a number that looks alarming and a hole. This
gate exists to test the JIT's **block lowering**: how a decoded instruction
becomes IR, how writes are committed, how a trap ends a block. An instruction it
never compiled is not an untested handler -- `LLVM == golden` compares every one
of the 413 -- it is one more instance of a lowering path already exercised by a
sibling. Forcing all 413 through would cost minutes to prove what another gate
proves already.

So the rule is: **report instruction coverage, require class coverage.** The
class condition fails the gate, and it can: removing every trapping instruction
from the pool reports `effect classes: 3/4 compiled; missing ['trap+guarded']`
and fails.

### What this does not settle

"Class" here means the effect-kind signature, and that is the right notion for
*this* gate because effect kinds are what its lowering branches on. It would be
the wrong notion elsewhere -- the scalable JIT needed addressing mode, since a
gather and a unit load are both a `set` and take different paths. A class is
whatever the code under test branches on, which means each gate has to name its
own, and a gate whose classes are chosen badly will pass while narrow.

## 5. The audit, completed

Measured across all 59 gate tools rather than reasoned about. A gate needs a
class condition only if its driver *samples instructions*; one that iterates
every fixture and samples operand values is complete over instructions by
construction, and asking it for a coverage guard would be asking it to prove
something it cannot fail.

| draws | gates | condition |
|---|---|---|
| instructions from a pool | `exec_fuzz`, `jit_c`, `jit_llvm`, `jit_stencil`, `migrate_vs_whole`, `packet_roundtrip`, `scalable_exec_check`, `sim_vs_executor`, `scalable_faulting`, `itinerary_vs_packet`, `fabric_vs_scalar`, `mapping_legality_check`, `fabric_topology_check` | all require a class |
| operand values, over every fixture | `exec_vs_golden`, `llvm_effects_check`, `llvm_patterns_check`, `saturating_check`, the five `*_vs_golden`, the three `exec_*_check`, `fclass_check`, `fflags_check`, `limb_check`, `blockmem_check`, the `scalable_*` value drivers | complete by construction |

Four gates were missing the condition and now have it: `scalable_exec_check`
(§3), `exec_fuzz`, `jit_c`, and `migrate_vs_whole` — the last drawing programs
from a pool and then migrating a checkpoint, so a run could report a green
capsule round-trip about state no instruction it ran ever wrote.

**A hole that was only visible from the other side, and what it hid.**
`exec_wide_check.py` skipped an instruction whose widths are all ≤ 32 as
"already covered by the compact check". That is true only of instructions the
compact check can *run*, and it cannot run one that touches architectural
state: its ABI has no state argument. So a narrow state-touching instruction —
RV32's `LR_W`/`SC_W` and their ordering variants, most of Zicsr — was executed
by neither compiled driver, and neither driver said so, because each was
skipping it in the belief the other had it. Reachability was the property
nobody was measuring: both drivers reported honest counts of what they ran.

Lifting the skip ran 28 more fixtures and found two real defects, in the code
under test rather than in the harness:

  * The wide C and Rust executors did not wrap a memory address at the width
    the address is evaluated at. Every operator masks its own result, so this
    was invisible for as long as every address was arithmetic; `lr.w` and
    `sc.w` address with a bare operand, and a 32-bit machine's address in a
    64-bit register slot reached memory with whatever the upper half held.
  * The golden model tested a `select`'s condition without masking it to the
    expression's width, while it masks the operands of every other
    width-sensitive operator. The congruent operators return their result
    unmasked, so an `or` whose low 32 bits are zero and whose upper half is
    not took the true branch in the model and the false one in C.

The second was reachable only after a third change. A store-conditional's
reservation check is three comparisons or-ed together, satisfied by random
state with probability 2⁻⁴¹: the store path of every `sc.w` in the corpus had
never been executed and could not have been. The wide driver now seeds each
state slot, on one trial, with the values the effects compare that slot
against — read off the expressions, so nothing in the driver knows what a
reservation is. That is this driver's version of the compact one's "trial 0
forces the source registers equal", and it is what makes a guarded store
reachable at all.

What remains stated rather than fixed: the wide driver evaluates a `setpc`
target at the ISA word while the executors and the golden model evaluate it at
the effect's own width. Every `setpc` in every corpus is arithmetic at the ISA
word, so the two coincide; a narrow ISA whose branch target is a bare register
would separate them. Related, the roundtrip fixtures do not publish
`word_bits`, so the driver defaults to 64 for a 32-bit corpus.

**The grep did not settle it.** Searching for a coverage vocabulary called
`packet_roundtrip`, `jit_stencil` and `sim_vs_executor` unguarded, and all
three had the condition under different names — slots and unit classes packed,
`hot`/`cold` halves, branch-taken and trap-raised. A guard is a fact about
control flow, not about wording, and this table was built by reading the nine
candidates rather than by matching on them.

One residual risk, stated rather than fixed: `saturating_check` carries its
oracle as two hardcoded tables, and covers all seven saturating instructions
the corpus offers today (four by value, three by the sticky flag). Nothing
tells it if the corpus gains an eighth. Detecting "this instruction saturates"
from a description means reading prose or pattern-matching semantics, and a
weak check there would be worse than the stated gap.

## 5a. The rung below the corpus: no instruction is dark

`corpus_coverage_check` asks whether any *corpus* is covered by nothing. One
rung below it is the same question about an *instruction*, and it had a
different answer.

Twenty-one of the ladder's tools build their cases from the roundtrip
fixtures — every execution driver among them. An instruction the encoder
cannot build a word for produces no fixture, so it is executed by none of
them, while its corpus goes on reporting as covered, because the corpus is.

The reasons were already computed and already written down. `emit-roundtrip-json`
carries a `skipped` list naming each instruction it could not encode and why:
a format field that is neither an operand nor pinned, or an operand that binds
to no field. Nothing read that list. In it were:

* **The four `fp_exceptions` witnesses.** That corpus exists to be the witness
  for what an operation raises, and `FSQRTX_D` — the one whose rationale says
  "the witness for invalid on a negative operand" — had never been executed,
  nor had the three conversions. Two of its six instructions ran.
* **`aarch64_fp_env`'s five FPCR/FPSR accessors,** whose rationale reads "a
  mode register is only a mode register if something can read it". Nothing read
  it.
* **Twelve RISC-V CSR-immediate forms,** six in each of `rv32i` and `rv64i`.
  Zicsr's immediate encodings put a five-bit unsigned operand where the register
  forms put `rs1`; an operand binds to the field its name matches, so `uimm`
  bound to nothing and `rs1` was left unbound. They now have a format of their
  own, which is what RISC-V's manual describes.
* **`effects_pure`'s `FMA`,** in the corpus `check_all` calls "the baseline the
  others are read against". A three-source instruction under a two-source
  format has nowhere to encode its third source; `R4` is the format that does.
* **RVV's `vsetvli`,** described against the vector format, so its scalar
  operands bound to none of `vd`/`vs1`/`vs2`.
* And the unused-field case in eleven other corpora — a square root under a
  two-source format, a mask generator that reads one register, a policy no-op.

Thirty-one instructions, plus the twelve CSR forms. All of them were fixed in
the *descriptions* rather than in the tools, and each fix makes the description
more faithful: a real ISA pins the bits its instructions do not use, and
`fsqrt.d`'s `rs2` field is zero in the manual as much as it is here.

The check is now a rule: every instruction whose lift entry carries semantics or
effects must have a fixture. The one exception is a scalable lane
instantiation, which renames its operands on purpose so that a lane shares one
encoding with its origin; those are counted (974) and checked by reading their
emitted effects instead. Removing a single `(encoding (rs2 0))` turns the gate
red, which is what makes this a rule rather than a report.

That rule has a hole in it, and the hole is the word *semantics*. It asks for a
fixture only from an instruction whose lift entry carries semantics or effects,
so an instruction that states none is exempt from it -- and there are eleven of
those in the AArch64 corpus alone, the pointer-authentication branches and
`BRK` among them. What an instruction computes may be undecided, deferred, or
genuinely unexpressible; **that it assembles and decodes is not negotiable
either way**, because a decoder that cannot read a word cannot read the program
containing it.

`emit-roundtrip-json` had been recording each unencodable instruction and its
reason all along, and `roundtrip_check` printed the list and passed. It is a
ceiling now: a corpus not named in `KNOWN_UNENCODABLE` must skip nothing, and a
named one may not skip more than it does today. AArch64's count is zero -- 917
instructions, 917 fixtures, all of them assembling and disassembling, and the
482 in an ISA with a reference assembler checked against `llvm-mc`. Giving
`BRK` one operand the encoding does not carry turns the gate red and names it.

The five nonzero entries are the scalable corpora, and they came to 267. That
is a gap in those descriptions rather than a property of scalable code, and the
ceiling exists so it cannot grow while nobody is looking -- and so that closing
it shows up as a number going down.

It has: 267 becomes 165, and the two causes turned out to want different
answers.

**A field no operand binds** was the mechanical half, and pinning it is what a
real ISA does with bits an instruction does not use. Nineteen instructions
across three corpora: RVV's mask and reduction forms leaving `vs1` loose, six
cross-lane reductions leaving `zm`, seven unit-stride loads leaving `rs2`. Each
is `(encoding (<field> 0))`, and each was already told apart from its siblings
by `func3` and `func7`, so pinning them to one value collides with nothing.

Worth saying what was *not* done here. RVV pins `vs1` to a different value per
mask instruction, because that field is a sub-opcode on real hardware --
`vmsbf.m` is 1, `vmsof.m` is 2. Copying those numbers would have been the
obvious move and the wrong one: `reference_isa_check` deliberately excludes
`rvv` and `sve` because their encodings are illustrative rather than
architectural, and half-matching an architecture is worse than plainly not
matching it. The pin is 0 because the question here is whether the instruction
round-trips, not whether it is RISC-V.

**An operand with no field** is the other half, and it is a format question
rather than an encoding one. `scalable_basic`'s tail-aware instructions print
`$vl` in their assembly and had nowhere to put it: every one of `SVE_R`'s 32
bits was spoken for. `SVE_R_VL` is the same shape with a five-bit `vl` and a
two-bit `func7`, which fits exactly and is enough because `func3` already tells
the three apart. That corpus goes from 36 skipped to 4, and RVV's scalable
execution gate from 136 comparisons to 152 -- which is the point: these
instructions were executed by nothing at all.

`scalable_predicate` went next, and it is now **zero**: every instruction in it
encodes, so it is out of the ceiling entirely rather than held at a number.
Nine instructions, three shapes. Seven name four registers -- destination,
governing predicate, two sources -- where `SVE_P` has fields for three, and
`SVE_PG` fits all four exactly, `func3` again separating the seven so two bits
of `func7` suffice. The other two, `SVAND_P_S` and `SVWHILELT_S`, call their
sources `pa`/`pb` and `base`/`count`: an operand binds to the field whose name
it matches, so those bound to nothing even though `SVE_P` has fields in exactly
those bit positions. `SVE_PP` and `SVE_WHILE` are the same bits under the names
the instructions use, so their encodings do not move at all.

**What that bought, stated precisely.** The floor -- every instruction
assembles and decodes whatever it says about semantics -- now holds for the
whole corpus, which is the rule this section is about. It bought no execution
coverage, and it is worth being exact about why: no gate registered for
`scalable_predicate` drives from roundtrip fixtures. Its five gates compare
values against the golden model or check predication and definedness directly
from the instruction table, and all five were already complete. The RVV fix
above did add coverage, 136 comparisons becoming 152, because `scalable_exec_check`
does drive from fixtures -- and that gate refuses this corpus for an unrelated
reason, having no vector load or store to run.

The remaining corpora went the same way and are all **zero** now, `rvv` last,
so the ceiling is empty: every instruction in every corpus encodes. Three shapes recurred:

* **A source under a different name.** A store's source sits exactly where a
  load's destination does, a slide's background where `zm` does, a broadcast's
  scalar likewise. The bits never moved; what was missing was a format calling
  them what the instruction calls them. `SVE_MS`, `SVE_XB`, `SVE_R_DUP`,
  `SVE_PP` and `SVE_WHILE` are all that, and none of their encodings changed.
* **One more register than the format holds.** `SVE_PG` and `SVE_XC` add a
  fifth field by spending five bits of `func7`, which works because `func3`
  already separates their users.
* **Registers the word does not name at all.** A segment load writes two, three
  or four *consecutive* registers and the instruction names only the first --
  which is what its assembly prints. `(derive zd0 n)` says so, the same
  mechanism `CASP` uses for a register pair, and `VLD4_S` with `zd0 = 1`
  decodes to 1, 2, 3, 4. Inventing four destination fields would not have fit
  anyway: four registers, a base and an opcode want 35 bits of 32.

**Encoding an operand creates an obligation to print it,** which the asm gate
said plainly: twelve failures reading `operand zb never appears in
"vslidedown2_s $zd, $zn"`. Text that omits an encoded operand cannot be
assembled back into the word it came from. `scalable_predicate` escaped the
same fate only because its templates end in `...`, which is the author saying
the rest are deliberately unspelled. RVV paid it too, for `v0` and `vl`.

One collision, and validation found it rather than a gate: `func7` shrinks to
two bits when a format spends five on a fourth register, and the two bits left
must not collide with any seven-bit `func7` already in the corpus. `01` looked
free and is not -- `VRGATHER_VV` is 62, whose top two bits are `01`. Only `11`
was unused. That is a fact about the corpus rather than about the design, and
the decode-disjointness rule stated it precisely enough to fix in one step.

### Defined, or named as not defined

SMT is where this invariant matters most, because something rests on it: the
ISE miner proves a candidate extension equal to the instructions it replaces by
composing their `define-fun`s and asking z3. An instruction silently absent
from the file is one the miner cannot compose, and the shape of that failure is
a proof about less than it appears to be about.

576 of AArch64's 917 instructions were absent with nothing written about them.
Almost all for a good reason -- a `define-fun` answers *what does this compute
from its operands*, and 565 of them write memory or architectural state, so
they are not that function. That is a boundary, not a gap. But an absence
cannot say which it is, and a reader looking for `axis_instr_str_x_unsigned`
could not tell an instruction that is not a value from one that had been
dropped. The emitter had always named an instruction whose lowering it
*attempted* and failed; one with nothing to attempt got nothing.

Every instruction is now defined or named -- 269 defined and 648 named on
AArch64, 196 and 142 on RV64I -- and `smt_accounted` keeps it so.

**What the reason should say was decided by an existing gate, not by me.** The
first attempt wrote a blanket "a behavior, not a value" for all 565, and
`capability_check` failed it: the capability manifest already records *why* each
instruction has no definition -- `behavior writes memory or architectural
state`, `behavior is guarded`, `behavior writes only architectural state` --
and its rule is that the manifest and the artifact must give **one** predicate,
not two. The specific reason had been computed all along; writing a vaguer one
beside it was a second answer to a question that already had one.

So the predicate lives in `pure_value_semantics`, the single place both read,
and the three silences this session introduced -- declared unsupplied,
performed by a routine, nothing said -- were taught there rather than in the
emitter. Both artifacts say the more precise thing at once because there is
only one thing to say.

That doubled what the join can check: **897 instructions cross-checked becomes
1710**. An instruction appearing in neither file could not be compared at all,
so nearly half of what the manifest claims to cover was outside it.

### Lowered, or named as not lowered

`emit-llvm-ir` emits `axis_eval_*` for a pure value and `axis_eff_*` for a
behavior, and writes a comment naming anything it withheld. That is the right
shape and nothing checked it held. An instruction could leave the file with no
function *and* no comment, and the only sign would be a number in a report
nobody recomputes.

Asked directly, 26 instructions across nine corpora were doing exactly that --
the eleven AArch64 forms declared `unsupplied`, the two performed by routines,
and others with nothing said about them at all. The effect path returned early
when there was no behavior and said nothing, and the pure path's note is no
help: "no formal_semantics declared" is what it says about every *effectful*
instruction, so it cannot distinguish one the effect path had also dropped.
That is why `llvm_accounted_check` refuses to count that note as a reason.

The effect path names them now, and which of the three silences it is: a
routine performs it, it is declared unsupplied, or nothing has been said yet.
The same three the lifter distinguishes, for the same reason -- they are
different facts and a reader deserves to know which.

Two things the check got wrong before it was right, both worth recording
because both would have made it *pass while measuring less*. A scalable
instruction is emitted once per lane, so `add_m_b` is lowered when
`add_m_b__l0` is -- counting only exact names reported 76 SVE instructions
missing that were lowered all along. And the emitted symbol is the mnemonic as
an *identifier*, so `ADD-AND-FLAGS` appears as `add_and_flags`; comparing raw
names reported six more. 1921 instructions over 56 corpora are accounted for
now, and suppressing the naming turns the gate red.

### A gate that cannot run is not coverage

`RV64I Rust exec` skipped every run of the ladder, reporting **"no executable
fixtures"**. RV64I has 1028 fixtures. The real cause is that the compact Rust
driver's ABI is 32 bits and every RV64I instruction is wider, so the width
filter discarded all of them -- a gate that could never have run, reporting a
reason that sent a reader looking for missing fixtures instead of the gate that
should have been registered.

Two fixes, because the skip and the hole are different problems. The skip names
the width now, counts the instructions it discarded, and points at the driver
that can run them. And `exec_wide_check --lang rust` is registered for RV64I,
where it executes **424 instructions** against the golden model with no
failures -- a corpus whose Rust executor had been checked by nothing at all.
The compact registration is gone rather than left skipping: a gate that cannot
run is not coverage, and keeping it would mean keeping a green line that stands
for nothing.

Asking the general form of the question -- which corpora have a C execution
gate and no Rust one -- found two more, `icmp_ops` and `policy_icount`, both of
which run clean and are registered. The third, `fp_exceptions`, is deliberately
left out: Rust declines all twelve of its instructions, and a gate that
executes nothing asserts nothing.

### An artifact should say what it cannot do

The Rust executor performed 796 AArch64 instructions where the C one performed
807, and the eleven missing were the double-precision forms that read their
rounding mode from `fpcr`. That difference is legitimate and documented:
`docs/simd_fp_design.md` section 8.4 says Rust's `f64` rounds to nearest-even
and `std` exposes no `fesetround`, so the C twin emits them and this one cannot.

The difference being legitimate is not the point. The point is that the emitted
file did not *say so* -- it simply lacked the functions, so a reader could not
tell an instruction Rust has no way to perform from a file that had been
truncated, and the gap appeared only as a decline line in another gate's output,
which is not in the artifact at all. `emit-llvm-ir` has always written its
refusals into the file it emits, naming the instruction and the reason.

The Rust executor does that now, and `executor_parity` holds it there: every
instruction the C executor performs and the Rust one does not must be named,
with a reason, in the Rust file. It also fails the other two ways the claim can
rot -- an instruction only *Rust* performs, which no language difference
explains, and a reason left standing for an instruction that is now emitted.
Over 56 corpora the only difference is those eleven, all one reason.

### Asking every corpus, not a chosen few

Emptying the ceiling raised the obvious next question: the roundtrip gates name
corpora one at a time, so they say a great deal about the ones they name and
nothing at all about the rest. Asked of *every* corpus, two failed outright --
`lisp_modes_cores` and `vliw_packet`, neither watched by any gate.

Both were the same thing, and it was not a bug in either description. The
decode-disjointness rule permits two instructions to share an encoding when
their **modes** are disjoint, or when their **units** sit in disjoint packet
slots; `SCALAR_ADD` and `TENSOR_MUL` share one under different modes, `VSTW`
and `VBRZ` under different units. A decoder handed only a word cannot tell such
a pair apart, and it returns nothing rather than guessing -- which is right,
and which the roundtrip fixture was reading as a failure. The fixture was
asking an unanswerable question.

So the question got the missing argument. `axis_decode_in_isa` had answered the
ISA-shaped version all along, and now has twins: entries carry their modes and
their unit, `axis_decode_in(word, isa, mode, unit)` skips the ones ruled out,
and the fixtures say which mode and unit their word is read in. A caller naming
none of the three gets exactly what it got before. `axis_lift_in_mode` is the
same addition on the lifter's own decoder.

`roundtrip: every corpus` is a gate now, so the next corpus that cannot decode
itself turns something red rather than waiting to be found by hand.

**What it bought, measured rather than assumed.** RVV's two fixes added
execution coverage -- `scalable_exec_check` drives from fixtures and went from
136 comparisons to 152 and then to 172. The four SVE corpora added none, and
the reason is worth recording: no gate registered for them drives from
fixtures. Their gates
compare values against the golden model, or check predication, definedness,
addressing and fault suppression straight from the instruction table, and every
one was already complete. What those four gained is the floor -- every
instruction assembles and decodes -- which is the rule this section is about,
and not coverage.

What it moved, on the corpora with execution gates:

| corpus | executed before | after |
|---|---|---|
| `fp_exceptions` (wide C) | 4 | 12 |
| `aarch64_fp_env` (wide C) | 8 | 18 |
| `masks` (wide C) | 2 | 10 |
| `rv32i` (wide C) | 312 | 324 |
| `rv64i` (wide C) | 624 | 636 |
| `effects_pure` (compact C) | 1 | 3 |

Zero failures among them, which is the outcome to expect from descriptions that
were right and unreachable — and the reason to say so plainly, since the same
work last time found two defects. One side effect: `vsetvli` became encodable,
and an encodable instruction gets a pattern, so the LLVM backend gained its
565th (`docs/llvm_backend.md`).

## 5b. The same question one rung over, with a different answer

Execution had a hole; the value side does not, and that is worth writing down
rather than assuming either way.

The question is whether any *definition* is proven by nothing. Twenty-one
corpora are named by no value-backend gate at all — the `lisp_*` frontend
fixtures, the personality and policy examples, `vliw_packet`, `regslice`,
`limbs`. Measured instead of reasoned about: 40 corpora carry a formal
definition, and 41 appear in `smt_vs_golden`'s sweep, which names no file and
proves every definition it finds against the golden model. The set with
definitions is contained in the set the sweep checks, so nothing is unproven.
The 41st is `fp_exceptions`, whose instructions carry no `formal_semantics` at
all: their *behaviors* yield a value function — one register write beside a
state clobber — and the SMT emitter takes it.

That measurement also corrected a report. `corpus_coverage_check` ended its
list of unnamed corpora with "this floor is all that covers them", which was
false for both it named: the sweep proves `policy_admission`'s three
definitions and `policy_icount`'s two, over a hundred cases each. The line now
reads the count out of the corpus's own emitted semantics and says which of the
two things is true. A report that overstates a gap is how a report gets
ignored, which is the failure this whole file exists to prevent.

## 5c. The pair nobody wrote down

`corpus_coverage_check` asks whether a corpus is covered by nothing, and
`check_all` runs the pairs somebody wrote down. Neither asks the other
question: of the (driver, corpus) pairs nobody wrote down, which ones work --
and which ones fail?

It is worth asking because the answer had been a defect three times in one
session, most clearly this one: `examples/simd_lanes.axisl` was failing
`exec_wide_check` **on a green tree**. The gate existed, the corpus existed,
and no line in the matrix put them together, so the wide executor's arithmetic
shift of a 16-bit lane stayed unsigned. Nothing was broken in the ladder; the
ladder simply did not contain that pair.

So the matrix was run: 15 corpus-parameterised drivers against all 55 corpora,
825 pairs, thirteen minutes on an idle machine. `tools/gate_matrix.py` is that
run, kept, and it sorts a pair three ways. The last full run: 167 pairs named by
a gate, 186 with nothing to do, 21 excluded by shape, 451 passing and named by
no gate, and none unexpected.

**Unexpected failures**, which is the output that matters. The run that
introduced this tool reported five, all of a kind the run itself made visible:
three were the identifier bug below, and two were `fp_rounding` against Rust
and LLVM, which decline directed rounding by design and are now named as an
exclusion with the document that argues it. No defect in the emitted artifacts
survived -- the three this session found were already fixed by then, which is
what makes the empty list worth printing rather than assuming.

**Excluded by shape**, which is every remaining failure. Four rules cover all
of them, and each names the driver that *is* built for the shape:

| shape | fails in | belongs to |
|---|---|---|
| a scalable lane or reduction | `exec_vs_golden`, `llvm_effects_check` | `scalable_exec_check.py` -- a lane writes one element of a `VL`-sized register |
| two instructions sharing an encoding in disjoint modes | the three roundtrip drivers | `decode_table_check.py`, `legality_vs_golden.py` -- which know modes |
| a syllable decoded in its slot | the roundtrip drivers, `exec_wide_check` | `packet_roundtrip.py` |
| every case in LLVM-undefined territory | `llvm_patterns_check` on `shift_widths` | nothing: the gate's own vacuity guard firing, correctly |
| an operator a backend declines by design | `rust_vs_golden`, `llvm_vs_golden` on `fp_rounding` | nothing: neither can set a rounding mode, argued in `simd_fp_design.md` §8.4 |

**Available**, meaning it passes and no gate names it. Not a defect -- most add
nothing a gated pair does not already prove -- but it is the list a new gate
comes from when a corpus grows a shape its drivers do not have.

Three things the sweep corrected on its way through:

* **One definition was proven by nothing on three backends.** The value drivers
  looked up `axis_eval_` plus the mnemonic lowercased, where the emitters build
  an identifier -- lowercase alphanumerics, everything else an underscore. Every
  mnemonic in the corpus is already an identifier except one,
  `CONSTRAINED-EXTEND`, so `c_vs_golden`, `rust_vs_golden` and `llvm_vs_golden`
  each looked for a name no backend emits, printed "no C function emitted", and
  skipped it. The function was in the header the whole time under its sanitised
  name. The drivers derive the identifier the same way the emitters do now.


* **`c_vs_golden`, `rust_vs_golden` and `llvm_vs_golden` failed where they
  should skip.** A description with no pure value semantics -- one whose
  instructions are all behaviors -- gave "no comparable functions found" and a
  non-zero exit, which is 17 corpora each reported as broken. `check_all`'s own
  contract is that a gate exits zero for a clean skip. They skip now, and a
  description that *has* specs and got no function out of the backend still
  fails, with the count of what was missed: nothing to compare and nothing
  comparing are different findings.
* **Believe a failure only when it is alone.** The first sweep ran eight
  drivers at once and produced 102 failures, half of which were the machine
  rather than the code -- these drivers compile C and Rust. The tool sweeps in
  parallel and then re-runs each failure by itself before reporting it, which
  keeps the speed and drops the noise. It also bounds each pair's wait: the
  report prints at the end, so a driver that never returns looks exactly like
  slow progress, and the first version of this tool spent fifty minutes proving
  that on a loaded laptop.

## 5d. A guard that fires on the dice, not on the defect

Describing the C extension added nineteen instructions to RV64I and broke
`sim_vs_executor` -- not its comparison, which reported zero failures, but its
two vacuity guards, which reported that no program in the run had branched and
none had trapped. Both were right, and neither was about RVC. The driver drew
its programs uniformly from the corpus and hoped a branch turned up. With 318
instructions and twelve of them branches, eight programs of ten words found one
often enough that nobody looked; with 337 it did not. The guard had been
carrying the run for some time.

So the draw plants what the guards ask for instead of hoping for it: a branch
in the odd programs, a trap in the even ones. The trap needed one more turn of
the same screw. Twenty RV64I instructions raise a trap and eighteen are the
dynamic-rounding FP forms, which raise only when the rounding mode says so, so
a uniform draw from *those* reaches `ebreak` about one time in ten -- the same
bug one level down. The plant now groups the trapping instructions by the cause
each one raises and takes the causes in turn, because the guard is written per
cause. It goes in the program's last slot, so a run that traps still executes
its whole body first rather than testing the hook and nothing after it.

Worth stating plainly, since it is the fifth time this shape has turned up here:
the guards did their job both times. A vacuity guard that fails on an unlucky
draw is annoying; the alternative -- no guard -- is a driver that reports zero
failures over a corpus it never reached into. The fix is never to loosen the
guard. It is to stop leaving the coverage to chance.

## 5e. Three conventions the JIT knew better than the table

Describing the Q-register loads and stores added eight instructions to the
effect surface, which changed which blocks the JIT's random pool drew, which
turned up three divergences that had nothing to do with 128-bit values. All
three were the same mistake: the block builder spelled out an AArch64
convention where the register class table already stated it, and the two
agreed for every class anyone had drawn.

* **A hardwired zero was "index 31 of anything but `reg`".** That is XZR and
  WZR exactly, for AArch64. The accelerator's own `reg32` also numbers 31 and
  hardwires nothing, so a block reading `reg32[31]` compiled a constant zero
  while the executor read the register. It asks `zero_index` now.

* **The stack pointer was living in a register-file slot.** `sp` is not a
  numbered register: the class table turns encoding 31 of the `sp` classes into
  an alias onto named state, and file slot 31 belongs to whichever class
  actually numbers 31 -- here the accelerator's `reg`. Both in slot 31 made
  `reg[31]` and `sp` the same storage in the JIT and different storage in the
  reference. The block now carries one slot past the file and the alias lands
  there.

* **A narrow write did not clear the rest of its register.** Writing `d1`
  zeroes the upper half of `v1`, a whole slot away; the executor has always
  applied the class's write policy and the JIT stored its one slot. The pure
  path's reference had the same hole, in its own commit convention.

The seed is the thing to notice. The gate's default seed passed before and
after; seeds 2, 3 and 4 failed on the code as it stood, and all five pass now.
None of these were found by looking -- they were found because a corpus grew
and moved the dice. That is the fourth and fifth and sixth time in this
document, and the lesson is the one already written above: a driver that
samples should say what it sampled, and a convention that a table states should
be read from the table rather than restated.

## 6. What this is not

Not a coverage *metric*. Line or branch coverage of the generated artifacts
would be a different and much larger project, and would not answer this
question: a gate can execute every line of a handler and still never run a
store. The question here is which *instruction classes* a differential run
actually compared, which is a property of the driver's sampling and nothing
else.

## The hardware was held to nothing

Every way of EXECUTING a description is compared against the golden model: the
C, Rust and Python executors, the LLVM IR, the SMT definitions, the
copy-and-patch JIT, and the symbolic machine. `emit-pyrtl` emitted two hundred
and fifty-eight functions and was compared against nothing at all.

⚠️ That asymmetry is the one that matters for co-design. A stack can say *six
ways of running this agree* and still not say *the hardware does what the
software says* — and every number a co-design study derives from generated RTL
rests on the second claim, not the first.

`tools/pyrtl_vs_golden.py` closes it with the shape the software backends
already use: build each instruction's netlist out of PyRTL `Input`s, simulate
it on the golden model's own deterministic vectors, require the wire to carry
the number the model computes.

**It found seventeen wrong circuits on its first run.** `_bits(value, width)`
truncated a wide wire and *left a narrow one alone* — so a twelve-bit immediate
asked for at sixty-four came back twelve bits wide, and every shift of it
dropped what it was supposed to move. AArch64's `add xd, xn, #imm, lsl #12`
built a circuit that returns `xn`. The software backends were all correct; only
the hardware was wrong, which is exactly what a missing gate looks like.

⚠️ Each instruction builds in its own `temp_working_block`. PyRTL keeps a global
block, so building every instruction into one makes each circuit slower than the
last — and a name collision between two instructions' inputs would be a wire
silently shared between them.

⚠️ A circuit that will not build is named with its reason and counted apart from
one that is wrong. "This description has an operator no circuit was written for"
— `mulh`, `fmul` — is a different fact from "the circuit disagrees", and a gate
that folded them together would report a stack building less hardware every
release as one that still passes. A run that builds nothing SKIPs rather than
passing on an empty comparison.
