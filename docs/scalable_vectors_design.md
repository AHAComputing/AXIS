# AXIS Scalable Vectors — SVE and RVV, whole-ISA

Status: **7 stages implemented** (S1-S7), complete. The execution side is
`docs/scalable_execution.md`; the corpora are
`examples/sve.axisl` and `examples/rvv.axisl`. `sve.axisl` has since become
Arm's own SVE, held to Arm's definition (§10, V1).

This header read "designed, not built" for as long as all seven stages had been
built and gated -- a redesign document whose status was never turned over when
the redesign landed. The count now comes from the staging list below rather than
from this line (`tools/doc_facts_check.py`).

It then carried "with dynamic permutes outstanding inside S6" for as long as
S6's own entry explained that they were not: `vrgather` was built and
`TBL_Z_B` closed the other architecture's side. The *count* was checked and the
*caveat* beside it was not, which is the same failure one clause over -- a
number a tool recomputes next to a sentence nobody does. A caveat is a claim
too, and this one is now gone rather than qualified.

This is a redesign. The first version carved out four exclusions — RVV's
agnostic policies, `LMUL` > 1, fault-suppressing and first-fault loads, and
gather/scatter — and each of them removed real instructions from reach. The
brief here is whole-ISA coverage, so this version replaces every exclusion with
a mechanism.

Reviewing them honestly, they were not equally hard. One was a genuine
impossibility argument that turns out to be wrong in an interesting way; two
need real new machinery; one I simply over-excluded. That asymmetry organises
what follows.

Syntax is Lisp-only. The legacy block frontend has been removed.

## 1. Why scalable vectors are a new value domain

`docs/simd_fp_design.md` justifies stages V1–V3 with one claim: SIMD is **not** a
new value domain. A lane-wise add on a 64-bit register holding two 32-bit lanes
is two masked adds on bit-vector slices, so vectors are *expanded away* at
elaboration and every backend keeps working untouched.

That claim does not survive scalability — you cannot unroll an unknown number of
lanes. Scalable vectors are the first AXIS feature that must reach the backends
*as vectors*. The earlier decision was not wrong; it was right for fixed lanes,
and this is a different problem wearing similar clothes.

## 2. What "whole ISA" actually contains

Before designing, the inventory — because the mechanisms have to be chosen
against it, not against the easy half.

**SVE.** Element-wise integer/FP arithmetic; predicate generation (`PTRUE`,
`WHILELT` family, compares); predicate-domain logic and the break family
(`BRKA`/`BRKB`/`PFIRST`/`PNEXT`); `PTEST` writing NZCV; reductions (`ADDV`,
`SMAXV`, `FADDV` pairwise, `FADDA` strictly-ordered); permutes (`TBL`, `EXT`,
`ZIP`/`UZP`/`TRN`, `SPLICE`, `COMPACT`, `LASTA`/`LASTB`, `DUP`/`SEL`); loads and
stores in unit, scalar+scalar, scalar+vector (gather), broadcast (`LD1R`),
non-fault (`LDNF1`), first-fault (`LDFF1`) and structured (`LD2`/`LD3`/`LD4`)
forms; `MOVPRFX`, a prefix that makes a destructive operation non-destructive.

**RVV.** Configuration (`vsetvli`/`vsetivli`/`vsetvl`) writing `vl` and `vtype`;
element-wise arithmetic including **widening and narrowing** forms whose
destination element width differs from the source; fixed-point saturating and
averaging operations with the `vxsat` sticky flag and `vxrm` rounding mode; mask
operations (`vmand`, `vcpop`, `vfirst`, `vmsbf`/`vmsif`/`vmsof`, `viota`,
`vid`); permutes (`vslideup`/`vslidedown`, `vrgather`, `vcompress`, `vmv.x.s`);
the full FP set with ordered and **unordered** reductions; loads and stores in
unit, strided, indexed-ordered, indexed-unordered, segment (`nf` up to 8),
fault-only-first and whole-register forms; and `vstart`, which lets a trapped
vector instruction resume mid-way.

Two things in that list are the reason the first design excluded so much: RVV
puts *type information* in a dynamic CSR, and both architectures deliberately
leave some results **architecturally unspecified**.

## 3. Five mechanisms

### M1. Definedness is itself a proven value

*Covers: RVV tail/mask-agnostic policies, unordered indexed stores, and any
RES0/UNKNOWN or CONSTRAINED UNPREDICTABLE field.*

⚠️ This list said "unordered FP reductions" for as long as it existed, and they
were never covered. A definedness mask says which **lanes** are unspecified; an
unordered reduction produces one fully defined value drawn from a set of
admissible ones, and there is no lane to mark. `src/scalable.rs` was right to
exclude them and this sentence was wrong to claim them — whole-value
indeterminacy is a different mechanism, and it is the order knob of
`docs/tensor_design.md` T2, which has since landed: `ReductionOrder` beside
`Realization`, swept the same way. The failure worth naming is not the
oversight but its shape, which is the one this document records twice already
in its own header: a claim stated beside a mechanism, where the mechanism was
checked and the claim about its reach was not.

The first design argued: an agnostic tail leaves elements architecturally
unspecified; a bit-exact differential ladder cannot prove an unspecified value,
because every backend would be free to differ and all of them would be right;
therefore model undisturbed and state the limit.

The first two steps are correct and the conclusion does not follow. What the
ladder cannot compare is the *contents* of an undefined lane. It can compare
**which lanes are undefined** — and that is the part the architecture actually
specifies.

So a vector result is a pair: a value and a **definedness mask**. Every backend
computes both. The gate asserts

```
defined_lhs == defined_rhs          # exact agreement, no masking
(value_lhs ^ value_rhs) & defined_lhs == 0
```

The first line is what keeps this from becoming a hole. A backend cannot
unilaterally widen its undefined region to make a disagreement vanish, because
the region itself is compared exactly. Marking an extra lane undefined is
immediately a gate failure, not a free pass.

Executors still need concrete bits, so a document declares how undefined lanes
are realised — and then the gate runs the ladder **once per realisation**:

```lisp
(unspecified-realization compute | ones | zeros)
```

Requiring defined-lane agreement under all of them proves something stronger
than picking one: that no consumer downstream depends on the undefined bits. A
description that quietly relies on "agnostic means all-ones on my machine" fails
the `undisturbed` run.

This inverts the original conclusion. Modelling unspecified behaviour honestly
turns out to yield a *stronger* gate than pretending it is specified, and the
mechanism is the same one an ISA spec already uses.

### M2. Parametric modes, so `LMUL` is static

*Covers: `LMUL` including fractional, `SEW`, `vta`/`vma`, `vxrm`.*

The obstruction is real: with `LMUL` = 4, operand `vs1` names registers
`v8..v11`, and *which registers an operand names* depends on a runtime CSR. The
lift table's operand fields are static, so a dynamic operand-to-register mapping
is not expressible.

But `vtype` is only dynamic between `vsetvli`s. Within a region it is constant,
which is exactly the shape of a **mode**: the same encoding meaning different
things depending on machine state. AXIS has modes, a mode-legality gate, and a
`mode_polymorphic` corpus.

The existing construct is too narrow to reuse as-is, and it is worth being
precise about the gap rather than claiming a free ride. Today `Mode` is a single
WARL-encoded CSR field, at most one block per document, whose values gate decode
*legality*; instructions list the modes they are legal in. `vtype` needs four
parameters, and they must reshape types and operands rather than merely permit
them. So `Mode` generalises:

```lisp
(defmode vtype
  (csr 0xc21)
  (params
    (sew  (field 5 3) (values 8 16 32 64))
    (lmul (field 2 0) (values 1/8 1/4 1/2 1 2 4 8))
    (vta  (field 6 6) (values undisturbed agnostic))
    (vma  (field 7 7) (values undisturbed agnostic)))
  (legal (<= (/ sew lmul) ELEN))
  (default (sew 32) (lmul 1) (vta undisturbed) (vma undisturbed)))
```

Two changes to the construct: several mode blocks per document, and mode values
that **bind parameters** consumed by type atoms and operand declarations instead
of only gating legality. The legality predicate is new too, and it earns its
place — `SEW/LMUL <= ELEN` is what makes most of the cross product illegal, and
without it the instantiation count is fiction.

A register-group operand then resolves statically:

```lisp
(vs1 rvv_v vt in (group lmul))
```

At elaboration with `LMUL` = k this names k consecutive registers and widens the
operand's shape by k. Fractional `LMUL` narrows it. Nothing dynamic survives.

`vl` stays **state**, not a mode. That split matches the hardware and keeps each
mechanism small: `vtype` changes *shapes*, `vl` changes *extent*. Shapes must be
static; extent need not be.

### M3. Shapes are rational, and per-operand

*Covers: fractional `LMUL`, widening/narrowing arithmetic, mask shapes.*

`Shape::Scalable { elem }` is not enough for two reasons discovered in the
inventory. Fractional `LMUL` means a vector occupies *part* of a register, and
widening operations (`vwadd`, `vnsrl`) have a destination element width that
differs from their sources.

```rust
enum Shape {
    Scalar(u32),
    Fixed    { lanes: u32, elem: u32 },
    Scalable { elem: u32, num: u32, den: u32 },   // lanes = VL*num / (den*elem)
}
```

and an operator's result shape is allowed to differ from its operand shapes.
There is precedent: `Ext { op, width, from_bits, arg }` already carries a
from/to pair, because sign extension always had this property. Widening
arithmetic is the same idea one level up.

`Fixed` stays exactly as it is and keeps being expanded at elaboration, so
nothing already proven changes.

### M4. One vector memory effect, with an address function and a predicate

*Covers: unit, strided, gather/scatter, segment, broadcast — and fault
suppression, by construction.*

This is the exclusion I got wrong. "Gather/scatter needs a vector in the address
position" made it sound like a new mechanism, but a unit-stride scalable load
*already* touches an unknown number of addresses. Once a memory effect is
lane-indexed at all, indexed addressing is a different address **function** and
nothing more:

```lisp
(set vd (vload vt pg (unit base)))
(set vd (vload vt pg (strided base step)))
(set vd (vload vt pg (indexed base vidx)))          ; gather
(vstore pg (indexed base vidx) vs vt)               ; scatter
(set (vd0 vd1 vd2) (vload-segment vt 3 pg (unit base)))
```

Lane `i` addresses `base + i*(elem/8)`, `base + i*step`, or `base + vidx[i]`.

Segment loads want up to 8 destinations and `EFFECT_MAX_WRITES` is 4 — a
constant already published in the lift artifact and read by every consumer, so
raising it to 8 is a parameter change, not a redesign. `EFFECT_OUT_SLOTS` grows
with it.

Fault suppression falls out of the *shape* of these forms. The predicate is an
**argument to the effect**, not a wrapper around it, so an inactive lane is
never addressed. This is why predication is deliberately not uniform across the
language: for arithmetic, masking as a lane-wise select is right and composable;
for memory it is wrong, because a select computes every lane and discards some,
and computing a lane can fault. One concept, two correct realisations — worth
stating explicitly so the asymmetry reads as a decision rather than an oversight.

### M5. Memory gains an accessibility boundary

*Covers: first-fault (`LDFF1`, `vle*ff`), non-fault (`LDNF1`).*

A first-fault load performs lane 0 normally, and for later lanes stops at the
first that would fault, recording where. That is data-dependent on the memory
map, and AXIS's memory model is a flat `i8*` with no notion of a fault
boundary — so this genuinely cannot be described today.

The smallest extension that makes it both describable *and testable* is an
accessible range in the effect ABI (`mem_lo`, `mem_hi`), with a predicate
`(accessible? addr n)` every backend evaluates identically:

```lisp
(set (vd vl) (vload-ff vt pg (unit base)))     ; RVV: truncates vl
(set (zd ffr) (vload-ff vni32 pg (unit base))) ; SVE: writes FFR
```

The gate is direct and non-tautological: place a hole in memory, and every
backend must stop at the same lane. A description that ignores the boundary
fails immediately.

The limit is worth naming — this models one contiguous accessible region, not a
page table. That is enough to prove lane-stopping behaviour, which is the
architectural content of first-fault, and not enough to model address
translation, which is not.

## 4. Surface syntax

### 4.1 Two spellings, one shape

The two architectures put element width in different places, and the syntax
should follow rather than force one into the other's frame.

SVE encodes it in the instruction, so the atom carries it — `v<lanes>i<elem>`
with the lane count as literal `n`:

```lisp
(add vni32 zn zm)          ; n lanes of i32
(fadd vnf64 zn zm)
```

RVV takes it from `vtype`, so the atom refers to the mode:

```lisp
(add vt vs1 vs2)             ; element = SEW, scale = LMUL
(vwadd vt2 vt vs1 vs2)       ; widening: destination is 2*SEW, 2*LMUL
(vnsrl vthalf vt vs1 vs2)    ; narrowing
(icmp_slt vm vt vs1 vs2)     ; result is a mask: VL lanes of i1
```

Both denote `Shape::Scalable`. One IR shape, two surface spellings, each
matching how its architecture actually talks.

### 4.2 Predicates are produced, not declared

A predicate is `vni1` (SVE) or `vm` (RVV). The existing rule — a comparison
carries the operator's width — generalises to: a comparison carries the
operator's *shape* with element width 1.

```lisp
(icmp_slt vni32 zn zm)            ; result is vni1
(vwhilelt vni1 i64 idx count)     ; SVE WHILELT / the RVV vl mask
```

### 4.3 Predication for arithmetic is a composable select

```lisp
(vmerge vni32 pg (add vni32 zn zm) zd)                 ; SVE /M
(vmerge vni32 pg (add vni32 zn zm) (vdup vni32 0))     ; SVE /Z, composed
(vundef vni32 pg (add vni32 zn zm))                    ; inactive lanes undefined (M1)
```

A mask argument on every operator would put the same concept in fifty places;
`vmerge` and `vundef` are the only two forms needed, and zeroing composes.

### 4.4 RVV's policy is architectural, so it is one form

Every RVV vector instruction applies the same rule to its result: lanes below
`vstart` are untouched, lanes at or above `vl` follow `vta`, masked-off lanes
follow `vma`. That is a property of the architecture, not of `vadd`, so it
should be written once rather than open-coded per instruction:

```lisp
(behavior (set vd (vpolicy vt (add vt vs1 vs2) vd)))
```

`vpolicy` reads `vstart`, `vl`, `v0`, `vta` and `vma` from state and mode, and
produces the value together with its definedness mask. `vstart` support is why
trapped-and-resumed vector instructions work rather than needing their own
mechanism.

## 5. Operator vocabulary

The mechanisms above are the architecture; the rest is vocabulary, and it is
listed here so the scope is not understated:

* **Cross-lane**: `vred*` (ordered, pairwise and unordered — the last two
  landed as `docs/tensor_design.md` T2), `vperm`/`vrgather`,
  `vslideup`/`vslidedown`, `vcompress`, `viota`, `vid`, `vcpop`, `vfirst`.
  Structured permutes (`ZIP`/`UZP`/`TRN`/`EXT`) are lane-index functions and
  expand once VL is instantiated.
* **Predicate domain**: logic, `BRKA`/`BRKB`/`PFIRST`/`PNEXT`,
  `vmsbf`/`vmsif`/`vmsof`, and `PTEST` reducing a predicate to NZCV.
* **Fixed-point**: saturating and averaging arithmetic, with `vxsat` as sticky
  state and `vxrm` as a mode parameter.
* **`MOVPRFX`**: an instruction-pair fusion. AXIS already fuses pairs — the
  LLVM backend fuses RMW pairs into `atomicrmw` — so this is a lowering rule.

## 6. Measured backend feasibility

Two facts were measured rather than assumed, and they decide the proof strategy.

**LLVM has the type but this host cannot run it.** `<vscale x 4 x i32>`, `select`
over `<vscale x 4 x i1>` and `llvm.vscale.i64()` all parse, and the module
compiles for `aarch64-linux-gnu -march=armv8-a+sve`. It **fails to legalize on a
host without SVE** — "Don't know how to legalize this scalable vector type" on
Apple Silicon — and this clang has no RISC-V backend at all.

**SMT-LIB has no scalable bitvector.** `(_ BitVec n)` with a variable `n` is not
a sort; z3 rejects it outright. There is no symbolic-width encoding to fall back
on.

| Backend | Scalable form | Notes |
|---|---|---|
| `golden_model.py` | native | Python loops to a runtime `vl`; the natural home for the definition |
| `axis_semantics.h` (C) | native | a loop over `vl`; no extension needed |
| `axis_semantics.rs` | native | same |
| `axis_semantics.ll` | native `<vscale x N x iW>` | emits and compiles; executes only on an SVE host |
| `semantics.smt2` | **only at a concrete VL** | SMT-LIB has no scalable sort |

## 7. Proving a description whose length and shape are parameters

The description is agnostic in VL and in `vtype`; **the proof is not**. The
ladder instantiates each document over concrete values and proves each
instantiation the way it proves everything else.

This is not a workaround invented here — it is what the project already does
with widths. C stops at 64 bits, LLVM and Rust reach 128, and each width is a
separately proven instantiation rather than a symbolic argument covering all of
them.

At each `(VL, vtype)` point the scalable shape instantiates **lane-indexed**:
one instruction becomes `VL*num/(den*elem)` instructions, each ordinary *scalar*
semantics over that lane's operands.

An earlier draft of this section said the instantiation reused V1's packed
expansion — pack the lanes into one `v<lanes>i<elem>` bit-vector and separate
them with shifts and masks. Building it showed that cannot work, and the reason
is worth recording because it is structural rather than incidental: `Sem::Int`
holds a `u128`, and `simd::vector_type_atom` rejects any shape wider than 128
bits, so a packed `vni32` at VL = 256 would need a lane mask with bit 255 set
and no AXIS literal can hold one. Packing is right for V1 because a NEON Q
register really *is* one 128-bit register; a scalable vector has no width an
AXIS scalar can hold, and forcing one on it caps VL at the smallest length SVE
permits.

Lane-indexed instantiation has no such ceiling, and it lands the per-lane
semantics on the most heavily proven part of the system — every backend and
every executor already handles ordinary scalar operators.

That choice paid again when registers wider than a machine word were built
(`docs/limbs.md`). Storing a 512-bit register needs limbs; *computing* on 512
bits at once would need limb arithmetic — carry propagation, cross-limb shifts,
comparison from the top. Under lane-indexed instantiation no value exceeds an
element, so a view spans at most two limbs and the whole second half was never
needed. The packed representation would have required all of it.

The two representations overlap at VL <= 128, and that overlap is the evidence
this one is right rather than merely self-consistent: `tools/scalable_vs_packed.py`
checks the lane-indexed instantiation against the packed expansion V1 already
proves, lane by lane, over every shape. The two share no code — one emits
shift/mask trees over a wide value, the other scalar operators over narrow
ones — so agreement is a real check. Beyond 128 bits only the lane-indexed
representation exists, which is the whole reason it was built.

Native scalable lowerings (golden's `vl` loop, C's, Rust's, LLVM's
`<vscale x N x iW>`) are then second implementations proven against the
instantiation, which is the relationship stage V2 already has.

Three things control the cost and the credibility:

**The corpus stays parametric; the gate instantiates.** `vtype` has 4 SEW × 7
LMUL × 4 policy combinations, and the naive reading — elaborate every
instruction at every point — turns a ~400-instruction RVV corpus into tens of
thousands of entries. The A64 corpus is 840 entries and its ladder already runs
73 seconds on the LLVM-effects gate alone, so that is not a viable artifact.
Instead the mode is an *instantiation parameter of the gate*, exactly as VL is,
and the emitted artifact stays parametric. `(legal (<= (/ sew lmul) ELEN))`
removes most of the cross product before it is ever built.

**Coverage is a covering array, not a cross product.** Every (instruction, SEW)
pair, every (instruction, LMUL) pair and every (SEW, LMUL) pair appears at least
once, rather than all triples. That is linear in the corpus rather than
quadratic, and it is stated as a sampling strategy rather than presented as
exhaustive.

**Definedness is compared exactly, and realisations are fuzzed.** Per M1: the
undefined *region* must match across backends, only its contents are free, and
the ladder runs under all four realisations. The non-tautology check is direct —
flipping one lane's definedness in one backend must fail the gate.

VL is instantiated at 128, 256 and 512. This proves the description at the
lengths and shapes tested, not for all lengths — a bug appearing only at
VL = 2048 would not be caught. It is evidence, not a proof over `n`, and the
LLVM scalable path gets a *compilation* check on this host rather than the
executing gate every other backend receives.

## 8. Staging

* **S1 — shape and element-wise arithmetic. Implemented.** `src/scalable.rs`,
  `examples/scalable_basic.axisl`, six gates. 12 instructions over four element
  widths and both domains instantiate lane-indexed and agree with golden in
  LLVM, SMT, C and Rust at VL = 128, 256 and 512 (Rust at 512 runs ~10 minutes
  and is outside the ladder's length sweep, but passes: 18944 checks). The
  packed cross-check runs 4480 lane comparisons across all four shapes.
  `vdup` is included because the broadcast source is the one operand that must
  *not* be lane-indexed, so it is the case that distinguishes a working
  instantiation from one that suffixes everything it sees.
* **S2 — definedness (M1). Implemented.** `(vtail <type> <vl> <body>)` marks
  lanes at or above `vl` unspecified. Building it produced a simplification
  worth keeping: the definedness mask is emitted as an ordinary *companion
  instruction* rather than a second return value, so all five backends compute
  it with machinery that already exists, and the existing backend-vs-golden
  gates already prove they agree on it exactly. M1 asks for the undefined region
  to be compared without masking; this is what makes that free instead of five
  more lowerings.

  `tools/scalable_definedness.py` runs every realisation (`compute`, `ones`,
  `zeros`) and checks the mask is identical under all of them, that defined
  lanes agree under all of them, and — property 3 — that some undefined lane
  actually differs. That last one is not decoration: on first run it failed,
  because random 32-bit `vl` values are essentially always larger than the lane
  count and no tail was ever reached. The first two properties had been holding
  vacuously. It now reports 768 cases over 16 partly-specified lanes, 393
  undefined lanes reached, all 393 differing.
* **S3 — parametric modes (M2) and rational shapes (M3). Implemented.**
  `examples/scalable_vtype.axisl`, five gates. `vti` is the integer shape
  `vtype` describes and `vtiw` its widened form; `SEW` sets the element width
  and `LMUL` the rational register footprint, both declared on the ISA and swept
  by the ladder. 15 instructions including widening (`vwadd`/`vwaddu`/`vwsub`/
  `vwmul`/`vwmulu`) and narrowing (`vnsrl`/`vnsra`) agree with golden in all
  four backends, over 22 legal `(SEW, LMUL)` points with 6 refused.

  The lane-count rule replaced S1's shape equality. S1 required a single shape
  per instruction, which was too strict: widening reads SEW lanes and writes
  2*SEW ones, and refusing that would have excluded a large part of RVV's
  arithmetic. What such an operation never changes is the *lane count*, because
  a widened operand also doubles its register footprint, so `LMUL` moves with
  `SEW` and the two cancel. Lane-count agreement admits every mixed-width form
  RVV has and still refuses shapes that would process a different number of
  elements.

  The legality predicate is itself differentially checked. `tools/scalable_modes.py`
  implements `SEW <= ELEN`, `LMUL >= SEW/ELEN` and `VLEN*LMUL >= SEW` from the
  specification, independently of the elaborator, and requires the two to agree
  point for point in *both* directions. A predicate that accepted everything
  would pass every backend gate and still be wrong, so the sweep fails if
  nothing is refused as well as if anything legal breaks.

  Register grouping's remaining half — which *registers* a group names — is
  still S5's, for the reason S1 already recorded: lane-to-register mapping is
  not expressed in pure semantics. `Operand.derived_from`/`derived_add`, built
  for AArch64's CASP pairs, is the mechanism it will use.
* **S4 — predication and the predicate domain. Implemented.**
  `examples/scalable_predicate.axisl`, six gates. A predicate turned out not to
  be a new kind of value at all: in the lane-indexed representation it is a
  vector whose lanes are 0 or 1, so `vmerge` is a per-lane `select`, SVE's
  predicate logic is ordinary lane arithmetic (`and` over two predicates needs
  no operator of its own), zeroing predication is the merging form with a
  broadcast zero, and `vundef` feeds S2's definedness machinery unchanged — a
  length and a predicate are two sources of the same per-lane question.

  One difference from packed SIMD is architectural rather than incidental. A
  packed lane-wise compare writes a lane *mask*, all-ones across the element,
  which is what NEON does and why `simd.rs` refuses comparisons outright. A
  scalable compare writes one *bit* per lane into a predicate, which is what SVE
  and RVV do. The scalable vocabulary therefore admits the integer comparisons
  that the packed one excludes, and both are right for their representation.
* **S5 — memory (M4, M5). Implemented.**
  `examples/scalable_memory.axisl`. `(vload <type> base)` gives lane l the
  address `base + l*bytes` and `(vload_strided <type> base step)` gives it
  `base + l*step` — the address *function* is the only difference, which is
  M4's point: gather is a third function, not a third mechanism.

  This is the first scalable stage in the effect layer, and the N-writes problem
  M4 anticipated did not arise: one instruction still becomes one lane
  instruction each, so a vector load is N single-write effects rather than one
  N-write effect, and `EFFECT_MAX_WRITES` never sees a vector.

  It also closes S1's recorded limit. A pure lane function is a function of its
  parameters, so lane identity is invisible to a differential gate; an address
  cannot hide that way, because `base + l*bytes` names the lane.
  `tools/scalable_addressing.py` is the independent reference — 4864 checks over
  eleven vector accesses, evaluating the emitted address numerically rather than
  comparing it as text. Injecting a one-lane offset error and a bytes/bits
  confusion both fail it while the executor gate passes.

  Stores put the shape in the address (`(store (vaddr vni32 rs1) zs i32)`) for
  the reason §7.6 gives, and the per-lane width is written out so a document
  that disagrees with its own address is an error rather than a silent
  correction. Writing `i16` against a `vni32` address now says so.

  Fault suppression (M5) came out cheaper than §7.7 priced it, and the reason
  is worth recording: accessibility is *ambient*, so it belongs in declared ISA
  state rather than in the effect ABI. State is already threaded through every
  executor and published in `STATE_SLOTS`, so `(vload_nf <type> base lo hi)` and
  `(vload_ff <type> base lo hi)` needed no ABI change at all — the guard lives on
  the effect, which is where it has to live, because a select computes every
  lane and discards some and computing a lane is exactly what faults.

  Segment loads are the third address function — field f of element l at
  `base + (l*nf + f)*bytes` — which is M4's claim made concrete: gather, stride
  and interleave are one mechanism with different offsets. They also did not
  need the `EFFECT_MAX_WRITES` bump from 4 to 8 that this document expected.
  Instantiation already splits by lane, so a lane instruction holds `nf`
  single-lane writes rather than one wide one, and SVE's LD2/LD3/LD4 fit inside
  4 as they stand. Only RVV's `nf` up to 8 would need the constant raised.

  `tools/scalable_faulting.py` states both fault forms independently: 1536 guard
  checks, 1088 lanes suppressed, and 326 cases where first-fault and
  non-faulting disagree. That last count is a gate in its own right — an
  accessible window that starts at the base makes the two forms identical, so a
  run that never placed the hole elsewhere would pass while testing nothing
  about the cumulative rule.
* **S6 — cross-lane vocabulary. Implemented.**
  Reductions, structured permutes, compress and the dynamic permute.
  `examples/scalable_crosslane.axisl`, five gates.

  This entry said "dynamic permutes are outstanding" for as long as
  `vrgather` had been built, described in `examples/rvv.axisl`, and compared
  against the golden model by every value backend -- one more claim that
  nothing recomputed. What was genuinely missing was the other architecture's:
  `examples/sve.axisl` now carries `TBL_Z_B`, so the same operator is checked
  four selects deep over 32-bit elements and sixteen deep over bytes, and
  `scalable_crosslane.py` compares both against what a gather *is* rather than
  only against the model.

  A **reduction** is the one shape in this language that does *not* become one
  instruction per lane: it reads every lane and produces a single result, so it
  stays one instruction whose operands are the lanes. That forced a better rule
  in the elaborator — operands are now derived from the lanes an expression
  actually names, rather than renamed one for one. A per-lane instruction names
  exactly one suffixed form and a reduction names them all, and only a rule that
  asks the expression serves both.

  Every reduction folds left-to-right and binary. That is one rule instead of
  two: `add`, `and`, `or` and `xor` fold n-ary in the IR but `max` and `min` are
  binary, so a flat fold would need an arity table to be correct. It also means
  the floating-point case needs no special handling, only a separate
  vocabulary — `fadd` is not associative, so an FP reduction has no value until
  its order is pinned, and writing the nesting out *is* the pinning. RVV draws
  exactly this line between `vfredosum` and `vfredusum`, and only the ordered
  form is described, because the unordered one has no single architectural
  answer.

  A **structured permute** (`vzip1`/`vzip2`, `vuzp1`/`vuzp2`, `vtrn1`/`vtrn2`,
  `vext`, `vslideup`/`vslidedown`) is a static map from an output lane to an
  input lane, so in the lane-indexed representation it is nothing more than
  reading a different lane's operand — the same shape the address functions took
  in S5. The slides take a *background* operand rather than inventing a zero:
  RVV's `vslideup` leaves the lanes below the offset undisturbed and
  `vslidedown`'s tail follows the tail policy, so a model that filled them with
  zero would describe neither.

  **Compress** is the hardest cross-lane shape in the language, and worth
  separating from gather. A gather asks which source lane an output lane
  *reads* and gets a runtime answer. A compress asks which output lane a source
  lane *lands in*, and the answer is a prefix count over the mask — so every
  output lane tests every source lane against a running total that is itself a
  sum over earlier lanes. Cubic where a gather is quadratic, which is why its
  ceiling is 16 lanes rather than 32. Output lanes past the number of active
  elements take a background operand, as RVV leaves them undisturbed.

  Extracting its prefix count then gave the whole mask family for free —
  `viota`, `vmsbf`, `vmsif`, `vmsof`, `vcpop`, `vfirst`. All six are the same
  question asked differently: where does this lane sit relative to the active
  lanes before it? `viota` reports the count, the three set-first masks are
  comparisons against it, and `vcpop` and `vfirst` collapse to scalars as a
  reduction does. That six operators fell out of one extraction is the usual
  sign that a construct was decomposed at the right joint — the prefix count was
  the real primitive and `vcompress` merely the first thing to need it.

  Building it found a bug in the Rust backend rather than in itself. A
  comparison lowered to `if a != b { 1 } else { 0 }` with *untyped* literals,
  which rustc resolves happily while a comparison only ever feeds a `select` or
  another comparison. A prefix count makes one an operand of arithmetic, and
  `{ 1 }.wrapping_add(..)` is an ambiguous-numeric-type error. The C emitter had
  always written `1u : 0u` there; the Rust one had not, and nothing had reached
  it in the years since. Same category as the 64-bit `sra` clamp §7.3 records:
  a lowering that was only ever exercised one way.

  **Dynamic** permutes are not described. `vrgather` reads its lane index from a
  runtime vector, so it cannot be a static map — it needs a select tree over
  every lane, quadratic in the lane count. Left out rather than built at a size
  that quietly stops scaling.

* **S7 — the corpora. Implemented.**
  `examples/sve.axisl`, seven gates. 76 source instructions expand to 489 lane
  instructions — 14 groups of 2 lanes, 28 of 4, 15 of 8, 14 of 16, and 5
  reductions that collapse to one instruction each. Arithmetic across all four
  element sizes, predicates and merging/zeroing predication, contiguous loads
  and stores, non-faulting and first-faulting loads, a two-field structure load,
  reductions and the structured permutes.

  The independent references were extended to cover it rather than leaving it
  with backend gates only, which would have repeated the mistake §7.4 measured:
  3968 address checks, 768 accessibility guards, 156 cross-lane checks.

  **The register-class change §3.5 predicted turned out not to be needed.** That
  section argued a vector register file needs `slot_bits` because a `z` register
  is VL bits wide and a predicate VL/8. Under lane-indexed instantiation nothing
  downstream ever sees a vector register — operands are *elements*, so the file
  is declared in elements and SVE's separate P registers need no separate class
  at all, because a predicate lane is a bit and so an ordinary element-wide
  value holding 0 or 1.

  The cost of that is the limit S1 recorded, still unclosed and now visible in a
  real description: `zn__l3` is element 3 of whatever register the `zn` field
  selects, and the packing of elements into a VL-bit register is not modelled.
  Memory addressing pinned the lane-to-*address* mapping in S5; the
  lane-to-register-bits mapping remains outside what a pure lane function can
  express.

  `examples/rvv.axisl` is the other half and the one that exercises S3: 30
  source instructions whose shapes come from `vtype` rather than from the
  instruction, so the same document is proven at 22 legal `(SEW, LMUL)` points
  with 6 refused. It carries both agnostic policies described honestly rather
  than resolved, widening and narrowing, unit/strided/segment/fault-only-first
  memory, reductions and slides, and a `vsetvli` that writes `vl` as ordinary
  architectural state — which is the payoff of having kept `vl` state and
  `vtype` a mode: vtype changes shapes and must be static, `vl` changes extent
  and need not be.

  Nine gates each, sharing the same independent references. Between them the two
  documents exercise every mechanism M1–M5 and every stage S1–S6.

### 7.1 What the S1 gates establish, checked by injection

Each gate was verified by breaking the thing it claims to check:

| Injected bug | Caught by |
|---|---|
| element atom forced to `i32`, so narrow lanes evaluate too wide | packed cross-check, 371/4480 comparisons fail |
| lane count off by one | packed cross-check, 1757/3776 fail |
| lane reads its neighbour's operands (`lane ^ 1`) | validation: ``unknown formal_semantics symbol `zn__l1` `` |

The third is caught by a different mechanism than expected, and the reason is a
real limit rather than a lucky escape. A pure lane function is a function of its
*parameters*: `(add i32 zn__l0 zm__l0)` and `(add i32 zn__l1 zm__l1)` are the
same function, so a differential gate that feeds lane values positionally cannot
tell them apart. What catches the swap is that the lane expression and the
operand list are derived independently — one from the expression's symbols, one
from the lane index — so a mismatch between them is a symbol error.

The consequence to state plainly: **S1 proves each lane's operator, element
width and lane count; it does not prove the lane-to-register-bits mapping**,
because at S1 that mapping is not expressed anywhere. Lane identity becomes
observable when lanes are read from a register file, which is the effect layer's
job — so it is S5's memory work and the executors, not this stage, that will
pin it down.

### 7.2 What the S2 gates establish, checked by injection

| Injected bug | Caught? |
|---|---|
| undefined bits leak into defined lanes (select arms swapped) | yes — 375 defined-lane disagreements, and the inert-knob check fires too |
| the tail begins one lane too late, consistently in both the mask and the value | **no — passes** |

The second is a genuine limit, measured rather than assumed. The value select
and the mask instruction are built from the same expression, so they cannot
disagree with each other; the gate proves the mask is *stable and honoured*, not
that it begins where the architecture says. Nothing in the corpus is an
independent statement of where the tail starts.

Closing it needs a second, independently-derived account of the active lane set
— the executors computing it from `vl` themselves, which is S5's work. Until
then, S2's claim is exactly: the region is agreed by every backend, and nothing
depends on what is inside it.

### 7.3 What S3 found in the backends

Mixed-width arithmetic is a shape AXIS had not had before — every prior
expression widens outward, via `sext`/`zext`, and none narrows. Narrowing
reached three things worth recording, none of which was in the scalable code:

**The 64-bit `sra` helper clamped its shift amount to 31.** The LLVM prelude
emits one template per width, and the arithmetic-shift helper's saturation
constant had not been parameterised along with the type: `select i1 %ge, {ty} 31`
where every other constant used `{wm1}`. So any 64-bit arithmetic shift by 63 or
more shifted by 31 instead. The `lshr` helper directly above it was correct,
which is exactly why `vnsrl` passed while `vnsra` failed and why the bug had
survived — it needs a 64-bit `sra` whose amount reaches 63, and every shift in
AXIS until now took its amount from a narrow encoded field.

**A destination operand kept a declared width the expression contradicted.** An
expression names what it *reads*, so a destination never appears in it and never
got corrected; a 32-bit result stayed declared as 64. C, Rust and LLVM survived
it by masking internally, and SMT did not, because it takes the declared sort at
its word. The destination is the result shape by definition, so it is now set
from the shape whether or not the expression mentions it.

**An AXIS semantics function evaluates at one width.** `tools/c_vs_golden.py`
states this where it picks a single C type per function, and narrowing is the
first construction that could contradict it — a wider node nested inside a
narrower one. Written that way, LLVM evaluated a 64-bit shift at 32 bits.
Narrowing is therefore expressed as a mask at the wide width rather than as a
narrow node wrapping a wide one.

A fourth is a description bug rather than a backend one: the shift amount is now
masked explicitly, because RVV takes the low lg2(2*SEW) bits and golden shifts
at Python's arbitrary precision while LLVM masks. Out-of-range shifts are a case
the backends do not agree on, so the description says which one it means instead
of relying on either.

### 7.4 The limit S4 made concrete, and the answer to it

S2 recorded that a consistently-wrong definedness mask passes, because the mask
and the value are built from the same expression. S4 shows that limit is not
about definedness at all — it is structural, and it applies to every gate on the
ladder.

Every backend derives its answer from the same description. So a differential
gate proves the *implementations* agree; it cannot notice a description that is
uniformly wrong. Inverting `vmerge`'s sense inverts all five backends
identically. Measured, with the merge sense inverted and separately with
`vwhilelt` off by one:

| | backend-vs-golden | independent check |
|---|---|---|
| `vmerge` arms swapped | **PASS** | FAIL |
| `vwhilelt` off by one | **PASS** | FAIL |

The answer is an independent statement of what the architecture means, and the
project already had two without naming the pattern: V1's packed expansion is an
independently-written oracle for S1's lane instantiation, and
`tools/scalable_modes.py` implements RVV's legality rule from the specification
rather than asking the elaborator. `tools/scalable_predication.py` is the third:
merging with an active lane must equal the plain operation, with an inactive
lane must equal the destination it merged into, zeroing must give zero, and
`vwhilelt` lane l must be active exactly while `base + l < count`. The corpus
carries unpredicated counterparts so the first two have something to be checked
against.

This is worth stating as a rule for the stages that follow: **a construct whose
meaning only the description states needs a reference the description did not
write.** Backend agreement is necessary and is not sufficient.

### 7.5 A gate that passed by doing nothing

The decode-driven executor harnesses cannot reach lane instructions, because
lanes share an encoding on purpose — S1 chose that rather than invent distinct
encodings and put a falsehood in the decode tables. Pointing `exec_vs_golden.py`
at the memory corpus reported:

    0 executed, 0 skipped (no semantics), 0 failures
    lift+execute == golden: PASS

All four effect harnesses exit 0 having done no work, and the ladder printed
`[ok ]`. This is not only a scalable-vector problem: the ladder already carried
`[ok  ] RV64I Rust exec  —  no executable fixtures`, which has been passing
vacuously for as long as it has existed.

The ladder already distinguishes a skip from a pass — `check_all.py` reads
`SKIP` in a gate's verdict — and these harnesses already used it for a missing
compiler. They now use it for zero work as well, so a gate that checks nothing
says so instead of claiming success. The count of skips is in the summary line,
where an unexplained rise is visible.

The general shape is the same one §7.4 named: a gate has to be able to fail. A
gate that cannot fail because it never runs is worse than an absent one, because
it occupies the space where evidence should be.

### 7.6 Why stores are not simply loads backwards

Stores are built, and the shape they took was forced rather than chosen. The
reasoning is recorded because it is the kind that looks arbitrary afterwards.

A load's vector-ness lives in a *value*: `(set zd (vload vni32 rs1))` puts
`vload` inside an expression, and an expression is a `SemanticExpr` that the
lane rewrite already walks. That is why loads could be instantiated after effect
elaboration, in the same hook the semantics use.

A store's vector-ness does not live in a value. `(store addr value width)`
becomes `Loc::Mem { addr, width, .. }`, and the location is built by the effect
elaborator from the source form — so a `vstore` written as a value would never
become a memory location at all. Expanding it therefore has to happen either
before elaboration, splitting the mechanism across two frontends, or by having
the vector-ness live somewhere the post-elaboration hook can still see.

The second is available and keeps one hook, and is what was built: put the
vector shape in the *address*.

```lisp
(store (vaddr vni32 rs1) zs i32)
```

`vaddr` is an ordinary expression, so the elaborator builds a `Loc::Mem` with it
as the address and the lane rewrite reaches it exactly as it reaches a load's.
Lane l's address becomes `rs1 + l*4`, and the location's width is set from the
shape rather than taken on trust — the element width is written explicitly so
the document reads honestly, and a mismatch with the shape is an error rather
than a silent correction.

The same form gives strided and indexed stores for free, since by then the
address function is the only thing that varies.

### 7.7 What the accessibility boundary actually cost

This section predicted that M5 would grow the effect ABI by a range
(`mem_lo`, `mem_hi`) across four executors and LLVM. Building it showed that is
not necessary, and the reason generalises: **accessibility is ambient, not
per-instruction**, so it belongs in architectural state the ISA declares rather
than in the ABI. State is already threaded through every executor and already
published in `STATE_SLOTS`, so the bounds cost nothing new — the instruction
names them (`(vload_ff <type> base lo hi)`) instead of depending on two magic
register names, and the document stays self-describing.

What is *not* negotiable is where the condition lives. A predicated load must
not fault on lanes it does not perform, and a select cannot express that because
it computes every lane and discards some — computing a lane is the thing that
faults. So the condition reaches the access itself, as the effect's guard. That
is the whole content of M5, and it is why predication is deliberately not
uniform across the language.

The gate for it is already clear and is the kind §7.4 calls for: place a hole in
memory, and every backend must stop at the same lane. A description that ignores
the boundary fails immediately, and no differential comparison between backends
is needed to see it.

### 7.8 A reference that could not see what it was for

`tools/scalable_crosslane.py` states the permute tables and the reduction folds
independently, and injecting a wrong `vzip1` fails it while every backend gate
passes — the expected result by now.

The reduction half did not work, and the way it failed is worth keeping. The
first version folded only the integer reductions, all of which use associative
operators. Reversing the fold's association therefore could not change their
answers, so a right-to-left fold passed. The one instruction whose *order* is
observable — `vfredosum`, which exists precisely because floating-point addition
is not associative — was not in the reference at all. The gate checked
everything except the property it had been written for.

Adding it was not sufficient either. With random 32-bit patterns as float
inputs, a reversed association was caught in 2 cases out of 552: random floats
are mostly enormous or minuscule, one term dominates the sum, and the fold is
associative in practice. Drawing the lanes across a narrow band of binary
exponents instead — so adding them loses low bits in one order and not
another — takes it to 87 of 556.

Two lessons, and the second is the one that generalises. A reference has to
cover the case that motivated the feature, not the cases that are easy to write.
And a gate that *can* fail is still not enough: it has to fail *often enough to
be trusted*, which means its inputs have to be chosen against the property, not
drawn uniformly and hoped over.

### 7.9 Vocabulary that needed no vocabulary

The last round of operators mostly consisted of not adding operators.

**Float predicates** needed one line: letting the IEEE comparisons through the
lane-local check. They return a bit, exactly as the integer comparisons do, so a
float predicate is the integer predicate machinery with a different element
domain.

**Saturating arithmetic** needed none at all, once `select` was admitted as
lane-local. `vsaddu` is "a sum below either operand has wrapped"; `vsadd` is "the
operands shared a sign the result does not". Both are written out in the corpus
rather than hidden inside an operator name, which puts the overflow rule where
it can be read and argued with. The cost is that the expression repeats its sum,
because the language cannot bind an intermediate — cheap at four lanes and not
at sixty-four, which is the same pressure toward a `let` binding that the gather
and compress trees create.

**Shifts turned out to be missing from the lane-local list entirely** — not from
the scalable one, from the shared one in `simd.rs`. A shift is lane-local in both
representations, since each lane shifts by its own amount and nothing crosses
the boundary. No packed corpus had ever asked for one, so nothing had noticed.
Adding it to the shared list rather than to the scalable extension is the
non-drifting choice: two lists that disagree about the same question are how
this project's bugs start.

**`vextract`** is the one that did need an operator, and the reason is precise:
"collapse to a single lane" is not something a lane-parallel vocabulary can say,
any more than a reduction is.

And a result worth more than the operators. SVE's `BRKA` and `BRKB` are RVV's
`vmsif` and `vmsbf` — the same prefix-count comparison under two architectures'
names. They share an operator here and differ only in mnemonic, which is the
strongest evidence available that this vocabulary was cut along architectural
joints rather than along one architecture's naming. The cross-lane reference
states both spellings separately, so if the shared operator ever stopped meaning
both, one of them would fail.

### 7.10 State is scalar, and lane instantiation had to be told

`vxsat` is RVV's fixed-point saturation flag: set when an instruction saturates,
and left set until software clears it. The sticky part is what makes it
interesting — the instruction reads the old flag and ors into it, so a saturating
instruction stops being a pure function and becomes effectful.

That exposed something lane instantiation had been getting away with. It suffixes
every symbol it meets, because in a vector expression every symbol *is* a vector
operand — and architectural state is not. There is one `vxsat`, not one per lane,
so the sticky read was becoming `vxsat__l0`, a name nothing declares.

The fix is that `VectorMode` now carries the state names, so the rewrite leaves
them alone. It belongs there rather than in a parameter threaded through
nineteen call sites, and a slice reference is `Copy`, so the mode keeps its
shape. This is the second time the question came up — the accessibility bounds
`mem_lo`/`mem_hi` in M5 were handled by constructing their expression inside the
operator, which worked and did not generalise. Two occurrences is when a special
case should become the rule.

It also turned up a latent bug next door: `reduce`, `vcpop`, `vfirst` and
`vextract` were calling `lane_of` with `VectorMode::default()` rather than the
real mode, discarding SEW, LMUL and now the state names. Harmless so far because
their operands are plain symbols; not harmless once state can appear in one.

The stickiness itself is checked independently, because nothing executes it: RVV
lane instructions are not encodable, so no executor reaches them, and the
backend gates all derive from the same description. `tools/saturating_check.py`
evaluates the emitted state write against `new = old | saturated`, and requires
the distinguishing case to occur — an already-set flag surviving a
*non*-saturating instruction, which is where a plain assignment would silently
clear it. Injecting exactly that assignment fails the reference and passes every
backend.

## 9. What is still out of reach

Much narrower than the first design, and worth stating precisely:

* **Address translation.** M5 models one contiguous accessible region, which is
  enough for lane-stopping behaviour and not enough for a page table.
* **Asynchronous interruption points.** `vstart` makes *resumption* describable;
  which lane an implementation chooses to trap at is not enumerable.
* **`LMUL` > 1 register grouping — the shapes are proven, and the grouping is
  now *stated* though still not modelled as a value.**
  Worth separating, because it is easy to read this as more than it is. The
  `(SEW, LMUL)` sweep covers 1/8 through 8 and passes at 2, 4 and 8: at
  `LMUL = 4, SEW = 32, VL = 128` an instruction instantiates to 16 lanes, the
  correct count. LMUL's effect on *shape* is described and proven.

  Which *registers* a group names is now published per operand: `packing.register`
  is how many registers past the encoded one the element sits, `packing.element`
  its index within that register, and `packing.lane` which lane it is — the last
  because a reduction is one instruction whose operands span every lane, so the
  instruction's own lane says nothing about them. At `LMUL = 4, SEW = 32,
  VLEN = 128` lane 15 reports register+3 element 3, which is an operand covering
  four registers: register grouping, as data.

  Published rather than modelled, and the distinction is the whole of what
  remains. Modelling the packing as a *value* would mean representing a whole
  VL-bit register, and `Sem::Int` holds a `u128` — at VL = 512 there is no value
  to hold it in. That is the same ceiling that forced lane-indexed instantiation
  at S1, so this limit and that decision have one cause. Stating the mapping
  costs nothing and is what a consumer actually needs: given the encoded
  register number, the three fields say exactly which element an operand is.

  What is still out of reach is any *operation* on a register as a wide value —
  a reinterpret between element widths, or a whole-register move that does not
  decompose into elements. Those need the wide value, not the mapping.
* **Dynamic permutes (`vrgather`) — built, with a stated ceiling.** It reads an
  *arbitrary* runtime-chosen source lane, so it cannot be a static map: lane l
  becomes a select tree over every source lane, which is quadratic. That is a
  real cost, so it is bounded rather than avoided — exact up to 32 lanes and
  refused beyond with the reason named:

  ```
  `vrgather` over 64 lanes needs 64 select nodes per lane, which is quadratic;
  the limit is 32 lanes
  ```

  A ceiling says more than an absence does. Excluded, the operator looked like a
  gap in the language; bounded, it is describable everywhere a description would
  actually want it, and the one place it stops is documented. An index at or
  above the lane count reads zero, as RVV specifies, and the reference checks
  both sides of that boundary — a run that only ever produced out-of-range
  indices would test nothing but the fallback.

  This is the third exclusion in this document whose reason did not survive
  contact with the representation. It was right that the tree is quadratic; it
  was wrong that quadratic meant *do not build it*.

  Building it also broke a gate, in a way worth keeping. `vrgather`'s ceiling is
  a limit of the *description*, not of the machine, and the `(SEW, LMUL)` sweep
  could not tell the two apart: at `SEW = 8, LMUL = 4` a vector has 64 lanes,
  past the ceiling, so the elaborator refused a point the specification calls
  perfectly legal and the sweep reported a legality disagreement. The gate was
  right to complain and wrong about what it had found.

  The fix is to keep the two questions separate. A refusal that cites a capacity
  limit, at a point the spec says is legal, is now counted and named rather than
  scored against the legality rule:

  ```
  28 (SEW, LMUL) points: 19 legal and proven, 6 refused
    3 legal point(s) past a description capacity limit: SEW=8 LMUL=4,
      SEW=8 LMUL=8, SEW=16 LMUL=8
  ```

  Naming them matters more than passing does. Those three lines say that this
  description cannot be expanded at three configurations a real machine can be
  in — which is a fact about the description, and exactly the kind of fact that
  a gate reporting only PASS or FAIL would have buried.

  Note what this does *not* cover. Gather and scatter **are** built, because
  element l reads element l of the index vector — its own lane — which makes
  them ordinary per-lane address functions rather than cross-lane operations.
  That entry sat on this list twice with the reason "needs a vector in the
  address position", which sounded like machinery and was not; it cost about
  fifteen lines. **An exclusion needs its reason rechecked against the
  representation that exists, not the one the design was written against.**
* **The exact value of an unordered FP reduction.** Excluded because the
  *architecture* has no answer, not because the language cannot hold it. Any
  reduction order is legal and different orders give different bit patterns, so
  there is no single value to describe. M1's machinery does fit — mark the
  result unspecified and fuzz across orders, proving no consumer depends on
  which appears — but the realisation knob varies *contents*
  (`compute`/`ones`/`zeros`) rather than evaluation order, so that route is
  available and unbuilt rather than closed.
* **SVE2, crypto and vendor extensions.** Vocabulary, not mechanism — they need
  operators, not new machinery.

## 10. Arm's SVE (V1-V4)

S7 built `sve.axisl` as an *illustrative* SVE: an RV-style base with opcodes of
its own, and shapes chosen for what the S1-S6 mechanisms needed --
non-destructive predicated arithmetic, unpredicated compares, a reduction into
a general register, inactive lanes left unspecified. Every gate compared AXIS
with AXIS or with a hand-written reference of those same shapes, so nothing
could say whether it was SVE. The V stages make it Arm's.

* **V1 -- Arm's encodings and semantics. Done.** 86 instructions on an
  `armv8-a` base at VL = 128, every one in Arm's layout: unpredicated
  ADD/SUB/MUL (SVE2) at every element size and AND/ORR/EOR/BIC; predicated,
  destructive ADD/SUB/SMAX/UMAX/SMIN/UMIN; TBL, ZIP/UZP/TRN, EXT, DUP;
  UADDV/SADDV/SMAXV/EORV into element 0 of Vd; CMPGT/CMPEQ and WHILELT with
  NZCV; FCMGT/FCMEQ; predicate AND/EOR, BRKA/BRKB, LASTB, CNTP; LD1/ST1 at
  every size, LD2W, LDNF1W and LDFF1W at `[Xn, #imm, MUL VL]`.
  `tools/sve_asl_check.py` builds each trial word from the corpus's own layout,
  requires `llvm-mc` to read it as the instruction the corpus names, runs it on
  Arm's ASL model (SVE at EL3, ZCR_EL3.LEN = 0) and on the Python, wide C and
  wide Rust executors from one random state, and requires every X, Z, P, NZCV
  and byte of a memory window to agree.

  What Arm's definition asked of the vocabulary, all of it small:
  a reduction may sit *inside* a per-lane expression (`UADDV` writes the sum
  into element 0; a compare's NZCV is "is the first active element true", a
  scalar over lanes beside a vector result); `vlastb` (the last active element,
  or the last element -- LASTB, and the C flag); `vuaddv`/`vsaddv` (UADDV and
  SADDV accumulate at 64 bits whatever the element); a scalar-typed outermost
  form (`CNTP`'s count into an X register); and an expression, not only an
  operand, as a segment or fault-suppressing load's base. Every other corpus
  is byte-identical under all of it.

  **What it found in AXIS, which no earlier gate could.** Every executor --
  Python, C and Rust -- ran a scalable word's lanes *in place*, so lane k's
  write was lane k+1's source whenever a destination is also a source:
  `uzp2 z11.s, z9.s, z11.s` read an element UZP had already overwritten. The
  whole-register references had the same sequencing, which is why they agreed.
  Each lane now reads a snapshot of the registers and state as they were
  before the word, and its writes merge back by the bits it changed (two lanes
  write different elements of one 64-bit slot). And a destructive operand read
  at a *different* lane than it is written -- EXT reads element k+1 of Zdn into
  element k -- was lost by the expander, which kept only the lane it saw read;
  it is declared as a destination plus a source derived from it.

  **Recorded limits.** EXT is described at one immediate (#4), since its
  general form reads a byte offset the static permute cannot take. LD2W's
  second register is Zt + 1 without Arm's wrap from Z31. And LDNF1W/LDFF1W
  keep the `mem_lo`/`mem_hi` window rather than Arm's FFR -- the ASL harness
  runs with the MMU off, where every access is to Device memory and Arm
  suppresses every non-fault or first-fault access, so these two are the gate's
  one named deferral.

  The hand-written SVE references of the definedness, addressing,
  fault-suppression and cross-lane gates described the illustrative shapes;
  those gates keep RVV and the mechanism corpora, and Arm's model holds SVE.
  Arm's SVE has no partly-specified result, so there is nothing for
  definedness to ask of it.
* **V2 -- breadth over what V1 has. Done.** 244 instructions: every element
  size where V1 had one (TBL, ZIP/UZP/TRN, DUP, the reductions, LASTB, CNTP)
  and LASTA beside LASTB; ORV/ANDV/UMAXV/SMINV/UMINV beside SMAXV/EORV; the
  compares CMPGE/CMPHS/CMPHI/CMPNE beside CMPGT/CMPEQ (the LT/LE/LO/LS forms
  are Arm's aliases of these, with the operands swapped); WHILELE/WHILELO/
  WHILELS beside WHILELT; PTRUE with every pattern at VL = 128, PFALSE and
  PTEST; all seven predicate logic operations, SEL, and the flag-setting
  ANDS/BICS/EORS/ORRS/ORNS/NORS/NANDS and BRKAS/BRKBS, each with Arm's
  PredTest; INDEX in all four immediate/register forms; LSL/LSR/ASR by an
  immediate (`tsz:imm3` giving both the size and the amount) and by a vector,
  predicated; ADD/SUB by an immediate with its optional `LSL #8`.

  The corpus is generated -- most of it is one form at four sizes, and a
  hand-copied family drifts -- by `tools/gen_sve.py`, and the gate
  "SVE corpus == its generator" (`gen_sve.py --check`) holds the committed
  file to it. `sve_asl_check.py` accepts Arm's *preferred disassembly* as
  the instruction's own name, since `llvm-mc` prints it whenever the operands
  allow: DUP (scalar) is always MOV, AND/ORR/SEL of a predicate with itself
  are MOV(S), EOR against the governing predicate is NOT(S). Its
  not-vacuous check is now per instruction -- each must change something in
  some trial -- since a single PTEST can find NZCV already as it leaves it.

  **What it found in AXIS.** Breadth found a size problem, not a wrong
  answer. The C and Rust emitters wrote `min`/`max` as an inline conditional
  that names each operand twice, so a fold of them doubles at every step:
  SMAXV over sixteen bytes rendered to 11 MB of C *per lane*, the executor
  header to 715 MB, and a compile that did not end. They now call one helper
  (`axis_minmax64`), and the SVE header is 25 MB. The expander gained
  `vlasta` beside `vlastb`.

  V2's gate run: 976 words, four per instruction, on Arm's model; `llvm-mc`
  named every one as the corpus does, and the Python and wide C executors
  left every register, flag and byte as Arm did.

  **Recorded limits.** The wide Rust executor was not in that run
  (`--no-rust`): building its 250-case driver outran a machine short of
  memory that day. The ladder's registration still runs it. PTRUE's counts
  are those of VL = 128, the one length the corpus describes.
* **V3 -- the FFR and fault suppression as Arm states them. Done.**
  SETFFR, WRFFR, RDFFR (unpredicated, and under Pg/Z with and without
  flags), and LDNF1 and LDFF1 at every size, held to Arm's model; the gate
  names no deferral any more. Its run: 1028 words over 257 instructions,
  `llvm-mc` and the Python and wide C executors agreeing with Arm on every
  one, and in 6 of the 32 first-fault and non-fault trials an element really
  was suppressed -- the gate now fails if none is.

  *The harness.* With the MMU off every data access is to Device memory, and
  Arm suppresses every non-fault and first-fault access there -- which is why
  V1 could only defer these. The template now turns translation on at EL3:
  identity-mapped, everything up to the end of the memory window Normal and
  write-back, the page after it unmapped, the UART a Device block. Three
  things were needed that no document said: SCTLR_EL3.WXN is set at the
  model's reset, making every writable page execute-never; AP[1] is RES1 in
  the EL3 regime; and the model implements RME, so EL3 is in Root state and
  fetching from any other physical address space -- the tables' NSE bit
  clear -- is a permission fault. The window moved to end on the page
  boundary, and AXIS is told the same boundary as `mem_hi`. Misaligned
  accesses, legal on Normal memory, are now drawn for every load and store.

  *What Arm's model does* -- asked directly before anything was described,
  since the existing `vload_nf`/`vload_ff` were RVV-shaped and nothing had
  held them to Arm:
  an element is suppressed when it, or an active element before it, would
  fault; a suppressed element clears its FFR element and every one after;
  an element whose FFR element is *already* false is suppressed too, even
  where nothing faults; a suppressed element of Zt keeps its old value, an
  inactive one that is not suppressed is zero; and LDFF1's first active
  element is an ordinary access that faults rather than being suppressed.
  A non-monotonic FFR is unpredictable, so the gate seeds only monotonic
  ones.

  *What it asked of the language, two small things.* A `(fixed k)` operand:
  a register no bits select, as fully encoded as a field-bound one, so the
  FFR is the predicate file's p16 and its lanes place like any predicate's.
  And `(vinbounds <type> base lo hi)`, a lane *value* -- 1 where the
  element lies wholly in [lo, hi) -- because the FFR's update depends on a
  prefix of it: with F = active and not in bounds, what survives is
  `ffr AND vmsbf(F)`, and every load stays guarded so nothing out of bounds
  is ever read. `vload_nf`/`vload_ff` keep RVV.

  **What it found beyond SVE.** The SMT gate had never checked a function of
  no arguments -- PFALSE was the first -- and wrote `(f)`, which is not
  SMT-LIB, so z3 answered with an error and every PFALSE case failed from V2
  on. It now applies such a function by its bare name.

  And the scalable JIT gate compared reads it should never have made. Its
  seeding placed a base anywhere from the buffer's first byte, and SVE's
  `[Xn, #imm, MUL VL]` reaches eight vector lengths below it; and two words
  of one block can want one register for different jobs -- X6 as LD2's base
  and as LDFF1's offset -- which no seeding satisfies, so LDFF1's first
  active element was read outside the buffer. The executor reads zero there,
  compiled code reads the heap, and the gate failed or passed with it. Bases
  now keep a margin, LDFF1's offset is its own addressing kind, and a block
  whose reference leaves the buffer is counted and not run -- as the scalar
  path already did.

  **Recorded limits.** "Would fault" is "leaves the window": an MMU's other
  reasons (permissions, attributes, watchpoints) are not described. The
  value a suppressed element keeps is the model's resolution.
* **V4 -- floating point, conversions, widening and narrowing, gathers and
  scatters. Done.** In four parts, each held to the model before the next:
  V4a floating point at .H/.S/.D -- FADD/FSUB/FMUL unpredicated and
  predicated, FDIV(R), FABD, FMAX/FMIN/FMAXNM/FMINNM, FMLA/FMLS/FNMLA/FNMLS,
  FABS/FNEG, FSQRT, FRINTN/P/M/Z/A, every compare with vectors and with
  #0.0, and FADDV/FMAXV/FMINV/FMAXNMV/FMINNMV/FADDA; V4b SCVTF/UCVTF/FCVTZS/
  FCVTZU/FCVT at every size pair, in containers the wider of the two; V4c
  SUNPK/UUNPK, SXT/UXT, SVE2's SADDL/UADDL/SSUBL/USUBL/SMULL/UMULL and
  ADDHN/SUBHN/SQXTN/UQXTN/SQXTUN, bottom and top; V4d word and doubleword
  gathers and scatters, [Xn, Zm] with UXTW/SXTW/LSL, scaled or not, and
  [Zn, #imm]. FPCR is DN = 1, round to nearest, as the AArch64 gate runs it.

  FMAX's NaN and signed-zero rules and FRINT's ties are the AArch64 corpus's
  own `defsem`s, copied in at generation time, so one statement of them is
  checked against Arm twice. That needed `vmap` over a scalable type -- the
  fixed-width `vmap`, once per lane, bound by `let` -- and half-precision
  lanes, which were refused as having no float semantics though the FP16
  work had given them some.

  **What it found in AXIS.**
  - A `defsem` call inside a binding list -- a `let`'s, a `vmap`'s -- was
    never inlined: the expander returned a list headed by a list as it
    stood. No description had put one there.
  - Written as Arm's recursive tree, FMAXV over halves rendered to 142 MB of
    C: every executor pastes a bound value's text where it is used, and each
    level of the tree names the one below several times. The four min/max
    reductions are described instead as what the tree provably computes --
    FMAXV/FMINV as the default NaN if any active element is NaN, else an
    integer max over sortable keys (which order +0 above -0, Arm's rule for
    two zeros); FMAXNMV/FMINNMV as Arm's FMAXNM once, at the first level
    where a signalling NaN matters, then a max that ignores the quiet NaNs
    above it.
  - An `inout` destination that every lane also reads at ANOTHER lane --
    FADDA's start value in element 0 -- is silently wrong; it has to be
    declared, as EXT's is, as a destination and a source derived from it.

  **Recorded limits.** FPSR's cumulative flags are not compared. Gathers
  cover word and doubleword elements; the byte and halfword forms load
  narrower than their container, which `vload_indexed` cannot say.

* **V5 -- the SVE2 remainder. Done.** V5a integer arithmetic -- halving
  (S/U(R)HADD, S/UHSUB(R)), saturating (SQADD/UQADD/SQSUB/UQSUB unpredicated
  and predicated, SQSUBR/UQSUBR, SUQADD/USQADD, SQABS/SQNEG), SMULH/UMULH,
  SQDMULH/SQRDMULH, SABD/UABD, SABA/UABA, the pairwise ADDP/S/UMAXP/S/UMINP,
  and the long S/UMLAL, S/UMLSL, S/UABAL, S/UABDL, bottom and top; V5b
  shifts by immediate -- ASRD, SQSHL/UQSHL/SQSHLU, SRSHR/URSHR, S/U(R)SRA,
  SRI/SLI, S/USHLL, and all sixteen narrowing shifts; V5c EOR3/BCAX/BSL/
  BSL1N/BSL2N/NBSL, XAR, EORBT/EORTB, CADD/SQCADD, TBX, two-register TBL,
  WHILEGE/GT/HS/HI, ADCL/SBCL, MATCH/NMATCH, HISTCNT/HISTSEG. The saturating
  forms reuse the AArch64 corpus's SQADD family `defsem`s; halving and
  rounding are written without a wider type (`(a >> 1) + (b >> 1)` and the
  bit that falls out); the pairwise and carry forms are TRN1/TRN2 of their
  sources, which say exactly which neighbour each lane pairs with.

  V5d the shifts by a vector -- SRSHL/URSHL/SQSHL/UQSHL/SQRSHL/UQRSHL --
  and the dot products and integer complex multiply-adds: SDOT/UDOT, CDOT
  and CMLA at every rotation.

  **What Arm's model settled.** SVE2's shifts by a vector take the WHOLE
  element of Zm as a signed amount -- not its low byte, as the Advanced SIMD
  forms of the same names do -- so an amount outside the element shifts
  everything out or saturates. The model said so directly: with upper bits
  set, every active element came back zero. And a signed rounding shift right
  by more than the element must read the rounding bit from the sign-extended
  value, or a negative number rounds to -1 instead of 0; the immediate forms
  never reach such an amount, the vector forms do.

  **What it found in AXIS.** The scalable-execution reference read each
  lane's inputs after earlier lanes had written them, and dropped a derived
  operand's register offset -- ADCLB and TBL2 were the first to notice. The
  LLVM emitter's high-half multiply "extended" an i32 operand to i16 for an
  8-bit element (SMULH.B, the first). TableGen named operand classes from
  one-per-encoding instructions but defined them from lanes, which type an
  immediate differently. And the pack ABI's 32-operand bound was below what
  a lane of V2's flag-setting byte compares already needed (53): it is 64 in
  ABI v2.

  **Recorded limits.** Taken up by V6, below.

* **V6 -- the rest of SVE2, and its optional extensions.** V6a integer:
  SQRDMLAH/SQRDMLSH, SQDMLAL/SQDMLSL/SQDMULL (bottom, top), PMUL and
  PMULLB/T, S/UADDW and S/USUBW, RADDHN/RSUBHN, S/UADALP, URECPE. V6b
  floating point: FCADD and FCMLA at every rotation, the pairwise
  FADDP/FMAXNMP/FMINNMP/FMAXP/FMINP, FLOGB, FCVTNT/FCVTLT, and
  FCVTX/FCVTXNT. V6c the optional extensions Arm's model implements: BitPerm
  (BEXT/BDEP/BGRP), AES (AESE/AESD/AESMC/AESIMC) and SHA3's RAX1.

  Each was written without a type twice the element's: SQRDMLAH is Zda plus
  the rounding doubling high half Q, added with saturation -- Arm's single
  saturation of the full sum, since Zda's part is an exact multiple of 2^T --
  with MIN*MIN, the one Q that does not fit, decided apart; FCVTX rounds to
  odd as nearest-even stepped back one unit in magnitude where it went up,
  then made odd; BEXT/BDEP place bit i by a `cpop` of the mask below it.

  **What it asked of the language.** `(vsegperm <type> src k0 ... kn-1)`, a
  fixed shuffle within each 128-bit segment. AES's ShiftRows and its column
  reads are such shuffles; written with `vrgather`, whose index is a runtime
  value, every output lane named every source lane and AESE rendered to
  11 MB of C. A static shuffle names the one lane it reads.

  **Recorded limits.** SM4E/SM4EKEY: four chained rounds, each a 256-entry
  S-box over the rounds before it, which the executors -- pasting a bound
  value's text where it is used -- would render exponentially; they need
  shared subexpressions in the backends first. URSQRTE, whose estimate is
  defined by a search loop. SVE2.1. The PMULL forms over 128-bit results
  (`.Q`, part of the AES extension).

