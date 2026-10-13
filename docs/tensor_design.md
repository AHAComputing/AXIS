# AXIS Matrix and Tensor Units — SME, AMX, and the engines that are not instructions

Status: **14 stages implemented** (T1, half precision; T1b, bfloat16; T1c, the
eight-bit formats; T2, the reduction order; T3, the second index; T5,
configuration from memory; T6a, the depth a description may reach; T6b, the
contraction and its orders; T6c, where the unrolling actually costs; T7, access
maps; T8, kernels and the launch composition; T8a, the elaboration passes
reaching the effect surface; T8b, more than one load in an effect; T9a, the
completion contract). T4 is **withdrawn**, with
the measurement that withdrew it.
§11 is the staging; §12 is what it deliberately leaves out. Every measurement in §4 and §10 was taken
on this host during the design, not remembered.

The float-format refusal described in §1 landed first, ahead of both and
independently of everything here, because it closed a defect rather than adding
a feature.

`docs/scalable_vectors_design.md` covers vectors whose *length* is a parameter.
This covers units whose result has a *second dimension*, whose elements are
narrower than anything AXIS can currently spell, and — for the accelerator half
— whose agent is not the instruction stream at all.

## 1. Three gaps, and only one of them is a new value domain

It is worth separating them immediately, because they are not equally hard and
the temptation is to treat "tensor" as one feature.

**Gap 1 — the element formats.** Every machine in §2 computes on `bf16`, `f16`,
`f8` or `i8`; several compute on `i4`. AXIS has `f32` and `f64`, and the way it
has them is the problem rather than the count. The float format is selected by
comparing the operator's width against 32:

```rust
let bits = if width > 32 { 64 } else { 32 };        // src/emit/semantics.rs, float_helper
let (exponent, significand) = if width > 32 { (11, 53) } else { (8, 24) };   // the SMT emitter
```

That rule is correct for exactly as long as there are two formats. Measured, by
writing `(formal (fadd f16 hn hm))` into a document and running it through:

* `axis check` **accepts it** — `is_type_atom` is `[iuf]` followed by digits, so
  `f16` has always parsed;
* the C backend emits `axis_fp32_add(hn, hm)` — a half-precision add computed in
  single precision, not narrowed, silently wrong;
* the SMT backend emits `((_ to_fp 8 24) ((_ extract 15 0) hn))`, and z3 rejects
  the file: `sort mismatch; invalid bit-vector size, expected bitvector of size
  (ebits+sbits)`.

One backend is loudly broken and one is quietly wrong, which is the worse pair.
`v4f16` and `vnf16` are refused by the lane and scalable atom parsers — those
refusals are asserted in unit tests — so the hole was only in *scalar* float
atoms, and it is the hole a matrix unit steps in first.

**That half is now closed**, ahead of everything else here and independently of
it: `ir::FLOAT_WIDTHS` is the list AXIS describes and `check_float_widths`
refuses anything else at lowering, so the probe above now reports

```
validation error: instruction `FADD_H` operator `fadd` names a 16-bit float as
its value, and AXIS describes f32 and f64
```

The guard is not half precision withheld — it is the language saying how many
float formats it has, where it previously resolved an unknown one to whichever
side of 32 it fell on. A conversion is checked on the end that is a float, so
`(fcvt_f2s i16 32 x)` — a 32-bit float to a 16-bit integer — stays legal, and
the whole corpus is unchanged. T1 below replaces the refusal with a table.

**Gap 2 — the shape, and the writes it implies.** `Shape` is `Scalar`, `Fixed`
and `Scalable`, all one-dimensional. A second dimension is a small change to
that enum and a large change to something else: the effect ABI reports at most
`EFFECT_MAX_WRITES = 4` writes, wide values arrive as limbs *inside* that budget
(`src/emit/llvm.rs` refuses a class whose limb count exceeds it), so one effect
can commit 256 bits. An Intel AMX tile is 8192. An SME `ZA` array at SVL = 512 is
262144. The write ABI, not the IR, is the wall.

**Gap 3 — the agent.** An AMX or SME instruction is still an instruction: it is
fetched, decoded and retired. An NPU tensor engine is not. Its operation is a
loop nest described by a descriptor, it runs for thousands of cycles after the
launch retires, and what the host may observe while it runs is a real part of
the contract. `defaccelerator` today carries the descriptor's *ABI* — schema,
byte count, launch entry, completion field — and one pure expression over scalar
ports. Nothing says what the engine computes over what region, or when the
answer becomes visible.

Only Gap 1 is a new value domain. Gap 2 is a representation problem with a known
shape. Gap 3 is a contract problem, and it is the one with a live consumer.

## 2. The inventory

Chosen so the mechanisms are picked against the whole list rather than the easy
half.

| Machine | The object | Configuration | Contraction |
|---|---|---|---|
| **SME** | `ZA`, an SVL×SVL byte array, sliced as `ZA0.B`, `ZA0.H`..`ZA1.H`, `ZA0.S`..`ZA3.S`, horizontally or vertically | streaming mode and SVL; `SMSTART`/`SMSTOP` | `FMOPA`/`BFMOPA`/`SMOPA` outer products accumulating into a tile |
| **Intel AMX** | 8 tile registers, up to 16 rows × 64 bytes | `LDTILECFG`, a **64-byte block read from memory** | `TDPBSSD` (i8→i32), `TDPBF16PS` (bf16→f32), K = 4 per step |
| **Apple AMX** | X, Y, Z register files; Z is the 2-D accumulator | undocumented | outer product into Z |
| **RVV matrix proposals** | tile/matrix registers or register groups | `vtype`-like | proposed, not ratified |
| **NVIDIA MMA** | fragments distributed across a warp's threads | none | `mma.sync` |
| **NPU / systolic engines** | on-chip buffers, not registers | a descriptor in memory | a whole layer |

Two entries decide the scope. **NVIDIA MMA is a non-goal** (§12): its operand
lives across 32 threads, so describing it needs a thread-level execution model
AXIS does not have and this document does not propose. **AMX's configuration
arrives from memory**, which is the one place the existing mode machinery does
not reach unchanged (§6).

## 3. What already carries its weight

Before proposing anything, the parts that need no change — because the failure
mode of a wave this size is rebuilding what exists under a new name.

| Already there | What it does for this |
|---|---|
| `defmode` with parameters (`scalable_vectors_design.md` M2) | `vtype` generalised to several parameters that reshape operands. A tile configuration is the same construct. |
| Limbs (`docs/limbs.md`) | A register wider than a machine word is `ceil(width/64)` slots. A 1 KB tile *stores* fine today. |
| Lane-indexed instantiation | A scalable instruction becomes N scalar ones at a concrete VL. A matrix instruction becomes rows×cols scalar ones at a concrete shape. Same move. |
| `iterate` (`docs/loops_design.md`) | A contraction is an accumulator carried across iterations. Ordered FP accumulation is already expressible. |
| Address functions (M4) | `unit`/`strided`/`indexed`/`segment` with the predicate as an *argument*, so inactive lanes are never addressed. |
| Definedness masks (M1) | Which lanes are architecturally unspecified, compared exactly. |
| `runs-mapping` composition (stage A4) | A launch instruction's semantics must *equal* the scalar order of the thing it launches. This is precisely the check a kernel launch needs. |
| `vmap` (landing now) | A lane body of several steps. Requantisation — multiply by a scale, round, shift, clamp to `i8` — is sayable the day this lands, and was not before. |

## 4. Mechanism 1 — element formats are named, not inferred from width

Replace the width comparison with a format table: name, exponent bits,
significand bits, and a **specials policy**. One table, in `ir.rs`, read by every
backend — the shape `ast::REGISTER_CLASSES` already has, for the same reason
(README §"Two real ISAs": nine places had grown their own answer to one
question). This is built, with `f16` in it (T1); the rows below it are T1b.

```
  name      eb  sb   specials            note
  f64       11  53   ieee
  f32        8  24   ieee
  f16        5  11   ieee
  bf16       8   8   ieee                f32's exponent range, f32's top half
  f8e5m2     5   3   ieee
  f8e4m3     4   4   finite-max          NOT IEEE: no infinities
```

Three consequences, each load-bearing.

**`f8` must be refused, not interpreted.** Two eight-bit float formats are in
common use and a width does not choose between them. The current grammar would
happily parse `f8` as "float, 8 bits"; the format table makes the name the key
and leaves `f8` unbound. `bf16` does not match `[iuf]` + digits at all, so the
atom grammar gains a named-atom lookup beside the parsed one.

**`f8e4m3` is not an IEEE format and cannot be one sort.** Measured: z3 accepts
`(_ FloatingPoint 8 8)` and `(_ FloatingPoint 4 4)`, so bf16 and an 8-bit sort
both exist. But OCP `e4m3` uses the all-ones exponent for *finite* values — its
maximum is 448, where IEEE semantics at eb=4, sb=4 stops at 240 — and has no
infinities and one NaN encoding. So `f8e4m3` lowers as: compute in a wider sort,
then apply the format's saturation and NaN rules explicitly. `f8e5m2` *is* the
IEEE sort and needs none of that. One format in the table carrying a policy the
others do not is the honest shape; pretending both fp8s are IEEE would put a
wrong answer in the only backend that proves rather than samples.

**Most of these formats are never arithmetic operands.** Worth stating because
it shrinks the work: with the exception of AArch64's `FEAT_B16B16`, no machine in
§2 performs a `bf16` addition. It converts bf16 to f32, multiplies there, and
accumulates in f32. So the required vocabulary is *conversion* plus f32
arithmetic, and the rounding to be got exactly right is `f32 → bf16` on the way
out — round-to-nearest-even on the top 16 bits — not a bf16 adder.

Backends (measured, §10): LLVM has `bfloat` and `half` natively and compiles
them on this host; C has `_Float16` and `__bf16` and both do arithmetic under
Apple clang 17; Rust's `f16` is **unstable** on 1.95 and there is no `bf16`
primitive, so Rust gets software conversion — which for bf16 is a shift and a
round, and for f16 is a short exact widening into f32.

## 5. Mechanism 2 — accumulation order is part of the description

`src/scalable.rs` says it plainly:

```rust
/// Ordered reductions over IEEE-754 lanes. ... floating-point addition is
/// **not associative** ... RVV draws exactly this distinction -- `vfredosum`
/// is ordered and `vfredusum` is not, and the unordered one has no single
/// architectural answer, which is why only the ordered form is described here.
const ORDERED_REDUCTIONS: &[(&str, &str)] = &[("vfredosum", "fadd"), ("vfredomul", "fmul")];
```

`scalable_vectors_design.md` §3 M1 lists "unordered FP reductions" among what
definedness masks cover. **They are not covered, and a definedness mask cannot
cover them.** A mask says *which lanes* are unspecified; an unordered reduction
produces one fully-defined value chosen from a set of admissible ones. That is
whole-value indeterminacy, and the two are different mechanisms. The design
document overclaims and the implementation is right; this is the seam a matrix
unit walks straight into, because every machine in §2 is an accumulator.

The extension is the *shape* of `unspecified-realization`, not the mask — and
this part is **built** (T2). Two orders are pinned, the unordered form is
whichever of them the ISA declares, and the ladder runs once per declaration:

```lisp
(vfredosum vnf32 zn)     ; left to right, rounding at every step
(vfredpsum vnf32 zn)     ; a balanced tree -- SVE's FADDV
(vfredusum vnf32 zn)     ; whichever the ISA's (reduction-realization ...) names
```

* the unordered form's admissible set is *the orders this language can already
  pin*, which is what makes the sweep decidable rather than a gesture at "any
  order": each realisation is an ordinary described instruction, and no backend
  learns that anything was unordered;
* the knob is ISA-level, exactly as `unspecified-realization` is, and a document
  that does not declare it means `sequential` — which is what every document
  meant before it existed, so nothing already emitted moves;
* a backend may not pick its own order and call it agreement: the realisation is
  fixed in the document the ladder elaborates, once per run.

What did not land with T2 and has since landed as T6b: the `(accumulate ...)`
form itself — an explicit contraction with a declared order and an `exact`
integer obligation. It had no home until there was a contraction to carry it.
The obligation is what it was predicted to be: with an accumulator wide enough
that no partial sum overflows, every order gives one answer, and the arithmetic
is checkable at elaboration. An `i8 × i8` product accumulated into `i32` admits
K up to 2^17, so AMX's K = 64 and a whole systolic column both pass with room —
and an `i16` accumulator over the same products is refused with the numbers.

Two further parameters, because the machines differ on them and the difference
is architectural:

* **where the product is rounded.** `fmul` then `fadd` rounds twice; a fused
  step rounds once. AXIS already distinguishes these — `fma` versus `fmul`+`fadd`
  is stage F1, and `tools/fp_fusion_check.py` proves they differ on a witness
  input. The matrix form inherits that distinction rather than inventing one.
* **the internal width.** "products formed exactly, accumulated at f32" is a
  different machine from "accumulated at f64 and rounded once at the end", and
  both exist.

The gate, and its non-vacuity condition: find a witness input on which two
admissible orders **differ**, and fail as vacuous if none is found. An order
declaration proven only on inputs where order does not matter is a declaration
proven over nothing — the same rule `packet_vs_serial.py` already applies to a
slot-crossing RAW that came out equal. `tools/reduction_order_check.py` is that
gate, and the witness is not hypothetical: random f32 vectors re-associate to
the same bits most of the time, so its case list leads with cancellation
patterns — `(1 + 1e30) + (-1e30 + 1)` is 0 where `((1 + 1e30) + -1e30) + 1` is 1.

## 6. Mechanism 3 — a second dimension, and the write it implies

```rust
enum Shape {
    Scalar(u32),
    Fixed    { lanes: u32, elem: u32 },
    Scalable { elem: u32, num: u32, den: u32 },
    Matrix   { rows: Dim, cols: Dim, elem: u32, layout: Layout },   // new
}
```

`Dim` is a literal or a mode parameter, so `ZA0.S` at SVL = 512 is
`Matrix { rows: 16, cols: 16, elem: 32 }` after the mode binds SVL, and an AMX
tile is `Matrix { rows: cfg.rows, cols: cfg.colsb / 4, elem: 32 }`. `Layout` is
row-major or column-major, and it is not decoration: SME addresses the *same*
`ZA` array horizontally and vertically, so a description that gets layout wrong
still passes every test that only ever reads it back the way it wrote it.

**Slice aliasing is the falsifiable content of this stage.** Write rows through
`ZA0H.S`, read columns through `ZA0V.S`, and require the transpose. Any
implementation that keeps two unrelated buffers passes a write-then-read-the-
same-way test and fails this one immediately.

### 6.1 The write ABI grows a shape, not more slots

⚠️ **This section is wrong and is kept for what it got wrong.** The wall it
computes is real arithmetic about a real constant, and nothing reaches it:
instantiation splits a tile operation into one instruction per element long
before any effect is asked to carry 8192 bits. T4 was withdrawn on that
measurement. What follows is the reasoning as it stood.

The measured wall: `EFFECT_MAX_WRITES = 4`, wide values as limbs inside that
budget, so 256 bits per effect. An `FMOPA` writes 1024; a `TDPBF16PS` writes
8192. Raising the constant does not reach either — 128 slots is not "headroom",
it is a different ABI, and the constant is published in the lift artifact and
read by every consumer.

So a write gains a shape. Today an effect is *a location and a value*; it
becomes *a location, a shape, and a producer*:

```
  write { loc: ZA0.S, shape: Matrix{16,16,32}, producer: fn(row, col) -> value }
```

The executor loops the shape and calls the producer; the C and Rust backends
emit the loop; the lift table publishes the shape so a consumer sizes its own
buffer from the description rather than from a constant. This is the same move
`vstore` already made for memory — a lane-indexed effect is a shape plus a
per-lane value rather than N separate writes — applied to the register side, and
it is the one change here that reaches every backend.

## 7. Mechanism 4 — the contraction stays a loop

The arithmetic that decides the proof strategy, from the repository's own
constants (`src/loops.rs`):

```
MAX_ITERATIONS = 1024        MAX_NODES = 200_000
```

⚠️ This section predicted that the node budget would be the wall, and it is
not. Measured while building T6a: a K = 1024 contraction expands to about eight
thousand nodes — a fortieth of the budget — and elaborates in milliseconds. The
wall is **depth**. A left-folded accumulation nests one level per step, every
emitter walks an expression recursively, and `emit-llvm-ir` overflows its stack
somewhere past 463 levels. The prediction was wrong in an instructive way: it
reasoned about the constant that was written down and not about the recursion
that was not.

What remains true is the conclusion. A `TDPBSSD` at 16×16 with K = 64 is 16384
multiply-accumulates over 256 outputs, and a *kernel* over a whole layer is
orders more; scalable vectors got away with full instantiation because VL lanes
number in the hundreds, and a contraction does not. It just runs out of stack
before it runs out of nodes.

`docs/loops_design.md` §3 already names the exit and files it under "later":

> Native lowering is worth doing when a loop is large enough that unrolling
> hurts.

This is that point. The relationship is the one stage V2 already established and
proved: **the expansion is the definition, the native form is a second
implementation, and a differential gate sits between them.** Concretely —

* the golden model loops, as it does for scalable vectors;
* C and Rust emit a real `for`;
* LLVM emits a loop, or `llvm.matrix.multiply` where the shape fits it —
  measured to compile on this host (§10);
* SMT proves at a **proof size**, not the architectural size: a 4×4×4
  instantiation fully unrolled, plus the separate obligation that the
  description is uniform in its dimensions (the index expressions are affine in
  row, col and k, so nothing is special about 4). The same split the project
  already makes between "C stops at 64 bits" and "each width is a separately
  proven instantiation".

Stating the limit exactly, because it is the one a reader should hold against
this: **no backend proves the architectural shape bit-exactly.** What is proven
is the small instantiation, the uniformity of the index maps, and — for FP — the
declared accumulation order at the small size. A 16×16 `FMOPA` is trusted
because 4×4 is proven and the description of the 16×16 differs only in a bound.

## 8. Mechanism 5 — access maps

A tensor operand in memory is a base and a set of strides over an iteration
space, and every addressing form in §2's right-hand column is one:
`TILELOADD`'s row stride, a strided RVV load, an im2col window, an NHWC vs NCHW
traversal, a DMA descriptor's tiling.

Generalise M4's address function from a form to an affine map:

```lisp
(map (i M) (j N)
  (addr (+ base (* i stride_i) (* j stride_j))))
```

`unit`, `strided`, `indexed` and `segment` all remain, as the spellings they
are; the map is what a 2-D or tiled access uses, and the predicate stays an
argument to the effect so an inactive point is never addressed (M4's asymmetry,
unchanged).

Two things this buys that are not the addressing itself: the **address trace**
becomes a computable sequence, so the gate is equality of traces against a
reference enumerator rather than a value comparison that a wrong-but-consistent
map passes; and **disjointness** becomes decidable for the affine case, which is
what a kernel needs in order to claim its output region does not overlap its
input.

## 9. Mechanism 6 — the engine that is not an instruction

This is Gap 3, and the part with a real consumer.

### 9.1 A kernel is an iteration space, access maps, and a body

```lisp
(defkernel conv2d_int8
  (engine npu0)
  (space (n N) (oc OC) (oy OH) (ox OW))
  (reads  (ifm  (map (ic IC) (ky KH) (kx KW) (addr ...)))
          (wt   (map (ic IC) (ky KH) (kx KW) (addr ...))))
  (writes (ofm  (map (addr ...))))
  (accumulate i32 (order exact) (over (ic IC) (ky KH) (kx KW))
    (mul i32 (sext i32 ifm) (sext i32 wt)))
  (epilogue (vmap i8 ((acc out)) (requantize ...))))
```

Everything in it is a mechanism above: the space and the maps are §8, the
accumulation is §5, the epilogue is `vmap` and ordinary integer arithmetic.
`defkernel` adds no arithmetic of its own, which is the test of whether the
mechanisms were factored correctly.

### 9.2 The launch must equal the kernel

Stage A4 already built this check for CGRA mappings: `runs-mapping` composes the
mapping's scalar order and requires the launching instruction's own semantics to
equal it, compared as lowered IR so two spellings agree and a swapped operand
does not. A kernel launch is the same obligation with a descriptor in place of
an operand list: the descriptor's fields bind the kernel's dimensions and base
addresses, and the composed result must equal what the instruction says it does.

The reuse is the argument for this shape. A `defkernel` that needed its own
equivalence checker would be a second, unproven notion of "computes the same
thing".

### 9.3 The completion contract

The part `defaccelerator` cannot say today, and the part a consumer asks about
first:

* **when the writes become visible.** A kernel's effects commit at the
  completion event, not progressively. `(visibility atomic-at-completion)`.
* **what the host sees before then.** Nothing, or partial, or undefined — and
  "undefined" is exactly M1's definedness applied to a memory *region* rather
  than to lanes. The region is compared exactly; its contents are not.
* **what the engine sees.** Whether the launch orders the host's prior stores
  against the kernel's reads, spelled with the `barrier` effect that already
  exists rather than a new word.
* **the observation points.** The gate follows from this and nothing else: an
  executor interleaves host steps with engine progress and requires agreement
  **only at the declared points**. Non-vacuity, in the shape §5 uses: the corpus
  must contain a mid-flight read whose result would differ, or the contract is
  being proven over a schedule where it says nothing.

That is what makes an asynchronous engine testable without a memory model:
determinism is claimed at completion, and completion is when it is checked.

### 9.4 What the manifest publishes

`axis.tensor-kernel.v1`, beside the existing `axis.fabric.v1` and
`axis.issue-packet.v1`: per kernel, the iteration space and which descriptor
field binds each dimension, the access maps, the element formats, the
accumulator width and order, the visibility contract, and the engine it runs on.
This is the table a runtime needs to build a descriptor and a compiler needs to
decide whether a layer fits — and it is derived from the same resolution the
executor runs, so the two cannot drift.

## 10. Measured backend feasibility

Taken on this host (Apple clang 17.0.0, arm64-apple-darwin24.5.0; z3 from
Homebrew; rustc 1.95.0) during the design.

| Claim | Result |
|---|---|
| z3 accepts `(_ FloatingPoint 8 8)` and `(_ FloatingPoint 4 4)` | **yes** — bf16 and an 8-bit float are sorts |
| ...but IEEE at eb=4,sb=4 is not OCP `e4m3` | max 240 vs 448; no infinities in `e4m3` |
| LLVM `bfloat`, `half`, `fadd` on both | **compiles**, natively for arm64 |
| LLVM 8-wide `bfloat` → `fpext` → `fmul` → `llvm.vector.reduce.fadd.v8f32` | **compiles** |
| `llvm.matrix.multiply.v16f32.v32f32.v8f32` | **compiles** |
| C `_Float16` arithmetic (Apple clang) | **compiles and runs** |
| C `__bf16` arithmetic (Apple clang) | **compiles** |
| Rust `f16` | **rejected**: "the type `f16` is unstable" |
| AXIS `(fadd f16 ...)` today | `check` passes; C emits `axis_fp32_add`; z3 rejects the SMT file |

The contrast with scalable vectors is worth recording, because it inverts the
proof strategy. There, LLVM had the type and **could not legalize it on this
host**, and SMT had no scalable sort at all — so LLVM was proven by emission and
SMT only at concrete VL. Here LLVM compiles everything, including a matrix
intrinsic, and z3 has every sort but one format's semantics. The scarce backend
is **Rust**, which is the reverse of the earlier wave and means the software
conversion path is not optional.

## 11. Staging

Each stage independently landable, each with a gate that can fail, and every
document using none of it producing byte-identical artifacts (§13).

- **T1 — the format table, and half precision.** _Done._ `ir::FLOAT_FORMATS`
  is one row per format — name, width, exponent bits, significand bits
  including the implicit one, canonical quiet NaN — and every backend reads it
  where it used to decide for itself: `if width > 32 { 64 } else { 32 }` for
  the C and Rust helper names, `(11, 53)` against `(8, 24)` for the SMT sort,
  `"double"` against `"float"` in LLVM, `'<d'` against `'<f'` in the emitted
  golden model. Four copies of one question, each correct for exactly as long
  as there are two formats. Adding `f16` was adding a row and teaching each
  backend's one rendering function about it.

  The backends deliberately do not agree by computing the same way: the golden
  model uses Python's `struct` `'e'`, SMT uses `(_ FloatingPoint 5 11)`, LLVM
  uses native `half`, and C and Rust compute in single and round to half in
  software. That last is not a fallback — double rounding from p' bits to p is
  innocuous when p' >= 2p + 2, and f32's 24 meet that bound exactly for f16's
  11, so one rounding's worth of correctness survives two. Rust had no choice
  (its `f16` is unstable, §10); C could have used `_Float16` and does not,
  because the header's value is being free of compiler extensions.

  Proven by the four differential gates on `examples/fp16.axisl` and by
  `tools/half_exhaustive_check.py`, which is the one that matters: **all 65536
  half patterns** through every unary half operation, in C and in Rust against
  the golden model, because a rounding bug lives in a thin band of patterns and
  a sample walks past it. Beside that, h → s → h is the identity on every
  non-NaN pattern (the widening is exact, subnormals included), and the
  narrowing is checked over inputs that must reach all five outcomes — rounded
  up, rounded down, tie-to-even, overflow to infinity, subnormal result — or
  the run fails as vacuous. It did fail that way when written: the first input
  range never overflowed, and the gate said so rather than passing.
  Injection-checked three ways — ties away from zero, subnormal results
  flushed, and a subnormal widened by shifting instead of renormalising — each
  failing a different property.

  What is **refused** rather than left to be discovered: the explicit-rounding
  (`fadd_rm`) and exception-word (`fadd_fx`) forms for f16.
  `FloatFormat::environment` is false for it, because stage F3's arithmetic in
  the reference model — exact rationals for inexactness, a subnormal threshold,
  a significand count — still asks whether the width is under 32. A format it
  has never been taught would be computed as single precision there, which is
  the defect this whole table exists to have stopped.

- **T1b — bfloat16, which is not a value domain.** _Done._ The obstruction was
  real and the answer was not to remove it. The IR identifies a float format by
  its **width**, and bf16 and f16 are both 16 bits — f16 fitted because 16 was
  free, and the second 16-bit format is where that representation runs out. But
  bf16 does not need a row, for the reason `docs/simd_fp_design.md` §1 gave
  about SIMD: **bf16 is f32's top half.** Its exponent field is f32's bit for
  bit, so widening is a shift and narrowing is an add and a shift, both
  ordinary integer expressions AXIS has had since the beginning.

  So `src/interchange.rs` expands `(fcvt_f2f bf16 f32 x)` and
  `(fcvt_f2f f32 bf16 x)` at elaboration, on the surface s-expression, beside
  the lane expansion and for the same reason: the typed IR, all six backends
  and every reflective artifact see integer arithmetic, and nothing learns a
  third 16-bit format exists. The canonical form keeps what the author wrote,
  so the round trip is unaffected. An **interchange format** — one a machine
  stores and converts but does not compute in — is the concept that makes this
  a mechanism rather than a special case, and `(fadd bf16 …)` is refused with
  those words.

  That also makes the four differential gates uninteresting here, which is
  worth saying rather than counting them as evidence: every backend consumes
  the same expansion, so of course they agree. What needed checking is whether
  the expansion is **right** — `(x + 0x7fff + ((x >> 16) & 1)) >> 16` is
  round-to-nearest-even and is not obvious. `tools/bf16_check.py` checks it
  against rounding computed in **exact rational arithmetic**: decode the f32 as
  a `Fraction`, find the two bf16 values it lies between, compare against their
  midpoint, break a tie towards the even pattern. Nothing in that oracle shares
  a line with the trick it checks. All 65536 widenings, 40000 narrowings with
  ties and the overflow band reached deliberately rather than by luck, and the
  round trip over every pattern. Injection-checked three ways.

  A fourth injection — widening without masking to 16 bits — **did not fail**,
  and the claim that it would was removed rather than kept: at `i32` the shift
  already moves the high half past bit 31, where the evaluation width discards
  it. Found by running the injection, which is the only reason it is known.

  `examples/bf16.axisl` carries `BFMAC` — two bf16 operands widened,
  multiplied and accumulated in f32 — because that is the inner step of every
  matrix unit in §2's inventory, and it is describable today.

- **T1c — the eight-bit formats.** _Done._ `f8e4m3` and `f8e5m2` expand the way
  bf16 does, and `f8` is refused with its own reason: a width does not choose
  between two formats, and these two disagree about the thing that matters
  most. e5m2 is IEEE-shaped. **e4m3 has no infinities** — it spends the
  all-ones exponent on finite values and keeps one pattern for NaN, which is
  why its largest is 448 where IEEE at that size stops at 240, and why an f32
  past its range *saturates* where e5m2's overflows.

  ⚠️ This entry predicted a loop, and it was wrong. The prediction — "an
  exponent rebias plus a subnormal renormalisation, a loop not a shift" — got
  the rebias right and the loop wrong, by generalising from f16, whose eleven
  significand bits really would want one. With **two or three** mantissa bits
  the leading one is in two or three possible places, so finding it is a select
  over those. Both directions of both formats are closed-form integer
  expressions, and a unit test asserts the expansion contains no `iterate`.

  A second thing the writing found: AXIS literals are unsigned, so `1 - bias`
  spelled out reaches the validator as an unknown symbol `-6`. Both directions
  are phrased in the **biased** exponent for that reason, and a test keeps them
  there.

  `tools/fp8_check.py` checks all 512 widenings against values decoded from
  each format's own fields as `Fraction`s, and 3020 narrowings driven onto
  every rounding boundary the formats have — the midpoint between each adjacent
  pair, from both sides — because a random f32 never lands on a midpoint and
  the midpoint is where ties-to-even is decided. It also requires the two
  formats to *part company*: on the same input e4m3 must saturate to 448 and
  e5m2 must overflow to infinity. Injection-checked three ways: truncating
  instead of rounding, saturating e4m3 onto its NaN pattern instead of 448, and
  widening a subnormal without finding its leading bit.
- **T2 — accumulation order.** _Done._ `vfredpsum` folds a balanced tree beside
  the left fold `vfredosum` already had, and `vfredusum` — the reduction RVV
  leaves unordered — is whichever of them the ISA's `(reduction-realization
  sequential | pairwise)` names. `ReductionOrder` in `src/scalable.rs` is the
  order analogue of `Realization`, and it is a second mechanism rather than a
  case of the first: a definedness mask says which *lanes* are free, and an
  unordered reduction is one fully defined value drawn from a set of admissible
  ones, with no lane to mark. The M1 overclaim is corrected in
  `docs/scalable_vectors_design.md` rather than left to be found again.

  `examples/scalable_crosslane.axisl` carried the exclusion in its own header —
  "the unordered form has no single architectural answer, so only the ordered
  one is described here rather than described wrongly" — and that sentence is
  gone, replaced by the two instructions it was standing in for.

  Proven by `tools/reduction_order_check.py`, whose four properties are each
  required to be non-vacuous: a pinned order does not move when the knob does;
  the associative integer reductions really do re-associate (5 of 5, checked as
  a change in the expression, not assumed) and keep their value; the unordered
  form equals its realisation's pinned twin on every input; and the two
  realisations **differ** somewhere, without which the first three hold over
  nothing. Injection-checked three ways — folding the tree as a left fold (the
  knob goes inert), letting the knob reach a pinned order, and matching the
  unordered form to the wrong twin — each failing the property it should.
  `tools/scalable_crosslane.py` gains an independent pairwise reference beside
  its ordered one, since a gate that only compared backends could not see a
  fold shape that was wrong the same way everywhere; swapping that reference
  for the sequential fold fails it in 63 cases.

  The `(accumulate ...)` form, the accumulator width and the `exact` integer
  obligation moved to T6 (§5): there is no contraction operator for them to
  qualify yet, and a form with no consumer is the one thing this repository
  does not build.
- **T3 — the second index.** _Done._ Not as a shape. §6 proposed
  `Shape::Matrix` beside `Scalar`, `Fixed` and `Scalable`; what was built is
  three **index functions**, because a tile turned out to already be a vector.

  ```text
    (vrows <type> <cols> a)        element k reads a[k / cols]
    (vcols <type> <cols> b)        element k reads b[k % cols]
    (vtranspose <type> <cols> m)   element k reads m[(k % cols) * rows + k / cols]
  ```

  `cols` names the **result's** columns throughout. The first two read a
  shorter operand than the result — four lanes of `zn` feeding sixteen lanes of
  tile — which is what an outer product is, and it falls out of the index
  rather than needing a second shape. So there is no `vmopa`: SME's FMOPA is
  `(fadd za (fmul (vrows ...) (vcols ...)))`, composed from three small maps
  the way `vmerge` composed predication.

  A static map cannot be checked by comparing backends, since every backend
  reads the same map. `tools/matrix_check.py` proves the three **against each
  other**: a transpose undoes the transpose of the other shape, transposing an
  outer product swaps its operands, and transposing a row broadcast gives a
  column broadcast.

  ⚠️ Two of the three injections written for that gate **passed**, and both
  were real holes rather than bad injections. Swapping `vrows` and `vcols`
  relabels every identity, so all of them still held — orientation needed an
  *absolute* property (the first row of a row broadcast is one value repeated),
  not a relative one. And a transpose using the row count where the column
  count belongs passed because the corpus was square, where the two numbers are
  equal; `examples/matrix.axisl` now carries a non-square pair, which is the
  common shape anyway since an AMX tile is 16×64 and only SME's ZA is square.
  A third hole surfaced with them: an out-of-range index silently renamed an
  operand to a lane nobody declared, and is now refused at elaboration.

- **T4 — the shaped write.** _Withdrawn._ Its premise is false.
  §6.1 argued that `EFFECT_MAX_WRITES = 4` — 256 bits with limbs — is the wall
  a 1024-bit `FMOPA` or an 8192-bit AMX tile hits, so an effect would need to
  become a location, a shape and a producer.

  It never hits it. Lane-indexed instantiation has turned one scalable
  instruction into one ordinary instruction **per lane** since stage S1, so a
  256-element tile operation is 256 single-write instructions and no effect
  ever carries more than one element. Measured before T3 was written: a
  256-lane instruction over 8192-bit registers elaborates, and all six backends
  emit it — C at 42 KB, LLVM at 51 KB, the capsule and the register file
  placing eight registers of 128 limbs each.

  The argument for the stage was arithmetic about a constant, and the constant
  was never reached. Nothing replaces it; if a description ever needs one
  instruction to commit a whole tile atomically — which is a different
  requirement, about visibility rather than width — that is T9's contract, not
  this one.
- **T5 — configuration from memory.** _Done._ ⚠️ And again the premise was
  half wrong. This entry called AMX's memory-resident `TILECFG` the one place
  the existing mode machinery does not reach — but the *semantics* were never
  the problem. Measured before the construct was designed: an instruction that
  reads a 64-byte block and writes **sixteen** configuration slots validates
  and emits through every backend today, with no ceiling reached.

  What was missing is everything around it. Nothing said those state slots were
  a configuration; nothing published where in the block each one lives, so a
  runtime that had to *build* the block would have read byte offsets out of an
  effect expression; and nothing named the configuration the document is
  elaborated at.

  ```lisp
  (defconfig tilecfg
    (bytes 64)
    (field tile0_rows (at 48) (width 1) (values 1 2 4 8 16))
    ...
    (instantiate (palette 1) (tile0_rows 16) ...))
  ```

  with `(configures tilecfg)` on the instruction. `defconfig` adds no
  semantics: it is a **second statement of a layout the semantics already
  imply**, and the only thing that makes a second statement worth having is
  that the two are required to agree. Validation walks each declared field,
  finds the state write that establishes it, and refuses a description whose
  load reads byte 47 where the declaration says 48. A declaration nothing
  checks is a comment.

  Five refusals in all — a moved offset, a value the architecture does not
  allow, an uninstantiated field, overlapping fields, and a field no
  instruction establishes — each checked by generating the perturbed document
  rather than by trusting the check exists. The layout reaches
  `mode_legality_manifest.json`, which already answers "what is this machine
  configured as"; a configuration read from memory is that question with a
  different source.

  ⚠️ The canonical emitter **dropped both new forms** at first, and the
  round-tripped document still validated — a declaration silently lost
  round-trips to something still correct, just weaker, which `axis check`
  cannot notice. The gate reads the emitted form for exactly that reason.
- **T6a — what validates must emit.** _Done._ §7 predicted the wall would be
  the node budget. Measured, it is not, and the correction is in §7 itself: a
  K = 1024 contraction is about eight thousand nodes and elaborates in
  milliseconds. What it also is, is **1028 levels deep** — a left-folded
  accumulation is one level per step — and every emitter walks an expression
  recursively. So `axis check` accepted it and `emit-llvm-ir` aborted the
  process with a stack overflow: not a wrong answer, no answer, and no
  diagnosis.

  `semantics::MAX_EXPR_DEPTH` is 400 and `validate_formal_semantics` refuses
  anything deeper with the depth, the limit, and what to do instead. The number
  is measured rather than chosen: on a debug build (the worst case, its frames
  being the largest) LLVM survives 463 and is gone by 483, SMT, C and Rust
  reach about 903, and the golden model survived every depth tried. The
  deepest expression in the whole corpus is **35**, a bit reversal in
  `examples/loops.axisl`, so the limit refuses nothing anyone writes and
  everything that would abort an emitter.

  Proven by `tools/expression_depth_check.py`: a document at the limit is
  emitted by six backends, one past it is **refused rather than crashed** —
  told apart by the signal and the message, since both are non-zero exits —
  and the deep document's measured depth is checked against what the guard
  reports, so a probe that failed to be deep cannot pass as a refusal of
  nothing. Injection-checked by raising the limit to 900, which turns property
  one into three explicit CRASHED diagnoses.

- **T6b — the contraction, and the orders it may fold in.** _Done._ The
  shortcut turned out to be the stage. A balanced fold is `log K` deep where a
  left fold is `K`, so the answer to T6a's limit is not a bigger number or a
  loop — it is to stop folding left where nothing requires it.

  ```lisp
  (accumulate <type> <op> (<index> <count>) (order <order>) <term>)
  ```

  The difference from `iterate` is the whole mechanism: an accumulation's terms
  are **independent** — the term names the index and no accumulator — so its
  association is free, and a free association is choosable. `sequential` folds
  left, `pairwise` folds a tree, and `exact` folds a tree because the operator
  is associative *and* nothing is lost.

  `exact` is an obligation rather than a label, checked at elaboration by a
  conservative magnitude analysis over the term: a masked slice, a sign- or
  zero-extended narrow value, a product of two of those. `i8 × i8` summed 64
  times is 16 bits of product, 6 of count and one of sign — 23, which an `i32`
  holds with nine to spare. Narrow the accumulator to `i16` and the description
  is refused with that arithmetic rather than rounded quietly. Anything the
  analysis does not recognise is assumed to fill the width, so it refuses
  rather than guesses.

  The payoff is `DOT_I8_1024` in `examples/contraction.axisl`: a thousand
  products, **depth 16**, emitted by every backend. As a left fold the same
  instruction nests 1029 deep, and T6a's guard refuses it — which is how the
  two stages check each other, and is exactly what the injection that folds
  `exact` left now reports.

  Floating point has no `exact`, and that is not a gap: an order is what the
  value *is*. `FADD_SEQ` and `FADD_PAIR` are the same eight terms in the two
  orders and are different instructions;
  `tools/contraction_check.py` requires them to disagree on some input, since
  an order declaration no input can tell apart is a declaration about nothing.
  Five properties in all, each falsifiable, and injection-checked three ways:
  folding `exact` left, dropping the obligation, and folding `pairwise` left
  each fail a different one.

- **T6c — where the unrolling actually costs.** _Done._ This stage was going
  to be native loops. Its first task was to measure what the unrolling costs,
  and the measurement said not to build them.

  A K = 1024 contraction, emitted and then given to each backend:

  ```text
                    artifact     build
    C                 229 KB     0.08 s   (0.07 s at -O2)
    Rust              214 KB     0.20 s
    LLVM IR           448 KB     0.05 s
    SMT               229 KB     0.01 s   (z3, parsing the definitions)
    golden model      442 KB     free to import
  ```

  **No compiler cares.** The prediction that size and compile time would be the
  pressure is wrong by two orders of magnitude; the whole set builds in under a
  second. What does care is the **reference model**, and not because it is
  Python: `_eval_axis_expr` re-tokenised and re-parsed the semantics *string on
  every call*. Invisible for a scalar instruction, dominant for a contraction,
  because the string grows with the term count.

  ```text
    K      per evaluation, reparsing    with the parse cached
      64                       1.8 ms                  0.97 ms
     256                      13.7 ms                  3.84 ms
    1024                     214.8 ms                 15.52 ms
  ```

  So T6c is one dict. The emitted golden model keeps parsed trees keyed by the
  expression, which is sound because `_eval` reads the tree and never mutates
  it. `tools/contraction_check.py` gains a sixth property — evaluating an
  instruction twice must not grow the cache — checked by behaviour rather than
  by timing, and injection-checked by removing the cache. End to end that gate
  goes from 9 seconds to 3, and every other gate that drives the golden model
  gains in proportion to its expressions.

  Native loops are **not** built and are not scheduled. The argument for them
  was compile cost, the measurement says there is none at any size AXIS can
  express, and a second implementation of the evaluator in three backends is a
  large thing to carry for a benefit nobody has measured. If a kernel-sized
  description ever makes one of those numbers move, the evidence will be in
  hand and the stage can be rewritten then.
- **T7 — access maps.** _Done._ Stage S5 gave a scalable load three address
  functions — unit, strided, indexed — and a tile wants a fourth while an
  im2col window wants a fifth. One form per shape is a vocabulary growing
  without a mechanism, so:

  ```lisp
  (vload_map <type> base (dim <extent> <stride>) ...)
  (vaddr_map <type> base (dim <extent> <stride>) ...)
  ```

  Dimensions outermost first, the way a subscript is written; lane `k`
  decomposes into one index per dimension and the offset is each index times
  its stride. **The extents are literals and the strides need not be**, which
  is the whole trick: the decomposition happens at elaboration where the lane
  is already a constant, so every index is a number by the time it multiplies a
  stride that may be a register. AMX's `TILELOADD` is `(dim 16 rs) (dim 16 4)`
  and nothing more.

  What `tools/access_map_check.py` checks *first* is that the mechanism
  **reproduces what it generalises**: one dimension at the element size must
  give the same addresses as `vaddr`, and one at a register stride the same as
  `vaddr_strided`. Both were proven in S5, so the general form answers to
  machinery already trusted rather than to a restatement of itself. Then the
  new shapes against an independent enumeration, and a requirement that the
  extra dimensions *do something* — the tile map must differ from both
  one-dimensional maps, and the window map from the tile. Injection-checked
  three ways: decomposing innermost-first, dropping the extent-product check,
  and ignoring every dimension after the first.

  One thing the first run measured rather than the map: with a 40-bit base the
  traces disagreed everywhere, because these instructions write their address
  to a register whose width comes from the shape — `vni32`, so 32 bits. The
  gate stays inside that width now, since truncation is a property of where the
  address was put and not of the map.
- **T8a — the elaboration passes reach the effect surface.** _Done._ Found by
  trying to compose a kernel out of the mechanisms above, which is what §9.1
  claims is possible. It is not, and the first reason is not the one the
  section anticipated.

  Bounded loops and contractions, SIMD lanes and the interchange float formats
  all turn source-level shorthand into ordinary semantics at elaboration — and
  every one of those passes ran on `formal_semantics` and **none ran on
  behaviors**. The effect surface is where *memory* is, so a contraction over
  loaded values, a lane-wise conversion of a loaded vector, or a tile read
  through an access map and accumulated could not be written at all. They did
  not fail helpfully either: `(accumulate ...)` in a behavior reached
  validation as "unsupported formal_semantics operator `accumulate`", a message
  about the typed IR rather than about the form.

  `effects::map_behavior_exprs` gives the passes a way in, and
  `examples/behavior_forms.axisl` is pairs: each shorthand written twice, once
  as a value and once inside a behavior whose result is stored, with
  `tools/behavior_forms_check.py` requiring the two to elaborate to the **same
  typed tree** — not the same text, since the value side round-trips through
  the IR and comes back spelled differently. Plus the non-vacuity that matters
  here: the shorthand must be *gone* from the elaborated tree, or two
  unexpanded forms are agreeing about nothing. Injection-checked by unwiring
  each pass from behaviors, which reproduces the original error messages
  exactly.

- **T8b — more than one load in an effect.** _Done._ The blocker T8 named is
  gone, and it turned out to live in **one place** rather than the model.

  Everything else was ready: the nested case already existed for atomic
  read-modify-write, whose load sits inside the stored value; the Python
  executor has always evaluated loads recursively through its memory reader;
  the effect summaries already walked for loads anywhere, with a comment saying
  so. What refused a second load was the validation step that lowers an effect
  value into the pure typed IR, which stripped a load only when the whole value
  was one.

  The fix is the move `getreg` made one construct over: a load is a leaf the
  pure IR has no node for, so it becomes a symbol before lowering and the IR
  checks the expression *around* it. The load itself is checked in the rewrite
  — shape, width, sign, order, and its address as a pure expression at the
  machine's width rather than the surrounding value's.

  Four things had to follow, and each was a real gap rather than a formality:

  * `load_address_width` was computed from a **top-level** load only, so a
    nested one had its address evaluated at the value's width;
  * both **wide executors declined** every instruction with a second load —
    and the Rust half still printed PASS, because a decline threshold covered
    the whole corpus. Their expression lowerings now read memory anywhere;
  * Rust needed the address bound to a local first, because `read64` takes
    `&mut self` and a pointer chase borrows `mem` twice at once. The binding is
    emitted **only** where the address itself reads memory, which leaves every
    existing artifact spelled as it was;
  * both executor gates seeded memory by looking for one load at the head, so
    they walked for all of them, innermost first — an inner load's value *is*
    the outer one's address.

  ⚠️ And the seeding change exposed a bug that had been invisible: the
  `exec_vs_golden` reference evaluated a **store's** value without
  `load_address_width`, so a block copy read `addr & 0xff`. Nothing noticed
  because nothing had ever seeded the cells a store reads from — both sides
  read zero and agreed. That is the same vacuity `docs/gate_coverage.md` was
  written about, found the same way: by making the gate do more work.

- **T8 — `defkernel` and the launch composition.** _Done._ A kernel is a
  name, params, an iteration space and a body; an instruction launches it with
  `runs-kernel`, binding its operands to the params positionally:

  ```lisp
  (defkernel matmul
    (params c a b)
    (space (i 2) (j 3))
    (store (add i64 c (add i64 (mul i64 i 12) (mul i64 j 4)))
           (accumulate i32 add (k 4) (order sequential)
             (mul i32 (load i32 unsigned (add i64 a (add i64 (mul i64 i 16) (mul i64 k 4))))
                      (load i32 unsigned (add i64 b (add i64 (mul i64 k 12) (mul i64 j 4))))))
           i32))

  (definstruction mm ... (runs-kernel matmul rd rs1 rs2))
  ```

  **The premise, tested first: a kernel adds no semantics.** The same matmul
  was already expressible twice over — as six hand-written stores, and as
  nested behavior-level `iterate`s — and both elaborated and executed before
  a line of T8 existed. So the launch is an expansion: params substituted, the
  body wrapped in one `iterate` per space dimension, and the result is the
  instruction's behavior. Every backend sees ordinary effects. What the form
  adds is what an expansion loses: a **name**, **params**, a space a scheduler
  can read without walking a body (the manifest publishes each kernel's
  params, space and `launched_by`), and a **check**.

  **The composition check.** An instruction may name a kernel *and* carry its
  own behavior; then the two must agree, effect by effect, or the document is
  refused with the effect index and both expressions. A4's structural equality
  was not enough, and this was found by trying it: substituting `i = 0, j = 1`
  leaves `(add i64 (mul i64 0 12) (mul i64 1 4))` where a hand-written behavior
  says `4`, so the check folds constants (`effects::fold_constants`) before
  comparing. It folds and does nothing else — no commutativity, no
  reassociation — because an operand swap is exactly the mistake the check is
  there to catch, which is the strictness A4 chose for the same reason.

  **What the stage found on the way.** The golden `_eval` dropped
  `load_address_width` on every recursive call, so a load nested inside
  arithmetic evaluated its address at the element width. T8b's probes used
  base `0x1000`, which survives truncation to 16 bits, and the Python executor
  shares that evaluator — so they agreed with each other and with the probe.
  The wide C and Rust executors draw 64-bit bases, and the first kernel launch
  through them disagreed. Fixed by threading the width through all six
  recursive sites; `tests/golden.rs` pins the address site.

  The simulator had the same blind spot twice over. Its fixed trace record was
  sized at **one access per effect** — true until T8b — so `mm`, whose six
  stores read eight words each, recorded eight of its 54 accesses and dropped
  the rest without a word. And the `sim_vs_executor` harness formatted each
  event into 512 bytes, which cut the line at the 23rd access even once the
  record held them all. Both now come from what is there:
  `Effect::memory_accesses` counts the loads in an effect's value, address and
  guard (and no event for a register write, so no existing corpus's bound
  rose), and the harness sizes the line by what the formatter reports.
  A kernel of this size exceeds the pack contract's 16 accesses per event, so
  `kernel.axisl` builds no JIT pack — the pack's `_Static_assert` refuses it
  at compile time, which is the contract working, not a limit being hidden.

  Corpus `examples/kernel.axisl`: a kernel-only launch (`mm`), the same launch
  with the six stores written out and checked against it (`mmflat`), and an
  elementwise kernel (`vadd`). The matmul is 2x4 by 4x3, not square, so a
  swapped `i` and `j` writes a different cell. Gate `tools/kernel_check.py`:
  each launch against a matmul and an add written in Python at random 64-bit
  bases; a moved column index and a dropped store refused by the composition
  check; six malformed kernels or launches refused, each for its own reason;
  the source surviving `emit-lisp` without the expansion written back; and the
  manifest's spaces. Injection-checked four ways (in the gate's docstring). The
  three executor gates run the corpus too.

  **Still not built, deliberately:** access maps inside a kernel body (T7's
  maps describe an instruction's operands, and nothing yet consumes a kernel's)
  and launch by descriptor rather than by operand. Both wait on §1's Gap 3 —
  a consumer that would read them — which is still the honest statement of who
  that would be.

- **What the every-corpus sweeps found behind T1–T7.** Adding `kernel.axisl`
  meant running the two sweeps that take every corpus — the roundtrip and the
  simulator — and both were red for reasons older than T8. Each stage had
  registered the gates it thought of, and none had registered the executors:

  - **`BFMAC` could not be encoded.** It named four register operands in a
    three-field format, so no word held its accumulator. It now accumulates
    into its destination (`bd += bn * bm`), the shape every matrix unit has.
  - **Six f16 instructions left a field unbound** — the unary ones, whose
    second source field no operand named. Pinned to zero with `(encoding (hm
    0))`, as `fp_scalar` always had.
  - **The wide executors ran f16 in f32.** Both still chose a helper with
    `width > 32 ? 64 : 32`, the guess `float_bits` replaced in the semantics
    backend, and returned single-precision bits for every half instruction.
    They now take the format from the table, reuse the semantics backend's
    float readers and writers for conversions, and decline the directed-
    rounding forms f16 has no helpers for.
  - **A state loaded from memory read the wrong address.** `setstate` and
    `setreg` evaluated their value without `load_address_width` — in the
    Python executor, the golden model's `apply_state_effects`, and both gate
    references — so `LDTILECFG` read its palette from `rs1 & 0xff`, and all
    four agreed. The C simulator, which had it right, was the one reporting a
    disagreement.

  Executor gates for `fp16`, `bf16`, `fp8`, `tilecfg`, `contraction`,
  `behavior_forms` and `completion` are registered now, three each.
  `matrix` and `access_map` are scalable: the wide executors skip them, and
  the scalable gate's breadth floor is for whole vector ISAs, so their own
  gates remain what holds them. One limit is recorded, not fixed:
  `exec_wide_check` compares only an instruction's **last** state write,
  because the wide executors report one, so `LDTILECFG`'s other five are
  held by the simulator sweep and by `config_check`, not by it.

- **T9a — the completion contract, declared.** _Done._ An accelerator
  manifest said how a descriptor is shaped and what field a completion is
  written to. It did not say **when** the engine's writes become visible, what
  the host may read before then, or whether the launch orders the host's prior
  stores — the three questions a runtime must answer to write correct code
  against an engine that outlives its launch, and none of them were anywhere.

  ```lisp
  (visibility immediate | atomic-at-completion | progressive)
  (launch-fence prior-stores | none)
  (in-flight unchanged | undefined)
  ```

  Every one is checked against something the description already said, because
  a declaration nothing checks is a comment. `coupling` and `visibility` are
  the same fact stated twice: a tightly coupled engine finishes inside the
  launching instruction, so it has nothing to poll and no in-flight window; a
  queue-descriptor one outlives its launch and must say how the host learns it
  is done. Six contradictions are refused, each checked by generating the
  contradictory document, and the contract reaches the manifest a live consumer
  already reads.

  `in-flight undefined` is M1's definedness one level up — applied to a memory
  *region* rather than to lanes — which is what §9.3 predicted, and it is the
  one part of that section that survived contact unchanged.

- **T9b — the completion contract, executed.** ⚠️ Not built, and the reason is
  a property of the system rather than a shortage of time. §9.3's gate is an
  executor that interleaves host steps with engine progress and requires
  agreement only at the declared observation points. **There is no execution
  model to interleave**: an accelerator is a pure function of its ports in
  every backend, evaluated instantaneously, so there is no mid-flight moment
  for a host to read in. Building one is a larger thing than the declaration
  and has nothing waiting on it, where the declaration has a consumer today.

  `tools/completion_check.py` says so in its own docstring rather than leaving
  the limit to be met later, which is the same treatment the one-load-per-
  effect boundary got in T8.

T1 and T2 are independent of everything else and of each other. T3→T4 are a
pair. T6 can land before T3 if the first contraction described is a vector dot
product rather than a matrix one, which may be the cheaper order.

## 12. Non-goals

* **Warp-distributed operands.** NVIDIA's `mma.sync` fragment layout is a
  property of a thread group, and AXIS has no thread-level execution model. Not
  "later" — not described, and named here so nobody reads T3 as covering it.
* **A tensor value in the IR.** Points instantiate to scalars, as lanes do. The
  IR stays one value domain plus IEEE, and the second dimension lives in shapes
  and effects. Every earlier wave that reached the IR paid for it in six
  backends.
* **Address translation.** The accessible-range boundary from M5 is the whole
  memory-map model, here as there. A DMA descriptor's addresses are physical and
  flat.
* **A memory model for concurrent engine and host.** Determinism is claimed at
  declared observation points. Interleavings between them are not explored.
* **Wider instruction words.** Unchanged from the packet design: formats stay
  ≤ 32 bits.
* **Sparsity metadata, compression formats, and layout swizzles that are not
  affine.** A 2:4 structured-sparsity mask is describable as a predicate; a
  compressed format whose decode is a sequential scan is not affine and is out.

## 13. What stays byte-identical

The property every wave in this repository has had to carry: a document that
uses none of this emits what it emits today, byte for byte. Three places make
that non-trivial and each is a check rather than a hope —

* the format table must resolve `f32` and `f64` to exactly the helpers and sorts
  the width comparison does now, which is a table lookup returning the same two
  answers;
* the shaped write must emit the current single-value form when the shape is
  scalar, including the same `EFFECT_OUT_SLOTS` layout, since every consumer
  reads it;
* the native loop must not be emitted for a document with no contraction.

The registration happened with T2: the header counts stages, each landed stage
in §11 is marked `_Done._`, and this file has a row in
`tools/doc_facts_check.py`'s table beside the four that were there. That tool
exists because `vliw_spatial_design.md` said B1–B3 long after B4 had landed and
`scalable_vectors_design.md` said "designed, not built" through all seven of its
stages. A status line is a claim like any other number in the repository, and
this one is now recomputed rather than remembered.
