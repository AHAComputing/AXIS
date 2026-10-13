# AXIS SIMD and Floating-Point Design

Status: SIMD stages V1, V2 and V3 implemented — lane-wise integer vectors at 64
and 128 bits, with LLVM additionally lowering to native `<N x iW>`. Floating
point stage F1 implemented for add, subtract, multiply, divide and square root,
and stage F2 (lane-wise IEEE-754) with it, proven on all five semantics backends
including z3's FloatingPoint theory. Stage F3 — the FP effect layer, both
rounding modes and exception flags — is implemented for RISC-V and for
AArch64's FPCR/FPSR; section 8 records its design, what it cost, why two
backends cannot follow, and which half of it actually ported.

## 1. Where AXIS starts from

The semantic IR (`src/ir.rs`) is a single value domain: an integer bit-vector
with an evaluation width. Every operator — arithmetic, bitwise, shifts,
rotates, bit counts, min/max, extends, select — is width-parameterized over
that one domain, and every backend (golden Python, C, Rust, SMT, LLVM, PyRTL)
lowers from it.

That has two consequences for this wave:

* **SIMD is not a new value domain.** A lane-wise integer add on a 64-bit
  register holding 2×32-bit lanes is exactly two masked adds on bit-vector
  slices. It can be *expressed* in today's IR; what is missing is a way to
  *say* it without hand-writing the shift/mask/or tree, and the guarantee that
  the masking is right.
* **Floating point is a new value domain.** IEEE-754 values are not bit-vectors
  with a width; they carry rounding modes, NaN payload propagation, subnormals,
  and exception flags. No amount of bit-vector composition expresses `fadd`
  without reimplementing soft-float, which would be a second, unproven model of
  arithmetic every backend would have to agree on.

The honest ordering therefore is SIMD first, floating point second — not
because SIMD matters more, but because SIMD is reachable with the existing
proof ladder while floating point needs new machinery in every backend.

## C at 128 bits

The C header used to stop at 64. The reason recorded was that a 128-bit integer
needs `unsigned __int128`, a compiler extension rather than standard C, and that
this header's value is being dependency-free — so the golden model, SMT, LLVM and
Rust covered 128-bit semantics and C did not.

The argument was sound and its conclusion had outlived it. The AArch64
`smulh`/`umulh` helpers have used that same extension since they were described,
and so does the wide executor's high-half multiply. A backend that cannot express
what the other four prove is the worse trade.

The portability is kept where it was actually worth something: the 128-bit
prelude is emitted only for a document that needs it, so a 32- or 64-bit header
still compiles under a compiler without the extension. That property is now
asserted rather than assumed — the golden test checks that `rv32i` produces no
`axis_sem128_` at all.

Two details the work turned on:

* **C has no 128-bit literal.** A wide constant is built from its halves,
  `((axis_u128)hi << 64) | lo`, in the emitter and in the test harness alike.
  It is the only place the wider tier needs different *syntax* rather than a
  different type name.
* **The helper contract is not uniform.** `axis_sem64_shl` takes `(value,
  amount)` while `lshr` and `sra` take `(value, amount, width)`. Assuming a
  uniform shape produced a prelude that compiled on its own and failed at every
  call site. The 128-bit set mirrors the 64-bit one signature for signature.

## 2. Width reality

The compiled backends do not all reach the widths SIMD wants:

| Backend | Widest integer | Why |
|---|---|---|
| `golden_model.py` | arbitrary | Python integers |
| `semantics.smt2` | arbitrary | `BitVec` of any width |
| `axis_semantics.ll` | 128 | native `i128` |
| `axis_semantics.rs` (Rust) | 128 | native `u128`/`i128` |
| `axis_semantics.h` (C) | 64 | standard C has no 128-bit integer |

The D-register shapes (`Vn.2S`, `Vn.4H`, `Vn.8B`) are proven on all five
backends. The Q-register shapes (`Vn.4S`, `Vn.8H`, `Vn.16B`) are proven on four:
C stops at 64 because a 128-bit integer there means `unsigned __int128`, a
compiler extension rather than standard C, and this header's value is being
dependency-free and portable. Those instructions are skipped in C with that
reason stated in the file. Adopting the extension is a one-line change if a
consumer ever wants it — the trade is explicit rather than assumed.

## Two float formats, said out loud

The float format was chosen everywhere by a comparison against 32 — the helper
name in C and Rust (`if width > 32 { 64 } else { 32 }`), the sort in SMT
(`(11, 53)` against `(8, 24)`). That is correct while there are two formats and
fails open when there are not: a third format spelled anyway resolves to
whichever side of 32 it lands on. Measured, before the guard:

* `(fadd f16 a b)` passed `axis check` — `is_type_atom` is `[iuf]` followed by
  digits, so `f16` has always parsed;
* C emitted `axis_fp32_add`, a half-precision add computed in single precision
  and not narrowed;
* z3 rejected the emitted file — `sort mismatch; invalid bit-vector size,
  expected bitvector of size (ebits+sbits)`.

One backend quietly wrong and one refusing to load is a worse pair than either
alone, so `ir::FLOAT_WIDTHS` names the formats and `check_float_widths` refuses
the rest at lowering, where every frontend and every expansion passes through.
The lane and scalable atom parsers already refused `v4f16` and `vnf16`; this is
the scalar case they never covered.

Two details it turns on. The check reads the **ambient** width, not only a
written atom, because a lane expansion hands its element width down and a guard
that only read the atom would leave that path open. And a conversion is checked
on the end that is a float: `fcvt_f2s`'s float side is its source, so
`(fcvt_f2s i16 32 x)` — a 32-bit float to a 16-bit integer — stays legal, while
`(fcvt_s2f f16 32 x)` and `(fcvt_f2f f32 16 x)` are refused on the destination
and the source respectively.

This is a statement about how many formats AXIS has, not a feature withheld.
`ir::FLOAT_FORMATS` is the table those comparisons became — name, width,
exponent bits, significand bits, canonical quiet NaN — and **f16 is a row in it**
(`docs/tensor_design.md` T1, `examples/fp16.axisl`). The golden model gets half
natively from Python's `struct` `'e'`, SMT from `(_ FloatingPoint 5 11)`, LLVM
from `half`; C and Rust compute in single and round, which is exact because
double rounding from p' bits to p is innocuous when p' >= 2p + 2 and f32's 24
meet that bound exactly for f16's 11. `tools/half_exhaustive_check.py` proves
the agreement over all 65536 patterns rather than a sample.

Two things stay refused, each with its reason. The explicit-rounding and
exception-word forms of §8 are not described for f16: their arithmetic in the
reference model still asks whether the width is under 32, so
`FloatFormat::environment` refuses the operator rather than letting a half be
computed as a single there. And `bf16` is not a row at all, because the IR
identifies a float format by its **width** and bf16 collides with f16 at 16
bits — so it expands instead, at elaboration, into the integer shift and
round it actually is (`src/interchange.rs`, T1b). The 8-bit formats are T1c:
their exponent fields are narrower than f32's, so converting one is a rebias
and a renormalisation rather than a shift.

## 3. Stage V1 — lane-wise integer SIMD (implemented)

A **vector type atom** `v<lanes>i<elem>` (`v2i32`, `v4i16`, `v8i8`) sets both
the register width (`lanes × elem`) and the lane width for one operator
application:

```lisp
(behavior (set vd (add v2i32 vn vm)))
```

The operator name is unchanged: `add` is `add`, and the type atom says whether
it applies once at 32 bits or twice at 32 bits within a 64-bit register. That
follows the language's existing rule — the type atom is what makes `(sra i16 …)`
differ from `(sra i32 …)` — so vectors add a shape to that atom rather than a
parallel family of `v*` operator names to keep in sync.

`src/ir.rs` expands that at lowering time into the existing bit-vector IR: for
each lane, shift the operands down, apply the scalar operator, mask to the lane
width, shift back, and combine. The masking is the whole point — it is what
stops lane 0's carry reaching lane 1 — and putting the expansion in the IR
means it is written once rather than per backend.

Because the result is ordinary `Sem`, **every backend and every gate works
unchanged**: the golden model, SMT, and LLVM all emit and prove lane-wise
semantics with no new code, and the C/Rust emitters skip 64-bit entries exactly
as they already do.

Lane-parallel operators are supported: `add`, `sub`, `mul`, `and`, `or`,
`xor`, `not`, and signed/unsigned `min`/`max`. Operators whose meaning is not
lane-local (extends, select, cross-lane reductions, shifts by a vector) are
rejected with a message rather than approximated.

### `vmap` — a lane operator with a body

That list is a description of what had somewhere to be written down, not of
what lanes can do. A saturating add, a lane-wise shift by a signed amount,
anything assembled out of several steps, was not expressible — lanes could
carry it fine, a lane operator just had no body. `vmap` gives it one:

```lisp
(vmap v2i16 ((a rs1) (b rs2))
  (let ((sum (add i16 a b))
        (same-sign (icmp_eq i16 (and i16 (xor i16 a b) 0x8000) 0))
        (flipped (icmp_ne i16 (and i16 (xor i16 a sum) 0x8000) 0))
        (overflowed (and i16 same-sign flipped))
        (limit (select i16 (icmp_eq i16 (and i16 (lshr i16 a 15) 1) 1)
                           0x8000 0x7fff)))
    (select i16 overflowed limit sum)))
```

The lane bindings are emitted as a `let` around the body rather than
substituted into it. A body binds its own names, and substitution would have
to decide which of those shadow a lane name and stop descending there; `let`
already answers that question everywhere it is resolved. This only became
usable once `let` bindings were sequential — a lane body is a chain of steps,
and a chain needs each step to see the one above it.

The closed list was safe **because** it was closed: every operator on it was
known to be lane-local. An arbitrary body is not, so the two properties that
used to hold by construction are proved instead, over every input rather than
sampled: the high lane of a result does not depend on the low lane of any
input, and a body computing wider than its lane is confined anyway.

### Crossing lanes

A lane source may say which lane it reads:

```lisp
(vmap v4i8 ((x (lane rn (/ lane-index 2)))
            (y (lane rm (/ lane-index 2))))
  (select i8 (icmp_eq i8 (and i8 lane-index 1) 0) x y))   ; ZIP1
```

`lane-index` is the lane being computed, and the index expression is folded
while the vector is expanded — `+`, `-`, `*`, `/`, `%` over literals and
`lane-index`. A permutation is a function from output lane to input lane, and
the output lane is a constant at expansion time, so `zip`, `uzp`, `trn` and a
pairwise add all disappear into the constant shifts the backends already
understood. Nothing downstream learns a new concept, which is the same bargain
the lane expansion itself made.

`lane-index` is *bound* rather than substituted, like the lane values, so a
body may rebind it. An index landing outside the vector is an error and not a
wrap: a permutation formula that is off by one is a description bug, and the
lane it would silently read holds real data.

What this does **not** reach is an index that is not known at expansion time —
`TBL`'s runtime table lookup, or `EXT`'s byte offset. Those are operand-driven
and take the same shape the corpus already uses for `size`: a `select` over the
values the field can hold.

**What this deliberately does not do:** the backends see the expansion, not a
vector. LLVM gets a shift/mask/or tree instead of `<2 x i32>`, so the optimizer
cannot see the parallelism, and PyRTL gets no lane structure. That is a real
limitation, recorded rather than hidden.

## 4. Stage V2 — native vector lowering (implemented for LLVM)

The V1 expansion stays the definition of what a lane-wise operator means, and
every backend still uses it. LLVM additionally lowers directly to `<N x iW>`,
so one operator becomes one instruction and the lane parallelism is visible to
the optimizer instead of buried in a shift/mask tree:

```llvm
define i64 @axis_eval_vadd_2s(i64 %vn, i64 %vm) {
entry:
  %t0 = bitcast i64 %vn to <2 x i32>
  %t1 = bitcast i64 %vm to <2 x i32>
  %t2 = add <2 x i32> %t0, %t1
  %t3 = bitcast <2 x i32> %t2 to i64
  ret i64 %t3
}
```

The design revision worth recording is where the lane structure lives. The
first instinct was to keep it in the IR — a `Sem::Vec` node, or lane metadata on
`App` — but expansion happens at elaboration, and by the time any backend runs,
`formal_semantics` is already scalar. Threading lane structure through the IR
would have meant either delaying expansion (touching every one of the ~145
`formal_semantics` read sites, all of which correctly expect scalar bit-vector
text) or carrying a parallel typed representation that each backend would have
to keep in agreement with the expansion by hand.

Instead the pre-expansion spelling is retained verbatim in
`Instruction::vector_semantics`, set by the expander from its own input. It
cannot drift from the expansion, because it *is* the expansion's input — the
same discipline that fixed the four re-derived-predicate bugs recorded
elsewhere in these docs. A document that uses no vector operators leaves the
field empty and nothing downstream changes.

The lowering is deliberately narrow: one lane-parallel operator applied to
whole-register operands, over `add`/`sub`/`mul`/`and`/`or`/`xor`. Anything else
— `not`, signed/unsigned min and max, nested lane expressions, mixed scalar and
vector operands — falls back to the V1 expansion rather than being partially
vectorized. `examples/simd_lanes.axisl` exercises both paths: `VADD_2S` lowers
natively, `VMAXS_4H` falls back, and `llvm_vs_golden` proves both against the
golden model's expansion. Widening the operator set is additive and each
addition arrives with the same oracle already in place.

The gate is the same shape as always, and it is the reason this stage is a
refactor rather than new semantics: the native lowering must agree bit-for-bit
with the V1 expansion, which is already proven against the golden model. Two
independent implementations of one specification, with a differential check
between them — not a second specification.

Not yet native: C and Rust (arrays or `std::simd`), PyRTL (per-lane wires), SMT
(`BitVec` concatenation). Each has the same oracle available whenever it is
worth doing. The retained spelling is on `Instruction` only, so an accelerator
written with lane operators still emits the expansion in every backend; adding
it there is the same three lines if a corpus ever needs it. Separately, `tools/jit_llvm.py` cannot execute these blocks — its
block IR hardcodes `call i32 @axis_eval_*`, so it is scalar-32-bit only. That
predates this stage and is a limitation of the JIT harness, not of the emitted
IR, which `llvm_vs_golden` executes at full width.

## 5. Stage V3 — 128-bit and the Q-register forms (implemented)

Done for LLVM and Rust, both of which have native 128-bit integers.
`examples/simd_q_lanes.axisl` carries the Q-register shapes and is proven
against the golden model on LLVM, Rust, and SMT.

The helper preludes are rendered from a width template rather than copied, so
width-derived constants — the shift-amount mask, the most negative value —
cannot be left at a narrower width. That is not a hypothetical: deriving the
64-bit LLVM prelude by text substitution silently left `and i32 %a, 31` in
place, masking 64-bit shift amounts to five bits, and `llvm_vs_golden` caught it
on MOVZ/MOVN/EXTR. The 32-bit helper sets stay separate and untemplated because
they do signed work by promoting to a wider type, which has no analogue at 64
or 128; the wide sets sign-extend in place and guard division overflow instead.

C remains at 64 (see the table above). 128-bit *effects* are a separate matter:
the effect ABIs pass values through `uint32_t`/`uint64_t` out-parameters, so
widening those is its own step and nothing needs it yet.

## 6. Stage F1 — scalar floating point

**Revision to this section's original design.** It claimed a value must become
`(width, class)` and that `Sem` has to carry which interpretation applies. That
is not necessary and it is the more invasive choice. An FP instruction reads bit
patterns out of registers and writes a bit pattern back; the interpretation
belongs to the *operator*, not to the value. So `Sem` stays a single bit-vector
domain and `fadd`/`fsub`/`fmul`/`fdiv` are simply new operators that reinterpret
their bit-vector arguments as IEEE-754, compute, and return the resulting bit
pattern. Two things follow, both good: no existing backend code changes meaning,
and the differential harnesses need no new comparison logic, because comparing
result *bit patterns* for equality is already exactly what they do — which is
also the only comparison that catches a wrong NaN payload or a sign-flipped
zero.

Remaining design constraints, in the order they bite:

1. **NaN is canonicalized by AXIS, not inherited from the host.** See point 4;
   this is what makes the bit-pattern comparison meaningful across platforms.
2. **Rounding is explicit.** Every rounding operation takes a mode
   (RNE/RTZ/RTP/RTN/RTA). AArch64 reads it from `FPCR`, which AXIS already
   models as named architectural state — so the mode is an effect-layer input,
   not an ambient global.
3. **Exception flags are effects.** Invalid/divide-by-zero/overflow/underflow/
   inexact accumulate into `FPSR`, which is already a declared state location.
   That means FP arithmetic is *effectful* by default, and the pure path only
   applies when a description opts out of flag updates.
4. **NaN propagation must be specified, not inherited.** Which input NaN is
   returned, and whether a signalling NaN is quieted, differs by architecture —
   x86 and ARM do not agree in every case. Left to the host, the backends would
   disagree on precisely the inputs that matter, and they would disagree
   *differently* depending on which machine ran the gate. AXIS therefore
   specifies the result: when an operation's result is NaN, it returns the
   canonical quiet NaN (sign clear, exponent all ones, mantissa MSB set, the
   rest zero). Every backend canonicalizes explicitly, so a bit-pattern
   comparison is platform-independent. An architecture whose real behaviour
   differs describes that behaviour explicitly rather than inheriting it.

Backend feasibility: golden Python (`struct`, plus `math.fma` for the fused
operation), C (`float`/`double`, with `sqrt`/`fma` from libm — so a float-using
header includes `math.h` and its consumers link `-lm`), Rust (`f32`/`f64` and
`mul_add`, no extra dependency), LLVM (native `fadd`/`fmul`/`fma` with explicit
rounding metadata), SMT (z3's `FloatingPoint` theory, which makes FP semantics
*provable* rather than merely testable — the most valuable part). PyRTL has no
FP, so hardware-facing output stays integer-only.

**Implemented for `fadd`/`fsub`/`fmul`/`fdiv` at f32 and f64.** The harness
concern that motivated staging this separately turned out to be answered by the
bit-pattern design: because the operators return bit patterns, the existing
`c_vs_golden`/`rust_vs_golden`/`llvm_vs_golden` comparisons already check
exactly the right thing, and no new comparison logic was needed. What did need
adding was *coverage*: float entries now get FP-shaped sample vectors (signed
zeros, signed infinities, quiet and signalling NaNs, the normal extremes, the
smallest subnormal), because random bit patterns land on an infinity or a NaN
too rarely to rely on. Removing the canonicalization from one backend fails 12
of 448 checks, so the rule is load-bearing rather than decorative.

Single precision computes through Python doubles in the golden model and rounds
to f32 after each step. That is safe for these four operations — binary64
carries more than 2p+2 bits of the binary32 significand, so double rounding
agrees with rounding once — and it is the reason `fmul.s` is worth having in the
corpus: a backend that computed in double and narrowed at the end would
double-round and disagree.

**SMT uses the FloatingPoint theory, so these semantics are proven rather than
sampled.** `emit-smt2` selects `QF_BVFP` when a document uses float operators
(integer-only documents keep `QF_BV`, so their artifacts are unchanged), lowers
each operator through `fp.add`/`fp.sub`/`fp.mul`/`fp.div` with an explicit `RNE`
rounding mode, and reinterprets bit patterns with `to_fp`. `smt_vs_golden.py`
then asks z3 to *refute* equality with the golden model and requires `unsat` for
every case — a proof per case, not a comparison.

The canonical-NaN rule turned out to be what makes that possible. SMT-LIB leaves
`fp.to_ieee_bv` deliberately unspecified for NaN, since NaN has many bit
patterns, so a NaN case would be unprovable as stated. Selecting the canonical
pattern on `fp.isNaN` first removes the underspecification. A convention adopted
for cross-platform determinism turned out to be the precondition for provability
— worth noting, because it is the sort of thing that looks like mere tidiness
until a solver refuses the underspecified form.

`fsqrt` and `fma` are implemented. `fma` is spelled explicitly because the
fusion is observable: one rounding versus two, differing on
`a = 1 + 2^-52, b = 1 - 2^-52, c = -1` where the unfused form cancels to `+0.0`
and the fused form keeps `-2^-104`. The corpus carries both instructions and
`tools/fp_fusion_check.py` requires them to disagree, which is what proves no
backend contracted the unfused one.

Contraction cannot reach the generated artifacts: an unfused multiply-add
lowers to `axis_fp64_add(axis_fp64_mul(a, b), c)`, and the intermediate
round-trips through a bit pattern and a NaN test, which no compiler can fuse
across. Verified by compiling the witness with `-ffp-contract=fast` and finding
the two instructions still distinct. The flag still matters for *consumer* code
that writes plain float expressions; it is not a requirement AXIS's own output
imposes.

Comparisons are implemented: `fcmp_oeq`, `fcmp_olt`, `fcmp_ole`, and
`fcmp_uno`, returning 1 or 0 at the operator's width. They are the clearest case
for why FP is not bit manipulation — `-0.0` and `+0.0` must compare equal while
NaN must not equal itself, so a bit comparison gets both wrong in opposite
directions. The ordered forms are false whenever either operand is NaN, and
`fcmp_uno` makes that unorderedness observable rather than implicit in three
predicates all being false. In SMT this required `fp.eq`, IEEE equality, rather
than SMT-LIB's structural `=`, which would have reported the two zeros unequal
and NaN equal to itself.

Conversions are implemented: `fcvt_f2s`, `fcvt_f2u`, `fcvt_s2f`, `fcvt_u2f`,
and `fcvt_f2f`. Like the extends they carry two widths — the type atom names the
destination, the first literal argument the source — so they lower through
`Sem::Ext` and reuse that machinery rather than adding a third shape.

Float to integer rounds toward zero, **saturates**, and maps NaN to 0. That had
to be specified rather than inherited: a C cast is undefined out of range, ARM
saturates, and x86 returns the most negative integer, so an unstated rule would
mean three different things. The backends divide neatly along whether they
already agree with it — Rust's `as` cast and LLVM's `fptosi.sat`/`fptoui.sat`
intrinsics implement precisely this behaviour, while C needs explicit range
tests because its cast is undefined there. (The plain `fptosi`/`fptoui` LLVM
instructions are poison out of range and would have been the wrong choice.)

SMT proves the conversions as well, which took reconstructing the saturation
rather than calling the solver's conversion. SMT-LIB's `fp.to_sbv`/`fp.to_ubv`
are *unspecified* for NaN and for out-of-range inputs — exactly the cases AXIS
makes total — so the lowering tests NaN first, then each threshold, and reaches
the conversion only on inputs it defines.

The thresholds are where the care went. Saturating when `v >= 2^(w-1)` is
exact. On the negative side, saturating when `v <= -2^(w-1)` looks too eager,
since `-2^(w-1) - 0.5` is out of range only after rounding — but every value in
that band truncates toward zero to exactly the minimum, which *is* the
saturation value, so the simpler condition is equivalent. That was checked
exhaustively at a small width before being written, rather than reasoned about
once and trusted.

Non-vacuity was checked directly: asserting the correct result for `+inf` and
for NaN gives `unsat` (proven), and asserting a wrong one gives `sat`. So all
five semantics backends now cover the whole scalar FP surface, and the fifth
proves it.

**FP reaches the effect layer.** `FCMPS_S` and `FCMPS_D` compare and write a
four-bit float condition code to named architectural state, which is how a real
ISA spells a comparison (AArch64 FCMP writes NZCV). They are proven by all three
executors — Python, C, and Rust — which compare `setstate` writes as part of the
architectural delta.

That removed the blocker recorded here earlier: the wide executor ABI's own
expression lowering had no float operators. Teaching it surfaced two defects
worth recording, both of the same kind.

First, the wide lowering kept a *local copy* of "what is a type atom", testing
only for `i` and `u`. When `f32`/`f64` arrived it treated `f64` as an unbound
symbol and silently emitted `axis_state64_read(state, "f64")` — a state read of a
register that does not exist, which would have quietly computed with zero. Both
lowerings now call `ir::type_atom_bits`. This is the fourth time in this area
that a re-derived predicate has drifted from the one it copied.

Second, the wide ABI holds every value in 64 bits, so a single-precision helper
needs its arguments narrowed. C accepted the mismatch through implicit
conversion and would have kept working by luck; Rust rejected it outright. The
narrowing is now explicit in both, and the episode is a small argument for
keeping a backend that refuses to guess.

Still open for FP: FPCR-driven rounding modes and FPSR exception-flag
accumulation. The state machinery is now demonstrably in reach — a float
instruction can write named state and be proven doing it — so what remains is
choosing how a rounding mode reaches an operator that currently hard-codes
round-to-nearest-even.
The effect-layer work has a known prerequisite: the wide executor ABI's own
expression lowering (`c_wide_expr` and its Rust twin) does not know the float
operators, so an FP instruction that writes NZCV or FPSR needs that path taught
first. The last two are why FP
arithmetic is ultimately effectful; the operators here are the subset that opts
out of flag updates.

## 7. Stage F2 — FP SIMD (implemented)

The composition of V1 and F1: lane-wise IEEE-754, in
[`examples/simd_fp_lanes.axisl`](../examples/simd_fp_lanes.axisl) — the AArch64
2S, 4S and 2D shapes over `fadd`/`fsub`/`fmul`/`fdiv`/`fsqrt` — proven on the
golden model, SMT, C, Rust, LLVM, and the executor.

It was cheap, and *why* it was cheap is the point. The lane extraction is
bit-vector work regardless of the element domain, because an AXIS float is a bit
pattern: shift the lane down, mask it, hand it to the operator, mask and place
the result. So the only thing a float lane changes is the type atom the per-lane
operator is given — `f32` instead of `i32`, one line in `expand_lanes`. That is
the return on having built the lane machinery domain-agnostically in V1 rather
than as integer-SIMD.

Comparisons are deliberately excluded. An AArch64 lane-wise compare writes a
lane *mask* of all-ones or all-zeros, not the 1/0 the scalar `fcmp_*` operators
return, so accepting `(fcmp_oeq v2f32 …)` would quietly mean the wrong thing;
lane masks need their own operator, which is a separate decision rather than a
free consequence of this one.

What it did surface is a bug two layers down. A float operator's width is its
own, not the enclosing function's, and F2 is the first thing that puts an `f32`
operator inside a 64-bit evaluation word — a scalar `f32` instruction has 32-bit
operands, so its word was 32 too, and the question never arose. Both the LLVM
and Rust emitters bitcast straight from the function word: `bitcast i64 to float`
is not a cast LLVM has, and `axis_fp32_add(u64, u64)` is not a call rustc
accepts. C accepted the same code through implicit integer conversion, which is
the worse outcome of the three — it would have compiled and computed on a value
narrowed by a rule the emitter never stated. All three now narrow to the float's
width and widen back explicitly, spelled out on every side rather than left to
what each language tolerates.

## 8. Stage F3 — the FP effect layer (implemented)

### 8.1 What makes this different

Every AXIS operator today is a pure function of its arguments and its width.
`(fadd f64 a b)` means one thing, everywhere, forever. A rounding mode breaks
that: the same instruction with the same operands produces a different result
depending on FPCR, a register some *other* instruction wrote. This is the first
construct in the language whose meaning depends on machine state, so the shape it
takes is worth deciding deliberately rather than discovering.

### 8.2 The operator shape

Two options were considered:

* **Read FPCR implicitly.** Faithful to the ISA — an AArch64 `FADD` really does
  consult FPCR without saying so — but it makes every floating-point operator
  state-dependent, which is exactly the property all six backends currently rely
  on not being true. The typed IR would stop being a function of its arguments.
* **Take the mode as an argument.** The operator stays pure; the state dependency
  moves into the behavior, where it is visible.

The second, with the mode **first** among the arguments:

```lisp
(set fd (fadd_rm f64 (and (lshr fpcr 22) 3) fn fm))
```

Mode-first rather than mode-last because these operators fold n-ary: a trailing
argument is ambiguous with a third addend, a leading one is not. The mode is an
ordinary 2-bit integer expression, which means an AArch64 behavior spells the
FPCR field with operators the language already has — `(and (lshr fpcr 22) 3)`
extracts `FPCR.RMode` — and needs no new ISA-specific helper. The encoding is
AArch64's: `00` nearest-even, `01` toward +infinity, `10` toward -infinity, `11`
toward zero.

The existing `fadd`/`fsub`/`fmul`/`fdiv`/`fsqrt` keep their meaning as
round-to-nearest-even, so nothing already proven changes.

### 8.3 Per-backend feasibility, measured

| Backend | Directed rounding | How |
|---|---|---|
| `golden_model.py` | yes | exact rational, then one ulp in the requested direction |
| `semantics.smt2` | yes | a `RoundingMode` variable selected from the mode bits |
| `axis_semantics.h` (C) | yes | `fesetround` under `#pragma STDC FENV_ACCESS ON` |
| `axis_semantics.ll` | **no** | `llvm.experimental.constrained.*` constrains the optimizer, it does not round |
| `axis_semantics.rs` (Rust) | **no** | no rounding-mode control in `std` |
| PyRTL | n/a | no float support |

Both "yes"es that carried risk were checked before committing to the design
rather than assumed:

* The golden algorithm — compute the round-to-nearest result with ordinary float
  arithmetic, compare against the exact value as a `Fraction`, and step one ulp
  with `math.nextafter` when the mode asks for it — was checked against C's
  `fesetround` over 64000 comparisons across all four modes and four operations,
  and agrees exactly. The probe earned its keep immediately: the first version
  returned the round-to-nearest result unchanged on overflow, and every one of
  its 1916 failures was an overflow case. IEEE-754 does not say "infinity" when a
  result overflows; it says round the exact value in the requested direction, and
  only two of the four directions can reach infinity. Toward zero gives the
  largest finite value in both signs, and each directed mode gives it in one
  sign.
* z3 accepts a `RoundingMode` as a free variable constrained by an `ite` chain
  over the mode bits, and proves it equivalent to the literal mode. The mode does
  not have to be static.

The LLVM row is a **correction to the first version of this section**, which
claimed directed rounding was expressible there "verbosely" via a four-way switch
over the constrained intrinsics. That was written from the LangRef and is wrong.
Built and measured, the switch returns the *identical* value for all four modes,
including under `-ffp-model=strict`, while C's `fesetround` returns three
distinct values for the same operands. The metadata argument to
`llvm.experimental.constrained.*` tells the optimizer that the rounding mode is
not known to be round-to-nearest, so it must not fold as if it were; it does not
make the arithmetic round that way. The rounding still comes from the hardware
floating-point environment, and emitted IR has no portable way to set it. Two
backends decline for the same underlying reason — no per-operation rounding
control — and one of them can at least say so in the IR.

This is a claim about the host LLVM, not about LLVM in principle, so it is
checked on every run rather than remembered. `tools/fp_rounding_check.py` asks
the host to add the same two numbers under `round.downward` and `round.upward`
and requires the same answer back; on LLVM 15 both calls select a bare
`fadd s0, s0, s1`, the mode having been parsed, verified and then dropped. The
day that stops being true the gate fails, and the failure is the good news: it
names the declines in `src/lifter.rs` and `src/emit/llvm.rs` that can then be
lifted, and the 137 instructions across RISC-V and AArch64 that would come
back with them.

### 8.4 Why Rust and LLVM are excluded, and what that costs

Rust's `f64` arithmetic is round-to-nearest-even with no way to change it: `std`
exposes no `fesetround`, and reaching for `libc` would put an FFI dependency in
a generated file whose value is being dependency-free. The alternative is
implementing directed rounding arithmetically — exact comparison in `u128`, or a
soft-float core — and that is precisely what section 1 rules out: *a second,
unproven model of arithmetic every backend would have to agree on*. Emitting it
would trade a stated limitation for an unstated risk.

So the Rust and LLVM emitters decline these operators with the reason in the
file, which is a pattern this project already has: the C header declines 128-bit
integers because standard C has none, and `simd_q_lanes` is proven on four
backends rather than five with that recorded rather than hidden. Directed
rounding is proven on the golden model, SMT and C — three independent
implementations, one of them a solver — and the other two keep the
round-to-nearest operators they already have.

The alternative is worse than the gap: lowering these to plain `fadd` would round
to nearest under every mode, and *no gate could see it*, because each mode's
answer would still be a plausible floating-point result. A stated limit is
checkable; a silent one is not.

### 8.4.1 What the implementation cost, in bugs

Three, all found by the gates rather than by reading:

* The golden model stepped one ulp with `math.nextafter`, which moves a *double*
  ulp whatever the format. Every single-precision case needing an adjustment
  overshot — 50 of 640. The step is done on the bit pattern now, which is one
  representable value by definition in either format.
* IEEE-754 §6.3: an exactly-zero sum or difference is `+0` under every rounding
  direction except toward-negative, where it is `-0`. z3 knew; the golden model
  did not.
* And the carve-out to that rule — `x + x` keeps x's sign even when x is a zero —
  is about the *effective* operands, so `(-0) - (+0)` is `(-0) + (-0)`, like
  signs, and keeps the sign rather than cancelling. C caught that one.

Each was a disagreement between two independent implementations of the same
specification, which is the entire argument for having three.

### 8.5 Exception flags (implemented)

FPSR accumulation (`IOC`, `DZC`, `OFC`, `UFC`, `IXC`) is a state write with an
`or`, which the effect layer already expresses; the work is in *detecting* each
condition. Invalid, divide-by-zero and overflow are computable from the operand
and result values alone. Inexact and underflow need to know whether the exact
result was representable, which is the same exactness test the golden algorithm
above already performs — and the same test Rust cannot perform without the
machinery 8.4 rejects. The split therefore lands in the same place.

The operators are the `_fx` forms of the value operators: `fadd_fx`, `fsub_fx`,
`fmul_fx`, `fdiv_fx`, `fsqrt_fx`, `fma_fx`, and the five conversions
`fcvt_f2s_fx`, `fcvt_f2u_fx`, `fcvt_s2f_fx`, `fcvt_u2f_fx`, `fcvt_f2f_fx`. Each
takes exactly its value form's arguments and returns the flag word, so the two
spellings read against each other at a glance. They take **no** rounding mode:
which exceptions an operation raises does not depend on the direction, except
for inexact, and an inexact result is inexact under every mode. RISC-V's
`fflags` is the same five bits under other names — `NV`, `DZ`, `OF`, `UF`, `NX`
— and `examples/rv32i.axisl` and `examples/rv64i.axisl` accrue them.

### 8.5.1 What comparisons and conversions needed that arithmetic did not

Two things, and they pull in opposite directions.

Comparisons needed **no new operator at all**. `FLT`/`FLE` signal invalid on any
NaN and `FEQ` only on a signalling one, and both are predicates on the bit
pattern — the same fact `FCLASS` is built from — so they are written in the
corpus as ordinary `defsem`s over the existing integer operators and every
backend lowers them, including SMT and Rust, which decline every `_fx`
operator. The rule that looked like it needed the floating-point environment
turned out to need only the mantissa's top bit.

Conversions needed the operators, and one of them could not use the
floating-point environment even in C. AXIS specifies float-to-integer as
truncate-saturate-NaN-to-zero, so the C cast whose flags `fetestexcept` would
report is undefined in exactly the out-of-range case that has to signal.
`axis_fp_to_int_fx` therefore decides invalid and inexact explicitly, and the
two are exclusive: a result that saturated reports that it did not fit, not
that it was rounded. The other four conversions are ordinary C conversions and
do read the environment.

The golden model answers all of them from exact integers and rationals rather
than from a rounded intermediate — for integer-to-float it strips the trailing
zeros off the integer and asks whether what is left fits the significand, which
needs no float arithmetic at all and so stays exact for a source wider than a
double's 53 bits.

### 8.5.2 Two rules IEEE-754 leaves to the implementation

**Tininess is detected before rounding.** IEEE-754 §7.5 permits either rule and
requires an implementation to say which. AXIS detects *before*: underflow asks
whether the exact result fell below the smallest normal, not whether the rounded
one did. The two differ in one narrow window — an exact result just under the
smallest normal that rounds up to it — and it is reachable: the fused
multiply-add of `2^-126`, `-2^-149` and `2^-126` has an exact sum a hair below
`2^-126` that rounds to exactly `2^-126`. Before-rounding says underflow and
inexact; after-rounding says inexact alone.

Before-rounding is what x86 and AArch64 do, which is why the C backend can read
underflow from the floating-point environment instead of reconstructing it. The
golden model originally detected after, and agreed with C on every case anyone
had run until an executor drew its operands from FP classes rather than uniform
bits.

**Integer-to-float rounds once.** `(float)(double)n` is two roundings, and for a
source wider than a double's 53 bits it disagrees with the one IEEE-754 asks
for: `9223372586610589697` sits one unit above the midpoint between two binary32
values, so it rounds up — but rounding to 53 bits lands it exactly *on* that
midpoint, where ties-to-even takes it back down. The golden model, the C header,
the Rust module and both wide executors all went through a double; z3's `to_fp`
and LLVM's `sitofp` round once, and were right.

Nothing caught it, for a reason worth recording. No 32-bit source can reach the
hazard — a double holds every `int32` exactly, so the intermediate is not a
rounding at all — and RV64's long conversions, the first instructions that could
ask, did not exist. When they were added, the differentials still passed: the
window is one in 2^39, and every gate that samples operands draws uniformly.
`smt_vs_golden` carries the witnesses now, beside the ties-to-even ones that are
there for the same reason.

### 8.5.3 Why a differential ladder cannot check this, and what does

The rules are stated once, in the corpus, and every backend reads that one
statement. A comparison that signalled on the wrong kind of NaN would be
emitted identically by all six and every differential would pass — the same
argument that `FCLASS` needed its own gate, one level along.
`tools/fflags_check.py` closes it: a table of witnesses whose expected flags are
written from the RISC-V spec, and a property sweep over random patterns for the
invariants no finite table shows — that an ordering comparison signals on every
NaN and an equality on exactly the signalling ones, that a widening conversion
is never inexact, that overflow and underflow never appear without inexact, and
that no conversion ever divides by zero. Five injected defects were each
required to fail it before it was trusted.

The same gate carries the arithmetic rules the executors later caught the model
getting wrong: that an invalid product signals whatever the addend is, a quiet
NaN included (IEEE-754 §7.2); that infinity minus itself has no value; that a
signalling NaN signals — which the golden model decided by reading the pattern
*back through a Python float*, the one place a signalling NaN stops signalling,
so every one of them read as quiet; and where AXIS puts tininess.

### 8.6 The second ISA, which is the actual test of 8.2

Section 8.2 argued the operator shape from AArch64 and then it was built for
RISC-V, which is a way of not answering the question. `examples/aarch64_fp_env.axisl`
answers it, and the two halves answer differently.

**The rounding mode ports for free, as claimed.** `_rm` takes the encoding
AArch64 uses — 00 nearest, 01 toward +infinity, 10 toward −infinity, 11 toward
zero — so `FPCR.RMode` reaches the operator through `(and (lshr fpcr 22) 3)` and
nothing else, exactly the expression 8.2 wrote. RISC-V is the ISA that maps: its
RTZ is 1 and it passes 3, its RDN is 2 and passes 2, its RUP is 3 and passes 1.
The encoding in the operator was AArch64's all along, and the corpus that needed
a translation table was the one it was built for.

AArch64's field is also two bits, so every value of it names a mode, and these
instructions carry no trap arm — where RISC-V's three-bit `frm` has two reserved
values and its DYN forms must trap on them. A description that states a trap
only where the ISA has one is the description working.

**The exception word does not port.** `_fx` returns RISC-V's `fflags` order,
invalid at bit 4 down to inexact at bit 0; AArch64's FPSR is that order
reversed, IOC at bit 0 up to IXC at bit 4. Overflow sits in the middle and is
the only bit that does not move. The corpus states the reversal as an ordinary
expression over operators that already existed — which is the same argument the
mode makes, reached from the other side: the operator does not need to know the
ISA, because the behavior can say what the ISA wants.

Whether the asymmetry is worth removing is a real question and the answer here
is no. Canonicalising the flag word to some third order would leave *both* ISAs
mapping instead of one, and the mapping is six lines of shifts either way.

**And it is not checkable by differential.** The reversal is stated once and
read by six backends, so all six would agree about the wrong order — the same
argument `FCLASS` and `fflags_check` needed, now for a bit numbering rather than
a rule. `tools/a64_fpenv_check.py` requires each condition to land on the
AArch64 bit *by number*, and for the mode requires the IEEE relations between
directions rather than restating a rounding algorithm: toward +infinity lands
above toward −infinity, nearest lands on one of those two neighbours, and toward
zero agrees with whichever faces zero for that sign. Three injected defects were
each required to fail it — the FPSR left in fflags order, the modes 01 and 11
swapped, and FPCR not consulted at all.

### 8.7 The corpus where the registers actually live

Section 8.6 answers the design question and does not close the gap it names:
the translation seed is where `FPCR` and `FPSR` are declared and where
`MRS`/`MSR` read and write them, and it had no floating-point arithmetic to
consult them. It has scalar double add, subtract, multiply, divide and square
root now, each with an accelerator counterpart and a lowering between them,
because a source instruction in that corpus is only half a description. The two
`FMOV` forms come with them, since without a move a `V` register could only ever
be written by the arithmetic that reads it.

`a64_vreg64` is a new register class: a separate file above the
general-purpose one, for the reason `rv_fpr` is one, because `d0` is not `x0`.

**The moves cost more than the arithmetic did, and what they cost is the
finding.** They are the first pair in any corpus that differs by *nothing but
which file its operands live in* — both move sixty-four bits — and three
separate places could not tell them apart:

* The translation map reported every register operand's class as `reg`, so the
  two keyed identically and each matched *both* accelerator targets. It reports
  the lowering family now, which is `reg` for every general-purpose class and so
  changes nothing that already worked.
* `translation_vs_golden` decided which operands were registers by comparing
  that class to the string `reg`, so an operand in any other file was skipped
  and read back as zero. The map states `register` outright now.
* The same driver keyed its register dictionary by index while the executors key
  theirs by `offset + index`, which agree only for a file at offset zero. The
  map states `slot_offset`, and the driver uses it.

Each was correct for as long as there was one register file to be wrong about.
Reverting the first alone brings back four mappings where there should be two,
and fails the gate.

`tools/a64_fpenv_check.py` runs against both corpora. It resolves mnemonics and
binds witnesses positionally, because the two spell these differently —
`vn`/`vm` in the focused corpus, `rn`/`rm` in the seed, which spells them the way
AArch64 does — and the rules being checked do not depend on the spelling.
