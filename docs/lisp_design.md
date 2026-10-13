# Lisp-Authored AXIS Design

Status: migration complete. All six stages are implemented: the reader,
compositional `let`/`if`, typed `defsem` functions, the document elaborator,
behavior unification, bounded families and property fragments, and corpus
migration. `.axisl` is the authoring default and every legacy example has a
verified canonical counterpart; the block grammar remains supported as an
explicitly selectable compatibility frontend. **Every corpus round-trips
through `emit-lisp` to byte-identical artifacts** — all 55, nothing excluded —
and `tools/lisp_roundtrip.py` fails otherwise, so this line is enforced rather
than counted.

## Direction

AXIS will become a Lisp-authored, statically elaborated architecture language.
Lisp is the authoring and composition layer; it is not the execution model.
Every accepted module expands into the same deterministic typed document,
semantic, and behavior IRs consumed by the existing generators.

This separates five concerns:

1. The reader recognizes lists, atoms, strings, quoting, comments, and spans.
2. Hygienic expansion handles reusable definitions and instruction families.
3. Elaboration resolves names, widths, operands, state locations, and formats.
4. Validation checks the resulting typed IR without depending on source syntax.
5. Backends consume only typed IR and never interpret macros or source forms.

The language remains total during compilation: no arbitrary I/O, unbounded
recursion, ambient host-language access, or order-dependent mutation.

## Proposed module surface

```lisp
(axis-module aarch64-base
  (version "0.2.0")

  (defisa aarch64
    (role source)
    (word-bits 64)
    (registers "x[31]:i64" "sp:i64" "nzcv:i4"))

  (defformat add-sub-extended
    (bits 32)
    (fields
      (sf 31)
      (op 30)
      (s 29)
      (fixed 28 24)
      (rm 20 16)
      (option 15 13)
      (amount 12 10)
      (rn 9 5)
      (rd 4 0)))

  (definstruction ADD-X-EXT
    (isa aarch64)
    (format add-sub-extended)
    (encoding (sf 1) (op 0) (s 0) (fixed #b01011))
    (operands
      (rd a64_gpr64sp i64 out)
      (rn a64_gpr64sp i64 in)
      (rm a64_gpr64 i64 in)
      (option imm i3 in)
      (amount imm i3 in))
    (requires (a64-extended-reg amount))
    (behavior
      (set rd
        (let ((rhs (a64-extend-reg i64 rm option amount)))
          (add i64 rn rhs))))))
```

Names are case-sensitive symbols. Keywords are ordinary symbols interpreted by
the elaborator, rather than reader-level syntax. Binary, hexadecimal, and
decimal literals all become width-checked bit-vector constants.

An operand may derive its architectural register selector from a directly
encoded operand:

```lisp
(operands
  (rs  a64_gpr64 i64 inout)
  (rs2 a64_gpr64 i64 inout (derive rs 1)))
```

The derived operand consumes no instruction bits. Decode and Python/C/Rust
lifters compute its selector after extracting `rs`, while semantics still see
`rs` and `rs2` as independent register values. Validation requires a positive
offset, an existing directly encoded source, and identical register kind and
width. This models implicit adjacent registers without inventing unencoded
operands and is the register-side prerequisite for AArch64 `CASP`.

An operand may instead name one register that no bits select:

```lisp
(operands
  (zt  vreg i32 inout)
  (ffr preg i32 inout (fixed 16)))
```

`(fixed k)` is register `k` of the operand's class, known at decode like a
field-bound selector, so a scalable operand's lanes place into it as they do
into any other. It consumes no bits, takes no derivation, and needs a class
with no aliased index. SVE's FFR is the case that asked: a predicate every
first-fault and non-fault load reads and clears, which the corpus holds as the
seventeenth register of the predicate file.

## Semantic language

The pure semantic subset starts with:

- typed bit-vector arithmetic, Boolean/bitwise operations, shifts and rotates;
- `let` with sequential lexical bindings, so a binding may name the ones
  before it and a chain of steps reads as a dataflow block;
- `if`/`select`;
- extensions, truncation, extraction, concatenation, and replication;
- comparisons and bounded `match`;
- parameterized `defsem` functions, elaborated and inlined before backends.

`let` is implemented by substitution into the typed `Sem` IR: each binding is
lowered against the scope its predecessors have already extended, and the
result is inlined, so no `Let` node reaches a backend. That is what lets a
description be written as a flat sequence of named steps

```lisp
(let ((sum        (add i32 rs1 rs2))
      (same-sign  (icmp_eq i32 (and i32 (xor i32 rs1 rs2) 0x80000000) 0))
      (flipped    (icmp_ne i32 (and i32 (xor i32 rs1 sum) 0x80000000) 0))
      (overflowed (and i32 same-sign flipped)))
  (select i32 overflowed limit sum))
```

while staying a single pure expression underneath -- the shape a saturating
lane operator needs, without a statement form or an assignment. `if`
lowers to `Op::Select`, which all semantic backends implement. `defsem`
parameters and results carry bit-vector widths; calls are arity- and
width-checked, nested calls inline hygienically, and direct or indirect
recursion is rejected before backend lowering.

The effect subset uses Lisp statements directly:

```lisp
(behavior
  (set rd
    (let ((address (add i64 rn offset)))
      (load i32 unsigned address)))
  (set rn (add i64 rn writeback))
  (when (eq alignment-fault 1)
    (trap misaligned)))
```

Behaviors remain ordered lists of typed effects. Pure expressions cannot mutate
state. Guards and trap conditions are explicit, making control and exceptional
behavior visible to analysis. Implemented statements are `set`, `setreg`,
`setstate`, `store`, `barrier`, `setpc`, `trap`, and `when`. `barrier` carries
a static architectural kind plus a typed option expression without
pretending that synchronization is a memory access. Behavior expressions support
`defsem` calls and lexical `let`; guards currently support equality and
inequality. Each value, address, load address, and guard carries its resolved
evaluation width in canonical behavior. This is independent of the location's
write width: an i64 flag computation may write `nzcv:i4`, while an i32 load may
evaluate its address in i64.

Decode legality is expressed with typed Lisp predicates under `requires`.
Unsigned `=`, `!=`, `<`, `<=`, `>`, and `>=` comparisons compose with `and`,
`or`, and `not`. `(masked-eq operand mask value)` constrains selected operand
bits; for example `(masked-eq rs 1 0)` requires an even register selector.
The architecture-specific predicates `a64-logical-imm`,
`a64-shifted-reg`, and `a64-extended-reg` remain available as typed leaves:

```lisp
(requires
  (and (< amount 5)
       (not (= option 7))))
```

Both source frontends parse legality once into `Instruction.decode_constraint`.
Validation, encoders, decoders, and Python/C/Rust lifters consume that recursive
tree directly; the compatibility `decode_requires` text is reflection and
diagnostic data only. See
[`examples/lisp_constraints.axisl`](../examples/lisp_constraints.axisl).

[`examples/lisp_behaviors.axisl`](../examples/lisp_behaviors.axisl) exercises
memory, control flow, traps, named architectural state, helper expansion, and a
reserved encoding.

Multi-access architectural operations use explicit transaction groups:

```lisp
(behavior
  (atomic-group 1
    (set rs (atomic-load i64 unsigned acquire rn))
    (set rs2 (atomic-load i64 unsigned acquire (add i64 rn 8)))
    (when (and (= rs (input rs)) (= rs2 (input rs2)))
      (atomic-store rn rt i64 release))))
```

The positive group id marks all enclosed ordered effects as one indivisible
architectural transaction. Groups must be contiguous, contain at least two
effects, and include an atomic load or store. Boolean `when` guards compose
equality predicates with `and`, `or`, and `not`; `input` observes the operand
value captured before the instruction began.

## Reuse and macros

`defsem` is semantic reuse and participates in type checking. Instruction
families use hygienic, bounded expansion rather than unrestricted procedural
macros. A family may iterate over a literal list of widths, opcodes, or flag
variants, but expansion must have a statically known finite result.

Declaration properties can be shared with bounded fragments:

```lisp
(defproperties accelerator-runtime
  (profile scalar)
  (backend-kind auto)
  (fallback-policy software))

(defaccelerator nearasic0
  (family nearasic)
  (use-properties accelerator-runtime)
  ...)
```

Fragments may be forward-declared and nested. `(use-properties name)` splices
at its exact position, so later properties preserve normal override order.
Unknown fragments, duplicate definitions, and direct or indirect cycles are
rejected. At most 16,384 properties may be inserted per module. Fragments are
also expanded inside instruction-family templates before row substitution, so
the resulting declarations still pass through the ordinary typed elaborators.

The implemented family form is a literal row table plus one instruction
template:

```lisp
(definstruction-family add-sub
  ($name $opcode $operator)
  ((ADD-X 0 add)
   (SUB-X 1 sub))
  (definstruction $name
    (encoding (op $opcode))
    (formal ($operator i64 rn rm))))
```

Parameters must begin with `$`, every parameter must be used, rows have fixed
arity, duplicate expanded instruction names are rejected, and a module may
expand at most 4096 family instructions. There is no procedural evaluation,
recursive expansion, ambient access, or string interpolation. Supplying a
complete string as a row literal handles assembly and descriptive text.

[`examples/lisp_aarch64_family.axisl`](../examples/lisp_aarch64_family.axisl)
uses one template for the W/X ADD/SUB shifted-register variants, including
operand kinds, semantics, fixed encoding fields, and typed legality
constraints.

### Functions that stay functions: `deffun`

`defsem` is substituted where it is used, and every backend pastes a bound
value's text where it is read, so a definition that names its parameters
several times grows with each level it is nested: written as Arm's pairwise
tree, SVE's FMAXV over halves rendered to 142 MB of C, and AES's S-box over a
gather to 11 MB. `deffun` is the other kind of reuse -- emitted once by every
backend, and called:

```lisp
(deffun mix ((a i32) (b i32)) i32
  (xor i32 (add i32 a b) (xor i32 (rotl32 a 7) (sub i32 b (rotl32 a 13)))))

(definstruction fnest ...
  (formal (mix (mix (mix rs1 rs2) rs2) rs1)))
```

A use is written as a `defsem`'s is, and elaborates to
`(call mix i32 (i32 rs1) (i32 rs2))`: the result type, and each argument with
the width its parameter reads it at, so a backend lowers a call without the
definition in hand. The golden model and PyRTL evaluate the body in an
environment of its parameters; C and Rust emit `static inline` functions and
`fn`s (once per evaluation tier that can hold them, prototypes first in C);
LLVM `define internal`; SMT one `define-fun` each; the wide executors their
own copies; lane expansion passes a call through with its arguments taken at
the lane. A function is pure, scalar and non-recursive; its body may inline
`defsem`s and call other functions, which the document orders callees first.
`emit-lisp` writes the functions and their calls in the elaborated form, which
the reader takes as it stands, and a call that disagrees with its definition is
refused. OptiSynth's dialect and LLVM selection patterns have no call, so an
instruction using one is declined there by name.

`tools/deffun_check.py` holds the one thing the backend gates cannot: that a
call computes what the same function inlined does. Every backend is compared
with a golden model that calls the function too, so a calling mistake they all
shared would pass them; the gate reads the corpus a second time with each
`deffun` as a `defsem` and requires the two golden models to agree.
[`examples/functions.axisl`](../examples/functions.axisl) is the corpus: a
plain call, a narrower function, a function calling functions, and a call
nested eight deep that inlined would be 3^8 copies of its innermost argument.

## Explicit translation lowerings

`deflowering` describes a source instruction sequence and one target
instruction using shared `$value` bindings:

```lisp
(deflowering fuse-a64-add-chain
  (source
    (A64_ADD (rd $tmp) (rn $lhs) (rm $rhs))
    (A64_ADD (rd $out) (rn $tmp) (rm $addend)))
  (target
    (ACCEL_ADD3
      (rd $out) (rs1 $lhs) (rs2 $rhs) (rs3 $addend)))
  (requires
    (and (!= $tmp $lhs)
         (!= $tmp $rhs)
         (!= $tmp $addend)))
  (source-cycles 2)
  (target-cycles 1)
  (benefit 2.0))
```

Source bindings are SSA-like: outputs define values and later inputs consume
them. At most one register result may remain; a source AArch64 zero-register
output may instead be the literal 31. All operands must be bound;
redefinitions, missing/unknown operands, incompatible value classes or widths,
unknown predicates, and source/target ISA-role mistakes are rejected. Target
inputs must be exactly the external source inputs and its optional output must
name the final source result.

Validation composes the typed semantics of every source step, substitutes the
bindings, and requires structural semantic identity with the target
expression. A step may have multiple encoded register results plus ordered,
unconditional register, named-state, and memory effects; every result and the
complete effect order must match exactly. An
AArch64 `a64_gpr64`/`a64_gpr32` output may bind literal 31 to state that its
computed value is discarded through XZR/WZR. The target then exposes no
register result and must preserve the state effects.
The translation manifest records the source sequence, encodings,
operand/value bindings, recursive predicate, cost, preserved named state,
original operand kinds, memory effects, and `semantic_equivalence: proven`.
Unconditional loads and
stores participate with exact access width, signedness, address, value, and
effect order. One-step pre/post-index writeback is supported through `inout`
bindings. PC writes participate with their exact target expression and an
optional guard. Unconditional fixed-register writes participate by normalized
register class, index, explicit width, value, and order; the typed
`(setreg reg 30 i64 value)` form lets a custom target state its link-register
convention without borrowing an AArch64 operand kind. Other guarded effects,
traps, and fault behavior remain outside the proof boundary.

[`examples/lisp_lowerings.axisl`](../examples/lisp_lowerings.axisl) contains
the complete two-add-to-ADD3 example. `axis emit-translation-python` generates
a standalone matcher/rewriter with `match_at`, `rewrite_once`, and
`rewrite_all`; it extracts encoded operands, unifies variables, checks
instruction and lowering predicates, and packs the target word.
`tools/lowering_vs_golden.py` checks positive matching, guard/fixed-bit
rejection, stream rewriting, and source-sequence versus fused-target execution
over edge cases and random inputs.

The canonical
[`aarch64_translation_seed.axisl`](../examples/aarch64_translation_seed.axisl)
also carries executable one-instruction lowerings for shifted-register ADD,
SUB, AND, ORR, EOR, ADDS, SUBS, CMN, CMP, unsigned-offset `LDR X`, and
unsigned-offset `STR X`, post-index `LDR X`, and pre-index `STR X` into scalar
accelerator operations, plus offset/post-index `LDP X` and offset/pre-index
`STP X`, plus direct `B`, conditional `B.cond`, indirect `BR`, `RET`, and
link-producing `BL`/`BLR`, W/X `CBZ`/`CBNZ`, and low/high-half
`TBZ`/`TBNZ`, plus W/X immediate ADD/SUB with flag-setting and CMN/CMP forms.
W/X extended-register ADD/SUB, flag-setting forms, and CMN/CMP aliases are
covered as well.
These rules prove
directly from structured `behavior`, not only from `formal` expressions.
ADDS/SUBS preserve ordered NZCV writes. CMN/CMP match through literal
`rd = 31` and produce state-only operations. LDR/STR preserve 64-bit memory
accesses, signed/scaled addresses, multiple register results, and writeback
order. Pair transfers preserve both ordered accesses and up to three final
register results. Predicates exclude encoded register 31 where it would
otherwise be treated as the accelerator's ordinary register 31.
Typed unsigned-offset memory rules additionally cover unsigned byte,
halfword, and word loads, sign-extending byte and word loads, and truncating
byte/halfword/word stores. Offset boundaries, high-bit payloads, access width,
and SP-base rejection are checked explicitly.
Register-offset LDR/STR rules preserve the scale-by-eight address and retain
SP-capable base plus XZR-capable index/data roles on the target. Runtime checks
exercise selector 31 in each role without introducing lowering guards.
W/X MADD/MSUB rules add modular three-source multiplication, including MUL and
MNEG aliases through XZR/WZR accumulators. Differential execution separately
places selector 31 in both multiplicands, the accumulator, and destination.
Branch proof preserves exact PC-relative or register-indirect targets and the
full `B.cond` NZCV guard. Runtime differential checks cover taken and
fall-through outcomes from a nonzero PC. Call proof additionally preserves the
64-bit link-register value and its ordering relative to the PC write.
Compare/test branches additionally preserve low-32-bit views and exact
low/high test-bit selection.
Immediate arithmetic preserves the zero-or-12-bit encoded shift, SP/WSP
register-31 behavior, W-result zero extension, and ordered NZCV writes.
Validation rejects a source/target mismatch in SP-aware operand kinds unless a
lowering predicate proves the selector is below 31.
Extended rules retain decode legality and exhaustively execute the 8×5 matrix
of UX*/SX* options and legal shifts.
Logical shifted-register rules cover W/X AND, ORR, EOR, ANDS, and TST. Their
runtime matrix checks all four shift modes at boundary amounts, architectural
XZR/WZR inputs, W-write zero extension, and logical NZCV effects.
Variable-register rules cover W/X LSLV, LSRV, ASRV, and RORV, including
modulo-width count masking at wrap boundaries, selector-31 zero inputs, signed
shift behavior, rotations, and W-write zero extension.
Move-wide rules cover X-form MOVN, MOVZ, and destructive MOVK for every
halfword lane and immediate boundary. MOVK is represented as an `inout`
destination and proves preservation of every unselected bit.
Logical-immediate rules cover W/X AND, ORR, EOR, ANDS, and TST using complete
six-bit mask fields. The execution matrix spans every legal `N:imms` element
shape, rotation boundaries, zero-register inputs, W zero extension, NZCV, and
reserved all-ones rejection.
Bitfield rules cover W/X SBFM, BFM, and UBFM. Every legal `immr`/`imms` pair
is executed at both widths; BFM retains its old destination through an
`inout` binding, and the complete six-bit W fields reject values above 31.

## Modes, personalities, and cores

Mode-aware decode and core declarations are available directly in Lisp:

```lisp
(defmode field-mode
  (csr 0x7c0)
  (field 1 0)
  (values (scalar 0) (simt 1) (xnn 2))
  (default scalar))

(definstruction TENSOR-MUL
  (modes xnn)
  ...)

(defpersonality simt8
  (mode simt)
  (implements rv32-axis)
  (discipline lockstep (lanes 8))
  (capsule "x[32]" pc))

(defcore pce-tile0
  (kind rvmt)
  (threads 8)
  (implements rv32-axis)
  (personalities scalar1 simt8 xnn0))

(defmemory scratchpad
  (kind scratchpad)
  (size-bytes 65536)
  (ports 2)
  (width-bits 32)
  (banks 4)
  (attributes explicit dma-visible))

(defaccelerator nearasic0
  (family nearasic)
  (descriptor-version 1)
  (descriptor-schema rvmt_nearasic_v1)
  (descriptor-bytes 68)
  (launch-abi rvmt_submit_entry)
  (completion status_addr)
  (target nearasic)
  (coupling queue_descriptor)
  (ports
    (a input bits i32)
    (b input bits i32)
    (y output bits i32))
  (formal (multiply-word a b)))

(deftile rvmt-tile0
  (cores pce-tile0)
  (accelerators nearasic0)
  (memories l1 scratchpad)
  (interconnect crossbar))
```

`defmode` values feed the existing mode-legality validator and manifest;
instruction `(modes ...)` sets participate in decode-space disjointness.
`defpersonality` binds a mode and ISA to a structured execution discipline and
portable state capsule. `defcore` composes those personalities and feeds the
same topology and manifest structures as the block frontend. `defmemory`
describes capacity, ports, latency, width, banking, and attributes; `deftile`
binds cores, accelerators, and memories through a validated interconnect.
`defaccelerator` covers descriptor, launch, coupling, MMIO/region, execution
profile, port, cost, resource, and fallback metadata. Ports use
`(name direction kind type)` tuples, and accelerator `(formal ...)`
expressions expand through the same typed `defsem` library as instructions.

An engine with **more than one output port** states one expression per port:

```lisp
(ports
  (a input bits i32)
  (b input bits i32)
  (s output bits i32)
  (d output bits i32))
(formal (result s (add i32 a b))
        (result d (sub i32 a b)))
```

Each result is typed against **its own** port's width, and every output port
must be stated -- an output with no expression is an error. The bare
`(formal <expr>)` form remains, and means the single result of a single-output
engine; using it with several output ports is refused rather than silently
defining the first. Emitters carry every result: `emit-smt2` writes one
`define-fun` per port (`axis_accel_<name>_<port>` when there is more than one),
`emit-golden-python` returns a tuple in port order, and `emit-semantics-json`
adds a `results` array beside the singular `formal_semantics` key it keeps for
existing consumers.
[`examples/lisp_modes_cores.axisl`](../examples/lisp_modes_cores.axisl)
demonstrates shared encodings in disjoint modes plus scalar, lockstep, and
systolic personalities with mutually migratable capsule layouts, two memory
classes, a descriptor-backed accelerator, and a complete crossbar-connected
tile.

## Compatibility and migration

The current block frontend remains accepted while the Lisp document elaborator
is built. Both frontends must produce the same `Document`, `Sem`, and `Behavior`
values; artifact schemas remain stable unless deliberately versioned.

Migration stages:

1. **Reader and semantic core:** span-aware reader, `let`, and `if`. Done.
2. **Semantic definitions:** `defsem`, typed parameters/results, hygienic
   inlining, arity checking, width checking, and recursion rejection. Done.
3. **Lisp document frontend:** `axis-module`, `defisa`, `defmode`,
   `defpersonality`, `defcore`, `defmemory`, `defaccelerator`, `deftile`,
   `defformat`, `definstruction`, operands, encodings, instruction mode sets,
   and compositional typed decode constraints are implemented. The typed
   document surface is complete.
4. **Behavior unification:** done. Behavior forms are parsed once into
   `Instruction.behavior`; validators and backends consume that typed tree
   directly. The source string remains diagnostic data only.
5. **Bounded families:** finite literal-table instruction generation is
   implemented. Bounded, forward-declared reusable property fragments are also
   implemented for ordinary declarations and family templates.
6. **Corpus migration:** done, and the block grammar it migrated away from has
   been removed. Every example had carried a canonical `.axisl` form generated
   with `emit-lisp` and verified to elaborate to the same typed document, so
   deleting the reader cost no description. PCE consumes emitted bundles rather
   than AXIS source, which is why `.pceadl` went with it.

   One fixture was not a duplicate: `rvmt_xpce.pceadl` was a different document
   from `rvmt_xpce.axis` and only shared a file stem — the small PCE-era
   extension manifest. It survives as
   [`xpce_manifest.axisl`](../examples/xpce_manifest.axisl).

Each stage is required to preserve differential agreement across the golden,
C, Rust, SMT, LLVM, and applicable hardware-oriented backends.

Corpus migration includes Lisp counterparts for:

- [`mode_polymorphic.axisl`](../examples/mode_polymorphic.axisl): shared
  encodings, mode legality, and illegal-in-mode execution;
- [`personality_composition.axisl`](../examples/personality_composition.axisl):
  structured disciplines, portable capsules, composed cores, and migration;
- [`rvmt_xpce.axisl`](../examples/rvmt_xpce.axisl): the primary PCE
  compatibility bundle, including instruction cost/pattern metadata, compiler
  intrinsics, a descriptor-coupled accelerator, memories, core, and tile;
- [`aarch64_translation_seed.axisl`](../examples/aarch64_translation_seed.axisl):
  408 AArch64 integer instructions, 418 accelerator targets, and 71 formats,
  with structured behaviors, flags, memory, control flow, typed legality, and
  418 executable lowering rules. W/X signed and unsigned division has defined
  zero-divisor and signed `MIN / -1` behavior across generated backends.
  Atomic signed/unsigned min/max covers B/H/W/X with all four ordering modes
  and explicit accelerator mappings.
  W/X `ADC`, `ADCS`, `SBC`, and `SBCS` read carry from NZCV, optionally write
  independently checked flags, and lower to state-aware accelerator targets;
  `NGC`/`NGCS` remain representable through their zero-register aliases.
  X-form `UMULH` and `SMULH` use explicit 128-bit intermediate semantics and
  lower to accelerator targets without losing the upper half of the product.
  W/X `EXTR` models the asymmetric `Rn:Rm` funnel shift, the equal-register
  `ROR #imm` alias, the zero-shift edge, and reserved W shifts above 31.
  `SMADDL`, `SMSUBL`, `UMADDL`, and `UMSUBL` preserve signed or unsigned W
  multiplication before wrapping into an X accumulator; `SMULL` and `UMULL`
  are represented by the architectural XZR accumulator aliases.
  W/X `BIC`, `ORN`, `EON`, and `BICS` complete the inverted-register half of
  the logical shifted-register encoding, including `MVN` aliases and
  state-only lowering for `BICS` with a zero-register destination.
  W/X `CCMP` and `CCMN` cover register and five-bit immediate operands; their
  true paths compute subtraction or addition flags, while false paths install
  the encoded NZCV literal without reading either comparison result.
  `LDUR`/`STUR` cover signed unscaled byte offsets for byte, halfword, W, and X
  memory widths, including W/X `LDURSB`, W/X `LDURSH`, and X `LDURSW`
  sign-extension behavior with SP bases and zero-register operands.
  Register-offset loads and stores cover byte, halfword, W, signed-extending,
  and X accesses with `UXTW`, `LSL`, `SXTW`, or `SXTX` index extension and the
  architectural access-size scale bit.
  Scalar single-register writeback covers byte, halfword, W, X, and
  sign-extending loads and stores in both pre-index and post-index modes,
  preserving whether memory is accessed before or after base update.

The first three Rust regressions require full `Document` equality and byte
identity across the primary frontend-sensitive artifacts. AArch64 replaces
legacy infix effect spelling with typed behavior forms, so its regression
requires equality after removing that compatibility-only spelling and exact
identity across executable backends. The reusable command-line gate:

```sh
python3 tools/frontend_equivalence.py \
  examples/mode_polymorphic.axisl examples/mode_polymorphic.axisl
```

validates both sources independently, emits complete bundles, and compares
their file sets and bytes. The mode pair produces 35 identical artifacts and
the same 12 mode/word decisions, including two illegal-in-mode cases. The
personality pair produces 36 identical artifacts and passes 2,496
split-migration-versus-whole-execution programs. The RVMT/PCE pair produces 34
identical artifacts and passes the PCE consumer contract plus native
encode/decode, lift, and execution gates. The AArch64 pair has identical typed
behavior and legality for its 758 shared declarations. Legacy source and its
canonical Lisp serialization produce 18 byte-identical core artifacts; the
full Lisp corpus then adds 68 ordered-memory, barrier, system-state,
paired-atomic/exclusive, and monitor-control instructions and 418 Lisp-only
lowering rules:

```sh
python3 tools/frontend_equivalence.py --core \
  examples/aarch64_translation_seed.axisl \
  examples/aarch64_translation_seed.axisl
```

`axis emit-lisp input.axis -o output.axisl` serializes any validated typed
document into canonical Lisp. It emits decode constraints from their typed
tree and legacy effects as structured `(behavior ...)` forms, so it is a
migration tool rather than a source-preserving formatter. Serializing an
already canonical document is idempotent.

## 8. The canonical form, checked

`emit-lisp` exists to write the canonical Lisp for a document — the form a
corpus could be replaced by. That claim was stated in `tests/golden.rs` —
*what comes back out is what went in, or a corpus cannot be rewritten from its
own emitted form* — and tested on one corpus by two assertions about barrier
forms. No gate drove the emitter at all.

`tools/lisp_roundtrip.py` now does, over every corpus, and defines fidelity as
**the artifacts do not move**: emit ten manifests from the source, emit the
canonical Lisp, re-elaborate it, emit them again, and require every byte to
match. A difference no artifact shows is one no consumer can see; a difference
in an artifact is one somebody downstream would have to live with.

Comparing `emit-lisp(emit-lisp(x))` with `emit-lisp(x)` would have looked like
the same check and been vacuous for exactly the bugs below: a form the emitter
drops is dropped identically on both sides, so a fabric that vanished agrees
with itself perfectly. The original document has to be one side.

### What it found

Seven defects, on the first run, and every one of them silent — each produced a
document that still validated, or artifacts a consumer would have read without
complaint:

| dropped | consequence |
|---|---|
| `defpacket` | a VLIW corpus came back with no packet, and two syllables that a packet's slots kept apart collided in one decode space — the canonical form did not even validate |
| `deffabric`, `defmapping`, `defchannel` | a CGRA corpus came back as a machine with no array, no schedule and no handshakes |
| an instruction's `(unit alu)` | every syllable fit every slot |
| an instruction's `(runs-mapping …)` | a launch ran nothing |
| a personality's `(exports …)`/`(imports …)` | a machine that lent nothing — added by G4b.3 to the manifest and never to the canonical form |
| an ISA's `(lanes N)` | `lane_id` became a symbol nothing introduced, and `grv_simt`'s own semantics stopped resolving |
| an operand's `element` marker | an operand became 64 bits of a 128-bit register with no way to say which |

The packet one is the sharpest: with `defpacket` gone, `VSTW` and `VBRZ`
occupied the same bit pattern, because what had kept them apart was the slot
each was decoded in. The canonical form of that corpus did not re-elaborate at
all.

And one the emitter got right while the *frontend* could not read it back: the
`enc` role — encoded, read by nothing — has always existed in the AST and
`operand_role` has always returned it, but the reader accepted only `in`,
`out` and `inout`. `emit-lisp` was writing a document its own reader rejected,
on seven corpora at once. The reader accepts it now.

A fabric link needed the same treatment from the other direction. Links are
declared compactly, `(links (north 1) (south 1) …)`, and elaboration expands
each into an explicit link that remembers its compass direction. Writing the
compact form back would mean recognising a pattern in a link set, which is
inference; the explicit form carries `(direction north)` instead, so the
canonical form states what the document holds.

### The seven that were excluded, and the question behind them

Seven corpora — SVE, RVV and the five scalable ones — used to be excluded, and
the exclusion was written up here as a boundary. It was really a question about
what `emit-lisp` is *for*, answered wrongly.

`emit-lisp` wrote the **elaborated** document. Scalable elaboration instantiates
one instruction per lane, so `sve.axisl` came back as 2797 `__l` instructions:
a lane's operand derives from its register at offset zero, which the surface
refuses, and its semantics binds a `lane_id` no declaration introduces. Those
really are inexpressible, and un-instantiating them really would be inference.
All of that was true and none of it was the point.

The point is what this emitter claims. `tests/golden.rs` states it: *what comes
back out is what went in, or a corpus cannot be rewritten from its own emitted
form* — a claim about replacing a **source**. A 14187-line file nobody could
keep is not a replacement for a 1060-line one.

So it writes the **frontend** document now: after Lisp macro expansion
(`use-properties`, bounded families, `let`/`if`, so the result needs no macro
layer to be understood) and before the four semantic passes in
`parser::parse_document`. Re-parsing what it writes runs those passes again and
lands on the same document, which is exactly what the round-trip gate requires.
`sve.axisl` goes from 14187 lines to 2172, all 55 corpora pass, and the
exclusion machinery is gone rather than left as a guard that can no longer
fire.

The elaborated rendering is still available to a caller that wants it —
`emit_lisp` renders whatever document it is handed and says so. What changed is
which document the CLI hands it.
