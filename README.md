# AXIS

AXIS is the **Acceleration eXtensions for Instruction Sets** architecture
description language. It is the standalone successor to PCE's `pce-adl` seed
and the permanent home for all ADL work: one source of truth for ISA
extensions, instruction semantics, accelerator contracts, topology metadata,
compiler collateral, RVMT handoff manifests, and PyRTL behavioral hooks. The
seed crate in PCE is frozen and will be retired once PCE consumes AXIS bundles
directly; see `docs/pce_migration.md` for the consumer seams and contract
invariants.

The current implementation is intentionally conservative. It preserves the
existing PCE bundle surface while introducing AXIS-native schema identity and
new description fields for whole ISAs and accelerator semantics.

AXIS is a Lisp-authored, statically elaborated language: `.axisl` is the only
source format. The legacy block grammar (`.axis`, `.pceadl`) that AXIS
inherited from `pce-adl` has been removed — every example had carried a
canonical Lisp form since the migration, PCE consumes emitted bundles rather
than AXIS source, and a second reader nobody authored in was a second place
for every new construct to be forgotten. `axis emit-lisp` still emits the
canonical form of a document, which is what pins the round trip.

The span-aware reader, compositional `let`/`if`, typed reusable `defsem`
functions, document frontend, architectural `behavior` forms, and typed decode
`requires` predicates, including unsigned comparisons composed with
`and`/`or`/`not`, are all available. Lisp `defmode`, instruction mode sets, and
structured `defpersonality`/`defcore` declarations drive the existing
legality, capsule, and topology artifacts; `defmemory` and `deftile` complete
the topology, while `defaccelerator` covers descriptor-backed accelerators and
shares typed `defsem` expansion with instructions. Bounded `defproperties`
fragments provide forward-declared, cycle-checked reuse across declarations and
instruction-family templates.
See [`docs/lisp_design.md`](docs/lisp_design.md),
[`examples/lisp_module.axisl`](examples/lisp_module.axisl), and
[`examples/lisp_modes_cores.axisl`](examples/lisp_modes_cores.axisl). Bounded,
literal-table instruction generation is demonstrated by
[`examples/lisp_aarch64_family.axisl`](examples/lisp_aarch64_family.axisl).

## Quickstart

```bash
cargo run -- check examples/rvmt_xpce.axisl
cargo run -- emit-json examples/rvmt_xpce.axisl -o /tmp/xpce_manifest.json
cargo run -- emit-rvmt-json examples/rvmt_xpce.axisl -o /tmp/rvmt_extension_manifest.json
cargo run -- emit-pyrtl examples/rvmt_xpce.axisl -o /tmp/xpce_pyrtl_semantics.py
cargo run -- emit-bundle examples/rvmt_xpce.axisl -o /tmp/xpce_bundle
```

## Two real ISAs

AXIS describes two architectures end to end, and the second one is why the first
is trustworthy. [`examples/aarch64_translation_seed.axisl`](examples/aarch64_translation_seed.axisl)
elaborates to 1715 instructions — 1280 AArch64 and the 435 of the accelerator it
lowers to; [`examples/rv32i.axisl`](examples/rv32i.axisl) elaborates to 247,
being RV32I with its A and F/D extensions, with their real encodings, proven on
the golden model, SMT, C, Rust, LLVM, all three executors, and both roundtrips.

Those two numbers are checked rather than remembered. `tools/doc_facts_check.py`
recomputes every count this repository states about itself and fails if the
prose has drifted — which it had: this paragraph said 544 and 40 for most of the
time it existed, and nothing recomputed either.

Writing the second one found three things the first had hidden, each because
AArch64 happens not to need it:

| What was missing | Why AArch64 never showed it |
|---|---|
| Integer comparisons as values | It compares by writing NZCV and testing it, so comparison lived in two ISA-specific helpers. RISC-V's `slt` *is* arithmetic and its branches compare registers directly. |
| A hardwired zero register | It encodes XZR as index 31 in some classes and SP in others. RISC-V's `x0` is index 0 and always zero. |
| One place that knows what a register class is | Its rules were written inline in each backend that generates register access code, so a second ISA meant editing every one and hoping they agreed. |

The third is the one worth generalizing. A register class is now a row in
`ast::REGISTER_CLASSES` — which index reads as zero, which index names a state
slot instead of the file, how wide a read is, where in the register that read
starts, what a write does to the bits outside it, and how many 64-bit slots one
register occupies — and the Python, C and Rust executors all render their access
code from it. Adding an architecture is adding a row. The last two fields are
each there because an architecture needed something the row could not say: x86's
`AL` preserves the rest of `RAX` while `EAX` zeroes it (`docs/register_slices.md`),
and a 128-bit vector register does not fit in a machine word (`docs/limbs.md`). Nine separate places had grown their own answer to "is this operand a
register", and they were found one differential failure at a time: the compact C
executor tested `strcmp(kind, "reg")` exactly, so a class with a name of its own
was silently read as an immediate.

## Description Model

AXIS source currently supports:

- `extension`: package-level name, version, target, and description.
- `isa`: whole-ISA metadata such as base ISA, word width, register surface,
  features, memory model, and endianness.
- `format`: named instruction bit layouts. Fields are named slices of
  instruction bits (`func7[31:25]`); scattered operand placements bind operand
  sub-slices to instruction bits (`imm[11:5]@[31:25]`). The RISC-V base
  formats R, R4, I, S, B, U, J are built in.
- `instruction`: format reference, operands, `asm` syntax, free-text
  semantics, typed `formal_semantics`, latency, throughput, cost hints,
  compiler intrinsic, and AHA rationale. Format fields resolve by name:
  fields matching an operand name carry that operand's bits; fields pinned by
  the flat `opcode`/`func3`/`func7` sugar or an explicit
  `encoding: [field=value, ...]` list become fixed decode bits (e.g.
  `encoding: [rs2=1]` turns R-format's rs2 slot into a Zbb-style unary-op
  discriminator). Every encoding fact — match/mask, operand packing,
  encodability — derives from this resolution; the validator additionally
  proves no two instructions overlap in the decode space.
  Reserved combinations inside variable fields can be excluded with a typed
  `decode_requires:` predicate. The AArch64 logical-immediate forms use
  `a64_logical_imm(i64, n, imms)` or `a64_logical_imm(i32, 0, imms)`;
  validation checks its operand references, generated encoders refuse illegal
  operand combinations, and generated decode/lift paths evaluate it after
  match/mask.
  An instruction may bind to a declared encoding space with `isa: <name>`.
  The legacy `opcode`/`func3`/`func7` fields are optional RISC-V sugar;
  non-RISC-V formats pin their named fixed fields with `encoding:`, as shown
  by `examples/aarch64_translation_seed.axisl`. PCE/AHA export remains
  intentionally restricted to RISC-V custom opcodes.
  An instruction may instead carry an infix `effects:` block (the effect
  surface, see `docs/effects_design.md`): `effects: set rd = rs1 * rs2 + rs3`,
  with function-call forms for the non-infix operators (`sext(i32, 8, x)`,
  `min(a, b)`, `not(i32, x)`, `clz(x)`). In the current stage a single register
  `set` desugars into `formal_semantics`, so it produces byte-identical
  artifacts to the s-expression form (`examples/effects_pure.axisl`). A
  memory-load write — `effects: set rd = load(i32, signed, rs1 + imm)`
  (`examples/effects_mem.axisl`) — keeps its semantics in `effects` (empty
  `formal_semantics`), so the pure value-model backends skip it and the Python
  executor (`axis_exec.py`) applies the effects against a memory model:
  `step(word, regs, mem)` binds operands, then evaluates register, memory, or
  architectural-state writes. Loads read via `mem.read`; named state uses
  forms such as
  `setstate(nzcv, a64_add_nzcv(i64, rn, rm), i4)`. State targets must be scalar
  locations declared by the instruction's ISA and are supplied to the Python
  executor with `step(..., state={"nzcv": value})`.
  Implicit fixed-register writes use `setreg(kind, index, value)` or the
  target-neutral typed form `setreg(kind, index, iW, value)`, allowing
  instructions such as AArch64 `BL` to write X30 without inventing an encoded
  destination operand.
  A store evaluates its address/value and writes via `mem.write`; its form is
  `store(addr,
  value, iW)` — has no register write (`examples/effects_store.axisl`).
  Ordering events use `barrier(kind, option)` and remain distinct from
  memory accesses in typed lift and translation metadata.
  Control flow uses `setpc(target)` with an optional `when <cond>:` guard (`==`/
  `!=`), and `pc` is in scope: `effects: when rs1 == rs2: setpc(pc + imm)`
  (`examples/effects_branch.axisl`); `step` returns `next_pc` (fall-through
  `pc + ILEN` unless a `setpc` fires). A `trap(cause)` effect (cause ∈ illegal,
  misaligned, access, ecall, ebreak) aborts the instruction and is reported as
  `step`'s `trap`; guarded, it is a predicated exception
  (`examples/effects_trap.axisl`). `tools/exec_vs_golden.py` proves the
  decode→bind→apply plumbing with a full-state (registers + memory + pc + trap)
  check against a reference.
- `core`: core kind, thread count, features, and optional `implements` ISA link.
- `accelerator`: family/target, runtime descriptor metadata, queue/MMIO
  coupling, ports, behavioral semantics, latency/throughput, and resources.
- `memory`: memory kind, size, ports, latency, width, banks, and attributes.
- `tile`: cores, accelerators, memories, and interconnect.

Example:

```text
isa rv32_axis {
  base: rv32im
  word_bits: 32
  registers: [x[32]:i32]
  features: [m, custom]
}

instruction mac_sq {
  mnemonic: MAC_SQ
  format: R
  opcode: 0x0b
  func3: 0x4
  func7: 0x05
  operands: [rd:reg:32:out, rs1:reg:32, rs2:reg:32]
  semantics: rd = rs1 * rs2 + rs1
  formal_semantics: (add i32 (mul i32 rs1 rs2) rs1)
}

accelerator nearasic0 {
  family: nearasic
  target: nearasic
  coupling: queue_descriptor
  ports: [a:input:bits:32, b:input:bits:32, y:output:bits:32]
  semantics: y = a * b
  formal_semantics: (mul i32 a b)
}

memory scratchpad {
  kind: scratchpad
  size_bytes: 65536
  ports: 2
  latency_cycles: 1
  width_bits: 32
  banks: 4
  attributes: [explicit, dma_visible]
}
```

## Emitters

```bash
cargo run -- check <input.axisl>
cargo run -- emit-json <input.axisl> -o manifest.json
cargo run -- emit-rvmt-json <input.axisl> -o rvmt_extension_manifest.json
cargo run -- emit-decode-json <input.axisl> -o decode_table.json
cargo run -- emit-encode-json <input.axisl> -o axis_encode_table.json
cargo run -- emit-encode-c <input.axisl> -o axis_encode.h
cargo run -- emit-roundtrip-json <input.axisl> -o axis_roundtrip_tests.json
cargo run -- emit-decode-c <input.axisl> -o axis_decode.h
cargo run -- emit-asm-disasm-json <input.axisl> -o asm_disasm.json
cargo run -- emit-capsule-json <input.axisl> -o state_capsule_manifest.json
cargo run -- emit-legality-json <input.axisl> -o mode_legality_manifest.json
cargo run -- emit-bundle-manifest <input.axisl> -o bundle_manifest.json
cargo run -- emit-semantics-json <input.axisl> -o semantics.json
cargo run -- emit-semantics-c <input.axisl> -o axis_semantics.h
cargo run -- emit-semantics-rust <input.axisl> -o axis_semantics.rs
cargo run -- emit-lift-json <input.axisl> -o axis_lift_table.json
cargo run -- emit-translation-json <input.axisl> -o axis_translation_map.json
cargo run -- emit-translation-python <input.axisl> -o axis_translate.py
cargo run -- emit-lisp <input.axisl> -o canonical.axisl
cargo run -- emit-lift-python <input.axisl> -o axis_lift.py
cargo run -- emit-lift-c <input.axisl> -o axis_lift.h
cargo run -- emit-lift-rust <input.axisl> -o axis_lift.rs
cargo run -- emit-exec-python <input.axisl> -o axis_exec.py
cargo run -- emit-exec-c <input.axisl> -o axis_exec.h
cargo run -- emit-llvm-ir <input.axisl> -o axis_semantics.ll
cargo run -- emit-smt2 <input.axisl> -o semantics.smt2
cargo run -- emit-python <input.axisl> -o manifest.py
cargo run -- emit-aha-json <input.axisl> -o aha_instructions.json
cargo run -- emit-tablegen <input.axisl> -o instructions.td
cargo run -- emit-intrinsics <input.axisl> -o intrinsics.h
cargo run -- emit-llvm-intrinsics <input.axisl> -o axis_intrinsics.td
cargo run -- emit-llvm-patterns <input.axisl> -o axis_patterns.td
cargo run -- emit-golden-python <input.axisl> -o golden_model.py
cargo run -- emit-pyrtl <input.axisl> -o pyrtl_semantics.py
cargo run -- emit-hw-pyrtl <input.axisl> -o axis_hw.py
cargo run -- emit-hw-json <input.axisl> -o axis_hw.json
cargo run -- emit-hw-smt2 <input.axisl> -o axis_hw.smt2
cargo run -- emit-bundle <input.axisl> -o bundle_dir
```

`emit-bundle` currently writes:

- `bundle_manifest.json`
- `manifest.json`
- `rvmt_extension_manifest.json`
- `decode_table.json`
- `axis_encode_table.json`
- `axis_encode.h`
- `axis_roundtrip_tests.json`
- `axis_decode.h`
- `asm_disasm.json`
- `semantics.json`
- `semantics.smt2`
- `aha_instructions.json`
- `adl_topology_manifest.json`
- `accelerator_descriptor_manifests.json`
- `adl_coupling_manifest.json`
- `rvmt_launch_templates.json`
- `rvmt_rcore_region_manifest.json`
- `instructions.td`
- `intrinsics.h`
- `axis_intrinsics.td`
- `axis_patterns.td`
- `golden_model.py`
- `axis_semantics.h`
- `axis_semantics.rs`
- `axis_semantics.ll`
- `axis_lift_table.json`
- `axis_lift.py`
- `axis_lift.h`
- `axis_lift.rs`
- `axis_exec.py`
- `axis_exec.h`
- `axis_exec.rs`
- `axis_sim.h`
- `pyrtl_semantics.py`

The primary manifest schema is `axis.manifest.v1`. Some sidecar files retain
their existing `pce-adl.*` schema names for compatibility with current PCE
loaders.

`bundle_manifest.json` uses `axis.bundle-manifest.v1` and indexes the files in
an emitted bundle with their artifact kind, schema identity, compatibility
target, generator name, generator version, and validated model counts.

`semantics.json` uses `axis.semantics.v1` and carries the parsed typed semantic
AST for instructions and accelerators. It is intended as the common input for
future proof, PyRTL, compiler-pattern, and golden-model backends.

`decode_table.json` uses `axis.decode-table.v1` and carries mnemonic, format,
assembly syntax, RISC-V match/mask values, decode keys, and operands. It is the
seed artifact for standalone asm/disasm, simulator decode, lifters, and JIT
block formation.

`axis_encode_table.json` uses `axis.encode-table.v1` and carries the inverse
encoding view: fixed instruction bits, operand roles, and known RISC-V operand
bit fields. Operands that AXIS cannot yet pack are marked `unencoded` so
roundtrip gaps are visible to downstream tools.

`axis_encode.h` is a header-only C encode table generated from the same
metadata. It exposes `AXIS_ENCODE_TABLE`, `axis_encode_apply_field(...)`, and
`axis_encode_by_index(...)`; instructions with incomplete operand packing are
marked non-encodable.

`axis_roundtrip_tests.json` uses `axis.roundtrip-tests.v1` and emits
deterministic sample encodings for fully encodable instructions. Instructions
with incomplete operand packing are listed under `skipped` with the unencoded
operand names.

`axis_decode.h` is a header-only C decoder generated from the same match/mask
table. It exposes `AXIS_DECODE_TABLE` and `axis_decode(uint32_t insn)` for
simulators and interpreters that do not want to parse JSON.

`asm_disasm.json` uses `axis.asm-disasm.v1` and carries opcode tokens,
assembly templates, operand print order, decode match/mask values, and
conventional RISC-V operand bit-field metadata. It is the bridge artifact for
standalone assemblers/disassemblers and LLVM MC generation.

`semantics.smt2` emits bit-vector `define-fun` declarations for instruction and
accelerator `formal_semantics`. It is intentionally solver-input text, so AXIS
does not need a Z3 dependency to produce proof collateral.

`golden_model.py` uses `axis.golden-model.v1` and emits pure-Python integer
evaluators named `eval_<instruction>(...)` and `eval_<accelerator>(...)` for
entries with `formal_semantics`. It also carries a trusted-spec registry
(`AXIS_SPECS` with per-entry signature, widths, and source semantics),
deterministic `sample_vectors(...)` generation, a generic `evaluate(...)`
entry point, and a `selftest()` — the artifact shape ALGO-WATCH-style
harnesses register as the auditable golden an implementation must match.

`axis_semantics.h` uses `axis.semantics-c.v1` and is a header-only pure-C
interpreter: one `axis_eval_<name>(...)` function per instruction/accelerator
with `formal_semantics`, bit-identical to the golden model (checked by
`tools/c_vs_golden.py`). No LLVM, JSON, or Python dependency — the cosim
oracle for C/C++ simulators.

`axis_lift_table.json` uses `axis.lift-table.v1` and is the inverse of the
encode table: the decode-to-semantic-IR seed. Per instruction it carries the
decode match/mask, the operand extraction fields (instruction-bit slices
reassembled into each operand value), the read/write operand roles, the
architectural `state_width` (distinct from the 32-bit instruction word), and
the typed `formal_semantics` AST. Two flags keep the distinction honest:
`operands_encodable` (the word can be decoded and its operands extracted) and
`liftable` (that plus a `formal_semantics` to bind them into) — a decodable
instruction with only free-text semantics is `operands_encodable` but not
`liftable`. `liftable` specifically means the *pure* path, the same flag the
generated C and Rust lifters use to decide that an `axis_eval_*` evaluator
exists; effectful instructions execute through their effect list instead.

That effect list rides along in `effects`, the same ordered program the
Python/C/Rust lifters run, so a JSON consumer sees memory accesses, control
flow, traps, barriers, and named-state writes rather than a bare
`"semantics": null` (both artifacts render it through one emitter, so they
cannot drift apart). Alongside it, `effect_summary` answers what an instruction
touches beyond its operands — `reads_memory`, `writes_memory`, `reads_state`,
`writes_state`, `writes_pc`, `may_trap`, `barrier` — without walking the
expressions. The
summary is expression-deep, not head-only: an atomic read-modify-write nests
its load inside the stored value and is reported as both a read and a write.

`axis_translation_map.json` uses `axis.translation-map.v1`. ISAs marked
`role: source` are matched to instructions in ISAs marked `role: target`
after typed semantic lowering and operand alpha-normalization. Only fully
encodable, single-result instructions are mapped. Each entry carries both
encodings and an explicit source-to-target operand map, including each mapped
operand's value class, original operand kind, and width; unmatched source
instructions remain visible for fallback handling. Instructions without a
proven target equivalent—including flag-setting and control-flow
operations—remain unmatched. The AArch64 seed's
`ADD_X_SHIFT0` identifier covers every legal
LSL/LSR/ASR amount and maps to `ACCEL_ADD64_SHIFTED`; the name is retained for
compatibility with earlier generated artifacts.
`tools/translation_vs_golden.py` executes both sides over 64-bit edge cases
and randomized inputs, requiring source and target execution to agree and,
when the pure semantics model supports the expression, checking both against
the trusted golden result. Effect-helper mappings use the architecture-specific
state checker as their independent oracle.
[`examples/aarch64_translation_seed.axisl`](examples/aarch64_translation_seed.axisl)
is the canonical Lisp form of the complete 826-instruction integer and
accelerator-target seed. It
uses structured `behavior` and `requires` forms throughout.
The division subset defines AArch64’s zero-divisor and signed-overflow results
directly, including generated C, Rust, LLVM, SMT, Python, and PyRTL semantics.
Conditional-select lowerings carry NZCV-dependent dataflow through effect
semantics while preserving XZR/WZR reads, discarded writes, and W zero extension.
Unary bit-manipulation semantics use reusable Lisp `defsem` definitions for
bit reversal, lane-aware byte reversal, and leading-sign count.
Explicit Lisp `deflowering` rules extend this from single-instruction discovery
to sequence fusion. Each rule binds every source and target operand to an
SSA-like `$value`, carries recursive comparison guards and source/target cost,
and is accepted only when validation proves the composed source typed
semantics identical to the target. The manifest exposes these under
`explicit_lowerings` without changing automatic `matches`.
[`examples/lisp_lowerings.axisl`](examples/lisp_lowerings.axisl) fuses two
AArch64 adds into `ACCEL_ADD3`; `tools/lowering_vs_golden.py` proves the encoded
two-step execution equals the accelerator instruction.

`emit-translation-python` generates standalone `axis_translate.py`
(`axis.translation-python.v1`). Its `match_at`, `rewrite_once`, and
`rewrite_all` APIs decode source windows, enforce instruction legality, unify
shared bindings, evaluate lowering guards, and pack the target word. Rules are
ordered deterministically by longest sequence, highest declared benefit, then
name. The lowering differential gate checks successful fusion, guard rejection,
fixed-bit rejection, greedy stream rewriting, and execution equivalence.
The canonical AArch64 corpus uses this path for 64-bit shifted-register ADD,
SUB, AND, ORR, EOR, ADDS, SUBS, CMN, CMP, unsigned-offset `LDR X`, and
unsigned-offset `STR X`. Register rules reject encoded register 31 when it
would be mistaken for an ordinary accelerator register. ADDS/SUBS prove their
register result and ordered NZCV write; CMN/CMP explicitly bind the source
destination to AArch64 XZR and lower to state-only accelerator instructions.
The memory rules preserve access width, load signedness, scaled address
calculation, stored value, signed indexed offsets, and register/memory
writeback order. Pair-transfer rules additionally preserve two ordered memory
accesses, two load destinations, and optional base writeback.
Typed unsigned-offset targets cover byte, halfword, and word zero-extending
loads, byte and word sign-extending loads, and truncating byte/halfword/word
stores. Their runtime matrix checks offset zero and 12-bit extrema, forced
high-bit load payloads, store truncation, and rejection of an SP base that the
generic accelerator register file cannot represent.
Register-offset LDR/STR targets retain distinct SP-capable base and
XZR-capable index/data operand kinds, so selector 31 remains lowerable rather
than guarded into fallback. Dedicated checks cover an SP base, XZR index,
discarded XZR load destination, and zero-valued XZR store source.
W/X MADD and MSUB extend the source corpus with modular three-source
multiplication. XZR/WZR accumulator forms describe the MUL/MNEG aliases, and
the target retains zero-register semantics in every input and destination role.
Control-flow rules lower direct `B`, guarded `B.cond`, indirect `BR`, `RET`,
and link-producing `BL`/`BLR`; proof includes the exact PC expression,
conditional guard, and ordered link-register write, while the differential
gate checks both taken and fall-through paths from a nonzero PC. Accelerator
calls explicitly declare their convention as a 64-bit generic register 30,
which is proven compatible with AArch64 X30 by register class, index, width,
value, and effect order.
The guarded branch set also covers W/X `CBZ`/`CBNZ` and low/high-half
`TBZ`/`TBNZ`, preserving 32-bit register views, bit-half selection, bit index,
signed displacement, and zero/nonzero sense.
Immediate arithmetic covers 64/32-bit ADD, SUB, ADDS, and SUBS, including the
encoded zero-or-12-bit shift, SP/WSP sources and destinations, NZCV generation,
and state-only CMN/CMP aliases. Lowering validation requires source and target
register-31 SP semantics to agree unless the rule explicitly excludes selector
31, and the runtime gate executes SP-aware bindings with selector 31.
Extended-register arithmetic covers W/X ADD, SUB, ADDS, SUBS, CMN, and CMP
with SP/WSP bridging and every UXTB/UXTH/UXTW/UXTX and
SXTB/SXTH/SXTW/SXTX option. The lowering differential exhaustively checks all
eight extension modes at shifts zero through four.
Shifted logical lowering covers W/X AND, ORR, EOR, ANDS, and the state-only
TST aliases. Its differential matrix exercises LSL, LSR, ASR, and ROR at
zero, one, and the width-specific maximum shift, including XZR/WZR inputs,
32-bit result zero extension, and N:Z:0:0 flag generation.
Variable-register lowering covers W/X LSLV, LSRV, ASRV, and RORV. Dedicated
boundary vectors prove modulo-32/modulo-64 count masking across the width and
double-width boundaries, XZR/WZR value and count inputs, signed right shifts,
rotates, and W-write zero extension.
Move-wide lowering covers X-form MOVN, MOVZ, and inout MOVK across all four
halfword positions and immediate extrema. MOVK proof and execution checks
require all 48 untouched destination bits to be preserved exactly.
Logical-immediate lowering covers W/X AND, ORR, EOR, ANDS, and state-only TST.
The W source format carries the architectural six-bit `immr` and `imms`
fields, including replicated 2/4/8/16/32-bit elements. Differential execution
enumerates every legal `N:imms` shape, rotation boundaries, XZR/WZR inputs,
W zero extension, logical NZCV, and reserved-encoding rejection.
Bitfield lowering covers W/X SBFM, destructive BFM, and UBFM. It exhaustively
executes every legal `immr`/`imms` pair at both data widths, checks XZR/WZR
sources, proves BFM preserves destination bits outside the selected field, and
rejects W encodings whose raw six-bit immediate fields exceed 31.

`tools/aarch64_state_check.py` checks the A64 register-31 rules (XZR/WZR versus
SP), overlapping W/X views, W-write zero extension, `ADDS`/`SUBS` NZCV
generation, signed branch offsets, and the complete 16×16 NZCV/condition-code
truth table used by `B.cond`. It also executes scaled SP-relative and indexed
memory forms, including signed writeback offsets, byte/halfword/word
zero-extension, sign-extending loads, truncating stores, and scaled register
offsets. Byte, halfword, W, X, and sign-extending loads and stores cover both
pre-index and post-index ordering.
Pair-transfer coverage includes W/X `LDP`/`STP` signed scaled offsets,
two-register loads/stores, SP bases, XZR/WZR behavior, W zero-extension and
store truncation, and pre/post-index writeback ordering.
Exclusive-memory coverage includes W/X `LDXR`/`STXR`, paired `LDXP`/`STXP`,
and their acquire/release forms. First-class per-access ordering metadata and
explicit reservation address/size/valid state distinguish scalar from paired
reservations; tests cover successful guarded commits, atomic two-address pair
updates, invalid/address/size mismatch failures, status results, and clearing.
`CLREX #imm4` completes the explicit local-monitor lifecycle: its encoded
implementation hint is preserved through lowering while execution invalidates
the reservation without changing its otherwise irrelevant address or size.
`LDARB`/`LDARH`/`LDAR` and `STLRB`/`STLRH`/`STLR` cover acquire loads and
release stores at B/H/W/X widths without modifying exclusive-monitor state.
`DMB`, `DSB`, and `ISB` are typed barrier events rather than dummy memory
accesses. Their raw four-bit options survive lift metadata and explicit
lowering to distinct accelerator ordering, completion, and instruction-stream
synchronization operations. Deterministic executors preserve the event while
treating its concurrent enforcement as a backend responsibility.
`SB` and `CSDB` carry distinct speculation-barrier semantics. The overlapping
`DSB #0` and `DSB #4` words decode canonically as `SSBB` and `PSSBB`; operand
constraints keep the generic and alias declarations disjoint.
`MRS Xt, NZCV` and `MSR NZCV, Xt` establish the system-register transfer
foundation. They convert between the internal four-bit flag state and
architectural `Xt[31:28]`, including XZR reads and discarded XZR writes, and
lower to explicit accelerator state-transfer operations.
The EL0-accessible user system registers `FPCR`, `FPSR`, `TPIDR_EL0`, and
`TPIDRRO_EL0` use the same typed named-state mechanism. Their `MRS` forms read
the state into `Xt` and their `MSR` forms write it at the architectural width,
so 32-bit `FPCR`/`FPSR` truncate a 64-bit source while read-only
`TPIDRRO_EL0` has no write form. Because such a read is a bare state atom
rather than an operand, the pure path cannot hold it: the behavior stays
authoritative and every lifter and executor emits it as an effect.
Atomic-RMW coverage includes W/X `SWP`, `SWPA`, `SWPL`, and `SWPAL`:
atomicity is retained
independently from ordering through lift, translation, lowering proof, and
generated execution, with acquire and release attached to the appropriate
transaction half, including SP bases and XZR/WZR operands.
Byte and halfword `SWP` variants cover all four ordering modes, truncate the
W source to the accessed width, and zero-extend the old memory value into W.
Byte and halfword `LDADD` variants additionally perform modular addition at
the accessed width before storing the wrapped result.
Byte and halfword `LDCLR` variants mask the complement and bit-clear operation
to the accessed width across all four ordering modes.
Byte and halfword `LDEOR` variants perform width-masked exclusive-or updates
while returning the zero-extended pre-update value.
Byte and halfword `LDSET` variants complete the current subword atomic family
with width-masked OR updates in every ordering mode.
`CAS` covers B/H/W/X and every ordering mode. Its `(input rs)` expression
preserves the entry expected value after the inout register receives the old
memory value, enabling an explicitly guarded atomic store.
Lisp operands can additionally use `(derive base offset)` to describe implicit
adjacent architectural registers. Derived selectors consume no encoding bits
and are materialized by Python, C, and Rust lifters. W/X `CASP`, `CASPA`,
`CASPL`, and `CASPAL` use two derived adjacent registers, even-selector
`masked-eq` legality, a conjunction over both entry expected values, and one
explicit four-effect atomic transaction. All eight forms lower to paired
accelerator CAS targets and pass Python/C/Rust execution checks.
`LDSMAX`, `LDSMIN`, `LDUMAX`, and `LDUMIN` likewise cover B/H/W/X and all four
ordering modes. Their typed `max`/`min`/`maxu`/`minu` expressions preserve the
access-width signedness distinction before storing and return the zero-extended
old value for subword forms.
The W/X `LDADD`, `LDADDA`, `LDADDL`, and `LDADDAL` family additionally
returns the old value while feeding it into the atomic modular addition.
W/X `LDCLR`, `LDEOR`, and `LDSET`, together with their `A`, `L`, and `AL`
variants, model atomic bit clear, exclusive-or, and set updates with relaxed,
acquire, release, and acquire-release ordering. Every form returns the
pre-update value.
PC-relative
and control-flow coverage includes split-immediate `ADR`/`ADRP`, direct
`B`/`BL`, implicit X30 link writes, indirect `BR`/`BLR`/`RET`,
W/X `CBZ`/`CBNZ`, and low/high-half `TBZ`/`TBNZ`. Integer data-processing
coverage includes W/X logical shifted-register forms, masked variable
`LSL`/`LSR`/`ASR`/`ROR`, X-form `MOVN`/`MOVZ`/`MOVK` constant building,
W/X logical bitmask immediates, and `SBFM`/`BFM`/`UBFM` with architectural
DecodeBitMasks expansion. Tests also prove that reserved logical-immediate
`N:imms` combinations and high-bit W bitfield fields are rejected by Python,
C, and Rust decode/execution.
Flag-setting W/X `ANDS` register/immediate forms compute architectural
N:Z:0:0, including `TST` aliases through the XZR/WZR destination behavior.
The W/X add/sub immediate family covers the encoded zero-or-12-bit shift,
SP/WSP sources and non-flagging destinations, NZCV generation, and the
`CMP`/`CMN` aliases formed with XZR/WZR destinations.
The corresponding extended-register family covers all UXTB/UXTH/UXTW/UXTX
and SXTB/SXTH/SXTW/SXTX options, shifts zero through four, SP/WSP operands,
W-write zero extension, flag generation, and rejection of reserved shifts.

`axis_lift.py` uses `axis.lift-python.v1` and is a standalone, dependency-free
lifter over that table: `decode(word)` matches the fixed bits, then evaluates
any operand-dependent `decode_requires` predicate before a word can count as a
match. The standalone JSON/C decode artifacts and the C/Rust lifters enforce
the same rule. `lift(word)` additionally extracts operand values and returns them bound
alongside the raw semantics. It is the seed for trace tools, binary
translation, and differential lift checks. `tools/lift_roundtrip.py` closes the
loop — AXIS instruction → encoded bits → `lift` → recovered mnemonic and
operands — the decode/lift analogue of `roundtrip_check.py`.

`axis_lift.h` (`axis.lift-c.v1`) and `axis_lift.rs` (`axis.lift-rust.v1`) are
the compiled siblings: the same static lift table plus `axis_lift(word, &out)`
(C) / `lift(word)` (Rust) `decode`+extract entry points, dependency-free, for
fast lifting in C/C++ and Rust simulators. `tools/lift_native_check.py`
compiles both with a generated driver and requires them to lift the encode
fixtures back to the same mnemonic and operand values as the Python lifter.

`axis_exec.py` (`axis.exec-python.v1`) is the lift→execute rung: a functional
single-step interpreter that composes the lift table (`axis_lift`) with the
proven golden semantics (`golden_model`). `step(word, regs)` decodes a word,
reads register-kind source operands from `regs` (immediates use their decoded
value), evaluates the instruction, and writes the result to the destination
register. Effectful instructions may also use a separate scalar architectural
`state` map and the ISA state width for guards and PC updates;
`run(words, regs)` sequences steps. It depends on the two modules
emitted beside it. `tools/exec_vs_golden.py` builds random register files and
proves the decode→bind→dispatch→writeback plumbing matches a reference
computed directly from the golden model — a full binary→execute check.

`axis_exec.h` (`axis.exec-c.v1`) is the compiled sibling: a header-only C
executor composing the C lifter (`axis_lift.h`) with the C semantics interpreter
(`axis_semantics.h`). `axis_exec_step(word, regs, reg_count, mem, pc)` decodes,
reads register operands, and either dispatches (a `switch` on the instruction id)
to the right `axis_eval_*` function or runs the instruction's effect list — the
full E1–E4 surface: set (with load-as-set peeled to a `mem->read` + extend),
store, `setpc` (control flow), and `trap`, each optionally guarded. The result
carries the written register, `next_pc` (the fall-through unless a setpc fires),
and the trap cause — the dependency-free core of a C/C++ simulator. Effect
expressions reuse the same `axis_sem_*` helpers and pure lowering as the
interpreter; guards lower to `==`/`!=`. `tools/exec_c_check.py` compiles it and
proves the full binary→execute agreement (registers, memory, next_pc, and trap)
with the golden model. (The lift tables carry an operand `kind` so reg vs
immediate binding is explicit in every backend.)

The same header also exposes `axis_exec_step64`, an ISA-qualified wide ABI with
64-bit registers, PC, and memory addresses/data plus a generic `axis_state64`
map for scalar
architectural state. It implements A64 X/W/SP/ZR register views, NZCV
generation, and condition evaluation while retaining `axis_exec_step` for
existing RV32 callers.

`axis_exec.rs` (`axis.exec-rust.v1`) completes the executor trio: a safe-Rust
executor composing the Rust lifter (`axis_lift.rs`) and semantics
(`axis_semantics.rs`). `step(word, regs, mem, pc)` dispatches by mnemonic to the
pure `axis_eval_*` functions or the same E1–E4 effect handling as the other two,
against a caller-supplied `Memory` trait, returning an `ExecResult`
(result/next_pc/trap). `tools/exec_rust_check.py` compiles the three modules with
a driver and proves the identical binary→execute agreement with the golden model.
The three executors — Python, C, Rust — are thus each differentially proven equal
to the golden reference across the full effect surface.
Rust's `step64`/`ExecResult64` path mirrors the C wide ABI using
`State64Entry` values and the `WideMemory` trait. Read/write operands use the
`:inout` role, which is carried into generated lift metadata and enables
indexed-address writeback. `tools/aarch64_native_state_check.py` compiles both
wide backends and executes AArch64 arithmetic, SP, NZCV, conditional branches,
scaled unsigned loads/stores, subword zero/sign extension, register offsets,
and pre/post-index writeback through native code.

`axis_sim.h` (`axis.sim-c.v1`) is the JIT on-ramp. Where `axis_exec_step`
decodes, lifts, and classifies operand roles on *every* executed instruction,
the simulator IR does that work once at block-build time: `axis_block_build`
turns a straight-line word sequence into pre-decoded `axis_op` records (resolved
input registers/immediates and destination), and `axis_block_run` executes them
with no per-step decode, lift-table scan, or role/kind `strcmp` — just a direct
call into the same proven `axis_exec.h` handlers, so behavior is inherited. The
pre-decoded `axis_op` is exactly the unit a later LLVM/Cranelift lowering would
compile; per the plan, the interpreter comes first, native codegen later. The
cross-executor fuzzer runs the sim IR as a fourth backend, so every random
program requires `python == c-step == c-sim == rust`.

`tools/jit_c.py` takes the native-codegen step: a **transpiling JIT**. It lowers a
decoded block into a single straight-line C function with the operand register
indices and immediates baked in as constants, then compiles it fresh per block
with `cc -O2` and runs it — pure instructions become direct calls to the proven
`axis_eval_*` handlers (which `-O2` inlines and constant-folds into specialized
machine code), while effectful instructions fall back to the proven
`axis_exec_step` runtime. So the JIT trusts no new code — it composes the
already-differentially-proven handlers — and is itself proven: the JIT-compiled
block's architectural trace must equal the Python interpreter (== golden) over
random programs across the full E1–E4 surface (`zbb_like` blocks specialize 100%
inline; `fuzz_mix` about a third inline with the rest via runtime). An injected
miscompile is caught.

`tools/jit_llvm.py` is the **LLVM backend** — a real *in-process* JIT (via
llvmlite's MCJIT, no subprocess, no temp files). It lowers a block to LLVM IR
that calls the proven `axis_eval_*` functions straight out of `axis_semantics.ll`
(the same LLVM semantics `llvm_vs_golden.py` proves equal to the golden model),
compiles it in memory, and executes it through a raw function pointer. It covers
the full pure surface — including `clz`/`ctz`/`cpop`, which the LLVM semantics
lower via `llvm.ctlz`/`cttz`/`ctpop` — and carries a **block cache** keyed by the
instruction-word sequence, so each distinct block is compiled once and the native
code is reused on repeats (~92% hit rate on a 24-block pool: the memoization a
hot-loop simulator needs). Proven the same way: the JIT'd block's register file
must equal the golden model over random blocks; an injected miscompile is caught.

It also covers the **effect surface**, at either width: an effectful instruction
calls the proven `axis_eff_*` handler, which performs its own loads and stores
against a byte buffer the JIT passes in. The block threads the pc through the
sequence, commits every register write the handler reports — each only when it
reports one, since a guarded `set` decides that at runtime — and exits early on
a trap.

Blocks are built at the ISA's own width, so AArch64 runs here too: a 64-bit
register file, pc and status, with the state array threaded through. Because a
compiled block knows each register index as a *constant*, AArch64's encoding-31
rule — the zero register for the plain classes, the stack pointer for the `sp`
ones — is decided at build time rather than tested at run time, and a W-form
read masks to 32 bits statically. Atomics are left out here, unlike in the
effects gate: an atomic access must be naturally aligned or the hardware faults,
and a block computes its addresses from a register file earlier instructions
have already modified, so an unaligned `atomicrmw` takes SIGBUS rather than
reporting a mismatch. Their value semantics are proven by that gate; this one
proves block composition. Effect blocks are checked
against `axis_exec.py` on the full architectural delta (registers, memory, pc,
trap, and step count) over the byte-addressed memory both sides share. Two
injected block-lowering bugs are caught: dropping the pc threading, and
committing a guarded write unconditionally. The second only bites on a corpus
with a guarded register write, which is what
[`examples/effects_guarded_set.axisl`](examples/effects_guarded_set.axisl)
exists to provide — every other effect shape makes "did this write a register"
a static question.

Cranelift remains open as a further backend for the same `axis_op`.

`tools/exec_fuzz.py` closes the loop those per-instruction checks leave open: it
runs random straight-line *programs* through every executor backend — the Python
step interpreter, the C step interpreter, the Rust step interpreter, and the C
simulator IR (`axis_sim.h`) — from an identical initial state and requires a
byte-identical architectural trace (all registers, memory, the final pc, and the
trap outcome). Where the per-fixture tools prove one instruction against the
golden model, the fuzzer proves the backends agree over program composition —
register dataflow through repeated writes, memory written then read back,
`setpc`, and traps — so `python == c-step == c-sim == rust`. It compiles the C
and Rust drivers once and streams programs over stdin, so thousands of programs
run in seconds; `examples/fuzz_mix.axisl` (pure ALU + load + store + branch + trap
in one disjoint-decode ISA) is the default target, and an injected divergence
(including a sim-only one) is caught immediately (non-tautological).

`axis_intrinsics.td` uses `axis.llvm-intrinsics.v1` and declares LLVM target
intrinsics as TableGen `Intrinsic<>` records under `TargetPrefix = "axis"`, so
`def int_axis_<name>` creates the `llvm.axis.<name>` intrinsic an out-of-tree
AXIS backend lowers to the custom instruction. Result/argument types come from
the instruction's operand widths. Memory attributes are selected from the
instruction's `effect_summary` rather than guessed: a pure `formal_semantics`
body (the same set with a reference body in `axis_semantics.ll`) is
`IntrNoMem, IntrWillReturn, IntrSpeculatable`; an instruction that only reads
memory is `IntrReadMem, IntrWillReturn`; one that only writes is
`IntrWriteMem, IntrWillReturn`; and one that does both carries neither marker,
since `IntrReadMem` asserts it does not write and `IntrWriteMem` that it does
not read. A memory access can fault, so no effectful intrinsic is
`IntrSpeculatable`.

Three shapes are withheld, each with the reason named in the file: an
instruction that writes `pc` or may trap (LLVM has no intrinsic form for
control flow), a barrier (an ordering event, not a value computation), and a
*guarded* register write — an intrinsic call always produces its result,
while a conditional write leaves its destination unchanged on the false path.
Instructions with non-standard operand widths are withheld as before.
`tools/tablegen_validate.py` runs the emitted intrinsics through `llvm-tblgen`
(wrapping them behind `include "llvm/IR/Intrinsics.td"` and running the intrinsic
enum/impl emitters with `--intrinsic-prefix=axis`): a clean run with every
`int_axis_*` present in the generated enum proves the declarations are valid LLVM
TableGen. It skips cleanly when no LLVM toolchain is found. (`instructions.td` and
`axis_patterns.td` reference the RISC-V target's TableGen tree and need an LLVM
source build to validate, so that tool checks only the self-contained intrinsics.)

`axis_patterns.td` uses `axis.llvm-patterns.v1` and carries SelectionDAG
lowering-pattern hints (IR→instruction): each `def : Pat<...>` maps the LLVM
DAG derived from an instruction's `formal_semantics` to its `llvm.axis.*`
intrinsic — e.g. `(add (mul i32:$rs1, i32:$rs2), i32:$rs3)` selects
`int_axis_pce_fma_i`. Operators lower to their ISD node names (`min`→`smin`,
`ashr`→`sra`, `not`→`(xor x, -1)`, `sext`→`sext_inreg`, `zext`→mask). Both
sides derive from the same typed IR, so the mapping holds by construction; a
pattern is emitted only when the operands share one standard integer width,
every input is referenced, and the operators have clean SelectionDAG forms —
otherwise the instruction is withheld with a comment.

`axis_semantics.rs` uses `axis.semantics-rust.v1` and is the safe-Rust sibling
of `axis_semantics.h`: one `pub fn axis_eval_<name>(..) -> u32` per
instruction/accelerator with `formal_semantics`, lowered from the same typed IR
and bit-identical to the golden model (checked by `tools/rust_vs_golden.py`).
Arithmetic uses `wrapping_*` so Rust's debug overflow checks match C's modular
u32 arithmetic; width-sensitive ops call the same `axis_sem_*` helper prelude.
The drop-in semantics module for Rust simulators (and the eval half of a future
Rust executor).

`axis_semantics.ll` uses `axis.semantics-llvm.v1` and is a self-contained LLVM
IR module lowered from the same typed IR: one `define i32 @axis_eval_<name>`
per instruction/accelerator with `formal_semantics`. Arithmetic lowers to
native SSA instructions; width-sensitive operations (shifts, rotates,
`clz`/`ctz`/`cpop`, signed/unsigned `min`/`max`, sign/zero extend) call a fixed
`axis_sem_*` helper prelude whose masking discipline mirrors the C interpreter,
so the two are bit-identical for widths up to 32. It is the seed for LLVM-based
lifting, JIT lowering, and optimizer-visible semantics.

Instructions wider than 32 bits lower in `i64` against an `axis_sem64_*`
prelude rendered from the same template at the wider width, so the AArch64
corpus's 64-bit pure semantics are emitted rather than skipped —
`llvm_vs_golden.py` proves all 65 of the seed's pure functions against the
golden model (4160 checks). A 32-bit-only module never gains the wide prelude
and its artifact is unchanged.

`axis_semantics.h` and `axis_semantics.rs` reach 64 bits the same way, each with
an `axis_sem64_*` helper set emitted only when needed. Those two sets are
written out rather than derived, because they differ in substance and not just
spelling: 64-bit values have no wider integer to promote into, so sign
extension happens in place and signed division guards `INT64_MIN / -1`, which
would otherwise overflow. `c_vs_golden.py` and `rust_vs_golden.py` prove both
against the golden model on the same 4160-check corpus, so all five semantics
backends — golden, SMT, LLVM, C, Rust — now agree at 64 bits.

Effectful instructions get a second family in the same module:
`define void @axis_eff_<name>(i8* %mem, iW %pc, iW* %out, iW %<input>…)`, where
`W` is the instruction's own evaluation width — 32, or 64 for a 64-bit ISA.
Loads and stores lower to native LLVM `load`/`store` against a flat
little-endian byte buffer — so memory is visible to the optimizer instead of
hidden behind a call — guards become real branches, and a trap records its
cause and returns, aborting the remaining effects. `%out` carries the written
value, the write flag, the next pc (defaulting to the `pc + 4` fall-through),
and the trap id. `tools/llvm_effects_check.py` compiles the module with clang
and requires the whole architectural delta — value, write flag, next pc, trap,
and the memory image — to equal `axis_exec.py` under the same byte-addressed
memory; an injected miscompile is caught. The AArch64 seed carries 481 of these
functions, covering every unsigned, unscaled, indexed, and acquire/release load
and store form, `ldp`/`stp` with and without writeback, the whole atomic
surface, `adr`/`adrp`, and every branch form, proven over 11544 effect
executions.

AArch64's own operators — the NZCV flag computations, condition-code tests,
shifted and extended register forms, and the high half of a 64-bit multiply —
lower to an LLVM prelude ported from the proven C helpers. They are deliberately
not in the portable `Sem` IR, which is the semantic core five backends agree on;
a flag nibble is not shared semantics. Each application is emitted as a call and
replaced by a symbol bound to its result temp, so what reaches the typed IR is
portable semantics again, and the substitution reuses the same rename map that
threads register writes forward. Every helper was checked against the golden
model standalone (60000 comparisons) before being wired in.

That includes the bitmask-immediate family — `wmask` and the bitfield moves —
which matters out of proportion to its instruction count, because AArch64
encodes `AND`/`ORR`/`EOR` with an immediate through `wmask` and every immediate
`LSL`/`LSR`/`ASR`/`UXTB`/`SXTH` as a `UBFM`/`SBFM` alias. With it, **725 of 775**
AArch64 effect functions are emitted and every operator-shaped gap is closed.

Fixed register writes and data barriers followed, taking that to **733 of 775**.
A fixed register reports through the same write slots as any other — what makes
it addressable is that the lift table publishes the index, so `BL`'s link
register needs no operand to name it — and a data barrier becomes a real `fence`
at the strongest ordering, since LLVM's fence has no notion of AArch64's
shareability domains and being stronger than asked is conservative rather than
wrong. The 42 left are the pair exclusives and pair compare-and-swaps, which act
on two registers as one transaction, and the instruction and speculation
barriers, which constrain the pipeline rather than memory and have no IR that
says so. The single-register exclusives came for free with the state array: the
monitor is ISA state like any other.

Effect functions also take an `iW* %state` array for scalar architectural state
— AArch64's NZCV, FPCR, FPSR, SP, and the thread pointers — indexed by the slot
order the generated lifter publishes as `STATE_SLOTS`. Every function takes it,
so a caller implements one calling convention. A read loads its slot at entry
and joins the same forwarding that makes a register write visible to later
effects, which is the mutable state map the executors have, expressed in SSA.
The gate seeds state with non-zero values and compares it after: an instruction
that reads NZCV and one that ignores it agree on an all-zero state, so a dropped
read would otherwise pass.

Atomic read-modify-writes lower to native `atomicrmw` and `cmpxchg` rather than
to a load and a store. AXIS models them as two effects — a register set from an
`atomic_load`, then an atomic store whose value may depend on what was loaded —
and splitting them would give the same answer on one thread, which is the
argument for fusing rather than against it: this gate runs one thread, so a
split lowering would be wrong in exactly the way nothing here can observe. The
pair is recognized structurally and becomes one instruction, or it is withheld.
The differential check proves the value semantics; indivisibility and ordering
are carried by construction. Orderings pair off the way AArch64's A and L bits
do, and an atomic access is driven only at naturally aligned addresses, because
the architecture faults otherwise and AXIS does not yet model that fault.

`%out` carries up to four register writes as `[value0, wrote0, next_pc, trap,
value1, wrote1, …]` — AArch64 `ldp` with writeback needs three. Write `k` is the
`k`-th register-writing effect, which the lift table publishes in order with its
destination operand, so a consumer maps writes to registers without guessing,
and the slot count is emitted as `EFFECT_OUT_SLOTS` so no caller has to hardcode
it. The first four slots are the layout earlier consumers already read.

The width is the widest of the operands, the ISA word, and each effect's own
value, address, and guard. The effects have to be in that maximum: an AArch64
`B` sign-extends its displacement to the 64-bit pc while its only operand is a
26-bit immediate, so an operands-only check would emit a silently truncating
i32 body.

Two things are withheld with an explanatory comment rather than approximated:
state writes, fixed registers, barriers, and atomic groups; and a value that
*reads* named state (AArch64 `adc` takes its carry-in from `nzcv`, which this
ABI does not pass in). The gate requires every register the executor changed to
be accounted for by a reported write, and compares each write against the
register it targets — collapsing them back onto one slot is caught as 3839
failures. Before the ABI carried more than one write, the post-indexed forms
passed while dropping their base-register update entirely, because the
comparison read a single `result`.

An effect that *reads* a register an earlier effect wrote needs no withholding.
A pre-indexed store is `rn = rn + imm; Mem64[rn] = rt`, and the address is the
updated base: each register write records the SSA value holding its result, and
later effects lower against that rather than the parameter — the same thing the
executors' mutable register file does, expressed as a rename on the typed IR
before lowering, so one code path still produces the output.

In `manifest.json` and `aha_instructions.json` the `formal_semantics` field
carries the OptiSynth dialect (PCE ADL.2) when the semantics are expressible
in it: n-ary ops folded to binary, literals typed (`i32:5`), `not` lowered to
`xor -1`, `min`/`max` to `select` over `icmp`. Rotates and extends have no
primitive form in the grammar, but they *are* the shift/mask idioms real LLVM
IR is written in, so AXIS expands them into it — `rol`/`ror` to the canonical
shift-or rotate (`(x << s) | (x >>u (W-s))`, `s = k mod W`), `sext` to
`ashr(shl(x, W-f), W-f)`, `zext` to `and(x, (1<<f)-1)` — giving PCE a rewrite
rule that actually matches incoming IR. Bit counts (`clz`/`ctz`/`cpop`) map to
the OptiSynth `intr` call form — `(intr llvm.ctlz|cttz|ctpop iW x)` — the LLVM
intrinsic the real IR uses; PCE registers Z3 builtin axioms for
`llvm.ctlz`/`cttz`/`ctpop` (validated bit-exact against the golden model), so
these axiomatise and prove too. PCE's `adl_bridge` derives Z3-proven rewrite
rules and intrinsic axioms from the dialect; against PCE main the zbb example now
yields **all 11 proven rules** (was 4, then 8). `optisynth_compatible` flags each
instruction; `semantics.json` always carries the raw AXIS dialect.

Because PCE registers the emitted dialect string as the intrinsic's Z3 axiom, an
unfaithful translation would go undetected by PCE's (consistency-only) proof
gate — so `tools/optisynth_vs_golden.py` evaluates the emitted OptiSynth dialect
with a faithful bitvector interpreter and requires it to equal the trusted
golden model on spec + random vectors, for every `optisynth_compatible`
instruction. That is the AXIS-side guarantee that every axiom PCE banks is
sound, not merely parseable.

## Cycle Simulator

`emit-pack-sim-c` generates a cycle-level simulator for the cores a
description declares — the role gem5 plays, with the machine written as
`defcore` / `defmemory` / `defmemsys` forms instead of C++. One library per
architecture (`libaxis_sim_<name>`, built by `tools/build_pack.py`) decodes,
executes and times programs from the same proven semantics as every other
artifact.

```lisp
(defcore xdecodes
  (kind rvmt) (implements iw32) (memory l1d)
  (issue-width 4)
  (window (rob 32) (issue-queue 32) (commit-width 4))
  (branch (penalty 0) (predictor bimodal) (entries 64))
  (front-end (fetch-width 4) (depth 2) (btb 64) (btb-penalty 3) (icache l1i))
  (engine execute)
  (units (alu (count 4) (pipelined true)) (mul (count 1) (pipelined true))
         (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true))))
```

It models in-order and out-of-order cores: a reorder window, renaming, a
load/store queue with speculation and store sets, branch and target
prediction with a return stack, instruction and data caches or a described
memory system with prefetchers, data and fetch TLBs, and the wrong path a mispredict fetches and executes. An
execution-driven engine (`(engine execute)`) computes values in the pipeline
and has the golden model judge every instruction at commit. Vector units have
lanes, so SVE and SME run on it; several cores share a memory, a core has
hardware contexts and warps, and one unit can be shared between cores. It is
not a full-system simulator: no OS, devices or checkpoints.

See [`docs/pack_simulator.md`](docs/pack_simulator.md) for the overview and
the map to each stage's design document.

## Structural Hardware Backend

`emit-hw-pyrtl` builds the netlist in AXIS rather than shipping semantics for
Python to interpret. Each instruction with `formal_semantics` is lowered to a
graph of hardware primitives at the widths its result actually demands, and the
instructions are then merged into functional units: one adder where sixteen
instructions add, a mux on each input they do not already agree about, and a
`sel` input naming the instruction that is running.

The module it writes carries:

- `INSTRUCTIONS`: each built instruction's builder, inputs and result width;
- `DECLINED`: each instruction with no circuit, and the reason;
- `EFFECTS` and `build_effect_<mnemonic>(...)`: branches, jumps, loads and
  stores, as one wire per value, guard and address (`EFFECTS_DECLINED` for the
  rest);
- `UNITS`: each unit's builder, members (a member's position is its select
  code), inputs and result width;
- `build_<mnemonic>(...)` and `build_unit_<name>(sel, ...)`, as straight-line
  PyRTL;
- `build_unit_<name>_pipelined(valid, sel, ...)`: the same unit cut into as
  many stages as its instructions declare cycles, accepting a new instruction
  every cycle.

`emit-hw-plan` writes the units AXIS would build, and `--hw-plan <file>` on
the `emit-hw-*` commands builds a proposed plan instead -- validated, and
refused only for what would change what the machine computes.

`emit-hw-json` is the plan: per instruction its area, depth and operators or
its reason for declining; per unit its members, operator instances, and area
merged against unmerged, area by operator, and any class of operator the
merger left unshared because sharing would not keep half of what it removes.
The areas and depths come from a cost model calibrated against Yosys and ABC
on SkyWater's open 130 nm cells; the artifact names that reference, and
`tools/hw_calibrate.py` holds the model to it.

`--core NAME`, on any command, is the description as one `defcore` sees it: a
core may give an instruction its own latency and unit (`(timing ...)`), and
state its cycle (`(cycle (gates N))`), and is refused at `axis check` a latency
the instruction's netlist does not fit at that cycle
(`docs/core_timing_design.md`).

`tools/hw_units_check.py` holds every netlist, and every instruction selected
in its unit, to the golden model by simulation. `emit-hw-smt2` writes the same
netlists as SMT-LIB functions and `tools/hw_prove.py` proves them against
`emit-smt2`'s definitions for every input. The module's
`extension_semantics(xlen)` is the mnemonic-to-callable map PCE's
`ExtensionRegistry.register_from_adl` asks an integrator for, and
`extension_datapath(xlen, mnemonics)` is one shared datapath over the merged
units for a dispatcher that can hand over its match wires.
`tools/hw_urv_check.py` runs both inside URV's extension unit.
See `docs/hardware_design.md`.

## PyRTL Backend

`emit-pyrtl` generates a Python module that:

- imports `aha` opportunistically to activate PCE's PyRTL fork when running
  inside PCE;
- imports `pyrtl`;
- exposes `INSTRUCTION_SEMANTICS` and `ACCELERATOR_SEMANTICS` metadata;
- emits `build_<mnemonic>(...)` functions for instructions with
  `formal_semantics`;
- emits `build_<accelerator>_behavior(...)` functions for accelerators with
  `formal_semantics`;
- emits `build_<accelerator>_module(...)` functions that instantiate declared
  PyRTL input/output ports and, when there is exactly one output, wire it to the
  generated behavioral function.

The first semantic evaluator handles simple typed s-expressions such as:

```text
(add i32 (mul i32 rs1 rs2) rs1)
```

`axis check` validates these expressions before emission. The current semantic
IR accepts integer literals, declared operand/port names, optional integer type
atoms such as `i32`, and these operators:

- arithmetic/bitwise: `add`, `sub`, `mul`, `udiv`, `sdiv`, `urem`, `srem`, `and`,
  `or`, `xor`, `not`
- shifts/rotates: `shl`/`sll`, `lshr`/`srl`, `sra`/`ashr`, `rol`, `ror`
- bit counting: `clz`, `ctz`, `cpop`
- IEEE-754 arithmetic: `fadd`, `fsub`, `fmul`, `fdiv`, `fsqrt`, and fused
  `fma` at `f32`/`f64`
- IEEE-754 comparisons: `fcmp_oeq`, `fcmp_olt`, `fcmp_ole`, `fcmp_uno`, which
  return 1 or 0 — the ordered forms are false when either operand is NaN, and
  `-0.0` compares equal to `+0.0`, so none of them is a bit comparison
- conversions: `fcvt_f2s`, `fcvt_f2u`, `fcvt_s2f`, `fcvt_u2f`, `fcvt_f2f`. Like
  the extends, the type atom names the destination width and the first argument
  the source. Float to integer rounds toward zero, **saturates**, and maps NaN
  to 0 — specified by AXIS because a C cast is undefined out of range, ARM
  saturates, and x86 returns the most negative integer
- comparisons: `min`, `max` (signed), `minu`, `maxu` (unsigned)
- width changes: `(sext <type> <from-bits> value)`, `(zext <type> <from-bits> value)`

Floating-point values cross AXIS as bit patterns: an `f32`/`f64` operator
reinterprets its bit-vector arguments as IEEE-754, computes in
round-to-nearest-even, and returns the result's bits. `Sem` therefore stays a
single bit-vector domain — only the operators are new — and the differential
harnesses need no new comparison logic, since comparing result bit patterns is
the only check that catches a wrong NaN payload or a sign-flipped zero. A NaN
result is AXIS's canonical quiet NaN, **specified rather than inherited**: x86
and ARM disagree on propagated NaN payloads, so every backend canonicalizes
explicitly and the comparison holds on any host.

`fma` is spelled explicitly rather than left to a compiler's contraction
choice: it rounds once where `(a * b) + c` rounds twice, and the two differ on
inputs like `a = 1 + 2^-52, b = 1 - 2^-52, c = -1`.
`tools/fp_fusion_check.py` drives that witness through the golden model, C, and
Rust and requires both agreement with golden *and* disagreement between the
fused and unfused instructions — without the second requirement, a backend that
contracted everything would still pass every other gate. Contraction cannot reach the generated artifacts: an unfused multiply-add
lowers to `axis_fp64_add(axis_fp64_mul(a, b), c)`, and the intermediate
round-trips through a bit pattern and a NaN test, which no compiler can fuse
across. Verified by compiling the witness with `-ffp-contract=fast` and finding
the two instructions still distinct. The flag still matters for *consumer* code
that writes plain float expressions; it is not a requirement AXIS's own output
imposes.
Float entries get FP-shaped sample vectors (signed zeros, infinities, quiet and
signalling NaNs, normal extremes, smallest subnormal), so the existing gates
exercise those classes instead of waiting for random bits to reach them.
Conversions are proven too: the SMT lowering reconstructs the saturation with
explicit threshold tests, because `fp.to_sbv`/`fp.to_ubv` are unspecified for
NaN and out-of-range inputs — the very cases AXIS makes total.

`emit-smt2` lowers float operators through SMT-LIB's FloatingPoint theory
(`QF_BVFP`, `fp.add`/`fp.sub`/`fp.mul`/`fp.div` with an explicit `RNE` rounding
mode), so `tools/smt_vs_golden.py` *proves* these semantics equal to the golden
model rather than sampling them — z3 must return `unsat` for the negation of
every case. Integer-only documents keep the narrower `QF_BV`. The canonical-NaN
rule is what makes the proof possible: SMT-LIB leaves `fp.to_ieee_bv`
unspecified for NaN, so selecting the canonical pattern on `fp.isNaN` first is
what removes the underspecification. Float instructions also reach the effect layer: `FCMPS_S`/`FCMPS_D` in the
corpus compare and write a four-bit condition code to named architectural state,
the way AArch64 FCMP writes NZCV, and all three executors prove that write as
part of the architectural delta. See
[`examples/fp_scalar.axisl`](examples/fp_scalar.axisl).

Floating point also says what it **signalled**, not only what it computed. The
`_fx` form of an operator — `fadd_fx`, `fdiv_fx`, `fsqrt_fx`, `fma_fx`, and the
five conversions `fcvt_f2s_fx`, `fcvt_f2u_fx`, `fcvt_s2f_fx`, `fcvt_u2f_fx`,
`fcvt_f2f_fx` — yields the five-bit exception word the same operation raises,
in RISC-V's `fflags` order, and an instruction accrues it with an `or`, which
is what `fflags` means. They take no rounding mode: which exceptions an
operation raises does not depend on the direction, except for inexact, and an
inexact result is inexact under every mode. C reads the floating-point
environment, the golden model decides from exact rationals, and Rust, LLVM and
SMT decline for the reason they decline directed rounding.

Comparisons need no operator at all: `FLT`/`FLE` signal invalid on any NaN and
`FEQ` only on a signalling one, and both are predicates on the bit pattern, so
they are written as ordinary `defsem`s and *every* backend lowers them. Float
to integer needs one and cannot use the environment even in C — AXIS specifies
truncate-saturate-NaN-to-zero, so the C cast whose flags `fetestexcept` would
report is undefined in exactly the out-of-range case that must signal.

The operators are ISA-neutral, and
[`examples/aarch64_fp_env.axisl`](examples/aarch64_fp_env.axisl) is where that
claim is measured rather than asserted. Half of it holds outright: `_rm` takes
the encoding AArch64 uses, so `FPCR.RMode` reaches it through
`(and (lshr fpcr 22) 3)` and nothing else — RISC-V is the ISA that maps, passing
3 for its RTZ. The other half does not: `_fx` returns `fflags` order and
AArch64's FPSR is its five-bit reversal, which the corpus states as an ordinary
expression. Neither needed a language change, which is the point.
`tools/a64_fpenv_check.py` requires each condition to land on the AArch64 bit by
number, since six backends reading one reversal would agree about a wrong one.
It runs against the translation seed as well, which is where FPCR and FPSR are
declared and where `MRS`/`MSR` read and write them: that corpus now has scalar
double arithmetic to consult them, each instruction with an accelerator
counterpart and a lowering between, and a `a64_vreg64` register class for the
`V` file — a separate file above the general-purpose one, because `d0` is not
`x0`.

Two rules IEEE-754 leaves open, AXIS decides and states. **Tininess is detected
before rounding** — underflow asks whether the *exact* result fell below the
smallest normal, not whether the rounded one did — which is what x86 and AArch64
do, and so what C can read from the environment. And **integer-to-float rounds
once**: going through a double first is two roundings, and for a source wider
than a double's 53 bits the two disagree. RV64's long conversions are the first
instructions that can ask, and the answer is one in 2^39 of the input space, so
the witnesses live in `smt_vs_golden` beside the ties-to-even ones rather than
waiting for a uniform draw.

The differential ladder cannot check any of this on its own: the rules are
stated once, in the corpus, so a comparison signalling on the wrong kind of NaN
would be emitted identically by all six backends. `tools/fflags_check.py`
restates them from the RISC-V spec — witnesses with hand-written flags, plus a
property sweep for the invariants no finite table shows — the same argument
`FCLASS` needed its own gate, one level along.

A **shift amount is read at the node's evaluation width**, like any other
argument: `(shl i8 v n)` shifts by the low eight bits of `n`, and an amount at or
past the width shifts everything out. Not a free choice — SMT-LIB's `bvshl` takes
both operands at one sort and resizes the amount, so a rule keeping the full
value is one that backend cannot implement.
[`examples/shift_widths.axisl`](examples/shift_widths.axisl) pins it on narrow
nodes, which is the only place the question is observable: at 64 bits an amount
cannot exceed the width without exceeding the word too. RISC-V never raised it
because its shifts mask the amount themselves, the way hardware with a
five-bit shift field does; a description language cannot assume that.

`(ones <type> <count>)` is a mask of `count` low bits and `(ones <type>)` is
every bit of the width; `(zeros …)` is zero, and is there because a cleared mask
reads as one beside the `ones` it complements. The count is an ordinary
expression, which is the whole reason this is an operator rather than something
an author writes as a literal — a mask of `vl` low bits, where `vl` is a
register, is not a constant. A count at or past the width gives every bit rather
than wrapping or faulting, and every backend states that separately, because
`1 << n` means four different things: zero in SMT-LIB, poison in LLVM, undefined
in C, an unbounded integer in Python. The count is evaluated at the node's
width like any other argument — not a free choice, since SMT-LIB must resize an
operand to the node's sort before it can use it.
[`examples/masks.axisl`](examples/masks.axisl) drives the counts from registers
so the gates reach the cases a literal never would, and RISC-V's `FLS` writes
its NaN-box as `(not i64 (ones i64 32))` instead of `0xffffffff00000000`.

A **vector type atom** `v<lanes>i<elem>` (`v2i32`, `v4i16`, `v8i8`) applies a
lane-local operator to each lane of a register independently: `(add v2i32 vn vm)`
adds two 32-bit lanes of a 64-bit register without carry crossing the lane
boundary. Vectors are elaboration-time shorthand — `src/simd.rs` expands them
into the bit-vector semantics before validation, the same stage that inlines
`defsem` calls — so every backend and gate handles them with no new code, and
the golden model, SMT, and LLVM all prove them. Operators that are not
lane-local (extends, select, cross-lane reductions) are rejected rather than
approximated. [`examples/simd_lanes.axisl`](examples/simd_lanes.axisl) carries
AArch64's 64-bit D-register shapes, proven on all five semantics backends, and
[`examples/simd_q_lanes.axisl`](examples/simd_q_lanes.axisl) the 128-bit
Q-register shapes, proven on four — LLVM and Rust have native 128-bit integers
while standard C does not, so the C header skips those with the reason stated
rather than reaching for `unsigned __int128`.

Because the expansion is elaboration-time, it is also the *definition* of what a
lane-wise operator means, which leaves each backend free to implement that
definition however it lowers best. LLVM does: it emits native `<N x iW>`, so one
operator becomes one instruction and the lane parallelism is visible to the
optimizer instead of buried in a shift/mask tree.

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

That is a second implementation of the same semantics, so it needs no new
oracle: `llvm_vs_golden` already proves the emitted IR against the golden
model's expansion. The lowering is intentionally narrow — one lane-parallel
operator over `add`/`sub`/`mul`/`and`/`or`/`xor` — and everything else (`not`,
min/max, nested or mixed expressions) falls back to the expansion rather than
being partially vectorized. `simd_lanes.axisl` exercises both paths in one
document: `VADD_2S` lowers natively, `VMAXS_4H` falls back, and both are proven.
Widening the operator set is additive, with the oracle already in place.
Lanes are not integer-only: `v<lanes>f<elem>` (`v2f32`, `v4f32`, `v2f64`) hands
each lane to the IEEE-754 operators, and because an AXIS float is a bit pattern
the lane extraction is the same bit-vector work either way — the element domain
changes only the type atom the per-lane operator receives.
[`examples/simd_fp_lanes.axisl`](examples/simd_fp_lanes.axisl) carries the
AArch64 2S/4S/2D shapes, proven on all five semantics backends and the executor.
Lane-wise *compares* are deliberately rejected: an AArch64 one writes a lane mask
of all-ones or all-zeros rather than the 1/0 the scalar operators return, so
spelling it as a lane-wise `fcmp` would mean the wrong thing.

See [`docs/simd_fp_design.md`](docs/simd_fp_design.md).

The type atom sets the evaluation width for width-sensitive operators (sign
bits, rotate distance, zero counting). Rotate distances are taken modulo the
width; shift distances at or beyond the width saturate (zeros for `lshr`, sign
fill for `sra`). This operator set covers RISC-V Zbb-class instructions —
`examples/zbb_like.axisl` exercises all of it.

`tools/smt_vs_golden.py <input.axisl>` differentially checks the emitted SMT
semantics against the emitted golden model with z3: every `formal_semantics`
function is evaluated on edge-case and random vectors and the SMT definition
is proven to return the same values.

`tools/roundtrip_check.py <input.axisl>` compiles the generated
`axis_encode.h`/`axis_decode.h` with cc and runs every roundtrip fixture
through them: encode operand values, compare the instruction word, decode it
back, compare the mnemonic.

`mode_legality_manifest.json` uses `axis.mode-legality.v1` and, when a document
declares a `mode` selector (a WARL CSR field, `docs/personality_design.md`),
carries the selector plus, per mode value, the `{mnemonic, match, mask}` legal
in it. Disjointness is checked *within* a mode, so instructions with disjoint
`modes` may legally reuse an encoding across modes (a polymorphic tile);
`manifest.json` gains a per-instruction `modes` array only when restricted, so
mode-free documents stay byte-identical. `tools/legality_vs_golden.py` proves,
for every mode × word, that this per-mode table agrees with the decode table
and the instructions' `modes`.

A `personality` may bind to a mode value (`(mode simt)`) and a `core` may compose
several (`(personalities scalar1 simt8 xnn0)`); the topology manifest then
carries the composed personalities under their core with mode and discipline
(`examples/personality_composition.axisl`). A core without composed personalities
stays byte-identical.

[`examples/personality_composition.axisl`](examples/personality_composition.axisl)
is its exact Lisp counterpart: full typed AST equality, 36 byte-identical
bundle artifacts, and 2,496 migration programs are enforced in tests.

[`examples/rvmt_xpce.axisl`](examples/rvmt_xpce.axisl) is the Lisp-authored
primary PCE compatibility example. Its instruction cost model, compiler
intrinsics and pattern metadata, accelerator contract, memories, core, and
tile drive all 34 bundle artifacts. The PCE contract oracle and
encode/decode, lift, and execution gates run directly on the Lisp source.

`axis_exec.py` `step(word, ..., mode=)` decodes **mode-aware**: among the
instructions matching a word it runs the one legal in `mode`, so a reused
encoding executes different instructions per mode (`SCALAR_OP` in `scalar`,
`TENSOR_OP` in `xnn`); a word illegal in the mode takes the trap path
(`trap="illegal"`). Without `mode=`, decode is unchanged. `tools/legality_vs_golden.py`
drives the executor and requires its per-mode decision to agree with the
legality manifest and the decode table.

`packet_manifest.json` uses `axis.issue-packet.v1` and describes a statically
scheduled machine's **issue packet**: the row of slots a VLIW core issues
together (`docs/vliw_spatial_design.md`, stage B1). A slot has a width and a
set of functional-unit classes; an instruction declares the `unit` that
executes it, and slot legality is derived from that rather than declared per
slot. A packet is a container of ordinary ≤32-bit syllables, not one wide word,
so nothing in the encoding core widens.

Slots give the decode space a second index, the way modes gave it a first:
two instructions contend for a bit pattern only if some slot can hold both. In
[`examples/vliw_packet.axisl`](examples/vliw_packet.axisl) `VSTW` and `VBRZ`
carry the *same* word, because `mem` is held by slot 0 alone and `br` by slot 3
alone — plain decode reports that word as ambiguous, and each slot resolves it
to its own instruction. `tools/packet_roundtrip.py` packs every slot
assignment, decodes it back, and requires the slots, mnemonics and operand
values to survive the container; it also requires perturbed containers to be
rejected *or* decode slot-legally, and fails a run in which a slot or a
declared unit class never carried a syllable.

`axis_exec.step_packet` gives a packet its semantics: every syllable is
evaluated against the state the packet started with, and the writes land
together. A read-after-write between slots reads the **old** value, and a load
in one slot does not see a store in another. Two syllables writing one
register, state slot, memory byte or `pc` is reported in `conflicts` and
commits nothing — never resolved by slot order, because a machine that picks a
winner has to say so and none can say so yet. A trap commits nothing either: a
packet retires whole or not at all. `next_pc` steps by the decoded group's byte
length. Validation refuses the two hazards no packet could resolve: two slots
that can both transfer control under `at_most_one`, and two slots that can both
write one fixed location unconditionally.

`tools/packet_vs_serial.py` proves it against the definition rather than
against a second copy of the executor — each syllable run **alone** against the
pre-packet state, then merged, computed through the ordinary single-instruction
path. Independent packets must agree with serial execution in every order; a
slot-crossing read-after-write and a load-against-store must **differ** from
it, and a case where they came out equal fails as vacuous instead of passing;
the two conflicts must be refused while serial execution of the same syllables
produces a value. All six classes are required to appear in a run.

A packet may declare `(hazards exposed)`: no interlocks, and a register write
with `latency` L becomes visible to the packet issued L packets later, with the
schedule responsible for the gap. The queue holding those in-flight writes is
passed to `step_packet` alongside the register file, because it *is*
architectural state — `new_delay_queue()` makes one, and stepping an exposed
packet without one raises rather than quietly running an interlocked machine
under the other name. A latency of 1 is visible to the next packet, so an
exposed machine whose every latency is 1 has no shadow and is an interlocked
one. Only register writes wait; stores, state writes and control transfers
commit with the packet.

Because the shadow is state, the capsule carries it: an exposed personality's
capsule gains a `__delay` section, sized from the same derivation the executor
reads, with its 16-byte entry format published field by field. That changes the
layout hash, so the manifest cannot call an exposed personality migratable with
an interlocked one. `tools/exposed_latency_check.py` emits the description
under both disciplines and compares the two machines, requires both edges of
the shadow (invisible for L-1 packets, visible on the L-th), and checkpoints at
every packet boundary through the `__delay` bytes — then repeats the checkpoint
with that section zeroed, which must **differ**, or the section is not carrying
state and the round-trip proved nothing about it
(`examples/vliw_exposed.axisl`, `docs/vliw_spatial_design.md` §7).

`state_capsule_manifest.json` uses `axis.state-capsule.v1` and pins, per
`personality`, the canonical byte layout of its portable architectural state
(the migratable "capsule" — registers + pc resolved against the ISA surface),
with a dependency-free SHA-256 `layout_hash` so consumers match checkpoint
formats by hash. `migratable_pairs` lists personalities that share a layout. It
is emitted only when a document declares personalities (see
`docs/personality_design.md`, `examples/personality_tile.axisl`).
`tools/migrate_vs_whole.py` proves the format: for every migratable pair and
every checkpoint point, checkpoint on A → serialize the capsule → restore on B →
finish equals the uninterrupted whole run, and re-derives each `layout_hash`
from its canonical string.

`tools/c_vs_golden.py <input.axisl>` compiles `axis_semantics.h` and requires
it to match the golden model bit-for-bit on the spec registry's deterministic
vectors plus randomized ones.

`tools/rust_vs_golden.py <input.axisl>` is the Rust sibling: it compiles
`axis_semantics.rs` with rustc and requires the same bit-for-bit agreement with
the golden model (skips cleanly if rustc is absent).

`tools/llvm_vs_golden.py <input.axisl>` is the LLVM-IR sibling: it compiles
`axis_semantics.ll` with clang against a generated driver and requires the same
bit-for-bit agreement with the golden model (skips cleanly if the local clang
cannot compile textual LLVM IR).

`tools/pce_smoke_check.py` loads an emitted bundle through PCE's real
loaders (`aha.isa.adl_loader`, `aha.optisynth.adl_bridge`), derives ADL.2
rewrite rules, registers intrinsic axioms, and requires every derived rule to
pass PCE's Z3 proof gate. It is the runtime proof that AXIS bundles load — passing
against PCE main for `rvmt_xpce` and `zbb_like`.

`tools/pce_contract_check.py` is its CI-resident guard: a self-contained oracle
that validates `emit-bundle` output against the exact field surface and
constraints those consumers read (the strict `pce-adl.aha-instructions.v1`
schema; the required/optional bundle file names; per-instruction mnemonic +
encoding; the `opcode`/`func3`/`func7` bit-ranges and `latency_cycles >= 1` that
`xrv_extension.from_adl` enforces; the operand fields) across every AHA-emittable
example — with **no PCE checkout**, so drift fails in AXIS CI before PCE sees it.
The Rust golden test `aha_json_pce_consumer_contract` pins the same surface at
emit time. See `docs/pce_migration.md` for the full contract and retirement plan.

This gives PCE immediate generated behavioral hooks for PyRTL golden models,
cosim, and early execute-unit experiments, plus a first structural accelerator
skeleton for port-level integration.

## Verification

```bash
cargo test
```

Current tests cover parsing, validation, manifest emission, compiler collateral,
RVMT compatibility output, bundle contents, ISA block emission, accelerator
semantic fields, and PyRTL emitter output.

`cargo test` pins the emitters; the `tools/` harnesses prove the emitted
artifacts against each other. To run the whole evidence ladder:

```bash
python3 tools/check_all.py            # every gate, on its corpus
python3 tools/check_all.py --quick    # skip the slow AArch64 gates
python3 tools/check_all.py --list     # the matrix, without running it
python3 tools/check_all.py --only jit # gates matching a substring
```

It reports one line per gate and exits non-zero if any failed. A gate that
cannot run for want of a toolchain (clang, rustc, llvmlite, z3) prints `SKIP`
and is counted separately, so a missing dependency never reads as a pass.
`pce_smoke_check` needs a PCE checkout and is opt-in via `--with-pce`.

The differential harnesses take a corpus path and default to the one they
were written for.
