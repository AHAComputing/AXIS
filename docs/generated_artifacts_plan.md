# AXIS Generated Artifacts Plan

This is the backend roadmap for AXIS-generated artifacts. The goal is one
typed architecture source that can feed compiler integration, simulators,
interpreters, JIT execution, proof tooling, and PCE/AHA handoff bundles without
each consumer reparsing ad hoc strings.

AXIS is the permanent home for all ADL work; PCE's in-repo seed crate
(`software/pce-adl/`) is frozen and will be retired. The named consumers that
drive prioritization are PCE/AHA's trustworthy tier — the URV extension-unit
dispatch path, the OptiSynth ADL bridge (planned ADL.2: semantics → Z3 axioms
and rewrite rules), and the ALGO-WATCH autonomous op-synthesis loop. The RVMT
tile surface is compat-frozen. See `docs/pce_migration.md` for the verified
consumer seams, contract invariants, and seed-retirement steps.

## Source Of Truth

All generated artifacts should flow from the same validated AXIS model:

```text
.axisl source
  -> parsed AST
  -> validated semantic IR
  -> target-specific generated artifacts
```

The important invariant: instruction encodings, operand lists, side effects,
latency/resource metadata, and formal semantics must agree across every emitted
artifact. If an emitter needs information that is not represented in the AST or
semantic IR, add it to AXIS first instead of hiding it in backend-specific code.

Explicit cross-ISA sequence rewrites are represented in the typed model as
Lisp `deflowering` rules. Their SSA-like operand bindings, legality predicate,
and cost metadata are validated before emission; source semantics are composed
and proven identical to the target semantic IR. They are emitted in
`axis.translation-map.v1` under `explicit_lowerings`, while exact
single-instruction discovery remains under `matches`.
`axis_translate.py` (`axis.translation-python.v1`) is the first executable
consumer: it performs deterministic longest/highest-benefit matching, binding
unification, predicate checks, and target instruction packing without importing
the AXIS compiler.

The production AArch64 seed exercises this path for 435 explicit lowerings: W/X
shifted-register logical forms and nine shifted-register arithmetic families,
carry-chain `ADC`/`ADCS`/`SBC`/`SBCS`,
signed and unsigned 64-bit multiply-high,
W/X extract/funnel-shift and rotate-immediate aliases,
signed and unsigned W-to-X widening multiply-accumulate families,
shifted-register arithmetic/logical families, unsigned-offset memory and typed
byte/halfword/W/X pre/post-index writeback, W/X offset/pre/post-index
`LDP`/`STP`, W/X scalar and paired relaxed/acquire/release
load/store-exclusive operations with address/size/valid reservation state,
atomic two-address commits, retained access ordering, encoded `CLREX`
monitor invalidation, non-exclusive B/H/W/X acquire loads and release stores,
typed option-preserving `DMB`/`DSB`/`ISB` barriers, and specialized
`SB`/`CSDB`/`SSBB`/`PSSBB` speculation barriers,
and NZCV `MRS`/`MSR` system-state transfers,
plus direct, conditional,
indirect, return, link-producing, compare-zero, and test-bit branches.
The atomic mapping surface also includes B/H/W/X signed maximum/minimum and
unsigned maximum/minimum in relaxed, acquire, release, and acquire-release
forms.
It also covers W/X immediate ADD/SUB, their flag-setting forms, and state-only
CMN/CMP aliases. The same result/alias split covers W/X extended-register
arithmetic. Coverage includes source
decode legality, architectural XZR guards, ordered NZCV state preservation,
state-only targets for discarded-result aliases, up to three register results,
signed offset edges, and exact ordered memory access/address/value/writeback
equivalence. Branch rules additionally preserve exact PC expressions,
conditional guards, and ordered fixed-register link writes, with runtime
checks for both taken and fall-through paths. W/X register views and low/high
test-bit selection are preserved explicitly. Immediate rules preserve SP/WSP
selector-31 behavior, zero-or-12-bit shifting, W zero extension, and NZCV.
Extended lowering additionally checks every UX*/SX* option at every legal
shift from zero through four.
W/X `UDIV` and `SDIV` preserve XZR/WZR roles, return zero for a zero divisor,
truncate signed quotients toward zero, and retain `MIN` for `MIN / -1`.
W/X `CSEL`, `CSINC`, `CSINV`, and `CSNEG` consume architectural NZCV without
modifying it; their lowering tests exhaust all 256 NZCV/condition combinations
and cover the equal-input and zero-input forms underlying `CINC`/`CINV`/`CNEG`
and `CSET`/`CSETM` assembler aliases.
One-source W/X lowering covers `RBIT`, `REV16`, lane/full-width `REV32`/`REV`,
`CLZ`, and `CLS`. Lisp `defsem` definitions compose their exact bit-vector
meaning from `let`, masks, shifts, and leading-zero count instead of relying
on backend-specific prose.
Logical lowering checks LSL, LSR, ASR, and ROR at zero, one, and the
width-specific maximum amount, including XZR/WZR inputs, W zero extension,
and the N:Z:0:0 effects of ANDS/TST.
Variable-register lowering adds W/X LSLV, LSRV, ASRV, and RORV with explicit
modulo-width count boundaries, selector-31 zero inputs, arithmetic shifts,
rotates, and W-result zero extension.
Move-wide lowering covers X MOVN/MOVZ/MOVK over all halfword lanes and
immediate extrema; MOVK additionally proves its read-modify-write destination
preserves the three unselected halfwords.
Logical-immediate lowering covers W/X AND/ORR/EOR/ANDS/TST with complete
six-bit mask fields, every legal replicated-element shape, rotation edges,
zero-register inputs, W zero extension, logical flags, and reserved encodings.
Bitfield lowering covers W/X SBFM/BFM/UBFM and every legal `immr`/`imms`
pair. BFM proves its read-modify-write destination, while W forms expose the
architectural six-bit fields and reject either immediate when it exceeds 31.
Typed unsigned-offset memory lowering covers zero-extending byte/halfword/word
loads, sign-extending byte/word loads, and truncating byte/halfword/word
stores. Its boundary matrix preserves scaling, access width, signedness, and
the distinction between an AArch64 SP base and generic accelerator registers.
Register-offset LDR/STR lowering retains the SP-capable base and XZR-capable
index/data roles directly on the target, including scale-by-eight addressing,
discarded XZR load results, and zero-valued XZR stores.
W/X MADD/MSUB lowering adds modular three-source multiply-accumulate semantics.
XZR/WZR accumulator and destination cases cover MUL/MNEG aliases and discarded
results, with overflow checked independently in Python, C, and Rust.

`decode_table.json` is the table a decoder is built from, and until
`tools/decode_table_check.py` existed nothing decoded with it: two tools read the
file and neither used it to pick an instruction out of a word. That is the one
property it exists to have, and it did not always hold -- the table published a
match, a mask and sometimes an ISA, while the validator permits two instructions
to share a word whenever their modes are disjoint, their units sit in disjoint
packet slots, or a predicate separates them. It carries `modes` and `unit` now,
and the gate is what says they are enough. Withholding either one fails it.

`asm_disasm.json` is a self-contained account of how an instruction is spelled
and where each operand's bits live, and `tools/asm_disasm_check.py` builds an
assembler and a disassembler out of it and runs them against the roundtrip
fixtures the encoder proves. Nothing in that gate reads the AXIS model, which is
the point: publishing a description that does not reassemble is what it exists
to catch.

Making it pass required the file to say three things it did not. Two
instructions may share a decode word when their **ISAs** differ, when their
**modes** are disjoint, or when their **units** sit in disjoint packet slots --
the validator proves exactly that, plus a decode predicate -- and the
description published only a match and a mask, so a consumer saw one word
meaning two instructions and had to guess. All four now appear, and each is
emitted only when it restricts something, so a document with no modes and no
packets produces byte-identical output to before.

It also required the assembly to be right, which it was not: 44 templates named
an operand the instruction does not have, several omitted an operand entirely,
and instructions that spell no assembly of their own got a synthesised one built
from their *input* operands, so the text named everything they read and nothing
they wrote. All fifty-five corpora pass now.

`axis_manifest.py` (`emit-python`) is the one artifact that is a *second
rendering of another*: `RVMT_EXTENSION_MANIFEST` is the RVMT extension manifest
and `PCE_ADL_MANIFEST` the AXIS one, both as Python literals. It is produced by
rewriting JSON's three literals -- `true`, `false`, `null` -- into Python's, and
that was done with a string replace, which rewrote them inside string *values*
too. The manifest is mostly prose, so a rationale reading "true of a null count"
came out as "True of a None count": the Python artifact disagreed with the JSON
it mirrors, in the data, and nothing compared the two. The rewrite walks the
document now and touches only what is outside a string.

`tools/manifest_python_check.py` imports the emitted module -- importing is part
of the check, since substring assertions pass on a file that is not valid Python
-- and requires both dicts to equal the JSON they mirror, reporting the first
differences by path. `examples/masks.axisl` carries those three words as English
in a rationale so the case stays covered; reverting the emitter fails the gate on
exactly that string.

The "validated semantic IR" stage is concrete: `src/ir.rs` lowers the parsed
`formal_semantics` s-expression into a typed, width-resolved tree (`Sem`) with
normalized operators (`sll`→`shl`, etc.), decoded literals, and `sext`/`zext`
source widths carried as fields. The validator, the OptiSynth normalizer, and
the C and SMT emitters all lower from this one IR rather than each re-walking
the raw s-expression — arity, type-atom width resolution, and the extend rules
live in exactly one place. New semantic operators and new semantic backends
should extend `src/ir.rs` and match on `Sem`, not re-parse strings. (The
`semantics.json` reflector is the deliberate exception: it serializes the raw
surface syntax, so it stays off the normalizing IR.)

## Artifact Layers

### 1. Manifest And Bundle Contracts

Status: started. AXIS currently emits `bundle_manifest.json`,
`decode_table.json`, `axis_encode_table.json`, `axis_encode.h`,
`axis_roundtrip_tests.json`, `axis_decode.h`, and `asm_disasm.json`. The
remaining work is full executable operand encoding/decoding plus binary
roundtrip test runners.

Outputs:

- `bundle_manifest.json`
- `manifest.json`
- `semantics.json`
- `semantics.smt2`
- `rvmt_extension_manifest.json`
- `decode_table.json`
- `axis_encode_table.json`
- `axis_encode.h`
- `axis_roundtrip_tests.json`
- `axis_decode.h`
- `asm_disasm.json`
- `adl_topology_manifest.json`
- `accelerator_descriptor_manifests.json`
- `rvmt_launch_templates.json`

Purpose:

- Stable handoff surface for PCE, AHA, RVMT, simulator harnesses, and SDK code.
- Machine-readable index of instructions, accelerators, memories, topology, and
  typed semantics.

Minimum validation:

- JSON validity.
- Stable schema names.
- Golden tests for key fields.
- Backward compatibility with existing PCE bundle consumers until migration is
  complete.

### 2. LLVM TableGen

Status: **superseded by a target.** `emit-tablegen` is still the stub
described below -- a patch into LLVM's RISC-V backend, kept as a compatibility
baseline and checked by nothing. The real TableGen is `emit-llvm-target`: a
self-contained target tree that LLVM's own generators build
(`docs/llvm_backend.md`, L1–L4 built). The plan below is the stub's, kept for
the record.

Outputs:

- `instructions.td`
- Eventually split files:
  - `AxisInstrFormats.td`
  - `AxisInstrInfo.td`
  - `AxisIntrinsics.td`
  - `AxisPatterns.td`

Purpose:

- Define instruction encodings.
- Define assembler/disassembler records.
- Define compiler-visible instruction metadata.
- Provide the anchor for SelectionDAG/GlobalISel/MC integration.

Needed AXIS data:

- Instruction format.
- Opcode/funct fields.
- Operand kinds and widths.
- Assembly syntax.
- Register class constraints.
- Immediate ranges/sign rules.
- Feature predicates.
- Scheduling/latency metadata.

Near-term plan:

1. Keep current deterministic `.td` output as compatibility baseline.
2. Done: `instruction` has an explicit `asm:` field (parsed, used in examples).
3. Emit separate TableGen records for formats, instruction definitions, and
   feature predicates.
4. Add tests that TableGen output includes encoding fields, operand DAGs, and
   asm strings for each instruction.

### 3. Assembler And Disassembler Collateral

Status: started. AXIS emits decode metadata, encode metadata, C encode/decode
headers, asm/disasm metadata, and deterministic JSON roundtrip fixtures. Full
executable encoders, C/Rust decode source files, and binary roundtrip test
runners remain open.

Outputs:

- LLVM MC asm/disasm TableGen records.
- Standalone generated decode tables for simulator/interpreter use.
- Standalone generated encode tables for assembler and fixture generation.
- Deterministic JSON roundtrip fixtures.
- Optional C/Rust decode helpers:
  - `axis_decode.h`
  - `axis_decode.c`
  - `axis_decode.rs`
- Optional C/Rust encode helpers:
  - `axis_encode.h`
  - `axis_encode.c`
  - `axis_encode.rs`

Purpose:

- Assemble AXIS custom instructions.
- Disassemble binary streams for debugging, traces, and simulator logs.
- Provide a fast decode path independent of LLVM for PCE simulators.

**The decode path is a tree.** `axis_decode.h` used to answer one word by
scanning the whole table -- 854 mask/compare pairs and a `strcmp` per word on
the AArch64 seed. It now emits, beside the table, `AXIS_DECODE_NODES` and
`AXIS_DECODE_LEAVES`: a recursive partition on the bits *every* candidate at a
node constrains. Since each candidate constrains those bits, a word that could
match one of them necessarily carries the value that leads to it, so the leaf a
word reaches holds every entry that could match it and the selection rules run
there unchanged. rv32i's 247 entries partition to leaves of at most 3, rv64i's
318 to 4, the AArch64 seed's 854 to 52; measured over 2M random words that is
8.9x, 10.8x and 10.7x faster than the scan.

**Scripts bind that decoder; they do not restate it.** `axis_decode.h` is
header-only `static inline`, which a foreign-function binding cannot see -- there
is no symbol to look up -- so the **pack's** decode library supplies them, and
`tools/axis_decode_ffi.py` compiles it with a twenty-line shim of flat names and
loads the result. ⚠️ That shim used to be an emitted artifact,
`emit-decode-abi-c`, whose symbols were identical for every description: two
architectures could not be loaded into one process. The command is gone; the
code behind it is what `emit-pack-decode-c` makes `static` and wraps. The ABI is
flat and index-based on purpose: only integers and `const char *` cross the
boundary, because a binding that reads `axis_decode_entry` through ctypes has to
restate the struct's layout, and a field added on the C side then silently shifts
what Python reads. An index has no layout to get wrong.

The alternative -- reading `decode_table.json` and writing the match/mask loop in
Python, which is what `aha/socc/axismine_decoder.py` does -- is a **second
decoder**: a second set of selection rules (the ISA filter, the definedness skip,
the rule that several entries on one word are the lanes of one scalable
instruction) to keep in agreement with the first, and nothing in either
repository would say which was right when they diverged.

**Decode in bulk.** Measured on the AArch64 seed, best of five: the compiled
decoder costs **0.05 us/word**, a raw ctypes call 0.34, and `decode()` -- which
also builds an `Instruction`, four calls per operand -- **20.1**. So the cost is
object construction, not the crossing, and a per-word binding gives back most of
what compiling the decoder bought. `axis_abi_decode_buffer`, `axis_abi_decode_le`
and `axis_abi_operands_buffer` take a whole buffer per call; with names looked up
through `Decoder.mnemonics` (a tuple built once at load) that is **0.25 us/word**,
five times the C decoder rather than four hundred. On a 2.5M-word text section:
0.6s instead of 50s. `decode_le` assembles words from bytes with explicit shifts,
so a little-endian image decodes the same way on any host -- which casting the
buffer to `uint32_t *` would not.

`tools/decode_ffi_check.py` checks the boundary rather than the logic behind it,
since a binding's failures are marshalling failures: identity fields against
`emit-decode-json`, operand extraction against the encoder over every roundtrip
fixture, tree against scan inside the caller's own process, and the out-of-range
edges. Writing it found two defects in the ABI on the first sweep -- AArch64's
CASP takes a register *pair* whose second half is `rs + 1` and is stored in no
bits at all, so extraction returned 0 for it and shifted by the unencoded row's
`lsb` of -1, which is undefined rather than merely wrong.

**What a real binary has that a description does not.** `tools/binary_coverage.py`
takes a description and an object file -- ELF64 or Mach-O, thin or universal --
and reports coverage plus the words that did not decode. This is AXISMINE's
caveat 4 made measurable: a kernel corpus cannot exercise what a real binary has,
so the instructions a description is missing are the ones no benchmark shows.
Run against `/bin/ls` (arm64e, nobody compiled it for this), the AArch64
translation seed decodes **87.0% of `__text`** and 75% of `__auth_stubs`; the
remainder is arm64e pointer authentication (`0xd503237f` `pacibsp`, `0xd65f0fff`
`retab`, `0xd71f0a11` `braa` 84 times in the stubs), some SIMD, literal data
interleaved in text, and, until they were added, one real gap:
the seed had `MOVZ_X`/`MOVK_X`/`MOVN_X` and not their 32-bit forms.

Classifying every undecoded word across eight system binaries -- one call to
`llvm-mc` per word, since disassembling them in one batch silently drops the
ones it cannot encode and shifts every later line onto the wrong word -- put
`MOVZ_W`/`MOVN_W`/`MOVK_W` at 1569 of 3253 misses, ahead of `pacibsp` at 433.
Adding them, with the `ACCEL_MOVZ32`/`MOVN32`/`MOVK32` targets their lowerings
need, took `/bin/ls` from 87.0% to **93.7%**, `sed` to 95.5% and `cat` to 96.4%.
The SIMD&FP load/store followed, and with them the vector file's real shape.
`V` is 128 bits and `q0` and `d0` are one register, so the file is **two limbs
of 64** -- not one slot holding 128, which works only where integers are
arbitrary precision and the generated C and Rust are not. `a64_vreg64` became
the low limb's view, which also makes a `D` write zero the upper half the way
the architecture says; it had carried that policy all along over 64-bit storage,
where there was nothing to zero. The two classes share a `lowering_family`,
because that is what says a view and its file are the same file.

That took the table's own invariant with it: *a class with no view must be one
limb*, since a read of a two-limb register could not say which limb it meant.
A class that declares the width of all its limbs can -- a read is every limb,
concatenated, which the graph's `limbs` on live-ins and live-outs already carry
-- so the invariant now admits exactly that and still rejects the shape it was
written for.

`stp q0, q1, [sp, #n]` was the single commonest undecoded word in a real binary
and decodes 164 times across the eight; coverage reaches 95.2%.

**Then pointer authentication, described rather than implemented.** Signing a
pointer is a keyed cipher over a modifier, and AXIS states no key, no cipher and
no fault -- so `PACIBSP`, `AUTIBSP`, `RETAB`, `BRAA`, `BLRAAZ` and `PACIZA`
carry prose `semantics` and no `behavior` or `formal` at all. Nothing claims to
compute what they compute and no executor is handed a value it would have had to
invent; what they carry is an **encoding**, which is the whole point. They were
1280 of the 1709 words a real arm64e binary had that this description could not
name, and a miner that cannot decode `pacibsp` cannot find the function boundary
that follows it. `BRK` went in beside them for the same reason and is not arm64e
at all -- base ISA that had simply never been described.

The cost is stated rather than hidden: the authenticating branches declare no
`setpc`, so a lifted block does not end at one. They decode and disassemble;
they do not terminate a region.

**Then scalar floating point, which is stateable and so is stated.** `FMOV_D`,
`FNEG_D`, `FABS_D`, `SCVTF` and `FCVTZS` in both source widths, and the two
`FCMP` forms with the four NZCV shapes an AArch64 float compare produces --
unordered included. The sign operations are bit operations on purpose: the
architecture defines `FNEG` and `FABS` as flipping and clearing the sign bit,
which is exact for NaNs where an arithmetic negation would not be.

**And describing them found the seed's scalar FP arithmetic at the wrong
encodings.** `FADD_D`, `FSUB_D`, `FMUL_D`, `FDIV_D` and `FSQRT_D` carried
`(fixed 483)` where AArch64 has 243, putting the whole family at `0x3c6…` --
which is the SIMD load/store space, not floating point at all. Real
`fadd d0, d1, d2` decoded to *nothing*, and had since the corpus was written;
the `fpop` values beside it were right, so only one constant was wrong. Nothing
caught it because every gate compares AXIS against AXIS: the encoder, the
decoder, the executors and the LLVM backend all agree on whatever the
description says, and none of them knows what the architecture says. What found
it was decoding a binary the architecture produced.

**And the encodings are now checked against someone else's tables.**
`reference_isa_check.py` hands every roundtrip fixture's word to `llvm-mc` as a
disassembler and requires two things: that the reference *recognise* the word at
all, and that the mnemonics agree after normalising two naming conventions and a
table of preferred aliases. The first has no noise -- an encoding AXIS calls a
valid AArch64 instruction that AArch64 does not is wrong, and `0x3c602800`
decodes to nothing. Measured: **1014 encodings across `aarch64_base`, `rv32i`
and `rv64i` agree**, 48 of them through a named alias, none refused. Put
`(fixed 483)` back and it names all four instructions and their words.

Two things it is careful about. The feature flags are part of the answer, not a
detail: asking `-triple=arm64` without `+lse,+pauth` refuses 172 perfectly good
words -- every atomic and every pointer-authentication form -- and reads exactly
like 172 corpus bugs, so they are written down with the reason. And it feeds
`llvm-mc` **one word per line**, because it drops a word it cannot decode and
prints nothing in its place; zipping a single stream back against the input
pairs every later word with its neighbour's disassembly. That is the same
misalignment `binary_coverage.py` guards against in a byte stream, met again one
tool along.

`sve` and `rvv` are deliberately not in the table. Both corpora exist to
exercise the scalable-vector machinery and their encodings are illustrative:
`aarch64` refuses 43 of SVE's 83 words and reads `SUB_Z_B` as `uaddv`. What
decides membership is whether a description means to be the architecture's
encoding, not whether it borrowed the architecture's name.

**And `MOVI`**, the commonest SIMD word a real binary has: `cmode=1110` with
`op=1`, which expands its eight-bit immediate by **replicating each bit into a
byte** rather than shifting it. Its immediate is also the first split field a
corpus has had to declare -- `abc` at 18:16 and `defgh` at 9:5, which the
four-number field form exists for. Checked against the assembler on asymmetric
values (`0x80`, `0x01`) rather than on the zero every real use happens to have,
because zero cannot tell a reversed split from a correct one.

The `Q=1` form states **no behavior**, for the same reason the IR withholds the
Q-form load: its value is 128 bits and every executor here computes in 64. The
Python one appeared to manage, because Python integers are arbitrary precision
-- and then stored the whole value in the low limb with the high one left zero,
which the limbed read-back caught. That is the boundary of the ≤64-bit value
model, met from a new direction: `LDR_Q`/`STR_Q` only move a wide value and were
never asked to *compute* one, so this is the first instruction to reach it.

**Then the tail, worked from the misses rather than from a manual.** The
W-destination signed loads and the unsigned conversions (forms beside ones
already here, one field apart); the writeback `d`-register pairs a prologue
saves with, `LDPSW`, and the unscaled and register-offset `q` accesses; and the
vector arithmetic -- `ADD`/`SUB`/`CMHI` with `size` as an operand, `AND`/`ORR`/
`BSL` with it pinned because the logical group uses it as opcode bits -- plus
`DUP`, `INS`, `MOVI_16B` and the last two pointer-authentication branches.
### An instruction may name a routine instead of semantics

Some instructions have no semantics AXIS can state. What pointer authentication
computes depends on a key the machine holds and a construction nothing here
models; what a breakpoint does is a question about the exception level rather
than about the register file. Eleven AArch64 instructions are in that position,
and they were simply silent -- which is honest about the semantics and says
nothing about what a simulator should do when it meets one.

`(implementation <symbol>)` lets such an instruction name a routine the
embedder supplies. It says **what to call, not what is computed**, and that
distinction decides who may use it:

* A consumer that **runs** code may call it. Both executors dispatch to it,
  with exactly the signature a generated effect function has -- the decoded
  instruction, the register file, memory, the pc, architectural state, and the
  result to report through. There was no reason to invent a second shape: an
  implementation does the same job.

  The two languages say "missing routine" differently, and the difference
  favours Rust. The C header *declares* the symbol, so a routine nobody
  supplies is a link error naming a mangled symbol. The Rust executor declares
  nothing: its pieces are concatenated into one module, so the call resolves
  against whatever the embedder defines beside it, and a missing routine is a
  compile error naming the function.
* A consumer that **reasons** about code must not. The golden model and SMT
  cannot call it, because a reference that defers to an opaque routine has
  stopped being a reference, and a solver handed a symbol it cannot see inside
  would be answering about nothing.

An instruction may not state both. A routine and a `formal` are two answers to
one question, and a consumer would have to pick; whichever it picked, the other
would be a claim nothing checked. Validation rejects it by name.

### The third answer: nobody performs it here

Naming a routine has a consequence, and measuring it produced the third state.
Pointing the eleven AArch64 instructions at `axis_impl_paciza` and friends made
`A64 wide C exec` stop *linking* -- correctly, since an instruction that names
a routine cannot execute without one, and AXIS does not ship routines for
pointer authentication because it cannot say what they compute. But it meant
the corpus could not record what it knew without breaking every C gate that
links against it.

So `(implementation unsupplied)` is the third answer. Not semantics, because
none can be stated; not a routine, because none is supplied. An executor that
meets one **traps**, and nothing is declared for it -- a header declaring a
symbol nobody defines is exactly the state this avoids.

The trap cause is `unimplemented`, deliberately not one of the machine's own --
`illegal`, `ecall`, `ebreak`, `misaligned`, `access`. Those say what the
machine does; this says what this build of the executor cannot. `PACIZA` does
not trap on hardware. Recording that the answer is missing *here* is a
different fact from "this instruction traps", and keeping the two apart is the
whole reason the state exists rather than being written as a behavior that
traps.

The eleven say it now, and `A64 wide C exec` links and passes. The lifter
distinguishes all three silences where it used to print "no semantics declared"
eleven times: an instruction that names a routine has an answer the lifter
cannot use, one that says `unsupplied` has declared that nobody has an answer,
and one that says nothing has not been asked.

### Then eleven became eight, one, and two

`unsupplied` was the right answer for all eleven only while nobody had looked
at them one at a time. Sorted, they are three different questions.

**Eight name a routine.** The pointer-authentication family -- `BRAAZ`,
`BLRAA`, `BLRAAZ`, `BRAA`, `RETAB`, `PACIBSP`, `AUTIBSP`, `PACIZA` -- is what
the hook was built for: the answer depends on a key the machine holds and a
QARMA construction nothing here models. They say `axis_impl_<mnemonic>` now,
which tells an embedder what to write and what it will be called.

**One was never in this category.** `BRK` takes a breakpoint exception, the
trap vocabulary has had `ebreak` all along, and RISC-V's `EBREAK` is already
written `(behavior (trap ebreak))`. It says the same thing now. A routine for
it would have been an embedder obligation invented to avoid two lines, and the
instruction is fully modelled rather than deferred.

**Two were never unsupplied either; they were unwritten.** Both said so in
prose that turned out to be an excuse rather than a reason, and both are now
stated as behavior. The corpus declares no `unsupplied` instruction at all.

`FMOV_D_IMM` said "the expansion is a table this description does not carry".
It is not a table. `VFPExpandImm` is bit assembly: the sign is `imm<7>`, the
11-bit exponent is `NOT(imm<6>)` then `imm<6>` repeated eight times then
`imm<5:4>`, and the fraction is `imm<3:0>` followed by 48 zeros. Written out
in shifts and ors, all **256** encodings agree with the ARM pseudocode, and
`0x70` is 1.0, `0x00` is 2.0, `0xf0` is -1.0.

`SCVTF_D_X_FIXED` said the scaling "is a division this value model would round
twice". That reason was **wrong**, and it is worth saying why, because it is
the kind of wrongness that is comfortable to leave alone. Scaling by a power of
two is exact: it maps the double grid onto itself, so `round(v)/2^k` and
`round(v/2^k)` are the same number, and the pair rounds once. Written as the
integer conversion followed by a multiply by `2^(scale-64)` -- an exponent
field, built with integer arithmetic -- it agrees with an exact rational
reference on 2007 cases spanning the full signed range and every scale.

### An operand transform, so the assembly can print what it means

`SCVTF_D_X_FIXED`'s assembly printed `fbits $scale`, and `$scale` is the encoded
field, which is `64 - fbits`. So it labelled a number `fbits` that is not fbits
-- the same family as the `lr.w` suffixes, text throwing away what the encoding
had right, except here the description **contradicted itself**: its own
semantics string said "64-scale fraction bits" while its assembly called that
same field fbits.

The mechanism it wanted did not exist. `derived_from`/`derived_add` carry a
register pair's second selector, not an arithmetic relation on an immediate. So
an operand can now carry one:

```lisp
(scale imm i6 in (asm (minus-from 64)))    ; printed = 64 - field
(count imm i5 in (asm (plus 1)))           ; printed = field + 1
```

⚠️ **The set is closed, and that is the design rather than a shortcut.** A
transform is published for a consumer to *assemble* with, not only to print
with, so it has to run backwards. Both forms are affine with a unit
coefficient, so both invert without division or rounding. A general expression
would need inverting, and one that could not invert would publish a
disassembler nobody can assemble back -- which is a worse artifact than the
mislabelled number it replaced.

Three things are checked rather than assumed:

* **It stays inside the numbers text can carry**, over the whole field rather
  than the values a fixture reaches. `(minus-from k)` on a `w`-bit field prints
  down to `k - (2^w - 1)`, so `minus-from 32` on `SCVTF`'s six-bit field prints
  `-31` for a legal encoding -- rejected, with that number in the message.
* **It inverts**, at both ends of the field and in the middle.
* **It is not on a register.** A transform relates an encoded number to a
  printed one; a register operand prints a name.

`asm_disasm.json` carries it, because that is the file whose job is spelling: a
consumer building a disassembler out of it would otherwise print the field and
call it by the assembly's name. `asm_disasm_check` gained a fourth property for
it and counts the operands that have one, so a corpus with none does not read
the same as a corpus whose transforms were all checked.

⚠️ What this does **not** check is whether the transform is the one the
architecture uses. Nothing here knows AArch64's encoding; `(asm (plus 3))` on
that operand validates cleanly and would be wrong. That is the same standing
limit every part of a description has -- it is the claim, not a derivation of
one -- and worth saying where a number now passes through arithmetic on its way
to the page.

### Naming a routine had a consequence again

The same one as the first time, and it wanted a different answer. Eight
declared routines are eight undefined symbols, and four harnesses stopped
linking a C executor and two stopped compiling a Rust one.

That link error is the most useful thing the generated file can do for someone
bringing a machine up: it names exactly the functions still to write. So it
stays. What the harnesses get is an **opt-in**: `-DAXIS_IMPL_STUBS` in C and
`--cfg axis_impl_stubs` in Rust emit placeholders reporting the same
`unimplemented` trap an instruction with no implementation reports. A harness
that holds no key could not implement these anyway, and asking for the
placeholders is visible in its build command.

⚠️ **Not weak symbols**, which was the obvious alternative and the wrong one. A
weak default would make "declared a routine, supplied none" and "declared
nothing" behave identically without anyone having chosen that -- and those are
precisely the two states the third answer exists to keep apart.

### A gate that scales past the corpus written for it

`implementation_routine_check` proves the hook works. It does so for one
instruction in a file written for the purpose, which was the entire population
until AArch64 started naming routines -- at which point eight real instructions
claimed a routine performed them and no gate touched any of them.

`implementation_dispatch_check.py` asks the question that scales: for every
instruction in a real corpus that names a routine, does the generated code call
*that* symbol, in both executors, and does every `unsupplied` one trap in both?
It cannot check what a routine computes -- nothing here knows, which is why the
routine exists.

⚠️ It does **not** check for shadowing, which is what it was written around.
An instruction naming a routine *and* stating semantics would have its effect
function matched first and the routine never called. That turned out to be
unreachable: validation already refuses the corpus, saying that stating both
"leaves two answers to one question". A gate guarding a state the parser will
not produce measures nothing, so it is not there.

What can be gated about an opaque routine is exactly one thing, and
`implementation_routine_check.py` asks it: is the routine reached, with the
operands the instruction decoded, and does what it leaves behind survive into
the machine? Whether the answer is *right* is unanswerable here -- nothing in
the description knows what right is -- and that is the honest limit of the hook
rather than a gap in the gate. The corpus carries a control beside it, an
instruction whose semantics AXIS does state, so a harness that ran nothing is
distinguishable from a routine that was never called.

Both executors are asked, rather than one checked and the other assumed:
removing either dispatch turns the gate red, and it says which language.

### The twelve wide SIMD instructions

All twelve state their semantics now, at 128 bits, checked against the golden
model by SMT, C, Rust and LLVM. They did not when they were written -- the
claim then was "128 bits wide, so no behavior is stated", and that had already
expired: `examples/simd_q_lanes.axisl` describes lane-wise 128-bit NEON shapes
and is gated against golden by three backends, and `src/simd.rs` expands a
`v<lanes>i<elem>` atom into ordinary bit-vector semantics at elaboration, so
every consumer sees arithmetic it already knows. The machinery was simply never
pointed at this corpus.

The reference gate earned its place again here: `INS_V_GEN` disassembled as
`mov`, and rather than widen the alias table on the strength of it looking like
an alias, `ins v1.h[1], w2` was assembled and shown to land in the same
encoding family -- `MOV (from general)` is the architecturally preferred
disassembly of `INS (general)`. An alias table that absorbs a real mismatch is
the one failure this gate has.

Then the last seven forms, each needing its own layout -- `FMOV` with an
8-bit encoded double, the fused `FMSUB`, `FCSEL` and `FCCMP`, fixed-point
`SCVTF` (bit 21 clear where the integer conversion sets it), `CMEQ` against zero
and the scalar `ADDP` a vectorised reduction ends with.

They were left until last because they cost a format each, and **that ordering
was about cost, not value**. Judging them by their share of the word count --
thirteen of 37223, 0.03% -- is the wrong measure in a mining context: *one
undecoded word ends a region*, so a form that appears twice inside a function
worth mining costs far more than two words. `fmov`, `fcsel` and `fmsub` cluster
in exactly the floating-point code a miner is looking at.

Coverage over eight system binaries, every executable section: **98.48%**, and
**every remaining miss is data**. All 567 are `udf` -- how the reference renders
unallocated encoding space -- or words the reference itself refuses. There are
**no real AArch64 instructions left undecoded** in those binaries. What
remains is mostly **not instructions** -- literal data interleaved in `__text`
(`0x00000a44` and friends) -- plus SIMD (`movi`) and a few addressing modes.

**One instruction is four bytes here**, because that is what AXIS describes: the
generated decoder takes a `uint32_t`. Measuring a freshly compiled RISC-V object
showed why that has to be said out loud rather than assumed. It reported 60.7%,
which read as a finding about `rv64i.axisl` and was a finding about the walk: at
offset `0x34` the object holds a 2-byte `c.nop` pad, `sum` begins at `0x36`, and
every later four-byte read is misaligned. Allowing a word to have been two bytes
long reaches **93.1%** -- the description was fine.

Two bytes is not a special case to be tolerated, though; it is the C extension,
and the honest response to a 93.1% is to describe what the other 6.9% is. RVC is
now in `rv64i.axisl`: nine 16-bit formats (CR, CI, CA, CB, CJ, CL, CS and the
shift and width variants) and nineteen instructions, from `c.addi` -- the
commonest compressed instruction in a real object -- through `c.ld`, `c.beqz`
and the `c.addiw`/`c.subw` pair that RV64 adds. Eleven of them needed a register
class of their own: the three-bit fields reach only `x8`-`x15`, which is what
`rv_gpr_c`'s `index_offset: 8` says, and `c.fld` needs the same window over the
float file as `rv_fpr_c`.

That window is where the interesting failure was. A register class that starts
partway into its file has to be resolved to a slot the same way in every backend
that owns a slot computation, and there are six: the Python lifter, the two
Python view helpers, the two generated C helpers, and the Rust simulator. The
first version applied `index_offset` in exactly one of them. Five agreed with
each other, which is the reason a wrong answer can look like a right one -- and
also the reason the ladder found it anyway, since agreement among five is not
what any gate checks. `sim_vs_executor` reported the same *value* written to two
different register *names*:

    simulator c 00008c89 C_SUB r=9,a w=9 v=ffffffffffffff39
    executor  c 00008c89 C_SUB r=1,2 w=1 v=ffffffffffffff39

The value matched because the arithmetic was never in question. Only the
disagreement about which register held it made the missing window visible. Coverage on both compiled objects is now
**100%** -- 97 of 97 instructions, with nothing left over.

So a report probes for it. A uniform shift cannot detect this, since the
misalignment begins partway through; the walk instead advances two bytes instead
of four on a miss, and says the stride looks wrong when that gains materially.
It is a **detector, not a decoder** -- a greedy resync can land on a word that
decodes by luck -- so the result is only ever used to discredit the number, never
to replace it. It stays silent on `/bin/ls` and on a compiled AArch64 object,
both genuinely four-byte streams.

Describing RVC then took the detector's whole premise away for RV64I, and the
gate that tested it said so. `binary_coverage_check` wedges two bytes into a
clean image and asserts the detector notices; the two bytes it wedges are
`0x0001`, which is `c.nop`. Once `c.nop` is an instruction rather than a pad,
the walk consumes two bytes for it and every later instruction lands back on
its own boundary -- coverage 99.41%, nothing misaligned, and a detector that
fired would have been the one telling the lie. So the wedge is now asserted
only where a shift is genuinely a shift: the check asks the description how many
instruction widths the ISA has, and holds the assertion for the four corpora
that answer one. RV64I answers two, and is the only one exempted.

Coverage is a measurement, so the gate asserts nothing about the number. It
asserts the **readers**, because every way of misreading a section header shows
up as a lower coverage number that reads like an honest finding about the corpus.
`binary_coverage_check.py` builds the object files itself -- ELF64, Mach-O, and a
universal binary whose wanted slice is second so that picking the first fails --
out of a description's own roundtrip fixtures, and requires every word back.
Words two ISAs share, or that two instructions of one ISA share (`vliw_packet`
puts `VSTW` and `VBRZ` on one word, told apart by slot), are dropped and counted
rather than hidden. The stride detector is gated too, in both directions: it must
stay silent on an image that is all four-byte instructions, and must fire when
two bytes are wedged into the middle of one. Injecting a detector that never
fires, one that always fires, and an ELF section offset off by two all fail this
gate.

The scan is still emitted, as `axis_decode_linear` / `axis_decode_linear_in_isa`,
and that is what makes the tree trustworthy rather than merely plausible:
`tools/decode_tree_check.py` compiles both from every corpus and requires the
same *entry pointer* from each -- on match words, on match words with the
operand bits randomised, on every single-bit near miss (which is how a
partition that dropped a candidate shows up), and on random words that should
find nothing -- under every ISA string in the table and under none.

Needed AXIS data:

- Canonical mnemonic.
- Assembly syntax.
- Operand print/parse kinds.
- Immediate encoding/decoding rules.
- Decode key and mask.
- Alias/pseudo-instruction rules later.

Near-term plan:

1. Expand the existing `asm:` field with parse/print constraints where needed,
   for example:

   ```text
   asm: "fma_i $rd, $rs1, $rs2, $rs3"
   ```

2. Harden the generated decode and encode tables:

   ```json
   {
     "mnemonic": "FMA_I",
     "match": 0x0800300b,
     "mask": 0xfe00707f,
     "format": "R4"
   }
   ```

3. Expand C/Rust decode and encode helpers using the same match/mask and operand
   field tables.
4. Extend asm/disasm metadata with aliases and pseudo-instruction rules.
5. Turn generated roundtrip fixtures into executable tests:
   encode -> decode -> mnemonic/operands.

### 4. Instruction To LLVM IR

Status: **built.** `emit-llvm-ir`, `emit-llvm-intrinsics`, `emit-llvm-patterns`
and `emit-intrinsics` give both directions -- an instruction as LLVM IR, and
IR patterns selected to instructions -- and `llvm_vs_golden.py` holds the IR
to the golden model on the scalar, FP, SIMD, scalable, matrix and narrow-float
corpora. The design and staging are `docs/llvm_backend.md`; the plan below is
the original one.

Outputs:

- LLVM IR intrinsic declarations.
- Lowering snippets or pattern metadata.
- Optional generated C header with builtin/intrinsic declarations.
- Eventually MLIR/LLVM dialect mappings.

Purpose:

- Express AXIS instructions in compiler IR.
- Map high-level idioms to custom instructions.
- Enable optimizer-visible semantics.

Two directions are needed:

- `insn-to-IR`: custom instruction intrinsic or operation lowered into LLVM IR
  semantics.
- `IR-to-insn`: LLVM IR pattern recognized and lowered into custom instruction.

Needed AXIS data:

- Typed formal semantics.
- Operand types.
- Result type.
- Memory effects.
- Undefined/poison behavior.
- Cost model.
- Pattern metadata.

Near-term plan:

1. Emit LLVM intrinsic declarations from AXIS instruction signatures.
2. Generate simple pure arithmetic intrinsic semantics for operators already in
   `formal_semantics`: `add`, `sub`, `mul`, `and`, `or`, `xor`, shifts.
3. Emit pattern hints from `formal_semantics` so `FMA_I` can advertise:

   ```text
   add(mul(rs1, rs2), rs3) -> FMA_I
   ```

4. Add checks that generated intrinsic signatures match operand widths and
   output widths.

### 5. Lift To IR

Status: **built.** The decode-to-semantics table (`emit-lift-json`), lifters in
Python, C and Rust (`emit-lift-*`), a block lifter, and binary lifting to LLVM
IR (`axis lift-blocks`, `axis lift-llvm`). Held by `lift_roundtrip.py`,
`lift_native_check.py`, `lift_ast_check.py` and `lift_block_check.py`. Design:
`docs/lifter_design.md` and `docs/binary_lift_design.md` (X1–X6). The plan
below is the original one.

Outputs:

- Instruction lifter:
  - binary instruction -> AXIS semantic IR
  - binary instruction -> LLVM IR
  - binary instruction -> simulator IR
- Trace lifting helpers for PCE simulator logs.

Purpose:

- Turn decoded instructions back into a typed IR representation.
- Support binary translation, trace analysis, differential testing, and JIT.

Needed AXIS data:

- Decode table.
- Operand extraction rules.
- Formal semantics.
- Register/memory effects.
- PC/control-flow effects.

Near-term plan:

1. Generate a decode-to-semantic-IR JSON table.
2. Generate Python lifter first for tests and trace tools.
3. Generate C/Rust lifter once the decode table stabilizes.
4. Add roundtrip tests:

   ```text
   AXIS instruction -> encoded bits -> decode -> lifted IR -> expected semantic AST
   ```

### 6. C Implementation For Simulator/Interpreter

Status: **built.** `emit-semantics-c` (one function per instruction), the
executors `emit-exec-c` / `-rust` / `-python`, the functional simulator
`emit-sim-c` (`docs/simulator.md`), and the pack's exec and cycle-simulator
libraries (`docs/pack_simulator.md`). Every executor is held to the golden
model, scalar and wide, by the `exec_*` gates. The plan below is the original
one.

Outputs:

- `axis_semantics.h`
- `axis_semantics.c`
- One C function per instruction and accelerator behavior where applicable.

Purpose:

- Fast portable interpreter hooks.
- Golden behavior for C/C++ simulators.
- No LLVM dependency.
- No PyRTL dependency.

Needed AXIS data:

- Formal semantics.
- Operand and result widths.
- Signedness rules.
- Memory effects.
- Trap/exception behavior.

Near-term plan:

1. Generate pure arithmetic C functions for side-effect-free instructions:

   ```c
   uint32_t axis_eval_fma_i(uint32_t rs1, uint32_t rs2, uint32_t rs3);
   ```

2. Mask results to declared result width.
3. Generate unsupported stubs for instructions with memory/control effects until
   effects are first-class in AXIS.
4. Add C compile smoke tests.
5. Add value tests against `golden_model.py`.

### 7. Fast JIT Engine For Simulator

Status: **built**, in three backends with fifteen gates between them —
`tools/jit_c.py` transpiles a block to C and compiles it, `tools/jit_llvm.py`
builds LLVM IR and runs it through MCJIT in-process, and `tools/jit_stencil.py`
compiles the handlers ahead of time and patches the operands at translation
time (`docs/jit_stencils.md`, J1-J6). "Native codegen not yet" was true of the
interpreter on-ramp and of nothing since.

The stencil backend ships as the sixth **pack library** (`libaxis_jit_<name>`),
which is why the count grew: `tools/jit_pack_check.py` runs what the library
translates against the executor beside it, over three corpora.

Outputs:

- JIT IR metadata.
- Generated decode dispatch.
- Generated instruction handlers.
- Backend-specific JIT glue.

Potential backends:

- LLVM ORC JIT for maximum reuse with LLVM IR lowering.
- Cranelift for fast compile times and simpler embedding.
- DynASM/asmjit-style direct machine-code emitter later if hot paths justify it.

Purpose:

- Speed up PCE architectural simulation.
- Execute AXIS custom instructions directly from generated semantics.
- Support mixed interpretation/JIT execution.

Needed AXIS data:

- Decode table.
- Lift-to-IR path.
- Instruction side effects.
- Register file model.
- Memory access model.
- Control-flow model.
- Trap/exception model.

Near-term plan:

1. Do not start with a native-code JIT. _(held to.)_
2. Done: `emit-sim-c` (`axis_sim.h`, `axis.sim-c.v1`) generates a compact
   simulator IR — a pre-decoded `axis_op` where decode/lift and operand-role
   classification are resolved once, not per executed instruction.
3. Done: `axis_block_run` interprets that IR with no per-step decode, lift-table
   scan, or role/kind `strcmp` — a direct call into the proven `axis_exec.h`
   handlers (`axis_exec_eval` / `axis_exec_apply`), so behavior is inherited.
4. Done (block formation): `axis_block_build` decodes a straight-line word
   sequence into an `axis_op[]` once, then `axis_block_run` executes it. Cache
   keys (memoizing built blocks by address/word hash) remain for the embedder.
5. Started (native codegen): `tools/jit_c.py` transpiles a decoded block into a
   single straight-line C function with operand register indices and immediates
   baked in as constants, then compiles it fresh per block with `cc -O2` (native
   codegen) and runs it. Pure instructions become direct calls to the proven
   `axis_eval_*` handlers (which `-O2` inlines and constant-folds into specialized
   machine code); effectful instructions fall back to the proven `axis_exec_step`
   runtime — so the JIT reuses only already-proven code. This realizes the
   transpile-to-native path. `tools/jit_llvm.py` adds the **LLVM backend**: a
   real *in-process* MCJIT (via llvmlite, no subprocess) that lowers a block to
   LLVM IR calling the proven `axis_eval_*` functions from `axis_semantics.ll`,
   compiles it in memory, and runs it through a function pointer — covering the
   full pure surface including `clz`/`ctz`/`cpop` (the LLVM semantics lower them
   via `llvm.ctlz`/`cttz`/`ctpop`). A **block cache** keyed by the word sequence
   compiles each distinct block once and reuses the native code on repeats
   (~92% hit rate on a 24-block pool) — the cache-key step of the plan. Cranelift
   remains open as a further backend for the same `axis_op`.
6. Done: `tools/exec_fuzz.py` runs random programs through the sim IR as a
   fourth backend and requires `python == c-step == c-sim == rust` (JIT output
   == `golden_model.py` == C interpreter); an injected sim-only bug is caught.
   `tools/jit_c.py` extends the same guarantee to the native-compiled block (full
   E1-E4 surface), and `tools/jit_llvm.py` to the in-process LLVM-JIT'd block
   (pure surface) — both require equality with the golden model over random
   programs, and both catch an injected miscompile.

### 8. PyRTL And Hardware-Facing Artifacts

Status: **two artifacts.** `emit-pyrtl` is the behavioural contract PCE's
loaders read (`axis.pyrtl-semantics.v1`), unchanged. Beside it, a structural
generator (`docs/hardware_design.md`): a netlist per instruction, functional
units they merge into, units pipelined to their latency, plans from outside,
and URV's extension slot -- `emit-hw-pyrtl`, `emit-hw-json`, `emit-hw-smt2`,
`emit-hw-plan`. Netlists are held to the golden model by simulation and to
`emit-smt2` by proof, and the cost model behind them is calibrated against
Yosys and an open cell library (`tools/hw_calibrate.py`). Not built: floating
point, 128-bit carries, units over instructions built as effects. The plan
below is the original one.

Outputs:

- `pyrtl_semantics.py`
- Structural accelerator module builders.
- Later generated execute-unit fragments and harnesses.

Purpose:

- Feed PCE's PyRTL fork.
- Produce behavioral hooks and simple structural skeletons.
- Support golden/cosim/proof harnesses.

Near-term plan:

1. Keep `emit-pyrtl` aligned with `semantics.json`.
2. Add generated tests that instantiate emitted PyRTL modules.
3. Add explicit pipeline/resource fields before generating multi-cycle hardware.
4. Add memory and queue interface generation only after effects/interfaces are
   first-class enough to avoid backend-specific guessing.

## Cross-Cutting Missing AXIS Features

Several emitters should wait for these language features:

- Semantic IR operator coverage for real extension ops: arithmetic shift,
  rotates, clz/ctz/popcount, signed/unsigned min/max, sign/zero extension.
  (Concrete driver: PCE's Zbb op set landed as hand-written primitives that
  AXIS cannot yet describe.)
- Operand extraction/encoding rules beyond simple R/I metadata (the encoding
  metamodel: spaces, formats, scattered field slices, transforms,
  constraints, decode-space disjointness checking).
- Register files as first-class typed objects, with register classes
  referenced by operands.
- Feature predicates and extension dependencies.
- Pseudo-instructions and aliases.
- Scheduling model: latency, throughput, ports, hazards.
- Signedness and overflow semantics.

Deprioritized until PCE grows the consuming surface (the URV extension unit is
pure-ops-by-design today: no traps, no memory effects). The forward-looking
design for the effect-carrying items below is in `docs/effects_design.md`
(a statement/effect layer over the pure `Sem` IR, staged E1–E5):

- Memory effects: load/store, ordering, atomicity, aliases.
- Control-flow effects: branch, jump, call, return, trap.
- Exceptions/traps and undefined behavior.
- Simulator ABI: register file, memory callbacks, trap callbacks.
- Variable-length encodings (RVC is described in `rv64i.axisl`; the walk
  advances by each format's own `bits`).
- Byte-granular `layout` for accelerator descriptors/MMIO (RVMT-era
  consumers are compat-frozen).

## Implementation Order

Ordered by live consumer demand (see `docs/pce_migration.md`):

**Wave A — align with the live seams.** Status: done.

1. Done: the semantic IR covers Zbb-class ops (sra/ashr, rol/ror,
   clz/ctz/cpop, min/max/minu/maxu, sext/zext, not), propagated through
   validation, golden model, SMT, and PyRTL emitters. Type atoms now set the
   evaluation width for width-sensitive operators. `examples/zbb_like.axisl`
   exercises the full set; `tools/smt_vs_golden.py` differentially proves the
   SMT output equal to the golden model with z3.
2. Done: `tests/pce_contract.rs` pins the exact field surface PCE's
   `adl_loader` and `from_adl` read; `tools/pce_smoke_check.py` loads AXIS
   `emit-bundle` output through the real `aha.isa.adl_loader` and
   `aha.optisynth.adl_bridge` (BACKLOG-012 gate 1 in PCE).

**Wave B — encoding metamodel, scoped to the live contract.** Status: done.

3. Done: top-level `format` blocks (named field slices, scattered operand
   placements via `name[hi:lo]@[hi:lo]`), built-in R/R4/I/S/B/U/J, and
   per-instruction `encoding: [field=value]` lists. All match/mask values,
   operand packing, and encodability derive from a single layout resolver
   (`src/layout.rs`); the hardcoded operand-name convention is gone, R4's
   rs3 is encodable, and the validator proves pairwise decode-space
   disjointness. Remaining from the original sketch: value transforms
   (signedness/scale) — deferred until immediates need them.
4. Done: `tools/roundtrip_check.py` compiles `axis_encode.h`/`axis_decode.h`
   with cc and executes every fixture (encode → compare word → decode →
   compare mnemonic).

**Wave C — proof collateral shaped for the AHA doctrine.** Status: done.

5. Done — and cheaper than expected: PCE's ADL.2 turned out to be fully
   implemented (`aha/optisynth/adl_semantics.py` + `adl_bridge`), parsing
   `formal_semantics` from the bundle with its own grammar. AXIS now emits
   the OptiSynth dialect into `manifest.json`/`aha_instructions.json` when
   expressible (`src/optisynth.rs`: n-ary→binary folds, typed constants,
   `not`→`xor -1`, `min`/`max`→`select`+`icmp`; `optisynth_compatible` flag;
   raw AXIS dialect stays in `semantics.json`). The smoke check drives the
   full PCE chain: rewrite rules derived, intrinsic axioms registered, every
   rule Z3-PROVEN through PCE's own proof gate — zero PCE code changes.
   Rotates/counts/extends have no OptiSynth form and skip soundly.
6. Done: `golden_model.py` carries a trusted-spec registry (`AXIS_SPECS`
   with signature/widths/source semantics per entry), deterministic
   `sample_vectors(...)`, `evaluate(...)`, and `selftest()`.
7. Done: `emit-semantics-c` generates header-only `axis_semantics.h`
   (`axis.semantics-c.v1`), one pure `axis_eval_<name>()` per entry with
   `formal_semantics`; `tools/c_vs_golden.py` proves it bit-identical to the
   golden model on spec-registry and randomized vectors.

**Wave D — LLVM IR semantics, differentially proven.** Status: started.

8. Done: `emit-llvm-ir` generates self-contained `axis_semantics.ll`
   (`axis.semantics-llvm.v1`), one `define i32 @axis_eval_<name>` per entry
   with `formal_semantics`, lowered from the typed IR (`src/ir.rs`).
   Arithmetic becomes native SSA; width-sensitive ops call a fixed
   `axis_sem_*` helper prelude that mirrors `C_SEMANTICS_HELPERS`.
   `tools/llvm_vs_golden.py` compiles it with clang and proves it
   bit-identical to the golden model across the full Zbb set. This is the
   substrate for the remaining LLVM-facing waves (intrinsic declarations,
   IR↔insn patterns, lift-to-IR, JIT lowering).

   Widths up to 64 are covered: the helper prelude is a width template
   rendered at 32 and 64, so a 64-bit instruction lowers in `i64` instead of
   being skipped, and the AArch64 seed's 65 pure functions are all proven
   against the golden model. The C and Rust semantics emitters remain
   32-bit-only, so their artifacts still skip those instructions.

9. Done: `emit-llvm-intrinsics` generates `axis_intrinsics.td`
   (`axis.llvm-intrinsics.v1`), Layer 4 step 1 — TableGen `Intrinsic<>`
   records under `TargetPrefix = "axis"` declaring `llvm.axis.*` intrinsics
   with result/argument types taken from operand widths. Declarations are
   gated on pure `formal_semantics` so the `IntrNoMem` purity markers are
   sound (Layer 4 step 4: `tests/golden.rs` pins the signature↔width
   invariant); effectful or non-standard-width instructions are withheld
   with a comment.

10. Done: `emit-llvm-patterns` generates `axis_patterns.td`
    (`axis.llvm-patterns.v1`), Layer 4 steps 2–3 — SelectionDAG `Pat<>`
    records mapping the LLVM DAG derived from `formal_semantics` to the
    `llvm.axis.*` intrinsic (`(add (mul $rs1, $rs2), $rs3) ->
    int_axis_pce_fma_i`). Operators lower to ISD node names via the same
    typed IR (`min`→`smin`, `not`→`(xor x, -1)`, `sext`→`sext_inreg`,
    `zext`→mask); patterns are emitted only when operands share one standard
    width, all inputs are referenced, and every operator has a clean DAG
    form, else withheld with a comment. `tests/golden.rs` pins the mapping.
    Layer 4 is now covered end to end (intrinsic decls, IR bodies, IR→insn
    patterns); the remaining compiler-integration work is register-class
    wiring in a real out-of-tree backend, outside AXIS's generation scope.

**Wave E — lift-to-IR (decode → semantic IR).** Status: started.

11. Done: `emit-lift-json` generates `axis_lift_table.json`
    (`axis.lift-table.v1`), Layer 5 step 1 — per instruction the decode
    match/mask, operand extraction fields (instruction-bit slices reassembled
    into operand values, reusing the layout resolver), read/write roles, and
    the typed semantics AST. `operands_encodable` vs `liftable` keep the
    decode-vs-semantic-binding distinction explicit.
12. Done: `emit-lift-python` generates `axis_lift.py`
    (`axis.lift-python.v1`), Layer 5 step 2 — a standalone `decode(word)` /
    `lift(word)` over the embedded table. `tools/lift_roundtrip.py` closes
    Layer 5 step 4: instruction → encoded bits → lift → recovered
    mnemonic/operands, checked against the encode fixtures.
13. Done: `emit-lift-c` / `emit-lift-rust` generate `axis_lift.h`
    (`axis.lift-c.v1`) and `axis_lift.rs` (`axis.lift-rust.v1`), Layer 5
    step 3 — the compiled lifters: the same static table and decode+extract
    entry points in header-only C and safe Rust. `tools/lift_native_check.py`
    compiles both against a generated driver and proves they lift the encode
    fixtures identically to the Python lifter.
14. Done: `emit-exec-python` generates `axis_exec.py`
    (`axis.exec-python.v1`), the lift→execute rung — a functional single-step
    interpreter composing the lift table with the proven golden semantics.
    `step(word, regs)` decodes, binds register/immediate operands, evaluates,
    and writes the destination register. `tools/exec_vs_golden.py` proves the
    decode→bind→dispatch→writeback plumbing matches the golden model on random
    register files (a full binary→execute check). This is the on-ramp to the
    simulator-IR interpreter wave.
15. Done: `emit-exec-c` generates `axis_exec.h` (`axis.exec-c.v1`), the
    compiled executor — header-only C composing the C lifter with the C
    semantics interpreter, dispatching decoded instructions to their
    `axis_eval_*` function and writing the destination register.
    `tools/exec_c_check.py` proves the same binary→execute agreement with the
    golden model. The lift tables now carry an operand `kind` so reg/immediate
    binding is explicit in every backend.
16. Done: `emit-semantics-rust` generates `axis_semantics.rs`
    (`axis.semantics-rust.v1`), the safe-Rust semantics interpreter — one
    `pub fn axis_eval_<name>` per entry, lowered from the same typed IR as the
    C/LLVM backends (arithmetic via `wrapping_*` to match C's modular u32).
    `tools/rust_vs_golden.py` proves it bit-identical to the golden model, so
    the semantics backends are now a quintet (golden/C/SMT/LLVM/Rust). This
    unblocks a Rust executor (the eval half now exists). Remaining Layer 5
    work: the Rust executor itself and effect-carrying instructions
    (loads/stores/branches).
17. Done: operand-dependent `decode_requires` constraints close reserved
    subspaces that match/mask cannot express. AArch64 logical-immediate
    `N:imms` legality is validated in the ADL and enforced consistently by the
    C encoder, decode table/header, Python/C/Rust lifters, and all three
    executors.
18. Done: derived register operands represent implicit adjacent registers as
    typed selectors based on a directly encoded operand. Layout resolution
    remains fully encodable, and Python/C/Rust lifters materialize the derived
    selector before execution.
19. Done: atomic transaction groups, composable boolean guards, and generic
    masked-equality decode constraints provide the remaining structural
    semantics needed by paired atomics. Canonical Lisp, lowering equivalence,
    translation manifests, and Python/C/Rust constraint paths consume the
    typed forms without opcode-specific checks.

**Later waves** (unchanged in spirit): simulator IR interpreter, JIT backend,
effect-rich semantics, multi-cycle PyRTL/RTL generation.

The practical rule: every new backend should be differentially checked against
at least one existing backend. For example, C interpreter output should match
`golden_model.py`; JIT output should match the interpreter; SMT equivalence
checks should compare generated functions where possible. This mirrors AHA's
evidence ladder — each AXIS artifact should slot in as PROVEN, COSIM, or KAT
collateral rather than trusted prose.
