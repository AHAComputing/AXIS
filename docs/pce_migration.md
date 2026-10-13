# AXIS ↔ PCE/AHA Migration

AXIS is the permanent home for all ADL work. The in-repo seed crate in PCE
(`software/pce-adl/`) has been **retired** (deleted 2026-07-15 on PCE branch
`adl/delete-pce-adl-seed`) — PCE's loaders consume AXIS bundles directly. This
document records the verified consumer seams in the PCE repo (checked 2026-07-02
against PCE main), the contracts AXIS must not break, and the completed
retirement steps (all five below are done).

## Live consumers (trustworthy tier)

These are the seams that matter. Everything AXIS does should be justified by
one of them.

### 1. `aha/isa/adl_loader.py` — instruction manifest loader

- Strictly validates `schema == "pce-adl.aha-instructions.v1"` on
  `aha_instructions.json` (AXIS `emit-aha-json`).
- `load_adl_bundle_dir(...)` reads an `emit-bundle` directory by fixed file
  names: `manifest.json`, `rvmt_extension_manifest.json`,
  `aha_instructions.json` (required); `adl_topology_manifest.json`,
  `accelerator_descriptor_manifests.json`, `adl_coupling_manifest.json`,
  `rvmt_launch_templates.json`, `rvmt_rcore_region_manifest.json` (optional).
- Per-instruction field contract (`_instruction_from_dict`): `mnemonic`
  (required), `encoding` object (required; `total_bits`, `opcode`, `func3`,
  `func7`), `description`, `category`, `operands` (`name` required, `type`,
  `width_bits`, `is_output`, `is_optional`, `description`), `semantics`,
  `latency_cycles`, `throughput_per_cycle`, `area_estimate_um2`,
  `power_estimate_mw`, `expected_speedup`, `applicable_patterns`, `rationale`.

#### What the encoding says, and what a consumer had to guess

`encoding` carried `total_bits`, `format`, `opcode`, `func3`, `func7` — the
opcode *space*, and nothing about where operands sit in the word. The loader
builds a `BitEncoding`, whose dataclass has carried a `fields: List[BitField]`
since before this manifest existed, and fills it with `[]`.

So `hardware/grv/grv_conformance/isa_surface.py` — which exists to remove three
copies of GRV's opcode allocation — says of the manifest it loads:

> the manifest pins the OPCODE SPACE exactly and says nothing about where
> operands sit in the word. Operand placement here is therefore the harness's
> RISC-V R-type convention

That convention is a fourth copy of a fact AXIS already resolves: the decoder,
the encoder and the lift table are all built from one `InstructionLayout`.
`encoding.fields` now publishes it, in the shape `BitField(name, start_bit,
width_bits, value)` takes — a fixed field carries its `value`, an operand slice
carries `operand_lo`, the bit of the operand that slice starts at, because a
scattered immediate is several slices of one operand and a list that could not
say which is which would be a fifth answer rather than the first.

`pce_contract_check.py` proves it is the *same* placement rather than a
plausible one: folding the fixed fields into a match and a mask has to
reproduce `decode_table.json` exactly, and a run that pairs fewer instructions
than the manifest holds fails as vacuous. Shifting every fixed field by one bit
produces 771 violations.

The consumer side is one line — `adl_loader._instruction_from_dict` passes
`fields=[]` into `BitEncoding` and would read them instead — and it is PCE's to
make. The manifest is additive until then: `pce_smoke_check` loads this bundle
through the real `load_adl_bundle_dir`, `adl_bridge`, and the ADL.2 Z3 gate
unchanged.

### 2. `aha/optisynth/adl_bridge.py` — OptiSynth projection

- Consumes the `load_adl_bundle_dir` dict or a raw manifest dict.
- Projects the bundle into an `EnginePassProfile`, per-intrinsic cost
  overrides, and intrinsic name sets.
- Intrinsic naming convention is pinned: `llvm.pce.<mnemonic-lower>`.
- **Phase ADL.2 (planned in PCE, deliverable from AXIS):** parse instruction
  semantics into a `Slice` so the verifier gets free Z3 axioms and the
  sketcher gets free rewrite rules. AXIS's typed `formal_semantics` /
  `semantics.json` is exactly this input; shaping AXIS proof collateral for
  ADL.2 is a roadmap wave, not an afterthought.
  - _Landed:_ AXIS's `optisynth_formal_semantics` (src/optisynth.rs) emits the
    OptiSynth micro-DSL into `formal_semantics`: rotates/extends expand into the
    grammar's shift/mask idioms, and `clz`/`ctz`/`cpop` map to the `intr` call
    form (`(intr llvm.ctlz|cttz|ctpop iW x)`). Against PCE main, the zbb example
    now derives **all 11 Z3-proven rewrite rules** (was 4, then 8).
  - _Landed:_ the **axiom half, as an artifact rather than as a string to
    parse.** `emit-smt-axioms` writes `intrinsic_axioms.smt2` into the bundle,
    and §4 below says why the shape is what it is.
    `tools/optisynth_vs_golden.py` proves the emitted dialect (including the
    `intr` bit-counts) equals the golden model, so the axioms PCE registers are
    sound. The `intr` bit-counts required a small PCE-side change (branch
    `adl/ctlz-cttz-ctpop-axioms`): `verifier/smt.py` gains validated Z3 builtin
    axioms for `llvm.ctlz`/`cttz`/`ctpop`, and `adl_bridge.py::_body_factory`
    resolves nested `INTRINSIC` nodes through the axiom registry (mirroring
    `_encode_slice`). The grammar also accepts `udiv`/`sdiv`/`urem`/`srem` —
    headroom AXIS **now uses**: `urem`/`srem` were added to the operator set so a
    divmod unit is expressible, and they lower to `bvurem`/`bvsrem` for exactly
    the verifier this note describes.

### 3. `aha/compute_core/extensibility/xrv_extension.py` — hardware dispatch

- `XRVExtensionDescriptor.from_adl(ci)` raises unless the instruction carries
  an explicit encoding; it consumes exactly `opcode`, `func3` (default 0),
  `func7`, and `latency_cycles`.
- The registry feeds both the XRV extension FU and
  `hardware/urv/urv_extension_unit.py` (URV's OoO custom-instruction dispatch:
  custom-0 opcode space, single in-flight FSM for multi-cycle ops).
- Deliberate v1 scope on the PCE side: **pure ops only** — no traps, no memory
  effects, no exception outputs. AXIS effects/trap semantics are therefore
  deprioritized until PCE grows that surface.

### 4. ALGO-WATCH — autonomous op synthesis (strategic target)

`aha/socc/algo_*.py` demonstrates an agent reading a paper, characterizing a
new op kind, synthesizing a kernel, and proof-gating it against a trusted
spec before banking. AXIS's role in this loop: the agent emits a `.axisl`
declaration for the new op, and AXIS generates the proof collateral —
`golden_model.py` as the trusted spec, SMT axioms, encode/decode metadata,
and the PyRTL FU builder. "Verify, don't trust" needs a typed declaration
format; AXIS is it.

## The axiom artifact (ADL.2)

`register_intrinsic_axioms_from_bundle` builds a Z3 axiom per instruction by
**re-parsing the `formal_semantics` string** out of the bundle. That is a second
parser for AXIS's expression language, living in another repository, and it is
the same situation `xnn_mt/contract.py` and the GRV frame descriptors were in:
a consumer maintaining by hand something the description already knows.

The tempting fix — ship the parsed AST — is the wrong one, and for a reason
worth writing down. **An AST has no gate.** Every other AXIS output is an
artifact in a consumer's own language, proven against the golden model by a
differential: `smt_vs_golden` asks z3, `llvm_patterns_check` evaluates every
DAG, `c_vs_golden` compiles and runs. A tree is inert; nothing in this ladder
can check that a consumer's *walk* of it means what AXIS means. Shipping one
would move their translator from parsing a string to walking a tree and leave
the correctness burden in exactly the same place — outside the gates.

So AXIS emits the axioms:

```smt2
; axis: cadd
(declare-fun |llvm.pce.cadd| ((_ BitVec 32) (_ BitVec 32)) (_ BitVec 32))
(assert (forall ((rs1 (_ BitVec 32)) (rs2 (_ BitVec 32)))
  (= (|llvm.pce.cadd| rs1 rs2) (bvadd rs1 rs2))))
```

**This is not `semantics.smt2` with a different header.** That file defines each
instruction as a `define-fun`, which a solver inlines — it answers "what does
this instruction compute" and can say nothing about `llvm.pce.cadd` *as a
symbol*, because after inlining the symbol is gone. A verifier handed a slice
that **calls** an intrinsic needs the opposite: the intrinsic declared
uninterpreted, and an axiom constraining it, so the call can be carried through
its own reasoning and discharged at the end. The quantifier is why the logic is
`BV` rather than `QF_BV`.

Three things this cost, each found by running the artifact rather than by
reasoning about it:

- **`(set-logic BVFP)` does not work.** The quantified bit-vector-plus-float
  logic has a name in SMT-LIB and z3 does not implement it: under it z3 does not
  know the `FloatingPoint` sort, so every rounding-mode constant becomes an
  unknown constant and the file stops parsing at the first one. `QF_BVFP` is
  quantifier-free and cannot hold a `forall`. Float documents emit `ALL`.
- **Quantifiers are not free.** With rv32i's 148 axioms in scope, z3
  instantiates per query and the gate took minutes. Every axiom here is
  `forall x. f(x) = body`, which is exactly what `:smt.macro-finder` turns back
  into a definition — with it, the same run is seconds. The emitted file says so
  in its own header, because a consumer meets the same wall.
- **The join key had to be written down.** `llvm.pce.<mnemonic-lower>` is not
  invertible: one lowercases a mnemonic, the golden model's `eval_<ident>`
  sanitises it. Each declaration carries `; axis: <ident>` above it, the way
  `llvm_backend.md` §6 reads operand names out of LLVM's own comments.

### The failure mode this shape has and `define-fun` does not

Definitions cannot contradict each other. A set of quantified assertions can —
and an unsatisfiable axiom set **entails every refutation query**. Measured on
`cgra_fabric`, with `llvm.pce.cadd` axiomatised twice, once correctly and once
as subtraction:

| axioms | `check-sat` | refute `cadd(3,4) = 7` |
|---|---|---|
| correct | sat | unsat ✓ |
| body changed to `bvsub` | sat | **sat** — caught by the golden comparison |
| contradictory | **unsat** — caught first | unsat — *would have passed* |

The third row is the whole argument for asking `check-sat` of the axioms alone
before anything is proved from them. A gate that only asked refutation questions
would report a perfect score for a file that says nothing, which is the shape of
vacuity `gate_coverage.md` exists to hunt. `tools/smt_axioms_check.py` asks
consistency first, then compares 20 random and 12 edge vectors per intrinsic
against the golden model: 49 corpora, and rv32i alone is 160 axioms over 2220
vectors.

`pce_contract_check.py` pins the artifact — present, headed, logic stated, and
one assertion per declaration, because an undeclared symbol is a call nothing
defines and an unconstrained one is a definition nothing calls.

## The capability manifest

`aha/measure/amf_vliw_axis.py` states a strict contract — one or two register
inputs, one register output, 32-bit pure combinational semantics, latency 1 —
and **fails closed** on anything else. So AHA discovers ineligibility one
instruction at a time, at consumption, by trying. AXIS knows the whole answer
before it emits anything: 693 declines in 17 named reasons on the AArch64 seed
alone.

`emit-capability-json` states it, and `capability_manifest.json` joins the
bundle. Per instruction: whether it states a value and the reason where it does
not, its shape (register inputs, immediate inputs, register outputs, result
width), what it touches (memory, state, the counter, traps, barriers), and its
latency and throughput. That is exactly the surface the v1 contract fails
closed on.

**Every field is read from a predicate an emitter already uses.**
`pure_value_semantics` is the same function the SMT, LLVM and axiom paths ask;
`effect_summary` is what the lift table publishes. This is a projection of
decisions already made, not a fifth place the rules live — and
`tools/capability_check.py` is what holds it to that: an instruction claiming a
value must have a `define-fun` in `semantics.smt2` and a `declare-fun` in
`intrinsic_axioms.smt2`; one declining must appear in both as a comment **with
the same reason string**, because a different reason means two predicates.
2604 instructions cross-checked over every corpus -- 897 before
`semantics.smt2` began naming what it does not define. An instruction appearing
in neither file could not be compared at all, so nearly half of what the join
claims to cover was outside it. The predicate is computed once, in
`pure_value_semantics`, which is what lets the manifest and the artifact say the
same thing: a blanket reason written into the emitter instead was rejected by
this very gate, correctly, as a second answer to a question that already had
one.

The join has to compare like with like, and learning that cost a wrong
diagnosis. Swept over all 55 it reported 18 contradictions — the capability
manifest declining `VREDSUM_S` for an operator `semantics.smt2` was busy
defining. Neither artifact was wrong. A **lane group** is one encoding standing
for N per-lane instructions: the capability entry is decode-keyed and describes
the vector operands the format binds, while the semantics artifacts describe
the instantiated lanes. Joined by mnemonic, two correct views of one encoding
read as a contradiction. The manifest publishes `lane_group` now, and the join
skips those and counts them — 211 of them.

That gate earned itself immediately. The first version of the manifest built
its own list of state names instead of asking
`effects::isa_scalar_state_names`, and included `pc` — which is the counter,
with its own `Loc::Pc`, not named scalar state. Every pc-relative instruction
claimed to read state, and the join caught it on `AUIPC`, `ADR` and `ADRP`:
a projection that disagreed with the thing it projects, found by the check
written to stop exactly that.

## Evidence for a certificate

`aha/cert/certificate.py` models a design's trust as `Claim`s carrying a
`ProofVerdict` and pointing at `EvidenceFragment`s, with an explicit rule: *a
claim with no evidence is allowed only at `unverified`/`failed`*, and its own
`audit` "reports it, so the honesty boundary is visible rather than silently
dropped". AXIS runs 283 gates and none of that reached a certificate.

`tools/evidence_manifest.py` emits what AXIS has established about a
description, in that shape. **It is a tool and not an emitter, and that is the
whole design**: a gate result is a fact about a *run*, not about a description,
and an emitter writing `proven` into a manifest would assert something it had
not done.

### Almost nothing is `proven`, and saying so is the point

The tiers are `failed`, `unverified`, `error_bounded`, `cosim`, `proven`.
Nearly every AXIS gate is a **differential over sampled inputs**: SMT against
the golden model on random and edge vectors, LLVM's encoder against AXIS's on
random operands, a lifted block against the executor on random initial state.
z3 answering `unsat` proves the vector it was asked about; it was not asked
about the others.

So these are `cosim` — two independent implementations agreeing — and not
`proven`. Claiming `proven` would be the overclaim a tier system exists to
prevent, and `aha/cert/adapters.py` calls its own mapping "conservative" for
the same reason.

### A decline is not a failure

The first version of this reported `zbb_like`'s block-graph gate as `failed`.
It had found **zero disagreements**: the corpus has no branch and no memory, so
the gate's vacuity guard fired and it exited non-zero having established
nothing. Reporting that as `failed` tells a consumer a design failed a check
that did not apply — the same dishonesty as `proven`, pointing the other way.

Exit codes cannot tell the two apart, so the tool reads the gate's own words
("proves nothing", "is stated and unchecked") and maps a decline to
`unverified` with the reason attached. That is a heuristic on phrasing and is
written down as one — **and it has been wrong twice.** `zbb_like`'s block gate
was reported `failed` for having no branch to check, and `effects_mem`'s SMT
and axiom gates for having no pure values at all ("no formal_semantics
functions found", "emits no intrinsic axioms"). Both surfaced by running the
tool over more descriptions, and each time the list of phrasings grew.

The durable fix is a **distinct exit status for a decline**, so a gate says
which it means rather than a reader inferring it from prose. That is a change
to every gate in the ladder and is not made yet. Until it is, a new phrasing
means a false `failed` — so `evidence_check.py` refuses a run in which every
claim came back the same verdict, since a run that never sees a second verdict
has not exercised the distinction it exists to enforce.

`tools/evidence_check.py` enforces on the producing side what `audit` only
reports on the consuming one: a claim above `unverified` names evidence, every
named fragment exists, a `cosim` claim's gate exited zero and an `unverified`
one's did not, and at least one claim is above `unverified` — or the document
establishes nothing and is not a certificate. Four injections are caught: a
decline reported as `cosim`, a claim with no evidence, a fragment that is not
there, and a document that establishes nothing.

## Legacy consumers (compat-frozen)

The RVMT tile (`hardware/rvmt_tile*.py`, cluster adapters) and the
rcore/launch-template surface are the previous generation. AXIS keeps emitting
their manifests unchanged (`pce-adl.rvmt-launch-templates.v1`,
`pce-adl.rvmt-rcore-regions.v1`, `pce-adl.topology.v1`,
`pce-adl.accelerator-descriptors.v1`, `pce-adl.coupling.v1`,
`rvmt_extension_manifest.json`) but does not extend them. New description
power targets URV/OptiSynth/ALGO-WATCH.

## Contract invariants

| Artifact | Schema | Consumer | Status |
| --- | --- | --- | --- |
| `aha_instructions.json` | `pce-adl.aha-instructions.v1` | `adl_loader` (strict check) | load-bearing |
| bundle directory file names | — | `load_adl_bundle_dir` | load-bearing |
| instruction/operand JSON fields | see above | `_instruction_from_dict` | load-bearing |
| `encoding.{opcode,func3,func7}` present | — | `from_adl` hardware dispatch | load-bearing |
| intrinsic naming `llvm.pce.<mnemonic>` | — | OptiSynth bridge | load-bearing |
| `formal_semantics` in `manifest.json`/`aha_instructions.json` | OptiSynth dialect (ADL.2 grammar) | `adl_bridge.extract_rewrite_rules_from_bundle` + `register_intrinsic_axioms_from_bundle` + Z3 proof gate | load-bearing |
| `semantics.json` | `axis.semantics.v1` (raw AXIS dialect) | typed-AST home; AXIS backends | load-bearing |
| `golden_model.py` `AXIS_SPECS`/`selftest` | `axis.golden-model.v1` | ALGO-WATCH trusted spec | shipped |
| `axis_semantics.h` | `axis.semantics-c.v1` | C/C++ cosim oracle | shipped |
| RVMT/topology/descriptor manifests | `pce-adl.*.v1` | RVMT tile surface | frozen compat |

Schema strings are API. Renaming any `pce-adl.*` schema or bundle file name is
a breaking change and needs a coordinated PCE update.

## Retirement steps for `software/pce-adl/`

1. **Contract fixtures in AXIS** — _Done._ Two gates encode the exact field
   surface `_instruction_from_dict` / `_operand_from_dict` / `from_adl` read and
   the `load_adl_bundle_dir` file-name contract, so drift fails in AXIS CI
   before PCE sees it:
   - `tests/golden.rs::aha_json_pce_consumer_contract` — pins the strict schema
     and every load-bearing instruction / encoding / operand field at
     `emit-aha-json` time (runs in `cargo test`, no PCE checkout needed).
   - `tools/pce_contract_check.py` — a self-contained oracle that validates
     `emit-bundle` output against the full contract (required/optional bundle
     files; schema; per-instruction mnemonic + encoding; `opcode`/`func3`/`func7`
     bit-ranges and `latency_cycles >= 1` that `from_adl` enforces; operand
     fields) across every AHA-emittable example, with no PCE import. Its
     mutation tests confirm it catches schema drift, out-of-range encodings,
     dropped operand fields, and missing bundle files.
   - `examples/rvmt_xpce.axisl` is the exact Lisp-authored compatibility
     fixture. Its typed document, AHA payload, and complete 34-file bundle are
     the only form of that fixture; `tests/pce_contract.rs` pins the field
     surface PCE reads.
2. **Cross-repo smoke check** — _Done._ `tools/pce_smoke_check.py` runs
   `axis emit-bundle` and loads the result through the real
   `aha.isa.adl_loader.load_adl_bundle_dir`, the `aha.optisynth.adl_bridge`
   projections, the ADL.2 rewrite-rule extraction, and the Z3 proof gate.
   Verified passing against PCE main for `rvmt_xpce` and `zbb_like`
   (`--axis-file` selects the example; `--pce-root` / `AXIS_PCE_ROOT` the repo).
   Run it whenever either side changes.
3. **Feature parity audit** — _Done (2026-07-08): AXIS is a verified strict
   superset, zero gaps._ Emitting a bundle from both the seed crate
   (`software/pce-adl`) and AXIS on **every** shared `.pceadl` example
   (`rvmt_xpce`, `accelerator_descriptor`, `rcore_descriptor`,
   `heterogeneous_tile`) and diffing recursively: every JSON key the seed emits
   is present in AXIS (0 dropped keys), AXIS emits all 10 seed bundle files
   (plus 24 more), and AXIS emit-bundle succeeds on every seed input (no
   regression). The standalone emitters match too: `emit-json` / `emit-rvmt-json`
   / `emit-aha-json` have 0 key gaps, and `emit-python` carries all three
   top-level symbols (`PCE_ADL_MANIFEST`, `PCE_ADL_SCHEMA`,
   `RVMT_EXTENSION_MANIFEST`) with no dropped dict keys. Nothing to port.
   Reproduce while the seed exists: `emit-bundle` from each side and diff keys.
4. **Repoint PCE** — _Done (merged into `grv-soc-integration`)._ The live
   loaders (`adl_loader`, `adl_bridge`) always read JSON, not the crate. The one
   genuine seed-*only* producer,
   `aha/optisynth/pcestudio/cli.py::_emit_bundle_via_rust_crate`, now prefers the
   AXIS binary (sibling `../axis`, or `PCE_ADL_CRATE` override, then a PATH
   lookup). `aha/compute_core/extensibility/__init__.py` and
   `aha/optisynth/adl_bridge.py` docstrings name AXIS. The ADL test resolvers
   (`test_optisynth_adl_realbundle_e2e.py`, `test_cli_adl.py`) already prefer the
   AXIS sibling; their seed-fallback branch is now dead code (AXIS is always
   present) — a trivial cosmetic cleanup left for a clean tree (`accel_capabilities.py`
   has no seed dependency; its "axis" refs are capability axes).
5. **Delete the seed** — _Done (PCE branch `adl/delete-pce-adl-seed`)._
   `software/pce-adl/` (15 tracked files: `src`, `Cargo.{toml,lock}`, `examples`,
   `tests`, `README`) and `tests/test_pce_adl_readme_contract.py` (which pinned
   the seed README) are removed. Preconditions were all verified first: no Cargo
   path-dependency on `pce-adl`, not a workspace member, no CI workflow builds it,
   and the loaders read JSON. Verified *after* deletion:
   `tools/pce_smoke_check.py` still loads an AXIS bundle through the real
   consumers and passes the Z3 gate (11/11 rules) — the loaders are untouched.
   The seed's End-to-End Quickstart docs (the `python -m aha.cli adl …` flow)
   lived only in its README; if still wanted, re-home them in AXIS's or PCE's
   docs (the CLI itself is unaffected).
