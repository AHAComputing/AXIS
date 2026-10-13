# AXIS Personality & Mode Design

Status: **5 stages implemented** (P1-P5), P5 being seam contracts, whose design
and gate live in [`elastic_seams_design.md`](elastic_seams_design.md) because a
seam is a channel at a boundary. This document designs
first-class **modes** (decode-gated legality) and **personalities** (an ISA view
bound to an execution discipline and a portable state capsule) for AXIS, and
stages the implementation so each step is independently landable and
differentially proven, the same way effects (`effects_design.md`) staged theirs.

The header said "proposal" for as long as all four stages had been built, which
is why the count is now computed from the staging list rather than written here
by hand (`tools/doc_facts_check.py`).

## 1. Motivation and honest scope

The PCE-field thrust ("polymorphic compute engines": unify heterogeneous cores
into a single computational field) needs an ISA-level control plane. The tight
form of core unification is a tile that *is* a scalar core, a SIMT group, or an
NPU depending on a **mode**, where:

- the legal instruction set changes with the mode (decode-gated legality — the
  hardware pattern is already proven in PCE as XRV H.3b's V-mode gating of
  hypervisor CSRs);
- a computation can **migrate** between personalities mid-flight, which
  requires a canonical, agreed **state capsule** (checkpoint format) so a
  split-run can be proven bit-exact against a whole-run;
- every op that is legal in more than one personality has **one** formal
  semantics, so the SIMT implementation and the scalar implementation are
  proven against the same source of truth by construction.

AXIS is the right home for all three: it already validates decode-space
disjointness (the spec-side proof gate), already declares the register surface
(`isa.registers`), and already has a full-state differential harness
(`exec_vs_golden.py`). What is missing is the vocabulary: today an instruction
is legal or not **globally**, a core implements one ISA unconditionally, and no
artifact pins a checkpoint format.

Reality check on demand: the live PCE consumers (URV extension unit — pure
ops; RVMT — compat-frozen) do not pull modes yet. The consumer is the planned
PCE-field saga. As with effects, this is a forward-looking language step, so it
is staged so that **mode-free documents produce byte-identical artifacts** at
every stage, and each stage lands with its own differential proof.

One roadmap consequence to flag now: wrong-mode execution must **trap**
(the VIRTUAL_INSTRUCTION-style fault, generalized). That pulls effects stage
E4 (traps) onto the critical path for stage P4 below, inverting the earlier
"traps deprioritized" call recorded in `pce_migration.md`.

## 2. Model

Three new top-level constructs, layered so each is useful without the next:

> A **mode** is a named, WARL-encoded machine state that gates decode
> legality. A **personality** binds one mode to an ISA view, an execution
> discipline, and a state capsule. An **instruction** carries the set of modes
> in which it is legal (default: all — the mode-free world is the "one mode"
> special case).

Semantics stay single-sourced: `formal_semantics`/`effects` are per
instruction, never per mode. If two personalities need genuinely different
behavior for an encoding, those are two instructions with disjoint mode sets —
which the validator can then check — not one instruction with two meanings.

The payoff for the decode space: today every instruction must be globally
disjoint. With modes, disjointness is required **within** each mode, so a
polymorphic tile legally *reuses* encoding space across modes (the XNN
personality's tensor op may share an opcode with the scalar personality's
custom op). Cross-mode reuse changes from "validator error" to "checked,
intentional, and emitted in the legality table".

## 3. Language surface

### `mode` block

```text
mode field_mode {
  csr: 0x7c0                 # CSR holding the mode field (custom range)
  field: [1:0]               # bit slice within the CSR (WARL)
  values: [scalar=0, simt=1, xnn=2]
  default: scalar
  description: PCE-field tile personality selector
}
```

At most one `mode` block per document in v1 (a single selector; nested/multiple
selectors are a non-goal). `values` names become the mode namespace.

### `instruction` gains `modes:`

```text
instruction fma_i {
  ...
  modes: [scalar, simt]      # legal only in these modes; omitted = all modes
}
```

### `personality` block

```text
personality simt8 {
  mode: simt                 # which field_mode value activates it
  implements: rv32_axis      # ISA view (existing isa reference)
  discipline: lockstep(lanes=8)
  capsule: [x[32], pc]       # portable state; default = the ISA's registers
  description: 8-lane lockstep SIMT personality
}
```

`discipline` is structured metadata in v1 (it flows to the topology/manifest
emitters for the PCE-side field allocator; it does not change semantics).
Forms: `lockstep(lanes=N)`, `independent(threads=N)`, `systolic(rows=R,
cols=C)`, `fused(width=N)`.

`capsule` lists the architectural state that migrates: register groups (by the
names declared in `isa.registers`) and `pc`. Everything not listed is
explicitly non-portable (personality-private state that must be drained, not
carried). The default is the full declared register surface of the
`implements` ISA.

`core` composes: `core pce_tile0 { personalities: [scalar1, simt8, xnn0] }`
alongside the existing single-ISA `implements` form, which remains valid and
is sugar for one implicit personality.

## 4. Validation (`src/validate.rs`)

- `mode`: values are distinct and densely nameable; `default` names a value;
  `field` width holds all values; CSR address is in the custom range.
- `instruction.modes`: every name resolves to a `mode` value.
- **Per-mode decode disjointness**: `validate_decode_space_disjointness`
  becomes mode-indexed — for each mode value, the instructions legal in that
  mode must be pairwise disjoint under the existing match/mask check. Two
  instructions may overlap in the decode space **iff** their mode sets are
  disjoint. A document with no `mode` block validates exactly as today (one
  implicit mode containing everything) — the current behavior is the
  degenerate case, not a special case.
- `personality`: `mode` names a value; `implements` names an ISA;
  no two personalities claim the same mode value; `capsule` entries resolve
  against the ISA's declared registers; discipline arguments are positive.
- **Capsule compatibility for migration**: any two personalities of the same
  core whose ISA views share the capsule registers get a derived
  `migratable: true` pair entry in the emitted manifest; incompatible capsules
  (different widths for the same named group) are a validation error, not a
  silent false.

## 5. Emitted artifacts

Two new bundle files (both optional in `load_adl_bundle_dir` terms — absent
for mode-free documents, so existing bundles are untouched):

- **`mode_legality_manifest.json`** — schema
  `axis.mode-legality.v1`: the mode block (CSR, field slice, values, default)
  plus, per mode value, the list of `{mnemonic, match, mask}` legal in that
  mode. This is the decode table the hardware mode gate consumes directly; the
  legality table is *derived from the same resolution* as every other encoding
  fact, so it cannot drift from `emit-json`/tablegen.
- **`state_capsule_manifest.json`** — schema `axis.state-capsule.v1`: per
  personality, the ordered capsule layout (name, count, width, byte offset in
  a canonical little-endian serialization), the discipline, and a
  `layout_hash` (sha256 of the canonical layout description) so RTL
  checkpoint logic, cosim harnesses, and `axis_exec` pin the same format by
  hash rather than by convention. Plus the derived `migratable` pair list.

Existing emitters: `manifest.json` instructions gain a `modes` array
(omitted when legal-in-all, keeping mode-free output byte-identical);
`topology` carries personalities under their core. Tablegen/LLVM/lift are
unchanged in v1 (mode is a runtime-machine concern, not a compiler one, until
per-mode subtarget features become a real need).

## 6. Execution and differential checking

- `axis_exec.py` `step(...)` gains an optional `mode=` argument. With a mode,
  dispatch consults the legality table first; an illegal-in-mode word raises
  the trap path (E4) — until E4 lands, a distinguished `IllegalInMode` result
  (stage P4 notes the dependency). Without `mode=`, behavior is unchanged.
- **Legality cross-check** (`tools/legality_vs_golden.py`): for every mode ×
  every instruction word in the examples, the executor's accept/trap decision
  must equal the manifest's match/mask tables — proving the emitted legality
  table and the executor derive from the same resolution.
- **Migration round-trip** (`tools/migrate_vs_whole.py`): run a program under
  personality A for k steps, serialize the capsule per the emitted layout,
  restore under personality B, run to completion; final full state must equal
  the uninterrupted whole-run, for every k and every migratable (A, B) pair.
  In AXIS both runs use the same executor, so this proves the **capsule
  serialization and the layout manifest** (offsets, widths, hash), which is
  exactly the contract the PCE RTL rung then proves against real cores —
  split-run-on-silicon vs `axis_exec` whole-run, same capsule bytes.

## 7. PCE consumer impact (informative)

- `aha/isa/adl_loader.py`: two new optional bundle file names, following the
  existing optional-manifest pattern.
- Hardware mode gate: XRV/URV extension dispatch consults the legality table
  keyed by the mode CSR field; wrong mode → trap (the H.3b gating pattern with
  a table instead of a hardcoded CSR list). This is the first consumer that
  needs the PCE-side trap surface for custom ops.
- The PCE-field saga's proof rungs consume the artifacts directly:
  personality-fidelity cosim uses `axis_exec` as golden per mode;
  migration-equivalence cosim uses the capsule manifest as the pinned
  checkpoint ABI; the field allocator reads disciplines from topology.

## 8. Staging (each independently landable and proven)

- **P1 — capsule emission.** _Done._ The `personality` block (parse + validate,
  `src/parser.rs`/`src/validate.rs`), capsule layout resolution with an in-crate
  SHA-256 layout hash (`src/capsule.rs`), and `state_capsule_manifest.json`
  (`src/emit/capsule.rs`, `emit-capsule-json`, bundled when personalities exist)
  with per-personality byte layout, `layout_hash`, and `migratable_pairs`. No
  `mode` construct yet (personalities without a mode selector still pin
  checkpoint ABIs for existing cores). Proven by `tools/migrate_vs_whole.py`:
  for every migratable pair and every checkpoint point k, checkpoint on A →
  serialize the capsule → restore on B → finish equals the whole run
  (`examples/personality_tile.axisl`; the harness also re-derives each
  `layout_hash` from its canonical string). Unlocks the PCE
  migration-equivalence rung immediately.
- **P2 — mode grammar + per-mode validation + legality manifest.** _Done._ The
  `mode` block (parse + validate: distinct values that fit the WARL field, a
  `default`, a custom CSR) and `instruction.modes`. `validate_decode_space_disjointness`
  is now mode-indexed — a pair conflicts only if their encodings overlap *and*
  their mode sets intersect, so disjoint-mode instructions may reuse an encoding
  (a mode-free document reduces to the old global rule). `emit-legality-json` /
  bundle `mode_legality_manifest.json` (`axis.mode-legality.v1`) carries the
  selector plus, per mode value, the `{mnemonic, match, mask}` legal in it;
  `manifest.json` instructions gain a `modes` array only when restricted (so
  mode-free output stays byte-identical). Proven by `tools/legality_vs_golden.py`
  (for every mode × word, the manifest's per-mode legal table agrees with the
  decode table + `modes` arrays, including illegal-in-mode) and by
  `examples/mode_polymorphic.axisl` — cross-mode encoding reuse that validates,
  its same-mode twin rejected, a bad mode reference rejected.
- **P3 — personality composition.** _Done._ `personality.mode` binds a
  personality to a mode value (validated to name a declared value, distinct per
  personality) and `core.personalities` composes them on a core (validated to
  name declared personalities). The topology manifest carries composed
  personalities under their core with mode + discipline (the view the PCE-side
  field allocator reads); a plain single-ISA core stays byte-identical. Proven
  by `examples/personality_composition.axisl` (three personalities — scalar /
  lockstep SIMT / systolic — bound to modes and composed): the P1 migration
  round-trip holds across all migratable pairs, the P2 legality cross-check
  holds, and a golden test pins the topology composition and the guardrails
  (unknown/duplicate mode binding, unknown personality in a core).
- **P4 — mode-aware execution.** _Done._ The lift table carries per-instruction
  legal `modes` (only in a mode document, so mode-free tables are unchanged), and
  `axis_exec.step(word, ..., mode=)` decodes mode-aware: among the instructions
  matching a word it selects the one legal in `mode`, so a reused encoding runs
  different instructions per mode (`SCALAR_OP` in `scalar`, `TENSOR_OP` in `xnn`);
  a word illegal in the mode takes the E4 trap path (`trap="illegal"`). Without
  `mode=`, decode is unchanged. `tools/legality_vs_golden.py` now drives the
  executor too: for every mode × word, the executor's mnemonic/illegal decision
  must equal the legality manifest and the decode table (three-way agreement).
- **P5 — seam contracts.** _Done._ Landed as G4b.3, whose design is
  [`docs/elastic_seams_design.md`](elastic_seams_design.md). An exported
  functional unit is an elastic channel at a personality boundary, which is why
  this and `vliw_spatial_design.md`'s G4 handshakes are one design rather than
  two — and why the channel itself landed there first, as G4b.1: a seam is a
  channel at a boundary, so the boundary was the part still missing.
  `(exports (mul-pipe (unit mul) (channel mul-result-bus)))` on one personality
  and `(imports (mul-pipe (from lane1) (channel mul-borrow-bus)))` on another;
  the two sides name their own channels, and `seam_contract_check.py` decides
  whether those compose — same protocol, importer's window containing the
  exporter's, order composing downward. The manifest publishes both sides, and
  the exported unit must be one some packet slot or fabric row declares: a
  machine cannot lend a unit it does not have.

**Non-goals for now:** multiple/nested mode selectors, per-mode instruction
semantics (explicitly rejected by the model — see §2), per-mode compiler
subtargets, dynamic discipline semantics (lockstep divergence rules live in
PCE proofs, not in AXIS v1), variable-length encodings.

## 9. Invariants

- A document with no `mode`/`personality` blocks produces **byte-identical
  artifacts** at every stage — the current single-mode world is the degenerate
  case of the new model.
- Semantics are single-sourced per instruction; a mode never selects between
  behaviors, only between legal/illegal.
- Every encoding fact in the legality manifest derives from the same
  format/encoding resolution as `emit-json` — the mode gate cannot drift from
  the decoder.
- The capsule layout is pinned by hash; consumers match by `layout_hash`,
  never by field-order convention.
- AXIS judges the spec (modes disjoint, capsules compatible, one semantics);
  PCE's `wire_*()` judges the silicon (gate traps correctly, personalities
  bit-exact vs `axis_exec`, capsule round-trips on RTL). Neither side
  self-certifies the other's claim.
