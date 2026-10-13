# AXIS Packets, Slots, and Fabrics — VLIW and CGRA

Status: **17 stages implemented** (B1-B4, G1-G4a, G4b.1-G4b.3, A1-A6). G4b.3 is
P5, the seam contracts of
[`elastic_seams_design.md`](elastic_seams_design.md); the consumer that
document was waiting for turned out to be the hardware repository rather than
this one. This document
designs the machinery AXIS needs to describe statically scheduled machines:
VLIW cores (packets of concurrently issued operations) and CGRAs (operations
placed on a fabric of processing elements and routed between them). It stages
the work the way `effects_design.md` and `personality_design.md` staged theirs
— each stage independently landable, each with a differential gate that can
fail, and every document that uses none of it producing unchanged artifact
content (§11).

## 1. The gap, stated precisely

AXIS describes what one instruction *means*. Nothing in it describes what
issues *together*, or *when*.

That is not a small omission dressed up: it is the single axis the language has
never had. Every existing expansion works *inside* one instruction — SIMD lanes
(`src/simd.rs`), scalable lane instantiation (`src/scalable.rs`), bounded loops
(`src/loops.rs`) all turn one word into more computation, and all of them stop
at the word boundary. Downstream, that boundary is a constant: `ILEN = 4` in
the emitted executor (`EXEC_PY_RUNTIME` in `src/emit/lift.rs`), `next_pc = pc +
ILEN`, one decode per word, one instruction retired.

A VLIW core violates exactly one thing in that list: several operations retire
per fetched word. A CGRA violates all of them: there is no word, no PC, and no
decode — an operation is placed at a point in space and repeats every II
cycles.

What already exists is the *vocabulary of intent* and nothing behind it:
`vliw_simd`, `spatial_dataflow` and `systolic_array` are strings in
`ACCELERATOR_TARGETS` (`src/validate.rs`), mirrored in `src/emit/topology.rs`;
personality `discipline` offers `systolic(rows,cols)` and `fused(width)` and
`docs/personality_design.md` §3 says outright that it "does not change
semantics". Those are labels on a manifest. Nothing checked a co-issue, nothing
executed a packet, nothing knew a fabric link existed. Stage B1 (§9) has since
closed the first of those — slots, units, slot-indexed decode and the packet
manifest are implemented — and everything after it here is still design.

**Reality check on demand.** No live PCE/AHA consumer reads a packet or a
fabric description today. The nearest real seams are the `fabric` value in
`RCORE_BACKEND_KINDS` and the `efpga`/`spatial_dataflow` accelerator targets,
which carry no structure. So this is a forward-looking language step, like
effects and modes were, and it is staged to prove itself against in-repo gates
before any consumer depends on it.

## 2. One mechanism, two machines

The reason this is one document and not two: a VLIW slot and a CGRA processing
element are the same object under a different resource space.

> An **issue group** is a set of operations that read one architectural state
> and commit one result. A **resource space** says which operations may occupy
> it simultaneously. VLIW's resource space is a fixed row of slots, indexed by
> functional unit. A CGRA's is a grid of PEs plus the links between them,
> indexed modulo an initiation interval.

Everything the two share falls out of that: parallel read-then-commit
semantics, write-conflict as an error rather than a resolution rule, exposed
result latency, and a resource-occupancy check on a *given* assignment. What
differs is only what a resource is, and one addition on the CGRA side —
**routing is itself a resource**, because a value that moves between PEs
occupies a link for a cycle the way an operation occupies a PE.

This is why the staging runs B (packets) before G (fabrics): G reuses B's group
semantics wholesale and adds a placement and a route to it.

## 3. What does not change: the 32-bit word

The load-bearing engineering constraint is `validate_format_definition` in
`src/layout.rs` — a format's `bits` must be between 1 and 32 — and the u32
match/mask carried through `src/emit/encode.rs`, the decode tables, the C
decoder, and every backend.

A 128-bit VLIW word does not fit that, and **widening it is rejected for v1**.
Widening reaches every emitter, every gate, and every consumer, to describe
machines that overwhelmingly do not need it: C6x, ST200/Lx, and Tensilica FLIX
are all containers of independently decodable syllables.

So a packet is a **container of syllables**, each syllable an ordinary
instruction with an ordinary ≤32-bit format, and a packet word is a sequence of
them. Nothing in encode/decode changes width; the packet layer sits above it
and is the only thing that knows a group exists. A machine whose syllables
genuinely span the container (a single 57-bit immediate crossing slot
boundaries) is out of scope and named as such in §9.

## 4. Language surface

Every construct here is **Lisp-only**. The legacy block grammar was a
compatibility frontend for sources that predate it, and every feature since
scalable vectors — loops, limbs, register slices, RVV and SVE — has landed in
`.axisl` alone. A new construct in a grammar kept for backward compatibility
would be a contradiction in terms.

### 4.1 Units

An instruction says which class of functional unit executes it. This is one
field, and slot legality is *derived* from it rather than declared per slot —
the alternative, an instruction per slot, multiplies the corpus and duplicates
semantics, which is the one thing this repository never does.

```lisp
(definstruction VADD
  (unit alu)
  ...)
```

Absent, `unit` defaults to a single implicit unit, which is what every existing
document means and why they stay byte-identical.

### 4.2 `defpacket`

The construct is a **packet**, not a bundle, for one reason worth writing down:
`bundle` already names the emitted artifact *directory* throughout this
repository (`emit-bundle`, `bundle_manifest.json`, PCE's
`load_adl_bundle_dir`). Two meanings of one word, in the same manifests and the
same gate names, is the "two answers to one question" shape that
`docs/wide_execution.md` §3 identifies as the source of nearly every defect
here. C6x's *execute packet* is the established term for the group, so the
group is a packet and the artifact directory stays a bundle.

```lisp
(defpacket vliw128
  (isa lx32)
  (slots
    (s0 (width 32) (units alu mem))
    (s1 (width 32) (units alu))
    (s2 (width 32) (units alu mul))
    (s3 (width 32) (units br)))
  (order little)                 ; syllable 0 at the lowest address
  (end fixed)                    ; or (end stop-bit (field 31))
  (hazards interlocked)          ; or `exposed`, see B3
  (branches at-most-one)
  (description "Four-slot packet, one branch unit"))
```

`(end fixed)` is a fixed-width packet (every fetch is four syllables). `(end
stop-bit (field 31))` is the C6x/Itanium shape: a bit in each syllable says
whether the group continues, so a packet is variable-length in syllables while
every syllable stays 32 bits. Both are decidable at decode; nothing else is
offered in v1.

An instruction may occupy slot *k* iff its `unit` is in slot *k*'s `units`. No
instruction names a slot.

### 4.3 `deffabric` (stage G1)

```lisp
(deffabric cgra4x4
  (rows 4) (cols 4)
  (pe (units alu mul) (regs 2) (const 1))
  (links (north 1) (south 1) (east 1) (west 1))
  (memory-ports (row 0 scratchpad) (row 3 scratchpad))
  (ii-max 16)
  (description "Nearest-neighbour 4x4 fabric with two memory rows"))
```

`links` declares a neighbour pattern with a latency in cycles; an explicit
`(link (0 0) (2 3) (latency 2))` form covers irregular topologies and buses. A
PE's `units` reuse §4.1's classes exactly, so an operation legal on a VLIW
`alu` slot is legal on an `alu` PE with no second declaration and no second
semantics.

### 4.4 `defmapping` (stage G2)

The configuration — a CGRA's program — is a placement and a routing:

```lisp
(defmapping dotprod-on-cgra4x4
  (fabric cgra4x4)
  (ii 2)
  (place (op0 VMUL (pe 1 1) (cycle 0))
         (op1 VADD (pe 1 2) (cycle 1)))
  (route (op0 -> op1 (via (1 1) east (1 2)) (cycle 0)))
  (equivalent-to dotprod-scalar))
```

`equivalent-to` names an ordinary instruction sequence with the same meaning.
That field is the whole point of the construct and the subject of the G3 gate:
a mapping is only worth describing if something can say it is *right*.

## 5. Validation

Packets (`src/validate.rs`, `src/layout.rs`):

- Every slot's `units` name declared unit classes; widths are ≤ 32 and the
  container is their sum (fixed) or a multiple of the syllable width
  (stop-bit).
- Every instruction's `unit` is occupiable by at least one slot, or it is
  undecodable and that is an error, not a warning.
- `at-most-one` branch: no **two slots** may each hold something that writes
  `pc`, read off the **behavior** rather than off a category name — the effect
  model already knows which instructions transfer control (`Loc::Pc`). The
  check is on slots and not on one packet's contents, because the contents vary
  at run time and the slots do not: if two slots can each branch, some legal
  packet branches twice. A guarded branch counts, since a conditional branch
  still occupies the port.
- **Static write-conflict**: if two slots can each hold something that writes
  one *fixed* location — an implicit register, a named state slot — with no
  guard, that is a validation error. Only unconditional writes: a guarded pair
  under exclusive predicates is a machine, not a mistake. The
  operand-dependent case (`rd` in two slots) cannot be decided here at all, and
  is B2's execution-time diagnosis.

Decode disjointness generalizes rather than forks.
`validate_decode_space_disjointness` (`src/validate.rs`) is already a
conjunction of independent contention tests — same encoding space, intersecting
mode sets, not lanes of one scalable origin, not proven disjoint by decode
constraints. Slots add **one more conjunct**: two instructions contend only if
some slot can hold both. A machine that gives its multiplier slot its own
opcode space then legally reuses an encoding the ALU slot also uses, and the
validator says so instead of rejecting it.

Fabrics and mappings:

- Every placed operation's `unit` is in its PE's `units`; every cycle is `<
  ii`; every route's endpoints are the producer's and consumer's PEs and its
  path follows declared links.
- **Modulo resource legality**: no two operations occupy one PE at the same
  `cycle mod ii`, and no two routes occupy one link at the same `cycle mod ii`.
  This is the entire legality condition of a modulo schedule and it is cheap to
  check *given* a mapping.
- Route latency is consistent: a consumer at cycle *c* is fed by a producer
  at cycle *c − Σ(link latencies) − (producer latency)*, modulo `ii`.

**AXIS checks a mapping; it does not compute one.** Placement and routing are a
compiler's search problem (OptiSynth's, a CGRA mapper's). The boundary is the
same one §9 of `personality_design.md` draws: AXIS judges the spec, the
consumer judges the silicon, and neither self-certifies the other's claim.

## 6. Semantics: read once, commit once

A packet's meaning is the concatenation of its syllables' effect lists in slot
order, **every expression evaluated against the pre-packet state**, with all
writes committed at the end.

Four consequences, each of which has to be said out loud because each is a
place a naive implementation silently does the other thing:

- A read-after-write between slots reads the **old** value. `add r1,r2,r3 ||
  add r4,r1,r5` reads the pre-packet `r1`.
- Two writes to one location in one packet is a **conflict**, reported, never
  last-slot-wins. A machine that genuinely resolves it declares how; v1 has no
  such declaration and therefore no such machine.
- `next_pc` is `pc + packet_bytes`. `ILEN` stays what it always was — the
  syllable's size in bytes — and the *step* becomes the decoded group's byte
  length, `ILEN × syllables`, published as `packet_bytes()`. A document with no
  `defpacket` never reaches that path and steps by `ILEN`, which is why every
  existing corpus is untouched.
- A **trap** in any syllable commits nothing either: a packet retires whole or
  not at all, and the first trap in slot order is the one reported. The
  alternative — letting the non-trapping slots land — would make the
  architectural state after a fault depend on which slot faulted, which is the
  imprecise-exception behaviour no description should imply by default.

Memory is the same rule: two stores to one address in one packet conflict; a
load in one slot does not see a store in another.

This costs the effect model nothing. Each instruction already yields an ordered
list of guarded effects with a bounded write count (`EFFECT_MAX_WRITES`,
`src/effects.rs`), and the executor already unions the writes of a *group* —
that is precisely how a scalable instruction's lanes execute today (`step` in
the emitted executor: one word decoding to a group whose writes are the union).
A packet is that path with a different grouping rule and a snapshot read, and
it inherits the group machinery already in place.

## 7. Exposed latency (stage B3)

`(hazards exposed)` is what makes a VLIW core a VLIW core: no interlock, a
result visible *N* packets later, the schedule responsible for the gap.

An instruction's existing `latency-cycles` field becomes architecturally
meaningful under `exposed`: the write commits `latency-cycles` packets after
issue, and a read in the shadow gets the old value. Under `interlocked` — the
default and every existing document — `latency-cycles` remains cost metadata,
exactly as the URV dispatch consumer reads it today.

The consequence worth flagging early, because it reaches another subsystem: an
exposed-latency machine's architectural state **includes its in-flight
writes**. A capsule that omits them (`docs/personality_design.md` §8 stage P1)
cannot restore a mid-shadow checkpoint, so migration of such a personality
would be unsound. The capsule layout therefore gains a `__delay` section under
`exposed`, which changes the layout hash — so the manifest cannot call an
exposed personality migratable with an interlocked one.

Two boundaries this draws, both narrower than "exposed latency" sounds:

- **Only register writes wait.** Stores, state writes and control transfers
  commit with the packet. A load's delayed *result* is the classic case and is
  covered; a branch's delay slots are a second mechanism and a non-goal (§10).
- **A latency of 1 is not a shadow.** It is visible to the next packet, which
  is what an interlocked machine does — so an exposed machine whose every
  latency is 1 emits no queue and has the same capsule. The same behaviour
  described two ways, and the hash says so by being equal.

## 8. Emitted artifacts and gates

Each stage's gate is named by what it can catch, not by what it runs.

- **`packet_manifest.json`** (`axis.issue-packet.v1`): slots, widths, unit
  sets, order, end rule, hazard discipline, and per instruction the slot mask
  it may occupy. Every fact derived from the same layout resolution as
  `emit-json`, so the packetizer's table cannot drift from the decoder's.
- **`tools/packet_roundtrip.py`** (B1): pack a legal group into a packet,
  decode it back, require the multiset of (mnemonic, operands) to match; and
  require every randomly generated container to be either rejected or decoded
  into a slot-legal group. Coverage reported per `docs/gate_coverage.md`'s rule
  — report which slots and unit classes a run packed, **fail** when a slot
  class never appeared.
- **`tools/packet_vs_serial.py`** (B2): the gate that makes parallel
  semantics real, in two halves. For a packet whose syllables have disjoint
  read/write sets — computed from the behaviors, not asserted — the packet
  result must equal serial execution in any order. For a packet with a
  slot-crossing RAW, the packet result must equal the snapshot execution **and
  differ** from the serial one. Without the second half the gate passes on an
  implementation that quietly executes syllables in sequence, which is the
  failure mode.
- **`tools/exposed_latency_check.py`** (B3): emits the description twice, once
  per hazard discipline, and compares the two machines — so "exposed differs
  from interlocked" is measured rather than claimed, and a run where they
  agreed fails as vacuous. Both edges of the shadow are required: a result is
  invisible for L-1 packets and visible on the L-th, the second half being what
  catches a queue that accepts writes and never lands them. It also checkpoints
  at every packet boundary, serializes the `__delay` section per the manifest's
  own field offsets, migrates between two personalities and finishes — then
  does it again with that section zeroed, which must **differ**, or the section
  is not load-bearing and the round-trip proved nothing about it. This is the
  mid-shadow migration proof; `migrate_vs_whole.py` keeps its own corpus, which
  has no packets and a single-instruction runner, rather than being forked into
  two gates in one file.
- **`packet_schedule_manifest.json`** + `emit-vliw-itinerary` (B4): the
  resource table an LLVM `SchedMachineModel`/`DFAPacketizer` consumes, emitted
  from the same slot/unit resolution. **`tools/itinerary_vs_packet.py`**: every
  packet the itinerary calls legal must validate, and every packet the
  validator accepts must be schedulable under the itinerary — two derivations
  of one fact, which is the shape of nearly every defect this repository has
  found.
- **`fabric_manifest.json`** (G1) and **`mapping_manifest.json`** (G2): the
  PE grid, unit sets, link graph with latencies; the placement, routes, and II,
  with the modulo occupancy tables the validator computed, published rather
  than re-derived.
- **`tools/fabric_vs_scalar.py`** (G3): the one that matters. Run the mapping
  as a cycle-by-cycle dataflow over the fabric, run its `equivalent-to` scalar
  sequence through the existing executor, and require identical results over
  random inputs — for every II the mapping declares, and across the modulo
  wrap, where a mapping that ignores a cross-iteration dependence stops being
  equal. Both sides evaluate the *same* per-operation semantics, so what the
  gate tests is the placement, the routing and the timing, which is exactly
  what is new.

- **`tools/exec_vs_golden.py`, `tools/exec_wide_check.py`** on
  `examples/cgra_fabric.axisl` (A6): the launch that reads the shared register
  file, executed — by the golden model, the Python executor and the two wide
  executors, which have to agree about a read no fixture's operands mention.
  What makes this a gate rather than a ceremony is the seeding: a register the
  description names and no operand selects is not in the drivers' random file,
  so before they seeded `reads_registers` both sides read an unseeded slot and
  agreed on zero. Injection-checked by reading the neighbouring register in
  each executor, which all three drivers catch.

Registration in `tools/check_all.py` follows the existing convention, and the
`AFFECTS` map gains the new tools; a change to the packet layer that cannot be
described there selects everything, as it should.

## 9. Staging

- **B1 — slots, units, packet decode.** _Done._ `(unit ...)` on instructions
  and `defpacket` in the Lisp frontend (`src/lisp.rs`), validated in
  `src/validate.rs`: slot widths inside the 32-bit syllable, units held by some
  slot, a stop bit inside the narrowest slot, and `exposed` refused as the
  discipline stage B3 implements. `validate_decode_space_disjointness` gained
  one conjunct — `slot_sets_intersect` — so two instructions contend only if
  some slot holds both, and a document with no packet computes the same answer
  it did before. `emit-packet-json` / bundle `packet_manifest.json`
  (`axis.issue-packet.v1`, `src/emit/packet.rs`) publishes each slot's width,
  bit offset and unit set alongside every issuable instruction's
  `match`/`mask`, which is the one table a packetizer and a decoder both read.
  The Python lifter carries `AXIS_PACKETS`, `decode_slot` and `decode_packet`,
  and `axis_exec` grows `step_packet` — which executes syllables **serially**,
  mutating the register file as it goes. That is wrong, says so in its
  docstring, and is wrong on purpose: B2 lands the snapshot semantics, and a
  placeholder that guessed right would leave `packet_vs_serial.py` unable to
  show it changed anything. Proven by `tools/packet_roundtrip.py` on
  `examples/vliw_packet.axisl`: every slot assignment packs and decodes back to
  the same slots, mnemonics and operand values; VSTW and VBRZ share one word
  that plain `decode` reports as ambiguous and each slot resolves to its own
  instruction; perturbed containers are rejected or decode slot-legally, with
  both outcomes required; and a slot or unit class no syllable reached fails
  the run. Injection-checked: making a slot ignore its unit set, or shifting
  syllables one slot over, each fails it.
- **B2 — group semantics.** _Done._ `step_packet` in the emitted executor now
  evaluates every syllable against the state the packet started with — a
  private `_PacketState` view of the register file and of architectural state,
  and a `_PacketMemory` whose reads reach the real memory and whose writes are
  buffered — and applies the writes in slot order. A read-after-write between
  slots reads the old value; a load does not see a sibling's store. Two
  syllables writing one register, one state slot, one memory byte, or `pc` is
  reported in `conflicts` and commits **nothing**, and so is a trap: a packet
  retires whole or not at all. `next_pc` steps by the decoded group's byte
  length (`packet_bytes()`); `ILEN` stays the syllable size. `register_writes`
  is keyed by the flat register slot rather than by operand name the way `step`
  reports, because two syllables both writing their `rd` are one key under the
  old convention and two registers under the new one, and only the second can
  answer whether they collided. `step_syllable` executes one syllable against
  an entry decode has already chosen, and `place_operand` — the inverse of
  `_extract`, in the lifter next to it — lets a caller build syllables over
  registers it picks. Validation gained the two structural hazards of §5: two
  slots that can both branch under `at_most_one`, and two slots that can both
  write one fixed location unconditionally. Proven by
  `tools/packet_vs_serial.py`, whose oracle is the definition rather than a
  second copy of the executor: **run each syllable alone against the pre-packet
  state and merge**, computed through the ordinary single-instruction path. Six
  classes, all required to appear: independent packets agree with serial
  execution in every order; a slot-crossing RAW and a load-against-store must
  **differ** from serial, and a case where they came out equal fails as vacuous
  rather than passing; a register conflict and a memory conflict must be
  refused while serial execution of the same syllables produces a value.
  Injection-checked five ways — seeding each syllable from the running merged
  state, writing memory through eagerly, committing a conflicting packet,
  stepping `pc` by `ILEN`, and the B1 placeholder itself — each fails the class
  it should.
- **B3 — exposed latency.** _Done._ `hazards exposed` is accepted, and
  `latency-cycles` stops being cost metadata: a register write with latency L
  becomes visible to the packet issued L packets later. The queue that holds it
  is `delayed`, passed by the caller alongside the register file because it
  *is* architectural state; `new_delay_queue()` makes one, and stepping an
  exposed packet without one raises rather than quietly running an interlocked
  machine under the other name. A write that has finished waiting lands with
  the issuing packet's writes and collides with them the same way, since two
  results arriving at one register in one boundary is a schedule the machine
  cannot honour whichever packet issued them. `validate::packet_delay_queue`
  derives the queue's shape once — `stages = max_latency - 1`, and
  `entries_per_stage` summed per slot rather than the widest times the slot
  count — and the packet manifest, the executor's packet table and the capsule
  all read that one derivation. The capsule gains a `__delay` entry sized from
  it, whose 16-byte format (valid, location, value) the manifest publishes
  field by field; because it is an ordinary capsule entry the canonical layout
  string and therefore the hash cover it with no change to either, and a
  packet-free document's capsule stays byte-identical. Two guards keep the
  queue finite and representable: a latency above 32, and a register wider than
  the 64-bit pending-value field, are both refused with the reason. Proven by
  `tools/exposed_latency_check.py` (§8), injection-checked four ways — treating
  every latency as 1, never landing what is due, scheduling one stage early,
  and dropping the capsule's delay section — each failing the half it should.
- **B4 — the schedule as an artifact.** _Done._ `emit-vliw-itinerary` /
  bundle `packet_schedule_manifest.json` (`axis.vliw-itinerary.v1`,
  `src/emit/packet.rs`) publishes the functional units with the slots that hold
  each, and per issuable instruction its unit, latency, whether it transfers
  control, and the **slot mask** it may occupy. The mask is the load-bearing
  field: whether a group can issue together is not "are there enough slots" but
  whether the instructions can be matched to distinct slots each of which holds
  that instruction's unit, so per-unit counts would call two `mul`s legal on a
  machine with three ALUs and one multiplier. Emitted from the same slot and
  unit resolution as `packet_manifest.json`, so the scheduler's table and the
  decoder's cannot drift.
  `tools/itinerary_vs_packet.py` decides every group both ways and requires
  agreement in both directions: sound (what the itinerary calls schedulable
  really packs and decodes back) and complete (what packs is called
  schedulable) -- a permissive table emits packets the machine rejects, a
  strict one silently costs issue width and no correctness test would notice.
  It also requires the corpus to *distinguish* slot matching from per-unit
  counting, failing as vacuous if no group does, since counting is the
  plausible-but-wrong implementation this exists to reject. Injection-checked
  both ways: a mask widened to every slot and a mask with one slot dropped each
  fail it.
  There is deliberately no per-group branch check. `at_most_one` is enforced
  statically -- `validate` rejects a packet whose declaration lets two slots
  transfer control -- so every branch contends for one slot and matching
  already refuses two. Emitting `branches: false` for every instruction leaves
  the gate passing, which is what says the check would have been dead; the
  field stays in the manifest because a scheduler needs to know a terminator.
- **G1 — fabric declaration.** _Done._ `deffabric` in the Lisp frontend, with
  compass patterns (`(links (north 1) ...)`) and the explicit
  `(link (0 0) (2 3) (latency 2))` for irregular topologies, both resolving to
  one edge list so nothing downstream has to know which spelling produced an
  edge. A pattern is an edge for every PE whose neighbour is on the grid, which
  is what makes a mesh a mesh: a torus would be a different pattern name, not a
  flag. `validate_fabrics` (`src/validate.rs`) checks the declaration and only
  the declaration — grid non-empty, PE units issued by some instruction,
  `ii-max` at least 1, link endpoints on the grid, no self-link, latency
  between 1 and `ii-max`, memory ports on real rows naming declared memories,
  and no PE left untouched by any link. Each is injection-checked.
  `emit-fabric-json` / bundle `fabric_manifest.json` (`axis.fabric.v1`,
  `src/emit/fabric.rs`) publishes the grid, the unit classes, the instructions
  a PE can issue, the memory ports, and the **expanded** link graph.
  `tools/fabric_topology_check.py` re-derives that expansion from rows, columns
  and direction alone and requires it to match, since a mapper that expanded
  the pattern itself would be a second derivation of the grid and the two would
  disagree at the boundary. The boundary is the whole difficulty, so a corpus
  where every PE has the same number of pattern edges fails as vacuous.
  Injection-checked: reversing `north` fails it, and wrapping like a torus is
  refused by validation before the gate sees it.
  `examples/cgra_fabric.axisl` declares a 4x4 mesh with two memory rows and a
  2x2 carrying one explicit diagonal, over instructions whose `unit` classes a
  packet slot would name identically.
- **G2 — mappings and modulo legality.** _Done._ `defmapping` in the Lisp
  frontend: a fabric, an initiation interval, a placement, routes, and the
  scalar order the mapping claims to compute. `validate_mappings`
  (`src/validate.rs`) checks the thirteen rules of §5 — fabric and instructions
  known, `ii` within the fabric's `ii-max`, every operation on the grid and on
  a PE holding its unit, no two operations on one PE at the same `cycle mod
  ii`, route endpoints the operations they join, every hop a declared link, no
  two routes across one link at one residue, latency consistent (a consumer's
  cycle is the producer's plus the producer's latency plus the time in flight,
  modulo `ii`), and a scalar order that accounts for every placed operation and
  invents none. Each is injection-checked.
  Routes name **positions only**, where §4.4 sketched positions interleaved
  with direction names: the direction between two given PEs is a fact about the
  fabric's links, so writing it again here would be a second derivation of the
  topology that could disagree with the first.
  `emit-mapping-json` / bundle `mapping_manifest.json` (`axis.mapping.v1`,
  `src/emit/mapping.rs`) publishes the placement, the routes, the II and the
  **modulo occupancy tables the validator decided legality on**, so a mapper
  reading it does not have to trust its own `cycle mod ii` to agree with the
  checker that accepted its output. `tools/mapping_legality_check.py`
  re-derives those tables from the placement, the routes and the fabric's link
  latencies, requires them to match, and re-checks the legality condition on
  what it derived. A corpus whose cycles are all below its II fails as vacuous,
  since the wrap never happens and `cycle mod ii` is `cycle`.
  Injection-checked three ways: publishing PE occupancy unwrapped, and link
  occupancy that ignores time in flight, each fail — the second only after the
  corpus gained a **two-hop** route, since with one hop the flight term is
  always zero and the injection was invisible.
- **G3 — fabric execution.** _Done._ `tools/fabric_vs_scalar.py` runs a
  mapping as a cycle-by-cycle dataflow over its fabric and its
  `equivalent-to` sequence straight through, over random inputs, and requires
  them to agree. Both sides evaluate the *same* per-operation semantics out of
  the golden model, so what is under test is the placement, the routing and
  the timing — the arithmetic is proven elsewhere, several ways.
  A route now says which operand it feeds (`(operand rs1)`), required rather
  than inferred: an operation with two inputs and one route has one routed
  operand and one free one, and a default that picked the first unrouted one
  would be right for the commutative cases and silently wrong for the rest.
  The interpreter models a PE's output as a **timeline**, not a slot. Once
  iterations overlap, a route entering a link at cycle *C* picks up whatever
  its source PE most recently finished at or before *C* — this iteration's
  value or the previous one's, decided entirely by the schedule. A slot per PE
  reports every pipelined schedule as broken (it was the first thing tried,
  and it did); a timeline is what can catch a mapping whose timing silently
  reads the wrong iteration.
  A route also says how many iterations back its value comes from
  (`(distance 1)`), which is what a software-pipelined loop *is*: a value
  produced late in one iteration and consumed early in the next. Without it the
  only expressible mappings are those whose dataflow fits inside one iteration,
  and the design's own claim about the modulo wrap could not be exercised.
  Stating it also makes the latency check **exact** rather than modular —
  `producer + latency + flight == consumer + distance * ii` closes on absolute
  cycles, where the same statement modulo `ii` cannot tell one iteration's
  value from another's and accepts a mapping that silently reads the wrong one.
  Both directions are injection-checked: a cross-iteration route declared
  `distance 0`, and a same-iteration route declared `distance 1`, each fail.
  Four guards. A corpus where no schedule outlives its II fails as vacuous —
  iterations never overlap and a pipelined machine is indistinguishable from a
  serial one. A corpus where no route crosses an iteration fails too, since it
  cannot tell a software-pipelined schedule from one that fits in a single
  iteration. Prologue iterations, where a consumer runs before its producer
  ever has, are excluded from the comparison rather than fudged. And it is
  injection-checked on the error the stage exists for: indexing a route by the
  *consumer's* iteration reads a value that has not been sent yet — which for
  a same-iteration route coincides with the right answer, so only the
  pipelined mapping catches it. It was the bug the first implementation had.
- **G4a — multi-context fabrics.** _Done._ `deffabric` gains `(contexts N)`,
  the number of configurations a PE holds, defaulting to 1. This is less a new
  feature than the constraint G1/G2 was missing: the modulo rule permits a PE
  to host one operation per residue, and nothing required the hardware to be
  able to hold them, so a mapping needing sixteen configurations on a
  single-context machine validated. `validate_mappings` now requires a PE's
  operation count to fit its fabric's contexts, `mapping_manifest.json`
  publishes the count per PE beside the occupancy tables, and
  `mapping_legality_check.py` re-derives it — failing as vacuous if no PE in
  the corpus holds more than one, since that cannot tell a multi-context fabric
  from a single-context one. Injection-checked three ways: a fabric with too
  few contexts, `contexts 0`, and a manifest publishing the wrong count.
- **G4b.2 — latency-insensitivity.** _Done._ The obligation an elastic route
  carries in place of a fixed schedule, and the classic correctness condition
  for elastic circuits: **the result does not depend on the timing.** G3 fixes
  the timing and compares against the scalar sequence;
  `tools/elastic_vs_scalar.py` varies it -- every token on every channel draws
  its own delay from that channel's window -- and requires the same answer. It
  shares G3's scalar reference rather than reimplementing one, because a
  timing-free oracle is exactly what an elastic mapping must agree with.

  What can fail is what `(order …)` promises. A preserving channel hands its
  tokens on in the order they entered however long each takes, so the pairing a
  consumer sees is delay-independent. Declare the ring's back edge `unordered`
  and a later token may overtake an earlier one, the accumulator reads a
  different iteration's value, and the gate says so. A run whose draws never
  differed, or a corpus with no elastic mapping, fails as vacuous.

  The stage needed one thing the language did not have. A ring with an empty
  buffer never fires: every operation on the cycle waits for a value only the
  cycle produces. Real hardware primes it, so `(initial <value>)` says what the
  buffer starts holding, and an initial token with no capacity to sit in is
  refused. Without it the first version of this gate passed by comparing two
  empty results -- which is the failure the vacuity guards exist for, found in
  the gate's own first run rather than in a corpus later.

- **G4b.3 — seams, which is P5.** _Done._ A personality lends a functional unit
  across a boundary and another borrows it:
  `(exports (mul-pipe (unit mul) (channel mul-result-bus)))` on one,
  `(imports (mul-pipe (from lane1) (channel mul-borrow-bus)))` on the other.
  The two sides name the same seam and deliberately not the same channel — the
  producer states what it promises, the consumer states what it can take, and
  `tools/seam_contract_check.py` decides whether those compose: one protocol,
  the importer's latency window containing the exporter's, and order composing
  downward, since a consumer cannot promise an order its producer never gave
  it. A shared channel would have made all three true by construction.

  The gate joins two artifacts rather than reading one. Seam sides come from
  `state_capsule.json`, channel contracts from `mapping_manifest.json`, and a
  manifest publishing a seam over a channel the other never declares is exactly
  the drift a single file hides. The exported unit must be a name some packet
  slot or fabric row holds — a machine cannot lend a multiplier it does not
  have — which is why the seam corpus is `vliw_exposed.axisl`, where the
  personalities and the units are both already declared.

- **A6 — the kernel reads the file.** _Done._ `(getreg <class> <index>)` in a
  behavior, the counterpart of `setreg`: the read an input operand already
  performs, with the index fixed by the description instead of selected by
  decode. A4 recorded why a launch took its live-ins in operands — semantics
  could write a fixed register and could not read one — and that made every
  kernel's live-in a value the launch handed over, which is a different machine
  from an ADRES mode switch, whose array reads the shared file itself.

  So a launch may now supply a live-in register either way, and validation
  composes the kernel with each register's actual source in place. Four rules,
  each rejected with the reason: reading a register the kernel does not read,
  leaving a register the launch neither reads nor takes in an operand, a launch
  behavior that is not one unguarded write to its output, and the composition
  itself — swapping the two registers the multiply reads is rejected, which is
  what makes two distinct live-ins worth having in the corpus.

  `examples/cgra_fabric.axisl` gains `CGRA_ENTER`, a launch with **no input
  operands at all**, beside the operand-supplied `CGRA_LAUNCH` it already had.
  The two mappings differ in exactly one thing: where the kernel's values come
  from.

  A register read is a leaf the pure IR has no node for, so it becomes a symbol
  before lowering — the move `(input x)` already makes — which means the read
  itself is checked in the effect validator or nowhere. The first
  implementation checked it only where the read *was* the whole expression, so
  a class `setreg` refuses passed one level down inside a multiply; the class
  test is what caught that.

  Executed, not just emitted: the golden model, the Python executor and both
  wide executors run it and agree, on a corpus whose registers the drivers now
  seed from the lift table's new `reads_registers`. The compact C and Rust ABIs
  decline the instruction — their effect lowering goes through the pure IR —
  so `exec_wide_check.py`'s "narrow, so the compact check has it" skip had to
  learn the exception, or the read would have been executed by no compiled
  backend at all. Asking why that skip was wrong here turned out to be worth
  more than the exception itself: it was wrong for architectural state too, and
  `docs/wide_execution.md` §8b carries what lifting it found.

- **A5 — mode exclusivity.** _Done._ A2 said the shared row "is why the two
  modes are exclusive". That was prose about the architecture, and nothing made
  a description violating it impossible: a corpus could declare the seam and run
  both halves in one mode, which is a machine using each functional unit twice.

  `(mode <value>)` on a packet and on a fabric. When the two share a row both
  must name one and the names must differ -- both, because an unnamed mode means
  *every* mode, which is exactly the machine that cannot exist. A launch must
  also be legal in the packet's mode: the array is entered, not entered from, so
  an instruction legal only inside it could never issue. Five ways to violate
  this are rejected with the reason, and the corpus was rejected the moment the
  rule landed, which is how I know it was not already true by accident.

  Both manifests publish their mode, because a scheduler reading one of them
  would not otherwise know the other exists.

- **A4 — the launch.** _Done._ `(runs-mapping <name>)` on an instruction says it
  enters the array with that schedule. Its input operands supply the registers
  the kernel reads -- one operand per *distinct* register, since one register
  feeding two operands is one input -- and its output receives the live-out.

  What makes this a stage rather than an annotation: validation composes the
  mapping's scalar order and requires the instruction's own semantics to equal
  it. The multiply's product is substituted into the add's routed operand, the
  add's other operand is the PE constant, and the register reads become the
  launch's operand. Compared as lowered IR rather than text, so two spellings of
  one expression agree and a swapped operand does not -- routing the product to
  the other operand is rejected even though the operator is commutative.

  Three obligations meet at the same sequence and none sees the other's
  evidence: the executor gates prove `CGRA_LAUNCH` against the golden model,
  `fabric_vs_scalar` proves the mapping computes its scalar order over the
  fabric, and this proves the two are talking about one computation. Changing
  the instruction's arithmetic, the kernel's constant, or which operand the
  product feeds is rejected with what disagreed.

  The launch takes its live-ins in operands because semantics can *write* a
  fixed register -- `setreg` -- and cannot read one. A kernel reading the shared
  file directly, as an ADRES mode switch does, needs a `getreg` this language
  does not have; that is the next stage, not a thing quietly assumed here. A6
  is that stage, and both forms are now legal: this one, and the launch that
  reads its live-ins itself.

- **A3 — live-in and live-out.** _Done._ `(live-in (op operand (reg N)))` or
  `(const V)`, and `(live-out (op (reg N)))`. Without them a mapping is a
  dataflow with inputs from nowhere: G3 hands every unrouted operand an
  anonymous random number, which proves the placement and the timing and says
  nothing about what the kernel reads out of the machine. Naming the register --
  or the PE's constant register, which a CGRA uses as much -- is what makes the
  kernel a state transformation, and it is the prerequisite for A4, where a
  mode-switch instruction's behavior is the mapping's scalar sequence.

  Six rules, each rejected with the reason: a live-in to an operation the
  mapping does not place, to something that is not an input, to an operand a
  route already feeds, twice to one operand, a constant on a PE with no constant
  register, and two results left in one register. The seventh is completeness --
  a mapping that names any source names them all -- stated that way rather than
  unconditionally so a mapping proven as a dataflow stays legal.

  What this does *not* add is a new dynamic check. Both sides of G3 read the
  same values, so drawing them as the machine would supply them makes the inputs
  faithful rather than the comparison sharper; the falsifiable content of the
  stage is the six static rules and the boundary the manifest now publishes.

- **A2 — the shared row.** _Done._ `(vliw-row <row> <packet>)` on a fabric says
  that row's PEs *are* that packet's slots. This is the defining relation of an
  ADRES-like machine -- the VLIW's functional units are the array's first row,
  not a copy of it, which is why the two modes are exclusive and why a value
  crosses between them through the register file rather than being transferred.
  Declaring it makes the correspondence checkable: as many columns as slots, the
  packet must exist, the row must be on the grid, and the fabric must not also
  describe that row, since the slots already do.

  It also makes the shared row heterogeneous *across its columns*, which no `pe`
  clause can express: a VLIW row is one multiplier and three plain slots, not
  four identical PEs. So the placement check resolves per PE rather than per
  row, and `madd-on-adres` is pinned to PE (0, 0) -- the only slot with a
  multiplier -- rather than to row 0. `examples/cgra_fabric.axisl` is the first
  corpus holding both a `defpacket` and a `deffabric`; the manifest publishes
  the seam and names which slot each PE of the shared row is.

- **A1 — heterogeneous PEs.** _Done._ A `pe` clause naming rows describes those
  rows and one naming none is the fabric's default, so a uniform grid is written
  and read exactly as before. The canonical CGRA is not uniform: an ADRES-style
  machine's first row *is* its VLIW's functional units and the rows below hold
  plain ALUs, which is why a kernel's multiplies have to land on row 0. Until a
  row could differ, the placement check asked whether an operation's unit was on
  its PE and could not fail -- every PE held every unit the fabric named.
  `examples/cgra_fabric.axisl` carries `adres4x4` and a mapping onto it; moving
  its multiply one row down is rejected, and the identical move on the uniform
  `cgra4x4` validates. The fabric manifest gains `rows_detail` -- per-row units,
  registers, constants and issuable instructions -- emitted only when the rows
  differ, because a mapper reading the fabric-wide list alone would place a
  multiply on a row of ALUs.

- **G4b.1 — the channel, and deadlock.** _Done._ `(defchannel <name> (protocol
  ready-valid) (latency <min> <max>) (capacity N) (order preserving))`, and a
  route that names one. G4's reservation was not one design — its four items
  split by which invariant each breaks, and only the handshakes break §10's
  static-arrival rule, which is why an elastic route is **exempt** from modulo
  legality rather than checked more loosely: bolting a latency window onto
  residue arithmetic would produce a check that means neither thing. It states
  no cycle, takes no residue in the occupancy table, and `fabric_vs_scalar`
  leaves it alone and says so, because what that gate proves has no content
  when arrival is a window.

  The obligation it carries instead has a decidable half, and this stage is
  that half: a cycle of channels with no buffering cannot move a token. The
  validator decides it and names the ring; `elastic_deadlock_check.py`
  re-derives it from the manifest and fails as vacuous on a corpus with no
  cyclic elastic path, since an acyclic graph cannot deadlock. Injection: take
  the buffer out of `examples/cgra_fabric.axisl`'s accumulator ring, or leave an
  elastic route holding a residue, and both fail.

  P5 (seam contracts) remains in
  [`docs/elastic_seams_design.md`](elastic_seams_design.md).
  What changed to make any of this worth building is recorded in its §7: the
  search that found "no consumer" was scoped to this repository, and the
  consumer is hardware — `backpressure` appears in 310 files of `pce/hardware`
  and `credit` in 151, with XNN-MT's frozen contract naming `result_credit` as
  an eligibility input.
- **Tagged-token dynamic dataflow: rejected**, with the reason recorded in that
  document's §6, rather than reserved indefinitely.
- **Partial reconfiguration: deferred**, same place. G4a covers the case that
  motivated it in practice.

## 10. Non-goals

- Widening the encoding core past 32 bits (§3); syllables that span slot
  boundaries.
- Computing a schedule, a placement or a routing. AXIS checks the one it is
  given.
- Predicated execution as a packet concept — it is already an effect guard,
  and a predicated syllable is an ordinary guarded write.
- Branch delay slots. Exposed *result* latency and exposed *control* latency
  are two mechanisms, and B3 implements the first: a control transfer commits
  with its packet.
- Speculative or dismissible loads, rotating register files, and hardware
  loop buffers. Each is a real VLIW feature and each is its own design.
- Dynamic dataflow, token matching, and anything where a value's arrival time
  is not a static function of the schedule.

## 11. Invariants

- A document with no `unit`, `defpacket`, `deffabric` or `defmapping`
  produces **byte-identical artifact content** at every stage: every manifest,
  table, header and backend file is unchanged, and no packet manifest is
  written at all. What does change is the shared generated runtime, which gains
  the packet functions and an empty `AXIS_PACKETS = {}` — a table that is empty
  rather than absent, so a consumer reads a fact instead of inferring one from
  a `NameError`. That is measured by diffing a full `emit-bundle`, not
  asserted. The single-issue world is the degenerate case of the group model,
  not a special case in it.
- One semantics per operation. A syllable in a packet, the same instruction
  issued alone, and the same operation placed on a PE all mean what the
  instruction's behavior says. A group decides *when* something happens and
  never *what*.
- A conflict is reported, never resolved. Two writes to one location in one
  group, two values on one link in one cycle, two operations on one PE at one
  cycle mod II — each is an error with a name, because every silent resolution
  rule is a place where a description and a machine can disagree forever.
- Every resource fact in a manifest derives from the resolution the validator
  used. The packetizer's table and the decoder's table are one table.
- Timing is described, not measured. AXIS says what the schedule must
  satisfy; whether silicon meets it is the consumer's rung, and neither side
  self-certifies the other's claim.
