# Elastic channels and seam contracts (G4b / P5)

Status: **3 stages implemented** (G4b.1, the channel and deadlock; G4b.2,
latency-insensitivity; G4b.3, seam contracts, which is P5). The
corpora contain 4 `defchannel` declarations and 1 bound seam, which is how this
line stopped saying "design only": that channel count was checked while it was
zero (`tools/doc_facts_check.py`), so the day it moved, this document,
`vliw_spatial_design.md` §9 and `personality_design.md` §8 were told to say
something else. A claim that something does not exist is a claim a repository
can check about itself, and it is worth writing down exactly because it expires
loudly.

The design is complete. What it deliberately does not cover is in §6.

Two documents reserved the same object under two names.
`vliw_spatial_design.md` §9 reserves G4's "elastic/credit handshakes" and says
they are "the same object as `personality_design.md`'s reserved P5 seam
contracts and should land as one design, not two".
`personality_design.md` §8 reserves P5 as "exported functional units with
handshake/latency contracts for cross-personality pipeline grafting".

They are the same object. This is that design.

## 1. Why G4 was not one design

G4 as reserved names four things. They split by **which invariant each breaks**,
and the load-bearing one is `vliw_spatial_design.md` §10's:

> a value's arrival time is a static function of the schedule

Everything B3, G2 and G3 prove rests on it.

| | breaks it? | belongs with |
|---|---|---|
| multi-context fabrics | no — a bigger configuration space, same timing | G1/G2 (**done**, stage G4a) |
| partial reconfiguration | not if swap points are static | G1/G2, deferred (§6) |
| elastic/credit handshakes | **yes** — arrival depends on backpressure | this document |
| tagged-token dataflow | **yes**, and arrival *order* too | rejected (§6) |

P5's seam contract is in the third row: a handshake at a personality boundary
rather than between two PEs. That is the whole reason the two reservations
point at each other — not that seams and fabrics are related, but that both
are elastic.

## 2. What elastic makes checkable

Static timing lets AXIS prove *this schedule computes what the scalar sequence
computes* (G3). That claim has no meaning once arrival is dynamic. Its
replacement is the classic correctness condition for elastic circuits, and it
is stronger:

> **The result does not depend on the timing.**

Latency-insensitivity. It is the shape this repository already uses: G3 fixes
the timing and compares against a scalar sequence; the elastic gate **varies
the timing and requires the same answer**. A run where the delays never
actually varied fails as vacuous, the same way a corpus with no modulo wrap
fails `mapping_legality_check` today.

Elastic creates a second obligation static timing never had, and it is the one
a mapper most wants checked: **deadlock**. A cycle of channels with
insufficient buffering hangs, and that is decidable from the declaration —
cycle detection plus capacity — without executing anything.

## 3. Language surface

```lisp
(defchannel result-bus
  (protocol ready-valid)   ; the handshake, named not modelled (§4)
  (latency 1 4)            ; a window, in cycles, inclusive
  (capacity 2)             ; buffered tokens; 0 is a pure wire
  (order preserving)       ; tokens leave as they entered
  (description "..."))
```

A mapping's route names a channel instead of being statically timed:

```lisp
(route (op0 -> op1 (operand rs1) (via (1 1) (1 2)) (channel result-bus)))
```

Such a route is **exempt from modulo legality** and carries the
latency-insensitivity obligation instead. The exemption is the honest
statement that the two timing models are different; bolting a window onto the
residue arithmetic would produce a check that means neither thing.

A personality exports a unit across the same mechanism, and another imports it:

```lisp
(defpersonality lane1
  ...
  (exports (mul-pipe (unit mul) (channel mul-result-bus))))

(defpersonality lane0
  ...
  (imports (mul-pipe (from lane1) (channel mul-borrow-bus))))
```

The two sides name the same seam and **not the same channel**. That is
deliberate: the producer states what it promises, the consumer states what it
can take, and whether those compose is then a question with an answer rather
than an assumption two designers each made separately. A single shared channel
would make the three rules of §4 vacuously true by construction.

The exported unit must be one the exporting machine has — a name held by some
packet slot or fabric row. A machine cannot lend a multiplier it does not have,
and that is decidable from the declaration.

## 4. What is described and what is not

The protocol is **named, not modelled**. `ready-valid` and `credit` are
identifiers a consumer matches on; AXIS does not describe the wires, and a
gate here can never say a handshake is implemented correctly. That is the same
boundary §5 of `vliw_spatial_design.md` and §9 of `personality_design.md`
already draw: AXIS judges the spec, the consumer judges the silicon.

What AXIS can decide from the declaration alone:

- every elastic route names a declared channel;
- latency windows compose along a path — the sum of minima and the sum of
  maxima, and a consumer's acceptable window must contain what reaches it;
- `capacity` is enough that no cycle of channels can deadlock;
- an export and an import agree: same protocol, importer's window contains
  exporter's, order guarantees compose.

## 5. The gates

- **`elastic_vs_scalar.py`** — latency-insensitivity. Run the mapping many
  times with each channel's delay drawn independently from its window, and
  require identical results. Requires that the drawn delays actually differed
  across runs, or the run proves nothing and fails as vacuous. This is
  `fabric_vs_scalar.py` with the timing varied instead of fixed, and it should
  share that interpreter rather than fork it.
- **`elastic_deadlock_check.py`** — the static half. Build the channel graph,
  find cycles, and require every cycle to carry capacity. Injection: removing
  a buffer from a cycle must fail it. A corpus with no cyclic channel path
  fails as vacuous, since acyclic graphs cannot deadlock and prove nothing
  about the check.
- **`seam_contract_check.py`** — for each export/import pair, the composition
  rules of §4. It works by **joining two artifacts**: the seam sides come from
  `state_capsule.json` and the channel contracts from `mapping_manifest.json`.
  Neither file can be checked against itself, so the join is the point — a
  manifest publishing a seam over a channel the other manifest never declares
  is exactly the drift one file would hide. A corpus with no import bound to an
  export fails as vacuous, since an unimported export composes with nothing.
  Injections, all seven checked in `tests/golden.rs`: widening an exporter's
  latency window past the importer's, an unordered exporter feeding a
  preserving importer, two protocols, a unit no slot holds, an import from
  itself, an import naming no export, and an import over an undeclared channel.

## 6. Rejected and deferred, with reasons

**Tagged-token dynamic dataflow: rejected**, not reserved. It is a whole
execution model — values carry tags, arrival order is not determined, and
matching is part of the machine. The consumers this repository serves are
VLIW- and CGRA-shaped, and nothing in `pce_migration.md`'s live-consumer list
asks for it. It buys nothing checkable that latency-insensitivity does not
already buy. A permanent "reserved" on a thing nobody wants is how a language
accumulates surface it cannot remove; a stated non-goal with a reason can be
revisited by anyone who has a use for it.

**Partial reconfiguration: deferred.** It needs a notion of *time-varying
configuration*, which neither the static nor the elastic model provides, and
no consumer is asking. G4a covers the case that motivated it in practice — a
PE doing different things at different residues — which is a fixed
configuration set, not a changing one.

## 7. Why this was design-only, and what changed

Every stage before this one had a consumer. B1–B4 serve a packetizer and a
scheduler; G1–G3 serve a CGRA mapper's output. Searching the documents for
`elastic`, `handshake`, `backpressure`, `credit` or `ready-valid` found one
line — P5's own reservation. Building an elastic checker with no elastic
description to check would have repeated the mistake the `.pceadl` frontend
was: a mechanism kept alive for a consumer that was not there, costing a second
place for every new construct to be forgotten.

**That search was scoped to this repository, which was the mistake in it.** The
consumer is not an AXIS document; it is hardware. In `pce/hardware`,
`backpressure` appears in 310 files and `credit` in 151, across
`xnn_federation`, `xnn_tile`, `xnn_mt`, `vx_cache`, `rv32e`, `pce_noc`, `cores`
and `xrv`. The live frontier there — XNN-MT, tile-boundary multithreading
around the XNN federation — carries a frozen contract
(`hardware/accel_engines/xnn_mt/contract.py`) whose seven-input eligibility
surface includes `result_credit`, whose obligations include "backpressure and
clear are conserved in both directions", and whose issue path is a two-entry
stable queue feeding a sixteen-entry ordered FIFO. That is this document's
subject, hand-written in Python, being proven module by module.

So the shape settled here is what a consumer is already building against, and
the argument for waiting has expired. What it was right about is narrower and
still holds: the protocol stays a name (§4), and a gate here can never say a
handshake is implemented correctly.

## 8. Invariants this must preserve

- A document with no `defchannel` produces **byte-identical artifacts**, the
  way one with no `defpacket` or `deffabric` does today.
- A statically-timed route keeps its modulo obligation exactly. Elastic is an
  alternative for a route, never a relaxation of the existing check.
- The protocol stays a name. The moment AXIS describes handshake wires it has
  started judging silicon, which is the other side of a boundary two documents
  already draw.
- A document whose personalities lend nothing produces a **byte-identical**
  capsule manifest, for the same reason. Both invariants are asserted, not
  assumed: `tests/golden.rs` checks a channel-free document against the mapping
  manifest and a seam-free one against the capsule manifest.
