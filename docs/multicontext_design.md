# Multi-context accelerators (M1–M3)

Status: **3 stages implemented** (M1, the context file; M2, eligibility and
policy; M3, bounded service executed). The corpora declare 1
multi-context accelerator, a checked number
(`tools/doc_facts_check.py`) for the same reason the `defchannel` count is one
in [`elastic_seams_design.md`](elastic_seams_design.md): the gate below fails as
vacuous without one, and a corpus can lose it while this header goes on claiming
the check runs. The design is complete; §6 is what it deliberately leaves out.

## 1. The consumer wrote this by hand, in Python

`pce/hardware/accel_engines/xnn_mt/contract.py` is 209 lines of frozen
dataclass. It declares sixteen hardware contexts, four context-id bits, an
issue queue two deep, a 91-cycle resident tile interval, 64 result rows and a
250 MHz target; it names a scheduling policy and a preemption boundary; it
lists a four-field identity tuple and a seven-input eligibility surface; and
its `validate()` hand-checks five relations between those numbers, including
that `context_id_bits` is exactly `(context_count - 1).bit_length()`.

That is an architecture description. It is written in Python because the ADL
had no way to say it, and it is checked by a hand-written `validate()` because
there was no validator to inherit. Both halves are the thing AXIS exists to
take over: the declaration belongs in the description, and the relations
between declared numbers belong in the checker every other AXIS construct
already gets for free.

The engine is the live frontier of that repository — tile-boundary
multithreading around the XNN federation, being proven module by module — so
this is not a speculative surface. It is a contract someone is currently
maintaining twice: once as constants, once as prose obligations underneath
them.

## 2. Why multi-context is not the same question as multi-*configuration*

AXIS already has `(contexts N)`, on `deffabric`, from G4a. It means the number
of configurations a PE can hold, and its entire obligation is a counting one:
a mapping may not need more configurations at a PE than that PE can hold.

An accelerator context is a different object. It retains state, carries an
identity, competes for issue, and can be starved. Its obligations are about
*fairness and liveness*, not about capacity. A fabric's configurations cannot
starve each other because nothing schedules between them.

The word stays the same in both forms anyway, and that is deliberate — §6
argues it. In both places it answers the same question, "how many of these
does the hardware retain at once"; what differs is what else the form says
about them, which is exactly what the reader is looking at when they read it.

## 3. What AXIS can decide, and what it cannot

Decidable from the declaration alone:

* `context-id-bits` encodes every context, and the count is a power of two of
  at least two. Getting this wrong builds a machine that cannot name half its
  own threads, and it is pure arithmetic — the kind of relation this
  repository has caught in a launch's operand widths and a capsule's layout
  and a packet's slot widths already.
* `issue-queue-depth` is at least two. A queue of one holds the issue being
  serviced and nothing else, so there is no prefetched issue and the latency
  hiding the whole engine exists for is impossible by construction. The
  consumer's `validate()` states this as "active plus prefetched"; AXIS can
  state it as a bound.
* the identity tuple retains `context_id`. An issue that does not carry which
  context it came from cannot have its result returned to that context, and no
  amount of downstream care recovers it.
* **the derived bounds, published rather than recomputed.** A work-conserving
  round robin over N contexts serves a persistently eligible context after at
  most `N - 1` other grants, and that bound in cycles is
  `(N - 1) × service-interval`. The consumer computes both as dataclass
  properties. A manifest that publishes them is one derivation instead of two,
  which is the same argument `mapping_manifest.json` makes for publishing the
  modulo occupancy tables the validator already computed.

Not decidable, and not attempted:

* whether the RTL implements the policy it names. `work-conserving-round-robin`
  is an identifier a consumer matches on, exactly as `ready-valid` is in
  [`elastic_seams_design.md`](elastic_seams_design.md) §4. AXIS judges the
  spec; the consumer judges the silicon.
* the utilization envelope. `estimate_xnn_mt_latency_hiding` is explicitly
  `MODELED`, with a caveat naming everything it omits — shared memory, NoC,
  result bandwidth, queue tails, faults, context-maintenance tax. A speedup
  number AXIS cannot check is a number AXIS should not carry.
* whether a grant is one-hot in hardware, whether a stalled issue is
  bit-stable, whether abort drains. Those are the consumer's proof
  obligations, and they are stated in its own contract where a prover can
  reach them.

## 4. Language surface

```lisp
(defaccelerator xnn0
  (family xnn)
  …
  (contexts 16)
  (context-id-bits 4)
  (issue-queue-depth 2)
  (service-interval-cycles 91)
  (scheduling work-conserving-round-robin)
  (preemption tile-boundary-only)
  (identity context_id tenant_id domain_id command_id)
  (eligibility descriptor_valid weights_ready activations_ready
               result_credit tenant_enabled not_faulted not_cancelled))
```

Absent, every field defaults to the single-context machine AXIS describes
today, and every artifact stays **byte-identical** — the invariant every stage
in this repository keeps and every stage asserts rather than assumes.

## 5. The stages

- **M1 — the context file.** _Done._ `(contexts)`, `(context-id-bits)`,
  `(issue-queue-depth)`, `(identity …)` on `defaccelerator`; the arithmetic
  relations of §3 in the validator; `"multicontext"` in `axis.manifest.v1`
  carrying the surface and the derived `max_other_grants_before_service`; and
  `tools/multicontext_check.py` re-deriving all of it from that manifest.
  Vacuity: a corpus with no accelerator holding more than one context cannot
  tell a multi-context engine from a single-context one, so a run over it
  fails.

  Eight injections, checked in `tests/golden.rs` and by hand: an id field one
  bit too wide and one too narrow, a context count that is not a power of two,
  a single context, a one-deep issue queue, an identity dropping `context_id`,
  an identity naming a field twice, and the numbers declared with no
  `(contexts N)` for them to be about. That last one is the case worth having:
  partly declared is worse than not declared, because every other check then
  passes over an object the description never made.
- **M2 — eligibility and policy, named not modelled.** _Done._ `(scheduling)`,
  `(preemption)`, `(eligibility …)`, `(service-interval-cycles)`, and the
  derived cycle bound. Closed vocabularies, because a policy name this
  language does not know is one no consumer can be held to — the argument
  `validate_channels` already makes for protocols.

  The rule worth having took two fields to state. **A bound is published
  exactly where the policy delivers one.** A work-conserving round robin
  rotates, so a persistently eligible context waits at most `contexts - 1`
  other grants — but only where there is a point at which it can rotate. Run to
  completion with no preemption point is still work-conserving and still
  unbounded, because a context that never finishes never yields; strict
  priority is unbounded for the other reason, a high-priority context served
  forever. Both are legitimate machines to describe and illegitimate ones to
  promise service for, so `max_other_grants_before_service` and
  `deterministic_dependency_cover_cycles` are published as `null` — *said*,
  not omitted, because a consumer reading a missing key cannot tell "no bound"
  from "this manifest forgot to say".

  So the vocabulary is closed at two policies and two preemption points, which
  is the smallest set that has to distinguish anything: one that rotates and
  one that does not. A third is a one-line change with `service_bound` and its
  gate behind it, which is what closing the set is for.

  Injections: a policy name nobody can match on, a preemption point outside the
  set, a service interval with no policy to denominate a bound for, an
  eligibility input named twice, and — the two that matter — either name
  changed to its unbounded form, after which the manifest must publish `null`
  and does.
- **M3 — bounded service, executed.** _Done._ The one obligation here that is
  not arithmetic: *a persistently eligible context waits at most `N - 1` other
  grants.* `tools/context_service_check.py` runs the policy the name denotes
  over the declared context count, with contexts becoming eligible and
  ineligible, and asks two questions rather than one:

  * **sound** — over two hundred seeded eligibility patterns, no persistently
    eligible context ever waits longer than the published bound;
  * **tight** — some pattern makes it wait exactly that long.

  The second is the one worth having. A bound that is never attained was never
  measured: publishing `1000` for a sixteen-context engine passes soundness
  forever and tells a consumer nothing, and soundness alone is the check that
  would let it through. Both fail on the corpus's bound moved by one, in
  opposite directions — narrowed, it is exceeded; widened, it is never reached.

  A third property is separate because it fails differently. A blocked context
  must not delay an eligible peer, and a rotation that waits for whichever
  context its pointer names — rather than skipping to the first eligible one —
  is still a round robin and still starves everyone behind one blocked context.
  That is a real arbiter bug, and the gate is pointed at it: with skipping
  turned off it reports the engine idling on 195 of 400 steps *with work
  available*, which names the failure as non-work-conserving rather than as a
  long wait. Idling and waiting are counted separately for exactly that reason.

  Nothing here models hardware. It runs the policy the name denotes, which is
  the standing `elastic_vs_scalar.py` has when it executes a mapping's declared
  timing: a spec whose own bound its own policy cannot meet is wrong before any
  silicon exists.

## 6. Rejected and deferred, with reasons

**Renaming one of the two `contexts`: rejected.** A fabric's contexts and an
accelerator's are different objects under one word, and the tempting fix is to
call one of them something else. But the word is not what disambiguates them —
the form is, and a reader is always looking at the form. Renaming buys clarity
in a sentence quoting the keyword alone, and costs it everywhere else, where
`(contexts 16)` would read as one thing on a fabric and `(hw-contexts 16)` as a
different thing on an accelerator when they answer the same question.

**The latency-hiding estimate: rejected**, not deferred. See §3. It is a
queueing envelope whose own author marked it `MODELED` and surrounded with a
list of the taxes it ignores. AXIS carrying it would turn a caveated model into
a manifest field, which is how a modeled number becomes a quoted one.

**Per-context memory and result bandwidth: deferred.** The contract's
performance SLOs report "the full memory/result/fairness tax", and the tax is
measured, not declared. Nothing here can check it, and a field nothing checks
is a field that drifts.

**Preemption below the tile boundary: deferred to the consumer.** XNN-MT.0
freezes `tile-boundary-only`, and a mid-tile preemption model needs a notion of
resumable partial state that neither AXIS nor the engine has. The vocabulary is
closed, so adding a value later is a one-line change with a gate behind it.

## 7. Invariants this must preserve

- An accelerator declaring no contexts produces **byte-identical artifacts**,
  the way a document with no `defchannel` or no seam does today.
- The policy stays a name. The moment AXIS describes the arbiter's wires it has
  started judging silicon.
- Derived numbers are published, never re-derived by a consumer. Two
  derivations of one fact is the failure mode `mapping_manifest.json` exists to
  avoid.
