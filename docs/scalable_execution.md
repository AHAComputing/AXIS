# Executing scalable vectors

Status: **built** (S1–S7). The corpora in `examples/sve.axisl` and `examples/rvv.axisl`
are described, instantiated, and proven equal across five backends. None of them
runs. This is what stands between the two, and what it takes to reach the JIT.

## 1. The measurement

```
$ cargo run -q -- emit-lift-json examples/sve.axisl
507 entries, 0 liftable
$ cargo run -q -- emit-roundtrip-json examples/sve.axisl
0 fixtures
```

Zero fixtures is the sharper number: a fixture is an encoded word plus the
operand values it decodes back to, and there is no word to encode.

`liftable` is `operands_encodable && has_semantics`. The semantics are there. The
encoding is not:

```json
{"name": "zd",      "role": "out", "width": 8, "fields": [{"insn_lo": 7, ...}]}
{"name": "zn__l0",  "role": "in",  "width": 8, "fields": []}
{"name": "zm__l0",  "role": "in",  "width": 8, "fields": []}
```

Instantiation renames an input operand per lane — `zn` becomes `zn__l0 .. zn__lN`
— and a format field binds to an operand *by name*. `zn` no longer matches any
operand, so its five bits bind to nothing and every lane operand decodes from
nothing. The destination survives only because a destination is never named by
the value expression, so it is never renamed.

Nothing downstream can run an instruction whose operands have no bits. That is
the whole of why 507 proven entries are unexecutable.

## 2. What is actually true about the encoding

A scalable instruction encodes **one register selector per declared vector
operand**. It does not encode one per lane — there is nothing in the 32 bits to
encode them with, and at LMUL > 1 the lanes span several registers that are
*consecutive by construction* rather than separately named.

So the model that matches the hardware is:

    zn          the encoded selector      — bound by decode, read by nothing
    zn__l0..N   elements of it            — read by the semantics, bound to no bits

which is exactly `derived_from` / `derived_add`, the mechanism AArch64's `CASP`
already uses: a register pair encodes its first register and the second is
`+1`. A lane operand is the same shape with a different bias.

### The role an operand needs and does not have

`(input, output)` has three inhabited combinations and the artifacts name them
`in`, `out`, `inout`. A selector is a fourth: **encoded but not read**. Every
emitter currently maps the unused `(false, false)` to `"in"`, which would feed a
register *number* into the semantics where a value belongs — the same failure
that cost 11256 phantom differential failures when `kind == "reg"` misclassified
an AArch64 operand.

That mapping is written out five times (`emit/lift.rs`, `emit/lisp.rs`,
`emit/encode.rs` twice, `emit/translation.rs`). It becomes one function in
`ast.rs` with a fourth arm, for the same reason `is_register_kind` did.

## 3. Where an element lives

Limb storage (`docs/limbs.md`) supplies the other half. A Z register of VL bits
occupies `VL / 64` slots; element *e* of width *w* is bits `[e*w, e*w + w)` of
that register — a view, exactly like `V0.S[1]`, and one that straddles a limb
boundary as soon as VL exceeds 64.

What a lane operand needs, then, is a view that the *class* cannot hold: the
class table is a compile-time constant, while VL and the element width are
per-document. So the view moves onto the operand:

    slot_stride    how many slots one register of this file occupies (VL / 64)
    view_offset    lane_element * element_width
    view_width     element_width

with zero meaning "no override — use the class". The class keeps saying which
file and where it starts; the operand says where in the register it reads. A
lane operand is precisely an operand that needs to say that.

`packing` already publishes `lane_register` and `lane_element`, from which those
three are derivable. They are published anyway rather than derived, because the
alternative is the same arithmetic written once per consumer — which is how
`index + offset` ended up in four drivers.

### `REGISTER_FILE_SLOTS` stops being a constant

32 Z registers at VL = 128 need 64 slots, which is exactly today's constant. At
VL = 256 they need 128. The constant becomes a quantity computed from the
document — the largest slot any class-and-stride combination reaches — with the
current value as a floor.

## 4. Stages

Each stage ends at a gate, because a stage that ends anywhere else cannot be
shown to have worked.

| Stage | Delivers | Gate |
|---|---|---|
| S1 | Selectors and derived lane operands; `liftable` becomes true | roundtrip: encode/decode over the SVE corpus |
| S2 | Per-operand views and a computed file size | a reference stating element placement from VL and width alone |
| S3 | Python and wide C/Rust executors apply operand views | lift+execute == golden over SVE and RVV (Rust: §12 — it did not, until 2026-09) |
| S4 | The JIT binds through the published table | JIT-compiled scalable block == executor |

S4 is the target and S1 is the only one that can be skipped by no route: an
instruction with no bits cannot be decoded, so nothing after it exists.

## 5. What the JIT needs beyond S3

`tools/jit_llvm.py` binds registers with its own rules — one slot per register,
plus an inline AArch64 W-form special case:

```python
if kind != "reg" and register_kind_width(kind) == 32 and bits == 64:
    ...
```

That is a sixth copy of the register-access rule, and the only one that never
read the class table. It works because every corpus it runs has one slot per
register and at most one view per class. A scalable block has neither.

So S4 is not "teach the JIT about vectors". It is: bind through the same
published table the executors bind through, including `slot_stride` and the
operand's view. The IR the JIT emits per instruction does not change at all —
the handlers it calls are the proven `axis_eval_*` functions, and a lane
instruction's handler is an ordinary scalar one.

## 6. What this does not do

* **No packed vector value ever exists.** A block of 16 lane instructions is 16
  scalar operations against 16 views. That is the whole point of lane-indexed
  instantiation, and it is why the JIT needs no vector IR.
* **No limb arithmetic.** Every value stays at element width.
* **Predication, memory, and cross-lane forms** instantiate to the same shape and
  come along for free where their operands are ordinary elements. Where they are
  not — a gather's per-lane address, a `vcompress` — S3 will say so rather than
  quietly skip them.

## 7. S1 and S2, built

`liftable` went from 0 to 238 of 507 for SVE and 0 to 100 of 190 for RVV;
fixtures from 0 to 35 and 28. What the remaining entries need is corpus work,
not mechanism: predicate, reduction and segment operands (`pd`, `rd`, `zd0`)
have no field in the corpora's formats, so they were unencodable before lanes
existed and still are. Named rather than hidden.

Three things the plan did not anticipate:

* **Deriving at offset zero was forbidden.** The rule exists because CASP's
  second register is `+1`, and a zero offset would make a derived operand a
  second name for the same register. A lane names a different *element* of the
  same register, so zero is exactly right — the rule now asks whether the
  operand carries element packing.
* **The decoder had to learn what the validator already knew.** Every lane
  shares its origin's word, and the disjointness rule had exempted them from
  contending over it since the day lanes were introduced. The decoder still
  returned "ambiguous" on the second match. Decode now names lane 0, and
  `decode_lanes` returns the group — which is what executing a scalable word
  will mean in S3.
* **The roundtrip gate would have passed on nothing.** With no encodable
  instruction it printed "nothing to run" and returned success. 507 described
  instructions, no word to encode, green. An empty corpus now fails.

### What the placement reference does not do

It never computes `lane * width`, because that is the expression under test.
It states four properties — elements tile their register exactly once, none
runs past it, the stride is as few whole slots as hold VL bits, and a lane
moves to the next register only when the previous one is full — and checks the
element *map* built across the whole corpus rather than any one instruction's
operands. That last part matters: `LASTB` reads one element and a gather reads
them out of order, so tiling is a property of the map, not of an operand list.

Measured on four injected stamps: a wrong stride, an element shifted by one,
and swapped register/element indices all fail on both corpora. Stamping the
lane index where the element index belongs **passes on SVE and fails on RVV** —
nothing in SVE groups registers, so the two are the same number there. Two
corpora, because one of them cannot see it.

## 8. S3 and S4, built

A scalable word now executes, in the Python executor and in the in-process
LLVM JIT.

`step` runs the group rather than an entry: a scalable word instantiates to
`VL/elem` scalar operations and all of them share it, so executing the word
means executing each lane. Every other instruction is a group of one and takes
the same path. Register access moved from the class to the operand — the class
still says which file, the operand says which element — and the two-limb stitch
underneath was already there.

The JIT needed no vector IR, which was the point of lane-indexed instantiation.
A block of a scalable word is `VL/elem` calls to the proven `axis_eval_*`
handlers, each an ordinary scalar operation; what changed is the addressing
around them: which slot an element loads from, and inserting a result without
disturbing its neighbours. Measured on `examples/sve.axisl`: 35 scalable words,
~29 lane calls per compiled block, cache hits on repeats.

### The evidence chain, and where it is a chain

| Gate | Compares | Independent of |
|---|---|---|
| lane placement | published placement vs four properties | the arithmetic that produced it |
| scalable exec | Python executor vs a whole-register model | views, limbs, and lanes |
| scalable JIT | compiled block vs the Python executor | the executor's *implementation*, not its model |

The third is a chain link rather than a fresh reference, and worth saying so:
it proves the compiled block agrees with an executor that the second gate
proves agrees with a model that has neither views nor limbs. Twelve injected
bugs across the three, each caught.

### The same corpus asymmetry, three times

Dropping the register bias — the term that puts a lane past a register's
capacity into the next register — **passes on SVE and fails on RVV**, in the
placement check, in the executor check, and in the JIT check. Nothing in the
SVE corpus groups registers, so the lane index and the element index are the
same number there and the bias is always zero. Every one of these gates runs on
both corpora for that reason, and none of them would have found it alone.

### What is still declined, by name

* **Effectful lanes** — SVE's `LD1`/`ST1`, RVV's saturating forms. They
  instantiate the same way; their reference is a memory image rather than a
  register file, so `scalable_exec_check` names them and the JIT block skips
  them.
* **A view across a slot boundary.** No element in either corpus straddles one:
  an element of width *w* sits at a multiple of *w*, and every *w* here divides
  64. The block lowering reads one slot per element and refuses anything else
  rather than emitting IR no corpus exercises. The straddling path is proven,
  in the executors, by `examples/limbs.axisl`.
* **269 SVE entries** whose predicate, reduction and segment operands have no
  field in the corpus's formats. Corpus work, not mechanism.

## 9. S5: vector memory

The declines in §8 said loads and stores "instantiate the same way; their
reference is a memory image rather than a register file". They now run — in the
executor and in the JIT — and getting there needed three things the corpora had
never had to be right about.

### The two register files were one

Every operand in both corpora named class `reg` at slot 0, and a vector operand
strides `VL / 64` slots. So `z1` occupied slots 2 and 3 while `x2` occupied slot
2: **the same storage**. It stayed invisible for exactly as long as no
instruction named both files, which is to say until a contiguous load, whose
base address is a scalar register and whose destination is a vector one.

There is now a `vreg` class at offset 32, with the scalar file below it. The
scalar file goes first because its size is fixed — putting the vector file first
would move the scalars every time VL changed.

### A format field binds by name, and memory names different operands

`SVE_Z` has fields `zd`, `zn`, `zm`. A contiguous load's operands are `zd` and
`rn`. So `rn` bound to nothing and every one of the 60 memory entries was
unencodable, for the same reason the lanes were in S1. Three formats with the
same bit layout and the names memory uses fixed it.

The first attempt at the RVV side gave one format every field, which is worse
than none: an instruction with a field it neither uses nor pins has an *unbound*
field, and an unbound field means not encodable. The plain load and store came
out exactly as unrunnable as before. One format per operand shape.

### Deriving needed the property, not the list

`vreg` could not be derived from — the rule allowed three kinds by name. The
property was never the name: a class that aliases an index to a state slot
cannot be derived from, because "the next register along" from AArch64's SP
names nothing. Asked that way, every class added since is admitted.

### What the gate says, and what a sampled gate missed

The reference states contiguity: element *e* of a unit-stride access is at
`base + e * bytes`. `scalable_addressing.py` already proves each lane *computes*
that address; this proves the bytes actually move between that address and that
element — a load that computed every address correctly and wrote them all into
element 0 passes there and fails here.

The JIT gate initially sampled its blocks, and a run whose memory words all
happened to be stores reported a green load path it never compiled. Measured:
with the load's destination placement deliberately broken, RVV **passed**. Every
block now carries one of each direction, and the gate fails if a run covers only
one. With that, the same injection fails on both corpora.

### Still declined, and now smaller

* **Strided, indexed and segment forms.** Their element maps are stated in
  `scalable_addressing.py`; running them needs the same care, not the same line
  of code. The gather also has a sharp edge worth recording: its address comes
  from an element of an index *vector*, so a driver that fills vector registers
  with random bits reaches a random address — which is a SIGBUS, not a failed
  comparison.
* **Fault suppression.** The buffer is declared wholly accessible, so nothing
  suppresses and contiguity is the whole expectation. What happens when an
  element is *not* accessible is `scalable_faulting.py`'s subject.

## 10. S6: the rest of vector memory

Strided, indexed and segment accesses now execute too, in the executor and the
JIT. The element map each one states was already written down in
`scalable_addressing.py`, so the reference reads it from there rather than
keeping a second copy:

    unit      element e is at base + e * bytes
    strided   element e is at base + e * step, step being a register
    indexed   element e is at base + index[e], index being a vector
    segment   field f of element e is at base + (e * nf + f) * bytes

Coverage now reported: SVE compiles `segment, unit`; RVV compiles `indexed,
segment, strided, unit`, in both directions.

### What made these harder than contiguous

All three difficulties are the same shape — an address the driver did not
control:

* **A stride bounded by the wrong thing.** The base can sit anywhere in the
  first half of the buffer, so the *step* is bounded by what is left divided by
  the lanes ahead of it, not by the buffer. Drawn from the whole buffer, lane 3
  lands past the end — where the executor's bounds check returns zero and
  compiled code reads whatever is there. That disagreement is how it was found.
* **An index vector is not a random register.** A gather's offset comes from an
  element of a vector, so the driver has to build that vector out of offsets
  that stay inside the buffer. Filling it with random bits reaches a random
  address, which in compiled code is a SIGBUS rather than a failed comparison.
* **A block can clobber its own index.** Once every block carries one word of
  each shape, an earlier instruction's destination can be the register a later
  gather indexes through. The gather then reads whatever was written there and
  leaves the buffer — a segmentation fault. The index vector now gets a
  register of its own that nothing else is allowed to claim.

None of these is a bug in the description or in the executor. They are the cost
of *running* an addressing mode rather than checking the address it computes,
and they are worth recording because each one presents as a crash rather than
as a failure.

### Coverage, again

The same lesson as §9, one level down. Forcing one word of each *direction* per
block was not enough once there were four addressing modes: a run could compile
every direction and still never compile a gather. Blocks now carry one word of
each **shape** — mode and direction together — and both drivers print what they
covered rather than only whether it passed.

Measured on three injected element maps: a stride that ignores its register, a
segment that swaps field and lane, and a gather that reads lane 0's index for
every lane. RVV fails all three. SVE passes the stride and gather injections
because it has neither form — which is the reason both corpora are gated, for
the third time.

### Still declined, and now honestly named

RVV's saturating arithmetic (`VSADD_VV_X` and friends) is effectful but touches
no memory: it writes a register and a sticky flag. The gate used to decline it
as "addressing not stated", which is a true sentence about the wrong subject. It
now says "effectful, but not memory". Checking those needs a state-aware
reference, which is a different piece of work from this one.

## 11. S7: saturating arithmetic, and a sticky flag

The last decline in the execution gate was RVV's saturating forms: effectful,
touching no memory, writing an element and OR-ing an overflow bit into `vxsat`.
They now run, and both corpora decline nothing at all — SVE 300 executions, RVV
136, every scalable instruction in each checked.

What makes them a different reference is not the arithmetic. The per-element
semantics are evaluated by the golden model's own evaluator, on an environment
this reference builds by extracting elements from whole registers, exactly as
the pure path does — what is under test is the extraction, the insertion and the
*ordering*.

**The flag accumulates across lanes.** Lane 3's `setstate` reads what lane 2
left, so the reference threads state in lane order rather than computing each
lane independently. A reference that evaluated lanes in isolation would agree
with an executor that did the same, and both would be wrong — so the gate is
built to notice: isolating the lanes' state in the executor fails it.

Three injections, and the third is worth recording as an honest negative:

| injected | result |
|---|---|
| the state write never lands | fail |
| each lane gets its own copy of the state | fail |
| the environment is not updated after a `setstate` | **pass** |

The third passes because these instructions have exactly one `setstate` per
lane, so updating the environment within an entry changes nothing that any lane
can observe. That is an inert injection rather than a hole in the gate — but the
distinction is only visible if you write down which injections *didn't* move,
and an instruction with two state writes in one lane would need the check the
third one was aiming at.

A run in which nothing saturated would exercise the ordinary path twice and the
flag not at all, so the gate reports how many cases changed it and fails if none
did.

## 12. The wide Rust executor, running lanes

The S3 row above said the wide C **and Rust** executors apply operand views.
The Rust one did not. Measured before the change, through
`scalable_exec_check.py --lang rust`:

| corpus | executed | declined | failures |
|---|---|---|---|
| `sve` | 24 | 236 | 48 |
| `rvv` | 8 | 128 | 16 |
| `scalable_crosslane` | 0 | 44 | 0 |
| `scalable_basic` | 0 | 60 | 0 |

Three things were missing, each present in the C twin:

- **The lane placement.** Rust's `LiftOperand` had no `register_bias`,
  `stride`, `view_offset`, `view_width` or `slot_base`, so a lane operand
  was read and written as a whole register by index. They are published now,
  and `read_operand64`/`write_operand64` apply them as C's
  `axis_read_operand64`/`axis_write_operand64` do, falling back to the class
  for an operand with no view.
- **The lane loop.** `step64` lifted the first matching entry and ran it — lane
  0, alone. It now runs `decode_lanes`' group in order, each lane lifted
  against its own entry (`lift_entry`), with the result the last lane's and
  the writes the union, as C's loop does.
- **`enc` operands.** A lane's origin operands are encoded and read by
  nothing. The pure path fed every non-output operand to the semantics and
  wrote every non-input one back; a scalar instruction has no `enc` operands,
  which is why that never showed.

**And the gate had a hole that made the table invisible.** The compiled path
of `scalable_exec_check.py` counted `FAIL` lines only, so an executor that
declined a case never failed it: Rust declining 236 of 260 SVE cases reported
48 failures, and on `scalable_basic` — every case declined — it reported
PASS. A decline is a failure now, read from the driver's own summary. C never
declined, so its two registered gates were not passing vacuously; they could
have been.

After: SVE, RVV, `scalable_crosslane`, `scalable_vtype` and `matrix` run on
the Rust executor with nothing declined and nothing failed, as they do on C,
and are registered for both (SVE and RVV had only C). `examples/sme.axisl`
runs on all three executors (`tools/sme_check.py` holds Rust too now).
Injection-checked four ways: running lane 0 alone, dropping the register
bias, feeding `enc` operands, and declining every scalable word each fail.

**Recorded, not fixed.** `scalable_basic` and `scalable_predicate` still fail
this gate on every executor — Python, C and Rust alike, with identical values
— for the instructions that read a *scalar* operand (`SVADD_DUP_S`,
`SVWHILELT_S`). Those corpora put the scalar in the same `reg` class as the
vectors, so it is register slot `rs` to the executors and vector register `rs`
to the whole-register model. Real SVE reads that scalar from the general
registers, a different file; the corpus is ambiguous, not the executors, which
is why the gate was never registered for those two. Separately,
`scalable_memory` executes nothing through either compiled executor: its
memory forms are not on the compiled arm, for C as for Rust.

