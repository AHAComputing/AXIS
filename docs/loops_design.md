# AXIS Bounded Loops

Status: **implemented** — `src/loops.rs`, `examples/loops.axisl`, 6 gates.

```
(iterate <type> (<index> <count>) (<acc> <init>) <body>)
```

`acc_0` is `init`; `acc_{k+1}` is `body` with `<index>` bound to the literal `k`
and `<acc>` bound to `acc_k`; the loop is `acc_count`.

## 1. What it is for

AXIS is statically elaborated: `defsem` calls inline, instruction families
expand, SIMD lanes expand, scalable vectors instantiate. A loop is the same idea
with the vector-ness removed, and it earns its place by expressing the one shape
none of those can: **iterations that depend on each other**.

Lane expansion requires lane-*local* operators, and `src/simd.rs` refuses
anything else — correctly, because a lane-wise operator that read another lane
would quietly mean the wrong thing. That restriction is what makes lanes
independent and the expansion sound. A loop carries an accumulator forward
instead, so a population count, a parity scan, a bit reversal or a carry chain
becomes describable, and none of those has a lane-wise spelling at all.

## 2. Why the bound is static

Because it costs nothing. An unrolled loop is ordinary semantics, so all five
backends and all three executors handle it with machinery that already exists —
the same argument that made scalable lane instantiation free, and for the same
reason: nothing downstream ever learns that a loop was there.

A **dynamic** trip count is a bounded loop plus a guard: iterate to the maximum
and let a predicate decide which iterations count. That is not a workaround
invented here — it is exactly what `vtail` already does for vector lanes, where
the architectural length `vl` selects among statically instantiated lanes.

Two guards keep the elaborator total. A count above 1024 is refused. And a body
that names its accumulator more than once doubles the expression each iteration,
so the node count is checked as it grows and reported as a diagnosable error
rather than an elaborator that stops responding:

```
`iterate` over 64 iterations expands past 200000 nodes at step 17; a body that
names `acc` more than once doubles each iteration
```

## 3. Native loops, later

Backends that have real loops (a `for` in C and Rust, blocks and a phi in LLVM)
could emit them instead of the unrolling, as a second implementation proven
against it. That is the relationship stage V2 already has with packed vectors:
the expansion is the definition, the native form is a second implementation, and
a differential gate sits between them.

SMT would keep the unrolling either way. QF_BV has no loops, which is the same
wall that decided the scalable-vector proof strategy — solvers work at concrete
sizes, so the description meets them there.

Native lowering is worth doing when a loop is large enough that unrolling hurts:
`vrgather` is the obvious candidate, since it needs a select tree over every
lane and is quadratic unrolled.

## 4. Evidence

Four backend gates against the golden model, and one that does something the
rest of the ladder cannot.

`cpop` is already a primitive operator, so a loop that computes a population
count has a reference **inside the language**. `tools/loop_equivalence.py` asserts
the two differ and requires `unsat`, which decides equality for every input at
once rather than sampling:

```
proved CPOP_LOOP_S == CPOP_PRIM_S for all 32-bit inputs
proved CPOP_LOOP_H == CPOP_PRIM_H for all 16-bit inputs
confirmed CPOP_LOOP_S != PARITY_LOOP_S, so the prover can still say no
```

The third line is not decoration. A prover that answered `unsat` to everything —
a malformed query, a name that failed to resolve — would report every
equivalence as proven, so a pair known to differ has to come back `sat`.

Checked by injection: a loop running one iteration short, and an index bound one
too high, both fail the equivalence proof. Both pass every backend gate, which
is the expected result by now and the reason §7.4 of the scalable-vector design
argues for references the description did not write. Here the reference is
unusually good, because the language already contained it.

## 5. A coverage hole, and a wrong diagnosis of it

Block-memory instructions got no executor coverage at first, and the reason I
recorded was wrong. I wrote that roundtrip fixtures are generated from
instructions that write a **register**, so an instruction whose whole effect is
on memory produces none. That is not the rule. Fixtures come from instructions
that are *encodable*, which means every operand binds to a format field and no
field is left unbound — and the block-memory format declared an `rs2` field that
no operand used. A bug in the corpus, not a property of the harness.

Binding it produced fixtures immediately, and two of the four executor gates now
do real work on these instructions: the Python executor and the LLVM effect
harness both run them.

**They do not close the gap I thought they did.** Injecting a loop that halves
its index — so every copy reads and writes the wrong address — leaves both of
them passing. Of course it does: one compares the executor against the golden
model and the other compares LLVM's effects against the Python executor, and all
three derive from the same description. What execution adds here is *backend*
coverage, not architectural coverage: it would catch an executor that mishandled
thirty-two stores in one instruction, and it cannot catch a description that
says the wrong thing.

`tools/blockmem_check.py` was doing the load-bearing work all along, and still
is. Worth being exact about, because "we now execute these instructions" reads
like stronger evidence than it is.

The other two skip for a reason that is real and unrelated: `exec_c_check` and
`exec_rust_check` drive the **compact 32-bit ABI**, and a block copy takes 64-bit
pointers. That is the same reason `RV64I Rust exec` skips, and it is a stated
limit of that ABI rather than anything about memory.

The correction matters more than the fix. A plausible explanation — "fixtures
need a destination register" — was consistent with everything I had observed,
and it was wrong, so it would have justified building a harness feature that was
never needed. What settled it was reading `is_encodable`, which is two lines.

**Scalable vector stores really are unexecutable**, and now for a stated reason
rather than an assumed one. Lane instantiation renames an operand to `zd__l0`,
and that name matches no format field, so the operand loses its encoding
binding — `fields=[]` in the lift table, while an unrenamed operand like `rs1`
keeps its own. Lane instructions therefore cannot be reached through the decode
path at all, which is consistent with their sharing an encoding by design. They
are checked by reading their emitted effects, which is what
`tools/scalable_addressing.py` does.

## 6. What is not covered

* ~~Loops in behaviors~~ — **built.** `(iterate (<index> <count>) <statement>
  ...)` repeats *effects*, which is what a block copy or fill is: one
  instruction performing a bounded number of memory accesses. `examples/blockmem.axisl`
  carries copy, strided copy, fill and reversed copy.

  It expands **before** effect elaboration, unlike the expression loop, and for
  the same reason a vector *store* had to put its shape in the address: a
  statement loop changes how many effects an instruction has, and the effect
  list is built by the elaborator it feeds. Anything that shapes a location has
  to arrive earlier than the thing that builds locations.

  It needed no multi-write ABI. `EFFECT_MAX_WRITES` bounds *register* writes,
  while a copy's stores go to the memory image — `MEMSET32` is 32 stores and
  zero register writes, comfortably inside an ABI that allows four.
* **Early exit.** `clz` cannot be written as an `iterate`, because it stops at
  the first set bit. A fold can compute it (accumulate a running "found yet"
  flag), but that is a different shape from the loop-with-break the operation
  actually is.
* **Loop-carried memory.** Nothing here reads what an earlier iteration stored,
  because effects are outside the expression domain.
