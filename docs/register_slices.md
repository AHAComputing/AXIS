# Register Slices

Status: **implemented.** `src/ast.rs`, five emitters, 5 gates.

## 1. What is missing

A register class today carries `view_width`: the width a read exposes when it is
narrower than the file. A write masks the value to that width and **overwrites
the whole slot**:

```c
value = axis_mask64(value, rules->view_width ? rules->view_width : 64u);
regs[slot] = value;
```

That is exactly right for AArch64, where writing `W0` zeroes the upper 32 bits of
`X0`. It is wrong for everything that *preserves*, and it cannot express a view
that does not start at bit 0. Concretely, none of these is describable:

| | Why not |
|---|---|
| x86 `AL` | writing it preserves the upper 56 bits of `RAX` |
| x86 `AH` | lives at bit offset 8; there is no offset |
| x86 `AX` | preserves the upper 48 |
| x86 `EAX` | zeroes the upper 32 — a *different* policy from `AL` in the same file |
| `INS V0.S[1], W0` | writes one lane and preserves the others |
| `UMOV W0, V0.B[3]` | reads at bit offset 24 |

x86 is unimplementable without this, and AArch64's element manipulation with it.
The three questions a register view has to answer are **where it starts**, **how
wide it is**, and **what happens to the bits it does not cover** — and only the
second is currently asked.

## 2. The model

A register file is storage; an operand names a *slice* of it.

```rust
pub struct RegisterClass {
    // ...
    /// Bit offset of this view within the register. `AH` is 8, a vector
    /// element is `index * element_width`.
    pub view_offset: u32,
    /// The width the view exposes. Unchanged in meaning from `view_width`.
    pub view_width: Option<u32>,
    /// What a write does to the bits outside the view.
    pub write_policy: WritePolicy,
}

pub enum WritePolicy {
    /// Bits outside the view become zero — AArch64's `W` view, x86's `EAX`.
    Zero,
    /// Bits outside the view keep their value — x86's `AL`, `AH`, `AX`, and
    /// every vector element insert.
    Preserve,
}
```

A read becomes `extract(storage, offset, width)` and a write becomes
`insert(storage, offset, width, value)`, with `insert` consulting the policy for
the bits it does not cover.

This subsumes what exists rather than replacing it: `view_width: Some(32)` with
`view_offset: 0` and `WritePolicy::Zero` is precisely today's behaviour, so the
AArch64 and RISC-V classes keep their meaning with two fields defaulted.

## 3. Why this does not need wide values

The `u128` ceiling that shapes so much of this project does not bind here,
because a slice is addressed **within one storage cell**. `AH` is bits 8..16 of a
64-bit cell; a 32-bit vector element is bits 32..64 of one. Both fit.

What still needs wide values is a slice that *spans* cells — reading `Q0` as one
128-bit value, or an unaligned view crossing a 64-bit boundary. The lane-indexed
representation already avoids needing that for vectors by addressing elements
rather than whole registers, and slices extend the same idea downward: name the
part you mean, never the whole.

## 4. Aliasing falls out

Two classes over the same storage with different offsets and widths *are* an
alias. `AL`, `AH`, `AX`, `EAX` and `RAX` become five classes with one `offset`
into the file and five `(view_offset, view_width, write_policy)` triples. Nothing
about the file changes; the views differ.

The existing `alias: Option<(u32, &str)>` field is a different thing and stays —
it redirects one *index* to architectural state, which is how AArch64 encodes SP
as register 31. Worth keeping the names distinct: that one is an index
redirection, this is a bit-range view.

## 5. Evidence, and a gate that could not fail

Two kinds of check, and the difference between them is the point.

`exec_wide_check.py` proves the executors *honour* the table: it applies the
same extract/insert and compares whole registers, in C and Rust. Both went
straight to 10 executed, 0 failures.

Then injecting "x86's `AL` zeroes the rest of `RAX`" left it **still passing**,
and so did dropping `AH`'s offset to zero. Of course: the reference reads the
same table the emitters do, so a wrong table makes both sides wrong together.
The gate proves consistency and can say nothing about correctness.

`tools/register_slice_check.py` states the views from the architectures instead —
width, offset, and policy for each of the eleven classes — and both injections
fail it. It also requires that some view preserves and some view starts above
bit 0, because without either the check collapses back to the width-only model
it replaced.

This is the same shape as §7.4 of the scalable-vector design: backend agreement
is necessary and never sufficient, and the reference has to be something the
description did not write.

## 6. What it cost

The read and write helpers are generated into five places — C and Rust, each in
compact and wide form, plus the Python lifter — and every one of them currently
implements masking inline. That is the same shape as the register-class test that
was written twice and wrong in both: a rule restated per backend. The helpers
should take the slice from the generated table, as `axis_reg_class_of` already
provides, so the policy is stated once.

Gating it needs a corpus with all three cases in one file: a zeroing narrow write,
a preserving narrow write, and a view at a non-zero offset. The distinguishing
observation is the one a uniform test misses — after writing a narrow view, what
happened to the bits *outside* it — so the reference has to check the whole
register, not the view it wrote through.

## 7. Done, and where it went next

Both items in §6 are built. The helpers take the slice from the generated table
in all five places, and `examples/regslice.axisl` carries the three cases with
`register_slice_check.py` stating the views from the architectures.

The slice machinery then turned out to be most of what registers wider than a
machine word need: a view is a bit range, and the only new thing a 128-bit
register asks is that the range may cross a storage boundary. That is
`docs/limbs.md`, which extends this table with a limb count and this check with
a straddling view — and found, in the process, that "the bits outside the view
become zero" had been implemented as *the bits outside the view in that slot*,
which is the same sentence only for registers of one limb.

## 8. One thing the corpus cannot see

A class may alias an index to a state slot instead of the register file —
AArch64's index 31 is `sp` for the `sp` classes — and the view applies to that
read as well: W-SP is the low 32 bits of the same `sp` that X-SP reads whole.

That mask is currently **unobservable**. Every operand carrying a view is typed
at the view's width, so its semantics evaluate at 32 bits and mask a too-wide
read downstream anyway. Measured rather than assumed: removing the mask from the
aliased read leaves every AArch64 gate passing — the ten in `--only A64`, plus
both architectural-state checks, which are the only gates that reach an aliased
register at all. AArch64 has no form that reads WSP into a
64-bit context (the extended-register forms read `Wn`, a non-aliased class), so
there is no fixture to add; the mask stays because it is what the architecture
says, not because a check would catch its absence.

The *write* side is a different matter and is now pinned. `ADD Wd, WSP, #imm`
with `sp = 0xDEAD_BEEF_0000_0FFF` must leave `sp = 0x1FFF`: the narrow write
zero-extends. The fixture that existed before held `0xFFFF_F000`, whose upper
half was already zero — so it could not tell zero-extension from preservation.
Injecting "an aliased narrow write keeps the upper half" now fails the Python
and both native arms; before the new fixture it passed all three.

## 9. Where a register lives, said once

A class says how a register is *viewed*. Nothing said where the file it views
**is**, so six consumers worked it out for themselves -- the Python lifter,
three executors, the stencil emitter and the pack -- each spelling
`offset + (index_offset + index) * limbs`, each sizing the file from a constant
that says every file has thirty-two registers. Two of those derivations have
been wrong, and one of them was wrong for two years: the stencil emitter indexed
the file raw, so a translated `c.sub` wrote `x1` where the architecture says
`x9`, and every check indexed it raw on both sides and agreed.

`emit-regfile-json` states it once, derived from the description's own
encodings:

```json
{ "class": "rv_fpr", "file": "rv_fpr", "base": 32, "index_offset": 0,
  "stride": 1, "lane_stride": 0, "registers": 32, "bits": 64, "top": 64,
  "view_width": null, "view_offset": 0, "write_policy": "zero",
  "zero_index": null, "alias": null }
```

`registers` comes from **the width of the selector the encodings use**, not from
a constant: RISC-V's compressed forms name eight registers with three bits and
now say so, and an architecture with a six-bit selector gets sixty-four
registers and the storage for them. The constant was right for every corpus
here and would have been silently short for the first one that wasn't.

### Two strides, both true

`stride` is the class's `limbs`. `lane_stride` is what this document's operands
say, which for a scalable file is `VL / 64` and is therefore **not a property of
the class**: `vreg` is one limb in the table and two slots per register in an
SVE document at VL = 128. The executor has two paths for exactly this reason --
an operand carrying a view uses its own `slot_base` and `stride`, one without
uses the class arithmetic -- so the layout publishes both and sizes the file
from the wider. Publishing one number would have meant picking which consumer to
be wrong for; the first version of this did, and said `vreg[1]` was slot 34
where the lifter says 33.

### Storage identity, which `lowering_family` is not

⚠️ A class now names the **file** it views. That is not `lowering_family`, which
says which operands a lowering may bind to one variable: x86's `x86_r32` and
`x86_r64` have different families on purpose, so a 32-bit operand cannot bind a
64-bit variable, and they are nonetheless the same registers. Nothing said so,
and the first thing that asked -- an overlap check over the derived layout --
reported `x86_r8hi` colliding with `x86_r64`, correctly, on the evidence it had.

With storage identity stated, the check means what it should: two classes that
name *different* files and share a slot are a description in which writing `v1`
changes `r2`. It found one. `simd_fp_lanes` addressed a single register file at
two strides -- its 64-bit lane instructions used `reg` (one slot per register)
and its 128-bit ones used `reg128` (two), so `v1` was slot 1 to one half of the
description and slots 2-3 to the other. Every differential gate passed, because
both sides of each comparison made the same assumption. The corpus names one
file now.

`tools/regfile_check.py` runs over all 56 corpora: every register the encodings
can name has storage, the layout's arithmetic is the lifter's, the register
count is the selector's, and no two files share a slot by accident. ⚠️ That last
check is a guard no corpus fires any more, so the gate carries a **positive
control** -- it writes a description that does overlap and requires the detector
to say so. Without it, deleting the detector would have passed. Five mutations,
five caught.
