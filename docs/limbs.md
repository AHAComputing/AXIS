# Limbs

Status: **built** (§6–§7). This supersedes the "fourth ABI" sketch in
`docs/wide_execution.md` §8a.

## 1. Why not a 128-bit tier

The executors hold registers in 64-bit slots, so a 128-bit register has nowhere
to live. The obvious fix is a third width tier — `axis_u128` beside `uint32_t`
and `uint64_t` — and it is the wrong one, for a reason that shows up immediately
after it would be built: **it moves the ceiling instead of removing it.** SVE at
VL = 2048 needs a 2048-bit register value. No fixed type reaches that, so a
128-bit tier buys one doubling and then the same conversation.

A value is instead **N machine words** — limbs. `regs` stays an array; a register
occupies `ceil(width / 64)` of it. That is not a new storage model, it is the one
the flat register file already has: register classes are placed by `offset` into
a single array, and a wide register is simply a class whose entries are wider
than one slot.

It also restores something the 128-bit C work traded away. `unsigned __int128`
is a compiler extension, and adopting it cost the header its dependency-free
property for documents that need wide values. Limbs are `uint64_t[]` — portable
C, no extension.

## 2. Only three backends need this

Worth stating before any work, because it halves the surface:

| Backend | Wide values today |
|---|---|
| golden Python | arbitrary — bignum by construction |
| SMT-LIB | arbitrary — `(_ BitVec 128)`, any N |
| LLVM IR | arbitrary — `iN` |
| C | fixed machine words |
| Rust | fixed machine words |
| executors | fixed machine words |

The first three are already unbounded and need no limb representation at all.
Limbs are a C/Rust/executor concern, and any design that touches the IR to serve
them is solving the problem in the wrong place.

## 3. Storage needs limbs; values mostly do not

The sharpest scoping question is whether *arithmetic* has to become limb-wise,
and for this project it largely does not.

Under lane-indexed instantiation, a scalable vector instruction is N ordinary
instructions over **element-width** operands. A 512-bit register is storage that
holds 16 32-bit elements; no operation ever computes on 512 bits at once. So:

* **Limb storage** — a register spanning several slots, with reads and writes
  addressing a bit range inside it — unlocks wide registers, `Q0` as one value,
  element access anywhere in a 2048-bit register, and slices that cross a limb
  boundary. Every value stays ≤ 64 bits.
* **Limb arithmetic** — add-with-carry, shifts across limbs, comparison from the
  top — would additionally let the *packed* representation exceed 64 bits in C
  and Rust. That is the representation lane-indexing exists to replace, so it is
  the smaller prize and much the larger cost: carry propagation is exactly the
  code that is easy to get subtly wrong, and it breaks the one-expression-per-
  function shape the emitters have.

Build the first. Leave the second until something needs it.

## 4. What limb storage looks like

A register class gains a width in limbs, and the slice machinery already added
for sub-register views extends across them:

```
read(index, offset, width):   gather bits [offset, offset+width) from
                              limbs[base + offset/64 ..], stitching across the
                              boundary when a view straddles one
write(index, offset, width, value, policy):
                              the same, with the surrounding bits zeroed or
                              preserved per the class's write policy
```

`view_offset` and `view_width` already say where a view sits; today they are
read as bit positions within one slot, and the change is that they become bit
positions within a register that may be several slots wide. `V0.S[1]` is offset
32 width 32 — inside the first limb. `V0.D[1]` is offset 64 — the second limb.
`Q0` is offset 0 width 128 — both, which is the case that needs stitching and
the one no current backend can express.

## 5. What to check

The distinguishing observation is a view that **crosses a limb boundary**, since
everything else is reachable without limbs at all. A corpus needs at least one
of each: a view inside a limb, a view exactly filling one, and a view straddling
two. A reference that only exercises the first two would pass on an
implementation that never stitches — which is the same trap as testing register
slices with only zeroing policies.

## 6. Built

Status of §1–§5: **implemented and gated.** What landed:

* `RegisterClass` gained `limbs`, and the slot a register starts at is
  `offset + index * limbs` rather than `offset + index`. Every existing class
  declares one limb, so that arithmetic is unchanged for all of them.
* C, Rust and the Python lifter read and write through a view by stitching at
  most two slots. At most two is not a simplification: under lane-indexed
  instantiation every value is ≤ 64 bits, so a view is never wider than a limb
  and cannot span three. No loop, no carry propagation — §3's scoping holding up
  in the code.
* `axis_lift.register_slot(kind, index)` is one definition of the slot maths.
  It had four copies across the drivers, each spelling it `index + offset` —
  correct only while every register fits in one slot.
* The same stride went into the *compact* 32-bit executors, which bind
  `regs[index + offset]` inline. They cannot hold a 128-bit register whatever
  the stride — their slots are `uint32_t` — but reading the low limb of the
  right register is a different kind of wrong from reading a neighbouring
  register, and the rule is now written once rather than per ABI. Seven sites
  in total: two per language in the compact executors, plus the generic
  bind/write path each of them has.

### A second thing the corpus found: an alias with a view

Restructuring the read path around limbs dropped the view mask from the
*aliased* branch — AArch64 index 31 reads `sp`, and W-SP is its low 32 bits.
Restored, and then measured: with the mask gone every gate that reaches an
aliased register still passes, because every operand carrying a view is typed at
the view's width and masks a too-wide read downstream. See `docs/register_slices.md` §8. The write side was a
real gap and is now pinned by a fixture with a non-zero upper half.

### A gap the corpus found: zeroing across a limb

The write policy said *the bits outside the view* become zero, and the first
implementation zeroed the bits outside the view **in the slot it wrote**. Those
are the same statement for a one-limb register and different for any other. The
architectural meaning is the register: an x86 VEX write of `XMM` zeroes the
upper half of its `YMM`, a whole limb away from the bits written.

Fixed by clearing every limb of the register before inserting, which also
collapses the two policies into one insertion path. The reason it surfaced is
that `v128_z0` — a zeroing view on a two-limb register — was added to the corpus
for exactly this crossing, and nothing else in the corpus could have shown it.

## 7. Evidence

Four gates, and they are not four of the same thing:

| Gate | Compares | Sees |
|---|---|---|
| `limbs wide C exec` | C executor vs golden model | stitching bugs |
| `limbs wide Rust exec` | Rust executor vs golden model | stitching bugs |
| `limbs == whole-register C` | C executor vs a reference with no limbs | layout bugs |
| `limbs == whole-register Rust` | Rust executor vs the same | layout bugs |
| `limbs == whole-register Python` | Python executor vs the same | both, for the third executor |

The first two read the same class table the emitters do, which is why they
cannot notice a table that is wrong — both sides move together. `limb_check.py`
models a 128-bit register as **one number**, states a view as a bit range of it,
and lets limbs appear at one point only: the ABI boundary where slot `base + k`
holds bits `[64k, 64k+64)`. `register_slice_check.py` states the same table from
the architectures.

Measured, rather than argued:

| Injected | wide gates | `limb_check` | `register_slice_check` |
|---|---|---|---|
| `v128_cross` view moved to bit 32 | **pass** | fail | fail |
| `v128_z0` flipped to preserving | **pass** | fail | fail |
| `v128_d1` claims three limbs | **pass** | fail | fail |
| C/Rust read drops the stitch | fail | fail | pass |
| C/Rust write drops the spill | fail | fail | pass |
| C zeroes only the slot it wrote | fail | fail | pass |
| slot stride ignores `limbs` | fail | fail | pass |
| Python read drops the stitch | n/a | fail | pass |
| Python zeroes only one slot | n/a | fail | pass |
| Python stride ignores `limbs` | n/a | fail | pass |

Each column catches something the others do not, which is the only reason to
have more than one. Both references also refuse to pass vacuously: `limb_check`
fails if no case wrote a straddling view or zeroed a multi-limb register, and
`register_slice_check` fails if no view in the table crosses a boundary.

### The executors move wide values now, and still do not compute on them

§3 said storage needs limbs and values mostly do not, and left the line there.
It turned out the executors had not drawn it at all: they were **computing** on
wide values, at 64 bits, and reporting `ok`. `axis_mem64`'s read returns a
`uint64_t`, so `LDUR_Q` was `mem->read(..., 128u)` into a 64-bit variable and
kept half. `sim_vs_executor` found it, against the Python executor, which models
the full width.

The eight wide **moves** -- `LDR_Q`, `STR_Q`, `LDP_Q`, `STP_Q` and the rest --
are exactly §3's first half and are built. A wide load reads `limbs` words of
memory and writes `rules.limbs` slots of the file; a wide store does the
reverse. No arithmetic happens: a move has none.

Three things this needed, each additive so no existing caller changed:

* `axis_read_limbs64` / `axis_write_limbs64` beside the view helpers, addressing
  the consecutive slots a wide register already occupies.
* Optional limb hooks on the memory interface -- C function pointers appended
  after `ctx`, Rust trait methods with defaults. Absent, the executor issues
  `limbs` ordinary accesses, which is what a bus does. Present, a host sees the
  wide access as ONE event. That distinction is not cosmetic: without it the
  simulator recorded two 64-bit reads where the reference recorded one 128-bit
  read, which is a disagreement about bookkeeping rather than about bytes.
* `result_limb[]` on the result and the trace record, so a 128-bit answer prints
  as one number instead of its low half.

### And then §3's second half, built

The twelve wide **SIMD** instructions -- `ADD_V`, `BSL_V`, `ADDP_D`, `MOVI_16B`
and the rest -- needed arithmetic, not movement. `mul i128` carries across
limbs and `lshr i128 rn 64` crosses them.

The value is `axis_wide`, an array of limbs, **not** a wider integer type. That
is the point: it generalises past 128, which a `__uint128_t` value would not.
`__uint128_t` appears once, inside `mul`, holding the 64×64 partial product
every schoolbook multiply needs -- the operand of the widening multiply, not
the representation of the value.

What made it small was `expand_lanes`. A lane-typed operator is already turned
into shifts, masks and ors at the expression level, so nothing lane-shaped
reaches the backend and only the scalar operators need a limb meaning: `and`,
`or`, `xor`, `not`, `add`, `sub`, `mul`, `shl`, `lshr`, the comparisons and
`select`. `c_limb_expr` is a deliberately small mirror of the 64-bit lowering
rather than a width parameter threaded through its forty-odd arms -- floating
point, the AArch64 helpers, division, rotates -- none of which has a limb
meaning worth inventing on spec. Anything outside the set declines, which is
the answer the caller already knows how to report.

**A narrow destination in a wide instruction still writes through the view
helper.** `ADDP_D` reads 128 bits and writes 64. Writing its one limb directly
left the other holding what the register held before, where AArch64 zeroes the
rest of the register on a narrow write -- something `axis_write_view64` has
always known and a limb write has no reason to, because a limb write is a
whole-register write and has nothing to zero. Caught by the differential, as
40 cases of `ADDP_D` with a correct low limb and a stale high one.

### ⚠️ The gate reached less than it looked like it did

480 instruction-level cases against the golden model, every limb of every
register seeded at random, all agreeing. Then six deliberate breaks --
the multiply's cross-limb carry, the add's carry, the subtract's borrow, both
bit-granular cross-limb shifts, and comparison from the top -- and the sweep
**passed all six**.

It reaches none of them, for reasons that are properties of the corpus rather
than of the gate. A lane add is shifted down to lane 0 before it adds, so it
never carries between limbs. `MOVI`'s broadcast constant times a byte is
exactly `2^64 - 1`, so its multiply never carries either. Only the word-granular
shifts were covered.

So the limb operations are driven **directly** as well, against Python's
integers, which have no limbs and no width: 2800 of them per run, over random
128-bit pairs and shift amounts from 0 to 129. All six mutations fail now. The
instruction sweep proves the instructions; the arithmetic sweep proves the
arithmetic, and neither substitutes for the other.

### Both executors, and the same gap found twice

The Rust twin is the same runtime operation for operation -- an array of limbs,
`u128` only as `mul`'s partial product -- with `rust_limb_expr` mirroring
`c_limb_expr` and the same rule for a narrow destination in a wide instruction.
Its `LiftOperand` gained `width` for the same reason the C one did: every other
field says where a value lives, and this says how big it is.

⚠️ And it had **the same coverage gap**, found the same way. Driven through its
instructions, the Rust shifts are exercised and the carries are not -- `add`,
`sub`, `mul` and the comparison were each broken on purpose and the instruction
sweep passed every time, exactly as it had for C. The direct arithmetic probe
runs against Rust too now, through an `A` line the driver reads, and all five
mutations fail.

Worth recording because of how the first Rust mutation run looked: every break
passed, which read like the gate not driving Rust at all. It was driving it. The
mutation had hit the **C** runtime -- the two emit the same helper text, and
replacing the first occurrence finds C, which is emitted earlier. The gate was
right and the test of the gate was wrong, which is the more embarrassing of the
two and the harder to notice.

### Which gate runs what, said in both of them

`exec_wide_check` reported twenty cases "past the 64-bit register slot, not
executed", and its reason was that a 128-bit operand had nowhere to live. That
stopped being true. What is still true is narrower and belongs to the driver
rather than to the executors: it seeds 64-bit values and compares one, so
running these there would pass with the upper half zero on both sides and
neither end exercising anything.

So the reason says that now, and names `wide_arith_check`, which seeds every
limb. The two derive the same population independently from the lift table --
operands wider than the word -- and it comes to twenty either way: twelve this
one drives as values, eight stated as effects that `simulator: A64` drives
through memory. A stale reason that reads as coverage is worse than no reason,
which is why it is the reason and not the count that was wrong.

## 8. Still not done

* **A view wider than 64 bits** — and **nothing wants one**. Every register
  class in the repository is one or two limbs, the widest view is 64, and a
  whole wide register is addressed by `view_width: None` plus its limb count
  rather than by a view. Scalable registers do not need it either: lane
  instantiation means no operation ever computes on a whole one. Left here as
  a known shape rather than a gap, because building it would be answering a
  question no description has asked.
* **`Sem::Int` past `u128`** — unchanged, and unrelated: it bounds the golden
  model's packed values, not the executors' storage.
