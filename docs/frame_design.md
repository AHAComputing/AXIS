# Stack frames and aggregate passing (F1–F3)

Status: **5 stages implemented** (F1, the frame declared and consistent; F2,
the frame executed; F3, aggregates; F4, regions and spill geometry; F5, the
pointer discipline). The
corpora declare 1 stack frame, a checked number
(`tools/doc_facts_check.py`) for the reason
[`elastic_seams_design.md`](elastic_seams_design.md) states: the gate below
fails as vacuous without one, and a corpus can lose it while this header goes on
claiming the check runs. The design is complete; §5 is what it deliberately
leaves out.

## 1. The consumer wrote this by hand, twice

[`llvm_backend.md`](llvm_backend.md) §9 named frame lowering and struct passing
as the two things L4 does not deliver, and said both were "reachable from here
and neither guessable". That was the right boundary and the wrong stopping
point, because a consumer had already written both by hand.

`pce/software/grv-linked-executable/src/lib.rs` carries a frame descriptor as
struct fields: `link_register`, `stack_pointer_register`,
`callee_saved_register`, `frame_size_bytes`, `saved_s0_offset`,
`saved_ra_offset`, `initial_stack_pointer` — register *numbers* and slot
*offsets*, declared in Rust. `hardware/grv/grv_linked_execution.py` then checks
a prologue against hand-encoded words:

```python
expected_wrapper = (
    _encode_addi(2, 2, -16),   # addi sp, sp, -16
    _encode_sw(1, 2, 12),      # sw   ra, 12(sp)
    _encode_sw(8, 2, 8),       # sw   s0, 8(sp)
    _encode_addi(8, 2, 16),    # addi s0, sp, 16
    ...
```

with the invariants beside it in Python: `initial_sp % 16` — the stack
alignment — and `frame_size != 16`. That is a frame layout and a prologue,
written twice by hand, in two languages, in two repositories, because the ADL
had no way to say it. It is the same shape `xnn_mt/contract.py` was in before
[`multicontext_design.md`](multicontext_design.md), and it settles the "is
there a consumer" question the same way.

## 2. What is guessable, and what is merely declared

§9's line holds and this design does not move it. Nothing here *infers* a
frame. Which end of the frame the saved registers live at, whether the frame
pointer points at the incoming stack pointer or at the frame base, how large a
frame the platform allows — all of it is declared, exactly as the calling
convention is.

What changes is that a declaration can then be *held to something*, and the
frame has a stronger set of somethings than the convention did, because a frame
is arithmetic over registers the ABI already named and offsets the ISA already
knows how to encode:

* **The saved set is a subset of what a callee may clobber.** A prologue that
  saved an argument register would be preserving a value the caller never
  asked it to preserve — and, worse, the register the value it was passed
  arrived in.
* **The layout is a function, and it must be injective.** Two registers in one
  slot is a frame that loses one of them.
* **The frame has to be addressable.** This is the join worth building the
  stage for. AXIS knows the exact immediate range of every instruction
  (`llvm_backend.md` §9's "immediates carry the range their semantics
  states"), so a platform declaring a 4096-byte maximum frame on a machine
  whose store reaches ±2048 from a base register is stating something its own
  instruction set refutes. A compiler discovers this as a miscompile or a
  scratch-register scramble; a description can discover it as a contradiction.
* **The prologue and the epilogue are inverse.** Whatever the layout, running
  one and then the other must restore every callee-saved register and the
  stack pointer. That is not arithmetic — it is executable, and F2 executes it.

## 3. Language surface

An ABI grows a frame:

```lisp
(defabi ilp32
  …
  (frame
    (growth down)                  ; which way the stack moves on a call
    (saved-area top)               ; saved registers at the high end of the frame
    (slot-bytes 4)
    (save-order (rv_gpr 1) (rv_gpr 8))   ; ra highest, then s0
    (frame-pointer-at incoming-sp)       ; fp = sp + frame, not fp = sp
    (max-frame-bytes 2048)
    (red-zone 0)
    (adjust ADDI) (save SW) (restore LW)))
```

`(adjust)`, `(save)` and `(restore)` name instructions, which looks at first
like an ABI reaching into an instruction set. It is the other way round: *which*
instructions establish a frame is a platform choice — RISC-V could use `sw` or
`c.swsp` — and naming them is what makes §2's addressability join and F2's
execution possible at all. They are checked to be what they claim: `save`
stores, `restore` loads, `adjust` writes a register from an immediate.

Aggregates are a second block, in F3:

```lisp
(aggregates
  (max-register-bytes 8)      ; larger than this passes by reference
  (split allowed)             ; may straddle the last register and the stack
  (return-pointer (rv_gpr 10)))
```

## 4. The stages

- **F1 — the frame, declared and consistent.** _Done._ The surface above, the
  structural rules of §2's first three bullets, `"frame"` in the manifest with
  the *computed slot table* published rather than left to a consumer, and
  `tools/frame_check.py` re-deriving it — including the addressability join
  against the emitted immediate predicates.

  The layout answers for any frame size, which is what makes it a layout rather
  than a table: `slot(0, 16)` and `slot(1, 16)` are 12 and 8, the consumer's own
  `saved_ra_offset` and `saved_s0_offset`, from a description that never
  mentions 16.

  The join reads the immediate range from the emitted LLVM target, where §9's
  rule already writes it as an `ImmLeaf` predicate — one derivation of "what
  this immediate may hold", and one that is already gated twice over. Declaring
  a 4096-byte frame is then caught with the arithmetic in the message:
  ``SW`` encodes −2048..2047 and the outermost slot is at 4092.

  Eleven validator injections rejected: saving a caller-saved register, saving
  one twice, a save that does not store, a restore that reads no memory, an
  adjust with no immediate, a slot too small for a return address, a slot that
  is not a power of two, a maximum frame that breaks the stack alignment, a red
  zone below an upward-growing stack, a growth direction nobody knows, and an
  instruction the ISA does not describe. Four more at the gate: two registers
  in one slot, a slot moved one word, a frame past the store's reach, and an
  adjustment whose instruction states no range at all.
- **F2 — the frame, executed.** _Done._ `tools/frame_exec_check.py` builds the
  prologue and epilogue from the layout, encodes them through the table
  `roundtrip_check.py` proves, and runs them in the golden model over random
  entry states — clobbering every saved register in between, because without
  that "the registers still hold their entry values" is true of a program that
  does nothing.

  **The first version passed every layout injection, and was right to.** It
  compared the value read back at each published slot — but the program was
  *built* from that same published table, so a store and a load at one wrong
  address round-trip exactly as well as at the right one. It was comparing the
  table with itself. This is the shape `gate_coverage.md` keeps finding: a
  check whose two sides came from one source.

  What survived the correction is the half a table cannot settle. The prologue's
  writes are read off the memory it touched: every address must land **inside
  the frame it just opened**, and there must be one per saved register — which
  catches an offset the instruction could not encode (it lands in the caller's
  frame) and two registers sharing a slot (one of them is never written).
  Then the epilogue must be inverse *as a program*. Whether the published table
  is the layout is arithmetic and stays in F1, where it is caught.

  Three injections into the program, all caught with the right message: the
  closing adjustment given the opening sign, a save based on the frame pointer
  instead of the stack pointer, and an epilogue whose adjustment runs before
  its loads. A fourth — the save and restore instructions exchanged — is
  refused before execution, by F1.

  The instruction roles are read from the description's own account: `SW`'s
  `(add i32 rs1 (sext i32 12 imm))` says which operand is the base and which
  the offset. Nothing searches the instruction set for something store-shaped;
  the ABI named the instruction and this reads what that instruction says about
  itself.
- **F3 — aggregates.** _Done._ The block above, and the rules that make it
  consistent with the convention it sits in: a threshold larger than the
  argument registers can hold passes nothing by value; a threshold that is not
  a whole number of registers is a boundary no register lands on; a return
  pointer that is not an argument register cannot be passed, because the caller
  passes that address like an argument and there is nowhere else to put it.

  The emitted convention gains `CCIfByVal<CCPassByVal<…>>`, read back by
  `--gen-callingconv` the way L4's register lists already are. The rule is
  emitted **first**, because it is a test on the argument rather than on its
  type: a type rule matching ahead of it would place the pointer where the
  block belongs.

  Six injections rejected: more bytes than the argument registers hold, a
  threshold no register boundary lands on, a threshold of nothing, a return
  pointer that is not an argument register, one in the stack pointer, and a
  split policy nobody knows.

- **F4 — regions and spill geometry.** _Done._ `(regions outgoing locals spill
  saved)`, lowest address first, and `(spill (rv_gpr 4 4) (rv_fpr 8 8))` — a
  class, the bytes one of its registers costs, and the alignment those slots
  need.

  **No region has a size, and that is the whole of the line.** Sizes are the
  allocator's, per function. Order is the platform's, and order has
  consequences a document can contradict: the saved area is now declared twice
  — by `saved-area` and by where `saved` sits among the regions — so the two
  have to agree; and the outgoing-argument area sits at the frame base and
  nowhere else, because that is where the callee's own stack pointer finds it.

  A spill slot has to hold the register, and how wide the register is comes
  from the *operands* rather than from the class table: `rv_gpr` covers RV32
  and RV64 with no width of its own, so asking the table would have made an
  RV32 slot eight bytes and refused the four-byte one that is right. The gate
  reads the width back from the emitted target's `RegisterClass` value types,
  which is the same fact from the other side.

  Injections: a region twice, a region nobody knows, regions with no saved
  area, `saved` at the end the `saved-area` denies, outgoing arguments above
  the frame base, a slot narrower than its register, a slot aligned past what
  the stack guarantees, two slots for one class, and a size that would misalign
  consecutive slots.

- **F5 — the pointer discipline.** _Done._ `(realignment allowed|forbidden)`,
  `(dynamic-allocation allowed|forbidden)`, `(base-pointer …)`. Three declared
  facts whose implications are the check:

  * dynamic allocation ⇒ a frame pointer, because a local addressed from a
    pointer that moves is somewhere else every time it is read;
  * realignment **and** dynamic allocation ⇒ a base pointer. Realignment moves
    the frame away from any fixed offset of the incoming stack pointer;
    dynamic allocation moves the stack pointer away from any fixed offset of
    the frame. Either alone leaves one pointer that still reaches a local.
    Both together leave none. LLVM spells the identical rule as
    `needsStackRealignment && hasVariableSizedObjects`;
  * a base pointer is callee-saved — it holds the frame base for the whole
    body, and a caller-saved register does not survive the calls that body
    makes — and is not the stack or frame pointer it exists to replace.

  The converse is deliberately *not* an error: declaring a base pointer that
  is never needed costs a register and states nothing false, and a description
  is allowed to reserve one.

  **And it is executed**, which is what "variable frames" is really about.
  `frame_exec_check.py` now runs a second program per trial: the prologue, a
  random downward move of the stack pointer standing in for an allocation, a
  clobber of every saved register *except the frame pointer* — which is live
  for the whole body by construction — and then a frame-pointer epilogue.
  Three injections into that program are caught: recovering the stack pointer
  after reloading the frame pointer rather than before (which destroys the only
  register that still knows where the frame is), an ordinary stack-pointer
  epilogue after the stack pointer has moved, and a wrong bias in the recovery.

  Writing it found the ordering the hard way: the frame pointer is itself one
  of the saved registers, so an epilogue that reloads it first has nothing left
  to compute the stack pointer from. Real epilogues recover the stack pointer
  first for exactly this reason.

## 5. Rejected and deferred, with reasons

**Emitting a real prologue into a `.td`: deferred, not rejected.** LLVM builds
prologues in C++ `FrameLowering`, not in TableGen, so there is no generator to
hand it to and no differential to run — the shape every other stage in
[`llvm_backend.md`](llvm_backend.md) leans on. F2's executed check is the
evidence available without one, and it is evidence about the *layout*, which is
the part a description states.

**Spill-slot *allocation*: still rejected, and only that.** How many spill
slots a function needs, and which value goes in which, is the register
allocator's decision, made per function at compile time. No description can
state it.

That rejection originally swept in stack realignment and variable-size frames
as well, and **that was wrong** — it confused the allocator's decisions with
the regions those decisions allocate into. A frame's *region order*, what one
register *costs* when it is spilled, and the pointer discipline that
realignment and dynamic allocation force are machine and platform facts with
sharp internal contradictions. F4 and F5 are that correction; §4 carries them.

**Aggregate field layout — padding, bitfields, alignment of nested structs:
deferred to the language ABI.** That is C's rule, not the machine's, and it
belongs to whoever defines the source language. What the machine ABI says is
how a laid-out aggregate is *passed*, which is §3's second block.

## 6. Invariants this must preserve

- An ABI declaring no frame produces **byte-identical artifacts**, the way one
  with no `defabi` does today.
- The frame ops stay a declaration. AXIS does not search the instruction set
  for something that looks like a store; it checks that what was named is one.
- The published slot table is the only derivation. A consumer reading the
  manifest gets offsets, not a rule for computing them.
