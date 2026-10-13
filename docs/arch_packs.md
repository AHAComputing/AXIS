# Arch packs: an architecture an external project can link

AXIS emits C. Turning that into something a downstream project depends on was
left to the reader, and the exported ABI could not have served anyway.

## 1. Why the old ABI could not be extended

`emit-decode-abi-c` gives every description the same symbol names:
`axis_abi_decode`, `axis_abi_count`, twenty-two of them. Two of its outputs
cannot coexist.

⚠️ And they do not collide *loudly*. Linking a base archive and an extension
archive into one program succeeds: the linker takes the first member that
satisfies each symbol and never looks at the second. Measured, with RV64I and
RV32I in one program:

```
  rv64i has 338
```

There is no second answer and no diagnostic. A consumer with a base ISA and its
own extension gets one architecture and is told nothing, which is the worst
shape a defect can take here.

## 2. What a pack is: one library per facet

An architecture is not one library. A disassembler and an assembler are
different programs with different dependencies, and a consumer that only reads
code should not link one that writes it.

```c
const axis_decode_pack *axis_decode_pack_rv64i(void);   /* libaxis_decode_rv64i */
const axis_asm_pack    *axis_asm_pack_rv64i(void);      /* libaxis_asm_rv64i    */
```

Each library exports exactly one symbol, named for its facet and its
architecture; everything else is `static`. Two architectures share no name, and
neither do two facets of one.

⚠️ **This replaced capability flags, which lied.** The first version was one
table with `AXIS_PACK_HAS_DECODE | AXIS_PACK_HAS_ASSEMBLE`, and it shipped with
`HAS_ASSEMBLE` set on every pack while the table carried no assemble pointer --
a flag whose entire purpose is to stop a host calling a null one. A library
either exists on disk or does not. That is a fact a host can check without
trusting anything the pack says about itself.

`axis_pack.h` is the contract, and is **corpus-independent by construction** --
nothing in it derives from a document -- which is what lets a host compile
against it once and load architectures it has never heard of. `pack_check`
asserts that rather than trusting it: the header must be byte-identical across
every pack, and a version stamp lets a host refuse one it cannot read.

```
<name>/
  include/axis_pack.h                the contract, identical for every pack
  include/axis_decode.h              this description's tables
  include/axis_encode.h
  lib/libaxis_decode_<name>.{a,so}   a disassembler
  lib/libaxis_asm_<name>.{a,so}      an assembler
  pack.json                          what is here, and which symbol each answers to
```

A disassembler linking the decoder alone, with no assembler in the binary:

```
  decoder-only binary: 0x00b50533 -> ADD (add $rd, $rs1, $rs2)
```

And an assembler linking only its own library, reading the printed/encoded
relation across the ABI -- `SCVTF` encodes `scale` and prints `fbits`:

```
  SCVTF_D_X_FIXED field scale=0  prints 64, back to 0
  SCVTF_D_X_FIXED field scale=63 prints 1,  back to 63
```

## 3. Extending AXIS without AXIS knowing

`pack.json` naming the entry symbol is not decoration. A host that `dlopen`s a
pack it has never heard of cannot guess `axis_pack_<name>` without first
knowing the name; reading it from the manifest beside the library is how a
downstream project loads an architecture this repository was never told about.

A host compiled against `axis_pack.h` alone -- no architecture's headers, no
architecture's name anywhere in it:

```
  host loaded 3 pack(s) it was not compiled against:
    rv64i                        338 instructions, flags 0x7
    rvv                           50 instructions, flags 0x7
    aarch64_translation_seed     917 instructions, flags 0x7
    rv64i                      0x00b50533 -> ADD
    rvv                        0x00b50533 -> (nothing)
```

The division of labour that makes this work: **AXIS compiles descriptions and
knows nothing about any particular one.** A project with its own ISA writes its
own `.axisl`, runs `build_pack.py` on it, and loads the result beside packs this
repository ships. Nothing here has to learn its name, and nothing here changes
when it does.

`pack_check` proves that with a description AXIS does not ship: a corpus copied
out of the tree and renamed, so its name appears in no AXIS source. It builds,
composes and decodes like any other.

## 4. What the gate holds

* **One name each.** A pack exports exactly one symbol and nothing else, so two
  share no name. Dropping the `static` -- reverting to the old ABI -- fails
  with all twenty-three symbols listed.
* **Together.** Linked into one program, each answers its own count and decodes
  its own words, and declines the other's.
* **Unknown to the host.** Loaded through the contract alone, by manifest.
* **The same answers.** Decoding through a pack agrees with the roundtrip
  fixtures the encoder and decoder paths already prove. A pack that composed
  beautifully and decoded differently would be worse than none.

## 5. Assembling

`assemble(index, values, &word)` returns 0 rather than a word when the values do
not satisfy the encoding -- a refusal, not a wrong answer. `pack_check`
assembles each fixture's operand values back and requires the fixture's own
word, so the library is exercised rather than asserted; breaking the encode call
fails the gate.

Lane fixtures are decoded but not assembled, and counted saying so:
`VADD_VV__l0` lists `vs1__l0` beside `vs1`, which are elaboration artifacts
rather than encoded fields, and the pack carries the instruction they elaborate.
246 of 290 fixtures assemble back; the other 44 are lanes.

## 6. The lifter and the executor

Four libraries now. The two new ones are what turn "a disassembler you can
link" into "a machine you can link":

```
  lift pack: rv64i, 338 instructions
  exec pack: rv64i, 72 register slots, 6 state slot(s)
  lifted 0x00b50533 -> ADD, 3 operand(s): rd=10 rs1=10 rs2=11
  executed ADD: a0 = 42 (7 + 35), next pc 4, ok=1
```

### Why the contract had to grow

`axis_lift.h` and `axis_exec.h` are `static inline` throughout, so nothing
collides at link time -- but two descriptions cannot share a translation unit,
because `axis_lift_entry`, `axis_mem64`, `axis_exec_result64` and five more
would be redefined and every static table would clash.

So a pack is an **adapter**. Each library compiles its own description's headers
into its own translation unit and exposes shapes that derive from no document:
`axis_pack_lifted`, `axis_pack_mem`, `axis_pack_state_entry`,
`axis_pack_exec_result`. Two architectures share only `axis_pack.h`.

⚠️ `axis_insn_id` could not come along. It is a per-description enum
(`AXIS_INSN_ADD`), so the contract uses the instruction *index* the decoder
already speaks in. And two bounds the contract fixes -- 64 operands, 8 limbs --
are checked by `_Static_assert` in every pack, and a description that outgrows
them stops the build naming the bound rather than truncating a value to fit.
The operand bound was 32 until SVE's lane expansion needed 53 -- one lane of a
flag-setting byte compare reads sixteen predicate lanes beside sixteen data
lanes -- and raising it changed `axis_pack_lifted`'s layout, so it is ABI v2.

### The lifter is not the decoder, and `count()` differs

A scalable instruction is lifted once per lane -- `VADD_VV__l0`, `__l1` -- because
an executor performs each lane, while a disassembler wants the instruction the
lanes elaborate and the decoder carries `VADD_VV`. The same word names different
things through the two libraries, on purpose. It is in the header, because a
consumer that expected them to agree would be right about every fixed-width
architecture and wrong about every scalable one.

### An adapter is where things fall out

A pack translates between two sets of types, so the question is what goes
missing in the crossing. The gate runs the same word twice in one binary --
through the pack, and through `axis_exec_step64` directly -- and compares every
register, every state value, the memory and the whole result.

⚠️ Five mutations were needed to get there, and **four of them passed at first**:

| broken on purpose | caught by |
|---|---|
| lifter returns the wrong instruction | the lift/decode agreement |
| executor drops its state writes | the adapter differential |
| executor under-reports its register file | the adapter differential |
| executor always claims `ok` | a word that decodes to nothing, added for it |
| executor drops the wide limbs | AArch64 in the corpora, added for it |

The last two are the instructive ones. Every fixture succeeds, so `ok` was 1
everywhere and hardcoding it changed nothing; and neither default corpus had a
register wider than the word, so `result_limb[]` -- which the contract carries
*specifically* for that -- was never populated. The gate was green and reaching
neither.

### A collision in the pack itself

Building the AArch64 executor pack failed to link beside a test that also asked
for placeholder routines: `axis_impl_braa` and its family were emitted with
external linkage, so two packs that name routines collide, and so does a host
that supplies its own. That is precisely the failure packs exist to avoid, in
the pack.

`AXIS_IMPL_STUBS_INTERNAL` gives them internal linkage. A pack carries its own,
overrides nothing, and reports `unimplemented` for those instructions; an
embedder with the real routines builds without the define and links them.

## 7. What a pack does not carry yet

Eight libraries: `decode`, `asm`, `disasm`, `lift`, `exec`, `sim`, `jit`, `z3`.
**Not** the Rust executor -- the Rust side emits as one flat crate and would want a
crate-shaped answer rather than this one.

A registration entry now covers implementation routines (§6c), and the lifter
walks bytes rather than only words (§6d).

What is still missing is the **object format**: `walk` takes a buffer and a
base address, and finding `__text` in a Mach-O or an ELF stays the host's --
`tools/binary_coverage.py` does it in Python. That is deliberate. A pack is per
architecture and an object format is not, so a Mach-O reader in every pack
would be the same code compiled fifty-six times, and reading one is not
something a description says anything about.

## 6a. The simulator: the library that runs

The executor steps one word a caller has already fetched. `libaxis_sim_<name>`
**runs**: it fetches, decides what a trap does, and reports what each
instruction did. That is the difference between something a host drives and
something that goes.

`docs/pack_simulator.md` is the overview of this library as a cycle
simulator: the engines, every clause a core can declare, and the counters.

```c
axis_pack_sim_hooks hooks = { read, write, fetch, trap, retire, ctx };
void *machine = S->create(&hooks);          /* the library allocates it */
S->reset(machine, entry_pc, isa, state, n);
S->run(machine, 10000);
```

⚠️ **The machine is the library's to allocate.** Its size is the
description's -- a scalable register spans several slots -- so a host that
declared one would be declaring a shape it cannot know. It comes back as a
`void *`, which is also what lets two architectures run in one program.

⚠️ **`fetch` is not `read`.** An instruction fetch is not a data access: a host
may serve it from another space, or refuse it -- and refusing is what ends a
run. `trap` is what makes this a machine rather than a harness: it decides
where a raised trap goes and whether the machine stops.

The `retire` event carries what an instruction did *and* what it touched --
which registers it read, which memory it accessed, in order. Neither is a
semantic fact, which is why they are on the event rather than in the result;
they are what a timing model needs and a functional one does not.

⚠️ An event that could not carry what an instruction did would be a trace that
quietly lost some of it, so the adapter checks at **compile time** that the
description fits the contract's caps (`_Static_assert` on reads, accesses and
limbs) rather than truncating at run time.

`sim_pack_check.py` runs a program through the library and steps the same words
through the pack's executor: same pc, same mnemonic, same next pc, same write
-- then every register, every state slot and every byte of memory at the end.
A word that decodes to nothing is where a run ends, and the two *agreeing*
about that is part of the check.

### 6b. The fast simulator: both engines, one machine

The simulator interprets until a host hands it the JIT. Then a run of
translatable instructions becomes one block, and the first instruction that is
not -- a branch, a trap, anything with no stencil -- is interpreted:

```c
axis_sim_jit options = { 1, 64, (uint64_t)(uintptr_t)memory, sizeof memory };
S->jit(machine, J, &options);          /* the host hands over the translator */
S->run(machine, steps);
```

⚠️ **The host hands over the JIT.** They are separate libraries and a pack does
not decide for a program which of them it linked. ⚠️ **`memory_base` is a
promise, not a bound**: translated code computes an address and uses it, so a
host that names a buffer is answering for every address the program can reach.
Left zero, only instructions that touch no memory are translated. ⚠️ **A retire
hook turns translation off**: the emitted bytes call nothing, and a host that
asked for a trace should not be handed a quieter one.

`sim_pack_check.py` runs the same looping program through both engines and
compares every register, every state slot, every byte of memory, and where each
stopped -- then times them:

| corpus | of the timed run, translated | speedup |
|---|---|---|
| RV64I | 92% | **11.2x** |
| RV32I | 84% | **6.2x** |
| AArch64 seed | 96% | **24.0x** |

⚠️ Each figure is one draw. The gate builds its loop from the corpus's own
fixtures, and a draw with no backward branch does not loop -- so the run halts
after its own length, a tenth of a millisecond, and dividing one such run by
another reports scheduler noise to two decimal places. The gate refuses to
print a ratio for those now and says which of the two reasons applied.

⚠️ **The share is reported beside the speedup, and that is the point.** A JIT
figure with nothing next to it cannot be read: this table once said 1.25x for
AArch64, and the fact that mattered -- four instructions of a twenty-four
instruction loop were being translated -- was in a sentence beside it rather
than in the measurement. The share and the speedup now move together, which is
the only way to tell "the translator is slow" from "the translator was handed
four instructions at a time".

The gate also names the instructions in its loop that have no stencil, because
those are what end a block, and it draws the loop from the stencils the TABLE
has rather than from a rule about which instructions a stencil can carry. That
rule was the translator's limit when it was written and stayed after the
translator grew past it, so a gate measuring a JIT kept drawing its program from
the corner the JIT had once been confined to.

**A 32-bit machine's state is not a 64-bit array.** A stencil is compiled
against `iW* %state` where W is the description's word, so RV32I's stencils read
slot `i` at byte `4i` while the simulator's array put it at byte `8i`. Writing
64-bit slots for a 32-bit reader handed `csrrci` a zero where `fflags` held 5 --
and only inside a block, because the interpreter reads the named entries and was
right the whole time. The width is the translator's to say, and it says it per
stencil.

**What the list of machine parts cost, three times.** ⚠️ Which holes the
LIBRARY fills is enumerated by NAME in three places -- the simulator's block
builder, the JIT gate's harness, and the pack's own patcher -- and a part
missing from one of them is not a hole left unpatched. It is a hole that code
tries to bind to an *operand*, fails to find, and gives up the whole block over.
When the memory window arrived, 23 of AArch64's 24 loop instructions had
stencils and 20% of the run was translated, because every load and store quietly
stopped ending up in a block. The list wants to be one list.

**What it cost to get right.** A block is all-or-nothing and a step limit is
not, so running one that overshot left the two engines stopped at different
addresses -- the tail of a budget is interpreted now. A pc where a block could
not be built has to be remembered, or a machine whose instructions the
translator does not take pays for a failed build at every pc, every time round
the loop: that measured **0.55x**, slower than interpreting, not because
translating is slow but because asking is. And the rule that refused a stencil
with a `state` hole refused every load and store there is -- the hole is in the
IR and the compiler drops it when nothing reads it, so the JIT library
publishes `reads_state`, which is the question that was meant.

## 6c. A routine the description would not describe

Some instructions have nothing to generate. Pointer authentication signs with a
key the description does not hold; a cipher round is a table nobody wants
transcribed into a machine description; a random number is not a function. AXIS
names a routine for these and stops:

```lisp
(implementation axis_impl_braaz)
```

The generated executor then calls that symbol, and an embedder compiling
`axis_exec.h` into their own program defines it. That is the whole answer when
the artifact is a header.

⚠️ It is no answer at all when the artifact is a **library**. A pack is built,
shipped, and loaded by a program that cannot relink it -- "define the symbol" is
advice a consumer holding a `.dylib` cannot take. So the placeholders inside a
pack are not dead ends. Each calls through a bridge, passing the number the
description gave it, and traps only when nothing is registered for it:

```c
const axis_exec_pack *E = axis_exec_pack_aarch64(void);
for (int32_t i = 0; i < E->routine_count(); ++i) {
  printf("%s performs %s\n", E->routine_name(i), E->routine_mnemonic(i));
}
int32_t bound = E->register_routine("axis_impl_braaz", my_pac_routine);
```

`register_routine` returns **how many instructions that name covered**, and 0
when the pack names no such routine -- so a typo is reported rather than
silently ignored, and one routine covering four mnemonics is bound once.

A routine has the shape a generated effect has -- the decoded word, the register
file, memory, the pc, architectural state, and the result to report through --
but in the *contract's* types, not the executor's:

```c
typedef void (*axis_pack_routine)(const axis_pack_lifted *lifted,
                                  uint64_t *regs, int32_t reg_count,
                                  const axis_pack_mem *mem, uint64_t pc,
                                  axis_pack_state_entry *state, int32_t state_count,
                                  axis_pack_exec_result *out);
```

That matters: a host that loads a pack has `axis_pack.h` and a `dlsym`, and
`axis_lifted` and `axis_mem64` are per-description shapes it cannot see. The
pack translates at the one boundary where the two meet, which is also where
`out.next_pc` is **seeded** with what the executor already decided -- a routine
that only writes a register must not have to restate where the machine goes
next, and one that did not know to would make every such instruction jump to
zero.

Each library carries its own registry. `axis_exec_pack` and `axis_sim_pack` are
separate libraries with separate copies of the placeholders, so binding on one
says nothing about the other, and a host that runs both binds both.

A pack built the other way -- against routines an embedder actually linked --
reports `routine_count() == 0` and refuses to register. There is nothing to
register: the bodies are in the library already, and letting a host replace them
at runtime would be offering to override code the build chose.

`tools/routine_pack_check.py` holds this, from a harness that includes
`axis_pack.h` and nothing else: that unbound is the same trap an undescribed
instruction reports, that the routine is told the operands the lifter decodes,
that what it does to registers, memory, state and the pc comes back through the
contract, that binding one name does not bind another, that clearing restores
the trap, and that the simulator's registry works after the executor's was
cleared.

## 6d. Bytes to instructions: the lifter walks an image

The lift library answers about a word a caller already has. A consumer holding
a binary has **bytes**, and the one thing it cannot work out for itself is the
step between two instructions:

```c
axis_pack_walked rows[256];
int32_t found = L->walk(text, text_bytes, 0x400000, "rv64i", rows, 256);
for (int32_t i = 0; i < found; ++i) {
  printf("0x%llx  %-10s %s\n", rows[i].address,
         rows[i].index < 0 ? "(data)" : L->mnemonic(rows[i].index),
         rows[i].ends_block ? "<- block ends" : "");
}
```

⚠️ Stepping a fixed four bytes is wrong for any description that is not all one
width. `binary_coverage.py` read 60.7% on a compiled object because a 16-bit
`c.nop` shifted everything after it, and the description was fine -- the finding
was about the walk. So `axis_lift_entry` now carries the instruction's own
encoding width (**not** `state_width`, which is the machine's word: a 64-bit
machine's instructions are 32 bits and its compressed ones 16, all in one
table), and the walk steps by it. Bytes that decode to nothing advance by the
narrowest instruction the description has, because a real section has data in
it and stopping at the first byte that is not an instruction would end every
walk at the first literal pool.

`block()` is the same walk stopped at the first instruction that ends a block --
what a consumer lifting to IR asks for, and what a JIT needs before it can
translate anything.

### `ends_block` has three values, and the third is the point

```
  0  no -- the description says what this does and none of it is the pc
  1  yes -- it writes the pc, or it traps
  2  this build CANNOT SAY
```

A consumer that treats the field as a boolean is right, which is the point of
the encoding. But `2` is not `1` with less confidence and it is certainly not
`0`: AArch64's `braaz` authenticates a pointer and jumps to it, its whole
description is one line of prose and an `(implementation axis_impl_braaz)`, and
a walker that called it an ordinary instruction would stride past a branch and
report what follows as the same basic block. Bytes that decode to nothing are
`2` for the same reason. An index the library does not have is `2` as well --
every other accessor answers a bad index with a harmless zero, and here zero is
the dangerous answer.

`tools/lift_walk_check.py` lays an image down out of the description's own
fixtures, at each instruction's own width, with a word that decodes to nothing
planted in the middle, and requires the library's walk to match a reference
walk row for row -- offsets, addresses, widths, operands, and `ends_block` --
while every instruction actually laid down must come back at the offset it was
laid at. It draws the scarce cases on purpose: an instruction that ends a block,
one the library will not vouch for, one whose operand the word does not carry.
Eight mutations, seven caught; the eighth is named in the gate's own docstring
as the column no corpus can exercise.

## 7a. The JIT, and the one thing AXIS cannot emit

`libaxis_jit_<name>` translates instructions into host machine code by copying
compiled *stencils* and patching their operand holes -- copy-and-patch, the
technique `docs/jit_stencils.md` measures.

⚠️ It is the only library with a half AXIS does not emit. Everything else in a
pack is derived from the description; a stencil's bytes are what a **compiler**
made of the description, on one host. So the work is split, and neither side
describes the other:

* `emit-pack-jit-c` writes the patcher, the vtable, and the *shape* of the
  table (`axis_jit_stencil`, `axis_jit_reloc`).
* `tools/jit_table.py` compiles `emit-stencil-ll`, reads each stencil's bytes
  and `adrp`/`add` sites out of the object, and writes `axis_jit_table.h`.

If those drift apart the library does not compile, which is the point of
splitting it this way rather than having the build emit C it also describes.

A stencil publishes what each hole **binds**, by the operand's own name:

```c
int32_t s = J->stencil_for("ADD");
for (int32_t h = 1; h < J->holes(s); ++h) values[h - 1] = value_of(J->hole(s, h));
J->translate(ops, n, buffer, size, exec_base, regs_addr, &used);
```

A count alone would have made a consumer guess the order AXIS emits stencils
in. Slot 0 is the register file, which the library fills itself; the caller
supplies the rest and owns the mapping and cache maintenance, because that is
the host's business and not the architecture's.

Where the bytes do not run, `pack.json` says so by name:

```json
"declined": { "jit": "Linux/x86_64: the patcher AXIS emits is AArch64, and this reader is Mach-O" }
```

### Loads, stores and atomics, and what they cost the contract

A JIT that only does arithmetic is a demonstration. The library translates
memory instructions too, and that changed the contract rather than extending
it: an instruction that loads needs the memory it reads, one that reports a
conditional write needs somewhere to report it, one that reads a rounding mode
needs the state, and one that reads the pc needs to be told which. Those belong
to the **machine**, not to the instruction, so they are given once per block:

```c
axis_jit_machine machine = { regs_addr, memory_addr, scratch_addr, state_addr };
J->translate(ops, n, buffer, size, exec_base, &machine, &used);
```

Each hole now carries a *kind*: the library fills the machine's own parts and
the caller supplies only the operands (`J->values(stencil)` says how many).
RV64I publishes 157 stencils where it published 66.

⚠️ **Translated code reaches memory raw.** The address an instruction computes
is used as it is -- there is no call in the emitted bytes, so there is nothing
to bound it with. A host that hands over a buffer must be able to answer for
every address the block can reach. `jit_pack_check.py` pays that price the way
`jit_stencil.py` does: a block carries a memory instruction only while the
registers it reads still hold what the harness seeded, because an earlier
instruction writing its base is a wild address rather than a wrong answer.

⚠️ **A relocation the patcher does not apply is a stencil that must not ship.**
AArch64 lowers some conditional selects through a jump table, leaving a
`PAGEOFF12` to `lJTI111_0` -- a table the copy does not bring along. The
builder skipped such relocations silently and published the stencil anyway; the
result was an illegal instruction the first time AArch64 ran a block. Sixteen
stencils are declined by name now.

**What building it found.** `jit_pack_check.py` runs each translated instruction
against the *executor in the same binary* -- the executor being what the ladder
already holds to the golden model. On the first run 16 of 66 disagreed: the
stencils indexed the register file with the raw field, so `c.sub`'s `x8`-`x15`
window (`index_offset: 8`) landed on `x1`, and RISC-V's hardwired `x0` was
written like any other slot. The pre-library gate had compared stencils against
a reference that indexed the file raw *too*, so both were wrong together and
agreed. `emit-stencil-ll` now does the lifter's arithmetic and refuses to emit a
stencil for a class it cannot model.

## 7b. The solver library, which carries no semantics

`libaxis_z3_<name>` hands a consumer the architecture as **terms a solver
holds** — what a symbolic engine needs to ask questions about an instruction
rather than run it.

```c
void *handle = Z->open(ctx);                       /* a Z3_context */
int32_t add = Z->index_of(handle, "ADD");
void *term = Z->apply(handle, add, operands, Z->arity(handle, add));
```

⚠️ **It carries no semantics of its own.** `emit-smt2`'s `axis_instr_*`
functions are already proven equal to the golden model; this library ships that
text and binds it into the caller's context. A third spelling of `fadd_rm` —
after the executor's and the symbolic backend's — is exactly what it exists to
avoid. What it adds is plumbing: parsing, naming, arity, operand order.

⚠️ **Z3's parser inlines `define-fun`**, so the definitions cannot be asked for
again once parsed. What can be done is to bind each instruction once *in the
same text*: an assertion applying it to named constants. Parsing hands those
back already expanded, and `apply` is `Z3_substitute` of the caller's terms for
the constants — one parse for a whole architecture.

⚠️ **The solver's types do not appear in the contract.** A `void *` is a
`Z3_context` or a `Z3_ast`, documented rather than included, so a consumer of
the other seven libraries needs no solver headers to compile against
`axis_pack.h`. Where the host has no solver, `pack.json` says so by name.

### Effects, which are most of what a symbolic engine asks

A value function answers "what does `add` compute". A branch's condition, a
store's address, a guarded write's guard are none of them a value — and until
`emit-smt2` emitted them, a consumer had terms for the arithmetic and nothing
for the parts that make a machine go.

```c
int32_t beq = Z->index_of(handle, "BEQ");
int32_t when = Z->effect_term(handle, beq, 0, "guard");   /* (ite (= rs1 rs2) 1 0) */
int32_t to   = Z->effect_term(handle, beq, 0, "value");   /* (bvadd pc (sign_extend imm)) */
```

An instruction is therefore **not one term**: `value_term` is what it computes,
and `effect_count`/`effect_kind`/`effect_place`/`effect_term` are what it does.
Each part is its own term, taking the instruction's operands, the `pc`, the
state its ISA declares, and each operand's value on entry (`__input_rs`, which
is what a compare-and-swap's guard reads).

RV64I publishes 480 effect terms and declines 226 by name: 126 exception words
(`inexact` asks whether the exact result was representable, which the float
theory never forms), 100 loads (a memory array in the signature is a separate
piece of work).

⚠️ An `unreachable!` had guarded those exception words for exactly the right
reason — "an exception word is a state write, not a value" — and lowering the
effects made it reachable. A panic is the wrong answer to "can this be stated";
it declines by name now.

**What the gate found.** The semantics being proven elsewhere, `z3_pack_check.py`
checks everything around them — and everything around them was wrong at first:

* a parameter can be an operand *or* a piece of architectural state, and only
  its **name** says which. Bound by position, `csrrw.frm` handed a register's
  contents to a rounding mode;
* an operand's value names a **slot**, not a register number — a compressed
  field's 1 is `x9` — which is why `axis_lift_pack` now publishes
  `register_slot`;
* an operand can be **wider than a slot**: a vector register is two of them,
  and passing one zero-extended the other half away.

Effects brought their own: the executor **writes into the register array it is
given**, so binding a term's operands afterwards fed a post-indexed store the
base it had just updated. And effects are **sequential** — each sees the
operands as the ones before it left them — so a part whose term reads an
operand an earlier effect wrote is counted rather than compared against the
wrong state. The directory itself is checked against the file's own naming: a
term for effect 2's value is called `axis_effect_<name>_2_value`, and a
directory that handed out effect 0's parts for every effect passes every
individual comparison while saying the wrong thing.

It also asks what the library does with a question it should refuse: a wrong
arity, a mismatched sort. `Z3_substitute` does not refuse — it returns a term in
an error state that a caller would carry into a solver — so `apply` checks
first, and 64 ill-formed calls per corpus confirm it.

## 7c. The symbolic library: a machine made of terms

The solver library hands out the terms an instruction **means**. This one runs a
machine out of them:

```c
void *m = S->create(ctx, Z, 64);        /* registers are free variables */
S->step(m, word, "rv64i");
Z3_ast r1 = (Z3_ast)S->reg(m, 1);       /* what x1 is now, as a term */
for (int32_t i = 0; i < S->paths(m); ++i) {
  axis_sym_path way = S->path(m, i);    /* constraint, and where it goes */
}
```

Registers hold terms, memory is `(Array (_ BitVec 64) (_ BitVec 8))`, the pc can
be a term, and named state is one term per declared slot. It carries **no
semantics**: every value comes from `axis_z3_pack->apply`, so a consumer gets an
engine over the same meaning its executor has rather than a second opinion that
agrees on the fixtures somebody happened to write.

⚠️ **A guarded `setpc` is two paths, not one.** A conditional branch does not
choose -- it says *when this, there* -- so `paths()` returns both with
complementary constraints, and the caller forks by `clone()`. An engine that
returned only the taken way would be exploring a different program.

### What holds it

`tools/sym_pack_check.py` does not check that the terms look right. It runs the
machine from free variables, **binds** those variables to concrete numbers, asks
the solver to evaluate, and requires every register to equal what the executor
computed from the same numbers. 170 comparisons across three architectures.

⚠️ And it runs the library the way a consumer does, which is a different
question from stepping one instruction. A **basic block** of them, so a register
feeds the next instruction and the pc moves and memory carries across; a
**clone**, because a fork is a copy and two ways out of a branch write different
registers; an **assumption**, which belongs to the machine that made it. None of
that is touched by a single step, and all of it is what a consumer does on its
first use. The pc after a run must not still be zero -- a machine that agrees
about every register and stands still ran every instruction at one address.

⚠️ The run is a basic block **by construction**, and the reason is worth
keeping: the executor is told which address it is at, so after a `jal` the
machine is somewhere the harness did not compute. A run with a branch in it
compares two engines executing different addresses, and it reads as the
symbolic machine getting `jalr`'s link value wrong.

That check found four things, each a silent skip rather than a wrong answer:

- a term takes the instruction's operands **and** the pc, every state slot, and
  `__input_<operand>` -- the entry value that makes `rd = rd + imm` mean the old
  `rd`. Binding only the first kind refused every branch in the description.
- a pure value's destination may be **`inout`**: taking only `out` left every
  compressed `c.addi` unwritten, and the machine agreed with the executor about
  thirty instructions while silently doing nothing for ten.
- a register is written in **limbs**, and what lies outside the value is the
  class's business -- writing `d1` clears the high half of `v1`.
- ⚠️ an effect the solver library has **no term for** is a refusal. `emit-smt2`
  declines the `load` operator, so a machine that shrugged there reported an
  `ldr` agreeing about every register except the one it was supposed to write.

### Loads, and who does which half

A load cannot be an SMT function. `emit-smt2` writes functions over bitvectors,
and a function over bitvectors has no memory to read from -- so `axis_instr_lb`
does not exist and cannot, short of threading an Array sort through the whole
IR.

⚠️ Its **address** can. That is a plain expression, and the machine that has
memory can do the `select` itself -- which is the division of labour a store
already has, where the solver library publishes where and what and the consumer
performs it. So an effect whose value is exactly a load publishes three more
things: the address as a part, the access width, and whether it sign-extends.
The symbolic library reads the bytes little end first, the same decomposition
the executors make, so a term and a run agree about which byte moved.

⚠️ "Exactly a load" is the rule, and it is not a hedge. `lb` is
`rd = load(i8, signed, rs1 + imm)` and the whole of its value is the load; an
instruction that added something to one would need the sum rendered, and the
sum is the part that cannot be written. Saying which of the two a description
has is why the other still declines by name.

One thing had to move for this to reach anything. A single-effect instruction
whose value is its own function gets no effect parts at all -- the pack points
the effect at `axis_instr_<name>` -- and for a load that is a pointer to the one
term that does not exist. `lb` came back as an instruction nobody could say
anything about until the short circuit learned to skip a load.

rv64i went from 47 instructions compared to 55, rv32i from 39 to 59, AArch64
from 41 to 56.

⚠️ And the gate had to stop being able to skip them. A register holding
`select(mem, addr)` over a FREE array evaluates to no numeral, and the
comparison passed over it -- so every load "agreed" by not being looked at. The
array is pinned to all zeros now, which is what the executor's hook answers, and
a register whose term does not evaluate is a failure rather than a shrug.

## 7d. What it costs: a scoreboard and a cache

An instruction count is not an answer. Two descriptions that retire the same
number of instructions can differ by a factor in time, and the whole point of
adding an instruction to a machine is to find out which way. So the simulator
grew two things that cost a run, and they are deliberately different kinds of
thing.

The first is the **scoreboard**, and it reads what the description already
declared. Every instruction in every corpus carries a `latency` and a
`throughput`, and until this existed nothing read either -- which made them free
text a designer typed, and made any co-design number built on them a quotation
of its author. The model is first-order and the name says so: in order, single
issue, no prediction. What it knows is the declared numbers and which registers
each instruction names, and that is enough to tell a dependent chain from an
independent stream, which is the question an instruction count cannot be asked
at all.

The second is the **cache**, and it is *not* in the description:

```c
typedef struct axis_sim_cache {
  uint32_t lines;        /* total lines; 0 for no cache */
  uint32_t ways;         /* 1 is direct-mapped; 0 means 1 */
  uint32_t line_bytes;   /* 0 means 64 */
  uint32_t miss_cycles;  /* what a miss adds to the instruction that caused it */
} axis_sim_cache;

void (*configure_cache)(void *machine, const axis_sim_cache *cache);
uint64_t (*cache_hits)(const void *machine);
uint64_t (*cache_misses)(const void *machine);
void (*touch_memory)(void *machine, uint64_t addr);
```

⚠️ This is a **microarchitecture parameter** and it is configured per machine,
like the translator is. A description says what instructions *mean*; how many
lines a machine keeps and what a miss costs is a property of one machine that
runs them. In the language it would make every description claim a cache it has
no business claiming -- and every consumer of the description inherit a number
nobody chose.

`touch_memory` is the odd one, and it earns its place: it tells this machine's
cache that an access happened which its own instructions did not make. An
accelerator sharing the cache, a DMA engine, a replayed trace, another core.
Whether a co-processor's traffic evicts the core's working set is a co-design
question, and a machine that only ever sees its own loads cannot be asked it.

### The stall belongs to the instruction, and that was twice wrong

A miss adds `miss_cycles` to `pending_stall`, and the scoreboard settles it.
Getting *which* instruction pays took two corrections, both of them plausible
wrong answers:

* the step used to account **before** lifting, which gave every instruction the
  stall of the one before it. A program whose last load missed reported the
  penalty on the instruction that followed. Lifted before, accounted after.
* the stall used to be cleared **before** the step, on the theory that nothing
  should carry over. That threw away exactly what a host reports through
  `touch_memory` -- which by construction happens between steps -- and charged
  it nothing. It is cleared after, by whoever accounts, and by the step itself
  when there was nothing to account for.

### What holds it

`cache_check.py`, by properties rather than by a second copy of the model,
because arithmetic agreeing with itself proves nothing:

* a working set that **fits** misses once per line and hits thereafter, so a
  second pass over the same addresses misses nothing;
* one that **does not fit** misses every pass, the line it wants having been
  evicted by the pass before;
* **two ways hold two colliding lines and not three**, and A, B, A, C, A tells
  least-recently-used from first-in-first-out -- the one trial that does, and
  the gate did not catch a FIFO victim until it was added;
* **hits plus misses is every access**, so nothing is counted twice or lost;
* **configuring a cache empties it**, which only a second configure on a live
  machine can see -- also found by mutation, every other trial starting fresh;
* **an unconfigured cache accounts for nothing**, which is what an option that
  is off has to mean;
* and the one that makes it a term in an answer rather than a counter: the same
  program under two miss penalties differs in cycles by exactly
  (misses x penalty).

⚠️ One level, LRU, no prefetch, no write policy, no coherence. What it can tell
you is a working set that fits from one that does not. What it cannot tell you
is what a real memory system does, and the model says which.

### One description is one design point, and a sweep is a curve

A cost model is not yet a study. The question a co-design study asks is *hold
the program fixed, vary the machine, and read the curve* -- and the stack could
not ask it, because until a miss cost cycles every variant of a description
reported the same number. `sweep_check.py` is the first gate that varies a
machine rather than checking one.

Its workload is built for it. The programs the other gates assemble are
straight-line fixtures from a corpus's own tests: they touch almost no memory,
and sweeping a cache over one draws a flat line. So this one builds a **strided
walk** -- W distinct lines, walked twice, from whatever load the description
offers -- and because W is known by construction the curve is checkable
arithmetic instead of a picture:

* **monotone**: a bigger cache never misses more;
* **the knee is the working set**: below W lines the second walk pays what the
  first did, so the program takes 2W misses; at W and above the second walk is
  free and it takes W. The transition is exact and lands on the number the
  program was built around;
* **the compulsory floor**: nothing misses fewer than W, because no cache hits
  a line that was never fetched;
* **the curve is a time**: cycles fall with misses by exactly the miss penalty,
  so the point that misses least is the point that runs fastest.

### Two things the gate assumed, and neither was true

**The stride.** The walk steps its immediate by a fixed number of units, and
the first version multiplied that by a 64-byte line to get an address. AArch64
*scales* its immediate by the access size and RISC-V does not, so the same
program strode 8x further on one machine than the other: a 32-line working set
folded onto four sets and missed everywhere, at every cache size. The stride is
now **measured** -- the harness reads the first addresses off the memory
interface and sizes the cache line to match. What one unit of an immediate
moves an address by is the description's business, and the gate had no standing
to guess.

**Spatial locality.** The first walk touched each line once, which tests only
whether a line is *still there*. A cache that made every address its own line
passed it unchanged -- and mutation testing said so, by removing `addr /
line_bytes` and watching nothing happen. A line is a **unit of transfer**: the
walk now touches each line twice, at the front and at the middle, so the second
access is free because the first one fetched the line. That is half of what a
cache is for and nothing here had measured it. Two accesses per line also made
the stride bigger than one byte, without which the division being mutated was
an identity on RISC-V and unobservable by construction.

⚠️ Instruction fetch does not go through the cache, deliberately. A unified
cache would put the loop's own lines in competition with the array's and move
the knee to wherever the program happened to be linked -- a worse measurement
and a much worse gate.

### The axis a designer actually edits

A sweep over cache geometry varies the *machine*. A designer varies the
**description**, and a stack where changing a number in the source does not
change the answer is a stack where the source is decoration. `cycle_check`
proves the simulator uses the latency a description declares; it does not prove
that a description you *edited* produces a machine that agrees.

`variant_check.py` does. It raises one instruction's declared latency, rebuilds
the pack from the edited text, and runs the same program on both machines:

* **the edit reaches the artifact** -- checked first and on its own, because
  every property below would also fail if it silently missed, and "the gate is
  red" is a different finding from "the edit did nothing";
* **and reaches nothing else** -- `(latency 1)` appears 338 times in one
  corpus, and an edit that caught them all would move the chained program and
  the independent one together, passing three of the four properties while
  measuring something else;
* **a dependent chain moves by exactly the difference times its depth**: K
  chained instructions at latency L take L x (K-1) + 1 cycles, so raising L by
  D raises them by D x (K-1). MUL at 3 -> 7 moves eight chained instructions by
  28 cycles, and the gate will not accept 27 or 29;
* **an independent stream does not move at all**. Latency is what a result
  costs whatever is *waiting* for it. Without this the gate would pass a model
  that charged latency to every instruction regardless of whether anything
  waited -- which is a stall, not a latency, and the mutation that makes that
  substitution is caught here and nowhere else;
* **the architecture is untouched**: both machines retire the same instructions
  and leave the same registers, fingerprinted across the whole file rather than
  sampled. A timing annotation that leaked into a result would be a description
  whose costs and whose meaning are not separable, and a co-design number taken
  from one could not be attributed to either.

⚠️ Latency is the axis because it is the one the description declares and the
simulator reads. Sweeping an instruction **in or out** is the other half of "is
this extension worth it", and it needs two kernels that compute the same thing
-- which needs hand-written pairs or a compiler that will select the new
instruction. Neither exists here yet, and the gate does not pretend to be it.

### A machine is not its instruction set

The cost model issued one instruction at a time, and AXIS describes VLIW
packets, unit-typed slots and multi-core fabrics. A four-wide machine with
three adders reported the cycle count of a scalar one -- so the language's
headline capability was invisible to the only consumer meant to answer "is this
worth it".

The pieces already existed and did not talk. Instructions have named their
`unit` all along; `emit-vliw-itinerary` publishes issue width, unit counts and
slot masks; `defcore` named a core and described no pipeline; and the lift
table carried `unit` to Python and **not** to C, which is why nothing at
runtime could contend for anything.

`defcore` is now the pipeline description -- the dynamic-issue counterpart to
what `defpacket` already does statically for VLIW:

```lisp
(defcore wide
  (kind rvmt) (implements iw32)
  (issue-width 4)
  (units (alu (count 4) (pipelined true))
         (mul (count 1) (pipelined false))))
```

⚠️ A unit declares **no latency**. The instruction already declares one, and a
second place to write the same number is exactly how a field becomes free text:
`expected-speedup` is 1.0 on all 338 instructions of one corpus precisely
because nothing ever had to agree with it. A unit says how many of it exist and
whether a new operation may start before the last finishes -- and those are the
two facts no declared throughput can express.

The ISA pack is the loadable plugin the machine drives, and that ABI already
existed. What was added is `core_count`, `core_name` and `select_core`, and
selecting nothing -- the default -- is the first-order model, so no description
written before this form suddenly claims a pipeline.

#### The anchor

A core of one issue slot with one pipelined copy of every unit **is** the
first-order model, and `core_check.py` requires it to agree cycle for cycle on
the same programs. A second timing model that agreed with nothing would be a
second thing to be wrong; making the old model a configuration of the new one
is what stops that.

#### What mutation testing added to the corpus

Two cores in `issue_width.axisl` exist because a mutation survived without
them, and both are worth stating plainly:

* **`serialmul`** has an *unpipelined* multiplier. Without it, `pipelined` was
  a flag nothing read -- every unit in the corpus was pipelined, so a model
  that ignored the flag agreed everywhere.
* **`narrowport`** has *more units than issue slots* (four adders, two slots).
  That is the only shape where issue width strictly binds: everywhere else the
  units run out first or at the same moment, so a model ignoring width entirely
  agreed with every other core. It is also the physically interesting case --
  the front end, not the adders, is the limit.

5/5 mutations caught after. The corpus reports `narrow:8 wide:2 choked:8
narrowport:4 serialmul:2` on eight independent adds, and a dependent chain
costs 22 on every one of them, because no width helps instructions that wait
for each other.

⚠️ `kind` is still closed to `{rvmt, simt}`. The structural families -- in
order, out of order, barrel-threaded, SIMT -- are the next axis, and they are
hand-written models rather than anything derivable from an ISA, which is why
gem5 does not generate its CPU models from its ISA description either.

### The cache a machine has is the one its description declares

`defmemory` has carried `size-bytes`, `latency-cycles`, `ports` and `banks`
since long before anything here could run a program, and nothing ever computed
with any of them. The same shape `area-estimate-um2` still has, and the same
shape `latency` had until a scoreboard read it.

⚠️ **This is a correction to what the cache landed with.** The argument for
keeping a cache out of the description was right about the *ISA* and wrong
about the *language*. An instruction means the same thing on every machine, so
a cache has no business on `definstruction` -- but AXIS has machine-side forms
too, and a machine is exactly where a cache lives. The distinction that matters
was never "in the language or out of it"; it is **which form says it**.

So a core names the memory it runs against, `defmemory` gained the two fields a
cache needs that a scratchpad does not, and selecting a core applies it:

```lisp
(defmemory l1d (kind cache) (size-bytes 4096) (line-bytes 64) (ways 1)
               (width-bits 64) (latency-cycles 10))
(defcore narrow (kind rvmt) (implements iw32) (memory l1d) (issue-width 1) ...)
```

The runtime `configure_cache` stays: the description is a **default, not a
ceiling**, and a host that wants a different cache asks for one after selecting
the machine. Validation refuses a geometry that is not one -- lines that do not
divide the size, ways that do not divide into sets, ways with no line size.

#### What the gate holds, and what mutation added to it

`described_cache_check.py` checks that each core's knee lands where its own
description puts it, that a core naming no memory accounts for nothing, that
moving between cores replaces the cache rather than keeping the old one, and
that a host override wins.

Two of its checks exist because a mutation survived without them:

* **the miss COST, in cycles.** Counting hits and misses on a cache whose
  penalty is ignored looks perfect -- `latency-cycles` would have stayed
  exactly as unread as it was. The gate now steps a program with a forced miss
  in front of every instruction and requires the declared penalty.
* **a walk that COLLIDES.** Every memory in the corpus was direct-mapped and
  every walk sequential, so a model ignoring the declared `ways` agreed
  everywhere. One memory is two-way now, and each core is walked with exactly
  as many colliding lines as it has ways (all stay) and with one more (none
  do).

### A taken branch costs what the machine says it costs

A machine that does not predict fetches the fall-through, and when the branch
goes elsewhere the front end starts again. That redirect is most of what
separates a core with a predictor from one without, and the cost model had no
way to say it -- every branch was free, on every machine.

```lisp
(defcore redirects (kind rvmt) (implements iw32) (issue-width 1)
  (branch (penalty 6))
  (units (alu (count 1) (pipelined true)) ... (br (count 1) (pipelined true))))
```

Three things about how it is charged, each of which is a different machine if
got wrong:

* **the redirect is paid by what FOLLOWS**, not by the branch. A taken branch
  costs what any instruction costs; what it does is leave the front end
  fetching the wrong address. So the front end has a ready time, and the next
  instruction waits for it.
* **only a TAKEN branch pays.** A conditional branch that falls through costs
  nothing -- the front end was already fetching the right address. Without a
  program that falls through, the gate would pass a model charging every branch
  *instruction* rather than every *redirect*, which is a plausible wrong
  answer.
* **taken-ness is a fact about the REGISTERS**, not the encoding, so the model
  asks the pc: did it go somewhere other than the next instruction? The two
  programs the gate runs are the same words at the same addresses, differing
  only in which registers the branch compares.

The gate's program ends with a non-branch, because the redirect is paid by a
successor and a program ending in a branch hides one whole penalty. Six taken
branches at a declared penalty of six cost 36 cycles; the same branches falling
through cost nothing. 4/4 mutations caught.

⚠️ `(branch (penalty N))` is the cost of **not predicting**. A predictor --
bimodal, a table, an indirect target buffer -- is the next thing this form
grows, and it needs a loop to be worth anything: a branch executed once is a
cold miss whatever the predictor. Saying which of the two a number describes
matters more than the number.

#### A trap this table has set three times

The Python lift table carries `unit`, `latency` and `ends_block` as keys whose
value is `None`. `entry.get("ends_block")` therefore returns None rather than a
default, and a gate that trusted it found no branches at all. The C table has
the real values -- it is the one a timing model reads -- and the fix each time
was to ask the description through `emit-json`, or to ask what the instruction
*does*: a branch is something with a `setpc` effect, whatever any flag says.

### What a predictor buys is visible only over a loop

`(branch (penalty N))` says what a redirect costs. `(predictor bimodal
(entries M))` says how often the machine pays it, and those are different
questions. A branch executed once is a cold miss whatever the machine keeps, so
a predictor cannot be measured on straight-line code at all.

⚠️ **No predictor is the predictor that always guesses "not taken".** A machine
without one is not a special case in the model -- it is the degenerate
configuration, mispredicting on exactly the taken branches. That is what keeps
the model that came before a configuration of the model that came after, and
`branch_check.py` still holds that end.

`predictor_check.py` runs a countdown loop at two trip counts, assembled from
the corpus's own instructions -- the decrement is an ordinary add of a register
the harness seeded with minus one, because a loop built from an instruction
invented for the gate is a loop no description has to contain.

| | 8 iterations | 16 iterations |
|---|---|---|
| no predictor | 7 mispredicts | 15 |
| bimodal | 3 | 3 |

**That the cost stops scaling is the property.** A predictor that helped
proportionally would be a faster machine rather than a predicting one. Three is
two to warm a two-bit counter and one to leave the loop, and it is three
whichever trip count you ask for.

#### Two things the loop had to grow

* **An instruction after it.** A redirect is paid by a successor, and the
  branch a predictor gets wrong is the one that *leaves* the loop. With nothing
  behind it that mispredict costs nothing, and the cycle count and the
  mispredict count then disagree by exactly one penalty -- a real discrepancy
  about a program that ends badly rather than anything about predicting.
* **A second branch that never goes anywhere.** With a single branch in the
  program, any index at all -- including a constant -- gives the same answer,
  and a table that put every branch on one counter passed unnoticed. Two
  branches with opposite habits interfere if they share a counter, which is the
  whole reason a table has a size. 5/5 mutations caught after.

⚠️ A methodology note worth more than the feature: one gate run in this session
reported a failure measured against a **mutated binary** -- a mutation script
was still running in the background and had the source patched. The numbers
looked like a real aliasing bug. Mutation scripts and gate runs cannot share a
tree, and a surprising result while one is in flight should be re-measured
before it is believed.

### Out of order, which is a different algorithm

Everything above computes one instruction at a time and never loops over time.
Out-of-order execution cannot be done that way: what makes a machine out of
order is the set of things simultaneously in flight, and there is no way to
know that without holding them. So `(window (rob N) (issue-queue M)
(commit-width W))` selects a **tick loop** — issue whatever is ready from
anywhere in the buffer, retire strictly in order — and a core with no window
uses the in-order path untouched.

```lisp
(defcore ooo (kind rvmt) (implements iw32) (issue-width 2)
  (window (rob 32) (issue-queue 32) (commit-width 2))
  (units (alu (count 2) (pipelined true)) (mul (count 1) (pipelined true)) …))
```

The property, and it is the only one that matters: **an instruction waiting on
a slow producer does not hold up the ones behind it.** No in-order machine can
do that at any width or unit count. Six independent producer/consumer pairs
cost 19 cycles in order, 11 on a six-entry window, 10 on a thirty-two-entry
one.

⚠️ **Cycle-accurate for the structures it has, over a correct-path trace.** It
does not fetch or execute the wrong path — the functional side is decoupled and
only ever runs what actually ran — so wrong-path cache pollution and wrong-path
prefetch are invisible. A mispredict is modelled as the front-end drain it
causes, which is the part this model can honestly see. Which half is modelled
matters more than the number.

#### One loop, and in-order issue is one line of it

The wart this landed with — two algorithms reporting two different quantities —
is gone. There is one pipeline now, and the difference is a single line:

```c
if (!axis_ooo_ready(m, e)) { if (in_order) { break; } continue; }
```

A machine without a window stops at the first instruction that is not ready; a
machine with one looks past it. Everything else — dispatch, execution, in-order
retirement — is the same machinery, which is what makes the two comparable at
all. **A dependent chain now costs exactly the same in order and out of order**,
which is the anchor the in-order configuration had never had.

An in-order machine still holds instructions in flight, so it has a buffer
whether or not a description names one; what it lacks is the ability to issue
past a stall. Undeclared, the buffer is deep and the retire width is the issue
width, so a structure a description did not speak about does not silently
become the constraint.

⚠️ The machine with **no core selected** is still a different and cruder model:
an analytical scoreboard that reports when an issue slot frees, roughly a
latency earlier. That is the model `cycle_check` and `variant_check` hold, and
it is a deliberate cheap path, not the pipeline.

#### Three bugs this unification found

Each was invisible while the two models were separate, and each produced
plausible numbers:

* **The reorder buffer had two defaults.** Entries were stored modulo 64 and
  looked up modulo 1, so every producer lookup missed, every miss read as
  *already retired*, and a dependent chain ran as fast as independent work. The
  model was not wrong about dependences — it never saw any.
* **The retire width was clamped to one at the table.** A core that did not
  declare one retired a single instruction per cycle, so a four-wide machine
  took exactly as long as a one-wide machine. The default was silently the
  constraint.
* **The redirect was armed before its branch was dispatched**, naming an entry
  that did not exist yet — so the next branch's prediction overwrote a pending
  redirect before anything consumed it, and six mispredicting branches charged
  one redirect between them.

#### A mispredict costs two different true things

In a pipeline the machine keeps retiring what is already in flight while the
front end waits, so the declared penalty is paid in **idle fetch** and rather
less of it in **total time**. `front_end_stalls` reports the first, because a
host that multiplied a mispredict count by a penalty would be asserting the
second and getting it wrong.

#### Four checks that exist because a mutation survived

Each of these was added after a model that was wrong in a specific way passed
everything else:

* **the reorder buffer is the binding constraint somewhere.** With every core
  declaring an issue queue equal to its buffer, either structure alone
  reproduced the other's effect, and a model ignoring the buffer entirely
  looked right. One core now declares a queue larger than its buffer — which
  is how a description says *the scheduler is not this machine's constraint*.
* **the critical path is a floor.** A chain of K instructions at latency L
  cannot finish in under L × (K−1); there is nothing in it to overlap. Chain
  *invariance* across window sizes cannot see a model that ignores dependences,
  because such a model is equally wrong at both sizes and the two still agree.
* **a single-copy unit starts one operation per cycle.** Only a run of
  independent work can see this — every other program here is bound by a
  dependence or by the buffer.
* **the pipeline drains before it is judged.** A machine still holding
  un-retired instructions has been credited with work it has not finished.

6/6 mutations caught. And two mutations had to be *rewritten* rather than
fixed: one replaced `break` with `continue` in a loop that re-reads the head,
which is the same thing — a mutation that changes nothing tests nothing, and
reading it as a gate weakness would have been the wrong lesson.

#### Memory ordering, renaming and history

The window grew the three structures its absence had been hiding, each a
`defcore` clause that is off unless declared (`docs/ooo_design.md`): `(lsq
...)` orders a load against the stores older than it — conservative or
perfect disambiguation, forwarding from an executed store, finite load and
store queues; `(rename (FILE N))` bounds the results in flight by the physical
registers a file has; and `(predictor gshare) (history N)` learns a pattern a
counter per address cannot. `lsq_check.py`, `rename_check.py` and
`history_check.py` hold them, 23/23 mutations caught. Then a store's address
became known before its value (O4), and a load may bet it misses a store whose
address is unknown — squashed and replayed when it loses, with store sets to
stop it losing twice (O5, `speculation_check.py`, 11/11). And instructions
now have to be fetched: `(front-end (fetch-width F) (depth D))` with an
optional buffer and branch target buffer, so a mispredict's refill is the
depth the pipeline has rather than a number typed on `branch` (O6–O7,
`frontend_check.py`, 11/11). A direction predictor is a component now:
`bimodal`, `gshare` and `tage` implement the `axis_sim_predictor` interface a
host's predictor does, and a namespaced one plugs in by name (O8,
`tage_check.py`, 10/10). And a return stack whose calls and returns are
derived from the ISA's `defabi` link register rather than marked (O9,
`ras_check.py`, 8/8). And issue ports, so units sharing one cannot start
together (O10, `ports_check.py`, 4/4). And an instruction cache — separate, so §7d's reason
against a unified one stands — with the front end fetching down the wrong path
into it until a mispredict resolves (O11, `icache_check.py`, 7/7). And the wrong path EXECUTED: the functional side forks
at a mispredict, runs the predicted path with its stores held back and its
traps swallowed, and is restored exactly, the reachable part touching both
caches (O12, `wrongpath_check.py`, 11/11). And then the arrangement turned round:
`(engine execute)` fetches the predicted path, executes at issue through the
generated executor, and commits by stepping the golden model and checking every
result against it — architecture identical by construction, the replay count a
measurement of the engine's own mistakes (E1, `xmode_check.py`, 12/12). Its wrong path is the real one: O12's cache answers without a fork,
the return stack repaired, history speculative and restored on every squash,
counters crediting only what committed (E2, `xspec_check.py`, 8/8). And complete: loads and stores known at decode so
the queues and conservative and store-set ordering work without a trace, in-order
execution-driven cores, and precise traps (E3, `xcomplete_check.py`, 8/8); at
about 3x the trace engine's cost (`engine_speed.py`). Several run together, in
lockstep over one memory: sequentially consistent, a peer's committed store
snooping any load that read those bytes early (MC1, `mcx_check.py`, 9/9). A direct
branch's target is a field of its word, so decode knows it: execution-driven, a
predicted-taken branch the buffer does not hold is redirected at decode rather
than mispredicted, and trace-driven, a branch guessed taken that falls through
has a wrong path after all; and while decode looks, fetch runs on into the
lines after the branch (D1–D2, W1, `redirect_check.py`, 11/11). And that wrong
path is in the machine while it lasts: it takes entries, registers and units,
holds an unpipelined unit against older work and past the squash, and a load
on it touches the cache when it issues, not when it was fetched (W2,
`occupancy_check.py`, 11/11 with `redirect_check.py` and `wrongpath_check.py`
— two more mutants are equivalent, and `docs/ooo_design.md` §20–21 say which).
And it mispredicts too: a branch on it the predictor gets wrong sends fetch
down a detour until that branch resolves, and the path resumes a refill later
(W3, `wrongpath_check.py`, 6/6). The limits that paragraph ended on are
lifted in `docs/ooo_design.md` §23–§26: a unit may say it aborts at a squash
(W4); detours nest and a wrong path's jumps are predicted, with a jump no
buffer holds running on into what follows it (W5, W6); a quick predictor may
be overridden at decode by the core's own (D3, `override_check.py`); and a
line fetched while decode looked arrives a cache latency after it was asked
for, not when the program next looks (D4).

### A declared latency is a claim about hardware

Every other gate in this ladder holds an artifact against another artifact.
This one holds a **description against silicon**, and it is the answer to a
question that had been open since the scoreboard landed: reading `latency` made
the model self-consistent and said nothing whatever about whether the number is
true.

The method is a **ratio of dependent chains**, because that is the one
measurement that survives not knowing the clock:

> A chain of N instructions that each read what the last one wrote takes
> N × latency cycles whatever else the machine is doing. Two such chains of the
> same length differ in time by exactly the ratio of their latencies.

Frequency cancels. Issue width cancels. Unit counts cancel — a chain uses one
unit at a time by construction. What is left is latency, which is the number
the description declares. The instructions are emitted as raw words with
`.inst`, so what runs is the encoding AXIS produces rather than an assembler's
idea of it.

On this machine, against `RBIT_X` at a declared latency of one:

| instruction | declared | measured |
|---|---|---|
| `AND_V` | 2 | **2.00×** |
| `MADD_X` | 3 | **3.00×** |
| `UDIV_X` | 8 | 7.45× |

The AArch64 corpus's declared latencies are, as far as this can see, right.

#### Three mistakes on the way, and each produced a number

* **`ucvtf d0, w1` is not a chain.** It writes a floating register and reads a
  general one, so putting "register 9" in both fields names two different
  registers in two different files: the instructions do not depend on each
  other at all, and what got measured was throughput wearing latency's name —
  0.14× a one-cycle instruction. Every operand must share a register class.
* **The clobber list forgot the vector registers.** `v8`–`v15` are
  callee-saved, so a chain of vector instructions corrupted its caller and the
  timing came back as garbage. The gate reported that as *an opcode the host
  does not have*, blaming the silicon for the clobber list.
* **An absent measurement divided into a baseline** gives 1e33, which is not a
  slow instruction. A run that never beats its sentinel says so.

#### What it cannot see

A data-dependent unit — an integer divider, most obviously — is measured at
whatever operands the chain happens to produce, which need not be its worst
case. A description declaring a worst case and a measurement finding a typical
one disagree for a reason that is nobody's mistake, and `UDIV_X` at 7.45
against a declared 8 is probably exactly that.

Instructions that are not the host's are **refused rather than run**: a
description may invent an opcode, and inventing one is not a licence to execute
it. Each kernel runs as its own process, so one that is not real takes itself
down and not the gate.

⚠️ Tolerance is a third. The margins actually observed are 0%, 0% and 7%, so
that leaves better than twice the headroom while still catching a declared
three that is really a one — which is the mutation it is held to.

## 7e. Described openly, modelled privately

A microarchitecture is mostly **policy**, and policy is not declarable. If this
stack is to host a world where some models are open and some are a vendor's, it
needs a boundary that carries three things AXIS does not own — and, crucially,
does not pretend to understand.

`emit-uarch-json` is that boundary: **`axis.uarch.v1`, a machine standing
alone.** It is separate from `emit-json` on purpose. That artifact is the whole
document, every instruction and every encoding, and a vendor describing a
machine should not have to ship an instruction set to do it.

```lisp
(defcore ahaclosed
  (kind rvmt) (implements iw32) (issue-width 4)
  (model aha-cycle-urv)
  (provenance modelled)
  (vendor (aha.rob-partition 2) (aha.lsq-depth 24) (aha.hypertrace on))
  (units (alu (count 4) (pipelined true)) …))
```

**`model`** names the implementation meant to time this core. Empty is AXIS's
own pipeline.

**`vendor`** holds parameters AXIS has never heard of, transported verbatim. A
round trip that normalised one would be editing a machine it cannot read. Keys
are namespaced so two vendors cannot collide and nobody has to arbitrate.

**`provenance`** says what *kind* of number this machine's figures are —
`declared` (a designer typed them), `measured` (put back to hardware and
checked, which `silicon_check.py` now makes a real category), or `modelled`
(produced by another model). A closed model's cycle count and a count measured
against silicon are different claims, and a stack that renders them identically
invites the reader to confuse them.

### The property the whole boundary exists for

⚠️ **A core naming a model this library is not is REFUSED.** `select_core`
returns 0 and the machine is left on whatever it was. Selecting anyway would
hand back the built-in pipeline's answer for somebody else's machine, and a
plausible wrong number is worse than a refusal — the same reason a pack reports
a missing JIT by name rather than by silently interpreting.

And a refusal has to be *actionable*: `core_model` says which implementation a
host would have to supply, because a host told only "no" cannot go and find
one. That is a separate check, and it is caught by its own mutation.

### The other half: a model that is not this library

`axis_uarch_pack` is the socket. A closed implementation arrives the way the
JIT and the solver do — a library exporting one symbol — and a host binds it by
the name a core asked for:

```c
int32_t wanted = S->register_model(&their_model);   /* cores that asked: 0 = typo */
S->select_core(m, "ahaclosed");                     /* now succeeds */
```

**Capability is presence.** Before registration the core is refused; after it,
the core selects and *the model times the machine*. `register_model` returns how
many declared cores asked for that name, so a model built for another
description — or a typo — is reported rather than accepted and then never used,
which would make every later refusal unexplained.

⚠️ **The event is flattened on purpose.** A model taking `axis_lift_entry *`
would need the generated header of the description it was built for, which
makes a closed model a per-corpus artifact and the boundary a fiction.
`axis_pack.h` is byte-identical across packs and depends on nothing, and this
keeps it that way: mnemonic, unit, latency, throughput, pc, whether control can
leave and whether it did, what the cache charged, and the register slots read
and written. Everything the built-in pipeline itself reads, in types any
compiler has.

⚠️ **The model's answer is returned whole** — not blended with this library's,
not quietly checked against it. Once a vendor's implementation is timing the
machine, the cycle count is that implementation's claim, and mixing in a second
one produces a figure neither of them made. The built-in pipeline stands down.

⚠️ **And a number can name its author.** `timing_source` returns the bound
model's name, or the empty string for this library's own pipeline.
`core_provenance` says what *kind* of claim a description makes; `timing_source`
says *who made the one you are holding*. In a stack mixing open and closed
models that is the only way a reader can tell the two apart.

A model's state belongs to the model: this library allocates none of it and
frees none of it, it only says when it is finished.

#### One mutation that changes nothing

Making the built-in pipeline run *alongside* a bound model is not caught, and
should not be: `cycles()` returns the model's answer either way, so the
mutation is semantically neutral under this ABI — like replacing `break` with
`continue` in a loop that re-reads its head. It wastes work and advances state
nothing reads. It is recorded here rather than papered over, because the day
this library exposes its own counters beside a bound model's, that neutrality
ends and the two would disagree with nobody able to say which was speaking.

## 7f. An instruction nothing selects is an instruction nobody has

Three things about compiler selection already existed, and it is worth being
precise about what each one proves, because the gap was narrower than it looked:

* `llvm_patterns_check.py` evaluates a pattern's **DAG against the golden
  model**, so a pattern saying `or` where the instruction computes `and` is
  caught. That is semantics, and it needs no LLVM.
* `llvm_target_check.py` hands the whole target to **`llvm-tblgen`** and
  compares the generated *encoder* against AXIS's own.
* `--gen-dag-isel` was already run — but the check on it was an **aggregate**.
  It failed only when the matcher selected *none* of the target's
  instructions, so one pattern quietly dropped passed while the others still
  selected.

`selectable_check.py` is the per-instruction census, the way the SMT gate is a
census. Every instruction declaring a pattern must appear in the matcher
`--gen-dag-isel` builds; the unselectable are **named with their reason**,
because "declares no pattern" and "declared one that was dropped" are different
findings and a merged count hides the second behind the first.

What it found, which had never been counted:

| corpus | instructions | declare a pattern | in the matcher |
|---|---|---|---|
| `zbb_like` | 11 | 11 | 11 |
| `rv32i` | 247 | **66** | 66 |

Every pattern that exists reaches the matcher. **181 of rv32i's 247
instructions declare no selection pattern at all** and are reachable only by
intrinsic. That is a legitimate design choice — it is what intrinsics are for —
but it was invisible, and "how much of this ISA can a compiler choose on its
own" is the first question a backend author asks.

⚠️ **The vacuity hole, and how it is closed.** A target that stopped emitting
patterns altogether would sail through a census of patterns: nothing to check,
nothing wrong. So the census is cross-checked against `emit-llvm-patterns`, a
second artifact derived from the same `formal_semantics` that independently
names the instructions AXIS believes are selectable. Emitting nothing is now a
failure rather than a decline.

⚠️ **What this still does not do is compile a program.** Whether a compiler
*choosing between* instructions picks this one for real code needs the target
linked into `llc`, and the `llc` on this host has never heard of it. This
proves the matcher **can** select the instruction, not that a compiler
**would** — and saying which of the two a gate measures is the difference
between a result and a slogan.

#### Where the strength actually is

Every mutation constructible here was caught, and most of them by
**`llvm-tblgen` itself** rather than by the census: patterns commented out
leave dangling syntax, and patterns renamed to another instruction fail type
checking. That is worth recording rather than engineering around. The census
earns its place on the case tblgen cannot see — a pattern that is well-formed,
accepted, and never matched — and the honest statement is that this is a guard
against a narrow failure sitting behind a very strong one.

## 8. A disassembler of its own

Printing lived in the **assembler**, so a consumer that only reads code had to
link one that writes it. Turning a word into text is its own job -- it needs the
decoder's tables, the spelling of a register, and the number an operand shows
where that is not the field it is encoded in -- so it is its own library:

```c
const axis_disasm_pack *axis_disasm_pack_rv64i(void);   /* libaxis_disasm_rv64i */
```

`disassemble(word, isa, buf, size)` does it in one call, and the pieces are
there for a consumer that wants them separately. A binary linking **only** the
disassembler:

```
  0x00b50533  add x10, x10, x11
  0xffb00613  addi x12, x0, -5
  0x003140b3  xor x1, x2, x3
  0xffffffff  (does not decode)
```

⚠️ It **refuses** a word two instructions both claim rather than answering with
whichever the table reaches first. That is the one thing a disassembler must
never do, and the ambiguity is counted rather than hidden.

The spelling machinery is generated into both the assembler and the
disassembler -- each gets its own `static` copy, which is what keeps them
independently linkable. `pack_check` requires the two to write **identical
text** for the same instruction, because two copies of one description that
drifted would be worse than one copy in the wrong library.

## 9. Text, generated

The assembler library reads and writes assembly now, so text to a word is the
pack's job rather than the consumer's:

```
  add x10, x10, x11      -> 0x00b50533   back: "add x10, x10, x11"
  addi x12, x0, -5       -> 0xffb00613   back: "addi x12, x0, -5"
  not a real instruction -> (no match)
```

`print` walks the template and replaces each placeholder; `parse` walks the
same template backwards, capturing a register name or a number. A candidate
must also **encode**: values that do not satisfy an instruction's constraints
are not a match for it, which is how two forms spelling one mnemonic are told
apart.

### The spelling comes from the description, and only goes so far

An ISA declaring `(registers "x[32]:i64")` names its registers `x0`..`x31`, and
that is the only naming any description states. ⚠️ ABI aliases -- RISC-V's
`a0`, AArch64's `sp` -- are stated nowhere, so nothing generated prints or
accepts them. Neither does a `w`/`x` distinction: `a64_gpr32` is a *view* of the
same file, and a description gives one spelling per file rather than per class.
Those are gaps in the description language, not in the generator, and they are
what the 36 ambiguous fixtures below are.

### What the round trip found

Every fixture is printed, parsed back and assembled, and must give the same
word. It found two things immediately.

**116 RISC-V instructions shared a spelling.** Six rounding-mode variants per
float operation -- `FADD_S_RNE` through `FADD_S_DYN` -- all printed
`fadd.s $rd, $rs1, $rs2`. A disassembler had to guess and an assembler could not
say which it meant. RISC-V spells the static mode as a suffix, so they do now;
eight more were bare names for the RNE encoding (`FMADD_S` beside
`FMADD_S_DYN`, `rm=000` against `rm=111`) and say so too. This is the `lr.w`
defect again, nine times the size.

**An immediate printed unsigned.** `addi x12, x0, -5` assembled correctly and
printed back as `4294967291` -- the same word, and not the same text. Only the
behavior says an immediate is signed, which the TableGen path already knew and
the printer did not.

⚠️ And four mutations, **three of which passed at first**: a signed immediate
printed unsigned, an out-of-range register accepted, a parser that read no
register number at all, and the `fbits` transform inverted the wrong way. Each
needed the gate to reach further -- a printed number must FIT its field (the
round trip alone cannot see it: `4294967291` truncates back to the same field);
a fixture whose own text its parser cannot read is a failure rather than a
statistic; every fixture's immediates are small positives, so a negative one is
now synthesised; and `SCVTF_D_X_FIXED` sits past the fixture cap, so the only
instruction with a transform was never printed.

564 fixtures round-trip, 99 of them again with a negative immediate, and 36 are
counted as ambiguous with the reason.
