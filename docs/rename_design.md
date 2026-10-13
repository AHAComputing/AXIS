# A move is done at rename, and a pair is one operation

Status: **ME1, FU1 and ZI1 built, on both engines.** FU1 -- pairs the decoder
fuses -- is §6; ZI1 -- a register xor-ed with itself -- is §7. A machine that renames executed its
register moves like any other instruction: a slot of the issue queue, a turn
on an adder, a register, a cycle in every chain that went through one.
`(window ... (eliminate moves))` is a machine that does not. Not built: §5.

## 1. What was missing

```lisp
(window (rob 224) (issue-queue 97) (commit-width 8))
```

Renaming maps every destination to a new physical register. For a move that
is wasted: the value already has a register, and the map can simply point
the destination at it. Every wide core since the early 2010s does this, and
it is worth a few percent everywhere -- more in code compiled without much
register allocation -- because a move then costs **no latency, no port, no
scheduler entry and no register**. Here a move was an add: a chain through
six moves was six cycles longer than the same chain without them, on every
machine a description could name.

## 2. The clause, and what a move is

```lisp
(window (rob 224) (issue-queue 97) (commit-width 8) (eliminate moves))
```

**Which instructions are moves is not declared. It is told from what each
computes** (`timing::move_forms`), as a micro-op's dependences are
(`docs/micro_ops_design.md`). An instruction is a move when its one result is
its one output register and its value is

* an input register of the same kind and width -- always a move; or
* that register added to, or-ed or xor-ed with another operand, or with
  another subtracted from it, or shifted by another -- a move **for the words
  in which the other operand is nothing**: the class's zero register, or an
  immediate of zero. `add rd, rs, x0` is a move; `add rd, rs, x5` is an add.

An instruction that says what it does any other way -- effects beside the
result, a guard, a routine, a narrower value -- is not one. The table is
emitted only for a pack in which some core eliminates.

A move done at rename is **an entry in the window and nothing else**:

| it takes | it does not take |
|---|---|
| a fetch and a dispatch slot | a slot of the issue queue, or of its unit's |
| an entry in the window | a unit, a port, or any of the issue width |
| a slot of the commit width | a register from the rename pool, or any of `rename-width` |

and it **follows what it read**: it is done at the cycle its source is, and
what reads its result wakes exactly as it would have for the source's own
producer -- the scheduler's loop (`schedule`) and the bypass from *that
producer's* unit included. A move of a move follows through both.

Validation refuses `(eliminate ...)` of anything but `moves`, and on a core
with no window of this library's to rename in.

## 3. How both engines do it

The entry is flagged at dispatch (`elim`), is skipped by everything that
counts or picks waiting instructions, and is completed by one pass at the
head of each cycle's issue (`axis_moves_follow`), oldest first: when all it
read has issued, it is issued, complete when the last of that is, and the
scheduler's record of the producer is copied to it.

Execution-driven, the entry also **executes** in that pass -- its value is
the window's like any other, so what reads it reads the right thing and the
golden model has nothing to object to at commit. A squash recounts what is
still waiting. No counter was added: **the pack ABI does not move.**

## 4. What holds it: `move_check.py`

Its own machines on `issue_width.axisl`, each with a twin that eliminates.
Cycles a trip, on both engines:

| program | executed | at rename |
|---|---|---|
| six adds, each through a move | 12 | 6 |
| six adds, each through two moves (one with the zero register first) | 18 | 6 |
| the first, with a scheduler loop of two | 24 | 12 |
| four adds, four moves, a counter, on one adder | 9 | 5 |
| a multiply and a move of it, carried round | latency + 1 | the multiply's latency |
| a multiply carried round, a second of it, six moves of that; issue queue of four | more | the multiply's latency |
| the same, six registers to rename with | more | the multiply's latency |
| a chain of adds of one; a multiply by the zero register | the same on both | |

and the last two again behind a branch nothing learns, where squashed moves
must give back what they held.

## 5. What is not here

* **Immediates materialised at rename.** Zero idioms are §7.
* **A bound on sharing.** Real machines count references to a physical
  register in a few bits and stop eliminating when the count is full; here
  any number of names may share one.
* **Moves between classes**, of a narrower view, or of an element: the value
  is not the register's.
* **The trace-driven wrong path** executes its moves.
* **A warp's riders and cracked instructions** are never eliminated.
* **Select by position** gives an eliminated move no position; nothing here
  measures that.

## 6. A pair is one operation (FU1)

```lisp
(timing (fuse (CMP B) (LUI ADDI) (MUL ADD)))
```

A decoder that sees a compare and the branch on it sends one operation to the
window, not two. Here every instruction was an entry, so the pair cost two
slots of every width, two entries, and a cycle between them.

**Which pairs a core fuses is the core's to say** -- a head and the tail that
follows it, each by mnemonic prefix, beside what else the core says about time
(`src/timing.rs`). It is a choice of the design and nothing in the
instructions decides it. **Whether two words are such a pair is not written.**
The engine tells it from the registers they name:

* the tail is the instruction dispatched straight after the head, in the same
  cycle, and the head has not issued;
* the tail **reads something the head writes** -- a register or state;
* the two **leave at most one register between them**. State (the flags) is
  not a register: `subs x0, ...; b.ne` is a pair, and so is
  `lui a0; addi a0, a0`, and `add a0, ...; add a1, a0, ...` is not;
* the head does not touch memory and the tail does not store (a tail that
  loads is below), neither is cracked, neither is a move done at rename, and
  a tail is no head.

The pair is then one operation, and **the head's entry is it**:

| | |
|---|---|
| its unit | whichever of the two takes longer runs it -- the tail's when they take the same, so a compare and its branch are on the branch unit |
| its cycles | the longer of the two |
| the tail | follows the head as a move follows what it read (§3): done when the head is |
| the tail takes | a fetch slot, and nothing else: no entry in the window, none of the dispatch, issue or commit width, no slot of a queue, no unit, and no register the head already took |

A pair whose operation would move to a unit with a queue of its own, full, is
not fused. Execution-driven, the tail executes where it completes, and a
branch that is a tail is resolved there -- a cycle sooner than unfused.

Validation refuses a pair one of whose prefixes names nothing the core
decodes; one whose head reaches an instruction that touches memory, or whose
tail reaches one that stores or that orders memory
(`docs/memory_model_design.md` §3); one that reaches an instruction the core
cracks; a head that changes the pc; a pair named twice; and any pair on
a core with no window of this library's. `emit-uarch-json` lists each core's
pairs under `timing`. No counter was added -- a fused pair is one of
`micro_ops` -- and **the pack ABI does not move.**

### What holds it: `fuse_check.py`

Its own machines on `issue_width.axisl`, each with a twin that fuses add with
add, add with branch, and multiply with add either way round. Cycles a trip,
on both engines:

| program | unfused | fused |
|---|---|---|
| twelve adds to one register | 12 | 6 |
| the same through two registers by turns; with another add between each; on a core that names only add-with-branch | 12 | 12 |
| a multiply and an add of it, either way round, carried round | latency + 1 | the multiply's latency |
| four adds, the counter and its branch, on one adder | 5 | 4 |
| the same behind a branch that waits for a multiply; a branch unit with a queue of one | 5; 6 | 4; 6 |
| four adds that read nothing of each other, to four registers or to one; a core that fuses adds only | 5 | 5 |
| eight pairs through a dispatch width of two; a commit width of two | 8 | 4 |
| two multiplies carried round and six pairs; a window of twelve; eleven registers | more | the multiplies' latency |
| the same in a window of eight, fused | | more |

and the last again behind a branch nothing learns, where squashed tails must
give back what they held.

### A tail that is a load (FU2)

```lisp
(timing (fuse (ADD LW) (LUI LW)))
```

An address formed and then loaded through is one access on a machine that
fuses it: the add is the load's addressing, not an operation. The pair is the
other way round from the rest: **the load's entry is the operation** -- on
the load's unit, in its queue and the load queue, for the longer of the two --
and **the head is what follows**: done when what it read is, taking no entry,
no width, no queue slot, no unit, and the one register the load would have
taken.

Told from the words as before, and one thing more: **the load writes every
register the head wrote, and the head wrote no state.** A head that follows
its sources has its result for nothing, and that is right only when nothing
but the load can read it. `add t0, a0, a1; lw t0, 0(t0)` is a pair;
`add t1, a0, a1; lw t0, 0(t1)` is two instructions.

`fuse_load_check.py`, its own machines on `issue_width.axisl`, both engines,
cycles a trip:

| program | unfused | fused |
|---|---|---|
| four adds each with a load through it, carried round | 4 x (load + 1) | 4 x load |
| the same on a core that fuses only adds; with the address left in its own register; with another add inside each link | 4 x (load + 1) | 4 x (load + 1) |
| a multiply, a load through it, and an add | multiply + load + 1 | the longer + 1 |
| six links, the counter and its branch through a dispatch width of two; a commit width of two | 7 | 4 |
| two multiplies carried round and six links; a window of twelve; eleven registers | more | the multiplies' latency |

### What is not here

* **A pair that stores**, a load fused into what uses it (a head that is the
  access), and a pair of loads.
* **The address the fused load has** is formed for nothing whatever the head
  was; a multiply fused into a load is the longer of the two and no more.
* **A pair's own unit and latency.** Both are derived from the two halves.
* **"Decoded together"** is "dispatched in the same cycle": a pair split
  across two fetch groups fuses when the window is what the machine is
  waiting for, and does not when fetch is.
* **Pairs of three**, and a fused pair that is then cracked.
* **The trace-driven wrong path** fuses nothing.
* **The tail's other sources.** The head does not wait for them; the pair is
  done when the last of them is.

## 7. A register xor-ed with itself is nothing (ZI1)

```lisp
(window (rob 224) (issue-queue 97) (commit-width 8) (eliminate moves zeros))
```

`xor r, r, r` is how a program clears a register, and it names `r` as a
source. Executed, it waits for whatever wrote `r` last -- a dependence on a
value it does not use, which ties the trip of a loop that clears a register
to the trip before. A machine that renames sees the two operands name one
register and knows the result when it decodes.

`zeros` beside `moves` in the clause, either or both. **Which instructions is
told from what each computes** (`timing::zero_forms`): its one result is its
one output register, and the value is one input register xor-ed with, or
less, another of the same kind and width. **Which words**, from the two
operands naming one register. Such an instruction is an entry in the window
exactly as a move done at rename is (§2) -- no queue slot, unit, issue width
or register -- and it **waits for nothing**: what reads its result is ready
the cycle after it enters. Execution-driven it still executes, on whatever
the register holds, and the result is nothing either way.

Validation refuses anything in the clause but `moves` and `zeros`, and
either twice. The pack ABI does not move.

`zero_idiom_check.py` adds an xor to `issue_width.axisl` -- the corpus has
none -- and builds its own machines. On both engines: a chain of six adds
started each trip from the register xor-ed with itself is seven cycles a
trip executed, and with the xor known it runs exactly as the same chain
started from an add of two registers nothing writes; started from an xor
with *another* register it is seven everywhere, and six adds of a register
to itself are six; four xors and the counter
on one adder are five cycles a trip executed and, known, what they are on
eight adders; and a machine that does only its moves executes its xors, as
one that knows only its zeros executes its moves.

Not here: an instruction that also writes flags (`subs r, r, r`), an `and`
with the zero register, a load of an immediate, and a zero idiom as half of
a fused pair.
