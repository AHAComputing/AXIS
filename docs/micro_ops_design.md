# Micro-ops: an instruction a core divides

Status: **U1 and U2 built, on both engines.** U1: a core may crack an
instruction into micro-ops; what each one reads, writes and loads is derived
from the instruction's effects. U2 (§7): a cache of decoded micro-ops and a
loop buffer, two ways round decode. Not built: a trace-driven wrong path's
cracked instructions (fusion and moves done at rename are
`docs/rename_design.md`). A host reads
what happened as three counts (§8, pack ABI 10). Decided by the user on 2026-10-09: the dependences
between micro-ops are **derived from the instruction's effects**, not declared
and not a serial chain.

## 1. What was missing

One instruction was one entry in the window: one unit, one latency, every
source waited for, every result ready together. That is wrong for the
instructions a wide core spends its design on:

* a load with arithmetic in it is a load *and then* an add, on two units;
* a load that moves its base on writes a base that depends on no memory at
  all -- as one entry, the next instruction's address waits for a load it
  never reads;
* and each of those is two places in the machine's widths, not one.

`docs/pack_simulator.md` listed it first among what the simulator could not
say of a complex machine.

## 2. The clause

```lisp
(defcore big
  ...
  (timing
    (micro-ops
      (LDADD (lsu 2) (alu 1))      ; a unit and its cycles, per micro-op, in order
      (LDPOST (lsu 2) (alu 1)))))
```

By mnemonic prefix, the longest winning, inside `(timing ...)` -- it is what
this core says about time, and `src/timing.rs` is the one place it is
resolved (`Core::micro_ops_of`). A core that says nothing cracks nothing, and
is the machine it was.

**That is all a core writes.** Which registers a micro-op reads, which it
writes, which of them touches memory and which waits for which are the
instruction's own account of itself, and writing them again beside the core
would be a second place for a fact nothing has to agree with -- 1,356 times
over, for the AArch64 seed.

## 3. The derivation

From the instruction's `(behavior ...)`, in the order it is written:

* **A micro-op on the instruction's own unit does its memory.** The
  instruction's accesses, in the order it makes them, go one to each such
  micro-op; the last takes any left over. A micro-op on another unit
  computes.
* **A result that reads no load is the first computing micro-op's**, and
  waits for no load. This is the address written back.
* **A result that *is* a load is the loading micro-op's own.**
* **A result computed from a load is the first computing micro-op after that
  load**, and waits for it.
* **What no operand names is the last micro-op's**: state read and written, a
  fixed register, the pc.

Every micro-op reads the instruction's operands as they were *before* the
instruction, whichever goes first. One that needs another's result waits for
that micro-op, and for nothing else of it.

Refused, each by the instruction's name: a crack into one micro-op; an
instruction that says what it does as a value (`(formal ...)`) and so has no
effects to divide; one that touches no memory, where nothing tells one
micro-op's work from another's; no micro-op on the unit the memory is done on,
or more of them than accesses; a result computed from a load with no computing
micro-op after the load; a micro-op with nothing to do; a micro-op on a unit
the core does not declare, or of no cycles; more than eight.

`emit-uarch-json` publishes the plan a core derived -- per cracked
instruction, each micro-op's unit, cycles, accesses, reads, writes and what it
waits for -- so a reader is not left to re-derive it, and the gate holds it to
the effects.

## 4. In the window

Trace-driven, each micro-op is an entry: it waits for room of its own -- an
entry, a queue slot, a load or store slot if it has an access, a register for
each result -- and takes a place in the dispatch width, so a cracked
instruction may straddle a cycle. It issues to its own unit when what it reads
is ready, completes after its own cycles, and retires as an entry, in order.
What the cache charged the instruction is charged to the micro-op that made
the access. A redirect is armed on the last micro-op, since the pc is its.

The simulator reads the plan as a table beside the core's: nothing in the pack
ABI moves.

### Execution-driven

The engine that executes what it fetches computes an instruction's values
when it issues, as one thing, and the golden model steps an instruction, not a
micro-op. Three rules keep both true of a cracked one.

* **Each micro-op executes the instruction, whole, and keeps its own part.**
  When a micro-op issues, the generated executor runs the instruction on what
  the window has made *by then*; the micro-op keeps the registers the
  description gave it, the last keeps what none was given -- state, a fixed
  register, the next pc, a trap -- and the rest is thrown away. So a loading
  micro-op that issues before the addend is ready computes a sum nobody
  keeps, and the add computes it again when it can.
* **It executes on the registers as they were before the instruction.** The
  window's view stops at the instruction's first micro-op: a sibling's result
  laid over it -- a base already moved on -- would be the instruction reading
  its own output.
* **An access is one micro-op's.** Only the micro-op the description gave an
  access to touches the cache, is charged the miss, records the load for a
  later store to squash, or holds the store. To the others it is a value.
* **An instruction is in the window whole.** Its micro-ops dispatch in one
  cycle or not at all; none retires until all have finished and all fit in
  what is left of the commit width; a store that squashes a load squashes
  from that load's first micro-op. A micro-op that is not the last retires by
  handing what it computed to the next, and the golden model steps once, at
  the last, and judges all of it.

A replay is the golden model disagreeing with what the pipeline computed, so
on this engine the gate has something the trace cannot give it: a cracked
program that replays computed some micro-op's part from the wrong registers.

The corpus gained `xcracks` / `xcracksnot` for it, and a third instruction:
`IWLX`, a load that moves its base on by a *register* -- the one whose second
micro-op can be kept waiting long after its first has finished.

The corpus gained two instructions a core may crack -- `IWLA`, a load added to
a register, and `IWLP`, a load that moves its base on -- and three cores:
`cracks`, its twin `cracksnot`, and `cracksslow`, whose add is on the one
multiplier.

## 5. What holds it: `micro_ops_check.py`

| | cracked | not |
|---|---|---|
| 24 more links of a chain of load-and-move through its base | 24 cycles: an add a link | 48: the instruction a link |
| 24 more links of a chain of load-and-add through its sum | 24: every load was made early | 72 |
| 96 more independent load-and-adds, four wide | 48: two micro-ops each | 24 |
| the same with the add on a unit the machine has one of | 96: one a cycle | — |
| one cold load-and-add and eight multiplies of its sum | the same 38 cycles | 38 |

Every row is the same number on the execution-driven pair, with no replay. A
loop that stores a word, loads-and-adds it, moves a base on and branches --
squashing cracked instructions from both sides -- and a load that moves its
base on into the register it loads to, retire what the uncracked machines
retire. The plan `cracks` publishes for each instruction is the one its
effects say, and every program leaves the same registers and memory on every
machine.

6/6 mutations caught: an instruction not cracked at all; an add that does not
wait for its load; a micro-op given the instruction's cycles; every micro-op
on the first one's unit; the base written back by the loading micro-op; and a
miss charged to every micro-op. A seventh -- micro-ops not counted in the
dispatch width -- is equivalent on every core here: a core's dispatch width
is its issue width, and the micro-ops are held to that when they issue. The
add that does not wait survived every chain, which retire behind the load
either way, until a program put multiplies behind one cold sum.

Execution-driven, 7/7 more: a micro-op that sees its siblings' results; the
golden model stepped for every micro-op; an add that does not wait for its
load; an instruction not cracked; one retired in pieces; an access made by
every micro-op; and a micro-op that hands nothing on. An eighth -- every
micro-op keeping every register -- is equivalent: each executes the whole
instruction, so the last, which retires them all, writes the same registers
over.

Three of those survived the first gate, and each needed a program of its own.
Retiring in pieces needs a first micro-op that has finished, with its result
in use, while the second still waits -- which no load-and-move by a constant
can show, since both micro-ops read the one base: hence `IWLX`. A base never
handed on looked right because the chain moved its base on by nothing. And an
access made twice costs no cycle -- the second finds the line -- so the gate
counts data-cache hits on the pair.

The base chain first measured the commit width. At 8 and 16 links the whole of
a cracked chain ran inside the first load's cold miss: the machine was waiting
to retire, not for the chain, and 8 more links cost 4 cycles. The chains are
longer than a miss.

## 6. What is not here

* **A trace-driven wrong path's cracked instructions** enter the window as
  one entry each (W2's dispatch), on a core that cracks them on the right
  path. Execution-driven, the wrong path is fetched and so cracked like any
  other.
* **Micro-ops of one instruction in different cycles**, execution-driven:
  they dispatch together and retire together. Trace-driven they may straddle
  a cycle at dispatch.
* **A warp's riders.** A cracked instruction is dispatched by each member of
  a warp for itself.
* **A store's address and data** as two micro-ops. O4 already lets a load
  wait for a store's address and not its value; the two halves are not two
  entries.
* **Instructions that touch no memory.** Nothing in an add of three registers
  says which micro-op adds which two.
* **Vector lanes.** A cracked instruction's micro-ops take one lane's worth of
  a unit with lanes.
* **Fusion, move elimination and zero idioms** are built: `docs/rename_design.md`.

## 7. U2 — two ways round decode

```lisp
(front-end (fetch-width 4) (depth 4) (icache l1i)
           (op-cache (entries 16) (ways 2) (window 32) (width 8) (depth 2))
           (loop-buffer (ops 16) (width 8) (depth 1)))
```

Code a machine has decoded before need not be fetched and decoded again. Both
clauses are optional and independent; a front end with neither is the one it
was.

**The micro-op cache** holds `entries` windows of `window` bytes of code,
`ways` to a set, as decoded micro-ops. Fetch entering a window the cache holds
takes it from there:

* **no instruction-cache lookup and no fetch-TLB lookup** -- nothing is
  fetched;
* **`width` micro-ops a cycle**, where decode delivers `fetch-width`
  *instructions*. A cracked instruction is as many as it cracks into, which
  is why this is counted in micro-ops and decode is not;
* **`depth` stages to dispatch**, where the front end has its own. That is
  what a mispredict refills through when its target is in the cache.

A window the cache does not hold is fetched and decoded as ever, and is there
afterwards. Entering a window is a lookup: crossing into one, a redirect, and
a taken branch -- even one that lands in the window fetch was already in.

**The loop buffer** replays a small loop. A backward branch taken twice
running, over a body of at most `ops` micro-ops with no other taken branch in
it, is a loop the buffer holds. From the next trip the body comes out of the
buffer: `width` micro-ops a cycle, `depth` stages from dispatch, nothing
fetched -- and **the loop's own branch does not end a fetch group**, because
the buffer wraps: the next trip's first micro-ops come in the cycle of this
one's last. It stops when fetch leaves the body: the branch falls through,
another branch is taken, or the path is squashed.

A change of path starts a new fetch group. Both are tables beside the core's:
nothing in the pack ABI moves.

Execution-driven, both work on the path fetch *predicts*: a wrong path fills
the cache with what it decoded, and what the loop buffer had learned goes with
a squash.

The corpus gained `decodes` and what it is with each -- `opcached`,
`opcachedshort` (no wider than decode, so that all it saves is stages),
`opcachedtiny` (one window) and `loopbuffered` -- and all but the single
window on the engine that fetches what it predicts.

### What holds it: `op_cache_check.py`

A loop of fourteen instructions the back end never holds up, on a machine four
wide at fetch, eight behind it and four stages deep; 16 more trips:

| | measured |
|---|---|
| decoded | 64 cycles: four fetch groups a trip, one ending at the branch |
| from a micro-op cache eight wide | 32: two a trip |
| from a loop buffer eight wide | 28: fourteen micro-ops a trip, no break at the branch |
| a loop of eighteen, in a buffer of sixteen | what it costs with no buffer |
| the loop of fourteen, in a cache of one window | 64: each of its two windows puts the other out |
| a straight line run once | the same with a cache as without |
| a branch two-bit counters cannot learn, cache no wider than decode | 8 mispredicts, 16 cycles cheaper: two stages each |
| a loop in two lines of one instruction-cache set | 2 instruction misses a trip decoded, none from the cache |
| six instructions that are ten micro-ops | 32: two cycles a trip of a cache eight wide |
| a loop that is exactly one window, closed by a jump | one group a trip where decode takes two, for as long as it runs |

Every timed row is the same number on the execution-driven cores.

16/16 mutations caught: a cache that holds everything, and one that holds
nothing; micro-ops delivered at decode's width, at decode's stages, fetched
from the instruction cache all the same, and counted as instructions -- each
on each engine; no lookup at a taken branch; a loop buffer that stops at its
branch, on each engine, holds a loop of any size, delivers at decode's width,
or never turns on. The lookup at a taken branch survived twice: with a redirect
also a lookup, the refill row found the window either way, and so did a loop
closed by a branch, whose first, cold, mispredict let it in. The loop that
holds it is one window closed by a jump.

The refill row first measured nothing at all: the branch's loop is inside one
window, fetch never left it, and a window is looked up on the way in -- so it
missed once and was decoded for ever. A taken branch is a way in.

### What is not here

* **Entry points.** A window is held whole or not at all, whatever offset
  fetch enters it at; a real cache holds it per way in.
* **Its capacity in micro-ops.** A window holds whatever code is in it; a
  window of cracked instructions is no fuller than one of adds.
* **What switching paths costs** beyond a new fetch group.
* **A wrong path, trace-driven**, which neither fills the cache nor is
  delivered from it; and the fetch that runs on while decode looks (D2),
  which is decode's on any path.
* **Loops with a taken branch inside**, and a loop the buffer unrolls to fill
  its width with whole trips.

## 8. What a host reads

Three counts at the end of `axis_sim_pack`, which is `abi_version` 10 for
them:

| | |
|---|---|
| `micro_ops` | micro-ops the program retired: one an instruction, or as many as the core cracks it into |
| `op_cache_ops` | of those, how many reached the window from the micro-op cache |
| `loop_buffer_ops` | and how many from the loop buffer |

The rest came through decode. They are the program's own: trace-driven,
nothing on a wrong path is counted because nothing on one is fetched by these
paths; execution-driven, a micro-op is counted when it retires, so one a
squash removed never was.

`micro_ops_check.py` holds the first to the instructions retired -- one each
on a machine that cracks nothing, two each of the cracked ones, on both
engines -- and `op_cache_check.py` the other two: every micro-op of a loop the
machine has learned, from the path that learned it, and none on a machine
with neither.
