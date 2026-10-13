# A store that has retired is not yet everyone's

Status: **WM1 and WM2 built, on the execution-driven engine.** A core may
declare a store buffer (WM1) and loads seen in any order (WM2, §6); cores
that share a memory then show what their ISA's memory model allows and
sequential consistency does not. Not built: §9.

## 1. What was missing

`run_cores` (`docs/ooo_design.md` §17) runs several execution-driven cores on
one memory, and what they saw together was **sequentially consistent by
construction**: a store was every core's the instant it retired, and a load
another core had run early over those bytes was squashed. That is a legal
implementation of every memory model and the behaviour of none of the
machines the models were written for. A program that is wrong under RVWMO or
Arm's model -- a flag published before the data it guards, two threads each
reading the other's flag after setting their own -- ran correctly here, every
time, on every timing.

An ISA already says which model it has, `(memory-model rvwmo)`. Nothing read
it.

## 2. The clause

```lisp
(defcore big
  ...
  (store-buffer (entries 16) (drain any))
  (engine execute))
```

A store that commits goes into the core's buffer instead of into memory.

* **The core reads its own.** Its loads, and its golden model, see memory
  with the buffer laid over it, oldest store first.
* **Nobody else does**, until the store is written. Writing it is what
  snoops the other cores and clears their exclusive monitors -- what
  retiring did on a core with no buffer.
* **A store asks for its line** when its turn comes -- the cache access a
  store made as it retired, before -- and is written the cycle after the
  line is there, one store a cycle. So the buffer is also time: a store to a
  line the core has to fetch holds its entry for the miss, a full buffer
  holds commit, and a machine whose store buffer backs up is now this one.
* **`(drain order)`**, the default: only the oldest store asks, and only it
  is written. Each core's stores reach memory in program order, after its
  later loads may have retired: **total store order.**
* **`(drain any)`**: every store asks as it enters, and the oldest one whose
  line is there is written -- **never past an older store that covers some
  of the same bytes.** Two stores to different lines reach memory in either
  order. That is the relaxed models' and nobody else's.

A core that stops -- halted, or at its step limit -- goes on writing what it
holds, a cycle at a time, while the cores beside it run; `run_cores` returns
when every buffer is empty. A core run by itself writes all of it as it
stops.

## 3. What orders memory

**An instruction that orders memory retires only when the buffer is empty,
and what it stores is written as it retires** -- as on a core with no buffer.
Which instructions is told from their effects (`timing::orders_memory`) and
is not declared:

* a barrier that orders memory (`dmb`, `dsb`, `fence`; not `isb` or
  `fence.i`, which order the pipeline);
* an access that is atomic -- a store-conditional and a load-exclusive are --
  or that acquires or releases;
* an instruction that both reads and writes memory.

An instruction the core cracks retires whole and is treated the same. This is
stronger than the models ask of some of these, and never weaker.

## 4. What the ISA's model allows

| `(memory-model ...)` | a buffer | `(drain any)` |
|---|---|---|
| `sc` | refused | refused |
| `rvwmo`, `armv8`, `weak` | yes | yes |
| anything else (`tso`, ...) | yes | refused |

Validation also refuses a buffer of no entries or more than 64, a `drain`
that is neither, and a buffer on a core that is not `(engine execute)` with a
window: a trace-driven core has run its program before its pipeline sees it,
and there is no moment at which another core could look.

No counter and nothing in the core's row: **the pack ABI does not move.**

## 5. What holds it: `store_buffer_check.py`

`issue_width.axisl` has no fence and no cache slow enough to tell a store
that waits from one that does not; the gate adds both, and machines alike but
for the clause. Two cores on one memory:

| | no buffer | in order | any order |
|---|---|---|---|
| store buffering, 49 timings: both loads read 0 | never | yes | yes |
| ... with a fence after each store | never | never | never |
| message passing, 7 timings: the reader reads what was there before | never | never | yes |
| ... with a fence between the datum and the flag | never | never | never |

and on every machine: a store and a load of the same word round a loop, and
seeded random programs, leave what they leave with no buffer, alone or beside
another core; **no replays anywhere** -- what a core read is what its golden
model reads; a load whose address is late reads the younger of two stores
its core still holds; a store across the end of a cold line is written before
a later one to the start of the next, which is ready first; four stores to
four cold lines retire together into a buffer of eight, a line's wait apart
into a buffer of one, and into a buffer of two sooner in any order than in
order.

## 6. A load another core's store overtakes (WM2)

```lisp
(load-order any)
```

A load that has read its bytes and not yet retired when another core writes
them was squashed and read again. That keeps a core's loads in program order
against the rest of the machine, which the relaxed models do not ask for: a
load may be satisfied before an older load of other bytes. **A core that says
`(load-order any)` keeps the load** -- and when it retires, its golden model
reads what the load read, not what memory holds by then.

Not every overtaken load may be kept:

* **Two loads of the same bytes never see memory go backwards.** When an
  older load reads, any younger load that was overtaken on some of those
  bytes and kept is squashed with everything after it: the older has the new
  bytes, so the younger must not have the old.
* **Nothing is satisfied before what orders memory.** A load is not kept if
  an instruction that orders memory (§3) is at or before it in the window --
  a fence it has not retired past, or the load itself being atomic,
  exclusive or acquiring.
* A load of more than four reads, one that also stores, a micro-op and a
  load whose value was predicted are not kept. They are squashed, as before.

`(load-order order)`, the default, is that squash for every overtaken load.
Validation refuses `any` on a core that is not `(engine execute)` with a
window, and on an ISA whose model is not `rvwmo`, `armv8` or `weak`.

### Total store order's (WM6)

```lisp
(load-order tso)
```

Total store order asks that a core's loads be seen in its program's order,
and not that each be seen when it retires. **A core that says
`(load-order tso)` keeps an overtaken load when every older load in its
window has read** -- and nothing that orders memory is at or before it, and
it is a load that can be kept at all, as above. It is then as if the load had
read after the last of those older loads and before the store: nothing wrote
its bytes in between, or it would have been overtaken then. A load with an
older load still to read is squashed, as in order.

What this is and is not:

* It is a choice of the core's, like `any`: what a design that tracks its
  loads this closely saves is the squash. `order` is always right.
* A load is seen before an older STORE of its own core -- that store is in
  the window, not yet anyone's. That is total store order's one reordering,
  and so **a core with `tso` or `any` shows store buffering with no store
  buffer declared**. Validation refuses `tso` on an ISA whose model is `sc`,
  and on a core that is not `(engine execute)` with a window.
* An older load that reads later than the store cannot happen: one that had
  not read stopped the keeping, and one that reads again was squashed, with
  everything after it.

⚠️ **The golden model is no longer the judge of a kept load's value.** For
every other instruction, and for a kept load's address, registers and next
pc, it still is.

### What holds it: `load_order_check.py`

A writer that stores the datum and then the flag, beside a reader that loads
the flag through an address it is slow to form and then the datum -- which
it therefore reads first. 49 timings each:

| the reader reads | in order | any order | any order, and a store buffer |
|---|---|---|---|
| the flag and not the datum | never | yes | yes |
| ... with a fence between its loads | never | never | never |
| the flag set and then clear, loading it twice | never | never | never |

`(load-order tso)`, with a store buffer or without, is the first column
there. What tells it from `order` is two cores that each store one word and
load the other, the store held at the head of the window behind multiplies
and the load not, 49 timings:

| | in order | `tso` | `any` |
|---|---|---|---|
| both loads read 0 | never | yes | yes |
| loads squashed | 49 | 0 | 0 |
| ... with a fence after each store: both read 0 | never | never | never |

and seeded random programs leave what they leave on a core with neither
clause, alone or beside others, with no replays anywhere.

## 7. On AArch64 and RV64: `a64_weak_check.py`, `rv_weak_check.py`

The two gates above count on a corpus small enough to reason about cycles in.
This one holds the same on `aarch64_base`, whose ISA says
`(memory-model armv8)`, with `STR`, `LDR` and `DMB` -- told to order memory
from its `(barrier dmb ...)` and nothing else. Three machines alike but for
the clauses, two cores each, 49 timings (7 for message passing):

| | neither | a buffer in order | a buffer and loads in any order |
|---|---|---|---|
| store buffering: both loads read 0 | never | yes | yes |
| ... with a `DMB` after each store | never | never | never |
| message passing: the flag and not the datum | never | never | yes |
| ... with a `DMB` between the stores | never | never | never |
| the reader's flag load late: the flag and not the datum | never | never | yes |
| ... with a `DMB` between its loads | never | never | never |
| the flag loaded twice: set and then clear | never | never | never |

and no replays anywhere.

A fourth machine, the buffer in order with `(load-order tso)` (WM6), is the
middle column in every row, and in message passing squashes none of the
reader's loads where the buffer in order alone squashes some.

`rv_weak_check.py` is the same gate given RISC-V's instructions: `rv64i`,
`(memory-model rvwmo)`, with `SD`, `LD` and `FENCE`. The same machines, the
same sweep, the same table.

## 8. In front of a cache that is busy

A blocking cache (`docs/blocking_cache_design.md`) takes one request a cycle
and none while a miss is on its way, and had no write buffer: a store retired
into it, waiting at the head of the window for its line. **A core with a
store buffer and a blocking cache has the write buffer.**

* **Commit does not wait for the cache.** A store retires into the buffer --
  unless it orders memory (§3), and is written as it retires.
* **The buffer asks as anything does**: only when the cache is free, the
  oldest store that has not asked first. One miss at a time, so the buffer
  drains in order whatever its `drain` says.
* **It asks last in a cycle**, after the loads that issue: a load is what the
  machine is waiting for, and a store that has retired is not. A full buffer
  holds commit, the window fills, and the loads stop coming: the stores are
  not starved.

`write_buffer_check.py`, with a miss of 10: four stores to four cold lines
retire in 5 cycles into a buffer of eight and 37 with none or into a buffer
of one; stores to a new line each, round a loop, are 11 cycles each on every
machine; a load behind four buffered misses waits for the one on its way and
not for the four; a fence after the four stores retires when the buffer is
empty; two cores beside each other both drain and finish.

## 9. What is not here

* **A count of what was kept.** A snoop that squashes is counted; a load
  that keeps what it read is not, and the pack ABI did not move for it.
* **Load buffering** -- a store visible before an older load of the same core
  has read. No machine with an in-order commit does it.
* **Forwarding has no cost** and no limit: a load reads a buffered store's
  bytes whatever their overlap.
* **Coalescing**: two stores to one line are two entries.
* **The trace-driven engine**, and so SIMT cores: refused.
* **An access across two lines** asks for the first only.
