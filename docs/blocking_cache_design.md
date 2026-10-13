# A cache that is busy

Status: **B1 built** -- the clause, the simulator's cache, and the gate.

A core's data cache has been a table of which lines it holds. A miss was a
number added to the instruction that missed: any number of them overlapped,
a store cost nothing, and a line replaced was gone. A described memory system
keeps time (`unified_engine_design.md`, U1 and U3), with miss registers and
lines on their way -- and still hides behind a write buffer every write that
goes below.

A real first-level cache of the simplest kind does none of that. It has one
port and one state machine: while a miss is on its way it takes nothing, a
store waits for its line as a load does, and a line that was stored to is
written behind before the line that replaces it is asked for. That is the
cache a core is first built with, and the simulator could not say what it
costs.

## The clause

```lisp
(defmemory l1d
  (kind cache)
  (size-bytes 4096)
  (line-bytes 64)
  (ways 1)
  (latency-cycles 10)
  (blocking true))
```

`blocking` is a cache policy (`memsys::MemoryPolicy`), and it is one
structure, so what is said beside it has to be what it is. It is refused with
`mshrs` above one, `write-through`, `no-write-allocate`, a replacement other
than `lru`, or a prefetcher: each would be a clause read and not acted on.

It is a core's own data cache, on the execution-driven engine. A cache that
is busy *until a cycle* needs a core that has cycles when it reaches memory,
which a trace-driven core does not; so a trace-driven core naming one is
refused, and so are a front end that fetches through one and a memory system
with one for a node.

## What it does

With L the cache's `latency-cycles`:

* **One request a cycle, and none while a miss is on its way.** After a hit
  the cache takes its next request the cycle after; after a miss, the cycle
  after it has answered.
* **A hit is answered in the cycle it is taken**, as before: what a load
  costs on a hit is its own latency.
* **A miss is answered L cycles after it is taken** -- and L more when the
  line it replaces was stored to. There is no write buffer: the line goes
  behind first.
* **A store is a request like a load.** It reaches the cache when it
  retires, waits for its line, and marks it stored to.
* **Replacement** is what it was: a way the set has not filled, the lowest
  first, and then the one used longest ago.

And the pipeline, around it:

* **A load does not issue to a cache that will not take it.** It is a
  structural stall, like a busy unit: the load stays in the window and
  something else may issue.
* **A store does not retire into a cache that will not take it.** It waits
  at the head, and everything behind it waits with it. One store retires a
  cycle, since the cache takes one request a cycle.
* **Commit comes before issue in a cycle**, so a store retiring has the
  cycle's request and a load waits for the next.
* A load down a wrong path has asked, as it always had on this engine: its
  miss holds the cache whether or not the load survives.

An access neither gate holds back -- an instruction's second, or one behind
a page walk -- is taken at the first cycle the cache is free, and what it
waited is its instruction's.

It is not in the pack ABI: a core's cache is blocking by a table beside the
cores, as its event instructions are.

## What holds it: `blocking_cache_check.py`

Cores alike but for the clause, on the same programs, with L = 10:

| | blocking | plain |
|---|---|---|
| loads of one word, 24 and 48 | 44 and 68 cycles | the same |
| a pointer chase, 24 and 48 loads | 339 and 675 | the same |
| 24 more loads, a new line each | 264: L + 1 each, exactly | 39 |
| 24 more stores, a new line each | 264: L + 1 each, exactly | 24 |
| 32 more loads replacing lines that were read | 352: L + 1 each | 52 |
| 32 more loads replacing lines that were stored to | 672: 2L + 1 each | 52 |
| the same, the lines read and then stored to where they lay | 672 | 52 |
| 24 more iterations of four stores that hit, four load/store units | 96: a request a cycle | 48 |
| the same, two stores and two loads | 96 | 48 |

**The oldest is next.** A miss holds the cache; behind it are a load whose
address is late and a younger one whose address is not, and the older has a
chain of multiplies on it. 50 cycles -- and 50 with the younger load taken
out. A load that issued to the busy cache and waited there would be next
when it freed, the younger first, and the chain would start a miss late.

What every program computes is the same on both. Six descriptions are
refused, and the clause survives `emit-lisp`.

7/7 mutations caught, each built on a clean checkout: a load that issues to a
busy cache (by the oldest-is-next program alone -- charged its wait instead,
it finishes when it would have); a store that retires into one; the cache
free the cycle a miss answers; a stored line replaced at no more cost; a hit
that does not take the cycle; a store that hits, and one that misses, leaving
its line clean.

## Why these numbers: the cache it is

The contract is not invented. It is what PCE's `CacheCore` does with one miss
register over a memory that answers L - 1 cycles after it is asked, measured
at its port: 1500 requests on each of two geometries -- loads and stores,
hits and misses, lines replaced clean and stored to, back to back and with
gaps -- taken and answered at exactly the cycles the five rules above give.
That measurement lives with the core that is built from it, not here.

## What is not here

* **More than one miss in flight.** `mshrs` above one is refused with
  `blocking`; a described memory system has miss registers, and no charge
  for a write behind.
* **A write buffer for a line written behind**, and so the choice between
  waiting for it and hiding it. A core's store buffer is a write buffer for
  its stores (`memory_model_design.md` §8).
* **A counter** for lines written behind: the pack's ABI has none to put it
  in, and the gate tells them by their cycles.
* **An instruction cache that is busy.** Fetch has its own timing for a line
  on its way (`ooo_design.md` §26).
* **The trace-driven engine**, which reaches memory at its functional step.
