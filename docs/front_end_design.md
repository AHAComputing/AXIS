# The predictor does not wait for fetch

Status: **FQ1 built, on both engines.** A front end predicted where fetch
was and no further: a line of code was asked of the instruction cache when
fetch arrived at it, and a miss was a stall of its whole latency however
long the machine had known the line was coming. `(target-queue N)` is a
decoupled front end. Not built: §5.

## 1. What was missing

```lisp
(front-end (fetch-width 4) (depth 4) (btb 512) (btb-penalty 2) (icache l1i))
```

Every miss in the instruction cache cost `latency-cycles`, in full, at the
moment fetch reached the line. In a machine built since about 2010 that is
false: the predictor is a separate engine that runs ahead of fetch down the
path it predicts, leaves what it found in a queue of fetch targets, and the
front of that queue is where fetch reads next while the rest of it is
prefetched. Straight, cold code -- a first call into a library, the code
after a context switch -- cost a miss a line here and costs a fraction of
one there, and no description could say which machine it was.

## 2. The clause

```lisp
(front-end (fetch-width 4) (depth 4) (btb 512) (btb-penalty 2) (icache l1i)
           (target-queue 8))
```

The predictor names **one line of code a cycle**, and may be **at most N
lines beyond the one fetch is reading**. A line is asked of the instruction
cache **when it is named**. When fetch arrives:

* a line the cache held is read, as before;
* a line named long enough ago has arrived, and is read;
* a line still on its way holds fetch for what is left of the fill, and is
  **not a miss of fetch's** -- `icache_misses` counts the lines fetch had to
  ask for itself;
* a line named as fetch arrives -- there was no time to run ahead -- is a
  miss, in full.

The queue only matters when fetch is slower than the predictor, and fetch is
slower whenever a line is more than one fetch group, the line before it
missed, or the window behind it is full. Then:

```
named(i) = max( named(i-1) + 1,  read(i-N) )      and never after fetch arrives
ready(i) = named(i) + latency
read(i)  = max( when fetch arrives, ready(i) )
```

For cold straight code of `g` fetch groups a line that is a line every
`max(g, latency / N)` cycles, against `latency + g` with no queue: the
misses overlap N deep until fetch itself is what is slow.

**Three things empty the queue**, and the line after each is named as fetch
arrives at it:

* **a redirect** -- a mispredicted branch, a value predicted wrong, a trap:
  what was named was the wrong path's;
* **a branch the predictor had no target for**, which decode finds
  (`btb-penalty`) or the core's own predictor overrides (`overrides`);
* **a new page**, on a core with a fetch TLB: the predictor names addresses
  and does not translate them.

A taken branch the predictor has a target for -- from the target buffer, or
a return from its stack -- does not: that is the point of the queue.

Validation refuses a queue with no `(icache ...)` to ask, one of more lines
than that cache holds, more than 64, and one on a core whose front end is
not this library's (`simt`, `model`).

## 3. How both engines do it

Neither engine walks a second program counter ahead of fetch. The cycle a
line was named is what the recurrence above says it was, worked out when
fetch arrives at the line; the fill is recorded as having started then
(`axis_ic_fill`), which is the mechanism a line asked for while decode
looked at a branch already used (`docs/ooo_design.md` §26). So:

* a core with no queue names every line as it arrives, and is cycle for
  cycle what it was -- every earlier gate runs unchanged;
* the engine that executes credits a head start along whatever path it is
  fetching, right or wrong, and a squash empties the queue;
* the state is a side table beside the core table and a ring of sixty-four
  cycles in the machine. **The pack ABI does not move.**

## 4. What holds it: `target_queue_check.py`

Its own machines, built onto `issue_width.axisl`: four wide at fetch,
sixteen instructions to a line, a miss of 24, queues of 0, 1, 2, 4 and 8,
and two with a fetch TLB and pages of four lines. On both engines:

| program | what it must show |
|---|---|
| eight more cold lines | 28 a line with no queue; 24, 12, 6, 4 with 1, 2, 4, 8 |
| sixteen cold lines | sixteen misses with no queue, one with any |
| a loop in one line | the same cycles on every machine |
| a mispredicted branch, then cold lines | the line gone to is a miss; the lines after gain what straight ones do |
| a jump with no target, then cold lines | the same |
| two lines that put each other out, each a jump to the other | two misses a trip with no queue, none with one; 12 cycles a trip at four ahead, 48 at one |
| cold lines in pages of four | one miss a page, and 3 × 24 cycles a page saved |

and the engines agree cycle for cycle where nothing is mispredicted.

## 5. What is not here

* **The predictor's own latency.** It names a line a cycle and a taken
  branch costs it nothing; a queue that hides a slow predictor's bubbles
  behind a full queue is not modelled, because no predictor here is slow
  except through `overrides`.
* **Blocks.** The queue counts lines of the instruction cache, not fetch
  blocks ending at taken branches; a loop inside one line is one entry.
* **What the queue named down a wrong path** beyond what fetch reached is
  not asked for. On the engine that executes, wrong-path lines fetch did
  reach are in the cache, as before.
* **A line named ahead is in the cache when fetch reads it.** It is put
  there as fetch arrives, so a queue cannot put out a line fetch has yet to
  read; validation's bound on N is what keeps that honest for straight code.
* **Fill buffers.** Any number of lines may be on their way at once.
* **Translation ahead.** The queue stops at a page; a front end that
  prefetches the fetch TLB too is not said.
* **The micro-op cache and loop buffer** are not fed by the queue: code that
  comes from either asks for no lines, and counts for none of the N.
