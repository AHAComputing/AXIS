# The scheduler has limits of its own

Status: **S1–S8 built, on both engines.** A window was a size, an issue queue
and a commit width; four things a scheduler designer edits were not said at
all (S1–S3), and nothing could be predicted but a branch (S4, §5). S5–S8
(§6) are what those left open: a queue several units share, a rename width,
a stride, and a scheduler that picks by position. Not built: the rest of §7.

## 1. What was missing

```lisp
(window (rob 64) (issue-queue 64) (commit-width 4))
```

* **How many enter the window a cycle** was the issue width, because nothing
  said otherwise. A machine renames fewer than it can start, or more.
* **The issue queue was one pool.** Real schedulers are several, one a unit
  or a cluster, and the one that fills is the one that stops the machine.
* **A dependent issued the cycle its producer completed**, whatever the
  producer's latency: a chain of one-cycle adds ran at one cycle a link on
  every machine, which is a statement about the wakeup-and-select loop that
  no description made.
* **A result reached every unit at once.** What the multiplier makes is at
  the adder's input the cycle it is made, as if they shared a wire.

## 2. The clauses

```lisp
(defcore big
  (window (rob 64) (issue-queue 64) (commit-width 4)
          (dispatch-width 6)          ; S1: micro-ops into the window a cycle
          (schedule 2))               ; S3: the wakeup-and-select loop, in cycles
  (bypass (mul alu 2) (fpu alu 1))    ; S3: what a result costs to cross units
  (units
    (alu (count 4) (pipelined true))
    (mul (count 1) (pipelined true) (queue 8))))   ; S2: how many may wait for it
```

Each is optional, and a core that says none of them is the machine it was.
None is in the pack ABI: each is a table beside the core's.

**S1 — `dispatch-width`.** How many micro-ops enter the window a cycle. Zero,
or unsaid, is the issue width. It is counted in micro-ops: a cracked
instruction is as many as it cracks into.

**S2 — a unit's `queue`.** How many instructions may *wait* for that unit --
dispatched and not yet issued. One bound for a unit whose queue is full does
not enter the window; and dispatch is in order, so nothing behind it does
either. That is the point of it: a slow chain on one unit stops the machine at
the door long before the reorder buffer is full. The core's one `issue-queue`
still bounds everything waiting.

**S3 — `schedule`.** The wakeup-and-select loop. A dependent issues no sooner
than `schedule` cycles after its producer *issued*. One is a scheduler that
issues dependents back to back, which is what every core was. Two is one that
cannot: a chain of one-cycle adds runs at two cycles a link, and a chain of
three-cycle multiplies -- which the loop is shorter than -- at three, as
before. It is a bound on issue-to-issue, not a cycle added to every result.

**S3 — `bypass`.** `(FROM TO N)`: an instruction on unit TO reading what an
instruction on unit FROM made waits N cycles more than the producer's
latency. It has a direction; `(mul alu 2)` says nothing of the way back.

## 3. A producer that has retired

The last two are delays on a *producer*, and they outlast it. An instruction
that has issued and completed may retire before a bypass has delivered its
result, and readiness in this pipeline is "every producer still in the window
has completed" -- a producer gone from the window is ready. So when each
instruction issued, when it completes and on what unit are kept by sequence
number, for as long as anything could be waiting on it, and a dependent asks
that record before it asks the window. Without it a bypass cost nothing at all
on any chain whose links retire as they finish.

A core that declares neither keeps no record and asks nothing.

## 4. What holds it: `scheduler_check.py`

One machine -- four wide, one multiplier of three cycles, adders of one -- and
what it is with each clause, on each engine; 32 more instructions:

| | plain | with the clause |
|---|---|---|
| independent adds | 8 cycles | 16, dispatching two a cycle |
| a chain of adds | 32 | 64, through a loop of two |
| a chain of multiplies | 96 | 96: a multiply is longer than the loop |
| a chain alternating multiply and add | 64 | 96, the product two cycles to the adder |
| a chain of adds, or of multiplies, on the bypassing machine | — | as plain: nothing crosses |
| one add of a chain of multiplies | — | exactly 2 more |
| one multiply of a chain of adds | — | 0: the bypass is one way |
| 4 more multiplies ahead of a long chain of adds | 1 | 12, with two allowed to wait for the multiplier |
| 4 multiplies ahead of the adds, against the plain machine | — | exactly 3 more: one issues, two wait, the fourth is one multiply late |

12/12 mutations caught: the issue width at the door, in the function and on
each engine; a queue that never fills, no door on each engine, and a queue
that counts what is executing as waiting; no loop, and a loop added after the
result instead of bounding issue to issue; no bypass, a bypass read backwards,
and a producer forgotten when it retires.

Two of them needed a program. A bypass read backwards cost every alternating
chain exactly what one read forwards does -- a chain that goes round crosses
as often one way as the other -- so two single crossings say which way it is.
And a queue that counted the multiply in flight let each further multiply in
at the same three-cycle spacing: only how late the FOURTH gets in tells them
apart.

## 5. S4 — a load's value, predicted

```lisp
(defcore guesses
  (value-prediction (entries 64) (confidence 2)))
```

A load's value is not known until the load has run, and everything that reads
it waits. But a load at one pc that has read the same value `confidence` times
running will usually read it again. So the machine says so: what depends on
the load issues without waiting for it, and the load runs to *check*.

* **Right**, and a chain of dependences through memory is gone. A pointer
  that points at itself is chased at the speed of the loop, not of the load.
* **Wrong**, and everything after the load ran on a value that was never
  there. It is squashed and fetched again once the load has said what it
  really read: the load's own time, then a refill.

The predictor is the simplest that is one: by pc, the last value and how many
times running it has been read. `entries` is the table; a load is predicted
when its entry is its own and has reached `confidence`. An instruction is
predicted if it loads, stores nothing, and has one register result -- which is
its result, so a load with an add in it is predicted too, unless the core
cracks it.

**Trace-driven** the functional step has already run, so what the load read is
in its register when it is dispatched: a right prediction marks the entry as
not waited for; a wrong one restarts the front end behind the load when it
completes, the way a mispredicted branch does. The table learns in program
order.

**Execution-driven** the predicted value goes into the window as if the load
had computed it, and younger instructions execute on it. When the load runs,
what it computed replaces it; if that differs, everything younger is squashed
and fetched again. The table learns when a load *retires* -- from the golden
model's register, which is what was read whatever the pipeline thought -- so
it is some loads behind what is being dispatched. That is why a short pattern
says different things on the two engines, and why the gate's mispredict on
both is a single change after a long run.

Two counts at the end of the pack, which is `abi_version` 11 for them:
`value_predictions`, loads predicted that read what was said, and
`value_mispredicts`, loads predicted that did not.

The corpus gained `valueplain` / `valuepredicts` and the pair on the other
engine.

### What holds it: `value_check.py`

| | unpredicted | predicted |
|---|---|---|
| 16 more trips chasing a pointer that points at itself | 32 cycles: the load a trip | 16: the loop a trip, every load predicted and none wrong -- on both engines |
| the same round a ring of four | — | the same cycles, nothing predicted |
| a field the same three trips in four (trace-driven) | — | wrong once every four trips and never right; 5 cycles a time |
| a field changed once after a long run | — | wrong exactly once trace-driven, at least once executing |
| a field read, late, into a register the loop adds to | — | the plain machine's cycles, every load right: the add saw the value predicted |

9/9 mutations caught: a table never trusted, and one trusted at once; what
depends on a predicted load still waiting for it, on each engine, and
everything waiting; a wrong value that costs nothing trace-driven and is not
squashed executing; a table that never learns; and a predicted value not in
the window for what depends on it. That last survived twice: a pointer at itself, where
the register held the value already; and a field read and then added to,
where the load -- older, and ready -- issued first in the same cycle and the
add saw what it had really read. The load's address comes off a multiply.

### What it is not

* **Any predictor but last-value.** No stride, no context, no confidence that
  decays rather than resets.
* **Speculative training**, execution-driven: a real predictor counts the
  predictions it has in flight.
* **Selective replay.** A wrong value squashes everything younger, whether or
  not it read the value.
* **Cracked loads, stores' data, and anything that is not a load.**

## 6. S5–S8 — what the first four left open

```lisp
(defcore big
  (window (rob 64) (issue-queue 64) (commit-width 4)
          (rename-width 4)                       ; S6
          (select position))                     ; S8
  (queues (int (size 24) (units alu br))         ; S5
          (mem (size 16) (units lsu)))
  (value-prediction (kind stride) (entries 64) (confidence 2)))   ; S7
```

**S5 — `queues`.** A queue several units share, which is what a scheduler
cluster is. What waits for any of its units waits in it, so an instruction
bound for one of them does not enter while the queue is full of the others'.
A unit is in at most one; it may have a `(queue N)` of its own as well, and
either full stops it. A queue of the multiplier's alone never sees a load; one
the multiplier shares with the load unit fills with loads waiting on each
other, and a multiply behind them waits at the door.

**S6 — `rename-width`.** How many *results* may be given a register in a
cycle. It is not a second dispatch width: an instruction that writes nothing
-- a store, a branch -- takes none of it, and one that writes two takes two.
An instruction with more results than the whole width has a cycle to itself.

**S7 — `(kind stride)`.** The value predictor keeps the last *difference*
beside the last value, and predicts their sum once the difference has
repeated `confidence` times. A value that does not change is a stride of
nothing, so this is the last-value predictor for every load that one
predicts; and a pointer walked a line at a time, which is never its last
value, is predicted every time.

**S8 — `(select position)`.** Oldest-first takes knowing every instruction's
age. A cheaper scheduler picks by where an instruction *sits*: each takes the
lowest free slot of the issue queue when it enters and gives it up when it
issues, and of those ready for a unit the lowest slot goes first. So an
instruction that entered while the low slots were taken sits above a younger
one that entered after they were given up -- and loses to it. `oldest`, or
nothing, is what every core was.

None is in the pack ABI. The corpus gained `clusters`, `renamesone`,
`valuestrides` and `selectsposition`, each on both engines.

### What holds them: `scheduler_check.py`, `value_check.py`

| | measured |
|---|---|
| 4 more multiplies, and 4 more loads, ahead of a long chain of adds | 12 and 8 cycles where the multiplier and the load unit share a queue of two; 12 and 1 where the queue is the multiplier's own; 1 and 1 with neither |
| 32 more independent adds, renaming one result a cycle | 32 cycles, where the plain machine takes 8 |
| 32 more stores, renaming one result a cycle | the plain machine's cycles: a store has no result |
| 32 more instructions, alternately of two results and of one, renaming two a cycle | 32 cycles: three results are more than a cycle renames |
| a load and a multiply waiting, then one more load, at a shared queue of two | exactly a multiply later than plain; nothing later where the queue is the multiplier's own |
| two multiplies ready together for one multiplier, a chain off the older | 1 cycle more by position than by age |
| the same, the chain off the younger | 1 cycle fewer |
| 16 more trips walking a pointer a line at a time (trace-driven) | 80 cycles unpredicted and by last value, which never predicts it; every load right by stride, and the chain gone |
| a pointer at itself, and a field read and added to, by stride | what last value costs: a stride of nothing |

9/9 mutations caught: no shared queue, and one that counts only its own
unit's; no rename width, and one that counts instructions rather than
results, on each engine; no stride, and one never trusted; a scheduler that
picks by age after all, and one whose slots are never given up.

Three survived the first programs. A shared queue that counted only its own
unit's looked right whenever one kind of instruction was waiting, which was
every program: it takes a load and a multiply waiting *together*. And
counting instructions renamed rather than results looked right for stores
(none either way), for adds (one either way) and for a run of two-result
instructions (the check asks how many results the *next* one has): it takes
a two-result instruction and then a one-result one, three in all, against a
width of two.

## 7. What is not here

* **Other select policies.** By age or by position in a queue that does not
  compact; a compacting queue, or round-robin among queues, is not said.
* **Selective replay** of a value predicted wrong, a predictor trained
  speculatively on the engine that executes, and predictors that read
  context.
* **Partial bypass networks**: a result that reaches a unit late *and* is
  unavailable for a cycle in between.
* **Rename as a stage.** `rename-width` bounds results a cycle; there is no
  buffer between renaming and dispatch for the two to drift apart in.
* **A trace-driven wrong path** is dispatched at this width and stopped at
  these queues like the right one; that it then issues through the same loop
  and bypasses follows from its being in the window.
* **Execution-driven micro-ops of one instruction** enter and leave the window
  in one cycle (`docs/micro_ops_design.md` §6).
