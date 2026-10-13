# Advanced out of order: memory ordering, renaming, history, speculation, fetch

Status: **O1–O12, E1–E4, MC1, A64-1/2, D1–D2 and W1–W3 implemented.** Companion to `docs/arch_packs.md` §7d, whose
window (`(window (rob N) (issue-queue M) (commit-width W))`) this extends.
`docs/pack_simulator.md` is the overview of the whole simulator: how to build
and drive one, every clause a core can declare, and where each is argued.

## 1. Why

The window that landed in §7d answers one question well: an instruction
waiting on a slow producer does not hold up the ones behind it. It is a real
tick loop — oldest-ready-first issue over a finite buffer, in-order commit, one
line away from in-order issue — and `ooo_check.py` holds it. But three
structures every out-of-order core has, and every cycle-level simulator worth
the name models (gem5's O3 among them), were missing, and each one's absence
produced a number that was wrong in a direction that looks like a finding:

* **Memory was not an ordering.** A load waited on registers only, so a load
  that read what an older store wrote could run first. A memory-carried chain
  ran at the speed of independent work.
* **Renaming was unbounded.** A write never waited for a physical register, so
  a 32-entry window let 32 results run ahead of a stall whatever the machine's
  register file could hold.
* **A predictor could learn habits, never patterns.** Bimodal keeps a counter
  per address, and an alternating branch defeats a counter per address
  forever.

Each is a `defcore` clause, and each is **off unless declared**: a core that
says nothing is the machine it was before, so no existing description acquires
a constraint it never stated. That is the same rule the window itself follows.

## 2. The forms

```lisp
(defcore big
  (kind rvmt) (implements iw32) (issue-width 2)
  (window (rob 32) (issue-queue 32) (commit-width 2))
  (lsq (loads 16) (stores 12) (disambiguation perfect) (forwarding true))   ; O1
  (rename (rv_gpr 48))                                                      ; O2
  (branch (penalty 6) (predictor gshare) (entries 1024) (history 10))       ; O3
  (units (alu (count 2) (pipelined true)) (mul (count 1) (pipelined true))
         (br (count 1) (pipelined true)) (lsu (count 2) (pipelined true))))
```

All three round-trip through `emit-lisp`, publish in `emit-json` and
`emit-uarch-json` (`"lsq"` is `null` — said, not omitted — for a core without
one), and reach the generated C as fields of `axis_sim_core`.

## 3. O1 — the load/store queue

**Where the addresses come from.** The model is trace-driven: the functional
step runs first and the timing model accounts for what it did. The pack's
memory hooks now record each access's `[lo, hi)` and direction as the step
makes it; dispatch copies them into the instruction's window entry. A host's
`touch_memory` is not an instruction's access and is not recorded.

**When a load may issue**, on a core with an `lsq`, besides its registers:

| older store in the window | conservative | perfect |
|---|---|---|
| not executed yet | wait (address unknown) | wait only if it overlaps |
| executed, load lies wholly inside it | forward once executed | forward once executed |
| executed, load straddles it | wait for it to retire | wait for it to retire |
| any overlap, `(forwarding false)` | wait for it to retire | wait for it to retire |

`perfect` is an oracle, and it is affordable here only because a trace knows
every address. It is the bound any memory-dependence predictor is measured
against, and saying that is its job is more useful than pretending it is a
predictor. A **straddle** cannot be forwarded because its bytes come from two
places; gem5 replays such a load after the store commits, and this is the same
decision.

**The queues** are backpressure, like the buffer: a load with no load-queue
entry cannot dispatch however ready it is. Zero means as deep as the window.

⚠️ One simplification, stated so nobody reads it as a finding (a second one
this section used to state is gone — see O4):

* **A store leaves the store queue when it retires.** Draining a committed
  store to the cache is instant, so a machine whose store buffer backs up is
  not this one.

### What holds it: `lsq_check.py`

* a chain through memory (store, load the same word, compute from it) costs at
  least `(store + load + compute) × (K−1)` — 37 cycles against a floor of 30 —
  and a window **without** an `lsq` goes under that floor (17), which is what
  "memory ordering not modelled" means, said rather than hidden;
* perfect disambiguation passes a store with a late *address* it does not
  overlap and conservative does not (14 vs 19); on the chain, where every load
  overlaps, the two agree exactly; and a store whose *value* is late but whose
  address is ready costs conservative nothing — exactly the oracle (O4);
* the words touching a store on either side cost what a far-away word costs:
  **touching is not overlapping**;
* a covered load forwards from an executed store (15) where a machine that
  does not forward waits for retirement (24); a straddling load pays the
  latter even on a forwarding machine, exactly;
* two-deep queues cost more than window-deep ones, for loads and for stores;
* a stand-in closed model is handed every access with its bytes.

11/11 mutations caught. One program was added because a mutation survived: **counting a shared
edge as an overlap** passed every program until one put a load next to a
store.

## 4. O2 — renaming

`(rename (rv_gpr 48))` gives the `rv_gpr` *file* 48 physical registers beyond
the architectural ones. A write takes one at dispatch and gives one back when
it retires — the register its destination was mapped to *before*, which
nothing younger can name any more. A file not listed renames without limit.

⚠️ **Per file, not per view.** AArch64's W and X forms are one file, as are the
D and Q views of the vector file; a pool per view would let a machine hold
twice the registers it has. The pack carries a class → file table for this.

⚠️ **A write to the zero register takes none**, and neither does a store. A
result nobody can read needs nowhere to live.

### What holds it: `rename_check.py`

The one property that pins the *count* rather than its direction: **on a
program where every instruction writes a register, N spare registers and an
N-entry reorder buffer are the same constraint** — dispatch waits for a
retirement either way — so `fewregs` (window 32, six spare) must match
`ooosmall` (window 6) to the cycle. An off-by-one pool still binds and still
costs more, and only this catches it. Alongside: a pool bigger than the window
costs exactly nothing, on a program longer than the pool too (which catches a
register taken and never returned); stores and zero-register writes cost the
small pool nothing.

6/6 mutations caught. Two needed the gate changed first, and both for the same
reason: **cheap work gains nothing from running ahead**. Independent adds
behind a slow head retire at the commit width however early they finish, so
the first version measured the same cycles with four spare registers and with
none; the work behind the head has to take a while for an early start to be
worth anything.

## 5. O3 — global history

`(predictor gshare) (history N)` indexes the same two-bit counters by address
XOR the last N outcomes. A branch then has a counter per recent history rather
than one per address, and an alternation — taken, not, taken, not — becomes
two habits. Validation refuses a history on a predictor that reads none, and a
gshare without one: both are numbers nothing reads.

### What holds it: `history_check.py`

A loop whose body flips a register between 1 and −1 (a multiply by minus one)
and branches on it:

| | 16 trips | 32 trips |
|---|---|---|
| bimodal | 11 mispredicts | 19 |
| gshare, history 1 | 13 | 21 |
| gshare, history 4 | 10 | 10 |

That gshare's cost **stops growing** is the property. The one-bit row is the
other half: inside a loop the outcome just before the alternating branch is
always the loop's own backward branch, so one bit cannot tell the phases apart
and must scale like bimodal. Without that core the declared length was a
number nothing had to read — at sixteen entries a history of four and one of
sixty-four index the same counters, and the mutation that dropped the mask
survived until the one-bit core existed. 6/6 caught after.

## 6. O4 — a store's address before its value

O1 landed with a store publishing its address only when it issued, which is
when its value was ready too. Real cores split store-address from store-data,
and without the split `conservative` was pessimistic on exactly the shape it
exists for: a store whose value is late still knows where it writes.

The pack now carries, per store instruction, which operands its address is
computed from — read off the declared effect's address expression, not
guessed — and a store's address is **known** once those producers have landed.
`conservative` waits for older store *addresses*; forwarding still waits for
the store to execute, because that is when the value exists. A store the
table does not know waits for every source, as before: the safe direction.

## 7. O5 — betting that a load misses

```lisp
(lsq (disambiguation speculative) (replay 4))
(lsq (disambiguation store-sets) (replay 4) (store-sets 64))
```

`speculative` never waits for a store whose address is unknown. When that
address resolves over a younger load that has already issued, the load read
memory before the store wrote it: a **violation**. The load and everything
younger are squashed — whether or not they read it, since the machine cannot
tell until it re-executes — and may issue again `replay` cycles later.
`store-sets` bets the same way and learns: the load's and the store's
addresses get one set in a table of `store-sets` entries, and a later load in
a set waits for any older unexecuted store in it. `memory_violations` reports
the count. Validation refuses a replay on a machine that never speculates and
a table on one that keeps none.

⚠️ **This needed no wrong path**, which the first version of this document said it would. A
memory-order squash replays the *correct* path — the same instructions,
re-executed — so a correct-path trace model can hold it exactly. Only a branch
mispredict fetches instructions that never retire.

### What holds it: `speculation_check.py`

A loop around a store whose address comes late and a load that either reads
what it wrote or reads elsewhere:

| | violations, 8 / 16 trips | cycles at 16 |
|---|---|---|
| perfect (the oracle) | 0 / 0 | 76 |
| speculative | 7 / 15 | 177 |
| store sets | 2 / 2 | 89 |

* **a bet that wins costs nothing**: on the loop that never aliases,
  speculation and store sets both cost exactly what the oracle costs (73), and
  conservative more (77);
* **speculation loses once per extra iteration**, exactly;
* **store sets lose a constant**, and what they cost over the oracle does not
  grow either (twice, not once: a load from the next iteration was already in
  the window when the table learned);
* **a squash costs at least its replay, and exactly its replay difference**:
  with an independent chain behind one violation, two machines differing only
  in `replay` differ by exactly that — 4 against 12 is 8 cycles;
* conservative and perfect never violate, and no machine changes a register.

O4 3/3 and O5 8/8 mutations caught. Two needed the program with the chain
behind the violation: **a squash of only the load** and **a free replay** both
passed every loop, because re-executing the chain on its own cost more than a
replay of four.

## 8. O6–O7 — the front end

```lisp
(front-end (fetch-width 4) (depth 2))                          ; O6
(front-end (fetch-width 4) (depth 8) (buffer 4))
(front-end (fetch-width 4) (depth 2) (btb 64) (btb-penalty 3)) ; O7
```

Until this, an instruction reached dispatch the moment the functional step
ran it, and a mispredict cost the number typed on `(branch (penalty N))`. With
a front end declared:

* up to `fetch-width` instructions are fetched a cycle, in **groups a branch
  predicted taken ends** — the next instruction comes from somewhere else;
* each reaches dispatch `depth` cycles after it was fetched;
* **a mispredict restarts fetch when the branch resolves**, so the refill is
  the depth, a number the pipeline produces; `branch_penalty` becomes extra
  recovery on top (zero in every core here);
* at most `buffer` instructions are fetched and not yet dispatched — by
  default `fetch-width × (depth + 1)`, the stages and no more. A front end
  must hold width × depth to sustain its width, and one that holds less
  starves the back end;
* a correctly predicted taken branch looks its target up in a direct-mapped
  **branch target buffer** of `btb` entries, which holds the *last* target
  each branch took; a miss — no entry, another branch's, or a different
  target — costs `btb-penalty` cycles, the time decode takes to find it. `btb`
  0 is a perfect buffer.

⚠️ The BTB is filled on every taken branch, including the ones the direction
predictor got wrong. So a cold direct branch usually misses nothing: by the
time the counter says "taken", the buffer has already seen it go. What a BTB
costs is **aliasing** and **indirect targets that change**.

The corpus gained `IWJR`, an indirect jump, because every branch it had was
direct — and a BTB that ignored the target it stored looked perfect on them.

### What holds it: `frontend_check.py`

Seven machines identical in everything a program executes on:

| | measured |
|---|---|
| 24 straight-line adds, depth 2 / 8 | 9 / 15 — exactly the extra depth, once |
| the same, fetching one a cycle | 27, floor 24 + 2 |
| the same, depth 8 holding 4 | 50, floor ⌈24/4⌉ × 8 = 48 |
| a 5-instruction loop, 8 more iterations | exactly 16 cycles: two fetch groups each |
| any loop, depth 8 vs 2 | exactly 6 × (mispredicts + 1) more |
| a mispredict on a slow vs a ready register | 27 vs 21: fetch waits for resolution |
| two taken branches, 1-entry BTB, 8 → 16 trips | 11 → 27 misses; each costs exactly the penalty |
| an alternating indirect jump, 64-entry BTB | one more miss per iteration |

and `front_end_stalls` is exactly mispredicts × (depth + penalty) on every loop the gate runs.

11/11 mutations caught, three of them only after the gate grew for them:
**restarting fetch before the branch resolved** (every branch had resolved at
once), **a BTB ignoring the stored target** (every branch was direct), and
**an unbounded buffer** (the default one never binds). And one program had to
be rewritten before it could see the group break at all: a three-instruction
loop runs one iteration a cycle on any front end, because its counter is a
one-cycle dependence carried round the loop.

## 9. O8 — a predictor is a component

Three predictors were three values of an enum, each with its own fields and
its own branch in the engine, and the next one would have been a fourth. That
is the shape that stops a model being extended by anyone but its author. So a
direction predictor is now a **component**: a C interface in `axis_pack.h`,

```c
typedef struct axis_sim_predictor {
  uint32_t abi_version; const char *name;
  void *(*create)(const axis_sim_core *core);   /* reads its own parameters */
  void (*destroy)(void *state);
  int32_t (*predict)(void *state, uint64_t pc);
  void (*update)(void *state, uint64_t pc, int32_t taken);
} axis_sim_predictor;
```

and `bimodal`, `gshare` and `tage` are this library's implementations *of it*,
reached through the same four calls a host's would be. Every number
`(branch ...)` gives beyond `penalty`, `predictor`, `entries` and `history` is
carried to the predictor as a `(key, value)` pair, read with
`axis_sim_param_of` — a header-only helper, so an external predictor needs
nothing but the header.

```lisp
(branch (penalty 6) (predictor tage) (entries 64) (history 32) (tables 4) (min-history 2))
(branch (penalty 6) (predictor acme.always) (entries 64) (acme.bias 1))
```

⚠️ **Open, but not loose.** A *namespaced* name is somebody else's predictor:
its numbers are carried verbatim, and the core is **refused** at selection
until a host calls `register_predictor` with that name — the rule `model`
already follows, for the same reason: another predictor's mispredicts are a
plausible number for somebody else's machine. An un-namespaced name must be a
built-in, and each built-in's numbers are held to what it reads, so `gshar`
and `(entires 16)` are errors rather than a predictor nobody has.
`register_predictor` answers how many cores asked (zero is a typo);
`core_predictor` tells a refused host what to go and find. Selection now
resolves both the model and the predictor before changing anything, which
also fixed a refusal that used to overwrite `m->model` first.

**TAGE**: a bimodal base and `tables` tagged tables whose histories run
geometrically from `min-history` to `history` (≤ 64); the longest table whose
tag matches predicts, and a mispredict allocates in a longer table whose entry
is not useful. ⚠️ The history is *mixed* by a multiply, not XOR-folded as
hardware does: a loop's history repeats with the loop, and folding a period-16
history at width 16 sent every phase to one entry with one tag — TAGE paid
three times a period where gshare paid one. A hash is a model choice, and the
one that does not alias on periodic histories is the one that measures the
algorithm rather than the fold.

### What holds it: `tage_check.py`

| | 80 / 160 trips |
|---|---|
| period-8 branch — TAGE | 10 / 10 mispredicts |
| period-8 — gshare (4 bits), bimodal | +8 each: once a period |
| period-20 (past a 32-outcome history) — TAGE vs bimodal | +4 vs +4 |
| alternating — TAGE | 5 / 5 |

and a stand-in `acme.always` is refused before registration, selects after,
is asked about all 160 branches and told all 160 outcomes, mispredicts exactly
the 9 not-taken ones, and reads `acme.bias` as 1. 10/10 mutations. **Counters
that never train** survived until the period-20 program: on any pattern the
history covers, allocation sets a new counter the right way and training is
never needed; past the history a context sees both outcomes, and only training
keeps the rare one from owning it.

⚠️ Adding cores switched gates off, twice. `history_check` picked "the gshare
with the longest history" and got TAGE's comparison core, which had no bimodal
twin, so it DECLINED; `core_check` and `uarch_ir_check` tried to select the
external-predictor core and read its refusal as a fault. Both kinds were caught
only because every `issue_width` gate was re-run and a SKIP read as a failure.

## 10. O9 — returns, and what a branch is

```lisp
(front-end (fetch-width 4) (depth 2) (btb 64) (btb-penalty 3) (ras 8))
```

A return-address stack needs to know which jumps are calls and which are
returns, and **nothing is marked by hand**. The pack derives, from each
instruction's declared effects, whether its `setpc` is guarded (conditional),
whether its target reads a register (indirect), and which register it links
into — an operand written from the pc, or a fixed register such as AArch64's
X30. What a call *is* then comes from the ISA's `defabi`: a jump that links
into the ABI's **link register** is a call, and an indirect jump through it
that does not link is a return. Any ISA with an ABI gets a return stack; one
without cannot, and validation refuses `(ras N)` there rather than keep a
stack nothing can push.

With a front end declared, the classification also settles two things O7
approximated:

* an **unconditional** jump is taken and decode knows it: the direction
  predictor is neither asked nor told, and only its target is in question;
* a **direct** branch the BTB misses costs `btb-penalty` — decode finds the
  target in the word — but an **indirect** one the BTB misses or gets wrong is
  not known until its register is read, so it redirects at resolution like a
  mispredict. `target_mispredicts` counts those and wrong return targets; each
  is also a mispredict, and the front end idles for each exactly as for a
  wrong direction.

A return pops the stack (a wrong or empty top is a target mispredict); a call
pushes the address after it; the stack is circular, so calls deeper than it
overwrite the oldest.

### What holds it: `ras_check.py`

On `returns` and its twin without a stack (`bigbtb`), with `iwabi` declaring
`x1` the link register and `IWJR` both calling and returning:

| | without a stack | with 8 |
|---|---|---|
| a function called from two sites, 8 / 16 trips | 18 / 34 wrong targets | 2 / 2 |
| twelve nested calls, each saving `x1` to memory | 24 | 16 — exactly 8 saved |

and on every run a wrong target is counted as a mispredict and idles the
front end (depth + penalty). 8/8 mutations; **a return miss that was counted
but not redirected** survived until that accounting was checked.

⚠️ The AArch64 seed classifies correctly — `BL`/`BLR` link through the fixed
X30, `RET`/`BR` are indirect through `rn` — but it declares no `defabi`, so its
return stack is inert until one names the link register.

## 11. O10 — issue ports

```lisp
(ports (p0 alu mul) (p1 alu) (p2 br lsu))
```

A unit count says how many operations of a kind can be in flight; it cannot
say that the multiplier and one of the adders are reached through the same
port, and so cannot both *start* in one cycle. That is what a scheduler
designer edits, and it is what `ports` states: each port names the units it
feeds, starts one instruction a cycle, and an instruction issues on any free
port feeding its unit (lowest-numbered first) that also has a free copy of the
unit. No `ports` is a core whose units are their own ports. Validation
refuses a port feeding a unit the core lacks, and a unit no port feeds — it
could never start anything.

### What holds it: `ports_check.py`

On `ported` and its twin `unported` (two adders, one multiplier, the
multiplier sharing `p0`): 24 independent adds cost 13 on both, 24 multiplies
27 on both — nothing in them contends for a port — while adds and multiplies
mixed cost 16 through two ports (floor 12) against 11 unported. 4/4
mutations.

## 12. O11 — the instruction cache, and the wrong path

```lisp
(defmemory l1i (kind cache) (size-bytes 256) (line-bytes 64) (ways 1) (width-bits 32) (latency-cycles 8))
(front-end (fetch-width 4) (depth 2) (icache l1i))
(front-end (fetch-width 4) (depth 2) (icache l1i) (wrong-path-fetch true))
```

§7d kept instruction fetch out of the cache on purpose: a *unified* cache would
put a loop's own lines in competition with its data and move the knee to
wherever the program was linked. That stands. What this adds is a separate
instruction cache, named on the front end the way a core's data cache is
named on the core — the same `defmemory`, the same geometry and LRU, its own
array. A fetch reads one line, so **a line boundary ends a fetch group**, and
a line the cache does not hold stalls that fetch for the cache's latency.

**The wrong path**, in the part a trace-driven model can honestly hold. The
functional side only ever runs what retired, so nothing on a wrong path
*executes* — but *fetch* down it does not need execution, only the prediction
and the time: between a mispredict and its resolution the front end fetches
sequentially from where the prediction pointed, `fetch-width` a cycle, and
those lines land in the instruction cache. That is a prefetch when the program
goes there later and pollution when it does not. It is **bounded by what the
machine can hold** — the fetch buffer and the reorder buffer fill with
wrong-path instructions and fetch stops — not by how long the branch takes to
resolve; a first version fetched for the whole delay and ran seven lines down
a path the machine could hold two of. The path followed is the fall-through
of a branch wrongly guessed not taken, or -- since W1 (§20) -- the target of
one wrongly guessed taken, which decode reads out of the word.
`wrong_path_lines` counts the lines.

### What holds it: `icache_check.py`

On `fetchcache`, `fetchahead` (the same plus wrong-path fetch) and `fetches`
(no instruction cache):

| | measured |
|---|---|
| a cold straight line over 4 lines | 4 misses; 51 vs 19 cycles — exactly 4 × 8 |
| a 2-line loop in a 4-line cache, 8 / 16 trips | 3 / 3 misses |
| a 5-line loop in a direct-mapped 4-line cache | +2 misses an iteration, exactly |
| a warm loop starting two words into a line | exactly 9 cycles an iteration: its line-bounded groups |
| a slow branch mispredicted over code run later | 1 miss with wrong-path fetch, 4 without |
| one mispredict behind 8 chained multiplies | 4 wrong-path lines: the bound, ⌈44 × 4 / 64⌉ + 1 |

and the uncached machine reports no misses and no wrong path anywhere; no
register differs on any machine. 7/7 mutations. Two needed programs of their
own: **fetching across line boundaries** passed everything line-aligned —
four-wide groups never straddle sixteen-word lines from an aligned start —
and **an unbounded wrong path** passed every branch that resolved quickly. The
bound's own program first measured nothing: its chain squared an even seed
eight times, which is zero modulo 2³², and the branch fell through.

## 13. O12 — the wrong path, executed

```lisp
(defcore runsahead ... (memory l1d)
  (front-end (fetch-width 4) (depth 2) (icache l1i) (wrong-path-execute true)))
```

O11 fetched the wrong path in line order because the model had no way to
*run* it: the functional side executes only what retires, and writes the
host's memory as it goes. O12 gives it one — **fork, run, discard**:

1. At a mispredict whose wrong path the trace can name — the fall-through of
   a branch guessed not taken, the target a return stack or target buffer
   predicted, or (W1, §20) the target decode finds in a direct branch's word —
   and *before the correct path's next instruction runs*, the
   functional state is copied: registers, state slots, pc, step count,
   status.
2. The simulator runs from the predicted pc in **shadow mode**: reads go to
   the host's memory **overlaid with the shadow's own stores**; **stores are
   buffered and never reach the host**; a **trap ends the run** without the
   host hearing of it; an instruction that does not decode ends it too; no
   retire events are emitted. Each instruction that completes leaves its pc
   and memory accesses in a trace. At most what the machine can hold is run
   (fetch buffer + reorder buffer).
3. The copy is put back, exactly.
4. When the mispredict resolves, the part of the trace the machine could have
   reached — (resolution − the branch's fetch) × fetch width, at most the
   trace — touches the caches: the **instruction cache along the path the
   wrong path really took**, through its own branches, and the **data cache
   with its loads and stores**. Touched, never charged, and not counted among
   the caches' hits and misses, which stay the path that retired.

⚠️ Step 4 happens *before* the next correct-path instruction runs, not at the
redirect inside its accounting: by then its functional step had already
touched the cache, so the wrong path could neither prefetch for it nor pollute
ahead of it — the right lines in the wrong order. Found by reasoning through
the gate's first program, before it ran.

⚠️ One limit, stated so it is not read as a finding (the other this section
first carried — wrong-path instructions occupying no window, unit or port — is
lifted by W2, §21, which also moves a wrong-path access from "fetched before
resolution" to "issued before resolution"):

* **The host's read hook sees wrong-path addresses.** Wrong-path pointers can
  be anything. A host whose reads have side effects — memory-mapped I/O — must
  not select a core that executes the wrong path.

### What holds it: `wrongpath_check.py`

On `runsahead`, `staysput` (a wrong path that touches nothing) and
`readsahead` (O11's line-order fetch), every program starting with a slow,
cold, taken branch — mispredicted not taken:

| | executed | not |
|---|---|---|
| a wrong-path load of what the correct path loads later | 0 data misses | 1 |
| a wrong-path load evicting a line the correct path reloads | 2 | 1 |
| a wrong-path store of a pointer, reloaded and dereferenced | 0 | 2 — both lines, so the reload saw the store |
| a wrong path that jumps to code run later | 1 instruction miss | 2 (and 2 in line order) |
| one load, then an undecodable word | exactly 1 wrong-path instruction | — |

and on every program the three machines retire the same instructions and leave
the same registers and **all 64 KiB of memory** — the wrong-path store never
landed — and a wrong path the correct path never meets costs exactly the same
cycles as none. 11/11 mutations, including stores reaching the host, a shadow
that cannot read its own stores, registers not restored, an undecodable word
recorded, misses or stall charged, the fork skipped, and the resolution window
ignored. **Charging the wrong path's misses** survived until the timing check
existed.

## 14. E1 — execution-driven: the pipeline executes, the golden model judges

```lisp
(defcore executes ... (front-end (fetch-width 4) (depth 2)) (engine execute) ...)
```

Everything before this is **trace-driven**: the functional side runs the path
that retires, and the pipeline replays it. That is exact for what it models
and blind by construction to whatever never retired — O12 had to fork the
functional side to see a wrong path at all, and still could not make that path
occupy the machine. `(engine execute)` turns the arrangement round:

| stage | per cycle |
|---|---|
| fetch | the **predicted** path, `fetch-width` a cycle, through the instruction cache; decode, direction prediction, BTB, return stack with a checkpoint per instruction |
| dispatch | after `depth`, into the window, through the same rename, queue, port and unit structures as trace mode |
| issue = **execute** | `axis_exec_step64` — the generated executor — on the committed registers and state overlaid, in program order, by what older in-flight instructions computed; a load reads memory overlaid byte-for-byte by older *executed* stores and touches the data cache; a store is held in its entry |
| memory order | a store that executes over a younger load that already read is a violation: squash from the load, fetch it again |
| resolve | a branch whose real next pc is not the predicted one squashes everything younger, restores the return stack, and redirects fetch — **before** commit in the cycle |
| **commit** | the **golden functional model steps**, and every register, state slot, store and next pc the pipeline computed is checked against it; a disagreement is a **replay**: the commit is already right — the golden model made it — and everything younger is squashed |

The architecture is therefore the golden model's **by construction**, and the
replay count is a measurement of the engine's own mistakes: any dependence the
pipeline fails to honour surfaces as a replay rather than as a wrong answer.
Every dependence in `issue_width` is declared, so there it must be zero.

⚠️ Stated limits: branch history is non-speculative (predictors are trained at
commit, re-predicting each branch before its update); a target buffer is always
learned, because a perfect one needs the oracle this engine does not have;
load-queue capacity is not modelled, because loads are not known until they
execute; memory disambiguation is speculative only. A host whose reads have side
effects must not select such a core (wrong paths read).

### What holds it: `xmode_check.py`

* **the anchor**: four branch-free programs cost exactly what trace-driven
  `fetches` costs, cycle for cycle;
* **the judge**: 24 seeded random programs — loops, data-dependent branches,
  loads and stores into one region — and three targeted ones retire the same
  instructions and leave the same registers and memory as the functional
  simulator, with **zero replays** (300 seeds checked by hand: 0 replays, 19 838
  wrong-path instructions squashed);
* a late store over an executed load is caught; a countdown loop's mispredicts
  are the same at 8 and 32 trips.

Getting to zero replays found three engine bugs, each a plausible design and
each wrong:

* **Commit before resolve.** A mispredicted branch completing in a cycle was
  committed with the wrong-path work behind it, up to the commit width, before
  the squash ran.
* **Writes captured by diff.** An instruction's writes were the registers whose
  value changed. A load writing the value the window already showed — put there
  by an older copy of the same load, with a writer in between not yet executed —
  recorded no write, and that in-between writer's value reached the committed
  register file. A write of the same value is still a write.
* **A non-retiring halt took time.** The undecodable word after a program, which
  trace mode never dispatches, was committed one cycle late, and the anchor was
  off by one.

12/12 mutations. Four needed targeted programs, because random ones never
reached them: store-to-load forwarding (a store and a load of one word in flight
together), the rename map rebuilt after a squash (a survivor still executing
when its reader is refetched), and the predictor and target buffer actually used
by fetch — correctness never needs either, so only the loop's mispredicts can
see them. A mutation that only disables the commit check is unobservable here,
and should be: the engine it judges is correct, and the other ten mutations are
the evidence that the judge catches one that is not.

## 15. E2 — the execution-driven wrong path is the real one

E1 made the engine; E2 makes it stand on its own for everything the trace
engine needed a workaround for.

**Counters count the path that retired.** A load on a wrong path touches the
data cache when it executes, and a fetch on one the instruction cache — those
are cache *contents*, and they stay. But the hit and miss each produced is held
on the instruction and credited to the counters only when it commits; so are a
branch's redirect, its wrong target and the front-end idle it caused. A
mispredicting branch on a wrong path redirects fetch all the same, and the
program never had it. Both engines' counters now mean the same thing.

**Speculative history.** E1 trained the predictor at commit, so a branch
fetched while older ones were still in flight was predicted with history stale
by every one of them. The predictor interface (O8) grows three optional calls —
`history`, `set_history`, `speculate` — read only from a predictor whose
`abi_version` is 2, so one built against the first struct is never read past its
end and simply keeps commit-time history. With them the engine:

* records the history before every instruction it fetches;
* moves it on at fetch by each conditional branch's prediction — by what fetch
  *did*, so a predicted-taken branch with no known target counts as not taken;
* on **any** squash, puts back the history from before the first instruction
  squashed — a memory violation's squash as much as a branch's;
* on a mispredict, puts back the branch's own history and moves it on by what
  the branch really did;
* at commit, trains the counter at the index the branch was **predicted** with:
  sets the history back to that instruction's, predicts, updates, and restores.

`gshare` and `tage` implement the three calls; `bimodal` has no history to offer.

**The wrong path, natively.** O12's programs on `xahead` — `staysput`,
execution-driven — need no fork: the engine fetched and executed that path.

### What holds it: `xspec_check.py`

| | execution-driven | trace, no wrong path | trace, forked (O12) |
|---|---|---|---|
| wrong-path load of what is loaded later | 0 misses | 1 | 0 |
| wrong-path load evicting what is reloaded | 2 | 1 | 2 |
| wrong-path pointer stored, reloaded, followed | 1 | 2 | 0 |
| wrong-path jump to code run later | 1 instruction miss | 2 | 1 |

⚠️ The pointer row differs from O12's, and the engine is right to. The shadow ran
its wrong path in program order, so its reload always saw its own store. Here
the wrong-path reload is free to issue before the store executes — speculative
disambiguation — and does: it reads memory, the dereference goes nowhere, and
the violation that would replay it comes after the branch squashed the whole
path. One line is prefetched, not two. The in-flight forwarding it skipped is
held by `xmode_check`'s FORWARD program.

And: a call fetched down a mispredicted path leaves exactly as many wrong return
targets as no call (0 = 0) — the callee is long, so the wrong path never pops
what it pushed; two alternating callers cost a constant; an alternating branch
costs gshare 10 mispredicts at 16 trips and at 32, and **exactly the same** with
a memory violation squashing branches every iteration. Zero replays throughout.

8/8 mutations. Two survived until the programs changed: **a return stack never
restored** came out right while the wrong path returned from the call it made —
a one-instruction callee popped what it pushed; and **history not restored on a
violation's squash** was invisible while the squash removed exactly two
iterations of a period-two pattern — the polluted history *was* the right one —
until the violating loop had to cost exactly what the clean one does.

## 16. E3 — the execution-driven engine, complete

E1 left four things to the trace engine. E3 takes them back.

**Loads and stores known at decode.** The pack carries, per instruction, whether
its declared effects read memory and whether they write it — any expression
that loads, any effect that stores. An execution-driven core therefore knows a
load is a load when it *decodes* it, not only once it has executed, and:

* the **load and store queues** bind, counting what is in flight from dispatch;
* **conservative** disambiguation works without a trace: a load waits for every
  older store to have *executed* — an unexecuted one has no address yet;
* **store sets** work: a violation trains the load's and the store's addresses
  into one set, and a later load waits for older unexecuted stores in its set.

`perfect` stays refused — an oracle over a trace this engine does not have — and
so does `(forwarding false)`, which would need to know a load overlaps an
in-flight store before the load executes.

⚠️ **An undeclared `lsq` means different things in the two engines, by
necessity.** Trace-driven, it means memory ordering is not modelled: loads never
wait for stores and never violate. Execution-driven, memory ordering cannot be
left out — loads read real memory when they execute — so no `lsq` is speculative
disambiguation with no replay penalty: a load that read too early is squashed.
`engine_speed.py`'s loop stores a word and reloads it every iteration, and costs
300 014 cycles trace-driven and 1 100 019 execution-driven for exactly that
reason.

**In order, timed both ways.** An execution-driven core may have no window: the
pipeline's in-order line applies to it as to any other.

**Precise traps.** A trap is taken when its instruction *commits*: the golden
model steps, the host's trap hook decides, and whatever was fetched after it —
down the path the pipeline guessed — is flushed if the handler sends the machine
elsewhere. That is counted as a **trap**, never as a replay: the pipeline
computed nothing wrong. A trap fetched down a wrong path is squashed with the
path and never reaches the hook. `traps` reports the count, and that new pack
function is why the pack ABI is now **v3**.

**The predictor contract, stated.** On an execution-driven core `predict` is
asked at fetch, ahead of older branches' updates; every `update`, at commit and
in program order, is immediately preceded by a `predict` of the same branch.
The header now says so.

### What holds it: `xcomplete_check.py`

| | measured |
|---|---|
| a store aliasing a load every iteration, 8 / 16 trips | speculative 8 / 16 violations; store sets 1 / 1; conservative 0 |
| the same loop, the load never aliasing | conservative 73 cycles, speculative 67, 0 violations |
| 8 loads behind a slow head | 25 cycles with a two-entry load queue, 17 with the window |
| the in-order pair `ifetch` / `iexec` | cycle-exact on four branch-free programs; 16 random programs the golden model's |
| a trap resumed after; a trap sent to a handler | one trap each, zero replays, the hook called as the golden model calls it |
| a trap fetched only down a wrong path | never taken |

8/8 mutations.

### What it costs: `engine_speed.py`

Not a gate — a measurement, so the choice between engines is made on numbers.
On a 10-instruction loop of loads, stores, multiplies and a data-dependent
branch, with every engine retiring the same instructions and leaving the same
registers (checked):

| engine | M instructions/s (E3) | now | relative time, now |
|---|---|---|---|
| functional, no cycles | 1.50 | 4.6 | 1.0× |
| first-order | 1.00 | 3.0 | 1.5× |
| trace-driven `fetches` | 0.80 | 2.1 | 2.2× |
| execution-driven `executes` | 0.30 | 0.9 | 5.0× |

Process CPU time, not the wall clock, so a busy machine's neighbours are not
measured; 200,000 iterations, the cycle counts identical before and after.
Executing every instruction twice — once speculatively, once by the judge — and
holding the window's state is the price of the wrong path being real.

**Where the time went, and what took it back (≈3× every engine).** Profiled,
half of E3's execution-driven time was `strcmp`:

- **Decoding filtered by name before encoding.** Every decode loop — the
  decoder's, the lifter's, the executor's two, `axis_sim_touches` — compared
  each table entry's ISA (and mode, and unit) as a string before testing the
  word against its mask. The mask and match now go first: one AND and a
  compare reject nearly every entry, and the string filters run only for the
  candidates. The conditions are a conjunction of pure tests, so the order is
  free.
- **Register classes looked up by name, on every operand of every step.**
  `axis_reg_class_of` compares pointers first (a kind is a literal the linker
  usually merges with the class's own name), then first characters, and calls
  `strcmp` only when those agree.
- **The execution-driven engine's per-instruction facts** — loads, stores,
  unit, operand directions, classes, rename pools, link and target operands —
  were rederived from strings at every dispatch, fetch and resolve. They are
  built once per lift-table entry (`axis_x_meta`) on first use. The window's
  occupancy (waiting, loads, stores) is kept as counters, not counted by a scan
  every cycle; a squash recounts the survivors.
- **The ROB ring was indexed `seq % rob`**, a division with the core's size,
  in every scan of the window. Storage is now `seq % AXIS_SIM_ROB_MAX`, a power
  of two, while what the core may hold is still `rob_tail - rob_head < rob`.
- **The rest.** Execute copies only the state slots the machine has, not
  sixty-four. The store-address scan, which only the trace engine's memory
  order reads, is not run every cycle for other cores.

**Then decoding itself (functional ≈9× E3, every engine ≥4×).** A step scanned
the lift table four times — the executor's decode and its lane loop, the
touched registers, a timing model's lift — and every operand of every step
found its class and its role by name:

- **A decode memo.** What a word decodes to is a fact about the word: the
  table is constant and its constraints read only the word. `axis_sim` gains a
  trailing, optional `memo` (NULL: decode every step, as before); a pack
  machine owns one, direct-mapped by word, keyed by the isa pointer, cleared at
  every reset. The executor is split so a decoded word is executed without
  another scan: `axis_exec_decode64` + `axis_exec_step64_decoded`, with
  `axis_exec_step64` the two in sequence. On a description the size of
  AArch64's, this is the difference that matters; this loop's table is small.
- **Classes and roles fixed at generation.** `axis_lift_operand` gains
  `reg_class` (an index into `axis_reg_classes`, -1 for none) and `role_code`
  (`AXIS_ROLE_IN`/`OUT`/`INOUT`/`ENC`), appended so positional initialisers
  stay correct; `kind` and `role` stay the names. The pointer comparison above
  rarely hit — a table's literals and the classes' names live in different
  translation units.
- **A word that is not a lane group** is executed as its first entry, without
  scanning the table for it again.

| engine | M instructions/s (E3) | now |
|---|---|---|
| functional | 1.50 | 13.3 |
| first-order | 1.00 | 10.3 |
| trace-driven | 0.80 | 4.3 |
| execution-driven | 0.30 | 1.3 |

What was left in the execution-driven engine was its own: before each execute
the whole register file was copied and the window's writes laid over it, and
after it the file was compared slot by slot to find what changed (the safety
net that catches a write no operand declares).

**E4 — the view is kept, not rebuilt.** The engine now keeps the committed
registers beside the golden model's own. An execute patches the window's
writes into that view, noting the slots; afterwards a slot the instruction
declares, or whose value is no longer what the window put there, is a write,
and exactly the noted slots are put back. The net under it is one comparison
of the whole file — which is the committed file again unless something
undeclared changed, and only then is it searched. Commit lays the
instruction's writes on the view and compares it with what the golden model
left, so it copies nothing either; on a disagreement the view takes the golden
model's registers. A host's `set_reg` invalidates it.

A profile had put the two copies and the scan at a quarter of the engine's
time; taking them out bought 6% on this loop (1.23 → 1.31 M instructions/s,
cycle counts identical), because a 64-slot file is cheap to copy and the
comparison that replaced the scan is not free. The cost removed grows with
the register file and what replaced it does not, but that is an argument, not
a measurement: nothing here times AArch64's file. Dispatch — clearing and
filling a window entry — is now the largest single cost.

### What holds it: `xview_check.py`

A copy cannot go stale; a view can, in two ways:

| | measured |
|---|---|
| a load of a cell that reads differently each time | 1 replay — the load's — and its readers agree with the golden model |
| a register the host writes 96 instructions ahead of its first reader | 0 replays |

and the existing execution-driven gates are unmoved: `xmode`, `xspec`,
`xcomplete`, `mcx` and `a64x` pass with the same counts and zero replays, and
the same gate passes on the engine as it was. 5/6 mutations: writes found by
difference alone, slots not put back, a patch value forgotten, no resync after
a disagreement, a silent `set_reg`. The two the new gate catches survived all
four older ones — none of them makes the golden model disagree about a
register, or writes one mid-run. The sixth, removing the net, survives
everything, as it would have before: no instruction in any corpus writes a
register it does not declare.

## 17. MC1 — several cores, one memory

`run_cores(machines, count, limit)` advances execution-driven machines of one
library together: every running core one cycle, in the order the host listed
them, before any core another. Their memory is the host's, so machines made
with the same hooks share it, and nothing else is shared — each keeps its own
window, predictor, caches and golden model.

**A store becomes everyone's when it commits.** Stores sit in the window until
they retire (E1), so the only moment another core can see one is its commit —
and at that moment the pack's write hook snoops every other core in the group:
a load that has executed, has not committed, and read any of those bytes read
them stale. It is squashed with everything after it and fetched again, counted
as a **snoop**, the way a core watching its peers' invalidations squashes a
load it ran early. Without the snoop, the golden model would catch the stale
value at the load's commit and call it a replay; with it, a replay stays what
it was, the pipeline's own error, and none happens here.

**The memory model is sequential consistency, by construction.** Each core's
memory order is its commit order, every store is visible to every core the
instant it commits, and a load that commits read memory as it was at its
commit (anything that changed it since it executed snooped it). So the cores
together perform one interleaving of their commits. Within a cycle, core 0's
commits are visible to core 1 in that cycle and core 1's to core 0 the next:
the order is a choice, made fixed so a run is reproducible.

Trace-driven cores are refused (-1): they have run their programs before their
pipelines see them, so there is no moment at which another core could change
what one read. So is a machine listed twice. A step limit now binds between
two instructions rather than between two cycles — a wide commit stops at it,
for `run` as much as for `run_cores`.

Coherent timing comes from the memory system as it is (MS5): cores that are
ports of one `defmemsys`, joined with `memsys_join`, are charged its
protocol's forwards, upgrades and invalidations through the same
`axis_sim_touch` every execution-driven access already goes through. This
gate holds the functional and ordering half; the coherent-timing half is
`memsys_pack_check.py`'s, so far on trace-driven cores.

### What holds it: `mcx_check.py`

On `issue_width`'s execution-driven core:

* **apart, nothing changes** — five pairs and a quartet of seeded random
  programs on disjoint regions, and a core whose loads forward from its own
  stores: together, each core's cycles, steps, registers and memory are exactly
  its own alone, with no snoops;
* **store buffering** — `x = 1; r = y` against `y = 1; r = x` behind 0–6 slow
  multiplies each (49 timings): (0, 0) never; (0, 1), (1, 0) and (1, 1) all
  happen; 41 snoops;
* **message passing** — data, then flag, against a spin on the flag then a
  read of the data, behind 0–6 multiplies: the datum every time; the spin's
  early loads snooped (6);
* zero replays anywhere; a limit of 7 stops both cores at 7; a trace-driven
  core and a machine listed twice refused.

9/9 mutations: no snoop, a snoop that ignores the store's width, one that
squashes without refetching, one that refetches without squashing, cores run
one after another instead of in lockstep, a commit that ignores the limit, a
trace-driven core or a duplicate accepted, and a core snooping its own store
(caught only once the forwarding program made a load read its own core's store
from the window — the first version's load always lost the race to a
violation instead).

## 18. A64-1 — AArch64 on the execution-driven engine

The engine's first real ISA. Run as it stood, it already left AArch64
programs with the golden model's architecture — that is by construction — but
paid for it in replays, about one program in ten: the pipeline knew only the
registers an instruction's OPERANDS name, and an AArch64 instruction reads and
writes more than that.

* **State is renamed like registers.** A compare writes NZCV and a select, a
  conditional branch or an ADC reads it; FP reads FPCR; the exclusives
  monitor is state too. Which state each instruction reads (a state name in
  any value, guard or address of its declared effects) and writes
  (`setstate`) is a table the pack carries (`AXIS_SIM_STATEOPS`), resolved
  against the state slots the host names at reset. Dispatch gives each state
  slot a producer past the register file, so a CSEL waits for its SUBS as an
  ADD waits for the ADD before it.
* **So are registers no operand names.** BL writes X30 (`Loc::FixedReg`): a
  destination like any other, from that register file's rename pool — and the
  RET that reads X30 waits for it.
* **SP is state reached through register 31.** An operand whose class aliases
  an index to state (`a64_gpr64sp` 31 → `sp`) names that state's producer, not
  a register slot.
* **A 128-bit destination is two slots**, and a zeroing 64-bit write to it
  clears the second. Execute recorded the slots a destination STARTS at
  whether or not their value changed (E1's lesson), but not the rest of it: a
  write of the value the window already showed in the upper half went
  unrecorded, and an older in-flight write to the same register won at
  commit. Every limb of every destination is now recorded.
* Sources and destinations per instruction go from 4 to 8: an FMADD reads
  three registers and FPCR, a load pair with writeback writes three.

The corpus declares an ISA and no core — AArch64 microarchitecture does not
belong in this repository — so the gate composes a neutral core (the same
window, front end and predictor as `issue_width`'s `executes`) and the AAPCS64
link register onto the ISA in a temporary file. The ABI is what lets the
return stack find calls and returns: BL and BLR link into X30, RET jumps
through it.

### What holds it: `a64x_check.py`

507 of the corpus's straight-line instructions run under the 64-bit C
executor and retire cleanly. On them:

* 48 seeded random programs (1900 instructions) — integer, flag-setting,
  conditional, loads and stores of every width, atomics, exclusives, scalar
  and vector floating point — leave exactly the golden model's registers,
  state and memory, with zero replays (before: 7 replays in 60 programs; the
  five minimised all involve flags, a 128-bit write-after-write, or memory
  the first harness aliased — see below);
* a countdown on NZCV, a chain of compares and selects, calls from two
  alternating sites, a push/store/load/pop loop through SP, and a Q load
  racing a 128-bit add to the same register: zero replays;
* return targets: 0 wrong with an eight-entry return stack, 5 without (6
  before D1, §19, changed how a cold BL is fetched).

The harness's memory is exact — a flat 64 KiB and a byte table keyed by the
whole address beyond it. The first harness wrapped addresses modulo 64 KiB,
which aliased two addresses in the host's memory that the pipeline, rightly,
did not.

Mutations: state reads not renamed, state writes not renamed, the SP alias
ignored, only a destination's first limb recorded — 4/4 caught. The SP one
only by timing: without the alias, SP and XZR — register 31 of two classes —
share a producer, so a load through SP waited for a compare into XZR; the gate
holds that load to exactly the cycles of one through X19 (28 = 28).

The fixed X30 write is renamed and its mutation survives, because nothing on
this engine can observe it: BL has no sources, so it issues before anything
fetched after it, and a reader of X30 dispatches cycles after BL has
completed. The renaming is there for what it is owed — a physical register
from the pool, and a producer the window can rebuild after a squash — not for
a race this pipeline cannot have.

### A64-2 — the trace-driven engine, the same dependences

The trace-driven pipeline dispatched from operand registers only, so on
AArch64 its CSEL did not wait for its SUBS and its SP load waited for a
compare into XZR: architecture right (it is the functional simulator's), time
wrong. It now takes its producer slots and its implicit reads and writes from
the same per-instruction facts the execution-driven engine uses
(`axis_ooo_dep_slot`, `axis_ooo_implicit_reads`, `axis_ooo_implicit_writes`
over the same `axis_x_meta`), the fixed register counted against its rename
pool before dispatch. No other corpus moves: `issue_width` has no state and
no aliasing class, and the RISC-V corpora that declare state are timed only
by the first-order scoreboard, which this does not touch.

`a64x_check.py` adds a trace-driven twin of its core, and holds it to the
execution-driven core's cycles on the programs with no branch to guess and no
store to order — the flag chain 27 = 27, the loads through SP and X19
28 = 28, the wide pair 11 = 11. Mutations: implicit reads dropped, implicit
writes dropped, the SP alias ignored, each in the trace engine alone.

**Not yet:** the SVE corpus on these engines; and the instructions the 64-bit
C executor cannot evaluate — wider-than-word values and the directed-rounding
forms — stop a program as unsupported on every engine alike.

## 19. D1 — decode knows where a direct branch goes

A direct branch's target is its own address plus a field of its word. No
register is read, so a front end that has decoded the word knows where the
branch goes — without a predictor's help, and long before the branch executes.
The trace-driven front end has charged exactly that since O7: a predicted-taken
direct branch the target buffer does not hold costs `btb-penalty`, "the time
decode takes to find it". The execution-driven engine did not: with no entry
it fell through, executed the branch, and redirected at resolution. Every
direct jump's first encounter was a full mispredict, and so was every eviction.

**The target is the description's own `setpc`.** For every instruction whose
`setpc` names no register operand, the simulator pack carries a function of
`(lifted, pc)` — the expression lowered by the 64-bit executor's emitter with
only the immediates bound, masked at the ISA's word. One statement of where
the branch goes, read twice: by the executor when the branch runs, and by
decode before it does. A branch whose target cannot be lowered is **declined
by name** in the generated source (`/* direct-targets: N lowered, M declined:
… */`) and behaves as before; `redirect_check.py` fails any corpus that
declines one.

**Execution-driven fetch** now asks it. Predicted taken, no return-stack
entry, no buffer entry, direct: the target is decode's, fetch resumes there
`btb-penalty` cycles later, and nothing is a mispredict. Indirect, the word has
no such field, and fetch falls through as it did.

The corpus gained `IWJ`, a direct unconditional jump: every jump it had either
asked a predictor (`IWBNZ`) or read a register (`IWJR`), and `xsmallbtb`, the
execution-driven twin of O7's one-entry buffer.

### D2 — while decode looks, fetch runs on

A branch the target buffer does not hold is, to the front end, not a branch:
until decode says otherwise it goes on fetching what follows, `fetch-width` a
cycle for `btb-penalty` cycles. Decode discards those instructions — they
never reach the fetch buffer — but the lines they came from are in the
instruction cache: prefetch if the program falls through to them later,
pollution if not. Touched, never charged, at most what the front end holds
-- until D4 (§26), which makes that fetch wait on a line it misses.
Execution-driven, always; trace-driven, on a core that models its wrong path
at all (`wrong-path-fetch` or `wrong-path-execute`), where the lines count
among `wrong_path_lines`. The corpus gained `xdecodes`: `xahead` with a buffer
that costs three cycles to miss.

## 20. W1 — the wrong path of a branch guessed taken

O11 and O12 followed one wrong path: the fall-through of a branch guessed not
taken, "the one wrong path a trace can name without a target it never saw". A
branch guessed **taken** that falls through sent the front end to its target —
and the trace never saw the program go there, so there was no wrong path at
all. Every loop exit is this case.

D1's function names it. The wrong path starts at the target the buffer holds
for this branch if it holds one; otherwise at the target decode finds, and
**`btb-penalty` cycles after the fetch**, because that is when the front end
learned it. That delay is part of the wrong path's window: a branch that
resolves before decode has found its target has no wrong path to speak of. An
indirect branch guessed taken with no entry had nowhere to go -- which W6 (§24)
reads as: nowhere but on.
Both `wrong-path-fetch` (line order) and `wrong-path-execute` take it.

The corpus gained `runsbtb`: `runsahead` with a one-entry buffer.

### What holds them: `redirect_check.py`

| | measured |
|---|---|
| 4 cold direct jumps, execution-driven | 0 mispredicts, 4 buffer misses, 20 cycles = its trace twin's 20 |
| 4 cold indirect jumps | 4 mispredicts: a register is not a field |
| two branches thrashing a one-entry buffer, 8 → 16 trips | 0 more mispredicts; 5 more evictions, each exactly 3 cycles |
| a loop branch with the same load on both sides | 3 mispredicts save 3 data misses — the exit, guessed taken, included |
| the same, its target evicted from the buffer | exactly 12 fewer wrong-path instructions: `fetch-width` × `btb-penalty` |
| the same, its target still in the buffer | the same count as a perfect buffer |
| a branch that resolves before decode finds its target | one data miss more: its wrong path loaded nothing |
| code one line past the target, run after the loop | 2 instruction misses fetching in line order, 3 without |
| a jump decoded two words before the line the program comes back to | 2 instruction misses, 3 on a buffer never missed — on each engine |

11/11 mutations caught: no decode redirect, a redirect that costs nothing, a
target four bytes off, no wrong path for a taken guess, decode's delay ignored,
the delay charged when the buffer held the target, the buffer's entry ignored,
line-order fetch left at the fall-through only, and for D2 no fetch while
decode looks on either engine and one that fetches a single word. A ninth — handing an
indirect jump a direct branch's function — is equivalent: fetch asks whether
the branch is indirect before it asks decode.

Twice the `FAR` program measured nothing, each time a miss saved cancelling a
miss caused in a four-line instruction cache: the target in the loop's own
set; then in the set a cold mispredict's fall-through fetch had polluted. The
program says where the lines have to be and why.

## 21. W2 — the wrong path holds what it uses

O12 ran the wrong path and then touched the caches with it, all at once, at
resolution. Its instructions were in no window, held no register, used no
unit. W2 puts them in the machine.

Until its branch resolves a machine does not know a path is wrong, so it
treats it as any other. Each instruction of the shadow's trace is **fetched**
`fetch-width` a cycle from where the wrong path started, **dispatched**
`depth` later if the window has an entry, the issue queue a slot, the load or
store queue a slot and the rename pool a register for each result — and waits
if not, as the right path does — and **issued** when its operands are ready
and a unit and a port are free, behind everything older. When the branch
resolves, everything after it leaves the window, and the rename map and the
physical registers are rebuilt from what is left.

What it costs the program:

* **A unit that is not pipelined is held for the whole latency.** Issue is
  oldest first, so within a cycle a wrong-path instruction never beats an
  older one to a unit or a port. But one that takes a unit in a cycle nothing
  older wanted it still has it when something older does.
* **It is still held after the squash.** The model does not abort an operation
  in a unit; it stops waiting for it. The right path, a refill later, can
  arrive to a unit that is not free. A unit that *can* be stopped says so
  (W4, §23).
* **A load touches the data cache when it issues**, not when it was fetched:
  one still waiting for an operand — or for a register, or for a line an
  earlier wrong-path load missed on — when the branch resolves never happened.
  A miss is the wrong-path load's own latency, and nobody else's: the
  counters and the right path's stalls are untouched, as in O12.
* The instruction cache is touched by what was **fetched**, as before.

Nothing on a wrong path retires, trains a store set, or counts as a
memory-order violation.

The corpus gained `contends` / `contendsnot`: one multiplier, not pipelined,
eight spare registers, a front end one stage deep.

### What holds it: `occupancy_check.py`

| | executed | not |
|---|---|---|
| a wrong-path multiply that took the multiplier while the branch's chain was adding | +2 cycles: latency − 1 | — |
| the same wrong path, an add instead | +0 | — |
| a wrong-path multiply issued beside its branch, a multiply first on the right path | +1: latency − 1 − depth | — |
| a wrong-path load whose address is ready | 0 data misses | 1 |
| one whose address is a multiply behind the branch's operand | 1 | 1 |
| a load through a pointer another wrong-path load missed on | 1 | 1 |
| nine wrong-path writes, eight spare registers, then the right path | +0 | — |
| a wrong-path load behind those nine writes | 1 | 1 |

and on every program both machines retire the same instructions and leave the
same registers and memory.

11/11 mutations caught: the wrong path never entering, never squashed (a
hang, which the gate's caller times out), keeping its registers at the squash,
taking none, taking no unit, ignoring its operands, ignoring the front end's
depth, touching the cache at dispatch, missing for free, and its misses
counted or charged. Nine of them here; ignoring the depth is caught by
`redirect_check.py` (a wrong path that starts late must also dispatch late),
and a miss charged to the right path by `wrongpath_check.py`, as it was in
O12. A twelfth — wrong-path dispatch not held to the dispatch
width — is equivalent on every core here: the wrong path is fetched
`fetch-width` a cycle, and no core fetches wider than it dispatches.

Three programs first measured something else. The "unreached" load was
prefetched anyway — by the wrong path falling through into the right path's
own load two words on, so the wrong path now ends at a word that does not
decode. The crowd of writes ran eight cycles *faster* with the wrong path than
without, because it had fetched the program's second cache line early. And a
wrong path that took no registers at all passed the crowd, having none to give
back, until a load was put behind it.

## 22. W3 — the wrong path mispredicts too

O12's shadow runs where the wrong path's own branches really go. The front
end did not: it went where the predictor said, and for a conditional branch
the predictor had never seen — which on a wrong path is most of them — that is
the other side. So the shadow **forks again** at each wrong-path conditional
branch the predictor gets wrong: it runs the predicted side, a *detour*,
recorded after the branch; that fork is discarded, its stores with it; and the
run goes on down the side the branch took.

The window (W2) then does what a machine does. It fetches the detour behind
the branch until the branch — itself an entry in the window, waiting on its
operands like any other — resolves; squashes the detour; and resumes fetching
the path the branch took, a refill later. Both sides reach the caches: the
detour's loads if they issued before the wrong-path branch resolved, the
resumed path's if they issue before the outer one does.

One level here: a detour's own branches are followed where they go,
unconditional and indirect branches on the wrong path are taken as predicted
right, and a taken guess the target buffer lost is not charged decode's time
there. W5 (§24) lifts all three.

### What holds it: `wrongpath_check.py`

Its programs' wrong paths had ended in an always-taken branch over the right
path's code — which the predictor, cold, guesses not taken. Their wrong-path
instruction counts rose (7 → 14 where a detour is now fetched) and every miss
count stayed. Two programs were added:

| | executed | not |
|---|---|---|
| a wrong path whose own branch is mispredicted: the detour loads A and stores a pointer over X; the resumed path loads X and through it | 0 data misses | 3 |
| the same, the outer branch resolving sooner | 1: the resumed path's second load is a refill too late | 3 |

The resumed path reads X as memory has it, not as the detour stored it — or
its second load would have gone where the pointer led, and the right path's
third line would have missed.

6/6 mutations caught: no detours, no resume, a detour never squashed, a
resume with no refill, the detour's registers kept, and the detour's stores
kept. The last survived a first version of the program, which also loaded the
word the stored pointer led to: a resumed path that saw the store prefetched
that line instead of the other, and the count was the same.

## 23. W4 — a unit that can be stopped

```lisp
(units
  (mul (count 1) (pipelined false) (abort true)))
```

W2 left a squashed multiply in the multiplier: "the model does not abort an
operation in a unit; it stops waiting for it." Whether a divider can be
flushed is a property of the divider, so it is the unit's to say.

`(abort true)`: what a squashed instruction held of this unit -- the copy, or
the lanes it took of one -- is given back, and the unit is free **the cycle
after the squash**. The cycle the squash arrives in is still the wrong path's:
an older instruction that became ready in that same cycle starts one cycle
late, not `latency - 1` late and not on time. Only what is still the
instruction's is returned, so a pipelined unit, which was somebody else's a
cycle later, has nothing to give; the validator refuses the clause there
unless the unit has lanes and so holds them for several beats. Every squash
aborts -- a mispredict's, a replay's, a trap's -- on both engines.

It is a table beside the core's, as a unit's lanes are: nothing in the pack
ABI moves.

The corpus gained `aborts` (`contends` with a multiplier that aborts) and the
pair `xcontends` / `xaborts` on the engine that executes its own wrong path.

### What holds it: `occupancy_check.py`

| | holds | aborts |
|---|---|---|
| a wrong-path multiply issued a cycle before an OLDER one was ready, its branch resolving the cycle that one is | +2: latency − 1 | +1: the cycle the squash arrives in |
| a wrong-path multiply issued beside its branch, a multiply first on the right path | +1 | +0 |
| a wrong-path multiply holding the unit while its branch is unresolved | +2 | +2: nothing is aborted before the squash |
| the older multiply, on the execution-driven pair | — | the same cycle saved |

and every other program of the gate costs the two machines the same.

5/5 mutations caught: an abort that frees nothing, one that frees the unit in
the cycle of the squash, every unit aborting whatever it declares, and a
squash that aborts on one engine only -- each engine in turn.

The first cross-engine check compared both programs and failed on the second:
the execution-driven engine's refill is a cycle longer than the trace's, so
its right-path multiply arrives after an unaborted one has finished anyway.
What is compared across engines is the instruction that was already in the
window.

## 24. W5, W6 — a detour is a wrong path, and a jump is predicted on one

W3 forked the shadow once: "a detour's own branches are followed where they
go", and every unconditional or indirect branch on a wrong path was "taken as
predicted right". Both were the trace speaking for the front end.

**The front end's answer is worked out the same way everywhere** now. At each
wrong-path branch: a conditional one asks the direction predictor; one guessed
taken goes where the return stack says, or the target buffer, or -- for a
direct branch neither holds -- where decode finds in the word, `btb-penalty`
cycles later; and an indirect one with no entry anywhere has nowhere to go but
on. Where that is not where the branch went, the shadow forks and runs the
side the front end chose.

* **Detours nest.** A detour is run by the same code that runs the wrong
  path, so its branches fork again: `AXIS_SIM_WP_DEPTH` (4) deep, past which a
  branch is followed where it goes. The window keeps the open branches
  outermost first and asks them in that order each cycle, since one resolving
  takes every detour inside it with it; fetch then resumes down the side that
  branch took, and no further than where the next one out resumes.
* **A detour is no longer than the room left.** What was fetched ahead of a
  detour is still in the fetch buffer and the window beside it, so a detour
  gets what the machine holds *less* what precedes it on the way down. Giving
  each detour the whole machine again let a wrong path hold more than the
  machine does.
* **Decode takes its time on a wrong path too.** A taken branch the front end
  got right but had to decode for holds what follows it back by
  `btb-penalty`, and a detour that starts at a decoded target starts that
  much later.
* **The return stack is the shadow's while it runs.** Wrong-path calls push
  and returns pop, a detour's pushes go when it does, and the stack is put
  back with the registers at the end.
* **A branch whose detour recorded nothing still stops fetch.** The front end
  went somewhere that did not decode; it waits there for the branch to
  resolve. Before, such a branch read as one predicted right.

**W6: nowhere to go but on.** The same rule on the *right* path. A jump through
a register that the buffer does not hold -- or a return with nothing on the
stack -- is, to the front end, not a branch it can follow: it fetches what
comes after until the jump has read its register. That is its wrong path. The
execution-driven engine always did this, being a front end; the trace said the
branch "has nowhere to have gone" and gave it none.

The corpus gained `runsreturns`: `runsahead` with a return stack.

### What holds them: `wrongpath_check.py`, `redirect_check.py`

| | measured |
|---|---|
| a wrong-path branch whose detour has a mispredicted branch of its own, each side loading a line the right path loads | 0 data misses; 3 with no wrong path |
| a detour that is a straight line longer than the machine, seven instructions deep in the wrong path | 46 wrong-path instructions: the 44 the machine holds, once, and the 2 of the path its branch took |
| a wrong path with a jump through a register, a load after it and a load where it goes | 2 misses with no wrong path, 1 on a buffer that holds every target, 0 on one that does not hold the jump |
| a wrong path with a direct jump to a load, its branch resolving at once | 0 with the target in the buffer; 1 where decode has to find it |
| a wrong-path branch guessed taken that falls through, a load at its target | exactly 1 data miss more where decode has to find the target |
| the program's own jump through a register no buffer holds, a load after it | 1 mispredict, 0 data misses -- on both engines; 0 and 1 on a perfect buffer |
| the same, a return with an empty stack | 1 and 0 |
| a call on the wrong path, then the program's return | 0: the stack is empty again |
| a call on a *detour*, then a return on the path its branch took | 0 |

10/10 mutations caught: one level of detour; a wrong-path jump through a
register followed where it goes; no decode time on a wrong path, for a branch
predicted right and for a detour that starts at a decoded target; a detour
given the whole machine; the stack kept after the shadow, and after a detour;
a return with an empty stack asking the buffer instead; and for W6 no wrong
path for the jump, or for the return. A detour starting on time survived
until a program had a wrong-path branch guessed *taken* that falls through --
trained on the right path, kept out of a one-entry buffer by a jump behind
it, and met again on the loop's exit with its counter at zero.

`redirect_check.py`'s evicted loop moved, and says why. Its exit's wrong path
is the loop again, and that loop's own branch -- taken, and not in a one-entry
buffer -- now costs decode's time on the wrong path: 18 fewer wrong-path
instructions, not the 12 the program exists to measure. The loop is longer
than what the decoding machine fetches before the branch resolves. A longer
loop that still loaded a new line every trip then measured 20: a load missing
each trip backs the window up, and how long the branch waits to enter depends
on how fast fetch was feeding it. It loads one line.

## 25. D3 — a predictor overridden at decode

```lisp
(branch (penalty 0) (predictor gshare) (entries 256) (history 8)
        (overrides (predictor bimodal) (entries 64) (cycles 2)))
```

§23's old list ended with "a predictor overridden at decode, which no core
here declares". A predictor worth having does not answer in the cycle fetch
needs an answer in, so a machine keeps a quick one for fetch to follow and
lets the real one speak a few cycles later. `(overrides ...)` declares the
quick one -- two-bit counters by pc -- and how many cycles after the fetch the
core's own predictor overrides it.

Where the two agree nothing happened. Where they do not, and fetch had really
gone somewhere else, the front end is redirected at decode:

* **quick "not taken", real "taken"**: fetch ran on past the branch and is
  sent to its target -- from the buffer, or the word (D1). This is the
  decode-time redirect of a branch guessed not taken. It costs `cycles`, or
  `btb-penalty` if decode needed longer for the target anyway.
* **quick "taken", real "not taken"**: fetch went to the target the buffer
  holds and is sent back to the fall-through, `cycles` later and in a new
  fetch group. With no target in the buffer the quick guess had nowhere to
  send fetch, and nothing is undone.

Either way what was fetched meanwhile is discarded and the lines it came from
are asked for (D2, D4).

**It costs time, never accuracy.** What the machine predicted is the core's
predictor's answer, and a mispredict is that answer being wrong. So when the
real predictor is wrong and the quick one disagreed -- the quick one was
*right* -- that is worth nothing: the wrong path starts `cycles` later,
because decode had to speak before fetch went down it. The quick table keeps
no history, so a squash has nothing of its to put back, and it is trained with
what a branch did when the real one is.

It is a table beside the core's: nothing in the pack ABI moves, and a core
without the clause emits the manifest it did.

The corpus gained `overridden` / `overridesnot` and `xoverridden` /
`xoverridesnot`: gshare over a bimodal table, and the same without, on each
engine.

### What holds it: `override_check.py`

| | measured, 16 more trips |
|---|---|
| a branch taken every other trip -- bimodal counters never call it taken, gshare learns it | 16 cycles more: 8 redirects, exactly 2 each, on both engines |
| a branch taken three trips in four -- bimodal counters always call it taken | 8 cycles more: 4 sent back, exactly 2 each |
| the same programs, mispredicts | the same on the machine with the clause and the one without, at both lengths |
| a branch in the last word of a line, redirected into a line the cache has lost | 8 fewer instruction misses, and no cycle more: the fill began while decode looked |
| a loop whose fall-through loads the next trip's line, mispredicted while gshare's history fills | 14 data misses against 6: the wrong path starts too late to load |

12/12 mutations caught: an override that costs nothing, on each engine; one
that costs a cycle more; the quick predictor deciding what is predicted; a
branch guessed taken not sent back, on each engine; no fetch while decode
looks, on each; a quick table never trained, on each; and a mispredict's wrong
path starting on time.

Three programs measured nothing first. A value flipped by a *multiply* made
the loop four cycles a trip in its back end, and an override cost it nothing:
a cycle lost in the front end is a cycle of the program's only if the front
end is what the program waits on. The fetch-ahead program in three lines had
every line in the cache -- from the wrong paths of the first mispredicts --
before gshare had learned the branch. And "mispredicts exactly as often" does
not hold of the warm-up of one program on the execution-driven engine: a
predictor there is trained when a branch *commits*, so a fetch held two cycles
at decode asks a table that has learned two cycles more. The gate says which
program, and holds the rest to it.

## 26. D4 — a line asked for is on its way

D2 touched every line in reach and "a miss on a line fetched while decode
looked stalls nothing: the line is simply there afterwards". A miss that began
while decode looked cost nobody anything, and one behind it was free too.

Each line of the instruction cache now has the cycle it arrives. Asked for at
`t`, a line the cache did not hold is there at `t` + the cache's latency --
whoever asked:

* **The fetch that runs on while decode looks waits on its misses.** It is
  the same fetch the program's own is, `fetch-width` a cycle from the cycle
  after the branch, and nothing past a missing line is asked for until it
  lands -- which is usually after decode has spoken.
* **The program waits for what is left of a fill.** Coming to a line that is
  on its way, fetch waits until it arrives. That is not a miss: the line was
  asked for already.
* **Execution-driven, the same holds of a squashed path.** Fetch that missed
  down a wrong path and was redirected leaves the fill running; the right
  path, landing in that line, waits for it.
* **Trace-driven, that fetch runs once the branch's own fetch cycle is
  known** -- after the branch is dispatched, where before it ran at the
  functional step and so before the branch's own line was looked up.

Wrong-path lines fetched in line order or by the shadow (O11, O12) say
nothing about when: they are there at once, as before.

The corpus gained `xwidedecodes` and `widedecodes`: eight words a cycle, so
three cycles of decode reach a line and a half past a jump.

### What holds it: `redirect_check.py`

| | measured |
|---|---|
| a jump in the last word of a line into the next line | 1 instruction miss fewer than a machine that decodes nothing, and exactly the same 25 cycles -- on each engine |
| a branch whose wrong path misses on the line its right path lands in, waiting on an add or on a multiply | the same 25 cycles either way |
| a jump at the end of a line, then the line two past it, fetching 8 wide | 3 instruction misses: fetch waited on the line between and never asked for that one |

6/6 mutations caught: a line on its way that is there at once, for each
engine's fetch; a fetch that does not wait on its miss; a fill that lands the
cycle it is asked for; a miss that starts no fill; and the fetch run at no
particular time.

The first of those programs jumped to the first word of the next line, and
mispredicted on the trace-driven machines: to a trace, a jump to the next
instruction is a branch that fell through. It jumps over one word.

## 27. What is not here

* **Detours more than four deep**, past which a wrong-path branch is followed
  where it goes (W5).
* **What a wrong path would have taught.** Nothing on one trains a predictor,
  a store set or the target buffer, and its branches ask the core's own
  predictor only: the quick one of D3 is not consulted there, and fetch does
  not run on while decode looks at a wrong-path branch (D2 is the right
  path's).
* **When a wrong-path line arrives**, trace-driven (D4): lines the shadow or
  line-order fetch touched are there at once. Only the program's fetch, the
  fetch that runs on while decode looks, and the execution-driven engine's
  own wrong path start a fill that takes time.
* **A quick predictor that is not bimodal** (D3). One with history would need
  it put back at a squash, as the core's is.
* **What an abort costs** (W4). The unit is free a cycle after the squash and
  owes nothing; a unit shared between cores does not give its turn back.
* **A conditional branch through a register**, guessed taken with no entry,
  that falls through: counted a mispredict although fetch, having nowhere to
  go, went the right way. No corpus here has one.
* **A jump to the next instruction**, trace-driven: the trace sees a branch
  that fell through.
* **Weaker memory models** (MC1) are `docs/memory_model_design.md`: a store
  buffer, and loads seen in any order, for a core whose ISA's model allows
  them. A core that declares neither is sequentially consistent, as here.

## 28. The ABI

`axis_sim_core` gained the `lsq`, `rename` and `predictor_history` fields at
its end, with an `axis_sim_rename` table type, then `replay` and `store_sets`
(O5); `axis_uarch_event` gained the accesses (`access_count`, `access_lo/hi`,
`access_write`, `AXIS_UARCH_MAX_ACCESSES`); `axis_sim_pack` gained
`memory_violations` at its end, then `btb_misses`, then `register_predictor`
and `core_predictor`; `axis_sim_core` the front end's six fields (O6–O7) and
`predictor_name` / `predictor_params` (O8), with the `axis_sim_param` and
`axis_sim_predictor` types and the header-only `axis_sim_param_of`; then `ras`
on the core and `target_mispredicts` on the pack (O9); then `unit_ports` and
`port_count` on the core (O10); then `icache` and `wrong_path_fetch` on the
core and `icache_misses` / `wrong_path_lines` on the pack (O11); then
`wrong_path_execute` on the core and `wrong_path_instructions` on the pack
(O12); then `execute_driven` on the core and `replays` / `squashed` on the pack
(E1); then `history`, `set_history` and `speculate` on `axis_sim_predictor`,
read only at `abi_version >= 2` (E2); then `traps` on the pack — the pack ABI
is v3 (E3); then `run_cores` and `snoops` on the pack — v4 (MC1); then
`cycle_cores` and `memsys_handle` on the pack and `memory_timed` on the core —
v5 (U3, `docs/unified_engine_design.md`). All are in `axis_pack.h`, so all are layout
changes to the shared contract. D1–D2 and W1–W3 change nothing in it: no
field, no counter, no clause. W4–W6 and D3–D4 add two clauses -- a unit's
`(abort ...)` and a branch's `(overrides ...)` -- and neither is in it: each
is a table beside the core's, private to the library, as a unit's lanes are. Neither do E4 or the first vector stages of
`docs/vector_units_design.md` (VM1–VM2, VU1), which size the window's own
lists from the description. **VM3 does — v6**: `axis_pack_sim_event` gained
`reads_total`, `writes_total` and `accesses_total` at its end, its three
counts are now how many entries the arrays hold, and `AXIS_PACK_MAX_TOUCH` is
64. **VU4 — v8**: `share_unit` on the pack, after the
context entries that are v7. **TLB1 — v9** (`docs/tlb_design.md`): `tlb` at
the end of `axis_sim_core`, with the `axis_sim_tlb` type, and `dtlb_misses`,
`itlb_misses` and `page_walks` at the end of the pack, then
`register_prefetcher` with the `axis_sim_prefetcher` type (PF1). **U1, U2 —
v10** (`docs/micro_ops_design.md`): `micro_ops`, `op_cache_ops` and
`loop_buffer_ops` at the end of the pack. The clauses themselves -- a core's
`micro-ops`, a front end's `op-cache` and `loop-buffer` -- are tables beside
the core's and move nothing. **S4 — v11**
(`docs/scheduler_design.md`): `value_predictions` and `value_mispredicts` at
the end of the pack; S1–S3 are tables beside the core's.
