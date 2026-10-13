# SIMT cores — warps of lanes, timed and executed (S1)

Status: **S1 built.** `(kind simt)` was a legal core kind with nothing behind
it ("the structural families -- in order, out of order, barrel-threaded, SIMT
-- are the next axis", `arch_packs.md`). A core of that kind may now declare a
warp machine, and `emit-pack-simt-c` generates its engine.

## 1. The form

```lisp
(defcore simt_l16
  (kind simt) (implements aarch64_base) (issue-width 1)
  (units (alu (count 1) (lanes 16)) ...)              ; optional; see §3
  (simt (warps 8) (lanes 16) (scheduler gto) (stack 16) (line 64)
    (isas a64_simt aarch64_base)                      ; decode order
    (untracked fpsr)                                  ; state not scoreboarded
    (cache (bytes 65536) (ways 4) (hit 4) (miss 150) (fill 10) (mshrs 16))
    (warp-control (tmc SIMT_TMC) (wspawn SIMT_WSPAWN)
                  (split SIMT_SPLIT SIMT_SPLITN SIMT_SPLITC) (join SIMT_JOIN)
                  (pred SIMT_PRED SIMT_PREDN SIMT_PREDC) (bar SIMT_BAR) (wsync SIMT_WSYNC))
    (sysread SIMT_ID (dst rt) (index (crm 8) (op2 1)))))
```

`lanes` is the knob: the same description at 4, 16 and 32 lanes is three
machines.

## 2. Two halves of every SIMT instruction

An ISA cannot describe a warp, and a core should not re-describe a predicate.
So a SIMT instruction is split where the two meet:

* **Per lane: the instruction's `behavior`**, executed by the generated
  executor like any other instruction. It writes state the ISA declares:
  `simt_pred` (the lane's predicate), `simt_arg` / `simt_arg2` (its operands),
  and for a SPLIT `rd <- simt_token`, which the machine presets to the
  reconvergence depth. An A64 SPLIT.cond's predicate is
  `(a64_cond_holds i4 nzcv cond)`, written in AXIS rather than in the engine.
* **Per warp: the role the core binds the mnemonic to.**

| role | reads, from the lanes | the warp |
|---|---|---|
| `tmc` | `simt_arg` | mask <- the last active lane's value; 0 ends the warp |
| `wspawn` | `simt_arg`, `simt_arg2` | warps 1..count-1 start at pc, lane 0 |
| `split` | `simt_pred`, `simt_token` | both groups non-empty: push (mask, next pc), run the smaller |
| `join` | `simt_arg` (token) | token below depth: run the other group at the SPLIT's next pc, or pop |
| `pred` | `simt_pred`, `simt_arg` | mask <- predicated lanes, or `simt_arg` if none |
| `bar` | `simt_arg`, `simt_arg2` | wait until `simt_arg2` warps reach barrier `simt_arg` |
| `wsync` | -- | wait until everything the warp issued has completed |
| `sysread` | -- | the host's `sysreg(warp, lane, index)` -> `dst` |

The semantics follow Vortex's warp-control unit, and agree with SimX's on what
both can run: pathfinder (64 columns, 4 warps x 4 lanes) executes 3,024 splits
(126 divergent) and 3,150 joins on both.

The validator refuses a role bound to no instruction, an instruction with no
behavior where the role reads one, a role reading state no ISA declares, and
everything the engine does not model (`engine`, `window`, `lsq`, `rename`,
`front-end`, `ports`): declaring one would be a number that changes nothing.

## 3. Timing

Every cycle, up to `issue-width` warps are chosen (`gto`: the last warp while
it can issue, then the oldest; `rr`: round robin) among those whose next
instruction has its operands ready (a per-warp scoreboard over register slots
and tracked state) and a free unit. The chosen instruction **executes then**,
in every active lane, and is charged:

* a unit of its class for ceil(warp lanes / unit lanes) cycles (every lane,
  active or not);
* its declared latency, plus, for memory, its coalesced lines: lane addresses
  in one `line` are one request, each line one cycle into the cache, a miss
  waiting for a miss slot (`mshrs`) and for memory (`fill` cycles per line);
* after control flow (a branch, a SIMT role) the warp waits for the outcome
  plus the core's branch penalty: no prediction.

**Unit classes are derived** when an instruction names none: memory -> `lsu`,
an operand outside the general register file -> `fpu`, a bound SIMT or
sysread instruction -> `sfu`, else `alu`. A class the core does not declare is
one pipelined full-width unit.

### 3b. Calibration knobs

Each forced by a microbenchmark that SimX, Vortex's cycle model, measured
and the engine could not express (a64-simt `notes/m6-engine-fidelity.md`):

* `(issue-interval N)`: the fewest cycles between two instructions of one
  warp (Vortex holds a warp at fetch until its instruction decodes: 9).
* `(pipeline N)`: cycles between issue and a readable result, beyond the
  latency.
* `(latency (class N)...)` and `(mnemonic-latency (PREFIX N)...)`: a machine
  that times by class, or by operation within a class (the longest prefix
  wins).
* `(inflight N)` on a unit: at most N operations in flight, each for its
  latency. ⚠️ A cap, not an interval: an initiation interval of 7 has the
  same throughput as 2 in flight for 14 cycles, and measured 10.47 cycles an
  op where the cap and SimX both measure 6.99.
  The operation **queues at the unit** for the slot that frees first; it does
  not hold its warp at issue. Holding has the same ideal throughput and locks
  into slower phases: a dependent FP chain on 4 warps measured 7.0 or 8.3
  cycles an op by alignment, where SimX, which queues, is 7.0 at every one.
* `(banks N)` on the cache: lines in different banks enter together.

Calibrated on 11 microbenchmark sequences (within 0.05 cycles an op) and
validated on eight held-out kernels, the engine's core matches SimX with a
median error of 1.5% over 27 runs, worst 6.9%. The one kernel that stood
apart (+22%) was Vortex's own stack interleave, which the core now declares
(§3a).

### 3a. Interleaved per-thread memory

`(interleave (top T) (bytes S) (granule G))`: the region `[T - threads*S, T)`
holds one `S`-byte slot per thread (threads = warps x lanes), and slot `k`'s
granule `j` is placed at `j*threads*G + k*G` from the region's base. It is a
permutation, so timing only: lanes address memory exactly as the program
does, and only the lines the cache sees change. That is what a GPU does to
local memory. Without it, one stack offset across a 16-lane warp is 16 lines
that cannot coalesce, `S` apart, crowding a few cache sets. Measured on the
A64 study's kernels: a call-heavy kernel 7.7-17.5x slower at 16 lanes, sgemm
1.8-4.4x, and the stack-free kernels identical to the cycle (the control).

`(group N)` interleaves within each group of N consecutive slots (a warp's
lanes) instead of across all threads, and `(xor true)` also XORs each
group's granule index with the group number, so equal offsets of different
groups land in different cache sets. Together they are Vortex's
`StackInterleave` (`sim/simx/stack_interleave.h`, `VX_lsu_agu.sv`), address
for address. `xor` needs a `group` and a power-of-two count of granules per
slot, or the XOR carries a granule out of its group and the map stops being
a permutation.

### 3c. Vector mode: one thread across the lanes

```lisp
(vector (isa a64_sve_lane)                       ; its instructions are per-lane halves
        (lane-classes a64_vreg64 a64_vreg128)    ; registers a lane holds a slice of
        (lane-state sve_p sve_ph)                ; state a lane holds a slice of
        (broadcast SVE_DUP_ZS0))                 ; vector instructions reading lane 0
```

A warp the host puts in vector mode (`axis_simt_set_vector`) is **one
thread**, not `lanes` of them. Lane 0 holds its scalar registers and state;
lane `e` holds slice `e` of every register of the lane classes. Then:

* an instruction of any other ISA executes **once**, in lane 0, and a write
  it makes to a lane-class register clears that register in the other lanes
  (a scalar write to a vector register zeroes the rest of it);
* an instruction of the vector ISA executes **in every lane**, each given
  lane 0's values for its non-lane sources and non-lane state, and its own
  slice of everything else -- or lane 0's slice too, if it is a `broadcast`.

So a vector instruction is written exactly as a SIMT instruction is: what one
lane does. The machine presets `simt_lane` (the lane's index) and
`simt_lanes` before each lane runs, where an ISA declares them, which is all
a contiguous load needs to find its slice. Timing is the warp's, unchanged:
one issue, the units and the coalescing cache of §3. A vector load over
consecutive slices coalesces into the lines it spans.

⚠️ **Refused, not approximated:** in vector mode, an instruction outside the
vector ISA naming a register wider than a slice (a 128-bit NEON form), and
warp control other than `tmc`.

One kind of result needs every lane, and is the machine's: `(flags STATE
MNEMONIC...)` names the vector instructions that are a **predicate test**.
Each lane leaves its active elements in `simt_arg` and whether its last
element is active in `simt_arg2`; the machine writes the thread's flags to
`STATE`: first active (bit 3), none active (bit 2), last not active (bit 1).
That is SVE's `whilelo`, and what makes a tail-folded loop runnable.

Two more things no lane can do alone:

* `(sum MNEMONIC...)`: a **reduction**. Each lane leaves its part in
  `simt_arg`; the machine writes the sum, modulo 2^64, to the instruction's
  lane-class destination in lane 0 and clears it in the others. SVE's `uaddv`.
* `(crosslane MNEMONIC...)`: a **permute**, which reads other lanes' slices.
  While one executes, the machine presents the lanes as memory at
  `0xffff000000000000`: region `r` is at `+ (r << 16)`, 8 bytes a lane, lane
  0 first. Regions 0..7 are the instruction's lane-class sources in operand
  order (each a whole register, as it was before the instruction); regions
  8.. are the core's lane-state slots in the order the ISA declares them.
  The behavior `load`s what it needs. Those loads are not memory accesses:
  they touch no cache, and the instruction's unit is derived as if it had
  none. SVE's `uzp1` on predicates is written this way.

**Not built:** a floating-point reduction (its order matters), and a
vector-mode case in `tools/simt_check.py`. The mechanism is gated through its
one user: the A64 study holds its 41 SVE instructions, one at a time at four
lane widths, to a model of SVE on whole registers
(a64-simt `isa/tools/sve_lane_check.py`). That gate found a bug here: a
broadcast left lane 0's slice in every lane's copy of the source register.

### 3d. Implicit divergence: no SPLIT, no JOIN

```lisp
(implicit (policy minpc))
(implicit (policy minsp-pc) (sp sp 8192))                 ; state slot, per-thread stack bytes
(implicit (policy maxdepth-pc) (calls BL BLR) (returns RET))
```

A core that declares it runs a binary with no divergence instructions at
all. When a warp's lanes disagree on the next pc, the warp **splits into
paths**, one per distinct pc. One path runs at a time; the others are parked
with their masks. After every instruction, a parked path at the running
path's pc **merges** into it, and the policy picks which path runs next:

* `minpc`: the lowest pc.
* `minsp-pc`: the deepest stack first, then the lowest pc -- SIMT-X's and
  DITVA's heuristic. Depth is the stack pointer's distance below a multiple
  of the per-thread stack size, since each thread has its own stack.
* `maxdepth-pc`: the deepest **call** first, counted per lane from the
  instructions named `calls` and `returns`, then the lowest pc. For an ISA
  whose calls do not move the stack pointer: an AArch64 leaf call is `BL`
  and `RET` through x30, so `minsp-pc` cannot see it.

`(yield MNEMONIC...)` names **reconvergence hints**: instructions that mark
where threads meet and do nothing else. A path whose next instruction is one
runs after every path that is not at one; among paths at hints, the policy
decides, so some path always runs.

Where threads reconverge is a guess here; a compiler's JOIN is not. A path
that runs past the others' meeting point runs its remaining instructions
alone, and nothing is wrong except the cycles.

Charged: a switch to another path is a fresh fetch (the branch penalty), and
the split itself is the divergent branch, which the warp already waits out.
⚠️ **Not charged or limited:** the path table's size (a warp may hold as many
paths as lanes), the comparison that finds a merge, and dependences are
still scoreboarded per warp, so one path waits on a register another wrote.

While paths are parked, a `TMC` speaks for the running path's threads only:
it can stop them (`mask <- arg and the path's mask`; an empty path retires),
never wake a lane that is parked somewhere else. With no path parked it is
Vortex's: `mask <- arg`, and a lane it wakes inherits the waker's call depth,
since it continues from the same pc. (Found by an OpenMP fork: the master
joins the team from several calls deep, the lanes it wakes from none, and
`maxdepth-pc` ran the master to the join alone.) A `PRED` that empties the
mask retires the running path's threads. A warp in vector mode does not
diverge.

### 3f. The exclusive monitor across threads

```lisp
(exclusive exclusive_address exclusive_size exclusive_valid)
```

names the monitor's state slots. Then every memory write clears each OTHER
lane's reservation that overlaps it, on every warp. ⚠️ Without it, a
load-exclusive / store-exclusive pair executed by a warp's lanes loses
updates: an ISA's monitor is one thread's, every lane reads the old value,
and every lane's store succeeds. Lanes execute an instruction in lane order,
so with the rule lane 0's store takes the others' reservations, they fail
and retry, and the retries diverge: an atomic update costs a warp a round a
lane. Not gated in `simt_check.py` (the test ISA has no exclusive pair); held
by the A64 study's OpenMP reduction and atomic counters, which fail without
it (a64-simt `notes/m11-openmp.md`).

Gated: `tools/simt_check.py` generates its programs without SPLIT, JOIN or
PRED for the `si_*` cores of `examples/simt_core.axisl`, and holds every
thread to what it computes alone. The test ISA has no call, so only `minpc`
is gated there; the others are held by the A64 study's kernels
(a64-simt `notes/m8-implicit.md`).

### 3e. Out of order: a window a warp

```lisp
(ooo (rob 128) (predictor none | bimodal | perfect) (entries 4096)
     (merge true | false) (memory-order true | false) (divergence-predictor true | false))
```

A core that declares it **dispatches** in order and **starts** out of order.
The lanes execute an instruction when it is dispatched, as before, so the
program's order is the dispatch order. But it is charged -- its lines through
the cache, its unit -- only when it starts: when every instruction that
produced one of its sources is done and a copy of its unit is free, oldest
first within a warp. It retires in order, and a warp with `rob` instructions
not yet retired cannot dispatch. With `issue-width` above 1 a warp may
dispatch several in a cycle.

Resources are taken in the order instructions start, cycle by cycle. A
version that charged at dispatch, with a start time in the future, reserved
memory in dispatch order; a dependent load then held the bus against every
younger independent one, and a streaming kernel ran 4x slower out of order
than in order.

* **The front end** runs on past a branch with `(predictor perfect)`, waits
  for every branch's outcome with `none`, and with `bimodal` waits for the
  ones `entries` two-bit counters, indexed by pc, get wrong. It always waits for a
  divergence (lanes disagreeing on the next pc) and for a warp-control
  instruction: neither is predicted.
* **A write under a partial mask** -- the warp is split, by SPLIT or
  implicitly -- merges into the register's old value, which the lanes it
  does not cover keep. So it waits for the previous writer as well as its
  sources. `(merge false)` drops that wait: the bound a renamer would reach
  if merging cost nothing.

* **A divergence predictor** (`divergence-predictor true`): `entries`
  two-bit counters by pc saying whether a branch will split the warp. A
  split it foresaw costs the front end nothing, since both paths' pcs are
  known; a split it missed, or one it called that did not happen, is waited
  out like an unpredicted branch. SIMT-X has one; this is the simplest.
* **Memory as an ordering** (`memory-order true`): a load waits for the
  youngest older store in its warp's window to any 8 bytes it reads, and
  takes the value when that store is done. Without it a value carried
  through memory costs nothing: 28 cycles against 83 for eight round trips.
  The last store to each 8 bytes is kept in a direct-mapped table of 4,096;
  a collision forgets the older store, so the model errs fast, rarely.

⚠️ **Not modelled:** a wrong path (execution is at dispatch, so nothing is
ever squashed), physical registers, load and store queues with a capacity,
memory order between warps, commit width, and predictors with history. AXIS's own out-of-order engine models all of
these for one thread (`docs/ooo_design.md`); this is the window alone, on a
warp.

Gated in `tools/simt_check.py`: the judge on `so_*` cores, explicit and
implicit; **WINDOW** (a miss, its dependent, and 20 independent adds: 44
cycles in order, 24 with a 32-entry window, 43 with a 4-entry one); **CHAIN**
(16 dependent multiplies cost the same in order and out); **MEMORY** (the
round trips above, and exactly 8 loads waiting); **PREDICT** (a 32-trip
loop: 32 misses with no predictor, 3 with two-bit counters, 0 with a
perfect one, and cycles in that order); **DIVPRED** (a loop that splits its
warp every trip: the same 16 splits, fewer cycles with the predictor).

### 3g. A second level, prefetchers, and lines in flight

```lisp
(cache (bytes 65536) (ways 4) (hit 4) (miss 150) (fill 10) (mshrs 16)
       (track-fills 1)                                   ; a line on its way is not there yet
       (l2-bytes 2097152) (l2-ways 8) (l2-hit 28)        ; a second level
       (prefetch-degree 4) (prefetch-entries 256)        ; stride, by (warp, pc)
       (prefetch-next-line 1))                           ; or: next lines on every miss
```

* **`track-fills`.** A line is allocated when it is requested. Without
  this, a second access to it while the miss is outstanding hits at once --
  the model every result before it used, optimistic wherever two warps touch
  a line within a miss of each other, and fatal to a prefetcher, all of whose
  lines are in flight. With it, an access waits for the line's arrival
  (`fill_waits` counts it). Off unless declared, so no earlier description
  changes.
* **L2.** An L1 miss looks in the L2: a hit costs `l2-hit` cycles (with a
  miss slot, and no memory bandwidth); a miss costs `miss`, as before, and
  allocates in both levels. Inclusive in effect, never invalidated.
* **Prefetch, stride.** A table of `prefetch-entries`, keyed by warp and pc:
  once a load's first line has moved by the same stride twice running, the
  lines its next `prefetch-degree` requests will touch are fetched into L1,
  taking miss slots and memory bandwidth. Counted as `prefetches` and, when
  a demand access first uses one, `prefetch_useful`.
* **Prefetch, next-line.** Every demand miss fetches the next
  `prefetch-degree` lines. ⚠️ The stride table never trains on a GPU-style
  kernel: warps take thread blocks in the order they finish, so one warp's
  loads from one instruction jump by varying amounts (0 prefetches on
  vecadd at 16 lanes). Next-line needs no training.

* **Prefetch, best-offset** (`prefetch-best-offset 1`): Michaud's
  prefetcher (HPCA 2016). One global offset D. A table of
  `prefetch-entries` recently filled lines records, for each fill, the line
  whose access would have asked for it, and when it arrived. At every demand
  miss and first use of a prefetched line X, one candidate offset d (1 to 64,
  prime factors at most 5) is tested: it scores if X - d is in the table and
  had arrived by now -- so an offset scores only if prefetching with it
  would have been in time. A phase ends at 100 rounds or a score of 31, and
  the best offset becomes D (or prefetching stops, if it scored 1 or less;
  demand fills are then recorded so a later phase can restart it). Each
  trigger fetches `prefetch-degree` lines from X + D. It starts at D = 1.
  Global by construction: it learns from addresses, not from a stream's
  sequence, so warps taking thread blocks in any order do not confuse it.

Gated: **PREFETCH** and **NEXTLINE** (a 128-line stream: 128 misses without,
3 and 26 with), **PREFETCH4** (four warps' interleaved streams: the stride
table keeps an entry per warp), **BESTOFF** (a 1,024-line stream: a phase
finishes and picks an offset of at least 2, misses 1,024 to 2; four warps:
512 to 4), **L2** (the stream twice through a 4 KiB L1: 128 L2 hits on the
second pass, fewer cycles).

⚠️ **Not modelled:** the instruction cache and fetch bandwidth, bank
conflicts, write-back traffic, a second cache level.

## 4. The host

`axis_simt.h`: memory, fetch, `sysreg` and `warp_done` hooks;
`axis_simt_start_warp` (a host's dispatcher starts and restarts warps: CTAs);
`axis_simt_run`; counters. The engine checks at creation that the exec pack
lists its state in the order the timing rows were written for.

## 5. What holds it: `simt_check.py` (S2)

On `examples/simt_core.axisl` -- `st32`, a small ISA with the warp operations,
and SIMT cores of four shapes (1x1, 1x8, 1x8 on a 2-lane ALU, 4x8):

* **the judge**: 40 random structured programs per core -- nested divergent
  if/else regions bracketed by SPLIT/JOIN, loops whose trip count is each
  thread's own narrowed by PRED at the latch, loads and stores into the
  thread's own memory -- leave every thread's registers and memory exactly as
  that thread run ALONE through the executor leaves them (the warp operations
  doing only their per-lane halves). Excluded: token registers and the saved
  mask, which differ by construction.
* **the invariants**, exact: UNIFORM (24 independent ops: 1 lane and 8 lanes
  cost the same), NARROW (8 lanes on a 2-lane ALU: +3 cycles an op), DIVERGE
  (one lane on ELSE: +B+3 warp instructions), ORDER (the smaller group runs
  first: a deliberate race's last writer), COALESCE (8 lanes, consecutive
  words: 1 line a load; 64 bytes apart: 8).

10/10 mutations: a JOIN that never pops, a PRED that ignores its fallback, a
JOIN that resumes the other group with the whole mask or at the JOIN instead
of the SPLIT, a token never preset, a SPLIT that pushes nothing, a TMC that
keeps the warp running (all the judge); occupancy that ignores unit lanes
(NARROW); coalescing per lane (COALESCE); and the larger group first, which
survived until ORDER was added -- race-free programs cannot see the order.

Two defects the gate found on its way in, both in descriptions rather than in
the engine, and both worth knowing:

* **A comparison takes its destination's width.** `(setstate simt_pred
  (icmp_ne rs1 0) i1)` compares bit 0 of `rs1`: the `i1` flows into the
  operands. The engine refused to go on -- the lanes it grouped by that
  predicate then disagreed on the branch testing the full register -- which
  is the check that found it. `(icmp_ne i32 rs1 0)` says what was meant.
* **The derived unit classes first took `file != "reg"` for "not an integer
  register",** which sends every RISC-V integer instruction (`rv_gpr`) to the
  FPU. NARROW measured +0 cycles on an ALU nothing reached.

Also held by the A64 study (a64-simt `simt/`): eight Vortex kernels pass their
hosts' checks at 4, 16 and 32 lanes, and split counts agree with SimX's.
