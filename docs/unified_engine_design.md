# One engine: SIMT cores on the pack simulator's machinery (U1–U4)

Status: **U1, U2 and U3 built.** U3 is coordinated with the session that
owns the pack pipeline, and lands on main.

## 1. Why

AXIS has two cycle-level engines that do not share a line of code:

- **The pack simulator** (`emit-pack-sim-c`; `arch_packs.md` §7d,
  `ooo_design.md`, `memory_system_design.md`). It is an execution-driven
  out-of-order pipeline: a load/store queue, renaming, TAGE and other
  predictors, a return stack, ports, an instruction cache and an executed
  wrong path. It runs several cores against one memory, and AArch64 runs on
  it. Its memory system is described (`defmemsys`): levels, policies,
  inclusion, MOESI, DRAM.
- **The SIMT engine** (`emit-pack-simt-c`, `simt_design.md`). It has warps,
  lanes, paths, SMT path issue, events and per-lane faults. It also carries a
  private window, a bimodal predictor, an L1 and L2, MSHR slots, a DRAM bus,
  lines in flight, and stride and best-offset prefetchers. Each of those is a
  simplified second copy of something the pack simulator has, or a timing
  mechanism the memory system lacks.

Two costs follow. A SIMT core cannot be compared with a CPU core on equal
terms: the A64-SIMT study compares against Neoverse V2 in gem5, with memory
parity matched by hand (study M14). And every memory-system feature is
written twice, or once in the wrong engine.

## 2. The stages

- **U1 — the memory system keeps time.** `memsys_engine.c` becomes able to
  answer *when* an access completes, not only what it costs:
  - per-cache MSHRs, as declared by `(mshrs N)`, which was parsed and never
    read;
  - lines in flight: installed at the miss with a ready time, so a later
    access waits for the fill;
  - DRAM banks busy for their row operation, and a channel bus busy for
    each line's burst;
  - `(prefetch stride)`, which validation accepted and the engine ignored,
    and `best-offset` (Michaud), moved here from the SIMT engine.

  The untimed entry points are unchanged, and their gates hold them to the
  same model. The timed entry point gets its own gate, against a timed
  reading in `tools/memsys_model.py`.
- **U2 — SIMT cores on the memory system.** A SIMT core may name a
  `defmemsys` port instead of its private `(cache ...)`. Its coalesced
  requests then go through the timed entry point. The private cache stays for
  existing descriptions and for the SIMT gate. Gate: the study's M15
  configuration, described as a `defmemsys`, reproduces within a stated
  tolerance, and every difference is accounted for.
- **U3 — one run loop, one memory.** CPU and SIMT cores of one system run
  together, sharing one coherent memory system: a heterogeneous machine, and
  the like-for-like comparison.
- **U4 — warps as hardware contexts of the pack pipeline.** A warp becomes
  a context of the execution-driven core, with a lane mask. The window, LSQ,
  predictors and instruction cache become the pack simulator's, and
  `simt_engine.c` is retired.

## 3. U1's contract (timed accesses)

`axis_ms_access_at(ms, port, addr, is_write, now, key)` returns the cycle at
which the access's data is available. Writes return when the port has the
line, as in the untimed model, where a write's cost is its read path. It
charges everything `axis_ms_access` does, at the same points, and then
waits:

- **A line in flight.** A hit on a line whose fill has not arrived completes
  when it arrives, not after the hit latency.
- **MSHRs.** A miss at a cache with N MSHRs takes the slot that frees first,
  and waits for it if every slot is busy. The slot is held until the line
  arrives. A cache with `(mshrs 0)` is unbounded.
- **A DRAM bank** serves one row operation at a time.
- **A DRAM channel** carries one line at a time. A line occupies it for
  `line-bytes / (2 x bus-bytes)` DRAM clocks, double data rate, with
  `bus-bytes` 8 unless declared.
- **Prefetches** are timed fetches: they take MSHRs, banks and the bus like
  demands. Next-line and stride install at the level of the miss that
  triggered them. Best-offset learns at a level from the arrival times of
  that level's fills.

Not modelled, as before: fabric contention, write-back traffic (still
posted, still free), and transient coherence states. Coherent regions are
charged as in the untimed model, with no waits added.

## 4. U1 as built

- **Engine.** `axis_ms_access_at(ms, port, addr, is_write, now, key, first)`
  in `memsys_engine.c`, with the contract's TIMED ACCESSES section at its
  head. Untimed entry points are unchanged; `memsys_sim_check.py` and
  `memsys_pack_check.py` pass as before.
- **Description.**
  - `(prefetch ...)` takes a list (`stride best-offset`) and gains
    `best-offset`; a name may appear once.
  - A DRAM may declare `(bus-bytes N)`, and the manifest carries it.
  - `(mshrs N)` and `(prefetch stride)` were accepted before and did
    nothing; timed accesses now read both.
- **Gate.** `tools/memsys_timed_check.py` holds the engine to
  `tools/memsys_timed_model.py` over seven configurations, cycle by cycle
  and counter by counter (155,568 accesses). An uncontended access must
  equal the untimed cost. Every mechanism must be reached. Five mutants are
  caught: the bus at an access's start, no fill wait, an MSHR freed at the
  miss, a prefetch that waits, and best-offset blind to timeliness.
- **Found while building it.** A posted write-back took bank and bus time
  in the engine's first draft. The contract says write-back traffic is free,
  and the model followed the contract, so the gate disagreed on every trace
  with writes.

## 5. U2 as built

- **A SIMT core that a `defmemsys` node names is a port of that system.** It
  has no private cache: validation refuses one beside the port, and a line
  size different from the system's. Each coalesced line of an instruction
  goes through `axis_ms_access_at`, at the cycle its L1 bank takes it. Its
  key is (warp, pc), and the request's first line trains a stride
  prefetcher. The core's hit, miss, L2, prefetch and fill-wait counters are
  then the port's, and the level below it.
- **SIMT gate MEMSYS.** A port core and its private-cache twin of the same
  shape agree to the cycle on a stream run twice (6,670 cycles, 256
  misses). Ignoring the port makes them disagree.

### Two corrections U2 forced on U1

Running the A64-SIMT study's M15 configuration as a memory system (study
`isa/a64_simt_cores.axisl`, `u2_lb2`) did not reproduce the private model
at first. On fused vecadd it was 26% slower. Two engine semantics were the
cause, and two hypotheses were wrong along the way: MSHRs alone, and DRAM
banks.

- **A store is a use.** A store that hit went straight to marking its line
  dirty. It never counted a prefetched line as used, triggered best-offset,
  or trained a stride. vecadd's output stream is all stores, so best-offset
  trained on two of its three streams. The contract always said "the first
  use of a prefetched line"; the engine and model now agree with it, and a
  store stream and a mutant hold it.
- **Prefetches dropped, where the private model let them queue.** With
  every MSHR busy, a prefetch was dropped (1,330 on fused vecadd at 16
  MSHRs), while the SIMT engine's private cache had let it wait, an
  unbounded queue in effect. With 256 MSHRs the two agree: 57 misses against
  59, exactly 3,088 useful prefetches, and cycles within 1.5%. Neither
  extreme is a hardware fact, so `(prefetch-queue N)` makes it a declared
  parameter: up to N prefetches wait for an MSHR, the rest are dropped, and
  0 keeps dropping. This moves fused vecadd by 20%, and the study's
  comparisons with Neoverse V2 rest on this prefetcher, so a description
  has to state N.

### A third correction: an unmapped address is free

The study's comparison then showed the memory system 7–13% *faster* on
five of 26 runs. Two hypotheses about DRAM queueing failed. Logging every
line access from both models answered it at the first access: a stack line
cost 150 cycles privately and 0 in the memory system. The SIMT engine places
interleaved stacks near the top of a 48-bit space, the description's address
map ended at 1 TiB, and the memory system charges an unmapped address
nothing, silently. A SIMT port now refuses an access outside its system's
map (SIMT gate MEMSYS; ignoring the refusal makes the gate fail). A flush
replaces the system but carries its counters over, as a private cache's do,
so a program of several launches reports all of them.

## 6. U3 as built

- **Timed memory on a CPU core.** `(memory-timing timed)` is for an
  execution-driven port of a `defmemsys`; it is refused on a trace-driven
  core and on one no system names. Its loads ask `axis_ms_stall_at` at the
  cycle they execute, keyed by pc for a stride prefetcher. The stall is what
  arrives past a first-level hit. Stores ask at commit, uncharged, as
  before. A squashed load has already touched memory: its MSHR and fill are
  real, and only its counters wait for commit. Untimed stays the default,
  and every pipeline gate keeps its numbers (xmode, xspec, xcomplete, mcx,
  a64x, wrongpath, occupancy, redirect, memsys_pack).
- **One clock.** `cycle_cores(machines, count, cycles)` steps
  execution-driven machines in lockstep for a bounded number of cycles and
  leaves them where they stand. `memsys_handle(machine)` hands out a
  machine's memory system, and `axis_simt_share_memsys` adopts it at the
  SIMT core's own port. A layout fingerprint refuses an instance built by
  another version of the engine, and a shared system is never replaced by a
  flush. Pack ABI v5 (`ooo_design.md` §28).
- **Gates.**
  - `memsys_x_check.py`. A 300-load chase costs 26,016 cycles timed and
    untimed. 300 independent misses take 7,378 cycles timed with four MSHRs,
    25,117 with one, and 3,733 untimed with either: the untimed path let
    every miss overlap for free. Both refusals fire.
  - `unified_run_check.py`. A timed CPU core and a SIMT core each have an L1
    over one L2 and DRAM. The CPU's 400 loads take 6,527 cycles alone and
    7,019 beside a SIMT stream; the shared L2's misses rise from 401 to 633;
    the CPU's sum is right both ways. With sharing made a no-op, the gate
    fails.

What remains is **U4**: warps as contexts of the pack pipeline, so the SIMT
engine's own window and front end go and the pack's TAGE, LSQ, instruction
cache and wrong path serve warps too.

## 7. U4: warps as contexts of the pack pipeline

Agreed with the session that owns the pipeline: no single reorder buffer
threaded with context ids. Every program-order loop (execute's overlay,
memory readiness, squash, resolve) stays per machine. A **context is a
whole machine**, and contexts of one core point at a group that holds what
a core has one of.

**U4a — hardware contexts (built).** `share_core(machine, other)`, pack ABI
v6.
- The group holds the unit copies, and this cycle's issue, dispatch and
  commit counts and port mask.
- Each context gets an even share of the window and issue queue (static
  partitioning) and keeps its own front end, rename map and golden model.
- `cycle_cores` rotates which context goes first each cycle.
- Not yet shared: the instruction cache, the predictor tables and the BTB
  are still per context, so a real SMT core's interference in those is not
  modelled.

Gate `contexts_check.py`, on a 2-wide core:
- independent adds take 812 cycles alone and 1,612 for two contexts;
- dependent chains take 1,210 alone and 1,612 for two, so they overlap;
- both reach the core's bound (1,600) within 1%;
- on a 4-wide core with one ALU, 1,413 alone and 2,811 for two;
- each context's registers are its program's.

It catches two mutants, units not shared and widths not shared. A mutant
that stops sharing only the issue width is not caught, and cannot be: the
shared dispatch and commit widths bound throughput by themselves.

**U4b — a warp is contexts sharing a front end (built).** Implicit SIMT, as the
A64-SIMT proposal settled on, needs no SIMT instruction: a warp's threads
are contexts, and what makes them a warp is that they share a front end.
- Each cycle a warp fetches ONE pc, for every member whose next pc it is,
  chosen lowest first. A member passed over too long goes first, the
  forward-progress rule the study found necessary (M17).
- Instructions fetched together carry a fusion tag (warp, fetch cycle, pc).
- The first member to dispatch, issue or commit a tagged instruction in a
  cycle pays the slot, the port and the unit; the others doing the same in
  that cycle ride free. One warp instruction serves every lane.
- Members whose operands are not ready together issue apart and pay apart:
  divergence in the back end costs what it should.
- Members at different pcs are fetched in different cycles: divergence in
  the front end.
- Registers stay per thread, renamed per thread, as the study found
  necessary (M18), and each thread has its own golden model, so a fused
  warp's results are checked thread by thread.

As built, pack ABI v7:
- `set_warp(machine, warp, age)` puts `machine`, a context of a shared
  core, into warp `warp` of that core; `age` is how many cycles a member
  may be passed over before it fetches first, one value per core. A core
  may hold several warps, which share its units and widths as contexts do
  (the study's x2x4: two warps of four). Refused with age 0, an age other
  than the core's other warps', a warp number of 64 or more, on a machine
  sharing no core, or once any member has started. `warp_rides(machine, out, 3)` reports how many of its
  instructions rode free at dispatch, issue and commit.
- The pc is picked once a cycle, by the first member to reach fetch, among
  members that could fetch (running, not stalled, buffer not full). A full
  buffer is not passed over, so a member issue-bound behind its own window
  does not hold the others' fetch.
- The tag is the fetch cycle plus the pc, carried on the rob entry
  (`x_fetched_at`). The group keeps, per stage, the tags paid for this
  cycle; they reset with the cycle's counters.
- Issue scans past a full width only for a warp, looking for riders. A
  rider takes no port and no unit.
- Wrong-path instructions fuse like any others: the warp fetched them once.

Gate `warp_check.py`, on the 2-wide core of `contexts_check`:
- converged: one alone 812 cycles, a warp of four 812, four plain contexts
  3,212. Riders at dispatch, issue and commit are 4,824, 4,815 and 4,806,
  against 4,803 program instructions for the three non-paying members. The
  excess is wrong-path work and each member's final undecodable fetch,
  which also fuse;
- two warps of two on one core: 1,612 cycles against the two-stream bound
  of 1,600, with 3,209 rides at issue for 3,202 instructions of the two
  non-paying members;
- diverged (two members running the same loop at two pcs): 1,609 cycles
  against a bound of 1,600, and nothing rides;
- aging, on a core fetching one instruction a cycle: with an age never
  reached, the lower member runs as if alone (1,610) and the higher one
  waits (3,218); with age 1 they alternate (3,206 and 3,211);
- every member's registers are its own program's, in every run.

It catches three engine mutants: no fusion at issue, no aging, and the
highest pc picked instead of the lowest. It does not catch a tag matched on
pc alone, without the fetch cycle. In every program it runs, members at one
pc were fetched in one cycle: drifting apart in time while staying at the
same pcs needs latencies that differ per member, and its memory is flat.

Limitation: members at the picked pc each follow their own prediction
within the fetch group, so two members that predict differently both fetch
that cycle: the warp fetches two paths at once, which a real front end would
not.

**Lockstep (forced by U4c's first measurement).** U4b as first built let a
member issue a fused instruction whenever it alone was ready, and ride only
if another member issued it in the same cycle. Run on the study's OpenMP
vecadd (8 OS threads as two warps of four), it rode 1.34 thread
instructions per issue where the SIMT engine, on the same binary, issued 3.9
lanes per warp instruction: 5,857 cycles against 3,396. A load finishing a
cycle apart split two members, and nothing joined them again. A SIMT core
issues a warp instruction for all its lanes at once, so the pipeline now
does too:
- **Fetch:** a warp fetches its pc only when every member at it can take
  it. A member with a full buffer holds the warp, rather than the others
  fetching on alone with new tags.
- **Issue:** a member's copy waits until every other member's copy of the
  same fused instruction is ready, whether in that member's window or
  still in its fetch buffer (`axis_x_warp_waits`). Members tick one after
  another within a cycle, and the rule depends on that:
  - a member that has already ticked has issued what it will this cycle,
    so its unissued copy goes next cycle and the asker waits for it;
  - a member yet to tick rides after the asker if its copy is ready now, or
    is still in its buffer but can dispatch this cycle.

  Readiness is judged at the asker's cycle, since a member that has ticked
  is a cycle ahead on its own clock.

Gate `warp_check` LOCKSTEP: a member whose loads always hit and one whose
loads always miss (each its own cache) run as one warp in 8,363 cycles,
against 8,386 for the same two as plain contexts, and 1,207 of 1,201
instructions ride at issue. The comparison is with the two as contexts,
not with the slower member alone (5,488), because contexts split the window
and half the window holds half the misses.

On vecadd, two warps of four now take 3,927 cycles, 16% over the SIMT
engine's 3,396, with 3.18 thread instructions per issue against its 3.9.

**U4c — the study on it (in progress).** The study's OS-thread OpenMP
programs (M17) now run on the pack pipeline, with one OS thread per
context (`simt/host_pack.c` in the study). The same binary runs on the
SIMT engine. Running them forced three changes beyond lockstep:
- **An ordered ISA list.** `reset` may name several ISAs separated by
  spaces, and a word is in the first that decodes it
  (`axis_sim_word_isa`). The study's programs are `aarch64_base` with
  hint words (YIELD, WFE, SEV, the reconvergence HINT) from `a64_simt`. A
  NULL ISA, meaning all of them, is ambiguous there: the seed's
  accelerator ISA also matches BL, SEV and NOP, and an ambiguous word
  decodes to nothing.
- **`(exclusive address size valid)` on any core.** A store-exclusive
  succeeds on its own monitor, and no instruction clears another core's,
  so OpenMP dot's LDXR/STXR reduction lost an update on eight contexts. A
  core that names its monitor has it cleared, in the golden model, by any
  store another core commits over the bytes it covers. A store-exclusive
  the window already ran on the stale monitor then disagrees at commit and
  is replayed. Gate `monitor_check.py` (RV64, four cores, 100 LR/SC adds
  each): 400 with the clause, 100 without.
- **The host's wrong path.** An execution-driven core executes loads its
  predictor fetched, before the branch decides whether they happen, so a
  host that dereferences addresses (the study's drivers share buffers by
  address) must read an unmapped address as 0. The SIMT engine never
  speculates an address, so its host never needed to.

**Events: a wait sleeps (U4c).** `(events (wait W) (send S) (local L))` on
an execution-driven core gives each machine an event register, with Arm's
WFE/SEV/SEVL semantics:
- **A send that commits** sets every machine's register in the
  `cycle_cores` call and wakes any that are asleep.
- **A local send** sets the machine's own register.
- **A wait that commits** with the register set clears it and goes on. With
  it clear, the machine sleeps: everything it fetched after the wait is
  squashed, the drain a real core does, and it fetches nothing until a send.
- **Sleeping is not idleness:** a sleeping machine does not count toward the
  100,000-cycle "committed nothing" halt. When every running machine is
  asleep, the call halts them all, saying so.
- **Warps:** a sleeping warp member is out of its warp's fetch pick and
  lockstep check.
- **Counting:** `warp_rides` reports a fourth number, how many times the
  machine slept.

Gate `events_check.py`, on RV64 with a wait, a send and a local send
composed in as FENCE-format words: one producer works 300 trips, stores a
flag and sends, while three waiters poll the flag with a wait between polls.
- With the clause, each waiter commits 8 instructions and sleeps once.
  Without it, each polls through 632.
- A send before the waits is held by the register.
- A wait after a local send goes straight on.
- Waiters with nobody to send halt after 5 cycles, saying why.

It catches four mutants: a send that wakes nobody, a wait that ignores the
register, a wait that never sleeps, and no all-asleep end.

This is the pack pipeline's form of M17's WFE events. Fetch-priority relax
did not reproduce M17's results (study note M20), and sleeping removes the
spin instructions rather than reordering them.

Still to do for U4c: M17's OS-thread runtime maps directly, one OS
thread per context. The study's implicit cores, re-described as warps of
contexts, are validated against `simt_engine.c`. The SIMT engine's own
window, predictor and front end then retire.
