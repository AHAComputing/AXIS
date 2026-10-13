# The pack simulator: a cycle model generated from the description

This is the entry point for AXIS's microarchitecture simulator — the thing a
reader coming from gem5 is looking for. It says what the simulator is, how to
build and drive one, what a description can say about a machine, what is
counted, and what is not modelled. Each stage has its own design document with
the reasons and the gate that holds it; this page points at them and repeats
none of the argument.

## 1. What it is

`axis emit-pack-sim-c` turns one `.axisl` description into one C library,
`libaxis_sim_<name>`. The library is a machine for that architecture: it
decodes, executes and times programs on the cores the description declares.
Nothing in it is hand-written per ISA. The instruction semantics are the same
proven ones every other AXIS artifact is generated from, and the pipeline is
the same generated code for RV64, AArch64, SVE, SME or a toy.

What that buys, against a hand-built simulator:

* **A core is a form, not a C++ class.** `defcore` declares widths, a window,
  units, a front end, a predictor; `defmemory` and `defmemsys` declare caches
  and the system behind them. Changing a machine is editing a description.
* **The functional model judges the timing model.** On an execution-driven
  core the pipeline computes values itself, and the golden model checks each
  instruction at commit. A dependence the pipeline failed to honour is a
  counted *replay*, not a silently wrong number.
* **Every modelled effect has a gate that fails when it is removed.** The
  gates are mutation-tested: each names the mutants it catches.

What it is not: a full-system simulator. There is no operating system, no
device model, no interrupt controller, no checkpointing, and a host supplies
memory through hooks. See §7.

## 2. Building and driving one

```
tools/build_pack.py examples/issue_width.axisl --out build/packs
```

builds every library of the pack, the simulator among them, and a `pack.json`
naming each library's entry symbol. `axis emit-pack-sim-c corpus.axisl` writes
the simulator's C alone. The contract is `include/axis_pack.h`, identical for
every pack; `axis_sim_pack` is the function table and carries `abi_version`
(11 as of value prediction — §8).

A host supplies five hooks (`read`, `write`, `fetch`, `trap`, `retire`) and
then:

```c
void *m = S->create(&hooks);
S->select_core(m, "xdecodes");      /* 0 for a name the description lacks */
S->reset(m, entry, "iw32", state, n_state);
S->count_cycles(m, 1);
S->run(m, limit);                   /* or S->step(m) */
S->cycles(m); S->steps(m); S->mispredicts(m); S->replays(m); /* ... */
S->destroy(m);
```

`select_core` refuses a core that names a timing model the host has not bound
(`register_model`), rather than fall back to the built-in pipeline: a
plausible number for a machine nobody asked about is worse than a refusal.
`timing_source` says which model produced a cycle count.

## 3. Two engines, one machine

| | trace-driven | execution-driven |
|---|---|---|
| declared by | default | `(engine execute)` |
| who computes values | the functional model, ahead of the pipeline | the pipeline, in its own window |
| wrong path | forked functional state (O12) | the pipeline's real speculation (E2) |
| checked by | — | the golden model at commit; a disagreement is a replay |
| several cores | no | yes: `run_cores`, `cycle_cores` |

Both run the same issue and commit loop and the same front end, and for a
program neither engine mis-speculates on they report the same cycle count —
the vector gates compare the two as a standing check. `docs/ooo_design.md`
§14–§16 is the execution-driven engine; `engine_speed.py` (§16) is what each
costs to run.

## 4. What a core can declare

```lisp
(defcore xdecodes
  (kind rvmt)
  (implements iw32)
  (memory l1d)
  (issue-width 4)
  (window (rob 32) (issue-queue 32) (commit-width 4))
  (branch (penalty 0) (predictor bimodal) (entries 64))
  (front-end (fetch-width 4) (depth 2) (btb 64) (btb-penalty 3) (icache l1i))
  (engine execute)
  (units
    (alu (count 4) (pipelined true))
    (mul (count 1) (pipelined true))
    (br  (count 1) (pipelined true))
    (lsu (count 1) (pipelined true))))
```

A core with no `(window ...)` is the in-order machine; a non-zero `rob` is
what makes it out of order. Each clause below is optional and absent means
the machine does not have the thing.

| Clause | What it models | Where |
|---|---|---|
| `issue-width`, `units` (`count`, `pipelined`) | how many instructions start per cycle, and on what | `arch_packs.md` §7d |
| unit `abort` | what a squashed instruction started in the unit is stopped, not run to the end | §23 |
| `window` (`rob`, `issue-queue`, `commit-width`) | out-of-order issue, in-order commit | `arch_packs.md` §7d |
| `window` `rename-width`, `select`; `queues`; `value-prediction` `kind` | results renamed a cycle, picking by position instead of age, a queue several units share, and a value predictor that follows a stride | `scheduler_design.md` §6 |
| `window` `dispatch-width`, `schedule`; `bypass`; unit `queue` | what enters the window a cycle, the wakeup-and-select loop, what a result costs to cross units, and how many may wait for one unit | `scheduler_design.md` |
| `value-prediction` (`entries`, `confidence`) | a load that has read the same value so many times running is predicted to again: nothing waits for it, and a wrong one is fetched again behind | `scheduler_design.md` §5 |
| `branch` (`penalty`, `predictor`, `entries`, `history`) | bimodal, gshare, or a bound predictor (`register_predictor`) | `ooo_design.md` §5, §9 |
| `branch` `overrides` (`predictor`, `entries`, `cycles`) | a quick predictor fetch follows, overridden at decode by the core's own | §25 |
| `lsq` (`loads`, `stores`, `disambiguation`, `forwarding`, `replay`, `store-sets`) | memory ordering, forwarding, betting a load misses | §3, §6, §7 |
| `rename` | a finite pool of physical registers | §4 |
| `front-end` (`fetch-width`, `depth`, `buffer`, `btb`, `btb-penalty`, `ras`, `icache`) | fetch, decode depth, target buffer, return stack, instruction cache | §8, §10, §12 |
| `ports` | units behind one issue port share it | §11 |
| wrong path (`front-end`, `engine`) | what a mispredicted path fetches, executes and holds; its own mispredicts, nested | §12–§13, §19–§24, §26 |
| `memory`, `memory-timing` | the core's cache -- a table of lines, or one that is busy (`(blocking true)`) -- or its port on a `defmemsys` | `memory_system_design.md`, `unified_engine_design.md` §6, `blocking_cache_design.md` |
| `tlb` (`data`, `fetch`, `second`, `page-bytes`, `walk-cycles`) | how many pages the machine remembers, and what forgetting one costs | `tlb_design.md` |
| `tlb` `walkers`, `walk`, `walk-cache`, `huge` | how many walks at once, a walk that reads its table through the data cache, a cache of the table's upper levels, and a region of large pages | `tlb_design.md` §2a |
| `(prefetch NAME...)` on a `defmemory` of a memory system | next-line, stride, best-offset, or one a host binds (`register_prefetcher`) | `unified_engine_design.md` §3–§4, `tlb_design.md` §3 |
| `window` `eliminate` | a register move -- told from what the instruction computes -- is done at rename: an entry in the window, and no queue slot, unit, register or latency | `rename_design.md` |
| `window` `eliminate zeros` | a register xor-ed with or subtracted from itself is known when it decodes: an entry like a move's, that waits for nothing | `rename_design.md` |
| `store-buffer` `entries`, `drain` | a store that retires waits in its core's buffer: its own loads read it, other cores do not until it is written -- in order (total store order) or each when its line is ready (the relaxed models); what orders memory retires past an empty buffer | `memory_model_design.md` |
| `load-order` | `any`: a load another core's store overtakes keeps what it read -- the relaxed models' load-load reordering -- unless an older load of the same bytes had not read, or something that orders memory stands before it. `tso`: it keeps it only when every older load of its core has read -- total store order's | `memory_model_design.md` |
| `timing` `fuse` | a pair the core names -- a compare and its branch -- is one operation when the tail reads what the head writes and they leave one register: one entry, one slot of every width, one unit; a tail that is a load takes its head into the access | `rename_design.md` |
| `front-end` `target-queue` | a decoupled front end: the predictor names a line a cycle, N beyond fetch, and a line is asked of the instruction cache when it is named | `front_end_design.md` |
| `front-end` `op-cache`, `loop-buffer` | code decoded once is delivered from a cache of micro-ops, or a small loop from a buffer: wider, fewer stages from dispatch, nothing fetched | `micro_ops_design.md` §7 |
| `timing` `micro-ops` | an instruction divided into micro-ops, each an entry, a unit and a latency; what each reads and writes is derived from the instruction's effects | `micro_ops_design.md` |
| `model`, `provenance`, `vendor` | a timing model that is not this library | `arch_packs.md` §7e |
| `events` (`wait`, `send`, `local`) | a wait sleeps until another core sends | `unified_engine_design.md` §7 |
| unit `lanes`, `length`, `accepts`, `transport`, `switch` | vector units (§5 below) | `vector_units_design.md` |

Section numbers without a file are `docs/ooo_design.md`.

An instruction declares its own latency and which unit it uses -- or,
naming none, issues to the class its effects derive (`lsu`, `fpu` or `alu`)
if the core declares it; a unit declares no latency. That is deliberate: a second place to write a latency is a
field nothing has to agree with. A core may override either with `(timing
...)` (`core_timing_design.md`), and this simulator charges the core's word:
two cores over one ISA may differ in a latency.

## 5. Vector units

A vector instruction is one instruction in the window, with every lane's
memory accesses and registers as its dependences. SVE and SME build as
simulator packs and run on both engines.

| Clause on a unit | Meaning |
|---|---|
| `(lanes N)` | the unit works on N 64-bit slices a cycle; a wider instruction takes several beats |
| `(length NAME)` | an instruction carrying operand NAME takes lanes for that many elements, not its whole register |
| `(accepts NAME...)` | other units' instructions may issue on this unit's idle lanes |
| `(transport N)`, `(switch N)` | what a unit shared between cores costs: a delay on every result, and a delay to change whom it serves |

`share_unit(machine, other, unit)` makes one unit of two cores a single set of
copies and lanes — an SME-like unit serving the cores around it. When a core
has several hardware contexts, the core (its group), not each context, is the
party that takes a turn. `docs/vector_units_design.md` has all of it.

## 6. Several cores, contexts and warps

| Call | What it joins | Where |
|---|---|---|
| `run_cores`, `cycle_cores` | several execution-driven machines over one memory, a cycle at a time | `ooo_design.md` §17 |
| `memsys_join` | machines as ports of one described memory system | `memory_system_design.md` |
| `share_core` | hardware contexts: threads of one core, sharing its units and widths | `unified_engine_design.md` §7 |
| `set_warp` | contexts sharing one front end (a warp) | `unified_engine_design.md` §7 |
| `share_unit` | one unit, several cores | `vector_units_design.md` §9 |

SIMT cores are a separate library (`emit-pack-simt-c`, `docs/simt_design.md`)
that runs on the same clock and the same memory system.

## 7. What is counted, and what is not modelled

Counters are functions on the pack, read after or during a run: `cycles`,
`steps`, `mispredicts`, `target_mispredicts`, `btb_misses`,
`front_end_stalls`, `cache_hits`, `cache_misses`, `icache_misses`,
`dtlb_misses`, `itlb_misses`, `page_walks`,
`micro_ops`, `op_cache_ops`, `loop_buffer_ops`, `value_predictions`,
`value_mispredicts`,
`wrong_path_lines`, `wrong_path_instructions`, `memory_violations`,
`replays`, `squashed`, `traps`, `snoops`, `warp_rides`, and per-node
statistics of a described memory system. They are reported rather than left
to be inferred from the cycle count, which in a pipeline cannot be done.

Not modelled, with the list each document keeps:

* **Full system**: no OS, devices, interrupts or checkpoints. A trap is
  precise, taken at commit, and handed to the host's `trap` hook.
* **Translation itself.** A TLB here is timing: a walk may read its table
  through the cache, but no entry is read for what it says and nothing faults
  (`tlb_design.md` §2, §2a).
* **Memory models weaker than sequential consistency**, atomics and fences
  across cores (`ooo_design.md` §27).
* **Speculation limits**: detours more than four deep, a quick predictor
  that is not bimodal, when a trace-driven wrong path's lines arrive, and the
  rest of `ooo_design.md` §27.
* **Vector limits**: a store wider than the window's access list replays; a
  vector access touches the cache once per lane; a shared unit charges
  nothing to leave it (`vector_units_design.md` §4, §10).
* **Power, area and frequency.** Hardware cost is the hardware generator's
  question (`docs/hardware_design.md`); nothing here models energy.

## 8. The ABI

`axis_sim_pack.abi_version` is 11. Fields are only ever added at the end, and a
host reads a field only at the version that introduced it. The history, field
by field, is `docs/ooo_design.md` §28; v5 is the timed memory system, v6 the
vector event counts, v7 hardware contexts, v8 `share_unit`, v9 the TLBs and
`register_prefetcher`, v10 the micro-op counts, v11 the value predictor's.

## 9. What holds it

Every stage is a gate in `tools/check_all.py`, named by the claim it checks —
"a load waits for the store it reads", "the wrong path holds what it uses",
"one unit, several cores". Each builds real packs, runs directed programs on
them, and compares cycle differences between two program lengths so that
front-end fill and drain cancel. `tools/check_all.py --only <substring>` runs
one; with `AXIS_BIN` set to a built `axis`, a gate takes seconds.
