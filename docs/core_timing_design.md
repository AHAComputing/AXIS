# Timing belongs to the core: a proposal

Status: **T1–T5 built** -- the clause, the one function that resolves it,
the simulator charging each core's word, the description as one core sees it
(`--core NAME`), the floor and `(latency derived)`, and the miner's tools on
one clock, and a modelled area beside the declared one. Decided by the user on 2026-10-07: a core *overrides* its
instructions' defaults, and a latency under what the netlist needs is
*refused*.

## 1. What is coupled

A `definstruction` says what an instruction computes and how it is encoded.
It also says, in the same form, how long it takes, which functional unit runs
it, and what it costs:

```lisp
(definstruction MUL
  ...
  (formal (mul i64 rs1 rs2))
  (latency 3)
  (throughput 1.0)
  (area-estimate-um2 4000.0)
  (power-estimate-mw 5.0)
  (expected-speedup 1.0))
```

The first two lines are the architecture. The rest is one machine. `(latency
N)` is written 338 times in `rv64i.axisl` and 1356 times in the AArch64 seed,
and a `defcore` cannot change any of them: a unit declares how many of it
exist and whether it is pipelined, and nothing else.

That was decided, and for a reason `docs/arch_packs.md` gives: *a second place
to write the same number is how a field becomes free text.* `expected-speedup`
is 1.0 on every RV64I instruction because nothing ever had to agree with it.
The reason is right. What it argues for is one place that something checks --
not that the place be the instruction.

Everything else about a machine is already the core's: widths, the window, the
predictor, the front end, the caches (`docs/pack_simulator.md` §4). Semantics
never mention a machine. Unit grouping and sharing can come from outside
(`--hw-plan`). Timing is the part that did not move.

## 2. What it has cost

* **Two cores over one ISA cannot differ in a latency.** The one thing a
  designer most wants to vary between a small core and a fast one is fixed per
  description.
* **`ise_cost.py` edits the description's text.** To price an extension at two
  cycles and at three it rewrites `(latency N)` with a regular expression and
  has AXIS read the whole description again, once per option.
* **The declared number and the built circuit disagree, and nothing says so.**
  RV64I declares `MUL` three cycles. The netlist AXIS generates for it is 61
  gate delays, two cycles at the 45-gate cycle the hardware planner groups by.
  The pack simulator charges three; the miner prices an extension against two.
  `docs/ise_mining_design.md` §9 lists it as a limit.
* **A machine property names the datapath.** The planner puts instructions of
  different declared latency in different units (`alu`, `alu_l2`, `mul_l3`),
  so a number on the instruction decides which circuits can share.
* **SIMT cores already needed the override**, and got one of their own:
  `class-latency` and `mnemonic-latency`, added because Vortex charges every
  ALU operation two cycles and its FPU fourteen for an FMA. A CPU `defcore`
  has no such clause.

## 3. The proposal

**An instruction's latency and unit become defaults. A core may say otherwise,
and what a core says is checked against the netlist.**

```lisp
(defcore fast
  (implements rv64i)
  (cycle (gates 45))
  (units
    (alu (count 4) (pipelined true))
    (mul (count 1) (pipelined true)))
  (timing
    (latency (MUL 2) (DIV 20) (REM 20))   ; by mnemonic prefix, longest wins
    (class-latency (alu 1))               ; every instruction issued to `alu`
    (unit (MINED0 mul))))                 ; which unit runs it, on this core
```

Resolution, for instruction `I` on core `C` (`src/timing.rs`, and nowhere
else):

*Unit.* The longest `unit` prefix of `C` that `I`'s mnemonic starts with; else
`I`'s own `(unit NAME)`; else a class derived from what `I` does --
`lsu` if it touches memory, `fpu` if it names a register outside the general
file, `alu` otherwise (`simt::derived_unit_class`, the rule a SIMT core
already applied). A derived class the core does not declare is no unit.
`Core::named_unit_of` is the first two alone: what a core's view writes into
its instructions and what `retimed` compares, because a derived class is the
instruction's own on every core and not a decision the core made.

*Latency.*

1. the longest `latency` prefix of `C` that `I`'s mnemonic starts with;
2. else `C`'s `class-latency` for the unit `I` resolves to **on `C`** -- an
   instruction a `unit` clause moved takes the latency of where it went;
3. else `I`'s own `(latency N)`.

A core with no `(timing ...)` is exactly today's machine. No corpus changes,
and `emit-json`'s `latency_cycles` -- which PCE's consumers read -- stays the
instruction's own number.

The names are the SIMT form's on purpose: this is that override, generalised,
and the SIMT clause becomes a spelling of it.

**What has to agree with it.** `(cycle ...)` gives the core a cycle length in
the calibrated model's units (`docs/hardware_design.md` §5). Every instruction
with a netlist then has a floor: its depth over the cycle, rounded up. A core
that gives an instruction fewer cycles than its netlist needs is describing a
machine AXIS cannot build, and is told so by name. `(latency derived)` asks
for the floor itself. That is the check the single-place rule wanted, and it
is one the instruction's own number has never had.

An instruction with no netlist -- floating point today, most of AArch64 until
units take effects -- has no floor, and its latency stays a declaration. The
gate counts them, as every hardware gate counts what it declines.

## 4. Staging

Each stage is useful alone and has a gate that fails without it.

**T1 -- the view.** _Done._ `(timing ...)` parsed on `defcore`, validated,
written back by `emit-lisp`. `Core::latency_of` and `Core::unit_of` are the
only place the order exists. `emit-uarch-json` publishes, per core that says
anything, every instruction whose unit or latency there is not its own.

Refused, by name: an entry that reaches no instruction the core decodes, a
latency of zero, an instruction sent to a unit the core does not declare, the
same key twice, and the clause on a SIMT core, which has its own.

Until T2 landed, `emit-pack-sim-c` refused a description with a retimed core:
the simulator would have timed it by its instructions' latencies, a plausible
number for a machine nobody described.

*Gate:* `core_timing_check.py` -- on every corpus nothing is published that
was not before; a core that retimes one instruction by name, a unit's worth
by class and moves one to another unit publishes exactly that; it survives
the printer; the simulator refuses it. `cargo test timing` holds the function.

**T2 -- the simulator reads the view.** _Done._ For each core the pack
simulator carries a table of every instruction whose latency or unit on that
core is not its own -- `Core::retimed`, resolved by the same function as
everything else -- and every place the pipeline took an instruction's latency
or unit now asks `axis_sim_latency_on(core, entry)` / `axis_sim_unit_on`: the
first-order scoreboard, the trace engine's dispatch, the execution-driven
engine, its wrong path, and the event a bound model is handed. A core that
says nothing has no table and is timed exactly as before.

The pack ABI did not move: the tables sit beside the core, as its exclusive
monitor and event instructions already do, rather than in the public
`axis_sim_core`. That has one consequence, and it is refused: a core timed by
an EXTERNAL model (`(model ...)`) is handed `axis_sim_core`, which carries no
retiming, so a core may not both name one and say `(timing ...)`.

`emit-pack-sim-c` no longer refuses a retimed core.

*Gate:* `core_timing_check.py` item 4. Five cores over one ISA that differ
only in what they say about time. A chain of eight multiplies takes 25 cycles
at the description's three and 57 on a core that says seven -- (7 − 3) × 8
more, every link -- and the same multiplies independent take four more, once,
for the last result. An add moved onto the multiplier takes the multiplier's
class latency. Execution-driven, the chain differs by the same 32. With the
lookup made to ignore the core, all five comparisons fail.

**T3 -- the floor.** _Done._ Three things.

*A core states its cycle*: `(cycle (gates N))`, in the cost model's unit.

*The description as one core sees it.* `--core NAME` on any command gives the
emitter that core's view (`timing::as_seen_by`): the instructions the core
decodes, each carrying the latency and unit it has there, and that core
alone. Nothing downstream learned a new rule -- the hardware planner, the
netlist emitters and `emit-json` read an instruction's latency exactly as they
did, and it is the core's. The hardware is planned at the core's cycle, and
`emit-hw-json` gives each netlist its `latency` beside the `cycles_needed` its
depth fits in.

*The floor.* A core that states its cycle is checked, at `axis check`, against
the netlist of every instruction it decodes: one given fewer cycles than its
depth needs is refused by name. On RV64I at the planner's own 45 gate delays:

```
core `c` timing: `DIV` is given 3 cycle(s), and its netlist is 1326 gate
delays deep: 30 at a cycle of 45
```

which is the description's declared number meeting the unrolled divider AXIS
builds for it. `(timing (latency (DIV 30) (REM 30)))` is accepted; so is
`(MUL 2)`, one fewer than RV64I declares; `(MUL 1)` is not.

Instructions built as *effects* -- branches, jumps, loads, stores -- are
floored too, by their own arithmetic: the address, the condition and the
value around the access. On RV64I at 45 gate delays none needs more cycles
than it declares, so nothing new is refused there; the floor is what stops a
description declaring a branch faster than its compare. Under `derived` an
effect keeps its own latency, because the memory a load waits for is not in
its netlist. An instruction with no netlist at all has no floor.

`(latency derived)` asks for the floor instead of stating it:
`(timing (latency (* derived)))` is the machine the netlists are, every
instruction at the fewest cycles it fits in; `(DIV derived)` asks for one
family's. It is resolved when the document is read, so every reader after
sees a number, and it prints back as written. The most specific prefix
decides, numbered or derived: `(* derived) (MUL 3)` keeps the multiplier at
three. It needs a `(cycle ...)` to be a number of, and is refused without one.
An instruction with no value netlist keeps its own latency under it.

*Gate:* `core_timing_check.py` items 5 and 6, and `cargo test timing`.

**T4 -- the consumers stop editing text.** _Done_, but for `axis-cores`. `ise_cost.py` no
longer rewrites `(latency N)`: an option is a `defcore` that gives the
extension its latency, every option is a core over one description, and each
is planned with `emit-hw-json --core`. The numbers it reports are the ones it
reported before.

`ise_mine.py --as-built` charges a chain on a core whose latencies are the
floors, `(latency (* derived))`, and `ise_cost.py` and `ise_run.py` price and
run on the same core: one clock for the chain and the extension
(`docs/ise_mining_design.md` §9). `ise_run.py` writes the extension's own
latency into the instruction it generates, which is a default and not an
edit. `axis-cores` is not changed.

**T5 -- the fields nothing checks.** _Done, the additive way: beside, not
instead._ The census found them READ, not dead: PCE's loader takes all three
from `aha_instructions.json`, its RTL generator sizes gate counts from
`area_estimate_um2`, and its autopilot and design-space explorer rank
instructions by `expected_speedup`; `tests/pce_contract.rs` pins them. What
they hold is placeholder: 1159 instructions declare 1500 µm², 2.0 mW and
2.0×, and 1033 declare zeros.

So nothing is replaced. `emit-aha-json` gains `area_model_um2` beside
`area_estimate_um2` -- the instruction's own netlist under the calibrated
model, in the same unit (NAND2 equivalents times sky130's `nand2_1`), null
where there is no netlist. `emit-json`'s `cost_model` gains `declared: true`
on the three declared fields and `area_model_um2` / `depth_model_gates`
beside them. PCE reads the declared number until it chooses to read the
modelled one; its loader ignores a key it does not know, and
`pce_smoke_check.py` loads the result through it.

On RV64I the two disagree by an order of magnitude and more: `ADD` declares
500 µm² and its 64-bit adder is 2354; `MUL` declares 4000 and is 76513;
`DIV`, unrolled, is 152441.

Power and speedup have no model, and stay declared. Computing the areas
lowers every instruction's netlist once per `emit-json`: about three seconds
on the AArch64 seed.

## 5. What this does not propose

* **Moving `(latency N)` off the instruction.** It stays, as the default and
  as the reference machine every gate today is held to. Deleting 1694 numbers
  to restate them on cores would be churn with no reader.
* **Throughput.** A unit's `count` and `pipelined` already say what a declared
  throughput cannot (`docs/arch_packs.md` §7d). It is left alone.
* **A cycle in picoseconds.** The model's unit is the gate delay, with one
  constant that says what that is in the reference library. A core's cycle is
  stated in the model's unit so it does not silently change meaning when the
  reference does.

## 6. Decided, and open

1. **Override, not move** (user, 2026-10-07). Defaults stay on the
   instruction; the core's word is final.
2. **A latency under the floor is refused** (user, 2026-10-07). T3 will fire
   on any description whose declared numbers were optimistic.
3. **T2 built here** (2026-10-07), after the user asked for it. The derived
   unit class (above) was written on another branch against T1 and replayed
   onto main after T2: the simulator reaches it through `axis_sim_unit_on`,
   in `Core::unit_of`'s order, with no second lookup at the call sites.
