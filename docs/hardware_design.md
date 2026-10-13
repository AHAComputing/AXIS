# Hardware from a description: netlists, and the units they merge into

Status: **10 stages implemented** (H1, the netlist; H1a, instructions stated as
effects; H1b, reference bodies and state; H2, functional units; H2a, a plan from outside;
H2b, the cost model calibrated; H2c, units with effects in them; H3, units in time;
H4a, an existing core's extension slot; H4b, that slot shared). H5 and H6 are
built elsewhere.

## 1. Why

`emit-pyrtl` ships each instruction's semantics as a *string*, and an
interpreter that turns the string into a circuit when Python runs. That is a
behavioural hook, and it is what PCE's loaders consume, but three things follow
from the shape and none of them can be fixed inside it:

* **There is no netlist until Python has run**, so AXIS cannot say how large an
  instruction is, how deep, or what it is made of.
* **Nothing is shared.** Thirty-eight RV32I instructions are thirty-eight
  circuits. `ADD`, `SUB`, `SLT` and `SLTU` each get an adder; a core has one.
* **It does not build everything it is given.** Run against the golden model on
  the day this was written, it built 27 of RV32I's 38 instructions with
  semantics and 52 of RV64I's 66 -- `mulh` and its siblings have no arm, and
  every constant is made 32 bits wide, which a 64-bit literal does not fit.

The generator this document describes builds the netlist in AXIS, where it can
be analysed, and then does the thing a netlist per instruction cannot: decide
which instructions belong in one functional unit and which of their operators
become one.

```
axis emit-hw-pyrtl examples/rv64i.axisl -o rv64_hw.py     # the circuits
axis emit-hw-json  examples/rv64i.axisl -o rv64_hw.json   # what was built, and why
axis emit-hw-smt2  examples/rv64i.axisl -o rv64_hw.smt2   # the same circuits, to prove
```

`emit-pyrtl` is unchanged. It is a published contract
(`axis.pyrtl-semantics.v1`) with consumers, and this is a second artifact
beside it, not a replacement under it.

## 2. The netlist (H1)

`src/hw.rs` lowers the typed IR (`ir::Sem`) into a hash-consed graph of
hardware primitives, each node carrying its exact width.

### 2.1 Polymorphism lives in control inputs

| primitive | arguments | result |
|---|---|---|
| `AddSub` | `a`, `b`, `sub` | `n + 1` bits: `a + (sub ? ~b : b) + sub`, carry on top |
| `Mul` | `a`, `b` | low `n` bits of the product |
| `MulWide` | `a`, `b`, `sa`, `sb` | all `2n` bits; `sa`/`sb` read an operand as signed |
| `DivRem` | `a`, `b`, `signed` | `2n` bits, remainder above quotient; zero divisor gives zero |
| `Shr` | `a`, `amount`, `fill` | `a >> amount`, `fill` shifted in |
| `Ror` | `a`, `amount` | rotate right, `n` a power of two |
| `Clz`, `Cpop` | `a` | a count |
| `Eq`, `And`, `Or`, `Xor`, `Not`, `Mux` | | gates |
| `Zext`, `Sext`, `Slice`, `Concat`, `Rev` | | wires |

There is one adder primitive and its third argument says whether it subtracts.
`add`, `sub`, `icmp_ult`, `icmp_slt`, `min` and `max` all lower onto it: an
unsigned less-than is a subtractor's carry, a signed one is its sign corrected
for overflow. `lshr` and `ashr` are one right shifter with a different fill,
and `shl` is the same shifter between two bit reversals, which are wires.
`ctz` is `clz` of the reversed value. `mulh`, `mulhu` and `mulhsu` are the high
half of one `MulWide` with different sign flags.

Two consequences. `SUB`, `SLT` and `SLTU` share a subtractor by hash-consing
alone, before any merging is attempted. And merging (§3) only ever has to bind
a node to a unit of the *same* primitive and mux its inputs -- the control
inputs among them, so "this unit adds for these instructions and subtracts for
those" is not a special case but a one-bit mux of two constants, which folds to
a decode.

### 2.2 Widths are demanded

`lower(sem, n)` returns an `n`-bit node congruent to the golden model's value
modulo `2^n`, and asks each argument only for the bits that can reach those `n`.

The golden model evaluates in unbounded integers and masks only where an
operator says so. `add`, `sub`, `mul` and the bitwise operators do not mask --
an `i32` add read at 64 bits is the 64-bit sum -- so they are built at the
demanded width whatever their type atom says. Operators that do mask (`lshr`,
`udiv`, the comparisons, `clz`, ...) are built at their type's width and
zero-extended above it. A signed quotient is not masked and is negative, so
above its type it is sign-extended, except `MIN / -1`, which is positive;
dividing one bit wider makes that case ordinary.

The effect is that `ADDW`'s `(sext i64 32 (add i32 rs1 rs2))` builds a 32-bit
adder, because nothing above bit 31 of the sum can reach the result.

`let` bindings are inlined by `ir::lower`, so one bound value appears as many
equal subtrees, possibly wanted at different widths. The lowering runs twice
over a hash-consed copy of the expression: the first pass records the widest
each subexpression is ever asked for, the second builds each once at that width
and slices it for the narrower uses. There is one set of lowering rules, used
by both passes, so the demand a rule records cannot drift from the node it
builds.

### 2.3 Every rewrite is a builder

Folding and the wiring identities happen where a node is made, so there is no
pass to skip:

* a shift by a constant is a slice and a concat;
* `x & 0x3f` is a slice and a zero-extension, which is what makes
  `(sll i64 rs1 (and i64 rs2 0x3f))` a six-stage shifter with no out-of-range
  detect;
* two zero-extended bits ANDed at 64 bits are one gate over two bits, which is
  what a `select` whose condition is two comparisons would otherwise not be;
* `a - (a / b) * b` is the remainder the divider already has. RISC-V's `REM` is
  written that way, because AXIS's remainder is zero for a zero divisor and
  RISC-V's is the dividend. Lowered as written it is a divider, a multiplier
  and a subtractor.

That last rule changed the plan: before it, the divider's unit held a
multiplier of its own and the cost test (§3.1) joined it to the multiplier's
unit as one `muldiv`. After it they have nothing in common and stay apart.

### 2.4 What has no circuit says so

An instruction that cannot be lowered is **declined, with the reason**:
`floating point, which has no circuit yet`, `an adder 128 bits wide`,
``reads `pc`, which is not an operand``. The emitted module carries a `DECLINED`
table beside `INSTRUCTIONS`, and the gate takes `--expect-declined N` so that a
generator which quietly builds less fails rather than passing on what is left.

### 2.5 Instructions stated as effects (H1a)

A branch, a jump, a load and a store have no single value. They are written as
effects -- write this register, set the program counter if that holds, store
this at that address -- and each is lowered to one node per thing it does: the
value of every effect, the guard that says whether it happens, a store's
address.

The program counter is an input like an operand. **Memory is not built.** A
load is an address out and a value in: the expression's `(load iN signed addr)`
is taken out, its address lowered on its own, and what was read comes back as
an input, sign-extended as the golden model reads it. A store is an address
and a value out. What is on the other side is a core's.

`emit-hw-pyrtl` gives each a `build_effect_<mnemonic>` returning those wires
and lists them in `EFFECTS`; what it cannot lower is in `EFFECTS_DECLINED` with
the reason -- an atomic store, a trap, two loads in one instruction.

`tools/hw_effects_check.py` holds every value, guard and address to the golden
model's own evaluator on the expressions `emit-lift-json` publishes, with a
memory that is different at every address and width: a memory of zeros would
agree with a netlist that read the wrong place.

| corpus | effect netlists | of which |
|---|---|---|
| RV32I | 33 | 23 register writes, 8 pc writes, 12 state writes, 5 stores |
| RV64I | 44 | 28 register writes, 12 pc writes, 12 state writes, 7 stores |

These are not merged into `emit-hw-json`'s units. A branch's comparison, its
target and a load's address are live in the same cycle of one instruction --
which stops two of them sharing an operator, and not a branch's adder being
another branch's. Units with effects in them are §3.5's, a separate artifact.

**Effects happen in order.** A pre-indexed store is `rn = rn + imm; Mem[rn] =
rt`, and the address is the *updated* base: AXIS's executors evaluate effects
one after another against a register file they have already written. In the
netlist, each register or state write rebinds its name to the node that
carries the new value, and the effects after it are lowered against that; a
load's address is lowered where the load stands. The program counter is not
threaded -- a jump-and-link sets it and then links the old one.

⚠️ The first version lowered every effect against the registers as they stood
before the instruction, and its gate evaluated the reference the same way. The
two agreed with each other on every instruction and were both wrong on every
pre-indexed form. What found it was a core built from the netlists, run beside
the executor. The gate now evaluates effects in order, and the old lowering
fails it on six instructions at once.

**Architectural state** is an input and an effect like any other. A flag word
a conditional reads comes in by name beside the operands (`EFFECTS[...]["state"]`
says which inputs are state), and writing one is a `setstate` effect.

### 2.6 Operators the IR does not carry: reference bodies

Some operators are implemented natively by every software backend and are not
in the typed IR at all -- AArch64's shifted and extended register operands,
its flag words, its bitmask immediates. A netlist cannot be lowered from a
name.

A description states what such an operator means, in its own operators, as a
`deffun` named `<operator>_ref_i<W>`: the operator at width `W`. Where the
lowering meets the operator used at that width it inlines the body, exactly as
it inlines any `deffun`. Nothing in the lowering knows an operator's name, and
no instruction's semantics change: the software backends go on computing the
built-in.

The body is then load-bearing, and nothing else compares it with the
operator. `tools/hw_reference_check.py` does, in the golden model, where both
exist: the operator evaluated directly and the reference called, on vectors
drawn from small values, boundary values and random ones -- a flag word turns
on a carry out of bit 63 and a bitmask immediate on six bits of one argument,
and uniform values reach neither.

On the AArch64 seed, 23 reference bodies take the effect netlists from 160 to
387 with architectural state, every one still equal to the golden model. Two
of the bodies were wrong as first written -- the sign position of a 32-bit
signed bitfield, and a degenerate immediate where the built-in is zero -- and
the gate is what said so.

A reference body is a `deffun`, so every software backend emits it too, and it
has to be something each of them can emit. Two limits of the C backend shaped
these: a function may only call functions of its own word size, so the 32-bit
bitfield references that use the 64-bit mask builders are declared at 64 bits
and return their low half; and a 64-bit high multiply has no C at all, so
`a64_umulh` and `a64_smulh` have no reference and the four instructions that
use them are still declined.

## 3. Functional units (H2)

`src/hw_units.rs`. The instructions of one unit never run in the same cycle, so
two of them can use one operator at the price of a multiplexer on each input
they do not already agree about.

### 3.1 Which instructions belong together

* **Declared**, when every instruction with a circuit carries a `(unit ...)`
  tag. The description has decided, and a `defcore` that names those units is
  already read by the timing model; a second answer here would be a second
  answer.
* **Derived**, otherwise. What fits in a cycle -- taken as two adders of the
  widest result when the description does not say -- is `alu`. What does not is
  named for its largest operator: `div`, `mul`, or `slow`. Then two slow units
  are joined if one merged unit is smaller than the two apart, by actually
  merging them and comparing. The ALU is never joined to a slow unit, which
  would put a single-cycle instruction behind a multi-cycle operator.

### 3.2 Which operators become one

Heavy nodes -- adders, multipliers, dividers, shifters, rotators, counters --
are bound to operator *instances*, in topological order, so a node's own
inputs are already placed when it is. A node may join an instance when:

* **no instruction that needs the node already uses the instance.** Two nodes
  of one instruction are live in the same cycle;
* **it closes no loop.** If the instance already feeds one of the node's own
  feeders, binding here makes a cycle through two muxes that no instruction
  ever selects together -- a false path, and a netlist tool rejects it anyway;
* **it pays.** The muxes it adds, plus any widening of the instance, cost less
  than the operator it saves.

That last test is made node by node and sees only the mux on the port. So it
is made again for the unit, class by class: the unit is built with the class
shared and with it apart, and the share stands only if it keeps at least
**half** of the operator area it removes (`SHARING_MARGIN`). The half is the
cost model's own error, measured (§5.2) -- what steers a shared operator is
the part the model prices worst, and always in sharing's favour. A class left
apart for it is named, in `emit-hw-json`'s `kept_apart`, with what sharing
would have removed and saved.

**And it has to fit the cycle, where a core states one.** Sharing puts a mux
before the shared operator and another after it, and every instruction the
unit runs pays for both. When the design is a core's view and the core states
`(cycle (gates N))` (`docs/core_timing_design.md`), a unit whose longest stage
the shares take past N is built again with each share undone in turn, and the
share whose undoing fits the cycle for least area is left apart -- named, with
`because: "cycle"` and the stage it would have made. RV64I's ALU at 45 gate
delays shares one adder among thirteen instructions for a 47-deep stage; apart
its adders make it 37 deep and 5700 NAND2 larger (13106 against 7406), and at
45 that is what is built. At 50 the share stands. The planner's own cycle -- two adders of the
widest result, when no core states one -- is a rule for grouping, and no share
is undone for crossing it.

Among the instances that qualify it takes the one whose inputs it already
matches, trying both operand orders for a commutative node.

A node narrower than its instance rides it under the extension that makes the
wide operator's low bits the narrow result: the fill bit for a shifter, the
sign under the sign flag for a multiplier or divider, ones *below* the value
for a leading-zero count.

⚠️ **The rule that makes `ADDW` free.** A sum's low bits depend only on its
operands' low bits. So when nothing reads an adder's carry, its operands may be
driven with *anything* above their width -- in particular with the wide value
they were sliced from. `ADDW` reads the low halves of `rs1` and `rs2`; `ADD`
reads `rs1` and `rs2`; under this rule they are the same two wires and `ADDW`
costs no mux at all. Without it the narrow operands are zero-extended, become
different sources, and cost 128 mux bits to save 32 adder bits -- which the cost
test rightly refuses, and RV64I's ALU comes out with two adders. The first
version did.

A plain multiply joins a wide multiplier, whose low word is the same product
whatever the sign flags, and promotes a plain instance to a wide one when a
high-half multiply arrives.

The unit takes a `sel` input, a member's position in the unit's member list.
Each mux is a balanced tree steered by "one of the members on my left is
running"; when no member that uses a wire is running nothing reads it, so no
source needs a decode to be the default.

### 3.3 What neither choice can do

Neither grouping nor binding can make a unit **wrong**. A merged unit is rebuilt
from the same nodes over muxed inputs, each instruction's result is recovered
by construction, and the gate holds every member to the golden model anyway.
The choices only move area and depth.

That is deliberate, and it is the seam the rest of this design hangs on (§6).

### 3.4 Units in time (H3)

A unit's instructions all declare one latency: the plan splits a group whose
members disagree, so RV64I's two `FCLASS` forms, which fit in a cycle and
declare two, are `alu_l2` beside `alu`. A unit of latency `L` gets `L - 1`
registers on every path from an input to its result.

`schedule` places them as soon as possible, each stage filled to an even share
of the unit's depth. A node that cannot be cut starts a new stage when it would
overrun the one it is in. A multiplier or a divider takes registers *inside*
itself: the multiplier is taken a slice of one operand at a time, the divider a
share of its quotient bits at a time, with everything still needed registered
between.

It is retiming and nothing else -- no node changes -- so the pipelined unit
computes what the unpipelined one does, `L - 1` cycles later. The gate issues a
**different instruction every cycle**, with idle cycles of noise among them,
and requires each result exactly that many cycles after its issue. Back to
back, because one instruction at a time would pass a unit whose stages leak:
a register missing on one path reads the *next* instruction's operand. It
caught exactly that in the first cut multiplier.

`emit-hw-json` gives each unit's `timing`: the declared latency, the registers,
the deepest stage, and the cycles the unit would need for every stage to fit
the cycle its ALU implies. On RV64I the description says a divide takes 3
cycles; the divider's stages are then some 400 gates deep and it would need 38.
That is a fact about the description, and the hardware is the first thing in
the stack able to state it.

### 3.5 Units with effects in them

§2.5 said effects are not merged into units, because a branch's comparison,
its target and a load's address are live in one cycle of one instruction.
That is a reason two nodes of ONE instruction cannot share an operator -- and
the merger has never let them. It is not a reason a branch's adder cannot be
another branch's.

`emit-hw-effect-json` and `emit-hw-effect-pyrtl` are units whose members may
be values or instructions stated as effects. Each output is a *slot*, named
by what it is and not by who drives it: `w0` the first register written,
`pc`, `s_<name>` a piece of state, `st0_addr` and `st0_value`, `ld_addr`. A
slot that some member does not drive, or drives under a condition, has
`<slot>_en` beside it. A value's result is `w0`, so `ADD` and `ADDS` -- one a
value, one an effect with a flag word beside it -- drive one slot and one
adder serves both. The merger is §3.2's, margin included.

AXIS's grouping puts its value units first, as they are, and each effect
instruction where its class and latency say: the unit it names, else `lsu`
for one that touches memory, `br` for one that sets the program counter,
`alu` otherwise -- joining a value unit of that class and latency if there is
one.

| corpus | effect members | units | merged / apart, NAND2 |
|---|---|---|---|
| RV32I | 33 of 71 | 7 | branches 1244 / 1470 |
| RV64I | 44 of 110 | 8 | branches 2833 / 4326, loads and stores 1417 / 2199 |
| AArch64 seed | 387 of 696 | 19 | ALU at one cycle 45464 / 91716 (249 members, 198 effects); loads and stores 6690 / 15430 |

They are a pair of artifacts BESIDE `emit-hw-pyrtl` and `emit-hw-json`, not a
change to them: what those publish -- and what `axis-cores` and URV's
extension slot read -- does not move. A unit here returns a dict of slot
wires, and `EFFECT_UNITS` says, for every member, which slot is which of its
own wires.

`tools/hw_effect_units_check.py` selects every member of every unit, puts
noise on every port, and compares each slot the member drives with that
member's own netlist -- which `hw_units_check.py` and `hw_effects_check.py`
already hold to the golden model -- and requires every slot it does not drive
to have its enable at zero. Claiming instead that every member writes every
slot fails it 206 times on RV32I.

**In time.** `build_effect_unit_<name>_pipelined(valid, sel, ...)` is the
unit cut by §3.4's scheduler, generalised to several outputs: one cut through
every slot, so all of them leave `latency - 1` registers later with a valid
bit beside them, and a new instruction is accepted every cycle.
`emit-hw-effect-json` gives each unit's `stage_delay`. The gate feeds every
pipelined unit a random instruction every cycle, a fifth of cycles empty, and
requires each slot to leave with what the combinational unit gave for those
inputs; a pipeline one register short fails it 65 times on RV32I.

Not yet: a proof (`emit-hw-smt2` covers value units) and the depth rule of
§3.2 -- a slot unit is not undone for a core's cycle.

## 4. What is checked

`tools/hw_units_check.py`, on the golden model's own vectors:

1. each instruction's own netlist;
2. the same instruction selected in its unit, **with noise on every other
   operand of the unit and on the bits of a port above the operand sharing
   it**;
3. the account: every instruction the golden model evaluates is built or
   declined by name, with the golden model's interface, and every built one is
   in exactly one unit.

`--measure` synthesises each unit and its unmerged baseline to gates with PyRTL
and requires the merged one to be smaller. `tools/hw_calibrate.py` (§5) does
the same through Yosys to standard cells, and holds the cost model to it.

`tools/hw_prove.py` asks the same of **every** input. `emit-hw-smt2` writes each
netlist as an SMT-LIB function beside the definition `emit-smt2` already gives
the instruction -- a definition written without knowing the netlist exists --
and z3 is asked whether they can differ, and whether a unit with its select
fixed can differ from its member on any value of any port.

| corpus | obligations | proved | not proved |
|---|---|---|---|
| RV32I | 76 | 74 | 2 |
| RV64I | 132 | 124 | 8 |
| zbb_like | 22 | 22 | 0 |

⚠️ "Not proved" is z3 running out of time, which is neither a proof nor a
refutation, and the gate pins the count so it cannot grow unnoticed. All ten
are two arithmetic facts z3 cannot bit-blast: a remainder rewritten to read the
divider (§2.3), and a 32-bit divide riding a 64-bit divider (§3.2). Those rules
are instead **exhausted at small widths** in `cargo test`, through the code that
ships: every pair of bytes for the remainder, and every input of every narrow
operator riding a wide one at four bits on eight.

`cargo test` also holds what needs neither tool: the primitives against
integers, the shapes the rewrites promise (one subtractor for `sub`/`ult`/`slt`,
a 33-bit adder under `ADDW`, no shifter for a constant shift), each merged unit
against its members on the graph's own interpreter, and no node of a merged
unit having an argument above it.

| corpus | netlists | declined | units |
|---|---|---|---|
| RV32I | 38 | 0 | `alu` 28, `alu_l2` 2, `mul` 4, `div` 4 |
| RV64I | 66 | 0 | `alu` 51, `alu_l2` 2, `mul` 5, `div` 8 |
| zbb_like | 11 | 0 | `alu` 11 |

RV64I's ALU is one 64-bit adder serving sixteen instructions and one 64-bit
shifter serving fourteen. Its multiplier unit is one wide multiplier serving
`MUL`, `MULW`, `MULH`, `MULHU` and `MULHSU`; its divider unit one divider
serving all eight divisions and remainders.

## 5. The cost model

Area in NAND2 equivalents, delay in gate delays. `emit-hw-json` says
`"calibrated": true` and names what against:

```
"cost_model": {"area_unit": "nand2-equivalent", "delay_unit": "gate", "calibrated": true,
               "reference": "yosys+abc, sky130_fd_sc_hd tt 1.80V 25C, no wire load",
               "ps_per_gate": 100.0, "cycle_budget": 45.0, "operators": [...]}
```

The reference is the PyRTL `emit-hw-pyrtl` ships, synthesised by Yosys and
mapped by ABC to SkyWater's open 130 nm cells (`tools/hw_synth.py`). A NAND2
equivalent is that library's `nand2_1`; a gate delay is 100 ps in it. It is a
synthesis estimate -- no placement, no wire load -- and a model of *these*
netlists: the divider it prices is the unrolled one that is emitted.

`tools/hw_calibrate.py` holds the model to it at three levels, a ratio being
model over synthesis:

| level | what | area, typical (range) | delay, typical (range) |
|---|---|---|---|
| operators | each alone at 8, 16, 32, 64 bits | 1.00 (0.91 -- 1.17) | 1.00 (0.81 -- 1.16) |
| instructions | RV32I, RV64I, zbb_like netlists | 1.04 -- 1.07 (0.87 -- 1.33) | 0.96 -- 1.03 (0.81 -- 1.57) |
| units | merged units of the same | 1.11 -- 1.38 (0.97 -- 1.38) | 1.07 -- 1.12 (1.03 -- 1.17) |

The constants were fitted on the first level and the other two are what the
fit was not shown. The gate fails when any of them leaves its band.

### 5.1 What the fit needed beyond constants

The first fit matched every operator and was still out by 3.6 times on RV32I's
ALU and by twelve on `FCLASS`. An operator's price was never the problem; what
synthesis leaves of it in context was. Three things are read from the graph
now, and none of them rewrites it:

* **Bits that cannot change** (`KnownBits`, kept per node). A zero-extension's
  upper half, a mask's cleared bits, a literal arm of a mux. A gate with a
  known operand is a wire, a mux with a literal arm is an AND, and a 64-bit mux
  of two zero-extended words is 32 bits of mux.
* **Bits nothing reads** (`HwGraph::demand`). A comparison is a subtractor of
  which only the carry is read: two thirds the area and half the depth. An
  adder's bits are priced one by one -- sum read or carry only, both operands
  free or one known, or one a sign extension's repeated bit.
* **What a mux tree brings in** (`bitwise_support`). A mux of `a & b`, `a | b`
  and `a ^ b` is three arms over two values: one small function of each bit,
  not a mux apiece. A mux in a tree is also cheaper than one alone, because
  trees map to four-input cells.

And two things about units: an operand read at two widths by two members is
one wire (`through_ports`, applied before merging, so the merger no longer
muxes a port against itself), and two shifters of one value by one amount --
a logical shift, an arithmetic one, a rotate -- are mostly one tree, which
synthesis builds once whether or not anything was merged.

### 5.2 What it is still wrong about, and which way

The model prices a unit 11% to 38% above synthesis, always above: a unit is
mostly muxes, and synthesis folds a mux into the logic on either side of it.
It prices a unit's members *apart* higher still, because synthesis shares
between operators the model prices one at a time.

So the model overstates what sharing saves. Each sharing decision AXIS made
on the three corpora, built both ways and synthesised:

| unit, class | removes | saves, model | saves, synthesised | keeps (model) |
|---|---|---|---|---|
| RV32I `alu`, adder | 657 | 468 | 301 | 71% |
| RV32I `alu`, shifter | 649 | 637 | 367 | 98% |
| RV64I `alu`, adder | 4923 | 5700 | 3539 | 116% |
| RV64I `alu`, shifter | 7441 | 7693 | 5097 | 103% |
| zbb_like `alu`, rotator | 488 | 177 | **-78** | 36% |
| zbb_like `alu`, comparator | 192 | 12 | **-166** | 6% |

(A share can keep more than it removes: thirteen adders become one, and the
result mux that chose between thirteen sums goes with them.)

⚠️ The last two were the merger being wrong, and it was wrong until this
table existed. It shared one rotator between `ROLX` and `RORX` behind bit
reversals, and one subtractor between `MINX` and `MAXUX` behind operand muxes;
synthesis, given them apart, already shares the rotate-right with the
arithmetic shift beside it, and the muxes cost more than was saved. The rule
of §3.2 comes from this table: a share that keeps under half of what it
removes is left apart. zbb_like's ALU now shares nothing and is 8% smaller
synthesised; the RISC-V ALUs are unchanged.

Six decisions are few, and all of them ALUs. The margin is where the evidence
puts it, not where a larger sample would.

⚠️ Sharing RV32I's adder saves 12% of the ALU and makes it 46% deeper
synthesised -- 38 gate delays against 26 -- because seven instructions'
operands now pass a mux before the adder and their results another after it.
The model sees that too (41 against 33). The merger weighs it against a cycle
when a core states one (§3.2), and otherwise only area.

Two things the sweep says about the netlists rather than the model: count of
leading zeros is a priority chain whose depth is linear in the width (31 gate
delays at 64 bits), and a signed double-word multiply costs 8% to 30% more
than the unsigned one because both operands are extended to twice their width.

### 5.3 The measurement had a defect of its own

PyRTL 0.12's Verilog export folds a net read once into its reader's
expression. Verilog sizes an operand of a concatenation by itself, so a
one-bit `a + b` that PyRTL made two bits wide comes out one bit wide again:
`CPOPX` synthesised as a parity tree, a third of the size of the population
count it is. `tools/hw_synth.py` writes the Verilog itself, a declared wire
and one assignment per net. PyRTL's own simulation, which every other hardware
gate uses, does not go through the export and was never wrong.

Mapping uses Yosys's liberty script without `dc2`, which restructures for area
and takes the prefix adder apart: a 64-bit add 10% smaller and three and a
half times slower. ABC is also not quite repeatable -- a unit's area moves a
few percent between runs of the same circuit written in a different order --
which is why the bands have headroom.

## 6. Where a proposer plugs in

The grouping of §3.1 and the binding of §3.2 are greedy heuristics over a
search space. Better answers exist: a different select encoding simplifies the
decode, a different binding order shares more, a unit split in two meets a
cycle a merged one does not.

A proposer -- a search, a learned cost model, a language-model harness -- may
choose any of them, because of §3.3: **a proposer can be wrong about what is
small and never about what is computed.** Everything it produces goes through
the same construction and the same gate. It proposes; it does not judge.

That rule is the reason the correctness-bearing part (lowering, rebuilding a
node over an instance, the extension rules) is deterministic code with a gate,
and the part handed to search is the part where a bad answer costs area and
nothing else.

### 6.1 The door (H2a)

```
axis emit-hw-plan examples/rv32i.axisl -o own.plan          # what AXIS would build
axis emit-hw-json examples/rv32i.axisl --hw-plan my.plan    # what MY plan costs
```

```
(hw-plan
  (unit alu (sharing when-it-pays) (members ADD SUB XOR ...))
  (unit muldiv (sharing always) (members MUL MULH DIV REM ...)))
```

A plan says which instructions share a unit and how eagerly their operators
are shared -- `when-it-pays`, the cost test of §3.2; `always`, whenever it is
legal; or `never`, every operator its own -- and nothing about what any
instruction computes. `--hw-plan` is
taken by `emit-hw-pyrtl`, `emit-hw-json` and `emit-hw-smt2`, and by both gates
as `--plan`.

A plan is refused, by name, for what would make it a different machine: an
instruction with no circuit, an instruction in two units, an instruction with a
circuit left out, two latencies in one unit. It is never refused for being
bad. `examples/hw_plans/rv32i_muldiv.plan` puts RV32I's multiplier and divider
in one unit, which share nothing; it comes out slightly larger than the two
apart, passes the simulation gate, and proves exactly what AXIS's own plan
proves. A proposer reads the cost from `emit-hw-json` and tries again.

## 7. Staging

- **H1 — the netlist.** _Done._ `src/hw.rs`, `emit-hw-pyrtl`, `emit-hw-json`,
  `emit-hw-smt2`.
  Demand-width lowering of the integer operators and `deffun` calls into the
  primitives of §2.1, rewrites in the builders, a cost model, declines by name.
- **H1a — instructions stated as effects.** _Done._ Branches, jumps, loads and
  stores as one node per value, guard and address; the program counter and the
  loaded value as inputs. §2.5.
- **H1b — reference bodies and state.** _Done._ An operator the IR does not
  carry is lowered through the `deffun` a description states for it; state
  reads are inputs and state writes effects. §2.5, §2.6.
- **H2 — functional units.** _Done._ `src/hw_units.rs`. Grouping by declaration
  or by rule and cost; operator binding with the no-loop and low-bits rules;
  merged units emitted beside the per-instruction netlists; the simulation gate
  and the proof gate.
- **H2a — a plan from outside.** _Done._ `--hw-plan` and `emit-hw-plan`: the
  units a proposer names, validated and built by the same construction. §6.1.
- **H3 — time.** _Done._ Each unit is also emitted pipelined
  (`build_unit_<name>_pipelined(valid, sel, ...)`), with one register fewer
  than the cycles its instructions declare -- the latency the cycle simulator
  charges. See §3.4.
- **H4a — an existing core's extension slot.** _Done._ URV, PCE's out-of-order
  RISC-V core, dispatches custom-0 instructions from a registry that
  `register_from_adl` fills from an ADL bundle -- encodings from the bundle,
  and for the hardware "the integrator provides the callables".
  `extension_semantics(xlen)` in the emitted module is that map. The gate
  (`tools/hw_urv_check.py`) has nothing of AXIS's on PCE's side: PCE's loader
  reads `emit-bundle`, PCE's `URVExtensionUnit` is elaborated unmodified with
  PCE's PyRTL, each instruction is issued by its real opcode and function
  fields, and what arrives at the completion port is compared with the golden
  model. zbb_like's eleven instructions run there.
- **H2c — units with effects in them.** _Done._ Branches, loads, stores and
  flag-writing instructions as members of units, beside values, each output a
  named slot. A separate artifact. §3.5.
- **H2b — the cost model, calibrated.** _Done._ Fitted to Yosys and ABC on an
  open cell library, and held to it on operators, instructions and units by
  `tools/hw_calibrate.py`. Known bits, demanded bits and what a mux tree brings
  in are read from the graph to price what synthesis leaves. §5.
- **H4b — the slot, shared.** _Done._ here; in PCE it is a drafted patch, not
  applied. URV's unit calls each extension's semantics on its own and muxes the
  results, so what H4a plugs in is eleven circuits, not the merged unit of H2.
  `extension_datapath(xlen, mnemonics)` is ONE datapath over the merged units:
  it takes the unit's own match wires, which a dispatcher already has, and
  makes the units' select and operand muxes from them. For the unit to call it,
  `URVExtensionUnit` needs a `shared_semantics` hook --
  `tools/pce_patches/urv_extension_unit_shared.patch`, some twenty lines. The
  gate applies that patch to a *copy* of PCE's unit in its scratch directory
  (PCE's tree is only read), runs zbb_like's eleven instructions through both
  forms against the golden model, and counts both in gates. Where AXIS shares
  an operator between the instructions the shared form has to be smaller;
  zbb_like's unit shares none (§5.2), so there the two are the same circuits
  behind different muxes and no saving is claimed.
- **H5 — a pipeline**, and **H6 — search.** Building a core around the units --
  decode, register file, operand select, bypass -- and the proposers of §6 are
  not part of this repository. What AXIS provides them is what is above: the
  netlist, the units, the plan, and the `Sharing` seam a proposer drives.

## 8. What this is not, yet

* **No architectural state beyond registers, the pc and plain memory.** Traps,
  atomic stores, CSR-like state and anything floating-point are declined by
  name. On RV32I that is 33 effect instructions built and 176 not.
* **No floating point**, and nothing 128 bits wide that needs a carry: the
  graph holds values in 128 bits and an adder's carry is one more. On the
  AArch64 seed that declines 587 instructions and builds 309.
* **The divider is unrolled**, sixty-four subtractors cut into as many stages as
  the description declares cycles. An iterative divider -- one subtractor,
  many cycles, busy while it runs -- is not built, and neither is the
  valid/ready handshake a unit that can be busy needs.
* **The merged ALU is deeper than its slowest member** -- 47 gate delays against
  25 on RV64I (4.7 ns against 2.5 in the reference library), just over the 45
  the grouping rule calls a cycle. The result mux has some forty inputs because
  `ADD` and `ADDI` are different circuits: one reads `rs2` and the other a
  sign-extended immediate. A core resolves that in operand select, before the
  unit. Here it is inside the unit, and moving it belongs to whatever builds
  the core around it.
* **The merger weighs depth only against a cycle a core states** (§3.2); with
  none it weighs area, and its area margin rests on six measured decisions.
* **Ports are operand names.** `rd`, read by the compressed forms, is a port of
  its own beside `rs1`.
* **The PyRTL is simulated, not proved.** The proof is of the graph; the
  Python that builds each primitive is held to it by simulation alone.
* **Accelerators** (`defaccelerator`) are not lowered. `emit-pyrtl` still builds
  them.
