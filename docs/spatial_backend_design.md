# Shared spatial execution backend: AXIS timing-model candidates

**Status (2026-10-02): design hypotheses, not implemented AXIS syntax, simulation results, RTL, or an admitted URV SKU.** This record keeps the alternatives together so that AXIS's cycle-level simulator can reject them before an RTL choice. It concerns backend organization; AXIS instruction semantics remain the functional oracle.

## Question

Can several architectural contexts use one spatial pool of execution units, including a vector unit whose lanes also execute independent scalar operations, and gain useful work per area and joule after paying for operand movement, ports, scheduling, fairness, and recovery?

A context may be a URV SMT hart or an independently owned frontend. An accelerator command is a separate possible producer with a different completion contract. The contexts retain their own architectural state, precise retirement, exceptions, and memory-ordering ownership. The backend only executes tagged work and returns results. This is different from the current AXIS `defabric` relation in which a VLIW packet and a spatial array share a row but run in mutually exclusive modes (`src/ast.rs`, `Fabric::mode` and `vliw_row`). The proposed backend allows *simultaneous, disjoint allocation of physical lanes* to scalar and vector work.

The Michaud/Mondelli/Seznec wide-cluster study motivates distributing issue and register access, but its two-cluster topology, 64-instruction block steering, and tolerable three-cycle crossing delay are candidates to test, not URV parameters: https://doi.org/10.1145/2800787 .

## Observations that constrain the experiment

- AXIS already describes `defcore` issue width, units, ports, finite OoO windows, rename, LSQ, branch/front-end behavior, and an execution-driven timing path (`docs/arch_packs.md`, `docs/ooo_design.md`). It has no declared shared-unit topology, per-context arbitration, lane group allocation, or scalar/vector concurrent ownership. Adding unit counts alone would model duplicate resources or zero-cost sharing.
- PCE's URV study measured W1/W2/W4 ready supply on a controlled ILP ladder, but the W8 preset sustained 2.29 IPC on ILP-8 code. Its four compiled residue kernels improved only 1.064–1.15x from W1 to W4. Those are workload- and model-specific observations, not predictions for this backend; they demand a front-end-supply baseline before attributing a result to shared execution (`pce/docs/AHA_URV_FEDERATION_DOCTRINE_ADDENDUM_20260828.md`, `pce/docs/BACKLOG.md`, 2026-09-30).
- PCE's existing URV vector path is gated and VLEN=256, with a vector physical register file, a single vector issue path, elementwise arithmetic, masks, slides, and reductions (`pce/hardware/urv/README.md`). Replacing its current execution structure with grouped lanes is a new architecture candidate. The named `urv-linux-rv64imac-1w` product does not include V, so this cannot be described as an improvement to that frozen SKU.

## Physical organization candidates

All arms must use the same total execution units, comparable total window and register capacity, and the same memory service envelope. Different routing and port structures are part of each arm's charged cost.

| Arm | Execution ownership | What it tests |
| --- | --- | --- |
| A: private | Four independent W2 contexts with private integer/branch/LSU and dedicated vector hardware | No-sharing reference; counts idle units as physically present. |
| B: wide SMT | One W8 shared window/backend serving four harts, with admission/fairness controls | Pooling without spatial distance; compare against a credible fixed wide core. |
| C: specialist pool | Nearby scalar ALU/branch/LSU per context; shared MUL/DIV/FP/custom/vector units | Whether expensive, intermittent units alone justify sharing. |
| D: elastic islands | Multiple local issue queues and execution islands, with remote issue or result forwarding | Whether idle general-purpose units can be borrowed after crossing costs. |
| E: fracturable tile | Four 64-bit lanes form one 256-bit vector group or four independent RV64 scalar slots | Whether vector idle time can become scalar throughput. |
| F: partial grouping | A vector request owns one/two/four lanes; unused lanes may execute scalar work | Whether mixed ownership outperforms whole-tile reservation after port and completion costs. |
| G: command producer | Typed accelerator/microcode requests compete for eligible lanes with instruction contexts | Whether sharing survives a distinct completion and cancellation policy. |
| H: redundant use | Spare lanes duplicate selected operations for comparison | Whether low-demand capacity has useful RAS value; not a throughput claim. |

Arm E first fractures *lane ownership*, not arithmetic width. A 64-bit scalar ADD needs correct RV64 carry and result semantics. Two packed 32-bit additions require carry isolation and independent destination tags if they are separate instructions. Narrow FP fracture requires its own rounding and exception behavior. Treat these as later, explicit subword variants. A physical vector tail or masked lane is not automatically free to scalar work: it can be lent only when register ports, result routes, mask/tail semantics, and completion tags are independent for that beat.

## Execution and ownership contract to model

1. A request carries producer kind, context and security domain, owner ROB/command tag plus generation, operation class, source locations/values, destination, vector element range and mask if applicable, and whether it may cause a fault or side effect. This is a *candidate timing-model record*, not an accepted AXIS language form.
2. A scalar context owns rename, precise traps, retirement, and memory order. A returned result may wake dependents only if its generation still matches; a redirect invalidates younger work from that context without canceling another context. Commands need an explicit completion/error acknowledgement rather than borrowing ROB semantics.
3. Branch resolution and ordinary loads/stores remain local in the first arms. Sharing LSQ segments, MSHRs, or cache bandwidth is a **separate** experiment: memory capacity may be worth more than extra ALUs, but global ordering, coherence, and side effects must be modeled and charged.
4. Local bypass and remote delivery have different latency and energy. The model must charge source operand reads, lane-input selection, inter-island hops, result transport, writeback ports, and queue occupancy. A remote operation cannot use a local-bypass latency by assertion.
5. A vector operation reserves a set of lanes for a specified number of beats and completes as one architectural instruction. Reduction and slide consume declared cross-lane links. A scheduler may lend unreserved lanes to scalar work; reserved lanes cannot be double-booked. A long vector operation needs a bounded scalar service policy, while scalar pressure must not starve a reserved vector group.
6. Admission policy is an independent variable: fixed per-context shares, work-conserving oldest-ready, ICOUNT-like pressure, a local-first remote-spill rule, and phase-level reservations are candidates. Record accepted, rejected, and stalled requests by context and reason; do not infer fairness from aggregate IPC.

## Minimal AXIS model increment

Keep ISA effects, instruction latency, and unit class definitions where they already live. Add backend structure to the machine/timing side, with a versioned exported representation and validation. The first increment should model a shared specialist unit across two contexts: finite request/result bandwidth, local versus remote latency, context generation, and guaranteed progress. Make the old single-core model the one-context, zero-distance case and require cycle-for-cycle equality there.

Then add spatial islands and lane-group reservations. A 256-bit tile can initially be four 64-bit lanes; one vector instruction claims all four, or four independent scalar instructions claim one each. Only after this works should two-lane groups and same-cycle vector/scalar overlap be added. Input and output bandwidth are independent resources: four arithmetic lanes do not imply eight scalar-register reads or four writebacks. Use explicit bank/port counts and refuse an unserviceable configuration instead of assuming ideal crossbars.

The existing `defabric` mapper and mode exclusivity remain valid for their current packet/CGRA use. A backend-sharing construct must name its relation to physical PEs without silently relaxing that exclusivity. A description that allocates one PE twice in a cycle must be rejected. Syntax such as `shared-backend`, `island`, or `lane-group` is *illustrative only* until AXIS validation, export, and simulator consumers agree on a schema.

## Falsification workloads and counters

Run the same compiled programs and initial architectural state on every arm. Include independent scalar chains; dependent chains; branch-heavy and miss-heavy code; vector elementwise, masked/tail, reduction, and slide kernels; mixed vector/scalar phases; four homogeneous harts; heterogeneous harts; and one latency-sensitive foreground context with background work. Include short and long phases, since a phase-level allocation can lose its benefit to transition cost. A trace-only mode can bracket an answer, but execution-driven runs and the generated functional oracle must check results and wrong-path/recovery behavior.

Report per-context retired work, aggregate useful work, dependent-stream latency, tail latency, FU/lane occupancy by *useful* operations, remote-hop and operand bytes, port stalls, vector reservation waste, starvation interval, mispredict/replay waste, cache/MSHR pressure, and modeled activity. State the exact clock/area assumption. At this stage, cycle counts and activity are model outputs; ASAP7 synthesis and post-layout frequency are later independent evidence, not numbers the simulator can manufacture.

The decisive comparisons are C versus A (specialist sharing), D versus C (general-purpose borrowing), E versus dedicated scalar+vector at equal resources, and F versus E (partial grouping). B is a necessary fixed-wide baseline throughout. Sweep crossing latency, lane count, vector fraction, input/output ports, queue depth, and fairness policy; show sensitivity rather than selecting one favorable point. Stop a candidate if its gain disappears under a plausible crossing/port cost, if one context's tail or progress bound fails, or if it wins only by assuming frontend supply that the measured URV cannot deliver.

## Model gates before RTL

- **Conservation:** no unit, issue port, lane, register port, or result path serves two incompatible requests in the same beat. A deliberately double-booked model must fail.
- **Ownership:** redirecting one context cancels its younger in-flight requests and cannot alter another context's architectural state. Delayed stale results must be dropped.
- **Vector completeness:** every active element executes once; mask/tail policy and reduction/slide order match AXIS semantics; a partial group cannot publish a whole-vector result.
- **Progress:** under stated finite service and credit assumptions, each admitted context receives bounded service; a saturated scalar context cannot indefinitely block a vector group, or vice versa.
- **Accounting:** zero-distance single-context reproduces the existing model; adding crossing delay cannot accelerate a dependent remote chain; reducing a bank/port count cannot increase available issue bandwidth; identical dedicated resources produce the same architectural result.
- **Evidence:** each sweep binds the exact AXIS description, simulator revision, workload hashes, model assumptions, and negative controls. Keep MODELED results separate from URV RTL measurements and physical PPA.

This record is an accumulation point. New variants should add a mechanism, its additional physical resource/port cost, a workload expected to benefit, a workload expected to falsify it, and the exact simulator capability needed. No arm is selected for RTL by this document.

## First timing increment: shared specialist unit (2026-10-02)

`tools/shared_backend_model.py` is a **separate operation-stream timing kernel**. It consumes versioned `axis.shared-backend.v1` JSON, including context-local dependencies and a declared unit/port/queue topology. It schedules either private copies or one shared pool with the same total unit count. Input and output routing delay, finite request and result ports, pipelined versus nonpipelined initiation, finite inbound queues, and round-robin context service are charged. Its result is `axis.shared-backend-result.v1` with per-operation timestamps and per-context stalls. `examples/shared_backend_v1.json` is a runnable specimen; `python3 tools/shared_backend_model.py examples/shared_backend_v1.json` prints its trace.

This is not yet the generated simulator's timing engine or a registered `axis_uarch_pack`. The current external model event (`axis_uarch_event` in `src/emit/encode.rs`) represents one retired instruction and carries **no context identity or shared cycle clock**. Two independently stepped simulator instances cannot express simultaneous contention through that ABI. The standalone stream kernel makes the resource and arbitration experiment executable while the multi-context host/event boundary is designed; its inputs are synthetic operation streams, so its counts are MODELED bounds, not compiled-program or URV performance evidence. It models one unit class only, and has no frontend, local ALU, ROB, LSQ, branch recovery, vector semantics, area, clock, or power.

`python3 tools/shared_backend_check.py` checks equal-resource skew and balanced cases, dependent-chain routing cost, request/result port bottlenecks, bounded service on two saturated streams, refusal of invalid private resource partitions and forward dependencies, and trace-level conservation. On the fixed synthetic gate, private/shared cycles are 25/14 with one busy context and 25/25 when both are busy; a four-operation dependent chain is 16 cycles at zero route delay and 28 with two cycles each way. These figures demonstrate model behavior only. The next AXIS increment needs a context-tagged event source and synchronized multi-context host before any compiled workload can validate the sharing hypothesis. A grouped-lane resource experiment can precede that seam; compiled-program validation and vector semantics still depend on it.

## Second timing increment: atomic lane groups (2026-10-02)

The same operation-stream kernel now accepts `lanes` per operation (default one). A width-N operation reserves N **adjacent** physical units at once; its one completion is returned through one result port. Disjoint one- and two-lane requests may start in the same beat. If an arrived group cannot fit, the conservative scheduler holds younger work for that beat rather than continually fragmenting the tile. Request admission and unit-issue round-robin cursors are separate: sharing one cursor initially let a continuing scalar stream reset vector priority each cycle and starve a full-width group until the scalar stream ended. The saturated negative case is retained in `shared_backend_check.py`.

`examples/fracturable_backend_v1.json` runs the grouped-lane case through the same CLI. The gate now checks nine property groups. With four modeled lanes, a two-lane request and a scalar start together at cycle 0 on separate lanes; a full-width request released at cycle 2 amid twenty scalar requests starts at cycle 3 and exclusively owns all four lanes that beat. These are resource-scheduler observations, **not RVV functional execution**. The model does not yet charge scalar/vector register-file banks, element masks, tail policy, per-element arithmetic, slide/reduction links, or precise vector completion. Until those are explicit, an unused masked element cannot be advertised as a free scalar slot, and no useful vector/scalar speedup can be claimed.
