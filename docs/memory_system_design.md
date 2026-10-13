# The memory system — described once, simulated here, generated in AHA

Status: **MS1–MS5 implemented.** Companion to `docs/arch_packs.md` §7d, whose
single-level cache this replaces as the thing a machine runs against.

## 1. Why

The pack's timing model has one cache: size, ways, line size and what a miss
costs, one level, LRU, no write policy, no coherence (`cache_check.py` says so).
It can tell a working set that fits from one that does not, and nothing more.
Meanwhile AHA — the consumer AXIS exists for — builds real memory fabrics:
`hardware/noc_ip/ip_gen.py` generates a mesh NoC from a `NoCIPConfig`,
`aha/chi/ip_gen.py` and `build_chi_node` a proof-carrying CHI coherent
interconnect from a `ChiIPConfig`, and `aha/dram` a DDR controller from a
`JedecTiming` profile. What AXIS gives AHA about any of it today is one word:
`synthesis_noc_topology` is `mesh` or `crossbar`, and the data width is a
constant 64 in the loader.

So a machine's memory system is written in three places that do not know about
each other — a host's `configure_cache` call, AHA's Python configs, and
nowhere at all for the levels, the coherence and the address map. This design
puts it in one: the description.

## 2. The forms

Three, all machine-side, in the language's existing idiom.

**`defmemory`** already said what a memory is. It now also says how a cache
*behaves* and what a DRAM *is*:

```lisp
(defmemory l1d (kind cache) (size-bytes 4096) (line-bytes 64) (ways 4) (latency-cycles 2)
  (replacement lru) (write-policy write-back) (allocate write-allocate) (mshrs 4))
(defmemory l2  (kind cache) (size-bytes 65536) (line-bytes 64) (ways 8) (latency-cycles 12)
  (replacement plru) (inclusion inclusive) (prefetch next-line) (prefetch-degree 1))
(defmemory ddr (kind dram) (size-bytes 0x80000000) (banks 32)
  (standard ddr5-4800) (channels 1) (ranks 1) (row-bytes 8192) (page-policy open)
  (timing (tck-ps 417) (tcl 40) (trcd 39) (trp 39) (tras 77)))
```

⚠️ A policy on a memory that is not a cache is refused, as is DRAM geometry on
anything but `(kind dram)`: a scratchpad with a replacement policy describes a
structure it does not have. A DRAM declares its timing in its own cycles; the
`standard` is a name a consumer with its own profile of the part resolves, and
a gate holds the two to each other.

**`definterconnect`** is the fabric:

```lisp
(definterconnect mesh3 (topology mesh (rows 3) (cols 3))   ; mesh | torus | ring | crossbar
  (virtual-channels 2) (buffer-depth 4) (flit-bits 64) (address-bits 48)
  (hop-cycles 1) (router-cycles 1))
```

**`defmemsys`** places instances of memories on it and says what is coherent:

```lisp
(defmemsys cluster
  (interconnect mesh3)
  (coherence (protocol moesi) (credit-depth 4) (txn-id-bits 8) (node-id-bits 7)
             (table-depth 4) (features retry qos))
  (nodes
    (c0-l1d (memory l1d) (core cpu0) (at 0 0) (next l2))
    (c1-l1d (memory l1d) (core cpu1) (at 2 0) (next l2))
    (l2     (memory l2) (at 1 1) (next ddr0) (home))
    (ddr0   (memory ddr) (at 1 2))
    (spm0   (memory spm) (at 0 2)))
  (address-map
    (region 0x0 0x80000000 ddr0 (home l2))
    (region 0x80000000 0x10000 spm0 (uncached))))
```

A node is an *instance*: two L1s are one `defmemory` placed twice. `(at x y)`
is column and row; a node's id is `y × cols + x`, which is how both AHA's NoC
routers and a CHI home-node id count, so no lowering renumbers anything.
`(next …)` is the level a miss goes to; an endpoint has none. `(home)` marks
a directory. A region maps an address range to the endpoint behind it and,
under a coherent protocol, to the home that orders it — or says `(uncached)`,
explicitly, so a forgotten home is still an error.

What validation refuses, each because a consumer would otherwise have to guess:
a cache with no next level and an endpoint with one; a chain that loops; two
line sizes in one system (a coherence unit is one line); two nodes at one
place (the fabric's address decode would be ambiguous); a node outside the
topology; overlapping, unaligned or out-of-range regions; a region at a cache;
a coherent region with no home, or a home that is not a directory; more places
than the node-id width can name.

## 3. The manifest: `axis.memsys.v1`

`emit-memsys-json` publishes every system **resolved**: node ids and
coordinates, each node's memory with its geometry and policy (defaults made
explicit — `lru`, `write-back`, `write-allocate`, `nine`), hop counts to the
next level on the declared topology, each core's path from its L1 to memory,
and the address map with target ids, target coordinates and home ids. A
consumer reads decisions, not rules to re-derive.

## 4. The lowerings

| AHA generator | Built from |
|---|---|
| `NoCIPConfig` (mesh NoC, NIP.4) | rows/cols of the topology; VCs; buffer depth; `address_bits`; `flit_bits`; one `AddressRegion(base, size, x, y)` per region at its target's place |
| `ChiIPConfig` (CHI IP, CHI-WIDEN.GEN) | node-id / txn-id / address / data bits; credit and table depth; features (the protocol's own — `moesi` — plus those declared); one `HomeRegion(base, size, home_id)` per coherent region |
| `Topology` (CHI DCT mesh) | kind and size of a square grid; the home node's id |
| `MoesiConfig` / `CoherenceConfig` | the number of private caches under the protocol |
| `JedecTiming` profile | the DRAM's `standard`, held against its declared timing |

Each lowering is a function of the manifest alone, and each is held by a gate
that runs AHA's own code on it: its address decoders must send every region
boundary where the description does, its proofs must pass at the generated
configuration, and a declared DRAM must have its standard's timing.

## 5. Stages

- **MS1 — the forms.** `defmemory` policy and DRAM, `definterconnect`,
  `defmemsys`, with the validation above and an `emit-lisp` round trip.
- **MS2 — the manifest.** `emit-memsys-json`, and a gate that checks it
  against the description by an independent reading.
- **MS3 — AHA.** The lowerings in §4, a tool that writes the configurations
  and runs AHA's generators on them, and the gate that holds the two sides
  together.
- **MS4 — the simulator's hierarchy.** Multi-level caches with the declared
  replacement, write and allocation policies and inclusion; DRAM with row
  buffers per bank and the declared timing; the interconnect's hop latency.
  Held against a reference model by trace, and by mutation.
- **MS5 — coherence.** Several machines attached to one memory system, a
  directory at each home running the declared protocol, SWMR checked on every
  transition. No transient states or races: one access completes before the
  next begins.

## 5a. What was built, and what holds it

- **MS1–MS2** — `src/memsys.rs`: the forms, their validation, `emit-memsys-json`
  and the `emit-lisp` round trip. `memsys_check.py` reads the description a
  second way and compares every resolved field, then makes each of twenty
  refusals happen once by a one-line edit of the example.
- **MS3** — `tools/memsys_aha.py` lowers a system into AHA's configurations
  and, with `--out`, runs AHA's generators: the NoC and CHI IP datasheets (with
  their proofs at this configuration), the composed CHI node and the
  address-routed mesh as Verilog. For the example every AHA proof passes —
  link no-overflow, one-hot allocation and XY deadlock-freedom on the 3×3×2VC
  mesh; the CHI link, transaction, bridge, directory, MOESI, QoS, retry and
  routing proofs. `memsys_aha_check.py` holds the lowering against AHA's own
  decoders (the NoC one simulated), hop metric, MOESI proof and DDR5 profile,
  and requires three perturbations of it to be caught. ⚠️ AHA's composed CHI
  node takes its cache and master counts from constants of its own (3 and 3),
  not from its configuration, so that one netlist does not yet reflect the
  description's two private caches; the MOESI proof does.
- **MS4** — `src/emit/memsys_engine.c`, the timing engine, with the contract
  at its head; `tools/memsys_model.py`, a second reading of it. The pack
  includes the engine and the description's tables; selecting a core that is
  a port of a system attaches a fresh engine, and every load and store is
  charged **what it costs beyond a hit in the port's own level** — the
  instruction's declared latency already covers that much. Four new entries
  at the end of `axis_sim_pack` report the system and each node's ten
  counters. `memsys_sim_check.py` holds engine to model access by access over
  ten configurations (every replacement, write and allocation policy, both
  inclusions, closed page, four topologies) with three engine mutants;
  `memsys_pack_check.py` holds the pack: a trace leaves every counter where
  the model does, and a load/store loop on a port core costs exactly the
  model's stalls more than on its twin in no system.

- **MS5** — coherence. Under `msi`, `mesi` or `moesi`, the ports hold a
  state per line and the home is an exact directory over the peer ports that
  pass it; the costs of a forward, an upgrade and an invalidating write miss
  are written into the engine's contract in terms of the fabric's one-way
  hops. Validation requires what the contract assumes: every port reaches its
  region's home; a coherent port is write-back, write-allocate and does not
  prefetch; a home is not exclusive. The model checks the single-writer
  invariant after every coherent access. `memsys_join(machine, other)` lets a
  machine share another's system at its own core's port, reference-counted,
  which is how two simulated cores become coherent with each other. Held by
  the engine-versus-model gate over all four protocols (a trace that makes
  lines change hands, and one that hands a line to sharers only, which is the
  only way to tell a granted E from a granted S), and by the pack gate's
  joined run: two machines in lockstep over the same lines leave every
  counter where the model does. ⚠️ Their cycles are held to a RANGE: a stall
  delays an instruction's completion, so a load's shows in full and a
  store's only as far as in-order retirement lets it -- the pipeline's policy
  (`arch_packs.md` §7d), not the memory system's.

## 6. What this is not

The timing model stays **correct-path and trace-driven** (`arch_packs.md` §7d):
wrong-path accesses are not made, so their cache pollution is not seen. A
fabric's contention is modelled as the hop latency the topology implies, not
as flits competing for buffers — that is AHA's RTL's to know, and a number
this model made up about it would be a second, unmeasured claim. What the
description adds to AHA is configuration, not a netlist: the generators are
AHA's, and so are their proofs.
