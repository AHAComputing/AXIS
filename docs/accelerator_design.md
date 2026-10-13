# AXIS Accelerators — the AHA engines, and a launch that reads its descriptor

Status: **H1 (H1a–H1c), H3, H3b, S1, S2a–S2c and S-ASL implemented.** H2 withdrawn (below). Companion to `docs/tensor_design.md`, whose
T8 built kernels and deferred "launch by descriptor" for want of a consumer.
This document is that consumer arriving. Every finding in §3 was measured on
this host before anything was built.

## 1. Why now

`docs/tensor_design.md` §1 ended on Gap 3 — an engine that is not an
instruction — and on the honest statement that nothing read what AXIS would
say about one. That is no longer true. PCE's `aha/isa/adl_loader.py` already
loads `accelerator_descriptor_manifests.json` from an AXIS bundle and maps each
accelerator's `descriptor_schema`, `descriptor_bytes`, `launch_abi`,
`completion`, `mmio_base`, `mmio_size` and `coupling` into AHA's coupling tiers
(`tightly_coupled` → tight, `queue_descriptor`/`loose` → loose, `stream` →
stream). What it reads are **names and counts**: a schema is a string, a
descriptor is a byte count. Nothing says where a field is, what the engine
refuses, or what it computes.

## 2. The inventory

About twenty engines, most of the concrete ones defined in
`pce/hardware/accel_engines/` and built through
`aha/compute_core/accel_factories.py`. Every one is driven in one of four
ways, and the four map onto different parts of AXIS:

| Driven by | Engines | AXIS today |
|---|---|---|
| **custom instructions** | XNN custom-0 (`MATMUL`, `MATMUL_ACC`, `MATADD`… in funct7, operands fixed in a0/a0/a1 — `software/xnn-sdk/asm/xnn_custom.S`); GRV warp tensor MMA, 2:4 sparse, MXFP8 | instructions, tile state and kernels already carry these |
| **a descriptor in memory** | XNN grid (32 B, 8 words, error codes 0–7 — `xnn_grid_descriptor_ingress.py`); Bio (68 B, 17 words, magic `0x42494F31`, `status_ptr` — `aha/verticals/bio/queue_abi.py`); NIC/PCIe rings; bridge `LaunchPort` | `defaccelerator` names the descriptor; **nothing reads it** — §3 |
| **an MMIO register map** | XNN MMIO, FlexMAC, DotProduct, PCE DMA, MCU DMA, IMC tile | **missing**: registers whose writes do something (kick, write-1-to-clear) |
| **streams** | SHA-256, AES/XTS/GCM, PQC NTT stream | **missing**: AXIS sends and does not receive, deliberately (tensor §12) |

The descriptor row goes first because it has a reader.

## 3. The premise, tested

A descriptor launch was written by hand as an ordinary behavior before any
design: `BIO_LAUNCH rs1` reads the descriptor at `rs1`, checks the magic, the
ABI version and a count, doubles `param0` words from `input_ptr` into
`output_ptr`, and writes a status code to `status_ptr`. It is refused, and
bisecting says exactly where:

- **A store's address may not read memory.** `(store (load i64 unsigned (add
  i64 rs1 64)) 7 i32)` fails with "unsupported formal_semantics operator
  `load`". A store *value* may load since T8b; an *address* may not. But
  "write where the descriptor says" is what a descriptor is: `output_ptr` and
  `status_ptr` are both read from memory.
- **A guard may not read memory.** `(when (eq (load i32 unsigned rs1) 5) …)`
  fails the same way. Validation (`magic == 0x42494F31`) and a count held in
  the descriptor (`i < param0`) are both guards over loaded values.
- **A typed guard comparison was refused with the wrong reason.** Guards
  compare untyped — `(ult i (load …))` — and the probe wrote `(ult i32 i …)`,
  the spelling every value uses. The refusal said "behavior guard must be a
  binary comparison", which read as though the `and` around it were the
  problem; it was not, and it now says what is.

Everything else in the probe elaborates: loads inside a stored value, inside a
`select`, a bounded `iterate`, a guarded store per element.

So the gap is not a new construct first. It is the same wall T8b removed for
values, standing at the two other places an effect evaluates an expression.

## 4. Stages

- **H1a — memory reads in addresses and guards.** _Done._ A store's address
  and a guard now read memory as a value could since T8b: the validator
  rewrites their loads to symbols, `annotate` records a machine-wide load
  address width for each, and the effect fixture publishes
  `guard_load_address_width` when a guard loads — only then, so every other
  fixture is unchanged.

  **Every load an effect names is performed, once, in order.** The first run
  of the probe through the C simulator disagreed with the Python executor on a
  bad-magic descriptor: C's `&&` read the magic, saw it wrong and stopped;
  Python read the magic, the version and the count. Both answers were right
  and the traces were different traces. C also leaves the order of `a + b` to
  the compiler, so an effect with two loads had matched the Python trace by
  habit. The wide C and Rust executors now **hoist** an effect's loads into
  sequenced temporaries — innermost first, left to right, the guard's before
  the `if` and the address's and value's inside it — and render each at its
  use exactly as the inline read was rendered, so no value changes, only the
  order is now a rule. The rule is the Python executor's and the validator's
  numbering; it will matter more than tracing once a read can have an effect
  of its own (H3's MMIO registers).

  **An injection that passed.** Dropping `guard_load_address_width` from the
  Python executor changed nothing at first: every guard in the corpus compared
  at 64 bits, where masking its loads' addresses to the guard's width is the
  identity. A flag test compares a byte, so the corpus now has one — Bio's
  `flags` bit 0, "notify", copies `job_id` beside the status — and the same
  injection reads the flags from `base & 0xff` and fails. The descriptor sits
  above 2³² for the same reason.

  Both generic executor gates now seed the cells a guard and a store's address
  read, not only a value's; they still only ever see random memory, which no
  magic check accepts, so the valid path is held by the corpus's own gate.

  Corpus `examples/descriptor_reads.axisl` (Bio-shaped, written by hand); gate
  `tools/descriptor_reads_check.py`: 24 descriptors — valid, bad magic, bad
  version, count too large — through the Python, wide C and wide Rust
  executors against a reference written from the layout; the order of a
  failed guard's reads; nothing read past a failed guard. Injection-checked
  three ways. LLVM and the SMT path decline these effects by absence, as they
  do `nested_loads`; `sim_vs_executor` holds the compiled trace order.
- **H1b — the descriptor, declared.** _Done._

  ```lisp
  (defdescriptor bio_v1
    (bytes 68)
    (fields (magic 0 i32) (abi_version 4 i32) … (status_ptr 64 i32))
    (check (eq magic 1112100657) 1)
    (check (eq abi_version 1) 2)
    (check (ult param0 9) 3)
    (status status_ptr i32))

  (definstruction bio_double …
    (launches bio_v1 rs1 double_words output_ptr input_ptr param0))
  ```

  A launch binds a kernel's params to fields (or to operands and literals)
  and its behavior is **derived**: each field becomes its load from the base
  operand plus its offset, every kernel statement is guarded by every check,
  and one status write follows — the first failing check's code, or 0. A
  `when` takes one statement and guards do not nest, so the checks are
  *distributed*: pushed through an `iterate` into its body and conjoined with
  a statement's own guard. An instruction that launches may not also state a
  behavior; there is no second copy to hold it to, so writing one is refused
  rather than silently preferred.

  Everything a launch relies on is checked once, at the declaration: fields
  inside the block, aligned and disjoint; checks that read only fields;
  status codes that are nonzero, distinct, and fit the status width; a status
  written through a field. The manifest publishes a `descriptors` section —
  layout, checks, status, launchers — and each launch; both only when a
  document has one.

  **Declaring is transcribing.** H1a's `BIO_LAUNCH` was written by hand and
  H1b's `BIO_DOUBLE` is derived; on the same descriptors they leave the same
  memory, which the gate checks.

  Corpus `examples/descriptor.axisl` (Bio's full 17-field layout, two kernels
  binding different fields); gate `tools/descriptor_check.py`: both launches
  on three executors against Bio's engine in Python, declared against
  written, fourteen refusals each for its own reason, the round trip, the
  manifest. Injection-checked three ways.
- **H1c — AHA's two descriptors.** _Done._ XNN grid v1 and Bio v1 are
  declared in `examples/aha_descriptors.axisl` from PCE's own definitions and
  linked to their engines: a `defaccelerator` whose `descriptor-schema` names
  a `defdescriptor` takes its byte count from the declaration, and one that
  states a different count is refused. The bundle's
  `accelerator_descriptor_manifests.json` — the file AHA's loader reads —
  now carries each linked accelerator's layout, checks and status
  destination, and only for a linked one, so every other bundle is unchanged.

  The grid did not fit H1b's form in three places, each now extended:
  - **a check may be a conjunction** — code 2 is "bad version *or* nonzero
    flags", and geometry, reserved and masks are conjunctions too;
  - **a status may be returned**, `(status returned i4)`, into the launching
    instruction's one output operand: the grid reports its error code rather
    than writing it through a pointer;
  - **a launch need not run a kernel**: the grid descriptor validates and
    stages, and what it computes arrives later as a stream.

  Two of PCE's eight codes are deliberately not checks: TRANSPORT (1) is a
  DMA fault while fetching the words and START_ID (7) is the start handshake
  matching a staged base. Neither is a property of the descriptor's contents,
  which is all a check reads.

  **Held to PCE's RTL, which found a bug.** The gate simulates PCE's own
  `decode_xnn_grid_descriptor_v1` — PyRTL, from PCE's source, with PCE's
  vendored PyRTL (`third_party/pyrtl`; the installed one lacks `pyrtl.sram`)
  — on 62 descriptors: valid, every single fault, stacked faults where the
  priority decides, and random words. The derived `XNN_GRID_SUBMIT` disagreed
  on ten. The status chain was typed at the status's four bits, and an
  untyped comparison evaluates at the width around it, so a sixteen-bit
  `m_count` of `0x8EF0` read as zero and a 16×32 geometry passed as 16×16.
  Bio never showed it: its status and its fields are all 32 bits. The chain
  is now typed at the widest field and narrowed by the write.

  **A discrepancy in PCE, recorded rather than resolved.** Bio's
  `queue_abi.py` submits to `BIO_ACCEL_TARGET = 5`, which the RVMT SDK
  (`rvmt_queue_abi.h`) names `RVMT_ACCEL_TARGET_NEARASIC`; the same header
  defines `RVMT_ACCEL_TARGET_BIO = 10`. The corpus follows the queue ABI —
  what a submitted job carries — and says so. Which one Bio means is PCE's to
  decide.

  Gate `tools/aha_descriptor_check.py`: Bio's fields, bytes, magic and
  version and XNN's version, words, bytes and error codes against PCE's
  constants, read with `ast` rather than imported; the derived submit on
  three executors against PCE's RTL decoder; the bundle's layouts, and AHA's
  `adl_loader.load_adl_bundle_dir` loading it; five refusals; the round trip.
  Without a PCE checkout (`PCE_ROOT`, default `../pce`) the constant and
  loader checks are skipped and the decoder is held to a reference written
  from PCE's rules.

- **S1 — SME's outer products.** _Done._ `examples/sme.axisl` describes
  FMOPA and FMOPS and the widening integer family — SMOPA, UMOPA, SUMOPA,
  USMOPA, SMOPS, four i8 products into each i32 — over a 16×16 `.S` tile,
  each merging-predicated twice: `pn` governs rows, `pm` columns.

  An outer product is T3's row and column broadcast, and a widening one reads
  byte *t* of each 32-bit element with a shift and an extension, so no new
  operator was needed. What was needed was smaller and was found by the first
  attempt: `fma`, `fneg`, `sext` and `zext` were not on the lane-local lists.
  Without `fma` an FMOPA could only be written as `fadd` of `fmul`, which
  rounds twice — and Arm's non-widening FMOPA is `FPMulAdd` per element,
  fused, one rounding. `sext` and `zext` are lane-local for *scalable* lanes
  only: a unit test written to pin their per-lane meaning in the packed path
  found that the packed expansion splits every argument across the lanes —
  right for a shift amount, wrong for an extension's literal source width,
  which became 8 in lane 0 and `8 >> 32 = 0` in lane 1. The packed path
  still refuses them. The ZA tiles got their own register class, `zatile`,
  past the vector and predicate files, so writing ZA0 does not change Z0.

  Predicates are one byte lane per predicate bit, so element *i* of `pn` read
  as i32 holds the bits for bytes 4i..4i+3: a `.S` element is active when its
  lowest bit is, and a widening product governs each source byte by its own
  bit — both Arm's rules.

  Gate `tools/sme_check.py` holds every instruction to a reference written
  from Arm's description: FMOPA as `a*b+c` computed exactly and rounded once
  to binary32. Cancellation inputs — `c` the negation of `a*b` rounded — make
  fused and unfused answers differ, and the gate requires that they did, so
  "fused" is a claim an input tested. The whole register file is compared
  afterwards, so a write that strayed into another tile, a Z or a P shows.
  The Python and wide C executors are held; injection-checked four ways
  (listed in the gate).

  **Recorded, not fixed.**
  - *The wide Rust executor runs no scalable instruction* —
    `scalable_exec_check.py --lang rust examples/sve.axisl` fails 48 of 260
    the same way, which is why no Rust scalable gate is registered. S1 holds
    Python and C and says so; it is a gap in that executor, not in SME.
  - *Z and P were as long as a tile* (VL = 8192) — resolved by S2a, below.
  - *BFMOPA and the widening FMOPA (f16 → f32) are absent*: Arm specifies
    their intermediate rounding (`BFDotAdd`, FPCR.EBF) in a way that must be
    modelled on purpose rather than approximated.

- **S2a — SME's geometry: one ZA, and tiles as views of it.** _Done._ At
  SVL = 512, Z and P are 512 bits and ZA is one array of 64 rows of 512 bits;
  row *i* of ZA*n*.S is ZA row 4*i*+*n*, of ZA*n*.D row 8*i*+*n*, of ZA*n*.H
  row 2*i*+*n*, and ZA0.B is all of it.

  **The premise, measured first: no new placement machinery.** Scalable lanes
  already group — a lane past `VL / elem` lands in the next register, which is
  how RVV's LMUL groups work. With a ZA "register" being one row, SME's
  interleave is only a *step*: a group advances `group_step` registers per
  register of elements. Four classes — `za_b`, `za_h`, `za_s`, `za_d`, steps
  1, 2, 4, 8 — view ONE file, `za`, so writing ZA1.D changes rows ZA1.S also
  names, which is the architecture rather than an accident. S1's `zatile`
  (a separate, tile-length file) is gone.

  Two things were added. A **square** shape, `mn<elem>`: a tile operation has
  (SVL / elem)² lanes — 256 for `.S` — and no LMUL expresses that, because the
  multiplier is itself VL-dependent. And **file sizing by reach**: a register
  file was sized by the five-bit selector alone, and a tile row lives up to 60
  rows past the encoded tile, so the size is now the selector's reach *plus*
  the furthest a lane group goes. That also covers an RVV group encoded near
  the top of the vector file, which the old sizing had not.

  The register file of the SME corpus went from 12,320 slots to 1,280, and
  its gate from fifteen minutes to under one. `FMOPA_D` (8 × 8, step 8) joins
  the corpus so the sharing has two views to disagree about. Gate
  `tools/sme_check.py` now keeps ZA as one byte array, updates it through
  the instruction's view, and compares every Z, P and ZA row afterwards; it
  requires a `.D` trial to have written a row, so the sharing was exercised.
  Injection-checked four ways, including a `za_s` step of 1 (contiguous
  tiles), which fails on every `.S` trial.

- **S2b — slices.** _Done._ `MOVA` moves one row (H) or column (V) of a
  tile, chosen at run time by a general register plus an immediate modulo
  the tile's 16, from a Z register into a tile or out of one, merging by a
  governing predicate.

  **The premise, restated before building: no register-indirect addressing.**
  The obvious reading — the register a lane writes depends on a general
  register's value — is something nothing in AXIS does. It is also not
  needed. A slice WRITE is a whole-tile operation in which each lane knows
  its own row and changes only where that row is the slice:
  `(vmerge mni32 (icmp_eq mni32 (vrow mni32 16) (vdup mni32 <index>)) new
  za)`. A slice READ goes the other way — one Z lane may come from any of
  16 tile elements — so it is a select chain over them, keyed on the index.
  Four lane forms carry both: `vrow` and `vcol` (a lane's own row and
  column, as literals), and `vslice` and `vslicev` (row or column *index*
  of a square tile, the index a scalar expression left unsuffixed, as
  `vdup`'s source is).

  (Arm restricts the slice register to W12–W15; the corpus first took any
  register in a five-bit field, and now takes Arm's field — see S-ASL.)
  The gate's reference computes
  the slice as `(ws + imm) mod 16` from a general register holding small or
  full 64-bit values, requires that some index wrapped, and compares the
  general registers too. Injection-checked four ways: the immediate
  ignored, a horizontal read done vertically, the modulo dropped, and `vrow`
  and `vcol` swapped in the code.

  **Next, and worth more than another instruction:** the other session's
  `tools/asl_check.py` runs AArch64 words on Arm's own executable
  specification (the Sail translation of the ASL for Armv9.4-A), and
  Armv9.4 includes SME. Everything S1 and S2 hold today is held to a
  reference written from Arm's *description*. Holding it to Arm's
  *definition* needs the corpus in real A64 encodings, the model run with
  SME enabled and a known SVL, and that harness extended to seed and read
  back Z, P and ZA.

- **S-ASL — SME held to Arm's definition.** _Done._ Everything above was held
  to a reference written from Arm's *description*. `tools/sme_asl_check.py`
  holds it to Arm's *definition*: the Sail translation of the ASL for
  Armv9.4-A, the emulator `tools/asl_model_build.sh` builds and
  `tools/asl_check.py` runs AArch64 on. The model implements SME
  (`has_sme`, `has_sme_f64f64`) at SVLs of 128, 256 and 512 bits.

  A template enables SME at EL3 (CPTR_EL3.ESM and .EZ, SMCR_EL3.LEN = 3, so
  SVL = 512), enters streaming mode with ZA on (`SMSTART`), loads every X, Z,
  P and all 64 ZA rows, runs one word, stores everything back and streams it
  out through the UART. The first run confirmed the geometry S2a chose: an
  FMOPA into ZA1.S wrote ZA rows 1 and 5 and left row 0 alone.

  The corpus's encodings are its own, so each trial runs twice from one
  machine state: AXIS runs its word, and the model runs Arm's — the same
  instruction and operands, assembled by `llvm-mc` from A64 syntax. Every X,
  Z, P0–P7 and ZA row must agree, and each trial is also compared with
  `sme_check.py`'s reference, so a disagreement says which of three is
  wrong. Beyond `sme_check.py`'s trials: MOVA's slice register in W12–W15,
  as Arm requires, and **special values** — infinities, signalling and quiet
  NaNs, signed zeros, subnormals, the largest finite value — in FMOPA, FMOPS
  and FMOPA.D, held AXIS against Arm alone, since the reference computes with
  exact rationals. FPCR.DN = 1, the mode `asl_check.py` runs and the corpus
  describes. The gate requires the model to have changed ZA or Z in every
  trial that must change something, so agreement is not two machines doing
  nothing.

  **All 64 words agree**, special values included: AXIS's fused FMOPA and
  FMOPS, the widening family's per-byte predication, the interleaved tile
  views and the run-time slices are Arm's. Four mutants of the corpus —
  FMOPS without its negation, SMOPA's bytes governed by one predicate bit, a
  horizontal slice read vertically, FMOPA unfused — each disagree with the
  model, and in each the gate's reference sides with Arm.

  **And the encodings are Arm's.** The corpus first sat on an RV-style base
  with formats of its own, so its words were not Arm's and the semantics
  were checked by assembling Arm's syntax beside them. It now declares
  Arm's layouts field for field — FMOPA/FMOPS `.S` and `.D`, the SMOPA
  family's `u0`/`u1`/`S` bits, MOVA's two directions — on an `armv8-a`
  base, and MOVA's two-bit `Rs` names W12–W15 through a register class,
  `a64_w12`, that reads register 12 + Rs as a W view. The gate now requires
  every word it builds to be *exactly* the word `llvm-mc` assembles for the
  same instruction, and runs that one word on both machines. The
  deviation S2b recorded — any slice register in a five-bit field — is
  gone with it.

  Still not held to Arm: the *asm* strings, which print the corpus's own
  syntax rather than Arm's (`fmopa_s $za, …` for `fmopa za1.s, p2/m, …`);
  a disassembly comparison needs register names for the Z, P and ZA
  classes, which nothing prints yet.

- **S2c — slices to and from memory.** _Done._ `LD1W` and `ST1W` move one
  `.S` slice, horizontal or vertical, between a tile and `Xn|SP + (Xm << 2)`
  — in Arm's encoding (`1110000010 st Rm V Rs Pg Rn 0 ZAt off2`), W12–W15
  for the slice as MOVA has it.

  Arm is exact about inactive elements, and so is the corpus. A load writes
  an active element from memory and an inactive one with **zero** (`/Z`), and
  does not read memory for it; a store writes active elements and **no
  others**. So a load is two guarded effects over the tile — `(when (and
  in-slice active) (set za (vload_map …)))` and `(when (and in-slice
  inactive) (set za 0))` — and H1a's rule that a guarded effect's loads run
  only when its guard holds is what keeps inactive elements from being read.
  A store is one guarded store per element.

  Two generalisations made that expressible:
  - **untyped guards over lanes.** A comparison, `and`, `or` or `not` whose
    arguments are vector expressions is taken per lane. A predicated
    vector store's guard is exactly that, and `lane_of` refused it, because
    it wanted a type atom in second position;
  - **an expression as a base.** `vaddr`, `vload_map` and their siblings
    took a single operand as base; Arm's address is `Xn + (Xm << 2)`. A
    base may now be a scalar expression, left unsuffixed as `vdup`'s
    source is.

  `tools/sme_check.py` seeds 16 words at the slice's address (Xm sometimes
  XZR), gives every executor a memory, and compares it with the register
  file; it requires that some load zeroed an inactive element and some
  store left one unwritten, so both of Arm's rules were exercised.
  `tools/sme_asl_check.py` loads a 2 KB memory window into Arm's model and
  streams it back out: **all 80 words agree** with the model — registers,
  ZA and memory — and each is the word `llvm-mc` assembles. Python, C and
  Rust all run it. Injection-checked four ways: a load that keeps inactive
  elements instead of zeroing them, an unguarded store, the index scaled by
  eight, and a horizontal load addressed by row.

- **H2 — XNN custom-0 as kernels.** _Withdrawn._ Its premise is false in
  this checkout. PCE's `XNNTileController`, the RTL that would execute the
  custom-0 commands, is a placeholder that raises `NotImplementedError`
  ("until the full XNN tile RTL package is restored"); the SDK issues
  `xnn_matmul(descriptor)` and then computes the matmul in C anyway ("so the
  firmware can take advantage of the accelerator when descriptors are
  understood by the microcode"); and the descriptor packs only `m | n<<8 |
  k<<16` and two flags, no addresses. Nothing defines what the instruction
  does, so describing it would be inventing it. The real XNN compute is the
  MMIO engine, which is H3.

- **H3 — an MMIO device.** _Done._ PCE's XNN systolic GEMM engine
  (`hardware/accel_engines/xnn_systolic_engine.py`, weight-stationary, int8
  into int32) is driven through registers: stream weights, stream
  activations, set M, kick, poll busy, stream results out.

  **The premise, measured first:** the engine's own PyRTL, simulated with
  PCE's vendored PyRTL, computes `R[m][n] = Σₖ A[m][k] · W[k][n]`, signed,
  weights row-major W[k][n] with the array's rows as K — which fixed the
  layout before anything was written.

  **The design needs one construct.** A register with a side effect — a
  stream that advances a pointer, a kick that computes, a result port that
  pops — is not a location a load or a store describes. Its effect is a
  behavior, and AXIS already states behaviors and holds them to every
  backend: as instructions. So the device's registers are instructions of
  the device's own ISA, over a device-local memory holding the engine's
  state (buffers, pointers, M) — a stream write is H1a's store at a loaded
  address, the kick is T8's kernel guarded by `m < M` — and `defdevice` is
  only the register map: which handler runs when the host reads or writes
  which word. It is checked at declaration: offsets inside the window and
  word-aligned, one handler per word and direction, handlers that are
  instructions of the device's ISA, a write handler taking at most the
  written value and a read handler returning exactly one value.

  The engine takes cycles and reports busy; AXIS's kick completes before the
  next access, so status reads 0 — a host that polls reads the same
  results.

  Corpus `examples/xnn_systolic.axisl` (the 4 × 4 instance, M up to 8); gate
  `tools/xnn_device_check.py`: six random jobs as one host session through
  PCE's RTL and through AXIS's handlers, every result equal and equal to
  A @ W; all 336 accesses replayed on the wide C and Rust executors from the
  device memory they started with; six bad register maps refused; the round
  trip and manifest. Injection-checked four ways: unsigned arithmetic, a
  result pointer that never advances, transposed weights, a status stuck
  busy.

  **H3b — the K-tile control.** _Done._ Register 0x30 is PCE's K-tile
  control: bit 0 accumulate, bit 1 more-K, bits 16–18 valid K (0 = all 4).
  K beyond the array is a chain of tiles, each re-streamed after a rewind,
  the continuation adding into what the last tile left.

  **The premise, measured on the RTL first:** a chain of tiles sums to the
  full-K product; rows past valid K are masked even when junk was streamed
  there; status bit 1 is a sticky error, bit 2 an open chain, and a rewind
  clears the error; an accumulate with no open chain, an M of 0 or 9, a
  valid K over 4, a continuation that changes M, and any kick while the
  error is set, are all refused and set the error, and a refused kick leaves
  the results the host reads unchanged.

  **No new construct.** The engine's results are two banks in device memory
  and a select bit: a kick writes the inactive bank from the activations,
  plus the active bank if it accumulates, then flips the select. That
  ordering is what makes "a refused kick changes nothing" hold without
  reading and writing one bank in one effect, and every rule above is a
  guard on the kick or on a register write.

  The gate's session now runs K from 1 to 12 in chains of up to three tiles,
  and every refusal, each followed by a job that must still come out right:
  211 reads over 24 kicks agree with PCE's RTL and with a protocol model
  written from scratch in the gate, and all 1035 accesses replay on the wide
  C and Rust executors. Injection-checked four more ways: an accumulate that
  drops the prior bank, no valid-K mask, the kick writing the active bank,
  and an error that does not block a kick. The one mutant not caught is
  equivalent: a refused kick that still computes writes only the inactive
  bank, which the next accepted kick overwrites, so no read can tell.

  The wide C executor's memory table grew for this. A kick touches about 84
  cells; the table is now sized by the cases and static per case (256 on the
  stack overflowed the AArch64 corpus's driver, which died printing
  nothing).

  Not yet: wide-result segments (0x24–0x2C), and a host program of *CPU*
  instructions whose loads and stores reach the device through a bus.
  Today the gate is the host.

- Later: **H3c** a CPU host reaching the device through a bus; **H4** NTT and Smith-Waterman as kernels against their
  goldens; **S3** streaming mode; SME's asm in Arm's syntax.

## 5. Measured for SME, recorded here so it is not re-measured

A 16×16 f32 FMOPA that accumulates into ZA and masks rows and columns by two
predicates — `(vmerge vnf32 (and vni32 (vrows vni32 16 pn) (vcols vni32 16
pm)) (fadd vnf32 za (fmul vnf32 (vrows vnf32 16 zn) (vcols vnf32 16 zm)))
za)` — validates, emits through golden, C and LLVM, and executes on both
scalable executors with no failures. What SME still lacks is elsewhere:
runtime-indexed slices, the tiles' shared storage, Z and ZA at different
lengths, the widening forms, and streaming mode.
