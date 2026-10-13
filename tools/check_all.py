#!/usr/bin/env python3
"""Run the AXIS evidence ladder: every differential gate, on its corpus.

AXIS's rule is that each generated artifact is differentially checked against
one already-proven artifact, but which gate runs against which example lived
only in each tool's own docstring -- there was no way to run the ladder. This
is that matrix, written down and executable.

Every gate prints a single verdict line and exits 0 (pass or a clean skip when
a toolchain is absent) or non-zero (fail). This runner reports one line per
gate plus a summary, and exits non-zero if any gate failed.

Usage:
  tools/check_all.py                 # the whole ladder
  tools/check_all.py --changed       # only what the working tree can affect
  tools/check_all.py --quick         # skip the slow AArch64 gates
  tools/check_all.py --only llvm     # gates whose name matches a substring
  tools/check_all.py --list          # show the matrix without running

The whole ladder takes minutes, and iterating on one emitter does not need it:
a change confined to the LLVM emitters and their checkers selects 40 gates of
219, and a change to one checker selects 12. `--changed` reads that from `git
diff` rather than from someone knowing the label conventions, and falls back to
the whole ladder the moment a changed path is one whose reach is not written
down -- the frontend, the IR, the effect model, a corpus. Under-running is the
failure mode that matters here, so the default when in doubt is everything, and
any run that is not the whole ladder says so on its last line.

None of the shortcuts is what gates a commit. They are for the loop before it.

`cargo test` is included as the first gate: the Rust regressions pin the
emitters, while the Python gates prove the emitted artifacts against each
other. `pce_smoke_check` is excluded by default because it needs a PCE
checkout; pass --with-pce (and AXIS_PCE_ROOT) to include it.

Temporary files. A run leaves nothing behind: each gets its own TMPDIR,
removed at exit, so whatever a gate puts in `tempfile` goes with it. That
covers gates run from here, and only from here -- a gate written for, or
run, by hand either removes its own directory (`atexit` + `shutil.rmtree`,
as `asl_check.py` does, with worker directories made inside it) or is run
with a TMPDIR the caller clears. Before this, ~196,000 `axis_*`
directories -- 56 GB -- had collected in the system temp.
"""

from __future__ import annotations

import argparse
import atexit
import concurrent.futures
import os
import shutil
import subprocess
from axis_cli import DECLINED
import sys
import tempfile
import time
from pathlib import Path

AXIS_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = AXIS_ROOT / "examples"


def example(name: str) -> str:
    return str(EXAMPLES / name)


# (label, argv, slow) -- `slow` marks the AArch64-corpus gates that dominate
# wall-clock time and that --quick omits.
def matrix(with_pce: bool) -> list[tuple[str, list[str], bool]]:
    gates: list[tuple[str, list[str], bool]] = [
        ("cargo test", ["cargo", "test", "--quiet"], False),
    ]

    def gate(label: str, tool: str, *args: str, slow: bool = False) -> None:
        gates.append((label, [sys.executable, str(AXIS_ROOT / "tools" / tool), *args], slow))

    # --- what this repository says about itself ---------------------------
    gate("documented numbers", "doc_facts_check.py")
    # Every corpus that emits SMT definitions, not the five that used to be
    # named. The backend was emitted for thirty-four and checked on five, so
    # over a thousand definitions -- including SVE's 435 and RV64I's 146 --
    # were generated and never compared against the golden model.
    gate("SMT == golden", "smt_vs_golden.py")
    # The floor: every corpus elaborates and emits, and the corpora no gate
    # names are listed every run. Coverage has narrowed silently twice, and
    # both times the gap was found by accident rather than by a red gate.
    gate("corpus coverage", "corpus_coverage_check.py")

    # --- encode/decode roundtrip ------------------------------------------
    # ⚠️ EVERY corpus, not a chosen few. The named gates below say a great deal
    # about the corpora they name and nothing about the rest, and two corpora
    # were failing to decode at all -- `lisp_modes_cores` and `vliw_packet` --
    # with no gate watching either. Both shared an encoding between instructions
    # the disjointness rule allows to share one, and a decoder handed only a
    # word cannot tell those apart; it refused, correctly, and nobody was
    # listening. This asks all of them, so the next such corpus is found by a
    # red gate rather than by someone running the tool by hand.
    gate("roundtrip: every corpus", "roundtrip_check.py",
         *sorted(str(path) for path in EXAMPLES.glob("*.axisl")))
    gate("roundtrip: zbb", "roundtrip_check.py", example("zbb_like.axisl"))
    gate("packet roundtrip", "packet_roundtrip.py", example("vliw_packet.axisl"))
    gate("packet semantics", "packet_vs_serial.py", example("vliw_packet.axisl"))
    gate("exposed latency", "exposed_latency_check.py", example("vliw_exposed.axisl"))
    # B4: the schedule a compiler reads against the packet the machine accepts,
    # in both directions -- a permissive table emits packets the machine
    # rejects, a strict one silently costs issue width.
    gate("itinerary == packet", "itinerary_vs_packet.py", example("vliw_packet.axisl"))
    # G1: the manifest's expanded edge list against an independent expansion of
    # the declared pattern. The boundary is the difficulty -- a mesh and a torus
    # differ only there -- so a corpus with no boundary fails as vacuous.
    gate("fabric topology", "fabric_topology_check.py", example("cgra_fabric.axisl"))
    # G2: the occupancy tables the validator decided legality on, re-derived.
    # A corpus whose cycles are all below its II fails as vacuous -- the wrap
    # never happens and `cycle mod ii` is `cycle`.
    gate("mapping legality", "mapping_legality_check.py", example("cgra_fabric.axisl"))
    # G3: the mapping run as a dataflow over the fabric against its scalar
    # sequence. Both sides evaluate the same per-operation semantics, so what
    # is under test is the placement, the routing and the timing.
    gate("fabric == scalar", "fabric_vs_scalar.py", example("cgra_fabric.axisl"))
    # G4b: the half of elastic that is decidable from the declaration. A ring
    # of pure wires has nowhere to put a token, and the validator's answer is
    # re-derived here from the manifest -- which must also show no residue for
    # a route whose arrival is a window.
    gate("elastic deadlock", "elastic_deadlock_check.py", example("cgra_fabric.axisl"))
    # G4b.2: the obligation elastic carries in place of a fixed schedule. G3
    # fixes the timing and compares; this varies it and requires the same
    # answer, failing as vacuous if the draws never differed.
    gate("elastic == scalar (any timing)", "elastic_vs_scalar.py",
         example("cgra_fabric.axisl"))
    # G4b.3: elastic at a personality boundary. A lent unit is a channel with a
    # machine on each end, and the gate joins two manifests to check that the
    # two ends were specified to be the same seam.
    gate("seam contracts", "seam_contract_check.py", example("vliw_exposed.axisl"))
    # M1: an accelerator's context numbers, which its consumer keeps by hand in
    # a Python dataclass with a hand-written validate(). The relations between
    # them are re-derived here from the manifest.
    gate("multi-context engines", "multicontext_check.py",
         example("heterogeneous_tile.axisl"))
    # M3: the one obligation here that is not arithmetic. M2 decides whether a
    # bound exists to publish; this runs the policy and requires the bound to be
    # both never exceeded and actually attained.
    gate("bounded context service", "context_service_check.py",
         example("heterogeneous_tile.axisl"))
    # L4: a calling convention is declared, not derived, so what is checkable
    # is whether it holds together. The other half -- LLVM's own
    # --gen-callingconv reading the emitted convention back -- rides in
    # llvm_target_check.py, where the rest of the target generators already are.
    # The canonical form, over every corpus. `emit-lisp` claims a document can
    # be rewritten from its own emitted form; until this gate that claim was
    # tested on one corpus by two assertions about barriers, and no gate drove
    # the emitter at all.
    # ADL.2: the axioms OptiSynth's verifier needs about intrinsic *calls*,
    # proved against the golden model. The consistency check first is not
    # ceremony -- a contradictory axiom set entails every refutation query, and
    # would report a perfect score for a file that says nothing.
    # X1: the tree a consumer lifting a binary reads instead of parsing text.
    # The gate is that consumer -- it walks the published JSON and must get the
    # executor's answer, so a tree that is not enough to compute with fails
    # here rather than in another repository.
    gate("published trees == executor", "lift_ast_check.py")
    # X2/X3: the same trees threaded into one graph per block, and the graph's
    # live-outs required to be exactly what the block wrote. The threading is
    # what nothing about a single instruction can check.
    gate("block graph == executor", "lift_block_check.py")
    # What each instruction can be expressed as, joined back to the artifacts
    # it claims about. A projection is only worth having if it is the same
    # thing the artifacts say.
    gate("capability manifest", "capability_check.py")
    # The evidence document says only what its evidence supports. Run on a
    # small corpus: it runs seven gates itself, and the point is the shape of
    # what it produces rather than a second sweep.
    gate("evidence == what ran", "evidence_check.py")
    gate("intrinsic axioms", "smt_axioms_check.py")
    gate("lisp round trip", "lisp_roundtrip.py")
    gate("abi consistency", "abi_check.py", example("rv32i.axisl"))
    # F1: the frame layout, and the join that makes it worth stating -- the
    # store named to save a register either reaches the top of the largest
    # declared frame or the instruction set refutes the declaration.
    gate("frame layout", "frame_check.py", example("rv32i.axisl"))
    # F2: the same frame, run. F1 decides whether the published table is the
    # layout; this decides whether the instructions reach where they are aimed
    # and whether the two halves are inverse as programs.
    gate("frame execution", "frame_exec_check.py", example("rv32i.axisl"))
    # A6: the launch that reads the shared register file, executed. Its
    # live-ins are registers the description names rather than operands decode
    # selects, so the golden model, the Python executor and both wide
    # executors have to agree about a read no fixture's operands mention --
    # and the drivers have to seed the register, or all four agree on zero.
    gate("CGRA launch python exec", "exec_vs_golden.py", example("cgra_fabric.axisl"))
    gate("CGRA launch wide C exec", "exec_wide_check.py", example("cgra_fabric.axisl"))
    gate("CGRA launch wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("cgra_fabric.axisl"))
    gate("itinerary == packet (exposed)", "itinerary_vs_packet.py",
         example("vliw_exposed.axisl"))
    gate("roundtrip: rvmt", "roundtrip_check.py", example("rvmt_xpce.axisl"))
    gate("lift roundtrip", "lift_roundtrip.py", example("zbb_like.axisl"))
    gate("lift native (C/Rust)", "lift_native_check.py", example("zbb_like.axisl"))

    # --- the semantics quintet vs the golden model ------------------------
    gate("C == golden", "c_vs_golden.py", example("zbb_like.axisl"))
    gate("Rust == golden", "rust_vs_golden.py", example("zbb_like.axisl"))
    gate("LLVM == golden", "llvm_vs_golden.py", example("zbb_like.axisl"))
    gate("OptiSynth == golden", "optisynth_vs_golden.py")

    # --- scalar IEEE-754 (SMT withholds float; z3's FP theory is a later stage)
    gate("FP C == golden", "c_vs_golden.py", example("fp_scalar.axisl"))
    gate("FP Rust == golden", "rust_vs_golden.py", example("fp_scalar.axisl"))
    gate("FP LLVM == golden", "llvm_vs_golden.py", example("fp_scalar.axisl"))
    gate("FP roundtrip", "roundtrip_check.py", example("fp_scalar.axisl"))
    gate("FP fused != unfused", "fp_fusion_check.py")
    # The exceptions an operation raises, decided from exact rationals by the
    # golden model and read from the environment by C -- two derivations, which
    # is the only reason describing them is worth anything.
    gate("FP exceptions python exec", "exec_vs_golden.py",
         example("fp_exceptions.axisl"))
    gate("FP exceptions wide C exec", "exec_wide_check.py",
         example("fp_exceptions.axisl"))
    # The ladder proves the backends agree with each other; RISC-V's ten
    # classes are an external fact, and a classification with two bits
    # transposed would be emitted identically by all of them.
    gate("FCLASS: RISC-V's ten classes", "fclass_check.py",
         example("rv32i.axisl"))
    gate("FCLASS: RISC-V's ten classes (RV64)", "fclass_check.py",
         example("rv64i.axisl"))
    # The FP effect layer for a second ISA. The operators are ISA-neutral by
    # construction; whether that is true is the thing being measured, and the
    # two halves answer differently -- the mode ports for free, the exception
    # word needs a five-bit reversal AArch64 states in the corpus.
    gate("A64 FP env python exec", "exec_vs_golden.py",
         example("aarch64_fp_env.axisl"))
    gate("A64 FP env wide C exec", "exec_wide_check.py",
         example("aarch64_fp_env.axisl"))
    gate("A64 FP env wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("aarch64_fp_env.axisl"))
    # A reversal stated once and read by six backends is what a differential
    # cannot see: they would agree about the wrong order.
    gate("FPCR/FPSR: AArch64's meanings", "a64_fpenv_check.py",
         example("aarch64_fp_env.axisl"))
    # And on the translation seed, which is where FPCR and FPSR actually live:
    # the same rules, the same witnesses, a corpus that also has to lower every
    # one of these to an accelerator instruction that agrees.
    gate("FPCR/FPSR: AArch64's meanings (seed)", "a64_fpenv_check.py",
         example("aarch64_translation_seed.axisl"))
    # The same argument one level along: which exceptions an operation raises
    # is an external fact too, and the corpus states it once, so a comparison
    # that signalled on the wrong kind of NaN would satisfy every differential.
    gate("fflags: RISC-V's exception rules", "fflags_check.py",
         example("rv64i.axisl"))
    gate("fflags: RISC-V's exception rules (RV32)", "fflags_check.py",
         example("rv32i.axisl"))
    # Zicsr and DYN only mean anything together: a mode register nothing can
    # set, or a CSR write nothing reads, each describe half a machine.
    gate("dynamic rounding selects", "dynamic_rounding_check.py",
         example("rv64i.axisl"))
    gate("dynamic rounding selects (RV32)", "dynamic_rounding_check.py",
         example("rv32i.axisl"))
    # Effectful FP: a comparison whose result is architectural state.
    gate("FP python exec", "exec_vs_golden.py", example("fp_scalar.axisl"))
    gate("FP C exec", "exec_c_check.py", example("fp_scalar.axisl"))
    gate("FP Rust exec", "exec_rust_check.py", example("fp_scalar.axisl"))

    # --- lane-wise SIMD (64-bit vectors; C/Rust cap at 32 and skip) --------
    gate("SIMD LLVM == golden", "llvm_vs_golden.py", example("simd_lanes.axisl"))
    gate("SIMD C == golden", "c_vs_golden.py", example("simd_lanes.axisl"))
    gate("SIMD Rust == golden", "rust_vs_golden.py", example("simd_lanes.axisl"))
    # 128-bit Q-register shapes: golden, SMT, LLVM, and Rust reach 128; C does
    # not (it would need `unsigned __int128`) and skips with that reason.
    gate("SIMD-Q LLVM == golden", "llvm_vs_golden.py", example("simd_q_lanes.axisl"))
    gate("SIMD-Q Rust == golden", "rust_vs_golden.py", example("simd_q_lanes.axisl"))
    # C reaches 128 bits too now; it was the one backend that declined.
    gate("SIMD-Q C == golden", "c_vs_golden.py", example("simd_q_lanes.axisl"))
    gate("SIMD roundtrip", "roundtrip_check.py", example("simd_lanes.axisl"))
    gate("SIMD lift roundtrip", "lift_roundtrip.py", example("simd_lanes.axisl"))
    gate("SIMD python exec", "exec_vs_golden.py", example("simd_lanes.axisl"))

    # --- scalable vectors (stage S1): a vector length that is not written ---
    # The four backends at VL=128, then the same document at 256 and 512 --
    # lengths the packed representation cannot reach, since a packed lane mask
    # would need bits no `Sem::Int` (a u128) can hold. Rust is omitted from the
    # length sweep only for wall-clock: at VL=512 it compiles 296 functions and
    # takes ~10 minutes; it passes there (18944 checks) when run directly.
    gate("scalable LLVM == golden", "llvm_vs_golden.py", example("scalable_basic.axisl"))
    gate("scalable C == golden", "c_vs_golden.py", example("scalable_basic.axisl"))
    gate("scalable Rust == golden", "rust_vs_golden.py", example("scalable_basic.axisl"))
    gate("scalable lane-indexed == packed", "scalable_vs_packed.py",
         example("scalable_basic.axisl"))
    gate("scalable at 128/256/512", "scalable_lengths.py",
         example("scalable_basic.axisl"))
    # Stage S2: a result that is only partly specified. The mask is compared
    # exactly across realisations of the undefined bits, values only under it,
    # and the gate fails if no undefined lane is reached or if the realisation
    # knob turns out to be inert -- either would make the other two vacuous.
    gate("scalable definedness", "scalable_definedness.py",
         example("scalable_basic.axisl"))

    # --- stage S3: shapes that come from `vtype` --------------------------
    # SEW sets the element width and LMUL the rational register footprint, so
    # an instruction written once means a different shape at every mode point.
    # The sweep also checks the legality predicate against the rule implemented
    # independently from the RVV specification, in both directions.
    gate("vtype LLVM == golden", "llvm_vs_golden.py", example("scalable_vtype.axisl"))
    gate("vtype C == golden", "c_vs_golden.py", example("scalable_vtype.axisl"))
    gate("vtype Rust == golden", "rust_vs_golden.py", example("scalable_vtype.axisl"))
    gate("vtype (SEW, LMUL) sweep", "scalable_modes.py", example("scalable_vtype.axisl"))

    # --- stage S4: predication -------------------------------------------
    # A predicate is a vector whose lanes are 0 or 1, so most of this composes.
    # The last gate is the one that matters: every backend derives its answer
    # from the same description, so the four above prove the implementations
    # agree and structurally cannot notice a description that is uniformly
    # wrong. `scalable_predication.py` states what predication means
    # independently and catches an inverted merge sense, which all four miss.
    gate("predication LLVM == golden", "llvm_vs_golden.py", example("scalable_predicate.axisl"))
    gate("predication C == golden", "c_vs_golden.py", example("scalable_predicate.axisl"))
    gate("predication Rust == golden", "rust_vs_golden.py", example("scalable_predicate.axisl"))
    gate("predication definedness", "scalable_definedness.py",
         example("scalable_predicate.axisl"))
    gate("predication == architecture", "scalable_predication.py",
         example("scalable_predicate.axisl"))

    # --- stage S5: vector memory -----------------------------------------
    # Where the lane-to-register mapping S1 could not express finally becomes
    # checkable: an address names its lane. The decode-driven exec harnesses
    # cannot reach these -- lanes share an encoding on purpose -- so they skip,
    # and this gate is the one that does the work.
    gate("scalable addressing", "scalable_addressing.py",
         example("scalable_memory.axisl"))
    gate("scalable fault suppression", "scalable_faulting.py",
         example("scalable_memory.axisl"))

    # --- stage S6: cross-lane --------------------------------------------
    # A reduction is the one shape that does not become one instruction per
    # lane, and a structured permute is a static map from an output lane to an
    # input lane. The last gate states both tables independently; the four
    # above cannot see a permute table that is wrong the same way everywhere.
    gate("crosslane LLVM == golden", "llvm_vs_golden.py", example("scalable_crosslane.axisl"))
    gate("crosslane C == golden", "c_vs_golden.py", example("scalable_crosslane.axisl"))
    gate("crosslane Rust == golden", "rust_vs_golden.py", example("scalable_crosslane.axisl"))
    # --- a third floating-point format ------------------------------------
    # f16 is where the two-format assumption broke: every backend picked
    # between single and double by comparing the width against 32, so a half
    # resolved to single in C and Rust and produced an SMT file z3 rejected.
    # The four differential gates prove the backends agree; the fifth proves it
    # over every pattern there is, which is the only way to catch a rounding
    # bug that lives in a thin band.
    gate("half LLVM == golden", "llvm_vs_golden.py", example("fp16.axisl"))
    gate("half C == golden", "c_vs_golden.py", example("fp16.axisl"))
    gate("half Rust == golden", "rust_vs_golden.py", example("fp16.axisl"))
    gate("half SMT == golden", "smt_vs_golden.py", example("fp16.axisl"))
    gate("half over every pattern", "half_exhaustive_check.py",
         example("fp16.axisl"))

    # bf16 is not a value domain: it expands into integer bit work, so every
    # backend consumes ordinary semantics and their agreement proves nothing
    # about the expansion. What checks the expansion is exact rational
    # arithmetic, which shares no line with the shift it is checking.
    gate("bf16 C == golden", "c_vs_golden.py", example("bf16.axisl"))
    gate("bf16 LLVM == golden", "llvm_vs_golden.py", example("bf16.axisl"))
    gate("bf16 SMT == golden", "smt_vs_golden.py", example("bf16.axisl"))
    gate("bf16 rounds correctly", "bf16_check.py", example("bf16.axisl"))

    # The eight-bit formats, which are two formats and not one. e5m2 is
    # IEEE-shaped; e4m3 has no infinities, spends its top exponent on finite
    # values and saturates. Checked against exact rational rounding on every
    # boundary the formats have, since a random f32 never lands on a midpoint.
    gate("fp8 C == golden", "c_vs_golden.py", example("fp8.axisl"))
    gate("fp8 LLVM == golden", "llvm_vs_golden.py", example("fp8.axisl"))
    gate("fp8 SMT == golden", "smt_vs_golden.py", example("fp8.axisl"))
    gate("fp8 rounds correctly", "fp8_check.py", example("fp8.axisl"))

    # A tile is a vector with a second index, so what needs checking is the
    # index functions -- and a static map cannot be checked by comparing
    # backends, since they all read the same map. These are proved against each
    # other instead, and the corpus is non-square because a square one cannot
    # tell a row count from a column count.
    gate("matrix C == golden", "c_vs_golden.py", example("matrix.axisl"))
    gate("matrix LLVM == golden", "llvm_vs_golden.py", example("matrix.axisl"))
    gate("matrix indices agree", "matrix_check.py", example("matrix.axisl"))

    # An access map is a generalisation, so what it has to prove is that it
    # reproduces the two address functions it generalises -- both proven in S5
    # -- before anything is believed about the shapes that are new.
    gate("access map C == golden", "c_vs_golden.py", example("access_map.axisl"))
    gate("access map LLVM == golden", "llvm_vs_golden.py", example("access_map.axisl"))
    gate("access map generalises", "access_map_check.py",
         example("access_map.axisl"))

    # A configuration read from memory. The semantics were always describable;
    # what `defconfig` adds is a second statement of the layout, and the only
    # thing that makes a second statement worth having is that the two must
    # agree. So this gate is mostly refusals.
    gate("configuration agrees", "config_check.py", example("tilecfg.axisl"))

    # The elaboration passes reach the effect surface, which is where memory
    # is. Each shorthand appears twice in the corpus -- as a value and inside a
    # behavior -- and the two must elaborate alike.
    gate("behavior forms agree", "behavior_forms_check.py",
         example("behavior_forms.axisl"))
    gate("behavior forms C == golden", "c_vs_golden.py",
         example("behavior_forms.axisl"))

    # When an engine's writes land, what the host sees before then, and whether
    # the launch fences. Each is checked against the coupling it is declared
    # beside, because the two are the same fact stated twice.
    gate("completion contract agrees", "completion_check.py",
         example("completion.axisl"))

    # More than one load in an effect. The three executors run it and the
    # golden model is the reference; the point of the corpus is that a
    # contraction whose terms are memory reads exists at all.
    gate("nested loads python exec", "exec_vs_golden.py",
         example("nested_loads.axisl"))
    gate("nested loads wide C exec", "exec_wide_check.py",
         example("nested_loads.axisl"))
    gate("nested loads wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("nested_loads.axisl"))

    # T8: a kernel is launched, not transcribed. The gate owns the claims only
    # a kernel makes -- a disagreeing launch is refused, the source survives --
    # and the three executors run the launches like any other behavior.
    gate("kernel launches agree", "kernel_check.py", example("kernel.axisl"))
    gate("kernel python exec", "exec_vs_golden.py", example("kernel.axisl"))
    gate("kernel wide C exec", "exec_wide_check.py", example("kernel.axisl"))
    gate("kernel wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("kernel.axisl"))

    # H3: an MMIO device -- PCE's XNN systolic GEMM engine as its register
    # map, each register an instruction of the device's ISA. Held to the
    # engine's own PyRTL (simulated with PCE's vendored PyRTL) over random
    # host sessions; to A @ W alone without a PCE checkout.
    gate("XNN device agrees", "xnn_device_check.py", example("xnn_systolic.axisl"), slow=True)
    gate("XNN device python exec", "exec_vs_golden.py", example("xnn_systolic.axisl"))
    gate("XNN device wide C exec", "exec_wide_check.py", example("xnn_systolic.axisl"))
    gate("XNN device wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("xnn_systolic.axisl"))

    # S1: SME's outer products, fused and twice predicated, against a
    # reference that rounds a*b+c exactly once. Python and C: the wide Rust
    # executor runs no scalable instruction (sve.axisl's too).
    gate("SME outer products agree", "sme_check.py", example("sme.axisl"), slow=True)
    # And against Arm's own executable definition (the Sail ASL model), which
    # the reference above is only a reading of. Declines without the model.
    gate("SME == Arm's specification", "sme_asl_check.py", example("sme.axisl"), slow=True)

    # H1a: an effect reads memory in its address and its guard, and every load
    # it names is performed, in order. The gate runs real descriptors -- valid
    # and each way invalid -- through all three executors against a reference
    # written from the layout; the generic gates below only ever see random
    # memory, which no magic check accepts.
    gate("descriptor reads agree", "descriptor_reads_check.py",
         example("descriptor_reads.axisl"))
    gate("descriptor reads python exec", "exec_vs_golden.py", example("descriptor_reads.axisl"))
    gate("descriptor reads wide C exec", "exec_wide_check.py", example("descriptor_reads.axisl"))
    gate("descriptor reads wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("descriptor_reads.axisl"))

    # H1b: a descriptor, declared. The launch's behavior is derived from the
    # layout, and the gate holds it to Bio's engine written in Python, to
    # H1a's hand-written launch over the same descriptors, and to every way a
    # declaration can be wrong.
    gate("descriptor launches agree", "descriptor_check.py",
         example("descriptor.axisl"), example("descriptor_reads.axisl"))
    gate("descriptor python exec", "exec_vs_golden.py", example("descriptor.axisl"))
    gate("descriptor wide C exec", "exec_wide_check.py", example("descriptor.axisl"))
    gate("descriptor wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("descriptor.axisl"))

    # H1c: AHA's own descriptors, held to PCE's constants, to PCE's RTL grid
    # decoder simulated on the same words, and to AHA's loader reading the
    # bundle. Without a PCE checkout the first and last are skipped and the
    # decoder is held to a reference written from PCE's rules.
    gate("AHA descriptors agree", "aha_descriptor_check.py", example("aha_descriptors.axisl"))
    gate("AHA descriptors python exec", "exec_vs_golden.py", example("aha_descriptors.axisl"))
    gate("AHA descriptors wide C exec", "exec_wide_check.py", example("aha_descriptors.axisl"))
    gate("AHA descriptors wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("aha_descriptors.axisl"))

    # The three executors on every tensor-stage corpus that has scalar
    # instructions. None of them were registered, and two were wrong: the wide
    # executors ran f16 arithmetic in f32 (a `width > 32` guess the semantics
    # backend had replaced with the format table), and a state loaded from
    # memory had its address masked to the state's width in the Python
    # executor, the golden model and both references alike -- so the three that
    # were checked agreed with each other. The every-corpus simulator sweep
    # found both. `matrix` and `access_map` are scalable and have their own
    # gates; the wide executors skip them.
    for name, corpus in (("half", "fp16"), ("bf16", "bf16"), ("fp8", "fp8"),
                         ("tile configuration", "tilecfg"),
                         ("contraction", "contraction"),
                         ("behavior forms", "behavior_forms"),
                         ("completion", "completion")):
        gate(f"{name} python exec", "exec_vs_golden.py", example(f"{corpus}.axisl"))
        gate(f"{name} wide C exec", "exec_wide_check.py", example(f"{corpus}.axisl"))
        gate(f"{name} wide Rust exec", "exec_wide_check.py", "--lang", "rust",
             example(f"{corpus}.axisl"))

    # A description that validates must emit. `iterate` bounds its expansion by
    # count and by nodes, and a contraction passes both while nesting one level
    # per step -- which every emitter walks recursively. Before the depth guard
    # a K = 1024 dot product passed `check` and aborted `emit-llvm-ir`.
    gate("expression depth", "expression_depth_check.py")

    # An accumulation's terms are independent, so its association is free --
    # and a free association is only free if choosing it cannot change the
    # answer. `exact` claims that and the obligation checks it; the float pair
    # shows the other side, where the order IS the value.
    gate("contraction C == golden", "c_vs_golden.py", example("contraction.axisl"))
    gate("contraction LLVM == golden", "llvm_vs_golden.py", example("contraction.axisl"))
    gate("contraction folds freely", "contraction_check.py",
         example("contraction.axisl"))

    gate("crosslane == architecture", "scalable_crosslane.py",
         example("scalable_crosslane.axisl"))
    # The order a reduction folds in is part of what it computes, and for the
    # unordered form the architecture declines to say. This sweeps both orders
    # AXIS pins, requires the pinned ones not to move, requires the associative
    # ones to re-associate and keep their value, and fails if no input can tell
    # the two realisations apart -- which would make the other three vacuous.
    gate("reduction order", "reduction_order_check.py",
         example("scalable_crosslane.axisl"))

    # --- SVE: Arm's own encodings and semantics (V1) ---------------------
    # sve.axisl began as stage S7, an illustrative SVE whose shapes were what
    # the S1-S6 mechanisms needed. It is now Arm's SVE, and the reference is
    # Arm's: every word is what llvm-mc reads as the named instruction, and
    # Arm's ASL model and all three executors must leave every X, Z, P, NZCV
    # and byte of memory alike. The hand-written SVE references of the
    # definedness, addressing, fault-suppression and cross-lane gates described
    # the illustrative shapes (unpredicated compares, a reduction into a
    # general register, inactive lanes unspecified); Arm's model checks the
    # same instructions exactly, so those gates keep RVV and the mechanism
    # corpora and no longer carry SVE. Arm's SVE has no partly-specified
    # result, so there is nothing for definedness to ask of it.
    gate("SVE corpus == its generator", "gen_sve.py", "--check", example("sve.axisl"))
    gate("SVE == Arm's specification", "sve_asl_check.py", example("sve.axisl"), slow=True)
    gate("SVE LLVM == golden", "llvm_vs_golden.py", example("sve.axisl"))
    gate("SVE C == golden", "c_vs_golden.py", example("sve.axisl"))
    gate("SVE lane packing", "lane_packing_check.py", example("sve.axisl"))
    # Scalable execution S1: the lanes carry encoding bits at all. Every lane of
    # one scalable instruction shares its origin's word by construction, so the
    # fixture set is one per word and the decoder has to tell "one instruction,
    # several lanes" from an ambiguous decode space. Before S1 these corpora
    # produced no fixtures whatsoever -- there was no word to encode.
    gate("SVE roundtrip", "roundtrip_check.py", example("sve.axisl"))
    gate("RVV roundtrip", "roundtrip_check.py", example("rvv.axisl"))
    # S2: where each element lives. Both corpora, and not for symmetry --
    # nothing in SVE groups registers, so a lane index and an element index are
    # the same number there and stamping one for the other passes. RVV's LMUL
    # separates them, and catches it.
    gate("SVE lane placement", "lane_placement_check.py", example("sve.axisl"))
    gate("RVV lane placement", "lane_placement_check.py", example("rvv.axisl"))
    # S3: the executor runs a scalable word by running its lanes, reading and
    # writing element-sized views of registers held as limbs. The reference has
    # neither -- a vector register is one integer and an element is a shift and
    # a mask.
    gate("SVE scalable exec", "scalable_exec_check.py", example("sve.axisl"))
    gate("RVV scalable exec", "scalable_exec_check.py", example("rvv.axisl"))
    # The same reference, driven through the generated C executor. It runs the
    # lanes, applies the placements and skips the selectors exactly as the
    # Python one does -- and had to be brought to that point, since a compiled
    # simulator is built on it.
    gate("SVE scalable exec (C)", "scalable_exec_check.py", "--lang", "c",
         example("sve.axisl"))
    gate("RVV scalable exec (C)", "scalable_exec_check.py", "--lang", "c",
         example("rvv.axisl"))
    # And through the generated Rust executor, which ran no scalable
    # instruction until it gained lane views and the lane loop its C twin had:
    # it declined 236 of SVE's 260 cases and this gate counted only FAIL
    # lines, so a decline was never a failure. Now a decline is one, and both
    # compiled executors carry the three corpora that pass on them too.
    gate("SVE scalable exec (Rust)", "scalable_exec_check.py", "--lang", "rust",
         example("sve.axisl"))
    gate("RVV scalable exec (Rust)", "scalable_exec_check.py", "--lang", "rust",
         example("rvv.axisl"))
    for corpus, label in (("scalable_crosslane", "cross-lane"), ("scalable_vtype", "vtype"),
                          ("matrix", "matrix")):
        for lang, name in (("c", "C"), ("rust", "Rust")):
            gate(f"{label} scalable exec ({name})", "scalable_exec_check.py", "--lang", lang,
                 example(f"{corpus}.axisl"))
    # S4: the same words compiled and run in process. The block calls the
    # proven scalar handlers -- a lane instruction's handler is an ordinary
    # one -- so what is under test is the placement in the emitted IR: which
    # slot each element loads from, and inserting a result without disturbing
    # its neighbours.
    # The length is a floor, not a cap: every block carries one word of each
    # shape the corpus offers -- unit, strided, indexed and segment, in both
    # directions -- so a run cannot be green about a mode it never compiled.
    # Small pools on purpose. Coverage comes from every block carrying one word
    # of every shape, not from volume -- so 12 executions prove what 40 did,
    # and an SVE block is 16 lanes per word.
    gate("SVE scalable JIT", "jit_llvm.py", "--scalable", "--distinct", "4",
         "--programs", "12", "--length", "6", example("sve.axisl"), slow=True)
    gate("RVV scalable JIT", "jit_llvm.py", "--scalable", "--distinct", "4",
         "--programs", "12", "--length", "6", example("rvv.axisl"))

    # RVV: the half of S7 that exercises stage S3, because its shapes come from
    # a dynamic CSR rather than from the instruction. The sweep is here rather
    # than only on the S3 corpus because this is where vtype actually belongs.
    gate("RVV LLVM == golden", "llvm_vs_golden.py", example("rvv.axisl"))
    gate("RVV C == golden", "c_vs_golden.py", example("rvv.axisl"))
    gate("RVV Rust == golden", "rust_vs_golden.py", example("rvv.axisl"))
    gate("RVV definedness", "scalable_definedness.py", example("rvv.axisl"))
    gate("RVV addressing", "scalable_addressing.py", example("rvv.axisl"))
    gate("RVV fault suppression", "scalable_faulting.py", example("rvv.axisl"))
    gate("RVV cross-lane", "scalable_crosslane.py", example("rvv.axisl"))
    gate("RVV (SEW, LMUL) sweep", "scalable_modes.py", "--backend", "smt",
         example("rvv.axisl"))
    # Saturation and float predicates are written compositionally in the
    # corpus, which puts the overflow rule where it can be read -- and where it
    # could be wrong the same way in every backend. Stated independently here,
    # with inputs drawn against both boundaries: saturation is rare among random
    # pairs, and an ordered compare differs from an unordered one only on NaN.
    gate("RVV saturation == architecture", "saturating_check.py", example("rvv.axisl"))
    # Where each lane element sits: how many registers past the encoded one and
    # which element within it. The corpus is written at LMUL 1, where every
    # element is in register 0 and the rule is untested, so the gate also
    # instantiates at LMUL 4 and requires operands to land past the first
    # register.
    gate("RVV lane packing == architecture", "lane_packing_check.py", example("rvv.axisl"))

    # --- bounded loops ----------------------------------------------------
    # A loop carries an accumulator between iterations, which is the one shape
    # lane expansion cannot express -- lanes are independent by construction.
    # The last gate *proves* rather than samples: a loop-defined popcount has a
    # reference inside the language, so SMT can decide equality for every input.
    gate("loops LLVM == golden", "llvm_vs_golden.py", example("loops.axisl"))
    gate("loops C == golden", "c_vs_golden.py", example("loops.axisl"))
    gate("loops Rust == golden", "rust_vs_golden.py", example("loops.axisl"))
    gate("loop == built-in (proved)", "loop_equivalence.py", example("loops.axisl"))
    # And through decode: every instruction in that corpus left its `zm` field
    # unpinned, so none of them was encodable and none had ever reached an
    # executor. The value backends above were proving expressions nothing could
    # build a word for.
    gate("loops python exec", "exec_vs_golden.py", example("loops.axisl"))
    # Statement-level loops: one instruction, many effects. The executor gates
    # cannot reach these -- roundtrip fixtures come from instructions that write
    # a register, and a block copy writes only memory -- so this states the
    # shapes independently instead.
    gate("block memory == architecture", "blockmem_check.py", example("blockmem.axisl"))
    # These run the block copies rather than reading them, which became
    # possible once the corpus stopped leaving an encoding field unbound. The C
    # and Rust executors still skip: they drive the compact 32-bit ABI and a
    # block copy takes 64-bit pointers.
    gate("block memory python exec", "exec_vs_golden.py", example("blockmem.axisl"))
    gate("block memory LLVM effects", "llvm_effects_check.py", example("blockmem.axisl"))
    gate("block memory wide C exec", "exec_wide_check.py", example("blockmem.axisl"))
    gate("block memory wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("blockmem.axisl"))
    # The 32-bit copy in that corpus is what gives the *compact* emitters a
    # store-of-load to lower; without it neither had ever been asked for one.
    gate("block memory C exec", "exec_c_check.py", example("blockmem.axisl"))
    gate("block memory Rust exec", "exec_rust_check.py", example("blockmem.axisl"))

    # --- the stencil JIT ----------------------------------------------------
    # One template per instruction compiled ahead of time, with the operands
    # left as holes a relocation names; translation copies the bytes and fills
    # the holes in. The gate checks that each stencil has exactly the holes its
    # operands imply, that a patched one agrees with the golden model, and that
    # they compose into a block -- and reports what translation costs against
    # compiling the same block, which is the only reason to do any of it.
    gate("stencil JIT: zbb", "jit_stencil.py", example("zbb_like.axisl"),
         "--run", "--blocks", "20")
    gate("stencil JIT: RV32I", "jit_stencil.py", example("rv32i.axisl"),
         "--run", "--blocks", "20")
    gate("stencil JIT: RV64I", "jit_stencil.py", example("rv64i.axisl"),
         "--run", "--blocks", "20")
    # Mixed mode, which is what a JIT actually runs in: a run of stencilable
    # words becomes one patched block, and the first word that is not -- an
    # effectful instruction -- ends it and is stepped by the executor. Both
    # halves have to happen, and the gate fails if a run is all of one. RV32I
    # and RV64I, because a corpus of pure arithmetic never leaves translated
    # code and proves nothing about coming back to it.
    # Mixed mode now translates loads, stores and atomics as well as
    # arithmetic; what is still stepped is branches and traps, which end a block
    # in any JIT. An atomic is translated only when its base is naturally
    # aligned -- arm64 faults otherwise, and RISC-V requires it of AMOs too.
    gate("stencil JIT: mixed RV32I", "jit_stencil.py", example("rv32i.axisl"),
         "--execute", "16", "--length", "16")
    gate("stencil JIT: mixed RV64I", "jit_stencil.py", example("rv64i.axisl"),
         "--execute", "16", "--length", "16")

    # --- the functional simulator ------------------------------------------
    # `emit-sim-c` is a machine: fetch from the pc, execute every lane of the
    # word, follow the pc it computes, with a hook table for memory, traps and
    # retirement. What it adds over the executor is the loop, so the gate runs
    # whole programs and compares the architectural delta. Three corpora
    # because each covers what the others cannot: RV64I branches, effects_trap
    # raises a trap, and SVE puts scalable lanes and vector memory through it.
    gate("simulator: RV64I", "sim_vs_executor.py", example("rv64i.axisl"),
         "--programs", "12", "--length", "10")
    gate("simulator: traps", "sim_vs_executor.py", example("effects_trap.axisl"),
         "--programs", "12", "--length", "10")
    gate("simulator: SVE", "sim_vs_executor.py", example("sve.axisl"),
         "--programs", "6", "--length", "6")
    gate("simulator: RVV", "sim_vs_executor.py", example("rvv.axisl"),
         "--programs", "6", "--length", "6")
    # ⚠️ And AArch64, which this gate was NOT registered for and should have
    # been. Every corpus above describes one machine; AArch64 describes two
    # ISAs, and running it turned up a harness bug that only a multi-ISA corpus
    # could show -- and then, once fixed, a silent truncation of every 128-bit
    # value in both generated executors. A gate that finds two defects the
    # first time it is pointed at a corpus was pointed at too few corpora.
    gate("simulator: A64", "sim_vs_executor.py",
         example("aarch64_translation_seed.axisl"),
         "--programs", "8", "--length", "10")
    # ⚠️ And every other corpus. This gate ran on five of fifty-six, and the
    # one time it was pointed at a sixth it found two defects immediately.
    # Widening it found three more: a harness that gave guarded branches and
    # guarded traps to the same programs so neither was reached, a 128-bit
    # operand in a one-limb register class that made the executor write past
    # the register into its neighbour, and a reference model that reported
    # `undecoded` where the machine reported `unimplemented`.
    #
    # One gate rather than fifty-one: the number worth reporting is how many
    # descriptions this machine can run, and the three it cannot are named
    # with the reason rather than left out of the count.
    gate("simulator: every corpus", "sim_vs_executor.py", "--all",
         "--programs", "8", "--length", "10", slow=True)

    # ⚠️ The tier above `A64 wide C exec`, which executes at 64 bits and names
    # the twenty cases past the register slot without running them. They run
    # now -- the executors hold a wide value as limbs -- and this drives every
    # one against the golden model with random contents in EVERY limb. Seeding
    # only the low half would agree with anything: the carry, the cross-limb
    # shift and the wide multiply would never be exercised.
    gate("wide arithmetic: A64", "wide_arith_check.py",
         example("aarch64_translation_seed.axisl"))
    # Both executors, because both have a limb runtime and neither is the
    # other's proof. The Rust one was written second and its shifts were
    # exercised by the instructions while its carries were not -- the same gap
    # the C one had, found the same way.
    gate("wide arithmetic: A64 (Rust)", "wide_arith_check.py",
         example("aarch64_translation_seed.axisl"), "--lang=rust")

    # --- register slices --------------------------------------------------
    # Overlapping views of one register: width, offset, and what a write does to
    # the bits outside the view. The executor gates prove the emitters honour
    # the table and cannot notice a table that is wrong -- they read it too --
    # so the last one states the views from the architectures instead.
    gate("register slices wide C", "exec_wide_check.py", example("regslice.axisl"))
    gate("register slices wide Rust", "exec_wide_check.py", "--lang", "rust",
         example("regslice.axisl"))
    gate("register views == architecture", "register_slice_check.py",
         example("regslice.axisl"))

    # --- limbs: registers wider than a machine word -------------------------
    # A register occupies several 64-bit slots, so a view can sit inside one, be
    # exactly one, or straddle two -- and only the last needs stitching, so a
    # corpus of in-limb views would pass an implementation that never stitches.
    # The first two gates are differential and share the table with the
    # emitters; the last two state the layout as whole registers instead, which
    # is what catches a table that is wrong rather than an executor that is.
    # Measured: moving v128_cross's view to bit 32, flipping v128_z0 to
    # preserving, or claiming three limbs for v128_d1 leaves both wide gates
    # passing and fails both references.
    gate("limbs wide C exec", "exec_wide_check.py", example("limbs.axisl"))
    gate("limbs wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("limbs.axisl"))
    gate("limbs == whole-register C", "limb_check.py", example("limbs.axisl"))
    gate("limbs == whole-register Rust", "limb_check.py", "--lang", "rust",
         example("limbs.axisl"))
    # The Python executor has the same stitch and no differential gate of its
    # own -- the compact python-exec check does not model views at all -- so
    # this reference is the only thing standing behind it.
    gate("limbs == whole-register Python", "limb_check.py", "--lang", "python",
         example("limbs.axisl"))

    # --- lane-wise IEEE-754 SIMD (stage F2): V1's lanes with F1's floats -----
    for backend, tool in (("LLVM", "llvm_vs_golden.py"), ("SMT", "smt_vs_golden.py"),
                          ("C", "c_vs_golden.py"), ("Rust", "rust_vs_golden.py")):
        gate(f"SIMD-FP {backend} == golden", tool, example("simd_fp_lanes.axisl"))
    gate("SIMD-FP python exec", "exec_vs_golden.py", example("simd_fp_lanes.axisl"))

    # --- RV32I: the second real ISA, complete -------------------------------
    for backend, tool in (("LLVM", "llvm_vs_golden.py"), ("SMT", "smt_vs_golden.py"),
                          ("C", "c_vs_golden.py"), ("Rust", "rust_vs_golden.py")):
        gate(f"RV32I {backend} == golden", tool, example("rv32i.axisl"))
    gate("RV32I python exec", "exec_vs_golden.py", example("rv32i.axisl"))
    gate("RV32I C exec", "exec_c_check.py", example("rv32i.axisl"))
    gate("RV32I Rust exec", "exec_rust_check.py", example("rv32i.axisl"))
    gate("RV32I roundtrip", "roundtrip_check.py", example("rv32i.axisl"))
    gate("RV32I lift roundtrip", "lift_roundtrip.py", example("rv32i.axisl"))
    gate("RV32I LLVM effects", "llvm_effects_check.py", example("rv32i.axisl"))


    # --- RV64I: the same opcodes reinterpreted at 64 bits, plus the W forms.
    # --- The compact C and Rust executors are a 32-bit ABI, so they have no
    # --- fixtures here; the same boundary AArch64 sits on.
    for backend, tool in (("LLVM", "llvm_vs_golden.py"), ("SMT", "smt_vs_golden.py"),
                          ("C", "c_vs_golden.py"), ("Rust", "rust_vs_golden.py")):
        gate(f"RV64I {backend} == golden", tool, example("rv64i.axisl"))
    gate("RV64I python exec", "exec_vs_golden.py", example("rv64i.axisl"))
    gate("RV64I roundtrip", "roundtrip_check.py", example("rv64i.axisl"))
    gate("RV64I lift roundtrip", "lift_roundtrip.py", example("rv64i.axisl"))
    gate("RV64I LLVM effects", "llvm_effects_check.py", example("rv64i.axisl"))
    # ⚠️ NOT the compact driver: its ABI is 32 bits and every RV64I instruction
    # is wider, so `RV64I Rust exec` skipped every run and RV64I's Rust
    # executor was executed by nothing at all. The skip said "no executable
    # fixtures", which reads as a corpus without fixtures -- RV64I has 1028 --
    # and sent a reader looking for the wrong thing. It names the width now,
    # and this is the gate it points at: 424 instructions against the golden
    # model, the rest declined for directed rounding.
    gate("RV64I wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("rv64i.axisl"), slow=True)
    # Two more the C executor was gated on and the Rust one was not, found by
    # asking which corpora have one and not the other. `fp_exceptions` is the
    # third and is deliberately absent: Rust declines all twelve of its
    # instructions, and a gate that executes nothing asserts nothing.
    gate("icmp wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("icmp_ops.axisl"))
    gate("icount wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("policy_icount.axisl"))
    # The compact 32-bit driver skips everything wider, which for RV64I is all
    # of it -- that gate has never run. This one drives the same fixtures
    # through axis_exec_step64, the general wide entry point the emitted header
    # has always had and only AArch64's bespoke harness ever used.
    # The same question for shift amounts, and the corpus that had to exist
    # before any backend answered it the same way twice. Narrow nodes only: at
    # 64 bits the amount cannot exceed the width in the way the old rules got
    # wrong, so a corpus of 64-bit shifts proves nothing here.
    gate("shift widths: golden == C", "c_vs_golden.py",
         example("shift_widths.axisl"))
    gate("shift widths: golden == Rust", "rust_vs_golden.py",
         example("shift_widths.axisl"))
    gate("shift widths: golden == LLVM", "llvm_vs_golden.py",
         example("shift_widths.axisl"))
    gate("shift widths: golden == SMT", "smt_vs_golden.py",
         example("shift_widths.axisl"))
    gate("shift widths python exec", "exec_vs_golden.py",
         example("shift_widths.axisl"))
    gate("shift widths wide C exec", "exec_wide_check.py",
         example("shift_widths.axisl"))
    gate("shift widths wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("shift_widths.axisl"))
    # `asm_disasm.json` is a self-contained account of how an instruction is
    # spelled and where its operands' bits live. It shipped in the bundle with
    # only its presence checked, so this builds an assembler and a
    # disassembler out of the artifact alone and runs them against the fixtures
    # the encoder already proves.
    gate("asm/disasm description", "asm_disasm_check.py", example("rv64i.axisl"))
    gate("asm/disasm description (RV32)", "asm_disasm_check.py",
         example("rv32i.axisl"))
    gate("asm/disasm description (A64)", "asm_disasm_check.py",
         example("aarch64_translation_seed.axisl"))
    gate("asm/disasm description (lanes)", "asm_disasm_check.py",
         example("scalable_basic.axisl"))
    gate("asm/disasm description (limbs)", "asm_disasm_check.py",
         example("simd_q_lanes.axisl"))
    # `decode_table.json` is the table a decoder is built from. Two tools read
    # it and neither decoded with it, so nothing checked the one property it
    # exists to have: a word picks out exactly one instruction.
    gate("decode table selects one", "decode_table_check.py",
         example("rv64i.axisl"))
    gate("decode table selects one (A64)", "decode_table_check.py",
         example("aarch64_translation_seed.axisl"))
    gate("decode table selects one (modes)", "decode_table_check.py",
         example("mode_polymorphic.axisl"))
    gate("decode table selects one (slots)", "decode_table_check.py",
         example("vliw_packet.axisl"))
    gate("decode table selects one (lanes)", "decode_table_check.py",
         example("sve.axisl"))
    # The generated decoder is a tree now, not a scan: a table of 854 entries
    # cost 854 mask/compare pairs and a strcmp each per word. Both decoders are
    # emitted, and this is the reason the fast one is trustworthy -- the scan is
    # what the tree is checked against, over every corpus, on match words, on
    # their operand bits randomised, on every single-bit near miss, and on
    # random words that should find nothing.
    gate("decode tree == linear scan", "decode_tree_check.py")
    # AXISMINE.1 wants "a decoder generated from the ISA description" in a
    # Python miner. The wrong way to get one is to read `decode_table.json` and
    # write the match/mask loop again -- that is a second decoder, with its own
    # selection rules to keep in agreement. `axis_decode_ffi` binds the
    # compiled one instead, and this checks the boundary rather than the logic:
    # the identity fields against `emit-decode-json`, operand extraction
    # against the encoder over every roundtrip fixture, and the edges.
    gate("bound decoder == compiled decoder", "decode_ffi_check.py")
    # AXISMINE's caveat 4: a kernel corpus cannot exercise what a real binary
    # has, so what a description is missing is exactly what no benchmark shows.
    # `binary_coverage.py` decodes an object file and reports what did not
    # decode. Coverage against a real binary is a measurement and this asserts
    # nothing about the number -- what it asserts is that the readers are
    # right, since every way of misreading a section header shows up as a lower
    # coverage number that reads like an honest finding about the corpus.
    gate("object readers lose no instruction", "binary_coverage_check.py")
    # The only gate here that knows what the architecture says. Every other one
    # compares AXIS against AXIS -- encoder, decoder, executors, golden model
    # and LLVM backend all agree on whatever the description says -- which is
    # why `FADD_D` sat at `(fixed 483)`, in the SIMD load/store space, for the
    # whole life of the corpus with 286 green gates around it.
    gate("encodings == reference assembler", "reference_isa_check.py")
    # A family corpus: its assembly used to interpolate a family parameter into
    # the text, which expansion did not substitute.
    gate("asm/disasm description (family)", "asm_disasm_check.py",
         example("icmp_ops.axisl"))
    # The shapes that each needed the description to say more than it did:
    # scalable lanes and definedness variants, a strided load's stride, a
    # predicate destination, and an instruction that spells no assembly at all
    # and gets a synthesised one.
    gate("asm/disasm description (SVE)", "asm_disasm_check.py",
         example("sve.axisl"))
    gate("asm/disasm description (RVV)", "asm_disasm_check.py",
         example("rvv.axisl"))
    gate("asm/disasm description (synthesised)", "asm_disasm_check.py",
         example("zbb_like.axisl"))
    gate("asm/disasm description (crosslane)", "asm_disasm_check.py",
         example("scalable_crosslane.axisl"))
    # Two instructions sharing a decode word, told apart by the mode they run
    # in or the packet slot their unit occupies -- which the description now
    # says, because the model always knew and the file never did.
    gate("asm/disasm description (modes)", "asm_disasm_check.py",
         example("mode_polymorphic.axisl"))
    gate("asm/disasm description (slots)", "asm_disasm_check.py",
         example("vliw_packet.axisl"))
    # `emit-python` is the one artifact that is a second rendering of another:
    # the JSON manifests, as Python literals. Rendered by rewriting three words,
    # which used to rewrite them inside string values too.
    gate("python manifest == json", "manifest_python_check.py")
    # `ones`/`zeros`: the counts here come from a register, so the gates reach
    # the at-and-past-the-width case a literal never would -- which is the case
    # every backend had to state separately, `1 << n` meaning something
    # different in each of them.
    gate("masks: golden == C", "c_vs_golden.py", example("masks.axisl"))
    gate("masks: golden == Rust", "rust_vs_golden.py", example("masks.axisl"))
    gate("masks: golden == LLVM", "llvm_vs_golden.py", example("masks.axisl"))
    gate("masks: golden == SMT", "smt_vs_golden.py", example("masks.axisl"))
    gate("masks python exec", "exec_vs_golden.py", example("masks.axisl"))
    gate("masks wide C exec", "exec_wide_check.py", example("masks.axisl"))
    gate("masks wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("masks.axisl"))
    # RV32I had neither wide gate, which is how a reference-side address bug
    # sat in a corpus the compact checks all passed: the 32-bit machine is the
    # one whose addresses wrap below the executor's 64-bit slot width, so it is
    # the corpus that had the most to say and the least asked of it.
    gate("RV32I wide C exec", "exec_wide_check.py", example("rv32i.axisl"))
    gate("RV32I wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("rv32i.axisl"))
    gate("RV64I wide C exec", "exec_wide_check.py", example("rv64i.axisl"))
    gate("RV64I wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("rv64i.axisl"))

    # --- integer comparisons: the operators a flagless ISA needs -------------
    for backend, tool in (("LLVM", "llvm_vs_golden.py"), ("SMT", "smt_vs_golden.py"),
                          ("C", "c_vs_golden.py"), ("Rust", "rust_vs_golden.py")):
        gate(f"icmp {backend} == golden", tool, example("icmp_ops.axisl"))
    gate("icmp python exec", "exec_vs_golden.py", example("icmp_ops.axisl"))

    # --- explicit rounding modes (stage F3). Three backends, not five: Rust and
    # --- LLVM decline directed rounding with the reason in the emitted file.
    gate("FP rounding C == golden", "c_vs_golden.py", example("fp_rounding.axisl"))
    gate("FP rounding python exec", "exec_vs_golden.py", example("fp_rounding.axisl"))
    # GRV's SIMT predication surface: encode/decode agreement, which the corpus
    # exists to keep in step, and execution against the golden model. It had no
    # gate because `exec_vs_golden` seeded state from a hardcoded list of five
    # names and crashed on a sixth.
    gate("GRV SIMT roundtrip", "roundtrip_check.py", example("grv_simt.axisl"))
    gate("GRV SIMT python exec", "exec_vs_golden.py", example("grv_simt.axisl"))

    # --- execution: binary -> execute, per backend ------------------------
    # `effects_pure` is the baseline the others are read against -- a pure
    # instruction whose `effects` desugars to `formal_semantics` and must stay
    # byte-identical. docs/effects_design.md says it is "proven across the
    # C/Rust/SMT differential harnesses"; it was, through a frontend-equivalence
    # gate that went with the block grammar, and nothing replaced it.
    for corpus in ("fuzz_mix", "effects_pure", "effects_mem", "effects_store",
                   "effects_branch", "effects_trap", "effects_guarded_set"):
        gate(f"python exec: {corpus}", "exec_vs_golden.py", example(f"{corpus}.axisl"))
        gate(f"C exec: {corpus}", "exec_c_check.py", example(f"{corpus}.axisl"))
        gate(f"Rust exec: {corpus}", "exec_rust_check.py", example(f"{corpus}.axisl"))
    # The counter's own width, which only an indirect branch can put in
    # question: every other `setpc` in every corpus is arithmetic, and an
    # operator masks its own result. `effects_branch` carries one whose target
    # is a bare register and whose state write is what brings it into the wide
    # driver's reach at all.
    # Where the two C paths now meet. The wide driver runs every instruction
    # the ABI can hold, so these corpora are checked by both generated
    # executors against one reference rather than by whichever the width
    # happened to select -- which is how a signed guard stayed unsigned in one
    # of them, an arithmetic shift of a 16-bit lane stayed unsigned in the
    # other, and four Zbb operators existed in one and not the other.
    gate("SIMD lanes wide C exec", "exec_wide_check.py", example("simd_lanes.axisl"))
    gate("SIMD lanes wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("simd_lanes.axisl"))
    gate("zbb wide C exec", "exec_wide_check.py", example("zbb_like.axisl"))
    gate("zbb wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("zbb_like.axisl"))
    # F1: description-defined functions, emitted once and called. Every backend
    # against the golden model, and the golden model's calls against the same
    # functions inlined -- the one comparison a shared calling mistake fails.
    gate("deffun: called == inlined", "deffun_check.py", example("functions.axisl"))
    for tool, label in (("c_vs_golden.py", "C"), ("rust_vs_golden.py", "Rust"),
                        ("llvm_vs_golden.py", "LLVM"), ("smt_vs_golden.py", "SMT")):
        gate(f"deffun {label} == golden", tool, example("functions.axisl"))
    gate("deffun C exec", "exec_c_check.py", example("functions.axisl"))
    gate("deffun Rust exec", "exec_rust_check.py", example("functions.axisl"))
    gate("deffun wide C exec", "exec_wide_check.py", example("functions.axisl"))
    gate("deffun wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("functions.axisl"))
    gate("deffun roundtrip", "roundtrip_check.py", example("functions.axisl"))
    gate("icmp wide C exec", "exec_wide_check.py", example("icmp_ops.axisl"))
    # The identity instruction, which is the one shape whose value no operator
    # masks: `(formal rs1)` returns whatever the register held, so a 32-bit
    # machine returned all 64 bits of the slot it is carried in. Every other
    # corpus computes something, and computing masks.
    gate("identity wide C exec", "exec_wide_check.py", example("policy_icount.axisl"))
    gate("branch targets wide C exec", "exec_wide_check.py",
         example("effects_branch.axisl"))
    gate("branch targets wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("effects_branch.axisl"))
    gate("cross-executor fuzz", "exec_fuzz.py")

    # --- JIT backends -----------------------------------------------------
    gate("JIT (transpiling C)", "jit_c.py")
    gate("JIT (LLVM, pure)", "jit_llvm.py", example("zbb_like.axisl"))
    gate("JIT (LLVM, effects)", "jit_llvm.py", example("fuzz_mix.axisl"))
    gate("JIT (LLVM, guarded)", "jit_llvm.py", example("effects_guarded_set.axisl"))
    gate("LLVM effects", "llvm_effects_check.py", example("fuzz_mix.axisl"))
    gate("LLVM effects (guarded)", "llvm_effects_check.py",
         example("effects_guarded_set.axisl"))

    # --- modes, personalities, compiler collateral ------------------------
    gate("mode legality", "legality_vs_golden.py", example("mode_polymorphic.axisl"))
    gate("capsule migration", "migrate_vs_whole.py", example("personality_composition.axisl"))
    # docs/personality_design.md names this harness against this corpus.
    gate("capsule migration: tile", "migrate_vs_whole.py", example("personality_tile.axisl"))
    gate("llvm-tblgen intrinsics", "tablegen_validate.py")
    # And what the patterns *mean*. tblgen-valid is syntax, and the patterns
    # file is not even that -- it references the RISC-V TableGen tree, so
    # `tablegen_validate.py` declines it. A `Pat<>` claims two things compute
    # the same function; this evaluates the DAG against the golden model and
    # says whether they do. Five corpora, because the bug it found first was
    # invisible at 32 bits.
    for corpus in ("zbb_like", "rv32i", "rv64i", "aarch64_translation_seed",
                   "rvmt_xpce"):
        gate(f"ISel patterns: {corpus}", "llvm_patterns_check.py",
             example(f"{corpus}.axisl"))

    # A generated LLVM target is only worth having if it encodes what AXIS
    # encodes. `llvm-tblgen` accepting the .td proves it parses; this compiles
    # the encoder LLVM generates from it and runs it against AXIS's own.
    # Twelve corpora, because what one can see another cannot: binding an
    # operand from the wrong slice is invisible to RVV, which has no
    # scattered operand, and obvious to RV64I, which has six.
    for corpus in ("zbb_like", "rv32i", "rv64i", "aarch64_translation_seed",
                   "rvmt_xpce", "simd_lanes", "rvv", "sve", "scalable_memory",
                   "fp_scalar", "limbs", "regslice"):
        # The gate also runs --gen-dag-isel, which builds a matcher from the
        # target's own selection patterns.
        gate(f"LLVM target MC: {corpus}", "llvm_target_check.py",
             example(f"{corpus}.axisl"), "--trials", "16")

    # --- PCE consumer contract --------------------------------------------
    gate("PCE contract", "pce_contract_check.py")
    if with_pce:
        gate("PCE smoke (needs PCE)", "pce_smoke_check.py")
        # H4a: AXIS's netlists as the semantics of URV's extension unit --
        # PCE's loader, PCE's registry, PCE's unit, unmodified -- issued by
        # opcode and read at the completion port.
        gate("netlists in URV's extension slot (needs PCE)", "hw_urv_check.py",
             example("zbb_like.axisl"))

    # --- AArch64 corpus (slow) --------------------------------------------
    gate("A64 LLVM == golden", "llvm_vs_golden.py",
         example("aarch64_translation_seed.axisl"), slow=True)
    gate("A64 C == golden", "c_vs_golden.py",
         example("aarch64_translation_seed.axisl"), slow=True)
    gate("A64 Rust == golden", "rust_vs_golden.py",
         example("aarch64_translation_seed.axisl"), slow=True)
    # A region lifted from bytes, against the executor. The block drivers above
    # compile a block the harness hands them; this one hands over bytes and
    # lets the lifter decide where the blocks are, which is the part only it
    # does -- discovery, branch folding, and constant register slots.
    gate("lift region: RV64I", "lift_region_check.py", example("rv64i.axisl"),
         "--regions", "40")
    gate("lift region: RV32I", "lift_region_check.py", example("rv32i.axisl"),
         "--regions", "40")
    gate("lift region: effects", "lift_region_check.py",
         example("fuzz_mix.axisl"), "--regions", "40")
    gate("lift region: guarded", "lift_region_check.py",
         example("effects_guarded_set.axisl"), "--regions", "40")
    # Every instruction the lifter takes, lifted alone and run against the
    # executor. One instruction is the smallest region there is, so a failure
    # here names an instruction rather than a neighbourhood -- and it is the
    # only lifting check AArch64 currently passes, because a region of several
    # AArch64 instructions still diverges.
    # Mining a compiled object for instruction-set extensions, and proving each
    # one computes what it replaces. The whole loop -- decode, block, thread,
    # compose, propose, discharge -- on a binary built during the run. Then
    # each proven proposal built: its netlist held to the golden model, and
    # priced alone and in the units of the description it was mined from.
    # Then run: each extension encoded, put in the program at its occurrences,
    # and both programs run on the simulator -- equal results, fewer cycles.
    gate("ISE mining == the code it replaces", "ise_check.py", slow=True)
    # The same invariant for SMT, where it matters most: the ISE miner composes
    # these define-funs to prove a candidate extension equal to what it
    # replaces, so an instruction silently absent is one a proof quietly does
    # not cover.
    gate("SMT accounts for every instruction", "smt_accounted_check.py")

    # Every instruction is either lowered to LLVM IR or named as not lowered.
    # An instruction that vanished from the file with no function and no comment
    # was invisible: the pure path's "no formal_semantics" note says that about
    # every effectful instruction, so it could not distinguish one the effect
    # path had also dropped.
    gate("LLVM accounts for every instruction", "llvm_accounted_check.py")

    # Two executors generated from one description should run the same program.
    # Where a language genuinely prevents that -- Rust has no fesetround -- the
    # difference must be STATED in the artifact, not left as a missing function.
    gate("executor parity", "executor_parity_check.py")

    # An instruction whose semantics are undecided or unexpressible may name a
    # routine the embedder supplies. Only a consumer that RUNS code may call it,
    # so this checks the one thing askable about an opaque routine: that it is
    # reached, with the operands the instruction decoded.
    # An architecture built as something an external project links, and the
    # property that makes that useful: several at once. The ABI this replaces
    # gave every description the same symbol names, so a base pack and an
    # extension linked together silently yielded one of them.
    gate("pack composition", "pack_check.py")

    # The sixth library: instructions translated to machine code by copying
    # stencils and patching operand holes, then RUN, against the executor in
    # the same binary. ⚠️ The executor is the reference because it is already
    # held to the golden model; comparing the JIT against another JIT is how
    # the pre-library gate came to index the register file raw on both sides
    # and call `c.sub`'s `x8` `x1`.
    # The seventh library, and the only one that RUNS: it fetches, decides
    # what a trap does, and reports what each instruction did. Held to the
    # executor beside it through the contract a consumer links, which is a
    # different claim from `simulator: every corpus` -- everything between
    # them is adapter code.
    gate("simulator library", "sim_pack_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    # The eighth library: the proven SMT definitions, bound into a solver's
    # context so a consumer applies them rather than deriving a second set.
    # ⚠️ The semantics are not that library's -- `emit-smt2`'s gates prove them
    # -- so this checks everything AROUND them, all of which can be wrong
    # quietly: which function a mnemonic names, what order its operands go in,
    # what sorts they have, and whether an ill-formed call is refused.
    gate("solver library", "z3_pack_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    # ⚠️ The one effect that leaves the machine without leaving an address
    # behind. A `send` is held the way every other effect is: three backends,
    # one golden model, compared bit for bit -- and what is compared is the
    # ORDERED LOG, because a message is not readable back. The guard case is
    # what separates "this happened" from "this was evaluated".
    gate("a message leaves the machine", "send_check.py",
         example("effects_send.axisl"))

    # ⚠️ A PROGRAM, not an instruction. An image on disk with an entry point,
    # loaded the way a loader loads one, started where it says to start, and
    # run until it stops itself -- which is the shape a co-design question has.
    # "Is this extension worth it" is not a question about one instruction.
    gate("a program runs", "workload_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    # ⚠️ The declared COSTS, made load-bearing. Every instruction carries a
    # latency and a throughput, and until the simulator grew a scoreboard
    # nothing read them -- which makes them free text, and any co-design number
    # built on them a quotation of its author. Held by properties rather than
    # by a second copy of the model: a chain costs its latency each, the same
    # instructions independent cost their issue interval, and the ratio is the
    # number the description declares.
    gate("declared latency", "cycle_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    # ⚠️ The MEMORY SYSTEM, which is the other half of a co-design answer.
    # The scoreboard charges what the description declares; a cache charges
    # what a machine does with the addresses a program computes, and only the
    # two together can tell a working set that fits from one that does not --
    # the question an instruction count cannot be asked at all. Held by
    # properties: a second pass over a set that fits is free, a set that does
    # not misses every time, two ways hold two colliding lines and not three,
    # hits plus misses is every access, and a miss costs exactly its penalty
    # in cycles. The cache is the MACHINE's, configured per machine, and
    # deliberately absent from the language.
    gate("a working set that fits", "cache_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    # ⚠️ A SWEEP, which is the shape a co-design study has: hold the program
    # fixed, vary the machine, and read the curve. Until a miss cost cycles
    # there was nothing to plot -- every variant reported the same number. The
    # workload is a strided walk over a working set of known size, so the
    # curve is checkable arithmetic rather than a picture: it is monotone, its
    # knee lands exactly on the working set, nothing beats the compulsory
    # misses, and cycles fall with misses by exactly the miss penalty. The
    # stride is measured off the memory interface, because what one unit of an
    # immediate moves an address by is the description's business.
    gate("the knee is the working set", "sweep_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    # ⚠️ The axis a DESIGNER edits. cycle_check proves the simulator uses the
    # declared latency and sweep_check varies the machine; neither varies the
    # description itself, and a stack where editing the source does not change
    # the answer is one where the source is decoration. One instruction's
    # latency is raised, the pack rebuilt from the edited text, and the same
    # program run on both: a dependent chain moves by exactly the difference
    # times its depth, an independent stream does not move at all, and both
    # machines leave the same registers -- a cost is not a meaning.
    gate("an edited description", "variant_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    # ⚠️ A MACHINE is not its instruction set. AXIS describes VLIW packets,
    # unit-typed slots and fabrics, and the only thing producing a NUMBER
    # issued one instruction at a time -- so a four-wide machine with three
    # adders reported what a scalar one did. `defcore` now declares a width
    # and its units, and the scoreboard contends for them. The anchor is what
    # makes it trustworthy: a core of one issue slot with one pipelined copy
    # of every unit IS the first-order model, and has to agree with it cycle
    # for cycle on the same programs.
    gate("a machine is not its ISA", "core_check.py",
         example("issue_width.axisl"))

    # ⚠️ And the MEMORY a machine declares. `defmemory` carried size, latency,
    # ports and banks since before anything could run a program, and nothing
    # computed with any of it -- the shape `area-estimate-um2` still has, and
    # the shape `latency` had until a scoreboard read it. A core now names the
    # memory it runs against and selecting it applies that cache. This is the
    # correction to what the cache landed with: keeping it off
    # `definstruction` was right, because an instruction means the same thing
    # on every machine; keeping it out of the LANGUAGE was not, because AXIS
    # has machine-side forms and a machine is where a cache lives.
    gate("the described cache", "described_cache_check.py",
         example("issue_width.axisl"))

    # ⚠️ And what a TAKEN branch costs. A machine that does not predict
    # fetches the fall-through, and when the branch goes elsewhere the front
    # end starts again -- most of what separates a core with a predictor from
    # one without, and the cost model could not say it: every branch was free
    # on every machine. Two cores differing in nothing but `(branch (penalty
    # N))` answer differently on the same program. A branch that falls
    # through costs nothing, which is what stops the model charging every
    # branch INSTRUCTION rather than every redirect.
    gate("a taken branch costs", "branch_check.py",
         example("issue_width.axisl"))

    # ⚠️ And how often it PAYS that. `(branch (penalty N))` says what a
    # redirect costs; `(predictor bimodal (entries M))` says how often the
    # machine gets one. A branch executed once is a cold miss whatever the
    # machine keeps, so a predictor cannot be measured on straight-line code
    # at all -- this runs a countdown loop at two trip counts. A machine that
    # does not guess pays per iteration; a machine that guesses pays a
    # constant three, whether the loop ran eight times or sixteen. That the
    # cost STOPS SCALING is what a predictor buys, and a predictor that helped
    # proportionally would be a faster machine rather than a predicting one.
    gate("a predictor is worth a loop", "predictor_check.py",
         example("issue_width.axisl"))

    # ⚠️ OUT OF ORDER, which is a different ALGORITHM rather than a wider
    # version of the in-order scoreboard: a tick loop over a finite reorder
    # buffer, issuing whatever is ready from anywhere in the window and
    # retiring strictly in order. What it buys is that an instruction waiting
    # on a slow producer does not hold up the ones behind it -- the one thing
    # no in-order machine can do at any width. Held by window size (a buffer
    # too small cannot reach the work), by a dependent chain being invariant
    # to window size (nothing in a chain may be reordered), and by both
    # machines leaving the same registers.
    #
    # ⚠️ Cycle-accurate for the structures it has, over a CORRECT-PATH trace:
    # it does not execute the wrong path, so wrong-path cache pollution is
    # invisible. Saying which half is modelled matters more than the number.
    gate("a waiter does not block", "ooo_check.py",
         example("issue_width.axisl"))

    # ⚠️ ADVANCED OUT OF ORDER (docs/ooo_design.md). Three structures a real
    # window has and the first one did not, each held to a program only it
    # can explain. O1: a load that reads what an older store wrote waits for
    # it -- a memory chain has a floor, perfect disambiguation passes a store
    # it does not overlap and conservative does not, a covered load forwards
    # from an executed store and a straddling one waits for retirement, and
    # the load and store queues are backpressure. And the addresses reach a
    # closed model, because the event promises everything the pipeline reads.
    gate("a load waits for the store it reads", "lsq_check.py",
         example("issue_width.axisl"))
    # O2: a result needs a physical register to live in until it retires. On
    # a program of nothing but writes, N spare registers and an N-entry
    # window are one constraint, so the two machines must agree to the cycle
    # -- that pins the count, not only its direction. Stores and writes to
    # the zero register take none.
    # O4/O5: a store's address is known before its value, and a machine may
    # BET that a load misses a store whose address it does not know yet. A
    # win must cost nothing (speculation equals the oracle to the cycle on a
    # loop that never aliases); a loss squashes everything younger and costs
    # exactly the declared replay more per unit of replay; speculation loses
    # once per iteration forever, and store sets lose a constant number of
    # times and then never again.
    gate("a bet on memory is paid for when lost", "speculation_check.py",
         example("issue_width.axisl"))
    # O6/O7: the FRONT END. Depth is a latency on straight-line code (six
    # stages deeper is exactly six cycles) and a rate over mispredicts
    # (exactly the extra depth per refill); a taken branch ends its fetch
    # group; fetch restarts when the branch RESOLVES; a buffer smaller than
    # width x depth starves dispatch; a one-entry BTB pays exactly its penalty
    # per aliasing miss, and an alternating indirect jump misses every time
    # because a BTB holds the last target.
    gate("instructions are fetched before they run", "frontend_check.py",
         example("issue_width.axisl"))
    # O8: a PREDICTOR IS A COMPONENT. The built-ins (bimodal, gshare, tage)
    # implement the same C interface a host's does, and a namespaced name is
    # somebody else's -- refused until registered, then predicting. TAGE
    # learns a period-8 branch a four-bit gshare pays for every period; past
    # its longest history it is no worse than bimodal, which only training
    # buys; and a stand-in external predictor is asked about every branch.
    gate("a predictor is a component", "tage_check.py",
         example("issue_width.axisl"))
    # O9: a RETURN STACK, with calls and returns DERIVED -- a jump that links
    # into the defabi's link register, an indirect jump through it that does
    # not link -- so any ISA with an ABI gets one and nothing is marked by
    # hand. A function called from two sites misses the target buffer twice
    # an iteration and the stack a constant; twelve nested calls against a
    # stack of eight save exactly eight; every wrong target is a redirect.
    gate("a return goes back where its call came from", "ras_check.py",
         example("issue_width.axisl"))
    # O10: ISSUE PORTS. A port starts one instruction a cycle, so units behind
    # one port cannot both start in the same cycle however many copies each
    # has. Adds alone and multiplies alone cost exactly what they cost with
    # every unit its own port; mixed, they start at most as many a cycle as
    # there are ports feeding them.
    gate("units behind one port share it", "ports_check.py",
         example("issue_width.axisl"))
    # O11: the INSTRUCTION CACHE and the WRONG PATH. A cold line misses once
    # and costs exactly the cache's latency; a loop that fits misses a
    # constant and one a line too big for a direct-mapped cache twice an
    # iteration; a fetch reads one line, so a skewed loop pays exactly its
    # line-bounded groups; fetching down a mispredicted fall-through
    # prefetches what the program runs later, bounded by what the machine
    # can hold rather than by how long the branch takes.
    gate("instructions come from a cache too", "icache_check.py",
         example("issue_width.axisl"))
    # O12: the WRONG PATH, EXECUTED. The functional side forks at a
    # mispredict, runs down the predicted path with its stores buffered and
    # its traps swallowed, and is restored exactly; the part the machine
    # reaches before resolution touches the caches. A wrong-path load
    # prefetches (one fewer miss) and pollutes (one more), exactly; it reads
    # its own stores and they never land; an undecodable word ends the run;
    # its jumps are followed, which fetching in line order cannot do; and
    # what it touches is never charged. W3: a wrong-path branch the predictor
    # gets wrong sends fetch down a detour until it resolves, then the path
    # resumes a refill later -- both sides reach the cache, and the detour's
    # stores go with it. W5: and a detour is a wrong path -- its own branches
    # have detours, three levels reach the cache, and a detour is no longer
    # than the room the machine has left.
    gate("the wrong path leaves nothing but its cache lines", "wrongpath_check.py",
         example("issue_width.axisl"))
    # E1: EXECUTION-DRIVEN. The front end fetches the predicted path,
    # instructions execute at issue through the generated executor on what
    # older in-flight instructions produced, branches resolve when they
    # execute, wrong-path work occupies the window until squashed, and every
    # commit steps the golden model and checks the pipeline against it. On
    # branch-free code it is its trace-driven twin cycle for cycle; on seeded
    # random programs it is the golden model, with zero replays; it squashes
    # real wrong paths, catches a late store, forwards, rebuilds its rename map,
    # and its prediction stops scaling over a loop.
    gate("the execution-driven core runs the golden model's program", "xmode_check.py",
         example("issue_width.axisl"))
    # E2: the execution-driven WRONG PATH IS THE REAL ONE. O12's programs give
    # the trace engine's cache answers without any fork; a call fetched down a
    # mispredicted path leaves the return stack as if it never was; an
    # alternating branch costs a constant with speculative history, and the
    # same with a memory violation squashing it every iteration; counters
    # count only what committed.
    gate("the execution-driven wrong path is the real one", "xspec_check.py",
         example("issue_width.axisl"))
    # E3: the execution-driven engine COMPLETE. Loads and stores known at
    # decode, so the queues bind and conservative, speculative and store-set
    # policies all work without a trace -- speculation violating once per
    # iteration on an aliasing loop, store sets once, conservative never; an
    # in-order execution-driven core cycle-exact against its trace twin and
    # the golden model on random programs; traps precise -- taken at commit,
    # never on a wrong path, never counted as replays.
    gate("the execution-driven engine is complete", "xcomplete_check.py",
         example("issue_width.axisl"))
    # MC1: several execution-driven cores in lockstep over one memory. Cores
    # apart are cycle-exact against themselves alone; store buffering never
    # lets both loads read 0 (sequential consistency) and does let either core
    # go first; a spin on a flag reads the datum behind it; a peer's committed
    # store squashes a stale load (a snoop) so the golden model never has to
    # (zero replays); the limit binds; a trace-driven core is refused.
    gate("several cores share one memory", "mcx_check.py",
         example("issue_width.axisl"))
    # S2: a SIMT core (docs/simt_design.md) leaves every thread of a
    # race-free, structured program -- nested divergent if/else, loops whose
    # trip count is the thread's own -- exactly as that thread run alone on
    # the executor leaves it; and its costs are the arithmetic of one
    # mechanism each: uniform code costs the same on 1 lane and 8, a 2-lane
    # ALU takes 4 cycles an op under an 8-lane warp, both arms of a
    # divergent branch are paid, the smaller group runs first, and lanes in
    # one line are one request.
    gate("a SIMT core runs a warp as its threads run alone", "simt_check.py",
         example("simt_core.axisl"))
    # A64-1: the execution-driven engine on AArch64, with a neutral core and
    # the AAPCS64 link register composed onto the ISA in a temporary file.
    # Flags, X30 and SP are renamed like registers, 128-bit destinations are
    # recorded limb by limb: random straight-line programs over every
    # instruction the C executor runs, a countdown on NZCV, calls from two
    # sites, a stack and a wide write-after-write -- the golden model's, with
    # zero replays; returns predicted with a return stack and not without.
    gate("AArch64 runs execution-driven", "a64x_check.py", slow=True)
    # E4: the execution-driven engine keeps a VIEW of the committed registers
    # instead of copying the file for every execute. A view can go stale where
    # a copy cannot: when the golden model disagrees about a register (one
    # replay, and the view takes the model's value) and when the host writes
    # one between steps (no replay).
    gate("the executing view follows the golden model", "xview_check.py",
         example("issue_width.axisl"))
    # VM1-VM2: a VECTOR instruction is one instruction in the pipeline. Its
    # window entry holds every lane's accesses and names every register every
    # lane touches -- the second limb, the register after, the destination a
    # guard may leave alone. Seven scalable corpora, each on an
    # execution-driven core and its trace-driven twin: the three engines
    # agree, nothing replays, and store-free programs match cycle for cycle.
    gate("a vector instruction is one instruction in the pipeline",
         "vector_pipeline_check.py", slow=True)
    # VM3: and Arm's SVE is 1086 of them -- every one once, then in random
    # programs, on both timing engines. A gate of its own for its size.
    gate("SVE runs on the pipeline", "vector_pipeline_check.py", example("sve.axisl"),
         slow=True)
    # VU1: A UNIT HAS LANES. `(lanes N)` makes a copy N lanes of 64 bits; an
    # instruction takes as many as its widest register is limbs. Two 128-bit
    # adds share four lanes in a cycle, one takes two beats on one lane, and
    # lanes do not speed up a dependent chain -- exactly, on both engines.
    gate("a unit has lanes", "vector_unit_check.py")
    # VU2: `(length vl)` names the operand that carries the element count, and
    # an instruction takes lanes for the elements it works on: one or two
    # 32-bit elements one 64-bit lane, three or four two -- read when the
    # instruction issues on one engine and before it steps on the other.
    gate("a unit that names a length works on that many elements",
         "vector_length_check.py")
    # VU3: `(accepts alu)` lends a vector unit's idle lanes. Scalars alone
    # triple on two lanes; beside adds that take both lanes they gain
    # nothing; on four lanes two ride what a 128-bit add leaves.
    gate("a vector unit lends its idle lanes", "vector_lend_check.py")
    # VU4: ONE UNIT, SEVERAL CORES. `share_unit` makes one named unit of two
    # machines a single set of copies and lanes. Two busy cores get half
    # each whichever ticks first, an idle partner costs nothing, a transport
    # cost triples a dependent chain and leaves independent work alone, and
    # a switch cost makes turns of switch + 1.
    gate("one unit, several cores", "vector_share_check.py")
    # TLB1: `(tlb (data ...) (fetch ...) (second ...) (walk-cycles N))` on a
    # core. Timing, not translation. A pointer chase round a ring of pages
    # misses once a page when the ring fits and every load when it does not,
    # each miss exactly one walk; ways are sets; a second level holds what
    # the first forgot; fetch misses once per page of code; a store
    # translates once, when it executes; a squashed load's page is remembered
    # and not counted.
    gate("a machine remembers only so many pages", "tlb_check.py")
    # PF1: a cache names a prefetcher this library has not got and a host
    # binds it. A host's next-line is the built-in's to the cycle and the
    # counter; one that asks for nothing is none; unbound, the core is
    # refused; one that knows a stride next-line cannot follow is worth most
    # of the run.
    gate("a prefetcher is a component a host may bring", "prefetcher_check.py")
    # D1, W1: a DIRECT branch's target is a field of its word, so decode knows
    # it. Execution-driven, a predicted-taken branch the buffer does not hold
    # is redirected at decode for `btb-penalty`, not at execution as a
    # mispredict -- cold direct jumps mispredict nothing and cost what the
    # trace twin costs, indirect ones every time. Trace-driven, a branch
    # guessed taken that falls through has a wrong path after all: its target,
    # later by decode's time when the buffer lost it. And every direct branch
    # of the corpus has a target lowered, or the gate fails by its name.
    # D2: and while decode looks, fetch runs on -- the lines after a decoded
    # jump are in the instruction cache when the program comes back to them.
    # D4: but a line asked for is on its way, not there: that fetch waits on a
    # line it misses and asks for nothing past it, and the program, coming to
    # a line still arriving, waits for what is left of the fill.
    # W5, W6: a wrong path's jumps are predicted like any others -- through a
    # register no buffer holds, fetch runs on; a direct one the buffer lost
    # costs decode's time there too; what a wrong path pushed on the return
    # stack goes when it does -- and the program's own jump with nowhere to
    # send fetch has the fall-through for its wrong path, on both engines.
    gate("decode knows where a direct branch goes", "redirect_check.py",
         example("issue_width.axisl"))
    # U1: a core cracks an instruction into micro-ops -- a unit and its cycles
    # each -- and what each reads, writes and loads is derived from the
    # instruction's effects. A base moved on by an add is ready an add later,
    # not a load later; a sum of a load waits for the load and the load for
    # nothing; and each micro-op is a place in every width.
    gate("a cracked instruction is several micro-ops", "micro_ops_check.py",
         example("issue_width.axisl"))
    # S1-S3: the scheduler's own limits. Two enter the window a cycle where
    # four did; a chain of one-cycle adds runs at two through a two-cycle
    # wakeup-and-select loop and a chain of multiplies at three as before; a
    # product takes two cycles more to reach an adder, and only that way; and
    # a multiplier two may wait for stops everything behind a third.
    gate("the scheduler has limits of its own", "scheduler_check.py",
         example("issue_width.axisl"))
    # S4: a load that has read the same value twice running is predicted to
    # again. A pointer at itself is chased at the loop's speed, not the
    # load's; a ring of four is never predicted; and a value predicted wrong
    # fetches everything behind the load again.
    gate("a load's value, predicted", "value_check.py",
         example("issue_width.axisl"))
    # U2: code decoded once is not decoded again. A loop of fourteen is four
    # fetch groups a trip decoded, two from a micro-op cache eight wide, and
    # fourteen micro-ops at eight a cycle from a loop buffer that does not
    # stop at its branch; a mispredict refills through the cache's stages; and
    # what comes from the cache is not fetched from the instruction cache.
    gate("two ways round decode", "op_cache_check.py",
         example("issue_width.axisl"))
    # FQ1: a decoupled front end. The predictor names a line a cycle, N beyond
    # the one fetch is reading, and a line is asked for when it is named: cold
    # straight code is a line every max(groups, miss / N) cycles. A redirect, a
    # jump with no target and a new page empty the queue; a jump with a target
    # does not. Builds its own machines.
    gate("a predictor does not wait for fetch", "target_queue_check.py")
    # ME1: a move done at rename. Which instructions are moves is told from
    # what they compute -- an add of the zero register -- and one is an entry
    # in the window and nothing else: no link in a chain, no unit, no slot of
    # the issue queue, no register, and what reads it wakes as for what it
    # read. Builds its own machines.
    gate("a move is done at rename", "move_check.py")
    # FU1: a pair the decoder fuses. The core names the pairs; whether two
    # words are one is told from the registers they name, and the pair is
    # then one entry, one slot of every width, one unit and one register.
    # Builds its own machines.
    gate("a pair is one operation", "fuse_check.py")
    # FU2: the tail of a pair may be a load -- an address formed into the
    # access -- and then the load's entry is the pair and the head follows.
    gate("an address formed into the load that uses it", "fuse_load_check.py")
    # ZI1: a register xor-ed with itself is known to be nothing at decode --
    # an entry like a move's, that waits for nothing. The corpus has no xor;
    # the gate adds one, and builds its own machines.
    gate("a register xor-ed with itself is nothing", "zero_idiom_check.py")
    # WM1: a store buffer. Two cores on one memory show what the ISA's memory
    # model allows and sequential consistency does not -- store buffering
    # with any buffer, the flag before the datum only draining in any order,
    # neither past a fence. Adds its own fence and cache; builds its own
    # machines.
    gate("a store that has retired is not yet everyone's", "store_buffer_check.py")
    # WM2: loads seen in any order. A reader that reads the datum before the
    # flag it loads first has the flag and not the datum only on a core that
    # says so; never past a fence; and never one word set and then clear.
    gate("a load overtaken keeps what it read", "load_order_check.py")
    # WM3: both on the instructions the model was written for. Two AArch64
    # cores with STR, LDR and DMB: store buffering, message passing and loads
    # out of order appear on the machine that allows each and on no other.
    gate("AArch64 cores show what Arm's model allows", "a64_weak_check.py")
    # ... and RISC-V's: two RV64 cores with SD, LD and FENCE under RVWMO.
    gate("RV64 cores show what RVWMO allows", "rv_weak_check.py")
    # A store buffer in front of a blocking cache is its write buffer: commit
    # does not wait for a store's line, the cache is as busy as it was, and a
    # load is next before a store that has retired.
    gate("a store buffer in front of a cache that is busy", "write_buffer_check.py")
    # D3: a quick predictor answers at fetch and the core's own overrides it at
    # decode. A branch bimodal counters never call taken and gshare learns is
    # fetched past and redirected to its target, exactly `cycles` a time; one
    # they always call taken is fetched at its target and sent back. The
    # machine with the clause and the one without mispredict exactly as often
    # -- it costs time, never accuracy -- on both engines.
    gate("a predictor overridden at decode", "override_check.py",
         example("issue_width.axisl"))
    # W2: wrong-path instructions ENTER THE WINDOW. A multiply on the wrong
    # path holds an unpipelined multiplier for its whole latency -- against
    # an older instruction that becomes ready, and past the squash; a load
    # touches the cache when it issues, so one still waiting for an operand,
    # a line or a register when the branch resolves prefetches nothing; and
    # the squash gives every register back.
    # W4: and a unit declared `(abort true)` gives itself back too, the cycle
    # after the squash -- one cycle late for an older multiply that was ready,
    # where a unit that holds makes it wait latency - 1.
    gate("the wrong path holds what it uses", "occupancy_check.py",
         example("issue_width.axisl"))
    gate("results need registers to live in", "rename_check.py",
         example("issue_width.axisl"))
    # O3: gshare folds global history into the index, so an alternating
    # branch -- which a counter per address pays for every other iteration
    # forever -- costs a constant. And one bit of history, inside a loop, is
    # always the loop's own branch: it must NOT learn the pattern, which is
    # what proves the declared length is read.
    gate("history learns a pattern", "history_check.py",
         example("issue_width.axisl"))

    # ⚠️ THE DESCRIPTION, held against SILICON. Every other gate here holds an
    # artifact against another artifact; `latency` was free text until a
    # scoreboard read it, and reading it made the model self-consistent while
    # saying nothing about whether the number is true. This host is an arm64
    # Mac and the corpus describes AArch64, so the claim can be put back to
    # the hardware: the ratio of two dependent chains is the ratio of their
    # latencies, which cancels clock frequency, issue width and unit counts
    # and leaves the one number the description declares.
    gate("a declared latency is silicon", "silicon_check.py",
         example("aarch64_translation_seed.axisl"))

    # ⚠️ The OPEN/CLOSED SEAM. A microarchitecture is mostly policy and policy
    # is not declarable, so a stack where some models are open and some are a
    # vendor's needs a boundary that carries three things AXIS does not own:
    # which implementation is meant to time a core, whatever that
    # implementation's knobs are (transported intact, never interpreted), and
    # what KIND of number the result would be. `axis.uarch.v1` is a machine
    # standing alone -- separate from emit-json, because a vendor describing a
    # machine should not have to ship an instruction set to do it. The
    # property it exists for: a core naming a model this library is not is
    # REFUSED, because answering with the built-in pipeline would be a
    # plausible number for somebody else's machine.
    gate("described openly, modelled privately", "uarch_ir_check.py",
         example("issue_width.axisl"))

    # ⚠️ A LANE BODY READS THE LANES IT NAMES. A vector operator had to be
    # ONE ATOM from a closed list, which is a description of what had somewhere
    # to be written down rather than of what lanes can do -- a saturating add
    # or a shift by a signed amount was not expressible. `vmap` gives a lane
    # operator a body, which moves the risk: the closed list was safe BECAUSE
    # it was closed. So lane-locality and containment are proved over every
    # input rather than held by construction, `vmap` is proved to agree with
    # the expansion it generalises, and the lane bindings are proved hygienic
    # against a body that rebinds a lane name. A cross-lane body cannot be
    # lane-local -- crossing lanes is what it is for -- so it is held instead
    # to which input lanes each output lane really depends on.
    gate("a lane body reads the lanes it names", "lane_body_check.py")

    # ⚠️ AXIS EXECUTES EACH AArch64 WORD AS ARM'S SPECIFICATION DOES. Every
    # other AArch64 check compares AXIS against AXIS, the assembler (encodings
    # only) or one machine's silicon -- none of them is the architecture. This
    # runs each word in the Sail translation of Arm's own ASL for Armv9.4-A,
    # from the same full register file, and compares every register after. It
    # drives every value of each small immediate, because the fixtures carry
    # one; and it seeds signalling and quiet NaNs, because random registers
    # almost never hold one and 33 FP instructions disagreed on exactly that.
    # FPCR.DN = 1: the corpus's declared NaN policy. Declines without the model
    # (tools/asl_model_build.sh) or llvm-mc.
    gate("AArch64 executes as Arm's ASL does", "asl_check.py",
         example("aarch64_translation_seed.axisl"))

    # ⚠️ THE WHOLE ADVSIMD SPACE, NOT THE FIXTURES. The reference check sees
    # one word per instruction; a `requires` that forgot an arrangement, or a
    # pattern matching an unallocated encoding, sits between fixtures. This
    # drives every opcode bit of the vector and scalar AdvSIMD space (196,608
    # words) through llvm-mc and AXIS's lift table: every word AXIS decodes
    # must be the reference's instruction, and none may be one it refuses.
    # Declines without llvm-mc.
    gate("AArch64 decodes the AdvSIMD space as LLVM does", "a64_space_check.py",
         example("aarch64_translation_seed.axisl"))

    # ⚠️ THE MEMORY SYSTEM, DESCRIBED ONCE (docs/memory_system_design.md).
    # `emit-memsys-json` resolves each `defmemsys` -- ids, hops, paths, the
    # address map's targets and homes -- and the first gate reads the
    # description a second way and compares every resolved field, then makes
    # each refusal the design promises happen once. The second lowers the same
    # manifest into AHA's NoC and CHI configurations and holds it against
    # AHA's own decoders (simulated), hop metric, MOESI proof and DRAM
    # profiles, with three perturbations that must each be caught; it declines
    # without a PCE checkout. The third holds the C timing engine to a Python
    # reference model access by access -- every replacement, write and
    # allocation policy, both inclusions, four topologies, all four coherence
    # protocols -- with four engine mutants; the fourth, the engine as the
    # simulator pack carries it: counters after a trace, a loop's cycles on a
    # port core against its twin in no system, and two machines joined into
    # one coherent system.
    gate("memory system manifest == description", "memsys_check.py",
         example("memory_system.axisl"))
    gate("AHA builds the described memory system", "memsys_aha_check.py",
         example("memory_system.axisl"))
    gate("memory-system engine == reference model", "memsys_sim_check.py",
         example("memory_system.axisl"))
    gate("the simulator runs the described memory system", "memsys_pack_check.py",
         example("memory_system.axisl"))
    # U1 (docs/unified_engine_design.md): TIMED accesses -- lines in flight,
    # MSHRs, DRAM banks and buses, next-line, stride and best-offset
    # prefetching -- held cycle by cycle to a second reading in absolute time;
    # uncontended, timed == untimed; five engine mutants caught.
    gate("the memory system keeps time", "memsys_timed_check.py",
         example("memory_system.axisl"))
    # U3: an execution-driven core with (memory-timing timed) asks the
    # memory system WHEN -- one access in flight costs what untimed does,
    # several meet the MSHRs -- and a CPU core and a SIMT core stepped on one
    # clock share one memory system and slow each other down.
    gate("an execution-driven core asks the memory system when", "memsys_x_check.py",
         example("memory_system.axisl"))
    # A core's own cache that is BUSY (docs/blocking_cache_design.md): one
    # request a cycle and none while a miss is on its way, a store that waits
    # for its line and a stored line written behind -- each held to the cycle.
    gate("a cache that is busy", "blocking_cache_check.py", example("issue_width.axisl"))
    gate("a CPU core and a SIMT core share one clock and one memory", "unified_run_check.py",
         example("simt_core.axisl"))
    # U4a: contexts of one core share its units, ports and widths and split
    # its window; U4b: a warp is contexts sharing one front end -- converged
    # members cost one, diverged ones two, and aging is what progress needs.
    gate("hardware contexts share one core", "contexts_check.py",
         example("memory_system.axisl"))
    gate("a warp is contexts sharing one front end", "warp_check.py",
         example("memory_system.axisl"))
    # U4c: a store one core commits clears every other core's exclusive
    # monitor over the bytes it wrote, for a core that names its monitor
    # `(exclusive ...)` -- four LR/SC adders end at 400; without it, 100.
    gate("a store clears the other cores' exclusive monitors", "monitor_check.py",
         example("rv64i.axisl"))
    # U4c: (events (wait W) (send S) (local L)) -- a wait with the event
    # register clear sleeps (squashing what it fetched after) until another
    # core's send commits. Waiters commit 8 instructions instead of 632
    # polling; a send before the waits is held; everyone asleep halts at once.
    gate("a wait for an event sleeps, and a send wakes it", "events_check.py",
         example("rv64i.axisl"))

    # ⚠️ A FIELD SPLIT ACROSS THE WORD IS PLACED IN BOTH HALVES. AArch64's
    # by-element index lives at bit 11 and bit 21 with the register between
    # them, declared as instruction-bits-to-operand-bits, one entry per slice.
    # Getting that mapping backwards is SILENT -- the widths still match, the
    # description still validates, and every value of the index encodes as
    # zero. `reference_isa_check` cannot see it: it compares against a real
    # assembler over the roundtrip fixtures, and the generator emits ONE test
    # per instruction, whose index is the single value a misplaced field still
    # encodes correctly. It agreed about nine instructions whose index went
    # nowhere. This drives the encoder table over every value instead.
    gate("a field split across the word", "split_field_check.py",
         example("aarch64_translation_seed.axisl"))

    # ⚠️ A LATER BINDING SEES THE EARLIER ONES. `let` bindings were
    # SIMULTANEOUS, so a chain of steps had to be nested into a staircase of
    # single-binding lets. Sequential bindings let the same computation be
    # written as a flat dataflow block while staying one pure expression
    # underneath. Checking the flat form PARSES would measure the front end
    # only; meaning is decided where `let` is inlined into the typed IR. So
    # the discriminator is a binding that SHADOWS an operand -- both readings
    # parse, and they compute different functions -- and the check is a z3
    # proof that the flat form equals its unambiguous staircase over all
    # inputs, plus the separately emitted golden model agreeing.
    gate("a later binding sees the earlier ones", "sequential_let_check.py")

    # ⚠️ AN INSTRUCTION NOTHING SELECTS IS AN INSTRUCTION NOBODY HAS.
    # `llvm_patterns_check` proves a pattern computes what its instruction
    # computes; `llvm_target_check` proves tblgen accepts the target and its
    # encoder matches AXIS's. Neither answers the compiler writer's question,
    # and the existing `--gen-dag-isel` check is an AGGREGATE: it fails only
    # when the matcher selects NONE of the target's instructions, so one
    # pattern quietly dropped passes while the others still select. This is
    # the per-instruction census, cross-checked against `emit-llvm-patterns`
    # so that emitting no patterns at all is a failure and not a decline.
    gate("a pattern reaches the matcher", "selectable_check.py",
         example("zbb_like.axisl"), example("rv32i.axisl"))

    # ⚠️ The HARDWARE, held to the golden model like every way of executing.
    # Six backends were compared and the RTL emitter was compared to nothing,
    # which is the asymmetry that matters for co-design: a stack can say "six
    # ways of running this agree" and still not say the hardware does what the
    # software says. The first run found seventeen wrong circuits.
    gate("PyRTL == golden: RV32I", "pyrtl_vs_golden.py", example("rv32i.axisl"))
    gate("PyRTL == golden: RV64I", "pyrtl_vs_golden.py", example("rv64i.axisl"))
    gate("PyRTL == golden: zbb", "pyrtl_vs_golden.py", example("zbb_like.axisl"))
    gate("PyRTL == golden: A64", "pyrtl_vs_golden.py",
         example("aarch64_translation_seed.axisl"))
    # H1-H2: the STRUCTURAL hardware -- a netlist per instruction, and the
    # functional units those merge into -- held to the same model. Each
    # instruction is checked on its own and again selected in its unit, with
    # noise on every wire it does not read. `--expect-declined 0` is what stops
    # a generator that quietly builds less from passing on what is left, and
    # `--measure` synthesises the ALU both ways so the area the plan claims to
    # save is counted in gates rather than taken from the cost model.
    gate("netlists and units == golden: RV32I", "hw_units_check.py", example("rv32i.axisl"),
         "--expect-declined", "0", "--measure")
    gate("netlists and units == golden: RV64I", "hw_units_check.py", example("rv64i.axisl"),
         "--expect-declined", "0")
    gate("netlists and units == golden: zbb", "hw_units_check.py", example("zbb_like.axisl"),
         "--expect-declined", "0", "--measure")
    # The same claim for EVERY input: each netlist against the definition
    # `emit-smt2` gives its instruction, and each unit, select fixed, against
    # its member. ⚠️ "Not proved" is z3 timing out -- a remainder rewritten to
    # read the divider, a 32-bit divide riding a 64-bit one -- and is neither a
    # proof nor a refutation. The count is pinned so it cannot grow unnoticed,
    # and those rules are exhausted at small widths in `cargo test` instead.
    gate("netlists and units proved: RV32I", "hw_prove.py", example("rv32i.axisl"),
         "--expect-unknown", "2")
    gate("netlists and units proved: RV64I", "hw_prove.py", example("rv64i.axisl"),
         "--expect-unknown", "8")
    gate("netlists and units proved: zbb", "hw_prove.py", example("zbb_like.axisl"),
         "--expect-unknown", "0")
    # H1a: the instructions stated as EFFECTS -- branches, jumps, loads, stores
    # -- every value, guard and address against the golden model's evaluator,
    # with a memory that differs at every address. The count is pinned for the
    # same reason the declined count is above.
    gate("effect netlists == golden: RV32I", "hw_effects_check.py", example("rv32i.axisl"),
         "--expect-built", "33")
    gate("effect netlists == golden: RV64I", "hw_effects_check.py", example("rv64i.axisl"),
         "--expect-built", "44")
    # H1b: what a description says a built-in operator MEANS, held to the
    # built-in. The netlist lowering inlines these bodies where no backend has
    # a native implementation, and nothing else compares them.
    gate("reference bodies == operators: A64", "hw_reference_check.py",
         example("aarch64_translation_seed.axisl"), "--expect", "23", slow=True)
    gate("effect netlists == golden: A64", "hw_effects_check.py",
         example("aarch64_translation_seed.axisl"), "--expect-built", "387", slow=True)
    # T1: a core's own word on latency and unit (docs/core_timing_design.md).
    # No corpus says anything yet, so nothing published has moved; a core that
    # does is published resolved, survives the printer, and is refused by the
    # simulator until the simulator charges it.
    gate("a core's timing is what is published", "core_timing_check.py")
    # H2c: units whose members may be instructions stated as effects --
    # branches, loads, stores, flag writes -- each output a named slot. Every
    # member selected, every slot it drives against its own netlist, every
    # slot it does not drive disabled.
    gate("units with effects == members: RV32I", "hw_effect_units_check.py", example("rv32i.axisl"))
    gate("units with effects == members: RV64I", "hw_effect_units_check.py", example("rv64i.axisl"))
    gate("units with effects == members: A64", "hw_effect_units_check.py",
         example("aarch64_translation_seed.axisl"), "--cases", "2", slow=True)
    # H2b: the cost model the merger and any search decide on, against what
    # the emitted circuits come to through Yosys and ABC on a standard-cell
    # library -- operators alone, whole instructions, merged units, and whether
    # merging saves what the model says. Skips without yosys or the library.
    # Slow: some hundreds of synthesis runs the first time, cached after.
    gate("cost model == synthesis", "hw_calibrate.py", slow=True)
    # H2a: a plan from OUTSIDE, and one AXIS would not choose -- the multiplier
    # and the divider as one unit, sharing whatever legally can be. A proposer
    # may be wrong about what is small; these are what stop it being wrong
    # about what is computed.
    gate("netlists and units == golden: a proposed plan", "hw_units_check.py",
         example("rv32i.axisl"), "--expect-declined", "0",
         "--plan", example("hw_plans/rv32i_muldiv.plan"))
    gate("netlists and units proved: a proposed plan", "hw_prove.py", example("rv32i.axisl"),
         "--expect-unknown", "2", "--plan", example("hw_plans/rv32i_muldiv.plan"))

    # ⚠️ Where every register LIVES, over every corpus. Six things index the
    # register file and each derived `offset + index_offset + index` for
    # itself; the stencil one was wrong for two years and agreed with itself.
    # This holds the published layout to the lifter, to the encodings the
    # selector widths come from, and to the rule that two files which are not
    # views of one another may not share a slot -- which found `simd_fp_lanes`
    # addressing one register file at two strides.
    gate("register storage", "regfile_check.py")

    # Bytes to instructions. The step between two of them is what a consumer
    # holding an image cannot work out for itself, and getting it wrong reads
    # as a description that is missing instructions. ⚠️ `rv64i` for the 16-bit
    # ones, `sve` for a description with no control flow at all, `aarch64` for
    # instructions the library will not vouch for.
    gate("lifting an image", "lift_walk_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"),
         example("sve.axisl"))

    # What a description NAMES and does not describe -- a signing routine, a
    # cipher round -- reaching a pack that was built before the host existed.
    # ⚠️ AArch64 is the only corpus that names any: the others decline, which
    # is why this gate runs on one corpus rather than three.
    gate("a host's routine", "routine_pack_check.py",
         example("aarch64_translation_seed.axisl"), example("rv64i.axisl"))

    # The ninth library: a machine made of the terms the eighth hands out.
    # ⚠️ Held by binding its free variables to numbers and requiring every
    # register to equal what the executor computed from the same numbers -- a
    # symbolic engine that agrees with a concrete run is one a consumer can
    # reason with; one that merely produces well-formed terms is not.
    gate("symbolic library", "sym_pack_check.py", example("rv64i.axisl"),
         example("rv32i.axisl"), example("aarch64_translation_seed.axisl"))

    gate("jit library: RV64I", "jit_pack_check.py", example("rv64i.axisl"))
    gate("jit library: RV32I", "jit_pack_check.py", example("rv32i.axisl"))
    gate("jit library: AArch64", "jit_pack_check.py",
         example("aarch64_translation_seed.axisl"))

    # --- symbolic execution ------------------------------------------------
    # The same effects the executors run, evaluated to terms instead of
    # numbers. Checked without a solver: run concretely from random inputs,
    # run symbolically from free variables, bind the variables to those inputs
    # and every register must agree. ⚠️ `zbb_like` is here because RV64I has no
    # `min`/`max` fixture -- lowering a signed comparison as unsigned passed on
    # RV64I and fails on zbb.
    gate("symbolic: RV64I", "symbolic_check.py", example("rv64i.axisl"))
    gate("symbolic: RV32I", "symbolic_check.py", example("rv32i.axisl"))
    gate("symbolic: zbb", "symbolic_check.py", example("zbb_like.axisl"))
    # ⚠️ AArch64 is where the REGISTER MODEL earns its keep: a `W` view that
    # zeroes the rest of its `X`, a `D` register inside a 128-bit one, and an
    # index 31 that is `SP` in one class and the zero register in another.
    # Treating a register file as an array of words passed every RISC-V gate
    # and got 544 of these wrong.
    gate("symbolic: AArch64", "symbolic_check.py",
         example("aarch64_translation_seed.axisl"))

    # And the same terms as a MACHINE: a pc, memory, architectural state, and
    # every path a branch can take. ⚠️ The property is sharper than agreement
    # and still needs no solver: explore once from free inputs, then for each
    # concrete input exactly ONE path may hold -- two means the fork invented a
    # way the machine cannot go, none means it lost the way it did go -- and
    # that path's registers, pc, state and memory must be the concrete
    # machine's, byte for byte.
    gate("symbolic machine: RV64I", "symbolic_machine_check.py", example("rv64i.axisl"))
    gate("symbolic machine: RV32I", "symbolic_machine_check.py", example("rv32i.axisl"))
    # A guarded write that is not a branch: rv64i has none, and turning
    # `ite(guard, new, old)` into `new` passed both other corpora.
    gate("symbolic machine: guarded set", "symbolic_machine_check.py",
         example("effects_guarded_set.axisl"))
    gate("symbolic machine: AArch64", "symbolic_machine_check.py",
         example("aarch64_translation_seed.axisl"))

    # ⚠️ And the SMT TEXT, proven rather than sampled. Everything above binds a
    # term's variables to one input and compares numbers, which says nothing
    # about `smt()` -- the rendering a caller hands to a solver. This asks a
    # solver whether the rendering and `emit-smt2`'s already-proven
    # `axis_instr_*` can EVER differ, over all inputs. It found that indexed
    # operators were being printed as plain applications and that Bool and
    # `(_ BitVec 1)` were being crossed: a rendering nothing could parse.
    gate("symbolic SMT: RV64I", "symbolic_smt_check.py", example("rv64i.axisl"))
    gate("symbolic SMT: RV32I", "symbolic_smt_check.py", example("rv32i.axisl"))
    # AArch64 at 60 s a question: FMAXNMV/FMINNMV .8H prove in 4-7 s alone and
    # past ten under the ladder's load, which reported proofs as failures.
    gate("symbolic SMT: AArch64", "symbolic_smt_check.py",
         example("aarch64_translation_seed.axisl"), "--timeout", "60")

    # ⚠️ And the other direction: not "is every real run covered" but "is every
    # listed path real". The solver is given a path's constraints and asked for
    # an input satisfying them; the concrete machine is then run on that exact
    # input and has to take THAT path, registers and all. It is the only check
    # of `path_smt`, the interface a caller actually uses -- which until now
    # rendered constraints into a script nobody had ever solved.
    gate("symbolic paths: RV64I", "symbolic_path_check.py", example("rv64i.axisl"))
    gate("symbolic paths: RV32I", "symbolic_path_check.py", example("rv32i.axisl"))
    gate("symbolic paths: AArch64", "symbolic_path_check.py",
         example("aarch64_translation_seed.axisl"))

    gate("implementation routine", "implementation_routine_check.py")

    # And the same hook in a REAL corpus. The gate above proves it works, on
    # one instruction in a file written for the purpose; this one asks whether
    # every instruction that names a routine is dispatched to it in both
    # executors, which is the question that grew teeth when AArch64's
    # pointer-authentication family started naming routines.
    gate("implementation dispatch: A64", "implementation_dispatch_check.py",
         example("aarch64_translation_seed.axisl"))

    # 137 instructions are declined for naming a rounding mode. The reason is
    # that codegen discards the mode, not that IR cannot say it -- a premise
    # about the host LLVM, so it is checked rather than assumed.
    gate("directed rounding", "fp_rounding_check.py")

    # The lifter is a library, and a library has to be reachable from a
    # compiled consumer. This links a C program against it and requires the
    # same bytes to give the same answer through both doors.
    gate("lift ABI: RV64I", "lift_abi_check.py", example("rv64i.axisl"),
         "--isa", "rv64i")
    gate("lift ABI: A64", "lift_abi_check.py",
         example("aarch64_translation_seed.axisl"), "--isa", "aarch64_base")
    gate("lift region: A64", "lift_region_check.py",
         example("aarch64_translation_seed.axisl"), "--regions", "40")
    # Shapes a random draw of six instructions out of seven hundred will
    # essentially never produce: a 128-bit value round-tripping through memory,
    # and a narrow view of a register a wide load just wrote.
    gate("lift planted: A64", "lift_region_check.py",
         example("aarch64_translation_seed.axisl"), "--planted")
    # A store-conditional whose reservation holds. The random sweep only ever
    # exercises the guard-false path, where a masked store is indistinguishable
    # from no store at all.
    gate("lift planted: RV64I", "lift_region_check.py",
         example("rv64i.axisl"), "--planted")
    gate("lift each: RV64I", "lift_region_check.py", example("rv64i.axisl"),
         "--per-instruction")
    gate("lift each: A64", "lift_region_check.py",
         example("aarch64_translation_seed.axisl"), "--per-instruction", slow=True)
    gate("A64 JIT (LLVM)", "jit_llvm.py",
         example("aarch64_translation_seed.axisl"), "--distinct", "8",
         "--programs", "60", slow=True)
    gate("A64 LLVM effects", "llvm_effects_check.py",
         example("aarch64_translation_seed.axisl"), slow=True)
    # The wide driver is the only one that executes this corpus's effects with
    # 64-bit registers, memory and PC *and* architectural state present. It had
    # never run here: an `inout` destination made it pass one argument too few
    # to the golden model, so it died before the first case.
    gate("A64 wide C exec", "exec_wide_check.py",
         example("aarch64_translation_seed.axisl"), slow=True)
    gate("A64 wide Rust exec", "exec_wide_check.py", "--lang", "rust",
         example("aarch64_translation_seed.axisl"), slow=True)
    gate("A64 architectural state", "aarch64_state_check.py", slow=True)
    gate("A64 native wide exec", "aarch64_native_state_check.py", slow=True)
    gate("A64 lowering equivalence", "lowering_vs_golden.py",
         example("aarch64_translation_seed.axisl"), slow=True)
    gate("A64 translation exec", "translation_vs_golden.py",
         example("aarch64_translation_seed.axisl"), slow=True)
    gate("lowering: lisp_lowerings", "lowering_vs_golden.py",
         example("lisp_lowerings.axisl"))
    return gates


# What a changed path can affect, most specific first. A path that matches
# nothing here selects *everything*, which is the only safe default: a
# selection rule that guesses wrong under-runs silently, and an under-run that
# reads as a pass is the failure this whole ladder exists to prevent.
#
# The tool each gate runs is the honest unit here -- a gate is affected by the
# checker it invokes, by the emitter that checker asks for output, and by the
# corpus it is pointed at.
AFFECTS: list[tuple[str, tuple[str, ...] | None]] = [
    # Prose gates one thing: the numbers in it are recomputed.
    ("docs/", ("documented numbers",)),
    ("README.md", ("documented numbers",)),
    (".gitignore", ()),
    ("tools/doc_facts_check.py", ("documented numbers",)),
    # The structural hardware backend: its own gates, its unit tests, and the
    # numbers `docs/hardware_design.md` states about it.
    ("src/hw.rs", ("netlists", "cargo test", "documented numbers", "cost model == synthesis")),
    ("src/hw_units.rs", ("netlists", "cargo test", "documented numbers", "cost model == synthesis")),
    ("src/emit/hw.rs", ("netlists", "cargo test", "documented numbers", "cost model == synthesis")),
    ("tools/hw_units_check.py", ("netlists and units == golden",)),
    ("tools/hw_prove.py", ("netlists and units proved",)),
    ("tools/hw_effects_check.py", ("effect netlists == golden",)),
    ("tools/hw_reference_check.py", ("reference bodies == operators",)),
    ("tools/hw_effect_units_check.py", ("units with effects == members",)),
    ("tools/core_timing_check.py", ("a core's timing",)),
    ("src/timing.rs", ("a core's timing", "cargo test")),
    ("tools/hw_calibrate.py", ("cost model == synthesis",)),
    ("tools/ise_cost.py", ("ISE mining",)),
    ("tools/ise_run.py", ("ISE mining",)),
    ("tools/ise_check.py", ("ISE mining",)),
    ("tools/ise_mine.py", ("ISE mining",)),
    ("tools/ise_prove.py", ("ISE mining",)),
    ("tools/hw_synth.py", ("cost model == synthesis",)),
    ("tools/hw_urv_check.py", ("netlists in URV's extension slot",)),
    ("tools/pce_patches/", ("netlists in URV's extension slot",)),
    ("examples/hw_plans/", ("a proposed plan",)),
    # A test file is the cargo gate and nothing else.
    ("tests/", ("cargo test",)),
    # The LLVM emitters and their two checkers.
    ("src/emit/llvm.rs", ("LLVM", "cargo test")),
    ("src/emit/llvm_target.rs", ("LLVM", "cargo test")),
    # An analysis tool no gate runs.
    ("tools/decline_census.py", ()),
    ("tools/llvm_target_check.py", ("LLVM target MC",)),
    ("tools/llvm_patterns_check.py", ("ISel patterns",)),
    # The packet gate and its corpus reach one gate each; the emitters they
    # exercise (`src/emit/packet.rs`, `src/emit/lift.rs`) do not appear here,
    # because lift.rs feeds most of the ladder and packet.rs is new enough that
    # under-running it is the risk worth avoiding.
    ("tools/half_exhaustive_check.py", ("half over every pattern",)),
    ("tools/bf16_check.py", ("bf16 rounds correctly",)),
    ("tools/fp8_check.py", ("fp8 rounds correctly",)),
    ("tools/matrix_check.py", ("matrix indices agree",)),
    ("tools/access_map_check.py", ("access map generalises",)),
    ("tools/config_check.py", ("configuration agrees",)),
    ("tools/behavior_forms_check.py", ("behavior forms agree",)),
    ("tools/completion_check.py", ("completion contract agrees",)),
    ("tools/xnn_device_check.py", ("XNN device agrees",)),
    ("examples/xnn_systolic.axisl", ("XNN device agrees", "XNN device python exec",
                                     "XNN device wide C exec", "XNN device wide Rust exec",
                                     "cargo test")),
    ("tools/sme_check.py", ("SME outer products agree", "SME == Arm's specification")),
    ("tools/sme_asl_check.py", ("SME == Arm's specification",)),
    ("tools/sve_asl_check.py", ("SVE == Arm's specification",)),
    ("tools/deffun_check.py", ("deffun: called == inlined",)),
    ("tools/gen_sve.py", ("SVE corpus == its generator", "SVE == Arm's specification")),
    ("examples/sme.axisl", ("SME outer products agree", "SME == Arm's specification",
                            "cargo test")),
    ("tools/aha_descriptor_check.py", ("AHA descriptors agree",)),
    ("examples/aha_descriptors.axisl", ("AHA descriptors agree", "AHA descriptors python exec",
                                        "AHA descriptors wide C exec",
                                        "AHA descriptors wide Rust exec", "cargo test")),
    ("tools/descriptor_check.py", ("descriptor launches agree",)),
    ("examples/descriptor.axisl", ("descriptor launches agree", "descriptor python exec",
                                   "descriptor wide C exec", "descriptor wide Rust exec",
                                   "cargo test")),
    ("tools/descriptor_reads_check.py", ("descriptor reads agree", "descriptor launches agree")),
    ("examples/descriptor_reads.axisl", ("descriptor reads agree",
                                         "descriptor launches agree",
                                         "descriptor reads python exec",
                                         "descriptor reads wide C exec",
                                         "descriptor reads wide Rust exec", "cargo test")),
    ("tools/kernel_check.py", ("kernel launches agree",)),
    ("examples/kernel.axisl", ("kernel launches agree", "kernel python exec",
                               "kernel wide C exec", "kernel wide Rust exec",
                               "cargo test")),
    ("examples/nested_loads.axisl", ("nested loads python exec",
                                     "nested loads wide C exec",
                                     "nested loads wide Rust exec", "cargo test")),
    ("examples/completion.axisl", ("completion contract agrees", "completion python exec", "completion wide C exec",
                                   "completion wide Rust exec", "cargo test")),
    ("examples/behavior_forms.axisl", ("behavior forms agree",
                                       "behavior forms C == golden", "behavior forms python exec", "behavior forms wide C exec",
                                       "behavior forms wide Rust exec", "cargo test")),
    ("examples/tilecfg.axisl", ("configuration agrees", "tile configuration python exec", "tile configuration wide C exec",
                                "tile configuration wide Rust exec", "cargo test")),
    ("examples/access_map.axisl", ("access map C == golden",
                                   "access map LLVM == golden",
                                   "access map generalises", "cargo test")),
    ("examples/matrix.axisl", ("matrix C == golden", "matrix LLVM == golden",
                               "matrix indices agree", "matrix scalable exec (C)",
                               "matrix scalable exec (Rust)", "cargo test")),
    ("examples/fp8.axisl", ("fp8 C == golden", "fp8 LLVM == golden",
                            "fp8 SMT == golden", "fp8 rounds correctly",
                            "fp8 python exec", "fp8 wide C exec",
                            "fp8 wide Rust exec", "cargo test")),
    ("tools/expression_depth_check.py", ("expression depth",)),
    ("tools/contraction_check.py", ("contraction folds freely",)),
    ("examples/contraction.axisl", ("contraction C == golden",
                                    "contraction LLVM == golden",
                                    "contraction folds freely", "contraction python exec", "contraction wide C exec",
                                    "contraction wide Rust exec", "cargo test")),
    # The guard lives with the shared semantics validator, and the loop
    # expansion is what reaches it, so both select this gate.
    ("src/semantics.rs", None),
    ("src/loops.rs", ("expression depth", "loop == built-in (proved)",
                      "contraction folds freely", "contraction C == golden",
                      "contraction LLVM == golden", "cargo test")),
    ("src/interchange.rs", ("bf16 C == golden", "bf16 LLVM == golden",
                            "bf16 SMT == golden", "bf16 rounds correctly",
                            "fp8 C == golden", "fp8 LLVM == golden",
                            "fp8 SMT == golden", "fp8 rounds correctly",
                            "cargo test")),
    ("examples/bf16.axisl", ("bf16 C == golden", "bf16 LLVM == golden",
                             "bf16 SMT == golden", "bf16 rounds correctly",
                             "bf16 python exec", "bf16 wide C exec",
                             "bf16 wide Rust exec", "cargo test")),
    ("examples/fp16.axisl", ("half LLVM == golden", "half C == golden",
                             "half Rust == golden", "half SMT == golden",
                             "half over every pattern", "half python exec", "half wide C exec",
                             "half wide Rust exec", "cargo test")),
    ("tools/reduction_order_check.py", ("reduction order",)),
    ("tools/packet_roundtrip.py", ("packet roundtrip",)),
    # packet_vs_serial is imported by the exposed gate for its packet builder,
    # so a change to it reaches both.
    ("tools/packet_vs_serial.py", ("packet semantics", "exposed latency")),
    ("tools/exposed_latency_check.py", ("exposed latency",)),
    ("examples/vliw_packet.axisl", ("packet roundtrip", "packet semantics", "cargo test")),
    ("examples/vliw_exposed.axisl", ("exposed latency", "cargo test")),
    # The golden model feeds llvm_patterns_check and every semantics gate.
    ("src/emit/semantics.rs", None),
]


def affected_gates(ref: str) -> tuple[set[str] | None, list[str]]:
    """Gate-label substrings the working tree's changes can affect.

    `None` means "everything" -- returned whenever a changed path is not
    described above, which includes every change to the frontend, the IR, the
    effect model or a corpus. Those reach too much to enumerate honestly.
    """
    try:
        tracked = subprocess.run(
            ["git", "diff", "--name-only", ref],
            cwd=AXIS_ROOT, capture_output=True, text=True, check=True).stdout.split()
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            cwd=AXIS_ROOT, capture_output=True, text=True, check=True).stdout.split()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None, []
    changed = sorted(set(tracked) | set(untracked))
    if not changed:
        return set(), changed
    selected: set[str] = set()
    for path in changed:
        for prefix, labels in AFFECTS:
            if path.startswith(prefix):
                if labels is None:
                    return None, changed
                selected.update(labels)
                break
        else:
            return None, changed
    return selected, changed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--quick", action="store_true",
                        help="skip the slow AArch64-corpus gates")
    parser.add_argument("--only", default="",
                        help="run only gates whose label contains this substring")
    parser.add_argument("--list", action="store_true", help="print the matrix and exit")
    parser.add_argument("--with-pce", action="store_true",
                        help="include pce_smoke_check (needs a PCE checkout)")
    parser.add_argument("--jobs", type=int,
                        default=max(1, min(8, (os.cpu_count() or 2) - 2)),
                        help="gates to run at once (1 restores the old "
                             "sequential run)")
    parser.add_argument("--changed", nargs="?", const="HEAD", default=None,
                        metavar="REF",
                        help="run only the gates the working tree's changes "
                             "can affect (default REF: HEAD). Falls back to "
                             "the whole ladder whenever a changed path is not "
                             "one this knows the reach of.")
    args = parser.parse_args()

    selected: set[str] | None = None
    if args.changed is not None:
        selected, changed = affected_gates(args.changed)
        print(f"--changed {args.changed}: {len(changed)} path(s) differ")
        if selected is None:
            print("  reach not known for at least one of them; "
                  "running the whole ladder")
        elif not selected:
            print("  nothing that gates anything changed")
        else:
            print(f"  selecting: {', '.join(sorted(selected))}")

    gates = [
        (label, argv) for label, argv, slow in matrix(args.with_pce)
        if not (args.quick and slow)
        and args.only.lower() in label.lower()
        and (selected is None
             or any(one.lower() in label.lower() for one in selected))
    ]
    if args.list:
        for label, argv in gates:
            print(f"{label:32} {' '.join(Path(a).name if '/' in a else a for a in argv)}")
        return 0
    if not gates:
        if selected == set():
            print("no gates affected")
            return 0
        print("no gates matched")
        return 1

    failures: list[str] = []
    skips: list[str] = []
    started = time.monotonic()

    # Build once, then point the gates at what was built. Building first is
    # the necessary half and not the sufficient one: the first parallel run of
    # the whole ladder still failed nine gates, because `cargo run` races with
    # itself over a binary it is prepared to replace. The gates have to stop
    # invoking cargo, which is what `AXIS_BIN` below is for.
    environment = dict(os.environ)
    # ⚠️ One temporary directory per run, removed when it ends. The gates
    # `mkdtemp` and mostly never clean up -- a work directory is what a
    # failure is diagnosed from -- and after a few hundred ladders the system
    # temp held ~196,000 `axis_*` directories, 56 GB, some a whole checkout.
    # A gate's TMPDIR is this one, so everything it leaves goes with the run;
    # to keep a failing gate's files, rerun that gate by hand.
    scratch = Path(tempfile.mkdtemp(prefix="axis_ladder_"))
    atexit.register(shutil.rmtree, scratch, True)
    environment["TMPDIR"] = str(scratch)
    if args.jobs != 1:
        build = subprocess.run(["cargo", "build", "--quiet"], cwd=AXIS_ROOT,
                               capture_output=True, text=True)
        if build.returncode != 0:
            print("cargo build failed; nothing can run")
            print(build.stderr.strip()[-2000:])
            return 1
        # And the gates exec it directly. Building first is not enough on its
        # own: cargo races with itself even over a fresh binary, which is what
        # failed nine gates the first time this ran concurrently. See
        # `tools/axis_cli.py`.
        environment["AXIS_BIN"] = str(AXIS_ROOT / "target" / "debug" / "axis")

    def run_gate(entry: tuple[str, list[str]]):
        label, argv = entry
        begin = time.monotonic()
        result = subprocess.run(argv, cwd=AXIS_ROOT, capture_output=True,
                                text=True, env=environment)
        return label, argv, result, time.monotonic() - begin

    def report(finished) -> None:
        label, argv, result, elapsed = finished
        lines = [line for line in result.stdout.strip().splitlines() if line.strip()]
        if argv[0] == "cargo":
            # cargo prints one result line per test binary and the last one is
            # usually an empty doc-test target, so the tail is misleading.
            passed = sum(int(line.split()[3]) for line in lines
                         if line.startswith("test result:"))
            failed = sum(int(line.split()[5]) for line in lines
                         if line.startswith("test result:"))
            verdict = f"{passed} tests passed, {failed} failed"
        else:
            verdict = lines[-1] if lines else "(no output)"
        if result.returncode == DECLINED:
            # **Still a failure here, and labelled so it reads as one.** A gate
            # in this ladder is paired with a corpus *chosen to exercise it*,
            # so "nothing here to check" means that pairing stopped proving
            # what it claims -- which is exactly what the vacuity guards were
            # written to catch. `evidence_manifest` reads the same status the
            # other way, because it runs gates against an arbitrary description
            # where a decline really is "not applicable". One status, two
            # readings, both right; see `axis_cli`.
            status = "DECL"
            failures.append(label)
        elif result.returncode != 0:
            status = "FAIL"
            failures.append(label)
        elif verdict.startswith("SKIP") or "SKIP" in verdict:
            status = "SKIP"
            skips.append(label)
        else:
            status = "ok"
        # Flushed per gate: the ladder takes minutes, so progress has to be
        # visible even when the output is piped. In a pool these arrive in
        # completion order, which is what progress means here.
        print(f"[{status:4}] {label:32} {elapsed:6.1f}s  {verdict[:88]}", flush=True)
        if status == "FAIL":
            for line in (result.stdout.strip().splitlines()[-6:]
                         + result.stderr.strip().splitlines()[-6:]):
                print(f"         | {line[:110]}")

    if args.jobs == 1:
        for entry in gates:
            report(run_gate(entry))
    else:
        # `cargo test` first and alone. It is the one gate that compiles, so
        # letting it share the lock with the pool is the situation this is
        # avoiding.
        compiling = [entry for entry in gates if entry[1][0] == "cargo"]
        rest = [entry for entry in gates if entry[1][0] != "cargo"]
        for entry in compiling:
            report(run_gate(entry))
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            pending = [pool.submit(run_gate, entry) for entry in rest]
            for future in concurrent.futures.as_completed(pending):
                report(future.result())

    total = time.monotonic() - started
    print(f"\n{len(gates)} gates in {total:.1f}s: "
          f"{len(gates) - len(failures) - len(skips)} passed, "
          f"{len(skips)} skipped, {len(failures)} failed")
    # Said every time, and not only when something is skipped. A subset that
    # passes is not the ladder passing, and the number that makes that obvious
    # belongs next to the one that could be mistaken for it.
    whole = len(matrix(args.with_pce))
    if len(gates) < whole:
        print(f"SUBSET: {len(gates)} of {whole} gates ran. "
              f"Run without --changed/--only/--quick before committing.")
    # Named, not merely counted. A skip is coverage that did not happen, and
    # the summary reported it as a number while naming every failure -- so a
    # gate that quietly stopped running looked like a gate that passed. The
    # same argument as the SUBSET line above, one line further down.
    if skips:
        print("skipped: " + ", ".join(skips))
    if failures:
        print("failed: " + ", ".join(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
