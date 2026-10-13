#!/usr/bin/env python3
"""Every corpus through every corpus-parameterised driver, gated or not.

`corpus_coverage_check` asks whether a corpus is covered by nothing, and
`check_all` runs the pairs somebody wrote down. Neither asks the other
question: of the pairs nobody wrote down, which ones *work* -- and which ones
fail?

It is worth asking because the answer has been a defect three times. The
clearest: `examples/simd_lanes.axisl` was failing `exec_wide_check` on a green
tree, because no gate ran that corpus through that driver, and the wide
executor's arithmetic shift of a 16-bit lane was unsigned. The gate existed.
The corpus existed. The pair did not.

This runs the whole matrix and sorts the result three ways. It runs the pairs
in parallel, and then **re-runs every failure one at a time before reporting
it**: these drivers compile C and Rust, and eight compilers at once produce
failures that are about the machine rather than about the code. The first sweep
of this matrix reported 102 failures, half of them that. A parallel run is fast
and a serial one is trustworthy, so this does both -- the second pass is small
because failures are.

  * **unexpected failures**: a pair that fails and is not explained below.
    These are the findings; there should be none.
  * **excluded**: a pair that fails for a reason the shape of the corpus
    explains. Four rules cover every one of them, and they are listed in
    EXCLUSIONS with what they mean.
  * **available**: a pair that passes and no gate names. Not a defect -- most
    add nothing a gated pair does not already prove -- but the list is where a
    new gate comes from when a corpus grows a shape its drivers do not have.

Usage:
  tools/gate_matrix.py                    # the whole matrix, ~13 minutes idle

This is an analysis tool rather than a ladder gate, for the reason
`decline_census.py` is: it takes minutes that a per-commit run cannot spend,
and its output is a list to read rather than a verdict to gate on. It does
exit non-zero on an unexpected failure, so it can be run in CI on a schedule.
  tools/gate_matrix.py --tool exec_wide   # one driver against every corpus
  tools/gate_matrix.py --corpus rv32i     # one corpus against every driver
"""

from __future__ import annotations

import argparse
import concurrent.futures
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

AXIS_ROOT = Path(__file__).resolve().parent.parent

# The drivers that take one corpus and compare two artifacts. A tool that
# sweeps every corpus itself (`smt_vs_golden`, `optisynth_vs_golden`) is not
# here: it has no pair to be missing.
DRIVERS: list[tuple[str, list[str]]] = [
    ("exec_vs_golden.py", []),
    ("exec_c_check.py", []),
    ("exec_rust_check.py", []),
    ("exec_wide_check.py", []),
    ("exec_wide_check.py", ["--lang", "rust"]),
    ("c_vs_golden.py", []),
    ("rust_vs_golden.py", []),
    ("llvm_vs_golden.py", []),
    ("roundtrip_check.py", []),
    ("lift_roundtrip.py", []),
    ("lift_native_check.py", []),
    ("asm_disasm_check.py", []),
    ("decode_table_check.py", []),
    ("llvm_effects_check.py", []),
    ("llvm_patterns_check.py", []),
]

# Why a pair fails without anything being wrong. Each is a driver meeting a
# description shape it was not built for, and each names the driver that *is*.
EXCLUSIONS: list[tuple[str, str, str]] = [
    # (tool prefix, corpus predicate name, why)
    ("exec_vs_golden.py", "scalable",
     "a lane writes one element of a VL-sized register; scalable_exec_check.py"),
    ("llvm_effects_check.py", "scalable",
     "same: lanes are that driver's, not this one's"),
    ("roundtrip_check.py", "mode_shared",
     "two instructions share an encoding in disjoint modes, which is what the "
     "corpus is for; decode_table_check.py and legality_vs_golden.py know modes"),
    ("lift_roundtrip.py", "mode_shared", "same"),
    ("lift_native_check.py", "mode_shared", "same"),
    ("roundtrip_check.py", "packet",
     "a syllable is decoded in its slot, not alone; packet_roundtrip.py"),
    ("lift_roundtrip.py", "packet", "same"),
    ("lift_native_check.py", "packet", "same"),
    ("asm_disasm_check.py", "packet", "same"),
    ("exec_wide_check.py", "packet", "same"),
    ("llvm_patterns_check.py", "undefined_dag",
     "every case lands where LLVM leaves the DAG undefined, so the gate's own "
     "vacuity guard fires -- correctly"),
    ("rust_vs_golden.py", "directed_rounding",
     "Rust has no access to the floating-point environment, so it declines the "
     "whole corpus with the reason in the emitted file (simd_fp_design.md 8.4)"),
    ("llvm_vs_golden.py", "directed_rounding",
     "LLVM's constrained intrinsics do not set the rounding mode either; same "
     "decline, same document"),
]

SCALABLE = {"sve", "rvv", "scalable_basic", "scalable_crosslane", "scalable_memory",
            "scalable_predicate", "scalable_vtype"}
MODE_SHARED = {"mode_polymorphic", "lisp_modes_cores"}
PACKET = {"vliw_packet", "vliw_exposed"}
UNDEFINED_DAG = {"shift_widths"}
DIRECTED_ROUNDING = {"fp_rounding"}

SHAPES = {"scalable": SCALABLE, "mode_shared": MODE_SHARED, "packet": PACKET,
          "undefined_dag": UNDEFINED_DAG, "directed_rounding": DIRECTED_ROUNDING}


def excluded(tool: str, corpus: str) -> str | None:
    for prefix, shape, why in EXCLUSIONS:
        if tool == prefix and corpus in SHAPES[shape]:
            return why
    return None


def run_pair(job: tuple[str, tuple[str, ...], str, str]) -> tuple[str, str]:
    """One (driver, corpus) pair: its verdict and the line it ended on."""
    tool, flags, _lang, corpus = job
    argv = [sys.executable, str(AXIS_ROOT / "tools" / tool), *flags,
            str(AXIS_ROOT / "examples" / f"{corpus}.axisl")]
    # A bounded wait, because one driver that does not return would otherwise
    # stall the sweep with no output at all: this tool prints its report at the
    # end, so a hang looks exactly like slow progress. The bound is generous --
    # the slowest honest pair in the matrix is the AArch64 seed at about ninety
    # seconds, and a loaded machine can double that.
    try:
        result = subprocess.run(argv, cwd=AXIS_ROOT, capture_output=True,
                                text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return "FAIL", "no verdict within 300s"
    last = (result.stdout.strip().splitlines() or [""])[-1]
    verdict = ("SKIP" if "SKIP" in last else
               "PASS" if "PASS" in last and result.returncode == 0 else
               "FAIL")
    return verdict, last


def gated_pairs() -> set[tuple[str, str, str]]:
    """(tool, lang, corpus) the ladder names, read from the matrix itself."""
    from check_all import matrix

    pairs = set()
    for _label, argv, _slow in matrix(with_pce=False):
        tool = next((Path(a).name for a in argv if a.endswith(".py")), None)
        corpus = next((Path(a).stem for a in argv if a.endswith(".axisl")), None)
        lang = "rust" if "rust" in argv else "c"
        if tool and corpus:
            pairs.add((tool, lang, corpus))
    return pairs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--tool", default="", help="only drivers whose name contains this")
    parser.add_argument("--corpus", default="", help="only corpora whose name contains this")
    parser.add_argument("--verbose", action="store_true", help="print every pair as it runs")
    parser.add_argument("--jobs", type=int, default=6,
                        help="pairs to run at once (default 6; every failure is "
                             "re-run alone before it is reported)")
    args = parser.parse_args()

    gated = gated_pairs()
    corpora = sorted(p.stem for p in (AXIS_ROOT / "examples").glob("*.axisl"))
    unexpected, available, excluded_pairs = [], [], []
    skipped, gated_passes = 0, 0

    jobs = []
    for tool, flags in DRIVERS:
        if args.tool and args.tool not in tool:
            continue
        lang = "rust" if "rust" in flags else "c"
        for corpus in corpora:
            if args.corpus and args.corpus not in corpus:
                continue
            jobs.append((tool, tuple(flags), lang, corpus))

    started = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        outcomes = list(pool.map(run_pair, jobs))
    for (tool, flags, lang, corpus), (verdict, last) in zip(jobs, outcomes):
        if args.verbose:
            print(f"{verdict:5} {tool} {lang} {corpus}", flush=True)
        pair = (tool, lang, corpus)
        if verdict == "SKIP":
            skipped += 1
        elif verdict == "FAIL":
            # Alone before it is believed. A driver that compiles competes with
            # its seven neighbours for the machine, and half of the first
            # sweep's failures were that competition.
            verdict, last = run_pair((tool, flags, lang, corpus))
            if verdict != "FAIL":
                if verdict == "SKIP":
                    skipped += 1
                elif pair in gated:
                    gated_passes += 1
                else:
                    available.append(pair)
                continue
            why = excluded(tool, corpus)
            (excluded_pairs if why else unexpected).append((pair, why or last))
        elif pair in gated:
            gated_passes += 1
        else:
            available.append(pair)

    total = (len(unexpected) + len(available) + len(excluded_pairs)
             + skipped + gated_passes)
    print(f"{total} pair(s) in {time.time() - started:.0f}s")
    print(f"  {gated_passes} named by a gate, {skipped} with nothing to do, "
          f"{len(excluded_pairs)} excluded by shape, {len(available)} passing and "
          f"named by no gate")
    if available and args.verbose:
        for tool, lang, corpus in available:
            print(f"    available: {tool} {lang} {corpus}")
    if unexpected:
        print(f"\n{len(unexpected)} unexpected failure(s):")
        for (tool, lang, corpus), line in unexpected:
            print(f"  {tool} {lang} {corpus}: {line[:100]}")
    print("gate matrix: " + ("PASS" if not unexpected else "FAIL"))
    return 1 if unexpected else 0


if __name__ == "__main__":
    raise SystemExit(main())
