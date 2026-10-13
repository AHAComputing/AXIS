#!/usr/bin/env python3
"""A declared latency is a claim about hardware. Gate.

Every other gate in this ladder holds an artifact against another artifact.
This one holds a DESCRIPTION against silicon. `latency` was free text until a
scoreboard read it; reading it made the model self-consistent and said nothing
about whether the number is true. The machine this runs on is an arm64 Mac and
the corpus describes AArch64, so for once the claim can be put back to the
hardware and checked.

⚠️ The method is a RATIO OF DEPENDENT CHAINS, because that is the one
measurement that survives not knowing the clock. A chain of N instructions that
each read what the last one wrote takes N x latency cycles whatever else the
machine is doing; two such chains of the same length differ in time by exactly
the ratio of their latencies. Frequency cancels. Issue width cancels. Unit
counts cancel -- a chain uses one unit at a time by construction. What is left
is latency, which is what the description declares.

  measured(X) / measured(baseline) == declared(X) / declared(baseline)

⚠️ What this cannot see. A data-dependent unit -- an integer divider, most
obviously -- is measured at whatever operands the chain happens to produce,
which need not be its worst case; a description that declares a worst case and
a measurement that finds a typical one disagree for a reason that is nobody's
mistake. Instructions that are not the host's are refused rather than run: a
description may invent an opcode, and inventing one is not a licence to execute
it. Each kernel runs as its own process so that one that is not real takes
itself down and not the gate.

Usage: tools/silicon_check.py <corpus.axisl> [--isa NAME] [--tolerance F]
"""
from __future__ import annotations

import argparse
import importlib
import json
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Instructions per unrolled chain body. ⚠️ Long enough that the loop's own
#: counter and branch -- which are independent of the chain and overlap with
#: it -- are a rounding error rather than a term.
BODY = 128
ITERATIONS = 20000
TRIALS = 15
#: How far two independent measurements of the same instruction may differ
#: before the gate stops believing either of them.
STABILITY = 0.10

HARNESS = r"""
/* Two dependent chains, INTERLEAVED, and the smallest ratio between them.

   ⚠️ Both in one process, alternating. Timing the two as separate programs
   made the measurement a property of how busy the machine was rather than of
   the instruction -- this gate runs in a ladder that executes gates
   concurrently, and a baseline descheduled differently from its target gives
   a ratio with nothing to do with latency. Adjacent measurements see adjacent
   conditions, and the minimum over many pairs is the closest thing to an
   unloaded one. */
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#define TIME_IT(BODY, OUT)                                                   \
  do {                                                                       \
    struct timespec a__, b__;                                                \
    clock_gettime(CLOCK_MONOTONIC, &a__);                                    \
    __asm__ volatile(                                                        \
      "mov x9, %%[seed]\n"                                                    \
      "mov x10, #1\n"                                                        \
      "mov x11, %%[iters]\n"                                                  \
      "1:\n" BODY                                                            \
      "subs x11, x11, #1\n"                                                  \
      "b.ne 1b\n"                                                            \
      :                                                                      \
      : [seed] "r" ((uint64_t)0x123456789ABCDEFull),                         \
        [iters] "r" ((uint64_t)%(iters)d)                                    \
      : "x9", "x10", "x11", "v9", "v10", "cc", "memory");                    \
    clock_gettime(CLOCK_MONOTONIC, &b__);                                    \
    (OUT) = (double)(b__.tv_sec - a__.tv_sec)                                \
          + (double)(b__.tv_nsec - a__.tv_nsec) / 1e9;                       \
  } while (0)

int main(void) {
  double best = 1e30, warm = 0.0;
  /* ⚠️ Warm both before timing either. */
  TIME_IT(%(base)s, warm);
  TIME_IT(%(target)s, warm);
  /* ⚠️ THE MINIMUM OF EACH, and the ratio OUTSIDE it. Noise can only make a
     measurement slower, so the smallest time observed is the best estimate of
     the unloaded one -- but the smallest RATIO is not an estimate of
     anything. Over noisy pairs it picks the trial where the denominator was
     unluckiest, and two identical chains then came out at 0.09x, which is not
     a property of any instruction.

     ⚠️ And each is timed in BOTH positions, because the second one measured
     is systematically warmer; one fixed order put RBIT against itself at
     0.44x. */
  double base_best = 1e30, target_best = 1e30;
  for (int trial = 0; trial < %(trials)d; ++trial) {
    double b1 = 0.0, t1 = 0.0, t2 = 0.0, b2 = 0.0;
    TIME_IT(%(base)s, b1);
    TIME_IT(%(target)s, t1);
    TIME_IT(%(target)s, t2);
    TIME_IT(%(base)s, b2);
    if (b1 > 0.0 && b1 < base_best) { base_best = b1; }
    if (b2 > 0.0 && b2 < base_best) { base_best = b2; }
    if (t1 > 0.0 && t1 < target_best) { target_best = t1; }
    if (t2 > 0.0 && t2 < target_best) { target_best = t2; }
  }
  if (base_best < 1e29 && target_best < 1e29) { best = target_best / base_best; }
  if (best > 1e29) { printf("NOTIMED\n"); return 1; }
  printf("RATIO %%.6f\n", best);
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def chain_word(lift, entry, encoded):
    """Every register operand on one register, so the chain is a chain.

    ⚠️ The destination and the FIRST register source share a register, which
    is what makes each instruction wait for the one before it. The remaining
    sources take a register holding one, so the value neither explodes nor
    collapses to zero -- a chain whose operand becomes zero is measuring a
    divider's early-out rather than its latency.
    """
    # ⚠️ ONE REGISTER CLASS throughout, or there is no chain. `ucvtf d0, w1`
    # writes a floating register and reads a general one: put "register 9" in
    # both fields and they are different registers in different files, the
    # instructions do not depend on each other at all, and what gets measured
    # is throughput wearing latency's name. It measured 0.14x a one-cycle
    # instruction, which is the shape of that mistake.
    kinds = {operand["kind"] for operand in entry["operands"]}
    if len(kinds) != 1:
        return None
    built = encoded
    first = True
    for operand in entry["operands"]:
        if not lift.is_register_operand(operand["kind"]):
            return None
        if operand["role"] in ("out", "inout"):
            built = lift.place_operand(built, entry, operand["name"], 9)
        elif first:
            built = lift.place_operand(built, entry, operand["name"], 9)
            first = False
        else:
            built = lift.place_operand(built, entry, operand["name"], 10)
    return built


def measure(base_word: int, word: int, work: Path,
            tag: str) -> tuple[float | None, str]:
    def chain(w: int) -> str:
        return "\n      ".join(f'".inst {w:#010x}\\n"' for _ in range(BODY))

    source = HARNESS % {"base": chain(base_word), "target": chain(word),
                        "iters": ITERATIONS, "trials": TRIALS}
    path = work / f"{tag}.c"
    path.write_text(source)
    binary = work / tag
    try:
        subprocess.run(["cc", "-std=c11", "-O2", "-o", str(binary), str(path)],
                       check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as error:
        # ⚠️ Would not ASSEMBLE is a different finding from would not RUN, and
        # reporting one as the other blames the silicon for the toolchain.
        said = (error.stderr or "").strip().splitlines()
        return None, f"the assembler refused it: {said[-1][:90] if said else '?'}"
    # ⚠️ Its own process. A description may name an opcode the host does not
    # have, and the honest outcome of running one is a dead child rather than
    # a dead gate.
    done = subprocess.run([str(binary)], capture_output=True, text=True)
    if "NOTIMED" in done.stdout:
        return None, "the chain reported no time at all"
    if done.returncode != 0:
        return None, (f"the host would not run it (exit {done.returncode}); a "
                      f"description may name an opcode this machine lacks")
    for line in done.stdout.splitlines():
        if line.startswith("RATIO"):
            return float(line.split()[1]), ""
    return None, "the kernel printed nothing"


def check(axis_file: Path, isa: str, tolerance: float) -> tuple[int, int]:
    name = axis_file.stem
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        print(f"  {name}: DECLINED this host is "
              f"{platform.system()}/{platform.machine()}, and the corpus "
              f"describes AArch64; silicon cannot be asked here")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
                 "-o", str(work / f"si_{name}.py")])
        sys.path.insert(0, str(work))
        lift = importlib.import_module(f"si_{name}")
        tests = {test["mnemonic"]: test for test in json.loads(
            run_cmd([*axis_prefix(), "emit-roundtrip-json",
                     str(axis_file)]).stdout)["tests"]}
        by_mnemonic = {row["mnemonic"]: row for row in lift.AXIS_LIFT_TABLE}

        # ⚠️ The host's OWN instruction set, named rather than guessed. A
        # description may declare an accelerator beside a real machine, and
        # nothing in the description says which of them this computer is.
        pool: dict[int, tuple[str, int]] = {}
        for instruction in facts["instructions"]:
            if instruction["isa"] != isa:
                continue
            mnemonic = instruction["mnemonic"]
            entry, test = by_mnemonic.get(mnemonic), tests.get(mnemonic)
            if entry is None or test is None or entry.get("effects"):
                continue
            outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
            if len(outs) != 1:
                continue
            word = chain_word(lift, entry, int(test["encoded"], 16))
            if word is None:
                continue
            latency = instruction.get("latency_cycles") or 1
            pool.setdefault(latency, (mnemonic, word))
        sys.modules.pop(f"si_{name}", None)

        if 1 not in pool or len(pool) < 2:
            print(f"  {name}: DECLINED needs a register-only instruction of "
                  f"latency one to measure against, and at least one other")
            return 0, 0

        base_mnemonic, base_word = pool[1]
        # ⚠️ The baseline against ITSELF first. Two identical chains must come
        # out at one; a machine that cannot produce that is too busy to be
        # asked about latency at all, and saying so beats reporting a ratio
        # that measured the load. This is the gate's own vacuity check.
        sanity, why = measure(base_word, base_word, work, "sanity")
        if sanity is None:
            print(f"  {name}: DECLINED no baseline: {base_mnemonic} -- {why}")
            return 0, 0
        if abs(sanity - 1.0) > 0.15:
            print(f"  {name}: DECLINED this machine timed {base_mnemonic} "
                  f"against itself at {sanity:.2f}x; it is too loaded to be "
                  f"asked what an instruction costs")
            return 0, 0

        checks = failures = 0
        report = []
        for latency in sorted(pool):
            if latency == 1:
                continue
            mnemonic, word = pool[latency]
            # ⚠️ TWICE, and they have to agree. Some units are data dependent
            # -- an integer divider most obviously -- and a chain measures
            # them at whatever operands it happens to produce rather than at
            # their worst case. An instruction whose measured latency is not
            # reproducible is one this method cannot speak about, and saying
            # so by name beats widening the tolerance until nothing fails,
            # which would blunt the check for everything else.
            ratio, why = measure(base_word, word, work, f"m{latency}")
            if ratio is None:
                print(f"  {name}: DECLINED {mnemonic} -- {why}")
                continue
            again, why = measure(base_word, word, work, f"n{latency}")
            if again is None:
                print(f"  {name}: DECLINED {mnemonic} -- {why}")
                continue
            if abs(ratio - again) > STABILITY * min(ratio, again):
                print(f"  {name}: DECLINED {mnemonic} measured {ratio:.2f}x "
                      f"and then {again:.2f}x; a latency this machine will "
                      f"not repeat is not one to hold a description to")
                continue
            ratio = min(ratio, again)
            report.append(f"{mnemonic} declared {latency} measured {ratio:.2f}")
            checks += 1
            if abs(ratio - latency) > tolerance * latency:
                print(f"  FAIL {name}: {mnemonic} declares a latency of "
                      f"{latency} and {base_mnemonic} declares 1, so a chain "
                      f"of the first should take {latency:.2f}x the time of a "
                      f"chain of the second; this machine took "
                      f"{ratio:.2f}x")
                failures += 1

        if not checks:
            print(f"  {name}: DECLINED nothing of the host's ran")
            return 0, 0
        if not failures:
            print(f"  {name}: against {base_mnemonic}, " + "; ".join(report)
                  + f", {checks} checks")
        return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--isa", default="aarch64_base")
    # ⚠️ Wide on purpose. This is not a cycle-accurate measurement: it is
    # asking whether a declared number is the right number rather than a
    # plausible-looking wrong one. A tolerance tight enough to be impressive
    # would be a gate that fails on a warm afternoon. The margins actually
    # observed are 8% and 14%, so a third leaves better than twice the
    # headroom and still catches a declared three that is really a one.
    parser.add_argument("--tolerance", type=float, default=0.30)
    args = parser.parse_args()
    checks, failures = check(args.corpus, args.isa, args.tolerance)
    if not checks and not failures:
        print("a declared latency is what the silicon does: SKIP")
        return DECLINED
    print(f"a declared latency is what the silicon does: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
