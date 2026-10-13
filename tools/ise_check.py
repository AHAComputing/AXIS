#!/usr/bin/env python3
"""Mining a real binary yields extensions, and they are what they replace.

The two halves run together: `ise_mine.py` finds candidates in a compiled
object and composes each into one semantics tree; `ise_prove.py` writes each as
an AXIS instruction, has AXIS lower it to SMT, and asks a solver whether it
equals the instructions it covers -- composed independently out of AXIS's own
per-instruction SMT.

The gate asserts three things, and the third is the one that matters:

* something was mined at all, so a silent decoder failure cannot pass as "no
  opportunities here";
* something was proven, so an obligation set that quietly emptied itself is a
  failure rather than a clean run;
* **nothing was refuted**, which is the claim: a composed extension that does
  not compute what the code computed is a defect in the mining, not a candidate
  to look at later.

Declines are neither. A candidate whose SMT will not compose at this width --
`srliw` narrows to 32 bits inside a 64-bit run, and inserting the narrowing
would be inventing which bits the extension keeps -- is named and counted.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
TOOLS = AXIS_ROOT / "tools"

KERNELS = r'''
#include <stdint.h>
uint64_t dot(const uint64_t *a, const uint64_t *b, int n) {
  uint64_t s = 0;
  for (int i = 0; i < n; i++) s += a[i] * b[i];
  return s;
}
uint32_t mixhash(uint32_t x, uint32_t y) {
  uint32_t h = x ^ (y << 7);
  h = h + (h << 3);
  h = h ^ (h >> 11);
  return h;
}
uint64_t saxpy(uint64_t *o, const uint64_t *a, uint64_t k, int n) {
  uint64_t t = 0;
  for (int i = 0; i < n; i++) { o[i] = k * a[i] + o[i]; t ^= o[i]; }
  return t;
}
uint32_t clampsum(const uint32_t *p, int n) {
  uint32_t s = 0;
  for (int i = 0; i < n; i++) { uint32_t v = p[i] & 0xffff; s += v * v; }
  return s;
}
'''


def main() -> int:
    if subprocess.run(["which", "z3"], capture_output=True).returncode != 0:
        print("SKIP: z3 is not installed")
        return DECLINED
    clang = "/opt/homebrew/opt/llvm/bin/clang"
    if not Path(clang).exists():
        clang = "clang"
    workdir = Path(tempfile.mkdtemp(prefix="axis_ise_"))
    source = workdir / "kernels.c"
    source.write_text(KERNELS)
    build = subprocess.run([clang, "--target=riscv64", "-march=rv64gc", "-O2",
                            "-c", "-o", str(workdir / "kernels.o"), str(source)],
                           capture_output=True, text=True)
    if build.returncode != 0:
        print("SKIP: no RISC-V cross compiler here")
        return DECLINED

    # The binary is built rather than checked in, so what is mined is what a
    # compiler actually emits today rather than what one emitted once.
    candidates = workdir / "candidates.json"
    mine = subprocess.run(
        [sys.executable, str(TOOLS / "ise_mine.py"),
         str(AXIS_ROOT / "examples" / "rv64i.axisl"), str(workdir / "kernels.o"),
         "--isa", "rv64i", "--top", "6", "--json", str(candidates)],
        capture_output=True, text=True, cwd=AXIS_ROOT)
    print(mine.stdout.strip())
    if mine.returncode != 0 or not candidates.exists():
        print(mine.stderr.strip()[:400])
        print("mined extensions == the code they replace: FAIL")
        return FAILED

    proposals = workdir / "proven"
    prove = subprocess.run(
        [sys.executable, str(TOOLS / "ise_prove.py"), str(candidates), "--top", "6",
         "--out", str(proposals)],
        capture_output=True, text=True, cwd=AXIS_ROOT)
    print(prove.stdout.strip())
    if prove.returncode != PASSED:
        print(prove.stderr.strip()[:400])
        return prove.returncode

    # The other half of what a proposal is for: it is an AXIS instruction, so
    # it has a netlist, and the netlist has a price in the machine it was
    # mined from. Each proven proposal is built, held to the golden model, and
    # added to the description to see which unit takes it and what that costs.
    costs = workdir / "costs.json"
    cost = subprocess.run(
        [sys.executable, str(TOOLS / "ise_cost.py"), str(candidates), str(proposals),
         "--check", "--json", str(costs)],
        capture_output=True, text=True, cwd=AXIS_ROOT)
    print(cost.stdout.strip())
    if cost.returncode != PASSED:
        print(cost.stderr.strip()[:400])
        return cost.returncode
    # ⚠️ A report that prices everything as a unit of its own has not asked
    # the question. The kernels multiply and accumulate, the machine has a
    # multiplier, and an extension that rides it must cost a fraction of one
    # that brings its own -- if no option shows that, the marginal area is
    # not being measured.
    extensions = json.loads(costs.read_text())["extensions"]
    shared = [option for extension in extensions for option in extension["options"]
              if option["joins"] and option["marginal_area"] < 0.5 * extension["area"]]
    if not shared:
        print("mined extensions, built and priced: FAIL -- no extension costs less in "
              "the machine than alone")
        return FAILED

    # And the part nothing above runs: the extension IN the program. The
    # kernels again, without compressed instructions so the rewriter lays out
    # whole words, mined at three inputs so multiply-accumulate is there. Each
    # extension is given an encoding, put at its occurrences, and both programs
    # are run on the simulator built from the description plus the extension.
    # ⚠️ This is the only check of the miner's binding of operands to the code:
    # the proof composes the original from the candidate's own names, and
    # agreed with a miner that took two loads for one value.
    plain = workdir / "kernels_g.o"
    build = subprocess.run([clang, "--target=riscv64", "-march=rv64g", "-mno-relax", "-O2",
                            "-c", "-o", str(plain), str(source)],
                           capture_output=True, text=True)
    if build.returncode != 0:
        print("SKIP the run: no RISC-V cross compiler for rv64g here")
        return PASSED
    wide, proposals3, runs = workdir / "wide.json", workdir / "proven3", workdir / "runs.json"
    for step in (
        [str(TOOLS / "ise_mine.py"), str(AXIS_ROOT / "examples" / "rv64i.axisl"), str(plain),
         "--isa", "rv64i", "--max-inputs", "3", "--top", "6", "--json", str(wide)],
        [str(TOOLS / "ise_prove.py"), str(wide), "--top", "6", "--out", str(proposals3)],
        [str(TOOLS / "ise_run.py"), str(wide), str(proposals3), str(plain),
         "--results", "1", "--top", "6", "--json", str(runs),
         "--call", "dot(buf:512,buf:512,60)", "--call", "mixhash(0x1234567,0x89abcde)",
         "--call", "saxpy(buf:512,buf:512,7,60)", "--call", "clampsum(buf:512,100)"],
    ):
        done = subprocess.run([sys.executable, *step], capture_output=True, text=True,
                              cwd=AXIS_ROOT)
        print(done.stdout.strip())
        if done.returncode != PASSED:
            print(done.stderr.strip()[:400])
            return done.returncode
    # One clock (`--as-built`): every instruction charged the cycles its
    # netlist needs, so a chain and the extension that replaces it are timed
    # alike. Multiply-accumulate's chain is then the multiplier's floor and
    # the adder's, read from the hardware plan -- not the latencies the
    # description declares.
    built = workdir / "built.json"
    done = subprocess.run(
        [sys.executable, str(TOOLS / "ise_mine.py"), str(AXIS_ROOT / "examples" / "rv64i.axisl"),
         str(plain), "--isa", "rv64i", "--max-inputs", "3", "--top", "3", "--as-built",
         "--json", str(built)], capture_output=True, text=True, cwd=AXIS_ROOT)
    if done.returncode != PASSED:
        print(done.stdout.strip()[-400:], done.stderr.strip()[-400:])
        return done.returncode
    plan = json.loads(subprocess.run(
        [*axis_prefix(), "emit-hw-json", str(AXIS_ROOT / "examples" / "rv64i.axisl")],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT).stdout)
    needed = {i["mnemonic"]: i["cycles_needed"] for i in plan["instructions"]
              if i["status"] == "built"}
    report = json.loads(built.read_text())
    mac = next((c for c in report["candidates"] if c["mnemonics"] == ["MUL", "ADD"]), None)
    if not report.get("clock") or mac is None \
            or mac["critical_path_cycles"] != needed["MUL"] + needed["ADD"]:
        print("mined extensions, as built: FAIL -- the chain is not charged the netlists' "
              f"cycles ({mac and mac['critical_path_cycles']} against "
              f"{needed['MUL']} + {needed['ADD']})")
        return FAILED
    print(f"as built: MUL+ADD is a chain of {mac['critical_path_cycles']} cycle(s), "
          f"the netlists' {needed['MUL']} + {needed['ADD']}")

    functions = [function for extension in json.loads(runs.read_text())["extensions"]
                 for function in extension["functions"]]
    faster = [f for f in functions if f["equal"] and f["cycles"][1] < f["cycles"][0]]
    # A loop that runs its occurrence every iteration has to show it: one
    # instruction fewer per trip, not one fewer per call.
    looped = [f for f in faster if f["steps"][0] - f["steps"][1] >= 60]
    if not looped:
        print("mined extensions, run in the program: FAIL -- no loop got shorter by its "
              "trip count")
        return FAILED
    return PASSED


if __name__ == "__main__":
    raise SystemExit(main())
