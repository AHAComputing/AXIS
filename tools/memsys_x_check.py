#!/usr/bin/env python3
"""An execution-driven core asks the memory system WHEN (U3). Gate.

`(memory-timing timed)` on an execution-driven port of a `defmemsys` charges
each load what `axis_ms_access_at` says (docs/unified_engine_design.md):
its data arrives when MSHRs, fills in flight and DRAM let it, at the cycle
the pipeline executes it. Untimed -- every core before U3 -- charges each
access its cost alone, however many are in flight.

Over the example memory system, made non-coherent and with no prefetcher so
that nothing but the access itself is timed:

  * ONE ACCESS AT A TIME, NO DIFFERENCE. A pointer chase -- each load's
    address waits on the last load -- runs in exactly as many cycles timed as
    untimed: with nothing else in flight, a timed access costs what an
    untimed one does (U1's invariant, seen through the pipeline).
  * MANY AT ONCE, MSHRS BIND. Independent loads that all miss: timed, one
    MSHR is slower than four; untimed, the MSHR count changes nothing,
    because the untimed path never sees more than one access.
  * REFUSALS. A trace-driven core asking for timed memory, and a timed core
    no memory system names, are refused.

Usage: tools/memsys_x_check.py [examples/memory_system.axisl]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_pack  # noqa: E402
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402
from memsys_pack_check import ENTRY, b_type, i_type  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

CORE = """  (defcore %(name)s
    (kind rvmt)
    (implements ms64)
    (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2))
    (engine execute)%(timing)s
    (units
      (alu (count 4) (pipelined true))
      (lsu (count 2) (pipelined true))
      (br (count 1) (pipelined true))))
"""
OLD_CPU = """  (defcore %s
    (kind rvmt)
    (implements ms64)
    (issue-width 1)
    (units
      (alu (count 1) (pipelined true))
      (lsu (count 1) (pipelined true))
      (br (count 1) (pipelined true))))
"""
EDITS = [("(protocol moesi)", "(protocol none)"),
         ("(region 0x0 0x80000000 ddr0 (home l2))", "(region 0x0 0x80000000 ddr0)"),
         ("(inclusion inclusive)\n    (prefetch next-line)\n    (prefetch-degree 1)", "(inclusion nine)"),
         (OLD_CPU % "cpu0", CORE % {"name": "cpu0", "timing": "\n    (memory-timing timed)"}),
         (OLD_CPU % "cpu1", CORE % {"name": "cpu1", "timing": ""})]


def r_type(opcode, funct3, funct7, rd, rs1, rs2):
    return (funct7 << 25) | (rs2 << 20) | (rs1 << 15) | (funct3 << 12) | (rd << 7) | opcode


def program(chase: bool, base: int, count: int, stride: int) -> list[int]:
    """x1 = base; x2 = count; do { ld x3,0(x1); [add x1,x1,x3]; x1 += stride; x2 -= 1 } while x2.
    Memory reads 0, so the add changes nothing but makes each address wait on the last load."""
    body = [i_type(0x03, 3, 3, 1, 0)]
    if chase:
        body.append(r_type(0x33, 0, 0, 1, 1, 3))
    body += [i_type(0x13, 0, 1, 1, stride), i_type(0x13, 0, 2, 2, -1)]
    body.append(b_type(0x63, 1, 2, 0, -4 * len(body)))
    return [i_type(0x13, 0, 1, 0, base), i_type(0x13, 0, 2, 0, count)] + body


HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axis_pack.h"
extern const axis_sim_pack *%(sim)s(void);
static const axis_sim_pack *S;
#define IMAGE (1 << 16)
static uint8_t CODE[IMAGE];
static uint32_t LEN;
static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; (void)a; (void)w; return 0; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; (void)a; (void)v; (void)w; }
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE && pc >= %(entry)d && pc < %(entry)d + 4 * LEN;
  if (!*ok) return 0u;
  uint32_t v = 0; for (uint32_t i = 0; i < 4; ++i) v |= (uint32_t)CODE[pc + i] << (8 * i); return v;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) { (void)c; (void)cause; *stop = 1; return pc; }
int main(int argc, char **argv) {
  S = %(sim)s();
  LEN = (uint32_t)(argc - 2);
  for (int i = 2; i < argc; ++i) {
    unsigned long w = strtoul(argv[i], 0, 0);
    for (uint32_t b = 0; b < 4; ++b) CODE[%(entry)d + 4 * (i - 2) + b] = (uint8_t)(w >> (8 * b));
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!S->select_core(m, argv[1])) { printf("NOCORE\n"); return 1; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  S->count_cycles(m, 1);
  unsigned long long steps = 0;
  while (S->step(m) == AXIS_PACK_SIM_RUNNING && steps < 1000000) steps++;
  printf("RUN %%llu %%llu\n", steps, (unsigned long long)S->cycles(m));
  S->destroy(m);
  return 0;
}
"""


def build(text: str, work: Path, tag: str):
    path = work / f"{tag}.axisl"
    path.write_text(text)
    pack = build_pack.build(path, work / f"packs_{tag}", only={"sim", "exec", "lift"})
    root = work / f"packs_{tag}" / pack["name"]
    isa = json.loads(subprocess.run([*axis_prefix(), "emit-json", str(path)], capture_output=True, text=True,
                                    check=True, cwd=AXIS_ROOT).stdout)["isas"][0]["name"]
    (work / f"{tag}.c").write_text(HARNESS % {"sim": pack["libraries"]["sim"]["entry"], "entry": ENTRY,
                                               "isa": f'"{isa}"'})
    binary = work / f"{tag}_h"
    subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(binary), str(work / f"{tag}.c"),
                    str(root / "lib" / pack["libraries"]["sim"]["static"]),
                    str(root / "lib" / pack["libraries"]["exec"]["static"])], check=True, capture_output=True)
    return binary


def cycles(binary: Path, core: str, words: list[int]) -> tuple[int, int]:
    out = subprocess.run([str(binary), core, *map(str, words)], capture_output=True, text=True, check=True).stdout
    _, steps, cyc = out.split()
    return int(steps), int(cyc)


def refused(text: str, work: Path, needle: str) -> bool:
    path = work / "refuse.axisl"
    path.write_text(text)
    run = subprocess.run([*axis_prefix(), "check", str(path)], capture_output=True, text=True, cwd=AXIS_ROOT)
    return run.returncode != 0 and needle in (run.stdout + run.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    text = args.axis_file.read_text()
    failures: list[str] = []
    for old, _ in EDITS:
        if text.count(old) != 1:
            failures.append(f"the anchor {old[:40]!r} is not in the example once")
    if failures:
        for f in failures:
            print(f"  FAIL {f}")
        return FAILED
    for old, new in EDITS:
        text = text.replace(old, new)
    one_mshr = text.replace("(allocate write-allocate)\n    (mshrs 4)", "(allocate write-allocate)\n    (mshrs 1)")
    chase, stream = program(True, 0x4000, 300, 1088), program(False, 0x4000, 300, 1088)
    with tempfile.TemporaryDirectory(prefix="axis_msx_") as work:
        work = Path(work)
        four, one = build(text, work, "four"), build(one_mshr, work, "one")
        ct, cu = cycles(four, "cpu0", chase), cycles(four, "cpu1", chase)
        if ct != cu:
            failures.append(f"a chase took {ct[1]} cycles timed and {cu[1]} untimed (steps {ct[0]}, {cu[0]}); "
                            "one access in flight must cost the same")
        s4t, s4u = cycles(four, "cpu0", stream)[1], cycles(four, "cpu1", stream)[1]
        s1t, s1u = cycles(one, "cpu0", stream)[1], cycles(one, "cpu1", stream)[1]
        if not s1t > s4t:
            failures.append(f"independent misses: timed with one MSHR {s1t} cycles, with four {s4t}; one must be slower")
        if s1u != s4u:
            failures.append(f"independent misses: untimed with one MSHR {s1u}, with four {s4u}; untimed must not see MSHRs")
        trace_timed = text.replace(CORE % {"name": "cpu0", "timing": "\n    (memory-timing timed)"},
                                   OLD_CPU.replace("(issue-width 1)", "(issue-width 1)\n    (memory-timing timed)") % "cpu0")
        if not refused(trace_timed, work, "trace-driven"):
            failures.append("a trace-driven core asking for timed memory was not refused")
        stray = text.replace("(defcore cpu1", "(defcore cpux\n    (kind rvmt) (implements ms64) (issue-width 4)\n"
                             "    (window (rob 32) (issue-queue 32) (commit-width 4))\n"
                             "    (branch (penalty 0) (predictor bimodal) (entries 64))\n"
                             "    (front-end (fetch-width 4) (depth 2)) (engine execute) (memory-timing timed)\n"
                             "    (units (alu (count 1) (pipelined true)) (lsu (count 1) (pipelined true)) (br (count 1) (pipelined true))))\n"
                             "  (defcore cpu1", 1)
        if not refused(stray, work, "no memory system names it"):
            failures.append("a timed core no memory system names was not refused")
    for f in failures:
        print(f"  FAIL {f}")
    print(f"  a 300-load chase: {ct[1]} cycles timed, {cu[1]} untimed; 300 independent misses: timed "
          f"{s4t} (four MSHRs) / {s1t} (one), untimed {s4u} / {s1u}; two refusals")
    verdict = "PASS" if not failures else "FAIL"
    print(f"an execution-driven core asks the memory system when: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
