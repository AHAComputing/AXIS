#!/usr/bin/env python3
"""A store clears the other cores' exclusive monitors (U4c). Gate.

A store-exclusive succeeds on its own core's monitor, and no instruction's
semantics clears another core's: that is the memory system's job. A core that
names its monitor, `(exclusive address size valid)`, has it cleared by every
store another core commits over the bytes it covers
(docs/unified_engine_design.md). Without it, two contexts of the study's
OpenMP dot each read the old total, each passed its own monitor, and the
reduction lost an update.

On RV64 (`examples/rv64i.axisl`, whose LR/SC monitor is ISA state), four
execution-driven cores stepped together each add 1 to one shared word 100
times in an LR/SC retry loop:

  * WITH THE MONITOR DECLARED, NOTHING IS LOST. The word ends at 400, and
    every core's registers are its golden model's.
  * WITHOUT IT, UPDATES ARE LOST. The same cores, the clause removed, end
    below 400. This is the control: a gate that cannot see the bug cannot
    see its fix.
  * REFUSAL. A clause naming state no ISA declares is refused.

Usage: tools/monitor_check.py [examples/rv64i.axisl]
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
CORES = 4
TRIPS = 100
WORD = 0x7F0  # the shared word, below the code (an addi immediate is 12-bit signed)

CORE = """
  (defcore %(name)s
    (kind rvmt)
    (implements rv64i)
    (issue-width 2)
    (window (rob 32) (issue-queue 32) (commit-width 2))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2))
    (engine execute)%(exclusive)s)
"""
CLAUSE = "\n    (exclusive exclusive_address exclusive_size exclusive_valid)"


def amo(func5: int, rd: int, rs1: int, rs2: int) -> int:
    return (func5 << 27) | (rs2 << 20) | (rs1 << 15) | (2 << 12) | (rd << 7) | 0x2F


def program() -> list[int]:
    """x1 = WORD; x2 = TRIPS; do { do { lr.w x3,(x1); x3 += 1; sc.w x4,x3,(x1) } while x4; x2 -= 1 } while x2."""
    return [
        i_type(0x13, 0, 1, 0, WORD),       # addi x1, x0, WORD
        i_type(0x13, 0, 2, 0, TRIPS),      # addi x2, x0, TRIPS
        amo(2, 3, 1, 0),                   # lr.w x3, (x1)
        i_type(0x13, 0, 3, 3, 1),          # addi x3, x3, 1
        amo(3, 4, 1, 3),                   # sc.w x4, x3, (x1)
        b_type(0x63, 1, 4, 0, -12),        # bne x4, x0, lr
        i_type(0x13, 0, 2, 2, -1),         # addi x2, x2, -1
        b_type(0x63, 1, 2, 0, -20),        # bne x2, x0, lr
    ]


HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axis_pack.h"
extern const axis_sim_pack *@SIM@(void);
static uint8_t MEM[1 << 16];
static uint32_t LEN;
static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0; if (a + w / 8 <= sizeof MEM) memcpy(&v, MEM + a, w / 8); return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; if (a + w / 8 <= sizeof MEM) memcpy(MEM + a, &v, w / 8); }
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc >= @ENTRY@ && pc < @ENTRY@ + 4ull * LEN; uint32_t v = 0; if (*ok) memcpy(&v, MEM + pc, 4); return v;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) { (void)c; (void)cause; *stop = 1; return pc; }
int main(int argc, char **argv) {
  const axis_sim_pack *S = @SIM@();
  LEN = (uint32_t)(argc - 2);
  for (int i = 2; i < argc; ++i) { uint32_t w = (uint32_t)strtoul(argv[i], 0, 0); memcpy(MEM + @ENTRY@ + 4 * (i - 2), &w, 4); }
  void *ms[@CORES@];
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  for (int k = 0; k < @CORES@; ++k) {
    ms[k] = S->create(&hooks);
    if (!S->select_core(ms[k], argv[1])) { printf("NOCORE\n"); return 1; }
    /* Every state slot, or the monitor is state that does not exist: LR
       sets nothing and SC reads it clear. */
    axis_pack_state_entry state[64];
    int32_t n = S->state_slots() < 64 ? S->state_slots() : 64;
    for (int32_t i = 0; i < n; ++i) { state[i].name = S->state_name(i); state[i].width = S->state_width(i); state[i].value = 0; }
    S->reset(ms[k], @ENTRY@u, @ISA@, state, n);
    S->count_cycles(ms[k], 1);
  }
  int guard = 0;
  while (S->cycle_cores(ms, @CORES@, 1) > 0 && ++guard < 2000000) {}
  uint32_t word = 0;
  memcpy(&word, MEM + @WORD@, 4);
  printf("WORD %u\n", word);
  for (int k = 0; k < @CORES@; ++k) {
    printf("CORE %d status=%d replays=%llu x2=%llu\n", k, S->status(ms[k]), (unsigned long long)S->replays(ms[k]),
           (unsigned long long)S->reg(ms[k], 2));
    S->destroy(ms[k]);
  }
  return 0;
}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "rv64i.axisl")
    args = parser.parse_args()
    text = args.axis_file.read_text()
    end = text.rstrip().rfind(")")
    cores = CORE % {"name": "mon", "exclusive": CLAUSE} + CORE % {"name": "nomon", "exclusive": ""}
    failures: list[str] = []
    rows: dict[str, dict] = {}
    with tempfile.TemporaryDirectory(prefix="axis_mon_") as work:
        work = Path(work)
        corpus = work / "mon.axisl"
        corpus.write_text(text[:end] + cores + text[end:])
        pack = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
        root = work / "packs" / pack["name"]
        isa = json.loads(subprocess.run([*axis_prefix(), "emit-json", str(corpus)], capture_output=True, text=True,
                                        check=True, cwd=AXIS_ROOT).stdout)["isas"][0]["name"]
        src = work / "h.c"
        src.write_text(HARNESS.replace("@SIM@", pack["libraries"]["sim"]["entry"]).replace("@ENTRY@", str(ENTRY))
                       .replace("@ISA@", f'"{isa}"').replace("@CORES@", str(CORES)).replace("@WORD@", str(WORD)))
        subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "h"), str(src),
                        str(root / "lib" / pack["libraries"]["sim"]["static"]),
                        str(root / "lib" / pack["libraries"]["exec"]["static"])], check=True, capture_output=True)
        for core in ("mon", "nomon"):
            out = subprocess.run([str(work / "h"), core, *map(str, program())], capture_output=True, text=True,
                                 check=True).stdout
            row = {"cores": []}
            for line in out.splitlines():
                f = line.split()
                if f[0] == "WORD":
                    row["word"] = int(f[1])
                elif f[0] == "CORE":
                    row["cores"].append({k: int(v) for k, v in (x.split("=") for x in f[2:])})
            rows[core] = row
        mon, nomon = rows["mon"], rows["nomon"]
        if mon.get("word") != CORES * TRIPS:
            failures.append(f"with the monitor declared the word ended at {mon.get('word')}, not {CORES * TRIPS}")
        for k, c in enumerate(mon["cores"]):
            if c["x2"] != 0:
                failures.append(f"with the monitor, core {k} stopped with {c['x2']} trips left (status {c['status']})")
        if nomon.get("word", CORES * TRIPS) >= CORES * TRIPS:
            failures.append(f"without the monitor the word ended at {nomon.get('word')}: no update was lost, so this "
                            "gate cannot see the bug it guards")
        bad = text[:end] + CORE % {"name": "bad", "exclusive": "\n    (exclusive exclusive_address nowhere exclusive_valid)"} \
            + text[end:]
        (work / "bad.axisl").write_text(bad)
        run = subprocess.run([*axis_prefix(), "check", str(work / "bad.axisl")], capture_output=True, text=True,
                             cwd=AXIS_ROOT)
        if run.returncode == 0 or "nowhere" not in run.stdout + run.stderr:
            failures.append("a monitor naming state no ISA declares was not refused")
    for f in failures:
        print(f"  FAIL {f}")
    print(f"  {CORES} cores x {TRIPS} LR/SC adds: with the monitor the word is {mon.get('word')} "
          f"(replays {sum(c['replays'] for c in mon['cores'])}); without it {nomon.get('word')}")
    verdict = "PASS" if not failures else "FAIL"
    print(f"a store clears the other cores' exclusive monitors: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
