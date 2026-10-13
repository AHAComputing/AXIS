#!/usr/bin/env python3
"""What precision costs: simulated instructions per second, by engine.

Not a gate -- a measurement, reported so the choice between engines is made on
numbers. One loop of loads, stores, multiplies and a data-dependent branch, run
for a fixed number of iterations on:

  functional       the simulator with no cycles counted at all;
  first-order      cycles counted, no core selected;
  trace-driven     a core whose pipeline replays the retired path (E0-O12);
  execution-driven its twin with `(engine execute)` (E1-E3).

Every run must retire the same instructions and leave the same registers --
checked, so a fast wrong answer cannot be reported as a fast one.

Usage: tools/engine_speed.py [corpus.axisl] [--trips N] [--keep DIR] [--only ENGINE]

`--keep DIR` builds the harness there and leaves it, and `--only` runs one
engine -- together, a binary a profiler can sample.
"""
from __future__ import annotations

import argparse
import contextlib
import os
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from lsq_check import Assembler, run_cmd  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
ENTRY, DATA = 0x200, 0x4000
BASE, MINUS_ONE, COUNTER = 5, 7, 9

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "axis_pack.h"
extern const axis_sim_pack *%(sim)s(void);
#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];
static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MEMORY[(a + i) %% IMAGE] << (8 * i); return v; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) MEMORY[(a + i) %% IMAGE] = (uint8_t)(v >> (8 * i)); }
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) { (void)c; *ok = pc + 4 <= IMAGE;
  return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u; }
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc; }
static const uint32_t LOOP[] = { %(loop)s };
static void go(const char *tag, const char *core, int count) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  for (uint32_t i = 0; i < sizeof LOOP / sizeof LOOP[0]; ++i)
    for (uint32_t b = 0; b < 4; ++b) MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(LOOP[i] >> (8 * b));
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (core && !S->select_core(m, core)) { printf("%%s NOCORE\n", tag); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  S->set_reg(m, %(base)d, %(data)du); S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, %(trips)du);
  S->count_cycles(m, count);
  /* PROCESS CPU time, not the wall clock: on a shared machine the wall
     clock measures the neighbours as much as the simulator. */
  struct timespec a, b; clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &a);
  S->run(m, 100000000u);
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &b);
  double secs = (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) { uint64_t v = S->reg(m, i);
    for (uint32_t k = 0; k < 8; ++k) { mark ^= (v >> (8 * k)) & 0xFFu; mark *= 1099511628211ull; } }
  printf("%%s steps %%llu seconds %%.6f cycles %%llu mark %%llu\n", tag,
         (unsigned long long)S->steps(m), secs, (unsigned long long)S->cycles(m), (unsigned long long)mark);
  S->destroy(m);
}
int main(void) {
  const char *only = getenv("AXIS_SPEED_ONLY");
  if (only && !strcmp(only, "execution-driven")) { go("execution-driven", "%(execute)s", 1); return 0; }
  if (only && !strcmp(only, "trace-driven")) { go("trace-driven", "%(trace)s", 1); return 0; }
  go("functional", 0, 0);
  go("first-order", 0, 1);
  go("trace-driven", "%(trace)s", 1);
  go("execution-driven", "%(execute)s", 1);
  return 0;
}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", nargs="?", type=Path,
                        default=AXIS_ROOT / "examples" / "issue_width.axisl")
    parser.add_argument("--trips", type=int, default=200000)
    parser.add_argument("--keep", type=Path)
    parser.add_argument("--only", choices=("execution-driven", "trace-driven"))
    args = parser.parse_args()
    if args.only:
        os.environ["AXIS_SPEED_ONLY"] = args.only
    with (contextlib.nullcontext(str(args.keep)) if args.keep else tempfile.TemporaryDirectory()) as tmp:
        work = Path(tmp)
        work.mkdir(parents=True, exist_ok=True)
        manifest = build_pack.build(args.corpus, work / "packs", only={"sim", "exec", "lift"})
        name = manifest["name"]
        facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(args.corpus)]).stdout)
        execute = next(c for c in facts["cores"] if c.get("engine") == "execute")
        keys = [k for k in execute if k not in ("name", "engine", "vendor")]
        trace = next(c for c in facts["cores"] if c.get("engine") != "execute"
                     and all(c.get(k) == execute.get(k) for k in keys))
        run_cmd([*axis_prefix(), "emit-lift-python", str(args.corpus), "-o", str(work / "sp.py")])
        sys.path.insert(0, str(work))
        lift = importlib.import_module("sp")
        tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(args.corpus)]).stdout)["tests"]
        latency = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
        asm = Assembler(lift, tests, latency)
        bnz = branch_encoder(lift, tests)
        add, mul = asm.fast_add, asm.slow
        body = [asm.ld(10, BASE, 0), asm.op(mul, 11, 10, 10), asm.op(add, 12, 11, 1),
                asm.st(12, BASE, 8), asm.ld(13, BASE, 8), bnz(13, 12, 8), asm.op(add, 14, 14, 1),
                asm.op(add, 15, 15, 13), asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
        body.append(bnz(COUNTER, 0, -4 * len(body)))
        loop = body + [asm.op(add, 21, 1, 1), 0]
        isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
        source = HARNESS % {
            "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "data": DATA,
            "base": lift.register_slot(asm.kind, BASE), "minus": lift.register_slot(asm.kind, MINUS_ONE),
            "counter": lift.register_slot(asm.kind, COUNTER), "trips": args.trips,
            "isa": f'"{isa}"' if isa else "NULL", "loop": ", ".join(f"{w}u" for w in loop),
            "trace": trace["name"], "execute": execute["name"],
        }
        root = work / "packs" / name
        (work / "speed.c").write_text(source)
        run_cmd(["cc", "-std=c11", "-O2", "-I", str(root / "include"), "-o", str(work / "speed"),
                 str(work / "speed.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
                 str(root / "lib" / manifest["libraries"]["exec"]["static"])])
        out = subprocess.run([str(work / "speed")], capture_output=True, text=True, check=True).stdout
    if args.keep:
        print(f"  harness kept: {args.keep / 'speed'}")
    rows = {}
    for line in out.splitlines():
        p = line.split()
        rows[p[0]] = (int(p[2]), float(p[4]), int(p[6]), int(p[8]))
    marks = {(r[0], r[3]) for r in rows.values()}
    base = rows.get("functional") or next(iter(rows.values()))
    print(f"{args.trips} iterations of a {len(body)}-instruction loop on `{trace['name']}` / "
          f"`{execute['name']}`:")
    for tag, (steps, secs, cycles, _) in rows.items():
        mips = steps / secs / 1e6 if secs else float("inf")
        print(f"  {tag:17s} {mips:8.2f} M instructions/s  {secs / base[1]:7.1f}x functional"
              f"  {cycles:>10} cycles")
    if len(marks) != 1:
        print("  ✗ the engines retired different instructions or left different registers")
        return 1
    print("  ✓ every engine retired the same instructions and left the same registers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
