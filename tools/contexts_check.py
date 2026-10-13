#!/usr/bin/env python3
"""Hardware contexts share one core (U4a). Gate.

`share_core(machine, other)` makes two execution-driven machines threads of
one core (docs/unified_engine_design.md): they share its units, ports and
issue, dispatch and commit width each cycle, and split its window; each keeps
its own front end, rename map and golden model. On a 2-wide core:

  * BANDWIDTH IS SHARED. Two contexts of independent adds -- each alone
    limited by the issue width -- each take at least 1.6x as long together
    as one takes alone.
  * LATENCY IS HIDDEN. Two contexts of dependent chains -- each alone
    limited by its chain, leaving a third of the core idle -- overlap: they
    take well under twice as long together as one alone.
  * THE BOUND IS REACHED. Either way two contexts finish within 5% of what
    the core allows them -- one's own time, or both threads' instructions
    through the shared issue width, whichever is longer.
  * UNITS ARE SHARED. On a 4-wide core with one ALU, two contexts of
    independent adds each take at least 1.8x as long together as alone.
  * EACH CONTEXT IS ITS OWN THREAD. Its registers end where its own program
    puts them, checked by its own golden model, alone and together.
  * FAIR WHATEVER ELSE IS ON THE CLOCK. With a machine of no group in the
    same `cycle_cores` call, the two contexts of the one-ALU core still
    finish within 2% of each other: each leads its core one cycle in two.
  * REFUSALS. A machine of another core, and one already started, are
    refused.

Usage: tools/contexts_check.py [examples/memory_system.axisl]
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
from memsys_x_check import OLD_CPU  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
TRIPS = 200

CORE = """  (defcore %(name)s
    (kind rvmt)
    (implements ms64)
    (issue-width 2)
    (window (rob 32) (issue-queue 32) (commit-width 2))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2))
    (engine execute)
    (units
      (alu (count 2) (pipelined true))
      (lsu (count 1) (pipelined true))
      (br (count 1) (pipelined true))))
"""


# Four wide, one ALU: here the UNIT is what two contexts contend for.
ONE_ALU = CORE.replace("(issue-width 2)", "(issue-width 4)").replace("(commit-width 2)", "(commit-width 4)") \
              .replace("(alu (count 2) (pipelined true))", "(alu (count 1) (pipelined true))") % {"name": "cpu0a"}


def program(dependent: bool) -> tuple[list[int], dict]:
    """x2 = TRIPS; loop { six adds; x2 -= 1 } while x2. Independent: x3..x8 += 1
    each. Dependent: x3 += 1 six times in a chain."""
    regs = [3] * 6 if dependent else [3, 4, 5, 6, 7, 8]
    body = [i_type(0x13, 0, r, r, 1) for r in regs] + [i_type(0x13, 0, 2, 2, -1)]
    body.append(b_type(0x63, 1, 2, 0, -4 * len(body)))
    want = {3: 6 * TRIPS} if dependent else {r: TRIPS for r in regs}
    return [i_type(0x13, 0, 2, 0, TRIPS)] + body, want


HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axis_pack.h"
extern const axis_sim_pack *@SIM@(void);
static const axis_sim_pack *S;
#define IMAGE (1 << 16)
static uint8_t CODE[IMAGE];
static uint32_t LEN;
static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; (void)a; (void)w; return 0; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; (void)a; (void)v; (void)w; }
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc >= @ENTRY@ && pc < @ENTRY@ + 4ull * LEN; uint32_t v = 0; if (*ok) memcpy(&v, CODE + pc, 4); return v;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) { (void)c; (void)cause; *stop = 1; return pc; }
static void *make(const char *core) {
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!S->select_core(m, core)) { printf("NOCORE\n"); exit(1); }
  S->reset(m, @ENTRY@u, @ISA@, NULL, 0);
  S->count_cycles(m, 1);
  return m;
}
static void report(const char *tag, void *m) {
  printf("%s cycles=%llu", tag, (unsigned long long)S->cycles(m));
  for (int r = 3; r <= 8; ++r) printf(" x%d=%llu", r, (unsigned long long)S->reg(m, r));
  printf("\n");
}
int main(int argc, char **argv) {
  S = @SIM@();
  if (S->abi_version < 7u || !S->share_core) { printf("NOABI\n"); return 0; }
  LEN = (uint32_t)(argc - 2);
  for (int i = 2; i < argc; ++i) { uint32_t w = (uint32_t)strtoul(argv[i], 0, 0); memcpy(CODE + @ENTRY@ + 4 * (i - 2), &w, 4); }
  const char *core = argv[1];
  void *a = make(core);
  void *one[1] = { a };
  while (S->cycle_cores(one, 1, 1) > 0) {}
  report("ALONE", a);
  S->destroy(a);
  void *p = make(core), *q = make(core);
  int shared = S->share_core(q, p);
  void *two[2] = { p, q };
  while (S->cycle_cores(two, 2, 1) > 0) {}
  printf("SHARED %d\n", shared);
  report("CTX0", p);
  report("CTX1", q);
  /* FAIR WHATEVER ELSE IS ON THE CLOCK: two contexts, and a machine of no
     group in the same call. */
  {
    void *a = make(core), *b = make(core), *y = make(core);
    S->share_core(b, a);
    void *three[3] = { a, b, y };
    while (S->cycle_cores(three, 3, 1) > 0) {}
    printf("THIRD a=%llu b=%llu y=%llu\n", (unsigned long long)S->cycles(a), (unsigned long long)S->cycles(b),
           (unsigned long long)S->cycles(y));
    S->destroy(y); S->destroy(b); S->destroy(a);
  }
  void *other = make("cpu1");
  printf("REFUSE_OTHER %d\n", S->share_core(other, p));
  void *fresh = make(core);
  printf("REFUSE_STARTED %d\n", S->share_core(fresh, p));
  S->destroy(other); S->destroy(fresh); S->destroy(q); S->destroy(p);
  return 0;
}
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    text = args.axis_file.read_text()
    failures: list[str] = []
    if text.count(OLD_CPU % "cpu0") != 1:
        print("  FAIL the example's `cpu0` is not where this gate expects it")
        return FAILED
    text = text.replace(OLD_CPU % "cpu0", CORE % {"name": "cpu0"} + "\n" + ONE_ALU)
    with tempfile.TemporaryDirectory(prefix="axis_ctx_") as work:
        work = Path(work)
        corpus = work / "ctx.axisl"
        corpus.write_text(text)
        pack = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
        root = work / "packs" / pack["name"]
        isa = json.loads(subprocess.run([*axis_prefix(), "emit-json", str(corpus)], capture_output=True, text=True,
                                        check=True, cwd=AXIS_ROOT).stdout)["isas"][0]["name"]
        src = work / "h.c"
        src.write_text(HARNESS.replace("@SIM@", pack["libraries"]["sim"]["entry"]).replace("@ENTRY@", str(ENTRY))
                       .replace("@ISA@", f'"{isa}"'))
        subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "h"), str(src),
                        str(root / "lib" / pack["libraries"]["sim"]["static"]),
                        str(root / "lib" / pack["libraries"]["exec"]["static"])], check=True, capture_output=True)
        results = {}
        for label, dependent in (("independent adds", False), ("dependent chains", True)):
            words, want = program(dependent)
            out = subprocess.run([str(work / "h"), "cpu0", *map(str, words)], capture_output=True, text=True,
                                 check=True).stdout
            if "NOABI" in out:
                failures.append("the simulator pack has no `share_core` (ABI < 7)")
                break
            rows = {}
            for line in out.splitlines():
                f = line.split()
                rows[f[0]] = {k: int(v) for k, v in (x.split("=") for x in f[1:] if "=" in x)} if "=" in line else f[1:]
            results[label] = rows
            if rows.get("SHARED") != ["1"]:
                failures.append(f"{label}: share_core refused two machines of one core")
            for tag in ("ALONE", "CTX0", "CTX1"):
                for r, v in want.items():
                    if rows[tag][f"x{r}"] != v:
                        failures.append(f"{label}: {tag} ended with x{r} = {rows[tag][f'x{r}']}, not {v}")
            alone = rows["ALONE"]["cycles"]
            together = max(rows["CTX0"]["cycles"], rows["CTX1"]["cycles"])
            # What two contexts can do at best: one's own time, or both
            # threads' instructions through the shared issue width.
            bound = max(alone, 2 * len(words[1:]) * TRIPS // 2)
            rows["bound"] = bound
            if not bound <= together <= 1.05 * bound:
                failures.append(f"{label}: two contexts together took {together} cycles; the core's bound is "
                                f"{bound} (one alone {alone}), and they should reach it within 5%")
            if not dependent and together < 1.6 * alone:
                failures.append(f"{label}: one context alone {alone} cycles, two together {together}; "
                                "sharing a 2-wide issue must cost each nearly double")
            if dependent and together >= 1.5 * alone:
                failures.append(f"{label}: one context alone {alone} cycles, two together {together}; "
                                "the chains should overlap, well short of running one after the other")
            if rows.get("REFUSE_OTHER") != ["0"]:
                failures.append("a machine of another core was allowed to share")
            if rows.get("REFUSE_STARTED") != ["0"]:
                failures.append("a machine was allowed to join a core whose contexts had started")
        # UNITS ARE SHARED: on the one-ALU core, independent adds are bound by
        # that ALU; two contexts each need nearly twice as long.
        words, _ = program(False)
        out = subprocess.run([str(work / "h"), "cpu0a", *map(str, words)], capture_output=True, text=True,
                             check=True).stdout
        unit = {}
        third = {}
        for line in out.splitlines():
            f = line.split()
            if f[0] in ("ALONE", "CTX0", "CTX1"):
                unit[f[0]] = int(f[1].split("=")[1])
            if f[0] == "THIRD":
                third = {k: int(v) for k, v in (x.split("=") for x in f[1:])}
        # FAIR: on the one-ALU core the two contexts contend for one unit; a
        # machine outside their group must not decide which of them leads.
        if third:
            ca, cb = third["a"], third["b"]
            if abs(ca - cb) > 0.02 * max(ca, cb):
                failures.append(f"one ALU, a third machine in the call: the two contexts took {ca} and {cb} cycles; "
                                "each should lead its core equally often")
            results["one ALU, with an unrelated machine beside them"] = {
                "ALONE": {"cycles": third["y"]}, "CTX0": {"cycles": ca}, "CTX1": {"cycles": cb}}
        if unit:
            together = max(unit["CTX0"], unit["CTX1"])
            if together < 1.8 * unit["ALONE"]:
                failures.append(f"one ALU: one context alone {unit['ALONE']} cycles, two together {together}; "
                                "sharing one ALU must cost each nearly double")
            results["one ALU, independent adds"] = {"ALONE": {"cycles": unit["ALONE"]}, "CTX0": {"cycles": unit["CTX0"]},
                                                    "CTX1": {"cycles": unit["CTX1"]}}
    for f in failures:
        print(f"  FAIL {f}")
    for label, rows in results.items():
        print(f"  {label}: one context alone {rows['ALONE']['cycles']} cycles; two sharing the core "
              f"{rows['CTX0']['cycles']} and {rows['CTX1']['cycles']} (bound {rows.get('bound')})")
    verdict = "PASS" if not failures else "FAIL"
    print(f"hardware contexts share one core: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
