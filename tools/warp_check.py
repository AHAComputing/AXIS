#!/usr/bin/env python3
"""A warp is contexts sharing one front end (U4b). Gate.

`set_warp(machine, warp, age)` puts a hardware context of a core
(`share_core`, U4a) into one of its warps (docs/unified_engine_design.md §7): each cycle the warp
fetches ONE pc for every member whose next pc it is -- the lowest any member
wants, or a member's passed over for `age` cycles -- and what members fetched
together dispatches, issues and commits as one instruction. On a 2-wide core:

  * CONVERGED, ONE INSTRUCTION. Four members running one program from one pc
    finish within 5% of one context alone; four contexts that are NOT a warp
    take at least 3.5x as long. Every member but the one that paid rides free
    at dispatch, issue and commit -- at least 95% of the instructions of the
    other three.
  * LOCKSTEP. A warp instruction issues when every member holding it is
    ready. Two members whose loads take different times -- one always hits
    its cache, one always misses -- stay one instruction: at least 95% ride
    at issue, and the warp takes no more than 5% over the same two members
    as contexts (not the slower one alone: contexts split the window).
  * DIVERGED, TWO. Two members running the same loop at two different pcs
    share nothing: at least 1.8x one alone, within 5% of what two contexts
    are allowed (both threads' instructions through the shared issue width),
    and nothing rides.
  * AGING IS WHAT PROGRESS NEEDS. On a core that fetches one instruction a
    cycle, the member at the higher pc gets no fetch while the lower one can
    use it: with an age no member reaches, the lower one runs as if alone
    (within 5%) and the higher one waits for it to finish (at least 1.8x one
    alone); with age 1 they alternate, and the lower one is slowed (at least
    1.5x).
  * EACH MEMBER IS ITS OWN THREAD. Its registers end where its own program
    puts them, checked by its own golden model, in every run above.
  * TWO WARPS ON ONE CORE. Four members in two warps of two run as two
    instruction streams: within 5% of what two contexts are allowed, with one
    member of each warp riding.
  * REFUSALS. Age 0, an age other than the core's other warps', warp number
    64, a machine that shares no core, and a warp whose members have started,
    are refused.

Usage: tools/warp_check.py [examples/memory_system.axisl]
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_pack  # noqa: E402
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402
from contexts_check import CORE, TRIPS, program  # noqa: E402
from memsys_pack_check import ENTRY, b_type, i_type  # noqa: E402
from memsys_x_check import r_type  # noqa: E402
from memsys_x_check import OLD_CPU  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
# Where the second copy of the program lives: a different pc, the same code.
SECOND = 0x800
NEVER = 0xFFFFFFFF

# One instruction fetched a cycle, four issued: here FETCH is what members
# contend for, and the order the front end serves them in is all that matters.
NARROW = CORE.replace("(issue-width 2)", "(issue-width 4)").replace("(commit-width 2)", "(commit-width 4)") \
             .replace("(fetch-width 4)", "(fetch-width 1)") \
             .replace("(alu (count 2) (pipelined true))", "(alu (count 4) (pipelined true))") % {"name": "cpu0n"}

def latency_program() -> tuple[list[int], dict]:
    """x2 = TRIPS; loop { ld x3, 0(x10); add x10, x10, x11; add x5, x5, x3; x4 += 1; x2 -= 1 } while x2.
    The add after the load waits for it, so a member whose loads miss runs
    slower than one whose loads hit -- unless the warp keeps them together."""
    body = [i_type(0x03, 3, 3, 10, 0), r_type(0x33, 0, 0, 10, 10, 11), r_type(0x33, 0, 0, 5, 5, 3),
            i_type(0x13, 0, 4, 4, 1), i_type(0x13, 0, 2, 2, -1)]
    body.append(b_type(0x63, 1, 2, 0, -4 * len(body)))
    return [i_type(0x13, 0, 2, 0, TRIPS)] + body, {4: TRIPS, 5: 0}


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
static int in(uint64_t pc, uint64_t base) { return pc >= base && pc < base + 4ull * LEN; }
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = in(pc, @ENTRY@) || in(pc, @ENTRY@ + @SECOND@);
  uint32_t v = 0; if (*ok) memcpy(&v, CODE + pc, 4); return v;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) { (void)c; (void)cause; *stop = 1; return pc; }
static void *make(const char *core, uint64_t pc) {
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!S->select_core(m, core)) { printf("NOCORE\n"); exit(1); }
  S->reset(m, pc, @ISA@, NULL, 0);
  S->count_cycles(m, 1);
  return m;
}
/* argv: core, age (-1 alone, 0 contexts, else warps), starts ("AABB": which
   copy each member runs), warps ("0011": each member's warp), words... */
int main(int argc, char **argv) {
  S = @SIM@();
  if (S->abi_version < 7u || !S->set_warp) { printf("NOABI\n"); return 0; }
  const char *core = argv[1];
  long age = strtol(argv[2], 0, 0);
  const char *starts = argv[3], *warps = argv[4];
  LEN = (uint32_t)(argc - 5);
  for (int i = 5; i < argc; ++i) {
    uint32_t w = (uint32_t)strtoul(argv[i], 0, 0);
    memcpy(CODE + @ENTRY@ + 4 * (i - 5), &w, 4);
    memcpy(CODE + @ENTRY@ + @SECOND@ + 4 * (i - 5), &w, 4);
  }
  int n = age < 0 ? 1 : (int)strlen(starts);
  void *ms[8];
  for (int k = 0; k < n; ++k) { ms[k] = make(core, @ENTRY@ + (starts[k] == 'B' ? @SECOND@ : 0)); }
  for (int k = 1; k < n && age >= 0; ++k) {
    if (!S->share_core(ms[k], ms[0])) { printf("NOSHARE\n"); return 1; }
  }
  /* WARP_STRIDES="s0,s1,...": each member loads from its own address, x10,
     stepping by its own stride, x11, through a cache of its own -- a stride
     of 0 always hits, 4096 always misses. */
  if (getenv("WARP_STRIDES")) {
    char *list = strdup(getenv("WARP_STRIDES")), *tok = strtok(list, ",");
    axis_sim_cache cache = { 64u, 4u, 64u, 30u };
    for (int k = 0; k < n && tok; ++k, tok = strtok(NULL, ",")) {
      S->configure_cache(ms[k], &cache);
      S->set_reg(ms[k], 10, 0x100000ull * (uint64_t)(k + 1));
      S->set_reg(ms[k], 11, strtoull(tok, 0, 0));
    }
    free(list);
  }
  if (age > 0) {
    int ok = 1;
    for (int k = 0; k < n; ++k) { ok &= S->set_warp(ms[k], (uint32_t)(warps[k] - '0'), (uint32_t)age); }
    printf("WARP %d\n", ok);
    printf("REFUSE_AGE %d\n", S->set_warp(ms[0], (uint32_t)(warps[0] - '0'), (uint32_t)age + 1u));
    printf("REFUSE_NUMBER %d\n", S->set_warp(ms[0], 64u, (uint32_t)age));
  }
  while (S->cycle_cores(ms, n, 1) > 0) {}
  for (int k = 0; k < n; ++k) {
    uint64_t r[3] = {0, 0, 0};
    S->warp_rides(ms[k], r, 3);
    printf("M%d cycles=%llu rd=%llu ri=%llu rc=%llu", k, (unsigned long long)S->cycles(ms[k]),
           (unsigned long long)r[0], (unsigned long long)r[1], (unsigned long long)r[2]);
    for (int g = 3; g <= 8; ++g) printf(" x%d=%llu", g, (unsigned long long)S->reg(ms[k], g));
    printf("\n");
  }
  if (age > 0) {
    printf("REFUSE_STARTED %d\n", S->set_warp(ms[0], 0u, (uint32_t)age));
    printf("REFUSE_ZERO %d\n", S->set_warp(ms[0], 0u, 0u));
    void *lone = make(core, @ENTRY@);
    printf("REFUSE_LONE %d\n", S->set_warp(lone, 0u, (uint32_t)age));
    S->destroy(lone);
  }
  for (int k = n - 1; k >= 0; --k) { S->destroy(ms[k]); }
  return 0;
}
"""


def run(binary: Path, core: str, age: int, starts: str, words: list[int], warps: str = "", strides: str = "") -> dict:
    env = dict(os.environ, WARP_STRIDES=strides) if strides else None
    out = subprocess.run([str(binary), core, str(age), starts, warps or "0" * len(starts), *map(str, words)],
                         capture_output=True, text=True, check=True, env=env).stdout
    rows: dict = {"members": []}
    for line in out.splitlines():
        f = line.split()
        if f[0].startswith("M") and f[0][1:].isdigit():
            rows["members"].append({k: int(v) for k, v in (x.split("=") for x in f[1:])})
        elif len(f) == 2:
            rows[f[0]] = f[1]
        else:
            rows[f[0]] = True
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    text = args.axis_file.read_text()
    failures: list[str] = []
    if text.count(OLD_CPU % "cpu0") != 1:
        print("  FAIL the example's `cpu0` is not where this gate expects it")
        return FAILED
    text = text.replace(OLD_CPU % "cpu0", CORE % {"name": "cpu0"} + "\n" + NARROW)
    words, want = program(False)
    insts = 1 + (len(words) - 1) * TRIPS
    lines: list[str] = []

    def threads_right(label: str, rows: dict) -> None:
        for k, m in enumerate(rows["members"]):
            for r, v in want.items():
                if m[f"x{r}"] != v:
                    failures.append(f"{label}: member {k} ended with x{r} = {m[f'x{r}']}, not {v}")

    with tempfile.TemporaryDirectory(prefix="axis_warp_") as work:
        work = Path(work)
        corpus = work / "warp.axisl"
        corpus.write_text(text)
        pack = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
        root = work / "packs" / pack["name"]
        isa = json.loads(subprocess.run([*axis_prefix(), "emit-json", str(corpus)], capture_output=True, text=True,
                                        check=True, cwd=AXIS_ROOT).stdout)["isas"][0]["name"]
        src = work / "h.c"
        src.write_text(HARNESS.replace("@SIM@", pack["libraries"]["sim"]["entry"]).replace("@ENTRY@", str(ENTRY))
                       .replace("@SECOND@", str(SECOND)).replace("@ISA@", f'"{isa}"'))
        binary = work / "h"
        subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(binary), str(src),
                        str(root / "lib" / pack["libraries"]["sim"]["static"]),
                        str(root / "lib" / pack["libraries"]["exec"]["static"])], check=True, capture_output=True)
        probe = subprocess.run([str(binary), "cpu0", "-1", "A", "0", *map(str, words)], capture_output=True, text=True,
                               check=True).stdout
        if "NOABI" in probe:
            print("  FAIL the simulator pack has no `set_warp` (ABI < 7)")
            return FAILED

        # CONVERGED.
        alone = run(binary, "cpu0", -1, "A", words)
        threads_right("alone", alone)
        one = alone["members"][0]["cycles"]
        warp = run(binary, "cpu0", 8, "AAAA", words)
        smt = run(binary, "cpu0", 0, "AAAA", words)
        threads_right("converged warp", warp)
        threads_right("four contexts", smt)
        if warp.get("WARP") != "1":
            failures.append("set_warp refused four members of one core that had not started")
        w = max(m["cycles"] for m in warp["members"])
        c = max(m["cycles"] for m in smt["members"])
        if w > 1.05 * one:
            failures.append(f"converged: one context alone {one} cycles, a warp of four {w}; one instruction "
                            "for four members should cost what one costs")
        if c < 3.5 * one:
            failures.append(f"converged: four contexts that are not a warp took {c} cycles, one alone {one}; "
                            "without fusion they share the issue width")
        for stage, key in (("dispatch", "rd"), ("issue", "ri"), ("commit", "rc")):
            rode = sum(m[key] for m in warp["members"])
            if rode < 0.95 * 3 * insts:
                failures.append(f"converged: {rode} instructions rode free at {stage}; of four members running "
                                f"{insts} each, three should ride (at least {int(0.95 * 3 * insts)})")
            if sum(m[key] for m in smt["members"]):
                failures.append(f"four contexts that are not a warp rode free at {stage}")
        lines.append(f"converged: one alone {one} cycles; a warp of four {w}; four contexts {c}; rides "
                     f"(dispatch/issue/commit) {sum(m['rd'] for m in warp['members'])}/"
                     f"{sum(m['ri'] for m in warp['members'])}/{sum(m['rc'] for m in warp['members'])} "
                     f"of {3 * insts}")
        if warp.get("REFUSE_STARTED") != "0":
            failures.append("set_warp was allowed on a warp whose members had started")
        if warp.get("REFUSE_ZERO") != "0":
            failures.append("set_warp accepted age 0")
        if warp.get("REFUSE_LONE") != "0":
            failures.append("set_warp accepted a machine that shares no core")
        if warp.get("REFUSE_AGE") != "0":
            failures.append("set_warp accepted an age other than the core's other warps'")
        if warp.get("REFUSE_NUMBER") != "0":
            failures.append("set_warp accepted warp number 64")

        # TWO WARPS, ONE CORE: four members, two to a warp. Each warp is one
        # instruction stream, so the core runs two -- what two contexts cost.
        two = run(binary, "cpu0", 8, "AAAA", words, "0011")
        threads_right("two warps", two)
        t2 = max(m["cycles"] for m in two["members"])
        bound2 = max(one, 2 * (len(words) - 1) * TRIPS // 2)
        if not bound2 <= t2 <= 1.05 * bound2:
            failures.append(f"two warps of two: {t2} cycles; two instruction streams through the shared issue "
                            f"width are allowed {bound2}, and should reach it within 5%")
        rode2 = sum(m["ri"] for m in two["members"])
        if rode2 < 0.95 * 2 * insts:
            failures.append(f"two warps of two: {rode2} rode free at issue; one member of each warp should ride "
                            f"(at least {int(0.95 * 2 * insts)})")
        lines.append(f"two warps of two on one core: {t2} cycles (bound {bound2}); {rode2} rode at issue of {2 * insts}")

        # LOCKSTEP: two members, one whose loads always hit and one whose loads
        # always miss. A warp instruction issues when every member holding it
        # is ready, so the fast member waits and they stay one instruction.
        lwords, lwant = latency_program()
        linsts = 1 + (len(lwords) - 1) * TRIPS
        lone_hit = run(binary, "cpu0", -1, "A", lwords, strides="0")["members"][0]["cycles"]
        lone_miss = run(binary, "cpu0", -1, "A", lwords, strides="4096")["members"][0]["cycles"]
        lock = run(binary, "cpu0", 8, "AA", lwords, strides="0,4096")
        for k, m in enumerate(lock["members"]):
            for r, v in lwant.items():
                if m[f"x{r}"] != v:
                    failures.append(f"lockstep: member {k} ended with x{r} = {m[f'x{r}']}, not {v}")
        lrode = sum(m["ri"] for m in lock["members"])
        if lrode < 0.95 * linsts:
            failures.append(f"lockstep: {lrode} of {linsts} rode free at issue between a member whose loads hit "
                            "and one whose loads miss; a warp instruction issues for both at once")
        # Against the same two as contexts, not the slow one alone: two
        # contexts split the window, and half the window holds half the misses.
        apart = run(binary, "cpu0", 0, "AA", lwords, strides="0,4096")
        lapart = max(m["cycles"] for m in apart["members"])
        lslow = max(m["cycles"] for m in lock["members"])
        if lslow > 1.05 * lapart:
            failures.append(f"lockstep: the warp took {lslow} cycles; the same two as contexts take {lapart}, and "
                            "keeping the faster member with the slower should cost no more")
        lines.append(f"lockstep: loads hitting alone {lone_hit} cycles, missing alone {lone_miss}; the two as "
                     f"contexts {lapart}, as one warp {lslow}, {lrode} of {linsts} riding at issue")

        # DIVERGED.
        div = run(binary, "cpu0", 8, "AB", words)
        threads_right("diverged warp", div)
        d = max(m["cycles"] for m in div["members"])
        bound = max(one, 2 * (len(words) - 1) * TRIPS // 2)
        if d < 1.8 * one:
            failures.append(f"diverged: two members at two pcs took {d} cycles, one alone {one}; they share "
                            "nothing and should cost nearly two")
        if d > 1.05 * bound:
            failures.append(f"diverged: two members at two pcs took {d} cycles; two contexts are allowed {bound}")
        if any(m[k] for m in div["members"] for k in ("rd", "ri", "rc")):
            failures.append("diverged: something rode free between members at different pcs")
        lines.append(f"diverged: two members at two pcs {d} cycles (bound {bound}, one alone {one})")

        # AGING.
        narrow_alone = run(binary, "cpu0n", -1, "A", words)["members"][0]["cycles"]
        starve = run(binary, "cpu0n", NEVER, "AB", words)
        fair = run(binary, "cpu0n", 1, "AB", words)
        threads_right("no aging", starve)
        threads_right("age 1", fair)
        low, high = starve["members"][0]["cycles"], starve["members"][1]["cycles"]
        if low > 1.05 * narrow_alone:
            failures.append(f"no aging: the member at the lower pc took {low} cycles, alone {narrow_alone}; "
                            "it should run as if alone")
        if high < 1.8 * narrow_alone:
            failures.append(f"no aging: the member at the higher pc took {high} cycles, alone {narrow_alone}; "
                            "it should wait for the lower one")
        flow = fair["members"][0]["cycles"]
        if flow < 1.5 * narrow_alone:
            failures.append(f"age 1: the member at the lower pc took {flow} cycles, alone {narrow_alone}; "
                            "sharing fetch with the other should slow it")
        lines.append(f"aging, one fetch a cycle: one alone {narrow_alone}; never aged {low} / {high}; "
                     f"age 1 {flow} / {fair['members'][1]['cycles']}")
    for f in failures:
        print(f"  FAIL {f}")
    for line in lines:
        print(f"  {line}")
    verdict = "PASS" if not failures else "FAIL"
    print(f"a warp is contexts sharing one front end: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
