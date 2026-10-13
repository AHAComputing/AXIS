#!/usr/bin/env python3
"""A prefetcher is a component a host may bring. Gate.

A cache of a described memory system names its prefetchers. A namespaced
name -- `(prefetch acme.next)` -- is one this library has not got
(docs/tlb_design.md, PF1): a host binds it with `register_prefetcher`, it is
shown every demand access of that cache on a core with timed memory, and what
it asks for is fetched by the library's own timed prefetch.

Over the example memory system, made non-coherent, with one execution-driven
core on timed memory streaming through lines that all miss:

  * A HOST'S NEXT-LINE IS THE LIBRARY'S. `acme.next`, written in the harness
    to ask for the lines after a miss, takes exactly the cycles and leaves
    exactly the counters of the built-in `next-line` at the same degree --
    the two are timed by the same machinery, so they cannot differ.
  * ONE THAT ASKS FOR NOTHING IS NO PREFETCHER, to the cycle.
  * IT SEES WHAT HAPPENED: as many misses as the cache counted, a first use
    for every prefetched line a load then used, the stream's key on each, and
    time that does not run backwards.
  * ONE THAT KNOWS THE STRIDE BEATS NEXT-LINE on a stream next-line cannot
    follow, and the lines it fetched are counted as prefetches.
  * UNBOUND IS REFUSED: `select_core` returns 0 until the name is bound,
    binding a name no cache asks for returns 0, and a bare name that is not
    built in, two names from outside on one cache, and one in a system with a
    SIMT port are refused by validation.

Usage: tools/prefetcher_check.py [examples/memory_system.axisl]
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
from memsys_pack_check import ENTRY, b_type, i_type, s_type  # noqa: E402
from memsys_x_check import CORE, OLD_CPU, program  # noqa: E402
from unified_run_check import ADDED as SIMT_SYSTEM  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

L1D = "(allocate write-allocate)\n    (mshrs 4))"
EDITS = [("(protocol moesi)", "(protocol none)"),
         ("(region 0x0 0x80000000 ddr0 (home l2))", "(region 0x0 0x80000000 ddr0)"),
         ("(inclusion inclusive)\n    (prefetch next-line)\n    (prefetch-degree 1)", "(inclusion nine)"),
         (OLD_CPU % "cpu0", CORE % {"name": "cpu0", "timing": "\n    (memory-timing timed)"}),
         (OLD_CPU % "cpu1", CORE % {"name": "cpu1", "timing": ""})]
DEGREE = 2
#: The stream's step, in lines: far enough that the next lines are never the
#: next ones wanted.
STEP_LINES = 17
LOADS = 200

#: name -> what the port's cache says about prefetching.
SYSTEMS = {
    "none": "",
    "next": f"\n    (prefetch next-line)\n    (prefetch-degree {DEGREE})",
    "host": f"\n    (prefetch acme.next)\n    (prefetch-degree {DEGREE})",
    "idle": f"\n    (prefetch acme.idle)\n    (prefetch-degree {DEGREE})",
    "far": f"\n    (prefetch acme.far)\n    (prefetch-degree {DEGREE})",
}
REFUSED = {
    "a bare name that is not built in": ("\n    (prefetch strde)", "is not one of"),
    "two prefetchers from outside": ("\n    (prefetch acme.a acme.b)", "binds one"),
}


def stores(base: int, count: int) -> list[int]:
    """x1 = base; x2 = count; do { ld x3,0(x1); x1 += x3; sd x0,64(x1); x1 += 192; x2 -= 1 } while x2.
    A load of one line, then a store to the next -- which only a prefetch brought -- three lines a trip, so
    no load ever lands on a prefetched line and every first use is a store's."""
    body = [i_type(0x03, 3, 3, 1, 0), (0 << 25) | (3 << 20) | (1 << 15) | (1 << 7) | 0x33,
            s_type(0x23, 3, 1, 0, 64), i_type(0x13, 0, 1, 1, 192), i_type(0x13, 0, 2, 2, -1)]
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

/* What a prefetcher was shown, whichever one it is. */
static uint64_t SAW[3], KEYS, KEY, BACKWARDS, LAST, CREATED, DESTROYED;
static uint32_t DEGREE_GIVEN, LINE_GIVEN;
static void *pf_create(uint32_t line_bytes, uint32_t degree) {
  CREATED++; LINE_GIVEN = line_bytes; DEGREE_GIVEN = degree; return &SAW;
}
static void pf_destroy(void *state) { (void)state; DESTROYED++; }
static void note(uint64_t key, int32_t saw, uint64_t now) {
  if (saw >= 0 && saw < 3) SAW[saw]++;
  if (key) { if (KEYS && key != KEY) KEYS = 2; else if (!KEYS) KEYS = 1; KEY = key; }
  if (now < LAST) BACKWARDS++;
  LAST = now;
}
/* The library's next-line, from outside: the lines after a miss. */
static int32_t next_observe(void *state, uint64_t line, uint64_t key, int32_t saw, uint64_t now,
                            uint64_t *out, int32_t max) {
  (void)state; note(key, saw, now);
  if (saw != AXIS_SIM_SAW_MISS) return 0;
  int32_t n = 0;
  for (uint32_t k = 1; k <= DEGREE_GIVEN && n < max; ++k) out[n++] = line + k;
  return n;
}
static int32_t idle_observe(void *state, uint64_t line, uint64_t key, int32_t saw, uint64_t now,
                            uint64_t *out, int32_t max) {
  (void)state; (void)line; (void)out; (void)max; note(key, saw, now); return 0;
}
/* One that knows where this stream goes: the line it will want next, and
   the ones after, on every access. */
static int32_t far_observe(void *state, uint64_t line, uint64_t key, int32_t saw, uint64_t now,
                           uint64_t *out, int32_t max) {
  (void)state; note(key, saw, now);
  int32_t n = 0;
  for (uint32_t k = 1; k <= 4u && n < max; ++k) out[n++] = line + k * %(step)du;
  return n;
}
static const axis_sim_prefetcher NEXT = { 1u, "acme.next", pf_create, pf_destroy, next_observe };
static const axis_sim_prefetcher IDLE = { 1u, "acme.idle", pf_create, pf_destroy, idle_observe };
static const axis_sim_prefetcher FAR = { 1u, "acme.far", pf_create, pf_destroy, far_observe };
static const axis_sim_prefetcher STRAY = { 1u, "acme.nobody", pf_create, pf_destroy, idle_observe };

int main(int argc, char **argv) {
  S = %(sim)s();
  if (S->abi_version < 9u || !S->register_prefetcher) { printf("NOABI\n"); return 0; }
  int bind = atoi(argv[2]);
  LEN = (uint32_t)(argc - 3);
  for (int i = 3; i < argc; ++i) {
    unsigned long w = strtoul(argv[i], 0, 0);
    for (uint32_t b = 0; b < 4; ++b) CODE[%(entry)d + 4 * (i - 3) + b] = (uint8_t)(w >> (8 * b));
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  int stray = S->register_prefetcher(&STRAY);
  int before = S->select_core(m, argv[1]);
  int named = 0;
  if (bind) { named = S->register_prefetcher(&NEXT) + S->register_prefetcher(&IDLE) + S->register_prefetcher(&FAR); }
  int after = S->select_core(m, argv[1]);
  printf("BIND stray %%d before %%d named %%d after %%d\n", stray, before, named, after);
  if (!after) { S->destroy(m); return 0; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  S->count_cycles(m, 1);
  unsigned long long steps = 0;
  while (S->step(m) == AXIS_PACK_SIM_RUNNING && steps < 1000000) steps++;
  uint64_t st[13] = { 0 };
  S->memsys_stats(m, 0, st, 13);
  printf("RUN steps %%llu cycles %%llu hits %%llu misses %%llu prefetches %%llu\n", steps,
         (unsigned long long)S->cycles(m), (unsigned long long)st[0], (unsigned long long)st[1],
         (unsigned long long)st[4]);
  S->destroy(m);
  printf("SAW hit %%llu miss %%llu first %%llu keys %%llu backwards %%llu created %%llu destroyed %%llu "
         "last %%llu line %%u degree %%u\n",
         (unsigned long long)SAW[0], (unsigned long long)SAW[1], (unsigned long long)SAW[2],
         (unsigned long long)KEYS, (unsigned long long)BACKWARDS, (unsigned long long)CREATED,
         (unsigned long long)DESTROYED, (unsigned long long)LAST, LINE_GIVEN, DEGREE_GIVEN);
  return 0;
}
"""


def build(text: str, work: Path, tag: str) -> Path:
    path = work / f"{tag}.axisl"
    path.write_text(text)
    pack = build_pack.build(path, work / f"packs_{tag}", only={"sim", "exec", "lift"})
    root = work / f"packs_{tag}" / pack["name"]
    isa = json.loads(subprocess.run([*axis_prefix(), "emit-json", str(path)], capture_output=True, text=True,
                                    check=True, cwd=AXIS_ROOT).stdout)["isas"][0]["name"]
    (work / f"{tag}.c").write_text(HARNESS % {"sim": pack["libraries"]["sim"]["entry"], "entry": ENTRY,
                                               "isa": f'"{isa}"', "step": STEP_LINES})
    binary = work / f"{tag}_h"
    subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(binary), str(work / f"{tag}.c"),
                    str(root / "lib" / pack["libraries"]["sim"]["static"]),
                    str(root / "lib" / pack["libraries"]["exec"]["static"])], check=True, capture_output=True)
    return binary


def run(binary: Path, bind: bool, words: list[int]) -> dict[str, dict[str, int]]:
    out = subprocess.run([str(binary), "cpu0", "1" if bind else "0", *map(str, words)],
                         capture_output=True, text=True, check=True).stdout
    said = {}
    for line in out.splitlines():
        parts = line.split()
        said[parts[0]] = {parts[i]: int(parts[i + 1]) for i in range(1, len(parts) - 1, 2)}
    return said


def refused(text: str, work: Path, needle: str) -> bool:
    path = work / "refuse.axisl"
    path.write_text(text)
    done = subprocess.run([*axis_prefix(), "check", str(path)], capture_output=True, text=True, cwd=AXIS_ROOT)
    return done.returncode != 0 and needle in (done.stdout + done.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    text = args.axis_file.read_text()
    failures: list[str] = []
    checks = 0

    def verdict(ok: bool, what: str) -> None:
        nonlocal checks
        checks += 1
        if not ok:
            failures.append(what)

    for old, _ in [*EDITS, (L1D, "")]:
        if text.count(old) != 1:
            print(f"  FAIL the anchor {old[:40]!r} is not in the example once")
            return FAILED
    for old, new in EDITS:
        text = text.replace(old, new)
    # ⚠️ A CHASE: each address waits on the load before it, so one access is in
    # flight at a time and the miss buffers are free for a prefetch. As
    # independent loads the misses themselves filled every buffer, each
    # prefetch was dropped, and a prefetcher that knew the stride exactly
    # fetched three lines in two hundred.
    stream = program(True, 0x4000, LOADS, 64 * STEP_LINES)
    near = program(True, 0x4000, LOADS, 64)
    with tempfile.TemporaryDirectory(prefix="axis_pf_") as tmp:
        work = Path(tmp)
        try:
            binaries = {name: build(text.replace(L1D, L1D[:-1] + clause + ")"), work, name)
                        for name, clause in SYSTEMS.items()}
            ran = {(name, tag): run(binaries[name], True, words)
                   for name in SYSTEMS for tag, words in (("stream", stream), ("near", near))}
            # ⚠️ STORES. A store that finds its line is a use like a load's and
            # takes another path through the cache; with loads alone, a
            # prefetcher never shown a store passed everything. Stores to fresh
            # lines one after another were no use either: they retire together,
            # their misses fill the buffers and nothing is prefetched for them.
            stored = {name: run(binaries[name], True, stores(0x4000, LOADS)) for name in ("host", "next")}
            unbound = run(binaries["host"], False, near)
        except subprocess.CalledProcessError as error:
            print(f"  FAIL {(error.stderr or error.stdout or str(error))[-400:]}")
            return FAILED
        for why, (clause, word) in REFUSED.items():
            verdict(refused(text.replace(L1D, L1D[:-1] + clause + ")"), work, word), f"{why} was not refused")
        # A SIMT core is a port of the system the unified-run gate builds: one
        # that validates as it stands, and must not once a cache of it names a
        # prefetcher only a pack-pipeline host could bind.
        simt = (AXIS_ROOT / "examples" / "simt_core.axisl").read_text()
        simt = simt[:simt.rstrip().rfind(")")] + SIMT_SYSTEM + ")\n"
        (work / "simt.axisl").write_text(simt)
        stands = subprocess.run([*axis_prefix(), "check", str(work / "simt.axisl")], capture_output=True,
                                text=True, cwd=AXIS_ROOT).returncode == 0
        verdict(stands and SIMT_SYSTEM.count("(mshrs 8))") == 1
                and refused(simt.replace("(mshrs 8))", "(mshrs 8) (prefetch acme.next))"), work, "from outside"),
                "a prefetcher from outside in a system with a SIMT port was not refused"
                if stands else "the system with a SIMT port does not validate as it stands")

    for tag in ("stream", "near"):
        host, builtin, none, idle = (ran[(n, tag)]["RUN"] for n in ("host", "next", "none", "idle"))
        verdict(host == builtin, f"{tag}: a host's next-line {host} is not the library's {builtin}")
        verdict(idle == none, f"{tag}: a prefetcher that asks for nothing {idle} is not no prefetcher {none}")
        saw = ran[("host", tag)]["SAW"]
        verdict(saw["miss"] == host["misses"],
                f"{tag}: it was shown {saw['miss']} misses and the cache counted {host['misses']}")
        verdict(saw["keys"] == 1, f"{tag}: one load made every access and it was shown {saw['keys']} key(s)")
        # ⚠️ And it is the machine's time: the last access it was shown is late
        # in the run. Never running backwards is true of a clock stuck at zero.
        verdict(saw["backwards"] == 0 and host["cycles"] // 2 < saw["last"] <= host["cycles"],
                f"{tag}: time ran backwards {saw['backwards']} times, or is not the run's: the last access "
                f"was shown at {saw['last']} of {host['cycles']} cycles")
        # Two caches are of the memory that names it -- each core's -- and each
        # has a state of its own.
        verdict((saw["created"], saw["destroyed"], saw["line"], saw["degree"]) == (2, 2, 64, DEGREE),
                f"{tag}: created {saw['created']}, destroyed {saw['destroyed']}, given a line of "
                f"{saw['line']} and degree {saw['degree']}")
        verdict(ran[("host", tag)]["BIND"] == {"stray": 0, "before": 0, "named": 2, "after": 1},
                f"{tag}: binding said {ran[('host', tag)]['BIND']}")
    verdict(stored["host"]["RUN"] == stored["next"]["RUN"] and stored["host"]["SAW"]["first"] > LOADS // 2
            and stored["host"]["SAW"]["miss"] == stored["host"]["RUN"]["misses"],
            f"stores: a host's next-line {stored['host']['RUN']} against the library's {stored['next']['RUN']}, "
            f"shown {stored['host']['SAW']['first']} first uses and {stored['host']['SAW']['miss']} misses")
    # Next-line follows consecutive lines and not a stride of seventeen.
    near_next, near_none = ran[("next", "near")]["RUN"], ran[("none", "near")]["RUN"]
    verdict(near_next["cycles"] < near_none["cycles"] and ran[("host", "near")]["SAW"]["first"] > LOADS // 2,
            f"consecutive lines: next-line took {near_next['cycles']} cycles against {near_none['cycles']}, "
            f"with {ran[('host', 'near')]['SAW']['first']} first uses shown")
    far, nxt, none = (ran[(n, "stream")]["RUN"] for n in ("far", "next", "none"))
    # ⚠️ Next-line is not worth NOTHING here -- a line it fetched opens a DRAM
    # row the stream comes back to -- so what is held is that it is worth
    # little and the one that knows the stride is worth most of the run.
    verdict(10 * nxt["cycles"] > 9 * none["cycles"] and 2 * far["cycles"] < nxt["cycles"],
            f"a stride of {STEP_LINES} lines: next-line {nxt['cycles']} cycles, the one that knows it "
            f"{far['cycles']}, none {none['cycles']}")
    verdict(far["prefetches"] > LOADS // 2 and ran[("far", "stream")]["SAW"]["first"] > LOADS // 2,
            f"the one that knows the stride fetched {far['prefetches']} lines, "
            f"{ran[('far', 'stream')]['SAW']['first']} of them used")
    verdict(unbound["BIND"] == {"stray": 0, "before": 0, "named": 0, "after": 0} and "RUN" not in unbound,
            f"unbound, the core was not refused: {unbound}")

    for f in failures:
        print(f"  FAIL {f}")
    print(f"  {LOADS} loads {STEP_LINES} lines apart: {none['cycles']} cycles with no prefetcher, "
          f"{nxt['cycles']} with next-line, {far['cycles']} with a host's that knows the stride")
    print(f"a prefetcher is a component a host may bring: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {len(failures)} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
