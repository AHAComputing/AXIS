#!/usr/bin/env python3
"""A working set that fits is not the same program as one that does not. Gate.

The scoreboard charges the latency a description declares. A cache charges what
a machine's memory system does, and the two together are the smallest thing
that can answer *is this extension worth it* with a number instead of an
instruction count.

⚠️ The cache is the MACHINE's, not the description's. A description says what
instructions mean; how many lines a machine keeps and what a miss costs is a
property of one machine that runs them. In the language it would make every
description claim a cache it has no business claiming.

Held by PROPERTIES, not by a second copy of the model -- arithmetic agreeing
with itself proves nothing:

  * **a working set that fits** misses once per line and hits thereafter, so a
    second pass over the same addresses misses nothing;
  * **a working set that does not fit** misses on every pass, because the line
    it wants was evicted by the pass before;
  * **ways are ways**: two lines that collide in a 2-way cache both stay
    resident; three do not, and LRU is why;
  * **least-recently-used is not first-in-first-out**, which only a reference
    order differing from the fill order can tell apart -- A, B, A, C, A;
  * **configuring a cache empties it**, which only a second configure on a
    live machine can see;
  * **hits plus misses is every access** -- nothing counted twice or lost;
  * **no cache configured is no accounting**: the machine behaves as it did
    before caches existed, which is what an unconfigured option must mean;
  * **a miss costs cycles**, and the same program under two miss penalties
    differs by exactly (misses x penalty). This last one is the point: it is
    what makes the cache a term in a co-design answer rather than a counter.

⚠️ One level, LRU, no prefetch, no write policy, no coherence. What it can
tell you is a working set that fits from one that does not. What it cannot
tell you is what a real memory system does, and the model says so.

Usage: tools/cache_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

CODE = 0x200
LINES = 64
LINE_BYTES = 64

HARNESS = r"""
/* One machine and one cache, driven by addresses rather than by a program, so
   that what is being checked is the cache and not whichever fixtures a corpus
   happens to carry. The addresses ARE the experiment. */
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];

static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MEMORY[(a + i) %% IMAGE] << (8 * i);
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) MEMORY[(a + i) %% IMAGE] = (uint8_t)(v >> (8 * i));
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u;
}
static uint64_t trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

#define LINES %(lines)uu
#define LINE_BYTES %(line_bytes)uu

static const axis_sim_pack *S;
static axis_pack_sim_hooks HOOKS;

/* Two passes over the same addresses, and what the cache made of them. */
static void geometry(const char *tag, uint32_t lines, uint32_t ways,
                     uint64_t first, uint64_t stride, uint32_t count) {
  void *m = S->create(&HOOKS);
  if (!m) { printf("NOMACHINE\n"); return; }
  axis_sim_cache cache = { lines, ways, LINE_BYTES, 1u };
  S->configure_cache(m, &cache);
  for (uint32_t pass = 0; pass < 2; ++pass) {
    for (uint32_t i = 0; i < count; ++i) {
      S->touch_memory(m, first + (uint64_t)i * stride);
    }
    printf("%%s pass %%u hits %%llu misses %%llu accesses %%u\n", tag, pass,
           (unsigned long long)S->cache_hits(m),
           (unsigned long long)S->cache_misses(m),
           (pass + 1) * count);
  }
  S->destroy(m);
}

/* ⚠️ Least-recently-used is not first-in-first-out, and only a reference
   ORDER that differs from the fill order can tell them apart. A, B, A, then
   C: under LRU the victim is B and A survives; under FIFO the victim is A,
   which is the line just used. The final touch of A is the question. */
static void recency(void) {
  void *m = S->create(&HOOKS);
  if (!m) { printf("NOMACHINE\n"); return; }
  axis_sim_cache cache = { LINES, 2u, LINE_BYTES, 1u };
  S->configure_cache(m, &cache);
  const uint64_t set_stride = (uint64_t)(LINES / 2) * LINE_BYTES;
  S->touch_memory(m, 0);                 /* A: miss */
  S->touch_memory(m, set_stride);        /* B: miss */
  S->touch_memory(m, 0);                 /* A: hit, and now the recent one */
  S->touch_memory(m, 2 * set_stride);    /* C: miss, and B is the older way */
  S->touch_memory(m, 0);                 /* A: hit under LRU, miss under FIFO */
  printf("RECENCY hits %%llu misses %%llu\n", (unsigned long long)S->cache_hits(m),
         (unsigned long long)S->cache_misses(m));
  S->destroy(m);
}

/* ⚠️ Configuring a cache EMPTIES it. A machine reconfigured mid-life that
   kept its old lines would report hits for a cache that never held them --
   the numbers would describe neither geometry. Only a second configure on a
   LIVE machine can see this; every other trial starts from a fresh one. */
static void reconfigured(void) {
  void *m = S->create(&HOOKS);
  if (!m) { printf("NOMACHINE\n"); return; }
  axis_sim_cache cache = { LINES, 1u, LINE_BYTES, 1u };
  S->configure_cache(m, &cache);
  for (uint32_t i = 0; i < LINES; ++i) { S->touch_memory(m, i * LINE_BYTES); }
  S->configure_cache(m, &cache);   /* same geometry, emptied */
  for (uint32_t i = 0; i < LINES; ++i) { S->touch_memory(m, i * LINE_BYTES); }
  printf("RECONFIG hits %%llu misses %%llu\n", (unsigned long long)S->cache_hits(m),
         (unsigned long long)S->cache_misses(m));
  S->destroy(m);
}

/* The same instructions, the same misses, two miss penalties.

   ⚠️ Stepped one at a time with a touch in front of each, because a stall is
   charged to the instruction that is about to run: that is what "a miss costs
   the instruction that asked for it" has to mean when the asking and the
   paying are two different calls. */
static void charged(const char *tag, uint32_t penalty, const uint32_t *words,
                    int32_t count) {
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(code)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  void *m = S->create(&HOOKS);
  if (!m) { printf("NOMACHINE\n"); return; }
  S->reset(m, %(code)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  }
  /* Every address maps to the same set, so every touch is a miss. */
  axis_sim_cache cache = { LINES, 1u, LINE_BYTES, penalty };
  S->configure_cache(m, &cache);
  S->count_cycles(m, 1);
  int32_t ran = 0;
  for (int32_t i = 0; i < count; ++i) {
    S->touch_memory(m, (uint64_t)i * LINES * LINE_BYTES);
    if (S->step(m) != AXIS_PACK_SIM_RUNNING) { break; }
    ran++;
  }
  printf("%%s cycles %%llu misses %%llu ran %%d\n", tag,
         (unsigned long long)S->cycles(m),
         (unsigned long long)S->cache_misses(m), ran);
  S->destroy(m);
}

int main(void) {
  S = %(sim)s();
  if (!S->configure_cache || !S->touch_memory) { printf("NOCACHE\n"); return 0; }
  HOOKS.read = rd; HOOKS.write = wr; HOOKS.fetch = fetch; HOOKS.trap = trap;

  /* Exactly the cache, one line apart: the second pass is free. */
  geometry("FITS", LINES, 1u, 0u, LINE_BYTES, LINES);
  /* One set, over and over: the line wanted was evicted by the pass before. */
  geometry("THRASH", LINES, 1u, 0u, (uint64_t)LINES * LINE_BYTES, LINES);
  /* Two colliding lines in two ways both stay. */
  geometry("ASSOC2", LINES, 2u, 0u, (uint64_t)(LINES / 2) * LINE_BYTES, 2u);
  /* Three do not, and LRU is the reason. */
  geometry("ASSOC3", LINES, 2u, 0u, (uint64_t)(LINES / 2) * LINE_BYTES, 3u);
  /* No cache is no accounting. */
  geometry("OFF", 0u, 1u, 0u, LINE_BYTES, LINES);
  recency();
  reconfigured();

  static const uint32_t WORDS[] = { %(words)s };
  const int32_t count = (int32_t)(sizeof WORDS / sizeof WORDS[0]);
  charged("FREE", 0u, WORDS, count);
  charged("COSTLY", %(penalty)uu, WORDS, count);
  return 0;
}
"""

PENALTY = 7


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def pick_program(axis_file: Path, work: Path, name: str, length: int):
    """A handful of instructions that step without branching or trapping.

    ⚠️ Nothing about the cache depends on WHICH instructions these are -- they
    are here to be charged, not to be measured. What matters is that they run.
    """
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"ca_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"ca_{name}")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    for test in tests:
        entry = next((row for row in lift.AXIS_LIFT_TABLE
                      if row["mnemonic"] == test["mnemonic"]), None)
        if entry is None or entry.get("effects") or entry.get("ends_block"):
            continue
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        if len(outs) != 1:
            continue
        word = int(test["encoded"], 16)
        isa = test.get("isa") or ""
        words = []
        for i in range(length):
            built = lift.place_operand(word, entry, outs[0]["name"], 3 + i)
            words.append(built)
        sys.modules.pop(f"ca_{name}", None)
        return words, isa, test["mnemonic"]
    sys.modules.pop(f"ca_{name}", None)
    return None, None, None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    words, isa, mnemonic = pick_program(axis_file, work, name, 8)
    if words is None:
        print(f"  {name}: DECLINED nothing that steps without branching")
        return 0, 0

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "code": CODE,
        "lines": LINES,
        "line_bytes": LINE_BYTES,
        "isa": f'"{isa}"' if isa else "NULL",
        "words": ", ".join(f"{w}u" for w in words),
        "penalty": PENALTY,
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / name), str(work / f"{name}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}")
        return 0, 1
    if "NOCACHE" in done.stdout:
        print(f"  FAIL {name}: the simulator library models no cache")
        return 0, 1
    if "NOMACHINE" in done.stdout:
        print(f"  FAIL {name}: the library would not make a machine")
        return 0, 1

    passes: dict[tuple[str, int], tuple[int, int, int]] = {}
    runs: dict[str, tuple[int, int, int]] = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 9 and parts[1] == "pass":
            passes[(parts[0], int(parts[2]))] = (int(parts[4]), int(parts[6]),
                                                 int(parts[8]))
        elif len(parts) == 5 and parts[1] == "hits":
            runs[parts[0]] = (int(parts[2]), int(parts[4]), 0)
        elif len(parts) == 7 and parts[1] == "cycles":
            runs[parts[0]] = (int(parts[2]), int(parts[4]), int(parts[6]))

    checks = failures = 0

    def want(tag: str, index: int, hits: int, misses: int,
             census: bool = True) -> None:
        nonlocal checks, failures
        checks += 1
        got = passes.get((tag, index))
        if got is None:
            print(f"  FAIL {name}: {tag} pass {index} reported nothing")
            failures += 1
            return
        if (got[0], got[1]) != (hits, misses):
            print(f"  FAIL {name}: {tag} pass {index} hit {got[0]} and missed "
                  f"{got[1]}; a cache of {LINES} lines should have hit {hits} "
                  f"and missed {misses}")
            failures += 1
            return
        # Every access is one or the other, or the counters are not a census.
        # ⚠️ Only where there is a cache: an unconfigured one accounts for
        # nothing on purpose, and is held to that below instead.
        if not census:
            return
        checks += 1
        if got[0] + got[1] != got[2]:
            print(f"  FAIL {name}: {tag} pass {index} made {got[2]} accesses "
                  f"and accounted for {got[0] + got[1]}")
            failures += 1

    # A working set that fits: paid for once.
    want("FITS", 0, 0, LINES)
    want("FITS", 1, LINES, LINES)
    # A working set that does not: paid for every time.
    want("THRASH", 0, 0, LINES)
    want("THRASH", 1, 0, 2 * LINES)
    # Two ways hold two colliding lines.
    want("ASSOC2", 0, 0, 2)
    want("ASSOC2", 1, 2, 2)
    # They do not hold three.
    want("ASSOC3", 0, 0, 3)
    want("ASSOC3", 1, 0, 6)
    # An unconfigured cache is not a cache that hits.
    want("OFF", 0, 0, 0, census=False)
    want("OFF", 1, 0, 0, census=False)
    checks += 1
    off = passes.get(("OFF", 1))
    if off and off[0] + off[1] != 0:
        print(f"  FAIL {name}: no cache was configured and {off[0] + off[1]} "
              f"accesses were still accounted")
        failures += 1

    # A, B, A, C, A: two hits and three misses is LRU. FIFO evicts the line
    # just used and reports one hit and four misses.
    checks += 1
    recency = runs.get("RECENCY")
    if recency != (2, 3, 0):
        print(f"  FAIL {name}: A,B,A,C,A in a 2-way cache hit "
              f"{recency[0] if recency else '?'} and missed "
              f"{recency[1] if recency else '?'}; least-recently-used keeps A "
              f"and evicts B, for 2 hits and 3 misses")
        failures += 1

    # A cache reconfigured to the same geometry is an empty cache: the second
    # pass over the very addresses the first one filled misses every one of
    # them. (Configuring also restarts the counters, so what is read back is
    # the second pass alone -- which is the pass in question.)
    checks += 1
    again = runs.get("RECONFIG")
    if again != (0, LINES, 0):
        print(f"  FAIL {name}: after reconfiguring, a second pass over the "
              f"addresses the first pass filled hit "
              f"{again[0] if again else '?'} and missed "
              f"{again[1] if again else '?'}; configuring a cache empties it, "
              f"so it should have missed all {LINES}")
        failures += 1

    free = runs.get("FREE")
    costly = runs.get("COSTLY")
    checks += 1
    if not free or not costly:
        print(f"  FAIL {name}: the charged runs reported nothing")
        failures += 1
    elif free[2] < 2 or free[2] != costly[2]:
        print(f"  FAIL {name}: the two runs executed {free[2]} and "
              f"{costly[2]} instruction(s); they are the same program")
        failures += 1
    elif free[1] != costly[1] or free[1] < 2:
        print(f"  FAIL {name}: the two runs missed {free[1]} and {costly[1]} "
              f"times; they are the same addresses")
        failures += 1
    else:
        # ⚠️ THE point of the whole model: a miss is a cost, not a counter.
        checks += 1
        expected = free[0] + costly[1] * PENALTY
        if costly[0] != expected:
            print(f"  FAIL {name}: {costly[1]} misses at {PENALTY} cycles each "
                  f"should have taken {free[0]} + {costly[1] * PENALTY} = "
                  f"{expected} cycles, and took {costly[0]}")
            failures += 1

    if not failures:
        print(f"  {name}: {mnemonic} x{free[2]}, {costly[1]} misses at "
              f"{PENALTY} cycles cost {costly[0] - free[0]} cycles, "
              f"{checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "rv64i.axisl"]
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp))
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("a working set that fits != one that does not: SKIP")
        return DECLINED
    print(f"a working set that fits != one that does not: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
