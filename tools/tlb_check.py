#!/usr/bin/env python3
"""A machine remembers only so many pages. Gate.

`(tlb (data ...) (fetch ...) (second ...) (page-bytes N) (walk-cycles N))` on
a `defcore` gives the core translation buffers (docs/tlb_design.md). It is
timing, not translation: addresses stay what the program computes. A lookup
the first level holds costs nothing beyond the instruction; one only the
second level holds costs that level's latency; one nothing holds costs the
walk as well.

Machines identical but for their TLB run the same programs on both engines,
at two lengths, and what is held is exact:

  * **a pointer chase round a ring of pages** -- every load's address is the
    load before it, so walks cannot overlap. A ring that fits misses once a
    page and costs exactly that many walks, however long the chase; one that
    does not fit misses every load;
  * **ways are sets**: three pages that share a set of two ways miss every
    time in a TLB with room for eight, and three that do not miss three times;
  * **the second level**: a ring too big for the first level and small enough
    for the second walks once a page and pays the second level's latency on
    every other load;
  * **fetch**: a straight line misses once per page of code it enters, each
    holding fetch for exactly the walk; a loop over three pages misses a
    constant in a fetch TLB that holds them and every page, every time round,
    in one that does not;
  * **a store translates when it executes**: its walk is its own latency on
    both engines, and it is counted once;
  * **the wrong path is remembered and not counted**: a page only a squashed
    load touched costs the load that later needs it nothing;
  * **the architecture is untouched**: every machine ends where the one with
    no TLB does.

Usage: tools/tlb_check.py
"""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from lsq_check import Assembler  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "issue_width.axisl"
ISA = "iw32"

ENTRY = 0x200
#: ⚠️ Small pages, so a program of a few hundred instructions crosses several
#: and a ring of them sits inside one base register's reach.
PAGE = 256
PAGE_WORDS = PAGE // 4
WALK = 20
SECOND = 3
LEVELS, LEVEL = 3, 4
MISS = 10
TABLE = f"(walk (levels {LEVELS}) (cycles {LEVEL}) (table 1048576))"
HUGE = f"(huge (bytes {8 * 256}) (from {0x4000}) (to {0x4000 + 4 * 8 * 256}))"
DATA = 0x4000
ONE, MINUS_ONE, COUNTER, POINTER, CURSOR, STRIDE, CODE = 8, 7, 9, 20, 21, 22, 23
TRIPS = (12, 24)

#: name -> the `(tlb ...)` clause; `none` is the machine translation is free on.
MACHINES = {
    "none": "",
    "d8": f"(tlb (data (entries 8)) (page-bytes {PAGE}) (walk-cycles {WALK}))",
    "d4": f"(tlb (data (entries 4)) (page-bytes {PAGE}) (walk-cycles {WALK}))",
    "d8w2": f"(tlb (data (entries 8) (ways 2)) (page-bytes {PAGE}) (walk-cycles {WALK}))",
    "d4s16": f"(tlb (data (entries 4)) (second (entries 16) (latency {SECOND})) "
             f"(page-bytes {PAGE}) (walk-cycles {WALK}))",
    # ⚠️ ONE entry: a store that looked its page up again when it retired would
    # find it gone -- every store here executes before the first retires --
    # and count twice. With room for the page that second lookup hits, and a
    # store translated twice passed every other machine.
    "d1": f"(tlb (data (entries 1)) (page-bytes {PAGE}) (walk-cycles {WALK}))",
    "df": f"(tlb (data (entries 8)) (fetch (entries 2)) (page-bytes {PAGE}) (walk-cycles {WALK}))",
    "f2": f"(tlb (fetch (entries 2)) (page-bytes {PAGE}) (walk-cycles {WALK}))",
    "f4": f"(tlb (fetch (entries 4)) (page-bytes {PAGE}) (walk-cycles {WALK}))",
    # ---- TLB2: the walker -------------------------------------------------
    # One walker: walks that would overlap take turns.
    "d8k1": f"(tlb (data (entries 8)) (page-bytes {PAGE}) (walkers 1) (walk-cycles {WALK}))",
    # A walk that READS a table of three levels, four cycles a level.
    "d8t3": f"(tlb (data (entries 8)) (page-bytes {PAGE}) {TABLE})",
    # ... with a cache of its upper levels.
    "d8t3c": f"(tlb (data (entries 8)) (page-bytes {PAGE}) (walk-cache (entries 4)) {TABLE})",
    # The ring's six pages inside ONE large page.
    "d8h": f"(tlb (data (entries 8)) (page-bytes {PAGE}) {HUGE} (walk-cycles {WALK}))",
    "d8t3h": f"(tlb (data (entries 8)) (page-bytes {PAGE}) {HUGE} {TABLE})",
    # ⚠️ A name ending in `m` is a machine with a DATA CACHE, which a walk
    # that reads its table reads it through: `nonem` is that cache and no TLB.
    "nonem": "",
    "d8t3m": f"(tlb (data (entries 8)) (page-bytes {PAGE}) {TABLE})",
}

#: The data cache those machines have. Four ways, so that the three lines a
#: walk reads and the line the load reads sit in a set together: direct-mapped,
#: the table's lines put the ring's own out and the count was the pollution's.
CACHE = """
  (defmemory tlbd (kind cache) (size-bytes 16384) (line-bytes 64) (ways 4)
    (width-bits 64) (latency-cycles {miss}))
"""

CORE = """
  (defcore tlb_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)){execute}{memory}
    {tlb}
    (units (alu (count 4) (pipelined true)) (mul (count 1) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true))))
"""

#: Descriptions validation must refuse, and a word of why.
REFUSED = {
    "two costs for a walk": (f"(tlb (data (entries 8)) (walk-cycles {WALK}) {TABLE})", "one cost"),
    "a walk cache over one level": ("(tlb (data (entries 8)) (walk-cache (entries 4)) "
                                    "(walk (levels 1) (cycles 4) (table 1048576)))", "walk-cache"),
    "a large page no larger than a page": (f"(tlb (data (entries 8)) (page-bytes 4096) "
                                           f"(huge (bytes 4096) (from 0) (to 8192)) "
                                           f"(walk-cycles {WALK}))", "large page"),
    "no walk": (f"(tlb (data (entries 8)) (page-bytes {PAGE}))", "walk-cycles"),
    "nothing looked up": (f"(tlb (second (entries 8) (latency 2)) (walk-cycles {WALK}))", "neither"),
    "ways that do not divide": (f"(tlb (data (entries 8) (ways 3)) (walk-cycles {WALK}))", "divide"),
    "a first level with a latency": (f"(tlb (data (entries 8) (latency 2)) (walk-cycles {WALK}))",
                                     "first-level"),
    "a free second level": (f"(tlb (data (entries 4)) (second (entries 16)) (walk-cycles {WALK}))",
                            "second-level"),
    "a page that is not a power of two": (f"(tlb (data (entries 4)) (page-bytes 3000) "
                                          f"(walk-cycles {WALK}))", "power of two"),
}

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

/* ⚠️ EXACT memory: an address outside the image reads zero and stores
   nowhere. A wrapped image makes two addresses one byte, which a model that
   orders accesses by address rightly does not. */
#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];

static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) if (a + i < IMAGE) v |= (uint64_t)MEMORY[a + i] << (8 * i);
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) if (a + i < IMAGE) MEMORY[a + i] = (uint8_t)(v >> (8 * i));
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

/* A ring of `ring` pages `step` pages apart from %(data)d: each holds the
   address of the next. With `step` 0, ONE HOT PAGE instead: its word k points
   at cold page k + 1, which points back at its word k + 1 -- hot, cold, hot,
   another cold, for `ring` cold pages. */
static void go(const char *tag, const char *core, const uint32_t *words, int32_t count,
               uint32_t trips, uint64_t steps, uint32_t ring, uint32_t step) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) { MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b)); }
  }
  for (uint32_t k = 0; k < ring && step; ++k) {
    wr(NULL, %(data)du + k * step * %(page)du, %(data)du + ((k + 1u) %% ring) * step * %(page)du, 32u);
  }
  for (uint32_t k = 0; k < ring && !step; ++k) {
    wr(NULL, %(data)du + 4u * k, %(data)du + (k + 1u) * %(page)du, 32u);
    wr(NULL, %(data)du + (k + 1u) * %(page)du, %(data)du + 4u * (k + 1u), 32u);
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, "%(isa)s", NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
  S->set_reg(m, %(pointer)d, %(data)du);
  S->set_reg(m, %(cursor)d, %(data)du);
  S->set_reg(m, %(stride)d, %(page)du);
  S->set_reg(m, %(code)d, %(entry)du);
  S->count_cycles(m, 1);
  S->run(m, steps);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = %(data)du; a < IMAGE; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu dmiss %%llu imiss %%llu walks %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->dtlb_misses(m), (unsigned long long)S->itlb_misses(m),
         (unsigned long long)S->page_walks(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (S->abi_version < 9u || !S->dtlb_misses) { printf("NOABI\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def build_programs(asm: Assembler, bnz):
    """name -> (words, steps for `trips` or None when fixed, fixed steps, ring, step)."""
    add = asm.fast_add

    def filler(n, base=10):
        return [asm.op(add, base + k % 8, 1, 2) for k in range(n)]

    def loop(body):
        body = body + [asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
        return body + [bnz(COUNTER, 0, -4 * len(body))]

    programs = {}
    # ⚠️ A CHASE: the load's address is the load before it, so one walk cannot
    # hide behind another. Independent loads walk side by side and a machine
    # that charged nothing for all but the first measured the same.
    # ⚠️ And a STRAIGHT LINE of them, stopped after as many as are wanted. As a
    # loop, the branch closing it was mispredicted while cold, the chase waited
    # on fetch on the machine with no TLB and not on one that was walking
    # anyway, and every difference came out a constant four or six short.
    chase = [asm.ld(POINTER, POINTER, 0) for _ in range(max(TRIPS))] + filler(2, base=26)
    programs["RING6"] = (chase, 1, 6, 1)
    # Three pages one set apart in a TLB of four sets, and three that are not.
    programs["SAMESET"] = (chase, 1, 3, 4)
    programs["SPREAD"] = (chase, 1, 3, 1)
    # ⚠️ Three pages EIGHT apart: one set of a direct-mapped table of eight,
    # and no trouble at all to a fully associative one. Without it a TLB that
    # ignored `ways` and mapped directly agreed with every ring above, whose
    # consecutive pages never share a set.
    programs["EIGHTH"] = (chase, 1, 3, 8)
    # ⚠️ ONE HOT PAGE between cold ones. A ring is used in the order it was
    # filled, so first-in-first-out and least-recently-used evict the same
    # page and a TLB that never noted a use passed every ring. Here the hot
    # page is the oldest entry and the most recently used one at once.
    programs["HOT"] = (chase, 1, max(TRIPS) // 2 + 1, 0)
    # A store to a fresh page each time round.
    store = loop([asm.st(ONE, CURSOR, 0), asm.op(add, CURSOR, CURSOR, STRIDE)]) + filler(2, base=26)
    programs["STORES"] = (store, 4, 0, 1)
    # Four pages of code, cold; and a loop over three.
    programs["STRAIGHT"] = (filler(4 * PAGE_WORDS), 4 * PAGE_WORDS, 0, 1)
    programs["LOOP3"] = (loop(filler(3 * PAGE_WORDS - 2)) + filler(2, base=26), 3 * PAGE_WORDS, 0, 1)
    # ⚠️ A load of the page the code itself is on. The fetch TLB already holds
    # that page and the data TLB does not: one table serving both looked the
    # same on every program whose code and data are on different pages.
    programs["SELF"] = ([asm.ld(25, CODE, 0)] + filler(2, base=26), 1, 0, 1)
    # ⚠️ APART (TLB2): six loads of six pages, none waiting for another. Their
    # walks overlap -- unless the machine has one walker.
    programs["APART"] = ([asm.ld(10 + k, POINTER, PAGE * k) for k in range(6)] + filler(2, base=26),
                         6, 0, 1)
    # ⚠️ THE WRONG PATH. Three multiplies, then a branch that is taken and
    # cold -- so guessed not taken -- over a load of the ring's page. The
    # machine runs that load while the branch resolves, squashes it, and the
    # program's own load of the same page comes after.
    slow = [asm.op(asm.slow, 24, ONE, ONE), asm.op(asm.slow, 24, 24, 24), asm.op(asm.slow, 24, 24, 24)]
    wrong = slow + [bnz(24, 0, 4 * 3), asm.ld(25, POINTER, 0), asm.op(add, 26, 25, 25)]
    wrong += filler(8) + [asm.ld(27, POINTER, 4)] + filler(2, base=26)
    programs["WRONG"] = (wrong, None, 1, 1)
    return programs, len(wrong) - 2 - 2


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text()
    end = source.rstrip().rfind(")")

    def corpus_with(cores: str, name: str) -> Path:
        path = work / f"{name}.axisl"
        path.write_text(source[:end] + cores + ")\n")
        return path

    def run_cmd(cmd, check=True):
        return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=AXIS_ROOT)

    passed = failed = 0

    def verdict(ok, what):
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL {what}")

    # What validation refuses.
    for why, (clause, word) in REFUSED.items():
        bad = corpus_with(CORE.format(engine="x", name="bad", isa=ISA, execute=" (engine execute)",
                                      memory="", tlb=clause), "refused")
        done = run_cmd([*axis_prefix(), "check", str(bad)], check=False)
        verdict(done.returncode != 0 and word in (done.stdout + done.stderr),
                f"a TLB with {why} was not refused for it: {(done.stdout + done.stderr).strip()[:160]}")

    cores = CACHE.format(miss=MISS) + "".join(
        CORE.format(engine=engine, name=name, isa=ISA, tlb=tlb,
                    memory="\n    (memory tlbd)" if name.endswith("m") else "",
                    execute=" (engine execute)" if engine == "x" else "")
        for name, tlb in MACHINES.items() for engine in ("x", "t"))
    corpus = corpus_with(cores, "tlb")
    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "tlb_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("tlb_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None:
        sys.modules.pop("tlb_lift", None)
        print(f"  tlb: DECLINED {asm.missing() or 'no branch'}")
        return 0, 0
    programs, wrong_steps = build_programs(asm, bnz)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    sys.modules.pop("tlb_lift", None)

    runs = []
    for label, (words, per_trip, ring, step) in programs.items():
        fixed = label in ("STRAIGHT", "WRONG", "SELF", "APART")
        for name in MACHINES:
            for engine in ("x", "t"):
                for trips in ((1,) if fixed else TRIPS if label != "LOOP3" else (4, 8)):
                    steps = (wrong_steps if label == "WRONG" else per_trip) if fixed else per_trip * trips
                    runs.append(f'  go("{label}_{engine}_{name}_{trips}", "tlb_{engine}_{name}", {label}, '
                                f'{len(words)}, {trips}u, {steps}u, {ring}u, {step}u);')
    body = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "isa": ISA, "data": DATA,
        "page": PAGE, "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
        "pointer": slot(POINTER), "cursor": slot(CURSOR), "stride": slot(STRIDE), "code": slot(CODE),
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, (words, _, _, _) in programs.items()),
        "runs": "\n".join(runs),
    }
    root = work / "packs" / manifest["name"]
    (work / "tlb.c").write_text(body)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "tlb"),
             str(work / "tlb.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / "tlb")], capture_output=True, text=True)
    if done.returncode != 0 or "NOABI" in done.stdout or "NOCORE" in done.stdout:
        print(f"  FAIL the harness: exit {done.returncode} {done.stdout[:200]}")
        return passed, failed + 1
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        said[parts[0]] = {parts[i]: int(parts[i + 1]) for i in range(1, len(parts) - 1, 2)}

    def at(label, engine, name, trips):
        return said[f"{label}_{engine}_{name}_{trips}"]

    def expect(label, name, trips, dmiss, imiss, walks, extra, plain="none"):
        """Counters, and cycles beyond the machine with no TLB, on both engines."""
        for engine in ("x", "t"):
            got, base = at(label, engine, name, trips), at(label, engine, plain, trips)
            seen = (got["dmiss"], got["imiss"], got["walks"], got["cycles"] - base["cycles"])
            verdict(seen == (dmiss, imiss, walks, extra),
                    f"{label} on {name} ({engine}, {trips}): misses/walks/extra cycles {seen}, "
                    f"expected {(dmiss, imiss, walks, extra)}")
            verdict(got["mark"] == base["mark"] and got["steps"] == base["steps"],
                    f"{label} on {name} ({engine}, {trips}) ended somewhere else than with no TLB")

    for trips in TRIPS:
        # Fits: once a page. Does not: every load.
        expect("RING6", "d8", trips, 6, 0, 6, 6 * WALK)
        expect("RING6", "d4", trips, trips, 0, trips, trips * WALK)
        # Ways are sets.
        expect("SAMESET", "d8w2", trips, trips, 0, trips, trips * WALK)
        expect("SPREAD", "d8w2", trips, 3, 0, 3, 3 * WALK)
        expect("SAMESET", "d8", trips, 3, 0, 3, 3 * WALK)
        expect("EIGHTH", "d8", trips, 3, 0, 3, 3 * WALK)
        # The hot page is never the one forgotten: it and each cold page, once.
        expect("HOT", "d4", trips, 1 + trips // 2, 0, 1 + trips // 2, (1 + trips // 2) * WALK)
        # Two TLBs are two tables: the code's page and the data's six.
        expect("RING6", "df", trips, 6, 1, 7, 7 * WALK)
        # The second level holds what the first forgot.
        expect("RING6", "d4s16", trips, trips, 0, 6, 6 * (SECOND + WALK) + (trips - 6) * SECOND)
        # A fetch TLB is not looked up by data, nor a data TLB by fetch.
        expect("RING6", "f2", trips, 0, 1, 1, WALK)
    # ---- TLB2: the walker ----------------------------------------------------
    for trips in TRIPS:
        # A walk that reads its table costs its levels, not a number.
        expect("RING6", "d8t3", trips, 6, 0, 6, 6 * LEVELS * LEVEL)
        # A walk cache holds the upper levels: the first walk reads all three,
        # and the five after it one.
        expect("RING6", "d8t3c", trips, 6, 0, 6, LEVELS * LEVEL + 5 * LEVEL)
        # Six pages inside one large page are one page: one miss, one walk --
        # and through a table, a walk a level shorter.
        expect("RING6", "d8h", trips, 1, 0, 1, WALK)
        expect("RING6", "d8t3h", trips, 1, 0, 1, (LEVELS - 1) * LEVEL)
        # ⚠️ THROUGH THE DATA CACHE: the first walk reads three lines nothing
        # holds; the five after find them. Against the same cache and no TLB.
        expect("RING6", "d8t3m", trips, 6, 0, 6, 6 * LEVELS * LEVEL + LEVELS * MISS, plain="nonem")
    # ⚠️ ONE WALKER: six walks that overlapped take turns. The loads issue a
    # cycle apart, so each after the first waits out the walk before it less
    # that cycle.
    expect("APART", "d8", 1, 6, 0, 6, WALK)
    expect("APART", "d8k1", 1, 6, 0, 6, WALK + 5 * (WALK - 1))
    expect("STRAIGHT", "f2", 1, 0, 4, 4, 4 * WALK)
    expect("STRAIGHT", "d8", 1, 0, 0, 0, 0)
    expect("SELF", "df", 1, 1, 1, 2, 2 * WALK)
    for trips in (4, 8):
        expect("LOOP3", "f4", trips, 0, 3, 3, 3 * WALK)
        expect("LOOP3", "f2", trips, 0, 3 * trips, 3 * trips, 3 * trips * WALK)
    # A store translates once, when it executes, on both engines.
    for trips in TRIPS:
        for engine in ("x", "t"):
            for tiny in ("d1",):
                got = at("STORES", engine, tiny, trips)
                verdict((got["dmiss"], got["walks"]) == (trips, trips),
                        f"STORES on {tiny} ({engine}, {trips}): {got['dmiss']} misses and "
                        f"{got['walks']} walks for {trips} stores")
            got, base = at("STORES", engine, "d8", trips), at("STORES", engine, "none", trips)
            verdict((got["dmiss"], got["walks"]) == (trips, trips),
                    f"STORES on d8 ({engine}, {trips}): {got['dmiss']} misses and {got['walks']} walks "
                    f"for {trips} stores to {trips} pages")
            verdict(got["cycles"] >= base["cycles"] + WALK,
                    f"STORES on d8 ({engine}, {trips}): a store's walk cost nothing "
                    f"({got['cycles']} against {base['cycles']})")
            verdict(got["mark"] == base["mark"], f"STORES on d8 ({engine}, {trips}) stored something else")
    # ⚠️ The wrong path: the execution-driven engine runs the squashed load, so
    # the page is there for the program's own -- which then neither misses nor
    # waits. The trace-driven engine here executes no wrong path, and misses.
    got, base = at("WRONG", "x", "d8", 1), at("WRONG", "x", "none", 1)
    verdict((got["dmiss"], got["walks"]) == (0, 0),
            f"WRONG on d8 (x): the squashed load's lookup was counted, or its page forgotten "
            f"({got['dmiss']} misses, {got['walks']} walks)")
    verdict(got["mark"] == base["mark"], "WRONG on d8 (x) ended somewhere else than with no TLB")
    got = at("WRONG", "t", "d8", 1)
    verdict((got["dmiss"], got["walks"]) == (1, 1),
            f"WRONG on d8 (t): {got['dmiss']} misses, {got['walks']} walks for one page, one load")
    return passed, failed


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_tlb_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL tlb: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a machine remembers only so many pages: SKIP")
        return DECLINED
    print(f"a machine remembers only so many pages: {'FAIL' if failures else 'PASS'} "
          f"({checks + failures} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
