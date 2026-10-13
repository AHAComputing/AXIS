#!/usr/bin/env python3
"""A cache that is busy (docs/blocking_cache_design.md). Gate.

`(blocking true)` on a core's data cache: one request a cycle, none while a
miss is on its way, no write buffer. A load does not issue to a cache that
will not take it, and a store does not retire into one. Without the clause a
miss is a number added to the instruction that missed, and any number of them
overlap.

Two cores of `issue_width.axisl`'s `executes`, alike but for the cache they
name -- `l1d`, and `l1d` with the clause -- run the same programs. With L the
cache's `latency-cycles`:

  * NOTHING IN FLIGHT, NO DIFFERENCE. Loads of one word, which all hit, and a
    pointer chase, whose every load waits on the last: the same cycles on
    both, and exactly.
  * A MISS HOLDS THE CACHE. Loads of a new line each, with nothing between
    them: L + 1 cycles a load, exactly -- L for the line and the cycle after
    it answers before the next is taken. The plain cache overlaps them.
  * A STORE WAITS FOR ITS LINE, AND FOR THE CACHE. Stores of a new line each:
    L + 1 cycles a store, exactly. The plain cache charges a store nothing.
  * A LINE STORED TO IS WRITTEN BEHIND. A cache full of lines, then loads
    that replace them: 2L + 1 cycles a load when the lines were stored to --
    as they were brought in, or where they lay -- and L + 1 when they were
    only read.
  * ONE REQUEST A CYCLE. Four stores an iteration, or two and two loads, all
    hits, on a pair of cores with four load/store units: four cycles an
    iteration, exactly, where the plain cache's core takes fewer.
  * THE OLDEST IS NEXT. A load does not issue to a busy cache and wait
    there: an older load whose address came late goes first when the cache
    frees, and a younger one behind it costs the program nothing.
  * WHAT THE PROGRAM COMPUTES IS THE SAME on both, in every run.
  * REFUSALS: a trace-driven core naming a blocking cache; a blocking cache
    that holds four misses, that prefetches, that is fetched through, or that
    is a node of a memory system.
  * The clause survives `emit-lisp`, and `emit-json` says it.

Usage: tools/blocking_cache_check.py [examples/issue_width.axisl]
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

import build_pack  # noqa: E402
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402
from lsq_check import Assembler, run_cmd  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
DATA = 0x4000
BASE, STRIDE, MINUS_ONE, ONE, COUNTER, SECOND = 5, 6, 7, 8, 9, 11

CORE = """  (defcore %(name)s
    (kind rvmt)
    (implements iw32)
    (memory %(memory)s)
    (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2))
    (engine execute)
    (units
      (alu (count 4) (pipelined true))
      (mul (count 1) (pipelined true))
      (br (count 1) (pipelined true))
      (lsu (count %(lsu)d) (pipelined true))))

"""
ANCHOR = "  (defcore executes\n"
XBLOCKS = {"name": "xblocks", "memory": "l1dblocks", "lsu": 1}
XPLAIN = {"name": "xplain", "memory": "l1d", "lsu": 1}
# Four load/store units, so that it is the cache that takes one request a
# cycle and not the unit.
WIDE_BLOCKS = {"name": "xwideblocks", "memory": "l1dblocks", "lsu": 4}
WIDE_PLAIN = {"name": "xwideplain", "memory": "l1d", "lsu": 4}

HARNESS = r"""
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
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

static void go(const char *tag, const char *core, const uint32_t *words, int32_t count,
               uint32_t trips, uint32_t second, uint32_t stride) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0u); }
  S->set_reg(m, %(base)d, %(data)du);
  S->set_reg(m, %(stride)d, stride);
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
  S->set_reg(m, %(second)d, second);
  S->count_cycles(m, 1);
  S->run(m, 200000u);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = %(data)du; a < IMAGE; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m), (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
%(programs)s
%(runs)s
  return 0;
}
"""


def described(text: str, clause: str = "(blocking true)") -> str:
    """The corpus with `l1d` again as `l1dblocks`, and a core over each."""
    at = text.index("  (defmemory l1d\n")
    end = text.index("\n\n", at)
    again = text[at:end].replace("(defmemory l1d", "(defmemory l1dblocks")
    assert again.endswith("))"), again[-40:]
    again = again[:-1] + f"\n    {clause})"
    text = text[:end] + "\n\n" + again + text[end:]
    assert text.count(ANCHOR) == 1
    return text.replace(ANCHOR, "".join(CORE % one for one in (XBLOCKS, XPLAIN, WIDE_BLOCKS, WIDE_PLAIN)) + ANCHOR)


def refused(text: str, work: Path, tag: str) -> str | None:
    """What AXIS says of `text`, when it will not have it."""
    path = work / f"{tag}.axisl"
    path.write_text(text)
    done = subprocess.run([*axis_prefix(), "emit-json", str(path)], capture_output=True, text=True,
                          cwd=AXIS_ROOT)
    return None if done.returncode == 0 else (done.stderr.strip().splitlines() or ["?"])[-1]


def check(axis_file: Path, work: Path) -> int:
    failures = 0

    def expect(what: str, ok: bool, detail: str = "") -> None:
        nonlocal failures
        if not ok:
            failures += 1
        print(f"  {'ok  ' if ok else 'FAIL'} {what}{(': ' + detail) if detail else ''}")

    source = axis_file.read_text()
    text = described(source)
    path = work / "blocking.axisl"
    path.write_text(text)
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(path)]).stdout)
    memory = next(m for m in facts["memories"] if m["name"] == "l1dblocks")
    plain = next(m for m in facts["memories"] if m["name"] == "l1d")
    latency = memory["latency_cycles"]
    lines = memory["size_bytes"] // memory["line_bytes"]
    stride = memory["line_bytes"]
    expect("emit-json says which cache is blocking",
           memory.get("blocking") is True and plain.get("blocking") is False)
    lisp = run_cmd([*axis_prefix(), "emit-lisp", str(path)]).stdout
    back = work / "back.axisl"
    back.write_text(lisp)
    again = json.loads(run_cmd([*axis_prefix(), "emit-json", str(back)]).stdout)
    expect("the clause survives emit-lisp",
           [m.get("blocking") for m in again["memories"]] == [m.get("blocking") for m in facts["memories"]]
           and lisp.count("(blocking true)") == 1)

    # ---- refusals -------------------------------------------------------------
    trace = text.replace(CORE % XBLOCKS,
                         (CORE % XBLOCKS).replace("    (engine execute)\n", "")
                         .replace("    (front-end (fetch-width 4) (depth 2))\n", ""))
    fetched = text.replace(CORE % XPLAIN,
                           (CORE % XPLAIN)
                           .replace("(depth 2))", "(depth 2) (icache l1dblocks))"))
    for what, bad, word in (
            ("a trace-driven core naming it", trace, "trace-driven"),
            ("one that holds four misses", described(source, "(blocking true)\n    (mshrs 4)"), "holds one"),
            ("one that prefetches", described(source, "(blocking true)\n    (prefetch next-line)"), "prefetches"),
            ("one that writes through",
             described(source, "(blocking true)\n    (write-policy write-through)"), "writes back"),
            ("one that is fetched through", fetched, "data cache"),
            ("`(blocking perhaps)`", described(source, "(blocking perhaps)"), "true or false")):
        said = refused(bad, work, "refused")
        expect(f"refused: {what}", said is not None and word in said, said or "accepted")

    # ---- the programs -----------------------------------------------------------
    manifest = build_pack.build(path, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    module = f"bc_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(path), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(path)]).stdout)["tests"]
    asm = Assembler(lift, tests, {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]})
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None:
        print(f"  {name}: DECLINED {asm.missing() or 'no branch'}")
        return failures
    add = asm.fast_add
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
    sys.modules.pop(module, None)

    def loop(body: list[int], counter: int) -> list[int]:
        body = body + [asm.op(add, counter, counter, MINUS_ONE)]
        return body + [bnz(counter, 0, -4 * len(body))]

    step = asm.op(add, BASE, BASE, STRIDE)
    programs = {
        # One word, over and over.
        "HITS": loop([asm.ld(12, BASE, 0)], COUNTER) + [0],
        # Each address waits on the load before it: memory reads zero.
        "CHASE": loop([asm.ld(12, BASE, 0), asm.op(add, BASE, BASE, 12), step], COUNTER) + [0],
        "LOADS": loop([asm.ld(12, BASE, 0), step], COUNTER) + [0],
        "STORES": loop([asm.st(ONE, BASE, 0), step], COUNTER) + [0],
        # A cache filled, by loads or by stores, and then replaced line by line.
        "READ_THEN": loop([asm.ld(12, BASE, 0), step], COUNTER) + loop([asm.ld(13, BASE, 0), step], SECOND) + [0],
        "STORED_THEN": loop([asm.st(ONE, BASE, 0), step], COUNTER)
                       + loop([asm.ld(13, BASE, 0), step], SECOND) + [0],
        # The same, the lines read first and stored to where they lie.
        "HIT_THEN": loop([asm.ld(12, BASE, 0), asm.st(ONE, BASE, 8), step], COUNTER)
                    + loop([asm.ld(13, BASE, 0), step], SECOND) + [0],
        # Requests that all hit, more of them an iteration than the plain
        # cache's core takes cycles for one: four stores, and two stores and
        # two loads.
        "FOUR_STORES": loop([asm.st(ONE, BASE, 4 * k) for k in range(4)], COUNTER) + [0],
        "TWO_AND_TWO": loop([asm.st(ONE, BASE, 0), asm.ld(12, BASE, 4), asm.st(ONE, BASE, 8),
                             asm.ld(13, BASE, 12)], COUNTER) + [0],
    }
    # ⚠️ WHO IS NEXT. A miss holds the cache; behind it a load whose address
    # is late, and a younger one whose address is not, both of other lines.
    # The older has a long chain on it. A load that issued to a busy cache
    # and waited there would be next when it frees, and the younger issued
    # first: the chain would start a miss later. Held in the window, the
    # older goes first -- and the younger costs the program nothing at all.
    mul = asm.slow
    order = [asm.op(add, 14, BASE, STRIDE), asm.op(add, 15, 14, STRIDE), asm.ld(12, BASE, 0),
             asm.op(mul, 17, 0, 0), asm.op(add, 16, 14, 17), asm.ld(13, 16, 0), None]
    order += [asm.op(mul, 13, 13, 13) for _ in range(8)] + [0]
    programs["OLDER_FIRST"] = [asm.ld(18, 15, 0) if w is None else w for w in order]
    programs["OLDER_ALONE"] = [asm.op(add, 18, 15, 15) if w is None else w for w in order]
    plan = [("HITS", n, 0, 0) for n in (24, 48)] + [("OLDER_FIRST", 0, 0, stride), ("OLDER_ALONE", 0, 0, stride)] + [("CHASE", n, 0, stride) for n in (24, 48)]
    plan += [(label, n, 0, stride) for label in ("LOADS", "STORES") for n in (24, 48)]
    plan += [(label, lines, n, stride) for label in ("READ_THEN", "STORED_THEN", "HIT_THEN") for n in (16, 48)]
    plan += [(label, n, 0, 0) for label in ("FOUR_STORES", "TWO_AND_TWO") for n in (24, 48)]
    wide = ("FOUR_STORES", "TWO_AND_TWO")
    runs = [f'  go("{label}_{first}_{second}_{tag}", "{"xwide" if label in wide else "x"}{core}", {label}, '
            f'{len(programs[label])}, {first}u, {second}u, {gap}u);'
            for label, first, second, gap in plan for tag, core in (("B", "blocks"), ("P", "plain"))]
    root = work / "packs" / name
    (work / f"{name}.c").write_text(HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "data": DATA,
        "base": slot(BASE), "stride": slot(STRIDE), "one": slot(ONE), "minus": slot(MINUS_ONE),
        "counter": slot(COUNTER), "second": slot(SECOND), "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs)})
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / name),
             str(work / f"{name}.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        expect("the harness runs", False, done.stderr[-300:])
        return failures
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 7:
            said[parts[0]] = {"cycles": int(parts[2]), "steps": int(parts[4]), "mark": int(parts[6])}
    expect("every run ran", len(said) == len(runs), f"{len(said)} of {len(runs)}")
    if len(said) != len(runs):
        print(done.stdout[-600:])
        return failures

    def cycles(label: str, first: int, second: int, tag: str) -> int:
        return said[f"{label}_{first}_{second}_{tag}"]["cycles"]

    same = [key[:-2] for key in said if key.endswith("_B")
            and (said[key]["mark"], said[key]["steps"]) != (said[key[:-1] + "P"]["mark"], said[key[:-1] + "P"]["steps"])]
    expect("what the program computes is the same on both", not same, ", ".join(same))
    for label in ("HITS", "CHASE"):
        pairs = [(cycles(label, n, 0, "B"), cycles(label, n, 0, "P")) for n in (24, 48)]
        expect(f"{label}: nothing in flight, no difference", all(b == p for b, p in pairs), str(pairs))
    for label, what in (("LOADS", "a miss holds the cache"), ("STORES", "a store waits for its line")):
        busy = cycles(label, 48, 0, "B") - cycles(label, 24, 0, "B")
        free = cycles(label, 48, 0, "P") - cycles(label, 24, 0, "P")
        expect(f"{label}: {what}, {latency} + 1 cycles each",
               busy == 24 * (latency + 1) and free < busy,
               f"24 more cost {busy} blocking and {free} plain")
    first, alone = cycles("OLDER_FIRST", 0, 0, "B"), cycles("OLDER_ALONE", 0, 0, "B")
    expect("OLDER_FIRST: a load waits in the window, and the oldest is next", first == alone,
           f"{first} cycles, {alone} without the younger load")
    for label in wide:
        busy = cycles(label, 48, 0, "B") - cycles(label, 24, 0, "B")
        free = cycles(label, 48, 0, "P") - cycles(label, 24, 0, "P")
        expect(f"{label}: one request a cycle, four an iteration", busy == 24 * 4 and free < busy,
               f"24 more cost {busy} blocking and {free} plain")
    for label, each in (("READ_THEN", latency + 1), ("STORED_THEN", 2 * latency + 1),
                        ("HIT_THEN", 2 * latency + 1)):
        busy = cycles(label, lines, 48, "B") - cycles(label, lines, 16, "B")
        free = cycles(label, lines, 48, "P") - cycles(label, lines, 16, "P")
        expect(f"{label}: replacing a line costs {each}", busy == 32 * each and free < 32 * (latency + 1),
               f"32 more cost {busy} blocking and {free} plain")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis", nargs="?", default=str(AXIS_ROOT / "examples" / "issue_width.axisl"))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="axis_blocking_") as work:
        failures = check(Path(args.axis), Path(work))
    print(f"a cache that is busy: {'FAIL' if failures else 'PASS'}")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    sys.exit(main())
