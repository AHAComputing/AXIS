#!/usr/bin/env python3
"""Instructions come from a cache too, and so do the ones that never run.
Gate.

`(front-end ... (icache NAME))` fetches through a declared cache
(docs/ooo_design.md, O11): a fetch reads one line, so a line boundary ends a
fetch group, and a line the cache does not hold stalls fetch for its latency.
`(wrong-path-fetch true)` keeps fetching where a mispredicted branch was
predicted to go until it resolves -- lines that land in the cache though
nothing on them runs. Three machines identical but for that:

  * **a cold straight line misses once a line**, exactly, each costing
    exactly the cache's latency, and a machine with no instruction cache
    misses nothing;
  * **a loop that fits misses a constant**, its lines cold once; **one that
    does not fit misses every iteration**, exactly the lines that conflict;
  * **the wrong path is bounded** by what the machine can hold -- its fetch
    buffer and window -- not by how long the branch takes to resolve;
  * **the wrong path prefetches**: a branch mispredicted not-taken sends the
    front end down the fall-through while it resolves; when the program later
    runs that code, the line fetched on the wrong path is already there -- so
    the machine that fetches down it misses less, and one that does not
    touched no wrong-path line at all;
  * **the architecture is untouched**: nothing on the wrong path runs.

Usage: tools/icache_check.py [corpus.axisl ...]
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
from lsq_check import Assembler, run_cmd  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
TRIPS = (8, 16)
ONE, MINUS_ONE, COUNTER = 8, 7, 9

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
               uint32_t trips, uint64_t steps) {
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
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
  S->count_cycles(m, 1);
  S->run(m, steps);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  printf("%%s cycles %%llu steps %%llu miss %%llu wrong %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->icache_misses(m), (unsigned long long)S->wrong_path_lines(m),
         (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->icache_misses) { printf("NOICACHE\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def build_programs(asm: Assembler, bnz, line_words, lines):
    add = asm.fast_add

    def filler(n, base=10):
        return [asm.op(add, base + k % 8, 1, 2) for k in range(n)]

    programs = {}
    # A cold straight line over four lines.
    straight = filler(4 * line_words)
    programs["STRAIGHT"] = (straight, len(straight), 4)
    # A loop of two lines, which fits.
    body = filler(2 * line_words - 2) + [asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
    body.append(bnz(COUNTER, 0, -4 * len(body)))
    programs["FIT"] = (body + filler(1), None, None)
    # ⚠️ A loop of `lines` + 1 lines in a direct-mapped cache of `lines`: its
    # first line and its last share a set and evict each other every time.
    body = filler((lines + 1) * line_words - 2) + [asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
    body.append(bnz(COUNTER, 0, -4 * len(body)))
    programs["NOFIT"] = (body + filler(1), None, None)
    # ⚠️ A loop that starts TWO WORDS INTO a line, so its fetch groups
    # straddle line boundaries unless a line ends them. Every other program
    # here is line-aligned, and with four-wide fetch and sixteen-word lines an
    # aligned group never straddles -- a front end that fetched across lines
    # passed them all, and mutation testing said so.
    body = filler(2 * line_words - 2) + [asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
    body.append(bnz(COUNTER, 0, -4 * len(body)))
    programs["SKEWED"] = (filler(2) + body + filler(1), None, len(body))
    # ⚠️ ONE mispredict resolving slowly: eight chained multiplies, then a
    # taken branch -- cold, so guessed not taken -- over a long fall-through.
    # Time enough to fetch far more than the machine can hold.
    # ⚠️ From the register holding ONE: squaring an even seed eight times is
    # zero modulo 2^32, the branch then falls through, and a first version
    # measured no mispredict at all.
    chain = [asm.op(asm.slow, 20, ONE, ONE)] + [asm.op(asm.slow, 20, 20, 20) for _ in range(7)]
    far = 12 * line_words
    words = chain + [bnz(20, 0, 4 * (far - len(chain)))]
    words += filler(far - len(words)) + filler(2, base=26)
    programs["BOUND"] = (words, len(chain) + 1 + 2, None)
    # ⚠️ THE WRONG PATH. A slow branch, taken and cold -- so mispredicted not
    # taken -- whose fall-through B the program runs only later, after C.
    words = [asm.op(asm.slow, 20, 1, 1), asm.op(asm.slow, 20, 20, 20),
             asm.op(asm.slow, 20, 20, 20)]
    c_at = 2 * line_words
    end_at = 3 * line_words
    words.append(bnz(20, 0, 4 * (c_at - len(words))))          # -> C
    b_start = len(words)
    words += filler(c_at - 1 - len(words))                       # B, the fall-through
    words.append(bnz(ONE, 0, 4 * (end_at - len(words))))        # B done -> END
    words += filler(line_words - 2, base=24)                     # C
    words.append(bnz(ONE, 0, 4 * (b_start - len(words))))       # C done -> B
    words += filler(end_at - len(words))
    words += filler(2, base=26)                                  # END
    steps = 4 + (line_words - 1) + (c_at - b_start) + 2
    programs["WRONGPATH"] = (words, steps, None)
    return programs


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    memories = {m["name"]: m for m in facts.get("memories", [])}

    def fe(core):
        return core.get("front_end") or {}

    cached = next((c for c in cores if fe(c).get("icache") and not fe(c).get("wrong_path_fetch")), None)
    ahead = next((c for c in cores if fe(c).get("icache") and fe(c).get("wrong_path_fetch")), None)
    plain = None
    if cached:
        want = {**fe(cached), "icache": "", "wrong_path_fetch": False}
        plain = next((c for c in cores if fe(c) == want
                      and all(c.get(k) == cached.get(k) for k in
                              ("issue_width", "units", "rob", "predictor", "predictor_entries",
                               "branch_penalty", "lsq", "ports"))), None)
    if not cached or not ahead or not plain:
        print(f"  {name}: DECLINED no instruction-cached core, wrong-path twin and uncached twin")
        return 0, 0
    icache = memories.get(fe(cached)["icache"]) or {}
    line_bytes = icache.get("line_bytes") or icache.get("line-bytes") or 64
    size = icache.get("size_bytes") or icache.get("size-bytes") or 0
    latency = icache.get("latency_cycles") or icache.get("latency-cycles") or 0
    ways = icache.get("ways") or 1
    lines = size // line_bytes if line_bytes else 0
    if not lines or ways != 1:
        print(f"  {name}: DECLINED the instruction cache is not a direct-mapped one this gate "
              f"can build conflicts for")
        return 0, 0
    line_words = line_bytes // 4

    module = f"ic_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing() or 'no branch'}")
        return 0, 0
    programs = build_programs(asm, bnz, line_words, lines)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    machines = {"CACHED": cached, "AHEAD": ahead, "PLAIN": plain}
    runs = []
    for label, (words, steps, _) in programs.items():
        for tag, core in machines.items():
            for trips in (TRIPS if steps is None else (1,)):
                limit = steps if steps is not None else trips * (len(words) - 1) + 1
                runs.append(f'  go("{label}_{tag}_{trips}", "{core["name"]}", {label}, '
                            f'{len(words)}, {trips}u, {limit}u);')
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY,
        "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, (words, _, _) in programs.items()),
        "runs": "\n".join(runs),
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
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 11 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    for label, (words, steps, _) in programs.items():
        for trips in (TRIPS if steps is None else (1,)):
            rows = [said.get(f"{label}_{tag}_{trips}") for tag in machines]
            checks += 1
            if any(r is None for r in rows):
                fail(f"{label} at {trips} reported nothing on some machine")
            elif len({(r["steps"], r["mark"]) for r in rows}) != 1:
                fail(f"{label} at {trips} retired different instructions or left different "
                     f"registers; nothing on the wrong path may run")
    if failures:
        return checks, failures

    def get(label, tag, trips=1, key="miss"):
        return said[f"{label}_{tag}_{trips}"][key]

    low, high = TRIPS
    # ⚠️ NO CACHE, NO MISSES; a cold line once.
    for label in programs:
        for trips in (TRIPS if programs[label][1] is None else (1,)):
            checks += 1
            if get(label, "PLAIN", trips) or get(label, "PLAIN", trips, "wrong"):
                fail(f"{label} on a core with no instruction cache reported misses")
    checks += 1
    if get("STRAIGHT", "CACHED") != 4:
        fail(f"a cold straight line over 4 lines missed {get('STRAIGHT', 'CACHED')} times")
    # ⚠️ And each cold miss costs exactly the cache's latency: a straight line
    # is fetch-bound, so the misses are the whole difference.
    checks += 1
    extra = get("STRAIGHT", "CACHED", key="cycles") - get("STRAIGHT", "PLAIN", key="cycles")
    if extra != get("STRAIGHT", "CACHED") * latency:
        fail(f"a cold straight line cost {extra} cycles more through the instruction cache, with "
             f"{get('STRAIGHT', 'CACHED')} misses at a latency of {latency}; that is exactly "
             f"{get('STRAIGHT', 'CACHED') * latency}")
    # ⚠️ A FETCH READS ONE LINE: a warm loop whose body straddles lines pays
    # one fetch cycle per group, and a group ends at every line boundary.
    width = fe(cached)["fetch_width"]
    body_len = programs["SKEWED"][2]
    start, groups = 2, 0
    while start < 2 + body_len:
        end = min(2 + body_len, (start // line_words + 1) * line_words)
        groups += -(-(end - start) // width)
        start = end
    checks += 1
    per = get("SKEWED", "CACHED", high, "cycles") - get("SKEWED", "CACHED", low, "cycles")
    if per != groups * (high - low):
        fail(f"a warm loop starting two words into a line cost {per} cycles per {high - low} "
             f"iterations; ending every fetch group at a line boundary makes it {groups} groups "
             f"an iteration, exactly {groups * (high - low)}")
    # ⚠️ THE WRONG PATH IS BOUNDED by what the machine holds.
    can_hold = ((fe(ahead).get("buffer") or width * (fe(ahead)["depth"] + 1))
                + (ahead.get("rob") or 64))
    most = -(-(can_hold * 4) // line_bytes) + 1
    checks += 1
    if get("BOUND", "AHEAD", key="wrong") > most:
        fail(f"one slow mispredict fetched {get('BOUND', 'AHEAD', key='wrong')} lines down the "
             f"wrong path; the machine holds {can_hold} instructions, at most {most} lines")
    checks += 1
    if not get("BOUND", "AHEAD", key="wrong"):
        fail("one slow mispredict fetched nothing down the wrong path")
    # ⚠️ A LOOP THAT FITS PAYS A CONSTANT; ONE THAT DOES NOT, EVERY TIME.
    checks += 1
    if get("FIT", "CACHED", high) != get("FIT", "CACHED", low):
        fail(f"a two-line loop in a {lines}-line cache missed {get('FIT', 'CACHED', low)} and "
             f"{get('FIT', 'CACHED', high)} times at {low} and {high} trips; it fits")
    checks += 1
    grew = get("NOFIT", "CACHED", high) - get("NOFIT", "CACHED", low)
    if grew != 2 * (high - low):
        fail(f"a loop one line bigger than a direct-mapped {lines}-line cache missed {grew} more "
             f"times over {high - low} more trips; its first and last lines evict each other, "
             f"exactly two misses an iteration")
    # ⚠️ THE WRONG PATH PREFETCHES.
    checks += 1
    if not get("WRONGPATH", "AHEAD", key="wrong") or get("WRONGPATH", "CACHED", key="wrong"):
        fail(f"wrong-path lines: {get('WRONGPATH', 'AHEAD', key='wrong')} fetching down the wrong "
             f"path and {get('WRONGPATH', 'CACHED', key='wrong')} not; only the first may touch any")
    checks += 1
    if get("WRONGPATH", "AHEAD") >= get("WRONGPATH", "CACHED"):
        fail(f"the machine that fetched down the mispredicted fall-through missed "
             f"{get('WRONGPATH', 'AHEAD')} times running it later, and the one that did not "
             f"{get('WRONGPATH', 'CACHED')}; the line was fetched already")

    if not failures:
        print(f"  {name}: straight line {get('STRAIGHT', 'CACHED')} misses over 4 lines; a loop "
              f"that fits {get('FIT', 'CACHED', low)}/{get('FIT', 'CACHED', high)}, one that does "
              f"not {get('NOFIT', 'CACHED', low)}/{get('NOFIT', 'CACHED', high)}; wrong path "
              f"{get('WRONGPATH', 'AHEAD')} misses after prefetching "
              f"{get('WRONGPATH', 'AHEAD', key='wrong')} line(s) vs {get('WRONGPATH', 'CACHED')}; "
              f"{checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "issue_width.axisl"]
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
        print("instructions come from a cache too: SKIP")
        return DECLINED
    print(f"instructions come from a cache too: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
