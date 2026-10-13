#!/usr/bin/env python3
"""The cache a machine has is the one its description declares. Gate.

`defmemory` has carried `size-bytes`, `latency-cycles`, `ports` and `banks`
since long before anything could run a program, and nothing ever computed with
any of them -- the same shape `area-estimate-um2` still has, and the same shape
`latency` had until a scoreboard read it. A number beside a design that nothing
reads is free text, and a co-design result built on one is a quotation of its
author.

So a core now names the memory it runs against, `defmemory` gained the two
fields a cache needs that a scratchpad does not have, and selecting a core
applies it.

⚠️ This is the correction to something the cache landed with. The argument for
keeping it out of the description was right about the ISA and wrong about the
LANGUAGE: an instruction means the same thing on every machine, so a cache has
no business on `definstruction` -- but AXIS has machine-side forms too, and a
machine is exactly where a cache lives. The distinction that matters was never
"in the language or out of it"; it is WHICH FORM says it.

Held by properties:

  * **the knee is where the description says**: a walk over exactly the
    declared number of lines is free on its second pass, and one over twice
    that many is not. Two cores differing only in declared size have their
    knees in different places;
  * **a core that names no memory has no cache**, and accounts for nothing --
    which is what a machine that was never given one has to report;
  * **selecting replaces**: a machine moved from a core with a cache to one
    without is left with none, rather than the one it had;
  * **the description is a default, not a ceiling**: a host that calls
    `configure_cache` afterwards gets the cache it asked for.

Usage: tools/described_cache_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
CHARGED_STEPS = 8

HARNESS = r"""
/* One machine, moved from described machine to described machine. */
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; (void)a; (void)w; return 0; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; (void)a; (void)v; (void)w; }

static const axis_sim_pack *S;
static axis_pack_sim_hooks HOOKS;

/* Two passes over `count` lines, `stride` apart, on the machine `core` names.
   ⚠️ Driven through `touch_memory` rather than through loads: what is under
   test is which cache the DESCRIPTION gave this core, and a corpus that
   happens to have no load instruction is not a reason to leave that
   unchecked. */
static void walk(const char *tag, const char *core, uint64_t stride,
                 uint32_t count, int32_t then_none, uint32_t override_lines) {
  void *m = S->create(&HOOKS);
  if (!m) { printf("NOMACHINE\n"); return; }
  int32_t took = S->select_core(m, core);
  if (then_none) { took = S->select_core(m, "%(nocache)s"); }
  if (override_lines) {
    axis_sim_cache forced = { override_lines, 1u, (uint32_t)stride, 1u };
    S->configure_cache(m, &forced);
  }
  for (uint32_t pass = 0; pass < 2; ++pass) {
    for (uint32_t i = 0; i < count; ++i) { S->touch_memory(m, i * stride); }
  }
  printf("%%s hits %%llu misses %%llu selected %%d\n", tag,
         (unsigned long long)S->cache_hits(m),
         (unsigned long long)S->cache_misses(m), took);
  S->destroy(m);
}

#define IMAGE (1 << 16)
static uint8_t CODE[IMAGE];
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE;
  if (!*ok) { return 0u; }
  uint32_t v = 0;
  for (uint32_t i = 0; i < 4; ++i) v |= (uint32_t)CODE[pc + i] << (8 * i);
  return v;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

/* ⚠️ What a miss COSTS, not just that it happened. `latency-cycles` is the
   number `defmemory` has carried all along, and counting hits and misses
   would leave it exactly as unread as it was -- a walk that reports the right
   miss count on a cache whose penalty is ignored looks perfect. Each step is
   preceded by a touch that cannot hit, so every instruction pays once. */
static void charged(const char *tag, const char *core, const uint32_t *words,
                    int32_t count, uint64_t stride) {
  memset(CODE, 0, sizeof CODE);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      CODE[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  S->count_cycles(m, 1);
  int32_t ran = 0;
  for (int32_t i = 0; i < count; ++i) {
    S->touch_memory(m, (uint64_t)(i + 1) * stride * 4096ull);
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
  if (!S->select_core || !S->touch_memory) { printf("NOCORES\n"); return 0; }
  HOOKS.read = rd; HOOKS.write = wr;
%(runs)s
  static const uint32_t PROGRAM[] = { %(program)s };
  charged("CHARGED", "%(charged_core)s", PROGRAM,
          (int32_t)(sizeof PROGRAM / sizeof PROGRAM[0]), %(charged_stride)dull);
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    memories = {memory["name"]: memory for memory in facts.get("memories", [])}
    cached, plain = [], []
    for core in facts.get("cores", []):
        memory = memories.get(core.get("memory") or "")
        if memory and memory.get("line_bytes"):
            cached.append((core, memory))
        else:
            plain.append(core)
    if not cached:
        print(f"  {name}: DECLINED no core names a memory with a line size")
        return 0, 0
    if not plain:
        print(f"  {name}: DECLINED every core has a cache, so there is nothing "
              f"to check having none against")
        return 0, 0

    runs = []
    for core, memory in cached:
        lines = memory["size_bytes"] // memory["line_bytes"]
        stride = memory["line_bytes"]
        runs.append(f'  walk("FIT_{core["name"]}", "{core["name"]}", '
                    f'{stride}ull, {lines}u, 0, 0u);')
        runs.append(f'  walk("OVER_{core["name"]}", "{core["name"]}", '
                    f'{stride}ull, {2 * lines}u, 0, 0u);')
        # ⚠️ Addresses that all land in ONE SET, which is the only walk that
        # can see the declared ways. A sequential walk touches each set once
        # and reports the same numbers whatever the associativity is.
        ways = memory["ways"] or 1
        sets = lines // ways
        collide = sets * memory["line_bytes"]
        runs.append(f'  walk("WAYS_{core["name"]}", "{core["name"]}", '
                    f'{collide}ull, {ways}u, 0, 0u);')
        runs.append(f'  walk("OVERWAYS_{core["name"]}", "{core["name"]}", '
                    f'{collide}ull, {ways + 1}u, 0, 0u);')
    first, first_memory = cached[0]
    lines = first_memory["size_bytes"] // first_memory["line_bytes"]
    stride = first_memory["line_bytes"]
    runs.append(f'  walk("NONE_{plain[0]["name"]}", "{plain[0]["name"]}", '
                f'{stride}ull, {lines}u, 0, 0u);')
    runs.append(f'  walk("REPLACED", "{first["name"]}", {stride}ull, '
                f'{lines}u, 1, 0u);')
    # Half the declared size, asked for by the host after selection.
    runs.append(f'  walk("OVERRIDE", "{first["name"]}", {stride}ull, '
                f'{lines}u, 0, {max(1, lines // 2)}u);')

    # ⚠️ The charged run uses a ONE-WIDE core with one copy of each unit, so
    # the cycle arithmetic has a single answer: each instruction issues one
    # cycle after the last and pays its own miss. On a wider machine the
    # expected number would depend on the issue model as well as the miss
    # cost, and this gate is about the miss cost.
    charged = next(((core, memory) for core, memory in cached
                    if (core.get("issue_width", 1) or 1) == 1
                    and all((unit.get("count", 1) or 1) == 1
                            for unit in core.get("units", []))), None)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    straight = next((test for test in tests
                     if not any(entry["mnemonic"] == test["mnemonic"]
                                and entry.get("effects")
                                for entry in facts["instructions"])), None)
    if charged is None or straight is None:
        program, charged_core, charged_stride, charged_memory = [0], "", 1, None
    else:
        charged_core = charged[0]["name"]
        charged_memory = charged[1]
        charged_stride = charged_memory["line_bytes"]
        program = [int(straight["encoded"], 16)] * CHARGED_STEPS

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "nocache": plain[0]["name"],
        "runs": "\n".join(runs),
        "entry": ENTRY,
        "isa": f'"{straight.get("isa") or ""}"' if straight and straight.get("isa") else "NULL",
        "program": ", ".join(f"{word}u" for word in program),
        "charged_core": charged_core,
        "charged_stride": charged_stride,
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
    if "NOCORES" in done.stdout:
        print(f"  FAIL {name}: the simulator library exposes no cores")
        return 0, 1

    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 7 and parts[1] == "hits":
            said[parts[0]] = (int(parts[2]), int(parts[4]), int(parts[6]))

    checks = failures = 0
    for core, memory in cached:
        lines = memory["size_bytes"] // memory["line_bytes"]
        # A walk over exactly the declared lines pays for each once.
        checks += 1
        fit = said.get(f"FIT_{core['name']}")
        if fit != (lines, lines, 1):
            print(f"  FAIL {name}: core `{core['name']}` declares "
                  f"{memory['size_bytes']}B in {memory['line_bytes']}B lines "
                  f"= {lines} lines; a walk over {lines} lines twice reported "
                  f"{fit}, not ({lines}, {lines}, 1)")
            failures += 1
        # Twice that many does not fit, and pays every time.
        checks += 1
        over = said.get(f"OVER_{core['name']}")
        if over != (0, 4 * lines, 1):
            print(f"  FAIL {name}: a walk over {2 * lines} lines on a "
                  f"{lines}-line cache reported {over}, not (0, {4 * lines}, 1)")
            failures += 1

    for core, memory in cached:
        ways = memory["ways"] or 1
        # Exactly as many colliding lines as there are ways: all resident.
        checks += 1
        fit = said.get(f"WAYS_{core['name']}")
        if fit != (ways, ways, 1):
            print(f"  FAIL {name}: `{memory['name']}` declares {ways} way(s), "
                  f"so {ways} lines sharing a set should all stay -- a second "
                  f"pass reported {fit}, not ({ways}, {ways}, 1)")
            failures += 1
        # One more than that: nothing survives, whatever the replacement.
        checks += 1
        over = said.get(f"OVERWAYS_{core['name']}")
        if over != (0, 2 * (ways + 1), 1):
            print(f"  FAIL {name}: {ways + 1} lines sharing a {ways}-way set "
                  f"cannot all stay; a second pass reported {over}, not "
                  f"(0, {2 * (ways + 1)}, 1)")
            failures += 1

    # ⚠️ Two cores whose declared sizes differ must put their knees in
    # different places, or the gate is measuring one cache twice.
    sizes = {memory["size_bytes"] for _, memory in cached}
    checks += 1
    if len(cached) > 1 and len(sizes) < 2:
        print(f"  FAIL {name}: every cached core declares the same size, so "
              f"nothing here shows the description choosing it")
        failures += 1

    checks += 1
    none = said.get(f"NONE_{plain[0]['name']}")
    if not none or none[0] + none[1] != 0:
        print(f"  FAIL {name}: core `{plain[0]['name']}` names no memory and "
              f"still accounted for {none[0] + none[1] if none else '?'} "
              f"access(es)")
        failures += 1

    checks += 1
    replaced = said.get("REPLACED")
    if not replaced or replaced[0] + replaced[1] != 0:
        print(f"  FAIL {name}: a machine moved to a core with no memory kept "
              f"the cache it had ({replaced})")
        failures += 1

    # The host's cache, asked for after selection, is the one in force.
    # ⚠️ Recomputed from `cached[0]`, which is the core the harness actually
    # used. `lines` is the loop variable above and holds the LAST core's
    # geometry by now -- the gate reported a real mismatch against a number
    # from the wrong machine, which is the same class of mistake as measuring
    # the right thing on the wrong config.
    first_lines = first_memory["size_bytes"] // first_memory["line_bytes"]
    half = max(1, first_lines // 2)
    checks += 1
    override = said.get("OVERRIDE")
    if first_lines > 1 and override != (0, 2 * first_lines, 1):
        print(f"  FAIL {name}: a host configured {half} lines after selecting "
              f"`{first['name']}` and walked {first_lines} lines twice; "
              f"nothing fits, so it should have missed {2 * first_lines} "
              f"times and reported {override}")
        failures += 1

    # ⚠️ And the declared miss COST, in cycles. Counting hits and misses on a
    # cache whose penalty is ignored looks perfect, which would leave
    # `latency-cycles` exactly as unread as it was before a core named it.
    if charged_memory is not None:
        checks += 1
        row = None
        for line in done.stdout.splitlines():
            parts = line.split()
            if len(parts) == 7 and parts[0] == "CHARGED" and parts[1] == "cycles":
                row = (int(parts[2]), int(parts[4]), int(parts[6]))
        penalty = charged_memory["latency_cycles"]
        # ⚠️ Derived from the PIPELINE, not from serialisation. The repeated
        # instruction writes one register and reads two others, so the copies
        # are independent: they issue one per cycle and each completes a
        # latency plus a miss later. Independent misses OVERLAP -- the last
        # one retires at N + latency + penalty -- and a model that charged
        # every miss serially would be describing a machine that blocks on
        # the first, which is a different machine.
        latency = next((entry.get("latency_cycles", 1) or 1
                        for entry in facts["instructions"]
                        if entry["mnemonic"] == straight["mnemonic"]), 1)
        want = CHARGED_STEPS + latency + penalty
        if row is None or row[2] != CHARGED_STEPS:
            print(f"  FAIL {name}: the charged run executed "
                  f"{row[2] if row else '?'} instruction(s) of {CHARGED_STEPS}")
            failures += 1
        elif row[1] != CHARGED_STEPS:
            print(f"  FAIL {name}: the charged run missed {row[1]} times for "
                  f"{CHARGED_STEPS} forced misses")
            failures += 1
        elif row[0] != want:
            print(f"  FAIL {name}: `{charged_memory['name']}` declares a miss "
                  f"at {penalty} cycles; {CHARGED_STEPS} independent "
                  f"instructions of latency {latency} each taking one miss "
                  f"retire by {want}, and the machine reported {row[0]}")
            failures += 1

    if not failures:
        shape = ", ".join(
            f"{core['name']}={memory['size_bytes'] // memory['line_bytes']} lines"
            for core, memory in cached)
        print(f"  {name}: {shape}; each knee where its description puts it, "
              f"{checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
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
        print("the cache is the one the description declares: SKIP")
        return DECLINED
    print(f"the cache is the one the description declares: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
