#!/usr/bin/env python3
"""Several execution-driven cores over one memory. Gate.

MC1 (docs/ooo_design.md): `run_cores` advances execution-driven machines in
lockstep, a cycle each, over the memory their host shares; a store that
commits squashes any other core's load that has executed over those bytes
and not committed (a snoop). Held here:

  * **apart, nothing changes**: cores whose programs touch disjoint memory
    take, together, exactly the cycles each takes alone, leave exactly the
    same registers and memory, and are never snooped -- two cores and four,
    and a core whose loads forward from its own stores (its own commit is
    no snoop);
  * **store buffering**: core 0 stores x then loads y, core 1 stores y then
    loads x. Over a sweep of delays in front of each, both loads reading 0 --
    the outcome sequential consistency forbids -- never happens, both orders
    in which one core goes first do, and the cores snoop each other;
  * **message passing**: core 0 writes a datum, then a flag; core 1 spins on
    the flag and then reads the datum. It always reads the datum, and the
    spin's early loads are squashed by the flag's store (snoops), never
    caught by the golden model (zero replays) -- anywhere in this gate;
  * **the limit binds**: each core stops at `limit` instructions;
  * **refusals**: a trace-driven core, and a machine listed twice, are
    refused (-1).

Usage: tools/mcx_check.py [corpus.axisl ...] [--seeds N]
"""
from __future__ import annotations

import argparse
import importlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from lsq_check import Assembler, run_cmd  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402
from xmode_check import random_program  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200      # core c's program at ENTRY + c * CODE
CODE = 0x400
DATA = 0x4000      # core c's own region at DATA + c * REGION when apart
REGION = 0x1000
BASE, ONE, MINUS_ONE, COUNTER = 5, 8, 7, 9
X, Y, DATUM, FLAG = 0, 64, 128, 192   # offsets from the shared base
OUT, OUT2 = 20, 21                    # where litmus loads land
MAXC = 4

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
static axis_pack_sim_hooks HOOKS = { rd, wr, fetch, on_trap, NULL, NULL };

static void image(void) {
  memset(MEMORY, 0, sizeof MEMORY);
  /* Every core's own region the same pattern, apart or together; the shared
     litmus words, at the first region's base, start at zero. */
  for (uint32_t r = 0; r < %(maxc)du; ++r) {
    for (uint32_t a = 0; a < 256u; ++a) { MEMORY[%(data)du + r * %(region)du + a] = (uint8_t)(a * 37u + 11u); }
  }
  for (uint32_t a = 0; a < 256u; ++a) { MEMORY[%(data)du + a] = 0u; }
}
static void place(int32_t c, const uint32_t *words, int32_t count) {
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) { MEMORY[%(entry)du + (uint32_t)c * %(code)du + 4u * (uint32_t)i + b] = (uint8_t)(words[i] >> (8 * b)); }
  }
}
static void *make(const char *core, int32_t c, int shared, uint32_t trips) {
  const axis_sim_pack *S = %(sim)s();
  void *m = S->create(&HOOKS);
  if (!m || !S->select_core(m, core)) { return NULL; }
  S->reset(m, %(entry)du + (uint32_t)c * %(code)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->set_reg(m, %(base)d, %(data)du + (shared ? 0u : (uint32_t)c * %(region)du));
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
  S->count_cycles(m, 1);
  return m;
}
static void report(const char *tag, int32_t c, void *m, int shared) {
  const axis_sim_pack *S = %(sim)s();
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  uint32_t at = %(data)du + (shared ? 0u : (uint32_t)c * %(region)du);
  for (uint32_t a = at; a < at + 256u; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s.%%d cycles %%llu steps %%llu replays %%llu snoops %%llu out %%llu out2 %%llu mark %%llu\n",
         tag, c, (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->replays(m), (unsigned long long)S->snoops(m),
         (unsigned long long)S->reg(m, %(out)d), (unsigned long long)S->reg(m, %(out2)d),
         (unsigned long long)mark);
}
/* Alone: one machine, run as every other gate runs it. */
static void alone(const char *tag, const char *core, int32_t c, const uint32_t *words, int32_t count,
                  uint32_t trips) {
  const axis_sim_pack *S = %(sim)s();
  image();
  place(c, words, count);
  void *m = make(core, c, 0, trips);
  if (!m) { printf("%%s NOCORE\n", tag); return; }
  S->run(m, 20000u);
  report(tag, c, m, 0);
  S->destroy(m);
}
/* Together: n machines, one memory, run_cores. */
static void together(const char *tag, const char *core, int32_t n, const uint32_t *const *words,
                     const int32_t *counts, int shared, uint32_t trips, uint64_t limit) {
  const axis_sim_pack *S = %(sim)s();
  image();
  void *ms[%(maxc)d];
  for (int32_t c = 0; c < n; ++c) {
    place(c, words[c], counts[c]);
    ms[c] = make(core, c, shared, trips);
    if (!ms[c]) { printf("%%s NOCORE\n", tag); return; }
  }
  int32_t rc = S->run_cores(ms, n, limit);
  printf("%%s rc %%d\n", tag, rc);
  for (int32_t c = 0; c < n; ++c) { report(tag, c, ms[c], shared); S->destroy(ms[c]); }
}
/* What run_cores refuses. */
static void refused(const char *tag, const char *core, const uint32_t *words, int32_t count, int twice) {
  const axis_sim_pack *S = %(sim)s();
  image();
  place(0, words, count);
  place(1, words, count);
  void *ms[2];
  ms[0] = make(core, 0, 1, 1u);
  ms[1] = twice ? ms[0] : make(core, 1, 1, 1u);
  if (!ms[0] || !ms[1]) { printf("%%s NOCORE\n", tag); return; }
  printf("%%s rc %%d\n", tag, S->run_cores(ms, 2, 0u));
  S->destroy(ms[0]);
  if (!twice) { S->destroy(ms[1]); }
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->run_cores) { printf("NOENGINE\n"); return 0; }
%(programs)s
%(runs)s
  return 0;
}
"""


def check(axis_file: Path, work: Path, seeds: int) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    core = next((c for c in cores if c.get("engine") == "execute" and not c.get("lsq")
                 and c.get("rob") and not (c.get("front_end") or {}).get("icache")
                 and not (c.get("front_end") or {}).get("ras") and c.get("predictor") == "bimodal"
                 and not c.get("memory")), None)
    trace = next((c for c in cores if c.get("engine") != "execute" and c.get("rob")), None)
    if core is None or trace is None:
        print(f"  {name}: DECLINED no plain execution-driven core, or no trace-driven one")
        return 0, 0

    module = f"mc_{name}"
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
    add, mul = asm.fast_add, asm.slow
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
    sys.modules.pop(module, None)

    def delay(n):
        """n slow multiplies on a register nothing else reads: time, not data."""
        return [asm.op(mul, 30, 30, 30) for _ in range(n)]

    def sb(mine, theirs, wait):
        return delay(wait) + [asm.st(ONE, BASE, mine), asm.ld(OUT, BASE, theirs), 0]

    def mp_writer(wait):
        return delay(wait) + [asm.st(3, BASE, DATUM)] + delay(2) + [asm.st(ONE, BASE, FLAG), 0]

    # The reader spins while the flag is not 1, then reads the datum.
    mp_reader = [asm.ld(OUT, BASE, FLAG), bnz(OUT, ONE, -4), asm.ld(OUT2, BASE, DATUM), 0]

    rng = random.Random(2468)
    programs = {f"R{k}": random_program(asm, bnz, rng, rng.randrange(8, 24)) for k in range(seeds)}
    waits = range(0, 7)
    for w in waits:
        programs[f"SB0_{w}"] = sb(X, Y, w)
        programs[f"SB1_{w}"] = sb(Y, X, w)
        programs[f"MPW_{w}"] = mp_writer(w)
    programs["MPR"] = mp_reader
    programs["STRAIGHT"] = [asm.op(add, 10 + k % 8, 1, 2) for k in range(40)] + [0]
    # A store and a load of the same word every iteration: the load forwards
    # from its own core's store, and that store's commit is no snoop of it.
    # (The stored register is ready long before, so the store executes first
    # and the load behind it reads the window, not memory.)
    fwd = [asm.st(1, BASE, 0), asm.ld(12, BASE, 0), asm.op(add, 1, 1, ONE),
           asm.op(add, 13, 13, 12), asm.op(add, COUNTER, COUNTER, MINUS_ONE)]
    fwd.append(bnz(COUNTER, 0, -4 * len(fwd)))
    programs["FWD"] = fwd + [0]

    runs = []
    expect = []

    def alone(tag, label, c, trips=5):
        runs.append(f'  alone("{tag}", "{core["name"]}", {c}, {label}, {len(programs[label])}, {trips}u);')
        expect.append(f"{tag}.{c}")

    def together(tag, labels, shared, trips=5, limit=0, which=None):
        n = len(labels)
        runs.append("  { static const uint32_t *const w[] = { " + ", ".join(labels) + " }; "
                    "static const int32_t n[] = { " + ", ".join(str(len(programs[x])) for x in labels)
                    + " }; " + f'together("{tag}", "{(which or core)["name"]}", {n}, w, n, {shared}, '
                    f"{trips}u, {limit}u); }}")
        expect.append(tag)
        expect.extend(f"{tag}.{c}" for c in range(n))

    # Apart: pairs and a quartet of random programs, each also alone.
    groups = [[f"R{k}", f"R{(k + 1) % seeds}"] for k in range(0, seeds, 2)]
    groups.append([f"R{k}" for k in range(min(MAXC, seeds))])
    groups.append(["FWD", "R0"])
    for g, labels in enumerate(groups):
        together(f"APART{g}", labels, 0)
        for c, label in enumerate(labels):
            alone(f"ALONE{g}", label, c)
    # Litmus.
    for w0 in waits:
        for w1 in waits:
            together(f"SB_{w0}_{w1}", [f"SB0_{w0}", f"SB1_{w1}"], 1)
    for w in waits:
        together(f"MP_{w}", [f"MPW_{w}", "MPR"], 1)
    # The limit, and the refusals.
    together("LIMIT", ["STRAIGHT", "STRAIGHT"], 0, limit=7)
    runs.append(f'  refused("TRACE", "{trace["name"]}", STRAIGHT, {len(programs["STRAIGHT"])}, 0);')
    runs.append(f'  refused("TWICE", "{core["name"]}", STRAIGHT, {len(programs["STRAIGHT"])}, 1);')
    expect += ["TRACE", "TWICE"]

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "code": CODE,
        "data": DATA, "region": REGION, "maxc": MAXC,
        "base": slot(BASE), "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
        "out": slot(OUT), "out2": slot(OUT2),
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs),
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / name), str(work / f"{name}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True, timeout=600)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}")
        return 0, 1
    said, rcs = {}, {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] == "rc":
            rcs[parts[0]] = int(parts[2])
        elif len(parts) == 15 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    checks += 1
    missing = [k for k in expect if k not in said and k not in rcs]
    if missing:
        fail(f"no report for {missing[:5]}")
        return checks, failures

    for key, row in said.items():
        checks += 1
        if row["replays"]:
            fail(f"{key}: {row['replays']} replay(s); a stale load is a snoop's to catch")

    # Apart: together is alone, exactly.
    for g, labels in enumerate(groups):
        checks += 1
        if rcs.get(f"APART{g}") != 0:
            fail(f"APART{g}: run_cores said {rcs.get(f'APART{g}')}")
        for c in range(len(labels)):
            both, one = said[f"APART{g}.{c}"], said[f"ALONE{g}.{c}"]
            checks += 1
            for field in ("cycles", "steps", "mark"):
                if both[field] != one[field]:
                    fail(f"APART{g} core {c}: {field} {both[field]} together, {one[field]} alone")
            if both["snoops"]:
                fail(f"APART{g} core {c}: {both['snoops']} snoop(s) with nothing shared")

    # Store buffering.
    outcomes, sb_snoops = set(), 0
    for w0 in waits:
        for w1 in waits:
            tag = f"SB_{w0}_{w1}"
            r0, r1 = said[f"{tag}.0"]["out"], said[f"{tag}.1"]["out"]
            outcomes.add((r0, r1))
            sb_snoops += said[f"{tag}.0"]["snoops"] + said[f"{tag}.1"]["snoops"]
            checks += 1
            if (r0, r1) == (0, 0):
                fail(f"{tag}: both loads read 0 -- not sequentially consistent")
    checks += 1
    if not {(0, 1), (1, 0)} <= outcomes:
        fail(f"store buffering: outcomes {sorted(outcomes)}; both orders should happen")
    checks += 1
    if not sb_snoops:
        fail("store buffering: no core ever snooped the other")

    # Message passing.
    mp_snoops = 0
    for w in waits:
        reader = said[f"MP_{w}.1"]
        mp_snoops += reader["snoops"]
        checks += 1
        if reader["out2"] != 0x11 * (slot(3) + 1) or reader["out"] != 1:
            fail(f"MP_{w}: the reader saw flag {reader['out']} and datum {reader['out2']:#x}")
    checks += 1
    if not mp_snoops:
        fail("message passing: the spin was never snooped")

    # The limit, and the refusals.
    for c in (0, 1):
        checks += 1
        if said[f"LIMIT.{c}"]["steps"] != 7:
            fail(f"LIMIT core {c}: {said[f'LIMIT.{c}']['steps']} steps under a limit of 7")
    for tag in ("TRACE", "TWICE"):
        checks += 1
        if rcs.get(tag) != -1:
            fail(f"{tag}: run_cores said {rcs.get(tag)}, not -1")

    print(f"  {name}: {len(groups)} groups apart == alone; store buffering {sorted(outcomes)} "
          f"over {len(waits) ** 2} timings, {sb_snoops} snoops; message passing {mp_snoops} snoops; "
          f"0 replays")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--seeds", type=int, default=8)
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "issue_width.axisl"]
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp), args.seeds)
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("several cores share one memory: SKIP")
        return DECLINED
    print(f"several cores share one memory: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
