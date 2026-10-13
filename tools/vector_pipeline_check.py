#!/usr/bin/env python3
"""A vector instruction is one instruction in the pipeline. Gate.

A scalable word is many lanes and one instruction (docs/vector_units_design.md,
VM1-VM2). On the timing engines it takes one window entry, and that entry has
to know everything the word does, not what its first lane does:

  * **every lane's accesses**: a vector load is one access per lane, and a
    window entry that held four made every vector store overflow -- a replay
    at commit, every time;
  * **every lane's registers**: lane 3 reads its sources' second limb, and a
    widening multiply's upper lanes write the register AFTER the one its
    first lane names. A reduction over that register must wait for the
    multiply.

Each scalable corpus gets a neutral core composed onto its ISA -- execution-
driven, and its trace-driven twin -- and runs its own instructions: every
fixture word once, then seeded random programs with the registers re-placed
among a few, so that instructions feed one another. On every program:

  * all three engines -- functional, trace-driven, execution-driven -- retire
    every instruction and leave the same registers, state and memory;
  * the execution-driven engine **replays nothing**: its dependences were
    complete;
  * a vector load that ran ahead of an older store over only its LATER lanes
    is squashed for it, not replayed: the window knows every lane's bytes;
  * the functional run's retire events never count more entries than their
    arrays hold, and none says it lost any;
  * and where no instruction stores, the two timed engines agree **cycle for
    cycle**, as they do on scalar straight-line code: the trace-driven window
    waits for the same producers.

Usage: tools/vector_pipeline_check.py [corpus.axisl ...] [--seeds N]
"""
from __future__ import annotations

import argparse
import importlib
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPORA = ("scalable_basic", "scalable_predicate", "scalable_crosslane", "scalable_memory",
           "scalable_vtype", "rvv", "matrix", "sme")

ENTRY = 0x200
LENGTH = 40
#: Registers the random programs draw from: few, so instructions collide.
POOL = (1, 2, 3, 4, 5, 6)

CORES = """
  (defcore vp_exec (kind rvmt) (implements %(isa)s) (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)) (engine execute))
  (defcore vp_trace (kind rvmt) (implements %(isa)s) (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)))
"""

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE (1 << 16)
static uint8_t CODE[IMAGE];

/* ⚠️ MEMORY IS EXACT: a byte for every 64-bit address that is written, and a
   fixed pattern for one that is not. These programs' base registers hold
   whatever the instructions before left in them. A memory that wrapped those
   addresses into a small image made two addresses one byte -- which the
   pipeline, ordering loads against stores by address, rightly did not -- and
   a store through one of them once landed on the program itself. */
#define CELLS (1u << 16)
static uint64_t CELL_AT[CELLS];
static uint8_t CELL_BYTE[CELLS], CELL_USED[CELLS];
static uint32_t cell(uint64_t a) {
  uint32_t i = (uint32_t)((a * 0x9E3779B97F4A7C15ull) >> 48);
  while (CELL_USED[i] && CELL_AT[i] != a) { i = (i + 1u) %% CELLS; }
  return i;
}
static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) {
    uint32_t at = cell(a + i);
    uint8_t byte = CELL_USED[at] ? CELL_BYTE[at] : (uint8_t)((a + i) * 31u + 7u);
    v |= (uint64_t)byte << (8 * i);
  }
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) {
    uint32_t at = cell(a + i);
    CELL_USED[at] = 1; CELL_AT[at] = a + i; CELL_BYTE[at] = (uint8_t)(v >> (8 * i));
  }
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE;
  return *ok ? (uint32_t)CODE[pc] | (uint32_t)CODE[pc + 1] << 8 | (uint32_t)CODE[pc + 2] << 16
               | (uint32_t)CODE[pc + 3] << 24 : 0u;
}
/* What the retire event said about itself (VM3): how many events held more
   entries than their arrays have -- never -- and how many said they had lost
   some. */
static uint64_t OVERRUN, LOSSY, EVENTS;
static void on_retire(void *c, const axis_pack_sim_event *event) {
  (void)c;
  /* The word a program ends on does not decode, and is reported all the same. */
  if (event->mnemonic) { EVENTS++; }
  if (event->read_count > (int32_t)AXIS_PACK_MAX_TOUCH || event->write_count > (int32_t)AXIS_PACK_MAX_TOUCH
      || event->access_count > (int32_t)AXIS_PACK_MAX_ACCESS || event->reads_total < event->read_count
      || event->writes_total < event->write_count || event->accesses_total < event->access_count) {
    OVERRUN++;
  }
  if (event->reads_total > event->read_count || event->writes_total > event->write_count
      || event->accesses_total > event->access_count) {
    LOSSY++;
  }
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

static void go(const char *tag, const char *core, const uint32_t *words, int32_t count) {
  const axis_sim_pack *S = %(sim)s();
  memset(CODE, 0, sizeof CODE);
  memset(CELL_USED, 0, sizeof CELL_USED);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) { CODE[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b)); }
  }
  /* The functional run is watched; the timed ones are as a host with no
     retire hook has them. */
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, core ? NULL : on_retire, NULL };
  OVERRUN = 0; LOSSY = 0; EVENTS = 0;
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (core && !S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  axis_pack_state_entry state[] = { %(state)s };
  S->reset(m, %(entry)du, "%(isa)s", state, %(states)d);
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x0101010101010101ull * (uint64_t)(i %% 7 + 1) + (uint64_t)i);
  }
  S->count_cycles(m, core != NULL);
  S->run(m, 100000u);
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (int32_t i = 0; i < %(states)d; ++i) {
    uint64_t v = S->state_value(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  /* Every byte written, whatever order the table holds them in. */
  uint64_t stored = 0;
  for (uint32_t i = 0; i < CELLS; ++i) {
    if (CELL_USED[i]) { stored += (CELL_AT[i] ^ ((uint64_t)CELL_BYTE[i] << 56)) * 0x9E3779B97F4A7C15ull; }
  }
  for (uint32_t b = 0; b < 8; ++b) { mark ^= (stored >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  printf("%%s steps %%llu cycles %%llu replays %%llu squashes %%llu overrun %%llu lossy %%llu events %%llu mark %%llu\n", tag,
         (unsigned long long)S->steps(m), (unsigned long long)S->cycles(m),
         (unsigned long long)(core ? S->replays(m) : 0u),
         (unsigned long long)(core ? S->memory_violations(m) : 0u),
         (unsigned long long)OVERRUN, (unsigned long long)LOSSY, (unsigned long long)EVENTS,
         (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
%(programs)s
%(runs)s
  return 0;
}
"""


def check(axis_file: Path, work: Path, seeds: int) -> tuple[int, int]:
    source = axis_file.read_text()
    found = re.search(r"\(defisa\s+(\S+)", source)
    name = axis_file.stem
    if not found or "(vector-bits" not in source:
        print(f"  {name}: DECLINED no scalable ISA")
        return 0, 0
    isa = found.group(1)
    corpus = work / f"{name}_vp.axisl"
    end = source.rstrip().rfind(")")
    corpus.write_text(source[:end] + CORES % {"isa": isa} + ")\n")

    def run_cmd(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=AXIS_ROOT)

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    module = f"vp_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    # One word per instruction: a lane group's lanes share theirs.
    words, stores = {}, set()
    for test in tests:
        if test.get("isa") not in (isa, None, ""):
            continue
        word = int(test["encoded"], 16)
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        if any(e.get("kind") == "store" for e in entry.get("effects") or []):
            stores.add(word)
        words.setdefault(word, entry)
    if not words:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED no fixture words")
        return 0, 0

    def scrambled(word, entry, rng):
        # ⚠️ The mask an instruction matches on is not an operand's to change:
        # a field that is one is left as the fixture has it.
        for operand in entry["operands"]:
            if "__l" in operand["name"] or not lift.is_register_operand(operand["kind"]):
                continue
            try:
                changed = lift.place_operand(word, entry, operand["name"], rng.choice(POOL))
            except Exception:  # noqa: BLE001 -- an operand with no field of its own
                continue
            if (changed & entry["mask"]) == entry["match"]:
                word = changed
        return word

    programs = {"EACH": list(words)}
    storing = {"EACH": bool(stores)}
    for seed in range(seeds):
        rng = random.Random(1000 + seed)
        picks = [rng.choice(list(words)) for _ in range(LENGTH)]
        programs[f"RANDOM{seed}"] = [scrambled(w, words[w], rng) for w in picks]
        storing[f"RANDOM{seed}"] = any(w in stores for w in picks)
    # And one with no store in it, so the two timed engines can be compared.
    quiet = [w for w in words if w not in stores]
    if quiet:
        rng = random.Random(7)
        programs["QUIET"] = [scrambled(w, words[w], rng)
                             for w in (rng.choice(quiet) for _ in range(LENGTH))]
        storing["QUIET"] = False
    # ⚠️ ORDER: a vector store whose data is late, and after it a vector load
    # of many lanes that starts seven bytes BEFORE the store -- so only the
    # load's later lanes meet it. The load runs first; when the store runs,
    # the window has to know those lanes read its bytes. Random programs
    # never showed it: their loads and stores are through whatever the
    # registers hold, and almost never meet. Registers 8 and 15 start seven
    # apart (the harness's pattern repeats every seven slots).
    def lanes_of(entry):
        base = entry["mnemonic"].rsplit("__l", 1)[0]
        return sum(1 for other in lift.AXIS_LIFT_TABLE
                   if other["mnemonic"].rsplit("__l", 1)[0] == base)

    def bases(entry):
        return [o["name"] for o in entry["operands"]
                if o["role"] == "in" and "__l" not in o["name"]
                and lift.is_register_operand(o["kind"])]

    def vectors(entry, role):
        return [o["name"].rsplit("__l", 1)[0] for o in entry["operands"]
                if o["role"] == role and "__l" in o["name"]]

    loads = [(w, e) for w, e in words.items() if w not in stores and len(bases(e)) == 1
             and len(vectors(e, "out")) == 1 and not vectors(e, "in")
             and not any("guard" in x for x in e.get("effects") or [])]
    saves = [(w, e) for w, e in words.items() if w in stores and len(bases(e)) == 1
             and len(vectors(e, "in")) == 1]
    ordered = False
    if loads and saves:
        wide_load = max(loads, key=lambda we: lanes_of(we[1]))
        save = min(saves, key=lambda we: lanes_of(we[1]))
        if lanes_of(wide_load[1]) >= 8:
            def place(word, entry, **values):
                for operand, value in values.items():
                    word = lift.place_operand(word, entry, operand, value)
                return word
            lw, le = wide_load
            sw, se = save
            programs["ORDER"] = [
                place(lw, le, **{vectors(le, "out")[0]: 10, bases(le)[0]: 1}),
                place(sw, se, **{vectors(se, "in")[0]: 10, bases(se)[0]: 15}),
                place(lw, le, **{vectors(le, "out")[0]: 12, bases(le)[0]: 8}),
            ]
            storing["ORDER"] = True
            ordered = True
    state_slots = list(getattr(lift, "STATE_SLOTS", []))
    sys.modules.pop(module, None)

    machines = {"FUNC": "NULL", "TRACE": '"vp_trace"', "EXEC": '"vp_exec"'}
    body = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "isa": isa,
        "state": ", ".join('{"%s", 0, %du}' % (n, w) for n, w in state_slots) or "{0, 0, 0u}",
        "states": len(state_slots),
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in ws)}, 0u }};"
            for label, ws in programs.items()),
        "runs": "\n".join(f'  go("{label}_{tag}", {core}, {label}, {len(ws)});'
                          for label, ws in programs.items() for tag, core in machines.items()),
    }
    root = work / "packs" / manifest["name"]
    (work / f"{name}.c").write_text(body)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / name),
             str(work / f"{name}.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}")
        return 0, 1
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 17 and parts[1] == "steps":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        sys.stderr.write(done.stderr)
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    timed = 0
    for label, ws in programs.items():
        rows = {tag: said.get(f"{label}_{tag}") for tag in machines}
        checks += 1
        if any(r is None for r in rows.values()):
            fail(f"{label} reported nothing on some engine")
            continue
        checks += 1
        if rows["FUNC"]["steps"] != len(ws):
            fail(f"{label}: the functional model retired {rows['FUNC']['steps']} of {len(ws)} "
                 f"instructions; a program that stops early checks nothing after it")
            continue
        checks += 1
        if len({(r["steps"], r["mark"]) for r in rows.values()}) != 1:
            fail(f"{label}: the engines retired {[r['steps'] for r in rows.values()]} "
                 f"instructions or left different registers, state or memory")
        checks += 1
        if rows["EXEC"]["replays"]:
            fail(f"{label}: the execution-driven engine replayed {rows['EXEC']['replays']} "
                 f"instruction(s); a vector word's window entry must name every register and "
                 f"hold every access of every lane")
        if not storing[label]:
            checks += 1
            timed += 1
            if rows["EXEC"]["cycles"] != rows["TRACE"]["cycles"]:
                fail(f"{label}, which stores nothing: {rows['EXEC']['cycles']} cycles "
                     f"execution-driven and {rows['TRACE']['cycles']} trace-driven; the two "
                     f"windows wait for the same producers")
    # ⚠️ THE RETIRE EVENT HOLDS WHAT IT COUNTS (VM3). Its arrays are a fixed
    # size; an event never claims more entries than it holds, and its totals
    # are never below its counts. No instruction of any corpus here is wider
    # than the event -- SME's widest store is sixteen accesses, exactly its
    # size -- so none says it lost entries; a corpus that grows one has to be
    # named here, since "it said so" is then the thing to hold.
    each = said.get("EACH_FUNC")
    if each:
        checks += 1
        if each["events"] != each["steps"]:
            fail(f"{each['events']} retire events for {each['steps']} instructions")
        checks += 1
        if each["overrun"]:
            fail(f"{each['overrun']} retire event(s) counted more entries than their arrays "
                 f"hold, or a total below its count")
        checks += 1
        if each["lossy"]:
            fail(f"{each['lossy']} retire event(s) said they had lost entries; no instruction "
                 f"here was known to be wider than the event")
    if ordered and said.get("ORDER_EXEC"):
        checks += 1
        if not said["ORDER_EXEC"]["squashes"]:
            fail("ORDER: the load that ran ahead of an older store over its later lanes was "
                 "never squashed for it; the program has to make the window order them to "
                 "say anything")
    if not failures:
        print(f"  {name}: {len(words)} instructions, {len(programs)} programs, all three engines "
              f"agree, 0 replays; {timed} store-free program(s) cycle for cycle; {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--seeds", type=int, default=6)
    parser.add_argument("--dump", action="store_true")
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / f"{c}.axisl" for c in CORPORA]
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
        print("a vector instruction is one instruction in the pipeline: SKIP")
        return DECLINED
    print(f"a vector instruction is one instruction in the pipeline: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
