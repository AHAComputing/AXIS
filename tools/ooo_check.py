#!/usr/bin/env python3
"""An instruction waiting on a slow producer does not hold up the ones behind
it. Gate.

That sentence is the whole of what out-of-order execution buys, and it is the
one thing the in-order model cannot do at any issue width or unit count. The
model that answers it is a different algorithm rather than a wider version of
the old one: a tick loop over a finite reorder buffer, issuing whatever is
ready from anywhere in the window and retiring strictly in order.

⚠️ Cycle-accurate for the structures it has, over a CORRECT-PATH trace. It does
not fetch or execute the wrong path -- the functional side is decoupled and
only ever runs what actually ran -- so wrong-path cache pollution and
wrong-path prefetch are invisible. A mispredict is modelled as the front-end
drain it causes, which is the part this model can honestly see. Saying which
half is modelled matters more than the cycle count.

The program is a BLOCKING one: a long-latency producer, an instruction that
waits for it, and then a run of work that needs neither. An in-order machine
cannot start the independent work until the waiter goes; a windowed one can.

  * **the window beats in order** on that program, strictly;
  * **a dependent CHAIN is not helped at all**, exactly. Nothing in a chain can
    be reordered, so a window that appeared to help one would be reordering
    something it had no right to -- this is the check that catches a model
    that simply runs faster;
  * **the window SIZE is what buys it**: a buffer too small to hold the
    independent work behind the waiter cannot reach it, so a small window
    lands between in-order and a large one;
  * **more window never costs more**;
  * **program order is preserved**: both machines retire the same instructions
    and leave the same registers, because a timing model that changed a result
    would be reordering the architecture rather than the schedule.

Usage: tools/ooo_check.py [corpus.axisl ...]
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

ENTRY = 0x200
#: Producer/consumer pairs. ⚠️ More than the small window holds and no more
#: than the large one, or the two windows cannot differ.
PAIRS = 6

HARNESS = r"""
/* One blocking program, one chain, run on each machine. */
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

static void go(const char *tag, const char *core, const uint32_t *words,
               int32_t count) {
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
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  }
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)count);
  /* ⚠️ A fingerprint of the whole register file: a timing model that changed
     a RESULT would be reordering the architecture, not the schedule. */
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  printf("%%s cycles %%llu steps %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core) { printf("NOCORES\n"); return 0; }
  static const uint32_t BLOCK[] = { %(block)s };
  static const uint32_t CHAIN[] = { %(chain)s };
  static const uint32_t SPREAD[] = { %(spread)s };
  const int32_t bn = (int32_t)(sizeof BLOCK / sizeof BLOCK[0]);
  const int32_t cn = (int32_t)(sizeof CHAIN / sizeof CHAIN[0]);
  const int32_t sn = (int32_t)(sizeof SPREAD / sizeof SPREAD[0]);
%(runs)s
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def build_programs(lift, tests, latency_of):
    """A blocking program, and a chain that nothing can reorder."""
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    candidates = []
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None or entry.get("effects"):
            continue
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        ins = [o for o in entry["operands"]
               if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        if len(outs) == 1 and len(ins) >= 1:
            candidates.append((test, entry, outs[0], ins))
    if len(candidates) < 2:
        return None, None, None, None, "fewer than two register-to-register instructions"

    def cost(row):
        return latency_of.get(row[0]["mnemonic"], 1) or 1

    slow = max(candidates, key=cost)
    fast = min(candidates, key=cost)
    if cost(slow) <= cost(fast):
        return None, None, None, None, "no instruction slower than another to block on"

    def encode(row, dest, source):
        test, entry, out, ins = row
        built = lift.place_operand(int(test["encoded"], 16), entry, out["name"], dest)
        for operand in ins:
            built = lift.place_operand(built, entry, operand["name"], source)
        return built

    # ⚠️ PAIRS, not one producer with fillers behind it. A single stall with
    # independent work after it barely separates the two models, because
    # commit is in order on both and the program ends right there -- the
    # independent work still has to retire behind the waiter. What separates
    # them is a stall that REPEATS: each pair's producer is independent of
    # every other pair, so a window can start the next producer while this
    # pair's consumer waits, and an in-order machine cannot.
    block = []
    for i in range(PAIRS):
        block.append(encode(slow, 8 + 2 * i, 1))
        block.append(encode(fast, 9 + 2 * i, 8 + 2 * i))
    # A chain: every instruction reads what the one before it wrote.
    chain = [encode(slow, 7, 7) for _ in range(6)]
    # ⚠️ And a run of INDEPENDENT slow instructions, which is the only shape
    # that can see the unit. Dependence-bound and window-bound programs are
    # both limited by something else, so a model that let any number of
    # operations start on a single-copy unit in one cycle looked right on
    # every program here -- mutation testing said so.
    spread = [encode(slow, 8 + i, 1) for i in range(2 * PAIRS)]
    return block, chain, spread, (cost(slow), slow[0]["mnemonic"]), None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    # ⚠️ PLAIN windows only: a core that also orders memory, bounds its
    # registers or has a front end is measuring something else as well, and
    # this gate's arithmetic is about the window alone. When the corpus grew
    # cores with those structures, the largest window became a front-end core
    # with no in-order twin, and this gate quietly DECLINED -- a gate that
    # stops running is a gate that stopped holding anything.
    def plain(core):
        return (not core.get("lsq") and not core.get("rename")
                and not core.get("front_end") and not core.get("model"))

    cores = [core for core in facts.get("cores", []) if plain(core)]

    def twin(core):
        return next((other for other in cores
                     if not other.get("rob")
                     and other.get("issue_width") == core.get("issue_width")
                     and other.get("units") == core.get("units")), None)

    windowed = sorted((core for core in cores if core.get("rob")),
                      key=lambda core: core["rob"])
    large = next((core for core in reversed(windowed) if twin(core)), None)
    small = next((core for core in windowed if large and core is not large
                  and core["rob"] < large["rob"]
                  and core.get("issue_width") == large.get("issue_width")
                  and core.get("units") == large.get("units")), None)
    if large is None or small is None:
        print(f"  {name}: DECLINED fewer than two plain windows of one machine")
        return 0, 0
    ordered = twin(large)
    if ordered is None:
        print(f"  {name}: DECLINED no in-order core with the same width and "
              f"units to compare against")
        return 0, 0

    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"oo_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"oo_{name}")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    block, chain, spread, slow, why = build_programs(lift, tests, latency_of)
    isa = tests[0].get("isa") or "" if tests else ""
    sys.modules.pop(f"oo_{name}", None)
    if block is None:
        print(f"  {name}: DECLINED {why}")
        return 0, 0

    runs = []
    for tag, core in (("ORDER", ordered), ("SMALL", small), ("LARGE", large)):
        runs.append(f'  go("B_{tag}", "{core["name"]}", BLOCK, bn);')
        runs.append(f'  go("C_{tag}", "{core["name"]}", CHAIN, cn);')
    runs.append(f'  go("U_LARGE", "{large["name"]}", SPREAD, sn);')

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "entry": ENTRY,
        "isa": f'"{isa}"' if isa else "NULL",
        "block": ", ".join(f"{w}u" for w in block),
        "chain": ", ".join(f"{w}u" for w in chain),
        "spread": ", ".join(f"{w}u" for w in spread),
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
        if len(parts) == 7 and parts[1] == "cycles":
            said[parts[0]] = (int(parts[2]), int(parts[4]), int(parts[6]))

    checks = failures = 0
    for tag in ("B_ORDER", "B_SMALL", "B_LARGE", "C_ORDER", "C_SMALL", "C_LARGE"):
        checks += 1
        if tag not in said:
            print(f"  FAIL {name}: {tag} reported nothing")
            failures += 1
    if failures:
        return checks, failures

    # Every machine ran the same program and left the same architecture.
    for prefix, count in (("B", len(block)), ("C", len(chain))):
        for tag in ("ORDER", "SMALL", "LARGE"):
            checks += 1
            if said[f"{prefix}_{tag}"][1] != count:
                print(f"  FAIL {name}: {prefix}_{tag} retired "
                      f"{said[f'{prefix}_{tag}'][1]} of {count}")
                failures += 1
        checks += 1
        marks = {said[f"{prefix}_{tag}"][2] for tag in ("ORDER", "SMALL", "LARGE")}
        if len(marks) != 1:
            print(f"  FAIL {name}: the {prefix} program left different "
                  f"registers on different machines; a timing model reordered "
                  f"the architecture")
            failures += 1
    if failures:
        return checks, failures

    # ⚠️ THE PROPERTY. A window lets independent work start while a waiter
    # waits; no in-order machine can, at any width.
    checks += 1
    if said["B_LARGE"][0] >= said["B_ORDER"][0]:
        print(f"  FAIL {name}: the blocking program cost {said['B_LARGE'][0]} "
              f"cycles on a {large['rob']}-entry window and "
              f"{said['B_ORDER'][0]} in order; a window that does not beat "
              f"in-order on a blocked program is not reordering anything")
        failures += 1

    # ⚠️ And a CHAIN is not helped by window size, exactly. This is the check
    # that separates a reordering machine from one that is simply faster.
    #
    # ⚠️ Compared between the two WINDOWS rather than against the in-order
    # machine, because the two models report different quantities: the
    # in-order scoreboard reports when the last instruction's issue slot
    # frees, and the window reports when the last instruction RETIRES. The
    # offset is about one latency and it is a known wart -- absolute cycle
    # counts are not comparable across the two models, only large-margin
    # directions are.
    # ⚠️ THE CRITICAL PATH IS A FLOOR, and this is the check that says
    # dependences are honoured at all. A chain of K instructions at latency L
    # cannot finish in less than L x (K-1) however wide the machine or big the
    # window -- there is nothing to overlap. Chain INVARIANCE alone cannot see
    # a model that ignores dependences, because such a model is equally wrong
    # at both window sizes and the two still agree.
    checks += 1
    floor = slow[0] * (len(chain) - 1)
    if said["C_LARGE"][0] < floor:
        print(f"  FAIL {name}: a chain of {len(chain)} {slow[1]} at latency "
              f"{slow[0]} cannot finish before {floor} cycles -- there is "
              f"nothing in it to overlap -- and the machine reported "
              f"{said['C_LARGE'][0]}")
        failures += 1

    # ⚠️ THE ANCHOR, and it is only sayable because in-order and out-of-order
    # are now ONE loop differing in one line. A chain has nothing to reorder,
    # so an in-order machine and a windowed one must agree on it EXACTLY --
    # not approximately, and not merely in direction. While the two were
    # separate algorithms reporting different quantities this could only be
    # checked window-against-window, which left the in-order configuration
    # anchored to nothing at all.
    checks += 1
    chain_costs = {tag: said[f"C_{tag}"][0] for tag in ("ORDER", "SMALL", "LARGE")}
    if len(set(chain_costs.values())) != 1:
        print(f"  FAIL {name}: a dependent chain cost {chain_costs} in order, "
              f"on a {small['rob']}-entry window and on a {large['rob']}-entry "
              f"one; nothing in a chain can be reordered, so none of those may "
              f"differ")
        failures += 1

    # The SIZE is what buys it: too small a window cannot reach the work.
    checks += 1
    if said["B_LARGE"][0] > said["B_SMALL"][0]:
        print(f"  FAIL {name}: blocking cost {said['B_SMALL'][0]} at "
              f"{small['rob']} entries and {said['B_LARGE'][0]} at "
              f"{large['rob']}; a bigger window must never cost more")
        failures += 1
    checks += 1
    if said["B_SMALL"][0] <= said["B_LARGE"][0]:
        print(f"  FAIL {name}: a {small['rob']}-entry window matched a "
              f"{large['rob']}-entry one on work that needs "
              f"{PAIRS} pairs of lookahead; the size is not being "
              f"read")
        failures += 1

    # ⚠️ A UNIT WITH ONE COPY STARTS ONE OPERATION A CYCLE, whatever the issue
    # width and however empty the window. Independent work is the only program
    # that can see this: everything else here is bound by a dependence or by
    # the buffer.
    unit_of = {entry["mnemonic"]: entry.get("unit")
               for entry in facts["instructions"]}
    copies = next((unit.get("count", 1) or 1 for unit in large.get("units", [])
                   if unit["name"] == unit_of.get(slow[1])), 1)
    spread_row = said.get("U_LARGE")
    checks += 1
    if spread_row is None or spread_row[1] != len(spread):
        print(f"  FAIL {name}: the independent run retired "
              f"{spread_row[1] if spread_row else '?'} of {len(spread)}")
        failures += 1
    else:
        checks += 1
        floor = -(-len(spread) // copies)
        if spread_row[0] < floor:
            print(f"  FAIL {name}: {len(spread)} independent {slow[1]} on "
                  f"{copies} cop(y/ies) of their unit cannot start faster than "
                  f"one each per cycle, so they cannot finish in under {floor} "
                  f"cycles; the machine reported {spread_row[0]}")
            failures += 1

    if not failures:
        print(f"  {name}: a {slow[1]} of latency {slow[0]} blocks "
              f"{PAIRS} independent pair(s) -- {said['B_ORDER'][0]} "
              f"cycles in order, {said['B_SMALL'][0]} at {small['rob']} "
              f"entries, {said['B_LARGE'][0]} at {large['rob']}; a chain costs "
              f"{said['C_SMALL'][0]} on all three, {checks} checks")
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
        print("a waiter does not hold up what follows it: SKIP")
        return DECLINED
    print(f"a waiter does not hold up what follows it: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
