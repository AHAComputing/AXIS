#!/usr/bin/env python3
"""One unit, several cores. Gate.

`share_unit(machine, other, "vec")` (docs/vector_units_design.md, VU4) makes
one unit of two cores a single set of copies and lanes -- an SME unit shared
by the cores around it. Each core keeps its own window and everything else.
What sharing costs is the unit's own: `(transport N)` on every result, and
`(switch N)` to change which core it serves; a turn is switch + 1 operations.

Two execution-driven machines run in step, each with its own program of
128-bit adds on a two-lane unit -- one add a cycle. Each figure is the cycles
the second half of a program costs its core:

  * **private, both busy**: one a cycle each -- two units;
  * **shared, both busy**: one every two cycles each -- one unit, turn about,
    and neither core starves whichever ticks first;
  * **shared, one busy**: the busy core has the whole unit, one a cycle;
  * **a switch cost of two**: a turn is three operations, and changing owner
    costs two cycles -- six operations in ten cycles, between them;
  * **a transport cost of two**: independent adds lose nothing -- the unit is
    as busy as it was -- and a chain, each add reading the last, takes three
    cycles a link instead of one;
  * the registers each core ends with are the ones it ends with alone, and
    nothing replays;
  * **a core of two contexts is one party**: sharing the unit with a second
    core, that core gets half -- not a third -- and the unit is never idle
    while anyone wants it;
  * and `share_unit` refuses two cores whose units differ, a unit neither
    has, a machine that has started, and two contexts of one core.

Usage: tools/vector_share_check.py
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
CORPUS = AXIS_ROOT / "examples" / "scalable_basic.axisl"
ISA = "sve_like"
ENTRY = 0x200
MACHINES = {
    "plain": "(vec (count 1) (pipelined true) (lanes 2))",
    "far": "(vec (count 1) (pipelined true) (lanes 2) (transport 2))",
    "turns": "(vec (count 1) (pipelined true) (lanes 2) (switch 2))",
}
CORE = """
  (defcore sh_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob 64) (issue-queue 64) (commit-width 8))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 8) (depth 2)) (engine execute)
    (units {unit}))
"""

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

/* Each core has its own program: the hooks' context is the code it runs. */
typedef struct { uint8_t code[4096]; } host;
static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; (void)w; return a * 31u + 7u; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; (void)a; (void)v; (void)w; }
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  host *h = c; *ok = pc + 4 <= sizeof h->code;
  return *ok ? (uint32_t)h->code[pc] | (uint32_t)h->code[pc + 1] << 8 | (uint32_t)h->code[pc + 2] << 16
               | (uint32_t)h->code[pc + 3] << 24 : 0u;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}
static void *make(const axis_sim_pack *S, host *h, const char *core, const uint32_t *words, int32_t count) {
  memset(h, 0, sizeof *h);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) { h->code[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b)); }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, h };
  void *m = S->create(&hooks);
  if (!m || !S->select_core(m, core)) { return NULL; }
  S->reset(m, %(entry)du, "%(isa)s", NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x0101010101010101ull * (uint64_t)(i %% 7 + 1) + (uint64_t)i);
  }
  S->count_cycles(m, 1);
  return m;
}
static uint64_t mark_of(const axis_sim_pack *S, void *m) {
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  return mark;
}
static host HA, HB;
static void go(const char *tag, const char *core, int shared, int swap,
               const uint32_t *wa, int32_t na, const uint32_t *wb, int32_t nb) {
  const axis_sim_pack *S = %(sim)s();
  void *a = make(S, &HA, core, wa, na), *b = make(S, &HB, core, wb, nb);
  if (!a || !b) { printf("%%s NOCORE\n", tag); return; }
  int joined = shared ? S->share_unit(b, a, "vec") : 1;
  /* Which core ticks first each cycle must not decide which is served. */
  void *both[2] = { swap ? b : a, swap ? a : b };
  S->run_cores(both, 2, 100000u);
  printf("%%s joined %%d ca %%llu cb %%llu sa %%llu sb %%llu replays %%llu ma %%llu mb %%llu\n", tag, joined,
         (unsigned long long)S->cycles(a), (unsigned long long)S->cycles(b),
         (unsigned long long)S->steps(a), (unsigned long long)S->steps(b),
         (unsigned long long)(S->replays(a) + S->replays(b)),
         (unsigned long long)mark_of(S, a), (unsigned long long)mark_of(S, b));
  S->destroy(a); S->destroy(b);
}

/* A core of TWO CONTEXTS and a second core, with the unit shared between the
   two cores or not. The share is asked through one context and is the
   core's. */
static host HC;
static void group(const char *tag, const char *core, int shared,
                  const uint32_t *wx, int32_t nx, const uint32_t *wy, int32_t ny) {
  const axis_sim_pack *S = %(sim)s();
  void *p = make(S, &HA, core, wx, nx), *q = make(S, &HB, core, wx, nx), *y = make(S, &HC, core, wy, ny);
  if (!p || !q || !y) { printf("%%s NOCORE\n", tag); return; }
  int joined = S->share_core(q, p) && (shared ? S->share_unit(y, q, "vec") : 1);
  void *all[3] = { p, q, y };
  while (S->cycle_cores(all, 3, 1) > 0) {}
  printf("%%s joined %%d cp %%llu cq %%llu cy %%llu sp %%llu sq %%llu sy %%llu replays %%llu\n", tag, joined,
         (unsigned long long)S->cycles(p), (unsigned long long)S->cycles(q), (unsigned long long)S->cycles(y),
         (unsigned long long)S->steps(p), (unsigned long long)S->steps(q), (unsigned long long)S->steps(y),
         (unsigned long long)(S->replays(p) + S->replays(q) + S->replays(y)));
  S->destroy(p); S->destroy(q); S->destroy(y);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (S->abi_version < 8u || !S->share_unit) { printf("NOABI\n"); return 0; }
%(programs)s
%(runs)s
  /* What it refuses. */
  {
    void *a = make(S, &HA, "sh_plain", IDLE, 0), *b = make(S, &HB, "sh_turns", IDLE, 0);
    void *c = make(S, &HB, "sh_plain", IDLE, 0);
    printf("REFUSE differ %%d unknown %%d", S->share_unit(b, a, "vec"), S->share_unit(c, a, "nope"));
    S->step(a);
    printf(" started %%d ok %%d\n", S->share_unit(c, a, "vec"), 0);
    S->destroy(a); S->destroy(b); S->destroy(c);
  }
  {
    /* Two contexts of one core already have one unit between them; and a
       core is shared before its units are. */
    void *p = make(S, &HA, "sh_plain", IDLE, 0), *q = make(S, &HB, "sh_plain", IDLE, 0);
    void *a = make(S, &HC, "sh_plain", IDLE, 0), *b = make(S, &HA, "sh_plain", IDLE, 0);
    int ctx = S->share_core(q, p);
    int same = S->share_unit(q, p, "vec");
    int unit = S->share_unit(b, a, "vec");
    printf("GREFUSE ctx %%d same %%d unit %%d coreafter %%d\n", ctx, same, unit, S->share_core(b, p));
    S->destroy(p); S->destroy(q); S->destroy(a); S->destroy(b);
  }
  return 0;
}
"""


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text().replace("(latency ", "(unit vec) (latency ")
    cores = "".join(CORE.format(name=name, isa=ISA, unit=unit) for name, unit in MACHINES.items())
    end = source.rstrip().rfind(")")
    corpus = work / "sh.axisl"
    corpus.write_text(source[:end] + cores + ")\n")

    def run_cmd(cmd):
        return subprocess.run(cmd, capture_output=True, text=True, check=True, cwd=AXIS_ROOT)

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "sh_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("sh_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    fixture = {test["mnemonic"]: int(test["encoded"], 16) for test in tests}
    name = "SVADD_S__l0"
    if name not in fixture:
        sys.modules.pop("sh_lift", None)
        print("  shared unit: DECLINED no 32-bit lane add")
        return 0, 0

    def add(dest, a, b):
        word = fixture[name]
        for operand, value in (("zd", dest), ("zn", a), ("zm", b)):
            word = lift.place_operand(word, by_mnemonic[name], operand, value)
        return word

    sys.modules.pop("sh_lift", None)
    programs = {"IDLE": []}
    for half in (1, 2):
        programs[f"INDEP{half}"] = [add(8 + i % 20, 1, 2) for i in range(12 * half)]
        programs[f"CHAIN{half}"] = [add(8, 8, 1) for _ in range(12 * half)]
    # (label, core, shared, program of A, program of B)
    plan = []
    for half in (1, 2):
        plan += [(f"PRIVATE{half}", "plain", 0, f"INDEP{half}", f"INDEP{half}"),
                 (f"SHARED{half}", "plain", 1, f"INDEP{half}", f"INDEP{half}"),
                 (f"ALONE{half}", "plain", 1, f"INDEP{half}", "IDLE"),
                 (f"TURNS{half}", "turns", 1, f"INDEP{half}", f"INDEP{half}"),
                 (f"TURNSALONE{half}", "turns", 1, f"INDEP{half}", "IDLE"),
                 (f"FARINDEP{half}", "far", 1, f"INDEP{half}", "IDLE"),
                 (f"FARCHAIN{half}", "far", 1, f"CHAIN{half}", "IDLE"),
                 (f"NEARCHAIN{half}", "far", 0, f"CHAIN{half}", "IDLE")]
    runs = [f'  go("{label}_{order}", "sh_{core}", {shared}, {int(order == "BA")}, '
            f'{pa}, {len(programs[pa])}, {pb}, {len(programs[pb])});'
            for label, core, shared, pa, pb in plan for order in ("AB", "BA")]
    for half in (1, 2):
        for label, shared in (("GPRIVATE", 0), ("GSHARED", 1)):
            runs.append(f'  group("{label}{half}", "sh_plain", {shared}, INDEP{half}, '
                        f'{len(programs[f"INDEP{half}"])}, INDEP{half}, '
                        f'{len(programs[f"INDEP{half}"])});')
    body = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "isa": ISA,
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in ws + [0])} }};"
            for label, ws in programs.items()),
        "runs": "\n".join(runs),
    }
    root = work / "packs" / manifest["name"]
    (work / "sh.c").write_text(body)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "sh"),
             str(work / "sh.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / "sh")], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL shared unit: the harness exited {done.returncode}")
        return 0, 1
    said, refuse, grefuse = {}, None, None
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 17 and parts[1] == "joined":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
        elif parts and parts[0] == "REFUSE":
            refuse = dict(zip(parts[1::2], map(int, parts[2::2])))
        elif parts and parts[0] == "GREFUSE":
            grefuse = dict(zip(parts[1::2], map(int, parts[2::2])))
        elif parts and parts[0] == "NOABI":
            print("  FAIL shared unit: the simulator pack has no `share_unit` (ABI < 8)")
            return 0, 1
    if "--dump" in sys.argv:
        print("   ", refuse, grefuse)
        for key in sorted(said):
            print("   ", key, said[key])

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL shared unit: {message}")
        failures += 1

    alone = {}
    for label, core, shared, pa, pb in plan:
        for order in ("AB", "BA"):
            row = said.get(f"{label}_{order}")
            checks += 1
            if row is None:
                fail(f"{label} reported nothing")
                return checks, failures
            checks += 1
            if not row["joined"] or row["replays"] or row["sa"] != len(programs[pa]) \
                    or row["sb"] != len(programs[pb]):
                fail(f"{label} ({order}): joined {row['joined']}, {row['replays']} replay(s), "
                     f"{row['sa']} and {row['sb']} instructions of {len(programs[pa])} and "
                     f"{len(programs[pb])}")
            # A core's registers are its program's, whoever it shares a unit with.
            checks += 1
            if alone.setdefault((core[:0], pa), row["ma"]) != row["ma"]:
                fail(f"{label} ({order}): core A's registers differ from another run of the "
                     f"same program; sharing a unit changes when, never what")
    if failures:
        return checks, failures

    def more(label, core, order="AB"):
        return (said[f"{label}2_{order}"][f"c{core}"] - said[f"{label}1_{order}"][f"c{core}"])

    expect = [("PRIVATE", "a", 12, "its own unit, one add a cycle"),
              ("PRIVATE", "b", 12, "its own unit, one add a cycle"),
              ("SHARED", "a", 24, "one unit between two busy cores, turn about"),
              ("SHARED", "b", 24, "one unit between two busy cores, turn about"),
              ("ALONE", "a", 12, "the whole shared unit, the other core idle"),
              ("FARINDEP", "a", 12, "transport delays a result, not the unit"),
              ("NEARCHAIN", "a", 12, "a chain on its own unit, one a cycle"),
              ("FARCHAIN", "a", 36, "a chain through a unit two cycles away: three a link")]
    for label, core, cycles, why in expect:
        for order in ("AB", "BA"):
            checks += 1
            if more(label, core, order) != cycles:
                fail(f"12 more adds on core {core.upper()} of {label} ({order}) cost "
                     f"{more(label, core, order)} cycles; {cycles} -- {why}")
    # ⚠️ A TURN is switch + 1 = 3 operations and a change of owner 2 cycles: six
    # operations in ten cycles between the two cores, so the 24 more
    # operations of the longer programs are four such rounds.
    for order in ("AB", "BA"):
        last = lambda half: max(said[f"TURNS{half}_{order}"]["ca"],  # noqa: E731
                                said[f"TURNS{half}_{order}"]["cb"])
        checks += 1
        if last(2) - last(1) != 40:
            fail(f"24 more adds between two cores taking turns of three with a switch cost of "
                 f"two ({order}) cost {last(2) - last(1)} cycles; four rounds of ten, 40")
    # ⚠️ And a core ALONE on a unit with a switch cost never pays it: nobody
    # else was served, so there is no owner to change from. Cycle for cycle
    # what the unit with no such cost takes -- the first use is not a switch.
    for half in (1, 2):
        checks += 1
        if said[f"TURNSALONE{half}_AB"]["ca"] != said[f"ALONE{half}_AB"]["ca"]:
            fail(f"a core alone on a shared unit with a switch cost took "
                 f"{said[f'TURNSALONE{half}_AB']['ca']} cycles and {said[f'ALONE{half}_AB']['ca']} "
                 f"on one without; with one core there is no owner to change from")
    # ⚠️ A CORE OF TWO CONTEXTS is one party. Sharing the unit with a second
    # core, that core gets half of it -- as it would from any one core -- and
    # the two contexts split the other half. A unit that took each context
    # for a core would give the second core a third.
    for label in ("GPRIVATE", "GSHARED"):
        for half in (1, 2):
            row = said.get(f"{label}{half}")
            checks += 1
            if not row or not row["joined"] or row["replays"] or len(
                    {row["sp"], row["sq"], row["sy"], 12 * half}) != 1:
                fail(f"{label}{half}: {row}")
                return checks, failures
    group_more = lambda label, who: said[f"{label}2"][who] - said[f"{label}1"][who]  # noqa: E731
    # The second core's figure is the one that says who the parties are: it is
    # busy only while the other core is. The contexts' own figures are not
    # held one by one -- how a core's contexts split what the core gets is
    # the core's arbitration, not the share's -- but the LATER of them is:
    # the unit does one add a cycle for as long as anyone wants one, so the
    # last add of all lands when every add has been done.
    for label, who, cycles, why in (
            ("GPRIVATE", "cy", 12, "a core with its own unit"),
            ("GSHARED", "cy", 24, "half the unit: the other core is one party, not two")):
        checks += 1
        if group_more(label, who) != cycles:
            fail(f"12 more adds cost {group_more(label, who)} cycles ({who}) in {label}; "
                 f"{cycles} -- {why}")
    for label, cycles, why in (
            ("GPRIVATE", 24, "24 more adds on the contexts' own unit"),
            ("GSHARED", 36, "36 more adds, all three programs', on the one unit")):
        last = max(group_more(label, "cp"), group_more(label, "cq"))
        checks += 1
        if last != cycles:
            fail(f"the later context finished {last} cycles later in {label}; {cycles} -- "
                 f"{why}, one a cycle with none idle")
    checks += 1
    if grefuse != {"ctx": 1, "same": 0, "unit": 1, "coreafter": 0}:
        fail(f"sharing among contexts answered {grefuse}; two contexts of one core cannot "
             f"share a unit they already share, and a core is shared before its units")
    checks += 1
    if refuse != {"differ": 0, "unknown": 0, "started": 0, "ok": 0}:
        fail(f"share_unit answered {refuse} to cores whose units differ, a unit neither has, "
             f"and a machine that has started; 0 to each")
    if not failures:
        print(f"  shared unit: 12 more adds cost {more('PRIVATE', 'a')} private, "
              f"{more('SHARED', 'a')} shared by two busy cores, {more('ALONE', 'a')} shared with "
              f"an idle one; a chain {more('NEARCHAIN', 'a')} near and {more('FARCHAIN', 'a')} two "
              f"cycles away; turns of three with a switch of two, 24 adds in 40; {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dump", action="store_true")
    parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL shared unit: {said[:500]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("one unit, several cores: SKIP")
        return DECLINED
    print(f"one unit, several cores: {'FAIL' if failures else 'PASS'} ({checks} checks, "
          f"{failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
