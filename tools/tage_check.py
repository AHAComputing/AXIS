#!/usr/bin/env python3
"""A predictor is a component: the built-in ones learn what their history can
see, and one this library never heard of plugs in by name. Gate.

`(branch (predictor NAME) (key value) ...)` names a direction predictor
(docs/ooo_design.md, O8). The built-ins -- bimodal, gshare, tage -- implement
the same C interface a host's does, and a namespaced name is somebody else's:
its numbers carried verbatim, the core refused until a host registers it.

A loop whose inner branch is taken seven times and not the eighth, and one
whose inner branch alternates:

  * **TAGE learns the long pattern**: its mispredicts are the SAME at both trip
    counts. Seeing which of the eight this is takes seven outcomes of that
    branch -- fourteen of global history, the loop's own branch between each;
  * **a short history cannot**: bimodal and a four-bit gshare pay once a
    period, forever -- their mispredicts grow by the extra periods, exactly;
  * **past its history, TAGE is no worse than a counter per address**: on a
    period-20 branch no table sees whole, every context sees both outcomes,
    and only training keeps the rare one from owning the entry;
  * **TAGE learns the short pattern too**: the alternation costs it a
    constant, the case its short tables exist for;
  * **an external predictor plugs in by name**: the core naming it is refused
    before registration and selects after; registering answers how many cores
    asked (one), a name nobody asked for answers zero, and `core_predictor`
    says what a refused host would have to supply;
  * **the external predictor is the one predicting**: a stand-in that always
    says "taken" is asked about every branch exactly once, told every outcome
    exactly once, and mispredicts exactly the not-taken outcomes;
  * **the architecture is untouched**.

Usage: tools/tage_check.py [corpus.axisl ...]
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
TRIPS = (80, 160)
PERIOD = 8
#: A period longer than the longest history can see: 20 iterations is 40
#: outcomes of global history, and the longest table holds 32.
LONG_PERIOD = 20
MINUS_ONE, COUNTER, PHASE, EIGHT, FLIP, ONE, TWENTY = 7, 9, 10, 11, 12, 15, 16

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

/* A stand-in for somebody else's predictor: always "taken", and it counts
   what it is asked and told, so the gate can say who was predicting. */
static uint64_t ASKED, TOLD, TOLD_NOT_TAKEN, BIAS;
static void *standin_create(const axis_sim_core *core) {
  ASKED = TOLD = TOLD_NOT_TAKEN = 0;
  BIAS = axis_sim_param_of(core, "acme.bias", 99u);
  return &ASKED;
}
static void standin_destroy(void *state) { (void)state; }
static int32_t standin_predict(void *state, uint64_t pc) { (void)state; (void)pc; ASKED++; return 1; }
static void standin_update(void *state, uint64_t pc, int32_t taken) {
  (void)state; (void)pc; TOLD++; if (!taken) { TOLD_NOT_TAKEN++; }
}
static const axis_sim_predictor STANDIN = {
  1u, "%(external)s", standin_create, standin_destroy, standin_predict, standin_update
};
static const axis_sim_predictor NOBODY = {
  1u, "acme.nobody-asked", standin_create, standin_destroy, standin_predict, standin_update
};

static int32_t go(const char *tag, const char *core, const uint32_t *words, int32_t count,
                  uint32_t trips) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return 0; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return 0; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0); }
  S->set_reg(m, %(minus)d, 0xFFFFFFFFull);
  S->set_reg(m, %(counter)d, trips);
  S->set_reg(m, %(phase)d, %(period)du);
  S->set_reg(m, %(eight)d, %(period)du);
  S->set_reg(m, %(flip)d, 1u);
  S->set_reg(m, %(one)d, 1u);
  S->set_reg(m, %(twenty)d, %(long_period)du);
  if (!strncmp(tag, "LONG", 4)) { S->set_reg(m, %(phase)d, %(long_period)du); }
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)(trips * (uint32_t)count + 8u));
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  printf("%%s cycles %%llu steps %%llu miss %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)S->mispredicts(m), (unsigned long long)mark);
  S->destroy(m);
  return 1;
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->register_predictor || !S->core_predictor) { printf("NOPREDICTORS\n"); return 0; }
%(programs)s
  for (int32_t i = 0; i < S->core_count(); ++i) {
    if (!strcmp(S->core_name(i), "%(outsourced)s")) {
      printf("ASKS %%s\n", S->core_predictor(i) ? S->core_predictor(i) : "-");
    }
  }
  /* Refused before registration, and the machine left alone. */
  {
    axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
    void *m = S->create(&hooks);
    printf("BEFORE %%d\n", S->select_core(m, "%(outsourced)s"));
    S->destroy(m);
  }
  printf("NOBODY %%d\n", S->register_predictor(&NOBODY));
  printf("REGISTERED %%d\n", S->register_predictor(&STANDIN));
%(runs)s
  printf("STANDIN asked %%llu told %%llu not_taken %%llu bias %%llu\n",
         (unsigned long long)ASKED, (unsigned long long)TOLD,
         (unsigned long long)TOLD_NOT_TAKEN, (unsigned long long)BIAS);
  return 0;
}
"""


def build_programs(asm: Assembler, bnz):
    add = asm.fast_add
    # ⚠️ PERIOD EIGHT: the phase counts down from eight; the inner branch is
    # taken while it is not zero and falls through to reset it when it is.
    def periodic(length_reg):
        return [asm.op(add, PHASE, PHASE, MINUS_ONE), bnz(PHASE, 0, 8),
                asm.op(add, PHASE, 0, length_reg),
                asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -16),
                asm.op(add, 13, 1, 1)]
    period = periodic(EIGHT)
    # ⚠️ PAST THE HISTORY: a period-20 branch, which no table can see whole.
    # Every table's context then sees both outcomes, and only TRAINING turns a
    # counter allocated on the rare outcome back to the common one. On a
    # pattern the history covers, allocation sets each new counter the right
    # way and training is never needed -- which is why a TAGE whose counters
    # never trained passed every other program here.
    long = periodic(TWENTY)
    # ALTERNATING: flip a register between 1 and -1 and branch on it.
    alternating = [asm.op(asm.slow, FLIP, FLIP, MINUS_ONE), bnz(FLIP, ONE, 8),
                   asm.op(add, 14, 14, 1), asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                   bnz(COUNTER, 0, -16), asm.op(add, 13, 1, 1)]
    return {"PERIOD": period, "ALT": alternating, "LONG": long}


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])

    def machine(core):
        return {k: core.get(k) for k in ("issue_width", "units", "rob", "branch_penalty",
                                         "predictor_entries", "lsq", "front_end")}

    tage = next((c for c in cores if c.get("predictor") == "tage"), None)
    external = next((c for c in cores if "." in (c.get("predictor") or "")), None)
    machines = {"TAGE": tage}
    if tage:
        machines["GSHARE"] = next((c for c in cores if c.get("predictor") == "gshare"
                                   and machine(c) == machine(tage)
                                   and c.get("predictor_history", 0) * 2 < PERIOD * 2), None)
        machines["BIMODAL"] = next((c for c in cores if c.get("predictor") == "bimodal"
                                    and machine({**c, "predictor_entries": tage["predictor_entries"]})
                                    == machine(tage)), None)
        machines["EXTERNAL"] = external
    missing = [tag for tag, core in machines.items() if core is None]
    if missing:
        print(f"  {name}: DECLINED no {', '.join(missing)} core")
        return 0, 0

    module = f"tage_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.fast_add is None or bnz is None or asm.slow is None:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED no add, multiply or two-register branch")
        return 0, 0
    programs = build_programs(asm, bnz)
    kind = next(o["kind"] for o in asm.by_mnemonic[asm.fast_add]["operands"]
                if o["role"] in ("out", "inout"))
    slot = lambda i: lift.register_slot(kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == asm.fast_add), "") or ""
    sys.modules.pop(module, None)

    runs = [f'  go("{program}_{tag}_{trips}", "{core["name"]}", {program}, '
            f'(int32_t)(sizeof {program} / sizeof {program}[0]), {trips}u);'
            for program in programs for tag, core in machines.items() if tag != "EXTERNAL"
            for trips in TRIPS]
    # The external predictor runs once, on the long pattern, after registering.
    runs.append(f'  go("PERIOD_EXTERNAL_{TRIPS[0]}", "{external["name"]}", PERIOD, '
                f'(int32_t)(sizeof PERIOD / sizeof PERIOD[0]), {TRIPS[0]}u);')
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY,
        "minus": slot(MINUS_ONE), "counter": slot(COUNTER), "phase": slot(PHASE),
        "eight": slot(EIGHT), "flip": slot(FLIP), "one": slot(ONE), "period": PERIOD,
        "twenty": slot(TWENTY), "long_period": LONG_PERIOD,
        "isa": f'"{isa}"' if isa else "NULL",
        "external": external["predictor"], "outsourced": external["name"],
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
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}")
        return 0, 1
    said, lines = {}, {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 9 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
        elif parts:
            lines[parts[0]] = parts[1:]
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])
        for key, value in lines.items():
            print("   ", key, value)

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    low, high = TRIPS
    for program in programs:
        for trips in TRIPS:
            rows = [said.get(f"{program}_{tag}_{trips}") for tag in ("TAGE", "GSHARE", "BIMODAL")]
            checks += 1
            if any(row is None for row in rows):
                fail(f"{program} at {trips} trips reported nothing on some machine")
            elif len({(row["steps"], row["mark"]) for row in rows}) != 1:
                fail(f"{program} at {trips} trips retired different instructions or left "
                     f"different registers on different predictors")
    if failures:
        return checks, failures

    def miss(program, tag, trips):
        return said[f"{program}_{tag}_{trips}"]["miss"]

    periods = (high - low) // PERIOD
    # ⚠️ TAGE LEARNS THE LONG PATTERN; a short history pays once a period.
    checks += 1
    if miss("PERIOD", "TAGE", high) != miss("PERIOD", "TAGE", low):
        fail(f"TAGE mispredicted {miss('PERIOD', 'TAGE', low)} and "
             f"{miss('PERIOD', 'TAGE', high)} times on a period-{PERIOD} branch at {low} and "
             f"{high} trips; with a {tage['predictor_history']}-outcome history it can see "
             f"which of the {PERIOD} this is, so what it pays must stop growing")
    for tag in ("GSHARE", "BIMODAL"):
        checks += 1
        grew = miss("PERIOD", tag, high) - miss("PERIOD", tag, low)
        if grew != periods:
            fail(f"{machines[tag]['name']} mispredicted {grew} more times over {high - low} "
                 f"more trips of a period-{PERIOD} branch; it cannot see the period, so it pays "
                 f"exactly once a period -- {periods}")
    # ⚠️ TAGE LEARNS THE SHORT PATTERN TOO.
    checks += 1
    if miss("ALT", "TAGE", high) != miss("ALT", "TAGE", low):
        fail(f"TAGE mispredicted {miss('ALT', 'TAGE', low)} and {miss('ALT', 'TAGE', high)} "
             f"times on an alternating branch; its short tables see that pattern")
    # ⚠️ PAST ITS HISTORY, TAGE IS NO WORSE THAN A COUNTER PER ADDRESS.
    checks += 1
    tage_grew = miss("LONG", "TAGE", high) - miss("LONG", "TAGE", low)
    bimodal_grew = miss("LONG", "BIMODAL", high) - miss("LONG", "BIMODAL", low)
    if tage_grew > bimodal_grew:
        fail(f"on a period-{LONG_PERIOD} branch, longer than its {tage['predictor_history']}-"
             f"outcome history, TAGE's mispredicts grew by {tage_grew} and bimodal's by "
             f"{bimodal_grew}; a context that sees both outcomes has to be trained back to the "
             f"common one, or TAGE is worse than no history at all")
    # ⚠️ AN EXTERNAL PREDICTOR PLUGS IN BY NAME.
    checks += 1
    if lines.get("ASKS") != [external["predictor"]]:
        fail(f"core_predictor said {lines.get('ASKS')} for `{external['name']}`, which asks "
             f"for {external['predictor']}")
    checks += 1
    if lines.get("BEFORE") != ["0"]:
        fail(f"`{external['name']}` selected before {external['predictor']} was registered; "
             f"a predictor nobody has must refuse the core, not be replaced by another")
    checks += 1
    if lines.get("NOBODY") != ["0"] or lines.get("REGISTERED") != ["1"]:
        fail(f"registering a predictor no core names returned {lines.get('NOBODY')} and the "
             f"one a core names {lines.get('REGISTERED')}; they must be 0 and 1")
    ext = said.get(f"PERIOD_EXTERNAL_{low}")
    stand = lines.get("STANDIN", [])
    checks += 1
    if ext is None or len(stand) != 8:
        fail(f"`{external['name']}` did not run after registration")
    else:
        asked, told, not_taken, bias = (int(stand[i]) for i in (1, 3, 5, 7))
        branches = 2 * low
        checks += 1
        if asked != branches or told != branches:
            fail(f"the registered predictor was asked {asked} times and told {told} over "
                 f"{branches} branches; every branch once each, or it is not the one predicting")
        checks += 1
        if ext["miss"] != not_taken:
            fail(f"a predictor that always says taken mispredicted {ext['miss']} times and saw "
                 f"{not_taken} branches not taken; those are the same number")
        checks += 1
        if bias != 1:
            fail(f"the registered predictor read `acme.bias` as {bias}; the core gives it 1")

    if not failures:
        print(f"  {name}: period-{PERIOD} branch over {low}/{high} trips -- TAGE "
              f"{miss('PERIOD', 'TAGE', low)}/{miss('PERIOD', 'TAGE', high)} mispredicts, "
              f"gshare {miss('PERIOD', 'GSHARE', low)}/{miss('PERIOD', 'GSHARE', high)}, bimodal "
              f"{miss('PERIOD', 'BIMODAL', low)}/{miss('PERIOD', 'BIMODAL', high)}; alternating "
              f"TAGE {miss('ALT', 'TAGE', low)}/{miss('ALT', 'TAGE', high)}; an external predictor "
              f"refused, registered, and predicting; {checks} checks")
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
        print("a predictor is a component: SKIP")
        return DECLINED
    print(f"a predictor is a component: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
