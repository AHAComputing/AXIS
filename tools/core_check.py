#!/usr/bin/env python3
"""A machine is not its instruction set, and the cost model has to know. Gate.

AXIS describes VLIW packets, unit-typed slots and multi-core fabrics, and until
this landed the only thing that produced a NUMBER issued one instruction at a
time. A four-wide machine with three adders reported the same cycle count as a
scalar one, which makes the language's headline capability invisible to the
one consumer that is supposed to answer "is this worth it".

So `defcore` grew a pipeline: `(issue-width N)` and `(units (alu (count 4)
(pipelined true)) ...)`. The ISA's half of the linkage already existed --
instructions have named their `unit` all along -- and the lift table carried it
to Python and not to C, which is why nothing could contend for anything.

⚠️ THE ANCHOR, and the reason this gate is trustworthy at all: a core of one
issue slot with one pipelined copy of every unit must reproduce the first-order
model cycle for cycle, on the same programs. A second timing model that agreed
with nothing would be a second thing to be wrong, and the way to stop that is
to make the old model a configuration of the new one and check it.

The rest are properties, not a second copy of the arithmetic:

  * **width is width**: N independent instructions on a W-wide machine with W
    copies of their unit take about N/W cycles;
  * **a unit is a RESOURCE**: the same N instructions on the same W-wide
    machine with ONE copy of that unit serialize completely. This is the
    distinction no declared throughput can express, and the only reason units
    are in the language;
  * **a chain is latency-bound**: widening a machine does not speed up
    instructions that wait for each other, so `wide` and `narrow` agree
    exactly on a dependent chain;
  * **a typo is refused**: selecting a core the description does not declare
    returns 0 and leaves the machine on the model it had, rather than
    silently reporting a plausible number for a machine nobody asked for.

Usage: tools/core_check.py [corpus.axisl ...]
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
RUN = 8

HARNESS = r"""
/* One program, run on each machine the description declares. */
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

/* `core` of NULL selects nothing, which is the first-order model. */
static void go(const axis_sim_pack *S, const char *tag, const char *core,
               const uint32_t *words, int32_t count) {
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(code)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  S->reset(m, %(code)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  }
  int32_t took = core ? S->select_core(m, core) : 1;
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)count);
  printf("%%s cycles %%llu steps %%llu selected %%d\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m), took);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->core_count) { printf("NOCORES\n"); return 0; }
  printf("CORES %%d\n", S->core_count());
  static const uint32_t SPREAD[] = { %(spread)s };
  static const uint32_t SLOW[] = { %(slow)s };
  static const uint32_t CHAIN[] = { %(chain)s };
  const int32_t n = (int32_t)(sizeof SPREAD / sizeof SPREAD[0]);
%(runs)s
  /* A name the description does not declare. */
  go(S, "TYPO", "no-such-core", SPREAD, n);
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def build_programs(lift, tests, isa, units_of, latency_of):
    """An independent stream and a dependent chain, from the corpus's own
    fixtures. The two differ only in register numbers."""
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    picked = {}
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None or entry.get("effects") or entry.get("ends_block"):
            continue
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        ins = [o for o in entry["operands"]
               if o["role"] == "in" and o["kind"] != "imm"]
        # ⚠️ The unit comes from `emit-json`, which publishes what the
        # DESCRIPTION declared. The lift table's own `unit` is derived from a
        # VLIW packet's slots, so a corpus with no packet reports none and a
        # gate that trusted it would decline on exactly the descriptions this
        # form exists for.
        unit = units_of.get(test["mnemonic"]) or ""
        if len(outs) != 1 or not ins or not unit:
            continue
        picked.setdefault(unit, (test, entry, outs[0], ins))

    def emit(chosen, dest_index, source_index):
        test, entry, dest, sources = chosen
        built = int(test["encoded"], 16)
        built = lift.place_operand(built, entry, dest["name"], dest_index)
        for operand in sources:
            built = lift.place_operand(built, entry, operand["name"], source_index)
        return built

    # The stream uses the unit with the most copies to vary across cores; the
    # chain uses whichever instruction has a latency above one, so that the
    # dependence has something to cost.
    if not picked:
        raise ValueError("no unit-bound instruction")
    # ⚠️ Latency from `emit-json`, not from the lift row. The row HAS a
    # `latency` key and its value is None, so `.get("latency", 1)` returns
    # None rather than the default -- and `max` over Nones quietly returns
    # whichever came first. The chain was being built from a latency-1
    # instruction, which is a weaker test that still passed.
    def cost(row):
        return latency_of.get(row[0]["mnemonic"], 1) or 1

    stream = min(picked.values(), key=cost)
    chain_row = max(picked.values(), key=cost)
    spread = [emit(stream, 3 + i, 20 + i) for i in range(RUN)]
    chain = [emit(chain_row, 3, 3) for _ in range(RUN)]
    slow = [emit(chain_row, 3 + i, 20 + i) for i in range(RUN)]
    return (spread, slow, chain, stream[0]["mnemonic"],
            chain_row[0]["mnemonic"], cost(chain_row))


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    # ⚠️ The pack is named by the MODULE, not the file. `issue_width.axisl`
    # builds `issuewidth`, and a gate that composed the path from the stem
    # looked for a library that was never going to be there.
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    # ⚠️ IN-ORDER CORES ONLY. Every formula in this gate -- ceil(N/width), a
    # chain at latency x (N-1) + 1 -- describes the in-order scoreboard, and a
    # core that declares a window runs a different algorithm that reports a
    # different quantity. Applying this arithmetic to one is measuring the
    # right thing on the wrong machine; `ooo_check.py` holds those.
    # ⚠️ And only cores this library is ALLOWED to be. A core naming an
    # external model is refused by `select_core` on purpose, so measuring it
    # here would time whatever the machine fell back to -- which is the
    # plausible wrong answer that refusal exists to prevent, arriving through
    # a gate instead.
    # ⚠️ The same goes for a core whose PREDICTOR is somebody else's (a
    # namespaced name, O8): it is refused until a host registers one, and a
    # gate that measured it anyway timed the machine with no core at all.
    # ⚠️ And only cores WITHOUT a front end: this arithmetic has instructions
    # arriving the moment they are stepped. A declared front end adds its
    # depth -- exactly two cycles on `ifetch` and `iexec`, which agree with
    # each other -- and frontend_check.py holds that.
    in_order = [core for core in facts.get("cores", [])
                if not core.get("rob") and not core.get("model")
                and "." not in (core.get("predictor") or "")
                and not core.get("front_end")]
    cores = [core["name"] for core in in_order]
    if not cores:
        print(f"  {name}: DECLINED the description declares no core")
        return 0, 0
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"co_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"co_{name}")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    isa = tests[0].get("isa") or "" if tests else ""
    try:
        units_of = {entry["mnemonic"]: entry.get("unit")
                    for entry in facts["instructions"]}
        latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                      for entry in facts["instructions"]}
        (spread, slow, chain, stream_mn, chain_mn,
         chain_latency) = build_programs(lift, tests, isa, units_of, latency_of)
    except ValueError:
        print(f"  {name}: DECLINED no unit-bound instruction to build a "
              f"program from")
        sys.modules.pop(f"co_{name}", None)
        return 0, 0
    sys.modules.pop(f"co_{name}", None)

    runs = ['  go(S, "BASE", NULL, SPREAD, n);',
            '  go(S, "BASESLOW", NULL, SLOW, n);',
            '  go(S, "BASECHAIN", NULL, CHAIN, n);']
    for core in cores:
        runs.append(f'  go(S, "S_{core}", "{core}", SPREAD, n);')
        runs.append(f'  go(S, "M_{core}", "{core}", SLOW, n);')
        runs.append(f'  go(S, "C_{core}", "{core}", CHAIN, n);')

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "code": CODE,
        "isa": f'"{isa}"' if isa else "NULL",
        "spread": ", ".join(f"{w}u" for w in spread),
        "slow": ", ".join(f"{w}u" for w in slow),
        "chain": ", ".join(f"{w}u" for w in chain),
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
    if "NOCORES" in done.stdout:
        print(f"  FAIL {name}: the simulator library exposes no cores")
        return 0, 1

    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 7 and parts[1] == "cycles":
            said[parts[0]] = (int(parts[2]), int(parts[4]), int(parts[6]))

    checks = failures = 0

    def cycles(tag):
        return said.get(tag, (None, None, None))[0]

    # Every run has to have RUN. A sweep over machines that all halted
    # immediately agrees with itself perfectly.
    for tag, row in said.items():
        checks += 1
        if tag != "TYPO" and row[1] != RUN:
            print(f"  FAIL {name}: {tag} ran {row[1]} instruction(s) of {RUN}")
            failures += 1

    # ⚠️ A SELECTED core is a PIPELINE, and a pipeline reports when the last
    # instruction RETIRES. The machine with no core selected is a different
    # and cruder model that reports when an issue slot frees, about a latency
    # earlier. Those two numbers were compared for exact equality here until
    # the in-order path became a pipeline, and the comparison was never
    # meaningful -- it happened to hold because both models were the same
    # arithmetic. The cross-model anchor is gone on purpose; what anchors the
    # pipeline now is that in-order issue is one line of it, which
    # `ooo_check.py` holds by running a chain on both and requiring equality.
    checks += 1
    if cycles("BASE") is None or cycles("BASECHAIN") is None:
        print(f"  FAIL {name}: the un-selected runs reported nothing")
        failures += 1

    # A name nobody declared is refused, and changes nothing.
    checks += 1
    typo = said.get("TYPO")
    if not typo or typo[2] != 0:
        print(f"  FAIL {name}: selecting an undeclared core returned "
              f"{typo[2] if typo else '?'}, not 0")
        failures += 1
    checks += 1
    if typo and typo[0] != cycles("BASE"):
        print(f"  FAIL {name}: a refused core still changed the model "
              f"({typo[0]} cycles vs {cycles('BASE')})")
        failures += 1

    # Width, unit copies and pipelining, against each other.
    unit_of = {entry["mnemonic"]: entry.get("unit")
               for entry in facts["instructions"]}
    cost_of = {entry["mnemonic"]: entry.get("latency_cycles", 1) or 1
               for entry in facts["instructions"]}
    for core in in_order:
        width = core.get("issue_width", 1) or 1
        units = {unit["name"]: unit for unit in core.get("units", [])}
        for tag, mnemonic in (("S", stream_mn), ("M", chain_mn)):
            got = cycles(f"{tag}_{core['name']}")
            if got is None:
                continue
            unit = units.get(unit_of.get(mnemonic) or "", {})
            copies = unit.get("count", 1) or 1
            latency = cost_of.get(mnemonic, 1)
            # Throughput is 1.0 throughout this corpus, so an unpipelined
            # unit's occupancy is its latency and a pipelined one's is a cycle.
            busy = 1 if unit.get("pipelined", True) else latency
            # ⚠️ FOUR things bound an independent stream in a pipeline, and the
            # model has to honour all of them: how many may BEGIN in a cycle,
            # how many copies of the unit there are and how long each stays
            # busy, how long the work itself takes, and how fast the machine
            # can RETIRE. Instruction i issues no earlier than floor(i/W) and
            # no earlier than floor(i/C) x busy; it finishes a latency later;
            # and nothing retires faster than the commit width, which defaults
            # to the issue width.
            last_issue = max((RUN - 1) // width, (RUN - 1) // copies * busy)
            want = max(last_issue + latency, -(-RUN // width) - 1) + 1
            checks += 1
            if got != want:
                print(f"  FAIL {name}: {RUN} independent {mnemonic} "
                      f"(latency {latency}) on core `{core['name']}` "
                      f"(width {width}, {copies} x "
                      f"{unit_of.get(mnemonic)}, "
                      f"{'pipelined' if unit.get('pipelined', True) else 'unpipelined'}) "
                      f"took {got} cycles, not {want}")
                failures += 1

    # ⚠️ A chain is latency-bound: no width helps it.
    chain_cycles = {core["name"]: cycles(f"C_{core['name']}")
                    for core in in_order}
    checks += 1
    distinct = {value for value in chain_cycles.values() if value is not None}
    if len(distinct) > 1:
        print(f"  FAIL {name}: a dependent chain of {chain_mn} took "
              f"{chain_cycles} on machines that differ only in width and "
              f"units; nothing there can issue in parallel")
        failures += 1
    # ⚠️ A chain of N at latency L retires at N x L: each instruction issues
    # when the one before it finishes, and the last finishes a latency after
    # it started. The in-order model reported L x (N-1) + 1 because it
    # measured issue slots rather than retirement.
    checks += 1
    want_chain = chain_latency * RUN + 1
    if distinct and distinct != {want_chain}:
        print(f"  FAIL {name}: {RUN} chained {chain_mn} at latency "
              f"{chain_latency} should take {want_chain} cycles, took "
              f"{distinct}")
        failures += 1

    if not failures:
        shape = " ".join(f"{core['name']}:{cycles('S_' + core['name'])}"
                         for core in in_order)
        print(f"  {name}: {RUN} independent {stream_mn} -- {shape}; a chain of "
              f"{chain_mn} costs {want_chain} on every one, {checks} checks")
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
        print("a machine is not its instruction set: SKIP")
        return DECLINED
    print(f"a machine is not its instruction set: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
