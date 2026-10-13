#!/usr/bin/env python3
"""A core's word on latency and unit is the one that is published. Gate.

An instruction's `(latency N)` and `(unit NAME)` are the reference machine's;
a `defcore` may say otherwise with `(timing ...)` (docs/core_timing_design.md,
stage T1). The order of precedence lives in one function, `Core::latency_of`,
and `cargo test` holds that function. This holds what leaves the binary:

  1. **nothing moved.** On every corpus, no core retimes anything: a
     description that predates the clause publishes no `timing` at all, and
     one whose cores only crack instructions into micro-ops publishes those
     cores with nothing retimed;
  2. **what a core says is what comes out.** A core added to
     `issue_width.axisl` retimes one instruction by name, a unit's worth by
     class, and moves one to another unit; the published table is exactly
     those, with the latency of where the moved one went;
  3. **it survives the printer.** `emit-lisp` of that description, read back,
     publishes the same table;
  4. **the simulator charges it** (T2): over one ISA, cores that differ
     only in what they say about time differ in cycles by exactly that on
     every link of a dependent chain, and once on independent work -- in
     order and execution-driven;
  5. **`--core NAME` is the description as that core sees it**: `emit-json`
     carries the core's latencies;
  6. **the floor** (T3): a core that states its cycle is refused a latency
     its instruction's netlist does not fit, and its hardware is planned at
     that cycle with its latencies.

Usage: tools/core_timing_check.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = AXIS_ROOT / "examples"


def axis(command: str, path: Path) -> subprocess.CompletedProcess:
    return subprocess.run([*axis_prefix(), command, str(path)],
                          capture_output=True, text=True, cwd=AXIS_ROOT)


CHAIN_LENGTH = 8
CODE = 0x200

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
  (void)c; for (uint32_t i = 0; i < w / 8; ++i) MEMORY[(a + i) %% IMAGE] = (uint8_t)(v >> (8 * i));
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u;
}
static uint64_t trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}
static void go(const axis_sim_pack *S, const char *core, const char *program,
               const uint32_t *words, int32_t count) {
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i)
    for (uint32_t b = 0; b < 4; ++b) MEMORY[%(code)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
  axis_pack_sim_hooks hooks = { rd, wr, fetch, trap, NULL, NULL };
  void *m = S->create(&hooks);
  S->reset(m, %(code)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  if (!S->select_core(m, core)) { printf("%%s.%%s NOCORE\n", core, program); S->destroy(m); return; }
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)count);
  printf("%%s.%%s %%llu\n", core, program, (unsigned long long)S->cycles(m));
  S->destroy(m);
}
int main(void) {
  const axis_sim_pack *S = %(sim)s();
%(runs)s
  return 0;
}
"""


def simulate(axis_file: Path, work: Path):
    """Cycles for each (core, program), or the reason there are none."""
    import importlib
    import build_pack
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        return "no simulator library was built"
    lift_path = work / f"lift_{name}.py"
    subprocess.run([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(lift_path)],
                   check=True, capture_output=True, cwd=AXIS_ROOT)
    sys.path.insert(0, str(work))
    lift = importlib.import_module(lift_path.stem)
    tests = json.loads(axis("emit-roundtrip-json", axis_file).stdout)["tests"]

    def program(mnemonic: str, chained: bool) -> list[int]:
        test = next(t for t in tests if t["mnemonic"] == mnemonic)
        word, isa = int(test["encoded"], 16), test.get("isa")
        entry = lift.decode(word, isa)
        out = next(o for o in entry["operands"] if o["role"] in ("out", "inout"))
        ins = [o for o in entry["operands"] if o["role"] == "in" and o["kind"] != "imm"]
        words = []
        for i in range(CHAIN_LENGTH):
            built = lift.place_operand(word, entry, out["name"], 3 if chained else 3 + i)
            for operand in ins:
                built = lift.place_operand(built, entry, operand["name"], 3 if chained else 20 + i)
            words.append(built)
        return words, isa

    programs = {"mulchain": program("IWMUL", True), "mulspread": program("IWMUL", False),
                "addchain": program("IWADD", True)}
    isa = next(iter(programs.values()))[1]
    cores = [c["name"] for c in json.loads(axis("emit-uarch-json", axis_file).stdout)["cores"]
             if c["name"].startswith(("t_", "x_"))]
    runs = []
    for core in cores:
        for label, (words, _isa) in programs.items():
            runs.append(f"  {{ static const uint32_t W[] = {{ {', '.join(f'{w}u' for w in words)} }};\n"
                        f"    go(S, \"{core}\", \"{label}\", W, {len(words)}); }}")
    source = HARNESS % {"sim": manifest["libraries"]["sim"]["entry"], "code": CODE,
                        "isa": f'"{isa}"' if isa else "NULL", "runs": "\n".join(runs)}
    root = work / "packs" / name
    (work / "timed.c").write_text(source)
    subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "timed"),
                    str(work / "timed.c"), str(root / "lib" / manifest["libraries"]["sim"]["static"]),
                    str(root / "lib" / manifest["libraries"]["exec"]["static"])],
                   check=True, capture_output=True)
    done = subprocess.run([str(work / "timed")], capture_output=True, text=True)
    said = {}
    for line in done.stdout.splitlines():
        key, value = line.split()
        if value == "NOCORE":
            return f"the simulator has no core `{key.split('.')[0]}`"
        said[key] = int(value)
    return said


def main() -> int:
    failures = []

    # 1. Every corpus, not a chosen few.
    with_cores = 0
    for corpus in sorted(EXAMPLES.glob("*.axisl")):
        result = axis("emit-uarch-json", corpus)
        if result.returncode != 0:
            continue                    # not every example is a whole module
        document = json.loads(result.stdout)
        with_cores += bool(document["cores"])
        # ⚠️ RETIMED, not merely timed. A core that cracks an instruction into
        # micro-ops (docs/micro_ops_design.md) says so in `(timing ...)` and is
        # published there, with nothing retimed: its instructions' latencies
        # and units are still the description's.
        moved = [entry["core"] for entry in document.get("timing", []) if entry["retimed"]]
        if moved:
            failures.append(f"{corpus.name}: {moved} retime instructions, and no corpus's "
                            f"core does")
    print(f"  {with_cores} corpora with cores, none retimed")

    # 2. A core that says something.
    base = (EXAMPLES / "issue_width.axisl").read_text()
    units: dict[str, list[str]] = {}
    for mnemonic, unit in re.findall(r"\(mnemonic (\w+)\)(?:(?!\(definstruction).)*?\(unit (\w+)\)",
                                     base, re.S):
        units.setdefault(unit, []).append(mnemonic)
    branches, multiplies = units["br"], units["mul"]
    core = f"""  (defcore retimed (kind rvmt) (implements iw32) (issue-width 2)
    (units (alu (count 2) (pipelined true)) (mul (count 1) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true)))
    (timing (latency ({branches[0]} 7)) (class-latency (br 2) (mul 5))
            (unit ({branches[1]} mul))))
"""
    expected = {branches[0]: ("br", 7), branches[1]: ("mul", 5)}
    expected |= {m: ("br", 2) for m in branches[2:]}
    expected |= {m: ("mul", 5) for m in multiplies}
    work = Path(tempfile.mkdtemp(prefix="axis_coretiming_"))
    retimed = work / "retimed.axisl"
    retimed.write_text(base.rstrip()[:-1] + core + ")\n")

    def published(path: Path):
        result = axis("emit-uarch-json", path)
        if result.returncode != 0:
            return None, result.stderr.strip()[:200]
        tables = json.loads(result.stdout).get("timing", [])
        # The cores that retime something: one that only cracks has no row.
        return {entry["core"]: {row["mnemonic"]: (row["unit"], row["latency"])
                                for row in entry["retimed"]}
                for entry in tables if entry["retimed"]}, ""

    said, error = published(retimed)
    if said is None:
        failures.append(f"a core with `(timing ...)` is not accepted: {error}")
    elif said != {"retimed": expected}:
        failures.append(f"the published table is {said}, not {{'retimed': {expected}}}")
    else:
        print(f"  a core retimes {len(expected)} instruction(s): one by name, "
              f"{len(branches) - 2 + len(multiplies)} by class, one moved to another unit")

    # 3. Through the printer and back.
    printed = axis("emit-lisp", retimed)
    again = work / "again.axisl"
    again.write_text(printed.stdout)
    if printed.returncode != 0 or published(again)[0] != said:
        failures.append("the table does not survive emit-lisp")

    # 4. The simulator charges the core's word (T2), on both engines. Five
    #    cores over one ISA that differ ONLY in what they say about time: a
    #    chain of K dependent multiplies on a core that gives IWMUL seven
    #    cycles takes exactly (7 - 3) x K cycles more than on one that says
    #    nothing, and the same multiplies independent take (7 - 3) more, once
    #    -- which is a latency and not a stall. An add moved onto the
    #    multiplier takes the multiplier's class latency.
    timed = work / "timed.axisl"
    in_order = "(issue-width 1) (units (alu (count 1) (pipelined true)) (mul (count 1) (pipelined true)) (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true)))"
    executes = ("(issue-width 4) (window (rob 32) (issue-queue 32) (commit-width 4)) "
                "(branch (penalty 0) (predictor bimodal) (entries 64)) "
                "(front-end (fetch-width 4) (depth 2)) (engine execute) "
                "(units (alu (count 4) (pipelined true)) (mul (count 1) (pipelined true)) "
                "(br (count 1) (pipelined true)) (lsu (count 1) (pipelined true)))")
    cores = {
        "t_plain": in_order,
        "t_slowmul": in_order + " (timing (latency (IWMUL 7)))",
        "t_addonmul": in_order + " (timing (unit (IWADD mul)) (class-latency (mul 4)))",
        "x_plain": executes,
        "x_slowmul": executes + " (timing (latency (IWMUL 7)))",
    }
    timed.write_text(base.rstrip()[:-1] + "".join(
        f"  (defcore {name} (kind rvmt) (implements iw32) {body})\n"
        for name, body in cores.items()) + ")\n")
    measured = simulate(timed, work)
    if isinstance(measured, str):
        failures.append(measured)
    else:
        k = CHAIN_LENGTH
        def cycles(core, program):
            return measured[f"{core}.{program}"]
        # A run ends when its last result is ready. So a chain pays the extra
        # latency on every one of its K links, and independent work pays it
        # once, on the last -- the tail, and nothing in between.
        checks = [
            ("t_slowmul", "t_plain", "mulchain", (7 - 3) * k),
            ("t_slowmul", "t_plain", "mulspread", 7 - 3),
            ("t_addonmul", "t_plain", "addchain", (4 - 1) * k),
            ("t_addonmul", "t_plain", "mulchain", (4 - 3) * k),
            ("x_slowmul", "x_plain", "mulchain", (7 - 3) * k),
        ]
        for slow, plain, program, extra in checks:
            got = cycles(slow, program) - cycles(plain, program)
            if got != extra:
                failures.append(f"{program} on `{slow}` takes {got} cycle(s) more than on "
                                f"`{plain}`, not {extra}")
        print(f"  a chain of {k} multiplies: {cycles('t_plain', 'mulchain')} cycles at the "
              f"description's 3, {cycles('t_slowmul', 'mulchain')} on a core that says 7, "
              f"{cycles('x_slowmul', 'mulchain')} execution-driven; independent, "
              f"{cycles('t_plain', 'mulspread')} and {cycles('t_slowmul', 'mulspread')}")

    # 5. `--core`: the description as that core sees it. What reads an
    #    instruction's latency reads the core's, and the simulator, given the
    #    view, has nothing left to refuse.
    seen = subprocess.run([*axis_prefix(), "emit-json", str(retimed), "--core", "retimed"],
                          capture_output=True, text=True, cwd=AXIS_ROOT)
    if seen.returncode != 0:
        failures.append(f"--core is not accepted: {seen.stderr.strip()[:160]}")
    else:
        rows = {row["mnemonic"]: row for row in json.loads(seen.stdout)["instructions"]}
        wrong = [m for m, (unit, latency) in expected.items()
                 if rows[m]["latency_cycles"] != latency]
        if wrong:
            failures.append(f"emit-json --core does not carry the core's latency for {wrong}")
    nobody = subprocess.run([*axis_prefix(), "emit-json", str(retimed), "--core", "nobody"],
                            capture_output=True, text=True, cwd=AXIS_ROOT)
    if nobody.returncode == 0 or "no core `nobody`" not in nobody.stderr:
        failures.append("--core with a name the description lacks is not refused by name")

    # 6. The floor (T3). RV64I, given a core that states a cycle. Its unrolled
    #    divider is declared three cycles and is thirty deep at 45 gate delays:
    #    refused, by name. With the core's own word for the divider it is
    #    accepted, and the hardware is planned at the core's cycle with the
    #    core's latencies -- no instruction given fewer cycles than it needs.
    rv64 = (EXAMPLES / "rv64i.axisl").read_text().rstrip()[:-1]

    def with_core(clauses: str) -> Path:
        path = work / f"rv64_{abs(hash(clauses))}.axisl"
        path.write_text(rv64 + f"  (defcore c (kind rvmt) (implements rv64i) {clauses})\n)\n")
        return path

    optimistic = axis("check", with_core("(cycle (gates 45))"))
    if optimistic.returncode == 0 or "at a cycle of 45" not in optimistic.stderr:
        failures.append("a core whose divider cannot fit its three cycles is accepted")
    honest = with_core("(cycle (gates 45)) (timing (latency (DIV 30) (REM 30) (MUL 2)))")
    plan = subprocess.run([*axis_prefix(), "emit-hw-json", str(honest), "--core", "c"],
                          capture_output=True, text=True, cwd=AXIS_ROOT)
    if plan.returncode != 0:
        failures.append(f"a core that gives its divider thirty cycles is refused: "
                        f"{plan.stderr.strip()[:200]}")
    else:
        report = json.loads(plan.stdout)
        built = [i for i in report["instructions"] if i["status"] == "built"]
        short = [i["mnemonic"] for i in built if i["latency"] < i["cycles_needed"]]
        latency = {i["mnemonic"]: i["latency"] for i in built}
        if report["cost_model"]["cycle_budget"] != 45.0:
            failures.append("the hardware is not planned at the core's cycle")
        if short:
            failures.append(f"planned with fewer cycles than the netlist needs: {short}")
        if (latency["MUL"], latency["DIV"], latency["ADD"]) != (2, 30, 1):
            failures.append(f"the plan's latencies are not the core's: {latency['MUL']}, "
                            f"{latency['DIV']}, {latency['ADD']}")
        print(f"  at a 45-gate cycle RV64I's divider is refused three cycles and planned at "
              f"thirty; {len(built)} netlists, none under its floor")

    for failure in failures:
        print(f"FAIL {failure}")
    print("a core's timing is what is published: " + ("FAIL" if failures else "PASS"))
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
