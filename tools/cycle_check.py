#!/usr/bin/env python3
"""The latency a description declares is the latency the machine takes. Gate.

Every instruction in every corpus carries `latency` and `throughput`, and until
the simulator grew a scoreboard nothing read them. A number beside the
semantics that nothing reads is free text, and a co-design result built on one
is a quotation of its author.

⚠️ This does not check the model against a second copy of the model, which
would be arithmetic agreeing with itself. It checks PROPERTIES that hold only
if the declared numbers are the ones being used:

  * a **chain** of dependent instructions costs its latency each, so N of them
    take about N x L cycles;
  * the **same instructions independent** cost their issue interval each, so N
    of them take about N cycles at throughput 1;
  * the ratio between the two IS the declared latency, which is the one number
    a designer wrote;
  * cycles never run ahead of instructions at throughput 1 -- a machine that
    retires one per cycle cannot take fewer cycles than instructions.

⚠️ The model is first-order by construction: in order, single issue, no memory
hierarchy, no prediction. It tells a dependent chain from an independent stream
and it is not a cycle-accurate machine. A gate that pretended otherwise would
be the more expensive mistake.

Usage: tools/cycle_check.py [corpus.axisl ...]
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

CODE = 0x200

HARNESS = r"""
/* One machine, counting cycles, on two programs that differ only in whether
   each instruction reads what the one before it wrote. */
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
static uint64_t trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

static uint64_t run(const axis_sim_pack *S, const uint32_t *words, int32_t count,
                    uint64_t *steps) {
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(code)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { return 0; }
  S->reset(m, %(code)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)count);
  uint64_t cycles = S->cycles(m);
  *steps = S->steps(m);
  S->destroy(m);
  return cycles;
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->count_cycles || !S->cycles) { printf("NOCYCLES\n"); return 0; }
  static const uint32_t CHAINED[] = { %(chained)s };
  static const uint32_t SPREAD[] = { %(spread)s };
  const int32_t count = (int32_t)(sizeof CHAINED / sizeof CHAINED[0]);
  uint64_t chained_steps = 0, spread_steps = 0;
  uint64_t chained = run(S, CHAINED, count, &chained_steps);
  uint64_t spread = run(S, SPREAD, count, &spread_steps);
  printf("CHAINED %%llu cycles %%llu steps\n", (unsigned long long)chained,
         (unsigned long long)chained_steps);
  printf("SPREAD %%llu cycles %%llu steps\n", (unsigned long long)spread,
         (unsigned long long)spread_steps);
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
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"cy_{name}.py")])
    sys.path.insert(0, str(work))
    import importlib
    lift = importlib.import_module(f"cy_{name}")
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cost = {entry["mnemonic"]: (entry["latency_cycles"],
                                float(entry["throughput_per_cycle"]))
            for entry in facts["instructions"]}
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]

    # ⚠️ One instruction, two programs. The pair differs only in the register
    # numbers, so anything that makes them take different times is the
    # dependence between them -- which is the one thing this model is for.
    best = None
    for test in tests:
        mnemonic = test["mnemonic"]
        latency, throughput = cost.get(mnemonic, (1, 1.0))
        if latency < 2 or throughput != 1.0:
            continue
        entry = next((row for row in lift.AXIS_LIFT_TABLE
                      if row["mnemonic"] == mnemonic), None)
        if entry is None or entry.get("effects"):
            continue
        names = {operand["name"]: operand for operand in entry["operands"]}
        outs = [operand for operand in entry["operands"]
                if operand["role"] in ("out", "inout")]
        ins = [operand for operand in entry["operands"]
               if operand["role"] == "in" and operand["kind"] != "imm"]
        if len(outs) != 1 or not ins or not names:
            continue
        best = (test, entry, latency, outs[0], ins)
        break
    if best is None:
        print(f"  {name}: DECLINED nothing with a latency above one and a "
              f"register to carry it")
        return 0, 0
    test, entry, latency, dest, sources = best
    word = int(test["encoded"], 16)
    isa = test.get("isa") or ""

    def encode(dest_index: int, source_index: int) -> int:
        fields = {}
        for operand in entry["operands"]:
            value = lift.lift(word, isa or None)["operands"].get(operand["name"], 0)
            if operand["name"] == dest["name"]:
                value = dest_index
            elif any(operand["name"] == s["name"] for s in sources):
                value = source_index
            fields[operand["name"]] = value or 0
        built = word
        for operand_name, value in fields.items():
            built = lift.place_operand(built, entry, operand_name, value)
        return built

    length = 8
    # Chained: each writes the register the next one reads.
    chained = [encode(3, 3) for _ in range(length)]
    # Spread: each writes a register nothing after it reads.
    spread = [encode(3 + i, 20 + i) for i in range(length)]

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "chained": ", ".join(f"{w}u" for w in chained),
        "spread": ", ".join(f"{w}u" for w in spread),
        "isa": f'"{isa}"' if isa else "NULL",
        "code": CODE,
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
        if line.startswith("NOCYCLES"):
            print(f"  FAIL {name}: the simulator library counts no cycles")
            return 0, 1
        parts = line.split()
        if len(parts) == 5:
            said[parts[0]] = (int(parts[1]), int(parts[3]))
    if "CHAINED" not in said or "SPREAD" not in said:
        print(f"  FAIL {name}: the harness reported nothing")
        return 0, 1

    chained_cycles, chained_steps = said["CHAINED"]
    spread_cycles, spread_steps = said["SPREAD"]
    checks = failures = 0

    checks += 1
    if chained_steps != spread_steps or chained_steps < 2:
        print(f"  FAIL {name}: the two programs ran {chained_steps} and "
              f"{spread_steps} instruction(s); they are the same program "
              f"with different registers")
        failures += 1

    # ⚠️ The ratio IS the declared latency. Anything else means the model is
    # using a number the description did not give it.
    checks += 1
    want = latency * (chained_steps - 1) + 1
    if chained_cycles != want:
        print(f"  FAIL {name}: {test['mnemonic']} declares latency {latency}, "
              f"and {chained_steps} chained took {chained_cycles} cycles, not "
              f"{want}")
        failures += 1
    checks += 1
    if spread_cycles != spread_steps:
        print(f"  FAIL {name}: {spread_steps} independent instruction(s) at "
              f"throughput 1 took {spread_cycles} cycles, not {spread_steps}")
        failures += 1
    checks += 1
    if spread_cycles >= chained_cycles:
        print(f"  FAIL {name}: a dependent chain took {chained_cycles} cycles "
              f"and an independent stream {spread_cycles} -- the model cannot "
              f"tell them apart")
        failures += 1

    if not failures:
        print(f"  {name}: {test['mnemonic']} declares latency {latency}; "
              f"{chained_steps} chained took {chained_cycles} cycles and "
              f"independent took {spread_cycles}, {checks} checks")
    sys.modules.pop(f"cy_{name}", None)
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "rv64i.axisl"]
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
        print("declared latency == cycles taken: SKIP")
        return DECLINED
    print(f"declared latency == cycles taken: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
