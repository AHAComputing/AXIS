#!/usr/bin/env python3
"""The view an executing instruction sees follows the golden model. Gate.

The execution-driven engine keeps the committed registers beside the golden
model's own -- a view, patched with the window's writes for one execute and
put back -- rather than copying the register file for every instruction
(docs/ooo_design.md, E4). A copy cannot go stale; a view can, in exactly two
ways, and each is held here:

  * **the golden model disagreed**: a load of a cell that reads differently
    each time executes with one value and commits with another. That is one
    replay -- the load's -- and the view takes the golden model's value, so
    what reads the register afterwards agrees. A view left with the pipeline's
    value would replay every reader;
  * **the host wrote a register between steps**: far enough ahead of its first
    reader that nothing in flight has read it, the reader executes with the
    new value and nothing replays. A view that missed the write would hand it
    the old one.

And in both, the registers at the end are the golden model's.

Usage: tools/xview_check.py [corpus.axisl ...]
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

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x200
#: The cell that reads differently each time, and the register that points at it.
CELL = 0x8000
BASE, LOADED, COPY, SUM, LATE = 5, 21, 22, 23, 24
#: Instructions between the start and the late register's first reader: more
#: than any window here holds, so nothing in flight has read it.
AHEAD = 96
NEW = 0x1234

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];
static uint64_t READS;

static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c;
  if (a == %(cell)du) { return 100u + READS++; }
  uint64_t v = 0;
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

static void go(const char *tag, const uint32_t *words, int32_t count, int32_t poke) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  READS = 0;
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) { MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b)); }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, "%(core)s")) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) { S->set_reg(m, i, 0x11u * (uint64_t)(i + 1)); }
  S->set_reg(m, %(base)d, %(cell)du);
  S->count_cycles(m, 1);
  if (poke) {
    /* Stepped, not run to a limit: a machine stopped at a step limit stays
       stopped. */
    S->step(m);
    S->step(m);
    S->set_reg(m, %(late)d, %(new)du);
  }
  S->run(m, 1000u);
  printf("%%s steps %%llu replays %%llu loaded %%llu copy %%llu sum %%llu late %%llu\n", tag,
         (unsigned long long)S->steps(m), (unsigned long long)S->replays(m),
         (unsigned long long)S->reg(m, %(loaded)d), (unsigned long long)S->reg(m, %(copy)d),
         (unsigned long long)S->reg(m, %(sum)d), (unsigned long long)S->reg(m, %(late)d));
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core || !S->replays) { printf("NOEXECUTE\n"); return 0; }
%(programs)s
  go("VOLATILE", VOLATILE, %(nv)d, 0);
  go("POKED", POKED, %(np)d, 1);
  return 0;
}
"""


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    # A plain execution-driven core: no data cache to time the cell, no
    # memory ordering to hold the load back.
    core = next((c for c in facts.get("cores", []) if c.get("engine") == "execute"
                 and not c.get("memory") and not c.get("lsq") and (c.get("rob") or 0) < AHEAD
                 and c.get("rob")), None)
    if not core:
        print(f"  {name}: DECLINED no plain execution-driven core")
        return 0, 0
    module = f"xv_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    if asm.missing():
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {asm.missing()}")
        return 0, 0
    add = asm.fast_add
    pad = asm.op(add, 30, 1, 1)
    # VOLATILE: load the cell, copy what was loaded, and add the two.
    volatile = [asm.ld(LOADED, BASE, 0), asm.op(add, COPY, LOADED, 0),
                asm.op(add, SUM, LOADED, COPY), 0]
    # POKED: the late register's only reader, far past anything in flight
    # when the host writes it.
    poked = [pad] * AHEAD + [asm.op(add, SUM, LATE, LATE), 0]
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
    sys.modules.pop(module, None)

    def table(label, words):
        return f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "cell": CELL,
        "core": core["name"], "isa": f'"{isa}"' if isa else "NULL",
        "base": slot(BASE), "loaded": slot(LOADED), "copy": slot(COPY), "sum": slot(SUM),
        "late": slot(LATE), "new": NEW,
        "programs": table("VOLATILE", volatile) + "\n" + table("POKED", poked),
        "nv": len(volatile), "np": len(poked),
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
        if len(parts) == 13 and parts[1] == "steps":
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
    if set(said) != {"VOLATILE", "POKED"}:
        fail(f"the harness reported {sorted(said)}")
        return checks, failures
    v, p = said["VOLATILE"], said["POKED"]
    # The golden model's read is the second: the pipeline's was 100.
    checks += 1
    if v["loaded"] == 100 or v["copy"] != v["loaded"] or v["sum"] != 2 * v["loaded"]:
        fail(f"a cell that reads differently each time left loaded {v['loaded']}, copy "
             f"{v['copy']}, sum {v['sum']}; the registers are the golden model's -- its own "
             f"read, copied and doubled")
    checks += 1
    if v["replays"] != 1:
        fail(f"a load whose cell changed between execute and commit replayed {v['replays']} "
             f"times; once -- the load -- and the view then holds what the golden model "
             f"read, so its readers agree")
    checks += 1
    if p["late"] != NEW or p["sum"] != 2 * NEW:
        fail(f"a register the host wrote between steps ended {p['late']}, its reader's sum "
             f"{p['sum']}; {NEW} and {2 * NEW}")
    checks += 1
    if p["replays"] != 0:
        fail(f"a register the host wrote {AHEAD} instructions before its first reader "
             f"replayed {p['replays']} times; the reader executes with the new value, so none")
    if not failures:
        print(f"  {name}: on `{core['name']}` a changing cell replayed {v['replays']} time and "
              f"its readers agreed; a register written by the host {AHEAD} instructions ahead "
              f"of its reader replayed {p['replays']}; {checks} checks")
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
        print("the executing view follows the golden model: SKIP")
        return DECLINED
    print(f"the executing view follows the golden model: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
