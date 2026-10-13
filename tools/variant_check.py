#!/usr/bin/env python3
"""A description you changed is a machine that answers differently. Gate.

`cycle_check` proves the simulator uses the latency a description declares.
`sweep_check` varies the machine and reads a curve. Neither varies the thing a
designer actually edits: the DESCRIPTION. A stack where changing a number in
the source does not change the answer is a stack where the source is
decoration, and nothing here had ever checked that it is not.

So: take a corpus, change one instruction's declared latency, rebuild the pack
from the edited source, and run the same program on both machines.

  * **the edit reaches the artifact**: the rebuilt pack declares the new
    number. Checked first and separately, because every other property here
    would also fail if the edit silently missed, and "the gate is red" is not
    the same finding as "the edit did nothing";
  * **a dependent chain moves by exactly the difference**: K chained
    instructions at latency L take L x (K-1) + 1 cycles, so raising L by D
    raises them by D x (K-1). Not "more", not "about" -- the number the
    description declares, times the depth of the chain;
  * **an independent stream does not move at all**: latency is what a result
    costs the instruction WAITING for it. Nothing waits in a spread program,
    so a change that moved it would be a change being charged twice;
  * **the architecture is untouched**: both machines retire the same
    instructions and leave the same registers. A timing annotation that leaked
    into a result would be a description whose costs and whose meaning are not
    separable, and a co-design number from one would be unattributable.

⚠️ Latency is the axis because it is the one a description declares and the
simulator reads. Sweeping an instruction IN or OUT of a description is the
other half of "is this extension worth it", and it needs two kernels that
compute the same thing -- which needs either hand-written pairs or a compiler
that will select the new instruction. Neither exists here yet, and this gate
does not pretend to be it.

Usage: tools/variant_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

CODE = 0x200
CHAIN = 8
#: What the declared latency is raised by. ⚠️ Not 1: an off-by-one in the
#: scoreboard and a correct model differ by one, and a gate that moved the
#: number by one could not tell those apart.
DELTA = 4

HARNESS = r"""
/* One program, run on a machine built from an edited description. */
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

static void go(const axis_sim_pack *S, const char *tag, const uint32_t *words,
               int32_t count) {
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
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)count);
  /* ⚠️ A fingerprint of the whole register file, not a spot check. What has
     to be identical between the two machines is the ARCHITECTURE, and a
     timing edit that moved one register would hide behind any sample. */
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) {
      mark ^= (v >> (8 * b)) & 0xFFu;
      mark *= 1099511628211ull;
    }
  }
  printf("%%s cycles %%llu steps %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)mark);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->count_cycles || !S->cycles) { printf("NOCYCLES\n"); return 0; }
  static const uint32_t CHAINED[] = { %(chained)s };
  static const uint32_t SPREAD[] = { %(spread)s };
  const int32_t count = (int32_t)(sizeof CHAINED / sizeof CHAINED[0]);
  go(S, "CHAINED", CHAINED, count);
  go(S, "SPREAD", SPREAD, count);
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def retime(source: str, mnemonic: str, latency: int) -> tuple[str, str | None]:
    """Rewrite one instruction's declared latency, and nobody else's.

    ⚠️ Scoped to the block that declares this mnemonic. `(latency 1)` appears
    338 times in one corpus, and an edit that caught them all would change
    every instruction's cost -- which moves the chained program and the spread
    one together, and would pass three of the four properties here while
    measuring something else entirely.
    """
    blocks = source.split("(definstruction ")
    for index, block in enumerate(blocks):
        if index == 0:
            continue
        if not re.search(rf"\(mnemonic\s+{re.escape(mnemonic)}\s*\)", block):
            continue
        edited, count = re.subn(r"\(latency\s+\d+\s*\)",
                                f"(latency {latency})", block, count=1)
        if not count:
            return source, f"{mnemonic} declares no latency to change"
        blocks[index] = edited
        return "(definstruction ".join(blocks), None
    return source, f"{mnemonic} has no instruction block to edit"


def declared_latency(axis_file: Path, mnemonic: str) -> int | None:
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json",
                                str(axis_file)]).stdout)
    for entry in facts["instructions"]:
        if entry["mnemonic"] == mnemonic:
            return entry["latency_cycles"]
    return None


def pick_chainable(lift, tests, cost):
    """One instruction, one destination, register sources, latency above one.

    ⚠️ Above one because the property is about a DIFFERENCE. An instruction
    already at the floor can be raised, but the pair of runs then differs in
    both what the edit did and what the floor does, and only one of those is
    under test.
    """
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    for test in tests:
        mnemonic = test["mnemonic"]
        latency, throughput = cost.get(mnemonic, (1, 1.0))
        if latency < 2 or throughput != 1.0:
            continue
        entry = by_mnemonic.get(mnemonic)
        if entry is None or entry.get("effects") or entry.get("ends_block"):
            continue
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        ins = [o for o in entry["operands"]
               if o["role"] == "in" and o["kind"] != "imm"]
        if len(outs) != 1 or not ins:
            continue
        return test, entry, latency, outs[0], ins
    return None, None, None, None, None


def programs(lift, test, entry, dest, sources, isa):
    """The same instruction twice over: once depending on itself, once not."""
    word = int(test["encoded"], 16)

    def encode(dest_index: int, source_index: int) -> int:
        built = word
        built = lift.place_operand(built, entry, dest["name"], dest_index)
        for operand in sources:
            built = lift.place_operand(built, entry, operand["name"], source_index)
        return built

    chained = [encode(3, 3) for _ in range(CHAIN)]
    spread = [encode(3 + i, 20 + i) for i in range(CHAIN)]
    return chained, spread


def measure(axis_file: Path, work: Path, tag: str, chained, spread, isa):
    manifest = build_pack.build(axis_file, work / f"packs_{tag}",
                                only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        return None, f"{name}: no simulator library"
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "chained": ", ".join(f"{w}u" for w in chained),
        "spread": ", ".join(f"{w}u" for w in spread),
        "isa": f'"{isa}"' if isa else "NULL",
        "code": CODE,
    }
    root = work / f"packs_{tag}" / name
    binary = work / f"{name}_{tag}"
    (work / f"{name}_{tag}.c").write_text(source)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(binary), str(work / f"{name}_{tag}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(binary)], capture_output=True, text=True)
    if done.returncode != 0:
        return None, f"the {tag} harness exited {done.returncode}"
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 7:
            said[parts[0]] = (int(parts[2]), int(parts[4]), int(parts[6]))
    if "CHAINED" not in said or "SPREAD" not in said:
        return None, f"the {tag} harness reported nothing ({done.stdout[:80]})"
    return said, None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    name = axis_file.stem
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"va_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"va_{name}")
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json",
                                str(axis_file)]).stdout)
    cost = {entry["mnemonic"]: (entry["latency_cycles"],
                                float(entry["throughput_per_cycle"]))
            for entry in facts["instructions"]}
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    test, entry, latency, dest, sources = pick_chainable(lift, tests, cost)
    if test is None:
        print(f"  {name}: DECLINED nothing with a latency above one and a "
              f"register to carry it")
        sys.modules.pop(f"va_{name}", None)
        return 0, 0
    isa = test.get("isa") or ""
    chained, spread = programs(lift, test, entry, dest, sources, isa)
    sys.modules.pop(f"va_{name}", None)

    # ⚠️ The edited description goes in the scratch tree, not beside the
    # original. A corpus has no relative includes to resolve, so there is
    # nothing to gain by writing into a directory other work shares -- and a
    # killed process does not run its cleanup, which is how stray files
    # outlive the run that made them.
    raised = latency + DELTA
    edited, why = retime(axis_file.read_text(), test["mnemonic"], raised)
    if why:
        print(f"  {name}: DECLINED {why}")
        return 0, 0
    variant = work / f"variant_{name}.axisl"
    variant.write_text(edited)
    checks = failures = 0

    # ⚠️ FIRST: did the edit reach the artifact? Every property below
    # would also fail if it did not, and those are different findings.
    checks += 1
    got = declared_latency(variant, test["mnemonic"])
    if got != raised:
        print(f"  FAIL {name}: the edited description declares latency "
              f"{got} for {test['mnemonic']}, not {raised}")
        return checks, 1
    checks += 1
    unchanged = {m: declared_latency(variant, m) for m in
                 list(cost)[:40] if m != test["mnemonic"]}
    drifted = [m for m, value in unchanged.items()
               if value is not None and value != cost[m][0]]
    if drifted:
        print(f"  FAIL {name}: editing {test['mnemonic']} also changed "
              f"{len(drifted)} other instruction(s): {drifted[:4]}")
        failures += 1

    base, why = measure(axis_file, work, "base", chained, spread, isa)
    if why:
        print(f"  FAIL {name}: {why}")
        return checks, 1
    after, why = measure(variant, work, "var", chained, spread, isa)
    if why:
        print(f"  FAIL {name}: {why}")
        return checks, 1

    steps = base["CHAINED"][1]
    checks += 1
    if steps != CHAIN or after["CHAINED"][1] != CHAIN:
        print(f"  FAIL {name}: the chain ran {steps} and "
              f"{after['CHAINED'][1]} instruction(s) of {CHAIN}")
        return checks, failures + 1

    # A dependent chain moves by the difference, times its depth.
    checks += 1
    moved = after["CHAINED"][0] - base["CHAINED"][0]
    want = DELTA * (steps - 1)
    if moved != want:
        print(f"  FAIL {name}: raising {test['mnemonic']}'s latency from "
              f"{latency} to {raised} moved {steps} chained instruction(s) by "
              f"{moved} cycles, not {want} "
              f"({base['CHAINED'][0]} -> {after['CHAINED'][0]})")
        failures += 1

    # ⚠️ And an independent stream does not move. Without this the gate would
    # pass a model that charged latency to every instruction regardless of
    # whether anything waited for it -- which is a stall, not a latency.
    checks += 1
    if after["SPREAD"][0] != base["SPREAD"][0]:
        print(f"  FAIL {name}: the same edit moved an INDEPENDENT stream from "
              f"{base['SPREAD'][0]} to {after['SPREAD'][0]} cycles; nothing "
              f"there waits for a result")
        failures += 1

    # A cost is not a meaning.
    for tag in ("CHAINED", "SPREAD"):
        checks += 1
        if base[tag][2] != after[tag][2]:
            print(f"  FAIL {name}: the {tag.lower()} program left different "
                  f"registers after a TIMING edit ({base[tag][2]} vs "
                  f"{after[tag][2]})")
            failures += 1
        checks += 1
        if base[tag][1] != after[tag][1]:
            print(f"  FAIL {name}: the {tag.lower()} program retired "
                  f"{base[tag][1]} and {after[tag][1]} instruction(s)")
            failures += 1

    if not failures:
        print(f"  {name}: {test['mnemonic']} latency {latency} -> {raised} "
              f"moved {steps} chained by {moved} cycles and an independent "
              f"stream by 0, same registers, {checks} checks")
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
        print("an edited description is a different machine: SKIP")
        return DECLINED
    print(f"an edited description is a different machine: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
