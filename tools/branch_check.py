#!/usr/bin/env python3
"""A taken branch costs what the machine says it costs. Gate.

A machine that does not predict fetches the fall-through, and when the branch
turns out to go elsewhere the front end starts again. That redirect is most of
what separates a core with a predictor from one without, and the cost model had
no way to say it: every branch was free, on every machine.

`defcore` now declares `(branch (penalty N))`. Two cores differing in nothing
else answer differently on the same program, and that difference is the whole
check:

  * **a taken branch costs the declared penalty**, once per branch;
  * **a branch that falls through costs nothing** -- the front end was already
    fetching the right address, so a not-taken branch on a machine with a
    penalty of six is a machine with a penalty of zero. Without this the gate
    would pass a model that charged every branch instruction rather than every
    redirect, which is a different machine and a plausible wrong answer;
  * **the redirect is paid by what FOLLOWS**, not by the branch: the branch
    itself costs what any instruction costs. The program therefore ends with a
    non-branch, so every branch has a successor to charge;
  * **penalty zero is the model that came before**, so a description that says
    nothing about branches describes the machine it always did.

⚠️ Taken-ness is a fact about the REGISTERS, not the encoding. The two programs
here are the same instruction at the same addresses, differing only in which
registers the branch compares -- so nothing but the direction of the branch can
explain a difference between them.

Usage: tools/branch_check.py [corpus.axisl ...]
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
BRANCHES = 6

HARNESS = r"""
/* One program, two machines that differ only in what a redirect costs. */
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
  printf("%%s cycles %%llu steps %%llu stalls %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)(S->front_end_stalls ? S->front_end_stalls(m) : 0));
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core) { printf("NOCORES\n"); return 0; }
  static const uint32_t TAKEN[] = { %(taken)s };
  static const uint32_t FELL[] = { %(fell)s };
  const int32_t n = (int32_t)(sizeof TAKEN / sizeof TAKEN[0]);
%(runs)s
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def build(lift, tests, facts, work, name):
    """A run of branches that go somewhere, and the same run falling through.

    ⚠️ Same instruction, same addresses, same count. Only the registers the
    branch compares differ, so the direction of the branch is the only thing
    that can explain a difference between the two.
    """
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    branch = filler = None
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        imms = [o for o in entry["operands"]
                if o["role"] == "in" and o["kind"] == "imm"]
        # ⚠️ A branch is what it DOES, not what a flag says. The lift row's
        # `ends_block` is None in this table -- the same trap `unit` and
        # `latency` set -- and an instruction that writes the pc is a branch
        # whatever any field claims.
        redirects = any(effect.get("kind") == "setpc"
                        for effect in (entry.get("effects") or []))
        if redirects and len(regs) == 2 and len(imms) == 1:
            branch = branch or (test, entry, regs, imms[0])
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        if not redirects and len(outs) == 1 and not entry.get("effects"):
            filler = filler or (test, entry, outs[0])
    if branch is None or filler is None:
        return None, None, "no conditional branch with two registers and an offset"

    test, entry, regs, imm = branch
    isa = test.get("isa") or ""
    word = int(test["encoded"], 16)

    def encode(left, right, offset):
        built = lift.place_operand(word, entry, regs[0]["name"], left)
        built = lift.place_operand(built, entry, regs[1]["name"], right)
        built = lift.place_operand(built, entry, imm["name"], offset)
        back = lift.lift(built, isa or None)
        if back is None or back["operands"].get(imm["name"]) != offset:
            return None
        return built

    # ⚠️ +8 clears the instruction after it, so a taken branch skips the
    # filler and a fall-through runs it. Both programs have the same words.
    jump, same = encode(1, 2, 8), encode(1, 1, 8)
    if jump is None or same is None:
        return None, None, f"{test['mnemonic']}'s offset will not hold 8"

    fill_test, fill_entry, fill_dest = filler
    pad = lift.place_operand(int(fill_test["encoded"], 16), fill_entry,
                             fill_dest["name"], 5)
    taken, fell = [], []
    for _ in range(BRANCHES):
        taken += [jump, pad]
        fell += [same, pad]
    # ⚠️ A non-branch last, so every branch has a successor to charge. The
    # redirect is paid by what follows; a program ending in a branch hides
    # one whole penalty.
    taken.append(pad)
    fell.append(pad)
    return (taken, fell), isa, None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = [core for core in facts.get("cores", [])
             if (core.get("issue_width", 1) or 1) == 1
             and all((unit.get("count", 1) or 1) == 1 for unit in core.get("units", []))]
    by_penalty: dict[int, dict] = {}
    for core in cores:
        by_penalty.setdefault(core.get("branch_penalty", 0), core)
    if 0 not in by_penalty or len(by_penalty) < 2:
        print(f"  {name}: DECLINED needs two one-wide cores whose branch "
              f"penalties differ, one of them zero")
        return 0, 0
    free = by_penalty[0]
    costly = by_penalty[max(k for k in by_penalty if k != 0)]
    penalty = costly["branch_penalty"]

    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"br_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"br_{name}")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    programs, isa, why = build(lift, tests, facts, work, name)
    sys.modules.pop(f"br_{name}", None)
    if programs is None:
        print(f"  {name}: DECLINED {why}")
        return 0, 0
    taken, fell = programs

    runs = []
    for tag, core in (("FREE", free["name"]), ("COSTLY", costly["name"])):
        runs.append(f'  go("T_{tag}", "{core}", TAKEN, n);')
        runs.append(f'  go("F_{tag}", "{core}", FELL, n);')

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "entry": ENTRY,
        "isa": f'"{isa}"' if isa else "NULL",
        "taken": ", ".join(f"{w}u" for w in taken),
        "fell": ", ".join(f"{w}u" for w in fell),
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

    for tag in ("T_FREE", "T_COSTLY", "F_FREE", "F_COSTLY"):
        checks += 1
        if tag not in said:
            print(f"  FAIL {name}: {tag} reported nothing")
            failures += 1
    if failures:
        return checks, failures

    # ⚠️ The two programs must actually have branched differently, or this is
    # one program measured twice. A taken run skips its fillers and retires
    # fewer instructions than one that falls through.
    checks += 1
    if said["T_FREE"][1] >= said["F_FREE"][1]:
        print(f"  FAIL {name}: the 'taken' program retired {said['T_FREE'][1]} "
              f"instruction(s) and the fall-through {said['F_FREE'][1]}; "
              f"nothing here is branching")
        failures += 1
    checks += 1
    if said["T_FREE"][1] != said["T_COSTLY"][1] or said["F_FREE"][1] != said["F_COSTLY"][1]:
        print(f"  FAIL {name}: the same program retired different counts on "
              f"the two cores; they differ in more than a branch penalty")
        failures += 1

    # ⚠️ The declared penalty is measured as FRONT-END IDLE, not as a cycle
    # difference. In a pipeline the machine keeps retiring what was already in
    # flight while the front end waits, so a mispredict costs the full penalty
    # in idle fetch and rather less in total time -- two different true
    # statements, and the declaration is about the first.
    checks += 1
    want = penalty * BRANCHES
    if said["T_COSTLY"][2] != want:
        print(f"  FAIL {name}: {BRANCHES} taken branches at a declared penalty "
              f"of {penalty} should idle the front end for {want} cycles; the "
              f"machine reported {said['T_COSTLY'][2]}")
        failures += 1

    # It still has to cost SOMETHING, or the idle was never on the clock.
    checks += 1
    if said["T_COSTLY"][0] <= said["T_FREE"][0]:
        print(f"  FAIL {name}: the taken program cost {said['T_FREE'][0]} "
              f"cycles with no penalty and {said['T_COSTLY'][0]} with "
              f"{penalty}; front-end idle that costs no time is not idle")
        failures += 1

    # ⚠️ And a branch that falls through costs nothing at all -- no idle, and
    # no time.
    checks += 1
    if said["F_COSTLY"][2] != 0:
        print(f"  FAIL {name}: a program whose branches all fall through idled "
              f"the front end for {said['F_COSTLY'][2]} cycle(s); the front "
              f"end was already fetching the right address")
        failures += 1
    checks += 1
    if said["F_COSTLY"][0] != said["F_FREE"][0]:
        print(f"  FAIL {name}: a program whose branches all fall through cost "
              f"{said['F_FREE'][0]} on a machine with no branch penalty and "
              f"{said['F_COSTLY'][0]} on one with {penalty}; nothing there "
              f"redirects a front end")
        failures += 1

    if not failures:
        print(f"  {name}: {BRANCHES} taken branches idle the front end "
              f"{said['T_COSTLY'][2]} cycles at a declared penalty of "
              f"{penalty} and cost {said['T_COSTLY'][0] - said['T_FREE'][0]} "
              f"in time; falling through costs nothing, {checks} checks")
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
        print("a taken branch costs what the machine says: SKIP")
        return DECLINED
    print(f"a taken branch costs what the machine says: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
