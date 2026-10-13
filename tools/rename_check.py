#!/usr/bin/env python3
"""A machine holds as many results in flight as it has registers to put them
in. Gate.

A window of thirty-two entries does not let thirty-two writes run ahead of a
stalled instruction: each needs a physical register to hold its result, and
gets one back only when it retires. `(rename (rv_gpr N))` on a `defcore` says
how many a register file has beyond the ones its ISA names
(docs/ooo_design.md, O2), and this gate holds it to programs only that number
can explain:

  * **the pool binds**: independent writes behind a slow head cost more on a
    machine with four spare registers than on one with no limit, window and
    units identical;
  * **a pool nothing can exhaust costs NOTHING**, exactly: more spare
    registers than the window has entries is a machine whose renaming can
    never be what stalls it, and it must match the unlimited one to the
    cycle -- on every program, including one longer than the pool, which is
    what catches a register that is taken and never given back;
  * **spare registers ARE a window, for writes**: on a program where every
    instruction writes one register of the file, N spare registers and an
    N-entry reorder buffer are the same constraint -- dispatch waits for a
    retirement either way -- so the renaming machine must match the
    small-window one to the cycle. This is what pins the count rather than
    only its direction: an off-by-one pool still binds, and still costs more;
  * **only a write takes one**: stores behind the same head, and writes to
    the zero register, cost the four-register machine exactly what they cost
    the unlimited one. A result nobody can read needs nowhere to live;
  * **the architecture is untouched**, as everywhere.

Usage: tools/rename_check.py [corpus.axisl ...]
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
from lsq_check import BASE, DATA, ENTRY, HARNESS, Assembler, run_cmd  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Independent writes behind the head: more than the small pool holds.
FANOUT = 12
#: A run longer than the large pool, so a register never given back shows.
LONG = 48


def build_programs(asm: Assembler):
    slow, fast = asm.slow, asm.fast
    # ⚠️ A dependent slow head: nothing behind it retires until it does, so
    # whatever runs ahead is holding its result in a register the whole time.
    head = [asm.op(slow, 10, 1, 1)] + [asm.op(slow, 10, 10, 10) for _ in range(3)]
    return {
        # ⚠️ SLOW work behind it, independent of it and of each other. Cheap
        # work gains nothing from running ahead -- it retires behind the head
        # at the commit width either way, and a first version measured the
        # same cycle count with four spare registers and with no limit. What
        # a register buys is an early START for something that takes a while.
        "WRITES": head + [asm.op(slow, 11 + (k % 16), 1, 2) for k in range(FANOUT)],
        # Stores write no register, and neither does a write to the zero one.
        "STORES": head + [asm.st(2, BASE, 4 * k) for k in range(FANOUT)],
        # ⚠️ SLOW, for the same reason: a cheap write to the zero register
        # that wrongly took a register lost nothing by waiting for one, and
        # mutation testing said so.
        "ZERO": head + [asm.op(slow, 0, 1, 2) for _ in range(FANOUT)],
        # No head at all: a long stream whose results retire as fast as they
        # land. A pool that never got a register back runs dry partway.
        "LONG": [asm.op(fast, 11 + (k % 16), 1, 2) for k in range(LONG)],
    }


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])

    def same_machine(a, b):
        keys = ("issue_width", "units", "rob", "issue_queue", "commit_width",
                "branch_penalty", "predictor", "lsq", "memory")
        return all(a.get(k) == b.get(k) for k in keys)

    renamed = sorted((core for core in cores if core.get("rename") and core.get("rob")),
                     key=lambda core: min(core["rename"].values()))
    if len(renamed) < 2:
        print(f"  {name}: DECLINED fewer than two windowed cores rename")
        return 0, 0
    few, many = renamed[0], renamed[-1]
    unlimited = next((core for core in cores if not core.get("rename")
                      and not core.get("model") and same_machine(core, few)), None)
    if unlimited is None or not same_machine(few, many):
        print(f"  {name}: DECLINED no unlimited core identical to the renaming ones")
        return 0, 0
    spare = min(few["rename"].values())
    window = next((core for core in cores if not core.get("rename") and not core.get("model")
                   and core.get("rob") == spare
                   and same_machine({**core, "rob": few["rob"]}, few)), None)
    if window is None:
        print(f"  {name}: DECLINED no core whose window is {spare} entries and otherwise "
              f"`{few['name']}`, to hold the pool's size against")
        return 0, 0
    if min(many["rename"].values()) < many["rob"]:
        print(f"  {name}: DECLINED `{many['name']}` has fewer spare registers than window "
              f"entries, so no core here is one renaming cannot bind")
        return 0, 0

    module = f"rn_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    why = asm.missing()
    zero = lift.REGISTER_CLASSES.get(asm.kind, (None,))[0] if asm.kind else None
    if not why and zero != 0:
        why = f"register class `{asm.kind}` has no zero register at index 0"
    if why:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {why}")
        return 0, 0
    programs = build_programs(asm)
    base_slot = lift.register_slot(asm.kind, BASE)
    isa = next((test.get("isa") for test in tests if test["mnemonic"] == asm.slow), "") or ""
    sys.modules.pop(module, None)

    machines = {"FEW": few, "MANY": many, "FREE": unlimited, "WIN": window}
    runs = [f'  go("{program}_{tag}", "{core["name"]}", {program}, '
            f'(int32_t)(sizeof {program} / sizeof {program}[0]));'
            for program in programs for tag, core in machines.items()]
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "entry": ENTRY,
        "data": DATA,
        "base": base_slot,
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs),
        "extra": "",
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

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    for program, words in programs.items():
        for tag, core in machines.items():
            checks += 1
            row = said.get(f"{program}_{tag}")
            if row is None:
                fail(f"{program} on {core['name']} reported nothing")
            elif row[1] != len(words):
                fail(f"{program} on {core['name']} retired {row[1]} of {len(words)}")
        checks += 1
        if len({said[f"{program}_{tag}"][2] for tag in machines
                if f"{program}_{tag}" in said}) > 1:
            fail(f"{program} left different registers or memory on different machines")
    if failures:
        return checks, failures
    cyc = {key: row[0] for key, row in said.items()}

    # ⚠️ THE POOL BINDS.
    checks += 1
    if cyc["WRITES_FEW"] <= cyc["WRITES_FREE"]:
        fail(f"{FANOUT} independent writes behind a slow head cost {cyc['WRITES_FEW']} "
             f"with {spare} spare registers and {cyc['WRITES_FREE']} with no limit; the "
             f"pool is not being read")
    # ⚠️ AN INEXHAUSTIBLE POOL COSTS NOTHING, on every program.
    for program in programs:
        checks += 1
        if cyc[f"{program}_MANY"] != cyc[f"{program}_FREE"]:
            fail(f"{program} cost {cyc[f'{program}_MANY']} on `{many['name']}`, whose pool "
                 f"is bigger than its window, and {cyc[f'{program}_FREE']} with no limit; "
                 f"renaming that cannot bind has charged something")
    # ⚠️ SPARE REGISTERS ARE A WINDOW, for a program of nothing but writes.
    for program in ("WRITES", "LONG"):
        checks += 1
        if cyc[f"{program}_FEW"] != cyc[f"{program}_WIN"]:
            fail(f"{program}, where every instruction writes a register, cost "
                 f"{cyc[f'{program}_FEW']} with {spare} spare registers and "
                 f"{cyc[f'{program}_WIN']} on a {spare}-entry window; for writes those are "
                 f"the same constraint, so the pool is holding a different number")
    # ⚠️ ONLY A WRITE TAKES ONE.
    for program, what in (("STORES", "stores"), ("ZERO", "writes to the zero register")):
        checks += 1
        if cyc[f"{program}_FEW"] != cyc[f"{program}_FREE"]:
            fail(f"{FANOUT} {what} behind a slow head cost {cyc[f'{program}_FEW']} with "
                 f"{spare} spare registers and {cyc[f'{program}_FREE']} with no limit; "
                 f"they hold no result, so they need no register")

    if not failures:
        print(f"  {name}: {FANOUT} writes behind a slow head cost {cyc['WRITES_FEW']} with "
              f"{spare} spare registers and {cyc['WRITES_FREE']} unlimited; "
              f"{cyc['WRITES_WIN']} on a {spare}-entry window, "
              f"{cyc['WRITES_MANY']} with more than the window; stores and zero writes "
              f"untouched; {checks} checks")
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
        print("results need registers to live in: SKIP")
        return DECLINED
    print(f"results need registers to live in: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
