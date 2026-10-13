#!/usr/bin/env python3
"""Units behind one port start one instruction between them a cycle. Gate.

`(ports (p0 alu mul) (p1 alu) ...)` on a `defcore` says which issue ports feed
which units (docs/ooo_design.md, O10). A port starts one instruction a cycle,
so units sharing a port cannot both start in the same cycle however many
copies each has -- the thing a unit count cannot express. Two machines
identical but for their ports:

  * **what no two share costs nothing**: a stream of adds -- two adders on two
    ports -- and a stream of multiplies -- one multiplier on one port -- cost
    exactly what they cost with every unit its own port;
  * **what does share, pays**: adds and multiplies mixed start at most as
    many a cycle as there are ports feeding them, so N of them cannot issue
    in fewer than N / ports cycles, and the ported machine is slower than its
    twin, which starts one of each unit a cycle;
  * **the architecture is untouched**.

Usage: tools/ports_check.py [corpus.axisl ...]
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

N = 24


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    ported = next((c for c in cores if c.get("ports")), None)
    twin = None
    if ported:
        keys = [k for k in ported if k not in ("name", "ports")]
        twin = next((c for c in cores if not c.get("ports")
                     and all(c.get(k) == ported.get(k) for k in keys if k != "vendor")), None)
    if not ported or not twin:
        print(f"  {name}: DECLINED no core with ports and a twin without")
        return 0, 0

    module = f"ports_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    why = asm.missing()
    unit_of = {entry["mnemonic"]: entry.get("unit") for entry in facts["instructions"]}
    if not why:
        add_unit, mul_unit = unit_of.get(asm.fast_add), unit_of.get(asm.slow)
        shared = [p for p, units in ported["ports"].items()
                  if add_unit in units or mul_unit in units]
        if add_unit == mul_unit or not any(add_unit in u and mul_unit in u
                                           for u in ported["ports"].values()):
            why = "no port that feeds both the adder and the multiplier"
    if why:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {why}")
        return 0, 0
    add, mul = asm.fast_add, asm.slow
    programs = {
        "ADDS": [asm.op(add, 10 + k % 12, 1, 2) for k in range(N)],
        "MULS": [asm.op(mul, 10 + k % 12, 1, 2) for k in range(N)],
        # Two adds for every multiply: what the units could start in a cycle
        # on a machine whose units are their own ports.
        "MIX": [asm.op(mul if k % 3 == 2 else add, 10 + k % 12, 1, 2) for k in range(N)],
    }
    base_slot = lift.register_slot(asm.kind, BASE)
    isa = next((t.get("isa") for t in tests if t["mnemonic"] == add), "") or ""
    sys.modules.pop(module, None)

    machines = {"PORTED": ported, "TWIN": twin}
    runs = [f'  go("{program}_{tag}", "{core["name"]}", {program}, '
            f'(int32_t)(sizeof {program} / sizeof {program}[0]));'
            for program in programs for tag, core in machines.items()]
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "data": DATA,
        "base": base_slot, "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs), "extra": "",
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
        rows = [said.get(f"{program}_{tag}") for tag in machines]
        checks += 1
        if any(r is None for r in rows):
            fail(f"{program} reported nothing on some machine")
        elif any(r[1] != len(words) for r in rows) or len({r[2] for r in rows}) != 1:
            fail(f"{program} retired different instructions or left different registers")
    if failures:
        return checks, failures
    cyc = {key: row[0] for key, row in said.items()}
    # ⚠️ WHAT NO TWO SHARE COSTS NOTHING, exactly.
    for program in ("ADDS", "MULS"):
        checks += 1
        if cyc[f"{program}_PORTED"] != cyc[f"{program}_TWIN"]:
            fail(f"{N} independent {program.lower()} cost {cyc[f'{program}_PORTED']} with ports "
                 f"and {cyc[f'{program}_TWIN']} without; nothing in them contends for a port, so "
                 f"the ports must cost nothing")
    # ⚠️ WHAT SHARES PAYS: at most `ports` a cycle.
    feeding = len(shared)
    floor = -(-N // feeding)
    checks += 1
    if cyc["MIX_PORTED"] < floor:
        fail(f"{N} adds and multiplies fed by {feeding} ports cannot issue in under {floor} "
             f"cycles; the ported machine reported {cyc['MIX_PORTED']}")
    checks += 1
    if cyc["MIX_PORTED"] <= cyc["MIX_TWIN"]:
        fail(f"adds and multiplies mixed cost {cyc['MIX_PORTED']} with a shared port and "
             f"{cyc['MIX_TWIN']} with each unit its own; the sharing is not being read")

    if not failures:
        print(f"  {name}: {N} adds {cyc['ADDS_PORTED']} = {cyc['ADDS_TWIN']}, {N} multiplies "
              f"{cyc['MULS_PORTED']} = {cyc['MULS_TWIN']}; mixed {cyc['MIX_PORTED']} through "
              f"{feeding} ports (floor {floor}) vs {cyc['MIX_TWIN']} unported; {checks} checks")
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
        print("units behind one port share it: SKIP")
        return DECLINED
    print(f"units behind one port share it: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
