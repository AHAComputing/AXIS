#!/usr/bin/env python3
"""The rounding mode a program selects is the mode it gets.

RISC-V's `DYN` forms take their rounding from `fcsr.frm` rather than from the
encoding, and Zicsr is what lets a program write it. Neither half means much
alone: a mode register nothing can set describes a machine dynamic rounding
cannot be used on, and a CSR write nothing reads is a store to nowhere.

So this drives the pair. For each mode, write `frm` with `CSRRW`, execute the
`DYN` instruction, and require the result to equal the *static* instruction for
that same mode -- two descriptions of one operation that only agree if the
write landed, the read saw it, and the operator honoured it.

Then the reserved modes: `frm` 5, 6 and 7 must trap and write nothing, which
is what the hardware does and what the description claims.

Vacuity: the static instructions must not all agree with each other, or the
comparison is satisfied by any mode at all and says nothing about selection.
The witness is an operand pair whose exact sum lies between two representables.

Usage: tools/dynamic_rounding_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

MODES = {0: "RNE", 1: "RUP", 2: "RDN", 3: "RTZ", 4: "RMM"}
RESERVED = (5, 6, 7)


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(output)],
                   check=True, cwd=AXIS_ROOT)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def f32(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_dynrm_"))
    sys.path.insert(0, str(workdir))
    for command, name in (("emit-lift-python", "axis_lift.py"),
                          ("emit-golden-python", "golden_model.py"),
                          ("emit-exec-python", "axis_exec.py"),
                          ("emit-roundtrip-json", "round.json")):
        emit(args.axis_file, command, workdir / name)
    lift = load(workdir / "axis_lift.py", "axis_lift")
    load(workdir / "golden_model.py", "golden_model")
    executor = load(workdir / "axis_exec.py", "axis_exec")
    tests = {t["mnemonic"]: t for t in
             json.loads((workdir / "round.json").read_text())["tests"]}

    needed = ["CSRRW_FRM", "FADD_S_DYN"] + [f"FADD_S_{name}" for name in MODES.values()]
    missing = [name for name in needed if name not in tests]
    if missing:
        print(f"{args.axis_file.name}: no dynamic rounding to check "
              f"(absent: {', '.join(missing[:4])})")
        return 0

    # 1.0 + 2^-24 is exactly halfway between two binary32 values, so the five
    # modes do not all agree on it -- which is what makes the comparison mean
    # something.
    lhs, rhs = f32(1.0), f32(2.0 ** -24)

    def run(mnemonic: str, mode: int | None):
        word = int(tests[mnemonic]["encoded"], 16)
        fx = {o["name"]: o["value"] for o in tests[mnemonic]["operands"]}
        regs = {lift.register_slot("rv_fpr", fx["rs1"]): lhs | 0xFFFFFFFF00000000,
                lift.register_slot("rv_fpr", fx["rs2"]): rhs | 0xFFFFFFFF00000000}
        state = {name: 0 for name, _ in lift.STATE_SLOTS}
        if mode is not None:
            csr = tests["CSRRW_FRM"]
            cw = {o["name"]: o["value"] for o in csr["operands"]}
            regs[lift.register_slot("rv_gpr", cw["rs1"])] = mode
            executor.step(int(csr["encoded"], 16), regs, state=state)
            if state.get("frm") != mode:
                return f"CSRRW wrote frm={state.get('frm')}, not {mode}", None
        out = executor.step(word, regs, state=state)
        slot = lift.register_slot("rv_fpr", fx["rd"])
        return (out, regs.get(slot))

    failures: list[str] = []
    static: dict[int, int] = {}
    for mode, name in MODES.items():
        _out, value = run(f"FADD_S_{name}", None)
        static[mode] = value & 0xFFFFFFFF if value is not None else None

    for mode, name in MODES.items():
        out, value = run("FADD_S_DYN", mode)
        if isinstance(out, str):
            failures.append(out)
            continue
        got = value & 0xFFFFFFFF if value is not None else None
        if out["trap"]:
            failures.append(f"frm={mode} ({name}) trapped: {out['trap']}")
        elif got != static[mode]:
            failures.append(f"frm={mode} ({name}): dyn gave 0x{got:08x}, "
                            f"static FADD_S_{name} gave 0x{static[mode]:08x}")

    for mode in RESERVED:
        out, value = run("FADD_S_DYN", mode)
        if isinstance(out, str):
            failures.append(out)
            continue
        if out["trap"] != "illegal":
            failures.append(f"frm={mode} is reserved and did not trap: {out['trap']}")
        if value is not None:
            failures.append(f"frm={mode} trapped and still wrote 0x{value:08x}")

    for failure in failures:
        print(f"FAIL {failure}")
    distinct = len(set(static.values()))
    print(f"{len(MODES)} selected mode(s) + {len(RESERVED)} reserved, "
          f"{distinct} distinct result(s) among the static forms")
    if distinct < 2:
        print("FAIL: every rounding mode gives the same result on this witness, "
              "so agreeing with the static form says nothing about selection")
        failures.append("vacuous")

    print("dynamic rounding == the mode selected: "
          + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
