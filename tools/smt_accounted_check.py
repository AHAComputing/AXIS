#!/usr/bin/env python3
"""Every instruction is either defined in SMT-LIB or named as not defined.

`emit-smt2` writes a `define-fun axis_instr_<name>` for an instruction whose
value is a function of its operands, and a comment naming anything it could not.
Most of a real corpus gets the comment: a `define-fun` answers *what does this
compute from its operands*, and an instruction that writes memory or
architectural state is not that function. That is a boundary rather than a gap,
and it is worth saying out loud rather than leaving as an absence -- 576 of
AArch64's 917 instructions were absent from the file with nothing written about
them, so a reader looking for `axis_instr_str_x_unsigned` could not tell an
instruction that is not a value from one that had been dropped.

This matters more here than for the other artifacts. The ISE miner discharges
its equivalence obligations against these definitions: a candidate extension is
proven equal to the instructions it replaces by composing their `define-fun`s
and asking z3. An instruction silently missing from the file is one the miner
cannot compose, and the shape of that failure is a proof about less than it
appears to be about.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def check(axis_file: Path) -> tuple[int, int]:
    def emit(verb: str) -> str:
        return subprocess.run([*axis_prefix(), verb, str(axis_file)],
                              capture_output=True, text=True, check=True,
                              cwd=AXIS_ROOT).stdout

    smt = emit("emit-smt2")
    support = emit("lift-support")

    def ident(name: str) -> str:
        return name.lower().replace("-", "_").replace(".", "_")

    instructions = {ident(line.split("\t")[0])
                    for line in support.splitlines() if "\t" in line}
    if not instructions:
        return 0, 0
    # A scalable instruction is defined once per LANE, so its origin is defined
    # when its lanes are -- the same view `llvm_accounted_check` takes and the
    # roundtrip fixtures take, because it is the same fact.
    def origin(name: str) -> str:
        return ident(re.sub(r"__l\d+(__defined)?$", "", name))

    defined = {origin(m) for m in
               re.findall(r"^\(define-fun axis_instr_(\w+) ", smt, re.M)}
    named = {origin(m) for m in re.findall(r"^; axis_instr_(\w+):", smt, re.M)}
    silent = sorted(instructions - defined - named)
    for mnemonic in silent:
        print(f"  FAIL {axis_file.name}: {mnemonic} has no SMT definition and no "
              f"comment saying why")
    return len(instructions), len(silent)


def main() -> int:
    files = [Path(arg) for arg in sys.argv[1:]]
    if not files:
        files = sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    total = failures = corpora = 0
    for axis_file in files:
        try:
            seen, bad = check(axis_file)
        except subprocess.CalledProcessError:
            continue
        if seen:
            corpora += 1
            total += seen
            failures += bad
    print(f"{total} instruction(s) over {corpora} corpus/corpora, "
          f"{failures} unaccounted for")
    print("every instruction defined or named: "
          + ("PASS" if not failures else "FAIL"))
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
