#!/usr/bin/env python3
"""Every instruction is either lowered to LLVM IR or named as not lowered.

`emit-llvm-ir` emits two kinds of function -- `axis_eval_*` for a pure value and
`axis_eff_*` for a behavior -- and writes a comment naming anything it withheld
and why. That is the right shape, and until now nothing checked it held: an
instruction could have vanished from the file with no function and no comment,
and the only sign would be a number in a report nobody recomputes.

This asks the question directly. For every instruction in every corpus: is there
a function, or is there a comment naming that instruction? Silence is the
failure, not refusal -- a stated reason is a fine answer, and 126 RISC-V
double-precision forms give one, that LLVM discards a directed rounding mode
(which `fp_rounding_check` re-measures every run rather than trusting).

The eval-path note "no formal_semantics declared" is not counted as a reason on
its own. It is what the pure path says about every effectful instruction, which
is most of them, so accepting it would make the check pass for an instruction
the effect path had also dropped in silence -- the exact hole this closes.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
#: The pure path's note about an effectful instruction, which says nothing about
#: whether the effect path emitted one.
NOT_A_REASON = "no formal_semantics declared"


def check(axis_file: Path) -> tuple[int, int]:
    def emit(verb: str) -> str:
        return subprocess.run([*axis_prefix(), verb, str(axis_file)],
                              capture_output=True, text=True, check=True,
                              cwd=AXIS_ROOT).stdout

    ll = emit("emit-llvm-ir")
    support = emit("lift-support")
    # The emitted symbol is the mnemonic as an identifier, so a hyphenated
    # mnemonic -- `ADD-AND-FLAGS` -- appears as `add_and_flags`. Comparing the
    # raw name found six instructions "missing" that were lowered all along.
    def ident(name: str) -> str:
        return name.lower().replace("-", "_").replace(".", "_")

    instructions = {ident(line.split("\t")[0])
                    for line in support.splitlines() if "\t" in line}
    if not instructions:
        return 0, 0
    # ⚠️ A scalable instruction is emitted once per LANE -- `add_m_b__l0`,
    # `__l1`, and so on -- so its origin is lowered when its lanes are. The
    # roundtrip fixtures take the same view of the same fact: the lanes
    # instantiated from one scalable instruction are that instruction.
    def origin(name: str) -> str:
        return ident(re.sub(r"__l\d+(__defined)?$", "", name))

    lowered = {origin(m) for m in
               re.findall(r"^define [^@]*@axis_eval_(\w+)\(", ll, re.M)}
    lowered |= {origin(m) for m in
                re.findall(r"^define void @axis_eff_(\w+)\(", ll, re.M)}
    explained = {origin(name) for name, why in
                 re.findall(r"^; axis_(?:eval|eff)_(\w+): (.*)$", ll, re.M)
                 if NOT_A_REASON not in why}

    silent = sorted(instructions - lowered - explained)
    for mnemonic in silent:
        print(f"  FAIL {axis_file.name}: {mnemonic} has no LLVM function and no "
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
            continue                    # a corpus this emitter is not run on
        if seen:
            corpora += 1
            total += seen
            failures += bad
    print(f"{total} instruction(s) over {corpora} corpus/corpora, "
          f"{failures} unaccounted for")
    print("every instruction lowered or named: "
          + ("PASS" if not failures else "FAIL"))
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
