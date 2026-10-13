#!/usr/bin/env python3
"""Every instruction that names a routine actually reaches it, in both executors.

`implementation_routine_check` proves the hook WORKS: it supplies a routine,
runs the instruction and watches the answer arrive. It does that for one
instruction in a corpus written for the purpose, which was the whole population
until AArch64's pointer-authentication family started naming routines too.

This asks the question that scales instead: for every instruction in a real
corpus that names a routine, does the generated code call THAT symbol, and is
there nothing else that would answer first? It cannot check what the routine
computes -- nothing here knows, which is why the routine exists -- so it checks
the three things that are knowable and that a silent regression would break.

⚠️ It does NOT check for shadowing -- an instruction that names a routine and
also states semantics, where `axis_exec_apply64` would match the effect
function first and never call the routine. That was the check this gate was
written around, and it turned out to be unreachable: `validate_document`
already refuses the corpus outright, saying that stating both "leaves two
answers to one question". A gate guarding a state the parser will not produce
measures nothing, so it is not here.
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def declared(source: str) -> tuple[dict[str, str], list[str]]:
    """Which instructions name a routine, and which name none, as written.

    Read from the corpus rather than from a generated artifact: the generated
    artifacts are what this gate is checking, so taking the expectation from
    one of them would compare a file against itself.
    """
    routines: dict[str, str] = {}
    unsupplied: list[str] = []
    for block in source.split("(definstruction ")[1:]:
        name = re.search(r"\(mnemonic\s+([A-Za-z0-9_]+)\)", block)
        answer = re.search(r"\(implementation\s+([A-Za-z0-9_]+)\)", block)
        if not name or not answer:
            continue
        if answer.group(1) == "unsupplied":
            unsupplied.append(name.group(1))
        else:
            routines[name.group(1)] = answer.group(1)
    return routines, unsupplied


def emit(axis_file: Path, command: str, out: Path) -> str:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   check=True, capture_output=True)
    return out.read_text()


def main() -> int:
    axis_file = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if axis_file is None or not axis_file.exists():
        print("usage: implementation_dispatch_check.py <corpus.axisl>")
        return FAILED
    routines, unsupplied = declared(axis_file.read_text())
    if not routines and not unsupplied:
        print("implementation dispatch: SKIP (this corpus names no routine)")
        return DECLINED

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        c = emit(axis_file, "emit-exec-c", workdir / "axis_exec.h")
        rust = emit(axis_file, "emit-exec-rust", workdir / "axis_exec.rs")

    problems: list[str] = []
    for mnemonic, symbol in sorted(routines.items()):
        ident = mnemonic  # the emitters use the mnemonic as the identifier
        if f"void {symbol}(const axis_lifted" not in c:
            problems.append(f"{mnemonic}: C declares no {symbol}")
        if f"case AXIS_INSN_{ident}: {symbol}(" not in c:
            problems.append(f"{mnemonic}: C does not dispatch to {symbol}")
        if f"void {symbol}(const axis_lifted *lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state, axis_exec_result64 *r) {{" not in c:
            problems.append(f"{mnemonic}: C has no stub for {symbol}")
        if f'"{mnemonic}" => {{ {symbol}(' not in rust:
            problems.append(f"{mnemonic}: Rust does not dispatch to {symbol}")
        if f"fn {symbol}(lifted: &Lifted" not in rust:
            problems.append(f"{mnemonic}: Rust has no stub for {symbol}")

    for mnemonic in sorted(unsupplied):
        if f'case AXIS_INSN_{mnemonic}: r->trapped = 1;' not in c:
            problems.append(f"{mnemonic}: declared unsupplied and C does not trap")
        if f'"{mnemonic}" => {{ result.trap = Some(' not in rust:
            problems.append(f"{mnemonic}: declared unsupplied and Rust does not trap")

    for line in problems:
        print(f"  {line}")
    print(f"{len(routines)} routine(s) named, {len(unsupplied)} unsupplied, "
          f"{len(problems)} problem(s)")
    if routines:
        print("  routines: " + ", ".join(f"{m} -> {s}" for m, s in sorted(routines.items())))
    if unsupplied:
        print("  unsupplied: " + ", ".join(sorted(unsupplied)))
    print("implementation dispatch:", "FAIL" if problems else "PASS")
    return FAILED if problems else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
