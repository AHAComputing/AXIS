#!/usr/bin/env python3
"""A calling convention is consistent with itself (stage L4).

`docs/llvm_backend.md` §2 draws the line this gate sits on: **AXIS describes an
instruction set, not a platform.** Which register holds the first argument,
which are callee-saved, how the stack is aligned — none of that follows from
the machine, and a description that inferred it would be inventing a convention
rather than generating one.

So an ABI is *declared*, and what a declaration can be held to is whether it is
consistent with itself. That is not a weak question. The rules below are the
ones a compiler acts on silently when they are wrong, which is the failure mode
worth catching before a single instruction is selected:

  * **the partition.** `reserved`, `callee-saved` and `caller-saved` cover every
    register of every class the ABI puts in a role, exactly once. A register in
    none of them is one a compiler cannot know whether to save across a call; a
    register in two is a contradiction between two statements the same document
    made.
  * an argument or a result never lands in a reserved register. Passing a value
    in the stack pointer, or in a register that discards what is written to it,
    is not a convention anyone can implement.
  * the stack pointer is reserved: an allocatable stack pointer is not one.
  * the frame pointer is callee-saved: a frame pointer the callee does not
    preserve is not one.
  * the stack holds a pointer at its stated alignment.

What is *not* checked, and cannot be: whether the convention matches any real
platform's. AXIS has no way to know that RISC-V's ILP32 puts the first argument
in x10. A description is free to declare a convention nobody else implements —
that is what describing a new machine means — and the gate's business is that
whatever it declared holds together.

The validator decides all of this. This re-derives it from `axis.manifest.v1`,
the way `mapping_legality_check.py` re-derives the modulo tables: two
derivations of one fact, from the artifact rather than from the code that
produced it. `llvm_target_check.py` carries the other half, where LLVM's own
`--gen-callingconv` reads the emitted convention back.

Coverage, per `docs/gate_coverage.md`: a corpus declaring no ABI fails as
vacuous.

Usage: tools/abi_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
# Every AXIS register file is this many registers: the executor, the JIT and
# the LLVM target all index it with a five-bit selector.
FILE_SIZE = 32
ROLES = ("reserved", "callee_saved", "caller_saved")


def check_abi(abi: dict) -> list[str]:
    name = abi["name"]
    failures: list[str] = []

    role_of: dict[tuple[str, int], str] = {}
    for role in ROLES:
        for entry in abi.get(role, []):
            key = (entry[0], entry[1])
            if key in role_of:
                failures.append(
                    f"{name}: `{key[0]} {key[1]}` is both {role_of[key]} and {role}; a "
                    f"register has one role across a call")
                continue
            role_of[key] = role
    for klass in sorted({klass for klass, _ in role_of}):
        missing = [index for index in range(FILE_SIZE)
                   if (klass, index) not in role_of]
        if missing:
            failures.append(
                f"{name}: `{klass}` {missing[0]}"
                + (f"..{missing[-1]}" if len(missing) > 1 else "")
                + " has no role; a compiler cannot know whether a register it was "
                  "told nothing about survives a call")

    for what in ("arguments", "returns"):
        seen: set[tuple[str, int]] = set()
        for entry in abi.get(what, []):
            key = (entry[0], entry[1])
            if key in seen:
                failures.append(f"{name}: `{key[0]} {key[1]}` appears twice in {what}")
            seen.add(key)
            role = role_of.get(key)
            if role is None:
                failures.append(
                    f"{name}: passes {what} in `{key[0]} {key[1]}`, which it gives no role")
            elif role == "reserved":
                failures.append(
                    f"{name}: passes {what} in reserved `{key[0]} {key[1]}`; a reserved "
                    f"register is one no value may be placed in")

    for what, required in (("stack_pointer", "reserved"),
                           ("frame_pointer", "callee_saved")):
        entry = abi.get(what)
        if entry is None:
            continue
        role = role_of.get((entry[0], entry[1]))
        if role != required:
            failures.append(
                f"{name}: {what} `{entry[0]} {entry[1]}` is {role or 'unassigned'}, "
                f"not {required}")
    link = abi.get("link_register")
    if link is not None and role_of.get((link[0], link[1])) == "reserved":
        failures.append(
            f"{name}: link register `{link[0]} {link[1]}` is reserved, and a call "
            f"writes it")

    # F3. What a machine ABI says about aggregates is how a laid-out one is
    # passed, never how it is laid out -- padding and nested alignment are the
    # source language's rule. The two checkable things are that the threshold
    # and the argument registers agree, and that an address passed like an
    # argument is in a register arguments are passed in.
    aggregates = abi.get("aggregates")
    if aggregates is not None:
        pointer_bytes = abi.get("pointer_bits", 32) // 8
        argument_bytes = len(abi.get("arguments", [])) * pointer_bytes
        threshold = aggregates.get("max_register_bytes", 0)
        if threshold <= 0 or threshold % pointer_bytes:
            failures.append(
                f"{name}: an aggregate threshold of {threshold} is not a whole number "
                f"of {pointer_bytes}-byte registers")
        elif threshold > argument_bytes:
            failures.append(
                f"{name}: passes aggregates of up to {threshold} bytes in {argument_bytes} "
                f"bytes of argument registers, so none of them can go by value")
        pointer = aggregates.get("return_pointer")
        if pointer is not None and [pointer[0], pointer[1]] not in [
                list(entry) for entry in abi.get("arguments", [])]:
            failures.append(
                f"{name}: returns aggregates through `{pointer[0]} {pointer[1]}`, which "
                f"is not an argument register")

    pointer_bits = abi.get("pointer_bits", 0)
    alignment = abi.get("stack_alignment", 0)
    if pointer_bits < 8 or pointer_bits & (pointer_bits - 1):
        failures.append(f"{name}: pointer width {pointer_bits} is not a power of two >= 8")
    elif alignment < pointer_bits // 8 or alignment & (alignment - 1):
        failures.append(
            f"{name}: stack alignment {alignment} does not hold a {pointer_bits}-bit "
            f"pointer at a power-of-two boundary")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv32i.axisl")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axis_abi_") as workdir:
        manifest = Path(workdir) / "manifest.json"
        subprocess.run([*axis_prefix(), "emit-json", str(args.axis_file),
                        "-o", str(manifest)],
                       cwd=AXIS_ROOT, check=True, capture_output=True)
        payload = json.loads(manifest.read_text())

    abis = payload.get("abis", [])
    failures: list[str] = []
    for abi in abis:
        failures.extend(check_abi(abi))
        if not failures:
            aggregates = abi.get("aggregates")
            passing = (f", aggregates to {aggregates['max_register_bytes']} bytes"
                       if aggregates else "")
            print(f"     {abi['name']}: {len(abi['arguments'])} argument register(s), "
                  f"{len(abi['callee_saved'])} callee-saved, "
                  f"{len(abi['reserved'])} reserved{passing}")

    for message in failures:
        print(f"FAIL {message}")
    if not abis:
        print("no abi in this corpus: a convention is declared, not derived, so a "
              "corpus without one has nothing for this to check")
        return DECLINED
    print("abi consistency: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
