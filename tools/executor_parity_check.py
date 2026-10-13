#!/usr/bin/env python3
"""The C and Rust executors perform the same instructions, or say why not.

Two executors generated from one description should be able to run the same
program. Where they cannot, the difference is a fact about a language rather
than about the instruction -- Rust's `f64` rounds to nearest-even and `std`
exposes no `fesetround`, so eleven AArch64 double-precision forms that read
their rounding mode from `fpcr` are performed by the C executor and not the
Rust one.

That is a legitimate difference and it is not the thing this gate is about.
What it is about is whether the difference is *stated*. It was not: the Rust
emitter simply left the function out, so a reader could not tell an instruction
Rust has no way to perform from a file that had been truncated, and the only
place the gap appeared was a decline line in another gate's output -- which is
not in the artifact at all. `emit-llvm-ir` has always written its refusals into
the file it emits; this holds the Rust executor to the same standard.

So: every instruction the C executor performs and the Rust one does not must be
named, with a reason, in the Rust file itself. An unnamed difference fails, and
the failure says which instruction.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, verb: str) -> str:
    return subprocess.run([*axis_prefix(), verb, str(axis_file)],
                          capture_output=True, text=True, check=True,
                          cwd=AXIS_ROOT).stdout


def check(axis_file: Path) -> int:
    c_text = emit(axis_file, "emit-exec-c")
    rs_text = emit(axis_file, "emit-exec-rust")
    in_c = {m.lower() for m in re.findall(r"axis_exec64_eff_(\w+)\(", c_text)}
    in_rust = {m.lower() for m in re.findall(r"fn axis_exec64_eff_(\w+)\(", rs_text)}
    # The refusals the Rust artifact states, by name.
    named = {m.lower() for m in re.findall(r"^//   (\w+): ", rs_text, re.M)}

    only_c = in_c - in_rust
    only_rust = in_rust - in_c
    unnamed = sorted(only_c - named)
    stale = sorted(named & in_rust)

    print(f"{axis_file.name}: C performs {len(in_c)}, Rust {len(in_rust)}; "
          f"{len(only_c)} in C only, {len(named)} named in the Rust file")
    failures = 0
    for mnemonic in unnamed:
        print(f"  FAIL {mnemonic}: the C executor performs it, the Rust one does "
              f"not, and the Rust file does not say why")
        failures += 1
    for mnemonic in sorted(only_rust):
        print(f"  FAIL {mnemonic}: the Rust executor performs it and the C one "
              f"does not, which no language difference explains")
        failures += 1
    # A reason for something it does perform is a reason that has gone stale.
    for mnemonic in stale:
        print(f"  FAIL {mnemonic}: named as unperformable, but a function for it "
              f"is emitted")
        failures += 1
    return failures


def main() -> int:
    files = [Path(arg) for arg in sys.argv[1:]]
    if not files:
        files = sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    failures = 0
    checked = 0
    for axis_file in files:
        try:
            failures += check(axis_file)
            checked += 1
        except subprocess.CalledProcessError:
            continue                    # a corpus neither executor is emitted for
    print(f"{checked} corpus/corpora compared")
    print("executors agree, or say why not: " + ("PASS" if not failures else "FAIL"))
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
