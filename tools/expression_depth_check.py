#!/usr/bin/env python3
"""A description that validates must emit. Gate.

`iterate` bounds its expansion by iteration count and node count, and a
contraction passes both while building a chain as deep as its trip count: a
left-folded `(add acc (mul ...))` is one level per step. Every emitter walks
that chain recursively, so before `MAX_EXPR_DEPTH` existed a K = 1024 dot
product passed `axis check` and then did this:

    thread 'main' has overflowed its stack
    fatal runtime error: stack overflow, aborting

Not a wrong answer -- no answer, and no diagnosis either. That is the worst
shape a limit can have: the language accepted something the artifacts could not
express, and said so by aborting the process.

Three properties:

  1. **what validates, emits.** A document at the limit is emitted by every
     backend without crashing. If the limit were set above what some backend
     survives, this is what would notice;
  2. **what does not validate is REFUSED, not crashed.** One level past the
     limit exits with a diagnosable error naming the depth, and the process
     exits normally. A crash and a refusal are both non-zero exits, so the two
     are told apart by the signal and by the message;
  3. **the deep document is deep.** Its measured depth is checked against what
     the guard reports, so a probe that failed to build a deep expression --
     because the elaborator folded it, say -- cannot pass this as a refusal of
     nothing.

The limit is 400, and the measured walls on a debug build (the worst case,
since its frames are the largest) are: LLVM survives 463 and is gone by 483;
SMT, C and Rust reach about 903; the golden model survived every depth tried.
The deepest expression in the whole corpus is 35.

Injection-checked: raising the limit past LLVM's wall makes property 1 fail as
a crash rather than a mismatch, which is the failure this gate is named for.

Usage: tools/expression_depth_check.py [--limit N]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
EMITTERS = (
    "emit-llvm-ir",
    "emit-smt2",
    "emit-semantics-c",
    "emit-semantics-rust",
    "emit-golden-python",
    "emit-stencil-ll",
)


def document(trip: int) -> str:
    """A dot product of `trip` steps: one level of nesting per step."""
    return f"""(axis-module depth
  (version "0.1.0") (target rvmt) (description "a contraction {trip} deep")
  (defisa d (base rv64im) (word-bits 32) (registers "x[32]:i32" "pc:i32")
    (features custom) (memory-model rvwmo) (endianness little))
  (defformat R (bits 32) (fields (opcode 6 0) (rd 11 7) (func3 14 12)
    (rs1 19 15) (rs2 24 20) (func7 31 25)))
  (definstruction dot
    (mnemonic DOT) (isa d) (category alu) (format R)
    (opcode 11) (func3 0) (func7 0)
    (operands (rd reg i32 out) (rs1 reg i32 in) (rs2 reg i32 in))
    (asm "dot $rd, $rs1, $rs2")
    (semantics "A {trip}-step contraction")
    (formal (iterate i32 (k {trip}) (acc 0)
      (add i32 acc (mul i32 (and i32 (lshr i32 rs1 k) 255)
                            (and i32 (lshr i32 rs2 k) 255)))))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 100.0) (power-estimate-mw 1.0) (expected-speedup 1.0)
    (rationale "depth probe")))
"""


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


def paren_depth(text: str) -> int:
    depth = deepest = 0
    for character in text:
        if character == "(":
            depth += 1
            deepest = max(deepest, depth)
        elif character == ")":
            depth -= 1
    return deepest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=None,
                        help="the limit under test; read from the source by default")
    args = parser.parse_args()

    limit = args.limit
    if limit is None:
        source = (AXIS_ROOT / "src" / "semantics.rs").read_text()
        found = re.search(r"pub const MAX_EXPR_DEPTH: usize = (\d+);", source)
        if not found:
            print("MAX_EXPR_DEPTH is not declared where this expects it")
            return 1
        limit = int(found.group(1))

    workdir = Path(tempfile.mkdtemp(prefix="axis_depth_"))
    failures = 0

    # One level of nesting per step, plus the wrapper the expansion puts around
    # it, so the trip count that lands exactly at the limit is a few short.
    deep_trip = limit + 64
    ok_trip = limit - 24

    # --- 1. what validates, emits ----------------------------------------
    ok_path = workdir / "ok.axisl"
    ok_path.write_text(document(ok_trip))
    checked = run([*axis_prefix(), "check", str(ok_path)])
    if checked.returncode != 0:
        print(f"FAIL a {ok_trip}-step contraction does not validate: {checked.stderr.strip()[:200]}")
        return 1
    emitted_depth = 0
    for emitter in EMITTERS:
        output = workdir / f"ok.{emitter}"
        result = run([*axis_prefix(), emitter, str(ok_path), "-o", str(output)])
        if result.returncode != 0:
            crashed = result.returncode < 0 or "overflowed its stack" in result.stderr
            print(f"FAIL {emitter} {'CRASHED' if crashed else 'failed'} on a document "
                  f"that validates: {result.stderr.strip()[:160]}")
            failures += 1
    json_path = workdir / "ok.json"
    if run([*axis_prefix(), "emit-json", str(ok_path), "-o", str(json_path)]).returncode == 0:
        semantics = json.loads(json_path.read_text())["instructions"][0]["formal_semantics"]
        emitted_depth = paren_depth(semantics)

    # --- 2 and 3. past the limit is refused, and is really deep ----------
    deep_path = workdir / "deep.axisl"
    deep_path.write_text(document(deep_trip))
    refused = run([*axis_prefix(), "check", str(deep_path)])
    message = (refused.stdout + refused.stderr).strip()
    reported = re.search(r"nests (\d+) deep", message)
    if refused.returncode == 0:
        print(f"FAIL a {deep_trip}-step contraction was accepted; the guard did not fire")
        failures += 1
    elif refused.returncode < 0 or "overflowed its stack" in message:
        print(f"FAIL a {deep_trip}-step contraction CRASHED rather than being refused")
        failures += 1
    elif not reported:
        print(f"FAIL refused without naming the depth: {message[:200]}")
        failures += 1
    elif int(reported.group(1)) <= limit:
        print(f"FAIL the guard reports {reported.group(1)}, which is inside the limit")
        failures += 1

    print(f"limit {limit}: a {ok_trip}-step contraction emits through "
          f"{len(EMITTERS)} backends at depth {emitted_depth}")
    print(f"  a {deep_trip}-step one is refused, reporting depth "
          f"{reported.group(1) if reported else '?'}")
    if emitted_depth and emitted_depth > limit:
        print(f"the document that emitted is {emitted_depth} deep, past the limit it passed")
        failures += 1
    if emitted_depth and emitted_depth < limit // 2:
        print(f"the document that emitted is only {emitted_depth} deep; this proves "
              f"nothing about the limit")
        failures += 1
    print("expression depth: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
