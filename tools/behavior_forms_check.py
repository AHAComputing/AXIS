#!/usr/bin/env python3
"""The same shorthand means the same thing in both surfaces. Gate.

AXIS turns source-level shorthand into ordinary semantics at elaboration:
bounded loops and contractions, SIMD lanes, the interchange float formats.
Every one of those passes ran on `formal_semantics` and **none ran on
behaviors** -- so none of them could be used where memory is, and none failed
helpfully when tried: `(accumulate ...)` in a behavior reached validation as
"unsupported formal_semantics operator `accumulate`", which is a message about
the typed IR rather than about the form.

Three properties:

  1. **the pairs agree.** Each shorthand appears twice in the corpus -- once as
     a `formal`, once inside a behavior whose result is stored -- and the two
     must elaborate to the same expression. A pass wired into one surface and
     not the other fails exactly here;
  2. **something was actually expanded.** The elaborated expression must differ
     from what the document wrote, or the pair agrees because neither side did
     anything;
  3. **a load nested inside any of these forms elaborates.** ⚠️ This property
     used to assert the opposite -- that such a nesting was REFUSED, because
     the effect model allowed one load per effect, and that was what stopped a
     contraction over memory reads. It admits more than one now (T8b), so the
     same two documents that had to be rejected have to be accepted, and the
     gate says which way round it is rather than being deleted.

Injection-checked: unwiring the loop pass from behaviors fails 1 for the
contraction pair, and unwiring the interchange pass fails it for the bf16 pair.

Usage: tools/behavior_forms_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
PAIRS = (("DOT_FORMAL", "DOT_STORED"), ("LANES_FORMAL", "LANES_STORED"),
         ("BF16_FORMAL", "BF16_STORED"))


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


NESTED = """(axis-module nested
  (version "0.1.0") (target rvmt) (description "a load under a form")
  (defisa n (base rv64im) (word-bits 64) (registers "x[32]:i64" "pc:i64")
    (features simd fp custom) (memory-model rvwmo) (endianness little))
  (defformat R (bits 32) (fields (opcode 6 0) (rd 11 7) (func3 14 12)
    (rs1 19 15) (rs2 24 20) (func7 31 25)))
  (definstruction nested
    (mnemonic NESTED) (isa n) (category custom) (format R)
    (opcode 11) (func3 0) (func7 0) (encoding (rs2 0))
    (operands (rd reg i64 out) (rs1 reg i64 in))
    (asm "nested $rd, $rs1")
    (semantics "A load underneath a form")
    (behavior (set rd BODY))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 1.0) (power-estimate-mw 1.0) (expected-speedup 1.0)
    (rationale "must be refused")))
"""

NESTINGS = {
    "contraction": "(accumulate i64 add (k 2) (order sequential) "
                   "(load i64 unsigned (add i64 rs1 (mul i64 k 8))))",
    "interchange": "(fcvt_f2f f32 bf16 (load i32 unsigned rs1))",
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    workdir = Path(tempfile.mkdtemp(prefix="axis_behforms_"))
    lift = workdir / "lift.json"
    result = run([*axis_prefix(), "emit-lift-json", str(args.axis_file), "-o", str(lift)])
    if result.returncode != 0:
        print(f"FAIL the lift table could not be emitted: {result.stderr.strip()[:200]}")
        return 1
    entries = {entry["mnemonic"]: entry
               for entry in json.loads(lift.read_text())["instructions"]}
    # ⚠️ Compared as TYPED TREES, not as text. Both sides elaborate to the same
    # semantics and render them differently -- the value side round-trips
    # through the typed IR and comes back as `(and i32 rs1 i32:65535)` where
    # the behavior side keeps `(and i32 rs1 0xffff)`. A string comparison would
    # be comparing the renderings, which is not what has to agree.
    if not all(name in entries for pair in PAIRS for name in pair):
        print("no paired behavior forms in this corpus")
        return DECLINED

    failures = 0
    expanded = 0
    # The shorthand each pair is written with. If it survives into the
    # elaborated tree then nothing expanded, and two unexpanded forms agreeing
    # proves nothing at all.
    shorthand = {"DOT_FORMAL": "accumulate", "LANES_FORMAL": "v2i32",
                 "BF16_FORMAL": "bf16"}
    for value_name, stored_name in PAIRS:
        value = entries[value_name].get("semantics_ast")
        stored = entries[stored_name]["effects"][0].get("value_ast")
        if value is None or stored is None:
            failures += 1
            print(f"FAIL {value_name} or {stored_name} carries no typed tree")
            continue
        if value != stored:
            failures += 1
            print(f"FAIL {value_name} and {stored_name} elaborate differently:")
            print(f"     value  {json.dumps(value)[:140]}")
            print(f"     stored {json.dumps(stored)[:140]}")
            continue
        token = shorthand[value_name]
        if token not in json.dumps(value) and token in source:
            expanded += 1

    if expanded != len(PAIRS):
        print(f"only {expanded} of {len(PAIRS)} pairs lost their shorthand; "
              f"agreement between two unexpanded forms proves nothing")
        failures += 1

    # 3. a load nested under a form elaborates, in both directions
    for name, body in NESTINGS.items():
        path = workdir / f"{name}.axisl"
        path.write_text(NESTED.replace("BODY", body))
        checked = run([*axis_prefix(), "check", str(path)])
        message = (checked.stdout + checked.stderr).strip()
        if checked.returncode != 0:
            print(f"FAIL a load nested under a {name} form was refused: {message[:160]}")
            failures += 1

    print(f"{len(PAIRS)} pairs elaborate alike in both surfaces, {expanded} of them "
          f"to something new")
    print(f"  a load under a form elaborates : {len(NESTINGS)} nesting(s) checked")
    print("behavior forms: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
