#!/usr/bin/env python3
"""An instruction nothing selects is an instruction nobody has. Gate.

AXIS emits a selection pattern for each instruction it can, and two things
already check them. `llvm_patterns_check.py` evaluates a pattern's DAG against
the golden model, so a pattern that said `or` where the instruction computes
`and` is caught. `llvm_target_check.py` hands the whole target to `llvm-tblgen`
and compares the generated ENCODER against AXIS's own.

Neither answers the question a compiler writer asks. `--gen-dag-isel` builds
the matcher LLVM's instruction selector actually uses, and the existing check
of it is an AGGREGATE: it fails only when the matcher selects *none* of the
target's instructions. One instruction whose pattern tblgen quietly drops --
unreachable, out-ranked, mistyped in a way that is legal but never matches --
passes today, because the other ten still select.

So this is a CENSUS, per instruction, the way the SMT gate is a census:

  * **every instruction that declares a pattern is in the matcher.** That is
    the property. A pattern emitted and then dropped is the silent form of
    shipping an instruction no compiler will ever choose;
  * **the unselectable are NAMED, with their reason** -- no pattern declared,
    or a pattern declared and dropped. Those are different findings and a
    count that merged them would hide the second behind the first;
  * **the census is not vacuous**: a target with no patterns at all is
    declined rather than passed, because a matcher is emitted even with none.

⚠️ What this still does not do is compile a program. Whether a compiler
choosing between instructions picks this one for real code needs the target
linked into `llc`, and `llc` here has never heard of it. This proves the
matcher CAN select the instruction, not that a compiler WOULD -- and saying
which of the two a gate measures is the difference between a result and a
slogan.

Usage: tools/selectable_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import llvm_target_check as backend  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

INSTRUCTION = re.compile(r"^def (\w+) : \w+Inst<", re.M)
#: The instruction a `Pat<>` selects is the first target instruction named in
#: its replacement DAG.
PATTERN = re.compile(r"^def : Pat<(.*?)>;\s*$", re.M | re.S)


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    name = axis_file.stem
    tb, inc = backend.find_tblgen(), backend.find_include()
    if tb is None or inc is None:
        print(f"  {name}: DECLINED no llvm-tblgen or no LLVM include directory "
              f"on this host; the matcher is LLVM's to build")
        return 0, 0
    td = work / f"{name}.td"
    td.write_text(subprocess.run(
        [*axis_prefix(), "emit-llvm-target", str(axis_file)],
        check=True, capture_output=True, text=True, cwd=AXIS_ROOT).stdout)
    text = td.read_text()

    declared = set(INSTRUCTION.findall(text))
    if not declared:
        print(f"  {name}: DECLINED the target declares no instructions")
        return 0, 0
    # Which instructions a pattern claims to select.
    patterned: set[str] = set()
    for body in PATTERN.findall(text):
        named = set(re.findall(r"\b([A-Z][A-Z0-9_]*)\b", body)) & declared
        patterned |= named
    # ⚠️ A SECOND ARTIFACT, so that emitting nothing is a failure rather than
    # a decline. `emit-llvm-patterns` derives its patterns from the same
    # `formal_semantics` and names the instruction each one is for, so it says
    # independently which instructions AXIS believes are selectable. Without
    # this, a target that stopped emitting patterns altogether would pass
    # straight through the vacuity check and report nothing wrong -- the
    # classic shape of a gate measuring less than its name.
    hinted = set(re.findall(
        r"^// (\w+) => llvm\.", subprocess.run(
            [*axis_prefix(), "emit-llvm-patterns", str(axis_file)],
            check=True, capture_output=True, text=True, cwd=AXIS_ROOT).stdout,
        re.M))
    if not patterned and not hinted:
        print(f"  {name}: DECLINED neither artifact claims a selectable "
              f"instruction, so there is nothing here a matcher could miss")
        return 0, 0

    try:
        backend.tablegen(tb, inc, td, "gen-dag-isel", work / "isel.inc")
    except SystemExit as error:
        print(f"  FAIL {name}: llvm-tblgen would not build a matcher: "
              f"{str(error)[:200]}")
        return 1, 1
    isel = (work / "isel.inc").read_text()
    # ⚠️ Intersected with this target's own instructions. LLVM's matcher always
    # carries its own entries, so names alone prove nothing.
    selectable = set(re.findall(r"TARGET_VAL\((?:\w+)::(\w+)\)", isel)) & declared

    checks = failures = 0

    # ⚠️ The two emitters agree about WHICH instructions are selectable. They
    # read the same semantics; a divergence means one of them changed and the
    # other did not.
    checks += 1
    missing = sorted(hinted - patterned)
    if missing:
        print(f"  FAIL {name}: `emit-llvm-patterns` hints a pattern for "
              f"{len(missing)} instruction(s) that the generated target does "
              f"not carry one for: {missing[:6]}")
        failures += 1

    # ⚠️ Not vacuous: a matcher is emitted even with no patterns at all.
    checks += 1
    if not selectable:
        print(f"  FAIL {name}: {len(patterned)} instruction(s) declare a "
              f"pattern and the matcher selects none of them")
        return checks, 1

    # THE PROPERTY: a declared pattern reaches the matcher.
    dropped = sorted(patterned - selectable)
    checks += 1
    if dropped:
        print(f"  FAIL {name}: {len(dropped)} instruction(s) declare a "
              f"selection pattern that llvm-tblgen did not put in the "
              f"matcher: {dropped[:6]}; a pattern emitted and then dropped is "
              f"an instruction no compiler will ever choose")
        failures += 1

    # ⚠️ Said out loud, and by REASON. An instruction with no pattern and one
    # whose pattern was dropped are different findings.
    silent = sorted(declared - patterned)
    if silent:
        print(f"  {name}: {len(silent)} instruction(s) declare no selection "
              f"pattern and are reachable only by intrinsic: {silent[:6]}"
              f"{' ...' if len(silent) > 6 else ''}")

    if not failures:
        print(f"  {name}: {len(declared)} instruction(s), {len(patterned)} "
              f"declare a pattern, {len(patterned & selectable)} of those are "
              f"in LLVM's matcher, {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "zbb_like.axisl"]
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
        print("a declared pattern reaches the matcher: SKIP")
        return DECLINED
    print(f"a declared pattern reaches the matcher: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
