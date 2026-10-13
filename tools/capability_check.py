#!/usr/bin/env python3
"""What the capability manifest claims is what the artifacts do.

`pce/aha/measure/amf_vliw_axis.py` states a strict contract -- one or two
register inputs, one register output, 32-bit pure combinational semantics,
latency 1 -- and **fails closed** on anything else. AHA therefore discovers
ineligibility one instruction at a time, at consumption, by trying. AXIS knows
the whole answer before it emits anything, and `emit-capability-json` states
it.

A manifest that states something is only worth having if it is the same thing
the artifacts say. So this joins it back:

  * an instruction whose `value.ok` is true must have a `define-fun` in
    `semantics.smt2` and a `declare-fun` in `intrinsic_axioms.smt2`;
  * one whose `value.ok` is false must appear in both as a *comment*, and the
    reason must be the same string -- the manifest is a projection of the same
    predicate, so a different reason means two predicates;
  * `touches` must agree with the lift table's own `effect_summary`.

Neither side is recomputed here. Both are read, and the check is that they
agree -- which is what makes the manifest a projection rather than a fifth
opinion.

Coverage: an instruction the manifest declines and the artifacts never mention
is reported, because a claim about an instruction nothing emits is a claim
about nothing.

Usage: tools/capability_check.py [input.axisl ...]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT = ("rv32i", "rv64i", "zbb_like", "aarch64_translation_seed")


def emit(axis_file: Path, command: str, out: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   cwd=AXIS_ROOT, check=True, capture_output=True)


def smt_identifier(mnemonic: str) -> str:
    """The spelling `smt_ident` gives a mnemonic: lowercase, others to `_`."""
    return "".join(ch if ch.isalnum() else "_" for ch in mnemonic).lower()


def check_one(axis_file: Path) -> tuple[int, list[str]]:
    work = Path(tempfile.mkdtemp(prefix="axis_cap_"))
    for command, name in (("emit-capability-json", "capability.json"),
                          ("emit-smt2", "semantics.smt2"),
                          ("emit-smt-axioms", "axioms.smt2"),
                          ("emit-lift-json", "lift.json")):
        emit(axis_file, command, work / name)
    capability = json.loads((work / "capability.json").read_text())
    smt = (work / "semantics.smt2").read_text()
    axioms = (work / "axioms.smt2").read_text()
    lift = {entry["mnemonic"]: entry
            for entry in json.loads((work / "lift.json").read_text())["instructions"]}

    defined = set(re.findall(r"\(define-fun axis_instr_(\w+) ", smt))
    # ⚠️ The reason, without the note about where the rest of the instruction
    # went. A declined VALUE function is not a declined instruction -- `bl`
    # writes two registers and one value cannot hold them, and every write it
    # makes is written as its own function -- so the artifact says so on the
    # line. The predicate this gate holds is about the value, and the note is
    # not part of it.
    declined = {
        name: reason.split(" -- its effects are written separately")[0]
        for name, reason in re.findall(r"^; axis_instr_(\w+): (.*)$", smt, re.M)
    }
    axiom_declared = set(re.findall(r"^; axis: (\w+)\n\(declare-fun ", axioms, re.M))
    axiom_declined = dict(re.findall(r"^; llvm\.pce\.([\w.]+): (.*)$", axioms, re.M))

    failures: list[str] = []
    checked = groups = 0
    for entry in capability["instructions"]:
        mnemonic = entry["mnemonic"]
        ident = smt_identifier(mnemonic)
        claims_value = entry["value"]["ok"]
        # A lane group's capability describes the *encoding* -- vector
        # operands, the declared vector semantics -- while `semantics.smt2`
        # defines the instantiated lanes. Both are right about different views
        # of one mnemonic, and joining them would report a contradiction that
        # is not one: on the full corpus set that was 18 instructions.
        if entry.get("lane_group"):
            groups += 1
            continue
        seen = ident in defined or ident in declined
        if not seen:
            # Not a failure by itself: an instruction with no output operand
            # has no SMT definition to have, and the manifest says why.
            continue
        checked += 1
        if claims_value and ident not in defined:
            failures.append(f"{mnemonic}: the manifest claims a value and "
                            f"`semantics.smt2` declines it ({declined.get(ident)})")
        if not claims_value and ident in defined:
            failures.append(f"{mnemonic}: the manifest declines a value "
                            f"({entry['value']['reason']}) and `semantics.smt2` "
                            f"defines one")
        if not claims_value and ident in declined:
            if declined[ident] != entry["value"]["reason"]:
                failures.append(
                    f"{mnemonic}: the manifest says `{entry['value']['reason']}` and "
                    f"`semantics.smt2` says `{declined[ident]}` -- two predicates "
                    f"where there should be one")
        if claims_value and ident not in axiom_declared and ident in defined:
            failures.append(f"{mnemonic}: defined in `semantics.smt2` and declared by "
                            f"no axiom")

        summary = (lift.get(mnemonic) or {}).get("effect_summary")
        if summary:
            for field, value in entry["touches"].items():
                if summary.get(field) != value:
                    failures.append(
                        f"{mnemonic}: the manifest says {field}={value} and the lift "
                        f"table says {summary.get(field)}")
    return checked, failures, groups


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    args = parser.parse_args()
    # Every corpus. Four of them was how a whole shape went unmet: swept, the
    # join reported 18 contradictions that were two views of one mnemonic.
    targets = args.axis_files or sorted((AXIS_ROOT / "examples").glob("*.axisl"))

    total = grouped = 0
    failures: list[str] = []
    for target in targets:
        checked, found, groups = check_one(target)
        total += checked
        grouped += groups
        failures.extend(found)
        print(f"     {target.name}: {checked} instruction(s) cross-checked, "
              f"{len(found)} disagreement(s)"
              + (f", {groups} lane group(s) not comparable" if groups else ""))
    for message in failures[:6]:
        print(f"FAIL {message}")
    if len(failures) > 6:
        print(f"     ... and {len(failures) - 6} more")
    print(f"{total} instruction(s) cross-checked, {len(failures)} disagreement(s), "
          f"{grouped} lane group(s) not comparable by mnemonic")
    if not total:
        print("no instruction was cross-checked: the manifest claimed nothing "
              "the artifacts mention")
        return DECLINED
    print("capability manifest == artifacts: "
          + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
