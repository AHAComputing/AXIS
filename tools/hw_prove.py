#!/usr/bin/env python3
"""The netlist is the instruction, for every input. Proved, not sampled.

`hw_units_check.py` simulates the emitted PyRTL on sixteen vectors an
instruction. That is the right check for the PyRTL -- it is the artifact that
ships -- and a weak one for the lowering, whose mistakes live in corners
sixteen vectors do not reach: the one quotient that overflows, a shift amount
of exactly the width, the carry of a narrow subtract riding a wide adder.

`emit-hw-smt2` writes each netlist as an SMT-LIB function beside the
definition `emit-smt2` already gives the instruction -- a definition written
without knowing the netlist exists. This asks z3 two things:

  1. `axis_hw_<instruction>` equals `axis_instr_<instruction>` on all inputs;
  2. `axis_hw_unit_<unit>`, with its select fixed to a member's code, equals
     that member's netlist on all inputs -- including every value of the ports
     the member does not read.

⚠️ Three answers, counted apart. `unsat` is a proof. `sat` is a counterexample
and fails. `unknown` is z3 running out of time, which is neither -- a 64-bit
multiplier against a 64-bit multiplier written differently is beyond
bit-blasting -- and it is reported by name and bounded by `--expect-unknown`,
so "the solver gave up" can never be read as "proved" and cannot grow
unnoticed either.

Usage: tools/hw_prove.py <input.axisl> [--timeout SECONDS] [--expect-unknown N]

Requires z3 on PATH; exits with a SKIP notice without it.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def operands(fields: list[str]) -> list[tuple[str, int]]:
    return [(name, int(width)) for name, width in (field.rsplit(":", 1) for field in fields)]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--timeout", type=int, default=20,
                        help="seconds z3 may spend on one obligation")
    parser.add_argument("--plan", type=Path, default=None,
                        help="prove the units of this plan (--hw-plan) instead of AXIS's own")
    parser.add_argument("--expect-unknown", type=int, default=None,
                        help="exactly this many obligations may time out")
    args = parser.parse_args()
    if shutil.which("z3") is None:
        print("z3 is not on PATH: SKIP")
        return DECLINED

    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "axis_hw.smt2"
        extra = ["--hw-plan", str(args.plan.resolve())] if args.plan else []
        subprocess.run([*axis_prefix(), "emit-hw-smt2", str(args.axis_file), *extra,
                        "-o", str(path)], check=True, capture_output=True, cwd=AXIS_ROOT)
        text = path.read_text()
        defined = set(re.findall(r"^\(define-fun (\S+) ", text, re.M))

        # The index the emitter wrote, so nothing here re-derives a name.
        instructions: dict[str, tuple[str, str, int, list[tuple[str, int]]]] = {}
        units: dict[str, tuple[str, int, int, list[tuple[str, int]]]] = {}
        members: list[tuple[str, int, str]] = []
        for line in re.findall(r"^; axis-hw (.*)$", text, re.M):
            kind, rest = line.split(" ", 1)
            if kind == "member":
                unit, code, netlist = rest.split()
                members.append((unit, int(code), netlist))
                continue
            label, rest = re.match(r'("(?:[^"\\]|\\.)*") (.*)', rest).groups()
            fields = rest.split()
            if kind == "instruction":
                instructions[fields[0]] = (label, fields[1], int(fields[2]), operands(fields[3:]))
            else:
                units[fields[0]] = (label, int(fields[1]), int(fields[2]), operands(fields[3:]))

        obligations: list[tuple[str, str]] = []
        unreferenced = 0
        for netlist, (label, reference, _, ops) in instructions.items():
            if reference not in defined:
                # `emit-smt2` writes some instructions' values elsewhere (as
                # effects); with no definition there is nothing to prove against.
                unreferenced += 1
                continue
            names = " ".join(f"a_{name}" for name, _ in ops)
            decls = "".join(f"(declare-const a_{name} (_ BitVec {width}))\n" for name, width in ops)
            call = lambda fn: f"({fn} {names})" if ops else fn  # noqa: E731
            obligations.append((f"{label} == its definition",
                                f"{decls}(assert (not (= {call(reference)} {call(netlist)})))\n"))
        by_netlist = {netlist: entry for netlist, entry in instructions.items()}
        for unit, code, netlist in members:
            label, select_width, width, ports = units[unit]
            member_label, _, member_width, ops = by_netlist[netlist]
            port_width = dict(ports)
            decls = "".join(f"(declare-const a_{name} (_ BitVec {w}))\n" for name, w in ports)
            # An operand narrower than its port reads the port's low bits; the
            # rest are left free, so the proof covers whatever sits on them.
            reads = " ".join(
                f"a_{name}" if port_width[name] == w else f"((_ extract {w - 1} 0) a_{name})"
                for name, w in ops)
            alone = f"({netlist} {reads})" if ops else netlist
            if width > member_width:
                alone = f"((_ zero_extend {width - member_width}) {alone})"
            drive = " ".join(f"a_{name}" for name, _ in ports)
            select = f"(_ bv{code} {select_width}) " if select_width else ""
            merged = f"({unit} {select}{drive})" if (select or drive) else unit
            obligations.append((f"{member_label} selected in {label}",
                                f"{decls}(assert (not (= {alone} {merged})))\n"))

        if not obligations:
            print("no netlist has a definition to prove against: SKIP")
            return DECLINED
        query = Path(tmp) / "query.smt2"
        body = [text, f"(set-option :timeout {args.timeout * 1000})\n"]
        for _, obligation in obligations:
            body.append(f"(push)\n{obligation}(check-sat)\n(pop)\n")
        query.write_text("".join(body))
        result = subprocess.run(["z3", str(query)], capture_output=True, text=True)
        answers = [line for line in result.stdout.split("\n") if line in ("sat", "unsat", "unknown")]
        if len(answers) != len(obligations):
            print(result.stdout[-2000:], result.stderr[-2000:], sep="\n")
            print(f"z3 answered {len(answers)} of {len(obligations)} obligations: FAIL")
            return FAILED

    proved = answers.count("unsat")
    refuted = [name for (name, _), answer in zip(obligations, answers) if answer == "sat"]
    unknown = [name for (name, _), answer in zip(obligations, answers) if answer == "unknown"]
    for name in refuted:
        print(f"  FAIL {name}: z3 has a counterexample")
    for name in unknown[:8]:
        print(f"  not proved in {args.timeout}s -- {name}")
    if len(unknown) > 8:
        print(f"  ... and {len(unknown) - 8} more not proved")
    failures = len(refuted)
    if args.expect_unknown is not None and len(unknown) != args.expect_unknown:
        print(f"  FAIL {len(unknown)} obligation(s) not proved, and this corpus is "
              f"expected to have {args.expect_unknown}")
        failures += 1
    if unreferenced:
        print(f"  {unreferenced} netlist(s) have no `emit-smt2` definition to prove against")
    print(f"{len(obligations)} obligation(s): {proved} proved, {len(refuted)} refuted, "
          f"{len(unknown)} not proved")
    print("netlists and units == their definitions (SMT):", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
