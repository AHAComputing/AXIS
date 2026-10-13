#!/usr/bin/env python3
"""A register xor-ed with itself is nothing. Gate.

`(window ... (eliminate zeros))` (docs/rename_design.md, ZI1): an instruction
whose result is nothing whatever its register holds -- a register xor-ed
with itself, or subtracted from itself -- is known to be so when it decodes.
It is an entry in the window, as a move done at rename is, and it waits for
nothing: not for the register it names. Which instructions is told from what
they compute, and the corpus here has none, so this gate adds an xor to it
and builds its own machines, alike but for the clause, to hold both engines
to what follows:

  * **it waits for nothing**: a chain of adds that starts each trip from a
    register xor-ed with itself is one chain round the loop where the xor is
    executed -- it reads the last trip's -- and is no chain where it is known
    to be nothing: the loop then runs exactly as it does started from an add
    of two registers that never change;
  * **two registers are not one**: the same chain started from an xor of the
    register with another is carried round on every machine -- and an add
    of a register to itself is an add;
  * **it takes no unit**: four of them and the counter on one adder are five
    cycles a trip executed, and with them known the loop runs as it does on
    eight adders;
  * **moves are not zeros and zeros are not moves**: a machine that does only
    its moves at rename executes its xors, and one that knows only its zeros
    executes its moves;
  * every program retires the same instructions and leaves the same registers
    and memory on every machine, on both engines;
  * and validation refuses to eliminate anything else, or the same thing
    twice.

Usage: tools/zero_idiom_check.py
"""
from __future__ import annotations

import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from lsq_check import Assembler  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402
from redirect_check import COUNTER, MINUS_ONE, ONE, harness_run  # noqa: E402


AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "issue_width.axisl"
ISA = "iw32"
SHORT, LONG = 16, 32
LINKS = 6
ZERO, CHAIN, OTHER = 0, 14, 15
XOR = "IWXOR"

#: The instruction the corpus lacks.
INSTRUCTION = """
  (definstruction iwxor
    (mnemonic IWXOR)
    (isa iw32)
    (category custom)
    (format R)
    (opcode 0x33)
    (unit alu)
    (operands
      (rd rv_gpr i32 out)
      (rs1 rv_gpr i32 in)
      (rs2 rv_gpr i32 in))
    (asm "iwxor $rd, $rs1, $rs2")
    (semantics "Exclusive or, on the adder")
    (formal (xor i32 rs1 rs2))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 500.0)
    (power-estimate-mw 1.0)
    (expected-speedup 1.0)
    (rationale "Exclusive or, on the adder"))
"""

CORE = """
  (defcore zi_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob 64) (issue-queue 64) (commit-width 8){eliminate})
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 8) (depth 2)){execute}
    (units (alu (count {alus}) (pipelined true)) (mul (count 2) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true))))
"""

MACHINES = {
    "wide": {}, "wide_zeros": {"eliminate": " (eliminate zeros)"},
    "wide_moves": {"eliminate": " (eliminate moves)"},
    "wide_both": {"eliminate": " (eliminate moves zeros)"},
    "one": {"alus": 1}, "one_zeros": {"alus": 1, "eliminate": " (eliminate zeros)"},
}

#: Descriptions validation must refuse, and a word of why.
REFUSED = {
    "something that is neither": ("(eliminate zeros adds)", "each once"),
    "the same thing twice": ("(eliminate zeros zeros)", "each once"),
}


def core(engine, name, spec):
    fields = {"eliminate": "", "alus": 8, **spec}
    return CORE.format(engine=engine, name=name, isa=ISA,
                       execute=" (engine execute)" if engine == "x" else "", **fields)


def build_programs(asm: Assembler, bnz):
    add = asm.fast_add
    step = asm.op(add, COUNTER, COUNTER, MINUS_ONE)
    links = [asm.op(add, CHAIN, CHAIN, ONE)] * LINKS

    def loop(body):
        return body + [step, bnz(COUNTER, 0, -4 * (len(body) + 1)), asm.op(add, 24, 1, 1), 0]

    programs = {}
    # CLEARED: the chain register xor-ed with itself, then six adds to it.
    programs["CLEARED"] = loop([asm.op(XOR, CHAIN, CHAIN, CHAIN)] + links)
    # FRESH: the same chain started from an add of two registers nothing writes.
    programs["FRESH"] = loop([asm.op(add, CHAIN, ONE, ONE)] + links)
    # MIXED: started from an xor of the register with ANOTHER, which is no idiom.
    programs["MIXED"] = loop([asm.op(XOR, CHAIN, CHAIN, OTHER)] + links)
    # DOUBLED: the register ADDED to itself, six times -- which is something.
    programs["DOUBLED"] = loop([asm.op(add, CHAIN, CHAIN, CHAIN)] * LINKS)
    # FOUR: four registers cleared, which wait for nothing either way.
    programs["FOUR"] = loop([asm.op(XOR, 20 + k, 20 + k, 20 + k) for k in range(4)])
    # MOVED: the chain through a move -- an add of the zero register.
    programs["MOVED"] = loop([w for _ in range(LINKS)
                              for w in (asm.op(add, CHAIN, OTHER, ONE), asm.op(add, OTHER, CHAIN, ZERO))])
    return programs


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text()
    end = source.rstrip().rfind(")")

    def corpus_with(cores: str, name: str) -> Path:
        path = work / f"{name}.axisl"
        path.write_text(source[:end] + INSTRUCTION + cores + ")\n")
        return path

    def run_cmd(cmd, check=True):
        return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=AXIS_ROOT)

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {message}")
        failures += 1

    for why, (clause, word) in REFUSED.items():
        text = core("x", "bad", {"eliminate": " " + clause})
        done = run_cmd([*axis_prefix(), "check", str(corpus_with(text, "refused"))], check=False)
        checks += 1
        if done.returncode == 0 or word not in done.stdout + done.stderr:
            fail(f"eliminating {why} was not refused for it: "
                 f"{(done.stdout + done.stderr).strip()[:160]}")

    cores = "".join(core(engine, name, spec)
                    for name, spec in MACHINES.items() for engine in ("t", "x"))
    corpus = corpus_with(cores, "zi")
    again = work / "zi_again.axisl"
    run_cmd([*axis_prefix(), "emit-lisp", str(corpus), "-o", str(again)])
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    twice = json.loads(run_cmd([*axis_prefix(), "emit-json", str(again)]).stdout)
    said_so = lambda doc: {c["name"]: c.get("eliminate", "") for c in doc.get("cores", [])  # noqa: E731
                           if c["name"].startswith("zi_")}
    checks += 1
    if said_so(facts) != said_so(twice) or said_so(facts) != {
            f"zi_{e}_{n}": spec.get("eliminate", "").strip(" ()").removeprefix("eliminate ")
            for n, spec in MACHINES.items() for e in ("t", "x")}:
        fail(f"what the description eliminates is not what is read back: {said_so(twice)}")

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "zi_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("zi_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None or asm.fast_add != "IWADD":
        sys.modules.pop("zi_lift", None)
        print(f"  zi: DECLINED {asm.missing() or 'not the add the programs are written with'}")
        return 0, 0
    programs = build_programs(asm, bnz)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    sys.modules.pop("zi_lift", None)
    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF, slot(ZERO): 0,
             slot(OTHER): 5}
    tags = [(f"{engine}_{machine}", f"zi_{engine}_{machine}")
            for machine in MACHINES for engine in ("t", "x")]
    lines = [f'  go("{p}_{tag}_{trips}", "{core_name}", {p}, {len(programs[p])}, {trips}u);'
             for p in programs for tag, core_name in tags for trips in (SHORT, LONG)]
    said = harness_run(work, manifest, name, ISA, seeds, programs, lines, 8)
    if said is None or any(f"{p}_{tag}_{trips}" not in said
                           for p in programs for tag, _ in tags for trips in (SHORT, LONG)):
        fail("the harness did not run, or some machine reported nothing")
        return checks + 1, failures

    for program in programs:
        for trips in (SHORT, LONG):
            rows = [said[f"{program}_{tag}_{trips}"] for tag, _ in tags]
            checks += 1
            if len({(r["steps"], r["mark"]) for r in rows}) != 1:
                fail(f"{program} retired different instructions or left different registers or "
                     f"memory on different machines: {sorted({r['steps'] for r in rows})}")
    if failures:
        return checks, failures

    more = LONG - SHORT
    for engine in ("t", "x"):
        who = lambda machine: f"zi_{engine}_{machine}"  # noqa: E731

        def grew(program, machine):
            return (said[f"{program}_{engine}_{machine}_{LONG}"]["cycles"]
                    - said[f"{program}_{engine}_{machine}_{SHORT}"]["cycles"])

        def expect(program, machine, a_trip, why):
            nonlocal checks
            checks += 1
            if grew(program, machine) != more * a_trip:
                fail(f"{more} more trips of {program} took {grew(program, machine)} cycles on "
                     f"{who(machine)}; {why} -- {a_trip} a trip, {more * a_trip}")

        def alike(program, machine, as_program, as_machine, why):
            nonlocal checks
            checks += 1
            if grew(program, machine) != grew(as_program, as_machine):
                fail(f"{more} more trips of {program} took {grew(program, machine)} cycles on "
                     f"{who(machine)} and {as_program} {grew(as_program, as_machine)} on "
                     f"{who(as_machine)}; {why}")

        # It waits for nothing.
        for machine in ("wide", "wide_moves"):
            expect("CLEARED", machine, LINKS + 1,
                   f"an xor that reads the last trip's register, and {LINKS} adds to it")
        checks += 1
        if grew("FRESH", "wide") >= more * (LINKS + 1):
            fail(f"{more} more trips of FRESH took {grew('FRESH', 'wide')} cycles on {who('wide')}; "
                 f"a chain that starts again each trip is not carried round")
        for machine in ("wide_zeros", "wide_both"):
            alike("CLEARED", machine, "FRESH", "wide",
                  "a register known to be nothing starts the chain as an add of two that never change does")
        # Two registers are not one.
        for machine in MACHINES:
            if machine.startswith("wide"):
                expect("MIXED", machine, LINKS + 1,
                       f"an xor of the register with another, and {LINKS} adds to it")
                expect("DOUBLED", machine, LINKS, f"{LINKS} adds of a register to itself, in one chain")
        # It takes no unit.
        expect("FOUR", "one", 5, "four xors and the counter on one adder")
        alike("FOUR", "one_zeros", "FOUR", "wide_zeros", "four registers known to be nothing take no adder")
        checks += 1
        if grew("FOUR", "one_zeros") >= more * 5:
            fail(f"{more} more trips of FOUR took {grew('FOUR', 'one_zeros')} cycles on {who('one_zeros')}; "
                 f"only the counter is on the adder")
        # Moves are not zeros and zeros are not moves.
        expect("MOVED", "wide_zeros", 2 * LINKS, f"{LINKS} adds and {LINKS} moves in one chain, each executed")
        for machine in ("wide_moves", "wide_both"):
            expect("MOVED", machine, LINKS, f"{LINKS} adds in one chain and {LINKS} moves done at rename")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_zi_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL zi: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a register xor-ed with itself is nothing: SKIP")
        return DECLINED
    print(f"a register xor-ed with itself is nothing: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
