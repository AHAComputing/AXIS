#!/usr/bin/env python3
"""An address formed into the load that uses it. Gate.

`(timing (fuse (ADD LOAD)))` (docs/rename_design.md, FU2): the tail of a pair
may be a load. The pair is then the LOAD's operation -- its entry, its unit,
its queue -- and the head is what follows: done when what it read is, with no
entry, width, queue slot or unit of its own. Only when the load writes every
register the head wrote, so that nothing else is given the head's result for
nothing. This gate builds its own machines, alike but for the clause, to hold
both engines to what follows:

  * **the pair is the load's cycles**: an add and a load through it, carried
    round, are the load's latency and one a link, and the load's latency
    fused; a multiply and a load through it are the multiply's;
  * **two words are not a pair because their mnemonics are**: a load into
    another register than the add's, a load with something between, and a
    pair the core does not name cost what they cost unfused;
  * **one slot of the dispatch width, and of the commit width**: six links,
    the counter and its branch through a width of two are seven cycles a
    trip, and four fused;
  * **one entry, one register**: pairs behind a slow multiply fill a window
    of twelve, or eleven registers; fused they do not;
  * **a squashed head gives back what it held**;
  * every program retires the same instructions and leaves the same registers
    and memory on every machine, on both engines;
  * and validation refuses a tail that stores and a head that loads.

Usage: tools/fuse_load_check.py
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
from redirect_check import BASE, COUNTER, MINUS_ONE, ONE, harness_run  # noqa: E402


AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "issue_width.axisl"
ISA = "iw32"
SHORT, LONG = 16, 32
ZERO, WALK, OTHER, SLOW = 0, 14, 15, 16
FLIP, FLOP = 28, 29
DATA = 0x4000
ADD, MUL, BNZ, LOAD, STORE = "IWADD", "IWMUL", "IWBNZ", "IWLW", "IWSW"
ALL = f"({ADD} {LOAD}) ({MUL} {LOAD})"

CORE = """
  (defcore fl_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob {rob}) (issue-queue 64) (commit-width {commit}){dispatch})
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 8) (depth 2)){execute}{rename}{fuse}
    (units (alu (count 8) (pipelined true)) (mul (count 2) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 8) (pipelined true))))
"""

#: name -> what differs from the plain machine; each has a twin that fuses.
KINDS = {"wide": {}, "disp": {"dispatch": " (dispatch-width 2)"}, "commit": {"commit": 2},
         "rob": {"rob": 12}, "pool": {"rename": "\n    (rename (rv_gpr 11))"}}
MACHINES = {f"{kind}{suffix}": dict(spec, fuse=f"\n    (timing (fuse {ALL}))" if suffix else "")
            for kind, spec in KINDS.items() for suffix in ("", "_fuse")}
# One that fuses adds with adds and no load with anything.
MACHINES["adds_only"] = {"fuse": f"\n    (timing (fuse ({ADD} {ADD})))"}

#: Timing clauses validation must refuse, and a word of why.
REFUSED = {
    "a tail that stores": (f"(timing (fuse ({ADD} {STORE})))", "touches memory"),
    "a head that loads": (f"(timing (fuse ({LOAD} {ADD})))", "touches memory"),
}


def core(engine, name, spec):
    fields = {"rob": 64, "commit": 8, "dispatch": "", "rename": "", "fuse": "", **spec}
    return CORE.format(engine=engine, name=name, isa=ISA,
                       execute=" (engine execute)" if engine == "x" else "", **fields)


def build_programs(asm: Assembler, bnz):
    add, mul = asm.fast_add, asm.slow
    step = asm.op(add, COUNTER, COUNTER, MINUS_ONE)

    def loop(body):
        return body + [step, bnz(COUNTER, 0, -4 * (len(body) + 1)), asm.op(add, 24, 1, 1), 0]

    # Memory at DATA holds nothing: a load through `r + BASE` leaves 0 in `r`,
    # and the next address is formed from it. Carried round the loop.
    link = lambda r: [asm.op(add, r, r, BASE), asm.ld(r, r, 0)]  # noqa: E731
    programs = {}
    # WALK: four links in one chain.
    programs["WALK"] = loop(link(WALK) * 4)
    # LIVE: the same chain, the address left in a register of its own.
    programs["LIVE"] = loop([w for _ in range(4)
                             for w in (asm.op(add, OTHER, WALK, BASE), asm.ld(WALK, OTHER, 0))])
    # BETWEEN: the chain with an add of something else inside every link.
    programs["BETWEEN"] = loop([w for _ in range(4)
                                for w in (asm.op(add, WALK, WALK, BASE), asm.op(add, 20, ONE, ONE),
                                          asm.ld(WALK, WALK, 0))])
    # MULWALK: a multiply by one, of the base, and a load through it.
    programs["MULWALK"] = loop([asm.op(mul, SLOW, BASE, ONE), asm.ld(SLOW, SLOW, 0),
                                asm.op(add, BASE, BASE, SLOW)])
    # PAIRS: six links that wait for nothing, then the counter and its branch.
    apart = lambda n: [w for k in range(n)  # noqa: E731
                       for w in (asm.op(add, 17 + k, ZERO, BASE), asm.ld(17 + k, 17 + k, 4 * k))]
    programs["PAIRS"] = loop(apart(6))
    # HELD: two multiplies carried round the loop, and six links between them.
    programs["HELD"] = loop([asm.op(mul, SLOW, SLOW, ONE), asm.op(mul, SLOW, SLOW, ONE)] + apart(6))
    # TURNS: the same behind a branch taken every other trip, which nothing
    # learns: heads of the wrong path are in the window when it is found out.
    programs["TURNS"] = loop([asm.op(add, 13, FLIP, ZERO), asm.op(add, FLIP, FLOP, ZERO),
                              asm.op(add, FLOP, 13, ZERO), bnz(FLIP, 0, 8), asm.op(add, OTHER, ONE, ONE),
                              asm.op(mul, SLOW, SLOW, ONE), asm.op(mul, SLOW, SLOW, ONE)] + apart(6))
    return programs


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text()
    end = source.rstrip().rfind(")")

    def corpus_with(cores: str, name: str) -> Path:
        path = work / f"{name}.axisl"
        path.write_text(source[:end] + cores + ")\n")
        return path

    def run_cmd(cmd, check=True):
        return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=AXIS_ROOT)

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {message}")
        failures += 1

    for why, (clause, word) in REFUSED.items():
        text = core("x", "bad", {"fuse": "\n    " + clause})
        done = run_cmd([*axis_prefix(), "check", str(corpus_with(text, "refused"))], check=False)
        checks += 1
        if done.returncode == 0 or word not in done.stdout + done.stderr:
            fail(f"{why} was not refused for it: {(done.stdout + done.stderr).strip()[:200]}")

    cores = "".join(core(engine, name, spec)
                    for name, spec in MACHINES.items() for engine in ("t", "x"))
    corpus = corpus_with(cores, "fl")
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "fl_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("fl_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None or (asm.fast_add, asm.slow, asm.load[0]) != (ADD, MUL, LOAD):
        sys.modules.pop("fl_lift", None)
        print(f"  fl: DECLINED {asm.missing() or 'not the instructions the pairs name'}")
        return 0, 0
    programs = build_programs(asm, bnz)
    slow, load = latency_of[MUL], latency_of[LOAD]
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    sys.modules.pop("fl_lift", None)
    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF, slot(ZERO): 0,
             slot(FLIP): 0, slot(FLOP): 1, slot(BASE): DATA}
    tags = [(f"{engine}_{machine}", f"fl_{engine}_{machine}")
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
        who = lambda machine: f"fl_{engine}_{machine}"  # noqa: E731

        def grew(program, machine):
            return (said[f"{program}_{engine}_{machine}_{LONG}"]["cycles"]
                    - said[f"{program}_{engine}_{machine}_{SHORT}"]["cycles"])

        def expect(program, machine, a_trip, why):
            nonlocal checks
            checks += 1
            if grew(program, machine) != more * a_trip:
                fail(f"{more} more trips of {program} took {grew(program, machine)} cycles on "
                     f"{who(machine)}; {why} -- {a_trip} a trip, {more * a_trip}")

        # The pair is the load's cycles.
        expect("WALK", "wide", 4 * (load + 1), f"four adds each with a load of {load} cycles through it")
        expect("WALK", "wide_fuse", 4 * load, "four loads, each with its address formed into it")
        expect("MULWALK", "wide", slow + load + 1, f"a multiply of {slow}, a load of {load} through it, and an add")
        expect("MULWALK", "wide_fuse", max(slow, load) + 1, "a multiply formed into the load through it, and an add")
        # Two words are not a pair because their mnemonics are.
        expect("WALK", "adds_only", 4 * (load + 1), "four links on a core that fuses no load")
        for machine in ("wide", "wide_fuse"):
            expect("LIVE", machine, 4 * (load + 1), "four links, each address left in a register of its own")
            expect("BETWEEN", machine, 4 * (load + 1), "four links, each with another add inside it")
        # One slot of the dispatch width, and of the commit width.
        for kind, what in (("disp", "dispatched"), ("commit", "retired")):
            expect("PAIRS", kind, 7, f"fourteen instructions {what} two a cycle")
            expect("PAIRS", f"{kind}_fuse", 4, f"six pairs, the counter and its branch {what} two a cycle")
        # One entry, one register.
        for kind, what in (("rob", "a window of twelve"), ("pool", "eleven registers to rename with")):
            expect("HELD", f"{kind}_fuse", 2 * slow,
                   f"two multiplies of {slow} cycles carried round, and pairs that fit in {what}")
            checks += 1
            if grew("HELD", kind) <= more * 2 * slow:
                fail(f"{more} more trips of HELD took {grew('HELD', kind)} cycles on {who(kind)}, "
                     f"no more than the multiplies' {more * 2 * slow}; six links between them "
                     f"fill {what} and keep the next multiply out")
            # ... and what a squashed head held is given back.
            checks += 1
            if grew("TURNS", f"{kind}_fuse") > grew("TURNS", kind):
                fail(f"{more} more trips of TURNS took {grew('TURNS', f'{kind}_fuse')} cycles on "
                     f"{who(f'{kind}_fuse')} and {grew('TURNS', kind)} on {who(kind)}; a fused "
                     f"pair holds less, so no more")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_fl_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL fl: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("an address formed into the load that uses it: SKIP")
        return DECLINED
    print(f"an address formed into the load that uses it: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
