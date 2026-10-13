#!/usr/bin/env python3
"""A move is done at rename. Gate.

`(window ... (eliminate moves))` (docs/rename_design.md, ME1): a machine that
renames gives a move's destination the register its source already has. The
move is an entry in the window and nothing else. Which instructions are moves
is told from what they compute -- here an add of the zero register -- and
this gate builds its own machines, alike but for the clause, to hold both
engines to what follows:

  * **a move is no link in a chain**: six adds, each through a move, are six
    cycles a trip where moves are done at rename and twelve where they are
    executed -- and through two moves each, six and eighteen;
  * **a move is done when what it read is**: a multiply and a move of it,
    carried round, are the multiply's latency a trip and not a cycle less;
  * **what reads a move wakes as for what the move read**: with a scheduler
    loop of two cycles the same chain is twelve a trip, not six and not
    twenty-four;
  * **a move takes no unit**: four adds, four moves and a counter on one
    adder are nine cycles a trip executed and five done at rename;
  * **nor a slot of the issue queue, nor a register**: moves that wait for a
    slow multiply fill a queue of four, or a pool of six registers, and hold
    the next multiply out of the window; done at rename they hold neither,
    and the loop runs at the multiply's latency exactly;
  * **an add of something is not a move**, and neither is a multiply by the
    zero register: both cost the same on every machine;
  * **a squashed move gives back what it held**: behind a branch nothing
    learns, the same loop ends, and no later than with its moves executed;
  * every program retires the same instructions and leaves the same registers
    and memory on every machine, on both engines;
  * and validation refuses to eliminate anything but moves, or to do it on a
    machine with no window.

Usage: tools/move_check.py
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
ZERO, CHAIN, VIA, SLOW = 0, 14, 15, 16
FLIP, FLOP = 28, 29

CORE = """
  (defcore mv_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob 64) (issue-queue {queue}) (commit-width 8){schedule}{eliminate})
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)){execute}{rename}
    (units (alu (count {alus}) (pipelined true)) (mul (count 2) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true))))
"""

#: name -> what differs from the plain machine; each has a twin that eliminates.
KINDS = {"wide": {}, "sched": {"schedule": " (schedule 2)"}, "one": {"alus": 1},
         "queue": {"queue": 4}, "pool": {"rename": "\n    (rename (rv_gpr 6))"}}
MACHINES = {f"{kind}{suffix}": dict(spec, eliminate=" (eliminate moves)" if suffix else "")
            for kind, spec in KINDS.items() for suffix in ("", "_elim")}

#: Descriptions validation must refuse, and a word of why.
REFUSED = {
    "something that is not a move": ("(window (rob 64) (issue-queue 64) (commit-width 8) "
                                     "(eliminate adds))", "moves"),
    "no window to rename in": ("(window (commit-width 1) (eliminate moves))", "no window"),
}


def core(engine, name, spec):
    fields = {"queue": 64, "schedule": "", "eliminate": "", "rename": "", "alus": 8, **spec}
    return CORE.format(engine=engine, name=name, isa=ISA,
                       execute=" (engine execute)" if engine == "x" else "", **fields)


def build_programs(asm: Assembler, bnz):
    add, mul = asm.fast_add, asm.slow
    move = lambda to, frm: asm.op(add, to, frm, ZERO)  # noqa: E731
    step = asm.op(add, COUNTER, COUNTER, MINUS_ONE)

    def loop(body):
        return body + [step, bnz(COUNTER, 0, -4 * (len(body) + 1)), asm.op(add, 24, 1, 1), 0]

    programs = {}
    # CHAIN: an add, and a move of it, and an add to the move ... one chain,
    # carried round the loop. CHAIN2: two moves between each pair of adds.
    programs["CHAIN"] = loop([w for _ in range(LINKS)
                              for w in (asm.op(add, CHAIN, VIA, ONE), move(VIA, CHAIN))])
    # The second of them names the zero register FIRST: an add is a move
    # whichever of the two it adds nothing to.
    programs["CHAIN2"] = loop([w for _ in range(LINKS)
                               for w in (asm.op(add, CHAIN, VIA, ONE), move(17, CHAIN),
                                         asm.op(add, VIA, ZERO, 17))])
    # ADDS: the same chain with an add of ONE where each move was -- which is
    # no move. MULZ: a chain of multiplies by the zero register, which is not
    # one either.
    programs["ADDS"] = loop([w for _ in range(LINKS)
                             for w in (asm.op(add, CHAIN, VIA, ONE), asm.op(add, VIA, CHAIN, ONE))])
    programs["MULZ"] = loop([asm.op(mul, SLOW, SLOW, ZERO)])
    # APART: four adds and four moves that wait for nothing.
    programs["APART"] = loop([asm.op(add, 20 + k, ONE, ONE) for k in range(4)]
                             + [move(26 + k, ONE) for k in range(4)])
    # SLOWLY: a multiply and a move of it, carried round: the move is done
    # when the multiply is, not when the multiply starts.
    programs["SLOWLY"] = loop([asm.op(mul, SLOW, VIA, ONE), move(VIA, SLOW)])
    # ⚠️ HELD: a multiply carried round the loop, a second multiply of what it
    # makes, and six moves of THAT -- which wait for it, and while they wait
    # hold whatever a move holds. The second multiply cannot start until the
    # first is done, so its moves wait through the cycle the next trip's
    # multiply has to be in the window by: moves of the first alone were
    # done as soon as it started, and held nothing for long enough to count.
    programs["HELD"] = loop([asm.op(mul, SLOW, SLOW, ONE), asm.op(mul, 17, SLOW, ONE)]
                            + [move(20 + k, 17) for k in range(6)])
    # ⚠️ TURNS: the same, behind a branch taken every other trip -- which two
    # bit counters never learn. On the engine that fetches what it predicts,
    # moves of the wrong path are in the window, waiting for the multiply,
    # when the branch is found out: what they held has to be given back.
    programs["TURNS"] = loop([move(13, FLIP), move(FLIP, FLOP), move(FLOP, 13),
                              bnz(FLIP, 0, 8), asm.op(add, 18, 18, ONE),
                              asm.op(mul, SLOW, SLOW, ONE), asm.op(mul, 17, SLOW, ONE)]
                             + [move(20 + k, 17) for k in range(6)])
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

    for why, (window, word) in REFUSED.items():
        text = core("x", "bad", {}).replace(
            "(window (rob 64) (issue-queue 64) (commit-width 8))", window)
        done = run_cmd([*axis_prefix(), "check", str(corpus_with(text, "refused"))], check=False)
        checks += 1
        if window not in text or done.returncode == 0 or word not in done.stdout + done.stderr:
            fail(f"eliminating with {why} was not refused for it: "
                 f"{(done.stdout + done.stderr).strip()[:160]}")

    cores = "".join(core(engine, name, spec)
                    for name, spec in MACHINES.items() for engine in ("t", "x"))
    corpus = corpus_with(cores, "mv")
    again = work / "mv_again.axisl"
    run_cmd([*axis_prefix(), "emit-lisp", str(corpus), "-o", str(again)])
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    twice = json.loads(run_cmd([*axis_prefix(), "emit-json", str(again)]).stdout)
    said_so = lambda doc: {c["name"]: c.get("eliminate", "") for c in doc.get("cores", [])  # noqa: E731
                           if c["name"].startswith("mv_")}
    checks += 1
    if said_so(facts) != said_so(twice) or said_so(facts) != {
            f"mv_{e}_{n}": "moves" if n.endswith("_elim") else "" for n in MACHINES for e in ("t", "x")}:
        fail(f"what the description eliminates is not what is read back: {said_so(twice)}")

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "mv_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("mv_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None:
        sys.modules.pop("mv_lift", None)
        print(f"  mv: DECLINED {asm.missing() or 'no branch'}")
        return 0, 0
    programs = build_programs(asm, bnz)
    slow = latency_of[asm.slow]
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    sys.modules.pop("mv_lift", None)
    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF, slot(ZERO): 0,
             slot(FLIP): 0, slot(FLOP): 1}
    tags = [(f"{engine}_{machine}", f"mv_{engine}_{machine}")
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
        who = lambda machine: f"mv_{engine}_{machine}"  # noqa: E731

        def grew(program, machine):
            return (said[f"{program}_{engine}_{machine}_{LONG}"]["cycles"]
                    - said[f"{program}_{engine}_{machine}_{SHORT}"]["cycles"])

        def expect(program, machine, a_trip, why):
            nonlocal checks
            checks += 1
            if grew(program, machine) != more * a_trip:
                fail(f"{more} more trips of {program} took {grew(program, machine)} cycles on "
                     f"{who(machine)}; {why} -- {a_trip} a trip, {more * a_trip}")

        # A move is no link in a chain.
        expect("CHAIN", "wide", 2 * LINKS, f"{LINKS} adds and {LINKS} moves in one chain, each executed")
        expect("CHAIN", "wide_elim", LINKS, f"{LINKS} adds in one chain and {LINKS} moves done at rename")
        expect("CHAIN2", "wide", 3 * LINKS, f"{LINKS} adds and {2 * LINKS} moves in one chain")
        expect("CHAIN2", "wide_elim", LINKS, f"{LINKS} adds, and moves of moves done at rename")
        # What reads a move wakes as for what the move read.
        expect("CHAIN", "sched", 4 * LINKS, f"{2 * LINKS} links, two cycles of scheduler each")
        expect("CHAIN", "sched_elim", 2 * LINKS,
               f"{LINKS} adds two cycles of scheduler apart, a move between them or not")
        # An add of something is not a move, nor a multiply by nothing.
        for machine in ("wide", "wide_elim"):
            expect("ADDS", machine, 2 * LINKS, f"{2 * LINKS} adds in one chain, none of them a move")
            expect("MULZ", machine, slow, f"a multiply of {slow} cycles carried round, which is no move")
        # A move is done when what it read is.
        expect("SLOWLY", "wide", slow + 1, f"a multiply of {slow} cycles and a move of it, carried round")
        expect("SLOWLY", "wide_elim", slow, f"a multiply of {slow} cycles, and a move that is done when it is")
        # A move takes no unit.
        expect("APART", "one", 9, "four adds, four moves and the counter on one adder")
        expect("APART", "one_elim", 5, "four adds and the counter on one adder, the moves on none")
        # Nor a slot of the issue queue, nor a register.
        for kind, what in (("queue", "a queue of four"), ("pool", "six registers to rename with")):
            expect("HELD", f"{kind}_elim", slow,
                   f"a multiply of {slow} cycles carried round, and moves that hold nothing of {what}")
            checks += 1
            if grew("HELD", kind) <= more * slow:
                fail(f"{more} more trips of HELD took {grew('HELD', kind)} cycles on {who(kind)}, "
                     f"no more than the multiply's {more * slow}; six moves waiting for it "
                     f"fill {what} and keep the next multiply out")
            # ... and what a squashed move held is given back: the loop behind a
            # branch nothing learns still ends, and no later than executed.
            checks += 1
            if grew("TURNS", f"{kind}_elim") > grew("TURNS", kind):
                fail(f"{more} more trips of TURNS took {grew('TURNS', f'{kind}_elim')} cycles on "
                     f"{who(f'{kind}_elim')} and {grew('TURNS', kind)} on {who(kind)}; a move "
                     f"done at rename holds less, so no more")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_mv_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL mv: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a move is done at rename: SKIP")
        return DECLINED
    print(f"a move is done at rename: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
