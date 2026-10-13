#!/usr/bin/env python3
"""A pair is one operation. Gate.

`(timing (fuse (HEAD TAIL) ...))` (docs/rename_design.md, FU1): a core names
the pairs its decoder fuses. Whether two words are such a pair is told from
the registers they name -- the tail is dispatched straight after the head, in
the same cycle, reads what the head writes, and the two leave one register
between them -- and the pair is then one operation: one entry in the window,
one slot of every width, one unit, one register. This gate builds its own
machines, alike but for the clause, to hold both engines to what follows:

  * **a pair is one link in a chain**: twelve adds to one register are twelve
    cycles a trip and six where add fuses with add -- six, not four: a tail
    is no head -- and a pair is still an entry, which a window of eight has
    too few of;
  * **a pair is the slower one's operation**: a multiply and an add of it,
    or an add and a multiply of it, carried round, are the multiply's
    latency a trip and not a cycle more;
  * **on the tail's unit when neither is slower**: four adds, the counter and
    its branch on one adder are five cycles a trip, and four where the
    counter is fused with the branch and runs where branches do -- unless
    the branch unit's own queue is full, and then the two are two;
  * **one slot of the dispatch width, and of the commit width**: eight pairs
    a trip through a width of two are eight cycles, and four fused;
  * **one entry, one register**: pairs behind a slow multiply fill a window
    of twelve, or eleven registers, and hold the next multiply out; fused
    they do not, and the loop runs at the multiplies' latency exactly;
  * **two words are not a pair because their mnemonics are**: an add that
    writes a second register, one that reads nothing of the add before it
    whichever register it writes,
    one with something between, and a pair the core does not name all cost
    what they cost unfused;
  * **a squashed tail gives back what it held**: behind a branch nothing
    learns, the same loop ends, and no later than unfused;
  * every program retires the same instructions and leaves the same registers
    and memory on every machine, on both engines;
  * and validation refuses a pair that names nothing, stores to memory, starts
    with a branch, is named twice, or has no window to be in.

Usage: tools/fuse_check.py
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
ZERO, CHAIN, SLOW = 0, 14, 16
FLIP, FLOP = 28, 29
ADD, MUL, BNZ = "IWADD", "IWMUL", "IWBNZ"
ALL = f"({ADD} {ADD}) ({ADD} {BNZ}) ({MUL} {ADD}) ({ADD} {MUL})"

CORE = """
  (defcore fu_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob {rob}) (issue-queue 64) (commit-width {commit}){dispatch})
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 8) (depth 2)){execute}{rename}{fuse}
    (units (alu (count {alus}) (pipelined true)) (mul (count 2) (pipelined true))
           (br (count 1) (pipelined true){brq}) (lsu (count 1) (pipelined true))))
"""

#: name -> what differs from the plain machine; each has a twin that fuses.
KINDS = {"wide": {}, "one": {"alus": 1}, "disp": {"dispatch": " (dispatch-width 2)"},
         "commit": {"commit": 2}, "rob": {"rob": 12}, "brq": {"alus": 1, "brq": " (queue 1)"}, "pool": {"rename": "\n    (rename (rv_gpr 11))"}}
MACHINES = {f"{kind}{suffix}": dict(spec, fuse=f"\n    (timing (fuse {ALL}))" if suffix else "")
            for kind, spec in KINDS.items() for suffix in ("", "_fuse")}
# Two that name one pair each: adds with adds on one adder, and the counter
# with its branch and nothing else.
MACHINES["adds_only"] = {"alus": 1, "fuse": f"\n    (timing (fuse ({ADD} {ADD})))"}
# And one that fuses with a window too small for even the pairs.
MACHINES["tiny_fuse"] = {"rob": 8, "fuse": f"\n    (timing (fuse {ALL}))"}
MACHINES["branch_only"] = {"fuse": f"\n    (timing (fuse ({ADD} {BNZ})))"}

#: Timing clauses validation must refuse, and a word of why.
REFUSED = {
    "a head that names nothing": (f"(timing (fuse (NOPE {ADD})))", "names no instruction"),
    "a tail that stores": (f"(timing (fuse ({ADD} IWSW)))", "touches memory"),
    "a head that changes the pc": (f"(timing (fuse ({BNZ} {ADD})))", "changes the pc"),
    "a pair named twice": (f"(timing (fuse ({ADD} {BNZ}) ({ADD} {BNZ})))", "twice"),
}


def core(engine, name, spec):
    fields = {"rob": 64, "commit": 8, "dispatch": "", "rename": "", "alus": 8, "fuse": "", "brq": "", **spec}
    return CORE.format(engine=engine, name=name, isa=ISA,
                       execute=" (engine execute)" if engine == "x" else "", **fields)


def build_programs(asm: Assembler, bnz):
    add, mul = asm.fast_add, asm.slow
    step = asm.op(add, COUNTER, COUNTER, MINUS_ONE)
    onto = lambda reg: asm.op(add, reg, reg, ONE)  # noqa: E731
    fresh = lambda reg: asm.op(add, reg, ONE, ONE)  # noqa: E731

    def loop(body):
        return body + [step, bnz(COUNTER, 0, -4 * (len(body) + 1)), asm.op(add, 24, 1, 1), 0]

    programs = {}
    # CHAIN: twelve adds to one register, carried round. Each reads the one
    # before and writes the same register: six pairs.
    programs["CHAIN"] = loop([onto(CHAIN)] * 12)
    # TWO: the same chain through two registers by turns -- each add leaves a
    # register the next does not write, and a pair leaves one.
    programs["TWO"] = loop([w for _ in range(6)
                            for w in (asm.op(add, CHAIN, 15, ONE), asm.op(add, 15, CHAIN, ONE))])
    # BETWEEN: the chain with an add of something else after every link.
    programs["BETWEEN"] = loop([w for _ in range(12) for w in (onto(CHAIN), fresh(20))])
    # APART: four adds that read nothing of each other.
    programs["APART"] = loop([fresh(20 + k) for k in range(4)])
    # QUEUED: a branch that waits for a multiply, four adds, and the counter
    # with its branch -- which arrive while the first branch is still waiting.
    programs["QUEUED"] = loop([asm.op(mul, 15, ONE, ONE), bnz(15, 0, 4)] + [fresh(20 + k) for k in range(4)])
    # SAME: four adds that write one register and read nothing of each other.
    programs["SAME"] = loop([fresh(20)] * 4)
    # MULADD, ADDMUL: a multiply and an add of it, either way round, carried
    # round the loop.
    programs["MULADD"] = loop([asm.op(mul, SLOW, SLOW, ONE), onto(SLOW)])
    programs["ADDMUL"] = loop([onto(SLOW), asm.op(mul, SLOW, SLOW, ONE)])
    # PAIRS: seven pairs that wait for nothing, and the counter with its branch.
    pairs = lambda n: [w for k in range(n) for w in (fresh(17 + k), onto(17 + k))]  # noqa: E731
    programs["PAIRS"] = loop(pairs(7))
    # ⚠️ HELD: two multiplies carried round the loop, and six pairs. The
    # second multiply is still in the window when the next trip's first has
    # to enter it, with every pair between them: unfused that is sixteen
    # entries and fifteen registers, fused nine of each.
    programs["HELD"] = loop([asm.op(mul, SLOW, SLOW, ONE), asm.op(mul, SLOW, SLOW, ONE)] + pairs(6))
    # ⚠️ TURNS: the same behind a branch taken every other trip, which two bit
    # counters never learn: tails of the wrong path are in the window when
    # the branch is found out, and what they held has to be given back.
    programs["TURNS"] = loop([asm.op(add, 13, FLIP, ZERO), asm.op(add, FLIP, FLOP, ZERO),
                              asm.op(add, FLOP, 13, ZERO), bnz(FLIP, 0, 8), fresh(15),
                              asm.op(mul, SLOW, SLOW, ONE), asm.op(mul, SLOW, SLOW, ONE)] + pairs(6))
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
    # ... and a machine with no window has nothing to put a pair in.
    text = core("x", "bad", {"fuse": f"\n    (timing (fuse ({ADD} {BNZ})))"}).replace(
        "(window (rob 64) (issue-queue 64) (commit-width 8))", "(window (commit-width 1))")
    done = run_cmd([*axis_prefix(), "check", str(corpus_with(text, "refused"))], check=False)
    checks += 1
    if "(window (commit-width 1))" not in text or done.returncode == 0 \
            or "no window" not in done.stdout + done.stderr:
        fail(f"a pair with no window was not refused for it: {(done.stdout + done.stderr).strip()[:200]}")

    cores = "".join(core(engine, name, spec)
                    for name, spec in MACHINES.items() for engine in ("t", "x"))
    corpus = corpus_with(cores, "fu")
    again = work / "fu_again.axisl"
    run_cmd([*axis_prefix(), "emit-lisp", str(corpus), "-o", str(again)])
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    said_so = lambda path: {c["core"]: c.get("fuse", [])  # noqa: E731
                            for c in json.loads(run_cmd([*axis_prefix(), "emit-uarch-json", str(path)]).stdout)
                            .get("timing", []) if c["core"].startswith("fu_")}
    every = [[ADD, ADD], [ADD, BNZ], [MUL, ADD], [ADD, MUL]]
    wanted = {f"fu_{e}_{n}": every if n.endswith("_fuse") else [[ADD, ADD]] if n == "adds_only" else [[ADD, BNZ]]
              for n in MACHINES for e in ("t", "x") if MACHINES[n].get("fuse")}
    checks += 1
    if said_so(corpus) != wanted or said_so(again) != wanted:
        fail(f"the pairs the description fuses are not what is read back: {said_so(again)}")

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "fu_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("fu_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None or (asm.fast_add, asm.slow) != (ADD, MUL):
        sys.modules.pop("fu_lift", None)
        print(f"  fu: DECLINED {asm.missing() or 'not the instructions the pairs name'}")
        return 0, 0
    programs = build_programs(asm, bnz)
    slow = latency_of[asm.slow]
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    sys.modules.pop("fu_lift", None)
    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF, slot(ZERO): 0,
             slot(FLIP): 0, slot(FLOP): 1}
    tags = [(f"{engine}_{machine}", f"fu_{engine}_{machine}")
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
        who = lambda machine: f"fu_{engine}_{machine}"  # noqa: E731

        def grew(program, machine):
            return (said[f"{program}_{engine}_{machine}_{LONG}"]["cycles"]
                    - said[f"{program}_{engine}_{machine}_{SHORT}"]["cycles"])

        def expect(program, machine, a_trip, why):
            nonlocal checks
            checks += 1
            if grew(program, machine) != more * a_trip:
                fail(f"{more} more trips of {program} took {grew(program, machine)} cycles on "
                     f"{who(machine)}; {why} -- {a_trip} a trip, {more * a_trip}")

        # A pair is one link in a chain, and a tail is no head.
        expect("CHAIN", "wide", 12, "twelve adds in one chain")
        expect("CHAIN", "wide_fuse", 6, "twelve adds in one chain, fused two by two")
        # Two words are not a pair because their mnemonics are.
        expect("CHAIN", "branch_only", 12, "twelve adds in one chain on a core that fuses no add with an add")
        for machine in ("wide", "wide_fuse"):
            expect("TWO", machine, 12, "twelve adds in one chain, each leaving a register of its own")
            expect("BETWEEN", machine, 12, "twelve adds in one chain, each with another add after it")
        expect("APART", "adds_only", 5, "four adds that read nothing of each other, and the counter, on one adder")
        expect("SAME", "adds_only", 5, "four adds to one register that read nothing of each other, on one adder")
        # A pair is the slower one's operation ...
        for program in ("MULADD", "ADDMUL"):
            expect(program, "wide", slow + 1, f"a multiply of {slow} cycles and an add, carried round")
            expect(program, "wide_fuse", slow, f"a multiply of {slow} cycles with an add fused into it")
        # ... and on the tail's unit when neither is slower.
        expect("APART", "one", 5, "four adds and the counter on one adder")
        expect("APART", "one_fuse", 4, "four adds on one adder, the counter fused with its branch")
        # ... unless that unit's own queue is full: then the two are two.
        expect("QUEUED", "one", 5, "four adds and the counter on one adder, behind a branch that waits")
        expect("QUEUED", "one_fuse", 4, "four adds on one adder, the counter fused with its branch")
        for machine in ("brq", "brq_fuse"):
            expect("QUEUED", machine, 6, "a branch unit whose queue of one is taken when the counter's "
                   "branch arrives: it waits to enter, fused with nothing")
        # One slot of the dispatch width, and of the commit width.
        for kind, what in (("disp", "dispatched"), ("commit", "retired")):
            expect("PAIRS", kind, 8, f"sixteen instructions {what} two a cycle")
            expect("PAIRS", f"{kind}_fuse", 4, f"eight pairs {what} two a cycle")
        # One entry, one register.
        for kind, what in (("rob", "a window of twelve"), ("pool", "eleven registers to rename with")):
            expect("HELD", f"{kind}_fuse", 2 * slow,
                   f"two multiplies of {slow} cycles carried round, and pairs that fit in {what}")
            checks += 1
            if grew("HELD", kind) <= more * 2 * slow:
                fail(f"{more} more trips of HELD took {grew('HELD', kind)} cycles on {who(kind)}, "
                     f"no more than the multiplies' {more * 2 * slow}; twelve adds between them "
                     f"fill {what} and keep the next multiply out")
            # ... and what a squashed tail held is given back.
            checks += 1
            if grew("TURNS", f"{kind}_fuse") > grew("TURNS", kind):
                fail(f"{more} more trips of TURNS took {grew('TURNS', f'{kind}_fuse')} cycles on "
                     f"{who(f'{kind}_fuse')} and {grew('TURNS', kind)} on {who(kind)}; a fused "
                     f"pair holds less, so no more")
        # A pair is still an entry: nine of them do not fit in eight.
        checks += 1
        if grew("HELD", "tiny_fuse") <= more * 2 * slow:
            fail(f"{more} more trips of HELD took {grew('HELD', 'tiny_fuse')} cycles on {who('tiny_fuse')}, "
                 f"no more than the multiplies' {more * 2 * slow}; nine entries a trip do not fit a window of eight")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_fu_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL fu: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a pair is one operation: SKIP")
        return DECLINED
    print(f"a pair is one operation: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
