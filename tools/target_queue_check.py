#!/usr/bin/env python3
"""A predictor that does not wait for fetch. Gate.

`(front-end ... (target-queue N))` (docs/front_end_design.md, FQ1) is a
DECOUPLED front end: the predictor runs ahead of fetch, naming a line of code
a cycle and at most N beyond the one fetch is reading, and a line is asked of
the instruction cache when it is named. This gate builds its own machines --
four instructions wide at fetch, sixteen to a line, a miss of twenty-four
cycles -- alike but for the queue, and holds them to its arithmetic:

  * **a miss is as long as the queue is short**: cold, straight code is a
    line every 28 cycles with no queue -- the miss and four groups -- and
    with one every max(4, 24/N): 24, 12, 6 and then 4, where fetch is what
    is slow and a longer queue buys nothing;
  * **a line named ahead is no miss of fetch's**: of sixteen cold lines the
    machine with a queue misses the first;
  * **code the cache holds gains nothing**: a loop in one line costs the same
    on every machine;
  * **a redirect empties the queue**: the line a mispredicted branch goes to
    is a miss in full, and the lines after it gain what straight ones do;
  * **so does a jump the predictor had no target for**, which decode finds;
  * **a jump it has a target for does not**: a loop over two lines that put
    each other out of the cache is two misses a trip with no queue and none
    with one, twelve cycles a trip;
  * **a new page is not named ahead**: with pages of four lines and a fetch
    TLB, the first line of each is a miss and the three behind it are not;
  * **the engine that fetches what it predicts agrees**, cycle for cycle;
  * every program retires the same instructions and leaves the same registers
    and memory on every machine;
  * and validation refuses a queue with no cache to ask, one of more lines
    than its cache holds, and one of more than sixty-four.

Usage: tools/target_queue_check.py
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
from redirect_check import (COUNTER, LINE, MINUS_ONE, ONE, SCRATCH_LINK,  # noqa: E402
                            direct_jump_encoder, harness_run, layout)

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "issue_width.axisl"
ISA = "iw32"
#: What a line costs to bring in, how many the cache holds, and a page.
MISS, LINES, PAGE, WALK = 24, 16, 256, 5
FETCH = 4
PER_LINE = LINE // 4
SHORT, LONG = 16, 32

CACHE = f"""
  (defmemory fqi (kind cache) (size-bytes {LINES * LINE}) (line-bytes {LINE}) (ways 1)
    (width-bits 32) (latency-cycles {MISS}))
"""

CORE = """
  (defcore fq_{engine}_{name} (kind rvmt) (implements {isa}) (issue-width 8)
    (window (rob 64) (issue-queue 64) (commit-width 8))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width {fetch}) (depth 2) (btb 16) (btb-penalty 2){icache}{queue}){execute}
    {tlb}
    (units (alu (count 8) (pipelined true)) (mul (count 1) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 1) (pipelined true))))
"""

TLB = f"(tlb (fetch (entries 8)) (page-bytes {PAGE}) (walk-cycles {WALK}))"
#: name -> (lines named ahead, has a fetch TLB).
MACHINES = {"q0": (0, False), "q1": (1, False), "q2": (2, False), "q4": (4, False),
            "q8": (8, False), "q0p": (0, True), "q4p": (4, True)}

#: Descriptions validation must refuse: (icache clause, queue), and a word of why.
REFUSED = {
    "no instruction cache": ("", 4, "no `(icache"),
    "more lines than its cache holds": (" (icache fqi)", LINES + 1, "holds"),
    "more than sixty-four lines": (" (icache fqi)", 65, "64"),
}


def core(engine, name, queue, tlb, icache=" (icache fqi)"):
    return CORE.format(engine=engine, name=name, isa=ISA, fetch=FETCH, icache=icache,
                       queue=f" (target-queue {queue})" if queue else "",
                       execute=" (engine execute)" if engine == "x" else "",
                       tlb=TLB if tlb else "")


def build_programs(asm: Assembler, bnz, jump):
    add = asm.fast_add
    apart = lambda k: asm.op(add, 20 + k % 4, ONE, ONE)  # noqa: E731
    pad = asm.op(add, 30, 1, 1)
    straight = lambda lines: [apart(k) for k in range(lines * PER_LINE)]  # noqa: E731
    programs = {}
    for lines in (8, 16):
        programs[f"STRAIGHT{lines}"] = straight(lines) + [0]
        # ⚠️ TURNED: a branch that is taken and that nothing has seen -- so
        # predicted not taken, and a redirect when it executes -- to a line
        # four on, and straight from there. HOPPED: a direct jump in its
        # place, which the predictor has no target for and decode finds.
        for label, word in (("TURNED", bnz(ONE, 0, 4 * (4 * PER_LINE - 2))),
                            ("HOPPED", jump(SCRATCH_LINK, 4 * (4 * PER_LINE - 2)))):
            programs[f"{label}{lines}"] = (layout({0: apart(0), 1: apart(1), 2: word},
                                                  4 * PER_LINE, pad)
                                           + straight(lines) + [0])
    # WARM: a loop in one line.
    programs["WARM"] = ([apart(k) for k in range(6)]
                        + [asm.op(add, COUNTER, COUNTER, MINUS_ONE), bnz(COUNTER, 0, -24),
                           asm.op(add, 24, 1, 1), 0])
    # ⚠️ PING: two lines of one set of the instruction cache, each ending in
    # a jump or a branch to the other. Each puts the other out, every trip --
    # and after the first trip the predictor has both targets: the two are
    # a word apart in their lines, so that they are not one slot of its buffer.
    far = LINES * PER_LINE
    programs["PING"] = layout({0: apart(0), 1: jump(SCRATCH_LINK, 4 * (far - 1)),
                               far: asm.op(add, COUNTER, COUNTER, MINUS_ONE),
                               far + 2: bnz(COUNTER, 0, -4 * (far + 2)),
                               far + 3: asm.op(add, 24, 1, 1)}, far + 4, pad) + [0]
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

    for why, (icache, queue, word) in REFUSED.items():
        bad = corpus_with(CACHE + core("x", "bad", queue, False, icache), "refused")
        done = run_cmd([*axis_prefix(), "check", str(bad)], check=False)
        checks += 1
        if done.returncode == 0 or word not in done.stdout + done.stderr:
            fail(f"a target queue with {why} was not refused for it: "
                 f"{(done.stdout + done.stderr).strip()[:160]}")

    cores = CACHE + "".join(core(engine, name, queue, tlb)
                            for name, (queue, tlb) in MACHINES.items() for engine in ("t", "x"))
    corpus = corpus_with(cores, "fq")
    # The clause survives being written out and read back.
    again = work / "fq_again.axisl"
    run_cmd([*axis_prefix(), "emit-lisp", str(corpus), "-o", str(again)])
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    twice = json.loads(run_cmd([*axis_prefix(), "emit-json", str(again)]).stdout)
    queues = lambda doc: {c["name"]: (c.get("front_end") or {}).get("target_queue", 0)  # noqa: E731
                          for c in doc.get("cores", []) if c["name"].startswith("fq_")}
    checks += 1
    if queues(facts) != queues(twice) or queues(facts) != {
            f"fq_{e}_{n}": q for n, (q, _) in MACHINES.items() for e in ("t", "x")}:
        fail(f"the queues the description declares are not the ones read back: {queues(twice)}")

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "fq_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("fq_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    jump = direct_jump_encoder(lift, tests)
    if asm.missing() or bnz is None or jump is None:
        sys.modules.pop("fq_lift", None)
        print(f"  fq: DECLINED {asm.missing() or 'no branch or direct jump'}")
        return 0, 0
    programs = build_programs(asm, bnz, jump)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    sys.modules.pop("fq_lift", None)
    seeds = {"counter": slot(COUNTER), slot(ONE): 1, slot(MINUS_ONE): 0xFFFFFFFF, slot(0): 0}
    tags = [(f"{engine}_{machine}", f"fq_{engine}_{machine}")
            for machine in MACHINES for engine in ("t", "x")]
    lines = [f'  go("{p}_{tag}_{trips}", "{core_name}", {p}, {len(programs[p])}, {trips}u);'
             for p in programs for tag, core_name in tags for trips in (SHORT, LONG)]
    said = harness_run(work, manifest, name, ISA, seeds, programs, lines, 8)
    if said is None or any(f"{p}_{tag}_{trips}" not in said
                           for p in programs for tag, _ in tags for trips in (SHORT, LONG)):
        fail("the harness did not run, or some machine reported nothing")
        return checks + 1, failures

    def get(program, engine, machine, key="cycles", trips=LONG):
        return said[f"{program}_{engine}_{machine}_{trips}"][key]

    for program in programs:
        for trips in (SHORT, LONG):
            rows = [said[f"{program}_{tag}_{trips}"] for tag, _ in tags]
            checks += 1
            if len({(r["steps"], r["mark"]) for r in rows}) != 1:
                fail(f"{program} retired different instructions or left different registers or "
                     f"memory on different machines: {sorted({r['steps'] for r in rows})}")
    if failures:
        return checks, failures

    plain = MISS + PER_LINE // FETCH
    for engine in ("t", "x"):
        who = lambda machine: f"fq_{engine}_{machine}"  # noqa: E731

        def more(label, machine, key="cycles"):
            """What eight more lines of it cost."""
            return get(f"{label}16", engine, machine, key) - get(f"{label}8", engine, machine, key)

        # A miss is as long as the queue is short.
        for machine, (queue, paged) in MACHINES.items():
            if paged:
                continue
            a_line = max(PER_LINE // FETCH, -(-MISS // queue)) if queue else plain
            for label in ("STRAIGHT", "TURNED", "HOPPED"):
                checks += 1
                if more(label, machine) != 8 * a_line:
                    fail(f"eight more cold lines of {label} took {more(label, machine)} cycles on "
                         f"{who(machine)}; a line is {PER_LINE // FETCH} groups and a miss of "
                         f"{MISS}, asked for {queue or 'no'} line(s) ahead -- {a_line} a line, "
                         f"{8 * a_line}")
            checks += 1
            missed = get("STRAIGHT16", engine, machine, "imiss")
            if (missed != 1) if queue else (missed < 16):
                fail(f"sixteen cold lines missed {missed} times on {who(machine)}; "
                     + ("named ahead, every line but the first was asked for before fetch "
                        "arrived -- 1" if queue else "each is a miss, 16 at least"))
            checks += 1
            if more("STRAIGHT", machine, "imiss") != (0 if queue else 8):
                fail(f"eight more cold lines missed {more('STRAIGHT', machine, 'imiss')} more "
                     f"times on {who(machine)}; {0 if queue else 8}")
            # Code the cache holds gains nothing.
            checks += 1
            if any(get("WARM", engine, machine, trips=t) != get("WARM", engine, "q0", trips=t)
                   for t in (SHORT, LONG)):
                fail(f"a loop in one line took {get('WARM', engine, machine)} cycles on "
                     f"{who(machine)} and {get('WARM', engine, 'q0')} on {who('q0')}; nothing "
                     f"is asked for that the cache does not hold, so the same")
            if not queue:
                continue
            # A redirect empties the queue, and so does a jump decode finds:
            # the line gone to is a miss in full, and nothing before it gained.
            for label, why in (("TURNED", "a mispredicted branch"),
                               ("HOPPED", "a jump the predictor had no target for")):
                checks += 1
                if get(f"{label}8", engine, machine, "imiss") != 2:
                    fail(f"{label}8 missed {get(f'{label}8', engine, machine, 'imiss')} times "
                         f"on {who(machine)}; its first line and the one {why} goes to, which "
                         f"nothing named -- 2")
                saved = get(f"{label}8", engine, "q0") - get(f"{label}8", engine, machine)
                straight = get("STRAIGHT8", engine, "q0") - get("STRAIGHT8", engine, machine)
                checks += 1
                if saved != straight:
                    fail(f"{label}8 is {saved} cycles shorter on {who(machine)} than on "
                         f"{who('q0')}, and eight straight lines are {straight}; after {why} "
                         f"the queue starts empty, as it does at the start -- the same")
        # ⚠️ A jump the predictor HAS a target for does not empty it.
        trips = LONG - SHORT
        grew = lambda machine, key="cycles": (get("PING", engine, machine, key, LONG)  # noqa: E731
                                              - get("PING", engine, machine, key, SHORT))
        checks += 1
        if grew("q0", "imiss") != 2 * trips or grew("q4", "imiss") != 0:
            fail(f"{trips} more trips over two lines that put each other out missed "
                 f"{grew('q0', 'imiss')} more times on {who('q0')} and {grew('q4', 'imiss')} on "
                 f"{who('q4')}; two a trip, and none where both were named ahead -- "
                 f"{2 * trips} and 0")
        checks += 1
        if grew("q4") != trips * 2 * MISS // 4 or grew("q1") != trips * 2 * MISS:
            fail(f"the same took {grew('q4')} more cycles on {who('q4')} and {grew('q1')} on "
                 f"{who('q1')}; two lines a trip, each asked for four lines ahead and one -- "
                 f"{trips * 2 * MISS // 4} and {trips * 2 * MISS}")
        checks += 1
        if grew("q0") <= grew("q1"):
            fail(f"the same took {grew('q0')} more cycles on {who('q0')}, no more than the "
                 f"{grew('q1')} of {who('q1')}; with no queue each miss starts when fetch arrives")
        # ⚠️ A new page is not named ahead: eight more lines are two pages,
        # the first line of each a miss in full and three named behind it.
        pages = 8 * LINE // PAGE
        per_page = PAGE // LINE
        checks += 1
        if more("STRAIGHT", "q4p", "imiss") != pages or more("STRAIGHT", "q0p", "imiss") != 8:
            fail(f"eight more cold lines in pages of {per_page} missed "
                 f"{more('STRAIGHT', 'q4p', 'imiss')} more times on {who('q4p')} and "
                 f"{more('STRAIGHT', 'q0p', 'imiss')} on {who('q0p')}; the predictor does not "
                 f"name a line across a page -- {pages} and 8")
        gained = more("STRAIGHT", "q0p") - more("STRAIGHT", "q4p")
        checks += 1
        if gained != pages * (per_page - 1) * MISS:
            fail(f"eight more cold lines in pages of {per_page} are {gained} cycles shorter on "
                 f"{who('q4p')} than on {who('q0p')}; every line but a page's first has its "
                 f"miss behind it -- {pages * (per_page - 1) * MISS}")
    # ⚠️ The engine that fetches what it predicts agrees, cycle for cycle --
    # where nothing is mispredicted. Where something is, it fetches a wrong
    # path the other does not, and each is held to the arithmetic above.
    for program in (p for p in programs if p.startswith(("STRAIGHT", "HOPPED"))):
        for machine in MACHINES:
            for trips in (SHORT, LONG):
                checks += 1
                if (get(program, "t", machine, trips=trips)
                        != get(program, "x", machine, trips=trips)):
                    fail(f"{program} ({trips}) took {get(program, 't', machine, trips=trips)} "
                         f"cycles on fq_t_{machine} and "
                         f"{get(program, 'x', machine, trips=trips)} on fq_x_{machine}")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_fq_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL fq: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a predictor does not wait for fetch: SKIP")
        return DECLINED
    print(f"a predictor does not wait for fetch: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
