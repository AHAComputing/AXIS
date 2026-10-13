#!/usr/bin/env python3
"""A store that has retired is not yet everyone's. Gate.

`(store-buffer (entries N) (drain order|any))` (docs/memory_model_design.md,
WM1): a store that commits waits in its core's buffer. The core's own loads
read it; no other core sees it until it is written. A buffer that drains in
order is total store order. One that writes each store when its own line is
ready lets two stores reach memory out of program order -- which the relaxed
models, RVWMO and Arm's, allow and no other does. An instruction that orders
memory retires only past an empty buffer.

The corpus has no fence and no cache slow enough to tell a store that waits
from one that does not, so this gate adds both, and three machines alike but
for the clause -- none, in order, in any order -- to hold the engine to
what follows, on two cores sharing one memory:

  * **store buffering**: `x = 1; r = y` beside `y = 1; r = x`, 49 timings.
    With no buffer both loads never read 0. With one, in either order, they
    do. With a fence between each store and its load they never do, on any
    machine;
  * **message passing**: the datum to a line the writer has to fetch, then
    the flag to one it holds, beside a reader that spins on the flag and
    reads the datum. With no buffer, and with one that drains in order, the
    reader reads the datum every time. Draining in any order the flag is
    written first and the reader reads what was there before. With a fence
    between the two stores it reads the datum every time;
  * **a core reads its own**: a store and a load of the same word, round a
    loop, and seeded random programs with loads and stores, leave the same
    registers and memory on every machine, apart or beside another -- with
    no replays, anywhere in this gate;
  * **the buffer is room**: four stores to four lines the core has to fetch
    retire at once into a buffer of eight, one line's wait apart into a
    buffer of one, and two by two into a buffer of two that drains in any
    order -- sooner than one of two that drains in order;
  * and validation refuses a buffer of no entries or too many, a way of
    draining that is neither, a core that is not execution-driven, one on an
    ISA that is sequentially consistent, and draining in any order on an ISA
    whose model is not known to allow it.

Usage: tools/store_buffer_check.py
"""
from __future__ import annotations

import importlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
from lsq_check import Assembler  # noqa: E402
from frontend_check import branch_encoder  # noqa: E402
from xmode_check import random_program  # noqa: E402
from mcx_check import (BASE, CODE, COUNTER, DATA, DATUM, ENTRY, FLAG, HARNESS, MAXC, MINUS_ONE,  # noqa: E402
                       ONE, OUT, OUT2, REGION, X, Y)

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "issue_width.axisl"
ISA = "iw32"
MISS = 30
WAITS = range(0, 7)
SEEDS = 6
LATES = range(0, 8)
SLOW = 24
FENCE = "IWFENCE"
#: Programs a core runs by itself, and must leave as a core with no buffer does.
OWN = [f"R{k}" for k in range(SEEDS)] + ["FWD", "BURST", "SAME"] + [f"LATE{n}" for n in LATES]

#: What the corpus lacks: a fence, and a cache a store can be seen waiting for.
ADDED = f"""
  (definstruction iwfence
    (mnemonic {FENCE})
    (isa {ISA})
    (category custom)
    (format I)
    (opcode 0x0f)
    (func3 0)
    (encoding (rd 0) (rs1 0))
    (unit alu)
    (operands
      (imm imm i8 in))
    (asm "iwfence $imm")
    (semantics "Order memory")
    (behavior (barrier fence imm))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
    (rationale "Order memory"))
  (defmemory sbd (kind cache) (size-bytes 4096) (line-bytes 64) (ways 1)
    (width-bits 32) (latency-cycles {MISS}))
"""

CORE = """
  (defcore sb_{name} (kind rvmt) (memory sbd) (implements {isa}) (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)){buffer}{engine}
    (units (alu (count 4) (pipelined true)) (mul (count 2) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 2) (pipelined true))))
"""

#: name -> the clause, and what it should read back as.
MACHINES = {
    "none": ("", None),
    "order": ("\n    (store-buffer (entries 8))", {"entries": 8, "drain": "order"}),
    "any": ("\n    (store-buffer (entries 8) (drain any))", {"entries": 8, "drain": "any"}),
    "one": ("\n    (store-buffer (entries 1) (drain order))", {"entries": 1, "drain": "order"}),
    "two": ("\n    (store-buffer (entries 2))", {"entries": 2, "drain": "order"}),
    "two_any": ("\n    (store-buffer (entries 2) (drain any))", {"entries": 2, "drain": "any"}),
}

#: (clause, engine, the ISA's memory model, a word of why) validation must refuse.
REFUSED = {
    "no entries": ("(store-buffer (drain any))", True, "rvwmo", "1 to 64"),
    "too many entries": ("(store-buffer (entries 65))", True, "rvwmo", "1 to 64"),
    "a way of draining that is neither": ("(store-buffer (entries 8) (drain fifo))", True, "rvwmo", "`order` or `any`"),
    "a core that is not execution-driven": ("(store-buffer (entries 8))", False, "rvwmo", "engine execute"),
    "an ISA that is sequentially consistent": ("(store-buffer (entries 8))", True, "sc", "sequentially consistent"),
    "any order under total store order": ("(store-buffer (entries 8) (drain any))", True, "tso", "pass each other"),
}


def core(name, buffer, engine=True):
    return CORE.format(name=name, isa=ISA, buffer=buffer, engine="\n    (engine execute)" if engine else "")


def build_programs(asm: Assembler, bnz):
    mul = asm.slow
    fence = asm._word(FENCE, imm=0)  # noqa: SLF001
    delay = lambda n: [asm.op(mul, 30, 30, 30) for _ in range(n)]  # noqa: E731
    programs = {}
    for w in WAITS:
        for mine, theirs, tag in ((X, Y, 0), (Y, X, 1)):
            # Each holds the line it will read before it starts, and not the
            # one it will write: its load is done while its store still waits.
            held = [asm.ld(22, BASE, theirs)] + delay(12 + w)
            programs[f"SB{tag}_{w}"] = held + [asm.st(ONE, BASE, mine), asm.ld(OUT, BASE, theirs), 0]
            programs[f"SBF{tag}_{w}"] = held + [asm.st(ONE, BASE, mine), fence,
                                               asm.ld(OUT, BASE, theirs), 0]
        # The writer holds the flag's line before it starts, and not the datum's.
        warm = [asm.ld(22, BASE, FLAG)] + delay(14)
        programs[f"MPW_{w}"] = warm + delay(w) + [asm.st(3, BASE, DATUM), asm.st(ONE, BASE, FLAG), 0]
        programs[f"MPWF_{w}"] = warm + delay(w) + [asm.st(3, BASE, DATUM), fence, asm.st(ONE, BASE, FLAG), 0]
    # The reader holds both lines, spins while the flag is not 1, then reads.
    programs["MPR"] = [asm.ld(22, BASE, DATUM), asm.ld(OUT, BASE, FLAG), bnz(OUT, ONE, -4),
                       asm.ld(OUT2, BASE, DATUM), 0]
    rng = random.Random(1357)
    for k in range(SEEDS):
        programs[f"R{k}"] = random_program(asm, bnz, rng, rng.randrange(8, 24))
    fwd = [asm.st(1, BASE, 0), asm.ld(12, BASE, 0), asm.op(asm.fast_add, 1, 1, ONE),
           asm.op(asm.fast_add, 13, 13, 12), asm.op(asm.fast_add, COUNTER, COUNTER, MINUS_ONE)]
    programs["FWD"] = fwd + [bnz(COUNTER, 0, -4 * len(fwd)), 0]
    # Two stores to one word of a cold line, and a load of it whose address
    # is `n` multiplies late: it reads the buffer, and the younger store.
    for n in LATES:
        slow = [asm.op(mul, SLOW, BASE, ONE)] + [asm.op(mul, SLOW, SLOW, ONE) for _ in range(n)]
        programs[f"LATE{n}"] = [asm.st(3, BASE, 0), asm.st(ONE, BASE, 0)] + slow + [asm.ld(OUT, SLOW, 0), 0]
    # A store across the end of a cold line, then one to the start of the
    # next, which the core holds: the second is ready first and must wait.
    # The multiplies after them are time for it to be written before the halt.
    programs["SAME"] = ([asm.ld(22, BASE, 64)] + delay(14)
                        + [asm.st(3, BASE, 62), asm.st(ONE, BASE, 64)] + delay(16) + [0])
    # Four stores to four lines nothing has touched.
    programs["BURST"] = [asm.st(ONE, BASE, 64 * k) for k in range(4)] + [0]
    return programs


def check(work: Path) -> tuple[int, int]:
    source = CORPUS.read_text()
    end = source.rstrip().rfind(")")

    def corpus_with(cores: str, name: str, model: str = "rvwmo") -> Path:
        text = source[:end] + ADDED + cores + ")\n"
        assert "(memory-model rvwmo)" in text
        path = work / f"{name}.axisl"
        path.write_text(text.replace("(memory-model rvwmo)", f"(memory-model {model})"))
        return path

    def run_cmd(cmd, check=True):
        return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=AXIS_ROOT)

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {message}")
        failures += 1

    for why, (clause, engine, model, word) in REFUSED.items():
        done = run_cmd([*axis_prefix(), "check",
                        str(corpus_with(core("bad", "\n    " + clause, engine), "refused", model))], check=False)
        checks += 1
        if done.returncode == 0 or word not in " ".join((done.stdout + done.stderr).split()):
            fail(f"a store buffer with {why} was not refused for it: "
                 f"{(done.stdout + done.stderr).strip()[:200]}")

    corpus = corpus_with("".join(core(name, buffer) for name, (buffer, _) in MACHINES.items())
                         + core("trace", "", False), "sb")
    again = work / "sb_again.axisl"
    run_cmd([*axis_prefix(), "emit-lisp", str(corpus), "-o", str(again)])
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    twice = json.loads(run_cmd([*axis_prefix(), "emit-json", str(again)]).stdout)
    said_so = lambda doc: {c["name"][3:]: c.get("store_buffer") for c in doc.get("cores", [])  # noqa: E731
                           if c["name"].startswith("sb_") and c["name"] != "sb_trace"}
    checks += 1
    if said_so(facts) != said_so(twice) or said_so(facts) != {n: back for n, (_, back) in MACHINES.items()}:
        fail(f"the buffer the description declares is not what is read back: {said_so(twice)}")

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "sb_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("sb_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None or FENCE not in asm.tests:
        sys.modules.pop("sb_lift", None)
        print(f"  sb: DECLINED {asm.missing() or 'no branch, or no fence'}")
        return 0, 0
    programs = build_programs(asm, bnz)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    datum = 0x11 * (slot(3) + 1)
    sys.modules.pop("sb_lift", None)

    runs, expect = [], []

    def alone(tag, machine, label, trips=5):
        runs.append(f'  alone("{tag}", "sb_{machine}", 0, {label}, {len(programs[label])}, {trips}u);')
        expect.append(f"{tag}.0")

    def together(tag, machine, labels, shared, trips=5):
        runs.append("  { static const uint32_t *const w[] = { " + ", ".join(labels) + " }; "
                    "static const int32_t n[] = { " + ", ".join(str(len(programs[x])) for x in labels)
                    + " }; " + f'together("{tag}", "sb_{machine}", {len(labels)}, w, n, {shared}, {trips}u, 0u); }}')
        expect.extend(f"{tag}.{c}" for c in range(len(labels)))

    litmus = ("none", "order", "any")
    for machine in litmus:
        for w0 in WAITS:
            for w1 in WAITS:
                together(f"SB_{machine}_{w0}_{w1}", machine, [f"SB0_{w0}", f"SB1_{w1}"], 1)
                together(f"SBF_{machine}_{w0}_{w1}", machine, [f"SBF0_{w0}", f"SBF1_{w1}"], 1)
        for w in WAITS:
            together(f"MP_{machine}_{w}", machine, [f"MPW_{w}", "MPR"], 1)
            together(f"MPF_{machine}_{w}", machine, [f"MPWF_{w}", "MPR"], 1)
    pairs = [[f"R{k}", f"R{(k + 1) % SEEDS}"] for k in range(0, SEEDS, 2)] + [["FWD", "R0"]]
    for machine in MACHINES:
        for g, labels in enumerate(pairs):
            together(f"APART{g}_{machine}", machine, labels, 0)
        for label in OWN:
            alone(f"ALONE_{label}_{machine}", machine, label)

    code = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "entry": ENTRY, "code": CODE,
        "data": DATA, "region": REGION, "maxc": MAXC,
        "base": slot(BASE), "one": slot(ONE), "minus": slot(MINUS_ONE), "counter": slot(COUNTER),
        "out": slot(OUT), "out2": slot(OUT2), "isa": f'"{ISA}"',
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs),
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(code)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / name), str(work / f"{name}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True, timeout=900)
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 15 and parts[1] == "cycles":
            said[parts[0]] = dict(zip(parts[1::2], map(int, parts[2::2])))
    if "--dump" in sys.argv:
        for key in sorted(said):
            print("   ", key, said[key])
    checks += 1
    if done.returncode != 0 or any(tag not in said for tag in expect):
        fail(f"the harness exited {done.returncode}, or some run reported nothing: "
             f"{[t for t in expect if t not in said][:4]}")
        return checks, failures

    # No replays, anywhere: what a core read is what its golden model reads.
    checks += 1
    replayed = sorted(tag for tag, row in said.items() if row["replays"])
    if replayed:
        fail(f"the golden model disagreed with the pipeline (replays) in {replayed[:6]}")

    def outcomes(prefix, machine):
        return {(said[f"{prefix}_{machine}_{a}_{b}.0"]["out"], said[f"{prefix}_{machine}_{a}_{b}.1"]["out"])
                for a in WAITS for b in WAITS}

    def read(prefix, machine):
        return {said[f"{prefix}_{machine}_{w}.1"]["out2"] for w in WAITS}

    for machine in litmus:
        seen = outcomes("SB", machine)
        checks += 1
        if not seen <= {(0, 0), (0, 1), (1, 0), (1, 1)}:
            fail(f"store buffering on sb_{machine} read something never stored: {sorted(seen)}")
        checks += 1
        if ((0, 0) in seen) != (machine != "none"):
            fail(f"store buffering on sb_{machine} read {sorted(seen)}; both loads read 0 "
                 f"{'only with a buffer' if machine == 'none' else 'when each store is still in its buffer'}")
        checks += 1
        if (0, 0) in outcomes("SBF", machine):
            fail(f"store buffering with a fence after each store read (0, 0) on sb_{machine}")
        checks += 1
        want = {datum} if machine != "any" else {0, datum}
        if not read("MP", machine) <= {0, datum} or (0 in read("MP", machine)) != (machine == "any"):
            fail(f"message passing on sb_{machine} read {sorted(read('MP', machine))}, not {sorted(want)}; "
                 f"the flag is written before the datum only by a buffer that drains in any order")
        checks += 1
        if read("MPF", machine) != {datum}:
            fail(f"message passing with a fence between the stores read {sorted(read('MPF', machine))} "
                 f"on sb_{machine}, not the datum {datum}")

    # A core reads its own: every machine leaves what the one with no buffer does.
    for machine in MACHINES:
        for label in OWN:
            mine, plain = said[f"ALONE_{label}_{machine}.0"], said[f"ALONE_{label}_none.0"]
            checks += 1
            if (mine["steps"], mine["mark"]) != (plain["steps"], plain["mark"]):
                fail(f"{label} alone on sb_{machine} left other registers or memory than on sb_none")
        for g, labels in enumerate(pairs):
            for c, label in enumerate(labels):
                mine, plain = said[f"APART{g}_{machine}.{c}"], said[f"ALONE_{label}_none.0"]
                checks += 1
                if mine["steps"] != plain["steps"] or mine["snoops"]:
                    fail(f"{label} beside another on sb_{machine}: {mine['steps']} steps and "
                         f"{mine['snoops']} snoops, not {plain['steps']} and none")

    # The buffer is room.
    took = {machine: said[f"ALONE_BURST_{machine}.0"]["cycles"] for machine in MACHINES}
    checks += 1
    if not (took["none"] == took["order"] == took["any"]):
        fail(f"four stores into a buffer of eight took {took['order']} and {took['any']} cycles, "
             f"not the {took['none']} they take with no buffer")
    checks += 1
    if took["one"] < took["order"] + 3 * MISS:
        fail(f"four stores into a buffer of one took {took['one']} cycles; each waits for the one "
             f"before to be written, a line of {MISS} cycles apart -- {took['order'] + 3 * MISS} or more")
    checks += 1
    if not took["order"] < took["two_any"] < took["two"] < took["one"]:
        fail(f"four stores took {took['two_any']} cycles into a buffer of two draining in any order, "
             f"{took['two']} in order, {took['one']} into one and {took['order']} into eight; "
             f"two lines fetched together are sooner than one after the other")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_sb_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL sb: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a store that has retired is not yet everyone's: SKIP")
        return DECLINED
    print(f"a store that has retired is not yet everyone's: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
