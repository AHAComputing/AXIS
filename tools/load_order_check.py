#!/usr/bin/env python3
"""A load another core's store overtakes keeps what it read. Gate.

`(load-order any)` (docs/memory_model_design.md, WM2): a load that has read
its bytes, and has not retired when another core writes them, was squashed
and read again -- so a core's loads saw memory in program order. The relaxed
models, RVWMO and Arm's, do not ask for that: a load may be satisfied before
an older load of other bytes. A core that says so keeps the load, and its
golden model reads what the load read.

Not everything may be kept. Two loads of the same bytes never see memory go
backwards, and a load behind something that orders memory is not satisfied
before it. This gate adds a fence to the corpus and machines alike but for
the clause, and holds the engine to what follows, a reader beside a writer:

  * **two loads of two words**: the writer stores the datum, then the flag.
    The reader loads the flag through an address it is slow to form, then the
    datum -- which it reads first. In order, it never has the flag and not
    the datum. In any order it does, at some of 49 timings;
  * **behind a fence it does not**: with a fence between the reader's loads,
    never, on any machine;
  * **two loads of one word**: the same reader loading the flag twice never
    reads it set and then clear, on any machine;
  * **with a store buffer too**: a core with both shows both;
  * **total store order's**, `(load-order tso)` (WM6): a load is kept when
    every older load of its core has read. Such a core never has the flag
    and not the datum either. But two cores that each store one word and
    load the other, the store held at the head of the window and the load
    not, both read 0 -- with no store buffer declared -- where in order each
    load is squashed and reads 1; and with a fence after the store, never;
  * random programs with loads and stores leave what they leave on a core
    with neither, alone or beside another -- with no replays, anywhere here;
  * and validation refuses an order that is neither, a core that is not
    execution-driven, any order on an ISA whose model is not known to allow
    it, and total store order's on an ISA that is sequentially consistent.

Usage: tools/load_order_check.py
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
                       ONE, OUT, OUT2, REGION)
from store_buffer_check import ADDED, FENCE, ISA  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPUS = AXIS_ROOT / "examples" / "issue_width.axisl"
WAITS = range(0, 7)
SEEDS = 4
SLOW = 24

CORE = """
  (defcore lo_{name} (kind rvmt) (memory sbd) (implements {isa}) (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)){clauses}{engine}
    (units (alu (count 4) (pipelined true)) (mul (count 2) (pipelined true))
           (br (count 1) (pipelined true)) (lsu (count 2) (pipelined true))))
"""

#: name -> its clauses, and what its load order should read back as.
MACHINES = {
    "order": ("", None),
    "said": ("\n    (load-order order)", "order"),
    "any": ("\n    (load-order any)", "any"),
    "both": ("\n    (store-buffer (entries 8) (drain any))\n    (load-order any)", "any"),
    "tso": ("\n    (load-order tso)", "tso"),
    "tso_buf": ("\n    (store-buffer (entries 8))\n    (load-order tso)", "tso"),
}

#: (clause, engine, the ISA's memory model, a word of why) validation must refuse.
REFUSED = {
    "an order that is neither": ("(load-order some)", True, "rvwmo", "`order`, `tso` or `any`"),
    "a core that is not execution-driven": ("(load-order any)", False, "rvwmo", "engine execute"),
    "any order under total store order": ("(load-order any)", True, "tso", "pass each other"),
    "total store order's on a sequentially consistent ISA": ("(load-order tso)", True, "sc", "before an older store"),
    "total store order's on a core that is not execution-driven": ("(load-order tso)", False, "rvwmo",
                                                                    "engine execute"),
}


def core(name, clauses, engine=True):
    return CORE.format(name=name, isa=ISA, clauses=clauses, engine="\n    (engine execute)" if engine else "")


def build_programs(asm: Assembler, bnz):
    mul = asm.slow
    fence = asm._word(FENCE, imm=0)  # noqa: SLF001
    delay = lambda n: [asm.op(mul, 30, 30, 30) for _ in range(n)]  # noqa: E731
    # The base again, through multiplies by one: an address formed late --
    # from before the writer's stores retire to well after.
    late = lambda n: ([asm.op(mul, SLOW, BASE, ONE)]  # noqa: E731
                      + [asm.op(mul, SLOW, SLOW, ONE) for _ in range(9 + 2 * n)])
    held = [asm.ld(22, BASE, FLAG), asm.ld(22, BASE, DATUM)] + delay(12)
    programs = {}
    for w in WAITS:
        # The writer: the datum, then the flag, after `w` multiplies.
        programs[f"W_{w}"] = held + delay(w) + [asm.st(3, BASE, DATUM), asm.st(ONE, BASE, FLAG), 0]
        # The readers, each holding both lines before it starts.
        programs[f"TWO_{w}"] = held + late(w) + [asm.ld(OUT, SLOW, FLAG), asm.ld(OUT2, BASE, DATUM), 0]
        programs[f"TWOF_{w}"] = held + late(w) + [asm.ld(OUT, SLOW, FLAG), fence, asm.ld(OUT2, BASE, DATUM), 0]
        programs[f"ONE_{w}"] = held + late(w) + [asm.ld(OUT, SLOW, FLAG), asm.ld(OUT2, BASE, FLAG), 0]
        # Store buffering with no buffer: the store waits at the head of the
        # window behind `w` multiplies and the load of the other word does
        # not.
        for side, (mine, other) in enumerate(((FLAG, DATUM), (DATUM, FLAG))):
            # An older load, of the core's own word, that has read and is
            # still in the window behind the multiplies.
            older = delay(w) + [asm.ld(23, BASE, mine)]
            programs[f"SB{side}_{w}"] = held + older + [asm.st(ONE, BASE, mine), asm.ld(OUT, BASE, other), 0]
            programs[f"SBF{side}_{w}"] = (held + older
                                          + [asm.st(ONE, BASE, mine), fence, asm.ld(OUT, BASE, other), 0])
    rng = random.Random(97531)
    for k in range(SEEDS):
        programs[f"R{k}"] = random_program(asm, bnz, rng, rng.randrange(8, 24))
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
            fail(f"{why} was not refused for it: {(done.stdout + done.stderr).strip()[:200]}")

    # What orders memory is told to a pack whose only such core is this one.
    for order in ("any", "tso"):
        only = run_cmd([*axis_prefix(), "emit-pack-sim-c",
                        str(corpus_with(core("only", f"\n    (load-order {order})"), "only"))]).stdout
        checks += 1
        if f'"{FENCE}"' not in only.split("AXIS_SIM_ORDERED[][2]", 1)[-1].split("};", 1)[0]:
            fail(f"a pack whose one core says `(load-order {order})` is not told that {FENCE} orders memory")

    corpus = corpus_with("".join(core(name, clauses) for name, (clauses, _) in MACHINES.items()), "lo")
    again = work / "lo_again.axisl"
    run_cmd([*axis_prefix(), "emit-lisp", str(corpus), "-o", str(again)])
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    twice = json.loads(run_cmd([*axis_prefix(), "emit-json", str(again)]).stdout)
    said_so = lambda doc: {c["name"][3:]: c.get("load_order") for c in doc.get("cores", [])  # noqa: E731
                           if c["name"].startswith("lo_")}
    checks += 1
    if said_so(facts) != said_so(twice) or said_so(facts) != {n: back for n, (_, back) in MACHINES.items()}:
        fail(f"the load order the description declares is not what is read back: {said_so(twice)}")

    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / "lo_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("lo_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    latency_of = {e["mnemonic"]: e.get("latency_cycles", 1) for e in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    bnz = branch_encoder(lift, tests)
    if asm.missing() or bnz is None or FENCE not in asm.tests:
        sys.modules.pop("lo_lift", None)
        print(f"  lo: DECLINED {asm.missing() or 'no branch, or no fence'}")
        return 0, 0
    programs = build_programs(asm, bnz)
    slot = lambda i: lift.register_slot(asm.kind, i)  # noqa: E731
    datum = 0x11 * (slot(3) + 1)
    sys.modules.pop("lo_lift", None)

    runs, expect = [], []

    def alone(tag, machine, label):
        runs.append(f'  alone("{tag}", "lo_{machine}", 0, {label}, {len(programs[label])}, 5u);')
        expect.append(f"{tag}.0")

    def together(tag, machine, labels, shared):
        runs.append("  { static const uint32_t *const w[] = { " + ", ".join(labels) + " }; "
                    "static const int32_t n[] = { " + ", ".join(str(len(programs[x])) for x in labels)
                    + " }; " + f'together("{tag}", "lo_{machine}", {len(labels)}, w, n, {shared}, 5u, 0u); }}')
        expect.extend(f"{tag}.{c}" for c in range(len(labels)))

    readers = ("TWO", "TWOF", "ONE")
    for machine in MACHINES:
        for reader in readers:
            for w in WAITS:
                for r in WAITS:
                    together(f"{reader}_{machine}_{w}_{r}", machine, [f"W_{w}", f"{reader}_{r}"], 1)
        for sb in ("SB", "SBF"):
            for w in WAITS:
                for r in WAITS:
                    together(f"{sb}_{machine}_{w}_{r}", machine, [f"{sb}0_{w}", f"{sb}1_{r}"], 1)
        together(f"APART_{machine}", machine, [f"R{k}" for k in range(SEEDS)], 0)
        for k in range(SEEDS):
            alone(f"ALONE_R{k}_{machine}", machine, f"R{k}")

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

    checks += 1
    replayed = sorted(tag for tag, row in said.items() if row["replays"])
    if replayed:
        fail(f"the golden model disagreed with the pipeline (replays) in {replayed[:6]}")

    def read(reader, machine):
        return {(said[f"{reader}_{machine}_{w}_{r}.1"]["out"], said[f"{reader}_{machine}_{w}_{r}.1"]["out2"])
                for w in WAITS for r in WAITS}

    def both(sb, machine):
        return {(said[f"{sb}_{machine}_{w}_{r}.0"]["out"], said[f"{sb}_{machine}_{w}_{r}.1"]["out"])
                for w in WAITS for r in WAITS}

    def squashed(sb, machine):
        return sum(said[f"{sb}_{machine}_{w}_{r}.{c}"]["snoops"] for w in WAITS for r in WAITS for c in (0, 1))

    for machine, (clauses, order) in MACHINES.items():
        relaxed = order == "any"
        kept = order in ("any", "tso")
        seen = both("SB", machine)
        checks += 1
        if not seen <= {(0, 0), (0, 1), (1, 0), (1, 1)}:
            fail(f"a store and a load each on lo_{machine} read something never stored: {sorted(seen)}")
        checks += 1
        if ((0, 0) in seen) != kept:
            fail(f"a store and a load of the other word on each of two lo_{machine} read {sorted(seen)}; "
                 f"both 0 {'at some timing, each load kept' if kept else 'never, each load read again'}")
        checks += 1
        if (0, 0) in both("SBF", machine):
            fail(f"a store, a fence and a load on each of two lo_{machine} both read 0")
        # A load no older load is behind is not squashed where loads are kept.
        checks += 1
        if (squashed("SB", machine) == 0) != kept:
            fail(f"{squashed('SB', machine)} loads were squashed on lo_{machine} with a store and a load "
                 f"on each core; {'none is, each is kept' if kept else 'in order some are'}")
        seen = read("TWO", machine)
        checks += 1
        if not seen <= {(0, 0), (0, datum), (1, 0), (1, datum)}:
            fail(f"two loads on lo_{machine} read something never stored: {sorted(seen)}")
        checks += 1
        if ((1, 0) in seen) != relaxed:
            fail(f"two loads on lo_{machine} read {sorted(seen)}; the flag and not the datum "
                 f"{'at some timing, the datum having been read first' if relaxed else 'never, in order'}")
        # The timings reach both sides of the stores: a reader done before
        # them, and one whose first load comes after -- which in order reads
        # the datum again, and in any order is the one that kept it.
        checks += 1
        if not {(0, 0), (1, 0) if relaxed else (1, datum)} <= seen:
            fail(f"two loads on lo_{machine} read only {sorted(seen)}; the timings should reach "
                 f"before both stores and after both")
        checks += 1
        if (1, 0) in read("TWOF", machine):
            fail(f"two loads with a fence between them read the flag and not the datum on lo_{machine}")
        checks += 1
        if (1, 0) in read("ONE", machine) or not read("ONE", machine) <= {(0, 0), (0, 1), (1, 1)}:
            fail(f"two loads of one word on lo_{machine} read {sorted(read('ONE', machine))}; "
                 f"never set and then clear")
        for k in range(SEEDS):
            mine, plain = said[f"ALONE_R{k}_{machine}.0"], said[f"ALONE_R{k}_order.0"]
            beside = said[f"APART_{machine}.{k}"]
            checks += 1
            if (mine["steps"], mine["mark"]) != (plain["steps"], plain["mark"]) or beside["steps"] != plain["steps"]:
                fail(f"R{k} on lo_{machine} left other registers or memory than on lo_order, "
                     f"or ran other instructions beside another core")
    return checks, failures


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="axis_lo_") as tmp:
        try:
            checks, failures = check(Path(tmp))
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL lo: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print("a load overtaken keeps what it read: SKIP")
        return DECLINED
    print(f"a load overtaken keeps what it read: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
