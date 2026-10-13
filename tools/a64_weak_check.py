#!/usr/bin/env python3
"""AArch64 cores on one memory show what Arm's model allows. Gate.

`store_buffer_check.py` and `load_order_check.py` hold the store buffer (WM1)
and loads seen in any order (WM2) on a corpus small enough to count cycles in
(docs/memory_model_design.md). This holds the same on the instructions the
model was written for: `aarch64_base`, whose ISA says `(memory-model armv8)`,
with `STR`, `LDR` and `DMB`. Four machines alike but for the two clauses --
none (sequentially consistent), a buffer drained in order (total store
order), the same with `(load-order tso)` (WM6), which shows what that one
shows and squashes fewer loads, and a buffer drained in any order with loads
in any order (relaxed) -- two cores each, over a sweep of timings:

  * **store buffering** (each stores its flag, then loads the other's): both
    loads read 0 with a buffer, never without, and never with a `DMB` after
    each store;
  * **message passing** (datum, then flag; the reader waits for the flag):
    the reader sees the flag and not the datum only on the relaxed machine,
    and never with a `DMB` between the stores;
  * **loads out of order** (the reader's load of the flag has its address
    late, so the datum is read first): the flag and not the datum only on the
    relaxed machine, never with a `DMB` between the loads -- and two loads of
    the flag never see it set and then clear;
  * no replays anywhere: what a core read is what its golden model reads.

Usage: tools/a64_weak_check.py
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
from mcx_check import CODE, DATA, ENTRY, HARNESS, MAXC, REGION  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
MISS = 30
WAITS = range(0, 7)
VALUE, BASE, MINUS_ONE, ONE, COUNTER, OUT, OUT2, HOLD, LATE, SPIN, XZR = 3, 5, 7, 8, 9, 20, 21, 22, 24, 30, 31


class Words:
    """Words from the corpus's own test encodings, with operands placed."""

    def __init__(self, lift, tests, isa):
        self.lift = lift
        self.by = {e["mnemonic"]: e for e in lift.AXIS_LIFT_TABLE if e.get("isa") == isa}
        self.word = {t["mnemonic"]: int(t["encoded"], 16) for t in tests if (t.get("isa") or isa) == isa}

    def missing(self, needed):
        return [m for m in needed if m not in self.by or m not in self.word]

    def __call__(self, mnemonic, **operands):
        word = self.word[mnemonic]
        for name, value in operands.items():
            word = self.lift.place_operand(word, self.by[mnemonic], name, value)
        return word


#: What a gate of this shape needs to know of an ISA: the litmus words a
#: line apart in the units its load counts offsets in, and its instructions.
A64 = {
    "corpus": "aarch64_translation_seed.axisl", "isa": "aarch64_base", "model": "armv8", "kind": "a64_gpr64",
    "prefix": "wk", "width": 64, "fence": "DMB", "title": "AArch64 cores show what Arm's model allows",
    "at": (0, 8, 16, 24),
    "needed": ["LDR_X_UNSIGNED", "STR_X_UNSIGNED", "MADD_X", "CBZ_X", "DMB"],
    "ld": lambda a, rt, rn, at: a("LDR_X_UNSIGNED", rt=rt, rn=rn, imm=at),
    "st": lambda a, rt, rn, at: a("STR_X_UNSIGNED", rt=rt, rn=rn, imm=at),
    "mul": lambda a, rd, rn, rm: a("MADD_X", rd=rd, rn=rn, rm=rm, ra=XZR),
    "barrier": lambda a: a("DMB", option=15),
    "spin": lambda a, reg: a("CBZ_X", rt=reg, imm=-1),
}

ADDED = """
  (defmemory {prefix}d (kind cache) (size-bytes 4096) (line-bytes 64) (ways 1)
    (width-bits {width}) (latency-cycles {miss}))
"""

CORE = """
  (defcore {prefix}_{name} (kind rvmt) (memory {prefix}d) (implements {isa}) (issue-width 4)
    (window (rob 32) (issue-queue 32) (commit-width 4))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2)){clauses}
    (engine execute))
"""

MACHINES = {
    "sc": "",
    "tso": "\n    (store-buffer (entries 8))",
    "kept": "\n    (store-buffer (entries 8))\n    (load-order tso)",
    "weak": "\n    (store-buffer (entries 8) (drain any))\n    (load-order any)",
}


def build_programs(a: Words, target):
    X, Y, DATUM, FLAG = target["at"]
    ld = lambda rt, rn, at: target["ld"](a, rt, rn, at)  # noqa: E731
    st = lambda rt, rn, at: target["st"](a, rt, rn, at)  # noqa: E731
    mul = lambda rd, rn, rm: target["mul"](a, rd, rn, rm)  # noqa: E731
    dmb = target["barrier"](a)
    delay = lambda n: [mul(SPIN, SPIN, SPIN) for _ in range(n)]  # noqa: E731
    # The base again, through multiplies by one: an address formed late.
    late = lambda n: [mul(LATE, BASE, ONE)] + [mul(LATE, LATE, ONE) for _ in range(6 + 2 * n)]  # noqa: E731
    both = [ld(HOLD, BASE, FLAG), ld(HOLD, BASE, DATUM)] + delay(12)
    programs = {}
    for w in WAITS:
        for mine, theirs, tag in ((X, Y, 0), (Y, X, 1)):
            # Each holds the line it will read before it starts, and not the
            # one it will write: its load is done while its store still waits.
            held = [ld(HOLD, BASE, theirs)] + delay(12 + w)
            programs[f"SB{tag}_{w}"] = held + [st(ONE, BASE, mine), ld(OUT, BASE, theirs), 0]
            programs[f"SBD{tag}_{w}"] = held + [st(ONE, BASE, mine), dmb, ld(OUT, BASE, theirs), 0]
        # The writer holds the flag's line before it starts, and not the datum's.
        warm = [ld(HOLD, BASE, FLAG)] + delay(14 + w)
        programs[f"MPW_{w}"] = warm + [st(VALUE, BASE, DATUM), st(ONE, BASE, FLAG), 0]
        programs[f"MPWD_{w}"] = warm + [st(VALUE, BASE, DATUM), dmb, st(ONE, BASE, FLAG), 0]
        # A writer that holds both lines: its stores are written as they retire.
        programs[f"W_{w}"] = both + delay(w) + [st(VALUE, BASE, DATUM), st(ONE, BASE, FLAG), 0]
        # Readers that hold both lines, and load the flag through a late address.
        programs[f"TWO_{w}"] = both + late(w) + [ld(OUT, LATE, FLAG), ld(OUT2, BASE, DATUM), 0]
        programs[f"TWOD_{w}"] = both + late(w) + [ld(OUT, LATE, FLAG), dmb, ld(OUT2, BASE, DATUM), 0]
        programs[f"ONE_{w}"] = both + late(w) + [ld(OUT, LATE, FLAG), ld(OUT2, BASE, FLAG), 0]
    # The reader holds both lines, spins while the flag is clear, then reads.
    programs["MPR"] = [ld(HOLD, BASE, DATUM), ld(OUT, BASE, FLAG), target["spin"](a, OUT),
                       ld(OUT2, BASE, DATUM), 0]
    return programs


def check(work: Path, target) -> tuple[int, int]:
    ISA, GPR, FENCE, P = target["isa"], target["kind"], target["fence"], target["prefix"]
    source = (AXIS_ROOT / "examples" / target["corpus"]).read_text()
    end = source.rstrip().rfind(")")

    def run_cmd(cmd, check=True):
        return subprocess.run(cmd, capture_output=True, text=True, check=check, cwd=AXIS_ROOT)

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {message}")
        failures += 1

    corpus = work / f"{P}.axisl"
    corpus.write_text(source[:end] + ADDED.format(prefix=P, width=target["width"], miss=MISS)
                      + "".join(CORE.format(prefix=P, name=n, isa=ISA, clauses=c) for n, c in MACHINES.items())
                      + ")\n")
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(corpus)]).stdout)
    model = next((i.get("memory_model") for i in facts.get("isas", []) if i.get("name") == ISA), None)
    checks += 1
    if model != target["model"]:
        fail(f"`{ISA}` says its memory model is {model!r}, not {target['model']}")
    manifest = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    run_cmd([*axis_prefix(), "emit-lift-python", str(corpus), "-o", str(work / f"{P}_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"{P}_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json", str(corpus)]).stdout)["tests"]
    a = Words(lift, tests, ISA)
    if a.missing(target["needed"]):
        sys.modules.pop(f"{P}_lift", None)
        print(f"  {P}: DECLINED {a.missing(target['needed'])}")
        return 0, 0
    programs = build_programs(a, target)
    slot = lambda i: lift.register_slot(GPR, i)  # noqa: E731
    datum = 0x11 * (slot(VALUE) + 1)
    sys.modules.pop(f"{P}_lift", None)

    runs, expect = [], []

    def together(tag, machine, labels):
        runs.append("  { static const uint32_t *const w[] = { " + ", ".join(labels) + " }; "
                    "static const int32_t n[] = { " + ", ".join(str(len(programs[x])) for x in labels)
                    + " }; " + f'together("{tag}", "{P}_{machine}", {len(labels)}, w, n, 1, 5u, 0u); }}')
        expect.extend(f"{tag}.{c}" for c in range(len(labels)))

    for machine in MACHINES:
        for w0 in WAITS:
            for w1 in WAITS:
                together(f"SB_{machine}_{w0}_{w1}", machine, [f"SB0_{w0}", f"SB1_{w1}"])
                together(f"SBD_{machine}_{w0}_{w1}", machine, [f"SBD0_{w0}", f"SBD1_{w1}"])
                for reader in ("TWO", "TWOD", "ONE"):
                    together(f"{reader}_{machine}_{w0}_{w1}", machine, [f"W_{w0}", f"{reader}_{w1}"])
        for w in WAITS:
            together(f"MP_{machine}_{w}", machine, [f"MPW_{w}", "MPR"])
            together(f"MPD_{machine}_{w}", machine, [f"MPWD_{w}", "MPR"])

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
    done = subprocess.run([str(work / name)], capture_output=True, text=True, timeout=1800)
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
             f"{[t for t in expect if t not in said][:4]} {done.stdout[:200]}")
        return checks, failures

    # No replays, anywhere: what a core read is what its golden model reads.
    checks += 1
    replayed = sorted(tag for tag, row in said.items() if row["replays"])
    if replayed:
        fail(f"the golden model disagreed with the pipeline (replays) in {replayed[:6]}")

    def pairs(prefix, machine):
        return {(said[f"{prefix}_{machine}_{x}_{y}.0"]["out"], said[f"{prefix}_{machine}_{x}_{y}.1"]["out"])
                for x in WAITS for y in WAITS}

    def reader(prefix, machine):
        return {(said[f"{prefix}_{machine}_{x}_{y}.1"]["out"], said[f"{prefix}_{machine}_{x}_{y}.1"]["out2"])
                for x in WAITS for y in WAITS}

    def got(prefix, machine):
        return {said[f"{prefix}_{machine}_{w}.1"]["out2"] for w in WAITS}

    for machine in MACHINES:
        on = f"{P}_{machine}"
        seen = pairs("SB", machine)
        checks += 1
        if not seen <= {(0, 0), (0, 1), (1, 0), (1, 1)} or ((0, 0) in seen) != (machine != "sc"):
            fail(f"store buffering on {on} read {sorted(seen)}; both loads read 0 "
                 f"{'only with a buffer' if machine == 'sc' else 'when each store is still in its buffer'}")
        checks += 1
        if (0, 0) in pairs("SBD", machine):
            fail(f"store buffering with a {FENCE} after each store read (0, 0) on {on}")
        checks += 1
        if not got("MP", machine) <= {0, datum} or (0 in got("MP", machine)) != (machine == "weak"):
            fail(f"message passing on {on} read {sorted(got('MP', machine))}; the flag is written "
                 f"before the datum only by a buffer that drains in any order")
        checks += 1
        if got("MPD", machine) != {datum}:
            fail(f"message passing with a {FENCE} between the stores read {sorted(got('MPD', machine))} "
                 f"on {on}, not the datum {datum}")
        seen = reader("TWO", machine)
        checks += 1
        if not seen <= {(0, 0), (0, datum), (1, datum), (1, 0)} or ((1, 0) in seen) != (machine == "weak"):
            fail(f"two loads on {on} read {sorted(seen)}; the flag and not the datum "
                 f"{'at some timing, the datum having been read first' if machine == 'weak' else 'never, in order'}")
        checks += 1
        if len(seen) < 2:
            fail(f"two loads on {on} read only {sorted(seen)}; the sweep does not cross the writer's stores")
        checks += 1
        if (1, 0) in reader("TWOD", machine):
            fail(f"two loads with a {FENCE} between them read the flag and not the datum on {on}")
        checks += 1
        if (1, 0) in reader("ONE", machine):
            fail(f"two loads of one word on {on} read {sorted(reader('ONE', machine))}; never set and then clear")
    # Total store order's loads: the reader's loads the writer's stores
    # overtake are kept where every older load has read, and squashed in order.
    squashed = lambda machine: sum(said[f"MP_{machine}_{w}.1"]["snoops"] for w in WAITS)  # noqa: E731
    checks += 1
    if squashed("kept") or not squashed("tso"):
        fail(f"message passing squashed {squashed('kept')} loads on {P}_kept and {squashed('tso')} on "
             f"{P}_tso; none where a load every older load of which has read is kept, some in order")
    return checks, failures


def main(target=None) -> int:
    target = target or A64
    with tempfile.TemporaryDirectory(prefix=f"axis_{target['prefix']}_") as tmp:
        try:
            checks, failures = check(Path(tmp), target)
        except subprocess.CalledProcessError as error:
            said = (error.stderr or error.stdout or str(error)).strip()
            print(f"  FAIL {target['prefix']}: {said[-400:]}")
            checks, failures = 0, 1
    if not checks and not failures:
        print(f"{target['title']}: SKIP")
        return DECLINED
    print(f"{target['title']}: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
