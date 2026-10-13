#!/usr/bin/env python3
"""Every path the explorer reports is one the machine can actually take.

`symbolic_machine_check.py` draws random inputs and asks which explored path
holds -- **completeness**: no real run is missing from the set. This asks the
other half. For each path, a solver is given that path's constraints and asked
for an input satisfying them; the concrete machine is then run on exactly that
input and has to take **that** path -- **soundness**: no path in the set is
invented.

⚠️ This is the first thing here that asks a solver a question about
*reachability* rather than equality, which is what a symbolic executor is for.
It is also the only check of `path_smt`, the interface a caller actually uses:
before this, the constraints were rendered into a script no one had ever
solved.

A path whose constraints are unsatisfiable is **infeasible**, not a failure:
the explorer forks without asking whether a branch can be taken, so some paths
it lists cannot happen. Those are counted, and a run where every path was
infeasible is a run that measured nothing.

⚠️ The programs hold no loads. A model has to fix memory as well as registers,
and constraining an array byte by byte is a different piece of work; the
machine gate covers memory, and this covers branching.

Usage: tools/symbolic_path_check.py [input.axisl] [--programs N]
"""
from __future__ import annotations

import argparse
import importlib
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import symbolic_machine_check as machine  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: `(define-fun r5 () (_ BitVec 64) #x000000000000002a)`, and the `bv` spelling.
MODEL = re.compile(
    r"\(define-fun (\S+) \(\) \(_ BitVec (\d+)\)\s+(#x[0-9a-fA-F]+|#b[01]+|\(_ bv(\d+) \d+\))\)")


def model_of(text: str) -> dict[str, int]:
    """What the solver chose, as numbers."""
    out = {}
    for name, _bits, literal, decimal in MODEL.findall(text):
        if decimal:
            out[name] = int(decimal)
        elif literal.startswith("#x"):
            out[name] = int(literal[2:], 16)
        else:
            out[name] = int(literal[2:], 2)
    return out


def solve(z3: str, script: str, workdir: Path, index: int, timeout: int):
    """(satisfiable, model). `None` when the solver would not answer."""
    path = workdir / f"path{index}.smt2"
    path.write_text(script + "(get-model)\n")
    try:
        done = subprocess.run([z3, "-smt2", f"-T:{timeout}", str(path)],
                              capture_output=True, text=True, timeout=timeout + 10)
    except subprocess.TimeoutExpired:
        return None, {}
    head = done.stdout.strip().splitlines()[:1]
    if not head:
        return None, {}
    # ⚠️ A REJECTED script is not an unanswered question. The solver refusing
    # the input -- an unknown operator, a sort mismatch -- is a defect in the
    # backend that wrote it, and filing it beside timeouts made one look like
    # a flaky solver for as long as the path happened to be sampled.
    if head[0].strip().startswith("(error"):
        return "error", {"message": head[0].strip()}
    if head[0].strip() == "unsat":
        return False, {}
    if head[0].strip() != "sat":
        return None, {}
    return True, model_of(done.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    parser.add_argument("--programs", type=int, default=8)
    parser.add_argument("--length", type=int, default=6)
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    z3 = shutil.which("z3")
    if z3 is None:
        print("no solver on the path: SKIP")
        return DECLINED

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for command, name in machine.ARTIFACTS:
            subprocess.run([*axis_prefix(), command, str(args.axis_file),
                            "-o", str(workdir / name)], check=True,
                           capture_output=True, cwd=AXIS_ROOT)
        sys.path.insert(0, str(workdir))
        lift = importlib.import_module("axis_lift")
        executor = importlib.import_module("axis_exec")
        sym = importlib.import_module("axis_symbolic")

        slots = lift.REGISTER_FILE_SLOTS
        table = lift.AXIS_LIFT_TABLE

        def reads_memory(entry):
            texts = [entry.get("semantics") or ""]
            texts += [effect.get("value") or "" for effect in (entry.get("effects") or [])]
            texts += [effect.get("guard") or "" for effect in (entry.get("effects") or [])]
            return any("load" in text for text in texts) or any(
                effect["kind"] == "store" for effect in (entry.get("effects") or []))

        plain = [e for e in table
                 if machine.usable(lift, e, {"set", "trap", "barrier", "setstate"})
                 and not reads_memory(e)
                 and not any(f["kind"] == "setpc" for f in (e.get("effects") or []))]
        branches = [e for e in table
                    if machine.usable(lift, e, {"set", "setpc"})
                    and not reads_memory(e)
                    and any(f["kind"] == "setpc" and f.get("guard")
                            for f in (e.get("effects") or []))]
        if not plain or not branches:
            print("a path needs a branch to fork at: SKIP")
            return DECLINED

        import random
        rng = random.Random(0x9A71)
        feasible = infeasible = unanswered = failures = unrenderable = 0
        reasons: dict[str, str] = {}
        programs = 0
        # Sorted: iterating a SET orders by hash, which Python randomises per
        # process, so the ISA each program was drawn from -- and so the whole
        # sample -- changed from run to run despite the seeded generator.
        isas = sorted(name for name in {e.get("isa") for e in plain} if name)

        for index in range(args.programs):
            here = isas[index % len(isas)] if isas else None
            pool = [e for e in plain if e.get("isa") == here] or plain
            forks = [e for e in branches if e.get("isa") == here] or branches
            image = bytearray(rng.getrandbits(8) for _ in range(machine.IMAGE))
            words, shapes = machine.build(lift, rng, pool, args.length, forks)
            if len(words) < 2:
                continue
            for k, (word, _isa) in enumerate(words):
                image[machine.CODE + 4 * k:machine.CODE + 4 * k + 4] = word.to_bytes(4, "little")
            image = bytes(image)
            end = machine.CODE + 4 * len(words)
            start = sym.State(slots, image, pc=machine.CODE, code=(machine.CODE, end))
            found = sym.explore(
                start, steps=args.length * 2, paths=16, isa=words[0][1],
                stop=lambda m: not (m.pc[0] == "const"
                                    and machine.CODE <= m.pc[2] < end))
            paths = [p for p in found["finished"] if not p.declined]
            if not paths:
                continue
            programs += 1

            for number, path in enumerate(paths):
                if not path.path:
                    continue          # nothing branched: no question to ask
                try:
                    script = sym.path_smt(path)
                except sym.Declined as why:
                    # A constraint this backend cannot render is a path no
                    # solver can be asked about -- counted by name, because a
                    # gate that skipped it silently would be reporting a
                    # smaller set of paths than the explorer found.
                    unrenderable += 1
                    reasons.setdefault(str(why), shapes[0] if shapes else "?")
                    continue
                answer, model = solve(z3, script, workdir,
                                      index * 100 + number, args.timeout)
                if answer == "error":
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: the solver rejected "
                              f"the path's script: {model['message'][:160]}")
                    continue
                if answer is None:
                    unanswered += 1
                    continue
                if not answer:
                    infeasible += 1
                    continue
                feasible += 1

                # ⚠️ The solver's input, not a random one: the machine must
                # take THIS path when run on it.
                values = [model.get(f"r{slot}", 0) for slot in range(slots)]
                state = {name: model.get(f"state_{name}", 0)
                         for name, _bits in lift.STATE_SLOTS}
                truth = machine.concrete_run(lift, executor, words, image, values,
                                             args.length * 2, state)
                if truth is None:
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: the machine would not "
                              f"run the input the solver chose")
                    continue
                bindings = path.bindings(values, state, image)
                if not path.holds(bindings):
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: the solver's model does "
                              f"not satisfy the path it came from")
                    continue
                where = path.pc[2] if path.pc[0] == "const" else None
                if bool(path.trapped) != bool(truth["trapped"]):
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: path trapped "
                              f"{path.trapped!r}, machine {truth['trapped']!r}")
                    continue
                if not path.trapped and where != truth["pc"]:
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: the solver's input took "
                              f"the machine to {truth['pc']:#x}, not {where:#x}")
                    continue
                # ⚠️ The registers, not only where it stopped. Every path
                # through a program whose branches jump FORWARD ends at the
                # same address, so the pc alone cannot tell one path from
                # another -- and two deliberately broken forks passed while
                # this compared nothing else.
                wrong = None
                for slot in range(slots):
                    got = sym.concrete(path.regs[slot], bindings)
                    want = truth["regs"].get(slot, 0)
                    if got != want:
                        wrong = (f"slot {slot}: path {got:#x} != machine {want:#x}")
                        break
                if wrong is None:
                    for name, bits in lift.STATE_SLOTS:
                        term = path.state.get(name) or sym.var(f"state_{name}", bits)
                        got = sym.concrete(term, bindings)
                        want = truth["state"].get(name, 0) & ((1 << bits) - 1)
                        if got != want:
                            wrong = f"state {name}: path {got:#x} != machine {want:#x}"
                            break
                if wrong:
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: on the solver's own "
                              f"input, {wrong}")

    print(f"{programs} program(s), {feasible} path(s) the solver made real and the "
          f"machine then took, {failures} it did not")
    print(f"  {infeasible} path(s) the explorer listed that cannot happen, "
          f"{unanswered} the solver would not answer, {unrenderable} whose "
          f"constraints this cannot render")
    for why, where in sorted(reasons.items())[:3]:
        print(f"    {why} (e.g. {where})")
    if not feasible:
        print("every path is one the machine takes: SKIP (nothing was solved)")
        return DECLINED
    print("every path is one the machine takes:",
          "FAIL" if failures or unanswered else "PASS")
    return FAILED if failures or unanswered else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
