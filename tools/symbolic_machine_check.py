#!/usr/bin/env python3
"""A symbolic MACHINE agrees with the concrete one -- every path, no solver.

`symbolic_check.py` holds one instruction at a time to the executor. This holds
a whole program: registers, a pc, memory and architectural state, explored over
*every* path a branch can take, from inputs that are free variables.

⚠️ The property is sharper than agreement, and it needs no solver. Explore the
program once from free inputs, producing a set of paths each carrying the
constraints that would have to hold for it to be the one taken. Then run the
same program concretely from random inputs and bind the variables to them:

* **exactly one** explored path may hold -- two means the fork invented a way
  the machine cannot go, none means it lost the way the machine did go;
* that path's registers, pc and memory must equal the concrete machine's.

A symbolic executor that forks wrongly, mis-orders a guard, or loses a store
through aliasing fails one of those two, and neither failure needs a solver to
see.

Memory is an array term, so a store to a computed address and a load from
another computed address alias exactly when the addresses are equal -- which is
what the concrete comparison then checks, byte for byte.

Usage: tools/symbolic_machine_check.py [input.axisl] [--programs N] [--cases N]
"""
from __future__ import annotations

import argparse
import importlib
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ARTIFACTS = (
    ("emit-lift-python", "axis_lift.py"),
    ("emit-golden-python", "golden_model.py"),
    ("emit-exec-python", "axis_exec.py"),
    ("emit-symbolic-python", "axis_symbolic.py"),
)

#: Where the program sits, and where its data does. Far enough apart that a
#: seeded address register reaches the data and not the code.
CODE = 0x100
DATA = 0x800
IMAGE = 1 << 12


class Mem:
    """The concrete side's memory: sparse, unbounded, byte for byte.

    ⚠️ Not a `bytearray`. Python slice assignment past the end APPENDS rather
    than writing where it was told, so a store to a wild address landed
    quietly at the end of the image and read back as zero -- which looks
    exactly like a symbolic executor losing a store, and cost an afternoon.
    The rule here is the one the symbolic memory follows: a byte is what was
    written, else the image's, else zero, at any address a register can hold.
    """

    def __init__(self, image, bits=64):
        self.image = bytes(image)
        self.cells = {}
        # The machine's address width, not a constant. RV32I's addresses wrap
        # at 32 bits and RV64I's at 64, and a harness that wrapped at the wrong
        # one disagreed with the terms about the byte after the last address.
        self.WRAP = (1 << bits) - 1

    def byte(self, address):
        if address in self.cells:
            return self.cells[address]
        return self.image[address] if 0 <= address < len(self.image) else 0

    #: ⚠️ Byte addresses wrap, because the machine's do. A load at the top of
    #: the address space reads its last byte and then address 0, which is what
    #: the symbolic side's `bvadd` does -- while Python's `addr + 1` just keeps
    #: counting and read zero instead. Found by seeding an all-ones register.
    def read(self, addr, width):
        return int.from_bytes(
            bytes(self.byte((addr + i) & self.WRAP) for i in range(width // 8)),
            "little")

    def write(self, addr, value, width):
        for i in range(width // 8):
            self.cells[(addr + i) & self.WRAP] = (value >> (8 * i)) & 0xFF


def usable(lift, entry, kinds):
    """Whether this instruction is one a program can be built out of.

    Register operands only (an immediate is fine), and its effects among the
    kinds asked for. `enc` operands are encoding constraints rather than
    choices, so they are left as the match word has them.
    """
    if entry.get("implementation"):
        return False
    for operand in entry["operands"]:
        if operand["kind"] != "imm" and not lift.is_register_operand(operand["kind"]):
            return False
    effects = entry.get("effects") or []
    return all(effect["kind"] in kinds for effect in effects)


def build(lift, rng, entries, count, branch_entries, guarded_entries=(),
          trap_entries=(), store_entries=()):
    """A program: arithmetic, memory, guarded writes and branches, at CODE.

    A branch's immediate is chosen so its target lands inside the program --
    forward, so exploration terminates -- because a branch out of the region is
    a path that stops rather than a fork that is followed.

    ⚠️ A guarded write that is not a branch is placed deliberately. Without one,
    turning `ite(guard, new, old)` into `new` -- saying every conditional write
    happened -- passed this gate, because nothing it ran had a guard on
    anything but a `setpc`.
    """
    words, shapes = [], []
    for index in range(count):
        want_branch = branch_entries and index in (1, count - 2)
        want_guard = guarded_entries and index == 2
        want_trap = trap_entries and index == 3
        # ⚠️ TWO stores, at both ends. One store cannot alias another, and a
        # corpus whose random instructions rarely write memory -- AArch64's --
        # left the whole aliasing question untested while RISC-V's atomics
        # covered it by accident.
        want_store = store_entries and index in (0, count - 1)
        entry = (rng.choice(branch_entries) if want_branch
                 else rng.choice(guarded_entries) if want_guard
                 else rng.choice(trap_entries) if want_trap
                 else rng.choice(store_entries) if want_store
                 else rng.choice(entries))
        word = entry["match"]
        # ⚠️ A memory instruction gets a zero offset and a base from a pair of
        # registers. Left random, two stores in a program never landed on the
        # same address -- AArch64 scales its offsets, so equal bases were not
        # enough -- and the aliasing an array-valued memory exists to model
        # went untested.
        touches_memory = any(f["kind"] in ("store",) or "load" in (f.get("value") or "")
                             for f in (entry.get("effects") or []))
        for operand in entry["operands"]:
            if operand["role"] == "enc":
                continue
            if operand["kind"] == "imm":
                # Forward, aligned, and short enough to stay in the program.
                value = (8 if want_branch else 0 if touches_memory
                         else rng.randrange(0, 16) * 2)
            elif touches_memory:
                value = rng.randrange(1, 3)
            else:
                # ⚠️ From 0, not from 1. Index 0 is RISC-V's hardwired zero,
                # and a program that never named it never tested that a write
                # there is discarded and a read there is zero.
                value = rng.randrange(0, 8)
            word = lift.place_operand(word, entry, operand["name"], value)
        decoded = lift.decode(word, entry.get("isa"))
        if decoded is None or decoded["mnemonic"] != entry["mnemonic"]:
            continue                     # the word we built is not the one we meant
        words.append((word, entry.get("isa")))
        shapes.append(entry["mnemonic"])
    return words, shapes


def concrete_run(lift, executor, words, image, values, steps, start_state, bits=64):
    """The machine, concretely: fetch from the pc, step, follow `next_pc`."""
    regs = {slot: value for slot, value in enumerate(values)}
    memory = Mem(image)
    state = dict(start_state)
    pc = CODE
    isa = words[0][1] if words else None
    for _ in range(steps):
        if not CODE <= pc < CODE + 4 * len(words):
            break
        word = memory.read(pc, 32)
        out = executor.step(word, regs, mem=memory, pc=pc, isa=isa, state=state)
        if out is None:
            return None
        if out.get("trap"):
            # A trap ends the concrete run the way it ends a symbolic path,
            # and the two have to agree about that as much as about registers.
            return {"regs": regs, "mem": memory, "pc": pc, "state": state,
                    "trapped": out["trap"]}
        pc = out.get("next_pc") if out.get("next_pc") is not None else pc + 4
    return {"regs": regs, "mem": memory, "pc": pc, "state": state, "trapped": None}


def _aliasing(sym, mem, bindings):
    """How many addresses this path stored to more than once.

    Reported rather than assumed: aliasing is the whole reason memory is an
    array term, and a run where no two stores met would not have tested it.
    """
    seen, twice = set(), 0
    while mem[0] == "store":
        _kind, _width, inner, addr, _value = mem
        at = sym.concrete(addr, bindings)
        if at in seen:
            twice += 1
        seen.add(at)
        mem = inner
    return twice


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    parser.add_argument("--programs", type=int, default=8)
    parser.add_argument("--length", type=int, default=6)
    parser.add_argument("--cases", type=int, default=6)
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for command, name in ARTIFACTS:
            subprocess.run([*axis_prefix(), command, str(args.axis_file),
                            "-o", str(workdir / name)], check=True,
                           capture_output=True, cwd=AXIS_ROOT)
        sys.path.insert(0, str(workdir))
        lift = importlib.import_module("axis_lift")
        executor = importlib.import_module("axis_exec")
        sym = importlib.import_module("axis_symbolic")

        slots = lift.REGISTER_FILE_SLOTS
        table = lift.AXIS_LIFT_TABLE
        # ⚠️ `trap` and `barrier` belong in the programs. Excluding them kept
        # every floating-point instruction with a dynamic rounding mode out,
        # and a trap fork that recorded the WRONG side of its guard passed.
        plain = [e for e in table
                 if usable(lift, e, {"set", "store", "trap", "barrier", "setstate"})
                 and not any(f["kind"] == "setpc" for f in (e.get("effects") or []))]
        # ⚠️ Guarded traps, counted apart from unguarded ones. The programs
        # contained `ecall` -- which always traps -- and that was enough to
        # report "5 inputs took a trapping path" while the guarded fork, the
        # one with two sides, was never reached: a `setstate` in the same
        # instruction had excluded every floating-point form that has one.
        traps = [e for e in plain
                 if any(f["kind"] == "trap" and f.get("guard")
                        for f in (e.get("effects") or []))]
        branches = [e for e in table
                    if usable(lift, e, {"set", "store", "setpc"})
                    and any(f["kind"] == "setpc" and f.get("guard")
                            for f in (e.get("effects") or []))]
        guarded = [e for e in table if usable(lift, e, {"set", "store", "setstate"})
                   and any(f.get("guard") and f["kind"] != "setpc"
                           for f in (e.get("effects") or []))]
        if not plain:
            print("a machine needs instructions to run: SKIP")
            return DECLINED

        stores = [e for e in plain
                  if any(f["kind"] == "store" for f in (e.get("effects") or []))]
        # A program with a store in it, deliberately: the mix drifted to
        # floating point when traps were allowed in, and the run that found
        # nothing aliasing was a run with almost no stores left.
        rng = random.Random(0x5EC0)
        programs = checked = failures = forks = 0
        guarded_placed = aliased = trapped_runs = trap_forks = 0
        declined: dict[str, str] = {}
        both_ways = 0

        # ⚠️ One ISA per program. A description can hold several -- an
        # accelerator beside the base it accelerates -- and their encodings
        # overlap, so a run that decoded every word under the first word's ISA
        # had most of its instructions come back as something else or as
        # nothing. Forty-one of forty-eight inputs were being skipped in
        # silence.
        isas = [name for name in {e.get("isa") for e in plain} if name]
        for program_index in range(args.programs):
            image = bytearray(rng.getrandbits(8) for _ in range(IMAGE))
            here = isas[program_index % len(isas)] if isas else None
            pool = [e for e in plain if e.get("isa") == here] or plain
            words, shapes = build(lift, rng, pool, args.length,
                                  [e for e in branches if e.get("isa") == here],
                                  [e for e in guarded if e.get("isa") == here],
                                  [e for e in traps if e.get("isa") == here],
                                  [e for e in stores if e.get("isa") == here])
            if len(words) < 2:
                continue
            for index, (word, _isa) in enumerate(words):
                image[CODE + 4 * index:CODE + 4 * index + 4] = word.to_bytes(4, "little")
            image = bytes(image)
            isa = words[0][1]

            # One exploration, from free inputs, over every path.
            start = sym.State(slots, image, pc=CODE,
                              code=(CODE, CODE + 4 * len(words)))
            end = CODE + 4 * len(words)
            found = sym.explore(
                start, steps=args.length * 2, paths=16, isa=isa,
                stop=lambda machine: not (machine.pc[0] == "const"
                                          and CODE <= machine.pc[2] < end))
            for mnemonic, why in found["declined"]:
                declined.setdefault(mnemonic or "?", why)
            paths = found["finished"]
            if len(paths) < 1:
                continue
            programs += 1
            forks += len(paths) - 1
            guarded_placed += sum(1 for name in shapes
                                  if any(e["mnemonic"] == name for e in guarded))
            trap_forks += sum(1 for name in shapes
                              if any(e["mnemonic"] == name for e in traps))

            for _ in range(args.cases):
                # Addresses that land in the data region, and values whose high
                # bit is set -- the ones that tell a signed compare from an
                # unsigned one.
                # ⚠️ A SMALL pool of addresses, so two stores land on one and a
                # load after them sees the newer. With addresses spread over
                # the region, nothing ever aliased -- and a memory that
                # returned the OLDEST store for an address passed this gate.
                pool = [DATA + 8 * k for k in range(4)]
                values = [rng.choice(pool) if rng.random() < 0.6
                          else rng.getrandbits(64) for _ in range(slots)]
                # Architectural state is an input too -- a rounding mode, a
                # reservation -- and holding it at zero is how a guard that
                # depends on it comes out the same way every run.
                start_state = {name: rng.randrange(0, 1 << min(bits, 4))
                               for name, bits in lift.STATE_SLOTS}
                truth = concrete_run(lift, executor, words, image, values,
                                     args.length * 2, start_state, sym.PC_BITS)
                if truth is None:
                    continue
                bindings = paths[0].bindings(values, start_state, image)
                held = [p for p in paths if p.holds(bindings)]
                if len(held) == 1 and held[0].declined:
                    # A path that stopped because something was refused is not
                    # a run to compare against; it is named and skipped.
                    for mnemonic, why in held[0].declined:
                        declined.setdefault(mnemonic or "?", why)
                    continue
                checked += 1
                if len(held) != 1:
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: {len(held)} of "
                              f"{len(paths)} path(s) hold for one input")
                    continue
                path = held[0]
                if len(paths) > 1:
                    both_ways += 1
                if bool(path.trapped) != bool(truth["trapped"]):
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: symbolic trap "
                              f"{path.trapped!r} != concrete {truth['trapped']!r}")
                    continue
                if path.trapped:
                    trapped_runs += 1
                    continue
                if path.pc[0] != "const" or path.pc[2] != truth["pc"]:
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: path ends at "
                              f"{path.pc} != concrete {truth['pc']:#x}")
                    continue
                bad = None
                for slot in range(slots):
                    try:
                        got = sym.concrete(path.regs[slot], bindings)
                    except sym.Declined as why:
                        declined.setdefault("?", str(why))
                        bad = "declined"
                        break
                    if got != truth["regs"].get(slot, 0):
                        bad = (f"slot {slot}: symbolic {got:#x} != concrete "
                               f"{truth['regs'].get(slot, 0):#x}")
                        break
                if bad is None:
                    for kind, rules in lift.REGISTER_CLASSES.items():
                        alias = rules[1]
                        if alias is None:
                            continue
                        term = (path.regs.get(alias[1])
                                or sym.var(f"reg_{alias[1]}", 64))
                        got = sym.concrete(term, bindings)
                        want = truth["regs"].get(alias[1], 0)
                        if got != want:
                            bad = (f"{alias[1]}: symbolic {got:#x} != "
                                   f"concrete {want:#x}")
                            break
                if bad is None:
                    # ⚠️ Architectural state too. A reservation, a rounding
                    # mode, a flag word: the machine's state is not only its
                    # registers, and a guarded `setstate` that ignored its
                    # guard passed this gate while nothing read `frm` or
                    # `exclusive_valid` back out.
                    for name, bits in lift.STATE_SLOTS:
                        term = path.state.get(name) or sym.var(f"state_{name}", bits)
                        got = sym.concrete(term, bindings)
                        want = truth["state"].get(name, 0) & ((1 << bits) - 1)
                        if got != want:
                            bad = f"state {name}: symbolic {got:#x} != concrete {want:#x}"
                            break
                if bad is None:
                    # Memory too, byte for byte over the data region -- a store
                    # that went to the wrong address is invisible in registers.
                    for addr in range(DATA, DATA + 128):
                        got = sym._select(path.mem.term, addr, bindings)
                        if got != truth["mem"].byte(addr):
                            bad = (f"byte {addr:#x}: {got:#x} != "
                                   f"{truth['mem'].byte(addr):#x}")
                            break
                    aliased += _aliasing(sym, path.mem.term, bindings)
                if bad and bad != "declined":
                    failures += 1
                    if failures <= 4:
                        print(f"FAIL {' '.join(shapes)}: {bad}")

        branches, stores = bool(branches), bool(stores)
        guarded, traps = bool(guarded), bool(traps)

    print(f"{programs} program(s) explored, {checked} concrete input(s) matched "
          f"against them, {failures} disagree")
    print(f"  {forks} fork(s) beyond the first path; {both_ways} input(s) "
          f"landed on a program that had more than one")
    print(f"  {guarded_placed} guarded write(s) that are not branches; "
          f"{aliased} store(s) onto an address another store had already used")
    print(f"  {trapped_runs} input(s) took a trapping path; {trap_forks} "
          f"instruction(s) whose trap is guarded, which forks both ways")
    if declined:
        shown = ", ".join(f"{name} ({why})" for name, why in sorted(declined.items())[:3])
        print(f"  {len(declined)} declined: {shown}")
    if not checked:
        print("symbolic machine == concrete machine: SKIP (nothing ran)")
        return DECLINED
    # ⚠️ A run with no fork proves nothing this gate exists for: it is
    # `symbolic_check.py` with extra steps. Say so rather than pass.
    # ⚠️ Coverage, asserted rather than hoped for -- and asserted against what
    # the CORPUS offers. Each of these was a mutation this gate did not catch
    # until the programs it builds contained the thing the name promises; a
    # description with no branch in it cannot fork, and saying so is different
    # from passing quietly.
    if branches and not forks:
        print("symbolic machine == concrete machine: FAIL (the description has "
              "branches and no path ever forked)")
        return FAILED
    if stores and not aliased:
        print("symbolic machine == concrete machine: FAIL (the description has "
              "stores and no two ever met on one address)")
        return FAILED
    if traps and not trap_forks:
        print("symbolic machine == concrete machine: FAIL (the description has "
              "guarded traps and no program contained one)")
        return FAILED
    if traps and not trapped_runs:
        print("symbolic machine == concrete machine: FAIL (the description has "
              "traps and no input ever took one)")
        return FAILED
    if guarded and not guarded_placed:
        print("symbolic machine == concrete machine: FAIL (the description has "
              "guarded writes and none was run)")
        return FAILED
    print("symbolic machine == concrete machine:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
