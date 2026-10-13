#!/usr/bin/env python3
"""Symbolic execution agrees with concrete execution, without a solver.

`emit-symbolic-python` walks the same effects the executors run and evaluates
them to terms: a register holds an expression, memory holds expressions, and a
guarded effect contributes a path constraint rather than a decision.

⚠️ The property that makes this checkable needs no solver. Run a program
concretely from random inputs, run it symbolically from free variables, then
BIND those variables to the concrete inputs and evaluate the terms. Every
register must come out the same. A solver answers questions about *all* inputs;
agreement on one is what says the terms mean what the instructions do -- and it
is the question a symbolic executor gets wrong, since a term that is merely
well-formed solves to the wrong answer in silence.

What it cannot interpret it names: an operator with no bitvector meaning, a
load from a symbolic address, an effect kind beyond `set` and `store`. A
declined instruction is counted, never approximated.

Usage: tools/symbolic_check.py [input.axisl] [--cases N]
"""
from __future__ import annotations

import argparse
import importlib
import json
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
    ("emit-roundtrip-json", "fixtures.json"),
)


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


def variants(lift, entry, word, isa):
    """The fixture's word, and the same instruction at boundary indices.

    ⚠️ A fixture names one register, usually `1`. The indices that mean
    something else -- RISC-V's hardwired `x0`, AArch64's `31` where a class
    aliases `SP` -- then never appear, and three deliberate breaks in the
    register model passed because nothing ever wrote one. The word is rebuilt
    through the field placement that decode reads back, and kept only if it
    still decodes to the same instruction.
    """
    yield word
    for index in (0, 31):
        rebuilt = word
        for operand in entry["operands"]:
            if operand["role"] == "enc" or not operand["fields"]:
                continue
            if not lift.is_register_operand(operand["kind"]):
                continue
            rebuilt = lift.place_operand(rebuilt, entry, operand["name"], index)
        if rebuilt == word:
            continue
        again = lift.decode(rebuilt, isa)
        if again is not None and again["mnemonic"] == entry["mnemonic"]:
            yield rebuilt


#: Values worth seeding beside random ones: the shift amounts that are a whole
#: rotation, the all-ones pattern, the sign bit, zero. A rotate by a multiple
#: of the width has to come back unchanged, and dropping that case let a
#: rotate that turned zero into a full turn pass.
BOUNDARY = (0, 1, 32, 64, (1 << 63), (1 << 64) - 1, (1 << 32) - 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    parser.add_argument("--cases", type=int, default=12)
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
        fixtures = json.loads((workdir / "fixtures.json").read_text())["tests"]

        slots = lift.REGISTER_FILE_SLOTS
        kinds = {o["kind"] for e in lift.AXIS_LIFT_TABLE for o in e["operands"]}
        used = [rules for kind, rules in lift.REGISTER_CLASSES.items() if kind in kinds]
        has_zero = any(rules[0] is not None for rules in used)
        has_alias = any(rules[1] is not None for rules in used)
        rng = random.Random(0xA715)
        checked = failures = 0
        # ⚠️ Counted, not assumed. Two deliberate breaks in the register model
        # -- writing the hardwired zero, and sending an aliased register to the
        # numbered file -- passed while nothing here ever wrote either one.
        wrote_zero = wrote_alias = 0
        reached: set[str] = set()
        declined: dict[str, str] = {}

        for test in fixtures:
            base = int(test["encoded"], 16)
            entry = lift.decode(base, test.get("isa"))
            if entry is None:
                continue
            shapes = list(variants(lift, entry, base, test.get("isa")))
            for case in range(args.cases):
                word = shapes[case % len(shapes)]
                image = bytes(rng.getrandbits(8) for _ in range(256))
                # ⚠️ A MIX. Small aligned values keep a computed address inside
                # the image; values with the high bit set are what tell a
                # signed comparison from an unsigned one. With only the first,
                # `min`/`max` lowered as `minu`/`maxu` passed this gate. An
                # address off the end reads zero on both sides, so the wide
                # ones cost nothing.
                # ⚠️ Two of the cases are fixed, not drawn. A rotate by a
                # whole turn has to come back unchanged, and whether any run
                # ever held a register at 0 or at the width was left to the
                # dice -- a rotate that turned zero into a full rotation
                # passed about half the time.
                if case == 0:
                    values = [0] * slots
                elif case == 1:
                    values = [64] * slots
                else:
                    values = [rng.randrange(0, 64) * 8 if rng.random() < 0.5
                              else rng.choice(BOUNDARY) if rng.random() < 0.3
                              else rng.getrandbits(64) for _ in range(slots)]

                concrete_regs = {i: v for i, v in enumerate(values)}
                memory = Mem(image)
                # ⚠️ Every declared state slot, not an empty dict. A
                # description that models an exclusive monitor reads
                # `exclusive_address` like any other symbol, and an empty state
                # makes the reference raise rather than run.
                # ⚠️ Varied, not zero. Architectural state is an input like
                # a register: with `frm` always 0 the dynamic rounding forms
                # take one rounding mode and never trap, and a guarded state
                # write whose guard is constant tests nothing.
                concrete_state = {name: rng.randrange(0, 1 << min(bits, 4))
                                  for name, bits in lift.STATE_SLOTS}
                # ⚠️ Snapshot BEFORE the step. `step` mutates the state dict,
                # and the symbolic term reads the state as it was: binding
                # `state_frm` to the value the instruction had just written
                # made `CSRRWI_FRM` -- which reads the old rounding mode into
                # its destination -- disagree by exactly the value it wrote.
                before = dict(concrete_state)
                out = executor.step(word, concrete_regs, mem=memory, pc=0,
                                    isa=test.get("isa"), state=concrete_state)
                if out is None:
                    break
                # ⚠️ A trap is COMPARED, then stopped on -- not skipped. In
                # these descriptions a guarded state write and a trap are two
                # halves of one condition: the dynamic rounding forms accrue
                # flags when `frm` is valid and trap when it is not. Breaking
                # on the trap meant the guard was only ever observed where it
                # held, so a symbolic executor that ignored the guard entirely
                # and always wrote agreed with every run this gate made. The
                # guard-false branch is the one worth checking, and a trap is
                # the only way to reach it.
                trapped = bool(out.get("trap"))

                # The model the executor concretises an address against.
                # The model an address is concretised against: every register
                # the machine has, aliased ones included, or a term that names
                # `sp` cannot be answered.
                model = {f"r{i}": v for i, v in enumerate(values)}
                for kind, rules in lift.REGISTER_CLASSES.items():
                    if rules[1] is not None:
                        model.setdefault(f"reg_{rules[1][1]}", 0)
                state = sym.State(slots, image, model=model)
                answer = sym.step(state, word, test.get("isa"))
                if not answer["ok"]:
                    declined.setdefault(test["mnemonic"], answer["why"])
                    break
                reached.add(test["mnemonic"])

                for operand in entry["operands"]:
                    if operand["role"] not in ("out", "inout"):
                        continue
                    if not lift.is_register_operand(operand["kind"]):
                        continue
                    rules = lift.REGISTER_CLASSES.get(operand["kind"])
                    index = lift._extract(word, operand["fields"]) if operand["fields"] else None
                    if rules is None or index is None:
                        continue
                    wrote_zero += int(rules[0] == index)
                    wrote_alias += int(rules[1] is not None and rules[1][0] == index)

                bindings = state.bindings(values, before)
                checked += 1
                for slot in range(slots):
                    want = concrete_regs.get(slot, 0)
                    term = state.regs.get(slot)
                    try:
                        got = sym.concrete(term, bindings)
                    except sym.Declined as why:
                        declined.setdefault(test["mnemonic"], str(why))
                        break
                    if got != want:
                        failures += 1
                        if failures <= 4:
                            print(f"FAIL {test['mnemonic']} word {word:#010x} "
                                  f"slot {slot}: symbolic {got:#x} != "
                                  f"concrete {want:#x}")
                        break
                # ⚠️ Aliased registers too. AArch64's `sp` is not in the
                # numbered file -- both machines keep it beside the registers
                # under its name -- so a loop over slots never compares it, and
                # a write that went to the wrong place would not show.
                for kind, rules in lift.REGISTER_CLASSES.items():
                    alias = rules[1]
                    if alias is None:
                        continue
                    name = alias[1]
                    term = state.regs.get(name) or sym.var(f"reg_{name}", 64)
                    got = sym.concrete(term, bindings)
                    want = concrete_regs.get(name, 0) & ((1 << 64) - 1)
                    if got != want:
                        failures += 1
                        if failures <= 4:
                            print(f"FAIL {test['mnemonic']} {name}: "
                                  f"symbolic {got:#x} != concrete {want:#x}")
                        break
                # ⚠️ Architectural state, not only registers. A rounding mode
                # written under a guard, an exception flag, a reservation: a
                # `setstate` that ignored its guard was invisible here while
                # this compared registers alone.
                for name, bits in lift.STATE_SLOTS:
                    term = state.state.get(name) or sym.var(f"state_{name}", bits)
                    try:
                        got = sym.concrete(term, bindings)
                    except sym.Declined as why:
                        declined.setdefault(test["mnemonic"], str(why))
                        break
                    want = concrete_state.get(name, 0) & ((1 << bits) - 1)
                    if got != want:
                        failures += 1
                        if failures <= 4:
                            print(f"FAIL {test['mnemonic']} state {name}: "
                                  f"symbolic {got:#x} != concrete {want:#x}")
                        break
                if trapped:
                    break

    print(f"{checked} run(s) compared register for register, {failures} disagree; "
          f"{len(reached)} instruction(s) executed symbolically")
    print(f"  {wrote_zero} write(s) to a hardwired zero register, "
          f"{wrote_alias} to an aliased one")
    # Said out loud: an instruction this cannot interpret is one the sweep
    # intended to check and did not.
    if declined:
        reasons = {}
        for name, why in declined.items():
            reasons.setdefault(why, []).append(name)
        print(f"  {len(declined)} instruction(s) declined, by reason:")
        for why, names in sorted(reasons.items(), key=lambda row: -len(row[1])):
            sample = ", ".join(sorted(names)[:3])
            more = f" (+{len(names) - 3} more)" if len(names) > 3 else ""
            print(f"    {len(names):4} {why}: {sample}{more}")
    if not checked:
        print("symbolic == concrete: SKIP (nothing ran)")
        return DECLINED
    if has_zero and not wrote_zero:
        print("symbolic == concrete: FAIL (a class here has a hardwired zero "
              "and nothing wrote it)")
        return FAILED
    if has_alias and not wrote_alias:
        print("symbolic == concrete: FAIL (a class here aliases a state slot "
              "and nothing wrote it)")
        return FAILED
    print("symbolic == concrete:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
