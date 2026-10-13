#!/usr/bin/env python3
"""A packet is not its syllables run in a row, and this is what says so.

Stage B2 gives a packet snapshot semantics: every syllable reads the state the
packet started with, and the writes land together
(`docs/vliw_spatial_design.md` §6). The failure mode that matters is an
implementation that quietly runs syllables in sequence -- it agrees with the
packet on every program whose syllables are independent, which is most of them,
so a gate built only from independent packets passes on it.

The oracle is the definition itself, not a second copy of the executor's packet
code: **run each syllable alone against the pre-packet state, and merge**. That
is what "every syllable reads one state" means, and it is computed by the
ordinary single-instruction path (`step_syllable`), so agreeing with it is a
real claim rather than a function agreeing with itself.

Every case is then checked three ways:

* `packet == isolated` -- the semantics.
* independent syllables: `packet == serial`, in every order. A correct
  implementation passes this half, and so does a sequential one.
* dependent syllables: `packet != serial`, and it must differ, because a case
  where the two agree tests nothing and is reported as vacuous rather than
  passed.

Two collisions must be refused rather than resolved -- two syllables writing
one register, two storing one address. Both must come back as conflicts with
nothing committed, while serial execution of the same syllables produces a
value, which is what makes the collision real rather than an error path reached
for some other reason.

One known asymmetry, stated rather than papered over: the oracle merges by
value, so it sees a collision only when two syllables write *different* values,
while the executor reports one whenever two syllables use the same write port.
The conflict cases below are built to collide under both readings.

Usage: tools/packet_vs_serial.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import itertools
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# Registers this gate reserves. Sources are read by everything and written by
# nothing; scratch destinations are per slot so a filler never collides with
# the case under test.
SRC_A, SRC_B, RAW_REG, CLASH_REG, BASE_REG = 1, 2, 5, 6, 30
SCRATCH = 20
BASE_ADDR = 0x400


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(output)],
                   check=True, cwd=AXIS_ROOT)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Mem:
    """Insertion-ordered, width-keyed memory matching the executors' ABI."""

    def __init__(self, initial=None):
        self.store = dict(initial or {})

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def kind_of(entry) -> str | None:
    """What this instruction does to shared state, from its effects alone."""
    effects = entry.get("effects")
    if effects is None:
        return "alu" if entry.get("writes") and entry.get("reads") else None
    kinds = {effect["kind"] for effect in effects}
    if "setpc" in kinds:
        return "branch"
    if "store" in kinds:
        return "store"
    if any(effect.get("load_address_width") is not None for effect in effects):
        return "load"
    if kinds == {"set"}:
        return "alu"
    return None


def register_operands(lift, entry) -> tuple[list[str], list[str]]:
    """(written, read) register-operand names, in declaration order."""
    def registers(names, roles):
        return [op["name"] for op in entry["operands"]
                if op["role"] in roles and op["name"] in names
                and lift.is_register_operand(op["kind"])]
    return registers(entry["writes"], ("out", "inout")), \
        registers(entry["reads"], ("in", "inout"))


def immediates(lift, entry) -> list[str]:
    return [op["name"] for op in entry["operands"]
            if op["role"] in ("in", "inout") and not lift.is_register_operand(op["kind"])]


def word_for(lift, entry, values: dict[str, int]) -> int:
    """Encode a syllable with the operand values a case needs."""
    word = entry["match"]
    for name, value in values.items():
        word = lift.place_operand(word, entry, name, value)
        if lift._operand_value(word, entry, name) != value:
            raise AssertionError(f"place_operand({name}={value}) did not round-trip")
    return word


def reg_slot(lift, entry, name, index) -> int:
    operand = next(op for op in entry["operands"] if op["name"] == name)
    return lift.register_slot(operand["kind"], index)


class Shape:
    """One declared packet, and what each of its slots can be given to hold."""

    def __init__(self, lift, manifest_packet, table):
        self.lift = lift
        self.packet = manifest_packet
        self.name = manifest_packet["name"]
        self.isa = manifest_packet["isa"] or None
        self.slots = manifest_packet["slots"]
        by_mnemonic = {entry["mnemonic"]: entry for entry in table}
        self.by_slot = []
        for slot in self.slots:
            # An instruction that reads a register its operands do not name is
            # left out: every case this driver builds reasons about which
            # syllables share a register by assigning operands, and a read the
            # operand assignment cannot move would make a case that says it
            # proves disjointness while two syllables share x3.
            holdable = [by_mnemonic[one["mnemonic"]]
                        for one in manifest_packet["instructions"]
                        if slot["index"] in one["slots"] and one["mnemonic"] in by_mnemonic
                        and not by_mnemonic[one["mnemonic"]].get("reads_registers")]
            self.by_slot.append(holdable)

    def pick(self, slot: int, kind: str):
        for entry in self.by_slot[slot]:
            if kind_of(entry) == kind:
                return entry
        return None

    def slots_with(self, kind: str) -> list[int]:
        return [index for index in range(len(self.slots)) if self.pick(index, kind)]

    def filler(self, slot: int):
        """Something legal for a slot the case does not measure.

        A branch-only slot gets an *untaken* branch and a store-only slot a
        store to an address nothing else touches, so a filler cannot move what
        is being measured.
        """
        for kind in ("alu", "load", "branch", "store"):
            entry = self.pick(slot, kind)
            if entry is None:
                continue
            written, read = register_operands(self.lift, entry)
            values = {name: SCRATCH + slot for name in written}
            for offset, name in enumerate(read):
                values[name] = SRC_A if offset % 2 == 0 else SRC_B
            if kind == "branch" and len(read) >= 2:
                values[read[0]], values[read[1]] = SRC_A, SRC_B
            if kind in ("load", "store") and read:
                values[read[0]] = BASE_REG
                if kind == "store" and len(read) >= 2:
                    values[read[1]] = SRC_A
            for name in immediates(self.lift, entry):
                values[name] = 0x40 * (slot + 1) if kind in ("load", "store") else 0
            return entry, values
        raise AssertionError(f"slot {slot} of packet {self.name} can hold nothing")

    def build(self, assignments: dict[int, tuple[dict, dict[str, int]]]) -> list[int]:
        words = []
        for index in range(len(self.slots)):
            entry, values = assignments.get(index) or self.filler(index)
            words.append(word_for(self.lift, entry, values))
        return words


def initial_registers(lift, entry) -> dict[int, int]:
    """Pre-packet register file: sources, a base pointer, and a stale RAW value."""
    name = next(op["name"] for op in entry["operands"]
                if lift.is_register_operand(op["kind"]))
    return {
        reg_slot(lift, entry, name, index): value
        for index, value in ((SRC_A, 7), (SRC_B, 11), (RAW_REG, 3),
                             (CLASH_REG, 0), (BASE_REG, BASE_ADDR))
    }


def run_packet(exec_module, words, regs, mem, pc, shape):
    state, memory = dict(regs), Mem(mem.store)
    outcome = exec_module.step_packet(words, state, memory, pc, shape.name, shape.isa)
    return outcome, state, memory


def run_serial(exec_module, lift, words, regs, mem, pc, shape, order=None):
    """The counterfactual: the same syllables, one after another."""
    decoded = lift.decode_packet(words, shape.name, shape.isa)
    if decoded is None:
        return None, None, None
    state, memory = dict(regs), Mem(mem.store)
    order = list(order if order is not None else range(len(decoded)))
    next_pc = pc + 4 * len(decoded)
    for index in order:
        syllable = decoded[index]
        outcome = exec_module.step_syllable(syllable["word"], syllable["entry"],
                                            state, memory, pc, shape.isa)
        if outcome is None:
            return None, None, None
        if outcome.get("next_pc") is not None and outcome["next_pc"] != pc + 4:
            next_pc = outcome["next_pc"]
    return {"next_pc": next_pc}, state, memory


def run_isolated(exec_module, lift, words, regs, mem, pc, shape):
    """Each syllable alone against the pre-packet state, then merged.

    This is the definition of a packet, computed through the ordinary
    single-instruction path. Where two syllables changed one location to
    different values the merge is ambiguous, and that is reported as a
    collision the executor is then required to have reported too.
    """
    decoded = lift.decode_packet(words, shape.name, shape.isa)
    if decoded is None:
        return None
    merged, memory = dict(regs), Mem(mem.store)
    reg_owner, mem_owner, collisions = {}, {}, []
    next_pc, branches = pc + 4 * len(decoded), 0
    for syllable in decoded:
        state, private = dict(regs), Mem(mem.store)
        outcome = exec_module.step_syllable(syllable["word"], syllable["entry"],
                                            state, private, pc, shape.isa)
        if outcome is None:
            return None
        for location, value in state.items():
            if regs.get(location) == value:
                continue
            if location in reg_owner and reg_owner[location] != value:
                collisions.append(("register", location))
            reg_owner[location] = value
            merged[location] = value
        for location, value in private.store.items():
            if mem.store.get(location) == value:
                continue
            if location in mem_owner and mem_owner[location] != value:
                collisions.append(("memory", location))
            mem_owner[location] = value
            memory.store[location] = value
        if outcome.get("next_pc") is not None and outcome["next_pc"] != pc + 4:
            next_pc, branches = outcome["next_pc"], branches + 1
    if branches > 1:
        collisions.append(("control", "pc"))
    return {"registers": merged, "memory": memory.store,
            "next_pc": next_pc, "collisions": collisions}


def compare(label, packet_outcome, packet_regs, packet_mem, isolated, failures):
    """The semantics: a packet's result is its syllables merged, not sequenced."""
    if packet_outcome is None or isolated is None:
        failures.append(f"{label}: packet did not decode")
        return False
    if isolated["collisions"]:
        if not packet_outcome["conflicts"]:
            failures.append(f"{label}: syllables collide on "
                            f"{isolated['collisions']}, and the packet reported none")
            return False
        if packet_outcome["committed"]:
            failures.append(f"{label}: a conflicting packet committed")
            return False
        return True
    if packet_outcome["conflicts"]:
        failures.append(f"{label}: packet reported conflicts "
                        f"{packet_outcome['conflicts']} the syllables do not have")
        return False
    if packet_regs != isolated["registers"]:
        failures.append(f"{label}: registers {diff(packet_regs, isolated['registers'])}")
        return False
    if packet_mem.store != isolated["memory"]:
        failures.append(f"{label}: memory {diff(packet_mem.store, isolated['memory'])}")
        return False
    if packet_outcome["next_pc"] != isolated["next_pc"]:
        failures.append(f"{label}: next_pc {packet_outcome['next_pc']:#x} "
                        f"vs {isolated['next_pc']:#x}")
        return False
    return True


def diff(left, right) -> str:
    keys = sorted(set(left) | set(right), key=repr)
    return ", ".join(f"{key!r}: {left.get(key)!r} vs {right.get(key)!r}"
                     for key in keys if left.get(key) != right.get(key))[:200]


def case_independent(exec_module, lift, shape, failures) -> bool:
    """Disjoint syllables: packet and serial agree, in every order."""
    alu_slots = shape.slots_with("alu")
    if not alu_slots:
        return False
    assignments = {}
    for slot in alu_slots:
        entry = shape.pick(slot, "alu")
        written, read = register_operands(lift, entry)
        values = {name: SCRATCH + slot for name in written}
        for offset, name in enumerate(read):
            values[name] = SRC_A if offset % 2 == 0 else SRC_B
        for name in immediates(lift, entry):
            values[name] = 0
        assignments[slot] = (entry, values)
    words = shape.build(assignments)
    regs = initial_registers(lift, shape.pick(alu_slots[0], "alu"))
    mem = Mem()
    outcome, packet_regs, packet_mem = run_packet(exec_module, words, regs, mem, 0x1000, shape)
    isolated = run_isolated(exec_module, lift, words, regs, mem, 0x1000, shape)
    ok = compare("independent", outcome, packet_regs, packet_mem, isolated, failures)
    # Serial, in every order: independence means order cannot matter.
    orders = list(itertools.permutations(range(len(words))))
    for order in orders[:6]:
        serial, serial_regs, serial_mem = run_serial(
            exec_module, lift, words, regs, mem, 0x1000, shape, order)
        if serial_regs != packet_regs or serial_mem.store != packet_mem.store:
            failures.append(f"independent: order {order} differs from the packet: "
                            f"{diff(serial_regs, packet_regs)}")
            ok = False
    return ok


def case_raw(exec_module, lift, shape, failures) -> bool:
    """A slot-crossing read-after-write reads the old value, and serial does not."""
    alu_slots = shape.slots_with("alu")
    if len(alu_slots) < 2:
        return False
    producer, consumer = alu_slots[0], alu_slots[1]
    assignments = {}
    entry = shape.pick(producer, "alu")
    written, read = register_operands(lift, entry)
    values = {name: RAW_REG for name in written}
    for offset, name in enumerate(read):
        values[name] = SRC_A if offset % 2 == 0 else SRC_B
    for name in immediates(lift, entry):
        values[name] = 0
    assignments[producer] = (entry, values)

    entry = shape.pick(consumer, "alu")
    written, read = register_operands(lift, entry)
    values = {name: SCRATCH + consumer for name in written}
    for offset, name in enumerate(read):
        values[name] = RAW_REG if offset == 0 else SRC_A
    for name in immediates(lift, entry):
        values[name] = 0
    assignments[consumer] = (entry, values)

    words = shape.build(assignments)
    regs = initial_registers(lift, entry)
    mem = Mem()
    outcome, packet_regs, packet_mem = run_packet(exec_module, words, regs, mem, 0x1000, shape)
    isolated = run_isolated(exec_module, lift, words, regs, mem, 0x1000, shape)
    ok = compare("raw", outcome, packet_regs, packet_mem, isolated, failures)
    serial, serial_regs, _ = run_serial(exec_module, lift, words, regs, mem, 0x1000, shape)
    consumer_slot = reg_slot(lift, entry, register_operands(lift, entry)[0][0],
                             SCRATCH + consumer)
    if packet_regs.get(consumer_slot) == serial_regs.get(consumer_slot):
        failures.append(
            f"raw: the packet and serial agreed ({packet_regs.get(consumer_slot)}), "
            f"so this case proves nothing about snapshot reads")
        ok = False
    return ok


def case_write_conflict(exec_module, lift, shape, failures) -> bool:
    """Two slots writing one register is refused, never resolved."""
    alu_slots = shape.slots_with("alu")
    if len(alu_slots) < 2:
        return False
    assignments = {}
    for position, slot in enumerate(alu_slots[:2]):
        entry = shape.pick(slot, "alu")
        written, read = register_operands(lift, entry)
        values = {name: CLASH_REG for name in written}
        for offset, name in enumerate(read):
            # Different sources, so the two writes differ in value as well as
            # in port -- the collision is real under either reading.
            values[name] = (SRC_A if position == 0 else SRC_B) if offset == 0 else SRC_B
        for name in immediates(lift, entry):
            values[name] = 0
        assignments[slot] = (entry, values)
    words = shape.build(assignments)
    regs = initial_registers(lift, shape.pick(alu_slots[0], "alu"))
    mem = Mem()
    outcome, packet_regs, packet_mem = run_packet(exec_module, words, regs, mem, 0x1000, shape)
    isolated = run_isolated(exec_module, lift, words, regs, mem, 0x1000, shape)
    ok = compare("write conflict", outcome, packet_regs, packet_mem, isolated, failures)
    if not outcome["conflicts"] or outcome["committed"]:
        failures.append(f"write conflict: expected an unresolved conflict, got "
                        f"{outcome['conflicts']} committed={outcome['committed']}")
        ok = False
    if packet_regs != regs:
        failures.append("write conflict: a conflicting packet changed the register file")
        ok = False
    serial, serial_regs, _ = run_serial(exec_module, lift, words, regs, mem, 0x1000, shape)
    clash = reg_slot(lift, shape.pick(alu_slots[0], "alu"),
                     register_operands(lift, shape.pick(alu_slots[0], "alu"))[0][0], CLASH_REG)
    if serial_regs.get(clash) == regs.get(clash):
        failures.append("write conflict: serial execution wrote nothing, so the "
                        "conflict was not a collision between two writes")
        ok = False
    return ok


def memory_case(exec_module, lift, shape, failures, second: str) -> bool:
    """A store in one slot against a load or a second store in another."""
    store_slots, other_slots = shape.slots_with("store"), shape.slots_with(second)
    pair = [(a, b) for a in store_slots for b in other_slots if a < b]
    if not pair:
        return False
    store_slot, other_slot = pair[0]
    store_entry = shape.pick(store_slot, "store")
    written, read = register_operands(lift, store_entry)
    if len(read) < 2:
        return False
    values = {read[0]: BASE_REG, read[1]: SRC_A}
    for name in immediates(lift, store_entry):
        values[name] = 0
    assignments = {store_slot: (store_entry, values)}

    other_entry = shape.pick(other_slot, second)
    written, read = register_operands(lift, other_entry)
    values = {name: SCRATCH + other_slot for name in written}
    values[read[0]] = BASE_REG
    if second == "store":
        values[read[1]] = SRC_B
    for name in immediates(lift, other_entry):
        values[name] = 0
    assignments[other_slot] = (other_entry, values)

    words = shape.build(assignments)
    regs = initial_registers(lift, store_entry)
    mem = Mem({(BASE_ADDR, 32): 0x5eed})
    outcome, packet_regs, packet_mem = run_packet(exec_module, words, regs, mem, 0x1000, shape)
    isolated = run_isolated(exec_module, lift, words, regs, mem, 0x1000, shape)
    label = "load vs store" if second == "load" else "memory conflict"
    ok = compare(label, outcome, packet_regs, packet_mem, isolated, failures)
    serial, serial_regs, serial_mem = run_serial(
        exec_module, lift, words, regs, mem, 0x1000, shape)
    if second == "load":
        loaded = reg_slot(lift, other_entry,
                          register_operands(lift, other_entry)[0][0], SCRATCH + other_slot)
        if packet_regs.get(loaded) != 0x5eed:
            failures.append(f"load vs store: the load read {packet_regs.get(loaded)!r}, "
                            f"not the pre-packet 0x5eed")
            ok = False
        if serial_regs.get(loaded) == packet_regs.get(loaded):
            failures.append("load vs store: serial agreed with the packet, so the "
                            "case proves nothing about memory snapshots")
            ok = False
    else:
        if not outcome["conflicts"] or outcome["committed"]:
            failures.append(f"memory conflict: expected an unresolved conflict, got "
                            f"{outcome['conflicts']} committed={outcome['committed']}")
            ok = False
        if serial_mem.store.get((BASE_ADDR, 32)) == 0x5eed:
            failures.append("memory conflict: serial stored nothing, so the conflict "
                            "was not a collision between two stores")
            ok = False
    return ok


def case_control(exec_module, lift, shape, failures) -> bool:
    """A taken branch sets next_pc; an untaken packet steps by its byte length."""
    branch_slots = shape.slots_with("branch")
    if not branch_slots:
        return False
    slot = branch_slots[0]
    entry = shape.pick(slot, "branch")
    _, read = register_operands(lift, entry)
    if len(read) < 2:
        # This case drives a branch's condition through two register operands.
        # A corpus whose branch has fewer is a case this gate cannot build, and
        # the coverage requirement then reports it rather than passing quietly.
        return False
    taken = {read[0]: SRC_A, read[1]: SRC_A}
    for name in immediates(lift, entry):
        taken[name] = 0x20
    words = shape.build({slot: (entry, taken)})
    regs = initial_registers(lift, entry)
    mem = Mem()
    outcome, packet_regs, packet_mem = run_packet(exec_module, words, regs, mem, 0x1000, shape)
    isolated = run_isolated(exec_module, lift, words, regs, mem, 0x1000, shape)
    ok = compare("control", outcome, packet_regs, packet_mem, isolated, failures)
    if outcome["next_pc"] == 0x1000 + outcome["bytes"]:
        failures.append("control: the branch was not taken, so next_pc says nothing")
        ok = False

    untaken = dict(taken)
    untaken[read[1]] = SRC_B
    words = shape.build({slot: (entry, untaken)})
    outcome, _, _ = run_packet(exec_module, words, regs, mem, 0x1000, shape)
    # The whole packet retires at once, so the step is its byte length and not
    # one instruction.
    if outcome["next_pc"] != 0x1000 + 4 * outcome["syllables"]:
        failures.append(f"control: an untaken packet stepped to "
                        f"{outcome['next_pc']:#x}, not by its {outcome['bytes']} bytes")
        ok = False
    return ok


def check(axis_file: Path) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        emit(axis_file, "emit-packet-json", workdir / "packet_manifest.json")
        emit(axis_file, "emit-lift-python", workdir / "axis_lift.py")
        emit(axis_file, "emit-golden-python", workdir / "golden_model.py")
        emit(axis_file, "emit-exec-python", workdir / "axis_exec.py")
        sys.path.insert(0, str(workdir))
        manifest = json.loads((workdir / "packet_manifest.json").read_text())
        lift = load_module(workdir / "axis_lift.py", "axis_lift")
        load_module(workdir / "golden_model.py", "golden_model")
        exec_module = load_module(workdir / "axis_exec.py", "axis_exec")
        table = lift.AXIS_LIFT_TABLE

        if not manifest["packets"]:
            print(f"{axis_file.name}: declares no packet -> FAIL")
            return False

        failures: list[str] = []
        covered: set[str] = set()
        cases = [
            ("independent", case_independent),
            ("raw", case_raw),
            ("write conflict", case_write_conflict),
            ("load vs store", lambda e, l, s, f: memory_case(e, l, s, f, "load")),
            ("memory conflict", lambda e, l, s, f: memory_case(e, l, s, f, "store")),
            ("control", case_control),
        ]
        for packet in manifest["packets"]:
            shape = Shape(lift, packet, table)
            for name, case in cases:
                if case(exec_module, lift, shape, failures):
                    covered.add(name)
        sys.path.remove(str(workdir))

        # Per docs/gate_coverage.md: a class this run never built is a class it
        # says nothing about, and a green result that says nothing is the thing
        # these gates exist to prevent.
        missing = sorted({name for name, _ in cases} - covered)
        print(f"{axis_file.name}: classes covered {len(covered)}/{len(cases)}: "
              f"{', '.join(sorted(covered)) or 'none'}")
        if missing:
            failures.append(f"classes the corpus never exercised: {missing}")
        for failure in failures[:20]:
            print(f"  {failure}")
        status = "PASS" if not failures else "FAIL"
        print(f"{axis_file.name}: {len(covered)} classes, {len(failures)} failures -> {status}")
        return not failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sources", nargs="+", type=Path)
    args = parser.parse_args()
    ok = all(check(source) for source in args.sources)
    print("PACKET SEMANTICS PASSED" if ok else "PACKET SEMANTICS FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
