#!/usr/bin/env python3
"""Execute scalable instructions and check them against a whole-register model.

Stage S3 of docs/scalable_execution.md. A scalable instruction instantiates to
`VL/elem` scalar operations over elements of the registers it names, and the
executor runs them by reading and writing element-sized views of a register held
as several 64-bit limbs. This checks that against a reference that has no views
and no limbs: a vector register is one integer, element *e* of width *w* is
`(value >> e*w) & mask`, and the instruction's answer is those elements' answers
put back in their places.

What is under test is the placement and the plumbing -- which bits each lane
reads, which it writes, and which register it lands in when the lanes outrun one
register. The per-element *semantics* are not re-derived here: they are the
scalar operators five backends already prove equal to the golden model, so the
reference calls the same evaluator on values it extracted itself.

Usage: tools/scalable_exec_check.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import collections
import importlib.util
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llvm_effects_check import ByteMemory          # noqa: E402
import exec_wide_check as wide                      # noqa: E402
from scalable_addressing import ADDRESSING, SEGMENTS  # noqa: E402
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
SLOT_BITS = 64
# Room for a whole vector at any base this driver picks, with the base itself
# far enough in that nothing wraps.
MEMORY_BYTES = 1 << 12
BASE_ADDRESS = 0x100


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file),
                    "-o", str(output)], check=True, cwd=AXIS_ROOT)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def vector_bits(axis_file: Path) -> int:
    match = re.search(r"\(vector-bits\s+(\d+)\)", axis_file.read_text())
    if match is None:
        raise SystemExit(f"{axis_file.name}: no (vector-bits ...)")
    return int(match.group(1))


def check_state_effects(lanes, fixture, lift, executor, golden, vl, cases):
    """Run an effectful instruction that touches no memory, and check its state.

    RVV's saturating forms are the shape: each lane writes an element and ORs an
    overflow bit into the sticky `vxsat`. Two things make them different from
    everything else this file checks.

    The state is *cumulative across lanes*: lane 3's `setstate` reads what lane
    2 left, so the reference has to thread it in lane order rather than compute
    each lane independently. A reference that evaluated the lanes in isolation
    would agree with an executor that did the same, and both would be wrong.

    The per-element *semantics* are not re-derived: the effect's value is
    evaluated by the golden model's own evaluator, on an environment this
    reference builds by extracting elements from whole registers. What is under
    test is the extraction, the insertion, and the ordering.
    """
    origin = lanes[0]["scalable_origin"]
    values = {operand["name"]: operand["value"] for operand in fixture["operands"]}
    placed = [operand for entry in lanes for operand in entry["operands"]
              if operand.get("view_width")]
    if not placed:
        return "no placed operand"
    stride = placed[0]["stride"]

    def key_of(operand):
        selector = values[operand.get("derived_from") or operand["name"]]
        return (operand["slot_base"],
                selector + operand.get("register_bias", 0))

    executions = failures = 0
    saturated = 0
    for _ in range(cases):
        registers = {}
        for operand in placed:
            registers.setdefault(key_of(operand), random.getrandbits(vl))
        regs = {}
        for (file_base, number), value in registers.items():
            for limb in range(stride):
                regs[file_base + number * stride + limb] = (
                    value >> (SLOT_BITS * limb)) & ((1 << SLOT_BITS) - 1)
        # ⚠️ A scalar register operand's VALUE, not its number. This path bound
        # the decoded index where the register's contents belong, as the pure
        # path once did (see `scalars` in main), and nothing noticed until an
        # effectful instruction read a scalar: SVE's WHILELT sets NZCV, so it
        # comes here, and the executor read an unseeded X register as zero
        # while this reference compared the two register NUMBERS. A register
        # the class reads as zero (XZR) is zero here too.
        scalar_values = {}
        for entry in lanes:
            for operand in entry["operands"]:
                if (operand.get("view_width") or operand["role"] == "enc"
                        or not lift.is_register_operand(operand["kind"])):
                    continue
                index = values[operand["name"]]
                slot = lift.register_slot(operand["kind"], index)
                zero = lift.REGISTER_CLASSES[operand["kind"]][0]
                if slot not in regs:
                    regs[slot] = random.getrandbits(SLOT_BITS)
                scalar_values[operand["name"]] = 0 if zero == index else regs[slot]
        state = {name: random.getrandbits(width) & ((1 << width) - 1)
                 for name, width in lift.STATE_SLOTS}

        expected = dict(registers)
        expected_state = dict(state)
        for entry in lanes:
            env = dict(expected_state)
            for operand in entry["operands"]:
                if operand["role"] == "enc":
                    continue
                if operand.get("view_width"):
                    width, offset = operand["view_width"], operand["view_offset"]
                    env[operand["name"]] = (
                        expected[key_of(operand)] >> offset) & ((1 << width) - 1)
                else:
                    env[operand["name"]] = scalar_values.get(operand["name"],
                                                             values[operand["name"]])
            for effect in entry.get("effects") or []:
                value = golden._eval_axis_expr(effect["value"], env,
                                               effect["eval_width"])
                if effect["kind"] == "setstate":
                    expected_state[effect["state"]] = value & (
                        (1 << effect["width"]) - 1)
                    env[effect["state"]] = expected_state[effect["state"]]
                    continue
                operand = next(op for op in entry["operands"]
                               if op["name"] == effect["dest"])
                width, offset = operand["view_width"], operand["view_offset"]
                cover = ((1 << width) - 1) << offset
                key = key_of(operand)
                expected[key] = (expected[key] & ~cover) | (
                    (value & ((1 << width) - 1)) << offset)
                env[effect["dest"]] = value & ((1 << width) - 1)

        seeded = dict(state)
        executor.step(int(fixture["encoded"], 16), regs, isa=fixture.get("isa"),
                      state=state)
        executions += 1
        # Whether this case observed the sticky flag change. A run in which none
        # did has checked the ordinary path and the flag not at all -- and the
        # flag is the whole reason these instructions are different.
        if expected_state != seeded:
            saturated += 1
        if any(expected_state[name] != state.get(name, 0)
               for name, _width in lift.STATE_SLOTS):
            failures += 1
            print(f"FAIL {origin} state: {state} != {expected_state}")
            continue
        for (file_base, number), value in sorted(expected.items()):
            for limb in range(stride):
                got = regs.get(file_base + number * stride + limb, 0)
                want = (value >> (SLOT_BITS * limb)) & ((1 << SLOT_BITS) - 1)
                if got != want:
                    failures += 1
                    print(f"FAIL {origin} file {file_base} reg {number} limb "
                          f"{limb}: {got:#018x} != {want:#018x}")
                    break
    return executions, failures, "state", saturated


def check_memory(lanes, fixture, lift, executor, vl, cases):
    """Run a vector memory access and check where the bytes went.

    The statement is the element map, and it is the one `scalable_addressing.py`
    makes:

        unit      element e is at base + e * bytes
        strided   element e is at base + e * step, step being a register
        indexed   element e is at base + index[e], index being a vector
        segment   field f of element e is at base + (e * nf + f) * bytes

    That tool proves the *address* each lane computes; this proves the bytes
    actually move between that address and that element, which is a different
    claim and can fail on its own -- a load that computed every address
    correctly and wrote them all into element 0 passes there and fails here.

    Returns (executions, failures, direction), or a string saying why not.
    """
    origin = lanes[0]["scalable_origin"]
    # An effectful instruction that touches no memory is not a memory
    # instruction: RVV's saturating forms write a register and a sticky flag.
    # Saying "addressing not stated" of those would be a true sentence about
    # the wrong subject.
    if not any(effect["kind"] in ("set", "store") and
               ("load" in str(effect.get("value", "")) or effect["kind"] == "store")
               for entry in lanes for effect in entry.get("effects") or []):
        return "effectful, but not memory"
    # A PREDICATED access -- a load that zeroes or a store that skips an
    # inactive element, as a guard on each effect -- is not one this unit,
    # strided, indexed or segment map describes: which bytes move depends on
    # the predicate. SVE's are held to Arm's model by sve_asl_check.py, byte
    # for byte, on all three executors.
    if any(effect.get("guard") for entry in lanes for effect in entry.get("effects") or []):
        return "predicated memory, which an element map does not describe (SVE's is held to Arm by sve_asl_check.py)"
    values = {operand["name"]: operand["value"] for operand in fixture["operands"]}
    placed = [operand for entry in lanes for operand in entry["operands"]
              if operand.get("view_width")]
    if not placed:
        return "no placed operand"
    slot_stride = placed[0]["stride"]
    file_base = placed[0]["slot_base"]

    segment = SEGMENTS.get(origin)
    if segment is not None:
        fields, element_bytes, base_name = segment
        kind, step_name = "segment", None
    else:
        mode = ADDRESSING.get(origin)
        if mode is None:
            return "addressing not stated"
        kind, element_bytes, base_name, step_name = mode
        fields = 1
        if kind not in ("unit", "strided", "indexed"):
            return f"{kind} addressing"
    if element_bytes is None:
        element_bytes = placed[0]["view_width"] // 8

    effect_kinds = {effect["kind"] for entry in lanes
                    for effect in entry.get("effects") or []}
    if effect_kinds == {"set"}:
        direction = "load"
    elif effect_kinds == {"store"}:
        direction = "store"
    else:
        return "mixed or unrecognised effects"

    def base_of(operand):
        return operand.get("derived_from") or operand["name"]

    def number_of(operand):
        return values[base_of(operand)] + operand.get("register_bias", 0)

    index_operands = {operand["name"]: operand for operand in placed
                      if kind == "indexed" and base_of(operand) == step_name}
    data_operands = [operand for operand in placed
                     if operand["name"] not in index_operands]
    lane_count = max(operand["lane"] for operand in data_operands) + 1
    scalar_kind = next((operand["kind"] for entry in lanes
                        for operand in entry["operands"]
                        if operand["name"] == base_name), None)
    if scalar_kind is None:
        return f"no base operand {base_name}"

    # Every address this produces has to land inside the buffer, and the widest
    # is the last lane's. A step or an index drawn without that in mind reaches
    # a random address -- which, once this runs compiled, is a fault rather than
    # a failed comparison.
    span = MEMORY_BYTES - BASE_ADDRESS - element_bytes
    step_limit = max(element_bytes, span // max(lane_count, 1))

    executions = failures = 0
    for _ in range(cases):
        image = bytearray(random.getrandbits(8) for _ in range(MEMORY_BYTES))
        memory = ByteMemory(bytes(image))
        regs = {}
        registers = {}
        index_elements = {}

        for operand in placed:
            number = number_of(operand)
            registers.setdefault(number, random.getrandbits(vl))
        # The index vector is not random: it is a vector of offsets, and an
        # offset that leaves the buffer is not a test of gathering.
        for operand in index_operands.values():
            number = number_of(operand)
            offset = (random.randrange(span // element_bytes + 1)
                      * element_bytes)
            index_elements[operand["lane"]] = offset
            cover = ((1 << operand["view_width"]) - 1) << operand["view_offset"]
            registers[number] = (registers[number] & ~cover) | (
                (offset & ((1 << operand["view_width"]) - 1))
                << operand["view_offset"])
        for number, value in registers.items():
            for limb in range(slot_stride):
                regs[file_base + number * slot_stride + limb] = (
                    value >> (SLOT_BITS * limb)) & ((1 << SLOT_BITS) - 1)

        regs[lift.register_slot(scalar_kind, values[base_name])] = BASE_ADDRESS
        step_value = element_bytes
        if kind == "strided":
            step_value = element_bytes * max(
                1, random.randrange(1, max(2, step_limit // element_bytes)))
            regs[lift.register_slot(scalar_kind, values[step_name])] = step_value

        def address(lane, field):
            if kind == "segment":
                return BASE_ADDRESS + (lane * fields + field) * element_bytes
            if kind == "strided":
                return BASE_ADDRESS + lane * step_value
            if kind == "indexed":
                return BASE_ADDRESS + index_elements[lane]
            return BASE_ADDRESS + lane * element_bytes

        expected_regs = dict(registers)
        expected_mem = bytearray(image)
        for entry in lanes:
            effects = entry.get("effects") or []
            for field, effect in enumerate(effects):
                if direction == "load":
                    operand = next(op for op in entry["operands"]
                                   if op["name"] == effect["dest"])
                else:
                    operand = next(op for op in entry["operands"]
                                   if op.get("view_width")
                                   and op["name"] not in index_operands
                                   and op["role"] in ("in", "inout"))
                number = number_of(operand)
                width, offset = operand["view_width"], operand["view_offset"]
                at = address(operand["lane"], field)
                if direction == "load":
                    element = int.from_bytes(
                        image[at:at + width // 8], "little")
                    cover = ((1 << width) - 1) << offset
                    expected_regs[number] = (expected_regs[number] & ~cover) | (
                        element << offset)
                else:
                    element = (registers[number] >> offset) & ((1 << width) - 1)
                    expected_mem[at:at + width // 8] = element.to_bytes(
                        width // 8, "little")

        state = {name: (MEMORY_BYTES if name.endswith("_hi") else 0)
                 for name, _width in lift.STATE_SLOTS}
        executor.step(int(fixture["encoded"], 16), regs, mem=memory,
                      isa=fixture.get("isa"), state=state)
        executions += 1
        for number, value in sorted(expected_regs.items()):
            for limb in range(slot_stride):
                got = regs.get(file_base + number * slot_stride + limb, 0)
                want = (value >> (SLOT_BITS * limb)) & ((1 << SLOT_BITS) - 1)
                if got != want:
                    failures += 1
                    print(f"FAIL {origin} v{number} limb {limb}: "
                          f"{got:#018x} != {want:#018x}")
                    break
        if bytes(memory.data) != bytes(expected_mem):
            differing = next(i for i in range(MEMORY_BYTES)
                             if memory.data[i] != expected_mem[i])
            failures += 1
            print(f"FAIL {origin} memory at {differing:#x}: "
                  f"{memory.data[differing]:#04x} != {expected_mem[differing]:#04x}")
    return executions, failures, f"{kind} {direction}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=4)
    parser.add_argument("--lang", default="python", choices=("python", "c", "rust"),
                        help="which generated executor to drive")
    args = parser.parse_args()

    vl = vector_bits(args.axis_file)
    workdir = Path(tempfile.mkdtemp(prefix="axis_scalable_"))
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    fixtures_path = workdir / "fixtures.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)
    if args.lang != "python":
        emit(args.axis_file, "emit-exec-c", workdir / "axis_exec.h")
        emit(args.axis_file, "emit-lift-c", workdir / "axis_lift.h")
        emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
    sys.path.insert(0, str(workdir))
    lift = load(workdir / "axis_lift.py", "axis_lift")
    golden = load(workdir / "golden_model.py", "golden_model")
    executor = load(workdir / "axis_exec.py", "axis_exec")
    fixtures = json.loads(fixtures_path.read_text())["tests"]

    slots = lift.REGISTER_FILE_SLOTS
    pending = []

    def run(word, regs, isa, mem=None, state=None, expect=None):
        """Execute one word, in-process or compiled.

        The Python arm mutates `regs` as it goes, which is what the reference
        compares against. A compiled arm cannot: it needs the expected values up
        front, so the case carries them and the comparison happens in the
        generated C. Same reference either way -- only who applies it moves.
        """
        if args.lang == "python":
            executor.step(word, regs, mem=mem, isa=isa, state=state)
            return None
        pending.append({
            "mnemonic": expect["mnemonic"], "word": word, "isa": isa or "",
            "pc": 0, "regs": [regs.get(i, 0) for i in range(slots)],
            "seed": expect.get("seed", []), "state": expect.get("state", []),
            "reg_checks": expect["reg_checks"], "mem_checks": expect.get("mem_checks", []),
            "state_write": None, "next_pc": None, "trap": None,
            "result": None, "slots": slots,
        })
        return None
    random.seed(0x5CA1)
    checked = failures = 0
    declined: dict[str, int] = collections.Counter()
    grouped = widths = 0
    seen_widths = set()
    memory_kinds: set[str] = set()
    # What the corpus *offers*, decided from the same tables `check_memory`
    # reads, so a form that declined still counts as offered rather than
    # vanishing from the comparison.
    offered_memory: set[str] = set()
    state_hits = state_cases = 0

    for fixture in fixtures:
        word = int(fixture["encoded"], 16)
        lanes = lift.decode_lanes(word, fixture.get("isa"))
        if len(lanes) <= 1 or not lanes[0].get("scalable_origin"):
            continue
        origin = lanes[0]["scalable_origin"]
        if any(entry.get("effects") for entry in lanes):
            if args.lang != "python":
                # The memory reference is a byte image; the compiled harness
                # takes cell-addressed memory. The C data path for vector
                # memory is proven by the simulator gate instead.
                declined[f"{origin}: memory, not on the {args.lang} arm"] += 1
                continue
            if not any(effect["kind"] in ("store",) or
                       (effect["kind"] == "set" and "load" in str(effect.get("value", "")))
                       for entry in lanes for effect in entry.get("effects") or []):
                # Effectful and touching no memory: RVV's saturating forms
                # write an element and a sticky flag. A different reference,
                # because the thing to get right is the flag's accumulation
                # across lanes rather than an address.
                outcome = check_state_effects(lanes, fixture, lift, executor,
                                              golden, vl, args.cases)
                if isinstance(outcome, str):
                    declined[f"{origin}: {outcome}"] += 1
                    continue
                ran, bad, _kind, hits = outcome
                checked += ran
                failures += bad
                state_cases += ran
                state_hits += hits
                continue
            # A predicated form is not offered to the unit/segment map at all
            # (see check_memory), so it cannot count as an addressing mode left
            # unexecuted here.
            predicated = any(effect.get("guard") for entry in lanes
                             for effect in entry.get("effects") or [])
            if predicated:
                pass
            elif origin in SEGMENTS:
                offered_memory.add("segment")
            elif origin in ADDRESSING:
                offered_memory.add(ADDRESSING[origin][0])
            outcome = check_memory(lanes, fixture, lift, executor, vl, args.cases)
            if isinstance(outcome, str):
                declined[f"{origin}: {outcome}"] += 1
                continue
            ran, bad, kind = outcome
            checked += ran
            failures += bad
            memory_kinds.add(kind)
            continue
        if any(entry["semantics"] is None for entry in lanes):
            declined[f"{origin}: no pure semantics"] += 1
            continue
        placements = [operand for entry in lanes for operand in entry["operands"]
                      if operand.get("view_width")]
        if not placements:
            declined[f"{origin}: no placed operand"] += 1
            continue
        stride = placements[0]["stride"]
        # A register is identified by its file *and* its number. Predicates and
        # vector registers are different files at the same stride, so `p3` and
        # `z3` are different registers -- keying by number alone puts a
        # comparison's predicate destination on top of its own input.

        for _ in range(args.cases):
            # One whole-register value per register the instruction names.
            values = {operand["name"]: operand["value"]
                      for operand in fixture["operands"]}
            registers: dict[int, int] = {}

            def whole(entry, operand):
                """Which register this operand's element lives in: (file, number)."""
                # A fixed register (SVE's FFR) has no selector: it IS the number.
                # A derived operand is its source's register plus its offset:
                # TBL2's second table register is Zn + 1, not Zn.
                selector = (operand["fixed"] if operand.get("fixed") is not None
                            else values[operand.get("derived_from") or operand["name"]]
                            + operand.get("derived_add", 0))
                key = (operand["slot_base"],
                       selector + operand.get("register_bias", 0))
                if key not in registers:
                    registers[key] = random.getrandbits(vl)
                return key

            for entry in lanes:
                for operand in entry["operands"]:
                    if operand.get("view_width"):
                        whole(entry, operand)

            # Scalar register inputs. `WHILELT` compares two of them to decide
            # how many lanes are active, and it is the first scalable form here
            # with one -- until it existed, passing the decoded *index* where
            # the register's value belongs was indistinguishable from correct.
            scalars = {}
            for entry in lanes:
                for operand in entry["operands"]:
                    if operand.get("view_width") or operand["role"] == "enc":
                        continue
                    if not lift.is_register_operand(operand["kind"]):
                        continue
                    slot = lift.register_slot(operand["kind"],
                                              values[operand["name"]])
                    # Wider than the operand, on purpose. A register holds a
                    # value; an operand reads as many bits of it as its width
                    # says. Seeding within the width makes those two
                    # indistinguishable -- and the difference was real: the C
                    # executor compared an i8 `whilelt` bound as a 64-bit
                    # number and said every lane active where the golden model
                    # said none.
                    scalars.setdefault(slot, random.getrandbits(16))

            regs = dict(scalars)
            for (file_base, number), value in registers.items():
                for limb in range(stride):
                    regs[file_base + number * stride + limb] = (
                        value >> (SLOT_BITS * limb)) & ((1 << SLOT_BITS) - 1)

            expected = dict(registers)
            for entry in lanes:
                inputs = []
                for operand in entry["operands"]:
                    if operand["role"] in ("out", "enc"):
                        continue
                    if not operand.get("view_width"):
                        # A register operand contributes its *value*; an
                        # immediate contributes itself.
                        if lift.is_register_operand(operand["kind"]):
                            inputs.append(scalars[lift.register_slot(
                                operand["kind"], values[operand["name"]])])
                        else:
                            inputs.append(values[operand["name"]])
                        continue
                    number = whole(entry, operand)
                    width, offset = operand["view_width"], operand["view_offset"]
                    # Every lane reads the registers as they were BEFORE the
                    # word -- Arm's rule, and the executors' since V1. Read
                    # from `expected`, a lane saw an earlier lane's write
                    # whenever a source is also a destination at another
                    # lane: ADCLB's carry lane, TBL2's second table register.
                    inputs.append((registers[number] >> offset) & ((1 << width) - 1))
                answer = golden.evaluate(entry["mnemonic"], *inputs)
                for operand in entry["operands"]:
                    if operand["role"] not in ("out", "inout"):
                        continue
                    if not operand.get("view_width"):
                        continue
                    number = whole(entry, operand)
                    width, offset = operand["view_width"], operand["view_offset"]
                    seen_widths.add(width)
                    cover = ((1 << width) - 1) << offset
                    expected[number] = (expected[number] & ~cover) | (
                        (answer & ((1 << width) - 1)) << offset)

            checks = [(file_base + number * stride + limb,
                       (value >> (SLOT_BITS * limb)) & ((1 << SLOT_BITS) - 1))
                      for (file_base, number), value in sorted(expected.items())
                      for limb in range(stride)]
            run(word, regs, fixture.get("isa"),
                expect={"mnemonic": origin, "reg_checks": checks})
            checked += 1
            if args.lang != "python":
                continue
            for (file_base, number), value in sorted(expected.items()):
                for limb in range(stride):
                    got = regs.get(file_base + number * stride + limb, 0)
                    want = (value >> (SLOT_BITS * limb)) & ((1 << SLOT_BITS) - 1)
                    if got != want:
                        failures += 1
                        if failures <= 6:
                            print(f"FAIL {origin} file {file_base} reg {number} "
                                  f"limb {limb}: "
                                  f"{got:#018x} != {want:#018x}")
                        break
        if len({operand.get("register_bias", 0) for operand in placements}) > 1:
            grouped += 1

    widths = len(seen_widths)
    print(f"{checked} scalable executions against a whole-register model, "
          f"{failures} failures")
    print(f"  VL {vl}, {widths} element width(s), {grouped} instruction(s) "
          f"write past the first register")
    print(f"  memory: {', '.join(sorted(memory_kinds)) or 'none executed'}")
    print(f"  addressing covered: "
          f"{', '.join(sorted({kind.split()[0] for kind in memory_kinds})) or 'none'}")
    if declined:
        shown = ", ".join(f"{name} x{count}" for name, count in
                          sorted(declined.items())[:5])
        more = f" (+{len(declined) - 5} more)" if len(declined) > 5 else ""
        print(f"  declined: {shown}{more}")
    ok = failures == 0
    # A register that fits in one limb would exercise none of the storage this
    # depends on, and one element width would barely constrain the placement.
    if vl <= SLOT_BITS:
        print("VL fits one slot: the limb path is untested")
        ok = False
    if widths < 2:
        print("one element width: the placement is barely constrained")
        ok = False
    if not checked:
        print("no scalable instruction executed")
        ok = False
    # `docs/gate_coverage.md` §3 says this gate "fails if a load and a store did
    # not both run". It reported the addressing modes and required nothing, so
    # the claim was about an intent rather than the code. A gather and a unit
    # load are both a `set` and take different paths, which is why addressing
    # mode is this gate's class -- and a corpus offering a form that never ran
    # is a green result about a data path nobody drove.
    addressing = {kind.split()[0] for kind in memory_kinds}
    if offered_memory and not offered_memory <= addressing:
        print(f"  addressing never executed: "
              f"{', '.join(sorted(offered_memory - addressing))}")
        ok = False
    # A corpus whose memory forms all declined would report a green data path
    # it never ran.
    if args.lang != "python":
        result = wide.build_and_run(pending, workdir, args.axis_file,
                                    "c" if args.lang == "c" else "rust")
        compiled = sum(1 for line in result.stdout.splitlines()
                       if line.startswith("FAIL"))
        # ⚠️ A DECLINE is not a pass. This counted FAIL lines alone, so an
        # executor that ran none of these instructions -- the wide Rust one,
        # until it gained lane views and a lane loop -- reported zero
        # failures over cases it never executed. The driver's own summary
        # says how many it declined, and any is a failure of this gate.
        summary = next((line for line in reversed(result.stdout.splitlines())
                        if " declined," in line), "")
        declined_count = int(summary.split(" declined,")[0].rsplit(" ", 1)[-1]) if summary else len(pending)
        if declined_count:
            print(f"  the {args.lang} executor declined {declined_count} of {len(pending)} case(s)")
            compiled += declined_count
        for line in result.stdout.splitlines()[:6]:
            if line.startswith(("FAIL", "DECLINE")):
                print(" ", line)
        failures += compiled
        print(f"{checked} scalable executions against a whole-register model, "
              f"{failures} failures")
        print(f"  driven through the {args.lang} executor, {len(pending)} case(s)")
        ok = failures == 0 and result.returncode == 0 and checked > 0
        if not checked:
            print("no scalable instruction executed")
        print(f"scalable execution == whole-register model ({args.lang}): "
              + ("PASS" if ok else "FAIL"))
        return 0 if ok else 1

    if state_cases:
        print(f"  sticky state: {state_cases} execution(s), {state_hits} of "
              f"which changed the flag")
    directions = {kind.split()[-1] for kind in memory_kinds}
    if state_cases and not state_hits:
        print("no case changed the sticky flag: it is untested")
        ok = False
    # Whenever the corpus offers a memory form this map describes. SVE's are
    # all predicated now and held to Arm elsewhere, so it offers none.
    if offered_memory and directions != {"load", "store"}:
        print(f"blocks cover {sorted(directions) or 'nothing'}: both a vector "
              f"load and a vector store have to run")
        ok = False
    print("scalable execution == whole-register model: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
