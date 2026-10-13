#!/usr/bin/env python3
"""A prologue and its epilogue are inverse (stage F2).

F1 checks that a declared frame is arithmetic that works and that the machine
can reach it. It never runs anything. This builds the prologue and epilogue the
layout describes, executes them in the golden model, and asks what a program
can be asked that arithmetic cannot:

  * every address the prologue writes lies **inside the frame** it just opened,
    and there is one for each saved register. An offset the instruction could
    not encode lands in the caller's frame, and two registers sharing a slot
    leave one of them unsaved -- both visible in the memory the prologue
    touched;
  * after the epilogue -- with every saved register clobbered in between, the
    way a callee body clobbers them -- each holds what it held on entry, and
    the stack pointer is back where it started.

The clobber is what makes the second a test. Without it, "the registers still
hold their entry values" is true of a program that does nothing at all.

**What this deliberately does not check, and why.** The first version compared
the values read back at each published slot, and passed every layout injection
thrown at it -- a slot moved by one word, the saved area at the wrong end.
Of course it did: the program was *built* from the published table and then
read back through it, so a store and a load at one wrong address round-trip
exactly as well as at the right one. That comparison was the table against
itself. Whether the published table is the layout the frame describes is
arithmetic, it belongs to `frame_check.py`, and it stays there. What is left
here is everything the table cannot settle: whether the instructions reach
where they are aimed, and whether the two halves are inverse *as programs* --
an adjustment closed with the wrong sign, a save based on the wrong register,
an epilogue whose adjustment runs before its loads. Those three are injected
and caught.

`pce/hardware/grv/grv_linked_execution.py` checks a prologue by comparing it
against hand-encoded words: `_encode_addi(2, 2, -16)`, `_encode_sw(1, 2, 12)`,
and so on. Comparing bytes proves the compiler emitted the expected
instructions; running them proves the expected instructions establish a frame.
The second question is the one a description can answer, because the
description is where the layout is stated.

**Nothing here searches the instruction set.** The ABI names three
instructions and F1 checks they are a store, a load and an
immediate-add. What this reads is their own published behavior -- SW's
`(add i32 rs1 (sext i32 12 imm))` says which operand is the base and which the
offset -- so the roles come from the description's statement about the
instruction it named, not from a guess about its shape.

Coverage, per `docs/gate_coverage.md`: a corpus with no declared frame fails as
vacuous, and so does a frame that saves no registers -- a prologue with nothing
to restore restores it correctly for free.

Usage: tools/frame_exec_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
TRIALS = 32


class Mem:
    """The width-keyed memory model axis_exec reads and writes."""

    def __init__(self):
        self.store: dict[tuple[int, int], int] = {}

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def base_and_offset(expr: str) -> tuple[str, str] | None:
    """`(add i32 rs1 (sext i32 12 imm))` -> ("rs1", "imm").

    The instruction's own account of its address. A form this does not
    recognise is reported rather than guessed at: an addressing mode with a
    scale or a second register is not the one a frame slot uses.
    """
    match = re.fullmatch(
        r"\(add i\d+ (\w+) \((?:sext|zext) i\d+ \d+ (\w+)\)\)", expr.strip())
    return (match.group(1), match.group(2)) if match else None


def encode(entry: dict, values: dict[str, int]) -> int:
    """One instruction word, from the encode table `roundtrip_check.py` proves."""
    word = int(entry["base_value"], 16)
    for operand in entry["operands"]:
        encoding = operand.get("encoding")
        if encoding is None:
            continue
        value = values.get(operand["name"], 0)
        for slice_ in encoding["slices"]:
            chunk = (value >> slice_["op_lsb"]) & ((1 << slice_["width"]) - 1)
            word |= chunk << slice_["lsb"]
    return word & 0xFFFFFFFF


def frame_program(frame: dict, table: dict, lift, frame_bytes: int):
    """The prologue and the epilogue, as words, plus the slot each save uses.

    Returns None with a reason when the named instructions do not state their
    address in a form a frame slot can use.
    """
    save, restore, adjust = (table.get(frame[key].upper())
                             for key in ("save", "restore", "adjust"))
    if not all((save, restore, adjust)):
        return None, "an instruction the abi names is not in the encode table"

    store = next((effect for effect in save["_effects"]
                  if effect.get("kind") == "store"), None)
    loads = next((effect for effect in restore["_effects"]
                  if effect.get("kind") == "set"), None)
    if store is None or loads is None:
        return None, "the abi's save does not store, or its restore does not load"
    store_addr = base_and_offset(store["addr"])
    load_match = re.fullmatch(r"\(load i\d+ \w+ (.*)\)", loads["value"].strip())
    load_addr = base_and_offset(load_match.group(1)) if load_match else None
    add_expr = adjust["_value"]
    add_parts = base_and_offset(add_expr) if add_expr else None
    if not (store_addr and load_addr and add_parts):
        return None, "an address the abi's frame instructions state is not base+offset"

    store_value = store["value"].strip()
    load_dest = loads["dest"]
    adjust_dest = adjust["_dest"]

    sp_class, sp_index = frame["_stack_pointer"]
    prologue = [encode(adjust, {add_parts[0]: sp_index, add_parts[1]: -frame_bytes,
                                adjust_dest: sp_index})]
    epilogue = []
    slots = []
    for slot in frame["slots"]:
        (klass, index), offset = slot["register"], slot["offset"]
        if klass != sp_class:
            return None, f"a saved register in class {klass} is not in the sp's file"
        offset = offset - (frame["max_frame_bytes"] - frame_bytes) if \
            frame["saved_area"] == "top" else offset
        prologue.append(encode(save, {store_addr[0]: sp_index,
                                      store_addr[1]: offset,
                                      store_value: index}))
        epilogue.append(encode(restore, {load_addr[0]: sp_index,
                                         load_addr[1]: offset,
                                         load_dest: index}))
        slots.append((index, offset))
    epilogue.append(encode(adjust, {add_parts[0]: sp_index, add_parts[1]: frame_bytes,
                                    adjust_dest: sp_index}))

    # F5. The second half, and the one "variable frames" is about. Where the
    # stack pointer may move inside a body, a local cannot be addressed from
    # it, so the frame pointer holds the incoming stack pointer and everything
    # is reached from there. That epilogue is a different program -- negative
    # offsets from the frame pointer, and a stack pointer restored by copying
    # it rather than by adding back a frame size it no longer knows -- and it
    # is the only one that still works after an allocation moves sp.
    fp = frame.get("_frame_pointer")
    fp_prologue = fp_epilogue = None
    if fp is not None and fp[0] == sp_class:
        fp_index = fp[1]
        fp_prologue = list(prologue)
        if frame["frame_pointer_at"] == "incoming-sp":
            fp_prologue.append(encode(adjust, {add_parts[0]: sp_index,
                                               add_parts[1]: frame_bytes,
                                               adjust_dest: fp_index}))
            bias = frame_bytes
        else:
            fp_prologue.append(encode(adjust, {add_parts[0]: sp_index,
                                               add_parts[1]: 0,
                                               adjust_dest: fp_index}))
            bias = 0
        # The stack pointer comes back from the frame pointer *first*, and the
        # rest of the epilogue is then the ordinary one. That order is not a
        # detail: the frame pointer is itself one of the saved registers here,
        # so reloading it before the stack pointer has been recovered destroys
        # the only thing that still knows where the frame is. Real epilogues
        # are written this way for this reason.
        fp_epilogue = [encode(adjust, {add_parts[0]: fp_index,
                                       add_parts[1]: -bias,
                                       adjust_dest: sp_index})]
        fp_epilogue.extend(epilogue)
    return (prologue, epilogue, slots, fp_prologue, fp_epilogue), None


def check(abi: dict, table: dict, axis_exec, lift, isa: str) -> list[str]:
    frame = abi["frame"]
    name = abi["name"]
    frame_bytes = min(frame["max_frame_bytes"],
                      max(frame["saved_bytes"], 16))
    # Round up to the alignment the abi states, the way a real frame is.
    align = abi["stack_alignment"]
    frame_bytes = ((frame_bytes + align - 1) // align) * align
    program, reason = frame_program(frame, table, lift, frame_bytes)
    if program is None:
        return [f"{name}: {reason}"]
    prologue, epilogue, slots, fp_prologue, fp_epilogue = program
    sp_class, sp_index = frame["_stack_pointer"]
    sp_slot = lift.register_slot(sp_class, sp_index)
    width = abi["pointer_bits"]
    mask = (1 << width) - 1

    failures: list[str] = []
    rng = random.Random(0x5F3759DF ^ frame_bytes)
    for trial in range(TRIALS):
        mem = Mem()
        entry_sp = (rng.randrange(1 << width) & ~(align - 1)) & mask
        # Keep the frame inside the address space: a stack pointer near zero
        # would wrap, and wrapping is the machine's business, not the frame's.
        entry_sp = max(entry_sp, frame_bytes + align) & ~(align - 1)
        regs = {sp_slot: entry_sp}
        entry_values = {}
        for index, _ in slots:
            value = rng.randrange(1 << width)
            regs[lift.register_slot(sp_class, index)] = value
            entry_values[index] = value

        mem.store.clear()
        regs = axis_exec.run(prologue, regs, mem, isa=isa)
        written = dict(mem.store)
        sp_after = regs.get(sp_slot, 0)
        expected_sp = (entry_sp - frame_bytes) & mask
        if sp_after != expected_sp:
            failures.append(
                f"{name}: trial {trial} prologue left sp at {sp_after:#x}, and a "
                f"{frame_bytes}-byte frame below {entry_sp:#x} starts at "
                f"{expected_sp:#x}")
            break
        # What the prologue *did*, read off the memory it touched rather than
        # off the offsets it was built from. Building the program from the
        # published slots and then reading those same slots back would compare
        # the table with itself, which is the vacuity this check would
        # otherwise have: a store and a load at one wrong address round-trip
        # exactly as well as at the right one. (Whether the published table is
        # the layout is F1's arithmetic, and it stays there.)
        if len(written) != len(slots):
            failures.append(
                f"{name}: trial {trial} prologue wrote {len(written)} address(es) for "
                f"{len(slots)} saved register(s); two registers sharing a slot leaves "
                f"one of them unsaved")
            break
        for (addr, _), value in written.items():
            if not sp_after <= addr < sp_after + frame_bytes:
                failures.append(
                    f"{name}: trial {trial} prologue wrote {addr:#x}, outside the frame "
                    f"[{sp_after:#x}, {(sp_after + frame_bytes):#x}); a slot the "
                    f"instruction could not encode lands in the caller's frame")
                break
            if value not in entry_values.values():
                failures.append(
                    f"{name}: trial {trial} prologue wrote {value:#x} at {addr:#x}, "
                    f"which is no saved register's entry value")
                break
        if failures:
            break

        # What a callee body does, and what makes the epilogue's job real.
        for index, _ in slots:
            regs[lift.register_slot(sp_class, index)] = rng.randrange(1 << width)

        regs = axis_exec.run(epilogue, regs, mem, isa=isa)
        if regs.get(sp_slot, 0) != entry_sp:
            failures.append(
                f"{name}: trial {trial} epilogue left sp at {regs.get(sp_slot, 0):#x}, "
                f"not the {entry_sp:#x} it was called with")
        for index, _ in slots:
            got = regs.get(lift.register_slot(sp_class, index), 0)
            if got != entry_values[index]:
                failures.append(
                    f"{name}: trial {trial} register {index} came back {got:#x} after "
                    f"the epilogue, and it was {entry_values[index]:#x} on entry")
        if failures:
            break

        # F5, executed: the same frame, with the stack pointer moved after the
        # prologue the way a dynamic allocation moves it. The sp-relative
        # epilogue above cannot survive that and is not asked to; this one has
        # to, because permitting the allocation is what the abi declared.
        if fp_epilogue is None:
            continue
        fp_index = frame["_frame_pointer"][1]
        mem = Mem()
        regs = {sp_slot: entry_sp}
        for index, _ in slots:
            regs[lift.register_slot(sp_class, index)] = entry_values[index]
        regs = axis_exec.run(fp_prologue, regs, mem, isa=isa)
        moved = (regs[sp_slot] - align * rng.randrange(1, 8)) & mask
        regs[sp_slot] = moved
        # A body clobbers the callee-saved registers it was given. It does not
        # clobber the frame pointer: that register is live for the whole body
        # by construction, which is what makes it the thing everything else is
        # addressed from. Clobbering it here destroyed the frame and reported
        # the epilogue for it.
        for index, _ in slots:
            if index != fp_index:
                regs[lift.register_slot(sp_class, index)] = rng.randrange(1 << width)
        regs = axis_exec.run(fp_epilogue, regs, mem, isa=isa)
        if regs.get(sp_slot, 0) != entry_sp:
            failures.append(
                f"{name}: trial {trial} with sp moved to {moved:#x} inside the body, "
                f"the frame-pointer epilogue left it at {regs.get(sp_slot, 0):#x} and "
                f"not the {entry_sp:#x} it was called with")
        for index, _ in slots:
            got = regs.get(lift.register_slot(sp_class, index), 0)
            if got != entry_values[index]:
                failures.append(
                    f"{name}: trial {trial} register {index} came back {got:#x} from a "
                    f"frame-pointer epilogue, and it was {entry_values[index]:#x} on "
                    f"entry")
        if failures:
            break
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv32i.axisl")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axis_frameexec_") as workdir:
        work = Path(workdir)
        outputs = {}
        for command, name in (("emit-json", "manifest.json"),
                              ("emit-encode-json", "encode.json"),
                              ("emit-lift-json", "lift.json"),
                              ("emit-semantics-json", "semantics.json"),
                              ("emit-golden-python", "golden_model.py"),
                              ("emit-exec-python", "axis_exec.py"),
                              ("emit-lift-python", "axis_lift.py")):
            path = work / name
            subprocess.run([*axis_prefix(), command, str(args.axis_file), "-o", str(path)],
                           cwd=AXIS_ROOT, check=True, capture_output=True)
            outputs[name] = path
        payload = json.loads(outputs["manifest.json"].read_text())
        encode_table = json.loads(outputs["encode.json"].read_text())
        lift_table = json.loads(outputs["lift.json"].read_text())
        # The executor imports the golden model by name, so the emitted
        # directory has to be importable before either is loaded.
        sys.path.insert(0, str(work))
        load_module(outputs["golden_model.py"], "golden_model")
        lift = load_module(outputs["axis_lift.py"], "axis_lift")
        axis_exec = load_module(outputs["axis_exec.py"], "axis_exec")

        table = {entry["mnemonic"].upper(): entry
                 for entry in (encode_table["instructions"]
                               if isinstance(encode_table, dict) else encode_table)}
        for entry in (lift_table["instructions"] if isinstance(lift_table, dict)
                      else lift_table):
            target = table.get(entry["mnemonic"].upper())
            if target is None:
                continue
            target["_effects"] = entry.get("effects") or []
            value = next((effect for effect in target["_effects"]
                          if effect.get("kind") == "set"), None)
            target["_value"] = value["value"] if value else None
            target["_dest"] = value["dest"] if value else None
        # An instruction that states a pure value has no effect list at all --
        # `effects.rs` treats a behavior as authoritative only where
        # `formal_semantics` is empty, and ADDI is the other case. Its value
        # comes from the semantics manifest, and its destination is the one
        # output operand it declares.
        semantics = json.loads((work / "semantics.json").read_text())
        for entry in semantics.get("instructions", []):
            target = table.get(entry["mnemonic"].upper())
            if target is None or target.get("_value"):
                continue
            target["_value"] = entry.get("formal_semantics") or None
            outputs_named = [operand["name"] for operand in entry.get("operands", [])
                             if operand.get("output")]
            target["_dest"] = outputs_named[0] if len(outputs_named) == 1 else None

        failures: list[str] = []
        frames = 0
        for abi in payload.get("abis", []):
            frame = abi.get("frame")
            if frame is None or not frame["slots"]:
                continue
            if abi.get("stack_pointer") is None:
                failures.append(f"{abi['name']}: a frame with no stack pointer")
                continue
            frame["_stack_pointer"] = abi["stack_pointer"]
            frame["_frame_pointer"] = (
                abi["frame_pointer"]
                if frame.get("dynamic_allocation") == "allowed" else None)
            frames += 1
            found = check(abi, table, axis_exec, lift, abi["isa"])
            failures.extend(found)
            if not found:
                print(f"     {abi['name']}: prologue and epilogue inverse over "
                      f"{TRIALS} random entry states, {len(frame['slots'])} saved "
                      f"register(s)")

    for message in failures:
        print(f"FAIL {message}")
    if not frames:
        print("no abi in this corpus declares a frame that saves anything: a prologue "
              "with nothing to restore restores it correctly for free")
        return DECLINED
    print("frame execution: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
