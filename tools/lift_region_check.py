#!/usr/bin/env python3
"""A lifted region runs what the executor runs.

`axis lift-llvm` turns a run of bytes into an LLVM module: basic blocks with
native arithmetic, real `br` edges between them, and a landing pad for every way
control can leave. That is a second front end onto the same semantics, so it
needs the same treatment every other backend gets -- run it, run the reference,
and require the register file, the memory and the address it left from to agree.

The reference is the Python executor, which `exec_vs_golden` already proves
equal to the golden model. What this adds on top of `jit_llvm.py` is the shape:
that driver compiles a *block the harness hands it* out of decoded entries,
while this one hands over bytes and lets the lifter decide where the blocks are.
The difference is exactly the thing being checked -- block discovery, the branch
folding that draws the edges, and the constant register slots that come from
knowing the encoding.
"""
from __future__ import annotations

import argparse
import ctypes
import re
import importlib
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import exec_fuzz as ef  # noqa: E402
from llvm_effects_check import ByteMemory, atomic_alignment  # noqa: E402
from axis_lift_ffi import Lifter  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
#: Tries at drawing an encoding that decodes back to the instruction it came
#: from, before the sweep gives up and says so.
DRAW_TRIES = 40

MEM_BYTES = 4096
REG_LIMIT = 4096


def emit(axis_file: Path, command: str, out: Path) -> None:
    result = subprocess.run([*axis_prefix(), command, str(axis_file)],
                            capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    out.write_text(result.stdout)


def block_starts(summary: str) -> set:
    """The addresses the lifter made blocks at, from its own account."""
    return {int(m, 16) for m in re.findall(r"^bb_([0-9a-f]+):", summary, re.M)}


def blocks_of(lifter, image: bytes, base: int, isa) -> str:
    """The lifter's account of where this region's blocks are."""
    try:
        return lifter.blocks(image, base, isa)
    except RuntimeError:
        return ""


def lift_bodies(lifter, image: bytes, base: int, isa) -> str:
    """A region's block functions, without the preamble."""
    try:
        return lifter.blocks_llvm(image, base, isa)
    except RuntimeError:
        return None


def lift(lifter, image: bytes, base: int, isa) -> str:
    """The lifter's module for these bytes, or None when it declines them."""
    try:
        return lifter.llvm(image, base, isa)
    except RuntimeError:
        return None


#: Regions built by hand rather than drawn, for shapes a random draw of six
#: instructions out of seven hundred will essentially never produce. Each is a
#: list of (mnemonic, operand values); a corpus missing any of them skips it.
PLANTED = [
    # A 128-bit value out of memory and back, then the LOW LIMB of the very
    # register the wide load wrote, read through the 64-bit view of the same
    # class. A wide register is two slots in the file, so the three steps only
    # agree if the wide load wrote both, the wide store read both, and the
    # narrow read took the right one of the two.
    ("wide round trip, then the low limb", [
        ("LDR_Q_UNSIGNED", {"rt": 1, "rn": 5, "imm": 0}),
        ("STR_Q_UNSIGNED", {"rt": 1, "rn": 6, "imm": 0}),
        ("STR_D_UNSIGNED", {"rt": 1, "rn": 7, "imm": 0}),
    ]),
    # The pair forms, which move two wide registers at once: four limbs out of
    # memory and four back, at offsets the description states rather than ones
    # the region computes.
    ("wide pair out and back", [
        ("LDP_Q_OFFSET", {"rt": 2, "rt2": 3, "rn": 5, "imm": 0}),
        ("STP_Q_OFFSET", {"rt": 2, "rt2": 3, "rn": 6, "imm": 0}),
    ]),
    # ⚠️ A store-conditional whose reservation HOLDS. `sc.w` lowers to a
    # masked store, and a masked store with a false mask is indistinguishable
    # from no lowering at all -- which is what the random sweep exercises, since
    # a random `exclusive_address` never equals a random `rs1`. Planting `lr.w`
    # first sets the reservation to the address `sc.w` then writes, so the
    # branch that actually stores is taken.
    ("a reservation taken, then a store-conditional", [
        ("LR_W", {"rd": 1, "rs1": 5}),
        ("SC_W", {"rd": 2, "rs1": 5, "rs2": 3}),
    ]),
    # And the same pair with the addresses disagreeing, so the store must NOT
    # happen. A masked store that ignored its mask would pass the case above and
    # fail this one.
    ("a reservation for another address", [
        ("LR_W", {"rd": 1, "rs1": 6}),
        ("SC_W", {"rd": 2, "rs1": 5, "rs2": 3}),
    ]),
    # A narrow write first, then a wide read of the register that write landed
    # in. Writing `d1` zeroes the rest of `v1`, so the wide store must see that
    # zero in the high limb -- not whatever the register held before.
    ("narrow write, wide read", [
        ("LDR_D_UNSIGNED", {"rt": 1, "rn": 5, "imm": 0}),
        ("STR_Q_UNSIGNED", {"rt": 1, "rn": 6, "imm": 0}),
    ]),
]


# Regions where the lifter and the executor are MEANT to disagree, each with
# the slot that differs and why. They are run like any other planted region and
# the disagreement is required: if one of these ever agrees, the exemption has
# gone stale and is describing a divergence that no longer exists, which is a
# failure exactly like an unexpected disagreement is.
#
# The whole list is about one decision. `sc.w` is modelled as a guarded store --
# it succeeds when the monitor is still valid -- and lifted as a compare-and-
# swap against the value `lr.w` captured. Those answer differently precisely
# where the architecture leaves room: RISC-V permits an implementation to keep
# a reservation across an unrelated store to the reserved address, so the model
# stores and the compare-and-swap, seeing changed memory, does not. Both are
# allowed; the simulator takes the permissive reading and the translator takes
# the one that is safe against another hart.
PLANTED_DIVERGENT = [
    ("a plain store between the reservation and the store-conditional", [
        ("LR_W", {"rd": 1, "rs1": 5}),
        ("SW", {"rs1": 5, "rs2": 4, "imm": 0}),
        ("SC_W", {"rd": 2, "rs1": 5, "rs2": 3}),
    ], 2, True,
     "the model still holds the reservation and stores; the compare-and-swap "
     "sees the word `sw` left behind and fails -- so the flag differs AND so "
     "does the word at the reserved address, which the model wrote and the "
     "lifted region left as `sw` had it"),
    # The same decision, on the other architecture that describes a monitor.
    # AArch64 is explicit that a store by the same PE to the reserved address
    # may leave the exclusive monitor set, so the model's reading is the
    # architecture's and the compare-and-swap is the stricter one.
    ("a plain store between the load-exclusive and the store-exclusive", [
        ("LDXR_W", {"rt": 1, "rn": 5}),
        ("STR_W_UNSIGNED", {"rt": 4, "rn": 5, "imm": 0}),
        ("STXR_W", {"rs": 2, "rt": 3, "rn": 5}),
    ], 2, True,
     "the model still holds the reservation and stores; the compare-and-swap "
     "sees the word `str` left behind and fails"),
]


def planted_regions(args, axis_lift, axis_exec, widths, lifter, rng, jit, slots,
                    state_slots, alias_slot, alias_name, file_slots):
    """The hand-built regions, each compared against the executor.

    The random draw reaches a wide instruction now and then, but never a wide
    value round-tripping, and never a narrow view of a register a wide load
    just wrote. Those are the shapes where a limb can go missing, so they are
    planted rather than hoped for.
    """
    by = {entry["mnemonic"]: entry for entry in axis_lift.AXIS_LIFT_TABLE}
    ran = failures = exempted = 0
    diverged: dict = {}
    both = ([(title, steps, None) for title, steps in PLANTED]
            + [(title, steps, (slot, memory, why))
               for title, steps, slot, memory, why in PLANTED_DIVERGENT])
    for title, steps, expect in both:
        if any(name not in by for name, _values in steps):
            continue                    # a corpus that does not describe these
        program = []
        for name, values in steps:
            entry = by[name]
            try:
                word = ef.encode(entry, values)
            except Exception as why:
                print(f"  {title}: {name} does not encode ({why})")
                failures += 1
                program = None
                break
            seen = axis_lift.decode(int(word), entry.get("isa"))
            if seen is None or seen["mnemonic"] != name:
                print(f"  {title}: {name} does not decode back to itself")
                failures += 1
                program = None
                break
            program.append((seen, values, word))
        if not program:
            continue
        isa = program[0][0].get("isa")
        image = region_bytes(program, widths)
        summary = blocks_of(lifter, image, 0, isa)
        if "declined at" in summary or "undecodable at" in summary:
            print(f"  {title}: the lifter declines it -- {summary.strip()}")
            failures += 1
            continue
        module = lift(lifter, image, 0, isa)
        if module is None:
            print(f"  {title}: it did not lift")
            failures += 1
            continue
        # ⚠️ A region containing an atomic is aligned even in the "unaligned"
        # run. The label is about limb offsets -- a plain load states `align 1`,
        # so an unaligned base must still put the second limb eight bytes after
        # the first -- and not about handing a compare-and-swap an address the
        # architecture forbids. This passed for a while on luck: Apple silicon
        # has FEAT_LSE2 and tolerates an unaligned atomic that stays inside a
        # 16-byte granule, so the fault waited for an address that crossed one.
        floor = max((atomic_alignment(seen) for seen, _v, _w in program), default=1)
        for label, mask in (("aligned", 15), ("unaligned", 0)):
            mask |= floor - 1
            seed_image = bytes(rng.getrandbits(8) for _ in range(MEM_BYTES))
            init_regs = [rng.randrange(REG_LIMIT) & ~mask for _ in range(file_slots)]
            init_state = [rng.randrange(1 << min(w, 32)) for _, w in state_slots]
            addressed, addr = [], 0
            for entry, _values, word in program:
                addressed.append((addr, int(word), entry.get("isa"),
                                  widths.get(entry["mnemonic"], 32) // 8, False))
                addr += widths.get(entry["mnemonic"], 32) // 8
            want = python_region(addressed, init_regs, seed_image, 0, axis_exec,
                                 axis_lift, slots, state_slots, init_state,
                                 alias_slot, alias_name)
            if want is None:
                print(f"  {title} ({label}): the executor could not run it")
                failures += 1
                continue
            jit.compile(module)
            got = jit.drive(None, 0, block_starts(summary), init_regs, seed_image,
                            init_state)
            ran += 1
            bad = [s for s in range(file_slots)
                   if got["regs"][s] != want["regs"][s]]
            # A region the two are meant to answer differently. The named slot
            # has to differ and nothing else may, so the exemption covers the
            # one divergence it describes rather than the whole region.
            if expect is not None:
                slot, memory, why = expect
                differed = got["mem"] != want["mem"]
                if slot not in bad:
                    print(f"  {title} ({label}): slot {slot} AGREES, but the "
                          f"exemption says it should not -- {why}")
                    failures += 1
                elif bad != [slot]:
                    others = [s for s in bad if s != slot]
                    print(f"  {title} ({label}): slot {others[0]} differs too, "
                          f"which the exemption does not cover")
                    failures += 1
                elif differed != memory:
                    said = "differ" if memory else "match"
                    print(f"  {title} ({label}): memory was supposed to {said} "
                          f"and did not")
                    failures += 1
                else:
                    exempted += 1
                    also = " and in memory" if memory else ""
                    diverged[title] = f"slot {slot}{also} -- {why}"
                continue
            if bad:
                print(f"  {title} ({label}): slot {bad[0]} lifted "
                      f"{got['regs'][bad[0]]:#x} != executor "
                      f"{want['regs'][bad[0]]:#x}")
                failures += 1
            elif got["mem"] != want["mem"]:
                first = next(i for i in range(len(want["mem"]))
                             if got["mem"][i] != want["mem"][i])
                print(f"  {title} ({label}): memory differs at byte {first}")
                failures += 1
    if ran == 0:
        print("planted region == executor: SKIP (this corpus describes none)")
        return DECLINED
    # Said out loud. A divergence that is expected is still a divergence, and a
    # run that reports only "0 failures" would be describing the sweep as
    # cleaner than it is.
    if diverged:
        print(f"{exempted} run(s) diverged as the exemptions describe:")
        # The ones that RAN. A corpus describes one architecture's monitor, and
        # naming the other's exemption here would be reporting a divergence
        # this run never saw.
        for title, told in diverged.items():
            print(f"  {title}: {told}")
    print(f"{ran} planted run(s), {failures} failure(s)")
    print("planted region == executor:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


def draw_region(entries, takes, length, rng, lift_mod, tries=40):
    """A region whose *decoded* instructions are all ones the lifter takes.

    Drawing an entry and encoding it is not enough. A random immediate can turn
    one encoding into another instruction, and a region is read back from bytes
    -- so what matters is what the word decodes to, not which entry produced it.
    Each word is decoded before it is kept, and one that lands on an instruction
    the lifter declines is redrawn rather than making the whole region unusable.
    """
    # One ISA for the whole region. This corpus describes a source encoding
    # space and a target one, and the same word decodes to a different
    # instruction in each -- so a region drawn from both is not a region, it is
    # two, and the lifter decoding it under one ISA reads instructions nobody
    # generated. A region of bytes belongs to one instruction set.
    isas = {entry.get("isa") for entry in entries}
    isa = rng.choice(sorted(isas, key=lambda name: name or ""))
    pool = [entry for entry in entries if entry.get("isa") == isa]
    if not pool:
        return None
    program = []
    for _ in range(length):
        for _attempt in range(tries):
            one = ef.gen_program(pool, 1, rng, lift_mod)[0]
            entry, _values, word = one
            seen = lift_mod.decode(int(word), entry.get("isa"))
            # The decode has to agree with what was generated, not merely be
            # liftable. A 32-bit encoding whose low half matches a compressed
            # instruction decodes as the compressed one -- correctly, that is
            # what those bytes are -- and then the region is laid out two bytes
            # wide for a word that needs four, and everything after it moves.
            if (seen is not None
                    and seen["mnemonic"] == entry["mnemonic"]
                    and takes(seen)
                    and atomic_address_is_drawn(
                        program + [(seen, _values, word)], lift_mod)):
                program.append((seen, _values, word))
                break
        else:
            return None
    return program


def atomic_address_is_drawn(program, lift_mod) -> bool:
    """No atomic in this region takes an address an earlier step computed.

    The register values this harness draws are all multiples of eight, so an
    atomic whose address is a register straight out of the file is naturally
    aligned. One whose address register an earlier instruction *wrote* is not:
    a byte loaded from the random image lands anywhere, and a 64-bit
    `atomicrmw` at an odd address is `ldclral` at an odd address, which faults.
    The process died with SIGBUS, which says nothing about which instruction
    was wrong.

    That fault is the machine being right. AArch64 requires an atomic to be
    aligned, so the emitted IR assumes it -- see the note beside `atomicrmw` in
    `src/emit/llvm.rs`. AXIS's value models have no way to express a fault, so
    they compute an answer where the machine would trap, and the two only
    disagree where the architecture says nothing. Comparing there measures
    neither, so the region is redrawn instead.
    """
    written = set()
    for entry, values, _word in program:
        for effect in entry.get("effects") or []:
            if not (effect.get("atomic")
                    or (effect.get("kind") == "set" and effect.get("value_ast", {})
                        .get("op", "").startswith("atomic"))):
                continue
            address = effect.get("addr_ast") or _atomic_load_address(effect)
            if address is None:
                continue
            symbol = address.get("symbol") if isinstance(address, dict) else None
            # Not a bare register: an address this harness cannot reason about,
            # so it is not one it will vouch for.
            if symbol is None or symbol not in values:
                return False
            if values[symbol] in written:
                return False
        # What this instruction leaves behind, for the steps after it.
        for operand in entry["operands"]:
            if operand.get("output") and lift_mod.is_register_operand(operand["kind"]):
                written.add(values.get(operand["name"]))
        for effect in entry.get("effects") or []:
            if effect.get("kind") == "set" and effect.get("dest") in values:
                written.add(values[effect["dest"]])
    return True


def _atomic_load_address(effect):
    """The address an `(atomic_load ...)` value reads, which is its last argument."""
    ast = effect.get("value_ast") or {}
    if ast.get("op") == "atomic_load" and ast.get("args"):
        return ast["args"][-1]
    return None


def sample_encoding(entry, lift_mod):
    """One legal encoding of this instruction, for asking whether it lifts."""
    values = {}
    for op in entry["operands"]:
        if lift_mod.is_register_operand(op["kind"]):
            values[op["name"]] = 1
        elif op["fields"]:
            values[op["name"]] = 1
        else:
            values[op["name"]] = 0
    try:
        return values, ef.encode(entry, values)
    except Exception:
        return values, None


def instruction_widths(axis_file: Path) -> dict:
    """How wide each instruction is, by mnemonic.

    From the decode table, which is where a width lives: the lift table
    describes what an instruction *computes* and carries no width at all, so
    defaulting to four bytes there laid every compressed instruction out in
    twice its space, and everything after it moved. The bug was in this harness
    and it read as the lifter disagreeing with the executor.
    """
    import json
    result = subprocess.run([*axis_prefix(), "emit-decode-json", str(axis_file)],
                            capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    return {row["mnemonic"]: row["bits"]
            for row in json.loads(result.stdout)["instructions"]}


def region_bytes(program, widths) -> bytes:
    """The program's words laid out as a byte stream, each its own width.

    A region is bytes, not a list of words: that is the whole difference from
    the block drivers, and laying a 16-bit instruction out in four bytes would
    hide exactly the misalignment the lifter has to get right.
    """
    image = bytearray()
    for entry, _values, word in program:
        width = widths.get(entry["mnemonic"], 32) // 8
        image += int(word).to_bytes(width, "little")
    return bytes(image)


def python_region(words_with_isa, init_regs, image, base, axis_exec, axis_lift,
                  slots, state_slots, init_state, alias_slot=None,
                  alias_name=None):
    """Run the same bytes through the executor, following the pc it reports.

    Stops when the pc leaves the region, which is what the lifted module does
    when it takes a `leave_` pad. Returns the register file, the memory and the
    address it stopped at, or None when an access escaped the buffer.
    """
    memory = ByteMemory(image)
    # One slot past the file is where the lifted region puts an aliased index --
    # AArch64's `sp`, which the executor keeps under a name rather than at an
    # index. Both sides have to start it from the same value and report it in
    # the same place, or every register file differs at that one slot.
    regs = {index: value for index, value in enumerate(init_regs)
            if index != alias_slot}
    if alias_slot is not None and alias_slot < len(init_regs):
        regs[alias_name] = init_regs[alias_slot]
    state = {name: value for (name, _), value in zip(state_slots, init_state)}
    by_addr = {addr: (word, isa, width, branches)
               for addr, word, isa, width, branches in words_with_isa}
    end = base + sum(1 for _ in ())  # placeholder, replaced below
    limit = len(by_addr) * 8 + 16
    pc = base
    steps = 0
    ilen = getattr(axis_exec, "ILEN", 4)
    while pc in by_addr and steps < limit:
        word, isa, width, branches = by_addr[pc]
        out = axis_exec.step(word, regs, mem=memory, pc=pc, state=state, isa=isa)
        if memory.escaped:
            return None
        steps += 1
        if out is None:
            return None
        if out.get("trap"):
            return None
        # The executor advances the pc by one fixed `ILEN`, because a word is
        # what it is handed. A region is bytes, and a compressed instruction is
        # two of them -- so a fall-through moves by the instruction's own width
        # and only a real redirect is taken from `next_pc`. Reading `next_pc`
        # for both walked four bytes past a 16-bit instruction and executed
        # whatever was there.
        nxt = out["next_pc"] & 0xFFFFFFFFFFFFFFFF
        fell = nxt == (pc + ilen) & 0xFFFFFFFFFFFFFFFF
        if branches and fell and width != ilen:
            # A compressed branch whose target happens to be `pc + ILEN` is
            # indistinguishable here from one that was not taken: the executor
            # reports the fall-through as `pc + ILEN` and the region's real
            # fall-through is `pc + 2`. Rather than guess -- and a guess would
            # be wrong about which of two instructions runs next -- the region
            # is declined and counted.
            return None
        pc = (pc + width) if fell else nxt
    if steps >= limit:
        return None
    del end
    final = [regs.get(index, 0) & 0xFFFFFFFFFFFFFFFF for index in range(len(init_regs))]
    if alias_slot is not None and alias_slot < len(final):
        final[alias_slot] = regs.get(alias_name, 0) & 0xFFFFFFFFFFFFFFFF
    return {
        "regs": final,
        "mem": bytes(memory.data),
        "pc": pc,
        # ⚠️ Architectural state, which this harness held and never compared.
        # An instruction whose only effect beyond its registers is a state write
        # -- `LDXP` setting the exclusive monitor is exactly that -- could drop
        # the write entirely and nothing here would notice.
        "state": [state.get(name, 0) & 0xFFFFFFFFFFFFFFFF for name, _ in state_slots],
    }


class RegionJit:
    """Compile a lifted module and call its region function."""

    #: Bytes past the compared image, so an address the reference did not take
    #: lands somewhere rather than faulting.
    slack = 1 << 20

    engine = None

    def __init__(self, bits: int):
        import llvmlite.binding as llvm

        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        self.llvm = llvm
        self.target = llvm.Target.from_default_triple()
        self.word = ctypes.c_uint64 if bits == 64 else ctypes.c_uint32
        self.bits = bits
        self.engines = []

    def compile(self, module_text: str):
        """Parse and compile one module, once.

        A module holding every region is thirty thousand lines of preamble plus
        a function each; parsing it per call turned a sweep into something that
        ran for an hour. It is compiled once and its functions are called by
        name.
        """
        tm = self.target.create_target_machine()
        mod = self.llvm.parse_assembly(module_text)
        mod.verify()
        engine = self.llvm.create_mcjit_compiler(mod, tm)
        engine.finalize_object()
        # Only the newest engine is kept alive. Several engines each defining a
        # module's worth of symbols is what `jit_llvm.py` warns about, and a
        # sweep that holds forty of them was resolving a call to whichever
        # engine registered the name first.
        self.engines = [(tm, engine)]
        self.engine = engine

    def drive(self, module_text, entry_pc, blocks, init_regs, image, init_state,
              limit=64):
        """Run block by block, the way a translator does.

        The lifted module has one function per basic block, each reporting where
        control goes next. Composing them is the caller's job -- which is the
        point of lifting by block: an edge the lifter guessed cannot be wrong if
        the lifter does not draw one.
        """
        if module_text is not None:
            self.compile(module_text)
        regs = (self.word * len(init_regs))(*init_regs)
        # ⚠️ `from_buffer_copy`, not `Array(*data)`. The second spells the
        # buffer as a million separate arguments -- one per byte of the image
        # plus a megabyte of slack -- and does it once per instruction compared.
        # It is the slowest line in the sweep by a wide margin, and it made a
        # run that finishes look exactly like one that has hung.
        memory = (ctypes.c_uint8 * (len(image) + self.slack)).from_buffer_copy(
            image + bytes(self.slack))
        status = (self.word * 4)()
        state = (self.word * max(len(init_state), 1))(*init_state) \
            if init_state else (self.word * 1)()
        pc = entry_pc
        steps = 0
        while pc in blocks and steps < limit:
            address = self.engine.get_function_address(f"axis_block_{pc:x}")
            cfunc = ctypes.CFUNCTYPE(
                None,
                ctypes.POINTER(self.word),
                ctypes.POINTER(ctypes.c_uint8),
                ctypes.POINTER(self.word),
                ctypes.POINTER(self.word),
            )(address)
            cfunc(regs, memory, status, state)
            pc = int(status[0])
            steps += 1
        return {
            "regs": [int(value) for value in regs],
            "mem": bytes(memory)[:len(image)],
            "pc": pc,
            "beyond": bytes(memory)[len(image):],
            "state": [int(value) for value in state],
            "steps": steps,
        }

    def run(self, module_text: str, name: str, init_regs, image, init_state):
        if module_text is not None:
            self.compile(module_text)
        engine = self.engine
        address = engine.get_function_address(name)
        cfunc = ctypes.CFUNCTYPE(
            None,
            ctypes.POINTER(self.word),
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.POINTER(self.word),
            ctypes.POINTER(self.word),
        )(address)
        regs = (self.word * len(init_regs))(*init_regs)
        # Room past the image the comparison covers. A lifted block that
        # computes an address the reference did not is a divergence to report,
        # and reporting it requires surviving it: writing one byte past a
        # tight allocation takes the process down with SIGBUS, which says
        # nothing about which instruction was wrong.
        # ⚠️ `from_buffer_copy`, not `Array(*data)`. The second spells the
        # buffer as a million separate arguments -- one per byte of the image
        # plus a megabyte of slack -- and does it once per instruction compared.
        # It is the slowest line in the sweep by a wide margin, and it made a
        # run that finishes look exactly like one that has hung.
        memory = (ctypes.c_uint8 * (len(image) + self.slack)).from_buffer_copy(
            image + bytes(self.slack))
        status = (self.word * 4)()
        state = (self.word * max(len(init_state), 1))(*init_state) \
            if init_state else (self.word * 1)()
        cfunc(regs, memory, status, state)
        return {
            "regs": [int(value) for value in regs],
            "mem": bytes(memory)[:len(image)],
            "pc": int(status[0]),
            "beyond": bytes(memory)[len(image):],
        }


def blame(args, program, widths, axis_lift, axis_exec, lifter, jit, slots,
          state_slots, init_regs, seed_image, init_state, alias_slot, alias_name,
          file_slots, base=0):
    """The first instruction of a failing region that disagrees.

    A region that differs names a neighbourhood; this names an instruction. It
    re-runs prefixes of the region -- one instruction, then two -- and stops at
    the first length where the lifted blocks and the executor part company. The
    prefix before it agreed, so the instruction that was added is the one to
    look at.
    """
    for count in range(1, len(program) + 1):
        prefix = program[:count]
        image = region_bytes(prefix, widths)
        isa = prefix[0][0].get("isa")
        summary = blocks_of(lifter, image, base, isa)
        if "declined at" in summary or "undecodable at" in summary:
            continue                    # this prefix is not liftable; try a longer one
        module = lift(lifter, image, base, isa)
        if module is None:
            continue
        addressed = []
        addr = base
        for entry, _values, word in prefix:
            width = widths.get(entry["mnemonic"], 32) // 8
            branches = any(effect.get("kind") == "setpc"
                           for effect in entry.get("effects") or [])
            addressed.append((addr, int(word), entry.get("isa"), width, branches))
            addr += width
        want = python_region(addressed, init_regs, seed_image, base, axis_exec,
                             axis_lift, slots, state_slots, init_state, alias_slot,
                             alias_name)
        if want is None:
            import os
            if os.environ.get("AXIS_DBG"):
                print(f"      blame: prefix {count} not runnable", flush=True)
            continue
        got = jit.drive(module, base, block_starts(summary), init_regs, seed_image,
                        init_state)
        import os
        if os.environ.get("AXIS_DBG"):
            same = got["regs"][:file_slots] == want["regs"]
            print(f"      blame: prefix {count} regs match={same} "
                  f"slot4 lifted={got['regs'][4]:#x} exec={want['regs'][4]:#x} "
                  f"steps={got['steps']} blocks={sorted(block_starts(summary))}",
                  flush=True)
        if got["regs"][:file_slots] != want["regs"] or got["mem"] != want["mem"]:
            bad = [slot for slot in range(file_slots)
                   if got["regs"][slot] != want["regs"][slot]]
            where = (f"slot {bad[0]}: lifted {got['regs'][bad[0]]:#x} != executor "
                     f"{want['regs'][bad[0]]:#x}" if bad else "memory differs")
            return prefix[-1][0]["mnemonic"], count, where
    return None


def sweep(args, axis_lift, axis_exec, widths, takes, refused, entries, lifter,
          rng, jit, slots, state_slots, alias_slot, alias_name, file_slots):
    """Lift each instruction on its own and name the ones that disagree.

    A sampled region says *that* something is wrong; this says *what*. One
    instruction is the smallest region there is, so a disagreement here names an
    instruction rather than a neighbourhood.

    Every region goes into **one** module. The preamble -- the semantics
    helpers, the AArch64 helpers, the float intrinsics -- is thirty thousand
    lines, and parsing and compiling it once per instruction turned a sweep of a
    nine-hundred-instruction corpus into something that ran for an hour without
    reaching the end. Each region is lifted at its own base address so its
    function has its own name, and the module is built once.
    """
    plan = []
    only = {name.strip() for name in args.only.split(",")} if args.only else None
    # The declines are counted against what the sweep was asked to look at. Left
    # whole under `--only` the total would be the corpus's, next to a compared
    # count that is five -- a number describing something other than this run.
    if only:
        refused = [name for name in refused if name in only]
    # ⚠️ Instructions this could not get a decodable encoding for, or could not
    # lift, are COUNTED. They used to be dropped in silence, and the count the
    # sweep printed was of what it happened to reach rather than what it set
    # out to: `STR_Q_REG` encodes to something that decodes back to itself
    # about half the time, so one seed compared it and the next did not, with
    # nothing in the output saying which.
    undrawable: list[str] = []
    unliftable: list[str] = []
    for entry in entries:
        if not takes(entry):
            continue
        name = entry["mnemonic"]
        if only and name not in only:
            continue
        # A random immediate can turn one encoding into another instruction, so
        # a single draw is a coin toss for some. Redraw rather than give up --
        # the same answer `draw_region` reached for the same reason.
        for _attempt in range(DRAW_TRIES):
            one = ef.gen_program([entry], 1, rng, axis_lift)[0]
            seen = axis_lift.decode(int(one[2]), entry.get("isa"))
            if seen is not None and seen["mnemonic"] == name:
                break
        else:
            undrawable.append(name)
            continue
        base = len(plan) * 16
        image = region_bytes([(seen, one[1], one[2])], widths)
        bodies = lift_bodies(lifter, image, base, entry.get("isa"))
        if bodies is None:
            unliftable.append(name)
            continue
        plan.append((name, seen, one, base, bodies))

    if not plan:
        print("no instruction lifted: nothing was compared")
        return FAILED

    # The preamble once, then every region's blocks. The library separates the
    # two, so this is an API rather than string surgery on a module.
    combined = lifter.preamble() + "".join(bodies for *_rest, bodies in plan)

    jit.compile(combined)
    divergent: dict = {}
    checked = skipped = 0
    for name, seen, one, base, _module in plan:
        seed_image = bytes(rng.getrandbits(8) for _ in range(MEM_BYTES))
        # An atomic access must be naturally aligned: arm64 does not allow an
        # unaligned one, and the JIT does not fault on it -- it spins, which
        # looks exactly like a slow sweep. `llvm_effects_check` aligns for the
        # same reason, and says the same thing: AXIS does not model the fault,
        # so this generates addresses the architecture allows rather than
        # comparing two backends on behaviour neither of them defines.
        align = atomic_alignment(seen)
        init_regs = [rng.randrange(REG_LIMIT) & ~(align - 1)
                     for _ in range(file_slots)]
        init_state = [rng.randrange(1 << min(w, 32)) for _, w in state_slots]
        width = widths.get(name, 32) // 8
        branches = any(effect.get("kind") == "setpc"
                       for effect in seen.get("effects") or [])
        want = python_region([(base, int(one[2]), seen.get("isa"), width, branches)],
                             init_regs, seed_image, base, axis_exec, axis_lift,
                             slots, state_slots, init_state, alias_slot,
                             alias_name)
        if want is None:
            skipped += 1
            continue
        got = jit.drive(None, base, {base}, init_regs, seed_image, init_state)
        checked += 1
        if got["regs"][:file_slots] != want["regs"]:
            bad = [slot for slot in range(file_slots)
                   if got["regs"][slot] != want["regs"][slot]]
            divergent[name] = (f"slot {bad[0]}: lifted {got['regs'][bad[0]]:#x} != "
                               f"executor {want['regs'][bad[0]]:#x}")
        elif got["mem"] != want["mem"]:
            first = next(i for i in range(len(want["mem"]))
                         if got["mem"][i] != want["mem"][i])
            divergent[name] = f"mem[{first}] differs"
        elif any(got["beyond"]):
            divergent[name] = "wrote past the memory the executor stayed inside"
        elif got["state"][:len(want["state"])] != want["state"]:
            bad = next(i for i in range(len(want["state"]))
                       if got["state"][i] != want["state"][i])
            divergent[name] = (f"state {state_slots[bad][0]}: lifted "
                               f"{got['state'][bad]:#x} != executor "
                               f"{want['state'][bad]:#x}")
        elif got["pc"] != want["pc"]:
            divergent[name] = (f"left at {got['pc']:#x}, executor reached "
                               f"{want['pc']:#x}")
    print(f"{checked} instruction(s) compared, {len(divergent)} disagree, "
          f"{skipped} not runnable, {len(refused)} refused before lifting")
    # Said out loud, because these are instructions the sweep intended to check
    # and did not -- the one number that used to go missing.
    if undrawable:
        print(f"{len(undrawable)} instruction(s) with no encoding that decodes "
              f"back to them in {DRAW_TRIES} tries: "
              f"{', '.join(sorted(undrawable)[:6])}"
              + (" (+more)" if len(undrawable) > 6 else ""))
    if unliftable:
        print(f"{len(unliftable)} instruction(s) accepted but not lifted: "
              f"{', '.join(sorted(unliftable)[:6])}"
              + (" (+more)" if len(unliftable) > 6 else ""))
    for name, why in sorted(divergent.items()):
        print(f"  {name}: {why}")
    # An instruction the lifter ACCEPTS and then cannot lift is a failure, not a
    # note. `refusal` documents itself as the single place that decides; twice
    # it was not, and both times the sweep saw it and said nothing because it
    # only counted what it reached.
    return PASSED if not divergent and not unliftable else FAILED


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    parser.add_argument("--regions", type=int, default=24)
    parser.add_argument("--length", type=int, default=6)
    parser.add_argument("--seed", type=int, default=0x11F7)
    parser.add_argument("--planted", action="store_true",
                        help="run the hand-built regions in PLANTED rather "
                             "than drawing random ones")
    # Restricting the sweep to a few mnemonics. The whole run takes minutes,
    # and when one instruction is in question the answer should not have to be
    # inferred from which of three totals moved.
    parser.add_argument("--only", default=None,
                        help="comma-separated mnemonics to sweep, all by default")
    parser.add_argument("--per-instruction", action="store_true",
                        help="lift each instruction alone and name the ones "
                             "that disagree, rather than sampling regions")
    parser.add_argument("--cases", type=int, default=4,
                        help="random cases per instruction in --per-instruction")
    args = parser.parse_args()

    try:
        import llvmlite.binding  # noqa: F401
    except ImportError:
        print("SKIP: llvmlite is not installed")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_liftregion_"))
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    try:
        lifter = Lifter(args.axis_file)
    except FileNotFoundError as missing:
        print(f"SKIP: {missing}")
        return DECLINED
    sys.path.insert(0, str(workdir))
    axis_lift = importlib.import_module("axis_lift")
    axis_exec = importlib.import_module("axis_exec")

    # Instructions the region lifter can take: encodable, with semantics, and
    # not one the LLVM path withholds. The lifter itself is the authority on the
    # last part -- it declines a region containing one -- so the filter here is
    # only about building regions that are worth running.
    # ⚠️ A DERIVED operand has no fields and needs none: `CASP` names a register
    # pair with one field, `rs2` being `rs + 1`, and the instruction word says
    # so only by saying `rs`. Requiring fields of every operand excluded all
    # sixteen paired compare-and-swaps from the sweep -- silently, before
    # `takes` was consulted, so they did not even appear in the refusal count.
    entries = [
        entry for entry in axis_lift.AXIS_LIFT_TABLE
        if all(op["fields"] or op.get("derived_from")
               for op in entry["operands"] if op["kind"] != "imm")
        and (entry.get("semantics") is not None or entry.get("effects"))
    ]
    if not entries:
        print("SKIP: nothing encodable to build a region from")
        return DECLINED

    widths = instruction_widths(args.axis_file)
    # Which instructions the lifter takes, asked once for the whole
    # description. Asking one at a time cost a process per instruction, which
    # is nine hundred of them on the AArch64 corpus, and the answers are the
    # same -- the lifter decides this from the description, not from a sample.
    verdicts = {name: reason is None for name, reason in lifter.support().items()}
    refused = sorted(name for name, ok in verdicts.items() if not ok)

    def takes(entry) -> bool:
        return verdicts.get(entry["mnemonic"], False)

    slots = axis_lift.REGISTER_FILE_SLOTS
    # A class that aliases an index onto a name -- AArch64's `sp`. The region
    # gives it the slot just past the file; the executor gives it the name.
    aliases = [rules[1] for rules in axis_lift.REGISTER_CLASSES.values() if rules[1]]
    alias_slot = slots if aliases else None
    alias_name = aliases[0][1] if aliases else None
    file_slots = slots + (1 if aliases else 0)
    state_slots = axis_lift.STATE_SLOTS
    bits = 64 if any(entry.get("state_width", 32) > 32
                     for entry in axis_lift.AXIS_LIFT_TABLE) else 32
    rng = random.Random(args.seed)
    jit = RegionJit(bits)

    lifted = declined = compared = failures = unstable = 0
    covered: set[str] = set()
    if args.per_instruction:
        return sweep(args, axis_lift, axis_exec, widths, takes, refused, entries,
                     lifter, rng, jit, slots, state_slots, alias_slot,
                     alias_name, file_slots)
    if args.planted:
        return planted_regions(args, axis_lift, axis_exec, widths, lifter, rng,
                               jit, slots, state_slots, alias_slot, alias_name,
                               file_slots)

    for index in range(args.regions):
        program = draw_region(entries, takes, args.length, rng, axis_lift)
        if program is None:
            declined += 1
            continue
        image = region_bytes(program, widths)
        # A base of its own, so this region's block functions have names of
        # their own. Every region lifted at 0 defines `axis_block_0`, and a JIT
        # holding several engines resolves that name to whichever registered it
        # first -- so a later region ran an earlier region's code and the
        # difference read as a lowering bug. Shrinking the region could not
        # reproduce it, which is the tell: the failure was not in the program.
        base = (index + 1) * 0x10000
        isa = program[0][0].get("isa")
        # What the *bytes* decode to, which is not what the generator intended:
        # a random immediate can turn one encoding into another instruction, so
        # a region built from liftable entries can still hold one the lifter
        # declines. It stops there, correctly, while the executor runs on -- so
        # the region is skipped rather than compared over different work.
        summary = blocks_of(lifter, image, base, isa)
        if "declined at" in summary or "undecodable at" in summary:
            declined += 1
            continue
        module = lift(lifter, image, base, isa)
        if module is None:
            declined += 1
            continue
        lifted += 1
        covered.update(entry["mnemonic"] for entry, _v, _w in program)

        seed_image = bytes(rng.getrandbits(8) for _ in range(MEM_BYTES))
        # The widest natural alignment any atomic in the region needs. arm64
        # does not allow an unaligned atomic and neither side models the fault,
        # so this generates addresses the architecture allows rather than
        # comparing two backends on behaviour neither of them defines. The
        # per-instruction sweep aligns for the same reason.
        align = max([atomic_alignment(entry) for entry, _v, _w in program] or [1])
        init_regs = [rng.randrange(REG_LIMIT) & ~(align - 1)
                     for _ in range(file_slots)]
        init_state = [rng.randrange(1 << min(width, 32)) for _, width in state_slots]

        addressed = []
        addr = base
        for entry, _values, word in program:
            width = widths.get(entry["mnemonic"], 32) // 8
            branches = any(effect.get("kind") == "setpc"
                           for effect in entry.get("effects") or [])
            addressed.append((addr, int(word), entry.get("isa"), width, branches))
            addr += width
        want = python_region(addressed, init_regs, seed_image, base, axis_exec,
                             axis_lift, slots, state_slots, init_state,
                             alias_slot, alias_name)
        if want is None:
            declined += 1
            continue
        # The reference has to give the same answer twice, and does not always:
        # see docs/lifter_design.md section 7b. A region where it does not is
        # counted and skipped, because comparing the lifter against a value that
        # changes between runs says nothing about the lifter.
        again = python_region(addressed, init_regs, seed_image, base, axis_exec,
                              axis_lift, slots, state_slots, init_state,
                              alias_slot, alias_name)
        if again is None or again["regs"] != want["regs"] \
                or again["mem"] != want["mem"]:
            unstable += 1
            continue
        got = jit.drive(module, base, block_starts(summary), init_regs, seed_image,
                        init_state)
        compared += 1
        if got["regs"][:file_slots] != want["regs"]:
            bad = [slot for slot in range(file_slots)
                   if got["regs"][slot] != want["regs"][slot]]
            print(f"FAIL region #{index}: registers differ at {bad[:6]} "
                  f"(steps={got['steps']}, blocks="
                  f"{sorted(block_starts(summary))})")
            for slot in bad[:3]:
                print(f"    slot {slot}: lifted {got['regs'][slot]:#x} != "
                      f"executor {want['regs'][slot]:#x}")
            found = blame(args, program, widths, axis_lift, axis_exec, lifter, jit,
                          slots, state_slots, init_regs, seed_image, init_state,
                          alias_slot, alias_name, file_slots, base)
            if found:
                print(f"    first disagreement after {found[1]} instruction(s): "
                      f"{found[0]} ({found[2]})")
            failures += 1
        elif got["mem"] != want["mem"]:
            first = next(i for i in range(len(want["mem"]))
                         if got["mem"][i] != want["mem"][i])
            print(f"FAIL region #{index}: mem[{first}] lifted {got['mem'][first]} "
                  f"!= executor {want['mem'][first]}")
            failures += 1
        elif any(got["beyond"]):
            first = next(i for i, byte in enumerate(got["beyond"]) if byte)
            print(f"FAIL region #{index}: wrote {first + len(seed_image):#x}, past "
                  f"the memory the executor stayed inside")
            failures += 1
        elif got["pc"] != want["pc"]:
            print(f"FAIL region #{index}: left at {got['pc']:#x}, executor "
                  f"reached {want['pc']:#x}")
            failures += 1
        if failures >= 3:
            print("... stopping after 3 failures")
            break

    print(f"{compared} region(s) compared, {lifted} lifted, {declined} declined, "
          f"{unstable} unstable, {failures} failures")
    if refused:
        shown = ", ".join(sorted(refused)[:6])
        more = f" (+{len(refused) - 6} more)" if len(refused) > 6 else ""
        print(f"{len(refused)} instruction(s) the lifter declines: {shown}{more}")
    if compared:
        print(f"instructions covered: {len(covered)}")
    # A run that lifted nothing proves nothing, and would otherwise print a
    # cheerful pass over an empty comparison.
    if not compared:
        print("no region was both lifted and executable: nothing was compared")
        print("lifted region == executor: FAIL")
        return FAILED
    ok = failures == 0
    print("lifted region == executor: " + ("PASS" if ok else "FAIL"))
    return PASSED if ok else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
