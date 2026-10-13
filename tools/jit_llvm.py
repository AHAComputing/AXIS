#!/usr/bin/env python3
"""In-process LLVM JIT backend for AXIS blocks (JIT plan step 5, native path).

Where tools/jit_c.py transpiles a block to C and shells out to `cc`, this is a
real in-process JIT: it lowers a decoded block to LLVM IR that *calls the proven
`axis_eval_*` functions from `axis_semantics.ll`* (the same LLVM semantics
`llvm_vs_golden.py` proves equal to the golden model), then compiles it in memory
with llvmlite's MCJIT/ORC and executes it through a raw function pointer -- no
subprocess, no temp files. Because the block only calls already-proven handlers,
it trusts no new semantics; it is itself proven here: the JIT-compiled block's
register file must equal the golden model over random blocks. A block cache keyed
by the instruction-word sequence compiles each distinct block once and reuses the
native code on repeats -- the memoization a hot-loop simulator needs.

This backend covers the full pure-instruction surface, including clz/ctz/cpop
(the LLVM semantics lower them via llvm.ctlz/cttz/ctpop), and the 32-bit effect
surface: effectful instructions call the proven `axis_eff_*` handlers, which do
their own loads and stores against a byte buffer the JIT passes in. The block
threads the pc through the sequence, commits a register write only when the
handler reports one (a guarded `set` decides that at runtime), and exits early
on a trap. Effect blocks are checked against `axis_exec.py` on the full
architectural delta -- registers, memory, pc, trap, and step count -- over the
same byte-addressed memory both sides use.

Usage: tools/jit_llvm.py [input.axisl] [--distinct N] [--programs M] [--seed S]

Requires: cargo (from the AXIS repo root) and llvmlite (pip install llvmlite).
"""

from __future__ import annotations

import argparse
import ctypes
import importlib
import os
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exec_fuzz as ef  # noqa: E402  (reuse program generator)
from llvm_effects_check import ByteMemory, TRAP_CAUSES  # noqa: E402
from scalable_addressing import ADDRESSING, SEGMENTS  # noqa: E402

AXIS_ROOT = ef.AXIS_ROOT
REG_COUNT = ef.REG_COUNT
# Effect programs run against a byte buffer, so their register and immediate
# values stay small enough that computed addresses land inside it.
EFFECT_MEM_BYTES = 1 << 16
EFFECT_REG_LIMIT = 4096
EFFECT_IMM_LIMIT = 64


def pyident(mnemonic: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "_", mnemonic).lower()


def signature_bits(sem_ll: str, symbol: str, effect: bool) -> int:
    """The evaluation width the emitted handler was given.

    A document can hold 32- and 64-bit instructions at once, and each handler is
    emitted at its own width, so the block reads the width off the definition
    rather than assuming the corpus is uniform.
    """
    marker = (f"define void @{symbol}(i8* %mem, " if effect
              else f"define i64 @{symbol}(")
    if effect:
        head = sem_ll.split(marker, 1)
        return 64 if len(head) > 1 and head[1].startswith("i64 %pc") else 32
    return 64 if marker in sem_ll else 32


def register_kind_width(kind: str) -> int:
    """The architectural width a register operand of this kind reads and writes."""
    return 32 if "gpr32" in kind else 64


def placed_slot(placement, index):
    """The slot an operand's register starts at, and the bit offset within it.

    A lane operand names an element of a register that spans several slots: the
    register is `index + register_bias` (a lane past a register's capacity is in
    the next one), it starts at `register * stride`, and the element sits at
    `view_offset` bits into it. Since every element width here divides a slot
    and every element is aligned to its own width, an element never straddles a
    slot boundary -- so the block reads one slot and masks. `scalable_program`
    refuses anything else rather than emitting IR for a case nothing exercises.
    """
    register = index + placement.get("register_bias", 0)
    slot = (placement.get("base", 0) + register * placement["stride"]
            + placement["view_offset"] // 64)
    return slot, placement["view_offset"] % 64


def read_register(index, kind, bits, name, lines, placement=None, slot=None,
                  lift=None):
    """IR for reading a register operand, with AArch64's conventions applied.

    The index is a constant in a compiled block, so XZR and SP are decided here
    rather than at run time: reading x31 is zero for the plain classes and the
    stack pointer for the `sp` ones, and a W-form read exposes the low 32 bits
    of the shared X register.

    `placement` is an operand's own view, which a register class cannot hold:
    element 5 of a scalable register, whose bits depend on VL. When it is
    present it decides the slot and the width, and the class conventions above
    do not apply -- a Z register has no zero index and no W form.
    """
    ty = f"i{bits}"
    if placement is not None:
        slot, shift = placed_slot(placement, index)
        width = placement["view_width"]
        pointer, loaded = f"%{name}_p", f"%{name}_v"
        lines.append(f"  {pointer} = getelementptr {ty}, {ty}* %regs, i64 {slot}")
        lines.append(f"  {loaded} = load {ty}, {ty}* {pointer}")
        if shift:
            shifted = f"%{name}_s"
            lines.append(f"  {shifted} = lshr {ty} {loaded}, {shift}")
            loaded = shifted
        if width < bits:
            masked = f"%{name}_m"
            lines.append(f"  {masked} = and {ty} {loaded}, {(1 << width) - 1}")
            loaded = masked
        return loaded
    if lift is not None and hardwired_zero(kind, index, lift):
        return "0"                              # a hardwired zero register
    pointer = f"%{name}_p"
    loaded = f"%{name}_v"
    # The slot, not the register number. They are the same only for a class
    # that starts the file and strides by one; `a64_vreg64` does neither, so
    # reading `d6` at index 6 read x6 -- a general-purpose register, with a
    # plausible value in it. The conventions above stay on the index, because
    # XZR and SP are facts about the number 31 and not about where it lands.
    lines.append(f"  {pointer} = getelementptr {ty}, {ty}* %regs, i64 "
                 f"{index if slot is None else slot}")
    lines.append(f"  {loaded} = load {ty}, {ty}* {pointer}")
    if kind != "reg" and register_kind_width(kind) == 32 and bits == 64:
        narrowed = f"%{name}_w"
        lines.append(f"  {narrowed} = and i64 {loaded}, 4294967295")
        return narrowed
    return loaded


def aliases_state(lift):
    """Whether any register class turns an index into named state.

    AArch64 does, for `sp`. A corpus that does not needs no slot for it, and
    adding one anyway would leave a slot the reference reports and the block
    never writes.
    """
    return any(rules[1] for rules in lift.REGISTER_CLASSES.values())


def hardwired_zero(kind, index, lift):
    """Whether this class hardwires this index to zero.

    From the class table, not from the number 31. AArch64 spells XZR that way,
    so a test for "not `reg` and index 31" agreed with the table for every
    AArch64 class and disagreed for the accelerator's own `reg32`, which
    numbers 31 like any other register and hardwires nothing. A block reading
    `reg32[31]` got a constant zero where the executor read the register.
    """
    rules = lift.REGISTER_CLASSES.get(kind)
    return bool(rules) and rules[0] is not None and index == rules[0]


def file_slot(kind, index, lift):
    """Where an operand's register lives in the block's flat array.

    The stack pointer is not a slot of the register file. AArch64 spells it as
    encoding 31 of the `sp` classes, which the class table turns into an alias
    onto named state -- and the file's slot 31 belongs to whichever class
    actually numbers 31, which in this corpus is the accelerator's plain `reg`.
    Keeping both in slot 31 made `reg[31]` and `sp` the same storage in the JIT
    and different storage in the reference, so a block that wrote one and read
    the other disagreed. The block carries one slot past the file and the alias
    lands there.
    """
    rules = lift.REGISTER_CLASSES.get(kind)
    if rules and rules[1] and index == rules[1][0]:
        return lift.REGISTER_FILE_SLOTS
    return lift.register_slot(kind, index)


def zeroed_limbs(kind, base, lift):
    """The slots a write to this class clears besides the one it lands in.

    A narrow view over a register held as several limbs says what happens to
    the rest of the register, and for a zeroing class the answer is "it becomes
    zero" -- writing AArch64's `d1` clears the upper half of `v1`, a whole slot
    away. The Python executor has always done this; the JIT stored its one slot
    and left the other limb holding whatever the last write to `q1` put there.
    """
    rules = lift.REGISTER_CLASSES.get(kind)
    if rules is None:
        return []
    view, preserves, limbs = rules[2], rules[5], rules[6] or 1
    if not view or preserves or limbs <= 1:
        return []
    return [base + k for k in range(1, limbs)]


def write_register(index, kind, bits, name, value, lines, guard=None,
                   placement=None, slot=None, zero_slots=(), lift=None):
    """IR for committing a register write, with the same conventions.

    A write to x31 is discarded by the plain classes and goes to the stack
    pointer for the `sp` ones. A W-form write zero-extends into the shared
    X register, which the handler has already done by masking to the operand
    width. `guard` is an `i1` for a write the handler reports conditionally.
    """
    ty = f"i{bits}"
    if placement is not None:
        # One element of a register, leaving the rest of it alone: read, clear
        # the element's bits, insert. A guarded write selects between the new
        # value and the old element, as the unplaced path does.
        slot, shift = placed_slot(placement, index)
        width = placement["view_width"]
        cover = ((1 << width) - 1) << shift
        pointer = f"%{name}_pd"
        lines.append(f"  {pointer} = getelementptr {ty}, {ty}* %regs, i64 {slot}")
        lines.append(f"  %{name}_old = load {ty}, {ty}* {pointer}")
        lines.append(f"  %{name}_keep = and {ty} %{name}_old, {~cover & ((1 << bits) - 1)}")
        lines.append(f"  %{name}_fit = and {ty} {value}, {(1 << width) - 1}")
        placed = f"%{name}_fit"
        if shift:
            lines.append(f"  %{name}_sh = shl {ty} {placed}, {shift}")
            placed = f"%{name}_sh"
        lines.append(f"  %{name}_new = or {ty} %{name}_keep, {placed}")
        stored = f"%{name}_new"
        if guard is not None:
            lines.append(f"  %{name}_sel = select i1 {guard}, {ty} {stored}, "
                         f"{ty} %{name}_old")
            stored = f"%{name}_sel"
        lines.append(f"  store {ty} {stored}, {ty}* {pointer}")
        return
    if lift is not None and hardwired_zero(kind, index, lift):
        return                                  # discarded by the class
    pointer = f"%{name}_pd"
    lines.append(f"  {pointer} = getelementptr {ty}, {ty}* %regs, i64 "
                 f"{index if slot is None else slot}")
    if guard is not None:
        old = f"%{name}_old"
        chosen = f"%{name}_sel"
        lines.append(f"  {old} = load {ty}, {ty}* {pointer}")
        lines.append(f"  {chosen} = select i1 {guard}, {ty} {value}, {ty} {old}")
        value = chosen
    lines.append(f"  store {ty} {value}, {ty}* {pointer}")
    # The rest of the register, for a class that zeroes what its view does not
    # cover. Guarded the same way the value is: a write that did not fire
    # clears nothing.
    for n, other in enumerate(zero_slots):
        rest = f"%{name}_z{n}"
        lines.append(f"  {rest} = getelementptr {ty}, {ty}* %regs, i64 {other}")
        cleared = "0"
        if guard is not None:
            lines.append(f"  %{name}_z{n}_old = load {ty}, {ty}* {rest}")
            lines.append(f"  %{name}_z{n}_sel = select i1 {guard}, {ty} 0, "
                         f"{ty} %{name}_z{n}_old")
            cleared = f"%{name}_z{n}_sel"
        lines.append(f"  store {ty} {cleared}, {ty}* {rest}")


def placement_of(operand, lift):
    """An operand's own view of the register it names, or None.

    Published by the lifter for lane operands only: the class says which file,
    the operand says which element. The file's own start comes from the class,
    which is why it is folded in here rather than assumed to be zero -- the
    vector file sits above the scalar one.
    """
    if operand is None or not operand.get("view_width"):
        return None
    # The file's own start, published with the placement: a file above a
    # scalable one moves with VL, so the class table cannot hold it.
    return dict(operand, base=operand.get(
        "slot_base", lift.REGISTER_CLASSES[operand["kind"]][3]))


def block_ir(program, sem_ll: str, lift, bits: int = 32) -> str:
    """Lower a block to `axis_jit_block(iW* regs, i8* mem, iW pc, iW* status,
    iW* state)`.

    Pure instructions call the proven `axis_eval_*` handlers; effectful ones
    call the proven `axis_eff_*` handlers, which perform their own memory
    accesses against `%mem` and report their writes, next pc and trap through a
    scratch array. The block threads the pc through the sequence and exits
    early on a trap, matching the reference executor. `status` receives the
    final pc, the trap id, and the number of instructions executed.

    `W` is 64 for a 64-bit ISA. The register file is one slot per architectural
    register, with slot 31 holding the stack pointer: on AArch64 the encoding
    31 means either SP or the zero register depending on the operand class, and
    because a compiled block knows every index as a constant, that choice is
    made here at build time rather than tested at run time.
    """
    ty = f"i{bits}"
    # The handler's scratch array is sized by the generated lifter, not by the
    # slots this block happens to read: an effect function writes every slot its
    # instruction needs, so a short array here would be a stack overrun.
    slots = lift.EFFECT_OUT_SLOTS
    state_slots = max(len(lift.STATE_SLOTS), 1)
    lines = [
        f"define void @axis_jit_block({ty}* %regs, i8* %mem, {ty} %pc, "
        f"{ty}* %status, {ty}* %state) {{",
        "entry:",
        f"  %eff = alloca [{slots} x {ty}]",
    ] + [
        f"  %eff{k} = getelementptr [{slots} x {ty}], [{slots} x {ty}]* %eff, "
        f"i64 0, i64 {k}"
        for k in range(slots)
    ] + [
        f"  %status_pc = getelementptr {ty}, {ty}* %status, i64 0",
        f"  %status_trap = getelementptr {ty}, {ty}* %status, i64 1",
        f"  %status_steps = getelementptr {ty}, {ty}* %status, i64 2",
    ]
    pc = "%pc"
    for i, (entry, values, _word) in enumerate(program):
        ident = pyident(entry["mnemonic"])
        args = []
        for k, op in enumerate(o for o in entry["operands"]
                               if o["role"] not in ("out", "enc")):
            # A selector is encoded and read by nothing: it carries the register
            # number an instruction's lanes are elements of, and passing it here
            # would hand the handler a register number where a value belongs.
            v = values[op["name"]]
            if lift.is_register_operand(op["kind"]):
                placement = placement_of(op, lift)
                base = file_slot(op["kind"], v, lift)
                # An operand wider than a slot is passed as limbs, low first --
                # the effect ABI's parameter list, and the register file's own
                # layout. Passing one argument for a two-limb register left the
                # handler reading the operands after it off by one.
                limbs = 1
                if placement is None:
                    limbs = max(1, -(-(op.get("width") or bits) // bits))
                for limb in range(limbs):
                    args.append(
                        f"{ty} " + read_register(v, op["kind"], bits,
                                                 f"o{i}_{k}_{limb}", lines,
                                                 placement=placement,
                                                 slot=base + limb, lift=lift))
            else:
                args.append(f"{ty} {v & ((1 << bits) - 1)}")

        if entry.get("effects"):
            call_args = ", ".join(
                ["i8* %mem", f"{ty} {pc}", f"{ty}* %eff0", f"{ty}* %state"] + args)
            lines.append(f"  call void @axis_eff_{ident}({call_args})")
            lines.append(f"  %o{i}_next = load {ty}, {ty}* %eff2")
            lines.append(f"  %o{i}_trap = load {ty}, {ty}* %eff3")
            # Write k is the k-th register-writing effect, whose destination
            # operand the lift table names; `wrote` is dynamic because a guarded
            # `set` decides at run time.
            kinds = {op["name"]: op["kind"] for op in entry["operands"]}
            writes = [e for e in entry["effects"]
                      if e.get("kind") in ("set", "setreg")]
            # Advanced by limbs rather than by one per effect: a write slot is
            # a register slot, so a 128-bit destination occupies two of them and
            # every write after it moves up by two. Counting effects committed
            # the low limb, dropped the high one, and read the next effect's
            # value out of the slot the high limb was in.
            position = 0
            for effect in writes:
                if effect.get("kind") == "setreg":
                    # A fixed register: the index is in the artifact, not in an
                    # operand. AArch64 BL writes x30.
                    value_slot, wrote_slot = ((0, 1) if position == 0
                                              else (2 + 2 * position, 3 + 2 * position))
                    name = f"o{i}_w{position}"
                    lines.append(f"  %{name}_val = load {ty}, {ty}* %eff{value_slot}")
                    lines.append(f"  %{name}_wrote = load {ty}, {ty}* %eff{wrote_slot}")
                    lines.append(f"  %{name}_did = icmp ne {ty} %{name}_wrote, 0")
                    fixed_kind = effect.get("reg_kind", "reg")
                    fixed_slot = file_slot(fixed_kind, effect["index"], lift)
                    write_register(effect["index"], fixed_kind,
                                   bits, name, f"%{name}_val", lines,
                                   guard=f"%{name}_did", slot=fixed_slot,
                                   zero_slots=zeroed_limbs(fixed_kind,
                                                           fixed_slot, lift),
                                   lift=lift)
                    position += 1
                    continue
                dest = effect.get("dest")
                if dest is None or dest not in values:
                    position += 1
                    continue
                dest_op = next((op for op in entry["operands"]
                                if op["name"] == dest), None)
                placement = placement_of(dest_op, lift)
                base = file_slot(kinds.get(dest, "reg"), values[dest], lift)
                limbs = 1
                if placement is None and dest_op is not None:
                    limbs = max(1, -(-(dest_op.get("width") or bits) // bits))
                for limb in range(limbs):
                    value_slot, wrote_slot = ((0, 1) if position == 0
                                              else (2 + 2 * position,
                                                    3 + 2 * position))
                    name = f"o{i}_w{position}"
                    lines.append(f"  %{name}_val = load {ty}, {ty}* %eff{value_slot}")
                    lines.append(f"  %{name}_wrote = load {ty}, {ty}* %eff{wrote_slot}")
                    lines.append(f"  %{name}_did = icmp ne {ty} %{name}_wrote, 0")
                    write_register(values[dest], kinds.get(dest, "reg"), bits,
                                   name, f"%{name}_val", lines,
                                   guard=f"%{name}_did", placement=placement,
                                   slot=base + limb,
                                   zero_slots=() if limbs > 1 else zeroed_limbs(
                                       kinds.get(dest, "reg"), base, lift),
                                   lift=lift)
                    position += 1
                continue
            # A trap aborts the block, reporting the pc and step count so far.
            lines.append(f"  %o{i}_trapped = icmp ne {ty} %o{i}_trap, 0")
            lines.append(f"  br i1 %o{i}_trapped, label %trap{i}, label %cont{i}")
            lines.append(f"trap{i}:")
            lines.append(f"  store {ty} %o{i}_next, {ty}* %status_pc")
            lines.append(f"  store {ty} %o{i}_trap, {ty}* %status_trap")
            lines.append(f"  store {ty} {i + 1}, {ty}* %status_steps")
            lines.append("  ret void")
            lines.append(f"cont{i}:")
            pc = f"%o{i}_next"
            continue

        # A handler is emitted at its own width, so a 64-bit block calling a
        # 32-bit one has to narrow the arguments and widen the result rather
        # than call through a mismatched type.
        call_bits = signature_bits(sem_ll, f"axis_eval_{ident}", effect=False)
        if call_bits == bits:
            lines.append(
                f"  %o{i}_r = call {ty} @axis_eval_{ident}({', '.join(args)})")
        else:
            narrow = []
            for k, argument in enumerate(args):
                value = argument.split(" ", 1)[1]
                if value.lstrip("-").isdigit():
                    narrow.append(f"i{call_bits} {int(value) & ((1 << call_bits) - 1)}")
                    continue
                temp = f"%o{i}_n{k}"
                lines.append(f"  {temp} = trunc {ty} {value} to i{call_bits}")
                narrow.append(f"i{call_bits} {temp}")
            lines.append(
                f"  %o{i}_rn = call i{call_bits} @axis_eval_{ident}({', '.join(narrow)})")
            lines.append(f"  %o{i}_r = zext i{call_bits} %o{i}_rn to {ty}")
        # `inout` is a destination too: a predicated add reads its destination
        # (the lanes it does not write keep what was there) and writes it.
        out_op = next((op for op in entry["operands"]
                       if op["role"] in ("out", "inout")
                       and lift.is_register_operand(op["kind"])), None)
        if out_op is not None:
            out_slot = file_slot(out_op["kind"], values[out_op["name"]], lift)
            write_register(values[out_op["name"]], out_op["kind"], bits, f"o{i}",
                           f"%o{i}_r", lines, placement=placement_of(out_op, lift),
                           slot=out_slot,
                           zero_slots=zeroed_limbs(out_op["kind"], out_slot, lift),
                           lift=lift)
        lines.append(f"  %o{i}_next = add {ty} {pc}, 4")
        pc = f"%o{i}_next"
    lines.append(f"  store {ty} {pc}, {ty}* %status_pc")
    lines.append(f"  store {ty} 0, {ty}* %status_trap")
    lines.append(f"  store {ty} {len(program)}, {ty}* %status_steps")
    lines.append("  ret void")
    lines.append("}")
    return "\n".join(lines)


class Jit:
    """MCJIT engine factory + block cache. Keeps engines alive."""

    def __init__(self, sem_ll: str, lift, bits: int = 32, reg_count: int = REG_COUNT):
        import llvmlite.binding as llvm
        self.llvm = llvm
        llvm.initialize()
        llvm.initialize_native_target()
        llvm.initialize_native_asmprinter()
        self.target = llvm.Target.from_default_triple()
        self.sem_ll = sem_ll
        self.lift = lift
        self.bits = bits
        # A scalable register spans several slots, so the file a block needs is
        # a property of the document rather than the 32 an integer ISA has.
        self.reg_count = reg_count
        self.word = ctypes.c_uint64 if bits == 64 else ctypes.c_uint32
        self.cache = {}          # words-tuple -> (tm, engine, cfunc)
        self.compiles = 0
        self.runs = 0

    def _compile(self, program):
        # A fresh target machine per engine: each block's module redefines the
        # same axis_eval_* symbols, so they must not share one machine's state.
        tm = self.target.create_target_machine()
        mod = self.llvm.parse_assembly(
            self.sem_ll + "\n" + block_ir(program, self.sem_ll, self.lift, self.bits))
        mod.verify()
        engine = self.llvm.create_mcjit_compiler(mod, tm)
        engine.finalize_object()
        addr = engine.get_function_address("axis_jit_block")
        cfunc = ctypes.CFUNCTYPE(
            None,
            ctypes.POINTER(self.word),
            ctypes.POINTER(ctypes.c_uint8),
            self.word,
            ctypes.POINTER(self.word),
            ctypes.POINTER(self.word),
        )(addr)
        self.compiles += 1
        return tm, engine, cfunc

    def run(self, program, init_regs, mem_image=b"", init_pc=0, init_state=()):
        key = tuple(w for _, _, w in program)
        hit = key in self.cache
        if not hit:
            self.cache[key] = self._compile(program)
        _tm, _engine, cfunc = self.cache[key]
        regs = (self.word * self.reg_count)(*init_regs)
        memory = (ctypes.c_uint8 * max(len(mem_image), 1))(*mem_image) \
            if mem_image else (ctypes.c_uint8 * 1)()
        status = (self.word * 3)()
        state = (self.word * max(len(init_state), 1))(*init_state) \
            if init_state else (self.word * 1)()
        cfunc(regs, memory, init_pc, status, state)
        self.runs += 1
        return {
            "regs": list(regs),
            "mem": bytes(memory) if mem_image else b"",
            "pc": status[0],
            "trap": status[1],
            "steps": status[2],
            "state": list(state)[:len(init_state)],
        }, hit


def gen_effect_program(entries, length, rng, axis_lift, require=None):
    """`ef.gen_program` with bounded immediates: a full-width random offset
    would compute an address outside the JIT's byte buffer, and the address is
    formed inside the proven effect handler where it cannot be masked.

    Operand values are canonicalized by decoding the word we just encoded. A
    scattered field need not cover every bit — a B-type branch immediate drops
    bit 0 — so the chosen value and the value the instruction actually encodes
    can differ, and the JIT must bake in what the word says. The reference
    executor decodes the word, so anything else compares two different programs.
    """
    program = []
    for step in range(length):
        # `require` puts one instruction in deliberately. The rest of a block
        # is random, but which *classes* of effect ever get compiled should not
        # be: see where the pool is built.
        entry = require if (require is not None and step == 0) else rng.choice(entries)
        values = {}
        reg_ops = [op for op in entry["operands"]
                   if axis_lift.is_register_operand(op["kind"])]
        for op in entry["operands"]:
            if axis_lift.is_register_operand(op["kind"]):
                values[op["name"]] = rng.randrange(REG_COUNT)
            else:
                width = max(w for _, _, w in op["fields"])
                limit = min(1 << width, EFFECT_IMM_LIMIT)
                values[op["name"]] = rng.randrange(limit)
        # Alias the sources sometimes so equality guards fire both ways.
        if len(reg_ops) >= 2 and rng.random() < 0.34:
            values[reg_ops[1]["name"]] = values[reg_ops[0]["name"]]
        # Redraw the immediates until the word is one the architecture defines.
        for _attempt in range(16):
            if decodes_back(entry, values, axis_lift):
                break
            for op in entry["operands"]:
                if axis_lift.is_register_operand(op["kind"]):
                    continue
                width = max(w for _, _, w in op["fields"])
                values[op["name"]] = rng.randrange(min(1 << width, EFFECT_IMM_LIMIT))
        word = ef.encode(entry, values)
        lifted = axis_lift.lift(word)
        if lifted is not None:
            # Merge rather than replace: an operand the lifter cannot decode
            # comes back as None, and dropping it entirely leaves the block
            # builder without a value for an operand the instruction still has.
            values.update({name: value for name, value
                           in lifted["operands"].items() if value is not None})
        program.append((entry, values, word))
    return program


def decodes_back(entry, values, axis_lift):
    """Whether the word these operand values encode decodes to this instruction.

    Random field values can spell a reserved encoding — AArch64's shifted
    register forms leave `shift = 3` undefined — and the reference executor
    refuses those, while a block calls the handler directly. Comparing the two
    on a word the architecture does not define compares an implementation
    against nothing, so those draws are retried instead.
    """
    word = ef.encode(entry, values)
    decoded = axis_lift.decode(word, entry.get("isa"))
    return decoded is not None and decoded["mnemonic"] == entry["mnemonic"]


def python_trace(program, init_regs, mem_image, init_pc, axis_exec,
                 bits=32, state_slots=(), init_state=(), slots=REG_COUNT,
                 sp_slot=None):
    """Reference for an effectful block: the Python executor, itself proven
    equal to the golden model, driven over the byte-addressed memory the
    generated IR uses. Returns None if an address escaped the buffer."""
    mask = (1 << bits) - 1
    memory = ByteMemory(mem_image)
    # On a 64-bit ISA the last slot of the flat register file is the stack
    # pointer, which the executor addresses by name rather than by index --
    # AArch64's encoding 31 means SP or the zero register depending on the
    # operand class. A 32-bit corpus has no such convention and the slot is an
    # ordinary register.
    # One past the register file, matching `file_slot`: the stack pointer is
    # named state, not a numbered register, and giving it a slot the classes
    # also number made `reg[31]` and `sp` the same storage on one side only.
    # A corpus with no aliasing class has no such slot and passes None.
    reserved = sp_slot
    regs = {index: value for index, value in enumerate(init_regs)
            if index != reserved}
    if reserved is not None:
        regs["sp"] = init_regs[reserved]
    state = {name: value for (name, _), value in zip(state_slots, init_state)}
    pc = init_pc
    trap = 0
    steps = 0
    for entry, _values, word in program:
        # The ISA has to be passed: this corpus describes a source and a target
        # encoding space, and the same word decodes to different instructions in
        # each. Without it the reference silently executes something else.
        out = axis_exec.step(word, regs, mem=memory, pc=pc, state=state,
                             isa=entry.get("isa"))
        steps += 1
        if memory.escaped:
            return None
        pc = out["next_pc"] if out else (pc + 4) & mask
        if out and out.get("trap"):
            trap = TRAP_CAUSES.index(out["trap"]) + 1
            break
    # The whole register file, not the general-purpose part of it. A class
    # with a file of its own sits above the others in the flat array --
    # `a64_vreg64` starts at 32 -- so comparing only the first 32 slots would
    # say nothing about what a SIMD&FP load wrote.
    final = [regs.get(index, 0) & mask
             for index in range(slots + (1 if reserved is not None else 0))]
    if reserved is not None:
        final[reserved] = regs.get("sp", 0) & mask
    return {
        "regs": final,
        "mem": bytes(memory.data),
        "pc": pc & mask,
        "trap": trap,
        "steps": steps,
        "state": [state.get(name, 0) & mask for name, _ in state_slots],
    }


def golden_regs(program, init_regs, golden, lift, bits=32):
    """Reference: run the pure block through the golden model.

    Applies the same register conventions the block compiles in — a W-form read
    exposes the low 32 bits of the shared X register, a write to the zero
    register is discarded — because the two have to agree on what a register
    holds, not only on what the semantics compute.
    """
    mask = (1 << bits) - 1
    regs = list(init_regs)
    for entry, values, _word in program:
        args = []
        for op in entry["operands"]:
            # `inout` counts as an input: AArch64 MOVK reads the register it
            # writes, and the golden model takes it as a positional argument.
            if op["role"] == "out":
                continue
            v = values[op["name"]]
            if not lift.is_register_operand(op["kind"]):
                args.append(v)
                continue
            if hardwired_zero(op["kind"], v, lift):
                args.append(0)
                continue
            value = regs[file_slot(op["kind"], v, lift)]
            if op["kind"] != "reg" and register_kind_width(op["kind"]) == 32:
                value &= 0xffffffff
            args.append(value)
        result = golden.evaluate(entry["mnemonic"], *args)
        # `inout` is a destination as well as an input -- AArch64's MOVK reads
        # the register it writes. Taking only "out" here meant the reference
        # never wrote it, and the block never wrote it either, so the gate
        # agreed about doing nothing. It writes it now, so this must too.
        out = next((op for op in entry["operands"]
                    if op["role"] in ("out", "inout")
                    and lift.is_register_operand(op["kind"])), None)
        if out is None:
            continue
        dst, kind = values[out["name"]], out["kind"]
        if hardwired_zero(kind, dst, lift):
            continue
        width = 32 if (kind != "reg" and register_kind_width(kind) == 32) else bits
        slot = file_slot(kind, dst, lift)
        regs[slot] = result & ((1 << width) - 1) & mask
        # The class's write policy is part of what a register holds, not a
        # detail of the semantics: writing `d1` zeroes the upper half of `v1`.
        # The executor has always applied it; this reference committed the one
        # slot the value landed in and left the rest of the register alone, so
        # the two disagreed about every D-form write into a dirty V register.
        for other in zeroed_limbs(kind, slot, lift):
            if other < len(regs):
                regs[other] = 0
    return regs


def bind_values(entry, word, lift):
    """Operand values for one entry of `word`, derivations included.

    A lane operand consumes no bits of its own: its register comes from the
    selector it derives from, plus the register its element sits in.
    """
    values = {}
    for operand in entry["operands"]:
        fields = operand["fields"]
        values[operand["name"]] = lift._extract(word, fields) if fields else operand.get("fixed")
    for operand in entry["operands"]:
        source = operand.get("derived_from")
        if source:
            values[operand["name"]] = values[source] + operand["derived_add"]
    return values


def place_registers(word, entry, rng, lift, slots, index_name=None):
    """The same word with fresh register numbers in its encoded selectors.

    A fixture picks one register per operand and every execution of it would
    read the same slots. Rewriting the selector fields exercises the placement
    -- a different register is a different pair of slots -- without re-deriving
    the encoding, since the fields say exactly which bits carry it.

    An index vector gets the last register and nothing else is allowed to have
    it. Otherwise an earlier instruction in the block writes the register a
    later gather indexes through, the gather reads whatever it wrote, and the
    address leaves the buffer -- which in compiled code is a segmentation
    fault, not a failed comparison. The driver seeds that register with
    offsets; a block that overwrites it is asking to read from nowhere.
    """
    # What each selector's file can hold. A selector carries no placement of
    # its own -- its lanes do -- and the files differ: predicates sit above the
    # vector registers at the same stride, so a number that fits one file runs
    # off the end of the other.
    placement_of_selector = {}
    for candidate in entry["operands"]:
        source = candidate.get("derived_from")
        if source and candidate.get("view_width"):
            placement_of_selector.setdefault(source, candidate)

    for operand in entry["operands"]:
        if operand["role"] not in ("enc", "out", "inout"):
            continue
        if not lift.is_register_operand(operand["kind"]):
            continue
        placement = placement_of_selector.get(operand["name"], operand)
        if placement.get("view_width"):
            room = (slots - placement["slot_base"]) // placement["stride"]
            room -= placement.get("register_bias", 0)
        else:
            room = slots - lift.REGISTER_CLASSES[operand["kind"]][3]
        reserved = max(room - 1, 0)
        is_index = index_name is not None and operand["name"] == index_name
        for insn_lo, op_lo, width in operand["fields"]:
            limit = min(max(reserved, 1), 1 << width)
            number = min(reserved, (1 << width) - 1) if is_index else rng.randrange(limit)
            cover = ((1 << width) - 1) << insn_lo
            word = (word & ~cover) | (((number >> op_lo) & ((1 << width) - 1)) << insn_lo)
    return word


def scalable_program(fixtures, sem_ll, rng, lift, length, slots):
    """A block of scalable words, expanded to the lanes they encode.

    Every lane of one word shares that word, so the block is `VL/elem` handler
    calls per instruction -- each an ordinary scalar operation against an
    element-sized view. Words whose lanes are effectful, have no LLVM handler,
    or would place an element across a slot boundary are left out: the block
    lowering reads one slot per element, and emitting IR for a case no corpus
    exercises would be worse than not having it.
    """
    usable = []
    for fixture in fixtures:
        word = int(fixture["encoded"], 16)
        lanes = lift.decode_lanes(word, fixture.get("isa"))
        if len(lanes) <= 1 or not lanes[0].get("scalable_origin"):
            continue
        effectful = any(entry.get("effects") for entry in lanes)
        if effectful:
            # A vector load or store: each lane calls the proven `axis_eff_*`
            # handler, which does its own access against the block's memory.
            if any(f"@axis_eff_{pyident(entry['mnemonic'])}(" not in sem_ll
                   for entry in lanes):
                continue
            # Only forms whose addressing is stated, because the driver has to
            # seed the registers those addresses come from -- a gather with a
            # random index vector reaches a random address, which in compiled
            # code is a fault rather than a failed comparison.
            origin = lanes[0]["scalable_origin"]
            if origin not in ADDRESSING and origin not in SEGMENTS:
                continue
        else:
            if any(entry["semantics"] is None for entry in lanes):
                continue
            if any(f"@axis_eval_{pyident(entry['mnemonic'])}(" not in sem_ll
                   for entry in lanes):
                continue
        straddles = any(
            operand["view_offset"] % 64 + operand["view_width"] > 64
            for entry in lanes for operand in entry["operands"]
            if operand.get("view_width")
        )
        if straddles:
            continue
        # A register number has to leave room for every register the lanes
        # reach: at LMUL > 1 the last lane is in a later register.
        bias = max((operand.get("register_bias", 0) for entry in lanes
                    for operand in entry["operands"]), default=0)
        stride = next((operand["stride"] for entry in lanes
                       for operand in entry["operands"]
                       if operand.get("view_width")), 1)
        room = slots // stride - bias
        if room > 0:
            kinds = {effect["kind"] for entry in lanes
                     for effect in entry.get("effects") or []}
            direction = ("load" if kinds == {"set"} else
                         "store" if kinds == {"store"} else
                         "pure" if not kinds else "other")
            origin = lanes[0]["scalable_origin"]
            mode = ("none" if direction == "pure" else
                    "segment" if origin in SEGMENTS else
                    (ADDRESSING.get(origin) or ("none",))[0])
            usable.append((fixture, lanes, room, f"{mode} {direction}"))
    if not usable:
        return [], 0, []

    # Each block gets one word of every shape the corpus offers -- unit load,
    # strided load, indexed store, and so on -- then a random tail. Sampling
    # alone leaves coverage to luck: a run whose memory words all happened to
    # be stores reported a green load path it never compiled, measured on the
    # RVV corpus with the load's placement deliberately broken. The same
    # argument applies one level down, to the addressing modes.
    required = []
    for shape in sorted({item[3] for item in usable}):
        candidates = [item for item in usable if item[3] == shape]
        required.append(candidates[rng.randrange(len(candidates))])
    program, words = [], []
    for position in range(max(length, len(required))):
        if position < len(required):
            fixture, lanes, room, _shape = required[position]
        else:
            fixture, lanes, room, _shape = usable[rng.randrange(len(usable))]
        origin = lanes[0]["scalable_origin"]
        mode = ADDRESSING.get(origin)
        index_name = mode[3] if mode and mode[0] == "indexed" else None
        word = place_registers(int(fixture["encoded"], 16), lanes[0], rng, lift,
                               slots, index_name)
        # Rewriting the selectors must not have changed which instruction this
        # is; if it did, the fields overlap the opcode and the corpus is at
        # fault rather than the driver.
        again = lift.decode_lanes(word, fixture.get("isa"))
        if len(again) != len(lanes) or again[0]["mnemonic"] != lanes[0]["mnemonic"]:
            continue
        words.append((word, fixture.get("isa")))
        for entry in again:
            program.append((entry, bind_values(entry, word, lift), word))
    return program, len(usable), words


def scalable_reference(words, init_regs, axis_exec, slots, image=b"",
                       state=None, sp_slot=None):
    """The register file and memory after those words, from the S3 executor.

    Not a second implementation of element placement: the point of this gate is
    that the *compiled block* agrees with the executor, and the executor agrees
    with a whole-register model that has neither views nor limbs.
    """
    # The stack pointer's slot is the executor's `sp`, not an index -- the same
    # split `python_trace` makes, for the same reason.
    regs = {index: value for index, value in enumerate(init_regs)
            if index != sp_slot}
    if sp_slot is not None:
        regs["sp"] = init_regs[sp_slot]
    memory = ByteMemory(image) if image else None
    live = dict(state or {})
    for word, isa in words:
        axis_exec.step(word, regs, mem=memory, isa=isa, state=live)
        if memory is not None and memory.escaped:
            return None
    final = [regs.get(index, 0)
             for index in range(slots + (1 if sp_slot is not None else 0))]
    if sp_slot is not None:
        final[sp_slot] = regs.get("sp", 0)
    return (final, bytes(memory.data) if memory is not None else b"", live)


def seed_addresses(program, init_regs, lift, rng, limit):
    """Make every address a memory block computes land inside its buffer.

    Register values are otherwise random 64-bit numbers, and each addressing
    mode turns a different one of them into an address:

        unit      the base register, and nothing else
        strided   the base, and a step small enough that the last lane fits
        indexed   the base, and every element of an index *vector*
        segment   the base

    A driver that seeded only the base would still gather from a random
    address, and a random address in compiled code is a fault rather than a
    failed comparison. The modes come from the addressing statement rather than
    from a second list here.
    """
    regs = list(init_regs)
    for entry, values, _word in program:
        origin = entry.get("scalable_origin")
        if not entry.get("effects"):
            continue
        segment = SEGMENTS.get(origin)
        mode = ADDRESSING.get(origin)
        if segment is not None:
            base_name, step_name, kind = segment[2], None, "segment"
        elif mode is not None:
            kind, _bytes, base_name, step_name = mode
        else:
            continue
        lanes = max((operand.get("lane", 0) for operand in entry["operands"]), default=0) + 1
        for operand in entry["operands"]:
            name = operand["name"]
            base = operand.get("derived_from") or name
            if not lift.is_register_operand(operand["kind"]):
                continue
            if base == base_name:
                # Clear of the buffer's start too: SVE's [Xn, #imm, MUL VL]
                # reaches up to eight vector lengths BELOW the base (LD2, two
                # registers' worth each), and an address before the buffer is
                # zero to the executor and whatever lies there to compiled code
                # -- a disagreement that came and went with the heap.
                margin = min(limit // 4, 1024)
                slot = lift.register_slot(operand["kind"], values[name])
                if slot < len(regs):
                    regs[slot] = (margin + rng.randrange(limit // 2 - margin)) & ~7
            elif kind == "offset" and base == step_name:
                # A scaled scalar offset (SVE's LDFF1 [Xn, Xm, LSL #s]): small,
                # so the base's half of the buffer still holds every lane.
                slot = lift.register_slot(operand["kind"], values[name])
                if slot < len(regs):
                    regs[slot] = rng.randrange(8)
            elif step_name is not None and base == step_name:
                # The base already sits anywhere in the first half, so what is
                # left for the *last* lane is the other half divided by the
                # lanes ahead of it. A step drawn from the whole buffer puts
                # lane 3 past the end -- where the executor's bounds check
                # returns zero and compiled code reads whatever is there, which
                # is exactly the disagreement that found this.
                room = max(8, (limit // 2) // max(lanes - 1, 1))
                if operand.get("view_width"):
                    # An index vector: every element is an offset, so every
                    # element has to be one that stays inside the buffer.
                    number = values[base] + operand.get("register_bias", 0)
                    slot = (operand["slot_base"]
                            + number * operand["stride"]
                            + operand["view_offset"] // 64)
                    shift = operand["view_offset"] % 64
                    width = operand["view_width"]
                    if slot < len(regs):
                        cover = ((1 << width) - 1) << shift
                        # An index is an offset from the base, not a step, so
                        # it is bounded by what is left rather than by what is
                        # left divided by the lanes.
                        offset = rng.randrange(max(8, limit // 2)) & ~7
                        regs[slot] = (regs[slot] & ~cover) | (
                            (offset & ((1 << width) - 1)) << shift)
                else:
                    slot = lift.register_slot(operand["kind"], values[name])
                    if slot < len(regs):
                        regs[slot] = max(8, rng.randrange(room) & ~7)
    return regs


def run_scalable(args, workdir, sem_ll, axis_lift, axis_exec, rng) -> int:
    """Compile and run blocks of scalable words, against the S3 executor."""
    import json

    slots = axis_lift.REGISTER_FILE_SLOTS
    # A vector access needs somewhere to land, and a scalar register holding a
    # random 64-bit number does not point at it.
    image = bytes(rng.getrandbits(8) for _ in range(EFFECT_MEM_BYTES))
    # Architectural state the corpus reads. A fault-first load asks whether an
    # address is accessible, and the answer is a pair of state slots -- so the
    # whole buffer is declared accessible rather than leaving them zero, which
    # would make every lane past the first suppress.
    state_names = [name for name, _width in axis_lift.STATE_SLOTS]
    init_state = tuple(
        (EFFECT_MEM_BYTES if name.endswith("_hi") else 0) for name in state_names)
    state_map = dict(zip(state_names, init_state))
    fixtures = json.loads((workdir / "fixtures.json").read_text())["tests"]
    pool = []
    usable = 0
    for _ in range(args.distinct):
        program, usable, words = scalable_program(
            fixtures, sem_ll, rng, axis_lift, args.length, slots)
        if program:
            pool.append((program, words))
    if not pool:
        print(f"SKIP: no scalable word this block lowering can compile "
              f"({len(fixtures)} fixtures)")
        return 0

    lanes_per_block = sum(len(program) for program, _ in pool) / len(pool)
    print(f"JIT backend: llvmlite MCJIT (in-process); {usable} scalable word(s), "
          f"{lanes_per_block:.0f} lane call(s) per block, {slots} register slots")
    extra = 1 if aliases_state(axis_lift) else 0
    jit = Jit(sem_ll, axis_lift, 64, reg_count=slots + extra)
    failures = 0
    memory_blocks = 0
    escaped = 0
    directions = {effect["kind"] for program, _ in pool
                  for entry, _, _ in program
                  for effect in entry.get("effects") or []}
    # What the run actually compiled, not what the corpus contains. The
    # difference is the whole lesson of the sampled-coverage bug: a gate that
    # reports a verdict without reporting its coverage is green about whatever
    # it happened to pick.
    compiled_modes = set()
    for program, _ in pool:
        for entry, _, _ in program:
            origin = entry.get("scalable_origin")
            if not entry.get("effects") or not origin:
                continue
            compiled_modes.add("segment" if origin in SEGMENTS
                               else (ADDRESSING.get(origin) or ("none",))[0])
    for n in range(args.programs):
        program, words = pool[rng.randrange(len(pool))]
        touches_memory = any(entry.get("effects") for entry, _, _ in program)
        init_regs = [rng.getrandbits(64) for _ in range(slots + extra)]
        if touches_memory:
            init_regs = seed_addresses(program, init_regs, axis_lift, rng,
                                       EFFECT_MEM_BYTES - (slots * 8))
            memory_blocks += 1
        # The reference first: a block whose accesses leave the buffer is not
        # run as compiled code at all. Two words can want one register for
        # different jobs -- X6 LD2's base and LDFF1's offset -- and seeding
        # cannot satisfy both; LDFF1's first active element is then read at an
        # address outside the buffer, which the executor reports and compiled
        # code would simply dereference.
        reference = scalable_reference(
            words, init_regs, axis_exec, slots,
            image if touches_memory else b"", state_map,
            sp_slot=slots if extra else None)
        if reference is None:
            escaped += 1
            continue
        want, want_mem, want_state = reference
        result, _hit = jit.run(program, init_regs,
                               mem_image=image if touches_memory else b"",
                               init_state=init_state)
        got = result["regs"]
        if got != want:
            failures += 1
            bad = [i for i in range(slots) if got[i] != want[i]]
            print(f"FAIL exec #{n}: slots differ at {bad[:6]}")
            for i in bad[:4]:
                print(f"    slot {i}: jit {got[i]:#018x} != executor {want[i]:#018x}")
            # Which words, in order: a slot number alone does not say which
            # instruction wrote it.
            origins = []
            for entry, _, _ in program:
                origin = entry.get("scalable_origin") or entry["mnemonic"]
                if not origins or origins[-1] != origin:
                    origins.append(origin)
            print(f"    block: {' '.join(origins)}")
            shown = set()
            for entry, values, _ in program:
                origin = entry.get("scalable_origin") or entry["mnemonic"]
                if origin not in shown:
                    shown.add(origin)
                    named = {k: v for k, v in values.items() if "__l" not in k}
                    print(f"    {origin}: {named}")
            if failures > 4:
                break
        got_state = dict(zip(state_names, result["state"]))
        if got_state != {name: want_state.get(name, 0) & ((1 << width) - 1)
                         for name, width in axis_lift.STATE_SLOTS}:
            failures += 1
            print(f"FAIL exec #{n}: state {got_state} != {want_state}")
            if failures > 4:
                break
        if touches_memory and result["mem"] != want_mem:
            failures += 1
            where = next(i for i in range(len(want_mem))
                         if result["mem"][i] != want_mem[i])
            print(f"FAIL exec #{n}: memory at {where:#x}: "
                  f"jit {result['mem'][where]:#04x} != executor {want_mem[where]:#04x}")
            if failures > 4:
                break
    print(f"{args.programs} scalable block executions ({memory_blocks} against "
          f"memory: {'+'.join(sorted(directions)) or 'none'}), {failures} failures, "
          f"{jit.compiles} compile(s), {jit.runs - jit.compiles} cache hit(s)")
    print(f"  addressing compiled: {', '.join(sorted(compiled_modes)) or 'none'}")
    if escaped:
        print(f"  {escaped} block(s) not compared: an access left the buffer")
    ok = failures == 0 and escaped < args.programs
    # A run that compiled only arithmetic would report a green data path it
    # never exercised: no load, no store, nothing written to the buffer.
    if not memory_blocks:
        print("no block touched memory: the vector data path is untested")
        ok = False
    elif directions != {"set", "store"}:
        print(f"blocks cover {sorted(directions)}: both directions have to run")
        ok = False
    print("scalable JIT block == executor: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "zbb_like.axisl")
    parser.add_argument("--distinct", type=int, default=24,
                        help="distinct block shapes in the pool")
    parser.add_argument("--programs", type=int, default=300,
                        help="executions (sampled from the pool -> cache hits)")
    parser.add_argument("--length", type=int, default=12)
    parser.add_argument("--seed", type=lambda s: int(s, 0), default=0x11713)
    parser.add_argument("--scalable", action="store_true",
                        help="compile blocks of scalable words, lane by lane")
    args = parser.parse_args()

    try:
        import llvmlite  # noqa: F401
    except ImportError:
        print("SKIP: llvmlite not installed (pip install llvmlite)")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="axis_jitllvm_"))
    if args.scalable:
        ef.emit(args.axis_file, "emit-roundtrip-json", workdir / "fixtures.json")
    ef.emit(args.axis_file, "emit-llvm-ir", workdir / "axis_semantics.ll")
    ef.emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    ef.emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    ef.emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    sem_ll = (workdir / "axis_semantics.ll").read_text()

    sys.path.insert(0, str(workdir))
    axis_lift = importlib.import_module("axis_lift")
    golden = importlib.import_module("golden_model")
    axis_exec = importlib.import_module("axis_exec")

    if args.scalable:
        return run_scalable(args, workdir, sem_ll, axis_lift, axis_exec,
                            random.Random(args.seed))

    # Pure, encodable instructions with an LLVM handler in the .ll.
    #
    # ⚠️ And an evaluation width this block ABI can carry. A block's register
    # file, pc and status are one machine word, 32 or 64, so a handler emitted
    # at 128 bits has a signature the block cannot call. `signature_bits` reads
    # the width off the definition and answers 32 or 64, so it reported 32 for
    # an `i128` handler and the block called `axis_eval_orr_v` with four i32
    # arguments; LLVM refused the module, which is the good outcome -- the
    # alternative was passing half a vector and believing the answer.
    entries = [
        e for e in axis_lift.AXIS_LIFT_TABLE
        if e["semantics"] is not None
        and f"@axis_eval_{pyident(e['mnemonic'])}(" in sem_ll
        and f"define i128 @axis_eval_{pyident(e['mnemonic'])}(" not in sem_ll
        and all(op["fields"] for op in e["operands"] if op["kind"] in ("reg", "imm"))
    ]
    print(f"JIT backend: llvmlite MCJIT (in-process); {len(entries)} pure instruction(s)"
          + (f": {', '.join(sorted(e['mnemonic'] for e in entries))}" if entries else ""))

    # One evaluation width for the block, taken from the ISA the corpus
    # describes: a 64-bit ISA needs a 64-bit register file, pc and status.
    block_bits = 64 if any(e.get("state_width", 32) > 32
                           for e in axis_lift.AXIS_LIFT_TABLE) else 32
    rng = random.Random(args.seed)
    pool = [ef.gen_program(entries, args.length, rng, axis_lift)
            for _ in range(args.distinct)] if entries else []
    # What the pool actually contains, against what the corpus offers. A gate
    # that samples reports how *much* it ran; this is what it ran, and the
    # difference is where a whole instruction class can go missing unnoticed.
    pooled = {entry["mnemonic"] for program in pool for entry, _v, _w in program}
    available = {entry["mnemonic"] for entry in entries}
    if entries:
        missing = sorted(available - pooled)
        print(f"pure coverage: {len(pooled)}/{len(available)} instruction(s) "
              f"in the block pool"
              + (f"; never compiled: {', '.join(missing[:6])}"
                 f"{f' (+{len(missing) - 6} more)' if len(missing) > 6 else ''}"
                 if missing else ""))
    # Sized from the description, not from the general-purpose file. The
    # scalable path already did this; the effect path defaulted to 32, so the
    # first instruction to write a second register file -- AArch64's `ldp d1,
    # d2` at slots 33 and 34 -- wrote past the end of a 32-element array and
    # corrupted unrelated general-purpose registers. The failure looked like
    # arithmetic disagreeing, which is the least useful place to start looking.
    effect_slots = axis_lift.REGISTER_FILE_SLOTS
    extra = 1 if aliases_state(axis_lift) else 0
    jit = Jit(sem_ll, axis_lift, block_bits, reg_count=effect_slots + extra)
    failures = 0
    for n in range(args.programs if pool else 0):
        program = pool[rng.randrange(len(pool))]
        init_regs = [rng.getrandbits(block_bits) for _ in range(effect_slots + extra)]
        result, _hit = jit.run(program, init_regs)
        got = result["regs"]
        want = golden_regs(program, init_regs, golden, axis_lift, block_bits)
        if got != want:
            failures += 1
            bad = [i for i in range(min(len(got), len(want)))
                   if got[i] != want[i]] or ["length"]
            print(f"FAIL exec #{n}: regs differ at {bad}")
            for i in bad[:4]:
                print(f"    r{i}: jit {got[i]:#010x} != golden {want[i]:#010x}")
            if failures >= 3:
                print("... stopping after 3 failures")
                return 1

    # Effectful blocks: the same JIT, now calling the proven axis_eff_*
    # handlers, checked against the Python executor over a shared byte memory.
    # Every register write a handler reports is committed, so multi-write forms
    # (AArch64's indexed loads, ldp/stp) run here rather than being filtered.
    # What a block still cannot carry is a write beyond the ABI's slots.
    def commitable(entry):
        return sum(1 for effect in entry["effects"]
                   if effect.get("kind") in ("set", "setreg")) <= axis_lift.EFFECT_MAX_WRITES

    effect_candidates = [
        e for e in axis_lift.AXIS_LIFT_TABLE
        if e.get("effects")
        and f"@axis_eff_{pyident(e['mnemonic'])}(" in sem_ll
        and all(op["fields"] for op in e["operands"]
                if axis_lift.is_register_operand(op["kind"]) or op["kind"] == "imm")
    ]
    # A handler whose evaluation width differs from the block's cannot be
    # called at all: its `out` and `state` arrays are that width, and a pointer
    # is not adaptable the way a scalar argument is.
    effect_candidates = [
        e for e in effect_candidates
        if signature_bits(sem_ll, f"axis_eff_{pyident(e['mnemonic'])}", effect=True)
        == block_bits
    ]
    # Atomic instructions are left out here, unlike in llvm_effects_check.
    # An atomic access must be naturally aligned or the hardware faults, and
    # that gate arranges aligned addresses because it drives one instruction at
    # a time with a known register value. A block computes its addresses from a
    # register file that earlier instructions have already modified, so the
    # alignment cannot be arranged up front -- an unaligned atomicrmw takes
    # SIGBUS and kills the process rather than reporting a mismatch. Their value
    # semantics are proven by that gate; this one proves block composition.
    atomics = [e for e in effect_candidates
               if any(x.get("atomic") for x in e["effects"])]
    effect_candidates = [e for e in effect_candidates if e not in atomics]
    if atomics:
        print(f"{len(atomics)} atomic instruction(s) left out: a block cannot "
              "guarantee the natural alignment they require")
    effect_entries = [e for e in effect_candidates if commitable(e)]
    multi = len(effect_candidates) - len(effect_entries)
    if multi:
        print(f"{multi} instruction(s) left out: more register writes than the "
              "effect ABI carries")
    effect_runs = effect_skipped = 0
    effect_covered: set[str] = set()
    uncovered_shapes: set = set()
    effect_pool = []
    if effect_entries:
        print(f"effect surface: {len(effect_entries)} instruction(s): "
              f"{', '.join(sorted(e['mnemonic'] for e in effect_entries))}")
        effect_pool = [gen_effect_program(effect_entries, args.length, rng, axis_lift)
                       for _ in range(args.distinct)]

        # Every effect class, deliberately. Which of forty instructions a run
        # picks does not matter; whether it ever compiled a store, a branch, a
        # trap or a guarded write does -- and leaving that to `rng.choice` made
        # it luck. Eight random blocks covered nine of eleven classes here and
        # sixteen covered ten, so the gate reported a hole in the lowering path
        # that was really a hole in the sample. Blocks that force each missing
        # class are appended rather than replacing the random ones, so the
        # random reach is unchanged and the classes are guaranteed.
        def shape(entry):
            kinds = tuple(sorted({e["kind"] for e in entry.get("effects") or []}))
            guarded = any("guard" in e for e in entry.get("effects") or [])
            writes = sum(1 for e in entry.get("effects") or []
                         if e["kind"] in ("set", "setreg"))
            return kinds + (("guarded",) if guarded else ()) + (
                ("multi-write",) if writes > 1 else ())

        drawn = {entry["mnemonic"] for program in effect_pool
                 for entry, _v, _w in program}
        for missing in sorted({shape(e) for e in effect_entries}
                              - {shape(e) for e in effect_entries
                                 if e["mnemonic"] in drawn}):
            required = next(e for e in effect_entries if shape(e) == missing)
            effect_pool.append(gen_effect_program(effect_entries, args.length,
                                                  rng, axis_lift, require=required))
        effect_covered = {entry["mnemonic"] for program in effect_pool
                          for entry, _v, _w in program}
        offered = {entry["mnemonic"] for entry in effect_entries}
        absent = sorted(offered - effect_covered)
        print(f"effect coverage: {len(effect_covered)}/{len(offered)} in the pool"
              + (f"; never compiled: {', '.join(absent[:6])}"
                 f"{f' (+{len(absent) - 6} more)' if len(absent) > 6 else ''}"
                 if absent else ""))
        offered_shapes = {shape(e) for e in effect_entries}
        covered_shapes = {shape(e) for e in effect_entries
                          if e["mnemonic"] in effect_covered}
        missing_shapes = offered_shapes - covered_shapes
        print(f"effect classes: {len(covered_shapes)}/{len(offered_shapes)} "
              f"compiled" + (f"; missing {sorted('+'.join(x) for x in missing_shapes)[:3]}"
                             if missing_shapes else ""))
        # Instruction coverage is reported and not required: at 413 effectful
        # instructions and a pool of eight blocks, a run compiles a fifth of
        # them, and forcing the rest through would cost minutes to prove what
        # `LLVM == golden` already proves for every one of them. What this gate
        # is about is the *block lowering*, and a class it never compiled is a
        # lowering path it never ran.
        uncovered_shapes = missing_shapes
        seed_image = bytes(rng.getrandbits(8) for _ in range(EFFECT_MEM_BYTES))
        for n in range(args.programs):
            program = effect_pool[rng.randrange(len(effect_pool))]
            init_regs = [rng.randrange(EFFECT_REG_LIMIT)
                         for _ in range(effect_slots + extra)]
            init_pc = rng.randrange(0, 1 << 16) & ~3
            init_state = [rng.randrange(1 << min(width, 32))
                          for _, width in axis_lift.STATE_SLOTS]
            want = python_trace(program, init_regs, seed_image, init_pc, axis_exec,
                                block_bits, axis_lift.STATE_SLOTS, init_state,
                                slots=effect_slots,
                                sp_slot=effect_slots if extra else None)
            if want is None:
                effect_skipped += 1
                continue
            got, _hit = jit.run(program, init_regs, seed_image, init_pc, init_state)
            effect_runs += 1
            fields = ("regs", "pc", "trap", "steps", "state")
            if any(got[field] != want[field] for field in fields) or got["mem"] != want["mem"]:
                failures += 1
                for field in fields:
                    if got[field] != want[field]:
                        print(f"FAIL effect exec #{n}: {field} "
                              f"jit {got[field]} != python {want[field]}")
                if got["mem"] != want["mem"]:
                    first = next(i for i in range(len(want["mem"]))
                                 if got["mem"][i] != want["mem"][i])
                    print(f"FAIL effect exec #{n}: mem[{first}] "
                          f"jit {got['mem'][first]} != python {want['mem'][first]}")
                if failures >= 3:
                    print("... stopping after 3 failures")
                    return 1

    hit_rate = 100 * (jit.runs - jit.compiles) // jit.runs if jit.runs else 0
    print(f"{jit.runs} executions of {len(pool) + len(effect_pool)} distinct blocks: "
          f"{jit.compiles} JIT compiles, {jit.runs - jit.compiles} cache hits "
          f"({hit_rate}% hit rate); {failures} divergences")
    if effect_entries:
        print(f"{effect_runs} effectful block executions "
              f"(registers + memory + pc + trap), {effect_skipped} skipped "
              "for addresses outside the buffer")
    ok = failures == 0
    if effect_entries and uncovered_shapes:
        print(f"  {len(uncovered_shapes)} effect class(es) never compiled: "
              f"the lowering path for them is untested")
        ok = False
    print("in-process LLVM JIT == golden: PASS" if ok else "in-process LLVM JIT == golden: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    _code = main()
    # llvmlite's MCJIT engines abort if torn down by the interpreter's exit-time
    # GC (ordering vs the shared global LLVM state). All real work is done and
    # printed by now, so flush and hard-exit past the destructor storm.
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_code)
