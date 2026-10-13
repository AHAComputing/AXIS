#!/usr/bin/env python3
"""Check AArch64 register, NZCV, and conditional-branch architectural behavior.

Proves register 31 as XZR/WZR versus SP, overlapping W/X register views, W-write
zero extension, flag-setting arithmetic, and all condition-code inputs used by
conditional control flow on real A64 encodings.

Usage: tools/aarch64_state_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import importlib
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def encode(entry: dict, **operands: int) -> int:
    word = entry["match"]
    for operand in entry["operands"]:
        if not operand["fields"]:
            continue
        value = operands[operand["name"]]
        for insn_lo, op_lo, width in operand["fields"]:
            mask = (1 << width) - 1
            word &= ~(mask << insn_lo)
            word |= ((value >> op_lo) & mask) << insn_lo
    return word


def signed_value(value: int, width: int) -> int:
    value &= (1 << width) - 1
    sign = 1 << (width - 1)
    return value - (1 << width) if value & sign else value


def condition_holds(nzcv: int, cond: int) -> bool:
    n, z, c, v = (
        bool(nzcv & 8),
        bool(nzcv & 4),
        bool(nzcv & 2),
        bool(nzcv & 1),
    )
    return (
        z,
        not z,
        c,
        not c,
        n,
        not n,
        v,
        not v,
        c and not z,
        (not c) or z,
        n == v,
        n != v,
        (not z) and n == v,
        z or n != v,
        True,
        True,
    )[cond]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "axis_file",
        nargs="?",
        type=Path,
        default=AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl",
    )
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_a64_state_"))
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    sys.path.insert(0, str(workdir))
    axis_lift = importlib.import_module("axis_lift")
    axis_exec = importlib.import_module("axis_exec")
    entries = {entry["mnemonic"]: entry for entry in axis_lift.AXIS_LIFT_TABLE}
    isa = "aarch64_base"
    failures = checks = 0

    class Memory:
        def __init__(self) -> None:
            self.cells: dict[tuple[int, int], int] = {}

        def read(self, addr: int, width: int) -> int:
            return self.cells.get((addr, width), 0)

        def write(self, addr: int, value: int, width: int) -> None:
            self.cells[(addr, width)] = value & ((1 << width) - 1)

    def check(label: str, condition: bool, detail: object) -> None:
        nonlocal failures, checks
        checks += 1
        if not condition:
            print(f"FAIL {label}: {detail}")
            failures += 1

    def shift_reg(value: int, shift: int, amount: int, width: int) -> int:
        mask = (1 << width) - 1
        value &= mask
        amount &= width - 1
        if shift == 0:
            return (value << amount) & mask
        if shift == 1:
            return value >> amount
        if shift == 2:
            signed = value - (1 << width) if value & (1 << (width - 1)) else value
            return (signed >> amount) & mask
        return value if amount == 0 else ((value >> amount) | (value << (width - amount))) & mask

    def extend_reg(value: int, option: int, amount: int, width: int) -> int:
        source_width = 8 << (option & 3)
        source_mask = (1 << source_width) - 1
        extended = value & source_mask
        if option & 4 and extended & (1 << (source_width - 1)):
            extended -= 1 << source_width
        return (extended << amount) & ((1 << width) - 1)

    # X31 is XZR for ADD (shifted register): reads zero and discards writes.
    entry = entries["ADD_X_SHIFT0"]
    word = encode(entry, rd=31, rn=31, rm=2, shift=0, imm6=0)
    regs = {2: 5}
    out = axis_exec.step(word, regs, isa=isa)
    check("XZR read", out["result"] == 5, out)
    check("XZR write discarded", 31 not in regs and out["writes"] == {}, (regs, out))

    # W reads the low half of X and writes a zero-extended 32-bit result.
    entry = entries["ADD_W_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm6=0)
    regs = {2: 0xFFFF_FFFF_0000_0001, 3: 0xAAAA_AAAA_0000_0002}
    out = axis_exec.step(word, regs, isa=isa)
    check("W/X overlap read", out["result"] == 3, out)
    check("W write zero extends", regs[1] == 3, regs)

    regs = {2: 0xFFFF_FFFF, 3: 1}
    out = axis_exec.step(word, regs, isa=isa)
    check("W arithmetic wraps", out["result"] == 0 and regs[1] == 0, (regs, out))

    entry = entries["SUB_W_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm6=0)
    regs = {2: 0, 3: 1}
    out = axis_exec.step(word, regs, isa=isa)
    check("SUB W wraps and zero extends", regs[1] == 0xFFFF_FFFF, (regs, out))

    entry = entries["ADD_X_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=1, imm6=4)
    regs = {2: 0x10, 3: 0x100}
    out = axis_exec.step(word, regs, isa=isa)
    check("ADD X shifted LSR", regs[1] == 0x20, (regs, out))

    entry = entries["SUB_W_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=2, imm6=31)
    regs = {2: 0, 3: 0x8000_0000}
    out = axis_exec.step(word, regs, isa=isa)
    check("SUB W shifted ASR", regs[1] == 1, (regs, out))

    entry = entries["ADD_X_SHIFT0"]
    reserved_shift = encode(entry, rd=1, rn=2, rm=3, shift=3, imm6=0)
    check(
        "ADD X reserved ROR decode",
        axis_lift.decode(reserved_shift, isa) is None,
        hex(reserved_shift),
    )
    entry = entries["ADD_W_SHIFT0"]
    reserved_amount = encode(entry, rd=1, rn=2, rm=3, shift=0, imm6=32)
    check(
        "ADD W oversized shift decode",
        axis_lift.decode(reserved_amount, isa) is None,
        hex(reserved_amount),
    )

    entry = entries["ADD_X_EXT"]
    for option in range(8):
        word = encode(entry, rd=1, rn=2, rm=3, option=option, imm3=4)
        regs = {2: 0, 3: 0xFEDC_BA98_7654_8081}
        out = axis_exec.step(word, regs, isa=isa)
        expected = extend_reg(regs[3], option, 4, 64)
        check(f"ADD X extension option {option}", regs[1] == expected, (regs, out))

    word = encode(entry, rd=31, rn=31, rm=2, option=0, imm3=4)
    regs = {"sp": 0x100, 2: 0xFF}
    out = axis_exec.step(word, regs, isa=isa)
    check("ADD X extended SP", regs["sp"] == 0x10F0, (regs, out))

    entry = entries["SUB_X_EXT"]
    word = encode(entry, rd=1, rn=2, rm=3, option=6, imm3=2)
    regs = {2: 5, 3: 0xFFFF_FFFF}
    out = axis_exec.step(word, regs, isa=isa)
    check("SUB X SXTW shifted", regs[1] == 9, (regs, out))

    entry = entries["ADD_W_EXT"]
    word = encode(entry, rd=1, rn=2, rm=3, option=3, imm3=1)
    regs = {2: 0, 3: 0x1_0000_0001}
    out = axis_exec.step(word, regs, isa=isa)
    check("ADD W UXTX zero extends", regs[1] == 2, (regs, out))

    entry = entries["ADDS_X_EXT"]
    word = encode(entry, rd=1, rn=2, rm=3, option=4, imm3=0)
    regs = {2: 0, 3: 0x80}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ADDS X SXTB flags",
        regs[1] == 0xFFFF_FFFF_FFFF_FF80 and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    entry = entries["SUBS_W_EXT"]
    word = encode(entry, rd=1, rn=2, rm=3, option=2, imm3=4)
    regs = {2: 0, 3: 1}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "SUBS W UXTW flags",
        regs[1] == 0xFFFF_FFF0 and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    entry = entries["ADD_X_EXT"]
    reserved_amount = encode(entry, rd=1, rn=2, rm=3, option=0, imm3=5)
    check(
        "ADD X extended oversized shift decode",
        axis_lift.decode(reserved_amount, isa) is None,
        hex(reserved_amount),
    )

    # The same encoded register number is SP in the immediate form.
    entry = entries["ADD_X_IMM_SP"]
    word = encode(entry, rd=31, rn=31, imm=7, sh=0)
    regs = {"sp": 10}
    out = axis_exec.step(word, regs, isa=isa)
    check("SP read/write", out["result"] == 17 and regs["sp"] == 17, (regs, out))
    check("SP write reported", out["writes"] == {"rd": 31}, out)

    word = encode(entry, rd=1, rn=2, imm=2, sh=1)
    regs = {2: 0x1234}
    out = axis_exec.step(word, regs, isa=isa)
    check("ADD X immediate shift 12", regs[1] == 0x3234, (regs, out))

    entry = entries["SUB_X_IMM_SP"]
    word = encode(entry, rd=31, rn=31, imm=1, sh=1)
    regs = {"sp": 0x5000}
    out = axis_exec.step(word, regs, isa=isa)
    check("SUB X immediate SP shift 12", regs["sp"] == 0x4000, (regs, out))

    entry = entries["ADD_W_IMM_SP"]
    word = encode(entry, rd=31, rn=31, imm=1, sh=1)
    regs = {"sp": 0xFFFF_F000}
    out = axis_exec.step(word, regs, isa=isa)
    check("ADD W immediate WSP wraps", regs["sp"] == 0, (regs, out))

    # The same instruction with bits above the view set in SP. W-SP is the low
    # 32 bits of the same register, so the upper half is not an input and does
    # not survive the write. Both halves of that were invisible while every SP
    # fixture held a value that already fitted in 32 bits: a read that skipped
    # the view mask returned the identical answer.
    regs = {"sp": 0xDEAD_BEEF_0000_0FFF}
    out = axis_exec.step(word, regs, isa=isa)
    check("ADD W immediate WSP ignores the upper half",
          regs["sp"] == 0x1FFF, (regs, out))

    entry = entries["SUB_W_IMM_SP"]
    word = encode(entry, rd=1, rn=2, imm=1, sh=1)
    regs = {2: 0x1000}
    out = axis_exec.step(word, regs, isa=isa)
    check("SUB W immediate shift 12", regs[1] == 0, (regs, out))

    entry = entries["ADDS_X_IMM"]
    word = encode(entry, rd=31, rn=2, imm=1, sh=0)
    regs = {2: 0xFFFF_FFFF_FFFF_FFFF}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "CMN X immediate alias",
        state["nzcv"] == 0b0110 and 31 not in regs and out["writes"] == {},
        (regs, state, out),
    )

    entry = entries["SUBS_X_IMM"]
    word = encode(entry, rd=31, rn=31, imm=1, sh=1)
    regs = {"sp": 0x1000}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "CMP SP immediate alias",
        state["nzcv"] == 0b0110 and regs["sp"] == 0x1000 and out["writes"] == {},
        (regs, state, out),
    )

    entry = entries["ADDS_W_IMM"]
    word = encode(entry, rd=1, rn=2, imm=1, sh=0)
    regs = {2: 0x7FFF_FFFF}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ADDS W immediate overflow",
        regs[1] == 0x8000_0000 and state["nzcv"] == 0b1001,
        (regs, state, out),
    )

    entry = entries["SUBS_W_IMM"]
    word = encode(entry, rd=1, rn=2, imm=1, sh=0)
    regs = {2: 0}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "SUBS W immediate borrow",
        regs[1] == 0xFFFF_FFFF and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    # ADDS produces architectural NZCV (N:Z:C:V in bits 3:0).
    entry = entries["ADDS_X_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm6=0)
    state: dict[str, int] = {}
    regs = {2: 0x7FFF_FFFF_FFFF_FFFF, 3: 1}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ADDS signed overflow",
        regs[1] == 0x8000_0000_0000_0000
        and state["nzcv"] == 0b1001
        and out["state_writes"] == {"nzcv": 0b1001},
        (regs, state, out),
    )

    state = {}
    regs = {2: 0xFFFF_FFFF_FFFF_FFFF, 3: 1}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ADDS zero and carry",
        regs[1] == 0 and state["nzcv"] == 0b0110,
        (regs, state, out),
    )

    # SUBS uses ARM's no-borrow carry rule; rd=31 is the CMP alias behavior.
    entry = entries["SUBS_X_SHIFT0"]
    word = encode(entry, rd=31, rn=2, rm=3, shift=0, imm6=0)
    state = {}
    regs = {2: 0, 3: 1}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "SUBS borrow and XZR discard",
        state["nzcv"] == 0b1000 and 31 not in regs and out["writes"] == {},
        (regs, state, out),
    )

    state = {}
    regs = {2: 0x8000_0000_0000_0000, 3: 1}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "SUBS signed overflow and no borrow",
        state["nzcv"] == 0b0011,
        (regs, state, out),
    )

    entry = entries["ADDS_W_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm6=0)
    state = {}
    regs = {2: 0xFFFF_FFFF, 3: 1}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ADDS W zero and carry",
        regs[1] == 0 and state["nzcv"] == 0b0110,
        (regs, state, out),
    )

    entry = entries["SUBS_W_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm6=0)
    state = {}
    regs = {2: 0x8000_0000, 3: 1}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "SUBS W signed overflow",
        regs[1] == 0x7FFF_FFFF and state["nzcv"] == 0b0011,
        (regs, state, out),
    )

    entry = entries["ADDS_X_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm6=63)
    regs = {2: 0, 3: 1}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ADDS X shifted flags",
        regs[1] == 0x8000_0000_0000_0000 and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    entry = entries["SUBS_W_SHIFT0"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=1, imm6=31)
    regs = {2: 0, 3: 0x8000_0000}
    state = {}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "SUBS W shifted flags",
        regs[1] == 0xFFFF_FFFF and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    # B.cond reads NZCV from architectural state. EQ is taken when Z=1; NE is
    # not taken for the same state. The immediate is scaled and sign-extended.
    entry = entries["B_COND"]
    eq_word = encode(entry, imm=3, cond=0)
    out = axis_exec.step(eq_word, {}, pc=0x1000, isa=isa, state={"nzcv": 0b0100})
    check("B.cond EQ taken", out["next_pc"] == 0x100C, out)

    ne_word = encode(entry, imm=3, cond=1)
    out = axis_exec.step(ne_word, {}, pc=0x1000, isa=isa, state={"nzcv": 0b0100})
    check("B.cond NE not taken", out["next_pc"] == 0x1004, out)

    back_word = encode(entry, imm=(1 << 19) - 1, cond=14)
    out = axis_exec.step(back_word, {}, pc=0x1000, isa=isa, state={"nzcv": 0})
    check("B.cond signed backward target", out["next_pc"] == 0x0FFC, out)

    # Exhaust the 4-bit flags x 4-bit condition-code truth table.
    for nzcv in range(16):
        for cond in range(16):
            word = encode(entry, imm=2, cond=cond)
            out = axis_exec.step(word, {}, pc=0x1000, isa=isa, state={"nzcv": nzcv})
            expected_pc = 0x1008 if condition_holds(nzcv, cond) else 0x1004
            check(
                f"ConditionHolds NZCV={nzcv:x} cond={cond:x}",
                out["next_pc"] == expected_pc,
                out,
            )

    memory = Memory()
    entry = entries["LDR_X_UNSIGNED"]
    word = encode(entry, rt=1, rn=31, imm=2)
    memory.write(0x1010, 0x1122_3344_5566_7788, 64)
    regs = {"sp": 0x1000}
    out = axis_exec.step(word, regs, mem=memory, isa=isa)
    check("LDR unsigned SP", regs[1] == 0x1122_3344_5566_7788, (regs, out))

    entry = entries["STR_X_UNSIGNED"]
    word = encode(entry, rt=2, rn=31, imm=1)
    regs = {"sp": 0x1000, 2: 0x8877_6655_4433_2211}
    out = axis_exec.step(word, regs, mem=memory, isa=isa)
    check("STR unsigned SP", memory.read(0x1008, 64) == regs[2], (memory.cells, out))

    subword_loads = [
        ("LDRB_W_UNSIGNED", 3, 8, 0xAB, 0xAB, "LDRB zero extend"),
        ("LDRH_W_UNSIGNED", 2, 16, 0xBEEF, 0xBEEF, "LDRH zero extend"),
        ("LDR_W_UNSIGNED", 2, 32, 0x89AB_CDEF, 0x89AB_CDEF, "LDR W zero extend"),
        ("LDRSB_X_UNSIGNED", 4, 8, 0x80, 0xFFFF_FFFF_FFFF_FF80, "LDRSB sign extend"),
        ("LDRSW_X_UNSIGNED", 3, 32, 0x8000_0001, 0xFFFF_FFFF_8000_0001, "LDRSW sign extend"),
    ]
    scales = {
        "LDRB_W_UNSIGNED": 0,
        "LDRH_W_UNSIGNED": 1,
        "LDR_W_UNSIGNED": 2,
        "LDRSB_X_UNSIGNED": 0,
        "LDRSW_X_UNSIGNED": 2,
    }
    for mnemonic, imm, width, raw, expected, label in subword_loads:
        entry = entries[mnemonic]
        word = encode(entry, rt=1, rn=31, imm=imm)
        addr = 0x1000 + (imm << scales[mnemonic])
        memory.write(addr, raw, width)
        regs = {"sp": 0x1000}
        out = axis_exec.step(word, regs, mem=memory, isa=isa)
        check(label, regs[1] == expected, (regs, out))

    regs = {"sp": 0x1000, 2: 0x1122_3344_5566_77A5}
    for mnemonic, imm, width, shift, expected, label in [
        ("STRB_W_UNSIGNED", 5, 8, 0, 0xA5, "STRB truncates"),
        ("STRH_W_UNSIGNED", 3, 16, 1, 0x77A5, "STRH truncates"),
        ("STR_W_UNSIGNED", 4, 32, 2, 0x5566_77A5, "STR W truncates"),
    ]:
        entry = entries[mnemonic]
        word = encode(entry, rt=2, rn=31, imm=imm)
        out = axis_exec.step(word, regs, mem=memory, isa=isa)
        addr = 0x1000 + (imm << shift)
        check(label, memory.read(addr, width) == expected, (memory.cells, out))

    unscaled_loads = [
        ("LDURB_W", "ACCEL_LDURU8_32_I9", 8, 0xA5, 0xA5),
        ("LDURSB_X", "ACCEL_LDURS8_64_I9", 8, 0x80, 0xFFFF_FFFF_FFFF_FF80),
        ("LDURSB_W", "ACCEL_LDURS8_32_I9", 8, 0x80, 0xFFFF_FF80),
        ("LDURH_W", "ACCEL_LDURU16_32_I9", 16, 0x80A5, 0x80A5),
        ("LDURSH_X", "ACCEL_LDURS16_64_I9", 16, 0x80A5, 0xFFFF_FFFF_FFFF_80A5),
        ("LDURSH_W", "ACCEL_LDURS16_32_I9", 16, 0x80A5, 0xFFFF_80A5),
        ("LDUR_W", "ACCEL_LDURU32_I9", 32, 0x8000_00A5, 0x8000_00A5),
        ("LDURSW_X", "ACCEL_LDURS32_64_I9", 32, 0x8000_00A5, 0xFFFF_FFFF_8000_00A5),
        ("LDUR_X", "ACCEL_LDURU64_I9", 64, 0x8123_4567_89AB_CDEF, 0x8123_4567_89AB_CDEF),
    ]
    negative_i9 = (1 << 9) - 16
    memory.write(0x8FF0, 0x8123_4567_89AB_CDEF, 64)
    for source_name, target_name, width, raw, expected in unscaled_loads:
        memory.write(0x8FF0, raw, width)
        for mnemonic, isa_name in (
            (source_name, "aarch64_base"),
            (target_name, "accelerator_scalar64"),
        ):
            word = encode(entries[mnemonic], rt=1, rn=31, imm=negative_i9)
            regs = {"sp": 0x9000}
            out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
            check(
                f"{mnemonic} negative offset and extension",
                regs[1] == expected and regs["sp"] == 0x9000,
                (regs, expected, out),
            )

    unscaled_stores = [
        ("STURB_W", "ACCEL_STUR8_32_I9", 8, 0xA5),
        ("STURH_W", "ACCEL_STUR16_32_I9", 16, 0x77A5),
        ("STUR_W", "ACCEL_STUR32_I9", 32, 0x5566_77A5),
        ("STUR_X", "ACCEL_STUR64_I9", 64, 0x1122_3344_5566_77A5),
    ]
    for source_name, target_name, width, expected in unscaled_stores:
        for mnemonic, isa_name in (
            (source_name, "aarch64_base"),
            (target_name, "accelerator_scalar64"),
        ):
            word = encode(entries[mnemonic], rt=2, rn=31, imm=255)
            regs = {"sp": 0x9000, 2: 0x1122_3344_5566_77A5}
            out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
            check(
                f"{mnemonic} positive unscaled offset and truncation",
                memory.read(0x90FF, width) == expected and regs["sp"] == 0x9000,
                (regs, memory.cells, out),
            )

    for mnemonic, isa_name in (
        ("STUR_X", "aarch64_base"),
        ("ACCEL_STUR64_I9", "accelerator_scalar64"),
    ):
        word = encode(entries[mnemonic], rt=31, rn=31, imm=0)
        regs = {"sp": 0x9200, 31: 0xFFFF_FFFF_FFFF_FFFF}
        out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
        check(
            f"{mnemonic} XZR store",
            memory.read(0x9200, 64) == 0,
            (regs, memory.cells, out),
        )

    def extend_index(value: int, option: int, amount: int) -> int:
        source_width = 8 << (option & 3)
        source_mask = (1 << source_width) - 1
        extended = value & source_mask
        if option & 4 and extended & (1 << (source_width - 1)):
            extended -= 1 << source_width
        return (extended << amount) & ((1 << 64) - 1)

    register_loads = [
        ("LDRB_W_REG", "ACCEL_LDRU8_32_REG", 8, 0xA5, 0xA5, 2, 0, 5),
        ("LDRSB_X_REG", "ACCEL_LDRS8_64_REG", 8, 0x80, 0xFFFF_FFFF_FFFF_FF80, 6, 0, 0xFFFF_FFFF),
        ("LDRSB_W_REG", "ACCEL_LDRS8_32_REG", 8, 0x80, 0xFFFF_FF80, 7, 1, 0xFFFF_FFFF_FFFF_FFFF),
        ("LDRH_W_REG", "ACCEL_LDRU16_32_REG", 16, 0x80A5, 0x80A5, 3, 1, 3),
        ("LDRSH_X_REG", "ACCEL_LDRS16_64_REG", 16, 0x80A5, 0xFFFF_FFFF_FFFF_80A5, 6, 1, 0xFFFF_FFFF),
        ("LDRSH_W_REG", "ACCEL_LDRS16_32_REG", 16, 0x80A5, 0xFFFF_80A5, 7, 0, 0xFFFF_FFFF_FFFF_FFFD),
        ("LDR_W_REG", "ACCEL_LDRU32_REG", 32, 0x8000_00A5, 0x8000_00A5, 2, 1, 2),
        ("LDRSW_X_REG", "ACCEL_LDRS32_64_REG", 32, 0x8000_00A5, 0xFFFF_FFFF_8000_00A5, 6, 1, 0xFFFF_FFFE),
        ("LDR_X_REG_LSL3", "ACCEL_LDR64_REG_LSL3", 64, 0x8123_4567_89AB_CDEF, 0x8123_4567_89AB_CDEF, 3, 1, 2),
    ]
    scale_for_width = {8: 0, 16: 1, 32: 2, 64: 3}
    for source_name, target_name, width, raw, expected, option, scaled, index in register_loads:
        amount = scaled * scale_for_width[width]
        address = (0xA000 + extend_index(index, option, amount)) & ((1 << 64) - 1)
        memory.write(address, raw, width)
        for mnemonic, isa_name in (
            (source_name, "aarch64_base"),
            (target_name, "accelerator_scalar64"),
        ):
            word = encode(entries[mnemonic], rt=1, rn=31, rm=3, option=option, s=scaled)
            regs = {"sp": 0xA000, 3: index}
            out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
            check(
                f"{mnemonic} option={option} scaled={scaled}",
                regs[1] == expected and regs["sp"] == 0xA000,
                (address, regs, expected, out),
            )

    register_stores = [
        ("STRB_W_REG", "ACCEL_STR8_32_REG", 8, 2, 0, 7, 0xA5),
        ("STRH_W_REG", "ACCEL_STR16_32_REG", 16, 3, 1, 3, 0x77A5),
        ("STR_W_REG", "ACCEL_STR32_REG", 32, 6, 1, 0xFFFF_FFFE, 0x5566_77A5),
        ("STR_X_REG_LSL3", "ACCEL_STR64_REG_LSL3", 64, 7, 0, 0xFFFF_FFFF_FFFF_FFF8, 0x1122_3344_5566_77A5),
    ]
    for source_name, target_name, width, option, scaled, index, expected in register_stores:
        amount = scaled * scale_for_width[width]
        address = (0xA200 + extend_index(index, option, amount)) & ((1 << 64) - 1)
        for mnemonic, isa_name in (
            (source_name, "aarch64_base"),
            (target_name, "accelerator_scalar64"),
        ):
            word = encode(entries[mnemonic], rt=2, rn=31, rm=3, option=option, s=scaled)
            regs = {"sp": 0xA200, 2: 0x1122_3344_5566_77A5, 3: index}
            out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
            check(
                f"{mnemonic} option={option} scaled={scaled}",
                memory.read(address, width) == expected and regs["sp"] == 0xA200,
                (address, regs, memory.cells, out),
            )

    entry = entries["LDR_W_REG"]
    reserved_option = encode(entry, rt=1, rn=2, rm=3, option=0, s=0)
    check(
        "LDR W register offset rejects reserved UXTB option",
        axis_lift.decode(reserved_option, isa) is None,
        hex(reserved_option),
    )

    regs = {4: 0x4000, 5: 2}
    memory.write(0x4010, 0x0102_0304_0506_0708, 64)
    entry = entries["LDR_X_REG_LSL3"]
    word = encode(entry, rt=1, rn=4, rm=5, option=3, s=1)
    out = axis_exec.step(word, regs, mem=memory, isa=isa)
    check("LDR register offset", regs[1] == 0x0102_0304_0506_0708, (regs, out))

    regs[2] = 0x8877_6655_4433_2211
    entry = entries["STR_X_REG_LSL3"]
    word = encode(entry, rt=2, rn=4, rm=5, option=3, s=1)
    out = axis_exec.step(word, regs, mem=memory, isa=isa)
    check("STR register offset", memory.read(0x4010, 64) == regs[2], (memory.cells, out))

    writeback_loads = [
        ("LDR_X_POST", "ACCEL_LDR64_POST_I9", False),
        ("LDR_X_PRE", "ACCEL_LDR64_PRE_I9", True),
    ]
    for source_name, target_name, pre in writeback_loads:
        offset = -8
        encoded_offset = (1 << 9) + offset
        address = 0x2000 + offset if pre else 0x2000
        memory.write(address, 0xAABB_CCDD_EEFF_0011, 64)
        for mnemonic, isa_name in (
            (source_name, "aarch64_base"),
            (target_name, "accelerator_scalar64"),
        ):
            word = encode(entries[mnemonic], rt=1, rn=4, imm=encoded_offset)
            regs = {4: 0x2000}
            out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
            check(
                f"{mnemonic} writeback ordering",
                regs[1] == 0xAABB_CCDD_EEFF_0011 and regs[4] == 0x1FF8,
                (address, regs, out),
            )

    writeback_stores = [
        ("STR_X_PRE", "ACCEL_STR64_PRE_I9", True),
        ("STR_X_POST", "ACCEL_STR64_POST_I9", False),
    ]
    for source_name, target_name, pre in writeback_stores:
        offset = -16
        encoded_offset = (1 << 9) + offset
        address = 0x3000 + offset if pre else 0x3000
        for mnemonic, isa_name in (
            (source_name, "aarch64_base"),
            (target_name, "accelerator_scalar64"),
        ):
            word = encode(entries[mnemonic], rt=2, rn=4, imm=encoded_offset)
            regs = {2: 0xFEED_FACE_CAFE_BEEF, 4: 0x3000}
            out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
            check(
                f"{mnemonic} writeback ordering",
                regs[4] == 0x2FF0 and memory.read(address, 64) == regs[2],
                (address, regs, memory.cells, out),
            )

    typed_writeback_loads = [
        ("LDRB_W", "ACCEL_LDRU8_32", 8, 0xA5, 0xA5),
        ("LDRSB_X", "ACCEL_LDRS8_64", 8, 0x80, 0xFFFF_FFFF_FFFF_FF80),
        ("LDRSB_W", "ACCEL_LDRS8_32", 8, 0x80, 0xFFFF_FF80),
        ("LDRH_W", "ACCEL_LDRU16_32", 16, 0x80A5, 0x80A5),
        ("LDRSH_X", "ACCEL_LDRS16_64", 16, 0x80A5, 0xFFFF_FFFF_FFFF_80A5),
        ("LDRSH_W", "ACCEL_LDRS16_32", 16, 0x80A5, 0xFFFF_80A5),
        ("LDR_W", "ACCEL_LDRU32", 32, 0x8000_00A5, 0x8000_00A5),
        ("LDRSW_X", "ACCEL_LDRS32_64", 32, 0x8000_00A5, 0xFFFF_FFFF_8000_00A5),
    ]
    for source_stem, target_stem, width, raw, expected in typed_writeback_loads:
        for phase, pre in (("PRE", True), ("POST", False)):
            offset = -8
            address = 0xB000 + offset if pre else 0xB000
            memory.write(address, raw, width)
            for mnemonic, isa_name in (
                (f"{source_stem}_{phase}", "aarch64_base"),
                (f"{target_stem}_{phase}_I9", "accelerator_scalar64"),
            ):
                word = encode(entries[mnemonic], rt=1, rn=31, imm=(1 << 9) + offset)
                regs = {"sp": 0xB000}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} width/extension/writeback",
                    regs[1] == expected and regs["sp"] == 0xAFF8,
                    (address, regs, expected, out),
                )

    typed_writeback_stores = [
        ("STRB_W", "ACCEL_STR8_32", 8, 0xA5),
        ("STRH_W", "ACCEL_STR16_32", 16, 0x77A5),
        ("STR_W", "ACCEL_STR32", 32, 0x5566_77A5),
    ]
    for source_stem, target_stem, width, expected in typed_writeback_stores:
        for phase, pre in (("PRE", True), ("POST", False)):
            offset = -16
            address = 0xB200 + offset if pre else 0xB200
            for mnemonic, isa_name in (
                (f"{source_stem}_{phase}", "aarch64_base"),
                (f"{target_stem}_{phase}_I9", "accelerator_scalar64"),
            ):
                word = encode(entries[mnemonic], rt=2, rn=31, imm=(1 << 9) + offset)
                regs = {"sp": 0xB200, 2: 0x1122_3344_5566_77A5}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} truncation/writeback",
                    memory.read(address, width) == expected and regs["sp"] == 0xB1F0,
                    (address, regs, memory.cells, out),
                )

    # Pair transfers cover W/X widths, all three addressing modes, both
    # frontends' source/accelerator encodings, scaled signed offsets, SP bases,
    # W-write zero extension, and store truncation.
    pair_widths = [
        ("W", "32", 32, 2, 4, 0x89AB_CDEF, 0xFEDC_BA98),
        (
            "X",
            "64",
            64,
            3,
            8,
            0x0123_4567_89AB_CDEF,
            0xFEDC_BA98_7654_3210,
        ),
    ]
    for source_width, target_width, width, scale, stride, first, second in pair_widths:
        for mode in ("OFFSET", "POST", "PRE"):
            signed_imm = -2
            encoded_imm = (1 << 7) + signed_imm
            base = 0xD000
            delta = signed_imm << scale
            address = base if mode == "POST" else base + delta
            expected_sp = base + delta if mode != "OFFSET" else base
            for operation in ("LDP", "STP"):
                source = f"{operation}_{source_width}_{mode}"
                target = f"ACCEL_{operation}{target_width}_{mode}_I7"
                for mnemonic, isa_name in (
                    (source, "aarch64_base"),
                    (target, "accelerator_scalar64"),
                ):
                    word = encode(
                        entries[mnemonic], rt=1, rt2=2, rn=31, imm=encoded_imm
                    )
                    regs = {
                        "sp": base,
                        1: 0xAAAA_AAAA_0000_0000 | first,
                        2: 0x5555_5555_0000_0000 | second,
                    }
                    if operation == "LDP":
                        memory.write(address, first, width)
                        memory.write(address + stride, second, width)
                    out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                    if operation == "LDP":
                        correct = (
                            regs[1] == first
                            and regs[2] == second
                            and regs["sp"] == expected_sp
                        )
                    else:
                        mask = (1 << width) - 1
                        correct = (
                            memory.read(address, width) == (regs[1] & mask)
                            and memory.read(address + stride, width)
                            == (regs[2] & mask)
                            and regs["sp"] == expected_sp
                        )
                    check(
                        f"{mnemonic} scaled {mode.lower()} SP {operation.lower()}",
                        correct,
                        (address, expected_sp, regs, memory.cells, out),
                    )

    for mnemonic, isa_name in (
        ("STP_X_OFFSET", "aarch64_base"),
        ("ACCEL_STP64_OFFSET_I7", "accelerator_scalar64"),
    ):
        word = encode(entries[mnemonic], rt=1, rt2=31, rn=31, imm=0)
        regs = {"sp": 0xD200, 1: 0xA5A5, 31: 0xFFFF_FFFF_FFFF_FFFF}
        out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
        check(
            f"{mnemonic} XZR store",
            memory.read(0xD200, 64) == 0xA5A5
            and memory.read(0xD208, 64) == 0,
            (regs, memory.cells, out),
        )

    for mnemonic, isa_name in (
        ("LDP_X_OFFSET", "aarch64_base"),
        ("ACCEL_LDP64_OFFSET_I7", "accelerator_scalar64"),
    ):
        memory.write(0xD400, 0xDEAD_BEEF, 64)
        memory.write(0xD408, 0x1234_5678, 64)
        word = encode(entries[mnemonic], rt=31, rt2=2, rn=31, imm=0)
        regs = {"sp": 0xD400}
        out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
        check(
            f"{mnemonic} XZR load discard",
            31 not in regs and regs[2] == 0x1234_5678,
            (regs, out),
        )

    exclusive_widths = [
        ("W", "32", 32, 0x89AB_CDEF, 0xAAAA_AAAA_CAFE_BABE),
        ("X", "64", 64, 0x0123_4567_89AB_CDEF, 0xCAFE_BABE_DEAD_BEEF),
    ]
    for source_width, target_width, width, loaded, replacement in exclusive_widths:
        for prefix, isa_name in (
            ("", "aarch64_base"),
            ("ACCEL_", "accelerator_scalar64"),
        ):
            load_mnemonic = (
                f"LDXR_{source_width}" if not prefix else f"ACCEL_LDXR{target_width}"
            )
            store_mnemonic = (
                f"STXR_{source_width}" if not prefix else f"ACCEL_STXR{target_width}"
            )
            load_word = encode(entries[load_mnemonic], rt=1, rn=31)
            store_word = encode(entries[store_mnemonic], rs=3, rt=2, rn=31)
            memory.write(0xD800, loaded, width)
            regs = {"sp": 0xD800, 1: 0xFFFF_FFFF_FFFF_FFFF, 2: replacement}
            state = {"exclusive_address": 0, "exclusive_size": 0, "exclusive_valid": 0}
            load_out = axis_exec.step(
                load_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{load_mnemonic} establishes reservation",
                regs[1] == loaded
                and state["exclusive_address"] == 0xD800
                and state["exclusive_size"] == width // 8
                and state["exclusive_valid"] == 1,
                (regs, state, load_out),
            )
            store_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{store_mnemonic} reservation success",
                regs[3] == 0
                and memory.read(0xD800, width)
                == (replacement & ((1 << width) - 1))
                and state["exclusive_valid"] == 0,
                (regs, state, memory.cells, store_out),
            )

            memory.write(0xD800, loaded, width)
            regs = {"sp": 0xD800, 2: replacement}
            state = {"exclusive_address": 0xD800, "exclusive_size": width // 8, "exclusive_valid": 0}
            failed_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{store_mnemonic} invalid reservation failure",
                regs[3] == 1
                and memory.read(0xD800, width) == loaded
                and state["exclusive_valid"] == 0,
                (regs, state, memory.cells, failed_out),
            )

            state = {"exclusive_address": 0xD900, "exclusive_size": width // 8, "exclusive_valid": 1}
            mismatched_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{store_mnemonic} address mismatch failure",
                regs[3] == 1
                and memory.read(0xD800, width) == loaded
                and state["exclusive_valid"] == 0,
                (regs, state, memory.cells, mismatched_out),
            )

            state = {
                "exclusive_address": 0xD800,
                "exclusive_size": 8 if width == 32 else 4,
                "exclusive_valid": 1,
            }
            size_mismatched_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{store_mnemonic} size mismatch failure",
                regs[3] == 1
                and memory.read(0xD800, width) == loaded
                and state["exclusive_valid"] == 0,
                (regs, state, memory.cells, size_mismatched_out),
            )

    for source_width, target_width, width, loaded, replacement in exclusive_widths:
        for load_mnemonic, store_mnemonic, isa_name in (
            (
                f"LDAXR_{source_width}",
                f"STLXR_{source_width}",
                "aarch64_base",
            ),
            (
                f"ACCEL_LDAXR{target_width}",
                f"ACCEL_STLXR{target_width}",
                "accelerator_scalar64",
            ),
        ):
            load_entry = entries[load_mnemonic]
            store_entry = entries[store_mnemonic]
            check(
                f"{load_mnemonic} acquire metadata",
                load_entry["effects"][0]["memory_order"] == "acquire",
                load_entry["effects"],
            )
            check(
                f"{store_mnemonic} release metadata",
                next(
                    effect
                    for effect in store_entry["effects"]
                    if effect["kind"] == "store"
                )["memory_order"]
                == "release",
                store_entry["effects"],
            )
            load_word = encode(load_entry, rt=1, rn=31)
            store_word = encode(store_entry, rs=3, rt=2, rn=31)
            memory.write(0xDA00, loaded, width)
            regs = {"sp": 0xDA00, 2: replacement}
            state = {"exclusive_address": 0, "exclusive_size": 0, "exclusive_valid": 0}
            load_out = axis_exec.step(
                load_word, regs, mem=memory, isa=isa_name, state=state
            )
            store_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{load_mnemonic}/{store_mnemonic} ordered reservation success",
                regs[1] == loaded
                and regs[3] == 0
                and memory.read(0xDA00, width)
                == (replacement & ((1 << width) - 1))
                and state["exclusive_valid"] == 0,
                (regs, state, memory.cells, load_out, store_out),
            )

    pair_exclusive_widths = [
        ("W", "32", 32, 8),
        ("X", "64", 64, 16),
    ]
    for source_width, target_width, width, pair_size in pair_exclusive_widths:
        stride = width // 8
        mask = (1 << width) - 1
        for load_mnemonic, store_mnemonic, isa_name in (
            (f"LDXP_{source_width}", f"STXP_{source_width}", "aarch64_base"),
            (
                f"ACCEL_LDXP{target_width}",
                f"ACCEL_STXP{target_width}",
                "accelerator_scalar64",
            ),
            (f"LDAXP_{source_width}", f"STLXP_{source_width}", "aarch64_base"),
            (
                f"ACCEL_LDAXP{target_width}",
                f"ACCEL_STLXP{target_width}",
                "accelerator_scalar64",
            ),
        ):
            load_entry = entries[load_mnemonic]
            store_entry = entries[store_mnemonic]
            load_word = encode(load_entry, rt=1, rt2=2, rn=31)
            store_word = encode(store_entry, rs=3, rt=4, rt2=5, rn=31)
            first = 0x0123_4567_89AB_CDEF & mask
            second = 0xFEDC_BA98_7654_3210 & mask
            replacement_first = 0xCAFE_BABE_DEAD_BEEF & mask
            replacement_second = 0x0BAD_F00D_1357_2468 & mask
            memory.write(0xDC00, first, width)
            memory.write(0xDC00 + stride, second, width)
            regs = {
                "sp": 0xDC00,
                4: replacement_first,
                5: replacement_second,
            }
            state = {
                "exclusive_address": 0,
                "exclusive_size": 0,
                "exclusive_valid": 0,
            }
            load_out = axis_exec.step(
                load_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{load_mnemonic} paired reservation",
                regs[1] == first
                and regs[2] == second
                and state["exclusive_address"] == 0xDC00
                and state["exclusive_size"] == pair_size
                and state["exclusive_valid"] == 1,
                (regs, state, load_out),
            )
            store_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{store_mnemonic} atomic pair success",
                regs[3] == 0
                and memory.read(0xDC00, width) == replacement_first
                and memory.read(0xDC00 + stride, width) == replacement_second
                and state["exclusive_valid"] == 0,
                (regs, state, memory.cells, store_out),
            )

            memory.write(0xDC00, first, width)
            memory.write(0xDC00 + stride, second, width)
            state = {
                "exclusive_address": 0xDC00,
                "exclusive_size": stride,
                "exclusive_valid": 1,
            }
            failed_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{store_mnemonic} rejects scalar-sized reservation atomically",
                regs[3] == 1
                and memory.read(0xDC00, width) == first
                and memory.read(0xDC00 + stride, width) == second
                and state["exclusive_valid"] == 0,
                (regs, state, memory.cells, failed_out),
            )

            if "AXP" in load_mnemonic:
                check(
                    f"{load_mnemonic}/{store_mnemonic} ordering metadata",
                    all(
                        effect["memory_order"] == "acquire"
                        for effect in load_entry["effects"]
                        if effect["kind"] == "load"
                    )
                    and all(
                        effect["memory_order"] == "release"
                        for effect in store_entry["effects"]
                        if effect["kind"] == "store"
                    ),
                    (load_entry["effects"], store_entry["effects"]),
                )

    for clrex_mnemonic, store_mnemonic, isa_name in (
        ("CLREX", "STXR_X", "aarch64_base"),
        ("ACCEL_CLREX", "ACCEL_STXR64", "accelerator_scalar64"),
    ):
        for option in (0, 15):
            clrex_word = encode(entries[clrex_mnemonic], option=option)
            store_word = encode(entries[store_mnemonic], rs=3, rt=2, rn=31)
            memory.write(0xDDF0, 0x0123_4567_89AB_CDEF, 64)
            regs = {
                "sp": 0xDDF0,
                2: 0xCAFE_BABE_DEAD_BEEF,
            }
            state = {
                "exclusive_address": 0xDDF0,
                "exclusive_size": 8,
                "exclusive_valid": 1,
            }
            clear_out = axis_exec.step(
                clrex_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{clrex_mnemonic} option {option} clears reservation",
                state["exclusive_address"] == 0xDDF0
                and state["exclusive_size"] == 8
                and state["exclusive_valid"] == 0,
                (state, clear_out),
            )
            store_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{clrex_mnemonic} forces following {store_mnemonic} failure",
                regs[3] == 1
                and memory.read(0xDDF0, 64) == 0x0123_4567_89AB_CDEF,
                (regs, state, memory.cells, store_out),
            )

    for kind in ("dmb", "dsb", "isb"):
        for mnemonic, isa_name in (
            (kind.upper(), "aarch64_base"),
            (f"ACCEL_{kind.upper()}", "accelerator_scalar64"),
        ):
            entry = entries[mnemonic]
            effect = entry["effects"][0]
            check(
                f"{mnemonic} typed barrier metadata",
                effect["kind"] == "barrier"
                and effect["barrier"] == kind
                and effect["width"] == 4
                and effect["eval_width"] == 4,
                effect,
            )
            options = (1, 15) if kind == "dsb" else (0, 15)
            for option in options:
                word = encode(entry, option=option)
                regs = {1: 0x1234, "sp": 0xDDF8}
                state = {
                    "exclusive_address": 0xDDF0,
                    "exclusive_size": 8,
                    "exclusive_valid": 1,
                }
                before_memory = dict(memory.cells)
                out = axis_exec.step(
                    word, regs, mem=memory, isa=isa_name, state=state, pc=0x4000
                )
                check(
                    f"{mnemonic} option {option} is state-transparent",
                    regs == {1: 0x1234, "sp": 0xDDF8}
                    and state
                    == {
                        "exclusive_address": 0xDDF0,
                        "exclusive_size": 8,
                        "exclusive_valid": 1,
                    }
                    and memory.cells == before_memory
                    and out["next_pc"] == 0x4004
                    and out["trap"] is None,
                    (regs, state, memory.cells, out),
                )

    for kind in ("sb", "csdb", "ssbb", "pssbb"):
        for mnemonic, isa_name in (
            (kind.upper(), "aarch64_base"),
            (f"ACCEL_{kind.upper()}", "accelerator_scalar64"),
        ):
            entry = entries[mnemonic]
            effect = entry["effects"][0]
            check(
                f"{mnemonic} specialized barrier metadata",
                effect["kind"] == "barrier"
                and effect["barrier"] == kind
                and effect["width"] == 4,
                effect,
            )
            word = encode(entry)
            regs = {1: 0x5678, "sp": 0xDE00}
            state = {
                "exclusive_address": 0xDDF0,
                "exclusive_size": 8,
                "exclusive_valid": 1,
            }
            before_memory = dict(memory.cells)
            out = axis_exec.step(
                word, regs, mem=memory, isa=isa_name, state=state, pc=0x5000
            )
            check(
                f"{mnemonic} is state-transparent",
                out["mnemonic"] == mnemonic
                and regs == {1: 0x5678, "sp": 0xDE00}
                and state
                == {
                    "exclusive_address": 0xDDF0,
                    "exclusive_size": 8,
                    "exclusive_valid": 1,
                }
                and memory.cells == before_memory
                and out["next_pc"] == 0x5004
                and out["trap"] is None,
                (regs, state, memory.cells, out),
            )

    for option, alias in ((0, "SSBB"), (4, "PSSBB")):
        word = encode(entries["DSB"], option=option)
        lifted = axis_lift.decode(word, "aarch64_base")
        check(
            f"DSB option {option} decodes canonically as {alias}",
            lifted is not None and lifted["mnemonic"] == alias,
            lifted,
        )

    for read_mnemonic, write_mnemonic, isa_name in (
        ("MRS_NZCV", "MSR_NZCV", "aarch64_base"),
        ("ACCEL_MRS_NZCV", "ACCEL_MSR_NZCV", "accelerator_scalar64"),
    ):
        read_entry = entries[read_mnemonic]
        write_entry = entries[write_mnemonic]
        for nzcv in (0, 5, 15):
            regs = {1: (1 << 64) - 1}
            state = {"nzcv": nzcv}
            out = axis_exec.step(
                encode(read_entry, rt=1), regs, isa=isa_name, state=state
            )
            check(
                f"{read_mnemonic} reads NZCV {nzcv}",
                regs[1] == nzcv << 28 and state["nzcv"] == nzcv,
                (regs, state, out),
            )

        regs = {31: (1 << 64) - 1}
        state = {"nzcv": 10}
        out = axis_exec.step(
            encode(read_entry, rt=31), regs, isa=isa_name, state=state
        )
        check(
            f"{read_mnemonic} discards XZR destination",
            regs[31] == (1 << 64) - 1 and state["nzcv"] == 10,
            (regs, state, out),
        )

        for value in (0, 0xA000_0000, 0xF123_4567_89AB_CDEF):
            regs = {2: value}
            state = {"nzcv": 5}
            out = axis_exec.step(
                encode(write_entry, rt=2), regs, isa=isa_name, state=state
            )
            check(
                f"{write_mnemonic} writes NZCV from Xt",
                state["nzcv"] == ((value >> 28) & 15) and regs[2] == value,
                (regs, state, out),
            )

        regs = {31: (1 << 64) - 1}
        state = {"nzcv": 15}
        out = axis_exec.step(
            encode(write_entry, rt=31), regs, isa=isa_name, state=state
        )
        check(
            f"{write_mnemonic} reads XZR as zero",
            state["nzcv"] == 0 and regs[31] == (1 << 64) - 1,
            (regs, state, out),
        )

    user_sysregs = (
        ("FPCR", "fpcr", 32, True),
        ("FPSR", "fpsr", 32, True),
        ("TPIDR_EL0", "tpidr_el0", 64, True),
        ("TPIDRRO_EL0", "tpidrro_el0", 64, False),
    )
    for suffix, state_name, width, writable in user_sysregs:
        mask = (1 << width) - 1
        for prefix, isa_name in (
            ("", "aarch64_base"),
            ("ACCEL_", "accelerator_scalar64"),
        ):
            read_mnemonic = f"{prefix}MRS_{suffix}"
            value = 0xFEDC_BA98_7654_3210 & mask
            regs = {1: 0}
            state = {state_name: value}
            out = axis_exec.step(
                encode(entries[read_mnemonic], rt=1),
                regs,
                isa=isa_name,
                state=state,
            )
            check(
                f"{read_mnemonic} named-state read",
                regs[1] == value and state[state_name] == value,
                (regs, state, out),
            )

            if writable:
                write_mnemonic = f"{prefix}MSR_{suffix}"
                source = 0x0123_4567_89AB_CDEF
                regs = {2: source}
                state = {state_name: 0}
                out = axis_exec.step(
                    encode(entries[write_mnemonic], rt=2),
                    regs,
                    isa=isa_name,
                    state=state,
                )
                check(
                    f"{write_mnemonic} named-state write",
                    state[state_name] == (source & mask) and regs[2] == source,
                    (regs, state, out),
                )

    ordered_widths = [
        ("B_W", "8", 8, 0xA5, 0x1234_5678_9ABC_DEF0),
        ("H_W", "16", 16, 0xBEEF, 0x1234_5678_9ABC_DEF0),
        ("W", "32", 32, 0x89AB_CDEF, 0x1234_5678_9ABC_DEF0),
        ("X", "64", 64, 0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210),
    ]
    for source_suffix, target_suffix, width, loaded, replacement in ordered_widths:
        source_load = {
            "B_W": "LDARB_W",
            "H_W": "LDARH_W",
            "W": "LDAR_W",
            "X": "LDAR_X",
        }[source_suffix]
        source_store = {
            "B_W": "STLRB_W",
            "H_W": "STLRH_W",
            "W": "STLR_W",
            "X": "STLR_X",
        }[source_suffix]
        for load_mnemonic, store_mnemonic, isa_name in (
            (source_load, source_store, "aarch64_base"),
            (
                f"ACCEL_LDAR{target_suffix}",
                f"ACCEL_STLR{target_suffix}",
                "accelerator_scalar64",
            ),
        ):
            load_entry = entries[load_mnemonic]
            store_entry = entries[store_mnemonic]
            check(
                f"{load_mnemonic}/{store_mnemonic} ordering metadata",
                load_entry["effects"][0]["memory_order"] == "acquire"
                and store_entry["effects"][0]["memory_order"] == "release",
                (load_entry["effects"], store_entry["effects"]),
            )
            load_word = encode(load_entry, rt=1, rn=31)
            store_word = encode(store_entry, rt=2, rn=31)
            memory.write(0xDE80, loaded, width)
            regs = {"sp": 0xDE80, 2: replacement}
            state = {
                "exclusive_address": 0xDE80,
                "exclusive_size": 16,
                "exclusive_valid": 1,
            }
            load_out = axis_exec.step(
                load_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{load_mnemonic} acquire load",
                regs[1] == loaded
                and state
                == {
                    "exclusive_address": 0xDE80,
                    "exclusive_size": 16,
                    "exclusive_valid": 1,
                },
                (regs, state, load_out),
            )
            store_out = axis_exec.step(
                store_word, regs, mem=memory, isa=isa_name, state=state
            )
            check(
                f"{store_mnemonic} release store",
                memory.read(0xDE80, width)
                == (replacement & ((1 << width) - 1))
                and state["exclusive_valid"] == 1,
                (regs, state, memory.cells, store_out),
            )

    atomic_widths = [
        ("W", "32", 32, 0x89AB_CDEF, 0xAAAA_AAAA_CAFE_BABE),
        ("X", "64", 64, 0x0123_4567_89AB_CDEF, 0xCAFE_BABE_DEAD_BEEF),
    ]
    atomic_orders = [
        ("SWP", "relaxed", "relaxed"),
        ("SWPA", "acquire", "relaxed"),
        ("SWPL", "relaxed", "release"),
        ("SWPAL", "acquire", "release"),
    ]
    for source_width, target_width, width, loaded, replacement in atomic_widths:
        for operation, load_order, store_order in atomic_orders:
            for mnemonic, isa_name in (
                (f"{operation}_{source_width}", "aarch64_base"),
                (f"ACCEL_{operation}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} atomic metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDC00, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {
                    "sp": 0xDC00,
                    1: replacement,
                    2: 0xFFFF_FFFF_FFFF_FFFF,
                }
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} atomic swap",
                    regs[2] == loaded
                    and memory.read(0xDC00, width)
                    == (replacement & ((1 << width) - 1)),
                    (regs, memory.cells, out),
                )

    atomic_encodings = {
        "SWP_W": 0xB8218062,
        "SWP_X": 0xF8218062,
        "SWPA_W": 0xB8A18062,
        "SWPA_X": 0xF8A18062,
        "SWPL_W": 0xB8618062,
        "SWPL_X": 0xF8618062,
        "SWPAL_W": 0xB8E18062,
        "SWPAL_X": 0xF8E18062,
    }
    for mnemonic, expected in atomic_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    narrow_swap_widths = [
        ("B", "8", 8, 0xA5, 0x1234),
        ("H", "16", 16, 0xBEEF, 0x12345678),
    ]
    narrow_swap_orders = [
        ("", "relaxed", "relaxed"),
        ("A", "acquire", "relaxed"),
        ("L", "relaxed", "release"),
        ("AL", "acquire", "release"),
    ]
    for source_suffix, target_width, width, loaded, replacement in narrow_swap_widths:
        mask = (1 << width) - 1
        for order_suffix, load_order, store_order in narrow_swap_orders:
            for mnemonic, isa_name in (
                (f"SWP{order_suffix}{source_suffix}", "aarch64_base"),
                (f"ACCEL_SWP{order_suffix}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} narrow atomic metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDC80, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDC80, 1: replacement, 2: 0xFFFF_FFFF}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} narrow atomic swap",
                    regs[2] == loaded
                    and memory.read(0xDC80, width) == (replacement & mask),
                    (regs, memory.cells, out),
                )

    narrow_swap_encodings = {
        "SWPB": 0x38218062,
        "SWPAB": 0x38A18062,
        "SWPLB": 0x38618062,
        "SWPALB": 0x38E18062,
        "SWPH": 0x78218062,
        "SWPAH": 0x78A18062,
        "SWPLH": 0x78618062,
        "SWPALH": 0x78E18062,
    }
    for mnemonic, expected in narrow_swap_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    for source_suffix, target_width, width, loaded, addend in narrow_swap_widths:
        mask = (1 << width) - 1
        for order_suffix, load_order, store_order in narrow_swap_orders:
            for mnemonic, isa_name in (
                (f"LDADD{order_suffix}{source_suffix}", "aarch64_base"),
                (f"ACCEL_LDADD{order_suffix}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} narrow fetch-add metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDCC0, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDCC0, 1: addend, 2: 0xFFFF_FFFF}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} narrow atomic fetch-add",
                    regs[2] == loaded
                    and memory.read(0xDCC0, width) == ((loaded + addend) & mask),
                    (regs, memory.cells, out),
                )

    narrow_ldadd_encodings = {
        "LDADDB": 0x38210062,
        "LDADDAB": 0x38A10062,
        "LDADDLB": 0x38610062,
        "LDADDALB": 0x38E10062,
        "LDADDH": 0x78210062,
        "LDADDAH": 0x78A10062,
        "LDADDLH": 0x78610062,
        "LDADDALH": 0x78E10062,
    }
    for mnemonic, expected in narrow_ldadd_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    for source_suffix, target_width, width, loaded, clear_bits in narrow_swap_widths:
        mask = (1 << width) - 1
        for order_suffix, load_order, store_order in narrow_swap_orders:
            for mnemonic, isa_name in (
                (f"LDCLR{order_suffix}{source_suffix}", "aarch64_base"),
                (f"ACCEL_LDCLR{order_suffix}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} narrow bit-clear metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDCD0, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDCD0, 1: clear_bits, 2: 0xFFFF_FFFF}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} narrow atomic bit clear",
                    regs[2] == loaded
                    and memory.read(0xDCD0, width)
                    == (loaded & (~clear_bits & mask)),
                    (regs, memory.cells, out),
                )

    narrow_ldclr_encodings = {
        "LDCLRB": 0x38211062,
        "LDCLRAB": 0x38A11062,
        "LDCLRLB": 0x38611062,
        "LDCLRALB": 0x38E11062,
        "LDCLRH": 0x78211062,
        "LDCLRAH": 0x78A11062,
        "LDCLRLH": 0x78611062,
        "LDCLRALH": 0x78E11062,
    }
    for mnemonic, expected in narrow_ldclr_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    for source_suffix, target_width, width, loaded, xor_bits in narrow_swap_widths:
        mask = (1 << width) - 1
        for order_suffix, load_order, store_order in narrow_swap_orders:
            for mnemonic, isa_name in (
                (f"LDEOR{order_suffix}{source_suffix}", "aarch64_base"),
                (f"ACCEL_LDEOR{order_suffix}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} narrow exclusive-or metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDCE0, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDCE0, 1: xor_bits, 2: 0xFFFF_FFFF}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} narrow atomic exclusive-or",
                    regs[2] == loaded
                    and memory.read(0xDCE0, width) == ((loaded ^ xor_bits) & mask),
                    (regs, memory.cells, out),
                )

    narrow_ldeor_encodings = {
        "LDEORB": 0x38212062,
        "LDEORAB": 0x38A12062,
        "LDEORLB": 0x38612062,
        "LDEORALB": 0x38E12062,
        "LDEORH": 0x78212062,
        "LDEORAH": 0x78A12062,
        "LDEORLH": 0x78612062,
        "LDEORALH": 0x78E12062,
    }
    for mnemonic, expected in narrow_ldeor_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    for source_suffix, target_width, width, loaded, set_bits in narrow_swap_widths:
        mask = (1 << width) - 1
        for order_suffix, load_order, store_order in narrow_swap_orders:
            for mnemonic, isa_name in (
                (f"LDSET{order_suffix}{source_suffix}", "aarch64_base"),
                (f"ACCEL_LDSET{order_suffix}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} narrow bit-set metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDCF0, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDCF0, 1: set_bits, 2: 0xFFFF_FFFF}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} narrow atomic bit set",
                    regs[2] == loaded
                    and memory.read(0xDCF0, width) == ((loaded | set_bits) & mask),
                    (regs, memory.cells, out),
                )

    narrow_ldset_encodings = {
        "LDSETB": 0x38213062,
        "LDSETAB": 0x38A13062,
        "LDSETLB": 0x38613062,
        "LDSETALB": 0x38E13062,
        "LDSETH": 0x78213062,
        "LDSETAH": 0x78A13062,
        "LDSETLH": 0x78613062,
        "LDSETALH": 0x78E13062,
    }
    for mnemonic, expected in narrow_ldset_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    cas_widths = [
        ("B", "8", 8, 0xA5, 0x5A),
        ("H", "16", 16, 0xBEEF, 0x1234),
        ("_W", "32", 32, 0x89AB_CDEF, 0x1020_3040),
        ("_X", "64", 64, 0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210),
    ]
    for source_suffix, target_width, width, loaded, desired in cas_widths:
        mask = (1 << width) - 1
        for order_suffix, load_order, store_order in narrow_swap_orders:
            source_operation = f"CAS{order_suffix}{source_suffix}"
            target_operation = f"ACCEL_CAS{order_suffix}{target_width}"
            for mnemonic, isa_name in (
                (source_operation, "aarch64_base"),
                (target_operation, "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} compare-and-swap metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                expected = loaded | (0xFFFF_0000 if width < 32 else 0)
                memory.write(0xDD80, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDD80, 1: expected, 2: desired}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} successful compare-and-swap",
                    regs[1] == loaded
                    and memory.read(0xDD80, width) == (desired & mask),
                    (regs, memory.cells, out),
                )
                memory.write(0xDD80, loaded, width)
                regs = {"sp": 0xDD80, 1: (loaded ^ 1) & mask, 2: desired}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} failed compare-and-swap",
                    regs[1] == loaded and memory.read(0xDD80, width) == loaded,
                    (regs, memory.cells, out),
                )

    cas_encodings = {
        "CASB": 0x08A17C62,
        "CASAB": 0x08E17C62,
        "CASLB": 0x08A1FC62,
        "CASALB": 0x08E1FC62,
        "CASH": 0x48A17C62,
        "CASAH": 0x48E17C62,
        "CASLH": 0x48A1FC62,
        "CASALH": 0x48E1FC62,
        "CAS_W": 0x88A17C62,
        "CASA_W": 0x88E17C62,
        "CASL_W": 0x88A1FC62,
        "CASAL_W": 0x88E1FC62,
        "CAS_X": 0xC8A17C62,
        "CASA_X": 0xC8E17C62,
        "CASL_X": 0xC8A1FC62,
        "CASAL_X": 0xC8E1FC62,
    }
    for mnemonic, expected in cas_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    minmax_operations = {
        "LDSMAX": lambda loaded, value, width: max(
            signed_value(loaded, width), signed_value(value, width)
        )
        & ((1 << width) - 1),
        "LDSMIN": lambda loaded, value, width: min(
            signed_value(loaded, width), signed_value(value, width)
        )
        & ((1 << width) - 1),
        "LDUMAX": lambda loaded, value, width: max(loaded, value),
        "LDUMIN": lambda loaded, value, width: min(loaded, value),
    }
    minmax_orders = (
        ("", "relaxed", "relaxed"),
        ("A", "acquire", "relaxed"),
        ("L", "relaxed", "release"),
        ("AL", "acquire", "release"),
    )
    minmax_widths = (
        ("B", "8", 8),
        ("H", "16", 16),
        ("_W", "32", 32),
        ("_X", "64", 64),
    )
    for operation, update in minmax_operations.items():
        for source_suffix, target_width, width in minmax_widths:
            mask = (1 << width) - 1
            loaded = 1 << (width - 1)
            value = 1
            for order, load_order, store_order in minmax_orders:
                source_ordered_suffix = (
                    f"{order}{source_suffix}"
                    if not source_suffix.startswith("_")
                    else f"{order}{source_suffix}"
                )
                for mnemonic, isa_name in (
                    (f"{operation}{source_ordered_suffix}", "aarch64_base"),
                    (
                        f"ACCEL_{operation}{order}{target_width}",
                        "accelerator_scalar64",
                    ),
                ):
                    entry = entries[mnemonic]
                    check(
                        f"{mnemonic} atomic min/max metadata",
                        entry["effects"][0]["atomic"] is True
                        and entry["effects"][0]["memory_order"] == load_order
                        and entry["effects"][1]["atomic"] is True
                        and entry["effects"][1]["memory_order"] == store_order,
                        entry["effects"],
                    )
                    memory.write(0xDDA0, loaded, width)
                    word = encode(entry, rs=1, rt=2, rn=31)
                    regs = {"sp": 0xDDA0, 1: value, 2: mask}
                    out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                    check(
                        f"{mnemonic} signedness and width",
                        regs[2] == loaded
                        and memory.read(0xDDA0, width)
                        == update(loaded, value, width),
                        (regs, memory.cells, out),
                    )

    minmax_encodings = {
        "LDSMAXB": 0x38214062,
        "LDSMAXALH": 0x78E14062,
        "LDSMIN_W": 0xB8215062,
        "LDSMINAL_X": 0xF8E15062,
        "LDUMAXB": 0x38216062,
        "LDUMAXALH": 0x78E16062,
        "LDUMIN_W": 0xB8217062,
        "LDUMINAL_X": 0xF8E17062,
    }
    for mnemonic, expected in minmax_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    ldadd_orders = [
        ("LDADD", "relaxed", "relaxed"),
        ("LDADDA", "acquire", "relaxed"),
        ("LDADDL", "relaxed", "release"),
        ("LDADDAL", "acquire", "release"),
    ]
    for source_width, target_width, width, loaded, addend in atomic_widths:
        mask = (1 << width) - 1
        for operation, load_order, store_order in ldadd_orders:
            for mnemonic, isa_name in (
                (f"{operation}_{source_width}", "aarch64_base"),
                (f"ACCEL_{operation}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} atomic fetch-add metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDD00, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDD00, 1: addend, 2: mask}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} atomic fetch-add",
                    regs[2] == loaded
                    and memory.read(0xDD00, width) == ((loaded + addend) & mask),
                    (regs, memory.cells, out),
                )

    ldadd_encodings = {
        "LDADD_W": 0xB8210062,
        "LDADD_X": 0xF8210062,
        "LDADDA_W": 0xB8A10062,
        "LDADDA_X": 0xF8A10062,
        "LDADDL_W": 0xB8610062,
        "LDADDL_X": 0xF8610062,
        "LDADDAL_W": 0xB8E10062,
        "LDADDAL_X": 0xF8E10062,
    }
    for mnemonic, expected in ldadd_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    memory.write(0xDDF0, 7, 64)
    word = encode(entries["LDADD_X"], rs=1, rt=1, rn=31)
    regs = {"sp": 0xDDF0, 1: 5}
    out = axis_exec.step(word, regs, mem=memory, isa="aarch64_base")
    check(
        "LDADD X overlapping source/destination",
        regs[1] == 7 and memory.read(0xDDF0, 64) == 12,
        (regs, memory.cells, out),
    )

    bitwise_atomics = [
        ("LDCLR", lambda old, value, mask: old & (~value & mask)),
        ("LDEOR", lambda old, value, mask: (old ^ value) & mask),
        ("LDSET", lambda old, value, mask: (old | value) & mask),
    ]
    for source_width, target_width, width, loaded, value in atomic_widths:
        mask = (1 << width) - 1
        for operation, update in bitwise_atomics:
            for mnemonic, isa_name in (
                (f"{operation}_{source_width}", "aarch64_base"),
                (f"ACCEL_{operation}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} relaxed atomic metadata",
                    all(effect["atomic"] is True for effect in entry["effects"])
                    and all(
                        effect["memory_order"] == "relaxed"
                        for effect in entry["effects"]
                    ),
                    entry["effects"],
                )
                memory.write(0xDDE0, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDDE0, 1: value, 2: mask}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} relaxed atomic bitwise update",
                    regs[2] == loaded
                    and memory.read(0xDDE0, width) == update(loaded, value, mask),
                    (regs, memory.cells, out),
                )

    ldclr_orders = [
        ("LDCLRA", "acquire", "relaxed"),
        ("LDCLRL", "relaxed", "release"),
        ("LDCLRAL", "acquire", "release"),
    ]
    for source_width, target_width, width, loaded, value in atomic_widths:
        mask = (1 << width) - 1
        for operation, load_order, store_order in ldclr_orders:
            for mnemonic, isa_name in (
                (f"{operation}_{source_width}", "aarch64_base"),
                (f"ACCEL_{operation}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} ordered atomic metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDDF0, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDDF0, 1: value, 2: mask}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} ordered atomic bit clear",
                    regs[2] == loaded
                    and memory.read(0xDDF0, width)
                    == (loaded & (~value & mask)),
                    (regs, memory.cells, out),
                )

    ordered_bitwise_atomics = [
        ("LDEORA", "acquire", "relaxed", lambda old, value, mask: (old ^ value) & mask),
        ("LDEORL", "relaxed", "release", lambda old, value, mask: (old ^ value) & mask),
        ("LDEORAL", "acquire", "release", lambda old, value, mask: (old ^ value) & mask),
        ("LDSETA", "acquire", "relaxed", lambda old, value, mask: (old | value) & mask),
        ("LDSETL", "relaxed", "release", lambda old, value, mask: (old | value) & mask),
        ("LDSETAL", "acquire", "release", lambda old, value, mask: (old | value) & mask),
    ]
    for source_width, target_width, width, loaded, value in atomic_widths:
        mask = (1 << width) - 1
        for operation, load_order, store_order, update in ordered_bitwise_atomics:
            for mnemonic, isa_name in (
                (f"{operation}_{source_width}", "aarch64_base"),
                (f"ACCEL_{operation}{target_width}", "accelerator_scalar64"),
            ):
                entry = entries[mnemonic]
                check(
                    f"{mnemonic} ordered atomic metadata",
                    entry["effects"][0]["atomic"] is True
                    and entry["effects"][0]["memory_order"] == load_order
                    and entry["effects"][1]["atomic"] is True
                    and entry["effects"][1]["memory_order"] == store_order,
                    entry["effects"],
                )
                memory.write(0xDDF0, loaded, width)
                word = encode(entry, rs=1, rt=2, rn=31)
                regs = {"sp": 0xDDF0, 1: value, 2: mask}
                out = axis_exec.step(word, regs, mem=memory, isa=isa_name)
                check(
                    f"{mnemonic} ordered atomic bitwise update",
                    regs[2] == loaded
                    and memory.read(0xDDF0, width) == update(loaded, value, mask),
                    (regs, memory.cells, out),
                )

    bitwise_atomic_encodings = {
        "LDCLR_W": 0xB8211062,
        "LDCLR_X": 0xF8211062,
        "LDCLRA_W": 0xB8A11062,
        "LDCLRA_X": 0xF8A11062,
        "LDCLRL_W": 0xB8611062,
        "LDCLRL_X": 0xF8611062,
        "LDCLRAL_W": 0xB8E11062,
        "LDCLRAL_X": 0xF8E11062,
        "LDEOR_W": 0xB8212062,
        "LDEOR_X": 0xF8212062,
        "LDEORA_W": 0xB8A12062,
        "LDEORA_X": 0xF8A12062,
        "LDEORL_W": 0xB8612062,
        "LDEORL_X": 0xF8612062,
        "LDEORAL_W": 0xB8E12062,
        "LDEORAL_X": 0xF8E12062,
        "LDSET_W": 0xB8213062,
        "LDSET_X": 0xF8213062,
        "LDSETA_W": 0xB8A13062,
        "LDSETA_X": 0xF8A13062,
        "LDSETL_W": 0xB8613062,
        "LDSETL_X": 0xF8613062,
        "LDSETAL_W": 0xB8E13062,
        "LDSETAL_X": 0xF8E13062,
    }
    for mnemonic, expected in bitwise_atomic_encodings.items():
        encoded = encode(entries[mnemonic], rs=1, rt=2, rn=3)
        check(
            f"{mnemonic} architectural encoding",
            encoded == expected,
            (hex(encoded), hex(expected)),
        )

    memory.write(0xDE00, 0x1122_3344_5566_7788, 64)
    word = encode(entries["SWP_X"], rs=31, rt=31, rn=31)
    regs = {"sp": 0xDE00, 31: 0xFFFF_FFFF_FFFF_FFFF}
    out = axis_exec.step(word, regs, mem=memory, isa="aarch64_base")
    check(
        "SWP X SP/XZR input and output",
        memory.read(0xDE00, 64) == 0 and regs[31] == 0xFFFF_FFFF_FFFF_FFFF,
        (regs, memory.cells, out),
    )

    entry = entries["ADR"]
    word = encode(entry, rd=1, imm=0x12345)
    regs = {}
    out = axis_exec.step(word, regs, pc=0x1000, isa=isa)
    check("ADR split positive immediate", regs[1] == 0x13345, (regs, out))

    word = encode(entry, rd=1, imm=(1 << 21) - 4)
    regs = {}
    out = axis_exec.step(word, regs, pc=0x2000, isa=isa)
    check("ADR signed negative immediate", regs[1] == 0x1FFC, (regs, out))

    entry = entries["ADRP"]
    word = encode(entry, rd=1, imm=2)
    regs = {}
    out = axis_exec.step(word, regs, pc=0x12345, isa=isa)
    check("ADRP page-relative positive", regs[1] == 0x14000, (regs, out))

    word = encode(entry, rd=1, imm=(1 << 21) - 1)
    regs = {}
    out = axis_exec.step(word, regs, pc=0x12345, isa=isa)
    check("ADRP page-relative negative", regs[1] == 0x11000, (regs, out))

    entry = entries["B"]
    word = encode(entry, imm=3)
    out = axis_exec.step(word, {}, pc=0x9000, isa=isa)
    check("B direct forward", out["next_pc"] == 0x900C, out)

    word = encode(entry, imm=(1 << 26) - 1)
    out = axis_exec.step(word, {}, pc=0x9000, isa=isa)
    check("B direct backward", out["next_pc"] == 0x8FFC, out)

    entry = entries["BL"]
    word = encode(entry, imm=2)
    regs = {}
    out = axis_exec.step(word, regs, pc=0xA000, isa=isa)
    check(
        "BL implicit link register",
        regs[30] == 0xA004
        and out["next_pc"] == 0xA008
        and out["writes"] == {"a64_gpr64:30": 30},
        (regs, out),
    )

    entry = entries["BR"]
    word = encode(entry, rn=5)
    out = axis_exec.step(word, {5: 0xBEEF_0000}, pc=0xB000, isa=isa)
    check("BR indirect target", out["next_pc"] == 0xBEEF_0000, out)

    entry = entries["RET"]
    word = encode(entry, rn=30)
    out = axis_exec.step(word, {30: 0xCAFE_0000}, pc=0xC000, isa=isa)
    check("RET through X30", out["next_pc"] == 0xCAFE_0000, out)

    entry = entries["BLR"]
    word = encode(entry, rn=5)
    regs = {5: 0xD00D_0000}
    out = axis_exec.step(word, regs, pc=0xD000, isa=isa)
    check(
        "BLR indirect link",
        out["next_pc"] == 0xD00D_0000 and regs[30] == 0xD004,
        (regs, out),
    )

    word = encode(entry, rn=30)
    regs = {30: 0xD00D_1000}
    out = axis_exec.step(word, regs, pc=0xD100, isa=isa)
    check(
        "BLR X30 reads target before link write",
        out["next_pc"] == 0xD00D_1000 and regs[30] == 0xD104,
        (regs, out),
    )

    entry = entries["CBZ_X"]
    word = encode(entry, rt=1, imm=3)
    out = axis_exec.step(word, {1: 0}, pc=0xE000, isa=isa)
    check("CBZ X taken", out["next_pc"] == 0xE00C, out)
    out = axis_exec.step(word, {1: 1}, pc=0xE000, isa=isa)
    check("CBZ X fallthrough", out["next_pc"] == 0xE004, out)

    entry = entries["CBNZ_X"]
    word = encode(entry, rt=1, imm=(1 << 19) - 1)
    out = axis_exec.step(word, {1: 1}, pc=0xE000, isa=isa)
    check("CBNZ X signed backward", out["next_pc"] == 0xDFFC, out)

    entry = entries["CBZ_W"]
    word = encode(entry, rt=1, imm=2)
    out = axis_exec.step(word, {1: 0x1_0000_0000}, pc=0xE100, isa=isa)
    check("CBZ W observes low half", out["next_pc"] == 0xE108, out)

    entry = entries["CBNZ_W"]
    word = encode(entry, rt=1, imm=2)
    out = axis_exec.step(word, {1: 0x1_0000_0001}, pc=0xE100, isa=isa)
    check("CBNZ W observes low half", out["next_pc"] == 0xE108, out)

    entry = entries["TBZ_W"]
    word = encode(entry, rt=1, bit=5, imm=2)
    out = axis_exec.step(word, {1: 0}, pc=0xE200, isa=isa)
    check("TBZ W low bit clear", out["next_pc"] == 0xE208, out)

    entry = entries["TBNZ_W"]
    word = encode(entry, rt=1, bit=5, imm=(1 << 14) - 1)
    out = axis_exec.step(word, {1: 1 << 5}, pc=0xE200, isa=isa)
    check("TBNZ W signed backward", out["next_pc"] == 0xE1FC, out)

    entry = entries["TBZ_X_HIGH"]
    word = encode(entry, rt=1, bit=8, imm=2)
    out = axis_exec.step(word, {1: 0}, pc=0xE300, isa=isa)
    check("TBZ X upper bit clear", out["next_pc"] == 0xE308, out)

    entry = entries["TBNZ_X_HIGH"]
    word = encode(entry, rt=1, bit=8, imm=2)
    out = axis_exec.step(word, {1: 1 << 40}, pc=0xE300, isa=isa)
    check("TBNZ X upper bit set", out["next_pc"] == 0xE308, out)

    logical_cases = [
        ("AND_X_SHIFTED", 64, 2, 4, 0xF0FF_F0FF_F0FF_F0FF, 0x8000_0000_0000_0001, "and"),
        ("ORR_X_SHIFTED", 64, 3, 8, 0x1000, 0x0123_4567_89AB_CDEF, "or"),
        ("EOR_X_SHIFTED", 64, 1, 12, 0xFFFF_0000_FFFF_0000, 0xFEDC_BA98_7654_3210, "xor"),
        ("AND_W_SHIFTED", 32, 0, 4, 0xF0FF_F0FF, 0x0123_4567, "and"),
        ("ORR_W_SHIFTED", 32, 2, 3, 0x1000, 0x8000_0001, "or"),
        ("EOR_W_SHIFTED", 32, 3, 7, 0xFFFF_0000, 0x1234_5678, "xor"),
        ("BIC_X_SHIFTED", 64, 0, 13, 0xFFFF_00FF_F0F0_AAAA, 0x0123_4567_89AB_CDEF, "bic"),
        ("ORN_X_SHIFTED", 64, 1, 9, 0x0000_0000_0000_1000, 0xFEDC_BA98_7654_3210, "orn"),
        ("EON_X_SHIFTED", 64, 3, 17, 0xF0F0_0F0F_AAAA_5555, 0x8000_0000_0000_0001, "eon"),
        ("BIC_W_SHIFTED", 32, 2, 5, 0xF0FF_AA55, 0x8000_0001, "bic"),
        ("ORN_W_SHIFTED", 32, 3, 11, 0x0000_1000, 0x1234_5678, "orn"),
        ("EON_W_SHIFTED", 32, 1, 7, 0xFFFF_0000, 0x89AB_CDEF, "eon"),
    ]
    for mnemonic, width, shift, amount, lhs, rhs, operation in logical_cases:
        entry = entries[mnemonic]
        word = encode(entry, rd=1, rn=2, rm=3, shift=shift, imm=amount)
        regs = {2: lhs, 3: rhs}
        state = {"nzcv": 0xA}
        out = axis_exec.step(word, regs, isa=isa, state=state)
        shifted = shift_reg(rhs, shift, amount, width)
        inverted = shifted ^ ((1 << width) - 1)
        expected = {
            "and": lhs & shifted,
            "or": lhs | shifted,
            "xor": lhs ^ shifted,
            "bic": lhs & inverted,
            "orn": lhs | inverted,
            "eon": lhs ^ inverted,
        }[operation] & ((1 << width) - 1)
        check(
            f"{mnemonic} shifted operand and flags preserved",
            regs[1] == expected and state["nzcv"] == 0xA,
            (regs, state, out),
        )

    entry = entries["ANDS_X_SHIFTED"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm=0)
    regs = {2: 0x8000_0000_0000_00FF, 3: 0x8000_0000_0000_0000}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ANDS X negative clears C/V",
        regs[1] == 0x8000_0000_0000_0000 and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    word = encode(entry, rd=31, rn=2, rm=3, shift=0, imm=0)
    regs = {2: 0xF0, 3: 0x0F}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "TST X alias zero and discard",
        state["nzcv"] == 0b0100 and 31 not in regs and out["writes"] == {},
        (regs, state, out),
    )

    entry = entries["ANDS_W_SHIFTED"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm=0)
    regs = {2: 0xFFFF_FFFF_8000_00FF, 3: 0x8000_0000}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ANDS W width and negative",
        regs[1] == 0x8000_0000 and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    entry = entries["BICS_X_SHIFTED"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm=0)
    regs = {2: 0x8000_0000_0000_00FF, 3: 0x7FFF_FFFF_FFFF_FFFF}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "BICS X negative clears C/V",
        regs[1] == 0x8000_0000_0000_0000 and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    word = encode(entry, rd=31, rn=2, rm=3, shift=0, imm=0)
    regs = {2: 0xF0, 3: 0xFF}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "BICS X zero-register destination preserves flags effect",
        state["nzcv"] == 0b0100 and 31 not in regs and out["writes"] == {},
        (regs, state, out),
    )

    entry = entries["BICS_W_SHIFTED"]
    word = encode(entry, rd=1, rn=2, rm=3, shift=0, imm=0)
    regs = {2: 0xFFFF_FFFF, 3: 0xFFFF_FFFF}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "BICS W zero result and W width",
        regs[1] == 0 and state["nzcv"] == 0b0100,
        (regs, state, out),
    )

    for width, suffix, value, amount in [
        (64, "X", 0x8000_0000_0000_0001, 68),
        (32, "W", 0x8000_0001, 36),
    ]:
        for mnemonic, shift in [
            (f"LSLV_{suffix}", 0),
            (f"LSRV_{suffix}", 1),
            (f"ASRV_{suffix}", 2),
            (f"RORV_{suffix}", 3),
        ]:
            entry = entries[mnemonic]
            word = encode(entry, rd=1, rn=2, rm=3)
            regs = {2: value, 3: amount}
            out = axis_exec.step(word, regs, isa=isa)
            check(
                f"{mnemonic} masked amount",
                regs[1] == shift_reg(value, shift, amount, width),
                (regs, out),
            )

    entry = entries["MOVZ_X"]
    word = encode(entry, rd=1, imm=0xABCD, hw=2)
    regs = {}
    out = axis_exec.step(word, regs, isa=isa)
    check("MOVZ shifted halfword", regs[1] == 0x0000_ABCD_0000_0000, (regs, out))

    entry = entries["MOVN_X"]
    word = encode(entry, rd=1, imm=0x1234, hw=1)
    regs = {}
    out = axis_exec.step(word, regs, isa=isa)
    check("MOVN shifted halfword", regs[1] == 0xFFFF_FFFF_EDCB_FFFF, (regs, out))

    entry = entries["MOVK_X"]
    word = encode(entry, rd=1, imm=0xABCD, hw=1)
    regs = {1: 0x1122_3344_5566_7788}
    out = axis_exec.step(word, regs, isa=isa)
    check("MOVK preserves other halfwords", regs[1] == 0x1122_3344_ABCD_7788, (regs, out))

    logical_immediate_cases = [
        ("AND_X_IMM", 64, {"n": 1, "immr": 0, "imms": 7}, 0x1234, 0x34),
        (
            "ORR_X_IMM",
            64,
            {"n": 0, "immr": 0, "imms": 54},
            0,
            0x7F7F_7F7F_7F7F_7F7F,
        ),
        (
            "EOR_X_IMM",
            64,
            {"n": 1, "immr": 8, "imms": 15},
            0,
            0xFF00_0000_0000_00FF,
        ),
        ("AND_W_IMM", 32, {"immr": 0, "imms": 7}, 0x1234, 0x34),
        ("ORR_W_IMM", 32, {"immr": 0, "imms": 54}, 0, 0x7F7F_7F7F),
        ("EOR_W_IMM", 32, {"immr": 4, "imms": 51}, 0, 0xF0F0_F0F0),
    ]
    for mnemonic, width, fields, source, expected in logical_immediate_cases:
        entry = entries[mnemonic]
        word = encode(entry, rd=1, rn=2, **fields)
        regs = {2: source}
        out = axis_exec.step(word, regs, isa=isa)
        check(f"{mnemonic} DecodeBitMasks", regs[1] == expected, (regs, out))

    entry = entries["ANDS_X_IMM"]
    word = encode(entry, rd=31, rn=2, n=1, immr=0, imms=7)
    regs = {2: 0x100}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "TST X immediate zero and discard",
        state["nzcv"] == 0b0100 and 31 not in regs and out["writes"] == {},
        (regs, state, out),
    )

    entry = entries["ANDS_W_IMM"]
    word = encode(entry, rd=1, rn=2, immr=1, imms=0)
    regs = {2: 0x8000_0000}
    state = {"nzcv": 0xF}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "ANDS W immediate negative",
        regs[1] == 0x8000_0000 and state["nzcv"] == 0b1000,
        (regs, state, out),
    )

    reserved_logical_immediates = [
        ("AND_X_IMM N=1 imms=63", "AND_X_IMM", {"n": 1, "immr": 0, "imms": 63}),
        ("AND_X_IMM N=0 imms=63", "AND_X_IMM", {"n": 0, "immr": 0, "imms": 63}),
        ("AND_W_IMM imms=31", "AND_W_IMM", {"immr": 0, "imms": 31}),
    ]
    for label, mnemonic, fields in reserved_logical_immediates:
        word = encode(entries[mnemonic], rd=1, rn=2, **fields)
        check(f"{label} decode reserved", axis_lift.decode(word, isa) is None, hex(word))
        check(f"{label} execution rejected", axis_exec.step(word, {2: 1}, isa=isa) is None, hex(word))

    bitfield_cases = [
        ("UBFM_X", 64, 8, 15, 0, 0x1234_5678, 0x56),
        (
            "SBFM_X",
            64,
            8,
            15,
            0,
            0x0000_0000_0000_8000,
            0xFFFF_FFFF_FFFF_FF80,
        ),
        (
            "BFM_X",
            64,
            56,
            7,
            0x1122_3344_5566_7788,
            0xAB,
            0x1122_3344_5566_AB88,
        ),
        ("UBFM_W", 32, 8, 15, 0, 0x1234_5678, 0x56),
        ("SBFM_W", 32, 8, 15, 0, 0x0000_8000, 0xFFFF_FF80),
        ("BFM_W", 32, 24, 7, 0x5566_7788, 0xAB, 0x5566_AB88),
    ]
    for mnemonic, _, immr, imms, dest, source, expected in bitfield_cases:
        entry = entries[mnemonic]
        word = encode(entry, rd=1, rn=2, immr=immr, imms=imms)
        regs = {1: dest, 2: source}
        out = axis_exec.step(word, regs, isa=isa)
        check(f"{mnemonic} bitfield", regs[1] == expected, (regs, out))

    reserved_w_bitfields = [
        ("SBFM_W immr=32", "SBFM_W", {"immr": 32, "imms": 0}),
        ("UBFM_W imms=32", "UBFM_W", {"immr": 0, "imms": 32}),
    ]
    for label, mnemonic, fields in reserved_w_bitfields:
        word = encode(entries[mnemonic], rd=1, rn=2, **fields)
        check(f"{label} decode reserved", axis_lift.decode(word, isa) is None, hex(word))
        check(
            f"{label} execution rejected",
            axis_exec.step(word, {1: 3, 2: 1}, isa=isa) is None,
            hex(word),
        )

    typed_memory_cases = [
        ("ACCEL_LDRU8_32_U12", 8, 0, 0x80, 0x80),
        ("ACCEL_LDRU16_32_U12", 16, 1, 0x8001, 0x8001),
        ("ACCEL_LDRU32_U12", 32, 2, 0x8000_0001, 0x8000_0001),
        ("ACCEL_LDRS8_64_U12", 8, 0, 0x80, 0xFFFF_FFFF_FFFF_FF80),
        (
            "ACCEL_LDRS32_64_U12",
            32,
            2,
            0x8000_0001,
            0xFFFF_FFFF_8000_0001,
        ),
    ]
    for mnemonic, width, scale, payload, expected in typed_memory_cases:
        memory = Memory()
        memory.write(0x6000 + (1 << scale), payload, width)
        word = encode(entries[mnemonic], rt=1, rn=2, imm=1)
        regs = {2: 0x6000}
        out = axis_exec.step(
            word, regs, mem=memory, isa="accelerator_scalar64"
        )
        check(f"{mnemonic} typed load", regs[1] == expected, (regs, out))

    typed_store_cases = [
        ("ACCEL_STR8_32_U12", 8, 0, 0xA5),
        ("ACCEL_STR16_32_U12", 16, 1, 0x77A5),
        ("ACCEL_STR32_U12", 32, 2, 0x5566_77A5),
    ]
    for mnemonic, width, scale, expected in typed_store_cases:
        memory = Memory()
        word = encode(entries[mnemonic], rt=1, rn=2, imm=1)
        regs = {1: 0x1122_3344_5566_77A5, 2: 0x6000}
        out = axis_exec.step(
            word, regs, mem=memory, isa="accelerator_scalar64"
        )
        check(
            f"{mnemonic} truncating store",
            memory.read(0x6000 + (1 << scale), width) == expected,
            (memory.cells, out),
        )

    memory = Memory()
    memory.write(0x6000, 0x8123_4567_89AB_CDEF, 64)
    word = encode(entries["ACCEL_LDR64_REG_LSL3"], rt=1, rn=31, rm=31, option=3, s=1)
    regs = {"sp": 0x6000, 31: 0xFFFF_FFFF_FFFF_FFFF}
    out = axis_exec.step(
        word, regs, mem=memory, isa="accelerator_scalar64"
    )
    check(
        "ACCEL LDR register offset SP/XZR",
        regs[1] == 0x8123_4567_89AB_CDEF,
        (regs, out),
    )

    memory = Memory()
    word = encode(entries["ACCEL_STR64_REG_LSL3"], rt=31, rn=31, rm=2, option=3, s=1)
    regs = {"sp": 0x6000, 2: 2, 31: 0xFFFF_FFFF_FFFF_FFFF}
    out = axis_exec.step(
        word, regs, mem=memory, isa="accelerator_scalar64"
    )
    check(
        "ACCEL STR register offset SP/XZR",
        memory.read(0x6010, 64) == 0,
        (memory.cells, out),
    )

    multiply_cases = [
        ("ACCEL_MADD64", 0xFFFF_FFFF_FFFF_FFFF, 2, 3, 1),
        ("ACCEL_MSUB64", 0xFFFF_FFFF_FFFF_FFFF, 2, 3, 5),
        ("ACCEL_MADD32", 0xFFFF_FFFF, 2, 3, 1),
        ("ACCEL_MSUB32", 0xFFFF_FFFF, 2, 3, 5),
    ]
    for mnemonic, lhs, rhs, acc, expected in multiply_cases:
        word = encode(entries[mnemonic], rd=1, rn=2, rm=3, ra=4)
        regs = {2: lhs, 3: rhs, 4: acc}
        out = axis_exec.step(word, regs, isa="accelerator_scalar64")
        check(f"{mnemonic} modular accumulation", regs[1] == expected, (regs, out))

    division_cases = [
        ("ACCEL_UDIV64", 100, 7, 14, "unsigned quotient"),
        ("ACCEL_UDIV64", 100, 0, 0, "zero divisor"),
        (
            "ACCEL_SDIV64",
            (-7) & 0xFFFF_FFFF_FFFF_FFFF,
            3,
            (-2) & 0xFFFF_FFFF_FFFF_FFFF,
            "truncation toward zero",
        ),
        (
            "ACCEL_SDIV64",
            0x8000_0000_0000_0000,
            0xFFFF_FFFF_FFFF_FFFF,
            0x8000_0000_0000_0000,
            "MIN/-1 overflow",
        ),
        ("ACCEL_UDIV32", 100, 7, 14, "word unsigned quotient"),
        ("ACCEL_UDIV32", 100, 0, 0, "word zero divisor"),
        (
            "ACCEL_SDIV32",
            (-7) & 0xFFFF_FFFF,
            3,
            (-2) & 0xFFFF_FFFF,
            "word truncation toward zero",
        ),
        (
            "ACCEL_SDIV32",
            0x8000_0000,
            0xFFFF_FFFF,
            0x8000_0000,
            "word MIN/-1 overflow",
        ),
    ]
    for mnemonic, lhs, rhs, expected, label in division_cases:
        word = encode(entries[mnemonic], rd=1, rn=2, rm=3)
        regs = {2: lhs, 3: rhs}
        out = axis_exec.step(word, regs, isa="accelerator_scalar64")
        check(f"{mnemonic} {label}", regs[1] == expected, (regs, out))

    conditional_select_cases = [
        ("ACCEL_CSEL64", 64, lambda value, mask: value),
        ("ACCEL_CSINC64", 64, lambda value, mask: (value + 1) & mask),
        ("ACCEL_CSINV64", 64, lambda value, mask: (~value) & mask),
        ("ACCEL_CSNEG64", 64, lambda value, mask: (-value) & mask),
        ("ACCEL_CSEL32", 32, lambda value, mask: value & mask),
        ("ACCEL_CSINC32", 32, lambda value, mask: (value + 1) & mask),
        ("ACCEL_CSINV32", 32, lambda value, mask: (~value) & mask),
        ("ACCEL_CSNEG32", 32, lambda value, mask: (-value) & mask),
    ]
    lhs = 0x0123_4567_89AB_CDEF
    rhs = 0xFEDC_BA98_7654_3210
    for mnemonic, width, false_value in conditional_select_cases:
        mask = (1 << width) - 1
        word = encode(entries[mnemonic], rd=1, rn=2, rm=3, cond=0)
        for nzcv, expected, path in (
            (4, lhs & mask, "true"),
            (0, false_value(rhs, mask), "false"),
        ):
            regs = {2: lhs, 3: rhs}
            state = {"nzcv": nzcv}
            out = axis_exec.step(
                word, regs, isa="accelerator_scalar64", state=state
            )
            check(
                f"{mnemonic} {path} path",
                regs[1] == expected and state == {"nzcv": nzcv},
                (regs, state, out),
            )

    word = encode(entries["ACCEL_CSINC64"], rd=1, rn=2, rm=31, cond=0)
    regs = {2: lhs, 31: 0xFFFF_FFFF_FFFF_FFFF}
    out = axis_exec.step(
        word, regs, isa="accelerator_scalar64", state={"nzcv": 0}
    )
    check("ACCEL CSINC64 XZR false input", regs[1] == 1, (regs, out))

    def reverse_bits(value: int, width: int) -> int:
        return int(f"{value & ((1 << width) - 1):0{width}b}"[::-1], 2)

    def reverse_bytes_in_lanes(value: int, width: int, lane_width: int) -> int:
        result = 0
        byte_count = lane_width // 8
        for lane in range(0, width, lane_width):
            for byte in range(byte_count):
                source = (value >> (lane + byte * 8)) & 0xFF
                result |= source << (lane + (byte_count - 1 - byte) * 8)
        return result

    def count_leading_sign(value: int, width: int) -> int:
        mask = (1 << width) - 1
        value &= mask
        probe = (~value) & mask if value & (1 << (width - 1)) else value
        return width - probe.bit_length() - 1

    unary_value = 0x0123_4567_89AB_CDEF
    unary_cases = [
        ("ACCEL_RBIT64", 64, reverse_bits(unary_value, 64)),
        ("ACCEL_REV16_64", 64, reverse_bytes_in_lanes(unary_value, 64, 16)),
        ("ACCEL_REV32_64", 64, reverse_bytes_in_lanes(unary_value, 64, 32)),
        ("ACCEL_REV64", 64, reverse_bytes_in_lanes(unary_value, 64, 64)),
        ("ACCEL_CLZ64", 64, 7),
        ("ACCEL_CLS64", 64, count_leading_sign(unary_value, 64)),
        ("ACCEL_RBIT32", 32, reverse_bits(unary_value, 32)),
        ("ACCEL_REV16_32", 32, reverse_bytes_in_lanes(unary_value, 32, 16)),
        ("ACCEL_REV32", 32, reverse_bytes_in_lanes(unary_value, 32, 32)),
        ("ACCEL_CLZ32", 32, 0),
        ("ACCEL_CLS32", 32, count_leading_sign(unary_value, 32)),
    ]
    for mnemonic, _width, expected in unary_cases:
        word = encode(entries[mnemonic], rd=1, rn=2)
        regs = {2: unary_value}
        out = axis_exec.step(word, regs, isa="accelerator_scalar64")
        check(f"{mnemonic} value", regs[1] == expected, (regs, expected, out))

    word = encode(entries["ACCEL_CLZ64"], rd=1, rn=31)
    regs = {31: 0xFFFF_FFFF_FFFF_FFFF}
    out = axis_exec.step(word, regs, isa="accelerator_scalar64")
    check("ACCEL CLZ64 XZR", regs[1] == 64, (regs, out))

    def add_with_carry(lhs: int, rhs: int, carry: int, width: int) -> tuple[int, int]:
        mask = (1 << width) - 1
        sign = 1 << (width - 1)
        lhs &= mask
        rhs &= mask
        total = lhs + rhs + carry
        result = total & mask
        signed_lhs = lhs - (1 << width) if lhs & sign else lhs
        signed_rhs = rhs - (1 << width) if rhs & sign else rhs
        signed_total = signed_lhs + signed_rhs + carry
        overflow = not (-sign <= signed_total < sign)
        nzcv = (
            (int(bool(result & sign)) << 3)
            | (int(result == 0) << 2)
            | (int(total > mask) << 1)
            | int(overflow)
        )
        return result, nzcv

    carry_vectors = {
        64: [
            (0, 0),
            ((1 << 64) - 1, 0),
            ((1 << 63) - 1, 0),
            (1 << 63, 1),
        ],
        32: [
            (0, 0),
            ((1 << 32) - 1, 0),
            ((1 << 31) - 1, 0),
            (1 << 31, 1),
        ],
    }
    for prefix, isa_name in [
        ("", "aarch64_base"),
        ("ACCEL_", "accelerator_scalar64"),
    ]:
        for operation in ("ADC", "ADCS", "SBC", "SBCS"):
            for width, suffix in ((64, "X" if not prefix else "64"), (32, "W" if not prefix else "32")):
                mnemonic = f"{prefix}{operation}_{suffix}" if not prefix else f"{prefix}{operation}{suffix}"
                for carry in (0, 1):
                    for lhs_value, rhs_value in carry_vectors[width]:
                        input_nzcv = 0b1001 | (carry << 1)
                        if operation.startswith("SB"):
                            result, expected_nzcv = add_with_carry(
                                lhs_value,
                                (~rhs_value) & ((1 << width) - 1),
                                carry,
                                width,
                            )
                        else:
                            result, expected_nzcv = add_with_carry(
                                lhs_value, rhs_value, carry, width
                            )
                        word = encode(entries[mnemonic], rd=1, rn=2, rm=3)
                        regs = {2: lhs_value, 3: rhs_value}
                        state = {"nzcv": input_nzcv}
                        out = axis_exec.step(
                            word, regs, isa=isa_name, state=state
                        )
                        expected_state = (
                            expected_nzcv if operation.endswith("S") else input_nzcv
                        )
                        check(
                            f"{mnemonic} C={carry} {lhs_value:x},{rhs_value:x}",
                            regs[1] == result and state["nzcv"] == expected_state,
                            (regs, state, result, expected_nzcv, out),
                        )

    conditional_compare_cases = [
        ("CCMN", 64, "REG", 0xFFFF_FFFF_FFFF_FFFF, 1),
        ("CCMP", 64, "REG", 0, 1),
        ("CCMN", 32, "REG", 0x7FFF_FFFF, 1),
        ("CCMP", 32, "REG", 0x8000_0000, 1),
        ("CCMN", 64, "IMM", 0xFFFF_FFFF_FFFF_FFE1, 31),
        ("CCMP", 64, "IMM", 0, 31),
        ("CCMN", 32, "IMM", 0x7FFF_FFE1, 31),
        ("CCMP", 32, "IMM", 0x8000_0000, 31),
    ]
    for operation, width, operand_form, lhs_value, rhs_value in conditional_compare_cases:
        mask = (1 << width) - 1
        if operation == "CCMN":
            _, true_nzcv = add_with_carry(lhs_value, rhs_value, 0, width)
        else:
            _, true_nzcv = add_with_carry(lhs_value, (~rhs_value) & mask, 1, width)
        source_suffix = "X" if width == 64 else "W"
        for mnemonic, isa_name in [
            (f"{operation}_{source_suffix}_{operand_form}", "aarch64_base"),
            (f"ACCEL_{operation}{width}_{operand_form}", "accelerator_scalar64"),
        ]:
            word = encode(
                entries[mnemonic], rn=2, rhs=rhs_value if operand_form == "IMM" else 3,
                cond=0, literal=0b1011,
            )
            for input_nzcv, expected_nzcv, path in (
                (0b0100, true_nzcv, "condition true"),
                (0, 0b1011, "literal false path"),
            ):
                regs = {2: lhs_value, 3: rhs_value}
                before = dict(regs)
                state = {"nzcv": input_nzcv}
                out = axis_exec.step(word, regs, isa=isa_name, state=state)
                check(
                    f"{mnemonic} {path}",
                    regs == before and state["nzcv"] == expected_nzcv,
                    (regs, state, expected_nzcv, out),
                )

    word = encode(
        entries["CCMP_X_REG"], rn=2, rhs=31, cond=0, literal=0
    )
    regs = {2: 0, 31: 0xFFFF_FFFF_FFFF_FFFF}
    state = {"nzcv": 0b0100}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    check(
        "CCMP X register reads XZR",
        state["nzcv"] == 0b0110 and regs[31] == 0xFFFF_FFFF_FFFF_FFFF,
        (regs, state, out),
    )

    # NGC/NGCS are assembler aliases for SBC/SBCS with Rn = XZR.
    word = encode(entries["SBCS_X"], rd=1, rn=31, rm=2)
    regs = {2: 5, 31: 0xDEAD_BEEF}
    state = {"nzcv": 0}
    out = axis_exec.step(word, regs, isa=isa, state=state)
    expected, expected_nzcv = add_with_carry(0, (~5) & ((1 << 64) - 1), 0, 64)
    check(
        "NGCS X alias uses XZR",
        regs[1] == expected and state["nzcv"] == expected_nzcv,
        (regs, state, out),
    )

    multiply_high_cases = [
        (0, 0),
        ((1 << 64) - 1, (1 << 64) - 1),
        (1 << 63, 2),
        (0xFEDC_BA98_7654_3210, 0x1234_5678_9ABC_DEF0),
    ]
    for source_name, target_name, signed in [
        ("UMULH_X", "ACCEL_UMULH64", False),
        ("SMULH_X", "ACCEL_SMULH64", True),
    ]:
        for lhs_value, rhs_value in multiply_high_cases:
            lhs_math, rhs_math = lhs_value, rhs_value
            if signed:
                if lhs_math & (1 << 63):
                    lhs_math -= 1 << 64
                if rhs_math & (1 << 63):
                    rhs_math -= 1 << 64
            expected = ((lhs_math * rhs_math) >> 64) & ((1 << 64) - 1)
            for mnemonic, isa_name in [
                (source_name, "aarch64_base"),
                (target_name, "accelerator_scalar64"),
            ]:
                word = encode(entries[mnemonic], rd=1, rn=2, rm=3)
                regs = {2: lhs_value, 3: rhs_value}
                out = axis_exec.step(word, regs, isa=isa_name)
                check(
                    f"{mnemonic} {lhs_value:x}*{rhs_value:x}",
                    regs[1] == expected,
                    (regs, expected, out),
                )

    word = encode(entries["UMULH_X"], rd=1, rn=31, rm=2)
    regs = {2: (1 << 64) - 1, 31: (1 << 64) - 1}
    out = axis_exec.step(word, regs, isa=isa)
    check("UMULH XZR input", regs[1] == 0, (regs, out))

    high, low = 0x0123_4567_89AB_CDEF, 0xFEDC_BA98_7654_3210
    for source_name, target_name, width in [
        ("EXTR_X", "ACCEL_EXTR64", 64),
        ("EXTR_W", "ACCEL_EXTR32", 32),
    ]:
        mask = (1 << width) - 1
        high_width, low_width = high & mask, low & mask
        for shift in (0, 1, width // 2, width - 1):
            expected = (
                low_width
                if shift == 0
                else (low_width >> shift) | (high_width << (width - shift))
            ) & mask
            for mnemonic, isa_name in [
                (source_name, "aarch64_base"),
                (target_name, "accelerator_scalar64"),
            ]:
                word = encode(entries[mnemonic], rd=1, rn=2, rm=3, lsb=shift)
                regs = {2: high, 3: low}
                out = axis_exec.step(word, regs, isa=isa_name)
                check(
                    f"{mnemonic} shift {shift}",
                    regs[1] == expected,
                    (regs, expected, out),
                )

    for mnemonic, isa_name in [
        ("EXTR_W", "aarch64_base"),
        ("ACCEL_EXTR32", "accelerator_scalar64"),
    ]:
        word = encode(entries[mnemonic], rd=1, rn=2, rm=3, lsb=32)
        check(
            f"{mnemonic} reserved shift",
            axis_lift.decode(word, isa_name) is None,
            hex(word),
        )

    word = encode(entries["EXTR_X"], rd=1, rn=2, rm=2, lsb=8)
    regs = {2: 0x0123_4567_89AB_CDEF}
    out = axis_exec.step(word, regs, isa=isa)
    expected = ((regs[2] >> 8) | (regs[2] << 56)) & ((1 << 64) - 1)
    check("ROR X immediate alias", regs[1] == expected, (regs, expected, out))

    widening_vectors = [
        (0xFFFF_FFFF, 2, 7),
        (0x8000_0000, 0xFFFF_FFFF, 0x0123_4567_89AB_CDEF),
        (0x7FFF_FFFF, 0x7FFF_FFFF, (1 << 64) - 1),
    ]
    for operation, signed, subtract in [
        ("SMADDL", True, False),
        ("SMSUBL", True, True),
        ("UMADDL", False, False),
        ("UMSUBL", False, True),
    ]:
        for lhs_value, rhs_value, accumulator in widening_vectors:
            lhs32, rhs32 = lhs_value & 0xFFFF_FFFF, rhs_value & 0xFFFF_FFFF
            if signed:
                if lhs32 & 0x8000_0000:
                    lhs32 -= 1 << 32
                if rhs32 & 0x8000_0000:
                    rhs32 -= 1 << 32
            product = lhs32 * rhs32
            expected = (accumulator - product if subtract else accumulator + product) & ((1 << 64) - 1)
            for mnemonic, isa_name in [
                (operation, "aarch64_base"),
                (f"ACCEL_{operation}", "accelerator_scalar64"),
            ]:
                word = encode(entries[mnemonic], rd=1, rn=2, rm=3, ra=4)
                regs = {2: lhs_value | (0xAAAA_AAAA << 32), 3: rhs_value | (0x5555_5555 << 32), 4: accumulator}
                out = axis_exec.step(word, regs, isa=isa_name)
                check(f"{mnemonic} mixed-width", regs[1] == expected, (regs, expected, out))

    for mnemonic, signed in [("SMADDL", True), ("UMADDL", False)]:
        word = encode(entries[mnemonic], rd=1, rn=2, rm=3, ra=31)
        regs = {2: 0xFFFF_FFFF, 3: 2, 31: 0xDEAD_BEEF}
        out = axis_exec.step(word, regs, isa=isa)
        expected = ((-1 if signed else 0xFFFF_FFFF) * 2) & ((1 << 64) - 1)
        check(f"{mnemonic} long-multiply alias", regs[1] == expected, (regs, expected, out))

    print(f"{checks} architectural-state checks, {failures} failures")
    ok = failures == 0
    print("AArch64 architectural state: PASS" if ok else "AArch64 architectural state: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
