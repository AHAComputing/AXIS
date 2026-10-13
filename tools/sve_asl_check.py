#!/usr/bin/env python3
"""AXIS's SVE executes as Arm's specification does. Gate.

`examples/sve.axisl` is SVE in Arm's encodings (docs/scalable_vectors_design.md,
V1-V3). This holds every instruction in it to Arm's DEFINITION -- the Sail
translation of the ASL for Armv9.4-A that `tools/asl_model_build.sh` builds and
`tools/asl_check.py` and `tools/sme_asl_check.py` already run words on -- and
to Arm's assembler:

  1. **the word is Arm's.** Each trial's word is built from the CORPUS's own
     layout (its fixed bits and operand fields, as the lift table publishes
     them) with random operand values, and `llvm-mc` must disassemble it to
     the instruction the corpus names. A corpus whose layout put a field in
     the wrong place would build a word Arm reads as something else;
  2. **Arm's model agrees.** The word runs on the model at VL = 128 (SVE on
     at EL3, ZCR_EL3.LEN = 0) and on AXIS's executor from the same state --
     every X, Z, P, NZCV and a memory window -- and every one of them, and
     every byte of the window, must come back identical;
  3. **not vacuously**: the model must have changed Z, P, an X register, NZCV
     or memory in every trial that must change something -- a store under an
     all-false predicate is the only exception.

Operand values are drawn from each field's whole range, registers repeating
freely -- so a destination that is also a source is exercised, which is where
an executor that writes one lane before reading the next goes wrong. Three
limits are held back and named: a base register is never SP (the harness does
not load it), LD2W's Zt is never Z31 (the corpus does not wrap Zt + 1, see its
header), and memory accesses are aimed inside the window both machines load.

The model runs with translation on (V3): with the MMU off every data access
is to Device memory, where Arm suppresses every first-fault and non-fault
access and faults a misaligned one. The template identity-maps everything up
to the end of the window as Normal memory and leaves the page after it
unmapped, so a first-fault or non-fault load aimed near the end runs into a
real translation fault -- and AXIS is told the same boundary as `mem_hi`. The
FFR goes in and out as a seventeenth predicate (the corpus's p16), always
monotonic, since Arm makes any other FFR unpredictable; and at least one such
load must have suppressed an element, or the fault path went untested.

FPCR.DN = 1, as `asl_check.py` runs.

Declines when the model or `llvm-mc` is absent.

Usage: tools/sve_asl_check.py <examples/sve.axisl> [--trials N] [--jobs N]
"""

from __future__ import annotations

import argparse
import importlib
import os
import random
import re
import struct
import subprocess
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exec_wide_check as wide   # noqa: E402
import sme_asl_check as sme_asl  # noqa: E402

DEFAULT_MODEL = Path.home() / ".cache" / "axis" / "asl" / "armv9"
VL = 128
VLB = VL // 8
STATE_IN, STATE_OUT, UART = 0x10000, 0x20000, 0x3c00 << 16
Z_AT, P_AT, FLAGS_AT = 0x100, 0x300, 0x400
SIZE = 0x410
#: The window both machines load ends at a page boundary, and the page after
#: it is not mapped: a load that runs off the end takes a translation fault,
#: which is what a first-fault or non-fault load exists to suppress.
MEM_AT, MEM_SIZE = 0x40800, 0x800
MAPPED_END = MEM_AT + MEM_SIZE
TT_AT = 0x80000                 # the translation tables, loaded as their own image
FFR_AT = P_AT + 2 * 16          # the FFR in and out, after P0-P15
BASE = MEM_AT + 0x400           # a load's base register: +-8 VLs of LD1, +-16 of LD2
MARK = 0xdeadbeef
DN = 1 << 25
M64 = (1 << 64) - 1
M32 = (1 << 32) - 1

#: The mnemonic `llvm-mc` prints for each corpus instruction, where the corpus
#: name is not simply the first word of it.
ARM_NAME = {"LD1_B": "ld1b", "LD1_H": "ld1h", "LD1_S": "ld1w",
            "LD1_D": "ld1d", "ST1_B": "st1b", "ST1_H": "st1h", "ST1_S": "st1w",
            "ST1_D": "st1d", "LD2_S": "ld2w",
            **{f"LD{kind}1_{s}": f"ld{kind.lower()}1{letter}" for kind in ("NF", "FF")
               for s, letter in (("B", "b"), ("H", "h"), ("S", "w"), ("D", "d"))}}


#: Instructions the harness cannot yet hold to Arm, and why. None, since V3
#: mapped the window as Normal memory and gave the FFR a register.
DEFERRED: dict[str, str] = {}


#: Arm's preferred disassembly, which `llvm-mc` prints when the operands allow
#: it: DUP (scalar) is always MOV; a predicate AND, ORR or SEL whose sources
#: coincide is MOV(S) Pd, Pg/Z, Pn; EOR against the governing predicate is NOT.
PREFERRED = {"dup": {"mov"}, "and": {"mov"}, "ands": {"movs"}, "orr": {"mov"},
             "orrs": {"movs"}, "sel": {"mov"}, "eor": {"not"}, "eors": {"nots"}}


def arm_name(mnemonic: str) -> str:
    name = ARM_NAME.get(mnemonic, mnemonic.split("_")[0].lower())
    # The corpus spells an operand into the name where Arm spells it into the
    # operands: CADD's rotation, TBL's second table register.
    return re.sub(r"(?<=cadd|cdot|cmla)(0|90|180|270)$", "", name).replace("tbl2", "tbl")


def reads_as(mnemonic: str, printed: str) -> bool:
    name = arm_name(mnemonic)
    return printed == name or printed in PREFERRED.get(name, ())


def tables() -> bytes:
    """EL3 translation tables: 4 KB granule, 39-bit VA, identity-mapped.

    With the MMU off every data access is to Device memory, where Arm
    suppresses every non-fault and first-fault access. Here everything below
    MAPPED_END is Normal memory, write-back; the page from MAPPED_END is not
    mapped at all; the UART is a Device block."""
    # AP[1] (bit 6) is RES1 at EL3. NSE (bit 11) with NS clear is the Root
    # physical address space: the model implements RME, and at EL3 a fetch
    # from any other space is a permission fault.
    AF, INNER, NORMAL, DEVICE = (1 << 10) | (1 << 6) | (1 << 11), 3 << 8, 1 << 2, 0
    out = bytearray(0x3000)
    struct.pack_into("<Q", out, 0, (TT_AT + 0x1000) | 3)                         # L1[0]
    struct.pack_into("<Q", out, 0x1000, (TT_AT + 0x2000) | 3)                    # L2[0]
    struct.pack_into("<Q", out, 0x1000 + 8 * (UART >> 21), UART | AF | DEVICE | 1)  # 2 MB block
    for page in range(MAPPED_END >> 12):                                        # L3
        struct.pack_into("<Q", out, 0x2000 + 8 * page, (page << 12) | AF | INNER | NORMAL | 3)
    return bytes(out)


#: TCR_EL3: T0SZ = 25, inner-shareable write-back walks, 4 KB granule.
TCR = (1 << 31) | (1 << 23) | (3 << 12) | (1 << 10) | (1 << 8) | 25


def template() -> list[str]:
    L = [f"movz x0, #{TT_AT >> 16}, lsl #16", "msr ttbr0_el3, x0",
         "movz x0, #0xff00", "msr mair_el3, x0",   # Attr0 Device-nGnRnE, Attr1 Normal WB
         f"movz x0, #{TCR & 0xffff:#x}", f"movk x0, #{TCR >> 16:#x}, lsl #16", "msr tcr_el3, x0",
         "tlbi alle3", "dsb sy", "isb",
         "mrs x0, sctlr_el3", "orr x0, x0, #0x1", "orr x0, x0, #0x4", "orr x0, x0, #0x1000",
         # Not A (alignment faults) and not WXN, which the model resets set
         # and which makes every writable page -- the template's own -- XN.
         "and x0, x0, #0xfffffffffffffffd", "and x0, x0, #0xfffffffffff7ffff",
         "msr sctlr_el3, x0", "isb",
         f"movz x30, #{STATE_IN >> 16}, lsl #16",
         # SVE at EL3: no trap (CPTR_EL3.EZ), VL = 128 (ZCR_EL3.LEN = 0).
         "mrs x0, cptr_el3", "orr x0, x0, #0x100", "msr cptr_el3, x0", "isb",
         "movz x0, #0", "msr zcr_el3, x0", "isb",
         f"add x9, x30, #{Z_AT}"]
    L += [f"ldr z{i}, [x9, #{i}, mul vl]" for i in range(32)]
    L += [f"add x10, x30, #{P_AT}", "ldr p0, [x10, #16, mul vl]", "wrffr p0.b"]
    L += [f"ldr p{i}, [x10, #{i}, mul vl]" for i in range(16)]
    L += [f"ldr x0, [x30, #{FLAGS_AT}]", "msr nzcv, x0",
          f"ldr x0, [x30, #{FLAGS_AT + 8}]", "msr fpcr, x0"]
    L += [f"ldp x{i}, x{i + 1}, [x30, #{8 * i}]" for i in range(0, 30, 2)]
    L += ["ldr x30, [x30, #240]", f".inst {MARK:#010x}",
          "msr tpidr_el3, x0", f"movz x0, #{STATE_OUT >> 16}, lsl #16"]
    L += [f"stp x{i}, x{i + 1}, [x0, #{8 * i}]" for i in range(1, 29, 2)]
    L += ["stp x29, x30, [x0, #232]", "mrs x1, tpidr_el3", "str x1, [x0]"]
    L += [f"add x9, x0, #{Z_AT}"] + [f"str z{i}, [x9, #{i}, mul vl]" for i in range(32)]
    L += [f"add x10, x0, #{P_AT}"] + [f"str p{i}, [x10, #{i}, mul vl]" for i in range(16)]
    L += ["rdffr p0.b", "str p0, [x10, #16, mul vl]"]
    L += ["mrs x1, nzcv", f"str x1, [x0, #{FLAGS_AT}]",
          f"movz x1, #{SIZE}", f"movz x2, #{UART >> 16}, lsl #16",
          "3: ldrb w3, [x0], #1", "strb w3, [x2]", "subs x1, x1, #1", "b.ne 3b",
          f"movz x0, #{MEM_AT >> 16}, lsl #16", f"movk x0, #{MEM_AT & 0xffff:#x}", f"movz x1, #{MEM_SIZE}",
          "5: ldrb w3, [x0], #1", "strb w3, [x2]", "subs x1, x1, #1", "b.ne 5b", "4: b 4b"]
    return L


def assemble(mc: str, lines: list[str], work: Path) -> bytes:
    src, obj, binf = work / "t.s", work / "t.o", work / "t.bin"
    src.write_text(".text\n" + "\n".join(lines) + "\n")
    subprocess.run([mc, "-triple=aarch64", "-mattr=+v9.4a,+sve2", "-filetype=obj",
                    "-o", str(obj), str(src)], check=True, capture_output=True)
    subprocess.run([str(Path(mc).with_name("llvm-objcopy")), "-O", "binary",
                    "--only-section=.text", str(obj), str(binf)], check=True, capture_output=True)
    return binf.read_bytes()


def disassemble(mc: str, words: list[int]) -> list[str]:
    """`llvm-mc`'s reading of each word: its mnemonic, or '' for a refusal.

    One word per call: a refusal prints a warning in place of a line, so a
    batch would misalign every answer after it."""
    seen: dict[int, str] = {}
    for word in words:
        if word in seen:
            continue
        text = " ".join(f"0x{b:02x}" for b in struct.pack("<I", word))
        done = subprocess.run([mc, "-triple=aarch64", "-mattr=+v9.4a,+sve2,+sve2-bitperm,+sve2-aes,+sve2-sm4,+sve2-sha3",
                                "-disassemble"],
                              input=text, capture_output=True, text=True)
        lines = [line.split()[0] for line in done.stdout.splitlines()
                 if line.strip() and not line.strip().startswith(".")]
        seen[word] = lines[0] if lines else ""
    return [seen[word] for word in words]


class ByteMemory:
    """Byte-addressed memory, the executors' read/write ABI."""

    def __init__(self, image: bytes):
        self.bytes = {MEM_AT + i: b for i, b in enumerate(image)}

    def read(self, address, width):
        return sum(self.bytes.get((address + i) & M64, 0) << (8 * i) for i in range(width // 8))

    def write(self, address, value, width):
        for i in range(width // 8):
            self.bytes[(address + i) & M64] = (value >> (8 * i)) & 0xFF

    def window(self) -> bytes:
        return bytes(self.bytes.get(MEM_AT + i, 0) for i in range(MEM_SIZE))


def instructions(lift) -> dict:
    """One encoding per corpus instruction: its match and its encoded operands."""
    out = {}
    for entry in lift.AXIS_LIFT_TABLE:
        origin = entry.get("scalable_origin") or entry["mnemonic"]
        if origin in out:
            continue
        operands = [(o["name"], o["kind"], o["fields"]) for o in entry["operands"]
                    if o["fields"] and not o.get("derived_from")]
        out[origin] = {"match": entry["match"], "mask": entry["mask"], "operands": operands,
                       "memory": (any(o["kind"] == "a64_gpr64sp" for o in entry["operands"])
                                  and origin.startswith(("LD", "ST"))) or "_G" in origin,
                       "flags": any(effect["kind"] == "setstate"
                                    for effect in entry.get("effects") or [])}
    return out


#: IEEE-754 formats by width: exponent bits and fraction bits.
FORMATS = {16: (5, 10), 32: (8, 23), 64: (11, 52)}


def fp_element(rng: random.Random, width: int) -> int:
    """One floating-point element: random bits, or a value FP semantics turn on."""
    if rng.random() < 0.5:
        return rng.getrandbits(width)
    exp_bits, frac_bits = FORMATS[width]
    sign = rng.getrandbits(1) << (width - 1)
    inf = ((1 << exp_bits) - 1) << frac_bits
    quiet = 1 << (frac_bits - 1)
    if rng.random() < 0.4:
        return sign | rng.choice([0, inf, inf | quiet, inf | quiet | 1, inf | 1, 1,
                                  inf | rng.getrandbits(frac_bits - 1) | 1])
    # A small integer or half: n or n + 0.5 for n below 8, exactly.
    halves = rng.randrange(1, 16)
    value = halves / 2
    bits = {16: "<e", 32: "<f", 64: "<d"}[width]
    return sign | int.from_bytes(struct.pack(bits, value), "little")


#: How each gather or scatter forms a lane's offset: (extension, scale).
GATHER_FORMS = {"GU": ("uxtw", 0), "GS": ("sxtw", 0), "GUS": ("uxtw", None), "GSS": ("sxtw", None),
                "GX": ("x", 0), "GXS": ("x", None), "GI": ("imm", None)}


def gather_form(name: str) -> tuple[int, str, int]:
    """A gather's element size in bytes, its offset extension, and its shift."""
    size = 4 if name[3] == "W" else 8
    extension, scale = GATHER_FORMS[name.split("_")[1]]
    return size, extension, (size.bit_length() - 1) if scale is None else scale


def aim_gather(rng: random.Random, name: str, values: dict, x: list, z: list) -> None:
    """Every lane's address inside the window, at any alignment.

    The offsets are what the extension will read: SXTW's may be negative, and
    for a 64-bit element with a 32-bit offset the upper half is random, which
    the extension must ignore."""
    size, extension, shift = gather_form(name)
    lanes = VLB // size
    if extension == "imm":
        imm = values["imm"]
        lane_bytes = b""
        for _ in range(lanes):
            address = MEM_AT + rng.randrange(0, MEM_SIZE - size + 1) - imm * size
            lane_bytes += address.to_bytes(size, "little")
        z[values["zn"]] = lane_bytes
        return
    base = MEM_AT + MEM_SIZE // 2
    x[values["rn"]] = base
    lane_bytes = b""
    for _ in range(lanes):
        low, high = (-(MEM_SIZE // 2), MEM_SIZE // 2 - size) if extension == "sxtw" else (0, MEM_SIZE // 2 - size)
        offset = rng.randrange(low, high + 1) >> shift
        element = offset & (M32 if extension != "x" else M64)
        if size == 8 and extension != "x":
            element |= rng.getrandbits(32) << 32
        lane_bytes += element.to_bytes(size, "little")
    z[values["zm"]] = lane_bytes


def gather_region(t: dict) -> tuple[int, list[int]]:
    """A gather's or scatter's element size and each lane's address."""
    name, v = t["mnemonic"], t["values"]
    size, extension, shift = gather_form(name)
    out = []
    for lane in range(VLB // size):
        if extension == "imm":
            element = int.from_bytes(t["z"][v["zn"]][lane * size:(lane + 1) * size], "little")
            out.append(element + v["imm"] * size)
            continue
        element = int.from_bytes(t["z"][v["zm"]][lane * size:(lane + 1) * size], "little")
        if extension == "uxtw":
            element &= M32
        elif extension == "sxtw":
            element = (element & M32) - ((element & (1 << 31)) << 1)
        out.append((t["x"][v["rn"]] + (element << shift)) & M64)
    return size, out


def trial(rng: random.Random, name: str, spec: dict) -> dict:
    word, values = spec["match"], {}
    for operand, kind, fields in spec["operands"]:
        bits = sum(f[2] for f in fields)
        value = rng.randrange(1 << bits)
        if kind in ("a64_gpr64sp", "a64_gpr32sp") and value == 31:
            value = rng.randrange(31)          # never SP: the harness does not load it
        if name.startswith("TBL2") and operand == "zn" and value == 31:
            value = rng.randrange(31)          # the pair Zn, Zn+1 does not wrap: the corpus's limit
        if name == "LD2_S" and operand == "zt" and value == 31:
            value = rng.randrange(31)          # no wrap from Z31: the corpus's limit
        if name.startswith("LDFF1") and operand == "rm" and value == values.get("rn"):
            value = (value + 1) % 31           # a base the trial can aim: Xn is not Xm
        values[operand] = value
        for insn_lo, op_lo, width in fields:
            word |= ((value >> op_lo) & ((1 << width) - 1)) << insn_lo
    x = [rng.getrandbits(64) for _ in range(31)]
    if name.startswith("WHILE"):
        # Near each other, so the predicate is neither all-true nor all-false
        # every time; and sometimes far, and sometimes signed-negative.
        # Register 31 is XZR here: it reads zero and has nothing to seed.
        a = rng.choice([rng.randrange(-40, 40), rng.getrandbits(64)])
        if values["rn"] != 31:
            x[values["rn"]] = a & M64
        if values["rm"] != 31:
            x[values["rm"]] = (a + rng.randrange(-4, 24)) & M64 if rng.random() < 0.8 \
                else rng.getrandbits(64)
    if spec["memory"] and "_G" in name:
        pass                                   # a gather aims each lane: below
    elif spec["memory"]:
        # Any alignment: the window is Normal memory and SCTLR_EL3.A is clear,
        # so Arm performs a misaligned element as it does an aligned one.
        x[values["rn"]] = BASE + rng.randrange(0, 64)
        if "rm" in values and values["rm"] != 31:
            x[values["rm"]] = rng.randrange(0, 8) if values["rm"] != values["rn"] else x[values["rm"]]
    # One byte per predicate bit; mostly-true, so compares and loads do work.
    p = [bytes(int(rng.random() < 0.7) for _ in range(VLB)) for _ in range(16)]
    # And the FFR, as p16: all true, as SETFFR leaves it before a first-fault
    # loop, or already partly cleared -- always MONOTONIC, true then false, the
    # only shape a load leaves it in. Arm makes any other FFR unpredictable.
    def monotonic(partial: bool) -> bytes:
        count = rng.randrange(VLB) if partial else VLB
        return bytes([1] * count + [0] * (VLB - count))
    p.append(monotonic(name == "SETFFR" or rng.random() < 0.5))
    if name == "WRFFR":
        p[values["pn"]] = monotonic(rng.random() < 0.7)
    if name.startswith(("LDNF1", "LDFF1")):
        # Near the end of mapped memory, sometimes misaligned, so that some
        # elements run into the unmapped page; or well inside, so none do.
        # Never LDFF1's first active element: that one is an ordinary access,
        # and a fault there is an exception, not something to suppress.
        size = ELEMENT[name[-1]]
        lanes = VLB // size
        first = next((e for e in range(lanes) if p[values["pg"]][e * size] & 1), None)
        if rng.random() < 0.6:
            fit = rng.randrange(1, lanes + 1)
            if name.startswith("LDFF1") and first is not None:
                fit = max(fit, first + 1)
            start = MAPPED_END - fit * size - rng.randrange(size)
        else:
            start = MEM_AT + rng.randrange(0, MEM_SIZE - VLB)
        if name.startswith("LDNF1"):
            imm = values["imm"] - 16 if values["imm"] & 8 else values["imm"]
            x[values["rn"]] = (start - imm * VLB) & M64
        else:
            offset = 0 if values["rm"] == 31 else rng.randrange(0, 4)
            if values["rm"] != 31:
                x[values["rm"]] = offset
            x[values["rn"]] = (start - (offset << (size.bit_length() - 1))) & M64
    z = [bytes(rng.getrandbits(8) for _ in range(VLB)) for _ in range(32)]
    if name.startswith("F") and (name[-1] in "HSD" or name.startswith("FCVTX")):
        # Floating point: random bits reach almost none of what FP semantics
        # turn on, so half the elements are drawn from what does -- quiet and
        # signalling NaNs, both zeros and infinities, a subnormal, and small
        # integers and halves, where FRINT's ties and FMAX's equal operands are.
        # FCVTX/FCVTXNT read doubles.
        size = 8 if name.startswith("FCVTX") else ELEMENT[name[-1]]
        z = [b"".join(fp_element(rng, 8 * size).to_bytes(size, "little")
                      for _ in range(VLB // size)) for _ in range(32)]
    if name.startswith(("SQ", "UQ", "SUQ", "USQ", "SH", "UH", "SRH", "URH", "SMULH", "UMULH",
                        "SABD", "UABD", "SABA", "UABA")):
        # Saturation and halving turn on at the ends of the range, which
        # random elements almost never reach: MIN, MAX, 0, -1, 1 and the halves.
        size = ELEMENT.get(name[-1], 1)
        edges = [0, 1, (1 << (8 * size)) - 1, 1 << (8 * size - 1), (1 << (8 * size - 1)) - 1,
                 (1 << (8 * size - 1)) + 1]
        z = [b"".join((rng.choice(edges) if rng.random() < 0.4 else rng.getrandbits(8 * size))
                      .to_bytes(size, "little") for _ in range(VLB // size)) for _ in range(32)]
    if name.startswith(("CMP", "SMAX", "SMIN", "UMAX", "UMIN", "MATCH", "NMATCH", "HIST")) \
            and rng.random() < 0.5:
        # Equal elements, so equality and the ties of max/min are reached --
        # some of them, not the whole register: a destructive MAX of Zdn with
        # a copy of itself changes nothing, and at .D, two lanes, a trial that
        # changes nothing is common enough that every trial of one did.
        size = ELEMENT[name[-1]] if name[-2] == "_" and name[-1] in ELEMENT else 1
        src, dst = z[values.get("zn", values.get("zd", 0))], bytearray(z[values.get("zm", 0)])
        for at in range(0, VLB, size):
            if rng.random() < 0.5:
                dst[at:at + size] = src[at:at + size]
        z[values.get("zm", 0)] = bytes(dst)
    if "_V_" in name and name.split("_")[0] in ("SRSHL", "URSHL", "SQSHL", "UQSHL", "SQRSHL", "UQRSHL"):
        # Shifts by a vector take each whole Zm element as a signed amount:
        # mostly amounts near the element's width either way, where rounding,
        # saturation and "everything shifted out" all turn on, and some
        # anywhere in the element's range.
        size = ELEMENT[name[-1]]
        bits = 8 * size
        def element() -> int:
            if rng.random() < 0.85:
                return rng.randrange(-bits - 2, bits + 3) & ((1 << bits) - 1)
            return rng.getrandbits(bits)
        z[values["zm"]] = b"".join(element().to_bytes(size, "little") for _ in range(VLB // size))
    if name.startswith(("TBX", "TBL2")):
        # Table indices mostly inside the table -- one register, or two for
        # TBL2 -- and some past it: a random index at .H and wider is out of
        # range almost always, and an out-of-range TBX changes nothing.
        size = ELEMENT[name[-1]]
        count = VLB // size * (2 if name.startswith("TBL2") else 1)
        z[values["zm"]] = b"".join(
            (rng.randrange(count) if rng.random() < 0.8 else rng.randrange(count, 2 * count + 4))
            .to_bytes(size, "little") for _ in range(VLB // size))
    if "_G" in name:
        aim_gather(rng, name, values, x, z)
    return {"mnemonic": name, "word": word, "values": values, "x": x, "z": z, "p": p,
            "flags": spec["flags"],
            "nzcv": rng.randrange(16), "mem": bytes(rng.getrandbits(8) for _ in range(MEM_SIZE))}


def pack(t: dict) -> bytearray:
    state = bytearray(SIZE)
    for r in range(31):
        struct.pack_into("<Q", state, 8 * r, t["x"][r] & M64)
    for r, z in enumerate(t["z"]):
        state[Z_AT + VLB * r:Z_AT + VLB * (r + 1)] = z
    for r, p in enumerate(t["p"]):
        struct.pack_into("<H", state, P_AT + 2 * r, sum((p[b] & 1) << b for b in range(VLB)))
    struct.pack_into("<QQ", state, FLAGS_AT, t["nzcv"] << 28, DN)
    return state


def unpack(out: bytes) -> dict:
    return {
        "x": [struct.unpack_from("<Q", out, 8 * r)[0] for r in range(31)],
        "z": [bytes(out[Z_AT + VLB * r:Z_AT + VLB * (r + 1)]) for r in range(32)],
        "p": [bytes((struct.unpack_from("<H", out, P_AT + 2 * r)[0] >> b) & 1 for b in range(VLB))
              for r in range(17)],
        "nzcv": struct.unpack_from("<Q", out, FLAGS_AT)[0] >> 28 & 0xF,
        "mem": bytes(out[SIZE:SIZE + MEM_SIZE]),
    }


_W: dict = {}


def _init(model: str, image: bytes, at: int) -> None:
    _W.update(model=model, image=image, at=at, work=Path(tempfile.mkdtemp(prefix="sve_asl_")))
    (_W["work"] / "tt.bin").write_bytes(tables())


def run_model(args: tuple) -> dict | None:
    word, state, memory = args
    image = bytearray(_W["image"])
    struct.pack_into("<I", image, _W["at"], word)
    code, blob, mem = _W["work"] / "c.bin", _W["work"] / "s.bin", _W["work"] / "m.bin"
    code.write_bytes(image)
    blob.write_bytes(state)
    mem.write_bytes(memory)
    out = subprocess.run([_W["model"], "-b", f"0x0,{code}", "-b", f"{STATE_IN:#x},{blob}",
                          "-b", f"{MEM_AT:#x},{mem}", "-b", f"{TT_AT:#x},{_W['work'] / 'tt.bin'}",
                          "-n", "0x0", "-l", "300000"],
                         capture_output=True).stdout
    return unpack(out[:SIZE + MEM_SIZE]) if len(out) >= SIZE + MEM_SIZE else None


def run_axis(axis_exec, t: dict, bases: dict) -> dict | None:
    stride = VL // 64
    regs = {r: t["x"][r] for r in range(31)}
    for file, registers in (("vreg", t["z"]), ("preg", t["p"])):
        for index, register in enumerate(registers):
            for k in range(stride):
                regs[bases[file] + index * stride + k] = int.from_bytes(register[8 * k:8 * k + 8], "little")
    state = {"nzcv": t["nzcv"], "mem_lo": 0, "mem_hi": MAPPED_END, "sp": 0}
    memory = ByteMemory(t["mem"])
    outcome = axis_exec.step(t["word"], regs, memory, 0, isa="sve", state=state)
    if outcome is None:
        return None

    def register(file: str, index: int) -> bytes:
        return b"".join((regs.get(bases[file] + index * stride + k, 0) & M64).to_bytes(8, "little")
                        for k in range(stride))
    return {"x": [regs.get(r, 0) & M64 for r in range(31)],
            "z": [register("vreg", r) for r in range(32)],
            "p": [register("preg", r) for r in range(17)],
            "nzcv": state.get("nzcv", 0) & 0xF, "mem": memory.window()}


ELEMENT = {"B": 1, "H": 2, "S": 4, "D": 8}
#: Cases per compiled driver.
CHUNK = 250


def element_region(t: dict) -> tuple[int, list[int]]:
    """A load's or store's element size and every element address it names."""
    name, v = t["mnemonic"], t["values"]
    size = ELEMENT[name[-1]]
    imm = v["imm"] - 16 if v["imm"] & 8 else v["imm"]
    count = VLB // size
    if name == "LD2_S":
        start = t["x"][v["rn"]] + imm * 2 * VLB
        return size, [start + e * size for e in range(2 * count)]
    start = t["x"][v["rn"]] + imm * VLB
    return size, [start + e * size for e in range(count)]


def fault_region(t: dict) -> tuple[int, list[int]]:
    """A first-fault or non-fault load's element size and element addresses."""
    name, v = t["mnemonic"], t["values"]
    size = ELEMENT[name[-1]]
    if name.startswith("LDNF1"):
        return element_region(t)
    offset = 0 if v["rm"] == 31 else t["x"][v["rm"]] << (size.bit_length() - 1)
    start = (t["x"][v["rn"]] + offset) & M64
    return size, [start + e * size for e in range(VLB // size)]


def wide_case(t: dict, arm: dict, lift, bases: dict, index: int) -> dict:
    """The trial as a case for the compiled executors, expecting Arm's answer."""
    stride = VL // 64
    file = [0] * lift.REGISTER_FILE_SLOTS

    def place(state, target):
        for r in range(31):
            target[r] = state["x"][r] & M64
        for kind, registers in (("vreg", state["z"]), ("preg", state["p"])):
            for number, register in enumerate(registers):
                for k in range(stride):
                    target[bases[kind] + number * stride + k] = int.from_bytes(
                        register[8 * k:8 * k + 8], "little")
    place({"x": t["x"], "z": t["z"], "p": t["p"]}, file)
    want = [0] * lift.REGISTER_FILE_SLOTS
    place(arm, want)
    seed, checks = [], []
    if t["mnemonic"].startswith(("LD", "ST")):
        size, addresses = (gather_region if "_G" in t["mnemonic"]
                           else fault_region if t["mnemonic"].startswith(("LDNF1", "LDFF1"))
                           else element_region)(t)
        for address in addresses:
            offset = address - MEM_AT
            if not 0 <= offset <= MEM_SIZE - size:
                continue                      # past the mapped end: never read
            seed.append((address, 8 * size, int.from_bytes(t["mem"][offset:offset + size], "little")))
            if t["mnemonic"].startswith("ST"):
                checks.append((address, 8 * size,
                               int.from_bytes(arm["mem"][offset:offset + size], "little")))
    sets_flags = t["flags"]
    return {"mnemonic": f"{t['mnemonic']}_{index}", "word": t["word"], "isa": "sve", "pc": 0,
            "regs": file, "seed": seed,
            "state": [("nzcv", t["nzcv"], 4), ("mem_lo", 0, 64), ("mem_hi", MAPPED_END, 64)],
            "reg_checks": [(slot, want[slot]) for slot in range(len(want)) if slot < 31
                           or slot >= bases["vreg"]],
            "mem_checks": checks, "state_write": ("nzcv", arm["nzcv"]) if sets_flags else None,
            "next_pc": 4, "trap": None, "slots": lift.REGISTER_FILE_SLOTS}


def differences(a: dict, b: dict) -> list[str]:
    out = [f"{key}{r}" for key, count in (("x", 31), ("z", 32), ("p", 17))
           for r in range(count) if a[key][r] != b[key][r]]
    if a["nzcv"] != b["nzcv"]:
        out.append(f"nzcv {a['nzcv']:04b} vs {b['nzcv']:04b}")
    if a["mem"] != b["mem"]:
        first = next(i for i in range(MEM_SIZE) if a["mem"][i] != b["mem"][i])
        out.append(f"memory at {MEM_AT + first:#x}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--trials", type=int, default=12, help="per instruction")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    parser.add_argument("--compiled-cases", type=int, default=3,
                        help="trials per instruction for the wide C and Rust executors")
    parser.add_argument("--python-only", action="store_true",
                        help="skip the wide C and Rust executors")
    parser.add_argument("--only", default="",
                        help="the instructions whose name starts with this (or any of a comma list), for a quick rerun")
    parser.add_argument("--no-rust", action="store_true",
                        help="skip the wide Rust executor, whose build is the slowest step")
    args = parser.parse_args()
    model = os.environ.get("AXIS_ASL_MODEL", str(DEFAULT_MODEL))
    mc = sme_asl.find_mc()
    for missing, what in ((not Path(model).exists(), f"no ASL model at {model} "
                           "(tools/asl_model_build.sh builds it)"),
                          (mc is None, "no llvm-mc on this host")):
        if missing:
            print(f"  DECLINED {what}")
            print("SVE == Arm's specification: SKIP")
            return 0
    work = Path(tempfile.mkdtemp(prefix="axis_sve_asl_"))
    for command, output in (("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py"),
                            ("emit-exec-python", "axis_exec.py")):
        wide.emit(args.axis_file.resolve(), command, work / output)
    sys.path.insert(0, str(work))
    axis_exec = importlib.import_module("axis_exec")
    lift = importlib.import_module("axis_lift")
    bases = {}
    for entry in lift.AXIS_LIFT_TABLE:
        for operand in entry["operands"]:
            if "slot_base" in operand:
                bases[operand["kind"]] = operand["slot_base"]

    specs = instructions(lift)
    for name, why in DEFERRED.items():
        if specs.pop(name, None):
            print(f"  deferred {name}: {why}")
    specs = {name: spec for name, spec in specs.items()
             if name.startswith(tuple(args.only.split(",")))}
    rng = random.Random(0x5FE)
    trials = [trial(rng, name, spec) for name, spec in sorted(specs.items())
              for _ in range(args.trials)]
    failures = []

    # 1. The word is Arm's.
    names = disassemble(mc, [t["word"] for t in trials])
    wrong = [(t, got) for t, got in zip(trials, names) if not reads_as(t["mnemonic"], got)]
    for t, got in wrong[:6]:
        failures.append(f"{t['mnemonic']} word {t['word']:#010x}: llvm-mc reads "
                        f"{got or 'nothing'}, the corpus names {arm_name(t['mnemonic'])}")
    if wrong:
        failures.append(f"{len(wrong)} of {len(trials)} words are not the instruction "
                        "the corpus names")

    # 2. Arm's model agrees.
    image = assemble(mc, template(), work)
    at = image.index(struct.pack("<I", MARK))
    with Pool(args.jobs, initializer=_init, initargs=(model, image, at)) as pool:
        results = pool.map(run_model, [(t["word"], pack(t), t["mem"]) for t in trials])
    disagreed, moved, by_name = 0, set(), {}
    faulting, suppressed = 0, 0
    for t, arm in zip(trials, results):
        label = f"{t['mnemonic']} {t['word']:#010x} {t['values']}"
        if arm is None:
            failures.append(f"{label}: the model produced no state (trapped or hung)")
            continue
        before = {"x": [v & M64 for v in t["x"]], "z": t["z"], "p": t["p"],
                  "nzcv": t["nzcv"], "mem": t["mem"]}
        if differences(arm, before):
            moved.add(t["mnemonic"])
        if t["mnemonic"].startswith(("LDNF1", "LDFF1")):
            faulting += 1
            suppressed += arm["p"][16] != t["p"][16]
        ours = run_axis(axis_exec, t, bases)
        if ours is None:
            failures.append(f"{label}: AXIS did not decode the word")
            continue
        off = differences(ours, arm)
        if off:
            disagreed += 1
            by_name.setdefault(t["mnemonic"], []).append(f"{label}: {off[:4]}")
    for name, cases in sorted(by_name.items()):
        failures.append(f"{name}: AXIS differs from Arm in {len(cases)} of {args.trials}; "
                        f"first {cases[0]}")
    # 2b. And the compiled executors, from the same states, against Arm's
    # answers: the wide C and Rust ones run each lane of a scalable word too.
    # Every instruction, `--compiled-cases` trials of each: the compiled
    # executors are built per chunk, and building one pulls in the whole
    # generated executor.
    taken: dict[str, int] = {}
    cases = []
    for index, (t, arm) in enumerate(zip(trials, results)):
        if arm is None or taken.get(t["mnemonic"], 0) >= args.compiled_cases:
            continue
        taken[t["mnemonic"]] = taken.get(t["mnemonic"], 0) + 1
        cases.append(wide_case(t, arm, lift, bases, index))
    for lang in () if args.python_only else ("c",) if args.no_rust else ("c", "rust"):
        target = work / lang
        target.mkdir()
        if lang == "c":
            for command, output in (("emit-exec-c", "axis_exec.h"), ("emit-lift-c", "axis_lift.h"),
                                    ("emit-semantics-c", "axis_semantics.h")):
                wide.emit(args.axis_file.resolve(), command, target / output)
        # In chunks: one generated `main` holding a thousand cases took rustc
        # past ninety minutes, and a compile that never ends is a gate that
        # never answers.
        lines, bad_runs = [], []
        for start in range(0, len(cases), CHUNK):
            chunk_dir = target / f"chunk{start // CHUNK}"
            chunk_dir.mkdir()
            for header in target.glob("*.h"):
                (chunk_dir / header.name).write_bytes(header.read_bytes())
            result = wide.build_and_run(cases[start:start + CHUNK], chunk_dir,
                                        args.axis_file.resolve(), lang)
            out = result.stdout.strip().splitlines()
            lines += [line for line in out if line.startswith(("FAIL", "DECLINE"))]
            summary = out[-1] if out else result.stderr.strip()[-300:]
            if result.returncode != 0 or " 0 failures" not in summary or " 0 declined" not in summary:
                bad_runs.append(summary)
        if bad_runs or lines:
            failures.append(f"wide {lang} against Arm: {len(lines)} failing line(s); {bad_runs[0] if bad_runs else ''}")
            bad = sorted({line.split()[1].rsplit("_", 1)[0] for line in lines})
            failures.append(f"  wide {lang} differs on: {', '.join(bad[:12])}")
            failures.extend(f"  {line}" for line in lines[:3])

    # 3. Not vacuously.
    # Per instruction: every one must change something in SOME trial. A single
    # trial may legitimately leave everything as it was -- a PTEST whose flags
    # were already those, a store under an all-false predicate.
    still = sorted(set(specs) - moved)
    if still:
        failures.append(f"the model changed nothing in any trial of {', '.join(still[:8])}")
    # And the fault path itself: some first-fault or non-fault load must have
    # run into the unmapped page, or those trials only held LD1 again.
    if faulting and not suppressed:
        failures.append(f"none of {faulting} first-fault and non-fault loads suppressed an element")

    print(f"{len(trials)} SVE words on Arm's ASL model at VL = {VL}, {len(specs)} instructions; "
          f"llvm-mc disagreed on {len(wrong)}, AXIS on {disagreed}")
    if faulting:
        print(f"  {suppressed} of {faulting} first-fault and non-fault loads suppressed an element")
    for failure in failures[:20]:
        print(f"  {failure}")
    ok = not failures
    print("SVE == Arm's specification: PASS" if ok else "SVE == Arm's specification: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
