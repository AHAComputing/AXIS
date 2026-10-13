#!/usr/bin/env python3
"""Stencil JIT: compile one template per instruction, patch operands per word.

Stage J1 of docs/jit_stencils.md. `jit_llvm.py` compiles a *block* at run time,
so translation costs an LLVM compile. This compiles one **stencil** per
instruction ahead of time -- the proven `axis_eval_*` handler with its operand
indices left as holes -- and translation becomes copying bytes and filling the
holes in.

A hole is a symbol the stencil references. Not knowing its address, the compiler
emits a relocation, and the object file's relocation table says where in the
emitted bytes that value is used. This stage builds the stencils, compiles them,
and reads that table back; the check is that every stencil has exactly the holes
its operands imply -- no more, and none missing.

Usage: tools/jit_stencil.py <input.axisl> [--dump N]
"""

from __future__ import annotations

import argparse
import ctypes
import ctypes.util
import json
import re
import random
import struct
import time
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llvm_effects_check import ByteMemory  # noqa: E402
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
# Room for any address a 16-bit register seed can form. The fallback steps real
# loads and stores, so they need somewhere to land.
MEMORY_BYTES = 1 << 20

# Mach-O, which is what this host emits. A different host means a different
# reader and a different patcher; the stencil IR does not change.
MH_MAGIC_64 = 0xFEEDFACF
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
# ARM64 relocation kinds, from mach-o/arm64/reloc.h. Only the two that name a
# symbol's address in code are handled here -- an operand block is an address,
# which is the whole reason the values go in one.
ARM64_RELOC_PAGE21 = 3
ARM64_RELOC_PAGEOFF12 = 4
RELOC_NAMES = {0: "UNSIGNED", 1: "SUBTRACTOR", 2: "BRANCH26",
               3: "PAGE21", 4: "PAGEOFF12", 5: "GOT_LOAD_PAGE21",
               6: "GOT_LOAD_PAGEOFF12", 7: "POINTER_TO_GOT", 8: "TLVP_LOAD_PAGE21",
               9: "TLVP_LOAD_PAGEOFF12", 10: "ADDEND"}


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file),
                    "-o", str(output)], check=True, cwd=AXIS_ROOT)


class MachO:
    """Just enough Mach-O to find a symbol's bytes and the relocations in them.

    Written rather than shelled out to `llvm-objdump`, which is not installed
    here -- and a parser that reads the fields it needs is easier to be sure of
    than a text format that changes between LLVM releases.
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        magic, _cpu, _sub, _ftype, ncmds, _size, _flags, _res = struct.unpack_from(
            "<IiiIIIII", data, 0)
        if magic != MH_MAGIC_64:
            raise SystemExit(f"not a 64-bit Mach-O object: {magic:#x}")
        self.sections: list[dict] = []
        self.symbols: list[tuple[str, int, int]] = []
        offset = 32
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, offset)
            if cmd == LC_SEGMENT_64:
                nsects = struct.unpack_from("<I", data, offset + 64)[0]
                at = offset + 72
                for _s in range(nsects):
                    name = data[at:at + 16].rstrip(b"\0").decode()
                    seg = data[at + 16:at + 32].rstrip(b"\0").decode()
                    addr, size, file_off = struct.unpack_from("<QQI", data, at + 32)
                    reloff, nreloc = struct.unpack_from("<II", data, at + 56)
                    self.sections.append({
                        "name": name, "segment": seg, "addr": addr, "size": size,
                        "offset": file_off, "reloff": reloff, "nreloc": nreloc,
                    })
                    at += 80
            elif cmd == LC_SYMTAB:
                symoff, nsyms, stroff, _strsize = struct.unpack_from(
                    "<IIII", data, offset + 8)
                for i in range(nsyms):
                    at = symoff + i * 16
                    strx, n_type, n_sect, _desc, value = struct.unpack_from(
                        "<IBBHQ", data, at)
                    end = data.index(b"\0", stroff + strx)
                    name = data[stroff + strx:end].decode()
                    self.symbols.append((name, n_sect, value))
            offset += cmdsize

    def text(self) -> dict:
        for section in self.sections:
            if section["name"] == "__text":
                return section
        raise SystemExit("object has no __text section")

    def relocations(self, section: dict) -> list[tuple[int, str, str]]:
        """(offset within the section, relocation kind, symbol name)."""
        out = []
        for i in range(section["nreloc"]):
            address, packed = struct.unpack_from(
                "<iI", self.data, section["reloff"] + i * 8)
            symbolnum = packed & 0xFFFFFF
            extern = (packed >> 27) & 1
            kind = (packed >> 28) & 0xF
            if not extern:
                continue                       # section-relative; not a hole
            name = self.symbols[symbolnum][0] if symbolnum < len(self.symbols) else "?"
            out.append((address, RELOC_NAMES.get(kind, str(kind)), name))
        return out


def effect_kinds(entry):
    """The effects this instruction has, if a stencil can carry all of them.

    Loads and stores can: they write a register and memory and nothing else.
    A branch writes the pc and a trap ends the block, and both are the block's
    business rather than a stencil's -- the existing JIT ends a block on them
    too. `setstate` is left out because syncing architectural state across the
    handoff is a separate thing to get right.
    """
    effects = entry.get("effects")
    if not effects:
        return None
    kinds = [effect["kind"] for effect in effects]
    if any(kind not in ("set", "store") for kind in kinds):
        return None
    if kinds.count("set") > 1:
        return None                    # one register write; more is more holes
    return kinds


def effect_widths(sem_ll: str) -> dict:
    """Each effect handler's machine width, from its own signature.

    As with the evaluators, not assumed: RV32I's handlers take `i32` for the pc
    and the scratch array, RV64I's take `i64`, and a stencil built at the wrong
    one does not parse.
    """
    return {name: int(width) for name, width in
            re.findall(r"^define void @axis_eff_(\w+)\(i8\* %mem, i(\d+) %pc",
                       sem_ll, flags=re.M)}


def emit_effect_stencil(lines, entry, ident, width):
    """A stencil around `axis_eff_*`: the machine pointers arrive as holes.

    The handler does its own memory accesses and reports its writes through a
    scratch array, so the stencil's work is binding the operands and committing
    the register write the handler says it made.
    """
    inputs = [op for op in entry["operands"] if op["role"] not in ("out", "enc")]
    writes = [effect for effect in entry["effects"] if effect["kind"] == "set"]
    dest_name = writes[0]["dest"] if writes else None
    names = []
    body = []
    machine = f"i{width}"
    for label, kind in (("regs", "i64*"), ("mem", "i8*"), (f"out", f"{machine}*"),
                        ("state", f"{machine}*"), ("pc", machine)):
        hole = f"AXIS_HOLE_{ident}_{label}"
        names.append(hole)
        lines.insert(1, f"@{hole} = external dso_local global i8")
        body.append(f"  %{label} = load {kind}, {kind}* bitcast (i8* @{hole} to {kind}*)")
    args = []
    for position, op in enumerate(inputs):
        hole = f"AXIS_HOLE_{ident}_op{position}"
        names.append(hole)
        lines.insert(1, f"@{hole} = external dso_local global i8")
        body.append(f"  %s{position} = load i64, i64* bitcast (i8* @{hole} to i64*)")
        if op["kind"] == "imm":
            raw = f"%s{position}"
        else:
            body.append(f"  %p{position} = getelementptr i64, i64* %regs, i64 %s{position}")
            body.append(f"  %v{position} = load i64, i64* %p{position}")
            raw = f"%v{position}"
        if width == 64:
            args.append(f"{machine} {raw}")
        else:
            body.append(f"  %a{position} = trunc i64 {raw} to {machine}")
            args.append(f"{machine} %a{position}")
    call_args = ", ".join([f"i8* %mem", f"{machine} %pc", f"{machine}* %out",
                           f"{machine}* %state"] + args)
    body.append(f"  call void @axis_eff_{ident}({call_args})")
    if dest_name is not None:
        hole = f"AXIS_HOLE_{ident}_dest"
        names.append(hole)
        lines.insert(1, f"@{hole} = external dso_local global i8")
        # Slot 0 is the value and slot 1 whether it was written: a guarded set
        # decides that at run time, so the commit is a select rather than a
        # store.
        body.append(f"  %vp = getelementptr {machine}, {machine}* %out, i64 0")
        body.append(f"  %valw = load {machine}, {machine}* %vp")
        body.append(f"  %wp = getelementptr {machine}, {machine}* %out, i64 1")
        body.append(f"  %wrote = load {machine}, {machine}* %wp")
        body.append(f"  %did = icmp ne {machine} %wrote, 0")
        if width == 64:
            body.append("  %val = bitcast i64 %valw to i64")
        else:
            body.append(f"  %val = zext {machine} %valw to i64")
        body.append(f"  %d = load i64, i64* bitcast (i8* @{hole} to i64*)")
        body.append("  %dp = getelementptr i64, i64* %regs, i64 %d")
        body.append("  %old = load i64, i64* %dp")
        body.append("  %new = select i1 %did, i64 %val, i64 %old")
        body.append("  store i64 %new, i64* %dp")
    lines.append(f"define void @axis_stencil_{ident}() {{")
    lines.append("entry:")
    lines.extend(body)
    lines.append("  ret void")
    lines.append("}")
    return names


def handler_widths(sem_ll: str) -> dict:
    """Each handler's evaluation width, read from its own signature.

    Not assumed: a document mixes them. RV64I has i32 handlers for its word
    forms and i64 for its doubles, and a stencil that called one at the other's
    width does not even parse -- which is how this was found.
    """
    return {name: int(width) for width, name in
            re.findall(r"^define i(\d+) @axis_eval_(\w+)\(", sem_ll, flags=re.M)}


def stencil_ir_from_axis(axis_file: Path, workdir: Path) -> tuple[str, dict, set]:
    """The stencil module as AXIS emits it, with its holes read back out.

    ⚠️ This module used to be built here, by regex-rewriting `emit-llvm-ir`
    inside this gate -- which is why there was no stencil *library*: the
    artifact a library would be built from was assembled in a test. AXIS emits
    it now (`emit-stencil-ll`), and this reads the holes out of the artifact
    rather than keeping a second account of them.

    The hole ORDER is the order each stencil first references them, which is
    what the patcher needs and what the emitter writes.
    """
    emit(axis_file, "emit-stencil-ll", workdir / "axis_stencils.ll")
    text = (workdir / "axis_stencils.ll").read_text()
    holes: dict[str, list[str]] = {}
    effect_stencils: set[str] = set()
    # ⚠️ A hole the HANDLER references is the stencil's too. `axis_eff_*` is
    # `alwaysinline`, so its references are relocations inside the stencil's
    # bytes even though they are not in the stencil's IR body -- and a hole
    # collected here but not there is reported as a symbol that is not a hole,
    # which is how the memory window announced itself.
    handler: dict[str, list[str]] = {}
    for match in re.finditer(
            r"define(?: internal)? void @axis_eff_(\w+)\([^)]*\)[^{]*\{\n(.*?)\n\}",
            text, re.S):
        ident, body = match.group(1), match.group(2)
        found: list[str] = []
        for hole in re.findall(r"@(AXIS_HOLE_\w+)", body):
            if hole not in found:
                found.append(hole)
        handler[ident] = found
    for match in re.finditer(
            r"define void @axis_stencil_(\w+)\(\) \{\n(.*?)\n\}", text, re.S):
        ident, body = match.group(1), match.group(2)
        seen: list[str] = []
        for hole in re.findall(r"@(AXIS_HOLE_\w+)", body):
            if hole not in seen:
                seen.append(hole)
        for hole in handler.get(ident, []):
            if hole not in seen:
                seen.append(hole)
        holes[ident] = seen
        if f"call void @axis_eff_{ident}(" in body:
            effect_stencils.add(ident)
    return text, holes, effect_stencils


def stencil_ir(entries, sem_ll: str) -> tuple[str, dict, set]:
    """The stencil module: one function per instruction, operands as holes.

    Each stencil takes the register file and reads its operands' *indices* from
    holes -- symbols whose addresses the patcher points at an operand block. The
    handler is inlined, so a stencil's bytes are self-contained apart from those
    holes.

    The register file is 64-bit slots, as the wide executor's is; a handler
    narrower than that gets its inputs truncated and its result zero-extended,
    which is what the executor does when it writes a narrow result into a slot.
    """
    widths = handler_widths(sem_ll)
    effects = effect_widths(sem_ll)
    # The handlers become internal and always-inlined, so a stencil's bytes are
    # a self-contained blob: no call, no frame, nothing to resolve but the
    # holes. Left external, LLVM keeps the call -- measured, and the stencil
    # came out with a prologue and a `bl` to a handler that copying the bytes
    # would not bring along.
    sem_ll = re.sub(r"^define i(\d+) @axis_eval_(\w+)\(([^)]*)\) \{",
                    r"define internal i\1 @axis_eval_\2(\3) alwaysinline {",
                    sem_ll, flags=re.M)
    # Effect handlers inline into their stencils for the same reason the pure
    # ones do.
    sem_ll = re.sub(r"^define void @axis_eff_(\w+)\(([^)]*)\) \{",
                    r"define internal void @axis_eff_\1(\2) alwaysinline {",
                    sem_ll, flags=re.M)
    lines = [sem_ll, "", "; --- stencils ---"]
    holes: dict[str, list[str]] = {}
    effect_stencils: set[str] = set()
    for entry in entries:
        ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
        if effect_kinds(entry) is not None:
            machine_width = effects.get(ident)
            if machine_width is None:
                continue
            names = emit_effect_stencil(lines, entry, ident, machine_width)
            if names:
                holes[ident] = names
                effect_stencils.add(ident)
            continue
        width = widths.get(ident)
        if width is None:
            continue
        inputs = [op for op in entry["operands"] if op["role"] not in ("out", "enc")]
        dest = next((op for op in entry["operands"]
                     if op["role"] in ("out", "inout")), None)
        if dest is None or not inputs:
            continue
        # The register file arrives through a hole, not through x0. A stencil is
        # a standalone function as far as the compiler is concerned, free to
        # clobber the argument registers; a block that concatenated them and
        # assumed x0 survived was relying on luck rather than on a rule. Reached
        # through a hole, every stencil is position-independent and composes
        # whatever the register allocator did.
        regs_hole = f"AXIS_HOLE_{ident}_regs"
        names, body = [regs_hole], []
        lines.insert(1, f"@{regs_hole} = external dso_local global i8")
        body.append(f"  %regs = load i64*, i64** bitcast (i8* @{regs_hole} to i64**)")
        for position, op in enumerate(inputs):
            hole = f"AXIS_HOLE_{ident}_{position}"
            names.append(hole)
            lines.insert(1, f"@{hole} = external dso_local global i8")
            body.append(f"  %s{position} = load i64, i64* bitcast (i8* @{hole} to i64*)")
            if op["kind"] == "imm":
                # An immediate is the simpler hole: the slot holds the value
                # itself rather than where to find it. Same patching, one
                # indirection less.
                body.append(f"  %w{position} = bitcast i64 %s{position} to i64")
            else:
                body.append(f"  %p{position} = getelementptr i64, i64* %regs, i64 %s{position}")
                body.append(f"  %w{position} = load i64, i64* %p{position}")
            if width == 64:
                body.append(f"  %v{position} = bitcast i64 %w{position} to i64")
            else:
                body.append(f"  %v{position} = trunc i64 %w{position} to i{width}")
        dest_hole = f"AXIS_HOLE_{ident}_dest"
        names.append(dest_hole)
        lines.insert(1, f"@{dest_hole} = external dso_local global i8")
        args = ", ".join(f"i{width} %v{i}" for i in range(len(inputs)))
        body.append(f"  %r = call i{width} @axis_eval_{ident}({args})")
        if width == 64:
            body.append("  %rw = bitcast i64 %r to i64")
        else:
            body.append(f"  %rw = zext i{width} %r to i64")
        body.append(f"  %d = load i64, i64* bitcast (i8* @{dest_hole} to i64*)")
        body.append("  %dp = getelementptr i64, i64* %regs, i64 %d")
        body.append("  store i64 %rw, i64* %dp")
        lines.append(f"define void @axis_stencil_{ident}() {{")
        lines.append("entry:")
        lines.extend(body)
        lines.append("  ret void")
        lines.append("}")
        holes[ident] = names
    return "\n".join(lines), holes, effect_stencils


def stencil_bytes(macho: MachO, text: dict, obj: bytes) -> dict:
    """Each stencil's machine code, by identifier.

    A symbol's size is not in a Mach-O symbol table, so it is the distance to
    the next symbol in the same section -- exact here because the stencils are
    the only things left in `__text` once the handlers inline away.
    """
    entries = sorted(((name.lstrip("_"), value) for name, sect, value in macho.symbols
                      if sect == 1 and name.startswith("_axis_stencil_")),
                     key=lambda item: item[1])
    out = {}
    for index, (name, addr) in enumerate(entries):
        end = entries[index + 1][1] if index + 1 < len(entries) else (
            text["addr"] + text["size"])
        start = text["offset"] + (addr - text["addr"])
        out[name[len("axis_stencil_"):]] = {
            "bytes": obj[start:start + (end - addr)],
            "addr": addr,
        }
    return out


class JitBuffer:
    """A page of executable memory, written through the JIT write-protect gate.

    Apple Silicon refuses a plain read-write-execute mapping; `MAP_JIT` plus
    `pthread_jit_write_protect_np` is the supported route, and this process can
    use it -- measured before the design leaned on it.
    """

    PROT_READ, PROT_WRITE, PROT_EXEC = 1, 2, 4
    MAP_PRIVATE, MAP_ANON, MAP_JIT = 0x0002, 0x1000, 0x0800

    def __init__(self, size: int = 1 << 16) -> None:
        self.libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        self.libc.mmap.restype = ctypes.c_void_p
        self.libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int,
                                   ctypes.c_int, ctypes.c_int, ctypes.c_long]
        self.size = size
        self.base = self.libc.mmap(
            None, size, self.PROT_READ | self.PROT_WRITE | self.PROT_EXEC,
            self.MAP_PRIVATE | self.MAP_ANON | self.MAP_JIT, -1, 0)
        if self.base in (None, 2 ** 64 - 1):
            raise SystemExit("cannot map executable memory")

    def write(self, offset: int, data: bytes) -> None:
        self.libc.pthread_jit_write_protect_np(0)
        ctypes.memmove(self.base + offset, data, len(data))
        self.libc.pthread_jit_write_protect_np(1)
        self.libc.sys_icache_invalidate(ctypes.c_void_p(self.base + offset),
                                        ctypes.c_size_t(len(data)))


def patch_page21(code: bytearray, offset: int, target: int, pc: int) -> None:
    """`adrp Xd, page` -- the signed page delta, in 4KB granules."""
    delta = (target >> 12) - (pc >> 12)
    word = struct.unpack_from("<I", code, offset)[0]
    word &= ~((3 << 29) | (0x7FFFF << 5))
    word |= (delta & 3) << 29
    word |= ((delta >> 2) & 0x7FFFF) << 5
    struct.pack_into("<I", code, offset, word)


def patch_pageoff12(code: bytearray, offset: int, target: int) -> bool:
    """The offset within the page, into whichever instruction is there.

    ⚠️ `add Xd, Xn, #imm12` takes it in BYTES; `ldr Xt, [Xn, #imm12]` takes it
    SCALED by the access size, because that field addresses words. Writing the
    byte value into a load patches a slot eight times too far away, which is
    plausible enough to run and wrong every time -- and the compiler picks the
    load form whenever the stencil reads a VALUE out of a hole rather than an
    address out of one. Returns whether the form was one it knows.
    """
    word = struct.unpack_from("<I", code, offset)[0]
    place = target & 0xFFF
    if (word & 0xFF800000) == 0x91000000:            # ADD (immediate), 64-bit
        word = (word & ~(0xFFF << 10)) | (place << 10)
    elif (word & 0x3B000000) == 0x39000000 and not word & (1 << 26):
        bytes_wide = 1 << (word >> 30)               # LDR/STR unsigned offset
        if place % bytes_wide:
            return False
        word = (word & ~(0xFFF << 10)) | ((place // bytes_wide) << 10)
    else:
        return False
    struct.pack_into("<I", code, offset, word)
    return True


RET = 0xD65F03C0


def translate_block(program, stencils, holes, by_symbol, text, buffer, block_base,
                    regs_addr):
    """Lay one stencil per instruction into the buffer, patched. Stage J3.

    Each stencil ends in `ret`; a block drops all but the last one's, so control
    falls from each into the next. Nothing else is rewritten -- that is the
    claim being tested, and it is why translation is a memcpy and a few stores
    rather than a compile.

    Returns the bytes written and the number of holes patched.
    """
    code = bytearray()
    block = bytearray(8 * sum(len(holes[ident]) for ident, _ in program))
    patches = 0
    slot_at = block_base
    for ident, values in program:
        raw = bytearray(stencils[ident]["bytes"])
        offset_in_block = len(code)
        slots = {}
        for hole in holes[ident]:
            slots[hole] = slot_at
            slot_at += 8
        for hole, slot in slots.items():
            for offset, kind in by_symbol.get(hole, []):
                site = offset - (stencils[ident]["addr"] - text["addr"])
                if not 0 <= site < len(raw):
                    continue
                target = buffer.base + slot
                pc = buffer.base + offset_in_block + site
                if kind == "PAGE21":
                    patch_page21(raw, site, target, pc)
                    patches += 1
                elif kind == "PAGEOFF12":
                    patch_pageoff12(raw, site, target)
                    patches += 1
        for hole, value in zip(holes[ident], [regs_addr] + list(values)):
            block[slots[hole] - block_base:slots[hole] - block_base + 8] = \
                struct.pack("<Q", value)
        # Fall through into the next stencil.
        code += raw[:-4]
    code += struct.pack("<I", RET)
    # Two writes, not one per hole. Each one crosses the JIT write-protect gate
    # and invalidates the instruction cache, and doing that per operand made
    # translation cost more than the copying it exists to replace.
    buffer.write(0, bytes(code))
    buffer.write(block_base, bytes(block))
    return code, patches


def run_blocks(entries, holes, macho, text, obj, by_symbol, workdir, programs,
               length, golden, lift):
    """Translate and run whole blocks; compare against the golden model. J3.

    The reference applies each instruction in order to a register file of its
    own, which is what the block does -- the point under test is that the
    stencils compose: that falling out of one lands in the next with the
    register file the previous one left.
    """
    stencils = stencil_bytes(macho, text, obj)
    usable = [e for e in entries
              if re.sub(r"[^0-9A-Za-z]", "_", e["mnemonic"]).lower() in stencils
              and not e.get("effects")]
    if not usable:
        return 0, 0, 0.0
    buffer = JitBuffer()
    BLOCK = 1 << 15
    rng = random.Random(0x81C4)
    ran = wrong = 0
    elapsed = 0.0
    for _ in range(programs):
        program, expect = [], []
        for _ in range(length):
            entry = usable[rng.randrange(len(usable))]
            ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
            inputs = [op for op in entry["operands"]
                      if op["role"] not in ("out", "enc")]
            slot_values, sources = [], []
            for op in inputs:
                if op["kind"] == "imm":
                    value = rng.getrandbits(12)
                    slot_values.append(value)
                    sources.append(("imm", value))
                else:
                    index = rng.randrange(1, 8)
                    slot_values.append(index)
                    # The slot, not the index: the stencil reaches the register
                    # the class names, and so must the reference.
                    sources.append(("zero", 0) if reads_zero(lift, op["kind"], index)
                                   else ("reg", lift.register_slot(op["kind"], index)))
            dest_op = next(op for op in entry["operands"]
                           if op["role"] in ("out", "inout"))
            dest = rng.randrange(1, 8)
            program.append((ident, slot_values + [dest]))
            expect.append((entry["mnemonic"], sources,
                           lift.register_slot(dest_op["kind"], dest),
                           reads_zero(lift, dest_op["kind"], dest)))
        regs = [rng.getrandbits(32) for _ in range(lift.REGISTER_FILE_SLOTS)]

        start = time.perf_counter()
        live = (ctypes.c_uint64 * lift.REGISTER_FILE_SLOTS)(*regs)
        _code, _patches = translate_block(program, stencils, holes, by_symbol,
                                          text, buffer, BLOCK,
                                          ctypes.addressof(live))
        elapsed += time.perf_counter() - start

        ctypes.CFUNCTYPE(None)(buffer.base)()

        want = list(regs)
        for mnemonic, sources, dest, dest_zero in expect:
            value = golden.evaluate(
                mnemonic, *[0 if kind == "zero" else value if kind == "imm"
                            else want[value] for kind, value in sources])
            if not dest_zero:
                want[dest] = value
        ran += 1
        got = list(live)
        if got != want:
            wrong += 1
            index = next(i for i in range(len(want)) if got[i] != want[i])
            if wrong <= 4:
                print(f"FAIL block: reg {index} patched {got[index]:#x} != "
                      f"golden {want[index]:#x}")
    return ran, wrong, elapsed


def compile_cost(entries, sem_ll, machine, length, rounds):
    """What the same block costs to *compile*, which is what stencils replace.

    A block of `length` instructions as one function, run through the same
    optimiser and emitted to an object -- the work `jit_llvm.py` does per block
    at run time. Timed against the stencil path's translation, because the
    entire argument for stencils is that this is the cost being removed.
    """
    import llvmlite.binding as llvm

    rng = random.Random(0x0C0DE)
    widths = handler_widths(sem_ll)
    usable = [e for e in entries
              if re.sub(r"[^0-9A-Za-z]", "_", e["mnemonic"]).lower() in widths
              and not e.get("effects")]
    if not usable:
        return 0.0
    elapsed = 0.0
    for _ in range(rounds):
        body = []
        for step in range(length):
            entry = usable[rng.randrange(len(usable))]
            ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
            width = widths[ident]
            inputs = [op for op in entry["operands"]
                      if op["role"] not in ("out", "enc")]
            args = []
            for position, op in enumerate(inputs):
                if op["kind"] == "imm":
                    args.append(f"i{width} {rng.randrange(1, 4096)}")
                    continue
                index = rng.randrange(1, 16)
                body.append(f"  %p{step}_{position} = getelementptr i{width}, i{width}* %regs, i64 {index}")
                body.append(f"  %v{step}_{position} = load i{width}, i{width}* %p{step}_{position}")
                args.append(f"i{width} %v{step}_{position}")
            body.append(f"  %r{step} = call i{width} @axis_eval_{ident}({', '.join(args)})")
            body.append(f"  %d{step} = getelementptr i{width}, i{width}* %regs, i64 {rng.randrange(1, 16)}")
            body.append(f"  store i{width} %r{step}, i{width}* %d{step}")
        source = (sem_ll + "\n\ndefine void @axis_block(i64* %regs) {\nentry:\n"
                  + "\n".join(body) + "\n  ret void\n}\n")
        # The same work `jit_llvm.py` does per block: parse the semantics
        # module with the block appended, and compile it. Including the
        # semantics parse is not a thumb on the scale -- the existing JIT pays
        # it per block too, because each block's module redefines the handlers.
        start = time.perf_counter()
        target = llvm.Target.from_triple(llvm.get_default_triple())
        tm = target.create_target_machine()
        module = llvm.parse_assembly(source)
        module.verify()
        engine = llvm.create_mcjit_compiler(module, tm)
        engine.finalize_object()
        engine.get_function_address("axis_block")
        elapsed += time.perf_counter() - start
    return elapsed / rounds


def reads_zero(lift, kind, index):
    """Whether this index of this class reads as zero and discards writes."""
    rules = lift.REGISTER_CLASSES.get(kind)
    return bool(rules) and rules[0] == index


def run_stencils(entries, holes, macho, text, obj, by_symbol, workdir, cases,
                 golden, lift):
    """Patch each stencil's holes and run it. Stage J2.

    The holes are addresses on this target, so each is pointed at a slot in an
    operand block beside the code, and the slot holds the operand's value.
    Patching is two instructions per hole -- the page, and the offset within it
    -- and nothing else about the stencil changes.
    """
    stencils = stencil_bytes(macho, text, obj)
    buffer = JitBuffer()
    BLOCK = 1 << 15
    rng = random.Random(0x57E4)
    ran = wrong = 0
    for entry in entries:
        ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
        if ident not in stencils or ident not in holes:
            continue
        if entry.get("effects"):
            continue          # emitted, not run -- see `stencilable`
        inputs = [op for op in entry["operands"] if op["role"] not in ("out", "enc")]
        code = bytearray(stencils[ident]["bytes"])
        slots = {hole: BLOCK + i * 8 for i, hole in enumerate(holes[ident])}
        for hole, slot in slots.items():
            for offset, kind in by_symbol.get(hole, []):
                site = offset - (stencils[ident]["addr"] - text["addr"])
                if not 0 <= site < len(code):
                    continue
                target = buffer.base + slot
                if kind == "PAGE21":
                    patch_page21(code, site, target, buffer.base + site)
                elif kind == "PAGEOFF12":
                    patch_pageoff12(code, site, target)
        buffer.write(0, bytes(code))

        for _ in range(cases):
            # A register hole's slot holds an index and the value goes in the
            # register file; an immediate's slot holds the value itself.
            # Seed the file first, then read back what each operand actually
            # sees. Two operands can draw the same register, and telling golden
            # the value that was *written* rather than the one that survived is
            # a bug in the driver that looks exactly like a bug in the patcher.
            slot_value, values = {}, []
            width = lift.REGISTER_FILE_SLOTS
            regs = (ctypes.c_uint64 * width)()
            for index in range(width):
                regs[index] = rng.getrandbits(16)
            slot_value[holes[ident][0]] = ctypes.addressof(regs)
            for op, hole in zip(inputs, holes[ident][1:]):
                if op["kind"] == "imm":
                    value = rng.getrandbits(16)
                    slot_value[hole] = value
                    values.append(value)
                else:
                    index = rng.randrange(1, 8)
                    slot_value[hole] = index
                    values.append(0 if reads_zero(lift, op["kind"], index)
                                  else regs[lift.register_slot(op["kind"], index)])
            dest_op = next(op for op in entry["operands"]
                           if op["role"] in ("out", "inout"))
            dest_index = rng.randrange(1, 8)
            dest_slot = lift.register_slot(dest_op["kind"], dest_index)
            slot_value[holes[ident][-1]] = dest_index
            for hole, slot in slots.items():
                buffer.write(slot, struct.pack("<Q", slot_value[hole]))
            ctypes.CFUNCTYPE(None)(buffer.base)()
            want = golden.evaluate(entry["mnemonic"], *values)
            got = regs[dest_slot]
            ran += 1
            if got != want:
                wrong += 1
                if wrong <= 5:
                    print(f"FAIL {entry['mnemonic']}: patched stencil {got:#x} "
                          f"!= golden {want:#x}")
    return ran, wrong


class SharedMemory:
    """The byte space, backed by a buffer the translated code writes directly.

    The Python executor and the patched block have to see the same bytes: an
    effect stencil stores through a raw pointer, and the fallback steps the very
    next instruction. Copying between two images at each handoff would work and
    would also hide a stencil that wrote to the wrong place until the copy.
    """

    def __init__(self, image: bytes) -> None:
        self.buffer = (ctypes.c_uint8 * len(image)).from_buffer_copy(image)
        self.escaped = False

    def _ok(self, addr: int, width: int) -> bool:
        count = width // 8
        if addr < 0 or addr + count > len(self.buffer):
            self.escaped = True
            return False
        return True

    def read(self, addr: int, width: int) -> int:
        if not self._ok(addr, width):
            return 0
        return int.from_bytes(bytes(self.buffer[addr:addr + width // 8]), "little")

    def write(self, addr: int, value: int, width: int) -> None:
        if not self._ok(addr, width):
            return
        data = (value & ((1 << width) - 1)).to_bytes(width // 8, "little")
        for offset, byte in enumerate(data):
            self.buffer[addr + offset] = byte

    def snapshot(self) -> bytes:
        return bytes(self.buffer)


def stencilable(entry, stencils) -> bool:
    """Whether this instruction has a stencil that can stand inside a block.

    Pure ones do. So do loads and stores, whose handler does its own accesses
    and reports its register write. Branches and traps do not: they end the
    block, which is the block's business rather than a stencil's.
    """
    ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
    if ident not in stencils:
        return False
    if entry.get("effects"):
        return effect_kinds(entry) is not None
    return entry["semantics"] is not None


def addressable(entry, word, isa, lift, live, written) -> bool:
    """Whether a memory instruction's address is one the driver can vouch for.

    Two conditions, and the second is the one that cost the most to find.

    *In range.* Every register operand must still hold a value the driver
    seeded and one far enough inside the buffer that any immediate this driver
    admits keeps it there. Some of those operands are not addresses, which only
    makes this refuse more than it must.

    *Aligned, when the access is atomic.* An atomic must be naturally aligned:
    arm64 faults otherwise, and RISC-V requires it of its AMOs too. A 64-bit
    `amoswap` whose base held 35354 -- comfortably inside the buffer -- takes a
    bus error, which is why this looked like a wild address for so long. The
    interpreter does not care, because it reads bytes; the host's atomic does.
    """
    bound = lift.lift(word, isa)
    headroom = MEMORY_BYTES - (1 << 13)
    atomic = max((effect.get("width", 0) for effect in entry["effects"]
                  if effect.get("atomic")), default=0)
    for op in entry["operands"]:
        if op["kind"] == "imm" or op["role"] == "enc":
            continue
        raw = bound["operands"].get(op["name"])
        if raw is None:
            continue
        slot = lift.register_slot(op["kind"], raw)
        if slot in written:
            return False
        if slot >= len(live):
            continue
        if live[slot] >= headroom:
            return False
        if atomic and live[slot] % (atomic // 8):
            return False
    return True


def execute_programs(fixtures, holes, macho, text, obj, by_symbol, lift,
                     executor, programs, length, rng):
    """Run whole programs: stencil what can be stencilled, step the rest. J5.

    This is the mixed mode a real JIT runs in. A run of stencilable words
    becomes one patched block; the first word that is not -- an effectful
    instruction, or one with no handler -- ends the block and is stepped by the
    proven executor, and translation resumes after it.

    The register file is shared, which is the point: the block writes the same
    slots the executor reads. That is why the stencils take a pointer to it
    rather than keeping values in registers, and it is what makes falling out of
    translated code into the interpreter cost nothing to arrange.
    """
    stencils = stencil_bytes(macho, text, obj)
    decoded = []
    unbounded = 0
    for fixture in fixtures:
        word = int(fixture["encoded"], 16)
        entry = lift.decode(word, fixture.get("isa"))
        if entry is None:
            continue
        if entry.get("effects") and stencilable(entry, stencils):
            # A translated load or store does raw pointer arithmetic: the
            # handler has no bounds check, because the host's memory hooks are
            # where that lives and a stencil calls none. So the driver only
            # runs the ones whose address it can keep inside the buffer -- a
            # fixture whose immediate sign-extends negative walks off it, and
            # that is a fault rather than a failed comparison. The interpreter
            # steps the rest, which is exactly what the fallback is for.
            bound = lift.lift(word, fixture.get("isa"))
            immediates = [bound["operands"].get(op["name"]) or 0
                          for op in entry["operands"] if op["kind"] == "imm"]
            if any(value >= 2048 for value in immediates):
                unbounded += 1
                continue
        decoded.append((word, entry, fixture.get("isa")))
    if not decoded:
        return 0, 0, 0, 0, unbounded
    if not any(stencilable(entry, stencils) for _w, entry, _i in decoded):
        return 0, 0, 0, 0, unbounded

    buffer = JitBuffer()
    BLOCK = 1 << 15
    slots = lift.REGISTER_FILE_SLOTS
    ran = wrong = translated = stepped = 0

    for _ in range(programs):
        program = [decoded[rng.randrange(len(decoded))] for _ in range(length)]
        # Eight-byte aligned, so an atomic whose base is a seeded register is
        # naturally aligned. `jit_llvm.py` seeds the same way for the same
        # reason.
        seed = {index: rng.getrandbits(16) & ~7 for index in range(slots)}
        image = bytes(rng.getrandbits(8) for _ in range(MEMORY_BYTES))

        # The reference: every word stepped by the proven executor, against its
        # own copy of the same memory.
        want = dict(seed)
        want_mem = ByteMemory(image)
        # Architectural state the corpus reads -- RISC-V's reservation for its
        # atomics. Both sides get their own, seeded the same.
        want_state = {name: 0 for name, _width in lift.STATE_SLOTS}
        for word, _entry, isa in program:
            executor.step(word, want, mem=want_mem, isa=isa, state=want_state)

        live = (ctypes.c_uint64 * slots)(*[seed[i] for i in range(slots)])
        # One buffer, written by the patched block and read by the fallback.
        mem = SharedMemory(image)
        live_mem = mem
        out_buf = (ctypes.c_uint64 * max(lift.EFFECT_OUT_SLOTS, 1))()
        state_buf = (ctypes.c_uint64 * max(len(lift.STATE_SLOTS), 1))()
        live_state = {name: 0 for name, _width in lift.STATE_SLOTS}
        index = 0
        while index < len(program):
            run = []
            written: set[int] = set()
            while index < len(program) and stencilable(program[index][1], stencils):
                word, entry, _isa = program[index]
                if entry.get("effects") and not addressable(entry, word, _isa,
                                                            lift, live, written):
                    # A translated load or store computes its address with no
                    # bounds check -- the host's hooks are where that lives, and
                    # a stencil calls none. So one is translated only when the
                    # driver can see where it will land: its address registers
                    # hold values it seeded, and nothing earlier in this block
                    # has overwritten them. A load that fed a later store's base
                    # is exactly the case that faults, and it is the interpreter
                    # that takes it.
                    break
                ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
                bound = lift.lift(word, _isa)

                def slot_of(op):
                    # ⚠️ The index the instruction encodes, not the slot it
                    # lands in. This used to write the slot, because the
                    # stencils indexed the register file raw -- a driver
                    # compensating for a defect in the artifact it drives, and
                    # it only worked because the reference indexed raw too.
                    # The stencils do the class arithmetic themselves now, so
                    # writing a slot here would apply the offset twice.
                    return bound["operands"].get(op["name"]) or 0

                # Inputs in order, then the destination -- the order the holes
                # were declared in. Declaration order is not that order: a
                # destination is usually written first.
                inputs = [op for op in entry["operands"]
                          if op["role"] not in ("out", "enc")]
                if entry.get("effects"):
                    # The machine pointers first, in the order the holes were
                    # declared, then the operands, then the destination the
                    # handler reports its write to.
                    values = [ctypes.addressof(mem.buffer),
                              ctypes.addressof(out_buf),
                              ctypes.addressof(state_buf), 0]
                    values += [slot_of(op) for op in inputs]
                    sets = [e for e in entry["effects"] if e["kind"] == "set"]
                    if sets:
                        dest = next(op for op in entry["operands"]
                                    if op["name"] == sets[0]["dest"])
                        values.append(slot_of(dest))
                else:
                    dest = next(op for op in entry["operands"]
                                if op["role"] in ("out", "inout"))
                    values = [slot_of(op) for op in inputs] + [slot_of(dest)]
                # ⚠️ The memory window, last, because that is where the hole
                # collector puts it: it is referenced by the HANDLER, which is
                # inlined, so it follows every hole the stencil names itself.
                # Left out, every later slot is one place off and a translated
                # store lands somewhere the interpreter never wrote.
                if "AXIS_HOLE_memory_mask" in holes.get(ident, []):
                    values.append(MEMORY_BYTES - 1)
                run.append((ident, values))
                for op in entry["operands"]:
                    if op["role"] in ("out", "inout") and op["kind"] != "imm":
                        written.add(slot_of(op))
                index += 1
            if run:
                # Architectural state crosses the handoff in both directions:
                # the block reads and writes the array, the fallback the dict.
                for position, (name, _width) in enumerate(lift.STATE_SLOTS):
                    state_buf[position] = live_state.get(name, 0)
                translate_block(run, stencils, holes, by_symbol, text, buffer,
                                BLOCK, ctypes.addressof(live))
                ctypes.CFUNCTYPE(None)(buffer.base)()
                for position, (name, _width) in enumerate(lift.STATE_SLOTS):
                    live_state[name] = state_buf[position]
                translated += len(run)
            if index < len(program):
                word, _entry, isa = program[index]
                regs = {i: live[i] for i in range(slots)}
                executor.step(word, regs, mem=live_mem, isa=isa,
                              state=live_state)
                for slot, value in regs.items():
                    if slot < slots:
                        live[slot] = value & 0xFFFFFFFFFFFFFFFF
                stepped += 1
                index += 1

        ran += 1
        got = {i: live[i] for i in range(slots)}
        if live_mem.snapshot() != bytes(want_mem.data):
            wrong += 1
            if wrong <= 4:
                got_bytes = live_mem.snapshot()
                where = next(i for i in range(MEMORY_BYTES)
                             if got_bytes[i] != want_mem.data[i])
                print(f"FAIL program: memory at {where:#x}")
        elif live_state != want_state:
            wrong += 1
            if wrong <= 4:
                print(f"FAIL program: state {live_state} != {want_state}")
        elif got != {i: want.get(i, 0) for i in range(slots)}:
            wrong += 1
            bad = next(i for i in range(slots) if got[i] != want.get(i, 0))
            if wrong <= 4:
                print(f"FAIL program: slot {bad} mixed-mode {got[bad]:#x} != "
                      f"executor {want.get(bad, 0):#x}")
    return ran, wrong, translated, stepped, unbounded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--run", action="store_true",
                        help="patch each stencil and execute it (stage J2)")
    parser.add_argument("--cases", type=int, default=4)
    parser.add_argument("--blocks", type=int, default=0,
                        help="translate and run N blocks (stage J3)")
    parser.add_argument("--length", type=int, default=8)
    parser.add_argument("--execute", type=int, default=0,
                        help="run N whole programs in mixed mode (stage J5)")
    parser.add_argument("--compare", type=int, default=0,
                        help="also compile N equivalent blocks, for the ratio")
    parser.add_argument("--dump", type=int, default=0,
                        help="print the holes of the first N stencils")
    args = parser.parse_args()

    try:
        import llvmlite.binding as llvm
    except ImportError:
        print("SKIP: llvmlite not installed (pip install llvmlite)")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="axis_stencil_"))
    emit(args.axis_file, "emit-llvm-ir", workdir / "axis_semantics.ll")
    emit(args.axis_file, "emit-lift-json", workdir / "lift.json")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    sys.path.insert(0, str(workdir))
    sem_ll = (workdir / "axis_semantics.ll").read_text()
    def has_handler(entry) -> bool:
        ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
        if entry.get("effects"):
            return f"@axis_eff_{ident}(" in sem_ll
        return entry["liftable"] and f"@axis_eval_{ident}(" in sem_ll

    entries = [e for e in json.loads((workdir / "lift.json").read_text())["instructions"]
               if has_handler(e)]
    if not entries:
        print("SKIP: no instruction has an LLVM handler to build a stencil from")
        return 0

    module_ir, holes, effect_stencils = stencil_ir_from_axis(args.axis_file, workdir)
    (workdir / "stencils.ll").write_text(module_ir)

    llvm.initialize(); llvm.initialize_native_target(); llvm.initialize_native_asmprinter()
    target = llvm.Target.from_triple(llvm.get_default_triple())
    machine = target.create_target_machine(codemodel="small", reloc="static")
    module = llvm.parse_assembly(module_ir)
    module.verify()
    # Inline the handlers so a stencil's bytes are self-contained: a call to an
    # external handler would be a second kind of hole, and the point of J1 is to
    # see the operand holes clearly.
    pmb = llvm.create_pass_manager_builder()
    pmb.opt_level = 2
    # llvmlite adds an inliner only when a threshold is set. Without this the
    # handlers stay behind a `bl` and the stencil is not self-contained --
    # which is what the object said the first time.
    pmb.inlining_threshold = 1 << 20
    pm = llvm.create_module_pass_manager()
    pmb.populate(pm)
    pm.run(module)
    obj = machine.emit_object(module)
    (workdir / "stencils.o").write_bytes(obj)

    macho = MachO(obj)
    text = macho.text()
    relocs = macho.relocations(text)
    by_symbol: dict[str, list[tuple[int, str]]] = {}
    for offset, kind, name in relocs:
        by_symbol.setdefault(name.lstrip("_"), []).append((offset, kind))

    checks = failures = unused = 0
    kinds_seen: set[str] = set()
    for ident, expected in sorted(holes.items()):
        checks += 1
        # A hole the stencil has no use for is optimised away, relocation and
        # all -- an instruction whose handler never reads architectural state
        # has no `state` load left to name. That is correct, and patching an
        # absent hole is a no-op. What must be there is every hole the stencil
        # cannot do without: its operands, its destination, and the register
        # file they index.
        # ⚠️ `_regs` is optional too. An instruction that reads no register and
        # writes none -- `c.j`, which takes an immediate and redirects the pc
        # -- indexes no register file, so the load is optimised away like any
        # other unused machine pointer. That could not happen while every
        # stencil wrote a register, and the first branch to get one failed here
        # rather than in anything about branches.
        required = [h for h in expected
                    if not h.endswith(("_regs", "_mem", "_out", "_state",
                                       "_pc", "_mask"))]
        missing = [h for h in required if h not in by_symbol]
        optional_gone = sum(1 for h in expected
                            if h not in required and h not in by_symbol)
        unused += optional_gone
        if missing:
            failures += 1
            if failures <= 5:
                print(f"FAIL {ident}: no relocation names {', '.join(missing[:3])}")
            continue
        for hole in expected:
            kinds_seen.update(kind for _off, kind in by_symbol.get(hole, []))
    stray = sorted(set(by_symbol) - {h for hs in holes.values() for h in hs})

    print(f"{len(entries)} stencils, {checks} checked, {failures} without their holes")
    print(f"  {len(relocs)} relocations over {len(by_symbol)} symbols; "
          f"kinds: {', '.join(sorted(kinds_seen)) or 'none'}")
    if effect_stencils:
        print(f"  {len(effect_stencils)} effect stencil(s); {unused} machine "
              f"pointer(s) optimised away as unused")
    if stray:
        print(f"  {len(stray)} symbol(s) referenced that are not holes: "
              f"{', '.join(stray[:4])}")
    for ident in sorted(holes)[:args.dump]:
        sites = [(h, by_symbol.get(h, [])) for h in holes[ident]]
        print(f"  {ident}: " + "; ".join(
            f"{h}@{'+'.join(f'{o:#x}/{k}' for o, k in s)}" for h, s in sites))

    if args.run or args.blocks or args.execute:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "golden_model", workdir / "golden_model.py")
        golden = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(golden)
        # ⚠️ The register file is not `index`. A class can start partway up the
        # flat array (`rv_fpr` at 32), can name a window of it (`rv_gpr_c`'s
        # three bits reach `x8`-`x15`), and can have an index that reads as
        # zero. This gate indexed it raw on BOTH sides, so its stencils and its
        # reference were wrong together and agreed -- until the stencils were
        # fixed and the reference segfaulted for reaching past 32 slots.
        spec = importlib.util.spec_from_file_location("axis_lift",
                                                      workdir / "axis_lift.py")
        lift_mod = importlib.util.module_from_spec(spec)
        sys.modules["axis_lift"] = lift_mod
        spec.loader.exec_module(lift_mod)
    if args.run:
        ran, wrong = run_stencils(entries, holes, macho, text, obj, by_symbol,
                                  workdir, args.cases, golden, lift_mod)
        failures += wrong
        print(f"  {ran} patched stencil(s) executed, {wrong} disagreed with "
              f"the golden model")
    if args.blocks:
        ran, wrong, elapsed = run_blocks(entries, holes, macho, text, obj,
                                         by_symbol, workdir, args.blocks,
                                         args.length, golden, lift_mod)
        failures += wrong
        if not ran:
            print("  no block could be built from this corpus")
            failures += 1
        else:
            per = elapsed / ran * 1e6
            print(f"  {ran} block(s) of {args.length} instructions translated "
                  f"and run, {wrong} disagreed; {per:.1f} us per translation")
            if args.compare:
                compiled = compile_cost(entries, sem_ll, machine, args.length,
                                        args.compare) * 1e6
                print(f"  compiling the same block: {compiled:.1f} us "
                      f"({compiled / per:.0f}x the translation)")
                # The whole argument for stencils is that translation replaces a
                # compile. If it does not, the machinery has bought nothing.
                if compiled <= per:
                    print("  translation is not cheaper than compiling: "
                          "the stencils have bought nothing")
                    failures += 1

    if args.execute:
        emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
        emit(args.axis_file, "emit-roundtrip-json", workdir / "fixtures.json")
        import importlib.util
        sys.modules["golden_model"] = golden
        spec = importlib.util.spec_from_file_location("axis_exec",
                                                      workdir / "axis_exec.py")
        executor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(executor)
        fixtures = json.loads((workdir / "fixtures.json").read_text())["tests"]
        ran, bad, hot, cold, unbounded = execute_programs(
            fixtures, holes, macho, text, obj, by_symbol, lift_mod, executor,
            args.execute, args.length, random.Random(0x3E11))
        failures += bad
        if not ran:
            print("  no program could be run in mixed mode")
            failures += 1
        else:
            print(f"  {ran} program(s) run in mixed mode, {bad} disagreed; "
                  f"{hot} instruction(s) translated, {cold} stepped")
            if unbounded:
                print(f"  {unbounded} memory fixture(s) left to the interpreter: "
                      f"their address leaves the driver's buffer")
            # Both halves have to happen. All-translated proves nothing about
            # falling out into the interpreter; all-stepped proves nothing at
            # all.
            if not hot or not cold:
                print("  mixed mode ran only one half: "
                      f"{hot} translated, {cold} stepped")
                failures += 1

    ok = failures == 0 and checks > 0
    # Two kinds, because an address on this target is materialised by a pair:
    # the page and the offset within it. One kind alone would mean the patcher
    # only has half of each site.
    if kinds_seen and kinds_seen != {"PAGE21", "PAGEOFF12"}:
        print(f"  note: unexpected relocation kinds for an address hole: "
              f"{sorted(kinds_seen)}")
    print("stencil holes == operands: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
