#!/usr/bin/env python3
"""An executable image, as a machine needs it: segments and an entry point.

⚠️ Not the same question `binary_coverage.py` asks. That reads SECTIONS, to say
which bytes of a binary are instructions a description decodes. Running one
needs SEGMENTS -- what the loader maps and where -- and the address to start
at, which sections do not carry. Two readers over one format because they are
two questions; sharing one would mean a coverage report that depended on a
program being loadable.

Reads ELF64 little-endian, which is what RISC-V and AArch64 images are. A format
it cannot read is said, not guessed at.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

#: A loadable segment.
PT_LOAD = 1


class Unreadable(Exception):
    """This file is not an image this can load."""


@dataclass
class Segment:
    address: int
    data: bytes
    #: How many bytes the segment occupies once mapped. ⚠️ `memsz` can exceed
    #: `filesz` -- that is `.bss`, and a loader that copied only the file bytes
    #: would leave a program's zeroed data holding whatever was there before.
    size: int
    writable: bool
    executable: bool


@dataclass
class Image:
    entry: int
    segments: list[Segment]
    machine: int

    def flatten(self, limit: int) -> bytes:
        """The segments laid into one flat memory, zero elsewhere."""
        memory = bytearray(limit)
        for segment in self.segments:
            if segment.address + segment.size > limit:
                raise Unreadable(
                    f"segment at {segment.address:#x} needs {segment.size} byte(s) "
                    f"and the machine has {limit}")
            memory[segment.address:segment.address + len(segment.data)] = segment.data
            # The rest of `memsz` is zero, which `bytearray` already is.
        return bytes(memory)


def read_elf(data: bytes) -> Image:
    if data[:4] != b"\x7fELF":
        raise Unreadable("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise Unreadable("only 64-bit little-endian ELF is read here")
    machine, = struct.unpack_from("<H", data, 0x12)
    entry, = struct.unpack_from("<Q", data, 0x18)
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    if not phoff or not phnum:
        raise Unreadable("the ELF has no program headers, so nothing says what to map")
    segments = []
    for index in range(phnum):
        at = phoff + index * phentsize
        kind, flags = struct.unpack_from("<II", data, at)
        offset, vaddr = struct.unpack_from("<QQ", data, at + 0x08)
        filesz, memsz = struct.unpack_from("<QQ", data, at + 0x20)
        if kind != PT_LOAD or not memsz:
            continue
        segments.append(Segment(
            address=vaddr,
            data=data[offset:offset + filesz],
            size=memsz,
            writable=bool(flags & 0x2),
            executable=bool(flags & 0x1),
        ))
    if not segments:
        raise Unreadable("the ELF has no loadable segment")
    return Image(entry=entry, segments=segments, machine=machine)


def load(path: Path) -> Image:
    return read_elf(Path(path).read_bytes())


def write_elf(path: Path, entry: int, segments: list[tuple[int, bytes]],
              machine: int = 243) -> None:
    """The smallest ELF64 that carries these bytes at these addresses.

    ⚠️ Here so the loader can be tested against a file rather than against the
    function that built it: a gate that fed `read_elf` a structure this module
    made in memory would be checking that two of its own functions agree. 243
    is RISC-V; the value only has to survive the round trip.
    """
    header_size = 0x40
    entry_size = 0x38
    table = header_size + entry_size * len(segments)
    body = bytearray()
    placed = []
    for address, data in segments:
        offset = table + len(body)
        body += data
        placed.append((offset, address, len(data)))
    out = bytearray()
    out += b"\x7fELF\x02\x01\x01\x00" + bytes(8)
    out += struct.pack("<HHI", 2, machine, 1)            # ET_EXEC, machine, v1
    out += struct.pack("<QQQ", entry, header_size, 0)    # entry, phoff, shoff
    out += struct.pack("<IHHHHHH", 0, header_size, entry_size, len(segments),
                       0, 0, 0)
    for offset, address, size in placed:
        out += struct.pack("<II", PT_LOAD, 0x5)          # read + execute
        out += struct.pack("<QQQ", offset, address, address)
        out += struct.pack("<QQQ", size, size, 0x1000)
    out += body
    Path(path).write_bytes(bytes(out))
