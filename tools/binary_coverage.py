#!/usr/bin/env python3
"""What a real binary contains that a description does not.

AXISMINE's caveat 4 is that a kernel corpus cannot exercise what a real binary
has: the instructions nobody wrote a benchmark for are exactly the ones a
description is most likely to be missing. The way to retire that caveat is to
decode a binary nobody compiled for the experiment and report what did not
decode.

    tools/binary_coverage.py examples/aarch64_translation_seed.axisl /bin/ls

    /bin/ls __text: 15252 bytes, 3813 words
      3318 decoded (87.0%), 495 not
      top decoded:   adrp=380, add_x_imm_sp=372, bl=275, ...
      top undecoded: 0x52800028 x52, 0xd503237f x35, ...

Coverage is a **measurement, not a contract**: a seed corpus decoding 87% of a
system binary is a fact about the corpus, and this tool prints it rather than
judging it. What it does assert -- see `binary_coverage_check.py` -- is that its
own object readers and its decode path are right, by rebuilding an image out of
a description's own roundtrip fixtures and requiring every word back.

Object formats: ELF64 and Mach-O (thin or universal), little-endian, which is
what AArch64 and RISC-V images are. A format it cannot read is said, not
guessed at.

**One instruction is four bytes here**, because that is what AXIS describes: the
generated decoder takes a `uint32_t`. A stream holding anything else -- a RISC-V
image built with the C extension, where a 2-byte `c.nop` pad shifts everything
after it -- misaligns, and every later word decodes to nothing. That produces a
low coverage number that looks like a finding about the description and is
really a finding about this walk, so it is not left to be misread: every report
probes the other byte offsets and says so when one of them does better.
"""

from __future__ import annotations

import argparse
import collections
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_decode_ffi import load  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ELF_MAGIC = b"\x7fELF"
MACHO_64 = 0xFEEDFACF
MACHO_FAT = 0xCAFEBABE
#: Mach-O CPU types worth naming when a universal binary offers a choice.
MACHO_CPUS = {0x0100000C: "arm64", 0x01000007: "x86_64", 0x0000000C: "arm"}
#: SHF_EXECINSTR -- the ELF flag that says a section holds instructions.
SHF_EXECINSTR = 0x4


class Unreadable(Exception):
    """The file is not an object file this tool claims to read."""


def elf_sections(data: bytes):
    """Executable sections of an ELF64 image, as (name, bytes, address)."""
    if data[4] != 2 or data[5] != 1:
        raise Unreadable("only 64-bit little-endian ELF is read here")
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if not shoff or not shnum:
        raise Unreadable("the ELF has no section headers")
    def header(index):
        return struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)
    _, _, _, _, stroff, strsize, *_ = header(shstrndx)
    strings = data[stroff:stroff + strsize]
    found = []
    for index in range(shnum):
        name_off, _, flags, addr, offset, size, *_ = header(index)
        if not flags & SHF_EXECINSTR or not size:
            continue
        end = strings.find(b"\0", name_off)
        name = strings[name_off:end].decode(errors="replace")
        found.append((name, data[offset:offset + size], addr))
    return found


def macho_sections(data: bytes, arch: str | None = None):
    """Executable sections of a Mach-O image, thin or universal."""
    magic, = struct.unpack_from(">I", data, 0)
    if magic == MACHO_FAT:
        count, = struct.unpack_from(">I", data, 4)
        slices = {}
        for index in range(count):
            cpu, _, offset, size, _ = struct.unpack_from(">iiIII", data, 8 + index * 20)
            slices[MACHO_CPUS.get(cpu, f"cpu{cpu:#x}")] = (offset, size)
        if not slices:
            raise Unreadable("the universal binary contains no architectures")
        # A universal binary is several images. Guessing wrong would report
        # coverage for the wrong one, so prefer a named arch, then arm64.
        chosen = arch or ("arm64" if "arm64" in slices else next(iter(slices)))
        if chosen not in slices:
            raise Unreadable(f"no {chosen} in this universal binary "
                             f"({', '.join(sorted(slices))})")
        offset, size = slices[chosen]
        return macho_sections(data[offset:offset + size])
    if struct.unpack_from("<I", data, 0)[0] != MACHO_64:
        raise Unreadable("only 64-bit little-endian Mach-O is read here")
    ncmds, = struct.unpack_from("<I", data, 16)
    position, found = 32, []
    for _ in range(ncmds):
        command, size = struct.unpack_from("<II", data, position)
        if command == 0x19:                                   # LC_SEGMENT_64
            nsects, = struct.unpack_from("<I", data, position + 64)
            at = position + 72
            for _ in range(nsects):
                name = data[at:at + 16].rstrip(b"\0").decode(errors="replace")
                addr, length = struct.unpack_from("<QQ", data, at + 32)
                offset, = struct.unpack_from("<I", data, at + 48)
                flags, = struct.unpack_from("<I", data, at + 64)
                # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
                if flags & 0x80000400 and length:
                    found.append((name, data[offset:offset + length], addr))
                at += 80
        position += size
    return found


def sections_of(path: Path, arch: str | None = None):
    data = path.read_bytes()
    if data[:4] == ELF_MAGIC:
        return "ELF", elf_sections(data)
    if len(data) >= 4 and struct.unpack_from(">I", data, 0)[0] in (MACHO_FAT,):
        return "Mach-O", macho_sections(data, arch)
    if len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == MACHO_64:
        return "Mach-O", macho_sections(data, arch)
    raise Unreadable(f"{path}: not an ELF or Mach-O object file")


def resync_rate(decoder, data: bytes, isa: str | None, limit: int = 1 << 16) -> float:
    """How much of `data` decodes if a word that does not decode is allowed to
    have been two bytes long.

    The fixed four-byte walk is right until the stream holds something shorter:
    one 2-byte `c.nop` pad in a RISC-V image shifts *everything after it*, and
    the coverage number then describes the walk rather than the description. A
    uniform shift cannot detect that, because the misalignment starts partway
    through -- so this walks, and on a miss advances two bytes instead of four.

    It is a **detector, not a decoder**: a greedy resync can land on a word
    that decodes by luck, which is why the result is only ever used to say the
    stride looks wrong, never as a coverage figure. Bounded, since detecting
    this does not need the whole section.
    """
    data = data[:limit]
    even = decoder.decode_bytes(data, isa)
    odd = decoder.decode_bytes(data[2:], isa)
    position, decoded, steps = 0, 0, 0
    while position + 4 <= len(data):
        if position % 4 == 0:
            index = even[position // 4] if position // 4 < len(even) else -1
        else:
            slot = (position - 2) // 4
            index = odd[slot] if 0 <= slot < len(odd) else -1
        steps += 1
        if index >= 0:
            decoded += 1
            position += 4
        else:
            position += 2
    return decoded / steps if steps else 0.0


def report(axis_file: Path, binary: Path, isa: str | None, arch: str | None,
           section: str | None, top: int = 8) -> dict:
    decoder = load(axis_file)
    kind, sections = sections_of(binary, arch)
    if section:
        sections = [item for item in sections if item[0] == section]
    if not sections:
        raise Unreadable(f"{binary}: no executable section"
                         + (f" named {section}" if section else ""))
    summary = {"binary": str(binary), "format": kind, "description":
               decoder.description, "isa": isa, "sections": []}
    for name, data, address in sections:
        indices = decoder.decode_bytes(data, isa)
        resynced = resync_rate(decoder, data, isa)
        words = [int.from_bytes(data[i * 4:i * 4 + 4], "little")
                 for i in range(len(indices))]
        decoded = collections.Counter(decoder.mnemonics[index]
                                      for index in indices if index >= 0)
        missed = collections.Counter(word for word, index in zip(words, indices)
                                     if index < 0)
        hits = sum(decoded.values())
        summary["sections"].append({
            "name": name, "address": address, "bytes": len(data),
            "words": len(indices), "decoded": hits, "undecoded": len(indices) - hits,
            "coverage": round(100.0 * hits / len(indices), 2) if indices else 0.0,
            "top_decoded": [[name, count] for name, count in decoded.most_common(top)],
            "top_undecoded": [[f"0x{word:08x}", count]
                              for word, count in missed.most_common(top)],
            "distinct_undecoded": len(missed),
        })
        rate = hits / len(indices) if indices else 0.0
        # A genuinely four-byte stream gains nothing from resyncing, because
        # there is nothing to resync to. A gain means the stream holds
        # something shorter.
        if resynced > rate + 0.15:
            summary["sections"][-1]["misaligned"] = {
                "coverage": round(100.0 * resynced, 2)}
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--isa", help="which ISA of the description to decode for; "
                                      "required when it carries more than one")
    parser.add_argument("--arch", help="which architecture of a universal binary")
    parser.add_argument("--section", help="only this section")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        summary = report(args.axis_file, args.binary, args.isa, args.arch,
                         args.section)
    except Unreadable as reason:
        print(f"cannot read: {reason}")
        return 2
    if args.json:
        import json
        print(json.dumps(summary, indent=2))
        return 0
    print(f"{summary['binary']} ({summary['format']}) against "
          f"{summary['description']}"
          + (f" isa={summary['isa']}" if summary["isa"] else ""))
    for item in summary["sections"]:
        print(f"  {item['name']} @0x{item['address']:x}: {item['bytes']} bytes, "
              f"{item['words']} words")
        print(f"    {item['decoded']} decoded ({item['coverage']}%), "
              f"{item['undecoded']} not "
              f"({item['distinct_undecoded']} distinct)")
        if item["top_decoded"]:
            print("    top decoded:   " + ", ".join(
                f"{name.lower()}={count}" for name, count in item["top_decoded"]))
        if item["top_undecoded"]:
            print("    top undecoded: " + ", ".join(
                f"{word} x{count}" for word, count in item["top_undecoded"]))
        if "misaligned" in item:
            skew = item["misaligned"]
            print(f"    ! the four-byte stride is wrong for this stream: "
                  f"allowing a word to have been two bytes long reaches "
                  f"{skew['coverage']}%. It holds instructions that are not "
                  f"four bytes (RISC-V compressed, say), which AXIS does not "
                  f"describe, so the number above measures this walk rather "
                  f"than the description.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
