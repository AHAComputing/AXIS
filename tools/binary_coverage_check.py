#!/usr/bin/env python3
"""`binary_coverage.py` reads objects correctly and loses no instruction.

Coverage against a real binary is a measurement, so there is nothing to assert
about the number. What can be wrong is everything around it: a section header
misread, an offset taken from the wrong field, a universal binary's wrong slice
chosen, words assembled in the wrong byte order -- each of which shows up as a
*lower* coverage number that looks like an honest finding about the corpus.

That failure mode is why this builds the object files itself. An image whose
executable section is exactly the words of a description's own roundtrip
fixtures must come back **100% decoded**. A miss is then unambiguous: the words
were checked to decode when handed straight to the binding, so a word that
misses after a trip through an object file was not delivered intact.

Pre-filtering with the decoder under test is not circular. The decoder's answer
for a given word is held fixed on both sides of the comparison; the only thing
that varies is whether the bytes arrived. Two kinds of word are dropped, and
counted rather than hidden: those an ISA shares with another ISA in the same
description, and those two instructions of one ISA share -- `vliw_packet` has
`VSTW` and `VBRZ` on one word, told apart by slot, which a bare 32-bit decode
cannot do and should not pretend to.

Both formats are built, ELF64 and Mach-O, because the reader has two paths and
the host only exercises one. The Mach-O is also wrapped in a universal binary,
since choosing a slice is its own way to read the wrong bytes.

Usage: tools/binary_coverage_check.py [<input.axisl> ...]  (default: a spread)
"""

from __future__ import annotations

import collections
import json
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED, axis_prefix
from axis_decode_ffi import load
from binary_coverage import Unreadable, report

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: A spread of shapes rather than every corpus: this checks the object readers,
#: which do not vary by corpus, so the corpora chosen are the ones whose words
#: differ most -- two ISAs in one description, scalable lanes, and RISC-V.
DEFAULT = ("aarch64_translation_seed.axisl", "rv64i.axisl", "sve.axisl",
           "rv32i.axisl", "vliw_packet.axisl")

TEXT_ADDRESS = 0x100000000


def build_elf(words: list[int]) -> bytes:
    """A minimal ELF64 whose one executable section holds `words`."""
    return build_elf_bytes(b"".join(word.to_bytes(4, "little") for word in words))


def build_elf_bytes(text: bytes) -> bytes:
    """The same, over bytes -- so a section can hold something that is not a
    whole number of four-byte instructions."""
    names = b"\0.text\0.shstrtab\0"
    text_off = 64
    strtab_off = text_off + len(text)
    shoff = strtab_off + len(names)
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4], header[5], header[6] = 2, 1, 1            # 64-bit, LE, version
    struct.pack_into("<HHI", header, 16, 2, 183, 1)      # ET_EXEC, AArch64
    struct.pack_into("<Q", header, 40, shoff)
    struct.pack_into("<HHHHHH", header, 52, 64, 0, 0, 64, 3, 2)
    def section(name_off, kind, flags, addr, offset, size):
        return struct.pack("<IIQQQQIIQQ", name_off, kind, flags, addr, offset,
                           size, 0, 0, 4, 0)
    sections = (section(0, 0, 0, 0, 0, 0)
                + section(1, 1, 0x4 | 0x2, TEXT_ADDRESS, text_off, len(text))
                + section(7, 3, 0, 0, strtab_off, len(names)))
    return bytes(header) + text + names + sections


def build_macho(words: list[int], *, fat: bool = False) -> bytes:
    """A minimal 64-bit Mach-O, optionally wrapped as a universal binary."""
    text = b"".join(word.to_bytes(4, "little") for word in words)
    command_size = 72 + 80
    text_off = 32 + command_size
    header = struct.pack("<IiiIIII I", 0xFEEDFACF, 0x0100000C, 0, 2, 1,
                         command_size, 0, 0)
    segment = struct.pack("<II16sQQQQiiII", 0x19, command_size, b"__TEXT",
                          TEXT_ADDRESS, len(text), text_off, len(text),
                          7, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT",
                          TEXT_ADDRESS, len(text), text_off, 2, 0, 0,
                          0x80000400, 0, 0, 0)
    thin = header + segment + section + text
    if not fat:
        return thin
    # Two slices, the wanted one second, so picking the first is a failure
    # rather than an accident that happens to work.
    offset = 4096
    decoy = b"\0" * 64
    fat_header = struct.pack(">II", 0xCAFEBABE, 2)
    fat_header += struct.pack(">iiIII", 0x01000007, 3, offset, len(decoy), 12)
    fat_header += struct.pack(">iiIII", 0x0100000C, 0, offset + 4096,
                              len(thin), 12)
    image = bytearray(offset + 4096 + len(thin))
    image[0:len(fat_header)] = fat_header
    image[offset:offset + len(decoy)] = decoy
    image[offset + 4096:offset + 4096 + len(thin)] = thin
    return bytes(image)


def widths_of(axis_file: Path, isa) -> set:
    """Every instruction width the description gives this ISA.

    One width means a shift of anything but that width is a misalignment.
    More than one means the stream is self-delimiting and a short instruction
    in the middle of it is just a short instruction.
    """
    result = subprocess.run([*axis_prefix(), "emit-decode-json", str(axis_file)],
                            capture_output=True, text=True, check=True,
                            cwd=AXIS_ROOT)
    rows = json.loads(result.stdout)["instructions"]
    return {row["bits"] for row in rows
            if isa is None or (row.get("isa") or None) == isa}


def fixture_words(axis_file: Path, decoder) -> tuple[dict, int]:
    """Fixture words grouped by ISA, keeping only those that decode when handed
    straight to the binding. Returns the groups and how many were dropped."""
    result = subprocess.run([*axis_prefix(), "emit-roundtrip-json", str(axis_file)],
                            capture_output=True, text=True, check=True,
                            cwd=AXIS_ROOT)
    document = json.loads(result.stdout)
    groups: dict = collections.defaultdict(list)
    dropped = 0
    for test in document["tests"]:
        word = int(test["encoded"], 16)
        isa = test.get("isa", "") or None
        if decoder.decode(word, isa) is None:
            dropped += 1
            continue
        groups[isa].append(word)
    return dict(groups), dropped


def check(axis_file: Path) -> int:
    decoder = load(axis_file)
    groups, dropped = fixture_words(axis_file, decoder)
    total = sum(len(words) for words in groups.values())
    if not total:
        print(f"{axis_file.name}: no fixture word decodes on its own, so an "
              f"image would prove nothing about reading -> DECLINE")
        return DECLINED
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        for isa, words in sorted(groups.items(), key=lambda item: item[0] or ""):
            images = {"ELF64": build_elf(words),
                      "Mach-O": build_macho(words),
                      "Mach-O universal": build_macho(words, fat=True)}
            for label, image in images.items():
                path = workdir / f"{isa or 'any'}-{label.replace(' ', '_')}"
                path.write_bytes(image)
                try:
                    summary = report(axis_file, path, isa, None, None, top=4)
                except Unreadable as reason:
                    failures.append(f"{isa} {label}: {reason}")
                    continue
                if len(summary["sections"]) != 1:
                    failures.append(f"{isa} {label}: found "
                                    f"{len(summary['sections'])} executable "
                                    f"sections, built 1")
                    continue
                section = summary["sections"][0]
                if section["words"] != len(words):
                    failures.append(f"{isa} {label}: read {section['words']} "
                                    f"words, wrote {len(words)}")
                if section["undecoded"]:
                    failures.append(
                        f"{isa} {label}: {section['undecoded']} of "
                        f"{section['words']} words did not survive the image "
                        f"(first {section['top_undecoded'][:2]})")
        # The wrong-stride detector, which is its own piece of logic and can
        # be wrong in both directions. A clean image of 4-byte instructions
        # must not trip it; the same image with two bytes wedged into the
        # middle -- what one `c.nop` pad does to a RISC-V section -- must.
        #
        # That second half only means anything for an ISA whose instructions
        # are all one width. Once RVC is described, two bytes wedged into a
        # RISC-V section are not a misalignment at all: `0x0001` is `c.nop`,
        # the walk consumes two bytes for it, and every later instruction is
        # back on its own boundary. There is nothing to detect, and a detector
        # that fired would be wrong. So the wedge is only asserted where a
        # shift is genuinely a shift.
        widest_isa = max(groups.items(), key=lambda item: len(item[1]))
        isa, words = widest_isa
        uniform_width = len(widths_of(axis_file, isa)) == 1
        if len(words) >= 8:
            clean = workdir / "stride-clean"
            clean.write_bytes(build_elf(words))
            if "misaligned" in report(axis_file, clean, isa, None, None)["sections"][0]:
                failures.append("the stride detector fired on an image that is "
                                "all four-byte instructions")
            body = b"".join(word.to_bytes(4, "little") for word in words)
            half = (len(body) // 8) * 4
            skewed = workdir / "stride-skewed"
            skewed.write_bytes(build_elf_bytes(body[:half] + b"\x01\x00" + body[half:]))
            section = report(axis_file, skewed, isa, None, None)["sections"][0]
            if uniform_width and "misaligned" not in section:
                failures.append(f"the stride detector missed two bytes wedged "
                                f"into the middle of {len(words)} instructions "
                                f"(it reported {section['coverage']}% and said "
                                f"nothing)")

    if failures:
        print(f"{axis_file.name}: {len(failures)} reader failure(s) -> FAIL")
        for line in failures[:6]:
            print(f"     {line}")
        return FAILED
    shared = f", {dropped} shared word(s) dropped" if dropped else ""
    print(f"{axis_file.name}: {total} word(s) in {len(groups)} ISA(s) recovered "
          f"from ELF64, Mach-O and universal images{shared} -> PASS")
    return PASSED


def main() -> int:
    files = [Path(arg) for arg in sys.argv[1:]] or [
        AXIS_ROOT / "examples" / name for name in DEFAULT]
    results = [check(axis_file) for axis_file in files]
    checked = results.count(PASSED)
    print(f"{len(results)} description(s): {checked} recovered from built images, "
          f"{results.count(DECLINED)} with no fixtures, "
          f"{results.count(FAILED)} failing")
    if FAILED in results:
        print("BINARY COVERAGE CHECK FAILED")
        return FAILED
    if not checked:
        print("BINARY COVERAGE CHECK DECLINED: no description built an image")
        return DECLINED
    print("BINARY COVERAGE CHECK PASSED")
    return PASSED


if __name__ == "__main__":
    sys.exit(main())
