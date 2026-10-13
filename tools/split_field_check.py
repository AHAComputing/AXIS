#!/usr/bin/env python3
"""A field split across the word is placed in both halves. Gate.

Some operands do not live in one contiguous run of bits. AArch64's by-element
index is the sharp case: `H` at bit 11 and `L` at bit 21 with the register
between them, and for a halfword element a third bit taken from `M` at bit 20.
The format language says this by mapping INSTRUCTION bits to OPERAND bits, one
entry per slice.

Getting that mapping backwards is silent. A field declared as instruction bits
11..11 carrying operand bits 21..21 is well-formed -- the widths match -- and
places the operand's twenty-second bit, which a two-bit operand does not have.
Every value of the index then encodes identically, as zero.

⚠️ `reference_isa_check` CANNOT SEE THIS, and that is the reason this file
exists rather than a note in that one. It compares AXIS's encoder against a
real assembler over the ROUNDTRIP FIXTURES, and the fixture generator emits
ONE test per instruction. For the by-element instructions that one test has
index zero, which is the single value a misplaced index field still encodes
correctly. The gate agreed with the assembler about nine instructions whose
index went nowhere.

So this drives the emitted encoder table directly, over EVERY value of the
split operand, and asks the assembler what it decoded:

  * **every value decodes to something.** A misplaced slice usually lands on
    bits that belong to another field, and the result is not an instruction;
  * **the values decode DISTINCTLY.** This is the property that matters. A
    field placed nowhere gives the same word for every value, and a word that
    decodes correctly for one value is not evidence of anything;
  * **the mnemonic does not change.** Distinct is not enough on its own --
    drifting into a neighbouring instruction would also be distinct.

Declines when no instruction has a split field, or when `llvm-mc` is absent.

Usage: tools/split_field_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
from reference_isa_check import find_llvm_mc  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ROW = re.compile(r'\{ "(\w+)", "(\w+)", "[^"]*", (0x[0-9a-f]+)u, ')
TABLE = re.compile(r"static const axis_encode_operand_field "
                   r"AXIS_ENCODE_OPERANDS_(\w+)\[\] = \{(.*?)\};", re.S)
FIELD = re.compile(r'\{ "(\w+)", "(\w+)", "\w+", "\w+", \d+, (\d+), (\d+), (\d+)u \}')
#: Only immediates are driven. A split REGISTER field would need the class's
#: legal indices, and none of the corpora have one.
DRIVEN_KIND = "imm"
#: An operand wider than this is not enumerated; the point is the placement,
#: and a handful of values shows it.
MAX_VALUES = 16


def declared_widths(axis_file: Path) -> dict[tuple[str, str], int]:
    """Every immediate operand's width, as the description declares it."""
    import json
    text = subprocess.run([*axis_prefix(), "emit-json", str(axis_file)],
                          check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT).stdout
    out: dict[tuple[str, str], int] = {}
    for instruction in json.loads(text).get("instructions", []):
        for operand in instruction.get("operands", []):
            if operand.get("kind") == DRIVEN_KIND:
                out[(instruction["mnemonic"], operand["name"])] = operand["width"]
    return out


def disassemble(mc: str, triple: str, word: int) -> str:
    encoded = ",".join(f"0x{(word >> (8 * k)) & 0xff:02x}" for k in range(4))
    out = subprocess.run([mc, "-disassemble", f"-triple={triple}"],
                         input=encoded, capture_output=True, text=True).stdout
    lines = [line.strip() for line in out.splitlines()
             if line.strip() and not line.strip().startswith(".")]
    return re.sub(r"\s+", " ", lines[-1]) if lines else ""


def check(axis_file: Path, mc: str, triple: str) -> tuple[int, int, int]:
    text = subprocess.run([*axis_prefix(), "emit-encode-c", str(axis_file)],
                          check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT).stdout
    slices = {m.group(1): FIELD.findall(m.group(2)) for m in TABLE.finditer(text)}
    widths = declared_widths(axis_file)
    checks = failures = driven = 0
    for row in ROW.finditer(text):
        mnemonic, base = row.group(1), int(row.group(3), 16)
        entries = slices.get(mnemonic, [])
        counts: dict[str, int] = {}
        for name, kind, _obit, _ibit, _width in entries:
            if kind == DRIVEN_KIND:
                counts[name] = counts.get(name, 0) + 1
        # ⚠️ COVERAGE FIRST, and this is the check that catches the bug the
        # file was written for. A field declared with the instruction and
        # operand slices the wrong way round produces ONE entry, not two, so
        # it looks contiguous and the placement test below skips it entirely
        # -- which is exactly what happened: the gate passed the broken
        # declaration it was written to catch. What gives it away without an
        # assembler is that the declared slices then cover the wrong operand
        # bits, and do not add up to the operand's width.
        for operand, count in counts.items():
            covered: set[int] = set()
            for name, _kind, obit, _ibit, slice_width in entries:
                if name != operand:
                    continue
                for bit in range(int(obit), int(obit) + int(slice_width)):
                    covered.add(bit)
            width = widths.get((mnemonic, operand))
            if width is not None:
                checks += 1
                if covered != set(range(width)):
                    failures += 1
                    print(f"  FAIL {mnemonic}: operand `{operand}` is {width} "
                          f"bit(s) wide but its field slices cover operand "
                          f"bit(s) {sorted(covered)} -- every value it can "
                          f"take encodes the same")
                    continue
            if count < 2:
                continue                      # contiguous: nothing split to place
            if width is None or (1 << width) > MAX_VALUES:
                continue
            driven += 1
            seen: dict[str, int] = {}
            for value in range(1 << width):
                word = base
                for name, _kind, obit, ibit, slice_width in entries:
                    source = {operand: value}.get(name, 1)
                    field = (source >> int(obit)) & ((1 << int(slice_width)) - 1)
                    word |= field << int(ibit)
                checks += 1
                decoded = disassemble(mc, triple, word)
                if not decoded:
                    failures += 1
                    print(f"  FAIL {mnemonic} {operand}={value}: {word:#010x} "
                          f"decodes to no instruction")
                    continue
                seen.setdefault(decoded, value)
                # ⚠️ DISTINCT IS NOT CORRECT. Two slices swapped between them
                # still place every bit and still give a different word for
                # every value -- the values are just transposed, and index 1
                # encodes what the assembler calls index 2. Where the assembler
                # prints the operand as a bracketed index, that number is the
                # one it decoded and has to be the one encoded.
                printed = re.findall(r"\[(\d+)\]", decoded)
                if printed:
                    checks += 1
                    if int(printed[-1]) != value:
                        failures += 1
                        print(f"  FAIL {mnemonic} {operand}={value}: "
                              f"{word:#010x} decodes as index {printed[-1]} -- "
                              f"the slices are placed but transposed")
            # ⚠️ THE PROPERTY. A field placed nowhere gives one word for every
            # value, and one correct decode is not evidence of a placement.
            checks += 1
            if len(seen) != (1 << width):
                failures += 1
                print(f"  FAIL {mnemonic}: {operand} takes {1 << width} values "
                      f"but only {len(seen)} distinct disassembly/ies -- the "
                      f"field is not placed where the operand's bits go")
                continue
            checks += 1
            mnemonics = {line.split()[0] for line in seen}
            if len(mnemonics) != 1:
                failures += 1
                print(f"  FAIL {mnemonic}: {operand} changes which instruction "
                      f"the word is: {sorted(mnemonics)}")
    return checks, failures, driven


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args()
    mc = find_llvm_mc()
    if mc is None:
        print("  DECLINED no llvm-mc on this host; what a word decodes to is "
              "the assembler's to say")
        return DECLINED
    files = args.files or [AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl"]
    checks = failures = driven = 0
    for axis_file in files:
        c, f, d = check(axis_file, mc, "arm64e-apple-darwin")
        checks, failures, driven = checks + c, failures + f, driven + d
    if not driven:
        print("  DECLINED no instruction here has an operand split across the "
              "word, so there is no placement to get wrong")
        return DECLINED
    verdict = "PASS" if failures == 0 else "FAIL"
    print(f"a field split across the word is placed in both halves: {verdict} "
          f"({checks} checks, {driven} split operand(s) driven, "
          f"{failures} failure(s))")
    return PASSED if failures == 0 else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
