#!/usr/bin/env python3
"""The encodings are the architecture's, checked against someone else's tables.

Every other gate in this ladder compares AXIS against AXIS. The encoder, the
decoder, the executors, the golden model and the LLVM backend all agree on
whatever the description says, and **not one of them knows what ARM or RISC-V
International says**. So a wrong encoding is invisible: `FADD_D` carried
`(fixed 483)` where AArch64 has 243 for the whole life of the corpus, putting
scalar floating-point arithmetic in the SIMD load/store space, and 286 green
gates had nothing to say about it. What found it was decoding a binary the
architecture had produced.

This is that, as a gate. Every roundtrip fixture's word is handed to `llvm-mc`
as a disassembler, and two things are required:

  * **the reference must recognise the word at all.** This is the check that
    matters and it has no noise: an encoding AXIS calls a valid AArch64
    instruction that AArch64 does not is wrong, full stop. `0x3c602800` --
    `FADD_D` as it was written -- disassembles to nothing.
  * **the mnemonics must agree**, after normalising two naming conventions and
    a table of preferred aliases. This is softer, and the table is part of the
    gate rather than a footnote: an *unexplained* difference fails, so the
    table cannot quietly rot into "everything is an alias".

An ISA with no reference assembler is declined, not guessed at. AXIS's
`accelerator_scalar64` and the VLIW and CGRA corpora are architectures nobody
else implements, and inventing a triple for them would compare a description
against itself again, one process further away.

Usage: tools/reference_isa_check.py [<input.axisl> ...]   (default: every corpus)

Requires: llvm-mc (set AXIS_LLVM_MC, or it is looked for on PATH and in the
Homebrew LLVM prefixes).
"""

from __future__ import annotations

import collections
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED, axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Which reference to ask, per ISA. The feature list is part of the answer, not
#: a detail: asking `-triple=arm64` without `+lse,+pauth` rejects 172 perfectly
#: good words -- the atomics and every pointer-authentication form -- and reads
#: exactly like 172 corpus bugs. A gate that cries wolf about the architecture
#: is worse than no gate, so the flags are written down here with the reason.
#: triple, features, and extra flags -- and the flags differ by target for a
#: reason worth stating, because the same option means opposite things.
#:
#: `-M=no-aliases` asks the reference to print the instruction it decoded rather
#: than the name it prefers. **RISC-V needs it**: without it a compressed
#: instruction prints as its expansion, `c.addi` as `addi`, and there is no way
#: to tell the sixteen-bit form from the thirty-two-bit one by name.
#: **AArch64 must not have it**: there the "alias" is often the architectural
#: name and the raw form is the encoding space it borrows -- `PACIBSP` prints as
#: `hint`, `CSDB` as `hint`, `SSBB` as `dsb`, which are true and useless. So one
#: target asks for less naming and the other for more.
REFERENCES = {
    "aarch64_base": ("arm64e-apple-darwin", "+lse,+fp-armv8,+neon,+pauth,+fptoint", []),
    "rv32i": ("riscv32", "+m,+a,+f,+d,+c", ["-M=no-aliases"]),
    "rv64i": ("riscv64", "+m,+a,+f,+d,+c", ["-M=no-aliases"]),
    # SVE joined once it meant to be Arm's (docs/scalable_vectors_design.md,
    # V1). Before that its encodings were illustrative: `aarch64` refused 43 of
    # its 83 words and read `SUB_Z_B` as `uaddv`.
    # ⚠️ SVE2's optional extensions are features of their own: without them the
    # reference does not decode AES, the bit permutes, RAX1 or SM4 at all --
    # 17 words refused that are Arm's encodings exactly (V6).
    "sve": ("aarch64", "+v9.4a,+sve2,+sve2-aes,+sve2-bitperm,+sve2-sha3,+sve2-sm4", []),
}

#: **`rvv` is deliberately absent, and being named after a real architecture is
#: not enough to add one.** It exists to exercise AXIS's scalable-vector
#: machinery -- lane groups, VL, `vtype` -- and its encodings are illustrative
#: rather than architectural: asked, `riscv64` refuses 13 of RVV's 35 words and
#: reads `VADD_VV` as `vfadd.vv`. What decides membership here is whether a
#: description means to be the architecture's encoding, not whether it borrowed
#: the architecture's name.

#: A rounding mode AXIS spells into the mnemonic and RISC-V spells as a field.
ROUNDING = re.compile(r"\.(rne|rtz|rdn|rup|rmm|dyn)$")

#: Preferred aliases: the same encoding, the name the reference prefers to
#: print. Every one of these was observed, not guessed, and each is a real
#: architectural alias rather than a disagreement about what the word means.
ALIASES = {
    # SVE: Arm's memory mnemonics carry the element size the corpus names in
    # its suffix (`LD1_S` is `ld1w`), and DUP (scalar) prints as `mov`.
    ("ld1", "ld1b"), ("ld1", "ld1h"), ("ld1", "ld1w"), ("ld1", "ld1d"),
    ("st1", "st1b"), ("st1", "st1h"), ("st1", "st1w"), ("st1", "st1d"),
    ("ld2", "ld2w"), ("ldnf1", "ldnf1w"), ("ldff1", "ldff1w"), ("dup", "mov"),
    # The non-faulting and first-faulting loads at the other element sizes
    # (V3-V5), and TBL over two table registers, which Arm also calls `tbl`.
    ("ldnf1", "ldnf1b"), ("ldnf1", "ldnf1h"), ("ldnf1", "ldnf1d"),
    ("ldff1", "ldff1b"), ("ldff1", "ldff1h"), ("ldff1", "ldff1d"),
    ("tbl2", "tbl"),
    # AArch64: the variable-shift forms, move-wide, and the bitfield family.
    ("lslv", "lsl"), ("lsrv", "lsr"), ("asrv", "asr"), ("rorv", "ror"),
    ("movn", "mov"), ("movz", "mov"),
    ("bfm", "bfxil"), ("sbfm", "sbfx"), ("sbfm", "asr"),
    ("ubfm", "ubfx"), ("ubfm", "lsr"),
    # SB is encoded in the MSR space and prints as one.
    ("sb", "msr"),
    # `INS (general)` has `MOV` as its architecturally preferred disassembly,
    # checked rather than assumed: `ins v1.h[1], w2` assembles into this family
    # and the reference prints the result as `mov`.
    ("ins", "mov"),
    # `NOT (vector)` is the architecture's name for the instruction -- ARM
    # C7.2, "Bitwise NOT (vector)" -- and `MVN` is its preferred DISASSEMBLY.
    # Observed, not assumed: `0x6e205841` is the NOT encoding and the reference
    # prints `mvn` for it. Recorded here rather than by renaming the
    # instruction, because the description should carry the architectural name
    # and this table exists to hold the difference.
    ("not", "mvn"),
    # `DUP (element)` in its scalar form, and `UMOV` of a word or doubleword,
    # have `MOV` as their preferred disassembly too: `0x5e010441` prints as
    # `mov b1, v2.b[0]` and `0x4e083c41` as `mov x1, v2.d[0]`.
    ("dup", "mov"), ("umov", "mov"),

    # RISC-V: the CSR writes that have their own names.
    ("csrrw.fflags", "fsflags"), ("csrrw.frm", "fsrm"),
    ("csrrwi.fflags", "fsflagsi"), ("csrrwi.frm", "fsrmi"),
    # And AXIS's spelling of the single-precision load and store.
    ("fls", "flw"), ("fss", "fsw"),
}


def find_llvm_mc() -> str | None:
    named = os.environ.get("AXIS_LLVM_MC")
    if named:
        return named if Path(named).exists() else None
    found = shutil.which("llvm-mc")
    if found:
        return found
    for prefix in sorted(Path("/opt/homebrew/opt").glob("llvm*")):
        candidate = prefix / "bin" / "llvm-mc"
        if candidate.exists():
            return str(candidate)
    return None


def axis_mnemonic(mnemonic: str, isa: str) -> str:
    """The reference's spelling of an AXIS mnemonic, as far as naming goes.

    AArch64 separates a form's suffix with `_` -- `LDR_X_UNSIGNED` is `ldr` and
    the rest says which encoding. RISC-V's mnemonics *contain* dots, which AXIS
    writes as `_`, so `FADD_S_RNE` is `fadd.s` with a rounding mode AXIS names
    and the reference makes an operand.
    """
    lowered = mnemonic.lower()
    if isa.startswith("rv"):
        return ROUNDING.sub("", lowered.replace("_", "."))
    return lowered.split("_")[0]


def agrees(ours: str, reference: str) -> bool:
    if ours == reference or (ours, reference) in ALIASES:
        return True
    # AXIS names a pinned operand in the mnemonic where the reference leaves it
    # an operand: `CSRRC_FFLAGS` is `csrrc` with the CSR named.
    if ours.startswith(reference + "."):
        return True
    # A complex ROTATION is the same thing in SVE: `CADD90` is `cadd` with the
    # rotation named, where Arm makes `#90` an operand. Only the four rotations
    # there are, so `cadd9` is still a disagreement.
    if ours.startswith(reference) and ours[len(reference):] in ("0", "90", "180", "270"):
        return True
    # And the reverse, where the reference names a condition AXIS encodes:
    # `B_COND` prints as `b.hs`, `b.eq`, and so on.
    return reference.startswith(ours + ".")


def disassemble(mc: str, words: list[tuple[int, int]], triple: str,
                mattr: str, extra: list) -> list[str | None]:
    """One entry per word: its mnemonic, or None if the reference refused it.

    One word per line, because `llvm-mc` **drops** a word it cannot decode and
    prints nothing in its place -- feeding it a single stream and zipping the
    output back against the input silently pairs every later word with its
    neighbour's disassembly. The warnings carry the line number, so the words
    it refused are named and the rest still line up. (This is the same
    misalignment that `binary_coverage.py` guards against in a byte stream, met
    again one tool along.)
    """
    # **As many bytes as the instruction is wide, and no more.** A 16-bit
    # instruction padded to four leaves a stray half-word, which the reference
    # decodes as a second instruction -- so one input line produces two output
    # lines and every later word pairs with its neighbour's disassembly. That is
    # the same misalignment as feeding a single stream, arriving by a different
    # route, and it is why the table publishes `bits`.
    source = "\n".join(
        ",".join(f"0x{byte:02x}" for byte in word.to_bytes(max(bits // 8, 1), "little"))
        for word, bits in words)
    result = subprocess.run(
        [mc, "--disassemble", f"-triple={triple}", f"-mattr={mattr}", *extra],
        input=source, capture_output=True, text=True)
    refused = {int(line) for line in re.findall(r"<stdin>:(\d+):", result.stderr)}
    printed = [line.strip() for line in result.stdout.splitlines()
               if line.strip() and not line.startswith(".")]
    accepted = [index for index in range(1, len(words) + 1) if index not in refused]
    if len(printed) != len(accepted):
        raise RuntimeError(
            f"llvm-mc printed {len(printed)} instructions for {len(accepted)} "
            f"words it did not refuse; the output cannot be aligned")
    answers: list[str | None] = [None] * len(words)
    for index, line in zip(accepted, printed):
        answers[index - 1] = line.split()[0].lower()
    return answers


def check(axis_file: Path, mc: str) -> int:
    result = subprocess.run([*axis_prefix(), "emit-roundtrip-json", str(axis_file)],
                            capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    tests = json.loads(result.stdout)["tests"]
    table = subprocess.run([*axis_prefix(), "emit-decode-json", str(axis_file)],
                           capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    widths = {entry["mnemonic"]: int(entry.get("bits", 32))
              for entry in json.loads(table.stdout)["instructions"]}
    by_isa: dict[str, list] = collections.defaultdict(list)
    for test in tests:
        if test.get("isa") in REFERENCES:
            by_isa[test["isa"]].append(test)
    if not by_isa:
        print(f"{axis_file.name}: no ISA here has a reference assembler -> DECLINE")
        return DECLINED

    failures: list[str] = []
    checked = aliased = 0
    for isa, group in sorted(by_isa.items()):
        triple, mattr, extra = REFERENCES[isa]
        # The width comes from the decode table, joined by mnemonic: a
        # roundtrip fixture says what the word is, not how wide it is.
        words = [(int(test["encoded"], 16), widths.get(test["mnemonic"], 32))
                 for test in group]
        answers = disassemble(mc, words, triple, mattr, extra)
        for test, answer in zip(group, answers):
            word = int(test["encoded"], 16)
            if answer is None:
                failures.append(
                    f"{isa} {test['mnemonic']} is 0x{word:08x}, which {triple} "
                    f"does not decode as any instruction")
                continue
            ours = axis_mnemonic(test["mnemonic"], isa)
            checked += 1
            if ours == answer:
                continue
            if agrees(ours, answer):
                aliased += 1
                continue
            failures.append(
                f"{isa} {test['mnemonic']} is 0x{word:08x}, which {triple} reads "
                f"as `{answer}` and not `{ours}`")

    if failures:
        print(f"{axis_file.name}: {len(failures)} disagreement(s) with the "
              f"reference -> FAIL")
        for line in failures[:8]:
            print(f"     {line}")
        return FAILED
    print(f"{axis_file.name}: {checked} encoding(s) agree with the reference "
          f"({aliased} through a named alias) -> PASS")
    return PASSED


def main() -> int:
    mc = find_llvm_mc()
    if mc is None:
        # Not a pass. A gate whose reference is absent has checked nothing, and
        # saying so is the difference between "no disagreement" and "no answer".
        print("no llvm-mc: the reference assembler is what this gate is, so it "
              "has checked nothing -> DECLINE")
        return DECLINED
    files = [Path(arg) for arg in sys.argv[1:]] or sorted(
        (AXIS_ROOT / "examples").glob("*.axisl"))
    results = [check(axis_file, mc) for axis_file in files]
    checked = results.count(PASSED)
    print(f"{len(results)} corpus/corpora: {checked} checked against a reference, "
          f"{results.count(DECLINED)} with no reference ISA, "
          f"{results.count(FAILED)} disagreeing")
    if FAILED in results:
        print("REFERENCE ISA CHECK FAILED")
        return FAILED
    if not checked:
        print("REFERENCE ISA CHECK DECLINED: no corpus had a reference ISA")
        return DECLINED
    print("REFERENCE ISA CHECK PASSED")
    return PASSED


if __name__ == "__main__":
    sys.exit(main())
