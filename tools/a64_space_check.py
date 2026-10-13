#!/usr/bin/env python3
"""AXIS decodes the whole AdvSIMD encoding space as LLVM does.

`reference_isa_check` asks the reference about each FIXTURE word: one value per
operand, one word per instruction. That misses the two ways a decoder goes
wrong between fixtures -- an arrangement `requires` should have excluded, and
an encoding the architecture leaves unallocated that a pattern still matches
-- and it cannot say what is left to describe.

This enumerates the space instead. Every word whose top bits are AdvSIMD
vector (`0 Q U 0111x`) or AdvSIMD scalar (`01 U 1111x`), with every opcode
bit driven and the registers fixed (`rd = 1`, `rn = 2`; `rm` is driven,
since several forms carry opcode or index bits there): 196,608 words, of
which the reference allocates about 54,000. Each is disassembled by `llvm-mc`
with every extension enabled and decoded by AXIS's lift table, and:

  * every word AXIS decodes, the reference decodes to the same instruction
    (up to the aliases `reference_isa_check` names), and
  * no word AXIS decodes is one the reference refuses.

Either failing is a decoder that accepts what the architecture does not say.
It also reports coverage: the reference's words grouped into FORMS -- a
mnemonic and its operand shape, `add v.8b, v.8b, v.8b` -- and how many AXIS
decodes. That number is the answer to "what is left in NEON", measured.

Usage: tools/a64_space_check.py [examples/aarch64_translation_seed.axisl]
"""

from __future__ import annotations

import argparse
import collections
import importlib
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED, axis_prefix
from reference_isa_check import agrees, find_llvm_mc

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: The reference prints these where AXIS names the underlying instruction.
SIMD_ALIASES = {("orr", "mov"), ("sshll", "sxtl"), ("ushll", "uxtl"),
                ("sshll2", "sxtl2"), ("ushll2", "uxtl2")}


def space() -> list[int]:
    words = []
    for q in (0, 1):
        for u in (0, 1):
            for b24 in (0, 1):
                for low in range(1 << 14):
                    words.append((q << 30) | (u << 29) | (0b0111 << 25) | (b24 << 24)
                                 | (low << 10) | (2 << 5) | 1)
    for u in (0, 1):
        for b24 in (0, 1):
            for low in range(1 << 14):
                words.append((1 << 30) | (u << 29) | (0b1111 << 25) | (b24 << 24)
                             | (low << 10) | (2 << 5) | 1)
    return words


def form(text: str) -> str:
    """A disassembly with its register numbers, immediates and indices erased."""
    t = text.replace("\t", " ")
    t = re.sub(r"\bv\d+\b", "v", t)
    t = re.sub(r"\b([bhsdq])\d+\b", r"\1", t)
    t = re.sub(r"#-?[0-9a-fx.e+]+", "#", t)
    t = re.sub(r"\[\d+\]", "[i]", t)
    return re.sub(r"\s+", " ", t).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path,
                        default=AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl")
    args = parser.parse_args()
    mc = find_llvm_mc()
    if mc is None:
        print("  DECLINED no llvm-mc on this host")
        return DECLINED

    with tempfile.TemporaryDirectory(prefix="axis_a64space_") as work:
        subprocess.run([*axis_prefix(), "emit-lift-python", str(args.axis_file),
                        "-o", str(Path(work) / "axis_lift.py")],
                       check=True, capture_output=True, cwd=AXIS_ROOT)
        sys.path.insert(0, work)
        lift = importlib.import_module("axis_lift")

        words = space()
        source = "\n".join(",".join(f"0x{b:02x}" for b in w.to_bytes(4, "little")) for w in words)
        result = subprocess.run([mc, "--disassemble", "-triple=aarch64", "-mattr=+all"],
                                input=source, capture_output=True, text=True)
        refused = {int(n) for n in re.findall(r"<stdin>:(\d+):", result.stderr)}
        printed = [line.strip() for line in result.stdout.splitlines()
                   if line.strip() and not line.startswith(".")]
        accepted = [i for i in range(1, len(words) + 1) if i not in refused]
        if len(printed) != len(accepted):
            print(f"  FAIL llvm-mc printed {len(printed)} lines for {len(accepted)} words")
            return FAILED
        # ⚠️ Vacuity: a reference that refused nearly everything, or a lift
        # table that decoded nothing, would agree about nothing.
        if len(accepted) < 40000:
            print(f"  FAIL the reference decoded only {len(accepted)} words; "
                  f"it is not the AdvSIMD space being swept")
            return FAILED

        failures: list[str] = []
        for index in sorted(refused):
            entry = lift.decode(words[index - 1], "aarch64_base")
            if entry is not None:
                failures.append(f"{words[index - 1]:#010x}: AXIS decodes {entry['mnemonic']}, "
                                f"the reference refuses it")
        forms: dict[str, list[int]] = collections.defaultdict(lambda: [0, 0])
        for index, text in zip(accepted, printed):
            word = words[index - 1]
            key = form(text)
            reference = key.split()[0]
            forms[key][0] += 1
            entry = lift.decode(word, "aarch64_base")
            if entry is None:
                continue
            forms[key][1] += 1
            ours = entry["mnemonic"].split("_")[0].lower()
            if not agrees(ours, reference) and (ours, reference) not in SIMD_ALIASES:
                failures.append(f"{word:#010x}: AXIS decodes {entry['mnemonic']}, "
                                f"the reference {text.strip()}")

    decoded = sum(c for _, c in forms.values())
    covered = sum(1 for n, c in forms.values() if c == n)
    partial = sum(1 for n, c in forms.values() if 0 < c < n)
    if decoded < 10000:
        failures.append(f"AXIS decoded only {decoded} words of the space; the lift table "
                        f"is not the corpus's")
    for line in failures[:20]:
        print(f"  FAIL {line}")
    if len(failures) > 20:
        print(f"  ... and {len(failures) - 20} more")
    print(f"  {len(words)} AdvSIMD words, {len(accepted)} allocated: AXIS decodes {decoded}, "
          f"covering {covered} of {len(forms)} forms ({partial} partly)")
    verdict = "PASS" if not failures else "FAIL"
    print(f"AXIS decodes the AdvSIMD space as the reference does: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
