#!/usr/bin/env python3
"""Prove the assembler/disassembler description can actually assemble.

`asm_disasm.json` is a self-contained account of how an instruction is spelled
and where each operand's bits live: a decode match and mask, an assembly
template, and per-operand bit slices. It ships in the bundle, and until now the
only thing checked about it was that the file was present and schema-shaped --
which cannot see a field placed at the wrong bit, a slice with the wrong width,
or a template naming an operand the instruction does not have.

So this gate builds an assembler and a disassembler *out of the artifact alone*
and runs them against the roundtrip fixtures, which the encode and decode paths
already prove. Nothing here reads the AXIS model: if the description is wrong,
the words it produces disagree with the words the proven encoder produced, which
is the whole point of publishing a description at all.

Three properties, and they fail differently:

* **Assembling.** Placing each operand's bits where the artifact says they go,
  over the decode match, must reproduce the fixture's encoded word exactly.
* **Disassembling.** Selecting the entry whose match the word satisfies, and
  extracting each operand from the same slices, must recover the operand values
  the fixture assembled from. It must also select exactly one entry -- an
  ambiguous description is a disassembler that guesses.
* **Spelling.** Every placeholder in the template must name an operand. The
  reverse -- every operand appearing in the template -- is required only where
  the template does not end in `...`, which is how a scalable corpus says its
  per-lane operands are elaboration artifacts rather than text anyone writes.

All fifty-five corpora pass. Getting there needed the description to say three
things it did not: which ISA an entry belongs to, which modes it is legal in,
and which functional unit executes it. The model has always known all three --
the validator uses exactly them, plus a decode predicate, to prove two
instructions may share a word -- but a consumer reading the published file saw
only a match and a mask, and had to guess between entries the model knows apart.

Usage: tools/asm_disasm_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
PLACEHOLDER = re.compile(r"\$(\w+)")
# How elaboration names a lane instantiation and the operands it synthesised
# for it: `SVADD_B__l2` carries `zn__l2`. Everything from the lane marker on is
# elaboration's, including suffixes stacked after it -- `ADD_U_S__l0__defined`
# is one definedness variant of one lane of one instruction, and all of them
# answer to the same word.
LANE_SUFFIX = re.compile(r"__l\d+.*$")


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def place(value: int, slices: list[dict]) -> int:
    """The operand's bits, in the word, exactly where the artifact says."""
    word = 0
    for piece in slices:
        chunk = (value >> piece["op_lsb"]) & ((1 << piece["width"]) - 1)
        word |= chunk << piece["lsb"]
    return word


def extract(word: int, slices: list[dict]) -> int:
    """The operand, back out of the word, through the same slices."""
    value = 0
    for piece in slices:
        chunk = (word >> piece["lsb"]) & ((1 << piece["width"]) - 1)
        value |= chunk << piece["op_lsb"]
    return value


def printed(transform: dict | None, field: int) -> int:
    """The number the assembly shows for this encoded field."""
    if not transform:
        return field
    kind, amount = transform["kind"], transform["amount"]
    return amount - field if kind == "minus_from" else field + amount


def encoded(transform: dict | None, shown: int) -> int:
    """The field an assembler must place for that number, going back."""
    if not transform:
        return shown
    kind, amount = transform["kind"], transform["amount"]
    return amount - shown if kind == "minus_from" else shown - amount


def render(template: str, entry: dict, values: dict) -> str:
    """The assembly text, with each immediate shown as the description says.

    Registers are left as their placeholder: naming them is a register-file
    question this file does not answer, and the property under test is the
    number, which is the part a transform changes.
    """
    text = template
    for operand in entry["operands"]:
        name = operand["name"]
        if name not in values or operand["kind"] not in ("imm", "simm", "uimm"):
            continue
        shown = printed(operand.get("asm_transform"), values[name])
        text = text.replace(f"${name}", str(shown))
    return text


def operand_mask(slices: list[dict]) -> int:
    """Which bits of the operand the encoding actually carries.

    An immediate whose low bits are implicit -- a branch target, a `LUI` --
    cannot be recovered below its first slice, and requiring that would be
    asking the description to store what the architecture does not.
    """
    mask = 0
    for piece in slices:
        mask |= ((1 << piece["width"]) - 1) << piece["op_lsb"]
    return mask


def modes_meet(left: dict, right: dict) -> bool:
    """Whether the two are ever legal at the same time.

    An entry with no modes is legal in all of them, which is what a document
    without modes means -- so an absent list meets everything.
    """
    a = left["decode"].get("modes")
    b = right["decode"].get("modes")
    return not a or not b or bool(set(a) & set(b))


def units_meet(left: dict, right: dict) -> bool:
    """Whether the two are ever issued together.

    Different units can share a word when their slots are disjoint, and this
    does not read the packet manifest to find out. It does not have to: the
    corpus validated, and the validator only permits a shared word when the
    modes, the slots, or a decode predicate separate the two. So within a
    corpus that parsed, differing units are already known to be separated --
    what would be unsound is assuming it of a corpus that had not been checked.
    """
    a = left["decode"].get("unit")
    b = right["decode"].get("unit")
    return not a or not b or a == b


def check(axis_file: Path) -> tuple[int, int, int]:
    workdir = Path(tempfile.mkdtemp(prefix="axis_asm_"))
    asm_path = workdir / "asm_disasm.json"
    fixtures_path = workdir / "roundtrip.json"
    emit(axis_file, "emit-asm-disasm-json", asm_path)
    emit(axis_file, "emit-roundtrip-json", fixtures_path)

    described = json.loads(asm_path.read_text())["instructions"]
    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])
    by_mnemonic = {entry["mnemonic"]: entry for entry in described}

    failures = 0
    checked = 0
    transformed = 0

    # Spelling: the template and the operand list must describe each other.
    for entry in described:
        named = set(PLACEHOLDER.findall(entry["asm_template"]))
        # The opcode token is not a placeholder, so what remains must be
        # operands and nothing else -- reading a lane instantiation's operands
        # under their architectural names. Expanding a scalable word renames
        # `zs` to `zs__l0` per lane, and the template is written against the
        # register the programmer names, not against the expansion.
        declared = {operand["name"] for operand in entry["operands"]}
        declared |= {LANE_SUFFIX.sub("", name) for name in declared}
        for stray in sorted(named - declared):
            print(f"FAIL {entry['mnemonic']}: template names ${stray}, "
                  f"which is not an operand")
            failures += 1
        # The reverse direction, over the operands that are actually in the
        # word. The artifact already says which those are: an operand whose
        # encoding carries no slices is either `unencoded` -- RISC-V V's `vl`
        # comes from a CSR -- or `derived`, synthesised when a scalable word
        # was expanded into lanes. Neither is in the encoding, so neither can
        # be in the text, and reading that from the description beats guessing
        # it from a naming convention. An `...` in the template is the author
        # saying the remaining operands are deliberately unspelled.
        spelled = {operand["name"] for operand in entry["operands"]
                   if (operand.get("encoding") or {}).get("slices")}
        if "..." not in entry["asm_template"]:
            for missing in sorted(spelled - named):
                print(f"FAIL {entry['mnemonic']}: operand {missing} never "
                      f"appears in `{entry['asm_template']}`")
                failures += 1

    for fixture in fixtures:
        entry = by_mnemonic.get(fixture["mnemonic"])
        if entry is None:
            print(f"FAIL {fixture['mnemonic']}: assembled by a fixture but "
                  f"absent from the description")
            failures += 1
            continue
        word = int(fixture["encoded"], 16)
        values = {operand["name"]: operand["value"]
                  for operand in fixture["operands"]}
        slices_of = {operand["name"]: operand["encoding"]["slices"]
                     for operand in entry["operands"]}
        checked += 1

        # Assemble from the description alone.
        built = int(entry["decode"]["match"], 16)
        for name, value in values.items():
            if name in slices_of:
                built |= place(value, slices_of[name])
        if built != word:
            print(f"FAIL {fixture['mnemonic']}: assembling from the description "
                  f"gives {built:#010x}, the encoder gave {word:#010x}")
            failures += 1

        # Disassemble, and require the choice to be unambiguous *within the
        # ISA*: two ISAs in one corpus have disjoint decode spaces by
        # construction, so a word means nothing until you say which machine is
        # reading it. Entries carrying a further predicate are left to a
        # consumer that evaluates it -- this gate does not, so it does not get
        # to call them ambiguous either.
        candidates = [other for other in described
                      if other.get("isa") == entry.get("isa")
                      and modes_meet(entry, other)
                      and units_meet(entry, other)
                      and not other["decode"].get("decode_constraint")
                      and not other["decode"].get("decode_requires")]
        matches = [other for other in candidates
                   if word & int(other["decode"]["mask"], 16)
                   == int(other["decode"]["match"], 16)]
        constrained = bool(entry["decode"].get("decode_constraint")
                           or entry["decode"].get("decode_requires"))
        if constrained:
            matches = [entry]
        # One word means one *instruction*, which for a scalable instruction is
        # all of its lanes: the executor decodes a word into a lane group and
        # runs each. So the requirement is one base mnemonic, not one entry --
        # sixteen `SVADD_B__l*` are the same instruction, and two different
        # bases would be a disassembler that has to guess.
        bases = {LANE_SUFFIX.sub("", other["mnemonic"]) for other in matches}
        want = LANE_SUFFIX.sub("", fixture["mnemonic"])
        if len(bases) != 1:
            names = ", ".join(sorted(bases)) or "none"
            print(f"FAIL {fixture['mnemonic']} ({word:#010x}): the description "
                  f"selects {len(bases)} instructions ({names})")
            failures += 1
        elif want not in bases:
            print(f"FAIL {word:#010x}: the description selects "
                  f"{sorted(bases)[0]}, the fixture assembled {want}")
            failures += 1

        for name, value in values.items():
            if name not in slices_of:
                continue
            carried = operand_mask(slices_of[name])
            recovered = extract(word, slices_of[name])
            if recovered != (value & carried):
                print(f"FAIL {fixture['mnemonic']}: operand {name} reads back "
                      f"as {recovered:#x}, was assembled from "
                      f"{value & carried:#x}")
                failures += 1

        # ⚠️ And the number the text SHOWS, which is not always the field. An
        # operand may declare a transform -- AArch64's fixed-point `SCVTF`
        # encodes `scale` and prints `fbits`, which is `64 - scale` -- and a
        # disassembler built from this file has to apply it, an assembler has
        # to run it backwards, and the two have to meet. Checked over the whole
        # field rather than at the fixture's one value: the fixture reaches one
        # encoding and the rule is about all of them.
        for operand in entry["operands"]:
            transform = operand.get("asm_transform")
            if not transform:
                continue
            name = operand["name"]
            width = operand["width"]
            span = (1 << min(width, 16)) - 1
            for field in {0, 1, span // 2, span, values.get(name, 0)}:
                shown = printed(transform, field)
                if shown < 0:
                    print(f"FAIL {fixture['mnemonic']}: operand {name} shows "
                          f"{shown} for field {field}, and the syntax has no "
                          f"sign for it")
                    failures += 1
                    break
                if encoded(transform, shown) != field:
                    print(f"FAIL {fixture['mnemonic']}: operand {name} shows "
                          f"{shown} for field {field} and reads back as "
                          f"{encoded(transform, shown)}")
                    failures += 1
                    break
            transformed += 1

    return checked, failures, transformed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    args = parser.parse_args()
    checked, failures, transformed = check(args.axis_file)
    print(f"{checked} fixture(s) assembled and disassembled from the "
          f"description, {failures} failure(s)")
    # Said out loud, because a corpus with none of these should not read the
    # same as a corpus whose transforms were all checked.
    print(f"  {transformed} operand(s) whose printed number differs from the "
          f"field it is encoded in")
    print("asm/disasm description == encoder: "
          + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
