#!/usr/bin/env python3
"""Executable roundtrip check: compile the generated C encode/decode headers
and run every roundtrip fixture through them.

For each fixture: encode the operand values with `axis_encode_by_index`,
compare against the fixture's expected instruction word, then decode the word
with `axis_decode` and compare the mnemonic. This closes the loop the JSON
fixtures only describe.

Usage: tools/roundtrip_check.py <input.axisl> [<input.axisl> ...]

Requires: cargo (run from the AXIS repo root), a C compiler on PATH (cc).
"""

from __future__ import annotations

import json
import re
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


LANE_OPERAND = re.compile(r"__l\d+$")


def architectural_name(mnemonic: str) -> str:
    """The name the encode and decode tables key on.

    A fixture is per *lane* -- `ADD_Z_B__l0` -- because the execution harnesses
    drive lanes from it. The encode and decode tables are per *encoding*, since
    a lane group shares one word and N entries on one key is a conflict a
    decoder can only answer one way. Roundtrip joins the two, so it maps the
    lane to its group here rather than either side changing shape for it.
    """
    return LANE_OPERAND.sub("", mnemonic)


def c_case(test: dict) -> str:
    mnemonic = architectural_name(test["mnemonic"])
    isa = test.get("isa", "")
    # ⚠️ The mode the word is read in, when the instruction names one. Two
    # instructions may share an encoding if their modes are disjoint, and the
    # word alone then does not say which -- the decoder returns NULL, which is
    # correct and is not a roundtrip failure. Asking without the mode was
    # asking an unanswerable question and calling the refusal a bug.
    mode = test.get("mode", "")
    mode_arg = f'"{mode}"' if mode else "NULL"
    # The other discriminator the disjointness rule admits: a packet slot.
    unit = test.get("unit", "")
    unit_arg = f'"{unit}"' if unit else "NULL"
    # The declared operands only, in the table's order. A fixture is per lane
    # and carries both -- `zn` and `zn__l0`, the selector and the element it
    # picked -- because the execution harnesses need the second. The encode
    # table holds one selector per vector operand, so passing the lane's list
    # shifted every value one place and encoded a different word.
    declared = [op for op in test["operands"] if not LANE_OPERAND.search(op["name"])]
    values = ", ".join(f"{op['value']}u" for op in declared) or "0u"
    expected = int(test["encoded"], 16)
    return f"""  {{
    uint32_t values[] = {{ {values} }};
    uint32_t insn = 0;
    int idx = find_entry("{mnemonic}");
    if (idx < 0 || !axis_encode_by_index((size_t)idx, values, &insn)) {{
      printf("FAIL encode {mnemonic}\\n");
      failures++;
    }} else {{
      if (insn != 0x{expected:08x}u) {{
        printf("FAIL value {mnemonic}: got 0x%08x want 0x{expected:08x}\\n", insn);
        failures++;
      }}
      const axis_decode_entry *decoded = axis_decode_in(insn, "{isa}", {mode_arg}, {unit_arg});
      if (decoded == NULL || strcmp(decoded->mnemonic, "{mnemonic}") != 0) {{
        printf("FAIL decode {mnemonic}: got %s\\n", decoded ? decoded->mnemonic : "(null)");
        failures++;
      }}
    }}
    cases++;
  }}
"""


def valid_constraint_values(constraint: dict, entry: dict) -> dict | None:
    values = {}
    kind = constraint["kind"]
    if kind in {"a64_logical_imm", "a64_shifted_reg", "a64_extended_reg"}:
        return values
    if kind == "uimm_compare":
        literal = constraint["literal"]
        valid = {
            "eq": literal,
            "ne": literal + 1,
            "lt": literal - 1 if literal else None,
            "le": literal,
            "gt": literal + 1,
            "ge": literal,
        }.get(constraint["op"])
        if valid is None:
            return None
        values[constraint["operand"]] = valid
        return values
    if kind == "uimm_mask_eq":
        values[constraint["operand"]] = constraint["value"]
        return values
    if kind == "and":
        for child in constraint["constraints"]:
            child_values = valid_constraint_values(child, entry)
            if child_values is None:
                return None
            values.update(child_values)
        return values
    if kind == "or":
        return valid_constraint_values(constraint["constraints"][0], entry)
    if kind == "not":
        return invalid_constraint_values(constraint["constraint"], entry)
    return None


def invalid_constraint_values(constraint: dict, entry: dict) -> dict | None:
    values = {}
    kind = constraint["kind"]
    if kind == "a64_logical_imm":
        n = constraint["n"]
        if constraint["width"] == 64 and n["kind"] == "operand":
            values[n["name"]] = 1
        values[constraint["imms"]] = 63 if constraint["width"] == 64 else 31
    elif kind == "a64_shifted_reg":
        if constraint["width"] == 64:
            values[constraint["shift"]] = 3
        else:
            values[constraint["amount"]] = 32
    elif kind == "a64_extended_reg":
        values[constraint["amount"]] = 5
    elif kind == "uimm_compare":
        literal = constraint["literal"]
        invalid = {
            "eq": literal + 1,
            "ne": literal,
            "lt": literal,
            "le": literal + 1,
            "gt": literal,
            "ge": literal - 1 if literal else None,
        }.get(constraint["op"])
        if invalid is None:
            return None
        values[constraint["operand"]] = invalid
    elif kind == "uimm_mask_eq":
        mask = constraint["mask"]
        if mask == 0:
            return None
        low_bit = mask & -mask
        values[constraint["operand"]] = constraint["value"] ^ low_bit
    elif kind == "and":
        return invalid_constraint_values(constraint["constraints"][0], entry)
    elif kind == "or":
        for child in constraint["constraints"]:
            child_values = invalid_constraint_values(child, entry)
            if child_values is None:
                return None
            values.update(child_values)
    elif kind == "not":
        return valid_constraint_values(constraint["constraint"], entry)
    else:
        return None
    return values


def holds(constraint: dict, values: dict) -> bool | None:
    """Whether `values` satisfy `constraint`, where that can be said here."""
    kind = constraint["kind"]
    if kind == "uimm_compare":
        value, literal = values.get(constraint["operand"], 0), constraint["literal"]
        return {"eq": value == literal, "ne": value != literal, "lt": value < literal,
                "le": value <= literal, "gt": value > literal, "ge": value >= literal}[constraint["op"]]
    if kind == "uimm_mask_eq":
        return values.get(constraint["operand"], 0) & constraint["mask"] == constraint["value"]
    if kind in ("and", "or"):
        results = [holds(child, values) for child in constraint["constraints"]]
        if None in results:
            return None
        return all(results) if kind == "and" else any(results)
    if kind == "not":
        inner = holds(constraint["constraint"], values)
        return None if inner is None else not inner
    return None


def compared_operands(constraint: dict) -> set:
    if constraint["kind"] in ("uimm_compare", "uimm_mask_eq"):
        return {constraint["operand"]}
    children = constraint.get("constraints") or [constraint.get("constraint")]
    return set().union(*(compared_operands(c) for c in children if c))


def reserved_case(entry: dict) -> dict | None:
    constraint = entry.get("decode_constraint")
    if constraint is None:
        return None
    values = invalid_constraint_values(constraint, entry)
    if values is None:
        return None
    # ⚠️ The value must be one the FIELD can hold, and must actually break the
    # rule. `(or (= size 0) (= size 3))` asks each branch for a violating
    # value and the last wins: `size = 4`, which a two-bit field stores as 0
    # -- a valid size -- so the "reserved" word was a legal one and the check
    # failed on a correct decoder. Mask to the width, evaluate, and when the
    # guess is wrong, search a small field for a value that breaks every
    # branch; when none can be found or judged, there is no reserved case.
    widths = {op["name"]: sum(f["width"] for f in op["encoding"]["slices"])
              for op in entry["operands"]}
    values = {name: value & ((1 << widths[name]) - 1) if name in widths else value
              for name, value in values.items()}
    verdict = holds(constraint, values)
    if verdict:
        names = compared_operands(constraint)
        if len(names) != 1 or widths.get(next(iter(names)), 99) > 8:
            return None
        name = next(iter(names))
        breaking = [v for v in range(1 << widths[name])
                    if holds(constraint, {**values, name: v}) is False]
        if not breaking:
            return None
        values[name] = breaking[0]
    values = {
        operand["name"]: values.get(operand["name"], 0)
        for operand in entry["operands"]
    }
    word = int(entry["base_value"], 16)
    for operand in entry["operands"]:
        value = values[operand["name"]]
        for field in operand["encoding"]["slices"]:
            mask = (1 << field["width"]) - 1
            word |= ((value >> field["op_lsb"]) & mask) << field["lsb"]
    return {
        "mnemonic": entry["mnemonic"],
        "isa": entry.get("isa", ""),
        "values": [values[operand["name"]] for operand in entry["operands"]],
        "word": word,
    }


def c_reserved_case(test: dict) -> str:
    values = ", ".join(f"{value}u" for value in test["values"])
    return f"""  {{
    uint32_t values[] = {{ {values} }};
    uint32_t insn = 0;
    int idx = find_entry("{architectural_name(test["mnemonic"])}");
    if (idx < 0 || axis_encode_by_index((size_t)idx, values, &insn)) {{
      printf("FAIL reserved encode {architectural_name(test["mnemonic"])}\\n");
      failures++;
    }}
    const axis_decode_entry *decoded = axis_decode_in(0x{test["word"]:08x}u, "{test["isa"]}", NULL, NULL);
    if (decoded != NULL && strcmp(decoded->mnemonic, "{architectural_name(test["mnemonic"])}") == 0) {{
      printf("FAIL reserved decode {architectural_name(test["mnemonic"])}\\n");
      failures++;
    }}
    cases++;
  }}
"""


def check(axis_file: Path) -> bool:
    workdir = Path(tempfile.mkdtemp(prefix="axis_rt_"))
    emit(axis_file, "emit-encode-c", workdir / "axis_encode.h")
    emit(axis_file, "emit-decode-c", workdir / "axis_decode.h")
    emit(axis_file, "emit-encode-json", workdir / "encode.json")
    emit(axis_file, "emit-roundtrip-json", workdir / "roundtrip.json")

    fixtures = json.loads((workdir / "roundtrip.json").read_text())
    tests = fixtures["tests"]
    encode_table = json.loads((workdir / "encode.json").read_text())
    reserved = [
        case
        for entry in encode_table["instructions"]
        if (case := reserved_case(entry)) is not None
    ]
    if not tests:
        # Not a pass. A corpus with no encodable instruction proves nothing
        # about encoding, and this returning True is how the check would have
        # reported success on the scalable corpora for as long as their lanes
        # carried no encoding bits: 507 described instructions, no word to
        # encode, "nothing to run", green.
        print(f"{axis_file.name}: no encodable instruction, so nothing to "
              f"roundtrip -> FAIL")
        return False

    main_c = workdir / "main.c"
    main_c.write_text(
        '#include <stdio.h>\n#include <string.h>\n'
        '#include "axis_encode.h"\n#include "axis_decode.h"\n\n'
        "static int find_entry(const char *mnemonic) {\n"
        "  for (size_t i = 0; i < AXIS_ENCODE_TABLE_LEN; ++i) {\n"
        "    if (strcmp(AXIS_ENCODE_TABLE[i].mnemonic, mnemonic) == 0) {\n"
        "      return (int)i;\n"
        "    }\n"
        "  }\n"
        "  return -1;\n"
        "}\n\n"
        "int main(void) {\n"
        "  int failures = 0;\n"
        "  int cases = 0;\n"
        + "".join(c_case(test) for test in tests)
        + "".join(c_reserved_case(test) for test in reserved)
        + '  printf("%d cases, %d failures\\n", cases, failures);\n'
        "  return failures == 0 ? 0 : 1;\n"
        "}\n"
    )

    binary = workdir / "roundtrip"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-o", str(binary), str(main_c), "-lm"],
        check=True,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    # A corpus that produced no cases proves nothing, and the driver reports
    # "0 cases, 0 failures" -- which reads as a pass. It is how this check would
    # have passed on the scalable corpora before their lanes carried any
    # encoding bits at all: there was no word to encode, so there was nothing
    # to get wrong.
    empty = result.stdout.strip().startswith("0 cases")
    if empty:
        print(f"{axis_file.name}: no encodable instruction, so nothing to "
              f"roundtrip -> FAIL")
        return False
    status = "PASS" if result.returncode == 0 else "FAIL"
    print(f"{axis_file.name}: {result.stdout.strip()} -> {status}")
    # ⚠️ An instruction that cannot be encoded is a FAILURE, not a footnote.
    # Whatever a description says about semantics -- and plenty of instructions
    # state none, deliberately, because what they compute is undecided or
    # unexpressible -- every one of them must still assemble and decode. That is
    # the floor, and it used to be printed and passed over: a corpus whose
    # encodings quietly stopped round-tripping would say so in a line nobody
    # reads and stay green.
    #
    # The counts below are what each corpus skips today, and they are a ceiling
    # rather than a target. Any corpus not named must skip nothing. The scalable
    # ones are nonzero because their formats carry a field no operand binds
    # (`unbound_field`) -- a gap in those descriptions, recorded here so it
    # cannot grow while nobody is looking.
    allowed = KNOWN_UNENCODABLE.get(axis_file.name, 0)
    skipped = fixtures["skipped"]
    if skipped:
        names = ", ".join(item["mnemonic"] for item in skipped)
        print(f"{axis_file.name}: skipped (not encodable): {names}")
    if len(skipped) > allowed:
        reasons = sorted({item["reason"] for item in skipped})
        print(f"{axis_file.name}: {len(skipped)} instruction(s) cannot be "
              f"encoded, more than the {allowed} this corpus is known to "
              f"({', '.join(reasons)}). Every instruction must assemble and "
              f"decode whatever it says about semantics -> FAIL")
        return False
    return result.returncode == 0


#: Instructions each corpus cannot encode today, as a ceiling. Zero for any
#: corpus not named. See the note in `check`.
#:
#: ⚠️ Empty, and that is the point: every instruction in every corpus encodes.
#: It held 267 across five scalable corpora when it was written, which is what a
#: ceiling is for -- it made a silent backlog into a number, and then into a
#: number that could go down. Adding an entry here is admitting an instruction
#: nothing can assemble; do it only with a reason worth reading.
KNOWN_UNENCODABLE: dict[str, int] = {}


def main() -> int:
    files = [Path(arg) for arg in sys.argv[1:]]
    if not files:
        print(__doc__)
        return 2
    ok = all(check(axis_file) for axis_file in files)
    print("ROUNDTRIP CHECK PASSED" if ok else "ROUNDTRIP CHECK FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
