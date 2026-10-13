#!/usr/bin/env python3
"""PCE consumer-contract oracle: AXIS bundles satisfy the fields PCE reads.

This is retirement-step-1 of the pce-adl migration (see docs/pce_migration.md):
a self-contained gate that encodes the *exact* field surface and constraints the
real PCE/AHA consumers read, and validates AXIS `emit-bundle` output against it —
WITHOUT importing the PCE repo. So a drift in AXIS emitters (a renamed field, a
dropped encoding, an out-of-range opcode) fails here, in AXIS CI, before PCE ever
sees the bundle. The runtime companion (tools/pce_smoke_check.py) proves the same
bundle loads through the actual consumers; this proves it *keeps* loading.

The contract mirrored here (checked against PCE main, 2026-07-02):

  * load_adl_bundle_dir  -> required files manifest.json,
    rvmt_extension_manifest.json, aha_instructions.json (+ five optional).
  * adl_loader (strict)  -> aha_instructions.json schema == pce-adl.aha-instructions.v1,
    a non-empty instructions list.
  * _instruction_from_dict -> mnemonic (required str), encoding (required object:
    total_bits, opcode, func3, func7), and the metadata fields it coerces.
  * _operand_from_dict   -> name (required str), type, width_bits, is_output,
    is_optional, description.
  * xrv_extension.from_adl -> opcode in 7 bits, func3 in 3 bits, func7 (if present)
    in 7 bits, latency_cycles >= 1 — else it raises.

Usage: tools/pce_contract_check.py [input.axisl ...]

With no arguments it checks every AHA-emittable example. Requires cargo (run from
the AXIS repo root); no PCE checkout needed.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

AHA_SCHEMA = "pce-adl.aha-instructions.v1"
# load_adl_bundle_dir reads these by fixed name; the first three are required
# (_read_json raises if missing), the rest are optional (_read_optional_json).
REQUIRED_BUNDLE_FILES = ("manifest.json", "rvmt_extension_manifest.json", "aha_instructions.json")
# Not a file `load_adl_bundle_dir` reads today. It is pinned here because
# `aha/optisynth/adl_bridge.py` builds these axioms by re-parsing the
# `formal_semantics` *string* out of the bundle, and the point of emitting them
# is that the parser on that side can go away -- which it can only do if the
# artifact is here every time, under this name, with this shape.
AXIOM_BUNDLE_FILE = "intrinsic_axioms.smt2"
OPTIONAL_BUNDLE_FILES = (
    "adl_topology_manifest.json",
    "accelerator_descriptor_manifests.json",
    "adl_coupling_manifest.json",
    "rvmt_launch_templates.json",
    "rvmt_rcore_region_manifest.json",
)


class Failures:
    def __init__(self):
        self.items: list[str] = []

    def check(self, cond: bool, message: str) -> bool:
        if not cond:
            self.items.append(message)
        return cond


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _coercible_float(value) -> bool:
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def emit_bundle(axis_file: Path, out_dir: Path) -> bool:
    result = subprocess.run(
        [*axis_prefix(), "emit-bundle", str(axis_file), "-o", str(out_dir)],
        cwd=AXIS_ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def check_encoding(enc, mnemonic: str, f: Failures) -> None:
    ctx = f"{mnemonic}.encoding"
    if not f.check(isinstance(enc, dict), f"{mnemonic}: encoding must be an object (loader raises otherwise)"):
        return
    f.check("total_bits" in enc and _is_int(enc["total_bits"]), f"{ctx}.total_bits missing/not int")
    # opcode: required by from_adl and must fit 7 bits.
    ok_op = f.check("opcode" in enc and _is_int(enc["opcode"]), f"{ctx}.opcode missing/not int")
    if ok_op:
        f.check(0 <= enc["opcode"] < (1 << 7), f"{ctx}.opcode {enc['opcode']} does not fit 7 bits (from_adl raises)")
    # func3: AXIS always emits it; from_adl needs it in 3 bits.
    if "func3" in enc and enc["func3"] is not None:
        f.check(_is_int(enc["func3"]) and 0 <= enc["func3"] < (1 << 3),
                f"{ctx}.func3 {enc.get('func3')} not an int in 3 bits (from_adl raises)")
    # func7: optional; if present must fit 7 bits.
    if "func7" in enc and enc["func7"] is not None:
        f.check(_is_int(enc["func7"]) and 0 <= enc["func7"] < (1 << 7),
                f"{ctx}.func7 {enc.get('func7')} not an int in 7 bits (from_adl raises)")
    # `fields`: where every bit of the word comes from. The consumer's
    # `BitEncoding` has carried this list since before the manifest did, and
    # its loader fills it with `[]` -- which is why GRV's conformance surface
    # places operands by convention and says so. Checked here for the shape
    # that `BitField(name, start_bit, width_bits, value)` takes, and for the
    # property that makes it worth having: the fixed fields must reconstruct
    # the decoder's own match and mask.
    fields = enc.get("fields")
    if not f.check(isinstance(fields, list), f"{ctx}.fields missing/not a list"):
        return
    total = enc.get("total_bits", 32) if _is_int(enc.get("total_bits")) else 32
    covered = 0
    for index, one in enumerate(fields):
        where = f"{ctx}.fields[{index}]"
        if not f.check(isinstance(one, dict), f"{where} must be an object"):
            continue
        f.check(isinstance(one.get("name"), str) and one["name"], f"{where}.name required str")
        ok = f.check(_is_int(one.get("start_bit")) and _is_int(one.get("width_bits")),
                     f"{where} needs int start_bit and width_bits")
        if not ok:
            continue
        f.check(one["width_bits"] >= 1 and one["start_bit"] >= 0
                and one["start_bit"] + one["width_bits"] <= total,
                f"{where} lies outside the {total}-bit word")
        f.check(("value" in one) != ("operand_lo" in one),
                f"{where} is either a fixed field with a value or an operand slice "
                f"with an operand_lo, and says which")
        mask = ((1 << one["width_bits"]) - 1) << one["start_bit"]
        f.check(covered & mask == 0, f"{where} overlaps a field already placed")
        covered |= mask


def check_operand(op, mnemonic: str, index: int, f: Failures) -> None:
    ctx = f"{mnemonic}.operands[{index}]"
    if not f.check(isinstance(op, dict), f"{ctx} must be an object"):
        return
    f.check(isinstance(op.get("name"), str) and op["name"], f"{ctx}.name required str (_operand_from_dict raises)")
    f.check("type" in op and isinstance(op["type"], str), f"{ctx}.type missing/not str")
    f.check("width_bits" in op and _is_int(op["width_bits"]), f"{ctx}.width_bits missing/not int")
    f.check("is_output" in op and isinstance(op["is_output"], bool), f"{ctx}.is_output missing/not bool")
    f.check("is_optional" in op and isinstance(op["is_optional"], bool), f"{ctx}.is_optional missing/not bool")
    f.check("description" in op, f"{ctx}.description missing")


def check_instruction(insn, index: int, f: Failures) -> None:
    if not f.check(isinstance(insn, dict), f"instruction {index} must be an object"):
        return
    mnemonic = insn.get("mnemonic")
    if not f.check(isinstance(mnemonic, str) and mnemonic,
                   f"instruction {index}: mnemonic required str (_instruction_from_dict raises)"):
        return
    check_encoding(insn.get("encoding"), mnemonic, f)
    # Metadata fields the loader coerces.
    f.check(_is_int(insn.get("latency_cycles", 1)) and insn.get("latency_cycles", 1) >= 1,
            f"{mnemonic}.latency_cycles must be an int >= 1 (from_adl raises)")
    for field in ("throughput_per_cycle", "area_estimate_um2", "power_estimate_mw", "expected_speedup"):
        if field in insn:
            f.check(_coercible_float(insn[field]), f"{mnemonic}.{field} not float-coercible")
    if "applicable_patterns" in insn:
        f.check(isinstance(insn["applicable_patterns"], list), f"{mnemonic}.applicable_patterns not a list")
    operands = insn.get("operands", [])
    f.check(isinstance(operands, list), f"{mnemonic}.operands not a list")
    for i, op in enumerate(operands if isinstance(operands, list) else []):
        check_operand(op, mnemonic, i, f)


def check_bundle(bundle_dir: Path, f: Failures) -> None:
    # File-name contract (load_adl_bundle_dir).
    for name in REQUIRED_BUNDLE_FILES:
        path = bundle_dir / name
        if not f.check(path.is_file(), f"required bundle file missing: {name}"):
            continue
        try:
            payload = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            f.check(False, f"{name} is not valid JSON: {exc}")
            continue
        if name != "aha_instructions.json":
            f.check(isinstance(payload, dict), f"{name} must be a JSON object (_read_json)")
    axioms = bundle_dir / AXIOM_BUNDLE_FILE
    f.check(axioms.exists(), f"{AXIOM_BUNDLE_FILE} missing from the bundle")
    if axioms.exists():
        text = axioms.read_text()
        f.check(text.startswith("; Generated by AXIS."),
                f"{AXIOM_BUNDLE_FILE} does not carry the AXIS header")
        f.check("(set-logic " in text,
                f"{AXIOM_BUNDLE_FILE} states no logic")
        # An axiom file of only comments is a file that says nothing, and a
        # consumer would read it as "this description has no intrinsics" rather
        # than as "the emitter stopped working".
        declared = text.count("(declare-fun ")
        asserted = text.count("(assert ")
        f.check(declared == asserted,
                f"{AXIOM_BUNDLE_FILE} declares {declared} intrinsic(s) and asserts "
                f"{asserted} axiom(s); an undeclared or unconstrained symbol is "
                f"either a call nothing defines or a definition nothing calls")

    for name in OPTIONAL_BUNDLE_FILES:
        path = bundle_dir / name
        if path.is_file():
            try:
                payload = json.loads(path.read_text())
            except json.JSONDecodeError as exc:
                f.check(False, f"{name} is not valid JSON: {exc}")
                continue
            f.check(isinstance(payload, (dict, list)), f"{name} must be a JSON object or list (_read_optional_json)")

    aha_path = bundle_dir / "aha_instructions.json"
    if not aha_path.is_file():
        return
    aha = json.loads(aha_path.read_text())
    f.check(aha.get("schema") == AHA_SCHEMA,
            f"aha_instructions.json schema is {aha.get('schema')!r}, must be {AHA_SCHEMA!r} (adl_loader strict-rejects otherwise)")
    instructions = aha.get("instructions")
    if not f.check(isinstance(instructions, list) and instructions,
                   "aha_instructions.json instructions must be a non-empty list"):
        return
    for i, insn in enumerate(instructions):
        check_instruction(insn, i, f)
    check_fields_are_the_decoders(bundle_dir, instructions, f)


def check_fields_are_the_decoders(bundle_dir: Path, instructions: list, f: Failures) -> None:
    """The manifest's bit placement is the decoder's, not a second answer.

    Shape checks say the `fields` list is well formed. This says it is *true*:
    a fixed field is a bit the decoder matches on, so folding the fixed fields
    into a match and a mask has to reproduce exactly what `decode_table.json`
    carries -- the same numbers `axis_decode.h` and the lifters are built from.
    Without this the manifest could describe a plausible word that no decoder
    would accept, which is the failure a consumer placing operands by
    convention already lives with.
    """
    decode_path = bundle_dir / "decode_table.json"
    if not decode_path.is_file():
        return
    decoded = {entry["mnemonic"]: entry
               for entry in json.loads(decode_path.read_text()).get("instructions", [])}
    compared = 0
    for insn in instructions:
        entry = decoded.get(insn.get("mnemonic"))
        fields = (insn.get("encoding") or {}).get("fields")
        if entry is None or not isinstance(fields, list):
            continue
        match = mask = 0
        for one in fields:
            if not isinstance(one, dict) or "value" not in one:
                continue
            width, start = one.get("width_bits", 0), one.get("start_bit", 0)
            field_mask = ((1 << width) - 1) << start
            match |= (one["value"] << start) & field_mask
            mask |= field_mask
        f.check(match == int(entry["match"], 16) and mask == int(entry["mask"], 16),
                f"{insn['mnemonic']}: encoding.fields fold to "
                f"match=0x{match:08x} mask=0x{mask:08x}, but the decoder matches "
                f"{entry['match']}/{entry['mask']}")
        compared += 1
    # A run that compared nothing proves nothing: the manifest and the decode
    # table are keyed by mnemonic, and a rename on either side would silently
    # leave every instruction unpaired.
    f.check(compared == len(instructions),
            f"only {compared} of {len(instructions)} instruction(s) were paired with "
            f"a decode-table entry")


def emittable(axis_file: Path) -> bool:
    """AHA-emittable examples only (pure ops with encodings); PCE v1 is pure-only."""
    result = subprocess.run(
        [*axis_prefix(), "emit-aha-json", str(axis_file)],
        cwd=AXIS_ROOT, capture_output=True, text=True,
    )
    return result.returncode == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    args = parser.parse_args()

    if args.axis_files:
        targets = list(args.axis_files)
    else:
        targets = [p for p in sorted((AXIS_ROOT / "examples").glob("*.axisl")) if emittable(p)]

    total_failures = 0
    for axis_file in targets:
        f = Failures()
        bundle_dir = Path(tempfile.mkdtemp(prefix="axis_contract_"))
        if not emit_bundle(axis_file, bundle_dir):
            print(f"FAIL {axis_file.name}: emit-bundle failed")
            total_failures += 1
            continue
        check_bundle(bundle_dir, f)
        if f.items:
            print(f"FAIL {axis_file.name}: {len(f.items)} contract violation(s)")
            for item in f.items:
                print(f"    - {item}")
            total_failures += len(f.items)
        else:
            n = len(json.loads((bundle_dir / "aha_instructions.json").read_text())["instructions"])
            print(f"OK   {axis_file.name}: {n} instruction(s) satisfy the PCE consumer contract")

    print()
    ok = total_failures == 0
    print("PCE consumer contract: PASS" if ok else f"PCE consumer contract: FAIL ({total_failures} violations)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
