#!/usr/bin/env python3
"""The Python binding returns what the compiled decoder returns.

`axis_decode_ffi` exists so a script does not write its own decoder. That only
helps if the binding itself is faithful, and a binding's failures are not the
decoder's: they are marshalling. A `restype` left at its ctypes default
truncates a returned `const char *` to 32 bits; an index computed one place off
reads the right field of the wrong instruction; a scattered immediate gathered
in the wrong order produces a plausible number that is not the operand.

So this checks the boundary, not the logic behind it:

  * **the identity fields** -- mnemonic, ISA, format, match and mask for every
    index -- against `emit-decode-json`, which is the same table read a way
    that shares no code with the ABI;
  * **operand extraction against encoding**, over every roundtrip fixture: the
    fixture names operand values, the encoder turned them into a word, and
    reading them back out of that word must return what went in. This is the
    only genuinely new arithmetic in the ABI, and encoding is its inverse;
  * **the tree against the scan through the binding**, so a caller's own
    process is covered and not merely AXIS's ladder;
  * **misses and out-of-range indices**, since returning garbage confidently
    is worse here than raising.

Usage: tools/decode_ffi_check.py [<input.axisl> ...]   (default: every corpus)

Requires: cargo (or AXIS_BIN), a C compiler on PATH (cc).
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED, axis_prefix
from axis_decode_ffi import load

AXIS_ROOT = Path(__file__).resolve().parent.parent
LANE_OPERAND = re.compile(r"__l\d+$")


def emitted_json(axis_file: Path, command: str) -> dict:
    result = subprocess.run([*axis_prefix(), command, str(axis_file)],
                            capture_output=True, text=True, check=True,
                            cwd=AXIS_ROOT)
    return json.loads(result.stdout)


def check(axis_file: Path, cache: Path) -> int:
    table = emitted_json(axis_file, "emit-decode-json")["instructions"]
    if not table:
        print(f"{axis_file.name}: no decodable instruction, so no binding to "
              f"check -> DECLINE")
        return DECLINED
    decoder = load(axis_file, cache_dir=cache)
    failures: list[str] = []

    if decoder.count != len(table):
        failures.append(f"binding says {decoder.count} instructions, the table "
                        f"has {len(table)}")

    # 1. The identity fields, index by index.
    for index, entry in enumerate(table[:decoder.count]):
        word = int(entry["match"], 16)
        found = decoder.at(index, word)
        for field, want in (("mnemonic", entry["mnemonic"]),
                            ("isa", entry.get("isa", "")),
                            ("format", entry.get("format", ""))):
            got = getattr(found, field)
            if got != want:
                failures.append(f"index {index} {field}: binding {got!r}, "
                                f"table {want!r}")
        if found.match != word or found.mask != int(entry["mask"], 16):
            failures.append(f"index {index} {entry['mnemonic']}: binding "
                            f"match/mask 0x{found.match:08x}/0x{found.mask:08x}, "
                            f"table {entry['match']}/{entry['mask']}")

    # 2. Operand extraction is encoding run backwards.
    fixtures = emitted_json(axis_file, "emit-roundtrip-json")["tests"]
    extracted = 0
    for fixture in fixtures:
        word = int(fixture["encoded"], 16)
        found = decoder.decode(word)
        if found is None:
            # Not this gate's finding: `roundtrip_check.py` owns whether a
            # fixture's word decodes at all, and a lane group legitimately
            # decodes to its origin rather than to the lane.
            continue
        wanted = {operand["name"]: operand["value"]
                  for operand in fixture["operands"]
                  if not LANE_OPERAND.search(operand["name"])}
        for operand in found.operands:
            if operand.name not in wanted:
                continue
            extracted += 1
            if operand.value != wanted[operand.name]:
                failures.append(
                    f"{found.mnemonic} 0x{word:08x} operand {operand.name}: "
                    f"read {operand.value}, encoded {wanted[operand.name]}")

    # 3. Tree and scan, through the binding, in this process.
    seed = 0x9E3779B97F4A7C15
    agreed = 0
    for entry in table:
        base, mask = int(entry["match"], 16), int(entry["mask"], 16)
        words = [base, base ^ 1]
        for _ in range(4):
            seed = (seed * 6364136223846793005 + 1442695040888963407) & (2**64 - 1)
            words.append(base | ((seed >> 32) & (~mask & 0xFFFFFFFF)))
        for word in words:
            tree, scan = decoder.decode(word), decoder.decode_linear(word)
            agreed += 1
            if (tree is None) != (scan is None) or (
                    tree is not None and tree.index != scan.index):
                failures.append(f"0x{word:08x}: tree {tree and tree.mnemonic}, "
                                f"scan {scan and scan.mnemonic}")

    # 4. The ISA argument actually crosses the boundary. A `c_char_p` given a
    # `str` instead of `bytes` raises, but a subtler slip -- encoding it wrong,
    # or passing the name of an ISA the table spells differently -- would make
    # every qualified decode miss, and a gate that only ever passes NULL would
    # not notice. RET in `aarch64_translation_seed` decodes *only* when its ISA
    # is named, because an accelerator ISA in the same description claims the
    # same encoding space.
    qualified = 0
    for name in decoder.isas:
        for entry in table:
            if entry.get("isa", "") != name:
                continue
            word = int(entry["match"], 16)
            tree, scan = decoder.decode(word, name), decoder.decode_linear(word, name)
            if (tree is None) != (scan is None) or (
                    tree is not None and tree.index != scan.index):
                failures.append(f"isa={name} 0x{word:08x}: tree "
                                f"{tree and tree.mnemonic}, scan {scan and scan.mnemonic}")
            qualified += tree is not None
    if decoder.isas and not qualified:
        failures.append(f"no word decoded under any of its own ISAs "
                        f"({', '.join(decoder.isas)}), so the isa argument "
                        f"never reached the decoder")

    # 5. Bulk decoding is the path a miner actually uses, and it is a second
    # marshalling surface: array types, an out-buffer the C side fills, and
    # words assembled from bytes. It has to give the same answers as the
    # per-word path that the rest of this gate just checked.
    sample = [int(entry["match"], 16) for entry in table]
    sample += [word ^ 0x5A5A5A5A for word in sample[:64]]
    single = [(lambda found: found.index if found else -1)(decoder.decode(word))
              for word in sample]
    bulk = decoder.decode_many(sample)
    if bulk != single:
        differing = [i for i, (a, b) in enumerate(zip(single, bulk)) if a != b]
        failures.append(f"decode_many disagrees with decode on "
                        f"{len(differing)} of {len(sample)} words, first at "
                        f"0x{sample[differing[0]]:08x}")
    # The same words as a little-endian image, which is what a section is.
    image = b"".join(word.to_bytes(4, "little") for word in sample)
    if decoder.decode_bytes(image) != single:
        failures.append("decode_bytes disagrees with decode on the same words "
                        "laid out little-endian")
    # A trailing partial word is not a word.
    if decoder.decode_bytes(image + b"\x01\x02") != single:
        failures.append("decode_bytes did not ignore a trailing partial word")
    if decoder.decode_many([]) or decoder.decode_bytes(b""):
        failures.append("an empty buffer decoded to something")
    # And the operands, in bulk, against the ones built one at a time.
    widest = max((len(found.operands) for found in
                  (decoder.decode(word) for word in sample) if found), default=0)
    if widest:
        rows = decoder.operands_many(sample, single, stride=widest)
        for word, index, row in zip(sample, single, rows):
            if index < 0:
                continue
            want = [operand.value for operand in decoder.decode(word).operands]
            if row[:len(want)] != want or any(row[len(want):]):
                failures.append(f"operands_many for 0x{word:08x}: {row}, "
                                f"one at a time {want}")
                break
        # Too narrow a stride must say so rather than truncate silently.
        if widest > 1:
            try:
                decoder.operands_many(sample, single, stride=widest - 1)
                failures.append(f"operands_many accepted stride {widest - 1} "
                                f"when an instruction has {widest} operands")
            except ValueError:
                pass

    # 6. The boundary's edges.
    if decoder.at(-1, 0) is not None:
        failures.append("index -1 returned an instruction")
    for out_of_range in (decoder.count, decoder.count + 1000):
        beyond = decoder.at(out_of_range, 0)
        if beyond is not None and beyond.mnemonic:
            failures.append(f"index {out_of_range} returned "
                            f"{beyond.mnemonic!r} past the end of the table")

    if not extracted:
        # Every fixture's operands were lane selectors, or there were none. The
        # identity checks still ran, but the arithmetic this gate exists for
        # did not, and reporting that as a pass is how a vacuous gate is born.
        print(f"{axis_file.name}: {decoder.count} instructions, no operand was "
              f"read back, so extraction proved nothing -> DECLINE")
        return DECLINED
    if failures:
        print(f"{axis_file.name}: {len(failures)} disagreement(s) -> FAIL")
        for line in failures[:8]:
            print(f"     {line}")
        return FAILED
    print(f"{axis_file.name}: {decoder.count} instructions, {extracted} operand(s) "
          f"read back, {agreed} tree/scan comparison(s), {qualified} ISA-qualified, "
          f"{len(sample)} bulk -> PASS")
    return PASSED


def main() -> int:
    files = [Path(arg) for arg in sys.argv[1:]] or sorted(
        (AXIS_ROOT / "examples").glob("*.axisl"))
    with tempfile.TemporaryDirectory() as cache:
        results = [check(axis_file, Path(cache)) for axis_file in files]
    checked = results.count(PASSED)
    print(f"{len(results)} binding(s): {checked} checked, "
          f"{results.count(DECLINED)} with nothing to read back, "
          f"{results.count(FAILED)} disagreeing")
    if FAILED in results:
        print("DECODE FFI CHECK FAILED")
        return FAILED
    if not checked:
        print("DECODE FFI CHECK DECLINED: no corpus exercised the binding")
        return DECLINED
    print("DECODE FFI CHECK PASSED")
    return PASSED


if __name__ == "__main__":
    sys.exit(main())
