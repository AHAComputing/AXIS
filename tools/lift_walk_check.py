#!/usr/bin/env python3
"""Bytes to instructions: the lifter walks an image, and every row is right. Gate.

The lift library answers about a word a caller already has. A consumer holding
a binary has BYTES, and the thing it cannot work out for itself is the step
between two instructions: a description whose instructions are not all one
width -- RISC-V with the compressed extension -- misaligns after the first
16-bit one, and every word after it decodes to nothing. That reads as a
description that is missing them and is really a fact about the walk.
`binary_coverage.py` measured 60.7% on a compiled object for exactly that
reason.

So the pack walks. This gate builds an image out of the description's own
roundtrip fixtures, laid out at each instruction's own width, and requires the
walk to hand back exactly what was laid down: the same offsets, the same
instructions, the same operands the Python lifter decodes, the same widths.

⚠️ And the three-valued `ends_block`, which is the part worth being careful
about. A branch is 1. An instruction performed by a routine the description
only names is 2 -- AArch64's `braaz` authenticates a pointer and jumps to it,
and its description is one line of prose -- and so are bytes that decode to
nothing, because a literal pool is not the continuation of a basic block. A
library that answered 0 for either would let a consumer walk through a branch
and call what follows the same block, which is the failure this whole field
exists to prevent, so the gate plants both cases and checks them.

⚠️ One column here is not measured: `operand_valid`. Forcing it to 1 in the
library is not caught, because no description AXIS has contains an operand that
is neither encoded in the word nor derived from one that is -- a lane operand
and AArch64's `casp` pair both derive -- so the column is all ones in every
corpus and there is nothing for a wrong answer to differ from. Said here rather
than left for a reader to assume the whole row is held.

Usage: tools/lift_walk_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Where the caller says the image starts, so `address` is not `offset`.
BASE = 0x40_0000
#: How many instructions to lay down.
LENGTH = 40

HARNESS = r"""
/* A consumer with an image and a pack. */
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_lift_pack *%(lift)s(void);

static const uint8_t IMAGE[] = { %(image)s };
#define ROWS 256

int main(void) {
  const axis_lift_pack *L = %(lift)s();
  if (!L->walk || !L->block || !L->ends_block || !L->instruction_bits) {
    printf("NOWALK\n"); return 0;
  }
  axis_pack_walked rows[ROWS];
  int32_t found = L->walk(IMAGE, (int32_t)sizeof IMAGE, %(base)sull, %(isa)s, rows, ROWS);
  printf("WALK %%d\n", found);
  for (int32_t i = 0; i < found; ++i) {
    printf("ROW %%d %%d 0x%%llx %%d 0x%%08x %%d %%d %%d", i, rows[i].offset,
           (unsigned long long)rows[i].address, rows[i].bytes, rows[i].word,
           rows[i].index, rows[i].ends_block, rows[i].operand_count);
    for (int32_t o = 0; o < rows[i].operand_count && o < AXIS_PACK_MAX_OPERANDS; ++o) {
      printf(" %%u/%%d", rows[i].operands[o], (int)rows[i].operand_valid[o]);
    }
    printf("\n");
    /* The directory must agree with the row: a walk that filled `ends_block`
       from somewhere else would pass every other check here. */
    if (rows[i].index >= 0 &&
        (L->ends_block(rows[i].index) != rows[i].ends_block ||
         (int32_t)(L->instruction_bits(rows[i].index) / 8u) != rows[i].bytes)) {
      printf("DISAGREE %%d directory says %%d/%%u, the row says %%d/%%d\n", i,
             L->ends_block(rows[i].index), L->instruction_bits(rows[i].index),
             rows[i].ends_block, rows[i].bytes);
    }
  }

  /* A block stops at the first instruction that ends one, and nowhere else. */
  int32_t got = L->block(IMAGE, (int32_t)sizeof IMAGE, %(base)sull, %(isa)s, rows, ROWS);
  printf("BLOCK %%d last_ends=%%d\n", got, got > 0 ? rows[got - 1].ends_block : -1);
  int32_t early = 0;
  for (int32_t i = 0; i + 1 < got; ++i) { if (rows[i].ends_block) { ++early; } }
  printf("BLOCKEARLY %%d\n", early);

  /* An index nobody has is `2`: "cannot say" is the only safe answer about an
     instruction the library does not have. */
  printf("OUTOFRANGE %%d %%d %%u\n", L->ends_block(-1), L->ends_block(L->count()),
         L->instruction_bits(-1));
  /* Arguments a caller gets wrong are answered, not trusted. */
  printf("REFUSED %%d %%d %%d\n",
         L->walk(NULL, 16, %(base)sull, %(isa)s, rows, ROWS),
         L->walk(IMAGE, (int32_t)sizeof IMAGE, %(base)sull, %(isa)s, NULL, ROWS),
         L->walk(IMAGE, (int32_t)sizeof IMAGE, %(base)sull, %(isa)s, rows, 0));
  /* A buffer that ends mid-instruction stops rather than reading past it. */
  int32_t cut = L->walk(IMAGE, 3, %(base)sull, %(isa)s, rows, ROWS);
  printf("CUT %%d\n", cut);
  return 0;
}
"""


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def reference_walk(lift, image: bytes, isa: str, bits: dict, step: int):
    """The same walk, in Python, from the Python lift table.

    ⚠️ Not a restatement of the C for its own sake. The image is laid down from
    fixtures and a gate could compare against THAT -- but an undecodable word
    is honestly two rows in a description that has 16-bit instructions, a
    16-bit instruction at the end of a buffer has no upper half, and the list
    of what was laid down cannot express either. So the reference is a walk,
    the two walks must agree row for row, and `laid` is kept only as the
    anchor that every instruction actually put in the image came back at the
    offset it was put at -- which is what catches two walks agreeing wrongly.
    """
    index_of = {id(entry): i for i, entry in enumerate(lift.AXIS_LIFT_TABLE)}
    rows = []
    at = 0
    while at + 2 <= len(image):
        word = image[at] | (image[at + 1] << 8)
        if at + 4 <= len(image):
            word |= (image[at + 2] << 16) | (image[at + 3] << 24)
        entry = lift.decode(word, isa)
        row = {"offset": at, "address": BASE + at, "word": word, "index": -1,
               "ends_block": 2, "operands": [], "bytes": step}
        if entry is not None:
            row["index"] = index_of[id(entry)]
            row["ends_block"] = expected_ends_block(entry)
            row["bytes"] = bits.get(entry["mnemonic"], 32) // 8 or step
            decoded = lift.lift_entry(word, entry)["operands"]
            row["operands"] = [
                (0, 0) if decoded.get(op["name"]) is None
                else (decoded[op["name"]], 1) for op in entry["operands"]]
        rows.append(row)
        at += row["bytes"]
    return rows


def expected_ends_block(entry) -> int:
    """What the description says, derived from the Python table rather than
    from the C one the library was built from."""
    kinds = {effect["kind"] for effect in (entry.get("effects") or [])}
    if kinds & {"setpc", "trap"}:
        return 1
    if entry.get("implementation"):
        return 2
    if not entry.get("effects") and not entry.get("semantics"):
        return 2
    return 0


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    # Only the lifter: `sve`'s simulator reads more registers than the pack
    # contract carries and stops that build by design, and a gate about walking
    # bytes should still be able to ask that description to walk bytes.
    manifest = build_pack.build(axis_file, work / "packs", only={"lift"})
    name = manifest["name"]
    if "lift" not in manifest["libraries"]:
        print(f"  {name}: no lift library")
        return 0, 1
    sys.path.insert(0, str(work))
    run([*axis_prefix(), "emit-lift-python", str(axis_file),
         "-o", str(work / "axis_lift.py")])
    lift = importlib.import_module("axis_lift")
    tests = json.loads(run([*axis_prefix(), "emit-roundtrip-json",
                            str(axis_file)]).stdout)["tests"]
    table = json.loads(run([*axis_prefix(), "emit-decode-json",
                            str(axis_file)]).stdout)
    bits = {entry["mnemonic"]: entry["bits"]
            for entry in table.get("instructions", table.get("entries", []))}

    # One ISA, so a word two of them claim is not being asked about here.
    counted: dict[str, int] = {}
    for test in tests:
        counted[test.get("isa") or ""] = counted.get(test.get("isa") or "", 0) + 1
    if not counted:
        print(f"  {name}: DECLINED the description has no fixtures to lay down")
        return 0, 0
    isa = max(counted, key=counted.get)
    usable = [t for t in tests if (t.get("isa") or "") == isa
              and bits.get(t["mnemonic"], 32) % 8 == 0]
    # ⚠️ Instructions with an operand the WORD DOES NOT CARRY go in first when
    # the description has any -- AArch64's `casp` pair, whose second register
    # is derived rather than encoded. Drawing fixtures in table order laid down
    # forty instructions whose every operand was encoded, and the `valid` flag
    # was then a column of ones that a library could get wrong unnoticed.
    uncarried = {entry["mnemonic"] for entry in lift.AXIS_LIFT_TABLE
                 if any(not operand["fields"] for operand in entry["operands"])}
    # And at least one instruction that ENDS a block, when the description has
    # one: everything this gate says about a block boundary is empty without it.
    enders = {entry["mnemonic"] for entry in lift.AXIS_LIFT_TABLE
              if expected_ends_block(entry) == 1}
    # ⚠️ And one the library WILL NOT VOUCH FOR -- an instruction performed by
    # a routine. There are eight of those in a corpus of nine hundred, they sort
    # last by every other criterion, and a table that called them ordinary
    # instructions passed this gate until they were drawn on purpose.
    unvouched = {entry["mnemonic"] for entry in lift.AXIS_LIFT_TABLE
                 if expected_ends_block(entry) == 2}
    usable.sort(key=lambda test: (test["mnemonic"] not in uncarried,
                                  test["mnemonic"] not in enders | unvouched))
    if len(usable) < 4:
        print(f"  {name}: DECLINED only {len(usable)} fixture(s) in {isa!r}")
        return 0, 0

    # ⚠️ A word that decodes to NOTHING, planted in the middle. Every other row
    # here is an instruction, and a walk that could not carry on past a literal
    # pool would still pass the rest of this gate.
    junk = None
    for candidate in (0x00000000, 0xFFFFFFFF, 0xDEADBEEF, 0x0BADC0DE):
        if lift.lift(candidate, isa) is None:
            junk = candidate
            break

    narrowest = min((width for width in bits.values() if width), default=32)
    step = narrowest // 8 or 4
    laid: list[tuple[int, str]] = []   # (offset, mnemonic)
    image = bytearray()
    for i, test in enumerate(usable[:LENGTH]):
        if junk is not None and i == len(usable[:LENGTH]) // 2:
            image += (junk & ((1 << (8 * step)) - 1)).to_bytes(step, "little")
        word = int(test["encoded"], 16)
        width = bits.get(test["mnemonic"], 32) // 8
        laid.append((len(image), test["mnemonic"]))
        image += word.to_bytes(width, "little")

    source = HARNESS % {
        "lift": manifest["libraries"]["lift"]["entry"],
        "image": ", ".join(f"0x{byte:02x}" for byte in image),
        "isa": f'"{isa}"' if isa else "NULL",
        "base": hex(BASE),
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
         "-o", str(work / name), str(work / f"{name}.c"),
         str(root / "lib" / manifest["libraries"]["lift"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode < 0:
        print(f"  FAIL {name}: the harness died on signal {-done.returncode}")
        return 0, 1

    rows: list[dict] = []
    said: dict[str, list[str]] = {}
    checks = failures = 0
    for line in done.stdout.splitlines():
        head, _, rest = line.partition(" ")
        if head == "ROW":
            parts = rest.split()
            rows.append({
                "offset": int(parts[1]), "address": int(parts[2], 16),
                "bytes": int(parts[3]), "word": int(parts[4], 16),
                "index": int(parts[5]), "ends_block": int(parts[6]),
                "operands": [tuple(int(x) for x in p.split("/"))
                             for p in parts[8:]],
            })
        else:
            said.setdefault(head, []).append(rest)

    if "NOWALK" in said:
        print(f"  FAIL {name}: the lift pack carries no walk")
        return 0, 1
    for line in said.get("DISAGREE", []):
        print(f"  FAIL {name}: the directory and the row disagree -- {line}")
        failures += 1

    expect = reference_walk(lift, bytes(image), isa, bits, step)
    checks += 1
    if len(rows) != len(expect):
        print(f"  FAIL {name}: the library walked {len(rows)} instruction(s) "
              f"out of {len(image)} bytes, the reference walk finds "
              f"{len(expect)}")
        failures += 1
    for want, row in zip(expect, rows):
        checks += 1
        if row != want:
            differs = [key for key in want if row.get(key) != want[key]]
            print(f"  FAIL {name}: the row at {want['offset']} differs in "
                  f"{differs}: " + ", ".join(
                      f"{key}={row.get(key)} want {want[key]}"
                      for key in differs))
            failures += 1
            break

    # ⚠️ The anchor. Two walks that stepped wrongly in the same way would agree
    # with each other and disagree with the image, and only this notices: every
    # instruction that was actually laid down has a row at the offset it was
    # laid at, naming it.
    at_offset = {row["offset"]: row for row in rows}
    for offset, mnemonic in laid:
        checks += 1
        row = at_offset.get(offset)
        entry = (lift.AXIS_LIFT_TABLE[row["index"]]
                 if row and row["index"] >= 0 else None)
        if entry is None or entry["mnemonic"] != mnemonic:
            print(f"  FAIL {name}: {mnemonic} was laid at {offset} and the "
                  f"walk has {entry['mnemonic'] if entry else None} there")
            failures += 1
            break

    # A block ends where the description says and not before.
    checks += 1
    ends = [i for i, row in enumerate(rows) if row["ends_block"]]
    block = said.get("BLOCK", ["0 last_ends=-1"])[0].split()
    got = int(block[0])
    want = (ends[0] + 1) if ends else len(rows)
    if got != want:
        print(f"  FAIL {name}: the block is {got} instruction(s), the first "
              f"that ends one is at {ends[0] if ends else None}")
        failures += 1
    checks += 1
    if said.get("BLOCKEARLY", ["-1"])[0].strip() != "0":
        print(f"  FAIL {name}: the block carried "
              f"{said['BLOCKEARLY'][0].strip()} instruction(s) past one that "
              f"ends a block")
        failures += 1

    checks += 1
    out_of_range = said.get("OUTOFRANGE", [""])[0].split()
    if out_of_range[:2] != ["2", "2"] or out_of_range[2:] != ["0"]:
        print(f"  FAIL {name}: out of range answered {out_of_range}, want "
              f"['2', '2', '0'] -- a zero there means 'control cannot leave "
              f"here' about an instruction the library does not have")
        failures += 1
    checks += 1
    if said.get("REFUSED", [""])[0].split() != ["-1", "-1", "0"]:
        print(f"  FAIL {name}: bad arguments answered "
              f"{said.get('REFUSED')}, want -1 -1 0")
        failures += 1
    checks += 1
    if said.get("CUT", [""])[0].strip() not in ("0", "1"):
        print(f"  FAIL {name}: a three-byte buffer walked "
              f"{said.get('CUT')} instruction(s)")
        failures += 1

    # ⚠️ Vacuity, said out loud. Every claim above about a block boundary is
    # empty if the image held no branch, and the gate would still print PASS.
    kinds = {value: sum(1 for row in rows if row["ends_block"] == value)
             for value in (0, 1, 2)}
    # ⚠️ A description with no control flow at all -- SVE here is arithmetic
    # and loads -- has no block boundary to check, and saying so is not the
    # same as failing to check one that exists.
    if enders:
        checks += 1
        if not kinds[1]:
            print(f"  FAIL {name}: the description has {len(enders)} "
                  f"instruction(s) that end a block and the image held none, "
                  f"so nothing here checked one")
            failures += 1
    nothing_here = sum(1 for row in rows if row["index"] < 0)
    checks += 1
    if junk is not None and not nothing_here:
        print(f"  FAIL {name}: a word that decodes to nothing was planted and "
              f"no row reports one")
        failures += 1
    # The two ways a row can be a 2, kept apart: bytes that decode to nothing,
    # and an instruction the description names a routine for.
    if unvouched:
        checks += 1
        if not any(row["index"] >= 0 and row["ends_block"] == 2 for row in rows):
            print(f"  FAIL {name}: the description has {len(unvouched)} "
                  f"instruction(s) it will not vouch for and the image held "
                  f"none")
            failures += 1
    if not failures:
        print(f"  {name}: {len(rows)} instruction(s) walked out of "
              f"{len(image)} bytes -- {kinds[1]} ending a block"
              + ("" if enders else " (the description has none)")
              + f", {kinds[2]} the library will not vouch for -- "
              f"{checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp))
            except subprocess.CalledProcessError as error:
                # ⚠️ `build_pack` runs its own commands and does not always
                # capture, so `stderr` can be None -- and a gate that died
                # here reported an AttributeError instead of the build failure
                # it was holding.
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:400]}")
                did, bad = 0, 1
            checks += did
            failures += bad
            sys.modules.pop("axis_lift", None)
            if str(Path(tmp)) in sys.path:
                sys.path.remove(str(Path(tmp)))
    if not checks and not failures:
        print("the walk == what was laid down: SKIP")
        return DECLINED
    print(f"the walk == what was laid down: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
