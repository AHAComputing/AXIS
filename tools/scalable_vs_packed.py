#!/usr/bin/env python3
"""Differential check: lane-indexed scalable instantiation vs the packed V1 expansion.

AXIS has two ways to say "this operator applies to each lane independently":

  * stage V1 packs the lanes into one bit-vector and separates them with shifts
    and masks (`src/simd.rs`), because a NEON Q register really is one 128-bit
    register; and
  * stage S1 instantiates a scalable vector lane-indexed, one ordinary scalar
    instruction per lane (`src/scalable.rs`), because a scalable vector has no
    width an AXIS scalar can hold -- `Sem::Int` is a u128.

They overlap exactly at VL <= 128, and that overlap is the evidence the newer
one is right: the packed path is already proven against golden, C, Rust, LLVM
and SMT, so agreeing with it lane by lane is a real check rather than a
self-consistency one. Beyond 128 bits only the lane-indexed path exists, which
is the whole reason it was built.

The two paths share no code: one emits shift/mask trees over a wide value, the
other emits scalar operators over narrow ones. A bug in either shows up here.

Usage: tools/scalable_vs_packed.py <scalable.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
PACKED_BITS = 128
# Scalable forms with no packed equivalent. `vdup` broadcasts a scalar and
# `vtail` marks a result partly unspecified; V1 packs fully-specified lanes of a
# real register and has neither concept.
NO_PACKED_FORM = ("vdup", "vtail")


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def load(path: Path):
    spec = importlib.util.spec_from_file_location(f"golden_{path.stem}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def to_packed(source: str) -> str:
    """Rewrite a scalable document into the packed V1 document it means at 128 bits.

    Only the vector spellings change: the same operators over the same operands,
    said the other way. Instructions using `vdup` are dropped because the packed
    expansion has no broadcast form -- stated here rather than silently skipped.
    """
    def widen(match: re.Match) -> str:
        kind, elem = match.group(1), int(match.group(2))
        if PACKED_BITS % elem:
            raise SystemExit(f"element width {elem} does not divide {PACKED_BITS}")
        return f"v{PACKED_BITS // elem}{kind}{elem}"

    packed = re.sub(r"\bvn([if])(\d+)\b", widen, source)
    # The packed register is one wide value, so operands and the register file
    # widen with it.
    # ⚠️ `reg128`, not `reg`. `reg` is one 64-bit slot, so declaring a
    # {PACKED_BITS}-bit operand in it is a value with nowhere to live -- which
    # validation refuses now, and which used to make the executor write past
    # the register into its neighbour.
    packed = re.sub(r"\breg i(8|16|32|64)\b", f"reg128 i{PACKED_BITS}", packed)
    packed = packed.replace('(registers "z[32]:i64"', f'(registers "z[32]:i{PACKED_BITS}"')
    packed = packed.replace("(word-bits 64)", f"(word-bits {PACKED_BITS})")
    packed = re.sub(r"\s*\(vector-bits \d+\)", "", packed)
    # Drop whole `definstruction` forms that use the broadcast form, by paren
    # matching rather than by splitting on text: this corpus has semicolons
    # inside quoted strings and parentheses inside comments, so any lexical
    # shortcut here miscounts.
    dropped = []
    while True:
        for begin in find_forms(packed, "(definstruction "):
            stop = matching_paren(packed, begin)
            form = packed[begin:stop]
            if any(f"({form_name} " in form for form_name in NO_PACKED_FORM):
                name = re.search(r"\(mnemonic (\S+?)\)", form)
                dropped.append(name.group(1) if name else "?")
                packed = packed[:begin] + packed[stop:]
                break
        else:
            break
    if dropped:
        print(
            f"note: no packed counterpart for {', '.join(dropped)}: "
            f"V1 has no {'/'.join(NO_PACKED_FORM)} form"
        )
    return packed


def find_forms(text: str, opener: str) -> list[int]:
    """Offsets of `opener` that are real syntax, not inside a comment or string."""
    offsets, in_string, in_comment = [], False, False
    for index, ch in enumerate(text):
        if in_comment:
            if ch == "\n":
                in_comment = False
            continue
        if in_string:
            if ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == ";":
            in_comment = True
        elif text.startswith(opener, index):
            offsets.append(index)
    return offsets


def matching_paren(text: str, begin: int) -> int:
    """Offset just past the paren that closes the one at `begin`."""
    depth, in_string, in_comment = 0, False, False
    for index in range(begin, len(text)):
        ch = text[index]
        if in_comment:
            if ch == "\n":
                in_comment = False
            continue
        if in_string:
            if ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch == ";":
            in_comment = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return index + 1
    raise SystemExit("unbalanced parentheses in the scalable document")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=64)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    if "(vector-bits 128)" not in source:
        print("this check compares at VL=128, the one length both representations reach")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_svp_"))
    packed_src = workdir / "packed.axisl"
    packed_src.write_text(to_packed(source))

    scalable_golden = workdir / "scalable_golden.py"
    packed_golden = workdir / "packed_golden.py"
    emit(args.axis_file, "emit-golden-python", scalable_golden)
    emit(packed_src, "emit-golden-python", packed_golden)
    scalable = load(scalable_golden)
    packed = load(packed_golden)

    # Regroup lanes using the facts the artifact publishes, not the name suffix.
    lanes: dict[str, dict[int, dict]] = {}
    for name, entry in scalable.AXIS_SPECS.items():
        origin = entry.get("scalable_origin")
        if origin is None:
            continue
        lanes.setdefault(origin, {})[entry["scalable_lane"]] = entry
    if not lanes:
        print("no scalable instructions found")
        return DECLINED

    random.seed(0x5CA1)
    checks = failures = 0
    compared = []
    for origin, by_lane in sorted(lanes.items()):
        reference = packed.AXIS_SPECS.get(origin)
        if reference is None:
            continue
        count = len(by_lane)
        elem = PACKED_BITS // count
        mask = (1 << elem) - 1
        compared.append(f"{origin}({count}x{elem})")
        for _ in range(args.cases):
            wide = [random.getrandbits(PACKED_BITS) for _ in reference["params"]]
            expected = reference["eval"](*wide)
            for lane in range(count):
                entry = by_lane[lane]
                narrow = [(value >> (lane * elem)) & mask for value in wide]
                if len(narrow) != len(entry["params"]):
                    raise SystemExit(
                        f"{origin} lane {lane}: packed takes {len(wide)} operands, "
                        f"lane takes {len(entry['params'])}"
                    )
                got = entry["eval"](*narrow)
                want = (expected >> (lane * elem)) & mask
                checks += 1
                if got != want:
                    failures += 1
                    if failures <= 5:
                        print(
                            f"FAIL {origin} lane {lane}: inputs "
                            f"{[hex(v) for v in narrow]} lane-indexed 0x{got:x} "
                            f"packed 0x{want:x}"
                        )

    if not compared:
        print("no instruction had both a scalable and a packed form")
        return DECLINED
    print(f"compared {len(compared)}: {', '.join(compared)}")
    print(f"{checks} lane comparisons, {failures} failures")
    print("lane-indexed == packed: " + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
