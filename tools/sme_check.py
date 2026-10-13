#!/usr/bin/env python3
"""SME's outer products at SME's geometry: fused, predicated twice, one ZA. Gate.

S1 and S2a (docs/accelerator_design.md). `examples/sme.axisl` describes FMOPA
and FMOPS (.S), FMOPA (.D) and the widening integer family (SMOPA, UMOPA,
SUMOPA, USMOPA, SMOPS) at SVL = 512: Z and P are 512 bits, ZA is ONE array of
64 rows, and a tile is a view of it -- row i of ZA<n>.S is ZA row 4i+n, of
ZA<n>.D row 8i+n. Every claim is held to a reference written HERE, from Arm's
description, over that one array:

  1. **every executor computes the tile, in the array.** Each instruction runs
     on the Python executor and the compiled wide C and Rust executors from a
     machine whose every Z, P and ZA row holds random bytes, and the WHOLE
     register file afterwards must be the reference's: the tile's rows updated
     where the view puts them, and nothing else changed;
  2. **the views share storage.** ZA<n>.D's rows are rows ZA<n'>.S also names
     (ZA row 9 is ZA1.D's row 1 and ZA1.S's row 2). The reference updates the
     one array, so an interleave off by one row, or tiles given storage of
     their own, fails 1 -- and the gate requires that a .D trial wrote a row
     some .S tile names, so the sharing was exercised, not assumed;
  3. **FMOPA is fused.** a*b+c computed exactly and rounded ONCE, at single and
     at double precision. Cancellation inputs -- c the negation of a*b rounded
     -- make fused and unfused answers differ, and the gate requires that they
     did, so "fused" is a claim some input tested;
  4. **both predicates govern.** Element (i, j) changes only where pn's element
     i and pm's element j are active; each source BYTE of a widening product is
     governed by its own predicate bit. The gate requires that some element was
     held and some changed;
  5. **a slice is chosen at run time** (S2b). MOVA moves row or column
     `(ws + imm) mod 16` -- ws a general register holding a small or a full
     64-bit value -- into a tile or out of one, merging by its predicate. The
     general registers are part of the compared file, and the gate requires
     that some index wrapped past the tile;
  6. **a slice moves to and from memory, as Arm says** (S2c). LD1W and ST1W
     move a slice between a tile and Xn + (Xm << 2), Xm sometimes XZR. A load
     writes an inactive element with ZERO and does not read it; a store writes
     no inactive element. Every executor gets a memory holding the 16 words
     the slice touches, memory is compared with the registers, and the gate
     requires that some load zeroed an inactive element and some store left
     one unwritten.

Injection-checked: spelling FMOPA as `fadd` of `fmul` fails 3; swapping
`vrows` and `vcols` in SMOPA fails 1; governing the widening bytes by byte 0's
bit alone fails 4; a `za_s` group step of 1 (tiles contiguous rather than
interleaved) fails 1 and 2; and for 5, ignoring the immediate, reading a
horizontal slice vertically, dropping the modulo, and swapping `vrow` and
`vcol` in `scalable.rs` each fail; for 6, a load that keeps inactive elements
instead of zeroing them, an unguarded store, the index scaled by eight, and a
horizontal load addressed by row each fail.

Usage: tools/sme_check.py <input.axisl> [--python-only]
"""

from __future__ import annotations

import argparse
import importlib
import random
import struct
import sys
import tempfile
from fractions import Fraction
from pathlib import Path

import exec_wide_check as wide

SVL = 512
ROW_BYTES = SVL // 8                    # a ZA row, a Z register, a P register
ZA_ROWS = SVL // 8                      # ZA is SVL/8 rows of SVL bits
REG_SLOTS = SVL // 64

# mnemonic: element bits. Encodings are Arm's; see `word`.
INSTRUCTIONS = {
    "FMOPA_S": 32, "FMOPS_S": 32, "SMOPA_S": 32, "UMOPA_S": 32, "SUMOPA_S": 32,
    "USMOPA_S": 32, "SMOPS_S": 32, "FMOPA_D": 64,
    # S2b: one slice, chosen at run time. Z -> tile (H, V), tile -> Z (H, V).
    "MOVA_ZTH": 32, "MOVA_ZTV": 32, "MOVA_TZH": 32, "MOVA_TZV": 32,
    # S2c: a slice to or from memory at Xn + (Xm << 2).
    "LD1W_H": 32, "LD1W_V": 32, "ST1W_H": 32, "ST1W_V": 32,
}
SIGNS = {"SMOPA_S": (1, 1), "UMOPA_S": (0, 0), "SUMOPA_S": (1, 0),
         "USMOPA_S": (0, 1), "SMOPS_S": (1, 1)}
FORMAT = {32: dict(pack="<f", unpack="<I", mant=23, emin=-126, emax=128),
          64: dict(pack="<d", unpack="<Q", mant=52, emin=-1022, emax=1024)}


def to_float(bits: int, width: int) -> float:
    f = FORMAT[width]
    return struct.unpack(f["pack"], struct.pack(f["unpack"], bits))[0]


def to_bits(value: float, width: int) -> int:
    f = FORMAT[width]
    return struct.unpack(f["unpack"], struct.pack(f["pack"], value))[0]


def round_exact(exact: Fraction, width: int, negative_zero: bool) -> int:
    """Round an exact rational to binary32/64, nearest-even, ONCE."""
    f = FORMAT[width]
    sign_bit = 1 << (width - 1)
    if exact == 0:
        return sign_bit if negative_zero else 0
    sign = sign_bit if exact < 0 else 0
    a = abs(exact)
    e = a.numerator.bit_length() - a.denominator.bit_length()
    if Fraction(2) ** e > a:
        e -= 1
    quantum = Fraction(2) ** (max(e, f["emin"]) - f["mant"])
    scaled = a / quantum
    whole = scaled.numerator // scaled.denominator
    rest = scaled - whole
    if rest > Fraction(1, 2) or (rest == Fraction(1, 2) and whole & 1):
        whole += 1
    value = whole * quantum
    if value >= Fraction(2) ** f["emax"]:
        return sign | to_bits(float("inf"), width)
    return sign | to_bits(float(value), width)


def fma(a: int, b: int, c: int, width: int) -> int:
    x, y, z = (to_float(v, width) for v in (a, b, c))
    sign_bit = 1 << (width - 1)
    exact = Fraction(x) * Fraction(y) + Fraction(z)
    # IEEE 754: an exact zero sum is +0 unless both addends are negative zeros.
    negative_zero = bool((a ^ b) & sign_bit) and bool(c & sign_bit) and x * y == 0 and z == 0
    return round_exact(exact, width, negative_zero)


def unfused(a: int, b: int, c: int, width: int) -> int | None:
    fmt = "<f" if width == 32 else "<d"
    try:
        product = struct.unpack(fmt, struct.pack(fmt, to_float(a, width) * to_float(b, width)))[0]
        return to_bits(product + to_float(c, width), width)
    except OverflowError:
        return None


def get(buf: bytearray, index: int, width: int) -> int:
    size = width // 8
    return int.from_bytes(buf[index * size:(index + 1) * size], "little")


def put(buf: bytearray, index: int, width: int, value: int) -> None:
    size = width // 8
    buf[index * size:(index + 1) * size] = (value & ((1 << width) - 1)).to_bytes(size, "little")


def tile_row(width: int, tile: int, i: int) -> int:
    """The ZA row that row i of ZA<tile> at this element width is."""
    return i * (width // 8) + tile


def byte_of(bits: int, t: int, signed: bool) -> int:
    value = (bits >> (8 * t)) & 0xFF
    return value - 256 if signed and value & 0x80 else value


def slice_index(t: dict) -> int:
    """Arm's slice number: the register plus the immediate, modulo the tile."""
    return (t["x"][t["ws_r"]] + t["imm"]) % (SVL // t["width"])


def reference(t: dict, za: list[bytearray]) -> list[bytearray]:
    """ZA after the instruction: one array, updated through the tile's view.
    A slice READ changes a Z register instead, which `t["z"]` carries."""
    mnemonic, width, tile = t["mnemonic"], t["width"], t["tile"]
    side = SVL // width
    out = [bytearray(row) for row in za]
    if mnemonic.startswith(("LD1W", "ST1W")):
        k = slice_index(t)
        pg, mem = t["pg"], t["mem"]
        for e in range(side):
            i, j = (k, e) if mnemonic.endswith("H") else (e, k)
            row = out[tile_row(width, tile, i)]
            address = t["address"] + 4 * e
            active = get(pg, e, width) & 1
            if mnemonic.startswith("LD1W"):
                # Arm's /Z: an inactive element is ZERO, and memory is not read.
                put(row, j, width, mem.get(address, 0) if active else 0)
            elif active:
                t["mem_after"][address] = get(za[tile_row(width, tile, i)], j, width)
        return out
    if mnemonic.startswith("MOVA"):
        k = slice_index(t)
        zn, pg = t["zn"], t["pg"]
        for e in range(side):
            if not get(pg, e, width) & 1:
                continue
            i, j = (k, e) if mnemonic.endswith("H") else (e, k)
            if mnemonic.startswith("MOVA_ZT"):
                put(out[tile_row(width, tile, i)], j, width, get(zn, e, width))
            else:
                put(zn, e, width, get(za[tile_row(width, tile, i)], j, width))
        return out
    zn, zm, pn, pm = (t[name] for name in ("zn", "zm", "pn", "pm"))
    for i in range(side):
        row = out[tile_row(width, tile, i)]
        for j in range(side):
            old = get(row, j, width)
            if mnemonic.startswith("FMOP"):
                if get(pn, i, width) & 1 and get(pm, j, width) & 1:
                    a = get(zn, i, width) ^ ((1 << (width - 1)) if mnemonic == "FMOPS_S" else 0)
                    put(row, j, width, fma(a, get(zm, j, width), old, width))
            else:
                sn, sm = SIGNS[mnemonic]
                a, b, p, q = get(zn, i, 32), get(zm, j, 32), get(pn, i, 32), get(pm, j, 32)
                total = sum(byte_of(a, k, sn) * ((p >> (8 * k)) & 1)
                            * byte_of(b, k, sm) * ((q >> (8 * k)) & 1) for k in range(4))
                put(row, j, width, old + (-total if mnemonic == "SMOPS_S" else total))
    return out


def random_float(rng: random.Random, width: int) -> int:
    mant, bias = (23, 127) if width == 32 else (52, 1023)
    kind = rng.random()
    if kind < 0.05:
        return rng.choice([0, 1 << (width - 1)])
    if kind < 0.10:
        return rng.getrandbits(mant) | (rng.getrandbits(1) << (width - 1))   # subnormal
    exponent = rng.randrange(bias - 27, bias + 28)
    return (rng.getrandbits(1) << (width - 1)) | (exponent << mant) | rng.getrandbits(mant)


def predicate(rng: random.Random, width: int) -> bytearray:
    """A byte-lane predicate register, each byte 0 or 1, half density."""
    return bytearray(rng.random() < 0.5 for _ in range(ROW_BYTES))


def trial(rng: random.Random, mnemonic: str, cancel: bool = False) -> dict:
    width = INSTRUCTIONS[mnemonic]
    side = SVL // width
    floating = mnemonic.startswith("FMOP")
    t = {"mnemonic": mnemonic, "width": width, "tile": rng.randrange(width // 8),
         "za": [bytearray(rng.randbytes(ROW_BYTES)) for _ in range(ZA_ROWS)],
         "z": [bytearray(rng.randbytes(ROW_BYTES)) for _ in range(32)],
         "p": [bytearray(b & 1 for b in rng.randbytes(ROW_BYTES)) for _ in range(8)]}
    zn_r, zm_r = rng.sample(range(32), 2)
    pn_r, pm_r = rng.sample(range(8), 2)
    t.update(zn_r=zn_r, zm_r=zm_r, pn_r=pn_r, pm_r=pm_r)
    # General registers, for a slice index: small values and ones that wrap.
    t["x"] = [rng.choice([rng.randrange(16), rng.getrandbits(64)]) for _ in range(32)]
    t["ws_r"], t["imm"] = rng.randrange(12, 16), rng.randrange(4)   # Arm: W12-W15
    t["pg"] = t["pn"] = t["p"][pn_r]
    # A base and an index, clear of the slice register, and 16 words of memory
    # at base + (index << 2) -- the words a slice touches.
    others = [r for r in range(31) if r != t["ws_r"]]
    t["xn_r"], xm = rng.sample(others, 2)
    t["xm_r"] = rng.choice([xm, 31])                     # 31 is XZR
    base = 0x40000 + (rng.randrange(0, 0x600) & ~3)
    index = rng.randrange(0, 64) if t["xm_r"] != 31 else 0
    t["x"][t["xn_r"]] = base
    if t["xm_r"] != 31:
        t["x"][t["xm_r"]] = index
    t["address"] = base + (index << 2)
    t["mem"] = {t["address"] + 4 * e: rng.getrandbits(32) for e in range(16)}
    t["mem_after"] = dict(t["mem"])
    t["zn"], t["zm"] = t["z"][zn_r], t["z"][zm_r]
    t["pn"], t["pm"] = t["p"][pn_r], t["p"][pm_r]
    t["pn"][:] = predicate(rng, width)
    t["pm"][:] = predicate(rng, width)
    if floating:
        for register in (t["zn"], t["zm"]):
            for k in range(side):
                put(register, k, width, random_float(rng, width))
        for i in range(side):
            row = t["za"][tile_row(width, t["tile"], i)]
            for j in range(side):
                c = random_float(rng, width)
                if cancel:
                    a = to_float(get(t["zn"], i, width), width)
                    b = to_float(get(t["zm"], j, width), width)
                    fmt = "<f" if width == 32 else "<d"
                    try:
                        product = struct.unpack(fmt, struct.pack(fmt, a * b))[0]
                        c = to_bits(-product, width) if product else 0
                    except OverflowError:
                        pass
                put(row, j, width, c)
    return t


# Arm's encodings: the fixed bits of each instruction, and which of its
# fields they sit beside. The corpus declares the same layouts.
MOPA_FIXED = {  # mnemonic: (bits 31..21 or 31..25, extra fixed bits)
    "FMOPA_S": (1028 << 21, 0), "FMOPS_S": (1028 << 21, 1 << 4),
    "FMOPA_D": (1030 << 21, 0),
    "SMOPA_S": (80 << 25, (2 << 22)), "UMOPA_S": (80 << 25, (1 << 24) | (2 << 22) | (1 << 21)),
    "SUMOPA_S": (80 << 25, (2 << 22) | (1 << 21)), "USMOPA_S": (80 << 25, (1 << 24) | (2 << 22)),
    "SMOPS_S": (80 << 25, (2 << 22) | (1 << 4)),
}


def word(t: dict) -> int:
    """The A64 word for this trial -- Arm's encoding, which the corpus uses and
    `sme_asl_check.py` holds to what `llvm-mc` assembles."""
    m = t["mnemonic"]
    if m.startswith(("LD1W", "ST1W")):
        v = 1 if m.endswith("V") else 0
        st = 1 if m.startswith("ST1W") else 0
        return ((898 << 22) | (st << 21) | (t["xm_r"] << 16) | (v << 15) | ((t["ws_r"] - 12) << 13)
                | (t["pn_r"] << 10) | (t["xn_r"] << 5) | (t["tile"] << 2) | t["imm"])
    if m.startswith("MOVA"):
        v = 1 if m.endswith("V") else 0
        rs = t["ws_r"] - 12                       # W12-W15 in a two-bit field
        head = (192 << 24) | (2 << 22) | (v << 15) | (rs << 13) | (t["pn_r"] << 10)
        if m.startswith("MOVA_ZT"):
            return head | (t["zn_r"] << 5) | (t["tile"] << 2) | t["imm"]
        return head | (1 << 17) | (t["tile"] << 7) | (t["imm"] << 5) | t["zn_r"]
    top, extra = MOPA_FIXED[m]
    return (top | extra | (t["zm_r"] << 16) | (t["pm_r"] << 13) | (t["pn_r"] << 10)
            | (t["zn_r"] << 5) | t["tile"])


def register_file(t: dict, za: list[bytearray], bases: dict) -> dict:
    """Slot -> 64-bit word, for every Z, P and ZA row."""
    regs: dict = {slot: value for slot, value in enumerate(t["x"])}
    for base, registers in ((bases["vreg"], t["z"]), (bases["preg"], t["p"]), (bases["za"], za)):
        for index, register in enumerate(registers):
            for k in range(REG_SLOTS):
                regs[base + index * REG_SLOTS + k] = int.from_bytes(register[8 * k:8 * k + 8], "little")
    return regs


class Memory:
    """Width-keyed memory, the executors' read/write ABI."""

    def __init__(self, words: dict):
        self.store = {(address, 32): value for address, value in words.items()}

    def read(self, address, width):
        return self.store.get((address, width), 0)

    def write(self, address, value, width):
        self.store[(address, width)] = value & ((1 << width) - 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--python-only", action="store_true",
                        help="skip the compiled executor (for iterating; the ladder runs both)")
    args = parser.parse_args()
    axis_file = args.axis_file.resolve()
    workdir = Path(tempfile.mkdtemp(prefix="axis_sme_"))
    for command, output in (("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py"),
                            ("emit-exec-python", "axis_exec.py")):
        wide.emit(axis_file, command, workdir / output)
    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    lift = importlib.import_module("axis_lift")
    # From the lane operands' own `slot_base`: a scalable register strides by
    # VL/64, not by the class's one slot, and every ZA view shares one base.
    bases = {}
    for entry in lift.AXIS_LIFT_TABLE:
        for operand in entry["operands"]:
            if "slot_base" in operand:
                kind = "za" if operand["kind"].startswith("za_") else operand["kind"]
                bases[kind] = operand["slot_base"]

    rng = random.Random(0x5E2)
    trials = [trial(rng, m) for m in INSTRUCTIONS
              for _ in range(6 if m.startswith(("MOVA", "LD1W", "ST1W")) else 3)]
    trials += [trial(rng, m, cancel=True) for m in ("FMOPA_S", "FMOPA_D") for _ in range(2)]
    failures: list[str] = []
    held = changed = wrapped = zeroed = kept = 0
    fused_differs = {32: False, 64: False}
    shared = False
    cases = []
    for index, t in enumerate(trials):
        width, side = t["width"], SVL // t["width"]
        before = register_file(t, t["za"], bases)
        want_za = reference(t, t["za"])            # a slice read updates t["zn"]
        want = register_file(t, want_za, bases)
        if t["mnemonic"].startswith(("MOVA", "LD1W", "ST1W")) \
                and (t["x"][t["ws_r"]] & 0xFFFF_FFFF) + t["imm"] >= SVL // t["width"]:
            wrapped += 1
        if t["mnemonic"].startswith(("LD1W", "ST1W")):
            inactive = sum(1 for e in range(side) if not get(t["pg"], e, width) & 1)
            if t["mnemonic"].startswith("LD1W"):
                zeroed += inactive
            else:
                kept += inactive
        regs = dict(before)
        memory = Memory(t["mem"])
        axis_exec.step(word(t), regs, memory, 0, isa="sme")
        want_mem = {(address, 32): value for address, value in t["mem_after"].items()}
        if memory.store != want_mem:
            wrong = sorted(k for k in set(memory.store) | set(want_mem)
                           if memory.store.get(k) != want_mem.get(k))
            failures.append(f"python {t['mnemonic']} trial {index}: memory differs at "
                            f"{[hex(a) for a, _ in wrong[:3]]}")
        if regs != want:
            wrong = sorted(k for k in set(regs) | set(want) if regs.get(k, 0) != want.get(k, 0))
            failures.append(f"python {t['mnemonic']} (tile {t['tile']}) trial {index}: "
                            f"{len(wrong)} slot(s) differ, first {wrong[:3]}")
        for i in range(side):
            r = tile_row(width, t["tile"], i)
            for j in range(side):
                same = get(want_za[r], j, width) == get(t["za"][r], j, width)
                held += same
                changed += not same
                if t["mnemonic"].startswith("FMOPA") and get(t["pn"], i, width) & 1 \
                        and get(t["pm"], j, width) & 1:
                    loose = unfused(get(t["zn"], i, width), get(t["zm"], j, width),
                                    get(t["za"][r], j, width), width)
                    if loose is not None and loose != get(want_za[r], j, width):
                        fused_differs[width] = True
            # A .D tile's row is a row some .S tile names too (every row is).
            if width == 64 and want_za[r] != t["za"][r]:
                shared = True
        file = [0] * lift.REGISTER_FILE_SLOTS
        for slot, value in before.items():
            file[slot] = value
        cases.append({
            "mnemonic": f"{t['mnemonic']}_{index}", "word": word(t), "isa": "sme", "pc": 0,
            "regs": file, "seed": [(a, 32, v) for a, v in t["mem"].items()], "state": [],
            "reg_checks": sorted(want.items()),
            "mem_checks": [(a, 32, v) for a, v in t["mem_after"].items()], "state_write": None,
            "next_pc": 4, "trap": None, "slots": lift.REGISTER_FILE_SLOTS,
        })
    for width, seen in fused_differs.items():
        if not seen:
            failures.append(f"no input separated a fused FMOPA from an unfused one at f{width}")
    if not (zeroed and kept):
        failures.append(f"LD1W zeroed {zeroed} inactive element(s) and ST1W left {kept} "
                        "unwritten; both of Arm's inactive-element rules must be exercised")
    if not wrapped:
        failures.append("no slice index wrapped past the tile: the modulo was never exercised")
    if not shared:
        failures.append("no .D trial changed a ZA row: the shared storage was never exercised")
    if not (held and changed):
        failures.append(f"predicates held {held} and changed {changed} elements; both must happen")
    # Both compiled executors. The wide Rust one ran no scalable instruction
    # until it gained lane views and the lane loop its C twin had; it runs
    # these now, and is held to the same reference.
    for lang in () if args.python_only else ("c", "rust"):
        target = workdir / lang
        target.mkdir()
        if lang == "c":
            for command, output in (("emit-exec-c", "axis_exec.h"), ("emit-lift-c", "axis_lift.h"),
                                    ("emit-semantics-c", "axis_semantics.h")):
                wide.emit(axis_file, command, target / output)
        result = wide.build_and_run(cases, target, axis_file, lang)
        lines = result.stdout.strip().splitlines()
        summary = lines[-1] if lines else result.stderr.strip()[-300:]
        if result.returncode != 0 or " 0 failures" not in summary or " 0 declined" not in summary:
            failures.append(f"wide {lang}: {summary}")
            failures.extend(f"  {line}" for line in lines[:4] if line.startswith(("FAIL", "DECLINE")))

    print(f"{len(trials)} trials on the Python executor"
          f"{'' if args.python_only else ' and the wide C and Rust executors'}; "
          f"{held} tile elements held and {changed} changed by their predicates")
    for failure in failures[:12]:
        print(f"  {failure}")
    ok = not failures
    print("SME outer products agree: PASS" if ok else "SME outer products agree: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
