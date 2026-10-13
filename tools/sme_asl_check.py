#!/usr/bin/env python3
"""AXIS's SME executes as Arm's specification does. Gate.

`tools/sme_check.py` holds `examples/sme.axisl` to a reference written from
Arm's DESCRIPTION of each instruction. This holds it to Arm's DEFINITION: the
Sail translation of the ASL for Armv9.4-A (`rems-project/sail-arm`), the
emulator `tools/asl_model_build.sh` builds and `tools/asl_check.py` already
runs AArch64 words on. Armv9.4 includes SME; the model implements it
(`has_sme`, `has_sme_f64f64`) at SVLs of 128, 256 and 512 bits.

How one SME word runs in a model built to boot ELF images: a template enables
SME at EL3 (CPTR_EL3.ESM, SMCR_EL3.LEN = 3, so SVL = 512), enters streaming
mode with ZA on (SMSTART), loads every X, Z, P and all 64 ZA rows from a state
block, executes the word, stores all of it back and streams it out through
the UART. The layout is the corpus's: a ZA row is 64 bytes, a Z register 64,
a P register 8 -- one bit per byte of Z, which AXIS models as one byte lane
per bit.

The corpus uses Arm's encodings, so each trial is one word: the gate builds it
from Arm's layouts, requires it to be exactly what `llvm-mc` assembles from the
same instruction's A64 syntax, and runs it on both machines from the same
state. Every X, Z, P0-P7 and ZA row must come back identical. The trials are `sme_check.py`'s (MOVA's slice register in W12-W15, as Arm's
two-bit field names it), and each is also compared with that gate's
reference, so a disagreement says which of the three is wrong.

FPCR.DN = 1, as `asl_check.py` runs: the corpus describes default-NaN mode.
Special values -- infinities, both kinds of NaN, signed zeros, subnormals, the
largest finite value -- go through FMOPA, FMOPS and FMOPA.D and are held AXIS
against Arm alone, since the reference computes with exact rationals. And the
model must have changed ZA or Z in every trial that must change something, so
agreement is not two machines doing nothing.

Injection-checked on the model: FMOPS without its negation (8 words),
SMOPA's bytes governed by one predicate bit (20), a horizontal slice read
vertically (4) and FMOPA unfused (7) each disagree with Arm -- and in every
one the gate's own reference sides with Arm, which is what says the
reference is a correct reading and not merely a second copy of AXIS. And for
the encodings: a corpus whose .S FMOPA format swaps Pn and Pm disagrees with
Arm on 18 words (AXIS decodes Arm's word differently), and a gate whose FMOPS
word drops the S bit is reported word by word against llvm-mc's.

Declines when the model or `llvm-mc` is absent.

Usage: tools/sme_asl_check.py <examples/sme.axisl> [--jobs N]
"""

from __future__ import annotations

import argparse
import importlib
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
from multiprocessing import Pool
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exec_wide_check as wide   # noqa: E402
import sme_check as sme          # noqa: E402

DEFAULT_MODEL = Path.home() / ".cache" / "axis" / "asl" / "armv9"
STATE_IN, STATE_OUT, UART = 0x10000, 0x20000, 0x3c00 << 16
Z_AT, P_AT, ZA_AT, FLAGS_AT = 0x100, 0x900, 0x980, 0x1980
SIZE = 0x1990
# The memory a slice load or store touches: sme_check's trials put their
# 16 words at 0x40000 + up to 0x740, inside this window, which the model
# loads with the state and streams back out after it.
MEM_AT, MEM_SIZE = 0x40000, 0x800
MARK = 0xdeadbeef
DN = 1 << 25
M64 = (1 << 64) - 1

#: A64 syntax for each corpus mnemonic, from a trial.
def a64(t: dict) -> str:
    m, n = t["mnemonic"], t["tile"]
    pn, pm, zn, zm = t["pn_r"], t["pm_r"], t["zn_r"], t["zm_r"]
    if m.startswith(("LD1W", "ST1W")):
        slice_ = f"za{n}{'h' if m.endswith('H') else 'v'}.s[w{t['ws_r']}, {t['imm']}]"
        xm = "xzr" if t["xm_r"] == 31 else f"x{t['xm_r']}"
        pred = f"p{pn}/z" if m.startswith("LD1W") else f"p{pn}"
        return f"{m[:4].lower()} {{{slice_}}}, {pred}, [x{t['xn_r']}, {xm}, lsl #2]"
    if m.startswith("MOVA"):
        ws, imm = t["ws_r"], t["imm"]
        slice_ = f"za{n}{'h' if m.endswith('H') else 'v'}.s[w{ws}, {imm}]"
        if m.startswith("MOVA_ZT"):
            return f"mova {slice_}, p{pn}/m, z{zn}.s"
        return f"mova z{zn}.s, p{pn}/m, {slice_}"
    op = {"FMOPA_S": "fmopa", "FMOPS_S": "fmops", "SMOPA_S": "smopa", "UMOPA_S": "umopa",
          "SUMOPA_S": "sumopa", "USMOPA_S": "usmopa", "SMOPS_S": "smops",
          "FMOPA_D": "fmopa"}[m]
    size = {"FMOPA_D": "d", "FMOPA_S": "s", "FMOPS_S": "s"}.get(m, "b")
    tile = "d" if m == "FMOPA_D" else "s"
    return f"{op} za{n}.{tile}, p{pn}/m, p{pm}/m, z{zn}.{size}, z{zm}.{size}"


def template() -> list[str]:
    L = [f"movz x30, #{STATE_IN >> 16}, lsl #16",
         # SME at EL3: no trap (ESM, and EZ for streaming SVE), SVL = 512.
         "mrs x0, cptr_el3", "orr x0, x0, #0x1000", "orr x0, x0, #0x100",
         "msr cptr_el3, x0", "isb", "movz x0, #3", "msr smcr_el3, x0", "isb", "smstart",
         f"add x9, x30, #{Z_AT}"]
    L += [f"ldr z{i}, [x9, #{i}, mul vl]" for i in range(32)]
    L += [f"add x10, x30, #{P_AT}"] + [f"ldr p{i}, [x10, #{i}, mul vl]" for i in range(16)]
    L += [f"add x8, x30, #{ZA_AT}", "mov w12, #0",
          "1: ldr za[w12, 0], [x8]", "add x8, x8, #64", "add w12, w12, #1", "cmp w12, #64",
          "b.ne 1b"]
    L += ["add x11, x30, #0x1000", f"ldr x0, [x11, #{FLAGS_AT - 0x1000}]", "msr nzcv, x0",
          f"ldr x0, [x11, #{FLAGS_AT - 0x1000 + 8}]", "msr fpcr, x0"]
    L += [f"ldp x{i}, x{i + 1}, [x30, #{8 * i}]" for i in range(0, 30, 2)]
    L += ["ldr x30, [x30, #240]", f".inst {MARK:#010x}",
          "msr tpidr_el3, x0", f"movz x0, #{STATE_OUT >> 16}, lsl #16"]
    L += [f"stp x{i}, x{i + 1}, [x0, #{8 * i}]" for i in range(1, 29, 2)]
    L += ["stp x29, x30, [x0, #232]", "mrs x1, tpidr_el3", "str x1, [x0]"]
    L += [f"add x9, x0, #{Z_AT}"] + [f"str z{i}, [x9, #{i}, mul vl]" for i in range(32)]
    L += [f"add x10, x0, #{P_AT}"] + [f"str p{i}, [x10, #{i}, mul vl]" for i in range(16)]
    L += [f"add x8, x0, #{ZA_AT}", "mov w12, #0",
          "2: str za[w12, 0], [x8]", "add x8, x8, #64", "add w12, w12, #1", "cmp w12, #64",
          "b.ne 2b"]
    L += ["add x11, x0, #0x1000", "mrs x1, nzcv", f"str x1, [x11, #{FLAGS_AT - 0x1000}]",
          f"movz x1, #{SIZE}", f"movz x2, #{UART >> 16}, lsl #16",
          "3: ldrb w3, [x0], #1", "strb w3, [x2]", "subs x1, x1, #1", "b.ne 3b",
          # Then the memory window, byte by byte, after the state block.
          f"movz x0, #{MEM_AT >> 16}, lsl #16", f"movz x1, #{MEM_SIZE}",
          "5: ldrb w3, [x0], #1", "strb w3, [x2]", "subs x1, x1, #1", "b.ne 5b", "4: b 4b"]
    return L


def find_mc() -> str | None:
    found = shutil.which("llvm-mc")
    if found:
        return found
    for prefix in (Path("/opt/homebrew/opt/llvm"), Path("/usr/local/opt/llvm")):
        if (prefix / "bin" / "llvm-mc").exists():
            return str(prefix / "bin" / "llvm-mc")
    return None


def assemble(mc: str, lines: list[str], work: Path) -> bytes:
    src, obj, binf = work / "t.s", work / "t.o", work / "t.bin"
    src.write_text(".text\n" + "\n".join(lines) + "\n")
    subprocess.run([mc, "-triple=aarch64", "-mattr=+v9.4a,+sme,+sme-f64f64", "-filetype=obj",
                    "-o", str(obj), str(src)], check=True, capture_output=True)
    subprocess.run([str(Path(mc).with_name("llvm-objcopy")), "-O", "binary",
                    "--only-section=.text", str(obj), str(binf)], check=True, capture_output=True)
    return binf.read_bytes()


def arm_words(mc: str, trials: list[dict], work: Path) -> list[int]:
    blob = assemble(mc, [a64(t) for t in trials], work)
    return [struct.unpack_from("<I", blob, 4 * i)[0] for i in range(len(trials))]


def pack(t: dict) -> bytearray:
    state = bytearray(SIZE)
    for r in range(31):
        struct.pack_into("<Q", state, 8 * r, t["x"][r] & M64)
    for r, z in enumerate(t["z"]):
        state[Z_AT + 64 * r:Z_AT + 64 * (r + 1)] = z
    for r, p in enumerate(t["p"]):                      # byte lanes -> one bit per byte
        struct.pack_into("<Q", state, P_AT + 8 * r, sum((p[b] & 1) << b for b in range(64)))
    for r, row in enumerate(t["za"]):
        state[ZA_AT + 64 * r:ZA_AT + 64 * (r + 1)] = row
    struct.pack_into("<QQ", state, FLAGS_AT, 0, DN)
    return state


def memory_image(words: dict) -> bytes:
    image = bytearray(MEM_SIZE)
    for address, value in words.items():
        struct.pack_into("<I", image, address - MEM_AT, value & 0xFFFF_FFFF)
    return bytes(image)


def unpack(out: bytes) -> dict:
    return {
        "mem": bytes(out[SIZE:SIZE + MEM_SIZE]),
        "x": [struct.unpack_from("<Q", out, 8 * r)[0] for r in range(31)],
        "z": [bytes(out[Z_AT + 64 * r:Z_AT + 64 * (r + 1)]) for r in range(32)],
        "p": [bytes((struct.unpack_from("<Q", out, P_AT + 8 * r)[0] >> b) & 1 for b in range(64))
              for r in range(8)],
        "za": [bytes(out[ZA_AT + 64 * r:ZA_AT + 64 * (r + 1)]) for r in range(64)],
    }


_W: dict = {}


def _init(model: str, image: bytes, at: int) -> None:
    _W.update(model=model, image=image, at=at, work=Path(tempfile.mkdtemp(prefix="sme_asl_")))


def run_model(args: tuple) -> dict | None:
    word, state, memory = args
    image = bytearray(_W["image"])
    struct.pack_into("<I", image, _W["at"], word)
    code, blob, mem = _W["work"] / "c.bin", _W["work"] / "s.bin", _W["work"] / "m.bin"
    code.write_bytes(image)
    blob.write_bytes(state)
    mem.write_bytes(memory)
    out = subprocess.run([_W["model"], "-C", "SMCR_EL3.LEN=3",
                          "-b", f"0x0,{code}", "-b", f"{STATE_IN:#x},{blob}",
                          "-b", f"{MEM_AT:#x},{mem}",
                          "-n", "0x0", "-l", "300000"], capture_output=True).stdout
    return unpack(out[:SIZE + MEM_SIZE]) if len(out) >= SIZE + MEM_SIZE else None


def axis_state(regs: dict, bases: dict) -> dict:
    def register(base: int, index: int) -> bytes:
        return b"".join((regs.get(base + 8 * index + k, 0) & M64).to_bytes(8, "little")
                        for k in range(8))
    return {"x": [regs.get(r, 0) & M64 for r in range(31)],
            "z": [register(bases["vreg"], r) for r in range(32)],
            "p": [register(bases["preg"], r) for r in range(8)],
            "za": [register(bases["za"], r) for r in range(64)]}


def differences(a: dict, b: dict) -> list[str]:
    out = []
    for key, count in (("x", 31), ("z", 32), ("p", 8), ("za", 64)):
        for r in range(count):
            if a[key][r] != b[key][r]:
                out.append(f"{key}{r}")
    if a["mem"] != b["mem"]:
        out.append("memory")
    return out


SPECIAL = {32: [0x0, 0x8000_0000, 0x7F80_0000, 0xFF80_0000, 0x7FC0_0001, 0x7F80_0001,
                0x0000_0001, 0x807F_FFFF, 0x7F7F_FFFF, 0x3F80_0000],
           64: [0x0, 1 << 63, 0x7FF0 << 48, 0xFFF0 << 48, (0x7FF8 << 48) | 1, (0x7FF0 << 48) | 1,
                0x1, (1 << 63) | 0xF_FFFF_FFFF_FFFF, 0x7FEF_FFFF_FFFF_FFFF, 0x3FF0 << 48]}


def special(rng: random.Random, t: dict) -> dict:
    """Infinities, NaNs of both kinds, signed zeros, subnormals and the largest
    finite value, in the sources and the tile: where default-NaN mode, IEEE's
    zero signs and overflow decide the answer, and a random float never goes."""
    width = t["width"]
    side = sme.SVL // width
    pick = lambda: rng.choice(SPECIAL[width] + [sme.random_float(rng, width)])
    for register in (t["zn"], t["zm"]):
        for k in range(side):
            sme.put(register, k, width, pick())
    for i in range(side):
        row = t["za"][sme.tile_row(width, t["tile"], i)]
        for j in range(side):
            sme.put(row, j, width, pick())
    t["special"] = True
    return t


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) // 2))
    args = parser.parse_args()
    model = os.environ.get("AXIS_ASL_MODEL", str(DEFAULT_MODEL))
    mc = find_mc()
    if not Path(model).exists():
        print(f"  DECLINED no ASL model at {model} (tools/asl_model_build.sh builds it)")
        print("SME == Arm's specification: SKIP")
        return 0
    if mc is None:
        print("  DECLINED no llvm-mc on this host to assemble the harness")
        print("SME == Arm's specification: SKIP")
        return 0
    axis_file = args.axis_file.resolve()
    work = Path(tempfile.mkdtemp(prefix="axis_sme_asl_"))
    for command, output in (("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py"),
                            ("emit-exec-python", "axis_exec.py")):
        wide.emit(axis_file, command, work / output)
    sys.path.insert(0, str(work))
    axis_exec = importlib.import_module("axis_exec")
    lift = importlib.import_module("axis_lift")
    bases = {}
    for entry in lift.AXIS_LIFT_TABLE:
        for operand in entry["operands"]:
            if "slot_base" in operand:
                kind = "za" if operand["kind"].startswith("za_") else operand["kind"]
                bases[kind] = operand["slot_base"]

    rng = random.Random(0xA5E)
    trials = [sme.trial(rng, m) for m in sme.INSTRUCTIONS for _ in range(4)]
    trials += [sme.trial(rng, m, cancel=True) for m in ("FMOPA_S", "FMOPA_D") for _ in range(2)]
    trials += [special(rng, sme.trial(rng, m)) for m in ("FMOPA_S", "FMOPS_S", "FMOPA_D")
               for _ in range(4)]
    image = assemble(mc, template(), work)
    at = image.index(struct.pack("<I", MARK))
    words = arm_words(mc, trials, work)
    # The corpus now uses Arm's encodings, so AXIS's word for a trial must BE
    # the word Arm's assembler produces -- and the model runs that one word.
    mismatched = [(t, sme.word(t), w) for t, w in zip(trials, words) if sme.word(t) != w]

    with Pool(args.jobs, initializer=_init, initargs=(model, image, at)) as pool:
        results = pool.map(run_model, [(w, pack(t), memory_image(t["mem"]))
                                       for w, t in zip(words, trials)])

    failures, attributed = [], {"axis": 0, "reference": 0}
    for t, ours, arms in mismatched[:6]:
        failures.append(f"`{a64(t)}`: AXIS encodes {ours:#010x}, llvm-mc {arms:#010x}")
    if mismatched:
        failures.append(f"{len(mismatched)} of {len(trials)} words encoded differently from Arm")
    moved = 0
    for index, (t, arm) in enumerate(zip(trials, results)):
        label = f"{t['mnemonic']} `{a64(t)}`"
        if arm is None:
            failures.append(f"{label}: the model produced no state (trapped or hung)")
            continue
        initial = {"z": [bytes(z) for z in t["z"]], "za": [bytes(r) for r in t["za"]],
                   "mem": memory_image(t["mem"])}
        if arm["za"] != initial["za"] or arm["z"] != initial["z"] or arm["mem"] != initial["mem"]:
            moved += 1
        regs = sme.register_file(t, t["za"], bases)
        memory = sme.Memory(t["mem"])
        axis_exec.step(sme.word(t), regs, memory, 0, isa="sme")
        got = axis_state(regs, bases)
        got["mem"] = memory_image({a: v for (a, w), v in memory.store.items() if w == 32})
        if t.get("special"):
            # The reference computes with exact rationals and has no NaN or
            # infinity; these are AXIS against Arm alone.
            off = differences(got, arm)
            if off:
                attributed["axis"] += 1
                failures.append(f"{label} (special values): AXIS differs from Arm at {off[:4]}")
            continue
        want_za = sme.reference(t, [bytearray(r) for r in t["za"]])
        ref = {"x": [v & M64 for v in t["x"][:31]], "z": [bytes(z) for z in t["z"]],
               "p": [bytes(p) for p in t["p"]], "za": [bytes(r) for r in want_za],
               "mem": memory_image(t["mem_after"])}
        axis_off, ref_off = differences(got, arm), differences(ref, arm)
        if axis_off:
            attributed["axis"] += 1
            failures.append(f"{label}: AXIS differs from Arm at {axis_off[:4]}"
                            f"{'' if ref_off else ' (the reference agrees with Arm)'}")
        if ref_off:
            attributed["reference"] += 1

    # ⚠️ Not vacuous: a model that ran the SME word as nothing would agree with
    # nothing AXIS does -- but "the model changed state" is required, not
    # inferred. Only a slice read or a slice store under an all-inactive
    # predicate may leave everything as it was.
    if moved < len(trials) - sum(1 for t in trials if t["mnemonic"].startswith(("MOVA_TZ", "ST1W"))):
        failures.append(f"the model changed ZA or Z in only {moved} of {len(trials)} trials")
    print(f"{len(trials)} SME words on Arm's ASL model at SVL = 512, "
          f"{len(sme.INSTRUCTIONS)} instructions; AXIS disagreed on {attributed['axis']}, "
          f"the gate's own reference on {attributed['reference']}")
    for failure in failures[:14]:
        print(f"  {failure}")
    ok = not failures
    print("SME == Arm's specification: PASS" if ok else "SME == Arm's specification: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
