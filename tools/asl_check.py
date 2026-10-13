#!/usr/bin/env python3
"""AXIS executes each AArch64 word as Arm's specification does. Gate.

Every other AArch64 check in this ladder compares AXIS against AXIS -- the
golden model, the C, Rust and LLVM backends, the solver -- plus the assembler
for encodings and, now and then, the silicon on whichever machine ran it. None
of those is the architecture. A description that reads Arm's pseudocode wrongly
is agreed with by every backend, because they all read the description.

This measures against the architecture's own EXECUTABLE definition: the Sail
translation of Arm's ASL for Armv9.4-A (`rems-project/sail-arm`), built as a C
emulator by `tools/asl_model_build.sh`. For each `aarch64_base` instruction it
takes AXIS's encoded word, seeds BOTH machines with the same full register file
-- all 31 X registers, all 32 V registers, NZCV and FPCR -- runs that one word,
and requires every register to come back identical.

How one word is run in a model built to boot ELF images: a template program
loads the state block, executes the word, stores every register, and streams
the stored block out through the model's UART, whose data register is a byte
store to physical 0x3c000000. The template is assembled once; each case
patches the word into it.

Three seeds per instruction: two random register files and one built of NaNs
with distinct payloads, both signs, both kinds. The NaN seed exists because a
random 128-bit register almost never holds a NaN in a lane, and the first run
of this check found 33 floating-point instructions that disagreed on exactly
that and had agreed on everything else.

⚠️ FPCR.DN = 1. This corpus describes AArch64 in default-NaN mode -- AXIS's
float operators answer THE default NaN for every ISA -- so the model runs in
the mode the corpus claims. Arm's reset value is DN = 0; the corpus says so
where the floating-point half of 3SAME begins. Run with `--fpcr 0` to see the
distance to propagation mode.

What is not run, each counted by name: instructions that touch memory, change
the PC, name SP, read or write system registers, FPSR or FPCR, or have no
semantics. Those need a different harness, not a looser comparison.

Declines when the model or `llvm-mc` is absent.

Usage: tools/asl_check.py [corpus.axisl] [--fpcr 0x2000000] [--jobs N]
"""
from __future__ import annotations

import argparse
import atexit
import collections
import importlib
import json
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
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
from reference_isa_check import find_llvm_mc  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MODEL = Path.home() / ".cache" / "axis" / "asl" / "armv9"
M64 = (1 << 64) - 1
DN = 1 << 25

# State block: X0..X30, V0..V31 at +0x100, NZCV at +0x300, FPCR at +0x308.
SIZE = 0x310
STATE_IN, STATE_OUT, UART = 0x10000, 0x20000, 0x3c00 << 16
MARK = 0xdeadbeef

#: Effect kinds and state names a register-to-register harness cannot run.
SKIP_KINDS = ("load", "store", "atomic", "setpc", "trap", "barrier", "send", "fence")
SKIP_STATE = ("sp", "tpidr", "exclusive", "fpsr", "fpcr")

#: Words the MODEL cannot run, as (mask, value, why). Each is a defect in the
#: pinned snapshot, not in the architecture, and each names what measures the
#: word instead -- an entry here is a hole in this gate, so it stays narrow:
#: one encoding pattern, never a mnemonic.
MODEL_DEFECTS = (
    # `addv b, v.16b` and `addv b, v.8b` -- byte lanes, either Q: Sail's
    # `Reduce` asserts on its operand widths (v8_base.sail:30795); `.4h`,
    # `.8h` and `.4s` run, and SMAXV and the rest do not go through `Reduce`.
    # Checked on silicon when each landed (vaddvq_u8 and vaddv_u8, 200
    # vectors each, the latter with junk in the upper half it must ignore).
    (0xbffffc00, 0x0e31b800, "the model asserts in Reduce (ADDV byte lanes)"),
)


def template_lines() -> list[str]:
    lines = [f"movz x30, #{STATE_IN >> 16}, lsl #16"]
    lines += [f"ldp q{i}, q{i + 1}, [x30, #{0x100 + 16 * i}]" for i in range(0, 32, 2)]
    lines += ["ldr x0, [x30, #0x300]", "msr nzcv, x0",
              "ldr x0, [x30, #0x308]", "msr fpcr, x0"]
    lines += [f"ldp x{i}, x{i + 1}, [x30, #{8 * i}]" for i in range(0, 30, 2)]
    lines += ["ldr x30, [x30, #240]", f".inst {MARK:#010x}",
              "msr tpidr_el3, x0", f"movz x0, #{STATE_OUT >> 16}, lsl #16"]
    lines += [f"stp x{i}, x{i + 1}, [x0, #{8 * i}]" for i in range(1, 29, 2)]
    lines += ["stp x29, x30, [x0, #232]", "mrs x1, tpidr_el3", "str x1, [x0]"]
    lines += [f"stp q{i}, q{i + 1}, [x0, #{0x100 + 16 * i}]" for i in range(0, 32, 2)]
    lines += ["mrs x1, nzcv", "str x1, [x0, #0x300]",
              f"movz x1, #{SIZE}", f"movz x2, #{UART >> 16}, lsl #16",
              "1: ldrb w3, [x0], #1", "strb w3, [x2]", "subs x1, x1, #1",
              "b.ne 1b", "2: b 2b"]
    return lines


def assemble_template(mc: str, work: Path) -> tuple[bytes, int]:
    src, obj = work / "t.s", work / "t.o"
    src.write_text(".text\n" + "\n".join(template_lines()) + "\n")
    subprocess.run([mc, "-triple=aarch64", "-mattr=+v9.4a", "-filetype=obj",
                    "-o", str(obj), str(src)], check=True, capture_output=True)
    objcopy = Path(mc).with_name("llvm-objcopy")
    binf = work / "t.bin"
    subprocess.run([str(objcopy), "-O", "binary", "--only-section=.text",
                    str(obj), str(binf)], check=True, capture_output=True)
    image = binf.read_bytes()
    return image, image.index(struct.pack("<I", MARK))


# ---- per-process state for the worker pool (spawn-safe) -------------------
_W: dict = {}


def _init(model: str, image: bytes, at: int, gen: str) -> None:
    sys.path.insert(0, gen)
    _W.update(model=model, image=image, at=at,
              lift=importlib.import_module("axis_lift"),
              exe=importlib.import_module("axis_exec"),
              work=Path(tempfile.mkdtemp(prefix="asl_", dir=gen)))


def run_model(word: int, x: dict, v: dict, nzcv: int, fpcr: int) -> dict | None:
    image = bytearray(_W["image"])
    struct.pack_into("<I", image, _W["at"], word)
    state = bytearray(SIZE)
    for r, val in x.items():
        struct.pack_into("<Q", state, 8 * r, val & M64)
    for r, val in v.items():
        struct.pack_into("<QQ", state, 0x100 + 16 * r, val & M64, (val >> 64) & M64)
    struct.pack_into("<QQ", state, 0x300, nzcv << 28, fpcr)
    code, blob = _W["work"] / "c.bin", _W["work"] / "s.bin"
    code.write_bytes(image)
    blob.write_bytes(state)
    out = subprocess.run([_W["model"], "-b", f"0x0,{code}", "-b", f"{STATE_IN:#x},{blob}",
                          "-n", "0x0", "-l", "6000"], capture_output=True).stdout
    if len(out) < SIZE:
        return None
    out = out[:SIZE]
    return {"x": [struct.unpack_from("<Q", out, 8 * r)[0] for r in range(31)],
            "v": [struct.unpack_from("<Q", out, 0x100 + 16 * r)[0]
                  | (struct.unpack_from("<Q", out, 0x108 + 16 * r)[0] << 64)
                  for r in range(32)],
            "nzcv": struct.unpack_from("<Q", out, 0x300)[0] >> 28}


def seeds(word: int) -> list[tuple[str, dict, dict, int]]:
    rng = random.Random(word)
    out = []
    for n in range(2):
        out.append((f"random#{n}", {i: rng.getrandbits(64) for i in range(31)},
                    {i: rng.getrandbits(128) for i in range(32)}, rng.getrandbits(4)))
    # NaNs in every lane shape: f32 quiet/signalling both signs, then f64.
    f32 = [0x7fc12345, 0xff812345, 0x3f800000, 0xffc00001]
    f64 = [0x7ff8000000012345, 0xfff0000000012345]
    lanes32 = sum(v << (32 * i) for i, v in enumerate(f32))
    lanes64 = f64[0] | (f64[1] << 64)
    out.append(("nan", {i: f64[i % 2] for i in range(31)},
                {i: (lanes32 if i % 2 else lanes64) for i in range(32)}, 0b0110))
    return out


def case(args: tuple) -> tuple[str, str, str]:
    """One word over every seed; a failure names the word, since a variant's
    is not the fixture's and nothing else would say which value failed."""
    mnemonic, verdict, detail = _case(args)
    return (mnemonic, verdict, detail if verdict == "agree" else f"{args[0]:#010x} {detail}")


def _case(args: tuple) -> tuple[str, str, str]:
    word, isa, mnemonic, pc, fpcr = args
    for label, x, v, nzcv in seeds(word):
        regs = dict(x)
        for n, val in v.items():
            regs[32 + 2 * n], regs[33 + 2 * n] = val & M64, val >> 64
        state = {"nzcv": nzcv, "fpcr": fpcr, "fpsr": 0}
        try:
            outcome = _W["exe"].step(word, regs, mem=None, pc=pc, isa=isa, state=state)
        except Exception as error:  # an executor that raises is a failure
            return (mnemonic, "raised", f"{type(error).__name__}: {error}"[:140])
        if outcome is None:
            return (mnemonic, "declined", "the AXIS executor declined the word")
        ref = run_model(word, x, v, nzcv, fpcr)
        if ref is None:
            return (mnemonic, "no-model-output", "the model produced no state")
        for r in range(31):
            if regs.get(r, 0) & M64 != ref["x"][r]:
                return (mnemonic, "DISAGREE", f"{label}: x{r} axis={regs.get(r, 0) & M64:#x} "
                                              f"asl={ref['x'][r]:#x}")
        for n in range(32):
            mine = (regs.get(32 + 2 * n, 0) & M64) | ((regs.get(33 + 2 * n, 0) & M64) << 64)
            if mine != ref["v"][n]:
                return (mnemonic, "DISAGREE", f"{label}: v{n} axis={mine:#034x} "
                                              f"asl={ref['v'][n]:#034x}")
        if state.get("nzcv", 0) & 15 != ref["nzcv"]:
            return (mnemonic, "DISAGREE", f"{label}: nzcv axis={state.get('nzcv', 0) & 15:04b} "
                                          f"asl={ref['nzcv']:04b}")
    return (mnemonic, "agree", "")


#: Immediates narrower than this are driven over every value they can take.
DRIVE_BITS = 4


def sampled(width: int) -> list[int]:
    """The values a wider immediate is driven over: every boundary it has.

    A field such as shift-by-immediate's `immh:immb` means an element size by
    its leading one and a shift by its distance from it, so the values that
    matter are each power of two and its neighbours -- the first and last of
    every size, and a shift of one either way -- plus a stride through the
    middle. Every value of a seven-bit field would triple the gate's time and
    add nothing those do not.
    """
    top = (1 << width) - 1
    values = {0, 1, top, top - 1}
    for bit in range(width):
        values |= {(1 << bit) - 1, 1 << bit, (1 << bit) + 1, (3 << bit) >> 1}
    values |= set(range(0, top + 1, max(1, (top + 1) // 16)))
    return sorted(v for v in values if 0 <= v <= top)


def variants(word: int, entry: dict, isa) -> list[int]:
    """The fixture's word, plus one word per other value of each immediate --
    every value of a small one, the boundaries of a wide one (`sampled`).

    ⚠️ The roundtrip fixtures carry ONE value per operand. An instruction whose
    `size` selects between four arrangements was therefore measured in one of
    them, and a wrong byte arm passed this gate untouched -- the same blind
    spot `reference_isa_check` has, one level up. Each variant is re-decoded
    by AXIS itself and kept only if it is still the same instruction, which is
    how every `requires` rule is honoured without restating any of them.
    """
    out = [word]
    for operand in entry["operands"]:
        if operand["kind"] != "imm" or not operand.get("fields"):
            continue
        width = sum(f[2] for f in operand["fields"])
        values = range(1 << width) if width <= DRIVE_BITS else sampled(width)
        cleared = word
        for ibit, _obit, fwidth in operand["fields"]:
            cleared &= ~(((1 << fwidth) - 1) << ibit)
        for value in values:
            candidate = cleared
            for ibit, obit, fwidth in operand["fields"]:
                candidate |= ((value >> obit) & ((1 << fwidth) - 1)) << ibit
            again = _W["lift"].decode(candidate, isa)
            if candidate not in out and again is not None \
                    and again["mnemonic"] == entry["mnemonic"]:
                out.append(candidate)
    return out


def why_not(entry: dict) -> str | None:
    effects = entry.get("effects")
    if entry.get("semantics") is None and effects is None:
        return "no semantics"
    text = json.dumps(effects or [])
    for kind in SKIP_KINDS:
        if f'"kind": "{kind}' in text:
            return f"touches memory or control ({kind})"
    for name in SKIP_STATE:
        if f'"{name}' in text:
            return f"reads or writes {name}"
    if any(op["kind"].endswith("sp") for op in entry["operands"]):
        return "names SP"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path,
                        default=AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl")
    parser.add_argument("--fpcr", type=lambda s: int(s, 0), default=DN)
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4)
    args = parser.parse_args()

    model = Path(os.environ.get("AXIS_ASL_MODEL", DEFAULT_MODEL))
    if not model.is_file():
        print(f"  DECLINED no Armv9.4-A model at {model}; build it with "
              f"tools/asl_model_build.sh (or set AXIS_ASL_MODEL)")
        return DECLINED
    mc = find_llvm_mc()
    if mc is None:
        print("  DECLINED no llvm-mc on this host to assemble the harness")
        return DECLINED

    gen = Path(tempfile.mkdtemp(prefix="asl_gen_"))
    # Each worker's directory is made inside this one, so one removal takes
    # them all: a run leaves nothing behind.
    atexit.register(shutil.rmtree, gen, True)
    for command, name in (("emit-lift-python", "axis_lift.py"),
                          ("emit-exec-python", "axis_exec.py"),
                          ("emit-golden-python", "golden_model.py"),
                          ("emit-roundtrip-json", "rt.json")):
        subprocess.run([*axis_prefix(), command, str(args.axis_file), "-o", str(gen / name)],
                       check=True, capture_output=True, cwd=AXIS_ROOT)
    image, at = assemble_template(mc, gen)
    _init(str(model), image, at, str(gen))

    todo, skipped = [], collections.Counter()
    driven = fixtures = 0
    for test in json.loads((gen / "rt.json").read_text())["tests"]:
        if test.get("isa") != "aarch64_base":
            continue
        word = int(test["encoded"], 16)
        entry = _W["lift"].decode(word, test.get("isa"))
        reason = "does not decode" if entry is None else why_not(entry)
        if reason:
            skipped[reason] += 1
            continue
        words = variants(word, entry, test.get("isa"))
        for mask, value, why in MODEL_DEFECTS:
            skipped[why] += sum((w & mask) == value for w in words)
            words = [w for w in words if (w & mask) != value]
        fixtures += 1
        driven += len(words) > 1
        # The word sits at `at` in the model's image, so that is its PC.
        todo += [(w, test.get("isa"), test["mnemonic"], at, args.fpcr) for w in words]

    # ⚠️ Vacuity: a harness that ran nothing, or a filter that grew until it
    # excluded most of the ISA, would report agreement about nothing -- and a
    # variant generator that silently produced only the fixture word would
    # put the one-value blind spot straight back.
    if driven < 50:
        print(f"  FAIL only {driven} instruction(s) had an immediate driven over "
              f"more than one value; the variants are not being generated")
        return FAILED
    if len(todo) < 250:
        print(f"  FAIL only {len(todo)} instruction(s) were runnable; the filter "
              f"or the corpus has shrunk what this measures")
        return FAILED

    with Pool(args.jobs, initializer=_init, initargs=(str(model), image, at, str(gen))) as pool:
        results = pool.map(case, todo)

    verdicts = collections.Counter(r[1] for r in results)
    for mnemonic, verdict, detail in results:
        if verdict != "agree":
            print(f"  FAIL {mnemonic}: {verdict} {detail}")
    print(f"  {verdicts['agree']} of {len(results)} word(s) agree with the "
          f"Armv9.4-A model: {fixtures} fixtures and {len(results) - fixtures} "
          f"further values of their immediates, over {3 * len(results)} "
          f"register files "
          f"(FPCR={args.fpcr:#x}); not runnable here: "
          + ", ".join(f"{n} {why}" for why, n in skipped.most_common()))
    failed = len(results) - verdicts["agree"]
    verdict = "PASS" if failed == 0 else "FAIL"
    print(f"AXIS executes each AArch64 word as Arm's specification does: {verdict}")
    return PASSED if failed == 0 else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
