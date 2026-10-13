#!/usr/bin/env python3
"""A kernel is launched, not transcribed, and a launch is checked. Gate.

`defkernel` names a body, its params and an iteration space; `runs-kernel`
binds an instruction's operands to the params. The launch expands to the
effects the space enumerates, so a kernel adds no semantics -- which is exactly
why every claim below is about what it must NOT get wrong:

  1. **the launch computes the kernel.** Each launching instruction is executed
     through the Python executor over random operands at 64-bit bases, and the
     memory it leaves is compared against a matmul and an elementwise add
     written here, in Python, from the kernel's stated shape -- not from
     anything AXIS emits. The matmul is 2x4 by 4x3, so a transposed index
     writes a different cell rather than the same one;
  2. **a hand-written behavior that names a kernel must BE that kernel.**
     `mmflat` writes the six stores out itself. Moving one column index by one
     element must be refused with the effect it disagrees at, and so must
     dropping a store. A composition check that accepts both is decoration;
  3. **a malformed kernel or launch is refused, by name.** An unknown kernel, a
     wrong param count, a duplicate kernel, an index that shadows a param, a
     zero extent and an empty body -- each generated here and each required to
     fail with its own reason;
  4. **the source survives.** `emit-lisp` keeps both `defkernel`s and all three
     `runs-kernel`s, does NOT write `mm`'s expansion back as a behavior (that
     would turn a launch into six hand-written stores on the next read), is
     stable under a second round trip, and the manifest is identical before and
     after it;
  5. **the manifest publishes the space.** Each kernel's params, space and the
     instructions that launch it are in `emit-json`, which is what a scheduler
     reads without walking a body.

Injection-checked: removing the composition check from `parser.rs` lets both
mutants of 2 through; comparing without constant folding refuses `mmflat`
itself, so the corpus stops validating; dropping `emit_kernel` from the
canonical emitter fails 4; and transposing matmul's output index in a copy of
the corpus (without `mmflat`, which would refuse it first) fails 1 at the first
cell.

Usage: tools/kernel_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
TRIALS = 24
MASK64 = (1 << 64) - 1


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


def axis(*args: str) -> subprocess.CompletedProcess:
    return run([*axis_prefix(), *args])


class Mem:
    """Width-keyed memory, the executor's read/write ABI."""

    def __init__(self, init=None):
        self.store = dict(init or {})

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def word(func3: int, rd: int, rs1: int, rs2: int) -> int:
    return 11 | rd << 7 | func3 << 12 | rs1 << 15 | rs2 << 20


def bases(rng: random.Random) -> tuple[int, int, int]:
    """Three disjoint regions, high enough that a truncated address shows."""
    region = rng.randrange(1 << 40, 1 << 62) & ~0xFFF
    return region, region + 0x1000, region + 0x2000


def reference_matmul(mem: dict, c: int, a: int, b: int) -> dict:
    out = dict(mem)
    for i in range(2):
        for j in range(3):
            total = sum(mem[(a + 16 * i + 4 * k, 32)] * mem[(b + 12 * k + 4 * j, 32)]
                        for k in range(4))
            out[(c + 12 * i + 4 * j, 32)] = total & 0xFFFF_FFFF
    return out


def reference_vadd(mem: dict, c: int, a: int, b: int) -> dict:
    out = dict(mem)
    for i in range(8):
        out[(c + 2 * i, 16)] = (mem[(a + 2 * i, 16)] + mem[(b + 2 * i, 16)]) & 0xFFFF
    return out


def check_execution(axis_exec, rng: random.Random) -> list[str]:
    failures = []
    cases = (("MM", 0, 32, (8, 12), reference_matmul),
             ("MMFLAT", 1, 32, (8, 12), reference_matmul),
             ("VADD", 2, 16, (8, 8), reference_vadd))
    for mnemonic, func3, width, (a_cells, b_cells), reference in cases:
        for _ in range(TRIALS):
            c, a, b = bases(rng)
            init = {}
            for base, cells in ((a, a_cells), (b, b_cells)):
                for n in range(cells):
                    init[(base + n * width // 8, width)] = rng.getrandbits(width)
            regs = {5: c, 6: a, 7: b}
            mem = Mem(init)
            out = axis_exec.step(word(func3, 5, 6, 7), regs, mem, 0)
            if out is None or out.get("trap") is not None:
                failures.append(f"{mnemonic}: did not execute ({out!r})")
                break
            want = reference(init, c, a, b)
            if mem.store != want:
                wrong = sorted(k for k in set(want) | set(mem.store)
                               if want.get(k) != mem.store.get(k))
                failures.append(f"{mnemonic}: memory differs from the reference at "
                                f"{[(hex(k[0]), k[1]) for k in wrong[:3]]}")
                break
    return failures


def refused(source: str, workdir: Path, name: str, *reasons: str) -> str | None:
    """None if `source` is refused with every reason; the complaint otherwise."""
    path = workdir / f"{name}.axisl"
    path.write_text(source)
    result = axis("check", str(path))
    if result.returncode == 0:
        return f"{name}: accepted"
    message = result.stderr + result.stdout
    missing = [r for r in reasons if r not in message]
    if missing:
        return f"{name}: refused, but not for {missing}: {message.strip()[:300]}"
    return None


def mutate(source: str, name: str, old: str, new: str) -> str:
    if source.count(old) < 1:
        raise SystemExit(f"FAIL: mutant `{name}` found nothing to change -- corpus moved?")
    return source.replace(old, new, 1)


def check_refusals(source: str, workdir: Path) -> list[str]:
    # The second store of `mmflat` is C[0][1]; its B column offset is 4.
    column = "(add i64 rs2 (add i64 (mul i64 k 12) 4))"
    second_store = re.search(r"\(store \(add i64 rd 4\)[\s\S]*?i32\)", source)
    if not second_store:
        raise SystemExit("FAIL: corpus has no second mmflat store")
    kernel_head = "(defkernel matmul\n    (params c a b)"
    mutants = [
        ("column-moved", mutate(source, "column-moved", column,
                                "(add i64 rs2 (add i64 (mul i64 k 12) 8))"),
         ("MMFLAT", "disagrees", "effect 1")),
        ("store-dropped", source.replace(second_store.group(0), "", 1),
         ("MMFLAT", "5 effect(s)", "6")),
        ("unknown-kernel", mutate(source, "unknown-kernel", "(runs-kernel vadd8 ",
                                  "(runs-kernel vadd9 "),
         ("vadd9",)),
        ("param-count", mutate(source, "param-count", "(runs-kernel matmul rd rs1 rs2)",
                               "(runs-kernel matmul rd rs1)"),
         ("matmul", "3")),
        ("duplicate-kernel", mutate(source, "duplicate-kernel", "(defkernel vadd8",
                                    "(defkernel matmul"),
         ("matmul", "duplicate")),
        ("index-shadows-param", mutate(source, "index-shadows-param",
                                       "(space (i 8))", "(space (a 8))"),
         ("vadd8", "`a`")),
        ("zero-extent", mutate(source, "zero-extent", "(space (i 8))", "(space (i 0))"),
         ("vadd8", "extent")),
        ("empty-body", re.sub(r"\(defkernel vadd8[\s\S]*?\(description",
                              "(defkernel vadd8\n    (params c a b)\n    (space (i 8))\n"
                              "    (description", source, count=1),
         ("vadd8", "no statements")),
    ]
    if kernel_head not in source:
        raise SystemExit("FAIL: corpus no longer declares matmul's params")
    return [complaint for name, text, reasons in mutants
            if (complaint := refused(text, workdir, name, *reasons))]


def check_round_trip(axis_file: Path, workdir: Path) -> list[str]:
    failures = []
    once, twice = workdir / "once.axisl", workdir / "twice.axisl"
    for src, dst in ((axis_file, once), (once, twice)):
        result = axis("emit-lisp", str(src), "-o", str(dst))
        if result.returncode != 0:
            return [f"emit-lisp {src.name}: {result.stderr.strip()}"]
    text = once.read_text()
    if text.count("(defkernel ") != 2:
        failures.append(f"round trip kept {text.count('(defkernel ')} of 2 defkernels")
    if text.count("(runs-kernel ") != 3:
        failures.append(f"round trip kept {text.count('(runs-kernel ')} of 3 launches")
    mm = re.search(r"\(definstruction mm\n[\s\S]*?\(rationale", text)
    if not mm or "(behavior" in mm.group(0):
        failures.append("round trip wrote mm's kernel expansion back as a behavior")
    if twice.read_text() != text:
        failures.append("emit-lisp is not stable under a second round trip")
    manifests = []
    for path in (axis_file, once):
        result = axis("emit-json", str(path))
        manifests.append(result.stdout)
    if manifests[0] != manifests[1]:
        failures.append("the manifest differs after a round trip")
    return failures


def check_manifest(axis_file: Path) -> list[str]:
    result = axis("emit-json", str(axis_file))
    manifest = json.loads(result.stdout)
    kernels = {k["name"]: k for k in manifest.get("kernels", [])}
    want = {
        "matmul": (["c", "a", "b"], [("i", 2), ("j", 3)], ["mm", "mmflat"]),
        "vadd8": (["c", "a", "b"], [("i", 8)], ["vadd"]),
    }
    failures = []
    for name, (params, space, launchers) in want.items():
        kernel = kernels.get(name)
        if kernel is None:
            failures.append(f"manifest does not publish kernel {name}")
            continue
        got = (kernel["params"], [(s["index"], s["extent"]) for s in kernel["space"]],
               kernel["launched_by"])
        if got != (params, space, launchers):
            failures.append(f"manifest kernel {name}: {got} != {(params, space, launchers)}")
    launches = {i["name"]: i.get("runs_kernel") for i in manifest["instructions"]}
    if launches.get("vadd") != {"name": "vadd8", "arguments": ["rd", "rs1", "rs2"]}:
        failures.append(f"manifest launch of vadd: {launches.get('vadd')}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()
    axis_file = args.axis_file.resolve()

    workdir = Path(tempfile.mkdtemp(prefix="axis_kernel_"))
    for command, output in (("emit-exec-python", "axis_exec.py"),
                            ("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py")):
        result = axis(command, str(axis_file), "-o", str(workdir / output))
        if result.returncode != 0:
            print(f"FAIL: {command}: {result.stderr.strip()}")
            return 1
    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")

    source = axis_file.read_text()
    sections = (
        ("launches compute their kernels", check_execution(axis_exec, random.Random(0x7E45))),
        ("a disagreeing launch is refused", check_refusals(source, workdir)),
        ("the source survives a round trip", check_round_trip(axis_file, workdir)),
        ("the manifest publishes the space", check_manifest(axis_file)),
    )
    ok = True
    for title, failures in sections:
        print(f"{'ok  ' if not failures else 'FAIL'} {title}")
        for failure in failures:
            print(f"     {failure}")
        ok &= not failures
    print("kernel launches agree: PASS" if ok else "kernel launches agree: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
