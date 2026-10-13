#!/usr/bin/env python3
"""A descriptor, declared: a launch derives its behavior from a layout. Gate.

H1b (docs/accelerator_design.md). `defdescriptor` says where each field of a
launch descriptor is, what an engine checks before it runs and the status each
failure writes; `(launches <descriptor> <base> <kernel> <argument>...)` binds a
kernel's params to fields and DERIVES the instruction's behavior. The claims:

  1. **the derived launch computes the engine.** `BIO_DOUBLE` and `BIO_ADD` run
     on the Python, wide C and wide Rust executors over valid descriptors and
     each way invalid, at bases above 2**32, against references written here
     from Bio's layout -- including the second input riding in `scratch_ptr`;
  2. **declaring is transcribing.** H1a's `BIO_LAUNCH` was written by hand;
     H1b's `BIO_DOUBLE` is derived from a declaration. On the same descriptors
     (no notify flag set) the two leave the same memory. Two descriptions of
     one engine that disagree would mean one of the derivations is wrong;
  3. **a bad declaration or launch is refused, each for its own reason.**
     Overlapping fields, a field past the end, a misaligned field, a field
     named twice, a check reading a name that is not a field, status 0, two
     checks sharing a status, a status too wide for where it is written, a
     status through a name that is not a field; a launch naming no descriptor,
     taking its base from a non-operand, binding a name that is nothing, with
     the wrong count, or stating a behavior as well;
  4. **the source survives.** `emit-lisp` keeps `defdescriptor` and both
     `launches`, writes no expansion back, is stable twice, and the manifest is
     the same before and after;
  5. **the manifest publishes the layout** -- 17 fields at their offsets, the
     three checks with their codes, the status, and both launchers.

Injection-checked: evaluating the checks' select chain in reverse (the last
failing check wins) fails 1 on descriptors with two faults; dropping the
check guard from the kernel's statements fails 1 on every invalid descriptor;
and dropping `emit_descriptor` from the canonical emitter fails 4.

Usage: tools/descriptor_check.py <input.axisl> <h1a-corpus.axisl>
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
import exec_wide_check as wide

AXIS_ROOT = Path(__file__).resolve().parent.parent
MAGIC = 0x42494F31
NAMES = ("magic", "abi_version", "op", "flags", "input_ptr", "input_bytes", "output_ptr",
         "output_bytes", "scratch_ptr", "scratch_bytes", "param0", "param1", "param2",
         "param3", "job_id", "reserved", "status_ptr")
OFFSET = {name: 4 * index for index, name in enumerate(NAMES)}
CAPACITY = 8
KINDS = ("ok", "magic", "version", "count", "magic+count")
MASK32 = 0xFFFF_FFFF


def axis(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([*axis_prefix(), *args], capture_output=True, text=True, cwd=AXIS_ROOT)


def descriptor(rng: random.Random, kind: str) -> tuple[int, dict]:
    base = rng.randrange(1 << 33, 1 << 48) & ~0xFF
    region = rng.randrange(1 << 20, 1 << 30) & ~0xFFF
    fields = {name: rng.getrandbits(32) for name in NAMES}
    fields.update({
        "magic": MAGIC if "magic" not in kind else MAGIC ^ (1 << rng.randrange(32)),
        "abi_version": 1 if kind != "version" else rng.randrange(2, 1 << 16),
        "input_ptr": region, "scratch_ptr": region + 0x100,
        "output_ptr": region + 0x200, "status_ptr": region + 0x300,
        "param0": rng.randrange(0, CAPACITY + 1) if "count" not in kind
        else rng.randrange(CAPACITY + 1, 1 << 16),
    })
    memory = {(base + OFFSET[name], 32): value for name, value in fields.items()}
    for i in range(CAPACITY):
        memory[(region + 4 * i, 32)] = rng.getrandbits(32)
        memory[(region + 0x100 + 4 * i, 32)] = rng.getrandbits(32)
    return base, memory


def reference(memory: dict, base: int, op: str) -> dict:
    """Bio's engine, from queue_abi.py's layout and the checks' order."""
    field = {name: memory.get((base + OFFSET[name], 32), 0) for name in NAMES}
    out = dict(memory)
    if field["magic"] != MAGIC:
        status = 1
    elif field["abi_version"] != 1:
        status = 2
    elif field["param0"] >= 9:
        status = 3
    else:
        status = 0
        for i in range(field["param0"]):
            a = memory.get((field["input_ptr"] + 4 * i, 32), 0)
            if op == "double":
                value = a * 2
            else:
                value = a + memory.get((field["scratch_ptr"] + 4 * i, 32), 0)
            out[(field["output_ptr"] + 4 * i, 32)] = value & MASK32
    out[(field["status_ptr"], 32)] = status
    return out


class Mem:
    def __init__(self, init):
        self.store = dict(init)

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def load_executor(axis_file: Path, workdir: Path, tag: str):
    target = workdir / tag
    target.mkdir()
    for command, output in (("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py"),
                            ("emit-exec-python", "axis_exec.py")):
        wide.emit(axis_file, command, target / output)
    sys.path.insert(0, str(target))
    for module in ("axis_exec", "axis_lift", "golden_model"):
        sys.modules.pop(module, None)
    executor = importlib.import_module("axis_exec")
    sys.path.remove(str(target))
    return executor


def diff(want: dict, got: dict) -> list:
    return sorted(k for k in set(want) | set(got) if want.get(k) != got.get(k))


def check_execution(axis_file: Path, workdir: Path, trials) -> list[str]:
    failures = []
    executor = load_executor(axis_file, workdir, "h1b")
    launches = (("BIO_DOUBLE", 0, "double"), ("BIO_ADD", 1, "add"))
    cases = []
    for mnemonic, func3, op in launches:
        word = 11 | (func3 << 12) | (6 << 15)
        for kind, base, memory in trials:
            want = reference(memory, base, op)
            mem = Mem(memory)
            executor.step(word, {6: base}, mem, 0)
            if mem.store != want:
                failures.append(f"python {mnemonic}, {kind}: memory differs at "
                                f"{[(hex(a), w) for a, w in diff(want, mem.store)[:3]]}")
            regs = [0] * 32
            regs[6] = base
            cases.append({
                "mnemonic": f"{mnemonic}_{kind}", "word": word, "isa": "rvbio", "pc": 0,
                "regs": regs, "seed": [(a, w, v) for (a, w), v in memory.items()],
                "state": [], "reg_checks": [],
                "mem_checks": [(a, w, v) for (a, w), v in want.items() if memory.get((a, w)) != v],
                "state_write": None, "next_pc": 4, "trap": None, "slots": 32,
            })
    for lang in ("c", "rust"):
        target = workdir / lang
        target.mkdir()
        if lang == "c":
            for command, output in (("emit-exec-c", "axis_exec.h"), ("emit-lift-c", "axis_lift.h"),
                                    ("emit-semantics-c", "axis_semantics.h")):
                wide.emit(axis_file, command, target / output)
        result = wide.build_and_run(cases, target, axis_file, lang)
        lines = result.stdout.strip().splitlines()
        summary = lines[-1] if lines else result.stderr.strip()[:300]
        if result.returncode != 0 or " 0 failures" not in summary or " 0 declined" not in summary:
            failures.append(f"wide {lang}: {summary}")
            failures.extend(f"  {line}" for line in lines[:4] if line.startswith(("FAIL", "DECLINE")))
    return failures


def check_agreement(axis_file: Path, h1a_file: Path, workdir: Path, trials) -> list[str]:
    declared = load_executor(axis_file, workdir, "declared")
    written = load_executor(h1a_file, workdir, "written")
    failures = []
    for kind, base, memory in trials:
        # H1a's engine also copies job_id when flags bit 0 is set; this layout
        # keeps flags as a word, and the byte cell H1a reads is left absent.
        left, right = Mem(memory), Mem(memory)
        declared.step(11 | (6 << 15), {6: base}, left, 0)
        written.step(11 | (6 << 15), {6: base}, right, 0)
        if left.store != right.store:
            failures.append(f"{kind}: BIO_DOUBLE (declared) and BIO_LAUNCH (written) differ at "
                            f"{[(hex(a), w) for a, w in diff(left.store, right.store)[:3]]}")
    return failures


def refused(source: str, workdir: Path, name: str, *reasons: str) -> str | None:
    path = workdir / f"{name}.axisl"
    path.write_text(source)
    result = axis("check", str(path))
    if result.returncode == 0:
        return f"{name}: accepted"
    message = result.stderr + result.stdout
    missing = [reason for reason in reasons if reason not in message]
    return f"{name}: refused, but not for {missing}: {message.strip()[:240]}" if missing else None


def mutate(source: str, old: str, new: str) -> str:
    if old not in source:
        raise SystemExit(f"FAIL: mutant anchor `{old}` not found -- corpus moved?")
    return source.replace(old, new, 1)


def check_refusals(source: str, workdir: Path) -> list[str]:
    behavior = ('    (launches bio_v1 rs1 double_words output_ptr input_ptr param0)\n'
                '    (behavior (store rs1 1 i32))')
    mutants = [
        ("overlap", mutate(source, "(op 8 i32)", "(op 6 i16)"), ("overlap",)),
        ("past-end", mutate(source, "(bytes 68)", "(bytes 64)"), ("status_ptr", "past")),
        ("misaligned", mutate(source, "(op 8 i32)", "(op 10 i32)"), ("`op`", "aligned")),
        ("named-twice", mutate(source, "(reserved 60 i32)", "(job_id 60 i32)"), ("`job_id`", "twice")),
        ("check-unknown", mutate(source, "(eq abi_version 1)", "(eq abi_versoin 1)"),
         ("abi_versoin", "not one of its fields")),
        ("status-zero", mutate(source, "(eq abi_version 1) 2)", "(eq abi_version 1) 0)"), ("success",)),
        ("status-shared", mutate(source, "(ult param0 9) 3)", "(ult param0 9) 2)"), ("status 2",)),
        ("status-too-wide", mutate(mutate(source, "(ult param0 9) 3)", "(ult param0 9) 300)"),
                                   "(status status_ptr i32)", "(status status_ptr i8)"),
         ("300", "i8")),
        ("status-unknown", mutate(source, "(status status_ptr i32)", "(status status i32)"),
         ("`status`", "not one of its fields")),
        ("unknown-descriptor", mutate(source, "(launches bio_v1 rs1 add_words",
                                      "(launches bio_v2 rs1 add_words"), ("bio_v2",)),
        ("base-not-operand", mutate(source, "(launches bio_v1 rs1 add_words",
                                    "(launches bio_v1 rs9 add_words"), ("rs9", "input operand")),
        ("argument-unknown", mutate(source, "add_words output_ptr input_ptr scratch_ptr param0",
                                    "add_words output_ptr input_ptr scratch param0"), ("`scratch`",)),
        ("argument-count", mutate(source, "add_words output_ptr input_ptr scratch_ptr param0",
                                  "add_words output_ptr input_ptr param0"), ("add_words", "4")),
        ("launch-and-behavior", mutate(source, behavior.splitlines()[0], behavior),
         ("takes its behavior from the launch",)),
    ]
    return [c for name, text, reasons in mutants if (c := refused(text, workdir, name, *reasons))]


def check_round_trip(axis_file: Path, workdir: Path) -> list[str]:
    once, twice = workdir / "once.axisl", workdir / "twice.axisl"
    for src, dst in ((axis_file, once), (once, twice)):
        result = axis("emit-lisp", str(src), "-o", str(dst))
        if result.returncode != 0:
            return [f"emit-lisp {src.name}: {result.stderr.strip()[:200]}"]
    text = once.read_text()
    failures = []
    if text.count("(defdescriptor ") != 1:
        failures.append(f"round trip kept {text.count('(defdescriptor ')} of 1 defdescriptor")
    if text.count("(launches ") != 2:
        failures.append(f"round trip kept {text.count('(launches ')} of 2 launches")
    if "(behavior" in text:
        failures.append("round trip wrote a launch's derived behavior back")
    if twice.read_text() != text:
        failures.append("emit-lisp is not stable under a second round trip")
    if axis("emit-json", str(axis_file)).stdout != axis("emit-json", str(once)).stdout:
        failures.append("the manifest differs after a round trip")
    return failures


def check_manifest(axis_file: Path) -> list[str]:
    manifest = json.loads(axis("emit-json", str(axis_file)).stdout)
    descriptors = {d["name"]: d for d in manifest.get("descriptors", [])}
    bio = descriptors.get("bio_v1")
    if bio is None:
        return ["manifest does not publish bio_v1"]
    failures = []
    fields = [(f["name"], f["offset"], f["width"]) for f in bio["fields"]]
    if fields != [(name, OFFSET[name], 32) for name in NAMES] or bio["bytes"] != 68:
        failures.append(f"manifest layout of bio_v1 is not Bio's: {fields[:3]}...")
    if [c["status"] for c in bio["checks"]] != [1, 2, 3]:
        failures.append(f"manifest checks: {bio['checks']}")
    if bio["status"] != {"field": "status_ptr", "returned": False, "width": 32, "success": 0}:
        failures.append(f"manifest status: {bio['status']}")
    if bio["launched_by"] != ["bio_double", "bio_add"]:
        failures.append(f"manifest launchers: {bio['launched_by']}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("h1a_file", type=Path)
    args = parser.parse_args()
    axis_file, h1a_file = args.axis_file.resolve(), args.h1a_file.resolve()
    workdir = Path(tempfile.mkdtemp(prefix="axis_descriptor_"))
    rng = random.Random(0xD35C)
    trials = [(kind, *descriptor(rng, kind)) for kind in KINDS for _ in range(5)]
    sections = (
        ("derived launches compute the engine", check_execution(axis_file, workdir, trials)),
        ("declared == written (H1a)", check_agreement(axis_file, h1a_file, workdir, trials)),
        ("bad declarations are refused", check_refusals(axis_file.read_text(), workdir)),
        ("the source survives a round trip", check_round_trip(axis_file, workdir)),
        ("the manifest publishes the layout", check_manifest(axis_file)),
    )
    ok = True
    for title, failures in sections:
        print(f"{'ok  ' if not failures else 'FAIL'} {title}")
        for failure in failures:
            print(f"     {failure}")
        ok &= not failures
    print("descriptor launches agree: PASS" if ok else "descriptor launches agree: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
