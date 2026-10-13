#!/usr/bin/env python3
"""AHA's descriptors, declared: held to PCE's constants, its RTL and its loader. Gate.

H1c (docs/accelerator_design.md). `examples/aha_descriptors.axisl` declares
AHA's XNN grid v1 and Bio v1 queue descriptors and links each to its engine.
Every claim is held to PCE itself where a checkout is present (PCE_ROOT, or
../pce beside this repository), and to a reference written here where not:

  1. **the layouts are PCE's.** Bio's seventeen fields, in order, at four bytes
     each, its byte count, magic and ABI version, from
     `aha/verticals/bio/queue_abi.py`; XNN's schema version, word count, byte
     count and every error code this corpus uses, from
     `hardware/accel_engines/xnn_grid_descriptor_ingress.py`. Read with `ast`,
     not imported, so a constant is compared and nothing is executed;
  2. **the derived submit IS PCE's decoder.** `XNN_GRID_SUBMIT` runs on the
     Python, wide C and wide Rust executors over valid descriptors, every
     single fault, stacked faults (where the priority decides) and random
     words, and the code it returns must equal what PCE's own PyRTL
     `decode_xnn_grid_descriptor_v1` computes for the same eight words --
     simulated, from PCE's source, with PCE's vendored PyRTL. Without PCE the
     same descriptors are held to a Python reference written from that
     function's rules;
  3. **the bundle carries the layout, and AHA loads it.** `emit-bundle` writes
     both layouts, checks and status destinations into
     `accelerator_descriptor_manifests.json`, with the byte count the
     declaration supplied; and PCE's `aha.isa.adl_loader.load_adl_bundle_dir`
     loads the bundle and hands both layouts through;
  4. **what H1c added is refused when wrong.** An accelerator whose byte count
     disagrees with its declaration; a returned status with no output to
     return it in; a field named `returned`; an `and` in a check with one
     comparison, or with something that is not a comparison;
  5. **the source survives**: `(status returned i4)` and a launch with no
     kernel round-trip stably.

Injection-checked, and the first one was not an injection: the status chain
typed at the status's own four bits compared XNN's sixteen-bit m_count and
sixty-four-bit masks at four bits, and 2 failed against PCE's RTL on ten of
62 descriptors before the fix existed. Letting only a compound check's first
comparison decide its code fails 2; dropping the layout from the descriptor
manifest fails 3; and a corpus with two fields or two codes swapped fails 1.

Usage: tools/aha_descriptor_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix
import exec_wide_check as wide

AXIS_ROOT = Path(__file__).resolve().parent.parent
PCE_ROOT = Path(os.environ.get("PCE_ROOT", AXIS_ROOT.parent / "pce"))
BIO_ABI = PCE_ROOT / "aha/verticals/bio/queue_abi.py"
XNN_INGRESS = PCE_ROOT / "hardware/accel_engines/xnn_grid_descriptor_ingress.py"
ROWS = COLS = 16
OUTSIDE = (~((1 << 16) - 1)) & ((1 << 64) - 1)


def axis(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([*axis_prefix(), *args], capture_output=True, text=True, cwd=AXIS_ROOT)


def constants(path: Path) -> dict:
    """Module-level literal assignments, by `ast`; nothing is imported."""
    values = {}
    for node in ast.parse(path.read_text()).body:
        # Annotated too: `BIO_DESC_FIELDS: Tuple[str, ...] = (...)`.
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target, value = node.targets[0], node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target, value = node.target, node.value
        else:
            continue
        if isinstance(target, ast.Name):
            try:
                values[target.id] = ast.literal_eval(value)
            except ValueError:
                pass
    return values


def manifest_descriptors(axis_file: Path) -> dict:
    manifest = json.loads(axis("emit-json", str(axis_file)).stdout)
    return {d["name"]: d for d in manifest.get("descriptors", [])}


def check_constants(axis_file: Path) -> tuple[list[str], str]:
    if not (BIO_ABI.exists() and XNN_INGRESS.exists()):
        return [], f"skipped: no PCE checkout at {PCE_ROOT}"
    declared = manifest_descriptors(axis_file)
    bio, xnn = declared["bio_v1"], declared["xnn_grid_v1"]
    failures = []
    pce = constants(BIO_ABI)
    fields = [(f["name"], f["offset"], f["width"]) for f in bio["fields"]]
    want = [(name, 4 * index, 32) for index, name in enumerate(pce["BIO_DESC_FIELDS"])]
    if fields != want:
        failures.append(f"bio_v1 fields are not BIO_DESC_FIELDS: {fields[:4]}... vs {want[:4]}...")
    if bio["bytes"] != pce["BIO_DESC_BYTES"]:
        failures.append(f"bio_v1 is {bio['bytes']} bytes; BIO_DESC_BYTES is {pce['BIO_DESC_BYTES']}")
    conditions = [c["condition"] for c in bio["checks"]]
    for name, constant in (("magic", "BIO_DESC_MAGIC"), ("abi_version", "BIO_DESC_ABI_VERSION")):
        if f"(eq {name} {pce[constant]})" not in conditions:
            failures.append(f"bio_v1 checks {name} against something other than {constant} = {pce[constant]}")
    pce = constants(XNN_INGRESS)
    if xnn["bytes"] != pce["XNN_GRID_DESCRIPTOR_BYTES"] \
            or xnn["bytes"] != 4 * pce["XNN_GRID_DESCRIPTOR_WORDS"]:
        failures.append(f"xnn_grid_v1 is {xnn['bytes']} bytes; PCE says "
                        f"{pce['XNN_GRID_DESCRIPTOR_BYTES']} ({pce['XNN_GRID_DESCRIPTOR_WORDS']} words)")
    version = pce["XNN_GRID_DESCRIPTOR_SCHEMA_VERSION"]
    if f"(eq version {version})" not in xnn["checks"][0]["condition"]:
        failures.append(f"xnn_grid_v1's first check does not test the schema version {version}")
    codes = [c["status"] for c in xnn["checks"]]
    want = [pce[f"XNN_GRID_DESCRIPTOR_ERROR_{name}"]
            for name in ("VERSION_FLAGS", "GEOMETRY", "RESERVED", "M_COUNT", "MASK")]
    if codes != want:
        failures.append(f"xnn_grid_v1 codes {codes} are not PCE's {want}, in PCE's priority")
    return failures, "held to PCE's constants"


def xnn_reference(words: list[int]) -> int:
    """decode_xnn_grid_descriptor_v1's rules, for a 16 x 16 grid, from its source."""
    w = words
    if not ((w[0] & 0xFFFF) == 1 and (w[0] >> 16) == 0):
        return 2
    if not ((w[1] & 0xFFFF) == ROWS and (w[1] >> 16) == COLS):
        return 3
    if not ((w[2] >> 16) == 0 and w[3] == 0):
        return 4
    if (w[2] & 0xFFFF) == 0:
        return 5
    row, col = w[4] | (w[5] << 32), w[6] | (w[7] << 32)
    if not (row & 1 and col & 1 and row & OUTSIDE == 0 and col & OUTSIDE == 0):
        return 6
    return 0


def pce_decode(descriptors: list[list[int]]) -> list[int] | None:
    """PCE's own RTL decoder, simulated with PCE's vendored PyRTL."""
    script = f"""
import json, sys
sys.path.insert(0, "third_party/pyrtl"); sys.path.insert(0, ".")
import pyrtl
from hardware.accel_engines.xnn_grid_descriptor_ingress import (
    decode_xnn_grid_descriptor_v1, XNNGridDescriptorPort)
pyrtl.reset_working_block()
present, terr = pyrtl.Input(1, "present"), pyrtl.Input(1, "terr")
words = tuple(pyrtl.Input(32, f"w{{i}}") for i in range(8))
decode = decode_xnn_grid_descriptor_v1(
    XNNGridDescriptorPort(present=present, transport_error=terr, words=words),
    rows={ROWS}, cols={COLS})
code = pyrtl.Output(4, "code"); code <<= decode.error_code
sim = pyrtl.Simulation()
out = []
for ws in json.load(sys.stdin):
    sim.step({{"present": 1, "terr": 0, **{{f"w{{i}}": ws[i] for i in range(8)}}}})
    out.append(sim.inspect("code"))
print(json.dumps(out))
"""
    result = subprocess.run([sys.executable, "-c", script], input=json.dumps(descriptors),
                            capture_output=True, text=True, cwd=PCE_ROOT)
    if result.returncode != 0:
        return None
    return json.loads(result.stdout.strip().splitlines()[-1])


def xnn_descriptors(rng: random.Random) -> list[list[int]]:
    def valid():
        return [1, ROWS | (COLS << 16), rng.randrange(1, 1 << 16), 0,
                1 | (rng.getrandbits(15) << 1), 0, 1 | (rng.getrandbits(15) << 1), 0]
    faults = [
        lambda w: w.__setitem__(0, rng.choice([0, 2, 7]) | (w[0] & 0xFFFF0000)),
        lambda w: w.__setitem__(0, (w[0] & 0xFFFF) | (rng.randrange(1, 1 << 16) << 16)),
        lambda w: w.__setitem__(1, rng.choice([8, 17, 64]) | (w[1] & 0xFFFF0000)),
        lambda w: w.__setitem__(1, (w[1] & 0xFFFF) | (rng.choice([1, 15, 32]) << 16)),
        lambda w: w.__setitem__(2, (w[2] & 0xFFFF) | (rng.randrange(1, 1 << 16) << 16)),
        lambda w: w.__setitem__(3, rng.randrange(1, 1 << 32)),
        lambda w: w.__setitem__(2, w[2] & 0xFFFF0000),
        lambda w: w.__setitem__(4, w[4] & ~1),
        lambda w: w.__setitem__(6, w[6] & ~1),
        lambda w: w.__setitem__(4, w[4] | (1 << rng.randrange(16, 32))),
        lambda w: w.__setitem__(5, w[5] | (1 << rng.randrange(32))),
        lambda w: w.__setitem__(7, w[7] | (1 << rng.randrange(32))),
    ]
    out = [valid() for _ in range(6)]
    for fault in faults:                       # every single fault
        for _ in range(2):
            w = valid(); fault(w); out.append(w)
    for _ in range(24):                        # stacked: the priority decides
        w = valid()
        for fault in rng.sample(faults, rng.randrange(2, 5)):
            fault(w)
        out.append(w)
    out.extend([rng.getrandbits(32) for _ in range(8)] for _ in range(8))
    return out


def cells(base: int, w: list[int]) -> dict:
    """The eight words as this corpus's fields read them: little-endian, and
    keyed by address and width, as the executors' memory is."""
    return {
        (base + 0, 16): w[0] & 0xFFFF, (base + 2, 16): w[0] >> 16,
        (base + 4, 16): w[1] & 0xFFFF, (base + 6, 16): w[1] >> 16,
        (base + 8, 16): w[2] & 0xFFFF, (base + 10, 16): w[2] >> 16,
        (base + 12, 32): w[3],
        (base + 16, 64): w[4] | (w[5] << 32), (base + 24, 64): w[6] | (w[7] << 32),
    }


class Mem:
    def __init__(self, init):
        self.store = dict(init)

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def check_decoder(axis_file: Path, workdir: Path) -> tuple[list[str], str]:
    rng = random.Random(0xA4A)
    descriptors = xnn_descriptors(rng)
    pce = pce_decode(descriptors) if XNN_INGRESS.exists() else None
    expected = pce if pce is not None else [xnn_reference(w) for w in descriptors]
    source = "PCE's RTL decoder" if pce is not None else "the reference (no PCE)"
    failures = []
    if pce is not None:
        disagree = [i for i, w in enumerate(descriptors) if xnn_reference(w) != pce[i]]
        if disagree:
            failures.append(f"this gate's reference and PCE's RTL disagree on {len(disagree)} "
                            f"descriptor(s), e.g. {descriptors[disagree[0]]}")
    if len(set(expected)) < 6:
        failures.append(f"the descriptors reach only codes {sorted(set(expected))}; "
                        f"every code 0 and 2-6 must be exercised")
    for command, output in (("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py"),
                            ("emit-exec-python", "axis_exec.py")):
        wide.emit(axis_file, command, workdir / output)
    sys.path.insert(0, str(workdir))
    executor = importlib.import_module("axis_exec")
    word = 11 | (5 << 7) | (6 << 15)           # XNN_GRID_SUBMIT x5, (x6)
    cases = []
    for index, (w, want) in enumerate(zip(descriptors, expected)):
        base = rng.randrange(1 << 33, 1 << 48) & ~0xFF
        regs = {6: base}
        executor.step(word, regs, Mem(cells(base, w)), 0)
        if regs.get(5) != want:
            failures.append(f"python: descriptor {index} {w} returned {regs.get(5)}, {source} says {want}")
        file = [0] * 32
        file[6] = base
        cases.append({
            "mnemonic": f"XNN_GRID_SUBMIT_{index}", "word": word, "isa": "rvaha", "pc": 0,
            "regs": file, "seed": [(a, wd, v) for (a, wd), v in cells(base, w).items()],
            "state": [], "reg_checks": [(5, want)], "mem_checks": [],
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
    return failures[:12], f"{len(descriptors)} descriptors against {source}"


def check_bundle(axis_file: Path, workdir: Path) -> tuple[list[str], str]:
    bundle = workdir / "bundle"
    result = axis("emit-bundle", str(axis_file), "-o", str(bundle))
    if result.returncode != 0:
        return [f"emit-bundle: {result.stderr.strip()[:200]}"], ""
    entries = {e["name"]: e for e in
               json.loads((bundle / "accelerator_descriptor_manifests.json").read_text())}
    failures = []
    for name, schema, fields, bytes_, returned in (("xnn_grid", "xnn_grid_v1", 9, 32, True),
                                                   ("bio", "bio_v1", 17, 68, False)):
        entry = entries.get(name)
        if entry is None:
            failures.append(f"the bundle has no descriptor manifest for {name}")
            continue
        if entry["descriptor_schema"] != schema or entry["descriptor_bytes"] != bytes_:
            failures.append(f"{name}: schema/bytes {entry['descriptor_schema']}/{entry['descriptor_bytes']}")
        if len(entry.get("descriptor_layout", [])) != fields:
            failures.append(f"{name}: the bundle carries {len(entry.get('descriptor_layout', []))} "
                            f"of {fields} fields")
        if entry.get("descriptor_status", {}).get("returned") is not returned:
            failures.append(f"{name}: status destination {entry.get('descriptor_status')}")
    if not (PCE_ROOT / "aha/isa/adl_loader.py").exists():
        return failures, "bundle checked; AHA's loader skipped (no PCE)"
    script = """
import json, sys
sys.path.insert(0, ".")
from aha.isa.adl_loader import load_adl_bundle_dir
loaded = load_adl_bundle_dir(sys.argv[1])
print(json.dumps({d["name"]: len(d.get("descriptor_layout", []))
                  for d in loaded["accelerator_descriptor_manifests"] or []}))
"""
    result = subprocess.run([sys.executable, "-c", script, str(bundle)],
                            capture_output=True, text=True, cwd=PCE_ROOT)
    if result.returncode != 0:
        failures.append(f"AHA's loader refused the bundle: {result.stderr.strip()[-300:]}")
    elif json.loads(result.stdout.strip().splitlines()[-1]) != {"xnn_grid": 9, "bio": 17}:
        failures.append(f"AHA's loader passed through {result.stdout.strip()}")
    return failures, "bundle checked and loaded by AHA's adl_loader"


def refused(source: str, workdir: Path, name: str, *reasons: str) -> str | None:
    path = workdir / f"{name}.axisl"
    path.write_text(source)
    result = axis("check", str(path))
    if result.returncode == 0:
        return f"{name}: accepted"
    message = result.stderr + result.stdout
    missing = [r for r in reasons if r not in message]
    return f"{name}: refused, but not for {missing}: {message.strip()[:240]}" if missing else None


def mutate(source: str, old: str, new: str) -> str:
    if old not in source:
        raise SystemExit(f"FAIL: mutant anchor `{old}` not found -- corpus moved?")
    return source.replace(old, new, 1)


def check_refusals(source: str, workdir: Path) -> list[str]:
    mutants = [
        ("bytes-disagree", mutate(source, "(descriptor-bytes 68)", "(descriptor-bytes 64)"),
         ("bio", "64", "68")),
        ("returned-without-output", mutate(source, "(operands (rd reg i64 out) (rs1 reg i64 in))",
                                           "(operands (rs1 reg i64 in))"),
         ("exactly one output",)),
        ("field-named-returned", mutate(source, "(reserved_word 12 i32)", "(returned 12 i32)"),
         ("`returned`",)),
        ("and-of-one", mutate(source, "(check (and (eq rows 16) (eq cols 16)) 3)",
                              "(check (and (eq rows 16)) 3)"), ("two comparisons",)),
        ("and-of-non-comparison", mutate(source, "(and (eq reserved_hi 0) (eq reserved_word 0))",
                                         "(and (eq reserved_hi 0) (add i32 reserved_word 0))"),
         ("a check is a comparison",)),
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
    if "(status returned i4)" not in text or "(launches xnn_grid_v1 rs1)" not in text:
        failures.append("the round trip lost the returned status or the kernel-less launch")
    if "(behavior" in text:
        failures.append("the round trip wrote a derived behavior back")
    if twice.read_text() != text:
        failures.append("emit-lisp is not stable under a second round trip")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()
    axis_file = args.axis_file.resolve()
    workdir = Path(tempfile.mkdtemp(prefix="axis_aha_desc_"))
    constant_failures, constant_note = check_constants(axis_file)
    decoder_failures, decoder_note = check_decoder(axis_file, workdir)
    bundle_failures, bundle_note = check_bundle(axis_file, workdir)
    sections = (
        (f"the layouts are PCE's ({constant_note})", constant_failures),
        (f"XNN_GRID_SUBMIT decodes as PCE does ({decoder_note})", decoder_failures),
        (f"the bundle carries the layout ({bundle_note})", bundle_failures),
        ("what H1c added is refused when wrong", check_refusals(axis_file.read_text(), workdir)),
        ("the source survives a round trip", check_round_trip(axis_file, workdir)),
    )
    ok = True
    for title, failures in sections:
        print(f"{'ok  ' if not failures else 'FAIL'} {title}")
        for failure in failures:
            print(f"     {failure}")
        ok &= not failures
    print("AHA descriptors agree: PASS" if ok else "AHA descriptors agree: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
