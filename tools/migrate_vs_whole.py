#!/usr/bin/env python3
"""Migration proof: split-run (checkpoint + migrate) == whole-run.

Emits golden_model.py, axis_lift.py, axis_exec.py, and
state_capsule_manifest.json from a personality document, then for random
straight-line programs:

  * runs the whole program on one register file (the "whole run");
  * runs the first half, serializes the architectural state into the capsule
    byte layout of one personality, deserializes those exact bytes into a fresh
    register file using the *other* personality's (identical) layout, and runs
    the second half (the "split run" — a migration between personalities);

and requires the final architectural state to match. This proves the capsule
layout captures all migratable state, round-trips its bytes, and that the
`migratable_pairs` in the manifest genuinely share a checkpoint format. It also
re-derives each canonical layout string and re-hashes it (SHA-256), proving the
manifest's `layout_hash` is reproducible outside the Rust crate.

Usage: tools/migrate_vs_whole.py <input.axisl> [--programs N] [--length L]

Requires: cargo (run from the AXIS repo root).
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def encode(entry, operand_values):
    """Encode an instruction word from operand values using the lift fields."""
    word = entry["match"]
    for op in entry["operands"]:
        value = operand_values.get(op["name"], 0)
        for insn_lo, op_lo, width in op["fields"]:
            piece = (value >> op_lo) & ((1 << width) - 1)
            word |= piece << insn_lo
    return word


def serialize(regs, pc, layout):
    """Pack the architectural state into capsule bytes per the layout."""
    buf = bytearray(layout["total_bytes"])
    for entry in layout["capsule"]:
        stride = entry["width_bits"] // 8
        for i in range(entry["count"]):
            value = pc if entry["name"] == "pc" else regs.get(i, 0)
            off = entry["byte_offset"] + i * stride
            buf[off:off + stride] = (value & ((1 << entry["width_bits"]) - 1)).to_bytes(
                stride, "little"
            )
    return bytes(buf)


def deserialize(buf, layout):
    """Reconstruct a fresh (regs, pc) from capsule bytes per the layout."""
    regs, pc = {}, 0
    for entry in layout["capsule"]:
        stride = entry["width_bits"] // 8
        for i in range(entry["count"]):
            off = entry["byte_offset"] + i * stride
            value = int.from_bytes(buf[off:off + stride], "little")
            if entry["name"] == "pc":
                pc = value
            else:
                regs[i] = value
    return regs, pc


def run(words, regs, pc, axis_exec):
    regs = dict(regs)
    for word in words:
        out = axis_exec.step(word, regs, None, pc)
        pc = out["next_pc"] if out else pc + 4
    return regs, pc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--programs", type=int, default=64)
    parser.add_argument("--length", type=int, default=12)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_migrate_"))
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    manifest_path = workdir / "state_capsule_manifest.json"
    emit(args.axis_file, "emit-capsule-json", manifest_path)

    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    axis_lift = importlib.import_module("axis_lift")

    manifest = json.loads(manifest_path.read_text())
    personalities = {p["name"]: p for p in manifest["personalities"]}
    if len(personalities) < 2 or not manifest["migratable_pairs"]:
        print("need at least two migratable personalities")
        return DECLINED

    # Reproduce each layout hash from the canonical string (SHA-256).
    for p in manifest["personalities"]:
        rehash = hashlib.sha256(p["canonical_layout"].encode()).hexdigest()
        if rehash != p["layout_hash"]:
            print(f"FAIL {p['name']}: layout_hash not reproducible")
            return 1

    # Executable straight-line instructions (pure register writes).
    execable = [
        e for e in axis_lift.AXIS_LIFT_TABLE
        if e["semantics"] is not None and any(o["role"] == "out" for o in e["operands"])
    ]
    if not execable:
        print("no executable instructions to build a program")
        return DECLINED

    random.seed(0x316)
    checks = failures = 0
    seen: set[str] = set()
    for pa_name, pb_name in manifest["migratable_pairs"]:
        layout_a, layout_b = personalities[pa_name], personalities[pb_name]
        for _ in range(args.programs):
            program = []
            for _ in range(args.length):
                entry = random.choice(execable)
                seen.add(entry["mnemonic"])
                values = {o["name"]: random.randrange(32)
                          for o in entry["operands"] if o["kind"] == "reg"}
                program.append(encode(entry, values))
            init = {i: random.getrandbits(32) for i in range(32)}

            whole_regs, whole_pc = run(program, init, 0, axis_exec)
            covered = [i for e in layout_a["capsule"] if e["name"] != "pc"
                       for i in range(e["count"])]

            # Checkpoint at every split point k: run k on A, migrate to B, finish.
            for k in range(len(program) + 1):
                mid_regs, mid_pc = run(program[:k], init, 0, axis_exec)
                capsule = serialize(mid_regs, mid_pc, layout_a)            # checkpoint on A
                resumed_regs, resumed_pc = deserialize(capsule, layout_b)  # migrate to B
                split_regs, split_pc = run(program[k:], resumed_regs, resumed_pc, axis_exec)

                checks += 1
                if any(whole_regs.get(i, 0) != split_regs.get(i, 0) for i in covered) \
                        or whole_pc != split_pc:
                    print(f"FAIL {pa_name}->{pb_name} at k={k}: split-run != whole-run")
                    failures += 1

    print(f"{checks} programs, {failures} failures")
    # `docs/gate_coverage.md`: report instruction coverage, require class
    # coverage. This gate draws its programs from a pool, so a run can migrate
    # a checkpoint that never touched the state a whole class of instruction
    # writes -- and report a green capsule round-trip about it.
    offered = {entry["mnemonic"] for entry in execable}
    absent = sorted(offered - seen)
    print(f"  coverage: {len(seen)}/{len(offered)} instruction(s) executed"
          + (f"; never run: {', '.join(absent[:6])}" if absent else ""))
    def shape(entry):
        effects = entry.get("effects") or []
        kinds = tuple(sorted({one["kind"] for one in effects}))
        writes = sum(1 for one in effects if one["kind"] in ("set", "setreg"))
        return kinds + (("multi-write",) if writes > 1 else ())
    offered_shapes = {shape(entry) for entry in execable}
    covered_shapes = {shape(entry) for entry in execable if entry["mnemonic"] in seen}
    missing_shapes = offered_shapes - covered_shapes
    print(f"  classes: {len(covered_shapes)}/{len(offered_shapes)} executed"
          + (f"; never run: "
             + ", ".join(sorted("+".join(one) or "pure" for one in missing_shapes))
             if missing_shapes else ""))
    ok = failures == 0 and not missing_shapes
    print("migrate (split) == whole: PASS" if ok else "migrate (split) == whole: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
