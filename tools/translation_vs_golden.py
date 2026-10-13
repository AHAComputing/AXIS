#!/usr/bin/env python3
"""Differentially execute cross-ISA translation-map entries.

For every source->target mapping, this emits the translation map, deterministic
encoding fixtures, Python lifter/executor, and golden model. It runs both
instruction words with the same randomized architectural register inputs and
deterministic memory (using the emitted operand map to translate register
indices) and requires:

    source execution == target execution [== source pure golden semantics]

Effect-only helper expressions do not enter the generic pure golden model; for
those mappings this checker differentially compares the two executors, while
the architecture-specific state checker supplies the independent oracle.

Usage: tools/translation_vs_golden.py [input.axisl] [--cases N] [--seed N]

Defaults to examples/aarch64_translation_seed.axisl.
"""

from __future__ import annotations

import argparse
import importlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "axis_file",
        nargs="?",
        type=Path,
        default=AXIS_ROOT / "examples" / "aarch64_translation_seed.axisl",
    )
    parser.add_argument("--cases", type=int, default=128)
    parser.add_argument("--seed", type=int, default=0xA64)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_translate_"))
    paths = {
        "map": workdir / "axis_translation_map.json",
        "fixtures": workdir / "axis_roundtrip_tests.json",
        "golden": workdir / "golden_model.py",
        "lift": workdir / "axis_lift.py",
        "exec": workdir / "axis_exec.py",
        "manifest": workdir / "manifest.json",
    }
    emit(args.axis_file, "emit-json", paths["manifest"])
    emit(args.axis_file, "emit-translation-json", paths["map"])
    emit(args.axis_file, "emit-roundtrip-json", paths["fixtures"])
    emit(args.axis_file, "emit-golden-python", paths["golden"])
    emit(args.axis_file, "emit-lift-python", paths["lift"])
    emit(args.axis_file, "emit-exec-python", paths["exec"])

    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    golden = importlib.import_module("golden_model")

    # Every scalar architectural state the ISAs declare starts at zero, so a
    # newly declared state is executable here without editing this harness.
    # `pc` is passed to `step` explicitly; register files are addressed through
    # operands rather than read by name.
    declared_state = {
        name: 0
        for isa in json.loads(paths["manifest"].read_text()).get("isas", [])
        for name in (
            entry.split(":", 1)[0].strip() for entry in isa.get("registers", [])
        )
        if name and name != "pc" and "[" not in name
    }

    translation = json.loads(paths["map"].read_text())
    fixtures = {
        fixture["mnemonic"]: fixture
        for fixture in json.loads(paths["fixtures"].read_text())["tests"]
    }
    rng = random.Random(args.seed)
    checks = failures = 0

    class Memory:
        def __init__(self) -> None:
            self.cells: dict[tuple[int, int], int] = {}

        def read(self, addr: int, width: int) -> int:
            mask = (1 << width) - 1
            return self.cells.get(
                (addr, width),
                (addr * 0x9E3779B97F4A7C15 ^ width) & mask,
            )

        def write(self, addr: int, value: int, width: int) -> None:
            self.cells[(addr, width)] = value & ((1 << width) - 1)

    for mapping in translation["matches"]:
        source = fixtures[mapping["source_mnemonic"]]
        target = fixtures[mapping["target_mnemonic"]]
        source_operands = {item["name"]: item["value"] for item in source["operands"]}
        target_operands = {item["name"]: item["value"] for item in target["operands"]}
        input_map = [item for item in mapping["operand_map"] if item["role"] == "in"]
        # Whether an operand is a register is a fact the map states, not one to
        # infer from the class name: a class in a different register file names
        # a different lowering family, and matching on the string "reg" skipped
        # every operand that was not a general-purpose one.
        register_map = [item for item in input_map if item.get("register")]
        output_map = next(item for item in mapping["operand_map"] if item["role"] == "out")
        source_word = int(source["encoded"], 16)
        target_word = int(target["encoded"], 16)

        vectors = [
            [0] * len(register_map),
            [(1 << 64) - 1] * len(register_map),
            [1 << 63] + [1] * max(0, len(register_map) - 1),
        ]
        vectors.extend(
            [rng.getrandbits(64) for _ in register_map] for _ in range(args.cases)
        )
        for values in vectors:
            source_regs = {}
            target_regs = {}
            source_memory = Memory()
            target_memory = Memory()
            source_state = {**declared_state, "nzcv": 0}
            target_state = dict(source_state)
            register_values = {}
            for operand_map, value in zip(register_map, values):
                # Keyed by slot, not by index: the executors place a
                # register at `offset + index * stride`, and a file above the
                # general-purpose one has a non-zero offset. Seeding by index
                # alone wrote into the wrong file and read back zero; ignoring
                # the stride wrote into the register before the one meant, once
                # AArch64's 128-bit `V` made a register two slots wide.
                offset = operand_map.get("slot_offset", 0)
                stride = operand_map.get("slot_stride", 1)
                source_regs[offset + source_operands[operand_map["source"]] * stride] = value
                target_regs[offset + target_operands[operand_map["target"]] * stride] = value
                register_values[operand_map["source"]] = value

            for operand_map in input_map:
                if not operand_map.get("register"):
                    source_value = source_operands[operand_map["source"]]
                    target_value = target_operands[operand_map["target"]]
                    if source_value != target_value:
                        print(
                            f"FAIL immediate map {operand_map['source']} -> "
                            f"{operand_map['target']}: {source_value} != {target_value}"
                        )
                        failures += 1

            source_out = axis_exec.step(
                source_word,
                source_regs,
                mem=source_memory,
                isa=mapping["source_isa"],
                state=source_state,
            )
            target_out = axis_exec.step(
                target_word,
                target_regs,
                mem=target_memory,
                isa=mapping["target_isa"],
                state=target_state,
            )
            golden_values = [
                register_values.get(item["source"], source_operands[item["source"]])
                for item in input_map
            ]
            if mapping["source_mnemonic"] in golden.AXIS_SPECS:
                expected = golden.evaluate(mapping["source_mnemonic"], *golden_values)
            else:
                expected = None if source_out is None else source_out["result"]
            out_offset = output_map.get("slot_offset", 0)
            out_stride = output_map.get("slot_stride", 1)
            source_dest = out_offset + source_operands[output_map["source"]] * out_stride
            target_dest = out_offset + target_operands[output_map["target"]] * out_stride
            checks += 1
            if (
                source_out is None
                or target_out is None
                or source_out["result"] != expected
                or target_out["result"] != expected
                or source_regs.get(source_dest) != expected
                or target_regs.get(target_dest) != expected
                or source_state != target_state
                or source_memory.cells != target_memory.cells
            ):
                print(
                    f"FAIL {mapping['source_mnemonic']} -> "
                    f"{mapping['target_mnemonic']} inputs={values}: "
                    f"source={source_out} target={target_out} expected={expected}"
                )
                failures += 1

    print(
        f"{len(translation['matches'])} mapping(s), {checks} execution checks, "
        f"{len(translation['unmatched_sources'])} fallback source(s), "
        f"{failures} failures"
    )
    ok = bool(translation["matches"]) and failures == 0
    print("translation execution: PASS" if ok else "translation execution: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
