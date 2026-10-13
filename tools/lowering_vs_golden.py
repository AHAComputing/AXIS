#!/usr/bin/env python3
"""Execute explicit lowering source sequences against their fused targets.

The validator already proves typed semantic-tree equality. This harness closes
the binary/runtime loop: it encodes every source step and target from the
manifest bindings, executes both paths with identical randomized inputs, and
requires the final register result, named architectural state, memory, and
explicit control-flow outcome to agree.

Usage: tools/lowering_vs_golden.py [input.axisl] [--cases N] [--seed N]
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


def encode(entry: dict, values: dict[str, int]) -> int:
    word = int(entry["match"], 16)
    for operand in entry["operands"]:
        if not operand["fields"]:
            continue
        value = values[operand["name"]]
        for field in operand["fields"]:
            width = field["width"]
            mask = (1 << width) - 1
            word &= ~(mask << field["insn_lo"])
            word |= ((value >> field["op_lo"]) & mask) << field["insn_lo"]
    return word


def lowering_value(value: dict, variables: dict[str, int]) -> int:
    if value["kind"] == "literal":
        return value["value"]
    return variables[value["name"]]


def predicate_holds(predicate: dict | None, variables: dict[str, int]) -> bool:
    if predicate is None:
        return True
    kind = predicate["kind"]
    if kind == "and":
        return all(predicate_holds(item, variables) for item in predicate["predicates"])
    if kind == "or":
        return any(predicate_holds(item, variables) for item in predicate["predicates"])
    if kind == "not":
        return not predicate_holds(predicate["predicate"], variables)
    lhs = lowering_value(predicate["lhs"], variables)
    rhs = lowering_value(predicate["rhs"], variables)
    return {
        "eq": lhs == rhs,
        "ne": lhs != rhs,
        "lt": lhs < rhs,
        "le": lhs <= rhs,
        "gt": lhs > rhs,
        "ge": lhs >= rhs,
    }[predicate["op"]]


def step_values(step: dict, variables: dict[str, int]) -> dict[str, int]:
    return {
        binding["operand"]: lowering_value(binding["value"], variables)
        for binding in step["bindings"]
    }


def variable_classes(lowering: dict) -> dict[str, str]:
    classes = {}
    for step in [*lowering["source_sequence"], lowering["target"]]:
        for binding in step["bindings"]:
            value = binding["value"]
            if value["kind"] == "variable":
                classes[value["name"]] = binding["class"]
    return classes


def variable_widths(lowering: dict) -> dict[str, int]:
    widths = {}
    for step in [*lowering["source_sequence"], lowering["target"]]:
        for binding in step["bindings"]:
            value = binding["value"]
            if value["kind"] == "variable":
                widths[value["name"]] = binding["width"]
    return widths


def source_dataflow(lowering: dict) -> tuple[list[str], list[str]]:
    produced = set()
    consumed_produced = set()
    external = []
    for step in lowering["source_sequence"]:
        for binding in step["bindings"]:
            value = binding["value"]
            if binding["role"] in {"in", "inout"} and value["kind"] == "variable":
                name = value["name"]
                if name in produced:
                    consumed_produced.add(name)
                elif name not in external:
                    external.append(name)
        for binding in step["bindings"]:
            value = binding["value"]
            if binding["role"] in {"out", "inout"} and value["kind"] == "variable":
                produced.add(value["name"])
    finals = produced - consumed_produced
    return external, sorted(finals)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "axis_file",
        nargs="?",
        type=Path,
        default=AXIS_ROOT / "examples" / "lisp_lowerings.axisl",
    )
    parser.add_argument("--cases", type=int, default=128)
    parser.add_argument("--seed", type=lambda value: int(value, 0), default=0x10A3)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_lowering_"))
    paths = {
        "translation": workdir / "translation.json",
        "lift_json": workdir / "lift.json",
        "lift": workdir / "axis_lift.py",
        "golden": workdir / "golden_model.py",
        "exec": workdir / "axis_exec.py",
        "translate": workdir / "axis_translate.py",
        "manifest": workdir / "manifest.json",
    }
    emit(args.axis_file, "emit-json", paths["manifest"])
    emit(args.axis_file, "emit-translation-json", paths["translation"])
    emit(args.axis_file, "emit-lift-json", paths["lift_json"])
    emit(args.axis_file, "emit-lift-python", paths["lift"])
    emit(args.axis_file, "emit-golden-python", paths["golden"])
    emit(args.axis_file, "emit-exec-python", paths["exec"])
    emit(args.axis_file, "emit-translation-python", paths["translate"])

    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    axis_translate = importlib.import_module("axis_translate")
    translation = json.loads(paths["translation"].read_text())
    lift_entries = {
        (entry["isa"], entry["mnemonic"]): entry
        for entry in json.loads(paths["lift_json"].read_text())["instructions"]
    }
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

    for lowering in translation["explicit_lowerings"]:
        classes = variable_classes(lowering)
        widths = variable_widths(lowering)
        register_variables = sorted(
            name for name, value_class in classes.items() if value_class == "reg"
        )
        if len(register_variables) > 30:
            raise ValueError(f"{lowering['name']} needs too many registers")
        encoded_variables = {
            name: index + 1 for index, name in enumerate(register_variables)
        }
        for name, value_class in classes.items():
            if value_class != "reg":
                encoded_variables[name] = (
                    (1 << widths[name]) - 1
                    if name in {"offset", "displacement"}
                    else 3
                    if name == "extend"
                    else 1
                )
        source_sp_variables = {
            binding["value"]["name"]
            for step in lowering["source_sequence"]
            for binding in step["bindings"]
            if binding["value"]["kind"] == "variable"
            and binding["operand_kind"].endswith("sp")
        }
        target_sp_variables = {
            binding["value"]["name"]
            for binding in lowering["target"]["bindings"]
            if binding["value"]["kind"] == "variable"
            and binding["operand_kind"].endswith("sp")
        }
        bridged_sp_variables = source_sp_variables & target_sp_variables
        for variable in bridged_sp_variables:
            encoded_variables[variable] = 31
        if not predicate_holds(lowering["requires"], encoded_variables):
            raise ValueError(
                f"{lowering['name']} deterministic bindings do not satisfy requires"
            )

        external, finals = source_dataflow(lowering)
        source_words = [
            encode(
                lift_entries[(step["isa"], step["mnemonic"])],
                step_values(step, encoded_variables),
            )
            for step in lowering["source_sequence"]
        ]
        target = lowering["target"]
        expected_target_word = encode(
            lift_entries[(target["isa"], target["mnemonic"])],
            step_values(target, encoded_variables),
        )
        generated_match = axis_translate.match_at(source_words)
        if (
            generated_match is None
            or generated_match["rule"] != lowering["name"]
            or generated_match["target_word"] != expected_target_word
        ):
            print(
                f"FAIL generated matcher {lowering['name']}: "
                f"got {generated_match}, target=0x{expected_target_word:08x}"
            )
            failures += 1

        rewritten, applied = axis_translate.rewrite_all(
            [0xFFFFFFFF, *source_words, 0xFFFFFFFF]
        )
        if (
            rewritten != [0xFFFFFFFF, expected_target_word, 0xFFFFFFFF]
            or len(applied) != 1
        ):
            print(f"FAIL generated rewrite_all {lowering['name']}: {rewritten}")
            failures += 1

        aliases = dict(encoded_variables)
        if "tmp" in aliases and "lhs" in aliases:
            aliases["tmp"] = aliases["lhs"]
            guarded_words = [
                encode(
                    lift_entries[(step["isa"], step["mnemonic"])],
                    step_values(step, aliases),
                )
                for step in lowering["source_sequence"]
            ]
            if axis_translate.match_at(guarded_words) is not None:
                print(f"FAIL generated guard rejection {lowering['name']}")
                failures += 1

        # Exercise at least one predicate-rejected register assignment when
        # the rule has such a guard (the AArch64 corpus uses this to exclude
        # encoded register 31 / XZR from ordinary accelerator registers).
        for variable in register_variables:
            guarded = dict(encoded_variables)
            guarded[variable] = 31
            if predicate_holds(lowering["requires"], guarded):
                continue
            guarded_words = [
                encode(
                    lift_entries[(step["isa"], step["mnemonic"])],
                    step_values(step, guarded),
                )
                for step in lowering["source_sequence"]
            ]
            guarded_match = axis_translate.match_at(guarded_words)
            if guarded_match is not None and guarded_match["rule"] == lowering["name"]:
                print(f"FAIL generated architectural guard rejection {lowering['name']}")
                failures += 1
            break

        first_step = lowering["source_sequence"][0]
        fixed_mask = int(first_step["mask"], 16)
        changed_bit = fixed_mask & -fixed_mask
        nonmatch_words = list(source_words)
        nonmatch_words[0] ^= changed_bit
        changed_match = axis_translate.match_at(nonmatch_words)
        if changed_match is not None and changed_match["rule"] == lowering["name"]:
            print(f"FAIL generated fixed-bit rejection {lowering['name']}")
            failures += 1

        external_registers = [name for name in external if classes[name] == "reg"]
        observable_registers = set()
        for variable in [
            *external_registers,
            *(name for name in finals if classes[name] == "reg"),
        ]:
            selector = encoded_variables[variable]
            observable_registers.add(
                "sp"
                if selector == 31 and variable in bridged_sp_variables
                else selector
            )

        def observable_values(registers: dict) -> dict:
            return {
                register: registers.get(register, 0)
                for register in observable_registers
            }

        has_pc_effect = any(
            effect.startswith("pc") for effect in lowering["effect_order"]
        )
        has_guarded_pc_effect = "pc:guarded" in lowering["effect_order"]
        vectors = [
            [0] * len(external_registers),
            [(1 << 64) - 1] * len(external_registers),
            [1 << 63] + [1] * max(0, len(external_registers) - 1),
        ]
        vectors.extend(
            [rng.getrandbits(64) for _ in external_registers]
            for _ in range(args.cases)
        )

        for vector_index, vector in enumerate(vectors):
            source_regs = {}
            target_regs = {}
            # The deterministic conditional-branch binding uses condition 1
            # (NE), so toggling Z guarantees taken and fall-through coverage
            # even when the random-case count is zero.
            nzcv = (
                (0 if vector_index % 2 == 0 else 0x4)
                if has_guarded_pc_effect
                else 0xF
            )
            source_state = {**declared_state, "nzcv": nzcv}
            target_state = dict(source_state)
            source_memory = Memory()
            target_memory = Memory()
            initial_pc = 0x1000
            source_pc = initial_pc
            for variable, value in zip(external_registers, vector):
                selector = encoded_variables[variable]
                register = (
                    "sp"
                    if selector == 31 and variable in bridged_sp_variables
                    else selector
                )
                source_regs[register] = value
                target_regs[register] = value

            if lowering["name"].startswith(
                (
                    "lower-a64-stxr-",
                    "lower-a64-stlxr-",
                    "lower-a64-stxp-",
                    "lower-a64-stlxp-",
                )
            ):
                base_selector = encoded_variables["base"]
                base_register = (
                    "sp"
                    if base_selector == 31 and "base" in bridged_sp_variables
                    else base_selector
                )
                base_value = source_regs.get(base_register, 0)
                reservation_case = vector_index % 3
                source_state["exclusive_valid"] = 0 if reservation_case == 1 else 1
                source_state["exclusive_address"] = (
                    base_value if reservation_case != 2 else base_value ^ 8
                )
                scalar = lowering["name"].startswith(
                    ("lower-a64-stxr-", "lower-a64-stlxr-")
                )
                source_state["exclusive_size"] = (
                    4 if lowering["name"].endswith("-w") else 8
                ) * (1 if scalar else 2)
                target_state = dict(source_state)

            source_result = None
            for step, word in zip(lowering["source_sequence"], source_words):
                source_result = axis_exec.step(
                    word,
                    source_regs,
                    mem=source_memory,
                    isa=step["isa"],
                    state=source_state,
                    pc=source_pc,
                )
                if source_result is None:
                    break
                source_pc = source_result["next_pc"]

            target_result = axis_exec.step(
                expected_target_word,
                target_regs,
                mem=target_memory,
                isa=target["isa"],
                state=target_state,
                pc=initial_pc,
            )
            checks += 1
            if (
                source_result is None
                or target_result is None
                or (
                    finals
                    and source_result["result"] != target_result["result"]
                )
                or observable_values(source_regs) != observable_values(target_regs)
                or source_state != target_state
                or source_memory.cells != target_memory.cells
                or (
                    has_pc_effect
                    and (
                        source_result["next_pc"] != target_result["next_pc"]
                        or source_result["trap"] != target_result["trap"]
                    )
                )
            ):
                print(
                    f"FAIL {lowering['name']} inputs={vector}: "
                    f"source={source_result} state={source_state} "
                    f"memory={source_memory.cells} target={target_result} "
                    f"state={target_state} memory={target_memory.cells}"
                )
                failures += 1

        # Scaled unsigned-offset memory forms need more than the deterministic
        # fixture offset. Exercise the full immediate range boundaries, force
        # the sign bit in load payloads, and use a truncation-sensitive store
        # value. Generic accelerator registers cannot represent AArch64 SP, so
        # selector 31 for the base must be rejected by these rules.
        unsigned_offset_memory = (
            "offset" in encoded_variables
            and widths["offset"] == 12
            and lowering["name"].endswith("-unsigned")
            and bool(lowering["memory_effects"])
        )
        if unsigned_offset_memory:
            sp_variant = dict(encoded_variables)
            sp_variant["base"] = 31
            sp_words = [
                encode(
                    lift_entries[(step["isa"], step["mnemonic"])],
                    step_values(step, sp_variant),
                )
                for step in lowering["source_sequence"]
            ]
            sp_match = axis_translate.match_at(sp_words)
            if sp_match is not None and sp_match["rule"] == lowering["name"]:
                print(f"FAIL SP-base memory match {lowering['name']}: {sp_match}")
                failures += 1

            memory_effect = lowering["memory_effects"][0]
            memory_width = int(memory_effect.rsplit("i", 1)[1])
            source_mnemonic = lowering["source_sequence"][0]["mnemonic"]
            scale = (
                3
                if source_mnemonic in {"LDR_X_UNSIGNED", "STR_X_UNSIGNED"}
                else 2
                if source_mnemonic
                in {"LDR_W_UNSIGNED", "LDRSW_X_UNSIGNED", "STR_W_UNSIGNED"}
                else 1
                if "LDRH" in source_mnemonic or "STRH" in source_mnemonic
                else 0
            )
            for offset in (0, 1, 0x7FF, 0xFFF):
                variant = dict(encoded_variables)
                variant["offset"] = offset
                variant_source_words = [
                    encode(
                        lift_entries[(step["isa"], step["mnemonic"])],
                        step_values(step, variant),
                    )
                    for step in lowering["source_sequence"]
                ]
                variant_target_word = encode(
                    lift_entries[(target["isa"], target["mnemonic"])],
                    step_values(target, variant),
                )
                variant_match = axis_translate.match_at(variant_source_words)
                if (
                    variant_match is None
                    or variant_match["rule"] != lowering["name"]
                    or variant_match["target_word"] != variant_target_word
                ):
                    print(
                        f"FAIL generated unsigned-memory match {lowering['name']} "
                        f"offset={offset:#x}: {variant_match}"
                    )
                    failures += 1
                    continue

                base_value = 0x4000
                source_regs = {}
                target_regs = {}
                for variable in external_registers:
                    selector = variant[variable]
                    value = (
                        base_value
                        if variable == "base"
                        else 0xFEDC_BA98_7654_80FF
                    )
                    source_regs[selector] = value
                    target_regs[selector] = value
                source_memory = Memory()
                target_memory = Memory()
                address = base_value + (offset << scale)
                payload = (1 << (memory_width - 1)) | 0x5A
                source_memory.cells[(address, memory_width)] = payload
                target_memory.cells[(address, memory_width)] = payload
                source_state = {**declared_state, "nzcv": 0xF}
                target_state = dict(source_state)
                source_result = None
                for step, word in zip(
                    lowering["source_sequence"], variant_source_words
                ):
                    source_result = axis_exec.step(
                        word,
                        source_regs,
                        mem=source_memory,
                        isa=step["isa"],
                        state=source_state,
                        pc=0x1000,
                    )
                target_result = axis_exec.step(
                    variant_target_word,
                    target_regs,
                    mem=target_memory,
                    isa=target["isa"],
                    state=target_state,
                    pc=0x1000,
                )
                checks += 1
                if (
                    source_result is None
                    or target_result is None
                    or (
                        finals
                        and source_result["result"] != target_result["result"]
                    )
                    or observable_values(source_regs)
                    != observable_values(target_regs)
                    or source_memory.cells != target_memory.cells
                    or source_state != target_state
                ):
                    print(
                        f"FAIL {lowering['name']} offset={offset:#x}: "
                        f"source={source_result} regs={source_regs} "
                        f"memory={source_memory.cells} target={target_result} "
                        f"regs={target_regs} memory={target_memory.cells}"
                    )
                    failures += 1

        # Register-offset memory retains AArch64's heterogeneous register
        # roles on the target: SP is legal as the base while register 31 is
        # XZR for the scaled index and load/store data operand. Exercise both
        # zero-register positions explicitly; randomized values alone cannot
        # change an encoded selector into register 31.
        if lowering["name"].endswith("-reg-lsl3"):
            zero_register_variants = [{"index": 31}]
            data_variable = "out" if "out" in encoded_variables else "value"
            zero_register_variants.append({data_variable: 31})
            for selector_overrides in zero_register_variants:
                variant = dict(encoded_variables)
                variant.update(selector_overrides)
                variant_source_words = [
                    encode(
                        lift_entries[(step["isa"], step["mnemonic"])],
                        step_values(step, variant),
                    )
                    for step in lowering["source_sequence"]
                ]
                variant_target_word = encode(
                    lift_entries[(target["isa"], target["mnemonic"])],
                    step_values(target, variant),
                )
                variant_match = axis_translate.match_at(variant_source_words)
                if (
                    variant_match is None
                    or variant_match["rule"] != lowering["name"]
                    or variant_match["target_word"] != variant_target_word
                ):
                    print(
                        f"FAIL generated register-offset match "
                        f"{lowering['name']} selectors={selector_overrides}: "
                        f"{variant_match}"
                    )
                    failures += 1
                    continue

                source_regs = {"sp": 0x7000, 31: 0xFFFF_FFFF_FFFF_FFFF}
                target_regs = dict(source_regs)
                index_value = 0 if variant["index"] == 31 else 2
                if variant["index"] != 31:
                    source_regs[variant["index"]] = index_value
                    target_regs[variant["index"]] = index_value
                if data_variable == "value" and variant["value"] != 31:
                    source_regs[variant["value"]] = 0xA5A5_5A5A_F0F0_0F0F
                    target_regs[variant["value"]] = 0xA5A5_5A5A_F0F0_0F0F
                address = 0x7000 + (index_value << 3)
                source_memory = Memory()
                target_memory = Memory()
                source_memory.cells[(address, 64)] = 0x8123_4567_89AB_CDEF
                target_memory.cells[(address, 64)] = 0x8123_4567_89AB_CDEF
                source_state = {**declared_state, "nzcv": 0xF, "sp": 0x7000}
                target_state = dict(source_state)
                source_result = None
                for step, word in zip(
                    lowering["source_sequence"], variant_source_words
                ):
                    source_result = axis_exec.step(
                        word,
                        source_regs,
                        mem=source_memory,
                        isa=step["isa"],
                        state=source_state,
                        pc=0x1000,
                    )
                target_result = axis_exec.step(
                    variant_target_word,
                    target_regs,
                    mem=target_memory,
                    isa=target["isa"],
                    state=target_state,
                    pc=0x1000,
                )
                checks += 1
                if (
                    source_result is None
                    or target_result is None
                    or (
                        finals
                        and source_result["result"] != target_result["result"]
                    )
                    or observable_values(source_regs)
                    != observable_values(target_regs)
                    or source_memory.cells != target_memory.cells
                    or source_state != target_state
                ):
                    print(
                        f"FAIL {lowering['name']} selectors={selector_overrides}: "
                        f"source={source_result} regs={source_regs} "
                        f"memory={source_memory.cells} target={target_result} "
                        f"regs={target_regs} memory={target_memory.cells}"
                    )
                    failures += 1

        # MADD/MSUB use four architectural register selectors. Exercise XZR
        # independently in every source, accumulator, and destination role;
        # the regular randomized vectors stress modular overflow but keep the
        # encoded selectors fixed.
        multiply_accumulate = any(
            f"-{operation}-" in lowering["name"]
            for operation in ("madd", "msub")
        )
        if multiply_accumulate:
            for zero_variable in ("lhs", "rhs", "acc", "out"):
                variant = dict(encoded_variables)
                variant[zero_variable] = 31
                variant_source_words = [
                    encode(
                        lift_entries[(step["isa"], step["mnemonic"])],
                        step_values(step, variant),
                    )
                    for step in lowering["source_sequence"]
                ]
                variant_target_word = encode(
                    lift_entries[(target["isa"], target["mnemonic"])],
                    step_values(target, variant),
                )
                variant_match = axis_translate.match_at(variant_source_words)
                if (
                    variant_match is None
                    or variant_match["rule"] != lowering["name"]
                    or variant_match["target_word"] != variant_target_word
                ):
                    print(
                        f"FAIL generated multiply match {lowering['name']} "
                        f"{zero_variable}=31: {variant_match}"
                    )
                    failures += 1
                    continue

                values = {
                    "lhs": 0xFFFF_FFFF_FFFF_FFFD,
                    "rhs": 0x8000_0000_0000_0003,
                    "acc": 0x0123_4567_89AB_CDEF,
                }
                source_regs = {31: 0xA5A5_A5A5_A5A5_A5A5}
                target_regs = dict(source_regs)
                for variable in external_registers:
                    selector = variant[variable]
                    if selector != 31:
                        source_regs[selector] = values[variable]
                        target_regs[selector] = values[variable]
                source_state = {**declared_state, "nzcv": 0xF}
                target_state = dict(source_state)
                source_result = None
                for step, word in zip(
                    lowering["source_sequence"], variant_source_words
                ):
                    source_result = axis_exec.step(
                        word,
                        source_regs,
                        isa=step["isa"],
                        state=source_state,
                        pc=0x1000,
                    )
                target_result = axis_exec.step(
                    variant_target_word,
                    target_regs,
                    isa=target["isa"],
                    state=target_state,
                    pc=0x1000,
                )
                checks += 1
                if (
                    source_result is None
                    or target_result is None
                    or (
                        finals
                        and source_result["result"] != target_result["result"]
                    )
                    or observable_values(source_regs)
                    != observable_values(target_regs)
                    or source_state != target_state
                ):
                    print(
                        f"FAIL {lowering['name']} {zero_variable}=31: "
                        f"source={source_result} regs={source_regs} "
                        f"target={target_result} regs={target_regs}"
                    )
                    failures += 1

        # Division has architecturally defined results for a zero divisor and
        # signed MIN/-1, unlike the host-language operators used by several
        # generated backends. Pin those cases and exercise XZR/WZR in every
        # encoded register role independently.
        division = any(
            f"-{operation}-" in lowering["name"]
            for operation in ("udiv", "sdiv")
        )
        if division:
            width = widths["lhs"]
            mask = (1 << width) - 1
            signed_division = "-sdiv-" in lowering["name"]
            division_cases = [
                ("zero-divisor", {}, 123, 0),
                (
                    "signed-truncation" if signed_division else "unsigned-quotient",
                    {},
                    (-7) & mask if signed_division else mask,
                    3,
                ),
            ]
            if signed_division:
                division_cases.append(
                    ("signed-overflow", {}, 1 << (width - 1), mask)
                )
            division_cases.extend(
                (
                    f"{zero_variable}=31",
                    {zero_variable: 31},
                    0xFEDC_BA98_7654_3217 & mask,
                    7,
                )
                for zero_variable in ("lhs", "rhs", "out")
            )

            for label, overrides, lhs_value, rhs_value in division_cases:
                variant = dict(encoded_variables)
                variant.update(overrides)
                variant_source_words = [
                    encode(
                        lift_entries[(step["isa"], step["mnemonic"])],
                        step_values(step, variant),
                    )
                    for step in lowering["source_sequence"]
                ]
                variant_target_word = encode(
                    lift_entries[(target["isa"], target["mnemonic"])],
                    step_values(target, variant),
                )
                variant_match = axis_translate.match_at(variant_source_words)
                if (
                    variant_match is None
                    or variant_match["rule"] != lowering["name"]
                    or variant_match["target_word"] != variant_target_word
                ):
                    print(
                        f"FAIL generated division match {lowering['name']} "
                        f"{label}: {variant_match}"
                    )
                    failures += 1
                    continue

                values = {"lhs": lhs_value, "rhs": rhs_value}
                source_regs = {31: 0xA5A5_A5A5_A5A5_A5A5}
                target_regs = dict(source_regs)
                for variable in external_registers:
                    selector = variant[variable]
                    if selector != 31:
                        source_regs[selector] = values[variable]
                        target_regs[selector] = values[variable]
                source_state = {**declared_state, "nzcv": 0xF}
                target_state = dict(source_state)
                source_result = None
                for step, word in zip(
                    lowering["source_sequence"], variant_source_words
                ):
                    source_result = axis_exec.step(
                        word,
                        source_regs,
                        isa=step["isa"],
                        state=source_state,
                        pc=0x1000,
                    )
                target_result = axis_exec.step(
                    variant_target_word,
                    target_regs,
                    isa=target["isa"],
                    state=target_state,
                    pc=0x1000,
                )
                checks += 1
                if (
                    source_result is None
                    or target_result is None
                    or (
                        finals
                        and source_result["result"] != target_result["result"]
                    )
                    or observable_values(source_regs)
                    != observable_values(target_regs)
                    or source_state != target_state
                ):
                    print(
                        f"FAIL {lowering['name']} {label}: "
                        f"source={source_result} regs={source_regs} "
                        f"target={target_result} regs={target_regs}"
                    )
                    failures += 1

        # Conditional-select dataflow consumes architectural NZCV without
        # writing it. Exhaust the complete flags/condition truth table and
        # independently exercise XZR/WZR in both inputs and the destination.
        conditional_select = any(
            f"-{operation}-" in lowering["name"]
            for operation in ("csel", "csinc", "csinv", "csneg")
        )
        if conditional_select:
            width = widths["lhs"]
            mask = (1 << width) - 1
            conditional_cases = [
                (
                    f"nzcv={nzcv:x},cond={condition:x}",
                    {"condition": condition},
                    nzcv,
                )
                for nzcv in range(16)
                for condition in range(16)
            ]
            conditional_cases.extend(
                [
                    ("lhs=31", {"lhs": 31, "condition": 0}, 4),
                    ("rhs=31", {"rhs": 31, "condition": 0}, 0),
                    ("out=31", {"out": 31, "condition": 0}, 4),
                    (
                        "same-input-alias",
                        {"rhs": encoded_variables["lhs"], "condition": 0},
                        0,
                    ),
                    (
                        "zero-input-alias",
                        {"lhs": 31, "rhs": 31, "condition": 0},
                        0,
                    ),
                ]
            )
            for label, overrides, nzcv in conditional_cases:
                variant = dict(encoded_variables)
                variant.update(overrides)
                variant_source_words = [
                    encode(
                        lift_entries[(step["isa"], step["mnemonic"])],
                        step_values(step, variant),
                    )
                    for step in lowering["source_sequence"]
                ]
                variant_target_word = encode(
                    lift_entries[(target["isa"], target["mnemonic"])],
                    step_values(target, variant),
                )
                variant_match = axis_translate.match_at(variant_source_words)
                if (
                    variant_match is None
                    or variant_match["rule"] != lowering["name"]
                    or variant_match["target_word"] != variant_target_word
                ):
                    print(
                        f"FAIL generated conditional-select match "
                        f"{lowering['name']} {label}: {variant_match}"
                    )
                    failures += 1
                    continue

                values = {
                    "lhs": 0x0123_4567_89AB_CDEF & mask,
                    "rhs": 0xFEDC_BA98_7654_3210 & mask,
                }
                source_regs = {31: 0xA5A5_A5A5_A5A5_A5A5}
                target_regs = dict(source_regs)
                for variable in external_registers:
                    selector = variant[variable]
                    if selector != 31:
                        source_regs[selector] = values[variable]
                        target_regs[selector] = values[variable]
                source_state = {**declared_state, "nzcv": nzcv}
                target_state = dict(source_state)
                source_result = None
                for step, word in zip(
                    lowering["source_sequence"], variant_source_words
                ):
                    source_result = axis_exec.step(
                        word,
                        source_regs,
                        isa=step["isa"],
                        state=source_state,
                        pc=0x1000,
                    )
                target_result = axis_exec.step(
                    variant_target_word,
                    target_regs,
                    isa=target["isa"],
                    state=target_state,
                    pc=0x1000,
                )
                checks += 1
                if (
                    source_result is None
                    or target_result is None
                    or (
                        finals
                        and source_result["result"] != target_result["result"]
                    )
                    or observable_values(source_regs)
                    != observable_values(target_regs)
                    or source_state != target_state
                ):
                    print(
                        f"FAIL {lowering['name']} {label}: "
                        f"source={source_result} regs={source_regs} "
                        f"target={target_result} regs={target_regs}"
                    )
                    failures += 1

        unary_data = any(
            f"-{operation}-" in lowering["name"]
            for operation in ("rbit", "rev16", "rev32", "rev", "clz", "cls")
        )
        if unary_data:
            for zero_variable in ("value", "out"):
                variant = dict(encoded_variables)
                variant[zero_variable] = 31
                variant_source_words = [
                    encode(
                        lift_entries[(step["isa"], step["mnemonic"])],
                        step_values(step, variant),
                    )
                    for step in lowering["source_sequence"]
                ]
                variant_target_word = encode(
                    lift_entries[(target["isa"], target["mnemonic"])],
                    step_values(target, variant),
                )
                variant_match = axis_translate.match_at(variant_source_words)
                if (
                    variant_match is None
                    or variant_match["rule"] != lowering["name"]
                    or variant_match["target_word"] != variant_target_word
                ):
                    print(
                        f"FAIL generated unary match {lowering['name']} "
                        f"{zero_variable}=31: {variant_match}"
                    )
                    failures += 1
                    continue

                source_regs = {31: 0xFFFF_FFFF_FFFF_FFFF}
                target_regs = dict(source_regs)
                if variant["value"] != 31:
                    source_regs[variant["value"]] = 0x0123_4567_89AB_CDEF
                    target_regs[variant["value"]] = 0x0123_4567_89AB_CDEF
                source_state = {**declared_state, "nzcv": 0xF}
                target_state = dict(source_state)
                source_result = None
                for step, word in zip(
                    lowering["source_sequence"], variant_source_words
                ):
                    source_result = axis_exec.step(
                        word,
                        source_regs,
                        isa=step["isa"],
                        state=source_state,
                        pc=0x1000,
                    )
                target_result = axis_exec.step(
                    variant_target_word,
                    target_regs,
                    isa=target["isa"],
                    state=target_state,
                    pc=0x1000,
                )
                checks += 1
                if (
                    source_result is None
                    or target_result is None
                    or (
                        finals
                        and source_result["result"] != target_result["result"]
                    )
                    or observable_values(source_regs)
                    != observable_values(target_regs)
                    or source_state != target_state
                ):
                    print(
                        f"FAIL {lowering['name']} {zero_variable}=31: "
                        f"source={source_result} regs={source_regs} "
                        f"target={target_result} regs={target_regs}"
                    )
                    failures += 1

        # Extended-register arithmetic has two independent encoded semantic
        # selectors. Cover every UX*/SX* option and every legal shift rather
        # than holding them constant while only randomizing register values.
        if "extension" in encoded_variables and "amount" in encoded_variables:
            for extension in range(8):
                for amount in range(5):
                    variant = dict(encoded_variables)
                    variant["extension"] = extension
                    variant["amount"] = amount
                    variant_source_words = [
                        encode(
                            lift_entries[(step["isa"], step["mnemonic"])],
                            step_values(step, variant),
                        )
                        for step in lowering["source_sequence"]
                    ]
                    variant_target_word = encode(
                        lift_entries[(target["isa"], target["mnemonic"])],
                        step_values(target, variant),
                    )
                    variant_match = axis_translate.match_at(variant_source_words)
                    if (
                        variant_match is None
                        or variant_match["rule"] != lowering["name"]
                        or variant_match["target_word"] != variant_target_word
                    ):
                        print(
                            f"FAIL generated extension match {lowering['name']} "
                            f"option={extension} amount={amount}: {variant_match}"
                        )
                        failures += 1
                        continue

                    source_regs = {}
                    target_regs = {}
                    for variable in external_registers:
                        selector = variant[variable]
                        register = (
                            "sp"
                            if selector == 31 and variable in bridged_sp_variables
                            else selector
                        )
                        value = (
                            0x8000_0000_0000_0001
                            if variable == "lhs"
                            else 0xFEDC_BA98_7654_80FF
                        )
                        source_regs[register] = value
                        target_regs[register] = value
                    source_state = {**declared_state, "nzcv": 0xF}
                    target_state = dict(source_state)
                    source_result = None
                    for step, word in zip(
                        lowering["source_sequence"], variant_source_words
                    ):
                        source_result = axis_exec.step(
                            word,
                            source_regs,
                            isa=step["isa"],
                            state=source_state,
                            pc=0x1000,
                        )
                    target_result = axis_exec.step(
                        variant_target_word,
                        target_regs,
                        isa=target["isa"],
                        state=target_state,
                        pc=0x1000,
                    )
                    checks += 1
                    if (
                        source_result is None
                        or target_result is None
                        or (
                            finals
                            and source_result["result"] != target_result["result"]
                        )
                        or source_regs != target_regs
                        or source_state != target_state
                    ):
                        print(
                            f"FAIL {lowering['name']} option={extension} "
                            f"amount={amount}: source={source_result} "
                            f"regs={source_regs} state={source_state} "
                            f"target={target_result} regs={target_regs} "
                            f"state={target_state}"
                        )
                        failures += 1

        # Register-offset loads and stores admit UXTW, LSL, SXTW, and SXTX,
        # with the S bit selecting either an unscaled index or the access-size
        # shift. Exercise the complete legal selector space; values 0, 1, 4,
        # and 5 are reserved by AArch64 and are rejected separately by the
        # architectural-state harness.
        if "extend" in encoded_variables and "scaled" in encoded_variables:
            for extend in (2, 3, 6, 7):
                for scaled in (0, 1):
                    variant = dict(encoded_variables)
                    variant["extend"] = extend
                    variant["scaled"] = scaled
                    variant_source_words = [
                        encode(
                            lift_entries[(step["isa"], step["mnemonic"])],
                            step_values(step, variant),
                        )
                        for step in lowering["source_sequence"]
                    ]
                    variant_target_word = encode(
                        lift_entries[(target["isa"], target["mnemonic"])],
                        step_values(target, variant),
                    )
                    variant_match = axis_translate.match_at(variant_source_words)
                    if (
                        variant_match is None
                        or variant_match["rule"] != lowering["name"]
                        or variant_match["target_word"] != variant_target_word
                    ):
                        print(
                            f"FAIL generated register-offset match {lowering['name']} "
                            f"option={extend} s={scaled}: {variant_match}"
                        )
                        failures += 1
                        continue

                    source_regs = {}
                    target_regs = {}
                    for variable in external_registers:
                        selector = variant[variable]
                        register = (
                            "sp"
                            if selector == 31 and variable in bridged_sp_variables
                            else selector
                        )
                        value = (
                            0x1800
                            if variable == "base"
                            else 0xFFFF_FFFE_8000_0003
                            if variable == "index"
                            else 0x8123_4567_89AB_CDEF
                        )
                        source_regs[register] = value
                        target_regs[register] = value
                    source_state = {**declared_state, "nzcv": 0xF}
                    target_state = dict(source_state)
                    source_memory = Memory()
                    target_memory = Memory()
                    source_result = None
                    for step, word in zip(
                        lowering["source_sequence"], variant_source_words
                    ):
                        source_result = axis_exec.step(
                            word,
                            source_regs,
                            mem=source_memory,
                            isa=step["isa"],
                            state=source_state,
                            pc=0x1000,
                        )
                    target_result = axis_exec.step(
                        variant_target_word,
                        target_regs,
                        mem=target_memory,
                        isa=target["isa"],
                        state=target_state,
                        pc=0x1000,
                    )
                    checks += 1
                    if (
                        source_result is None
                        or target_result is None
                        or (
                            finals
                            and source_result["result"] != target_result["result"]
                        )
                        or source_regs != target_regs
                        or source_state != target_state
                        or source_memory.cells != target_memory.cells
                    ):
                        print(
                            f"FAIL {lowering['name']} option={extend} s={scaled}: "
                            f"source={source_result} regs={source_regs} "
                            f"target={target_result} regs={target_regs}"
                        )
                        failures += 1

        # Logical shifted-register operations admit all four AArch64 shift
        # modes, including ROR. Exercise each mode at zero, one, and the
        # width-specific maximum amount. Two cases also force an input
        # selector to XZR/WZR so the target's architectural zero-register
        # operand kinds are checked rather than merely proved structurally.
        logical_shift = any(
            f"-{operation}-" in lowering["name"]
            for operation in ("and", "orr", "eor", "ands", "tst")
        )
        if (
            logical_shift
            and "shift" in encoded_variables
            and "amount" in encoded_variables
        ):
            amounts = sorted({0, 1, (1 << widths["amount"]) - 1})
            for shift in range(4):
                for amount in amounts:
                    variant = dict(encoded_variables)
                    variant["shift"] = shift
                    variant["amount"] = amount
                    if shift == 0 and amount == 0 and "lhs" in variant:
                        variant["lhs"] = 31
                    if shift == 1 and amount == 1 and "rhs" in variant:
                        variant["rhs"] = 31
                    variant_source_words = [
                        encode(
                            lift_entries[(step["isa"], step["mnemonic"])],
                            step_values(step, variant),
                        )
                        for step in lowering["source_sequence"]
                    ]
                    variant_target_word = encode(
                        lift_entries[(target["isa"], target["mnemonic"])],
                        step_values(target, variant),
                    )
                    variant_match = axis_translate.match_at(variant_source_words)
                    if (
                        variant_match is None
                        or variant_match["rule"] != lowering["name"]
                        or variant_match["target_word"] != variant_target_word
                    ):
                        print(
                            f"FAIL generated logical-shift match {lowering['name']} "
                            f"shift={shift} amount={amount}: {variant_match}"
                        )
                        failures += 1
                        continue

                    source_regs = {}
                    target_regs = {}
                    for variable in external_registers:
                        selector = variant[variable]
                        value = (
                            0x8000_0000_0000_0001
                            if variable == "lhs"
                            else 0xFEDC_BA98_7654_80FF
                        )
                        source_regs[selector] = value
                        target_regs[selector] = value
                    source_state = {**declared_state, "nzcv": 0xF}
                    target_state = dict(source_state)
                    source_result = None
                    for step, word in zip(
                        lowering["source_sequence"], variant_source_words
                    ):
                        source_result = axis_exec.step(
                            word,
                            source_regs,
                            isa=step["isa"],
                            state=source_state,
                            pc=0x1000,
                        )
                    target_result = axis_exec.step(
                        variant_target_word,
                        target_regs,
                        isa=target["isa"],
                        state=target_state,
                        pc=0x1000,
                    )
                    checks += 1
                    if (
                        source_result is None
                        or target_result is None
                        or (
                            finals
                            and source_result["result"] != target_result["result"]
                        )
                        or source_regs != target_regs
                        or source_state != target_state
                    ):
                        print(
                            f"FAIL {lowering['name']} shift={shift} amount={amount}: "
                            f"source={source_result} regs={source_regs} "
                            f"state={source_state} target={target_result} "
                            f"regs={target_regs} state={target_state}"
                        )
                        failures += 1

        # Variable-register shifts mask the count modulo the data width.
        # Pin the wrap boundaries rather than relying on random values, and
        # execute both value/count selector-31 cases to prove XZR/WZR reads.
        variable_shift = any(
            f"-{operation}-" in lowering["name"]
            for operation in ("lslv", "lsrv", "asrv", "rorv")
        )
        if (
            variable_shift
            and "value" in encoded_variables
            and "amount" in encoded_variables
        ):
            data_width = widths["value"]
            cases = [
                ({}, amount)
                for amount in (
                    0,
                    1,
                    data_width - 1,
                    data_width,
                    data_width + 1,
                    2 * data_width - 1,
                    (1 << data_width) - 1,
                )
            ]
            cases.extend(
                [
                    ({"value": 31}, 1),
                    ({"amount": 31}, data_width - 1),
                ]
            )
            for selector_overrides, amount_value in cases:
                variant = dict(encoded_variables)
                variant.update(selector_overrides)
                variant_source_words = [
                    encode(
                        lift_entries[(step["isa"], step["mnemonic"])],
                        step_values(step, variant),
                    )
                    for step in lowering["source_sequence"]
                ]
                variant_target_word = encode(
                    lift_entries[(target["isa"], target["mnemonic"])],
                    step_values(target, variant),
                )
                variant_match = axis_translate.match_at(variant_source_words)
                if (
                    variant_match is None
                    or variant_match["rule"] != lowering["name"]
                    or variant_match["target_word"] != variant_target_word
                ):
                    print(
                        f"FAIL generated variable-shift match {lowering['name']} "
                        f"selectors={selector_overrides} amount={amount_value}: "
                        f"{variant_match}"
                    )
                    failures += 1
                    continue

                source_regs = {}
                target_regs = {}
                for variable in external_registers:
                    selector = variant[variable]
                    value = (
                        amount_value
                        if variable == "amount"
                        else (
                            0x8000_0000_0000_0001
                            if data_width == 64
                            else 0x8000_0001
                        )
                    )
                    source_regs[selector] = value
                    target_regs[selector] = value
                source_state = {**declared_state, "nzcv": 0xF}
                target_state = dict(source_state)
                source_result = None
                for step, word in zip(
                    lowering["source_sequence"], variant_source_words
                ):
                    source_result = axis_exec.step(
                        word,
                        source_regs,
                        isa=step["isa"],
                        state=source_state,
                        pc=0x1000,
                    )
                target_result = axis_exec.step(
                    variant_target_word,
                    target_regs,
                    isa=target["isa"],
                    state=target_state,
                    pc=0x1000,
                )
                checks += 1
                if (
                    source_result is None
                    or target_result is None
                    or (
                        finals
                        and source_result["result"] != target_result["result"]
                    )
                    or source_regs != target_regs
                    or source_state != target_state
                ):
                    print(
                        f"FAIL {lowering['name']} selectors={selector_overrides} "
                        f"amount={amount_value}: source={source_result} "
                        f"regs={source_regs} target={target_result} "
                        f"regs={target_regs}"
                    )
                    failures += 1

        # Move-wide operations select one of four 16-bit lanes in a 64-bit
        # destination -- but only two in a 32-bit one, where the architecture
        # leaves the high bit of the lane selector unallocated. So the lanes
        # come from the lowering's own `requires` rather than from the count
        # that was true of the first move-wide form described here.
        move_wide = any(
            f"-{operation}-" in lowering["name"]
            for operation in ("movn", "movz", "movk")
        )
        covered = 0
        if (
            move_wide
            and "halfword" in encoded_variables
            and "imm" in encoded_variables
        ):
            for halfword in range(4):
                for immediate in (0, 1, 0x8000, 0xFFFF):
                    variant = dict(encoded_variables)
                    variant["halfword"] = halfword
                    variant["imm"] = immediate
                    if not predicate_holds(lowering["requires"], variant):
                        continue
                    covered += 1
                    variant_source_words = [
                        encode(
                            lift_entries[(step["isa"], step["mnemonic"])],
                            step_values(step, variant),
                        )
                        for step in lowering["source_sequence"]
                    ]
                    variant_target_word = encode(
                        lift_entries[(target["isa"], target["mnemonic"])],
                        step_values(target, variant),
                    )
                    variant_match = axis_translate.match_at(variant_source_words)
                    if (
                        variant_match is None
                        or variant_match["rule"] != lowering["name"]
                        or variant_match["target_word"] != variant_target_word
                    ):
                        print(
                            f"FAIL generated move-wide match {lowering['name']} "
                            f"halfword={halfword} imm={immediate:#x}: "
                            f"{variant_match}"
                        )
                        failures += 1
                        continue

                    source_regs = {}
                    target_regs = {}
                    for variable in external_registers:
                        selector = variant[variable]
                        source_regs[selector] = 0x0123_4567_89AB_CDEF
                        target_regs[selector] = 0x0123_4567_89AB_CDEF
                    if "-movk-" in lowering["name"]:
                        selector = variant["out"]
                        source_regs[selector] = 0x0123_4567_89AB_CDEF
                        target_regs[selector] = 0x0123_4567_89AB_CDEF
                    source_state = {**declared_state, "nzcv": 0xF}
                    target_state = dict(source_state)
                    source_result = None
                    for step, word in zip(
                        lowering["source_sequence"], variant_source_words
                    ):
                        source_result = axis_exec.step(
                            word,
                            source_regs,
                            isa=step["isa"],
                            state=source_state,
                            pc=0x1000,
                        )
                    target_result = axis_exec.step(
                        variant_target_word,
                        target_regs,
                        isa=target["isa"],
                        state=target_state,
                        pc=0x1000,
                    )
                    checks += 1
                    if (
                        source_result is None
                        or target_result is None
                        or (
                            finals
                            and source_result["result"] != target_result["result"]
                        )
                        or source_regs != target_regs
                        or source_state != target_state
                    ):
                        print(
                            f"FAIL {lowering['name']} halfword={halfword} "
                            f"imm={immediate:#x}: source={source_result} "
                            f"regs={source_regs} target={target_result} "
                            f"regs={target_regs}"
                        )
                        failures += 1
            # A move-wide lowering whose every lane the `requires` excludes
            # would run no variant and pass by having tried nothing.
            if not covered:
                print(f"FAIL {lowering['name']} is move-wide and its requires "
                      f"excluded every lane, so no lane was checked")
                failures += 1

        # Bitfield operations use every immr/imms pair at their data width.
        # BFM is deliberately destructive, so seed both its old destination
        # and source while comparing the complete register file. W encodings
        # retain the architectural six-bit fields but reject values 32..63.
        bitfield = (
            "rotate" in encoded_variables
            and "size" in encoded_variables
            and any(
                f"-{operation}-" in lowering["name"]
                for operation in ("sbfm", "bfm", "ubfm")
            )
        )
        if bitfield:
            data_width = widths["value"]
            if data_width == 32:
                for variable in ("rotate", "size"):
                    invalid_variant = dict(encoded_variables)
                    invalid_variant[variable] = 32
                    invalid_words = [
                        encode(
                            lift_entries[(step["isa"], step["mnemonic"])],
                            step_values(step, invalid_variant),
                        )
                        for step in lowering["source_sequence"]
                    ]
                    invalid_match = axis_translate.match_at(invalid_words)
                    if (
                        invalid_match is not None
                        and invalid_match["rule"] == lowering["name"]
                    ):
                        print(
                            f"FAIL reserved W bitfield match {lowering['name']} "
                            f"{variable}=32: {invalid_match}"
                        )
                        failures += 1

            zero_register_tested = False
            for rotate in range(data_width):
                for size in range(data_width):
                    variant = dict(encoded_variables)
                    variant["rotate"] = rotate
                    variant["size"] = size
                    if not zero_register_tested:
                        variant["value"] = 31
                        zero_register_tested = True
                    variant_source_words = [
                        encode(
                            lift_entries[(step["isa"], step["mnemonic"])],
                            step_values(step, variant),
                        )
                        for step in lowering["source_sequence"]
                    ]
                    variant_target_word = encode(
                        lift_entries[(target["isa"], target["mnemonic"])],
                        step_values(target, variant),
                    )
                    variant_match = axis_translate.match_at(variant_source_words)
                    if (
                        variant_match is None
                        or variant_match["rule"] != lowering["name"]
                        or variant_match["target_word"] != variant_target_word
                    ):
                        print(
                            f"FAIL generated bitfield match {lowering['name']} "
                            f"rotate={rotate} size={size}: {variant_match}"
                        )
                        failures += 1
                        continue

                    source_regs = {}
                    target_regs = {}
                    for variable in external_registers:
                        selector = variant[variable]
                        value = (
                            0x0123_4567_89AB_CDEF
                            if variable == "out"
                            else 0xFEDC_BA98_7654_80FF
                        )
                        source_regs[selector] = value
                        target_regs[selector] = value
                    source_state = {**declared_state, "nzcv": 0xF}
                    target_state = dict(source_state)
                    source_result = None
                    for step, word in zip(
                        lowering["source_sequence"], variant_source_words
                    ):
                        source_result = axis_exec.step(
                            word,
                            source_regs,
                            isa=step["isa"],
                            state=source_state,
                            pc=0x1000,
                        )
                    target_result = axis_exec.step(
                        variant_target_word,
                        target_regs,
                        isa=target["isa"],
                        state=target_state,
                        pc=0x1000,
                    )
                    checks += 1
                    if (
                        source_result is None
                        or target_result is None
                        or (
                            finals
                            and source_result["result"] != target_result["result"]
                        )
                        or source_regs != target_regs
                        or source_state != target_state
                    ):
                        print(
                            f"FAIL {lowering['name']} rotate={rotate} "
                            f"size={size}: source={source_result} "
                            f"regs={source_regs} target={target_result} "
                            f"regs={target_regs}"
                        )
                        failures += 1

        # Logical immediates encode replicated element size and run length in
        # N:imms, then rotate that element. Enumerate every legal shape and
        # the rotation boundaries for each shape. Also prove that a reserved
        # all-ones S encoding cannot select the lowering.
        logical_immediate = (
            "rotate" in encoded_variables
            and "size" in encoded_variables
            and any(
                f"-{operation}-" in lowering["name"]
                for operation in ("and", "orr", "eor", "ands", "tst")
            )
            and lowering["name"].endswith("-imm")
        )
        if logical_immediate:
            invalid_variant = dict(encoded_variables)
            if "n" in invalid_variant:
                invalid_variant["n"] = 1
            invalid_variant["rotate"] = 0
            invalid_variant["size"] = 63
            invalid_words = [
                encode(
                    lift_entries[(step["isa"], step["mnemonic"])],
                    step_values(step, invalid_variant),
                )
                for step in lowering["source_sequence"]
            ]
            invalid_match = axis_translate.match_at(invalid_words)
            if (
                invalid_match is not None
                and invalid_match["rule"] == lowering["name"]
            ):
                print(
                    f"FAIL reserved logical-immediate match {lowering['name']}: "
                    f"{invalid_match}"
                )
                failures += 1

            n_values = range(2) if "n" in encoded_variables else (0,)
            zero_register_tested = False
            for n_value in n_values:
                for size in range(64):
                    encoded = ((n_value & 1) << 6) | ((~size) & 0x3F)
                    length = encoded.bit_length() - 1
                    if length < 1:
                        continue
                    levels = (1 << length) - 1
                    if (size & levels) == levels:
                        continue
                    for rotate in sorted({0, 1, levels, 63}):
                        variant = dict(encoded_variables)
                        if "n" in variant:
                            variant["n"] = n_value
                        variant["rotate"] = rotate
                        variant["size"] = size
                        if not zero_register_tested and "value" in variant:
                            variant["value"] = 31
                            zero_register_tested = True
                        variant_source_words = [
                            encode(
                                lift_entries[(step["isa"], step["mnemonic"])],
                                step_values(step, variant),
                            )
                            for step in lowering["source_sequence"]
                        ]
                        variant_target_word = encode(
                            lift_entries[(target["isa"], target["mnemonic"])],
                            step_values(target, variant),
                        )
                        variant_match = axis_translate.match_at(
                            variant_source_words
                        )
                        if (
                            variant_match is None
                            or variant_match["rule"] != lowering["name"]
                            or variant_match["target_word"] != variant_target_word
                        ):
                            print(
                                f"FAIL generated logical-immediate match "
                                f"{lowering['name']} n={n_value} rotate={rotate} "
                                f"size={size}: {variant_match}"
                            )
                            failures += 1
                            continue

                        source_regs = {}
                        target_regs = {}
                        for variable in external_registers:
                            selector = variant[variable]
                            source_regs[selector] = 0xA5A5_5A5A_F0F0_0F0F
                            target_regs[selector] = 0xA5A5_5A5A_F0F0_0F0F
                        source_state = {**declared_state, "nzcv": 0xF}
                        target_state = dict(source_state)
                        source_result = None
                        for step, word in zip(
                            lowering["source_sequence"], variant_source_words
                        ):
                            source_result = axis_exec.step(
                                word,
                                source_regs,
                                isa=step["isa"],
                                state=source_state,
                                pc=0x1000,
                            )
                        target_result = axis_exec.step(
                            variant_target_word,
                            target_regs,
                            isa=target["isa"],
                            state=target_state,
                            pc=0x1000,
                        )
                        checks += 1
                        if (
                            source_result is None
                            or target_result is None
                            or (
                                finals
                                and source_result["result"]
                                != target_result["result"]
                            )
                            or source_regs != target_regs
                            or source_state != target_state
                        ):
                            print(
                                f"FAIL {lowering['name']} n={n_value} "
                                f"rotate={rotate} size={size}: "
                                f"source={source_result} regs={source_regs} "
                                f"state={source_state} target={target_result} "
                                f"regs={target_regs} state={target_state}"
                            )
                            failures += 1

    print(
        f"{len(translation['explicit_lowerings'])} lowering(s), "
        f"{checks} execution checks, {failures} failures"
    )
    ok = bool(translation["explicit_lowerings"]) and failures == 0
    print("lowering sequence == target: PASS" if ok else "lowering sequence == target: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
