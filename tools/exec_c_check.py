#!/usr/bin/env python3
"""Differential check: the generated C executor (axis_exec.h) vs the golden model.

Emits axis_exec.h, axis_lift.h, axis_semantics.h, golden_model.py, and the
encode fixtures from the same .axisl source, compiles the C executor with a
generated driver, and for each fixture runs axis_exec_step against a random
register file, requiring the result and the written register to match a
reference computed from the golden model on the fixture's ground-truth operand
indices. This is the compiled sibling of exec_vs_golden.py (binary -> execute).

Usage: tools/exec_c_check.py <input.axisl>

Requires: cargo (from the AXIS repo root) and cc on PATH.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import shutil
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


def load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module



def register_slot(kind, index, lift):
    """Where this operand's register lives in the flat file.

    A class carries an offset, which is how an architecture with more than one
    register file is modelled: RISC-V's f5 is slot 37 while x5 is slot 5. A
    harness that ignores it seeds one register and reads another, which shows up
    as every floating-point operand reading zero.
    """
    return lift.register_slot(kind, index)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    if not shutil.which("cc"):
        print("SKIP: cc not found")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="axis_execc_"))
    emit(args.axis_file, "emit-exec-c", workdir / "axis_exec.h")
    emit(args.axis_file, "emit-lift-c", workdir / "axis_lift.h")
    emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)

    golden = load(workdir / "golden_model.py")
    sys.path.insert(0, str(workdir))
    axis_lift = importlib.import_module("axis_lift")
    # Sized by the artifact, not by 32: a second register file needs more slots.
    FILE_SLOTS = axis_lift.REGISTER_FILE_SLOTS

    class Mem:
        def __init__(self, init=None):
            self.store = dict(init or {})

        def read(self, addr, width):
            return self.store.get((addr, width), 0)

        def write(self, addr, value, width):
            self.store[(addr, width)] = value & ((1 << width) - 1)

    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])
    random.seed(0xC0DE)
    cases = []
    REG_COUNT = FILE_SLOTS
    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = axis_lift.decode(word, test.get("isa"))
        if entry is None or (entry["semantics"] is None and entry.get("effects") is None):
            continue
        fx = {o["name"]: o["value"] for o in test["operands"]}
        kind = {op["name"]: op["kind"] for op in entry["operands"]}
        role = {op["name"]: op["role"] for op in entry["operands"]}
        # The compact ABI is 32-bit. An instruction whose operands are wider
        # belongs to the separately checked wide executor -- which is true of
        # AArch64, of RV64, and of RV32's D extension, whose ISA word is 32 but
        # whose float operands are 64. The operand widths come from the artifact
        # rather than being inferred from the ISA.
        if entry.get("state_width", 32) > 32 or any(
                op.get("width", 32) > 32 for op in entry["operands"]):
            continue

        effects = entry.get("effects")
        if effects is not None:
            # The compact executor ABI has no named-state input, so an
            # instruction that reads or writes architectural state executes
            # through the separately checked wide ABI. The names come from the
            # generated lifter rather than being spelled out: this test read
            # "nzcv" literally, which covered AArch64's flags and missed
            # RISC-V's reservation state entirely.
            touched = json.dumps(effects)
            if any(name in touched for name, _ in axis_lift.STATE_SLOTS):
                continue
            # A register the description names rather than decodes is the
            # same story: the compact effect lowering goes through the pure
            # IR, which has no node for that read, so this ABI declines the
            # instruction and the wide check runs it.
            if entry.get("reads_registers"):
                continue
            # Two trials when guarded so both directions run: trial 0 forces all
            # source registers equal (guard taken), trial 1 random.
            has_guard = any("guard" in eff for eff in effects)
            for trial in range(2 if has_guard else 1):
                regs = [0] * FILE_SLOTS
                shared = random.getrandbits(32)
                for name, k in kind.items():
                    if axis_lift.is_register_operand(k):
                        slot = register_slot(k, fx[name], axis_lift)
                        regs[slot] = (shared if (trial == 0 and has_guard)
                                      else random.getrandbits(32))
                cases.append(_effect_case(test, entry, effects, fx, kind, regs,
                                          REG_COUNT, golden, Mem, axis_lift,
                                          trial))
            continue

        regs = [0] * FILE_SLOTS
        for name, k in kind.items():
            if axis_lift.is_register_operand(k):
                regs[register_slot(k, fx[name], axis_lift)] = random.getrandbits(32)
        init = "{" + ",".join(f"{v}u" for v in regs) + "}"
        inputs = []
        for op in entry["operands"]:
            if role[op["name"]] != "in":
                continue
            idx = fx[op["name"]]
            k = kind[op["name"]]
            inputs.append(regs[register_slot(k, idx, axis_lift)]
                          if axis_lift.is_register_operand(k) else idx)
        expected = golden.evaluate(entry["mnemonic"], *inputs)
        dest = next((register_slot(kind[op["name"]], fx[op["name"]], axis_lift)
                     for op in entry["operands"]
                     if role[op["name"]] == "out"
                     and axis_lift.is_register_operand(kind[op["name"]])), None)
        cases.append(
            f'  {{ uint32_t regs[] = {init};\n'
            f'    axis_exec_result res = axis_exec_step({word}u, regs, {REG_COUNT}, NULL, 0u);\n'
            f'    checks++;\n'
            f'    if (!res.ok || res.result != {expected}u) {{ printf("FAIL {test["mnemonic"]} result 0x%08x want 0x{expected:08x}\\n", res.ok?res.result:0u); failures++; }}\n'
            + (f'    else if (regs[{dest}] != {expected}u) {{ printf("FAIL {test["mnemonic"]} dest\\n"); failures++; }}\n' if dest is not None else "")
            + "  }\n"
        )

    if not cases:
        print("SKIP: no executable fixtures")
        return 0

    main_c = workdir / "driver.c"
    main_c.write_text(
        '#include <stdio.h>\n#include <stdint.h>\n#include "axis_exec.h"\n\n'
        "typedef struct { uint32_t addr, width, value; } cell;\n"
        "typedef struct { cell cells[64]; int count; } memctx;\n"
        "static uint32_t mem_read(void *c, uint32_t addr, uint32_t width) {\n"
        "  memctx *m = (memctx *)c;\n"
        "  for (int i = 0; i < m->count; ++i)\n"
        "    if (m->cells[i].addr == addr && m->cells[i].width == width) return m->cells[i].value;\n"
        "  return 0u;\n}\n"
        "static void mem_write(void *c, uint32_t addr, uint32_t value, uint32_t width) {\n"
        "  memctx *m = (memctx *)c;\n"
        "  uint32_t masked = width >= 32 ? value : (value & ((1u << width) - 1u));\n"
        "  for (int i = 0; i < m->count; ++i)\n"
        "    if (m->cells[i].addr == addr && m->cells[i].width == width) { m->cells[i].value = masked; return; }\n"
        "  m->cells[m->count].addr = addr; m->cells[m->count].width = width;\n"
        "  m->cells[m->count].value = masked; m->count++;\n}\n\n"
        "int main(void) {\n  int checks = 0, failures = 0;\n"
        "  (void)mem_read; (void)mem_write;\n"
        + "".join(cases)
        + '  printf("%d executed, %d failures\\n", checks, failures);\n'
        "  return failures == 0 ? 0 : 1;\n}\n"
    )
    binary = workdir / "driver"
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-I", str(workdir),
         "-o", str(binary), str(main_c), "-lm"],
        check=True,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    print(result.stdout.strip())
    ok = result.returncode == 0
    print("C exec == golden: PASS" if ok else "C exec == golden: FAIL")
    return result.returncode


def _peeled_value(eff, env, golden):
    """An effect's value, peeling a load rather than evaluating one.

    `_eval_axis_expr` evaluates a whole expression at one width, so asking it
    for a store's `(load i8 unsigned (add i32 rs 0))` at the 8-bit value width
    truncates the *address* to 8 bits and reads the wrong cell. It returned zero
    for every block copy, and since unwritten memory also reads zero the check
    could not tell a working copy from an instruction that did nothing.
    """
    node = golden._parse(golden._tokenize(eff["value"]))
    if isinstance(node, list) and node and node[0] in ("load", "atomic_load"):
        access = int(node[1][1:])
        signed = node[2] == "signed"
        addr = golden._eval(node[-1], env, eff["load_address_width"])
        raw = env["__mem__"](addr, access)
        if signed and access and raw >> (access - 1):
            raw -= 1 << access
        return raw & ((1 << eff["eval_width"]) - 1)
    return golden._eval_axis_expr(eff["value"], env, eff["eval_width"])


def _effect_case(test, entry, effects, fx, kind, regs, reg_count, golden, Mem, lift,
                 trial=0):
    """Compute the golden reference (registers, memory, next_pc, trap) for one
    effect fixture and emit a C case that runs axis_exec_step and asserts the
    full architectural delta. Registers/memory cover E2, next_pc E3, trap E4."""
    word = int(test["encoded"], 16)
    # The counter is drawn from the top of the space on the trial where the
    # fall-through happens -- a guarded fixture spends trial 0 on the taken
    # branch, an unguarded one has only trial 0. The compact ABI wraps by being
    # 32 bits wide, so what this exercises is that it still does.
    guarded = any("guard" in effect for effect in effects)
    pc = (0xFFFFFFFC if trial == 1 or not guarded
          else random.getrandbits(30) * 4)
    env = {name: (regs[register_slot(k, fx[name], lift)]
                  if lift.is_register_operand(k) else fx[name])
           for name, k in kind.items()}
    env["pc"] = pc

    # Seed backing memory for any load-as-set so the read is deterministic.
    # Every effect, not only a `set`: a block copy's load lives inside a
    # *store*, and seeding only set-values leaves the reference expecting
    # to store zeros into memory that already reads zero.
    seed = {}
    for eff in effects:
        # Not every effect has a value: a trap carries a cause and a barrier
        # an option. The `kind == "set"` guard this replaced implied one.
        if "value" not in eff:
            continue
        node = golden._parse(golden._tokenize(eff["value"]))
        if isinstance(node, list) and node and node[0] in ("load", "atomic_load"):
            access = int(node[1][1:])
            addr = golden._eval(node[-1], env, eff["load_address_width"])
            seed[(addr, access)] = random.getrandbits(access)

    ref_mem = Mem(seed)
    ref_env = dict(env)
    ref_env["__mem__"] = ref_mem.read
    ref_next_pc = pc + 4
    ref_trap = None
    state_write = None
    reg_checks = []
    mem_checks = []
    for eff in effects:
        if "guard" in eff and not golden._eval_axis_expr(
            eff["guard"], ref_env, eff["guard_width"],
            eff.get("guard_load_address_width")
        ):
            continue
        if eff["kind"] == "trap":
            ref_trap = eff["cause"]
            break
        if eff["kind"] == "set":
            value = golden._eval_axis_expr(eff["value"], ref_env, eff["eval_width"])
            # The slot includes the class offset, so a float destination is
            # checked where it is actually written rather than at the integer
            # register of the same number.
            reg_checks.append((register_slot(kind[eff["dest"]], fx[eff["dest"]], lift), value))
            # A later effect reads what this one wrote: RISC-V's atomic
            # read-modify-writes store a function of the value they just loaded
            # into rd. The executors evaluate effects in order against a mutable
            # register file, so the reference has to as well -- without this it
            # would be comparing an implementation against a model of a
            # different instruction.
            ref_env[eff["dest"]] = value
        elif eff["kind"] == "setstate":
            value = golden._eval_axis_expr(eff["value"], ref_env, eff["eval_width"])
            state_write = (
                eff["state"],
                value & ((1 << eff["width"]) - 1),
            )
        elif eff["kind"] == "store":
            addr = golden._eval_axis_expr(eff["addr"], ref_env, eff["addr_width"])
            value = _peeled_value(eff, ref_env, golden)
            ref_mem.write(addr, value, eff["width"])
            mem_checks.append((addr, eff["width"], value & ((1 << eff["width"]) - 1)))
        elif eff["kind"] == "setpc":
            ref_next_pc = golden._eval_axis_expr(eff["value"], ref_env, 32)

    mn = test["mnemonic"]
    checks_c = ""
    for idx, value in reg_checks:
        checks_c += f'    if (regs[{idx}] != {value}u) {{ printf("FAIL {mn} reg\\n"); failures++; }}\n'
    for addr, width, value in mem_checks:
        checks_c += f'    if (mem_read(&ctx, {addr}u, {width}u) != {value}u) {{ printf("FAIL {mn} mem\\n"); failures++; }}\n'
    if state_write is not None:
        name, value = state_write
        checks_c += f'    if (res.state_name == NULL || strcmp(res.state_name, "{name}") != 0 || res.state_value != {value}u) {{ printf("FAIL {mn} state\\n"); failures++; }}\n'
    checks_c += f'    if (res.next_pc != {ref_next_pc & 0xffffffff}u) {{ printf("FAIL {mn} next_pc\\n"); failures++; }}\n'
    if ref_trap is None:
        checks_c += f'    if (res.trapped) {{ printf("FAIL {mn} spurious trap\\n"); failures++; }}\n'
    else:
        checks_c += (
            f'    if (!res.trapped || strcmp(res.trap_cause, "{ref_trap}") != 0) {{ printf("FAIL {mn} trap\\n"); failures++; }}\n'
        )

    init = "{" + ",".join(f"{v}u" for v in regs) + "}"
    seed_c = ",".join(f"{{{a}u,{w}u,{v}u}}" for (a, w), v in seed.items())
    return (
        f'  {{ uint32_t regs[] = {init};\n'
        f'    memctx ctx = {{ {{{seed_c}}}, {len(seed)} }};\n'
        f'    axis_mem M = {{ mem_read, mem_write, &ctx }};\n'
        f'    axis_exec_result res = axis_exec_step({word}u, regs, {reg_count}, &M, {pc}u);\n'
        f'    checks++;\n{checks_c}  }}\n'
    )


if __name__ == "__main__":
    sys.exit(main())
