#!/usr/bin/env python3
"""Differential check: the generated Rust executor (axis_exec.rs) vs the golden model.

Emits axis_semantics.rs, axis_lift.rs, axis_exec.rs, golden_model.py, axis_lift.py,
and the encode fixtures from the same .axisl source, concatenates the three Rust
modules with a generated driver, compiles it with rustc, and for each fixture runs
`step(word, regs, mem, pc)` against a random register file / memory, requiring the
result, written register, memory, next_pc, and trap to match a reference computed
from the golden model on the fixture's ground-truth operand indices. The Rust
sibling of exec_c_check.py (binary -> execute), completing the exec trio.

Usage: tools/exec_rust_check.py <input.axisl>

Requires: cargo (from the AXIS repo root) and rustc on PATH.
"""

from __future__ import annotations

import argparse
import importlib
import json
import random
import re
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


class Mem:
    """Width-keyed memory model matching axis_exec's read/write ABI."""

    def __init__(self, init=None):
        self.store = dict(init or {})

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)



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

    if not shutil.which("rustc"):
        print("SKIP: rustc not found")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="axis_execr_"))
    sem_rs = workdir / "axis_semantics.rs"
    lift_rs = workdir / "axis_lift.rs"
    exec_rs = workdir / "axis_exec.rs"
    emit(args.axis_file, "emit-semantics-rust", sem_rs)
    emit(args.axis_file, "emit-lift-rust", lift_rs)
    emit(args.axis_file, "emit-exec-rust", exec_rs)
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)

    sys.path.insert(0, str(workdir))
    golden = importlib.import_module("golden_model")
    axis_lift = importlib.import_module("axis_lift")
    # Sized by the artifact, not by 32: a second register file needs more slots.
    FILE_SLOTS = axis_lift.REGISTER_FILE_SLOTS

    # A backend may decline an instruction with the reason in the file — Rust
    # declines directed rounding, because std cannot change the floating-point
    # environment (docs/simd_fp_design.md 8.4). Driving one anyway compares an
    # executor against a function that was never emitted.
    semantics_text = sem_rs.read_text()
    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])
    random.seed(0xC0DE)
    cases = []
    declined = 0
    REG_COUNT = FILE_SLOTS
    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = axis_lift.decode(word, test.get("isa"))
        if entry is None or (entry["semantics"] is None and entry.get("effects") is None):
            continue
        if entry["semantics"] is not None and (
                f"fn axis_eval_{re.sub(r'[^0-9A-Za-z]', '_', entry['mnemonic']).lower()}("
                not in semantics_text):
            declined += 1
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
            # Named architectural-state reads belong to the wide executor ABI.
            # The compact ABI has no named-state input, so state-touching
            # instructions execute through the separately checked wide ABI. The
            # names come from the generated lifter: this test read "nzcv"
            # literally, which covered AArch64's flags and missed RISC-V's
            # reservation state entirely.
            touched = json.dumps(effects)
            if any(name in touched for name, _ in axis_lift.STATE_SLOTS):
                continue
            # A register the description names rather than decodes is the
            # same story: the compact effect lowering goes through the pure
            # IR, which has no node for that read, so this ABI declines the
            # instruction and the wide check runs it.
            if entry.get("reads_registers"):
                continue
            has_guard = any("guard" in eff for eff in effects)
            for trial in range(2 if has_guard else 1):
                regs = [0] * FILE_SLOTS
                shared = random.getrandbits(32)
                for name, k in kind.items():
                    if axis_lift.is_register_operand(k):
                        slot = register_slot(k, fx[name], axis_lift)
                        regs[slot] = (shared if (trial == 0 and has_guard)
                                      else random.getrandbits(32))
                cases.append(_effect_case(test, effects, fx, kind, regs, REG_COUNT, golden,
                                          Mem, axis_lift, trial))
            continue

        regs = [0] * FILE_SLOTS
        for name, k in kind.items():
            if axis_lift.is_register_operand(k):
                regs[register_slot(k, fx[name], axis_lift)] = random.getrandbits(32)
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
        init = "[" + ",".join(f"{v}u32" for v in regs) + "]"
        dest_check = (
            f'        if regs[{dest}] != {expected}u32 {{ println!("FAIL {test["mnemonic"]} dest"); failures += 1; }}\n'
            if dest is not None else ""
        )
        cases.append(
            f'    {{ let mut regs: [u32; {REG_COUNT}] = {init};\n'
            f'      let mut mem = DriverMem::default();\n'
            f'      let res = step({word}u32, &mut regs, &mut mem, 0u32);\n'
            f'      checks += 1;\n'
            f'      if !res.ok || res.result != Some({expected}u32) {{ println!("FAIL {test["mnemonic"]} result"); failures += 1; }}\n'
            f'{dest_check}    }}\n'
        )

    if declined:
        print(f"{declined} instruction(s) skipped: no Rust semantics function emitted")
    if not cases:
        # ⚠️ Say WHICH nothing. "No executable fixtures" reads as a corpus with
        # no fixtures, and RV64I has 1028 of them -- every one wider than this
        # driver, whose ABI is 32-bit. A skip that names the wrong cause is
        # worse than a skip, because it sends the next reader looking for
        # missing fixtures instead of the gate that should have been registered.
        wide = sum(1 for entry in axis_lift.AXIS_LIFT_TABLE
                   if entry.get("state_width", 32) > 32
                   or any(op.get("width", 32) > 32 for op in entry["operands"]))
        if wide:
            print(f"SKIP: this driver's ABI is 32-bit and {wide} instruction(s) "
                  f"are wider; `exec_wide_check.py --lang rust` is the gate for "
                  f"those")
        else:
            print("SKIP: no executable fixtures")
        return 0

    driver = (
        sem_rs.read_text()
        + "\n"
        + lift_rs.read_text()
        + "\n"
        + exec_rs.read_text()
        + "\n"
        + _driver_prelude()
        + "fn main() {\n    let mut checks = 0i64;\n    let mut failures = 0i64;\n"
        + "".join(cases)
        + '    println!("{} checks, {} failures", checks, failures);\n'
        "    std::process::exit(if failures == 0 { 0 } else { 1 });\n}\n"
    )
    driver_path = workdir / "driver.rs"
    driver_path.write_text(driver)
    binary = workdir / "driver"
    subprocess.run(
        ["rustc", "--edition", "2021", "-A", "warnings", "--cfg", "axis_impl_stubs", "-o", str(binary), str(driver_path)],
        check=True,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    print(result.stdout.strip())
    ok = result.returncode == 0
    print("Rust exec == golden: PASS" if ok else "Rust exec == golden: FAIL")
    return result.returncode


def _driver_prelude() -> str:
    """A simple cell-list Memory impl for the driver."""
    return (
        "#[derive(Default)]\n"
        "struct DriverMem { cells: Vec<(u32, u32, u32)> }\n"
        "impl Memory for DriverMem {\n"
        "    fn read(&mut self, addr: u32, width: u32) -> u32 {\n"
        "        for &(a, w, v) in &self.cells { if a == addr && w == width { return v; } }\n"
        "        0\n    }\n"
        "    fn write(&mut self, addr: u32, value: u32, width: u32) {\n"
        "        let masked = if width >= 32 { value } else { value & ((1u32 << width) - 1) };\n"
        "        for c in self.cells.iter_mut() { if c.0 == addr && c.1 == width { c.2 = masked; return; } }\n"
        "        self.cells.push((addr, width, masked));\n    }\n"
        "}\n\n"
    )


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


def _effect_case(test, effects, fx, kind, regs, reg_count, golden, Mem, lift,
                 trial=0):
    """Compute the golden reference (registers, memory, next_pc, trap) for one
    effect fixture and emit a Rust case that runs step and asserts the full
    architectural delta. Registers/memory cover E2, next_pc E3, trap E4."""
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
    checks = ""
    for idx, value in reg_checks:
        checks += f'      if regs[{idx}] != {value}u32 {{ println!("FAIL {mn} reg"); failures += 1; }}\n'
    for addr, width, value in mem_checks:
        checks += f'      if mem.read({addr}u32, {width}u32) != {value}u32 {{ println!("FAIL {mn} mem"); failures += 1; }}\n'
    if state_write is not None:
        name, value = state_write
        checks += f'      if res.state_write != Some(("{name}", {value}u32)) {{ println!("FAIL {mn} state"); failures += 1; }}\n'
    checks += f'      if res.next_pc != {ref_next_pc & 0xffffffff}u32 {{ println!("FAIL {mn} next_pc"); failures += 1; }}\n'
    if ref_trap is None:
        checks += f'      if res.trap.is_some() {{ println!("FAIL {mn} spurious trap"); failures += 1; }}\n'
    else:
        checks += f'      if res.trap != Some("{ref_trap}") {{ println!("FAIL {mn} trap"); failures += 1; }}\n'

    init = "[" + ",".join(f"{v}u32" for v in regs) + "]"
    seed_c = ", ".join(f"({a}u32, {w}u32, {v}u32)" for (a, w), v in seed.items())
    return (
        f'    {{ let mut regs: [u32; {reg_count}] = {init};\n'
        f'      let mut mem = DriverMem {{ cells: vec![{seed_c}] }};\n'
        f'      let res = step({word}u32, &mut regs, &mut mem, {pc}u32);\n'
        f'      checks += 1;\n{checks}    }}\n'
    )


if __name__ == "__main__":
    sys.exit(main())
