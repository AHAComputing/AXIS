#!/usr/bin/env python3
"""Differential check: lift+execute (axis_exec) vs the golden model.

Emits `golden_model.py`, `axis_lift.py`, `axis_exec.py`, and the encode
fixtures from the same .axisl source. For each fixture it builds a random
register file, runs `axis_exec.step(word, regs)` (decode -> bind operands ->
evaluate -> write destination), and checks the result and the written register
against a reference computed directly from the golden model using the
fixture's ground-truth operand indices. This proves the decode/bind/dispatch
plumbing is consistent end to end (binary -> execute); it does not re-test the
semantics themselves (c/smt/llvm_vs_golden already do).

Usage: tools/exec_vs_golden.py <input.axisl>

Requires: cargo (run from the AXIS repo root).
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


def register_slot(kind: str, index: int, lift) -> int:
    """Where this operand's register lives in the flat file.

    A class carries an offset, which is how an architecture with more than one
    register file is modelled: RISC-V's f5 is slot 37 while x5 is slot 5. A
    reference that ignores the offset seeds and reads a different register than
    the executor writes.
    """
    return lift.register_slot(kind, index)


def register_view(kind: str, index: int, regs: dict, lift) -> int:
    """The value this operand *names*, which is not always the whole slot.

    A windowed class -- x86's `AL` and `AH`, a 32-bit slice of a 128-bit
    vector -- names a bit range inside the register, and a write to a
    preserving one leaves the rest alone. Reading the raw slot and handing it
    to the golden model compares two different things.

    This check did exactly that, and passed anyway, because every corpus that
    used a windowed class declared its operands at the machine word instead of
    the window's width. Two errors that cancelled: the descriptions were wrong
    in the way that made this right. Narrowing the operands to what they
    actually name broke it, which is the correct outcome and how both were
    found.
    """
    _zero, _alias, view_width, _offset, view_offset, _preserve, limbs = (
        lift.REGISTER_CLASSES[kind][:7])
    slot = lift.register_slot(kind, index)
    if view_width is None:
        # ⚠️ Every limb, not the first. A class with no view names the WHOLE
        # register, and a register may be several slots: reading one returned
        # the low 64 bits of a 128-bit value and compared it against the golden
        # model's whole answer. It agreed for as long as the only wide corpora
        # declared their operands in a one-limb class -- two errors cancelling,
        # again -- and broke the moment those descriptions named a class that
        # could hold what they had said they held.
        whole = 0
        for limb in range(max(limbs, 1)):
            whole |= regs.get(slot + limb, 0) << (64 * limb)
        return whole
    # A view may cross a limb boundary, so the register is read as one number
    # and the window taken out of it.
    whole = 0
    for limb in range(limbs):
        whole |= regs.get(slot + limb, 0) << (64 * limb)
    return (whole >> view_offset) & ((1 << view_width) - 1)


def is_register_kind(kind: str, lift) -> bool:
    """Whether this operand kind names a register, per the generated lifter.

    `lift` is passed in rather than read from a module global because
    `tools/jit_c.py` and `tools/jit_llvm.py` reuse these helpers from another
    process, where no global would be set.
    """
    return lift.is_register_operand(kind)


def register_width(kind: str) -> int:
    return 64 if "64" in kind else 32


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


class Mem:
    """A width-keyed memory model matching axis_exec's read/write ABI."""

    def __init__(self, init=None):
        self.store = dict(init or {})

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_exec_"))
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)

    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    axis_lift = importlib.import_module("axis_lift")
    golden = importlib.import_module("golden_model")

    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])
    random.seed(0xE0EC)
    executed = 0
    skipped = 0
    failures = 0
    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = axis_lift.decode(word, test.get("isa"))
        if entry is None or (entry["semantics"] is None and entry.get("effects") is None):
            skipped += 1
            continue
        fx = {o["name"]: o["value"] for o in test["operands"]}
        kind = {op["name"]: op["kind"] for op in entry["operands"]}
        role = {op["name"]: op["role"] for op in entry["operands"]}

        # Random contents for each distinct source register index.
        regs = {}
        for name, k in kind.items():
            if not is_register_kind(k, axis_lift):
                continue
            slot = register_slot(k, fx[name], axis_lift)
            if slot not in regs:
                regs[slot] = random.getrandbits(register_width(k))
        # And for each register the behavior names itself. Without this the
        # executor and the reference both read an unseeded slot, agree on zero,
        # and the read is never executed by either -- a green gate for a value
        # nothing produced.
        for read in entry.get("reads_registers", []):
            slot = register_slot(read["kind"], read["index"], axis_lift)
            if slot not in regs:
                regs[slot] = random.getrandbits(register_width(read["kind"]))

        effects = entry.get("effects")
        if effects is not None:
            # Two trials so equality guards exercise both directions: trial 0
            # forces all source registers equal (taken), trial 1 is random.
            has_guard = any("guard" in eff for eff in effects)
            for trial in range(2 if has_guard else 1):
                if trial == 0 and has_guard:
                    shared = random.getrandbits(32)
                    regs = {idx: shared for idx in regs}
                else:
                    regs = {idx: random.getrandbits(32) for idx in regs}
                # Every state slot the ISA declares, at its declared width.
                # This was a list of five names -- nzcv and the three exclusive
                # slots and sp -- so a description with a sixth had it unbound,
                # and the golden evaluator raised `unknown AXIS semantic atom`
                # rather than declining. A corpus whose instructions read state
                # this file had not heard of could not be gated at all, which
                # is why GRV's `exec_mask` had no gate.
                state = {}
                effects_text = json.dumps(effects)
                for name, width in axis_lift.STATE_SLOTS:
                    if name in effects_text:
                        state[name] = random.getrandbits(width) & ((1 << width) - 1)
                # An exclusive reservation is compared against an address and a
                # size, so uniform bits would almost never match. These stay
                # seeded to plausible values on top of the declared width.
                if "exclusive_size" in state:
                    state["exclusive_size"] = random.choice((4, 8, 16))
                if any(
                    k.endswith("sp") and fx[name] == 31
                    for name, k in kind.items()
                ):
                    state["sp"] = random.getrandbits(64)
                if _run_effect_trial(
                    test,
                    entry,
                    effects,
                    fx,
                    kind,
                    regs,
                    state,
                    golden,
                    axis_exec,
                    Mem,
                    axis_lift,
                    trial,
                ):
                    failures += 1
                executed += 1
            continue

        # Reference: read inputs from the fixture's ground-truth indices.
        inputs = []
        for op in entry["operands"]:
            if role[op["name"]] not in ("in", "inout"):
                continue
            idx = fx[op["name"]]
            k = kind[op["name"]]
            inputs.append(register_view(k, idx, regs, axis_lift)
                          if is_register_kind(k, axis_lift) else idx)
        expected = golden.evaluate(entry["mnemonic"], *inputs)
        dest = next((register_slot(kind[op["name"]], fx[op["name"]], axis_lift)
                     for op in entry["operands"]
                     if role[op["name"]] in ("out", "inout")
                     and is_register_kind(kind[op["name"]], axis_lift)), None)
        regs_after = dict(regs)
        out = axis_exec.step(word, regs_after, isa=test.get("isa"))
        executed += 1
        if out is None or out["result"] != expected:
            got = None if out is None else out["result"]
            print(f"FAIL {test['mnemonic']}: result {got} want {expected}")
            failures += 1
            continue
        for op in entry["operands"]:
            if role[op["name"]] in ("out", "inout") and is_register_kind(
                    kind[op["name"]], axis_lift):
                # A write to a hardwired-zero register is discarded by the
                # architecture, so "the register did not change" is the correct
                # outcome rather than a missing write. RISC-V's x0 is index 0;
                # AArch64's XZR is 31 in the classes that have one. The rules
                # come from the generated table, not from a test per ISA.
                zero_index = axis_lift.REGISTER_CLASSES[kind[op["name"]]][0]
                if zero_index is not None and fx[op["name"]] == zero_index:
                    continue
                written = register_view(
                    kind[op["name"]], fx[op["name"]], regs_after, axis_lift)
                if written != expected:
                    print(f"FAIL {test['mnemonic']}: dest reg not written")
                    failures += 1

    print(f"{executed} executed, {skipped} skipped (no semantics), {failures} failures")
    ok = failures == 0
    if ok and not executed:
        # The marker has to be on the *verdict* line: check_all.py reads the
        # last line, so a SKIP anywhere above it is invisible and the gate
        # reports a pass for having done nothing -- which is the failure mode
        # this notice exists to prevent.
        print("SKIP: no instruction executed -- lift+execute == golden")
        return 0
    print("lift+execute == golden: PASS" if ok else "lift+execute == golden: FAIL")
    return 0 if ok else 1


def _run_effect_trial(
    test, entry, effects, fx, kind, regs, state, golden, axis_exec, Mem, lift,
    trial=0,
):
    """Apply the effect list to a fixture-indexed reference and compare the
    executor's full register/memory/pc delta. Returns True on mismatch."""
    word = int(test["encoded"], 16)
    # The program counter is a value of the ISA word, so it is drawn from that
    # word -- and on the first trial from its very top, where `pc + ILEN` wraps.
    # Chosen rather than sampled, for the reason the guarded fixtures force
    # their registers equal on trial 0: a wrap that turns up one run in four is
    # a gate that passes because it looked away. This driver used to draw 30
    # bits and call it a 32-bit machine's counter, so the last word of the
    # address space was not reachable at all.
    pc_bits = entry.get("state_width", 32)
    # Which trial gets the top depends on what the other one is for. A guarded
    # fixture spends trial 0 on the taken branch -- registers forced equal --
    # so the fall-through is trial 1, and that is the trial where the wrap can
    # happen at all. An unguarded one has a single trial and takes the top.
    guarded = any("guard" in effect for effect in effects)
    at_top = trial == 1 or not guarded
    pc = ((1 << pc_bits) - 4 if at_top
          else random.getrandbits(pc_bits - 2) * 4)
    def read_register(k, selector, from_regs=None, from_state=None):
        # The class's rules come from the generated table rather than from
        # AArch64's spelled out by hand. This read index 31 as the zero register
        # or SP and tested `"gpr32" in kind` for the narrow view, which was
        # correct for exactly one architecture and silently wrong for the next:
        # RISC-V's zero is index 0, and its float registers are a second file
        # reached through an offset.
        #
        # Two callers: an operand, whose index decode supplies, and a behavior's
        # `getreg`, whose index the description fixes. One reader, because the
        # two are the same read.
        from_regs = regs if from_regs is None else from_regs
        from_state = state if from_state is None else from_state
        # Indexed rather than unpacked: the class tuple grows as register
        # views gain fields, and an unpack breaks on every addition.
        entry = lift.REGISTER_CLASSES[k]
        zero, alias, view = entry[0], entry[1], entry[2]
        if zero is not None and selector == zero:
            return 0
        if alias is not None and selector == alias[0]:
            value = from_state.get(alias[1], 0)
        else:
            value = from_regs.get(lift.register_slot(k, selector), 0)
        return value & ((1 << view) - 1) if view else value & 0xFFFF_FFFF_FFFF_FFFF

    def read_operand(name):
        k, selector = kind[name], fx[name]
        if not is_register_kind(k, lift):
            return selector
        return read_register(k, selector)

    env = {name: read_operand(name) for name in kind}
    env.update({f"__input_{name}": value for name, value in env.items()})
    env["pc"] = pc
    env.update(state)
    init = {}

    def seed_loads(node, addr_width):
        """Seed a cell for every load in the tree, innermost first.

        ⚠️ Every load, not the one at the head. An effect may read memory more
        than once now, and a load's address may itself be a load -- a pointer
        chase is `(load (load rs1))`. Seeding the inner one first is what makes
        the outer address computable: it is read out of the memory this is
        filling, so the order of the walk is the order the machine would go in.
        """
        if not isinstance(node, list):
            return
        if node and node[0] in ("load", "atomic_load"):
            seed_loads(node[-1], addr_width)
            access = int(node[1][1:])
            reader = Mem(init).read
            addr = golden._eval(node[-1], {**env, "__mem__": reader}, addr_width)
            addr &= (1 << addr_width) - 1
            init.setdefault((addr, access), random.getrandbits(access))
            return
        for item in node:
            seed_loads(item, addr_width)

    for eff in effects:
        # Every expression an effect evaluates: the guard, a store's address
        # and the value. A store WRITES its address, but computing it may read
        # -- a descriptor's engine stores to the pointer it found there -- and
        # a guard may read the word it checks. Walking only the value left
        # both reading cells nothing had seeded, which both sides then agreed
        # were zero.
        if eff.get("guard"):
            seed_loads(golden._parse(golden._tokenize(eff["guard"])),
                       eff.get("guard_load_address_width") or 64)
        if eff.get("addr"):
            seed_loads(golden._parse(golden._tokenize(eff["addr"])),
                       eff.get("addr_width") or 64)
        text = eff.get("value")
        if not text:
            continue
        width = eff.get("load_address_width") or eff["eval_width"]
        seed_loads(golden._parse(golden._tokenize(text)), width)

    ref_regs, ref_state, ref_mem = dict(regs), dict(state), Mem(init)
    ref_env = dict(env)
    ref_env["__mem__"] = ref_mem.read
    # A register the description names rather than decodes, read against the
    # reference's own file so that an earlier effect's write is visible exactly
    # as it is to the executor.
    ref_env["__regs__"] = lambda k, index: read_register(k, index, ref_regs, ref_state)
    pc_mask = (1 << pc_bits) - 1
    ref_next_pc = (pc + 4) & pc_mask
    ref_trap = None
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
            eval_width = eff.get("load_address_width") or eff["eval_width"]
            value = golden._eval_axis_expr(
                eff["value"], ref_env, eval_width
            )
            dest, dest_kind = fx[eff["dest"]], kind[eff["dest"]]
            entry = lift.REGISTER_CLASSES[dest_kind]
            zero, alias, view = entry[0], entry[1], entry[2]
            value &= ((1 << view) - 1) if view else 0xFFFF_FFFF_FFFF_FFFF
            if zero is not None and dest == zero:
                pass                              # hardwired zero discards it
            elif alias is not None and dest == alias[0]:
                ref_state[alias[1]] = value
                ref_env[alias[1]] = value
            else:
                ref_regs[lift.register_slot(dest_kind, dest)] = value
            ref_env[eff["dest"]] = value
        elif eff["kind"] == "setreg":
            value = golden._eval_axis_expr(
                eff["value"], ref_env, eff["eval_width"],
                eff.get("load_address_width")
            )
            value &= (1 << eff["width"]) - 1
            fixed_zero = lift.REGISTER_CLASSES[eff["reg_kind"]][0]
            if fixed_zero is None or eff["index"] != fixed_zero:
                ref_regs[lift.register_slot(eff["reg_kind"], eff["index"])] = value
        elif eff["kind"] == "setstate":
            value = golden._eval_axis_expr(
                eff["value"], ref_env, eff["eval_width"],
                eff.get("load_address_width")
            )
            value &= (1 << eff["width"]) - 1
            ref_state[eff["state"]] = value
            ref_env[eff["state"]] = value
        elif eff["kind"] == "store":
            addr = golden._eval_axis_expr(eff["addr"], ref_env, eff["addr_width"])
            addr &= (1 << eff["addr_width"]) - 1
            # ⚠️ `load_address_width`, like every other branch. A stored value
            # may itself be a load -- a block copy is memory to memory in one
            # effect -- and that load's address is as wide as the machine, not
            # as wide as the element being stored. Without it this reference
            # evaluated a 32-bit address at 8 bits and read byte `addr & 0xff`,
            # which is the same mistake the executor's store branch records
            # having made. It was invisible because nothing seeded the cells a
            # store reads from: both sides read zero and agreed.
            value = golden._eval_axis_expr(
                eff["value"], ref_env, eff["eval_width"],
                eff.get("load_address_width")
            )
            ref_mem.write(addr, value, eff["width"])
        elif eff["kind"] == "setpc":
            # Masked here rather than trusted to the expression's own width: a
            # target that does no arithmetic -- `(setpc rs1)` -- comes back as
            # whatever the register held, and what reaches the counter is that
            # value taken at the ISA word.
            ref_next_pc = golden._eval_axis_expr(
                eff["value"], ref_env, eff["eval_width"]
            ) & pc_mask

    exec_regs, exec_state, exec_mem = dict(regs), dict(state), Mem(init)
    out = axis_exec.step(
        word,
        exec_regs,
        exec_mem,
        pc,
        isa=test.get("isa"),
        state=exec_state,
    )
    if (exec_regs != ref_regs or exec_state != ref_state
            or exec_mem.store != ref_mem.store
            or out["next_pc"] != ref_next_pc or out["trap"] != ref_trap):
        print(
            f"FAIL {test['mnemonic']} (effect): "
            f"register/state/memory/pc/trap mismatch; "
            f"regs={exec_regs!r}/{ref_regs!r} "
            f"state={exec_state!r}/{ref_state!r} "
            f"memory={exec_mem.store!r}/{ref_mem.store!r} "
            f"pc={out['next_pc']!r}/{ref_next_pc!r} "
            f"trap={out['trap']!r}/{ref_trap!r}"
        )
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
