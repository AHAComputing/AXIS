#!/usr/bin/env python3
"""The published tree is enough to compute what the instruction computes (X1).

Every effect in `lift_table.json` now carries its expression twice: as the text
it always did, and as a tree. The text is what `pce/aha/optisynth/adl_bridge.py`
re-parses today, and a second parser for AXIS's language living in another
repository is the thing `docs/binary_lift_design.md` exists to remove.

**This gate is a consumer.** It writes the tree-walking evaluator such a
consumer would write -- knowing nothing about AXIS's internals, reading only
the published JSON -- and requires it to agree with the generated executor on
every fixture the corpus has. If the walk gets the right answer, the artifact
is sufficient; if it cannot, the artifact is missing something and that is the
finding.

So the walker is deliberately naive and deliberately **fails loudly on an
operator it does not know**, naming it. A walker that silently skipped what it
had not implemented would report a perfect score for whatever subset it
happened to cover, which is the vacuity this ladder is built to refuse.

The two sides share the description and no code: one is a tree walk over JSON,
the other is Python that AXIS generated from the same instruction.

Usage: tools/lift_ast_check.py [input.axisl ...]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent


class Unsupported(Exception):
    """An operator this walker does not implement, named rather than skipped."""


def mask(value: int, width: int) -> int:
    return value & ((1 << width) - 1)


def signed(value: int, width: int) -> int:
    value = mask(value, width)
    return value - (1 << width) if value >> (width - 1) else value


def _decode_bit_masks(imm_n: int, imms: int, immr: int, width: int):
    """AArch64's `DecodeBitMasks`, as `(wmask, tmask)`.

    A logical immediate *is* this: a run of ones, rotated, replicated to fill
    the register. `imm_n` with the inverted `imms` names the element size, and
    the two masks differ only when the field wraps -- which is why the bitfield
    moves need both and the logical immediates need only the first.
    """
    combined = ((imm_n & 1) << 6) | (~imms & 0x3F)
    length = combined.bit_length() - 1
    if length < 1:
        raise Unsupported("a64 bitmask: no element size, which is UNDEFINED")
    esize = 1 << length
    if esize > width:
        raise Unsupported("a64 bitmask: element wider than the register")
    levels = esize - 1
    run, rotate = imms & levels, immr & levels
    span = (run - rotate) % esize
    def replicate(element: int) -> int:
        whole = 0
        for step in range(width // esize):
            whole |= element << (step * esize)
        return whole
    ones = (1 << (run + 1)) - 1
    welem = ones if not rotate else (
        ((ones >> rotate) | (ones << (esize - rotate))) & ((1 << esize) - 1))
    return replicate(welem), replicate((1 << (span + 1)) - 1)


def evaluate(node: dict, env: dict[str, int], width: int, memory) -> int:
    """One node of a published tree, in the vocabulary the JSON uses."""
    if "const" in node:
        return int(node["const"], 0)
    if "symbol" in node:
        name = node["symbol"]
        if name not in env:
            raise Unsupported(f"symbol `{name}`")
        # **At the width of the node reading it.** RV64's `SRLW` is
        # `(sext i64 32 (srl i32 rs1 ...))`: `rs1` is a 64-bit operand and the
        # shift reads its low 32. Returning the operand's own width here made
        # every W-form and every 32-bit divide disagree with the executor --
        # which is how this rule was learned, from the gate rather than from
        # the artifact, and why `binary_lift_design.md` §5 now states it.
        return mask(env[name], width)
    op = node.get("op")
    args = node.get("args", [])
    # A type atom rides in the `type` field, not as an argument, so the width a
    # node computes at is the node's own.
    kind = node.get("type")
    here = int(kind[1:]) if isinstance(kind, str) and kind.startswith("i") else width

    def value(index: int, at: int | None = None) -> int:
        return evaluate(args[index], env, at if at is not None else here, memory)

    # `sll`/`srl`/`sra` are the same operators as `shl`/`lshr`/`ashr` --
    # `normalize_op` folds each pair -- and the published tree keeps whichever
    # spelling the description used, so a consumer has to accept both.
    op = {"sll": "shl", "srl": "lshr", "sra": "ashr"}.get(op, op)
    if op in ("add", "sub", "mul", "and", "or", "xor", "shl"):
        acc = value(0)
        for index in range(1, len(args)):
            rhs = value(index)
            acc = {
                "add": lambda a, b: a + b,
                "sub": lambda a, b: a - b,
                "mul": lambda a, b: a * b,
                "and": lambda a, b: a & b,
                "or": lambda a, b: a | b,
                "xor": lambda a, b: a ^ b,
                "shl": lambda a, b: (a << b) if b < here else 0,
            }[op](acc, rhs)
        return mask(acc, here)
    if op == "not":
        return mask(~value(0), here)
    # **Shifts saturate; they do not wrap.** A shift amount at or beyond the
    # width gives zero, or the sign for an arithmetic right shift. That is the
    # IR's rule, and it is why `SRLW` carries `(and rs2 0x1f)` in its own
    # description -- RV64's W-forms mask, so the *description* says so -- while
    # `SRAX` does not and saturates. Assuming the hardware convention here made
    # every unmasked shift disagree with the executor.
    if op == "lshr":
        amount = value(1)
        return mask(value(0) >> amount, here) if amount < here else 0
    if op == "ashr":
        amount, raw = value(1), signed(value(0), here)
        if amount >= here:
            return mask(-1 if raw < 0 else 0, here)
        return mask(raw >> amount, here)
    if op in ("sext", "zext"):
        # `(sext iW N x)`: N is the meaningful width of x, W the result.
        from_bits = int(args[0]["const"], 0)
        raw = value(1, from_bits)
        return mask(signed(raw, from_bits) if op == "sext" else mask(raw, from_bits), here)
    if op == "let":
        # Sequential bindings, then the body. Each binding sees the ones before
        # it, which is what makes `RBIT`'s five-step bit reversal expressible
        # without repeating a subexpression five times.
        #
        # A `let` reaching here without them came through the *block graph*,
        # where a node is rebuilt as `{op, type, args}` and the bindings are not
        # among them -- `lift_block` does not expand a `let` into nodes. Said,
        # not crashed: the block gate declines the instruction the way it
        # declines any construct it cannot walk.
        if "body" not in node:
            raise Unsupported("operator `let` outside a published tree")
        inner = dict(env)
        for binding in node.get("bindings", []):
            inner[binding["name"]] = evaluate(binding["value"], inner, here, memory)
        return evaluate(node["body"], inner, here, memory)
    if op == "a64_shift_reg":
        # `(a64_shift_reg iW value shift amount)` -- the shifted-register
        # operand. Two bits of `shift` name the kind, which is the encoding's
        # own numbering and not this walker's invention.
        value, kind, amount = (value(0), value(1), value(2))
        amount &= 63 if here >= 64 else 31
        if kind == 0:
            return mask(value << amount, here)
        if kind == 1:
            return mask(value, here) >> amount
        if kind == 2:
            return mask(signed(value, here) >> amount, here)
        rotated = mask(value, here)
        return mask((rotated >> amount) | (rotated << (here - amount)), here) \
            if amount else rotated
    if op == "a64_extend_reg":
        # `(a64_extend_reg iW value option amount)` -- extract, extend, then
        # shift left. `option` numbers UXTB..SXTX in the architecture's order;
        # the low two bits give the width and bit 2 says whether it is signed.
        value, option, amount = (value(0), value(1), value(2))
        from_bits = (8, 16, 32, 64)[option & 3]
        part = mask(value, from_bits)
        if option & 4:
            part = signed(part, from_bits)
        return mask(part << amount, here)
    if op == "a64_cond_holds":
        # `(a64_cond_holds i4 nzcv cond)`. The low bit of `cond` inverts the
        # test -- except for `AL`, where the architecture reserves 0b1111 and
        # does not invert it into "never".
        flags, cond = value(0), value(1)
        negative, zero = (flags >> 3) & 1, (flags >> 2) & 1
        carry, overflow = (flags >> 1) & 1, flags & 1
        held = (
            zero,
            carry,
            negative,
            overflow,
            carry and not zero,
            negative == overflow,
            (not zero) and negative == overflow,
            1,
        )[(cond >> 1) & 7]
        if cond & 1 and (cond & 0xF) != 0xF:
            held = not held
        return 1 if held else 0
    if op == "a64_wmask":
        # `(a64_wmask iW n immr imms)` -- the logical immediate's write mask.
        wmask, _ = _decode_bit_masks(value(0), value(2), value(1), here)
        return mask(wmask, here)
    if op in ("a64_umulh", "a64_smulh"):
        # The high half of a full-width product, which is the whole reason the
        # instruction exists: the low half is what `MUL` already gives.
        left, right = value(0), value(1)
        if op == "a64_smulh":
            left, right = signed(left, here), signed(right, here)
        else:
            left, right = mask(left, here), mask(right, here)
        return mask((left * right) >> here, here)
    if op in ("a64_ubfm", "a64_sbfm", "a64_bfm"):
        # The bitfield moves, which are one operation with three endings. The
        # architecture builds them from *two* masks, and that is the part a
        # single "field of this width" shortcut gets wrong: `wmask` says which
        # bits the rotated source contributes and `tmask` says how far the field
        # extends, and they differ exactly when the field wraps (S < R). Eight
        # instructions disagreed with the executor until this used both.
        destination = value(0) if op == "a64_bfm" else 0
        source = value(1) if op == "a64_bfm" else value(0)
        rotate = value(2) if op == "a64_bfm" else value(1)
        top_bit = value(3) if op == "a64_bfm" else value(2)
        wmask, tmask = _decode_bit_masks(1 if here >= 64 else 0,
                                         top_bit, rotate, here)
        source = mask(source, here)
        rotate &= here - 1
        rotated = source if not rotate else mask(
            (source >> rotate) | (source << (here - rotate)), here)
        bottom = rotated & wmask
        if op == "a64_bfm":
            # `tmask` applies to the *result* as well, which is the step it is
            # easy to leave out: the destination keeps its own bits both outside
            # `wmask` and outside `tmask`, and the two differ when the field
            # wraps. Omitting it put a bit of the rotated source into bit 63 of
            # a `BFM` whose field ends at bit 1, and the block gate said so.
            bottom = (mask(destination, here) & ~wmask) | bottom
            return mask((mask(destination, here) & ~tmask) | (bottom & tmask), here)
        if op == "a64_ubfm":
            return mask(bottom & tmask, here)
        # `SBFM` fills everything outside the field with the *source's* top bit,
        # which is bit S of the source and not of the rotated value.
        sign = (source >> (top_bit & (here - 1))) & 1
        return mask(((mask(-1, here) if sign else 0) & ~tmask) | (bottom & tmask), here)
    if op == "load":
        # `(load iW signed|unsigned addr)` -- but the width atom rides in
        # `type`, so the published node has two arguments and not three.
        #
        # Two widths meet here and they are not the same one. `type` says how
        # many bits come *from memory*; the caller's `width` says how wide the
        # value is where it is used. `ldursb w1, [x2, #3]` loads eight bits and
        # produces a 32-bit value, so masking the result to eight threw the
        # sign extension away and gave 0xfe where the machine gives 0xfffffffe.
        # The address is neither width: it is an address.
        sign = args[0].get("symbol")
        address = evaluate(args[1], env, 64, memory)
        raw = memory.read(mask(address, 64), here)
        return mask(signed(raw, here) if sign == "signed" else raw, width)
    if op and op.startswith("icmp_"):
        lhs, rhs = value(0), value(1)
        if op in ("icmp_slt", "icmp_sge", "icmp_sgt", "icmp_sle"):
            lhs, rhs = signed(lhs, here), signed(rhs, here)
        return int({
            "icmp_eq": lhs == rhs, "icmp_ne": lhs != rhs,
            "icmp_ult": lhs < rhs, "icmp_uge": lhs >= rhs,
            "icmp_ugt": lhs > rhs, "icmp_ule": lhs <= rhs,
            "icmp_slt": lhs < rhs, "icmp_sge": lhs >= rhs,
            "icmp_sgt": lhs > rhs, "icmp_sle": lhs <= rhs,
        }[op])
    if op == "select":
        return value(1) if mask(value(0), here) else value(2)
    if op in ("udiv", "urem", "sdiv", "srem"):
        lhs, rhs = value(0), value(1)
        if op in ("sdiv", "srem"):
            lhs, rhs = signed(lhs, here), signed(rhs, here)
        if rhs == 0:
            # Division by zero is the machine's answer, not arithmetic's, and
            # the description states it per architecture. A walker that guessed
            # would be inventing semantics, so it declines.
            raise Unsupported(f"`{op}` by zero")
        quotient = abs(lhs) // abs(rhs)
        if op in ("udiv", "sdiv"):
            result = quotient if (lhs < 0) == (rhs < 0) else -quotient
        else:
            result = lhs - rhs * (quotient if (lhs < 0) == (rhs < 0) else -quotient)
        return mask(result, here)
    if op in ("clz", "ctz", "cpop"):
        raw = mask(value(0), here)
        if op == "cpop":
            return bin(raw).count("1")
        if raw == 0:
            return here
        if op == "clz":
            return here - raw.bit_length()
        return (raw & -raw).bit_length() - 1
    if op in ("rotl", "rotr"):
        raw, amount = mask(value(0), here), value(1) % here
        if op == "rotr":
            amount = (here - amount) % here
        return mask((raw << amount) | (raw >> (here - amount)) if amount else raw, here)
    raise Unsupported(f"operator `{op}`")


def seed_register(lift, regs: dict, kind: str, index: int, value: int) -> None:
    """Put `value` where the operand's *view* will read it from.

    The inverse of `register_view`: a windowed class needs its bits placed at
    the window's offset, possibly across limbs, or the view reads the zeros
    beside them.
    """
    _zero, _alias, view_width, _offset, view_offset, _preserve, limbs = (
        lift.REGISTER_CLASSES[kind][:7])
    slot = lift.register_slot(kind, index)
    if view_width is None:
        regs[slot] = value & ((1 << 64) - 1)
        return
    # **Merged, not overwritten.** Two views of one register -- two `v128_*`
    # windows of the same 128-bit vector -- are seeded separately and share a
    # slot, so writing the whole storage for each would leave only the last
    # one's bits. Read what is there and place this view into it.
    whole = 0
    for limb in range(limbs):
        whole |= regs.get(slot + limb, 0) << (64 * limb)
    hole = ((1 << (64 * limbs)) - 1) ^ (((1 << view_width) - 1) << view_offset)
    whole = (whole & hole) | ((value & ((1 << view_width) - 1)) << view_offset)
    for limb in range(limbs):
        regs[slot + limb] = (whole >> (64 * limb)) & ((1 << 64) - 1)


def register_view(kind: str, index: int, regs: dict, lift) -> int:
    """The value this operand *names*, which is not always the whole slot."""
    _zero, _alias, view_width, _offset, view_offset, _preserve, limbs = (
        lift.REGISTER_CLASSES[kind][:7])
    slot = lift.register_slot(kind, index)
    if view_width is None:
        return regs.get(slot, 0)
    whole = 0
    for limb in range(limbs):
        whole |= regs.get(slot + limb, 0) << (64 * limb)
    return (whole >> view_offset) & ((1 << view_width) - 1)


class Memory:
    def __init__(self):
        self.store: dict[tuple[int, int], int] = {}

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = mask(value, width)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # Registered before execution, so a module that imports another emitted one
    # by name finds *this* corpus's copy rather than a previous corpus's.
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emit(axis_file: Path, command: str, out: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   cwd=AXIS_ROOT, check=True, capture_output=True)


def check_one(axis_file: Path, named: bool) -> tuple[int, int, dict[str, int]] | None:
    work = Path(tempfile.mkdtemp(prefix="axis_liftast_"))
    for command, name in (("emit-lift-json", "lift.json"),
                          ("emit-golden-python", "golden_model.py"),
                          ("emit-lift-python", "axis_lift.py"),
                          ("emit-exec-python", "axis_exec.py"),
                          ("emit-roundtrip-json", "fixtures.json")):
        emit(axis_file, command, work / name)
    # The emitted executor does `import golden_model` and `import axis_lift` by
    # name. Sweeping more than one corpus, the second one's executor would
    # otherwise resolve to the first one's cached modules and evaluate nothing
    # -- which showed up as two corpora silently reporting no trees at all.
    for cached in ("golden_model", "axis_lift", "axis_exec"):
        sys.modules.pop(cached, None)
    sys.path.insert(0, str(work))
    load_module(work / "golden_model.py", "golden_model")
    lift_module = load_module(work / "axis_lift.py", "axis_lift")
    exec_module = load_module(work / "axis_exec.py", "axis_exec")
    table = json.loads((work / "lift.json").read_text())
    fixtures = json.loads((work / "fixtures.json").read_text())
    fixtures = fixtures["tests"] if isinstance(fixtures, dict) else fixtures

    by_mnemonic = {entry["mnemonic"]: entry for entry in table["instructions"]}
    agreed = 0
    unsupported: dict[str, int] = {}
    failures = lanes_declined = 0
    for test in fixtures:
        word = int(test["encoded"], 16)
        record = lift_module.lift(word, test.get("isa"))
        if record is None:
            continue
        # A scalable instruction is a lane *group*: one word instantiates to
        # N element operations, `step` runs all of them and reports the last
        # lane's result, and `decode` hands back lane 0. Comparing one lane's
        # tree against another lane's answer is comparing two different things.
        # `gate_coverage.md` §5c already names the driver this shape belongs to
        # -- `scalable_exec_check.py` -- so it is declined here by shape and
        # counted, not silently passed.
        if len(lift_module.decode_lanes(word, test.get("isa"))) > 1:
            lanes_declined += 1
            continue
        entry = by_mnemonic.get(record["mnemonic"])
        if entry is None:
            continue
        # A reduction is the other scalable shape, and the one that is *not* a
        # lane group: it reads every lane and produces one result, so it stays
        # one instruction whose operands are the lanes -- `zn`, `zn__l0`,
        # `zn__l1`, ... Seeding those means placing values in the elements of
        # one vector register, which is `scalable_exec_check.py`'s job and not
        # this walker's. Declined by the same shape rule as a lane group.
        if any(re.search(r"__l\d", operand["name"]) for operand in entry["operands"]):
            lanes_declined += 1
            continue
        # Two places an instruction's value can be published, and a consumer
        # lifting a binary needs both: a behavior states it as an effect, and a
        # pure instruction states it in `semantics` -- which this table has
        # always carried as a tree rather than as text.
        if entry.get("effects"):
            # One `set` with no guard: the shape a walker answers alone. A
            # guarded or multi-effect instruction needs X2's block machinery
            # and is passed over, not silently counted.
            effects = [e for e in entry["effects"] if e.get("kind") == "set"]
            if len(entry["effects"]) != 1 or not effects or "guard" in entry["effects"][0]:
                continue
            effect = effects[0]
            tree = effect.get("value_ast")
            eval_width = effect["eval_width"]
        else:
            tree = entry.get("semantics")
            eval_width = next((o["width"] for o in entry["operands"]
                               if o["role"] == "out"), 32)
        if not isinstance(tree, dict) or "error" in tree:
            continue

        env = dict(record["operands"])
        registers, memory = {}, Memory()
        for operand in entry["operands"]:
            if operand["role"] == "out" or not lift_module.is_register_operand(operand["kind"]):
                continue
            index = record["operands"][operand["name"]]
            seed_register(lift_module, registers, operand["kind"], index,
                          (0xCAFEF00D * (index + 1)))
            # **Through the view, not the slot.** A windowed class -- x86's
            # `AH`, a 32-bit slice of a 128-bit vector -- names a bit range
            # inside the register, and seeding the raw slot compares two
            # different things. `exec_vs_golden.py` carries the same warning;
            # this gate met the shape only when it was swept over every corpus,
            # and `limbs.axisl` disagreed on six instructions.
            env[operand["name"]] = register_view(
                operand["kind"], index, registers, lift_module)
        try:
            walked = evaluate(tree, env, eval_width, memory)
        except Unsupported as exc:
            unsupported[str(exc)] = unsupported.get(str(exc), 0) + 1
            continue

        after = exec_module.step(word, dict(registers), memory, isa=test.get("isa"))
        if after is None:
            continue
        destination = next((o for o in entry["operands"] if o["role"] == "out"), None)
        if destination is None:
            continue
        # `result`, not `writes` and not the register file. `writes` maps an
        # operand name to the register *index* it wrote, and the file would
        # show a zero for a hardwired-zero destination -- neither is the value
        # the instruction computed, which is what a tree walk produces.
        if after.get("result") is None:
            continue
        expected = mask(after["result"], eval_width)
        if expected != mask(walked, eval_width):
            failures += 1
            if failures <= 3:
                print(f"FAIL {axis_file.name} {record['mnemonic']}: the tree computes "
                      f"{walked:#x}, the executor wrote {expected:#x}")
        else:
            agreed += 1
    if not agreed and not failures:
        if named:
            print(f"FAIL {axis_file.name}: no single-effect instruction to walk")
            return (0, 1, unsupported, lanes_declined)
        # A corpus that is *entirely* declined by shape still has something to
        # report: that the sweep met the shape. Returning None here dropped 76
        # lane groups from the total and made the run look as though it had
        # never seen a scalable corpus at all.
        if lanes_declined:
            return (0, 0, unsupported, lanes_declined)
        return None
    return (agreed, failures, unsupported, lanes_declined)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    args = parser.parse_args()
    # Every corpus. Three of them was how a windowed register class went
    # unmet -- `limbs.axisl` disagreed on six instructions the moment it was
    # asked, which is `gate_coverage.md` §5c's argument about pairs nobody
    # wrote down, arriving in a gate written after it.
    targets = args.axis_files or sorted((AXIS_ROOT / "examples").glob("*.axisl"))

    total_agreed = total_failed = total_lanes = 0
    unsupported: dict[str, int] = {}
    for target in targets:
        result = check_one(target, named=bool(args.axis_files))
        if result is None:
            continue
        agreed, failed, missing, lanes = result
        total_agreed += agreed
        total_failed += failed
        total_lanes += lanes
        for name, count in missing.items():
            unsupported[name] = unsupported.get(name, 0) + count
        print(f"     {target.name}: {agreed} tree(s) agree with the executor, "
              f"{failed} disagree"
              + (f", {lanes} lane group(s) declined by shape" if lanes else ""))

    if unsupported:
        # Named, and not a failure: this walker is a consumer's, and what it has
        # not implemented is a fact about the walker. It becomes a failure only
        # if it swallows everything -- see the count below.
        print(f"     walker does not implement {len(unsupported)} construct(s): "
              + ", ".join(f"{name} ({count})" for name, count in
                          sorted(unsupported.items(), key=lambda kv: -kv[1])[:5]))
    print(f"{total_agreed} tree(s) walked, {total_failed} disagreement(s), "
          f"{total_lanes} lane group(s) declined by shape")
    if not total_agreed:
        print("no tree was walked: the artifact proved nothing here")
        return DECLINED
    print("published trees == executor: " + ("PASS" if not total_failed else "FAIL"))
    return 1 if total_failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
