#!/usr/bin/env python3
"""Check that each SelectionDAG pattern computes what its instruction computes.

`emit-llvm-patterns` emits `Pat<(dag), (int_axis_x $a, $b)>` -- "when LLVM's
instruction selector sees this DAG, use this instruction". That is a claim about
*equality of functions*, and until now nothing checked it: `tablegen_validate.py`
proves tblgen accepts the file, which is syntax. A pattern whose DAG said `or`
where the instruction computes `and` would be accepted, shipped, and would
silently select the wrong instruction for correct IR.

So the DAG is evaluated here, over random inputs, and compared against the
golden model for the instruction the pattern names. The node meanings are stated
from LLVM's own definitions rather than read back from AXIS -- `sra` is an
arithmetic shift because LLVM says so, and if AXIS's notion of the instruction
disagrees that is exactly the finding.

Usage: tools/llvm_patterns_check.py <input.axisl> [--cases N]
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file),
                    "-o", str(output)], check=True, cwd=AXIS_ROOT)


def tokenize(text: str):
    return re.findall(r"\(|\)|,|[^\s(),]+", text)


def parse(tokens, position=0):
    """The DAG as nested lists. `(op a b)` -> ["op", a, b]."""
    if tokens[position] != "(":
        return tokens[position], position + 1
    node = [tokens[position + 1]]
    position += 2
    while tokens[position] != ")":
        if tokens[position] == ",":
            position += 1
            continue
        child, position = parse(tokens, position)
        node.append(child)
    return node, position + 1


class Poison(Exception):
    """The DAG's value is undefined here, so the instruction may do anything.

    LLVM leaves shifts past the width undefined; an instruction that clamps and
    one that wraps are both correct selections. A gate that compared those cases
    would be asserting a rule LLVM does not have.
    """


def mask(value: int, width: int) -> int:
    return value & ((1 << width) - 1)


def signed(value: int, width: int) -> int:
    value = mask(value, width)
    return value - (1 << width) if value >> (width - 1) else value


# LLVM's SelectionDAG node meanings, written from LLVM's definitions. This is
# the independent statement: if AXIS's instruction disagrees with what LLVM
# means by `rotl`, the pattern is wrong however self-consistent AXIS is.
class Memory:
    """A deterministic memory both sides of the comparison read.

    The point is not what it holds but that it is the *same* function of the
    address on both sides. A load pattern is right exactly when its address
    computation matches the instruction's, so give the two the same memory and
    any disagreement is a disagreement about the address -- which is the whole
    question a scaled offset raises.
    """

    def __init__(self, seed):
        self.seed = seed

    def read(self, addr, access_bits):
        value = 0
        for index in range(access_bits // 8):
            byte = (addr + index) & 0xFFFFFFFFFFFFFFFF
            # A cheap avalanche, so neighbouring addresses do not hold
            # neighbouring values and an off-by-one address still disagrees.
            mixed = (byte * 0x9E3779B97F4A7C15 + self.seed) & 0xFFFFFFFFFFFFFFFF
            mixed ^= mixed >> 29
            value |= ((mixed >> 17) & 0xFF) << (8 * index)
        return value


def evaluate(node, env, width):
    if isinstance(node, str):
        if node.startswith("$"):
            return env[node[1:]]
        if re.fullmatch(r"-?\d+", node):
            return mask(int(node), width)
        if ":" in node:                      # `i32:$rs1` -- a typed operand
            _type, name = node.split(":", 1)
            return env[name.lstrip("$")]
        raise KeyError(node)
    op = node[0]
    args = node[1:]
    # A typed constant, `(i64 8)`. TableGen needs the type where it cannot
    # infer one; the value is the constant.
    if re.fullmatch(r"i\d+", op) and len(args) == 1:
        # `(i64 8)` is a typed constant. `(i32 i32:$rs2)` is the same syntax
        # saying the *type* of a leaf, which a store's value needs because a
        # store has no result to infer one from.
        if isinstance(args[0], str) and re.fullmatch(r"-?\d+", args[0]):
            return mask(int(args[0]), width)
        return evaluate(args[0], env, int(op[1:]))
    if op == "sext_inreg":
        value = evaluate(args[0], env, width)
        from_width = int(args[1][1:])
        return mask(signed(value, from_width), width)
    values = [evaluate(arg, env, width) for arg in args
              if not (isinstance(arg, str) and re.fullmatch(r"i\d+", arg))]
    if op == "and":
        return values[0] & values[1]
    if op == "or":
        return values[0] | values[1]
    if op == "xor":
        return values[0] ^ values[1]
    if op == "add":
        return mask(values[0] + values[1], width)
    if op == "sub":
        return mask(values[0] - values[1], width)
    if op == "mul":
        return mask(values[0] * values[1], width)
    # A shift by more than the width is *poison* in LLVM, not a modulo -- so
    # the instruction may do anything there and the pattern is still correct.
    # Comparing those cases said SRAX disagreed with `(sra a, b)` when what
    # actually differed was AXIS clamping the amount where LLVM defines
    # nothing. The gate refuses the case rather than inventing a rule for it.
    if op in ("shl", "srl", "sra", "rotl", "rotr") and values[1] >= width:
        raise Poison(op)
    if op == "shl":
        return mask(values[0] << values[1], width)
    if op == "srl":
        return values[0] >> values[1]
    if op == "sra":
        return mask(signed(values[0], width) >> values[1], width)
    if op == "rotl":
        amount = values[1]
        return mask((values[0] << amount) | (values[0] >> (width - amount)), width) \
            if amount else values[0]
    if op == "rotr":
        amount = values[1]
        return mask((values[0] >> amount) | (values[0] << (width - amount)), width) \
            if amount else values[0]
    # ⚠️ A COMPARISON, which yields one or zero. LLVM's `setcc` family
    # produces an i1 and the target widens it into the register the
    # instruction writes; at this width the value is 1 or 0, which is what
    # AXIS's `icmp_*` computes too. The meanings are taken from LLVM's
    # definitions -- `setlt` is SIGNED and `setult` is not, and if AXIS's
    # notion of the instruction disagrees that is exactly the finding.
    if op == "seteq":
        return 1 if values[0] == values[1] else 0
    if op == "setne":
        return 1 if values[0] != values[1] else 0
    if op == "setlt":
        return 1 if signed(values[0], width) < signed(values[1], width) else 0
    if op == "setge":
        return 1 if signed(values[0], width) >= signed(values[1], width) else 0
    if op == "setult":
        return 1 if values[0] < values[1] else 0
    if op == "setuge":
        return 1 if values[0] >= values[1] else 0
    # ⚠️ The HIGH HALF, taken at twice the width and shifted back down. LLVM's
    # `mulhs` multiplies two signed values of this width and yields the upper
    # half; `mulhu` does the same unsigned. Their meanings are stated here
    # from LLVM's definitions rather than read back from AXIS -- which is the
    # whole point of this gate, and the reason adding a pattern without
    # adding its node here would have made the instruction selectable and
    # unchecked at the same time.
    if op == "mulhs":
        product = signed(values[0], width) * signed(values[1], width)
        return mask(product >> width, width)
    if op == "mulhu":
        return mask((values[0] * values[1]) >> width, width)
    if op == "umax":
        return max(values[0], values[1])
    if op == "umin":
        return min(values[0], values[1])
    if op == "smax":
        return mask(max(signed(values[0], width), signed(values[1], width)), width)
    if op == "smin":
        return mask(min(signed(values[0], width), signed(values[1], width)), width)
    if op == "ctlz":
        return width if values[0] == 0 else width - values[0].bit_length()
    if op == "cttz":
        if values[0] == 0:
            return width
        return (values[0] & -values[0]).bit_length() - 1
    if op == "ctpop":
        return bin(values[0]).count("1")
    # A width change. `zext`/`sext` widen a narrower register into the
    # pattern; `trunc` narrows a wider one into it. The value arrives already
    # evaluated at this pattern's width, so the mask is the whole of it -- and
    # the sign, for `sext`, is taken at the source's width.
    if op == "trunc":
        return mask(values[0], width)
    if op == "zext":
        return mask(values[0], width)
    if op == "sext":
        source = leaf_width(args[0], width)
        return mask(signed(values[0], source), width)
    # A load reads the memory in `env`, which is the same object the golden
    # model reads. `load` is the full width; `sextloadiN`/`zextloadiN` read N
    # bits and widen, which is the form the DAG is in by selection time.
    if op == "load" or re.fullmatch(r"[sz]extloadi\d+", op):
        memory = env.get("__mem__")
        if memory is None:
            raise NotImplementedError(op)
        # The address is evaluated at *its* width, which need not be the
        # result's -- AArch64 reads a byte into a `W` register through an `X`
        # address, and computing that address 32 bits wide wraps it.
        addr_width = leaf_width(args[0], width)
        addr = evaluate(args[0], env, addr_width)
        access = width if op == "load" else int(op[len("sextloadi"):])
        raw = memory.read(mask(addr, addr_width), access)
        return mask(signed(raw, access) if op.startswith("s") else raw, width)
    raise NotImplementedError(op)


def golden_eval(golden, mnemonic, values):
    """The golden model's value for one instruction.

    `AXIS_SPECS` indexes the instructions that state themselves through
    `formal_semantics`. An instruction that states itself through a structured
    `behavior` has a generated evaluator all the same -- it is simply not in
    that registry, which other tools iterate and which is deliberately left
    alone here. Reaching the function directly is what lets a pattern derived
    from a behavior be checked against a model built from the same behavior,
    by a different implementation.
    """
    try:
        return golden.evaluate(mnemonic, *values)
    except KeyError:
        pass
    # A generated `eval_*` builds its own environment, and a load needs a
    # `__mem__` reader in it that only the caller can supply. The model is this
    # process's own module, so the reader goes in on the way past rather than
    # through a signature every other consumer of the golden model would have
    # to grow.
    ident = "".join(c.lower() if c.isalnum() else "_" for c in mnemonic)
    if ident[:1].isdigit():
        ident = "_" + ident
    function = getattr(golden, f"eval_{ident}", None)
    if function is None:
        raise KeyError(mnemonic)
    return function(*values)


def leaf_width(node, default):
    """The width the leaves of this sub-DAG are typed at.

    A store's two halves need not agree -- AArch64 stores a `W` register
    through an `X` address -- so each is evaluated at its own.
    """
    if isinstance(node, str):
        found = re.fullmatch(r"(?:[su]imm\d+(?:s\d+)?)?i(\d+):\$\w+", node)
        return int(found.group(1)) if found else None
    if isinstance(node, list):
        if node and isinstance(node[0], str):
            found = re.fullmatch(r"i(\d+)", node[0])
            if found:
                return int(found.group(1))
        for child in node:
            width = leaf_width(child, None)
            if width is not None:
                return width
    return default


ATOMIC_RMW = {
    "swap": lambda old, val, width: val,
    "add": lambda old, val, width: old + val,
    "sub": lambda old, val, width: old - val,
    "and": lambda old, val, width: old & val,
    "or": lambda old, val, width: old | val,
    "xor": lambda old, val, width: old ^ val,
    "max": lambda old, val, width: max(signed(old, width), signed(val, width)),
    "min": lambda old, val, width: min(signed(old, width), signed(val, width)),
    "umax": lambda old, val, width: max(old, val),
    "umin": lambda old, val, width: min(old, val),
}


def atomic_rmw_parts(node):
    """`(operation, width, pointer-DAG, value-DAG)` if this is an atomic RMW.

    LLVM spells the whole read-modify-write one node, and its *result* is the
    old value at the address -- which is what the register half of an AArch64
    `LDADD` holds. Three things are compared: where it read, what it returned,
    and what it left behind.
    """
    if not isinstance(node, list) or len(node) != 3:
        return None
    found = re.fullmatch(
        r"atomic_(?:load_)?(\w+?)_i(\d+)_(?:monotonic|acquire|release|acq_rel|seq_cst)",
        node[0])
    if not found or found.group(1) not in ATOMIC_RMW:
        return None
    return found.group(1), int(found.group(2)), node[1], node[2]


def indexed_store_parts(node):
    """`(pre?, access, value, base, offset)` if this pattern is an indexed store.

    `(post_store $val, $base, $off)` stores at `$base` and leaves `$base + $off`
    in the base register; the pre-index form does both at the advanced address.
    Three things are written and a pattern can get any of them wrong, so all
    three are compared.
    """
    if not isinstance(node, list) or len(node) != 4:
        return None
    found = re.fullmatch(r"(pre|post)_(store|truncsti(\d+))", node[0])
    if not found:
        return None
    access = int(found.group(3)) if found.group(3) else None
    return found.group(1) == "pre", access, node[1], node[2], node[3]


def store_parts(node):
    """`(node-name, value-DAG, address-DAG)` if this pattern is a store.

    A store has no result, so it is compared differently from everything else:
    not one number against another but *where* it writes and *what*, which are
    the two children of the node and the two things a pattern can get wrong.
    """
    if not isinstance(node, list) or not node:
        return None
    op = node[0]
    if op != "store" and not re.fullmatch(r"truncstorei\d+", op):
        return None
    if len(node) != 3:
        return None
    return op, node[1], node[2]


def install_memory(golden, memory):
    """Put `memory` in every environment the golden model evaluates in."""
    original = golden._eval_axis_expr

    def with_memory(expr, env, width, *rest, **named):
        if "__mem__" not in env:
            env = dict(env, __mem__=memory.read)
        return original(expr, env, width, *rest, **named)

    golden._eval_axis_expr = with_memory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=32)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_patterns_"))
    emit(args.axis_file, "emit-llvm-patterns", workdir / "patterns.td")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    spec = importlib.util.spec_from_file_location("golden_model",
                                                  workdir / "golden_model.py")
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)

    text = (workdir / "patterns.td").read_text()
    entries = re.findall(
        r"// (\S+) => \S+\ndef : Pat<(.+?),\n\s*\((int_axis_\w+)([^)]*)\)>;",
        text, re.S)
    if not entries:
        print("SKIP: no selection patterns in this document")
        return 0

    rng = random.Random(0x15E1)
    memory = Memory(0x5EED)
    install_memory(golden, memory)
    checked = failures = poisoned = 0
    declined: dict[str, str] = {}
    nodes_seen: set[str] = set()
    for mnemonic, dag_text, _intrinsic, operand_text in entries:
        # The argument list positionally: `$name` is drawn, a bare integer is
        # a *pinned* operand -- a selector this pattern is the specialisation
        # for. `(add rn (shl rm imm6))` is what the instruction computes when
        # its shift kind is 0, and asking the golden model about a random one
        # would be asking a different question.
        arguments = [token for token in re.findall(r"\$\w+|\b\d+\b", operand_text)]
        operands = [token[1:] for token in arguments if token.startswith("$")]
        try:
            dag, _ = parse(tokenize(dag_text.strip()))
        except Exception as error:                       # noqa: BLE001
            declined[mnemonic] = f"unparsed: {error}"
            continue
        # The root states what the pattern produces, and that is the width to
        # compare at. The first *leaf* type is not the same thing: a load whose
        # address is wider than its result has an `i64` leaf and an `i32`
        # result, and reading the leaf compared the wrong number.
        root = re.match(r"\(i(\d+) ", dag_text.strip())
        types = re.findall(r"i(\d+):", dag_text)
        width = int(root.group(1)) if root else (int(types[0]) if types else 32)
        for token in re.findall(r"\((\w+)", dag_text):
            nodes_seen.add(token)
        # An immediate leaf carries the range its predicate states, and the
        # DAG's meaning depends on it. `simm12i32:$imm` says the value LLVM
        # matches here is a *sign-extended* 12-bit number -- the instruction
        # encodes its low 12 bits and the semantics sign-extends them back, so
        # the two agree only for values in that range. Drawing a full 32-bit
        # immediate would be asking the pattern about values the instruction
        # cannot encode, and it disagrees for exactly those.
        ranges = {name: (kind == "s", int(bits))
                  for kind, bits, name in
                  re.findall(r"\b([su])imm(\d+)i\d+:\$(\w+)", dag_text)}
        # `maskimm<hex>` names the bits the instruction actually encodes. The
        # operand's other bits are not in the instruction at all, so a value
        # with one set is not one this instruction can represent -- asking the
        # pattern about it asks about an encoding that does not exist.
        masks = {name: int(hexmask, 16)
                 for hexmask, name in
                 re.findall(r"\bmaskimm([0-9a-f]+)i\d+:\$(\w+)", dag_text)}
        # `uimm12s8i64:$imm` is a *scaled* immediate: the value the pattern
        # matches is eight times the value the instruction encodes, because the
        # semantics multiplies the field back. AArch64's unsigned-offset LDR
        # addresses `rn + imm * 8` and encodes `imm`.
        #
        # So the two sides are asked different questions unless this divides.
        # The pattern is given a byte offset -- a multiple of the scale, or the
        # instruction cannot represent it at all -- and the golden model is
        # given the quotient, which is what its operand means.
        scaled = {name: (kind == "s", int(bits), int(scale))
                  for kind, bits, scale, name in
                  re.findall(r"\b([su])imm(\d+)s(\d+)i\d+:\$(\w+)", dag_text)}

        # The width an operand's *own* leaf is typed at, which need not be the
        # pattern's. A store's two halves differ, and drawing a nine-bit signed
        # offset masked to 32 bits handed the pattern `0xffffff64` where the
        # instruction sign-extended to 64 and got `-156`. The two then differed
        # by exactly 2^32, which reads as a wraparound bug and is not one.
        leaf_widths = {name: int(bits) for bits, name in
                       re.findall(r"\b(?:[su]imm\d+(?:s\d+)?)?i(\d+):\$(\w+)", dag_text)}

        def draw(name, width=width):
            width = leaf_widths.get(name, width)
            if name in masks:
                return rng.getrandbits(width) & masks[name]
            if name in scaled:
                is_signed, bits, scale = scaled[name]
                if is_signed:
                    field = rng.randrange(-(1 << (bits - 1)), 1 << (bits - 1))
                else:
                    field = rng.getrandbits(bits)
                return mask(field * scale, width)
            if name not in ranges:
                return rng.getrandbits(width)
            signed, bits = ranges[name]
            if signed:
                return mask(rng.randrange(-(1 << (bits - 1)), 1 << (bits - 1)), width)
            return rng.getrandbits(bits)

        def encoded(name, value, width=width):
            """The field value, for an operand the pattern matches scaled."""
            if name not in scaled:
                return value
            _, _, scale = scaled[name]
            return signed(value, leaf_widths.get(name, width)) // scale

        # The root's type wrapper is not part of the shape: `(i32 (atomic_swap
        # ...))` is an atomic, and a store's value carries one too.
        inner = dag
        if (isinstance(inner, list) and len(inner) == 2
                and isinstance(inner[0], str) and re.fullmatch(r"i\d+", inner[0])):
            inner = inner[1]
        atomic = atomic_rmw_parts(inner)
        atomic_model = None
        if atomic is not None:
            ident = "".join(c.lower() if c.isalnum() else "_" for c in mnemonic)
            if ident[:1].isdigit():
                ident = "_" + ident
            atomic_model = getattr(golden, f"atomic_rmw_{ident}", None)
            if atomic_model is None:
                declined[mnemonic] = "no atomic model"
                continue

        indexed = indexed_store_parts(dag)
        indexed_model = None
        if indexed is not None:
            ident = "".join(c.lower() if c.isalnum() else "_" for c in mnemonic)
            if ident[:1].isdigit():
                ident = "_" + ident
            indexed_model = getattr(golden, f"indexed_store_{ident}", None)
            if indexed_model is None:
                declined[mnemonic] = "no indexed-store model"
                continue

        # A store's own evaluator, beside `eval_*` and under its own name --
        # the value function raises for a store, because there is no value.
        store = store_parts(dag)
        store_model = None
        if store is not None:
            ident = "".join(c.lower() if c.isalnum() else "_" for c in mnemonic)
            if ident[:1].isdigit():
                ident = "_" + ident
            store_model = getattr(golden, f"store_{ident}", None)
            if store_model is None:
                declined[mnemonic] = "no store model"
                continue

        ok = True
        for _ in range(args.cases):
            env = {name: draw(name) for name in operands}
            env["__mem__"] = memory
            if atomic is not None:
                operation, access, pointer_dag, value_dag = atomic
                pointer_width = leaf_width(pointer_dag, width)
                try:
                    address = evaluate(pointer_dag, env, pointer_width)
                    operand = evaluate(value_dag, env, access)
                except Poison:
                    poisoned += 1
                    continue
                except (NotImplementedError, KeyError) as error:
                    declined[mnemonic] = f"node {error}"
                    ok = False
                    break
                # A narrow atomic operates at the *memory* width, not the
                # register's: `LDUMAXB` compares a byte against a byte, and
                # feeding it a whole `W` register makes `umax` pick the wrong
                # one whenever the upper bits are set.
                old_value = memory.read(mask(address, pointer_width), access)
                new_value = ATOMIC_RMW[operation](
                    old_value, mask(operand, access), access)
                want_addr, want_old, want_new, want_access = atomic_model(*[
                    encoded(token[1:], env[token[1:]]) if token.startswith("$")
                    else int(token) for token in arguments
                ])
                checked += 1
                if (mask(address, pointer_width) != mask(want_addr, pointer_width)
                        or mask(old_value, access) != mask(want_old, access)
                        or mask(new_value, access) != mask(want_new, access)
                        or access != want_access):
                    failures += 1
                    if failures <= 5:
                        operand_values = {name: hex(value) for name, value
                                          in env.items() if not name.startswith("__")}
                        print(f"FAIL {mnemonic}: pattern reads "
                              f"{mask(old_value, access):#x} at "
                              f"{mask(address, pointer_width):#x} and leaves "
                              f"{mask(new_value, access):#x}, instruction reads "
                              f"{mask(want_old, access):#x} at "
                              f"{mask(want_addr, pointer_width):#x} and leaves "
                              f"{mask(want_new, access):#x} for {operand_values}")
                    ok = False
                    break
                continue
            if indexed is not None:
                pre, access, value_dag, base_dag, offset_dag = indexed
                value_width = leaf_width(value_dag, width)
                base_width = leaf_width(base_dag, width)
                access = access or value_width
                try:
                    got_value = evaluate(value_dag, env, value_width)
                    base = evaluate(base_dag, env, base_width)
                    offset = evaluate(offset_dag, env, base_width)
                except Poison:
                    poisoned += 1
                    continue
                except (NotImplementedError, KeyError) as error:
                    declined[mnemonic] = f"node {error}"
                    ok = False
                    break
                advanced = mask(base + offset, base_width)
                got_addr = advanced if pre else mask(base, base_width)
                want_addr, want_value, want_access, want_base = indexed_model(*[
                    encoded(token[1:], env[token[1:]]) if token.startswith("$")
                    else int(token) for token in arguments
                ])
                checked += 1
                if (mask(got_addr, base_width) != mask(want_addr, base_width)
                        or mask(got_value, access) != mask(want_value, access)
                        or mask(advanced, base_width) != mask(want_base, base_width)
                        or access != want_access):
                    failures += 1
                    if failures <= 5:
                        operand_values = {name: hex(value) for name, value
                                          in env.items() if not name.startswith("__")}
                        print(f"FAIL {mnemonic}: pattern stores "
                              f"{mask(got_value, access):#x} at "
                              f"{mask(got_addr, base_width):#x} leaving "
                              f"{mask(advanced, base_width):#x}, instruction stores "
                              f"{mask(want_value, want_access):#x} at "
                              f"{mask(want_addr, base_width):#x} leaving "
                              f"{mask(want_base, base_width):#x} for {operand_values}")
                    ok = False
                    break
                continue
            if store is not None:
                node, value_dag, addr_dag = store
                value_width = leaf_width(value_dag, width)
                addr_width = leaf_width(addr_dag, width)
                access = value_width if node == "store" \
                    else int(node[len("truncstorei"):])
                try:
                    got_value = evaluate(value_dag, env, value_width)
                    got_addr = evaluate(addr_dag, env, addr_width)
                except Poison:
                    poisoned += 1
                    continue
                except (NotImplementedError, KeyError) as error:
                    declined[mnemonic] = f"node {error}"
                    ok = False
                    break
                want_addr, want_value, want_access = store_model(*[
                    encoded(token[1:], env[token[1:]]) if token.startswith("$")
                    else int(token) for token in arguments
                ])
                checked += 1
                # The address in full, and the value only as far as it is
                # written: a `truncstorei8` pattern is right about the low
                # eight bits and says nothing about the rest.
                if (mask(got_addr, addr_width) != mask(want_addr, addr_width)
                        or mask(got_value, access) != mask(want_value, access)
                        or access != want_access):
                    failures += 1
                    if failures <= 5:
                        operand_values = {name: hex(value) for name, value
                                          in env.items() if not name.startswith("__")}
                        print(f"FAIL {mnemonic}: pattern stores "
                              f"{mask(got_value, access):#x} at "
                              f"{mask(got_addr, addr_width):#x}, instruction stores "
                              f"{mask(want_value, want_access):#x} at "
                              f"{mask(want_addr, addr_width):#x} for {operand_values}")
                    ok = False
                    break
                continue
            try:
                got = evaluate(dag, env, width)
            except Poison:
                poisoned += 1
                continue
            except (NotImplementedError, KeyError) as error:
                declined[mnemonic] = f"node {error}"
                ok = False
                break
            want = golden_eval(golden, mnemonic, [
                encoded(token[1:], env[token[1:]]) if token.startswith("$")
                else int(token)
                for token in arguments
            ])
            checked += 1
            if mask(got, width) != mask(want, width):
                failures += 1
                if failures <= 5:
                    operand_values = {name: hex(value) for name, value
                                      in env.items() if not name.startswith("__")}
                    print(f"FAIL {mnemonic}: pattern {mask(got, width):#x} != "
                          f"instruction {mask(want, width):#x} for "
                          f"{operand_values}")
                ok = False
                break
        if not ok and mnemonic not in declined:
            continue

    print(f"{len(entries)} pattern(s), {len(entries) - len(declined)} evaluated, "
          f"{checked} evaluation(s), {failures} disagree")
    # `DAG nodes exercised` is read off the pattern *text*, so a node this file
    # cannot evaluate appears there while every pattern using it is declined.
    # That is how three families -- the loads, the truncations, the atomics --
    # each shipped reported as passing while nothing had compared them. The
    # declines are counted by node now, next to the number they were hiding
    # behind.
    print(f"  DAG nodes exercised: {', '.join(sorted(nodes_seen))}")
    if poisoned:
        print(f"  {poisoned} case(s) skipped: LLVM leaves the DAG undefined there")
    if declined:
        by_node: dict[str, int] = {}
        for reason in declined.values():
            by_node[reason] = by_node.get(reason, 0) + 1
        print(f"  {len(declined)} of {len(entries)} pattern(s) DECLINED, "
              f"not evaluated -- these are not checked against anything:")
        for reason, count in sorted(by_node.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"    {count:5d}  {reason}")
    ok = failures == 0 and checked > 0
    if not checked:
        print("no pattern was evaluated: nothing was compared")
    print("selection patterns == instruction: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
