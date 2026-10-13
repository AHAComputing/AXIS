#!/usr/bin/env python3
"""Find instruction-set extensions worth having, in real binaries.

The question an ISE study asks is: which *sequences* of instructions recur
often enough, and compute something small enough, that one instruction should
replace them. Answering it needs three things that AXIS already has and that
usually have to be built and trusted separately:

* **A decoder that reads the whole binary.** A miner that silently skips what
  it cannot decode reports the frequency of what it understood, which is a
  statement about the miner.
* **Semantics for each instruction, in a form that composes.** The lift table
  carries `semantics` as a tree over operand names, so a run of instructions
  composes into one expression by substitution rather than by pattern-matching
  disassembly text.
* **A way to check the composition is right.** `emit-smt2` gives one
  `define-fun` per instruction, so the claim "this proposed instruction equals
  those three" is a proof obligation rather than a hope. `ise_prove.py`
  discharges it.

What this file does is the first two. It threads each basic block at
*instruction* granularity -- `lift_block` threads at operator granularity,
which is the right unit for a dataflow consumer and the wrong one here, because
an extension replaces whole instructions and its proof obligation is written in
terms of theirs.
"""
from __future__ import annotations

import argparse
import collections
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
from axis_lift_ffi import Lifter  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, out: Path) -> None:
    result = subprocess.run([*axis_prefix(), command, str(axis_file)],
                            capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    out.write_text(result.stdout)


class Use:
    """A value flowing between instructions in one block.

    Either a register the block read before writing (`live_in`), or the result
    of an instruction in the block. Compared and hashed by shape, so two
    occurrences of the same computation in different blocks are the same
    candidate.
    """

    __slots__ = ("kind", "slot", "producer")

    def __init__(self, kind, slot=None, producer=None):
        self.kind = kind            # "in" | "def" | "opaque"
        self.slot = slot            # register slot, for "in"
        self.producer = producer    # index into the block's instruction list

    def __repr__(self):
        if self.kind == "def":
            return f"def[{self.producer}]"
        return f"{self.kind}[{self.slot}]"


class Threaded:
    """One block's instructions, each with its operands resolved to `Use`s."""

    def __init__(self):
        self.steps = []             # (mnemonic, {operand: Use|int}, out_slot)
        self.semantics = []         # the step's semantics tree, over operand names
        self.widths = []            # operand name -> width, for the immediates
        self.pcs = []               # where the step is, when the caller said
        self.registers = []         # operand name -> (kind, index), as encoded
        self.outs = []              # (kind, index) of the register the step writes

    def __len__(self):
        return len(self.steps)


def thread_block(words, axis_lift, isa, addresses=None):
    """Resolve each instruction's register reads to what produced them.

    A read reaches the last write of the same slot, or the block's boundary.
    Anything the block does that is not a single register write -- a store, a
    branch, a state effect -- ends the run, because an extension that replaced
    it would have to carry that effect too and this rung does not model one.
    """
    threaded = Threaded()
    defs = {}

    def opaque(entry, word, position):
        """This instruction is not minable; what it writes becomes unknown.

        A load, a store, a branch. Ending the block here would be simpler and
        would also be wrong: a block is mostly loads with arithmetic between
        them, and stopping at the first one measured seven instructions in a
        binary with hundreds. So the instruction's results become sources a
        cone may read and may not absorb, and threading carries on.
        """
        if entry is None:
            defs.clear()
            return
        for name in entry.get("writes") or []:
            operand = next((op for op in entry["operands"] if op["name"] == name),
                           None)
            if operand is None or not axis_lift.is_register_operand(operand["kind"]):
                continue
            index = axis_lift._extract(int(word), operand["fields"]) \
                if operand["fields"] else None
            if index is None:
                defs.clear()
                return
            # ⚠️ One source per register per instruction. This named a source
            # by how many minable steps came before it, so two loads with no
            # arithmetic between them were ONE value: `ld a4; ld a5; mul a4,
            # a5, a4` was mined as a square, a three-input multiply-accumulate
            # was reported as a two-input one, and the proof agreed -- it
            # composes from the same names. Writing the occurrence down by
            # register is what showed it.
            slot = axis_lift.register_slot(operand["kind"], index)
            defs[slot] = Use("opaque", slot=slot, producer=("opaque", position))

    for position, word in enumerate(words):
        entry = axis_lift.decode(int(word), isa)
        if entry is None:
            defs.clear()
            continue
        # The tree, not the text: composition is substitution into a tree, and
        # substituting into the string would be a second parser.
        #
        # An instruction whose whole behavior is one unguarded register write is
        # a pure value computation written in the effect dialect, and is taken
        # as one. AArch64 describes its arithmetic that way -- every
        # shifted-register `add`, `sub`, `and` and `orr` -- so reading only
        # `semantics_ast` saw eighty-seven of nine hundred instructions. A
        # write to architectural state beside the value is *not* taken: an
        # extension replacing it would have to define the flags too, and this
        # rung states obligations over values.
        semantics = entry.get("semantics_ast")
        effects = entry.get("effects") or []
        if not semantics and len(effects) == 1 and effects[0].get("kind") == "set" \
                and "guard" not in effects[0]:
            semantics = effects[0].get("value_ast")
        # A value that reads memory is not a value this rung can state an
        # obligation about: `emit-smt2` has no definition for `load`, so a
        # candidate containing one would be counted here and declined at the
        # proof. Reporting it as a candidate would be reporting a frequency for
        # something that cannot be proposed.
        if semantics is not None and reads_memory(semantics):
            semantics = None
        outputs = [op for op in entry["operands"]
                   if op.get("role") in ("out", "inout")
                   and axis_lift.is_register_operand(op["kind"])]
        if not semantics or len(outputs) != 1 \
                or (effects and len(effects) != 1):
            opaque(entry, word, position)
            continue
        values = {}
        fields = {op["name"]: op for op in entry["operands"]}
        decoded = {name: axis_lift._extract(int(word), op["fields"])
                   for name, op in fields.items() if op["fields"]}
        usable = True
        for op in entry["operands"]:
            if op.get("role") == "out":
                continue
            index = decoded.get(op["name"])
            if index is None:
                usable = False
                break
            if axis_lift.is_register_operand(op["kind"]):
                slot = axis_lift.register_slot(op["kind"], index)
                values[op["name"]] = defs.get(slot) or Use("in", slot=slot)
            else:
                values[op["name"]] = int(index)      # an immediate is a constant
        index = decoded.get(outputs[0]["name"])
        if not usable or index is None:
            opaque(entry, word, position)
            continue
        slot = axis_lift.register_slot(outputs[0]["kind"], index)
        threaded.steps.append((entry["mnemonic"], values, slot))
        threaded.semantics.append(semantics)
        threaded.widths.append({op["name"]: op.get("width", 32)
                                for op in entry["operands"]})
        threaded.pcs.append(addresses[position] if addresses else None)
        threaded.outs.append((outputs[0]["kind"], index))
        threaded.registers.append({
            op["name"]: (op["kind"], decoded[op["name"]]) for op in entry["operands"]
            if axis_lift.is_register_operand(op["kind"]) and op["name"] in decoded})
        defs[slot] = Use("def", producer=len(threaded.steps) - 1)
    return threaded


def cone(threaded, root, max_inputs, max_steps):
    """The instructions a candidate rooted at `root` would replace.

    Grown backwards from the root, taking a producer whenever doing so does not
    push the input count past the budget. The budget is the architectural
    constraint that makes this a real question: an extension has to read its
    operands through the register file the machine already has, so two inputs
    and one output is the classic shape and anything wider needs justifying.

    Returns the covered instruction indices in program order, or None when the
    root alone already exceeds the budget.
    """
    covered = {root}
    while True:
        inputs = cone_inputs(threaded, covered)
        if len(inputs) <= max_inputs:
            break
        # Too wide: absorbing the producer of one input may narrow it, if that
        # producer's own inputs are already in the cone.
        grew = False
        for use in inputs:
            if use.kind != "def" or use.producer in covered:
                continue
            trial = covered | {use.producer}
            if len(trial) > max_steps:
                continue
            if len(cone_inputs(threaded, trial)) <= len(inputs):
                covered = trial
                grew = True
                break
        if not grew:
            return None
    # Then grow greedily while it stays inside both budgets: a bigger cone
    # replaces more instructions, which is the whole point.
    while len(covered) < max_steps:
        best = None
        for use in cone_inputs(threaded, covered):
            if use.kind != "def" or use.producer in covered:
                continue
            trial = covered | {use.producer}
            width = len(cone_inputs(threaded, trial))
            if width <= max_inputs and (best is None or width < best[0]):
                best = (width, use.producer)
        if best is None:
            break
        covered.add(best[1])
    return sorted(covered)


def cone_inputs(threaded, covered):
    """The registers a cone reads from outside itself, in first-appearance order.

    Registers only. An immediate reaches the machine through the instruction
    word, not through the register file, so it costs no read port -- and the
    budget this is measured against is a count of ports. Counting immediates
    against it would refuse a two-register extension for carrying a constant.
    """
    seen, order = set(), []
    for index in sorted(covered):
        _mnemonic, values, _slot = threaded.steps[index]
        for name in sorted(values):
            use = values[name]
            if isinstance(use, int):
                continue
            if use.kind == "def" and use.producer in covered:
                continue
            key = (use.kind, use.slot, use.producer)
            if key not in seen:
                seen.add(key)
                order.append(use)
    return order


def cone_immediates(threaded, covered):
    """The immediates a cone reads, as `(step, operand, width)`, in order.

    Abstracted rather than baked in. `sub sp, sp, #48` then `add x0, sp, #32`
    recurs forty-five times across the system binaries with *those* constants,
    and hundreds of times with others -- and one instruction per pair of
    constants is not an extension, it is a table. The shape is the candidate;
    the constants are its operands.
    """
    found = []
    for index in sorted(covered):
        _mnemonic, values, _slot = threaded.steps[index]
        for name in sorted(values):
            if isinstance(values[name], int):
                found.append((index, name, threaded.widths[index].get(name, 32)))
    return found


def canonical(threaded, covered):
    """A key that is the same for two occurrences of the same computation.

    Inputs are renamed by first appearance, so the same shape on different
    registers is one candidate. Immediates are kept as written: `x << 7` and
    `x << 3` are different extensions, and a miner that merged them would
    report a frequency for something it could not emit.
    """
    inputs = cone_inputs(threaded, covered)
    names = {(use.kind, use.slot, use.producer): f"a{i}"
             for i, use in enumerate(inputs)}
    constants = {(step, operand): f"k{i}"
                 for i, (step, operand, _w)
                 in enumerate(cone_immediates(threaded, covered))}
    order = {index: position for position, index in enumerate(sorted(covered))}
    parts = []
    for index in sorted(covered):
        mnemonic, values, _slot = threaded.steps[index]
        arguments = []
        for name in sorted(values):
            use = values[name]
            if isinstance(use, int):
                arguments.append(f"{name}={constants[(index, name)]}")
            elif use.kind == "def" and use.producer in covered:
                arguments.append(f"{name}=t{order[use.producer]}")
            else:
                arguments.append(f"{name}={names[(use.kind, use.slot, use.producer)]}")
        parts.append(f"t{order[index]}={mnemonic}({','.join(arguments)})")
    return " ; ".join(parts), len(inputs)


def site(threaded, covered, image):
    """Where one occurrence is, and what its operands are there.

    The shape says what an extension computes; this says what a rewriter needs
    to put one in the program: the instructions it covers, by address, the
    register each input is read from and where, each immediate's value, and
    the register the root writes. Names are the proposal's -- `a0`, `k0` -- in
    the order `canonical` and `compose` give them.
    """
    inputs, immediates, names = [], [], {}
    for index in sorted(covered):
        _mnemonic, values, _slot = threaded.steps[index]
        for name in sorted(values):
            use = values[name]
            if isinstance(use, int):
                immediates.append(use)
                continue
            if use.kind == "def" and use.producer in covered:
                continue
            key = (use.kind, use.slot, use.producer)
            if key not in names:
                kind, register = threaded.registers[index][name]
                names[key] = len(inputs)
                inputs.append({"kind": kind, "register": register, "read_at": []})
            inputs[names[key]]["read_at"].append(threaded.pcs[index])
    out_kind, out_register = threaded.outs[max(covered)]
    return {"image": image, "covers": [threaded.pcs[index] for index in sorted(covered)],
            "inputs": inputs, "immediates": immediates,
            "rd": {"kind": out_kind, "register": out_register}}


def reads_memory(node) -> bool:
    """Whether this semantics tree loads."""
    if isinstance(node, dict):
        if node.get("op") in ("load", "atomic_load"):
            return True
        return any(reads_memory(arg) for arg in node.get("args", []))
    return False


def substitute(node, binding):
    """An instruction's semantics tree with its operand symbols replaced.

    The lift table gives semantics over operand *names*; a cone gives what each
    name is bound to -- an input of the extension, a constant, or the tree of
    the instruction that produced it. Substitution is therefore the whole of
    composition, and it is a tree walk rather than a pattern match on text.
    """
    if isinstance(node, dict) and "symbol" in node:
        return binding.get(node["symbol"], node)
    if isinstance(node, dict) and "args" in node:
        return {**node, "args": [substitute(arg, binding) for arg in node["args"]]}
    return node


def compose(threaded, covered):
    """The cone as one semantics tree, plus the inputs it reads.

    Returns None when any covered instruction's semantics are missing, which is
    the honest answer: a candidate whose meaning cannot be composed cannot be
    proposed, and counting it would inflate the report.
    """
    inputs = cone_inputs(threaded, covered)
    names = {(use.kind, use.slot, use.producer): f"a{i}"
             for i, use in enumerate(inputs)}
    immediates = cone_immediates(threaded, covered)
    constants = {(step, operand): f"k{i}"
                 for i, (step, operand, _w) in enumerate(immediates)}
    trees = {}
    for index in sorted(covered):
        _mnemonic, values, _slot = threaded.steps[index]
        semantics = threaded.semantics[index]
        if semantics is None:
            return None
        binding = {}
        for name, use in values.items():
            if isinstance(use, int):
                binding[name] = {"symbol": constants[(index, name)]}
            elif use.kind == "def" and use.producer in covered:
                binding[name] = trees[use.producer]
            else:
                binding[name] = {"symbol": names[(use.kind, use.slot, use.producer)]}
        trees[index] = substitute(semantics, binding)
    return (trees[max(covered)],
            [names[(u.kind, u.slot, u.producer)] for u in inputs],
            [(constants[(step, operand)], width)
             for step, operand, width in immediates])


def free_symbols(node, bound) -> list:
    """Symbols the composed tree names that nothing binds -- architectural state.

    Substitution replaces operand names and leaves everything else alone, so a
    value that reads `nzcv` still says `nzcv` after composition. The extension
    reads it too, and its proposal has to declare it, so the names are carried
    rather than left for the prover to rediscover.
    """
    found = []
    def walk(item):
        if isinstance(item, dict):
            if "symbol" in item:
                name = item["symbol"]
                if name not in bound and name not in found:
                    found.append(name)
            for argument in item.get("args", []):
                walk(argument)
    walk(node)
    return found


def render(node):
    """A semantics tree as the s-expression AXIS parses back."""
    if isinstance(node, dict) and "symbol" in node:
        return node["symbol"]
    if isinstance(node, dict) and "const" in node:
        return str(node["const"])
    if isinstance(node, dict) and "args" in node:
        head = node["op"]
        typed = f" {node['type']}" if node.get("type") else ""
        return f"({head}{typed} " + " ".join(render(a) for a in node["args"]) + ")"
    return str(node)


def as_built(axis_file: Path, workdir: Path) -> tuple[Path, dict]:
    """The description with one more core: the machine its netlists ARE.

    Every instruction is given the fewest cycles its netlist needs at the
    cycle the hardware planner groups by -- `(latency (* derived))`, which
    `docs/core_timing_design.md` defines -- so a chain and the extension that
    replaces it are charged on one clock. An instruction with no netlist
    keeps the latency it declares.
    """
    plan = subprocess.run([*axis_prefix(), "emit-hw-json", str(axis_file)],
                          capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    cycle = round(json.loads(plan.stdout)["cost_model"]["cycle_budget"])
    text = axis_file.read_text().rstrip()
    core = f"  (defcore as_built (kind rvmt) (cycle (gates {cycle})) (timing (latency (* derived))))\n"
    built = workdir / f"{axis_file.stem}_as_built.axisl"
    built.write_text(text[:-1] + "\n" + core + ")\n")
    return built, {"core": "as_built", "cycle_gates": cycle}


def instruction_latencies(axis_file: Path, core: str | None = None) -> dict:
    """Each instruction's latency in cycles, by mnemonic, from the description.

    A count of instructions removed is a poor proxy for what an extension is
    worth: replacing a three-cycle multiply and a one-cycle add is not the same
    saving as replacing two moves. The description states a latency per
    instruction, so the *chain* those instructions form is a fact rather than an
    estimate -- and what the extension itself would cost is not, so it stays a
    parameter the caller supplies.
    """
    result = subprocess.run([*axis_prefix(), "emit-capability-json", str(axis_file),
                             *(["--core", core] if core else [])],
                            capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    document = json.loads(result.stdout)
    rows = next(value for value in document.values() if isinstance(value, list))
    return {row["mnemonic"]: row.get("latency_cycles") or 1 for row in rows}


def critical_path(threaded, covered, latencies) -> int:
    """Cycles along the longest dependence chain the cone contains.

    The instructions a cone covers do not all run one after another -- two that
    read the same registers run together on any machine wide enough. What an
    extension removes is the *chain*, so that is what is measured.
    """
    longest = {}
    for index in sorted(covered):
        mnemonic, values, _slot = threaded.steps[index]
        before = max(
            [longest.get(use.producer, 0) for use in values.values()
             if not isinstance(use, int) and use.kind == "def"
             and use.producer in covered] or [0])
        longest[index] = before + (latencies.get(mnemonic) or 1)
    return max(longest.values()) if longest else 0


def sections_of(path: Path):
    """Executable sections of an ELF or Mach-O, reusing the coverage reader."""
    from binary_coverage import sections_of as read
    return read(path)[1]


def blocks_of(lifter, image: bytes, base: int, isa):
    """(start, words, addresses) per basic block, from the lifter's own account.

    The lifter decides where blocks end, which is the point of asking it rather
    than guessing: a run that crosses a branch is not a block, and an extension
    mined across one would be replacing instructions that do not always run.
    """
    import re
    # A word the description does not cover ends the lifter's walk, which is
    # right for a region and wrong for a survey: one undecoded instruction
    # would silence the rest of a section. So the walk restarts after it, and
    # what was skipped is counted -- a miner that quietly stops reports the
    # frequency of what it reached.
    report, offset, skipped = "", 0, 0
    while offset < len(image):
        part = lifter.blocks(image[offset:], base + offset, isa)
        report += part
        stop = re.search(r"undecodable at 0x([0-9a-f]+)", part)
        if not stop:
            break
        resume = int(stop.group(1), 16) - base + 2
        if resume <= offset:
            break
        offset, skipped = resume, skipped + 1
    blocks, current, addresses, start = [], [], [], None
    for line in report.splitlines():
        head = re.match(r"^bb_([0-9a-f]+):", line)
        if head:
            if current:
                blocks.append((start, current, addresses))
            start, current, addresses = int(head.group(1), 16), [], []
            continue
        # Any address width. Eight digits is what a 32-bit region prints and
        # what this matched for a while; a Mach-O `__text` at 0x100000700 is
        # nine, and the miner reported that binary as having no blocks at all.
        body = re.match(r"^\s+([0-9a-f]{4,16})\s+([0-9a-f]+)\s+(\S+)", line)
        if body:
            current.append(int(body.group(2), 16))
            addresses.append(int(body.group(1), 16))
    if current:
        blocks.append((start, current, addresses))
    return blocks, skipped


def mine(lifter, axis_lift, images, isa, max_inputs, max_steps, latencies):
    """Candidates over every block of every image, counted."""
    found = collections.defaultdict(lambda: {"count": 0, "steps": 0, "inputs": 0,
                                             "example": None, "semantics": None,
                                             "inputs_named": [], "mnemonics": [],
                                             "immediates": [], "state": [],
                                             "path": 0, "sites": []})
    blocks = instructions = undecoded = 0
    for name, image, base in images:
        found_blocks, skipped = blocks_of(lifter, image, base, isa)
        undecoded += skipped
        for start, words, addresses in found_blocks:
            blocks += 1
            threaded = thread_block(words, axis_lift, isa, addresses)
            instructions += len(threaded)
            for root in range(len(threaded)):
                covered = cone(threaded, root, max_inputs, max_steps)
                if covered is None or len(covered) < 2:
                    continue        # one instruction is not an extension
                composed = compose(threaded, covered)
                if composed is None:
                    continue
                key, width = canonical(threaded, covered)
                record = found[key]
                record["semantics"] = render(composed[0])
                record["inputs_named"] = composed[1]
                record["immediates"] = composed[2]
                record["path"] = critical_path(threaded, covered, latencies)
                record["state"] = free_symbols(
                    composed[0],
                    set(composed[1]) | {name for name, _w in composed[2]})
                record["mnemonics"] = [threaded.steps[i][0] for i in covered]
                record["count"] += 1
                record["sites"].append(site(threaded, covered, name))
                record["steps"] = len(covered)
                record["inputs"] = width
                if record["example"] is None:
                    record["example"] = f"{name}+{start:#x}"
    return found, blocks, instructions, undecoded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("binaries", type=Path, nargs="+")
    parser.add_argument("--isa", default=None)
    parser.add_argument("--max-inputs", type=int, default=2,
                        help="values the extension may read (register-file ports)")
    parser.add_argument("--max-steps", type=int, default=4,
                        help="instructions one extension may replace")
    parser.add_argument("--top", type=int, default=12)
    parser.add_argument("--extension-latency", type=int, default=1,
                        help="cycles the proposed instruction would take; the "
                             "one number here that is an assumption")
    parser.add_argument("--as-built", action="store_true",
                        help="charge every instruction the cycles its netlist needs, not the "
                             "latency it declares -- the clock ise_cost.py charges an "
                             "extension on")
    parser.add_argument("--json", type=Path, default=None,
                        help="write the candidates here, for ise_prove.py")
    args = parser.parse_args()

    try:
        lifter = Lifter(args.axis_file)
    except FileNotFoundError as missing:
        print(f"SKIP: {missing}")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_ise_"))
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    sys.path.insert(0, str(workdir))
    axis_lift = importlib.import_module("axis_lift")

    images = []
    for path in args.binaries:
        for name, data, base in sections_of(path):
            if name in (".text", "__text"):
                images.append((f"{path.name}:{name}", data, base))
    if not images:
        print("no executable section found")
        return FAILED

    clock = None
    if args.as_built:
        built, clock = as_built(args.axis_file, workdir)
        latencies = instruction_latencies(built, clock["core"])
    else:
        latencies = instruction_latencies(args.axis_file)
    found, blocks, instructions, undecoded = mine(
        lifter, axis_lift, images, args.isa, args.max_inputs, args.max_steps,
        latencies)
    # What an extension is worth: every occurrence removes the instructions it
    # covers and adds one. Cycles would be better and need a model of the
    # machine; this is the count, and it is stated as a count.
    def cycles(record):
        """Cycles removed: the chain, less what the extension itself costs."""
        return record["count"] * max(record["path"] - args.extension_latency, 0)

    ranked = sorted(found.items(),
                    key=lambda item: (cycles(item[1]),
                                      item[1]["count"] * (item[1]["steps"] - 1)),
                    reverse=True)
    print(f"{len(images)} section(s), {blocks} block(s), {instructions} threaded "
          f"instruction(s), {undecoded} word(s) the description does not cover, "
          f"{len(found)} distinct candidate(s)")
    print(f"cycles removed assumes the extension costs "
          f"{args.extension_latency} cycle(s); the chain is "
          + (f"the netlists' at a {clock['cycle_gates']}-gate cycle" if clock
             else "the description's"))
    print(f"{'cycles':>7}  {'saved':>6}  {'seen':>5}  {'path':>4}  {'in':>2}  shape")
    for key, record in ranked[:args.top]:
        saved = record["count"] * (record["steps"] - 1)
        print(f"{cycles(record):>7}  {saved:>6}  {record['count']:>5}  "
              f"{record['path']:>4}  {record['inputs']:>2}  {key}")

    if args.json:
        args.json.write_text(json.dumps({
            "schema": "axis.ise-candidates.v1",
            "description": str(args.axis_file),
            "clock": clock,
            "isa": args.isa,
            "sections": [name for name, _data, _base in images],
            "blocks": blocks,
            "threaded_instructions": instructions,
            "candidates": [
                {"shape": key, "occurrences": record["count"],
                 "instructions": record["steps"], "inputs": record["inputs"],
                 "saved": record["count"] * (record["steps"] - 1),
                 "critical_path_cycles": record["path"],
                 "cycles_removed": record["count"]
                     * max(record["path"] - args.extension_latency, 0),
                 "example": record["example"],
                 "mnemonics": record["mnemonics"],
                 "operands": record["inputs_named"],
                 "immediates": record["immediates"],
                 "state": record["state"],
                 "sites": record["sites"],
                 "formal_semantics": record["semantics"]}
                for key, record in ranked
            ],
        }, indent=2))
    return PASSED


if __name__ == "__main__":
    raise SystemExit(main())
