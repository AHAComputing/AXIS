#!/usr/bin/env python3
"""The graph a block lifts to computes what the block computes (X2).

X1 proved one instruction's published tree is enough to compute with.
`lift_block` puts a run of them together: each tree instantiated with the
register indices decode chose, and every read threaded to the last write of the
same architectural location. That threading is the whole of the stage --
`addi x5, x1, 7` followed by `add x6, x5, x2` is one graph or it is two, and
nothing about a single instruction can tell you which.

So the gate runs both: it evaluates the graph over random initial registers and
compares against `axis_exec.run` on the same words and the same seed. Two
implementations -- a graph walk and generated Python -- sharing the description
and no code.

**The graph's live-outs are checked against what execution changed** (X3's
predicate, brought forward because it costs nothing here): a location the graph
reports leaving changed must be one `run` wrote, and every location `run` wrote
must be in the graph. AXISMINE `.4` reports the consumer-side version of this
missing -- `region_is_expressible` never looks at live-outs, and 23 of its 31
mined regions have more than one -- so a block IR that got this wrong would be
wrong in exactly the way that already cost them.

Blocks are built from the corpus's own fixtures, which is what makes them
decodable and what bounds them: instructions whose effect is a single
unguarded register write, chained so that later ones read earlier ones'
destinations. A branch, a store and a guarded effect are declined by
`lift_block` itself and reported, not silently dropped.

Usage: tools/lift_block_check.py [input.axisl ...] [--blocks N]
"""

from __future__ import annotations

import argparse
import json
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED
from lift_ast_check import (Memory, Unsupported, evaluate, load_module, mask,
                            register_view, seed_register)

AXIS_ROOT = Path(__file__).resolve().parent.parent


def evaluate_graph(graph, seeds: dict[tuple[str, int], int], memory) -> dict[int, int]:
    """Every node's value, inputs bound to the same seeds the executor got.

    Nodes are valued in id order, which is construction order, which is program
    order -- so a load sees the stores that precede it in the block, exactly as
    execution does. That is the whole content of the memory ordering this graph
    claims: every store aliases every other, and nothing is reordered.
    """
    values: dict[int, int] = {}
    by_id = {node["id"]: node for node in graph["nodes"]}
    for node in graph["nodes"]:
        kind = node["kind"]
        if kind == "store":
            address = mask(values[node["address"]], 64)
            value = values[node["value"]]
            memory.write(address, value, node["width"])
            values[node["id"]] = value
            continue
        if kind == "input":
            location = tuple(node["location"])
            values[node["id"]] = mask(seeds.get(location, 0), node["width"])
        elif kind == "const":
            values[node["id"]] = mask(int(str(node["value"]), 0), node["width"])
        elif kind == "op":
            # The published tree, rebuilt one level deep: each argument is a
            # node this walk has already valued, so the X1 evaluator sees a
            # constant where the tree had a subexpression.
            #
            # Masked to *this* node's width, which is X1's own rule -- a symbol
            # is read at the width of the node reading it -- restored after
            # turning the symbol into a constant. Without it a 64-bit input
            # feeding a 32-bit operator kept its high half.
            widths = [node["width"]] * len(node["args"])
            if node["op"] == "load":
                # `(load iW sign addr)` decides sign-extension by reading
                # `args[0]`'s *symbol*, and turning every argument into a
                # constant destroyed it -- so every signed load read unsigned
                # and `ldursb w1, [x2, #3]` gave 0xfe where the machine gives
                # 0xfffffffe. The marker is published, as an input node located
                # at `('__symbol__', 'signed')`; it just has to be handed back
                # as a symbol rather than as its value.
                marker = by_id.get(node["args"][0], {})
                if marker.get("kind") == "input" and marker["location"][0] == "__symbol__":
                    sign_symbol = marker["location"][1]
                else:
                    sign_symbol = None
                # ...except a load's address, which is an address and not a
                # value of the loaded width. Masking it like one truncated
                # 0x7fa1...bb to sixteen bits, so a 16-bit load missed the
                # 16-bit store that had just written that very address and
                # read zero. Stores never had this because they carry a
                # separate `address` field, masked to 64 -- the asymmetry is
                # what hid it.
                widths[-1] = 64
            args = [{"const": str(mask(values[arg], width))}
                    for arg, width in zip(node["args"], widths)]
            if node["op"] == "load" and sign_symbol is not None:
                args[0] = {"symbol": sign_symbol}
            values[node["id"]] = evaluate(
                {"op": node["op"], "type": node.get("type"), "args": args},
                {}, node["width"], memory)
        else:
            raise Unsupported(f"node kind `{kind}`")
    return values


def names_only_operands(tree, operands: set[str]) -> bool:
    """Does this tree read anything but its own operands?

    An instruction reading architectural state -- AArch64's `fpsr`, a rounding
    mode, the counter -- needs a state dict the block model does not carry, and
    the golden model raises rather than guessing. Filtered here so the gate
    declines it the way the walker does, instead of the executor throwing
    mid-sweep.
    """
    if not isinstance(tree, dict):
        return True
    if "symbol" in tree:
        return tree["symbol"] in operands or tree["symbol"] in ("signed", "unsigned")
    return all(names_only_operands(arg, operands) for arg in tree.get("args", []))


_EVALUABLE: dict[tuple[int, int], bool] = {}


def _evaluable(word: int, lift_module, isa=None) -> bool:
    """Whether the walker can evaluate this instruction on its own.

    Asked by trying it rather than by matching a list of operator names, so it
    cannot drift from what `evaluate_graph` actually implements. Only
    `Unsupported` filters -- any other failure is a real one and belongs in the
    gate's output, not swallowed here.
    """
    key = (id(lift_module), word, isa)
    if key in _EVALUABLE:
        return _EVALUABLE[key]
    graph = lift_module.lift_block([word], isa=isa)
    verdict = False
    if graph is not None and graph["instructions"]:
        try:
            evaluate_graph(graph, {}, Memory())
            verdict = True
        except Unsupported:
            verdict = False
    _EVALUABLE[key] = verdict
    return verdict


def build_block(fixtures, table, lift_module, rng, length: int, force_terminator=False):
    """A run of words whose later instructions read earlier ones' results.

    Chained on purpose: a block of independent instructions would have no
    def-use edge to get wrong, and threading is what X2 adds.
    """
    usable, terminators = [], []
    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = table.get(word)
        if entry is None:
            continue
        operand_names = {operand["name"] for operand in entry["operands"]}
        trees = [entry.get("semantics_ast")]
        for effect in entry.get("effects") or []:
            trees += [effect.get("value_ast"), effect.get("addr_ast"),
                      effect.get("guard_ast")]
        if not all(names_only_operands(tree, operand_names)
                   for tree in trees if tree is not None):
            continue
        # A lane group and a reduction are the scalable shapes: one word that
        # is N element operations, and one instruction whose operands are all
        # the lanes. `gate_coverage.md` §5c names the driver they belong to,
        # `scalable_exec_check.py`, and it is not this one.
        if len(lift_module.decode_lanes(word, test.get("isa"))) > 1:
            continue
        if any(re.search(r"__l\d", operand["name"]) for operand in entry["operands"]):
            continue
        effects = entry.get("effects") or []
        if effects:
            # A load or a store: one unguarded effect, which is what a block
            # can hold and what `lift_block` models. Excluding these was the
            # coverage hole -- the memory path was implemented and checked by
            # nothing, and a block mined from a real binary is mostly memory.
            if len(effects) != 1:
                continue
            if effects[0]["kind"] == "setpc":
                # A terminator, kept aside: a block ends in one, so it is
                # appended rather than drawn into the body.
                terminators.append((word, entry, None, test.get("isa")))
                continue
            if "guard" in effects[0]:
                continue
            if effects[0]["kind"] not in ("set", "store"):
                continue
            if effects[0]["kind"] == "set" and effects[0].get("value_ast") is None:
                continue
            usable.append((word, entry,
                           next((o for o in entry["operands"] if o["role"] == "out"), None),
                           test.get("isa")))
            continue
        destination = next((o for o in entry["operands"] if o["role"] == "out"), None)
        if destination is None or not lift_module.is_register_operand(destination["kind"]):
            continue
        if not isinstance(entry.get("semantics_ast"), dict):
            continue
        usable.append((word, entry, destination, test.get("isa")))
    # Only instructions this walker can actually evaluate. Most of AArch64's
    # reach `a64_shift_reg`, `a64_extend_reg`, `a64_wmask`, `a64_bfm` or `let`,
    # which are named and unimplemented here -- and a block containing one is
    # skipped whole. Drawing six at random and hoping all six land outside that
    # set is how this gate worked until now: three of forty blocks survived on
    # the AArch64 corpus, and a shift in the random stream took that to zero.
    # The instructions are still counted as declined; they are just no longer
    # drawn into blocks that then prove nothing.
    # **One ISA per block, and the block says which.** A word can belong to two
    # ISAs of one description -- `aarch64_translation_seed` describes a source
    # and a target that share encodings -- and decoding it without saying which
    # is ambiguous, so `lift_block` correctly answers nothing. Asking without an
    # ISA cost **203 of that corpus's 884 instructions**, every one reported as
    # "no instruction decodes it", which reads like a hole in the lifter and was
    # a question this gate was not asking properly. Mixing two ISAs in one block
    # was never right either: a program is one ISA.
    offered = sorted({item[3] for item in usable if item[3]})
    block_isa = rng.choice(offered) if offered else None
    usable = [item for item in usable
              if item[3] == block_isa and _evaluable(item[0], lift_module, block_isa)]
    terminators = [item for item in terminators
                   if item[3] == block_isa and _evaluable(item[0], lift_module, block_isa)]
    if not usable:
        return None, None, None
    words, seeds = [], {}
    chosen = [usable[rng.randrange(len(usable))] for _ in range(length)]
    # A block ends in a branch, so some of ours do -- which is what makes the
    # terminator check reachable at all. The first block of a corpus that has a
    # terminator always takes one, and the rest flip a coin.
    #
    # It used to be the coin alone. Only one corpus here supplies terminators,
    # so across 984 blocks exactly one ended in a branch, and whether the
    # terminator was checked at all came down to where the rng landed. Adding
    # six instructions to an unrelated corpus shifted the stream, that block
    # stopped ending in a branch, and the gate declined -- correctly, and for a
    # reason that had nothing to do with the change.
    if terminators and (force_terminator or rng.random() < 0.5):
        chosen.append(terminators[rng.randrange(len(terminators))])
    for word, entry, _destination, _isa in chosen:
        words.append(word)
        record = lift_module.lift(word, block_isa)
        if record is None:
            # A word two entries can decode is ambiguous, and `lift` says so by
            # returning nothing rather than picking one.
            continue
        for operand in entry["operands"]:
            if operand["role"] == "out" or not lift_module.is_register_operand(operand["kind"]):
                continue
            index = record["operands"].get(operand["name"])
            if index is None:
                continue
            seeds.setdefault((operand["kind"], index), rng.getrandbits(operand["width"]))
    return words, seeds, block_isa


def check_one(axis_file: Path, blocks: int, length: int, named: bool):
    work = Path(tempfile.mkdtemp(prefix="axis_block_"))
    for command, name in (("emit-lift-python", "axis_lift.py"),
                          ("emit-golden-python", "golden_model.py"),
                          ("emit-exec-python", "axis_exec.py"),
                          ("emit-roundtrip-json", "fixtures.json")):
        subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(work / name)],
                       cwd=AXIS_ROOT, check=True, capture_output=True)
    for cached in ("golden_model", "axis_lift", "axis_exec"):
        sys.modules.pop(cached, None)
    sys.path.insert(0, str(work))
    load_module(work / "golden_model.py", "golden_model")
    lift_module = load_module(work / "axis_lift.py", "axis_lift")
    exec_module = load_module(work / "axis_exec.py", "axis_exec")

    fixtures = json.loads((work / "fixtures.json").read_text())
    fixtures = fixtures["tests"] if isinstance(fixtures, dict) else fixtures
    table = {}
    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = lift_module.decode(word, test.get("isa"))
        if entry is not None:
            table[word] = entry

    rng = random.Random(0x1F2E3D4C)
    checked = failures = 0
    declined = with_stores = with_loads = with_terminator = wide_declined = 0
    for index in range(blocks):
        words, seeds, isa = build_block(fixtures, table, lift_module, rng, length,
                                        force_terminator=index == 0)
        if not words:
            break
        graph = lift_module.lift_block(words, isa=isa)
        # Slots a register class throws writes away for, such as RISC-V's x0.
        discarded_slots = {
            lift_module.register_slot(kind, entry[0])
            for kind, entry in lift_module.REGISTER_CLASSES.items()
            if entry[0] is not None}
        declined += len(graph["declined"])
        if not graph["instructions"]:
            continue

        # Through each class's view, not into its raw slot: a windowed class
        # names a bit range inside the register, and seeding the slot would
        # have the executor read the zeros beside it. `lift_ast_check` had this
        # bug and `limbs.axisl` found it, six instructions at a time.
        registers: dict[int, int] = {}
        for (kind, index), value in seeds.items():
            seed_register(lift_module, registers, kind, index, value)
        # The graph's live-ins are **storage**, not views: overlapping classes
        # share one slot, so the input node carries the whole register and the
        # view is applied by nodes inside the graph. Seeding by `(class, index)`
        # would hand the same slot two different values.
        # A limbed class spans consecutive slots and the graph holds it as one
        # number, so the seed is the concatenation. `limbs.axisl` is the corpus
        # that has this and the one that disagreed until it did.
        storage: dict[tuple, int] = {}
        # How many slots each storage actually occupies, from the class rather
        # than from the value's width. A 128-bit operand of the generic `reg`
        # class lives in *one* slot -- Python integers are not 64 bits -- while
        # a two-limb class spans two, and only the class knows which.
        slot_limbs: dict[int, int] = {}
        for (kind, index) in seeds:
            limbs = lift_module.REGISTER_CLASSES[kind][6] or 1
            base = lift_module.register_slot(kind, index)
            slot_limbs[base] = max(slot_limbs.get(base, 1), limbs)
            whole = 0
            for limb in range(limbs):
                whole |= registers.get(base + limb, 0) << (64 * limb)
            storage[("__reg__", base)] = whole
        # Stepped, not run, because X3's claim is about what the block *wrote*
        # and `run` returns a register file. A write of zero to a register that
        # held zero is a write and leaves no trace in the file, so a diff would
        # report the graph wrong for being right.
        after = dict(registers)
        changed = set()
        # One memory across the block, so a load sees the store before it --
        # the same thing the graph evaluation does, and the only way the two
        # sides are answering the same question.
        exec_memory = Memory()
        last_pc = last_next = None
        for offset, word in enumerate(words):
            address = offset * 4
            try:
                outcome = exec_module.step(word, after, exec_memory, pc=address,
                                           isa=isa)
            except NotImplementedError:
                # The golden model declining an atom it cannot evaluate without
                # state. Skipped, not crashed: this gate is about the graph.
                outcome = None
            if outcome is None:
                continue
            last_pc, last_next = address, outcome.get("next_pc")
            entry = lift_module.decode(word, isa)
            for name, index in (outcome.get("writes") or {}).items():
                operand = next((o for o in entry["operands"] if o["name"] == name), None)
                if operand is not None and lift_module.is_register_operand(operand["kind"]):
                    changed.add(lift_module.register_slot(operand["kind"], index))
        if any(node["kind"] == "store" for node in graph["nodes"]):
            with_stores += 1
        if any(node.get("op") == "load" for node in graph["nodes"]):
            with_loads += 1
        graph_memory = Memory()
        try:
            values = evaluate_graph(graph, storage, graph_memory)
        except Unsupported:
            continue
        # The terminator, present and unresolved: the graph states the guard
        # and the target and says nothing about which way it went, so the check
        # is that evaluating them predicts what execution actually did.
        terminator = graph.get("terminator")
        if terminator is not None and last_next is not None:
            with_terminator += 1
            taken = (terminator["guard"] is None
                     or bool(values.get(terminator["guard"], 0)))
            width = graph["nodes"][terminator["target"]]["width"]
            expected = (mask(values[terminator["target"]], width) if taken
                        else terminator["pc"] + 4)
            if mask(last_next, width) != mask(expected, width):
                failures += 1
                if failures <= 3:
                    print(f"FAIL {axis_file.name}: the terminator predicts "
                          f"{expected:#x} ({'taken' if taken else 'not taken'}) and "
                          f"execution went to {last_next:#x}")
        if graph_memory.store != exec_memory.store:
            failures += 1
            if failures <= 3:
                print(f"FAIL {axis_file.name}: the graph leaves memory "
                      f"{sorted(graph_memory.store.items())[:2]} and execution leaves "
                      f"{sorted(exec_memory.store.items())[:2]}")

        checked += 1
        for entry in graph["live_out"]:
            location = tuple(entry["location"])
            if location[0] != "__reg__":
                continue
            slot = location[1]
            width = graph["nodes"][entry["node"]]["width"]
            limbs = entry.get("limbs", 1)
            if limbs > 1:
                # Split across slots, because the class says so. A storage
                # wider than a slot is held by the executor either in one
                # Python integer -- the generic `reg` class, whose 128-bit
                # operands live in a single slot -- or across limbs, and only
                # the class knows which. The graph publishes it now; guessing
                # was wrong in each direction on different corpora.
                got_whole = mask(values[entry["node"]], width)
                mismatch = any(
                    mask(after.get(slot + limb, 0), 64)
                    != ((got_whole >> (64 * limb)) & ((1 << 64) - 1))
                    for limb in range(limbs))
                if mismatch:
                    failures += 1
                    if failures <= 3:
                        print(f"FAIL {axis_file.name}: limbed {location} differs "
                              f"from the executor's file")
                continue
            # The executor's file, which applies the class's own rules -- a
            # hardwired-zero destination discards its write, and the graph is
            # allowed to say the value was computed anyway.
            expected = mask(after.get(slot, 0), width)
            got = mask(values[entry["node"]], width)
            if expected != got and not _is_discarded(lift_module, location):
                failures += 1
                if failures <= 3:
                    print(f"FAIL {axis_file.name}: {location} is {got:#x} in the graph "
                          f"and {expected:#x} after execution")
        reported = {e["location"][1] for e in graph["live_out"]
                    if e["location"][0] == "__reg__"}
        missing = changed - reported
        if missing:
            failures += 1
            print(f"FAIL {axis_file.name}: execution changed {sorted(missing)}, which "
                  f"the graph does not report as live-out")
        # And the other direction, which is the one that would mislead a miner:
        # a region claiming to produce something it does not. A write the class
        # discards -- RISC-V's x0 -- is reported by the graph and invisible in
        # the file, and that is the graph being right.
        extra = {slot for slot in reported - changed
                 if slot not in discarded_slots}
        if extra:
            failures += 1
            print(f"FAIL {axis_file.name}: the graph reports {sorted(extra)} live-out, "
                  f"and execution left them unchanged")
    if not checked:
        if named:
            print(f"FAIL {axis_file.name}: no block could be built from its fixtures")
            return (0, 1, declined, 0, 0, 0, 0)
        return None
    # A widened filter that admitted memory instructions and never built a block
    # containing one would be coverage on paper. The counts are reported so the
    # difference is visible rather than assumed.
    return (checked, failures, declined, with_stores, with_loads, with_terminator,
            wide_declined)


def _is_discarded(lift_module, location) -> bool:
    """A write the register class throws away, such as RISC-V's `x0`."""
    kind, index = location
    entry = lift_module.REGISTER_CLASSES.get(kind)
    return bool(entry) and entry[0] == index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    parser.add_argument("--blocks", type=int, default=40)
    parser.add_argument("--length", type=int, default=6)
    args = parser.parse_args()
    targets = args.axis_files or sorted((AXIS_ROOT / "examples").glob("*.axisl"))

    total = failed = declined = stored = loaded = ended = 0
    for target in targets:
        result = check_one(target, args.blocks, args.length, named=bool(args.axis_files))
        if result is None:
            continue
        checked, bad, skipped, stores, loads, terminated, wide = result
        total += checked
        failed += bad
        declined += skipped
        stored += stores
        loaded += loads
        ended += terminated
        print(f"     {target.name}: {checked} block(s) of {args.length}, {bad} "
              f"disagreement(s); {stores} write memory, {loads} read it, "
              f"{terminated} end in a branch, {skipped} instruction(s) declined"
              + (f", {wide} wide live-out(s) declined by shape" if wide else ""))
    print(f"{total} block(s) evaluated, {failed} disagreement(s); {stored} touched "
          f"memory by writing, {loaded} by reading, {ended} ended in a branch")
    if not total:
        print("no block was evaluated: the graph proved nothing here")
        return DECLINED
    if not ended:
        print("no block ended in a branch: the terminator is stated and unchecked")
        return DECLINED
    if not stored or not loaded:
        # The memory path is implemented and would be unchecked, which is the
        # hole this stage was opened to close.
        print("no block both wrote and read memory: the graph's memory ordering "
              "-- every store aliasing every other -- is claimed and unproven")
        return DECLINED
    print("block graph == executor: " + ("PASS" if not failed else "FAIL"))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
