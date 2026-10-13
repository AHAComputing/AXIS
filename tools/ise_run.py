#!/usr/bin/env python3
"""Put a mined extension in the program it was mined from, and run both.

`ise_mine.py` says a shape occurs; `ise_prove.py` that the proposal computes
what the shape's instructions compose to; `ise_cost.py` what the proposal
costs. None of them runs anything, and two things are still only claimed:

  * that the proposal's operands are the CODE's -- the proof composes the
    original from the candidate's own operand names, so a miner that binds two
    different values to one name is proved right;
  * that an occurrence is worth the chain it replaces -- which is true only if
    the instructions it covers can actually go, and they cannot when anything
    else reads what they wrote.

So this rewrites the program and runs it. For one extension at a time:

  1. **encode.** The proposal gets a real instruction word: an opcode no
     instruction of the description uses, found from the description's own
     decode table, and a field for each operand. An extension whose operands
     do not fit the word is declined by name -- that is a fact about the
     extension, and a ranking that ignored it ranked something unbuildable.
  2. **rewrite.** At each occurrence the root becomes the extension. A covered
     instruction is REMOVED only when every reader of what it wrote is itself
     covered and its register is dead where the function leaves; otherwise it
     stays, and the occurrence saves less than the count said. An occurrence
     is declined when an input it read early is overwritten before the root.
     Branches are re-encoded for the new layout, through the description's own
     field encoder.
  3. **run.** Both programs on the pack simulator built from the description
     plus the extension, same inputs. The results must be equal -- return
     value and every byte of data memory -- and the difference in cycles is
     the measurement.

What is specific to an architecture is the calling convention, in `ABIS`:
which registers carry arguments, which are live when a function returns. The
instruction encodings, the control flow and the register reads and writes all
come from the description.

Usage: tools/ise_run.py candidates.json proposals_dir program.o
           --call 'dot(buf:512,buf:512,60)' [--call ...] [--abi rv64]
           [--latency N] [--json out.json]

Arguments are integers or `buf:N`, a buffer of N pseudo-random bytes.
"""
from __future__ import annotations

import argparse
import importlib
import json
import math
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402
import ise_cost  # noqa: E402
from ise_mine import sections_of  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

# The one thing here a description does not say.
ABIS = {
    "rv64": {
        "kind": "rv_gpr",
        "arguments": [10, 11, 12, 13, 14, 15, 16, 17],
        "results": [10, 11],
        "return_address": 1,
        "stack": 2,
        # Live when a function returns, besides its results: the stack and
        # thread pointers, and everything the callee had to preserve.
        "preserved": [1, 2, 3, 4, 8, 9, *range(18, 28)],
    },
}

CODE, DATA, STACK, HALT, IMAGE = 0x1000, 0x10000, 0xF0000, 0xFFFF0, 1 << 20

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE %(image)du
static uint8_t MEMORY[IMAGE];

static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MEMORY[(a + i) %% IMAGE] << (8 * i);
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) MEMORY[(a + i) %% IMAGE] = (uint8_t)(v >> (8 * i));
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc != %(halt)du && pc + 4 <= IMAGE;
  return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u;
}
static uint64_t trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

typedef struct { int32_t slot; uint64_t value; } set_t;

static void run(const axis_sim_pack *S, const char *label, const uint32_t *words,
                int32_t count, uint64_t entry, const set_t *sets, int32_t n_sets) {
  memset(MEMORY, 0, sizeof MEMORY);
  /* The same bytes for both programs: a multiplicative generator, so no
     buffer is all zeros and a multiply by one is not a multiply by nothing. */
  uint64_t seed = 0x9E3779B97F4A7C15ull;
  for (uint32_t i = %(data)du; i < %(stack)du; ++i) {
    seed = seed * 6364136223846793005ull + 1442695040888963407ull;
    MEMORY[i] = (uint8_t)(seed >> 56);
  }
  for (int32_t i = 0; i < count; ++i)
    for (uint32_t b = 0; b < 4; ++b)
      MEMORY[%(code)du + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
  axis_pack_sim_hooks hooks = { rd, wr, fetch, trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("%%s NOMACHINE\n", label); return; }
  S->reset(m, entry, %(isa)s, NULL, 0);
  if (%(core)s && !S->select_core(m, %(core)s)) { printf("%%s NOCORE\n", label); S->destroy(m); return; }
  for (int32_t i = 0; i < S->register_slots(); ++i) S->set_reg(m, i, 0);
  for (int32_t i = 0; i < n_sets; ++i) S->set_reg(m, sets[i].slot, sets[i].value);
  S->count_cycles(m, 1);
  S->run(m, %(limit)dull);
  uint64_t sum = 1469598103934665603ull;
  for (uint32_t i = %(data)du; i < %(stack)du; ++i) sum = (sum ^ MEMORY[i]) * 1099511628211ull;
  printf("%%s pc %%llu result %%llu memory %%llu steps %%llu cycles %%llu\n", label,
         (unsigned long long)S->pc(m), (unsigned long long)S->reg(m, %(result)d),
         (unsigned long long)sum, (unsigned long long)S->steps(m),
         (unsigned long long)S->cycles(m));
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->count_cycles || !S->cycles) { printf("NOCYCLES\n"); return 0; }
%(runs)s
  return 0;
}
"""


def axis(command: str, axis_file: Path, out: Path | None = None) -> str:
    args = [*axis_prefix(), command, str(axis_file)] + (["-o", str(out)] if out else [])
    return subprocess.run(args, capture_output=True, text=True, check=True, cwd=AXIS_ROOT).stdout


# --- 1. an encoding ---------------------------------------------------------

def free_opcode(table: list, isa: str | None):
    """(mask, value) of the bits every full-width instruction fixes, set to a
    value no instruction of the description can decode as."""
    entries = [e for e in table if isa is None or e.get("isa") in (None, isa)]
    width = max(e["bits"] for e in entries)
    common = (1 << width) - 1
    for entry in entries:
        if entry["bits"] == width:
            common &= int(entry["mask"], 16)
    if common == 0 or common & (common + 1):
        return None             # nothing, or not one field in the low bits
    for value in range(common + 1):
        clash = any((int(e["match"], 16) ^ value) & int(e["mask"], 16) & common == 0
                    for e in entries)
        if not clash:
            return common, value, width
    return None


def encoded_instruction(name: str, proposal: str, candidate: dict, site: dict,
                        table: list, isa: str | None, latency: int):
    """The proposal as an instruction of the base description, with a format
    of its own, or the reason it has none."""
    opcode = free_opcode(table, isa)
    if opcode is None:
        return None, "the description has no free opcode"
    common, value, width = opcode
    kind = site["rd"]["kind"]
    # A register field is wide enough for every register an occurrence names.
    selector = max(max(i["register"] for i in s["inputs"] + [s["rd"]])
                   for s in candidate["sites"])
    register_bits = max(5, selector.bit_length())
    reg_width = re.search(r"\(rd reg i(\d+) out\)", proposal).group(1)
    operands = [("rd", register_bits, f"(rd {kind} i{reg_width} out)")]
    operands += [(op, register_bits, f"({op} {kind} i{reg_width} in)")
                 for op in candidate["operands"]]
    operands += [(op, bits, f"({op} imm i{bits} in)") for op, bits in candidate["immediates"]]
    low = common.bit_length()
    needed = sum(bits for _n, bits, _d in operands)
    if low + needed > width:
        return None, (f"{needed} operand bits and a {low}-bit opcode do not fit "
                      f"a {width}-bit word")
    fields, at = [f"(op {low - 1} 0)"], low
    for operand, bits, _decl in operands:
        fields.append(f"({operand} {at + bits - 1} {at})")
        at += bits
    fixed = ""
    if at < width:
        fields.append(f"(fn {width - 1} {at})")
        fixed = " (fn 0)"
    behavior = re.search(r"\(behavior .*\)\n", proposal).group(0).strip()
    mnemonic = name.upper()
    isa_line = f"(isa {isa})" if isa else ""
    text = f"""
  (defformat ISE_{mnemonic}
    (bits {width})
    (fields {' '.join(fields)}))

  (definstruction {name}
    (mnemonic {mnemonic})
    {isa_line}
    (category custom)
    (format ISE_{mnemonic})
    (opcode 0) (func3 0) (func7 0)
    (encoding (op {value}){fixed})
    (operands
      {' '.join(decl for _n, _b, decl in operands)})
    (semantics "mined from a real binary")
    {behavior}
    (latency {latency})
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
    (rationale "Candidate mined by ise_mine.py; run by ise_run.py"))
"""
    return text, ""


# --- 2. the program, and its rewrite ------------------------------------------

class Instruction:
    __slots__ = ("pc", "word", "entry", "reads", "writes", "target", "conditional", "leaves",
                 "offset_operand", "offset_bits")

    def __init__(self, pc, word, entry, lift):
        self.pc, self.word, self.entry = pc, word, entry
        self.reads, self.writes = set(), set()
        for op in entry["operands"]:
            if not lift.is_register_operand(op["kind"]) or not op["fields"]:
                continue
            slot = lift.register_slot(op["kind"], lift._extract(word, op["fields"]))
            if op.get("role") in ("in", "inout"):
                self.reads.add(slot)
            if op.get("role") in ("out", "inout"):
                self.writes.add(slot)
        # Control flow, from the effects: a `setpc` to `pc + sext(imm)` goes
        # somewhere this file can see, and any other `setpc` leaves it.
        self.target = self.offset_operand = self.offset_bits = None
        self.conditional = self.leaves = False
        for effect in entry.get("effects") or []:
            if effect.get("kind") != "setpc":
                continue
            tree = effect.get("value_ast") or {}
            args = tree.get("args", [])
            relative = (tree.get("op") == "add" and len(args) == 2
                        and args[0].get("symbol") == "pc" and args[1].get("op") == "sext")
            if not relative:
                self.leaves = True
                continue
            bits, operand = int(args[1]["args"][0]["const"]), args[1]["args"][1]["symbol"]
            raw = lift._extract(word, next(op["fields"] for op in entry["operands"]
                                           if op["name"] == operand))
            self.offset_operand, self.offset_bits = operand, bits
            self.target = pc + (raw - (1 << bits) if raw >> (bits - 1) else raw)
            self.conditional = "guard" in effect


def mentions_pc(node) -> bool:
    if isinstance(node, dict):
        return node.get("symbol") == "pc" or any(mentions_pc(a) for a in node.get("args", []))
    return False


def function_of(image: bytes, base: int, start: int, end: int, lift, isa, sizes):
    """The function's instructions, or the reason it cannot be rewritten."""
    body = []
    for pc in range(start, end, 4):
        word = int.from_bytes(image[pc - base:pc - base + 4], "little")
        entry = lift.decode(word, isa)
        if entry is None:
            return None, f"a word at {pc:#x} the description does not cover"
        if sizes.get(entry["mnemonic"], 32) != 32:
            return None, f"a short instruction at {pc:#x}; the rewriter lays out whole words"
        instruction = Instruction(pc, word, entry, lift)
        effects = entry.get("effects") or []
        links = any(e.get("kind") == "set" and mentions_pc(e.get("value_ast")) for e in effects)
        if links and not instruction.leaves:
            if instruction.target is not None and instruction.writes - {0}:
                return None, f"a call at {pc:#x}"
            if instruction.target is None:
                return None, f"a pc-relative value at {pc:#x}"
        if instruction.target is not None and not start <= instruction.target < end:
            return None, f"a jump out of the function at {pc:#x}"
        body.append(instruction)
    return body, ""


def successors(body, index):
    instruction = body[index]
    if instruction.leaves:
        return []
    after = []
    if instruction.target is not None:
        after.append((instruction.target - body[0].pc) // 4)
        if not instruction.conditional:
            return after
    if index + 1 < len(body):
        after.append(index + 1)
    return after


def readers_of(body, index, slot, live_at_return):
    """Every instruction that can read what `body[index]` wrote to `slot`, and
    whether that value is still there when the function is left."""
    readers, escapes, seen = set(), False, set()
    stack = list(successors(body, index))
    if body[index].leaves:
        escapes = slot in live_at_return
    while stack:
        at = stack.pop()
        if at in seen:
            continue
        seen.add(at)
        instruction = body[at]
        if slot in instruction.reads:
            readers.add(at)
        if instruction.leaves:
            escapes = escapes or slot in live_at_return
            continue
        if slot in instruction.writes:
            continue
        following = successors(body, at)
        if not following:
            escapes = True      # runs off the end: nothing is known past it
        stack.extend(following)
    return readers, escapes


def rewrite(body, sites, extension, lift, live_at_return, zero_slots):
    """The function with the extension at each occurrence that can take it.
    Returns the new words, where the entry moved to, and what happened at each
    occurrence."""
    index_of = {instruction.pc: i for i, instruction in enumerate(body)}
    removed, replaced, report = set(), {}, []
    for site in sorted(sites, key=lambda s: s["covers"][-1]):
        covers = [index_of[pc] for pc in site["covers"]]
        root = covers[-1]
        if any(i in removed or i in replaced for i in covers):
            report.append((site, 0, "overlaps an occurrence already rewritten"))
            continue
        # What can go: a covered instruction all of whose readers are the
        # root or covered instructions that are going too.
        going = set(covers[:-1])
        changed = True
        while changed:
            changed = False
            for i in sorted(going):
                for slot in body[i].writes - zero_slots:
                    readers, escapes = readers_of(body, i, slot, live_at_return)
                    if escapes or not readers <= going | {root}:
                        going.discard(i)
                        changed = True
                        break
        # What the extension reads at the root must be what the covered
        # instruction read where it stood.
        clobbered = None
        for operand in site["inputs"]:
            slot = lift.register_slot(operand["kind"], operand["register"])
            for pc in operand["read_at"]:
                for i in range(index_of[pc], root):
                    if i not in going and slot in body[i].writes:
                        clobbered = (operand["register"], body[i].pc)
        if clobbered:
            report.append((site, 0, f"register {clobbered[0]} is overwritten at "
                                    f"{clobbered[1]:#x}, before the root reads it"))
            continue
        word = int(extension["match"])
        word = lift.place_operand(word, extension, "rd", site["rd"]["register"])
        for position, operand in enumerate(site["inputs"]):
            word = lift.place_operand(word, extension, f"a{position}", operand["register"])
        for position, value in enumerate(site["immediates"]):
            word = lift.place_operand(word, extension, f"k{position}", value)
        replaced[root] = word
        removed |= going
        kept = len(covers) - 1 - len(going)
        report.append((site, len(going), f"{kept} covered instruction(s) stay: something "
                                         f"else reads what they wrote" if kept else ""))

    # The layout, then every relative transfer re-aimed through it. A target
    # that was removed is the next instruction that was not.
    new_pc, at = {}, body[0].pc
    for i in range(len(body)):
        new_pc[i] = at
        if i not in removed:
            at += 4
    words = []
    for i, instruction in enumerate(body):
        if i in removed:
            continue
        word = replaced.get(i, instruction.word)
        if i not in replaced and instruction.target is not None:
            offset = new_pc[index_of[instruction.target]] - new_pc[i]
            bits = instruction.offset_bits
            if not -(1 << (bits - 1)) <= offset < 1 << (bits - 1):
                raise RuntimeError(f"a branch at {instruction.pc:#x} no longer reaches")
            word = lift.place_operand(word, instruction.entry, instruction.offset_operand,
                                      offset & ((1 << bits) - 1))
        words.append(word)
    return words, report


# --- 3. the run -----------------------------------------------------------------

def symbols_of(path: Path) -> dict:
    tool = shutil.which("llvm-nm") or "/opt/homebrew/opt/llvm/bin/llvm-nm"
    if not Path(tool).exists() and not shutil.which(tool):
        tool = "nm"
    listing = subprocess.run([tool, "--numeric-sort", "--defined-only", str(path)],
                             capture_output=True, text=True, check=True).stdout
    found = [(int(parts[0], 16), parts[2]) for parts in map(str.split, listing.splitlines())
             if len(parts) == 3 and parts[1] in "Tt"]
    return {name: (start, found[i + 1][0] if i + 1 < len(found) else None)
            for i, (start, name) in enumerate(found)}


def parse_call(text: str):
    match = re.fullmatch(r"\s*(\w+)\((.*)\)\s*", text)
    if not match:
        raise SystemExit(f"--call wants `name(arg, ...)`, not `{text}`")
    arguments, at = [], DATA
    for item in filter(None, (a.strip() for a in match.group(2).split(","))):
        if item.startswith("buf:"):
            arguments.append(at)
            at += (int(item[4:]) + 15) & ~15
        else:
            arguments.append(int(item, 0) & (1 << 64) - 1)
    return match.group(1), arguments


def simulate(pack_root: Path, manifest: dict, isa, abi, lift, runs, work: Path, tag: str,
             core: str | None = None):
    """`runs` is (label, words, argument values). Returns label -> measurements."""
    blocks = []
    for number, (label, words, arguments) in enumerate(runs):
        sets = [(lift.register_slot(abi["kind"], abi["arguments"][i]), value)
                for i, value in enumerate(arguments)]
        sets += [(lift.register_slot(abi["kind"], abi["return_address"]), HALT),
                 (lift.register_slot(abi["kind"], abi["stack"]), STACK)]
        blocks.append(
            f"  {{ static const uint32_t W[] = {{ {', '.join(f'{w}u' for w in words)} }};\n"
            f"    static const set_t R[] = {{ "
            + ", ".join(f"{{ {slot}, {value}ull }}" for slot, value in sets) + " };\n"
            f"    run(S, \"{label}\", W, {len(words)}, {CODE}u, R, {len(sets)}); }}")
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"], "image": IMAGE, "halt": HALT,
        "data": DATA, "stack": STACK, "code": CODE, "limit": 10_000_000,
        "isa": f'"{isa}"' if isa else "NULL",
        "core": f'"{core}"' if core else "0",
        "result": lift.register_slot(abi["kind"], abi["results"][0]),
        "runs": "\n".join(blocks)}
    (work / f"{tag}.c").write_text(source)
    subprocess.run(["cc", "-std=c11", "-O1", "-I", str(pack_root / "include"),
                    "-o", str(work / tag), str(work / f"{tag}.c"),
                    str(pack_root / "lib" / manifest["libraries"]["sim"]["static"]),
                    str(pack_root / "lib" / manifest["libraries"]["exec"]["static"])],
                   check=True, capture_output=True, text=True)
    done = subprocess.run([str(work / tag)], capture_output=True, text=True)
    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 11:
            said[parts[0]] = {parts[i]: int(parts[i + 1]) for i in range(1, 11, 2)}
    return said


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("candidates", type=Path)
    parser.add_argument("proposals", type=Path)
    parser.add_argument("program", type=Path)
    parser.add_argument("--call", action="append", required=True)
    parser.add_argument("--abi", default="rv64", choices=sorted(ABIS))
    parser.add_argument("--latency", type=int, default=None,
                        help="cycles the extension takes; by default the fewest its "
                             "netlist's depth fits in")
    parser.add_argument("--results", type=int, default=None,
                        help="how many result registers the called functions return in; "
                             "by default every one the convention has, which keeps an "
                             "instruction whose value might be a second result")
    parser.add_argument("--top", type=int, default=None,
                        help="run only the first N proposals")
    parser.add_argument("--json", type=Path, default=None)
    args = parser.parse_args()
    if args.results is None:
        args.results = len(ABIS[args.abi]["results"])

    report = json.loads(args.candidates.read_text())
    description = Path(report["description"])
    if not description.is_absolute():
        description = AXIS_ROOT / description
    isa, abi = report.get("isa"), ABIS[args.abi]
    base_text = description.read_text()
    work = Path(tempfile.mkdtemp(prefix="axis_iserun_"))
    table = json.loads(axis("emit-decode-json", description))["instructions"]
    base_plan = ise_cost.hw_plan(description)
    budget = base_plan["cost_model"]["cycle_budget"]
    bodies = ise_cost.reference_bodies(base_text)

    images = {f"{args.program.name}:{name}": (data, base)
              for name, data, base in sections_of(args.program)}
    symbols = symbols_of(args.program)
    calls = [parse_call(text) for text in args.call]

    rows, ran, unequal = [], 0, 0
    proposals = sorted(args.proposals.glob("mined*.axisl"),
                       key=lambda p: int(re.search(r"\d+", p.stem).group()))
    for path in proposals[:args.top]:
        candidate = report["candidates"][int(re.search(r"\d+", path.stem).group())]
        label = "+".join(candidate["mnemonics"])
        if candidate.get("state"):
            print(f"  DECLINE {label}: reads state, and the rewriter places registers")
            continue
        entry, _costed = ise_cost.alone(path, path.stem.upper(), bodies, work)
        if not entry or entry["status"] != "built":
            print(f"  DECLINE {label}: no netlist to take a latency from")
            continue
        latency = args.latency or max(1, math.ceil(entry["depth"] / budget))
        sites = [s for s in candidate["sites"] if s["image"] in images]
        if not sites:
            continue
        text, why = encoded_instruction(path.stem, path.read_text(), candidate, sites[0],
                                        table, isa, latency)
        if text is None:
            print(f"  DECLINE {label}: {why}")
            continue

        # The description plus the extension, and everything built from that.
        name = f"{description.stem}_{path.stem}"
        extended = work / f"{name}.axisl"
        clock = report.get("clock")
        # On the miner's as-built clock the program runs on that machine: a
        # core giving every instruction its netlist's floor, the extension's
        # included.
        timed = (f"  (defcore {clock['core']} (kind rvmt) (cycle (gates {clock['cycle_gates']})) "
                 f"(timing (latency (* derived))))\n") if clock else ""
        extended.write_text(base_text.rstrip()[:-1] + text + timed + ")\n")
        try:
            axis("check", extended)
        except subprocess.CalledProcessError as error:
            print(f"  DECLINE {label}: AXIS does not accept it encoded "
                  f"({error.stderr.strip().splitlines()[0][:90]})")
            continue
        manifest = build_pack.build(extended, work / "packs", only={"sim", "exec", "lift"})
        axis("emit-lift-python", extended, work / f"lift_{name}.py")
        sys.path.insert(0, str(work))
        lift = importlib.import_module(f"lift_{name}")
        decoded = json.loads(axis("emit-decode-json", extended))["instructions"]
        sizes = {e["mnemonic"]: e["bits"] for e in decoded}
        extension = next(e for e in decoded if e["mnemonic"] == path.stem.upper())
        extension = lift.decode(int(extension["match"], 16), isa)
        live = {lift.register_slot(abi["kind"], r)
                for r in abi["preserved"] + abi["results"][:args.results]}

        runs, notes, static = [], {}, {}
        for function, arguments in calls:
            if function not in symbols:
                raise SystemExit(f"{args.program.name} defines no `{function}`")
            start, end = symbols[function]
            image, (data, base) = next(
                (n, v) for n, v in images.items() if v[1] <= start < v[1] + len(v[0]))
            end = end if end is not None else base + len(data)
            body, why = function_of(data, base, start, end, lift, isa, sizes)
            if body is None:
                notes[function] = f"not rewritten: {why}"
                continue
            here = [s for s in sites if s["image"] == image
                    and start <= s["covers"][0] and s["covers"][-1] < end]
            words, outcome = rewrite(body, here, extension, lift, live, set())
            static[function] = (len(body), len(words), outcome)
            runs.append((f"{function}.before", [i.word for i in body], arguments))
            runs.append((f"{function}.after", words, arguments))
        said = simulate(work / "packs" / manifest["name"], manifest, isa, abi, lift, runs,
                        work, name, clock["core"] if clock else None)

        print(f"  {path.stem}: {label}, at {latency} cycle(s)")
        row = {"proposal": path.stem, "replaces": candidate["mnemonics"],
               "latency": latency, "functions": []}
        for function, _arguments in calls:
            if function in notes:
                print(f"    {function}: {notes[function]}")
                continue
            was, now, outcome = static[function]
            taken = [o for o in outcome if o[1] or not o[2].startswith(("overlaps", "register"))]
            if not any(site for site, _gone, why in outcome
                       if not why.startswith(("overlaps", "register"))):
                for site, _gone, why in outcome:
                    print(f"    {function}: an occurrence at {site['covers'][-1]:#x} is "
                          f"left as it is -- {why}")
                continue
            before, after = said.get(f"{function}.before"), said.get(f"{function}.after")
            if not before or not after:
                print(f"    FAIL {function}: the simulator did not run it")
                unequal += 1
                continue
            same = all(before[k] == after[k] for k in ("result", "memory")) \
                and before["pc"] == after["pc"] == HALT
            ran += 1
            unequal += not same
            saved = before["cycles"] - after["cycles"]
            print(f"    {function}: {was} -> {now} instruction(s); "
                  f"{before['steps']} -> {after['steps']} executed, "
                  f"{before['cycles']} -> {after['cycles']} cycle(s), "
                  f"{saved / before['cycles']:.1%} fewer"
                  + ("" if same else "  ⚠️ AND A DIFFERENT RESULT"))
            for site, gone, why in outcome:
                if why:
                    print(f"      at {site['covers'][-1]:#x}: {why}")
            # What one occurrence was worth when it ran, beside what the
            # ranking said: the chain less the extension's latency. They
            # differ whenever the machine overlaps the latency with work that
            # does not wait for it, which a count cannot know.
            placed = [(site, gone) for site, gone, why in outcome
                      if not why.startswith(("overlaps", "register"))]
            dropped = before["steps"] - after["steps"]
            if len(placed) == 1 and placed[0][1] and dropped:
                times = dropped // placed[0][1]
                said_so = max(candidate["critical_path_cycles"] - latency, 0)
                print(f"      it ran {times} time(s) and saved {saved / times:.1f} cycle(s) "
                      f"each; the chain less the latency is {said_so}")
            row["functions"].append({
                "name": function, "instructions": [was, now], "equal": same,
                "steps": [before["steps"], after["steps"]],
                "cycles": [before["cycles"], after["cycles"]],
                "occurrences": [{"root": site["covers"][-1], "removed": gone, "note": why}
                                for site, gone, why in outcome]})
        rows.append(row)

    if args.json:
        args.json.write_text(json.dumps({"schema": "axis.ise-runs.v1",
                                         "description": str(description),
                                         "program": str(args.program),
                                         "extensions": rows}, indent=2))
    print(f"{ran} function run(s) with an extension in them, {unequal} with a different result")
    if ran == 0:
        print("mined extensions, run in the program: DECLINED -- nothing could be rewritten")
        return DECLINED
    ok = unequal == 0
    print("mined extensions, run in the program: " + ("PASS" if ok else "FAIL"))
    return PASSED if ok else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
