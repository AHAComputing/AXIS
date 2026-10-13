#!/usr/bin/env python3
"""Differential check: the generated C executor at 64 bits vs the golden model.

`tools/exec_c_check.py` drives the compact 32-bit ABI and skips any instruction
whose operands or state are wider. That skip was written as "belongs to the
separately checked wide executor", and for AArch64 it does -- but the wide check
was `aarch64_native_state_check.py`, which drives hand-written cases for one
architecture. Everything else wide simply went unexecuted: RV64I's 216
instructions, SVE's 76, RVV's, and every block-memory instruction.

The emitted header has always had the general entry point --
`axis_exec_step64(word, isa, regs, reg_count, mem, pc, state)` -- so nothing
needed generating. What was missing was a driver that is not AArch64-shaped.
This is that driver: it runs the same roundtrip fixtures the compact check does,
through the 64-bit ABI, against the same golden model.

Both pure semantics and effects. The effect path is the reason the wide ABI
exists at all: it is the one that carries architectural *state*, which the
compact ABI has no room for, so instructions that read or write state have never
been executed by a generated executor outside AArch64.

A decline is not a disagreement: an instruction the executor has no lowering
for is counted and named rather than failed, or the gate could only pass by the
executor growing features. But the C executor now declines *nothing* on every
corpus this ladder gates, so that is checked -- `--max-declines` defaults to 0
for C and to unlimited for Rust, which declines the floating-point environment
by design.

Usage: tools/exec_wide_check.py <input.axisl> [--cases N] [--max-declines N]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# Uniform 64-bit noise reaches an IEEE-754 class about as often as it
# reaches a specific integer, so a share of each register is drawn from the
# values that decide floating-point behaviour instead. The double-rounding
# witnesses are the reason this list exists: converting an integer to a
# float through a double rounds twice, and 9223372586610589697 is one unit
# above the midpoint between two binary32 values -- it rounds up, but
# rounding to a double's 53 bits lands it exactly *on* the midpoint, where
# ties-to-even takes it back down. Every backend agreed on the wrong answer,
# and no uniform draw would ever have said so: the window is one in 2**39.
INTERESTING = (
    # binary64 classes, and binary32 classes in the low half.
    0x0000000000000000, 0x8000000000000000, 0x3ff0000000000000,
    0xbff0000000000000, 0x7ff0000000000000, 0xfff0000000000000,
    0x7ff8000000000000, 0x7ff0000000000001, 0x7fefffffffffffff,
    0x0010000000000000, 0x0000000000000001,
    0xffffffff3f800000, 0xffffffff7f800000, 0xffffffff7fc00000,
    0xffffffff7f800001, 0xffffffff00800000, 0xffffffffff800000,
    # Integers at the conversion boundaries: the largest and smallest that
    # fit each destination, and one past each.
    0x000000007fffffff, 0x0000000080000000, 0xffffffff80000000,
    0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff,
    # Double-rounding witnesses, signed and unsigned, and their negations.
    9223372586610589697, 4611686293305294849,
    (-4611686293305294849) & 0xffffffffffffffff,
    9223372586610589697 ^ 0x8000000000000000,
)


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class Mem:
    """The reference memory the golden evaluation runs against.

    Addresses wrap. The executors compute them in a 64-bit register and so do
    that for free; this model held Python integers, which do not, and a base
    near the top of the space plus a positive offset became a key no read could
    match -- the seeded cell was there, at the address before it overflowed, and
    the load returned zero. Masking here rather than at the two call sites: the
    wrap is a property of the address space, not of one caller.
    """

    ADDRESS_BITS = 64

    def __init__(self, init=None):
        self.store = {(self._wrap(addr), width): value
                      for (addr, width), value in dict(init or {}).items()}

    @classmethod
    def _wrap(cls, addr):
        return addr & ((1 << cls.ADDRESS_BITS) - 1)

    def read(self, addr, width):
        return self.store.get((self._wrap(addr), width), 0)

    def write(self, addr, value, width):
        self.store[(self._wrap(addr), width)] = value & ((1 << width) - 1)


def register_slot(kind: str, index: int, axis_lift) -> int:
    """Where a register lands in the flat file, from the generated table."""
    return axis_lift.register_slot(kind, index)


def register_slots(kind: str, index: int, axis_lift):
    """Every slot the register occupies.

    A class whose registers are wider than a machine word holds each one in
    consecutive slots. Seeding only the first leaves the rest zero, and a view
    living above the first slot would then read a constant -- which is exactly
    the case a limb implementation can get wrong while every check passes.
    """
    base = axis_lift.register_slot(kind, index)
    return range(base, base + axis_lift.REGISTER_CLASSES[kind][6])



def render_c(case: dict) -> str:
    """One case as C, driving axis_exec_step64."""
    mn = case["mnemonic"]
    body = ""
    if case.get("result") is not None:
        mask = (1 << case.get("result_width", 64)) - 1
        body += (f'    if ((res.result & UINT64_C({mask})) '
                 f'!= UINT64_C({case["result"]})) {{ '
                 f'printf("FAIL {mn} result\\n"); failures++; }}\n')
    for slot, value in case["reg_checks"]:
        body += (f'    if (regs[{slot}] != UINT64_C({value})) {{ '
                 f'printf("FAIL {mn} reg slot {slot} want %llu got %llu\\n", '
                 f'(unsigned long long)UINT64_C({value}), (unsigned long long)regs[{slot}]); '
                 f'failures++; }}\n')
    for addr, width, value in case["mem_checks"]:
        body += (f'    if (mem_read(&ctx, UINT64_C({addr}), {width}u) != UINT64_C({value})) {{ '
                 f'printf("FAIL {mn} mem addr {addr} w{width} want %llu got %llu\\n", '
                 f'(unsigned long long)UINT64_C({value}), '
                 f'(unsigned long long)mem_read(&ctx, UINT64_C({addr}), {width}u)); '
                 f'failures++; }}\n')
    if case["state_write"] is not None:
        name, value = case["state_write"]
        # Expected and actual, not just the category: a state disagreement
        # that names only the instruction says nothing about which of the two
        # is wrong, and these are flag words where the difference is the whole
        # finding.
        body += (f'    if (res.state_name == NULL || strcmp(res.state_name, "{name}") != 0 '
                 f'|| res.state_value != UINT64_C({value})) {{ '
                 f'printf("FAIL {mn} state {name} want %llu got %llu (%s)\\n", '
                 f'(unsigned long long)UINT64_C({value}), '
                 f'(unsigned long long)res.state_value, '
                 f'res.state_name ? res.state_name : "none"); '
                 f'failures++; }}\n')
    if case["next_pc"] is not None:
        body += (f'    if (res.next_pc != UINT64_C({case["next_pc"]})) {{ '
                 f'printf("FAIL {mn} next_pc\\n"); failures++; }}\n')
    if case["trap"] is None:
        body += f'    if (res.trapped) {{ printf("FAIL {mn} spurious trap\\n"); failures++; }}\n'
    else:
        body += (f'    if (!res.trapped || strcmp(res.trap_cause, "{case["trap"]}") != 0) {{ '
                 f'printf("FAIL {mn} trap\\n"); failures++; }}\n')

    init = "{" + ",".join(f"UINT64_C({v})" for v in case["regs"]) + "}"
    cells = ",".join(f"{{UINT64_C({a}),{w}u,UINT64_C({v})}}" for a, w, v in case["seed"])
    entries = ",".join(f'{{"{n}",UINT64_C({v}),{w}u}}' for n, v, w in case["state"])
    return (
        f'  {{ uint64_t regs[] = {init};\n'
        f'    static memctx ctx = {{ {{{cells}}}, {len(case["seed"])} }};\n'
        f'    axis_mem64 M = {{ mem_read, mem_write, &ctx }};\n'
        f'    axis_state64_entry entries[] = {{{entries or "{0}"}}};\n'
        f'    axis_state64 st = {{ entries, {len(case["state"])} }};\n'
        f'    axis_exec_result64 res = axis_exec_step64({case["word"]}u, '
        f'{json.dumps(case["isa"])}, regs, {case["slots"]}, &M, '
        f'UINT64_C({case["pc"]}), &st);\n'
        f'    checks++;\n'
        f'    if (!res.ok) {{ declined++; printf("DECLINE {mn}\\n"); }} else {{\n{body}    }}\n  }}\n'
    )


def render_rust(case: dict) -> str:
    """The same case as Rust, driving step64.

    Deliberately generated from the same reference data as the C one. The hard
    part of this check is the *reference* -- sequencing effects, keeping only
    surviving writes, honouring the hardwired zero register -- and two copies of
    that would be two things to keep in agreement.
    """
    mn = case["mnemonic"]
    body = ""
    if case.get("result") is not None:
        # Masked to the destination's width, for the same reason the C
        # renderer does it: the executor reports the expression, the
        # architecture writes the window.
        mask = (1 << case.get("result_width", 64)) - 1
        body += (f'        if r.result.map(|v| v & {mask}u64) '
                 f'!= Some({case["result"]}u64) {{ '
                 f'println!("FAIL {mn} result"); failures += 1; }}\n')
    for slot, value in case["reg_checks"]:
        # The slot and both values, as the C twin prints them: "reg" alone
        # said which instruction and nothing about which register.
        body += (f'        if regs[{slot}] != {value}u64 {{ '
                 f'println!("FAIL {mn} reg slot {slot} want {value} got {{}}", regs[{slot}]); '
                 f'failures += 1; }}\n')
    for addr, width, value in case["mem_checks"]:
        body += (f'        if mem.read64({addr}u64, {width}u32) != {value}u64 {{ '
                 f'println!("FAIL {mn} mem"); failures += 1; }}\n')
    if case["state_write"] is not None:
        name, value = case["state_write"]
        body += (f'        match &r.state_write {{ Some((n, v)) if *n == "{name}" '
                 f'&& *v == {value}u64 => {{}}, _ => {{ '
                 f'println!("FAIL {mn} state"); failures += 1; }} }}\n')
    if case["next_pc"] is not None:
        body += (f'        if r.next_pc != {case["next_pc"]}u64 {{ '
                 f'println!("FAIL {mn} next_pc"); failures += 1; }}\n')
    if case["trap"] is None:
        body += (f'        if r.trap.is_some() {{ '
                 f'println!("FAIL {mn} spurious trap"); failures += 1; }}\n')
    else:
        body += (f'        if r.trap != Some("{case["trap"]}") {{ '
                 f'println!("FAIL {mn} trap"); failures += 1; }}\n')

    init = ",".join(f"{v}u64" for v in case["regs"])
    cells = ",".join(f"(({a}u64,{w}u32),{v}u64)" for a, w, v in case["seed"])
    entries = ",".join(f'State64Entry {{ name: "{n}", value: {v}u64, width: {w}u32 }}'
                       for n, v, w in case["state"])
    isa = f'Some("{case["isa"]}")' if case["isa"] else "None"
    return (
        f'    {{\n'
        f'        let mut regs: Vec<u64> = vec![{init}];\n'
        f'        let mut mem = Cells::new(vec![{cells}]);\n'
        f'        let mut st: Vec<State64Entry> = vec![{entries}];\n'
        f'        let r = step64({case["word"]}u32, {isa}, &mut regs, &mut mem, '
        f'{case["pc"]}u64, &mut st);\n'
        f'        checks += 1;\n'
        f'        if !r.ok {{ declined += 1; println!("DECLINE {mn}"); }} else {{\n{body}        }}\n'
        f'    }}\n'
    )


def build_and_run(cases: list, workdir, axis_file, lang: str):
    """Compile the generated executor around these cases and run it.

    Shared with `limb_check.py`, which drives the same executors from a
    different reference. The half worth reusing is this one -- emitting,
    concatenating and compiling -- while the half worth keeping separate is
    the reference that decides what the answers should be.
    """
    if lang == "rust":
        emit(axis_file, "emit-lift-rust", workdir / "axis_lift.rs")
        emit(axis_file, "emit-semantics-rust", workdir / "axis_semantics.rs")
        emit(axis_file, "emit-exec-rust", workdir / "axis_exec.rs")
        driver = workdir / "driver.rs"
        # Concatenated rather than moduled, as the compact Rust check does: the
        # generated files are written as one flat crate.
        driver.write_text(
            (workdir / "axis_semantics.rs").read_text() + "\n"
            + (workdir / "axis_lift.rs").read_text() + "\n"
            + (workdir / "axis_exec.rs").read_text() + "\n\n"
            + "struct Cells { cells: Vec<((u64, u32), u64)> }\n"
            + "impl Cells {\n"
            + "    fn new(cells: Vec<((u64, u32), u64)>) -> Self { Cells { cells } }\n"
            + "}\n"
            + "impl WideMemory for Cells {\n"
            + "    fn read64(&mut self, addr: u64, width: u32) -> u64 {\n"
            + "        self.cells.iter().find(|((a, w), _)| *a == addr && *w == width)\n"
            + "            .map_or(0, |(_, v)| *v)\n    }\n"
            + "    fn write64(&mut self, addr: u64, value: u64, width: u32) {\n"
            + "        let masked = if width >= 64 { value } else { value & ((1u64 << width) - 1) };\n"
            + "        if let Some(cell) = self.cells.iter_mut()\n"
            + "            .find(|((a, w), _)| *a == addr && *w == width) { cell.1 = masked; }\n"
            + "        else { self.cells.push(((addr, width), masked)); }\n    }\n}\n\n"
            + "fn main() {\n    let mut checks = 0; let mut failures = 0; let mut declined = 0;\n"
            + "".join(render_rust(case) for case in cases)
            + '    println!("{} executed at 64 bits, {} declined, {} failures",\n'
              "             checks - declined, declined, failures);\n"
            "    if failures > 0 { std::process::exit(1); }\n}\n"
        )
        binary = workdir / "driver"
        subprocess.run(
            ["rustc", "--edition", "2021", "-A", "warnings", "--cfg", "axis_impl_stubs", "-o", str(binary),
             str(driver)],
            check=True, cwd=workdir,
        )
    else:
        driver = workdir / "driver.c"
        # ⚠️ Sized by the cases and STATIC per case. The table was 64 cells,
        # too few for a device whose kick touches ~84; raising it to 256 on the
        # stack put 6 KB in each of the AArch64 corpus's 1784 case blocks and
        # the driver died of it silently, printing nothing. Static storage
        # keeps any capacity off the stack, and the capacity is what the
        # largest case seeds plus room for what it writes.
        capacity = max([64] + [len(case["seed"]) + 64 for case in cases])
        driver.write_text(
            '#include <stdio.h>\n#include <stdint.h>\n#include <string.h>\n'
            '#include "axis_exec.h"\n\n'
            "typedef struct { uint64_t addr; uint32_t width; uint64_t value; } cell;\n"
            f"typedef struct {{ cell cells[{capacity}]; int count; }} memctx;\n"
            "static uint64_t mem_read(void *c, uint64_t addr, uint32_t width) {\n"
            "  memctx *m = (memctx *)c;\n"
            "  for (int i = 0; i < m->count; ++i)\n"
            "    if (m->cells[i].addr == addr && m->cells[i].width == width) return m->cells[i].value;\n"
            "  return 0;\n}\n"
            "static void mem_write(void *c, uint64_t addr, uint64_t value, uint32_t width) {\n"
            "  memctx *m = (memctx *)c;\n"
            "  uint64_t masked = width >= 64 ? value : (value & ((UINT64_C(1) << width) - 1));\n"
            "  for (int i = 0; i < m->count; ++i)\n"
            "    if (m->cells[i].addr == addr && m->cells[i].width == width) { m->cells[i].value = masked; return; }\n"
            "  m->cells[m->count].addr = addr; m->cells[m->count].width = width;\n"
            "  m->cells[m->count].value = masked; m->count++;\n}\n\n"
            "int main(void) {\n  int checks = 0, failures = 0, declined = 0;\n"
            "  (void)mem_read; (void)mem_write;\n"
            + "".join(render_c(case) for case in cases)
            + '  printf("%d executed at 64 bits, %d declined, %d failures\\n",\n'
              '         checks - declined, declined, failures);\n'
            "  return failures == 0 ? 0 : 1;\n}\n"
        )
        binary = workdir / "driver"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Werror", "-DAXIS_IMPL_STUBS",
             "-I", str(workdir),
             "-o", str(binary), str(driver), "-lm"],
            check=True,
        )
    result = subprocess.run([str(binary)], capture_output=True, text=True)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=2)
    parser.add_argument("--max-declines", type=int, default=None,
                        metavar="N",
                        help="fail if more than N instructions are declined "
                             "(default: 0 for C, unlimited for Rust)")
    parser.add_argument("--list-declines", action="store_true",
                        help="name every declined instruction rather than a sample")
    parser.add_argument("--lang", default="c", choices=("c", "rust"),
                        help="which generated executor to drive")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_wide_"))
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-exec-c", workdir / "axis_exec.h")
    emit(args.axis_file, "emit-lift-c", workdir / "axis_lift.h")
    emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)

    sys.path.insert(0, str(workdir))
    axis_lift = load(workdir / "axis_lift.py", "axis_lift")
    golden = load(workdir / "golden_model.py", "axis_golden_wide")
    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])

    slots = axis_lift.REGISTER_FILE_SLOTS
    random.seed(0x571D)
    cases, scalable = [], 0
    # The register slot width the emitted executors use. Named rather than
    # spelled 64 inline: when the storage widens, this is the one place that
    # decides which instructions the driver may run.
    REGISTER_SLOT_BITS = 64

    too_wide: dict[str, int] = {}

    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = axis_lift.decode(word, test.get("isa"))
        if entry is None:
            continue
        # An instruction described only by a behavior has no `semantics`, so a
        # guard on that alone silently drops every effectful instruction --
        # which is what left this driver reporting "0 effectful" while RV64I's
        # loads, stores and branches sat right there in the fixtures.
        if entry["semantics"] is None and entry.get("effects") is None:
            continue
        effects = entry.get("effects")
        widest = max([op.get("width", 32) for op in entry["operands"]]
                     + [entry.get("state_width", 32)])
        if widest > REGISTER_SLOT_BITS:
            # ⚠️ Not the executors' limit any more -- THIS DRIVER's. The
            # executors hold a wide value as limbs now and run all of these;
            # what has not changed is that this driver seeds 64-bit values and
            # compares one, so running them here would "pass" with the upper
            # half zero on both sides and neither exercising anything. The
            # reason used to be "a 128-bit operand has nowhere to live", which
            # stopped being true and would have left them unmeasured while
            # reading as if they were covered.
            #
            # `wide_arith_check.py` is the gate for them, in both languages: it
            # seeds every limb and compares every limb.
            too_wide.setdefault(test["mnemonic"], 0)
            too_wide[test["mnemonic"]] += 1
            continue
        # A scalable instruction is not this driver's: a lane writes one
        # element of a register whose size is `VL`, and this one models a
        # register as a 64-bit slot. `scalable_exec_check.py` is built for
        # them -- it reads and writes element-sized views over limbs -- and
        # every entry in a scalable corpus carries the origin it is a lane of,
        # reductions included, which is the flag to read.
        if entry.get("scalable_origin"):
            scalable += 1
            continue
        # Narrow instructions run here too. The rule used to be that the
        # compact check has them, which was half true and half a hole: it
        # cannot run one that touches architectural state or reads a register
        # its operands do not name, and those were skipped by both drivers in
        # the belief the other had them.
        #
        # Nothing is skipped now, because the two are not one check run twice.
        # They are two independently generated C executors -- a 32-bit ABI
        # whose arithmetic is `uint32_t` and a 64-bit one whose arithmetic is
        # explicit masks -- and an instruction checked by one of them is
        # checked against the golden model but not against the other. That is
        # how a signed guard emitted as an unsigned comparison lived in the
        # compact path while the wide one had the rule, and how an arithmetic
        # shift of a 16-bit lane stayed unsigned in the wide path while the
        # compact one had it. Running everything both ABIs can hold takes
        # RV32I from 324 cases to 494 and its gate from 11 seconds to 20, and
        # closes the seam between them.

        fx = {o["name"]: o["value"] for o in test["operands"]}
        if effects is not None:
            cases.extend(_effect_case(test, entry, effects, fx, axis_lift,
                                      golden, slots, args.cases))
            continue
        kind = {op["name"]: op["kind"] for op in entry["operands"]}
        role = {op["name"]: op["role"] for op in entry["operands"]}
        def hardwired_zero(k: str, index: int) -> bool:
            """A class may hardwire one index to zero -- RISC-V's x0. Reads of
            it give zero and writes to it are dropped, so a driver that ignores
            this disagrees with the executor about every fixture that happens to
            name register 0. The rule comes from the generated table."""
            zero_index = axis_lift.REGISTER_CLASSES[k][0]
            return zero_index is not None and index == zero_index

        for trial in range(args.cases):
            regs = [0] * slots
            for name, k in kind.items():
                if axis_lift.is_register_operand(k) and not hardwired_zero(k, fx[name]):
                    for slot in register_slots(k, fx[name], axis_lift):
                        # The first trial takes an interesting value in every
                        # register rather than a share of them: with only a
                        # couple of trials per instruction, a coin flip leaves
                        # whole classes unreached on most runs, and the point of
                        # the list is that these are the values worth reaching.
                        regs[slot] = (
                            random.choice(INTERESTING)
                            if trial == 0 or random.random() < 0.4
                            else random.getrandbits(64)
                        )
            inputs = []
            for op in entry["operands"]:
                # A destructive instruction reads its destination as well as
                # writing it, and the golden model takes every operand it
                # reads -- `operand.input`, which is true of `inout`. Asking
                # only for `in` passed one argument too few for every such
                # instruction, which is why this harness had never run on the
                # AArch64 seed at all.
                if role[op["name"]] not in ("in", "inout"):
                    continue
                k = kind[op["name"]]
                if not axis_lift.is_register_operand(k):
                    inputs.append(fx[op["name"]])
                elif hardwired_zero(k, fx[op["name"]]):
                    inputs.append(0)
                else:
                    # Read through the view: a class at bit offset 8 yields
                    # bits 8..16, not the low byte.
                    inputs.append(
                        _view_read(regs, k, fx[op["name"]], axis_lift))
            expected = golden.evaluate(entry["mnemonic"], *inputs)
            dest_op = next((op for op in entry["operands"]
                            if role[op["name"]] in ("out", "inout")
                            and axis_lift.is_register_operand(kind[op["name"]])
                            and not hardwired_zero(kind[op["name"]], fx[op["name"]])), None)
            # What the *register* holds afterwards, which is not the value the
            # instruction computed once a view covers only part of it, and need
            # not be one slot once a register spans several.
            dest_writes = (_view_write(regs, kind[dest_op["name"]],
                                       fx[dest_op["name"]], expected, axis_lift)
                           if dest_op is not None else {})
            cases.append({
                "mnemonic": test["mnemonic"],
                "word": word,
                "isa": entry.get("isa") or "",
                "pc": 0,
                "regs": regs,
                "seed": [],
                "state": [],
                "reg_checks": list(dest_writes.items()),
                "mem_checks": [],
                "state_write": None,
                "next_pc": None,
                "trap": None,
                "result": expected,
                # The width the *destination* is, which is not always the
                # width the expression computed at. `VADD_DX` adds at 64 bits
                # and writes a 32-bit view, so the value that reaches the
                # register is narrower than the value the executor reports.
                # The golden model narrows; `res.result` carries the
                # expression, and the two coincide for every instruction whose
                # destination is as wide as its arithmetic -- which was every
                # instruction until an operand was declared as wide as the
                # window it names.
                "result_width": (
                    axis_lift.REGISTER_CLASSES[kind[dest_op["name"]]][2] or 64
                ) if dest_op is not None else 64,
                "slots": slots,
            })

    if too_wide:
        names = ", ".join(sorted(too_wide)[:4])
        more = f" (+{len(too_wide) - 4} more)" if len(too_wide) > 4 else ""
        print(f"  {sum(too_wide.values())} case(s) wider than this driver's "
              f"{REGISTER_SLOT_BITS}-bit values, left to `wide_arith_check.py`, "
              f"which seeds every limb: {names}{more}")
    if not cases:
        print(f"SKIP: nothing to execute ({sum(too_wide.values())} past the "
              f"register slot, {scalable} scalable)")
        return 0

    result = build_and_run(cases, workdir, args.axis_file, args.lang)
    # The declines are a list of what this executor cannot yet do -- a fact
    # about the executor, worth naming rather than counting.
    declines = sorted({line.split(None, 1)[1]
                       for line in result.stdout.splitlines()
                       if line.startswith("DECLINE ")})
    print("\n".join(line for line in result.stdout.strip().splitlines()
                    if not line.startswith("DECLINE ")))
    if scalable:
        print(f"  ({scalable} scalable fixture(s) left to scalable_exec_check)")
    if declines:
        limit = len(declines) if args.list_declines else 6
        shown = ", ".join(declines[:limit])
        more = f" (+{len(declines) - limit} more)" if len(declines) > limit else ""
        print(f"  declined: {shown}{more}")
    ok = result.returncode == 0
    label = "Rust" if args.lang == "rust" else "C"
    # How many declines are acceptable is a fact about the executor, and the
    # two executors are in different places. The wide C one declines nothing on
    # any corpus this ladder gates -- 312 RV32I fixtures, 624 RV64I, 1708
    # AArch64, every one executed -- so a decline appearing there is a lowering
    # that stopped being emitted rather than a feature nobody has written, and
    # a gate that shrugged at it would pass while covering less. Rust cannot
    # reach the floating-point environment at all, so it declines directed
    # rounding and the exception-accruing forms by design, and names them.
    #
    # Stated here rather than as a flag on each of the eleven C gates: a
    # twelfth would not know to carry it, which is how the claim would quietly
    # stop being made.
    max_declines = args.max_declines
    if max_declines is None and args.lang == "c":
        max_declines = 0
    if max_declines is not None and len(declines) > max_declines:
        print(f"  {len(declines)} instruction(s) declined, at most "
              f"{max_declines} expected")
        ok = False
    print(f"wide {label} executor == golden model: " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def _view_read(regs: list, kind: str, index: int, lift) -> int:
    """What a read through this class's view yields.

    A view that starts at bit 8 reads bits 8..16, not the low byte -- and in a
    register held as several slots it need not stay inside one, so bits 48..80
    are stitched from the top of one slot and the bottom of the next. A view is
    never wider than a slot, so it never spans more than two.
    """
    _zero, _alias, view, _offset, view_offset, _preserves, _limbs = (
        lift.REGISTER_CLASSES[kind][:7])
    base = register_slot(kind, index, lift)
    if not view:
        return regs[base] & ((1 << 64) - 1)
    low, shift = base + view_offset // 64, view_offset % 64
    bits = regs[low] >> shift
    if shift and shift + view > 64:
        bits |= regs[low + 1] << (64 - shift)
    return bits & ((1 << view) - 1)


def _view_write(regs: list, kind: str, index: int, value: int, lift) -> dict:
    """The slots a write through the view changes, as {slot: new value}.

    The value that reaches a register is not the value the instruction
    computed: a view covers part of the storage, and the bits outside it either
    become zero or keep what they had. Checking only the view would pass either
    way, so the reference models every slot the register occupies -- from the
    published table, not from knowing which architecture this is.
    """
    _zero, _alias, view, _offset, view_offset, preserves, limbs = (
        lift.REGISTER_CLASSES[kind][:7])
    base = register_slot(kind, index, lift)
    if not view:
        return {base: value & ((1 << 64) - 1)}
    value &= (1 << view) - 1
    # A zeroing view clears the whole register. Every limb of it, not the one
    # the view happens to land in -- so the reference names them all, and a
    # write that cleared only the slot it touched fails here.
    out = {} if preserves else {base + k: 0 for k in range(limbs)}
    low, shift = base + view_offset // 64, view_offset % 64
    cover = (((1 << view) - 1) << shift) & ((1 << 64) - 1)
    kept = out.get(low, regs[low]) & ~cover
    out[low] = (kept | ((value << shift) & cover)) & ((1 << 64) - 1)
    if shift and shift + view > 64:
        spill = (1 << (shift + view - 64)) - 1
        kept = out.get(low + 1, regs[low + 1]) & ~spill
        out[low + 1] = (kept | ((value >> (64 - shift)) & spill)) & ((1 << 64) - 1)
    return out


def _seed_loads(node, env, address_width, seed, golden, Mem):
    """Seed a cell for every load in the tree, innermost first.

    ⚠️ Every load, not the one at the head. An effect may read memory more than
    once now, and a load's address may itself be a load -- a pointer chase is
    `(load (load rs1))`. Seeding the inner one first is what makes the outer
    address computable, since it is read out of the memory being filled.

    Masked, because an address wraps: `_eval` returns the arithmetic value, and
    a base near the top of the space plus a positive offset exceeds the word.
    The executors wrap it; this did not, and emitted a C literal too large for
    any integer type.
    """
    if not isinstance(node, list):
        return
    if node and node[0] in ("load", "atomic_load"):
        _seed_loads(node[-1], env, address_width, seed, golden, Mem)
        access = int(node[1][1:])
        reader = Mem(seed).read
        addr = golden._mask(
            golden._eval(node[-1], {**env, "__mem__": reader}, address_width),
            address_width,
        )
        seed.setdefault((addr, access), random.getrandbits(access))
        return
    for item in node:
        _seed_loads(item, env, address_width, seed, golden, Mem)


def _effect_value(eff: dict, env: dict, golden) -> int:
    """An effect's value, with the address width the loads inside it need.

    This used to PEEL a load, because `_eval_axis_expr` evaluates a whole
    expression at one width: asking it for `(load i8 unsigned (add i64 rs 0))`
    at the store's 8-bit value width truncated the *address* to 8 bits and read
    the wrong cell -- it returned zero for every copy, which is why a block
    copy rewritten to store a constant still passed.

    ⚠️ Peeling handles exactly one load, at the head. An effect may now read
    memory several times, and a load's address may itself be a load, so the
    peel is replaced by the thing it was working around: `load_address_width`
    passed to the evaluator, which applies it to every load it meets and does
    the same mask the peel did.
    """
    return golden._eval_axis_expr(
        eff["value"], env, eff["eval_width"], eff.get("load_address_width")
    )

def _guard_candidates(effects, state_name, env, golden) -> list[int]:
    """Values this state slot is compared against, anywhere in the effects.

    A state slot only ever reaches a guard through an operator -- `(xor i32
    exclusive_address rs1)`, `(icmp_eq fflags 0)` -- so the values worth trying
    are the *siblings* of the slot's own atom, evaluated in the operand
    environment. Nothing here knows what a reservation is; it knows that a
    description comparing a slot against something has said which value makes
    the comparison hold.
    """
    found: list[int] = []

    def walk(node):
        if not isinstance(node, list):
            return
        if any(item == state_name for item in node if isinstance(item, str)):
            for sibling in node[1:]:
                if sibling == state_name or _is_type_atom(sibling):
                    continue
                try:
                    value = golden._eval(sibling, env, 64)
                except Exception:
                    continue
                if isinstance(value, int) and value not in found:
                    found.append(value)
        for item in node:
            walk(item)

    for eff in effects:
        for key in ("value", "guard", "addr"):
            if key in eff:
                walk(golden._parse(golden._tokenize(eff[key])))
    return found


def _is_type_atom(node) -> bool:
    return (isinstance(node, str) and len(node) > 1
            and node[0] in "iuf" and node[1:].isdigit())


def _effect_case(test, entry, effects, fx, lift, golden, slots, trials):
    """Reference the full architectural delta of one effectful fixture at 64
    bits, and emit a C case asserting it.

    This mirrors the compact driver's effect case, with three differences that
    are the whole point of the wide ABI: registers, memory and the program
    counter are 64 bits, and architectural **state** is present. The compact
    path skips any instruction that touches state because its ABI has nowhere to
    put it, so RISC-V's reservation state and AArch64's flags have only ever
    been executed through bespoke harnesses.
    """
    word = int(test["encoded"], 16)
    kind = {op["name"]: op["kind"] for op in entry["operands"]}
    cases = []
    # The ISA's word, from the entry rather than from a document-level default
    # of 64. This driver evaluated a branch target and wrapped the counter at
    # that default, so on a 32-bit machine it was expecting a 64-bit counter
    # while the executors kept a 32-bit one -- the two agreed only because
    # every corpus's branch target is arithmetic, which masks its own result.
    pc_bits = entry.get("state_width", 32)
    pc_mask = (1 << pc_bits) - 1
    for trial in range(trials):
        # The last word in the address space on the first trial, where
        # `pc + ILEN` wraps, and an aligned draw from inside the space
        # otherwise. The old draw -- 40 bits, whatever the machine -- was a
        # counter a 32-bit machine cannot hold.
        pc = ((1 << pc_bits) - 4 if trial == 0
              else random.getrandbits(pc_bits - 2) * 4)
        regs = [0] * slots
        for name, k in kind.items():
            if lift.is_register_operand(k):
                zero_index = lift.REGISTER_CLASSES[k][0]
                if zero_index is None or fx[name] != zero_index:
                    for slot in register_slots(k, fx[name], lift):
                        # The first trial takes an interesting value in every
                        # register rather than a share of them: with only a
                        # couple of trials per instruction, a coin flip leaves
                        # whole classes unreached on most runs, and the point of
                        # the list is that these are the values worth reaching.
                        regs[slot] = (
                            random.choice(INTERESTING)
                            if trial == 0 or random.random() < 0.4
                            else random.getrandbits(64)
                        )
        # And the registers the behavior names itself, which no operand
        # carries. Unseeded they read zero on both sides, which is agreement
        # about a value neither side computed.
        for read in entry.get("reads_registers", []):
            zero_index = lift.REGISTER_CLASSES[read["kind"]][0]
            if zero_index is not None and read["index"] == zero_index:
                continue
            for slot in register_slots(read["kind"], read["index"], lift):
                if regs[slot] == 0:
                    regs[slot] = (random.choice(INTERESTING)
                                  if trial == 0 or random.random() < 0.4
                                  else random.getrandbits(64))
        env = {name: (_view_read(regs, k, fx[name], lift)
                      if lift.is_register_operand(k) else fx[name])
               for name, k in kind.items()}
        env["pc"] = pc
        # `(input rs)` is an operand's value *before* the instruction ran,
        # which a destructive instruction needs to refer to after it has
        # overwritten it -- a store-exclusive comparing against its own
        # reservation, for one. The executors bind these snapshots beside the
        # operands; a harness that does not cannot evaluate the guard at all.
        env.update({"__input_" + name: value for name, value in env.items()})
        # Architectural state the instruction may read. Seeded rather than
        # zeroed, because zero is the value a broken state read also produces.
        state = {name: random.getrandbits(width) & ((1 << width) - 1)
                 for name, width in lift.STATE_SLOTS}
        # On one trial, seed each state slot with what the effects compare it
        # against instead of with noise. A guard that tests three state slots
        # against an operand and two constants -- which is what a
        # store-conditional's reservation check is -- is satisfied by random
        # state with probability 2**-41: the store path of every `sc.w` in the
        # corpus had never been executed by any differential gate, and could
        # not have been. This is the wide driver's version of the compact
        # driver's "trial 0 forces the source registers equal".
        if trial == 0:
            for name, width in lift.STATE_SLOTS:
                candidates = _guard_candidates(effects, name, env, golden)
                if candidates:
                    state[name] = random.choice(candidates) & ((1 << width) - 1)
        env.update(state)

        # Back any load with a deterministic value.
        #
        # Every effect, not just a `set`: a block copy's load lives inside a
        # *store*, and seeding only set-values leaves the reference expecting to
        # store zeros into memory that already reads zero -- so the check cannot
        # tell a working copy from an instruction that did nothing. Measured:
        # with this loop keyed on "set", a copy rewritten to store a constant
        # still passed with zero failures.
        seed = {}
        for eff in effects:
            # Not every effect has a value: a trap carries a cause and a
            # barrier an option. The `kind == "set"` guard this replaced implied
            # one, and dropping it without replacing the implication is what
            # broke the trap corpora.
            # The guard and a store's address as well as the value: either
            # may read memory (a descriptor launch reads both), and a cell
            # nothing seeded reads zero on both sides, which is agreement
            # about nothing.
            if eff.get("guard"):
                _seed_loads(golden._parse(golden._tokenize(eff["guard"])), env,
                            eff.get("guard_load_address_width") or pc_bits,
                            seed, golden, Mem)
            if eff.get("addr"):
                _seed_loads(golden._parse(golden._tokenize(eff["addr"])), env,
                            eff.get("addr_width") or pc_bits, seed, golden, Mem)
            if "value" not in eff:
                continue
            address_width = (eff.get("load_address_width")
                             or eff.get("addr_width") or pc_bits)
            _seed_loads(golden._parse(golden._tokenize(eff["value"])),
                        env, address_width, seed, golden, Mem)

        memory = Mem(seed)
        ref_env = dict(env)
        ref_env["__mem__"] = memory.read
        # The file as the executor sees it while the effects land, which is not
        # the file the case starts from: a `getreg` after a write to the same
        # register reads the write. The initial `regs` stays untouched because
        # it is what the emitted case seeds the executor with.
        live = list(regs)

        def read_register(k, index, _lift=lift, _live=live, _env=ref_env):
            zero, alias = _lift.REGISTER_CLASSES[k][0], _lift.REGISTER_CLASSES[k][1]
            if zero is not None and index == zero:
                return 0
            if alias is not None and index == alias[0]:
                return _env.get(alias[1], 0)
            return _view_read(_live, k, index, _lift)

        ref_env["__regs__"] = read_register
        next_pc = (pc + 4) & pc_mask
        trap = None
        state_write = None
        reg_checks, mem_checks = [], []
        for eff in effects:
            if "guard" in eff and not golden._eval_axis_expr(
                eff["guard"], ref_env, eff["guard_width"],
            eff.get("guard_load_address_width")
            ):
                continue
            if eff["kind"] == "trap":
                trap = eff["cause"]
                break
            if eff["kind"] == "set":
                # Peeled, not evaluated whole: a `set` whose value *is* a load
                # -- every compare-and-swap and every atomic read-modify-write
                # begins with one -- would otherwise have its address masked to
                # the value width, reading a cell nothing seeded and expecting
                # zero from every one of them.
                value = _effect_value(eff, ref_env, golden)
                dest_kind = kind[eff["dest"]]
                zero_index = lift.REGISTER_CLASSES[dest_kind][0]
                if zero_index is None or fx[eff["dest"]] != zero_index:
                    written = _view_write(regs, dest_kind, fx[eff["dest"]],
                                          value, lift)
                    reg_checks.extend(written.items())
                    for slot, slot_value in written.items():
                        live[slot] = slot_value
                # A later effect reads what this one wrote -- an atomic
                # read-modify-write stores a function of the value it just
                # loaded, so the reference must sequence as the executor does.
                ref_env[eff["dest"]] = value
            elif eff["kind"] == "setstate":
                # Through `_effect_value` like `set` and `store`: a state loaded
                # from memory is as narrow as the state, its address is not.
                value = _effect_value(eff, ref_env, golden)
                state_write = (eff["state"], value & ((1 << eff["width"]) - 1))
                ref_env[eff["state"]] = state_write[1]
            elif eff["kind"] == "store":
                addr = golden._eval_axis_expr(eff["addr"], ref_env, eff["addr_width"])
                value = _effect_value(eff, ref_env, golden)
                memory.write(addr, value, eff["width"])
                mem_checks.append((addr, eff["width"], value & ((1 << eff["width"]) - 1)))
            elif eff["kind"] == "setpc":
                # At the effect's own width, and then at the counter's: an
                # arithmetic target masks itself, a bare register does not, and
                # what reaches the counter is the value taken at the ISA word.
                next_pc = golden._eval_axis_expr(
                    eff["value"], ref_env, eff["eval_width"]) & pc_mask

        mn = test["mnemonic"]
        # An instruction may write the same place twice -- RISC-V's FL.S loads
        # a 32-bit float and then NaN-boxes it into the same register, two
        # effects with one destination. Only the last write survives, so
        # asserting every intermediate would fail against a correct executor.
        reg_checks = list({slot: value for slot, value in reg_checks}.items())
        collapsed = {(addr, width): value for addr, width, value in mem_checks}
        mem_checks = [(addr, width, value) for (addr, width), value in collapsed.items()]

        cases.append({
            "mnemonic": mn,
            "word": word,
            "isa": entry.get("isa") or "",
            "pc": pc,
            "regs": regs,
            "seed": [(a, w, v) for (a, w), v in seed.items()],
            "state": [(name, state[name], width) for name, width in lift.STATE_SLOTS],
            "reg_checks": reg_checks,
            "mem_checks": mem_checks,
            "state_write": state_write,
            "next_pc": next_pc & pc_mask,
            "trap": trap,
            "slots": slots,
        })
    return cases


if __name__ == "__main__":
    sys.exit(main())
