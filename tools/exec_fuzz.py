#!/usr/bin/env python3
"""Cross-executor differential fuzzer: Python == C == Rust over random programs.

The three generated executors (axis_exec.py / .h / .rs) are each proven equal to
the golden model *per instruction* (exec_vs_golden, exec_c_check, exec_rust_check).
This fuzzer checks the next thing those miss: that they agree with each other over
whole multi-step programs — register dataflow through repeated writes, memory
written then read back, control flow (setpc), and traps. For each random
straight-line program it runs all three executors from an identical initial state
and requires a byte-identical architectural trace (all 32 registers, memory, the
final pc, and the trap outcome). The Python executor — proven == golden — is the
reference; any divergence is a real cross-backend bug.

Usage: tools/exec_fuzz.py [input.axisl] [--programs N] [--length L] [--seed S]

Defaults to examples/fuzz_mix.axisl (pure ALU + load + store + branch + trap).
Requires: cargo (from the AXIS repo root); cc and rustc on PATH (each side is
skipped with a notice if its compiler is missing).
"""

from __future__ import annotations

import argparse
import importlib
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
REG_COUNT = 32


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


class Mem:
    """Insertion-ordered, width-keyed memory matching the executors' ABI."""

    def __init__(self):
        self.store = {}

    def read(self, addr, width):
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def encode(entry, values):
    """Encode an instruction word from operand values using the lift fields."""
    word = entry["match"]
    for op in entry["operands"]:
        value = values.get(op["name"], 0)
        for insn_lo, op_lo, width in op["fields"]:
            piece = (value >> op_lo) & ((1 << width) - 1)
            word |= piece << insn_lo
    return word


def program_coverage(programs, entries):
    """What a pool of programs actually contains, against what was offered.

    A gate that samples reports how *much* it ran. This is what it ran: the
    difference is where an entire instruction class can go missing without the
    output changing, which has happened twice in this repo.
    """
    used = {entry["mnemonic"] for program in programs for entry, _v, _w in program}
    offered = {entry["mnemonic"] for entry in entries}
    return used, offered


def gen_program(entries, length, rng, lift):
    """A random straight-line program: list of (entry, values, word)."""
    program = []
    for _ in range(length):
        entry = rng.choice(entries)
        values = {}
        reg_ops = [op for op in entry["operands"]
                   if lift.is_register_operand(op["kind"])]
        for op in entry["operands"]:
            if lift.is_register_operand(op["kind"]):
                values[op["name"]] = rng.randrange(REG_COUNT)
            else:  # immediate: full width
                width = max(w for _, _, w in op["fields"])
                values[op["name"]] = rng.getrandbits(width)
        # 1/3 of the time, alias the two source registers so equality guards
        # (branch/trap `when rs1 == rs2`) fire and exercise the taken path.
        if len(reg_ops) >= 2 and rng.random() < 0.34:
            values[reg_ops[1]["name"]] = values[reg_ops[0]["name"]]
        program.append((entry, values, encode(entry, values)))
    return program


def canonical(regs, mem, pc, trap, steps):
    """The architectural trace string every executor must reproduce exactly."""
    regs_str = "".join(f" {regs.get(i, 0) & 0xffffffff:08x}" for i in range(REG_COUNT))
    mem_str = "".join(f" {a:08x}:{w}:{v & ((1 << w) - 1):08x}"
                      for (a, w), v in mem.store.items())
    return (f"REGS{regs_str}\n"
            f"PC {pc & 0xffffffff:08x}\n"
            f"TRAP {1 if trap else 0} {trap or '-'}\n"
            f"MEM{mem_str}\n"
            f"STEPS {steps}")


def run_python(axis_exec, words, init_regs, init_pc):
    regs = dict(init_regs)
    mem = Mem()
    pc = init_pc
    steps = 0
    trap = None
    for word in words:
        out = axis_exec.step(word, regs, mem, pc)
        steps += 1
        pc = out["next_pc"] if out else (pc + 4) & 0xffffffff
        if out and out.get("trap"):
            trap = out["trap"]
            break
    return canonical(regs, mem, pc, trap, steps)


# --- compiled drivers ---------------------------------------------------------

_C_MEM = (
    "typedef struct { uint32_t addr, width, value; } cell;\n"
    "typedef struct { cell cells[256]; int count; } memctx;\n"
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
    "  m->cells[m->count].value = masked; m->count++;\n}\n"
)


# Each driver is compiled ONCE and reads a program from stdin per invocation:
#   line 1: init_pc
#   line 2: 32 initial registers
#   line 3: word count, then that many instruction words
# so a large fuzz run is one compile + many fast executions.
C_DRIVER = (
    '#include <stdio.h>\n#include <stdint.h>\n#include "axis_exec.h"\n\n'
    + _C_MEM
    + "#define MAXW 8192\n"
    "int main(void) {\n"
    "  uint32_t pc; if (scanf(\"%u\", &pc) != 1) return 2;\n"
    f"  uint32_t regs[{REG_COUNT}];\n"
    f"  for (int i = 0; i < {REG_COUNT}; ++i) if (scanf(\"%u\", &regs[i]) != 1) return 2;\n"
    "  int nwords; if (scanf(\"%d\", &nwords) != 1 || nwords > MAXW) return 2;\n"
    "  static uint32_t words[MAXW];\n"
    "  for (int i = 0; i < nwords; ++i) if (scanf(\"%u\", &words[i]) != 1) return 2;\n"
    "  memctx ctx = { {0}, 0 };\n"
    "  axis_mem M = { mem_read, mem_write, &ctx };\n"
    "  int steps = 0, trapped = 0; const char *cause = \"-\";\n"
    "  for (int i = 0; i < nwords; ++i) {\n"
    "    axis_exec_result r = axis_exec_step(words[i], regs, 32, &M, pc);\n"
    "    steps++; pc = r.next_pc;\n"
    "    if (r.trapped) { trapped = 1; cause = r.trap_cause ? r.trap_cause : \"-\"; break; }\n"
    "  }\n"
    "  printf(\"REGS\");\n"
    f"  for (int i = 0; i < {REG_COUNT}; ++i) printf(\" %08x\", regs[i]);\n"
    "  printf(\"\\nPC %08x\\n\", pc);\n"
    "  printf(\"TRAP %d %s\\n\", trapped, trapped ? cause : \"-\");\n"
    "  printf(\"MEM\");\n"
    "  for (int i = 0; i < ctx.count; ++i) printf(\" %08x:%u:%08x\", ctx.cells[i].addr, ctx.cells[i].width, ctx.cells[i].value);\n"
    "  printf(\"\\nSTEPS %d\\n\", steps);\n"
    "  return 0;\n}\n"
)


def program_stdin(words, init_regs, init_pc):
    return (f"{init_pc}\n"
            + " ".join(str(v) for v in init_regs) + "\n"
            + f"{len(words)}\n" + " ".join(str(w) for w in words) + "\n")


# The simulator-IR (JIT on-ramp) driver: build the block once, then run the
# pre-decoded ops. Must produce the exact same trace as the step interpreter.
# The generated *machine* (`emit-sim-c`), driven so that it sees the same
# program the step interpreter does. The fuzz's model hands words in sequence
# rather than fetching them by pc, so the fetch hook does exactly that: which
# words the machine sees is the host's policy, and this host's policy is a
# straight-line block. Everything else -- executing, applying, following the
# trap -- is the machine's.
SIM_C_DRIVER = (
    '#include <stdio.h>\n#include <stdint.h>\n#include <string.h>\n'
    '#include "axis_sim.h"\n\n'
    "#define MAXW 8192\n"
    "static uint32_t WORDS[MAXW];\n"
    "static int NWORDS = 0;\n"
    "static int CURSOR = 0;\n"
    "typedef struct { uint32_t addr; uint32_t width; uint32_t value; } cell;\n"
    "static cell CELLS[64];\n"
    "static int NCELLS = 0;\n"
    "static uint64_t sim_read(void *c, uint64_t addr, uint32_t width) {\n"
    "  (void)c;\n"
    "  for (int i = 0; i < NCELLS; ++i)\n"
    "    if (CELLS[i].addr == (uint32_t)addr && CELLS[i].width == width) return CELLS[i].value;\n"
    "  return 0;\n}\n"
    "static void sim_write(void *c, uint64_t addr, uint64_t value, uint32_t width) {\n"
    "  (void)c;\n"
    "  uint32_t masked = width >= 32 ? (uint32_t)value : (uint32_t)(value & ((1u << width) - 1u));\n"
    "  for (int i = 0; i < NCELLS; ++i)\n"
    "    if (CELLS[i].addr == (uint32_t)addr && CELLS[i].width == width) { CELLS[i].value = masked; return; }\n"
    "  CELLS[NCELLS].addr = (uint32_t)addr; CELLS[NCELLS].width = width;\n"
    "  CELLS[NCELLS].value = masked; NCELLS++;\n}\n"
    "static uint32_t sim_fetch(void *c, uint64_t pc, int *ok) {\n"
    "  (void)c; (void)pc;\n"
    "  if (CURSOR >= NWORDS) { *ok = 0; return 0; }\n"
    "  *ok = 1; return WORDS[CURSOR++];\n}\n"
    "static const char *CAUSE = \"-\";\n"
    "static uint64_t sim_trap(void *c, const char *cause, uint64_t pc, int *stop) {\n"
    "  (void)c; CAUSE = cause ? cause : \"-\"; *stop = 1; return pc;\n}\n"
    "int main(void) {\n"
    "  uint32_t pc; if (scanf(\"%u\", &pc) != 1) return 2;\n"
    f"  uint32_t regs[{REG_COUNT}];\n"
    f"  for (int i = 0; i < {REG_COUNT}; ++i) if (scanf(\"%u\", &regs[i]) != 1) return 2;\n"
    "  if (scanf(\"%d\", &NWORDS) != 1 || NWORDS > MAXW) return 2;\n"
    "  for (int i = 0; i < NWORDS; ++i) if (scanf(\"%u\", &WORDS[i]) != 1) return 2;\n"
    "  axis_sim sim;\n"
    "  axis_sim_hooks hooks = { sim_read, sim_write, sim_fetch, sim_trap, NULL, NULL };\n"
    "  axis_sim_init(&sim, &hooks, NULL, 0);\n"
    "  sim.pc = pc;\n"
    f"  for (int i = 0; i < {REG_COUNT}; ++i) sim.regs[i] = regs[i];\n"
    "  axis_sim_run(&sim, 0);\n"
    "  int trapped = CAUSE[0] != '-' || CAUSE[1] != 0;\n"
    "  printf(\"REGS\");\n"
    f"  for (int i = 0; i < {REG_COUNT}; ++i) printf(\" %08x\", (uint32_t)sim.regs[i]);\n"
    "  printf(\"\\nPC %08x\\n\", (uint32_t)sim.pc);\n"
    "  printf(\"TRAP %d %s\\n\", trapped, trapped ? CAUSE : \"-\");\n"
    "  printf(\"MEM\");\n"
    "  for (int i = 0; i < NCELLS; ++i) printf(\" %08x:%u:%08x\", CELLS[i].addr, CELLS[i].width, CELLS[i].value);\n"
    "  printf(\"\\nSTEPS %llu\\n\", (unsigned long long)sim.steps);\n"
    "  return 0;\n}\n"
)

_RUST_MEM = (
    "#[derive(Default)]\n"
    "struct DriverMem { cells: Vec<(u32, u32, u32)> }\n"
    "impl Memory for DriverMem {\n"
    "    fn read(&mut self, addr: u32, width: u32) -> u32 {\n"
    "        for &(a, w, v) in &self.cells { if a == addr && w == width { return v; } }\n"
    "        0\n    }\n"
    "    fn write(&mut self, addr: u32, value: u32, width: u32) {\n"
    "        let masked = if width >= 32 { value } else { value & ((1u32 << width) - 1) };\n"
    "        for c in self.cells.iter_mut() { if c.0 == addr && c.1 == width { c.2 = masked; return; } }\n"
    "        self.cells.push((addr, width, masked));\n    }\n}\n"
)

RUST_DRIVER = (
    _RUST_MEM
    + "use std::io::Read;\n"
    "fn main() {\n"
    "    let mut input = String::new();\n"
    "    std::io::stdin().read_to_string(&mut input).unwrap();\n"
    "    let mut toks = input.split_whitespace().map(|t| t.parse::<u32>().unwrap());\n"
    "    let mut pc: u32 = toks.next().unwrap();\n"
    f"    let mut regs: [u32; {REG_COUNT}] = [0; {REG_COUNT}];\n"
    f"    for i in 0..{REG_COUNT} {{ regs[i] = toks.next().unwrap(); }}\n"
    "    let nwords = toks.next().unwrap();\n"
    "    let words: Vec<u32> = (0..nwords).map(|_| toks.next().unwrap()).collect();\n"
    "    let mut mem = DriverMem::default();\n"
    "    let mut steps = 0i64;\n    let mut trapped = 0;\n    let mut cause = \"-\";\n"
    "    for &w in words.iter() {\n"
    "        let r = step(w, &mut regs, &mut mem, pc);\n"
    "        steps += 1; pc = r.next_pc;\n"
    "        if let Some(c) = r.trap { trapped = 1; cause = c; break; }\n"
    "    }\n"
    "    let mut out = String::from(\"REGS\");\n"
    "    for i in 0..32 { out.push_str(&format!(\" {:08x}\", regs[i])); }\n"
    "    out.push_str(&format!(\"\\nPC {:08x}\\n\", pc));\n"
    "    out.push_str(&format!(\"TRAP {} {}\\n\", trapped, if trapped == 1 { cause } else { \"-\" }));\n"
    "    out.push_str(\"MEM\");\n"
    "    for c in mem.cells.iter() { out.push_str(&format!(\" {:08x}:{}:{:08x}\", c.0, c.1, c.2)); }\n"
    "    out.push_str(&format!(\"\\nSTEPS {}\", steps));\n"
    "    println!(\"{}\", out);\n}\n"
)



def effect_shape(entry):
    """The class a driver's lowering branches on: which effect kinds an
    instruction has, whether any is guarded, and whether it writes twice.

    `docs/gate_coverage.md`: report instruction coverage, require class
    coverage. Which of forty adds a run picked does not matter; whether it ever
    ran a store, a branch, a trap or a guarded write does.
    """
    effects = entry.get("effects") or []
    kinds = tuple(sorted({one["kind"] for one in effects}))
    guarded = any("guard" in one for one in effects)
    writes = sum(1 for one in effects if one["kind"] in ("set", "setreg"))
    return kinds + (("guarded",) if guarded else ()) + (
        ("multi-write",) if writes > 1 else ())

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "fuzz_mix.axisl")
    parser.add_argument("--programs", type=int, default=200)
    parser.add_argument("--length", type=int, default=16)
    parser.add_argument("--seed", type=lambda s: int(s, 0), default=0xF0F0)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_fuzz_"))
    # Python side.
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    # C side.
    have_cc = shutil.which("cc") is not None
    if have_cc:
        emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
        emit(args.axis_file, "emit-lift-c", workdir / "axis_lift.h")
        emit(args.axis_file, "emit-exec-c", workdir / "axis_exec.h")
        emit(args.axis_file, "emit-sim-c", workdir / "axis_sim.h")
    # Rust side.
    have_rustc = shutil.which("rustc") is not None
    if have_rustc:
        emit(args.axis_file, "emit-semantics-rust", workdir / "axis_semantics.rs")
        emit(args.axis_file, "emit-lift-rust", workdir / "axis_lift.rs")
        emit(args.axis_file, "emit-exec-rust", workdir / "axis_exec.rs")

    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    axis_lift = importlib.import_module("axis_lift")

    # ⚠️ This driver's ABI is 32-bit: its trace masks every register and the pc
    # to 32 bits, and it hands `step` no architectural state at all. An
    # instruction wider than that, or one that reads a named state register,
    # belongs to the wide executor that `exec_wide_check` compares -- the same
    # rule `exec_rust_check` applies, and for the same reason.
    #
    # It used to have no rule. The filter took any instruction with semantics
    # or effects, and on AArch64 the first one that read `fpcr` reached the
    # golden model with no `fpcr` in its environment and raised
    # `unknown AXIS semantic atom: fpcr` -- a traceback, from a gate whose
    # whole subject is that backends either agree or say why not.
    def compact(entry) -> bool:
        if entry.get("state_width", 32) > 32:
            return False
        if any(op.get("width", 32) > 32 for op in entry["operands"]):
            return False
        # A named state read has nowhere to come from in this ABI. The names
        # are the lifter's, not a literal list, so this covers AArch64's
        # `fpcr`/`nzcv` and RISC-V's reservation state alike.
        return not (entry.get("reads_state") or entry.get("writes_state"))

    encodable = [
        e for e in axis_lift.AXIS_LIFT_TABLE
        if (e["semantics"] is not None or e.get("effects") is not None)
        and all(op["fields"] for op in e["operands"] if op["kind"] in ("reg", "imm"))
    ]
    entries = [e for e in encodable if compact(e)]
    wide = len(encodable) - len(entries)
    if not entries:
        # Said with its cause. A bare "nothing to fuzz" sends the next reader
        # looking for missing fixtures rather than at the gate that does cover
        # these -- which is the mistake `exec_rust_check` records having made.
        if wide:
            print(f"SKIP: this driver's ABI is 32-bit and stateless, and "
                  f"{wide} instruction(s) are wider or read architectural "
                  f"state; `exec_wide_check.py` is the gate for those")
        else:
            print("no executable, encodable instructions to fuzz")
        return DECLINED
    if wide:
        print(f"{wide} instruction(s) left to the wide executor: wider than "
              f"this driver's 32-bit ABI, or reading architectural state")
    print(f"fuzzing {len(entries)} instruction(s): "
          f"{', '.join(sorted(e['mnemonic'] for e in entries))}")
    labels = "python" + (" + c-step + c-sim" if have_cc else "") + (" + rust" if have_rustc else "")
    print(f"backends: {labels}")
    if not (have_cc or have_rustc):
        print("SKIP: neither cc nor rustc found; nothing to differentially compare")
        return 0

    # Compile each compiled backend once; then feed programs over stdin.
    c_bin = _compile_c(workdir) if have_cc else None
    sim_bin = _compile_sim(workdir) if have_cc else None
    rust_bin = _compile_rust(workdir) if have_rustc else None

    rng = random.Random(args.seed)
    failures = 0
    seen: set[str] = set()
    for n in range(args.programs):
        program = gen_program(entries, args.length, rng, axis_lift)
        seen.update(entry["mnemonic"] for entry, _v, _w in program)
        words = [word for _, _, word in program]
        init_regs = [rng.getrandbits(32) for _ in range(REG_COUNT)]
        init_pc = rng.getrandbits(30) * 4
        stdin = program_stdin(words, init_regs, init_pc)

        reference = run_python(axis_exec, words,
                               {i: v for i, v in enumerate(init_regs)}, init_pc)
        for label, binary in ((l, b) for l, b in
                              (("c-step", c_bin if have_cc else None),
                               ("c-sim", sim_bin if have_cc else None),
                               ("rust", rust_bin if have_rustc else None)) if b):
            got = _run(binary, stdin)
            if got != reference:
                failures += 1
                print(f"FAIL program #{n} ({label} != python)")
                _report_diff(reference, got, words, init_regs, init_pc)
                if failures >= 3:
                    print("... stopping after 3 failures")
                    return 1

    print(f"{args.programs} programs x {args.length} instrs: {failures} divergences")
    offered = {entry["mnemonic"] for entry in entries}
    missing = sorted(offered - seen)
    print(f"  coverage: {len(seen)}/{len(offered)} instruction(s) executed"
          + (f"; never run: {', '.join(missing[:6])}"
             f"{f' (+{len(missing) - 6} more)' if len(missing) > 6 else ''}"
             if missing else ""))
    # Class coverage is required where instruction coverage is only reported:
    # a run that never ran a whole effect class is a green result about a
    # path it did not take.
    offered_shapes = {effect_shape(entry) for entry in entries}
    covered_shapes = {effect_shape(entry) for entry in entries
                      if entry["mnemonic"] in seen}
    absent_shapes = offered_shapes - covered_shapes
    print(f"  classes: {len(covered_shapes)}/{len(offered_shapes)} executed"
          + (f"; never ran: "
             + ", ".join(sorted("+".join(shape) or "pure" for shape in absent_shapes))
             if absent_shapes else ""))
    ok = failures == 0 and not absent_shapes
    print("python == c == rust over random programs: PASS" if ok
          else "python == c == rust over random programs: FAIL")
    return 0 if ok else 1


def _compile_c(workdir):
    (workdir / "driver.c").write_text(C_DRIVER)
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-DAXIS_IMPL_STUBS",
         "-I", str(workdir),
         "-o", str(workdir / "driver_c"), str(workdir / "driver.c")],
        check=True,
    )
    return workdir / "driver_c"


def _compile_sim(workdir):
    (workdir / "driver_sim.c").write_text(SIM_C_DRIVER)
    subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-DAXIS_IMPL_STUBS",
         "-I", str(workdir),
         "-o", str(workdir / "driver_sim"), str(workdir / "driver_sim.c")],
        check=True,
    )
    return workdir / "driver_sim"


def _compile_rust(workdir):
    full = ("\n".join((workdir / f).read_text()
                      for f in ("axis_semantics.rs", "axis_lift.rs", "axis_exec.rs"))
            + "\n" + RUST_DRIVER)
    (workdir / "driver.rs").write_text(full)
    subprocess.run(
        ["rustc", "--edition", "2021", "-A", "warnings", "--cfg", "axis_impl_stubs",
         "-o", str(workdir / "driver_rs"), str(workdir / "driver.rs")],
        check=True,
    )
    return workdir / "driver_rs"


def _run(binary, stdin):
    return subprocess.run([str(binary)], input=stdin,
                          capture_output=True, text=True).stdout.strip()


def _report_diff(reference, got, words, init_regs, init_pc):
    print(f"  init_pc={init_pc:#010x}")
    print(f"  words={[hex(w) for w in words]}")
    for r, g in zip(reference.splitlines(), got.splitlines()):
        marker = "  " if r == g else "!="
        print(f"  {marker} py:  {r}")
        if r != g:
            print(f"     got: {g}")


if __name__ == "__main__":
    sys.exit(main())
