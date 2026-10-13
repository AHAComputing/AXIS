#!/usr/bin/env python3
"""JIT step 5: transpile a decoded block to specialized native code, proven.

This is the native-codegen rung of the JIT plan (docs/generated_artifacts_plan.md
section 7, step 5). Where axis_sim.h pre-decodes a block and interprets it with a
dispatch loop, this JIT goes one further: it *transpiles* the block into a single
straight-line C function with the operand register indices and immediates baked
in as constants, then compiles it fresh per block with `cc -O2` (native codegen)
and runs it. Pure instructions become direct calls to the proven `axis_eval_*`
semantics (which -O2 inlines and constant-folds into real specialized machine
code); effectful instructions fall back to the proven `axis_exec_step` runtime.
So the whole thing reuses only already-differentially-proven code -- no new
semantics to trust -- and is itself proven here: the JIT-compiled block's
architectural trace must equal the Python interpreter (== golden) over random
programs, across the full E1-E4 surface.

Compiling per block is inherent to a JIT (each block gets its own code), so this
runs fewer programs than the interpreter fuzzer by default.

Usage: tools/jit_c.py [input.axisl] [--programs N] [--length L] [--seed S]

Requires: cargo (from the AXIS repo root) and cc on PATH.
"""

from __future__ import annotations

import argparse
import importlib
import re
import shutil
import subprocess
import sys
import tempfile

import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0, str(_Path(__file__).resolve().parent))
from axis_cli import DECLINED
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import exec_fuzz as ef  # noqa: E402  (reuse generator, canonical trace, reference)

AXIS_ROOT = ef.AXIS_ROOT


def pyident(mnemonic: str) -> str:
    return re.sub(r"[^0-9A-Za-z]", "_", mnemonic).lower()


def transpile(program, sem_h: str, lift):
    """Transpile a block into straight-line C. Returns (body, has_effect, npure)."""
    body = []
    has_effect = False
    npure = 0
    for entry, values, word in program:
        mnemonic = entry["mnemonic"]
        ident = pyident(mnemonic)
        pure = entry.get("semantics") is not None and f"axis_eval_{ident}(" in sem_h
        if pure:
            npure += 1
            args = []
            for op in entry["operands"]:
                if op["role"] == "in":
                    v = values[op["name"]]
                    args.append(f"regs[{v}]" if lift.is_register_operand(op["kind"])
                                else f"{v}u")
            dst = next((values[op["name"]] for op in entry["operands"]
                        if op["role"] == "out"
                        and lift.is_register_operand(op["kind"])), None)
            call = f"axis_eval_{ident}({', '.join(args)})"
            if dst is not None:
                body.append(f"  regs[{dst}] = {call}; pc += 4u; steps++;  /* jit {mnemonic} */")
            else:
                body.append(f"  (void){call}; pc += 4u; steps++;  /* jit {mnemonic} */")
        else:
            has_effect = True
            body.append(
                f"  {{ axis_exec_result r = axis_exec_step({word}u, regs, 32, &M, pc);"
                f" pc = r.next_pc; steps++;"
                f" if (r.trapped) {{ trapped = 1; cause = r.trap_cause ? r.trap_cause : \"-\";"
                f" goto done; }} }}  /* runtime {mnemonic} */"
            )
    return "\n".join(body), has_effect, npure


def driver(program, sem_h: str, lift):
    block, has_effect, npure = transpile(program, sem_h, lift)
    label = "done:;\n" if has_effect else ""
    src = (
        '#include <stdio.h>\n#include <stdint.h>\n#include "axis_exec.h"\n\n'
        + ef._C_MEM
        + "int main(void) {\n"
        "  uint32_t pc; if (scanf(\"%u\", &pc) != 1) return 2;\n"
        f"  uint32_t regs[{ef.REG_COUNT}];\n"
        f"  for (int i = 0; i < {ef.REG_COUNT}; ++i) if (scanf(\"%u\", &regs[i]) != 1) return 2;\n"
        "  memctx ctx = { {0}, 0 };\n"
        "  axis_mem M = { mem_read, mem_write, &ctx }; (void)M;\n"
        "  int steps = 0, trapped = 0; const char *cause = \"-\";\n"
        "  /* ---- JIT-transpiled block (operand indices baked in) ---- */\n"
        + block + "\n" + label
        + "  printf(\"REGS\");\n"
        f"  for (int i = 0; i < {ef.REG_COUNT}; ++i) printf(\" %08x\", regs[i]);\n"
        "  printf(\"\\nPC %08x\\n\", pc);\n"
        "  printf(\"TRAP %d %s\\n\", trapped, trapped ? cause : \"-\");\n"
        "  printf(\"MEM\");\n"
        "  for (int i = 0; i < ctx.count; ++i) printf(\" %08x:%u:%08x\", ctx.cells[i].addr, ctx.cells[i].width, ctx.cells[i].value);\n"
        "  printf(\"\\nSTEPS %d\\n\", steps);\n"
        "  return 0;\n}\n"
    )
    return src, npure



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
    parser.add_argument("--programs", type=int, default=40)
    parser.add_argument("--length", type=int, default=12)
    parser.add_argument("--seed", type=lambda s: int(s, 0), default=0x51A)
    args = parser.parse_args()

    if not shutil.which("cc"):
        print("SKIP: cc not found")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="axis_jit_"))
    ef.emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    ef.emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    ef.emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    ef.emit(args.axis_file, "emit-semantics-c", workdir / "axis_semantics.h")
    ef.emit(args.axis_file, "emit-lift-c", workdir / "axis_lift.h")
    ef.emit(args.axis_file, "emit-exec-c", workdir / "axis_exec.h")
    sem_h = (workdir / "axis_semantics.h").read_text()

    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    axis_lift = importlib.import_module("axis_lift")

    entries = [
        e for e in axis_lift.AXIS_LIFT_TABLE
        if (e["semantics"] is not None or e.get("effects") is not None)
        and all(op["fields"] for op in e["operands"] if op["kind"] in ("reg", "imm"))
    ]
    if not entries:
        print("no executable, encodable instructions to JIT")
        return DECLINED

    import random
    rng = random.Random(args.seed)
    failures = 0
    total_pure = total_ops = 0
    seen: set[str] = set()
    for n in range(args.programs):
        program = ef.gen_program(entries, args.length, rng, axis_lift)
        seen.update(entry["mnemonic"] for entry, _v, _w in program)
        words = [w for _, _, w in program]
        init_regs = [rng.getrandbits(32) for _ in range(ef.REG_COUNT)]
        init_pc = rng.getrandbits(30) * 4

        reference = ef.run_python(axis_exec, words,
                                  {i: v for i, v in enumerate(init_regs)}, init_pc)

        src, npure = driver(program, sem_h, axis_lift)
        total_pure += npure
        total_ops += len(program)
        (workdir / "jit.c").write_text(src)
        subprocess.run(
            ["cc", "-std=c11", "-O2", "-Wall", "-Werror", "-I", str(workdir),
             "-o", str(workdir / "jit"), str(workdir / "jit.c")],
            check=True,
        )
        stdin = f"{init_pc}\n" + " ".join(str(v) for v in init_regs) + "\n"
        got = subprocess.run([str(workdir / "jit")], input=stdin,
                             capture_output=True, text=True).stdout.strip()
        if got != reference:
            failures += 1
            print(f"FAIL program #{n} (jit != python)")
            ef._report_diff(reference, got, words, init_regs, init_pc)
            if failures >= 3:
                print("... stopping after 3 failures")
                return 1

    pct = (100 * total_pure // total_ops) if total_ops else 0
    print(f"{args.programs} blocks x {args.length} instrs JIT-compiled "
          f"({pct}% ops specialized inline, rest via proven runtime): "
          f"{failures} divergences")
    offered = {entry["mnemonic"] for entry in entries}
    missing = sorted(offered - seen)
    print(f"  coverage: {len(seen)}/{len(offered)} instruction(s) compiled"
          + (f"; never compiled: {', '.join(missing[:6])}"
             f"{f' (+{len(missing) - 6} more)' if len(missing) > 6 else ''}"
             if missing else ""))
    # Class coverage is required where instruction coverage is only reported:
    # a run that never compiled a whole effect class is a green result about a
    # path it did not take.
    offered_shapes = {effect_shape(entry) for entry in entries}
    covered_shapes = {effect_shape(entry) for entry in entries
                      if entry["mnemonic"] in seen}
    absent_shapes = offered_shapes - covered_shapes
    print(f"  classes: {len(covered_shapes)}/{len(offered_shapes)} compiled"
          + (f"; never compiled: "
             + ", ".join(sorted("+".join(shape) or "pure" for shape in absent_shapes))
             if absent_shapes else ""))
    ok = failures == 0 and not absent_shapes
    print("jit-compiled block == golden: PASS" if ok else "jit-compiled block == golden: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
