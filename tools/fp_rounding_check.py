#!/usr/bin/env python3
"""The premise behind declining directed rounding, checked rather than assumed.

Every backend that goes through LLVM -- the IR emitter, the JIT, the lifter --
declines an instruction whose semantics name an explicit rounding mode. 137 of
them do, across RISC-V and AArch64: `fadd.s.rdn`, `fcvt.w.d.rtz`, and their
kind.

The reason usually given is that emitted IR "cannot set the floating-point
environment". That is not quite true, and the imprecision is dangerous: LLVM
*does* have a way to say it in the IR itself, `llvm.experimental.constrained.*`
with a `round.downward` metadata operand, and no environment is involved. A
reader who knows that is one step from emitting those intrinsics and believing
the problem solved.

The actual reason is one level down. The host LLVM parses the mode, verifies
it, and then discards it in instruction selection: `round.downward` and
`round.upward` both come out as a bare `fadd`, which rounds to nearest. Emitting
the intrinsic would not produce directed rounding, it would produce
round-to-nearest wearing a label that says otherwise -- a wrong answer that
looks authoritative, which is worse than the decline.

So this gate pins the premise. It asks the host LLVM to add the same two
numbers under two opposite rounding modes and requires that it get the *same*
answer, because that is what "the mode is discarded" means. The day a newer
LLVM honours the metadata, this gate fails -- and the failure is the good news:
the decline can be lifted, and the message says so.
"""
from __future__ import annotations

import ctypes
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED  # noqa: E402

# 1.0f + 2**-30. The exact sum lies strictly between 1.0 and the next float
# above it, so the three modes have three distinguishable answers: downward
# gives 1.0, upward gives 1 + 2**-23, nearest gives 1.0. One pair of modes
# would do; using a value that separates them all makes the failure legible.
LEFT = 1.0
RIGHT = float.fromhex("0x1p-30")

MODULE = r'''
declare float @llvm.experimental.constrained.fadd.f32(float, float, metadata, metadata)

define float @axis_round_down(float %a, float %b) #0 {
  %r = call float @llvm.experimental.constrained.fadd.f32(
         float %a, float %b, metadata !"round.downward",
         metadata !"fpexcept.ignore") #0
  ret float %r
}

define float @axis_round_up(float %a, float %b) #0 {
  %r = call float @llvm.experimental.constrained.fadd.f32(
         float %a, float %b, metadata !"round.upward",
         metadata !"fpexcept.ignore") #0
  ret float %r
}

attributes #0 = { strictfp }
'''


def main() -> int:
    try:
        import llvmlite.binding as llvm
    except ImportError:
        print("directed rounding survives codegen: DECLINED (no llvmlite)")
        return DECLINED

    llvm.initialize()
    llvm.initialize_native_target()
    llvm.initialize_native_asmprinter()

    module = llvm.parse_assembly(MODULE)
    module.verify()
    machine = llvm.Target.from_default_triple().create_target_machine()

    # The assembly says it plainly, and is worth reading when this fails.
    assembly = machine.emit_assembly(module)
    engine = llvm.create_mcjit_compiler(module, machine)
    engine.finalize_object()
    signature = ctypes.CFUNCTYPE(ctypes.c_float, ctypes.c_float, ctypes.c_float)
    down = signature(engine.get_function_address("axis_round_down"))(LEFT, RIGHT)
    up = signature(engine.get_function_address("axis_round_up"))(LEFT, RIGHT)

    version = ".".join(str(part) for part in llvm.llvm_version_info)
    if down == up:
        floats = [line.strip() for line in assembly.splitlines()
                  if "fadd" in line]
        print(f"LLVM {version} discards the rounding mode: {down.hex()} both "
              f"ways, {floats[:1]}")
        print("directed rounding survives codegen: PASS (it does not, as "
              "assumed)")
        return PASSED

    print(f"LLVM {version} HONOURS the rounding mode: down {down.hex()}, "
          f"up {up.hex()}")
    print("The decline on directed rounding rests on codegen discarding the "
          "mode, and this LLVM no longer does. `_rm` semantics can now be "
          "lowered with llvm.experimental.constrained.* -- see the refusals "
          "in src/lifter.rs and src/emit/llvm.rs, and "
          "docs/simd_fp_design.md.")
    print("directed rounding survives codegen: FAIL")
    return FAILED


if __name__ == "__main__":
    raise SystemExit(main())
