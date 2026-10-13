#!/usr/bin/env python3
"""RV64 cores on one memory show what RVWMO allows. Gate.

`a64_weak_check.py` with RISC-V's instructions: `rv64i`, whose ISA says
`(memory-model rvwmo)`, with `SD`, `LD` and `FENCE` -- told to order memory
from its `(barrier fence ...)`. The same four machines, two cores each, the
same sweep of timings, and the same table (docs/memory_model_design.md):
store buffering with a buffer and never without; message passing's and the
late load's weak outcomes only on the relaxed machine; none of them past a
fence; a word loaded twice never set and then clear; no replays.

Usage: tools/rv_weak_check.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import a64_weak_check  # noqa: E402

ZERO = 0
RV64 = {
    "corpus": "rv64i.axisl", "isa": "rv64i", "model": "rvwmo", "kind": "rv_gpr",
    "prefix": "rw", "width": 64, "fence": "FENCE", "title": "RV64 cores show what RVWMO allows",
    # Byte offsets, a line apart.
    "at": (0, 64, 128, 192),
    "needed": ["LD", "SD", "MUL", "BEQ", "FENCE"],
    "ld": lambda a, rd, rs1, at: a("LD", rd=rd, rs1=rs1, imm=at),
    "st": lambda a, rs2, rs1, at: a("SD", rs2=rs2, rs1=rs1, imm=at),
    "mul": lambda a, rd, rs1, rs2: a("MUL", rd=rd, rs1=rs1, rs2=rs2),
    "barrier": lambda a: a("FENCE", option=0xFF),
    # Back to the load while the flag is clear.
    "spin": lambda a, reg: a("BEQ", rs1=reg, rs2=ZERO, imm=-4),
}

if __name__ == "__main__":
    raise SystemExit(a64_weak_check.main(RV64))
