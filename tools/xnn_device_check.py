#!/usr/bin/env python3
"""An MMIO device, held to the engine's own RTL. Gate.

H3 (docs/accelerator_design.md). `examples/xnn_systolic.axisl` describes PCE's
XNN systolic GEMM engine (hardware/accel_engines/xnn_systolic_engine.py) as its
register map: `defdevice` names, for each word of the MMIO window, the
instruction of the device's ISA that runs when the host touches it -- stream a
weight, stream an activation, set M, kick, read status, pop a result, rewind.
The claims:

  1. **the engine's RTL agrees.** Random jobs -- M from 1 to 8, K from 1 to
     12 as chains of up to three K tiles (H3b: register 0x30's accumulate,
     more-K and valid K), signed int8 weights and activations -- and every
     refusal the engine has (an orphan accumulate, a kick under the sticky
     error, M of 0 or 9, valid K over 4, a continuation that changes M), each
     followed by a job that must still be right, run as ONE host session
     through PCE's own PyRTL engine (simulated with PCE's vendored PyRTL,
     polling busy as a host does) and through AXIS's handlers on the Python
     executor. Every value the host reads -- results and status -- must be
     the same, and must be what a protocol model written here from scratch
     reads;
  2. **every executor runs the handlers.** Each access of the Python session
     is replayed on the wide C and Rust executors from the device memory it
     started with: the value read and the device memory after must match;
  3. **a bad register map is refused**: a register outside the window, a
     misaligned one, two handlers for one word and direction, a handler that
     is not an instruction, a read handler with no result, a write handler
     that writes a register;
  4. **the source survives**: `defdevice` round-trips through `emit-lisp`
     stably, and the manifest publishes the map.

Injections that must fail it: unsigned arithmetic, a result pointer that
never advances, transposed weights, a status stuck busy (H3); an accumulate
that drops the prior bank, no valid-K mask, the kick writing the active bank,
an error that does not block a kick (H3b). A refused kick that computes anyway
is an EQUIVALENT mutant: it writes the inactive bank, which the next accepted
kick overwrites, so no read can see it.

The engine takes cycles and reports busy; AXIS's kick completes before the
next access, so status reads 0. A host that polls reads the same results --
the session polls on the RTL side and reads status once on AXIS's.

Without a PCE checkout (PCE_ROOT, default ../pce) claim 1 is held to the
Python reference alone.

Usage: tools/xnn_device_check.py <examples/xnn_systolic.axisl>
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import random
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix
import exec_wide_check as wide

AXIS_ROOT = Path(__file__).resolve().parent.parent
PCE_ROOT = Path(os.environ.get("PCE_ROOT", AXIS_ROOT.parent / "pce"))
ROWS = COLS = 4
M_MAX = 8
MASK32 = 0xFFFF_FFFF


def axis(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([*axis_prefix(), *args], capture_output=True, text=True, cwd=AXIS_ROOT)


def signed32(value: int) -> int:
    return value - (1 << 32) if value & (1 << 31) else value


def tile_ops(rng: random.Random, a, w, m: int, lo: int, hi: int, acc: int, more: int) -> list:
    """One K tile: rewind, stream the slice's weights and activations (junk
    past valid K, which the engine must mask), set M and K control, kick."""
    ops = [("w", 0x18, 0)]
    for r in range(ROWS):
        for c in range(COLS):
            ops.append(("w", 0x00, (w[lo + r][c] if lo + r < hi else rng.randrange(256)) & 0xFF))
    for i in range(m):
        for r in range(ROWS):
            ops.append(("w", 0x04, (a[i][lo + r] if lo + r < hi else rng.randrange(256)) & 0xFF))
    valid = hi - lo if hi - lo < ROWS else 0
    ops += [("w", 0x08, m), ("w", 0x30, acc | (more << 1) | (valid << 16)), ("kick",),
            ("r", 0x10)]
    return ops


def job_ops(rng: random.Random, k: int) -> list:
    m = rng.randrange(1, M_MAX + 1)
    a = [[rng.randrange(-128, 128) for _ in range(k)] for _ in range(m)]
    w = [[rng.randrange(-128, 128) for _ in range(COLS)] for _ in range(k)]
    tiles = [(lo, min(lo + ROWS, k)) for lo in range(0, k, ROWS)]
    ops = []
    for index, (lo, hi) in enumerate(tiles):
        ops += tile_ops(rng, a, w, m, lo, hi, 1 if index else 0, 1 if index < len(tiles) - 1 else 0)
    ops += [("r", 0x14)] * (m * COLS)
    return ops


def session(rng: random.Random) -> list:
    """A host session: single tiles, K chains, and every refusal the engine
    has -- each followed by a rewind and a job that must still be right."""
    ops = []
    for k in (4, 3, 1, 6, 9, 12, 8):
        ops += job_ops(rng, k)
    # An orphan accumulate: refused, the error sticks, results unchanged.
    ops += [("w", 0x18, 0), ("w", 0x08, 2), ("w", 0x30, 1), ("kick",), ("r", 0x10),
            ("r", 0x14), ("r", 0x14)]
    # A plain kick while the error is set: refused too -- and the results are
    # read after it, or a kick that the error failed to block would change
    # nothing anything looked at (it did, once: the injection passed).
    ops += [("w", 0x30, 0), ("kick",), ("r", 0x10), ("r", 0x14), ("r", 0x14)]
    ops += job_ops(rng, 5)
    # Bad M, bad valid K: each sets the error; a rewind clears it.
    for bad in ((0x08, 0), (0x08, M_MAX + 1), (0x30, (ROWS + 1) << 16)):
        ops += [("w", 0x18, 0), ("w", *bad), ("r", 0x10)]
    ops += job_ops(rng, 7)
    # A chain whose continuation changes M: refused.
    m = 3
    a = [[rng.randrange(-128, 128) for _ in range(8)] for _ in range(m + 1)]
    w = [[rng.randrange(-128, 128) for _ in range(COLS)] for _ in range(8)]
    ops += tile_ops(rng, a, w, m, 0, 4, 0, 1)
    ops += tile_ops(rng, a, w, m + 1, 4, 8, 1, 0)
    ops += [("r", 0x14)] * 4
    ops += job_ops(rng, 10)
    return ops


def model_session(ops: list) -> list[int]:
    """The protocol as documented and measured, written here from scratch --
    a third implementation, so a disagreement says which side is wrong."""
    st = {"w": [], "a": [], "rptr": 0, "m": 0, "kctl": 0, "err": 0, "open": 0,
          "chain_m": 0, "banks": [[0] * (M_MAX * COLS), [0] * (M_MAX * COLS)], "sel": 0}
    reads = []
    for op in ops:
        if op[0] == "w":
            _, off, v = op
            if off == 0x18:
                st.update(w=[], a=[], rptr=0, err=0)
            elif off == 0x00:
                st["w"].append(v)
            elif off == 0x04:
                st["a"].append(v)
            elif off == 0x08:
                if 1 <= v <= M_MAX:
                    st["m"] = v
                else:
                    st["err"] = 1
            elif off == 0x30:
                if (v >> 16) <= ROWS:
                    st["kctl"] = v
                else:
                    st["err"] = 1
        elif op[0] == "kick":
            acc, more, vk = st["kctl"] & 1, (st["kctl"] >> 1) & 1, (st["kctl"] >> 16) or ROWS
            ok = not st["err"] and (not acc or (st["open"] and st["m"] == st["chain_m"]))
            if not ok:
                st["err"] = 1
                continue
            sx = lambda x: x - 256 if x & 0x80 else x
            prior, dest = st["banks"][st["sel"]], st["banks"][st["sel"] ^ 1]
            for i in range(st["m"]):
                for n in range(COLS):
                    total = sum(sx(st["a"][i * ROWS + k]) * sx(st["w"][k * COLS + n]) for k in range(vk))
                    dest[i * COLS + n] = (total + (prior[i * COLS + n] if acc else 0)) & MASK32
            st.update(sel=st["sel"] ^ 1, open=more, chain_m=st["m"])
        else:
            _, off = op
            if off == 0x10:
                reads.append((st["err"] << 1) | (st["open"] << 2))
            else:
                reads.append(st["banks"][st["sel"]][st["rptr"]])
                st["rptr"] += 1
    return reads


RTL = r"""
import json, sys
sys.path.insert(0, "third_party/pyrtl"); sys.path.insert(0, ".")
import pyrtl
from hardware.accel_engines.xnn_systolic_engine import XNNSystolicEngine
pyrtl.reset_working_block()
engine = XNNSystolicEngine(rows=%(rows)d, cols=%(cols)d, m_max=%(m_max)d, name="dut")
port = engine.mmio_port
port.req_valid <<= pyrtl.Input(1, "v"); port.req_write <<= pyrtl.Input(1, "w")
port.req_addr <<= pyrtl.Input(32, "a"); port.req_data <<= pyrtl.Input(32, "d")
port.rsp_ready <<= 1
pyrtl.Output(1, "rv").__ilshift__(port.rsp_valid)
pyrtl.Output(32, "rd").__ilshift__(port.rsp_data)
pyrtl.Output(1, "ready").__ilshift__(port.req_ready)
sim = pyrtl.Simulation()
def step(v=0, w=0, a=0, d=0):
    sim.step({"v": v, "w": w, "a": a, "d": d & 0xFFFFFFFF})
    return sim.inspect("rv"), sim.inspect("rd"), sim.inspect("ready")
def write(a, d=0):
    for _ in range(100):
        if step(1, 1, a, d)[2]: break
    step()
def read(a):
    for _ in range(100):
        rv, rd, ready = step(1, 0, a)
        if ready: break
    for _ in range(100):
        if rv: return rd
        rv, rd, ready = step()
    raise SystemExit("no response")
out = []
for op in json.load(sys.stdin):
    if op[0] == "w":
        write(op[1], op[2])
    elif op[0] == "kick":
        write(0x0C)
        polls = 0
        while read(0x10) & 1:
            polls += 1
            if polls > 2000: raise SystemExit("busy forever")
    else:
        out.append(read(op[1]))
print(json.dumps(out))
"""


def rtl_session(ops: list) -> list[int] | None:
    if not (PCE_ROOT / "hardware/accel_engines/xnn_systolic_engine.py").exists():
        return None
    script = RTL % {"rows": ROWS, "cols": COLS, "m_max": M_MAX}
    result = subprocess.run([sys.executable, "-c", script], input=json.dumps(ops),
                            capture_output=True, text=True, cwd=PCE_ROOT)
    if result.returncode != 0:
        raise SystemExit(f"FAIL: the RTL session did not run: {result.stderr.strip()[-400:]}")
    return json.loads(result.stdout.strip().splitlines()[-1])


class Memory:
    def __init__(self, store=None):
        self.store = dict(store or {})

    def read(self, address, width):
        return self.store.get((address, width), 0)

    def write(self, address, value, width):
        self.store[(address, width)] = value & ((1 << width) - 1)


class DeviceModel:
    """The register map, run as its handlers: a write puts the value in x1,
    a read takes the result from x2, and device memory is the engine's state."""

    VALUE, RESULT = 1, 2

    def __init__(self, device: dict, executor, lift):
        self.executor, self.isa = executor, device["isa"]
        entries = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
        names = {entry["mnemonic"].lower(): entry for entry in lift.AXIS_LIFT_TABLE}
        self.handlers = {}
        for register in device["registers"]:
            entry = names.get(register["handler"]) or entries.get(register["handler"].upper())
            word = entry["match"]
            for operand in entry["operands"]:
                if operand["role"] == "enc" or not operand.get("fields"):
                    continue
                number = self.VALUE if operand["role"] == "in" else self.RESULT
                for lo, op_lo, width in operand["fields"]:
                    word |= ((number >> op_lo) & ((1 << width) - 1)) << lo
            self.handlers[(register["access"], register["offset"])] = word
        self.memory = Memory()
        self.trace: list[dict] = []

    def access(self, kind: str, offset: int, value: int = 0) -> int:
        word = self.handlers[(kind, offset)]
        before = dict(self.memory.store)
        regs = {self.VALUE: value & MASK32}
        out = self.executor.step(word, regs, self.memory, 0, isa=self.isa)
        if out is None or out.get("trap") is not None:
            raise SystemExit(f"FAIL: handler for {kind} {offset:#x} did not run: {out}")
        result = regs.get(self.RESULT, 0) & MASK32 if kind == "read" else None
        self.trace.append({"word": word, "value": value & MASK32, "result": result,
                           "before": before, "after": dict(self.memory.store)})
        return result or 0


def axis_session(model: DeviceModel, ops: list) -> list[int]:
    reads = []
    for op in ops:
        if op[0] == "w":
            model.access("write", op[1], op[2])
        elif op[0] == "kick":
            model.access("write", 0x0C)
        else:
            reads.append(model.access("read", op[1]))
    return reads


def replay_compiled(model: DeviceModel, axis_file: Path, workdir: Path) -> list[str]:
    cases = []
    for index, step in enumerate(model.trace):
        regs = [0] * 32
        regs[DeviceModel.VALUE] = step["value"]
        after = step["after"]
        changed = [(a, w, v) for (a, w), v in after.items() if step["before"].get((a, w)) != v]
        cases.append({
            "mnemonic": f"XNN_ACCESS_{index}", "word": step["word"], "isa": model.isa, "pc": 0,
            "regs": regs, "seed": [(a, w, v) for (a, w), v in step["before"].items()],
            "state": [], "mem_checks": changed,
            "reg_checks": [(DeviceModel.RESULT, step["result"])] if step["result"] is not None else [],
            "state_write": None, "next_pc": 4, "trap": None, "slots": 32,
        })
    failures = []
    for lang in ("c", "rust"):
        target = workdir / lang
        target.mkdir()
        if lang == "c":
            for command, output in (("emit-exec-c", "axis_exec.h"), ("emit-lift-c", "axis_lift.h"),
                                    ("emit-semantics-c", "axis_semantics.h")):
                wide.emit(axis_file, command, target / output)
        result = wide.build_and_run(cases, target, axis_file, lang)
        lines = result.stdout.strip().splitlines()
        summary = lines[-1] if lines else result.stderr.strip()[-300:]
        if result.returncode != 0 or " 0 failures" not in summary or " 0 declined" not in summary:
            failures.append(f"wide {lang}: {summary}")
            failures.extend(f"  {line}" for line in lines[:4] if line.startswith(("FAIL", "DECLINE")))
    return failures


def refused(source: str, workdir: Path, name: str, *reasons: str) -> str | None:
    path = workdir / f"{name}.axisl"
    path.write_text(source)
    result = axis("check", str(path))
    if result.returncode == 0:
        return f"{name}: accepted"
    message = result.stderr + result.stdout
    missing = [r for r in reasons if r not in message]
    return f"{name}: refused, but not for {missing}: {message.strip()[:220]}" if missing else None


def mutate(source: str, old: str, new: str) -> str:
    if old not in source:
        raise SystemExit(f"FAIL: mutant anchor `{old}` not found -- corpus moved?")
    return source.replace(old, new, 1)


def check_refusals(source: str, workdir: Path) -> list[str]:
    mutants = [
        ("outside-window", mutate(source, "(register 0x18 write xnn_w_reset)",
                                  "(register 0x1000 write xnn_w_reset)"), ("window",)),
        ("misaligned", mutate(source, "(register 0x18 write xnn_w_reset)",
                              "(register 0x1a write xnn_w_reset)"), ("0x1a",)),
        ("two-handlers", mutate(source, "(register 0x18 write xnn_w_reset)",
                                "(register 0x0c write xnn_w_reset)"), ("two write handlers",)),
        ("not-an-instruction", mutate(source, "(register 0x18 write xnn_w_reset)",
                                      "(register 0x18 write xnn_w_rewind)"), ("xnn_w_rewind",)),
        ("read-without-result", mutate(source, "(register 0x10 read xnn_r_status)",
                                       "(register 0x10 read xnn_w_kick)"), ("exactly one register output",)),
        ("write-that-writes", mutate(source, "(register 0x18 write xnn_w_reset)",
                                     "(register 0x18 write xnn_r_result)"), ("no outputs",)),
    ]
    return [c for name, text, reasons in mutants if (c := refused(text, workdir, name, *reasons))]


def check_round_trip(axis_file: Path, workdir: Path) -> list[str]:
    once, twice = workdir / "once.axisl", workdir / "twice.axisl"
    for src, dst in ((axis_file, once), (once, twice)):
        result = axis("emit-lisp", str(src), "-o", str(dst))
        if result.returncode != 0:
            return [f"emit-lisp {src.name}: {result.stderr.strip()[:200]}"]
    text = once.read_text()
    failures = []
    if text.count("(register ") != 8 or "(defdevice xnn_systolic" not in text:
        failures.append("the round trip lost the register map")
    if twice.read_text() != text:
        failures.append("emit-lisp is not stable under a second round trip")
    if axis("emit-json", str(axis_file)).stdout != axis("emit-json", str(once)).stdout:
        failures.append("the manifest differs after a round trip")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--no-rtl", action="store_true",
                        help="hold AXIS to the model alone (for iterating; the ladder runs the RTL)")
    args = parser.parse_args()
    axis_file = args.axis_file.resolve()
    workdir = Path(tempfile.mkdtemp(prefix="axis_xnn_dev_"))
    for command, output in (("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py"),
                            ("emit-exec-python", "axis_exec.py")):
        wide.emit(axis_file, command, workdir / output)
    sys.path.insert(0, str(workdir))
    executor = importlib.import_module("axis_exec")
    lift = importlib.import_module("axis_lift")
    manifest = json.loads(axis("emit-json", str(axis_file)).stdout)
    device = manifest["devices"][0]

    ops = session(random.Random(0xA11))
    model = DeviceModel(device, executor, lift)
    ours = axis_session(model, ops)
    want = model_session(ops)
    theirs = None if args.no_rtl else rtl_session(ops)
    failures: list[str] = []
    labels = [op for op in ops if op[0] == "r"]

    def first_difference(x, y):
        return next((i for i, (p, q) in enumerate(zip(x, y)) if p != q), None)

    if ours != want:
        i = first_difference(ours, want)
        failures.append(f"read {i} ({labels[i][1]:#x}): AXIS {ours[i]:#x}, the model {want[i]:#x}")
    if theirs is not None and theirs != ours:
        i = first_difference(theirs, ours)
        failures.append(f"read {i} ({labels[i][1]:#x}): the RTL {theirs[i]:#x}, AXIS {ours[i]:#x}")
    if theirs is not None and theirs != want:
        i = first_difference(theirs, want)
        failures.append(f"read {i}: the RTL {theirs[i]:#x}, the model {want[i]:#x}")
    kinds = {"errors": sum(1 for v, (_, off) in zip(want, labels) if off == 0x10 and v & 2),
             "open chains": sum(1 for v, (_, off) in zip(want, labels) if off == 0x10 and v & 4)}
    if not all(kinds.values()):
        failures.append(f"the session never showed {[k for k, v in kinds.items() if not v]}")
    source = ("PCE's RTL and the model" if theirs is not None
              else "the model (RTL skipped)" if args.no_rtl else "the model (no PCE checkout)")
    sections = (
        (f"{len(ours)} reads over {sum(1 for op in ops if op[0] == 'kick')} kicks agree with {source}",
         failures),
        (f"{len(model.trace)} accesses replayed on the wide C and Rust executors",
         replay_compiled(model, axis_file, workdir)),
        ("a bad register map is refused", check_refusals(axis_file.read_text(), workdir)),
        ("the source survives a round trip", check_round_trip(axis_file, workdir)),
    )
    ok = True
    for title, problems in sections:
        print(f"{'ok  ' if not problems else 'FAIL'} {title}")
        for problem in problems[:8]:
            print(f"     {problem}")
        ok &= not problems
    print("XNN device agrees: PASS" if ok else "XNN device agrees: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
