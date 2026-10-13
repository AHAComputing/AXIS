#!/usr/bin/env python3
"""A launch reads its descriptor: loads in addresses and guards. Gate.

H1a (docs/accelerator_design.md). An effect's address and guard may read
memory, as its value could since T8b. `examples/descriptor_reads.axisl` is a
descriptor launch shaped like AHA's Bio queue ABI, and every claim below is
held against a reference written HERE, from the descriptor's layout, not from
anything AXIS emits:

  1. **every executor computes the launch.** The Python executor and the wide
     C and Rust executors each run four kinds of descriptor -- valid, a bad
     magic, a bad version, a count past what the engine holds -- and must leave
     exactly the memory the reference does: the doubled words and a 0 status,
     or the right error code and nothing else written;
  2. **the descriptor is high, and one guard is narrow.** Its base is above
     2**32, and the notify flag is tested by an i8 comparison, so a guard
     whose loads were evaluated at the comparison's width reads
     `base & 0xff`. That is the `guard_load_address_width` a fixture now
     publishes, and the bug it prevents is the one `setstate` had;
  3. **every load an effect names is performed**, whatever the guard's `and`
     decides. For a descriptor with a bad magic, the Python executor must read
     the version and the count too, in the order the effect names them. The C
     simulator used to stop at the magic; `sim_vs_executor` on this corpus
     holds the compiled side to the same trace;
  4. **nothing past the guard reads.** A failed guard skips its effect's
     address and value, so a bad descriptor's element loop reads no input.

Injection-checked: not passing `guard_load_address_width` to the Python
executor's guard fails 1 and 2 -- the flags byte is read from `base & 0xff` --
and it PASSED until the corpus had a guard narrower than 64 bits, which is why
the notify flag exists; evaluating the guard's `and` lazily in the golden
evaluator fails 3; evaluating a store's value before its guard fails 3 and 4.

Usage: tools/descriptor_reads_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib
import random
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix
import exec_wide_check as wide

MAGIC = 0x42494F31
OFFSETS = {"magic": 0, "version": 4, "input_ptr": 16, "output_ptr": 24,
           "param0": 40, "job_id": 56, "status_ptr": 64}
FLAGS = 12
CAPACITY = 8
KINDS = ("ok", "magic", "version", "count")


def descriptor(rng: random.Random, kind: str) -> tuple[int, dict]:
    """A descriptor above 2**32 and the memory it points into."""
    base = rng.randrange(1 << 33, 1 << 48) & ~0xFF
    region = rng.randrange(1 << 20, 1 << 30) & ~0xFFF
    fields = {
        "magic": MAGIC if kind != "magic" else MAGIC ^ (1 << rng.randrange(32)),
        "version": 1 if kind != "version" else rng.randrange(2, 1 << 16),
        "input_ptr": region,
        "output_ptr": region + 0x100,
        "param0": rng.randrange(0, CAPACITY + 1) if kind != "count"
        else rng.randrange(CAPACITY + 1, 1 << 16),
        "status_ptr": region + 0x200,
    }
    fields["job_id"] = rng.getrandbits(32)
    memory = {(base + OFFSETS[name], 32): value for name, value in fields.items()}
    # The flags byte is its own cell: these executors' memory is keyed by
    # address AND width, so an i8 read at 12 is not the low byte of a word.
    memory[(base + FLAGS, 8)] = rng.getrandbits(8)
    for i in range(CAPACITY):
        memory[(region + 4 * i, 32)] = rng.getrandbits(32)
    return base, memory


def reference(memory: dict, base: int) -> dict:
    """What the engine leaves behind, from the layout and nothing else."""
    field = {name: memory.get((base + off, 32), 0) for name, off in OFFSETS.items()}
    out = dict(memory)
    if field["magic"] != MAGIC:
        status = 1
    elif field["version"] != 1:
        status = 2
    elif field["param0"] > CAPACITY:
        status = 3
    else:
        status = 0
        for i in range(field["param0"]):
            word = memory.get((field["input_ptr"] + 4 * i, 32), 0)
            out[(field["output_ptr"] + 4 * i, 32)] = (word * 2) & 0xFFFF_FFFF
    out[(field["status_ptr"], 32)] = status
    if memory.get((base + FLAGS, 8), 0) & 1:
        out[(field["status_ptr"] + 4, 32)] = field["job_id"]
    return out


class Recorder:
    """Width-keyed memory that remembers the order it was read in."""

    def __init__(self, init):
        self.store = dict(init)
        self.reads: list[tuple[int, int]] = []

    def read(self, addr, width):
        self.reads.append((addr, width))
        return self.store.get((addr, width), 0)

    def write(self, addr, value, width):
        self.store[(addr, width)] = value & ((1 << width) - 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()
    axis_file = args.axis_file.resolve()
    workdir = Path(tempfile.mkdtemp(prefix="axis_desc_reads_"))
    for command, output in (("emit-lift-python", "axis_lift.py"),
                            ("emit-golden-python", "golden_model.py"),
                            ("emit-exec-python", "axis_exec.py")):
        wide.emit(axis_file, command, workdir / output)
    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")
    axis_lift = importlib.import_module("axis_lift")

    word = 11 | (6 << 15)                     # BIO_LAUNCH (x6)
    slot = axis_lift.register_slot("reg", 6)
    rng = random.Random(0xB10)
    trials = [(kind, *descriptor(rng, kind)) for kind in KINDS for _ in range(6)]
    failures: list[str] = []

    # 1, 2: the Python executor.
    for kind, base, memory in trials:
        mem = Recorder(memory)
        axis_exec.step(word, {slot: base}, mem, 0)
        want = reference(memory, base)
        if mem.store != want:
            wrong = sorted(k for k in set(want) | set(mem.store) if want.get(k) != mem.store.get(k))
            failures.append(f"python, {kind} descriptor at {base:#x}: memory differs at "
                            f"{[(hex(a), w) for a, w in wrong[:3]]}")

    # 3, 4: what a bad-magic descriptor reads, in order.
    kind, base, memory = next(t for t in trials if t[0] == "magic")
    mem = Recorder(memory)
    axis_exec.step(word, {slot: base}, mem, 0)
    guard = [(base + OFFSETS[name], 32) for name in ("magic", "version", "param0", "param0")]
    first = mem.reads[:4]
    if first != guard:
        failures.append(f"a failed guard read {[(hex(a), w) for a, w in first]}, not the "
                        f"magic, the version and the count twice, in that order")
    input_ptr = memory[(base + OFFSETS["input_ptr"], 32)]
    if any(input_ptr <= a < input_ptr + 4 * CAPACITY for a, _ in mem.reads):
        failures.append("a failed guard still read the input its effect would have copied")

    # 1: the wide C and Rust executors, on the same descriptors.
    cases = []
    for kind, base, memory in trials:
        want = reference(memory, base)
        regs = [0] * 32
        regs[slot] = base
        cases.append({
            "mnemonic": f"BIO_LAUNCH_{kind}", "word": word, "isa": "rvdesc", "pc": 0,
            "regs": regs, "seed": [(a, w, v) for (a, w), v in memory.items()],
            "state": [], "reg_checks": [],
            "mem_checks": [(a, w, v) for (a, w), v in want.items() if memory.get((a, w)) != v],
            "state_write": None, "next_pc": 4, "trap": None, "slots": 32,
        })
    for lang in ("c", "rust"):
        target = workdir / lang
        target.mkdir()
        if lang == "c":
            for command, output in (("emit-exec-c", "axis_exec.h"), ("emit-lift-c", "axis_lift.h"),
                                    ("emit-semantics-c", "axis_semantics.h")):
                wide.emit(axis_file, command, target / output)
        result = wide.build_and_run(cases, target, axis_file, lang)
        summary = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
        if result.returncode != 0 or " 0 failures" not in summary or " 0 declined" not in summary:
            failures.append(f"wide {lang}: {summary or result.stderr.strip()[:300]}")
            failures.extend(f"  {line}" for line in result.stdout.splitlines()[:4]
                            if line.startswith(("FAIL", "DECLINE")))

    print(f"{len(trials)} descriptors x 3 executors, {len(failures)} failure(s)")
    for failure in failures:
        print(f"  {failure}")
    ok = not failures
    print("descriptor reads agree: PASS" if ok else "descriptor reads agree: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
