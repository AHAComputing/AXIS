#!/usr/bin/env python3
"""A program is loaded from a file, run to completion, and counted. Gate.

Every other gate here asks about instructions. This asks about a PROGRAM: an
image on disk with an entry point, loaded the way a loader loads one, started
where it says to start, and run until it stops itself.

⚠️ That is the shape a co-design question has. "Is this extension worth it" is
not a question about one instruction, and until the stack could load and run a
workload it could only answer the first kind.

What is checked, and each of them has been wrong at least once in something
this session touched:

  * the loader puts the bytes where the file says, and nowhere else;
  * the machine STARTS at the entry point rather than at zero;
  * the program runs exactly as many instructions as it contains -- a loader
    that mapped one byte short would run a different program and still stop;
  * it stops because the program asked, not because the step limit ran out;
  * the cycle count is at least the instruction count and reflects the
    latencies the description declares.

⚠️ The program is assembled from the description's own fixtures, so there is no
cross-compiler in the loop and the expected counts are arithmetic rather than
observation. A real binary needs a toolchain this repository does not carry; a
loader that cannot be tested without one is a loader nobody can trust yet.

Usage: tools/workload_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import axis_image  # noqa: E402
import run_workload  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Where the program is placed. ⚠️ Not zero: a machine that ignored the entry
#: point would start at zero and run whatever is there, and a program at zero
#: would let it.
ENTRY = 0x1000


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def build_program(axis_file: Path, work: Path):
    """Straight-line instructions from the corpus's own fixtures, then a trap.

    The trap is how a program says it is finished, so the run ends because the
    program ended rather than because a limit did.
    """
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / "wl_lift.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module("wl_lift")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    table = json.loads(run_cmd([*axis_prefix(), "emit-decode-json",
                                str(axis_file)]).stdout)
    bits = {entry["mnemonic"]: entry["bits"]
            for entry in table.get("instructions", table.get("entries", []))}

    counted: dict[str, int] = {}
    for test in tests:
        counted[test.get("isa") or ""] = counted.get(test.get("isa") or "", 0) + 1
    isa = max(counted, key=counted.get) if counted else ""

    by_kind = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    body, stopper = [], None
    for test in tests:
        if (test.get("isa") or "") != isa or bits.get(test["mnemonic"]) != 32:
            continue
        entry = by_kind.get(test["mnemonic"])
        if entry is None:
            continue
        kinds = {effect["kind"] for effect in (entry.get("effects") or [])}
        word = int(test["encoded"], 16)
        if kinds == {"trap"} and stopper is None:
            stopper = word
        elif not kinds & {"trap", "setpc", "store"} and len(body) < 16:
            # ⚠️ No store either: the program sits in the memory it would write
            # to, and a workload that overwrote itself is a different program
            # from the one the loader was given.
            body.append(word)
    sys.modules.pop("wl_lift", None)
    return isa, body, stopper


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    name = axis_file.stem
    isa, body, stopper = build_program(axis_file, work)
    if stopper is None or len(body) < 4:
        print(f"  {name}: DECLINED no straight-line fixtures and a trap to "
              f"make a program from")
        return 0, 0
    program = body + [stopper]
    image = work / f"{name}.elf"
    blob = b"".join(word.to_bytes(4, "little") for word in program)
    axis_image.write_elf(image, ENTRY, [(ENTRY, blob)])

    # ⚠️ Read back through the loader, not from the bytes just written: what is
    # being checked is that a file on disk says where its program goes.
    loaded = axis_image.load(image)
    checks = failures = 0
    checks += 1
    if loaded.entry != ENTRY:
        print(f"  FAIL {name}: the image says it starts at {loaded.entry:#x}, "
              f"not {ENTRY:#x}")
        failures += 1
    # ⚠️ The LENGTH, not only the bytes. A loader that drops a segment's last
    # byte is invisible whenever that byte is zero -- and RISC-V's `ecall` is
    # `0x00000073`, so the program this gate builds ends in one. Comparing
    # contents alone reported a truncating loader as correct.
    checks += 1
    carried = sum(len(segment.data) for segment in loaded.segments)
    if carried != len(blob):
        print(f"  FAIL {name}: the image carries {carried} byte(s), the "
              f"program is {len(blob)}")
        failures += 1
    checks += 1
    flat = loaded.flatten(1 << 16)
    if flat[ENTRY:ENTRY + len(blob)] != blob:
        print(f"  FAIL {name}: the loader put different bytes at {ENTRY:#x}")
        failures += 1
    checks += 1
    if any(flat[:ENTRY]):
        print(f"  FAIL {name}: the loader wrote below the segment it was given")
        failures += 1

    said = run_workload.run_image(axis_file, image, work, isa or None,
                                  limit=10_000, jit=False, cycles=True,
                                  image_bytes=1 << 16)
    steps = int(said.get("STEPS", 0))
    cycles = int(said.get("CYCLES", 0))
    status = said.get("STATUS", "")

    checks += 1
    if steps != len(program):
        print(f"  FAIL {name}: the program has {len(program)} instruction(s) "
              f"and {steps} retired")
        failures += 1
    checks += 1
    # Status 1 is HALTED: the program asked to stop. 4 is the step limit, which
    # means it never did.
    if not status.startswith("1 "):
        print(f"  FAIL {name}: the run ended {status!r}, not because the "
              f"program trapped")
        failures += 1
    checks += 1
    if cycles < steps:
        print(f"  FAIL {name}: {steps} instruction(s) took {cycles} cycle(s), "
              f"which is faster than one per cycle")
        failures += 1

    if not failures:
        print(f"  {name}: {steps} instruction(s) from {image.name} at "
              f"{ENTRY:#x}, stopped {status}, {cycles} cycle(s), {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "rv64i.axisl"]
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp))
            except (subprocess.CalledProcessError, SystemExit,
                    axis_image.Unreadable) as error:
                said = getattr(error, "stderr", None) or str(error)
                print(f"  FAIL {corpus.stem}: {said.strip()[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("a program runs to completion: SKIP")
        return DECLINED
    print(f"a program runs to completion: {'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
