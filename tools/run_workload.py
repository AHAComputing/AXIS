#!/usr/bin/env python3
"""Run a program to completion on the machine a description describes.

The libraries answer questions about instructions. This runs a PROGRAM: it
loads an image, starts at its entry point, and runs until the program stops
itself -- then reports how many instructions retired, how many cycles that
took, and how long it took to find out.

⚠️ This is the shape a co-design question actually has. "Is this extension
worth it" is not a question about one instruction; it is a question about a
workload, and until something could load and run one the stack could only
answer the first.

⚠️ A program stops by trapping -- `ecall` on RISC-V, `brk` on AArch64 -- and
the host decides that a trap ends the run. That is the whole of the ABI here:
no file descriptors, no heap, no arguments. A workload that needs those needs a
syscall layer, which is a decision about what the machine promises rather than
a missing feature of this.

Usage: tools/run_workload.py <input.axisl> <image.elf> [--isa NAME] [--limit N]
                             [--jit] [--cycles]
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402
import axis_image  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

HARNESS = r"""
/* A host with a program in it. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);
%(jit_extern)s

#define IMAGE %(image_bytes)d
static uint8_t MEMORY[IMAGE];
static const uint8_t PROGRAM[] = { %(program)s };
static int32_t STOPPED;
static const char *WHY;

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
  (void)c; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)rd(NULL, pc, 32u) : 0u;
}
/* ⚠️ A trap ENDS the run, and says which trap it was. That is the ABI: the
   program asks to stop and the host agrees. */
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; STOPPED = 1; WHY = cause; *stop = 1; return pc;
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  memcpy(MEMORY, PROGRAM, sizeof PROGRAM);
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return 1; }
  S->reset(m, %(entry)dull, %(isa)s, NULL, 0);
  %(cycles_on)s
  %(jit_on)s
  struct timespec started, ended;
  clock_gettime(CLOCK_MONOTONIC, &started);
  S->run(m, %(limit)dull);
  clock_gettime(CLOCK_MONOTONIC, &ended);
  double seconds = (double)(ended.tv_sec - started.tv_sec)
                 + (double)(ended.tv_nsec - started.tv_nsec) / 1e9;
  printf("STEPS %%llu\n", (unsigned long long)S->steps(m));
  printf("CYCLES %%llu\n", (unsigned long long)S->cycles(m));
  printf("PC %%llu\n", (unsigned long long)S->pc(m));
  printf("STATUS %%d %%s\n", S->status(m),
         S->halt_reason(m) ? S->halt_reason(m) : (WHY ? WHY : "(running)"));
  printf("SECONDS %%.6f\n", seconds);
  printf("TRANSLATED %%llu %%llu\n", (unsigned long long)S->translated(m),
         (unsigned long long)S->blocks_built(m));
  S->destroy(m);
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def run_image(axis_file: Path, image_path: Path, work: Path, isa: str | None,
              limit: int, jit: bool, cycles: bool, image_bytes: int) -> dict:
    image = axis_image.load(image_path)
    flat = image.flatten(image_bytes)
    wanted = {"sim", "exec", "lift"} | ({"jit"} if jit else set())
    manifest = build_pack.build(axis_file, work / "packs", only=wanted)
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        raise SystemExit(f"{name}: no simulator library")
    has_jit = jit and "jit" in manifest["libraries"]
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "jit_extern": (f'extern const axis_jit_pack *{manifest["libraries"]["jit"]["entry"]}(void);'
                       if has_jit else ""),
        "jit_on": (f'{{ axis_sim_jit options = {{ 1, 64, (uint64_t)(uintptr_t)MEMORY, IMAGE }};'
                   f' S->jit(m, {manifest["libraries"]["jit"]["entry"]}(), &options); }}'
                   if has_jit else ""),
        # ⚠️ Cycles and translation do not go together, and the runner says so
        # rather than reporting a figure that stopped advancing.
        "cycles_on": "S->count_cycles(m, 1);" if cycles and not has_jit else "",
        "image_bytes": image_bytes,
        "program": ", ".join(str(byte) for byte in flat),
        "entry": image.entry,
        "isa": f'"{isa}"' if isa else "NULL",
        "limit": limit,
    }
    root = work / "packs" / name
    (work / "run.c").write_text(source)
    libraries = [str(root / "lib" / manifest["libraries"][f]["static"])
                 for f in (("sim", "exec", "jit") if has_jit else ("sim", "exec"))]
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / "run"), str(work / "run.c"), *libraries])
    done = subprocess.run([str(work / "run")], capture_output=True, text=True)
    if done.returncode != 0:
        raise SystemExit(f"the workload harness exited {done.returncode}")
    said: dict[str, str] = {}
    for line in done.stdout.splitlines():
        head, _, rest = line.partition(" ")
        said[head] = rest
    said["_jit"] = "1" if has_jit else ""
    return said


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("image", type=Path)
    parser.add_argument("--isa")
    parser.add_argument("--limit", type=int, default=10_000_000)
    parser.add_argument("--jit", action="store_true")
    parser.add_argument("--cycles", action="store_true")
    parser.add_argument("--image-bytes", type=int, default=1 << 16)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        said = run_image(args.axis_file, args.image, Path(tmp), args.isa,
                         args.limit, args.jit, args.cycles, args.image_bytes)
    steps = int(said.get("STEPS", 0))
    cycles = int(said.get("CYCLES", 0))
    seconds = float(said.get("SECONDS", 0.0))
    status = said.get("STATUS", "")
    print(f"{args.image.name}: {steps} instruction(s) retired, stopped {status}")
    if cycles:
        print(f"  {cycles} cycle(s) by the description's own latencies "
              f"({cycles / steps:.2f} per instruction)" if steps else "")
    elif args.cycles:
        print("  no cycle count: the translator was enabled, and translated "
              "bytes call nothing")
    if said.get("_jit"):
        ran, blocks = said.get("TRANSLATED", "0 0").split()
        print(f"  {ran} instruction(s) ran as translated code across {blocks} block(s)")
    if seconds > 0 and steps:
        print(f"  {seconds * 1e3:.1f} ms, {steps / seconds / 1e6:.2f} MIPS")
    return PASSED


if __name__ == "__main__":
    raise SystemExit(main())
