#!/usr/bin/env python3
"""One description is one design point. A sweep is a curve, and it has a knee.

Every other gate here asks a question about one machine. This asks the question
a co-design study actually asks: hold the program fixed, vary the machine, and
see what the curve does. Until the simulator could charge a miss there was
nothing to plot -- fifty variants of a description all retired the same number
of instructions and reported the same number, which is a plotting exercise over
a constant.

⚠️ The stride is MEASURED, not assumed, and the cache's line is set to it.
The walk steps its immediate by one; how far that moves an address is the
description's business -- AArch64 scales the field by the access size and
RISC-V does not -- so the harness reads the first two addresses off the memory
interface and sizes the line to match. Assuming a 64-byte line put AArch64's
offsets eight lines apart, folded a 32-line working set onto four sets, and
reported a machine that missed everywhere at every cache size.

⚠️ The workload is a STRIDED WALK, built for this and not borrowed. The
programs the other gates assemble are straight-line fixtures: they touch no
memory to speak of, and sweeping a cache over one produces a flat line. A
sweep needs a working set, so this builds one -- W distinct lines, walked
twice, from the description's own load instruction -- and the size of that
working set is known by construction, which is what makes the curve checkable
rather than merely drawable.

What is checked, and none of it is eyeballing a plot:

  * **monotone**: a bigger cache never misses more. A curve that goes back up
    means the replacement policy or the indexing is wrong, and it is the first
    thing a sweep is able to see at all;
  * **the knee is the working set**: below W lines the second walk misses
    everything the first one did, so the program pays 2W; at W and above the
    second walk is free and it pays W. The transition is exact, not
    approximate, and it lands on the number the program was built around;
  * **the compulsory floor**: no cache, however large, misses fewer than W.
    A machine that reported fewer would be reporting hits for lines nothing had
    ever fetched;
  * **the curve is a TIME**, not a counter: cycles fall with misses by exactly
    the miss penalty, so the point that misses least is the point that runs
    fastest, and the sweep is an answer rather than a histogram.

⚠️ The cache is a DATA cache: instruction fetch does not go through it. A
unified cache would put the loop's own lines in competition with the array's
and move the knee somewhere that depends on where the program was linked, which
is a worse measurement and a much worse gate.

Usage: tools/sweep_check.py [corpus.axisl ...]
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
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

ENTRY = 0x1000
#: Where the walked array lives: line-aligned, clear of the program, and inside
#: the image. ⚠️ Line-aligned matters -- an array starting mid-line would make
#: the first and last lines partial and the knee land half a line out.
ARRAY = 0x4000
IMAGE_BYTES = 1 << 16
#: The working set, in lines. The knee goes here or the model is wrong.
WORKING_LINES = 32
#: Immediate units per line, and where in the line the second access lands.
#: ⚠️ TWO accesses per line, not one. A walk of one access per line tests only
#: whether a line is still there -- temporal locality -- and a cache that
#: made every address its own line passed that unchanged. The second access
#: is what tests a line as a UNIT OF TRANSFER: having fetched it for the
#: first byte, the rest of it is free. That is half of what a cache is for
#: and nothing here measured it.
#: ⚠️ And a stride of more than one unit, so that `addr / line_bytes` is
#: doing arithmetic. On RISC-V one unit is one byte, which made the division
#: by the line size an identity and the mutation that removed it invisible.
UNITS_PER_LINE = 8
MISS_CYCLES = 10
#: ⚠️ Straddling the working set on both sides. A grid that stopped at W would
#: show a fall and no floor, and one that started at W would show a floor and
#: no fall; neither is a knee.
GRID = (4, 8, 16, 32, 64, 128)

HARNESS = r"""
/* One program, one array, and a cache that changes size underneath it. */
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE %(image_bytes)d
static uint8_t MEMORY[IMAGE];
static const uint8_t PROGRAM[] = { %(program)s };

/* ⚠️ What the machine ACTUALLY addressed. The walk steps its immediate by
   one; how far that moves an address is the description's business, and
   AArch64 scales the field by the access size while RISC-V does not. Reading
   the answer off the memory interface beats assuming either. */
static uint64_t SEEN[4];
static uint32_t SEEN_COUNT;

/* ⚠️ Fetch reads through here, NOT through `rd`. The cache is a data cache,
   and letting the program's own lines compete with the array's would move the
   knee to wherever the program happened to be linked. */
static uint32_t rd_code(uint64_t a) {
  uint32_t v = 0;
  for (uint32_t i = 0; i < 4; ++i) v |= (uint32_t)MEMORY[(a + i) %% IMAGE] << (8 * i);
  return v;
}
static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c;
  if (SEEN_COUNT < 4) { SEEN[SEEN_COUNT++] = a; }
  uint64_t v = 0;
  for (uint32_t i = 0; i < w / 8; ++i) v |= (uint64_t)MEMORY[(a + i) %% IMAGE] << (8 * i);
  return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c;
  for (uint32_t i = 0; i < w / 8; ++i) MEMORY[(a + i) %% IMAGE] = (uint8_t)(v >> (8 * i));
}
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)rd_code(pc) : 0u;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

static const uint32_t SIZES[] = { %(grid)s };

static void *fresh(const axis_sim_pack *S, axis_pack_sim_hooks *hooks) {
  memset(MEMORY, 0, sizeof MEMORY);
  /* ⚠️ At the ENTRY, not at zero. The bytes come back out of the loader, so
     the image is still what says where they go -- but a memcpy to the front
     of memory puts them where the machine never looks, and the sweep reported
     six identical points of nothing having run. */
  memcpy(MEMORY + %(entry)d, PROGRAM, sizeof PROGRAM);
  void *m = S->create(hooks);
  if (!m) { return NULL; }
  S->reset(m, %(entry)dull, %(isa)s, NULL, 0);
  /* ⚠️ EVERY slot, so the base register holds the array whichever slot the
     description puts it in. The loads all read one register and write
     another, so what the rest hold never reaches an address. */
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, %(array)dull);
  }
  return m;
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->configure_cache) { printf("NOCACHE\n"); return 0; }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };

  /* The calibration run: no cache, just the first two addresses. */
  SEEN_COUNT = 0;
  void *m = fresh(S, &hooks);
  if (!m) { printf("NOMACHINE\n"); return 1; }
  S->run(m, %(limit)dull);
  S->destroy(m);
  if (SEEN_COUNT < 3) { printf("NOSTRIDE %%u\n", SEEN_COUNT); return 0; }
  /* ⚠️ The walk goes front-of-line, middle-of-line, next-line -- so the LINE
     stride is the first address to the third, and the first to the second is
     the half that has to land inside it. Taking the line stride from the
     first two would size every line at half its width and put the second
     access in a line of its own, which is the spatial hit this is here to
     see. */
  uint64_t first = SEEN[0];
  uint64_t half = SEEN[1] - SEEN[0];
  uint64_t stride = SEEN[2] - SEEN[0];
  printf("STRIDE %%llu half %%llu first %%llu\n", (unsigned long long)stride,
         (unsigned long long)half, (unsigned long long)first);
  if (!stride) { return 0; }

  for (uint32_t g = 0; g < sizeof SIZES / sizeof SIZES[0]; ++g) {
    SEEN_COUNT = 0;
    m = fresh(S, &hooks);
    if (!m) { printf("NOMACHINE\n"); return 1; }
    /* ⚠️ The line IS the stride, so the walk steps exactly one line at a
       time whatever the description's immediate means. Assuming a 64-byte
       line put AArch64's scaled offsets eight lines apart, which folded a
       32-line working set onto four sets and missed everywhere. */
    axis_sim_cache cache = { SIZES[g], 1u, (uint32_t)stride, %(penalty)du };
    S->configure_cache(m, &cache);
    S->count_cycles(m, 1);
    S->run(m, %(limit)dull);
    printf("POINT %%u lines %%llu hits %%llu misses %%llu cycles %%llu steps %%d status\n",
           SIZES[g], (unsigned long long)S->cache_hits(m),
           (unsigned long long)S->cache_misses(m),
           (unsigned long long)S->cycles(m),
           (unsigned long long)S->steps(m), S->status(m));
    S->destroy(m);
  }
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def ast_loads(node) -> bool:
    """Whether this value reads memory anywhere inside it."""
    if isinstance(node, dict):
        if node.get("op") == "load":
            return True
        return any(ast_loads(arg) for arg in node.get("args") or [])
    return False


def pick_strider(lift, tests):
    """A load that takes a base register and an immediate, and writes a third.

    ⚠️ Chosen by what its effect DOES, not by its mnemonic. A gate that looked
    for `LW` would work on two corpora and decline on the rest for no reason
    anyone could act on.
    """
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        effects = entry.get("effects") or []
        if len(effects) != 1 or effects[0]["kind"] != "set":
            continue
        if not ast_loads(effects[0].get("value_ast")):
            continue
        outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
        regs = [o for o in entry["operands"]
                if o["role"] == "in" and lift.is_register_operand(o["kind"])]
        imms = [o for o in entry["operands"]
                if o["role"] == "in" and o["kind"] == "imm"]
        if len(outs) != 1 or len(regs) != 1 or len(imms) != 1:
            continue
        if not lift.is_register_operand(outs[0]["kind"]):
            continue
        return test, entry, outs[0], regs[0], imms[0]
    return None, None, None, None, None


def pick_stopper(lift, tests):
    """How the program says it is finished."""
    by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
    for test in tests:
        entry = by_mnemonic.get(test["mnemonic"])
        if entry is None:
            continue
        kinds = {effect["kind"] for effect in (entry.get("effects") or [])}
        if kinds == {"trap"}:
            return int(test["encoded"], 16)
    return None


def build_walk(lift, test, entry, dest, base, imm, isa):
    """W lines walked twice, each load a line further along.

    ⚠️ Every word is decoded back before it is used. An immediate field too
    narrow to hold the offset would otherwise encode some other program
    perfectly quietly, and the sweep would measure a working set nobody chose.
    """
    rules = lift.REGISTER_CLASSES.get(base["kind"])
    zero = rules[0] if rules else None
    base_index = 1 if zero != 1 else 2
    dest_index = 3 if zero != 3 else 4
    word = int(test["encoded"], 16)
    walk = []
    for _ in range(2):
        for line in range(WORKING_LINES):
            # ⚠️ In UNITS of this immediate, not in bytes. What one unit moves
            # an address by is the description's business -- AArch64 scales
            # the field by the access size and RISC-V does not -- so the walk
            # counts in units and the harness measures what they came to.
            # Two per line: the front of it, then the middle.
            for offset in (line * UNITS_PER_LINE,
                           line * UNITS_PER_LINE + UNITS_PER_LINE // 2):
                built = lift.place_operand(word, entry, imm["name"], offset)
                built = lift.place_operand(built, entry, base["name"], base_index)
                built = lift.place_operand(built, entry, dest["name"], dest_index)
                back = lift.lift(built, isa or None)
                if back is None or back.get("mnemonic") != test["mnemonic"]:
                    return None, f"{test['mnemonic']} did not decode back"
                got = back["operands"]
                if got.get(imm["name"]) != offset:
                    return None, (f"{test['mnemonic']}'s immediate will not "
                                  f"hold {offset}: it reads back as "
                                  f"{got.get(imm['name'])}")
                if (got.get(base["name"]) != base_index
                        or got.get(dest["name"]) != dest_index):
                    return None, f"{test['mnemonic']}'s registers did not round-trip"
                walk.append(built)
    return walk, None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    name = axis_file.stem
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file),
             "-o", str(work / f"sw_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"sw_{name}")
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]

    counted: dict[str, int] = {}
    for test in tests:
        key = test.get("isa") or ""
        counted[key] = counted.get(key, 0) + 1
    isa = max(counted, key=counted.get) if counted else ""
    same_isa = [test for test in tests if (test.get("isa") or "") == isa]

    test, entry, dest, base, imm = pick_strider(lift, same_isa)
    if test is None:
        print(f"  {name}: DECLINED no load taking a base register and an "
              f"immediate to walk an array with")
        sys.modules.pop(f"sw_{name}", None)
        return 0, 0
    stopper = pick_stopper(lift, same_isa)
    if stopper is None:
        print(f"  {name}: DECLINED nothing that traps, so a program has no "
              f"way to say it is finished")
        sys.modules.pop(f"sw_{name}", None)
        return 0, 0
    walk, why = build_walk(lift, test, entry, dest, base, imm, isa)
    sys.modules.pop(f"sw_{name}", None)
    if walk is None:
        print(f"  {name}: DECLINED {why}")
        return 0, 0

    program = walk + [stopper]
    blob = b"".join(word.to_bytes(4, "little") for word in program)
    image = work / f"{name}.elf"
    axis_image.write_elf(image, ENTRY, [(ENTRY, blob)])
    flat = axis_image.load(image).flatten(IMAGE_BYTES)

    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "image_bytes": IMAGE_BYTES,
        "program": ", ".join(str(byte) for byte in flat[ENTRY:ENTRY + len(blob)]),
        "entry": ENTRY,
        "array": ARRAY,
        "isa": f'"{isa}"' if isa else "NULL",
        "grid": ", ".join(f"{size}u" for size in GRID),
        "penalty": MISS_CYCLES,
        "limit": len(program) + 4,
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
             "-o", str(work / name), str(work / f"{name}.c"),
             str(root / "lib" / manifest["libraries"]["sim"]["static"]),
             str(root / "lib" / manifest["libraries"]["exec"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}")
        return 0, 1
    if "NOCACHE" in done.stdout:
        print(f"  FAIL {name}: the simulator library models no cache")
        return 0, 1

    curve: dict[int, tuple[int, int, int, int, int]] = {}
    stride = half = first = None
    for line in done.stdout.splitlines():
        parts = line.split()
        if parts[:1] == ["NOSTRIDE"]:
            print(f"  FAIL {name}: the walk made {parts[1]} memory access(es); "
                  f"it is {2 * WORKING_LINES} loads")
            return 1, 1
        if len(parts) == 6 and parts[0] == "STRIDE":
            stride, half, first = int(parts[1]), int(parts[3]), int(parts[5])
        if len(parts) == 13 and parts[0] == "POINT":
            curve[int(parts[1])] = (int(parts[3]), int(parts[5]), int(parts[7]),
                                    int(parts[9]), int(parts[11]))

    checks = failures = 0

    # ⚠️ The measured stride, held to what a walk needs. A zero stride means
    # every load hit one address and the "working set" is one line; an array
    # not aligned to the stride puts the first and last lines half in, and the
    # knee lands somewhere no arithmetic predicts.
    checks += 1
    if not stride:
        print(f"  FAIL {name}: the walk's immediate moved no address")
        return checks, 1
    checks += 1
    if first != ARRAY:
        print(f"  FAIL {name}: the first load addressed {first:#x}, not the "
              f"array at {ARRAY:#x}")
        failures += 1
    # ⚠️ The second access has to land INSIDE the line, or the walk is two
    # accesses to two lines and the spatial hit it is built to see never
    # happens.
    checks += 1
    if half * 2 != stride:
        print(f"  FAIL {name}: the walk's half-line offset moved {half} "
              f"byte(s) and its line stride is {stride}; the second access is "
              f"not inside the first one's line")
        failures += 1
    checks += 1
    if ARRAY % stride:
        print(f"  {name}: DECLINED an array at {ARRAY:#x} is not aligned to "
              f"a stride of {stride}")
        return 0, 0

    checks += 1
    if sorted(curve) != sorted(GRID):
        print(f"  FAIL {name}: the sweep reported {sorted(curve)}, not "
              f"{list(GRID)}")
        return checks, 1

    # ⚠️ The program has to have RUN. A sweep over a machine that stopped at
    # its first instruction is six identical zeroes and a monotone curve.
    for size in GRID:
        hits, misses, cycles, steps, status = curve[size]
        checks += 1
        if steps != len(program):
            print(f"  FAIL {name}: at {size} lines the program ran {steps} "
                  f"instruction(s) of {len(program)}")
            failures += 1
            break
        checks += 1
        if hits + misses != 4 * WORKING_LINES:
            print(f"  FAIL {name}: at {size} lines the walk made {hits + misses} "
                  f"accesses; it loads {4 * WORKING_LINES} times")
            failures += 1
            break
    else:
        misses = [curve[size][1] for size in GRID]

        # A bigger cache never misses more.
        checks += 1
        if any(later > earlier for earlier, later in zip(misses, misses[1:])):
            print(f"  FAIL {name}: misses went back up across the sweep: "
                  f"{dict(zip(GRID, misses))}")
            failures += 1

        # The knee is the working set, exactly.
        checks += 1
        want = {size: (WORKING_LINES if size >= WORKING_LINES
                       else 2 * WORKING_LINES) for size in GRID}
        got = dict(zip(GRID, misses))
        if got != want:
            print(f"  FAIL {name}: the knee is not at {WORKING_LINES} lines. "
                  f"Walked {WORKING_LINES} lines twice and got {got}, "
                  f"expected {want}")
            failures += 1

        # Nothing beats the compulsory misses.
        checks += 1
        if min(misses) < WORKING_LINES:
            print(f"  FAIL {name}: {min(misses)} misses for a walk over "
                  f"{WORKING_LINES} distinct lines -- no cache can hit a line "
                  f"nothing fetched")
            failures += 1

        # ⚠️ A line is a UNIT OF TRANSFER. Even at the smallest cache, where
        # nothing survives from one walk to the next, the second access to
        # each line is free: the line was fetched for the first. Two walks
        # over W lines is 2W such accesses, and a cache that made every
        # address its own line would report none of them -- which is exactly
        # the mutation this gate could not see before the walk touched each
        # line twice.
        checks += 1
        spatial = curve[GRID[0]][0]
        if spatial != 2 * WORKING_LINES:
            print(f"  FAIL {name}: at {GRID[0]} lines the walk hit {spatial} "
                  f"time(s); nothing survives a walk at that size, so the "
                  f"{2 * WORKING_LINES} second-accesses-within-a-line are the "
                  f"only hits there are")
            failures += 1

        # ⚠️ And the curve is a TIME. Without this the sweep is a histogram:
        # it would rank the machines and never say the fastest one is faster.
        checks += 1
        small, large = curve[GRID[0]], curve[GRID[-1]]
        spread = (small[1] - large[1]) * MISS_CYCLES
        if small[2] - large[2] != spread:
            print(f"  FAIL {name}: {small[1] - large[1]} misses apart at "
                  f"{MISS_CYCLES} cycles each is {spread} cycles; the sweep "
                  f"reported {small[2] - large[2]}")
            failures += 1

    if not failures:
        shape = " ".join(f"{size}:{curve[size][1]}" for size in GRID)
        print(f"  {name}: {test['mnemonic']} strides {stride}B, walks "
              f"{WORKING_LINES} lines twice; "
              f"misses {shape}, knee at {WORKING_LINES}, "
              f"{curve[GRID[0]][2] - curve[GRID[-1]][2]} cycles apart, "
              f"{checks} checks")
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
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:300]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("the knee of the curve is the working set: SKIP")
        return DECLINED
    print(f"the knee of the curve is the working set: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
