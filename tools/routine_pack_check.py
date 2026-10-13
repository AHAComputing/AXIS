#!/usr/bin/env python3
"""A host supplies what the description would not describe. Gate.

Some instructions have no semantics to generate. Pointer authentication signs
with a key the description does not hold; a cipher round is a table nobody
wants transcribed into a machine description; a random number is not a
function. AXIS names a routine for these and stops there, and the generated
executor calls a symbol an embedder defines.

⚠️ That answer runs out the moment the artifact is a LIBRARY. A pack is built,
shipped, and then loaded by a program that cannot relink it -- so "define the
symbol" is advice the consumer cannot take. `register_routine` is the answer
for that case, and this gate is the claim that it works: that a pack names the
routines it lacks, that binding one reaches the placeholder inside the
library, that the routine sees the same operands the lifter reports, that what
it does to registers, memory, state and the pc comes back through the
contract, and that everything NOT bound still traps exactly as before.

The harness includes `axis_pack.h` and nothing else. A host that loads a pack
has that header and a `dlsym`, and a gate that reached for the generated
executor's types would be proving something no consumer can use.

Usage: tools/routine_pack_check.py [corpus.axisl ...]
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
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Where the one instruction sits, and the cell the routine is asked to write.
CODE = 0x200
CELL = 0x800

HARNESS = r"""
/* A host that has a pack and nothing else. */
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_exec_pack *%(exec)s(void);
extern const axis_sim_pack *%(sim)s(void);

#define SLOTS 256
#define IMAGE (1 << 16)

static uint64_t REGS[SLOTS];
static unsigned char MEMORY[IMAGE];

static uint64_t host_read(void *ctx, uint64_t addr, uint32_t width) {
  (void)ctx; uint64_t value = 0; uint32_t bytes = (width + 7u) / 8u;
  for (uint32_t i = 0; i < bytes && addr + i < IMAGE; ++i) {
    value |= (uint64_t)MEMORY[addr + i] << (8 * i);
  }
  return value;
}
static void host_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {
  (void)ctx; uint32_t bytes = (width + 7u) / 8u;
  for (uint32_t i = 0; i < bytes && addr + i < IMAGE; ++i) {
    MEMORY[addr + i] = (unsigned char)(value >> (8 * i));
  }
}

/* What the routine SAW, so the gate can say whether it was told the truth. */
static int32_t seen_calls;
static int32_t seen_index;
static int32_t seen_operands;
static uint32_t seen_operand[AXIS_PACK_MAX_OPERANDS];
static uint64_t seen_pc;
static uint64_t seen_reg;
static int32_t seen_state_count;
static uint64_t seen_state0;
static uint64_t seen_memory;
static int32_t seen_has_mem;

#define WROTE_SLOT 7u
#define MARK 0x5ea1ed0000ull

static void routine(const axis_pack_lifted *lifted, uint64_t *regs, int32_t reg_count,
                    const axis_pack_mem *mem, uint64_t pc,
                    axis_pack_state_entry *state, int32_t state_count,
                    axis_pack_exec_result *out) {
  ++seen_calls;
  seen_index = lifted ? lifted->index : -2;
  seen_operands = lifted ? lifted->operand_count : -1;
  for (int32_t i = 0; lifted && i < lifted->operand_count && i < AXIS_PACK_MAX_OPERANDS; ++i) {
    seen_operand[i] = lifted->operands[i];
  }
  seen_pc = pc;
  seen_reg = (reg_count > 1) ? regs[1] : 0u;
  seen_state_count = state_count;
  seen_state0 = state_count > 0 ? state[0].value : 0u;
  seen_has_mem = mem && mem->read && mem->write ? 1 : 0;
  if (seen_has_mem) {
    seen_memory = mem->read(mem->ctx, %(cell)du, 32u);
    mem->write(mem->ctx, %(cell)du, seen_memory + 1u, 32u);
  }
  /* What a routine is FOR: a value only it can compute, reported the way a
     generated effect reports one. */
  if (reg_count > (int32_t)WROTE_SLOT) { regs[WROTE_SLOT] = MARK | (pc & 0xffffu); }
  if (state_count > 0) { state[0].value = state[0].value ^ 0xfull; }
  out->result = MARK | (pc & 0xffffu);
  out->wrote = 1; out->dest = WROTE_SLOT; out->dest_slot = WROTE_SLOT;
  out->next_pc = pc + 0x40u;
  out->ok = 1;
}

/* A second one, for the simulator's registry, so a bind on one library
   cannot be mistaken for a bind on the other. */
static int32_t sim_calls;
static void sim_routine(const axis_pack_lifted *lifted, uint64_t *regs, int32_t reg_count,
                        const axis_pack_mem *mem, uint64_t pc,
                        axis_pack_state_entry *state, int32_t state_count,
                        axis_pack_exec_result *out) {
  (void)lifted; (void)mem; (void)state; (void)state_count;
  ++sim_calls;
  if (reg_count > (int32_t)WROTE_SLOT) { regs[WROTE_SLOT] = MARK; }
  out->wrote = 1; out->dest = WROTE_SLOT; out->dest_slot = WROTE_SLOT;
  out->result = MARK; out->next_pc = pc + 4u; out->ok = 1;
}

static uint64_t sim_read(void *ctx, uint64_t addr, uint32_t width) { return host_read(ctx, addr, width); }
static void sim_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) { host_write(ctx, addr, value, width); }
static uint32_t sim_fetch(void *ctx, uint64_t pc, int32_t *ok) {
  (void)ctx; *ok = pc + 4 <= IMAGE; return *ok ? (uint32_t)host_read(NULL, pc, 32u) : 0u;
}
static uint64_t sim_trap(void *ctx, const char *cause, uint64_t pc, int32_t *stop) {
  (void)ctx; (void)cause; *stop = 1; return pc;
}

static int32_t step(const axis_exec_pack *E, uint32_t word,
                    axis_pack_state_entry *state, int32_t state_count,
                    axis_pack_exec_result *out) {
  axis_pack_mem mem = { host_read, host_write, NULL };
  return E->step(word, %(isa)s, REGS, SLOTS, &mem, %(code)du, state, state_count, out);
}

int main(void) {
  const axis_exec_pack *E = %(exec)s();
  const axis_sim_pack *S = %(sim)s();
  if (!E->register_routine) { printf("NOREGISTER exec\n"); return 0; }

  printf("COUNT %%d\n", E->routine_count());
  for (int32_t i = 0; i < E->routine_count(); ++i) {
    const char *name = E->routine_name(i);
    const char *mnemonic = E->routine_mnemonic(i);
    printf("ROUTINE %%s %%s\n", name ? name : "(null)", mnemonic ? mnemonic : "(null)");
  }

  int32_t state_count = E->state_slots();
  if (state_count > 16) { state_count = 16; }
  axis_pack_state_entry state[16];
  for (int32_t i = 0; i < state_count; ++i) {
    state[i].name = E->state_name(i); state[i].width = E->state_width(i);
    state[i].value = 0x30u + (uint64_t)i;
  }
  for (int32_t i = 0; i < SLOTS; ++i) { REGS[i] = 0x1000u + (uint64_t)i; }
  host_write(NULL, %(cell)du, 0x11u, 32u);

  /* 1. Before anything is bound: the same trap an undescribed instruction
        reports, and nothing touched. */
  axis_pack_exec_result out;
  uint64_t before = REGS[WROTE_SLOT];
  step(E, %(word)uu, state, state_count, &out);
  printf("UNBOUND trapped=%%d cause=%%s wrote=%%d reg_changed=%%d calls=%%d\n",
         out.trapped, out.trap_cause ? out.trap_cause : "(null)", out.wrote,
         REGS[WROTE_SLOT] != before, seen_calls);

  /* 2. Bound. */
  int32_t bound = E->register_routine("%(routine)s", routine);
  int32_t unknown = E->register_routine("axis_impl_no_such_routine", routine);
  printf("BOUND %%d UNKNOWN %%d\n", bound, unknown);

  memset(&out, 0, sizeof out);
  before = REGS[WROTE_SLOT];
  int32_t took = step(E, %(word)uu, state, state_count, &out);
  printf("BOUNDSTEP took=%%d trapped=%%d ok=%%d wrote=%%d dest=%%u result=0x%%llx "
         "next_pc=0x%%llx reg=0x%%llx changed=%%d calls=%%d\n",
         took, out.trapped, out.ok, out.wrote, out.dest,
         (unsigned long long)out.result, (unsigned long long)out.next_pc,
         (unsigned long long)REGS[WROTE_SLOT], REGS[WROTE_SLOT] != before, seen_calls);
  printf("SAW index=%%d operands=%%d pc=0x%%llx reg1=0x%%llx state_count=%%d "
         "state0=0x%%llx mem=%%d read=0x%%llx wrote=0x%%llx state_now=0x%%llx\n",
         seen_index, seen_operands, (unsigned long long)seen_pc,
         (unsigned long long)seen_reg, seen_state_count,
         (unsigned long long)seen_state0, seen_has_mem,
         (unsigned long long)seen_memory,
         (unsigned long long)host_read(NULL, %(cell)du, 32u),
         (unsigned long long)(state_count > 0 ? state[0].value : 0u));
  for (int32_t i = 0; i < seen_operands && i < AXIS_PACK_MAX_OPERANDS; ++i) {
    printf("OPERAND %%d %%u\n", i, seen_operand[i]);
  }

  /* 3. Another routine, never bound, still traps. */
  %(other)s

  /* 4. Unbound again: the trap comes back. */
  int32_t cleared = E->register_routine("%(routine)s", NULL);
  memset(&out, 0, sizeof out);
  int32_t was_cleared = seen_calls;
  step(E, %(word)uu, state, state_count, &out);
  printf("CLEARED %%d trapped=%%d cause=%%s calls_added=%%d\n", cleared, out.trapped,
         out.trap_cause ? out.trap_cause : "(null)", seen_calls - was_cleared);

  /* 5. The simulator's own registry. Separate library, separate table: the
        exec pack's binding was just cleared and this must still work. */
  if (!S->register_routine) { printf("NOREGISTER sim\n"); return 0; }
  int32_t sbound = S->register_routine("%(routine)s", sim_routine);
  printf("SIMBOUND %%d count=%%d\n", sbound, S->routine_count());
  host_write(NULL, %(code)du, %(word)uu, 32u);
  axis_pack_sim_hooks hooks = { sim_read, sim_write, sim_fetch, sim_trap, NULL, NULL };
  void *machine = S->create(&hooks);
  if (!machine) { printf("NOMACHINE\n"); return 0; }
  S->reset(machine, %(code)du, %(isa)s, state, state_count);
  int32_t ran = S->step(machine);
  printf("SIMSTEP ran=%%d status=%%d reason=%%s calls=%%d reg=0x%%llx\n", ran,
         S->status(machine), S->halt_reason(machine) ? S->halt_reason(machine) : "(null)",
         sim_calls, (unsigned long long)S->reg(machine, WROTE_SLOT));
  S->destroy(machine);
  return 0;
}
"""

OTHER = r"""memset(&out, 0, sizeof out);
  int32_t was_other = seen_calls;
  step(E, %(word)uu, state, state_count, &out);
  printf("OTHER trapped=%%d cause=%%s calls_added=%%d\n", out.trapped,
         out.trap_cause ? out.trap_cause : "(null)", seen_calls - was_other);"""


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def candidates(lift, tests):
    """Instructions that name a routine and that a fixture gives a word for."""
    encoded: dict[str, int] = {}
    for test in tests:
        encoded.setdefault(test["mnemonic"], int(test["encoded"], 16))
    found = []
    for index, entry in enumerate(lift.AXIS_LIFT_TABLE):
        routine = entry.get("implementation")
        if not routine or entry["mnemonic"] not in encoded:
            continue
        found.append((index, entry, routine, encoded[entry["mnemonic"]]))
    return found


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs")
    name = manifest["name"]
    for library in ("exec", "sim"):
        if library not in manifest["libraries"]:
            print(f"  {name}: no {library} library")
            return 0, 1
    sys.path.insert(0, str(work))
    run([*axis_prefix(), "emit-lift-python", str(axis_file),
         "-o", str(work / "axis_lift.py")])
    lift = importlib.import_module("axis_lift")
    tests = json.loads(run([*axis_prefix(), "emit-roundtrip-json",
                            str(axis_file)]).stdout)["tests"]
    found = candidates(lift, tests)
    if not found:
        named = sum(1 for entry in lift.AXIS_LIFT_TABLE
                    if entry.get("implementation"))
        # ⚠️ Two different reasons, said apart. "This architecture describes
        # everything it has" is a corpus with nothing to say; "it names eight
        # routines and no fixture reaches one" is a hole in the fixtures, and
        # a gate that printed the same line for both would hide the second.
        print(f"  {name}: DECLINED " + ("the description names no routine it "
              "does not describe" if not named else
              f"{named} routine(s) named and no fixture reaches one"))
        return 0, 0

    index, entry, routine, word = found[0]
    # A second routine with a DIFFERENT name, so "bound one" can be told apart
    # from "bound them all".
    other = next(((i, e, r, w) for i, e, r, w in found if r != routine), None)
    others = OTHER % {"word": other[3]} if other else 'printf("NOOTHER\\n");'
    expected = [e.get("implementation") for e in lift.AXIS_LIFT_TABLE
                if e.get("implementation")]
    covers = sum(1 for r in expected if r == routine)

    source = HARNESS % {
        "exec": manifest["libraries"]["exec"]["entry"],
        "sim": manifest["libraries"]["sim"]["entry"],
        "isa": f'"{entry["isa"]}"' if entry.get("isa") else "NULL",
        "code": CODE, "cell": CELL, "word": word, "routine": routine,
        "other": others,
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run(["cc", "-std=c11", "-O1", "-I", str(root / "include"),
         "-o", str(work / name), str(work / f"{name}.c"),
         str(root / "lib" / manifest["libraries"]["exec"]["static"]),
         str(root / "lib" / manifest["libraries"]["sim"]["static"])])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode < 0:
        print(f"  FAIL {name}: the harness died on signal {-done.returncode}")
        return 0, 1

    fields: dict[str, dict[str, str]] = {}
    lines: dict[str, str] = {}
    listed: list[tuple[str, str]] = []
    operands: dict[int, int] = {}
    for line in done.stdout.splitlines():
        head, _, rest = line.partition(" ")
        if head == "ROUTINE":
            listed.append(tuple(rest.split()))
            continue
        if head == "OPERAND":
            slot, value = rest.split()
            operands[int(slot)] = int(value)
            continue
        lines[head] = rest
        fields[head] = dict(part.split("=", 1) for part in rest.split()
                            if "=" in part)

    checks = failures = 0

    def want(tag: str, key: str, value, why: str):
        nonlocal checks, failures
        checks += 1
        have = fields.get(tag, {}).get(key)
        if have is None:
            print(f"  FAIL {name}: the harness never said {tag}.{key}")
            failures += 1
        elif str(have) != str(value):
            print(f"  FAIL {name}: {why} -- {tag}.{key} is {have}, want {value}")
            failures += 1

    if "NOREGISTER" in lines:
        print(f"  FAIL {name}: the pack carries no register_routine")
        return 0, 1

    # The directory is the description's.
    checks += 1
    if lines.get("COUNT", "").strip() != str(len(expected)):
        print(f"  FAIL {name}: the pack names {lines.get('COUNT')} routine(s), "
              f"the description names {len(expected)}")
        failures += 1
    checks += 1
    named = sorted(n for n, _ in listed)
    if named != sorted(expected):
        print(f"  FAIL {name}: the pack's routine names are not the "
              f"description's ({named[:3]} vs {sorted(expected)[:3]})")
        failures += 1
    checks += 1
    mnemonics = {n: m for n, m in listed}
    if mnemonics.get(routine) != entry["mnemonic"] and covers == 1:
        print(f"  FAIL {name}: {routine} is reported for "
              f"{mnemonics.get(routine)}, the description gives it "
              f"{entry['mnemonic']}")
        failures += 1

    # Unbound is a trap and nothing else.
    want("UNBOUND", "trapped", 1, "an unbound routine did not trap")
    want("UNBOUND", "cause", "unimplemented", "the trap did not name its cause")
    want("UNBOUND", "wrote", 0, "an unbound routine reported a write")
    want("UNBOUND", "reg_changed", 0, "an unbound routine changed a register")
    want("UNBOUND", "calls", 0, "an unbound routine was called anyway")

    checks += 1
    bound, unknown = lines.get("BOUND", "0 UNKNOWN 0").split()[0::2]
    if bound != str(covers):
        print(f"  FAIL {name}: binding {routine} covered {bound} instruction(s), "
              f"the description gives it {covers}")
        failures += 1
    checks += 1
    if unknown != "0":
        print(f"  FAIL {name}: binding a name the pack does not have "
              f"reported {unknown}")
        failures += 1

    # Bound: the routine ran, and what it did came back.
    want("BOUNDSTEP", "took", 1, "the step did not report an instruction")
    want("BOUNDSTEP", "trapped", 0, "a bound routine still trapped")
    want("BOUNDSTEP", "ok", 1, "a bound routine was not reported as performed")
    want("BOUNDSTEP", "calls", 1, "the placeholder did not reach the routine")
    want("BOUNDSTEP", "wrote", 1, "the routine's write did not come back")
    want("BOUNDSTEP", "changed", 1, "the routine's register write did not land")
    mark = 0x5ea1ed0000 | (CODE & 0xffff)
    want("BOUNDSTEP", "result", f"0x{mark:x}", "the routine's result did not come back")
    want("BOUNDSTEP", "next_pc", f"0x{CODE + 0x40:x}",
         "the routine's next pc did not come back")
    want("BOUNDSTEP", "reg", f"0x{mark:x}", "the register holds something else")

    # And what the routine was told.
    want("SAW", "index", index, "the routine was told the wrong instruction")
    want("SAW", "operands", len(entry.get("operands") or []),
         "the routine was told the wrong number of operands")
    want("SAW", "pc", f"0x{CODE:x}", "the routine was told the wrong pc")
    want("SAW", "reg1", "0x1001", "the routine did not see the register file")
    want("SAW", "mem", 1, "the routine was given no memory")
    want("SAW", "read", "0x11", "the routine read the wrong memory")
    want("SAW", "wrote", "0x12", "the routine's memory write did not land")
    if lift.AXIS_LIFT_TABLE[index].get("operands"):
        decoded = lift.lift(word, entry.get("isa"))
        checks += 1
        if decoded is not None:
            values = [decoded["operands"][op["name"]]
                      for op in entry["operands"]
                      if op["name"] in decoded["operands"]]
            saw = [operands[i] for i in sorted(operands)][:len(values)]
            if values and saw != values:
                print(f"  FAIL {name}: the routine saw operands {saw}, the "
                      f"lifter decodes {values}")
                failures += 1
    state_slots = fields.get("SAW", {}).get("state_count")
    if state_slots and state_slots != "0":
        want("SAW", "state0", "0x30", "the routine was told the wrong state")
        want("SAW", "state_now", "0x3f",
             "the routine's state write did not come back")

    if "OTHER" in fields:
        want("OTHER", "trapped", 1, "an unbound routine did not trap")
        want("OTHER", "calls_added", 0,
             "binding one routine called it for another")

    want("CLEARED", "trapped", 1, "clearing a routine did not restore the trap")
    want("CLEARED", "calls_added", 0, "a cleared routine was called anyway")

    # The simulator's registry is its own.
    checks += 1
    if lines.get("SIMBOUND", "").split()[0] != str(covers):
        print(f"  FAIL {name}: the simulator bound "
              f"{lines.get('SIMBOUND', '').split()[:1]}, want {covers}")
        failures += 1
    if "SIMSTEP" in fields:
        want("SIMSTEP", "calls", 1,
             "the simulator's placeholder did not reach the routine")
        checks += 1
        if fields["SIMSTEP"].get("reason") == "unimplemented":
            print(f"  FAIL {name}: the simulator still halted unimplemented "
                  f"with a routine bound")
            failures += 1
    elif "NOMACHINE" not in lines:
        print(f"  FAIL {name}: the simulator never stepped")
        failures += 1

    if not failures:
        print(f"  {name}: {len(expected)} routine(s) named, {routine} bound and "
              f"reached, {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp))
            except subprocess.CalledProcessError as error:
                print(f"  FAIL {corpus.stem}: {error.stderr.strip()[:400]}")
                did, bad = 0, 1
            checks += did
            failures += bad
            for module in ("axis_lift",):
                sys.modules.pop(module, None)
            if str(Path(tmp)) in sys.path:
                sys.path.remove(str(Path(tmp)))
    # ⚠️ A failure is never a SKIP, and neither is a gate that asked nothing
    # because every harness died: `checks` counts questions the library
    # answered, so zero of them with no failure is a corpus that names no
    # routine and nothing else.
    if not checks and not failures:
        print("a host's routine reaches the library: SKIP")
        return DECLINED
    print(f"a host's routine reaches the library: "
          f"{'FAIL' if failures else 'PASS'} "
          f"({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
