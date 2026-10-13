#!/usr/bin/env python3
"""A machine made of terms agrees with the machine made of numbers. Gate.

The solver library hands out the terms an instruction MEANS. `libaxis_sym_*`
runs a machine out of them: registers holding terms, memory as an array, a pc
that can be a term, and the constraint that says when each way out of a branch
is taken. This is the compiled-language twin of the Python symbolic machine,
and it is held the same way that one is.

⚠️ The check is not "the terms look right". It is: run the machine symbolically
from free variables, then BIND those variables to concrete numbers, ask the
solver to evaluate, and require every register to equal what the executor
computed from the same numbers. A symbolic engine that agrees with a concrete
run on every seed is one a consumer can reason with; one that merely produces
well-formed terms is not.

⚠️ And the branch. A guarded `setpc` must come back as TWO paths with
complementary constraints, because a conditional branch does not choose -- an
engine that returned only the taken way would be exploring a different program.
The gate requires both, and requires the one whose constraint the seeds satisfy
to be where the executor actually went.

Usage: tools/sym_pack_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402
import build_pack  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

HARNESS = r"""
/* A consumer with a machine of terms and a machine of numbers. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <z3.h>
#include "axis_pack.h"

extern const axis_sym_pack *%(sym)s(void);
extern const axis_z3_pack *%(z3)s(void);
extern const axis_exec_pack *%(exec)s(void);

#define SLOTS 64
static uint64_t REGS[SLOTS];
static uint64_t SEED[SLOTS];

static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; (void)a; (void)w; return 0u; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; (void)a; (void)v; (void)w; }

int main(void) {
  static const uint32_t WORDS[] = { %(words)s };
  const int32_t count = (int32_t)(sizeof WORDS / sizeof WORDS[0]);
  Z3_config cfg = Z3_mk_config();
  Z3_context ctx = Z3_mk_context(cfg);
  Z3_del_config(cfg);
  const axis_sym_pack *S = %(sym)s();
  const axis_z3_pack *Z = %(z3)s();
  const axis_exec_pack *X = %(exec)s();

  for (int32_t w = 0; w < count; ++w) {
    for (int32_t i = 0; i < SLOTS; ++i) { SEED[i] = 0x1111u * (uint64_t)(i + 1) + (uint64_t)w; }

    void *m = S->create(ctx, Z, SLOTS);
    if (!m) { printf("NOMACHINE\n"); return 1; }
    /* ⚠️ Memory the two machines can both answer for. The executor reaches it
       through a hook that returns zero; the symbolic machine starts with a
       FREE array, and a register holding `select(mem, addr)` evaluates to no
       numeral at all -- so the comparison below would skip it and every load
       would "agree" by not being looked at. Pinning the array to all zeros is
       what makes a load a question. */
    S->set_memory(m, Z3_mk_const_array(ctx, Z3_mk_bv_sort(ctx, 64),
                                       Z3_mk_unsigned_int64(ctx, 0u, Z3_mk_bv_sort(ctx, 8))));
    if (!S->step(m, WORDS[w], %(isa)s)) {
      printf("REFUSED %%d %%s\n", w, S->refusal(m) ? S->refusal(m) : "(no reason)");
      S->destroy(m);
      continue;
    }

    /* The same word, on numbers. */
    memcpy(REGS, SEED, sizeof REGS);
    axis_pack_mem mem = { rd, wr, NULL };
    axis_pack_exec_result pr;
    int32_t ran = X->step(WORDS[w], %(isa)s, REGS, SLOTS, &mem, 0u, NULL, 0, &pr);
    if (!ran || !pr.ok || pr.trapped) { printf("NOTRUN %%d\n", w); S->destroy(m); continue; }

    /* ⚠️ Bind, then evaluate. The registers were free variables; a model that
       says what each one is turns every term into the number the executor
       should have computed. */
    Z3_solver solver = Z3_mk_solver(ctx);
    Z3_solver_inc_ref(ctx, solver);
    for (int32_t i = 0; i < SLOTS; ++i) {
      Z3_ast var = (Z3_ast)S->reg(m, i);
      if (!var) { continue; }
      Z3_ast want = Z3_mk_unsigned_int64(ctx, SEED[i], Z3_mk_bv_sort(ctx, 64));
      /* The variable, not the term the step left behind: asking about `r3`
         after `r3` was written is asking about the free variable it began as. */
      char name[32]; snprintf(name, sizeof name, "r%%d", i);
      Z3_ast fresh = Z3_mk_const(ctx, Z3_mk_string_symbol(ctx, name), Z3_mk_bv_sort(ctx, 64));
      Z3_solver_assert(ctx, solver, Z3_mk_eq(ctx, fresh, want));
    }
    if (Z3_solver_check(ctx, solver) != Z3_L_TRUE) { printf("UNSAT %%d\n", w); S->destroy(m); continue; }
    Z3_model model = Z3_solver_get_model(ctx, solver);
    Z3_model_inc_ref(ctx, model);

    int bad = 0;
    for (int32_t i = 0; i < SLOTS && !bad; ++i) {
      Z3_ast term = (Z3_ast)S->reg(m, i);
      if (!term) { continue; }
      Z3_ast out = NULL;
      if (!Z3_model_eval(ctx, model, term, true, &out) || !out) { continue; }
      uint64_t got = 0;
      if (!Z3_get_numeral_uint64(ctx, out, (unsigned long long *)&got)) {
        /* ⚠️ A term that does not evaluate is not a register that agrees. */
        printf("OPEN %%d reg %%d\n", w, i);
        continue;
      }
      if (got != REGS[i]) {
        printf("DIFF %%d reg %%d: terms 0x%%llx, executor 0x%%llx\n", w, i,
               (unsigned long long)got, (unsigned long long)REGS[i]);
        bad = 1;
      }
    }
    if (!bad) { printf("AGREE %%d paths %%d\n", w, S->paths(m)); }
    Z3_model_dec_ref(ctx, model);
    Z3_solver_dec_ref(ctx, solver);
    S->destroy(m);
  }
  /* ---- a consumer's shape: several instructions, then a fork ---------- */
  {
    static const uint32_t RUN[] = { %(run)s };
    const int32_t steps = (int32_t)(sizeof RUN / sizeof RUN[0]);
    for (int32_t i = 0; i < SLOTS; ++i) { SEED[i] = 0x2222u * (uint64_t)(i + 1) + 7u; }

    void *m = S->create(ctx, Z, SLOTS);
    S->set_memory(m, Z3_mk_const_array(ctx, Z3_mk_bv_sort(ctx, 64),
                                       Z3_mk_unsigned_int64(ctx, 0u, Z3_mk_bv_sort(ctx, 8))));
    memcpy(REGS, SEED, sizeof REGS);
    axis_pack_mem mem = { rd, wr, NULL };
    int32_t ran = 0;
    uint64_t at = 0;
    for (int32_t i = 0; i < steps; ++i) {
      /* ⚠️ Skipped in BOTH engines or in neither. A word the symbolic machine
         refuses is one this phase has nothing to say about; running it on the
         executor alone would leave the two comparing different programs. */
      if (!S->step(m, RUN[i], %(isa)s)) { continue; }
      axis_pack_exec_result pr;
      if (!X->step(RUN[i], %(isa)s, REGS, SLOTS, &mem, at, NULL, 0, &pr)
          || !pr.ok || pr.trapped) {
        printf("RUNONESIDED %%d\n", i);
        break;
      }
      at += 4u;
      ran++;
    }
    printf("RAN %%d of %%d\n", ran, steps);

    /* ⚠️ The pc has to have moved. A machine whose registers agree and whose
       pc stands still is one that ran every instruction at the same address. */
    Z3_ast where = (Z3_ast)S->pc(m);
    Z3_solver solver = Z3_mk_solver(ctx);
    Z3_solver_inc_ref(ctx, solver);
    for (int32_t i = 0; i < SLOTS; ++i) {
      char name[32]; snprintf(name, sizeof name, "r%%d", i);
      Z3_ast fresh = Z3_mk_const(ctx, Z3_mk_string_symbol(ctx, name), Z3_mk_bv_sort(ctx, 64));
      Z3_solver_assert(ctx, solver, Z3_mk_eq(ctx, fresh,
          Z3_mk_unsigned_int64(ctx, SEED[i], Z3_mk_bv_sort(ctx, 64))));
    }
    if (Z3_solver_check(ctx, solver) == Z3_L_TRUE) {
      Z3_model model = Z3_solver_get_model(ctx, solver);
      Z3_model_inc_ref(ctx, model);
      int bad = 0;
      for (int32_t i = 0; i < SLOTS && !bad; ++i) {
        Z3_ast term = (Z3_ast)S->reg(m, i), out = NULL;
        if (!term || !Z3_model_eval(ctx, model, term, true, &out) || !out) { continue; }
        uint64_t got = 0;
        if (!Z3_get_numeral_uint64(ctx, out, (unsigned long long *)&got)) {
          printf("RUNOPEN reg %%d\n", i); bad = 1; continue;
        }
        if (got != REGS[i]) {
          printf("RUNDIFF reg %%d: terms 0x%%llx, executor 0x%%llx\n", i,
                 (unsigned long long)got, (unsigned long long)REGS[i]);
          bad = 1;
        }
      }
      Z3_ast pc_out = NULL;
      uint64_t pc_got = 0;
      if (where && Z3_model_eval(ctx, model, where, true, &pc_out) && pc_out
          && Z3_get_numeral_uint64(ctx, pc_out, (unsigned long long *)&pc_got)) {
        printf("RUNPC %%llu\n", (unsigned long long)pc_got);
      } else {
        printf("RUNPC open\n");
      }
      Z3_model_dec_ref(ctx, model);
    }
    Z3_solver_dec_ref(ctx, solver);

    /* ⚠️ A fork is a copy. Two ways out of a branch write different registers,
       and a consumer that explored one by mutating the shared machine would
       report the second path's state for the first. */
    void *other = S->clone(m);
    if (!other) { printf("NOCLONE\n"); }
    else {
      S->set_reg(other, 1, Z3_mk_unsigned_int64(ctx, 0xABCDu, Z3_mk_bv_sort(ctx, 64)));
      Z3_ast mine = (Z3_ast)S->reg(m, 1), theirs = (Z3_ast)S->reg(other, 1);
      printf("CLONE %%d\n", mine != theirs);
      /* And what a consumer assumes to get somewhere is kept, in order. */
      S->assume(other, Z3_mk_true(ctx));
      printf("ASSUMED %%d %%d\n", S->constraints(other), S->constraints(m));
      S->destroy(other);
    }
    S->destroy(m);
  }

  Z3_del_context(ctx);
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def check(axis_file: Path, work: Path, rng: random.Random) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs",
                                only={"sym", "z3", "exec", "lift"})
    name = manifest["name"]
    for library in ("sym", "z3", "exec"):
        if library not in manifest["libraries"]:
            print(f"  {name}: DECLINED no {library} library "
                  f"({manifest.get('declined', {}).get(library, 'not built')})")
            return 0, 0
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                            str(axis_file)]).stdout)["tests"]
    counted: dict[str, int] = {}
    for test in tests:
        counted[test.get("isa") or ""] = counted.get(test.get("isa") or "", 0) + 1
    isa = max(counted, key=counted.get) if counted else ""
    chosen = [test for test in tests if (test.get("isa") or "") == isa][:60]
    words = [int(test["encoded"], 16) for test in chosen]
    named = [test["mnemonic"] for test in chosen]
    if not words:
        print(f"  {name}: DECLINED no fixture in {isa!r}")
        return 0, 0

    # ⚠️ One width, because the harness advances the pc by four. A compressed
    # instruction is two bytes, and mixing them would make the executor's pc
    # and the symbolic machine's disagree about a program neither got wrong.
    table = json.loads(run_cmd([*axis_prefix(), "emit-decode-json",
                                str(axis_file)]).stdout)
    bits = {entry["mnemonic"]: entry["bits"]
            for entry in table.get("instructions", table.get("entries", []))}
    # ⚠️ And a BASIC BLOCK: nothing that redirects the pc. The executor is told
    # which address it is at, and after a `jal` the machine is somewhere the
    # harness did not compute -- so a run with a branch in it compares two
    # engines that are executing different addresses, which reads as the
    # symbolic machine getting `jalr`'s link value wrong. Forks are the phase
    # after this one.
    lift = json.loads(run_cmd([*axis_prefix(), "emit-lift-json",
                               str(axis_file)]).stdout)
    straight = {entry["mnemonic"] for entry in lift["instructions"]
                if not any(effect["kind"] in ("setpc", "trap")
                           for effect in (entry.get("effects") or []))}
    run = [int(test["encoded"], 16) for test in chosen
           if bits.get(test["mnemonic"]) == 32
           and test["mnemonic"] in straight][:8]
    solver = build_pack.solver_paths()
    headers, libraries_at = solver
    source = HARNESS % {
        "sym": manifest["libraries"]["sym"]["entry"],
        "z3": manifest["libraries"]["z3"]["entry"],
        "exec": manifest["libraries"]["exec"]["entry"],
        "words": ", ".join(f"{word}u" for word in words),
        # ⚠️ A run, not a set of singles. Registers feeding the next
        # instruction, the pc advancing, memory carried across -- none of
        # which a one-instruction comparison touches, and all of which a
        # consumer does on its first use.
        "run": ", ".join(f"{word}u" for word in run),
        "isa": f'"{isa}"' if isa else "NULL",
    }
    root = work / "packs" / name
    (work / f"{name}.c").write_text(source)
    run_cmd(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-I", str(headers),
         "-o", str(work / name), str(work / f"{name}.c"),
         *(str(root / "lib" / manifest["libraries"][f]["static"])
           for f in ("sym", "z3", "exec")),
         f"-L{libraries_at}", "-lz3"])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}: "
              f"{done.stderr.strip()[:200]}")
        return 0, 1

    agreed = refused = failures = 0
    branches = 0
    opened: list[str] = []
    stepped = 0
    for line in done.stdout.splitlines():
        if line.startswith("DIFF "):
            which = int(line.split()[1])
            print(f"  FAIL {name}: {named[which]} -- {line}")
            failures += 1
        elif line.startswith("AGREE "):
            agreed += 1
            if line.split()[-1] == "2":
                branches += 1
        elif line.startswith(("REFUSED", "NOTRUN", "UNSAT")):
            refused += 1
            if line.startswith("REFUSED") and refused <= 3:
                which = int(line.split()[1])
                print(f"  {name}: {named[which]} refused -- "
                      f"{line.split(maxsplit=2)[2]}")
        elif line.startswith("OPEN "):
            opened.append(line.split()[1])
        elif line.startswith(("RUNDIFF", "RUNOPEN")):
            spelled = [test["mnemonic"] for test in chosen
                       if int(test["encoded"], 16) in run]
            print(f"  FAIL {name}: over a run of instructions -- {line}")
            print(f"         the run was: {', '.join(spelled[:8])}")
            failures += 1
        elif line.startswith("RAN "):
            ran, of = int(line.split()[1]), int(line.split()[3])
            # ⚠️ A run of one proves nothing a single step did not. What this
            # phase is for is a register feeding the next instruction and a pc
            # that moves, and neither happens in one step.
            if ran < 2:
                print(f"  FAIL {name}: the run stopped after {ran} of {of} "
                      f"instruction(s), so nothing carried between two")
                failures += 1
            else:
                stepped = ran
        elif line.startswith("RUNONESIDED "):
            print(f"  FAIL {name}: the symbolic machine ran instruction "
                  f"{line.split()[1]} of the run and the executor would not")
            failures += 1
        elif line.startswith("RUNPC "):
            where = line.split()[1]
            if where == "open" or int(where) == 0:
                print(f"  FAIL {name}: the pc is {where} after the run -- a "
                      f"machine that agrees about registers and stands still "
                      f"ran every instruction at one address")
                failures += 1
        elif line.startswith("NOCLONE"):
            print(f"  FAIL {name}: the library would not clone a machine")
            failures += 1
        elif line.startswith("CLONE "):
            if line.split()[1] != "1":
                print(f"  FAIL {name}: writing a clone's register changed the "
                      f"machine it was cloned from")
                failures += 1
        elif line.startswith("ASSUMED "):
            theirs, mine = (int(x) for x in line.split()[1:])
            if theirs != 1 or mine != 0:
                print(f"  FAIL {name}: an assumption on one machine is held by "
                      f"{theirs} and {mine} -- it belongs to one of them")
                failures += 1
        elif line.startswith("NOMACHINE"):
            print(f"  FAIL {name}: the library would not make a machine")
            failures += 1

    # ⚠️ A run where nothing agreed proves nothing: every word refused is a
    # gate reporting that it asked no questions.
    if not agreed:
        print(f"  FAIL {name}: no instruction was compared -- {refused} refused")
        failures += 1
    elif opened:
        print(f"  FAIL {name}: {len(opened)} register(s) held a term that does "
              f"not evaluate -- nothing was compared for "
              f"{', '.join(named[int(w)] for w in opened[:4])}")
        failures += 1
    elif not failures:
        print(f"  {name}: {agreed} instruction(s) agreed with the executor "
              f"({branches} with two paths), {refused} refused; a run of "
              f"{stepped} agreed throughout")
    return agreed, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "rv64i.axisl"]
    if build_pack.solver_paths() is None:
        print("no solver on this host: SKIP")
        return DECLINED
    rng = random.Random(args.seed)
    checks = failures = 0
    for corpus in corpora:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                did, bad = check(corpus, Path(tmp), rng)
            except subprocess.CalledProcessError as error:
                said = (error.stderr or error.stdout or str(error)).strip()
                print(f"  FAIL {corpus.stem}: {said[:400]}")
                did, bad = 0, 1
            checks += did
            failures += bad
    if not checks and not failures:
        print("terms == executor: SKIP")
        return DECLINED
    print(f"terms == executor: {'FAIL' if failures else 'PASS'} "
          f"({checks} compared, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
