#!/usr/bin/env python3
"""An instruction performed by a routine the embedder supplies actually runs it.

Some instructions have no semantics AXIS can state. What pointer authentication
computes depends on a key the machine holds and a construction nothing here
models; what a breakpoint does is a question about the exception level rather
than about the register file. Those instructions still decode and still
assemble -- `roundtrip_check` makes that a rule -- but a description that
invented arithmetic for them would be stating something untrue.

`(implementation <symbol>)` lets such an instruction name a routine instead. It
says *what to call*, not what is computed, and that distinction decides who may
use it: a consumer that RUNS code calls it, and a consumer that REASONS about
code must not. So this gate asks the one question that can be asked about an
opaque routine -- is it reached, with the operands the instruction decoded, and
does what it leaves behind survive into the machine? It cannot ask whether the
answer is right, because nothing here knows what right is. That is the honest
limit of the hook and the reason it is confined to executors.

The signature is exactly a generated effect function's, so the routine is
handed the same things: the decoded instruction, the register file, memory, the
pc, architectural state, and the result to report through.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

# The routine the embedder supplies. It does something arithmetic AXIS never
# stated -- a rotate mixed with the modifier -- precisely so that no generated
# path could have produced the same answer by accident.
PROBE = r'''
#include <stdio.h>
#include <string.h>
#include "axis_exec.h"

static int reached = 0;

void axis_impl_auth_step(const axis_lifted *lifted, uint64_t *regs,
                         size_t reg_count, const axis_mem64 *mem, uint64_t pc,
                         axis_state64 *state, axis_exec_result64 *r) {
  (void)mem; (void)pc;
  reached += 1;
  uint64_t value = axis_read_operand64(regs, reg_count,
                                       &lifted->entry->operands[1],
                                       lifted->operands[1], state);
  uint64_t modifier = axis_read_operand64(regs, reg_count,
                                          &lifted->entry->operands[2],
                                          lifted->operands[2], state);
  /* Nothing in the description says this. That is the point. */
  uint64_t signed_value = ((value << 13) | (value >> 51)) ^ (modifier * 31u);
  uint32_t dest = lifted->operands[0];
  if (axis_write_operand64(regs, reg_count, &lifted->entry->operands[0], dest,
                           signed_value, state)) {
    r->wrote = 1;
    r->dest = axis_operand_register(&lifted->entry->operands[0], dest);
    r->dest_slot = axis_operand_slot(&lifted->entry->operands[0], dest);
  }
  r->result = signed_value;
}

int main(void) {
  uint64_t regs[64];
  memset(regs, 0, sizeof regs);
  regs[1] = 0x0123456789abcdefULL;
  regs[2] = 0x5ULL;
  /* This instruction touches no memory; the callbacks exist so the signature
     is the one a generated effect function has. */
  axis_mem64 mem = { 0, 0, 0 };
  axis_state64 state; memset(&state, 0, sizeof state);

  /* The control first: an instruction whose semantics AXIS does state, so a
     harness that ran nothing is distinguishable from a routine never called.
     It is a pure value, so it goes through `eval64` rather than `apply64` --
     which is itself the distinction being tested, since an instruction with no
     semantics has no `eval64` case at all and must reach the routine through
     the effect path. */
  axis_lifted plain;
  if (!axis_lift(WORD_PLAIN, &plain)) { printf("FAIL decode plain\n"); return 1; }
  uint64_t inputs[2] = { regs[1], regs[2] };
  uint64_t plain_value = 0;
  if (!axis_exec_eval64(plain.entry->id, inputs, 2, &plain_value)) {
    printf("FAIL eval plain\n"); return 1;
  }
  if (plain_value != regs[1] + regs[2]) {
    printf("FAIL plain gave %llu, wanted %llu\n",
           (unsigned long long)plain_value,
           (unsigned long long)(regs[1] + regs[2]));
    return 1;
  }

  axis_lifted insn;
  if (!axis_lift(WORD_AUTH, &insn)) { printf("FAIL decode auth\n"); return 1; }
  axis_exec_result64 r; memset(&r, 0, sizeof r);
  if (!axis_exec_apply64(insn.entry->id, &insn, regs, 64, &mem, 0, &state, &r)) {
    printf("FAIL apply auth\n"); return 1;
  }
  if (reached != 1) { printf("FAIL routine reached %d time(s)\n", reached); return 1; }

  uint64_t value = 0x0123456789abcdefULL, modifier = 0x5ULL;
  uint64_t want = ((value << 13) | (value >> 51)) ^ (modifier * 31u);
  if (r.result != want) {
    printf("FAIL result %llu, wanted %llu\n",
           (unsigned long long)r.result, (unsigned long long)want);
    return 1;
  }
  if (!r.wrote) { printf("FAIL the write was not reported\n"); return 1; }
  if (regs[4] != want) {
    printf("FAIL register %llu, wanted %llu\n",
           (unsigned long long)regs[4], (unsigned long long)want);
    return 1;
  }
  /* The third answer: nobody performs this one, so meeting it is a trap and
     not a call. The cause is the artifact's, not the machine's. */
  axis_lifted missing;
  if (!axis_lift(WORD_UNSUPPLIED, &missing)) { printf("FAIL decode unsupplied\n"); return 1; }
  axis_exec_result64 m; memset(&m, 0, sizeof m);
  if (!axis_exec_apply64(missing.entry->id, &missing, regs, 64, &mem, 0, &state, &m)) {
    printf("FAIL apply unsupplied\n"); return 1;
  }
  if (!m.trapped) { printf("FAIL unsupplied did not trap\n"); return 1; }
  if (!m.trap_cause || strcmp(m.trap_cause, "unimplemented") != 0) {
    printf("FAIL trap cause %s\n", m.trap_cause ? m.trap_cause : "(none)");
    return 1;
  }
  if (reached != 1) { printf("FAIL a routine ran for an unsupplied instruction\n"); return 1; }

  printf("OK\n");
  return 0;
}
'''


def encode(axis_file: Path, mnemonic: str, values: dict) -> int:
    """One word, built by the description's own encoder."""
    work = Path(tempfile.mkdtemp(prefix="axis_impl_enc_"))
    subprocess.run([*axis_prefix(), "emit-lift-python", str(axis_file),
                    "-o", str(work / "axis_lift.py")],
                   check=True, capture_output=True, cwd=AXIS_ROOT)
    sys.path.insert(0, str(work))
    sys.path.insert(0, str(AXIS_ROOT / "tools"))
    import importlib
    axis_lift = importlib.import_module("axis_lift")
    importlib.reload(axis_lift)
    import exec_fuzz as ef
    entry = next(e for e in axis_lift.AXIS_LIFT_TABLE if e["mnemonic"] == mnemonic)
    return int(ef.encode(entry, values))


RUST_PROBE = r'''
// The routine the embedder defines beside the generated module. Rust needs no
// declaration for it: the pieces are one module, so a missing routine is a
// compile error naming the function rather than a link error naming a symbol.
static mut REACHED: i32 = 0;

fn axis_impl_auth_step(lifted: &Lifted, regs: &mut [u64], _mem: &mut dyn WideMemory,
                       _pc: u64, state: &mut [State64Entry],
                       result: &mut ExecResult64) {
    unsafe { REACHED += 1; }
    let value = read_reg64(regs, lifted.operands[1].unwrap_or(0),
                           lifted.entry.operands[1].kind, state);
    let modifier = read_reg64(regs, lifted.operands[2].unwrap_or(0),
                              lifted.entry.operands[2].kind, state);
    // Nothing in the description says this. That is the point.
    let signed = ((value << 13) | (value >> 51)) ^ modifier.wrapping_mul(31);
    let dest = lifted.operands[0].unwrap_or(0);
    if write_reg64(regs, dest, lifted.entry.operands[0].kind, signed, state) {
        result.wrote = Some(dest);
    }
    result.result = Some(signed);
}

struct NoMemory;
impl WideMemory for NoMemory {
    fn read64(&mut self, _addr: u64, _width: u32) -> u64 { 0 }
    fn write64(&mut self, _addr: u64, _value: u64, _width: u32) {}
}

fn main() {
    let mut regs = vec![0u64; 64];
    regs[1] = 0x0123456789abcdefu64;
    regs[2] = 5u64;
    let mut mem = NoMemory;
    let mut state: Vec<State64Entry> = Vec::new();

    // The control: semantics AXIS does state, so a harness that ran nothing is
    // distinguishable from a routine never called.
    let plain = step64(WORD_PLAIN, None, &mut regs, &mut mem, 0, &mut state);
    if plain.result != Some(regs[1].wrapping_add(regs[2])) {
        println!("FAIL plain gave {:?}", plain.result);
        std::process::exit(1);
    }

    let r = step64(WORD_AUTH, None, &mut regs, &mut mem, 0, &mut state);
    if unsafe { REACHED } != 1 {
        println!("FAIL routine reached {} time(s)", unsafe { REACHED });
        std::process::exit(1);
    }
    let value = 0x0123456789abcdefu64;
    let want = ((value << 13) | (value >> 51)) ^ 5u64.wrapping_mul(31);
    if r.result != Some(want) {
        println!("FAIL result {:?}, wanted {}", r.result, want);
        std::process::exit(1);
    }
    if r.wrote.is_none() { println!("FAIL the write was not reported"); std::process::exit(1); }
    if regs[4] != want {
        println!("FAIL register {}, wanted {}", regs[4], want);
        std::process::exit(1);
    }
    // The third answer: a trap rather than a call, with the artifact's cause.
    let missing = step64(WORD_UNSUPPLIED, None, &mut regs, &mut mem, 0, &mut state);
    if missing.trap != Some("unimplemented") {
        println!("FAIL unsupplied trap {:?}", missing.trap);
        std::process::exit(1);
    }
    if unsafe { REACHED } != 1 {
        println!("FAIL a routine ran for an unsupplied instruction");
        std::process::exit(1);
    }

    println!("OK");
}
'''


def check_rust(axis_file: Path, plain: int, auth: int, missing: int) -> bool:
    """The same question of the Rust executor, which dispatches the same way."""
    work = Path(tempfile.mkdtemp(prefix="axis_impl_rs_"))
    for command, name in (("emit-semantics-rust", "axis_semantics.rs"),
                          ("emit-lift-rust", "axis_lift.rs"),
                          ("emit-exec-rust", "axis_exec.rs")):
        subprocess.run([*axis_prefix(), command, str(axis_file),
                        "-o", str(work / name)],
                       check=True, capture_output=True, cwd=AXIS_ROOT)
    generated = "\n".join((work / name).read_text() for name in
                           ("axis_semantics.rs", "axis_lift.rs", "axis_exec.rs"))
    if f"axis_impl_auth_step(lifted" not in generated:
        print("  rust: the dispatch does not call the routine")
        return False
    source = RUST_PROBE.replace("WORD_PLAIN", f"0x{plain:08x}u32").replace(
        "WORD_AUTH", f"0x{auth:08x}u32").replace(
        "WORD_UNSUPPLIED", f"0x{missing:08x}u32")
    (work / "driver.rs").write_text(generated + "\n" + source)
    build = subprocess.run(
        ["rustc", "--edition", "2021", "-A", "warnings",
         "-o", str(work / "driver"), str(work / "driver.rs")],
        capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stderr[-1200:])
        print("  rust: the probe did not build")
        return False
    run = subprocess.run([str(work / "driver")], capture_output=True, text=True)
    line = run.stdout.strip() or run.stderr.strip()
    print(f"  rust: {line}")
    return run.returncode == 0 and line.endswith("OK")


def main() -> int:
    axis_file = AXIS_ROOT / "examples" / "implementation_routine.axisl"
    if not axis_file.exists():
        print("implementation routine == called: SKIP (no corpus)")
        return DECLINED
    work = Path(tempfile.mkdtemp(prefix="axis_impl_"))
    for command, name in (("emit-exec-c", "axis_exec.h"),
                          ("emit-lift-c", "axis_lift.h"),
                          ("emit-semantics-c", "axis_semantics.h")):
        subprocess.run([*axis_prefix(), command, str(axis_file),
                        "-o", str(work / name)],
                       check=True, capture_output=True, cwd=AXIS_ROOT)

    header = (work / "axis_exec.h").read_text()
    if "void axis_impl_auth_step(" not in header:
        print("implementation routine == called: FAIL (no declaration emitted)")
        return FAILED
    # ⚠️ Declared, not defined. A header that defined it would be answering the
    # question the embedder is supposed to answer.
    if "void axis_impl_auth_step(const axis_lifted" in header.split(
            "axis_exec_apply64")[0] and header.count("axis_impl_auth_step") < 2:
        print("implementation routine == called: FAIL (declared but never called)")
        return FAILED

    plain = encode(axis_file, "ADD_PLAIN", {"rd": 3, "rs1": 1, "rs2": 2})
    auth = encode(axis_file, "AUTH_STEP", {"rd": 4, "rs1": 1, "rs2": 2})
    missing = encode(axis_file, "SIGN_RETURN", {"rd": 5, "rs1": 1, "rs2": 2})
    # ⚠️ Nothing is declared for an unsupplied instruction, and the probe checks
    # that too: a header that declared a symbol nobody defines would make the
    # build require a definition that does not exist, which is the state this
    # third answer exists to avoid.
    if "axis_impl_sign_return" in header:
        print("implementation routine == called: FAIL "
              "(an unsupplied instruction declared a routine)")
        return FAILED
    source = PROBE.replace("WORD_PLAIN", f"0x{plain:08x}u").replace(
        "WORD_AUTH", f"0x{auth:08x}u").replace(
        "WORD_UNSUPPLIED", f"0x{missing:08x}u")
    (work / "probe.c").write_text(source)
    build = subprocess.run(
        ["cc", "-std=c11", "-Wall", "-Werror", "-I", str(work),
         "-o", str(work / "probe"), str(work / "probe.c")],
        capture_output=True, text=True)
    if build.returncode != 0:
        print(build.stderr[-1500:])
        print("implementation routine == called: FAIL (the probe did not build)")
        return FAILED
    run = subprocess.run([str(work / "probe")], capture_output=True, text=True)
    print(f"  c:    {run.stdout.strip() or run.stderr.strip()}")
    ok = run.returncode == 0 and run.stdout.strip().endswith("OK")
    # Both executors that can call a routine are asked, rather than one
    # checked and the other assumed.
    ok = check_rust(axis_file, plain, auth, missing) and ok
    print("implementation routine == called: " + ("PASS" if ok else "FAIL"))
    return PASSED if ok else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
