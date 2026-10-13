#!/usr/bin/env python3
"""Instructions wider than the word agree with the golden model.

`exec_wide_check` is the 64-bit tier and says so: it reports the cases "past
the 64-bit register slot" and does not execute them, because for a long time
nothing could. Its reason -- "a 128-bit operand has nowhere to live" -- stopped
being true when the executors learned to hold a wide value as limbs, and the
twenty instructions it names went from unexecutable to unmeasured, which is
worse.

This is the tier above it. Every instruction with an operand wider than the
word, driven with random contents in every limb of every register it reads,
against the golden model, which has always computed at full width.

⚠️ The registers are seeded whole. A driver that seeded 64 bits and left the
rest zero would agree with anything: the upper half would be zero on both sides
and the carry, the cross-limb shift and the wide multiply -- the three things
limb arithmetic can get wrong -- would never be exercised at all. That is the
failure this gate exists to avoid, and it is the one the tier below fell into.
"""
from __future__ import annotations

import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

DRIVER = r'''
#include <stdio.h>
#include <string.h>
#include "axis_exec.h"
static uint8_t MEM[1 << 16];
static uint64_t host_read(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0; uint32_t n = w / 8;
  if (a + n > sizeof MEM) return 0;
  for (uint32_t i = 0; i < n; ++i) v |= (uint64_t)MEM[a + i] << (8 * i);
  return v;
}
static void host_write(void *c, uint64_t a, uint64_t v, uint32_t w) {
  (void)c; uint32_t n = w / 8;
  if (a + n > sizeof MEM) return;
  for (uint32_t i = 0; i < n; ++i) MEM[a + i] = (uint8_t)(v >> (8 * i));
}
int main(void) {
  uint32_t word; char isa[64];
  while (scanf("%%u %%63s", &word, isa) == 2) {
    uint64_t regs[%(slots)d];
    for (int i = 0; i < %(slots)d; ++i) {
      unsigned long long v; scanf("%%llu", &v); regs[i] = v;
    }
    static axis_state64_entry SLOTS[] = %(state)s;
    axis_state64_entry live[sizeof SLOTS / sizeof SLOTS[0]];
    memcpy(live, SLOTS, sizeof SLOTS);
    axis_state64 state = { live, sizeof live / sizeof live[0] };
    axis_mem64 mem = { host_read, host_write, NULL };
    axis_exec_result64 r = axis_exec_step64(word, isa, regs, %(slots)d, &mem, 0, &state);
    printf("R %%d", r.ok);
    for (int i = 0; i < %(slots)d; ++i) printf(" %%llu", (unsigned long long)regs[i]);
    printf("\n"); fflush(stdout);
  }
  return 0;
}
'''



# ⚠️ The limb operations, driven DIRECTLY. The instruction-level comparison
# above cannot reach them all: a lane add is shifted down to lane 0 before it
# adds, so it never carries between limbs, and `MOVI`'s broadcast constant
# times a byte is exactly 2^64-1, so its multiply never carries either. Every
# one of those paths was mutated to something wrong and the instruction sweep
# still passed, which is the sweep saying it does not reach them.
#
# So they are tested as arithmetic, against Python's integers, which have no
# limbs and no width. Carry, borrow, the cross-limb shift by a non-multiple of
# 64, and comparison from the top are exactly the code limb arithmetic is easy
# to get wrong in, and none of them was covered a moment ago.
ARITH = r'''
#include <stdio.h>
#include "axis_exec.h"
int main(void) {
  unsigned long long a0, a1, b0, b1, sh;
  while (scanf("%llu %llu %llu %llu %llu", &a0, &a1, &b0, &b1, &sh) == 5) {
    axis_wide a = axis_wide_zero(), b = axis_wide_zero();
    a.limb[0] = a0; if (AXIS_WIDE_LIMBS > 1) a.limb[1] = a1;
    b.limb[0] = b0; if (AXIS_WIDE_LIMBS > 1) b.limb[1] = b1;
    axis_wide r[5];
    r[0] = axis_wide_add(a, b, 128u);
    r[1] = axis_wide_sub(a, b, 128u);
    r[2] = axis_wide_mul(a, b, 128u);
    r[3] = axis_wide_shl(a, sh, 128u);
    r[4] = axis_wide_lshr(a, sh, 128u);
    for (int i = 0; i < 5; ++i) {
      printf("%llu %llu ", (unsigned long long)r[i].limb[0],
             (unsigned long long)(AXIS_WIDE_LIMBS > 1 ? r[i].limb[1] : 0));
    }
    printf("%d %d\n", axis_wide_eq(a, b), axis_wide_ult(a, b));
    fflush(stdout);
  }
  return 0;
}
'''


def check_arithmetic(workdir, rng, rounds: int, lang: str, driver) -> tuple[int, int]:
    """The limb helpers against Python integers. Returns (checked, failures)."""
    if lang == "rust":
        binary, prefix = driver, "A "
    else:
        (workdir / "arith.c").write_text(ARITH)
        subprocess.run(["cc", "-std=c11", "-DAXIS_IMPL_STUBS", "-I", str(workdir),
                        "-o", str(workdir / "arith"), str(workdir / "arith.c"),
                        "-lm"], check=True)
        binary, prefix = workdir / "arith", ""
    mask = (1 << 128) - 1
    proc = subprocess.Popen([str(binary)], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, text=True)
    checked = failures = 0
    for _ in range(rounds):
        a = rng.getrandbits(128)
        b = rng.getrandbits(128)
        shift = rng.randrange(0, 130)
        proc.stdin.write(f"{prefix}{a & ((1 << 64) - 1)} {a >> 64} "
                         f"{b & ((1 << 64) - 1)} {b >> 64} {shift}\n")
        proc.stdin.flush()
        parts = [int(x) for x in proc.stdout.readline().split()]
        got = [parts[2 * i] | (parts[2 * i + 1] << 64) for i in range(5)]
        want = [(a + b) & mask, (a - b) & mask, (a * b) & mask,
                (a << shift) & mask if shift < 128 else 0,
                (a >> shift) if shift < 128 else 0]
        for name, have, expect in zip(
                ("add", "sub", "mul", "shl", "lshr"), got, want):
            checked += 1
            if have != expect:
                failures += 1
                if failures <= 4:
                    print(f"  wide {name}: {have:#034x} != {expect:#034x} "
                          f"(a={a:#034x} b={b:#034x} shift={shift})")
        for name, have, expect in (("eq", parts[10], int(a == b)),
                                   ("ult", parts[11], int(a < b))):
            checked += 1
            if have != expect:
                failures += 1
                print(f"  wide {name}: {have} != {expect}")
    proc.stdin.close()
    proc.wait()
    return checked, failures



# The Rust twin of the driver above. Concatenated into one flat crate, as the
# other Rust harnesses do, because that is how the generated files are written.
RUST_DRIVER = """
struct NoMem;
impl WideMemory for NoMem {
    fn read64(&mut self, _a: u64, _w: u32) -> u64 { 0 }
    fn write64(&mut self, _a: u64, _v: u64, _w: u32) {}
}
fn main() {
    let mut line = String::new();
    loop {
        line.clear();
        if std::io::stdin().read_line(&mut line).unwrap_or(0) == 0 { break; }
        let mut it = line.split_whitespace();
        let head = match it.next() { Some(t) => t, None => break };
        // ⚠️ An "A" line drives the limb helpers DIRECTLY, for the reason the
        // C twin does: the instructions reach the shifts and nothing else. The
        // carry, the borrow and the comparison from the top were each broken
        // on purpose and the instruction sweep passed every time.
        if head == "A" {
            let n: Vec<u64> = it.map(|t| t.parse::<u64>().unwrap()).collect();
            let mut a = wide_zero(); let mut b = wide_zero();
            a.limb[0] = n[0]; if AXIS_WIDE_LIMBS > 1 { a.limb[1] = n[1]; }
            b.limb[0] = n[2]; if AXIS_WIDE_LIMBS > 1 { b.limb[1] = n[3]; }
            let sh = n[4];
            let r = [wide_add(a, b, 128), wide_sub(a, b, 128), wide_mul(a, b, 128),
                     wide_shl(a, sh, 128), wide_lshr(a, sh, 128)];
            let mut out = String::new();
            for w in r.iter() {
                out.push_str(&format!("{} {} ", w.limb[0],
                    if AXIS_WIDE_LIMBS > 1 { w.limb[1] } else { 0 }));
            }
            out.push_str(&format!("{} {}", wide_eq(a, b) as i32, wide_ult(a, b) as i32));
            println!("{}", out);
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            continue;
        }
        let word: u32 = head.parse().unwrap();
        let isa = it.next().unwrap().to_string();
        let mut regs: Vec<u64> = it.map(|t| t.parse::<u64>().unwrap()).collect();
        let mut state = vec![%(state)s];
        let mut mem = NoMem;
        let r = step64(word, Some(&isa), &mut regs, &mut mem, 0, &mut state);
        let mut out = format!("R {}", if r.ok { 1 } else { 0 });
        for v in &regs { out.push_str(&format!(" {}", v)); }
        println!("{}", out);
        use std::io::Write;
        std::io::stdout().flush().unwrap();
    }
}
"""


def build_rust(workdir, lift) -> Path:
    """One flat crate: semantics, lifter, executor and a stdin driver."""
    entries = ",".join(
        f'State64Entry {{ name: "{n}", value: 0u64, width: {w}u32 }}'
        for n, w in lift.STATE_SLOTS)
    driver = workdir / "driver.rs"
    driver.write_text(
        (workdir / "axis_semantics.rs").read_text() + "\n"
        + (workdir / "axis_lift.rs").read_text() + "\n"
        + (workdir / "axis_exec.rs").read_text() + "\n"
        + RUST_DRIVER % {"state": entries})
    binary = workdir / "driver_rs"
    subprocess.run(["rustc", "--edition", "2021", "-A", "warnings",
                    "--cfg", "axis_impl_stubs", "-o", str(binary), str(driver)],
                   check=True, cwd=workdir)
    return binary


def encode(entry, values: dict) -> int:
    """The word for these operand values, the way the fixtures were built."""
    word = entry["match"]
    for op in entry["operands"]:
        value = values.get(op["name"], 0)
        for insn_lo, op_lo, width in op["fields"]:
            word |= ((value >> op_lo) & ((1 << width) - 1)) << insn_lo
    return word


def place(lift, kind: str, index: int) -> tuple[int, int]:
    """Where a register of this class lives, and how many limbs it spans."""
    rules = lift.REGISTER_CLASSES[kind]
    return rules[3] + index * rules[6], rules[6]


def main() -> int:
    axis_file = Path(sys.argv[1]) if len(sys.argv) > 1 else None
    if axis_file is None or not axis_file.exists():
        print("usage: wide_arith_check.py <corpus.axisl>")
        return FAILED
    argv = [a for a in sys.argv[2:] if not a.startswith("--")]
    lang = "rust" if "--lang=rust" in sys.argv else "c"
    cases = int(argv[0]) if argv else 40

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        emits = [("emit-lift-python", "axis_lift.py"),
                 ("emit-golden-python", "golden_model.py"),
                 ("emit-roundtrip-json", "fixtures.json")]
        emits += ([("emit-exec-rust", "axis_exec.rs"),
                   ("emit-lift-rust", "axis_lift.rs"),
                   ("emit-semantics-rust", "axis_semantics.rs")]
                  if lang == "rust" else
                  [("emit-exec-c", "axis_exec.h"),
                   ("emit-lift-c", "axis_lift.h"),
                   ("emit-semantics-c", "axis_semantics.h")])
        for command, name in emits:
            subprocess.run([*axis_prefix(), command, str(axis_file),
                            "-o", str(workdir / name)], check=True,
                           capture_output=True)
        sys.path.insert(0, str(workdir))
        import importlib
        lift = importlib.import_module("axis_lift")
        golden = importlib.import_module("golden_model")

        slots = lift.REGISTER_FILE_SLOTS
        state = "{" + ",".join(f'{{"{n}",0,{w}u}}' for n, w in lift.STATE_SLOTS) + "}"
        if lang == "rust":
            driver = build_rust(workdir, lift)
        else:
            (workdir / "driver.c").write_text(
                DRIVER % {"slots": slots, "state": state or "{0}"})
            subprocess.run(["cc", "-std=c11", "-DAXIS_IMPL_STUBS", "-I", str(workdir),
                            "-o", str(workdir / "driver"), str(workdir / "driver.c"),
                            "-lm"], check=True)
            driver = workdir / "driver"

        fixtures = json.loads((workdir / "fixtures.json").read_text())["tests"]
        wide = [t for t in fixtures
                if (entry := lift.decode(int(t["encoded"], 16), t.get("isa")))
                and any(op.get("width", 0) > 64 for op in entry["operands"])]
        if not wide:
            print("wide arithmetic == golden model: SKIP "
                  "(no instruction here is wider than the word)")
            return DECLINED

        rng = random.Random(0x5EED)
        proc = subprocess.Popen([str(driver)], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True)
        checked = failures = 0
        reached: set[str] = set()
        declined: set[str] = set()
        # Two different reasons, kept apart. An instruction the EXECUTOR turned
        # away is a hole in the executor; one with no formal semantics is a
        # hole in this gate's reference, and for the wide memory moves that is
        # all it is -- they are stated as effects and `simulator: A64` compares
        # them against the same golden model, through memory rather than
        # through a value.
        unstated: set[str] = set()
        for test in wide:
            word = int(test["encoded"], 16)
            entry = lift.decode(word, test.get("isa"))
            spec = golden.AXIS_SPECS.get(test["mnemonic"])
            if entry is None:
                continue
            if spec is None:
                unstated.add(test["mnemonic"])
                continue
            base_values = {op["name"]: op["value"] for op in test["operands"]}
            for attempt in range(cases):
                # ⚠️ The IMMEDIATES are redrawn too, not just the registers. A
                # fixture carries one immediate, and `MOVI`'s whole job is to
                # multiply it by a 128-bit broadcast constant -- so leaving it
                # fixed left the multiply's cross-limb carry unexercised, which
                # a deliberately broken carry proved by passing.
                values = dict(base_values)
                if attempt:
                    for op in entry["operands"]:
                        if lift.is_register_operand(op["kind"]) or not op["fields"]:
                            continue
                        bits = max(w for _lo, _op_lo, w in op["fields"])
                        values[op["name"]] = rng.getrandbits(bits)
                    word = encode(entry, values)
                    again = lift.decode(word, test.get("isa"))
                    if again is None or again["mnemonic"] != test["mnemonic"]:
                        continue
                regs = [rng.getrandbits(64) for _ in range(slots)]
                proc.stdin.write(f"{word} {test.get('isa') or 'none'} "
                                 + " ".join(str(v) for v in regs) + "\n")
                proc.stdin.flush()
                parts = proc.stdout.readline().split()
                ok, got = int(parts[1]), [int(x) for x in parts[2:]]
                if not ok:
                    declined.add(test["mnemonic"])
                    break
                reached.add(test["mnemonic"])
                inputs = []
                for op in entry["operands"]:
                    if op["role"] in ("out", "enc"):
                        continue
                    value = values.get(op["name"], 0)
                    if lift.is_register_operand(op["kind"]):
                        base, limbs = place(lift, op["kind"], value)
                        inputs.append(sum(regs[base + k] << (64 * k)
                                          for k in range(limbs)))
                    else:
                        inputs.append(value)
                want = spec["eval"](*inputs)
                dest = next((op for op in entry["operands"]
                             if op["role"] in ("out", "inout")), None)
                if dest is None:
                    continue
                base, limbs = place(lift, dest["kind"], values.get(dest["name"], 0))
                have = sum(got[base + k] << (64 * k) for k in range(limbs))
                want &= (1 << (limbs * 64)) - 1
                checked += 1
                if have != want:
                    failures += 1
                    if failures <= 4:
                        print(f"  {test['mnemonic']}: executor {have:#034x} "
                              f"!= golden {want:#034x}")
        proc.stdin.close()
        proc.wait()
        ops, op_failures = check_arithmetic(workdir, rng, 400, lang, driver)
        checked += ops
        failures += op_failures
        print(f"  {ops} limb operation(s) checked against Python integers")

    print(f"{checked} wide case(s) compared, {failures} disagree, "
          f"{len(reached)} instruction(s) reached")
    # Said out loud: an instruction the executor turned away is one this gate
    # intended to check and did not.
    if declined:
        shown = ", ".join(sorted(declined)[:6])
        more = f" (+{len(declined) - 6} more)" if len(declined) > 6 else ""
        print(f"  {len(declined)} the executor declines: {shown}{more}")
    if unstated:
        shown = ", ".join(sorted(unstated)[:4])
        more = f" (+{len(unstated) - 4} more)" if len(unstated) > 4 else ""
        print(f"  {len(unstated)} stated as effects rather than as a value, so "
              f"this gate has nothing to compare; `simulator: A64` runs them "
              f"through memory: {shown}{more}")
    if not checked:
        print("wide arithmetic == golden model: SKIP (nothing ran)")
        return DECLINED
    label = "Rust" if lang == "rust" else "C"
    print(f"wide {label} arithmetic == golden model:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
