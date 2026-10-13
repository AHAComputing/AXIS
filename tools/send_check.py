#!/usr/bin/env python3
"""A message leaves the machine, and every backend agrees which. Gate.

`send(port, value, iW)` is the one effect that leaves the machine without
leaving an address behind. It exists because a posted-message ISA's instruction
does exactly what a store does -- evaluate two expressions, emit one ordered
event, continue -- and because an effect no gate could hold is an effect this
language cannot afford to have.

So this holds it the way every other effect is held: three independent
backends, one golden model, compared bit for bit.

⚠️ What is compared is the LOG, not a final state. A message is not readable
back -- that is what makes it a message rather than a store -- so the only
observable is the sequence: which port, what value, how wide, in what order.
Two backends that posted the same two messages in the other order would leave
identical machines behind, and that is a difference this gate is here to see.

⚠️ And the guard. `SEND_NZ` posts only when its payload is non-zero, which is
what separates "this was evaluated" from "this happened": a backend that logged
every send it computed would report messages the machine does not post. Roughly
half the seeds make that guard false on purpose.

Usage: tools/send_check.py [corpus.axisl ...]
"""
from __future__ import annotations

import argparse
import importlib
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

HARNESS = r"""
/* One machine, a log of what it posted. */
#include <stdio.h>
#include <string.h>
#include "axis_lift.h"
#include "axis_semantics.h"
#include "axis_exec.h"

#define SLOTS 64
#define SENT 256
static uint64_t REGS[SLOTS];
static struct { uint64_t port, value; uint32_t width; } SENT_LOG[SENT];
static int32_t SENT_COUNT;

static uint64_t rd(void *c, uint64_t a, uint32_t w) { (void)c; (void)a; (void)w; return 0u; }
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; (void)a; (void)v; (void)w; }
static void sent(void *c, uint64_t port, uint64_t value, uint32_t width) {
  (void)c;
  if (SENT_COUNT < SENT) {
    SENT_LOG[SENT_COUNT].port = port;
    SENT_LOG[SENT_COUNT].value = value;
    SENT_LOG[SENT_COUNT].width = width;
  }
  SENT_COUNT++;
}

int main(void) {
  static const uint32_t WORDS[] = { %(words)s };
  static const uint64_t SEEDS[][4] = { %(seeds)s };
  const int32_t cases = (int32_t)(sizeof SEEDS / sizeof SEEDS[0]);
  const int32_t count = (int32_t)(sizeof WORDS / sizeof WORDS[0]);
  axis_mem64 mem = { rd, wr, NULL, NULL, NULL, sent };
  for (int32_t c = 0; c < cases; ++c) {
    for (int32_t w = 0; w < count; ++w) {
      /* ⚠️ Multiplied, not offset. `seed + i` is never zero for i > 0, so a
         guard that tests its payload against zero was true in every case and
         the gate never saw one withheld. */
      for (int32_t i = 0; i < SLOTS; ++i) { REGS[i] = SEEDS[c][i %% 4] * (uint64_t)(i + 1); }
      SENT_COUNT = 0;
      axis_state64 held = { NULL, 0 };
      axis_exec_result64 r = axis_exec_step64(WORDS[w], %(isa)s, REGS, SLOTS,
                                              &mem, 0x100u, &held);
      printf("CASE %%d %%d %%d %%d", c, w, r.ok, SENT_COUNT);
      for (int32_t i = 0; i < SENT_COUNT && i < SENT; ++i) {
        printf(" %%llu/%%llu/%%u", (unsigned long long)SENT_LOG[i].port,
               (unsigned long long)SENT_LOG[i].value, SENT_LOG[i].width);
      }
      printf("\n");
    }
  }
  return 0;
}
"""


def run(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def reference(lift, golden, entry, word, regs):
    """What the golden model says this instruction posts, in order.

    Built from the lift table's own effect list and the golden model's
    expression evaluator -- the two artifacts every other differential gate
    uses -- rather than from a second reading of the description.
    """
    env = {}
    for operand in entry["operands"]:
        value = lift.lift_entry(word, entry)["operands"].get(operand["name"])
        if value is None:
            return None
        if operand["kind"] in ("imm",):
            env[operand["name"]] = value
        else:
            slot = lift.register_slot(operand["kind"], value)
            env[operand["name"]] = regs[slot % len(regs)]
    posted = []
    for effect in (entry.get("effects") or []):
        if effect["kind"] != "send":
            continue
        if effect.get("guard"):
            held = golden._eval_axis_expr(effect["guard"], env,
                                          effect.get("guard_width") or 32)
            if not held:
                continue
        port = golden._eval_axis_expr(effect["port"], env,
                                      effect.get("port_width")
                                      or effect["eval_width"])
        value = golden._eval_axis_expr(effect["value"], env,
                                       effect["eval_width"])
        posted.append((port, value & ((1 << effect["width"]) - 1),
                       effect["width"]))
    return posted


def check(axis_file: Path, work: Path, rng: random.Random) -> tuple[int, int]:
    name = axis_file.stem
    run([*axis_prefix(), "emit-lift-python", str(axis_file),
         "-o", str(work / f"sl_{name}.py")])
    run([*axis_prefix(), "emit-golden-python", str(axis_file),
         "-o", str(work / f"sg_{name}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(f"sl_{name}")
    golden = importlib.import_module(f"sg_{name}")

    sending = [entry for entry in lift.AXIS_LIFT_TABLE
               if any(effect["kind"] == "send"
                      for effect in (entry.get("effects") or []))]
    if not sending:
        print(f"  {name}: DECLINED nothing in this description posts a message")
        return 0, 0

    tests = json.loads(run([*axis_prefix(), "emit-roundtrip-json",
                            str(axis_file)]).stdout)["tests"]
    by_mnemonic = {}
    for test in tests:
        by_mnemonic.setdefault(test["mnemonic"], int(test["encoded"], 16))
    words, entries = [], []
    for entry in sending:
        word = by_mnemonic.get(entry["mnemonic"])
        if word is None:
            continue
        words.append(word)
        entries.append(entry)
    if not words:
        print(f"  {name}: DECLINED no fixture reaches an instruction that posts")
        return 0, 0

    # ⚠️ A zero among the seeds, so a guarded send is seen NOT to fire. Without
    # one, every case posts and "logged what it computed" passes.
    seeds = [[0, 0, 0, 0], [1, 2, 3, 4], [0xffffffff, 0, 7, 0x80000000]]
    seeds += [[rng.randrange(1 << 32) for _ in range(4)] for _ in range(5)]

    isa = entries[0].get("isa") or ""
    source = HARNESS % {
        "words": ", ".join(f"{word}u" for word in words),
        "seeds": ", ".join("{" + ", ".join(f"{v}ull" for v in seed) + "}"
                           for seed in seeds),
        "isa": f'"{isa}"' if isa else "NULL",
    }
    for command, out in (("emit-lift-c", "axis_lift.h"),
                         ("emit-semantics-c", "axis_semantics.h"),
                         ("emit-exec-c", "axis_exec.h")):
        run([*axis_prefix(), command, str(axis_file), "-o", str(work / out)])
    (work / f"{name}.c").write_text(source)
    run(["cc", "-std=c11", "-O1", "-I", str(work), "-o", str(work / name),
         str(work / f"{name}.c")])
    done = subprocess.run([str(work / name)], capture_output=True, text=True)
    if done.returncode != 0:
        print(f"  FAIL {name}: the harness exited {done.returncode}")
        return 0, 1

    checks = failures = 0
    posted_any = 0
    withheld_any = 0
    for line in done.stdout.splitlines():
        if not line.startswith("CASE "):
            continue
        parts = line.split()
        case, which, ok, sent_count = (int(x) for x in parts[1:5])
        got = [tuple(int(x) for x in field.split("/")) for field in parts[5:]]
        entry, word = entries[which], words[which]
        regs = [(seeds[case][i % 4] * (i + 1)) & 0xFFFFFFFFFFFFFFFF
                for i in range(64)]
        want = reference(lift, golden, entry, word, regs)
        if want is None:
            continue
        checks += 1
        if got != want:
            print(f"  FAIL {name}: {entry['mnemonic']} with seed {case} posted "
                  f"{got}, the golden model says {want}")
            failures += 1
        posted_any += len(want)
        if not want and (entry.get("effects")
                         and any(e["kind"] == "send" and e.get("guard")
                                 for e in entry["effects"])):
            withheld_any += 1
        checks += 1
        if sent_count != len(want):
            print(f"  FAIL {name}: {entry['mnemonic']} posted {sent_count} "
                  f"message(s), the golden model says {len(want)}")
            failures += 1

    # Vacuity, both ways: a run where nothing was posted proves nothing, and so
    # does one where no guard ever withheld a message.
    checks += 1
    if not posted_any:
        print(f"  FAIL {name}: no message was posted in any case")
        failures += 1
    guarded = any(effect.get("guard") for entry in sending
                  for effect in (entry.get("effects") or [])
                  if effect["kind"] == "send")
    if guarded:
        checks += 1
        if not withheld_any:
            print(f"  FAIL {name}: no guard ever withheld a message, so "
                  f"'posted' and 'evaluated' were never told apart")
            failures += 1

    if not failures:
        print(f"  {name}: {posted_any} message(s) posted and matched, "
              f"{withheld_any} withheld by a guard, {checks} checks")
    for module in (f"sl_{name}", f"sg_{name}"):
        sys.modules.pop(module, None)
    if str(work) in sys.path:
        sys.path.remove(str(work))
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    parser.add_argument("--seed", type=int, default=20260918)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "effects_send.axisl"]
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
        print("what was posted == the golden model: SKIP")
        return DECLINED
    print(f"what was posted == the golden model: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, "
          f"{failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
