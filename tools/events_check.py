#!/usr/bin/env python3
"""A wait for an event sleeps; a send wakes it (U4c). Gate.

`(events (wait W) (send S))` on an execution-driven core gives each machine
an event register (docs/unified_engine_design.md). A wait that commits with
it set clears it and goes on; with it clear the machine SLEEPS -- what it
fetched after the wait is squashed and it fetches nothing -- until another
machine's send commits, which sets every register and wakes every sleeper.

On RV64 (`examples/rv64i.axisl`), with a wait and a send composed in as
FENCE-format words, four execution-driven cores stepped together: one
producer does some work, stores a flag and sends; three waiters poll the flag
with a wait between polls.

  * WAITERS SLEEP. With the clause, every waiter ends where its program
    puts it, having slept, and committed at most 20 instructions.
  * WITHOUT IT THEY SPIN. The same cores without the clause commit more than
    200 instructions each, polling: the wait does nothing.
  * NO WAKE IS LOST. A producer with no work sends before the waiters
    reach their wait; the event register holds it, and every waiter ends.
  * A WAIT AFTER AN EVENT GOES ON. Waiters that set their own register
    (the local send) and then wait do not sleep: the wait clears it and
    they end at once.
  * NOBODY LEFT TO SEND. Waiters with no producer all sleep, and the run
    ends at once, each machine halted saying why -- not 100,000 idle cycles.
  * REFUSALS. Events naming an instruction that does not exist, and events
    on a trace-driven core, are refused.

Usage: tools/events_check.py [examples/rv64i.axisl]
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_pack  # noqa: E402
from axis_cli import FAILED, PASSED, axis_prefix  # noqa: E402
from memsys_pack_check import ENTRY, b_type, i_type, s_type  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
FLAG = 0x7F0
WAITER = 0x100  # the waiters' routine, this many bytes after ENTRY
WORK = 300

INSTRUCTIONS = """
  (definstruction WFE_T
    (mnemonic WFE_T) (isa rv64i) (category custom) (format RV_FENCE)
    (opcode 0x0f) (func3 2) (encoding (fm 0) (rd 0) (rs1 0))
    (operands (option imm i8 in)) (asm "wfe.t $option")
    (semantics "Wait for an event: architecturally free to do nothing")
    (behavior (barrier fence option))
    (latency 1) (throughput 1.0) (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)
    (rationale "events_check's wait, composed in"))
  (definstruction SEV_T
    (mnemonic SEV_T) (isa rv64i) (category custom) (format RV_FENCE)
    (opcode 0x0f) (func3 3) (encoding (fm 0) (rd 0) (rs1 0))
    (operands (option imm i8 in)) (asm "sev.t $option")
    (semantics "Send an event to every core")
    (behavior (barrier fence option))
    (latency 1) (throughput 1.0) (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)
    (rationale "events_check's send, composed in"))
  (definstruction SEVL_T
    (mnemonic SEVL_T) (isa rv64i) (category custom) (format RV_FENCE)
    (opcode 0x0f) (func3 4) (encoding (fm 0) (rd 0) (rs1 0))
    (operands (option imm i8 in)) (asm "sevl.t $option")
    (semantics "Set this core's own event register")
    (behavior (barrier fence option))
    (latency 1) (throughput 1.0) (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)
    (rationale "events_check's local send, composed in"))
"""
CORE = """
  (defcore %(name)s
    (kind rvmt)
    (implements rv64i)
    (issue-width 2)
    (window (rob 32) (issue-queue 32) (commit-width 2))
    (branch (penalty 0) (predictor bimodal) (entries 64))
    (front-end (fetch-width 4) (depth 2))
    (engine %(engine)s)%(events)s)
"""
CLAUSE = "\n    (events (wait WFE_T) (send SEV_T) (local SEVL_T))"
WFE, SEV, SEVL = 0x200F, 0x300F, 0x400F


def producer(work: int) -> list[int]:
    """x2 = work; while x2: x2 -= 1; x1 = FLAG; x3 = 1; sw x3,0(x1); sev."""
    words = [i_type(0x13, 0, 2, 0, work)]
    if work:
        words += [i_type(0x13, 0, 2, 2, -1), b_type(0x63, 1, 2, 0, -4)]
    return words + [i_type(0x13, 0, 1, 0, FLAG), i_type(0x13, 0, 3, 0, 1), s_type(0x23, 2, 1, 3, 0), SEV]


def waiter() -> list[int]:
    """x1 = FLAG; loop: lw x3,0(x1); bne x3,x0,done; wfe; jal x0,loop; done: x5 = 7."""
    return [i_type(0x13, 0, 1, 0, FLAG),
            i_type(0x03, 2, 3, 1, 0),          # lw x3, 0(x1)
            b_type(0x63, 1, 3, 0, 12),         # bne x3, x0, +12
            WFE,
            (((-12 >> 20) & 1) << 31) | (((-12 >> 1) & 0x3FF) << 21) | (((-12 >> 11) & 1) << 20)
            | (((-12 >> 12) & 0xFF) << 12) | 0x6F,  # jal x0, -12
            i_type(0x13, 0, 5, 0, 7)]          # addi x5, x0, 7


HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axis_pack.h"
extern const axis_sim_pack *@SIM@(void);
static uint8_t MEM[1 << 16];
static uint64_t rd(void *c, uint64_t a, uint32_t w) {
  (void)c; uint64_t v = 0; if (a + w / 8 <= sizeof MEM) memcpy(&v, MEM + a, w / 8); return v;
}
static void wr(void *c, uint64_t a, uint64_t v, uint32_t w) { (void)c; if (a + w / 8 <= sizeof MEM) memcpy(MEM + a, &v, w / 8); }
static uint32_t LIMIT;
static uint32_t fetch(void *c, uint64_t pc, int32_t *ok) {
  (void)c; *ok = pc >= @ENTRY@ && pc < LIMIT; uint32_t v = 0; if (*ok) memcpy(&v, MEM + pc, 4); return v;
}
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) { (void)c; (void)cause; *stop = 1; return pc; }
/* argv: core, producers (0 or 1), words of the producer, "--", words of the waiter. */
int main(int argc, char **argv) {
  const axis_sim_pack *S = @SIM@();
  int producers = atoi(argv[2]), i = 3;
  uint32_t at = @ENTRY@;
  for (; i < argc && strcmp(argv[i], "--"); ++i, at += 4) { uint32_t w = (uint32_t)strtoul(argv[i], 0, 0); memcpy(MEM + at, &w, 4); }
  at = @ENTRY@ + @WAITER@;
  for (++i; i < argc; ++i, at += 4) { uint32_t w = (uint32_t)strtoul(argv[i], 0, 0); memcpy(MEM + at, &w, 4); }
  LIMIT = at;
  int n = producers + 3;
  void *ms[4];
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  for (int k = 0; k < n; ++k) {
    ms[k] = S->create(&hooks);
    if (!S->select_core(ms[k], argv[1])) { printf("NOCORE\n"); return 1; }
    axis_pack_state_entry state[64];
    int32_t ns = S->state_slots() < 64 ? S->state_slots() : 64;
    for (int32_t j = 0; j < ns; ++j) { state[j].name = S->state_name(j); state[j].width = S->state_width(j); state[j].value = 0; }
    S->reset(ms[k], (k < producers ? @ENTRY@u : @ENTRY@u + @WAITER@u), @ISA@, state, ns);
    S->count_cycles(ms[k], 1);
  }
  uint64_t cycles = 0;
  while (S->cycle_cores(ms, n, 1) > 0 && ++cycles < 400000) {}
  printf("CYCLES %llu\n", (unsigned long long)cycles);
  for (int k = 0; k < n; ++k) {
    uint64_t r[4] = {0, 0, 0, 0};
    S->warp_rides(ms[k], r, 4);
    printf("M%d role=%s steps=%llu sleeps=%llu x5=%llu status=%d why=%s\n", k, k < producers ? "producer" : "waiter",
           (unsigned long long)S->steps(ms[k]), (unsigned long long)r[3], (unsigned long long)S->reg(ms[k], 5),
           S->status(ms[k]), S->halt_reason(ms[k]) ? S->halt_reason(ms[k]) : "-");
    S->destroy(ms[k]);
  }
  return 0;
}
"""


def run(binary: Path, core: str, producers: int, work: int) -> dict:
    args = [str(binary), core, str(producers), *map(str, producer(work)), "--", *map(str, waiter())]
    out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    rows: dict = {"machines": []}
    for line in out.splitlines():
        f = line.split(" ", 2)
        if f[0] == "CYCLES":
            rows["cycles"] = int(f[1])
        elif f[0].startswith("M"):
            head, why = line.split(" why=", 1)
            fields = dict(x.split("=", 1) for x in head.split()[1:])
            fields["why"] = why
            rows["machines"].append(fields)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "rv64i.axisl")
    args = parser.parse_args()
    text = args.axis_file.read_text()
    end = text.rstrip().rfind(")")
    cores = CORE % {"name": "ev", "engine": "execute", "events": CLAUSE} \
        + CORE % {"name": "noev", "engine": "execute", "events": ""}
    failures: list[str] = []
    lines: list[str] = []
    with tempfile.TemporaryDirectory(prefix="axis_ev_") as work:
        work = Path(work)
        corpus = work / "ev.axisl"
        corpus.write_text(text[:end] + INSTRUCTIONS + cores + text[end:])
        pack = build_pack.build(corpus, work / "packs", only={"sim", "exec", "lift"})
        root = work / "packs" / pack["name"]
        isa = json.loads(subprocess.run([*axis_prefix(), "emit-json", str(corpus)], capture_output=True, text=True,
                                        check=True, cwd=AXIS_ROOT).stdout)["isas"][0]["name"]
        src = work / "h.c"
        src.write_text(HARNESS.replace("@SIM@", pack["libraries"]["sim"]["entry"]).replace("@ENTRY@", str(ENTRY))
                       .replace("@WAITER@", str(WAITER)).replace("@ISA@", f'"{isa}"'))
        subprocess.run(["cc", "-std=c11", "-O1", "-I", str(root / "include"), "-o", str(work / "h"), str(src),
                        str(root / "lib" / pack["libraries"]["sim"]["static"]),
                        str(root / "lib" / pack["libraries"]["exec"]["static"])], check=True, capture_output=True)

        def waiters(rows):
            return [m for m in rows["machines"] if m["role"] == "waiter"]

        ev = run(work / "h", "ev", 1, WORK)
        for k, m in enumerate(waiters(ev)):
            if m["x5"] != "7":
                failures.append(f"with events, waiter {k} ended with x5 = {m['x5']} ({m['why']}), not 7")
            if int(m["steps"]) > 20 or int(m["sleeps"]) < 1:
                failures.append(f"with events, waiter {k} committed {m['steps']} instructions and slept "
                                f"{m['sleeps']} times; a waiter should sleep, not poll")
        noev = run(work / "h", "noev", 1, WORK)
        for k, m in enumerate(waiters(noev)):
            if m["x5"] != "7":
                failures.append(f"without events, waiter {k} ended with x5 = {m['x5']}, not 7")
            if int(m["steps"]) <= 200:
                failures.append(f"without events, waiter {k} committed only {m['steps']} instructions; polling "
                                "should take hundreds, or this gate cannot see what sleeping saves")
        lines.append(f"producer works {WORK} trips: waiters commit {[m['steps'] for m in waiters(ev)]} instructions "
                     f"with events (slept {[m['sleeps'] for m in waiters(ev)]}), "
                     f"{[m['steps'] for m in waiters(noev)]} polling")
        early = run(work / "h", "ev", 1, 0)
        for k, m in enumerate(waiters(early)):
            if m["x5"] != "7":
                failures.append(f"a send before the waits: waiter {k} ended with x5 = {m['x5']} ({m['why']}); the "
                                "event register must hold a send no one was asleep for")
        lines.append(f"send before the waits: waiters end with x5 = {[m['x5'] for m in waiters(early)]}")
        # A wait with the register already set: each waiter's own local send
        # first, then the waiter's program. No producer, so a waiter that slept
        # here would never wake.
        def local_first() -> list[int]:
            return [SEVL] + waiter()[:1] + [WFE] + [i_type(0x13, 0, 5, 0, 7)]
        args = [str(work / "h"), "ev", "0", "--", *map(str, local_first())]
        out = subprocess.run(args, capture_output=True, text=True, check=True).stdout
        held = [ln for ln in out.splitlines() if ln.startswith("M")]
        if not held or any(" x5=7 " not in ln or " sleeps=0 " not in ln for ln in held):
            failures.append("a wait after a local send slept, or did not end: " + "; ".join(held))
        lines.append("a wait after a local send goes on: " + ", ".join(
            ln.split(" x5=")[0].split()[-2] + " x5=" + ln.split(" x5=")[1].split()[0] for ln in held))
        alone = run(work / "h", "ev", 0, 0)
        if alone["cycles"] > 2000:
            failures.append(f"waiters with nobody to send ran {alone['cycles']} cycles; every machine asleep is the end")
        for k, m in enumerate(alone["machines"]):
            if "asleep" not in m["why"]:
                failures.append(f"waiter {k} with nobody to send stopped with `{m['why']}`, not saying it was asleep")
        lines.append(f"nobody to send: ended after {alone['cycles']} cycles: {alone['machines'][0]['why']}")
        for label, bad, needle in (
                ("an undeclared wait", CORE % {"name": "bad", "engine": "execute",
                                               "events": "\n    (events (wait NOPE) (send SEV_T))"}, "NOPE"),
                ("events on a trace-driven core", CORE % {"name": "bad", "engine": "trace", "events": CLAUSE},
                 "trace-driven")):
            (work / "bad.axisl").write_text(text[:end] + INSTRUCTIONS + bad + text[end:])
            checked = subprocess.run([*axis_prefix(), "check", str(work / "bad.axisl")], capture_output=True,
                                     text=True, cwd=AXIS_ROOT)
            if checked.returncode == 0 or needle not in checked.stdout + checked.stderr:
                failures.append(f"{label} was not refused")
    for f in failures:
        print(f"  FAIL {f}")
    for line in lines:
        print(f"  {line}")
    verdict = "PASS" if not failures else "FAIL"
    print(f"a wait for an event sleeps, and a send wakes it: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
