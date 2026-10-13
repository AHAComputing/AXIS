#!/usr/bin/env python3
"""A load that reads what a store wrote waits for it. Gate.

Registers are not the only way one instruction waits for another. A load that
reads what an older store wrote depends on it THROUGH MEMORY, and a window
that let the load run first would be timing a value the program never had.
`(lsq ...)` on a `defcore` says how a machine orders the two
(docs/ooo_design.md, O1), and this gate holds each clause of it to a program
that only that clause can explain:

  * **a chain through memory costs its latencies.** Store, load the same
    word, compute from it, store again: nothing in that can overlap, so K
    rounds cannot finish in under (store + load + compute) x (K-1) however
    big the window. And a window with NO `lsq` goes under that floor --
    which is what "memory ordering is not modelled" means, said rather than
    hidden;
  * **perfect disambiguation passes a store it does not overlap; conservative
    does not.** A store whose value comes late, then loads from elsewhere: a
    machine that cannot know the addresses differ until the store executes
    waits, and one that knows (the trace does) does not. On the memory chain,
    where every load DOES overlap, the two must agree exactly;
  * **forwarding is from an executed store, not a retired one.** A store
    stuck behind a slow instruction at the head of the window, then a load of
    what it wrote: forwarding lets the load go as soon as the store executes,
    and a machine that does not forward waits for it to retire;
  * **a load straddling a store is not forwarded.** Half its bytes are the
    store's and half are memory's, so it waits for retirement even on a
    machine that forwards -- exactly what the machine that does not forward
    pays on the same program;
  * **the queues are backpressure.** Independent loads behind a slow head
    cost more on a machine that holds two in flight than on one that holds as
    many as the window, and the same for stores;
  * **the architecture is untouched**: every machine retires the same
    instructions and leaves the same registers and the same memory.

Usage: tools/lsq_check.py [corpus.axisl ...]
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

ENTRY = 0x200
#: Where the programs keep their data: far from the code, so no store can
#: rewrite an instruction and no load can read one.
DATA = 0x4000
#: Rounds of the memory chain, and independent accesses behind a slow head.
ROUNDS = 6
FANOUT = 8

HARNESS = r"""
#include <stdio.h>
#include <string.h>
#include "axis_pack.h"

extern const axis_sim_pack *%(sim)s(void);

#define IMAGE (1 << 16)
static uint8_t MEMORY[IMAGE];

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
static uint64_t on_trap(void *c, const char *cause, uint64_t pc, int32_t *stop) {
  (void)c; (void)cause; *stop = 1; return pc;
}

static void go(const char *tag, const char *core, const uint32_t *words,
               int32_t count) {
  const axis_sim_pack *S = %(sim)s();
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m) { printf("NOMACHINE\n"); return; }
  if (!S->select_core(m, core)) { printf("%%s NOCORE\n", tag); S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  }
  S->set_reg(m, %(base)d, %(data)du);
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)count);
  /* ⚠️ The register file AND the data: a timing model that let a load pass
     the store it reads would change a register, and one that reordered two
     stores would change memory. */
  uint64_t mark = 1469598103934665603ull;
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    uint64_t v = S->reg(m, i);
    for (uint32_t b = 0; b < 8; ++b) { mark ^= (v >> (8 * b)) & 0xFFu; mark *= 1099511628211ull; }
  }
  for (uint32_t a = %(data)du; a < %(data)du + 4096u; ++a) { mark ^= MEMORY[a]; mark *= 1099511628211ull; }
  printf("%%s cycles %%llu steps %%llu mark %%llu\n", tag,
         (unsigned long long)S->cycles(m), (unsigned long long)S->steps(m),
         (unsigned long long)mark);
  S->destroy(m);
}

/* A stand-in for a closed timing model: it keeps what it was handed about
   memory, so the gate can ask whether the addresses reached it at all. */
static int32_t SEEN_LOADS, SEEN_STORES;
static uint64_t FIRST_LO, FIRST_HI;
static uint64_t STANDIN;
static void *standin_create(const axis_sim_core *core) {
  (void)core; SEEN_LOADS = SEEN_STORES = 0; FIRST_LO = FIRST_HI = 0; return &STANDIN;
}
static void standin_destroy(void *state) { (void)state; }
static void standin_account(void *state, const axis_uarch_event *event) {
  (void)state;
  for (int32_t a = 0; a < event->access_count; ++a) {
    if (event->access_write[a]) {
      if (!SEEN_STORES++) { FIRST_LO = event->access_lo[a]; FIRST_HI = event->access_hi[a]; }
    } else { SEEN_LOADS++; }
  }
}
static uint64_t standin_cycles(const void *state) { (void)state; return 1u; }
static const char *standin_provenance(void) { return "modelled"; }

static void model_run(const char *core, const char *model, const uint32_t *words, int32_t count) {
  const axis_sim_pack *S = %(sim)s();
  static axis_uarch_pack standin;
  standin.abi_version = 1u; standin.name = model; standin.generator = "stand-in";
  standin.create = standin_create; standin.destroy = standin_destroy;
  standin.account = standin_account; standin.cycles = standin_cycles;
  standin.provenance = standin_provenance;
  if (!S->register_model || S->register_model(&standin) <= 0) { printf("MODEL none\n"); return; }
  memset(MEMORY, 0, sizeof MEMORY);
  for (int32_t i = 0; i < count; ++i) {
    for (uint32_t b = 0; b < 4; ++b) {
      MEMORY[%(entry)d + 4 * i + b] = (uint8_t)(words[i] >> (8 * b));
    }
  }
  axis_pack_sim_hooks hooks = { rd, wr, fetch, on_trap, NULL, NULL };
  void *m = S->create(&hooks);
  if (!m || !S->select_core(m, core)) { printf("MODEL noselect\n"); if (m) S->destroy(m); return; }
  S->reset(m, %(entry)du, %(isa)s, NULL, 0);
  for (int32_t i = 0; i < S->register_slots(); ++i) {
    S->set_reg(m, i, 0x11u * (uint64_t)(i + 1));
  }
  S->set_reg(m, %(base)d, %(data)du);
  S->count_cycles(m, 1);
  S->run(m, (uint64_t)count);
  printf("MODEL loads %%d stores %%d first %%llu %%llu\n", SEEN_LOADS, SEEN_STORES,
         (unsigned long long)FIRST_LO, (unsigned long long)FIRST_HI);
  S->destroy(m);
}

int main(void) {
  const axis_sim_pack *S = %(sim)s();
  if (!S->select_core) { printf("NOCORES\n"); return 0; }
%(programs)s
%(runs)s
%(extra)s
  return 0;
}
"""


def run_cmd(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True,
                          cwd=AXIS_ROOT, **kwargs)


def symbols(ast):
    """Every operand name an expression tree reads."""
    if isinstance(ast, dict):
        found = {ast["symbol"]} if "symbol" in ast else set()
        for arg in ast.get("args", []):
            found |= symbols(arg)
        return found
    return set()


class Assembler:
    """Words from the corpus's own instructions, with operands placed."""

    def __init__(self, lift, tests, latency_of):
        self.lift = lift
        self.by_mnemonic = {entry["mnemonic"]: entry for entry in lift.AXIS_LIFT_TABLE}
        self.tests = {test["mnemonic"]: test for test in tests}
        self.latency_of = latency_of
        self.load = self.store = None
        arithmetic = []
        for mnemonic, entry in self.by_mnemonic.items():
            if mnemonic not in self.tests:
                continue
            effects = entry.get("effects") or []
            regs_in = [o for o in entry["operands"]
                       if o["role"] == "in" and lift.is_register_operand(o["kind"])]
            outs = [o for o in entry["operands"] if o["role"] in ("out", "inout")]
            if (len(effects) == 1 and effects[0].get("kind") == "set"
                    and (effects[0].get("value_ast") or {}).get("op") == "load"
                    and len(outs) == 1 and len(regs_in) == 1
                    and effects[0].get("width") == 32 and self.load is None):
                address = symbols(effects[0]["value_ast"])
                self.load = (mnemonic, outs[0]["name"], regs_in[0]["name"],
                             next(o["name"] for o in entry["operands"]
                                  if o["name"] in address and o is not regs_in[0]
                                  and not lift.is_register_operand(o["kind"])))
            elif (len(effects) == 1 and effects[0].get("kind") == "store"
                  and effects[0].get("width") == 32 and len(regs_in) == 2
                  and not outs and self.store is None):
                address = symbols(effects[0]["addr_ast"])
                base = next(o["name"] for o in regs_in if o["name"] in address)
                value = next(o["name"] for o in regs_in if o["name"] != base)
                offset = next(o["name"] for o in entry["operands"]
                              if o["name"] in address
                              and not lift.is_register_operand(o["kind"]))
                self.store = (mnemonic, base, value, offset)
            elif not effects and len(outs) == 1 and len(regs_in) == 2:
                arithmetic.append(mnemonic)
        # An ADD specifically, to form an address from a base and an offset.
        self.fast_add = next((m for m in arithmetic
                              if (self.by_mnemonic[m].get("semantics_ast") or {}).get("op")
                              == "add"), None)
        cost = lambda m: self.latency_of.get(m, 1) or 1  # noqa: E731
        self.slow = max(arithmetic, key=cost) if arithmetic else None
        self.fast = min(arithmetic, key=cost) if arithmetic else None
        self.kind = None
        if self.load:
            entry = self.by_mnemonic[self.load[0]]
            self.kind = next(o["kind"] for o in entry["operands"] if o["name"] == self.load[1])

    def missing(self):
        if not self.load:
            return "no 32-bit load of one register from base + offset"
        if not self.store:
            return "no 32-bit store of one register to base + offset"
        if not self.fast_add:
            return "no two-register add to form an address with"
        if not self.slow or self.cost(self.slow) <= self.cost(self.fast):
            return "no arithmetic slower than another to hold a store up with"
        return None

    def cost(self, mnemonic):
        return self.latency_of.get(mnemonic, 1) or 1

    def _word(self, mnemonic, **operands):
        entry = self.by_mnemonic[mnemonic]
        word = int(self.tests[mnemonic]["encoded"], 16)
        for name, value in operands.items():
            word = self.lift.place_operand(word, entry, name, value)
        return word

    def op(self, mnemonic, dest, a, b):
        entry = self.by_mnemonic[mnemonic]
        out = next(o["name"] for o in entry["operands"] if o["role"] in ("out", "inout"))
        ins = [o["name"] for o in entry["operands"]
               if o["role"] == "in" and self.lift.is_register_operand(o["kind"])]
        return self._word(mnemonic, **{out: dest, ins[0]: a, ins[1]: b})

    def ld(self, dest, base, offset):
        mnemonic, out, reg, imm = self.load
        return self._word(mnemonic, **{out: dest, reg: base, imm: offset})

    def st(self, value, base, offset):
        mnemonic, reg, data, imm = self.store
        return self._word(mnemonic, **{data: value, reg: base, imm: offset})


BASE = 5


def build_programs(asm: Assembler):
    slow = asm.slow
    programs = {}
    # ⚠️ A CHAIN THROUGH MEMORY: each round stores a value, loads it back,
    # and computes the next value from what it loaded. The only thing linking
    # a store to the load after it is the address.
    chain = []
    for k in range(ROUNDS):
        chain.append(asm.st(6, BASE, 4 * k))
        chain.append(asm.ld(7, BASE, 4 * k))
        chain.append(asm.op(slow, 6, 7, 7))
    programs["CHAIN"] = chain
    # ⚠️ A store whose ADDRESS comes late, then a load that does NOT overlap
    # it. The address is the base plus a zero that two slow multiplies take
    # to produce (anything times the zero register), so a machine that cannot
    # see past an unresolved store address waits that long for no reason.
    #
    # ⚠️ And the loaded value FEEDS A CHAIN. Commit is in order, so loads that
    # merely finish early still retire behind the store and the program ends
    # at the same moment -- a first version measured one cycle between the
    # two machines. What an early load buys is an early start for whatever
    # waits on it, so something has to.
    def late(offset, late_address=True):
        if late_address:
            prefix = [asm.op(slow, 12, 1, 0), asm.op(slow, 12, 12, 12),
                      asm.op(asm.fast_add, 10, BASE, 12), asm.st(2, 10, 64)]
        else:
            # The VALUE late and the address ready: every store here computes
            # its address from the base alone.
            prefix = [asm.op(slow, 10, 1, 1), asm.op(slow, 10, 10, 10),
                      asm.op(slow, 10, 10, 10), asm.st(10, BASE, 64)]
        return prefix + [asm.ld(11, BASE, offset)] + [asm.op(slow, 11, 11, 11) for _ in range(3)]
    programs["DISJOINT"] = late(256)
    # ⚠️ A late VALUE does not hide an early ADDRESS (O4). The store computes
    # where it writes from a register that is ready; only what it writes is
    # late. A conservative machine knows the load misses it and must cost
    # exactly what the oracle costs -- before the split, a store published
    # its address only when its value arrived, and conservative paid for that.
    programs["LATEDATA"] = late(256, late_address=False)
    # ⚠️ The words TOUCHING the store's, one on each side. Disjoint by a byte
    # is disjoint: a model that counted a shared edge as an overlap passed
    # every other program here, because none of them put a load next to a
    # store -- mutation testing said so.
    programs["BELOW"] = late(60)
    programs["ABOVE"] = late(68)
    # ⚠️ FORWARDING: a slow chain at the head keeps everything behind it from
    # retiring; a store that needs none of it executes at once, and a load of
    # what it wrote can take the value from it -- or wait for it to retire.
    head = [asm.op(slow, 10, 1, 1), asm.op(slow, 10, 10, 10), asm.op(slow, 10, 10, 10),
            asm.op(slow, 10, 10, 10)]
    tail = [asm.op(slow, 12, 12, 12) for _ in range(3)]
    programs["FORWARD"] = head + [asm.st(2, BASE, 64), asm.ld(12, BASE, 64)] + tail
    # And the same with the load straddling the store: half its bytes are the
    # store's and half are memory's.
    programs["STRADDLE"] = head + [asm.st(2, BASE, 64), asm.ld(12, BASE, 66)] + tail
    # ⚠️ QUEUES: independent accesses behind the same slow head. Nothing
    # retires until the head does, so a machine's loads-in-flight bound is
    # what decides how many of them start early.
    programs["LOADS"] = head + [asm.ld(11 + k, BASE, 512 + 4 * k) for k in range(FANOUT)]
    programs["STORES"] = head + [asm.st(2, BASE, 1024 + 4 * k) for k in range(FANOUT)]
    return programs


def pick(cores, **want):
    """The core whose lsq clause says exactly this."""
    for core in cores:
        lsq = core.get("lsq")
        if lsq is None:
            continue
        if all((lsq.get(key) or 0) == value if key in ("loads", "stores")
               else lsq.get(key) == value for key, value in want.items()):
            return core
    return None


def check(axis_file: Path, work: Path) -> tuple[int, int]:
    manifest = build_pack.build(axis_file, work / "packs", only={"sim", "exec", "lift"})
    name = manifest["name"]
    if "sim" not in manifest["libraries"]:
        print(f"  {name}: DECLINED no simulator library")
        return 0, 0
    facts = json.loads(run_cmd([*axis_prefix(), "emit-json", str(axis_file)]).stdout)
    cores = facts.get("cores", [])
    conservative = pick(cores, disambiguation="conservative", forwarding=True, loads=0, stores=0)
    perfect = pick(cores, disambiguation="perfect", forwarding=True, loads=0, stores=0)
    unforwarded = pick(cores, disambiguation="perfect", forwarding=False, loads=0, stores=0)
    tight = next((core for core in cores if core.get("lsq")
                  and core["lsq"].get("loads") and core["lsq"].get("stores")
                  and core["lsq"].get("disambiguation") == "perfect"
                  and core["lsq"].get("forwarding")), None)
    unordered = next((core for core in cores if core.get("rob") and core.get("lsq") is None
                      and not core.get("rename") and not core.get("model")), None)
    # A core timed by somebody else's model, to hand a stand-in the events.
    closed = next((core for core in cores if core.get("model")), None)
    missing = [label for label, core in (("conservative", conservative), ("perfect", perfect),
                                         ("no-forwarding", unforwarded), ("bounded-queue", tight),
                                         ("windowed without an lsq", unordered))
               if core is None]
    if missing:
        print(f"  {name}: DECLINED no {', '.join(missing)} core to compare")
        return 0, 0

    module = f"lsq_{name}"
    run_cmd([*axis_prefix(), "emit-lift-python", str(axis_file), "-o", str(work / f"{module}.py")])
    sys.path.insert(0, str(work))
    lift = importlib.import_module(module)
    tests = json.loads(run_cmd([*axis_prefix(), "emit-roundtrip-json",
                                str(axis_file)]).stdout)["tests"]
    latency_of = {entry["mnemonic"]: entry.get("latency_cycles", 1)
                  for entry in facts["instructions"]}
    asm = Assembler(lift, tests, latency_of)
    why = asm.missing()
    if why:
        sys.modules.pop(module, None)
        print(f"  {name}: DECLINED {why}")
        return 0, 0
    programs = build_programs(asm)
    base_slot = lift.register_slot(asm.kind, BASE)
    isa = next((test.get("isa") for test in tests if test["mnemonic"] == asm.load[0]), "") or ""
    sys.modules.pop(module, None)

    machines = {"CONS": conservative, "PERF": perfect, "NOFW": unforwarded,
                "TIGHT": tight, "NONE": unordered}
    runs = []
    for program in programs:
        for tag, core in machines.items():
            runs.append(f'  go("{program}_{tag}", "{core["name"]}", {program}, '
                        f'(int32_t)(sizeof {program} / sizeof {program}[0]));')
    source = HARNESS % {
        "sim": manifest["libraries"]["sim"]["entry"],
        "entry": ENTRY,
        "data": DATA,
        "base": base_slot,
        "isa": f'"{isa}"' if isa else "NULL",
        "programs": "\n".join(
            f"  static const uint32_t {label}[] = {{ {', '.join(f'{w}u' for w in words)} }};"
            for label, words in programs.items()),
        "runs": "\n".join(runs),
        "extra": (f'  model_run("{closed["name"]}", "{closed["model"]}", CHAIN, '
                  f'(int32_t)(sizeof CHAIN / sizeof CHAIN[0]));' if closed else ""),
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

    said = {}
    for line in done.stdout.splitlines():
        parts = line.split()
        if len(parts) == 7 and parts[1] == "cycles":
            said[parts[0]] = (int(parts[2]), int(parts[4]), int(parts[6]))

    checks = failures = 0

    def fail(message):
        nonlocal failures
        print(f"  FAIL {name}: {message}")
        failures += 1

    for program, words in programs.items():
        for tag in machines:
            checks += 1
            row = said.get(f"{program}_{tag}")
            if row is None:
                fail(f"{program} on {machines[tag]['name']} reported nothing")
            elif row[1] != len(words):
                fail(f"{program} on {machines[tag]['name']} retired {row[1]} of {len(words)}")
        checks += 1
        marks = {said[f"{program}_{tag}"][2] for tag in machines if f"{program}_{tag}" in said}
        if len(marks) > 1:
            fail(f"{program} left different registers or memory on different machines; "
                 f"a timing model reordered the architecture")
    if failures:
        return checks, failures

    # ⚠️ THE ADDRESSES REACH A CLOSED MODEL. The event a model is handed
    # promises everything the built-in pipeline reads, and the pipeline now
    # reads what each instruction touched; a model with a load/store queue of
    # its own could not be built on an event that left them out.
    if closed:
        row = next((line.split() for line in done.stdout.splitlines()
                    if line.startswith("MODEL")), None)
        checks += 1
        want = ["MODEL", "loads", str(ROUNDS), "stores", str(ROUNDS), "first",
                str(DATA), str(DATA + 4)]
        if row != want:
            fail(f"a stand-in model timing `{closed['name']}` was handed "
                 f"{' '.join(row) if row else 'nothing'} for {ROUNDS} stores and {ROUNDS} "
                 f"loads, the first store at [{DATA}, {DATA + 4})")

    cyc = {key: row[0] for key, row in said.items()}
    store_l, load_l, slow_l = (asm.cost(asm.store[0]), asm.cost(asm.load[0]), asm.cost(asm.slow))

    # ⚠️ THE FLOOR. Every round waits for the one before it through memory.
    floor = (store_l + load_l + slow_l) * (ROUNDS - 1)
    for tag in ("CONS", "PERF", "NOFW", "TIGHT"):
        checks += 1
        if cyc[f"CHAIN_{tag}"] < floor:
            fail(f"{ROUNDS} rounds of store/load/{asm.slow} through one address cannot "
                 f"finish under {floor} cycles on {machines[tag]['name']}, which reported "
                 f"{cyc[f'CHAIN_{tag}']}; a load ran before the store it reads")
    # And a window with no lsq DOES go under it: memory ordering not modelled,
    # which is what a core that never declared one has always meant.
    checks += 1
    if cyc["CHAIN_NONE"] >= floor:
        fail(f"a core with no `lsq` reported {cyc['CHAIN_NONE']} on the memory chain, at "
             f"or above its floor of {floor}; an undeclared lsq is supposed to leave "
             f"memory ordering unmodelled, and this one is ordering something")
    # Every load in the chain overlaps its store, so knowing the addresses buys
    # nothing there -- exactly.
    checks += 1
    if cyc["CHAIN_CONS"] != cyc["CHAIN_PERF"]:
        fail(f"on a chain where every load overlaps the store before it, conservative "
             f"cost {cyc['CHAIN_CONS']} and perfect {cyc['CHAIN_PERF']}; there is nothing "
             f"for disambiguation to find")

    # ⚠️ DISAMBIGUATION: loads that overlap nothing pass a late store only on
    # a machine that knows they overlap nothing.
    checks += 1
    if cyc["DISJOINT_PERF"] >= cyc["DISJOINT_CONS"]:
        fail(f"a load disjoint from a late store, and a chain on it, cost {cyc['DISJOINT_PERF']} with "
             f"perfect disambiguation and {cyc['DISJOINT_CONS']} conservative; knowing "
             f"the addresses differ has to let them go first")

    for program in ("BELOW", "ABOVE"):
        checks += 1
        if cyc[f"{program}_PERF"] != cyc["DISJOINT_PERF"]:
            fail(f"a load of the word {'below' if program == 'BELOW' else 'above'} a late "
                 f"store cost {cyc[f'{program}_PERF']} with perfect disambiguation and one "
                 f"far from it {cyc['DISJOINT_PERF']}; touching is not overlapping")

    checks += 1
    if cyc["LATEDATA_CONS"] != cyc["LATEDATA_PERF"]:
        fail(f"a load that misses a store whose VALUE is late but whose address is "
             f"ready cost {cyc['LATEDATA_CONS']} conservative and {cyc['LATEDATA_PERF']} "
             f"perfect; the address was known, so conservative knew it missed")

    # ⚠️ FORWARDING: from an executed store, not a retired one.
    checks += 1
    if cyc["FORWARD_PERF"] >= cyc["FORWARD_NOFW"]:
        fail(f"a load of a store stuck behind a slow head cost {cyc['FORWARD_PERF']} "
             f"forwarded and {cyc['FORWARD_NOFW']} not; forwarding that does not beat "
             f"waiting for retirement is not forwarding")
    # ⚠️ A STRADDLE is not forwarded, even by a machine that forwards -- it
    # pays what the machine that does not forward pays, exactly.
    checks += 1
    if cyc["STRADDLE_PERF"] != cyc["STRADDLE_NOFW"]:
        fail(f"a load straddling a store cost {cyc['STRADDLE_PERF']} on a forwarding "
             f"machine and {cyc['STRADDLE_NOFW']} on one that does not; half its bytes "
             f"are not the store's, so neither can forward it")
    checks += 1
    if cyc["STRADDLE_PERF"] <= cyc["FORWARD_PERF"]:
        fail(f"a straddling load cost {cyc['STRADDLE_PERF']} and a covered one "
             f"{cyc['FORWARD_PERF']} on the forwarding machine; the straddle was forwarded")

    # ⚠️ THE QUEUES are backpressure.
    for program, which in (("LOADS", "loads"), ("STORES", "stores")):
        checks += 1
        if cyc[f"{program}_TIGHT"] <= cyc[f"{program}_PERF"]:
            fail(f"{FANOUT} independent {which} behind a slow head cost "
                 f"{cyc[f'{program}_TIGHT']} holding {tight['lsq'][which]} in flight and "
                 f"{cyc[f'{program}_PERF']} holding the window; the {which} queue is not "
                 f"being read")

    if not failures:
        print(f"  {name}: memory chain {cyc['CHAIN_PERF']} (floor {floor}, "
              f"{cyc['CHAIN_NONE']} unordered); disjoint loads {cyc['DISJOINT_PERF']} perfect "
              f"vs {cyc['DISJOINT_CONS']} conservative; forwarded {cyc['FORWARD_PERF']} vs "
              f"{cyc['FORWARD_NOFW']} at retire, straddle {cyc['STRADDLE_PERF']}; queues "
              f"{cyc['LOADS_TIGHT']}/{cyc['LOADS_PERF']} loads, "
              f"{cyc['STORES_TIGHT']}/{cyc['STORES_PERF']} stores; {checks} checks")
    return checks, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", nargs="*", type=Path)
    args = parser.parse_args()
    corpora = args.corpora or [AXIS_ROOT / "examples" / "issue_width.axisl"]
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
        print("a load waits for the store it reads: SKIP")
        return DECLINED
    print(f"a load waits for the store it reads: "
          f"{'FAIL' if failures else 'PASS'} ({checks} checks, {failures} failure(s))")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
