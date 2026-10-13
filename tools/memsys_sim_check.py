#!/usr/bin/env python3
"""The memory-system engine does what the contract says. Gate.

`src/emit/memsys_engine.c` is the C timing engine a simulator pack runs
against a described memory system; `tools/memsys_model.py` is a second
reading of the same contract, written separately and structured differently.
This compiles the engine with tables made from an `axis.memsys.v1` manifest,
runs the same address traces through both, and requires every access to cost
the same and every node to end with the same counters.

Over the example AND variants of it, because one configuration exercises one
branch of each policy: FIFO, PLRU and random replacement; write-through;
no-write-allocate; an exclusive L2; a closed page; torus, ring and crossbar
fabrics. The traces are chosen to reach what matters -- streams that overflow
each level, many lines into one set, both cores writing, the uncached window,
one DRAM row and then another in the same bank.

⚠️ And the comparison is shown to be able to fail: three mutants of the
engine -- a one-way trip, no row-buffer hit, FIFO stamps renewed on use, E granted
beside a sharer -- must each disagree with the model somewhere.

Usage: tools/memsys_sim_check.py [examples/memory_system.axisl]
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED, axis_prefix
from memsys_model import Model

AXIS_ROOT = Path(__file__).resolve().parent.parent
ENGINE = AXIS_ROOT / "src" / "emit" / "memsys_engine.c"

KIND = {"cache": 0, "dram": 1, "scratchpad": 2}
REPL = {"lru": 0, "plru": 1, "fifo": 2, "random": 3}
INCL = {"nine": 0, "inclusive": 1, "exclusive": 2}
TOPO = {"mesh": 0, "torus": 1, "ring": 2, "crossbar": 3}

#: Variants of the example, as literal edits: each switches on a branch the
#: example leaves off.
VARIANTS = {
    "as described": [],
    "fifo L1, random L2": [("(replacement lru)", "(replacement fifo)"), ("(replacement plru)", "(replacement random)")],
    "plru L1, lru L2": [("(replacement plru)", "(replacement lru)\n    (x-was-plru)"), ("(replacement lru)\n    (write-policy", "(replacement plru)\n    (write-policy"),
                        ("(replacement lru)\n    (x-was-plru)", "(replacement lru)")],
    "write-through, no-write-allocate L1, not coherent": [
        ("(write-policy write-back)\n    (allocate write-allocate)\n    (mshrs 4)",
         "(write-policy write-through)\n    (allocate no-write-allocate)\n    (mshrs 4)"),
        ("(protocol moesi)", "(protocol none)"), ("(region 0x0 0x80000000 ddr0 (home l2))", "(region 0x0 0x80000000 ddr0)")],
    "exclusive L2, not coherent": [("(inclusion inclusive)", "(inclusion exclusive)"), ("(protocol moesi)", "(protocol none)"),
                                   ("(region 0x0 0x80000000 ddr0 (home l2))", "(region 0x0 0x80000000 ddr0)")],
    "MSI": [("(protocol moesi)", "(protocol msi)")],
    "MESI": [("(protocol moesi)", "(protocol mesi)")],
    "not coherent": [("(protocol moesi)", "(protocol none)"), ("(region 0x0 0x80000000 ddr0 (home l2))", "(region 0x0 0x80000000 ddr0)")],
    "non-inclusive L2, no prefetch": [("(inclusion inclusive)\n    (prefetch next-line)\n    (prefetch-degree 1)", "(inclusion nine)")],
    "closed page": [("(page-policy open)", "(page-policy closed)")],
    "torus": [("(topology mesh (rows 3) (cols 3))", "(topology torus (rows 3) (cols 3))")],
    "ring": [("(topology mesh (rows 3) (cols 3))", "(topology ring (nodes 9))"),
             ("(at 1 1) (next ddr0)", "(at 4 0) (next ddr0)"), ("(ddr0 (memory ddr) (at 1 2))", "(ddr0 (memory ddr) (at 7 0))"),
             ("(spm0 (memory spm) (at 0 2))", "(spm0 (memory spm) (at 6 0))")],
    "crossbar": [("(topology mesh (rows 3) (cols 3))", "(topology crossbar (ports 9))"),
                 ("(at 1 1) (next ddr0)", "(at 4 0) (next ddr0)"), ("(ddr0 (memory ddr) (at 1 2))", "(ddr0 (memory ddr) (at 7 0))"),
                 ("(spm0 (memory spm) (at 0 2))", "(spm0 (memory spm) (at 6 0))")],
}

#: Engine mutants, as literal edits of the source; each must be caught.
MUTANTS = {
    "a one-way trip": ("return 2ull * axis_ms_hops", "return 1ull * axis_ms_hops"),
    "no row-buffer hit": ("else if (s->open_row[bank] == id) { dram = n->tcl;", "else if (s->open_row[bank] == id) { dram = n->trcd + n->tcl;"),
    "E granted beside sharers": ("(holders == 0 && protocol >= 2)", "(protocol >= 2)"),
    "FIFO renewed on use": ("if (n->replacement == AXIS_MS_LRU) s->stamp[slot] = ++ms->clock;",
                            "if (n->replacement == AXIS_MS_LRU || n->replacement == AXIS_MS_FIFO) s->stamp[slot] = ++ms->clock;"),
}


def c_string(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def tables(system: dict) -> str:
    """The engine's configuration for one system, from the manifest alone."""
    index = {n["name"]: i for i, n in enumerate(system["nodes"])}
    rows = []
    for n in system["nodes"]:
        d = n.get("dram", {})
        rows.append(
            "  {%s, %s, %d, %d, %du, %du, %du, %du, %du, %du, %d, %d, %d, %d, %du, %du, %du, %du, %du, %du, %du, %du}" % (
                c_string(n["name"]), c_string(n["core"]), KIND[n["kind"]],
                index[n["next"]] if n["next"] else -1, n["x"], n["y"], n["latency_cycles"],
                n.get("sets", 0), n.get("ways", 0), n.get("line_bytes", 0),
                REPL.get(n.get("replacement", "lru"), 0), INCL.get(n.get("inclusion", "nine"), 0),
                int(n.get("write_policy", "write-back") == "write-back"),
                int(n.get("allocate", "write-allocate") == "write-allocate"),
                n.get("prefetch_degree", 0) if n.get("prefetch") == "next-line" else 0,
                n.get("banks", 0), d.get("row_bytes", 0), int(d.get("page_policy") == "closed"),
                d.get("tck_ps", 0), d.get("tcl", 0), d.get("trcd", 0), d.get("trp", 0)))
    regions = ["  {%du, %du, %d, %d, %d}" % (r["base"], r["size"], index[r["target"]], int(r["uncached"]),
                                           index[r["home"]] if r["home"] else -1)
               for r in system["address_map"]]
    ic = system["interconnect"]
    return (f"static const axis_ms_node_cfg NODES[] = {{\n" + ",\n".join(rows) + "\n};\n"
            f"static const axis_ms_region_cfg REGIONS[] = {{\n" + ",\n".join(regions) + "\n};\n"
            f"static const axis_ms_system_cfg SYSTEM = {{{c_string(system['name'])}, {system['clock_ps']}u, "
            f"{TOPO[ic['topology']]}, {ic['cols']}u, {ic['rows']}u, {ic['hop_cycles']}u, {ic['router_cycles']}u, "
            f"{len(rows)}, NODES, {len(regions)}, REGIONS, "
            f"{ {'msi': 1, 'mesi': 2, 'moesi': 3}.get(system['coherence']['protocol'], 0)}}};\n")


DRIVER = r"""
#include <stdio.h>
int main(void) {
  axis_ms *ms = axis_ms_new(&SYSTEM);
  char core[64]; unsigned long long addr; int w;
  while (scanf("%63s %llx %d", core, &addr, &w) == 3) {
    printf("%llu\n", (unsigned long long)axis_ms_access(ms, axis_ms_port(ms, core), addr, w));
  }
  for (int32_t i = 0; i < SYSTEM.node_count; ++i) {
    const axis_ms_stats *s = axis_ms_stats_of(ms, i);
    printf("S %d %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n", i,
      (unsigned long long)s->hits, (unsigned long long)s->misses, (unsigned long long)s->writebacks,
      (unsigned long long)s->evictions, (unsigned long long)s->prefetches, (unsigned long long)s->back_invalidations,
      (unsigned long long)s->row_hits, (unsigned long long)s->row_idle, (unsigned long long)s->row_conflicts,
      (unsigned long long)s->accesses, (unsigned long long)s->forwards,
      (unsigned long long)s->invalidations, (unsigned long long)s->upgrades);
  }
  axis_ms_free(ms);
  return 0;
}
"""
STAT_FIELDS = ("hits", "misses", "writebacks", "evictions", "prefetches", "back_invalidations",
               "row_hits", "row_idle", "row_conflicts", "accesses", "forwards", "invalidations", "upgrades")


def traces(system: dict) -> dict[str, list[tuple[str, int, int]]]:
    """Address traces chosen to reach each mechanism."""
    cores = sorted(n["core"] for n in system["nodes"] if n["core"])
    l1 = next(n for n in system["nodes"] if n["core"])
    line, stride = l1["line_bytes"], l1["sets"] * l1["line_bytes"]
    cached = next(r for r in system["address_map"] if not r["uncached"])
    uncached = [r for r in system["address_map"] if r["uncached"]]
    base = cached["base"]
    rng = random.Random(1)
    out = {}
    # Many lines into ONE set: replacement decides everything.
    out["one set"] = [(cores[0], base + k * stride, 0) for k in (0, 1, 2, 3, 0, 4, 0, 5, 1, 6, 2, 0, 7, 8, 0, 3)] * 3
    # Streams larger than each level, read then written.
    out["streams"] = ([(cores[0], base + k * line, 0) for k in range(3000)]
                      + [(cores[0], base + k * line, 1) for k in range(0, 3000, 3)])
    # Both cores, random reads and writes over a working set twice the L2.
    out["mixed"] = [(rng.choice(cores), base + rng.randrange(0, 2 * 65536, 8), rng.randrange(2)) for _ in range(6000)]
    # DRAM rows: the same row, then another row in the same bank, then back.
    row = 8192 * 32
    out["rows"] = [(cores[1], base + a, 0) for a in
                   [0, 64, 128, row, row + 64, 0, 2 * row, 64 * 1024 * 1024, 0, row]] * 2
    if uncached:
        u = uncached[0]
        out["uncached"] = [(cores[k % 2], u["base"] + (k * 8) % u["size"], k % 3 == 0) for k in range(200)]
    out["unmapped"] = [(cores[0], (1 << 40) + k * 64, 0) for k in range(4)]
    # ⚠️ Both cores on the SAME few lines, reading and writing: the only
    # trace that makes lines change hands, so the only one that reaches a
    # forward, an upgrade and an invalidation.
    out["ping-pong"] = [(cores[k % 2], base + ((k // 2) % 6) * line + 8 * (k % 3), (k // 3) % 2)
                        for k in range(3000)]
    # ⚠️ A line whose only holders are SHARERS, read by a port that then
    # writes it: the one sequence that tells a granted E from a granted S --
    # silent from E, an upgrade from S. It needs the owner to have let the
    # line go: core 0 writes X, core 1 reads it, core 0 is made to evict it by
    # `ways` lines in its set, and then reads and writes it again.
    hand = []
    for k in range(40):
        x = base + 0x40000 + k * line
        hand += [(cores[0], x, 1), (cores[1], x, 0)]
        hand += [(cores[0], x + j * stride, 0) for j in range(1, l1["ways"] + 1)]
        hand += [(cores[0], x, 0), (cores[0], x, 1)]
    out["handover"] = hand
    return out


def run_engine(binary: Path, trace) -> tuple[list[int], dict]:
    text = "".join(f"{c} {a:x} {int(w)}\n" for c, a, w in trace)
    out = subprocess.run([str(binary)], input=text, capture_output=True, text=True, check=True).stdout.split("\n")
    costs = [int(x) for x in out if x and not x.startswith("S")]
    stats = {}
    for x in out:
        if x.startswith("S "):
            f = x.split()
            stats[int(f[1])] = dict(zip(STAT_FIELDS, map(int, f[2:])))
    return costs, stats


def run_model(system: dict, trace) -> tuple[list[int], dict]:
    m = Model(system)
    ports = {}
    costs = []
    for core, addr, w in trace:
        if core not in ports:
            ports[core] = m.port(core)
        costs.append(m.access(ports[core], addr, bool(w)))
    stats = {i: {k: getattr(m.stats(i), k) for k in STAT_FIELDS} for i in range(len(system["nodes"]))}
    stats["violations"] = m.violations
    return costs, stats


def build(work: Path, system: dict, source: str, name: str) -> Path:
    c = work / f"{name}.c"
    c.write_text(source + "\n" + tables(system) + DRIVER)
    binary = work / name
    subprocess.run(["cc", "-O1", "-o", str(binary), str(c)], check=True, capture_output=True)
    return binary


def compare(system: dict, binary: Path, label: str) -> tuple[list[str], int]:
    bad, checked = [], 0
    for name, trace in traces(system).items():
        ec, es = run_engine(binary, trace)
        mc, ms = run_model(system, trace)
        checked += len(trace)
        for k, (e, m) in enumerate(zip(ec, mc)):
            if e != m:
                c, a, w = trace[k]
                bad.append(f"{label} / {name}: access {k} ({c} {'W' if w else 'R'} {a:#x}) costs {e} in the engine, {m} in the model")
                break
        if ms.get("violations"):
            bad.append(f"{label} / {name}: the model saw {ms['violations']} single-writer violations")
        for i in es:
            if es[i] != ms[i]:
                diff = {f: (es[i][f], ms[i][f]) for f in STAT_FIELDS if es[i][f] != ms[i][f]}
                bad.append(f"{label} / {name}: node {system['nodes'][i]['name']} counters differ (engine, model): {diff}")
    return bad, checked


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path,
                        default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    if not shutil.which("cc"):
        print("  DECLINED no C compiler")
        return DECLINED
    source = ENGINE.read_text()
    text = args.axis_file.read_text()
    failures, accesses, variants = [], 0, 0
    reached = {"row_hits": 0, "row_conflicts": 0, "back_invalidations": 0, "writebacks": 0, "prefetches": 0,
               "forwards": 0, "invalidations": 0, "upgrades": 0}
    with tempfile.TemporaryDirectory(prefix="axis_memsim_") as work:
        work = Path(work)
        example_system = None
        for label, edits in VARIANTS.items():
            variant = text
            for old, new in edits:
                if variant.count(old) != 1:
                    failures.append(f"variant `{label}`: the edit anchor {old!r} is not in the example once")
                    break
                variant = variant.replace(old, new)
            path = work / "variant.axisl"
            path.write_text(variant)
            run = subprocess.run([*axis_prefix(), "emit-memsys-json", str(path)], capture_output=True,
                                 text=True, cwd=AXIS_ROOT)
            if run.returncode != 0:
                failures.append(f"variant `{label}` is refused: {run.stderr.strip()[:160]}")
                continue
            for system in json.loads(run.stdout)["systems"]:
                example_system = example_system or system
                binary = build(work, system, source, "engine")
                bad, n = compare(system, binary, label)
                failures += bad
                accesses += n
                variants += 1
                for trace in traces(system).values():
                    for s in run_engine(binary, trace)[1].values():
                        for k in reached:
                            reached[k] += s[k]
        # ⚠️ Vacuity: a mechanism no trace reached is one this gate says
        # nothing about, whatever it reports.
        for k, v in reached.items():
            if v == 0:
                failures.append(f"no trace reached `{k}`")
        if example_system:
            for what, (old, new) in MUTANTS.items():
                if source.count(old) != 1:
                    failures.append(f"mutant `{what}`: its anchor is not in the engine once")
                    continue
                binary = build(work, example_system, source.replace(old, new), "mutant")
                bad, _ = compare(example_system, binary, what)
                if not bad:
                    # The FIFO mutant needs FIFO: try it where FIFO is declared.
                    variant = text.replace("(replacement lru)", "(replacement fifo)")
                    path = work / "fifo.axisl"
                    path.write_text(variant)
                    fifo = json.loads(subprocess.run([*axis_prefix(), "emit-memsys-json", str(path)],
                                                     capture_output=True, text=True, cwd=AXIS_ROOT).stdout)["systems"][0]
                    bad, _ = compare(fifo, build(work, fifo, source.replace(old, new), "mutant"), what)
                if not bad:
                    failures.append(f"mutant `{what}` agreed with the model everywhere")
    for line in failures[:25]:
        print(f"  FAIL {line}")
    print(f"  {variants} configuration(s), {accesses} accesses, engine and model compared access by access; "
          f"reached {', '.join(f'{k}={v}' for k, v in reached.items())}; {len(MUTANTS)} engine mutants")
    verdict = "PASS" if not failures else "FAIL"
    print(f"memory-system engine == reference model: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
