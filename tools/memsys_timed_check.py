#!/usr/bin/env python3
"""Timed memory-system accesses (U1): engine == reference reading. Gate.

`axis_ms_access_at` (src/emit/memsys_engine.c, TIMED ACCESSES) answers when an
access completes: lines in flight, MSHRs, DRAM banks and channel buses, and
next-line, stride and best-offset prefetching. `tools/memsys_timed_model.py`
reads the same contract in absolute time. This gate runs both over traces
of (core, address, write, cycle, key, first) and requires every completion
cycle and every counter, the timed ones included, to agree.

Three more things it requires:
  * THE INVARIANT. With nothing contending -- accesses far apart, no
    prefetcher -- a timed access completes exactly the untimed cost after it
    starts, so timing adds only waiting.
  * VACUITY. Every timed mechanism is reached by some trace.
  * MUTANTS. Seven literal edits of the engine (the bus at the start of an
    access, no fill wait, an MSHR freed at the miss, a prefetch that waits
    with no room in its queue, the queue ignored, a store not counted as a
    use of a prefetched line, best-offset ignoring timeliness) are each
    caught, on the configuration with a queue.

Usage: tools/memsys_timed_check.py [examples/memory_system.axisl]
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
from memsys_sim_check import INCL, KIND, REPL, STAT_FIELDS, TOPO, c_string
from memsys_timed_model import TIMED_STATS, TimedModel

AXIS_ROOT = Path(__file__).resolve().parent.parent
ENGINE = AXIS_ROOT / "src" / "emit" / "memsys_engine.c"

NOT_COHERENT = [("(protocol moesi)", "(protocol none)"), ("(region 0x0 0x80000000 ddr0 (home l2))", "(region 0x0 0x80000000 ddr0)")]
L1_POLICY = "(write-policy write-back)\n    (allocate write-allocate)\n    (mshrs 4)"
L2_PREFETCH = "(inclusion inclusive)\n    (prefetch next-line)\n    (prefetch-degree 1)"
#: Configurations, as literal edits of the example. Coherent ports may not
#: prefetch, and coherent regions are untimed, so most are not coherent.
VARIANTS = {
    "next-line L2, 4 MSHRs": NOT_COHERENT,
    "stride L1": NOT_COHERENT + [(L1_POLICY, L1_POLICY + "\n    (prefetch stride)\n    (prefetch-degree 2)")],
    "stride and best-offset L1, 2 MSHRs": NOT_COHERENT + [
        (L1_POLICY, L1_POLICY.replace("(mshrs 4)", "(mshrs 2)") + "\n    (prefetch stride best-offset)\n    (prefetch-degree 2)")],
    "stride and best-offset L1, 2 MSHRs, a queue of 3": NOT_COHERENT + [
        (L1_POLICY, L1_POLICY.replace("(mshrs 4)", "(mshrs 2)") + "\n    (prefetch stride best-offset)\n    (prefetch-degree 2)\n    (prefetch-queue 3)")],
    "best-offset L2, exclusive": NOT_COHERENT + [
        (L2_PREFETCH, "(inclusion exclusive)\n    (prefetch best-offset)\n    (prefetch-degree 1)\n    (mshrs 8)")],
    "two channels, narrow bus, closed page": NOT_COHERENT + [("(page-policy open)", "(page-policy closed)\n    (channels 2)\n    (bus-bytes 4)")],
    "write-through, no-write-allocate L1": NOT_COHERENT + [(L1_POLICY, L1_POLICY.replace("write-back", "write-through").replace("write-allocate", "no-write-allocate"))],
    "coherent, as described": [],
}
#: The invariant's configuration: nothing prefetches.
QUIET = NOT_COHERENT + [(L2_PREFETCH, "(inclusion nine)")]

MUTANTS = {
    "the bus at the start of an access": ("uint64_t done = ms->t0 + *cost, xfer = done - (done - start >= burst ? burst : done - start);",
                                          "uint64_t done = ms->t0 + *cost, xfer = start; (void)done;"),
    "no fill wait": ("      if (s->ready[slot] > ms->t0 + *cost) {\n        /* In flight",
                     "      if (0 && s->ready[slot] > ms->t0 + *cost) {\n        /* In flight"),
    "an MSHR freed at the miss": ("if (mshr >= 0) s->mshr_free[mshr] = s->ready[slot];", "if (mshr >= 0) s->mshr_free[mshr] = miss_at;"),
    "a prefetch waits with no room in the queue": ("      if (q < 0) { s->stats.prefetch_dropped++; return 0; }",
                                                   "      if (q < 0) { s->stats.prefetch_dropped++; q = 0; }"),
    "the prefetch queue ignored": ("      for (uint32_t k = 0; k < n->prefetch_queue; ++k) if (s->pq[k] <= at) { q = (int32_t)k; break; }",
                                   "      for (uint32_t k = 0; k < 0; ++k) if (s->pq[k] <= at) { q = (int32_t)k; break; }"),
    "a store not a use of a prefetch": ("      if (s->pf[slot]) {\n        s->pf[slot] = 0;\n        s->stats.prefetch_useful++;\n        if (n->prefetch_kinds & AXIS_MS_PF_BOP) axis_ms_bop_trigger(ms, port, line, g->target, ms->t0);",
                                       "      if (0 && s->pf[slot]) {\n        s->pf[slot] = 0;\n        s->stats.prefetch_useful++;\n        if (n->prefetch_kinds & AXIS_MS_PF_BOP) axis_ms_bop_trigger(ms, port, line, g->target, ms->t0);"),
    "best-offset blind to timeliness": ("if (s->bop_line[k] == base + 1 && s->bop_ready[k] <= now) ++s->bop_score[s->bop_test];",
                                        "if (s->bop_line[k] == base + 1) ++s->bop_score[s->bop_test];"),
}


def tables(system: dict) -> str:
    """The engine's configuration from the manifest, with the timed fields."""
    index = {n["name"]: i for i, n in enumerate(system["nodes"])}
    rows = []
    for n in system["nodes"]:
        d = n.get("dram", {})
        kinds = set(n.get("prefetch", "").split())
        bits = int("next-line" in kinds) | int("stride" in kinds) << 1 | int("best-offset" in kinds) << 2
        rows.append(
            "  {%s, %s, %d, %d, %du, %du, %du, %du, %du, %du, %d, %d, %d, %d, %du, %du, %du, %du, %du, %du, %du, %du, %du, %du, %du, %du, %du, %du}" % (
                c_string(n["name"]), c_string(n["core"]), KIND[n["kind"]],
                index[n["next"]] if n["next"] else -1, n["x"], n["y"], n["latency_cycles"],
                n.get("sets", 0), n.get("ways", 0), n.get("line_bytes", 0),
                REPL.get(n.get("replacement", "lru"), 0), INCL.get(n.get("inclusion", "nine"), 0),
                int(n.get("write_policy", "write-back") == "write-back"),
                int(n.get("allocate", "write-allocate") == "write-allocate"),
                n.get("prefetch_degree", 0) if "next-line" in kinds else 0,
                n.get("banks", 0), d.get("row_bytes", 0), int(d.get("page_policy") == "closed"),
                d.get("tck_ps", 0), d.get("tcl", 0), d.get("trcd", 0), d.get("trp", 0),
                n.get("mshrs", 0), bits, max(n.get("prefetch_degree", 0), 1) if kinds else 0,
                max(d.get("channels", 1), 1), d.get("bus_bytes", 8), n.get("prefetch_queue", 0)))
    regions = ["  {%du, %du, %d, %d, %d}" % (r["base"], r["size"], index[r["target"]], int(r["uncached"]),
                                           index[r["home"]] if r["home"] else -1)
               for r in system["address_map"]]
    ic = system["interconnect"]
    protocol = {"msi": 1, "mesi": 2, "moesi": 3}.get(system["coherence"]["protocol"], 0)
    return (f"static const axis_ms_node_cfg NODES[] = {{\n" + ",\n".join(rows) + "\n};\n"
            f"static const axis_ms_region_cfg REGIONS[] = {{\n" + ",\n".join(regions) + "\n};\n"
            f"static const axis_ms_system_cfg SYSTEM = {{{c_string(system['name'])}, {system['clock_ps']}u, "
            f"{TOPO[ic['topology']]}, {ic['cols']}u, {ic['rows']}u, {ic['hop_cycles']}u, {ic['router_cycles']}u, "
            f"{len(rows)}, NODES, {len(regions)}, REGIONS, {protocol}}};\n")


DRIVER = r"""
#include <stdio.h>
int main(int argc, char **argv) {
  int untimed = argc > 1;
  axis_ms *ms = axis_ms_new(&SYSTEM);
  char core[64]; unsigned long long addr, t, key; int w, first;
  while (scanf("%63s %llx %d %llu %llu %d", core, &addr, &w, &t, &key, &first) == 6) {
    int32_t port = axis_ms_port(ms, core);
    unsigned long long done = untimed ? t + axis_ms_access(ms, port, addr, w)
                                      : axis_ms_access_at(ms, port, addr, w, t, key, first);
    printf("%llu\n", done);
  }
  for (int32_t i = 0; i < SYSTEM.node_count; ++i) {
    const axis_ms_stats *s = axis_ms_stats_of(ms, i);
    printf("S %d %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n", i,
      (unsigned long long)s->hits, (unsigned long long)s->misses, (unsigned long long)s->writebacks,
      (unsigned long long)s->evictions, (unsigned long long)s->prefetches, (unsigned long long)s->back_invalidations,
      (unsigned long long)s->row_hits, (unsigned long long)s->row_idle, (unsigned long long)s->row_conflicts,
      (unsigned long long)s->accesses, (unsigned long long)s->forwards,
      (unsigned long long)s->invalidations, (unsigned long long)s->upgrades,
      (unsigned long long)s->fill_waits, (unsigned long long)s->mshr_waits, (unsigned long long)s->bank_waits,
      (unsigned long long)s->bus_waits, (unsigned long long)s->prefetch_useful, (unsigned long long)s->prefetch_dropped,
      (unsigned long long)s->bop_offset, (unsigned long long)s->bop_rounds);
  }
  axis_ms_free(ms);
  return 0;
}
"""
FIELDS = STAT_FIELDS + TIMED_STATS


def traces(system: dict) -> dict[str, list[tuple]]:
    cores = sorted(n["core"] for n in system["nodes"] if n["core"])
    l1 = next(n for n in system["nodes"] if n["core"])
    line = l1["line_bytes"]
    base = next(r for r in system["address_map"] if not r["uncached"])["base"]
    rng = random.Random(7)
    out = {}
    # Many misses at one cycle: MSHRs, banks and the bus contend.
    out["burst"] = [(cores[0], base + 0x100000 + k * 4096 * 3, 0, 1000 + (k // 16) * 40, 0, 1) for k in range(160)]
    # A line touched again while its fill is on the way.
    out["in flight"] = [(cores[k % 2], base + 0x200000 + (k // 4) * line, k % 5 == 0, 5000 + k, 0, 1) for k in range(400)]
    # A stream, a line every few cycles: next-line and best-offset learn it.
    out["stream"] = [(cores[0], base + 0x300000 + k * line, 0, 10000 + 3 * k, 0x40, 1) for k in range(3000)]
    # A long stream a line a cycle: with memory a hundred-odd cycles away only
    # a large offset is timely, which is what best-offset must learn -- and
    # learning takes phases of up to 27 x 100 triggers.
    out["fast stream"] = [(cores[0], base + 0x2000000 + k * line, 0, 120000 + k, 0x41, 1) for k in range(12000)]
    # A stream of STORES: the first use of a prefetched line is a store's.
    out["store stream"] = [(cores[1], base + 0x3000000 + k * line, 1, 400000 + 2 * k, 0x42, 1) for k in range(3000)]
    # Requests of four lines from one pc, three lines apart: stride trains on
    # each request's first line and fires for all four.
    st = []
    for r in range(400):
        for j in range(4):
            st.append((cores[1], base + 0x800000 + (r * 12 + j) * line, 0, 40000 + 6 * r, 0x99, int(j == 0)))
    out["strided requests"] = st
    # Random, two cores, sometimes several at one cycle.
    t, mixed = 60000, []
    for _ in range(5000):
        t += rng.choice((0, 0, 1, 3, 20))
        mixed.append((rng.choice(cores), base + rng.randrange(0, 4 * 65536, 8), rng.randrange(2), t,
                      rng.choice((0, 0x10, 0x20)), rng.randrange(2)))
    out["mixed"] = mixed
    # DRAM: one bank, rows alternating, back to back.
    row = 8192 * 32
    out["rows"] = [(cores[1], base + 0x1000000 + (k % 2) * row + (k // 2) * line, 0, 90000 + k, 0, 1) for k in range(64)]
    return out


def run_engine(binary: Path, trace, untimed: bool = False):
    text = "".join(f"{c} {a:x} {int(w)} {t} {key} {f}\n" for c, a, w, t, key, f in trace)
    args = [str(binary)] + (["untimed"] if untimed else [])
    out = subprocess.run(args, input=text, capture_output=True, text=True, check=True).stdout.split("\n")
    done = [int(x) for x in out if x and not x.startswith("S")]
    stats = {}
    for x in out:
        if x.startswith("S "):
            f = x.split()
            stats[int(f[1])] = dict(zip(FIELDS, map(int, f[2:])))
    return done, stats


def run_model(system: dict, trace):
    m = TimedModel(system)
    ports, done = {}, []
    for c, a, w, t, key, f in trace:
        ports.setdefault(c, m.port(c))
        done.append(m.access_at(ports[c], a, bool(w), t, key, bool(f)))
    stats = {}
    for i in range(len(system["nodes"])):
        s = {k: getattr(m.stats(i), k) for k in STAT_FIELDS}
        s.update(m.timed_stats(i))
        stats[i] = s
    return done, stats


def build(work: Path, system: dict, source: str, name: str) -> Path:
    c = work / f"{name}.c"
    c.write_text(source + "\n" + tables(system) + DRIVER)
    binary = work / name
    subprocess.run(["cc", "-O1", "-o", str(binary), str(c)], check=True, capture_output=True)
    return binary


def compare(system: dict, binary: Path, label: str):
    bad, checked = [], 0
    for name, trace in traces(system).items():
        ed, es = run_engine(binary, trace)
        md, ms = run_model(system, trace)
        checked += len(trace)
        for k, (e, m) in enumerate(zip(ed, md)):
            if e != m:
                c, a, w, t, key, f = trace[k]
                bad.append(f"{label} / {name}: access {k} ({c} {'W' if w else 'R'} {a:#x} at {t}) done at {e} in the engine, {m} in the model")
                break
        for i in es:
            if es[i] != ms[i]:
                diff = {f: (es[i][f], ms[i][f]) for f in FIELDS if es[i][f] != ms[i][f]}
                bad.append(f"{label} / {name}: node {system['nodes'][i]['name']} counters differ (engine, model): {diff}")
    return bad, checked


def system_of(text: str, edits, work: Path, failures: list, label: str):
    for old, new in edits:
        if text.count(old) != 1:
            failures.append(f"variant `{label}`: the anchor {old!r} is not in the example once")
            return None
        text = text.replace(old, new)
    path = work / "variant.axisl"
    path.write_text(text)
    run = subprocess.run([*axis_prefix(), "emit-memsys-json", str(path)], capture_output=True, text=True, cwd=AXIS_ROOT)
    if run.returncode != 0:
        failures.append(f"variant `{label}` is refused: {run.stderr.strip()[:200]}")
        return None
    return json.loads(run.stdout)["systems"][0]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path, default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    if not shutil.which("cc"):
        print("  DECLINED no C compiler")
        return DECLINED
    source = ENGINE.read_text()
    text = args.axis_file.read_text()
    failures, accesses, configs = [], 0, 0
    reached = {k: 0 for k in ("fill_waits", "mshr_waits", "bank_waits", "bus_waits", "prefetches",
                              "prefetch_useful", "prefetch_dropped", "bop_rounds")}
    with tempfile.TemporaryDirectory(prefix="axis_memtimed_") as work:
        work = Path(work)
        stride_system = None
        for label, edits in VARIANTS.items():
            system = system_of(text, edits, work, failures, label)
            if system is None:
                continue
            if label.startswith("stride and best-offset") and "queue" in label:
                stride_system = system
            binary = build(work, system, source, "engine")
            bad, n = compare(system, binary, label)
            failures += bad
            accesses += n
            configs += 1
            for trace in traces(system).values():
                for s in run_engine(binary, trace)[1].values():
                    for k in reached:
                        reached[k] += s[k]
        # THE INVARIANT: far apart and with no prefetcher, timed == untimed.
        quiet = system_of(text, QUIET, work, failures, "quiet")
        if quiet is not None:
            binary = build(work, quiet, source, "quiet")
            spaced = [(c, a, w, k * 100000, 0, 1) for k, (c, a, w, _, _, _) in enumerate(traces(quiet)["mixed"][:2000])]
            timed, _ = run_engine(binary, spaced)
            untimed, _ = run_engine(binary, spaced, untimed=True)
            for k, (x, y) in enumerate(zip(timed, untimed)):
                if x != y:
                    failures.append(f"invariant: uncontended access {k} completes at {x} timed, {y} untimed")
                    break
        for k, v in reached.items():
            if v == 0:
                failures.append(f"no trace reached `{k}`")
        if stride_system is not None:
            for what, (old, new) in MUTANTS.items():
                if source.count(old) != 1:
                    failures.append(f"mutant `{what}`: its anchor is not in the engine once")
                    continue
                caught = False
                for system in (stride_system,):
                    bad, _ = compare(system, build(work, system, source.replace(old, new), "mutant"), what)
                    caught |= bool(bad)
                if not caught:
                    failures.append(f"mutant `{what}` agreed with the model everywhere")
    for line in failures[:25]:
        print(f"  FAIL {line}")
    print(f"  {configs} configuration(s), {accesses} timed accesses compared cycle by cycle; reached "
          f"{', '.join(f'{k}={v}' for k, v in reached.items())}; the uncontended invariant over 2000 accesses; "
          f"{len(MUTANTS)} engine mutants")
    verdict = "PASS" if not failures else "FAIL"
    print(f"timed memory-system engine == reference reading: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
