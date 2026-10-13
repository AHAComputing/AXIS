#!/usr/bin/env python3
"""A memory system's manifest says what its description says. Gate.

`emit-memsys-json` publishes each `defmemsys` RESOLVED -- node ids, hop counts,
each core's path to memory, set counts, the address map's target and home ids,
every default made explicit -- so that no consumer re-derives a decision the
description already made. That is only worth anything if the resolution is
right, and it cannot be checked by reading the manifest back against itself.

So this reads the description a second way: a small s-expression reader here,
the arithmetic written again from `docs/memory_system_design.md` (a node's id
is `y * cols + x`; a mesh hop count is Manhattan distance, a torus and a ring
take the short way round, a crossbar is one hop), and compares every resolved
field.

And the validation is held rule by rule: each refusal in the design is made to
happen, once, by a one-line edit of the example, and must come back as a
refusal that names what is wrong. A rule nothing exercises is a rule nobody
knows still holds.

Usage: tools/memsys_check.py [examples/memory_system.axisl]
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import FAILED, PASSED, axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def read(text: str):
    """An s-expression reader: atoms, strings and lists; comments dropped."""
    tokens = re.findall(r'"(?:[^"\\]|\\.)*"|\(|\)|[^\s()]+', re.sub(r";[^\n]*", "", text))
    def at(i):
        if tokens[i] == "(":
            out, i = [], i + 1
            while tokens[i] != ")":
                x, i = at(i)
                out.append(x)
            return out, i + 1
        return tokens[i], i + 1
    return at(0)[0]


def num(text: str) -> int:
    return int(text.replace("_", ""), 0)


def props(form) -> dict:
    return {p[0]: p[1:] for p in form if isinstance(p, list) and p}


def expected(module) -> dict:
    """The manifest this description should produce, derived here."""
    memories, ics, systems = {}, {}, []
    for form in module[2:]:
        if not isinstance(form, list) or not form:
            continue
        if form[0] == "defmemory":
            memories[form[1]] = props(form[2:])
        elif form[0] == "definterconnect":
            ics[form[1]] = props(form[2:])
        elif form[0] == "defmemsys":
            systems.append((form[1], props(form[2:])))
    out = {}
    for name, sysp in systems:
        ic = ics[sysp["interconnect"][0]]
        topo = ic["topology"]
        kind = topo[0]
        dims = {d[0]: num(d[1]) for d in topo[1:]}
        if kind in ("mesh", "torus"):
            cols, rows = dims["cols"], dims["rows"]
        else:
            cols, rows = dims.get("nodes", dims.get("ports")), 1

        def hops(a, b):
            dx, dy = abs(a[0] - b[0]), abs(a[1] - b[1])
            if kind == "mesh":
                return dx + dy
            if kind == "torus":
                return min(dx, cols - dx) + min(dy, rows - dy)
            if kind == "ring":
                return min(dx, cols - dx)
            return int(a != b)

        nodes = {}
        for entry in sysp["nodes"]:
            p = props(entry[1:])
            at = tuple(num(v) for v in p["at"]) + ((0,) if len(p["at"]) == 1 else ())
            nodes[entry[0]] = {"memory": p["memory"][0], "core": p.get("core", [""])[0],
                               "next": p.get("next", [""])[0], "home": "home" in p, "at": at}
        resolved = {}
        for n, v in nodes.items():
            m = memories[v["memory"]]
            r = {"id": v["at"][1] * cols + v["at"][0], "x": v["at"][0], "y": v["at"][1],
                 "core": v["core"], "next": v["next"], "home": v["home"],
                 "size_bytes": num(m["size-bytes"][0])}
            if v["next"]:
                r["hops_to_next"] = hops(v["at"], nodes[v["next"]]["at"])
            if "line-bytes" in m:
                line, ways = num(m["line-bytes"][0]), num(m.get("ways", ["1"])[0])
                r["sets"] = r["size_bytes"] // line // ways
                r["replacement"] = m.get("replacement", ["lru"])[0]
                r["write_policy"] = m.get("write-policy", ["write-back"])[0]
                r["allocate"] = m.get("allocate", ["write-allocate"])[0]
                r["inclusion"] = m.get("inclusion", ["nine"])[0]
            if "timing" in m:
                t = {k[0]: num(k[1]) for k in m["timing"]}
                r["dram"] = {"tck_ps": t["tck-ps"], "tcl": t["tcl"], "trcd": t["trcd"],
                             "trp": t["trp"], "tras": t["tras"],
                             "standard": m.get("standard", [""])[0]}
            resolved[n] = r
        paths = {}
        for n, v in nodes.items():
            if v["core"]:
                chain, at = [n], v
                while at["next"]:
                    chain.append(at["next"])
                    at = nodes[at["next"]]
                paths[v["core"]] = chain
        regions = []
        for entry in sysp.get("address-map", []):
            p = props(entry[4:])
            target, home = entry[3], p.get("home", [""])[0]
            regions.append({"base": num(entry[1]), "size": num(entry[2]), "target": target,
                            "target_id": resolved[target]["id"],
                            "home_id": resolved[home]["id"] if home else None,
                            "uncached": "uncached" in p})
        out[name] = {"clock_ps": num(sysp.get("clock-ps", ["0"])[0]),
                     "cols": cols, "rows": rows, "topology": kind, "nodes": resolved,
                     "paths": paths, "regions": regions}
    return out


def compare(want: dict, manifest: dict) -> list[str]:
    bad = []
    got = {s["name"]: s for s in manifest["systems"]}
    if set(got) != set(want):
        return [f"systems: manifest has {sorted(got)}, the description {sorted(want)}"]
    for name, w in want.items():
        g = got[name]
        if g["clock_ps"] != w["clock_ps"]:
            bad.append(f"{name}: clock_ps is {g['clock_ps']}, should be {w['clock_ps']}")
        for key in ("cols", "rows", "topology"):
            if g["interconnect"][key] != w[key]:
                bad.append(f"{name}: {key} is {g['interconnect'][key]}, should be {w[key]}")
        gnodes = {n["name"]: n for n in g["nodes"]}
        for node, fields in w["nodes"].items():
            for key, value in fields.items():
                have = gnodes.get(node, {}).get(key, "<absent>")
                if key == "dram":
                    have = {k: have.get(k) for k in value} if isinstance(have, dict) else have
                if have != value:
                    bad.append(f"{name}.{node}: {key} is {have}, should be {value}")
        if g["paths"] != w["paths"]:
            bad.append(f"{name}: paths are {g['paths']}, should be {w['paths']}")
        for i, (gr, wr) in enumerate(zip(g["address_map"], w["regions"])):
            for key, value in wr.items():
                if gr.get(key) != value:
                    bad.append(f"{name}: region {i} {key} is {gr.get(key)}, should be {value}")
        if len(g["address_map"]) != len(w["regions"]):
            bad.append(f"{name}: {len(g['address_map'])} regions, should be {len(w['regions'])}")
    return bad


#: Each refusal the design promises, as (what, an edit to the example, a
#: fragment the refusal must contain). The edit is a literal replacement.
REFUSALS = [
    ("a cache with no next level", "(at 1 1) (next ddr0) (home)", "(at 1 1) (home)", "names no next level"),
    ("an endpoint with a next level", "(ddr0 (memory ddr) (at 1 2))", "(ddr0 (memory ddr) (at 1 2) (next l2))", "only a cache misses"),
    ("a loop of levels", "(c1-l1d (memory l1d) (core cpu1) (at 2 0) (next l2))",
     "(c1-l1d (memory l1d) (core cpu1) (at 2 0) (next c1b)) (c1b (memory l1d) (at 2 1) (next c1-l1d))", "cycle"),
    ("two nodes at one place", "(spm0 (memory spm) (at 0 2))", "(spm0 (memory spm) (at 1 2))", "two nodes at"),
    ("a node off the fabric", "(spm0 (memory spm) (at 0 2))", "(spm0 (memory spm) (at 0 3))", "outside"),
    ("overlapping regions", "(region 0x80000000 0x10000 spm0 (uncached))",
     "(region 0x7fff0000 0x10000 spm0 (uncached))", "overlap"),
    ("an unaligned region", "(region 0x80000000 0x10000 spm0 (uncached))",
     "(region 0x80000020 0x10000 spm0 (uncached))", "aligned"),
    ("a region at a cache", "(region 0x80000000 0x10000 spm0 (uncached))",
     "(region 0x80000000 0x10000 l2 (uncached))", "ends at an endpoint"),
    ("a coherent region with no home", "(region 0x0 0x80000000 ddr0 (home l2))",
     "(region 0x0 0x80000000 ddr0)", "names no home"),
    ("a home that is no directory", "(region 0x0 0x80000000 ddr0 (home l2))",
     "(region 0x0 0x80000000 ddr0 (home c0-l1d))", "not declared `(home)`"),
    ("an uncached region with a home", "(region 0x80000000 0x10000 spm0 (uncached))",
     "(region 0x80000000 0x10000 spm0 (uncached) (home l2))", "uncached and names a home"),
    ("a region past the address width", "(address-bits 48)", "(address-bits 30)", "address bits"),
    ("a policy on a scratchpad", "(kind scratchpad)", "(kind scratchpad) (replacement lru)", "is not a cache"),
    ("an unknown replacement", "(replacement plru)", "(replacement mru)", "is not one of"),
    ("a DRAM with no timing", "(timing (tck-ps 417) (tcl 40) (trcd 39) (trp 39) (tras 77))",
     "(timing (tck-ps 417) (tcl 40) (trcd 39) (trp 39))", "tras"),
    ("tRAS shorter than tRCD", "(tras 77)", "(tras 20)", "shorter than tRCD"),
    ("two line sizes", "(size-bytes 65536)\n    (line-bytes 64)", "(size-bytes 65536)\n    (line-bytes 128)", "line sizes"),
    ("a node private to no core", "(core cpu1)", "(core cpu9)", "not declared"),
    ("more places than node ids", "(node-id-bits 7)", "(node-id-bits 3)", "node-id bits"),
    ("a DRAM with no clock to meet", "(clock-ps 333)", "", "clock-ps"),
    ("a write-through port under a protocol", "(write-policy write-back)\n    (allocate write-allocate)\n    (mshrs 4)",
     "(write-policy write-through)\n    (allocate write-allocate)\n    (mshrs 4)", "not write-back, write-allocate"),
    ("a prefetching port under a protocol", "(allocate write-allocate)\n    (mshrs 4)",
     "(allocate write-allocate)\n    (mshrs 4)\n    (prefetch next-line)", "has no owner"),
    ("an exclusive home", "(inclusion inclusive)", "(inclusion exclusive)", "is exclusive"),
    ("a port that does not reach its home", "(c1-l1d (memory l1d) (core cpu1) (at 2 0) (next l2))",
     "(c1-l1d (memory l1d) (core cpu1) (at 2 0) (next l2b)) (l2b (memory l2) (at 2 1) (next ddr0))", "does not reach home"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path,
                        default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    source = args.axis_file.read_text()
    failures: list[str] = []

    result = subprocess.run([*axis_prefix(), "emit-memsys-json", str(args.axis_file)],
                            capture_output=True, text=True, cwd=AXIS_ROOT)
    if result.returncode != 0:
        print(f"  FAIL emit-memsys-json: {result.stderr.strip()[:200]}")
        return FAILED
    manifest = json.loads(result.stdout)
    want = expected(read(source))
    # ⚠️ Vacuity: a manifest with no system, or a system with no region, would
    # agree with a reading that found nothing.
    if not want or not all(w["regions"] and len(w["nodes"]) >= 3 for w in want.values()):
        print("  FAIL the description has no memory system worth comparing")
        return FAILED
    failures += compare(want, manifest)

    refused = 0
    with tempfile.TemporaryDirectory(prefix="axis_memsys_") as work:
        for what, old, new, fragment in REFUSALS:
            if source.count(old) != 1:
                failures.append(f"refusal `{what}`: the edit's anchor is not in the example once")
                continue
            path = Path(work) / "mutant.axisl"
            path.write_text(source.replace(old, new))
            run = subprocess.run([*axis_prefix(), "check", str(path)], capture_output=True,
                                 text=True, cwd=AXIS_ROOT)
            said = (run.stdout + run.stderr).strip()
            if run.returncode == 0:
                failures.append(f"refusal `{what}`: accepted")
            elif fragment not in said:
                failures.append(f"refusal `{what}`: refused, but for another reason: {said[:160]}")
            else:
                refused += 1

    for line in failures:
        print(f"  FAIL {line}")
    nodes = sum(len(w["nodes"]) for w in want.values())
    print(f"  {len(want)} system(s), {nodes} node(s) resolved as the description says; "
          f"{refused} of {len(REFUSALS)} refusals made to happen")
    verdict = "PASS" if not failures else "FAIL"
    print(f"memory system manifest == description: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
