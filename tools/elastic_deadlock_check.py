#!/usr/bin/env python3
"""A cycle of elastic channels with no buffering cannot move (stage G4b).

Static timing lets AXIS prove that a schedule computes what a scalar sequence
computes (`fabric_vs_scalar.py`, G3). Elastic breaks the premise that claim
rests on -- `vliw_spatial_design.md` §10's rule that a value's arrival time is a
static function of the schedule -- so an elastic route is exempt from the modulo
checks and carries different obligations instead. This is the half that is
decidable from the declaration alone, and it is the one a mapper most wants: a
ring of pure wires has nowhere to put a token, so nothing in it can ever move.

The validator decides this. This gate re-derives it from
`mapping_manifest.json`, the way `mapping_legality_check.py` re-derives the
modulo tables: two derivations of one fact, from the artifact rather than from
the code that produced it.

Coverage, per `docs/gate_coverage.md`: a corpus with no cyclic elastic path
fails as vacuous. An acyclic graph cannot deadlock, so a run over one proves
nothing about the check -- the same reason a corpus whose cycles never wrap
fails the modulo gate.

Usage: tools/elastic_deadlock_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def elastic_cycles(mapping: dict) -> list[list[str]]:
    """Every simple cycle in this mapping's elastic route graph.

    Depth-first from each operation, over elastic routes only: a statically
    timed route waits for a cycle rather than for a peer, so it cannot be part
    of a deadlock.
    """
    edges: dict[str, list[dict]] = {}
    for route in mapping.get("route", []):
        if route.get("channel"):
            edges.setdefault(route["from"], []).append(route)
    found: list[list[str]] = []

    def walk(node: str, path: list[str], on_path: set[str]) -> None:
        for route in edges.get(node, []):
            nxt = route["to"]
            if nxt in on_path:
                start = path.index(nxt)
                found.append(path[start:] + [nxt])
                continue
            walk(nxt, path + [nxt], on_path | {nxt})

    for start in list(edges):
        walk(start, [start], {start})
    return found


def capacity_on(mapping: dict, channels: dict[str, dict], first: str, second: str) -> int:
    """The buffering between two operations, over every route that joins them."""
    return max(
        (channels.get(route.get("channel", ""), {}).get("capacity", 0)
         for route in mapping.get("route", [])
         if route["from"] == first and route["to"] == second),
        default=0,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "cgra_fabric.axisl")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axis_elastic_") as workdir:
        manifest = Path(workdir) / "mapping.json"
        subprocess.run([*axis_prefix(), "emit-mapping-json", str(args.axis_file),
                        "-o", str(manifest)],
                       cwd=AXIS_ROOT, check=True, capture_output=True)
        payload = json.loads(manifest.read_text())

    channels = {one["name"]: one for one in payload.get("channels", [])}
    mappings = payload.get("mappings", [])
    failures = cycles_seen = buffered = 0
    for mapping in mappings:
        for cycle in elastic_cycles(mapping):
            cycles_seen += 1
            holds = any(capacity_on(mapping, channels, a, b) > 0
                        for a, b in zip(cycle, cycle[1:]))
            if holds:
                buffered += 1
                continue
            failures += 1
            print(f"FAIL {mapping['name']}: {' -> '.join(cycle)} is a ring of pure "
                  f"wires; no token can move")
        # The other direction, and the one a manifest can get wrong quietly: an
        # elastic route must not appear in the modulo occupancy table, because
        # legality was never decided on a residue for it.
        elastic = {f"{route['from']} -> {route['to']}"
                   for route in mapping.get("route", []) if route.get("channel")}
        for entry in mapping.get("link_occupancy", []):
            if entry.get("route") in elastic:
                failures += 1
                print(f"FAIL {mapping['name']}: {entry['route']} is elastic and still "
                      f"holds residue {entry.get('residue')} in the occupancy table")

    print(f"{len(mappings)} mapping(s), {cycles_seen} elastic cycle(s), "
          f"{buffered} of them buffered")
    if not cycles_seen:
        print("no cyclic elastic path in this corpus: an acyclic graph cannot "
              "deadlock, so this run proves nothing about the check")
        failures += 1
    print("elastic deadlock: " + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
