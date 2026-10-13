#!/usr/bin/env python3
"""The fabric manifest's link graph is the topology it declares.

`fabric_manifest.json` publishes the edge list **expanded** — a consumer reads
one list and never has to know whether an edge came from a compass pattern or
an explicit `(link ...)`. This re-derives the expansion independently and
requires the two to agree, which is the drift the manifest exists to prevent: a
mapper that expanded `(north 1)` itself would be a second derivation of the
grid, and the two would disagree at the boundary.

The boundary is the whole difficulty. A mesh's edge PEs have fewer neighbours
than its interior ones, and *which* ones is exactly the off-by-one a second
implementation gets wrong — a torus differs from a mesh only there. So a run
where every PE has a full complement of neighbours proves nothing about the
expansion and **fails as vacuous**.

Also checked, because they are cheap and each is a way a grid can be malformed
while every edge looks fine on its own: every endpoint on the grid, no
self-links, latency at least one and no longer than `ii-max`, every PE touched
by some link, and the declared unit classes issuable by some instruction.

Usage: tools/fabric_topology_check.py [input.axisl]
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

# Row 0 is the top, so north decreases the row. Stated here independently of
# the reader on purpose: if this table and the frontend's disagree, that is the
# defect the gate is for.
DIRECTIONS = {"north": (-1, 0), "south": (1, 0), "east": (0, 1), "west": (0, -1)}


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def expand(fabric: dict) -> set[tuple]:
    """Re-derive the pattern edges, from rows/cols and the direction alone."""
    rows, cols = fabric["rows"], fabric["cols"]
    latency = {}
    for link in fabric["links"]:
        if link["direction"]:
            latency[link["direction"]] = link["latency"]
    edges = set()
    for direction, cycles in latency.items():
        row_delta, col_delta = DIRECTIONS[direction]
        for row in range(rows):
            for col in range(cols):
                to_row, to_col = row + row_delta, col + col_delta
                if 0 <= to_row < rows and 0 <= to_col < cols:
                    edges.add((row, col, to_row, to_col, cycles, direction))
    return edges


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "cgra_fabric.axisl")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_fabric_"))
    emit(args.axis_file, "emit-fabric-json", workdir / "fabric.json")
    emit(args.axis_file, "emit-json", workdir / "document.json")
    manifest = json.loads((workdir / "fabric.json").read_text())
    document = json.loads((workdir / "document.json").read_text())
    mnemonics = {one["mnemonic"] for one in document["instructions"]}

    if not manifest["fabrics"]:
        print(f"{args.axis_file.name}: declares no fabric, nothing to check")
        return 0

    failures: list[str] = []
    boundary_seen = 0
    checked = 0
    for fabric in manifest["fabrics"]:
        name = fabric["name"]
        rows, cols = fabric["rows"], fabric["cols"]
        if fabric["pes"] != rows * cols:
            failures.append(f"{name}: says {fabric['pes']} PEs for a {rows}x{cols} grid")

        published = {(l["from"][0], l["from"][1], l["to"][0], l["to"][1],
                      l["latency"], l["direction"]) for l in fabric["links"]}
        patterned = {edge for edge in published if edge[5]}
        derived = expand(fabric)
        for edge in derived - patterned:
            failures.append(f"{name}: the pattern implies ({edge[0]},{edge[1]}) -> "
                            f"({edge[2]},{edge[3]}) {edge[5]}, the manifest omits it")
        for edge in patterned - derived:
            failures.append(f"{name}: the manifest has ({edge[0]},{edge[1]}) -> "
                            f"({edge[2]},{edge[3]}) {edge[5]}, the pattern does not imply it")
        checked += len(published)

        degree = {(r, c): 0 for r in range(rows) for c in range(cols)}
        for link in fabric["links"]:
            for row, col, end in ((*link["from"], "source"), (*link["to"], "destination")):
                if not (0 <= row < rows and 0 <= col < cols):
                    failures.append(f"{name}: link {end} ({row},{col}) is off a {rows}x{cols} grid")
                else:
                    degree[(row, col)] += 1
            if link["from"] == link["to"]:
                failures.append(f"{name}: link from ({link['from']}) to itself")
            if link["latency"] < 1:
                failures.append(f"{name}: link {link['from']}->{link['to']} has latency "
                                f"{link['latency']}")
            if link["latency"] > fabric["ii_max"]:
                failures.append(f"{name}: link {link['from']}->{link['to']} takes "
                                f"{link['latency']} cycles, longer than ii-max {fabric['ii_max']}")
        if rows * cols > 1:
            for position, count in degree.items():
                if count == 0:
                    failures.append(f"{name}: PE {position} is touched by no link")

        # The boundary: some PE must have fewer pattern edges than the fullest
        # one, or a mesh and a torus are indistinguishable here.
        pattern_degree = {(r, c): 0 for r in range(rows) for c in range(cols)}
        for edge in patterned:
            pattern_degree[(edge[0], edge[1])] += 1
        if pattern_degree and len(set(pattern_degree.values())) > 1:
            boundary_seen += 1

        # That every declared unit is issued by *some* instruction is the
        # validator's rule and is injection-checked there; `emit-json` does not
        # publish an instruction's unit, so this cannot re-derive it. What is
        # checkable here is the other direction -- the issuable list names real
        # instructions -- and that the list is not empty, since a fabric
        # nothing can run on is a grid rather than a machine.
        for mnemonic in fabric["issuable"]:
            if mnemonic not in mnemonics:
                failures.append(f"{name}: issuable names `{mnemonic}`, "
                                f"which is not an instruction in this document")
        if not fabric["issuable"]:
            failures.append(f"{name}: no instruction can issue on any PE")

    for failure in failures[:10]:
        print(f"FAIL {failure}")
    if len(failures) > 10:
        print(f"... and {len(failures) - 10} more")

    print(f"{len(manifest['fabrics'])} fabric(s), {checked} link(s) re-derived")
    if boundary_seen == 0:
        print("FAIL: no fabric has a boundary -- every PE has the same number of "
              "pattern edges, so this corpus cannot tell a mesh from a torus")
        failures.append("vacuous")
    else:
        print(f"{boundary_seen} fabric(s) with a boundary the expansion had to get right")

    print("fabric manifest == declared topology: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
