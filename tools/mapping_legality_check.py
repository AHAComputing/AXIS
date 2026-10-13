"""The mapping manifest's occupancy is the schedule it publishes.

`mapping_manifest.json` carries the placement, the routes, the initiation
interval, and the modulo occupancy tables the validator decided legality on, and how many
configurations each PE is asked to hold.
This re-derives those tables from the placement and the routes alone — with
the link latencies read from `fabric_manifest.json` — and requires them to
match, then re-checks the legality condition on the re-derived tables.

Two derivations of one fact, which is the shape of nearly every defect this
repository has found. A mapper that recomputed `cycle mod ii` itself is a
second derivation, and this is the gate that says the two agree.

The residue is where a modulo schedule differs from any other, so a run whose
cycles are all below `ii` proves nothing about it: the wrap never happens and
`cycle mod ii` is `cycle`. Such a run **fails as vacuous**.

Usage: tools/mapping_legality_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "cgra_fabric.axisl")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_mapping_"))
    emit(args.axis_file, "emit-mapping-json", workdir / "mapping.json")
    emit(args.axis_file, "emit-fabric-json", workdir / "fabric.json")
    emit(args.axis_file, "emit-json", workdir / "document.json")
    mappings = json.loads((workdir / "mapping.json").read_text())["mappings"]
    fabrics = {f["name"]: f for f in json.loads((workdir / "fabric.json").read_text())["fabrics"]}
    latency = {one["mnemonic"]: one.get("latency_cycles", 1)
               for one in json.loads((workdir / "document.json").read_text())["instructions"]}

    if not mappings:
        print(f"{args.axis_file.name}: declares no mapping, nothing to check")
        return 0

    failures: list[str] = []
    wrapped = 0
    multiplexed = 0
    for mapping in mappings:
        name, ii = mapping["name"], mapping["ii"]
        fabric = fabrics.get(mapping["fabric"])
        if fabric is None:
            failures.append(f"{name}: names fabric `{mapping['fabric']}`, absent from the manifest")
            continue
        links = {((l["from"][0], l["from"][1]), (l["to"][0], l["to"][1])): l["latency"]
                 for l in fabric["links"]}
        place = {one["id"]: one for one in mapping["place"]}

        # --- PE occupancy, re-derived ---
        derived_pe = sorted((tuple(one["pe"]), one["cycle"] % ii, one["id"])
                            for one in mapping["place"])
        published_pe = sorted((tuple(one["pe"]), one["residue"], one["op"])
                              for one in mapping["pe_occupancy"])
        if derived_pe != published_pe:
            failures.append(f"{name}: PE occupancy differs from the placement it publishes")
        for one in mapping["place"]:
            if one["residue"] != one["cycle"] % ii:
                failures.append(f"{name}: `{one['id']}` says residue {one['residue']} "
                                f"for cycle {one['cycle']} mod {ii}")
            if one["cycle"] >= ii:
                wrapped += 1

        # --- configurations per PE, re-derived ---
        derived_configs = Counter(tuple(one["pe"]) for one in mapping["place"])
        published_configs = {tuple(one["pe"]): one["configurations"]
                             for one in mapping["pe_configurations"]}
        if dict(derived_configs) != published_configs:
            failures.append(f"{name}: PE configuration counts differ from the placement")
        for position, count in derived_configs.items():
            if count > fabric["contexts"]:
                failures.append(f"{name}: PE {position} needs {count} configurations, "
                                f"but a PE of `{fabric['name']}` holds {fabric['contexts']}")
            if count > 1:
                multiplexed += 1

        # --- link occupancy, re-derived ---
        derived_link = []
        for route in mapping["route"]:
            # An elastic route has no residue to derive: its arrival is a
            # channel's window, so the validator exempted it from the modulo
            # rule and the manifest publishes no occupancy for it. Deriving one
            # here would be this gate inventing the number it exists to check.
            # `elastic_deadlock_check.py` holds what an elastic route owes.
            if route.get("channel"):
                continue
            flight = 0
            via = [tuple(position) for position in route["via"]]
            for source, target in zip(via, via[1:]):
                hop = links.get((source, target))
                if hop is None:
                    failures.append(f"{name}: route {route['from']} -> {route['to']} hops "
                                    f"{source} -> {target}, which the fabric does not link")
                    hop = 1
                derived_link.append((source, target, (route["cycle"] + flight) % ii,
                                     f"{route['from']} -> {route['to']}"))
                if route["cycle"] + flight >= ii:
                    wrapped += 1
                flight += hop
            # Latency consistency, re-derived from the manifests.
            producer, consumer = place.get(route["from"]), place.get(route["to"])
            if producer and consumer:
                arrives = (producer["cycle"] + latency.get(producer["mnemonic"], 1) + flight) % ii
                if arrives != consumer["cycle"] % ii:
                    failures.append(
                        f"{name}: {route['from']} -> {route['to']} arrives at {arrives} mod {ii}, "
                        f"but {route['to']} issues at {consumer['cycle'] % ii}")
        published_link = [((l["link"][0][0], l["link"][0][1]),
                           (l["link"][1][0], l["link"][1][1]), l["residue"], l["route"])
                          for l in mapping["link_occupancy"]]
        if sorted(derived_link) != sorted(published_link):
            failures.append(f"{name}: link occupancy differs from the routes it publishes")

        # --- the legality condition, on the re-derived tables ---
        for (position, residue), count in Counter(
                (pe, residue) for pe, residue, _ in derived_pe).items():
            if count > 1:
                failures.append(f"{name}: PE {position} is used {count} times at residue {residue}")
        for key, count in Counter(
                (source, target, residue) for source, target, residue, _ in derived_link).items():
            if count > 1:
                failures.append(f"{name}: link {key[0]}->{key[1]} carries {count} values "
                                f"at residue {key[2]}")

        # The scalar order accounts for every operation and invents none.
        if sorted(mapping["scalar_order"]) != sorted(place):
            failures.append(f"{name}: scalar order {mapping['scalar_order']} is not the "
                            f"placed operations {sorted(place)}")

    for failure in failures[:10]:
        print(f"FAIL {failure}")
    print(f"{len(mappings)} mapping(s) re-derived")
    if wrapped == 0:
        print("FAIL: every cycle is below its II, so the modulo wrap never happens and "
              "this corpus cannot tell `cycle mod ii` from `cycle`")
        failures.append("vacuous")
    else:
        print(f"{wrapped} placement(s)/hop(s) past the II, where the wrap is load-bearing")
    if multiplexed == 0:
        print("FAIL: no PE holds more than one configuration, so this corpus cannot tell "
              "a multi-context fabric from a single-context one")
        failures.append("vacuous")
    else:
        print(f"{multiplexed} PE(s) holding more than one configuration")

    print("mapping manifest == modulo legality: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
