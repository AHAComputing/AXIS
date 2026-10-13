#!/usr/bin/env python3
"""Two sides of a seam were specified to be the same seam (stage G4b.3).

A personality can lend a functional unit across a boundary: `lane1` exports its
multiplier, `lane0` imports it. That is what XNN-MT's tile boundary is -- one
tile's array used by its neighbour -- and what makes it checkable is that each
side names its *own* channel. The producer promises what it promises; the
consumer states what it can take; whether those compose is then a question with
an answer rather than an assumption two designers each made separately.

The three rules, from `docs/elastic_seams_design.md` §4:

  * same protocol, because a protocol is a name a consumer matches on and two
    names that differ are two handshakes;
  * the importer's latency window contains the exporter's, because a producer
    that can be later than its consumer tolerates is a producer whose results
    the consumer will drop;
  * order composes downward: `preserving` may consume `preserving`, and may not
    consume `unordered`.

The validator decides all three. This gate re-derives them by *joining two
artifacts*: the seam sides come from `state_capsule.json` and the channel
contracts from `mapping_manifest.json`. Neither file alone can be checked
against itself, so the join is the point -- a manifest that publishes a seam
whose channel the other manifest never declares is exactly the drift a single
file would hide.

Coverage, per `docs/gate_coverage.md`: a corpus with no import bound to an
export fails as vacuous. An unimported export composes with nothing, so a run
over one exercises no rule at all.

Usage: tools/seam_contract_check.py [input.axisl]
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


def emit(axis_file: Path, command: str, workdir: str, name: str) -> dict:
    out = Path(workdir) / name
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   cwd=AXIS_ROOT, check=True, capture_output=True)
    return json.loads(out.read_text())


def contains(outer: dict, inner: dict) -> bool:
    """Does `outer`'s latency window contain `inner`'s?"""
    return (outer["latency_min"] <= inner["latency_min"]
            and outer["latency_max"] >= inner["latency_max"])


def check_seams(personalities: dict[str, dict],
                channels: dict[str, dict]) -> tuple[list[str], int]:
    """Every failure the join finds, and the number of bound seams it checked.

    Split out from `main` because the emitters validate before they emit, so a
    doctored *corpus* can never reach this code -- which would leave the rules
    below unexercised and unexercisable. Given two dicts they can be driven
    directly, which is how they were shown to fire.
    """
    failures: list[str] = []
    pairs = 0
    for name, personality in personalities.items():
        for entry in personality.get("imports", []):
            exporter = personalities.get(entry["from"])
            if exporter is None:
                failures.append(
                    f"{name} imports `{entry['name']}` from `{entry['from']}`, "
                    f"which this manifest does not publish")
                continue
            export = next((one for one in exporter.get("exports", [])
                           if one["name"] == entry["name"]), None)
            if export is None:
                failures.append(
                    f"{name} imports `{entry['name']}` from `{entry['from']}`, "
                    f"which exports no such unit")
                continue
            near = channels.get(entry["channel"])
            far = channels.get(export["channel"])
            if near is None or far is None:
                missing = entry["channel"] if near is None else export["channel"]
                failures.append(
                    f"seam `{entry['name']}`: channel `{missing}` is named by a "
                    f"personality and declared by no channel")
                continue

            pairs += 1
            if near["protocol"] != far["protocol"]:
                failures.append(
                    f"seam `{entry['name']}`: {exporter['name']} speaks "
                    f"`{far['protocol']}` and {name} speaks `{near['protocol']}`")
            if not contains(near, far):
                failures.append(
                    f"seam `{entry['name']}`: {exporter['name']} exports with latency "
                    f"{far['latency_min']}..{far['latency_max']} and {name} accepts "
                    f"only {near['latency_min']}..{near['latency_max']}")
            if far["order"] == "unordered" and near["order"] == "preserving":
                failures.append(
                    f"seam `{entry['name']}`: {exporter['name']} exports unordered "
                    f"and {name} imports preserving")
    return failures, pairs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "vliw_exposed.axisl")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axis_seam_") as workdir:
        capsule = emit(args.axis_file, "emit-capsule-json", workdir, "capsule.json")
        mapping = emit(args.axis_file, "emit-mapping-json", workdir, "mapping.json")

    channels = {one["name"]: one for one in mapping.get("channels", [])}
    personalities = {one["name"]: one for one in capsule.get("personalities", [])}

    exported = sum(len(one.get("exports", [])) for one in personalities.values())
    messages, pairs = check_seams(personalities, channels)
    for message in messages:
        print(f"FAIL {message}")
    failures = len(messages)

    print(f"{len(personalities)} personality(ies), {exported} export(s), "
          f"{pairs} bound seam(s) checked")
    if not pairs:
        print("no import bound to an export in this corpus: an unimported export "
              "composes with nothing, so this run exercises no rule")
        failures += 1
    print("seam contracts: " + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
