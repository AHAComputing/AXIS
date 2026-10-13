#!/usr/bin/env python3
"""AHA builds the memory system the description describes. Gate.

`tools/memsys_aha.py` lowers each `defmemsys` into AHA's configurations. This
holds that lowering against AHA's OWN code -- the only thing entitled to say
what a configuration means there:

  * the memory fabric: AHA's synthesizable address decoder, SIMULATED, and its
    Python model both send every region boundary, midpoint and gap to the
    place the manifest says -- the target's `(at x y)`, or nowhere;
  * the coherent fabric: AHA's CHI home decoder names the manifest's home id
    at every probe (an uncached region has none), and AHA's own
    decoder-versus-model cosim passes at this configuration;
  * the topology: AHA's hop METRIC reproduces every `hops_to_next` the
    manifest publishes -- the number the simulator will charge -- and its
    home is the node the description marked `(home)`;
  * the protocol: AHA's exhaustive MOESI (or MSI) proof holds at the number
    of private caches the description has;
  * the memory: a DRAM's declared timing is its `standard`'s, as AHA's
    profile of the part has it;
  * no protocol mechanism is named that AHA does not have.

⚠️ And each comparison is shown to be able to fail: the lowering is perturbed
three ways -- x and y transposed, a home off by one, a timing off by one --
and each perturbation must be noticed. A comparison that agrees with a wrong
answer is agreement about nothing.

Declines without a PCE checkout (`AXIS_PCE_ROOT`).

Usage: tools/memsys_aha_check.py [examples/memory_system.axisl]
"""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED
from memsys_aha import PCE_ROOT, lower, manifest_of, run_in_pce

AXIS_ROOT = Path(__file__).resolve().parent.parent


def expected_place(system: dict, addr: int):
    for r in system["address_map"]:
        if r["base"] <= addr < r["base"] + r["size"]:
            return [r["target_x"], r["target_y"]]
    return None


def expected_home(system: dict, addr: int):
    for r in system["address_map"]:
        if r["base"] <= addr < r["base"] + r["size"]:
            return None if r["uncached"] else r["home_id"]
    return None


def judge(system: dict, lowered: dict, report: dict) -> list[str]:
    bad = []
    noc = report["noc"]
    if len(noc["probes"]) < 4:
        bad.append(f"only {len(noc['probes'])} address probes; the map is not being exercised")
    for p in noc["probes"]:
        want = expected_place(system, p)
        for who in ("rtl", "model"):
            got = noc[who][str(p)]
            if got != want:
                bad.append(f"NoC {who} decoder sends {p:#x} to {got}, the description to {want}")
    chi = report["chi"]
    if lowered["chi"] is not None:
        if chi["unknown_features"]:
            bad.append(f"CHI mechanisms AHA does not have: {chi['unknown_features']}")
        for p, got in chi["home"].items():
            want = expected_home(system, int(p))
            if got != want:
                bad.append(f"CHI home decoder sends {int(p):#x} to home {got}, the description to {want}")
        cosim = chi["decoder_cosim"]
        if not cosim.get("equivalent") or cosim.get("mismatches"):
            bad.append(f"AHA's CHI home decoder disagrees with its own model: {cosim}")
    topo = report["topology"]
    if lowered["topology"] is not None:
        if topo["home"] != lowered["topology"]["home_node"]:
            bad.append(f"AHA's topology puts the home at {topo['home']}, the description at {lowered['topology']['home_node']}")
        declared = {(h["from"], h["to"]): h["hops"] for h in lowered["hops"]}
        if not topo["dist"]:
            bad.append("no hop distance was compared")
        for a, b, d in topo["dist"]:
            if d != declared[(a, b)]:
                bad.append(f"AHA's metric puts {a}->{b} at {d} hops, the manifest at {declared[(a, b)]}")
    co = report["coherence"]
    if lowered["coherence"] is not None:
        proof = co.get("proof")
        if proof is None:
            bad.append(f"coherence: {co.get('declined', 'no proof ran')}")
        elif not (proof.get("proven") or proof.get("holds") or proof.get("ok")):
            bad.append(f"AHA's {lowered['coherence']['protocol']} proof does not hold at "
                       f"{lowered['coherence']['n_caches']} caches: {proof}")
    for declared, aha in zip(lowered["dram"], report["dram"]):
        if "unknown" in aha:
            bad.append(f"DRAM `{declared['node']}`: {aha['unknown']}")
            continue
        for key in ("tck_ps", "tcl", "trcd", "trp", "tras"):
            if declared[key] != aha[key]:
                bad.append(f"DRAM `{declared['node']}` declares {key}={declared[key]}; "
                           f"{declared['standard']} is {aha[key]}")
    return bad


def perturbations(lowered: dict):
    """Three wrong lowerings, each of which some comparison must reject."""
    t = copy.deepcopy(lowered)
    for r in t["noc"]["regions"]:
        r["x"], r["y"] = r["y"], r["x"]
    yield "x and y transposed", t, "sys"
    if lowered["chi"] and lowered["chi"]["regions"]:
        h = copy.deepcopy(lowered)
        h["chi"]["regions"][0]["home_id"] += 1
        yield "a home off by one", h, "chi"
    if lowered["dram"]:
        d = copy.deepcopy(lowered)
        d["dram"][0]["tcl"] += 1
        yield "a CAS latency off by one", d, "dram"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", nargs="?", type=Path,
                        default=AXIS_ROOT / "examples" / "memory_system.axisl")
    args = parser.parse_args()
    if not (PCE_ROOT / "third_party" / "pyrtl").is_dir():
        print(f"  DECLINED no PCE checkout with vendored PyRTL at {PCE_ROOT}")
        return DECLINED
    failures: list[str] = []
    checked = 0
    for system in manifest_of(args.axis_file)["systems"]:
        lowered = lower(system)
        try:
            report = run_in_pce(lowered, "check")
        except RuntimeError as error:
            failures.append(f"{system['name']}: {error}")
            continue
        failures += [f"{system['name']}: {b}" for b in judge(system, lowered, report)]
        checked += 1
        for what, wrong, _ in perturbations(lowered):
            # The NoC decoders are AHA's and are fed the WRONG regions: the
            # comparison against the description must then disagree.
            wrong_report = run_in_pce(wrong, "check")
            if not judge(system, wrong, wrong_report):
                failures.append(f"{system['name']}: {what} went unnoticed")
    if checked == 0:
        failures.append("no memory system was checked")
    for line in failures:
        print(f"  FAIL {line}")
    print(f"  {checked} memory system(s) lowered and held against AHA's decoders, metric, "
          f"coherence proof and DRAM profiles; 3 perturbations each must be caught")
    verdict = "PASS" if not failures else "FAIL"
    print(f"AHA builds the described memory system: {verdict}")
    return PASSED if not failures else FAILED


if __name__ == "__main__":
    sys.exit(main())
