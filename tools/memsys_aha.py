#!/usr/bin/env python3
"""AHA's memory fabric and coherent fabric, generated from an AXIS description.

`docs/memory_system_design.md` §4. A `defmemsys` is lowered, from its
`axis.memsys.v1` manifest alone, into the configurations AHA's own generators
take -- and then AHA's generators are run on them:

  * the MEMORY FABRIC -- `hardware/noc_ip`'s `NoCIPConfig`: the mesh, its
    virtual channels and buffers, the address and data widths, and one
    `AddressRegion(base, size, x, y)` per region, at its target's place;
  * the COHERENT FABRIC -- `aha/chi`'s `ChiIPConfig`: the CHI link widths and
    credits, the requester table, the protocol mechanisms, and one
    `HomeRegion(base, size, home_id)` per coherent region -- plus the CHI
    `Topology` the home sits in and the `MoesiConfig` (or MSI
    `CoherenceConfig`) over the private caches;
  * the MEMORY -- `aha/dram`'s timing profile for the DRAM's `standard`.

With `--out DIR` it writes each configuration, AHA's IP manifests for them
(the proofs run at THIS configuration, `run_measure` off: measurement needs
yosys and is AHA's to report), and the netlists -- the composed CHI node and
the address-routed mesh -- as Verilog.

⚠️ The lowering is AXIS's; everything after it is AHA's. This file decides
what a description MEANS to AHA -- which coordinate a region routes to, which
id a home is -- and `memsys_aha_check.py` holds that meaning against AHA's own
decoders, metric and profiles. It does not re-implement a router.

Needs a PCE checkout (`AXIS_PCE_ROOT`, default ../pce) with its vendored
PyRTL; without one, the lowering still runs and the generation declines.

Usage: tools/memsys_aha.py examples/memory_system.axisl [--out DIR] [--no-proofs]
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED, axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
PCE_ROOT = Path(os.environ.get("AXIS_PCE_ROOT", AXIS_ROOT.parent / "pce"))

#: AHA's CHI mechanisms a description may name. The protocol brings its own
#: (`moesi`); a mesh brings dimension-order `routing`, because that is the
#: routing the description's hop counts assume.
PROTOCOL_FEATURES = {"moesi": {"moesi"}, "mesi": set(), "msi": set(), "none": set()}


def manifest_of(axis_file: Path) -> dict:
    out = subprocess.run([*axis_prefix(), "emit-memsys-json", str(axis_file)],
                         capture_output=True, text=True, check=True, cwd=AXIS_ROOT)
    return json.loads(out.stdout)


def lower(system: dict) -> dict:
    """One `axis.memsys.v1` system as AHA's configurations, in plain data."""
    ic, co = system["interconnect"], system["coherence"]
    nodes = {n["name"]: n for n in system["nodes"]}
    regions = system["address_map"]
    coherent = co["protocol"] != "none"
    noc = {
        "rows": ic["rows"], "cols": ic["cols"],
        "num_vcs": ic["virtual_channels"], "buffer_depth": ic["buffer_depth"],
        "addr_width": ic["address_bits"], "data_width": ic["flit_bits"],
        "regions": [{"base": r["base"], "size": r["size"], "x": r["target_x"], "y": r["target_y"]}
                    for r in regions],
    }
    features = set(co["features"]) | PROTOCOL_FEATURES.get(co["protocol"], set())
    if ic["topology"] == "mesh":
        features.add("routing")
    chi = {
        "node_id_bits": co["node_id_bits"], "txn_id_bits": co["txn_id_bits"],
        "addr_bits": ic["address_bits"], "data_bits": ic["flit_bits"],
        "credit_depth": co["credit_depth"], "table_depth": co["table_depth"],
        "features": sorted(features),
        "regions": [{"base": r["base"], "size": r["size"], "home_id": r["home_id"]}
                    for r in regions if not r["uncached"] and r["home_id"] is not None],
    } if coherent else None
    homes = sorted({r["home_id"] for r in regions if r["home_id"] is not None})
    square = ic["topology"] in ("mesh", "torus") and ic["rows"] == ic["cols"]
    topology = None
    if coherent and len(homes) == 1 and (square or ic["topology"] == "ring"):
        topology = {"kind": ic["topology"], "size": ic["cols"], "home_node": homes[0]}
    private = [n for n in system["nodes"] if n["core"] and n["kind"] == "cache"]
    coherence = {"protocol": co["protocol"], "n_caches": len(private)} if coherent else None
    drams = [{"node": n["name"], "standard": n["dram"]["standard"], **{k: n["dram"][k] for k in
              ("tck_ps", "tcl", "trcd", "trp", "tras")}} for n in system["nodes"] if "dram" in n]
    # Every place that has a next level, and how far it is -- what AHA's own
    # topology metric must agree with.
    hops = [{"from": n["id"], "to": nodes[n["next"]]["id"], "hops": n["hops_to_next"]}
            for n in system["nodes"] if n["next"]]
    return {"system": system["name"], "noc": noc, "chi": chi, "topology": topology,
            "coherence": coherence, "dram": drams, "hops": hops}


#: The part that runs inside PCE, on the lowered data. It builds AHA's
#: configuration objects -- whose own validation is the first check -- and
#: either reports what AHA says about them or generates the artifacts.
RUNNER = textwrap.dedent(r'''
    import json, sys
    sys.path.insert(0, "third_party/pyrtl"); sys.path.insert(0, ".")
    import pyrtl
    from hardware.noc_ip.ip_gen import AddressRegion, NoCIPConfig, addr_to_coord, addr_decoder
    from aha.chi.ip_gen import ChiIPConfig, HomeRegion, chi_addr_to_home, cosim_home_decoder
    from aha.chi.features import optional_features, rtl_features
    from aha.chi.dct_mesh import Topology
    from aha.dram.timing import profile

    job = json.load(sys.stdin)
    low, mode, out = job["lowered"], job["mode"], job.get("out")
    report = {"system": low["system"], "noc": {}, "chi": {}, "topology": {}, "coherence": {}, "dram": []}

    n = low["noc"]
    noc = NoCIPConfig(rows=n["rows"], cols=n["cols"], num_vcs=n["num_vcs"], buffer_depth=n["buffer_depth"],
                      addr_width=n["addr_width"], data_width=n["data_width"],
                      regions=[AddressRegion(**r) for r in n["regions"]])
    probes = []
    for r in n["regions"]:
        probes += [r["base"], r["base"] + r["size"] // 2, r["base"] + r["size"] - 1]
        if r["base"] > 0: probes.append(r["base"] - 1)
        probes.append(r["base"] + r["size"])
    probes = sorted({p for p in probes if p < (1 << n["addr_width"])})
    # AHA's synthesizable decoder, simulated, at every boundary -- and its model.
    pyrtl.reset_working_block()
    a = pyrtl.Input(n["addr_width"], "addr"); x, y, hit = addr_decoder(noc, a)
    ox = pyrtl.Output(len(x), "x"); ox <<= x; oy = pyrtl.Output(len(y), "y"); oy <<= y
    oh = pyrtl.Output(1, "hit"); oh <<= hit
    sim = pyrtl.Simulation()
    rtl = {}
    for p in probes:
        sim.step({"addr": p}); t = sim.inspect
        rtl[p] = [t("x"), t("y")] if t("hit") else None
    model = {p: (list(addr_to_coord(noc, p)) if addr_to_coord(noc, p) else None) for p in probes}
    report["noc"] = {"probes": probes, "rtl": {str(k): v for k, v in rtl.items()},
                     "model": {str(k): v for k, v in model.items()}}

    c = low["chi"]
    if c is not None:
        known = {f.name for f in optional_features()}
        report["chi"]["unknown_features"] = sorted(set(c["features"]) - known)
        chi = ChiIPConfig(node_id_bits=c["node_id_bits"], txn_id_bits=c["txn_id_bits"], addr_bits=c["addr_bits"],
                          data_bits=c["data_bits"], credit_depth=c["credit_depth"], table_depth=c["table_depth"],
                          features=frozenset(set(c["features"]) & known),
                          regions=[HomeRegion(**r) for r in c["regions"]])
        report["chi"]["home"] = {str(p): chi_addr_to_home(chi, p) for p in probes if p < (1 << c["addr_bits"])}
        report["chi"]["decoder_cosim"] = cosim_home_decoder(chi)

    t = low["topology"]
    if t is not None:
        topo = Topology(name=f"{low['system']}", kind=t["kind"], size=t["size"], home_node=t["home_node"])
        report["topology"] = {"home": topo.home, "n_nodes": topo.n_nodes,
                              "dist": [[h["from"], h["to"], topo.dist(h["from"], h["to"])] for h in low["hops"]]}

    co = low["coherence"]
    if co is not None and co["protocol"] == "moesi":
        from aha.chi.moesi import MoesiConfig, prove_moesi_exhaustive
        report["coherence"] = {"proof": prove_moesi_exhaustive(MoesiConfig(name=low["system"], n_caches=co["n_caches"]))}
    elif co is not None and co["protocol"] == "msi":
        from aha.chi.coherence import CoherenceConfig, prove_swmr_exhaustive
        report["coherence"] = {"proof": prove_swmr_exhaustive(CoherenceConfig(name=low["system"], n_caches=co["n_caches"]))}
    elif co is not None:
        report["coherence"] = {"declined": f"AHA has no {co['protocol']} directory"}

    for d in low["dram"]:
        try:
            p = profile(d["standard"])
            report["dram"].append({"node": d["node"], "standard": d["standard"],
                                   "tck_ps": round(p.tck_ns * 1000), "tcl": p.CL, "trcd": p.tRCD,
                                   "trp": p.tRP, "tras": p.tRAS})
        except KeyError as e:
            report["dram"].append({"node": d["node"], "standard": d["standard"], "unknown": str(e)})

    if mode == "generate":
        import dataclasses, pathlib
        from hardware.noc_ip.ip_gen import generate_ip_manifest
        from aha.chi.ip_gen import generate_chi_ip_manifest
        from aha.chi.chi_node_rtl import ChiNodeConfig, build_chi_node
        from aha.chi.link import ChiConfig
        d = pathlib.Path(out); d.mkdir(parents=True, exist_ok=True)
        proofs = job["proofs"]
        written = []
        def put(name, text):
            (d / name).write_text(text); written.append(name)
        put("noc_ip.txt", generate_ip_manifest(noc, run_proofs=proofs, run_measure=False).render())
        if c is not None:
            put("chi_ip.txt", generate_chi_ip_manifest(chi, run_proofs=proofs, run_measure=False).render())
            rtl_names = {f.name for f in rtl_features()} - {"link", "bridge", "coherence"}
            pyrtl.reset_working_block()
            build_chi_node(ChiNodeConfig(features=frozenset(chi.features) & rtl_names,
                                         credit_depth=chi.credit_depth, table_depth=chi.table_depth,
                                         chi=chi.chi_config()))
            import io
            buf = io.StringIO(); pyrtl.output_to_verilog(buf, add_reset=True); put("chi_node.v", buf.getvalue())
        from hardware.noc_ip.mesh_fabric import build_mesh_fabric
        from hardware.noc_ip.niu import NIUConfig
        pyrtl.reset_working_block()
        # The NIU's data path is the flit's; its address, the NoC's.
        niu = NIUConfig(addr_width=n["addr_width"], data_width=n["data_width"], link_depth=n["buffer_depth"])
        build_mesh_fabric(niu, [(r["base"], r["size"], r["x"], r["y"]) for r in n["regions"]],
                          rows=n["rows"], cols=n["cols"], depth=n["buffer_depth"])
        import io
        buf = io.StringIO(); pyrtl.output_to_verilog(buf, add_reset=True); put("noc_mesh.v", buf.getvalue())
        put("configs.json", json.dumps({"noc": dataclasses.asdict(noc),
                                        "chi": dataclasses.asdict(chi) if c is not None else None,
                                        "dram": report["dram"]}, default=list, indent=2))
        report["written"] = written
    print(json.dumps(report))
''')


def run_in_pce(lowered: dict, mode: str, out: str | None = None, proofs: bool = True) -> dict | None:
    if not (PCE_ROOT / "third_party" / "pyrtl").is_dir():
        return None
    job = json.dumps({"lowered": lowered, "mode": mode, "out": out, "proofs": proofs})
    run = subprocess.run([sys.executable, "-c", RUNNER], input=job, capture_output=True,
                         text=True, cwd=PCE_ROOT)
    if run.returncode != 0:
        raise RuntimeError(f"AHA refused the lowered configuration:\n{run.stderr.strip()[-1500:]}")
    return json.loads(run.stdout.strip().splitlines()[-1])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--out", type=Path, help="write AHA's configurations, manifests and netlists here")
    parser.add_argument("--no-proofs", action="store_true", help="skip AHA's proofs in the IP manifests")
    args = parser.parse_args()
    manifest = manifest_of(args.axis_file)
    for system in manifest["systems"]:
        lowered = lower(system)
        if not args.out:
            print(json.dumps(lowered, indent=2))
            continue
        target = args.out / system["name"]
        try:
            report = run_in_pce(lowered, "generate", str(target.resolve()), not args.no_proofs)
        except RuntimeError as error:
            print(f"  FAIL {system['name']}: {error}")
            return FAILED
        if report is None:
            print(f"  DECLINED no PCE checkout at {PCE_ROOT}")
            return DECLINED
        print(f"  {system['name']}: wrote {', '.join(report['written'])} to {target}")
    return PASSED


if __name__ == "__main__":
    sys.exit(main())
