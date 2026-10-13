#!/usr/bin/env python3
"""AXIS's netlists run in an existing core's custom-instruction slot. Gate.

URV, PCE's out-of-order RISC-V core, has an extension unit that dispatches
custom-0 instructions from a registry. The registry is filled from an ADL
bundle by `register_from_adl`, which takes the encodings from the bundle and
says of the hardware: "ADL alone cannot supply the hardware semantics callable
... the integrator provides the callables". Until now someone wrote them.

This is the whole seam, with nothing of AXIS's on PCE's side of it:

  * the **encodings and latencies** come from `emit-bundle`, read by PCE's own
    `aha.isa.adl_loader.load_adl_bundle_dir`;
  * the **semantics** come from `emit-hw-pyrtl`'s `extension_semantics`;
  * the **unit** is PCE's `URVExtensionUnit`, elaborated unmodified with PCE's
    vendored PyRTL, issued each instruction by its real opcode and function
    fields, and read at its completion port.

What completes is compared with the golden model. ⚠️ A unit that never
completes an instruction is a failure and not a skip: the registry matched
nothing, which is exactly the drift this exists to catch.

Then the same, **shared**. URV's unit calls one callable per extension and
muxes the results, so what the registry plugs in is a circuit each. With a
`shared_semantics` hook the unit hands its match wires to ONE datapath --
`extension_datapath`, the merged units -- and both are synthesised to count
what that saves. The hook is a small change to PCE's unit, drafted in
`tools/pce_patches/urv_extension_unit_shared.patch`. Where PCE does not have it
yet the patch is applied to a COPY of the unit in the gate's scratch directory
and that copy is elaborated; PCE's tree is never written.

Usage: tools/hw_urv_check.py <input.axisl> [--pce-root PATH] [--cases N]

Exits with a SKIP notice when there is no PCE checkout.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

# Runs inside PCE, with PCE's PyRTL. Exit status is the gate's.
DRIVER = r'''
import importlib.util, random, sys
sys.path.insert(0, "third_party/pyrtl"); sys.path.insert(0, ".")
import pyrtl
from aha.isa.adl_loader import load_adl_bundle_dir
from aha.compute_core.extensibility import ExtensionRegistry
from hardware.urv.design.execute.urv_extension_unit import URVExtensionUnit

work, cases, seed = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])

def load(name):
    spec = importlib.util.spec_from_file_location(name, f"{work}/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

golden, rtl = load("golden_model"), load("axis_hw")
XLEN = 32
instructions = load_adl_bundle_dir(f"{work}/bundle")["custom_instructions"]
semantics = rtl.extension_semantics(XLEN)
# What the unit can take today: a register destination and at most two
# sources. The rest are named, not dropped.
eligible, left_out = [], []
for ci in instructions:
    arity = len(rtl.INSTRUCTIONS.get(ci.mnemonic, {"inputs": [0] * 9})["inputs"])
    (eligible if ci.mnemonic in semantics and arity <= 2 else left_out).append(ci)
for ci in left_out:
    why = rtl.DECLINED.get(ci.mnemonic) or "more than two sources, or wider than the core"
    print(f"  {ci.mnemonic} is not bound -- {why}")
if not eligible:
    print("no instruction of this bundle fits the extension unit: SKIP")
    raise SystemExit(2)

registry = ExtensionRegistry()
registry.register_from_adl(eligible, semantics)
import inspect
unit_class = URVExtensionUnit
shared_how = "PCE's own unit"
if "shared_semantics" not in inspect.signature(URVExtensionUnit.__init__).parameters:
    spec = importlib.util.spec_from_file_location(
        "hardware.urv.design.execute._axis_shared_unit", f"{work}/urv_extension_unit.py")
    patched = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = patched
    spec.loader.exec_module(patched)
    unit_class = patched.URVExtensionUnit
    shared_how = "a patched copy of PCE's unit"

PORTS_IN = ("issue_valid", "issue_opcode", "issue_funct3", "issue_funct7", "issue_src0",
            "issue_src1", "issue_immediate", "issue_rob_idx", "issue_phys_dest",
            "issue_thread_id", "issue_writes_prf", "flush_valid")

def elaborate(shared):
    pyrtl.reset_working_block()
    if shared:
        unit = unit_class(registry, xlen=XLEN, rob_idx_bits=6, phys_dest_bits=7, name_prefix="hw",
                          shared_semantics=rtl.extension_datapath(
                              XLEN, [ext.descriptor.mnemonic for ext in registry]))
    else:
        unit = URVExtensionUnit(registry, xlen=XLEN, rob_idx_bits=6, phys_dest_bits=7,
                                name_prefix="hw")
    ins = {}
    for name in PORTS_IN:
        wire = getattr(unit, name)
        port = pyrtl.Input(wire.bitwidth, name)
        wire <<= port
        ins[name] = port
    for name in ("issue_ready", "complete_valid", "complete_rob_idx", "complete_data"):
        wire = getattr(unit, name)
        out = pyrtl.Output(wire.bitwidth, name)
        out <<= wire
    return ins

def gates(shared):
    elaborate(shared)
    # Lowered to gates and counted as lowered. PCE's PyRTL names synthesised
    # wires so that its optimiser's own sanity check rejects this block, and
    # both units are counted the same way, which is all a comparison needs.
    pyrtl.synthesize()
    return sum(1 for net in pyrtl.working_block().logic if net.op in "&|^~n")

def run(shared, label):
  ins = elaborate(shared)
  rng = random.Random(seed)
  sim = pyrtl.Simulation()
  idle = {name: 0 for name in ins}
  sim.step(idle)
  compared = failures = 0
  for ci in eligible:
      spec = golden.AXIS_SPECS[ci.mnemonic]
      params = spec["params"]
      vectors = list(golden.sample_vectors(ci.mnemonic, count=max(2, cases // 2)))
      while len(vectors) < cases:
          vectors.append(tuple(rng.getrandbits(width) for _, width in params))
      for vector in vectors:
          srcs = list(vector) + [rng.getrandbits(XLEN)] * (2 - len(vector))
          rob = rng.getrandbits(6)
          for _ in range(8):
              if sim.inspect("issue_ready"):
                  break
              sim.step(idle)
          sim.step({**idle, "issue_valid": 1, "issue_opcode": ci.encoding.opcode,
                    "issue_funct3": ci.encoding.func3 or 0,
                    "issue_funct7": ci.encoding.func7 or 0,
                    "issue_src0": srcs[0] & 0xffffffff, "issue_src1": srcs[1] & 0xffffffff,
                    "issue_rob_idx": rob, "issue_phys_dest": 1, "issue_writes_prf": 1})
          done = bool(sim.inspect("complete_valid"))
          for _ in range(ci.latency_cycles + 4):
              if done:
                  break
              sim.step(idle)
              done = bool(sim.inspect("complete_valid"))
          want = golden.evaluate(ci.mnemonic, *vector) & ((1 << spec["result_width"]) - 1)
          compared += 1
          if not done:
              print(f"  FAIL {ci.mnemonic}{vector}: the unit never completed it")
              failures += 1
              break
          got, tag = sim.inspect("complete_data"), sim.inspect("complete_rob_idx")
          if got != want or tag != rob:
              print(f"  FAIL {ci.mnemonic}{vector}: URV completes {got:#x} (rob {tag}), "
                    f"the golden model says {want:#x} (rob {rob})")
              failures += 1
              break
  print(f"{len(eligible)} instruction(s) bound into URV's extension unit ({label}), "
        f"{compared} issued, {failures} disagreeing")
  return failures

failures = run(False, "a circuit each")
failures += run(True, f"one shared datapath, in {shared_how}")
apart, merged = gates(False), gates(True)
print(f"  the unit is {merged} gates shared, {apart} with a circuit each")
# A size is owed only where AXIS shares an operator. Where its merger left
# every operator apart -- because sharing would not keep half of what it
# removes -- the shared datapath is the same circuits behind one result mux,
# and there is no saving to hold it to.
import json
shares = [f"{unit['name']}: {instance['class']}"
          for unit in json.load(open(f"{work}/axis_hw.json"))["units"]
          for instance in unit["instances"] if instance["nodes"] > 1]
if not shares:
    print("  AXIS shares no operator between these instructions, so no saving is claimed")
elif merged >= apart:
    print(f"  FAIL AXIS shares {', '.join(shares)} and URV's unit is no smaller for it")
    failures += 1
print("AXIS netlists in URV's extension slot == golden model:", "FAIL" if failures else "PASS")
raise SystemExit(1 if failures else 0)
'''


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--pce-root", type=Path,
                        default=Path(os.environ.get("AXIS_PCE_ROOT", AXIS_ROOT.parent / "pce")))
    parser.add_argument("--cases", type=int, default=16)
    parser.add_argument("--seed", type=int, default=20261004)
    args = parser.parse_args()
    needed = ["aha/isa/adl_loader.py", "hardware/urv/design/execute/urv_extension_unit.py",
              "third_party/pyrtl"]
    if not all((args.pce_root / path).exists() for path in needed):
        print(f"no PCE checkout with URV's extension unit at {args.pce_root}: SKIP")
        return DECLINED
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        (work / "bundle").mkdir()
        for command, output in (("emit-bundle", work / "bundle"),
                                ("emit-golden-python", work / "golden_model.py"),
                                ("emit-hw-pyrtl", work / "axis_hw.py"),
                                ("emit-hw-json", work / "axis_hw.json")):
            subprocess.run([*axis_prefix(), command, str(args.axis_file.resolve()), "-o",
                            str(output)], check=True, capture_output=True, cwd=AXIS_ROOT)
        # The drafted hook, applied to a copy: PCE's own file is only read.
        unit_source = args.pce_root / "hardware/urv/design/execute/urv_extension_unit.py"
        patch = AXIS_ROOT / "tools/pce_patches/urv_extension_unit_shared.patch"
        (work / "urv_extension_unit.py").write_text(unit_source.read_text())
        if "shared_semantics" not in unit_source.read_text():
            subprocess.run(["patch", "-s", str(work / "urv_extension_unit.py"), str(patch)],
                           check=True, capture_output=True)
        result = subprocess.run(
            [sys.executable, "-c", DRIVER, str(work), str(args.cases), str(args.seed)],
            cwd=args.pce_root, capture_output=True, text=True)
    print(result.stdout, end="")
    if result.returncode not in (0, 1, 2) or "== golden model:" not in result.stdout \
            and result.returncode != 2:
        print(result.stderr[:1500], result.stderr[-1500:], sep="\n...\n")
        print("the driver did not run inside PCE: FAIL")
        return 1
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
