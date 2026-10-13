#!/usr/bin/env python3
"""Cross-repo smoke check: AXIS bundles load through PCE's real consumers.

This is gate 1 of PCE BACKLOG-012 (retire software/pce-adl). It emits a
bundle from the AXIS examples and loads it through:
  - aha.isa.adl_loader.load_adl_bundle_dir (strict schema + field contract)
  - aha.optisynth.adl_bridge projections (EnginePassProfile, cost overrides,
    intrinsic names)

Usage: tools/pce_smoke_check.py [--pce-root PATH] [--axis-file FILE]

The PCE repo defaults to ../pce relative to the AXIS repo root, overridable
with --pce-root or the AXIS_PCE_ROOT environment variable.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--pce-root",
        type=Path,
        default=Path(os.environ.get("AXIS_PCE_ROOT", AXIS_ROOT.parent / "pce")),
    )
    parser.add_argument(
        "--axis-file",
        type=Path,
        default=AXIS_ROOT / "examples" / "rvmt_xpce.axisl",
    )
    args = parser.parse_args()

    if not (args.pce_root / "aha" / "isa" / "adl_loader.py").is_file():
        print(f"PCE repo not found at {args.pce_root} (use --pce-root)", file=sys.stderr)
        return 2

    bundle_dir = Path(tempfile.mkdtemp(prefix="axis_bundle_"))
    subprocess.run(
        [*axis_prefix(), "emit-bundle", str(args.axis_file),
         "-o", str(bundle_dir)],
        check=True,
        cwd=AXIS_ROOT,
    )

    sys.path.insert(0, str(args.pce_root))
    from aha.isa.adl_loader import load_adl_bundle_dir  # noqa: E402

    loaded = load_adl_bundle_dir(bundle_dir)
    instructions = loaded["custom_instructions"]
    assert instructions, "bundle contained no custom instructions"
    for instruction in instructions:
        assert instruction.encoding is not None, (
            f"{instruction.mnemonic} lost its encoding — from_adl would raise"
        )
        assert instruction.encoding.opcode is not None
    assert loaded["aha_metadata"]["schema"] == "pce-adl.aha-instructions.v1"
    assert loaded["manifest"], "manifest.json missing or empty"
    assert loaded["rvmt_extension_manifest"], "rvmt_extension_manifest.json missing"
    print(f"adl_loader: OK ({len(instructions)} instructions: "
          f"{', '.join(i.mnemonic for i in instructions)})")

    from aha.optisynth import adl_bridge  # noqa: E402

    profile = adl_bridge.engine_profile_from_bundle(loaded)
    costs = adl_bridge.cost_overrides_from_bundle(loaded)
    intrinsics = adl_bridge.intrinsic_names_from_bundle(loaded)
    assert intrinsics, "no intrinsic names projected"
    print(f"adl_bridge: OK (profile={type(profile).__name__}, "
          f"{len(costs)} cost overrides, intrinsics={sorted(intrinsics)})")

    # ADL.2: rewrite rules derived from formal_semantics. AXIS emits the
    # OptiSynth dialect into aha_instructions.json, so every instruction
    # marked optisynth_compatible must yield a rule here.
    rules, skipped = adl_bridge.extract_rewrite_rules_from_bundle(loaded)
    compatible = [
        inst["mnemonic"]
        for inst in _raw_instructions(bundle_dir)
        if inst.get("optisynth_compatible")
    ]
    rule_names = [rule.name for rule in rules]
    print(f"adl.2 rewrite rules: {len(rules)} derived ({', '.join(rule_names)})")
    if skipped:
        print(f"adl.2 skipped: {skipped}")
    missing = [
        mnemonic
        for mnemonic in compatible
        if not any(mnemonic.lower() in name for name in rule_names)
    ]
    assert not missing, (
        f"instructions marked optisynth_compatible derived no rule: {missing}"
    )

    # Top of the evidence ladder: register the intrinsic axioms from the
    # bundle, then require every derived rule to be Z3-PROVEN.
    try:
        import z3  # noqa: F401
    except ImportError:
        print("adl.2 proof gate: SKIPPED (no z3 in this environment)")
    else:
        registered, _ = adl_bridge.register_intrinsic_axioms_from_bundle(loaded)
        spec, _ = adl_bridge.pass_spec_from_bundle(loaded, require_verified=True)
        proven = [rule.name for rule in spec.rules]
        unproven = sorted(set(rule_names) - set(proven))
        assert not unproven, f"rules failed the Z3 proof gate: {unproven}"
        print(f"adl.2 proof gate: {len(proven)} rules Z3-PROVEN "
              f"({len(registered)} axioms registered)")

    print("PCE SMOKE CHECK PASSED")
    return 0


def _raw_instructions(bundle_dir: Path) -> list:
    import json

    payload = json.loads((bundle_dir / "aha_instructions.json").read_text())
    return payload.get("instructions", [])


if __name__ == "__main__":
    sys.exit(main())
