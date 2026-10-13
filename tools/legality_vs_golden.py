#!/usr/bin/env python3
"""Legality cross-check: the mode-legality manifest vs decode table vs executor.

Emits the mode-legality manifest, decode table, manifest.json, fixtures, and the
Python executor from a mode document. For every mode value and every instruction
word in the fixtures, it derives the mode-aware decode decision three ways:

  * from the legality manifest — scan that mode's `legal` table for a
    match/mask hit;
  * independently — among all instructions whose *global* decode-table
    match/mask hits the word, pick the one legal in that mode per manifest.json's
    per-instruction `modes` (empty = all modes);
  * from the executor — `axis_exec.step(word, ..., mode=)`: the mnemonic it
    runs, or illegal-in-mode when it takes the trap path (P4).

and requires all three to agree, including the illegal-in-mode case. This proves
the per-mode legality tables and the executor's mode-aware dispatch derive from
the same encoding resolution, and that cross-mode encoding reuse resolves to the
right instruction per mode.

Usage: tools/legality_vs_golden.py <input.axisl>

Requires: cargo (run from the AXIS repo root).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def hexval(text):
    return int(text, 16)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_legality_"))
    legality_path = workdir / "mode_legality_manifest.json"
    decode_path = workdir / "decode_table.json"
    manifest_path = workdir / "manifest.json"
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    emit(args.axis_file, "emit-legality-json", legality_path)
    emit(args.axis_file, "emit-decode-json", decode_path)
    emit(args.axis_file, "emit-json", manifest_path)
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")

    legality = json.loads(legality_path.read_text())
    if legality["mode"] is None:
        print("no mode block; nothing to check")
        return 0

    import importlib
    sys.path.insert(0, str(workdir))
    axis_exec = importlib.import_module("axis_exec")

    # Global decode table: mnemonic -> (match, mask).
    decode = {
        e["mnemonic"]: (hexval(e["match"]), hexval(e["mask"]))
        for e in json.loads(decode_path.read_text())["instructions"]
    }
    # Per-instruction legal modes from manifest.json (missing "modes" = all).
    manifest = json.loads(manifest_path.read_text())
    all_modes = [v["name"] for v in legality["mode"]["values"]]
    inst_modes = {
        i["mnemonic"]: i.get("modes", all_modes) for i in manifest["instructions"]
    }
    # The legality manifest's per-mode legal tables.
    legal_tables = {
        m["mode"]: [(e["mnemonic"], hexval(e["match"]), hexval(e["mask"])) for e in m["legal"]]
        for m in legality["modes"]
    }

    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])
    checks = failures = 0
    for mode_name in all_modes:
        for test in fixtures:
            word = hexval(test["encoded"])
            # From the manifest: which mnemonic does this mode's table decode to?
            from_manifest = [mn for (mn, ma, mk) in legal_tables[mode_name]
                             if word & mk == ma]
            # Independent: instructions whose global encoding matches, legal here.
            from_decode = [mn for mn, (ma, mk) in decode.items()
                           if word & mk == ma and mode_name in inst_modes.get(mn, all_modes)]
            # The executor's mode-aware decision (P4): the mnemonic it runs, or
            # None when it traps illegal-in-mode.
            out = axis_exec.step(word, {}, None, 0, mode_name)
            from_exec = [] if out is None or out.get("trap") == "illegal" else [out["mnemonic"]]

            checks += 1
            if not (sorted(from_manifest) == sorted(from_decode) == sorted(from_exec)):
                print(f"FAIL mode={mode_name} word={test['encoded']}: "
                      f"manifest {from_manifest} decode {from_decode} exec {from_exec}")
                failures += 1
            # Disjointness within a mode: at most one legal decode.
            if len(from_manifest) > 1:
                print(f"FAIL mode={mode_name} word={test['encoded']}: "
                      f"ambiguous legal decode {from_manifest}")
                failures += 1

    illegal = sum(
        1 for mode_name in all_modes for test in fixtures
        if not any(word & mk == ma for (_, ma, mk) in legal_tables[mode_name]
                   for word in [hexval(test["encoded"])])
    )
    print(f"{checks} (mode, word) checks, {illegal} illegal-in-mode, {failures} failures")
    ok = failures == 0
    print("legality == decode == exec: PASS" if ok else "legality == decode == exec: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
