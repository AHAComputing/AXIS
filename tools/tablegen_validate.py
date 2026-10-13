#!/usr/bin/env python3
"""Validate the emitted LLVM intrinsics with llvm-tblgen (when available).

AXIS emits three TableGen artifacts:

  * axis_intrinsics.td -- llvm.axis.* intrinsic declarations,
  * axis_patterns.td   -- SelectionDAG Pat<> rules mapping IR to those intrinsics,
  * instructions.td    -- RVInst-derived instruction records.

The intrinsics are the self-contained piece: they depend only on LLVM's own
`llvm/IR/Intrinsics.td`, so llvm-tblgen can fully parse and type-check them and
emit the intrinsic enum/impl. This tool does exactly that -- it wraps the emitted
axis_intrinsics.td behind `include "llvm/IR/Intrinsics.td"` and runs the intrinsic
emitters; a clean run (and every emitted `int_axis_*` appearing in the generated
enum) proves the declarations are valid LLVM TableGen, closing the "intrinsics are
structurally emitted but never run through tblgen" gap.

instructions.td and axis_patterns.td reference the RISC-V target's TableGen tree
(RVInst, GPR, InstFormatR, DAG nodes); fully checking them needs an LLVM *source*
build tree, which this tool does not assume. It reports them as not-validated here.

The tool SKIPs cleanly (exit 0) when llvm-tblgen or LLVM's TableGen include dir
cannot be found, so it is safe to run anywhere.

Usage: tools/tablegen_validate.py [input.axisl]

Environment overrides:
  AXIS_LLVM_TBLGEN   path to the llvm-tblgen binary
  AXIS_LLVM_INCLUDE  LLVM include dir containing llvm/IR/Intrinsics.td
  LLVM_CONFIG        llvm-config binary to query (default: llvm-config)

Requires: cargo (run from the AXIS repo root). Uses llvm-tblgen if present.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# Common Homebrew / system locations to probe when llvm-config is absent.
BREW_PREFIXES = ("/opt/homebrew/opt/llvm", "/usr/local/opt/llvm")


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def llvm_config(field: str):
    cfg = os.environ.get("LLVM_CONFIG", "llvm-config")
    if not shutil.which(cfg):
        for prefix in BREW_PREFIXES:
            candidate = Path(prefix) / "bin" / "llvm-config"
            if candidate.exists():
                cfg = str(candidate)
                break
        else:
            return None
    try:
        out = subprocess.run([cfg, field], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, OSError):
        return None
    return out.stdout.strip() or None


def find_tblgen():
    override = os.environ.get("AXIS_LLVM_TBLGEN")
    if override and Path(override).exists():
        return override
    found = shutil.which("llvm-tblgen")
    if found:
        return found
    bindir = llvm_config("--bindir")
    candidates = []
    if bindir:
        candidates.append(Path(bindir) / "llvm-tblgen")
    candidates += [Path(p) / "bin" / "llvm-tblgen" for p in BREW_PREFIXES]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def find_include_dir():
    """An include dir that contains llvm/IR/Intrinsics.td."""
    def ok(path):
        return path and (Path(path) / "llvm" / "IR" / "Intrinsics.td").exists()

    override = os.environ.get("AXIS_LLVM_INCLUDE")
    if ok(override):
        return override
    inc = llvm_config("--includedir")
    if ok(inc):
        return inc
    for prefix in BREW_PREFIXES:
        candidate = Path(prefix) / "include"
        if ok(candidate):
            return str(candidate)
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "zbb_like.axisl")
    args = parser.parse_args()

    tblgen = find_tblgen()
    if not tblgen:
        print("SKIP: llvm-tblgen not found "
              "(set AXIS_LLVM_TBLGEN or install LLVM)")
        return 0
    include_dir = find_include_dir()
    if not include_dir:
        print("SKIP: LLVM TableGen include dir (llvm/IR/Intrinsics.td) not found "
              "(set AXIS_LLVM_INCLUDE)")
        return 0

    workdir = Path(tempfile.mkdtemp(prefix="axis_tblgen_"))
    intrinsics = workdir / "axis_intrinsics.td"
    emit(args.axis_file, "emit-llvm-intrinsics", intrinsics)

    # The emitted intrinsic short names we expect to survive tblgen.
    names = sorted(set(re.findall(r"def\s+(int_axis_\w+)\s*:", intrinsics.read_text())))
    if not names:
        print("no llvm.axis.* intrinsics emitted (nothing to validate)")
        return 0

    wrapper = workdir / "wrapper.td"
    wrapper.write_text(
        'include "llvm/IR/Intrinsics.td"\n'
        f'include "{intrinsics}"\n'
    )

    print(f"llvm-tblgen: {tblgen}")
    print(f"include dir: {include_dir}")
    failures = 0
    enum_stdout = ""
    # Target intrinsics carry TargetPrefix="axis"; --intrinsic-prefix=axis makes
    # the enum/impl emitters emit this target's records (and type-check them).
    passes = (
        ("-gen-intrinsic-enums", ["--intrinsic-prefix=axis"]),
        ("-gen-intrinsic-impl", ["--intrinsic-prefix=axis"]),
    )
    for gen, extra in passes:
        result = subprocess.run(
            [tblgen, gen, *extra, "-I", include_dir, str(wrapper)],
            capture_output=True, text=True,
        )
        status = "ok" if result.returncode == 0 else "FAIL"
        print(f"  {gen}: {status}")
        if result.returncode != 0:
            failures += 1
            sys.stderr.write(result.stderr)
        elif gen == "-gen-intrinsic-enums":
            enum_stdout = result.stdout

    # Each emitted intrinsic (int_axis_andn) must appear as an enum member
    # (axis_andn), proving tblgen accepted and registered every declaration.
    missing = [full for full in names if full[len("int_"):] not in enum_stdout]
    if enum_stdout:
        if missing:
            print(f"  enum coverage: {len(names) - len(missing)}/{len(names)} "
                  f"(missing: {', '.join(missing)})")
            failures += 1
        else:
            print(f"  enum coverage: {len(names)}/{len(names)} intrinsics present")

    print("NOTE: instructions.td and axis_patterns.td reference the RISC-V target "
          "TableGen tree (RVInst/GPR/DAG nodes) and need an LLVM source build to "
          "validate; not checked here.")

    ok = failures == 0
    print("LLVM intrinsics tblgen-valid: PASS" if ok else "LLVM intrinsics tblgen-valid: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
