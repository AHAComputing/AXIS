#!/usr/bin/env python3
"""A declared configuration and the instruction that establishes it must agree. Gate.

`defconfig` adds no semantics. An instruction that reads a 64-byte block and
writes sixteen configuration slots validates and emits through every backend
without it -- measured before the construct was designed. What it adds is a
SECOND STATEMENT of a layout the semantics already imply, and the only thing
that makes a second statement worth having is that the two are required to
agree.

So this gate is about refusals, and about the manifest a consumer reads:

  1. **the corpus agrees with itself.** The declared offsets and the offsets
     the instruction loads from match, which is what `axis check` enforces and
     what this confirms is actually being enforced rather than skipped;
  2. **a disagreement is refused**, naming both bytes. Checked by moving one
     load by a single byte;
  3. **a value the architecture does not allow is refused**, naming it. A
     configuration a machine cannot be put into is not a configuration;
  4. **an uninstantiated field is refused.** A description is elaborated at one
     configuration, so it names one;
  5. **overlapping fields are refused**, since two fields at one byte are two
     answers to one question;
  6. **the manifest publishes the layout**: every declared field with its
     offset, width and legal values, the instantiation, and which instruction
     establishes it -- because reading byte offsets out of an effect expression
     is the thing this replaces.

⚠️ Property 6 is not decoration. The first version of the canonical emitter
DROPPED both `defconfig` and `configures`, and the round-tripped document still
validated -- a declaration that is silently lost round-trips to a document that
is still correct, just weaker. `axis check` cannot catch that; a reader of the
emitted form can.

Usage: tools/config_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


def refuses(workdir: Path, source: str, name: str, expected: str) -> str | None:
    """Write a perturbed document and require a refusal mentioning `expected`."""
    path = workdir / f"{name}.axisl"
    path.write_text(source)
    result = run([*axis_prefix(), "check", str(path)])
    message = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        return f"{name}: accepted, and should not have been"
    if expected not in message:
        return f"{name}: refused for the wrong reason: {message[:160]}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    if "(defconfig " not in source:
        print("no memory-resident configuration in this corpus")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_config_"))
    failures = []

    # 1. the corpus agrees with itself
    checked = run([*axis_prefix(), "check", str(args.axis_file)])
    if checked.returncode != 0:
        failures.append(f"the corpus does not validate: "
                        f"{(checked.stdout + checked.stderr).strip()[:160]}")

    # 2. a load one byte out
    failures.append(refuses(
        workdir, source.replace("(add i64 rs1 48)", "(add i64 rs1 47)", 1),
        "moved", "declares byte 48"))
    # 3. a value the architecture does not allow
    failures.append(refuses(
        workdir, source.replace("(tile0_rows 16)", "(tile0_rows 15)", 1),
        "illegal", "not one of its legal values"))
    # 4. a field left uninstantiated
    failures.append(refuses(
        workdir, source.replace(" (tile1_rows 16)", "", 1),
        "partial", "uninstantiated"))
    # 5. two fields at one byte
    failures.append(refuses(
        workdir, source.replace("(field tile1_rows (at 49)", "(field tile1_rows (at 48)", 1),
        "overlap", "overlap at byte 48"))
    # ...and a field the instruction does not establish at all
    failures.append(refuses(
        workdir,
        source.replace("      (setstate tile1_rows (load i8 unsigned (add i64 rs1 49)) i8)", "", 1),
        "missing", "0 time(s)"))

    # 6. the manifest publishes it
    manifest_path = workdir / "legality.json"
    emitted = run([*axis_prefix(), "emit-legality-json", str(args.axis_file),
                   "-o", str(manifest_path)])
    if emitted.returncode != 0:
        failures.append("the legality manifest could not be emitted")
    else:
        manifest = json.loads(manifest_path.read_text())
        configs = manifest.get("configs") or []
        if not configs:
            failures.append("the manifest publishes no configuration")
        else:
            config = configs[0]
            declared = set(re.findall(r"\(field (\w+) \(at (\d+)\)", source))
            published = {(field["name"], str(field["at"])) for field in config["fields"]}
            if declared != published:
                failures.append(f"the manifest's fields are {sorted(published)} and the "
                                f"document declares {sorted(declared)}")
            if not config.get("instantiate"):
                failures.append("the manifest publishes no instantiation")
            if not config.get("established_by"):
                failures.append("the manifest does not say which instruction establishes it")

    # ...and the canonical form keeps it, which a check of the round trip
    # cannot notice on its own: a dropped declaration still validates.
    canonical = workdir / "canonical.axisl"
    if run([*axis_prefix(), "emit-lisp", str(args.axis_file),
            "-o", str(canonical)]).returncode == 0:
        text = canonical.read_text()
        if "(defconfig " not in text:
            failures.append("the canonical form drops the configuration")
        if "(configures " not in text:
            failures.append("the canonical form drops `configures`")

    failures = [failure for failure in failures if failure]
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"5 refusals, the published layout and the canonical round trip")
    print("configuration: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
