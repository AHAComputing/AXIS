#!/usr/bin/env python3
"""Prove the Python manifest says what the JSON manifests say.

`emit-python` is the only generated artifact that is a *second representation
of another one*: `RVMT_EXTENSION_MANIFEST` is `emit-rvmt-json` written as Python
literals, and `PCE_ADL_MANIFEST` is `emit-json`. A duplicate that nothing
compares is a duplicate that can drift, and this one was checked by asserting
that a few substrings appeared in the text -- which cannot see a renamed key, a
dropped instruction, or a field that stopped being emitted on one side.

So the module is imported, not grepped, and both dicts are required to equal the
JSON they mirror. Importing is itself part of the check: the previous assertions
would have passed on a file that was not valid Python at all.

The two dicts differ from each other, which is what makes this discriminating --
a lowering that returned the same manifest twice would fail here rather than
look like agreement.

Usage: tools/manifest_python_check.py [input.axisl ...]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

# Which Python name mirrors which JSON emitter, and the schema each declares.
PAIRS = (
    ("RVMT_EXTENSION_MANIFEST", "emit-rvmt-json", None),
    ("PCE_ADL_MANIFEST", "emit-json", "AXIS_SCHEMA"),
)

DEFAULT_CORPORA = (
    "rv64i.axisl",
    "rv32i.axisl",
    "xpce_manifest.axisl",
    "accelerator_descriptor.axisl",
    "aarch64_translation_seed.axisl",
    # Its rationale carries the words `true`, `false` and `null` as English,
    # which is the case the rendering used to corrupt.
    "masks.axisl",
)


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True, cwd=AXIS_ROOT,
    )


def differences(python_value, json_value, path="") -> list[str]:
    """Where the two disagree, by path, rather than that they disagree."""
    if type(python_value) is not type(json_value):
        # JSON has no tuples and Python literals here should not either, so a
        # type split is a real difference rather than a serialization artifact.
        return [f"{path or '<root>'}: {type(python_value).__name__} vs "
                f"{type(json_value).__name__}"]
    if isinstance(python_value, dict):
        out = []
        for key in sorted(set(python_value) | set(json_value)):
            where = f"{path}.{key}" if path else str(key)
            if key not in python_value:
                out.append(f"{where}: missing from the Python manifest")
            elif key not in json_value:
                out.append(f"{where}: missing from the JSON manifest")
            else:
                out.extend(differences(python_value[key], json_value[key], where))
            if len(out) > 20:
                break
        return out
    if isinstance(python_value, list):
        if len(python_value) != len(json_value):
            return [f"{path}: {len(python_value)} entries vs {len(json_value)}"]
        out = []
        for index, (left, right) in enumerate(zip(python_value, json_value)):
            out.extend(differences(left, right, f"{path}[{index}]"))
            if len(out) > 20:
                break
        return out
    if python_value != json_value:
        return [f"{path}: {python_value!r} vs {json_value!r}"]
    return []


def check(axis_file: Path) -> int:
    workdir = Path(tempfile.mkdtemp(prefix="axis_manifest_"))
    module_path = workdir / "axis_manifest.py"
    emit(axis_file, "emit-python", module_path)

    spec = importlib.util.spec_from_file_location("axis_manifest", module_path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except SyntaxError as error:
        print(f"FAIL {axis_file.name}: emitted Python does not parse: {error}")
        return 1

    failures = 0
    for name, command, schema_name in PAIRS:
        if not hasattr(module, name):
            print(f"FAIL {axis_file.name}: the module defines no {name}")
            failures += 1
            continue
        target = workdir / f"{command}.json"
        emit(axis_file, command, target)
        found = differences(getattr(module, name), json.loads(target.read_text()))
        if found:
            print(f"FAIL {axis_file.name}: {name} != {command}")
            for line in found[:10]:
                print(f"    {line}")
            failures += 1
        if schema_name is not None:
            stated = getattr(module, schema_name, None)
            carried = json.loads(target.read_text()).get("schema")
            if carried is not None and stated != carried:
                print(f"FAIL {axis_file.name}: {schema_name} is {stated!r} but "
                      f"{command} carries {carried!r}")
                failures += 1

    # The two must not be the same object rendered twice: if they were, the
    # equality above would hold for a lowering that had lost one of them.
    if (hasattr(module, "RVMT_EXTENSION_MANIFEST")
            and hasattr(module, "PCE_ADL_MANIFEST")
            and module.RVMT_EXTENSION_MANIFEST == module.PCE_ADL_MANIFEST):
        print(f"FAIL {axis_file.name}: both manifests are identical, so one of "
              f"them is not being emitted")
        failures += 1
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    args = parser.parse_args()
    files = args.axis_files or [AXIS_ROOT / "examples" / name
                                for name in DEFAULT_CORPORA]

    failures = sum(check(path) for path in files)
    print(f"{len(files)} corpus/corpora checked, {failures} failure(s)")
    print("python manifest == json manifests: "
          + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
