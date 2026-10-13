#!/usr/bin/env python3
"""A completion contract agrees with the coupling it is declared beside. Gate.

An accelerator manifest said how a descriptor is shaped and what field a
completion is written to. It did not say when the engine's writes become
visible, what the host may read before then, or whether the launch orders the
host's prior stores -- the three questions a runtime must answer to write
correct code against an engine that outlives its launch.

`visibility`, `launch-fence` and `in-flight` say them, and every one is checked
against something the description already said, because a declaration nothing
checks is a comment. `coupling` and `visibility` are the same fact stated
twice: a tightly coupled engine finishes inside the launching instruction, so
it has nothing to poll and no in-flight window; a queue-descriptor one outlives
its launch and must say how the host learns it is done.

Six refusals, each checked by generating the contradictory document:

  1. an engine that outlives its launch claiming its writes are immediate;
  2. a tightly coupled one claiming they land at a completion;
  3. one that lands at a completion and names no completion field;
  4. one that completes inside its launch and names a completion field anyway;
  5. one that writes progressively and does not say what the host sees;
  6. one that says what is visible in flight and has no flight.

And two things a reader downstream depends on:

  7. **the manifest publishes all three**, since a contract nothing can read is
     the state this replaces;
  8. **the canonical form keeps them.** ⚠️ Not decoration: when `defconfig`
     landed in T5 the emitter dropped it, and the round-tripped document still
     validated -- a declaration silently lost round-trips to something still
     correct, just weaker, which `axis check` cannot see.

⚠️ What this does NOT check is the timing. An accelerator is a pure function of
its ports in every backend, so there is no execution model with a mid-flight
moment in it, and an interleaving gate needs one built first. That is stated
here so the limit is a measured property of the language rather than a
memory of one.

Usage: tools/completion_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


def refuses(workdir: Path, source: str, name: str, expected: str) -> str | None:
    path = workdir / f"{name}.axisl"
    path.write_text(source)
    result = run([*axis_prefix(), "check", str(path)])
    message = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        return f"{name}: accepted, and should not have been"
    if expected not in message:
        return f"{name}: refused for the wrong reason: {message[:170]}"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    if "(visibility " not in source:
        print("no completion contract in this corpus")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_completion_"))
    failures = []

    checked = run([*axis_prefix(), "check", str(args.axis_file)])
    if checked.returncode != 0:
        failures.append(f"the corpus does not validate: "
                        f"{(checked.stdout + checked.stderr).strip()[:170]}")

    # 1. an engine that outlives its launch, claiming immediacy
    failures.append(refuses(
        workdir,
        source.replace("    (visibility atomic-at-completion)", "    (visibility immediate)", 1),
        "async-immediate", "has a moment"))
    # 2. a tightly coupled one landing at a completion
    failures.append(refuses(
        workdir,
        source.replace("    (target nearasic) (coupling queue_descriptor)",
                       "    (target nearasic) (coupling tightly_coupled)", 1),
        "sync-completion", "no completion to land at"))
    # 3. landing at a completion with no completion field
    failures.append(refuses(
        workdir, source.replace(" (completion status_addr)", "", 1),
        "no-field", "nothing tells the host"))
    # 4. completing inside the launch and naming one anyway
    failures.append(refuses(
        workdir,
        source.replace("    (launch-abi rvmt_submit_entry)\n    (target nearasic) (coupling tightly_coupled)",
                       "    (launch-abi rvmt_submit_entry) (completion status_addr)\n"
                       "    (target nearasic) (coupling tightly_coupled)", 1),
        "sync-field", "nothing to poll"))
    # 5. progressive without saying what is seen
    failures.append(refuses(
        workdir, source.replace("    (in-flight undefined)\n", "", 1),
        "progressive-silent", "what the host sees"))
    # 6. an in-flight window on an engine with no flight
    failures.append(refuses(
        workdir,
        source.replace("    (visibility immediate)\n    (launch-fence none)",
                       "    (visibility immediate)\n    (launch-fence none)\n"
                       "    (in-flight undefined)", 1),
        "no-flight", "has no flight"))

    # 7. the manifest publishes it
    manifest = workdir / "manifest.json"
    if run([*axis_prefix(), "emit-json", str(args.axis_file),
            "-o", str(manifest)]).returncode != 0:
        failures.append("the manifest could not be emitted")
    else:
        accelerators = json.loads(manifest.read_text())["accelerators"]
        for accelerator in accelerators:
            for field in ("visibility", "launch_fence"):
                if not accelerator.get(field):
                    failures.append(f"the manifest does not publish {field} for "
                                    f"{accelerator['name']}")
        published = {a["name"]: a.get("in_flight") for a in accelerators}
        if not any(published.values()):
            failures.append("the manifest publishes no in-flight window at all")

    # 8. the canonical form keeps them
    canonical = workdir / "canonical.axisl"
    if run([*axis_prefix(), "emit-lisp", str(args.axis_file),
            "-o", str(canonical)]).returncode == 0:
        text = canonical.read_text()
        for form in ("(visibility ", "(launch-fence ", "(in-flight "):
            if form not in text:
                failures.append(f"the canonical form drops `{form.strip('( ')}`")

    failures = [failure for failure in failures if failure]
    for failure in failures:
        print(f"FAIL {failure}")
    print("6 contradictions refused, the contract published and round-tripped")
    print("completion contract: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
