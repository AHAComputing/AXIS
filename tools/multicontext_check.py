#!/usr/bin/env python3
"""An engine's context numbers can all be true at once (stage M1).

`pce/hardware/accel_engines/xnn_mt/contract.py` declares sixteen hardware
contexts, four context-id bits and a two-deep issue queue, and hand-checks the
relations between them in a Python `validate()`. Those relations are the kind
AXIS decides for every other construct it describes, so M1 moves the
declaration into the description and the checking into the validator.

This gate is the second derivation, from `axis.manifest.v1` rather than from
the code that produced it -- the same division as `mapping_legality_check.py`,
which re-derives the modulo tables the validator already computed:

  * `context_id_bits` is exactly what names the largest id, `contexts - 1`. A
    narrow field cannot name every context; a wide one names contexts the
    machine does not have.
  * `issue_queue_depth` is at least two: the issue being serviced, and one
    prefetched behind it. A queue of one hides no latency, which is the only
    reason the contexts exist.
  * the identity tuple carries `context_id`, because an issue that cannot say
    which context it came from cannot have its result returned to one.
  * `max_other_grants_before_service` is the published derived bound, and the
    gate recomputes it. Publishing it is the point -- a consumer that derived
    it itself would be a second derivation of the fact the manifest already
    states -- so a published value that disagrees with the arithmetic is the
    one failure this field can have.

And M2's rule, which is the one with two fields in it: **a bound is published
exactly when the policy delivers one.** A work-conserving round robin rotates,
so a persistently eligible context waits at most `contexts - 1` other grants --
but only if there is a point at which it can rotate. Run to completion with no
preemption point is still work-conserving and still unbounded, because a
context that never finishes never yields; and strict priority is unbounded for
the other reason, a high-priority context served forever. Both are legitimate
machines to describe and illegitimate ones to publish a bound for, so the
manifest says `null` -- said, not omitted, because a consumer reading a missing
key cannot tell "no bound" from "forgot to say".

What is *not* checked here is whether hardware implements any of it. The
scheduling policy is a name, and a gate here can never say an arbiter is fair.
AXIS judges the spec; the consumer judges the silicon.

Coverage, per `docs/gate_coverage.md`: a corpus with no accelerator holding
more than one context fails as vacuous. A single-context engine cannot tell
this check from an empty one -- the same rule `mapping_legality_check.py`
applies to a fabric whose PEs hold one configuration.

Usage: tools/multicontext_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent


def canonical(value: str) -> str:
    """The validator's spelling rule: a hyphen and an underscore are one word."""
    return value.strip().lower().replace("-", "_")


def check_contexts(name: str, entry: dict) -> list[str]:
    """Every relation the declaration must satisfy, re-derived."""
    failures: list[str] = []
    contexts = entry.get("contexts", 0)
    if contexts < 2 or contexts & (contexts - 1):
        failures.append(f"{name}: {contexts} contexts is not a power of two >= 2")
        return failures

    needed = (contexts - 1).bit_length()
    if entry.get("context_id_bits") != needed:
        failures.append(
            f"{name}: {entry.get('context_id_bits')} context-id bits for {contexts} "
            f"contexts, which needs exactly {needed}")
    if entry.get("issue_queue_depth", 0) < 2:
        failures.append(
            f"{name}: issue queue {entry.get('issue_queue_depth')} deep holds no "
            f"prefetched issue, so the contexts hide no latency")
    identity = entry.get("identity", [])
    if "context_id" not in identity:
        failures.append(
            f"{name}: identity {identity} does not carry context_id, so a result "
            f"cannot be returned to the context that asked for it")

    # M2: what the policy decides is whether there is a bound at all.
    rotates = canonical(entry.get("scheduling", "")) == "work_conserving_round_robin"
    yields = canonical(entry.get("preemption", "")) == "tile_boundary_only"
    bound = entry.get("max_other_grants_before_service")
    if rotates and yields:
        if bound != contexts - 1:
            failures.append(
                f"{name}: published bound {bound} is not {contexts - 1}, the other "
                f"contexts a rotating policy can serve first")
    elif bound is not None:
        failures.append(
            f"{name}: publishes a bound of {bound} under "
            f"`{entry.get('scheduling')}` / `{entry.get('preemption')}`, which "
            f"delivers no bound; an unbounded engine is one to describe, not one "
            f"to promise service for")

    interval = entry.get("service_interval_cycles", 0)
    cycles = entry.get("deterministic_dependency_cover_cycles")
    expected = bound * interval if (bound is not None and interval) else None
    if cycles != expected:
        failures.append(
            f"{name}: dependency cover {cycles} is not {expected}, the bound in "
            f"grants times the {interval}-cycle service interval")

    eligibility = entry.get("eligibility", [])
    if len(set(eligibility)) != len(eligibility):
        failures.append(f"{name}: eligibility {eligibility} names an input twice")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "heterogeneous_tile.axisl")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axis_mctx_") as workdir:
        manifest = Path(workdir) / "manifest.json"
        subprocess.run([*axis_prefix(), "emit-json", str(args.axis_file),
                        "-o", str(manifest)],
                       cwd=AXIS_ROOT, check=True, capture_output=True)
        payload = json.loads(manifest.read_text())

    accelerators = payload.get("accelerators", [])
    failures: list[str] = []
    multi = bounded = 0
    for accelerator in accelerators:
        entry = accelerator.get("multicontext")
        if entry is None:
            continue
        multi += 1
        if entry.get("max_other_grants_before_service") is not None:
            bounded += 1
        failures.extend(check_contexts(accelerator["name"], entry))

    for message in failures:
        print(f"FAIL {message}")
    print(f"{len(accelerators)} accelerator(s), {multi} of them multi-context, "
          f"{bounded} promising bounded service")
    if not multi:
        print("no accelerator in this corpus retains more than one context: a "
              "single-context engine cannot tell this check from an empty one")
        return DECLINED
    if not bounded:
        print("no engine in this corpus promises bounded service: the arithmetic "
              "the bound is made of never runs")
        return DECLINED
    print("multi-context: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
