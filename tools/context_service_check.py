#!/usr/bin/env python3
"""The bound an engine publishes is one its policy delivers (stage M3).

M1 checks that an engine's context numbers can all be true at once and M2 that
a bound is published exactly where the policy delivers one. Neither runs the
policy. This does: it is the one obligation in `multicontext_design.md` that is
not arithmetic, and it is the classic liveness property of a shared engine --
*a persistently eligible context waits at most `contexts - 1` other grants.*

The check has two halves, and the second is the one worth having:

  * **sound** -- across many eligibility patterns, no persistently eligible
    context ever waits longer than the published bound;
  * **tight** -- some pattern makes it wait exactly that long. A bound that is
    never attained is a bound that was not measured. Publishing `1000` for a
    sixteen-context engine would pass soundness forever and tell a consumer
    nothing, and "sound" alone is the check that would let it through.

A third property is separate from both, because it fails differently: a
blocked context must not delay an eligible peer. A round robin that waits for
whichever context its pointer names, rather than skipping to the first eligible
one, is still a round robin and still starves everybody behind one blocked
context. That is a real arbiter bug, and it is the injection this gate is
pointed at.

Nothing here models hardware. It runs the policy the *name* denotes, which is
the same standing as `elastic_vs_scalar.py` executing a mapping's declared
timing: AXIS judges the spec, and a spec whose own bound its own policy cannot
meet is wrong before any silicon exists.

Coverage, per `docs/gate_coverage.md`: an engine publishing no bound has
nothing to execute, so a corpus of only unbounded engines fails as vacuous --
the same rule M1 applies to a corpus of single-context ones.

Usage: tools/context_service_check.py [input.axisl]
"""

from __future__ import annotations

import argparse
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
TRIALS = 200
STEPS = 400


def grant(pointer: int, eligible: set[int], contexts: int, *, skipping: bool = True):
    """One arbitration step: who gets the engine, and where the pointer lands.

    `skipping` is the property under test. A work-conserving round robin scans
    from the pointer to the first *eligible* context; turning it off leaves a
    rotation that waits for whichever context its pointer happens to name,
    which is the arbiter bug this gate exists to catch.
    """
    if not eligible:
        return None, pointer
    if not skipping:
        chosen = pointer if pointer in eligible else None
        return chosen, (pointer + 1) % contexts if chosen is not None else pointer
    for offset in range(contexts):
        candidate = (pointer + offset) % contexts
        if candidate in eligible:
            return candidate, (candidate + 1) % contexts
    return None, pointer


def worst_wait(contexts: int, victim: int, pattern,
               *, skipping: bool = True) -> tuple[int, int]:
    """Most other grants the victim sits through, and steps the engine idled.

    `pattern(step)` returns the contexts eligible at that step; the victim is
    added to it, so it is persistently eligible by construction -- which is the
    precondition the published bound is about.

    Idling is counted separately rather than folded into the wait, because the
    two are different failures. A long wait is an unfair policy; an idle step
    with work available is a policy that is not work-conserving at all, and
    calling that "waited N grants" would name the wrong bug.
    """
    pointer = 0
    waited = worst = idled = 0
    for step in range(STEPS):
        eligible = set(pattern(step)) | {victim}
        chosen, pointer = grant(pointer, eligible, contexts, skipping=skipping)
        if chosen is None:
            idled += 1
            continue
        if chosen == victim:
            worst = max(worst, waited)
            waited = 0
        else:
            waited += 1
    return max(worst, waited), idled


def check_service(name: str, contexts: int, bound: int, *,
                  skipping: bool = True) -> tuple[list[str], int]:
    """Soundness and tightness of one engine's bound. Returns (failures, worst)."""
    failures: list[str] = []
    everyone = range(contexts)

    # Tightness: every other context eligible at every step, so the rotation
    # serves all of them before coming back. This is the pattern the bound is
    # the answer to, and it must be attained rather than merely respected.
    attained, idled = worst_wait(contexts, 0, lambda _: everyone, skipping=skipping)
    if idled:
        failures.append(
            f"{name}: the engine idled on {idled} of {STEPS} steps with every context "
            f"eligible; a policy that does not run available work is not "
            f"work-conserving, and no bound in grants survives it")
    if attained != bound:
        failures.append(
            f"{name}: with every context eligible a persistently eligible one waits "
            f"{attained} other grants, not the published {bound}"
            + (" -- a bound never attained was never measured"
               if attained < bound else ""))

    # Soundness: many patterns, seeded so a failure is reproducible.
    worst = attained
    rng = random.Random(0x9E3779B9 ^ contexts)
    for trial in range(TRIALS):
        eligible_at = [
            {c for c in everyone if rng.random() < 0.5}
            for _ in range(STEPS)
        ]
        victim = rng.randrange(contexts)
        seen, idled = worst_wait(contexts, victim, lambda step: eligible_at[step],
                                 skipping=skipping)
        worst = max(worst, seen)
        if idled:
            failures.append(
                f"{name}: trial {trial} idled on {idled} of {STEPS} steps with work "
                f"available; the policy is not work-conserving")
            break
        if seen > bound:
            failures.append(
                f"{name}: trial {trial} left context {victim} waiting {seen} other "
                f"grants, past the published bound of {bound}")
            break

    # And the property that fails differently: one context blocked forever must
    # not delay the rest.
    blocked = contexts - 1
    stalled, idled = worst_wait(contexts, 0,
                                lambda _: {c for c in everyone if c != blocked},
                                skipping=skipping)
    worst = max(worst, stalled)
    if idled:
        failures.append(
            f"{name}: context {blocked} is blocked and the engine idled {idled} times "
            f"waiting for it while its peers were ready -- head-of-line blocking, "
            f"which is what a rotation that does not skip does")
    if stalled > bound:
        failures.append(
            f"{name}: with context {blocked} blocked forever, an eligible peer waits "
            f"{stalled} grants; a blocked context must not head-of-line block")
    return failures, worst


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "heterogeneous_tile.axisl")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="axis_service_") as workdir:
        manifest = Path(workdir) / "manifest.json"
        subprocess.run([*axis_prefix(), "emit-json", str(args.axis_file),
                        "-o", str(manifest)],
                       cwd=AXIS_ROOT, check=True, capture_output=True)
        payload = json.loads(manifest.read_text())

    failures: list[str] = []
    bounded = 0
    for accelerator in payload.get("accelerators", []):
        entry = accelerator.get("multicontext")
        if entry is None:
            continue
        bound = entry.get("max_other_grants_before_service")
        if bound is None:
            print(f"     {accelerator['name']}: publishes no bound, so there is no "
                  f"promise to execute")
            continue
        bounded += 1
        found, worst = check_service(accelerator["name"], entry["contexts"], bound)
        failures.extend(found)
        if not found:
            print(f"     {accelerator['name']}: {entry['contexts']} contexts, bound "
                  f"{bound}, worst observed {worst} over {TRIALS} patterns")

    for message in failures:
        print(f"FAIL {message}")
    if not bounded:
        print("no engine in this corpus promises bounded service: there is no "
              "policy to run and nothing to attain")
        return DECLINED
    print("context service: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
