"""How a gate runs the AXIS binary.

Every tool here shells out to `cargo run` for its emits, and that is why the
ladder could not run its gates concurrently. Cargo replaces the binary in place
and keeps its own bookkeeping, and several `cargo run` invocations at once
observe each other doing it:

    error: could not execute process `target/debug/axis ...` (never executed)
    Caused by: No such file or directory (os error 2)

Nine gates failed that way on the first parallel run of the full ladder, all of
them passing on their own -- the "spurious failures" the runner's own comment
had warned about, reproduced at sixteen concurrent invocations of a *fresh*
binary. Pre-building does not help, because the race is cargo's and not the
build's.

So a gate does not invoke cargo when the runner has already built. `check_all`
sets `AXIS_BIN` to the binary it built and the gates exec it directly, which
has no lock and no bookkeeping. Without that variable this falls back to `cargo
run`, so every tool still works on its own from a clean checkout.
"""

from __future__ import annotations

import os


def axis_prefix() -> list[str]:
    """The argv prefix that runs the AXIS binary, one way or the other."""
    binary = os.environ.get("AXIS_BIN")
    return [binary] if binary else ["cargo", "run", "-q", "--"]


# What a gate's exit status means.
#
# `PASSED` and `FAILED` are the usual pair. `DECLINED` is the third thing a
# gate can honestly say: *nothing here to check* -- a corpus with no elastic
# cycle, no branch, no pure value, no multi-limb write. Every vacuity guard in
# this ladder means that, and each used to say it by exiting 1, which is what
# "something is wrong" says too.
#
# Two callers read the difference in **opposite directions, and both are
# right**:
#
#   * `check_all` runs a gate against a corpus *chosen to exercise it*, so a
#     decline there is still a failure -- the coverage that pairing claims has
#     evaporated, which is precisely what the vacuity guards exist to catch;
#   * `evidence_manifest` runs gates against an arbitrary description, where a
#     decline means *not applicable* and the honest verdict is `unverified`,
#     not `failed`.
#
# Inferring which from a gate's prose was a heuristic and was wrong twice:
# `zbb_like`'s block gate reported as failed for having no branch, and
# `effects_mem`'s SMT and axiom gates for having no pure values.
#
# **Adopting this is not mechanical.** A first attempt rewrote it by matching
# text near each `return 1` and caught the summary line above every gate's
# final `return 1 if failures else 0`, which would have made real failures
# report as declines -- the one direction that hides a defect. Each site is a
# judgement about what that particular exit means, and the sites below were
# read one at a time.
PASSED = 0
FAILED = 1
DECLINED = 2
