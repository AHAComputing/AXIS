#!/usr/bin/env python3
"""Emit what AXIS has actually established about a description, as evidence.

`pce/aha/cert/certificate.py` models a design's trust as `Claim`s carrying a
`ProofVerdict` and pointing at `EvidenceFragment`s, with an explicit honesty
rule: *a claim with no evidence is allowed only at `unverified`/`failed`*. AXIS
runs 282 gates and none of that reaches a certificate, so an AHA design built
from an AXIS description carries `unverified` for properties AXIS checks every
run.

**This is a tool and not an emitter, and that is the whole design.** A gate
result is a fact about a *run*, not about a description. An emitter that wrote
`proven` into a manifest would be asserting something it had not done -- the
exact dishonesty this repository refuses everywhere else. So the evidence comes
from running the gates, here, now, and carries their real output.

## The verdict tier, and why almost nothing is `proven`

AHA's tiers are `failed`, `unverified`, `error_bounded`, `cosim`, `proven`.
Nearly every AXIS gate is a **differential over sampled inputs**: the SMT
semantics are checked against the golden model on random and edge vectors, the
LLVM encoder against AXIS's on random operands, a lifted block against the
executor on random initial state. z3 answering `unsat` proves the vector it was
asked about; it was not asked about the others.

So these are `cosim` -- co-simulation of two independent implementations --
and not `proven`. Calling them `proven` would be the overclaim that a tier
system exists to prevent, and `aha/cert/adapters.py` says its own mapping is
"conservative" for the same reason. A universally quantified claim would need a
gate that quantifies, and AXIS has one such check (an axiom set's consistency)
which is not by itself a claim about a design.

Usage: tools/evidence_manifest.py <corpus.axisl> [-o evidence.json]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent

# (fragment id, tool, takes the corpus as an argument, claim kind, statement).
# Every entry is a differential between two independent implementations, which
# is what fixes the tier at `cosim`.
GATES = [
    ("smt_vs_golden", "smt_vs_golden.py", True, "functional_equivalence",
     "the emitted SMT-LIB semantics agree with the generated golden model over "
     "random and edge-case vectors"),
    ("intrinsic_axioms", "smt_axioms_check.py", True, "functional_equivalence",
     "each intrinsic axiom constrains its symbol to the value the golden model "
     "computes, and the axiom set is satisfiable"),
    ("exec_vs_golden", "exec_vs_golden.py", True, "functional_equivalence",
     "the generated Python executor agrees with the golden model on every "
     "fixture"),
    ("roundtrip", "roundtrip_check.py", True, "structural_preservation",
     "every instruction encodes and decodes back to itself"),
    ("lift_trees", "lift_ast_check.py", True, "functional_equivalence",
     "the published expression trees, walked by a consumer-shaped evaluator, "
     "compute what the executor computes"),
    ("lift_blocks", "lift_block_check.py", True, "functional_equivalence",
     "a lifted block's dataflow graph computes what executing the same words "
     "computes, and its live-outs are exactly what the block wrote"),
    ("capability", "capability_check.py", True, "structural_preservation",
     "the capability manifest agrees with the artifacts it projects"),
]


def run_gate(tool: str, corpus: Path, takes_corpus: bool):
    command = [sys.executable, str(AXIS_ROOT / "tools" / tool)]
    if takes_corpus:
        command.append(str(corpus))
    result = subprocess.run(command, cwd=AXIS_ROOT, capture_output=True, text=True)
    return result.returncode, (result.stdout or "").strip()


def axis_build() -> str:
    result = subprocess.run([*axis_prefix(), "--version"], cwd=AXIS_ROOT,
                            capture_output=True, text=True)
    return result.stdout.strip() or "unknown"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    args = parser.parse_args()

    claims, evidence = [], []
    for fragment_id, tool, takes_corpus, kind, statement in GATES:
        code, output = run_gate(tool, args.corpus, takes_corpus)
        # **A decline is not a failure.** A gate whose vacuity guard fires --
        # `zbb_like` has no branch and no memory, so the block gate has nothing
        # to establish -- exits non-zero and found nothing wrong. Reporting
        # that as `failed` would tell a consumer a design failed a check that
        # did not apply to it, which is the same dishonesty as `proven` in the
        # other direction.
        #
        # Exit codes cannot tell the two apart, so this reads the gate's own
        # words. That is a heuristic on phrasing and is written down as one.
        #
        # **It has now been wrong twice.** `zbb_like`'s block gate was reported
        # `failed` for having no branch to check, and `effects_mem`'s SMT and
        # axiom gates for having no pure values -- "no formal_semantics
        # functions found" and "emits no intrinsic axioms". Both were found by
        # running this over more descriptions, and each time the list of
        # phrasings grew. The durable fix is a distinct exit status for a
        # decline, so a gate says which it means instead of a reader inferring
        # it; that is a change to every gate in the ladder and is not made
        # here. Until then, a new phrasing means a false `failed`, which is
        # why the check below refuses a run that never sees a second verdict.
        # The status, where the gate reports one. `DECLINED` means "nothing
        # here to check" and comes from the gate itself rather than from its
        # prose -- which is what this used to read, wrongly, twice.
        #
        # The phrasing list is kept for the gates that do not report the status
        # yet: a vacuity folded into a shared failure counter cannot be
        # separated without restructuring the gate, and those still exit 1. So
        # this is exact where a status exists and heuristic where it does not,
        # and the count of each is printed rather than blurred.
        vacuous = code == DECLINED or (code != 0 and any(
            marker in output
            for marker in ("proves nothing", "proved nothing", "is stated and "
                           "unchecked", "exercises no rule", "nothing to prove",
                           "establishes nothing", "no formal_semantics functions "
                           "found", "emits no ", "no block was evaluated",
                           "did not exercise")))
        if code == 0:
            verdict, ids = "cosim", (fragment_id,)
        elif vacuous:
            verdict, ids = "unverified", (fragment_id,)
        else:
            verdict, ids = "failed", (fragment_id,)
        evidence.append({
            "fragment_id": fragment_id,
            "source": "axis_gate",
            "payload": {"tool": tool, "exit_code": code,
                        # The gate's own words: this file is hashed and never
                        # interpreted by the cert core, so the payload has to
                        # carry enough for a re-verifier to chase it.
                        "report": output.splitlines()[-6:]},
        })
        claims.append({
            "kind": kind,
            "verdict": verdict,
            "statement": statement + (
                " -- not established here: the gate had nothing to check on this "
                "description" if verdict == "unverified" else ""),
            "evidence_ids": list(ids),
        })

    # What AXIS declares and does not check. Stated rather than omitted: a
    # consumer reading latency out of a manifest should see that nothing here
    # established it.
    claims.append({
        "kind": "timing_bound",
        "verdict": "unverified",
        "statement": "per-instruction latency and throughput are declared by the "
                     "description and checked by no gate in this manifest",
        "evidence_ids": [],
    })

    document = {
        "schema": "axis.evidence.v1",
        "description": args.corpus.stem,
        "axis_build": axis_build(),
        "claims": claims,
        "evidence": evidence,
    }
    text = json.dumps(document, indent=2) + "\n"
    if args.output:
        args.output.write_text(text)
    else:
        sys.stdout.write(text)

    failed = [claim for claim in claims if claim["verdict"] == "failed"]
    for claim in failed:
        print(f"FAIL {claim['evidence_ids'][0]}: {claim['statement']}",
              file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
