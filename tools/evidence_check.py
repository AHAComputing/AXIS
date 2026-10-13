#!/usr/bin/env python3
"""The evidence document says only what its evidence supports.

`tools/evidence_manifest.py` runs AXIS's gates for a description and reports
what they established, as `Claim`s and `EvidenceFragment`s in the shape
`pce/aha/cert/certificate.py` consumes. An evidence document is a trust
statement, so the ways it can be wrong are the ways a trust statement is worst:
claiming more than was run, pointing at evidence that is not there, or reading
`cosim` off a gate that failed.

`certificate.py` states the first rule itself -- *a claim with no evidence is
allowed only at `unverified`/`failed`* -- and notes that its own `audit` reports
rather than enforces it, "so the honesty boundary is visible rather than
silently dropped". This enforces it on the producing side, which is the side
that can.

Four checks:

  * a claim above `unverified` names at least one fragment;
  * every named fragment exists;
  * a `cosim` claim's fragments all exited zero, and a `failed` claim's did not
    -- the verdict has to be what the evidence says;
  * at least one claim is above `unverified`, or the document establishes
    nothing and should not be mistaken for a certificate.

Usage: tools/evidence_check.py [corpus.axisl]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

AXIS_ROOT = Path(__file__).resolve().parent.parent
SUPPORTED = {"cosim", "proven", "error_bounded"}


def check(document: dict) -> list[str]:
    failures: list[str] = []
    fragments = {entry["fragment_id"]: entry for entry in document["evidence"]}
    established = 0
    for claim in document["claims"]:
        verdict, ids = claim["verdict"], claim["evidence_ids"]
        if verdict in SUPPORTED:
            established += 1
            if not ids:
                failures.append(
                    f"a `{verdict}` {claim['kind']} claim names no evidence")
        for fragment_id in ids:
            if fragment_id not in fragments:
                failures.append(f"claim names fragment `{fragment_id}`, which the "
                                f"document does not carry")
                continue
            code = fragments[fragment_id]["payload"]["exit_code"]
            if verdict in SUPPORTED and code != 0:
                failures.append(
                    f"`{verdict}` claim rests on `{fragment_id}`, which exited "
                    f"{code} -- the verdict is not what the evidence says")
            if verdict == "failed" and code == 0:
                failures.append(
                    f"`failed` claim rests on `{fragment_id}`, which exited zero")
            # A gate that ran clean cannot support "not established here".
            if verdict == "unverified" and code == 0:
                failures.append(
                    f"`unverified` claim rests on `{fragment_id}`, which exited "
                    f"zero -- a gate that established something is not evidence "
                    f"that nothing was established")
    if not established:
        failures.append("no claim is above `unverified`: this document "
                        "establishes nothing and is not a certificate")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpora", type=Path, nargs="*")
    args = parser.parse_args()

    # More than one, and chosen to differ: this document's shape depends on
    # which gates ran and how they came out, so a single corpus exercises one
    # verdict mix. `zbb_like` has no branch and no memory and produces an
    # `unverified` decline; `rv32i` establishes everything it can;
    # `cgra_fabric` and `effects_mem` carry shapes neither does. Running each
    # costs seven gates, which is why this is a handful and not all 55.
    targets = args.corpora or [AXIS_ROOT / "examples" / name for name in
                               ("zbb_like.axisl", "rv32i.axisl",
                                "cgra_fabric.axisl", "effects_mem.axisl")]

    failures: list[str] = []
    verdicts: dict[str, int] = {}
    for corpus in targets:
        result = subprocess.run(
            [sys.executable, str(AXIS_ROOT / "tools" / "evidence_manifest.py"),
             str(corpus)],
            cwd=AXIS_ROOT, capture_output=True, text=True)
        if not result.stdout.strip():
            print(f"FAIL {corpus.name}: the evidence tool produced nothing "
                  f"({result.stderr.strip()[:160]})")
            failures.append(corpus.name)
            continue
        document = json.loads(result.stdout)
        found = check(document)
        for message in found:
            print(f"FAIL {corpus.name}: {message}")
        failures.extend(found)
        for claim in document["claims"]:
            verdicts[claim["verdict"]] = verdicts.get(claim["verdict"], 0) + 1
        supported = sum(1 for claim in document["claims"]
                        if claim["verdict"] in SUPPORTED)
        unverified = sum(1 for claim in document["claims"]
                         if claim["verdict"] == "unverified")
        print(f"     {corpus.name}: {supported} claim(s) with evidence, "
              f"{unverified} stated unverified, "
              f"{len(document['evidence'])} fragment(s)")

    print(f"{len(targets)} description(s): "
          + ", ".join(f"{count} {verdict}"
                      for verdict, count in sorted(verdicts.items())))
    # A run that only ever saw one verdict has not exercised the rule that
    # distinguishes them, which is the whole content of this check.
    if len(verdicts) < 2:
        print("every claim came back the same verdict: this run did not "
              "exercise the distinction it exists to enforce")
        return 1
    print("evidence == what ran: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
