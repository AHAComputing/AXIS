#!/usr/bin/env python3
"""Every corpus elaborates and emits, and no corpus is dark.

Two jobs, and the second is the one that earns this gate a place.

**Every corpus elaborates.** Validate each `examples/*.axisl` and emit the
artifacts that any valid document supports. That is cheap, and it is a floor:
a corpus can never be reachable by nothing.

**No corpus is dark.** Read `check_all.py`'s own gate matrix, collect every
example path any gate names, and report the corpora no gate names. This exists
because coverage has silently narrowed twice, both times invisibly:

  * `exec_wide_check.py` could not run on the AArch64 seed at all -- it died on
    the first instruction with an `inout` operand -- so the largest corpus had
    never had its effects executed at 64 bits. Behind that were three more
    harness bugs and one real defect: every branch target wrapped at 2^32.
  * `optisynth_vs_golden.py` swept `examples/*.axis`, so when the corpus moved
    to `.axisl` it kept passing while covering thirteen files instead of
    forty-five. A signed lane compare had been an unsigned one the whole time,
    with a witness sitting in the SIMD corpus whose rationale named the exact
    failure.

Neither was found by a failing gate. Both were found by accident, months late.
A count printed every run is what turns "nothing told me" into "nothing is
telling me, and here is the list" -- provided the list is true. This one said
"this floor is all that covers them" about two corpora that `smt_vs_golden`
sweeps and proves; it now says which definitions reach them.

**No instruction is dark.** One rung below the corpus: an instruction that no
fixture can be built for is executed by nothing, whatever gates its corpus
carries, because every execution driver works from the roundtrip fixtures. That
happens when a format field is neither an operand nor pinned, or an operand
binds to no field -- both of which the roundtrip manifest reports, in a
`skipped` list nothing read. Thirty-one instructions across eleven corpora were
in it, including the four `fp_exceptions` witnesses the corpus exists to be,
and the six RISC-V CSR-immediate forms in each of `rv32i` and `rv64i`.

The exception is a scalable lane instantiation. Lane renaming turns `zd` into
`zd__l0`, which matches no format field on purpose -- the lanes share one
encoding with their origin -- and those are checked by reading their emitted
effects instead. Every other runnable instruction must have a fixture, and this
fails if one does not.

Usage: tools/corpus_coverage_check.py [--verbose]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = AXIS_ROOT / "examples"

# Artifacts every valid document supports, whatever it describes. An emitter
# that needs prose fields or a particular shape (AHA export, bundles, LLVM
# patterns) is not here: declining those is a property of the corpus, not a
# failure, and the gates that care name their own corpora.
UNIVERSAL = [
    "check",
    "emit-json",
    "emit-decode-json",
    "emit-encode-json",
    "emit-lift-json",
    "emit-semantics-json",
    "emit-golden-python",
    "emit-exec-python",
]


def corpora() -> list[Path]:
    return sorted(EXAMPLES.glob("*.axisl"))


def named_by_gates() -> set[str]:
    """Every example stem a ladder gate names.

    Read from the matrix rather than from the source text: a gate carries its
    arguments in its argv, so this cannot drift from what actually runs.
    """
    from check_all import matrix

    named: set[str] = set()
    for _label, argv, _slow in matrix(with_pce=False):
        for arg in argv:
            path = Path(arg)
            if path.suffix == ".axisl":
                named.add(path.stem)
    return named


def named_by_tests() -> set[str]:
    """Every example stem the Rust suite reads.

    The ladder is not the only thing that covers a corpus, and reporting as if
    it were is how this check first read: it called twelve corpora dark when
    ten of them back Rust tests. A frontend fixture belongs in `cargo test`
    rather than in a differential gate, and that is coverage.
    """
    named: set[str] = set()
    roots = [AXIS_ROOT / "tests", AXIS_ROOT / "src"]
    for root in roots:
        for path in root.rglob("*.rs"):
            text = path.read_text()
            for stem in (candidate.stem for candidate in corpora()):
                if f"examples/{stem}.axisl" in text:
                    named.add(stem)
    return named


def formal_definitions(semantics_json: Path) -> int:
    """How many value definitions this corpus offers the sweeping gates.

    `smt_vs_golden` names no corpus: it sweeps them all and proves every
    definition it finds against the golden model. So a corpus with definitions
    is covered by it whether or not the matrix mentions the file, and the count
    is what says so -- read from the corpus's own emitted semantics rather than
    from a list of names kept in step by hand.
    """
    semantics = json.loads(semantics_json.read_text())
    return sum(1 for kind in ("instructions", "accelerators")
               for entry in semantics.get(kind, [])
               if entry.get("formal_semantics"))


def dark_instructions(lift_json: Path, roundtrip_json: Path) -> tuple[list[str], int]:
    """([mnemonic], lanes) that carry semantics and can never be executed.

    Every execution driver works from the roundtrip fixtures, so an instruction
    the encoder cannot build a word for is run by none of them -- and its
    corpus still reports as covered, because the corpus is. The reasons are in
    the roundtrip manifest's own `skipped` list: an operand bound to no field,
    or a field bound to nothing.

    Lanes are excepted and counted: a scalable instruction is instantiated per
    lane with renamed operands that match no field by design, sharing one
    encoding with the origin they come from.
    """
    lift = json.loads(lift_json.read_text())
    fixtures = json.loads(roundtrip_json.read_text())
    encoded = {test["mnemonic"] for test in fixtures.get("tests", [])}
    dark, lanes = [], 0
    for entry in lift["instructions"]:
        runnable = (entry.get("semantics") is not None
                    or entry.get("effects") is not None)
        if not runnable or entry["mnemonic"] in encoded:
            continue
        if entry.get("scalable_origin"):
            lanes += 1
            continue
        dark.append(entry["mnemonic"])
    return dark, lanes


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    failures = 0
    checked = 0
    dark: dict[str, list[str]] = {}
    definitions: dict[str, int] = {}
    lanes = 0
    for path in corpora():
        with tempfile.TemporaryDirectory() as scratch:
            scratch = Path(scratch)
            # Two of the artifacts are kept rather than discarded: the
            # instruction-level check below reads them, and emitting them again
            # in a second pass would cost this gate twice for work it has just
            # done. The fixtures are not in UNIVERSAL -- a corpus need not be
            # encodable to be valid -- so they are emitted beside it and not
            # counted among the artifacts every document supports.
            kept = {"emit-lift-json": scratch / "lift.json",
                    "emit-roundtrip-json": scratch / "roundtrip.json",
                    "emit-semantics-json": scratch / "semantics.json"}
            emitted = True
            for command in [*UNIVERSAL, "emit-roundtrip-json"]:
                argv = [*axis_prefix(), command, str(path)]
                if command != "check":
                    argv += ["-o", str(kept.get(command, Path("/dev/null")))]
                result = subprocess.run(argv, cwd=AXIS_ROOT, capture_output=True, text=True)
                if command in UNIVERSAL:
                    checked += 1
                if result.returncode != 0:
                    message = (result.stdout + result.stderr).strip().splitlines()
                    print(f"FAIL {path.name} {command}: {message[0] if message else '?'}")
                    failures += 1
                    emitted = False
            if emitted:
                names, corpus_lanes = dark_instructions(
                    scratch / "lift.json", scratch / "roundtrip.json")
                lanes += corpus_lanes
                if names:
                    dark[path.name] = names
                definitions[path.stem] = formal_definitions(scratch / "semantics.json")
        if args.verbose:
            print(f"  ok  {path.name}")

    print(f"{len(corpora())} corpora x {len(UNIVERSAL)} artifacts = {checked} checked")

    if dark:
        print(f"\n{sum(len(names) for names in dark.values())} instruction(s) with "
              f"semantics that no fixture can be built for, so no executor runs them:")
        for corpus, names in sorted(dark.items()):
            shown = ", ".join(names[:6])
            more = f" (+{len(names) - 6} more)" if len(names) > 6 else ""
            print(f"  {corpus}: {shown}{more}")
        failures += 1
    else:
        print(f"every instruction with semantics has a fixture "
              f"({lanes} scalable lane instantiations excepted)")

    # The self-report. Not a failure: a corpus can be adequately covered by a
    # sweep that names no file, and demanding a named gate per corpus would be
    # a rule nobody could keep. Printing the list is what makes a silent
    # narrowing loud.
    #
    # It used to end "this floor is all that covers them", which was false for
    # both corpora it named: `smt_vs_golden` sweeps every corpus and proves the
    # formal definitions it finds -- three of them in `policy_admission` and two
    # in `policy_icount`, over a hundred cases each. A report that overstates a
    # gap is how a report gets ignored, so the line now says which of the two
    # things is true, from the corpus's own emitted semantics rather than from
    # a list kept here.
    covered = named_by_gates() | named_by_tests()
    unnamed = [path.stem for path in corpora() if path.stem not in covered]
    if unnamed:
        print(f"\n{len(unnamed)} corpus/corpora named by no gate and read by no test:")
        for stem in unnamed:
            count = definitions.get(stem, 0)
            reach = (f"{count} formal definition(s), which the corpus-sweeping "
                     f"differential gates check"
                     if count else "no formal definitions; this floor is all that covers it")
            print(f"  {stem} — {reach}")
    else:
        print("every corpus is named by a gate or read by a test")

    print("every corpus elaborates and emits: " + ("PASS" if failures == 0 else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
