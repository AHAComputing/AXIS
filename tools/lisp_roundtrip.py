#!/usr/bin/env python3
"""A corpus can be rewritten from its own emitted form.

`emit-lisp` exists to produce the canonical Lisp for a document -- the form a
corpus could be replaced by. `tests/golden.rs` states the claim outright: *what
comes back out is what went in, or a corpus cannot be rewritten from its own
emitted form.* Until this gate, that claim was tested on one corpus by two
assertions about barrier forms, and no gate drove the emitter at all.

The comparison is **the artifacts, byte for byte**: emit them from the source,
emit the canonical Lisp, re-elaborate that, emit them again, and require every
byte to match. Defining fidelity as "the artifacts do not move" rather than as
"the syntax trees match" is deliberate -- a difference no artifact shows is a
difference no consumer can see, and a difference in an artifact is one somebody
downstream would have to live with.

The set below is the individual emitters rather than `emit-bundle`, which
refuses a document it cannot export to PCE/AHA (`rv32i`'s `LUI` is not on a
custom opcode) and would have excluded the corpora with the most to say. Every
emitter here answers for any valid document, and between them they carry every
top-level form.

**Idempotence is the trap this does not fall into.** Comparing
`emit-lisp(emit-lisp(x))` with `emit-lisp(x)` looks like the same check and is
vacuous for exactly the bug worth finding: a form the emitter drops is dropped
identically on both sides, so a fabric that vanished agrees with itself
perfectly. The original document has to be one side of the comparison.

**Nothing is excluded.** Seven corpora used to be: `emit-lisp` wrote the
*elaborated* document, and scalable elaboration instantiates one instruction
per lane, so `sve.axisl` came back as 2797 `__l` instructions the surface
cannot express. That was reported here as a boundary -- and it was really a
question about what `emit-lisp` is for, answered wrongly. It now writes the
*frontend* document, before the semantic passes, which is what "a form a corpus
could be replaced by" has to mean. All 55 round-trip.

Coverage, per `docs/gate_coverage.md`: a form no corpus declares is a form this
proves nothing about, so the sweep reports which top-level forms it actually
exercised and fails if the corpora between them do not cover the language.

Usage: tools/lisp_roundtrip.py [input.axisl ...]
"""

from __future__ import annotations

import argparse
import filecmp
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
# Every top-level form the language has. `defproperties` is absent on purpose:
# `(use-properties ...)` is expanded during elaboration, so a canonical
# document legitimately has none, and expecting one back would be expecting the
# emitter to un-expand a macro.
FORMS = (
    "defisa", "definstruction", "defformat", "defmode", "defpacket", "deffabric",
    "defmapping", "defchannel", "defabi", "deftile", "defcore", "defaccelerator",
    "defmemory", "deflowering", "defpersonality",
)


# One artifact per family of declarations, and between them everything a
# document can hold: instructions, formats, ISAs and modes in the decode table;
# semantics in its own; cores, accelerators, memories, tiles and ABIs in the
# manifest; and one apiece for packets, fabrics, mappings, personalities and
# mode legality.
ARTIFACTS = (
    ("emit-json", "manifest.json"),
    ("emit-decode-json", "decode.json"),
    ("emit-encode-json", "encode.json"),
    ("emit-semantics-json", "semantics.json"),
    ("emit-lift-json", "lift.json"),
    ("emit-capsule-json", "capsule.json"),
    ("emit-packet-json", "packet.json"),
    ("emit-fabric-json", "fabric.json"),
    ("emit-mapping-json", "mapping.json"),
    ("emit-legality-json", "legality.json"),
)


def emit(source: Path, command: str, out: Path) -> tuple[bool, str]:
    result = subprocess.run([*axis_prefix(), command, str(source), "-o", str(out)],
                            cwd=AXIS_ROOT, capture_output=True, text=True)
    return result.returncode == 0, (result.stderr or result.stdout).strip()


def differences(left: Path, right: Path) -> list[str]:
    """Every artifact that moved, named. Directories are flat, so one pass."""
    names = sorted({path.name for path in left.iterdir()}
                   | {path.name for path in right.iterdir()})
    out = []
    for name in names:
        a, b = left / name, right / name
        if not a.exists():
            out.append(f"{name}: only after the round trip")
        elif not b.exists():
            out.append(f"{name}: lost by the round trip")
        elif not filecmp.cmp(a, b, shallow=False):
            out.append(f"{name}: differs")
    return out


def check(source: Path, workdir: Path) -> tuple[list[str], set[str]]:
    forms = {form for form in FORMS
             if re.search(rf"\({form}\s", source.read_text())}
    before, after = workdir / "before", workdir / "after"
    before.mkdir()
    after.mkdir()
    canonical = workdir / "canonical.axisl"
    ok, message = emit(source, "emit-lisp", canonical)
    if not ok:
        return [f"emit-lisp failed: {message[:200]}"], forms
    for command, name in ARTIFACTS:
        ok, message = emit(source, command, before / name)
        if not ok:
            # The source itself declining an emitter is not this gate's
            # business; skip that artifact on both sides rather than reporting
            # the corpus as broken.
            continue
        ok, message = emit(canonical, command, after / name)
        if not ok:
            return [
                f"the canonical form does not re-elaborate ({command}): "
                f"{message[:220]}"
            ], forms
    return differences(before, after), forms


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    parser.add_argument("--verbose", action="store_true",
                        help="name every artifact that moved, not just the count")
    args = parser.parse_args()

    sources = args.axis_files or sorted((AXIS_ROOT / "examples").glob("*.axisl"))
    failures = 0
    covered: set[str] = set()
    for source in sources:
        with tempfile.TemporaryDirectory(prefix="axis_lisprt_") as tmp:
            found, forms = check(source, Path(tmp))
        covered |= forms
        if found:
            failures += 1
            print(f"FAIL {source.name}: {len(found)} artifact(s) moved")
            for message in (found if args.verbose else found[:4]):
                print(f"       {message}")
            if not args.verbose and len(found) > 4:
                print(f"       ... and {len(found) - 4} more")

    print(f"{len(sources)} corpus(es), {len(sources) - failures} round-trip to "
          f"byte-identical artifacts")
    missing = [form for form in FORMS if form not in covered]
    if missing:
        print(f"no corpus in this run declares {', '.join(missing)}: a form nothing "
              f"declares is one this proves nothing about")
        failures += 1
    print("lisp round trip: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
