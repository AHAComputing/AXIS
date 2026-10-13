#!/usr/bin/env python3
"""Recompute the numbers this repository states about itself.

Prose carries counts, and nothing recomputes them. That is not a small
problem here: `docs/llvm_backend.md` said "490 of 809 declines are a result
plus NZCV, flag-setting is next" for long enough that it was repeated as the
plan, across a whole session's work, after the change that falsified it had
already landed. The sentence outlived its evidence because no one was going to
check, and the README said 544 AArch64 instructions and 40 RV32I ones against
an actual 840 and 155.

A number in prose is a claim. This registers the claims worth checking and
computes each one, so a stale one fails a gate instead of becoming a plan.

It deliberately does *not* try to parse every number in every document. A
checker that claimed to do that and quietly matched nothing would be the same
failure one level up -- the registry below is short, explicit, and its
membership is the honest statement of what is checked.

`TABLES` is the same idea for a whole table. `llvm_backend.md` §8's decline
census went stale twice under a sentence promising it was recomputed, and the
second time the *labels* moved too -- a reason reworded from "writes 2 values"
to "writes N values" shifted every row beneath it. Checking one row would have
passed while the census as a whole was wrong, so a table is compared as a
table, labels by identity.

Usage:
  tools/doc_facts_check.py           # verify every registered fact
  tools/doc_facts_check.py --show    # print what each one computes to
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
CORPORA = ("rv32i rv64i aarch64_translation_seed rvmt_xpce simd_lanes rvv sve "
           "scalable_memory fp_scalar limbs regslice zbb_like").split()


def axis(command: str, corpus: str) -> str:
    source = AXIS_ROOT / "examples" / f"{corpus}.axisl"
    return subprocess.run(
        [*axis_prefix(), command, str(source), "-o", "/dev/stdout"],
        cwd=AXIS_ROOT, capture_output=True, text=True, check=True).stdout


def instructions(corpus: str) -> list[dict]:
    return json.loads(axis("emit-json", corpus))["instructions"]


def netlists(corpus: str, status: str) -> int:
    plan = json.loads(axis("emit-hw-json", corpus))
    return sum(1 for one in plan["instructions"] if one["status"] == status)


def isa_count(corpus: str, isa: str) -> int:
    return sum(1 for one in instructions(corpus) if one.get("isa") == isa)


def lift(corpus: str) -> list[dict]:
    table = json.loads(axis("emit-lift-json", corpus))
    return table["instructions"] if isinstance(table, dict) else table


# Prose in this repository writes small counts as words, and a claim is a claim
# whether it is spelled `4` or `four`. Reading both is cheaper than forcing
# every corrected sentence into digits, which is what the first version of this
# did to two of them.
NUMBER_WORDS = {
    "zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19, "twenty": 20,
    "thirty": 30, "forty": 40, "fifty": 50,
}


def stated_number(text: str) -> int | None:
    """The number a document states, in digits or in words."""
    if text.isdigit():
        return int(text)
    return NUMBER_WORDS.get(text.lower())


def gates_matching(tool: str) -> int:
    """How many ladder gates run a tool whose name contains this."""
    sys.path.insert(0, str(AXIS_ROOT / "tools"))
    from check_all import matrix

    return sum(1 for _label, argv, _slow in matrix(with_pce=False)
               if any(tool in arg for arg in argv))


def gates_naming(corpus: str) -> int:
    """How many ladder gates name this corpus, read from the matrix itself.

    A gate carries its arguments in its argv, so this cannot drift from what
    actually runs -- the same reason `corpus_coverage_check` reads the matrix
    rather than the source text.
    """
    sys.path.insert(0, str(AXIS_ROOT / "tools"))
    from check_all import matrix

    return sum(1 for _label, argv, _slow in matrix(with_pce=False)
               if any(arg.endswith(f"{corpus}.axisl") for arg in argv))


def patterns(corpus: str) -> int:
    return axis("emit-llvm-target", corpus).count("\ndef : Pat")


# (file, a regex whose one group is the number, what it should be)
#
# The regex has to be specific enough that it matches the sentence meant and
# not a number that happens to look like it -- a fact that stops matching is
# reported as a failure, because a claim that has been reworded away is a claim
# nobody is checking any more.
FACTS: list[tuple[str, str, str]] = [
    ("README.md", r"elaborates to (\d+) instructions",
     "aarch64_translation_seed: total instructions"),
    ("README.md", r"(\d+) AArch64 and the",
     "aarch64_translation_seed: aarch64_base instructions"),
    ("README.md", r"and the (\d+) of the accelerator",
     "aarch64_translation_seed: accelerator_scalar64 instructions"),
    ("README.md", r"elaborates to (\d+),\n?being RV32I|elaborates to (\d+),",
     "rv32i: total instructions"),
    # The staging section marks each stage `_Done._` as it lands, and the status
    # line at the top said B1-B3 long after B4 and every G stage had. Nothing
    # computed it, so nothing noticed.
    ("docs/vliw_spatial_design.md", r"Status: \*\*(\d+) stages implemented\*\*",
     "vliw_spatial_design: stages marked done"),
    # Two more status headers, for the same reason and after the same failure:
    # `personality_design.md` said "proposal" and `scalable_vectors_design.md`
    # said "designed, not built" for as long as every stage in each had been
    # built and gated. A status line is a claim about the repository like any
    # other number here, and these two had gone years without one.
    ("docs/personality_design.md", r"Status: \*\*(\d+) stages implemented\*\*",
     "personality_design: stages marked done"),
    ("docs/scalable_vectors_design.md", r"Status: \*\*(\d+) stages implemented\*\*",
     "scalable_vectors_design: stages marked implemented"),
    ("docs/effects_design.md", r"Status: \*\*(\d+) stages implemented\*\*",
     "effects_design: stages marked done"),
    # Registered with its first landed stage rather than later, which is the
    # whole lesson of the three above: a status line written once and never
    # recomputed is how each of them went stale.
    ("docs/tensor_design.md", r"Status: \*\*(\d+) stages? implemented\*\*",
     "tensor_design: stages marked done"),
    # Registered with H1 and H2, and with the two counts the document's table
    # leads with: how many instructions have a netlist is exactly the number
    # that falls silently when an operator loses its arm.
    ("docs/hardware_design.md", r"Status: \*\*(\d+) stages? implemented\*\*",
     "hardware_design: stages marked done"),
    ("docs/hardware_design.md", r"\| RV64I \| (\d+) \| 0 \|", "rv64i: instructions with a netlist"),
    ("docs/hardware_design.md", r"\| RV32I \| (\d+) \| 0 \|", "rv32i: instructions with a netlist"),
    ("docs/hardware_design.md", r"declines (\d+) instructions and builds",
     "aarch64_translation_seed: instructions with no netlist"),
    # A gate count is a claim about the matrix, and two of them had drifted the
    # cheap way -- a gate was added and the sentence was not. Counting the
    # matrix entries that name the corpus is the same derivation the
    # `named_by_gates` half of corpus coverage makes.
    # Numbers written into a correction are claims like any other. Each of
    # these replaced a sentence that had gone stale -- "CSRs and floating point
    # are non-goals", "a multi-write ABI is open", "native codegen not yet" --
    # so each is computed, and the correction cannot rot the way the claim it
    # replaced did.
    ("docs/effects_design.md", r"(\d+)\s+Zicsr instructions", "rv32i: CSR instructions"),
    ("docs/effects_design.md", r"The (\d+) `ldp`/`stp`\s+forms",
     "aarch64_translation_seed: ldp/stp forms"),
    ("docs/effects_design.md", r"bounds it at (\w+), and the bound",
     "effects: EFFECT_MAX_WRITES"),
    ("docs/generated_artifacts_plan.md", r"in three backends with (\w+) gates",
     "matrix: JIT gates"),
    # An absence, stated as the number it is. Three documents lean on elastic
    # channels being unbuilt, and the argument for leaving them unbuilt is
    # empirical -- no consumer, no description. This is that fact, checked.
    ("docs/elastic_seams_design.md", r"contain (\d+) `defchannel` declarations",
     "corpora: defchannel declarations"),
    # And the seam count, for the same reason one document over: a gate that
    # requires a bound pair to be non-vacuous is a gate whose corpus can lose
    # the pair, and the header would go on claiming the rule is exercised.
    ("docs/elastic_seams_design.md", r"declarations and (\d+) bound seam",
     "corpora: bound seams"),
    ("docs/multicontext_design.md", r"corpora declare (\d+)\s*\nmulti-context",
     "corpora: multi-context accelerators"),
    ("docs/multicontext_design.md", r"Status: \*\*(\d+) stages implemented\*\*",
     "multicontext_design: stages marked done"),
    # An ABI is declared, so a corpus can lose the declaration and the L4 gate
    # would fail as vacuous while this header went on claiming L4 is built.
    ("docs/llvm_backend.md", r"corpora declare (\d+) calling convention",
     "corpora: calling conventions"),
    ("docs/frame_design.md", r"corpora declare (\d+) stack frame",
     "corpora: stack frames"),
    ("docs/binary_lift_design.md", r"publishes (\d+)\s*\neffect value trees",
     "rv32i: lift effects carrying a tree"),
    ("docs/binary_lift_design.md", r"^  (\d+) trees over every corpus",
     "corpora: trees the consumer-walker checks"),
    ("docs/binary_lift_design.md", r"compares against the executor on the same words: (\d+)",
     "blocks the graph gate evaluates"),
    ("docs/pce_migration.md", r"^(\d+) instructions cross-checked over every corpus",
     "instructions the capability join checks"),
    # The axiom sweep's own reach, because "35 corpora" is the kind of number
    # that becomes a plan.
    ("docs/pce_migration.md", r"golden model: (\d+) corpora, and rv32i",
     "corpora: emitting intrinsic axioms"),
    ("docs/pce_migration.md", r"rv32i alone is (\d+) axioms",
     "rv32i: intrinsic axioms"),
    ("docs/frame_design.md", r"Status: \*\*(\d+) stage[s]? implemented\*\*",
     "frame_design: stages marked done"),
    ("docs/loops_design.md", r"`examples/loops\.axisl`, (\d+) gates",
     "matrix: gates naming loops.axisl"),
    ("docs/register_slices.md", r"five emitters, (\d+) gates",
     "matrix: gates naming regslice.axisl"),
    # Drifted from 418 to 432 unnoticed, because nothing computed it: the
    # count of `deflowering` rules the AArch64 seed carries.
    ("docs/generated_artifacts_plan.md",
     r"exercises this path for (\d+) explicit lowerings",
     "aarch64_translation_seed: explicit lowerings"),
    ("docs/llvm_backend.md", r"^(\d+) patterns across twelve corpora",
     "all corpora: emitted patterns"),
    ("docs/llvm_backend.md", r"so AArch64 finished at (\d+)\.",
     "aarch64_translation_seed: emitted patterns"),
    ("docs/llvm_backend.md", r"(\d+) of that\ncorpus's \d+ instructions carry a structured",
     "aarch64_translation_seed: instructions with a behavior"),
    ("docs/llvm_backend.md", r"of that\ncorpus's (\d+) instructions carry a structured",
     "aarch64_translation_seed: total instructions"),
    ("docs/llvm_backend.md", r"(\d+) instruction\(s\) with no pattern, in \d+ shape",
     "aarch64_translation_seed: instructions with no pattern"),
]

COMPUTE = {
    "aarch64_translation_seed: total instructions":
        lambda: len(instructions("aarch64_translation_seed")),
    "aarch64_translation_seed: aarch64_base instructions":
        lambda: isa_count("aarch64_translation_seed", "aarch64_base"),
    "aarch64_translation_seed: accelerator_scalar64 instructions":
        lambda: isa_count("aarch64_translation_seed", "accelerator_scalar64"),
    "rv32i: total instructions": lambda: len(instructions("rv32i")),
    "vliw_spatial_design: stages marked done": lambda: len(re.findall(
        # `[\w.]` because a stage may be a sub-stage: G4b split into G4b.1,
        # G4b.2 and G4b.3, and a pattern that stopped at the dot counted the
        # first of them as no stage at all -- a header that stayed "correct"
        # by not seeing the entry underneath it.
        r"^- \*\*[ABG]\d[\w.]* .*?\*\* _Done\._",
        (AXIS_ROOT / "docs" / "vliw_spatial_design.md").read_text(), re.M)),
    "multicontext_design: stages marked done": lambda: len(re.findall(
        r"^- \*\*M\d+ .*?\*\* _Done\._",
        (AXIS_ROOT / "docs" / "multicontext_design.md").read_text(), re.M)),
    "personality_design: stages marked done": lambda: len(re.findall(
        r"^- \*\*P\d+ .*?\*\* _Done\._",
        (AXIS_ROOT / "docs" / "personality_design.md").read_text(), re.M)),
    # A different marker vocabulary, because that document uses one: a stage is
    # a `*` bullet naming itself and saying "Implemented". S6 says "Implemented,
    # less dynamic permutes", which is the caveat rather than a second state --
    # the stage is built and one operator inside it is not.
    "rv32i: CSR instructions": lambda: sum(
        1 for one in instructions("rv32i") if one["mnemonic"].startswith("CSRR")),
    "aarch64_translation_seed: ldp/stp forms": lambda: sum(
        1 for one in instructions("aarch64_translation_seed")
        if one["mnemonic"].startswith(("LDP", "STP"))),
    "effects: EFFECT_MAX_WRITES": lambda: int(re.search(
        r"pub const EFFECT_MAX_WRITES: usize = (\d+);",
        (AXIS_ROOT / "src" / "effects.rs").read_text()).group(1)),
    "matrix: JIT gates": lambda: gates_matching("jit_"),
    "corpora: defchannel declarations": lambda: sum(
        path.read_text().count("(defchannel")
        for path in (AXIS_ROOT / "examples").glob("*.axisl")),
    # `context-id-bits` rather than `contexts`, which `deffabric` also uses for
    # a different object (multicontext_design.md §2 argues why the word is
    # shared). Validation requires the id width on every declared engine, so
    # counting it counts exactly the multi-context accelerators.
    "corpora: multi-context accelerators": lambda: sum(
        path.read_text().count("(context-id-bits ")
        for path in (AXIS_ROOT / "examples").glob("*.axisl")),
    "corpora: emitting intrinsic axioms": lambda: sum(
        1 for path in sorted((AXIS_ROOT / "examples").glob("*.axisl"))
        if "(declare-fun " in axis("emit-smt-axioms", path.stem)),
    "rv32i: intrinsic axioms":
        lambda: axis("emit-smt-axioms", "rv32i").count("(declare-fun "),
    # Run rather than remembered: the walker's reach is the evidence X1 rests
    # on, and a number for it that nothing recomputes is the failure this whole
    # gate exists to prevent.
    "corpora: trees the consumer-walker checks": lambda: int(re.search(
        r"^(\d+) tree\(s\) walked",
        subprocess.run([sys.executable, str(AXIS_ROOT / "tools" / "lift_ast_check.py")],
                       cwd=AXIS_ROOT, capture_output=True, text=True).stdout,
        re.M).group(1)),
    "instructions the capability join checks": lambda: int(re.search(
        r"^(\d+) instruction\(s\) cross-checked",
        subprocess.run([sys.executable, str(AXIS_ROOT / "tools" / "capability_check.py")],
                       cwd=AXIS_ROOT, capture_output=True, text=True).stdout,
        re.M).group(1)),
    "blocks the graph gate evaluates": lambda: int(re.search(
        r"^(\d+) block\(s\) evaluated",
        subprocess.run([sys.executable, str(AXIS_ROOT / "tools" / "lift_block_check.py")],
                       cwd=AXIS_ROOT, capture_output=True, text=True).stdout,
        re.M).group(1)),
    "rv32i: lift effects carrying a tree":
        lambda: axis("emit-lift-json", "rv32i").count("\"value_ast\""),
    "corpora: stack frames": lambda: sum(
        path.read_text().count("(save-order ")
        for path in (AXIS_ROOT / "examples").glob("*.axisl")),
    "frame_design: stages marked done": lambda: len(re.findall(
        r"^- \*\*F\d+ .*?\*\* _Done\._",
        (AXIS_ROOT / "docs" / "frame_design.md").read_text(), re.M)),
    "corpora: calling conventions": lambda: sum(
        path.read_text().count("(defabi ")
        for path in (AXIS_ROOT / "examples").glob("*.axisl")),
    "corpora: bound seams": lambda: sum(
        path.read_text().count("(imports (")
        for path in (AXIS_ROOT / "examples").glob("*.axisl")),
    "matrix: gates naming loops.axisl": lambda: gates_naming("loops"),
    "matrix: gates naming regslice.axisl": lambda: gates_naming("regslice"),
    "effects_design: stages marked done": lambda: len(re.findall(
        r"^- \*\*E\d+ .*?\*\* _Done\._",
        (AXIS_ROOT / "docs" / "effects_design.md").read_text(), re.M)),
    "scalable_vectors_design: stages marked implemented": lambda: len(re.findall(
        r"^\* \*\*S\d+ .*?[Ii]mplemented",
        (AXIS_ROOT / "docs" / "scalable_vectors_design.md").read_text(), re.M)),
    "hardware_design: stages marked done": lambda: len(re.findall(
        r"^- \*\*H[\w.]+ .*?\*\* _Done\._",
        (AXIS_ROOT / "docs" / "hardware_design.md").read_text(), re.M)),
    "rv64i: instructions with a netlist": lambda: netlists("rv64i", "built"),
    "rv32i: instructions with a netlist": lambda: netlists("rv32i", "built"),
    "aarch64_translation_seed: instructions with no netlist":
        lambda: netlists("aarch64_translation_seed", "declined"),
    "tensor_design: stages marked done": lambda: len(re.findall(
        # `[\w.]` for the same reason the VLIW rule has it: T1 split into T1,
        # T1b and T1c the moment bf16 turned out to need a different mechanism
        # from f16, and a count that missed the sub-stages would have reported
        # a stale number while looking like it was computing one.
        r"^- \*\*T[\w.]+ .*?\*\* _Done\._",
        (AXIS_ROOT / "docs" / "tensor_design.md").read_text(), re.M)),
    "aarch64_translation_seed: explicit lowerings":
        lambda: json.loads(axis("emit-translation-json",
                                "aarch64_translation_seed"))["explicit_lowering_count"],
    "all corpora: emitted patterns":
        lambda: sum(patterns(corpus) for corpus in CORPORA),
    "aarch64_translation_seed: emitted patterns":
        lambda: patterns("aarch64_translation_seed"),
    "aarch64_translation_seed: instructions with a behavior":
        lambda: sum(1 for one in lift("aarch64_translation_seed")
                    if one.get("effects")),
    # Distinct *instructions*, not decline lines. An instruction with several
    # specialisations gets a line per form that failed, so counting lines said
    # 679 where 585 instructions have no pattern -- and the difference is
    # exactly the sort of number that reads as authoritative and is not.
    "aarch64_translation_seed: instructions with no pattern":
        lambda: len({found for found in re.findall(
            r"^// (\S+): .*; no pattern$",
            axis("emit-llvm-target", "aarch64_translation_seed"), re.M)}),
}


# A whole table, rather than a number at a time. §8's census is eleven counts
# and eleven labels that drift together -- when a decline reason was reworded
# from "writes 2 values beside its state" to "writes N values", every row below
# it moved -- so checking one row would have passed while the table as a whole
# was wrong. Comparing labels by identity is the point: a renamed cause is a
# changed census, not a cosmetic edit.
TABLES: list[tuple[str, str, str]] = [
    ("docs/llvm_backend.md", "| cause | count |",
     "aarch64_translation_seed: decline census"),
]

CENSUS_ROWS = 10


def aarch64_decline_census() -> list[tuple[str, int]]:
    """The census `llvm_target_check.py` prints, from the same target file.

    Computed from `emit-llvm-target` alone: the decline reasons are comments in
    the emitted `.td`, so this needs no tblgen, no compiler and no execution --
    which is what makes it cheap enough to live in this gate.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from llvm_target_check import decline_census

    census = decline_census(axis("emit-llvm-target", "aarch64_translation_seed"))
    named = census[:CENSUS_ROWS]
    rest = census[CENSUS_ROWS:]
    if rest:
        named.append((f"everything else, in {len(rest)} further reasons",
                      sum(count for _, count in rest)))
    return named


TABLE_COMPUTE = {
    "aarch64_translation_seed: decline census": aarch64_decline_census,
}


def stated_table(text: str, header: str) -> list[tuple[str, int]] | None:
    """The rows of the markdown table that starts with `header`."""
    start = text.find(header)
    if start < 0:
        return None
    rows = []
    for line in text[start:].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if len(cells) != 2 or not cells[1].isdigit():
            break
        rows.append((cells[0], int(cells[1])))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--show", action="store_true",
                        help="print each fact's computed value")
    args = parser.parse_args()

    computed = {name: how() for name, how in COMPUTE.items()}
    if args.show:
        for name, value in computed.items():
            print(f"{value:6d}  {name}")
        return 0

    failures = []
    for path, pattern, name in FACTS:
        text = (AXIS_ROOT / path).read_text()
        found = re.search(pattern, text, re.M)
        if not found:
            failures.append(f"  {path}: no longer says anything matching "
                            f"/{pattern}/ -- {name} is unchecked")
            continue
        stated = stated_number(next(group for group in found.groups() if group))
        if stated is None:
            failures.append(f"  {path}: {name} is written as something this "
                            f"cannot read as a number")
            continue
        if stated != computed[name]:
            failures.append(f"  {path}: says {stated}, {name} is "
                            f"{computed[name]}")

    for path, header, name in TABLES:
        text = (AXIS_ROOT / path).read_text()
        stated = stated_table(text, header)
        computed_rows = TABLE_COMPUTE[name]()
        if stated is None:
            failures.append(f"  {path}: no table starting `{header}` -- {name} "
                            f"is unchecked")
        elif stated != computed_rows:
            failures.append(f"  {path}: {name} has drifted")
            for row in range(max(len(stated), len(computed_rows))):
                was = stated[row] if row < len(stated) else None
                now = computed_rows[row] if row < len(computed_rows) else None
                if was != now:
                    failures.append(f"      says {was}, computes {now}")

    if failures:
        print(f"FAIL: {len(failures)} stated number(s) do not match:")
        print("\n".join(failures))
        return 1
    print(f"documented numbers == computed: PASS ({len(FACTS)} checked, "
          f"{len(TABLES)} table(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())
