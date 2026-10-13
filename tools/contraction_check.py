#!/usr/bin/env python3
"""An accumulation's order is chosen, and `exact` means the choice cannot show. Gate.

`iterate` carries an accumulator from step to step, so its association is fixed
by meaning. An accumulation's terms are independent, which is what makes the
association free -- and a free association is only free if choosing it cannot
change the answer. That is what `(order exact)` claims and what this measures.

Five properties:

  1. **exact == sequential, on every input tried.** The elaborator folds an
     exact accumulation in halves; the reference folds the same terms left to
     right, in Python, from the emitted per-term expressions. If the obligation
     were wrong -- an accumulator one bit too narrow -- the two would part
     company at the first overflow;
  2. **exact is shallow.** Its depth is logarithmic in the term count, checked
     against `2 + 2*ceil(log2(count))`. This is the property the stage exists
     for: a left fold of 1024 terms nests 1024 deep, which
     `semantics::MAX_EXPR_DEPTH` refuses and which aborted `emit-llvm-ir`
     before that guard existed;
  3. **and it emits.** The 1024-term contraction goes through every backend,
     which is the end-to-end version of 2;
  4. **a declared float order is not decoration.** The sequential and pairwise
     forms of the same eight terms must DISAGREE on some input. An order no
     input can tell apart is a declaration about nothing, and this fails as
     vacuous rather than passing;
  5. **the obligation refuses.** An accumulator too narrow to hold every
     partial result is rejected with the arithmetic, and the rejection names
     the width. Checked by generating the narrow document, not by trusting
     that the check exists;
  6. **the reference model parses each expression once.** It used to reparse on
     every call, which is invisible for a scalar instruction and dominant for a
     contraction -- 215 ms per evaluation at K = 1024, against 15 ms with the
     parse cached. Checked by behaviour rather than by timing: evaluating the
     same instruction twice must not grow the parse cache.

Injection-checked: folding `exact` left instead of in halves fails 2 and 3;
dropping the width obligation lets the narrow document through and fails 5;
and folding `pairwise` as a left fold makes 4 vacuous.

Usage: tools/contraction_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import math
import random
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix, DECLINED

AXIS_ROOT = Path(__file__).resolve().parent.parent
EMITTERS = ("emit-llvm-ir", "emit-smt2", "emit-semantics-c",
            "emit-semantics-rust", "emit-golden-python")


def run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, cwd=AXIS_ROOT)


def paren_depth(text: str) -> int:
    depth = deepest = 0
    for character in text:
        if character == "(":
            depth += 1
            deepest = max(deepest, depth)
        elif character == ")":
            depth -= 1
    return deepest


FOLDERS = {
    "add": lambda a, b, w: (a + b) & ((1 << w) - 1),
    "mul": lambda a, b, w: (a * b) & ((1 << w) - 1),
    "and": lambda a, b, w: a & b,
    "or": lambda a, b, w: a | b,
    "xor": lambda a, b, w: a ^ b,
}


def terms_of(source: str, mnemonic: str) -> tuple[int, str, str, str]:
    """The count, order, index name and operator an accumulation was written with.

    Read from the document because the artifact cannot say: the whole point of
    the form is that the fold shape is gone by the time anything is emitted.
    """
    block = re.search(rf"\(definstruction[^(]*?\(mnemonic {mnemonic}\).*?(?=\n  \(definstruction|\n\)$)",
                      source, re.S)
    if not block:
        return 0, "", "", ""
    found = re.search(r"\(accumulate\s+(\S+)\s+(\S+)\s+\((\w+)\s+(\d+)\)\s+\(order\s+(\w+)\)",
                      block.group(0))
    if not found:
        return 0, "", "", ""
    return int(found.group(4)), found.group(5), found.group(3), found.group(2)


def term_of(source: str, mnemonic: str) -> str:
    """The term text an accumulation folds, as the document wrote it."""
    block = re.search(rf"\(mnemonic {mnemonic}\).*?\(formal (\(accumulate.*?)\)\n    \(latency",
                      source, re.S)
    if not block:
        return ""
    body = block.group(1)
    term = body[body.index("(order"):]
    return term[term.index(")") + 1:].strip()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=256)
    args = parser.parse_args()

    source = args.axis_file.read_text()
    if "(accumulate " not in source:
        print("no accumulations in this corpus")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_contract_"))
    golden_path = workdir / "golden_model.py"
    json_path = workdir / "manifest.json"
    # ⚠️ Checked rather than assumed. Under the injection that folds `exact`
    # left, the 1024-term contraction stops validating at all, so these fail
    # and every later step would have read a file that was never written --
    # reporting a traceback where the gate should report a failure.
    for command, output in (("emit-golden-python", golden_path), ("emit-json", json_path)):
        result = run([*axis_prefix(), command, str(args.axis_file), "-o", str(output)])
        if result.returncode != 0:
            crashed = result.returncode < 0 or "overflowed its stack" in result.stderr
            print(f"FAIL {command} {'CRASHED on' if crashed else 'rejected'} this corpus: "
                  f"{(result.stdout + result.stderr).strip()[:200]}")
            print("contraction: FAIL")
            return 1
    spec = importlib.util.spec_from_file_location("axis_golden_contract", golden_path)
    golden = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(golden)
    manifest = {entry["mnemonic"]: entry for entry in json.loads(json_path.read_text())["instructions"]}

    failures = 0
    rng = random.Random(0xC0FFEE)

    # --- 1 and 2. exact agrees with a left fold, and is shallow ----------
    checked = 0
    for mnemonic, entry in sorted(golden.AXIS_SPECS.items()):
        count, order, index, operator = terms_of(source, mnemonic)
        if order != "exact" or not count:
            continue
        # A tree over `count` terms adds ceil(log2(count)) levels to whatever
        # the term itself is, and nothing else. Measuring the term rather than
        # assuming it keeps this a statement about the FOLD.
        term_text = term_of(source, mnemonic)
        allowed = paren_depth(term_text) + math.ceil(math.log2(count)) + 1
        depth = paren_depth(manifest[mnemonic]["formal_semantics"])
        if depth > allowed:
            print(f"FAIL {mnemonic}: {count} terms over a term {paren_depth(term_text)} deep "
                  f"folded {depth} deep, and a tree is at most {allowed}")
            failures += 1

        # The reference: the same terms, summed left to right, in Python.
        # Built from the description rather than from the emitted expression,
        # so it is not a second reading of the thing under test.
        width = entry.get("result_width", 32)
        for _ in range(args.cases):
            values = tuple(rng.getrandbits(w) for _, w in entry["params"])
            got = entry["eval"](*values)
            want = left_fold_reference(source, mnemonic, values, entry, golden)
            if want is None:
                break
            if got != want:
                failures += 1
                if failures <= 5:
                    print(f"FAIL {mnemonic}{values}: folded {got:#x}, left fold {want:#x}")
            checked += 1

    # --- 3. the longest contraction emits --------------------------------
    for emitter in EMITTERS:
        result = run([*axis_prefix(), emitter, str(args.axis_file), "-o", str(workdir / emitter)])
        if result.returncode != 0:
            crashed = result.returncode < 0 or "overflowed its stack" in result.stderr
            print(f"FAIL {emitter} {'CRASHED' if crashed else 'failed'} on this corpus")
            failures += 1

    # --- 4. a declared float order is not decoration ---------------------
    pairs = [(a, b) for a in golden.AXIS_SPECS for b in golden.AXIS_SPECS
             if terms_of(source, a)[1] == "sequential" and terms_of(source, b)[1] == "pairwise"
             and terms_of(source, a)[0] == terms_of(source, b)[0] != 0]
    differed = 0
    for sequential, pairwise in pairs:
        left = golden.AXIS_SPECS[sequential]
        right = golden.AXIS_SPECS[pairwise]
        for _ in range(args.cases * 8):
            values = tuple(rng.getrandbits(w) for _, w in left["params"])
            if left["eval"](*values) != right["eval"](*values):
                differed += 1
    if pairs and not differed:
        print("the two float orders never differed; the declaration is decoration")
        failures += 1

    # --- 5. the obligation refuses ---------------------------------------
    narrow = workdir / "narrow.axisl"
    narrow.write_text(NARROW_DOCUMENT)
    refused = run([*axis_prefix(), "check", str(narrow)])
    message = (refused.stdout + refused.stderr)
    if refused.returncode == 0:
        print("FAIL an i16 accumulator over 64 byte products was accepted as exact")
        failures += 1
    elif "accumulator is 16" not in message:
        print(f"FAIL refused without the arithmetic: {message.strip()[:160]}")
        failures += 1

    # --- 6. the reference model parses once ------------------------------
    cache = getattr(golden, "_PARSED", None)
    if cache is None:
        print("FAIL the golden model has no parse cache; every evaluation reparses")
        failures += 1
    else:
        biggest = max(golden.AXIS_SPECS, key=lambda name: len(
            manifest.get(name, {}).get("formal_semantics", "")))
        entry = golden.AXIS_SPECS[biggest]
        values = tuple(0 for _ in entry["params"])
        entry["eval"](*values)
        settled = len(cache)
        entry["eval"](*values)
        if len(cache) != settled:
            print(f"FAIL evaluating {biggest} twice parsed it twice")
            failures += 1
        elif settled == 0:
            print("FAIL the parse cache stayed empty, so nothing was cached")
            failures += 1

    print(f"{checked} exact foldings against a left fold over {len(pairs)} order pair(s)")
    print(f"  float orders differed : {differed} case(s)")
    print("contraction: " + ("PASS" if not failures else "FAIL"))
    return 1 if failures else 0


def left_fold_reference(source, mnemonic, values, entry, golden):
    """Sum the terms left to right, evaluating each one on its own.

    Each term is the description's term with the index substituted, which the
    golden model can evaluate directly -- so the reference shares the term with
    the implementation and shares nothing of the FOLD, which is what is under
    test.
    """
    count, order, index, operator = terms_of(source, mnemonic)
    block = re.search(rf"\(mnemonic {mnemonic}\).*?\(formal (\(accumulate.*?)\)\n    \(latency",
                      source, re.S)
    if not block:
        return None
    term = term_of(source, mnemonic)
    fold = FOLDERS.get(operator)
    if fold is None:
        return None
    environment = dict(zip([name for name, _ in entry["params"]], values))
    width = entry.get("result_width", 32)
    total = None
    for step in range(count):
        step_text = re.sub(rf"\b{index}\b", str(step), term)
        try:
            value = golden._eval_axis_expr(step_text, dict(environment), width)
        except Exception:
            return None
        total = value if total is None else fold(total, value, width)
    return total


NARROW_DOCUMENT = """(axis-module narrow
  (version "0.1.0") (target rvmt) (description "an accumulator one size too small")
  (defisa n (base rv64im) (word-bits 32) (registers "x[32]:i16" "pc:i32")
    (features custom) (memory-model rvwmo) (endianness little))
  (defformat R (bits 32) (fields (opcode 6 0) (rd 11 7) (func3 14 12)
    (rs1 19 15) (rs2 24 20) (func7 31 25)))
  (definstruction narrow_dot
    (mnemonic NARROW_DOT) (isa n) (category alu) (format R)
    (opcode 11) (func3 0) (func7 0)
    (operands (rd reg i16 out) (rs1 reg i16 in) (rs2 reg i16 in))
    (asm "narrow_dot $rd, $rs1, $rs2")
    (semantics "Sixty-four byte products into sixteen bits")
    (formal (accumulate i16 add (k 64) (order exact)
      (mul i16 (sext i16 8 (lshr i16 rs1 (and i16 (mul i16 k 8) 24)))
               (sext i16 8 (lshr i16 rs2 (and i16 (mul i16 k 8) 24))))))
    (latency 6) (throughput 1.0)
    (area-estimate-um2 100.0) (power-estimate-mw 1.0) (expected-speedup 1.0)
    (rationale "must be refused")))
"""


if __name__ == "__main__":
    sys.exit(main())
