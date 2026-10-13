#!/usr/bin/env python3
"""Differential check: the generated decode tree agrees with a linear scan.

`emit-decode-c` emits two decoders over one table. `axis_decode_linear_in_isa`
is the obviously correct one -- it looks at every entry and applies the
selection rules in order. `axis_decode_in_isa` walks a tree that partitions the
table on bits every candidate constrains, so it reaches a small leaf and
applies those same rules there. The tree is what a consumer calls; the scan is
what makes the tree checkable.

The two are not checked by reading them. This compiles the generated header
and requires the tree and the scan to return *the same entry pointer* for:

  * every instruction's match word, and that word with each don't-care bit
    randomised -- the words that actually decode;
  * every single-bit flip of every match word, which is how a near-miss finds
    a partition that dropped a candidate it should have kept;
  * pseudorandom words, which are almost all misses, so the tree's "no child
    claims this value -> NULL" shortcut has to agree that nothing matched;
  * all of the above under each ISA string in the table and under NULL, since
    the ISA filter runs after selection and can turn a hit into a miss.

A disagreement is printed as the word and the two answers.

Usage: tools/decode_tree_check.py <input.axisl> [<input.axisl> ...]

Requires: cargo (run from the AXIS repo root), a C compiler on PATH (cc).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import DECLINED, FAILED, PASSED, axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

DRIVER = r"""
#include <stdio.h>
#include "axis_decode.h"

static uint64_t seed = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void) {
  seed = seed * 6364136223846793005ull + 1442695040888963407ull;
  return (uint32_t)(seed >> 32);
}

/* Every distinct ISA string in the table, plus NULL. The filter runs after
   selection in both decoders, so it is part of what has to agree. */
static const char *isas[64];
static size_t isa_count = 0;

static void collect_isas(void) {
  isas[isa_count++] = NULL;
  for (size_t i = 0; i < AXIS_DECODE_TABLE_LEN && isa_count < 64; ++i) {
    const char *name = AXIS_DECODE_TABLE[i].isa;
    if (!name || !name[0]) { continue; }
    int seen = 0;
    for (size_t j = 0; j < isa_count; ++j) {
      if (isas[j] && strcmp(isas[j], name) == 0) { seen = 1; break; }
    }
    if (!seen) { isas[isa_count++] = name; }
  }
}

static long words = 0;
static long failures = 0;

static void compare(uint32_t insn) {
  for (size_t i = 0; i < isa_count; ++i) {
    const axis_decode_entry *tree = axis_decode_in_isa(insn, isas[i]);
    const axis_decode_entry *scan = axis_decode_linear_in_isa(insn, isas[i]);
    ++words;
    if (tree == scan) { continue; }
    if (++failures <= 8) {
      printf("  0x%08x isa=%s: tree=%s scan=%s\n", insn,
             isas[i] ? isas[i] : "(any)",
             tree ? tree->mnemonic : "(none)",
             scan ? scan->mnemonic : "(none)");
    }
  }
}

int main(void) {
  collect_isas();
  for (size_t i = 0; i < AXIS_DECODE_TABLE_LEN; ++i) {
    const uint32_t match = AXIS_DECODE_TABLE[i].match;
    const uint32_t mask = AXIS_DECODE_TABLE[i].mask;
    compare(match);
    /* The don't-care bits carry the operands. Filling them at random is how
       a real instruction word differs from its match value. */
    for (int k = 0; k < DONTCARE_SAMPLES; ++k) {
      compare(match | (rnd() & ~mask));
    }
    /* One bit wrong. If a partition dropped a candidate, the word that finds
       it is next to a word that matches. */
    for (int bit = 0; bit < 32; ++bit) {
      compare(match ^ (1u << bit));
    }
  }
  for (long k = 0; k < RANDOM_WORDS; ++k) { compare(rnd()); }
  printf("%ld comparisons, %ld disagreements\n", words, failures);
  return failures == 0 ? 0 : 1;
}
"""


def check(axis_file: Path) -> int:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp)
        header = workdir / "axis_decode.h"
        subprocess.run(
            [*axis_prefix(), "emit-decode-c", str(axis_file), "-o", str(header)],
            check=True,
            cwd=AXIS_ROOT,
        )
        text = header.read_text()
        # A corpus whose table is empty has no decoder to disagree about, and
        # the driver would print "0 disagreements" and read as a pass.
        entries = text.count("  { AXIS_INSN_")
        if entries == 0:
            print(f"{axis_file.name}: no decodable instruction, so no decoder "
                  f"to differ -> DECLINE")
            return DECLINED
        # The tree is a tree only when it branches. On a table small enough to
        # fit one leaf the two decoders are the same loop over the same set,
        # which is agreement with nothing to say.
        branching = text.count("  { 0x") > 1
        # Big tables cost more per word, so spend the words where the table is.
        samples = 8 if entries > 400 else 24
        random_words = 20000 if entries > 400 else 60000
        main_c = workdir / "main.c"
        main_c.write_text(
            f"#define DONTCARE_SAMPLES {samples}\n"
            f"#define RANDOM_WORDS {random_words}\n" + DRIVER
        )
        binary = workdir / "decode_tree"
        subprocess.run(
            ["cc", "-std=c11", "-O1", "-Wall", "-Werror", "-o", str(binary),
             str(main_c)],
            check=True,
        )
        result = subprocess.run([str(binary)], capture_output=True, text=True)
    report = result.stdout.strip()
    if result.returncode != 0:
        print(f"{axis_file.name}: {report} -> FAIL")
        return FAILED
    shape = "tree" if branching else "single leaf"
    print(f"{axis_file.name}: {entries} entries, {shape}, {report} -> PASS")
    return PASSED


def main() -> int:
    # Every corpus by default. The two decoders differ only where the tree
    # branches, and the tables that branch most are exactly the ones no short
    # default list would have named -- 854 AArch64 entries against 1 for an
    # accelerator descriptor.
    files = [Path(arg) for arg in sys.argv[1:]] or sorted(
        (AXIS_ROOT / "examples").glob("*.axisl"))
    results = [check(axis_file) for axis_file in files]
    trees = sum(1 for status in results if status == PASSED)
    print(f"{len(results)} corpus decoder(s): {trees} checked, "
          f"{results.count(DECLINED)} with no table, "
          f"{results.count(FAILED)} disagreeing")
    if FAILED in results:
        print("DECODE TREE CHECK FAILED")
        return FAILED
    if not trees:
        print("DECODE TREE CHECK DECLINED: no corpus had a decode table")
        return DECLINED
    print("DECODE TREE CHECK PASSED")
    return PASSED


if __name__ == "__main__":
    sys.exit(main())
