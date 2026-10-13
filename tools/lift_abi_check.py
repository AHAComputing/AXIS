#!/usr/bin/env python3
"""The lifter's C ABI does what the command does.

The lifter is a Rust library, and until it had a C ABI the only way to reach it
was to spawn `axis` and read text back. That is fine for a person and wrong for
a program: the per-instruction sweep spent most of its time re-parsing a
nine-hundred-instruction description, once per instruction.

This compiles a C program against the library and requires it to produce, for
the same bytes, exactly what `axis lift-llvm` and `axis lift-blocks` produce.
Two doors onto one lifter is two things that can drift apart, so the check is
byte-for-byte rather than "looks similar".

It also exercises the size-then-fill contract -- ask with no buffer, get the
length; ask again, get the text -- because a caller that trusts a returned
length is the one that overflows when it is wrong.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

PROBE = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "axis_lift.h"

/* Ask for the size, allocate, ask again -- the contract the header states. */
static char *query(intptr_t (*call)(const axis_lifter *, const unsigned char *,
                                    intptr_t, uint64_t, const char *, char *,
                                    intptr_t),
                   const axis_lifter *h, const unsigned char *bytes,
                   intptr_t count, uint64_t addr, const char *isa) {
  intptr_t needed = call(h, bytes, count, addr, isa, NULL, 0);
  if (needed < 0) { fprintf(stderr, "%s\n", axis_lift_last_error()); return NULL; }
  char *buffer = malloc((size_t)needed + 1);
  intptr_t again = call(h, bytes, count, addr, isa, buffer, needed + 1);
  if (again != needed) {
    fprintf(stderr, "size disagreed: %ld then %ld\n", (long)needed, (long)again);
    free(buffer);
    return NULL;
  }
  return buffer;
}

int main(int argc, char **argv) {
  if (argc < 6) { fprintf(stderr, "usage: probe <desc> <bin> <addr> <isa> <out>\n"); return 2; }
  axis_lifter *h = axis_lift_open(argv[1]);
  if (!h) { fprintf(stderr, "open: %s\n", axis_lift_last_error()); return 2; }

  FILE *image = fopen(argv[2], "rb");
  if (!image) { fprintf(stderr, "cannot read %s\n", argv[2]); return 2; }
  static unsigned char bytes[65536];
  size_t count = fread(bytes, 1, sizeof bytes, image);
  fclose(image);

  uint64_t addr = strtoull(argv[3], NULL, 16);
  const char *isa = argv[4][0] ? argv[4] : NULL;

  if (axis_lift_instruction_count(h) <= 0) {
    fprintf(stderr, "no instructions\n"); return 2;
  }

  char *blocks = query(axis_lift_blocks, h, bytes, (intptr_t)count, addr, isa);
  if (!blocks) return 2;
  char *llvm = query(axis_lift_llvm, h, bytes, (intptr_t)count, addr, isa);
  if (!llvm) { free(blocks); return 2; }

  intptr_t needed = axis_lift_support(h, NULL, 0);
  char *support = malloc((size_t)needed + 1);
  axis_lift_support(h, support, needed + 1);

  /* The split has to compose back into the whole: a consumer that emits the
     preamble once and appends each region's blocks must get the same module a
     self-contained lift gives, or the two paths are two lifters. */
  intptr_t pre_len = axis_lift_preamble(h, NULL, 0);
  char *preamble = malloc((size_t)pre_len + 1);
  axis_lift_preamble(h, preamble, pre_len + 1);
  char *bodies = query(axis_lift_llvm_blocks, h, bytes, (intptr_t)count, addr, isa);
  if (!bodies) { fprintf(stderr, "blocks-only lift failed\n"); return 2; }
  size_t joined = strlen(preamble) + strlen(bodies);
  if (joined != strlen(llvm) ||
      strncmp(preamble, llvm, strlen(preamble)) != 0 ||
      strcmp(bodies, llvm + strlen(preamble)) != 0) {
    fprintf(stderr, "preamble + blocks != whole module (%zu vs %zu)\n",
            joined, strlen(llvm));
    return 2;
  }
  free(preamble); free(bodies);

  FILE *out = fopen(argv[5], "wb");
  fputs(blocks, out); fputc('\x01', out);
  fputs(llvm, out);   fputc('\x01', out);
  fputs(support, out);
  fclose(out);

  free(blocks); free(llvm); free(support);
  axis_lift_close(h);
  return 0;
}
'''


def command(args, *rest) -> str:
    result = subprocess.run([*axis_prefix(), *rest], capture_output=True,
                            text=True, cwd=AXIS_ROOT)
    return result.stdout if result.returncode == 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "rv64i.axisl")
    parser.add_argument("--addr", default="0")
    parser.add_argument("--isa", default="")
    parser.add_argument("--cc", default="cc")
    args = parser.parse_args()

    library = AXIS_ROOT / "target" / "release" / "libaxis_adl.a"
    if not library.exists():
        print("SKIP: no libaxis_adl.a; build with `cargo build --release`")
        return DECLINED

    workdir = Path(tempfile.mkdtemp(prefix="axis_liftabi_"))
    # Bytes to lift: the description's own fixtures, laid out back to back.
    import json
    fixtures = json.loads(subprocess.run(
        [*axis_prefix(), "emit-roundtrip-json", str(args.axis_file)],
        capture_output=True, text=True, check=True, cwd=AXIS_ROOT).stdout)["tests"]
    widths = {row["mnemonic"]: row["bits"] for row in json.loads(subprocess.run(
        [*axis_prefix(), "emit-decode-json", str(args.axis_file)],
        capture_output=True, text=True, check=True,
        cwd=AXIS_ROOT).stdout)["instructions"]}
    isa = args.isa or (fixtures[0].get("isa") or "")
    image = bytearray()
    for test in fixtures:
        if (test.get("isa") or "") != isa:
            continue
        image += int(test["encoded"], 16).to_bytes(
            widths.get(test["mnemonic"], 32) // 8, "little")
        if len(image) >= 256:
            break
    binary = workdir / "region.bin"
    binary.write_bytes(bytes(image))

    (workdir / "probe.c").write_text(PROBE)
    build = subprocess.run(
        [args.cc, "-std=c11", "-I", str(AXIS_ROOT / "include"),
         "-o", str(workdir / "probe"), str(workdir / "probe.c"), str(library),
         "-lm", "-framework", "CoreFoundation", "-framework", "Security"]
        if sys.platform == "darwin" else
        [args.cc, "-std=c11", "-I", str(AXIS_ROOT / "include"),
         "-o", str(workdir / "probe"), str(workdir / "probe.c"), str(library),
         "-lm", "-lpthread", "-ldl"],
        capture_output=True, text=True)
    if build.returncode != 0:
        print("FAIL: the C probe did not link against the library")
        print(build.stderr.strip()[:600])
        return FAILED

    answer = workdir / "answer.txt"
    run = subprocess.run([str(workdir / "probe"), str(args.axis_file),
                          str(binary), args.addr, isa, str(answer)],
                         capture_output=True, text=True)
    if run.returncode != 0:
        print("FAIL: the C probe did not run")
        print(run.stderr.strip()[:600])
        return FAILED

    got_blocks, got_llvm, got_support = answer.read_text().split("\x01")

    argv = ["--binary", str(binary), "--addr", args.addr]
    if isa:
        argv += ["--isa", isa]
    want_blocks = command(args, "lift-blocks", str(args.axis_file), *argv)
    want_llvm = command(args, "lift-llvm", str(args.axis_file), *argv)
    want_support = command(args, "lift-support", str(args.axis_file))

    failures = []
    for name, got, want in (("blocks", got_blocks, want_blocks),
                            ("llvm", got_llvm, want_llvm),
                            ("support", got_support, want_support)):
        if want is None:
            failures.append(f"the command failed for {name}")
        elif got != want:
            first = next((i for i in range(min(len(got), len(want)))
                          if got[i] != want[i]), min(len(got), len(want)))
            failures.append(f"{name} differs at byte {first} "
                            f"({len(got)} vs {len(want)} bytes)")
    print(f"{len(image)} byte region, {len(want_llvm or '')} bytes of IR, "
          f"preamble + blocks composes, {len(failures)} disagreement(s)")
    for line in failures:
        print(f"  {line}")
    ok = not failures
    print("C ABI == command: " + ("PASS" if ok else "FAIL"))
    return PASSED if ok else FAILED


if __name__ == "__main__":
    raise SystemExit(main())
