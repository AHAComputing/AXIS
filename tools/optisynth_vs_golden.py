#!/usr/bin/env python3
"""Differential check: the emitted OptiSynth-dialect formal_semantics == golden.

AXIS emits, into aha_instructions.json / manifest.json, a `formal_semantics`
string in PCE OptiSynth's ADL.2 micro-DSL (binary ops, typed constants,
icmp/select). PCE registers that string as the Z3 *axiom* for the instruction's
intrinsic and derives rewrite rules from it — so if the translation is wrong,
PCE's verifier and sketcher reason from an unsound axiom. The Z3 proof gate on
the PCE side is a consistency check (pattern ≡ intrinsic, whose body *is* the
pattern), so it cannot catch a faithful-looking-but-wrong translation. This tool
does: it evaluates the emitted OptiSynth dialect with a faithful bitvector
interpreter and requires it to equal the trusted golden model on the golden
spec's own vectors plus randomized ones, for every `optisynth_compatible`
instruction. That makes the ADL.2 proof collateral trustworthy, not just
parseable — the AXIS-side guarantee behind every axiom PCE banks.

Usage: tools/optisynth_vs_golden.py [input.axisl ...]

With no arguments it checks every AHA-emittable example. Requires cargo (run from
the AXIS repo root); no PCE checkout needed.
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent

_CONST_RE = re.compile(r"^i(\d+):(-?\d+)$")
_WIDTH_RE = re.compile(r"^i(\d+)$")

_BINOPS = {"add", "sub", "mul", "and", "or", "xor", "shl", "lshr", "ashr",
           "udiv", "sdiv", "urem", "srem"}
_ICMPS = {"icmp_eq", "icmp_ne", "icmp_ult", "icmp_ule", "icmp_slt", "icmp_sle"}


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def load_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# --- OptiSynth-dialect interpreter (faithful to Z3 bitvector semantics) -------

def _tokenize(text: str):
    return re.findall(r"\(|\)|[^\s()]+", text)


def _parse(tokens, pos=0):
    tok = tokens[pos]
    if tok == "(":
        items = []
        pos += 1
        while tokens[pos] != ")":
            node, pos = _parse(tokens, pos)
            items.append(node)
        return items, pos + 1
    return tok, pos + 1


def parse(text: str):
    node, _ = _parse(_tokenize(text), 0)
    return node


def _mask(value: int, width: int) -> int:
    return value & ((1 << width) - 1)


def _signed(value: int, width: int) -> int:
    value = _mask(value, width)
    if value >> (width - 1):
        return value - (1 << width)
    return value


def _width_of(tok: str) -> int:
    m = _WIDTH_RE.match(tok)
    if not m:
        raise ValueError(f"expected width token like i32, got {tok!r}")
    return int(m.group(1))


def evaluate(node, env):
    """Return (value, width) for an OptiSynth-dialect node under `env`
    (name -> (value, width))."""
    if isinstance(node, str):
        m = _CONST_RE.match(node)
        if m:
            width = int(m.group(1))
            return _mask(int(m.group(2)), width), width
        if node in env:
            return env[node]
        raise ValueError(f"unbound variable {node!r}")

    head = node[0]
    if head == "intr":
        # (intr <name> <width> <args...>): a named intrinsic call. Model the
        # LLVM bit-count intrinsics exactly as PCE's Z3 builtins do.
        name = node[1]
        width = _width_of(node[2])
        av, _ = evaluate(node[3], env)
        x = _mask(av, width)
        if name == "llvm.ctpop":
            r = bin(x).count("1")
        elif name == "llvm.ctlz":
            r = width if x == 0 else width - x.bit_length()
        elif name == "llvm.cttz":
            r = width if x == 0 else (x & -x).bit_length() - 1
        else:
            raise ValueError(f"unsupported intrinsic {name!r}")
        return _mask(r, width), width
    if head in _ICMPS:
        # (icmp_* <width-decl> a b): result is i1; compare at the operand width.
        av, aw = evaluate(node[2], env)
        bv, bw = evaluate(node[3], env)
        w = aw
        if head == "icmp_eq":
            r = av == bv
        elif head == "icmp_ne":
            r = av != bv
        elif head == "icmp_ult":
            r = av < bv
        elif head == "icmp_ule":
            r = av <= bv
        elif head == "icmp_slt":
            r = _signed(av, w) < _signed(bv, w)
        else:  # icmp_sle
            r = _signed(av, w) <= _signed(bv, w)
        return (1 if r else 0), 1

    if head == "select":
        width = _width_of(node[1])
        cv, _ = evaluate(node[2], env)
        tv, _ = evaluate(node[3], env)
        fv, _ = evaluate(node[4], env)
        return _mask(tv if cv != 0 else fv, width), width

    if head in _BINOPS:
        width = _width_of(node[1])
        av, _ = evaluate(node[2], env)
        bv, _ = evaluate(node[3], env)
        return _binop(head, av, bv, width), width

    raise ValueError(f"unsupported form head {head!r}")


def _binop(op, a, b, width):
    if op == "add":
        return _mask(a + b, width)
    if op == "sub":
        return _mask(a - b, width)
    if op == "mul":
        return _mask(a * b, width)
    if op == "and":
        return _mask(a & b, width)
    if op == "or":
        return _mask(a | b, width)
    if op == "xor":
        return _mask(a ^ b, width)
    if op == "shl":
        return _mask(a << b, width) if b < width else 0
    if op == "lshr":
        return _mask(a, width) >> b if b < width else 0
    if op == "ashr":
        return _mask(_signed(a, width) >> min(b, width - 1), width)
    if op == "udiv":
        return (1 << width) - 1 if b == 0 else _mask(a // b, width)
    if op == "urem":
        return a if b == 0 else _mask(a % b, width)
    if op in ("sdiv", "srem"):
        sa, sb = _signed(a, width), _signed(b, width)
        if sb == 0:
            return (1 << width) - 1 if op == "sdiv" else a
        q = int(sa / sb) if op == "sdiv" else sa - int(sa / sb) * sb
        return _mask(q, width)
    raise ValueError(f"unsupported binop {op!r}")


def check_example(axis_file: Path, cases: int) -> tuple[int, int]:
    """Returns (checked_instructions, failures)."""
    workdir = Path(tempfile.mkdtemp(prefix="axis_opti_"))
    aha_path = workdir / "aha_instructions.json"
    golden_path = workdir / "golden_model.py"
    emit(axis_file, "emit-aha-json", aha_path)
    emit(axis_file, "emit-golden-python", golden_path)

    import json
    aha = json.loads(aha_path.read_text())
    golden = load_module(golden_path)

    random.seed(0x0D1)
    checked = failures = 0
    for insn in aha["instructions"]:
        if not insn.get("optisynth_compatible"):
            continue
        mnemonic = insn["mnemonic"]
        spec = golden.AXIS_SPECS.get(mnemonic)
        if spec is None:
            continue
        expr = parse(insn["formal_semantics"])
        params = spec["params"]  # [(name, width), ...] in golden order

        vectors = list(golden.sample_vectors(mnemonic, count=max(1, cases // 2)))
        for _ in range(cases - len(vectors)):
            vectors.append(tuple(random.getrandbits(width) for _, width in params))

        insn_failures = 0
        for values in vectors:
            env = {name: (value & ((1 << width) - 1), width)
                   for (name, width), value in zip(params, values)}
            got, _ = evaluate(expr, env)
            want = spec["eval"](*values)
            if got != want:
                if insn_failures == 0:
                    print(f"FAIL {mnemonic}: OptiSynth {insn['formal_semantics']}")
                    print(f"     {dict(zip((n for n, _ in params), values))}: "
                          f"got {got:#010x} want {want:#010x}")
                insn_failures += 1
        checked += 1
        failures += insn_failures
        if insn_failures == 0:
            print(f"  ok  {mnemonic}: {len(vectors)} vectors  {insn['formal_semantics']}")

    return checked, failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_files", type=Path, nargs="*")
    parser.add_argument("--cases", type=int, default=256,
                        help="vectors per instruction (spec samples + random)")
    args = parser.parse_args()

    if args.axis_files:
        targets = list(args.axis_files)
    else:
        targets = []
        for path in sorted((AXIS_ROOT / "examples").glob("*.axisl")):
            probe = subprocess.run(
                [*axis_prefix(), "emit-aha-json", str(path)],
                cwd=AXIS_ROOT, capture_output=True, text=True,
            )
            if probe.returncode == 0:
                targets.append(path)

    total_checked = total_failures = 0
    for axis_file in targets:
        print(f"== {axis_file.name} ==")
        checked, failures = check_example(axis_file, args.cases)
        total_checked += checked
        total_failures += failures

    print()
    print(f"{total_checked} optisynth_compatible instruction(s) checked, "
          f"{total_failures} failures")
    ok = total_failures == 0
    print("OptiSynth dialect == golden: PASS" if ok else "OptiSynth dialect == golden: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
