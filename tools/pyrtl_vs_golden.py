#!/usr/bin/env python3
"""The hardware AXIS emits computes what the golden model says. Gate.

Every way of EXECUTING a description is held to the golden model: the C, Rust
and Python executors, the LLVM IR, the SMT definitions, the copy-and-patch
JIT, and the symbolic machine. `emit-pyrtl` emitted two hundred and
fifty-eight functions and was held to nothing.

⚠️ That asymmetry is the one that matters for co-design. A stack can say "six
ways of running this agree" and still not say "the hardware does what the
software says", and every number derived from the generated RTL rests on the
second claim rather than the first.

So: build each instruction's netlist out of PyRTL `Input`s, simulate it on the
golden model's own deterministic vectors, and require the wire to carry the
number the model computes. Same vectors, same comparison, same discipline as
`c_vs_golden.py` -- the difference is that one end is a circuit.

Usage: tools/pyrtl_vs_golden.py <input.axisl> [--cases N]

Requires: cargo (from the AXIS repo root) and `pyrtl`. Exits with a SKIP notice
if PyRTL is not installed, because a gate that cannot build a circuit has not
found one that disagrees.
"""

from __future__ import annotations

import argparse
import importlib.util
import random
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(output)],
                   check=True, capture_output=True, cwd=AXIS_ROOT)


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def emitted_ident(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name).lower()


def check(axis_file: Path, work: Path, cases: int, rng: random.Random):
    import pyrtl

    emit(axis_file, "emit-golden-python", work / "golden_model.py")
    emit(axis_file, "emit-pyrtl", work / "axis_pyrtl.py")
    golden = load(work / "golden_model.py", "golden_model")
    rtl = load(work / "axis_pyrtl.py", "axis_pyrtl")

    built = compared = failures = 0
    missing: list[str] = []
    refused: dict[str, int] = {}
    for name, entry in golden.AXIS_SPECS.items():
        builder = getattr(rtl, f"build_{emitted_ident(name)}", None)
        if builder is None:
            missing.append(name)
            continue
        params = entry["params"]
        result_width = entry.get("result_width", 32)
        vectors = list(golden.sample_vectors(name, count=max(2, cases // 2)))
        while len(vectors) < cases:
            vectors.append(tuple(rng.getrandbits(width) for _, width in params))

        # ⚠️ One netlist per instruction, in its own working block. PyRTL keeps
        # a global block, and building every instruction into one would make
        # each new circuit a little slower than the last and the last one
        # enormous -- and a name collision between two instructions' inputs
        # would be a wire silently shared.
        with pyrtl.temp_working_block():
            try:
                inputs = [pyrtl.Input(bitwidth=max(width, 1), name=f"in{i}")
                          for i, (_, width) in enumerate(params)]
                answer = builder(*inputs)
                out = pyrtl.Output(bitwidth=max(result_width, 1), name="answer")
                out <<= answer
            except Exception as error:  # noqa: BLE001
                # ⚠️ Named, not counted. "This description has an operator no
                # circuit was written for" is a different fact from "the
                # circuit is wrong", and a gate that folded them together
                # would report a stack that builds less hardware every release
                # as one that still passes.
                reason = f"{type(error).__name__}: {error}"[:70]
                refused[reason] = refused.get(reason, 0) + 1
                continue
            built += 1
            sim = pyrtl.Simulation()
            for vector in vectors:
                sim.step({f"in{i}": value & ((1 << max(width, 1)) - 1)
                          for i, (value, (_, width)) in enumerate(zip(vector, params))})
                got = sim.inspect("answer")
                # The golden model's own evaluator, which is what every other
                # backend here is compared against.
                want = golden.evaluate(name, *vector)
                want &= (1 << max(result_width, 1)) - 1
                compared += 1
                if got != want:
                    print(f"  FAIL {name}{vector}: the circuit says {got:#x}, "
                          f"the golden model {want:#x}")
                    failures += 1
                    break
    return built, compared, failures, missing, refused


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=16)
    parser.add_argument("--seed", type=int, default=20260919)
    args = parser.parse_args()
    try:
        import pyrtl  # noqa: F401
    except Exception:  # noqa: BLE001
        print("pyrtl is not installed: SKIP")
        return DECLINED
    rng = random.Random(args.seed)
    with tempfile.TemporaryDirectory() as tmp:
        built, compared, failures, missing, refused = check(
            args.axis_file, Path(tmp), args.cases, rng)
    if missing:
        print(f"  {len(missing)} instruction(s) with no circuit emitted: "
              f"{', '.join(missing[:4])}")
    for reason, count in sorted(refused.items(), key=lambda kv: -kv[1])[:4]:
        print(f"  {count} circuit(s) would not build -- {reason}")
    # ⚠️ A run that built nothing proves nothing, and says so rather than
    # passing on an empty comparison.
    if not compared:
        print("no circuit was compared: SKIP")
        return DECLINED
    print(f"{built} circuit(s) built, {compared} vector(s) simulated, "
          f"{failures} disagreeing")
    print("PyRTL == golden model:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
