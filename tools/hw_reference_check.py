#!/usr/bin/env python3
"""A reference body means what the built-in operator it describes means. Gate.

Some operators are implemented natively by every software backend -- AArch64's
shifted and extended register operands, its flag words, its bitmask
immediates -- and mean what the golden model's evaluator says. A backend with
no native implementation needs that meaning stated in the description's own
operators. A description states it as `(deffun <operator>_ref_i<W> ...)`, and
the netlist lowering inlines that body wherever the operator is used at width
W.

So the body is now load-bearing, and nothing else compares it with the
operator: every software backend computes the built-in. This does, in the
golden model, where both exist -- the operator evaluated directly, and the
reference called.

⚠️ The vectors are not uniform. A flag word turns on a carry out of bit 63 and
a bitmask immediate on six bits of one argument; uniform 64-bit values reach
neither often. Each argument is drawn from small values, boundary values and
random ones.

Usage: tools/hw_reference_check.py <input.axisl> [--cases N] [--expect N]
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import DECLINED, FAILED, PASSED, axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent
REFERENCE = re.compile(r"^(?P<operator>.+)_ref_i(?P<width>\d+)$")


def draw(rng: random.Random, width: int) -> int:
    top = (1 << width) - 1
    kind = rng.randrange(5)
    if kind == 0:
        return rng.randrange(min(top, 127) + 1)
    if kind == 1:
        return rng.choice((0, 1, top, top - 1, top >> 1, (top >> 1) + 1))
    if kind == 2:
        # Random above, every low pattern below: where a field of an
        # argument selects a case.
        return (rng.getrandbits(width) & ~0x7f | rng.randrange(128)) & top
    return rng.getrandbits(width)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--cases", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=20261006)
    parser.add_argument("--expect", type=int, default=None,
                        help="exactly this many reference bodies are compared")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "golden_model.py"
        subprocess.run([*axis_prefix(), "emit-golden-python", str(args.axis_file), "-o",
                        str(path)], check=True, capture_output=True, cwd=AXIS_ROOT)
        spec = importlib.util.spec_from_file_location("golden_model", path)
        golden = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(golden)

    rng = random.Random(args.seed)
    compared = failures = 0
    for name, (params, result, text) in sorted(getattr(golden, "_FUNCTIONS", {}).items()):
        named = REFERENCE.match(name)
        if named is None or text is None:
            continue
        operator, width = named["operator"], int(named["width"])
        builtin = [operator, f"i{width}", *[param for param, _ in params]]
        called = ["call", name, f"i{result}", *[[f"i{size}", param] for param, size in params]]
        mask = (1 << result) - 1
        compared += 1
        for _ in range(args.cases):
            env = {param: draw(rng, size) for param, size in params}
            try:
                want = golden._eval(builtin, dict(env), width) & mask
            except NotImplementedError:
                print(f"  FAIL {name}: the golden model has no operator `{operator}` to describe")
                failures += 1
                break
            got = golden._eval(called, dict(env), result) & mask
            if got != want:
                shown = ", ".join(f"{param}={value:#x}" for param, value in env.items())
                print(f"  FAIL {name}({shown}): the reference says {got:#x}, "
                      f"`{operator}` is {want:#x}")
                failures += 1
                break
    if not compared:
        print("this description states no reference body: SKIP")
        return DECLINED
    if args.expect is not None and compared != args.expect:
        print(f"  FAIL {compared} reference bodies, and this corpus is expected to have "
              f"{args.expect}")
        failures += 1
    print(f"{compared} reference bod(ies), {args.cases} vectors each, {failures} disagreeing")
    print("reference bodies == the operators they describe:", "FAIL" if failures else "PASS")
    return FAILED if failures else PASSED


if __name__ == "__main__":
    raise SystemExit(main())
