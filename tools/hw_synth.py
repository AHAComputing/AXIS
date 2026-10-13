#!/usr/bin/env python3
"""Synthesise a PyRTL block to standard cells, and say what it came to.

The reference AXIS's hardware cost model is calibrated against
(`tools/hw_calibrate.py`), kept apart so anything else that wants a measured
area or delay asks the same way and gets the same answer.

The flow is Yosys's `synth`, then ABC mapping to a liberty library, and the
numbers are ABC's own: the mapped area, and the delay of the longest path
under the library's timing tables (`stime`). No wire load, no placement -- a
synthesis estimate, which is what a cost model that ranks alternatives before
anything is placed can be held to.

Area is reported in NAND2 equivalents: the mapped area over the area of the
library's smallest two-input NAND. Delay is reported in picoseconds; what a
"gate delay" is worth in them is a constant the calibration fits.

The library is SkyWater's open 130 nm high-density cell library at the typical
corner, fetched once into `~/.cache/axis/sky130` (it is Apache-2.0 and not
vendored). `AXIS_LIBERTY` names another.

Usage as a library:

    from hw_synth import Synth
    synth = Synth.find()          # None without yosys or the library
    area, delay_ps = synth.measure(pyrtl, build)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

LIBERTY_NAME = "sky130_fd_sc_hd__tt_025C_1v80.lib"
LIBERTY_URL = ("https://raw.githubusercontent.com/efabless/skywater-pdk-libs-sky130_fd_sc_hd/"
               "master/timing/" + LIBERTY_NAME)
LIBERTY_SHA256 = "8e78e14442062dba34d414fca6490b2f6b96038d4510d1438ca44fee31487135"
CACHE = Path(os.environ.get("AXIS_CACHE", Path.home() / ".cache" / "axis"))

# The mapping script, stated here rather than left to a Yosys default so a
# Yosys upgrade cannot move the reference without this file changing.
#
# It is Yosys's liberty script WITHOUT `dc2`, and that is the decision in it.
# `dc2` restructures for area and takes Yosys's prefix adder apart: a 64-bit
# add comes out 10% smaller and three and a half times slower (7.7 ns against
# 2.2), with a delay that grows linearly in the width. An adder nobody would
# build is not what a cost model should be fitted to, so the structure Yosys
# chose is mapped as it stands (`&dch`, `&nf`) and then sized.
ABC_SCRIPT = """\
strash
&get -n
&dch -f
&nf
&put
buffer
upsize
dnsize
stime -p
"""


def liberty_path(fetch: bool = False) -> Path | None:
    """The reference library, or None. `fetch` downloads it when absent."""
    named = os.environ.get("AXIS_LIBERTY")
    if named:
        return Path(named) if Path(named).is_file() else None
    path = CACHE / "sky130" / LIBERTY_NAME
    if path.is_file():
        return path
    if not fetch:
        return None
    path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(LIBERTY_URL, timeout=120) as response:
        data = response.read()
    if hashlib.sha256(data).hexdigest() != LIBERTY_SHA256:
        raise RuntimeError(f"{LIBERTY_URL} is not the library this was calibrated against")
    path.write_bytes(data)
    return path


def nand2_area(liberty: Path) -> float:
    """The area of the library's smallest two-input NAND."""
    areas = []
    text = liberty.read_text()
    for match in re.finditer(r'cell\s*\(\s*"?([\w.]*nand2[\w.]*?)"?\s*\)\s*\{', text, re.I):
        area = re.search(r"\barea\s*:\s*([\d.eE+-]+)", text[match.end():match.end() + 4000])
        if area:
            areas.append(float(area.group(1)))
    if not areas:
        raise RuntimeError(f"{liberty} has no two-input NAND to measure area in")
    return min(areas)


def block_to_verilog(pyrtl, block) -> str:
    """A PyRTL block as Verilog, one declared wire and one assignment per net.

    Not `pyrtl.output_to_verilog`: PyRTL 0.12 folds single-use nets into their
    reader's expression, and Verilog sizes an operand of a concatenation by
    itself -- so a one-bit `a + b` whose sum PyRTL made two bits wide comes
    out one bit wide again, and a population count synthesises as a parity
    tree a third of its size. Here every net keeps the width PyRTL gave it,
    because every net is a wire declared at that width.
    """
    names: dict = {}

    def name(wire) -> str:
        if isinstance(wire, pyrtl.Const):
            return f"{len(wire)}'d{wire.val}"
        if wire not in names:
            names[wire] = f"w{len(names)}"
        return names[wire]

    def declared(wire) -> str:
        return f"[{len(wire) - 1}:0] {name(wire)}"

    ports, wires, body, registers = ["input clk"], [], [], []
    for wire in sorted(block.wirevector_subset(pyrtl.Input), key=lambda w: w.name):
        ports.append(f"input {declared(wire)}")
    for wire in sorted(block.wirevector_subset(pyrtl.Output), key=lambda w: w.name):
        ports.append(f"output {declared(wire)}")
    for net in sorted(block.logic, key=str):
        dest, args, op = net.dests[0], net.args, net.op
        if op in "m@":
            raise RuntimeError("memories are not synthesised here")
        if op == "r":
            wires.append(f"  reg {declared(dest)};")
            registers.append(f"    {name(dest)} <= {name(args[0])};")
            continue
        if not isinstance(dest, pyrtl.Output):
            wires.append(f"  wire {declared(dest)};")
        if op == "w":
            value = name(args[0])
        elif op == "~":
            value = f"~{name(args[0])}"
        elif op in "&|^+-*<>":
            value = f"{name(args[0])} {op} {name(args[1])}"
        elif op == "n":
            value = f"~({name(args[0])} & {name(args[1])})"
        elif op == "=":
            value = f"{name(args[0])} == {name(args[1])}"
        elif op == "x":
            value = f"{name(args[0])} ? {name(args[2])} : {name(args[1])}"
        elif op == "c":
            value = "{" + ", ".join(name(arg) for arg in args) + "}"
        elif op == "s":
            source = args[0]
            if isinstance(source, pyrtl.Const):
                bits = sum(((source.val >> bit) & 1) << index
                           for index, bit in enumerate(net.op_param))
                value = f"{len(dest)}'d{bits}"
            else:
                value = "{" + ", ".join(f"{name(source)}[{bit}]"
                                        for bit in reversed(net.op_param)) + "}"
        else:
            raise RuntimeError(f"no Verilog for PyRTL's `{op}`")
        body.append(f"  assign {name(dest)} = {value};")
    text = ["module toplevel(" + ", ".join(ports) + ");", *wires, *body]
    if registers:
        text += ["  always @(posedge clk) begin", *registers, "  end"]
    return "\n".join(text + ["endmodule", ""])


@dataclass
class Synth:
    yosys: str
    liberty: Path
    nand2: float
    cache_dir: Path | None = None

    @classmethod
    def find(cls, fetch: bool = False, cache: bool = True) -> "Synth | None":
        yosys = shutil.which("yosys")
        if not yosys:
            return None
        liberty = liberty_path(fetch)
        if liberty is None:
            return None
        cache_dir = CACHE / "hw_synth" if cache else None
        return cls(yosys, liberty, nand2_area(liberty), cache_dir)

    def describe(self) -> str:
        version = subprocess.run([self.yosys, "-V"], capture_output=True, text=True).stdout
        return f"{' '.join(version.split()[:2])}, {self.liberty.name}"

    def verilog(self, pyrtl, build) -> str:
        """`build()` wires a block; this is that block as Verilog."""
        with pyrtl.temp_working_block():
            build()
            return block_to_verilog(pyrtl, pyrtl.working_block())

    def measure(self, pyrtl, build) -> tuple[float, float]:
        """(area in NAND2 equivalents, longest path in ps) of what `build` wires."""
        return self.measure_verilog(self.verilog(pyrtl, build))

    def measure_verilog(self, verilog: str, top: str = "toplevel") -> tuple[float, float]:
        key = hashlib.sha256(
            "\0".join([verilog, top, ABC_SCRIPT, self.describe(),
                       str(self.liberty.stat().st_size)]).encode()).hexdigest()
        cached = self.cache_dir / f"{key}.json" if self.cache_dir else None
        if cached and cached.is_file():
            area, delay = json.loads(cached.read_text())
            return area, delay
        with tempfile.TemporaryDirectory(prefix="axis_synth_") as tmp:
            source = Path(tmp) / "design.v"
            source.write_text(verilog)
            script = Path(tmp) / "map.abc"
            script.write_text(ABC_SCRIPT)
            commands = "; ".join([
                f"read_verilog {source}",
                f"synth -flatten -top {top}",
                f"dfflibmap -liberty {self.liberty}",
                f"abc -liberty {self.liberty} -script {script}",
                f"stat -liberty {self.liberty}",
            ])
            run = subprocess.run([self.yosys, "-q", "-l", str(Path(tmp) / "log"), "-p", commands],
                                 capture_output=True, text=True)
            log = (Path(tmp) / "log").read_text() if (Path(tmp) / "log").exists() else ""
            if run.returncode != 0:
                raise RuntimeError(f"yosys failed:\n{run.stderr[-2000:]}\n{log[-2000:]}")
        # Combinational logic is all one ABC run; registers split it into
        # several, and the block's longest path is the longest of them.
        delays = [float(d) for d in re.findall(r"Delay\s*=\s*([\d.]+)\s*ps", log)]
        chip = re.findall(r"Chip area for (?:top )?module.*?:\s*([\d.]+)", log)
        if chip:
            result = (float(chip[-1]) / self.nand2, max(delays, default=0.0))
        elif re.search(r"Number of cells:\s+0\b", log):
            result = (0.0, 0.0)  # wires only: an immediate placed, a field moved
        else:
            raise RuntimeError(f"yosys reported no area:\n{log[-2000:]}")
        if cached:
            cached.parent.mkdir(parents=True, exist_ok=True)
            cached.write_text(json.dumps(result))
        return result
