#!/usr/bin/env python3
"""The stencil table a JIT pack is built from: what a compiler made of AXIS's IR.

⚠️ This is the one part of a pack AXIS does not emit. Every other library is
derived from the description, so `emit-pack-*-c` can write all of it. A
stencil's *bytes* are not derived from the description -- they are what a
compiler made of it, for one instruction set, on one host. So AXIS emits the
patcher (`emit-pack-jit-c`) and the stencil IR (`emit-stencil-ll`), and this
compiles the IR and reads the result back out: each stencil's machine code, the
`adrp`/`add` sites inside it, and which hole each site reaches.

The header it writes fills in the table shape `emit-pack-jit-c` declares. If
the two ever disagree the library does not compile, which is the point of
splitting them this way rather than having either side describe the other.

Effect stencils go in too, now that the contract carries a machine rather than
a register file: a hole is classified by what it binds -- the register file,
memory, the scratch an effect reports through, the state, the pc, or an operand
-- and the library fills the machine's own from one `axis_jit_machine` while
the caller supplies the operands.

Usage: tools/jit_table.py <corpus.axisl> -o <axis_jit_table.h>
"""
from __future__ import annotations

import argparse
import json
import platform
import re
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402
from jit_stencil import MachO  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: Every stencil ends in this, and a block keeps only the last one. A stencil
#: that does not is not one this table can carry: the patcher would fall out of
#: it into whatever the compiler left behind.
RET = 0xD65F03C0

#: The two relocation kinds that name a symbol's address in code, in the order
#: `emit-pack-jit-c` numbers them.
#:
#: ⚠️ Named `RELOC_KINDS`, not `KINDS`. A second `KINDS` -- for what a HOLE
#: binds -- shadowed this one, `kind not in KINDS` went true for every
#: relocation, and the table came out with 157 stencils and no patch sites at
#: all. It built, it linked, and every hole would have read whatever the
#: compiler left there.
RELOC_KINDS = {"PAGE21": 0, "PAGEOFF12": 1}


class Unsupported(Exception):
    """This host is not one whose stencils this table format can describe."""


def host_triple() -> str:
    machine = platform.machine()
    if machine not in ("arm64", "aarch64") or platform.system() != "Darwin":
        raise Unsupported(f"{platform.system()}/{machine}: the patcher AXIS emits "
                          "is AArch64, and this reader is Mach-O")
    return f"{machine}-apple-{platform.system().lower()}"


def emit(axis_file: Path, command: str, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   check=True, cwd=AXIS_ROOT)


def machine_words(text: str) -> dict[str, int]:
    """How wide a stencil's scratch and state slots are, from its own loads.

    ⚠️ Read from the artifact, not assumed to be 64. An effect handler reports
    through slots of its machine's word, so RV32I's are 32 bits wide -- and a
    caller that allocated 64-bit slots for them would have the handler write
    every other one.
    """
    found = re.findall(
        r"%out = load i(\d+)\*, i\d+\*\* bitcast \(i8\* @AXIS_HOLE_(\w+)_out", text)
    return {ident: int(bits) for bits, ident in found}


def holes_from_ir(text: str) -> tuple[dict[str, list[str]], set[str]]:
    """Each stencil's holes, in the order it first references them.

    The order is the patcher's contract -- slot 0 is the register file and the
    rest are the operands -- so it is read from the artifact rather than
    reconstructed from the description a second time.
    """
    holes: dict[str, list[str]] = {}
    effects: set[str] = set()
    # ⚠️ The handler's holes count as the stencil's. An effect stencil CALLS
    # `axis_eff_<ident>`, which is `alwaysinline`, so by the time there is an
    # object file the handler's references are relocations inside the
    # stencil's bytes -- but they are not in the stencil's IR body, which is
    # what this reads. A hole reached this way and not collected is a
    # relocation the patcher does not recognise, and the stencil is declined
    # for referring to its own machine: that is how the memory window arrived,
    # taking every load and store in the table with it.
    handler_holes: dict[str, list[str]] = {}
    for match in re.finditer(r"define(?: internal)? void @axis_eff_(\w+)\([^)]*\)[^{]*\{\n(.*?)\n\}",
                             text, re.S):
        ident, body = match.group(1), match.group(2)
        found: list[str] = []
        for hole in re.findall(r"@(AXIS_HOLE_\w+)", body):
            if hole not in found:
                found.append(hole)
        handler_holes[ident] = found
    for match in re.finditer(r"define void @axis_stencil_(\w+)\(\) \{\n(.*?)\n\}",
                             text, re.S):
        ident, body = match.group(1), match.group(2)
        seen: list[str] = []
        for hole in re.findall(r"@(AXIS_HOLE_\w+)", body):
            if hole not in seen:
                seen.append(hole)
        for hole in handler_holes.get(ident, []):
            if hole not in seen:
                seen.append(hole)
        holes[ident] = seen
        if f"call void @axis_eff_{ident}(" in body:
            effects.add(ident)
    return holes, effects


def compile_ir(source: Path, obj: Path) -> bytes:
    subprocess.run(["clang", "-x", "ir", "-O2", "-c", "-o", str(obj), str(source)],
                   check=True, capture_output=True)
    return obj.read_bytes()


def stencil_code(macho: MachO, text: dict, obj: bytes) -> dict[str, tuple[int, int]]:
    """Each stencil's (file offset, size), sized by the distance to the next.

    Mach-O symbol tables carry no size, and the stencils are all that is left in
    `__text` once the handlers inline away, so the next symbol's address is the
    end of this one -- plus whatever padding the assembler put between them,
    which `trim` takes back off.
    """
    entries = sorted(((name.lstrip("_"), value) for name, sect, value in macho.symbols
                      if sect == 1 and name.startswith("_axis_stencil_")),
                     key=lambda item: item[1])
    out = {}
    for index, (name, addr) in enumerate(entries):
        end = entries[index + 1][1] if index + 1 < len(entries) else (
            text["addr"] + text["size"])
        out[name[len("axis_stencil_"):]] = (
            text["offset"] + (addr - text["addr"]), end - addr, addr)
    return out


def trim(code: bytes) -> bytes | None:
    """The stencil without the padding after its `ret`, or None if it has none.

    The patcher drops the last four bytes of every stencil but the block's last,
    so those four bytes must BE the `ret`. Padding left after it would be
    executed instead.
    """
    for end in range(len(code), 3, -4):
        if struct.unpack_from("<I", code, end - 4)[0] == RET:
            return code[:end]
        if any(code[end - 4:end]):
            return None                  # something real after the last `ret`
    return None


#: What a hole binds, in the order `emit-pack-jit-c` numbers the kinds.
HOLE_KINDS = {"regs": 0, "mem": 1, "out": 2, "state": 3, "pc": 4, "mask": 5}
VALUE = 6


def hole_kinds(holes: list[str], operands: list[dict]) -> list[int] | None:
    """Which of a stencil's holes the LIBRARY fills, and which the caller does.

    ⚠️ A pure stencil's machine part is the register file and nothing else; an
    effect stencil also takes the memory it reads, the scratch it reports its
    write through, the state it consults and the pc it was at. Those belong to
    the machine, are the same for every instruction in a block, and a contract
    that made a caller pass them per operand would be describing the stencil's
    internals rather than the instruction's.
    """
    kinds = []
    for hole in holes:
        tail = hole.rsplit("_", 1)[-1]
        kinds.append(HOLE_KINDS.get(tail, VALUE))
    return kinds


def hole_names(holes: list[str], operands: list[dict],
               writes: list[str] | None = None) -> list[str] | None:
    """What each hole binds, by the operand's own name.

    A pack that published only a hole COUNT would be asking its consumer to
    know the order AXIS emits stencils in -- inputs in description order, then
    the destination. Naming them is what makes the table bindable by someone
    who has never read the emitter. A hole whose name cannot be recovered is
    not published at all; a wrong name is worse than no stencil.
    """
    inputs = [op for op in operands if op["role"] not in ("out", "enc")]
    dest = next((op for op in operands if op["role"] in ("out", "inout")), None)
    names = []
    for hole in holes:
        tail = hole.rsplit("_", 1)[-1]
        if tail in HOLE_KINDS:
            names.append(tail)
        elif tail == "dest":
            first = (writes or [None])[0] if writes else None
            if first is None and dest is None:
                return None
            names.append(first or dest["name"])
        elif tail.startswith("dest") and tail[4:].isdigit():
            # The k-th register this instruction writes. A stencil commits all
            # of them now, and each needs its own hole and its own name.
            which = int(tail[4:])
            if not writes or which >= len(writes):
                return None
            names.append(writes[which])
        elif tail.isdigit() and int(tail) < len(inputs):
            names.append(inputs[int(tail)]["name"])
        elif tail.startswith("op") and tail[2:].isdigit() and int(tail[2:]) < len(inputs):
            # An effect stencil spells its operands `op0`, `op1`; a pure one
            # spells them `0`, `1`. Same position, different prefix.
            names.append(inputs[int(tail[2:])]["name"])
        else:
            return None
    return names if len(names) == len(holes) else None


def scratch_slots(workdir: Path) -> int:
    """How many slots an effect reports through: value, wrote, next pc, trap.

    Read from the emitted lifter, which is the one place that says.
    """
    text = (workdir / "axis_lift.py").read_text()
    found = re.search(r"^EFFECT_OUT_SLOTS = (\d+)", text, re.M)
    return int(found.group(1)) if found else 0


def build_table(axis_file: Path, workdir: Path) -> dict:
    triple = host_triple()
    emit(axis_file, "emit-stencil-ll", workdir / "stencils.ll")
    emit(axis_file, "emit-lift-json", workdir / "lift.json")
    emit(axis_file, "emit-lift-python", workdir / "axis_lift.py")
    ir = (workdir / "stencils.ll").read_text()
    holes, effects = holes_from_ir(ir)
    words = machine_words(ir)
    mnemonics, operands, writes = {}, {}, {}
    for entry in json.loads((workdir / "lift.json").read_text())["instructions"]:
        ident = re.sub(r"[^0-9A-Za-z]", "_", entry["mnemonic"]).lower()
        mnemonics[ident] = entry["mnemonic"]
        operands[ident] = entry["operands"]
        # ⚠️ In EFFECT ORDER, which is what the scratch's write slots are in.
        # An instruction's output operands in declaration order are usually the
        # same list and are not the same fact: the handler fills slot `k` from
        # the `k`-th register-writing effect, and the lift table publishes each
        # with the operand it lands in so a consumer does not have to guess.
        writes[ident] = [effect["dest"] for effect in (entry.get("effects") or [])
                         if effect["kind"] == "set" and effect.get("dest")]

    obj = compile_ir(workdir / "stencils.ll", workdir / "stencils.o")
    macho = MachO(obj)
    text = macho.text()
    by_symbol: dict[str, list[tuple[int, str]]] = {}
    every: list[tuple[int, str, str]] = []
    for offset, kind, name in macho.relocations(text):
        by_symbol.setdefault(name.lstrip("_"), []).append((offset, kind))
        every.append((offset, kind, name.lstrip("_")))
    code = stencil_code(macho, text, obj)

    stencils, declined = [], []
    blob = bytearray()
    relocs: list[tuple[int, int, int]] = []
    for ident in sorted(code):
        if ident not in mnemonics:
            declined.append((ident, "no instruction of that name in the corpus"))
            continue
        start, size, addr = code[ident]
        body = trim(obj[start:start + size])
        if body is None:
            declined.append((ident, "does not end in `ret`"))
            continue
        # ⚠️ A relocation this patcher does not apply is a stencil that must
        # not ship. AArch64's atomics leave a `bl` to a compiler-rt helper --
        # a BRANCH26 relocation, relative to where the code was ASSEMBLED --
        # and copying those bytes somewhere else and running them is an
        # illegal instruction, which is how this was found. Skipping the
        # relocation silently, as this did, published the stencil anyway.
        own = set(holes.get(ident, []))
        foreign = [
            (kind, name) for offset, kind, name in every
            if 0 <= offset - (addr - text["addr"]) < size
            and (kind not in RELOC_KINDS or name not in own)
        ]
        if foreign:
            kind, name = foreign[0]
            declined.append((ident, f"a {kind} relocation to `{name}` "
                                    f"this patcher does not apply"))
            continue
        sites = []
        for hole_index, hole in enumerate(holes.get(ident, [])):
            for offset, kind in by_symbol.get(hole, []):
                site = offset - (addr - text["addr"])
                if kind not in RELOC_KINDS or not 0 <= site < len(body):
                    continue
                sites.append((site, hole_index, RELOC_KINDS[kind]))
        sites.sort()
        names = hole_names(holes.get(ident, []), operands[ident],
                           writes.get(ident))
        if names is None:
            declined.append((ident, "its holes do not line up with its operands"))
            continue
        kinds = hole_kinds(holes.get(ident, []), operands[ident])
        live = {kind for _site, hole_index, _r in sites
                for kind in (kinds[hole_index],)}
        stencils.append({
            "ident": ident, "mnemonic": mnemonics[ident],
            "offset": len(blob), "size": len(body),
            "holes": len(holes.get(ident, [])), "names": names, "kinds": kinds,
            "values": sum(1 for kind in kinds if kind == VALUE),
            "effectful": int(ident in effects),
            "word_bits": words.get(ident, 0), "live": sorted(live),
            # ⚠️ Whether the compiled stencil actually READS architectural
            # state, which is not the same as having a hole for it: the hole is
            # in the IR and the compiler drops it when nothing uses it. A
            # consumer that refused every stencil with a state hole refused
            # every effect stencil there is.
            "reads_state": int(HOLE_KINDS["state"] in live),
            "reloc": len(relocs), "reloc_count": len(sites),
        })
        blob += body
        relocs.extend(sites)
    return {"host": triple, "code": bytes(blob), "relocs": relocs,
            "stencils": stencils, "declined": declined,
            "scratch_slots": scratch_slots(workdir)}


def render(table: dict, name: str) -> str:
    out = [f"/* Generated by tools/jit_table.py from {name}'s stencils, compiled",
           f"   for {table['host']}. AXIS emits the patcher and the IR; this is what",
           "   a compiler made of the IR, which no description can say.",
           "   schema: axis.jit-table.v1 */",
           f"#define AXIS_JIT_HOST \"{table['host']}\"",
           f"#define AXIS_JIT_STENCIL_COUNT {len(table['stencils'])}",
           f"#define AXIS_JIT_SCRATCH_SLOTS {table['scratch_slots']}", ""]
    out.append("static const uint8_t AXIS_JIT_CODE[] = {")
    for at in range(0, len(table["code"]), 16):
        row = ", ".join(f"0x{b:02X}" for b in table["code"][at:at + 16])
        out.append(f"  {row},")
    out.append("};")
    out.append("")
    out.append("static const axis_jit_reloc AXIS_JIT_RELOCS[] = {")
    for site, hole, kind in table["relocs"] or [(0, 0, 0)]:
        out.append(f"  {{ {site}, {hole}, {kind} }},")
    out.append("};")
    out.append("")
    for s in table["stencils"]:
        row = ", ".join(f"\"{name}\"" for name in s["names"])
        out.append(f"static const char *const AXIS_JIT_NAMES_{s['ident']}[] = "
                   f"{{ {row} }};")
        kinds = ", ".join(str(kind) for kind in s["kinds"])
        out.append(f"static const uint8_t AXIS_JIT_KINDS_{s['ident']}[] = "
                   f"{{ {kinds} }};")
    out.append("")
    out.append("static const axis_jit_stencil AXIS_JIT_STENCILS[] = {")
    for s in table["stencils"]:
        out.append(f"  {{ \"{s['mnemonic']}\", {s['offset']}, {s['size']}, "
                   f"{s['holes']}, {s['values']}, {s['effectful']}, "
                   f"{s['word_bits']}, {s['reads_state']}, "
                   f"AXIS_JIT_NAMES_{s['ident']}, AXIS_JIT_KINDS_{s['ident']}, "
                   f"{s['reloc']}, {s['reloc_count']} }},")
    out.append("};")
    # ⚠️ What the table actually PATCHES, by machine part. A hole the compiler
    # optimised away has no relocation and is filled into a slot nothing reads
    # -- which is correct, and is also why pointing `state` somewhere wrong
    # changes no answer here: not one stencil in these corpora reads it.
    counts = {name: 0 for name in ("regs", "mem", "out", "state", "pc", "mask")}
    order = ["regs", "mem", "out", "state", "pc", "mask"]
    for s in table["stencils"]:
        for kind in s["live"]:
            if kind < len(order):
                counts[order[kind]] += 1
    out.append("")
    out.append("/* Stencils with a live relocation for each machine part:")
    out.append("     " + ", ".join(f"{name} {counts[name]}" for name in order))
    out.append(" */")
    if table["declined"]:
        out.append("")
        out.append("/* Not in this table, and why:")
        for ident, reason in table["declined"][:40]:
            out.append(f"     {ident}: {reason}")
        if len(table["declined"]) > 40:
            out.append(f"     ... and {len(table['declined']) - 40} more")
        out.append(" */")
    return "\n".join(out) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("-o", "--out", type=Path, required=True)
    parser.add_argument("--workdir", type=Path)
    args = parser.parse_args()
    workdir = args.workdir or args.out.parent / "jit-work"
    workdir.mkdir(parents=True, exist_ok=True)
    try:
        table = build_table(args.axis_file, workdir)
    except Unsupported as reason:
        print(f"no JIT table: {reason}")
        return 2
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render(table, args.axis_file.stem))
    live = {}
    for stencil in table["stencils"]:
        for kind in stencil["live"]:
            live[kind] = live.get(kind, 0) + 1
    names = ["regs", "mem", "out", "state", "pc", "mask", "value"]
    print(f"{len(table['stencils'])} stencils, {len(table['code'])} bytes of code, "
          f"{len(table['relocs'])} relocations, {len(table['declined'])} declined")
    print("  patched by part: " + ", ".join(
        f"{names[kind]} {count}" for kind, count in sorted(live.items())))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
