#!/usr/bin/env python3
"""Build one architecture as a linkable pack: headers, a static lib, a shared lib.

An arch pack is what a consumer actually links. AXIS emits C, and until now
turning that into something an external project could depend on was left to the
reader -- with the added trap that the exported ABI used fixed symbol names, so
two of them could not coexist. `emit-pack-c` fixes the names; this builds the
artifact.

The layout, per architecture:

    <out>/<name>/
      include/axis_pack.h      the contract, identical for every pack
      include/axis_decode.h    the generated tables this pack was built from
      include/axis_encode.h
      lib/libaxis_decode_<name>.{a,so}     a disassembler
      lib/libaxis_asm_<name>.{a,so}        an assembler
      lib/libaxis_disasm_<name>.{a,so}     a disassembler: a word to its text
      lib/libaxis_lift_<name>.{a,so}       a lifter
      lib/libaxis_exec_<name>.{a,so}       a machine
      lib/libaxis_jit_<name>.{a,so}        a copy-and-patch JIT, where one is possible
      lib/libaxis_sim_<name>.{a,so}        a machine that runs a program
      lib/libaxis_z3_<name>.{a,so}         the proven terms, bound to a solver
      pack.json                            what is here, and which symbol each answers to

⚠️ Separate libraries, not one with capability flags. The flags were the first
version and they lied immediately: `AXIS_PACK_HAS_ASSEMBLE` shipped set on every
pack while the table carried no assemble pointer. A library either exists on
disk or does not, which a host can check without trusting what a pack says about
itself -- and a consumer that only reads code links the decoder rather than
dragging an assembler behind it.

⚠️ `pack.json` names the entry symbol, and that is not decoration. A host that
`dlopen`s a pack it has never heard of cannot guess `axis_pack_<name>` without
first knowing the name; reading it from the manifest beside the library is how
an external project loads an architecture AXIS was never told about.

Usage: tools/build_pack.py <corpus.axisl> [--out DIR]
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402
import jit_table  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: What a pack is built from. The ABI header is corpus-independent; the rest
#: are this description's tables.
SOURCES = (
    ("emit-pack-abi-c", "include/axis_pack.h"),
    ("emit-decode-c", "include/axis_decode.h"),
    ("emit-encode-c", "include/axis_encode.h"),
    ("emit-lift-c", "include/axis_lift.h"),
    ("emit-semantics-c", "include/axis_semantics.h"),
    ("emit-exec-c", "include/axis_exec.h"),
    ("emit-sim-c", "include/axis_sim.h"),
)

#: One library per facet: the emitter that writes it, the source it writes, and
#: the entry symbol it exports.
LIBRARIES = (
    ("decode", "emit-pack-decode-c", "src/decode.c"),
    ("asm", "emit-pack-asm-c", "src/asm.c"),
    ("disasm", "emit-pack-disasm-c", "src/disasm.c"),
    ("lift", "emit-pack-lift-c", "src/lift.c"),
    ("exec", "emit-pack-exec-c", "src/exec.c"),
    ("sim", "emit-pack-sim-c", "src/sim.c"),
)

#: The sixth library is not like the other five. Everything above is derived
#: from the description, so AXIS emits it and any host can compile it. A
#: stencil's bytes are what a compiler made of the description for one
#: instruction set on one host, so this one is built only where those bytes run
#: -- and where it is not, the pack says so by name rather than by omission.
JIT = ("jit", "emit-pack-jit-c", "src/jit.c")

#: The SIMT engine (docs/simt_design.md): built for a description that has a
#: `(kind simt)` core declaring `(simt ...)`, or when a caller asks for it.
#: It links against the description's own lift and exec libraries, so it is
#: a static library only -- a shared one would carry their symbols unresolved.
SIMT = ("simt", "emit-pack-simt-c", "src/simt.c")
#: The eighth is host-conditional for a different reason than the JIT: it needs
#: a SOLVER to link against. Where there is none, the pack says so by name
#: rather than shipping a library whose every call would fail.
Z3 = ("z3", "emit-pack-z3-c", "src/z3.c")
#: ⚠️ Beside the solver library and on the same condition: it is a machine made
#: of the terms that library hands out, so without a solver there is nothing for
#: it to be made of.
SYM = ("sym", "emit-pack-sym-c", "src/sym.c")


def solver_paths():
    """Where this host keeps `z3.h` and `libz3`, or None."""
    for prefix in (os.environ.get("AXIS_Z3_PREFIX"), "/opt/homebrew/opt/z3",
                   "/usr/local/opt/z3", "/usr", "/usr/local"):
        if not prefix:
            continue
        root = Path(prefix)
        if (root / "include" / "z3.h").exists():
            for lib in ("lib", "lib64"):
                if list((root / lib).glob("libz3.*")):
                    return root / "include", root / lib
    return None


def emit(axis_file: Path, command: str, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([*axis_prefix(), command, str(axis_file), "-o", str(out)],
                   check=True, cwd=AXIS_ROOT)


def pack_ident(name: str) -> str:
    """The C identifier form, matching `pack_ident` in the emitter."""
    ident = "".join(ch if ch.isalnum() else "_" for ch in name).lower()
    return f"_{ident}" if ident[:1].isdigit() else ident


def build(axis_file: Path, out_root: Path, only: set[str] | None = None) -> dict:
    """Build a pack. `only` names the libraries a caller needs.

    ⚠️ Not an optimisation. Every library is built by default and one that
    cannot be built stops the whole pack -- `sve`'s simulator reads 272
    registers where the contract carries 16, which is a `_Static_assert` on
    purpose. A gate that wants the LIFTER out of that description should not be
    told there is no pack at all, so it asks for what it uses.
    """
    name = json.loads(subprocess.run(
        [*axis_prefix(), "emit-json", str(axis_file)],
        check=True, capture_output=True, text=True, cwd=AXIS_ROOT).stdout)["name"]
    ident = pack_ident(name)
    root = out_root / name
    for command, relative in SOURCES:
        emit(axis_file, command, root / relative)

    include, lib = root / "include", root / "lib"
    lib.mkdir(parents=True, exist_ok=True)
    suffix = "dylib" if platform.system() == "Darwin" else "so"
    libraries = {}
    for facet, command, relative in LIBRARIES:
        if only is not None and facet not in only:
            continue
        emit(axis_file, command, root / relative)
        obj = root / "src" / f"{facet}.o"
        # ⚠️ `-DAXIS_IMPL_STUBS_INTERNAL`, not `-DAXIS_IMPL_STUBS`. A
        # description that names implementation routines leaves them for the
        # embedder, and a pack built without any would not link -- but stubs
        # with EXTERNAL linkage make the library collide with every other pack
        # that names routines, and with a host that supplies its own. Private
        # placeholders keep a pack self-contained: it reports the same
        # `unimplemented` trap and overrides nothing.
        subprocess.run(["cc", "-std=c11", "-O2", "-fPIC", "-DAXIS_IMPL_STUBS_INTERNAL",
                        "-I", str(include), "-c", "-o", str(obj),
                        str(root / relative)], check=True)
        static = lib / f"libaxis_{facet}_{ident}.a"
        subprocess.run(["ar", "rcs", str(static), str(obj)], check=True)
        shared = lib / f"libaxis_{facet}_{ident}.{suffix}"
        subprocess.run(["cc", "-shared", "-o", str(shared), str(obj)], check=True)
        libraries[facet] = {
            "entry": f"axis_{facet}_pack_{ident}",
            "static": static.name,
            "shared": shared.name,
        }

    declined = {}
    facet, command, relative = SIMT
    facts = json.loads(subprocess.run(
        [*axis_prefix(), "emit-json", str(axis_file)],
        check=True, capture_output=True, text=True, cwd=AXIS_ROOT).stdout)
    has_simt = any(core.get("simt") for core in facts.get("cores", []))
    if (only is None and has_simt) or (only is not None and facet in only):
        emit(axis_file, "emit-pack-simt-h", include / "axis_simt.h")
        emit(axis_file, command, root / relative)
        obj = root / "src" / f"{facet}.o"
        subprocess.run(["cc", "-std=c11", "-O2", "-fPIC", "-I", str(include), "-c", "-o",
                        str(obj), str(root / relative)], check=True)
        static = lib / f"libaxis_{facet}_{ident}.a"
        subprocess.run(["ar", "rcs", str(static), str(obj)], check=True)
        libraries[facet] = {"entry": "axis_simt_create", "static": static.name}
    elif only is None:
        declined[facet] = "no SIMT core in this description"
    facet, command, relative = JIT
    try:
        if only is not None and facet not in only:
            raise jit_table.Unsupported("not asked for")
        table = jit_table.build_table(axis_file, root / "src" / "jit-work")
    except jit_table.Unsupported as reason:
        declined[facet] = str(reason)
    else:
        emit(axis_file, command, root / relative)
        (include / "axis_jit_table.h").write_text(
            jit_table.render(table, name))
        obj = root / "src" / f"{facet}.o"
        subprocess.run(["cc", "-std=c11", "-O2", "-fPIC",
                        "-I", str(include), "-c", "-o", str(obj),
                        str(root / relative)], check=True)
        static = lib / f"libaxis_{facet}_{ident}.a"
        subprocess.run(["ar", "rcs", str(static), str(obj)], check=True)
        shared = lib / f"libaxis_{facet}_{ident}.{suffix}"
        subprocess.run(["cc", "-shared", "-o", str(shared), str(obj)], check=True)
        libraries[facet] = {
            "entry": f"axis_{facet}_pack_{ident}",
            "static": static.name,
            "shared": shared.name,
            "host": table["host"],
            "stencils": len(table["stencils"]),
        }

    for facet, command, relative in (Z3, SYM):
        solver = solver_paths()
        if only is not None and facet not in only:
            declined[facet] = "not asked for"
            continue
        if solver is None:
            declined[facet] = ("no solver on this host: `z3.h` and `libz3` are "
                               "what it binds")
            continue
        headers, libraries_at = solver
        emit(axis_file, command, root / relative)
        obj = root / "src" / f"{facet}.o"
        subprocess.run(["cc", "-std=c11", "-O2", "-fPIC", "-I", str(include),
                        "-I", str(headers), "-c", "-o", str(obj),
                        str(root / relative)], check=True)
        static = lib / f"libaxis_{facet}_{ident}.a"
        subprocess.run(["ar", "rcs", str(static), str(obj)], check=True)
        shared = lib / f"libaxis_{facet}_{ident}.{suffix}"
        subprocess.run(["cc", "-shared", "-o", str(shared), str(obj),
                        f"-L{libraries_at}", "-lz3"], check=True)
        libraries[facet] = {
            "entry": f"axis_{facet}_pack_{ident}",
            "static": static.name,
            "shared": shared.name,
            "solver": "z3",
        }

    facet, command, relative = ("z3-unused", "", "")
    solver = None
    if False:
        solver = solver_paths()
    if only is not None and facet not in only:
        declined[facet] = "not asked for"
    elif solver is None:
        declined[facet] = "no solver on this host: `z3.h` and `libz3` are what it binds"
    else:
        headers, libraries_at = solver
        emit(axis_file, command, root / relative)
        obj = root / "src" / f"{facet}.o"
        subprocess.run(["cc", "-std=c11", "-O2", "-fPIC", "-I", str(include),
                        "-I", str(headers), "-c", "-o", str(obj),
                        str(root / relative)], check=True)
        static = lib / f"libaxis_{facet}_{ident}.a"
        subprocess.run(["ar", "rcs", str(static), str(obj)], check=True)
        shared = lib / f"libaxis_{facet}_{ident}.{suffix}"
        subprocess.run(["cc", "-shared", "-o", str(shared), str(obj),
                        f"-L{libraries_at}", "-lz3"], check=True)
        libraries[facet] = {
            "entry": f"axis_{facet}_pack_{ident}",
            "static": static.name,
            "shared": shared.name,
            "solver": "z3",
            "links": "-lz3",
        }

    manifest = {
        "schema": "axis.pack.v2",
        "name": name,
        "abi_version": 11,
        "libraries": libraries,
        "declined": declined,
        "include": [path.name for path in sorted(include.iterdir())],
    }
    (root / "pack.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path)
    parser.add_argument("--out", type=Path, default=AXIS_ROOT / "build" / "packs")
    args = parser.parse_args()
    manifest = build(args.axis_file, args.out)
    for facet, library in manifest["libraries"].items():
        print(f"{manifest['name']}/{facet}: {library['static']}, "
              f"{library['shared']}, entry {library['entry']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
