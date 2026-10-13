"""The generated decoder, bound into Python — not reimplemented in it.

A script that wants to name the instruction at a word has two options. It can
read `decode_table.json` and write its own match/mask loop, which is what
`aha/socc/axismine_decoder.py` does today; or it can call the decoder AXIS
already generates. The first is a **second decoder**, and a second decoder is a
second set of selection rules to keep in agreement -- the ISA filter, the
definedness skip, and the rule that several entries sharing a word are the
lanes of one scalable instruction rather than an ambiguity. A Python
re-implementation that omits those is not a smaller decoder, it is a different
one, and nothing in either repository would say which was right.

So this compiles the emitted C and calls it. The decode logic crosses no
language boundary; only integers and strings do.

    from axis_decode_ffi import load
    isa = load("examples/rv64i.axisl")
    insn = isa.decode(0x0000_8067)      # -> Instruction(mnemonic='JALR', ...)
    insn.operands                        # -> (Operand(name='rd', value=0), ...)

**Pass `isa=` when a description holds more than one.** It is not a filter for
tidiness. `aarch64_translation_seed.axisl` describes `aarch64_base` beside an
`accelerator_scalar64` whose `ACCEL_BL_I26` claims match `0xd4000000` / mask
`0xfc000000` -- the whole branch-register space -- so `0xd65f03c0` is `ret` in
one ISA and `accel_bl_i26` in the other, and with no ISA named the decoder
correctly answers *nothing*: two instructions genuinely match. A hand-written
scan that ignores the `isa` field does not avoid this, it hides it, returning
whichever entry it happened to reach first. `Decoder.isas` lists what a
description offers, so the argument is discoverable rather than folklore.

The decoder is a **value**, returned from `load`, not a module global. Callers
that widen a mining window by monkey-patching a module-level `mnemonic` have
hit a recursion trap three times in PCE's history; there is nothing here to
patch.

The shared library is cached under `cache_dir` keyed by the description's
content and the AXIS build stamp, so a rebuilt AXIS or an edited `.axisl`
produces a new library rather than a stale answer -- the failure mode that cost
`AXISMINE.0` a day of misattribution.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axis_cli import axis_prefix  # noqa: E402

AXIS_ROOT = Path(__file__).resolve().parent.parent

#: What the ABI emitter produces, and what it needs beside it.
_ARTIFACTS = (
    ("emit-pack-abi-c", "axis_pack.h"),
    ("emit-decode-c", "axis_decode.h"),
    ("emit-encode-c", "axis_encode.h"),
    ("emit-pack-decode-c", "axis_decode_pack.c"),
)

#: ⚠️ Flat names over the PACK, rather than a generated ABI of flat names.
#:
#: There used to be an emitter for this -- `emit-decode-abi-c` -- and its
#: symbols were the same for every description, so two architectures could not
#: be loaded into one process. The pack fixed that by naming its entry after
#: the architecture, and this is the twenty lines that bind one pack into
#: ctypes: the decode logic still crosses no language boundary, and the flat
#: names are private to this shared object rather than shipped in an artifact.
_SHIM = """
#include "axis_pack.h"
extern const axis_decode_pack *%(entry)s(void);
static const axis_decode_pack *pack(void) { return %(entry)s(); }

const char *axis_abi_description(void) { return pack()->name; }
const char *axis_abi_generator(void) { return pack()->generator; }
int32_t axis_abi_count(void) { return pack()->count(); }
int32_t axis_abi_decode(uint32_t w, const char *isa) { return pack()->decode(w, isa); }
int32_t axis_abi_decode_linear(uint32_t w, const char *isa) { return pack()->decode_linear(w, isa); }
const char *axis_abi_mnemonic(int32_t i) { return pack()->mnemonic(i); }
const char *axis_abi_isa(int32_t i) { return pack()->isa(i); }
const char *axis_abi_format(int32_t i) { return pack()->format(i); }
const char *axis_abi_asm_syntax(int32_t i) { return pack()->asm_syntax(i); }
uint32_t axis_abi_match(int32_t i) { return pack()->match(i); }
uint32_t axis_abi_mask(int32_t i) { return pack()->mask(i); }
uint32_t axis_abi_bits(int32_t i) { return pack()->bits(i); }
int32_t axis_abi_operand_count(int32_t i) { return pack()->operand_count(i); }
const char *axis_abi_operand_name(int32_t i, int32_t o) { return pack()->operand_name(i, o); }
const char *axis_abi_operand_kind(int32_t i, int32_t o) { return pack()->operand_kind(i, o); }
const char *axis_abi_operand_role(int32_t i, int32_t o) { return pack()->operand_role(i, o); }
uint32_t axis_abi_operand_value(uint32_t w, int32_t i, int32_t o) {
  return pack()->operand_value(w, i, o);
}
int32_t axis_abi_tables_aligned(void) { return pack()->tables_aligned(); }
int32_t axis_abi_decode_buffer(const uint32_t *words, int32_t n, const char *isa,
                               int32_t *out) {
  return pack()->decode_buffer(words, n, isa, out);
}
int32_t axis_abi_decode_le(const uint8_t *bytes, int32_t n, const char *isa,
                           int32_t *out) {
  return pack()->decode_le(bytes, n, isa, out);
}
int32_t axis_abi_decode_stream(const uint8_t *bytes, int32_t n, const char *isa,
                               int32_t *offset, int32_t *index, int32_t *size,
                               int32_t limit) {
  return pack()->decode_stream(bytes, n, isa, offset, index, size, limit);
}
int32_t axis_abi_operands_buffer(const uint32_t *words, const int32_t *indices,
                                 int32_t n, int32_t stride, uint32_t *out) {
  return pack()->operands_buffer(words, indices, n, stride, out);
}
"""


def _pack_entry(source: Path) -> str:
    """The symbol this description's decode library exports."""
    name = json.loads(subprocess.run(
        [*axis_prefix(), "emit-json", str(source)],
        check=True, capture_output=True, text=True, cwd=AXIS_ROOT).stdout)["name"]
    ident = "".join(ch if ch.isalnum() else "_" for ch in name).lower()
    if ident[:1].isdigit():
        ident = f"_{ident}"
    return f"axis_decode_pack_{ident}"

_STRING = ctypes.c_char_p
_I32 = ctypes.c_int32
_U32 = ctypes.c_uint32

#: Every symbol's signature, declared. ctypes defaults an unspecified restype
#: to `c_int`, which truncates a returned pointer to 32 bits and hands back a
#: plausible-looking address that is not the string. Declaring all of them is
#: the difference between a binding and a segfault.
_SIGNATURES = {
    "axis_abi_description": (_STRING, []),
    "axis_abi_generator": (_STRING, []),
    "axis_abi_count": (_I32, []),
    "axis_abi_decode": (_I32, [_U32, _STRING]),
    "axis_abi_decode_linear": (_I32, [_U32, _STRING]),
    "axis_abi_mnemonic": (_STRING, [_I32]),
    "axis_abi_isa": (_STRING, [_I32]),
    "axis_abi_format": (_STRING, [_I32]),
    "axis_abi_asm_syntax": (_STRING, [_I32]),
    "axis_abi_match": (_U32, [_I32]),
    "axis_abi_mask": (_U32, [_I32]),
    "axis_abi_bits": (_U32, [_I32]),
    "axis_abi_decode_stream": (_I32, [ctypes.POINTER(ctypes.c_uint8), _I32, _STRING,
                                      ctypes.POINTER(_I32), ctypes.POINTER(_I32),
                                      ctypes.POINTER(_I32), _I32]),
    "axis_abi_operand_count": (_I32, [_I32]),
    "axis_abi_operand_name": (_STRING, [_I32, _I32]),
    "axis_abi_operand_kind": (_STRING, [_I32, _I32]),
    "axis_abi_operand_role": (_STRING, [_I32, _I32]),
    "axis_abi_operand_value": (_U32, [_U32, _I32, _I32]),
    "axis_abi_tables_aligned": (_I32, []),
    "axis_abi_decode_buffer": (_I32, [ctypes.POINTER(_U32), _I32, _STRING,
                                      ctypes.POINTER(_I32)]),
    "axis_abi_decode_le": (_I32, [ctypes.POINTER(ctypes.c_uint8), _I32, _STRING,
                                  ctypes.POINTER(_I32)]),
    "axis_abi_operands_buffer": (_I32, [ctypes.POINTER(_U32), ctypes.POINTER(_I32),
                                        _I32, _I32, ctypes.POINTER(_U32)]),
}


@dataclass(frozen=True)
class Operand:
    """One declared operand, with the value this word carries for it."""
    name: str
    kind: str
    role: str
    value: int


@dataclass(frozen=True)
class Instruction:
    index: int
    mnemonic: str
    isa: str
    format: str
    asm_syntax: str
    match: int
    mask: int
    operands: Tuple[Operand, ...]


def _text(value: Optional[bytes]) -> str:
    return value.decode() if value else ""


class Decoder:
    """A loaded ISA description's decoder. Construct with `load`."""

    def __init__(self, library: ctypes.CDLL, source: Path):
        self._lib = library
        self.source = source
        for name, (restype, argtypes) in _SIGNATURES.items():
            function = getattr(library, name)
            function.restype = restype
            function.argtypes = argtypes
        self.description = _text(library.axis_abi_description())
        self.generator = _text(library.axis_abi_generator())
        self.count = int(library.axis_abi_count())
        # Named once, so turning a bulk result into names is a list index
        # rather than a call. This is most of why bulk decoding is worth
        # having: the crossing is what costs, not the decode.
        self.mnemonics: Tuple[str, ...] = tuple(
            _text(library.axis_abi_mnemonic(index)) for index in range(self.count))
        if not library.axis_abi_tables_aligned():
            # The decode and encode tables are indexed as one. If they ever
            # stop agreeing, an operand read would come from the right slot of
            # the wrong instruction, which is a wrong answer rather than an
            # error, so this refuses to load at all.
            raise RuntimeError(
                f"{source}: the decode and encode tables are not aligned, so an "
                f"operand would be read from another instruction")

    @property
    def isas(self) -> Tuple[str, ...]:
        """The ISA names this description carries, in table order. Pass one to
        `decode` when there is more than one: entries from different ISAs may
        share an encoding, and an unqualified decode of a shared word is
        ambiguous rather than wrong."""
        seen = {self.at(index).isa for index in range(self.count)}
        return tuple(sorted(name for name in seen if name))

    def decode(self, word: int, isa: Optional[str] = None) -> Optional[Instruction]:
        return self.at(self._lib.axis_abi_decode(word & 0xFFFFFFFF, _encode(isa)),
                        word)

    def decode_linear(self, word: int,
                      isa: Optional[str] = None) -> Optional[Instruction]:
        """The same answer by scanning the table. The tree is checked against
        this in AXIS's own ladder; exposing it lets a caller check the build it
        actually loaded, in its own process."""
        return self.at(
            self._lib.axis_abi_decode_linear(word & 0xFFFFFFFF, _encode(isa)), word)

    def mnemonic(self, word: int, isa: Optional[str] = None) -> Optional[str]:
        """Lower-cased -- the spelling PCE's platform decoders return."""
        found = self.decode(word, isa)
        return found.mnemonic.lower() if found else None

    def decode_many(self, words, isa: Optional[str] = None) -> list:
        """Decode a sequence of words in **one** crossing, returning a table
        index per word and -1 where nothing matched.

        Per-word `decode` costs ~33us: ~3us of ctypes for the call and the rest
        building an `Instruction` from four more calls per operand. The decoder
        itself costs 0.05us. A real text section is millions of words, so a
        miner should decode in bulk, name the results through `mnemonics`, and
        build objects only for what it keeps.
        """
        words = list(words)
        count = len(words)
        if not count:
            return []
        buffer = (_U32 * count)(*(word & 0xFFFFFFFF for word in words))
        out = (_I32 * count)()
        got = self._lib.axis_abi_decode_buffer(buffer, count, _encode(isa), out)
        if got != count:
            raise RuntimeError(f"bulk decode returned {got} for {count} words")
        return list(out)

    def walk(self, data: bytes, isa: Optional[str] = None) -> list:
        """Walk a byte stream by each instruction's **own width**.

        Returns `(offset, index, nbytes)` per instruction, `index` -1 where
        nothing decoded. This is what `decode_bytes` cannot do: it steps a fixed
        four bytes, which is right until the stream holds a 16-bit instruction
        and then wrong for everything after it. A compiled RISC-V object read
        60.7% that way and 93.1% when the widths were honoured, and the
        description had been right the whole time.

        A word that decodes to nothing advances by the narrowest width the table
        has, because a real section has data in it and stopping at the first
        byte that is not an instruction would end the walk early.
        """
        count = len(data)
        if count < 2:
            return []
        limit = count // 2 + 1
        offsets = (_I32 * limit)()
        indices = (_I32 * limit)()
        widths = (_I32 * limit)()
        buffer = (ctypes.c_uint8 * count).from_buffer_copy(data)
        found = self._lib.axis_abi_decode_stream(buffer, count, _encode(isa),
                                                 offsets, indices, widths, limit)
        if found < 0:
            raise RuntimeError("the stream walk refused its arguments")
        return [(offsets[i], indices[i], widths[i]) for i in range(found)]

    def bits(self, index: int) -> int:
        """How wide the instruction at a table index is."""
        return int(self._lib.axis_abi_bits(index))

    def decode_bytes(self, data: bytes, isa: Optional[str] = None) -> list:
        """The same, over a little-endian image -- what an ELF section is.

        The word assembly happens in C with explicit shifts, so the result does
        not depend on the host's byte order the way casting the buffer to
        `uint32_t *` would. Trailing bytes past the last whole word are
        ignored, which is what a section not a multiple of four means.
        """
        count = len(data) // 4
        if not count:
            return []
        out = (_I32 * count)()
        buffer = (ctypes.c_uint8 * len(data)).from_buffer_copy(data)
        got = self._lib.axis_abi_decode_le(buffer, len(data), _encode(isa), out)
        if got != count:
            raise RuntimeError(f"bulk decode returned {got} for {count} words")
        return list(out)

    def operands_many(self, words, indices, stride: int = 8) -> list:
        """Operand values for many decoded words in one crossing.

        Returns one list per word, `stride` wide. A word whose index is -1 or
        whose operand list is shorter keeps zeros in the unused columns; if any
        instruction had more operands than `stride`, this raises rather than
        return silently truncated rows.
        """
        words, indices = list(words), list(indices)
        count = len(words)
        if count != len(indices):
            raise ValueError(f"{count} words but {len(indices)} indices")
        if not count:
            return []
        word_buffer = (_U32 * count)(*(word & 0xFFFFFFFF for word in words))
        index_buffer = (_I32 * count)(*indices)
        out = (_U32 * (count * stride))()
        widest = self._lib.axis_abi_operands_buffer(word_buffer, index_buffer,
                                                    count, stride, out)
        if widest > stride:
            raise ValueError(f"stride {stride} is too narrow: an instruction "
                             f"here has {widest} operands")
        return [list(out[i * stride:(i + 1) * stride]) for i in range(count)]

    def at(self, index: int, word: int = 0) -> Optional[Instruction]:
        """The instruction at a table index, with the operand values `word`
        carries for it. `word` is what makes an `Instruction` concrete; pass 0
        to describe the entry itself, which is how a caller enumerates the ISA
        without decoding anything."""
        if index < 0:
            return None
        lib = self._lib
        operands = tuple(
            Operand(
                name=_text(lib.axis_abi_operand_name(index, ordinal)),
                kind=_text(lib.axis_abi_operand_kind(index, ordinal)),
                role=_text(lib.axis_abi_operand_role(index, ordinal)),
                value=int(lib.axis_abi_operand_value(word & 0xFFFFFFFF, index,
                                                     ordinal)),
            )
            for ordinal in range(max(0, lib.axis_abi_operand_count(index)))
        )
        return Instruction(
            index=index,
            mnemonic=_text(lib.axis_abi_mnemonic(index)),
            isa=_text(lib.axis_abi_isa(index)),
            format=_text(lib.axis_abi_format(index)),
            asm_syntax=_text(lib.axis_abi_asm_syntax(index)),
            match=int(lib.axis_abi_match(index)),
            mask=int(lib.axis_abi_mask(index)),
            operands=operands,
        )


def _encode(isa: Optional[str]) -> Optional[bytes]:
    return isa.encode() if isa else None


def _stamp(source: Path) -> str:
    """What the cached library is a build of. The AXIS build is part of it: a
    stale binary emitting a stale table is exactly how `AXISMINE.0` reported
    two failures that were one wrong `target/release/axis`."""
    digest = hashlib.sha256(source.read_bytes())
    try:
        version = subprocess.run([*axis_prefix(), "--version"], capture_output=True,
                                 text=True, cwd=AXIS_ROOT, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError):
        version = "unknown"
    digest.update(version.encode())
    return digest.hexdigest()[:16]


def _suffix() -> str:
    return ".dylib" if sys.platform == "darwin" else ".dll" if os.name == "nt" else ".so"


def load(axis_file, *, cache_dir=None, compiler: str = "cc") -> Decoder:
    """Emit, compile and bind the decoder for one ISA description."""
    source = Path(axis_file)
    if not source.is_absolute():
        source = (AXIS_ROOT / source) if not source.exists() else source.resolve()
    if not source.exists():
        raise FileNotFoundError(f"no such ISA description: {source}")
    root = Path(cache_dir) if cache_dir else Path(
        os.environ.get("AXIS_FFI_CACHE", Path(tempfile.gettempdir()) / "axis-ffi"))
    workdir = root / f"{source.stem}-{_stamp(source)}"
    library = workdir / f"libaxis_{source.stem}{_suffix()}"
    if not library.exists():
        workdir.mkdir(parents=True, exist_ok=True)
        for command, name in _ARTIFACTS:
            subprocess.run([*axis_prefix(), command, str(source), "-o",
                            str(workdir / name)], check=True, cwd=AXIS_ROOT)
        # Built into a temporary name and moved, so a killed compile leaves no
        # half-written library for the next run to load and believe.
        (workdir / "axis_decode_shim.c").write_text(
            _SHIM % {"entry": _pack_entry(source)})
        staged = library.with_suffix(library.suffix + ".staged")
        subprocess.run([compiler, "-std=c11", "-O2", "-shared", "-fPIC", "-o",
                        str(staged), str(workdir / "axis_decode_shim.c"),
                        str(workdir / "axis_decode_pack.c"),
                        f"-I{workdir}"], check=True)
        staged.replace(library)
    return Decoder(ctypes.CDLL(str(library)), source)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "examples/rv64i.axisl"
    isa = load(target)
    print(f"{isa.description}: {isa.count} instructions, generator {isa.generator}")
    print(f"  ISAs: {', '.join(isa.isas) or '(none named)'}")
    for word in (int(arg, 0) for arg in sys.argv[2:]):
        found = isa.decode(word)
        if not found:
            print(f"  0x{word:08x}  (no instruction)")
            continue
        operands = ", ".join(f"{op.name}={op.value}" for op in found.operands)
        print(f"  0x{word:08x}  {found.mnemonic.lower():<16} {operands}")
