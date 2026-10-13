"""The lifter as a library, through its C ABI.

The CLI re-parses the whole description on every call. That is invisible for
one region and dominant for a sweep: lifting each of AArch64's instructions on
its own spawned nine hundred processes to ask nine hundred questions of one
description. This binds `libaxis_adl` instead, so the description is parsed
once and the handle answers.

The size-then-fill contract is the header's: ask with no buffer to learn the
length, allocate, ask again. It is honoured here rather than guessed at, so a
wrong length shows up as a mismatch instead of a truncated answer.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

AXIS_ROOT = Path(__file__).resolve().parent.parent


def _library_path() -> Path:
    override = os.environ.get("AXIS_LIB")
    if override:
        return Path(override)
    suffix = {"darwin": "dylib"}.get(os.uname().sysname.lower(), "so")
    return AXIS_ROOT / "target" / "release" / f"libaxis_adl.{suffix}"


class Lifter:
    """A parsed description, ready to lift with."""

    def __init__(self, axis_file: Path, library: Path | None = None):
        path = Path(library) if library else _library_path()
        if not path.exists():
            raise FileNotFoundError(f"{path}: build with `cargo build --release`")
        lib = ctypes.CDLL(str(path))
        _sig(lib)
        self._lib = lib
        handle = lib.axis_lift_open(str(axis_file).encode())
        if not handle:
            raise RuntimeError(lib.axis_lift_last_error().decode())
        self._handle = handle

    def close(self) -> None:
        if getattr(self, "_handle", None):
            self._lib.axis_lift_close(self._handle)
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _ask(self, call, *arguments) -> str:
        needed = call(self._handle, *arguments, None, 0)
        if needed < 0:
            raise RuntimeError(self._lib.axis_lift_last_error().decode())
        buffer = ctypes.create_string_buffer(needed + 1)
        again = call(self._handle, *arguments, buffer, needed + 1)
        if again != needed:
            raise RuntimeError(f"the library disagreed about its own length: "
                               f"{needed} then {again}")
        return buffer.value.decode()

    def blocks(self, image: bytes, address: int = 0, isa: str | None = None) -> str:
        return self._ask(self._lib.axis_lift_blocks, image, len(image), address,
                         isa.encode() if isa else None)

    def llvm(self, image: bytes, address: int = 0, isa: str | None = None) -> str:
        return self._ask(self._lib.axis_lift_llvm, image, len(image), address,
                         isa.encode() if isa else None)

    def preamble(self) -> str:
        """The semantics helpers, which do not depend on the bytes."""
        return self._ask(self._lib.axis_lift_preamble)

    def blocks_llvm(self, image: bytes, address: int = 0,
                    isa: str | None = None) -> str:
        """A region's block functions, without the preamble."""
        return self._ask(self._lib.axis_lift_llvm_blocks, image, len(image),
                         address, isa.encode() if isa else None)

    def support(self) -> dict:
        """Mnemonic to `None` when the lifter takes it, or the reason it does not."""
        verdicts = {}
        for line in self._ask(self._lib.axis_lift_support).splitlines():
            if line.startswith("#"):
                continue
            name, _, reason = line.partition("\t")
            verdicts[name] = None if reason == "ok" else reason
        return verdicts

    @property
    def instruction_count(self) -> int:
        return int(self._lib.axis_lift_instruction_count(self._handle))


def _sig(lib) -> None:
    ptr = ctypes.c_void_p
    lib.axis_lift_open.restype = ptr
    lib.axis_lift_open.argtypes = [ctypes.c_char_p]
    lib.axis_lift_close.restype = None
    lib.axis_lift_close.argtypes = [ptr]
    lib.axis_lift_last_error.restype = ctypes.c_char_p
    lib.axis_lift_last_error.argtypes = []
    region = [ptr, ctypes.c_char_p, ctypes.c_ssize_t, ctypes.c_uint64,
              ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ssize_t]
    for name in ("axis_lift_blocks", "axis_lift_llvm", "axis_lift_llvm_blocks"):
        fn = getattr(lib, name)
        fn.restype = ctypes.c_ssize_t
        fn.argtypes = region
    for name in ("axis_lift_support", "axis_lift_preamble"):
        fn = getattr(lib, name)
        fn.restype = ctypes.c_ssize_t
        fn.argtypes = [ptr, ctypes.c_char_p, ctypes.c_ssize_t]
    lib.axis_lift_instruction_count.restype = ctypes.c_int
    lib.axis_lift_instruction_count.argtypes = [ptr]
