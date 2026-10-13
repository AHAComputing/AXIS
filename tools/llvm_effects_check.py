#!/usr/bin/env python3
"""Differential check: the generated LLVM effect functions vs the Python executor.

`axis_semantics.ll` carries `define void @axis_eff_<name>(i8* %mem, iW %pc,
iW* %out, iW %<input>...)` for every instruction whose behavior the pure `Sem`
path cannot hold (E5). This harness compiles that IR with clang against a
generated driver and requires the full architectural delta -- written value,
write flag, next pc, trap id, and the memory image -- to match `axis_exec.py`,
which `exec_vs_golden.py` proves equal to the golden model.

`W` is the instruction's own evaluation width: 32, or 64 for a 64-bit ISA (an
AArch64 branch adds its displacement to a 64-bit pc). The driver reads the
emitted `define` line to pick the C types rather than assuming the narrow ABI,
because a driver that called an i64 function through a uint32_t prototype would
pass garbage and report a semantics failure.

Memory model: the generated IR lowers loads and stores to native LLVM
`load`/`store` against a flat little-endian byte buffer, which is the
byte-addressed space `docs/effects_design.md` describes. The executors take a
caller-supplied memory instead of imposing one (`exec_c_check.py` happens to
supply an (addr, width)-keyed cell model), so this harness gives the Python
side the same byte-addressed buffer the IR uses -- otherwise the two would be
compared under different memory models.

Usage: tools/llvm_effects_check.py [input.axisl] [--cases N] [--seed S]

Requires: cargo (from the AXIS repo root) and a clang that can compile textual
LLVM IR. Exits 0 with a SKIP notice if clang cannot.
"""

from __future__ import annotations

import argparse
import importlib
import importlib.util
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from axis_cli import axis_prefix

AXIS_ROOT = Path(__file__).resolve().parent.parent
MEM_BYTES = 1 << 16
# Operand values stay small so any address an effect computes lands inside the
# buffer; a case whose address escapes it is skipped rather than truncated.
MAX_REG_VALUE = 4096
TRAP_CAUSES = ["illegal", "misaligned", "access", "ecall", "ebreak"]


def emit(axis_file: Path, command: str, output: Path) -> None:
    subprocess.run(
        [*axis_prefix(), command, str(axis_file), "-o", str(output)],
        check=True,
        cwd=AXIS_ROOT,
    )


def clang_handles_ll(clang: str, workdir: Path) -> bool:
    probe = workdir / "probe.ll"
    probe.write_text("define i32 @axis_probe() {\nentry:\n  ret i32 7\n}\n")
    result = subprocess.run(
        [clang, "-c", str(probe), "-o", str(workdir / "probe.o")],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


class ByteMemory:
    """The byte-addressed little-endian space the generated IR assumes."""

    def __init__(self, data: bytes) -> None:
        self.data = bytearray(data)
        self.escaped = False

    def _slice(self, addr: int, width: int):
        count = width // 8
        if addr < 0 or addr + count > len(self.data):
            self.escaped = True
            return None
        return slice(addr, addr + count)

    def read(self, addr: int, width: int) -> int:
        window = self._slice(addr, width)
        if window is None:
            return 0
        return int.from_bytes(self.data[window], "little")

    def write(self, addr: int, value: int, width: int) -> None:
        window = self._slice(addr, width)
        if window is None:
            return
        masked = value & ((1 << width) - 1)
        self.data[window] = masked.to_bytes(width // 8, "little")


def compare_and_swap_operands(entry):
    """`(compared, address)` operand names if this is a compare-and-swap.

    The shape is a register set from an atomic load followed by an atomic store
    guarded on that register still holding its entry value -- the comparison
    compare-and-swap performs. Returns None for anything else.
    """
    effects = entry.get("effects") or []
    if len(effects) != 2:
        return None
    load, store = effects
    if load.get("kind") != "set" or store.get("kind") != "store":
        return None
    if not (load.get("atomic") and store.get("atomic") and store.get("guard")):
        return None
    address = store.get("addr")
    compared = load.get("dest")
    # Only a bare operand address is usable here; anything computed would need
    # the address evaluated the way the handler evaluates it.
    if not address or not address.isidentifier() or not compared:
        return None
    return compared, address


def atomic_alignment(entry) -> int:
    """Bytes an atomic effect of this instruction must be aligned to, or 1.

    ⚠️ A PAIRED atomic needs twice its element's alignment. `CASP` and `LDXP`
    each touch two consecutive words as ONE transaction, which is one `casp` or
    `ldxp` over a 16-byte quantity, and arm64 requires that quantity to be
    16-byte aligned -- not 8, which is all the element width asks for. Aligning
    to the element handed the JIT an 8-aligned address and the process died
    with SIGBUS, saying nothing about which instruction was wrong.

    What makes it a pair is that its atomic effects touch two DIFFERENT
    addresses. A compare-and-swap also has two atomic effects of one width, and
    they are at the same address, so counting effects would double its
    alignment for no reason; counting distinct addresses does not. An earlier
    version keyed on a derived operand instead, which is how `CASP` spells its
    register pair -- and `LDXP` encodes both of its registers, so it was missed
    and faulted.

    ⚠️ A STORE-CONDITIONAL needs alignment its description does not ask for.
    `sc.w`'s store is written as an ordinary guarded store -- the description
    says nothing about atomicity -- but the lifter turns the pair into a
    `cmpxchg`, which inherits the hardware's alignment rule, and RISC-V requires
    a reservation address to be naturally aligned in the first place. Taking the
    description at its word gave the sweep a 1-aligned address and the process
    died with SIGBUS inside the compare-and-swap.
    """
    effects = entry.get("effects") or []
    atomics = [effect for effect in effects if effect.get("atomic")]
    # The guarded reservation store, counted at its own width for the reason
    # above. Matched the way the lifter matches it: a guard about the monitor.
    for effect in effects:
        guard = effect.get("guard") or ""
        if (effect.get("kind") == "store" and not effect.get("atomic")
                and "exclusive_address" in guard and "exclusive_valid" in guard):
            atomics.append(effect)
    if not atomics:
        return 1
    element = max(effect.get("width", 8) for effect in atomics) // 8
    return element * (2 if len(atomic_addresses(atomics)) > 1 else 1)


def atomic_addresses(effects) -> set:
    """The distinct places a set of atomic effects touches, as written."""
    places = set()
    for effect in effects:
        if effect.get("addr"):
            places.add(effect["addr"])
            continue
        # A load spells its address inside the value: the last argument of
        # `(atomic_load <type> <sign> <order> <addr>)`.
        value = (effect.get("value") or "").strip()
        if value.startswith("(atomic_load "):
            parts = value[1:-1].split(None, 4)
            if len(parts) == 5:
                places.add(parts[4])
    return places


def operand_limbs(operand, abi_bits):
    """How many ABI-wide limbs this operand occupies.

    A 128-bit vector register is two 64-bit slots in the file and two
    parameters in the effect ABI, low first. Everything narrower is one of
    each, which is every operand that existed before the Q forms.
    """
    width = operand.get("width") or abi_bits
    return max(1, -(-width // abi_bits))


def extra_write_checks(mnemonic, entry, writes, fixture_index, before, after,
                       register_slot,
                       abi_bits):
    """C assertions for the writes beyond the first, or None to skip the case.

    Write `k` is the `k`-th register-writing effect, and the lift table gives
    its destination operand, so the register it targets is that operand's
    decoded value. The value it should carry is what the executor left in that
    register -- which identifies the write only when each one targets a
    distinct register that actually holds the result. Two writes to the same
    register, or a write to AArch64's zero register (discarded architecturally
    while the handler still computes and reports a value), are reported as
    unchecked rather than compared against something the reference cannot say.
    """
    suffix = "ull" if abi_bits == 64 else "u"
    kinds = {operand["name"]: operand["kind"] for operand in entry["operands"]}
    widths = {operand["name"]: operand.get("width") for operand in entry["operands"]}
    operands = {operand["name"]: operand for operand in entry["operands"]}
    # Counted in limbs, not in effects: one `ldr q0` write is two slots, so a
    # single wide write still has a second position to check. Counting effects
    # returned early and left the high limb compared against nothing.
    positions = sum(
        1 if write.get("kind") == "setreg"
        else operand_limbs(operands.get(write.get("dest"), {}), abi_bits)
        for write in writes
    )
    if positions <= 1:
        return ""
    targets = []
    for write in writes:
        if write.get("kind") == "setreg":
            # A fixed register names its index outright rather than through an
            # operand, which is what makes it addressable by a consumer.
            targets.append((write["index"], "reg", write["index"]))
            continue
        dest = write.get("dest")
        if dest is None or dest not in fixture_index:
            return None
        index = fixture_index[dest]
        kind = kinds.get(dest, "reg")
        # 31 is XZR/WZR (writes discarded) or SP depending on the class.
        if kind != "reg" and index == 31:
            return None
        limbs = operand_limbs(operands.get(dest, {}), abi_bits)
        if limbs > 1:
            # Each limb is its own write position, low first, and its own slot
            # in the file -- which is exactly what the register file holds now
            # that the reference splits a wide value instead of keeping it in
            # one arbitrary-precision integer.
            base = register_slot(kind, index)
            targets.extend((base + limb, kind, index) for limb in range(limbs))
            continue
        # Through the class, the way the seeding already does it. A register
        # file of its own sits above the general-purpose one in the flat array
        # -- `a64_vreg64` starts at 32 -- so reading `after[index]` for
        # `ldp d1, d2` looked up x1 and x2, found the zeros nobody wrote, and
        # reported the load as broken. Every effectful instruction wrote the
        # general-purpose file until the SIMD&FP loads were described.
        targets.append((register_slot(kind, index), kind, index))
    if len({slot for slot, _, _ in targets}) != len(targets):
        return None
    checks = []
    for position, (slot, kind, index) in enumerate(targets):
        value_slot, wrote_slot = ((0, 1) if position == 0
                                  else (2 + 2 * position, 3 + 2 * position))
        want = after.get(slot, 0)
        # Named by its class rather than as `x<n>`: a failure about "x1" for
        # `ldp d1, d2` sends a reader to the wrong register file.
        register = f"{kind}[{index}]"
        checks.append(
            f'    if (out[{wrote_slot}] != 1{suffix}) {{ printf("FAIL {mnemonic} '
            f'write {position} did not fire\\n"); failures++; }}\n'
            f'    if (out[{value_slot}] != {want}{suffix}) {{ printf("FAIL {mnemonic} '
            f'write {position} ({register}) want 0x{want:x}\\n"); failures++; }}\n'
        )
    return "".join(checks)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("axis_file", type=Path, nargs="?",
                        default=AXIS_ROOT / "examples" / "fuzz_mix.axisl")
    parser.add_argument("--cases", type=int, default=24,
                        help="cases per effectful instruction")
    parser.add_argument("--seed", type=int, default=0x5E5)
    parser.add_argument("--clang", default="clang")
    args = parser.parse_args()

    workdir = Path(tempfile.mkdtemp(prefix="axis_llvmeff_"))
    if not clang_handles_ll(args.clang, workdir):
        print(f"SKIP: {args.clang} cannot compile textual LLVM IR here")
        return 0

    ll_path = workdir / "axis_semantics.ll"
    emit(args.axis_file, "emit-llvm-ir", ll_path)
    emit(args.axis_file, "emit-golden-python", workdir / "golden_model.py")
    emit(args.axis_file, "emit-lift-python", workdir / "axis_lift.py")
    emit(args.axis_file, "emit-exec-python", workdir / "axis_exec.py")
    fixtures_path = workdir / "axis_roundtrip_tests.json"
    emit(args.axis_file, "emit-roundtrip-json", fixtures_path)

    sys.path.insert(0, str(workdir))
    axis_lift = importlib.import_module("axis_lift")
    axis_exec = importlib.import_module("axis_exec")

    ll_text = ll_path.read_text()
    fixtures = json.loads(fixtures_path.read_text()).get("tests", [])
    rng = random.Random(args.seed)
    seed_image = bytes(rng.getrandbits(8) for _ in range(MEM_BYTES))

    # Grouped by mnemonic rather than one flat list: emitting every case into a
    # single `main` produced a function large enough that clang spent minutes in
    # register allocation on it, and the cost grows faster than the case count.
    cases: dict[str, list[str]] = {}
    multi_write: list[str] = []
    state_widths: set[int] = set()
    unchecked = 0
    declared: dict[str, tuple[int, int]] = {}
    covered: list[str] = []
    skipped: list[str] = []
    for test in fixtures:
        word = int(test["encoded"], 16)
        entry = axis_lift.decode(word, test.get("isa"))
        if entry is None or not entry.get("effects"):
            continue
        mnemonic = entry["mnemonic"]
        fn_name = f"axis_eff_{mnemonic.lower()}"
        signature = f"define void @{fn_name}("
        if signature not in ll_text:
            skipped.append(mnemonic)
            continue
        # The ABI width is whatever the emitter chose for this function.
        header = ll_text[ll_text.index(signature):].split(")", 1)[0]
        abi_bits = 64 if "i64 %pc" in header else 32

        fixture_index = {operand["name"]: operand["value"] for operand in test["operands"]}
        inputs = [op for op in entry["operands"] if op["role"] != "out"]
        emitted = 0
        for case in range(args.cases):
            regs: dict[int, int] = {}
            values: list[int] = []
            for operand in inputs:
                index = fixture_index[operand["name"]]
                # `is_register_operand` comes from the generated lifter: an
                # AArch64 operand's kind is its register class, so a local
                # `kind == "reg"` test would pass the register *number* in as
                # the value and compare it against an executor that read the
                # register file.
                if axis_lift.is_register_operand(operand["kind"]):
                    # The slot a register occupies includes its class's offset,
                    # which is how a second register file is modelled: RISC-V's
                    # f5 is slot 37 while x5 is slot 5. Seeding the wrong slot
                    # feeds the handler one register and the executor another.
                    index = axis_lift.register_slot(operand["kind"], index)
                    limbs = operand_limbs(operand, abi_bits)
                    for limb in range(limbs):
                        # Case 0 forces equal register inputs so an equality
                        # guard is taken at least once; the rest are random.
                        value = 0 if case == 0 else rng.randrange(MAX_REG_VALUE)
                        if limbs > 1:
                            # A limb that is only ever a small number would make
                            # the high half indistinguishable from the low one,
                            # and a lowering that stored the same limb twice
                            # would pass. The upper limb of a vector register is
                            # not an address, so it takes the whole range.
                            value = rng.randrange(1 << abi_bits)
                        else:
                            # An atomic access must be naturally aligned:
                            # AArch64 takes an alignment fault otherwise, and
                            # LLVM's atomicrmw and cmpxchg inherit that from the
                            # hardware. AXIS does not yet model the fault, so
                            # this generates addresses the architecture allows
                            # rather than comparing two backends on behaviour
                            # neither of them defines.
                            value &= ~(atomic_alignment(entry) - 1)
                        regs[index + limb] = value
                        values.append(value)
                else:
                    values.append(index)
            pc = rng.randrange(0, 1 << 16) & ~3
            # A compare-and-swap only stores when the memory still holds what
            # the comparison register held, and against random memory that is
            # never true: an injected swap of cmpxchg's expected and new
            # operands showed up in 2 cases out of 11544, which is a gate that
            # barely tests the instruction. Half the cases now load the
            # comparison register with what is actually at the address, so both
            # outcomes are exercised.
            swap = compare_and_swap_operands(entry)
            if swap and case % 2 == 1:
                compared, address = swap
                addr_value = regs.get(fixture_index.get(address))
                if addr_value is not None:
                    width = atomic_alignment(entry)
                    window = seed_image[addr_value:addr_value + width]
                    if len(window) == width:
                        held = int.from_bytes(window, "little")
                        regs[fixture_index[compared]] = held
                        values = [held if operand["name"] == compared else value
                                  for operand, value in zip(inputs, values)]

            memory = ByteMemory(seed_image)
            before = dict(regs)
            # Architectural state is an in/out array indexed by the lifter's
            # published slot order. Seeding it with non-zero values matters:
            # an instruction that reads NZCV and one that ignores it agree on
            # an all-zero state, so a handler that dropped the read would pass.
            state_values = [rng.randrange(1 << min(width, 32))
                            for _, width in axis_lift.STATE_SLOTS]
            state = {name: value for (name, _), value
                     in zip(axis_lift.STATE_SLOTS, state_values)}
            reference = axis_exec.step(word, regs, mem=memory, pc=pc,
                                       isa=test.get("isa"), state=state)
            if memory.escaped:
                continue
            # Every register the executor changed has to be accounted for by a
            # write the handler reports. Without this the comparison below --
            # which reads one value and one flag -- would pass an instruction
            # that silently dropped its base-register update, which is exactly
            # what the post-indexed forms did before the ABI carried more than
            # one write.
            changed_regs = {
                name: value for name, value in regs.items()
                if before.get(name) != value
            }
            # `setreg` is a register write too -- AArch64 BL writes x30 -- and it
            # occupies a write slot exactly like a `set`. Counting only `set`
            # made the check below report BL's link register as an unaccounted
            # change, which is the check working: the harness's notion of "the
            # writes this instruction reports" had drifted from the ABI's.
            writes = [effect for effect in (entry.get("effects") or [])
                      if effect.get("kind") in ("set", "setreg")]
            # Which *slots* the reported writes may touch. Counting writes
            # against changed registers worked while one write moved one slot,
            # and stopped the moment a register spanned limbs: writing `d1`
            # zeroes the upper half of `v1`, so two slots change for one
            # architectural write and the count said the instruction had
            # dropped something. The set is also a stronger check than the
            # count was -- it says *which* register went unreported, not just
            # that one did.
            written_slots = set()
            operand_kinds = {op["name"]: op["kind"] for op in entry["operands"]}
            for write in writes:
                if write.get("kind") == "setreg":
                    written_slots.add(write["index"])
                    continue
                dest = write.get("dest")
                if dest is None or dest not in fixture_index:
                    written_slots = None
                    break
                kind = operand_kinds.get(dest, "reg")
                base = axis_lift.register_slot(kind, fixture_index[dest])
                limbs = axis_lift.REGISTER_CLASSES[kind][6] or 1
                written_slots.update(range(base, base + limbs))
            unreported = (set(changed_regs) - written_slots
                          if written_slots is not None else set())
            if unreported:
                print(f"FAIL {mnemonic} changed {sorted(unreported)}, which no "
                      f"write reports; it reports {len(writes)} write(s) "
                      f"covering {sorted(written_slots)}")
                multi_write.append(mnemonic)
                break
            result = reference.get("result")
            trap = reference.get("trap")
            trap_id = TRAP_CAUSES.index(trap) + 1 if trap else 0
            extra = extra_write_checks(
                mnemonic, entry, writes, fixture_index, before, regs,
                axis_lift.register_slot, abi_bits)
            if extra is None:
                unchecked += 1
                continue
            # `out[0]` is a register slot, so a value wider than one carries
            # its low limb there and the rest in the slots after it. The
            # reference reports the whole value, which is the right thing for it
            # to report and the wrong thing to compare a slot against.
            if result is not None and result >= (1 << abi_bits):
                result &= (1 << abi_bits) - 1
            expected = [
                result if result is not None else 0,
                0 if result is None else 1,
                reference.get("next_pc", pc + 4),
                trap_id,
            ]
            # Only the bytes the case actually touched can differ, so compare
            # those explicitly plus a checksum over the whole image.
            changed = [
                (offset, byte)
                for offset, byte in enumerate(memory.data)
                if byte != seed_image[offset]
            ]
            checksum = sum(memory.data) & 0xFFFFFFFF

            declared[fn_name] = (
                sum(operand_limbs(operand, abi_bits)
                    if axis_lift.is_register_operand(operand["kind"]) else 1
                    for operand in inputs),
                abi_bits,
            )
            ctype = "uint64_t" if abi_bits == 64 else "uint32_t"
            suffix = "ull" if abi_bits == 64 else "u"
            hexfmt = "0x%016llx" if abi_bits == 64 else "0x%08x"
            cast = "(unsigned long long)" if abi_bits == 64 else ""
            plain = "%llu" if abi_bits == 64 else "%u"
            argument_text = "".join(f", {value}{suffix}" for value in values)
            state_text = ", ".join(f"{value}{suffix}" for value in state_values)
            # Only the slots this case actually changed are compared by name,
            # plus a sum over the whole array. Comparing all nine slots per case
            # generated a C driver so large that the gate went from 24 seconds
            # to over ten minutes, and the sum catches a write to a slot the
            # reference did not touch just as well.
            mask = (1 << abi_bits) - 1
            state_checks = "".join(
                f'    if (state[{slot}] != {state[name]}{suffix}) {{ printf('
                f'"FAIL {mnemonic} state {name} want 0x{state[name]:x}\\n"); '
                f"failures++; }}\n"
                for slot, (name, _) in enumerate(axis_lift.STATE_SLOTS)
                if state[name] != state_values[slot]
            )
            state_total = sum(state[name] for name, _ in axis_lift.STATE_SLOTS) & mask
            state_checks += (
                f'    if (state_total{abi_bits}(state) != {state_total}{suffix}) '
                f'{{ printf("FAIL {mnemonic} state image\\n"); failures++; }}\n'
            )
            state_widths.add(abi_bits)
            checks = "".join(
                f'    if (mem[{offset}] != {byte}u) {{ printf("FAIL {mnemonic} mem[{offset}]\\n"); failures++; }}\n'
                for offset, byte in changed
            )
            cases.setdefault(mnemonic, []).append(
                "  {\n"
                "    memcpy(mem, seed, MEM_BYTES);\n"
                f"    {ctype} out[{axis_lift.EFFECT_OUT_SLOTS}] = {{0}};\n"
                f"    {ctype} state[] = {{{state_text or '0'}}};\n"
                f"    {fn_name}((void *)mem, {pc}{suffix}, out, state{argument_text});\n"
                "    checks++;\n"
                + ("" if extra else
                   f'    if (out[0] != {expected[0]}{suffix}) {{ printf("FAIL {mnemonic} value {hexfmt} want 0x{expected[0]:x}\\n", {cast}out[0]); failures++; }}\n'
                   f'    if (out[1] != {expected[1]}{suffix}) {{ printf("FAIL {mnemonic} wrote {plain} want {expected[1]}\\n", {cast}out[1]); failures++; }}\n')
                + f'    if (out[2] != {expected[2]}{suffix}) {{ printf("FAIL {mnemonic} next_pc {hexfmt} want 0x{expected[2]:x}\\n", {cast}out[2]); failures++; }}\n'
                f'    if (out[3] != {expected[3]}{suffix}) {{ printf("FAIL {mnemonic} trap {plain} want {expected[3]}\\n", {cast}out[3]); failures++; }}\n'
                f"{extra}"
                f"{state_checks}"
                f"{checks}"
                f'    if (checksum(mem) != {checksum}u) {{ printf("FAIL {mnemonic} memory image\\n"); failures++; }}\n'
                "  }\n"
            )
            emitted += 1
        if emitted:
            covered.append(mnemonic)

    if not cases:
        print("SKIP: no effectful instructions with LLVM effect functions")
        return 0
    groups = "".join(
        f"static void check_{name.lower()}(int *checks, int *failures) {{\n"
        + "".join(block.replace("checks++", "(*checks)++")
                       .replace("failures++", "(*failures)++")
                  for block in blocks)
        + "}\n\n"
        for name, blocks in cases.items()
    )
    # ⚠️ Named before it runs, and flushed. Twelve thousand cases in one
    # binary, and when one of them takes the process down the buffered stdout
    # goes with it -- so this gate could report a bare FAIL with no way to tell
    # which instruction did it.
    calls = "".join(
        f'  fprintf(stderr, "AT {name}\\n");\n'
        f"  check_{name.lower()}(&checks, &failures);\n" for name in cases)

    # Exact prototypes: (memory, pc, out) plus one operand each, at the width
    # the emitted function actually uses.
    declarations = "\n".join(
        "extern void {name}(void *, {word}, {word} *, {word} *{operands});".format(
            name=name,
            word=("uint64_t" if abi_bits == 64 else "uint32_t"),
            operands="".join(
                ", uint64_t" if abi_bits == 64 else ", uint32_t" for _ in range(arity)
            ),
        )
        for name, (arity, abi_bits) in sorted(declared.items())
    )
    driver = workdir / "driver.c"
    driver.write_text(
        "#include <stdio.h>\n#include <stdint.h>\n#include <string.h>\n\n"
        f"#define MEM_BYTES {MEM_BYTES}\n"
        # ⚠️ Sixteen-aligned, and said rather than hoped. A 128-bit atomic --
        # `casp x0, x1, x4, x5, [x8]` -- faults on AArch64 unless its address
        # is 16-aligned, and the address here is `mem + rn`. Nothing asked for
        # the base to be aligned, so the gate passed for as long as the
        # compiler happened to pick 16, and one added line of debugging output
        # in the driver was enough to move it to 8 and take the process down.
        "static _Alignas(16) uint8_t mem[MEM_BYTES];\n"
        "static uint8_t seed[MEM_BYTES];\n\n"
        f"{declarations}\n\n"
        "static uint32_t checksum(const uint8_t *data) {\n"
        "  uint32_t total = 0;\n"
        "  for (int i = 0; i < MEM_BYTES; ++i) { total += data[i]; }\n"
        "  return total;\n}\n\n"
        # A helper rather than the sum spelled out in every case: nine inline
        # terms across twelve thousand cases is a driver clang spends minutes on.
        + "".join(
            f"static uint{bits}_t state_total{bits}(const uint{bits}_t *s) {{\n"
            f"  uint{bits}_t total = 0;\n"
            f"  for (int i = 0; i < {len(axis_lift.STATE_SLOTS)}; ++i) "
            "{ total += s[i]; }\n"
            "  return total;\n}\n\n"
            for bits in sorted(state_widths)
        )
        + groups
        + "int main(void) {\n  int checks = 0, failures = 0;\n"
        "  FILE *image = fopen(\"seed.bin\", \"rb\");\n"
        "  if (!image || fread(seed, 1, MEM_BYTES, image) != MEM_BYTES) { printf(\"seed image missing\\n\"); return 2; }\n"
        "  fclose(image);\n"
        + calls
        + '  printf("%d effect executions, %d failures\\n", checks, failures);\n'
        "  return failures == 0 ? 0 : 1;\n}\n"
    )
    (workdir / "seed.bin").write_bytes(seed_image)

    binary = workdir / "driver"
    subprocess.run(
        [args.clang, "-Wno-override-module", "-o", str(binary),
         str(driver), str(ll_path)],
        check=True,
    )
    result = subprocess.run([str(binary)], capture_output=True, text=True, cwd=workdir)
    print(result.stdout.strip())
    # ⚠️ Why it failed, not just that it did. A harness that dies on a signal
    # printed nothing at all and this gate reported a bare FAIL under a
    # thousand-mnemonic coverage line -- so the one thing a reader needed was
    # the one thing not said.
    if result.returncode != 0:
        print(f"the harness exited {result.returncode}"
              + (f": {result.stderr.strip()[:300]}" if result.stderr.strip() else ""))
    if skipped:
        print(f"withheld from LLVM IR (wide/state effects): {', '.join(sorted(set(skipped)))}")
    print(f"covered: {', '.join(covered)}")
    if unchecked:
        print(f"{unchecked} case(s) not checked: a secondary write targeted the "
              "zero register or the same register twice, so the executor's "
              "final register file does not identify each write")
    if multi_write:
        print(f"{len(set(multi_write))} multi-write instructions reached a "
              "single-write ABI: " + ", ".join(sorted(set(multi_write))))
    ok = result.returncode == 0 and not multi_write
    print("LLVM effects == python executor: PASS" if ok else
          "LLVM effects == python executor: FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
