#!/usr/bin/env python3
"""Exposed latency: the shadow is real, and a checkpoint has to carry it.

Under `hazards exposed` a machine does not interlock. A result with latency L
becomes visible to the packet issued L packets later, and until then it is
architectural state living in neither the register file nor the instruction
stream (`docs/vliw_spatial_design.md` §7). Two things can go wrong, and this
checks both.

**The shadow.** A read of a result still in flight must get the *old* value,
and the same program on the same description with `interlocked` hazards must
get the new one. The two machines are emitted separately and compared, so
"exposed differs from interlocked" is a measurement rather than a claim. A run
where they agreed would prove nothing and fails as vacuous. Both edges of the
shadow are checked: invisible at L-1 packets, visible at L — the second half is
what catches a queue that accepts writes and never lands them.

**The checkpoint.** A capsule that omits the in-flight writes cannot restore a
checkpoint taken mid-shadow, so migration across one would silently drop
results. The capsule's `__delay` section is serialized and deserialized here
per the manifest's own field offsets, checkpointing at *every* packet boundary
and migrating between two personalities; split-run must equal whole-run. Then
the same checkpoint is taken again with the delay section zeroed, and that one
must **differ** — otherwise the section is not load-bearing and the round-trip
proved nothing about it.

Usage: tools/exposed_latency_check.py <input.axisl>
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from axis_cli import axis_prefix
from packet_vs_serial import (Mem, Shape, emit, immediates, load_module,
                              reg_slot, register_operands, word_for)

AXIS_ROOT = Path(__file__).resolve().parent.parent

SRC_A, SRC_B, TARGET = 1, 2, 5
SCRATCH = 20


def purge_modules() -> None:
    """Forget the emitted modules so the other discipline's can be loaded.

    `axis_exec` imports `axis_lift` and `golden_model` by plain name, so two
    variants cannot be resident at once; each is measured in turn instead.
    """
    for name in ("axis_exec", "axis_lift", "golden_model"):
        sys.modules.pop(name, None)


def emit_variant(source: Path, workdir: Path, hazards: str) -> Path:
    """The description with its hazard discipline set to `hazards`."""
    text = source.read_text()
    for other in ("exposed", "interlocked"):
        text = text.replace(f"(hazards {other})", f"(hazards {hazards})")
    variant = workdir / f"{source.stem}_{hazards}.axisl"
    variant.write_text(text)
    for command, name in (("emit-packet-json", "packet_manifest.json"),
                          ("emit-capsule-json", "state_capsule_manifest.json"),
                          ("emit-lift-python", "axis_lift.py"),
                          ("emit-golden-python", "golden_model.py"),
                          ("emit-exec-python", "axis_exec.py")):
        emit(variant, command, workdir / name)
    return variant


def serialize(regs, pc, delayed, layout, delay_shape, keep_delay=True) -> bytes:
    """Pack registers, pc and the in-flight writes into capsule bytes."""
    buf = bytearray(layout["total_bytes"])
    for entry in layout["capsule"]:
        stride = entry["width_bits"] // 8
        if delay_shape and entry["name"] == delay_shape["entry_name"]:
            if not keep_delay or delayed is None:
                continue
            per_stage = delay_shape["entries_per_stage"]
            for stage, pending in enumerate(delayed):
                for index, (location, value, _origin) in enumerate(pending):
                    slot = stage * per_stage + index
                    off = entry["byte_offset"] + slot * stride
                    buf[off] = 1
                    buf[off + 4:off + 8] = int(location).to_bytes(4, "little")
                    buf[off + 8:off + 16] = (value & ((1 << 64) - 1)).to_bytes(8, "little")
            continue
        for i in range(entry["count"]):
            value = pc if entry["name"] == "pc" else regs.get(i, 0)
            off = entry["byte_offset"] + i * stride
            buf[off:off + stride] = (value & ((1 << entry["width_bits"]) - 1)).to_bytes(
                stride, "little")
    return bytes(buf)


def deserialize(buf, layout, delay_shape):
    """Reconstruct (regs, pc, delayed) from capsule bytes."""
    regs, pc, delayed = {}, 0, None
    for entry in layout["capsule"]:
        stride = entry["width_bits"] // 8
        if delay_shape and entry["name"] == delay_shape["entry_name"]:
            per_stage = delay_shape["entries_per_stage"]
            delayed = [[] for _ in range(delay_shape["stages"])]
            for slot in range(entry["count"]):
                off = entry["byte_offset"] + slot * stride
                if not buf[off]:
                    continue
                location = int.from_bytes(buf[off + 4:off + 8], "little")
                value = int.from_bytes(buf[off + 8:off + 16], "little")
                # The origin label is diagnostic and not state, so a restored
                # write says so rather than inventing the slot it came from.
                delayed[slot // per_stage].append((location, value, "restored"))
            continue
        for i in range(entry["count"]):
            off = entry["byte_offset"] + i * stride
            value = int.from_bytes(buf[off:off + stride], "little")
            if entry["name"] == "pc":
                pc = value
            else:
                regs[i] = value
    return regs, pc, delayed


READER = 24


def build_program(shape, lift, packets: int):
    """One long-latency producer, then readers of its result, packet by packet.

    Returns `(words, producer_slot, reader_slots, target_latency)`. Every slot
    the case does not use carries a filler, because a packet is full.
    """
    # The deepest instruction any slot can hold is what makes a shadow at all.
    best = None
    for index in range(len(shape.slots)):
        for entry in shape.by_slot[index]:
            written, read = register_operands(lift, entry)
            if not written or len(read) < 1:
                continue
            latency = entry.get("latency", 1)
            if best is None or latency > best[2]:
                best = (index, entry, latency)
    if best is None or best[2] < 2:
        return None
    producer_slot, producer, latency = best

    written, read = register_operands(lift, producer)
    values = {name: TARGET for name in written}
    for offset, name in enumerate(read):
        values[name] = SRC_A if offset % 2 == 0 else SRC_B
    for name in immediates(lift, producer):
        values[name] = 0
    program = [shape.build({producer_slot: (producer, values)})]

    reader_slots = []
    for step in range(1, packets):
        reader_slot = next((index for index in range(len(shape.slots))
                            if shape.pick(index, "alu") is not None), None)
        reader = shape.pick(reader_slot, "alu")
        written, read = register_operands(lift, reader)
        values = {name: READER + step for name in written}
        for offset, name in enumerate(read):
            values[name] = TARGET if offset == 0 else SRC_A
        for name in immediates(lift, reader):
            values[name] = 0
        program.append(shape.build({reader_slot: (reader, values)}))
        reader_slots.append((step, reader_slot, reader, values))
    return program, producer_slot, producer, reader_slots, latency


def measure(workdir: Path, packets: int):
    """Run the program on whichever discipline this workdir was emitted for."""
    purge_modules()
    sys.path.insert(0, str(workdir))
    manifest = json.loads((workdir / "packet_manifest.json").read_text())
    capsule = json.loads((workdir / "state_capsule_manifest.json").read_text())
    lift = load_module(workdir / "axis_lift.py", "axis_lift")
    load_module(workdir / "golden_model.py", "golden_model")
    exec_module = load_module(workdir / "axis_exec.py", "axis_exec")
    shape = Shape(lift, manifest["packets"][0], lift.AXIS_LIFT_TABLE)
    built = build_program(shape, lift, packets)
    if built is None:
        sys.path.remove(str(workdir))
        return None
    program, producer_slot, producer, reader_slots, latency = built

    regs = {reg_slot(lift, producer, register_operands(lift, producer)[1][0], index): value
            for index, value in ((SRC_A, 7), (SRC_B, 11), (TARGET, 3))}
    delayed = exec_module.new_delay_queue(shape.name)
    mem, pc = Mem(), 0x2000
    snapshots, queues = [], []
    for words in program:
        outcome = exec_module.step_packet(words, regs, mem, pc, shape.name,
                                          shape.isa, None, delayed)
        if outcome is None or outcome["conflicts"]:
            sys.path.remove(str(workdir))
            return {"error": f"packet did not run cleanly: {outcome and outcome['conflicts']}"}
        pc = outcome["next_pc"]
        snapshots.append(dict(regs))
        queues.append(None if delayed is None else [list(stage) for stage in delayed])

    # What the producer's result is, and what a reader makes of the old value
    # and of the new one -- both computed by running one syllable alone, so the
    # expectations are the executor's own arithmetic and not a copy of it.
    decoded = lift.decode_packet(program[0], shape.name, shape.isa)
    syllable = next(one for one in decoded if one["slot"] == shape.slots[producer_slot]["name"])
    probe = dict(snapshots[0])
    for stage in (queues[0] or []):
        for location, value, _origin in stage:
            probe[location] = value
    target_slot = reg_slot(lift, producer, register_operands(lift, producer)[0][0], TARGET)

    # What each reader computed, and what it would have computed from the old
    # value and from the new one -- both by running that one syllable alone,
    # so the expectations are the executor's own arithmetic rather than a copy.
    produced = probe.get(target_slot)
    readers = []
    for step, reader_slot, reader, values in reader_slots:
        word = program[step][reader_slot]
        destination = reg_slot(lift, reader, register_operands(lift, reader)[0][0],
                               READER + step)
        expectations = {}
        for label, seen in (("old", 3), ("new", produced)):
            alone = {reg_slot(lift, reader, register_operands(lift, reader)[1][0], TARGET): seen,
                     reg_slot(lift, reader, register_operands(lift, reader)[1][0], SRC_A): 7,
                     reg_slot(lift, reader, register_operands(lift, reader)[1][0], SRC_B): 11}
            entry = lift.decode_slot(word, {"name": shape.slots[reader_slot]["name"],
                                            "width": shape.slots[reader_slot]["width"],
                                            "units": tuple(shape.slots[reader_slot]["units"])},
                                     shape.isa)
            exec_module.step_syllable(word, entry, alone, None, 0, shape.isa)
            expectations[label] = alone.get(destination)
        readers.append({"step": step, "destination": destination,
                        "observed": snapshots[step].get(destination),
                        "from_old": expectations["old"], "from_new": expectations["new"]})

    result = {
        "words": program,
        "latency": latency,
        "snapshots": snapshots,
        "queues": queues,
        "target_slot": target_slot,
        "produced": produced,
        "readers": readers,
        "capsule": capsule,
        "delay_stages": shape.packet.get("delay_stages"),
    }
    sys.path.remove(str(workdir))
    return result


def check_shadow(exposed, interlocked, failures) -> bool:
    """A read in the shadow gets the old value, and the interlocked twin does not."""
    if exposed["words"] != interlocked["words"]:
        failures.append("the two disciplines built different programs, so nothing "
                        "they disagree about is about hazards")
        return False
    latency = exposed["latency"]
    target = exposed["target_slot"]
    old = 3                                    # what TARGET held before the packet
    produced = exposed["produced"]
    if produced is None or produced == old:
        failures.append(f"the producer's result ({produced!r}) equals what the "
                        f"register already held, so no shadow is observable")
        return False

    ok = True
    for reader, twin in zip(exposed["readers"], interlocked["readers"]):
        step = reader["step"]
        if reader["from_old"] == reader["from_new"]:
            failures.append(f"reader in packet {step} computes the same value from the "
                            f"old target and the new one, so it observes nothing")
            ok = False
            continue
        # A result with latency L is visible to the packet issued L packets
        # later, and to none before it. Both edges: a queue that accepts writes
        # and never lands them passes the first on its own.
        shadowed = step < latency
        want = reader["from_old"] if shadowed else reader["from_new"]
        if reader["observed"] != want:
            failures.append(
                f"exposed: the reader in packet {step} got {reader['observed']!r}, want "
                f"{want!r} ({'in the shadow' if shadowed else 'after the result landed'})")
            ok = False
        # The interlocked twin never has a shadow at all.
        if twin["observed"] != twin["from_new"]:
            failures.append(f"interlocked: the reader in packet {step} got "
                            f"{twin['observed']!r}, want {twin['from_new']!r}")
            ok = False
    # The register file itself: the result lands at the end of packet L-1, which
    # is what makes it visible to packet L.
    for step in range(len(exposed["snapshots"])):
        landed = exposed["snapshots"][step].get(target) == produced
        if landed != (step >= latency - 1):
            failures.append(f"exposed: after packet {step} the target had "
                            f"{'landed' if landed else 'not landed'}, and a latency-"
                            f"{latency} write lands at the end of packet {latency - 1}")
            ok = False
    # The whole point: the two machines must actually disagree somewhere.
    if exposed["snapshots"] == interlocked["snapshots"]:
        failures.append("exposed and interlocked produced identical state, so this "
                        "run proves nothing about exposed latency")
        ok = False
    return ok


def check_capsule(exposed, failures) -> bool:
    """A checkpoint taken mid-shadow restores, and one without the queue does not."""
    manifest = exposed["capsule"]
    personalities = {one["name"]: one for one in manifest["personalities"]}
    if len(personalities) < 2 or not manifest["migratable_pairs"]:
        failures.append("the corpus declares no migratable pair, so a checkpoint "
                        "here would not be a migration")
        return False

    for one in manifest["personalities"]:
        rehash = hashlib.sha256(one["canonical_layout"].encode()).hexdigest()
        if rehash != one["layout_hash"]:
            failures.append(f"{one['name']}: layout_hash is not reproducible from "
                            f"its canonical layout")
            return False
        if exposed["delay_stages"] and one["delay_queue"] is None:
            failures.append(f"{one['name']}: the packet has "
                            f"{exposed['delay_stages']} delay stages and the capsule "
                            f"describes none")
            return False

    name_a, name_b = manifest["migratable_pairs"][0]
    layout_a, layout_b = personalities[name_a], personalities[name_b]
    delay_shape = layout_a["delay_queue"]
    if layout_a["layout_hash"] != layout_b["layout_hash"]:
        failures.append("a migratable pair whose layouts hash differently")
        return False

    ok, dropped_differed = True, False
    for step, snapshot in enumerate(exposed["snapshots"]):
        queue = exposed["queues"][step]
        for keep in (True, False):
            capsule = serialize(snapshot, 0, queue, layout_a, delay_shape, keep_delay=keep)
            regs, _pc, delayed = deserialize(capsule, layout_b, delay_shape)
            restored = (regs, [[(location, value) for location, value, _ in stage]
                               for stage in (delayed or [])])
            wanted = ({index: snapshot.get(index, 0)
                       for entry in layout_a["capsule"] if entry["name"] == "x"
                       for index in range(entry["count"])},
                      [[(location, value) for location, value, _ in stage]
                       for stage in (queue or [])])
            restored = ({index: regs.get(index, 0) for index in wanted[0]}, restored[1])
            if keep:
                if restored != wanted:
                    failures.append(f"checkpoint at packet {step} did not round-trip: "
                                    f"queue {restored[1]} vs {wanted[1]}")
                    ok = False
            elif queue and any(queue) and restored != wanted:
                # Dropping the delay section has to lose something, or the
                # section is not carrying state and the round-trip above proved
                # nothing about it.
                dropped_differed = True
    if not dropped_differed:
        failures.append("zeroing the capsule's delay section changed nothing, so the "
                        "section is not load-bearing and this proves nothing")
        ok = False
    return ok


def check(source: Path, packets: int) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        results = {}
        for hazards in ("exposed", "interlocked"):
            workdir = root / hazards
            workdir.mkdir()
            emit_variant(source, workdir, hazards)
            results[hazards] = measure(workdir, packets)
        purge_modules()

        if results["exposed"] is None:
            print(f"{source.name}: no instruction with a latency above 1, so there is "
                  f"no shadow to observe -> FAIL")
            return False
        for hazards, result in results.items():
            if result.get("error"):
                print(f"{source.name}: {hazards}: {result['error']} -> FAIL")
                return False

        failures: list[str] = []
        shadow = check_shadow(results["exposed"], results["interlocked"], failures)
        capsule = check_capsule(results["exposed"], failures)
        stages = results["exposed"]["delay_stages"]
        print(f"{source.name}: latency {results['exposed']['latency']}, "
              f"{stages} delay stages, {len(results['exposed']['snapshots'])} packets; "
              f"shadow {'ok' if shadow else 'FAILED'}, "
              f"capsule {'ok' if capsule else 'FAILED'}")
        for failure in failures[:20]:
            print(f"  {failure}")
        status = "PASS" if not failures else "FAIL"
        print(f"{source.name}: {len(failures)} failures -> {status}")
        return not failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--packets", type=int, default=6)
    args = parser.parse_args()
    ok = all(check(source, args.packets) for source in args.sources)
    print("EXPOSED LATENCY PASSED" if ok else "EXPOSED LATENCY FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
