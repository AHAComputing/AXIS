//! AXIS emit: issue-packet manifest (VLIW/CGRA design stage B1).
//!
//! `packet_manifest.json` (`axis.issue-packet.v1`) carries each declared
//! packet's slots — width, bit offset in the container, and the functional-unit
//! classes the slot holds — together with, per slot-legal instruction, the
//! `match`/`mask` the decoder uses.
//!
//! Publishing the encoding alongside the slot is the point: a packetizer and a
//! decoder built from this file read one table, so the position a syllable may
//! occupy and the bits that identify it cannot drift apart.

use super::common::*;

pub fn emit_packet_manifest_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.issue-packet.v1\",");
    if document.packets.is_empty() {
        // Packet-free documents keep the emitter total rather than absent, so a
        // consumer reads an empty list instead of guessing from a missing file.
        line(&mut out, 1, "\"packets\": []");
        out.push_str("}\n");
        return out;
    }
    line(&mut out, 1, "\"packets\": [");
    let packet_count = document.packets.len();
    for (packet_index, packet) in document.packets.iter().enumerate() {
        line(&mut out, 2, "{");
        line(&mut out, 3, &format!("\"name\": {},", json_string(&packet.name)));
        line(&mut out, 3, &format!("\"isa\": {},", json_string(&packet.isa)));
        // The mode this packet issues in, when it says. A fabric sharing its
        // slots names a different one, and a scheduler reading only one of the
        // two manifests would not know the other exists.
        if !packet.mode.is_empty() {
            line(&mut out, 3, &format!("\"mode\": {},", json_string(&packet.mode)));
        }
        line(&mut out, 3, &format!("\"order\": {},", json_string(&packet.order)));
        line(&mut out, 3, &format!("\"end\": {},", json_string(&packet.end)));
        line(&mut out, 3, &format!("\"stop_bit\": {},", packet.stop_bit));
        line(&mut out, 3, &format!("\"hazards\": {},", json_string(&packet.hazards)));
        line(&mut out, 3, &format!("\"branches\": {},", json_string(&packet.branches)));
        line(&mut out, 3, &format!("\"syllables\": {},", packet.slots.len()));
        // The delay queue an exposed packet carries, derived once in
        // `validate::packet_delay_queue` and read here, by the executor's
        // packet table, and by the capsule's `__delay` section.
        let delay = crate::validate::packet_delay_queue(document, packet);
        line(
            &mut out,
            3,
            &format!(
                "\"delay_stages\": {},",
                delay.as_ref().map(|delay| delay.stages).unwrap_or(0)
            ),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"delay_entries_per_stage\": {},",
                delay
                    .as_ref()
                    .map(|delay| delay.entries_per_stage)
                    .unwrap_or(0)
            ),
        );
        line(
            &mut out,
            3,
            &format!("\"container_bits\": {},", packet.container_bits()),
        );
        line(&mut out, 3, "\"slots\": [");
        let mut bit_offset = 0u32;
        let slot_count = packet.slots.len();
        for (slot_index, slot) in packet.slots.iter().enumerate() {
            let units = slot
                .units
                .iter()
                .map(|unit| json_string(&canonical_unit(unit)))
                .collect::<Vec<_>>()
                .join(", ");
            let comma = if slot_index + 1 == slot_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"index\": {slot_index}, \"name\": {}, \"width\": {}, \
                     \"bit_offset\": {bit_offset}, \"units\": [{units}]}}{comma}",
                    json_string(&slot.name),
                    slot.width
                ),
            );
            bit_offset += slot.width;
        }
        line(&mut out, 3, "],");

        line(&mut out, 3, "\"instructions\": [");
        let issuable: Vec<&Instruction> = document
            .instructions
            .iter()
            .filter(|instruction| packet_issues(packet, instruction))
            .collect();
        let issuable_count = issuable.len();
        for (index, instruction) in issuable.iter().enumerate() {
            let unit = canonical_unit(&instruction.unit);
            let slots = packet
                .slots_for_unit(&unit)
                .iter()
                .map(|slot| slot.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            let layout = layout_for(document, instruction);
            let comma = if index + 1 == issuable_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"mnemonic\": {}, \"unit\": {}, \"slots\": [{slots}], \
                     \"match\": {}, \"mask\": {}}}{comma}",
                    json_string(&instruction.mnemonic),
                    json_string(&unit),
                    json_hex_u32(layout.match_value),
                    json_hex_u32(layout.mask_value)
                ),
            );
        }
        line(&mut out, 3, "]");
        let comma = if packet_index + 1 == packet_count {
            ""
        } else {
            ","
        };
        line(&mut out, 2, &format!("}}{comma}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

/// Whether this packet can issue this instruction: same instruction space, and
/// some slot holds its unit.
fn packet_issues(packet: &Packet, instruction: &Instruction) -> bool {
    let space = packet.isa.trim().is_empty()
        || instruction.isa.trim().is_empty()
        || packet.isa.eq_ignore_ascii_case(&instruction.isa);
    let unit = canonical_unit(&instruction.unit);
    space && !unit.is_empty() && !packet.slots_for_unit(&unit).is_empty()
}

/// AXIS emit: VLIW itinerary manifest (design stage B4).
///
/// `packet_schedule_manifest.json` (`axis.vliw-itinerary.v1`) is the resource
/// table an LLVM `SchedMachineModel` / `DFAPacketizer` consumes: the functional
/// units, how many issue slots hold each, and per instruction the slot mask it
/// may occupy along with its latency.
///
/// It is emitted from the same slot and unit resolution as
/// `emit_packet_manifest_json`, for the reason that file exists at all: a
/// scheduler and a decoder built from two derivations of the slot table would
/// drift, and the drift would show up as a packet the compiler emits and the
/// machine rejects.
///
/// The slot *mask* is the load-bearing field. Whether a group of instructions
/// can issue together is not "are there enough slots" -- it is whether the
/// instructions can be matched to distinct slots each of which holds that
/// instruction's unit. Publishing per-unit counts alone would call a group of
/// two `mul`s legal on a machine with three ALUs and one multiplier.
pub fn emit_vliw_itinerary_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.vliw-itinerary.v1\",");
    if document.packets.is_empty() {
        line(&mut out, 1, "\"packets\": []");
        out.push_str("}\n");
        return out;
    }
    line(&mut out, 1, "\"packets\": [");
    let packet_count = document.packets.len();
    for (packet_index, packet) in document.packets.iter().enumerate() {
        line(&mut out, 2, "{");
        line(&mut out, 3, &format!("\"name\": {},", json_string(&packet.name)));
        line(&mut out, 3, &format!("\"isa\": {},", json_string(&packet.isa)));
        line(
            &mut out,
            3,
            &format!("\"issue_width\": {},", packet.slots.len()),
        );
        line(
            &mut out,
            3,
            &format!("\"hazards\": {},", json_string(&packet.hazards)),
        );
        line(
            &mut out,
            3,
            &format!("\"branches\": {},", json_string(&packet.branches)),
        );
        let delay = crate::validate::packet_delay_queue(document, packet);
        line(
            &mut out,
            3,
            &format!(
                "\"delay_stages\": {},",
                delay.as_ref().map(|delay| delay.stages).unwrap_or(0)
            ),
        );

        // Every unit some slot holds, with the slots that hold it. The count is
        // how many of that unit can issue in one packet only when no slot holds
        // two units; the mask is what stays true either way.
        let mut units: Vec<String> = Vec::new();
        for slot in &packet.slots {
            for unit in &slot.units {
                let unit = canonical_unit(unit);
                if !units.contains(&unit) {
                    units.push(unit);
                }
            }
        }
        units.sort();
        line(&mut out, 3, "\"functional_units\": [");
        let unit_count = units.len();
        for (index, unit) in units.iter().enumerate() {
            let slots = packet.slots_for_unit(unit);
            let mask = slot_mask(&slots);
            let comma = if index + 1 == unit_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"name\": {}, \"slot_mask\": {}, \"count\": {}}}{comma}",
                    json_string(unit),
                    json_hex_u32(mask),
                    slots.len()
                ),
            );
        }
        line(&mut out, 3, "],");

        line(&mut out, 3, "\"itineraries\": [");
        let issuable: Vec<&Instruction> = document
            .instructions
            .iter()
            .filter(|instruction| packet_issues(packet, instruction))
            .collect();
        let issuable_count = issuable.len();
        for (index, instruction) in issuable.iter().enumerate() {
            let unit = canonical_unit(&instruction.unit);
            let mask = slot_mask(&packet.slots_for_unit(&unit));
            // Read from the behavior, the same way `validate` decides whether
            // two slots may both branch -- not from the category or the
            // mnemonic, which say what an instruction is called rather than
            // what it does.
            let (_, writes_pc) = crate::validate::fixed_write_locations(instruction);
            let comma = if index + 1 == issuable_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"mnemonic\": {}, \"unit\": {}, \"slot_mask\": {}, \
                     \"latency\": {}, \"branches\": {}}}{comma}",
                    json_string(&instruction.mnemonic),
                    json_string(&unit),
                    json_hex_u32(mask),
                    instruction.latency_cycles,
                    literals_boolean(writes_pc)
                ),
            );
        }
        line(&mut out, 3, "]");
        let comma = if packet_index + 1 == packet_count {
            ""
        } else {
            ","
        };
        line(&mut out, 2, &format!("}}{comma}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

/// Slots as a bitmask, which is how a DFA packetizer indexes a resource class.
fn slot_mask(slots: &[usize]) -> u32 {
    slots.iter().fold(0u32, |mask, slot| mask | (1u32 << slot))
}

fn literals_boolean(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}
