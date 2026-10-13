//! AXIS emit: fabric manifest (VLIW/CGRA design stage G1).
//!
//! `fabric_manifest.json` (`axis.fabric.v1`) carries the PE grid, the unit
//! classes every PE holds, and the link graph with its latencies — the edges
//! **expanded**, so a consumer reads one list and never has to know whether an
//! edge came from a compass pattern or an explicit declaration.
//!
//! Publishing the expansion rather than the pattern is the point. A mapper
//! that re-derived `(north 1)` into edges would be a second derivation of the
//! grid, and the two would disagree about the boundary — a mesh's edge PEs
//! have fewer neighbours, and which ones is exactly the sort of off-by-one a
//! second implementation gets wrong.

use super::common::*;

pub fn emit_fabric_manifest_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.fabric.v1\",");
    if document.fabrics.is_empty() {
        line(&mut out, 1, "\"fabrics\": []");
        out.push_str("}\n");
        return out;
    }
    line(&mut out, 1, "\"fabrics\": [");
    let fabric_count = document.fabrics.len();
    for (fabric_index, fabric) in document.fabrics.iter().enumerate() {
        line(&mut out, 2, "{");
        line(&mut out, 3, &format!("\"name\": {},", json_string(&fabric.name)));
        line(&mut out, 3, &format!("\"rows\": {},", fabric.rows));
        line(&mut out, 3, &format!("\"cols\": {},", fabric.cols));
        line(&mut out, 3, &format!("\"pes\": {},", fabric.rows * fabric.cols));
        line(&mut out, 3, &format!("\"regs\": {},", fabric.regs));
        line(&mut out, 3, &format!("\"consts\": {},", fabric.consts));
        line(&mut out, 3, &format!("\"ii_max\": {},", fabric.ii_max));
        line(&mut out, 3, &format!("\"contexts\": {},", fabric.contexts));
        // Every unit held anywhere on the grid. On a uniform fabric that is the
        // one list there has ever been; on a heterogeneous one it is a
        // capability summary, and `rows` below is what a mapper must read.
        let units = fabric
            .all_units()
            .iter()
            .map(|unit| json_string(&canonical_unit(unit)))
            .collect::<Vec<_>>()
            .join(", ");
        line(&mut out, 3, &format!("\"units\": [{units}],"));

        // Every instruction a PE of this fabric can issue, by the same unit
        // resolution a packet slot uses. Published so a mapper checking
        // "is this operation placeable here" reads the answer rather than
        // recomputing it from two tables.
        let mut issuable: Vec<&str> = document
            .instructions
            .iter()
            .filter(|instruction| {
                let unit = canonical_unit(&instruction.unit);
                !unit.is_empty()
                    && fabric
                        .all_units()
                        .iter()
                        .any(|held| canonical_unit(held) == unit)
            })
            .map(|instruction| instruction.mnemonic.as_str())
            .collect();
        issuable.sort_unstable();
        let issuable = issuable
            .iter()
            .map(|mnemonic| json_string(mnemonic))
            .collect::<Vec<_>>()
            .join(", ");
        line(&mut out, 3, &format!("\"issuable\": [{issuable}],"));

        // Per-row detail, where the rows differ. A mapper that reads only the
        // fabric-wide lists above would place a multiply on a row of plain
        // ALUs, so a heterogeneous fabric says row by row what it holds and
        // what may issue there. Absent entirely when every PE is the same, so
        // a uniform fabric's manifest is unchanged.
        // The shared row, when there is one. A consumer that reads the grid
        // and the packet separately would take them for two machines; this is
        // what says they are one, and which row is the seam.
        // Which mode this fabric runs in. A consumer scheduling both halves
        // needs to know they are exclusive, and the seam alone does not say it.
        if !fabric.mode.is_empty() {
            line(&mut out, 3, &format!("\"mode\": {},", json_string(&fabric.mode)));
        }
        if let Some((row, packet)) = &fabric.vliw_row {
            line(&mut out, 3, "\"vliw_row\": {");
            line(&mut out, 4, &format!("\"row\": {row},"));
            line(&mut out, 4, &format!("\"packet\": {}", json_string(packet)));
            line(&mut out, 3, "},");
        }
        if !fabric.pe_rows.is_empty() || fabric.vliw_row.is_some() {
            line(&mut out, 3, "\"rows_detail\": [");
            let shared = fabric.vliw_row.as_ref().and_then(|(_, name)| {
                document.packets.iter().find(|packet| &packet.name == name)
            });
            for row in 0..fabric.rows {
                // A shared row is heterogeneous *across* its columns, because
                // its PEs are slots, so it is reported per PE rather than once.
                if let (Some((seam, _)), Some(packet)) = (&fabric.vliw_row, shared) {
                    if *seam == row {
                        for col in 0..fabric.cols {
                            let units: Vec<String> = fabric
                                .units_at_pe(row, col, Some(packet))
                                .iter()
                                .map(|unit| json_string(&canonical_unit(unit)))
                                .collect();
                            let slot = packet
                                .slots
                                .get(col as usize)
                                .map(|slot| slot.name.as_str())
                                .unwrap_or("");
                            line(&mut out, 4, "{");
                            line(&mut out, 5, &format!("\"row\": {row},"));
                            line(&mut out, 5, &format!("\"col\": {col},"));
                            line(&mut out, 5, &format!("\"slot\": {},", json_string(slot)));
                            line(&mut out, 5, &format!("\"units\": [{}]", units.join(", ")));
                            line(&mut out, 4, "},");
                        }
                        continue;
                    }
                }
                let held: Vec<String> = fabric
                    .units_at(row)
                    .iter()
                    .map(|unit| json_string(&canonical_unit(unit)))
                    .collect();
                let mut here: Vec<&str> = document
                    .instructions
                    .iter()
                    .filter(|instruction| {
                        let unit = canonical_unit(&instruction.unit);
                        !unit.is_empty()
                            && fabric
                                .units_at(row)
                                .iter()
                                .any(|holds| canonical_unit(holds) == unit)
                    })
                    .map(|instruction| instruction.mnemonic.as_str())
                    .collect();
                here.sort_unstable();
                let here = here
                    .iter()
                    .map(|mnemonic| json_string(mnemonic))
                    .collect::<Vec<_>>()
                    .join(", ");
                let comma = if row + 1 == fabric.rows { "" } else { "," };
                line(&mut out, 4, "{");
                line(&mut out, 5, &format!("\"row\": {row},"));
                line(&mut out, 5, &format!("\"units\": [{}],", held.join(", ")));
                line(&mut out, 5, &format!("\"regs\": {},", fabric.regs_at(row)));
                line(&mut out, 5, &format!("\"consts\": {},", fabric.consts_at(row)));
                line(&mut out, 5, &format!("\"issuable\": [{here}]"));
                line(&mut out, 4, &format!("}}{comma}"));
            }
            line(&mut out, 3, "],");
        }

        line(&mut out, 3, "\"memory_ports\": [");
        let port_count = fabric.ports.len();
        for (index, port) in fabric.ports.iter().enumerate() {
            let comma = if index + 1 == port_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"row\": {}, \"memory\": {}}}{comma}",
                    port.row,
                    json_string(&port.memory)
                ),
            );
        }
        line(&mut out, 3, "],");

        line(&mut out, 3, "\"links\": [");
        let link_count = fabric.links.len();
        for (index, link) in fabric.links.iter().enumerate() {
            let comma = if index + 1 == link_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"from\": [{}, {}], \"to\": [{}, {}], \"latency\": {}, \
                     \"direction\": {}}}{comma}",
                    link.from_row,
                    link.from_col,
                    link.to_row,
                    link.to_col,
                    link.latency,
                    json_string(&link.direction)
                ),
            );
        }
        line(&mut out, 3, "]");
        let comma = if fabric_index + 1 == fabric_count {
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
