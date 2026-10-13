//! AXIS emit: mapping manifest (VLIW/CGRA design stage G2).
//!
//! `mapping_manifest.json` (`axis.mapping.v1`) carries the placement, the
//! routes and the initiation interval — and the **modulo occupancy tables the
//! validator computed**, published rather than left to be re-derived.
//!
//! Publishing them is the point. Legality of a modulo schedule is entirely
//! "nothing is used twice in one steady-state cycle", and a consumer that
//! recomputed `cycle mod ii` itself would be a second derivation of the one
//! fact the validator already decided. A mapper reading this file can see
//! which PE and which link its schedule occupies at each residue without
//! trusting its own arithmetic to agree with the checker that accepted it.

use super::common::*;

pub fn emit_mapping_manifest_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.mapping.v1\",");
    // The channels a route may name. Emitted only when a document declares
    // one, so a description with no elastic anything produces the bytes it
    // produced before channels existed -- the invariant every stage of this
    // work has kept (`vliw_spatial_design.md` §11).
    if !document.channels.is_empty() {
        line(&mut out, 1, "\"channels\": [");
        let count = document.channels.len();
        for (index, channel) in document.channels.iter().enumerate() {
            let comma = if index + 1 == count { "" } else { "," };
            line(
                &mut out,
                2,
                &format!(
                    "{{\"name\": {}, \"protocol\": {}, \"latency_min\": {}, \
                     \"latency_max\": {}, \"capacity\": {}, \"order\": {}, \
                     \"initial\": {}}}{comma}",
                    json_string(&channel.name),
                    json_string(&channel.protocol),
                    channel.latency_min,
                    channel.latency_max,
                    channel.capacity,
                    json_string(&channel.order),
                    channel.initial
                ),
            );
        }
        line(&mut out, 1, "],");
    }
    if document.mappings.is_empty() {
        line(&mut out, 1, "\"mappings\": []");
        out.push_str("}\n");
        return out;
    }
    line(&mut out, 1, "\"mappings\": [");
    let mapping_count = document.mappings.len();
    for (mapping_index, mapping) in document.mappings.iter().enumerate() {
        line(&mut out, 2, "{");
        line(&mut out, 3, &format!("\"name\": {},", json_string(&mapping.name)));
        line(&mut out, 3, &format!("\"fabric\": {},", json_string(&mapping.fabric)));
        line(&mut out, 3, &format!("\"ii\": {},", mapping.ii));
        let order = mapping
            .equivalent_to
            .iter()
            .map(|id| json_string(id))
            .collect::<Vec<_>>()
            .join(", ");
        line(&mut out, 3, &format!("\"scalar_order\": [{order}],"));

        line(&mut out, 3, "\"place\": [");
        let op_count = mapping.ops.len();
        for (index, op) in mapping.ops.iter().enumerate() {
            let comma = if index + 1 == op_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"id\": {}, \"mnemonic\": {}, \"pe\": [{}, {}], \"cycle\": {}, \
                     \"residue\": {}}}{comma}",
                    json_string(&op.id),
                    json_string(&op.mnemonic),
                    op.row,
                    op.col,
                    op.cycle,
                    op.cycle % mapping.ii
                ),
            );
        }
        line(&mut out, 3, "],");

        // Where the values come from and where the result is left. Emitted
        // only when the mapping says, so a mapping proven as a dataflow reads
        // exactly as it did.
        if !mapping.live_in.is_empty() {
            line(&mut out, 3, "\"live_in\": [");
            for (index, live) in mapping.live_in.iter().enumerate() {
                let comma = if index + 1 == mapping.live_in.len() { "" } else { "," };
                let source = match &live.source {
                    crate::ast::MappingSource::Register(index) => {
                        format!("\"kind\": \"reg\", \"index\": {index}")
                    }
                    crate::ast::MappingSource::Constant(value) => {
                        format!("\"kind\": \"const\", \"value\": {value}")
                    }
                };
                line(
                    &mut out,
                    4,
                    &format!(
                        "{{\"op\": {}, \"operand\": {}, {source}}}{comma}",
                        json_string(&live.op),
                        json_string(&live.operand)
                    ),
                );
            }
            line(&mut out, 3, "],");
        }
        if !mapping.live_out.is_empty() {
            line(&mut out, 3, "\"live_out\": [");
            for (index, live) in mapping.live_out.iter().enumerate() {
                let comma = if index + 1 == mapping.live_out.len() { "" } else { "," };
                line(
                    &mut out,
                    4,
                    &format!(
                        "{{\"op\": {}, \"register\": {}}}{comma}",
                        json_string(&live.op),
                        live.register
                    ),
                );
            }
            line(&mut out, 3, "],");
        }
        line(&mut out, 3, "\"route\": [");
        let route_count = mapping.routes.len();
        for (index, route) in mapping.routes.iter().enumerate() {
            let via = route
                .via
                .iter()
                .map(|(row, col)| format!("[{row}, {col}]"))
                .collect::<Vec<_>>()
                .join(", ");
            let comma = if index + 1 == route_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"from\": {}, \"to\": {}, \"operand\": {}, \"via\": [{via}], \
                     \"cycle\": {}, \"distance\": {}, \"channel\": {}}}{comma}",
                    json_string(&route.from),
                    json_string(&route.to),
                    json_string(&route.operand),
                    route.cycle,
                    route.distance,
                    json_string(&route.channel)
                ),
            );
        }
        line(&mut out, 3, "],");

        // The occupancy the validator decided legality on. A PE entry is a
        // position and the residue it is busy at; a link entry is an edge and
        // the residue a value is crossing it at.
        let fabric = document
            .fabrics
            .iter()
            .find(|fabric| fabric.name == mapping.fabric);
        line(&mut out, 3, "\"pe_occupancy\": [");
        let op_count = mapping.ops.len();
        for (index, op) in mapping.ops.iter().enumerate() {
            let comma = if index + 1 == op_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"pe\": [{}, {}], \"residue\": {}, \"op\": {}}}{comma}",
                    op.row,
                    op.col,
                    op.cycle % mapping.ii,
                    json_string(&op.id)
                ),
            );
        }
        line(&mut out, 3, "],");

        // How many configurations each PE is asked to hold: one per operation
        // placed on it. Published beside the occupancy because it is the other
        // resource a mapping spends, and the one a single-context fabric runs
        // out of first.
        let mut configurations: Vec<((u32, u32), usize)> = Vec::new();
        for op in &mapping.ops {
            match configurations
                .iter_mut()
                .find(|(position, _)| *position == (op.row, op.col))
            {
                Some((_, count)) => *count += 1,
                None => configurations.push(((op.row, op.col), 1)),
            }
        }
        line(&mut out, 3, "\"pe_configurations\": [");
        let configuration_count = configurations.len();
        for (index, ((row, col), count)) in configurations.iter().enumerate() {
            let comma = if index + 1 == configuration_count { "" } else { "," };
            line(
                &mut out,
                4,
                &format!("{{\"pe\": [{row}, {col}], \"configurations\": {count}}}{comma}"),
            );
        }
        line(&mut out, 3, "],");

        line(&mut out, 3, "\"link_occupancy\": [");
        let mut entries: Vec<String> = Vec::new();
        for route in &mapping.routes {
            // An elastic route occupies no residue: its arrival is a window,
            // and the validator exempted it from the modulo rule for that
            // reason. Publishing a residue for it would put a number in the
            // table that legality was never decided on -- which is the one
            // thing this manifest exists not to do.
            if !route.channel.is_empty() {
                continue;
            }
            let mut flight = 0u32;
            for pair in route.via.windows(2) {
                let (from, to) = (pair[0], pair[1]);
                let latency = fabric
                    .and_then(|fabric| {
                        fabric.links.iter().find(|link| {
                            (link.from_row, link.from_col, link.to_row, link.to_col)
                                == (from.0, from.1, to.0, to.1)
                        })
                    })
                    .map(|link| link.latency)
                    .unwrap_or(1);
                entries.push(format!(
                    "{{\"link\": [[{}, {}], [{}, {}]], \"residue\": {}, \"route\": {}}}",
                    from.0,
                    from.1,
                    to.0,
                    to.1,
                    (route.cycle + flight) % mapping.ii,
                    json_string(&format!("{} -> {}", route.from, route.to))
                ));
                flight += latency;
            }
        }
        let entry_count = entries.len();
        for (index, entry) in entries.iter().enumerate() {
            let comma = if index + 1 == entry_count { "" } else { "," };
            line(&mut out, 4, &format!("{entry}{comma}"));
        }
        line(&mut out, 3, "]");
        let comma = if mapping_index + 1 == mapping_count {
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
