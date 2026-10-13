//! AXIS emit: state-capsule manifest (personality design stage P1).
//!
//! `state_capsule_manifest.json` pins, per personality, the canonical byte
//! layout of its portable architectural state, hashed as `layout_hash` so
//! every consumer (RTL checkpoint logic, cosim harnesses, `axis_exec`
//! wrappers) matches the format by hash rather than by convention.

use super::common::*;
use crate::capsule::{
    canonical_layout, layout_hash, layouts_migratable, resolve_capsule, CapsuleLayout,
};

fn emit_seams(out: &mut String, key: &str, seams: &[crate::ast::PersonalitySeam]) {
    if seams.is_empty() {
        return;
    }
    line(out, 3, &format!("\"{key}\": ["));
    let count = seams.len();
    for (index, seam) in seams.iter().enumerate() {
        let comma = if index + 1 == count { "" } else { "," };
        let side = if key == "exports" {
            format!("\"unit\": {}", json_string(&seam.unit))
        } else {
            format!("\"from\": {}", json_string(&seam.from))
        };
        line(
            out,
            4,
            &format!(
                "{{\"name\": {}, {side}, \"channel\": {}}}{comma}",
                json_string(&seam.name),
                json_string(&seam.channel)
            ),
        );
    }
    line(out, 3, "],");
}

pub fn emit_state_capsule_manifest_json(document: &Document) -> String {
    let resolved: Vec<(&Personality, Option<CapsuleLayout>)> = document
        .personalities
        .iter()
        .map(|personality| {
            let layout = document
                .isas
                .iter()
                .find(|isa| isa.name.eq_ignore_ascii_case(&personality.implements))
                .and_then(|isa| {
                    resolve_capsule(
                        isa,
                        personality,
                        crate::validate::personality_delay_queue(document, personality).as_ref(),
                    )
                    .ok()
                });
            (personality, layout)
        })
        .collect();

    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.state-capsule.v1\",");
    line(&mut out, 1, "\"personalities\": [");
    let count = resolved.len();
    for (idx, (personality, layout)) in resolved.iter().enumerate() {
        let last = idx + 1 == count;
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"name\": {},", json_string(&personality.name)),
        );
        line(
            &mut out,
            3,
            &format!("\"implements\": {},", json_string(&personality.implements)),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"description\": {},",
                json_string(&personality.description)
            ),
        );
        line(&mut out, 3, "\"discipline\": {");
        line(
            &mut out,
            4,
            &format!("\"kind\": {},", json_string(&personality.discipline.kind)),
        );
        let params = personality
            .discipline
            .params
            .iter()
            .map(|(key, value)| format!("{}: {value}", json_string(key)))
            .collect::<Vec<_>>()
            .join(", ");
        line(&mut out, 4, &format!("\"params\": {{{params}}}"));
        line(&mut out, 3, "},");
        // The seams this personality lends and borrows (P5 / G4b.3). Emitted
        // only when there are any, so every manifest produced before seams
        // existed stays byte-identical. Each side names its own channel; the
        // channel's contract is published once, in the mapping manifest, and a
        // consumer joins the two rather than reading two copies that can drift.
        emit_seams(&mut out, "exports", &personality.exports);
        emit_seams(&mut out, "imports", &personality.imports);
        match layout {
            Some(layout) => {
                line(&mut out, 3, "\"capsule\": [");
                let entries = layout.entries.len();
                for (entry_idx, entry) in layout.entries.iter().enumerate() {
                    let comma = if entry_idx + 1 == entries { "" } else { "," };
                    line(
                        &mut out,
                        4,
                        &format!(
                            "{{\"name\": {}, \"count\": {}, \"width_bits\": {}, \"byte_offset\": {}}}{comma}",
                            json_string(&entry.name),
                            entry.count,
                            entry.width_bits,
                            entry.byte_offset
                        ),
                    );
                }
                line(&mut out, 3, "],");
                line(
                    &mut out,
                    3,
                    &format!("\"total_bytes\": {},", layout.total_bytes),
                );
                line(
                    &mut out,
                    3,
                    &format!(
                        "\"canonical_layout\": {},",
                        json_string(&canonical_layout(layout))
                    ),
                );
                line(
                    &mut out,
                    3,
                    &format!("\"layout_hash\": {},", json_string(&layout_hash(layout))),
                );
                // What the `__delay` bytes mean. Without this a consumer sees a
                // 128-bit register group with a strange name and has to guess,
                // and guessing a checkpoint ABI is the failure this manifest
                // exists to prevent.
                match crate::validate::personality_delay_queue(document, personality) {
                    Some(delay) if delay.stages > 0 && delay.entries_per_stage > 0 => {
                        line(&mut out, 3, "\"delay_queue\": {");
                        line(&mut out, 4, &format!("\"stages\": {},", delay.stages));
                        line(
                            &mut out,
                            4,
                            &format!("\"entries_per_stage\": {},", delay.entries_per_stage),
                        );
                        line(
                            &mut out,
                            4,
                            &format!("\"entry_bytes\": {},", crate::capsule::DELAY_ENTRY_BYTES),
                        );
                        line(
                            &mut out,
                            4,
                            &format!("\"entry_name\": {},", json_string(crate::capsule::DELAY_ENTRY_NAME)),
                        );
                        line(&mut out, 4, "\"fields\": [");
                        line(&mut out, 5, "{\"name\": \"valid\", \"byte_offset\": 0, \"bytes\": 1},");
                        line(&mut out, 5, "{\"name\": \"reserved\", \"byte_offset\": 1, \"bytes\": 3},");
                        line(&mut out, 5, "{\"name\": \"location\", \"byte_offset\": 4, \"bytes\": 4},");
                        line(&mut out, 5, "{\"name\": \"value\", \"byte_offset\": 8, \"bytes\": 8}");
                        line(&mut out, 4, "],");
                        line(
                            &mut out,
                            4,
                            "\"note\": \"stage k holds the writes committing after k+1 more packet ends\"",
                        );
                        line(&mut out, 3, "}");
                    }
                    // An exposed machine whose every latency is 1 has no
                    // shadow, so it has no queue and its capsule is an
                    // interlocked one — which is the truth about how it runs.
                    _ => line(&mut out, 3, "\"delay_queue\": null"),
                }
            }
            None => {
                // Validation refuses unresolvable capsules; keep the emitter
                // total for direct library use.
                line(&mut out, 3, "\"capsule\": [],");
                line(&mut out, 3, "\"total_bytes\": 0,");
                line(&mut out, 3, "\"canonical_layout\": \"\",");
                line(&mut out, 3, "\"layout_hash\": \"\",");
                line(&mut out, 3, "\"delay_queue\": null");
            }
        }
        line(&mut out, 2, &format!("}}{}", if last { "" } else { "," }));
    }
    line(&mut out, 1, "],");

    line(&mut out, 1, "\"migratable_pairs\": [");
    let mut pairs = Vec::new();
    for (idx, (personality_a, layout_a)) in resolved.iter().enumerate() {
        for (personality_b, layout_b) in resolved.iter().skip(idx + 1) {
            if let (Some(layout_a), Some(layout_b)) = (layout_a, layout_b) {
                if layouts_migratable(layout_a, layout_b) {
                    pairs.push(format!(
                        "[{}, {}]",
                        json_string(&personality_a.name),
                        json_string(&personality_b.name)
                    ));
                }
            }
        }
    }
    let pair_count = pairs.len();
    for (idx, pair) in pairs.into_iter().enumerate() {
        let comma = if idx + 1 == pair_count { "" } else { "," };
        line(&mut out, 2, &format!("{pair}{comma}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_document, validate_document};

    const SOURCE: &str = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (defisa rv32_axis
    (base rv32im)
    (word-bits 32)
    (registers "x[32]:i32" "pc:i32")
    (memory-model rvwmo)
    (endianness little)
  )

  (definstruction fma_i
    (mnemonic FMA_I)
    (category custom)
    (format R4)
    (opcode 11)
    (func3 3)
    (func7 0)
    (encoding (func2 0))
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
      (rs3 reg i32 in)
    )
    (formal (add i32 (mul i32 rs1 rs2) rs3))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )

  (defpersonality scalar1
    (implements rv32_axis)
    (discipline independent (threads 1))
    (capsule "x[32]" "pc")
  )

  (defpersonality simt8
    (implements rv32_axis)
    (discipline lockstep (lanes 8))
    (capsule "x[32]" "pc")
  )
)
"#;

    #[test]
    fn emits_layout_hash_offsets_and_migratable_pair() {
        let document = parse_document(SOURCE).unwrap();
        validate_document(&document).unwrap();
        let manifest = emit_state_capsule_manifest_json(&document);
        assert!(manifest.contains("\"schema\": \"axis.state-capsule.v1\""));
        assert!(manifest.contains("\"name\": \"scalar1\""));
        assert!(manifest.contains("\"kind\": \"lockstep\""));
        assert!(manifest.contains("{\"lanes\": 8}"));
        assert!(manifest.contains(
            "{\"name\": \"pc\", \"count\": 1, \"width_bits\": 32, \"byte_offset\": 128}"
        ));
        assert!(manifest.contains("\"total_bytes\": 132,"));
        assert!(manifest.contains("[\"scalar1\", \"simt8\"]"));
        // The hash pins the layout only: migratable personalities share it.
        let hashes: Vec<&str> = manifest
            .match_indices("\"layout_hash\": \"")
            .map(|(idx, pat)| &manifest[idx + pat.len()..idx + pat.len() + 64])
            .collect();
        assert_eq!(hashes.len(), 2);
        assert_eq!(hashes[0], hashes[1]);
        assert!(hashes.iter().all(|hash| hash.len() == 64));
    }

    #[test]
    fn personality_free_document_emits_empty_manifest() {
        let document = parse_document(
            r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction tls_load
    (mnemonic TLS_LOAD)
    (category custom)
    (format R)
    (opcode 11)
    (func3 1)
    (func7 2)
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
"#,
        )
        .unwrap();
        validate_document(&document).unwrap();
        let manifest = emit_state_capsule_manifest_json(&document);
        assert!(manifest.contains("\"personalities\": [\n  ],"));
    }
}
