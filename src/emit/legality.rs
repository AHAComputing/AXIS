//! AXIS emit: mode-legality manifest (personality design stage P2).
//!
//! `mode_legality_manifest.json` (`axis.mode-legality.v1`) carries the mode
//! selector (CSR, field slice, values, default) and, per mode value, the list
//! of `{mnemonic, match, mask}` legal in that mode. It is the decode table the
//! hardware mode gate consumes; the legality entries derive from the same
//! layout resolution as every other encoding fact, so they cannot drift.

use super::common::*;


/// The memory-resident configurations a document declares
/// (`docs/tensor_design.md`, T5).
///
/// Published here because this manifest already answers "what is this machine
/// configured as", and a configuration read from memory is the same question
/// with a different source. A runtime that must BUILD the block reads the
/// offsets from here rather than from an effect expression -- which was the
/// only place they lived before, and is the reason the construct exists.
fn config_array(document: &Document) -> String {
    let entries: Vec<String> = document
        .configs
        .iter()
        .map(|config| {
            let fields = config
                .fields
                .iter()
                .map(|field| {
                    let values = field
                        .values
                        .iter()
                        .map(|value| value.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    format!(
                        "{{\"name\": {}, \"at\": {}, \"width\": {}, \"values\": [{values}]}}",
                        json_string(&field.name),
                        field.at,
                        field.width
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            let instantiate = config
                .instantiate
                .iter()
                .map(|(name, value)| format!("{}: {value}", json_string(name)))
                .collect::<Vec<_>>()
                .join(", ");
            let established = document
                .instructions
                .iter()
                .filter(|instruction| instruction.configures == config.name)
                .map(|instruction| json_string(&instruction.mnemonic))
                .collect::<Vec<_>>()
                .join(", ");
            format!(
                "{{\"name\": {}, \"source\": \"memory\", \"bytes\": {}, \
                 \"fields\": [{fields}], \"instantiate\": {{{instantiate}}}, \
                 \"established_by\": [{established}]}}",
                json_string(&config.name),
                config.bytes
            )
        })
        .collect();
    format!("[{}]", entries.join(", "))
}

pub fn emit_mode_legality_manifest_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.mode-legality.v1\",");

    let Some(mode) = document.modes.first() else {
        // Mode-free documents have no selector; keep the emitter total.
        line(&mut out, 1, "\"mode\": null,");
        line(&mut out, 1, "\"modes\": [],");
        line(&mut out, 1, &format!("\"configs\": {}", config_array(document)));
        out.push_str("}\n");
        return out;
    };

    line(&mut out, 1, "\"mode\": {");
    line(
        &mut out,
        2,
        &format!("\"name\": {},", json_string(&mode.name)),
    );
    line(&mut out, 2, &format!("\"csr\": \"0x{:x}\",", mode.csr));
    line(
        &mut out,
        2,
        &format!(
            "\"field\": {{\"hi\": {}, \"lo\": {}}},",
            mode.field_hi, mode.field_lo
        ),
    );
    line(
        &mut out,
        2,
        &format!("\"default\": {},", json_string(&mode.default)),
    );
    let values = mode
        .values
        .iter()
        .map(|(name, value)| format!("{{\"name\": {}, \"value\": {value}}}", json_string(name)))
        .collect::<Vec<_>>()
        .join(", ");
    line(&mut out, 2, &format!("\"values\": [{values}]"));
    line(&mut out, 1, "},");

    line(&mut out, 1, "\"modes\": [");
    let value_count = mode.values.len();
    for (idx, (value_name, value_num)) in mode.values.iter().enumerate() {
        let legal: Vec<&Instruction> = document
            .instructions
            .iter()
            .filter(|instruction| {
                instruction.modes.is_empty() || instruction.modes.iter().any(|m| m == value_name)
            })
            .collect();
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"mode\": {},", json_string(value_name)),
        );
        line(&mut out, 3, &format!("\"value\": {value_num},"));
        line(&mut out, 3, "\"legal\": [");
        let legal_count = legal.len();
        for (legal_idx, instruction) in legal.iter().enumerate() {
            let layout = layout_for(document, instruction);
            let comma = if legal_idx + 1 == legal_count {
                ""
            } else {
                ","
            };
            line(
                &mut out,
                4,
                &format!(
                    "{{\"mnemonic\": {}, \"match\": {}, \"mask\": {}}}{comma}",
                    json_string(&instruction.mnemonic),
                    json_hex_u32(layout.match_value),
                    json_hex_u32(layout.mask_value)
                ),
            );
        }
        line(&mut out, 3, "]");
        let comma = if idx + 1 == value_count { "" } else { "," };
        line(&mut out, 2, &format!("}}{comma}"));
    }
    line(&mut out, 1, "],");
    line(&mut out, 1, &format!("\"configs\": {}", config_array(document)));
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_document, validate_document};

    const SOURCE: &str = r#"(axis-module xmode
  (version "1.0")
  (target rvmt)

  (defmode field_mode
    (csr 1984)
    (field 1 0)
    (values
      (scalar 0)
      (xnn 1)
    )
    (default scalar)
  )

  (definstruction scalar_op
    (mnemonic SCALAR_OP)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
    )
    (modes scalar)
    (formal (add i32 rs1 rs2))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )

  (definstruction xnn_op
    (mnemonic XNN_OP)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
    )
    (modes xnn)
    (formal (mul i32 rs1 rs2))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
"#;

    #[test]
    fn cross_mode_reuse_appears_per_mode() {
        let document = parse_document(SOURCE).unwrap();
        validate_document(&document).unwrap();
        let manifest = emit_mode_legality_manifest_json(&document);
        assert!(manifest.contains("\"schema\": \"axis.mode-legality.v1\""));
        assert!(manifest.contains("\"csr\": \"0x7c0\""));
        assert!(manifest.contains("\"field\": {\"hi\": 1, \"lo\": 0}"));
        // The same encoding is legal as SCALAR_OP in `scalar` and XNN_OP in `xnn`.
        assert!(manifest.contains("\"mode\": \"scalar\","));
        assert!(manifest.contains("\"mnemonic\": \"SCALAR_OP\""));
        assert!(manifest.contains("\"mode\": \"xnn\","));
        assert!(manifest.contains("\"mnemonic\": \"XNN_OP\""));
    }

    #[test]
    fn mode_free_document_emits_null_selector() {
        let document = parse_document(
            r#"(axis-module xmode
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
        let manifest = emit_mode_legality_manifest_json(&document);
        assert!(manifest.contains("\"mode\": null,"));
        assert!(manifest.contains("\"modes\": []"));
    }
}
