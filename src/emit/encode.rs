//! AXIS emit: encode domain (split from the former monolithic emit.rs).

use super::common::*;
use crate::decode_constraint::{CompareOp, ConstraintValue, DecodeConstraint};

fn decode_constraint(instruction: &Instruction) -> Option<&DecodeConstraint> {
    instruction.decode_constraint.as_ref()
}

fn c_word_operand(layout: &InstructionLayout, operand: &str) -> String {
    layout
        .operand_bindings(operand)
        .iter()
        .map(|field| {
            let mask = if field.width >= 32 {
                "0xffffffffu".to_string()
            } else {
                format!("0x{:x}u", (1u32 << field.width) - 1)
            };
            format!(
                "(((insn >> {}) & {mask}) << {})",
                field.insn_lo, field.op_lo
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

fn compare_operator(op: CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "==",
        CompareOp::Ne => "!=",
        CompareOp::Lt => "<",
        CompareOp::Le => "<=",
        CompareOp::Gt => ">",
        CompareOp::Ge => ">=",
    }
}

fn constraint_json(constraint: &DecodeConstraint) -> String {
    match constraint {
        DecodeConstraint::A64LogicalImmediate { width, n, imms } => {
            let n = match n {
                ConstraintValue::Literal(value) => {
                    format!("{{\"kind\": \"literal\", \"value\": {value}}}")
                }
                ConstraintValue::Operand(name) => {
                    format!("{{\"kind\": \"operand\", \"name\": {}}}", json_string(name))
                }
            };
            format!(
                "{{\"kind\": \"a64_logical_imm\", \"width\": {width}, \"n\": {n}, \"imms\": {}}}",
                json_string(imms)
            )
        }
        DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        } => format!(
            "{{\"kind\": \"a64_shifted_reg\", \"width\": {width}, \"shift\": {}, \"amount\": {}}}",
            json_string(shift),
            json_string(amount)
        ),
        DecodeConstraint::A64ExtendedRegister { amount } => format!(
            "{{\"kind\": \"a64_extended_reg\", \"amount\": {}}}",
            json_string(amount)
        ),
        DecodeConstraint::UnsignedCompare {
            operand,
            op,
            literal,
        } => format!(
            "{{\"kind\": \"uimm_compare\", \"operand\": {}, \"op\": {}, \"literal\": {literal}}}",
            json_string(operand),
            json_string(op.name())
        ),
        DecodeConstraint::MaskedEq {
            operand,
            mask,
            value,
        } => format!(
            "{{\"kind\": \"uimm_mask_eq\", \"operand\": {}, \"mask\": {mask}, \"value\": {value}}}",
            json_string(operand)
        ),
        DecodeConstraint::And(children) | DecodeConstraint::Or(children) => {
            let kind = if matches!(constraint, DecodeConstraint::And(_)) {
                "and"
            } else {
                "or"
            };
            format!(
                "{{\"kind\": \"{kind}\", \"constraints\": [{}]}}",
                children
                    .iter()
                    .map(constraint_json)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
        DecodeConstraint::Not(child) => format!(
            "{{\"kind\": \"not\", \"constraint\": {}}}",
            constraint_json(child)
        ),
    }
}

fn c_encode_constraint_expr(constraint: &DecodeConstraint, instruction: &Instruction) -> String {
    let operand = |name: &str| {
        let index = instruction
            .operands
            .iter()
            .position(|operand| operand.name == name)
            .expect("canonical decode constraint operand");
        format!("operand_values[{index}]")
    };
    match constraint {
        DecodeConstraint::A64LogicalImmediate { width, n, imms } => {
            let n = match n {
                ConstraintValue::Literal(value) => format!("{value}u"),
                ConstraintValue::Operand(name) => operand(name),
            };
            format!(
                "axis_encode_a64_logical_imm_valid({width}u, {n}, {})",
                operand(imms)
            )
        }
        DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        } => format!(
            "({} < 3u && {} < {width}u)",
            operand(shift),
            operand(amount)
        ),
        DecodeConstraint::A64ExtendedRegister { amount } => {
            format!("{} < 5u", operand(amount))
        }
        DecodeConstraint::UnsignedCompare {
            operand: name,
            op,
            literal,
        } => format!("{} {} {literal}u", operand(name), compare_operator(*op)),
        DecodeConstraint::MaskedEq {
            operand: name,
            mask,
            value,
        } => format!("({} & {mask}u) == {value}u", operand(name)),
        DecodeConstraint::And(children) | DecodeConstraint::Or(children) => {
            let joiner = if matches!(constraint, DecodeConstraint::And(_)) {
                " && "
            } else {
                " || "
            };
            format!(
                "({})",
                children
                    .iter()
                    .map(|child| c_encode_constraint_expr(child, instruction))
                    .collect::<Vec<_>>()
                    .join(joiner)
            )
        }
        DecodeConstraint::Not(child) => {
            format!("!({})", c_encode_constraint_expr(child, instruction))
        }
    }
}

fn c_decode_constraint_expr(constraint: &DecodeConstraint, layout: &InstructionLayout) -> String {
    let operand = |name: &str| format!("({})", c_word_operand(layout, name));
    match constraint {
        DecodeConstraint::A64LogicalImmediate { width, n, imms } => {
            let n = match n {
                ConstraintValue::Literal(value) => format!("{value}u"),
                ConstraintValue::Operand(name) => operand(name),
            };
            format!(
                "axis_decode_a64_logical_imm_valid({width}u, {n}, {})",
                operand(imms)
            )
        }
        DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        } => format!(
            "({} < 3u && {} < {width}u)",
            operand(shift),
            operand(amount)
        ),
        DecodeConstraint::A64ExtendedRegister { amount } => {
            format!("{} < 5u", operand(amount))
        }
        DecodeConstraint::UnsignedCompare {
            operand: name,
            op,
            literal,
        } => format!("{} {} {literal}u", operand(name), compare_operator(*op)),
        DecodeConstraint::MaskedEq {
            operand: name,
            mask,
            value,
        } => format!("({} & {mask}u) == {value}u", operand(name)),
        DecodeConstraint::And(children) | DecodeConstraint::Or(children) => {
            let joiner = if matches!(constraint, DecodeConstraint::And(_)) {
                " && "
            } else {
                " || "
            };
            format!(
                "({})",
                children
                    .iter()
                    .map(|child| c_decode_constraint_expr(child, layout))
                    .collect::<Vec<_>>()
                    .join(joiner)
            )
        }
        DecodeConstraint::Not(child) => {
            format!("!({})", c_decode_constraint_expr(child, layout))
        }
    }
}

pub fn emit_decode_table_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.decode-table.v1\",");
    line(
        &mut out,
        1,
        &format!("\"name\": {},", json_string(&document.extension.name)),
    );
    line(
        &mut out,
        1,
        &format!("\"version\": {},", json_string(&document.extension.version)),
    );
    line(&mut out, 1, "\"instructions\": [");
    // One entry per ENCODING: a lane group shares one decode key.
    let entries = architectural_instructions(document);
    for (idx, instruction) in entries.iter().enumerate() {
        let layout = layout_for(document, instruction);
        let (match_value, mask_value) = (layout.match_value, layout.mask_value);
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"mnemonic\": {},", json_string(&instruction.mnemonic)),
        );
        if !instruction.isa.is_empty() {
            line(
                &mut out,
                3,
                &format!("\"isa\": {},", json_string(&instruction.isa)),
            );
        }
        line(
            &mut out,
            3,
            &format!("\"format\": {},", json_string(&instruction.format)),
        );
        // **How wide the instruction is.** Everything described so far is 32
        // bits and a consumer could assume it; RISC-V's C extension is 16, and
        // a decoder that steps four bytes through a stream holding one
        // misaligns everything after it -- `binary_coverage.py` read 60.7% on a
        // compiled object for exactly that reason, and the description was
        // fine. The width is a fact about the instruction, so the table states
        // it rather than every consumer inferring it from an ISA's name.
        line(&mut out, 3, &format!("\"bits\": {},", layout.bits));
        line(
            &mut out,
            3,
            &format!("\"asm\": {},", json_string(&instruction_asm(instruction))),
        );
        line(
            &mut out,
            3,
            &format!("\"match\": {},", json_hex_u32(match_value)),
        );
        line(
            &mut out,
            3,
            &format!("\"mask\": {},", json_hex_u32(mask_value)),
        );
        // What makes a shared decode word unambiguous, beside the ISA above and
        // the predicates below. Two instructions may carry one match and mask
        // when their modes are disjoint or their units sit in disjoint packet
        // slots -- the validator proves exactly that -- and this table said
        // neither, so `SCALAR_OP` and `TENSOR_OP` were one word with two
        // meanings to anyone reading it. Emitted only when they restrict
        // something, so a document with no modes and no packets is unchanged.
        if !instruction.modes.is_empty() {
            let modes: Vec<String> = instruction.modes.iter().map(|m| json_string(m)).collect();
            line(&mut out, 3, &format!("\"modes\": [{}],", modes.join(", ")));
        }
        if !instruction.unit.trim().is_empty() {
            line(
                &mut out,
                3,
                &format!("\"unit\": {},", json_string(instruction.unit.trim())),
            );
        }
        if !instruction.decode_requires.trim().is_empty() {
            line(
                &mut out,
                3,
                &format!(
                    "\"decode_requires\": {},",
                    json_string(instruction.decode_requires.trim())
                ),
            );
        }
        if let Some(constraint) = decode_constraint(instruction) {
            line(
                &mut out,
                3,
                &format!("\"decode_constraint\": {},", constraint_json(constraint)),
            );
        }
        line(&mut out, 3, "\"decode_key\": {");
        line(&mut out, 4, &format!("\"opcode\": {},", instruction.opcode));
        line(&mut out, 4, &format!("\"func3\": {},", instruction.func3));
        line(&mut out, 4, &format!("\"func7\": {}", instruction.func7));
        line(&mut out, 3, "},");
        emit_operands_json(&mut out, &instruction.operands, 3);
        out.push('\n');
        let suffix = if idx + 1 == entries.len() {
            ""
        } else {
            ","
        };
        line(&mut out, 2, &format!("}}{suffix}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

pub fn emit_encode_table_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.encode-table.v1\",");
    line(
        &mut out,
        1,
        &format!("\"name\": {},", json_string(&document.extension.name)),
    );
    line(
        &mut out,
        1,
        &format!("\"version\": {},", json_string(&document.extension.version)),
    );
    line(&mut out, 1, "\"word_bits\": 32,");
    line(&mut out, 1, "\"instructions\": [");
    // One entry per ENCODING: a lane group shares one encoding.
    let entries = architectural_instructions(document);
    for (idx, instruction) in entries.iter().enumerate() {
        let layout = layout_for(document, instruction);
        let (match_value, mask_value) = (layout.match_value, layout.mask_value);
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"mnemonic\": {},", json_string(&instruction.mnemonic)),
        );
        if !instruction.isa.is_empty() {
            line(
                &mut out,
                3,
                &format!("\"isa\": {},", json_string(&instruction.isa)),
            );
        }
        line(
            &mut out,
            3,
            &format!("\"format\": {},", json_string(&instruction.format)),
        );
        line(
            &mut out,
            3,
            &format!("\"asm\": {},", json_string(&instruction_asm(instruction))),
        );
        line(
            &mut out,
            3,
            &format!("\"base_value\": {},", json_hex_u32(match_value)),
        );
        line(
            &mut out,
            3,
            &format!("\"fixed_mask\": {},", json_hex_u32(mask_value)),
        );
        if !instruction.decode_requires.trim().is_empty() {
            line(
                &mut out,
                3,
                &format!(
                    "\"decode_requires\": {},",
                    json_string(instruction.decode_requires.trim())
                ),
            );
        }
        if let Some(constraint) = decode_constraint(instruction) {
            line(
                &mut out,
                3,
                &format!("\"decode_constraint\": {},", constraint_json(constraint)),
            );
        }
        line(&mut out, 3, "\"fixed_fields\": {");
        emit_layout_fixed_fields_json(&mut out, &layout, 4);
        line(&mut out, 3, "},");
        line(&mut out, 3, "\"operands\": [");
        for (operand_idx, operand) in instruction.operands.iter().enumerate() {
            emit_encode_operand_json(
                &mut out,
                operand,
                &layout,
                4,
                operand_idx + 1 == instruction.operands.len(),
            );
        }
        line(&mut out, 3, "]");
        let suffix = if idx + 1 == entries.len() {
            ""
        } else {
            ","
        };
        line(&mut out, 2, &format!("}}{suffix}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

pub fn emit_encode_c(document: &Document) -> String {
    let guard = format!(
        "AXIS_{}_ENCODE_H",
        tablegen_ident(&document.extension.name).to_ascii_uppercase()
    );
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. Header-only encode table. */\n");
    out.push_str(&format!("#ifndef {guard}\n#define {guard}\n\n"));
    out.push_str("#include <stdbool.h>\n#include <stdint.h>\n#include <stddef.h>\n\n");
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    out.push_str("/* One row per operand bit-field. Scattered operands (e.g. RISC-V\n");
    out.push_str(" * S/B/J immediates) contribute several rows; operand_index selects the\n");
    out.push_str(" * caller's operand value and src_lsb the slice of it stored here. */\n");
    out.push_str("typedef struct axis_encode_operand_field {\n");
    out.push_str("  const char *name;\n");
    out.push_str("  const char *kind;\n");
    out.push_str("  const char *role;\n");
    out.push_str("  const char *field;\n");
    out.push_str("  int operand_index;\n");
    out.push_str("  int src_lsb;\n");
    out.push_str("  int lsb;\n");
    out.push_str("  uint32_t width;\n");
    out.push_str("} axis_encode_operand_field;\n\n");
    out.push_str("typedef struct axis_encode_entry {\n");
    out.push_str("  const char *mnemonic;\n");
    out.push_str("  const char *format;\n");
    out.push_str("  const char *asm_syntax;\n");
    out.push_str("  uint32_t base_value;\n");
    out.push_str("  uint32_t fixed_mask;\n");
    out.push_str("  bool encodable;\n");
    out.push_str("  const axis_encode_operand_field *fields;\n");
    out.push_str("  size_t field_count;\n");
    out.push_str("  size_t operand_count;\n");
    out.push_str("} axis_encode_entry;\n\n");

    // One entry per ENCODING, the same list `emit-encode-json` publishes. The
    // C table is indexed by a row number a consumer reads out of that JSON --
    // `axis_encode_by_index` is called with it -- so the two lists have to be
    // the same list. They were not: the JSON moved to one-per-encoding and this
    // stayed one-per-lane, which made every index name a different instruction
    // on the two sides.
    let architectural = architectural_instructions(document);
    for instruction in &architectural {
        if instruction.operands.is_empty() {
            continue;
        }
        let layout = layout_for(document, instruction);
        out.push_str(&format!(
            "static const axis_encode_operand_field AXIS_ENCODE_OPERANDS_{}[] = {{\n",
            tablegen_ident(&instruction.mnemonic)
        ));
        for (operand_idx, operand) in instruction.operands.iter().enumerate() {
            let bindings = layout.operand_bindings(&operand.name);
            let role = crate::ast::operand_role(operand, true);
            if bindings.is_empty() {
                // ⚠️ A FIXED operand's row carries its VALUE where an encoded
                // field carries a source bit position: the row has no bits
                // (`lsb` -1, width 0), so `src_lsb` is otherwise unread, and
                // the value is what a decoder owes for the operand. SVE's
                // FFR is predicate register 16, named by no bits of SETFFR;
                // read back as register 0 it was P0.
                out.push_str(&format!(
                    "  {{ {}, {}, {}, {}, {}, {}, -1, 0u }},\n",
                    c_string(&operand.name),
                    c_string(&operand.kind),
                    c_string(role),
                    c_string(if operand.fixed.is_some() { "fixed" } else { "unencoded" }),
                    operand_idx,
                    operand.fixed.unwrap_or(0)
                ));
                continue;
            }
            for binding in bindings {
                out.push_str(&format!(
                    "  {{ {}, {}, {}, {}, {}, {}, {}, {}u }},\n",
                    c_string(&operand.name),
                    c_string(&operand.kind),
                    c_string(role),
                    c_string(&operand.name),
                    operand_idx,
                    binding.op_lo,
                    binding.insn_lo,
                    binding.width
                ));
            }
        }
        out.push_str("};\n\n");
    }

    out.push_str("static const axis_encode_entry AXIS_ENCODE_TABLE[] = {\n");
    for instruction in &architectural {
        let layout = layout_for(document, instruction);
        let (match_value, mask_value) = (layout.match_value, layout.mask_value);
        let fields = if instruction.operands.is_empty() {
            "NULL".to_string()
        } else {
            format!(
                "AXIS_ENCODE_OPERANDS_{}",
                tablegen_ident(&instruction.mnemonic)
            )
        };
        let field_count = if instruction.operands.is_empty() {
            "0u".to_string()
        } else {
            format!(
                "sizeof(AXIS_ENCODE_OPERANDS_{}) / sizeof(AXIS_ENCODE_OPERANDS_{}[0])",
                tablegen_ident(&instruction.mnemonic),
                tablegen_ident(&instruction.mnemonic)
            )
        };
        out.push_str(&format!(
            "  {{ {}, {}, {}, 0x{:08x}u, 0x{:08x}u, {}, {}, {}, {}u }},\n",
            c_string(&instruction.mnemonic),
            c_string(&instruction.format),
            c_string(&instruction_asm(instruction)),
            match_value,
            mask_value,
            if layout.is_encodable() {
                "true"
            } else {
                "false"
            },
            fields,
            field_count,
            instruction.operands.len()
        ));
    }
    out.push_str("};\n\n");
    out.push_str(
        "static const size_t AXIS_ENCODE_TABLE_LEN = sizeof(AXIS_ENCODE_TABLE) / sizeof(AXIS_ENCODE_TABLE[0]);\n\n",
    );
    out.push_str(
        "static inline uint32_t axis_encode_apply_field(uint32_t insn, uint32_t value, int lsb, uint32_t width) {\n",
    );
    out.push_str("  if (lsb < 0 || width == 0u || width > 32u) {\n");
    out.push_str("    return insn;\n");
    out.push_str("  }\n");
    out.push_str("  uint32_t mask = width == 32u ? 0xffffffffu : ((1u << width) - 1u);\n");
    out.push_str(
        "  return (insn & ~(mask << (uint32_t)lsb)) | ((value & mask) << (uint32_t)lsb);\n",
    );
    out.push_str("}\n\n");
    out.push_str(
        "static inline bool axis_encode_a64_logical_imm_valid(uint32_t width, uint32_t n, uint32_t imms) {\n",
    );
    out.push_str(
        "  if ((width == 32u && n != 0u) || (width != 32u && width != 64u)) { return false; }\n",
    );
    out.push_str("  uint32_t encoded = ((n & 1u) << 6) | ((~imms) & 0x3fu);\n");
    out.push_str("  int length = -1;\n");
    out.push_str("  for (int bit = 6; bit >= 0; --bit) { if (encoded & (1u << bit)) { length = bit; break; } }\n");
    out.push_str("  if (length < 1) { return false; }\n");
    out.push_str("  uint32_t levels = (1u << length) - 1u;\n");
    out.push_str("  return (imms & levels) != levels;\n");
    out.push_str("}\n\n");
    out.push_str(
        "static inline bool axis_encode_constraint_ok(size_t index, const uint32_t *operand_values) {\n",
    );
    out.push_str("  (void)operand_values;\n");
    out.push_str("  switch (index) {\n");
    for (index, instruction) in architectural.iter().enumerate() {
        let Some(constraint) = decode_constraint(instruction) else {
            continue;
        };
        out.push_str(&format!(
            "    case {index}u: return {};\n",
            c_encode_constraint_expr(constraint, instruction)
        ));
    }
    out.push_str("    default: return true;\n");
    out.push_str("  }\n");
    out.push_str("}\n\n");
    out.push_str(
        "static inline bool axis_encode_by_index(size_t index, const uint32_t *operand_values, uint32_t *out_insn) {\n",
    );
    out.push_str("  if (index >= AXIS_ENCODE_TABLE_LEN || out_insn == NULL) {\n");
    out.push_str("    return false;\n");
    out.push_str("  }\n");
    out.push_str("  const axis_encode_entry *entry = &AXIS_ENCODE_TABLE[index];\n");
    out.push_str("  if (!entry->encodable) {\n");
    out.push_str("    return false;\n");
    out.push_str("  }\n");
    out.push_str("  if (entry->operand_count > 0u && operand_values == NULL) {\n");
    out.push_str("    return false;\n");
    out.push_str("  }\n");
    out.push_str("  if (!axis_encode_constraint_ok(index, operand_values)) {\n");
    out.push_str("    return false;\n");
    out.push_str("  }\n");
    out.push_str("  uint32_t insn = entry->base_value;\n");
    out.push_str("  for (size_t i = 0; i < entry->field_count; ++i) {\n");
    out.push_str("    const axis_encode_operand_field *field = &entry->fields[i];\n");
    out.push_str("    uint32_t value = operand_values[field->operand_index];\n");
    out.push_str("    if (field->src_lsb > 0) {\n");
    out.push_str("      value >>= (uint32_t)field->src_lsb;\n");
    out.push_str("    }\n");
    out.push_str("    insn = axis_encode_apply_field(insn, value, field->lsb, field->width);\n");
    out.push_str("  }\n");
    out.push_str("  *out_insn = insn;\n");
    out.push_str("  return true;\n");
    out.push_str("}\n\n");
    out.push_str("#ifdef __cplusplus\n}\n#endif\n\n");
    out.push_str(&format!("#endif /* {guard} */\n"));
    out
}

pub fn emit_roundtrip_tests_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.roundtrip-tests.v1\",");
    line(
        &mut out,
        1,
        &format!("\"name\": {},", json_string(&document.extension.name)),
    );
    line(
        &mut out,
        1,
        &format!("\"version\": {},", json_string(&document.extension.version)),
    );
    line(&mut out, 1, "\"tests\": [");
    // One fixture per *word*. The lanes instantiated from one scalable
    // instruction share its encoding by construction -- that is what the
    // decode-disjointness rule already exempts them from -- so sixteen
    // fixtures for ADD_Z_B are sixteen copies of the same word, fifteen of
    // which can only fail: decode names the lane it names. Roundtrip is a
    // property of the encoding, and there is one encoding here.
    //
    // The lane's NAME is kept, and deliberately: a fixture is also what the
    // execution harnesses drive lanes from, and they resolve a lane's operands
    // through it. Renaming these to the group made `scalable_exec_check` read
    // a selector the fixture no longer carried. `roundtrip_check` maps the
    // name to its group instead, which is a question about one consumer rather
    // than about what a fixture is.
    let layouts: Vec<(&Instruction, InstructionLayout)> = document
        .instructions
        .iter()
        .map(|instruction| (instruction, layout_for(document, instruction)))
        .collect();
    let encodable: Vec<&(&Instruction, InstructionLayout)> = layouts
        .iter()
        .filter(|(_, layout)| layout.is_encodable())
        .filter(|(instruction, _)| {
            instruction.scalable_origin.is_empty() || instruction.scalable_lane == 0
        })
        // A definedness mask is a second view of its instruction's word, not a
        // second instruction: it shares the encoding by construction, so a
        // fixture for it is a duplicate that decode can only answer one way.
        .filter(|(instruction, _)| instruction.definedness_of.is_empty())
        .collect();
    for (idx, (instruction, layout)) in encodable.iter().enumerate() {
        let (match_value, mask_value) = (layout.match_value, layout.mask_value);
        let encoded = encode_sample_instruction(instruction, layout);
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"mnemonic\": {},", json_string(&instruction.mnemonic)),
        );
        if !instruction.isa.is_empty() {
            line(
                &mut out,
                3,
                &format!("\"isa\": {},", json_string(&instruction.isa)),
            );
        }
        // ⚠️ The mode this fixture's word is read in. Two instructions may
        // share an encoding when their modes are disjoint, and then the word
        // alone does not say which one it is -- a decoder handed only the word
        // refuses, correctly. A fixture that did not carry the mode was asking
        // an unanswerable question and reading the refusal as a failure.
        if !instruction.modes.is_empty() {
            line(
                &mut out,
                3,
                &format!("\"mode\": {},", json_string(&instruction.modes[0])),
            );
        }
        // And the unit, for the same reason: a packet slot is the other thing
        // that lets two instructions share an encoding.
        if !instruction.unit.is_empty() {
            line(
                &mut out,
                3,
                &format!("\"unit\": {},", json_string(&instruction.unit)),
            );
        }
        line(
            &mut out,
            3,
            &format!("\"format\": {},", json_string(&instruction.format)),
        );
        line(
            &mut out,
            3,
            &format!("\"asm\": {},", json_string(&instruction_asm(instruction))),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"operands\": {},",
                json_roundtrip_operand_values(instruction, layout)
            ),
        );
        line(
            &mut out,
            3,
            &format!("\"encoded\": {},", json_hex_u32(encoded)),
        );
        line(&mut out, 3, "\"expected_decode\": {");
        line(
            &mut out,
            4,
            &format!("\"match\": {},", json_hex_u32(match_value)),
        );
        line(
            &mut out,
            4,
            &format!("\"mask\": {},", json_hex_u32(mask_value)),
        );
        line(
            &mut out,
            4,
            &format!(
                "\"matches\": {}",
                json_bool((encoded & mask_value) == match_value)
            ),
        );
        line(&mut out, 3, "}");
        let suffix = if idx + 1 == encodable.len() { "" } else { "," };
        line(&mut out, 2, &format!("}}{suffix}"));
    }
    line(&mut out, 1, "],");
    line(&mut out, 1, "\"skipped\": [");
    let skipped: Vec<&(&Instruction, InstructionLayout)> = layouts
        .iter()
        .filter(|(_, layout)| !layout.is_encodable())
        .collect();
    for (idx, (instruction, layout)) in skipped.iter().enumerate() {
        let suffix = if idx + 1 == skipped.len() { "" } else { "," };
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"mnemonic\": {},", json_string(&instruction.mnemonic)),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"reason\": {},",
                json_string(roundtrip_skip_reason(layout))
            ),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"operands\": {}",
                json_list(&roundtrip_blocking_names(layout))
            ),
        );
        line(&mut out, 2, &format!("}}{suffix}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

/// One node of the decode tree emitted beside the table.
struct DecodeNode {
    /// Bits this node switches on; 0 marks a leaf.
    mask: u32,
    /// The `insn & parent.mask` that selects this node.
    key: u32,
    /// First child node, or first index into the leaf-entry array.
    first: usize,
    count: usize,
}

/// Partition the decode table so a word reaches only the entries that can match
/// it.
///
/// The linear decoder tests every entry -- 247 for `rv32i`, 854 for the AArch64
/// seed, with a `strcmp` per entry for the ISA filter -- and disassembling a
/// binary makes that the hot loop.
///
/// At each node, take the bits **every remaining candidate constrains**: the
/// AND of their masks, less whatever ancestors already used. Partition on the
/// value each entry requires there. That choice is what makes this exact rather
/// than a filter -- an entry constrains those bits, so a word matching it
/// necessarily carries that value and reaches its leaf, and a word whose value
/// no child claims cannot match any entry at all. Nothing is ever missed, so
/// the selection rules run unchanged over a smaller set.
///
/// Measured worst leaf: 3 of 247 for `rv32i`, 4 of 318 for `rv64i`, 52 of 854
/// for the AArch64 seed, whose cross-ISA overlap is what stops it going lower.
fn build_decode_tree(entries: &[(u32, u32)]) -> (Vec<DecodeNode>, Vec<usize>) {
    const LEAF: usize = 4;
    let mut nodes = vec![DecodeNode { mask: 0, key: 0, first: 0, count: 0 }];
    let mut leaves = Vec::new();
    let all: Vec<usize> = (0..entries.len()).collect();
    build_decode_node(entries, &all, 0, 0, &mut nodes, &mut leaves, LEAF);
    (nodes, leaves)
}

fn build_decode_node(
    entries: &[(u32, u32)],
    candidates: &[usize],
    used: u32,
    index: usize,
    nodes: &mut Vec<DecodeNode>,
    leaves: &mut Vec<usize>,
    leaf_limit: usize,
) {
    let common = candidates
        .iter()
        .fold(u32::MAX, |acc, &i| acc & entries[i].1)
        & !used;
    let mut groups: Vec<(u32, Vec<usize>)> = Vec::new();
    if candidates.len() > leaf_limit && common != 0 {
        for &i in candidates {
            let key = entries[i].0 & common;
            match groups.iter_mut().find(|(existing, _)| *existing == key) {
                Some((_, bucket)) => bucket.push(i),
                None => groups.push((key, vec![i])),
            }
        }
        // Sorted, because the generated walk binary-searches them.
        groups.sort_by_key(|(key, _)| *key);
    }
    // A partition that separates nothing is not worth a level: it would cost a
    // search and hand back the set it started with.
    if groups.len() < 2 {
        nodes[index].mask = 0;
        nodes[index].first = leaves.len();
        nodes[index].count = candidates.len();
        leaves.extend_from_slice(candidates);
        return;
    }
    let first_child = nodes.len();
    for (key, _) in &groups {
        nodes.push(DecodeNode { mask: 0, key: *key, first: 0, count: 0 });
    }
    nodes[index].mask = common;
    nodes[index].first = first_child;
    nodes[index].count = groups.len();
    for (offset, (_, bucket)) in groups.iter().enumerate() {
        build_decode_node(entries, bucket, used | common, first_child + offset, nodes,
                          leaves, leaf_limit);
    }
}

pub fn emit_decode_c(document: &Document) -> String {
    // One entry per ENCODING. A decode table maps a word to an
    // instruction, and the lanes of a scalable group share one word --
    // emitting each of them puts N entries on one key and decode can only
    // answer with the first. A roundtrip then encodes `ADD_Z_B` and gets
    // `ADD_Z_B__l0` back, which is the same instruction under the name of
    // one of its lanes.
    let architectural = architectural_instructions(document);
    let guard = format!(
        "AXIS_{}_DECODE_H",
        tablegen_ident(&document.extension.name).to_ascii_uppercase()
    );
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. Header-only decode table. */\n");
    out.push_str(&format!("#ifndef {guard}\n#define {guard}\n\n"));
    out.push_str("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n\n");
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    out.push_str("typedef enum axis_insn_id {\n");
    out.push_str("  AXIS_INSN_UNKNOWN = 0,\n");
    for instruction in &architectural {
        out.push_str(&format!(
            "  AXIS_INSN_{},\n",
            tablegen_ident(&instruction.mnemonic)
        ));
    }
    out.push_str("} axis_insn_id;\n\n");
    out.push_str("typedef struct axis_decode_entry {\n");
    out.push_str("  axis_insn_id id;\n");
    out.push_str("  const char *isa;\n");
    out.push_str("  const char *mnemonic;\n");
    out.push_str("  const char *format;\n");
    out.push_str("  const char *asm_syntax;\n");
    out.push_str("  uint32_t match;\n");
    out.push_str("  uint32_t mask;\n");
    /* How many bits the instruction occupies. 32 everywhere until RISC-V's C
       extension, which is 16 -- and a consumer stepping a fixed four bytes
       through a stream holding one misaligns everything after it. */
    out.push_str("  uint32_t bits;\n");
    /* Which scalable instruction this entry is a lane of, and which lane. A
       lane shares its origin's encoding by construction, so the decoder needs
       to tell "several entries, one instruction" from real ambiguity. */
    out.push_str("  const char *scalable_origin;\n");
    out.push_str("  uint32_t scalable_lane;\n");
    /* Whether this entry is a definedness mask, which shares its
       instruction's word rather than having one of its own. */
    out.push_str("  int definedness;\n");
    /* The modes this instruction is legal in, space separated, or "" for one
       legal in all of them. Two instructions may share an encoding when their
       modes are disjoint, and a decoder handed only a word then cannot tell
       them apart -- it returns NULL, which is right. `axis_decode_in_mode` is
       how a caller that knows the mode asks. */
    out.push_str("  const char *modes;\n");
    /* The functional unit this instruction issues to, or "". The same rule
       admits it: two instructions may share an encoding when their units are
       held by disjoint packet slots. A VLIW word says which slot it is in, so
       a caller reading a packet knows the unit even though the word alone does
       not identify the instruction. */
    out.push_str("  const char *unit;\n");
    out.push_str("} axis_decode_entry;\n\n");
    out.push_str("static const axis_decode_entry AXIS_DECODE_TABLE[] = {\n");
    for instruction in &architectural {
        let layout = layout_for(document, instruction);
        let (match_value, mask_value) = (layout.match_value, layout.mask_value);
        out.push_str(&format!(
            "  {{ AXIS_INSN_{}, {}, {}, {}, {}, 0x{:08x}u, 0x{:08x}u, {}u, {}, {}u, {}, {}, {} }},\n",
            tablegen_ident(&instruction.mnemonic),
            c_string(&instruction.isa),
            c_string(&instruction.mnemonic),
            c_string(&instruction.format),
            c_string(&instruction_asm(instruction)),
            match_value,
            mask_value,
            layout.bits,
            c_string(&instruction.scalable_origin),
            instruction.scalable_lane,
            i32::from(!instruction.definedness_of.is_empty()),
            c_string(&instruction.modes.join(" ")),
            c_string(&instruction.unit)
        ));
    }
    out.push_str("};\n\n");
    out.push_str(
        "static const size_t AXIS_DECODE_TABLE_LEN = sizeof(AXIS_DECODE_TABLE) / sizeof(AXIS_DECODE_TABLE[0]);\n\n",
    );
    // The decode tree, beside the table it indexes. See `build_decode_tree`.
    let keys: Vec<(u32, u32)> = architectural
        .iter()
        .map(|instruction| {
            let layout = layout_for(document, instruction);
            (layout.match_value, layout.mask_value)
        })
        .collect();
    let (nodes, leaves) = build_decode_tree(&keys);
    out.push_str("/* Decode tree: at a node, `insn & mask` selects one child by key;\n");
    out.push_str("   `mask == 0` is a leaf naming a run of AXIS_DECODE_LEAVES. Every\n");
    out.push_str("   candidate constrains the bits a node switches on, so a word reaches\n");
    out.push_str("   the one leaf holding every entry that could match it. */\n");
    out.push_str("typedef struct axis_decode_node {\n");
    out.push_str("  uint32_t mask;\n  uint32_t key;\n");
    out.push_str("  uint32_t first;\n  uint32_t count;\n");
    out.push_str("} axis_decode_node;\n\n");
    out.push_str("static const axis_decode_node AXIS_DECODE_NODES[] = {\n");
    for node in &nodes {
        out.push_str(&format!(
            "  {{ 0x{:08x}u, 0x{:08x}u, {}u, {}u }},\n",
            node.mask, node.key, node.first, node.count
        ));
    }
    out.push_str("};\n\n");
    out.push_str("static const uint32_t AXIS_DECODE_LEAVES[] = {\n");
    for (index, leaf) in leaves.iter().enumerate() {
        if index % 12 == 0 {
            out.push_str("  ");
        }
        out.push_str(&format!("{leaf}u,"));
        out.push_str(if index % 12 == 11 { "\n" } else { " " });
    }
    if leaves.len() % 12 != 0 {
        out.push('\n');
    }
    out.push_str("};\n\n");
    out.push_str(
        "static inline int axis_decode_a64_logical_imm_valid(uint32_t width, uint32_t n, uint32_t imms) {\n",
    );
    out.push_str(
        "  if ((width == 32u && n != 0u) || (width != 32u && width != 64u)) { return 0; }\n",
    );
    out.push_str("  uint32_t encoded = ((n & 1u) << 6) | ((~imms) & 0x3fu);\n");
    out.push_str("  int length = -1;\n");
    out.push_str("  for (int bit = 6; bit >= 0; --bit) { if (encoded & (1u << bit)) { length = bit; break; } }\n");
    out.push_str("  if (length < 1) { return 0; }\n");
    out.push_str("  uint32_t levels = (1u << length) - 1u;\n");
    out.push_str("  return (imms & levels) != levels;\n");
    out.push_str("}\n\n");
    out.push_str("static inline int axis_decode_constraint_ok(uint32_t insn, axis_insn_id id) {\n");
    out.push_str("  (void)insn;\n");
    out.push_str("  switch (id) {\n");
    for instruction in &architectural {
        let Some(constraint) = decode_constraint(instruction) else {
            continue;
        };
        let layout = layout_for(document, instruction);
        out.push_str(&format!(
            "    case AXIS_INSN_{}: return {};\n",
            tablegen_ident(&instruction.mnemonic),
            c_decode_constraint_expr(constraint, &layout)
        ));
    }
    out.push_str("    default: return 1;\n");
    out.push_str("  }\n");
    out.push_str("}\n\n");
    // The linear decoder is kept, renamed, and is what the tree is checked
    // against: two implementations of one selection rule, one obviously
    // correct and one fast. `tools/decode_tree_check.py` compiles both and
    // requires them to agree on every fixture and on random words.
    out.push_str("static inline int axis_decode_unit_ok(const axis_decode_entry *entry, const char *unit) {\n");
    out.push_str("  if (!unit || !entry->unit[0]) { return 1; }\n");
    out.push_str("  return strcmp(entry->unit, unit) == 0;\n");
    out.push_str("}\n\n");
    out.push_str("static inline int axis_decode_mode_ok(const axis_decode_entry *entry, const char *mode) {\n");
    out.push_str("  if (!mode || !entry->modes[0]) { return 1; }\n");
    out.push_str("  size_t n = strlen(mode);\n");
    out.push_str("  for (const char *at = entry->modes; *at; ) {\n");
    out.push_str("    const char *end = at;\n");
    out.push_str("    while (*end && *end != ' ') { ++end; }\n");
    out.push_str("    if ((size_t)(end - at) == n && strncmp(at, mode, n) == 0) { return 1; }\n");
    out.push_str("    at = *end ? end + 1 : end;\n");
    out.push_str("  }\n");
    out.push_str("  return 0;\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_decode_entry *axis_decode_linear_in(uint32_t insn, const char *isa, const char *mode, const char *unit) {\n");
    out.push_str("  const axis_decode_entry *found = NULL;\n");
    out.push_str("  for (size_t i = 0; i < AXIS_DECODE_TABLE_LEN; ++i) {\n");
    out.push_str("    const axis_decode_entry *entry = &AXIS_DECODE_TABLE[i];\n");
    out.push_str("    /* The encoding first: one AND and a compare reject nearly every entry, and\n       the string filters behind it run only for the candidates. */\n");
    out.push_str("    if ((insn & entry->mask) != entry->match) { continue; }\n");
    out.push_str("    if (!axis_decode_mode_ok(entry, mode)) { continue; }\n");
    out.push_str("    if (!axis_decode_unit_ok(entry, unit)) { continue; }\n");
    out.push_str("    if (isa && entry->isa[0] && strcmp(entry->isa, isa) != 0) { continue; }\n");
    out.push_str("    if (entry->definedness) { continue; }\n");
    out.push_str("    if ((insn & entry->mask) == entry->match && axis_decode_constraint_ok(insn, entry->id)) {\n");
    /* Several entries from one scalable origin are one instruction: every
       lane carries the same encoding, which is exactly what the decode
       disjointness rule exempts them from contending over. Decode names lane
       0; a caller that wants the group asks for the lanes. Anything else that
       matches twice is ambiguous. */
    out.push_str("      if (found) {\n");
    out.push_str("        if (!entry->scalable_origin[0] || !found->scalable_origin[0]\n");
    out.push_str("            || strcmp(entry->scalable_origin, found->scalable_origin) != 0) { return NULL; }\n");
    out.push_str("        if (entry->scalable_lane < found->scalable_lane) { found = entry; }\n");
    out.push_str("        continue;\n");
    out.push_str("      }\n");
    out.push_str("      found = entry;\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("  return found;\n");
    out.push_str("}\n\n");
    // The tree walk. It runs the *same* selection rules as the linear decoder
    // -- first match wins, ambiguity is no answer unless the entries are lanes
    // of one scalable instruction, in which case the lowest lane wins -- over
    // the leaf a word reaches instead of over the whole table.
    out.push_str("static inline const axis_decode_entry *axis_decode_in(uint32_t insn, const char *isa, const char *mode, const char *unit) {\n");
    out.push_str("  uint32_t node = 0u;\n");
    out.push_str("  for (;;) {\n");
    out.push_str("    const axis_decode_node *current = &AXIS_DECODE_NODES[node];\n");
    out.push_str("    if (current->mask == 0u) { break; }\n");
    out.push_str("    const uint32_t want = insn & current->mask;\n");
    /* Children are emitted sorted by key, so this is a binary search. */
    out.push_str("    uint32_t lo = current->first, hi = current->first + current->count;\n");
    out.push_str("    uint32_t chosen = 0xffffffffu;\n");
    out.push_str("    while (lo < hi) {\n");
    out.push_str("      const uint32_t mid = lo + ((hi - lo) >> 1);\n");
    out.push_str("      const uint32_t key = AXIS_DECODE_NODES[mid].key;\n");
    out.push_str("      if (key == want) { chosen = mid; break; }\n");
    out.push_str("      if (key < want) { lo = mid + 1u; } else { hi = mid; }\n");
    out.push_str("    }\n");
    /* No child claims this value, and every candidate constrains these bits,
       so no entry in the table can match. */
    out.push_str("    if (chosen == 0xffffffffu) { return NULL; }\n");
    out.push_str("    node = chosen;\n");
    out.push_str("  }\n");
    out.push_str("  const axis_decode_node *leaf = &AXIS_DECODE_NODES[node];\n");
    out.push_str("  const axis_decode_entry *found = NULL;\n");
    out.push_str("  for (uint32_t i = 0; i < leaf->count; ++i) {\n");
    out.push_str("    const axis_decode_entry *entry = &AXIS_DECODE_TABLE[AXIS_DECODE_LEAVES[leaf->first + i]];\n");
    out.push_str("    /* The encoding first: one AND and a compare reject nearly every entry, and\n       the string filters behind it run only for the candidates. */\n");
    out.push_str("    if ((insn & entry->mask) != entry->match) { continue; }\n");
    out.push_str("    if (!axis_decode_mode_ok(entry, mode)) { continue; }\n");
    out.push_str("    if (!axis_decode_unit_ok(entry, unit)) { continue; }\n");
    out.push_str("    if (isa && entry->isa[0] && strcmp(entry->isa, isa) != 0) { continue; }\n");
    out.push_str("    if (entry->definedness) { continue; }\n");
    out.push_str("    if ((insn & entry->mask) == entry->match && axis_decode_constraint_ok(insn, entry->id)) {\n");
    out.push_str("      if (found) {\n");
    out.push_str("        if (!entry->scalable_origin[0] || !found->scalable_origin[0]\n");
    out.push_str("            || strcmp(entry->scalable_origin, found->scalable_origin) != 0) { return NULL; }\n");
    out.push_str("        if (entry->scalable_lane < found->scalable_lane) { found = entry; }\n");
    out.push_str("        continue;\n");
    out.push_str("      }\n");
    out.push_str("      found = entry;\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("  return found;\n");
    out.push_str("}\n\n");
    /* The named doors onto the same selection. `_in_isa` has answered the
       ISA-shaped version of this question all along; `_in_mode` is its twin,
       and both are `_in` with the other argument left open. */
    out.push_str("static inline const axis_decode_entry *axis_decode_in_isa(uint32_t insn, const char *isa) {\n");
    out.push_str("  return axis_decode_in(insn, isa, NULL, NULL);\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_decode_entry *axis_decode_in_mode(uint32_t insn, const char *mode) {\n");
    out.push_str("  return axis_decode_in(insn, NULL, mode, NULL);\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_decode_entry *axis_decode_linear_in_isa(uint32_t insn, const char *isa) {\n");
    out.push_str("  return axis_decode_linear_in(insn, isa, NULL, NULL);\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_decode_entry *axis_decode_linear_in_mode(uint32_t insn, const char *mode) {\n");
    out.push_str("  return axis_decode_linear_in(insn, NULL, mode, NULL);\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_decode_entry *axis_decode(uint32_t insn) {\n");
    out.push_str("  return axis_decode_in(insn, NULL, NULL, NULL);\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_decode_entry *axis_decode_linear(uint32_t insn) {\n");
    out.push_str("  return axis_decode_linear_in(insn, NULL, NULL, NULL);\n");
    out.push_str("}\n\n");
    out.push_str("#ifdef __cplusplus\n}\n#endif\n\n");
    out.push_str(&format!("#endif /* {guard} */\n"));
    out
}

pub fn emit_asm_disasm_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.asm-disasm.v1\",");
    line(
        &mut out,
        1,
        &format!("\"name\": {},", json_string(&document.extension.name)),
    );
    line(
        &mut out,
        1,
        &format!("\"version\": {},", json_string(&document.extension.version)),
    );
    line(&mut out, 1, "\"instructions\": [");
    for (idx, instruction) in document.instructions.iter().enumerate() {
        let layout = layout_for(document, instruction);
        let (match_value, mask_value) = (layout.match_value, layout.mask_value);
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"mnemonic\": {},", json_string(&instruction.mnemonic)),
        );
        // Which ISA the entry belongs to. Two instructions in different ISAs
        // may share a decode word -- their spaces are disjoint by
        // construction, not by encoding -- so a consumer building a
        // disassembler from this file alone cannot scope its search without
        // being told. The decode table has always carried it; this did not,
        // and an AArch64 corpus that also describes an accelerator selected
        // two entries for 223 of its own fixtures.
        line(
            &mut out,
            3,
            &format!("\"isa\": {},", json_string(&instruction.isa)),
        );
        line(
            &mut out,
            3,
            &format!("\"format\": {},", json_string(&instruction.format)),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"opcode_token\": {},",
                json_string(&tablegen_opcode_string(instruction))
            ),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"asm_template\": {},",
                json_string(&instruction_asm(instruction))
            ),
        );
        line(&mut out, 3, "\"decode\": {");
        line(
            &mut out,
            4,
            &format!("\"match\": {},", json_hex_u32(match_value)),
        );
        line(
            &mut out,
            4,
            &format!("\"mask\": {},", json_hex_u32(mask_value)),
        );
        // Match and mask do not always settle it, and neither does the ISA.
        // The validator proves two instructions may share a word when their
        // *modes* are disjoint, or when their units sit in disjoint packet
        // slots, or when a decode predicate separates them -- and the
        // description published none of those, so two instructions that the
        // model knows apart were indistinguishable to anyone reading the file.
        //
        // Empty means unrestricted in both cases, which is what a document
        // without modes or packets means, so nothing is emitted for it and
        // existing output is unchanged.
        if !instruction.modes.is_empty() {
            let modes: Vec<String> = instruction.modes.iter().map(|m| json_string(m)).collect();
            line(
                &mut out,
                4,
                &format!("\"modes\": [{}],", modes.join(", ")),
            );
        }
        if !instruction.unit.trim().is_empty() {
            line(
                &mut out,
                4,
                &format!("\"unit\": {},", json_string(instruction.unit.trim())),
            );
        }
        // An entry can also carry a further predicate, and 103 of the AArch64
        // corpus's do. Selecting on match and mask alone is a disassembler that
        // answers before it has read the whole description.
        if !instruction.decode_requires.trim().is_empty() {
            line(
                &mut out,
                4,
                &format!(
                    "\"decode_requires\": {},",
                    json_string(instruction.decode_requires.trim())
                ),
            );
        }
        if let Some(constraint) = decode_constraint(instruction) {
            line(
                &mut out,
                4,
                &format!("\"decode_constraint\": {},", constraint_json(constraint)),
            );
        }
        line(&mut out, 4, "\"fixed_fields\": {");
        emit_layout_fixed_fields_json(&mut out, &layout, 5);
        line(&mut out, 4, "}");
        line(&mut out, 3, "},");
        line(&mut out, 3, "\"operands\": [");
        for (operand_idx, operand) in instruction.operands.iter().enumerate() {
            emit_asm_operand_json(
                &mut out,
                operand,
                &layout,
                4,
                operand_idx + 1 == instruction.operands.len(),
            );
        }
        line(&mut out, 3, "],");
        line(
            &mut out,
            3,
            &format!(
                "\"operand_print_order\": {}",
                json_list(&asm_operand_placeholders(instruction))
            ),
        );
        let suffix = if idx + 1 == document.instructions.len() {
            ""
        } else {
            ","
        };
        line(&mut out, 2, &format!("}}{suffix}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

fn emit_asm_operand_json(
    out: &mut String,
    operand: &Operand,
    layout: &InstructionLayout,
    indent: usize,
    is_last: bool,
) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"name\": {},", json_string(&operand.name)),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"placeholder\": {},",
            json_string(&format!("${}", operand.name))
        ),
    );
    line(
        out,
        indent + 1,
        &format!("\"kind\": {},", json_string(&operand.kind)),
    );
    line(out, indent + 1, &format!("\"width\": {},", operand.width));
    line(
        out,
        indent + 1,
        &format!(
            "\"role\": {},",
            json_string(crate::ast::operand_role(operand, true))
        ),
    );
    if !operand.derived_from.is_empty() {
        line(
            out,
            indent + 1,
            &format!(
                "\"derived\": {{\"from\": {}, \"add\": {}}},",
                json_string(&operand.derived_from),
                operand.derived_add
            ),
        );
    }
    // ⚠️ How the printed number relates to the encoded field, when they are
    // not the same number. Published HERE above all, because this is the file
    // whose job is spelling: a consumer building a disassembler out of it
    // would otherwise print the field and call it by the assembly's name.
    // `kind` says which relation and `amount` its constant; going back is
    // `k - printed` and `printed - k` respectively, which is why the set is
    // closed to these two.
    match operand.asm_transform {
        crate::ast::AsmTransform::Identity => {}
        crate::ast::AsmTransform::MinusFrom(k) => line(
            out,
            indent + 1,
            &format!("\"asm_transform\": {{\"kind\": \"minus_from\", \"amount\": {k}}},"),
        ),
        crate::ast::AsmTransform::Plus(k) => line(
            out,
            indent + 1,
            &format!("\"asm_transform\": {{\"kind\": \"plus\", \"amount\": {k}}},"),
        ),
    }
    line(out, indent + 1, "\"encoding\": {");
    emit_operand_encoding_json(out, operand, layout, indent + 2);
    line(out, indent + 1, "}");
    let suffix = if is_last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

fn emit_encode_operand_json(
    out: &mut String,
    operand: &Operand,
    layout: &InstructionLayout,
    indent: usize,
    is_last: bool,
) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"name\": {},", json_string(&operand.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"kind\": {},", json_string(&operand.kind)),
    );
    line(out, indent + 1, &format!("\"width\": {},", operand.width));
    line(
        out,
        indent + 1,
        &format!(
            "\"role\": {},",
            json_string(crate::ast::operand_role(operand, true))
        ),
    );
    line(out, indent + 1, "\"encoding\": {");
    emit_operand_encoding_json(out, operand, layout, indent + 2);
    line(out, indent + 1, "}");
    let suffix = if is_last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

fn emit_operand_encoding_json(
    out: &mut String,
    operand: &Operand,
    layout: &InstructionLayout,
    indent: usize,
) {
    let bindings = layout.operand_bindings(&operand.name);
    if bindings.is_empty() {
        if let Some(index) = operand.fixed {
            line(out, indent, "\"field\": \"fixed\",");
            line(out, indent, &format!("\"register\": {index},"));
        } else if !operand.derived_from.is_empty() {
            line(out, indent, "\"field\": \"derived\",");
            line(
                out,
                indent,
                &format!("\"from\": {},", json_string(&operand.derived_from)),
            );
            line(out, indent, &format!("\"add\": {},", operand.derived_add));
        } else {
            line(out, indent, "\"field\": \"unencoded\",");
        }
        line(out, indent, "\"lsb\": null,");
        line(out, indent, "\"width\": 0,");
        line(out, indent, "\"slices\": []");
        return;
    }
    line(
        out,
        indent,
        &format!("\"field\": {},", json_string(&operand.name)),
    );
    // Legacy contiguous view: populated only for a single bit-0-based slice.
    if bindings.len() == 1 && bindings[0].op_lo == 0 {
        line(out, indent, &format!("\"lsb\": {},", bindings[0].insn_lo));
    } else {
        line(out, indent, "\"lsb\": null,");
    }
    let total_width: u32 = bindings.iter().map(|binding| binding.width).sum();
    line(out, indent, &format!("\"width\": {total_width},"));
    let slices: Vec<String> = bindings
        .iter()
        .map(|binding| {
            format!(
                "{{\"op_lsb\": {}, \"lsb\": {}, \"width\": {}}}",
                binding.op_lo, binding.insn_lo, binding.width
            )
        })
        .collect();
    line(out, indent, &format!("\"slices\": [{}]", slices.join(", ")));
}

fn emit_layout_fixed_fields_json(out: &mut String, layout: &InstructionLayout, indent: usize) {
    for (idx, field) in layout.fixed_fields.iter().enumerate() {
        let suffix = if idx + 1 == layout.fixed_fields.len() {
            ""
        } else {
            ","
        };
        line(
            out,
            indent,
            &format!("{}: {}{}", json_string(&field.name), field.value, suffix),
        );
    }
}

fn width_mask32(width: u32) -> u32 {
    if width >= 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    }
}

/// Pick a deterministic value satisfying a simple unsigned constraint on one
/// operand. Boolean constraints are traversed in source order, so an `any`
/// constraint selects its first legal alternative while `all` constraints can
/// still contribute per-operand bounds.
fn constrained_operand_sample(constraint: &DecodeConstraint, operand_name: &str) -> Option<u32> {
    match constraint {
        DecodeConstraint::UnsignedCompare {
            operand,
            op,
            literal,
        } if operand == operand_name => Some(match op {
            CompareOp::Eq | CompareOp::Le | CompareOp::Ge => *literal,
            CompareOp::Ne => u32::from(*literal == 0),
            CompareOp::Lt => literal.saturating_sub(1),
            CompareOp::Gt => literal.saturating_add(1),
        }),
        DecodeConstraint::MaskedEq {
            operand,
            mask: _,
            value,
        } if operand == operand_name => Some(*value),
        DecodeConstraint::And(children) | DecodeConstraint::Or(children) => children
            .iter()
            .find_map(|child| constrained_operand_sample(child, operand_name)),
        _ => None,
    }
}

/// Deterministic sample value for roundtrip fixtures, masked to the bits the
/// layout can actually encode so encode -> decode recovers it exactly.
fn sample_operand_value(
    instruction: &Instruction,
    layout: &InstructionLayout,
    idx: usize,
    operand: &Operand,
) -> u32 {
    if let Some(index) = operand.fixed {
        return index;
    }
    if !operand.derived_from.is_empty() {
        let source_index = instruction
            .operands
            .iter()
            .position(|candidate| candidate.name == operand.derived_from)
            .expect("validated derived operand source");
        return sample_operand_value(
            instruction,
            layout,
            source_index,
            &instruction.operands[source_index],
        )
        .wrapping_add(operand.derived_add);
    }
    let mut seed = idx as u32 + 1;
    if let Some(constraint) = decode_constraint(instruction) {
        if let Some(value) = constrained_operand_sample(constraint, &operand.name) {
            seed = value;
        }
    }
    match decode_constraint(instruction) {
        Some(DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        }) => {
            if shift == &operand.name {
                seed = seed.min(2);
            } else if amount == &operand.name {
                seed = seed.min(width.saturating_sub(1));
            }
        }
        Some(DecodeConstraint::A64ExtendedRegister { amount }) if amount == &operand.name => {
            seed = seed.min(4);
        }
        _ => {}
    }
    let mut encodable_mask = 0u32;
    for binding in layout.operand_bindings(&operand.name) {
        encodable_mask |= width_mask32(binding.width) << binding.op_lo;
    }
    seed & encodable_mask
}

fn encode_sample_instruction(instruction: &Instruction, layout: &InstructionLayout) -> u32 {
    let mut encoded = layout.match_value;
    for (idx, operand) in instruction.operands.iter().enumerate() {
        let value = sample_operand_value(instruction, layout, idx, operand);
        for binding in layout.operand_bindings(&operand.name) {
            let slice = (value >> binding.op_lo) & width_mask32(binding.width);
            encoded = (encoded & !(width_mask32(binding.width) << binding.insn_lo))
                | (slice << binding.insn_lo);
        }
    }
    encoded
}

fn json_roundtrip_operand_values(instruction: &Instruction, layout: &InstructionLayout) -> String {
    let items: Vec<String> = instruction
        .operands
        .iter()
        .enumerate()
        .map(|(idx, operand)| {
            let field = if operand.fixed.is_some() {
                "fixed"
            } else if !operand.derived_from.is_empty() {
                "derived"
            } else if layout.operand_bindings(&operand.name).is_empty() {
                "unencoded"
            } else {
                operand.name.as_str()
            };
            format!(
                "{{\"name\": {}, \"value\": {}, \"field\": {}}}",
                json_string(&operand.name),
                sample_operand_value(instruction, layout, idx, operand),
                json_string(field)
            )
        })
        .collect();
    format!("[{}]", items.join(", "))
}

fn roundtrip_blocking_names(layout: &InstructionLayout) -> Vec<String> {
    let mut names = layout.unencoded_operands.clone();
    for field in &layout.unbound_fields {
        if !names.iter().any(|existing| existing == field) {
            names.push(field.clone());
        }
    }
    names
}

fn roundtrip_skip_reason(layout: &InstructionLayout) -> &'static str {
    if !layout.unencoded_operands.is_empty() {
        "unencoded_operand"
    } else if !layout.unbound_fields.is_empty() {
        "unbound_field"
    } else {
        "unsupported_encoding"
    }
}

/// A stable, exported C ABI over the generated decoder, for scripts.
///
/// The decode and encode headers are header-only `static inline`, which a
/// foreign-function binding cannot see: there is no symbol to look up. This
/// emits the one translation unit that gives them symbols.
///
/// Every entry point is **flat and index-based** -- integers, `uint32_t`, and
/// `const char *` only, no struct crossing the boundary. That is deliberate.
/// A binding that reads `axis_decode_entry` through ctypes has to restate the
/// struct's layout in Python, and a field added to the C side then silently
/// shifts what the Python side reads. An index has no layout to get wrong.
///
/// The index is into both tables at once, which holds because both are emitted
/// from `architectural_instructions` in that order. `axis_abi_tables_aligned`
/// is that assumption made checkable rather than assumed: it walks both tables
/// and compares mnemonics, so a future change to either emitter fails a gate
/// instead of silently returning another instruction's operands.
/// The arch-pack contract: one header, identical for every description.
///
/// ⚠️ This is the file that makes packs COMPOSABLE, and it exists because the
/// previous ABI was not. `emit-decode-abi-c` gives every description the same
/// symbol names, so two packs in one program collide -- and not loudly: the
/// linker takes the first archive member that satisfies each symbol and never
/// looks at the second, so the program gets one architecture and is told
/// nothing.
///
/// ⚠️ And it declares SEVERAL tables, one per library, rather than one table
/// with capability flags. The flags were the first version and they lied
/// immediately: `AXIS_PACK_HAS_ASSEMBLE` shipped set on every pack while the
/// table carried no assemble pointer. A library either exists on disk or does
/// not, which is a fact a host can check without trusting anything the pack
/// says about itself -- and a consumer that wants only a disassembler links
/// only the decoder rather than dragging an assembler behind it.
pub fn emit_pack_abi_c(_document: &Document) -> String {
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. The arch-pack ABI: one contract, every description. */\n");
    out.push_str("/* schema: axis.pack-abi-c.v1 */\n");
    out.push_str("#ifndef AXIS_PACK_H\n#define AXIS_PACK_H\n\n");
    out.push_str("#include <stdint.h>\n#include <stddef.h>\n\n");
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    out.push_str("/* Bumped when a table below changes shape. A host compares it against\n   what a library reports and refuses one it cannot read, rather than\n   calling through a pointer that means something else now. */\n");
    // v2: AXIS_PACK_MAX_OPERANDS 32 -> 64, which changes axis_pack_lifted's
    // layout. SVE's lane expansion reached 53 -- a flag-setting byte compare
    // reads sixteen predicate lanes beside its sixteen data lanes.
    // v3: axis_sim_pack gains `traps` (E3, execution-driven precise traps);
    // axis_sim_predictor's speculative-history calls (E2) ride on its own
    // abi_version.
    // v4: axis_sim_pack gains `run_cores` and `snoops` (MC1, several
    // execution-driven cores over one memory).
    // v5: axis_sim_pack gains `cycle_cores` and `memsys_handle`, and
    // axis_sim_core `memory_timed` (U3, docs/unified_engine_design.md).
    // v6: AXIS_PACK_MAX_TOUCH 16 -> 64, and axis_pack_sim_event gains the
    // true counts its clamped arrays may not hold (VM3, SVE and SME).
    // v7: axis_sim_pack gains `share_core` (U4a, hardware contexts), and
    // `set_warp` and `warp_rides` (U4b, a warp as contexts sharing one front
    // end).
    // v8: axis_sim_pack gains `share_unit` (VU4, one unit shared by several
    // cores: docs/vector_units_design.md).
    out.push_str("#define AXIS_PACK_ABI_VERSION 11u\n\n");
    out.push_str("/* Every library exports one symbol, `axis_<facet>_pack_<name>`, and nothing\n   else. The name comes from the description, so a base architecture and an\n   extension never collide -- which is the whole reason for the indirection. */\n\n");

    out.push_str("/* ---- decoding: what a disassembler needs ------------------------- */\n");
    out.push_str("typedef struct axis_decode_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("\n  int32_t (*count)(void);\n");
    out.push_str("\n  /* Word to instruction index, or -1. `isa` may be NULL, and then a word\n     two ISAs both claim decodes to nothing rather than to a guess. */\n");
    out.push_str("  int32_t (*decode)(uint32_t insn, const char *isa);\n");
    out.push_str("  int32_t (*decode_linear)(uint32_t insn, const char *isa);\n");
    out.push_str("  int32_t (*decode_buffer)(const uint32_t *words, int32_t count, const char *isa, int32_t *out);\n");
    out.push_str("  int32_t (*decode_le)(const uint8_t *bytes, int32_t byte_count, const char *isa, int32_t *out);\n");
    out.push_str("  int32_t (*decode_stream)(const uint8_t *bytes, int32_t byte_count, const char *isa, int32_t *out_offset, int32_t *out_index, int32_t *out_bytes, int32_t limit);\n");
    out.push_str("\n  /* What an instruction index names. NULL or 0 out of range. */\n");
    out.push_str("  const char *(*mnemonic)(int32_t index);\n");
    out.push_str("  const char *(*isa)(int32_t index);\n");
    out.push_str("  const char *(*format)(int32_t index);\n");
    out.push_str("  const char *(*asm_syntax)(int32_t index);\n");
    out.push_str("  uint32_t (*match)(int32_t index);\n");
    out.push_str("  uint32_t (*mask)(int32_t index);\n");
    out.push_str("  uint32_t (*bits)(int32_t index);\n");
    out.push_str("\n  int32_t (*operand_count)(int32_t index);\n");
    out.push_str("  const char *(*operand_name)(int32_t index, int32_t operand);\n");
    out.push_str("  const char *(*operand_kind)(int32_t index, int32_t operand);\n");
    out.push_str("  const char *(*operand_role)(int32_t index, int32_t operand);\n");
    out.push_str("  uint32_t (*operand_value)(uint32_t insn, int32_t index, int32_t operand);\n");
    out.push_str("  int32_t (*operands_buffer)(const uint32_t *words, const int32_t *indices, int32_t count, int32_t stride, uint32_t *out);\n");
    out.push_str("\n  int32_t (*tables_aligned)(void);\n");
    out.push_str("} axis_decode_pack;\n\n");

    out.push_str("/* ---- disassembling: a word to the text it is ---------------------\n\n   Separate from the decoder because turning a word into TEXT needs more than\n   its tables: the spelling of a register, and the number an operand prints\n   where that is not the field it is encoded in. And separate from the\n   assembler because reading code should not mean linking something that\n   writes it. */\n");
    out.push_str("typedef struct axis_disasm_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("\n  int32_t (*count)(void);\n");
    out.push_str("\n  /* A word to its assembly, in one call. Returns 0 when the word decodes\n     to nothing, or to more than this pack can tell apart. */\n");
    out.push_str("  int32_t (*disassemble)(uint32_t word, const char *isa, char *out, size_t size);\n");
    out.push_str("\n  /* And the pieces, for a consumer that wants them separately. */\n");
    out.push_str("  int32_t (*decode)(uint32_t word, const char *isa);\n");
    out.push_str("  int32_t (*print)(int32_t index, const uint32_t *operand_values, char *out, size_t size);\n");
    out.push_str("  const char *(*mnemonic)(int32_t index);\n");
    out.push_str("  int32_t (*operand_count)(int32_t index);\n");
    out.push_str("  uint32_t (*operand_value)(uint32_t word, int32_t index, int32_t operand);\n");
    out.push_str("} axis_disasm_pack;\n\n");
    out.push_str("/* ---- assembling: the other direction ----------------------------- */\n");
    out.push_str("typedef struct axis_asm_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("\n  int32_t (*count)(void);\n");
    out.push_str("  const char *(*mnemonic)(int32_t index);\n");
    out.push_str("  const char *(*asm_syntax)(int32_t index);\n");
    out.push_str("  int32_t (*operand_count)(int32_t index);\n");
    out.push_str("  const char *(*operand_name)(int32_t index, int32_t operand);\n");
    out.push_str("  const char *(*operand_kind)(int32_t index, int32_t operand);\n");
    out.push_str("\n  /* Operand values to a word. Returns 0 and leaves `out` alone when the\n     values do not satisfy the instruction's encoding constraints, which is\n     a refusal rather than a wrong word. */\n");
    out.push_str("  int32_t (*assemble)(int32_t index, const uint32_t *operand_values, uint32_t *out);\n");
    out.push_str("\n  /* The number the assembly PRINTS for an encoded field, and the field an\n     assembler must place for a printed number. They differ where an operand\n     declares a transform -- AArch64's fixed-point `SCVTF` encodes `scale`\n     and prints `fbits`, which is 64 minus it. */\n");
    out.push_str("  int64_t (*operand_printed)(int32_t index, int32_t operand, uint32_t field);\n");
    out.push_str("  int64_t (*operand_encoded)(int32_t index, int32_t operand, int64_t printed);\n");
    out.push_str("  /* The field's width in bits, and how many of them the description\n     sign extends (0 when it does not). A printed number that does not fit\n     these is text no assembler should have written. */\n");
    out.push_str("  uint32_t (*operand_bits)(int32_t index, int32_t operand);\n");
    out.push_str("  uint32_t (*operand_signed_bits)(int32_t index, int32_t operand);\n");
    out.push_str("\n  /* Text, both ways.\n\n     `print` writes the assembly for an instruction and its operand values;\n     `parse` reads that text back into an instruction index and values, and\n     returns 0 when nothing matches. Together with `assemble` that is a whole\n     assembler: text to a word, generated from the description rather than\n     written against it.\n\n     ⚠️ The register SPELLING is the one the description states -- an ISA\n     declaring `x[32]` names its registers `x0`..`x31`. ABI aliases like\n     RISC-V's `a0` or AArch64's `sp` are stated by no description, so nothing\n     here prints or accepts them. That is a gap in the descriptions, not in\n     the generator. */\n");
    out.push_str("  int32_t (*print)(int32_t index, const uint32_t *operand_values, char *out, size_t size);\n");
    out.push_str("  int32_t (*parse)(const char *text, int32_t *index, uint32_t *operand_values);\n");
    out.push_str("} axis_asm_pack;\n\n");

    out.push_str("/* ---- shared shapes: what the lifter and the executor traffic in ---\n\n   ⚠️ These live HERE rather than in the generated headers, and that is what\n   makes a lifter or an executor packageable at all. `axis_lift.h` and\n   `axis_exec.h` are `static inline` throughout: nothing collides at link\n   time, but two descriptions cannot share a translation unit, because\n   `axis_lift_entry`, `axis_mem64`, `axis_exec_result64` and five more types\n   would be redefined and every static table would clash.\n\n   So a pack is an ADAPTER. Each library compiles its own description's\n   headers into its own translation unit and exposes these shapes, which\n   derive from no document. Two architectures share only this file. */\n\n");
    out.push_str("/* Bounds the contract fixes, so a host can size an array without knowing\n   which description it will be handed. Measured against every corpus in the\n   repository: the widest instruction has 53 operands (a lane of SVE's\n   flag-setting byte compare, ABI v2 raised the bound from 32) and the widest\n   register 2 limbs. A pack whose description outgrows these fails to COMPILE, on a\n   `_Static_assert` naming the bound -- not at run time, and never by\n   truncating a value to fit. */\n");
    out.push_str("#define AXIS_PACK_MAX_OPERANDS 64u\n");
    out.push_str("#define AXIS_PACK_MAX_LIMBS     8u\n\n");
    out.push_str("/* One decoded instruction: which one, and what its operands hold. */\n");
    out.push_str("typedef struct axis_pack_lifted {\n");
    out.push_str("  int32_t index;                                 /* -1 when nothing decodes */\n");
    out.push_str("  int32_t operand_count;\n");
    out.push_str("  uint32_t operands[AXIS_PACK_MAX_OPERANDS];\n");
    out.push_str("  uint8_t operand_valid[AXIS_PACK_MAX_OPERANDS]; /* an operand the word does not carry */\n");
    out.push_str("} axis_pack_lifted;\n\n");

    out.push_str("/* One instruction, as a walk over BYTES finds it.\n\n   The lifter answers about a word a caller already has. A consumer holding\n   an image has bytes, and the step between two instructions is the thing it\n   cannot compute itself: a description whose instructions are not all one\n   width -- RISC-V with the compressed extension -- misaligns after the first\n   16-bit instruction, and every word after it then decodes to nothing, which\n   reads as a description that is missing them.\n\n   ⚠️ `ends_block` has THREE values, and a consumer that treats it as a\n   boolean is right about two of them. See `ends_block()` below. */\n");
    out.push_str("typedef struct axis_pack_walked {\n");
    out.push_str("  int32_t offset;                                /* bytes from the start of the buffer */\n");
    out.push_str("  uint64_t address;                              /* what the caller called the buffer's start, plus that */\n");
    out.push_str("  int32_t bytes;                                 /* what this instruction took */\n");
    out.push_str("  uint32_t word;                                 /* assembled little-endian, for a caller that wants to print it */\n");
    out.push_str("  int32_t index;                                 /* -1 when nothing decodes here */\n");
    out.push_str("  int32_t ends_block;\n");
    out.push_str("  int32_t operand_count;\n");
    out.push_str("  uint32_t operands[AXIS_PACK_MAX_OPERANDS];\n");
    out.push_str("  uint8_t operand_valid[AXIS_PACK_MAX_OPERANDS];\n");
    out.push_str("} axis_pack_walked;\n\n");
    out.push_str("/* The memory a host lends an executor.\n\n   ⚠️ A value wider than the word arrives as several accesses of the word's\n   width, which is what a bus does. The generated executor can take a wide\n   access in one call when a host offers one; this contract does not carry\n   that hook, so a pack leaves it unset and the executor splits. Correct\n   either way, and a host that wants to see the wide access as one event\n   links the executor directly rather than through a pack. */\n");
    out.push_str("typedef struct axis_pack_mem {\n");
    out.push_str("  uint64_t (*read)(void *ctx, uint64_t addr, uint32_t width);\n");
    out.push_str("  void (*write)(void *ctx, uint64_t addr, uint64_t value, uint32_t width);\n");
    out.push_str("  void *ctx;\n} axis_pack_mem;\n\n");
    out.push_str("/* One named scalar of architectural state -- a flag word, a rounding mode,\n   an exclusive monitor. Register files are addressed through operands. */\n");
    out.push_str("typedef struct axis_pack_state_entry {\n");
    out.push_str("  const char *name;\n  uint64_t value;\n  uint32_t width;\n");
    out.push_str("} axis_pack_state_entry;\n\n");
    out.push_str("/* What executing one instruction did. */\n");
    out.push_str("typedef struct axis_pack_exec_result {\n");
    out.push_str("  const char *mnemonic;\n");
    out.push_str("  uint64_t result;                            /* the low limb, always */\n");
    out.push_str("  uint64_t result_limb[AXIS_PACK_MAX_LIMBS];  /* a value wider than the word */\n");
    out.push_str("  uint32_t result_limbs;                      /* 0 for an ordinary answer */\n");
    out.push_str("  int32_t wrote;\n  uint32_t dest;\n  uint32_t dest_slot;\n");
    out.push_str("  const char *state_name;\n  uint64_t state_value;\n");
    out.push_str("  uint64_t next_pc;\n");
    out.push_str("  int32_t trapped;\n  const char *trap_cause;\n");
    out.push_str("  int32_t ok;                                 /* 0 when this build cannot perform it */\n");
    out.push_str("} axis_pack_exec_result;\n\n");

    // ⚠️ In the PACK's types, not the executor's. A host that loads a pack has
    // `axis_pack.h` and nothing else -- it cannot see `axis_lifted` or
    // `axis_mem64`, which are the generated executor's and differ per
    // description in the sizes they carry. So a routine speaks the contract
    // every library here speaks, and the pack translates at the boundary.
    out.push_str("/* What performs an instruction the description NAMES a routine for and\n   does not describe -- pointer authentication, a cryptographic round, a\n   random number. The same shape a generated effect has: the decoded word,\n   the register file, memory, the pc, architectural state, and the result to\n   report through.\n\n   ⚠️ A pack is built before the program that loads it exists, so \"link the\n   real one\" is not an answer a shipped library can offer. `register_routine`\n   is how a host supplies it, and until it does, the instruction traps with\n   the same cause an undescribed one reports. */\n");
    out.push_str("typedef void (*axis_pack_routine)(const axis_pack_lifted *lifted,\n                                  uint64_t *regs, int32_t reg_count,\n                                  const axis_pack_mem *mem, uint64_t pc,\n                                  axis_pack_state_entry *state, int32_t state_count,\n                                  axis_pack_exec_result *out);\n\n");

    out.push_str("/* ---- lifting: a word to what it says -----------------------------\n\n   ⚠️ This table is NOT the decoder's, and `count()` differs. A scalable\n   instruction is lifted once per lane -- `VADD_VV__l0`, `__l1`, ... -- because\n   an executor performs each lane, while a disassembler wants the instruction\n   the lanes elaborate and the decoder carries `VADD_VV`. So the same word\n   names different things through the two libraries, on purpose: strip the\n   `__l<N>` suffix to get from one to the other. A consumer that expected them\n   to agree would be right about every fixed-width architecture and wrong about\n   every scalable one. */\n\n");
    out.push_str("typedef struct axis_lift_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("\n  int32_t (*count)(void);\n");
    out.push_str("  int32_t (*lift)(uint32_t word, const char *isa, axis_pack_lifted *out);\n");
    out.push_str("  const char *(*mnemonic)(int32_t index);\n");
    out.push_str("  const char *(*isa)(int32_t index);\n");
    out.push_str("  int32_t (*operand_count)(int32_t index);\n");
    out.push_str("  const char *(*operand_name)(int32_t index, int32_t operand);\n");
    out.push_str("  const char *(*operand_kind)(int32_t index, int32_t operand);\n");
    out.push_str("  const char *(*operand_role)(int32_t index, int32_t operand);\n");
    out.push_str("  uint32_t (*operand_width)(int32_t index, int32_t operand);\n");
    out.push_str("  /* ⚠️ Which slot of the flat register file an operand's value names.\n     Not the value: a compressed field's 1 is `x9`, a class can start\n     partway up the file, and a consumer that indexed the file with the\n     field would read the wrong register and get a plausible answer. */\n");
    out.push_str("  uint32_t (*register_slot)(int32_t index, int32_t operand, uint32_t value);\n");
    out.push_str("  /* Whether this build can lift the instruction's effects at all. */\n");
    out.push_str("  int32_t (*liftable)(int32_t index);\n");
    out.push_str("  /* How wide this instruction's ENCODING is, in bits. Not the machine's\n     word: a 64-bit machine's instructions are 32 bits, and a compressed one\n     is 16 in the same table. */\n");
    out.push_str("  uint32_t (*instruction_bits)(int32_t index);\n");
    out.push_str("  /* Whether control may leave a block at this instruction.\n\n       0 -- no. The description says what it does and none of it is the pc.\n       1 -- yes: it writes the pc, or it traps.\n       2 -- ⚠️ THIS BUILD CANNOT SAY. An instruction performed by a routine the\n            description only NAMES may be anything, including a branch --\n            AArch64's `braaz` authenticates a pointer and jumps to it, and its\n            whole description is one line of prose. A walker that read this as\n            0 would stride past a branch and call what follows a basic block. */\n");
    out.push_str("  int32_t (*ends_block)(int32_t index);\n");
    out.push_str("  /* Walk a buffer, one row per INSTRUCTION rather than per word. Returns\n     how many rows were filled, or -1 on a bad argument. A run of bytes that\n     decodes to nothing is reported with `index` -1 and stepped over by the\n     narrowest instruction the description has -- a real section has data in\n     it, and stopping at the first byte that is not an instruction would end\n     every walk at the first literal pool. */\n");
    out.push_str("  int32_t (*walk)(const uint8_t *bytes, int32_t byte_count, uint64_t base,\n                  const char *isa, axis_pack_walked *out, int32_t limit);\n");
    out.push_str("  /* The same walk, stopped after the first instruction that ends a block.\n     What a consumer lifting to IR asks for, and the answer a JIT needs before\n     it can translate anything. */\n");
    out.push_str("  int32_t (*block)(const uint8_t *bytes, int32_t byte_count, uint64_t base,\n                   const char *isa, axis_pack_walked *out, int32_t limit);\n");
    out.push_str("} axis_lift_pack;\n\n");

    out.push_str("/* ---- executing: a machine -------------------------------------- */\n");
    out.push_str("typedef struct axis_exec_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("\n  /* How big a register file this description needs, and which named\n     scalars of state it reads. A host sizes its arrays from these. */\n");
    out.push_str("  int32_t (*register_slots)(void);\n");
    out.push_str("  int32_t (*state_slots)(void);\n");
    out.push_str("  const char *(*state_name)(int32_t slot);\n");
    out.push_str("  uint32_t (*state_width)(int32_t slot);\n");
    out.push_str("\n  /* One instruction. Returns 0 when the word does not decode or this\n     build cannot perform it, and `out->ok` says which. */\n");
    out.push_str("  int32_t (*step)(uint32_t word, const char *isa, uint64_t *regs, int32_t reg_count,\n                  const axis_pack_mem *mem, uint64_t pc,\n                  axis_pack_state_entry *state, int32_t state_count,\n                  axis_pack_exec_result *out);\n");
    out.push_str("  /* The routines this description names and does not describe. A host binds\n     one by the name the description gives it -- `register_routine` returns how\n     many instructions that name covered, and 0 when the pack names no such\n     routine, so a typo is reported rather than silently ignored.\n\n     ⚠️ Registration is not thread-safe and is not meant to be: bind before\n     the first step, from the thread that loaded the pack. */\n  int32_t (*routine_count)(void);\n  const char *(*routine_name)(int32_t slot);\n  const char *(*routine_mnemonic)(int32_t slot);\n  int32_t (*register_routine)(const char *name, axis_pack_routine fn);\n");
    out.push_str("} axis_exec_pack;\n\n");

    out.push_str("/* ---- a copy-and-patch JIT ----------------------------------------\n\n   One stencil per instruction, compiled ahead of time with its operands left\n   as holes a relocation names. Translation is `memcpy` plus a few stores:\n   copy each stencil's bytes, patch the holes to point at a block of operand\n   slots, fill the slots. The compile happened at build time.\n\n   ⚠️ Unlike the other libraries this one carries HOST machine code, so its\n   bytes are for the machine that built it. The pack directory says which.\n   `translate` writes into a buffer the caller supplies and tells it how much\n   it used; mapping that buffer executable, crossing a write-protect gate and\n   invalidating the instruction cache are the host's policy and stay the\n   host's. */\n");
    out.push_str("/* Where the machine's parts live, for a stencil that touches them.\n\n   ⚠️ An instruction that only computes needs the register file and nothing\n   else. One that LOADS needs the memory it reads; one that reports a\n   conditional write needs somewhere to report it; one that reads a rounding\n   mode needs the state. Those addresses are the machine's, not the\n   instruction's, so they are given once for a whole block rather than per\n   operand.\n\n   ⚠️ Translated code accesses `memory` RAW -- the address an instruction\n   computes, with no bound applied. A host that hands over a buffer must be\n   able to answer for every address the block can reach. That is the price of\n   there being no call in the emitted code, and it is the caller's to pay. */\n");
    out.push_str("/* ⚠️ `memory_mask` is what turns `memory` from a PROMISE into a BOUND.\n\n   Translated code computes an address and uses it -- there is no call in the\n   emitted bytes to put a check in -- so a host that named a buffer was\n   answering for every address the program could reach, and could not. Every\n   interpreter here already masks: the executors reach memory through a host\n   hook, and every host writes `buffer[(addr + i) & MASK]`.\n\n   So translated code masks too, with this. A window of `n` bytes is\n   `memory_mask = n - 1` and `n` a power of two; an address outside it wraps\n   to inside it, which is what the interpreter does, so the two engines agree\n   about a program that runs off the end rather than one of them dying.\n\n   ⚠️ Zero means a window of one byte, not \"unbounded\". A host that wants the\n   old behaviour asks for it by name: all ones. */\n");
    out.push_str("typedef struct axis_jit_machine {\n");
    out.push_str("  uint64_t registers;        /* the flat register file */\n");
    out.push_str("  uint64_t memory;           /* byte-addressed, indexed by the address computed */\n");
    out.push_str("  uint64_t scratch;          /* what an effect reports: value, wrote, next pc, trap */\n");
    out.push_str("  uint64_t state;            /* one slot per declared state name */\n");
    out.push_str("  uint64_t memory_mask;      /* every address is `and`-ed with this */\n");
    out.push_str("} axis_jit_machine;\n\n");
    out.push_str("typedef struct axis_jit_op {\n");
    out.push_str("  int32_t stencil;            /* which stencil, from `stencil_for` */\n");
    out.push_str("  const uint64_t *values;     /* one per operand hole, in order */\n");
    out.push_str("  int32_t value_count;\n");
    out.push_str("  uint64_t pc;                /* this instruction's address, for one that reads it */\n");
    out.push_str("} axis_jit_op;\n\n");
    out.push_str("typedef struct axis_jit_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("  const char *host;           /* the machine these bytes run on */\n");
    out.push_str("\n  int32_t (*count)(void);\n");
    out.push_str("  /* The stencil for an instruction, or -1 when there is none -- a\n     branch, a trap, anything a block ends on rather than carries. */\n");
    out.push_str("  int32_t (*stencil_for)(const char *mnemonic);\n");
    out.push_str("  const char *(*mnemonic)(int32_t stencil);\n");
    out.push_str("  /* How many holes a stencil has, machine pointers and operands\n     together. `values` is how many the CALLER supplies; the rest the\n     library fills from `axis_jit_machine`. */\n");
    out.push_str("  int32_t (*holes)(int32_t stencil);\n");
    out.push_str("  int32_t (*values)(int32_t stencil);\n");
    out.push_str("  /* Whether this stencil touches memory or state -- whether a caller\n     has to mean the addresses it passes, rather than pass zero. */\n");
    out.push_str("  int32_t (*effectful)(int32_t stencil);\n");
    out.push_str("  /* How wide a slot of `scratch` and `state` is for this stencil, and\n     how many slots `scratch` needs. A machine's word, not always 64:\n     RV32I's handlers report through 32-bit slots. Zero when the stencil\n     touches neither. */\n");
    out.push_str("  int32_t (*word_bits)(int32_t stencil);\n");
    out.push_str("  int32_t (*scratch_slots)(void);\n");
    out.push_str("  /* ⚠️ Whether this stencil READS architectural state, which is not\n     the same as having a hole for it: the hole is in the IR and the\n     compiler drops it when nothing uses it. */\n");
    out.push_str("  int32_t (*reads_state)(int32_t stencil);\n");
    out.push_str("  /* What hole `index` binds: a machine part by its name -- \"regs\",\n     \"mem\", \"out\", \"state\", \"pc\" -- or an operand by ITS name. A\n     consumer fills `values` by name rather than by guessing the order\n     AXIS happened to emit the stencils in. */\n");
    out.push_str("  const char *(*hole)(int32_t stencil, int32_t index);\n");
    out.push_str("\n  /* Lay `count` stencils into `buffer`, patched to run at `exec_base`.\n     Returns 0 when the buffer is too small or an op names no stencil.\n     `out_used` receives the total bytes, code and operand slots together. */\n");
    out.push_str("  int32_t (*translate)(const axis_jit_op *ops, int32_t count,\n                       uint8_t *buffer, size_t size, uint64_t exec_base,\n                       const axis_jit_machine *machine, size_t *out_used);\n");
    out.push_str("} axis_jit_pack;\n\n");
    out.push_str("/* ---- simulating: a machine that runs a program ------------------\n\n   The executor steps one word a caller has already fetched. A SIMULATOR\n   fetches, decides what a trap does, and reports what each instruction did\n   -- which is the difference between something a host drives and something\n   that runs. Everything the host owns is a hook; everything the\n   description owns is inside. */\n\n");
    out.push_str("#define AXIS_PACK_MAX_TOUCH   64u\n");
    out.push_str("#define AXIS_PACK_MAX_ACCESS  16u\n\n");
    out.push_str("/* One memory access an instruction made, in the order it made it. */\n");
    out.push_str("typedef struct axis_pack_access {\n  uint64_t addr;\n  uint64_t value;\n  uint32_t width;\n  int32_t is_write;\n  uint64_t limb[AXIS_PACK_MAX_LIMBS];  /* wider than the word, low first */\n  uint32_t limbs;                      /* 0 for an ordinary access */\n} axis_pack_access;\n\n");
    out.push_str("/* What one instruction did. Enough to trace, to count, or to drive a\n   timing model: what it read and wrote are not semantic facts -- the\n   answer is the same without them -- which is why they are on the event\n   rather than in the result. */\n");
    out.push_str("typedef struct axis_pack_sim_event {\n");
    out.push_str("  uint64_t pc;\n  uint32_t word;\n  const char *mnemonic;   /* NULL when it did not decode */\n");
    out.push_str("  int32_t ok;\n  int32_t wrote;\n  uint32_t dest;\n  uint32_t write_slot;\n");
    out.push_str("  uint64_t result;\n  uint64_t result_limb[AXIS_PACK_MAX_LIMBS];\n  uint32_t result_limbs;\n");
    out.push_str("  const char *trap_cause; /* NULL unless it trapped */\n  uint64_t next_pc;\n");
    out.push_str("  uint32_t reads[AXIS_PACK_MAX_TOUCH];\n  int32_t read_count;\n");
    out.push_str("  uint32_t writes[AXIS_PACK_MAX_TOUCH];\n  int32_t write_count;\n");
    out.push_str("  axis_pack_access accesses[AXIS_PACK_MAX_ACCESS];\n  int32_t access_count;\n");
    out.push_str("  /* ⚠️ abi_version 6 (VM3): HOW MANY THERE WERE. The three counts above\n     are how many entries the arrays HOLD, never more than their size. A\n     512-bit instruction reads more registers and makes more accesses than\n     a fixed record carries -- an SME store is 64 byte lanes -- and these\n     say so: a total above its count is an event that lost entries, and a\n     consumer that needs every one must not trust it. Equal on every\n     scalar description. */\n");
    out.push_str("  int32_t reads_total;\n  int32_t writes_total;\n  int32_t accesses_total;\n");
    out.push_str("} axis_pack_sim_event;\n\n");
    out.push_str("/* ⚠️ `fetch` is not `read`. An instruction fetch is not a data access:\n   a host may serve it from another space, or refuse it. `trap` is what\n   makes this a machine rather than a harness -- it decides where a raised\n   trap goes and whether the machine stops. */\n");
    out.push_str("typedef struct axis_pack_sim_hooks {\n");
    out.push_str("  uint64_t (*read)(void *ctx, uint64_t addr, uint32_t width);\n");
    out.push_str("  void (*write)(void *ctx, uint64_t addr, uint64_t value, uint32_t width);\n");
    out.push_str("  uint32_t (*fetch)(void *ctx, uint64_t pc, int32_t *ok);\n");
    out.push_str("  uint64_t (*trap)(void *ctx, const char *cause, uint64_t pc, int32_t *stop);\n");
    out.push_str("  void (*retire)(void *ctx, const axis_pack_sim_event *event);\n");
    out.push_str("  void *ctx;\n} axis_pack_sim_hooks;\n\n");
    out.push_str("/* What stopped it. `RUNNING` means nothing has. */\n");
    out.push_str("enum {\n  AXIS_PACK_SIM_RUNNING = 0,\n  AXIS_PACK_SIM_HALTED = 1,\n  AXIS_PACK_SIM_UNDECODED = 2,\n  AXIS_PACK_SIM_UNSUPPORTED = 3,\n  AXIS_PACK_SIM_STEP_LIMIT = 4\n};\n\n");
    out.push_str("/* What a host must say before its machine may be JIT-ted.\n\n   ⚠️ `memory_base` is a PROMISE, not a bound. Translated code computes an\n   address and uses it -- there is no call in the emitted bytes, so there is\n   nothing to put a check in -- which means a host that names a buffer here is\n   answering for every address the program can compute. Left zero, the\n   translator takes only instructions that touch no memory, and the rest are\n   interpreted, which is slower and always safe. */\n");
    out.push_str("/* A cache, for a machine that wants one.\n\n   ⚠️ This is a MICROARCHITECTURE parameter and it is deliberately not in the\n   description. A description says what instructions mean; how many lines a\n   machine keeps and how long a miss costs is a property of one machine that\n   runs them, and putting it in the language would make every description\n   claim a cache it has no business claiming. It is configured here, per\n   machine, like the translator is.\n\n   ⚠️ One level, direct-mapped or set-associative, LRU, no prefetch, no\n   write-allocate policy to choose, no coherence. What it can tell you is a\n   working set that fits from one that does not, which an instruction count\n   cannot do at all; what it cannot tell you is what a real memory system\n   does. `lines` of 0 means no cache and every access is a hit at zero\n   cost, which is what the machine did before this existed. */\n");
    out.push_str("typedef struct axis_sim_cache {\n");
    out.push_str("  uint32_t lines;        /* total lines; 0 for no cache */\n");
    out.push_str("  uint32_t ways;         /* 1 is direct-mapped; 0 means 1 */\n");
    out.push_str("  uint32_t line_bytes;   /* 0 means 64 */\n");
    out.push_str("  uint32_t miss_cycles;  /* what a miss adds to the instruction that caused it */\n");
    out.push_str("} axis_sim_cache;\n\n");
    out.push_str("/* A core's TLBs (abi_version 9). ⚠️ TIMING, not translation: addresses stay\n   what the program computes, no page table is read and nothing faults. What\n   is modelled is how many pages a program touches against how many the\n   machine remembers. A first-level hit is in the instruction's own latency;\n   a first-level miss the second level holds costs `second_cycles`; a miss\n   everywhere costs `walk_cycles` more. Ways of 0 are fully associative. */\n");
    out.push_str("typedef struct axis_sim_tlb {\n");
    out.push_str("  uint32_t data_entries, data_ways;      /* every load and store */\n");
    out.push_str("  uint32_t fetch_entries, fetch_ways;    /* fetch, once per page it enters */\n");
    out.push_str("  uint32_t second_entries, second_ways, second_cycles;  /* one, behind both */\n");
    out.push_str("  uint32_t page_bytes;                   /* 0 means 4096 */\n");
    out.push_str("  uint32_t walk_cycles;\n");
    out.push_str("} axis_sim_tlb;\n\n");
    out.push_str("/* One functional unit a core has, by the name its instructions use.\n\n   ⚠️ A unit declares no LATENCY. The instruction already declares one, and\n   a second place to write the same number is how a field becomes free text:\n   `expected-speedup` is 1.0 on all 338 instructions of one corpus precisely\n   because nothing ever had to agree with it. What a unit says is how many of\n   it exist, and whether a new operation may start before the last finishes. */\n");
    out.push_str("typedef struct axis_sim_unit {\n");
    out.push_str("  const char *name;\n");
    out.push_str("  uint32_t count;       /* two adders issue two adds a cycle */\n");
    out.push_str("  uint32_t pipelined;   /* 0: busy for the whole latency */\n");
    out.push_str("} axis_sim_unit;\n\n");
    out.push_str("/* A MACHINE the description declares, as distinct from the instructions\n   it runs. What an instruction means is the same on a core with one adder\n   and on a core with four; how long a program takes is not, and that is the\n   whole reason a core is a separate form from an instruction.\n\n   ⚠️ Selecting one is OPTIONAL and off by default. A machine with no core\n   selected is the first-order model that came before cores could say\n   anything: single issue, no resource contention. That is what keeps every\n   description written before this form from suddenly claiming a pipeline. */\n");
    out.push_str("/* Physical registers a core keeps beyond one register file's\n   architectural ones. */\n");
    out.push_str("typedef struct axis_sim_rename {\n  const char *file;\n  uint32_t extra;\n} axis_sim_rename;\n\n");
    out.push_str("/* A number a component reads by name (O8): a predictor's `tables`, or\n   whatever a predictor AXIS has never heard of was given. */\n");
    out.push_str("typedef struct axis_sim_param {\n  const char *key;\n  uint32_t value;\n} axis_sim_param;\n\n");
    out.push_str("typedef struct axis_sim_core {\n");
    out.push_str("  const char *name;\n");
    out.push_str("  const char *isa;\n");
    out.push_str("  uint32_t issue_width;      /* how many may BEGIN in one cycle */\n");
    out.push_str("  const axis_sim_unit *units;\n");
    out.push_str("  int32_t unit_count;\n");
    out.push_str("  /* The memory this core runs against, as the description declares it.\n     All zero when the core names none, or names one that is not a cache.\n\n     ⚠️ Selecting the core APPLIES this, so a described machine arrives\n     with the cache its description gave it rather than whatever the host\n     happened to configure last. A host that wants a different one calls\n     `configure_cache` afterwards -- the description is the default, not a\n     ceiling. */\n");
    out.push_str("  axis_sim_cache cache;\n");
    out.push_str("  /* What a TAKEN branch costs: the front end fetched the fall-through\n     and has to start again somewhere else. ⚠️ This is the cost of not\n     PREDICTING -- a machine with no predictor pays it every time, which is\n     what an in-order core without one does. Zero is a front end that never\n     stalls, which is what every core modelled here did before one could\n     say otherwise. */\n");
    out.push_str("  uint32_t branch_penalty;\n");
    out.push_str("  /* How this core guesses. 0 is NO PREDICTOR, which guesses \"not taken\"\n     every time -- so a machine without one is not a special case in the\n     model, it is the degenerate predictor, and it costs a penalty on\n     exactly the taken branches. 1 is bimodal: two-bit counters indexed by\n     address, `predictor_entries` of them. 2 is gshare: the same counters,\n     indexed by address XOR the last `predictor_history` outcomes.\n\n     ⚠️ Finite on purpose. Two branches landing on one counter interfere,\n     and whether that matters is the question a predictor study asks. */\n");
    out.push_str("  uint32_t predictor;\n");
    out.push_str("  uint32_t predictor_entries;\n");
    out.push_str("  /* The reorder buffer, the issue queue, and how many may retire at\n     once. ⚠️ A NON-ZERO `rob` MEANS OUT OF ORDER, and selects a different\n     model entirely: a tick loop with finite structures, rather than the\n     in-order scoreboard that computes one instruction at a time. A core\n     with no window uses the in-order path untouched, which is what keeps\n     every description written before this from acquiring a pipeline it\n     never claimed. */\n");
    out.push_str("  uint32_t rob;\n");
    out.push_str("  uint32_t issue_queue;\n");
    out.push_str("  uint32_t commit_width;\n");
    out.push_str("  /* Which implementation is meant to time this core. Empty is this\n     library's own pipeline.\n\n     ⚠️ A NAME IS A REQUIREMENT. A host without the model this core asks\n     for must be told so, not handed the built-in pipeline -- falling back\n     produces a plausible cycle count for somebody else's machine, and a\n     plausible wrong number is worse than a refusal. A microarchitecture is\n     mostly policy, policy is not declarable, and a description that names\n     a model is saying the geometry here is not the whole machine. */\n");
    out.push_str("  const char *model;\n");
    out.push_str("  /* What KIND of number this machine's figures are: `declared` (typed by\n     a designer), `measured` (put back to hardware and checked),\n     `modelled` (produced by another model). Carried, never inferred. */\n");
    out.push_str("  const char *provenance;\n");
    out.push_str("  /* ⚠️ MEMORY ORDERING, for a core that declares a load/store queue\n     (docs/ooo_design.md, O1). `lsq` of 0 is a machine whose loads wait on\n     registers only -- what every core did before this -- and the four\n     numbers after it are then not read. Queues of 0 are as deep as the\n     window. `disambiguation` 0 is conservative (a load waits until every\n     older store has its address), 1 is perfect (only for older stores it\n     overlaps). 2 is speculative: a load never waits for an unknown address\n     and is squashed and replayed, `replay` cycles later, when an older\n     store's address resolves over it (O5). 3 is store-sets: speculative,\n     and a load that has collided with a store waits for it next time, from a\n     table of `store_sets` entries. `forwarding` 1 hands an executed store's\n     value to a load it wholly covers; 0, or a partial overlap, waits for the\n     store to retire. */\n");
    out.push_str("  uint32_t lsq;\n  uint32_t load_queue;\n  uint32_t store_queue;\n");
    out.push_str("  uint32_t disambiguation;\n  uint32_t forwarding;\n");
    out.push_str("  /* ⚠️ PHYSICAL REGISTERS beyond the architectural file, per register\n     FILE (O2). A write allocates one at dispatch and gives one back when it\n     retires -- the previous mapping of its register, which nothing younger\n     can read any more. A file not listed renames without limit. */\n");
    out.push_str("  const axis_sim_rename *rename;\n  int32_t rename_count;\n");
    out.push_str("  /* Bits of global branch history `gshare` folds into its index (O3). */\n");
    out.push_str("  uint32_t predictor_history;\n");
    out.push_str("  uint32_t replay;\n  uint32_t store_sets;\n");
    out.push_str("  /* ⚠️ THE FETCH PIPELINE (O6-O7), for a core that declares one; `fe` 0\n     is a machine whose instructions reach dispatch as they are stepped. Up\n     to `fetch_width` are fetched a cycle, a branch predicted taken ends its\n     group, and each reaches dispatch `fe_depth` cycles after it was\n     fetched -- so a mispredict's refill is the depth, with `branch_penalty`\n     on top. At most `fe_buffer` are fetched and not dispatched. `btb` 0 is\n     a perfect target buffer; otherwise a predicted-taken branch whose target\n     it does not hold costs `btb_penalty` before fetch resumes. */\n");
    out.push_str("  uint32_t fe;\n  uint32_t fetch_width;\n  uint32_t fe_depth;\n  uint32_t fe_buffer;\n");
    out.push_str("  uint32_t btb;\n  uint32_t btb_penalty;\n");
    out.push_str("  /* ⚠️ THE PREDICTOR, BY NAME (O8), and every number it was given. A\n     built-in (`bimodal`, `gshare`, `tage`) or one a host registers; a core\n     naming one this library has not got is refused, never handed another.\n     `predictor` above stays the old code for readers that know it. */\n");
    out.push_str("  const char *predictor_name;\n  const axis_sim_param *predictor_params;\n  int32_t predictor_param_count;\n");
    out.push_str("  /* Return-address stack entries, 0 for none (O9). */\n  uint32_t ras;\n");
    out.push_str("  /* ⚠️ ISSUE PORTS (O10): for each unit, in `units` order, a mask of the\n     ports that feed it. A port starts one instruction a cycle. `port_count`\n     0 is a core whose units are their own ports. */\n");
    out.push_str("  const uint32_t *unit_ports;\n  uint32_t port_count;\n");
    out.push_str("  /* ⚠️ THE INSTRUCTION CACHE fetch reads through (O11), all zero for a\n     fetch that never misses; and whether the front end fetches down the\n     predicted path until a mispredict resolves, touching those lines. */\n");
    out.push_str("  axis_sim_cache icache;\n  uint32_t wrong_path_fetch;\n");
    out.push_str("  /* ⚠️ Whether the wrong path is EXECUTED (O12): the functional side\n     forks at a mispredict, runs down the predicted path with its writes\n     buffered and its traps swallowed, and is restored exactly; what the\n     machine could have reached before resolution then touches the caches. */\n");
    out.push_str("  uint32_t wrong_path_execute;\n");
    out.push_str("  /* ⚠️ EXECUTION-DRIVEN (E1): fetch the predicted path, execute at issue\n     through the generated executor, resolve at completion, and commit by\n     stepping the golden model and checking the pipeline against it. 0 is\n     trace-driven, what every core was before. */\n");
    out.push_str("  uint32_t execute_driven;\n");
    out.push_str("  /* ⚠️ TIMED MEMORY (U3): a port of a described memory system asks it WHEN\n     an access completes (MSHRs, fills in flight, DRAM banks and bus) rather\n     than what it would cost alone. Execution-driven cores only; 0 is what\n     every core was before. */\n");
    out.push_str("  uint32_t memory_timed;\n");
    out.push_str("  /* The core's TLBs, all zero for translation that is free. Read only at\n     `abi_version >= 9`. */\n");
    out.push_str("  axis_sim_tlb tlb;\n");
    out.push_str("} axis_sim_core;\n\n");
    out.push_str("/* The number `key` a core gave its predictor, or `fallback`. Here, not in\n   a library, so an external predictor reads its parameters with nothing\n   but this header. */\n");
    out.push_str("static inline uint32_t axis_sim_param_of(const axis_sim_core *core, const char *key, uint32_t fallback) {\n");
    out.push_str("  for (int32_t i = 0; core && i < core->predictor_param_count; ++i) {\n");
    out.push_str("    const char *a = core->predictor_params[i].key, *b = key;\n");
    out.push_str("    while (*a && *a == *b) { ++a; ++b; }\n");
    out.push_str("    if (*a == *b) { return core->predictor_params[i].value; }\n  }\n  return fallback;\n}\n\n");
    out.push_str("/* ⚠️ A DIRECTION PREDICTOR is a component with state of its own (O8).\n   The built-in ones implement exactly this, so a host's predictor and this\n   library's are timed by the same pipeline through the same calls.\n\n   On a TRACE-driven core `predict` is asked for every branch before it is\n   known and `update` told the outcome right after -- in program order, one\n   branch at a time. On an EXECUTION-driven core (E1) `predict` is asked at\n   fetch, ahead of older branches' updates, and every `update` -- at commit,\n   in program order -- is immediately preceded by a `predict` of the same\n   branch, so a predictor that remembers its last lookup trains the right\n   entry. One that offers speculative history (abi_version 2) is also handed\n   the history that branch was predicted with. */\n");
    out.push_str("typedef struct axis_sim_predictor {\n  uint32_t abi_version;\n  const char *name;\n");
    out.push_str("  void *(*create)(const axis_sim_core *core);\n  void (*destroy)(void *state);\n");
    out.push_str("  int32_t (*predict)(void *state, uint64_t pc);\n");
    out.push_str("  void (*update)(void *state, uint64_t pc, int32_t taken);\n");
    out.push_str("  /* ⚠️ abi_version 2 (E2): SPECULATIVE HISTORY, optional. An\n     execution-driven engine predicts a branch long before the ones ahead of it\n     retire; a predictor offering these lets it advance the history with each\n     prediction, checkpoint it per instruction, and put it back on a squash.\n     Read only when `abi_version >= 2`, so a predictor built against the first\n     version of this struct is never read past its end -- and gets history\n     trained at commit, as before. */\n");
    out.push_str("  uint64_t (*history)(const void *state);\n");
    out.push_str("  void (*set_history)(void *state, uint64_t history);\n");
    out.push_str("  void (*speculate)(void *state, uint64_t pc, int32_t taken);\n");
    out.push_str("} axis_sim_predictor;\n\n");
    out.push_str("/* ⚠️ A PREFETCHER is a component too (abi_version 9). A cache of a described\n   memory system that names one this library has not got -- a namespaced\n   name, `(prefetch acme.spp)` -- is given it by a host. It is shown every\n   demand access of that cache on a core with timed memory: the line, the\n   key of the stream it belongs to (the instruction's address; 0 for none),\n   what happened, and the cycle. It answers with lines to fetch, at most\n   `max`, and the library fetches them as it fetches its own: through a miss\n   buffer, the prefetch queue or a drop, and the levels below. `create` is\n   given the cache's line size and its declared `prefetch-degree`. */\n");
    out.push_str("enum { AXIS_SIM_SAW_HIT = 0, AXIS_SIM_SAW_MISS = 1, AXIS_SIM_SAW_FIRST_USE = 2 };\n");
    out.push_str("typedef struct axis_sim_prefetcher {\n  uint32_t abi_version;\n  const char *name;\n");
    out.push_str("  void *(*create)(uint32_t line_bytes, uint32_t degree);\n  void (*destroy)(void *state);\n");
    out.push_str("  int32_t (*observe)(void *state, uint64_t line, uint64_t key, int32_t saw, uint64_t now,\n                     uint64_t *fetch, int32_t max);\n");
    out.push_str("} axis_sim_prefetcher;\n\n");
    out.push_str("/* What the simulator tells a timing model about one retired instruction.\n\n   ⚠️ Everything the model needs and nothing it has to ask back for. A model\n   that had to call into the simulator would be a model the simulator has to\n   trust; this way a closed implementation is a pure function of what it is\n   handed, and a host can reason about what crosses the boundary. */\n");
    out.push_str("#define AXIS_UARCH_MAX_REGS 8\n");
    out.push_str("#define AXIS_UARCH_MAX_ACCESSES 4\n");
    out.push_str("typedef struct axis_uarch_event {\n");
    out.push_str("  /* ⚠️ FLATTENED, not a pointer into this library's tables. A model taking\n     `axis_lift_entry *` would need the generated header of the description\n     it was built for -- which makes a closed model a per-corpus artifact and\n     the boundary a fiction. `axis_pack.h` is byte-identical across packs and\n     depends on nothing, and this has to keep it that way. Everything the\n     built-in pipeline itself reads is here, in types any compiler has. */\n");
    out.push_str("  const char *mnemonic;\n");
    out.push_str("  const char *unit;              /* empty when the description names none */\n");
    out.push_str("  uint32_t latency;\n");
    out.push_str("  uint32_t throughput_milli;     /* a rate: 1.0 is 1000 */\n");
    out.push_str("  uint64_t pc;\n");
    out.push_str("  int32_t ends_block;            /* control CAN leave here */\n");
    out.push_str("  int32_t taken;                 /* and did: the pc went elsewhere */\n");
    out.push_str("  uint64_t memory_stall;         /* what this machine's cache charged */\n");
    out.push_str("  /* Register slots, so a model finds its own dependences without knowing\n     how this description numbers registers. */\n");
    out.push_str("  int32_t read_count;\n");
    out.push_str("  uint32_t reads[AXIS_UARCH_MAX_REGS];\n");
    out.push_str("  int32_t write_count;\n");
    out.push_str("  uint32_t writes[AXIS_UARCH_MAX_REGS];\n");
    out.push_str("  /* ⚠️ What it touched in memory, [lo, hi) with a flag per access for a\n     write. The built-in pipeline orders loads against stores by these\n     (O1), and a promise of \"everything the pipeline reads\" that left them\n     out would be a promise a closed model with a load/store queue could\n     not be built on. */\n");
    out.push_str("  int32_t access_count;\n");
    out.push_str("  uint64_t access_lo[AXIS_UARCH_MAX_ACCESSES];\n");
    out.push_str("  uint64_t access_hi[AXIS_UARCH_MAX_ACCESSES];\n");
    out.push_str("  int32_t access_write[AXIS_UARCH_MAX_ACCESSES];\n");
    out.push_str("} axis_uarch_event;\n\n");
    out.push_str("/* A TIMING MODEL that is not this library.\n\n   ⚠️ This is the other half of `model` on a core. A vendor's\n   microarchitecture is mostly policy, policy is not declarable, and the\n   honest way to host one is to let it arrive as code: a library exporting a\n   single symbol, exactly as the JIT and solver libraries do. Capability is\n   presence -- a host that has the model registers it, and a host that does\n   not is refused by name rather than quietly given the built-in pipeline.\n\n   ⚠️ `provenance` is the MODEL's, not the description's. Once a closed model\n   produces the number, the number is that model's claim, and a result that\n   still reported the description's word for it would be attributing a\n   vendor's figure to a designer's estimate. */\n");
    out.push_str("typedef struct axis_uarch_pack {\n");
    out.push_str("  uint32_t abi_version;\n");
    out.push_str("  const char *name;        /* matched against a core's `model` */\n");
    out.push_str("  const char *generator;\n");
    out.push_str("  void *(*create)(const axis_sim_core *core);\n");
    out.push_str("  void (*destroy)(void *state);\n");
    out.push_str("  void (*account)(void *state, const axis_uarch_event *event);\n");
    out.push_str("  uint64_t (*cycles)(const void *state);\n");
    out.push_str("  const char *(*provenance)(void);\n");
    out.push_str("} axis_uarch_pack;\n\n");
    out.push_str("typedef struct axis_sim_jit {\n");
    out.push_str("  int32_t enabled;\n");
    out.push_str("  int32_t blocks;            /* translated blocks to keep; 0 for a default */\n");
    out.push_str("  uint64_t memory_base;      /* the host's flat memory, or 0 */\n");
    out.push_str("  uint64_t memory_size;\n");
    out.push_str("} axis_sim_jit;\n\n");
    out.push_str("typedef struct axis_sim_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n\n");
    out.push_str("  int32_t (*register_slots)(void);\n  int32_t (*state_slots)(void);\n");
    out.push_str("  const char *(*state_name)(int32_t slot);\n  uint32_t (*state_width)(int32_t slot);\n");
    out.push_str("  /* ⚠️ The machine is the LIBRARY's to allocate. Its size is the\n     description's -- a scalable register spans several slots -- so a host\n     that declared one would be declaring a shape it cannot know. */\n");
    out.push_str("  void *(*create)(const axis_pack_sim_hooks *hooks);\n");
    out.push_str("  void (*destroy)(void *machine);\n");
    out.push_str("  void (*reset)(void *machine, uint64_t pc, const char *isa,\n                const axis_pack_state_entry *state, int32_t count);\n\n");
    out.push_str("  int32_t (*step)(void *machine);\n");
    out.push_str("  int32_t (*run)(void *machine, uint64_t limit);\n\n");
    out.push_str("  uint64_t (*pc)(const void *machine);\n");
    out.push_str("  uint64_t (*steps)(const void *machine);\n");
    out.push_str("  int32_t (*status)(const void *machine);\n");
    out.push_str("  const char *(*halt_reason)(const void *machine);\n");
    out.push_str("  uint64_t (*reg)(const void *machine, int32_t slot);\n");
    out.push_str("  void (*set_reg)(void *machine, int32_t slot, uint64_t value);\n");
    out.push_str("  uint64_t (*state_value)(const void *machine, int32_t slot);\n\n");
    out.push_str("  /* ⚠️ Translation is OFF until a host asks for it, and the host hands\n     over the JIT library itself -- the two are separate libraries and a\n     pack does not decide for a program which of them it linked. Returns 0\n     when this build cannot translate at all.\n\n     A translated run reports no retire events: the emitted bytes call no\n     hook. So a machine with a retire hook installed keeps interpreting,\n     and a host that wants both speed and a trace has to choose per run\n     rather than be given something quieter than it asked for. */\n");
    out.push_str("  int32_t (*jit)(void *machine, const axis_jit_pack *translator,\n                 const axis_sim_jit *options);\n");
    out.push_str("  /* How many instructions ran as translated code, and how many blocks\n     were built to run them. A host can tell whether it got what it\n     asked for rather than assume. */\n");
    out.push_str("  /* ⚠️ A FIRST-ORDER timing model: in order, single issue, no memory\n     hierarchy, no prediction. What it knows is the latency and throughput\n     the DESCRIPTION declares and which registers each instruction names, and\n     that is enough to tell a dependent chain from an independent stream --\n     the question an instruction count cannot answer at all. It is not a\n     cycle-accurate machine and the name says which.\n\n     ⚠️ Counted on the interpreted path only. Translated bytes call nothing,\n     so a run that enables the translator gets no cycles: the same trade the\n     retire hook makes, said rather than silently stopping. */\n");
    out.push_str("  void (*count_cycles)(void *machine, int32_t on);\n");
    out.push_str("  uint64_t (*cycles)(const void *machine);\n");
    out.push_str("  /* A cache for this machine, and what it did. ⚠️ Configured here rather\n     than declared in the description: how many lines a machine keeps is a\n     property of one machine, not of what its instructions mean. Off until\n     a host asks, and then every access is looked up and a miss is charged\n     to the instruction that asked for it. */\n");
    out.push_str("  void (*configure_cache)(void *machine, const axis_sim_cache *cache);\n");
    out.push_str("  uint64_t (*cache_hits)(const void *machine);\n");
    out.push_str("  uint64_t (*cache_misses)(const void *machine);\n");
    out.push_str("  /* Tell this machine's cache that an access happened that its own\n     instructions did not make: an accelerator sharing the cache, a DMA\n     engine, a replayed trace, another core. Whether a co-processor's\n     traffic evicts the core's working set is a co-design question, and a\n     machine that only ever sees its own loads cannot be asked it.\n\n     ⚠️ One address is one line. An access that spans two lines is the\n     caller's to report as two -- the width is not passed because the\n     cache does not model a fill of anything but the line it names. */\n");
    out.push_str("  void (*touch_memory)(void *machine, uint64_t addr);\n");
    out.push_str("  /* The cores this description declares, and which one this machine is.\n\n     ⚠️ `select_core` returns 0 for a name the description does not declare,\n     so a typo is reported rather than silently leaving the machine on the\n     model it had. Selecting none -- the default -- is single issue with no\n     resource contention, which is what every machine did before a core could\n     declare a width. */\n");
    out.push_str("  int32_t (*core_count)(void);\n");
    out.push_str("  const char *(*core_name)(int32_t slot);\n");
    out.push_str("  /* The model a core asks for, and what kind of numbers it claims. A\n     host refused by `select_core` reads these to learn what it would have\n     to supply, and whether the figures would be a designer's estimate or\n     something measured. A host told only `no` cannot go and find one. */\n");
    out.push_str("  const char *(*core_model)(int32_t slot);\n");
    out.push_str("  const char *(*core_provenance)(int32_t slot);\n");
    out.push_str("  /* Bind a timing model this library is not. Returns how many declared\n     cores asked for it -- 0 means no core names this model, so a typo is\n     reported rather than silently accepted and then never used.\n\n     ⚠️ Bind before selecting the core, from the thread that loaded the\n     pack: registration is not thread-safe and is not meant to be, the same\n     trade `register_routine` makes. */\n");
    out.push_str("  int32_t (*register_model)(const axis_uarch_pack *model);\n");
    out.push_str("  /* Which model produced this machine's cycle count: a bound model's\n     name, or the empty string for this library's own pipeline.\n\n     ⚠️ A number that cannot say where it came from is the thing this whole\n     boundary exists to prevent. `core_provenance` says what KIND of claim a\n     description makes; this says WHO made the one you are holding. */\n");
    out.push_str("  const char *(*timing_source)(const void *machine);\n");
    out.push_str("  int32_t (*select_core)(void *machine, const char *name);\n");
    out.push_str("  /* How many branches this machine guessed wrong. ⚠️ Reported rather\n     than inferred from cycles: a host that has to divide a cycle count by\n     a penalty to learn its mispredict rate is doing arithmetic the model\n     already did, and getting a different answer the moment anything else\n     costs cycles too. */\n");
    out.push_str("  uint64_t (*mispredicts)(const void *machine);\n");
    out.push_str("  /* Cycles the front end spent idle waiting for a redirect.\n\n     ⚠️ Reported because in a PIPELINE it cannot be read off the cycle\n     count: the machine keeps retiring what was already in flight while the\n     front end waits, so a mispredict costs the declared penalty in idle\n     fetch and rather less than that in total time. Those are two different\n     true statements, and a host that multiplied a mispredict count by a\n     penalty would be asserting the wrong one. */\n");
    out.push_str("  uint64_t (*front_end_stalls)(const void *machine);\n");
    out.push_str("  uint64_t (*translated)(const void *machine);\n");
    out.push_str("  uint64_t (*blocks_built)(const void *machine);\n");
    out.push_str("  /* The routines this description names and does not describe. A host binds\n     one by the name the description gives it -- `register_routine` returns how\n     many instructions that name covered, and 0 when the pack names no such\n     routine, so a typo is reported rather than silently ignored.\n\n     ⚠️ Registration is not thread-safe and is not meant to be: bind before\n     the first step, from the thread that loaded the pack. */\n  int32_t (*routine_count)(void);\n  const char *(*routine_name)(int32_t slot);\n  const char *(*routine_mnemonic)(int32_t slot);\n  int32_t (*register_routine)(const char *name, axis_pack_routine fn);\n");
    out.push_str("  /* The described memory system this machine's selected core is a port of\n     (docs/memory_system_design.md), and what each of its nodes did. The\n     name is empty and the count 0 when the core is in none -- then the\n     single cache above is the model. `memsys_stats` writes up to `n` of:\n     hits, misses, writebacks, evictions, prefetches, back-invalidations,\n     row hits, idle-bank opens, row conflicts, endpoint accesses, coherence\n     forwards, invalidations, upgrades -- in that order -- and returns how\n     many it wrote. */\n");
    out.push_str("  const char *(*memsys_name)(const void *machine);\n  int32_t (*memsys_node_count)(const void *machine);\n  const char *(*memsys_node_name)(const void *machine, int32_t node);\n  int32_t (*memsys_stats)(const void *machine, int32_t node, uint64_t *out, int32_t n);\n");
    out.push_str("  /* Share `other`'s memory system, at this machine's own core's port --\n     how several machines are made coherent with each other. 0 when refused. */\n");
    out.push_str("  int32_t (*memsys_join)(void *machine, void *other);\n");
    out.push_str("  /* Loads squashed because an older store's address resolved over them\n     after they had issued (O5). Zero on a machine that never speculates --\n     which is what makes the count a claim rather than an estimate. */\n");
    out.push_str("  uint64_t (*memory_violations)(const void *machine);\n");
    out.push_str("  /* Predicted-taken branches whose target the BTB did not hold (O7). */\n");
    out.push_str("  uint64_t (*btb_misses)(const void *machine);\n");
    out.push_str("  /* Bind a predictor this library has not got, by the name a core asks\n     for. Returns how many declared cores name it -- 0 is a typo or another\n     description's. And which predictor a core asks for, so a refused host\n     knows what to go and find. */\n");
    out.push_str("  int32_t (*register_predictor)(const axis_sim_predictor *predictor);\n");
    out.push_str("  const char *(*core_predictor)(int32_t slot);\n");
    out.push_str("  /* Taken branches that went where they were predicted to go the WRONG\n     way round: an indirect jump or a return whose target the BTB or the\n     return stack had wrong (O9). Counted among `mispredicts` too -- each one\n     is a redirect at resolution -- and separately, so a host can tell a\n     wrong direction from a wrong destination. */\n");
    out.push_str("  uint64_t (*target_mispredicts)(const void *machine);\n");
    out.push_str("  /* Instruction-cache misses on the path that retired, and lines fetched\n     down paths that did not (O11). */\n");
    out.push_str("  uint64_t (*icache_misses)(const void *machine);\n");
    out.push_str("  uint64_t (*wrong_path_lines)(const void *machine);\n");
    out.push_str("  /* Wrong-path instructions the machine executed before their\n     mispredicts resolved (O12): run on a forked functional state, none of\n     them retired, and their memory reached only the caches. */\n");
    out.push_str("  uint64_t (*wrong_path_instructions)(const void *machine);\n");
    out.push_str("  /* An execution-driven core's own mistakes and its squashes (E1). A\n     REPLAY is a commit where the golden model disagreed with what the\n     pipeline computed -- a dependence it failed to honour -- and on a\n     description whose every dependence is declared there are none. */\n");
    out.push_str("  uint64_t (*replays)(const void *machine);\n");
    out.push_str("  uint64_t (*squashed)(const void *machine);\n");
    out.push_str("  /* Traps an execution-driven core took, precisely, at commit (E3). */\n");
    out.push_str("  uint64_t (*traps)(const void *machine);\n");
    out.push_str("  /* Several execution-driven machines of this library, over the memory\n     their hosts share, advanced together a cycle at a time until every one\n     has stopped (MC1). Each runs at most `limit` instructions (0: no limit).\n     0, or -1 if one is not an execution-driven core counting cycles. */\n");
    out.push_str("  int32_t (*run_cores)(void **machines, int32_t count, uint64_t limit);\n");
    out.push_str("  /* Loads squashed because another core's store committed over what\n     they had read (MC1). */\n");
    out.push_str("  uint64_t (*snoops)(const void *machine);\n");
    out.push_str("  /* Several execution-driven machines advanced together for `cycles`\n     cycles, in lockstep as `run_cores` does, and left where they stand: a\n     host stepping other machines (SIMT ones) on the same clock calls this\n     a cycle at a time (U3). Returns how many are still running, or -1 as\n     `run_cores`. */\n");
    out.push_str("  int32_t (*cycle_cores)(void **machines, int32_t count, uint64_t cycles);\n");
    out.push_str("  /* The memory system this machine is a port of, for another library to\n     share (a SIMT pack's `axis_simt_share_memsys`), or NULL. Opaque. */\n");
    out.push_str("  void *(*memsys_handle)(void *machine);\n");
    out.push_str("  /* HARDWARE CONTEXTS (U4a): `machine` becomes another thread of the core\n     `other` runs -- they share its units, issue ports and issue, dispatch and\n     commit width each cycle, and split its window and issue queue evenly;\n     each keeps its own front end, rename map and golden model. Both must be\n     execution-driven machines of the same core, neither started. Step them\n     together with `cycle_cores`. 1, or 0 if refused. */\n");
    out.push_str("  int32_t (*share_core)(void *machine, void *other);\n");
    out.push_str("  /* A WARP (U4b): `machine`, a context of a shared core, joins warp `warp`\n     of it; the warp's members share one front end. Each cycle a warp\n     fetches ONE pc -- the lowest any member wants, or the pc of a member\n     passed over for `age` cycles -- for every member whose next pc it is.\n     What they fetched together is one instruction to the back end: the\n     first member to dispatch, issue or commit it in a cycle pays the slot,\n     port and unit, and the others ride free. Several warps of one core share\n     its units and widths as contexts do. Registers and golden models stay\n     per member. Call after `share_core`, before anything runs; `age` 0, an\n     age other than the core's other warps', and a warp number of 64 or more\n     are refused. 1, or 0 if refused. */\n");
    out.push_str("  int32_t (*set_warp)(void *machine, uint32_t warp, uint32_t age);\n");
    out.push_str("  /* How many of this member's instructions rode free at dispatch, issue\n     and commit, then how many times it slept on an event wait, into\n     out[0..n); returns how many were written (at most 4). */\n");
    out.push_str("  int32_t (*warp_rides)(const void *machine, uint64_t *out, int32_t n);\n");
    out.push_str("  /* ⚠️ ONE UNIT, SEVERAL CORES (VU4, abi_version 8). `machine` and `other`\n     -- two execution-driven machines, each a core of its own with its own\n     window and its own other units -- share the unit called `unit`: one set\n     of copies and lanes between them, as an SME unit is shared by the cores\n     around it. Both cores must declare the unit alike. What sharing costs\n     is the unit's own: `(transport N)` cycles on every result, and\n     `(switch N)` cycles to change which core it serves; a core that has had\n     switch + 1 turns yields to one that is waiting. The machines must run\n     in step (`run_cores`, `cycle_cores`). A context of a shared core shares\n     through its core: the core is the party, whichever context is named.\n     1, or 0 when refused: a machine already running, two contexts of one\n     core, units that differ. Share a core before its units. */\n");
    out.push_str("  int32_t (*share_unit)(void *machine, void *other, const char *unit);\n");
    out.push_str("  /* What the TLBs did (abi_version 9): first-level misses of the data and\n     of the fetch TLB, and how many of either went all the way to a walk.\n     The program's own, as the cache counters are: a lookup on a path that\n     is squashed changes what the TLB holds and is not counted. */\n");
    out.push_str("  uint64_t (*dtlb_misses)(const void *machine);\n");
    out.push_str("  uint64_t (*itlb_misses)(const void *machine);\n");
    out.push_str("  uint64_t (*page_walks)(const void *machine);\n");
    out.push_str("  /* Bind a prefetcher this library has not got, by the name a cache asks\n     for (abi_version 9). Returns how many caches name it -- 0 is a typo or\n     another description's. A core whose memory system names one nobody has\n     bound is refused by `select_core`, as an unbound predictor's is. */\n");
    out.push_str("  int32_t (*register_prefetcher)(const axis_sim_prefetcher *prefetcher);\n");
    out.push_str("  /* Micro-ops (abi_version 10): how many the program retired -- one an\n     instruction, unless the core cracks it -- and how many of them reached\n     the window from the micro-op cache and from the loop buffer rather than\n     through decode. The program's own: nothing on a wrong path counts. */\n");
    out.push_str("  uint64_t (*micro_ops)(const void *machine);\n  uint64_t (*op_cache_ops)(const void *machine);\n  uint64_t (*loop_buffer_ops)(const void *machine);\n");
    out.push_str("  /* Value prediction (abi_version 11): loads whose value was predicted and\n     was what they read, and loads predicted that read something else --\n     each of which fetched everything after it again. */\n");
    out.push_str("  uint64_t (*value_predictions)(const void *machine);\n  uint64_t (*value_mispredicts)(const void *machine);\n");
    out.push_str("} axis_sim_pack;\n\n");
    out.push_str("/* ---- solving: an architecture as terms a solver holds -----------\n\n   ⚠️ This library carries NO semantics of its own. It ships the SMT-LIB\n   definitions `emit-smt2` emits -- which are proven equal to the golden\n   model -- and binds them into a solver's context, so a consumer building a\n   symbolic engine applies the proven function rather than deriving a second\n   one. What it adds is plumbing: parsing, naming, and operand order.\n\n   ⚠️ The solver's own types do not appear here. A `void *` is a\n   `Z3_context` or a `Z3_ast`, documented rather than included, so that a\n   consumer of any other library in this pack needs no solver headers to\n   compile against this contract. */\n\n");
    out.push_str("typedef struct axis_z3_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("  /* The solver this was built against, so a host can refuse a\n     mismatch rather than crash inside one. */\n");
    out.push_str("  const char *solver;\n\n");
    out.push_str("  /* The proven definitions themselves, for a caller who would rather\n     hand them to another solver, or read them. */\n");
    out.push_str("  const char *(*smtlib)(void);\n\n");
    out.push_str("  /* Parse the definitions into `context` (a `Z3_context`) once and\n     return a handle, or NULL when the solver would not take them. */\n");
    out.push_str("  void *(*open)(void *context);\n");
    out.push_str("  void (*close)(void *handle);\n\n");
    out.push_str("  int32_t (*count)(void *handle);\n");
    out.push_str("  const char *(*mnemonic)(void *handle, int32_t index);\n");
    out.push_str("  int32_t (*index_of)(void *handle, const char *mnemonic);\n\n");
    out.push_str("  /* ⚠️ An instruction is not one term. Its VALUE is what it computes;\n     its EFFECTS are what it does -- a branch's condition and target, a\n     store's address and value, a guarded write's guard. A symbolic engine\n     needs the second set more than the first, and each part is its own\n     term. `-1` means this description has no proven term for that part;\n     `emit-smt2` prints the reason beside its name. */\n");
    out.push_str("  int32_t (*value_term)(void *handle, int32_t index);\n");
    out.push_str("  int32_t (*effect_count)(void *handle, int32_t index);\n");
    out.push_str("  /* \"set\", \"store\", \"setpc\", \"setstate\", \"trap\", \"barrier\". */\n");
    out.push_str("  const char *(*effect_kind)(void *handle, int32_t index, int32_t effect);\n");
    out.push_str("  /* Where a `set` or `setstate` lands: the operand it writes, or the\n     state slot it names. NULL for the kinds that write neither. */\n");
    out.push_str("  const char *(*effect_place)(void *handle, int32_t index, int32_t effect);\n");
    out.push_str("  /* `part` is \"guard\", \"addr\" or \"value\". */\n");
    out.push_str("  int32_t (*effect_term)(void *handle, int32_t index, int32_t effect,\n                         const char *part);\n");
    out.push_str("  /* ⚠️ When an effect's value is exactly a LOAD, `\"load_addr\"` is the one\n     part a solver can hold: an SMT function over bitvectors has no memory\n     to read from. These say how to finish the job -- how wide the access is\n     and whether it sign-extends -- so a consumer with memory does the\n     `select` itself, the way it already performs a store this publishes the\n     address and the value of. 0 bits means the value is not a load. */\n");
    out.push_str("  uint32_t (*effect_load_bits)(void *handle, int32_t index, int32_t effect);\n");
    out.push_str("  int32_t (*effect_load_signed)(void *handle, int32_t index, int32_t effect);\n\n");
    out.push_str("  /* And the terms themselves, by the index the four above hand back. */\n");
    out.push_str("  int32_t (*terms)(void *handle);\n");
    out.push_str("  /* What `emit-smt2` calls this term: `axis_instr_add`,\n     `axis_effect_beq_0_guard`. A consumer can check the directory it was\n     handed against the file's own naming rather than trusting it. */\n");
    out.push_str("  const char *(*term_name)(void *handle, int32_t term);\n");
    out.push_str("  int32_t (*arity)(void *handle, int32_t term);\n");
    out.push_str("  const char *(*operand_name)(void *handle, int32_t term, int32_t operand);\n");
    out.push_str("  uint32_t (*operand_bits)(void *handle, int32_t term, int32_t operand);\n");
    out.push_str("  uint32_t (*value_bits)(void *handle, int32_t term);\n\n");
    out.push_str("  /* Apply a term to `count` operand terms (`Z3_ast`), giving a `Z3_ast`.\n     NULL when the arity is wrong or a sort does not match, never a term\n     that means something else. */\n");
    out.push_str("  void *(*apply)(void *handle, int32_t term, void *const *operands, int32_t count);\n");
    out.push_str("} axis_z3_pack;\n\n");
    out.push_str("/* ---- executing symbolically: a machine made of terms -------------\n\n   The solver library hands out the terms an instruction MEANS. This one runs\n   a machine out of them: registers that hold terms instead of numbers, memory\n   as an array a solver can reason about, a pc that can be a term, and the\n   constraint that says when each way out of a branch is the one taken.\n\n   ⚠️ It carries no semantics either. Every value it computes comes from\n   `axis_z3_pack->apply` -- the definitions `emit-smt2` proves equal to the\n   golden model -- so a consumer gets a symbolic engine over the SAME meaning\n   its executor has, rather than a second opinion that agrees on the fixtures\n   somebody happened to write.\n\n   ⚠️ A `Z3_ast` and a `Z3_context` appear here as `void *`, for the reason\n   they do in the solver contract: a consumer of any other library in this\n   pack must not need solver headers to compile against this one. */\n\n");
    out.push_str("/* What a step decided about where the machine goes next.\n\n   ⚠️ A LIST, because a guarded `setpc` is two answers. A conditional branch\n   does not choose; it says `when this, there` -- and an engine that took one\n   way and dropped the other would be exploring a different program. The\n   caller forks by cloning, which is why cloning is cheap and explicit. */\n");
    out.push_str("typedef struct axis_sym_path {\n");
    out.push_str("  void *constraint;   /* Z3_ast, an i1: when this way is taken. NULL means always */\n");
    out.push_str("  void *pc;           /* Z3_ast: where it goes */\n");
    out.push_str("} axis_sym_path;\n\n");
    out.push_str("typedef struct axis_sym_pack {\n");
    out.push_str("  uint32_t abi_version;\n  const char *name;\n  const char *generator;\n  const char *entry;\n");
    out.push_str("  const char *solver;\n");
    out.push_str("\n  /* A machine whose registers are free variables. ⚠️ The solver library is\n     passed in rather than found: the two are separate libraries, and which\n     one a program linked is not this one's to decide. */\n");
    out.push_str("  void *(*create)(void *context, const axis_z3_pack *terms, int32_t regs);\n");
    out.push_str("  void (*destroy)(void *machine);\n");
    out.push_str("  /* ⚠️ A fork is a COPY, not a shared machine with a longer path. Two ways\n     out of a branch write different registers, and an engine that let them\n     share would report the second path's machine for the first. */\n");
    out.push_str("  void *(*clone)(const void *machine);\n");
    out.push_str("\n  void *(*reg)(const void *machine, int32_t slot);\n");
    out.push_str("  void (*set_reg)(void *machine, int32_t slot, void *term);\n");
    out.push_str("  void *(*pc)(const void *machine);\n");
    out.push_str("  void (*set_pc)(void *machine, void *term);\n");
    out.push_str("  /* Memory as one array term, `(Array (_ BitVec 64) (_ BitVec 8))`. Byte\n     addressed, because that is what a description's widths are in. */\n");
    out.push_str("  void *(*memory)(const void *machine);\n");
    out.push_str("  void (*set_memory)(void *machine, void *array);\n");
    out.push_str("  int32_t (*state_slots)(void);\n");
    out.push_str("  const char *(*state_name)(int32_t slot);\n");
    out.push_str("  void *(*state)(const void *machine, int32_t slot);\n");
    out.push_str("  void (*set_state)(void *machine, int32_t slot, void *term);\n");
    out.push_str("\n  /* One instruction, symbolically. Returns 0 when the word does not decode\n     or this build cannot say what it means -- and `refusal` says which. */\n");
    out.push_str("  int32_t (*step)(void *machine, uint32_t word, const char *isa);\n");
    out.push_str("  const char *(*refusal)(const void *machine);\n");
    out.push_str("\n  /* Where the last step can go. One entry with a NULL constraint is an\n     instruction that does not branch. */\n");
    out.push_str("  int32_t (*paths)(const void *machine);\n");
    out.push_str("  axis_sym_path (*path)(const void *machine, int32_t which);\n");
    out.push_str("\n  /* Everything assumed to get here, in order. */\n");
    out.push_str("  int32_t (*constraints)(const void *machine);\n");
    out.push_str("  void *(*constraint)(const void *machine, int32_t which);\n");
    out.push_str("  void (*assume)(void *machine, void *term);\n");
    out.push_str("} axis_sym_pack;\n\n");

    out.push_str("typedef const axis_decode_pack *(*axis_decode_pack_fn)(void);\n");
    out.push_str("typedef const axis_asm_pack *(*axis_asm_pack_fn)(void);\n");
    out.push_str("typedef const axis_disasm_pack *(*axis_disasm_pack_fn)(void);\n");
    out.push_str("typedef const axis_jit_pack *(*axis_jit_pack_fn)(void);\n");
    out.push_str("typedef const axis_sim_pack *(*axis_sim_pack_fn)(void);\n");
    out.push_str("typedef const axis_z3_pack *(*axis_z3_pack_fn)(void);\n");
    out.push_str("typedef const axis_lift_pack *(*axis_lift_pack_fn)(void);\n");
    out.push_str("typedef const axis_exec_pack *(*axis_exec_pack_fn)(void);\n\n");
    out.push_str("#ifdef __cplusplus\n}\n#endif\n#endif /* AXIS_PACK_H */\n");
    out
}

/// A description's name as a C identifier. The entry symbols are built from it.
pub fn pack_ident(name: &str) -> String {
    let mut ident: String = name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect();
    if ident.starts_with(|ch: char| ch.is_ascii_digit()) {
        ident.insert(0, '_');
    }
    ident.to_lowercase()
}

/// The ABI body with every name given internal linkage.
///
/// ⚠️ The `static` is what makes packs composable. `emit-decode-abi-c` emits
/// these with external linkage, which is why two of its outputs cannot coexist.
/// Reusing its text rather than restating it: two accounts of the same tables
/// would be two things to keep in step, and the value of a pack is that it is
/// the proven decoder rather than a copy of one.
fn pack_body(document: &Document) -> String {
    let mut out = String::new();
    for line in emit_decode_abi_c(document).lines() {
        if line.starts_with("/* Generated by AXIS") || line.starts_with("/* schema:") {
            continue;
        }
        if line.starts_with("const char *axis_abi_")
            || line.starts_with("int32_t axis_abi_")
            || line.starts_with("uint32_t axis_abi_")
        {
            out.push_str("static ");
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// The decoder library: what a disassembler needs, and nothing else.
pub fn emit_pack_decode_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's decoder, as a library. */\n");
    out.push_str("/* schema: axis.pack-decode-c.v1 */\n");
    out.push_str("#include \"axis_pack.h\"\n\n");
    out.push_str(&pack_body(document));
    out.push_str(&format!(
        "\nstatic const axis_decode_pack AXIS_DECODE_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  \
{}, {}, {},\n  axis_abi_count,\n  axis_abi_decode, axis_abi_decode_linear, \
axis_abi_decode_buffer, axis_abi_decode_le, axis_abi_decode_stream,\n  \
axis_abi_mnemonic, axis_abi_isa, axis_abi_format, axis_abi_asm_syntax,\n  \
axis_abi_match, axis_abi_mask, axis_abi_bits,\n  axis_abi_operand_count, \
axis_abi_operand_name, axis_abi_operand_kind, axis_abi_operand_role,\n  \
axis_abi_operand_value, axis_abi_operands_buffer,\n  axis_abi_tables_aligned\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_decode_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_decode_pack *axis_decode_pack_{ident}(void) {{ return &AXIS_DECODE_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

/// The assembler library: values to a word, and the printed/encoded relation.
///
/// Separate from the decoder because a consumer that only reads code should not
/// have to link one that writes it -- and because a capability that is a
/// library either exists or does not, where a capability flag can be, and was,
/// simply wrong.
/// How many bits of an immediate the description SIGN extends, or 0.
///
/// ⚠️ Only the behavior says so. An operand is declared `imm i12` whether it
/// holds a signed offset or an unsigned shift amount, and the difference shows
/// only where the semantics writes `(sext i64 12 imm)`. The TableGen path
/// already derives ranges this way and records why: reading the operand list
/// alone declared `uimm12i32` for an immediate the description sign extends,
/// which refused half the legal encodings of every load and store.
///
/// Here it decides how the assembly PRINTS. Without it `addi x12, x0, -5`
/// assembled correctly and printed back as `4294967291`, which is the same
/// word and not the same text -- and an assembler whose output its own parser
/// reads differently is not one anybody should publish.
fn signed_immediate_bits(instruction: &Instruction, name: &str) -> u32 {
    let mut text = instruction.formal_semantics.clone();
    if let Some(behavior) = instruction.behavior.as_ref() {
        for effect in &behavior.effects {
            text.push(' ');
            text.push_str(&crate::effects::render_semantic_expr(&effect.value.expr));
            if let Some(guard) = effect.guard.as_ref() {
                text.push(' ');
                text.push_str(&crate::effects::render_semantic_expr(&guard.expr));
            }
        }
    }
    // `(sext <type> <bits> <name>)`, wherever it appears. Matched on the
    // rendered form rather than by walking every expression shape: the point
    // is one fact about one operand, and the walk would be a second reading of
    // what `render_semantic_expr` already produced.
    let mut rest = text.as_str();
    while let Some(at) = rest.find("(sext ") {
        rest = &rest[at + 6..];
        let mut parts = rest.split(|c: char| c == ')' || c.is_whitespace());
        let _ty = parts.next();
        let bits = parts.next().and_then(|b| b.parse::<u32>().ok());
        let who = parts.next();
        if let (Some(bits), Some(who)) = (bits, who) {
            if who == name {
                return bits;
            }
        }
    }
    0
}

/// The text machinery: register spellings, the per-operand table, and the
/// printer and parser built on them.
///
/// Emitted into BOTH the assembler and the disassembler. A disassembler should
/// not have to link an assembler to turn a word into text, and an assembler
/// needs the same spellings to read that text back -- so the machinery is
/// shared by being generated into each, which is what keeps the two libraries
/// independently linkable. Each gets its own `static` copy; they meet only at
/// `axis_pack.h`.
fn pack_text_machinery(document: &Document) -> String {
    let architectural = architectural_instructions(document);
    let mut out = String::new();

    // The transform each operand declares, as a table this library reads. It
    // is the description's, not a consumer's guess: the field and the number
    // the assembly shows are different numbers wherever one is declared.
    // ⚠️ The operand table carries which register file an operand names, as an
    // index into `AXIS_ASM_FILES`, or -1 for an immediate. Asking a register
    // class would mean including the lifter's header, and an assembler should
    // not have to link a lifter to spell a register.
    let files = crate::effects::isa_register_files(&document.isas);
    let file_of = |kind: &str| -> i32 {
        let Some(rules) = crate::ast::register_class(kind) else {
            return -1;
        };
        let slot = rules.offset / u32::from(rules.limbs.max(1));
        let mut base = 0u32;
        for (index, (_, count)) in files.iter().enumerate() {
            if slot >= base && slot < base + count {
                return index as i32;
            }
            base += count;
        }
        if files.is_empty() { -1 } else { 0 }
    };
    out.push_str("\ntypedef struct { int32_t kind; int64_t amount; int32_t file; uint32_t signed_bits; uint32_t bits; } axis_asm_xform;\n");
    out.push_str("static const axis_asm_xform AXIS_ASM_XFORM[] = {\n");
    for instruction in &architectural {
        for operand in &instruction.operands {
            let (kind, amount) = match operand.asm_transform {
                crate::ast::AsmTransform::Identity => (0, 0),
                crate::ast::AsmTransform::MinusFrom(k) => (1, i64::from(k)),
                crate::ast::AsmTransform::Plus(k) => (2, i64::from(k)),
            };
            out.push_str(&format!(
                "  {{ {kind}, {amount}, {}, {}u, {}u }},\n",
                file_of(&operand.kind),
                signed_immediate_bits(instruction, &operand.name),
                operand.width
            ));
        }
    }
    out.push_str("  { 0, 0, -1, 0u, 0u }\n};\n");
    out.push_str("static const int32_t AXIS_ASM_XFORM_BASE[] = {\n");
    let mut base = 0usize;
    for instruction in &architectural {
        out.push_str(&format!("  {base},\n"));
        base += instruction.operands.len();
    }
    out.push_str("  0\n};\n\n");
    out.push_str("static int32_t axis_asm_slot(int32_t index, int32_t operand) {\n");
    out.push_str("  if (!axis_abi_in_range(index) || operand < 0) { return -1; }\n");
    out.push_str("  if (operand >= axis_abi_operand_count(index)) { return -1; }\n");
    out.push_str("  return AXIS_ASM_XFORM_BASE[index] + operand;\n}\n\n");
    out.push_str("static int64_t axis_asm_printed(int32_t index, int32_t operand, uint32_t field) {\n");
    out.push_str("  int32_t slot = axis_asm_slot(index, operand);\n");
    out.push_str("  if (slot < 0) { return (int64_t)field; }\n");
    out.push_str("  const axis_asm_xform *x = &AXIS_ASM_XFORM[slot];\n");
    out.push_str("  /* Signed where the description sign extends it, so the text reads\n     as the number the instruction means. */\n");
    out.push_str("  int64_t value = (int64_t)field;\n");
    out.push_str("  if (x->signed_bits && x->signed_bits < 64u) {\n");
    out.push_str("    uint64_t sign = UINT64_C(1) << (x->signed_bits - 1u);\n");
    out.push_str("    uint64_t masked = (uint64_t)field & ((UINT64_C(1) << x->signed_bits) - 1u);\n");
    out.push_str("    value = (int64_t)((masked ^ sign) - sign);\n  }\n");
    out.push_str("  if (x->kind == 1) { return x->amount - value; }\n");
    out.push_str("  if (x->kind == 2) { return value + x->amount; }\n");
    out.push_str("  return value;\n}\n\n");
    out.push_str("static uint32_t axis_asm_bits(int32_t index, int32_t operand) {\n");
    out.push_str("  int32_t slot = axis_asm_slot(index, operand);\n");
    out.push_str("  return slot < 0 ? 0u : AXIS_ASM_XFORM[slot].bits;\n}\n\n");
    out.push_str("static uint32_t axis_asm_signed_bits(int32_t index, int32_t operand) {\n");
    out.push_str("  int32_t slot = axis_asm_slot(index, operand);\n");
    out.push_str("  return slot < 0 ? 0u : AXIS_ASM_XFORM[slot].signed_bits;\n}\n\n");
    out.push_str("static int64_t axis_asm_encoded(int32_t index, int32_t operand, int64_t printed) {\n");
    out.push_str("  int32_t slot = axis_asm_slot(index, operand);\n");
    out.push_str("  if (slot < 0) { return printed; }\n");
    out.push_str("  const axis_asm_xform *x = &AXIS_ASM_XFORM[slot];\n");
    out.push_str("  if (x->kind == 1) { return x->amount - printed; }\n");
    out.push_str("  if (x->kind == 2) { return printed - x->amount; }\n");
    out.push_str("  return printed;\n}\n\n");

    // ⚠️ The register spelling, from the only naming a description states: an
    // ISA declaring `x[32]` names its registers `x0`..`x31`. A class picks its
    // file by the slot it starts at. ABI aliases are stated nowhere and so are
    // printed and accepted nowhere.
    let files = crate::effects::isa_register_files(&document.isas);
    out.push_str("typedef struct { const char *prefix; uint32_t base; uint32_t count; } axis_asm_file;\n");
    out.push_str("static const axis_asm_file AXIS_ASM_FILES[] = {\n");
    let mut base = 0u32;
    for (prefix, count) in &files {
        out.push_str(&format!(
            "  {{ {}, {base}u, {count}u }},\n",
            c_string(prefix)
        ));
        base += count;
    }
    out.push_str("  { NULL, 0u, 0u }\n};\n");
    out.push_str(&format!(
        "static const int32_t AXIS_ASM_FILE_COUNT = {};\n\n",
        files.len()
    ));
    // Which file a class indexes into, by the slot its registers start at.
    out.push_str("static const axis_asm_file *axis_asm_file_at(int32_t index, int32_t operand) {\n");
    out.push_str("  int32_t slot = axis_asm_slot(index, operand);\n");
    out.push_str("  if (slot < 0) { return NULL; }\n");
    out.push_str("  int32_t which = AXIS_ASM_XFORM[slot].file;\n");
    out.push_str("  if (which < 0 || which >= AXIS_ASM_FILE_COUNT) { return NULL; }\n");
    out.push_str("  return &AXIS_ASM_FILES[which];\n}\n\n");

    // Printing: the template, with each placeholder replaced by what it names.
    out.push_str("static int32_t axis_asm_print(int32_t index, const uint32_t *values, char *out, size_t size) {\n");
    out.push_str("  if (!axis_abi_in_range(index) || !out || !size) { return 0; }\n");
    out.push_str("  const char *t = axis_abi_asm_syntax(index);\n  if (!t) { return 0; }\n");
    out.push_str("  size_t n = 0;\n");
    out.push_str("  while (*t) {\n");
    out.push_str("    if (*t != '$') { if (n + 1 < size) { out[n] = *t; } ++n; ++t; continue; }\n");
    out.push_str("    ++t;\n    const char *name = t;\n");
    out.push_str("    while (*t && (isalnum((unsigned char)*t) || *t == '_')) { ++t; }\n");
    out.push_str("    size_t len = (size_t)(t - name);\n");
    out.push_str("    int32_t which = -1;\n");
    out.push_str("    for (int32_t i = 0; i < axis_abi_operand_count(index); ++i) {\n");
    out.push_str("      const char *on = axis_abi_operand_name(index, i);\n");
    out.push_str("      if (on && strlen(on) == len && !strncmp(on, name, len)) { which = i; break; }\n    }\n");
    out.push_str("    char piece[64];\n");
    out.push_str("    if (which < 0) { snprintf(piece, sizeof piece, \"$%.*s\", (int)len, name); }\n");
    out.push_str("    else {\n");
    out.push_str("      const axis_asm_file *file = axis_asm_file_at(index, which);\n");
    out.push_str("      if (file) {\n");
    out.push_str("        snprintf(piece, sizeof piece, \"%s%u\", file->prefix, values[which]);\n");
    out.push_str("      } else {\n");
    out.push_str("        snprintf(piece, sizeof piece, \"%lld\", (long long)axis_asm_printed(index, which, values[which]));\n");
    out.push_str("      }\n    }\n");
    out.push_str("    for (const char *q = piece; *q; ++q) { if (n + 1 < size) { out[n] = *q; } ++n; }\n");
    out.push_str("  }\n");
    out.push_str("  out[n < size ? n : size - 1] = 0;\n");
    out.push_str("  return n < size ? 1 : 0;\n}\n\n");

    // Parsing: the same template, read backwards.
    out.push_str("static int axis_asm_skip(const char **p) {\n  while (**p == ' ' || **p == '\\t') { ++*p; }\n  return 1;\n}\n\n");
    out.push_str("/* One instruction's template against the text. Literals must match with\n   whitespace treated as flexible; a placeholder captures a register name or a\n   number and yields the encoded field. */\n");
    out.push_str("static int32_t axis_asm_try(int32_t index, const char *text, uint32_t *values) {\n");
    out.push_str("  const char *t = axis_abi_asm_syntax(index);\n  if (!t) { return 0; }\n");
    out.push_str("  const char *p = text;\n");
    out.push_str("  for (int32_t i = 0; i < axis_abi_operand_count(index); ++i) { values[i] = 0; }\n");
    out.push_str("  while (*t) {\n");
    out.push_str("    if (*t == ' ') { axis_asm_skip(&p); while (*t == ' ') { ++t; } continue; }\n");
    out.push_str("    if (*t != '$') { axis_asm_skip(&p); if (*p != *t) { return 0; } ++p; ++t; continue; }\n");
    out.push_str("    ++t;\n    const char *name = t;\n");
    out.push_str("    while (*t && (isalnum((unsigned char)*t) || *t == '_')) { ++t; }\n");
    out.push_str("    size_t len = (size_t)(t - name);\n");
    out.push_str("    int32_t which = -1;\n");
    out.push_str("    for (int32_t i = 0; i < axis_abi_operand_count(index); ++i) {\n");
    out.push_str("      const char *on = axis_abi_operand_name(index, i);\n");
    out.push_str("      if (on && strlen(on) == len && !strncmp(on, name, len)) { which = i; break; }\n    }\n");
    out.push_str("    if (which < 0) { return 0; }\n");
    out.push_str("    axis_asm_skip(&p);\n");
    out.push_str("    const axis_asm_file *file = axis_asm_file_at(index, which);\n");
    out.push_str("    if (file) {\n");
    out.push_str("      size_t plen = strlen(file->prefix);\n");
    out.push_str("      if (strncmp(p, file->prefix, plen)) { return 0; }\n");
    out.push_str("      p += plen;\n      if (!isdigit((unsigned char)*p)) { return 0; }\n");
    out.push_str("      uint32_t number = 0;\n");
    out.push_str("      while (isdigit((unsigned char)*p)) { number = number * 10u + (uint32_t)(*p++ - '0'); }\n");
    out.push_str("      if (number >= file->count) { return 0; }\n");
    out.push_str("      values[which] = number;\n");
    out.push_str("    } else {\n");
    out.push_str("      int negative = 0;\n      if (*p == '-') { negative = 1; ++p; }\n");
    out.push_str("      if (!isdigit((unsigned char)*p)) { return 0; }\n");
    out.push_str("      long long shown = 0;\n");
    out.push_str("      while (isdigit((unsigned char)*p)) { shown = shown * 10 + (*p++ - '0'); }\n");
    out.push_str("      if (negative) { shown = -shown; }\n");
    out.push_str("      values[which] = (uint32_t)axis_asm_encoded(index, which, shown);\n");
    out.push_str("    }\n  }\n");
    out.push_str("  axis_asm_skip(&p);\n  return *p ? 0 : 1;\n}\n\n");
    out.push_str("/* ⚠️ Every instruction, not the first whose mnemonic matches. Two forms\n   may spell the same mnemonic and differ in their operands, and a parser that\n   stopped at the first would assemble the wrong one. A candidate must also\n   ENCODE: values that do not satisfy the instruction's constraints are not a\n   match for it. */\n");
    out.push_str("static int32_t axis_asm_parse(const char *text, int32_t *index, uint32_t *values) {\n");
    out.push_str("  if (!text || !index || !values) { return 0; }\n");
    out.push_str("  for (int32_t i = 0; i < axis_abi_count(); ++i) {\n");
    out.push_str("    uint32_t candidate[32];\n");
    out.push_str("    if (!axis_asm_try(i, text, candidate)) { continue; }\n");
    out.push_str("    uint32_t word = 0;\n");
    out.push_str("    if (!axis_abi_assemble(i, candidate, &word)) { continue; }\n");
    out.push_str("    *index = i;\n");
    out.push_str("    for (int32_t k = 0; k < axis_abi_operand_count(i); ++k) { values[k] = candidate[k]; }\n");
    out.push_str("    return 1;\n  }\n  return 0;\n}\n\n");

    out
}

/// The disassembler library: a word to the text it is.
///
/// The decoder says which instruction a word is and what its operands hold;
/// this says what it looks like. Those are different jobs -- spelling a
/// register and printing a transformed immediate are not decode table work --
/// and a consumer that only reads code should not have to link an assembler to
/// get them, which is where `print` lived until this existed.
/// The copy-and-patch JIT library: the patcher, over a table the build writes.
///
/// ⚠️ The split is deliberate. Everything else a pack contains is derived from
/// the description, so AXIS emits all of it. A stencil's *bytes* are not: they
/// are what a compiler made of the description on a particular machine, so the
/// build extracts them from an object file and writes `axis_jit_table.h`
/// beside this. AXIS emits the logic; the build emits the data. Keeping the
/// two apart is what stops this file pretending to know something it cannot.
/// The simulator as a library: a machine a host drives through hooks.
///
/// ⚠️ An ADAPTER, like the executor's. `axis_sim.h` is `static inline`
/// throughout, so two descriptions cannot share a translation unit -- and its
/// machine is sized by the description, so a host cannot declare one. The
/// library owns the allocation and hands back an opaque pointer, which is the
/// only arrangement where a program can run two architectures at once.
/// The solver library: an architecture as terms a solver holds.
///
/// ⚠️ It carries NO semantics of its own. `emit-smt2`'s `axis_instr_*`
/// functions are proven equal to the golden model, and this ships that text
/// and binds it into a caller's Z3 context -- so a consumer building a
/// symbolic engine applies the proven function instead of deriving a second
/// one. Everything here is plumbing: parsing, naming, arity, operand order.
/// A third spelling of `fadd_rm` is exactly what this exists to avoid.
///
/// ⚠️ Z3's parser INLINES `define-fun`, so the definitions cannot be asked for
/// again once parsed. What can be done is to bind each instruction once, in
/// the same text: an assertion that applies it to named constants. Parsing
/// gives those applications back already expanded, and `apply` is then
/// `Z3_substitute` of the caller's terms for the constants. One parse for the
/// whole architecture, and the semantics stay the proven file's.
pub fn emit_pack_z3_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let smt = crate::emit::semantics::emit_smt2(document);
    let functions = smt_signatures(&smt);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's proven terms, bound to a solver. */\n");
    out.push_str("/* schema: axis.pack-z3-c.v1 */\n");
    out.push_str("#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n");
    out.push_str("#include \"axis_pack.h\"\n#include <z3.h>\n\n");
    out.push_str("/* `emit-smt2`'s output, verbatim, and then one assertion per\n   \
instruction applying it to named constants. The proof that these mean what\n   \
the instructions mean is that file's, which is why this one has no\n   semantics in it. */\n");
    out.push_str("static const char AXIS_Z3_SMTLIB[] =\n");
    for line in smt.lines() {
        out.push_str(&format!("  {}\n", c_string(&format!("{line}\n"))));
    }
    for (index, function) in functions.iter().enumerate() {
        for (position, bits) in function.parameters.iter().enumerate() {
            out.push_str(&format!(
                "  {}\n",
                c_string(&format!(
                    "(declare-fun axis_arg_{index}_{position} () (_ BitVec {bits}))\n"
                ))
            ));
        }
        let arguments = (0..function.parameters.len())
            .map(|position| format!("axis_arg_{index}_{position}"))
            .collect::<Vec<_>>()
            .join(" ");
        let call = if function.parameters.is_empty() {
            function.name.clone()
        } else {
            format!("({} {arguments})", function.name)
        };
        // ⚠️ Bound against a NAMED constant, and the term is whichever side of
        // the equality is not it. Z3 normalises an equality's operands, so
        // "argument 0" is not reliably the application -- with the numeral on
        // the other side, `add`'s term came back as the literal zero and every
        // value folded to it.
        out.push_str(&format!(
            "  {}\n",
            c_string(&format!(
                "(declare-fun axis_bind_{index} () (_ BitVec {}))\n",
                function.result
            ))
        ));
        out.push_str(&format!(
            "  {}\n",
            c_string(&format!("(assert (= axis_bind_{index} {call}))\n"))
        ));
    }
    out.push_str("  ;\n\n");
    out.push_str("typedef struct axis_z3_signature {\n  const char *mnemonic;\n  \
int32_t arity;\n  const uint32_t *parameters;\n  const char *const *names;\n  \
uint32_t result;\n} axis_z3_signature;\n\n");
    for (index, function) in functions.iter().enumerate() {
        let widths = function
            .parameters
            .iter()
            .map(|bits| format!("{bits}u"))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "static const uint32_t AXIS_Z3_ARGS_{index}[] = {{ {} }};\n",
            if widths.is_empty() { "0u".to_string() } else { widths }
        ));
        let names = function
            .names
            .iter()
            .map(|name| c_string(name))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "static const char *const AXIS_Z3_NAMES_{index}[] = {{ {} }};\n",
            if names.is_empty() { "NULL".to_string() } else { names }
        ));
    }
    out.push_str("\nstatic const axis_z3_signature AXIS_Z3_SIGNATURES[] = {\n");
    for (index, function) in functions.iter().enumerate() {
        out.push_str(&format!(
            "  {{ {}, {}, AXIS_Z3_ARGS_{index}, AXIS_Z3_NAMES_{index}, {}u }},\n",
            c_string(&function.name),
            function.parameters.len(),
            function.result
        ));
    }
    out.push_str("};\n");
    out.push_str(&format!("#define AXIS_Z3_COUNT {}\n\n", functions.len()));
    // Which term is which part of which instruction. The SMT file names them
    // (`axis_instr_add`, `axis_effect_beq_0_guard`) and the DOCUMENT says what
    // each effect is -- a store, a branch, a state write -- so the directory is
    // built from both rather than parsed out of the names.
    let term_of = |name: &str| -> i32 {
        functions
            .iter()
            .position(|function| function.name == name)
            .map(|at| at as i32)
            .unwrap_or(-1)
    };
    let mut rows: Vec<String> = Vec::new();
    let mut effect_rows: Vec<String> = Vec::new();
    for instruction in &document.instructions {
        let ident = crate::emit::semantics::smt_ident_of(&instruction.mnemonic);
        let effects = instruction
            .behavior
            .as_ref()
            .map(|behavior| behavior.effects.as_slice())
            .unwrap_or(&[]);
        let first = effect_rows.len();
        for (position, effect) in effects.iter().enumerate() {
            let (kind, place) = match &effect.loc {
                crate::effects::Loc::Reg(name) => ("set", Some(name.clone())),
                crate::effects::Loc::FixedReg { kind, index, .. } => {
                    ("set", Some(format!("{kind}:{index}")))
                }
                crate::effects::Loc::State { name, .. } => ("setstate", Some(name.clone())),
                crate::effects::Loc::Mem { .. } => ("store", None),
                crate::effects::Loc::Pc => ("setpc", None),
                crate::effects::Loc::Trap => ("trap", None),
                crate::effects::Loc::Barrier { .. } => ("barrier", None),
                crate::effects::Loc::Port { .. } => ("send", None),
            };
            // An effect the SMT file did not write a value for, because the
            // instruction's own function already is it, points there.
            let mut value = term_of(&format!("axis_effect_{ident}_{position}_value"));
            if value < 0 && kind == "set" && effects.len() == 1 {
                value = term_of(&format!("axis_instr_{ident}"));
            }
            // The load's shape, from the description rather than the term: an
            // access width and whether it sign-extends are facts about the
            // instruction, and the address is the only part a solver holds.
            let (load_bits, load_signed) =
                crate::effects::plain_load(&effect.value.expr)
                    .map(|(_addr, bits, signed)| (bits, i32::from(signed)))
                    .unwrap_or((0, 0));
            effect_rows.push(format!(
                "  {{ {}, {}, {}, {}, {}, {}, {load_bits}u, {load_signed} }},",
                c_string(kind),
                place.map(|name| c_string(&name)).unwrap_or("NULL".to_string()),
                term_of(&format!("axis_effect_{ident}_{position}_guard")),
                term_of(&format!("axis_effect_{ident}_{position}_addr")),
                value,
                term_of(&format!("axis_effect_{ident}_{position}_load_addr"))
            ));
        }
        rows.push(format!(
            "  {{ {}, {}, {}, {} }},",
            c_string(&instruction.mnemonic),
            term_of(&format!("axis_instr_{ident}")),
            first,
            effects.len()
        ));
    }
    out.push_str("/* ⚠️ `load` is three fields, not one. An SMT function over bitvectors has\n   no memory to read, so a load's VALUE cannot be written -- but its address\n   can, and a consumer that has memory does the `select` itself. The width and\n   the sign are what it needs to know to do that, and they are the\n   description's rather than the term's. `load` is -1 when the effect's value\n   is not exactly a load. */\n");
    out.push_str("typedef struct axis_z3_effect {\n  const char *kind;\n  const char *place;\n  int32_t guard;\n  int32_t addr;\n  int32_t value;\n  int32_t load;\n  uint32_t load_bits;\n  int32_t load_signed;\n} axis_z3_effect;\n\n");
    out.push_str("static const axis_z3_effect AXIS_Z3_EFFECTS[] = {\n");
    for row in &effect_rows {
        out.push_str(row);
        out.push('\n');
    }
    out.push_str("  { NULL, NULL, -1, -1, -1, -1, 0u, 0 }\n};\n\n");
    out.push_str("typedef struct axis_z3_instruction {\n  const char *mnemonic;\n  int32_t value;\n  int32_t first_effect;\n  int32_t effects;\n} axis_z3_instruction;\n\n");
    out.push_str("static const axis_z3_instruction AXIS_Z3_INSTRUCTIONS[] = {\n");
    for row in &rows {
        out.push_str(row);
        out.push('\n');
    }
    out.push_str("};\n");
    out.push_str(&format!("#define AXIS_Z3_INSTRUCTION_COUNT {}\n\n", rows.len()));
    out.push_str("typedef struct axis_z3_handle {\n  Z3_context context;\n  \
Z3_ast bodies[AXIS_Z3_COUNT ? AXIS_Z3_COUNT : 1];\n  \
Z3_ast *arguments[AXIS_Z3_COUNT ? AXIS_Z3_COUNT : 1];\n} axis_z3_handle;\n\n");
    out.push_str("static const char *axis_z3_smtlib(void) { return AXIS_Z3_SMTLIB; }\n\n");
    out.push_str("static void *axis_z3_open(void *context) {\n");
    out.push_str("  Z3_context ctx = (Z3_context)context;\n  if (!ctx) { return NULL; }\n");
    out.push_str("  Z3_ast_vector parsed = Z3_parse_smtlib2_string(ctx, AXIS_Z3_SMTLIB, 0, NULL,\n                                                NULL, 0, NULL, NULL);\n");
    out.push_str("  if (!parsed) { return NULL; }\n");
    out.push_str("  Z3_ast_vector_inc_ref(ctx, parsed);\n");
    out.push_str("  unsigned found = Z3_ast_vector_size(ctx, parsed);\n");
    out.push_str("  /* One assertion per instruction, in the order they were written.\n     Fewer means the solver dropped one, and a handle that guessed which\n     would be answering about the wrong instruction. */\n");
    out.push_str("  if (found != (unsigned)AXIS_Z3_COUNT) {\n    Z3_ast_vector_dec_ref(ctx, parsed);\n    return NULL;\n  }\n");
    out.push_str("  axis_z3_handle *handle = (axis_z3_handle *)calloc(1, sizeof *handle);\n");
    out.push_str("  if (!handle) { Z3_ast_vector_dec_ref(ctx, parsed); return NULL; }\n");
    out.push_str("  handle->context = ctx;\n");
    out.push_str("  /* ⚠️ Each assertion says which term it binds, and the position it\n     came back in does not. `(= axis_bind_7 <term>)` is read by finding the\n     ANCHOR -- a constant whose name carries the index -- because the parser\n     is free to reorder both the assertions and an equality's two sides, and\n     reading them positionally handed out `addiw`'s term for `addi`: the same\n     arithmetic, sign-extended from 32, which looks like an answer. */\n");
    out.push_str("  for (unsigned a = 0; a < found; ++a) {\n");
    out.push_str("    Z3_ast bound = Z3_ast_vector_get(ctx, parsed, a);\n");
    out.push_str("    if (Z3_get_ast_kind(ctx, bound) != Z3_APP_AST) { continue; }\n");
    out.push_str("    Z3_app application = Z3_to_app(ctx, bound);\n");
    out.push_str("    if (Z3_get_app_num_args(ctx, application) != 2) { continue; }\n");
    out.push_str("    Z3_ast sides[2] = { Z3_get_app_arg(ctx, application, 0),\n                        Z3_get_app_arg(ctx, application, 1) };\n");
    out.push_str("    int32_t which = -1, other = -1;\n");
    out.push_str("    for (int32_t side = 0; side < 2; ++side) {\n");
    out.push_str("      if (Z3_get_ast_kind(ctx, sides[side]) != Z3_APP_AST) { continue; }\n");
    out.push_str("      Z3_app constant = Z3_to_app(ctx, sides[side]);\n");
    out.push_str("      if (Z3_get_app_num_args(ctx, constant) != 0) { continue; }\n");
    out.push_str("      Z3_symbol symbol = Z3_get_decl_name(ctx, Z3_get_app_decl(ctx, constant));\n");
    out.push_str("      if (Z3_get_symbol_kind(ctx, symbol) != Z3_STRING_SYMBOL) { continue; }\n");
    out.push_str("      const char *name = Z3_get_symbol_string(ctx, symbol);\n");
    out.push_str("      int32_t at = -1;\n");
    out.push_str("      if (name && sscanf(name, \"axis_bind_%d\", &at) == 1) {\n");
    out.push_str("        which = at; other = 1 - side;\n      }\n    }\n");
    out.push_str("    if (which < 0 || which >= AXIS_Z3_COUNT || handle->bodies[which]) { continue; }\n");
    out.push_str("    Z3_ast body = sides[other];\n");
    out.push_str("    Z3_inc_ref(ctx, body);\n    handle->bodies[which] = body;\n");
    out.push_str("  }\n");
    out.push_str("  /* And the argument constants each term substitutes for. */\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_Z3_COUNT; ++i) {\n");
    out.push_str("    int32_t arity = AXIS_Z3_SIGNATURES[i].arity;\n");
    out.push_str("    handle->arguments[i] = (Z3_ast *)calloc(arity ? (size_t)arity : 1,\n                                            sizeof(Z3_ast));\n");
    out.push_str("    if (!handle->arguments[i]) { continue; }\n");
    out.push_str("    for (int32_t k = 0; k < arity; ++k) {\n");
    out.push_str("      char name[64];\n");
    out.push_str("      snprintf(name, sizeof name, \"axis_arg_%d_%d\", i, k);\n");
    out.push_str("      Z3_sort sort = Z3_mk_bv_sort(ctx, AXIS_Z3_SIGNATURES[i].parameters[k]);\n");
    out.push_str("      Z3_ast constant = Z3_mk_const(ctx, Z3_mk_string_symbol(ctx, name), sort);\n");
    out.push_str("      Z3_inc_ref(ctx, constant);\n      handle->arguments[i][k] = constant;\n    }\n  }\n");
    out.push_str("  Z3_ast_vector_dec_ref(ctx, parsed);\n  return handle;\n}\n\n");
    out.push_str("static void axis_z3_close(void *raw) {\n");
    out.push_str("  axis_z3_handle *handle = (axis_z3_handle *)raw;\n  if (!handle) { return; }\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_Z3_COUNT; ++i) {\n");
    out.push_str("    if (handle->bodies[i]) { Z3_dec_ref(handle->context, handle->bodies[i]); }\n");
    out.push_str("    if (!handle->arguments[i]) { continue; }\n");
    out.push_str("    for (int32_t k = 0; k < AXIS_Z3_SIGNATURES[i].arity; ++k) {\n");
    out.push_str("      if (handle->arguments[i][k]) { Z3_dec_ref(handle->context, handle->arguments[i][k]); }\n    }\n");
    out.push_str("    free(handle->arguments[i]);\n  }\n  free(handle);\n}\n\n");
    out.push_str("static int axis_z3_in_range(int32_t i) { return i >= 0 && i < AXIS_Z3_COUNT; }\n");
    out.push_str("static int axis_z3_named(int32_t i) { return i >= 0 && i < AXIS_Z3_INSTRUCTION_COUNT; }\n");
    out.push_str("static int32_t axis_z3_count(void *raw) { (void)raw; return AXIS_Z3_INSTRUCTION_COUNT; }\n");
    out.push_str("static int32_t axis_z3_terms(void *raw) { (void)raw; return AXIS_Z3_COUNT; }\n");
    out.push_str("static const char *axis_z3_mnemonic(void *raw, int32_t i) {\n  (void)raw;\n  return axis_z3_named(i) ? AXIS_Z3_INSTRUCTIONS[i].mnemonic : NULL;\n}\n");
    out.push_str("static int32_t axis_z3_value_term(void *raw, int32_t i) {\n  (void)raw;\n  return axis_z3_named(i) ? AXIS_Z3_INSTRUCTIONS[i].value : -1;\n}\n");
    out.push_str("static int32_t axis_z3_effect_count(void *raw, int32_t i) {\n  (void)raw;\n  return axis_z3_named(i) ? AXIS_Z3_INSTRUCTIONS[i].effects : 0;\n}\n");
    out.push_str("static const axis_z3_effect *axis_z3_effect_at(int32_t i, int32_t k) {\n");
    out.push_str("  if (!axis_z3_named(i) || k < 0 || k >= AXIS_Z3_INSTRUCTIONS[i].effects) { return NULL; }\n");
    out.push_str("  return &AXIS_Z3_EFFECTS[AXIS_Z3_INSTRUCTIONS[i].first_effect + k];\n}\n");
    out.push_str("static const char *axis_z3_effect_kind(void *raw, int32_t i, int32_t k) {\n  (void)raw;\n  const axis_z3_effect *e = axis_z3_effect_at(i, k);\n  return e ? e->kind : NULL;\n}\n");
    out.push_str("static uint32_t axis_z3_effect_load_bits(void *raw, int32_t i, int32_t k) {\n  (void)raw;\n  const axis_z3_effect *e = axis_z3_effect_at(i, k);\n  return e ? e->load_bits : 0u;\n}\n");
    out.push_str("static int32_t axis_z3_effect_load_signed(void *raw, int32_t i, int32_t k) {\n  (void)raw;\n  const axis_z3_effect *e = axis_z3_effect_at(i, k);\n  return e ? e->load_signed : 0;\n}\n");
    out.push_str("static const char *axis_z3_effect_place(void *raw, int32_t i, int32_t k) {\n  (void)raw;\n  const axis_z3_effect *e = axis_z3_effect_at(i, k);\n  return e ? e->place : NULL;\n}\n");
    out.push_str("static int32_t axis_z3_effect_term(void *raw, int32_t i, int32_t k, const char *part) {\n  (void)raw;\n");
    out.push_str("  const axis_z3_effect *e = axis_z3_effect_at(i, k);\n");
    out.push_str("  if (!e || !part) { return -1; }\n");
    out.push_str("  if (!strcmp(part, \"load_addr\")) { return e->load; }\n");
    out.push_str("  if (!strcmp(part, \"guard\")) { return e->guard; }\n");
    out.push_str("  if (!strcmp(part, \"addr\")) { return e->addr; }\n");
    out.push_str("  if (!strcmp(part, \"value\")) { return e->value; }\n");
    out.push_str("  return -1;\n}\n");
    out.push_str("static const char *axis_z3_term_name(void *raw, int32_t i) {\n  (void)raw;\n  return axis_z3_in_range(i) ? AXIS_Z3_SIGNATURES[i].mnemonic : NULL;\n}\n");
    out.push_str("static int32_t axis_z3_arity(void *raw, int32_t i) {\n  (void)raw;\n  return axis_z3_in_range(i) ? AXIS_Z3_SIGNATURES[i].arity : 0;\n}\n");
    out.push_str("static uint32_t axis_z3_operand_bits(void *raw, int32_t i, int32_t operand) {\n  (void)raw;\n");
    out.push_str("  if (!axis_z3_in_range(i) || operand < 0 || operand >= AXIS_Z3_SIGNATURES[i].arity) { return 0u; }\n");
    out.push_str("  return AXIS_Z3_SIGNATURES[i].parameters[operand];\n}\n");
    out.push_str("static uint32_t axis_z3_value_bits(void *raw, int32_t i) {\n  (void)raw;\n  return axis_z3_in_range(i) ? AXIS_Z3_SIGNATURES[i].result : 0u;\n}\n");
    out.push_str("/* ⚠️ A parameter is an operand or a piece of architectural state, and\n   only its NAME says which. A caller binding by position alone would hand\n   a register's contents to a rounding mode and get a term about nothing --\n   which is what the gate saw before these were published. */\n");
    out.push_str("static const char *axis_z3_operand_name(void *raw, int32_t i, int32_t operand) {\n  (void)raw;\n");
    out.push_str("  if (!axis_z3_in_range(i) || operand < 0 || operand >= AXIS_Z3_SIGNATURES[i].arity) { return NULL; }\n");
    out.push_str("  return AXIS_Z3_SIGNATURES[i].names[operand];\n}\n");
    out.push_str("/* The directory is keyed by the mnemonic as the DESCRIPTION spells it:\n   the table carries the document's own name, not the SMT file's\n   lower-cased one. */\n");
    out.push_str("static int32_t axis_z3_index_of(void *raw, const char *mnemonic) {\n  (void)raw;\n");
    out.push_str("  if (!mnemonic) { return -1; }\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_Z3_INSTRUCTION_COUNT; ++i) {\n");
    out.push_str("    if (!strcmp(AXIS_Z3_INSTRUCTIONS[i].mnemonic, mnemonic)) { return i; }\n  }\n");
    out.push_str("  return -1;\n}\n\n");
    out.push_str("/* ⚠️ Arity and sorts are checked before substituting. `Z3_substitute` with\n   \
a mismatched sort gives back a term in an error state rather than refusing,\n   \
and a caller would carry that into a solver and get an answer about\n   something else. */\n");
    out.push_str("static void *axis_z3_apply(void *raw, int32_t i, void *const *operands, int32_t count) {\n");
    out.push_str("  axis_z3_handle *handle = (axis_z3_handle *)raw;\n");
    out.push_str("  if (!handle || !axis_z3_in_range(i) || (count && !operands)) { return NULL; }\n");
    out.push_str("  if (count != AXIS_Z3_SIGNATURES[i].arity || !handle->bodies[i]) { return NULL; }\n");
    out.push_str("  if (!count) { return (void *)handle->bodies[i]; }\n");
    out.push_str("  Z3_ast *given = (Z3_ast *)calloc((size_t)count, sizeof(Z3_ast));\n");
    out.push_str("  if (!given) { return NULL; }\n");
    out.push_str("  for (int32_t k = 0; k < count; ++k) {\n");
    out.push_str("    if (!operands[k]) { free(given); return NULL; }\n");
    out.push_str("    Z3_sort want = Z3_mk_bv_sort(handle->context, AXIS_Z3_SIGNATURES[i].parameters[k]);\n");
    out.push_str("    Z3_sort have = Z3_get_sort(handle->context, (Z3_ast)operands[k]);\n");
    out.push_str("    if (!Z3_is_eq_sort(handle->context, want, have)) { free(given); return NULL; }\n");
    out.push_str("    given[k] = (Z3_ast)operands[k];\n  }\n");
    out.push_str("  Z3_ast term = Z3_substitute(handle->context, handle->bodies[i], (unsigned)count,\n                              handle->arguments[i], given);\n");
    out.push_str("  free(given);\n  return (void *)term;\n}\n\n");
    out.push_str(&format!(
        "static const axis_z3_pack AXIS_Z3_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  {}, {}, {},\n  \
\"z3\",\n  axis_z3_smtlib, axis_z3_open, axis_z3_close,\n  \
axis_z3_count, axis_z3_mnemonic, axis_z3_index_of,\n  \
axis_z3_value_term, axis_z3_effect_count, axis_z3_effect_kind,\n  \
axis_z3_effect_place, axis_z3_effect_term,\n  \
axis_z3_effect_load_bits, axis_z3_effect_load_signed,\n  \
axis_z3_terms, axis_z3_term_name, axis_z3_arity,\n  \
axis_z3_operand_name, axis_z3_operand_bits, axis_z3_value_bits, axis_z3_apply\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_z3_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_z3_pack *axis_z3_pack_{ident}(void) {{ return &AXIS_Z3_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

/// One `define-fun` the SMT backend emitted: its name, its parameters' names
/// and widths, and its result width.
struct SmtSignature {
    name: String,
    parameters: Vec<u32>,
    names: Vec<String>,
    result: u32,
}

/// The instruction functions `emit-smt2` defined, read back out of its output.
///
/// ⚠️ Read rather than recomputed. Which instructions that file defines, and
/// which it declines, is its decision -- taken instruction by instruction with
/// a reason printed beside each -- and a second answer here would ship terms
/// for instructions it had refused.
fn smt_signatures(text: &str) -> Vec<SmtSignature> {
    let mut out = Vec::new();
    for line in text.lines() {
        // ⚠️ Both families. The value functions are `axis_instr_*` and the
        // effect parts are `axis_effect_*`; reading only the first left every
        // branch condition and store address out of the table, and the
        // directory pointed at terms that were not there.
        let Some(rest) = line
            .strip_prefix("(define-fun axis_instr_")
            .map(|rest| ("axis_instr_", rest))
            .or_else(|| {
                line.strip_prefix("(define-fun axis_effect_")
                    .map(|rest| ("axis_effect_", rest))
            })
        else {
            continue;
        };
        let (prefix, rest) = rest;
        let Some((name, rest)) = rest.split_once(" (") else { continue };
        let Some((parameters, result)) = rest.rsplit_once(") (_ BitVec ") else { continue };
        let Some(result) = result.trim_end_matches(')').parse::<u32>().ok() else { continue };
        let mut widths = Vec::new();
        let mut names = Vec::new();
        let mut ok = true;
        // `((rs1 (_ BitVec 64)) (frm (_ BitVec 3)))`: the NAME matters as much
        // as the width. A parameter can be an operand or a piece of
        // architectural state, and only its name says which -- a caller that
        // bound them by position would hand a register's contents to a
        // rounding mode and get a well-formed term about nothing.
        for piece in parameters.split('(').skip(1) {
            let piece = piece.trim();
            // ⚠️ `_ BitVec 64`, not "anything starting with an underscore". A
            // parameter named `__input_rs1` -- an operand's value on entry,
            // which a compare-and-swap's guard reads -- starts with one too,
            // and skipping it made the name list shorter than the width list,
            // which dropped the whole signature. Four hundred and eighty
            // effect terms went missing that way, silently.
            if piece.starts_with("_ ") || piece.is_empty() {
                continue;
            }
            match piece.split_whitespace().next() {
                Some(parameter) => names.push(parameter.to_string()),
                None => ok = false,
            }
        }
        for piece in parameters.split("(_ BitVec ").skip(1) {
            match piece.split(')').next().and_then(|bits| bits.trim().parse::<u32>().ok()) {
                Some(bits) => widths.push(bits),
                None => ok = false,
            }
        }
        if ok && names.len() == widths.len() {
            out.push(SmtSignature {
                name: format!("{prefix}{name}"),
                parameters: widths,
                names,
                result,
            });
        }
    }
    out
}

pub fn emit_pack_sim_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let state = crate::effects::isa_scalar_state_slots(&document.isas);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's simulator, as a library. */\n");
    out.push_str("/* schema: axis.pack-sim-c.v1 */\n");
    out.push_str("#include <stdlib.h>\n#include <string.h>\n");
    out.push_str("#include \"axis_pack.h\"\n#include \"axis_lift.h\"\n");
    out.push_str("#include \"axis_semantics.h\"\n#include \"axis_exec.h\"\n#include \"axis_sim.h\"\n\n");
    // A description whose instructions touch more than the contract carries
    // must fail to BUILD. Truncating an event would be reporting less than
    // happened, in a field whose whole purpose is to say what happened.
    out.push_str("/* ⚠️ An event that cannot carry everything an instruction did SAYS SO\n   \
(`reads_total`, `accesses_total`), where this was two compile-time\n   \
assertions that it always could. A trace that quietly lost entries is\n   \
still refused -- the totals are what makes the loss loud -- but the\n   \
assertions refused more than that: a description with one instruction\n   \
wider than the record had no simulator at all, and SVE and SME are\n   \
made of them. */\n");
    out.push_str("_Static_assert(AXIS_EXEC_MAX_LIMBS <= (int)AXIS_PACK_MAX_LIMBS,\n               \
\"this description's registers take more limbs than the pack contract carries\");\n\n");
    out.push_str("/* One translated run of straight-line instructions, kept by the pc it\n   starts at. ⚠️ A block is what makes this fast rather than merely\n   JIT-shaped: translation costs microseconds and a loop pays it once. */\n");
    out.push_str("typedef struct axis_sim_block {\n  uint64_t pc;\n  size_t at;\n  \
size_t used;\n  int32_t count;\n  int32_t live;\n  \
/* ⚠️ Whether anything in it touches architectural state. The machine keeps\n     named entries and a stencil wants a flat array, so the two are copied\n     around every block that needs it -- and copying them around every block\n     that does NOT cost more than the translation saved on short blocks: a\n     RISC-V loop of plain arithmetic went from 9.2x to 1.4x paying for six\n     slots it never read. Asked once, when the block is built. */\n  \
int32_t touches_state;\n  \
/* Whether its last instruction may redirect the pc. A block is straight-line\n     code, so a branch can only ever be its last: everything after a taken one\n     would run regardless. */\n  \
int32_t ends_on_branch;\n} axis_sim_block;\n\n");
    out.push_str("/* ⚠️ A pc where a block could NOT be built is remembered too. Without\n   that, a machine whose instructions the translator does not take pays for a\n   failed build at every pc, every time round the loop -- which measured 0.55x\n   against plain interpretation: not slower to translate, slower to keep\n   asking. */\n");
    out.push_str("typedef struct axis_sim_cold {\n  uint64_t pc;\n  int32_t live;\n} axis_sim_cold;\n\n");
    out.push_str("#define AXIS_SIM_BLOCK_MAX 32\n");
    out.push_str("#define AXIS_SIM_BLOCKS_DEFAULT 64\n");
    out.push_str("#define AXIS_SIM_CODE_BYTES (1u << 20)\n");
    out.push_str("#define AXIS_SIM_CACHE_LINES 4096u\n");
    out.push_str("#define AXIS_SIM_UNIT_COPIES 256u\n");
    out.push_str("/* The most lanes one copy of a unit is modelled with (VU1). */\n#define AXIS_SIM_UNIT_LANES_MAX 16u\n");
    out.push_str("#define AXIS_SIM_BHT_ENTRIES 4096u\n");
    out.push_str("/* The ring's storage, a power of two: an entry lives at seq % AXIS_SIM_ROB_MAX,\n   which is a mask, whatever the core's buffer. What the core may hold is\n   rob_tail - rob_head < axis_ooo_rob(core), never the slot it lands in --\n   indexed by the core's size instead, every access in the window's scans was\n   a division. */\n");
    out.push_str("#define AXIS_SIM_ROB_MAX 512u\n");
    out.push_str("#define AXIS_SIM_SB_MAX 64u\n");
    out.push_str("#define AXIS_SIM_KEEP 4\n");
    out.push_str("_Static_assert((AXIS_SIM_ROB_MAX & (AXIS_SIM_ROB_MAX - 1u)) == 0u, \"the ROB ring is a power of two\");\n");
    out.push_str("/* What an in-order machine holds in flight when its description says\n   nothing: deep enough that the buffer is never what limits it. */\n");
    out.push_str("#define AXIS_SIM_INORDER_WINDOW 64u\n");
    // Eight each (A64-1): an AArch64 FMADD reads three registers and FPCR, a
    // load pair with writeback writes three, and a flag-setting op adds NZCV.
    // ⚠️ How many registers a window entry reads and writes is the
    // description's too (VM2): a vector instruction reads and writes every
    // limb of every register its lanes name.
    // ⚠️ SLOTS, not registers (VM3): `AXIS_SIM_MAX_READS` counts registers, and
    // an entry names every 64-bit slot of each -- eight for a 512-bit
    // register, and an SME outer product writes a whole tile of them. Sized
    // by registers alone, every instruction that wrote a tile overflowed its
    // entry and was replayed.
    out.push_str(&format!(
        "enum {{ AXIS_SIM_WORD_SLOTS = {},\n       AXIS_SIM_WIDE_RAW = AXIS_SIM_MAX_READS * AXIS_EXEC_MAX_LIMBS > AXIS_SIM_WORD_SLOTS\n                           ? AXIS_SIM_MAX_READS * AXIS_EXEC_MAX_LIMBS : AXIS_SIM_WORD_SLOTS,\n       AXIS_SIM_WIDE = AXIS_SIM_WIDE_RAW > 256 ? 256 : (AXIS_SIM_WIDE_RAW < 8 ? 8 : AXIS_SIM_WIDE_RAW) }};\n",
        widest_word_slots(document)
    ));
    out.push_str("#define AXIS_SIM_OOO_SRC AXIS_SIM_WIDE\n#define AXIS_SIM_OOO_DST AXIS_SIM_WIDE\n");
    out.push_str("/* Who produces each register slot -- and, past them, each state slot. */\n#define AXIS_SIM_PRODUCERS (AXIS_SIM_REG_SLOTS + 64u)\n");
    // ⚠️ How many accesses a window entry holds is the DESCRIPTION's: a
    // scalar machine's instructions make a handful, a vector load makes one
    // per lane. Four, fixed, made every vector store overflow its entry --
    // which is a replay at commit, every time. Adjacent accesses are
    // coalesced as they are recorded, so this bounds what cannot be: a
    // gather's scattered lanes.
    out.push_str("#if AXIS_SIM_MAX_ACCESSES > 64\n#define AXIS_SIM_OOO_MEM 64\n#elif AXIS_SIM_MAX_ACCESSES > 4\n#define AXIS_SIM_OOO_MEM AXIS_SIM_MAX_ACCESSES\n#else\n#define AXIS_SIM_OOO_MEM 4\n#endif\n");
    out.push_str("#define AXIS_SIM_RENAME_POOLS 8\n");
    out.push_str("#define AXIS_SIM_SSIT_MAX 4096u\n");
    out.push_str("#define AXIS_SIM_BTB_MAX 4096u\n");
    out.push_str("#define AXIS_SIM_FE_MAX 1024u\n");
    out.push_str("#define AXIS_SIM_ICACHE_LINES 1024u\n");
    // The TLB arrays are as large as the largest any core declares: a
    // machine of a description with no TLB carries one entry of each.
    let tlb_l1 = document
        .cores
        .iter()
        .filter_map(|c| c.tlb.as_ref())
        .map(|t| t.data.entries.max(t.fetch.entries))
        .max()
        .unwrap_or(0)
        .max(1);
    let tlb_l2 = document.cores.iter().filter_map(|c| c.tlb.as_ref()).map(|t| t.second.entries).max().unwrap_or(0).max(1);
    out.push_str(&format!("#define AXIS_SIM_TLB_L1 {tlb_l1}u\n#define AXIS_SIM_TLB_L2 {tlb_l2}u\n"));
    out.push_str("#define AXIS_SIM_WP_MAX 1024u\n");
    out.push_str("/* How deep detours nest on a wrong path (W5): a wrong-path branch's own\n   wrong path, and that one's, this many times. Deeper, a branch is followed\n   where it goes. */\n#define AXIS_SIM_WP_DEPTH 4\n");
    out.push_str("#define AXIS_SIM_SHADOW_BYTES 1024u\n");
    out.push_str("#define AXIS_SIM_XBUF 256u\n");
    out.push_str("#define AXIS_SIM_X_WRITES AXIS_SIM_WIDE\n");
    out.push_str("#define AXIS_SIM_NO_SEQ UINT64_MAX\n\n");
    // ⚠️ A REORDER BUFFER ENTRY. The in-order model needs none of this: it
    // computes a cycle per instruction and forgets it. An out-of-order
    // machine has to remember what is in flight, because what is in flight is
    // what makes it out of order.
    out.push_str("typedef struct axis_sim_rob_entry {\n");
    out.push_str("  uint64_t seq;\n");
    out.push_str("  int32_t valid;\n  int32_t issued;\n");
    out.push_str("  uint64_t complete;\n");
    out.push_str("  uint32_t latency;\n  uint64_t stall;\n");
    out.push_str("  int32_t unit;        /* index into the core's units, -1 for none */\n");
    out.push_str("  int32_t elim;        /* a move done at rename (ME1): no queue slot, unit or register */\n");
    out.push_str("  /* WM2: what its first reads of memory were given, and whether another\n     core's store has overtaken one of them and it kept what it read. */\n  int32_t x_overtaken;\n  int32_t x_rcount;\n  uint64_t x_raddr[AXIS_SIM_KEEP];\n  uint64_t x_rval[AXIS_SIM_KEEP];\n  uint32_t x_rwidth[AXIS_SIM_KEEP];\n");
    out.push_str("  int32_t x_ordered;   /* WM1: whether it orders memory -- 0 not yet asked, 1 no, 2 yes */\n");
    out.push_str("  int32_t fused;       /* the tail of a fused pair (FU1): no entry of its own, no width */\n  int32_t fuse_head;   /* the head of one */\n");
    out.push_str("  uint32_t redirect;   /* cycles the front end owes after this one */\n");
    out.push_str("  int32_t src_count;\n  uint64_t src_seq[AXIS_SIM_OOO_SRC];\n");
    out.push_str("  int32_t dst_count;\n  uint32_t dst_slot[AXIS_SIM_OOO_DST];\n");
    out.push_str("  /* The rename pool each destination took a register from, -1 for none. */\n");
    out.push_str("  int32_t dst_pool[AXIS_SIM_OOO_DST];\n");
    out.push_str("  /* What it touched in memory, as the functional step saw it: a trace\n     knows every address, which is what makes perfect disambiguation a\n     configuration rather than a fiction. [lo, hi) in bytes. */\n");
    out.push_str("  int32_t is_load;\n  int32_t is_store;\n");
    out.push_str("  /* ⚠️ A STORE'S ADDRESS is known before its value can be (O4): the\n     producers of the operands its address is computed from, apart from the\n     rest. A load waiting on an older store's address waits on these, not on\n     the whole store. `addr_known` latches once they have landed. */\n");
    out.push_str("  int32_t addr_src_count;\n  uint64_t addr_src_seq[AXIS_SIM_OOO_SRC];\n  int32_t addr_known;\n");
    out.push_str("  /* Where it is, its store set (0 for none), and the first cycle it may\n     issue again after a squash. */\n");
    out.push_str("  uint64_t pc;\n  uint32_t store_set;\n  uint64_t not_before;\n");
    out.push_str("  /* ⚠️ EXECUTION-DRIVEN (E1): the word and its decode, where the front end\n     guessed it goes, what executing it computed -- registers, state, stores\n     held back, loads it read -- and the return stack before it. */\n");
    out.push_str("  uint32_t x_word;\n  int32_t x_bad;\n  axis_lifted x_lifted;\n  uint64_t x_pred_next;\n");
    out.push_str("  int32_t x_branch;\n  int32_t x_conditional;\n  uint32_t x_ras_top;\n  uint32_t x_ras_count;\n");
    out.push_str("  int32_t x_executed;\n  int32_t x_resolved;\n  uint64_t x_next;\n  int32_t x_trapped;\n  int32_t x_overflow;\n");
    out.push_str("  int32_t x_wcount;\n  uint32_t x_wslot[AXIS_SIM_X_WRITES];\n  uint64_t x_wval[AXIS_SIM_X_WRITES];\n");
    out.push_str("  int32_t x_scount;\n  uint32_t x_sidx[4];\n  uint64_t x_sval[4];\n");
    out.push_str("  int32_t x_mcount;\n  uint64_t x_maddr[AXIS_SIM_OOO_MEM];\n  uint64_t x_mval[AXIS_SIM_OOO_MEM];\n  uint32_t x_mwidth[AXIS_SIM_OOO_MEM];\n");
    out.push_str("  int32_t x_lcount;\n  uint64_t x_llo[AXIS_SIM_OOO_MEM];\n  uint64_t x_lhi[AXIS_SIM_OOO_MEM];\n");
    out.push_str("  /* E2: the branch history before it was fetched, and what it did to the\n     caches -- credited to the counters only if it commits. */\n");
    out.push_str("  uint64_t x_hist;\n  int32_t x_ic_miss;\n  uint64_t x_dhits;\n  uint64_t x_dmiss;\n  uint32_t x_tmiss;\n  uint32_t x_twalk;\n  uint8_t x_it_miss;\n");
    out.push_str("  /* U4b: the cycle it was fetched in -- with its pc, the tag a warp's\n     members fuse on. */\n  uint64_t x_fetched_at;\n");
    out.push_str("  /* And whether it redirected fetch: a wrong direction or a wrong target. */\n");
    out.push_str("  int32_t x_redirected;\n  int32_t x_wrong_target;\n");
    out.push_str("  /* ⚠️ ON THE WRONG PATH (W2), trace-driven: which instruction of the\n     shadow's trace this is, plus one; 0 for one of the program's own. It\n     holds its entry, its register and its unit like any other, never\n     retires, and leaves when its branch resolves. */\n  uint32_t wrong;\n");
    out.push_str("  /* How many 64-bit limbs the widest register this instruction names is\n     (VU1): the lanes it needs of a unit that has them. */\n  uint32_t span;\n");
    out.push_str("  /* ⚠️ HOW MUCH OF IT IS WORK (VU2): on a unit that names a length, the\n     operand carrying the element count -- a value in the word (1), or a\n     register read when it issues (2) -- with how many elements the word has\n     and how wide each is. 0: all of it. */\n");
    out.push_str("  uint32_t len_kind;\n  uint32_t len_slot;\n  uint64_t len_val;\n  uint32_t elems;\n  uint32_t elem_bits;\n");
    out.push_str("  int32_t mem_count;\n  uint64_t mem_lo[AXIS_SIM_OOO_MEM];\n  uint64_t mem_hi[AXIS_SIM_OOO_MEM];\n");
    out.push_str("  /* WHAT IT HOLDS OF A UNIT (W4): the copy it issued on, plus one; the unit\n     that copy belongs to -- its own, or the one that lent it lanes; whether\n     that is a unit shared between cores; which lanes; and until when. Read\n     only when it is squashed, by a unit that aborts. */\n");
    out.push_str("  int32_t held_slot;\n  int32_t held_unit;\n  int32_t held_shared;\n  uint32_t held_lanes;\n  uint64_t held_until;\n");
    out.push_str("  /* ⚠️ A MICRO-OP, execution-driven (U1): which of its instruction's it is\n     and of how many -- 0 of 0 for an instruction that is one entry -- and\n     which of the instruction's memory accesses are its own. */\n");
    out.push_str("  int32_t x_uop;\n  int32_t x_uops;\n  uint32_t x_acc_mask;\n  int32_t x_acc_rest;\n  /* The path it was fetched by (U2), counted when it retires. */\n  int32_t x_path;\n");
    out.push_str("  /* ⚠️ A VALUE PREDICTED (S4): `vp` while what depends on it need not wait\n     for it. Execution-driven, the value that was predicted, in the window\n     as if computed until the load really runs; and what came of it. */\n");
    out.push_str("  int32_t vp;\n  int32_t x_vp;\n  uint64_t x_vp_val;\n  int32_t x_vp_bad;\n");
    out.push_str("  /* TLB2: the cycles of page walk in what it waits on, which a walker has\n     to be free for. */\n  uint64_t walk;\n");
    out.push_str("  /* S8: its slot in the issue queue, plus one, on a machine that selects\n     by position; 0 until it has one. */\n  uint32_t iq_slot;\n");
    out.push_str("} axis_sim_rob_entry;\n\n");
    out.push_str("/* One instruction the execution-driven front end fetched and has not yet\n   dispatched. */\n");
    out.push_str("typedef struct axis_x_fetched {\n  uint64_t pc;\n  uint32_t word;\n  uint64_t fetched;\n  int32_t bad;\n");
    out.push_str("  int32_t branch;\n  int32_t conditional;\n  uint64_t pred_next;\n  uint32_t ras_top;\n  uint32_t ras_count;\n");
    out.push_str("  uint64_t hist;\n  int32_t ic_miss;\n  uint8_t it_miss;\n  /* U2: the stages between its fetch and dispatch, by the path it came. */\n  uint32_t depth;\n  int32_t path;\n");
    out.push_str("  axis_lifted lifted;\n} axis_x_fetched;\n\n");
    // The memory-system engine and this description's systems, ahead of the
    // machine that holds one (docs/memory_system_design.md, MS4).
    out.push_str(include_str!("memsys_engine.c"));
    out.push('\n');
    out.push_str(&crate::memsys::emit_pack_tables(document));
    out.push('\n');
    out.push_str("/* ⚠️ HARDWARE CONTEXTS (U4a, docs/unified_engine_design.md): machines that\n   are threads of ONE core point at one group, and share what a core has one\n   of -- its units, its issue ports, its issue, dispatch and commit bandwidth\n   each cycle -- while each keeps its own window share, rename map, front end\n   and golden model. The counters are this cycle's, reset when it changes. */\n");
    out.push_str("/* ⚠️ A WARP (U4b) is a set of a group's members that share a front end\n   too. Each cycle it fetches one pc (`fetch_pc[warp]`, chosen once per\n   cycle), and the back end sees an instruction its members fetched together as one: the\n   tags paid for this cycle, per stage -- dispatch, issue, commit -- are\n   `fuse_*`, and a member finding its instruction's tag there rides free. */\n");
    out.push_str("#define AXIS_SIM_WARP_MAX 64\n#define AXIS_SIM_FUSE 64\n");
    out.push_str(r#"/* ⚠️ A UNIT SHARED BY SEVERAL CORES (VU4): its copies and lanes, which core
   it served last and for how many turns running, and when each core last
   asked for it -- which is what "waiting" means. */
#define AXIS_SIM_SHARERS 8
#define AXIS_SIM_SHARED_UNITS 32
typedef struct axis_sim_shared {
  int32_t refs;
  uint64_t unit_free[AXIS_SIM_UNIT_COPIES];
  uint64_t lane_free[AXIS_SIM_UNIT_COPIES][AXIS_SIM_UNIT_LANES_MAX];
  const void *owner;
  uint32_t streak;
  int32_t count;
  const void *who[AXIS_SIM_SHARERS];
  uint64_t asked[AXIS_SIM_SHARERS];
} axis_sim_shared;

"#);
    out.push_str("typedef struct axis_sim_group {\n  int32_t refs;\n  int32_t count;\n  uint64_t unit_free[AXIS_SIM_UNIT_COPIES];\n  uint64_t lane_free[AXIS_SIM_UNIT_COPIES][AXIS_SIM_UNIT_LANES_MAX];\n  uint64_t cycle;\n  uint32_t issued;\n  uint32_t committed;\n  uint32_t dispatched;\n  uint32_t ports_busy;\n  uint32_t warp_age;\n  uint64_t fetch_cycle[AXIS_SIM_WARP_MAX];\n  uint64_t fetch_pc[AXIS_SIM_WARP_MAX];\n  int32_t fetch_any[AXIS_SIM_WARP_MAX];\n  struct axis_pack_machine *member[AXIS_SIM_WARP_MAX];\n  uint32_t fuse_n[3];\n  uint32_t fuse_warp[3][AXIS_SIM_FUSE];\n  uint64_t fuse_pc[3][AXIS_SIM_FUSE];\n  uint64_t fuse_at[3][AXIS_SIM_FUSE];\n  /* The units this CORE shares with other cores (VU4): the group is the\n     party to the share, not each of its contexts. */\n  struct axis_sim_shared *shared[AXIS_SIM_SHARED_UNITS];\n} axis_sim_group;\n\n");
    out.push_str("typedef struct axis_pack_machine {\n  axis_sim sim;\n  \
axis_pack_sim_hooks host;\n  axis_state64_entry state[64];\n  int32_t state_count;\n\
  /* Translation, all of it off until a host asks. */\n  \
const axis_jit_pack *jit;\n  axis_sim_jit options;\n  uint8_t *code;\n  \
size_t code_used;\n  axis_sim_block *blocks;\n  int32_t block_count;\n  \
axis_sim_cold *cold;\n  int32_t cold_count;\n  \
uint64_t translated;\n  uint64_t built;\n  uint64_t scratch[64];\n  \
uint64_t state_words[64];\n  \
/* The width a stencil indexes `state_words` at: the description's word, which\n     the translator publishes per stencil and is one number for a machine. */\n  \
int32_t jit_word_bits;\n  \
/* ⚠️ A FIRST-ORDER timing model, and it says so in its name. In order, single\n     issue, no memory hierarchy, no branch prediction: what it knows is the\n     latency and throughput the DESCRIPTION declares and which registers each\n     instruction reads and writes. That is enough to tell a dependent chain\n     from an independent stream, which is the question an instruction count\n     cannot answer at all -- and not enough to be called a cycle-accurate\n     machine. */\n  \
int32_t counting;\n  uint64_t cycle;\n  uint64_t issue_free;\n  uint64_t ready[AXIS_SIM_REG_SLOTS];\n  \
axis_sim_cache cache;\n  uint64_t tag[AXIS_SIM_CACHE_LINES];\n  uint64_t used[AXIS_SIM_CACHE_LINES];\n  \
uint8_t valid[AXIS_SIM_CACHE_LINES];\n  uint64_t clock;\n  \
/* A BLOCKING cache (docs/blocking_cache_design.md): which lines were stored\n     to, and the cycle it takes its next request. */\n  \
uint8_t dirty[AXIS_SIM_CACHE_LINES];\n  uint64_t dc_free;\n  \
uint64_t hits;\n  uint64_t misses;\n  \
/* ⚠️ What this instruction's accesses cost, charged when it is accounted.\n     A miss is not a stall of the machine: it delays the instruction that\n     asked, and the scoreboard is where that becomes cycles. */\n  \
uint64_t pending_stall;\n  \
/* The core this machine is, or NULL for the first-order model. */\n  \
const axis_sim_core *core;\n  \
/* When each COPY of each unit is free, flattened; `unit_base` says where a\n     unit\'s copies begin. Two adders are two entries, and an instruction takes\n     whichever comes free first. */\n  \
uint64_t unit_free[AXIS_SIM_UNIT_COPIES];\n  \
/* ⚠️ A UNIT WITH LANES (VU1): when each lane of each copy is free. A copy\n     declared `(lanes N)` is N 64-bit lanes, and `unit_free` is not read for\n     it. */\n  \
uint64_t lane_free[AXIS_SIM_UNIT_COPIES][AXIS_SIM_UNIT_LANES_MAX];\n  \
/* The units of this core that are SHARED with other cores (VU4), by unit;\n     NULL for one that is its own. */\n  \
struct axis_sim_shared *shared[AXIS_SIM_SHARED_UNITS];\n  \
int32_t unit_base[AXIS_SIM_UNIT_COPIES];\n  \
/* The cycle currently being filled, and how much of the issue width has\n     gone into it. */\n  \
uint64_t issue_cycle;\n  uint32_t issued_this_cycle;\n  \
/* When the front end can deliver again, and what the instruction just\n     stepped owes it. A taken branch on a machine that does not predict\n     redirects the fetch, and everything behind it waits. */\n  \
uint64_t front_end_ready;\n  uint32_t pending_redirect;\n  \
/* Two-bit saturating counters, and what this machine got wrong. */\n  \
const axis_sim_predictor *pred;\n  void *pred_state;\n  uint64_t mispredicts;\n  \
/* ⚠️ OVERRIDDEN AT DECODE (D3): the quick predictor fetch follows, for a core\n     that declares one, and the cycles after which the core's own overrides\n     it. 0: the one predictor answers at fetch. */\n  \
void *quick_state;\n  uint32_t quick_cycles;\n  \
/* ⚠️ THE SCHEDULER (S1-S3): how many enter the window a cycle (0: the issue\n     width), the wakeup-and-select loop in cycles, each unit's own queue and\n     what a result costs to reach another unit -- and, for every instruction\n     that has issued, when and on what, kept past its retirement: a\n     dependent may still be waiting on a delay after its producer is gone. */\n  \
/* S4: the value predictor -- by pc, the last value a load read and how many\n     times running it has read it -- and what came of predicting. */\n  \
uint32_t vp_entries;\n  uint32_t vp_conf;\n  uint64_t vp_pc[1024];\n  uint64_t vp_val[1024];\n  uint8_t vp_cnt[1024];\n  \
uint64_t value_predictions;\n  uint64_t value_mispredicts;\n  int32_t vp_flush;\n  \
uint32_t disp_width;\n  uint32_t sched;\n  const uint32_t *unit_queue;\n  const uint8_t *bypass;\n  int32_t bypass_n;\n  \
uint64_t done_seq[AXIS_SIM_ROB_MAX];\n  uint64_t done_at[AXIS_SIM_ROB_MAX];\n  uint64_t done_issue[AXIS_SIM_ROB_MAX];\n  int32_t done_unit[AXIS_SIM_ROB_MAX];\n  \
/* Micro-ops the program retired: one an instruction, or as many as the\n     core cracks it into. */\n  \
uint64_t micro_ops;\n  \
/* ⚠️ U2: the micro-op cache -- windows of code already decoded, with the\n     window fetch is in and whether it was held -- the loop buffer's loop and\n     the candidate for one, and the path the last instruction came by: 0\n     decoded, 1 from the cache, 2 from the loop buffer. */\n  \
uint64_t oc_tag[AXIS_SIM_ICACHE_LINES];\n  uint64_t oc_used[AXIS_SIM_ICACHE_LINES];\n  uint8_t oc_valid[AXIS_SIM_ICACHE_LINES];\n  \
uint64_t oc_clock;\n  uint64_t oc_window;\n  int32_t oc_have;\n  int32_t oc_hit;\n  \
uint32_t oc_entries;\n  uint32_t oc_ways;\n  uint32_t oc_bytes;\n  uint32_t oc_width;\n  uint32_t oc_depth;\n  \
uint32_t lb_ops;\n  uint32_t lb_width;\n  uint32_t lb_depth;\n  int32_t lb_on;\n  int32_t lb_next;\n  \
uint64_t lb_branch;\n  uint64_t lb_target;\n  uint64_t lb_cand_branch;\n  uint64_t lb_cand_target;\n  \
uint32_t lb_run;\n  int32_t lb_clean;\n  int32_t fe_path;\n  int32_t oc_reenter;\n  uint32_t tq_entries;\n  int32_t tq_live;\n  int32_t tq_new_page;\n  uint64_t tq_count;\n  uint64_t tq_named;\n  uint64_t tq_read[64];\n  uint64_t op_cache_ops;\n  uint64_t loop_buffer_ops;\n  \
/* The window, for a core that has one. `now` is the cycle the tick loop has\n     reached; the in-order model has no such thing because it never ticks. */\n  \
axis_sim_rob_entry rob[AXIS_SIM_ROB_MAX];\n  \
uint64_t rob_head;\n  uint64_t rob_tail;\n  uint64_t now;\n  \
uint64_t reg_producer[AXIS_SIM_PRODUCERS];\n  \
uint64_t dispatch_cycle;\n  uint32_t dispatched_this_cycle;\n  \
/* S5-S7: results given a register this cycle and how many may be; the queue\n     each unit shares, if any, and each queue's size; and whether the value\n     predictor follows a stride, with each entry's. */\n  \
int32_t select_position;\n  int32_t elim_on;\n  uint32_t elim_waiting;\n  const char *const *fuse;\n  int32_t loads_any;\n  const axis_sim_rob_entry *x_keep;\n  int32_t x_keep_at;\n  uint32_t sb_entries;\n  int32_t sb_any;\n  uint32_t sb_count;\n  int32_t sb_through;\n  uint64_t sb_addr[AXIS_SIM_SB_MAX];\n  uint64_t sb_value[AXIS_SIM_SB_MAX];\n  uint64_t sb_done[AXIS_SIM_SB_MAX];\n  uint32_t sb_width[AXIS_SIM_SB_MAX];\n  uint8_t sb_started[AXIS_SIM_SB_MAX];\n  uint32_t fuse_live;\n  uint64_t fz_seq;\n  uint64_t fz_at;\n  const void *fz_entry;\n  int32_t fz_unit;\n  int32_t fz_absorb;\n  uint32_t fz_latency;\n  uint32_t renamed_this_cycle;\n  uint32_t rename_width;\n  const uint8_t *unit_cluster;\n  const uint32_t *cluster_size;\n  int32_t vp_stride;\n  uint64_t vp_step[1024];\n  \
uint64_t redirect_seq;\n  uint32_t redirect_cycles;\n  uint64_t front_end_stalls;\n  \
/* The accesses the instruction being stepped made, recorded by the memory\n     hooks and handed to its window entry at dispatch. */\n  \
int32_t acc_count;\n  uint64_t acc_lo[AXIS_SIM_OOO_MEM];\n  uint64_t acc_hi[AXIS_SIM_OOO_MEM];\n  \
uint8_t acc_write[AXIS_SIM_OOO_MEM];\n  \
/* Physical registers each rename pool has handed out and not had back. */\n  \
uint32_t rename_used[AXIS_SIM_RENAME_POOLS];\n  \
/* The address of the instruction being accounted, its memory-order\n     violations, and the store-set table: a set per instruction address, 0\n     for none, and the next set to hand out. */\n  \
uint64_t step_pc;\n  uint32_t step_word;\n  uint64_t step_len;\n  uint64_t violations;\n  \
/* The fetch pipeline: the cycle the current group was fetched and how full\n     it is, what the last instruction left the next one (a group break, a\n     bubble, a redirect), when each recent instruction was dispatched -- the\n     buffer's bound -- and the target buffer, tag = pc + 1. */\n  \
uint64_t fetch_cycle;\n  uint32_t fetched_in_group;\n  int32_t fe_restart;\n  \
int32_t fe_group_break;\n  uint32_t fe_bubble;\n  uint64_t fe_redirect_seq;\n  \
int32_t fe_pending_mispredict;\n  int32_t fe_pending_break;\n  uint32_t fe_pending_bubble;\n  \
uint64_t fe_count;\n  uint64_t fe_dispatched[AXIS_SIM_FE_MAX];\n  \
uint64_t btb_tag[AXIS_SIM_BTB_MAX];\n  uint64_t btb_target[AXIS_SIM_BTB_MAX];\n  uint64_t btb_misses;\n  \
/* The return stack: `ras_count` pushed and not popped, the newest at\n     `ras_top` -- circular, so a call deeper than the stack overwrites the\n     oldest, which is what one does. */\n  \
uint64_t ras_stack[64];\n  uint32_t ras_top;\n  uint32_t ras_count;\n  uint64_t target_mispredicts;\n  \
/* The instruction cache: lines, LRU clock, the line fetch is in now, and\n     where the wrong path starts once its mispredict resolves. */\n  \
uint64_t ic_tag[AXIS_SIM_ICACHE_LINES];\n  uint64_t ic_used[AXIS_SIM_ICACHE_LINES];\n  \
uint8_t ic_valid[AXIS_SIM_ICACHE_LINES];\n  \
/* ⚠️ A LINE ON ITS WAY (D4): the cycle each line the cache holds arrives.\n     Zero for one that is simply there. And what fetch is to do while decode\n     looks at the branch just accounted (D2), once that branch's own fetch\n     cycle is known. */\n  \
uint64_t ic_ready[AXIS_SIM_ICACHE_LINES];\n  uint64_t fe_pending_d2_from;\n  uint32_t fe_pending_d2;\n  \
uint64_t ic_clock;\n  uint64_t ic_line;\n  int32_t ic_have_line;\n  \
/* The TLBs: [0] data, [1] fetch, and the one second level behind both. */\n  \
uint64_t tlb_tag[2][AXIS_SIM_TLB_L1];\n  uint64_t tlb_used[2][AXIS_SIM_TLB_L1];\n  uint8_t tlb_valid[2][AXIS_SIM_TLB_L1];\n  \
uint64_t tlb2_tag[AXIS_SIM_TLB_L2];\n  uint64_t tlb2_used[AXIS_SIM_TLB_L2];\n  uint8_t tlb2_valid[AXIS_SIM_TLB_L2];\n  \
uint64_t tlb_clock;\n  uint64_t dtlb_misses;\n  uint64_t itlb_misses;\n  uint64_t page_walks;\n  \
/* ⚠️ THE WALKER (TLB2): how many walks may be in progress and when each\n     walker is free; a page table that is READ -- its levels, what a level\n     costs, where it is laid out, and the tables it has been found to have --\n     a cache of its upper levels; a region of large pages; and the walk the\n     access being made now has asked for. */\n  \
uint32_t tw_walkers;\n  uint32_t tw_levels;\n  uint32_t tw_cycles;\n  uint32_t tw_pwc;\n  \
uint64_t tw_table;\n  uint64_t tw_huge_bytes;\n  uint64_t tw_huge_from;\n  uint64_t tw_huge_to;\n  \
uint64_t walker_free[8];\n  uint64_t tw_node[1024];\n  uint32_t tw_node_at[1024];\n  uint32_t tw_nodes;\n  \
uint64_t pwc_key[64];\n  uint64_t pwc_used[64];\n  uint8_t pwc_valid[64];\n  uint64_t pending_walk;\n  \
uint64_t it_page;\n  int32_t it_have;\n  uint8_t x_it_pending;\n  int32_t tlb_skip;\n  \
uint64_t icache_misses;\n  uint64_t wrong_path_lines;\n  \
int32_t wp_pending;\n  uint64_t wp_pending_start;\n  int32_t wp_armed;\n  uint64_t wp_start;\n  uint64_t fe_redirect_fetch;\n  \
/* ⚠️ THE SHADOW (O12): whether the functional side is running a wrong path\n     now, whether it trapped, the bytes it stored (never the host's), and\n     the trace it left -- each instruction's pc and memory accesses. */\n  \
int32_t shadow;\n  int32_t shadow_stopped;\n  uint32_t shadow_writes;\n  \
uint64_t shadow_addr[AXIS_SIM_SHADOW_BYTES];\n  uint8_t shadow_byte[AXIS_SIM_SHADOW_BYTES];\n  \
uint32_t wpx_len;\n  int32_t wpx_pending;\n  int32_t wpx_armed;\n  uint64_t wpx_pc[AXIS_SIM_WP_MAX];\n  \
int32_t wpx_acc[AXIS_SIM_WP_MAX];\n  uint64_t wpx_lo[AXIS_SIM_WP_MAX][AXIS_SIM_OOO_MEM];\n  \
uint8_t wpx_write[AXIS_SIM_WP_MAX][AXIS_SIM_OOO_MEM];\n  uint64_t wrong_path_instructions;\n  \
/* W1-W2: each wrong-path instruction's word and where its accesses end, so\n     it can enter the window; and how long after the branch's own fetch the\n     front end started down the wrong path -- decode's time, when the target\n     buffer did not hold the target. */\n  \
uint32_t wpx_word[AXIS_SIM_WP_MAX];\n  uint64_t wpx_hi[AXIS_SIM_WP_MAX][AXIS_SIM_OOO_MEM];\n  uint32_t fe_pending_delay;\n  \
/* W3, W5: a wrong-path branch the front end got wrong is followed in the\n     trace by its DETOUR -- the side it was predicted to take and did not --\n     and `wpx_resume` is where the path it took picks up again, 0 for an\n     entry that sent fetch nowhere wrong. A detour's own branches have\n     detours inside it. `wpx_bubble`: the cycles decode took to find where\n     fetch goes next, before this entry could be fetched. */\n  \
uint32_t wpx_resume[AXIS_SIM_WP_MAX];\n  uint32_t wpx_bubble[AXIS_SIM_WP_MAX];\n  \
/* ⚠️ THE EXECUTION-DRIVEN ENGINE (E1): where fetch is on the predicted path\n     and when it may go on, what it fetched, the instruction executing now,\n     the commit's own stores for the check, and what the engine got wrong. */\n  \
int32_t x_started;\n  uint64_t x_fetch_pc;\n  uint64_t x_fetch_resume;\n  int32_t x_fetch_stopped;\n  \
axis_x_fetched x_buf[AXIS_SIM_XBUF];\n  uint32_t x_buf_head;\n  uint32_t x_buf_count;\n  \
axis_sim_rob_entry *x_cur;\n  uint64_t x_stall;\n  int32_t x_committing;\n  \
/* U1: which memory access the instruction executing now is on, counted as\n     it makes them, and where the last one ended. */\n  \
uint32_t x_ord;\n  uint64_t x_ord_end;\n  int32_t x_ord_any;\n  \
int32_t x_cw_count;\n  uint64_t x_cw_addr[AXIS_SIM_OOO_MEM];\n  uint64_t x_cw_value[AXIS_SIM_OOO_MEM];\n  uint32_t x_cw_width[AXIS_SIM_OOO_MEM];\n  \
uint64_t x_committed;\n  int32_t x_halted;\n  int32_t x_flush;\n  uint64_t x_replays;\n  uint64_t x_squashed;\n  \
int32_t x_retired;\n  int32_t x_ic_pending;\n  int32_t x_trap_hit;\n  uint64_t x_traps;\n  struct axis_pack_machine **x_peers;\n  int32_t x_peer_count;\n  uint64_t x_snoops;\n  uint64_t x_idle;\n  uint64_t x_limit;\n  axis_sim_group *grp;\n  uint32_t x_warp;\n  uint64_t x_passed;\n  uint64_t x_rides[3];\n  uint64_t x_monitors_cleared;\n  int32_t x_event;\n  int32_t x_sleeping;\n  uint64_t x_sleeps;\n  \
/* What the engine knows about each decode entry, built once per core rather\n     than re-derived by string comparison for every instruction it sees; and\n     the window's occupancy, kept rather than recounted. */\n  \
struct axis_x_meta *x_meta;\n  void *x_lanes;\n  axis_sim_memo *memo;\n  uint32_t x_waiting;\n  uint32_t x_loads;\n  uint32_t x_stores;\n  \
/* ⚠️ THE VIEW an executing instruction sees (execution-driven): the committed\n     registers, kept beside them -- patched with the window's writes for one\n     execute and put back, slot by slot, rather than copied whole each time.\n     `x_list` names the slots patched or declared written during an execute,\n     `x_mark` which (1 patched, 2 declared), `x_patch` what each was patched\n     to. Not valid until the first execute, or after anything else has\n     written the registers. */\n  \
uint64_t x_view[AXIS_SIM_REG_SLOTS];\n  uint64_t x_patch[AXIS_SIM_REG_SLOTS];\n  uint32_t x_list[AXIS_SIM_REG_SLOTS];\n  uint8_t x_mark[AXIS_SIM_REG_SLOTS];\n  int32_t x_view_ok;\n  \
uint32_t ssit[AXIS_SIM_SSIT_MAX];\n  uint32_t next_set;\n  \
/* A timing model that is not this library, and its state. */\n  \
const axis_uarch_pack *model;\n  const axis_uarch_pack *model_owner;\n  void *model_state;\n  \
/* The described memory system this machine's core is a port of, when it\n     is one: every access goes through it instead of the single cache. */\n  \
axis_ms *ms;\n  int32_t ms_port;\n  int32_t ms_system;\n} axis_pack_machine;\n\n");
    // Each hook is the host's, reached through the machine rather than
    // directly: the simulator's own hook signatures are the generated ones,
    // and the contract's are the corpus-independent ones.
    // ⚠️ One lookup per ACCESS, and a miss charges the instruction that asked
    // rather than stalling the machine. Set-associative with LRU; a line is
    // resident or it is not, and there is no prefetch to make it arrive early.
    out.push_str(TLB_C);
    out.push_str("static int axis_sim_core_blocking(const axis_sim_core *core);\n");
    out.push_str("static void axis_sim_touch(axis_pack_machine *m, uint64_t addr, int is_write) {\n");
    out.push_str("  /* ⚠️ TRANSLATION COMES FIRST: the access cannot start until the page is\n     known, so what the TLB costs is ahead of whatever the cache then does. */\n");
    out.push_str("  uint64_t walk = (m->core && m->core->tlb.data_entries && !m->tlb_skip) ? axis_tlb_lookup(m, 0, addr) : 0u;\n");
    out.push_str("  m->pending_stall += walk;\n");
    out.push_str("  /* ⚠️ A described memory system replaces the single cache, and charges\n     the instruction what the access costs beyond a hit in its first level:\n     the declared latency already covers that much. */\n");
    out.push_str("  if (m->ms && m->core && m->core->memory_timed) {\n");
    out.push_str("    /* U3: the system says when; what is past a first-level hit at this\n       cycle is the stall. The stride key is the instruction's pc. */\n");
    out.push_str("    uint64_t key = m->x_cur ? m->x_cur->pc : 0u;\n");
    out.push_str("    m->pending_stall += axis_ms_stall_at(m->ms, m->ms_port, addr, is_write, m->now + walk, key);\n");
    out.push_str("    return;\n  }\n");
    out.push_str("  if (m->ms) { m->pending_stall += axis_ms_stall(m->ms, m->ms_port, addr, is_write); return; }\n");
    out.push_str("  (void)is_write;\n");
    out.push_str("  if (!m->cache.lines) { return; }\n");
    out.push_str(r#"  /* ⚠️ A BLOCKING CACHE keeps time (docs/blocking_cache_design.md). It takes
     one request a cycle and none while a miss is on its way, so a request
     is TAKEN at the first cycle the cache is free, and what it waits until
     then is the instruction's as a miss is. Issue and commit hold a load
     and a store back until the cache is free, so for them this wait is
     nothing; it is here for the access they do not gate -- an instruction's
     second, or one after a page walk. */
  int blocking = axis_sim_core_blocking(m->core);
  uint64_t taken = m->now + walk;
  if (blocking) {
    if (m->dc_free > taken) { m->pending_stall += m->dc_free - taken; taken = m->dc_free; }
    m->dc_free = taken + 1u;
  }
"#);
    out.push_str("  uint32_t line_bytes = m->cache.line_bytes ? m->cache.line_bytes : 64u;\n");
    out.push_str("  uint32_t ways = m->cache.ways ? m->cache.ways : 1u;\n");
    out.push_str("  uint32_t lines = m->cache.lines;\n");
    out.push_str("  if (lines > AXIS_SIM_CACHE_LINES) { lines = AXIS_SIM_CACHE_LINES; }\n");
    out.push_str("  if (ways > lines) { ways = lines; }\n");
    out.push_str("  uint32_t sets = lines / ways;\n");
    out.push_str("  if (!sets) { return; }\n");
    out.push_str("  uint64_t line = addr / line_bytes;\n");
    out.push_str("  uint32_t set = (uint32_t)(line % sets);\n");
    out.push_str("  uint32_t base = set * ways;\n");
    out.push_str("  m->clock++;\n");
    out.push_str("  for (uint32_t w = 0; w < ways; ++w) {\n");
    out.push_str("    if (m->valid[base + w] && m->tag[base + w] == line) {\n");
    out.push_str("      m->used[base + w] = m->clock;\n      m->hits++;\n      if (blocking && is_write) { m->dirty[base + w] = 1; }\n      return;\n    }\n  }\n");
    out.push_str("  /* A miss takes the way that has gone longest unused, which for a\n     direct-mapped cache is the only one. */\n");
    out.push_str("  uint32_t victim = base;\n");
    out.push_str("  for (uint32_t w = 0; w < ways; ++w) {\n");
    out.push_str("    if (!m->valid[base + w]) { victim = base + w; break; }\n");
    out.push_str("    if (m->used[base + w] < m->used[victim]) { victim = base + w; }\n  }\n");
    out.push_str(r#"  /* ⚠️ No write buffer: a line that was stored to is written behind before
     the line that replaces it is asked for, and the miss waits for both.
     Nothing is taken until the cycle after it is answered. */
  uint64_t cost = m->cache.miss_cycles;
  if (blocking) {
    if (m->valid[victim] && m->dirty[victim]) { cost += m->cache.miss_cycles; }
    m->dirty[victim] = (uint8_t)(is_write != 0);
    m->dc_free = taken + cost + 1u;
  }
"#);
    out.push_str("  m->valid[victim] = 1;\n  m->tag[victim] = line;\n  m->used[victim] = m->clock;\n");
    out.push_str("  m->misses++;\n  m->pending_stall += cost;\n}\n\n");
    // ⚠️ What an access TOUCHED, not what it cost: the window orders loads
    // against stores by the bytes they name, and the functional step is the
    // only thing that knows them. A host's own `touch_memory` is not an
    // instruction's access and is not recorded.
    out.push_str("static void axis_sim_note_access(axis_pack_machine *m, uint64_t addr, uint32_t width, int is_write) {\n");
    out.push_str("  uint32_t bytes = width >= 8u ? width / 8u : 1u;\n");
    out.push_str("  /* ⚠️ A VECTOR ACCESS IS ONE ACCESS (VM1). An instruction that loads\n     sixteen lanes makes sixteen calls here, one after another's last byte;\n     what the window orders loads against stores by is the bytes, so the\n     calls are one range. A gather's lanes are not adjacent and stay apart. */\n");
    out.push_str("  if (m->acc_count > 0 && m->acc_count <= (int32_t)AXIS_SIM_OOO_MEM) {\n");
    out.push_str("    int32_t p = m->acc_count - 1;\n");
    out.push_str("    if (m->acc_write[p] == (uint8_t)(is_write != 0) && m->acc_hi[p] == addr) { m->acc_hi[p] = addr + bytes; return; }\n  }\n");
    out.push_str("  if (m->acc_count >= (int32_t)AXIS_SIM_OOO_MEM) { return; }\n");
    out.push_str("  m->acc_lo[m->acc_count] = addr;\n  m->acc_hi[m->acc_count] = addr + bytes;\n");
    out.push_str("  m->acc_write[m->acc_count] = (uint8_t)(is_write != 0);\n  m->acc_count++;\n}\n\n");
    out.push_str("/* ⚠️ ONE STORE of an execution-driven instruction, recorded -- by the\n   pipeline when it executes and by the golden model when it commits, through\n   this one function, so the two lists are comparable entry for entry. A\n   store that continues the one before it is laid on its end, up to eight\n   bytes an entry: a vector store's lanes are a few words, not a list as long\n   as the vector. Past the list's end the count still rises, which is how an\n   overflow is told. */\n");
    out.push_str("static void axis_x_note_store(uint64_t *at, uint64_t *value, uint32_t *bits, int32_t *count,\n                              uint64_t addr, uint64_t v, uint32_t width) {\n");
    out.push_str("  uint32_t bytes = width >= 8u ? width / 8u : 1u;\n");
    out.push_str("  if (bytes < 8u) { v &= (1ull << (8u * bytes)) - 1ull; }\n");
    out.push_str("  if (*count > 0 && *count <= (int32_t)AXIS_SIM_OOO_MEM) {\n");
    out.push_str("    int32_t p = *count - 1;\n    uint32_t held = bits[p] / 8u;\n");
    out.push_str("    if (at[p] + held == addr && held + bytes <= 8u) {\n");
    out.push_str("      value[p] |= v << (8u * held);\n      bits[p] += 8u * bytes;\n      return;\n    }\n  }\n");
    out.push_str("  if (*count < (int32_t)AXIS_SIM_OOO_MEM) {\n");
    out.push_str("    at[*count] = addr;\n    value[*count] = v;\n    bits[*count] = 8u * bytes;\n  }\n");
    out.push_str("  (*count)++;\n}\n\n");
    out.push_str(STORE_BUFFER_C);
    out.push_str("static uint64_t axis_sim_read(void *ctx, uint64_t addr, uint32_t width) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)ctx;\n");
    out.push_str("  /* ⚠️ The golden model COMMITTING for an execution-driven core: the\n     pipeline already charged this access when the instruction executed, so\n     the cache is not touched twice. */\n");
    out.push_str("  if (m->x_committing) {\n    /* ⚠️ A load another core's store overtook, and that kept what it read\n       (WM2): the golden model reads what the load read. */\n    if (m->x_keep) {\n      int32_t k = m->x_keep_at++;\n      if (k < m->x_keep->x_rcount && k < AXIS_SIM_KEEP && m->x_keep->x_raddr[k] == addr && m->x_keep->x_rwidth[k] == width) { return m->x_keep->x_rval[k]; }\n    }\n    uint64_t held = m->host.read ? m->host.read(m->host.ctx, addr, width) : 0u;\n    return m->sb_count ? axis_sb_overlay(m, addr, width, held) : held;\n  }\n");
    out.push_str("  /* ⚠️ On the WRONG PATH: the host's memory, overlaid with what the\n     wrong path itself stored -- and no cache touched yet, because how much\n     of this path the machine reaches is only known at resolution. */\n");
    out.push_str("  if (m->shadow) {\n");
    out.push_str("    axis_sim_note_access(m, addr, width, 0);\n");
    out.push_str("    uint64_t value = m->host.read ? m->host.read(m->host.ctx, addr, width) : 0u;\n");
    out.push_str("    uint32_t bytes = width >= 8u ? width / 8u : 1u;\n");
    out.push_str("    for (uint32_t b = 0; b < bytes && b < 8u; ++b) {\n");
    out.push_str("      for (uint32_t w = m->shadow_writes; w > 0u; --w) {\n");
    out.push_str("        if (m->shadow_addr[w - 1u] == addr + b) {\n");
    out.push_str("          value = (value & ~(0xFFull << (8u * b))) | ((uint64_t)m->shadow_byte[w - 1u] << (8u * b));\n");
    out.push_str("          break;\n        }\n      }\n    }\n");
    out.push_str("    return value;\n  }\n");
    out.push_str("  axis_sim_touch(m, addr, 0);\n");
    out.push_str("  axis_sim_note_access(m, addr, width, 0);\n");
    out.push_str("  return m->host.read ? m->host.read(m->host.ctx, addr, width) : 0u;\n}\n\n");
    out.push_str("static void axis_x_snoop(axis_pack_machine *m, uint64_t addr, uint32_t width);\n");
    out.push_str("static const char *const *axis_sim_core_exclusive(const axis_sim_core *core);\n");
    out.push_str("static const char *const *axis_sim_core_events(const axis_sim_core *core);\n");
    out.push_str("static uint32_t axis_sim_latency_on(const axis_sim_core *core, const axis_lift_entry *entry);\n");
    out.push_str("static const char *axis_sim_unit_on(const axis_sim_core *core, const axis_lift_entry *entry);\n");
    out.push_str("static const char *axis_sim_derived_unit(const axis_lift_entry *entry);\n");
    out.push_str("static void axis_sim_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)ctx;\n");
    out.push_str("  /* Committing: the store the check compares the pipeline's against. */\n");
    out.push_str("  if (m->x_committing) {\n");
    out.push_str("    axis_x_note_store(m->x_cw_addr, m->x_cw_value, m->x_cw_width, &m->x_cw_count, addr, value, width);\n");
    out.push_str("    /* ⚠️ Retired, and not yet written (WM1): it waits in this core's buffer. */\n    if (m->sb_entries && !m->sb_through) { axis_sb_push(m, addr, value, width); return; }\n");
    out.push_str("    if (m->host.write) { m->host.write(m->host.ctx, addr, value, width); }\n");
    out.push_str("    /* Now it is everyone's: a core running beside this one that has\n       already read these bytes, and not yet committed, read them stale. */\n");
    out.push_str("    if (m->x_peer_count) { axis_x_snoop(m, addr, width); }\n    return;\n  }\n");
    out.push_str("  /* ⚠️ A wrong-path store NEVER reaches the host: it is buffered for the\n     wrong path's own later loads, and discarded with the rest of it. */\n");
    out.push_str("  if (m->shadow) {\n");
    out.push_str("    axis_sim_note_access(m, addr, width, 1);\n");
    out.push_str("    uint32_t bytes = width >= 8u ? width / 8u : 1u;\n");
    out.push_str("    for (uint32_t b = 0; b < bytes && b < 8u && m->shadow_writes < AXIS_SIM_SHADOW_BYTES; ++b) {\n");
    out.push_str("      m->shadow_addr[m->shadow_writes] = addr + b;\n");
    out.push_str("      m->shadow_byte[m->shadow_writes++] = (uint8_t)(value >> (8u * b));\n    }\n");
    out.push_str("    return;\n  }\n");
    out.push_str("  axis_sim_touch(m, addr, 1);\n");
    out.push_str("  axis_sim_note_access(m, addr, width, 1);\n");
    out.push_str("  if (m->host.write) { m->host.write(m->host.ctx, addr, value, width); }\n}\n\n");
    out.push_str("static uint32_t axis_sim_fetch(void *ctx, uint64_t pc, int *ok) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)ctx;\n");
    out.push_str("  int32_t answered = 1;\n");
    out.push_str("  uint32_t word = m->host.fetch ? m->host.fetch(m->host.ctx, pc, &answered) : 0u;\n");
    out.push_str("  if (ok) { *ok = (int)answered; }\n  return word;\n}\n\n");
    out.push_str("static uint64_t axis_sim_trap(void *ctx, const char *cause, uint64_t pc, int *stop) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)ctx;\n");
    out.push_str("  /* ⚠️ A trap on the wrong path is not a trap: nothing on that path\n     happened. The shadow stops there and the host never hears of it. */\n");
    out.push_str("  if (m->shadow) { m->shadow_stopped = 1; if (stop) { *stop = 1; } return pc; }\n");
    out.push_str("  /* The golden model committing a trap for an execution-driven core: an\n     exception, not a mistake of the pipeline's. */\n");
    out.push_str("  if (m->x_committing) { m->x_trap_hit = 1; }\n");
    out.push_str("  int32_t halt = 1;\n");
    out.push_str("  uint64_t where = m->host.trap ? m->host.trap(m->host.ctx, cause, pc, &halt) : pc;\n");
    out.push_str("  if (stop) { *stop = (int)halt; }\n  return where;\n}\n\n");
    out.push_str("/* The event, copied into the contract's shape. Field for field rather\n   \
than by cast: the two structs mean the same thing and are not the same\n   \
type, and a pack whose header changed shape under a consumer would be\n   \
the collision this whole arrangement exists to avoid. */\n");
    out.push_str("static void axis_sim_retire(void *ctx, const axis_sim_event *event) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)ctx;\n");
    out.push_str("  if (m->shadow) { return; }\n");
    out.push_str("  if (!m->host.retire) { return; }\n");
    out.push_str("  axis_pack_sim_event out;\n  memset(&out, 0, sizeof out);\n");
    out.push_str("  out.pc = event->pc; out.word = event->word; out.mnemonic = event->mnemonic;\n");
    out.push_str("  out.ok = event->ok; out.wrote = event->wrote; out.dest = event->dest;\n");
    out.push_str("  out.write_slot = event->write_slot; out.result = event->result;\n");
    out.push_str("  out.result_limbs = event->result_limbs;\n");
    out.push_str("  for (uint32_t i = 0; i < event->result_limbs && i < AXIS_PACK_MAX_LIMBS; ++i) {\n");
    out.push_str("    out.result_limb[i] = event->result_limb[i];\n  }\n");
    out.push_str("  out.trap_cause = event->trap_cause; out.next_pc = event->next_pc;\n");
    out.push_str("  out.reads_total = event->read_count; out.writes_total = event->write_count;\n");
    out.push_str("  out.accesses_total = event->access_count;\n");
    out.push_str("  out.read_count = event->read_count < (int)AXIS_PACK_MAX_TOUCH ? event->read_count : (int)AXIS_PACK_MAX_TOUCH;\n");
    out.push_str("  out.write_count = event->write_count < (int)AXIS_PACK_MAX_TOUCH ? event->write_count : (int)AXIS_PACK_MAX_TOUCH;\n");
    out.push_str("  for (int i = 0; i < event->read_count && i < (int)AXIS_PACK_MAX_TOUCH; ++i) {\n");
    out.push_str("    out.reads[i] = event->reads[i];\n  }\n");
    out.push_str("  for (int i = 0; i < event->write_count && i < (int)AXIS_PACK_MAX_TOUCH; ++i) {\n");
    out.push_str("    out.writes[i] = event->writes[i];\n  }\n");
    out.push_str("  out.access_count = event->access_count < (int)AXIS_PACK_MAX_ACCESS ? event->access_count : (int)AXIS_PACK_MAX_ACCESS;\n");
    out.push_str("  for (int i = 0; i < event->access_count && i < (int)AXIS_PACK_MAX_ACCESS; ++i) {\n");
    out.push_str("    out.accesses[i].addr = event->accesses[i].addr;\n");
    out.push_str("    out.accesses[i].value = event->accesses[i].value;\n");
    out.push_str("    out.accesses[i].width = event->accesses[i].width;\n");
    out.push_str("    out.accesses[i].is_write = event->accesses[i].is_write;\n");
    out.push_str("    out.accesses[i].limbs = event->accesses[i].limbs;\n");
    out.push_str("    for (uint32_t k = 0; k < event->accesses[i].limbs && k < AXIS_PACK_MAX_LIMBS; ++k) {\n");
    out.push_str("      out.accesses[i].limb[k] = event->accesses[i].limb[k];\n    }\n  }\n");
    out.push_str("  m->host.retire(m->host.ctx, &out);\n}\n\n");
    out.push_str("static int32_t axis_quick_predict(axis_pack_machine *m, uint64_t pc);\nstatic void axis_quick_train(axis_pack_machine *m, uint64_t pc, int32_t taken);\nstatic void axis_quick_drop(axis_pack_machine *m);\n");
    out.push_str("static void *axis_sim_create(const axis_pack_sim_hooks *hooks) {\n");
    out.push_str("  if (!hooks) { return NULL; }\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)calloc(1, sizeof *m);\n");
    out.push_str("  if (!m) { return NULL; }\n  m->host = *hooks;\n");
    out.push_str("  axis_sim_hooks wired = { axis_sim_read, axis_sim_write, axis_sim_fetch,\n                           axis_sim_trap, axis_sim_retire, m };\n");
    out.push_str("  axis_sim_init(&m->sim, &wired, m->state, 0);\n");
    out.push_str("  /* The decode memo: without it every step scans the lift table four\n     times. A machine that could not have one runs without. */\n");
    out.push_str("  m->memo = (axis_sim_memo *)calloc(1, sizeof *m->memo);\n  m->sim.memo = m->memo;\n  return m;\n}\n\n");
    out.push_str("/* ⚠️ A model's state belongs to the MODEL. This library allocated none of\n   it and frees none of it -- it only says when it is finished, and lets the\n   implementation that made the state decide what that means. */\n");
    out.push_str("static void axis_sim_free(void *machine) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n");
    out.push_str("  if (m && m->model_state && m->model_owner) { m->model_owner->destroy(m->model_state); }\n");
    out.push_str("  if (m && m->pred && m->pred_state) { m->pred->destroy(m->pred_state); }\n  if (m) { axis_quick_drop(m); }\n");
    out.push_str("  if (m && m->x_meta) { free(m->x_meta); }\n");
    out.push_str("  if (m && m->x_lanes) { free(m->x_lanes); }\n");
    out.push_str("  for (int32_t u = 0; m && u < AXIS_SIM_SHARED_UNITS; ++u) {\n    axis_sim_shared *sh = m->shared[u];\n    if (!sh) { continue; }\n");
    out.push_str("    for (int32_t i = 0; i < sh->count; ++i) { if (sh->who[i] == (const void *)m) { sh->who[i] = 0; } }\n");
    out.push_str("    if (sh->owner == (const void *)m) { sh->owner = 0; }\n    if (--sh->refs <= 0) { free(sh); }\n  }\n");
    out.push_str("  if (m && m->memo) { free(m->memo); }\n");
    out.push_str("  if (m && m->ms) { axis_ms_free(m->ms); }\n");
    out.push_str("  if (m && m->grp) {\n    for (int32_t i = 0; i < m->grp->count; ++i) { if (m->grp->member[i] == m) { m->grp->member[i] = 0; } }\n    if (--m->grp->refs <= 0) {\n      for (int32_t u = 0; u < AXIS_SIM_SHARED_UNITS; ++u) {\n        axis_sim_shared *sh = m->grp->shared[u];\n        if (!sh) { continue; }\n        for (int32_t i = 0; i < sh->count; ++i) { if (sh->who[i] == (const void *)m->grp) { sh->who[i] = 0; } }\n        if (sh->owner == (const void *)m->grp) { sh->owner = 0; }\n        if (--sh->refs <= 0) { free(sh); }\n      }\n      free(m->grp);\n    }\n  }\n");
    out.push_str("  free(machine);\n}\n\n");
    out.push_str("static void axis_sim_reset_machine(void *machine, uint64_t pc, const char *isa,\n                                   const axis_pack_state_entry *state, int32_t count) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n  if (!m) { return; }\n");
    out.push_str("  axis_pack_sim_hooks host = m->host;\n");
    out.push_str("  m->x_started = 0;\n");
    out.push_str("  /* What each instruction does to state is resolved against the state this\n     reset names, so it is worked out again for the next. */\n  if (m->x_meta) { free(m->x_meta); m->x_meta = 0; }\n");
    out.push_str("  memset(&m->sim, 0, sizeof m->sim);\n");
    out.push_str("  m->state_count = count < 64 ? count : 64;\n");
    out.push_str("  for (int32_t i = 0; i < m->state_count; ++i) {\n");
    out.push_str("    m->state[i].name = state ? state[i].name : NULL;\n");
    out.push_str("    m->state[i].value = state ? state[i].value : 0u;\n");
    out.push_str("    m->state[i].width = state ? state[i].width : 0u;\n  }\n");
    out.push_str("  axis_sim_hooks wired = { axis_sim_read, axis_sim_write, axis_sim_fetch,\n                           axis_sim_trap, axis_sim_retire, m };\n");
    out.push_str("  axis_sim_init(&m->sim, &wired, m->state, (size_t)m->state_count);\n");
    out.push_str("  m->host = host;\n  m->sim.pc = pc;\n  m->sim.isa = isa;\n");
    out.push_str("  /* The isa is the caller's pointer, and what it says may have changed;\n     so may the words. The memo starts again with the run. */\n");
    out.push_str("  axis_sim_memo_clear(m->memo);\n  m->sim.memo = m->memo;\n");
    out.push_str("  /* ⚠️ A reset forgets every translated block. The bytes at a pc are the\n     host's to change between runs, and a cache that outlived them would be\n     running the program that used to be there. */\n");
    out.push_str("  m->block_count = 0;\n  m->cold_count = 0;\n  m->code_used = 0;\n  \
m->translated = 0;\n  m->built = 0;\n}\n\n");
    // The mixed loop. Everything below is the composition the gates have been
    // demonstrating in `jit_stencil.py`'s mixed mode: a run of translatable
    // instructions becomes one block, and the first instruction that is not --
    // a branch, a trap, anything with no stencil -- is interpreted.
    out.push_str("#if defined(__APPLE__) || defined(__linux__)\n");
    out.push_str("#include <sys/mman.h>\n");
    out.push_str("#define AXIS_SIM_CAN_JIT 1\n#else\n#define AXIS_SIM_CAN_JIT 0\n#endif\n\n");
    out.push_str("/* Whether this instruction can go in a translated block, and what it\n   needs if it can.\n\n   ⚠️ A stencil that reads architectural state used to be refused here: the\n   state a stencil expects is a flat array of the machine's word and this\n   machine keeps named entries. It is accepted now, and `axis_sim_state_in`\n   and `axis_sim_state_out` are what makes that true -- the flat array is\n   filled from the named entries before a block runs and read back after.\n\n   The refusal cost more than it looked: AArch64 spells the stack pointer as\n   index 31 of a register class that aliases the `sp` slot, so every\n   stack-relative add, load and store reads state, which is three fifths of\n   the architecture. */\n");
    // ⚠️ Memory AND state together is refused, and only that pair. A stencil
    // that reads state computes with it; one that also touches memory can
    // compute an ADDRESS from it, and the state a host seeds is not bounded
    // the way its registers are -- AArch64's `sp` is a state slot, so
    // `ldr x0, [sp, #8]` reaches wherever `sp` points. Translated code applies
    // no bound, by contract, and a host that promised a buffer cannot answer
    // for that. The interpreter runs these, which is slower and always safe.
    // ⚠️ The general answer is a memory manager, not this rule.
    // ⚠️ Gone: the retreat this replaced. A stencil that touched memory AND
    // read state was refused because it could compute an address from state,
    // and a host bounds its registers but not its state slots. Translated code
    // masks every address now, so there is nothing left to be unable to answer
    // for -- and the retreat had cost every stack-relative load and store in
    // the architecture where `sp` IS a state slot.
    out.push_str("static int axis_sim_unbounded(const axis_pack_machine *m, int32_t stencil) {\n");
    out.push_str("  (void)m; (void)stencil; return 0;\n}\n");
    out.push_str("static int axis_sim_translatable(axis_pack_machine *m, int32_t stencil,\n                                 int effectful) {\n");
    out.push_str("  if (stencil < 0) { return 0; }\n");    out.push_str("  if (axis_sim_unbounded(m, stencil)) { return 0; }\n");
    out.push_str("  /* ⚠️ A power of two, because the bound is a mask. A host whose\n     window is 3000 bytes has not asked for something this cannot do -- it\n     has asked for something a single `and` cannot express, and the answer\n     is to interpret rather than to round its window up and write outside\n     it. */\n");
    out.push_str("  if (effectful && (!m->options.memory_size\n                    || (m->options.memory_size & (m->options.memory_size - 1u)))) {\n    return 0;\n  }\n");

    out.push_str("  return 1;\n}\n\n");
    out.push_str("/* Build one block at `pc`, or return NULL when the instruction there is\n   not one the translator takes. */\n");
    out.push_str("static axis_sim_block *axis_sim_build(axis_pack_machine *m, uint64_t pc) {\n");
    out.push_str("  axis_jit_op ops[AXIS_SIM_BLOCK_MAX];\n");
    out.push_str("  static uint64_t values[AXIS_SIM_BLOCK_MAX][8];\n");
    out.push_str("  int32_t count = 0, branchy = 0;\n");
    out.push_str("  for (; count < AXIS_SIM_BLOCK_MAX; ++count) {\n");
    out.push_str("    int answered = 1;\n");
    out.push_str("    uint64_t at = pc + (uint64_t)(4 * count);\n");
    out.push_str("    uint32_t word = m->host.fetch ? m->host.fetch(m->host.ctx, at, &answered) : 0u;\n");
    out.push_str("    if (!answered) { break; }\n");
    out.push_str("    axis_lifted lifted;\n");
    out.push_str("    /* ⚠️ In the machine's OWN isa. A description can hold several whose\n       encodings overlap, and decoding without one hands back whichever\n       matched first -- which translated nothing at all on AArch64, because\n       the instruction it found was not the one the interpreter ran. */\n");
    out.push_str("    if (!axis_sim_lift(&m->sim, word, &lifted) || !lifted.entry) { break; }\n");
    out.push_str("    int32_t stencil = m->jit->stencil_for(lifted.entry->mnemonic);\n");
    out.push_str("    if (!axis_sim_translatable(m, stencil, m->jit->effectful(stencil))) { break; }\n");
    out.push_str("    int32_t wanted = m->jit->values(stencil);\n");
    out.push_str("    if (wanted > 8) { break; }\n");
    out.push_str("    /* Each hole by NAME, as the library publishes them: the operand the\n       instruction decoded, not the position AXIS happened to emit. */\n");
    out.push_str("    int32_t filled = 0;\n    int ok = 1;\n");
    out.push_str("    for (int32_t h = 0; h < m->jit->holes(stencil) && ok; ++h) {\n");
    out.push_str("      const char *want = m->jit->hole(stencil, h);\n");
    // ⚠️ Every machine part, and the list is the library's to fill. A part
    // missing here is not a hole left unpatched -- it is a hole this tries to
    // bind to an OPERAND, fails to find, and gives up the whole block over. The
    // memory window arrived and every load and store silently stopped ending up
    // in a block: 23 of 24 instructions had stencils and 20% of the run was
    // translated.
    out.push_str("      if (!want || !strcmp(want, \"regs\") || !strcmp(want, \"mem\")\n          || !strcmp(want, \"out\") || !strcmp(want, \"state\")\n          || !strcmp(want, \"pc\") || !strcmp(want, \"mask\")) { continue; }\n");
    out.push_str("      ok = 0;\n");
    out.push_str("      for (int32_t o = 0; o < lifted.entry->operand_count; ++o) {\n");
    out.push_str("        const axis_lift_operand *operand = &lifted.entry->operands[o];\n");
    out.push_str("        if (strcmp(operand->name, want) || !lifted.operand_valid[o]) { continue; }\n");
    out.push_str("        values[count][filled++] = (uint64_t)lifted.operands[o];\n");
    out.push_str("        ok = 1; break;\n      }\n    }\n");
    out.push_str("    if (!ok || filled != wanted) { break; }\n");
    out.push_str("    ops[count].stencil = stencil;\n    ops[count].values = values[count];\n");
    out.push_str("    ops[count].value_count = filled;\n    ops[count].pc = at;\n");
    // ⚠️ A branch ENDS the block, and is in it. A block is straight-line code,
    // so everything after a taken branch would run regardless -- which is why
    // these used to stop the block one instruction short and leave the branch
    // to the interpreter. Taking it means one interpreted step per iteration
    // becomes none, and the block's own last instruction says where to go.
    out.push_str("    if (lifted.entry->ends_block) { ++count; branchy = 1; break; }\n  }\n");
    out.push_str("  /* ⚠️ A block that is ONLY a branch is still not worth building: the\n     translation costs more than the one interpretation it saves, and the\n     two-instruction floor below would have refused it anyway. */\n");
    out.push_str("  /* One instruction is not worth a block: it would cost a translation to\n     save an interpretation. */\n");
    out.push_str("  if (count < 2) { return NULL; }\n");
    out.push_str("  if (m->block_count >= m->options.blocks) { return NULL; }\n");
    out.push_str("  size_t room = AXIS_SIM_CODE_BYTES - m->code_used;\n");
    out.push_str("  size_t used = 0;\n");
    out.push_str("  axis_jit_machine parts = { (uint64_t)(uintptr_t)m->sim.regs,\n                             m->options.memory_base,\n                             (uint64_t)(uintptr_t)m->scratch,\n                             (uint64_t)(uintptr_t)m->state_words,\n                             m->options.memory_size - 1u };\n");
    out.push_str("#if AXIS_SIM_CAN_JIT\n");
    out.push_str("  if (mprotect(m->code, AXIS_SIM_CODE_BYTES, PROT_READ | PROT_WRITE)) { return NULL; }\n");
    out.push_str("#endif\n");
    out.push_str("  if (!m->jit->translate(ops, count, m->code + m->code_used, room,\n                         (uint64_t)(uintptr_t)(m->code + m->code_used),\n                         &parts, &used)) { return NULL; }\n");
    out.push_str("#if AXIS_SIM_CAN_JIT\n");
    out.push_str("  if (mprotect(m->code, AXIS_SIM_CODE_BYTES, PROT_READ | PROT_EXEC)) { return NULL; }\n");
    out.push_str("  __builtin___clear_cache((char *)(m->code + m->code_used),\n                          (char *)(m->code + m->code_used + used));\n");
    out.push_str("#endif\n");
    out.push_str("  axis_sim_block *block = &m->blocks[m->block_count++];\n");
    out.push_str("  block->pc = pc; block->at = m->code_used; block->used = used;\n");
    out.push_str("  block->count = count; block->live = 1;\n");
    out.push_str("  block->ends_on_branch = branchy;\n");
    out.push_str("  block->touches_state = 0;\n");
    out.push_str("  for (int32_t k = 0; k < count; ++k) {\n");
    out.push_str("    if (m->jit->reads_state(ops[k].stencil)) { block->touches_state = 1; break; }\n  }\n");
    out.push_str("  m->code_used += used;\n  m->built++;\n  return block;\n}\n\n");
    // ⚠️ The named entries and the flat array, in both directions. Translated
    // code reaches state by offset from one pointer -- a stencil is machine
    // code, it cannot look a name up -- and the machine keeps `{name, value,
    // width}` because that is what a host reads. The two are copied around
    // every block rather than kept in step continuously, which costs one pass
    // over a handful of slots and means the interpreter's own path is
    // untouched.
    //
    // ⚠️ Masked on the way back. A stencil writes a whole word; a slot four
    // bits wide keeps four, and letting the extra bits through would make a
    // translated run disagree with an interpreted one about a flag word
    // nobody wrote.
    // ⚠️ At the MACHINE's word width, not always 64. A stencil is compiled
    // against `iW* %state` where W is the description's word, so a 32-bit
    // machine's stencil reads slot `i` at byte `4i` while this array puts it at
    // byte `8i`. Writing 64-bit slots to a 32-bit reader handed RV32I's
    // `csrrci` a zero where `fflags` held 5, and only in a block -- the
    // interpreter reads the named entries and was right all along.
    out.push_str("static void axis_sim_state_in(axis_pack_machine *m) {\n");
    out.push_str("  for (int32_t i = 0; i < m->state_count && i < 64; ++i) {\n");
    out.push_str("    if (m->jit_word_bits == 32) {\n");
    out.push_str("      ((uint32_t *)m->state_words)[i] = (uint32_t)m->state[i].value;\n");
    out.push_str("    } else { m->state_words[i] = m->state[i].value; }\n  }\n}\n");
    out.push_str("static void axis_sim_state_out(axis_pack_machine *m) {\n");
    out.push_str("  for (int32_t i = 0; i < m->state_count && i < 64; ++i) {\n");
    out.push_str("    uint64_t value = m->jit_word_bits == 32\n");
    out.push_str("                   ? (uint64_t)((const uint32_t *)m->state_words)[i]\n");
    out.push_str("                   : m->state_words[i];\n");
    out.push_str("    uint32_t width = m->state[i].width;\n");
    out.push_str("    if (width && width < 64u) { value &= (UINT64_C(1) << width) - 1u; }\n");
    out.push_str("    m->state[i].value = value;\n  }\n}\n");
    // ⚠️ Declared costs, used. `latency` and `throughput` sat beside every
    // instruction in every description and nothing read them -- which makes
    // them free text a designer typed, and makes any co-design number built on
    // them a quotation of its author. This is the smallest thing that reads
    // them: an in-order single-issue scoreboard over the registers an
    // instruction names.
    out.push_str("static void axis_sim_account(axis_pack_machine *m, const axis_lift_entry *entry,\n");
    out.push_str("                             const axis_lifted *lifted) {\n");
    out.push_str("  uint64_t issue = m->issue_free;\n");
    out.push_str("  /* It cannot issue before what it reads is ready. */\n");
    out.push_str("  for (int32_t o = 0; o < entry->operand_count; ++o) {\n");
    out.push_str("    const axis_lift_operand *operand = &entry->operands[o];\n");
    out.push_str("    if (!operand->role || (operand->role_code == AXIS_ROLE_OUT)) { continue; }\n");
    out.push_str("    if (!axis_op_class(operand)) { continue; }\n");
    out.push_str("    uint32_t slot = axis_operand_slot(operand, lifted->operands[o]);\n");
    out.push_str("    if (slot < AXIS_SIM_REG_SLOTS && m->ready[slot] > issue) { issue = m->ready[slot]; }\n");
    out.push_str("  }\n");
    out.push_str("  uint32_t latency = axis_sim_latency_on(m->core, entry);\n");
    out.push_str("  for (int32_t o = 0; o < entry->operand_count; ++o) {\n");
    out.push_str("    const axis_lift_operand *operand = &entry->operands[o];\n");
    out.push_str("    if (!operand->role\n        || ((operand->role_code != AXIS_ROLE_OUT) && (operand->role_code != AXIS_ROLE_INOUT))) { continue; }\n");
    out.push_str("    if (!axis_op_class(operand)) { continue; }\n");
    out.push_str("    uint32_t slot = axis_operand_slot(operand, lifted->operands[o]);\n");
    out.push_str("    if (slot < AXIS_SIM_REG_SLOTS) { m->ready[slot] = issue + latency + m->pending_stall; }\n");
    out.push_str("  }\n");
    out.push_str("  /* And the issue port is busy for one instruction's worth of it. A unit\n     that retires one every other cycle has a throughput of 500. */\n");
    out.push_str("  uint32_t rate = entry->throughput_milli ? entry->throughput_milli : 1000u;\n");
    out.push_str("  uint64_t interval = (1000u + rate - 1u) / rate;\n");
    out.push_str("  if (interval < 1u) { interval = 1u; }\n");
    out.push_str("  /* ⚠️ And what its memory accesses cost. A miss delays the instruction\n     that asked for it, which is why this is charged here and not as a\n     stall of the whole machine: the next independent instruction can still\n     issue behind it. */\n");
    out.push_str("  m->issue_free = issue + interval + m->pending_stall;\n");
    out.push_str("  m->pending_stall = 0;\n");
    out.push_str("  if (m->issue_free > m->cycle) { m->cycle = m->issue_free; }\n}\n\n");
    out.push_str("/* ⚠️ ONE definition of how big the buffer is. It was written out three\n   times with two different defaults, so entries were stored modulo 64 and\n   looked up modulo 1: every producer lookup missed, every miss read as\n   `already retired`, and a dependent chain ran as fast as independent work.\n   The model was not wrong about dependences -- it never saw any. */\n");
    out.push_str("static uint32_t axis_ooo_rob(const axis_sim_core *core) {\n");
    out.push_str("  uint32_t rob = core->rob ? core->rob : AXIS_SIM_INORDER_WINDOW;\n");
    out.push_str("  return rob > AXIS_SIM_ROB_MAX ? AXIS_SIM_ROB_MAX : rob;\n}\n\n");
    out.push_str("/* A context's share of a window it splits with the core's other contexts:\n   statically partitioned, at least one entry. */\n");
    out.push_str("static uint32_t axis_grp_share(const axis_sim_group *g, uint32_t whole) {\n");
    out.push_str("  if (!g || g->count <= 1) { return whole; }\n");
    out.push_str("  uint32_t part = whole / (uint32_t)g->count;\n  return part ? part : 1u;\n}\n\n");
    out.push_str("/* The group's counters are this cycle's: the first context to look at a\n   new cycle starts them again. */\n");
    out.push_str("static void axis_grp_sync(axis_sim_group *g, uint64_t now) {\n");
    out.push_str("  if (g && g->cycle != now) {\n    g->cycle = now;\n    g->issued = g->committed = g->dispatched = g->ports_busy = 0;\n    g->fuse_n[0] = g->fuse_n[1] = g->fuse_n[2] = 0;\n  }\n}\n\n");
    out.push_str("/* ⚠️ RIDING (U4b). Whether an instruction fetched at `at` from `pc` has\n   already been paid for at `stage` (0 dispatch, 1 issue, 2 commit) this\n   cycle by another member of its warp: then it takes no slot, port or unit.\n   Otherwise `pay` records that it paid, so the members behind it ride. Same\n   cycle only: a member a cycle behind pays its own way, which is what\n   divergence -- in time as much as in pc -- costs. */\n");
    out.push_str("static int axis_grp_rides(const axis_sim_group *g, int stage, uint32_t warp, uint64_t at, uint64_t pc) {\n");
    out.push_str("  if (!g || !warp) { return 0; }\n");
    out.push_str("  for (uint32_t i = 0; i < g->fuse_n[stage]; ++i) {\n");
    out.push_str("    if (g->fuse_warp[stage][i] == warp && g->fuse_at[stage][i] == at && g->fuse_pc[stage][i] == pc) { return 1; }\n  }\n  return 0;\n}\n\n");
    out.push_str("static void axis_grp_pay(axis_sim_group *g, int stage, uint32_t warp, uint64_t at, uint64_t pc) {\n");
    out.push_str("  if (!g || !warp || g->fuse_n[stage] >= AXIS_SIM_FUSE) { return; }\n");
    out.push_str("  g->fuse_warp[stage][g->fuse_n[stage]] = warp;\n");
    out.push_str("  g->fuse_at[stage][g->fuse_n[stage]] = at;\n  g->fuse_pc[stage][g->fuse_n[stage]++] = pc;\n}\n\n");
    out.push_str("static axis_sim_rob_entry *axis_ooo_find(axis_pack_machine *m, uint64_t seq) {\n");
    out.push_str("  if (seq == AXIS_SIM_NO_SEQ || seq < m->rob_head || seq >= m->rob_tail) { return 0; }\n");
    out.push_str("  axis_sim_rob_entry *e = &m->rob[seq % AXIS_SIM_ROB_MAX];\n");
    out.push_str("  return (e->valid && e->seq == seq) ? e : 0;\n}\n\n");
    out.push_str("/* Whether [lo, hi) of one access meets another's. */\n");
    out.push_str("static int axis_ooo_overlaps(const axis_sim_rob_entry *a, const axis_sim_rob_entry *b, int *covered) {\n");
    out.push_str("  int any = 0;\n  *covered = 1;\n");
    out.push_str("  for (int32_t i = 0; i < a->mem_count; ++i) {\n");
    out.push_str("    int hit = 0, inside = 0;\n");
    out.push_str("    for (int32_t j = 0; j < b->mem_count; ++j) {\n");
    out.push_str("      if (a->mem_lo[i] < b->mem_hi[j] && b->mem_lo[j] < a->mem_hi[i]) {\n");
    out.push_str("        hit = 1;\n        if (b->mem_lo[j] <= a->mem_lo[i] && a->mem_hi[i] <= b->mem_hi[j]) { inside = 1; }\n      }\n    }\n");
    out.push_str("    if (hit) { any = 1; if (!inside) { *covered = 0; } }\n  }\n");
    out.push_str("  return any;\n}\n\n");
    out.push_str("/* ⚠️ A LOAD AGAINST THE STORES OLDER THAN IT (O1). Registers are not the\n   only way one instruction waits for another: a load that reads what a store\n   wrote depends on it through memory, and a window that let it run first\n   would be reading a value the program never had.\n\n   * CONSERVATIVE: an older store that has not executed has no address yet,\n     so the load cannot know it does not overlap, and waits. PERFECT: the\n     trace knows every address, so only a store it overlaps holds it --\n     an oracle, and the bound any predictor of memory dependences is\n     measured against.\n   * An overlapping store the load lies wholly INSIDE forwards its value\n     once it has executed. A partial overlap cannot be forwarded -- the\n     bytes come from two places -- and waits for the store to retire, as\n     does every overlap on a machine that does not forward. Retired means\n     gone from the window, which is why that is `return 0` here. */\n");
    out.push_str("static int axis_ooo_memory_ready(axis_pack_machine *m, const axis_sim_rob_entry *e) {\n");
    out.push_str("  uint32_t policy = m->core->disambiguation;\n");
    out.push_str("  for (uint64_t s = m->rob_head; s < e->seq; ++s) {\n");
    out.push_str("    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("    if (!o->valid || !o->is_store) { continue; }\n");
    out.push_str("    /* ⚠️ A store in this load's SET is waited for, address known or not:\n       the two have collided before, and the table says they will again. */\n");
    out.push_str("    if (policy == 3u && o->store_set && o->store_set == e->store_set && !o->issued) { return 0; }\n");
    out.push_str("    if (!o->addr_known) {\n");
    out.push_str("      if (policy == 0u) { return 0; }           /* conservative: cannot know */\n");
    out.push_str("      if (policy >= 2u) { continue; }           /* speculative: bet it misses */\n");
    out.push_str("    }\n");
    out.push_str("    int covered = 0;\n");
    out.push_str("    if (!axis_ooo_overlaps(e, o, &covered)) { continue; }\n");
    out.push_str("    if (!m->core->forwarding || !covered) { return 0; }\n");
    out.push_str("    if (!o->issued || o->complete > m->now) { return 0; }\n  }\n");
    out.push_str("  return 1;\n}\n\n");
    out.push_str("/* Whether the operands a store's ADDRESS is computed from have landed. */\n");
    out.push_str("static int axis_ooo_address_ready(axis_pack_machine *m, const axis_sim_rob_entry *o) {\n");
    out.push_str("  for (int32_t i = 0; i < o->addr_src_count; ++i) {\n");
    out.push_str("    axis_sim_rob_entry *p = axis_ooo_find(m, o->addr_src_seq[i]);\n");
    out.push_str("    if (p && (!p->issued || p->complete > m->now)) { return 0; }\n  }\n  return 1;\n}\n\n");
    out.push_str("/* ⚠️ A MEMORY-ORDER VIOLATION (O5). A store whose address has just become\n   known, over a younger load that has already issued: the load read memory\n   before the store wrote it, so its value -- and everything computed from it\n   -- is wrong. It and everything younger are squashed, and may issue again\n   `replay` cycles from now. A store-set machine also learns the pair, so the\n   next load from that address waits for the next store from this one. */\n");
    out.push_str("static void axis_ooo_resolve_addresses(axis_pack_machine *m) {\n");
    out.push_str("  const axis_sim_core *core = m->core;\n");
    out.push_str("  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {\n");
    out.push_str("    axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("    if (!o->valid || !o->is_store || o->addr_known) { continue; }\n");
    out.push_str("    if (!axis_ooo_address_ready(m, o)) { continue; }\n");
    out.push_str("    o->addr_known = 1;\n");
    out.push_str("    if (!core->lsq || core->disambiguation < 2u) { continue; }\n");
    out.push_str("    for (uint64_t t = s + 1u; t < m->rob_tail; ++t) {\n");
    out.push_str("      axis_sim_rob_entry *l = &m->rob[t % AXIS_SIM_ROB_MAX];\n");
    out.push_str("      int covered = 0;\n");
    out.push_str("      if (!l->valid || l->wrong || !l->is_load || !l->issued || !axis_ooo_overlaps(l, o, &covered)) { continue; }\n");
    out.push_str("      m->violations++;\n");
    out.push_str("      if (core->disambiguation == 3u && core->store_sets) {\n");
    out.push_str("        uint32_t n = core->store_sets < AXIS_SIM_SSIT_MAX ? core->store_sets : AXIS_SIM_SSIT_MAX;\n");
    out.push_str("        uint32_t li = (uint32_t)((l->pc >> 2) % n), si = (uint32_t)((o->pc >> 2) % n);\n");
    out.push_str("        uint32_t set = m->ssit[li] ? m->ssit[li] : (m->ssit[si] ? m->ssit[si] : ++m->next_set);\n");
    out.push_str("        m->ssit[li] = set;\n        m->ssit[si] = set;\n");
    out.push_str("        l->store_set = set;\n        o->store_set = set;\n      }\n");
    out.push_str("      for (uint64_t u = t; u < m->rob_tail; ++u) {\n");
    out.push_str("        axis_sim_rob_entry *x = &m->rob[u % AXIS_SIM_ROB_MAX];\n");
    out.push_str("        if (!x->valid) { continue; }\n");
    out.push_str("        x->issued = 0;\n        x->complete = 0;\n        x->not_before = m->now + core->replay;\n      }\n");
    out.push_str("      break;\n    }\n  }\n}\n\n");
    out.push_str("/* ⚠️ A LOAD AGAINST OLDER STORES, execution-driven (E3). No trace says where\n   anything points, so the policies are about what has EXECUTED: conservative\n   waits for every older store -- an unexecuted one has no address yet --\n   speculative waits for none and is squashed when it was wrong, and\n   store-sets waits only for older stores that have collided with this load\n   before. */\n");
    out.push_str("static int axis_x_memory_ready(axis_pack_machine *m, const axis_sim_rob_entry *e) {\n");
    out.push_str("  uint32_t policy = m->core->disambiguation;\n");
    out.push_str("  if (policy == 2u) { return 1; }\n");
    out.push_str("  for (uint64_t s = m->rob_head; s < e->seq; ++s) {\n");
    out.push_str("    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("    if (!o->valid || !o->is_store || o->x_executed) { continue; }\n");
    out.push_str("    if (policy == 0u) { return 0; }\n");
    out.push_str("    if (policy == 3u && o->store_set && o->store_set == e->store_set) { return 0; }\n  }\n");
    out.push_str("  return 1;\n}\n\n");
    out.push_str("/* Ready when every producer has issued and its result has landed. A\n   producer already committed is gone from the buffer, and gone means ready. */\n");
    // S1-S3: each core's scheduler, beside the core table rather than in it.
    out.push_str("static const uint32_t AXIS_SIM_CORE_SCHED[][2] = {\n");
    for core in &document.cores {
        out.push_str(&format!("  {{ {}u, {}u }},\n", core.dispatch_width, core.schedule));
    }
    out.push_str("  { 0u, 0u }\n};\n");
    for (index, core) in document.cores.iter().enumerate() {
        if core.units.iter().any(|u| u.queue != 0) {
            out.push_str(&format!(
                "static const uint32_t AXIS_SIM_UNIT_QUEUE_{index}[] = {{ {} }};\n",
                core.units.iter().map(|u| format!("{}u", u.queue)).collect::<Vec<_>>().join(", ")
            ));
        }
        if !core.bypass.is_empty() {
            let n = core.units.len();
            let mut cells = vec![0u32; n * n];
            for (from, to, cycles) in &core.bypass {
                let at = |name: &String| core.units.iter().position(|u| u.name.eq_ignore_ascii_case(name));
                if let (Some(f), Some(t)) = (at(from), at(to)) {
                    cells[f * n + t] = *cycles;
                }
            }
            out.push_str(&format!(
                "static const uint8_t AXIS_SIM_BYPASS_{index}[] = {{ {} }};\n",
                cells.iter().map(|c| format!("{c}u")).collect::<Vec<_>>().join(", ")
            ));
        }
    }
    out.push_str("static const uint32_t *const AXIS_SIM_CORE_UNIT_QUEUE[] = {\n");
    for (index, core) in document.cores.iter().enumerate() {
        if core.units.iter().any(|u| u.queue != 0) {
            out.push_str(&format!("  AXIS_SIM_UNIT_QUEUE_{index},\n"));
        } else {
            out.push_str("  0,\n");
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("static const uint8_t *const AXIS_SIM_CORE_BYPASS[] = {\n");
    for (index, core) in document.cores.iter().enumerate() {
        if core.bypass.is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_BYPASS_{index},\n"));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("static const int32_t AXIS_SIM_CORE_UNITS[] = {\n");
    for core in &document.cores {
        out.push_str(&format!("  {},\n", core.units.len()));
    }
    out.push_str("  0\n};\n");
    // TLB2: each core's walker, page table, walk cache and large pages.
    out.push_str("static const uint64_t AXIS_SIM_CORE_TLB2[][8] = {\n");
    for core in &document.cores {
        let t = core.tlb.clone().unwrap_or_default();
        out.push_str(&format!(
            "  {{ {}ull, {}ull, {}ull, {}ull, {}ull, {}ull, {}ull, {}ull }},\n",
            t.walkers, t.walk_levels, t.walk_level_cycles, t.walk_table, t.walk_cache,
            t.huge_bytes, t.huge_from, t.huge_to
        ));
    }
    out.push_str("  { 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull, 0ull }\n};\n");
    // ME1: which cores do their moves at rename, and which instructions are
    // moves -- told from what each computes (`timing::move_forms`).
    out.push_str("static const uint8_t AXIS_SIM_CORE_ELIM[] = {");
    for core in &document.cores {
        let does = |what: &str| core.eliminate.split(' ').any(|word| word == what);
        out.push_str(&format!(" {}u,", u32::from(does("moves")) | u32::from(does("zeros")) << 1));
    }
    out.push_str(" 0u };\n");
    out.push_str("typedef struct { const char *isa; const char *mnemonic; const char *source; const char *zero; } axis_sim_move;\n");
    out.push_str("static const axis_sim_move AXIS_SIM_MOVES[] = {\n");
    if document.cores.iter().any(|core| core.eliminate.split(' ').any(|word| word == "moves")) {
        for instruction in &document.instructions {
            for (source, zero) in crate::timing::move_forms(instruction) {
                out.push_str(&format!(
                    "  {{ {}, {}, {}, {} }},\n",
                    c_string(&instruction.isa),
                    c_string(&instruction.mnemonic),
                    c_string(&source),
                    c_string(zero.as_deref().unwrap_or(""))
                ));
            }
        }
    }
    out.push_str("  { 0, 0, 0, 0 }\n};\n");
    // WM1: each core's store buffer -- entries, and whether it drains in any
    // order, and how its loads are seen (0 in order, 1 in any, 2 in theirs:
    // total store order's) -- and the instructions that order memory
    // (`timing::orders_memory`).
    out.push_str("static const uint32_t AXIS_SIM_CORE_SB[][3] = {\n");
    for core in &document.cores {
        out.push_str(&format!(
            "  {{ {}u, {}u, {}u }},\n",
            core.store_buffer,
            u32::from(core.store_drain == "any"),
            match core.load_order.as_str() {
                "any" => 1u32,
                "tso" => 2u32,
                _ => 0u32,
            }
        ));
    }
    out.push_str("  { 0u, 0u, 0u }\n};\n");
    out.push_str("static const char *const AXIS_SIM_ORDERED[][2] = {\n");
    if document.cores.iter().any(|core| core.store_buffer != 0 || matches!(core.load_order.as_str(), "any" | "tso")) {
        for instruction in document.instructions.iter().filter(|i| crate::timing::orders_memory(i)) {
            out.push_str(&format!("  {{ {}, {} }},\n", c_string(&instruction.isa), c_string(&instruction.mnemonic)));
        }
    }
    out.push_str("  { 0, 0 }\n};\n");
    out.push_str("static int axis_sim_orders(const axis_lift_entry *entry) {\n  if (!entry) { return 0; }\n  for (int32_t i = 0; AXIS_SIM_ORDERED[i][1]; ++i) {\n    if (!strcmp(AXIS_SIM_ORDERED[i][1], entry->mnemonic) && (!entry->isa || !strcmp(AXIS_SIM_ORDERED[i][0], entry->isa))) { return 1; }\n  }\n  return 0;\n}\n");
    // ZI1: which instructions are nothing when two of their operands name one
    // register (`timing::zero_forms`); `source` and `zero` are the two.
    out.push_str("static const axis_sim_move AXIS_SIM_ZEROS[] = {\n");
    if document.cores.iter().any(|core| core.eliminate.split(' ').any(|word| word == "zeros")) {
        for instruction in &document.instructions {
            for (a, b) in crate::timing::zero_forms(instruction) {
                out.push_str(&format!(
                    "  {{ {}, {}, {}, {} }},\n",
                    c_string(&instruction.isa),
                    c_string(&instruction.mnemonic),
                    c_string(&a),
                    c_string(&b)
                ));
            }
        }
    }
    out.push_str("  { 0, 0, 0, 0 }\n};\n");
    // FU1: the pairs each core's decoder fuses, head and tail by mnemonic
    // prefix. Whether two words are such a pair the engine tells from the
    // registers they name.
    for (index, core) in document.cores.iter().enumerate() {
        let Some(timing) = core.timing.as_ref().filter(|t| !t.fuse.is_empty()) else { continue };
        out.push_str(&format!("static const char *const AXIS_SIM_FUSE_{index}[] = {{"));
        for (head, tail) in &timing.fuse {
            out.push_str(&format!(" {}, {},", c_string(head), c_string(tail)));
        }
        out.push_str(" 0, 0 };\n");
    }
    out.push_str("static const char *const *const AXIS_SIM_CORE_FUSE[] = {");
    for (index, core) in document.cores.iter().enumerate() {
        if core.timing.as_ref().is_some_and(|t| !t.fuse.is_empty()) {
            out.push_str(&format!(" AXIS_SIM_FUSE_{index},"));
        } else {
            out.push_str(" 0,");
        }
    }
    out.push_str(" 0 };\n");
    out.push_str("static const uint8_t AXIS_SIM_CORE_SELECT[] = {\n");
    for core in &document.cores {
        out.push_str(&format!("  {}u,\n", u32::from(core.select == "position")));
    }
    out.push_str("  0u\n};\n");
    out.push_str("static const uint32_t AXIS_SIM_CORE_VP[][4] = {\n");
    for core in &document.cores {
        let (entries, confidence) = core.value_prediction.unwrap_or((0, 0));
        out.push_str(&format!(
            "  {{ {entries}u, {confidence}u, {}u, {}u }},\n",
            u32::from(core.value_stride),
            core.rename_width
        ));
    }
    out.push_str("  { 0u, 0u, 0u, 0u }\n};\n");
    // S5: the queue each unit shares -- its index plus one, 0 for none -- and
    // each queue's size.
    for (index, core) in document.cores.iter().enumerate() {
        if core.queues.is_empty() {
            continue;
        }
        let of = |unit: &crate::ast::CoreUnit| {
            core.queues
                .iter()
                .position(|(_, _, members)| members.iter().any(|m| m.eq_ignore_ascii_case(&unit.name)))
                .map_or(0, |at| at + 1)
        };
        out.push_str(&format!(
            "static const uint8_t AXIS_SIM_UNIT_CLUSTER_{index}[] = {{ {} }};\n",
            core.units.iter().map(|u| format!("{}u", of(u))).collect::<Vec<_>>().join(", ")
        ));
        out.push_str(&format!(
            "static const uint32_t AXIS_SIM_CLUSTER_SIZE_{index}[] = {{ {} }};\n",
            core.queues.iter().map(|(_, size, _)| format!("{size}u")).collect::<Vec<_>>().join(", ")
        ));
    }
    for (what, ty) in [("UNIT_CLUSTER", "uint8_t"), ("CLUSTER_SIZE", "uint32_t")] {
        out.push_str(&format!("static const {ty} *const AXIS_SIM_CORE_{what}[] = {{\n"));
        for (index, core) in document.cores.iter().enumerate() {
            if core.queues.is_empty() {
                out.push_str("  0,\n");
            } else {
                out.push_str(&format!("  AXIS_SIM_{what}_{index},\n"));
            }
        }
        out.push_str("  0\n};\n");
    }
    out.push_str(SCHED_C);
    out.push_str("static int axis_ooo_ready(axis_pack_machine *m, const axis_sim_rob_entry *e) {\n");
    out.push_str("  for (int32_t i = 0; i < e->src_count; ++i) {\n");
    out.push_str("    /* A delay the scheduler or a bypass adds outlasts the producer's place\n       in the window (S3). */\n");
    out.push_str("    axis_sim_rob_entry *p = axis_ooo_find(m, e->src_seq[i]);\n");
    out.push_str("    /* A value predicted is not waited for (S4). */\n    if (p && p->vp) { continue; }\n");
    out.push_str("    if (axis_sched_waits(m, e->src_seq[i], e->unit)) { return 0; }\n");
    out.push_str("    if (!p) { continue; }\n");
    out.push_str("    if (!p->issued || p->complete > m->now) { return 0; }\n  }\n");
    out.push_str("  if (m->core->lsq && e->is_load) {\n    return m->core->execute_driven ? axis_x_memory_ready(m, e) : axis_ooo_memory_ready(m, e);\n  }\n");
    out.push_str("  return 1;\n}\n\n");
    out.push_str("/* ⚠️ LOCKSTEP (U4c). A warp instruction issues once, for every member that\n   holds it, when ALL of them are ready -- what a SIMT core does with its\n   lanes. A member whose copy is ready waits for a member whose copy is not.\n   Letting each issue when it alone was ready made riding depend on members\n   being ready in the same cycle, which a load finishing a cycle apart ends\n   for good: vecadd on two warps of four rode 1.3 to an issue where the SIMT\n   engine issued 3.9 lanes. Copies in a member's window or still in its\n   fetch buffer are waited for; a member at another pc holds none. */\n");
    out.push_str("static int axis_x_warp_waits(axis_pack_machine *m, const axis_sim_rob_entry *e) {\n");
    out.push_str("  axis_sim_group *g = m->grp;\n");
    out.push_str("  if (!g || !m->x_warp) { return 0; }\n");
    out.push_str("  for (int32_t i = 0; i < g->count; ++i) {\n");
    out.push_str("    axis_pack_machine *o = g->member[i];\n");
    out.push_str("    if (!o || o == m || o->x_warp != m->x_warp || o->sim.status != AXIS_SIM_RUNNING) { continue; }\n");
    out.push_str("    /* ⚠️ Members tick one after another within a cycle. One that has\n       ticked in this one has issued what it is going to: its unissued copy\n       goes next cycle, so this one waits to go with it. One that has not\n       ticked yet will issue after this one and ride, if its copy is ready\n       then -- in its window and ready now, or still in its fetch buffer and\n       dispatched this cycle. Waiting on a buffered copy of a member yet to\n       tick instead made the two issue a cycle apart and both pay. */\n");
    out.push_str("    int ticked = o->now > m->now;\n");
    out.push_str("    for (uint64_t s = o->rob_head; s < o->rob_tail; ++s) {\n");
    out.push_str("      axis_sim_rob_entry *x = &o->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("      if (!x->valid || x->issued || x->x_fetched_at != e->x_fetched_at || x->pc != e->pc) { continue; }\n");
    out.push_str("      if (ticked) { return 1; }\n");
    out.push_str("      if (x->not_before > m->now || !axis_ooo_ready(o, x)) { return 1; }\n");
    out.push_str("      break;\n    }\n");
    out.push_str("    /* A buffered copy: wait, unless the member has yet to tick and can\n       dispatch it this cycle -- deep enough through the front end, among the\n       first `issue_width` in its buffer, with room in its share of the\n       window. A member whose window is full of misses cannot, and issuing\n       without it split the warp exactly where lockstep matters. */\n");
    out.push_str("    uint32_t width = o->core->issue_width ? o->core->issue_width : 1u;\n");
    out.push_str("    uint64_t room = axis_grp_share(g, axis_ooo_rob(o->core));\n");
    out.push_str("    for (uint32_t b = 0; b < o->x_buf_count; ++b) {\n");
    out.push_str("      const axis_x_fetched *f = &o->x_buf[(o->x_buf_head + b) % AXIS_SIM_XBUF];\n");
    out.push_str("      if (f->fetched != e->x_fetched_at || f->pc != e->pc) { continue; }\n");
    out.push_str("      if (ticked || b >= width || f->fetched + o->core->fe_depth > m->now\n");
    out.push_str("          || o->rob_tail - o->rob_head + b >= room) { return 1; }\n");
    out.push_str("      break;\n    }\n");
    out.push_str("  }\n  return 0;\n}\n\n");
    out.push_str("/* How many threads one issue of `e` serves: itself, and every other member\n   of its warp holding a copy of the same fused instruction -- which, issuing\n   in lockstep, ride with it. */\n");
    out.push_str("static uint32_t axis_x_warp_threads(axis_pack_machine *m, const axis_sim_rob_entry *e) {\n");
    out.push_str("  axis_sim_group *g = m->grp;\n  uint32_t n = 1u;\n");
    out.push_str("  if (!g || !m->x_warp) { return n; }\n");
    out.push_str("  for (int32_t i = 0; i < g->count; ++i) {\n");
    out.push_str("    axis_pack_machine *o = g->member[i];\n");
    out.push_str("    if (!o || o == m || o->x_warp != m->x_warp || o->sim.status != AXIS_SIM_RUNNING) { continue; }\n");
    out.push_str("    int held = 0;\n");
    out.push_str("    for (uint64_t s = o->rob_head; s < o->rob_tail && !held; ++s) {\n");
    out.push_str("      const axis_sim_rob_entry *x = &o->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("      held = x->valid && x->x_fetched_at == e->x_fetched_at && x->pc == e->pc;\n    }\n");
    out.push_str("    for (uint32_t b = 0; b < o->x_buf_count && !held; ++b) {\n");
    out.push_str("      const axis_x_fetched *f = &o->x_buf[(o->x_buf_head + b) % AXIS_SIM_XBUF];\n");
    out.push_str("      held = f->fetched == e->x_fetched_at && f->pc == e->pc;\n    }\n");
    out.push_str("    n += (uint32_t)held;\n  }\n  return n;\n}\n\n");
    out.push_str("/* One cycle: retire in order from the head, then issue whatever is ready\n   from anywhere in the window. Committing first is what frees the entry an\n   instruction dispatched this cycle may need. */\n");
    out.push_str("static void axis_x_commit_one(axis_pack_machine *m, axis_sim_rob_entry *e);\nstatic void axis_x_hand_on(axis_pack_machine *m, axis_sim_rob_entry *e);\n");
    out.push_str("static void axis_x_after_commit(axis_pack_machine *m);\n");
    out.push_str("static void axis_x_resolve(axis_pack_machine *m);\n");
    out.push_str("static uint64_t axis_x_execute(axis_pack_machine *m, axis_sim_rob_entry *e);\n");
    out.push_str("static uint64_t axis_wp_access(axis_pack_machine *m, const axis_sim_rob_entry *e);\n");
    out.push_str(r#"/* ⚠️ A UNIT HAS LANES (docs/vector_units_design.md, VU1). `(lanes N)` on a
   unit makes one copy of it N lanes of 64 bits, and an instruction takes as
   many as the widest register it names is limbs: a scalar one, a 128-bit
   vector two. Narrower than the unit, several instructions share a copy in a
   cycle. WIDER, it takes every lane of a copy for ceil(need / N) BEATS -- the
   512-bit instruction on a 256-bit datapath -- and completes that many cycles
   less one later. With no `lanes` a unit is what it was: one instruction a
   copy. */
static uint32_t axis_unit_lanes(const axis_pack_machine *m, int32_t unit);
static const char *axis_unit_length(const axis_pack_machine *m, int32_t unit);
static uint32_t axis_unit_lenders(const axis_pack_machine *m, int32_t unit);
static int axis_unit_aborts(const axis_pack_machine *m, int32_t unit);
/* ⚠️ HOW MANY LANES IT NEEDS (VU2): as many as its widest register is limbs
   -- or, on a unit that names a length, as many as the elements it actually
   works on fill. A four-element add told to do two elements is half a
   register of work. The count is the instruction's own operand: a value in
   the word, or a register, whose value is what the newest older instruction
   to write it left, read now that this one may issue. */
static uint32_t axis_unit_need(const axis_pack_machine *m, const axis_sim_rob_entry *e) {
  uint32_t need = e->span ? e->span : 1u;
  if (!e->len_kind || !e->elem_bits) { return need; }
  uint64_t count = e->len_val;
  if (e->len_kind == 2u) {
    count = m->sim.regs[e->len_slot];
    for (uint64_t s = e->seq; s-- > m->rob_head;) {
      const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
      int32_t found = 0;
      if (!o->valid || !o->x_executed) { continue; }
      for (int32_t w = 0; w < o->x_wcount && !found; ++w) {
        if (o->x_wslot[w] == e->len_slot) { count = o->x_wval[w]; found = 1; }
      }
      if (found) { break; }
    }
  }
  if (count > e->elems) { count = e->elems; }
  uint64_t active = (count * e->elem_bits + 63u) / 64u;
  if (!active) { active = 1u; }
  return active < need ? (uint32_t)active : need;
}
/* ⚠️ ONE RULE ON EVERY CORE (agreed for U4c and VU1): an issue demands
   what one thread needs x the THREADS it serves. A context's own
   instruction serves one; a warp's fused instruction serves every member
   holding it, and its payer reserves the lanes its riders use. A 2-lane unit
   under a fused scalar of eight members takes 4 beats, which is what S1's
   SIMT reading said. */
static uint32_t axis_unit_beats(uint32_t need, uint32_t lanes) {
  return (lanes && need > lanes) ? (need + lanes - 1u) / lanes : 1u;
}
/* Whether copy `slot` can start an instruction needing `need` lanes now; with
   lanes, which ones it takes. The unit and lane times are the core's: a
   group's, for a context of one. */
static int axis_unit_can(const uint64_t *unit_free, uint64_t (*lane_free)[AXIS_SIM_UNIT_LANES_MAX], uint64_t now,
                         uint32_t need, int32_t slot, uint32_t lanes, uint8_t *taken, uint32_t *take) {
  if (!lanes) { return unit_free[slot] <= now; }
  if (need > lanes) { need = lanes; }
  *take = 0;
  for (uint32_t l = 0; l < lanes && *take < need; ++l) {
    if (lane_free[slot][l] <= now) { taken[(*take)++] = (uint8_t)l; }
  }
  return *take == need;
}
static void axis_unit_hold(uint64_t *unit_free, uint64_t (*lane_free)[AXIS_SIM_UNIT_LANES_MAX], int32_t slot,
                           uint32_t lanes, const uint8_t *taken, uint32_t take, uint64_t until) {
  if (!lanes) { unit_free[slot] = until; return; }
  for (uint32_t i = 0; i < take; ++i) { lane_free[slot][taken[i]] = until; }
}
/* ⚠️ AN OPERATION ABORTED (W4). A squashed instruction leaves the window at
   once, but what it started in a unit goes on unless the unit can stop: by
   default the model stops waiting for the result and the unit computes it
   anyway, held to the end. A unit declared `(abort true)` gives back what the
   instruction held -- the copy, or its lanes -- and is free the cycle AFTER
   the squash: the cycle it arrives in is the unit's last on that operation.
   Only what is still this instruction's is given back; a unit that is
   pipelined was already somebody else's. */
static void axis_unit_abort(axis_pack_machine *m, axis_sim_rob_entry *o) {
  if (!o->held_slot || o->held_until <= m->now + 1u || !axis_unit_aborts(m, o->held_unit)) { return; }
  axis_sim_group *grp = m->grp;
  axis_sim_shared *sh = 0;
  if (o->held_shared) {
    sh = o->held_unit < (int32_t)AXIS_SIM_SHARED_UNITS ? (grp ? grp->shared : m->shared)[o->held_unit] : 0;
    if (!sh) { return; }
  }
  uint64_t *uf = sh ? sh->unit_free : (grp ? grp->unit_free : m->unit_free);
  uint64_t (*lf)[AXIS_SIM_UNIT_LANES_MAX] = sh ? sh->lane_free : (grp ? grp->lane_free : m->lane_free);
  int32_t slot = o->held_slot - 1;
  if (!o->held_lanes) { if (uf[slot] == o->held_until) { uf[slot] = m->now + 1u; } }
  else {
    for (uint32_t l = 0; l < AXIS_SIM_UNIT_LANES_MAX; ++l) {
      if (((o->held_lanes >> l) & 1u) && lf[slot][l] == o->held_until) { lf[slot][l] = m->now + 1u; }
    }
  }
  o->held_slot = 0;
}
"#);
    out.push_str(r#"/* ⚠️ WHOSE TURN A SHARED UNIT IS (VU4). Several cores tick one after another
   in a cycle, so "first come" would be "first ticked", every cycle, and the
   second core would never be served. A turn is switch + 1 operations: long
   enough that changing owner is not all the unit does. The core the unit is
   serving goes on while its turn lasts, and after it only if nobody else is
   waiting; another core takes over once the turn is spent, or at once if the
   owner has stopped asking. "Waiting" is having asked this cycle or the
   last -- every attempt is recorded, granted or not. */
static void axis_unit_cost(const axis_pack_machine *m, int32_t unit, uint32_t *transport, uint32_t *change);
/* ⚠️ THE PARTY to a share is a CORE: a machine, or -- for the contexts of a
   shared core -- their group. A core's contexts already settle among
   themselves who issues; to another core they are one requester, and a unit
   that saw each context as a core would give a core of four contexts four
   turns in five. */
static int axis_shared_may(axis_sim_shared *sh, const void *party, uint64_t now, uint32_t turn) {
  int32_t me = -1, own = -1;
  for (int32_t i = 0; i < sh->count; ++i) {
    if (sh->who[i] == party) { me = i; }
    if (sh->who[i] == sh->owner) { own = i; }
  }
  if (me < 0) { return 0; }
  sh->asked[me] = now + 1u;
  if (!sh->owner) { return 1; }
  if (sh->owner == party) {
    if (sh->streak < turn) { return 1; }
    for (int32_t i = 0; i < sh->count; ++i) {
      if (i != me && sh->asked[i] && sh->asked[i] + 1u >= now + 1u) { return 0; }
    }
    return 1;
  }
  /* Not the owner: its turn has to be over, or it has to have gone quiet. */
  if (sh->streak >= turn) { return 1; }
  return !(own >= 0 && sh->asked[own] && sh->asked[own] + 1u >= now + 1u);
}
/* The unit starts an operation for `party`: the cycles changing owner costs. */
static uint32_t axis_shared_grant(axis_sim_shared *sh, const void *party, uint32_t change) {
  if (sh->owner == party) { sh->streak++; return 0u; }
  uint32_t cost = sh->owner ? change : 0u;
  sh->owner = party;
  sh->streak = 1u;
  return cost;
}
"#);
    out.push_str(MOVES_C);
    out.push_str(FUSE_C);
    out.push_str("static void axis_ooo_tick(axis_pack_machine *m) {\n");
    out.push_str("  const axis_sim_core *core = m->core;\n");
    out.push_str("  /* ⚠️ An in-order machine still has instructions IN FLIGHT -- issued,\n     executing, not yet retired -- so it has a buffer whether or not a\n     description names one. What it does not have is the ability to issue\n     past a stalled instruction. Undeclared, the buffer is generous and the\n     retire width is the issue width, so the structures a description did\n     not speak about do not silently become the constraint. */\n");
    out.push_str("  uint32_t commit_width = core->commit_width ? core->commit_width\n                       : (core->issue_width ? core->issue_width : 1u);\n");
    out.push_str("  uint32_t issue_width = core->issue_width ? core->issue_width : 1u;\n");
    out.push_str("  int32_t in_order = core->rob == 0u;\n");
    out.push_str("  /* ⚠️ Execution-driven: RESOLVE BEFORE COMMIT. A mispredicted branch that\n     completes this cycle must squash what came after it before anything\n     after it can retire -- resolved after commit instead, the wrong-path\n     work behind it retired in the same cycle, and the golden model replayed\n     every one. */\n");
    out.push_str("  axis_sim_group *grp = m->grp;\n  axis_grp_sync(grp, m->now);\n");
    out.push_str("  uint64_t *unit_free = grp ? grp->unit_free : m->unit_free;\n");
    out.push_str("  uint64_t (*lane_free)[AXIS_SIM_UNIT_LANES_MAX] = grp ? grp->lane_free : m->lane_free;\n");
    out.push_str("  if (core->execute_driven) { axis_x_resolve(m); }\n");
    out.push_str("  /* ⚠️ COMMIT IS IN ORDER, however wide it is. An instruction that\n     finished early waits for everything before it, which is most of why a\n     big window does not buy what its size suggests. */\n");
    out.push_str("  for (uint32_t c = 0; m->rob_head < m->rob_tail; ++c) {\n");
    out.push_str("    /* ⚠️ A step limit falls between two instructions, not between two\n       cycles: a wide commit stops at it, as the golden model would. */\n");
    out.push_str("    if (core->execute_driven && m->x_limit && m->sim.steps >= m->x_limit) { break; }\n");
    out.push_str("    axis_sim_rob_entry *e = &m->rob[m->rob_head % AXIS_SIM_ROB_MAX];\n");
    out.push_str("    if (!e->valid || e->wrong || !e->issued || e->complete > m->now) { break; }\n");
    out.push_str("    /* ⚠️ THE STORE BUFFER (WM1): a store needs room in it, and what orders\n       memory waits for it to be empty. */\n    if (core->execute_driven && !axis_sb_admits(m, e)) { break; }\n");
    out.push_str("    /* ⚠️ A store retires INTO the cache, and a blocking cache that is busy\n       does not take it: the store waits at the head, and everything behind\n       it. One a cycle, since the cache takes one request a cycle. A core\n       with a store buffer retires it into that instead (WM1), and it is\n       the buffer that waits for the cache -- unless the store orders\n       memory, and is written as it retires. */\n");
    out.push_str("    if (e->is_store && m->dc_free > m->now && axis_sim_core_blocking(core)\n        && (!core->execute_driven || !m->sb_entries || axis_sb_ordered(e))) { break; }\n");
    out.push_str(r#"    /* ⚠️ A CRACKED INSTRUCTION RETIRES WHOLE, execution-driven (U1). The
       golden model steps an instruction, not a micro-op, and what younger
       instructions see is the window laid over what has committed: a
       micro-op gone from the window before its instruction had stepped would
       take its result out of sight. So none of them retires until all have
       finished and all fit in what is left of this cycle's commit width --
       or the cycle is theirs alone, for one wider than the machine. */
    if (core->execute_driven && e->x_uops > 1 && e->x_uop == 0) {
      int32_t whole = 1;
      for (int32_t v = 1; v < e->x_uops && whole; ++v) {
        const axis_sim_rob_entry *o = &m->rob[(m->rob_head + (uint64_t)v) % AXIS_SIM_ROB_MAX];
        whole = m->rob_head + (uint64_t)v < m->rob_tail && o->valid && o->issued && o->complete <= m->now;
      }
      uint32_t spent = grp ? grp->committed : c;
      if (!whole || (spent && spent + (uint32_t)e->x_uops > commit_width)) { break; }
    }
"#);
    out.push_str("    /* A warp's member retiring what another has retired this cycle rides\n       (U4b); anything else needs commit bandwidth. */\n");
    out.push_str("    int rides = axis_grp_rides(grp, 2, m->x_warp, e->x_fetched_at, e->pc);\n");
    out.push_str("    if (!rides && !e->fused && !(core->execute_driven && e->x_uop > 0) && (grp ? grp->committed : c) >= commit_width) { break; }\n");
    out.push_str("    /* Retiring a write frees the register its destination was mapped to\n       BEFORE -- nothing younger can name that one any more. One back per\n       one taken, so the count is what is in flight. */\n");
    out.push_str("    for (int32_t d = 0; d < e->dst_count; ++d) {\n");
    out.push_str("      if (e->dst_pool[d] >= 0 && m->rename_used[e->dst_pool[d]]) { m->rename_used[e->dst_pool[d]]--; }\n    }\n");
    out.push_str("    /* ⚠️ COUNTED WHEN IT RETIRES, execution-driven: a micro-op of a path\n       that was squashed was never the program's. */\n");
    out.push_str("    if (core->execute_driven && !e->x_bad) {\n      m->micro_ops += e->fused ? 0u : 1u;\n      if (e->x_path == 1) { m->op_cache_ops++; } else if (e->x_path == 2) { m->loop_buffer_ops++; }\n    }\n");
    out.push_str("    if (core->execute_driven) {\n      /* Not the last micro-op: what it computed goes on to the one that is,\n         where the golden model steps and judges all of it (U1). */\n      if (e->x_uops > 1 && e->x_uop + 1 < e->x_uops) { axis_x_hand_on(m, e); }\n      else { axis_x_commit_one(m, e); }\n      m->x_loads -= (uint32_t)e->is_load;\n      m->x_stores -= (uint32_t)e->is_store;\n    }\n");
    out.push_str("    if (rides) { m->x_rides[2]++; }\n");
    out.push_str("    else if (grp && !e->fused) { grp->committed++; axis_grp_pay(grp, 2, m->x_warp, e->x_fetched_at, e->pc); }\n");
    out.push_str("    e->valid = 0;\n    m->rob_head++;\n    /* The tail of a fused pair retires with its head, in no width of its own (FU1). */\n    if (e->fused) { c--; if (m->fuse_live) { m->fuse_live--; } }\n");
    out.push_str("    if ((!core->execute_driven || m->x_retired) && m->now + 1u > m->cycle) { m->cycle = m->now + 1u; }\n");
    out.push_str("    if (core->execute_driven && (m->x_flush || m->x_halted)) { break; }\n  }\n");
    out.push_str("  if (core->execute_driven) {\n    axis_x_after_commit(m);\n");
    out.push_str("    if (m->x_halted) { m->now++; return; }\n  }\n");
    out.push_str("  /* ⚠️ ISSUE IS NOT. Oldest-ready-first over the whole window, which is\n     the one thing the in-order model cannot do at any width: an instruction\n     waiting on a slow producer does not hold up the ones behind it. */\n");
    out.push_str("  /* Only a trace-driven memory order reads what this learns: without an lsq\n     nothing does, and the execution-driven engine knows its addresses by\n     executing. A scan of the window every cycle, skipped. */\n");
    out.push_str("  if (core->lsq && !core->execute_driven) { axis_ooo_resolve_addresses(m); }\n");
    out.push_str("  /* What was done at rename follows what it read (ME1), before anything issues. */\n  if (m->elim_waiting) { axis_moves_follow(m); }\n");
    out.push_str("  uint32_t issued = grp ? grp->issued : 0u;\n");
    out.push_str("  uint32_t ports_busy = grp ? grp->ports_busy : 0u;\n");
    out.push_str("  /* ⚠️ THE ORDER IT PICKS IN (S8): by age, which is the window's own order,\n     or by position in the issue queue. */\n");
    out.push_str("  uint64_t order[AXIS_SIM_ROB_MAX];\n  uint32_t picks = m->select_position ? axis_select_order(m, order) : 0u;\n");
    out.push_str("  for (uint64_t at = 0, s = m->rob_head; m->select_position ? at < picks : s < m->rob_tail; ++at, ++s) {\n");
    out.push_str("    if (m->select_position) { s = order[at]; if (s >= m->rob_tail) { continue; } }\n");
    out.push_str("    axis_sim_rob_entry *e = &m->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("    if (!e->valid || e->issued || e->elim) { continue; }\n");
    out.push_str("    /* ⚠️ IN-ORDER ISSUE IS THIS ONE LINE. A machine without a window\n       stops at the first instruction that is not ready; one with a window\n       looks past it. Everything else about the pipeline -- dispatch,\n       execution, in-order retirement -- is the same machinery, which is\n       what makes the two comparable at all. They were two algorithms\n       reporting two different quantities before this. */\n");
    out.push_str("    /* Issue width spent: only a rider (U4b) may still issue, so the scan\n       goes on for a warp and stops for anything else. */\n");
    out.push_str("    int rides = axis_grp_rides(grp, 1, m->x_warp, e->x_fetched_at, e->pc);\n");
    out.push_str("    if (!rides && issued >= issue_width) { if (in_order || !m->x_warp) { break; } continue; }\n");
    out.push_str("    if (e->not_before > m->now || !axis_ooo_ready(m, e)) { if (in_order) { break; } continue; }\n");
    out.push_str("    if (!rides && core->execute_driven && axis_x_warp_waits(m, e)) { if (in_order) { break; } continue; }\n");
    out.push_str("    /* ⚠️ A BLOCKING CACHE takes a load when it is free, and a load does not\n       issue to a cache that will not take it: a structural stall, like a\n       busy unit. A store that retired this cycle has the cache's one\n       request, which is why commit comes first. */\n");
    out.push_str("    if (e->is_load && m->dc_free > m->now && axis_sim_core_blocking(core)) { if (in_order) { break; } continue; }\n");
    out.push_str("    /* ⚠️ A PORT first (O10): of the ports that feed this unit, one not yet\n       used this cycle. None free is a structural stall like a busy unit --\n       and for an in-order machine, the end of this cycle's issue. */\n");
    out.push_str("    uint32_t port = 0;\n");
    out.push_str("    if (!rides && core->port_count && e->unit >= 0) {\n");
    out.push_str("      uint32_t free_ports = core->unit_ports[e->unit] & ~ports_busy;\n");
    out.push_str("      if (!free_ports) { if (in_order) { break; } continue; }\n");
    out.push_str("      port = free_ports & (~free_ports + 1u);\n    }\n");
    out.push_str("    int32_t chosen = -1;\n    int32_t held_unit = e->unit;\n");
    out.push_str("    uint32_t busy = 1u;\n");
    out.push_str("    /* A unit with lanes (VU1): how many, the beats this instruction takes\n       of it, and which lanes of the copy chosen. A rider computes the same\n       beats as its payer, which reserved its lanes, so the two complete\n       together. */\n");
    out.push_str("    uint32_t lanes = e->unit >= 0 ? axis_unit_lanes(m, e->unit) : 0u;\n");
    out.push_str("    uint32_t threads = lanes ? axis_x_warp_threads(m, e) : 1u;\n");
    out.push_str("    uint32_t need = lanes ? axis_unit_need(m, e) * threads : 1u;\n    uint32_t beats = axis_unit_beats(need, lanes);\n");
    out.push_str("    uint8_t taken[AXIS_SIM_UNIT_LANES_MAX];\n    uint32_t take = 0;\n");
    out.push_str("    /* ⚠️ A unit SHARED with other cores (VU4): its copies and lanes are\n       the shared ones, it may not be this core's turn, and what it costs to\n       be served is the unit's own -- the result's way back, and the change\n       of owner. */\n");
    out.push_str("    axis_sim_shared **shared = grp ? grp->shared : m->shared;\n");
    out.push_str("    const void *party = grp ? (const void *)grp : (const void *)m;\n");
    out.push_str("    axis_sim_shared *sh = (!rides && e->unit >= 0 && e->unit < AXIS_SIM_SHARED_UNITS) ? shared[e->unit] : 0;\n");
    out.push_str("    uint64_t *uf = sh ? sh->unit_free : unit_free;\n");
    out.push_str("    uint64_t (*lf)[AXIS_SIM_UNIT_LANES_MAX] = sh ? sh->lane_free : lane_free;\n");
    out.push_str("    uint32_t far = 0, change = 0, extra = 0;\n");
    out.push_str("    if (sh) {\n      axis_unit_cost(m, e->unit, &far, &change);\n");
    out.push_str("      if (!axis_shared_may(sh, party, m->now, change + 1u)) { if (in_order) { break; } continue; }\n    }\n");
    out.push_str("    if (!rides && e->unit >= 0) {\n");
    out.push_str("      int32_t base = sh ? 0 : m->unit_base[e->unit];\n");
    out.push_str("      uint32_t copies = core->units[e->unit].count ? core->units[e->unit].count : 1u;\n");
    out.push_str("      for (uint32_t k = 0; k < copies; ++k) {\n");
    out.push_str("        int32_t slot = base + (int32_t)k;\n");
    out.push_str("        if (slot >= (int32_t)AXIS_SIM_UNIT_COPIES) { break; }\n");
    out.push_str("        if (axis_unit_can(uf, lf, m->now, need, slot, lanes, taken, &take)) { chosen = slot; break; }\n      }\n");
    out.push_str(r#"      /* ⚠️ A LANE BORROWED (VU3). Its own unit has no copy free; a unit that
         `accepts` it and has lanes idle this cycle may run it on them -- as
         many as it is wide, one for a scalar. Its own unit FIRST, so a lane is
         borrowed only when it would otherwise wait; and issue is oldest
         first, so a vector instruction older than the borrower already has
         the lanes it wanted. The borrowed lanes are held as the lender holds
         them: for a cycle if it is pipelined, for the latency if not. A
         warp's payer borrows for its riders too (need x threads), through
         the core's unit and lane times -- a group's, for a context. */
      int32_t host = e->unit;
      if (chosen < 0) {
        uint32_t lenders = axis_unit_lenders(m, e->unit);
        for (int32_t v = 0; lenders && v < core->unit_count && v < 32 && chosen < 0; ++v) {
          uint32_t lent = ((lenders >> v) & 1u) ? axis_unit_lanes(m, v) : 0u;
          /* A lender shared with other cores lends nothing (VU4): whose
             turn it is is about its own instructions. */
          if (!lent || (v < AXIS_SIM_SHARED_UNITS && shared[v])) { continue; }
          uint32_t wide = axis_unit_need(m, e) * threads;
          int32_t from = m->unit_base[v];
          uint32_t many = core->units[v].count ? core->units[v].count : 1u;
          for (uint32_t k = 0; k < many; ++k) {
            int32_t slot = from + (int32_t)k;
            if (slot >= (int32_t)AXIS_SIM_UNIT_COPIES) { break; }
            if (axis_unit_can(unit_free, lane_free, m->now, wide, slot, lent, taken, &take)) {
              chosen = slot; host = v; lanes = lent; need = wide;
              beats = axis_unit_beats(wide, lent);
              /* On the lender, which is this core's own: not the shared unit. */
              sh = 0; uf = unit_free; lf = lane_free; far = 0;
              break;
            }
          }
        }
      }
"#);
    out.push_str("      if (chosen < 0) { continue; }\n");
    out.push_str("      if (sh) { extra = axis_shared_grant(sh, party, change); }\n");
    out.push_str("      busy = (core->units[host].pipelined ? 1u : e->latency) + (beats - 1u) + extra;\n      held_unit = host;\n    }\n");
    out.push_str("    e->issued = 1;\n");
    out.push_str("    ports_busy |= port;\n");
    out.push_str("    /* ⚠️ Execution-driven: it EXECUTES now, on what the window has made,\n       and a load's cache miss is its own. */\n");
    out.push_str("    if (core->execute_driven) { m->x_waiting--; m->pending_walk = 0; e->stall = axis_x_execute(m, e); e->walk = m->pending_walk; m->pending_walk = 0; }\n");
    out.push_str("    /* A wrong-path instruction's accesses reach the cache when it ISSUES\n       (W2), and a miss is its own latency. */\n");
    out.push_str("    else if (e->wrong) { e->stall = axis_wp_access(m, e); }\n");
    out.push_str("    /* ⚠️ A WALKER has to be free (TLB2): the walk in what it waits on starts\n       when one is, and that walker is busy until the walk is done. */\n");
    out.push_str("    uint64_t walker = (e->walk && !e->wrong) ? axis_walker_take(m, m->now, e->walk) : 0u;\n");
    out.push_str("    e->complete = m->now + (e->latency ? e->latency : 1u) + (beats - 1u) + e->stall + extra + far + walker;\n    axis_sched_note(m, e);\n");
    out.push_str("    if (chosen >= 0) {\n      axis_unit_hold(uf, lf, chosen, lanes, taken, take, m->now + busy);\n");
    out.push_str("      /* What it holds, for a unit that aborts at a squash (W4). */\n");
    out.push_str("      e->held_slot = chosen + 1;\n      e->held_unit = held_unit;\n      e->held_shared = uf != unit_free;\n      e->held_until = m->now + busy;\n      e->held_lanes = 0u;\n");
    out.push_str("      for (uint32_t i = 0; lanes && i < take; ++i) { e->held_lanes |= 1u << taken[i]; }\n    }\n");
    out.push_str("    if (rides) { m->x_rides[1]++; }\n    else { issued++; axis_grp_pay(grp, 1, m->x_warp, e->x_fetched_at, e->pc); }\n  }\n");
    out.push_str("  if (grp) { grp->issued = issued; grp->ports_busy = ports_busy; }\n");
    out.push_str("  /* What the store buffer asks of a blocking cache, it asks last (WM1). */\n  if (core->execute_driven) { axis_sb_late(m); }\n");
    out.push_str("  m->now++;\n}\n\n");
    // ⚠️ Renaming is per register FILE. A view of a file -- AArch64's W of
    // its X, the D of its Q -- takes its register from the same pool, or a
    // machine would hold twice the registers it has.
    // ⚠️ Which operands a store's ADDRESS is computed from, from the effect
    // the description declares (O4). The pipeline would otherwise have to
    // treat every source as address and every store as late as its value.
    out.push_str("typedef struct { const char *isa; const char *mnemonic; const char *names; } axis_sim_store_addr;\n");
    out.push_str("static const axis_sim_store_addr AXIS_SIM_STORE_ADDRESS[] = {\n");
    for instruction in &document.instructions {
        if !crate::effects::behavior_is_authoritative(instruction) {
            continue;
        }
        let Some(behavior) = instruction.behavior.as_ref() else { continue };
        let mut names: Vec<String> = Vec::new();
        let mut stores = false;
        for effect in &behavior.effects {
            if let crate::effects::Loc::Mem { addr, .. } = &effect.loc {
                stores = true;
                for atom in crate::effects::expr_atoms(&addr.expr) {
                    if instruction.operands.iter().any(|o| o.name == atom) && !names.contains(&atom) {
                        names.push(atom);
                    }
                }
            }
        }
        if stores {
            out.push_str(&format!(
                "  {{ {}, {}, {} }},\n",
                c_string(&instruction.isa),
                c_string(&instruction.mnemonic),
                c_string(&format!(" {} ", names.join(" ")))
            ));
        }
    }
    out.push_str("  { 0, 0, 0 }\n};\n");
    out.push_str("static const char *axis_sim_store_address(const axis_lift_entry *entry) {\n");
    out.push_str("  for (const axis_sim_store_addr *r = AXIS_SIM_STORE_ADDRESS; r->mnemonic; ++r) {\n");
    out.push_str("    if (!strcmp(r->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(r->isa, entry->isa))) { return r->names; }\n  }\n  return 0;\n}\n");
    out.push_str("static int axis_sim_names(const char *names, const char *name) {\n");
    out.push_str("  if (!name) { return 0; }\n  size_t n = strlen(name);\n");
    out.push_str("  for (const char *p = strstr(names, name); p; p = strstr(p + 1, name)) {\n");
    out.push_str("    if (p > names && p[-1] == ' ' && p[n] == ' ') { return 1; }\n  }\n  return 0;\n}\n");
    out.push_str(&emit_control_tables(document));
    out.push_str(&emit_memop_table(document));
    out.push_str(&emit_stateop_table(document));
    out.push_str(&emit_keeps_table(document));
    out.push_str(&emit_direct_targets(document));
    out.push_str("typedef struct { const char *kind; const char *file; } axis_sim_reg_file;\n");
    out.push_str("static const axis_sim_reg_file AXIS_SIM_REG_FILES[] = {\n");
    for class in crate::ast::REGISTER_CLASSES {
        out.push_str(&format!("  {{ {}, {} }},\n", c_string(class.name), c_string(class.file)));
    }
    out.push_str("};\n");
    out.push_str("static const char *axis_sim_file_of(const char *kind) {\n");
    out.push_str("  for (size_t i = 0; kind && i < sizeof AXIS_SIM_REG_FILES / sizeof AXIS_SIM_REG_FILES[0]; ++i) {\n");
    out.push_str("    if (!strcmp(AXIS_SIM_REG_FILES[i].kind, kind)) { return AXIS_SIM_REG_FILES[i].file; }\n  }\n  return 0;\n}\n");
    out.push_str("static int32_t axis_sim_rename_pool(const axis_sim_core *core, const char *kind) {\n");
    out.push_str("  if (!core->rename_count || !kind) { return -1; }\n");
    out.push_str("  const char *file = 0;\n");
    out.push_str("  for (size_t i = 0; i < sizeof AXIS_SIM_REG_FILES / sizeof AXIS_SIM_REG_FILES[0]; ++i) {\n");
    out.push_str("    if (!strcmp(AXIS_SIM_REG_FILES[i].kind, kind)) { file = AXIS_SIM_REG_FILES[i].file; break; }\n  }\n");
    out.push_str("  if (!file) { return -1; }\n");
    out.push_str("  for (int32_t p = 0; p < core->rename_count && p < (int32_t)AXIS_SIM_RENAME_POOLS; ++p) {\n");
    out.push_str("    if (!strcmp(core->rename[p].file, file)) { return p; }\n  }\n");
    out.push_str("  return -1;\n}\n\n");
    out.push_str("/* ⚠️ One instruction-cache lookup: 1 on a miss, which also brings the line\n   in over the least recently used way. The data cache's geometry and LRU, in\n   a separate array -- a unified cache would put a loop's own lines in\n   competition with its data, which §7d says is a worse measurement. */\n");
    out.push_str("static int axis_ic_touch(axis_pack_machine *m, uint64_t line) {\n");
    out.push_str("  const axis_sim_cache *c = &m->core->icache;\n");
    out.push_str("  uint32_t lines = c->lines < AXIS_SIM_ICACHE_LINES ? c->lines : AXIS_SIM_ICACHE_LINES;\n");
    out.push_str("  uint32_t ways = c->ways ? c->ways : 1u;\n  if (ways > lines) { ways = lines; }\n");
    out.push_str("  uint32_t sets = ways ? lines / ways : 0u;\n  if (!sets) { return 0; }\n");
    out.push_str("  uint32_t base = (uint32_t)(line % sets) * ways;\n  m->ic_clock++;\n");
    out.push_str("  for (uint32_t w = 0; w < ways; ++w) {\n");
    out.push_str("    if (m->ic_valid[base + w] && m->ic_tag[base + w] == line) { m->ic_used[base + w] = m->ic_clock; return 0; }\n  }\n");
    out.push_str("  uint32_t victim = base;\n");
    out.push_str("  for (uint32_t w = 0; w < ways; ++w) {\n");
    out.push_str("    if (!m->ic_valid[base + w]) { victim = base + w; break; }\n");
    out.push_str("    if (m->ic_used[base + w] < m->ic_used[victim]) { victim = base + w; }\n  }\n");
    out.push_str("  m->ic_valid[victim] = 1;\n  m->ic_tag[victim] = line;\n  m->ic_used[victim] = m->ic_clock;\n  m->ic_ready[victim] = 0u;\n  return 1;\n}\n\n");
    out.push_str(r#"/* ⚠️ A LINE ON ITS WAY (D4). A miss brings a line in, and the line is not
   there until the cache's latency has passed -- whoever asked for it. Fetch
   that missed and was then sent elsewhere (a squash, or decode finding a
   branch) leaves the fill running: the program, coming to that line before
   it lands, waits for what is left of it rather than finding it "simply
   there", and does not miss -- the line was asked for already. `axis_ic_fill`
   says when a line just missed arrives; `axis_ic_ready` when a line the
   cache holds does, 0 for one that has. A wrong path fetched in line order
   or run in the shadow (O11, O12) says nothing, and its lines are there at
   once, as before. */
static int32_t axis_ic_way(const axis_pack_machine *m, uint64_t line) {
  const axis_sim_cache *c = &m->core->icache;
  uint32_t lines = c->lines < AXIS_SIM_ICACHE_LINES ? c->lines : AXIS_SIM_ICACHE_LINES;
  uint32_t ways = c->ways ? c->ways : 1u;
  if (ways > lines) { ways = lines; }
  uint32_t sets = ways ? lines / ways : 0u;
  if (!sets) { return -1; }
  uint32_t base = (uint32_t)(line % sets) * ways;
  for (uint32_t w = 0; w < ways; ++w) {
    if (m->ic_valid[base + w] && m->ic_tag[base + w] == line) { return (int32_t)(base + w); }
  }
  return -1;
}
static void axis_ic_fill(axis_pack_machine *m, uint64_t line, uint64_t when) {
  int32_t at = axis_ic_way(m, line);
  if (at >= 0) { m->ic_ready[at] = when; }
}
static uint64_t axis_ic_ready(const axis_pack_machine *m, uint64_t line) {
  int32_t at = axis_ic_way(m, line);
  return at >= 0 ? m->ic_ready[at] : 0u;
}
static uint64_t axis_fe_decode_fetch(axis_pack_machine *m, uint64_t from, uint64_t start, uint32_t cycles);

"#);
    out.push_str("/* ⚠️ FORK, RUN, DISCARD (O12). The functional state -- registers, state\n   slots, pc, step count, status -- is copied; the simulator runs from where\n   the prediction pointed with its stores buffered and its traps swallowed;\n   each instruction it completes leaves its pc and its accesses in the trace;\n   and the copy is put back, exactly. At most what the machine can hold in\n   flight is run: the fetch buffer and the reorder buffer, full of wrong-path\n   work, are where fetch stops. An instruction that would trap, or does not\n   decode, ends the run without being recorded -- on the wrong path it never\n   happened, and neither does anything after it. */\n");
    out.push_str("static void axis_sim_run_shadow(axis_pack_machine *m, uint64_t start);\n\n");
    out.push_str("/* ⚠️ THE EXECUTED WRONG PATH, as far as the machine got before its branch\n   resolved: its own control flow through the instruction cache, its loads\n   and stores through the data cache. Touched, never charged -- the redirect\n   is what it cost -- and not counted among the cache's hits and misses, which\n   stay the path that retired.\n\n   ⚠️ Called BEFORE the next correct-path instruction runs. Consumed at the\n   redirect instead -- inside that instruction's accounting -- its functional\n   step had already touched the cache, so the wrong path could neither\n   prefetch for it nor pollute ahead of it: the right lines, in the wrong\n   order. Ticking to the branch's resolution here is timing only; the\n   redirect then finds it resolved. */\n");
    out.push_str("static void axis_sim_consume_wrong_path(axis_pack_machine *m);\n\n");
    out.push_str("/* Dispatch in program order, and tick until there is room to do it. */\n");
    out.push_str("static uint32_t axis_ooo_dep_slot(axis_pack_machine *m, const axis_lift_entry *entry, const axis_lifted *lifted, int32_t o);\n");
    out.push_str("static int32_t axis_x_lane_slots(axis_pack_machine *m, uint32_t word, const axis_lift_entry *entry, int32_t writes, const uint32_t *have, int32_t have_count, uint32_t *out, int32_t max);\n");
    out.push_str("static int32_t axis_ooo_reads(axis_pack_machine *m, const axis_lift_entry *entry, int32_t o);\n");
    out.push_str("static void axis_x_width(axis_pack_machine *m, axis_sim_rob_entry *e, uint32_t word, const axis_lift_entry *entry, const axis_lifted *lifted);\n");
    out.push_str("static int32_t axis_ooo_implicit_reads(axis_pack_machine *m, const axis_lift_entry *entry, uint32_t *slot, int32_t max);\n");
    out.push_str("typedef struct axis_sim_crack axis_sim_crack;\n");
    out.push_str(CRACK_TYPES_C);
    out.push_str("static const axis_sim_crack *axis_sim_crack_of(const axis_pack_machine *m, const axis_lift_entry *entry);\n");
    // U2: each core's micro-op cache and loop buffer, beside the core table
    // rather than in it, so the pack ABI does not move.
    out.push_str("static const uint32_t AXIS_SIM_CORE_FE2[][8] = {\n");
    for core in &document.cores {
        let fe = core.front_end.as_ref();
        let oc = fe.and_then(|f| f.op_cache.as_ref());
        let lb = fe.and_then(|f| f.loop_buffer.as_ref());
        out.push_str(&format!(
            "  {{ {}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u }},\n",
            oc.map_or(0, |o| o.entries),
            oc.map_or(0, |o| o.ways),
            oc.map_or(0, |o| o.window),
            oc.map_or(0, |o| o.width),
            oc.map_or(0, |o| o.depth),
            lb.map_or(0, |l| l.ops),
            lb.map_or(0, |l| l.width),
            lb.map_or(0, |l| l.depth)
        ));
    }
    out.push_str("  { 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u }\n};\n");
    // FQ1: how many lines each core's predictor names ahead of fetch --
    // beside the core table too.
    out.push_str("static const uint32_t AXIS_SIM_CORE_TQ[] = {");
    for core in &document.cores {
        out.push_str(&format!(" {}u,", core.front_end.as_ref().map_or(0, |f| f.target_queue)));
    }
    out.push_str(" 0u };\n");
    out.push_str(TARGET_QUEUE_C);
    out.push_str(FRONT2_C);
    out.push_str("static axis_sim_rob_entry *axis_sim_dispatch_cracked(axis_pack_machine *m, const axis_lift_entry *entry, const axis_lifted *lifted, const axis_sim_crack *crack);\n");
    out.push_str("static int32_t axis_ooo_implicit_writes(axis_pack_machine *m, const axis_lift_entry *entry, uint32_t *slot, int32_t *pool, int32_t max);\n");
    out.push_str(FUSE_TRACE_C);
    out.push_str("static void axis_sim_account_pipeline(axis_pack_machine *m, const axis_lift_entry *entry,\n");
    out.push_str("                                 const axis_lifted *lifted) {\n");
    out.push_str("  const axis_sim_core *core = m->core;\n");
    out.push_str("  uint32_t rob = axis_ooo_rob(core);\n");
    out.push_str("  uint32_t queue = core->issue_queue ? core->issue_queue : rob;\n");
    out.push_str("  uint32_t width = axis_disp_width(m);\n");
    out.push_str("  /* ⚠️ A mispredict resolves when the branch COMPLETES, and what follows\n     it could not have been fetched until then plus the refill. Ticking the\n     branch to completion here is the squash: the front end really did stop. */\n");
    out.push_str("  /* ⚠️ Only once the branch itself is IN the window. The prediction runs\n     before dispatch, so on the branch's own dispatch `redirect_seq` names an\n     entry that does not exist yet -- and a redirect charged to the branch\n     that caused it is a redirect charged one instruction too early. */\n");
    out.push_str("  /* ⚠️ A DECLARED FRONT END (O6): the instruction is fetched in a group of\n     at most `fetch_width`, a new group after a taken branch or a full one,\n     and cannot dispatch until `fe_depth` cycles after it was fetched. A\n     mispredict restarts fetch when the branch resolves, so its refill is the\n     depth -- a number the pipeline produces, where the flat penalty below is\n     one a designer typed. */\n");
    out.push_str("  if (core->fe) {\n");
    out.push_str("    uint32_t fw = core->fetch_width ? core->fetch_width : 1u;\n");
    out.push_str("    if (m->fe_redirect_seq != AXIS_SIM_NO_SEQ) {\n");
    out.push_str("      axis_sim_rob_entry *b = axis_ooo_find(m, m->fe_redirect_seq);\n");
    out.push_str("      while (b && (!b->issued || b->complete > m->now)) { axis_ooo_tick(m); b = axis_ooo_find(m, m->fe_redirect_seq); }\n");
    out.push_str("      /* ⚠️ THE WRONG PATH (O11). From the branch's own fetch until now the\n         front end was fetching where the prediction said, `fetch_width` a\n         cycle and in line order -- instructions that will never run, from\n         lines that are now in the cache all the same. Touched, not charged:\n         their cost was the stall the redirect already is. */\n");
    out.push_str("      if (m->wp_armed && core->icache.lines) {\n");
    out.push_str("        uint32_t lb = core->icache.line_bytes ? core->icache.line_bytes : 64u;\n");
    out.push_str("        uint64_t window = m->now > m->fe_redirect_fetch ? m->now - m->fe_redirect_fetch : 0u;\n");
    out.push_str("        uint64_t first = m->wp_start / lb;\n");
    out.push_str("        /* ⚠️ BOUNDED by what the machine can hold: the front end's buffer and\n           the window behind it fill with wrong-path instructions and fetch\n           stops. A first version fetched for the whole resolution delay and\n           ran seven lines down a path the machine could hold two of. */\n");
    out.push_str("        uint64_t can_hold = (core->fe_buffer ? core->fe_buffer : (uint64_t)fw * (core->fe_depth + 1u)) + axis_ooo_rob(core);\n");
    out.push_str("        uint64_t fetched = window * fw;\n        if (fetched > can_hold) { fetched = can_hold; }\n");
    out.push_str("        uint64_t last = (m->wp_start + fetched * 4u + lb - 1u) / lb;\n");
    out.push_str("        if (last > first + AXIS_SIM_ICACHE_LINES) { last = first + AXIS_SIM_ICACHE_LINES; }\n");
    out.push_str("        for (uint64_t line = first; line < last; ++line) { axis_ic_touch(m, line); axis_tlb_touch(m, 1, line * lb); m->wrong_path_lines++; }\n");
    out.push_str("      }\n");
    out.push_str("      m->wpx_armed = 0;\n      m->oc_have = 0;\n");
    out.push_str("      m->wp_armed = 0;\n      m->ic_have_line = 0;\n      m->it_have = 0;\n      axis_tq_reset(m);\n");
    out.push_str("      m->fetch_cycle = m->now + core->branch_penalty;\n");
    out.push_str("      m->fe_restart = 1;\n      m->fe_group_break = 0;\n      m->fe_bubble = 0;\n");
    out.push_str("      m->front_end_stalls += core->branch_penalty + core->fe_depth;\n");
    out.push_str("      m->fe_redirect_seq = AXIS_SIM_NO_SEQ;\n    }\n");
    out.push_str("    /* ⚠️ THE PATH it comes by (U2): decoded, from the micro-op cache, or\n       from the loop buffer -- and so how many of it make a group, counted\n       in what, and how far it is from dispatch. */\n");
    out.push_str("    int32_t path = axis_fe_path(m, m->step_pc);\n    uint32_t ops = path ? axis_fe_ops(m, entry) : 1u;\n");
    out.push_str("    uint32_t group = path == 2 ? m->lb_width : (path == 1 ? m->oc_width : fw);\n");
    out.push_str("    uint32_t stages = path == 2 ? m->lb_depth : (path == 1 ? m->oc_depth : core->fe_depth);\n");
    out.push_str("    if (path == 1) { m->op_cache_ops += ops; } else if (path == 2) { m->loop_buffer_ops += ops; }\n");
    out.push_str("    uint64_t f;\n");
    out.push_str("    if (m->fe_restart || m->fe_count == 0u) { f = m->fetch_cycle; m->fetched_in_group = 0; }\n");
    out.push_str("    else if (m->fe_group_break || path != m->fe_path || m->fetched_in_group + ops > group) {\n");
    out.push_str("      f = m->fetch_cycle + 1u + m->fe_bubble;\n      m->fetched_in_group = 0;\n    }\n");
    out.push_str("    else { f = m->fetch_cycle; }\n");
    out.push_str("    int32_t restarted = m->fe_restart || m->fe_count == 0u;\n");
    out.push_str("    m->fe_restart = 0;\n    m->fe_group_break = 0;\n    m->fe_bubble = 0;\n    m->fe_path = path;\n");
    out.push_str("    /* ⚠️ A NEW LINE is a new fetch group -- a fetch reads one line -- and a\n       lookup, which on a miss holds this fetch for the cache's latency. */\n");
    out.push_str("    /* ⚠️ A NEW PAGE is a lookup in the fetch TLB before the line can be\n       asked for: what it costs holds this fetch, ahead of the cache. */\n");
    out.push_str("    if (!path && core->tlb.fetch_entries) {\n");
    out.push_str("      uint64_t page = m->step_pc / (core->tlb.page_bytes ? core->tlb.page_bytes : 4096u);\n");
    out.push_str("      if (!m->it_have || page != m->it_page) {\n");
    out.push_str("        uint64_t walk_asked = m->pending_walk;\n        uint64_t walk = axis_tlb_lookup(m, 1, m->step_pc);\n        m->tq_new_page = 1;\n");
    out.push_str("        /* Fetch's walk needs a walker too (TLB2), from the cycle it is asked. */\n");
    out.push_str("        walk += axis_walker_take(m, f, m->pending_walk - walk_asked);\n        m->pending_walk = walk_asked;\n");
    out.push_str("        if (walk) {\n");
    out.push_str("          if (!restarted && f == m->fetch_cycle && m->fetched_in_group) { f = m->fetch_cycle + 1u; }\n");
    out.push_str("          f += walk;\n          m->fetched_in_group = 0;\n        }\n");
    out.push_str("        m->it_page = page;\n        m->it_have = 1;\n      }\n    }\n");
    out.push_str("    if (!path && core->icache.lines) {\n");
    out.push_str("      uint32_t lb = core->icache.line_bytes ? core->icache.line_bytes : 64u;\n");
    out.push_str("      uint64_t line = m->step_pc / lb;\n");
    out.push_str("      if (!m->ic_have_line || line != m->ic_line) {\n");
    out.push_str("        if (!restarted && f == m->fetch_cycle && m->fetched_in_group) { f = m->fetch_cycle + 1u; m->fetched_in_group = 0; }\n");
    out.push_str("        /* ⚠️ NAMED AHEAD (FQ1): a core whose predictor runs ahead of fetch\n           asked for this line when it named it. What is left of the fill\n           holds this fetch, and a line asked for ahead is no miss of\n           fetch's. A core with no queue names the line as it arrives. */\n");
    out.push_str("        uint64_t named = axis_tq_named(m, f);\n");
    out.push_str("        if (axis_ic_touch(m, line)) {\n          uint64_t ready = named + core->icache.miss_cycles;\n          if (named == f) { m->icache_misses++; }\n");
    out.push_str("          if (ready > f) { f = ready; m->fetched_in_group = 0; }\n          axis_ic_fill(m, line, ready);\n        }\n");
    out.push_str("        /* ⚠️ Held, and not here yet (D4): asked for while decode looked at\n           a branch, and still on its way. What is left of the fill holds\n           this fetch; it is not a miss. */\n");
    out.push_str("        else if (axis_ic_ready(m, line) > f) { f = axis_ic_ready(m, line); m->fetched_in_group = 0; }\n");
    out.push_str("        axis_tq_took(m, named, f);\n");
    out.push_str("        m->ic_line = line;\n        m->ic_have_line = 1;\n      }\n    }\n");
    out.push_str("    /* ⚠️ THE BUFFER: fetch cannot run further ahead of dispatch than the\n       front end holds. Undeclared, it holds the stages and no more. */\n");
    out.push_str("    uint64_t hold = core->fe_buffer ? core->fe_buffer : (uint64_t)fw * (core->fe_depth + 1u);\n");
    out.push_str("    if (hold > AXIS_SIM_FE_MAX) { hold = AXIS_SIM_FE_MAX; }\n");
    out.push_str("    if (m->fe_count >= hold) {\n");
    out.push_str("      uint64_t freed = m->fe_dispatched[(m->fe_count - hold) % AXIS_SIM_FE_MAX];\n");
    out.push_str("      if (freed > f) { f = freed; m->fetched_in_group = 0; }\n    }\n");
    out.push_str("    m->fetch_cycle = f;\n    m->fetched_in_group += ops;\n");
    out.push_str("    while (m->now < f + stages) { axis_ooo_tick(m); }\n");
    out.push_str("  }\n");
    out.push_str("  else if (m->redirect_cycles) {\n");
    out.push_str("    axis_sim_rob_entry *b = axis_ooo_find(m, m->redirect_seq);\n");
    out.push_str("    while (b && (!b->issued || b->complete > m->now)) { axis_ooo_tick(m); b = axis_ooo_find(m, m->redirect_seq); }\n");
    out.push_str("    uint64_t resume = m->now + m->redirect_cycles;\n");
    out.push_str("    m->front_end_stalls += m->redirect_cycles;\n");
    out.push_str("    while (m->now < resume) { axis_ooo_tick(m); }\n");
    out.push_str("    m->redirect_cycles = 0;\n    m->redirect_seq = AXIS_SIM_NO_SEQ;\n  }\n");
    out.push_str("  /* ⚠️ CRACKED (U1): an instruction this core divides into micro-ops is\n     dispatched as that many entries, each its own. Everything from here to\n     the arming below is one entry's dispatch, and is theirs instead. */\n");
    out.push_str("  axis_sim_rob_entry *e = 0;\n  const axis_sim_crack *crack = axis_sim_crack_of(m, entry);\n");
    out.push_str("  if (crack) { e = axis_sim_dispatch_cracked(m, entry, lifted, crack); }\n  else {\n");
    out.push_str("  /* ⚠️ A MOVE DONE AT RENAME (ME1) waits for an entry and for nothing else:\n     not a slot of the issue queue or of its unit's, not a register. */\n  int32_t elim = axis_move_at_rename(m, entry, lifted);\n");
    out.push_str("  /* ⚠️ THE TAIL OF A FUSED PAIR (FU1) is not an operation of its own: no\n     entry, no slot of any width, no queue, no unit. It is here, following\n     its head, as a move follows what it read. */\n  axis_sim_rob_entry *fuse_head = axis_fuse_trace(m, entry, lifted);\n  int32_t absorb = fuse_head != 0 && m->fz_absorb;\n  uint32_t pair_latency = m->fz_latency;\n  int32_t fuse = fuse_head != 0 && !absorb;\n  if (fuse) { elim = 1; axis_fuse_take(m, fuse_head); }\n  /* FU2: the head follows, and this load is the pair. */\n  if (absorb) { axis_fuse_absorb(m, fuse_head); }\n  int32_t zero = (fuse || elim) ? 0 : axis_zero_at_rename(m, entry, lifted);\n  if (zero) { elim = 1; }\n");
    out.push_str("  /* ⚠️ BACKPRESSURE, which the in-order model has no way to express: a\n     full reorder buffer stops dispatch however ready the instruction is,\n     and a full issue queue does the same. This is where window size turns\n     into cycles. */\n");
    out.push_str("  while (!fuse && axis_rob_full(m, rob, 1u)) { axis_ooo_tick(m); }\n");
    out.push_str("  for (;;) {\n");
    out.push_str("    uint32_t waiting = 0;\n");
    out.push_str("    for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {\n");
    out.push_str("      axis_sim_rob_entry *e = &m->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("      if (e->valid && !e->issued && !e->elim) { waiting++; }\n    }\n");
    out.push_str("    if (elim || waiting < queue) { break; }\n    axis_ooo_tick(m);\n  }\n");
    out.push_str("  if (m->now > m->dispatch_cycle) { m->dispatch_cycle = m->now; m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0; }\n");
    out.push_str("  int32_t is_load = 0, is_store = 0;\n");
    out.push_str("  for (int32_t a = 0; a < m->acc_count; ++a) { if (m->acc_write[a]) { is_store = 1; } else { is_load = 1; } }\n");
    out.push_str("  /* ⚠️ The QUEUES are backpressure like the buffer is: a load with no\n     load-queue entry cannot dispatch however ready it is. A store holds its\n     entry until it retires; draining to the cache after that is instant\n     here, and a machine whose store buffer backs up is not this one. */\n");
    out.push_str("  if (core->lsq && (is_load || is_store)) {\n");
    out.push_str("    for (;;) {\n");
    out.push_str("      uint32_t loads = 0, stores = 0;\n");
    out.push_str("      for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {\n");
    out.push_str("        const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];\n");
    out.push_str("        if (!o->valid) { continue; }\n");
    out.push_str("        loads += o->is_load ? 1u : 0u;\n        stores += o->is_store ? 1u : 0u;\n      }\n");
    out.push_str("      int full = (is_load && core->load_queue && loads >= core->load_queue)\n");
    out.push_str("              || (is_store && core->store_queue && stores >= core->store_queue);\n");
    out.push_str("      if (!full) { break; }\n      axis_ooo_tick(m);\n    }\n  }\n");
    out.push_str("  /* ⚠️ And a WRITE needs a free physical register, which it does not\n     get back until it retires. What limits a machine that renames is how\n     many results it can hold in flight, not how many registers its ISA\n     names -- a write to the zero register holds none. */\n");
    out.push_str("  int32_t want_pool[AXIS_SIM_OOO_DST];\n  uint32_t want_slot[AXIS_SIM_OOO_DST];\n  int32_t want = 0;\n");
    out.push_str("  for (int32_t o = 0; o < entry->operand_count && want < (int32_t)AXIS_SIM_OOO_DST; ++o) {\n");
    out.push_str("    const axis_lift_operand *operand = &entry->operands[o];\n");
    out.push_str("    if (!operand->role || ((operand->role_code != AXIS_ROLE_OUT) && (operand->role_code != AXIS_ROLE_INOUT))) { continue; }\n");
    out.push_str("    const axis_reg_class *rules = axis_op_class(operand);\n");
    out.push_str("    if (!rules) { continue; }\n");
    out.push_str("    uint32_t at = axis_ooo_dep_slot(m, entry, lifted, o);\n");
    out.push_str("    if (at >= AXIS_SIM_PRODUCERS) { continue; }\n");
    out.push_str("    int32_t pool = -1;\n");
    out.push_str("    if (at < AXIS_SIM_REG_SLOTS && !(rules->zero_index >= 0 && lifted->operands[o] == (uint64_t)rules->zero_index)) {\n");
    out.push_str("      pool = axis_sim_rename_pool(core, operand->kind);\n    }\n");
    out.push_str("    want_slot[want] = at;\n    want_pool[want++] = pool;\n  }\n");
    out.push_str("  /* ⚠️ And what no operand names (A64-2): state it writes, and a fixed\n     register -- each a destination, the fixed one from its pool. */\n");
    out.push_str("  uint32_t implicit_slot[AXIS_SIM_OOO_DST];\n");
    out.push_str("  int32_t implicit = axis_ooo_implicit_writes(m, entry, implicit_slot, want_pool + want, (int32_t)AXIS_SIM_OOO_DST - want);\n");
    out.push_str("  int32_t explicit_writes = want;\n  for (int32_t d = 0; d < implicit; ++d) { want_slot[want + d] = implicit_slot[d]; }\n  want += implicit;\n  int32_t renames = axis_fuse_renames(fuse_head, elim || absorb, want_slot, want_pool, want);\n");
    out.push_str("  for (;;) {\n");
    out.push_str("    uint32_t need[AXIS_SIM_RENAME_POOLS] = {0};\n    int short_of = 0;\n");
    out.push_str("    for (int32_t d = 0; d < want; ++d) { if (want_pool[d] >= 0) { need[want_pool[d]]++; } }\n");
    out.push_str("    for (int32_t p = 0; p < core->rename_count && p < (int32_t)AXIS_SIM_RENAME_POOLS; ++p) {\n");
    out.push_str("      if (need[p] && m->rename_used[p] + need[p] > core->rename[p].extra) { short_of = 1; }\n    }\n");
    out.push_str("    /* A write the pool could never satisfy -- more destinations than the\n       machine has spare registers -- is let through rather than waited for\n       forever, once nothing else is in flight to give one back. */\n");
    out.push_str("    if (!short_of || m->rob_head == m->rob_tail) { break; }\n    axis_ooo_tick(m);\n  }\n");
    out.push_str("  if (m->now > m->dispatch_cycle) { m->dispatch_cycle = m->now; m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0; }\n");
    out.push_str("  /* ⚠️ ITS UNIT'S OWN QUEUE (S2): full, and it does not enter -- nor does\n     anything behind it. */\n");
    out.push_str("  {\n    int32_t bound = -1;\n    const char *bname = elim ? 0 : axis_sim_unit_on(core, entry);\n");
    out.push_str("    for (int32_t u = 0; bname && bname[0] && u < core->unit_count; ++u) {\n      if (!strcmp(core->units[u].name, bname)) { bound = u; break; }\n    }\n");
    out.push_str("    while (axis_unit_queue_full(m, bound)) { axis_ooo_tick(m); }\n  }\n");
    out.push_str("  if (m->now > m->dispatch_cycle) { m->dispatch_cycle = m->now; m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0; }\n");
    out.push_str("  while ((!fuse && !absorb && m->dispatched_this_cycle >= width) || axis_rename_full(m, (uint32_t)renames)) { axis_ooo_tick(m); m->dispatch_cycle = m->now; m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0; }\n");
    out.push_str("  e = &m->rob[m->rob_tail % AXIS_SIM_ROB_MAX];\n");
    out.push_str("  memset(e, 0, sizeof *e);\n");
    out.push_str("  e->is_load = is_load;\n  e->is_store = is_store;\n");
    out.push_str("  e->pc = m->step_pc;\n");
    out.push_str("  if (core->lsq && core->disambiguation == 3u && core->store_sets) {\n");
    out.push_str("    uint32_t n = core->store_sets < AXIS_SIM_SSIT_MAX ? core->store_sets : AXIS_SIM_SSIT_MAX;\n");
    out.push_str("    e->store_set = m->ssit[(uint32_t)((e->pc >> 2) % n)];\n  }\n");
    out.push_str("  /* A store names which of its operands its address comes from; one the\n     table does not know waits for every source, as a store did before. */\n");
    out.push_str("  const char *address = is_store ? axis_sim_store_address(entry) : 0;\n");
    out.push_str("  for (int32_t a = 0; a < m->acc_count && a < (int32_t)AXIS_SIM_OOO_MEM; ++a) {\n");
    out.push_str("    e->mem_lo[a] = m->acc_lo[a];\n    e->mem_hi[a] = m->acc_hi[a];\n    e->mem_count = a + 1;\n  }\n");
    out.push_str("  for (int32_t d = 0; d < AXIS_SIM_OOO_DST; ++d) { e->dst_pool[d] = -1; }\n");
    out.push_str("  e->seq = m->rob_tail;\n  e->valid = 1;\n  e->issued = 0;\n");
    out.push_str("  e->latency = axis_sim_latency_on(core, entry);\n  axis_x_width(m, e, m->step_word, entry, lifted);\n  /* The functional step has run: the register's value is what it was\n     BEFORE the step, kept then. */\n  if (e->len_kind == 2u) { e->len_kind = 1u; e->len_val = m->step_len; }\n");
    out.push_str("  e->stall = m->pending_stall;\n  m->pending_stall = 0;\n  e->walk = m->pending_walk;\n  m->pending_walk = 0;\n");
    out.push_str("  e->unit = -1;\n");
    out.push_str("  {\n    const char *uname = axis_sim_unit_on(core, entry);\n");
    out.push_str("    for (int32_t u = 0; uname && uname[0] && u < core->unit_count; ++u) {\n");
    out.push_str("      if (!strcmp(core->units[u].name, uname)) { e->unit = u; break; }\n    }\n  }\n");
    out.push_str("  if (elim) { e->unit = -1; e->elim = 1; m->elim_waiting++; }\n  if (fuse) { e->fused = 1; m->fuse_live++; }\n  if (absorb) { e->latency = pair_latency; }\n");
    out.push_str("  /* Which in-flight instructions this one is waiting for, and which\n     registers it will make other instructions wait for. */\n");
    out.push_str("  for (int32_t o = 0; o < entry->operand_count; ++o) {\n");
    out.push_str("    const axis_lift_operand *operand = &entry->operands[o];\n");
    out.push_str("    if (!operand->role || !axis_op_class(operand)) { continue; }\n");
    out.push_str("    uint32_t slot = axis_ooo_dep_slot(m, entry, lifted, o);\n");
    out.push_str("    if (slot >= AXIS_SIM_PRODUCERS) { continue; }\n");
    out.push_str("    if ((operand->role_code != AXIS_ROLE_OUT) || axis_ooo_reads(m, entry, o)) {\n");
    out.push_str("      /* A producer is waited for once (VM2): a compress names eight lanes of\n         two registers before its third. */\n");
    out.push_str("      int32_t seen = m->reg_producer[slot] == AXIS_SIM_NO_SEQ;\n");
    out.push_str("      for (int32_t k = 0; k < e->src_count && !seen; ++k) { seen = e->src_seq[k] == m->reg_producer[slot]; }\n");
    out.push_str("      if (!seen && e->src_count < AXIS_SIM_OOO_SRC) { e->src_seq[e->src_count++] = m->reg_producer[slot]; }\n");
    out.push_str("      if (is_store && (!address || axis_sim_names(address, operand->name))\n          && e->addr_src_count < AXIS_SIM_OOO_SRC) {\n");
    out.push_str("        e->addr_src_seq[e->addr_src_count++] = m->reg_producer[slot];\n      }\n    }\n");
    out.push_str("    if ((operand->role_code == AXIS_ROLE_OUT) || (operand->role_code == AXIS_ROLE_INOUT)) {\n");
    out.push_str("      if (e->dst_count < AXIS_SIM_OOO_DST) {\n        e->dst_pool[e->dst_count] = want_pool[e->dst_count];\n        e->dst_slot[e->dst_count++] = slot;\n      }\n    }\n  }\n");
    out.push_str("  {\n    uint32_t read_slot[AXIS_SIM_OOO_SRC];\n");
    out.push_str("    int32_t reads = axis_ooo_implicit_reads(m, entry, read_slot, (int32_t)AXIS_SIM_OOO_SRC);\n");
    out.push_str("    for (int32_t i = 0; i < reads && e->src_count < AXIS_SIM_OOO_SRC; ++i) { e->src_seq[e->src_count++] = m->reg_producer[read_slot[i]]; }\n");
    out.push_str("    for (int32_t i = 0; i < implicit && e->dst_count < AXIS_SIM_OOO_DST; ++i) {\n");
    out.push_str("      e->dst_pool[e->dst_count] = want_pool[explicit_writes + i];\n      e->dst_slot[e->dst_count++] = implicit_slot[i];\n    }\n  }\n");
    out.push_str("  /* ⚠️ And every OTHER lane's registers (VM2): the limbs and the registers\n     a vector word's first lane does not name. */\n");
    out.push_str("  {\n    uint32_t more[AXIS_SIM_OOO_SRC];\n");
    out.push_str("    int32_t n = axis_x_lane_slots(m, m->step_word, entry, 0, 0, 0, more, (int32_t)AXIS_SIM_OOO_SRC);\n");
    out.push_str("    /* Every slot every lane reads; a producer already waited for is not\n       waited for twice, or the first lane's own would fill the list. */\n");
    out.push_str("    for (int32_t i = 0; i < n && e->src_count < AXIS_SIM_OOO_SRC; ++i) {\n");
    out.push_str("      uint64_t from = m->reg_producer[more[i]];\n      int32_t seen = from == AXIS_SIM_NO_SEQ;\n");
    out.push_str("      for (int32_t k = 0; k < e->src_count && !seen; ++k) { seen = e->src_seq[k] == from; }\n");
    out.push_str("      if (!seen) { e->src_seq[e->src_count++] = from; }\n    }\n");
    out.push_str("    e->dst_count += axis_x_lane_slots(m, m->step_word, entry, 1, e->dst_slot, e->dst_count, e->dst_slot + e->dst_count, (int32_t)AXIS_SIM_OOO_DST - e->dst_count);\n  }\n");
    out.push_str("  /* A zero idiom waits for nothing (ZI1). */\n  if (zero) { e->src_count = 0; e->addr_src_count = 0; }\n");
    out.push_str("  for (int32_t d = 0; d < e->dst_count; ++d) { if (e->dst_pool[d] >= 0) { m->rename_used[e->dst_pool[d]]++; } }\n");
    out.push_str("  for (int32_t d = 0; d < e->dst_count; ++d) { m->reg_producer[e->dst_slot[d]] = e->seq; }\n");
    out.push_str(r#"  /* ⚠️ A LOAD'S VALUE, PREDICTED (S4), trace-driven. The functional step has
     run, so what the load read is in its register: right, and nothing waits
     for this entry; wrong, and the front end starts again once it has
     completed -- everything after it was running on a value never there. */
  if (m->vp_entries && core->fe && is_load && !is_store && e->dst_count == 1 && e->dst_slot[0] < AXIS_SIM_REG_SLOTS) {
    uint64_t read = m->sim.regs[e->dst_slot[0]], said = 0;
    if (axis_vp_predict(m, e->pc, &said)) {
      if (said == read) { e->vp = 1; m->value_predictions++; }
      else { m->value_mispredicts++; m->vp_flush = 1; }
    }
    axis_vp_train(m, e->pc, read);
  }
"#);
    out.push_str("  m->rob_tail++;\n  m->dispatched_this_cycle += (fuse || absorb) ? 0u : 1u;\n  m->renamed_this_cycle += (uint32_t)renames;\n  m->micro_ops += (fuse || absorb) ? 0u : 1u;\n  m->fz_seq = (elim || is_load || is_store) ? AXIS_SIM_NO_SEQ : e->seq;\n  m->fz_at = m->now;\n  m->fz_entry = entry;\n  }\n");
    out.push_str("  /* ⚠️ ARMED AFTER DISPATCH, and that ordering is the whole of it. The\n     prediction runs before dispatch, so arming there named an entry that\n     did not exist yet -- and the NEXT branch's prediction overwrote the\n     pending redirect before anything consumed it. Six mispredicting\n     branches charged one redirect between them, which is a plausible\n     number and the wrong one. */\n");
    out.push_str("  if (core->fe) {\n");
    out.push_str("    m->fe_dispatched[m->fe_count % AXIS_SIM_FE_MAX] = m->now;\n    m->fe_count++;\n");
    out.push_str("    if (m->fe_pending_mispredict) {\n      m->fe_redirect_seq = e->seq;\n      m->fe_redirect_fetch = m->fetch_cycle + m->fe_pending_delay;\n");
    out.push_str("      m->wp_armed = m->wp_pending;\n      m->wp_start = m->wp_pending_start;\n");
    out.push_str("      m->wpx_armed = m->wpx_pending;\n    }\n");
    out.push_str("    m->wp_pending = 0;\n    m->wpx_pending = 0;\n");
    out.push_str("    m->fe_group_break = m->fe_pending_break;\n    m->fe_bubble = m->fe_pending_bubble;\n");
    out.push_str("    /* A branch the predictor could not follow (FQ1): what it named past it is gone. */\n    if (m->fe_pending_bubble) { axis_tq_reset(m); }\n");
    out.push_str("    m->fe_pending_mispredict = 0;\n    m->fe_pending_break = 0;\n    m->fe_pending_bubble = 0;\n    m->fe_pending_delay = 0;\n");
    out.push_str("    /* ⚠️ WHILE DECODE LOOKED AT THIS BRANCH, fetch ran on (D2) -- from the\n       cycle after the branch's own fetch, which is known only now. */\n");
    out.push_str("    axis_lb_settle(m);\n");
    out.push_str("    /* A value predicted wrong (S4): fetch starts again behind this load. */\n");
    out.push_str("    if (m->vp_flush) {\n      m->fe_redirect_seq = e->seq;\n      m->fe_redirect_fetch = m->fetch_cycle;\n      m->wp_armed = 0;\n      m->wpx_armed = 0;\n      m->vp_flush = 0;\n      axis_tq_reset(m);\n    }\n");
    out.push_str("    if (m->fe_pending_d2) {\n      m->wrong_path_lines += axis_fe_decode_fetch(m, m->fe_pending_d2_from, m->fetch_cycle + 1u, m->fe_pending_d2);\n      m->fe_pending_d2 = 0;\n    }\n  }\n");
    out.push_str("  if (m->pending_redirect) {\n");
    out.push_str("    m->redirect_seq = e->seq;\n");
    out.push_str("    m->redirect_cycles = m->pending_redirect;\n");
    out.push_str("    m->pending_redirect = 0;\n  }\n}\n\n");
    out.push_str("/* ⚠️ The pipeline has to EMPTY before its cycle count means anything: the\n   last instructions dispatched have not retired, and a machine judged before\n   they do is a machine credited with work it has not finished. Draining is\n   simulation, not bookkeeping, so a count read mid-run is pessimistic by the\n   drain -- which is the honest direction to be wrong in. */\n");
    out.push_str("static void axis_ooo_drain(axis_pack_machine *m) {\n");
    out.push_str("  /* An execution-driven machine stops at its last commit: what is still in\n     its window was never part of the run. */\n");
    out.push_str("  if (!m->core || m->core->execute_driven) { return; }\n");
    out.push_str("  uint64_t guard = 0;\n");
    out.push_str("  while (m->rob_head < m->rob_tail && guard < 1000000u) { axis_ooo_tick(m); guard++; }\n}\n\n");
    out.push_str("static axis_sim_block *axis_sim_find(axis_pack_machine *m, uint64_t pc) {\n");
    out.push_str("  for (int32_t i = 0; i < m->block_count; ++i) {\n");
    out.push_str("    if (m->blocks[i].live && m->blocks[i].pc == pc) { return &m->blocks[i]; }\n  }\n");
    out.push_str("  for (int32_t i = 0; i < m->cold_count; ++i) {\n");
    out.push_str("    if (m->cold[i].live && m->cold[i].pc == pc) { return NULL; }\n  }\n");
    out.push_str("  axis_sim_block *built = axis_sim_build(m, pc);\n");
    out.push_str("  if (!built && m->cold && m->cold_count < m->options.blocks * 4) {\n");
    out.push_str("    m->cold[m->cold_count].pc = pc;\n    m->cold[m->cold_count].live = 1;\n");
    out.push_str("    m->cold_count++;\n  }\n");
    out.push_str("  return built;\n}\n\n");
    out.push_str(XMODE_C);
    out.push_str(WRONGPATH_C);
    out.push_str("static int32_t axis_sim_step_machine(void *machine) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n");
    out.push_str("  if (!m) { return AXIS_PACK_SIM_HALTED; }\n");
    out.push_str("  /* ⚠️ Counted on the INTERPRETED path only, and a host that wants\n     cycles does not enable the translator -- the same trade the retire hook\n     makes, and for the same reason: translated bytes call nothing, so there\n     is nothing to count them from. Saying so beats reporting a cycle figure\n     that silently stopped advancing. */\n");
    out.push_str("  if (!m->counting) { return (int32_t)axis_sim_step(&m->sim); }\n");
    out.push_str("  if (m->core && m->core->execute_driven && !(m->model && m->model_state)) { return axis_x_step(m); }\n");
    out.push_str("  /* ⚠️ Lifted before, accounted AFTER. What an instruction's memory\n     accesses cost is known only once it has made them, and charging the\n     scoreboard first gave every instruction the stall of the one before\n     it -- a program whose last load missed reported the penalty on the\n     instruction that followed, which is a plausible number and the wrong\n     one. */\n");
    out.push_str("  int32_t answered = 1;\n");
    out.push_str("  uint32_t word = m->host.fetch ? m->host.fetch(m->host.ctx, m->sim.pc, &answered) : 0u;\n");
    out.push_str("  axis_lifted lifted;\n");
    out.push_str("  int accountable = answered && axis_sim_lift(&m->sim, word, &lifted)\n                 && lifted.entry;\n");
    out.push_str("  uint64_t pc_before = m->sim.pc;\n");
    out.push_str("  if (m->core && m->core->fe && m->wpx_armed && m->fe_redirect_seq != AXIS_SIM_NO_SEQ) {\n");
    out.push_str("    axis_sim_consume_wrong_path(m);\n  }\n");
    out.push_str("  m->acc_count = 0;\n  m->pending_walk = 0;\n");
    out.push_str("  /* ⚠️ A length in a register (VU2) is read BEFORE the step: the\n     instruction may write the register it took its length from. */\n");
    out.push_str("  m->step_len = 0;\n");
    out.push_str("  if (m->core && accountable) {\n");
    out.push_str("    const axis_x_meta *xl = axis_x_meta_of(m, lifted.entry);\n");
    out.push_str("    if (xl->len_op1 && xl->op_class[xl->len_op1 - 1]) {\n");
    out.push_str("      uint32_t slot = axis_x_operand_slot(xl, lifted.entry, &lifted, xl->len_op1 - 1);\n");
    out.push_str("      if (slot < AXIS_SIM_REG_SLOTS) { m->step_len = m->sim.regs[slot]; }\n    }\n  }\n");
    out.push_str("  int32_t status = (int32_t)axis_sim_step(&m->sim);\n");
    out.push_str("  /* ⚠️ TAKEN, not merely a branch. A conditional branch that falls\n     through costs a machine with no predictor nothing at all -- the front\n     end was already fetching the right address -- so what matters is\n     whether the pc went somewhere other than the next instruction. Asking\n     the pc is the only way to know: whether a branch is taken is a fact\n     about the registers, not about the encoding. */\n");
    out.push_str("  if (m->core && accountable && lifted.entry->ends_block) {\n");
    out.push_str("    uint32_t bytes = lifted.entry->bits ? lifted.entry->bits / 8u : 4u;\n");
    out.push_str("    int32_t taken = m->sim.pc != pc_before + bytes;\n");
    out.push_str("    /* ⚠️ NO PREDICTOR is the predictor that always says \"not taken\", so\n       a machine without one is not a special case here -- it is the\n       degenerate configuration, and it mispredicts on exactly the taken\n       branches. That is what keeps the model that came before this a\n       configuration of the model that came after. */\n");
    out.push_str("    /* ⚠️ WHAT KIND OF BRANCH, for a machine with a front end (O9): whether\n       its direction is in question at all, whether its target is in a\n       register, and whether it is a call or a return -- all read off the\n       description, the last two through the ABI's link register. */\n");
    out.push_str("    int32_t conditional = 1, indirect = 0, is_call = 0, is_return = 0;\n");
    out.push_str("    /* Where the front end went instead, when this branch sends it wrong\n       and the trace can name the place: the fall-through of a branch guessed\n       not taken, or the target a return stack or target buffer predicted. */\n");
    out.push_str("    uint64_t wrong_start = 0;\n    int32_t wrong_known = 0;\n");
    out.push_str("    if (m->core->fe) { axis_sim_classify(lifted.entry, &lifted, &conditional, &indirect, &is_call, &is_return); }\n");
    out.push_str("    /* An UNCONDITIONAL jump is taken, and decode knows it: the direction\n       predictor is neither asked nor told. Only its target is in question. */\n");
    out.push_str("    int32_t consult = !m->core->fe || conditional;\n");
    out.push_str("    int32_t guess = consult ? ((m->pred && m->pred_state) ? (m->pred->predict(m->pred_state, pc_before) != 0) : 0) : 1;\n");
    out.push_str(r#"    /* ⚠️ OVERRIDDEN AT DECODE (D3). `guess` is the core's predictor, which
       speaks at decode; fetch followed the quick one. `over` is the cycles
       that cost when they disagreed and fetch had really gone elsewhere:
       on past a branch the quick one called not taken, or to the target the
       buffer holds for one it called taken -- with no target there was
       nowhere to go, and nothing to undo. An undeclared buffer holds every
       target, which for a direct branch is the one decode reads. */
    int32_t quick = guess;
    uint32_t over = 0;
    uint64_t quick_to = pc_before + bytes;
    if (consult && m->core->fe && m->quick_state) {
      quick = axis_quick_predict(m, pc_before);
      if (quick != guess) {
        if (!quick) { over = m->quick_cycles; }
        else if (m->core->btb) {
          uint32_t n = m->core->btb < AXIS_SIM_BTB_MAX ? m->core->btb : AXIS_SIM_BTB_MAX;
          uint32_t at = (uint32_t)((pc_before / (bytes ? bytes : 4u)) % n);
          if (m->btb_tag[at] == pc_before + 1u) { quick_to = m->btb_target[at]; over = m->quick_cycles; }
        }
        else if (!indirect) {
          axis_sim_target_fn find = axis_x_meta_of(m, lifted.entry)->direct;
          if (find && find(&lifted, pc_before, &quick_to)) { over = m->quick_cycles; }
        }
      }
    }
"#);
    out.push_str("    if (guess != taken) {\n");
    out.push_str("      m->mispredicts++;\n");
    out.push_str("      /* Where the front end went instead: the fall-through for a branch\n         wrongly guessed not taken. */\n");
    out.push_str("      if (!guess) { wrong_start = pc_before + bytes; wrong_known = 1; }\n");
    out.push_str("      /* ⚠️ GUESSED TAKEN, and it fell through (W1): the front end went to\n         the branch's TARGET, which the trace never saw -- the program did\n         not go there. The target buffer names it if it holds this branch;\n         otherwise, for a direct branch, DECODE does, from the word and the\n         address alone, `btb_penalty` after the fetch -- so that much later\n         is when the wrong path starts. An indirect branch with no entry went\n         nowhere but on, which is where the program went too. */\n");
    out.push_str("      else if (m->core->fe) {\n");
    out.push_str("        uint64_t to = 0;\n        int32_t have = 0;\n");
    out.push_str("        if (m->core->btb) {\n");
    out.push_str("          uint32_t n = m->core->btb < AXIS_SIM_BTB_MAX ? m->core->btb : AXIS_SIM_BTB_MAX;\n");
    out.push_str("          uint32_t at = (uint32_t)((pc_before / (bytes ? bytes : 4u)) % n);\n");
    out.push_str("          if (m->btb_tag[at] == pc_before + 1u) { to = m->btb_target[at]; have = 1; }\n        }\n");
    out.push_str("        if (!have && !indirect) {\n");
    out.push_str("          axis_sim_target_fn find = axis_x_meta_of(m, lifted.entry)->direct;\n");
    out.push_str("          if (find && find(&lifted, pc_before, &to)) {\n");
    out.push_str("            have = 1;\n            m->fe_pending_delay = m->core->btb ? m->core->btb_penalty : 0u;\n          }\n        }\n");
    out.push_str("        if (have) { wrong_start = to; wrong_known = 1; }\n      }\n");
    out.push_str("      if (m->core->fe && m->core->wrong_path_fetch && wrong_known) {\n");
    out.push_str("        m->wp_pending = 1;\n        m->wp_pending_start = wrong_start;\n      }\n");
    out.push_str("      if (m->core->fe) { m->fe_pending_mispredict = 1; }\n");
    out.push_str("      else { m->pending_redirect = m->core->branch_penalty; }\n    }\n");
    out.push_str("    /* ⚠️ A branch predicted TAKEN, and right: the next instruction comes\n       from elsewhere, so it is fetched in a new group -- and from where the\n       return stack or the target buffer says. A RETURN asks the stack. A\n       DIRECT branch the buffer misses costs `btb_penalty`, decode finding\n       the target in the word; an INDIRECT one it misses or gets wrong is\n       not known until the register is read, so it redirects at resolution\n       like any mispredict (O7, O9). */\n");
    out.push_str("    else if (taken && m->core->fe) {\n");
    out.push_str("      m->fe_pending_break = 1;\n");
    out.push_str("      if (is_return && m->core->ras) {\n");
    out.push_str("        uint64_t want = 0;\n");
    out.push_str("        if (m->ras_count) {\n          want = m->ras_stack[m->ras_top];\n");
    out.push_str("          m->ras_top = (m->ras_top + 63u) % 64u;\n          m->ras_count--;\n        }\n");
    out.push_str("        if (want != m->sim.pc) {\n");
    out.push_str("          m->mispredicts++;\n          m->target_mispredicts++;\n          m->fe_pending_mispredict = 1;\n");
    out.push_str("          /* ⚠️ NOWHERE TO GO BUT ON (W6): an empty stack predicts nothing,\n             so fetch ran past the return into what follows it. */\n");
    out.push_str("          wrong_start = want ? want : pc_before + bytes;\n          wrong_known = 1;\n        }\n      }\n");
    out.push_str("      else if (m->core->btb) {\n");
    out.push_str("        uint32_t n = m->core->btb < AXIS_SIM_BTB_MAX ? m->core->btb : AXIS_SIM_BTB_MAX;\n");
    out.push_str("        uint32_t at = (uint32_t)((pc_before / (bytes ? bytes : 4u)) % n);\n");
    out.push_str("        if (m->btb_tag[at] != pc_before + 1u || m->btb_target[at] != m->sim.pc) {\n");
    out.push_str("          m->btb_misses++;\n");
    out.push_str("          if (indirect) {\n            m->mispredicts++;\n            m->target_mispredicts++;\n            m->fe_pending_mispredict = 1;\n");
    out.push_str("            /* ⚠️ NOWHERE TO GO BUT ON (W6): a jump through a register that\n               the buffer does not hold is, to the front end, not a branch --\n               it fetched what follows until the jump executed. That is its\n               wrong path, as it is the execution-driven engine's. */\n");
    out.push_str("            wrong_start = m->btb_tag[at] == pc_before + 1u ? m->btb_target[at] : pc_before + bytes;\n            wrong_known = 1;\n          }\n");
    out.push_str("          else {\n            m->fe_pending_bubble = m->core->btb_penalty;\n");
    out.push_str("            /* ⚠️ And while decode looked, fetch ran on past the branch (D2)\n               -- on a machine that models its wrong path at all. */\n");
    out.push_str("            if (m->core->wrong_path_fetch || m->core->wrong_path_execute) {\n");
    out.push_str("              m->fe_pending_d2_from = pc_before + bytes;\n              m->fe_pending_d2 = m->core->btb_penalty;\n            }\n          }\n        }\n      }\n    }\n");
    out.push_str("    /* A CALL pushes where to come back to, whatever was predicted. */\n");
    out.push_str("    if (is_call && m->core->ras) {\n");
    out.push_str("      uint32_t depth = m->core->ras < 64u ? m->core->ras : 64u;\n");
    out.push_str("      m->ras_top = (m->ras_top + 1u) % 64u;\n      m->ras_stack[m->ras_top] = pc_before + bytes;\n");
    out.push_str("      if (m->ras_count < depth) { m->ras_count++; }\n    }\n");
    out.push_str("    if (taken && m->core->fe && m->core->btb) {\n");
    out.push_str("      uint32_t n = m->core->btb < AXIS_SIM_BTB_MAX ? m->core->btb : AXIS_SIM_BTB_MAX;\n");
    out.push_str("      uint32_t at = (uint32_t)((pc_before / (bytes ? bytes : 4u)) % n);\n");
    out.push_str("      m->btb_tag[at] = pc_before + 1u;\n      m->btb_target[at] = m->sim.pc;\n    }\n");
    out.push_str(r#"    /* ⚠️ WHAT THE OVERRIDE COST (D3). A branch the core's predictor got wrong
       sends fetch down its wrong path that much LATER -- decode had to speak
       first. One it got right is a redirect at decode: a new fetch group,
       `over` cycles on, and while decode looked fetch ran where the quick
       guess pointed, which is in the instruction cache now (D2). */
    if (over) {
      if (m->fe_pending_mispredict) { if (m->fe_pending_delay < over) { m->fe_pending_delay = over; } }
      else {
        m->fe_pending_break = 1;
        if (m->fe_pending_bubble < over) { m->fe_pending_bubble = over; }
        if (m->core->wrong_path_fetch || m->core->wrong_path_execute) {
          m->fe_pending_d2_from = quick_to;
          if (m->fe_pending_d2 < over) { m->fe_pending_d2 = over; }
        }
      }
    }
    if (consult) { axis_quick_train(m, pc_before, taken); }
    /* ⚠️ THE LOOP'S OWN BRANCH, FROM THE BUFFER (U2): the buffer wraps, so the
       branch ends no fetch group and nothing looks its target up. */
    if (m->lb_on && pc_before == m->lb_branch && taken && !m->fe_pending_mispredict) {
      m->fe_pending_break = 0;
      m->fe_pending_bubble = 0;
      m->fe_pending_d2 = 0;
    }
"#);
    out.push_str("    if (consult && m->pred && m->pred_state) { m->pred->update(m->pred_state, pc_before, taken); }\n");
    out.push_str("    /* ⚠️ FORK NOW, while the functional state is the branch's own: the\n       correct path's next instruction has not run yet. */\n");
    out.push_str("    if (wrong_known && m->core->fe && m->core->wrong_path_execute) {\n");
    out.push_str("      axis_sim_run_shadow(m, wrong_start);\n      m->wpx_pending = 1;\n    }\n");
    out.push_str("  }\n");
    out.push_str("  /* What the loop buffer learns from it (U2), branch or not. */\n");
    out.push_str("  if (m->core && m->core->fe && accountable) {\n    uint32_t lbytes = lifted.entry->bits ? lifted.entry->bits / 8u : 4u;\n");
    out.push_str("    axis_lb_saw(m, pc_before, axis_fe_ops(m, lifted.entry), lifted.entry->ends_block, m->sim.pc != pc_before + lbytes, m->sim.pc);\n  }\n");
    out.push_str("  /* ⚠️ Cleared AFTER, never before. A host that reports an access of\n     its own -- an accelerator sharing the cache -- does it between steps,\n     so a stall banked before the step is a cost this instruction owes.\n     Zeroing first threw exactly that away and charged nothing. An\n     instruction with nothing to account for still settles the bill,\n     or the stall would carry to the next one. */\n");
    out.push_str("  if (accountable) {\n");
    out.push_str("    /* ⚠️ A SELECTED core is a pipeline, in order or not. The analytical\n       scoreboard below is what a machine with NO core selected uses: a\n       cheaper, cruder model that reports when an issue slot frees rather\n       than when an instruction retires. The two are different models and\n       always were -- what changed is that a description no longer picks\n       one by accident. */\n");
    out.push_str("    /* ⚠️ The MODEL gets it, if there is one, and this library's pipeline\n       then does not run at all. Two models and one cycle count is a number\n       whose origin nobody can state. */\n");
    out.push_str("    if (m->model && m->model_state) {\n");
    out.push_str("      axis_uarch_event event;\n");
    out.push_str("      memset(&event, 0, sizeof event);\n");
    out.push_str("      event.mnemonic = lifted.entry->mnemonic;\n");
    out.push_str("      event.unit = axis_sim_unit_on(m->core, lifted.entry) ? axis_sim_unit_on(m->core, lifted.entry) : \"\";\n");
    out.push_str("      event.latency = axis_sim_latency_on(m->core, lifted.entry);\n");
    out.push_str("      event.throughput_milli = lifted.entry->throughput_milli;\n");
    out.push_str("      event.pc = pc_before;\n");
    out.push_str("      event.ends_block = lifted.entry->ends_block;\n");
    out.push_str("      uint32_t mbytes = lifted.entry->bits ? lifted.entry->bits / 8u : 4u;\n");
    out.push_str("      event.taken = m->sim.pc != pc_before + mbytes;\n");
    out.push_str("      event.memory_stall = m->pending_stall;\n      m->pending_stall = 0;\n");
    out.push_str("      for (int32_t o = 0; o < lifted.entry->operand_count; ++o) {\n");
    out.push_str("        const axis_lift_operand *operand = &lifted.entry->operands[o];\n");
    out.push_str("        if (!operand->role || !axis_op_class(operand)) { continue; }\n");
    out.push_str("        uint32_t slot = axis_operand_slot(operand, lifted.operands[o]);\n");
    out.push_str("        if ((operand->role_code != AXIS_ROLE_OUT) && event.read_count < AXIS_UARCH_MAX_REGS) {\n");
    out.push_str("          event.reads[event.read_count++] = slot;\n        }\n");
    out.push_str("        if (((operand->role_code == AXIS_ROLE_OUT) || (operand->role_code == AXIS_ROLE_INOUT))\n");
    out.push_str("            && event.write_count < AXIS_UARCH_MAX_REGS) {\n");
    out.push_str("          event.writes[event.write_count++] = slot;\n        }\n      }\n");
    out.push_str("      for (int32_t a = 0; a < m->acc_count && a < (int32_t)AXIS_UARCH_MAX_ACCESSES; ++a) {\n");
    out.push_str("        event.access_lo[a] = m->acc_lo[a];\n        event.access_hi[a] = m->acc_hi[a];\n");
    out.push_str("        event.access_write[a] = m->acc_write[a];\n        event.access_count = a + 1;\n      }\n");
    out.push_str("      m->model->account(m->model_state, &event);\n    }\n");
    out.push_str("    else if (m->core) { m->step_pc = pc_before; m->step_word = word; axis_sim_account_pipeline(m, lifted.entry, &lifted); }\n");
    out.push_str("    else { axis_sim_account(m, lifted.entry, &lifted); }\n  }\n");
    out.push_str("  else { m->pending_stall = 0; }\n");
    out.push_str("  return status;\n}\n");
    out.push_str("/* The mixed loop. A run of translatable instructions becomes one block;\n   the first instruction that is not -- a branch, a trap, anything with no\n   stencil -- is interpreted, and the loop goes round again. The two halves\n   share one register file and one memory, which is what makes them one\n   machine rather than two. */\n");
    out.push_str("static int32_t axis_sim_run_machine(void *machine, uint64_t limit) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n");
    out.push_str("  if (!m) { return AXIS_PACK_SIM_HALTED; }\n");
    out.push_str("  /* ⚠️ Counting means stepping. The fast path hands the whole run to\n     `axis_sim_run`, which never returns between instructions -- so a\n     scoreboard hung on the step wrapper saw nothing and reported zero\n     cycles for a program that plainly took some. A host that asked for\n     cycles has said it wants the slower loop. */\n");
    out.push_str("  if (!m->jit || !m->options.enabled) {\n");
    out.push_str("    if (!m->counting) { return (int32_t)axis_sim_run(&m->sim, limit); }\n");
    out.push_str("    m->x_limit = limit;\n");
    out.push_str("    while (m->sim.status == AXIS_SIM_RUNNING) {\n");
    out.push_str("      if (limit && m->sim.steps >= limit) {\n");
    out.push_str("        m->sim.status = AXIS_SIM_STEP_LIMIT;\n");
    out.push_str("        m->sim.halt_reason = \"step limit\";\n        break;\n      }\n");
    out.push_str("      axis_sim_step_machine(m);\n    }\n");
    out.push_str("    m->x_limit = 0;\n");
    out.push_str("    return (int32_t)m->sim.status;\n  }\n");
    out.push_str("  while (m->sim.status == AXIS_SIM_RUNNING) {\n");
    out.push_str("    if (limit && m->sim.steps >= limit) {\n");
    out.push_str("      m->sim.status = AXIS_SIM_STEP_LIMIT;\n      m->sim.halt_reason = \"step limit\";\n      break;\n    }\n");
    out.push_str("    axis_sim_block *block = axis_sim_find(m, m->sim.pc);\n");
    out.push_str("    /* ⚠️ A block is all-or-nothing, and the step limit is not. Running one\n       that would overshoot left the machine past the limit and at a different\n       pc than the interpreter -- the same program, stopped somewhere else.\n       The tail of a budget is interpreted. */\n");
    out.push_str("    if (block && limit && m->sim.steps + (uint64_t)block->count > limit) {\n");
    out.push_str("      block = NULL;\n    }\n");
    out.push_str("    if (block) {\n");
    out.push_str("      if (block->touches_state) { axis_sim_state_in(m); }\n");
    out.push_str("      ((void (*)(void))(uintptr_t)(m->code + block->at))();\n");
    out.push_str("      if (block->touches_state) { axis_sim_state_out(m); }\n");
    out.push_str("      /* ⚠️ Where the machine goes next is the LAST instruction's to\n         say. Every handler writes it into the scratch -- `pc + 4` when\n         nothing branches, the target when something does, a select when a\n         guard decides -- and a block that ends on a branch has that answer\n         sitting there. Adding `4 * count` instead was right only because\n         no block had ever ended on one. */\n");
    out.push_str("      if (block->ends_on_branch) {\n");
    out.push_str("        m->sim.pc = m->jit_word_bits == 32\n");
    out.push_str("                  ? (uint64_t)((const uint32_t *)m->scratch)[2]\n");
    out.push_str("                  : m->scratch[2];\n");
    out.push_str("      } else {\n");
    out.push_str("        m->sim.pc += (uint64_t)(4 * block->count);\n      }\n");
    out.push_str("      m->sim.steps += (uint64_t)block->count;\n");
    out.push_str("      m->translated += (uint64_t)block->count;\n");
    out.push_str("      continue;\n    }\n");
    out.push_str("    axis_sim_step(&m->sim);\n  }\n");
    out.push_str("  return (int32_t)m->sim.status;\n}\n");
    out.push_str("static int32_t axis_sim_enable_jit(void *machine, const axis_jit_pack *translator,\n                                  const axis_sim_jit *options) {\n");
    out.push_str("#if !AXIS_SIM_CAN_JIT\n  (void)machine; (void)translator; (void)options;\n  return 0;\n#else\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n");
    out.push_str("  if (!m || !translator || !options) { return 0; }\n");
    out.push_str("  /* ⚠️ A retire hook and translation do not go together: the emitted bytes\n     call nothing, so a translated run reports no events. Rather than give a\n     host a quieter trace than it asked for, this refuses. */\n");
    out.push_str("  if (m->host.retire) { return 0; }\n");
    out.push_str("  /* Asked, not assumed: the translator says how wide a scratch or state\n     slot is on this machine. */\n");
    out.push_str("  m->jit_word_bits = 64;\n");
    out.push_str("  for (int32_t i = 0; i < translator->count(); ++i) {\n");
    out.push_str("    if (translator->word_bits(i)) { m->jit_word_bits = translator->word_bits(i); break; }\n  }\n");
    out.push_str("  if (!options->enabled) { m->jit = NULL; return 1; }\n");
    out.push_str("  int32_t blocks = options->blocks > 0 ? options->blocks : AXIS_SIM_BLOCKS_DEFAULT;\n");
    out.push_str("  if (!m->code) {\n");
    out.push_str("    m->code = (uint8_t *)mmap(NULL, AXIS_SIM_CODE_BYTES, PROT_READ | PROT_WRITE,\n                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n");
    out.push_str("    if (m->code == MAP_FAILED) { m->code = NULL; return 0; }\n  }\n");
    out.push_str("  if (!m->blocks) {\n");
    out.push_str("    m->blocks = (axis_sim_block *)calloc((size_t)blocks, sizeof *m->blocks);\n");
    out.push_str("    if (!m->blocks) { return 0; }\n  }\n");
    out.push_str("  if (!m->cold) {\n");
    out.push_str("    /* Four times the blocks: a pc that cannot start a block is still a\n       pc, and a loop has more of those than it has blocks. Too small and\n       the machine keeps re-attempting what it has already refused. */\n");
    out.push_str("    m->cold = (axis_sim_cold *)calloc((size_t)blocks * 4, sizeof *m->cold);\n");
    out.push_str("    if (!m->cold) { return 0; }\n  }\n");
    out.push_str("  m->jit = translator;\n  m->options = *options;\n  m->options.blocks = blocks;\n");
    out.push_str("  return 1;\n#endif\n}\n");
    out.push_str("static uint64_t axis_sim_translated(const void *machine) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  return m ? m->translated : 0u;\n}\n");
    out.push_str("static void axis_sim_count_cycles(void *machine, int32_t on) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n");
    out.push_str("  if (!m) { return; }\n  m->counting = on;\n");
    out.push_str("  if (on) {\n    m->cycle = 0;\n    m->issue_free = 0;\n");
    out.push_str("    for (size_t i = 0; i < AXIS_SIM_REG_SLOTS; ++i) { m->ready[i] = 0; }\n  }\n}\n");
    // ⚠️ The cores the DESCRIPTION declares, emitted as a table a host picks
    // from by name. Not a runtime struct the host fills in, the way the cache
    // is: how many adders a core has is something the description says, and a
    // host that invented one would be quoting itself.
    out.push_str("#define AXIS_SIM_MODELS 8\n");
    out.push_str("static const axis_uarch_pack *AXIS_SIM_MODEL[AXIS_SIM_MODELS];\n");
    out.push_str("static int32_t AXIS_SIM_MODEL_COUNT;\n");
    out.push_str("static const axis_uarch_pack *axis_sim_model_for(const char *name) {\n");
    out.push_str("  if (!name || !name[0]) { return 0; }\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_SIM_MODEL_COUNT; ++i) {\n");
    out.push_str("    if (AXIS_SIM_MODEL[i] && AXIS_SIM_MODEL[i]->name\n        && !strcmp(AXIS_SIM_MODEL[i]->name, name)) { return AXIS_SIM_MODEL[i]; }\n  }\n  return 0;\n}\n");
    out.push_str("static void axis_sim_configure_cache(void *machine, const axis_sim_cache *cache);\n");
    out.push_str("static const axis_sim_unit AXIS_SIM_NO_UNITS[1] = { { \"\", 0u, 0u } };\n");
    for core in &document.cores {
        let ident = tablegen_ident(&core.name);
        if core.units.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "static const axis_sim_unit AXIS_SIM_UNITS_{ident}[] = {{\n"
        ));
        for unit in &core.units {
            out.push_str(&format!(
                "  {{ {}, {}u, {}u }},\n",
                c_string(&unit.name),
                unit.count.max(1),
                u32::from(unit.pipelined)
            ));
        }
        out.push_str("};\n");
        // VU1: the lanes each unit declares, beside the contract's unit table
        // rather than in it -- the pack ABI carries a unit's name, count and
        // whether it is pipelined, and this is the simulator's own.
        out.push_str(&format!(
            "static const uint32_t AXIS_SIM_UNIT_LANES_{ident}[] = {{ {} }};\n",
            core.units.iter().map(|unit| format!("{}u", unit.lanes)).collect::<Vec<_>>().join(", ")
        ));
        // VU2: and the operand each unit says carries the element count.
        out.push_str(&format!(
            "static const char *const AXIS_SIM_UNIT_LENGTH_{ident}[] = {{ {} }};\n",
            core.units
                .iter()
                .map(|unit| if unit.length.is_empty() { "0".to_string() } else { c_string(&unit.length) })
                .collect::<Vec<_>>()
                .join(", ")
        ));
        // VU4: what each unit costs when cores share it: transport, switch.
        out.push_str(&format!(
            "static const uint32_t AXIS_SIM_UNIT_COST_{ident}[][2] = {{ {} }};\n",
            core.units
                .iter()
                .map(|unit| format!("{{ {}u, {}u }}", unit.transport, unit.switch))
                .collect::<Vec<_>>()
                .join(", ")
        ));
        // W4: whether an operation in each unit is aborted at a squash.
        out.push_str(&format!(
            "static const uint8_t AXIS_SIM_UNIT_ABORT_{ident}[] = {{ {} }};\n",
            core.units.iter().map(|unit| format!("{}u", u32::from(unit.abort))).collect::<Vec<_>>().join(", ")
        ));
        // VU3: for each unit, which units lend it lanes -- a bit per unit.
        out.push_str(&format!(
            "static const uint32_t AXIS_SIM_UNIT_LENDERS_{ident}[] = {{ {} }};\n",
            core.units
                .iter()
                .map(|unit| {
                    let mask = core.units.iter().enumerate().fold(0u32, |mask, (index, lender)| {
                        let lends = index < 32
                            && lender.accepts.iter().any(|name| name.eq_ignore_ascii_case(&unit.name));
                        if lends { mask | (1u32 << index) } else { mask }
                    });
                    format!("{mask}u")
                })
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    for core in &document.cores {
        if core.ports.is_empty() {
            continue;
        }
        let ident = tablegen_ident(&core.name);
        let masks: Vec<String> = core
            .units
            .iter()
            .map(|unit| {
                let mask = core.ports.iter().enumerate().fold(0u32, |mask, (i, (_, units))| {
                    if units.iter().any(|u| u.eq_ignore_ascii_case(&unit.name)) {
                        mask | (1u32 << i)
                    } else {
                        mask
                    }
                });
                format!("{mask}u")
            })
            .collect();
        out.push_str(&format!(
            "static const uint32_t AXIS_SIM_UNIT_PORTS_{ident}[] = {{ {} }};\n",
            masks.join(", ")
        ));
    }
    for core in &document.cores {
        if core.predictor_params.is_empty() {
            continue;
        }
        let ident = tablegen_ident(&core.name);
        out.push_str(&format!("static const axis_sim_param AXIS_SIM_PREDICTOR_PARAMS_{ident}[] = {{\n"));
        for (key, value) in &core.predictor_params {
            out.push_str(&format!("  {{ {}, {value}u }},\n", c_string(key)));
        }
        out.push_str("};\n");
    }
    for core in &document.cores {
        if core.rename.is_empty() {
            continue;
        }
        let ident = tablegen_ident(&core.name);
        out.push_str(&format!(
            "static const axis_sim_rename AXIS_SIM_RENAME_{ident}[] = {{\n"
        ));
        for (file, extra) in &core.rename {
            // The file as the class table spells it, which is what the
            // lookup compares against; validation has already said it exists.
            let canonical = crate::ast::REGISTER_CLASSES
                .iter()
                .find(|class| class.file.eq_ignore_ascii_case(file))
                .map_or(file.as_str(), |class| class.file);
            out.push_str(&format!("  {{ {}, {extra}u }},\n", c_string(canonical)));
        }
        out.push_str("};\n");
    }
    out.push_str("static const axis_sim_core AXIS_SIM_CORES[] = {\n");
    for core in &document.cores {
        let ident = tablegen_ident(&core.name);
        let units = if core.units.is_empty() {
            "AXIS_SIM_NO_UNITS".to_string()
        } else {
            format!("AXIS_SIM_UNITS_{ident}")
        };
        // The core's memory, where it is a cache. A scratchpad has no line
        // size and becomes no cache here, which is what it is.
        let cache = document
            .memories
            .iter()
            .find(|memory| {
                !core.memory.is_empty() && memory.name.eq_ignore_ascii_case(&core.memory)
            })
            .filter(|memory| memory.line_bytes != 0)
            .map(|memory| {
                format!(
                    "{{ {}u, {}u, {}u, {}u }}",
                    memory.size_bytes / u64::from(memory.line_bytes),
                    memory.ways.max(1),
                    memory.line_bytes,
                    memory.latency_cycles
                )
            })
            .unwrap_or_else(|| "{ 0u, 0u, 0u, 0u }".to_string());
        let (replay, store_sets) = core.lsq.as_ref().map_or((0, 0), |l| (l.replay, l.store_sets));
        let (fe, fw, depth, fbuf, btb, btbp) = core.front_end.as_ref().map_or((0, 0, 0, 0, 0, 0), |f| {
            (1, f.fetch_width, f.depth, f.buffer, f.btb, f.btb_penalty)
        });
        let ras = core.front_end.as_ref().map_or(0, |f| f.ras);
        let wrong_path = core.front_end.as_ref().map_or(0, |f| u32::from(f.wrong_path_fetch));
        let wrong_exec = core.front_end.as_ref().map_or(0, |f| u32::from(f.wrong_path_execute));
        let execute_driven = u32::from(core.engine.eq_ignore_ascii_case("execute"));
        let memory_timed = u32::from(core.memory_timing.eq_ignore_ascii_case("timed"));
        let icache = core
            .front_end
            .as_ref()
            .and_then(|f| {
                document.memories.iter().find(|m| !f.icache.is_empty() && m.name.eq_ignore_ascii_case(&f.icache))
            })
            .filter(|memory| memory.line_bytes != 0)
            .map(|memory| {
                format!(
                    "{{ {}u, {}u, {}u, {}u }}",
                    memory.size_bytes / u64::from(memory.line_bytes),
                    memory.ways.max(1),
                    memory.line_bytes,
                    memory.latency_cycles
                )
            })
            .unwrap_or_else(|| "{ 0u, 0u, 0u, 0u }".to_string());
        let unit_ports = if core.ports.is_empty() {
            "0".to_string()
        } else {
            format!("AXIS_SIM_UNIT_PORTS_{ident}")
        };
        let tlb = core.tlb.as_ref().map_or_else(
            || "{ 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u }".to_string(),
            |t| {
                format!(
                    "{{ {}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u, {}u }}",
                    t.data.entries, t.data.ways, t.fetch.entries, t.fetch.ways,
                    t.second.entries, t.second.ways, t.second.latency, t.page_bytes, t.walk_cycles
                )
            },
        );
        let (lsq, loads, stores, perfect, forwarding) = match &core.lsq {
            Some(lsq) => (
                1,
                lsq.loads,
                lsq.stores,
                match lsq.disambiguation.as_str() {
                    "perfect" => 1,
                    "speculative" => 2,
                    "store-sets" => 3,
                    _ => 0,
                },
                u32::from(lsq.forwarding),
            ),
            None => (0, 0, 0, 0, 0),
        };
        let rename = if core.rename.is_empty() {
            "0".to_string()
        } else {
            format!("AXIS_SIM_RENAME_{ident}")
        };
        let predictor = if core.predictor.eq_ignore_ascii_case("gshare") {
            2u32
        } else {
            u32::from(core.predictor.eq_ignore_ascii_case("bimodal"))
        };
        out.push_str(&format!(
            "  {{ {}, {}, {}u, {}, {}, {}, {}u, {}u, {}u, {}u, {}u, {}u, {}, {}, \
             {lsq}u, {loads}u, {stores}u, {perfect}u, {forwarding}u, {rename}, {}, {}u, {replay}u, {store_sets}u, \
             {fe}u, {fw}u, {depth}u, {fbuf}u, {btb}u, {btbp}u, {}, {}, {}, {ras}u, {unit_ports}, {}u, \
             {icache}, {wrong_path}u, {wrong_exec}u, {execute_driven}u, {memory_timed}u, {tlb} }},\n",
            c_string(&core.name),
            c_string(&core.implements),
            core.issue_width.max(1),
            units,
            core.units.len(),
            cache,
            core.branch_penalty,
            predictor,
            core.predictor_entries.max(1),
            core.rob,
            if core.issue_queue == 0 { core.rob } else { core.issue_queue },
            // ⚠️ Emitted UNDECLARED as zero, so the library's own default --
            // the issue width -- can apply. Clamping to one here made every
            // core that did not name a retire width retire one per cycle,
            // and a four-wide machine then took exactly as long as a
            // one-wide one: the default was silently the constraint.
            core.commit_width,
            c_string(&core.model),
            c_string(if core.provenance.is_empty() { "declared" } else { &core.provenance }),
            core.rename.len(),
            core.predictor_history,
            c_string(if core.predictor.is_empty() { "" } else { &core.predictor }),
            if core.predictor_params.is_empty() {
                "0".to_string()
            } else {
                format!("AXIS_SIM_PREDICTOR_PARAMS_{ident}")
            },
            core.predictor_params.len(),
            core.ports.len()
        ));
    }
    out.push_str("  { 0, 0, 0u, 0, 0, { 0u, 0u, 0u, 0u }, 0u, 0u, 0u, 0u, 0u, 0u, 0, 0, 0u, 0u, 0u, 0u, 0u, 0, 0, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0u, 0, 0, 0, 0u, 0, 0u, { 0u, 0u, 0u, 0u }, 0u, 0u, 0u }\n};\n");
    // VU1: each core's unit lanes, in the cores' own order.
    out.push_str("static const uint32_t *const AXIS_SIM_UNIT_LANES[] = {\n");
    for core in &document.cores {
        if core.units.is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_UNIT_LANES_{},\n", tablegen_ident(&core.name)));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("static uint32_t axis_unit_lanes(const axis_pack_machine *m, int32_t unit) {\n");
    out.push_str("  if (!m->core || unit < 0 || unit >= m->core->unit_count) { return 0u; }\n");
    out.push_str("  const uint32_t *lanes = AXIS_SIM_UNIT_LANES[m->core - AXIS_SIM_CORES];\n");
    out.push_str("  uint32_t n = lanes ? lanes[unit] : 0u;\n");
    out.push_str("  return n > AXIS_SIM_UNIT_LANES_MAX ? AXIS_SIM_UNIT_LANES_MAX : n;\n}\n");
    out.push_str("static const char *const *const AXIS_SIM_UNIT_LENGTH[] = {\n");
    for core in &document.cores {
        if core.units.is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_UNIT_LENGTH_{},\n", tablegen_ident(&core.name)));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("static const char *axis_unit_length(const axis_pack_machine *m, int32_t unit) {\n");
    out.push_str("  if (!m->core || unit < 0 || unit >= m->core->unit_count) { return 0; }\n");
    out.push_str("  const char *const *names = AXIS_SIM_UNIT_LENGTH[m->core - AXIS_SIM_CORES];\n");
    out.push_str("  return names ? names[unit] : 0;\n}\n");
    out.push_str("static const uint32_t *const AXIS_SIM_UNIT_LENDERS[] = {\n");
    for core in &document.cores {
        if core.units.is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_UNIT_LENDERS_{},\n", tablegen_ident(&core.name)));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("static uint32_t axis_unit_lenders(const axis_pack_machine *m, int32_t unit) {\n");
    out.push_str("  if (!m->core || unit < 0 || unit >= m->core->unit_count) { return 0u; }\n");
    out.push_str("  const uint32_t *lenders = AXIS_SIM_UNIT_LENDERS[m->core - AXIS_SIM_CORES];\n");
    out.push_str("  return lenders ? lenders[unit] : 0u;\n}\n");
    out.push_str("static const uint8_t *const AXIS_SIM_UNIT_ABORT[] = {\n");
    for core in &document.cores {
        if core.units.is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_UNIT_ABORT_{},\n", tablegen_ident(&core.name)));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("static int axis_unit_aborts(const axis_pack_machine *m, int32_t unit) {\n");
    out.push_str("  if (!m->core || unit < 0 || unit >= m->core->unit_count) { return 0; }\n");
    out.push_str("  const uint8_t *aborts = AXIS_SIM_UNIT_ABORT[m->core - AXIS_SIM_CORES];\n");
    out.push_str("  return aborts ? aborts[unit] != 0u : 0;\n}\n");
    out.push_str("static const uint32_t (*const AXIS_SIM_UNIT_COST[])[2] = {\n");
    for core in &document.cores {
        if core.units.is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_UNIT_COST_{},\n", tablegen_ident(&core.name)));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("static void axis_unit_cost(const axis_pack_machine *m, int32_t unit, uint32_t *transport, uint32_t *change) {\n");
    out.push_str("  *transport = 0; *change = 0;\n");
    out.push_str("  if (!m->core || unit < 0 || unit >= m->core->unit_count) { return; }\n");
    out.push_str("  const uint32_t (*cost)[2] = AXIS_SIM_UNIT_COST[m->core - AXIS_SIM_CORES];\n");
    out.push_str("  if (cost) { *transport = cost[unit][0]; *change = cost[unit][1]; }\n}\n");
    out.push_str(&format!(
        "static const int32_t AXIS_SIM_CORE_COUNT = {};\n",
        document.cores.len()
    ));
    // Each core's exclusive monitor, by state name (U4c): what another core's
    // store clears. Private to this library, beside the core table rather
    // than in it, so the pack ABI does not move.
    out.push_str("static const char *const AXIS_SIM_CORE_EXCLUSIVE[][3] = {\n");
    for core in &document.cores {
        match &core.exclusive {
            Some((a, b, c)) => out.push_str(&format!("  {{ {}, {}, {} }},\n", c_string(a), c_string(b), c_string(c))),
            None => out.push_str("  { 0, 0, 0 },\n"),
        }
    }
    out.push_str("  { 0, 0, 0 }\n};\n");
    // Whether its data cache is a blocking one (docs/blocking_cache_design.md).
    out.push_str("static const uint8_t AXIS_SIM_CORE_BLOCKING[] = {\n ");
    for core in &document.cores {
        let blocking = document.memories.iter().any(|memory| {
            !core.memory.is_empty() && memory.name.eq_ignore_ascii_case(&core.memory) && memory.policy.blocking
        });
        out.push_str(&format!(" {},", u8::from(blocking)));
    }
    out.push_str(" 0\n};\n");
    // And its event instructions (U4c): wait, send, local; 0 for none.
    out.push_str("static const char *const AXIS_SIM_CORE_EVENTS[][3] = {\n");
    for core in &document.cores {
        match &core.events {
            Some((w, s, l)) => out.push_str(&format!(
                "  {{ {}, {}, {} }},\n",
                c_string(w),
                c_string(s),
                if l.is_empty() { "0".to_string() } else { c_string(l) }
            )),
            None => out.push_str("  { 0, 0, 0 },\n"),
        }
    }
    out.push_str("  { 0, 0, 0 }\n};\n");
    // The unit an instruction that names none issues to (U4c): derived from
    // its effects, as a SIMT core derives it (crate::simt::derived_unit_class).
    out.push_str("typedef struct { const char *isa; const char *mnemonic; const char *unit; } axis_sim_derived;\n");
    out.push_str("static const axis_sim_derived AXIS_SIM_DERIVED_UNITS[] = {\n");
    for instruction in &document.instructions {
        if instruction.unit.trim().is_empty() {
            out.push_str(&format!(
                "  {{ {}, {}, {} }},\n",
                c_string(&instruction.isa),
                c_string(&instruction.mnemonic),
                c_string(&crate::simt::derived_unit_class(instruction))
            ));
        }
    }
    out.push_str("  { 0, 0, 0 }\n};\n");
    out.push_str("/* Looked up once per entry: the trace engine asks for every step. */\n");
    out.push_str("static const char *axis_sim_derived_unit(const axis_lift_entry *entry) {\n");
    out.push_str("  static const axis_lift_entry *seen[4096];\n  static const char *unit[4096];\n");
    out.push_str("  uint32_t h = (uint32_t)(((uintptr_t)entry >> 4) * 2654435761u) % 4096u;\n");
    out.push_str("  if (seen[h] == entry) { return unit[h]; }\n");
    out.push_str("  const char *found = 0;\n");
    out.push_str("  for (const axis_sim_derived *d = AXIS_SIM_DERIVED_UNITS; d->mnemonic; ++d) {\n");
    out.push_str("    if (!strcmp(d->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(d->isa, entry->isa))) { found = d->unit; break; }\n  }\n");
    out.push_str("  seen[h] = entry;\n  unit[h] = found;\n  return found;\n}\n");
    // What each core says about time (docs/core_timing_design.md, T2): every
    // instruction whose latency or unit on that core is not its own, as
    // `Core::latency_of` / `Core::unit_of` resolve it. A side table indexed
    // like the core's others, so the pack ABI does not move; a core that
    // says nothing has none, and is timed exactly as before.
    out.push_str("typedef struct { const char *isa; const char *mnemonic; const char *unit; uint32_t latency; } axis_sim_retimed;\n");
    // U1: what each core cracks, as `Core::micro_ops_of` divided it. Operands
    // by position, accesses by the order the instruction makes them.
    for (index, core) in document.cores.iter().enumerate() {
        let cracked = core.cracked(&document.instructions);
        if cracked.is_empty() {
            continue;
        }
        out.push_str(&format!("static const axis_sim_crack AXIS_SIM_CRACKS_{index}[] = {{\n"));
        for (mnemonic, ops) in &cracked {
            let instruction = document
                .instructions
                .iter()
                .find(|i| core.decodes(i) && i.mnemonic == *mnemonic)
                .expect("cracked instructions are the document's");
            let mask = |names: &[String]| -> u32 {
                instruction.operands.iter().enumerate().fold(0u32, |mask, (at, operand)| {
                    if at < 32 && names.contains(&operand.name) { mask | (1u32 << at) } else { mask }
                })
            };
            let bits = |list: &[usize]| list.iter().filter(|&&n| n < 32).fold(0u32, |m, &n| m | (1u32 << n));
            let rows: Vec<String> = ops
                .iter()
                .take(8)
                .map(|op| {
                    format!(
                        "{{ {}, {}u, {}u, {}u, {}u, {}u, {}, {} }}",
                        c_string(&op.unit),
                        op.latency,
                        mask(&op.reads),
                        mask(&op.writes),
                        bits(&op.accesses),
                        bits(&op.after),
                        u32::from(op.rest),
                        u32::from(op.implicit)
                    )
                })
                .collect();
            out.push_str(&format!(
                "  {{ {}, {}, {{ {} }} }},\n",
                c_string(mnemonic),
                rows.len(),
                rows.join(", ")
            ));
        }
        out.push_str("  { 0, 0, { { 0, 0u, 0u, 0u, 0u, 0u, 0, 0 } } }\n};\n");
    }
    out.push_str("static const axis_sim_crack *const AXIS_SIM_CORE_CRACKS[] = {\n");
    for (index, core) in document.cores.iter().enumerate() {
        if core.cracked(&document.instructions).is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_CRACKS_{index},\n"));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str(CRACK_C);
    for (index, core) in document.cores.iter().enumerate() {
        let retimed = core.retimed(&document.instructions);
        if retimed.is_empty() {
            continue;
        }
        out.push_str(&format!("static const axis_sim_retimed AXIS_SIM_RETIMED_{index}[] = {{\n"));
        for (mnemonic, unit, latency) in retimed {
            let isa = document
                .instructions
                .iter()
                .find(|instruction| instruction.mnemonic == mnemonic && core.decodes(instruction))
                .map_or("", |instruction| instruction.isa.as_str());
            out.push_str(&format!(
                "  {{ {}, {}, {}, {latency}u }},\n",
                c_string(isa),
                c_string(mnemonic),
                c_string(unit)
            ));
        }
        out.push_str("  { 0, 0, 0, 0u }\n};\n");
    }
    out.push_str("static const axis_sim_retimed *const AXIS_SIM_CORE_RETIMED[] = {\n");
    for (index, core) in document.cores.iter().enumerate() {
        if core.retimed(&document.instructions).is_empty() {
            out.push_str("  0,\n");
        } else {
            out.push_str(&format!("  AXIS_SIM_RETIMED_{index},\n"));
        }
    }
    out.push_str("  0\n};\n");
    out.push_str("/* The row of `core`'s table for `entry`, or 0. Found once per (core,\n   entry): the trace engine asks at every step. */\n");
    out.push_str("static const axis_sim_retimed *axis_sim_retimed_of(const axis_sim_core *core, const axis_lift_entry *entry) {\n");
    out.push_str("  if (!core || !entry) { return 0; }\n");
    out.push_str("  const axis_sim_retimed *table = AXIS_SIM_CORE_RETIMED[core - AXIS_SIM_CORES];\n");
    out.push_str("  if (!table) { return 0; }\n");
    out.push_str("  static const axis_sim_core *seen_core[4096];\n  static const axis_lift_entry *seen_entry[4096];\n  static const axis_sim_retimed *seen_row[4096];\n");
    out.push_str("  uint32_t h = (uint32_t)((((uintptr_t)entry >> 4) ^ ((uintptr_t)core * 31u)) * 2654435761u) % 4096u;\n");
    out.push_str("  if (seen_entry[h] == entry && seen_core[h] == core) { return seen_row[h]; }\n");
    out.push_str("  const axis_sim_retimed *found = 0;\n");
    out.push_str("  for (const axis_sim_retimed *r = table; r->mnemonic; ++r) {\n");
    out.push_str("    if (!strcmp(r->mnemonic, entry->mnemonic) && (!entry->isa || !r->isa[0] || !strcmp(r->isa, entry->isa))) { found = r; break; }\n  }\n");
    out.push_str("  seen_core[h] = core;\n  seen_entry[h] = entry;\n  seen_row[h] = found;\n  return found;\n}\n");
    out.push_str("/* The cycles `entry` takes on `core`: the core's word, else its own. */\n");
    out.push_str("static uint32_t axis_sim_latency_on(const axis_sim_core *core, const axis_lift_entry *entry) {\n");
    out.push_str("  const axis_sim_retimed *r = axis_sim_retimed_of(core, entry);\n");
    out.push_str("  if (r) { return r->latency; }\n");
    out.push_str("  return (entry && entry->latency) ? entry->latency : 1u;\n}\n");
    out.push_str("/* The unit `entry` issues to on `core`, by name: the core's word, else the\n   one it names, else the one its effects derive (U4c) -- the order\n   `Core::unit_of` gives. */\n");
    out.push_str("static const char *axis_sim_unit_on(const axis_sim_core *core, const axis_lift_entry *entry) {\n");
    out.push_str("  const axis_sim_retimed *r = axis_sim_retimed_of(core, entry);\n");
    out.push_str("  if (r && r->unit && r->unit[0]) { return r->unit; }\n");
    out.push_str("  if (!entry) { return 0; }\n");
    out.push_str("  return (entry->unit && entry->unit[0]) ? entry->unit : axis_sim_derived_unit(entry);\n}\n");
    out.push_str("static const char *const *axis_sim_core_events(const axis_sim_core *core) {\n");
    out.push_str("  return core ? AXIS_SIM_CORE_EVENTS[core - AXIS_SIM_CORES] : 0;\n}\n");
    out.push_str("/* Whether `core`'s data cache is a blocking one -- and the core one that\n   keeps time when it reaches memory, which only the execution-driven engine\n   does. */\n");
    out.push_str("static int axis_sim_core_blocking(const axis_sim_core *core) {\n");
    out.push_str("  return core && core->execute_driven && AXIS_SIM_CORE_BLOCKING[core - AXIS_SIM_CORES];\n}\n");
    out.push_str("static const char *const *axis_sim_core_exclusive(const axis_sim_core *core) {\n");
    out.push_str("  return core ? AXIS_SIM_CORE_EXCLUSIVE[core - AXIS_SIM_CORES] : 0;\n}\n");
    out.push_str("static int32_t axis_sim_core_count(void) { return AXIS_SIM_CORE_COUNT; }\n");
    out.push_str("static const char *axis_sim_core_name(int32_t slot) {\n  return (slot >= 0 && slot < AXIS_SIM_CORE_COUNT) ? AXIS_SIM_CORES[slot].name : 0;\n}\n");
    out.push_str("/* ⚠️ Returns how many declared cores asked for this model. Zero means no\n   core names it -- a typo, or a model built for another description -- and\n   saying so beats accepting a registration that will never be used and then\n   refusing every core for reasons the host cannot see. */\n");
    out.push_str(PREDICTORS_C);
    // D3: each core's quick predictor -- entries and override cycles -- beside
    // the core table rather than in it, so the pack ABI does not move.
    out.push_str("static const uint32_t AXIS_SIM_CORE_QUICK[][2] = {\n");
    for core in &document.cores {
        let (entries, cycles) = core.overrides.as_ref().map_or((0, 0), |q| (q.entries, q.cycles));
        out.push_str(&format!("  {{ {entries}u, {cycles}u }},\n"));
    }
    out.push_str("  { 0u, 0u }\n};\n");
    out.push_str(QUICK_C);
    out.push_str(PREFETCHERS_C);
    out.push_str("static int32_t axis_sim_register_model(const axis_uarch_pack *model) {\n");
    out.push_str("  if (!model || !model->name || !model->name[0]) { return 0; }\n");
    out.push_str("  if (!model->create || !model->account || !model->cycles) { return 0; }\n");
    out.push_str("  int32_t wanted = 0;\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_SIM_CORE_COUNT; ++i) {\n");
    out.push_str("    if (AXIS_SIM_CORES[i].model && !strcmp(AXIS_SIM_CORES[i].model, model->name)) { wanted++; }\n  }\n");
    out.push_str("  if (!wanted) { return 0; }\n");
    out.push_str("  if (AXIS_SIM_MODEL_COUNT < AXIS_SIM_MODELS) { AXIS_SIM_MODEL[AXIS_SIM_MODEL_COUNT++] = model; }\n");
    out.push_str("  return wanted;\n}\n");
    out.push_str("static const char *axis_sim_core_model(int32_t slot) {\n  return (slot >= 0 && slot < AXIS_SIM_CORE_COUNT) ? AXIS_SIM_CORES[slot].model : 0;\n}\n");
    out.push_str("static const char *axis_sim_core_provenance(int32_t slot) {\n  return (slot >= 0 && slot < AXIS_SIM_CORE_COUNT) ? AXIS_SIM_CORES[slot].provenance : 0;\n}\n");
    out.push_str("/* ⚠️ Returns 0 for a name the description does not declare, and leaves\n   the machine on the model it had. A typo that silently kept the\n   first-order model would report a plausible number for a machine nobody\n   asked for. */\n");
    out.push_str("static int32_t axis_sim_select_core(void *machine, const char *name) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n");
    out.push_str("  if (!m) { return 0; }\n");
    out.push_str("  if (!name) { m->core = 0; return 1; }\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_SIM_CORE_COUNT; ++i) {\n");
    out.push_str("    if (strcmp(AXIS_SIM_CORES[i].name, name)) { continue; }\n");
    out.push_str("    /* ⚠️ REFUSED, not approximated. This core asks to be timed by an\n       implementation that is not this library, and this library has no way\n       to be it. Selecting anyway would hand back the built-in pipeline's\n       number for somebody else's machine -- exactly the plausible wrong\n       answer a mixed open/closed stack exists to prevent. The machine is\n       left on whatever it was on. */\n");
    out.push_str("    /* ⚠️ Refused only while the model is ABSENT. Capability is presence:\n       a host that has this vendor's implementation registers it and the\n       core selects; a host that does not is told no by name rather than\n       handed the built-in pipeline's answer for somebody else's machine. */\n");
    out.push_str("    /* Both resolved into locals and refused BEFORE anything changes: a\n       refusal leaves the machine exactly as it was, which assigning\n       `m->model` first did not quite do. */\n");
    out.push_str("    const axis_uarch_pack *model = axis_sim_model_for(AXIS_SIM_CORES[i].model);\n");
    out.push_str("    if (AXIS_SIM_CORES[i].model && AXIS_SIM_CORES[i].model[0] && !model) { return 0; }\n");
    out.push_str("    const axis_sim_predictor *pred = axis_sim_predictor_for(AXIS_SIM_CORES[i].predictor_name);\n");
    out.push_str("    if (AXIS_SIM_CORES[i].predictor_name && AXIS_SIM_CORES[i].predictor_name[0] && !pred) { return 0; }\n");
    out.push_str("    /* And a prefetcher from outside that a cache of this core's memory\n       system names: unbound, the core is refused for the same reason. */\n");
    out.push_str("    if (!axis_sim_prefetchers_bound(name)) { return 0; }\n");
    out.push_str("    m->model = model;\n");
    out.push_str("    if (m->model_state && m->model_owner) { m->model_owner->destroy(m->model_state); }\n");
    out.push_str("    m->model_state = 0;\n    m->model_owner = 0;\n");
    out.push_str("    if (m->model) {\n      m->model_owner = m->model;\n      m->model_state = m->model->create(&AXIS_SIM_CORES[i]);\n    }\n");
    out.push_str("    m->core = &AXIS_SIM_CORES[i];\n");
    out.push_str("    memset(m->unit_free, 0, sizeof m->unit_free);\n    memset(m->lane_free, 0, sizeof m->lane_free);\n");
    out.push_str("    /* A shared unit starts a run idle and nobody's, whichever of its cores\n       is reset. */\n");
    out.push_str("    for (int32_t u = 0; u < AXIS_SIM_SHARED_UNITS; ++u) {\n      axis_sim_shared *sh = m->grp ? m->grp->shared[u] : m->shared[u];\n      if (!sh) { continue; }\n");
    out.push_str("      memset(sh->unit_free, 0, sizeof sh->unit_free);\n      memset(sh->lane_free, 0, sizeof sh->lane_free);\n");
    out.push_str("      memset(sh->asked, 0, sizeof sh->asked);\n      sh->owner = 0;\n      sh->streak = 0;\n    }\n");
    out.push_str("    m->issue_cycle = 0;\n    m->issued_this_cycle = 0;\n");
    out.push_str("    /* ⚠️ The DESCRIPTION's cache, applied on selection. A host that\n       wants another calls configure_cache after this; a core that names no\n       cache clears it, so selecting a machine never leaves the one before\n       it in place. */\n");
    out.push_str("    axis_sim_configure_cache(m, &AXIS_SIM_CORES[i].cache);\n");
    out.push_str("    /* ⚠️ And the memory system this core is a port of, fresh: selecting a\n       machine never inherits the lines another one left behind. */\n");
    out.push_str("    if (m->ms) { axis_ms_free(m->ms); m->ms = 0; }\n");
    out.push_str("    m->ms_port = -1;\n    m->ms_system = -1;\n");
    out.push_str("    for (int32_t s = 0; s < AXIS_MS_SYSTEM_COUNT && !m->ms; ++s) {\n");
    out.push_str("      axis_ms *ms = axis_ms_new(&AXIS_MS_SYSTEMS[s]);\n");
    out.push_str("      int32_t port = ms ? axis_ms_port(ms, name) : -1;\n");
    out.push_str("      if (port >= 0) { m->ms = ms; m->ms_port = port; m->ms_system = s; axis_sim_bind_prefetchers(ms); } else { axis_ms_free(ms); }\n");
    out.push_str("    }\n");
    out.push_str("    /* ⚠️ The predictor BY NAME, fresh. One this library has not got and no\n       host registered refuses the core -- the rule `model` follows, and for\n       the same reason: another predictor's mispredicts are a plausible\n       number for somebody else's machine. */\n");
    out.push_str("    if (m->pred && m->pred_state) { m->pred->destroy(m->pred_state); }\n");
    out.push_str("    m->pred = pred;\n    m->pred_state = pred ? pred->create(&AXIS_SIM_CORES[i]) : 0;\n    axis_quick_select(m, i);\n    axis_fe2_select(m, i);\n    axis_tq_select(m, i);\n    axis_sched_select(m, i);\n");
    out.push_str("    memset(m->rename_used, 0, sizeof m->rename_used);\n");
    out.push_str("    m->acc_count = 0;\n");
    out.push_str("    memset(m->ssit, 0, sizeof m->ssit);\n    m->next_set = 0;\n    m->violations = 0;\n");
    out.push_str("    m->fetch_cycle = 0;\n    m->fetched_in_group = 0;\n    m->fe_restart = 0;\n");
    out.push_str("    m->fe_group_break = 0;\n    m->fe_bubble = 0;\n    m->fe_redirect_seq = AXIS_SIM_NO_SEQ;\n");
    out.push_str("    m->fe_pending_mispredict = 0;\n    m->fe_pending_break = 0;\n    m->fe_pending_bubble = 0;\n    m->fe_pending_delay = 0;\n");
    out.push_str("    m->fe_count = 0;\n    m->btb_misses = 0;\n");
    out.push_str("    m->ras_top = 0;\n    m->ras_count = 0;\n    m->target_mispredicts = 0;\n");
    out.push_str("    memset(m->ic_valid, 0, sizeof m->ic_valid);\n    memset(m->ic_ready, 0, sizeof m->ic_ready);\n    m->fe_pending_d2 = 0;\n    m->ic_clock = 0;\n    m->ic_have_line = 0;\n");
    out.push_str("    memset(m->tlb_valid, 0, sizeof m->tlb_valid);\n    memset(m->tlb2_valid, 0, sizeof m->tlb2_valid);\n");
    out.push_str("    m->tlb_clock = 0;\n    m->dtlb_misses = 0;\n    m->itlb_misses = 0;\n    m->page_walks = 0;\n    m->it_have = 0;\n    m->x_it_pending = 0;\n    m->tlb_skip = 0;\n");
    out.push_str("    m->icache_misses = 0;\n    m->wrong_path_lines = 0;\n    m->wp_pending = 0;\n    m->wp_armed = 0;\n");
    out.push_str("    m->shadow = 0;\n    m->wpx_len = 0;\n    m->wpx_pending = 0;\n    m->wpx_armed = 0;\n    m->wrong_path_instructions = 0;\n");
    out.push_str("    m->x_started = 0;\n    m->x_committed = 0;\n    m->x_halted = 0;\n    m->x_flush = 0;\n");
    out.push_str("    m->x_replays = 0;\n    m->x_squashed = 0;\n    m->x_buf_count = 0;\n    m->x_buf_head = 0;\n    m->x_traps = 0;\n    m->x_snoops = 0;\n    m->x_passed = 0;\n    memset(m->x_rides, 0, sizeof m->x_rides);\n    m->x_event = 0;\n    m->x_sleeping = 0;\n    m->x_sleeps = 0;\n");
    out.push_str("    /* The metadata depends on the core (its units, its rename pools). */\n");
    out.push_str("    if (m->x_meta) { free(m->x_meta); m->x_meta = 0; }\n");
    out.push_str("    m->x_waiting = 0;\n    m->x_loads = 0;\n    m->x_stores = 0;\n    m->sb_count = 0;\n    m->fuse_live = 0;\n    m->fz_seq = AXIS_SIM_NO_SEQ;\n");
    out.push_str("    memset(m->btb_tag, 0, sizeof m->btb_tag);\n    memset(m->btb_target, 0, sizeof m->btb_target);\n");
    out.push_str("    memset(m->rob, 0, sizeof m->rob);\n");
    out.push_str("    m->rob_head = 0;\n    m->rob_tail = 0;\n    m->now = 0;\n");
    out.push_str("    m->dispatch_cycle = 0;\n    m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0;\n");
    out.push_str("    m->redirect_seq = AXIS_SIM_NO_SEQ;\n    m->redirect_cycles = 0;\n    m->front_end_stalls = 0;\n");
    out.push_str("    for (uint32_t r = 0; r < AXIS_SIM_PRODUCERS; ++r) { m->reg_producer[r] = AXIS_SIM_NO_SEQ; }\n");
    out.push_str("    m->mispredicts = 0;\n    m->front_end_ready = 0;\n    m->pending_redirect = 0;\n");
    out.push_str("    int32_t base = 0;\n");
    out.push_str("    for (int32_t u = 0; u < m->core->unit_count; ++u) {\n");
    out.push_str("      m->unit_base[u] = base;\n");
    out.push_str("      uint32_t copies = m->core->units[u].count ? m->core->units[u].count : 1u;\n");
    out.push_str("      base += (int32_t)copies;\n");
    out.push_str("      if (base > (int32_t)AXIS_SIM_UNIT_COPIES) { base = (int32_t)AXIS_SIM_UNIT_COPIES; }\n");
    out.push_str("    }\n");
    out.push_str("    return 1;\n  }\n  return 0;\n}\n");
    out.push_str("static void axis_sim_configure_cache(void *machine, const axis_sim_cache *cache) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)machine;\n");
    out.push_str("  if (!m) { return; }\n");
    out.push_str("  if (!cache) { memset(&m->cache, 0, sizeof m->cache); return; }\n");
    out.push_str("  m->cache = *cache;\n");
    out.push_str("  memset(m->valid, 0, sizeof m->valid);\n");
    out.push_str("  memset(m->used, 0, sizeof m->used);\n");
    out.push_str("  memset(m->dirty, 0, sizeof m->dirty);\n  m->dc_free = 0;\n");
    out.push_str("  m->hits = 0;\n  m->misses = 0;\n  m->clock = 0;\n}\n");
    out.push_str("static void axis_sim_touch_memory(void *machine, uint64_t addr) {\n  if (machine) { axis_sim_touch((axis_pack_machine *)machine, addr, 0); }\n}\n");
    out.push_str("static uint64_t axis_sim_mispredicts(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->mispredicts : 0u;\n}\n");
    out.push_str("static const char *axis_sim_timing_source(const void *machine) {\n");
    out.push_str("  const axis_pack_machine *m = machine;\n");
    out.push_str("  if (!m) { return 0; }\n");
    out.push_str("  return (m->model && m->model_state && m->model->name) ? m->model->name : \"\";\n}\n");
    out.push_str("static uint64_t axis_sim_replays(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->x_replays : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_traps(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->x_traps : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_dtlb_misses(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->dtlb_misses : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_itlb_misses(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->itlb_misses : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_micro_ops(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->micro_ops : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_op_cache_ops(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->op_cache_ops : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_value_predictions(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->value_predictions : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_value_mispredicts(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->value_mispredicts : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_loop_buffer_ops(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->loop_buffer_ops : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_page_walks(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->page_walks : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_snoops(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->x_snoops : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_squashed(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->x_squashed : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_wrong_path_instructions(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->wrong_path_instructions : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_icache_misses(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->icache_misses : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_wrong_path_lines(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->wrong_path_lines : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_target_mispredicts(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->target_mispredicts : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_btb_misses(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->btb_misses : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_memory_violations(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->violations : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_front_end_stalls(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->front_end_stalls : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_cache_hits(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->hits : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_cache_misses(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return m ? m->misses : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_cycles_of(const void *machine) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  return m ? m->cycle : 0u;\n}\n");
    out.push_str("/* ⚠️ Draining before reporting, and the cast says why it has to: an\n   out-of-order machine still holds instructions that have not retired, and\n   a count taken before they do credits the machine with work it has not\n   finished. The in-order model has nothing in flight and drains to itself. */\n");
    out.push_str("static uint64_t axis_sim_cycles(const void *machine) {\n");
    out.push_str("  axis_pack_machine *m = (axis_pack_machine *)(uintptr_t)machine;\n");
    out.push_str("  if (!m) { return 0u; }\n");
    out.push_str("  /* ⚠️ The model's answer, WHOLE. Not blended with this library's and not\n     quietly checked against it: once a vendor's implementation is timing\n     the machine, the cycle count is that implementation's claim, and\n     mixing in a second one produces a figure neither of them made. */\n");
    out.push_str("  if (m->model && m->model_state) { return m->model->cycles(m->model_state); }\n");
    out.push_str("  axis_ooo_drain(m);\n");
    out.push_str("  return axis_sim_cycles_of(machine);\n}\n");
    out.push_str("static uint64_t axis_sim_blocks_built(const void *machine) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  return m ? m->built : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_pc(const void *machine) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  return m ? m->sim.pc : 0u;\n}\n");
    out.push_str("static uint64_t axis_sim_steps(const void *machine) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  return m ? m->sim.steps : 0u;\n}\n");
    out.push_str("static int32_t axis_sim_status_of(const void *machine) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  return m ? (int32_t)m->sim.status : AXIS_PACK_SIM_HALTED;\n}\n");
    out.push_str("static const char *axis_sim_halt_reason(const void *machine) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  return m ? m->sim.halt_reason : NULL;\n}\n");
    out.push_str("static uint64_t axis_sim_reg(const void *machine, int32_t slot) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  if (!m || slot < 0 || slot >= AXIS_SIM_REG_SLOTS) { return 0u; }\n  return m->sim.regs[slot];\n}\n");
    out.push_str("static void axis_sim_set_reg(void *machine, int32_t slot, uint64_t value) {\n  axis_pack_machine *m = (axis_pack_machine *)machine;\n  if (!m || slot < 0 || slot >= AXIS_SIM_REG_SLOTS) { return; }\n  m->sim.regs[slot] = value;\n  m->x_view_ok = 0;\n}\n");
    out.push_str("static uint64_t axis_sim_state_value(const void *machine, int32_t slot) {\n  const axis_pack_machine *m = (const axis_pack_machine *)machine;\n  if (!m || slot < 0 || slot >= m->state_count) { return 0u; }\n  return m->state[slot].value;\n}\n");
    out.push_str("static int32_t axis_sim_register_slots(void) { return AXIS_SIM_REG_SLOTS; }\n");
    // The same state list the executor publishes, from the same place: a
    // simulator that disagreed with the executor about which slots exist would
    // be a second answer to a question the description settles.
    out.push_str("typedef struct { const char *name; uint32_t width; } axis_sim_slot;\n");
    out.push_str("static const axis_sim_slot AXIS_SIM_STATE[] = {\n");
    for (name, width) in &state {
        out.push_str(&format!("  {{ {}, {width}u }},\n", c_string(name)));
    }
    out.push_str("  { NULL, 0u }\n};\n");
    out.push_str(&format!(
        "static int32_t axis_sim_state_slots(void) {{ return {}; }}\n",
        state.len()
    ));
    out.push_str("static int axis_sim_state_ok(int32_t s) { return s >= 0 && s < axis_sim_state_slots(); }\n");
    out.push_str("static const char *axis_sim_state_name(int32_t s) { return axis_sim_state_ok(s) ? AXIS_SIM_STATE[s].name : NULL; }\n");
    out.push_str("static uint32_t axis_sim_state_width(int32_t s) { return axis_sim_state_ok(s) ? AXIS_SIM_STATE[s].width : 0u; }\n\n");
    out.push_str("static const char *axis_sim_memsys_name(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return (m && m->ms) ? AXIS_MS_SYSTEMS[m->ms_system].name : \"\";\n}\n");
    out.push_str("static int32_t axis_sim_memsys_node_count(const void *machine) {\n  const axis_pack_machine *m = machine;\n  return (m && m->ms) ? AXIS_MS_SYSTEMS[m->ms_system].node_count : 0;\n}\n");
    out.push_str("static const char *axis_sim_memsys_node_name(const void *machine, int32_t node) {\n  const axis_pack_machine *m = machine;\n  if (!m || !m->ms || node < 0 || node >= AXIS_MS_SYSTEMS[m->ms_system].node_count) { return 0; }\n  return AXIS_MS_SYSTEMS[m->ms_system].nodes[node].name;\n}\n");
    out.push_str("static int32_t axis_sim_memsys_stats(const void *machine, int32_t node, uint64_t *out, int32_t n) {\n");
    out.push_str("  const axis_pack_machine *m = machine;\n");
    out.push_str("  const axis_ms_stats *s = (m && m->ms) ? axis_ms_stats_of(m->ms, node) : 0;\n");
    out.push_str("  if (!s || !out) { return 0; }\n");
    out.push_str("  const uint64_t all[13] = { s->hits, s->misses, s->writebacks, s->evictions, s->prefetches,\n                            s->back_invalidations, s->row_hits, s->row_idle, s->row_conflicts, s->accesses,\n                            s->forwards, s->invalidations, s->upgrades };\n");
    out.push_str("  int32_t k = n < 13 ? n : 13;\n  for (int32_t i = 0; i < k; ++i) { out[i] = all[i]; }\n  return k;\n}\n\n");
    out.push_str("/* ⚠️ Coherence needs one memory system under several machines. `machine`\n   gives up its own and shares `other`'s, at the port its OWN core has there;\n   refused (0) when `other` has none or holds no port for this core. The\n   system is freed by the last machine to let it go. */\n");
    out.push_str("static int32_t axis_sim_memsys_join(void *machine, void *other) {\n");
    out.push_str("  axis_pack_machine *m = machine, *o = other;\n");
    out.push_str("  if (!m || !o || !o->ms || !m->core) { return 0; }\n");
    out.push_str("  int32_t port = axis_ms_port(o->ms, m->core->name);\n");
    out.push_str("  if (port < 0) { return 0; }\n");
    out.push_str("  if (m->ms) { axis_ms_free(m->ms); }\n");
    out.push_str("  m->ms = o->ms;\n  m->ms->refs++;\n  m->ms_port = port;\n  m->ms_system = o->ms_system;\n  return 1;\n}\n\n");
    out.push_str("static void *axis_sim_memsys_handle(void *machine) {\n  axis_pack_machine *m = machine;\n  return m ? (void *)m->ms : 0;\n}\n\n");
    out.push_str("static int32_t axis_sim_share_core(void *machine, void *other) {\n");
    out.push_str("  axis_pack_machine *m = machine, *o = other;\n");
    out.push_str("  if (!m || !o || m == o || !m->core || m->core != o->core || !m->core->execute_driven) { return 0; }\n");
    out.push_str("  if (m->x_started || o->x_started || m->grp) { return 0; }\n");
    out.push_str("  /* A core is shared BEFORE its units are (VU4): a unit share made by a\n     machine is that machine's, and would not follow it into a group. */\n");
    out.push_str("  for (int32_t u = 0; u < AXIS_SIM_SHARED_UNITS; ++u) { if (m->shared[u] || o->shared[u]) { return 0; } }\n");
    out.push_str("  if (!o->grp) {\n");
    out.push_str("    o->grp = (axis_sim_group *)calloc(1, sizeof *o->grp);\n    if (!o->grp) { return 0; }\n");
    out.push_str("    o->grp->refs = 1;\n    o->grp->count = 1;\n    o->grp->cycle = ~0ull;\n    memset(o->grp->fetch_cycle, 0xff, sizeof o->grp->fetch_cycle);\n    o->grp->member[0] = o;\n");
    out.push_str("    memcpy(o->grp->unit_free, o->unit_free, sizeof o->grp->unit_free);\n");
    out.push_str("    memcpy(o->grp->lane_free, o->lane_free, sizeof o->grp->lane_free);\n  }\n");
    out.push_str("  if (o->grp->count >= AXIS_SIM_WARP_MAX) { return 0; }\n");
    out.push_str("  m->grp = o->grp;\n  m->grp->refs++;\n  m->grp->member[m->grp->count++] = m;\n  return 1;\n}\n\n");
    out.push_str("static int32_t axis_sim_set_warp(void *machine, uint32_t warp, uint32_t age) {\n");
    out.push_str("  axis_pack_machine *m = machine;\n");
    out.push_str("  if (!m || !m->grp || !age || warp >= AXIS_SIM_WARP_MAX) { return 0; }\n");
    out.push_str("  if (m->grp->warp_age && m->grp->warp_age != age) { return 0; }\n");
    out.push_str("  for (int32_t i = 0; i < m->grp->count; ++i) {\n    if (m->grp->member[i] && m->grp->member[i]->x_started) { return 0; }\n  }\n");
    out.push_str("  m->grp->warp_age = age;\n  m->x_warp = warp + 1u;\n  return 1;\n}\n\n");
    out.push_str(r#"static int32_t axis_sim_unit_named(const axis_pack_machine *m, const char *unit) {
  for (int32_t u = 0; m->core && unit && u < m->core->unit_count && u < AXIS_SIM_SHARED_UNITS; ++u) {
    if (!strcmp(m->core->units[u].name, unit)) { return u; }
  }
  return -1;
}
static int32_t axis_sim_share_unit(void *machine, void *other, const char *unit) {
  axis_pack_machine *m = machine, *o = other;
  if (!m || !o || m == o || !m->core || !o->core) { return 0; }
  if (!m->core->execute_driven || !o->core->execute_driven) { return 0; }
  if (m->x_started || o->x_started) { return 0; }
  /* ⚠️ A context of a shared core shares through its GROUP: the core is the
     party, and two contexts of one core already have one unit between them. */
  const void *mp = m->grp ? (const void *)m->grp : (const void *)m;
  const void *op = o->grp ? (const void *)o->grp : (const void *)o;
  if (mp == op) { return 0; }
  int32_t mu = axis_sim_unit_named(m, unit), ou = axis_sim_unit_named(o, unit);
  if (mu < 0 || ou < 0) { return 0; }
  axis_sim_shared **mine = m->grp ? &m->grp->shared[mu] : &m->shared[mu];
  axis_sim_shared **theirs = o->grp ? &o->grp->shared[ou] : &o->shared[ou];
  if (*mine) { return 0; }
  /* ⚠️ ONE unit: the two cores have to mean the same thing by it. */
  uint32_t mt, ms, ot, os;
  axis_unit_cost(m, mu, &mt, &ms);
  axis_unit_cost(o, ou, &ot, &os);
  if (m->core->units[mu].count != o->core->units[ou].count
      || m->core->units[mu].pipelined != o->core->units[ou].pipelined
      || axis_unit_lanes(m, mu) != axis_unit_lanes(o, ou) || mt != ot || ms != os) { return 0; }
  axis_sim_shared *sh = *theirs;
  if (!sh) {
    sh = (axis_sim_shared *)calloc(1, sizeof *sh);
    if (!sh) { return 0; }
    sh->refs = 1;
    sh->count = 1;
    sh->who[0] = op;
    *theirs = sh;
  }
  if (sh->count >= AXIS_SIM_SHARERS) { return 0; }
  sh->who[sh->count++] = mp;
  sh->refs++;
  *mine = sh;
  return 1;
}
"#);
    out.push_str("static int32_t axis_sim_warp_rides(const void *machine, uint64_t *out, int32_t n) {\n");
    out.push_str("  const axis_pack_machine *m = machine;\n");
    out.push_str("  if (!m || !out) { return 0; }\n");
    out.push_str("  /* Then how many times it slept on a wait (U4c events). */\n");
    out.push_str("  int32_t k = n < 4 ? n : 4;\n  for (int32_t i = 0; i < k; ++i) { out[i] = i < 3 ? m->x_rides[i] : m->x_sleeps; }\n  return k;\n}\n\n");
    out.push_str(&pack_routine_registry(document));
    out.push_str(&format!(
        "static const axis_sim_pack AXIS_SIM_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  {}, {}, {},\n  \
axis_sim_register_slots, axis_sim_state_slots, axis_sim_state_name, axis_sim_state_width,\n  \
axis_sim_create, axis_sim_free, axis_sim_reset_machine,\n  \
axis_sim_step_machine, axis_sim_run_machine,\n  \
axis_sim_pc, axis_sim_steps, axis_sim_status_of, axis_sim_halt_reason,\n  \
axis_sim_reg, axis_sim_set_reg, axis_sim_state_value,\n  \
axis_sim_enable_jit,\n  axis_sim_count_cycles, axis_sim_cycles,\n  \
axis_sim_configure_cache, axis_sim_cache_hits, axis_sim_cache_misses,\n  \
axis_sim_touch_memory,\n  \
axis_sim_core_count, axis_sim_core_name,\n  \
axis_sim_core_model, axis_sim_core_provenance, axis_sim_register_model,\n  \
axis_sim_timing_source,\n  \
axis_sim_select_core,\n  \
axis_sim_mispredicts, axis_sim_front_end_stalls,\n  \
axis_sim_translated, axis_sim_blocks_built,\n  \
pack_routine_count, pack_routine_name, pack_routine_mnemonic, pack_register_routine,\n  \
axis_sim_memsys_name, axis_sim_memsys_node_count, axis_sim_memsys_node_name, axis_sim_memsys_stats,\n  \
axis_sim_memsys_join,\n  \
axis_sim_memory_violations,\n  \
axis_sim_btb_misses,\n  \
axis_sim_register_predictor, axis_sim_core_predictor,\n  \
axis_sim_target_mispredicts,\n  \
axis_sim_icache_misses, axis_sim_wrong_path_lines,\n  \
axis_sim_wrong_path_instructions,\n  \
axis_sim_replays, axis_sim_squashed,\n  \
axis_sim_traps,\n  axis_sim_run_cores,\n  axis_sim_snoops,\n  axis_sim_cycle_cores,\n  axis_sim_memsys_handle,\n  axis_sim_share_core,\n  axis_sim_set_warp,\n  axis_sim_warp_rides,\n  axis_sim_share_unit,\n  axis_sim_dtlb_misses, axis_sim_itlb_misses, axis_sim_page_walks,\n  axis_sim_register_prefetcher,\n  axis_sim_micro_ops, axis_sim_op_cache_ops, axis_sim_loop_buffer_ops,\n  axis_sim_value_predictions, axis_sim_value_mispredicts\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_sim_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_sim_pack *axis_sim_pack_{ident}(void) {{ return &AXIS_SIM_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

pub fn emit_pack_jit_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's copy-and-patch JIT, as a library. */\n");
    out.push_str("/* schema: axis.pack-jit-c.v1 */\n");
    out.push_str("#include <string.h>\n#include \"axis_pack.h\"\n\n");
    // AXIS fixes the table's SHAPE here; the build fills it in. Neither half
    // can drift without the other failing to compile, which is the point.
    out.push_str("enum { AXIS_JIT_PAGE21 = 0, AXIS_JIT_PAGEOFF12 = 1 };\n\n");
    out.push_str("/* One `adrp`/`add` site inside a stencil, and the hole it reaches. */\n");
    out.push_str("typedef struct axis_jit_reloc {\n  uint32_t site;\n  uint32_t hole;\n  uint32_t kind;\n} axis_jit_reloc;\n\n");
    out.push_str("/* What a hole binds. The machine kinds the library fills itself; a\n   VALUE is the caller's, in order. */\n");
    out.push_str("enum { AXIS_JIT_REGS = 0, AXIS_JIT_MEMORY = 1, AXIS_JIT_SCRATCH = 2,\n       AXIS_JIT_STATE = 3, AXIS_JIT_PC = 4, AXIS_JIT_MASK = 5,\n       AXIS_JIT_VALUE = 6 };\n\n");
    out.push_str("typedef struct axis_jit_stencil {\n  const char *mnemonic;\n  uint32_t offset;       /* into AXIS_JIT_CODE */\n  uint32_t size;\n  uint32_t holes;        /* machine parts and operands together */\n  uint32_t values;       /* how many of them the caller supplies */\n  uint32_t effectful;    /* whether it reaches memory or state */\n  uint32_t word_bits;    /* the width of a scratch or state slot */\n  uint32_t reads_state;  /* whether the compiled bytes really read it */\n  const char *const *names;  /* one per hole: what it binds */\n  const uint8_t *kinds;      /* one per hole: which of the above */\n  uint32_t reloc;        /* into AXIS_JIT_RELOCS */\n  uint32_t reloc_count;\n} axis_jit_stencil;\n\n");
    out.push_str("/* Written by the build from the compiled stencils: their bytes, their\n   relocation sites, and how many holes each has. AXIS cannot emit this --\n   it is what a compiler made of the description on one machine, not\n   something the description says. */\n");
    out.push_str("#include \"axis_jit_table.h\"\n\n");
    out.push_str("#if !defined(__aarch64__)\n");
    out.push_str("#error \"this pack's stencils are AArch64 machine code; build it on the host they are for\"\n");
    out.push_str("#endif\n\n");
    out.push_str("enum { AXIS_JIT_SLOT = 8 };\n");
    out.push_str("/* `ret`, which every stencil ends in and a block keeps only once. */\n");
    out.push_str("enum { AXIS_JIT_RET = 0xD65F03C0u };\n\n");
    // The two relocation kinds an AArch64 `adrp`/`add` pair produces. A hole is
    // reached as a page plus an offset, so patching one is patching both.
    out.push_str("/* `adrp Xd, page` -- the signed page delta, in 4KB granules. */\n");
    out.push_str("static void axis_jit_page21(uint8_t *code, uint32_t site, uint64_t target, uint64_t pc) {\n");
    out.push_str("  int64_t delta = (int64_t)(target >> 12) - (int64_t)(pc >> 12);\n");
    out.push_str("  uint32_t word;\n  memcpy(&word, code + site, 4);\n");
    out.push_str("  word &= ~((3u << 29) | (0x7FFFFu << 5));\n");
    out.push_str("  word |= (uint32_t)(delta & 3) << 29;\n");
    out.push_str("  word |= (uint32_t)((delta >> 2) & 0x7FFFF) << 5;\n");
    out.push_str("  memcpy(code + site, &word, 4);\n}\n\n");
    out.push_str("/* `add Xd, Xn, #imm12` -- the offset within the page. */\n");
    // ⚠️ The low twelve bits go in DIFFERENTLY depending on the instruction.
    // `ADD (immediate)` takes them as they are; `LDR`/`STR` with an unsigned
    // offset take them SCALED by the access size, because the field addresses
    // words rather than bytes. This wrote the unscaled value into whatever it
    // found, which is right for the `adrp; add; ldr [x]` shape LLVM had always
    // produced here and silently wrong for `adrp; ldr [x, #off]` -- and the
    // compiler picks the second whenever it is loading a value rather than
    // computing an address. The memory window is such a load, and every
    // translated access read the wrong slot.
    //
    // ⚠️ Returns whether it could. A form this does not know is a refusal, so
    // translation fails, rather than a patch that produces plausible bytes.
    out.push_str("static int axis_jit_pageoff12(uint8_t *code, uint32_t site, uint64_t target) {\n");
    out.push_str("  uint32_t word;\n  memcpy(&word, code + site, 4);\n");
    out.push_str("  const uint32_t offset = (uint32_t)(target & 0xFFFu);\n");
    out.push_str("  if ((word & 0xFF800000u) == 0x91000000u) {\n");
    out.push_str("    /* ADD (immediate), 64-bit: the field is bytes. */\n");
    out.push_str("    word = (word & ~(0xFFFu << 10)) | (offset << 10);\n");
    out.push_str("  } else if ((word & 0x3B000000u) == 0x39000000u && !(word & (1u << 26))) {\n");
    out.push_str("    /* LDR/STR (immediate, unsigned offset): the field is scaled by the\n       access size, so an offset that is not a multiple of it cannot be\n       expressed at all. ⚠️ Integer forms only -- the SIMD ones take their\n       scale from two fields, and guessing would be the same mistake again. */\n");
    out.push_str("    const uint32_t bytes = 1u << (word >> 30);\n");
    out.push_str("    if (offset & (bytes - 1u)) { return 0; }\n");
    out.push_str("    word = (word & ~(0xFFFu << 10)) | ((offset / bytes) << 10);\n");
    out.push_str("  } else {\n    return 0;\n  }\n");
    out.push_str("  memcpy(code + site, &word, 4);\n  return 1;\n}\n\n");
    out.push_str("static int32_t axis_jit_count(void) { return AXIS_JIT_STENCIL_COUNT; }\n");
    out.push_str("static int axis_jit_in_range(int32_t s) { return s >= 0 && s < AXIS_JIT_STENCIL_COUNT; }\n");
    out.push_str("static const char *axis_jit_mnemonic(int32_t s) {\n  return axis_jit_in_range(s) ? AXIS_JIT_STENCILS[s].mnemonic : NULL;\n}\n");
    out.push_str("static int32_t axis_jit_holes(int32_t s) {\n  return axis_jit_in_range(s) ? (int32_t)AXIS_JIT_STENCILS[s].holes : 0;\n}\n");
    out.push_str("static int32_t axis_jit_values(int32_t s) {\n  return axis_jit_in_range(s) ? (int32_t)AXIS_JIT_STENCILS[s].values : 0;\n}\n");
    out.push_str("static int32_t axis_jit_effectful(int32_t s) {\n  return axis_jit_in_range(s) ? (int32_t)AXIS_JIT_STENCILS[s].effectful : 0;\n}\n");
    out.push_str("static int32_t axis_jit_word_bits(int32_t s) {\n  return axis_jit_in_range(s) ? (int32_t)AXIS_JIT_STENCILS[s].word_bits : 0;\n}\n");
    out.push_str("static int32_t axis_jit_scratch_slots(void) { return AXIS_JIT_SCRATCH_SLOTS; }\n");
    out.push_str("static int32_t axis_jit_reads_state(int32_t s) {\n  return axis_jit_in_range(s) ? (int32_t)AXIS_JIT_STENCILS[s].reads_state : 0;\n}\n");
    out.push_str("static const char *axis_jit_hole(int32_t s, int32_t index) {\n");
    out.push_str("  if (!axis_jit_in_range(s) || index < 0) { return NULL; }\n");
    out.push_str("  const axis_jit_stencil *st = &AXIS_JIT_STENCILS[s];\n");
    out.push_str("  return index < (int32_t)st->holes ? st->names[index] : NULL;\n}\n");
    out.push_str("static int32_t axis_jit_stencil_for(const char *mnemonic) {\n");
    out.push_str("  if (!mnemonic) { return -1; }\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_JIT_STENCIL_COUNT; ++i) {\n");
    out.push_str("    if (!strcmp(AXIS_JIT_STENCILS[i].mnemonic, mnemonic)) { return i; }\n  }\n");
    out.push_str("  return -1;\n}\n\n");
    out.push_str("/* Lay one stencil per op, patched. Each ends in `ret`; a block drops all\n   but the last, so control falls from each into the next. Nothing else is\n   rewritten -- that is the whole claim, and why translation is a copy and a\n   few stores rather than a compile. */\n");
    out.push_str("static int32_t axis_jit_translate(const axis_jit_op *ops, int32_t count,\n                                  uint8_t *buffer, size_t size, uint64_t exec_base,\n                                  const axis_jit_machine *machine, size_t *out_used) {\n");
    out.push_str("  if (!ops || !buffer || !machine || count <= 0) { return 0; }\n");
    out.push_str("  size_t code_size = 4;                 /* the block's own final `ret` */\n");
    out.push_str("  size_t slots = 0;\n");
    out.push_str("  for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("    if (!axis_jit_in_range(ops[i].stencil)) { return 0; }\n");
    out.push_str("    const axis_jit_stencil *s = &AXIS_JIT_STENCILS[ops[i].stencil];\n");
    out.push_str("    if (ops[i].value_count != (int32_t)s->values) { return 0; }\n");
    out.push_str("    code_size += s->size - 4;           /* its `ret` falls through */\n");
    out.push_str("    slots += s->holes;\n  }\n");
    // ⚠️ Eight-aligned, because a slot is read by a `ldr x` whose offset field
    // is SCALED by eight: an odd multiple of four cannot be expressed at all,
    // and the patcher refuses it rather than round it. The code before it is a
    // multiple of four instructions, so without this the slots land on a
    // four-byte boundary half the time and every block with a doubleword load
    // of a slot fails to translate -- which is what happened the first time a
    // stencil loaded a value from a hole instead of an address.
    out.push_str("  size_t block_base = (code_size + (AXIS_JIT_SLOT - 1)) & ~(size_t)(AXIS_JIT_SLOT - 1);\n");
    out.push_str("  size_t total = block_base + slots * AXIS_JIT_SLOT;\n");
    out.push_str("  if (total > size) { return 0; }\n");
    out.push_str("  memset(buffer, 0, total);\n");
    out.push_str("  size_t at = 0, slot_at = block_base;\n");
    out.push_str("  for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("    const axis_jit_stencil *s = &AXIS_JIT_STENCILS[ops[i].stencil];\n");
    out.push_str("    uint8_t *here = buffer + at;\n");
    out.push_str("    memcpy(here, AXIS_JIT_CODE + s->offset, s->size);\n");
    out.push_str("    for (uint32_t r = 0; r < s->reloc_count; ++r) {\n");
    out.push_str("      const axis_jit_reloc *rel = &AXIS_JIT_RELOCS[s->reloc + r];\n");
    out.push_str("      if (rel->site >= s->size) { continue; }\n");
    out.push_str("      uint64_t target = exec_base + slot_at + (uint64_t)rel->hole * AXIS_JIT_SLOT;\n");
    out.push_str("      uint64_t pc = exec_base + at + rel->site;\n");
    out.push_str("      if (rel->kind == AXIS_JIT_PAGE21) { axis_jit_page21(here, rel->site, target, pc); }\n");
    out.push_str("      else if (!axis_jit_pageoff12(here, rel->site, target)) { return 0; }\n    }\n");
    out.push_str("    /* Each hole gets what its KIND says: a machine part from the block's\n       one machine, an operand from this op's values, in order. */\n");
    out.push_str("    int32_t taken = 0;\n");
    out.push_str("    for (uint32_t h = 0; h < s->holes; ++h) {\n");
    out.push_str("      uint64_t slot_value = 0;\n");
    out.push_str("      switch (s->kinds[h]) {\n");
    out.push_str("        case AXIS_JIT_REGS:    slot_value = machine->registers; break;\n");
    out.push_str("        case AXIS_JIT_MEMORY:  slot_value = machine->memory; break;\n");
    out.push_str("        case AXIS_JIT_SCRATCH: slot_value = machine->scratch; break;\n");
    out.push_str("        case AXIS_JIT_STATE:   slot_value = machine->state; break;\n");
    out.push_str("        case AXIS_JIT_PC:      slot_value = ops[i].pc; break;\n");
    out.push_str("        case AXIS_JIT_MASK:    slot_value = machine->memory_mask; break;\n");
    out.push_str("        default:\n");
    out.push_str("          if (taken >= ops[i].value_count) { return 0; }\n");
    out.push_str("          slot_value = ops[i].values[taken++];\n");
    out.push_str("          break;\n      }\n");
    out.push_str("      memcpy(buffer + slot_at + (size_t)h * AXIS_JIT_SLOT, &slot_value, AXIS_JIT_SLOT);\n    }\n");
    out.push_str("    slot_at += (size_t)s->holes * AXIS_JIT_SLOT;\n");
    out.push_str("    at += s->size - 4;\n  }\n");
    out.push_str("  uint32_t ret = AXIS_JIT_RET;\n  memcpy(buffer + at, &ret, 4);\n");
    out.push_str("  if (out_used) { *out_used = total; }\n  return 1;\n}\n\n");
    out.push_str(&format!(
        "static const axis_jit_pack AXIS_JIT_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  \
{}, {}, {}, AXIS_JIT_HOST,\n  axis_jit_count, axis_jit_stencil_for, axis_jit_mnemonic,\n  \
axis_jit_holes, axis_jit_values,\n  axis_jit_effectful,\n  axis_jit_word_bits, axis_jit_scratch_slots,\n  axis_jit_reads_state, axis_jit_hole, axis_jit_translate\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_jit_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_jit_pack *axis_jit_pack_{ident}(void) {{ return &AXIS_JIT_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

pub fn emit_pack_disasm_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's disassembler, as a library. */\n");
    out.push_str("/* schema: axis.pack-disasm-c.v1 */\n");
    out.push_str("#include <ctype.h>\n#include <stdio.h>\n#include <string.h>\n#include \"axis_pack.h\"\n\n");
    out.push_str(&pack_body(document));
    out.push_str(&pack_text_machinery(document));
    // ⚠️ One call, and it refuses rather than guesses. A word two instructions
    // both claim is not one this can name -- the description spells them the
    // same way, which `pack_check` counts -- and answering with whichever came
    // first in the table is what a disassembler must never do.
    out.push_str("static int32_t axis_disasm_one(uint32_t word, const char *isa, char *out, size_t size) {\n");
    out.push_str("  int32_t index = axis_abi_decode(word, isa);\n");
    out.push_str("  if (index < 0 || !out || !size) { return 0; }\n");
    out.push_str("  uint32_t values[32];\n");
    out.push_str("  int32_t count = axis_abi_operand_count(index);\n");
    out.push_str("  if (count > 32) { return 0; }\n");
    out.push_str("  for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("    values[i] = axis_abi_operand_value(word, index, i);\n  }\n");
    out.push_str("  return axis_asm_print(index, values, out, size);\n}\n\n");
    out.push_str(&format!(
        "static const axis_disasm_pack AXIS_DISASM_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  \
{}, {}, {},\n  axis_abi_count,\n  axis_disasm_one,\n  axis_abi_decode, axis_asm_print,\n  \
axis_abi_mnemonic, axis_abi_operand_count, axis_abi_operand_value\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_disasm_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_disasm_pack *axis_disasm_pack_{ident}(void) {{ return &AXIS_DISASM_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

pub fn emit_pack_asm_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's assembler, as a library. */\n");
    out.push_str("/* schema: axis.pack-asm-c.v1 */\n");
    out.push_str("#include <ctype.h>\n#include <stdio.h>\n#include <string.h>\n#include \"axis_pack.h\"\n\n");
    out.push_str(&pack_body(document));
    out.push_str(&pack_text_machinery(document));
    out.push_str(&format!(
        "static const axis_asm_pack AXIS_ASM_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  \
{}, {}, {},\n  axis_abi_count,\n  axis_abi_mnemonic, axis_abi_asm_syntax,\n  \
axis_abi_operand_count, axis_abi_operand_name, axis_abi_operand_kind,\n  \
axis_abi_assemble,\n  axis_asm_printed, axis_asm_encoded,\n  axis_asm_bits, axis_asm_signed_bits,\n  axis_asm_print, axis_asm_parse\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_asm_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_asm_pack *axis_asm_pack_{ident}(void) {{ return &AXIS_ASM_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

/// The lifter library: a word to what it says, behind the contract's shapes.
///
/// An adapter over `axis_lift.h`, which is `static inline` throughout. That is
/// the whole reason this exists rather than exporting the header's own types: a
/// second description's header in the same translation unit would redefine
/// `axis_lift_entry` and clash on every static table, so each library compiles
/// its own and meets the others only at `axis_pack.h`.
pub fn emit_pack_lift_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's lifter, as a library. */\n");
    out.push_str("/* schema: axis.pack-lift-c.v1 */\n");
    // ⚠️ `axis_exec.h` for one function: `axis_operand_slot`, the rule that
    // turns an operand's value into a slot of the flat file. It lives with the
    // executor because that is what indexes the file, and a copy here would be
    // a second answer about where `x9` is.
    out.push_str("#include <string.h>\n#include \"axis_pack.h\"\n#include \"axis_lift.h\"\n");
    out.push_str("#include \"axis_semantics.h\"\n#include \"axis_exec.h\"\n\n");
    // The bound the contract fixes, checked against what this description
    // actually needs. A corpus that outgrows it stops the build here, naming
    // the bound, rather than losing operands at run time.
    out.push_str("_Static_assert(AXIS_LIFT_MAX_OPERANDS <= AXIS_PACK_MAX_OPERANDS,\n");
    out.push_str("               \"this description has more operands than AXIS_PACK_MAX_OPERANDS\");\n\n");
    out.push_str("static int32_t pack_count(void) { return (int32_t)AXIS_LIFT_TABLE_LEN; }\n");
    out.push_str("static int pack_in_range(int32_t index) {\n  return index >= 0 && (size_t)index < AXIS_LIFT_TABLE_LEN;\n}\n");
    out.push_str("static const char *pack_mnemonic(int32_t i) { return pack_in_range(i) ? AXIS_LIFT_TABLE[i].mnemonic : NULL; }\n");
    out.push_str("static const char *pack_isa(int32_t i) { return pack_in_range(i) ? AXIS_LIFT_TABLE[i].isa : NULL; }\n");
    out.push_str("static int32_t pack_operand_count(int32_t i) { return pack_in_range(i) ? AXIS_LIFT_TABLE[i].operand_count : 0; }\n");
    out.push_str("static int pack_operand_ok(int32_t i, int32_t o) {\n  return pack_in_range(i) && o >= 0 && o < AXIS_LIFT_TABLE[i].operand_count;\n}\n");
    out.push_str("static const char *pack_operand_name(int32_t i, int32_t o) { return pack_operand_ok(i, o) ? AXIS_LIFT_TABLE[i].operands[o].name : NULL; }\n");
    out.push_str("static const char *pack_operand_kind(int32_t i, int32_t o) { return pack_operand_ok(i, o) ? AXIS_LIFT_TABLE[i].operands[o].kind : NULL; }\n");
    out.push_str("static const char *pack_operand_role(int32_t i, int32_t o) { return pack_operand_ok(i, o) ? AXIS_LIFT_TABLE[i].operands[o].role : NULL; }\n");
    out.push_str("static uint32_t pack_operand_width(int32_t i, int32_t o) { return pack_operand_ok(i, o) ? AXIS_LIFT_TABLE[i].operands[o].width : 0u; }\n");
    out.push_str("/* The generated lifter already knows this -- a class's offset, its\n   window, its limbs -- and a pack that recomputed it would be a second\n   answer to a question the description settles. */\n");
    out.push_str("static uint32_t pack_register_slot(int32_t i, int32_t o, uint32_t value) {\n");
    out.push_str("  if (!pack_operand_ok(i, o)) { return 0u; }\n");
    out.push_str("  return axis_operand_slot(&AXIS_LIFT_TABLE[i].operands[o], value);\n}\n");
    out.push_str("static int32_t pack_liftable(int32_t i) { return pack_in_range(i) ? (int32_t)AXIS_LIFT_TABLE[i].liftable : 0; }\n\n");
    out.push_str("static int32_t pack_lift(uint32_t word, const char *isa, axis_pack_lifted *out) {\n");
    out.push_str("  if (!out) { return 0; }\n");
    out.push_str("  axis_lifted lifted;\n");
    out.push_str("  if (!axis_lift_in_isa(word, isa, &lifted)) { out->index = -1; out->operand_count = 0; return 0; }\n");
    out.push_str("  out->index = (int32_t)(lifted.entry - AXIS_LIFT_TABLE);\n");
    out.push_str("  out->operand_count = lifted.entry->operand_count;\n");
    out.push_str("  for (int32_t i = 0; i < AXIS_PACK_MAX_OPERANDS; ++i) {\n");
    out.push_str("    int inside = i < lifted.entry->operand_count;\n");
    out.push_str("    out->operands[i] = inside ? lifted.operands[i] : 0u;\n");
    out.push_str("    out->operand_valid[i] = (uint8_t)(inside ? (lifted.operand_valid[i] ? 1 : 0) : 0);\n");
    out.push_str("  }\n  return 1;\n}\n\n");

    out.push_str("static uint32_t pack_instruction_bits(int32_t i) { return pack_in_range(i) ? AXIS_LIFT_TABLE[i].bits : 0u; }\n");
    /* Out of range is `2`, not `0`. Every other accessor here answers a bad
       index with a harmless zero; this one's zero means "control cannot leave
       here", which is the dangerous answer to give about an instruction the
       library does not have. */
    out.push_str("static int32_t pack_ends_block(int32_t i) { return pack_in_range(i) ? AXIS_LIFT_TABLE[i].ends_block : 2; }\n\n");
    /* The narrowest instruction in the table, which is how far a walk steps
       over bytes that decode to nothing. Computed once per call rather than
       baked in: it is a fact about the table and the table is right there. */
    out.push_str("static int32_t pack_step_bytes(void) {\n");
    out.push_str("  uint32_t narrowest = 32u;\n");
    out.push_str("  for (size_t i = 0; i < AXIS_LIFT_TABLE_LEN; ++i) {\n");
    out.push_str("    if (AXIS_LIFT_TABLE[i].bits && AXIS_LIFT_TABLE[i].bits < narrowest) {\n");
    out.push_str("      narrowest = AXIS_LIFT_TABLE[i].bits;\n    }\n  }\n");
    out.push_str("  const int32_t step = (int32_t)(narrowest / 8u);\n");
    out.push_str("  return step > 0 ? step : 4;\n}\n\n");
    out.push_str("static int32_t pack_walk_until(const uint8_t *bytes, int32_t byte_count, uint64_t base,\n");
    out.push_str("                               const char *isa, axis_pack_walked *out, int32_t limit,\n");
    out.push_str("                               int stop_at_block_end) {\n");
    out.push_str("  if (!bytes || byte_count < 0 || !out || limit < 0) { return -1; }\n");
    out.push_str("  const int32_t step = pack_step_bytes();\n");
    out.push_str("  int32_t at = 0, found = 0;\n");
    /* ⚠️ `at + 2`, not `at + 4`: a 16-bit instruction at the very end of a
       section has no upper half to read, and requiring four bytes would drop
       it. The word is assembled from what is there. */
    out.push_str("  while (at + 2 <= byte_count && found < limit) {\n");
    out.push_str("    uint32_t word = (uint32_t)bytes[at] | ((uint32_t)bytes[at + 1] << 8);\n");
    out.push_str("    if (at + 4 <= byte_count) {\n");
    out.push_str("      word |= ((uint32_t)bytes[at + 2] << 16) | ((uint32_t)bytes[at + 3] << 24);\n");
    out.push_str("    }\n");
    out.push_str("    axis_pack_walked *row = &out[found];\n");
    out.push_str("    memset(row, 0, sizeof *row);\n");
    out.push_str("    row->offset = at;\n    row->address = base + (uint64_t)at;\n");
    out.push_str("    row->word = word;\n    row->index = -1;\n");
    out.push_str("    axis_lifted lifted;\n");
    out.push_str("    if (axis_lift_in_isa(word, isa, &lifted) && lifted.entry) {\n");
    out.push_str("      row->index = (int32_t)(lifted.entry - AXIS_LIFT_TABLE);\n");
    out.push_str("      row->ends_block = lifted.entry->ends_block;\n");
    out.push_str("      int32_t count = lifted.entry->operand_count;\n");
    out.push_str("      if (count > AXIS_PACK_MAX_OPERANDS) { count = AXIS_PACK_MAX_OPERANDS; }\n");
    out.push_str("      row->operand_count = count;\n");
    out.push_str("      for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("        row->operands[i] = lifted.operands[i];\n");
    out.push_str("        row->operand_valid[i] = (uint8_t)(lifted.operand_valid[i] ? 1 : 0);\n      }\n");
    out.push_str("      const int32_t width = (int32_t)(lifted.entry->bits / 8u);\n");
    out.push_str("      row->bytes = width > 0 ? width : step;\n");
    out.push_str("    } else {\n");
    /* ⚠️ Bytes that decode to nothing END A BLOCK too, and say so with the
       same `2` a routine's instruction uses: a consumer that kept walking
       through a literal pool would be reporting the pool's contents as the
       instructions that follow the branch. */
    out.push_str("      row->bytes = step;\n      row->ends_block = 2;\n");
    out.push_str("    }\n");
    out.push_str("    at += row->bytes;\n    ++found;\n");
    out.push_str("    if (stop_at_block_end && row->ends_block) { break; }\n");
    out.push_str("  }\n  return found;\n}\n\n");
    out.push_str("static int32_t pack_walk(const uint8_t *bytes, int32_t byte_count, uint64_t base,\n");
    out.push_str("                         const char *isa, axis_pack_walked *out, int32_t limit) {\n");
    out.push_str("  return pack_walk_until(bytes, byte_count, base, isa, out, limit, 0);\n}\n");
    out.push_str("static int32_t pack_block(const uint8_t *bytes, int32_t byte_count, uint64_t base,\n");
    out.push_str("                          const char *isa, axis_pack_walked *out, int32_t limit) {\n");
    out.push_str("  return pack_walk_until(bytes, byte_count, base, isa, out, limit, 1);\n}\n\n");

    out.push_str(&format!(
        "static const axis_lift_pack AXIS_LIFT_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  \
{}, {}, {},\n  pack_count, pack_lift, pack_mnemonic, pack_isa,\n  \
pack_operand_count, pack_operand_name, pack_operand_kind, pack_operand_role,\n  \
pack_operand_width, pack_register_slot, pack_liftable,\n  \
pack_instruction_bits, pack_ends_block, pack_walk, pack_block\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_lift_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_lift_pack *axis_lift_pack_{ident}(void) {{ return &AXIS_LIFT_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

/// The executor library: a machine, behind the contract's shapes.
/// The registry that lets a HOST supply what a pack could not be built with.
///
/// ⚠️ The whole point is that a pack is a file on disk. An instruction the
/// description names a routine for -- pointer authentication, a cipher round --
/// has no body in a pack, because the body belongs to whoever has the key, and
/// that program is not the one that ran the C compiler. Registration is how the
/// two meet: the generated executor's placeholders call a bridge, and this is
/// the bridge, translating the executor's types into the contract's at the one
/// boundary where they meet.
///
/// Emitted into both the executor pack and the simulator pack, which are
/// separate libraries with separate copies of the placeholders -- so each
/// carries its own registry and binding one says nothing about the other.
fn pack_routine_registry(document: &Document) -> String {
    let routines = document
        .instructions
        .iter()
        .filter(|instruction| {
            let answer = instruction.implementation.trim();
            !answer.is_empty() && answer != crate::ast::UNSUPPLIED
        })
        .count();
    let mut out = String::new();
    if routines == 0 {
        out.push_str("/* This description names no routine it does not describe. */\n");
        out.push_str("static int32_t pack_routine_count(void) { return 0; }\n");
        out.push_str("static const char *pack_routine_name(int32_t slot) { (void)slot; return NULL; }\n");
        out.push_str("static const char *pack_routine_mnemonic(int32_t slot) { (void)slot; return NULL; }\n");
        out.push_str("static int32_t pack_register_routine(const char *name, axis_pack_routine fn) {\n");
        out.push_str("  (void)name; (void)fn; return 0;\n}\n\n");
        return out;
    }
    out.push_str("#if defined(AXIS_IMPL_STUBS_INTERNAL)\n");
    out.push_str("/* The routines this build has placeholders for, and the table a host\n   fills. Indexed by the number the placeholder passes, so the call costs\n   no string compare -- the compare happens once, when binding. */\n");
    out.push_str("static axis_pack_routine AXIS_PACK_ROUTINES[");
    out.push_str(&format!("{routines}"));
    out.push_str("];\n");
    out.push_str("static int32_t pack_routine_count(void) { return axis_impl_routine_count(); }\n");
    out.push_str("static const char *pack_routine_name(int32_t slot) { return axis_impl_routine_name(slot); }\n");
    out.push_str("static const char *pack_routine_mnemonic(int32_t slot) { return axis_impl_routine_mnemonic(slot); }\n\n");
    // The host's memory, the other way round. `pack_mem_read` bridges the
    // contract's memory into the executor's; a routine is called from inside
    // the executor and needs the reverse, and the two structs having the same
    // shape today is still not a promise either file makes.
    out.push_str("static uint64_t pack_routine_mem_read(void *ctx, uint64_t addr, uint32_t width) {\n");
    out.push_str("  const axis_mem64 *m = (const axis_mem64 *)ctx;\n");
    out.push_str("  return m && m->read ? m->read(m->ctx, addr, width) : 0u;\n}\n");
    out.push_str("static void pack_routine_mem_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {\n");
    out.push_str("  const axis_mem64 *m = (const axis_mem64 *)ctx;\n");
    out.push_str("  if (m && m->write) { m->write(m->ctx, addr, value, width); }\n}\n\n");
    out.push_str("static void pack_routine_bridge(int32_t routine, const axis_lifted *lifted, uint64_t *regs,\n");
    out.push_str("                               size_t reg_count, const axis_mem64 *mem, uint64_t pc,\n");
    out.push_str("                               axis_state64 *state, axis_exec_result64 *r) {\n");
    out.push_str("  axis_pack_routine fn = (routine >= 0 && routine < pack_routine_count())\n");
    out.push_str("                       ? AXIS_PACK_ROUTINES[routine] : NULL;\n");
    out.push_str(&format!(
        "  /* Registered for another routine and not this one: the same trap an\n     undescribed instruction reports, because that is what this is. */\n  if (!fn) {{ r->trapped = 1; r->trap_cause = {}; return; }}\n",
        c_string(crate::ast::UNSUPPLIED_TRAP)
    ));
    out.push_str("  axis_pack_lifted view;\n  memset(&view, 0, sizeof view);\n  view.index = -1;\n");
    out.push_str("  if (lifted && lifted->entry) {\n");
    out.push_str("    view.index = (int32_t)(lifted->entry - AXIS_LIFT_TABLE);\n");
    out.push_str("    int32_t count = (int32_t)lifted->entry->operand_count;\n");
    out.push_str("    if (count > AXIS_PACK_MAX_OPERANDS) { count = AXIS_PACK_MAX_OPERANDS; }\n");
    out.push_str("    view.operand_count = count;\n");
    out.push_str("    for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("      view.operands[i] = lifted->operands[i];\n");
    out.push_str("      view.operand_valid[i] = (uint8_t)(lifted->operand_valid[i] ? 1 : 0);\n    }\n  }\n");
    out.push_str("  axis_pack_state_entry entries[64];\n  int32_t n = 0;\n");
    out.push_str("  if (state && state->entries) {\n");
    out.push_str("    n = (int32_t)(state->count < 64 ? state->count : 64);\n");
    out.push_str("    for (int32_t i = 0; i < n; ++i) {\n");
    out.push_str("      entries[i].name = state->entries[i].name;\n");
    out.push_str("      entries[i].value = state->entries[i].value;\n");
    out.push_str("      entries[i].width = state->entries[i].width;\n    }\n  }\n");
    out.push_str("  axis_pack_mem bridged = { pack_routine_mem_read, pack_routine_mem_write, (void *)mem };\n");
    out.push_str("  axis_pack_exec_result out;\n  memset(&out, 0, sizeof out);\n");
    // ⚠️ Seeded, not zeroed: the executor has already decided what the next pc
    // is when nothing branches, and a routine that only writes a register must
    // not have to restate it -- one that did not know to would silently make
    // every such instruction jump to zero.
    out.push_str("  out.mnemonic = r->mnemonic;\n  out.next_pc = r->next_pc;\n");
    out.push_str("  fn(&view, regs, (int32_t)reg_count, mem ? &bridged : NULL, pc, entries, n, &out);\n");
    out.push_str("  /* The machine's copy is authoritative, so what the routine changed goes back. */\n");
    out.push_str("  if (state && state->entries) {\n");
    out.push_str("    for (int32_t i = 0; i < n; ++i) { state->entries[i].value = entries[i].value; }\n  }\n");
    out.push_str("  r->result = out.result;\n");
    out.push_str("  r->result_limbs = out.result_limbs;\n");
    out.push_str("  for (uint32_t i = 0; i < out.result_limbs && i < AXIS_EXEC_MAX_LIMBS; ++i) {\n");
    out.push_str("    r->result_limb[i] = out.result_limb[i];\n  }\n");
    out.push_str("  r->wrote = out.wrote; r->dest = out.dest; r->dest_slot = out.dest_slot;\n");
    out.push_str("  r->state_name = out.state_name; r->state_value = out.state_value;\n");
    out.push_str("  r->next_pc = out.next_pc;\n");
    out.push_str("");
    out.push_str("  r->trapped = out.trapped; r->trap_cause = out.trap_cause;\n}\n\n");
    out.push_str("static int32_t pack_register_routine(const char *name, axis_pack_routine fn) {\n");
    out.push_str("  if (!name) { return 0; }\n  int32_t bound = 0;\n");
    out.push_str("  /* By name, so one routine covers every instruction the description\n     gives it -- and the count says how many, which is how a host notices\n     it bound a name the pack does not have. */\n");
    out.push_str("  for (int32_t i = 0; i < pack_routine_count(); ++i) {\n");
    out.push_str("    const char *have = pack_routine_name(i);\n");
    out.push_str("    if (have && strcmp(have, name) == 0) { AXIS_PACK_ROUTINES[i] = fn; ++bound; }\n  }\n");
    out.push_str("  if (bound) { axis_impl_set_bridge(pack_routine_bridge); }\n");
    out.push_str("  return bound;\n}\n");
    out.push_str("#else\n");
    out.push_str("/* Built against routines an embedder LINKED. There is nothing to register:\n   the bodies are in the library already, and a pack that let a host replace\n   them at runtime would be offering to override code the build chose. */\n");
    out.push_str("static int32_t pack_routine_count(void) { return 0; }\n");
    out.push_str("static const char *pack_routine_name(int32_t slot) { (void)slot; return NULL; }\n");
    out.push_str("static const char *pack_routine_mnemonic(int32_t slot) { (void)slot; return NULL; }\n");
    out.push_str("static int32_t pack_register_routine(const char *name, axis_pack_routine fn) {\n");
    out.push_str("  (void)name; (void)fn; return 0;\n}\n");
    out.push_str("#endif\n\n");
    out
}

/// A machine made of terms: `libaxis_sym_<name>`.
///
/// ⚠️ This library carries NO semantics. Every value it computes comes from the
/// solver library's `apply` -- the definitions `emit-smt2` proves equal to the
/// golden model -- so a consumer building an engine on it is reasoning about
/// the same meaning its executor has. What this adds is the machine: registers
/// that hold terms, memory as an array, a pc that can be a term, and the
/// constraint that says when each way out of a branch is taken.
pub fn emit_pack_sym_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let slots = crate::ast::register_file_slots(document);
    let state = crate::effects::isa_scalar_state_slots(&document.isas);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's machine, made of terms. */\n");
    out.push_str("/* schema: axis.pack-sym-c.v1 */\n");
    out.push_str("#include <stdlib.h>\n#include <string.h>\n");
    // ⚠️ The executor's header too, for `axis_operand_slot`. Which slot an
    // operand names is the generated lifter's arithmetic -- a class's offset,
    // its index offset, its stride -- and recomputing it here would be a
    // second answer to a question the description settles.
    out.push_str("#include \"axis_pack.h\"\n#include \"axis_lift.h\"\n");
    out.push_str("#include \"axis_semantics.h\"\n#include \"axis_exec.h\"\n#include <z3.h>\n\n");
    out.push_str(&format!(
        "#define AXIS_SYM_SLOTS {slots}\n#define AXIS_SYM_STATE {}\n",
        state.len().max(1)
    ));
    out.push_str("#define AXIS_SYM_PATHS 4\n#define AXIS_SYM_ASSUMED 256\n");
    out.push_str("#define AXIS_SYM_OPERANDS AXIS_PACK_MAX_OPERANDS\n\n");
    out.push_str("typedef struct { const char *name; uint32_t width; } axis_sym_slot;\n");
    out.push_str("static const axis_sym_slot AXIS_SYM_STATE_SLOTS[] = {\n");
    for (name, width) in &state {
        out.push_str(&format!("  {{ {}, {width}u }},\n", c_string(name)));
    }
    out.push_str("  { NULL, 0u }\n};\n\n");
    out.push_str(&format!(
        "static int32_t sym_state_slots(void) {{ return {}; }}\n",
        state.len()
    ));
    out.push_str("static const char *sym_state_name(int32_t s) {\n");
    out.push_str("  return s >= 0 && s < sym_state_slots() ? AXIS_SYM_STATE_SLOTS[s].name : NULL;\n}\n\n");

    // ⚠️ The machine keeps `Z3_ast` and nothing else. A symbolic register file
    // that also held a concrete shadow would be two answers about one machine.
    out.push_str("typedef struct axis_sym_machine {\n");
    out.push_str("  Z3_context ctx;\n  const axis_z3_pack *terms;\n  void *handle;\n");
    out.push_str("  int32_t regs;\n");
    out.push_str("  Z3_ast reg[AXIS_SYM_SLOTS];\n");
    out.push_str("  Z3_ast state[AXIS_SYM_STATE];\n");
    out.push_str("  Z3_ast memory;\n  Z3_ast pc;\n");
    out.push_str("  axis_sym_path path[AXIS_SYM_PATHS];\n  int32_t path_count;\n");
    out.push_str("  Z3_ast assumed[AXIS_SYM_ASSUMED];\n  int32_t assumed_count;\n");
    out.push_str("  const char *refusal;\n");
    out.push_str("} axis_sym_machine;\n\n");

    out.push_str("static Z3_ast sym_bits(axis_sym_machine *m, uint64_t value, unsigned width) {\n");
    out.push_str("  return Z3_mk_unsigned_int64(m->ctx, value, Z3_mk_bv_sort(m->ctx, width));\n}\n\n");
    // A value as wide as the term wants it: the solver refuses a mismatched
    // sort outright, which is the behaviour to preserve rather than paper over.
    out.push_str("static Z3_ast sym_fit(axis_sym_machine *m, Z3_ast value, unsigned want) {\n");
    out.push_str("  if (!value) { return NULL; }\n");
    out.push_str("  Z3_sort sort = Z3_get_sort(m->ctx, value);\n");
    out.push_str("  if (Z3_get_sort_kind(m->ctx, sort) != Z3_BV_SORT) { return value; }\n");
    out.push_str("  unsigned have = Z3_get_bv_sort_size(m->ctx, sort);\n");
    out.push_str("  if (have == want) { return value; }\n");
    out.push_str("  return have > want ? Z3_mk_extract(m->ctx, want - 1u, 0u, value)\n");
    out.push_str("                     : Z3_mk_zero_ext(m->ctx, want - have, value);\n}\n\n");
    out.push_str("static void *sym_create(void *context, const axis_z3_pack *terms, int32_t regs) {\n");
    out.push_str("  if (!context || !terms) { return NULL; }\n");
    out.push_str("  axis_sym_machine *m = (axis_sym_machine *)calloc(1, sizeof *m);\n");
    out.push_str("  if (!m) { return NULL; }\n");
    out.push_str("  m->ctx = (Z3_context)context;\n  m->terms = terms;\n");
    out.push_str("  m->handle = terms->open(context);\n");
    out.push_str("  if (!m->handle) { free(m); return NULL; }\n");
    out.push_str("  m->regs = regs > AXIS_SYM_SLOTS ? AXIS_SYM_SLOTS : regs;\n");
    // ⚠️ Free variables, named by SLOT. A consumer binds them by name to ask
    // what a program does to a register it chooses.
    out.push_str("  for (int32_t i = 0; i < m->regs; ++i) {\n");
    out.push_str("    char name[32];\n    snprintf(name, sizeof name, \"r%d\", i);\n");
    out.push_str("    m->reg[i] = Z3_mk_const(m->ctx, Z3_mk_string_symbol(m->ctx, name),\n");
    out.push_str("                            Z3_mk_bv_sort(m->ctx, 64));\n  }\n");
    out.push_str("  for (int32_t i = 0; i < sym_state_slots(); ++i) {\n");
    out.push_str("    m->state[i] = Z3_mk_const(m->ctx,\n");
    out.push_str("        Z3_mk_string_symbol(m->ctx, AXIS_SYM_STATE_SLOTS[i].name),\n");
    out.push_str("        Z3_mk_bv_sort(m->ctx, 64));\n  }\n");
    out.push_str("  /* Byte-addressed, because that is what a description's widths are in. */\n");
    out.push_str("  m->memory = Z3_mk_const(m->ctx, Z3_mk_string_symbol(m->ctx, \"mem\"),\n");
    out.push_str("      Z3_mk_array_sort(m->ctx, Z3_mk_bv_sort(m->ctx, 64), Z3_mk_bv_sort(m->ctx, 8)));\n");
    out.push_str("  m->pc = sym_bits(m, 0u, 64u);\n");
    out.push_str("  return m;\n}\n\n");
    out.push_str("static void sym_destroy(void *machine) {\n");
    out.push_str("  axis_sym_machine *m = (axis_sym_machine *)machine;\n");
    out.push_str("  if (!m) { return; }\n  if (m->handle) { m->terms->close(m->handle); }\n");
    out.push_str("  free(m);\n}\n\n");
    out.push_str("static void *sym_clone(const void *machine) {\n");
    out.push_str("  const axis_sym_machine *from = (const axis_sym_machine *)machine;\n");
    out.push_str("  if (!from) { return NULL; }\n");
    out.push_str("  axis_sym_machine *m = (axis_sym_machine *)calloc(1, sizeof *m);\n");
    out.push_str("  if (!m) { return NULL; }\n  memcpy(m, from, sizeof *m);\n");
    out.push_str("  /* ⚠️ Its own handle: closing one machine must not take the other's\n     bound definitions with it. The terms are the solver's and are shared. */\n");
    out.push_str("  m->handle = from->terms->open((void *)from->ctx);\n");
    out.push_str("  if (!m->handle) { free(m); return NULL; }\n  return m;\n}\n\n");
    out.push_str("static void *sym_reg(const void *machine, int32_t slot) {\n");
    out.push_str("  const axis_sym_machine *m = (const axis_sym_machine *)machine;\n");
    out.push_str("  return m && slot >= 0 && slot < m->regs ? (void *)m->reg[slot] : NULL;\n}\n");
    out.push_str("static void sym_set_reg(void *machine, int32_t slot, void *term) {\n");
    out.push_str("  axis_sym_machine *m = (axis_sym_machine *)machine;\n");
    out.push_str("  if (m && slot >= 0 && slot < m->regs && term) { m->reg[slot] = (Z3_ast)term; }\n}\n");
    out.push_str("static void *sym_pc(const void *machine) {\n  const axis_sym_machine *m = machine;\n  return m ? (void *)m->pc : NULL;\n}\n");
    out.push_str("static void sym_set_pc(void *machine, void *term) {\n  axis_sym_machine *m = machine;\n  if (m && term) { m->pc = (Z3_ast)term; }\n}\n");
    out.push_str("static void *sym_memory(const void *machine) {\n  const axis_sym_machine *m = machine;\n  return m ? (void *)m->memory : NULL;\n}\n");
    out.push_str("static void sym_set_memory(void *machine, void *array) {\n  axis_sym_machine *m = machine;\n  if (m && array) { m->memory = (Z3_ast)array; }\n}\n");
    out.push_str("static void *sym_state(const void *machine, int32_t slot) {\n");
    out.push_str("  const axis_sym_machine *m = machine;\n");
    out.push_str("  return m && slot >= 0 && slot < sym_state_slots() ? (void *)m->state[slot] : NULL;\n}\n");
    out.push_str("static void sym_set_state(void *machine, int32_t slot, void *term) {\n");
    out.push_str("  axis_sym_machine *m = machine;\n");
    out.push_str("  if (m && slot >= 0 && slot < sym_state_slots() && term) { m->state[slot] = (Z3_ast)term; }\n}\n");
    out.push_str("static const char *sym_refusal(const void *machine) {\n  const axis_sym_machine *m = machine;\n  return m ? m->refusal : NULL;\n}\n");
    out.push_str("static int32_t sym_paths(const void *machine) {\n  const axis_sym_machine *m = machine;\n  return m ? m->path_count : 0;\n}\n");
    out.push_str("static axis_sym_path sym_path(const void *machine, int32_t which) {\n");
    out.push_str("  const axis_sym_machine *m = machine;\n  axis_sym_path none = { NULL, NULL };\n");
    out.push_str("  return m && which >= 0 && which < m->path_count ? m->path[which] : none;\n}\n");
    out.push_str("static int32_t sym_constraints(const void *machine) {\n  const axis_sym_machine *m = machine;\n  return m ? m->assumed_count : 0;\n}\n");
    out.push_str("static void *sym_constraint(const void *machine, int32_t which) {\n");
    out.push_str("  const axis_sym_machine *m = machine;\n");
    out.push_str("  return m && which >= 0 && which < m->assumed_count ? (void *)m->assumed[which] : NULL;\n}\n");
    out.push_str("static void sym_assume(void *machine, void *term) {\n");
    out.push_str("  axis_sym_machine *m = machine;\n");
    out.push_str("  if (m && term && m->assumed_count < AXIS_SYM_ASSUMED) { m->assumed[m->assumed_count++] = (Z3_ast)term; }\n}\n\n");

    // ⚠️ Binding a term's operands is the whole of the plumbing, and the whole
    // of what can go quietly wrong. A term names its operands; the lifted word
    // carries values for names. A register operand contributes the machine's
    // TERM for the slot it names -- `register_slot`, not the field, because a
    // compressed field's 1 is `x9` -- and an immediate contributes a constant.
    // An operand a term wants and the word does not carry is a refusal, never
    // a zero.
    out.push_str("static Z3_ast sym_bind(axis_sym_machine *m, int32_t term,\n");
    out.push_str("                       const axis_lift_entry *entry, const axis_lifted *lifted) {\n");
    out.push_str("  Z3_ast operands[AXIS_SYM_OPERANDS];\n");
    out.push_str("  int32_t arity = m->terms->arity(m->handle, term);\n");
    out.push_str("  if (arity > AXIS_SYM_OPERANDS) { m->refusal = \"the term takes more operands than the contract carries\"; return NULL; }\n");
    out.push_str("  for (int32_t a = 0; a < arity; ++a) {\n");
    out.push_str("    const char *want = m->terms->operand_name(m->handle, term, a);\n");
    out.push_str("    uint32_t bits = m->terms->operand_bits(m->handle, term, a);\n");
    out.push_str("    Z3_ast bound = NULL;\n");
    out.push_str("    if (!want) { m->refusal = \"a term operand with no name\"; return NULL; }\n");
    // ⚠️ Four kinds of parameter, not one. A proven term takes the
    // instruction's operands, the PC, every named state slot, and the ENTRY
    // value of an operand it also writes -- `__input_rs1`, which is what makes
    // `rd = rd + imm` mean the old `rd`. Binding only the first kind refused
    // every branch in the description, because a branch's target is a function
    // of the pc.
    out.push_str("    if (!strcmp(want, \"pc\")) { operands[a] = sym_fit(m, m->pc, bits ? bits : 64u); continue; }\n");
    out.push_str("    for (int32_t sslot = 0; sslot < sym_state_slots() && !bound; ++sslot) {\n");
    out.push_str("      if (!strcmp(want, AXIS_SYM_STATE_SLOTS[sslot].name)) {\n");
    out.push_str("        bound = sym_fit(m, m->state[sslot], bits ? bits : 64u);\n      }\n    }\n");
    out.push_str("    if (bound) { operands[a] = bound; continue; }\n");
    out.push_str("    /* The value an operand had on ENTRY, which for a step that has not\n       written anything yet is the value it has. */\n");
    out.push_str("    const char *entry_of = strncmp(want, \"__input_\", 8) ? want : want + 8;\n");
    out.push_str("    for (int32_t o = 0; o < entry->operand_count && !bound; ++o) {\n");
    out.push_str("      const axis_lift_operand *operand = &entry->operands[o];\n");
    out.push_str("      if (!operand->name || strcmp(entry_of, operand->name)) { continue; }\n");
    out.push_str("      if (!lifted->operand_valid[o]) { break; }\n");
    out.push_str("      if (!strcmp(operand->kind, \"imm\")) {\n");
    out.push_str("        bound = sym_bits(m, (uint64_t)lifted->operands[o], bits ? bits : 64u);\n");
    out.push_str("      } else {\n");
    out.push_str("        uint32_t slot = axis_operand_slot(operand, lifted->operands[o]);\n");
    out.push_str("        if ((int32_t)slot >= m->regs) { break; }\n");
    out.push_str("        bound = sym_fit(m, m->reg[slot], bits ? bits : 64u);\n");
    out.push_str("      }\n    }\n");
    out.push_str("    if (!bound) { m->refusal = \"an operand the term wants, which this word does not carry\"; return NULL; }\n");
    out.push_str("    operands[a] = bound;\n  }\n");
    out.push_str("  return (Z3_ast)m->terms->apply(m->handle, term, (void *const *)operands, arity);\n}\n\n");

    // ⚠️ A guarded write is an `ite`, not a skipped one. A store-conditional
    // that fails leaves the byte alone, and an engine that assumed it succeeded
    // would be describing half the machine.
    out.push_str("static Z3_ast sym_guarded(axis_sym_machine *m, Z3_ast guard, Z3_ast taken, Z3_ast kept) {\n");
    out.push_str("  if (!guard) { return taken; }\n");
    out.push_str("  Z3_ast one = sym_bits(m, 1u, Z3_get_bv_sort_size(m->ctx, Z3_get_sort(m->ctx, guard)));\n");
    out.push_str("  return Z3_mk_ite(m->ctx, Z3_mk_eq(m->ctx, guard, one), taken, kept);\n}\n\n");
    // Memory, byte by byte and little end first. The same decomposition the
    // executors make, so a term and a run agree about which byte moved.
    out.push_str("static Z3_ast sym_store(axis_sym_machine *m, Z3_ast array, Z3_ast addr,\n");
    out.push_str("                        Z3_ast value, uint32_t width, Z3_ast guard) {\n");
    out.push_str("  uint32_t bytes = (width + 7u) / 8u;\n");
    out.push_str("  Z3_ast wide = sym_fit(m, value, bytes * 8u);\n");
    out.push_str("  for (uint32_t i = 0; i < bytes; ++i) {\n");
    out.push_str("    Z3_ast at = Z3_mk_bvadd(m->ctx, sym_fit(m, addr, 64u), sym_bits(m, i, 64u));\n");
    out.push_str("    Z3_ast byte = Z3_mk_extract(m->ctx, 8u * i + 7u, 8u * i, wide);\n");
    out.push_str("    Z3_ast kept = Z3_mk_select(m->ctx, array, at);\n");
    out.push_str("    array = Z3_mk_store(m->ctx, array, at, sym_guarded(m, guard, byte, kept));\n");
    out.push_str("  }\n  return array;\n}\n\n");

    // ⚠️ A register is written in LIMBS, and what lies outside the value is the
    // class's business. Writing `d1` puts sixty-four bits in the low slot of a
    // two-slot register and the architecture clears the high one; writing `q1`
    // fills both. Fitting the value to one slot dropped half of every 128-bit
    // load and left the high slot of every 64-bit one holding what it held --
    // the same pair of mistakes the stencils made, found the same way.
    out.push_str("static void sym_write_reg(axis_sym_machine *m, const axis_lift_operand *operand,\n");
    out.push_str("                          uint32_t slot, Z3_ast value, Z3_ast guard) {\n");
    out.push_str("  if (!value) { return; }\n");
    out.push_str("  const axis_reg_class *rules = axis_op_class(operand);\n");
    out.push_str("  uint32_t limbs = rules && rules->limbs ? rules->limbs : 1u;\n");
    out.push_str("  uint32_t width = operand->width ? operand->width : 64u;\n");
    out.push_str("  uint32_t carried = (width + 63u) / 64u;\n");
    out.push_str("  if (!carried) { carried = 1u; }\n");
    out.push_str("  Z3_ast wide = sym_fit(m, value, carried * 64u);\n");
    out.push_str("  if (!wide) { return; }\n");
    out.push_str("  for (uint32_t k = 0; k < limbs; ++k) {\n");
    out.push_str("    if ((int32_t)(slot + k) >= m->regs) { break; }\n");
    out.push_str("    Z3_ast piece;\n");
    out.push_str("    if (k < carried) {\n");
    out.push_str("      piece = carried == 1u ? wide\n");
    out.push_str("            : Z3_mk_extract(m->ctx, 64u * k + 63u, 64u * k, wide);\n");
    out.push_str("    } else if (rules && !rules->preserves) {\n");
    out.push_str("      piece = sym_bits(m, 0u, 64u);\n");
    out.push_str("    } else { continue; }\n");
    out.push_str("    m->reg[slot + k] = sym_guarded(m, guard, sym_fit(m, piece, 64u), m->reg[slot + k]);\n");
    out.push_str("  }\n}\n\n");
    // ⚠️ The mirror of `sym_store`. The solver library holds a load's ADDRESS
    // and says how wide the access is and whether it extends; the bytes are
    // this machine's, because this machine is the one with memory. Little end
    // first, the same decomposition the executors make, so a term and a run
    // agree about which byte moved.
    out.push_str("static Z3_ast sym_load(axis_sym_machine *m, Z3_ast addr, uint32_t width, int sign) {\n");
    out.push_str("  uint32_t bytes = (width + 7u) / 8u;\n");
    out.push_str("  if (!bytes) { return NULL; }\n");
    out.push_str("  Z3_ast base = sym_fit(m, addr, 64u);\n");
    out.push_str("  Z3_ast value = Z3_mk_select(m->ctx, m->memory, base);\n");
    out.push_str("  for (uint32_t i = 1; i < bytes; ++i) {\n");
    out.push_str("    Z3_ast at = Z3_mk_bvadd(m->ctx, base, sym_bits(m, i, 64u));\n");
    out.push_str("    value = Z3_mk_concat(m->ctx, Z3_mk_select(m->ctx, m->memory, at), value);\n  }\n");
    out.push_str("  if (width < bytes * 8u) { value = Z3_mk_extract(m->ctx, width - 1u, 0u, value); }\n");
    out.push_str("  if (width >= 64u) { return value; }\n");
    out.push_str("  return sign ? Z3_mk_sign_ext(m->ctx, 64u - width, value)\n");
    out.push_str("              : Z3_mk_zero_ext(m->ctx, 64u - width, value);\n}\n\n");
    out.push_str("static int32_t sym_step(void *machine, uint32_t word, const char *isa) {\n");
    out.push_str("  axis_sym_machine *m = (axis_sym_machine *)machine;\n");
    out.push_str("  if (!m) { return 0; }\n");
    out.push_str("  m->refusal = NULL;\n  m->path_count = 0;\n");
    out.push_str("  axis_lifted lifted;\n");
    out.push_str("  if (!axis_lift_in_isa(word, isa, &lifted) || !lifted.entry) {\n");
    out.push_str("    m->refusal = \"the word does not decode in this isa\"; return 0;\n  }\n");
    out.push_str("  const axis_lift_entry *entry = lifted.entry;\n");
    out.push_str("  int32_t index = m->terms->index_of(m->handle, entry->mnemonic);\n");
    out.push_str("  if (index < 0) { m->refusal = \"the solver library has no terms for it\"; return 0; }\n");
    out.push_str("  /* Where it goes if nothing redirects it. A description that says\n     otherwise overwrites this below. */\n");
    out.push_str("  Z3_ast fall = Z3_mk_bvadd(m->ctx, m->pc, sym_bits(m, entry->bits / 8u, 64u));\n");
    out.push_str("  Z3_ast next = fall;\n  Z3_ast branch_guard = NULL;\n  int branched = 0;\n");
    out.push_str("  int32_t effects = m->terms->effect_count(m->handle, index);\n");
    // ⚠️ An instruction with no effects is a pure VALUE, and its destination is
    // the operand the description marks. Two shapes, because the solver library
    // publishes two: `value_term` for a function of its operands, effect parts
    // for everything that writes somewhere.
    out.push_str("  if (effects <= 0) {\n");
    out.push_str("    int32_t term = m->terms->value_term(m->handle, index);\n");
    out.push_str("    if (term < 0) { m->refusal = \"no value term and no effects\"; return 0; }\n");
    out.push_str("    Z3_ast value = sym_bind(m, term, entry, &lifted);\n");
    out.push_str("    if (!value) { return 0; }\n");
    out.push_str("    int landed = 0;\n");
    out.push_str("    for (int32_t o = 0; o < entry->operand_count; ++o) {\n");
    out.push_str("      const axis_lift_operand *operand = &entry->operands[o];\n");
    out.push_str("      /* ⚠️ `inout` as well as `out`. A compressed `c.addi` writes the\n         register it reads, and taking only `out` left every one of them\n         unwritten -- a machine that agreed with the executor about thirty\n         instructions and silently did nothing for ten. */\n");
    out.push_str("      if (!operand->role\n          || ((operand->role_code != AXIS_ROLE_OUT) && (operand->role_code != AXIS_ROLE_INOUT))) { continue; }\n");
    out.push_str("      uint32_t slot = axis_operand_slot(operand, lifted.operands[o]);\n");
    out.push_str("      if ((int32_t)slot < m->regs) { sym_write_reg(m, operand, slot, value, NULL); }\n");
    out.push_str("      landed = 1;\n      break;\n    }\n");
    out.push_str("    if (!landed) { m->refusal = \"a value with nowhere to put it\"; return 0; }\n");
    out.push_str("  }\n");
    out.push_str("  for (int32_t e = 0; e < effects; ++e) {\n");
    out.push_str("    int landed = 0;\n");
    out.push_str("    const char *kind = m->terms->effect_kind(m->handle, index, e);\n");
    out.push_str("    const char *place = m->terms->effect_place(m->handle, index, e);\n");
    out.push_str("    int32_t guard_term = m->terms->effect_term(m->handle, index, e, \"guard\");\n");
    out.push_str("    Z3_ast guard = guard_term >= 0 ? sym_bind(m, guard_term, entry, &lifted) : NULL;\n");
    out.push_str("    if (guard_term >= 0 && !guard) { return 0; }\n");
    out.push_str("    int32_t value_term = m->terms->effect_term(m->handle, index, e, \"value\");\n");
    out.push_str("    Z3_ast value = value_term >= 0 ? sym_bind(m, value_term, entry, &lifted) : NULL;\n");
    out.push_str("    if (value_term >= 0 && !value) { return 0; }\n");
    // ⚠️ An effect the solver library has no term for is a REFUSAL, not an
    // effect skipped. `emit-smt2` declines the `load` operator, so a machine
    // that shrugged here reported an `ldr` that agreed about every register
    // except the one it was supposed to write -- which reads as a working
    // engine with a rounding error rather than as an instruction nobody can
    // say anything about.
    out.push_str("    if (value_term < 0) {\n");
    out.push_str("      /* A load: the solver holds where, this machine holds what is there. */\n");
    out.push_str("      uint32_t load_bits = m->terms->effect_load_bits(m->handle, index, e);\n");
    out.push_str("      int32_t load_term = m->terms->effect_term(m->handle, index, e, \"load_addr\");\n");
    out.push_str("      if (load_bits && load_term >= 0) {\n");
    out.push_str("        Z3_ast at = sym_bind(m, load_term, entry, &lifted);\n");
    out.push_str("        if (!at) { return 0; }\n");
    out.push_str("        value = sym_load(m, at, load_bits,\n");
    out.push_str("                         m->terms->effect_load_signed(m->handle, index, e));\n");
    out.push_str("        if (!value) { m->refusal = \"a load of no width\"; return 0; }\n");
    out.push_str("      } else {\n");
    out.push_str("        m->refusal = \"the solver library has no value term for one of its effects\";\n");
    out.push_str("        return 0;\n      }\n    }\n");
    out.push_str("    if (!kind) { m->refusal = \"an effect with no kind\"; return 0; }\n");
    out.push_str("    if (!strcmp(kind, \"set\") && place) {\n");
    out.push_str("      for (int32_t o = 0; o < entry->operand_count; ++o) {\n");
    out.push_str("        const axis_lift_operand *operand = &entry->operands[o];\n");
    out.push_str("        if (!operand->name || strcmp(operand->name, place)) { continue; }\n");
    out.push_str("        uint32_t slot = axis_operand_slot(operand, lifted.operands[o]);\n");
    out.push_str("        if ((int32_t)slot >= m->regs) { break; }\n");
    out.push_str("        sym_write_reg(m, operand, slot, value, guard);\n");
    out.push_str("        landed = 1;\n        break;\n      }\n");
    out.push_str("      /* ⚠️ A write that lands nowhere is a refusal. Doing nothing quietly is\n         how ten instructions came back agreeing about registers they had\n         never written. */\n");
    out.push_str("      if (!landed) { m->refusal = \"a set whose destination is no operand of this word\"; return 0; }\n");
    out.push_str("    } else if (!strcmp(kind, \"setstate\") && place) {\n");
    out.push_str("      for (int32_t sslot = 0; sslot < sym_state_slots(); ++sslot) {\n");
    out.push_str("        if (strcmp(AXIS_SYM_STATE_SLOTS[sslot].name, place)) { continue; }\n");
    out.push_str("        m->state[sslot] = sym_guarded(m, guard, sym_fit(m, value, 64u), m->state[sslot]);\n");
    out.push_str("        landed = 1;\n        break;\n      }\n");
    out.push_str("      if (!landed) { m->refusal = \"a setstate naming a slot this isa does not declare\"; return 0; }\n");
    out.push_str("    } else if (!strcmp(kind, \"store\")) {\n");
    out.push_str("      int32_t addr_term = m->terms->effect_term(m->handle, index, e, \"addr\");\n");
    out.push_str("      Z3_ast addr = addr_term >= 0 ? sym_bind(m, addr_term, entry, &lifted) : NULL;\n");
    out.push_str("      if (!addr || !value) { m->refusal = \"a store with no address\"; return 0; }\n");
    out.push_str("      uint32_t width = m->terms->value_bits(m->handle, value_term);\n");
    out.push_str("      m->memory = sym_store(m, m->memory, addr, value, width ? width : 8u, guard);\n");
    out.push_str("    } else if (!strcmp(kind, \"setpc\")) {\n");
    out.push_str("      if (!value) { m->refusal = \"a setpc with no target\"; return 0; }\n");
    out.push_str("      next = sym_fit(m, value, 64u);\n  branch_guard = guard;\n  branched = 1;\n");
    out.push_str("    } else {\n");
    out.push_str("      m->refusal = kind; return 0;\n");
    out.push_str("    }\n  }\n");
    // ⚠️ Both ways out, in order. A guarded branch is `when this, there;
    // otherwise, on` -- and an engine that returned only the taken way would
    // be exploring a different program from the one it was given.
    out.push_str("  if (branched && branch_guard) {\n");
    out.push_str("    Z3_ast one = sym_bits(m, 1u, Z3_get_bv_sort_size(m->ctx, Z3_get_sort(m->ctx, branch_guard)));\n");
    out.push_str("    Z3_ast taken = Z3_mk_eq(m->ctx, branch_guard, one);\n");
    out.push_str("    m->path[0].constraint = taken;      m->path[0].pc = next;\n");
    out.push_str("    m->path[1].constraint = Z3_mk_not(m->ctx, taken); m->path[1].pc = fall;\n");
    out.push_str("    m->path_count = 2;\n");
    out.push_str("    m->pc = Z3_mk_ite(m->ctx, taken, next, fall);\n");
    out.push_str("  } else {\n");
    out.push_str("    m->path[0].constraint = NULL;  m->path[0].pc = next;\n");
    out.push_str("    m->path_count = 1;\n    m->pc = next;\n  }\n");
    out.push_str("  return 1;\n}\n\n");

    out.push_str(&format!(
        "static const axis_sym_pack AXIS_SYM_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  {}, {}, {},\n  \"z3\",\n  \
sym_create, sym_destroy, sym_clone,\n  \
sym_reg, sym_set_reg, sym_pc, sym_set_pc,\n  \
sym_memory, sym_set_memory,\n  \
sym_state_slots, sym_state_name, sym_state, sym_set_state,\n  \
sym_step, sym_refusal,\n  sym_paths, sym_path,\n  \
sym_constraints, sym_constraint, sym_assume\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_sym_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_sym_pack *axis_sym_pack_{ident}(void) {{ return &AXIS_SYM_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

pub fn emit_pack_exec_c(document: &Document) -> String {
    let ident = pack_ident(&document.extension.name);
    let slots = crate::ast::register_file_slots(document);
    let state = crate::effects::isa_scalar_state_slots(&document.isas);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. One architecture's executor, as a library. */\n");
    out.push_str("/* schema: axis.pack-exec-c.v1 */\n");
    out.push_str("#include <string.h>\n#include \"axis_pack.h\"\n#include \"axis_lift.h\"\n");
    out.push_str("#include \"axis_semantics.h\"\n#include \"axis_exec.h\"\n\n");
    out.push_str("_Static_assert(AXIS_EXEC_MAX_LIMBS <= AXIS_PACK_MAX_LIMBS,\n");
    out.push_str("               \"this description's registers span more limbs than AXIS_PACK_MAX_LIMBS\");\n\n");
    out.push_str(&format!(
        "static int32_t pack_register_slots(void) {{ return {slots}; }}\n"
    ));
    out.push_str("typedef struct { const char *name; uint32_t width; } axis_pack_slot;\n");
    out.push_str("static const axis_pack_slot AXIS_PACK_STATE[] = {\n");
    for (name, width) in &state {
        out.push_str(&format!("  {{ {}, {width}u }},\n", c_string(name)));
    }
    out.push_str("  { NULL, 0u }\n};\n");
    out.push_str(&format!(
        "static int32_t pack_state_slots(void) {{ return {}; }}\n",
        state.len()
    ));
    out.push_str("static int pack_state_ok(int32_t s) { return s >= 0 && s < pack_state_slots(); }\n");
    out.push_str("static const char *pack_state_name(int32_t s) { return pack_state_ok(s) ? AXIS_PACK_STATE[s].name : NULL; }\n");
    out.push_str("static uint32_t pack_state_width(int32_t s) { return pack_state_ok(s) ? AXIS_PACK_STATE[s].width : 0u; }\n\n");
    // The host's memory, reached through a trampoline rather than by casting
    // one struct to the other: they have the same shape today and that is not
    // a promise either file makes to the other.
    out.push_str("static uint64_t pack_mem_read(void *ctx, uint64_t addr, uint32_t width) {\n");
    out.push_str("  const axis_pack_mem *m = (const axis_pack_mem *)ctx;\n");
    out.push_str("  return m && m->read ? m->read(m->ctx, addr, width) : 0u;\n}\n");
    out.push_str("static void pack_mem_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {\n");
    out.push_str("  const axis_pack_mem *m = (const axis_pack_mem *)ctx;\n");
    out.push_str("  if (m && m->write) { m->write(m->ctx, addr, value, width); }\n}\n\n");
    out.push_str("static int32_t pack_step(uint32_t word, const char *isa, uint64_t *regs, int32_t reg_count,\n");
    out.push_str("                        const axis_pack_mem *mem, uint64_t pc,\n");
    out.push_str("                        axis_pack_state_entry *state, int32_t state_count,\n");
    out.push_str("                        axis_pack_exec_result *out) {\n");
    out.push_str("  if (!out) { return 0; }\n  memset(out, 0, sizeof *out);\n");
    out.push_str("  axis_state64_entry entries[64];\n");
    out.push_str("  int32_t n = state_count < 64 ? state_count : 64;\n");
    out.push_str("  for (int32_t i = 0; i < n; ++i) {\n");
    out.push_str("    entries[i].name = state[i].name; entries[i].value = state[i].value;\n");
    out.push_str("    entries[i].width = state[i].width;\n  }\n");
    out.push_str("  axis_state64 held = { entries, (size_t)n };\n");
    out.push_str("  axis_mem64 bridged = { pack_mem_read, pack_mem_write, (void *)mem };\n");
    out.push_str("  axis_exec_result64 r = axis_exec_step64(word, isa, regs, (size_t)reg_count,\n");
    out.push_str("                                         mem ? &bridged : NULL, pc, &held);\n");
    out.push_str("  /* The host's copy is authoritative, so what the machine changed goes back. */\n");
    out.push_str("  for (int32_t i = 0; i < n; ++i) { state[i].value = entries[i].value; }\n");
    out.push_str("  out->mnemonic = r.mnemonic;\n  out->result = r.result;\n");
    out.push_str("  out->result_limbs = r.result_limbs;\n");
    out.push_str("  for (uint32_t i = 0; i < r.result_limbs && i < AXIS_PACK_MAX_LIMBS; ++i) {\n");
    out.push_str("    out->result_limb[i] = r.result_limb[i];\n  }\n");
    out.push_str("  out->wrote = r.wrote; out->dest = r.dest; out->dest_slot = r.dest_slot;\n");
    out.push_str("  out->state_name = r.state_name; out->state_value = r.state_value;\n");
    out.push_str("  out->next_pc = r.next_pc; out->trapped = r.trapped;\n");
    out.push_str("  out->trap_cause = r.trap_cause; out->ok = r.ok;\n");
    out.push_str("  return r.ok || r.trapped ? 1 : 0;\n}\n\n");
    out.push_str(&pack_routine_registry(document));
    out.push_str(&format!(
        "static const axis_exec_pack AXIS_EXEC_PACK = {{\n  AXIS_PACK_ABI_VERSION,\n  \
{}, {}, {},\n  pack_register_slots, pack_state_slots, pack_state_name, pack_state_width,\n  \
pack_step,\n  pack_routine_count, pack_routine_name, pack_routine_mnemonic, pack_register_routine\n}};\n\n",
        c_string(&document.extension.name),
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped")),
        c_string(&format!("axis_exec_pack_{ident}"))
    ));
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    out.push_str(&format!(
        "const axis_exec_pack *axis_exec_pack_{ident}(void) {{ return &AXIS_EXEC_PACK; }}\n"
    ));
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

/// The decoder's translation unit, in flat C, for `emit_pack_decode_c` to
/// make `static` and wrap.
///
/// ⚠️ No longer a command. It was `emit-decode-abi-c`, and its symbols were the
/// same for every description -- so a program that linked two architectures got
/// one of them, silently. The pack replaced it and this is what the pack is
/// built from, which is why the code is still here and the artifact is not.
pub(crate) fn emit_decode_abi_c(document: &Document) -> String {
    let architectural = architectural_instructions(document);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. Exported C ABI over the decode tables. */\n");
    out.push_str("/* schema: axis.decode-abi-c.v1 */\n");
    out.push_str("#include \"axis_decode.h\"\n#include \"axis_encode.h\"\n\n");
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    out.push_str(&format!(
        "const char *axis_abi_description(void) {{ return {}; }}\n",
        c_string(&document.extension.name)
    ));
    out.push_str(&format!(
        "const char *axis_abi_generator(void) {{ return {}; }}\n",
        c_string(option_env!("AXIS_BUILD").unwrap_or("unstamped"))
    ));
    out.push_str(&format!(
        "int32_t axis_abi_count(void) {{ return {}; }}\n\n",
        architectural.len()
    ));
    // Out of range is answered, not trusted: a binding that computes an index
    // wrongly gets NULL or 0 rather than whatever follows the array.
    out.push_str("static int axis_abi_in_range(int32_t index) {\n");
    out.push_str("  return index >= 0 && (size_t)index < AXIS_DECODE_TABLE_LEN;\n");
    out.push_str("}\n\n");
    out.push_str("int32_t axis_abi_decode(uint32_t insn, const char *isa) {\n");
    out.push_str("  const axis_decode_entry *entry = axis_decode_in_isa(insn, isa);\n");
    out.push_str("  if (!entry) { return -1; }\n");
    out.push_str("  return (int32_t)(entry - AXIS_DECODE_TABLE);\n");
    out.push_str("}\n\n");
    // The scan, exported too. A binding is one more place the fast decoder
    // could be wrong, and this is what lets a script check it in its own
    // process rather than trusting that a gate elsewhere ran.
    out.push_str("int32_t axis_abi_decode_linear(uint32_t insn, const char *isa) {\n");
    out.push_str("  const axis_decode_entry *entry = axis_decode_linear_in_isa(insn, isa);\n");
    out.push_str("  if (!entry) { return -1; }\n");
    out.push_str("  return (int32_t)(entry - AXIS_DECODE_TABLE);\n");
    out.push_str("}\n\n");
    for (name, field) in [
        ("mnemonic", "mnemonic"),
        ("isa", "isa"),
        ("format", "format"),
        ("asm_syntax", "asm_syntax"),
    ] {
        out.push_str(&format!(
            "const char *axis_abi_{name}(int32_t index) {{\n  \
             return axis_abi_in_range(index) ? AXIS_DECODE_TABLE[index].{field} : NULL;\n}}\n"
        ));
    }
    for (name, field) in [("match", "match"), ("mask", "mask"), ("bits", "bits")] {
        out.push_str(&format!(
            "uint32_t axis_abi_{name}(int32_t index) {{\n  \
             return axis_abi_in_range(index) ? AXIS_DECODE_TABLE[index].{field} : 0u;\n}}\n"
        ));
    }
    out.push('\n');
    // Operands the word carries no bits for. AArch64's CASP takes a register
    // *pair*: `rs2` is `rs + 1` by architecture, and the encoding stores one
    // of them. The description says so -- `(derived rs 1)` -- and the encode
    // header records only that the operand is unencoded, since an encoder has
    // nothing to write. A decoder does have something to compute, so the rule
    // is emitted here rather than left to the caller, which is where it would
    // become a hand-written table again.
    out.push_str("typedef struct axis_abi_derived {\n");
    out.push_str("  int32_t instruction;\n  int32_t operand;\n");
    out.push_str("  int32_t source;\n  uint32_t add;\n");
    out.push_str("} axis_abi_derived;\n\n");
    out.push_str("static const axis_abi_derived AXIS_ABI_DERIVED[] = {\n");
    let mut derived_rows = 0usize;
    for (index, instruction) in architectural.iter().enumerate() {
        for (ordinal, operand) in instruction.operands.iter().enumerate() {
            if operand.derived_from.is_empty() {
                continue;
            }
            let source = instruction
                .operands
                .iter()
                .position(|other| other.name == operand.derived_from);
            let Some(source) = source else {
                continue;
            };
            derived_rows += 1;
            out.push_str(&format!(
                "  {{ {index}, {ordinal}, {source}, {}u }},\n",
                operand.derived_add
            ));
        }
    }
    // A zero-length array is not C. An impossible row keeps the lookup uniform.
    if derived_rows == 0 {
        out.push_str("  { -1, -1, -1, 0u },\n");
    }
    out.push_str("};\n");
    out.push_str(&format!(
        "static const size_t AXIS_ABI_DERIVED_LEN = {derived_rows};\n\n"
    ));
    out.push_str("int32_t axis_abi_operand_count(int32_t index) {\n");
    out.push_str("  if (!axis_abi_in_range(index)) { return -1; }\n");
    out.push_str("  return (int32_t)AXIS_ENCODE_TABLE[index].operand_count;\n");
    out.push_str("}\n\n");
    // An operand's name/kind/role live on its *fields*, and a scattered
    // immediate has several. The first field carrying an operand's index names
    // it; they all agree, because they are one operand's slices.
    out.push_str("static const axis_encode_operand_field *axis_abi_field_of(\n");
    out.push_str("    int32_t index, int32_t operand) {\n");
    out.push_str("  const axis_encode_entry *entry = &AXIS_ENCODE_TABLE[index];\n");
    out.push_str("  for (size_t i = 0; i < entry->field_count; ++i) {\n");
    out.push_str("    if (entry->fields[i].operand_index == operand) { return &entry->fields[i]; }\n");
    out.push_str("  }\n  return NULL;\n}\n\n");
    for name in ["name", "kind", "role"] {
        out.push_str(&format!(
            "const char *axis_abi_operand_{name}(int32_t index, int32_t operand) {{\n"
        ));
        out.push_str("  if (!axis_abi_in_range(index) || operand < 0) { return NULL; }\n");
        out.push_str(
            "  const axis_encode_operand_field *field = axis_abi_field_of(index, operand);\n",
        );
        out.push_str(&format!("  return field ? field->{name} : NULL;\n}}\n"));
    }
    out.push('\n');
    // The inverse of `axis_encode_apply_field`. Encoding scatters an operand's
    // bits across the word; decoding gathers them back, each slice returning to
    // the place in the value it came from.
    out.push_str("static uint32_t axis_abi_operand_bits(uint32_t insn, int32_t index,\n");
    out.push_str("                                      int32_t operand) {\n");
    out.push_str("  const axis_encode_entry *entry = &AXIS_ENCODE_TABLE[index];\n");
    out.push_str("  uint32_t value = 0u;\n");
    out.push_str("  for (size_t i = 0; i < entry->field_count; ++i) {\n");
    out.push_str("    const axis_encode_operand_field *field = &entry->fields[i];\n");
    out.push_str("    if (field->operand_index != operand) { continue; }\n");
    /* An unencoded operand's row carries lsb -1, and shifting by a negative
       count is undefined -- not merely wrong. */
    out.push_str("    if (field->lsb < 0 || field->width == 0u) {\n");
    out.push_str("      /* A FIXED operand is in no bits, and has a value all the same: its\n         row carries it where a field carries a source position. */\n");
    out.push_str("      if (field->field && !strcmp(field->field, \"fixed\")) { value = (uint32_t)field->src_lsb; }\n");
    out.push_str("      continue;\n    }\n");
    out.push_str("    const uint32_t bits = field->width >= 32u\n");
    out.push_str("        ? insn >> field->lsb\n");
    out.push_str("        : (insn >> field->lsb) & ((1u << field->width) - 1u);\n");
    out.push_str("    value |= (uint32_t)(bits << field->src_lsb);\n");
    out.push_str("  }\n  return value;\n}\n\n");
    out.push_str("uint32_t axis_abi_operand_value(uint32_t insn, int32_t index, int32_t operand) {\n");
    out.push_str("  if (!axis_abi_in_range(index) || operand < 0) { return 0u; }\n");
    out.push_str("  uint32_t offset = 0u;\n");
    /* A derivation could in principle name another derived operand. The bound
       is the operand count, so a description that somehow made a cycle stops
       instead of looping. */
    out.push_str("  for (int hop = 0; hop <= (int)AXIS_ENCODE_TABLE[index].operand_count; ++hop) {\n");
    out.push_str("    int32_t source = -1;\n");
    out.push_str("    for (size_t i = 0; i < AXIS_ABI_DERIVED_LEN; ++i) {\n");
    out.push_str("      if (AXIS_ABI_DERIVED[i].instruction == index\n");
    out.push_str("          && AXIS_ABI_DERIVED[i].operand == operand) {\n");
    out.push_str("        source = AXIS_ABI_DERIVED[i].source;\n");
    out.push_str("        offset += AXIS_ABI_DERIVED[i].add;\n");
    out.push_str("        break;\n");
    out.push_str("      }\n");
    out.push_str("    }\n");
    out.push_str("    if (source < 0) { return axis_abi_operand_bits(insn, index, operand) + offset; }\n");
    out.push_str("    operand = source;\n");
    out.push_str("  }\n");
    out.push_str("  return 0u;\n}\n\n");
    // Bulk decode. A binding that crosses the boundary once per word pays
    // ~3us of ctypes for a decode that costs 0.05us, and materialising the
    // operands costs ten times that again -- so the compiled decoder buys
    // nothing at the call site it was compiled for. A real text section is
    // millions of words; these take the whole buffer and return one index per
    // word, leaving the caller to build objects only for the words it keeps.
    out.push_str("int32_t axis_abi_decode_buffer(const uint32_t *words, int32_t count,\n");
    out.push_str("                               const char *isa, int32_t *out) {\n");
    out.push_str("  if (!words || !out || count < 0) { return -1; }\n");
    out.push_str("  for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("    const axis_decode_entry *entry = axis_decode_in_isa(words[i], isa);\n");
    out.push_str("    out[i] = entry ? (int32_t)(entry - AXIS_DECODE_TABLE) : -1;\n");
    out.push_str("  }\n  return count;\n}\n\n");
    /* A file gives bytes, not words. Assembling them here with explicit shifts
       decodes a little-endian image the same way on any host, which casting
       the buffer to `uint32_t *` would not. */
    out.push_str("int32_t axis_abi_decode_le(const uint8_t *bytes, int32_t byte_count,\n");
    out.push_str("                           const char *isa, int32_t *out) {\n");
    out.push_str("  if (!bytes || !out || byte_count < 0) { return -1; }\n");
    out.push_str("  const int32_t count = byte_count / 4;\n");
    out.push_str("  for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("    const uint8_t *at = bytes + (size_t)i * 4u;\n");
    out.push_str("    const uint32_t word = (uint32_t)at[0] | ((uint32_t)at[1] << 8)\n");
    out.push_str("        | ((uint32_t)at[2] << 16) | ((uint32_t)at[3] << 24);\n");
    out.push_str("    const axis_decode_entry *entry = axis_decode_in_isa(word, isa);\n");
    out.push_str("    out[i] = entry ? (int32_t)(entry - AXIS_DECODE_TABLE) : -1;\n");
    out.push_str("  }\n  return count;\n}\n\n");
    // The operands of many words at once, laid out `stride` apart so one call
    // fills a rectangular buffer the caller can read without another crossing.
    out.push_str("int32_t axis_abi_operands_buffer(const uint32_t *words, const int32_t *indices,\n");
    out.push_str("                                 int32_t count, int32_t stride, uint32_t *out) {\n");
    out.push_str("  if (!words || !indices || !out || count < 0 || stride <= 0) { return -1; }\n");
    out.push_str("  int32_t widest = 0;\n");
    out.push_str("  for (int32_t i = 0; i < count; ++i) {\n");
    out.push_str("    const int32_t index = indices[i];\n");
    out.push_str("    if (!axis_abi_in_range(index)) { continue; }\n");
    out.push_str("    const int32_t operands = (int32_t)AXIS_ENCODE_TABLE[index].operand_count;\n");
    out.push_str("    if (operands > widest) { widest = operands; }\n");
    out.push_str("    const int32_t fill = operands < stride ? operands : stride;\n");
    out.push_str("    for (int32_t n = 0; n < fill; ++n) {\n");
    out.push_str("      out[(size_t)i * (size_t)stride + (size_t)n] =\n");
    out.push_str("          axis_abi_operand_value(words[i], index, n);\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    /* The widest operand list seen, so a caller given too small a stride is
       told what it needed rather than quietly handed truncated rows. */
    out.push_str("  return widest;\n}\n\n");
    // Walking a stream whose instructions are not all one width. Stepping a
    // fixed four bytes through RISC-V compressed code misaligns everything
    // after the first 16-bit instruction, and the decoder then answers nothing
    // for the rest -- which reads as a description that is missing them.
    //
    // The caller gets one row per *instruction*, not per word: the byte offset
    // it started at, the table index, and how many bytes it took. A word that
    // decodes to nothing advances by the smallest width in the table, because
    // the alternative is to stop at the first byte that is not an instruction
    // and a real section has data in it.
    out.push_str("int32_t axis_abi_decode_stream(const uint8_t *bytes, int32_t byte_count,\n");
    out.push_str("                               const char *isa, int32_t *out_offset,\n");
    out.push_str("                               int32_t *out_index, int32_t *out_bytes,\n");
    out.push_str("                               int32_t limit) {\n");
    out.push_str("  if (!bytes || byte_count < 0 || !out_offset || !out_index || !out_bytes) { return -1; }\n");
    out.push_str("  uint32_t narrowest = 32u;\n");
    out.push_str("  for (size_t i = 0; i < AXIS_DECODE_TABLE_LEN; ++i) {\n");
    out.push_str("    if (AXIS_DECODE_TABLE[i].bits < narrowest) { narrowest = AXIS_DECODE_TABLE[i].bits; }\n");
    out.push_str("  }\n");
    out.push_str("  const int32_t step = (int32_t)(narrowest / 8u) > 0 ? (int32_t)(narrowest / 8u) : 4;\n");
    out.push_str("  int32_t at = 0, found = 0;\n");
    out.push_str("  while (at + 2 <= byte_count && found < limit) {\n");
    /* Assembled little-endian, and only as many bytes as are left: a 16-bit
       instruction at the very end of a section has no upper half to read. */
    out.push_str("    uint32_t word = (uint32_t)bytes[at] | ((uint32_t)bytes[at + 1] << 8);\n");
    out.push_str("    if (at + 4 <= byte_count) {\n");
    out.push_str("      word |= ((uint32_t)bytes[at + 2] << 16) | ((uint32_t)bytes[at + 3] << 24);\n");
    out.push_str("    }\n");
    out.push_str("    const axis_decode_entry *entry = axis_decode_in_isa(word, isa);\n");
    out.push_str("    out_offset[found] = at;\n");
    out.push_str("    if (entry) {\n");
    out.push_str("      const int32_t width = (int32_t)(entry->bits / 8u);\n");
    out.push_str("      out_index[found] = (int32_t)(entry - AXIS_DECODE_TABLE);\n");
    out.push_str("      out_bytes[found] = width;\n");
    out.push_str("      at += width > 0 ? width : step;\n");
    out.push_str("    } else {\n");
    out.push_str("      out_index[found] = -1;\n");
    out.push_str("      out_bytes[found] = step;\n");
    out.push_str("      at += step;\n");
    out.push_str("    }\n");
    out.push_str("    ++found;\n");
    out.push_str("  }\n");
    out.push_str("  return found;\n}\n\n");
    // ⚠️ The assembler direction, which `AXIS_PACK_HAS_ASSEMBLE` claimed on
    // every pack while the table had no such pointer -- a flag whose whole job
    // is to stop a host calling a null one.
    out.push_str("int32_t axis_abi_assemble(int32_t index, const uint32_t *operand_values, uint32_t *out) {\n");
    out.push_str("  if (!axis_abi_in_range(index) || !out) { return 0; }\n");
    out.push_str("  uint32_t word = 0;\n");
    out.push_str("  if (!axis_encode_by_index((size_t)index, operand_values, &word)) { return 0; }\n");
    out.push_str("  *out = word;\n  return 1;\n}\n\n");
    out.push_str("int32_t axis_abi_tables_aligned(void) {\n");
    out.push_str("  if (AXIS_DECODE_TABLE_LEN != AXIS_ENCODE_TABLE_LEN) { return 0; }\n");
    out.push_str("  for (size_t i = 0; i < AXIS_DECODE_TABLE_LEN; ++i) {\n");
    out.push_str("    if (strcmp(AXIS_DECODE_TABLE[i].mnemonic,\n");
    out.push_str("               AXIS_ENCODE_TABLE[i].mnemonic) != 0) { return 0; }\n");
    out.push_str("  }\n  return 1;\n}\n\n");
    out.push_str("#ifdef __cplusplus\n}\n#endif\n");
    out
}

/// The scheduler's own limits (docs/scheduler_design.md, S1-S3).
const SCHED_C: &str = r#"
/* ⚠️ THE SCHEDULER (S1-S3, docs/scheduler_design.md). Four things a window
   said nothing about.

   DISPATCH WIDTH: how many micro-ops enter the window a cycle. It was the
   issue width, because nothing said otherwise; a machine renames fewer than
   it can start, or more.

   A UNIT'S OWN QUEUE: how many instructions may wait for one unit. One bound
   for a unit whose queue is full does not enter the window -- and dispatch
   is in order, so nothing behind it does either.

   THE WAKEUP-AND-SELECT LOOP: a dependent issues no sooner than `sched`
   cycles after its producer ISSUED. One cycle is a scheduler that issues
   dependents back to back; two is one that cannot, and a chain of one-cycle
   adds runs at two.

   A BYPASS: what a result costs to reach an instruction on another unit,
   beyond the producer's latency.

   The last two are delays on a producer, and a producer may retire before
   they have run out: when an instruction issued, and on what, is kept by its
   sequence number for as long as anything could be waiting on it. */
static uint32_t axis_disp_width(const axis_pack_machine *m) {
  return m->disp_width ? m->disp_width : (m->core->issue_width ? m->core->issue_width : 1u);
}
static void axis_sched_select(axis_pack_machine *m, int32_t slot) {
  m->disp_width = AXIS_SIM_CORE_SCHED[slot][0];
  m->sched = AXIS_SIM_CORE_SCHED[slot][1];
  m->unit_queue = AXIS_SIM_CORE_UNIT_QUEUE[slot];
  m->bypass = AXIS_SIM_CORE_BYPASS[slot];
  m->bypass_n = AXIS_SIM_CORE_UNITS[slot];
  for (uint32_t i = 0; i < AXIS_SIM_ROB_MAX; ++i) { m->done_seq[i] = AXIS_SIM_NO_SEQ; }
  m->vp_entries = AXIS_SIM_CORE_VP[slot][0] < 1024u ? AXIS_SIM_CORE_VP[slot][0] : 1024u;
  m->vp_conf = AXIS_SIM_CORE_VP[slot][1];
  m->vp_stride = (int32_t)AXIS_SIM_CORE_VP[slot][2];
  m->rename_width = AXIS_SIM_CORE_VP[slot][3];
  m->select_position = AXIS_SIM_CORE_SELECT[slot];
  m->elim_on = AXIS_SIM_CORE_ELIM[slot];
  m->fuse = AXIS_SIM_CORE_FUSE[slot];
  m->sb_entries = AXIS_SIM_CORE_SB[slot][0] < AXIS_SIM_SB_MAX ? AXIS_SIM_CORE_SB[slot][0] : AXIS_SIM_SB_MAX;
  m->sb_any = (int32_t)AXIS_SIM_CORE_SB[slot][1];
  m->loads_any = (int32_t)AXIS_SIM_CORE_SB[slot][2];
  m->x_keep = 0;
  m->sb_count = 0;
  m->elim_waiting = 0;
  m->fuse_live = 0;
  m->fz_seq = AXIS_SIM_NO_SEQ;
  m->tw_walkers = (uint32_t)(AXIS_SIM_CORE_TLB2[slot][0] > 8u ? 8u : AXIS_SIM_CORE_TLB2[slot][0]);
  m->tw_levels = (uint32_t)AXIS_SIM_CORE_TLB2[slot][1];
  m->tw_cycles = (uint32_t)AXIS_SIM_CORE_TLB2[slot][2];
  m->tw_table = AXIS_SIM_CORE_TLB2[slot][3];
  m->tw_pwc = (uint32_t)(AXIS_SIM_CORE_TLB2[slot][4] > 64u ? 64u : AXIS_SIM_CORE_TLB2[slot][4]);
  m->tw_huge_bytes = AXIS_SIM_CORE_TLB2[slot][5];
  m->tw_huge_from = AXIS_SIM_CORE_TLB2[slot][6];
  m->tw_huge_to = AXIS_SIM_CORE_TLB2[slot][7];
  memset(m->walker_free, 0, sizeof m->walker_free);
  memset(m->pwc_valid, 0, sizeof m->pwc_valid);
  m->tw_nodes = 0;
  memset(m->tw_node, 0, sizeof m->tw_node);
  m->pending_walk = 0;
  m->renamed_this_cycle = 0;
  m->unit_cluster = AXIS_SIM_CORE_UNIT_CLUSTER[slot];
  m->cluster_size = AXIS_SIM_CORE_CLUSTER_SIZE[slot];
  memset(m->vp_step, 0, sizeof m->vp_step);
  memset(m->vp_cnt, 0, sizeof m->vp_cnt);
  for (uint32_t i = 0; i < 1024u; ++i) { m->vp_pc[i] = ~0ull; }
  m->value_predictions = 0;
  m->value_mispredicts = 0;
  m->vp_flush = 0;
}
/* ⚠️ VALUE PREDICTION (S4). A load's value is not known until the load has
   run, and everything that reads it waits. But a load at one pc that has
   read the same value `vp_conf` times running will usually read it again: so
   the machine says so, what depends on the load issues without waiting for
   it, and the load runs to CHECK. Right, and a dependence chain through
   memory has gone. Wrong, and everything after the load used a value that
   was never there: it is squashed and fetched again once the load has said
   what it really read.

   Last value, by pc, with a count of times running. 1 with the value when
   the table is confident. */
static int axis_vp_predict(const axis_pack_machine *m, uint64_t pc, uint64_t *value) {
  if (!m->vp_entries) { return 0; }
  uint32_t at = (uint32_t)((pc >> 2) % m->vp_entries);
  if (m->vp_pc[at] != pc || m->vp_cnt[at] < m->vp_conf) { return 0; }
  *value = m->vp_val[at] + (m->vp_stride ? m->vp_step[at] : 0u);
  return 1;
}
static void axis_vp_train(axis_pack_machine *m, uint64_t pc, uint64_t value) {
  if (!m->vp_entries) { return; }
  uint32_t at = (uint32_t)((pc >> 2) % m->vp_entries);
  /* ⚠️ A STRIDE (S7): the last value and the last DIFFERENCE, trusted once
     the difference has repeated. A value that does not change is a stride
     of nothing, so this is the last-value predictor for every load that one
     predicts -- and one that walks is predicted too. */
  if (m->vp_stride) {
    uint64_t step = m->vp_pc[at] == pc ? value - m->vp_val[at] : 0u;
    if (m->vp_pc[at] == pc && step == m->vp_step[at]) { if (m->vp_cnt[at] < 255u) { m->vp_cnt[at]++; } }
    else { m->vp_cnt[at] = 0; m->vp_step[at] = step; }
    m->vp_pc[at] = pc;
    m->vp_val[at] = value;
    return;
  }
  if (m->vp_pc[at] == pc && m->vp_val[at] == value) { if (m->vp_cnt[at] < 255u) { m->vp_cnt[at]++; } return; }
  m->vp_pc[at] = pc;
  m->vp_val[at] = value;
  m->vp_cnt[at] = 0;
}
/* ⚠️ A QUEUE SEVERAL UNITS SHARE (S5): what waits for any of them waits in
   it, so loads waiting on memory can fill the queue a multiply would have
   entered. A unit may have a queue of its own as well; either full stops it. */
static int axis_unit_queue_full(const axis_pack_machine *m, int32_t unit) {
  if (unit < 0 || unit >= m->core->unit_count) { return 0; }
  uint32_t own = m->unit_queue ? m->unit_queue[unit] : 0u;
  uint32_t shared = m->unit_cluster ? m->unit_cluster[unit] : 0u;
  if (!own && !shared) { return 0; }
  uint32_t waiting = 0, together = 0;
  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!o->valid || o->issued || o->unit < 0) { continue; }
    if (o->unit == unit) { waiting++; }
    if (shared && o->unit < m->core->unit_count && m->unit_cluster[o->unit] == shared) { together++; }
  }
  return (own && waiting >= own) || (shared && together >= m->cluster_size[shared - 1u]);
}
/* ⚠️ SELECT BY POSITION (S8). The scheduler this pipeline had picks the OLDEST
   ready instruction, which takes knowing every instruction's age. A cheaper
   one picks by where an instruction SITS: each takes the lowest free slot of
   the issue queue when it enters and gives it up when it issues, and of
   those ready the lowest slot goes first. An instruction that entered while
   the low slots were taken sits above a younger one that entered after they
   were given up -- and loses to it.

   The waiting instructions, in the order this machine picks among them. A
   slot is given here, in order of entry, to each that has none yet: every
   cycle before anything issues, which is the cycle it entered. */
static uint32_t axis_select_order(axis_pack_machine *m, uint64_t *order) {
  uint64_t used[AXIS_SIM_ROB_MAX / 64u];
  uint32_t n = 0;
  memset(used, 0, sizeof used);
  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (o->valid && !o->issued && o->iq_slot) { used[(o->iq_slot - 1u) / 64u] |= 1ull << ((o->iq_slot - 1u) % 64u); }
  }
  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
    axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!o->valid || o->issued || o->elim) { continue; }
    if (!o->iq_slot) {
      for (uint32_t k = 0; k < AXIS_SIM_ROB_MAX; ++k) {
        if (!((used[k / 64u] >> (k % 64u)) & 1u)) { used[k / 64u] |= 1ull << (k % 64u); o->iq_slot = k + 1u; break; }
      }
    }
    /* Insertion by slot: the queue is small and nearly in order already. */
    uint32_t at = n++;
    while (at > 0 && m->rob[order[at - 1u] % AXIS_SIM_ROB_MAX].iq_slot > o->iq_slot) { order[at] = order[at - 1u]; at--; }
    order[at] = s;
  }
  return n;
}
/* ⚠️ RENAME WIDTH (S6): how many results may be given a register this cycle.
   An instruction that writes nothing takes none of it; one that writes more
   than the whole width has a cycle to itself. */
static int axis_rename_full(const axis_pack_machine *m, uint32_t results) {
  return m->rename_width && results && m->renamed_this_cycle
         && m->renamed_this_cycle + results > m->rename_width;
}
/* An instruction issues: when, when it is done, and on what. */
static void axis_sched_note(axis_pack_machine *m, const axis_sim_rob_entry *e) {
  if (m->sched < 2u && !m->bypass) { return; }
  uint32_t at = (uint32_t)(e->seq % AXIS_SIM_ROB_MAX);
  m->done_seq[at] = e->seq;
  m->done_at[at] = e->complete;
  m->done_issue[at] = m->now;
  m->done_unit[at] = e->unit;
}
/* Whether an instruction on `unit` still has to wait for what `seq` made,
   the producer's own latency apart. */
static int axis_sched_waits(const axis_pack_machine *m, uint64_t seq, int32_t unit) {
  if (m->sched < 2u && !m->bypass) { return 0; }
  uint32_t at = (uint32_t)(seq % AXIS_SIM_ROB_MAX);
  if (seq == AXIS_SIM_NO_SEQ || m->done_seq[at] != seq) { return 0; }
  uint64_t ready = m->done_at[at];
  int32_t from = m->done_unit[at];
  if (m->bypass && unit >= 0 && from >= 0 && unit < m->bypass_n && from < m->bypass_n) {
    ready += m->bypass[from * m->bypass_n + unit];
  }
  if (m->sched > 1u && m->done_issue[at] + m->sched > ready) { ready = m->done_issue[at] + m->sched; }
  return ready > m->now;
}
"#;

/// The micro-op cache and the loop buffer (docs/micro_ops_design.md, U2).
const MOVES_C: &str = r#"
/* ---- a MOVE DONE AT RENAME (ME1, docs/rename_design.md) -----------------
   A machine that renames does not have to execute a register move: the
   destination is given the register the source already has. Here that is an
   entry in the window that is nothing else -- it waits for no slot of the
   issue queue, takes no unit, no issue width and no register -- and FOLLOWS
   what it read: it is done when its source is, and what reads its result
   wakes as it would have for the source's own producer, the scheduler's loop
   and the bypass from that producer's unit included.

   Which instructions are moves is told from what they compute. Some are
   moves for some words only -- an add of the zero register, of an immediate
   of zero -- and `zero` names the operand that has to be nothing. */
static int axis_move_at_rename(const axis_pack_machine *m, const axis_lift_entry *entry, const axis_lifted *lifted) {
  if (!(m->elim_on & 1) || !entry) { return 0; }
  for (const axis_sim_move *row = AXIS_SIM_MOVES; row->mnemonic; ++row) {
    if (strcmp(row->mnemonic, entry->mnemonic) || (entry->isa && strcmp(row->isa, entry->isa))) { continue; }
    if (!row->zero[0]) { return 1; }
    for (int32_t o = 0; o < entry->operand_count; ++o) {
      const axis_lift_operand *operand = &entry->operands[o];
      if (!operand->name || strcmp(operand->name, row->zero)) { continue; }
      const axis_reg_class *rules = axis_op_class(operand);
      if (rules ? (rules->zero_index >= 0 && lifted->operands[o] == (uint32_t)rules->zero_index)
                : lifted->operands[o] == 0u) { return 1; }
    }
  }
  return 0;
}
/* ⚠️ A ZERO IDIOM (ZI1): a register xor-ed with itself, or subtracted from
   itself, is nothing whatever the register holds. A machine that renames
   knows so when it decodes: the instruction is an entry in the window as a
   move is, and it WAITS FOR NOTHING -- not for the register it names. Which
   instructions are told from what they compute; which words, from the two
   operands naming one register. */
static int axis_zero_at_rename(const axis_pack_machine *m, const axis_lift_entry *entry, const axis_lifted *lifted) {
  if (!(m->elim_on & 2) || !entry) { return 0; }
  for (const axis_sim_move *row = AXIS_SIM_ZEROS; row->mnemonic; ++row) {
    if (strcmp(row->mnemonic, entry->mnemonic) || (entry->isa && strcmp(row->isa, entry->isa))) { continue; }
    int32_t a = -1, b = -1;
    for (int32_t o = 0; o < entry->operand_count; ++o) {
      const char *name = entry->operands[o].name;
      if (name && !strcmp(name, row->source)) { a = o; }
      if (name && !strcmp(name, row->zero)) { b = o; }
    }
    if (a >= 0 && b >= 0 && lifted->operands[a] == lifted->operands[b]) { return 1; }
  }
  return 0;
}
/* Each move not yet done, oldest first: done when everything it read is on
   its way, and at the cycle the last of it arrives. Oldest first, so a move
   of a move follows in the same pass. */
static void axis_moves_follow(axis_pack_machine *m) {
  for (uint64_t s = m->rob_head; m->elim_waiting && s < m->rob_tail; ++s) {
    axis_sim_rob_entry *e = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!e->valid || !e->elim || e->issued) { continue; }
    uint64_t ready = m->now, from = AXIS_SIM_NO_SEQ;
    int waits = 0;
    for (int32_t i = 0; i < e->src_count && !waits; ++i) {
      axis_sim_rob_entry *p = axis_ooo_find(m, e->src_seq[i]);
      /* A value predicted is not waited for (S4). */
      if (p && p->vp) { continue; }
      if (p && !p->issued) { waits = 1; break; }
      if (e->src_seq[i] != AXIS_SIM_NO_SEQ && (from == AXIS_SIM_NO_SEQ || (p && p->complete >= ready))) { from = e->src_seq[i]; }
      if (p && p->complete > ready) { ready = p->complete; }
    }
    if (waits) { continue; }
    e->issued = 1;
    m->elim_waiting--;
    /* Execution-driven, its value is the window's like any other. */
    if (m->core->execute_driven) { (void)axis_x_execute(m, e); }
    e->complete = ready;
    /* What the scheduler remembers of the producer, it remembers of this. */
    if (m->sched >= 2u || m->bypass) {
      uint32_t at = (uint32_t)(e->seq % AXIS_SIM_ROB_MAX), was = (uint32_t)(from % AXIS_SIM_ROB_MAX);
      if (from != AXIS_SIM_NO_SEQ && m->done_seq[was] == from) {
        m->done_seq[at] = e->seq;
        m->done_at[at] = m->done_at[was];
        m->done_issue[at] = m->done_issue[was];
        m->done_unit[at] = m->done_unit[was];
      }
    }
  }
}
"#;

const FUSE_C: &str = r#"
/* ---- a pair the decoder makes one operation of (FU1, docs/rename_design.md)
   A core names the pairs its decoder fuses, head and tail. Whether two WORDS
   are such a pair is told from the registers they name: the tail is the
   instruction dispatched straight after the head, in the same cycle; it reads
   something the head writes; and the two leave at most one register between
   them. The head never touches memory; the tail may read it (FU2, below).

   The pair is then ONE operation. The head's entry is it: on the unit of
   whichever of the two takes longer -- the tail's when they take the same,
   which puts a compare and its branch on the branch unit -- and for that
   long. The tail is in the window only as something that follows the head,
   as a move follows what it read: it takes no entry, none of the dispatch,
   issue or commit width, no slot of a queue, no unit, and no register the
   head already took.

   ⚠️ A TAIL THAT IS A LOAD (FU2) is the other way round: an address formed
   into the access that uses it. The LOAD's entry is the operation -- on its
   own unit, in its own queue, for the longer of the two -- and the HEAD is
   what follows: done when what it read is, and no entry, width, queue slot
   or unit. Only when the load writes every register the head wrote, and the
   head wrote no state: nothing else may be given the head's result for
   nothing. */
static int axis_unit_queue_full(const axis_pack_machine *m, int32_t unit);
/* Whether the window has no room for `n` more. A tail is not an entry. */
static int axis_rob_full(const axis_pack_machine *m, uint32_t rob, uint32_t n) {
  uint64_t held = m->rob_tail - m->rob_head;
  return held - m->fuse_live + n > (uint64_t)rob || held + n > (uint64_t)AXIS_SIM_ROB_MAX;
}
/* The head this instruction fuses with, or none. Changes nothing: the unit
   and the cycles the pair would take are left in `fz_unit`, `fz_latency`. */
static axis_sim_rob_entry *axis_fuse_pair(axis_pack_machine *m, const axis_lift_entry *entry, int32_t unit,
                                          uint32_t latency, const uint32_t *reads, int32_t nreads,
                                          const uint32_t *writes, int32_t nwrites, int32_t loads) {
  m->fz_absorb = 0;
  if (!m->fuse || !entry || m->fz_seq == AXIS_SIM_NO_SEQ || m->fz_at != m->now) { return 0; }
  if (m->fz_seq + 1u != m->rob_tail || m->rob_tail - m->rob_head >= (uint64_t)AXIS_SIM_ROB_MAX) { return 0; }
  axis_sim_rob_entry *h = axis_ooo_find(m, m->fz_seq);
  const axis_lift_entry *first = m->fz_entry;
  if (!h || !first || !h->valid || h->issued || h->elim || h->fuse_head || h->is_load || h->is_store || h->wrong) { return 0; }
  int named = 0;
  for (const char *const *p = m->fuse; p[0] && !named; p += 2) {
    named = (!strcmp(p[0], "*") || !strncmp(first->mnemonic, p[0], strlen(p[0])))
         && (!strcmp(p[1], "*") || !strncmp(entry->mnemonic, p[1], strlen(p[1])));
  }
  if (!named) { return 0; }
  int reads_it = 0;
  for (int32_t i = 0; i < nreads && !reads_it; ++i) {
    reads_it = reads[i] < AXIS_SIM_PRODUCERS && m->reg_producer[reads[i]] == h->seq;
  }
  if (!reads_it) { return 0; }
  uint32_t mine = h->latency ? h->latency : 1u, its = latency ? latency : 1u;
  if (loads) {
    /* The load writes all the head wrote, and the head wrote no state. */
    for (int32_t d = 0; d < h->dst_count; ++d) {
      int again = 0;
      for (int32_t k = 0; k < nwrites && !again; ++k) { again = writes[k] == h->dst_slot[d]; }
      if (h->dst_slot[d] >= AXIS_SIM_REG_SLOTS || !again) { return 0; }
    }
    m->fz_unit = unit;
    m->fz_latency = mine > its ? mine : its;
    m->fz_absorb = 1;
    return h;
  }
  /* One register between them: state -- the flags -- is not one. */
  uint32_t one = AXIS_SIM_PRODUCERS;
  for (int32_t d = 0; d < h->dst_count + nwrites; ++d) {
    uint32_t slot = d < h->dst_count ? h->dst_slot[d] : writes[d - h->dst_count];
    if (slot >= AXIS_SIM_REG_SLOTS || slot == one) { continue; }
    if (one != AXIS_SIM_PRODUCERS) { return 0; }
    one = slot;
  }
  m->fz_unit = h->unit;
  m->fz_latency = mine > its ? mine : its;
  if (its >= mine && unit >= 0 && unit != h->unit) {
    /* It moves to the tail's unit, if that unit's queue has room for it. */
    if (axis_unit_queue_full(m, unit)) { return 0; }
    m->fz_unit = unit;
  }
  return h;
}
static void axis_fuse_take(axis_pack_machine *m, axis_sim_rob_entry *h) {
  h->fuse_head = 1;
  h->unit = m->fz_unit;
  h->latency = m->fz_latency;
  m->fz_seq = AXIS_SIM_NO_SEQ;
}
/* The head of a pair whose tail is a load (FU2) becomes what follows: it is
   done when what it read is, and holds nothing. */
static void axis_fuse_absorb(axis_pack_machine *m, axis_sim_rob_entry *h) {
  h->elim = 1;
  h->fused = 1;
  h->unit = -1;
  m->elim_waiting++;
  m->fuse_live++;
  m->fz_seq = AXIS_SIM_NO_SEQ;
}
/* The registers a dispatch renames. A move takes none; a tail takes none the
   head already took. */
static int32_t axis_fuse_renames(const axis_sim_rob_entry *head, int32_t elim, const uint32_t *slot, int32_t *pool, int32_t want) {
  if (!elim) { return want; }
  int32_t renames = 0;
  for (int32_t d = 0; d < want; ++d) {
    int shared = !head;
    for (int32_t k = 0; head && k < head->dst_count && !shared; ++k) { shared = head->dst_slot[k] == slot[d]; }
    if (shared) { pool[d] = -1; } else { renames++; }
  }
  return renames;
}
"#;

const FUSE_TRACE_C: &str = r#"

/* What a trace-driven tail reads and writes, for `axis_fuse_pair`. */
static axis_sim_rob_entry *axis_fuse_trace(axis_pack_machine *m, const axis_lift_entry *entry, const axis_lifted *lifted) {
  if (!m->fuse || !entry) { return 0; }
  for (int32_t a = 0; a < m->acc_count; ++a) { if (m->acc_write[a]) { return 0; } }
  const axis_sim_core *core = m->core;
  uint32_t reads[AXIS_SIM_OOO_SRC], writes[AXIS_SIM_OOO_DST];
  int32_t pools[AXIS_SIM_OOO_DST];
  int32_t nr = 0, nw = 0;
  for (int32_t o = 0; o < entry->operand_count; ++o) {
    const axis_lift_operand *operand = &entry->operands[o];
    if (!operand->role || !axis_op_class(operand)) { continue; }
    uint32_t slot = axis_ooo_dep_slot(m, entry, lifted, o);
    if (slot >= AXIS_SIM_PRODUCERS) { continue; }
    if (((operand->role_code != AXIS_ROLE_OUT) || axis_ooo_reads(m, entry, o)) && nr < (int32_t)AXIS_SIM_OOO_SRC) { reads[nr++] = slot; }
    if (((operand->role_code == AXIS_ROLE_OUT) || (operand->role_code == AXIS_ROLE_INOUT)) && nw < (int32_t)AXIS_SIM_OOO_DST) { writes[nw++] = slot; }
  }
  nr += axis_ooo_implicit_reads(m, entry, reads + nr, (int32_t)AXIS_SIM_OOO_SRC - nr);
  nw += axis_ooo_implicit_writes(m, entry, writes + nw, pools, (int32_t)AXIS_SIM_OOO_DST - nw);
  int32_t unit = -1;
  const char *uname = axis_sim_unit_on(core, entry);
  for (int32_t u = 0; uname && uname[0] && u < core->unit_count; ++u) {
    if (!strcmp(core->units[u].name, uname)) { unit = u; break; }
  }
  return axis_fuse_pair(m, entry, unit, axis_sim_latency_on(core, entry), reads, nr, writes, nw, m->acc_count > 0);
}
"#;

const STORE_BUFFER_C: &str = r#"
/* ---- the stores a core has retired and not yet written (WM1,
   docs/memory_model_design.md) ------------------------------------------
   Without a buffer a store is memory's, and every core's, the moment it
   retires: sequential consistency. With one, a store that retires WAITS:
   this core's own loads read it from the buffer, and no other core sees it
   until it is written. A buffer that drains in order is total store order;
   one that writes each store when its own line is ready -- never past an
   older store to the same bytes -- lets two stores reach memory out of
   program order, which only a relaxed model allows.

   What must not be reordered does not use it: an instruction that ORDERS
   MEMORY -- a barrier, an atomic or exclusive access, an acquire or release,
   a read-modify-write -- retires only when the buffer is empty, and what it
   stores is written as it retires. */
static void axis_x_snoop(axis_pack_machine *m, uint64_t addr, uint32_t width);
static int axis_sim_orders(const axis_lift_entry *entry);
/* Memory as this core sees it: what is written, under what it has retired. */
static uint64_t axis_sb_overlay(const axis_pack_machine *m, uint64_t addr, uint32_t width, uint64_t value) {
  uint32_t bytes = width >= 8u ? width / 8u : 1u;
  for (uint32_t i = 0; i < m->sb_count; ++i) {
    uint32_t wb = m->sb_width[i] >= 8u ? m->sb_width[i] / 8u : 1u;
    for (uint32_t b = 0; b < bytes && b < 8u; ++b) {
      uint64_t at = addr + b;
      if (at >= m->sb_addr[i] && at < m->sb_addr[i] + wb) {
        uint64_t byte = (m->sb_value[i] >> (8u * (uint32_t)(at - m->sb_addr[i]))) & 0xFFu;
        value = (value & ~(0xFFull << (8u * b))) | (byte << (8u * b));
      }
    }
  }
  return value;
}
/* Entry `i` is written: memory's, and everyone's -- a core beside this one
   that read those bytes early read them stale. */
static void axis_sb_write(axis_pack_machine *m, uint32_t i) {
  uint64_t addr = m->sb_addr[i];
  uint32_t width = m->sb_width[i];
  if (m->host.write) { m->host.write(m->host.ctx, addr, m->sb_value[i], width); }
  for (uint32_t k = i + 1u; k < m->sb_count; ++k) {
    m->sb_addr[k - 1u] = m->sb_addr[k];
    m->sb_value[k - 1u] = m->sb_value[k];
    m->sb_width[k - 1u] = m->sb_width[k];
    m->sb_done[k - 1u] = m->sb_done[k];
    m->sb_started[k - 1u] = m->sb_started[k];
  }
  m->sb_count--;
  if (m->x_peer_count) { axis_x_snoop(m, addr, width); }
}
static void axis_sb_push(axis_pack_machine *m, uint64_t addr, uint64_t value, uint32_t width) {
  /* An instruction with more stores than the buffer holds pushes the oldest out. */
  if (m->sb_count >= m->sb_entries || m->sb_count >= AXIS_SIM_SB_MAX) { axis_sb_write(m, 0u); }
  uint32_t i = m->sb_count++;
  m->sb_addr[i] = addr;
  m->sb_value[i] = value;
  m->sb_width[i] = width;
  m->sb_done[i] = 0;
  m->sb_started[i] = 0;
}
/* ⚠️ ONE CYCLE of the buffer. A store asks for its line -- the cache access a
   store made when it retired, on a core with no buffer -- and is written the
   cycle after the line is there, one store a cycle. In order, only the oldest
   asks and only the oldest is written; in any order every store asks as it
   enters, and the oldest one ready is written unless an older one covers
   some of the same bytes.

   ⚠️ A BLOCKING CACHE (docs/blocking_cache_design.md) takes one request a
   cycle and none while a miss is on its way, from the buffer as from
   anything: a store asks only when the cache is free, the oldest that has
   not asked first, and AFTER the cycle's loads have issued -- a load is
   what the machine is waiting for, and a store that has retired is not. So
   the buffer is that cache's write buffer -- commit does not wait for a
   store's line -- and it drains in order whatever it says. */
static int axis_sim_core_blocking(const axis_sim_core *core);
static void axis_sb_ask(axis_pack_machine *m, int blocking) {
  for (uint32_t i = 0; i < m->sb_count && (m->sb_any || !i); ++i) {
    if (m->sb_started[i]) { continue; }
    if (blocking && m->dc_free > m->now) { break; }
    uint64_t stall = m->pending_stall;
    m->tlb_skip = 1;  /* translated when it executed */
    axis_sim_touch(m, m->sb_addr[i], 1);
    m->tlb_skip = 0;
    m->sb_done[i] = m->now + 1u + (m->pending_stall - stall);
    m->pending_stall = stall;
    m->sb_started[i] = 1;
  }
}
/* The end of a cycle, for a blocking cache: what has not asked may. */
static void axis_sb_late(axis_pack_machine *m) {
  if (m->sb_count && axis_sim_core_blocking(m->core)) { axis_sb_ask(m, 1); }
}
static void axis_sb_cycle(axis_pack_machine *m) {
  if (!m->sb_count) { return; }
  for (uint32_t i = 0; i < m->sb_count && (m->sb_any || !i); ++i) {
    if (!m->sb_started[i] || m->sb_done[i] > m->now) { continue; }
    uint32_t wb = m->sb_width[i] >= 8u ? m->sb_width[i] / 8u : 1u;
    int behind = 0;
    for (uint32_t k = 0; k < i && !behind; ++k) {
      uint32_t kb = m->sb_width[k] >= 8u ? m->sb_width[k] / 8u : 1u;
      behind = m->sb_addr[k] < m->sb_addr[i] + wb && m->sb_addr[i] < m->sb_addr[k] + kb;
    }
    if (behind) { continue; }
    axis_sb_write(m, i);
    break;
  }
  if (!axis_sim_core_blocking(m->core)) { axis_sb_ask(m, 0); }
}
/* A core run by itself that stops writes what it holds, oldest first: there
   is nobody beside it to see when. */
static void axis_sb_flush(axis_pack_machine *m) {
  while (m->sb_count) { axis_sb_write(m, 0u); }
}
static int axis_sb_ordered(axis_sim_rob_entry *e) {
  /* A cracked instruction retires whole (U1), so it is treated as one that orders. */
  if (!e->x_ordered) { e->x_ordered = (e->x_uops > 1 || axis_sim_orders(e->x_lifted.entry)) ? 2 : 1; }
  return e->x_ordered == 2;
}
/* Whether `e` may retire this cycle, as far as the buffer goes. */
static int axis_sb_admits(const axis_pack_machine *m, axis_sim_rob_entry *e) {
  if (!m->sb_entries) { return 1; }
  if (axis_sb_ordered(e)) { return m->sb_count == 0u; }
  return e->x_mcount <= 0 || !m->sb_count || m->sb_count + (uint32_t)e->x_mcount <= m->sb_entries;
}
"#;

const TARGET_QUEUE_C: &str = r#"
/* ---- a DECOUPLED front end (FQ1, docs/front_end_design.md) --------------
   The predictor does not wait for fetch. It runs ahead down the path it
   predicts, naming one line of code a cycle, and what it has named waits in
   a queue for fetch to arrive: `(target-queue N)` lines beyond the one fetch
   is reading, and no more. A line is asked of the instruction cache WHEN IT
   IS NAMED, so a line fetch is slow to reach -- because the one before it
   missed, or the window behind it is full, or a line is several fetch groups
   long -- has been on its way since, and what fetch waits for is what is
   left of the fill.

   Neither engine walks the predictor ahead. The cycle a line was named is
   what the queue's own arithmetic says it was, worked out when fetch arrives:

       named(i) = max( named(i-1) + 1,  read(i-N) )   and never after fetch,

   one line a cycle, and the queue's last slot is free once fetch is reading
   the line N back. Three things empty the queue, and the line after them is
   named as fetch arrives at it: a redirect, since what was named was the
   wrong path's; a branch the predictor had no target for, which decode
   finds; and a new page, which the predictor names but does not translate. */
static void axis_tq_reset(axis_pack_machine *m) { m->tq_live = 0; m->tq_count = 0; m->tq_new_page = 0; }
static void axis_tq_select(axis_pack_machine *m, int32_t slot) {
  m->tq_entries = AXIS_SIM_CORE_TQ[slot] < 64u ? AXIS_SIM_CORE_TQ[slot] : 64u;
  axis_tq_reset(m);
}
static uint64_t axis_tq_named(const axis_pack_machine *m, uint64_t arrives) {
  uint64_t named = arrives;
  if (m->tq_entries && m->tq_live && !m->tq_new_page) {
    named = m->tq_named + 1u;
    if (m->tq_count >= m->tq_entries) {
      uint64_t read = m->tq_read[(m->tq_count - m->tq_entries) % 64u];
      if (read > named) { named = read; }
    }
    if (named > arrives) { named = arrives; }
  }
  return named;
}
static void axis_tq_took(axis_pack_machine *m, uint64_t named, uint64_t read) {
  m->tq_named = named;
  m->tq_read[m->tq_count % 64u] = read;
  m->tq_count++;
  m->tq_live = 1;
  m->tq_new_page = 0;
}
"#;

const FRONT2_C: &str = r#"
/* ⚠️ TWO WAYS ROUND DECODE (U2). Code a machine has decoded before need not
   be fetched and decoded again.

   THE MICRO-OP CACHE holds windows of code as decoded micro-ops. Fetch
   entering a window the cache holds takes it from there: no instruction-
   cache lookup and no fetch-TLB lookup, `oc_width` MICRO-OPS a cycle where
   decode delivers `fetch_width` instructions, and `oc_depth` stages to
   dispatch where the front end has `fe_depth`. A window it does not hold is
   fetched and decoded as ever, and is in the cache afterwards.

   THE LOOP BUFFER replays a small loop. A backward branch taken twice
   running, over a body of at most `lb_ops` micro-ops with no other taken
   branch in it, is a loop the buffer holds: from then on the body comes out
   of the buffer, `lb_width` micro-ops a cycle, `lb_depth` stages from
   dispatch, and the loop's branch does not end a fetch group -- the buffer
   wraps. It stops when fetch leaves the body.

   A change of path starts a new fetch group. */
static uint32_t axis_fe_ops(const axis_pack_machine *m, const axis_lift_entry *entry) {
  const axis_sim_crack *crack = entry ? axis_sim_crack_of(m, entry) : 0;
  return crack ? (uint32_t)crack->count : 1u;
}
static void axis_fe2_select(axis_pack_machine *m, int32_t slot) {
  const uint32_t *row = AXIS_SIM_CORE_FE2[slot];
  m->oc_entries = row[0] < AXIS_SIM_ICACHE_LINES ? row[0] : AXIS_SIM_ICACHE_LINES;
  m->oc_ways = row[1] ? row[1] : 1u;
  m->oc_bytes = row[2] ? row[2] : 64u;
  m->oc_width = row[3] ? row[3] : 1u;
  m->oc_depth = row[4];
  m->lb_ops = row[5];
  m->lb_width = row[6] ? row[6] : 1u;
  m->lb_depth = row[7];
  memset(m->oc_valid, 0, sizeof m->oc_valid);
  m->oc_clock = 0;
  m->oc_have = 0;
  m->oc_hit = 0;
  m->lb_on = 0;
  m->lb_next = -1;
  m->lb_cand_branch = ~0ull;
  m->lb_run = 0;
  m->lb_clean = 0;
  m->fe_path = 0;
  m->oc_reenter = 0;
  m->micro_ops = 0;
  m->op_cache_ops = 0;
  m->loop_buffer_ops = 0;
}
/* 1 when the cache holds `window`; if not, decode builds it and it is there
   next time, over the least recently used way of its set. */
static int axis_oc_touch(axis_pack_machine *m, uint64_t window) {
  uint32_t ways = m->oc_ways > m->oc_entries ? m->oc_entries : m->oc_ways;
  uint32_t sets = ways ? m->oc_entries / ways : 0u;
  if (!sets) { return 0; }
  uint32_t base = (uint32_t)(window % sets) * ways;
  m->oc_clock++;
  for (uint32_t w = 0; w < ways; ++w) {
    if (m->oc_valid[base + w] && m->oc_tag[base + w] == window) { m->oc_used[base + w] = m->oc_clock; return 1; }
  }
  uint32_t victim = base;
  for (uint32_t w = 0; w < ways; ++w) {
    if (!m->oc_valid[base + w]) { victim = base + w; break; }
    if (m->oc_used[base + w] < m->oc_used[victim]) { victim = base + w; }
  }
  m->oc_valid[victim] = 1;
  m->oc_tag[victim] = window;
  m->oc_used[victim] = m->oc_clock;
  return 0;
}
/* The path the instruction at `pc` comes by. */
static int32_t axis_fe_path(axis_pack_machine *m, uint64_t pc) {
  if (m->lb_on) {
    if (pc >= m->lb_target && pc <= m->lb_branch) { return 2; }
    m->lb_on = 0;
  }
  if (!m->oc_entries) { return 0; }
  uint64_t window = pc / m->oc_bytes;
  if (!m->oc_have || window != m->oc_window) {
    m->oc_hit = axis_oc_touch(m, window);
    m->oc_window = window;
    m->oc_have = 1;
  }
  return m->oc_hit ? 1 : 0;
}
/* What the loop buffer learns from one instruction, in the order the front
   end sees them: how many micro-ops, and for a branch whether it was taken
   and where to. What it decides takes effect AFTER this instruction
   (`lb_next`): the branch that makes a loop is not itself from the buffer,
   and the one that ends it still is. */
static void axis_lb_saw(axis_pack_machine *m, uint64_t pc, uint32_t ops, int32_t branch, int32_t taken,
                        uint64_t target) {
  if (branch && taken) { m->oc_reenter = 1; }
  if (!m->lb_ops) { return; }
  m->lb_run += ops;
  if (!branch) { return; }
  if (!taken) {
    if (pc == m->lb_cand_branch) { m->lb_cand_branch = ~0ull; }
    if (m->lb_on && pc == m->lb_branch) { m->lb_next = 0; }
    return;
  }
  if (target > pc) {
    m->lb_clean = 0;
    if (m->lb_on) { m->lb_next = 0; }
    return;
  }
  if (m->lb_cand_branch == pc && m->lb_cand_target == target && m->lb_clean && m->lb_run <= m->lb_ops) {
    if (!m->lb_on) { m->lb_branch = pc; m->lb_target = target; m->lb_next = 1; }
  } else if (m->lb_on) { m->lb_next = 0; }
  m->lb_cand_branch = pc;
  m->lb_cand_target = target;
  m->lb_run = 0;
  m->lb_clean = 1;
}
/* ⚠️ And a branch that was taken sends fetch INTO a window, which is a
   lookup even when it is the window fetch was already in: a loop inside one
   window was otherwise decoded for ever, having missed once on the way in. */
static void axis_lb_settle(axis_pack_machine *m) {
  if (m->lb_next >= 0) { m->lb_on = m->lb_next; m->lb_next = -1; }
  if (m->oc_reenter) { m->oc_have = 0; m->oc_reenter = 0; }
}
"#;

/// A cracked instruction's micro-ops, as the simulator reads them (U1).
const CRACK_TYPES_C: &str = r#"
/* ⚠️ MICRO-OPS (U1, docs/micro_ops_design.md). A core may divide an
   instruction into several: each has its own entry in the window, its own
   unit and its own latency. The core says only the unit and the cycles; what
   each micro-op reads, writes and loads is divided out of the instruction's
   own effects when the description is read, and arrives here as masks --
   operands by position, memory accesses by the order the instruction makes
   them, and the micro-ops whose results this one waits for. */
#define AXIS_SIM_CRACK_MAX 8
typedef struct axis_sim_micro_op {
  const char *unit;
  uint32_t latency;
  uint32_t reads;      /* operands, by position */
  uint32_t writes;
  uint32_t accesses;   /* which of the instruction's accesses, in order */
  uint32_t after;      /* micro-ops it waits for, by position */
  int32_t rest;        /* and every access past its last */
  int32_t implicit;    /* state, fixed registers, the pc */
} axis_sim_micro_op;
struct axis_sim_crack {
  const char *mnemonic;
  int32_t count;
  axis_sim_micro_op op[AXIS_SIM_CRACK_MAX];
};
"#;

const CRACK_C: &str = r#"
static const axis_sim_crack *axis_sim_crack_of(const axis_pack_machine *m, const axis_lift_entry *entry) {
  if (!m->core || !entry) { return 0; }
  const axis_sim_crack *row = AXIS_SIM_CORE_CRACKS[m->core - AXIS_SIM_CORES];
  for (; row && row->mnemonic; ++row) {
    if (!strcmp(row->mnemonic, entry->mnemonic)) { return row; }
  }
  return 0;
}

/* ⚠️ ONE INSTRUCTION, SEVERAL ENTRIES (U1), trace-driven. Each micro-op waits
   for room of its own -- an entry, a queue slot, a load or store slot if it
   has an access, a register for each result -- and takes its place in the
   dispatch width, so a cracked instruction may straddle a cycle. It issues to
   its own unit when what IT reads is ready: the instruction's operands as
   they were before the instruction, whichever micro-op goes first, and the
   micro-ops it is `after`. So a base moved on by an add is ready an add
   later, not a load later, and a sum of a load waits for the load.

   Returns the LAST micro-op's entry: the one a redirect is armed on, since
   the pc is its. */
static axis_sim_rob_entry *axis_sim_dispatch_cracked(axis_pack_machine *m, const axis_lift_entry *entry,
                                                     const axis_lifted *lifted, const axis_sim_crack *crack) {
  const axis_sim_core *core = m->core;
  uint32_t rob = axis_ooo_rob(core);
  uint32_t queue = core->issue_queue ? core->issue_queue : rob;
  uint32_t width = axis_disp_width(m);
  /* What each operand names, and who makes it -- BEFORE the instruction. */
  uint32_t slot_of[32];
  uint64_t before[32];
  for (int32_t o = 0; o < 32; ++o) {
    slot_of[o] = AXIS_SIM_PRODUCERS;
    before[o] = AXIS_SIM_NO_SEQ;
    if (o >= entry->operand_count) { continue; }
    const axis_lift_operand *operand = &entry->operands[o];
    if (!operand->role || !axis_op_class(operand)) { continue; }
    slot_of[o] = axis_ooo_dep_slot(m, entry, lifted, o);
    if (slot_of[o] < AXIS_SIM_PRODUCERS) { before[o] = m->reg_producer[slot_of[o]]; }
  }
  uint32_t read_slot[AXIS_SIM_OOO_SRC];
  uint64_t read_before[AXIS_SIM_OOO_SRC];
  int32_t reads = axis_ooo_implicit_reads(m, entry, read_slot, (int32_t)AXIS_SIM_OOO_SRC);
  for (int32_t i = 0; i < reads; ++i) { read_before[i] = m->reg_producer[read_slot[i]]; }
  const char *address = axis_sim_store_address(entry);
  uint64_t stall = m->pending_stall;
  m->pending_stall = 0;
  uint64_t walked = m->pending_walk;
  m->pending_walk = 0;
  uint64_t seq_of[AXIS_SIM_CRACK_MAX];
  axis_sim_rob_entry *e = 0;
  for (int32_t u = 0; u < crack->count && u < AXIS_SIM_CRACK_MAX; ++u) {
    const axis_sim_micro_op *op = &crack->op[u];
    /* Its accesses: the ones it is given, and past its last if it takes the
       rest. */
    int32_t top = -1;
    for (int32_t a = 0; a < 32; ++a) { if ((op->accesses >> a) & 1u) { top = a; } }
    int32_t mine[AXIS_SIM_OOO_MEM];
    int32_t mine_count = 0, is_load = 0, is_store = 0;
    for (int32_t a = 0; a < m->acc_count && a < (int32_t)AXIS_SIM_OOO_MEM; ++a) {
      int32_t own = (a < 32 && ((op->accesses >> a) & 1u)) || (op->rest && a > top);
      if (!own) { continue; }
      mine[mine_count++] = a;
      if (m->acc_write[a]) { is_store = 1; } else { is_load = 1; }
    }
    /* Its results. */
    int32_t want_pool[AXIS_SIM_OOO_DST];
    uint32_t want_slot[AXIS_SIM_OOO_DST];
    int32_t want = 0;
    for (int32_t o = 0; o < entry->operand_count && o < 32 && want < (int32_t)AXIS_SIM_OOO_DST; ++o) {
      if (!((op->writes >> o) & 1u) || slot_of[o] >= AXIS_SIM_PRODUCERS) { continue; }
      const axis_lift_operand *operand = &entry->operands[o];
      const axis_reg_class *rules = axis_op_class(operand);
      int32_t pool = -1;
      if (slot_of[o] < AXIS_SIM_REG_SLOTS && !(rules->zero_index >= 0 && lifted->operands[o] == (uint64_t)rules->zero_index)) {
        pool = axis_sim_rename_pool(core, operand->kind);
      }
      want_pool[want] = pool;
      want_slot[want++] = slot_of[o];
    }
    if (op->implicit) {
      want += axis_ooo_implicit_writes(m, entry, want_slot + want, want_pool + want, (int32_t)AXIS_SIM_OOO_DST - want);
    }
    /* Room: the window, the queue, the load and store queues, the registers,
       and this cycle's dispatch width -- each as an instruction's own waits. */
    while (axis_rob_full(m, rob, 1u)) { axis_ooo_tick(m); }
    for (;;) {
      uint32_t waiting = 0, loads = 0, stores = 0;
      for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
        const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
        if (!o->valid) { continue; }
        waiting += o->issued ? 0u : 1u;
        loads += o->is_load ? 1u : 0u;
        stores += o->is_store ? 1u : 0u;
      }
      int full = waiting >= queue
              || (core->lsq && ((is_load && core->load_queue && loads >= core->load_queue)
                                || (is_store && core->store_queue && stores >= core->store_queue)));
      uint32_t need[AXIS_SIM_RENAME_POOLS] = {0};
      for (int32_t d = 0; d < want; ++d) { if (want_pool[d] >= 0) { need[want_pool[d]]++; } }
      int short_of = 0;
      for (int32_t p = 0; p < core->rename_count && p < (int32_t)AXIS_SIM_RENAME_POOLS; ++p) {
        if (need[p] && m->rename_used[p] + need[p] > core->rename[p].extra) { short_of = 1; }
      }
      if (!full && (!short_of || m->rob_head == m->rob_tail)) { break; }
      axis_ooo_tick(m);
    }
    {
      int32_t bound = -1;
      for (int32_t k = 0; k < core->unit_count; ++k) {
        if (!strcmp(core->units[k].name, op->unit)) { bound = k; break; }
      }
      while (axis_unit_queue_full(m, bound)) { axis_ooo_tick(m); }
    }
    if (m->now > m->dispatch_cycle) { m->dispatch_cycle = m->now; m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0; }
    while (m->dispatched_this_cycle >= width || axis_rename_full(m, (uint32_t)want)) { axis_ooo_tick(m); m->dispatch_cycle = m->now; m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0; }
    m->renamed_this_cycle += (uint32_t)want;
    e = &m->rob[m->rob_tail % AXIS_SIM_ROB_MAX];
    memset(e, 0, sizeof *e);
    e->seq = m->rob_tail;
    e->valid = 1;
    e->pc = m->step_pc;
    e->is_load = is_load;
    e->is_store = is_store;
    e->latency = op->latency;
    e->unit = -1;
    for (int32_t k = 0; k < core->unit_count; ++k) {
      if (!strcmp(core->units[k].name, op->unit)) { e->unit = k; break; }
    }
    if (core->lsq && core->disambiguation == 3u && core->store_sets && (is_load || is_store)) {
      uint32_t n = core->store_sets < AXIS_SIM_SSIT_MAX ? core->store_sets : AXIS_SIM_SSIT_MAX;
      e->store_set = m->ssit[(uint32_t)((e->pc >> 2) % n)];
    }
    for (int32_t i = 0; i < mine_count; ++i) {
      e->mem_lo[i] = m->acc_lo[mine[i]];
      e->mem_hi[i] = m->acc_hi[mine[i]];
      e->mem_count = i + 1;
    }
    /* What the cache charged the instruction is the memory micro-op's. */
    if (mine_count || u + 1 == crack->count) { e->stall = stall; stall = 0; e->walk = walked; walked = 0; }
    for (int32_t d = 0; d < AXIS_SIM_OOO_DST; ++d) { e->dst_pool[d] = -1; }
    for (int32_t o = 0; o < entry->operand_count && o < 32; ++o) {
      if (!((op->reads >> o) & 1u) || before[o] == AXIS_SIM_NO_SEQ) { continue; }
      int32_t seen = 0;
      for (int32_t k = 0; k < e->src_count && !seen; ++k) { seen = e->src_seq[k] == before[o]; }
      if (!seen && e->src_count < AXIS_SIM_OOO_SRC) { e->src_seq[e->src_count++] = before[o]; }
      if (is_store && (!address || axis_sim_names(address, entry->operands[o].name))
          && e->addr_src_count < AXIS_SIM_OOO_SRC) {
        e->addr_src_seq[e->addr_src_count++] = before[o];
      }
    }
    for (int32_t v = 0; v < u; ++v) {
      if (((op->after >> v) & 1u) && e->src_count < AXIS_SIM_OOO_SRC) { e->src_seq[e->src_count++] = seq_of[v]; }
    }
    if (op->implicit) {
      for (int32_t i = 0; i < reads && e->src_count < AXIS_SIM_OOO_SRC; ++i) {
        if (read_before[i] != AXIS_SIM_NO_SEQ) { e->src_seq[e->src_count++] = read_before[i]; }
      }
    }
    for (int32_t d = 0; d < want && e->dst_count < AXIS_SIM_OOO_DST; ++d) {
      e->dst_pool[e->dst_count] = want_pool[d];
      e->dst_slot[e->dst_count++] = want_slot[d];
      if (want_pool[d] >= 0) { m->rename_used[want_pool[d]]++; }
      m->reg_producer[want_slot[d]] = e->seq;
    }
    seq_of[u] = e->seq;
    m->rob_tail++;
    m->dispatched_this_cycle++;
    m->micro_ops++;
  }
  return e;
}
"#;

/// The quick predictor a core's own overrides at decode (docs/ooo_design.md,
/// D3): the built-in bimodal table, a second instance of it.
const QUICK_C: &str = r#"
/* ⚠️ OVERRIDDEN AT DECODE (D3). A predictor good enough to be worth having
   does not answer in the cycle fetch needs an answer in. So a machine keeps a
   quick one -- two-bit counters by pc -- for fetch to follow, and lets the
   real one speak `quick_cycles` later, at decode: where they agree nothing
   happened, and where they do not the front end is redirected -- to the
   target, when the quick guess was "not taken" and the real one says taken,
   which is the decode-time redirect of a branch guessed not taken; back to
   the fall-through, when it was the other way round and the buffer had a
   target for fetch to have gone to. Either way the instructions fetched
   meanwhile are discarded and the lines they came from stay in the cache.

   What the machine PREDICTED is the real predictor's answer, and a mispredict
   is that answer being wrong: the quick one costs time and never accuracy.
   It keeps no history, so a squash has nothing of its to put back, and it is
   trained with what the branch did when the real one is. */
static int32_t axis_quick_predict(axis_pack_machine *m, uint64_t pc) {
  return m->quick_state ? (axis_bimodal_predict(m->quick_state, pc) != 0) : 0;
}
static void axis_quick_train(axis_pack_machine *m, uint64_t pc, int32_t taken) {
  if (!m->quick_state) { return; }
  (void)axis_bimodal_predict(m->quick_state, pc);
  axis_bimodal_update(m->quick_state, pc, taken);
}
static void axis_quick_drop(axis_pack_machine *m) {
  if (m->quick_state) { axis_table_destroy(m->quick_state); }
  m->quick_state = 0;
  m->quick_cycles = 0;
}
static void axis_quick_select(axis_pack_machine *m, int32_t slot) {
  axis_quick_drop(m);
  if (slot < 0 || slot >= AXIS_SIM_CORE_COUNT || !AXIS_SIM_CORE_QUICK[slot][0]) { return; }
  axis_sim_core as = AXIS_SIM_CORES[slot];
  as.predictor_entries = AXIS_SIM_CORE_QUICK[slot][0];
  m->quick_state = axis_bimodal_create(&as);
  m->quick_cycles = m->quick_state ? AXIS_SIM_CORE_QUICK[slot][1] : 0u;
}
"#;

/// The direction predictors this library ships, each implementing
/// `axis_sim_predictor` exactly as a host's would (docs/ooo_design.md, O8),
/// and the registry that finds one by name.
const PREDICTORS_C: &str = r#"
/* ---- built-in predictors: bimodal, gshare, tage ---------------------- */
static uint32_t axis_pred_entries(const axis_sim_core *core) {
  uint32_t n = core->predictor_entries ? core->predictor_entries : 1u;
  return n > 4096u ? 4096u : n;
}

/* Two-bit saturating counters: one surprise does not undo a habit. */
static void axis_pred_count(uint8_t *c, int32_t taken) {
  if (taken) { if (*c < 3u) { (*c)++; } } else if (*c > 0u) { (*c)--; }
}

typedef struct { uint32_t n; uint32_t bits; uint64_t history; uint32_t last; uint8_t *ctr; } axis_pred_table;

static void *axis_bimodal_create(const axis_sim_core *core) {
  axis_pred_table *t = calloc(1, sizeof *t);
  if (!t) { return 0; }
  t->n = axis_pred_entries(core);
  t->ctr = calloc(t->n, 1);
  return t;
}
static void axis_table_destroy(void *state) {
  axis_pred_table *t = state;
  if (t) { free(t->ctr); free(t); }
}
static int32_t axis_bimodal_predict(void *state, uint64_t pc) {
  axis_pred_table *t = state;
  t->last = (uint32_t)((pc >> 2) % t->n);
  return t->ctr[t->last] >= 2u;
}
static void axis_bimodal_update(void *state, uint64_t pc, int32_t taken) {
  axis_pred_table *t = state; (void)pc;
  axis_pred_count(&t->ctr[t->last], taken);
}

/* gshare: the same counters, indexed by address XOR the last `history`
   outcomes -- a counter per recent history rather than per address. */
static void *axis_gshare_create(const axis_sim_core *core) {
  axis_pred_table *t = axis_bimodal_create(core);
  if (t) { t->bits = core->predictor_history; }
  return t;
}
static int32_t axis_gshare_predict(void *state, uint64_t pc) {
  axis_pred_table *t = state;
  uint64_t mask = t->bits >= 64u ? ~0ull : ((1ull << t->bits) - 1u);
  t->last = (uint32_t)(((pc >> 2) ^ (t->history & mask)) % t->n);
  return t->ctr[t->last] >= 2u;
}
static void axis_gshare_update(void *state, uint64_t pc, int32_t taken) {
  axis_pred_table *t = state; (void)pc;
  axis_pred_count(&t->ctr[t->last], taken);
  t->history = (t->history << 1) | (uint64_t)(taken != 0);
}

/* ⚠️ TAGE: a bimodal base and `tables` tagged tables, table i indexed and
   tagged by address and the last L(i) outcomes, L geometric from
   `min-history` to `history`. The LONGEST matching table predicts; a
   mispredict allocates in a longer one whose entry nobody is using. That is
   what lets it learn a pattern a short history cannot see without paying for
   a long history on branches that do not need one. */
#define AXIS_TAGE_TABLES 8
typedef struct {
  uint32_t n, tables, tag_bits;
  uint32_t length[AXIS_TAGE_TABLES];
  uint64_t history;
  uint8_t *base;
  uint16_t *tag[AXIS_TAGE_TABLES];
  int8_t *ctr[AXIS_TAGE_TABLES];
  uint8_t *useful[AXIS_TAGE_TABLES];
  /* what predict found, for update */
  int32_t provider, alt_pred, provider_pred;
  uint32_t index[AXIS_TAGE_TABLES], want[AXIS_TAGE_TABLES], base_index;
} axis_tage;

/* ⚠️ The last `length` outcomes, MIXED rather than folded. Hardware folds
   history by XOR into a few bits, and a first version did the same -- and a
   loop's history, which repeats with the loop, folded to one value for every
   phase whenever the fold width divided the period: two histories that
   differ landed on one entry with one tag, and the longest table could not
   tell them apart. TAGE paid three times a period where gshare paid one. A
   multiply spreads every bit of the masked history over the word, so
   distinct histories collide only as often as a hash does. */
static uint64_t axis_mix(uint64_t h, uint32_t length) {
  if (length < 64u) { h &= (1ull << length) - 1u; }
  return (h + 1u) * 0x9E3779B97F4A7C15ull;
}
static void axis_tage_destroy(void *state) {
  axis_tage *t = state;
  if (!t) { return; }
  free(t->base);
  for (uint32_t i = 0; i < t->tables; ++i) { free(t->tag[i]); free(t->ctr[i]); free(t->useful[i]); }
  free(t);
}
static void *axis_tage_create(const axis_sim_core *core) {
  axis_tage *t = calloc(1, sizeof *t);
  if (!t) { return 0; }
  t->n = axis_pred_entries(core);
  t->tables = axis_sim_param_of(core, "tables", 4u);
  if (t->tables > AXIS_TAGE_TABLES) { t->tables = AXIS_TAGE_TABLES; }
  if (t->tables < 1u) { t->tables = 1u; }
  t->tag_bits = axis_sim_param_of(core, "tag-bits", 8u);
  double low = (double)axis_sim_param_of(core, "min-history", 4u);
  double high = (double)(core->predictor_history ? core->predictor_history : 32u);
  for (uint32_t i = 0; i < t->tables; ++i) {
    /* L(i) = low * (high / low) ^ (i / (tables - 1)), by repeated product so
       no libm is needed. */
    double l = low;
    if (t->tables > 1u) {
      double step = 1.0, ratio = high / low;
      /* the (tables-1)-th root of ratio, by bisection */
      double lo = 1.0, hi = ratio > 1.0 ? ratio : 1.0;
      for (int k = 0; k < 60; ++k) {
        double mid = (lo + hi) / 2, p = 1.0;
        for (uint32_t j = 0; j + 1u < t->tables; ++j) { p *= mid; }
        if (p < ratio) { lo = mid; } else { hi = mid; }
      }
      for (uint32_t j = 0; j < i; ++j) { step *= lo; }
      l = low * step;
    }
    t->length[i] = (uint32_t)(l + 0.5);
    if (t->length[i] < 1u) { t->length[i] = 1u; }
    if (t->length[i] > 64u) { t->length[i] = 64u; }
    t->tag[i] = calloc(t->n, sizeof *t->tag[i]);
    t->ctr[i] = calloc(t->n, sizeof *t->ctr[i]);
    t->useful[i] = calloc(t->n, 1);
  }
  t->base = calloc(t->n, 1);
  return t;
}
static int32_t axis_tage_predict(void *state, uint64_t pc) {
  axis_tage *t = state;
  uint64_t a = pc >> 2;
  t->base_index = (uint32_t)(a % t->n);
  int32_t base = t->base[t->base_index] >= 2u;
  t->provider = -1;
  int32_t alt = -1;
  for (uint32_t i = 0; i < t->tables; ++i) {
    uint64_t mixed = axis_mix(t->history, t->length[i]);
    t->index[i] = (uint32_t)((a ^ (mixed >> 40) ^ ((uint64_t)i * 0x9E37u)) % t->n);
    t->want[i] = (uint32_t)(((mixed >> 20) ^ a) & ((1u << t->tag_bits) - 1u)) + 1u;
  }
  for (int32_t i = (int32_t)t->tables - 1; i >= 0; --i) {
    if (t->tag[i][t->index[i]] == t->want[i]) {
      if (t->provider < 0) { t->provider = i; } else if (alt < 0) { alt = i; }
    }
  }
  t->alt_pred = alt >= 0 ? (t->ctr[alt][t->index[alt]] >= 0) : base;
  t->provider_pred = t->provider >= 0 ? (t->ctr[t->provider][t->index[t->provider]] >= 0) : base;
  return t->provider_pred;
}
static void axis_tage_update(void *state, uint64_t pc, int32_t taken) {
  axis_tage *t = state; (void)pc;
  int32_t p = t->provider;
  if (p >= 0) {
    int8_t *c = &t->ctr[p][t->index[p]];
    if (taken) { if (*c < 3) { (*c)++; } } else if (*c > -4) { (*c)--; }
    if (t->provider_pred != t->alt_pred) {
      uint8_t *u = &t->useful[p][t->index[p]];
      if (t->provider_pred == taken) { if (*u < 3u) { (*u)++; } } else if (*u > 0u) { (*u)--; }
    }
  } else {
    axis_pred_count(&t->base[t->base_index], taken);
  }
  /* A mispredict allocates in a LONGER table, in an entry nobody is using;
     when every candidate is in use, they all age instead. */
  if (t->provider_pred != taken) {
    int32_t placed = 0;
    for (uint32_t i = (uint32_t)(p + 1); i < t->tables && !placed; ++i) {
      if (t->useful[i][t->index[i]] == 0u) {
        t->tag[i][t->index[i]] = (uint16_t)t->want[i];
        t->ctr[i][t->index[i]] = taken ? 0 : -1;
        placed = 1;
      }
    }
    if (!placed) {
      for (uint32_t i = (uint32_t)(p + 1); i < t->tables; ++i) {
        if (t->useful[i][t->index[i]] > 0u) { t->useful[i][t->index[i]]--; }
      }
    }
  }
  t->history = (t->history << 1) | (uint64_t)(taken != 0);
}

/* Speculative history (E2): what the history is, putting it back, and moving
   it on by a predicted outcome without training anything. Bimodal keeps no
   history and offers none. */
static uint64_t axis_gshare_history(const void *state) { return ((const axis_pred_table *)state)->history; }
static void axis_gshare_set_history(void *state, uint64_t h) { ((axis_pred_table *)state)->history = h; }
static void axis_gshare_speculate(void *state, uint64_t pc, int32_t taken) {
  axis_pred_table *t = state; (void)pc;
  t->history = (t->history << 1) | (uint64_t)(taken != 0);
}
static uint64_t axis_tage_history(const void *state) { return ((const axis_tage *)state)->history; }
static void axis_tage_set_history(void *state, uint64_t h) { ((axis_tage *)state)->history = h; }
static void axis_tage_speculate(void *state, uint64_t pc, int32_t taken) {
  axis_tage *t = state; (void)pc;
  t->history = (t->history << 1) | (uint64_t)(taken != 0);
}
static const axis_sim_predictor AXIS_SIM_BUILTIN_PREDICTORS[] = {
  { 2u, "bimodal", axis_bimodal_create, axis_table_destroy, axis_bimodal_predict, axis_bimodal_update, 0, 0, 0 },
  { 2u, "gshare", axis_gshare_create, axis_table_destroy, axis_gshare_predict, axis_gshare_update,
    axis_gshare_history, axis_gshare_set_history, axis_gshare_speculate },
  { 2u, "tage", axis_tage_create, axis_tage_destroy, axis_tage_predict, axis_tage_update,
    axis_tage_history, axis_tage_set_history, axis_tage_speculate },
};
#define AXIS_SIM_PREDICTOR_SLOTS 16
static const axis_sim_predictor *AXIS_SIM_PREDICTOR[AXIS_SIM_PREDICTOR_SLOTS];
static int32_t AXIS_SIM_PREDICTOR_COUNT;

/* A registered predictor first -- a host may replace a built-in on purpose --
   then the built-ins. `none` and the empty name are no predictor at all. */
static const axis_sim_predictor *axis_sim_predictor_for(const char *name) {
  if (!name || !name[0] || !strcmp(name, "none")) { return 0; }
  for (int32_t i = 0; i < AXIS_SIM_PREDICTOR_COUNT; ++i) {
    if (AXIS_SIM_PREDICTOR[i] && !strcmp(AXIS_SIM_PREDICTOR[i]->name, name)) { return AXIS_SIM_PREDICTOR[i]; }
  }
  for (size_t i = 0; i < sizeof AXIS_SIM_BUILTIN_PREDICTORS / sizeof AXIS_SIM_BUILTIN_PREDICTORS[0]; ++i) {
    if (!strcmp(AXIS_SIM_BUILTIN_PREDICTORS[i].name, name)) { return &AXIS_SIM_BUILTIN_PREDICTORS[i]; }
  }
  return 0;
}
static int32_t axis_sim_register_predictor(const axis_sim_predictor *predictor) {
  if (!predictor || !predictor->name || !predictor->name[0]) { return 0; }
  if (!predictor->create || !predictor->destroy || !predictor->predict || !predictor->update) { return 0; }
  int32_t asked = 0;
  for (int32_t i = 0; i < AXIS_SIM_CORE_COUNT; ++i) {
    if (AXIS_SIM_CORES[i].predictor_name && !strcmp(AXIS_SIM_CORES[i].predictor_name, predictor->name)) { asked++; }
  }
  if (!asked) { return 0; }
  for (int32_t i = 0; i < AXIS_SIM_PREDICTOR_COUNT; ++i) {
    if (!strcmp(AXIS_SIM_PREDICTOR[i]->name, predictor->name)) { AXIS_SIM_PREDICTOR[i] = predictor; return asked; }
  }
  if (AXIS_SIM_PREDICTOR_COUNT >= AXIS_SIM_PREDICTOR_SLOTS) { return 0; }
  AXIS_SIM_PREDICTOR[AXIS_SIM_PREDICTOR_COUNT++] = predictor;
  return asked;
}
static const char *axis_sim_core_predictor(int32_t slot) {
  return (slot >= 0 && slot < AXIS_SIM_CORE_COUNT) ? AXIS_SIM_CORES[slot].predictor_name : 0;
}
"#;

/// Prefetchers a host binds (PF1, docs/tlb_design.md §3): the registry, the
/// check `select_core` makes, and the binding of each to the cache naming it.
const PREFETCHERS_C: &str = r#"
#define AXIS_SIM_PREFETCHER_SLOTS 16
static const axis_sim_prefetcher *AXIS_SIM_PREFETCHER[AXIS_SIM_PREFETCHER_SLOTS];
static int32_t AXIS_SIM_PREFETCHER_COUNT;

static const axis_sim_prefetcher *axis_sim_prefetcher_for(const char *name) {
  for (int32_t i = 0; name && i < AXIS_SIM_PREFETCHER_COUNT; ++i) {
    if (!strcmp(AXIS_SIM_PREFETCHER[i]->name, name)) { return AXIS_SIM_PREFETCHER[i]; }
  }
  return 0;
}
static int32_t axis_sim_register_prefetcher(const axis_sim_prefetcher *prefetcher) {
  if (!prefetcher || !prefetcher->name || !prefetcher->name[0] || !prefetcher->observe) { return 0; }
  int32_t asked = 0;
  for (int32_t s = 0; s < AXIS_MS_SYSTEM_COUNT; ++s) {
    for (int32_t k = 0; k < AXIS_MS_SYSTEMS[s].node_count; ++k) {
      const char *named = axis_ms_ext_name(&AXIS_MS_SYSTEMS[s], k);
      if (named && !strcmp(named, prefetcher->name)) { asked++; }
    }
  }
  if (!asked) { return 0; }
  for (int32_t i = 0; i < AXIS_SIM_PREFETCHER_COUNT; ++i) {
    if (!strcmp(AXIS_SIM_PREFETCHER[i]->name, prefetcher->name)) { AXIS_SIM_PREFETCHER[i] = prefetcher; return asked; }
  }
  if (AXIS_SIM_PREFETCHER_COUNT >= AXIS_SIM_PREFETCHER_SLOTS) { return 0; }
  AXIS_SIM_PREFETCHER[AXIS_SIM_PREFETCHER_COUNT++] = prefetcher;
  return asked;
}
/* Whether every prefetcher the memory system of core `name` names from
   outside has been bound. A core no system names has none to bind. */
static int axis_sim_prefetchers_bound(const char *name) {
  for (int32_t s = 0; s < AXIS_MS_SYSTEM_COUNT; ++s) {
    const axis_ms_system_cfg *c = &AXIS_MS_SYSTEMS[s];
    int port = 0;
    for (int32_t k = 0; k < c->node_count; ++k) { if (c->nodes[k].core && !strcmp(c->nodes[k].core, name)) { port = 1; } }
    if (!port) { continue; }
    for (int32_t k = 0; k < c->node_count; ++k) {
      const char *named = axis_ms_ext_name(c, k);
      if (named && !axis_sim_prefetcher_for(named)) { return 0; }
    }
    return 1;
  }
  return 1;
}
static void axis_sim_bind_prefetchers(axis_ms *ms) {
  for (int32_t k = 0; k < ms->cfg->node_count; ++k) {
    const axis_sim_prefetcher *p = axis_sim_prefetcher_for(axis_ms_ext_name(ms->cfg, k));
    if (!p) { continue; }
    axis_ms_ext_prefetcher ext = { p->create, p->destroy, p->observe };
    axis_ms_bind_prefetcher(ms, k, &ext);
  }
}
"#;

/// What kind of control transfer each instruction is, read off its declared
/// effects, and each ISA's link register from its `defabi` (O9). Nothing here
/// is marked by hand: a CALL is a jump that links into the ABI's link
/// register, and a RETURN is an indirect jump through it that does not link.
/// Which instructions read memory and which write it, from their declared
/// effects (E3) -- so an execution-driven core knows a load is a load when it
/// DECODES it, not only once it has executed, and can count it against a load
/// queue and hold it behind older stores.
fn emit_memop_table(document: &Document) -> String {
    use crate::effects::{expr_reads_memory, Loc};
    let mut out = String::new();
    out.push_str("typedef struct { const char *isa; const char *mnemonic; int32_t loads; int32_t stores; } axis_sim_memop;\n");
    out.push_str("static const axis_sim_memop AXIS_SIM_MEMOPS[] = {\n");
    for instruction in &document.instructions {
        if !crate::effects::behavior_is_authoritative(instruction) {
            continue;
        }
        let Some(behavior) = instruction.behavior.as_ref() else { continue };
        let mut loads = false;
        let mut stores = false;
        for effect in &behavior.effects {
            if matches!(effect.loc, Loc::Mem { .. }) {
                stores = true;
            }
            if expr_reads_memory(&effect.value.expr)
                || effect.guard.as_ref().is_some_and(|g| expr_reads_memory(&g.expr))
            {
                loads = true;
            }
            if let Loc::Mem { addr, .. } = &effect.loc {
                if expr_reads_memory(&addr.expr) {
                    loads = true;
                }
            }
        }
        if loads || stores {
            out.push_str(&format!(
                "  {{ {}, {}, {}, {} }},\n",
                c_string(&instruction.isa),
                c_string(&instruction.mnemonic),
                i32::from(loads),
                i32::from(stores)
            ));
        }
    }
    out.push_str("  { 0, 0, 0, 0 }\n};\n");
    out.push_str("static void axis_sim_memop_of(const axis_lift_entry *entry, int32_t *loads, int32_t *stores) {\n");
    out.push_str("  *loads = 0;\n  *stores = 0;\n");
    out.push_str("  for (const axis_sim_memop *r = AXIS_SIM_MEMOPS; entry && r->mnemonic; ++r) {\n");
    out.push_str("    if (!strcmp(r->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(r->isa, entry->isa))) {\n");
    out.push_str("      *loads = r->loads;\n      *stores = r->stores;\n      return;\n    }\n  }\n}\n");
    out
}

/// What each instruction does to architectural STATE and to registers no
/// operand names, from its declared effects (A64-1): the state it reads (a
/// state name anywhere in a value, a guard or an address), the state it
/// writes (`setstate`), and the fixed registers it writes (`Loc::FixedReg`,
/// AArch64's BL into X30). An execution-driven core renames these like
/// registers: a CSEL waits for the compare whose flags it reads, a RET for the
/// BL that linked -- found by name when it DECODES, not discovered as a replay
/// when the golden model disagrees at commit.
fn emit_stateop_table(document: &Document) -> String {
    use crate::effects::Loc;
    use crate::semantics::SemanticExpr;
    fn mentions(expr: &SemanticExpr, out: &mut Vec<String>) {
        match expr {
            SemanticExpr::Atom(name) => out.push(name.clone()),
            SemanticExpr::List(items) => items.iter().for_each(|item| mentions(item, out)),
        }
    }
    let names = crate::effects::isa_scalar_state_names(&document.isas);
    let mut out = String::new();
    out.push_str("typedef struct { const char *isa; const char *mnemonic; const char *reads; const char *writes;\n");
    out.push_str("  int32_t fixed_count; const char *fixed_kind[2]; int32_t fixed_index[2]; } axis_sim_stateop;\n");
    out.push_str("static const axis_sim_stateop AXIS_SIM_STATEOPS[] = {\n");
    for instruction in &document.instructions {
        if !crate::effects::behavior_is_authoritative(instruction) {
            continue;
        }
        let Some(behavior) = instruction.behavior.as_ref() else { continue };
        let operands: Vec<&str> = instruction.operands.iter().map(|o| o.name.as_str()).collect();
        let mut atoms = Vec::new();
        let mut writes: Vec<String> = Vec::new();
        let mut fixed: Vec<(String, u32)> = Vec::new();
        for effect in &behavior.effects {
            mentions(&effect.value.expr, &mut atoms);
            if let Some(guard) = &effect.guard {
                mentions(&guard.expr, &mut atoms);
            }
            match &effect.loc {
                Loc::State { name, .. } if !writes.contains(name) => writes.push(name.clone()),
                Loc::FixedReg { kind, index, .. }
                    if fixed.len() < 2 && !fixed.iter().any(|(k, i)| k == kind && i == index) =>
                {
                    fixed.push((kind.clone(), *index));
                }
                Loc::Mem { addr, .. } => mentions(&addr.expr, &mut atoms),
                _ => {}
            }
        }
        let reads: Vec<&String> = names
            .iter()
            .filter(|name| atoms.contains(name) && !operands.contains(&name.as_str()))
            .collect();
        if reads.is_empty() && writes.is_empty() && fixed.is_empty() {
            continue;
        }
        let spaced = |list: &[&String]| {
            format!(" {} ", list.iter().map(|n| n.as_str()).collect::<Vec<_>>().join(" "))
        };
        let kinds: Vec<String> = (0..2)
            .map(|k| fixed.get(k).map_or("0".to_string(), |(kind, _)| c_string(kind)))
            .collect();
        let indices: Vec<String> =
            (0..2).map(|k| fixed.get(k).map_or("0".to_string(), |(_, i)| i.to_string())).collect();
        out.push_str(&format!(
            "  {{ {}, {}, \"{}\", \"{}\", {}, {{ {}, {} }}, {{ {}, {} }} }},\n",
            c_string(&instruction.isa),
            c_string(&instruction.mnemonic),
            spaced(&reads),
            spaced(&writes.iter().collect::<Vec<_>>()),
            fixed.len(),
            kinds[0],
            kinds[1],
            indices[0],
            indices[1]
        ));
    }
    out.push_str("  { 0, 0, 0, 0, 0, { 0, 0 }, { 0, 0 } }\n};\n");
    out
}

fn emit_control_tables(document: &Document) -> String {
    use crate::effects::{expr_atoms, Loc};
    let mut out = String::new();
    out.push_str("typedef struct { const char *isa; const char *mnemonic; int32_t conditional; int32_t indirect;\n");
    out.push_str("  const char *target; const char *link; const char *link_file; int32_t link_index; } axis_sim_control;\n");
    out.push_str("static const axis_sim_control AXIS_SIM_CONTROL[] = {\n");
    let file_of = |class: &str| {
        crate::ast::REGISTER_CLASSES
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(class))
            .map_or(class.to_string(), |c| c.file.to_string())
    };
    for instruction in &document.instructions {
        if !crate::effects::behavior_is_authoritative(instruction) {
            continue;
        }
        let Some(behavior) = instruction.behavior.as_ref() else { continue };
        let Some(jump) = behavior.effects.iter().find(|e| matches!(e.loc, Loc::Pc)) else { continue };
        let registers: Vec<&str> = instruction
            .operands
            .iter()
            .filter(|o| crate::ast::register_class(&o.kind).is_some())
            .map(|o| o.name.as_str())
            .collect();
        let target_atoms = expr_atoms(&jump.value.expr);
        let target = target_atoms.iter().find(|a| registers.contains(&a.as_str())).cloned();
        // A LINK: a write whose value is computed from the pc and no register.
        let mut link = String::new();
        let (mut link_file, mut link_index) = (String::new(), -1i64);
        for effect in &behavior.effects {
            let atoms = expr_atoms(&effect.value.expr);
            let from_pc = atoms.iter().any(|a| a == "pc")
                && !atoms.iter().any(|a| registers.contains(&a.as_str()));
            if !from_pc {
                continue;
            }
            match &effect.loc {
                Loc::Reg(dest) if registers.contains(&dest.as_str()) => link = dest.clone(),
                Loc::FixedReg { kind, index, .. } => {
                    link_file = file_of(kind);
                    link_index = i64::from(*index);
                }
                _ => {}
            }
        }
        out.push_str(&format!(
            "  {{ {}, {}, {}, {}, {}, {}, {}, {} }},\n",
            c_string(&instruction.isa),
            c_string(&instruction.mnemonic),
            i32::from(jump.guard.is_some()),
            i32::from(target.is_some()),
            c_string(target.as_deref().unwrap_or("")),
            c_string(&link),
            c_string(&link_file),
            link_index
        ));
    }
    out.push_str("  { 0, 0, 0, 0, 0, 0, 0, 0 }\n};\n");
    out.push_str("typedef struct { const char *isa; const char *file; uint32_t index; } axis_sim_link_reg;\n");
    out.push_str("static const axis_sim_link_reg AXIS_SIM_LINKS[] = {\n");
    for abi in &document.abis {
        if let Some(link) = &abi.link_register {
            out.push_str(&format!(
                "  {{ {}, {}, {}u }},\n",
                c_string(&abi.isa),
                c_string(&file_of(&link.class)),
                link.first
            ));
        }
    }
    out.push_str("  { 0, 0, 0u }\n};\n");
    out.push_str(r#"static const axis_sim_link_reg *axis_sim_link_of(const char *isa) {
  for (const axis_sim_link_reg *l = AXIS_SIM_LINKS; l->isa; ++l) {
    if (!isa || !strcmp(l->isa, isa)) { return l; }
  }
  return 0;
}
static const char *axis_sim_file_of(const char *kind);
/* Whether operand `name` of this instruction names the link register. */
static int32_t axis_sim_names_link(const axis_lift_entry *entry, const axis_lifted *lifted,
                                   const char *name, const axis_sim_link_reg *link) {
  if (!link || !name || !name[0]) { return 0; }
  for (int32_t o = 0; o < entry->operand_count; ++o) {
    const axis_lift_operand *operand = &entry->operands[o];
    if (!operand->name || strcmp(operand->name, name)) { continue; }
    const char *file = axis_sim_file_of(operand->kind);
    return file && !strcmp(file, link->file) && lifted->operands[o] == (uint64_t)link->index;
  }
  return 0;
}
static void axis_sim_classify(const axis_lift_entry *entry, const axis_lifted *lifted,
                              int32_t *conditional, int32_t *indirect, int32_t *is_call, int32_t *is_return) {
  const axis_sim_control *c = AXIS_SIM_CONTROL;
  for (; c->mnemonic; ++c) {
    if (!strcmp(c->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(c->isa, entry->isa))) { break; }
  }
  if (!c->mnemonic) { return; }  /* unknown: a conditional direct branch, as before */
  const axis_sim_link_reg *link = axis_sim_link_of(entry->isa);
  *conditional = c->conditional;
  *indirect = c->indirect;
  *is_call = axis_sim_names_link(entry, lifted, c->link, link)
             || (link && c->link_file[0] && !strcmp(c->link_file, link->file)
                 && c->link_index == (int32_t)link->index);
  *is_return = c->indirect && !*is_call && axis_sim_names_link(entry, lifted, c->target, link);
}
"#);
    out
}

/// The most 64-bit slots any one WORD reads or writes: over every lane of a
/// scalable word, the distinct places its operands' views fall. A lane names
/// bits of a register by offset, and which register is the word's to say, so
/// two operands are two sets of slots and one operand's lanes are one.
fn widest_word_slots(document: &Document) -> usize {
    use std::collections::{BTreeMap, BTreeSet};
    let mut words: BTreeMap<(String, String), [BTreeSet<(String, i64, u32)>; 2]> = BTreeMap::new();
    for instruction in &document.instructions {
        let origin = if instruction.scalable_origin.is_empty() {
            instruction.mnemonic.clone()
        } else {
            instruction.scalable_origin.clone()
        };
        let sets = words.entry((instruction.isa.clone(), origin)).or_default();
        for operand in &instruction.operands {
            if crate::ast::register_class(&operand.kind).is_none() {
                continue;
            }
            let base = operand.name.split("__l").next().unwrap_or(&operand.name).to_string();
            let limbs = if operand.view_width > 0 { 1 } else { operand.slot_stride.max(1) };
            for limb in 0..limbs {
                // A lane's register is the word's, moved by the lane's own bias: a
                // tile's rows are sixteen registers.
                let place = (
                    base.clone(),
                    i64::from(operand.derived_add) * 4096 + i64::from(operand.lane_register),
                    operand.slot_base + operand.view_offset / 64 + limb,
                );
                if operand.input {
                    sets[0].insert(place.clone());
                }
                if operand.output {
                    sets[1].insert(place);
                }
            }
        }
    }
    words.values().map(|sets| sets[0].len().max(sets[1].len())).max().unwrap_or(0)
}

/// Which destinations an instruction may LEAVE AS THEY WERE
/// (docs/vector_units_design.md, VM2): a register written under a guard keeps
/// its old value when the guard fails, so the register the instruction
/// produces is made from the one before it -- a non-faulting load's lanes past
/// the fault, a conditional move not taken. The operand says `out`; the
/// pipeline has to read it.
fn emit_keeps_table(document: &Document) -> String {
    use crate::effects::Loc;
    let mut out = String::new();
    out.push_str("typedef struct { const char *isa; const char *mnemonic; const char *names; } axis_sim_keep;\n");
    out.push_str("static const axis_sim_keep AXIS_SIM_KEEPS[] = {\n");
    for instruction in &document.instructions {
        if !crate::effects::behavior_is_authoritative(instruction) {
            continue;
        }
        let Some(behavior) = instruction.behavior.as_ref() else { continue };
        let mut names: Vec<&str> = Vec::new();
        for effect in &behavior.effects {
            if let (Loc::Reg(dest), Some(_)) = (&effect.loc, &effect.guard) {
                if !names.contains(&dest.as_str()) {
                    names.push(dest);
                }
            }
        }
        if !names.is_empty() {
            out.push_str(&format!(
                "  {{ {}, {}, {} }},\n",
                c_string(&instruction.isa),
                c_string(&instruction.mnemonic),
                c_string(&format!(" {} ", names.join(" ")))
            ));
        }
    }
    out.push_str("  { 0, 0, 0 }\n};\n");
    out
}

/// WHERE A DIRECT BRANCH GOES, from its word and its address alone
/// (docs/ooo_design.md, D1).
///
/// A direct branch's target is `pc` plus a field of the word: no register is
/// read, so a front end knows it as soon as the word is decoded -- which is
/// what lets it redirect fetch without waiting for the branch to execute, and
/// what names the wrong path of a branch guessed taken that the trace never
/// saw go there. The expression is the description's own `setpc`, lowered by
/// the executor's emitter with only the immediates bound: one statement of
/// where the branch goes, read twice.
///
/// ⚠️ A branch whose target this cannot lower is DECLINED BY NAME in the
/// generated source, and has no decode-time target -- it behaves as it did
/// before. Counted, so a gate can refuse a corpus where that is silent.
fn emit_direct_targets(document: &Document) -> String {
    use crate::effects::{expr_atoms, Loc};
    let states = crate::effects::isa_scalar_state_names(&document.isas);
    let mut functions = String::new();
    let mut rows = String::new();
    let mut found = 0usize;
    let mut declined: Vec<String> = Vec::new();
    for (index, instruction) in document.instructions.iter().enumerate() {
        if !crate::effects::behavior_is_authoritative(instruction) {
            continue;
        }
        let Some(behavior) = instruction.behavior.as_ref() else { continue };
        let jumps: Vec<_> = behavior.effects.iter().filter(|e| matches!(e.loc, Loc::Pc)).collect();
        let Some(jump) = jumps.first() else { continue };
        let atoms = expr_atoms(&jump.value.expr);
        let register = |name: &String| {
            instruction
                .operands
                .iter()
                .any(|o| &o.name == name && crate::ast::register_class(&o.kind).is_some())
        };
        // Indirect: the target is in a register, and decode cannot know it.
        if atoms.iter().any(register) {
            continue;
        }
        let label = format!("{}:{}", instruction.isa, instruction.mnemonic);
        if jumps.len() != 1 || atoms.iter().any(|a| states.contains(a)) {
            declined.push(label);
            continue;
        }
        let bindings: Vec<(String, String)> = instruction
            .operands
            .iter()
            .enumerate()
            .filter(|(_, o)| o.kind == "imm")
            .map(|(pos, o)| (o.name.clone(), format!("lifted->operands[{pos}]")))
            .collect();
        let Some(value) = super::lift::c_wide_expr(&jump.value.expr, &bindings, jump.value.width) else {
            declined.push(label);
            continue;
        };
        functions.push_str(&format!(
            "static int axis_sim_target_{index}(const axis_lifted *lifted, uint64_t pc, uint64_t *target) {{\n  (void)lifted; (void)pc;\n  *target = axis_mask64({value}, lifted->entry->state_width);\n  return 1;\n}}\n"
        ));
        rows.push_str(&format!(
            "  {{ {}, {}, axis_sim_target_{index} }},\n",
            c_string(&instruction.isa),
            c_string(&instruction.mnemonic)
        ));
        found += 1;
    }
    let mut out = String::new();
    out.push_str("/* ⚠️ WHERE A DIRECT BRANCH GOES, from its word and its address alone (D1):\n   the description's own `setpc`, with only the immediates bound. No register\n   is read, so decode knows it. */\n");
    out.push_str(&format!(
        "/* direct-targets: {found} lowered, {} declined{}{} */\n",
        declined.len(),
        if declined.is_empty() { "" } else { ": " },
        declined.join(" ")
    ));
    out.push_str("typedef int (*axis_sim_target_fn)(const axis_lifted *lifted, uint64_t pc, uint64_t *target);\n");
    out.push_str(&functions);
    out.push_str("typedef struct { const char *isa; const char *mnemonic; axis_sim_target_fn find; } axis_sim_direct;\n");
    out.push_str("static const axis_sim_direct AXIS_SIM_DIRECT[] = {\n");
    out.push_str(&rows);
    out.push_str("  { 0, 0, 0 }\n};\n");
    out.push_str("static axis_sim_target_fn axis_sim_direct_target_of(const axis_lift_entry *entry) {\n");
    out.push_str("  for (const axis_sim_direct *d = AXIS_SIM_DIRECT; d->mnemonic; ++d) {\n");
    out.push_str("    if (!strcmp(d->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(d->isa, entry->isa))) { return d->find; }\n  }\n  return 0;\n}\n");
    out
}

/// The wrong path in the window, trace-driven (docs/ooo_design.md, W2).
const WRONGPATH_C: &str = r#"
/* ==== W2: the wrong path in the window, trace-driven ==================== */

/* ⚠️ A WRONG-PATH INSTRUCTION ISSUES, and its accesses reach the data cache
   NOW -- not when it was fetched, and not at all if its branch resolves
   first. A miss is this instruction's own latency, so what a wrong-path load
   feeds waits for the line as it would on the right path; it is nobody
   else's. The counters, and the stall the next correct-path instruction owes,
   are put back: touched, never charged. */
static uint64_t axis_wp_access(axis_pack_machine *m, const axis_sim_rob_entry *e) {
  uint32_t k = e->wrong - 1u;
  if (k >= m->wpx_len) { return 0u; }
  uint64_t stall = m->pending_stall, hits = m->hits, misses = m->misses;
  uint64_t tmiss = m->dtlb_misses, twalk = m->page_walks, asked = m->pending_walk;
  m->pending_stall = 0;
  for (int32_t a = 0; a < m->wpx_acc[k] && a < (int32_t)AXIS_SIM_OOO_MEM; ++a) {
    axis_sim_touch(m, m->wpx_lo[k][a], m->wpx_write[k][a]);
  }
  m->pending_walk = asked;
  uint64_t own = m->pending_stall;
  m->pending_stall = stall;
  m->hits = hits;
  m->misses = misses;
  m->dtlb_misses = tmiss;
  m->page_walks = twalk;
  return own;
}

/* One instruction of the wrong path, run and recorded: its pc, its word, and
   its accesses. 0 when the path ends here -- a trap, a word that does not
   decode, or a full trace. */
static int axis_wp_step(axis_pack_machine *m, axis_lifted *lifted, uint64_t *at) {
  if (m->wpx_len >= AXIS_SIM_WP_MAX) { return 0; }
  uint64_t pc = m->sim.pc;
  int32_t got = 1;
  uint32_t word = m->host.fetch ? m->host.fetch(m->host.ctx, pc, &got) : 0u;
  if (!got || !axis_sim_lift(&m->sim, word, lifted)) { lifted->entry = 0; }
  m->acc_count = 0;
  axis_sim_status st = axis_sim_step(&m->sim);
  if (m->shadow_stopped || st != AXIS_SIM_RUNNING) { return 0; }
  uint32_t k = m->wpx_len++;
  m->wpx_pc[k] = pc;
  m->wpx_word[k] = word;
  m->wpx_resume[k] = 0;
  m->wpx_bubble[k] = 0;
  m->wpx_acc[k] = m->acc_count;
  for (int32_t a = 0; a < m->acc_count && a < (int32_t)AXIS_SIM_OOO_MEM; ++a) {
    m->wpx_lo[k][a] = m->acc_lo[a];
    m->wpx_hi[k][a] = m->acc_hi[a];
    m->wpx_write[k][a] = m->acc_write[a];
  }
  *at = pc;
  return 1;
}

/* ⚠️ THE WRONG PATH MISPREDICTS TOO (W3, W5). The shadow runs where the
   wrong path's branches really go, but the front end went where it PREDICTED
   -- and at each branch that is worked out the way the right path's is: a
   conditional branch asks the direction predictor; a branch guessed taken
   goes where the return stack says, or the target buffer, or -- for a direct
   branch neither holds -- where decode finds in the word, `btb_penalty`
   cycles later; and an indirect one with no entry anywhere has nowhere to go
   but on (W6). Where that is not where the branch went, the shadow forks
   again: it runs the side the front end chose, a DETOUR, recorded after the
   branch; then that fork is discarded -- its stores and its return stack with
   it -- and the run goes on down the side the branch took.

   ⚠️ A DETOUR IS A WRONG PATH, so its branches have detours of their own:
   `AXIS_SIM_WP_DEPTH` deep, and no longer than the machine has room left for
   -- what is in flight ahead of a detour is still in flight beside it. A
   branch the front end got RIGHT but had to decode for holds what follows it
   back by decode's cycles, on a wrong path as on the right one.

   The window then fetches each detour until its branch resolves, squashes
   it, and resumes after a refill (`axis_sim_consume_wrong_path`). */
static void axis_wp_run(axis_pack_machine *m, int32_t level, uint64_t budget, uint32_t late) {
  const axis_sim_core *core = m->core;
  for (uint64_t run = 0; run < budget; ++run) {
    axis_lifted lifted;
    uint64_t pc = 0;
    uint32_t k = m->wpx_len;
    if (!axis_wp_step(m, &lifted, &pc)) { break; }
    m->wpx_bubble[k] = late;
    late = 0;
    if (!lifted.entry || !lifted.entry->ends_block) { continue; }
    int32_t conditional = 1, indirect = 0, is_call = 0, is_return = 0;
    axis_sim_classify(lifted.entry, &lifted, &conditional, &indirect, &is_call, &is_return);
    uint32_t bytes = lifted.entry->bits ? lifted.entry->bits / 8u : 4u;
    uint64_t next = m->sim.pc;
    int32_t taken = next != pc + bytes;
    int32_t guess = conditional ? ((m->pred && m->pred_state) ? (m->pred->predict(m->pred_state, pc) != 0) : 0) : 1;
    /* Where the front end went, and how long decode took to send it there. */
    uint64_t went = pc + bytes;
    uint32_t found_late = 0;
    if (guess) {
      int32_t known = 0;
      /* A return on a machine with a return stack asks the stack and nothing
         else, as the right path's does: an empty one predicts nothing. */
      int32_t stackless = is_return && core->ras && !m->ras_count;
      if (is_return && core->ras && m->ras_count) {
        went = m->ras_stack[m->ras_top];
        known = 1;
        m->ras_top = (m->ras_top + 63u) % 64u;
        m->ras_count--;
      }
      if (stackless) { known = 1; }
      if (!known && core->btb) {
        uint32_t n = core->btb < AXIS_SIM_BTB_MAX ? core->btb : AXIS_SIM_BTB_MAX;
        uint32_t slot = (uint32_t)((pc / (bytes ? bytes : 4u)) % n);
        if (m->btb_tag[slot] == pc + 1u) { went = m->btb_target[slot]; known = 1; }
      }
      if (!known && !indirect) {
        axis_sim_target_fn find = axis_x_meta_of(m, lifted.entry)->direct;
        if (find && find(&lifted, pc, &went)) { known = 1; found_late = core->btb ? core->btb_penalty : 0u; }
      }
      /* An undeclared buffer is a perfect one: it holds where this goes. */
      if (!known && indirect && !core->btb && taken) { went = next; known = 1; }
      if (!known) { went = pc + bytes; }
    }
    if (is_call && core->ras) {
      uint32_t depth = core->ras < 64u ? core->ras : 64u;
      m->ras_top = (m->ras_top + 1u) % 64u;
      m->ras_stack[m->ras_top] = pc + bytes;
      if (m->ras_count < depth) { m->ras_count++; }
    }
    if (went == next) { late = found_late; continue; }
    if (level >= AXIS_SIM_WP_DEPTH) { continue; }
    axis_sim here = m->sim;
    axis_state64_entry here_state[64];
    memcpy(here_state, m->state, sizeof here_state);
    uint32_t writes = m->shadow_writes;
    uint64_t ras_stack[64];
    uint32_t ras_top = m->ras_top, ras_count = m->ras_count;
    memcpy(ras_stack, m->ras_stack, sizeof ras_stack);
    m->sim.pc = went;
    axis_wp_run(m, level + 1, budget - run - 1u, found_late);
    m->wpx_resume[k] = m->wpx_len;
    m->sim = here;
    memcpy(m->state, here_state, sizeof here_state);
    m->shadow_writes = writes;
    m->shadow_stopped = 0;
    memcpy(m->ras_stack, ras_stack, sizeof ras_stack);
    m->ras_top = ras_top;
    m->ras_count = ras_count;
  }
}

/* ⚠️ FORK, RUN, DISCARD (O12). The functional state -- registers, state
   slots, pc, step count, status -- is copied; the simulator runs from where
   the prediction pointed with its stores buffered and its traps swallowed;
   each instruction it completes leaves its pc and its accesses in the trace;
   and the copy is put back, exactly -- the return stack too, which the wrong
   path's calls and returns moved. At most what the machine can hold in
   flight is run: the fetch buffer and the reorder buffer, full of wrong-path
   work, are where fetch stops. An instruction that would trap, or does not
   decode, ends the run without being recorded -- on the wrong path it never
   happened, and neither does anything after it. */
static void axis_sim_run_shadow(axis_pack_machine *m, uint64_t start) {
  const axis_sim_core *core = m->core;
  uint32_t fw = core->fetch_width ? core->fetch_width : 1u;
  uint64_t cap = (core->fe_buffer ? core->fe_buffer : (uint64_t)fw * (core->fe_depth + 1u)) + axis_ooo_rob(core);
  if (cap > AXIS_SIM_WP_MAX) { cap = AXIS_SIM_WP_MAX; }
  axis_sim saved = m->sim;
  axis_state64_entry saved_state[64];
  memcpy(saved_state, m->state, sizeof saved_state);
  int32_t acc_count = m->acc_count;
  uint64_t acc_lo[AXIS_SIM_OOO_MEM], acc_hi[AXIS_SIM_OOO_MEM];
  uint8_t acc_write[AXIS_SIM_OOO_MEM];
  memcpy(acc_lo, m->acc_lo, sizeof acc_lo);
  memcpy(acc_hi, m->acc_hi, sizeof acc_hi);
  memcpy(acc_write, m->acc_write, sizeof acc_write);
  uint64_t ras_stack[64];
  uint32_t ras_top = m->ras_top, ras_count = m->ras_count;
  memcpy(ras_stack, m->ras_stack, sizeof ras_stack);
  m->shadow = 1;
  m->shadow_stopped = 0;
  m->shadow_writes = 0;
  m->wpx_len = 0;
  m->sim.pc = start;
  m->sim.status = AXIS_SIM_RUNNING;
  axis_wp_run(m, 0, cap, 0u);
  m->sim = saved;
  memcpy(m->state, saved_state, sizeof saved_state);
  m->acc_count = acc_count;
  memcpy(m->acc_lo, acc_lo, sizeof acc_lo);
  memcpy(m->acc_hi, acc_hi, sizeof acc_hi);
  memcpy(m->acc_write, acc_write, sizeof acc_write);
  memcpy(m->ras_stack, ras_stack, sizeof ras_stack);
  m->ras_top = ras_top;
  m->ras_count = ras_count;
  m->shadow = 0;
}

/* Instruction `k` of the shadow's trace enters the window, if the window has
   room for it: an entry, an issue-queue slot, a load- or store-queue slot, a
   physical register for each result. 0 when it does not -- the wrong path
   waits behind a full machine exactly as the right one does. */
static int axis_wp_dispatch(axis_pack_machine *m, uint32_t k) {
  const axis_sim_core *core = m->core;
  uint32_t rob = axis_ooo_rob(core);
  uint32_t queue = core->issue_queue ? core->issue_queue : rob;
  if (axis_rob_full(m, rob, 1u)) { return 0; }
  uint32_t waiting = 0, loads = 0, stores = 0;
  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!o->valid) { continue; }
    waiting += o->issued ? 0u : 1u;
    loads += o->is_load ? 1u : 0u;
    stores += o->is_store ? 1u : 0u;
  }
  if (waiting >= queue) { return 0; }
  axis_lifted lifted;
  if (!axis_sim_lift(&m->sim, m->wpx_word[k], &lifted) || !lifted.entry) { return 0; }
  const axis_lift_entry *entry = lifted.entry;
  const axis_x_meta *x = axis_x_meta_of(m, entry);
  if (axis_unit_queue_full(m, x->unit)) { return 0; }
  int32_t is_load = 0, is_store = 0;
  for (int32_t a = 0; a < m->wpx_acc[k] && a < (int32_t)AXIS_SIM_OOO_MEM; ++a) {
    if (m->wpx_write[k][a]) { is_store = 1; } else { is_load = 1; }
  }
  if (core->lsq && ((is_load && core->load_queue && loads >= core->load_queue)
                    || (is_store && core->store_queue && stores >= core->store_queue))) { return 0; }
  int32_t want_pool[AXIS_SIM_OOO_DST];
  uint32_t want_slot[AXIS_SIM_OOO_DST];
  int32_t want = 0;
  for (int32_t o = 0; o < entry->operand_count && want < (int32_t)AXIS_SIM_OOO_DST; ++o) {
    if (!x->op_out[o]) { continue; }
    uint32_t slot = axis_x_operand_slot(x, entry, &lifted, o);
    if (slot >= AXIS_SIM_PRODUCERS) { continue; }
    const axis_reg_class *rules = x->op_class[o];
    want_pool[want] = (slot >= AXIS_SIM_REG_SLOTS
                       || (rules->zero_index >= 0 && lifted.operands[o] == (uint32_t)rules->zero_index))
                      ? -1 : x->op_pool[o];
    want_slot[want++] = slot;
  }
  for (int32_t i = 0; i < x->st_write_count && want < (int32_t)AXIS_SIM_OOO_DST; ++i) {
    want_pool[want] = -1;
    want_slot[want++] = AXIS_SIM_REG_SLOTS + x->st_write[i];
  }
  for (int32_t i = 0; i < x->fixed_count && want < (int32_t)AXIS_SIM_OOO_DST; ++i) {
    want_pool[want] = x->fixed_pool[i];
    want_slot[want++] = x->fixed_slot[i];
  }
  uint32_t need[AXIS_SIM_RENAME_POOLS] = {0};
  for (int32_t i = 0; i < want; ++i) { if (want_pool[i] >= 0) { need[want_pool[i]]++; } }
  for (int32_t p = 0; p < core->rename_count && p < (int32_t)AXIS_SIM_RENAME_POOLS; ++p) {
    if (need[p] && m->rename_used[p] + need[p] > core->rename[p].extra) { return 0; }
  }
  if (axis_rename_full(m, (uint32_t)want)) { return 0; }
  m->renamed_this_cycle += (uint32_t)want;
  axis_sim_rob_entry *e = &m->rob[m->rob_tail % AXIS_SIM_ROB_MAX];
  memset(e, 0, sizeof *e);
  e->seq = m->rob_tail;
  e->valid = 1;
  e->wrong = k + 1u;
  e->latency = axis_sim_latency_on(m->core, entry);
  e->unit = x->unit;
  axis_x_width(m, e, m->wpx_word[k], entry, &lifted);
  /* A length in a register is whatever the wrong path left there, which the
     shadow did not keep: the whole register's width. */
  if (e->len_kind == 2u) { e->len_kind = 0; }
  e->pc = m->wpx_pc[k];
  e->is_load = is_load;
  e->is_store = is_store;
  for (int32_t a = 0; a < m->wpx_acc[k] && a < (int32_t)AXIS_SIM_OOO_MEM; ++a) {
    e->mem_lo[a] = m->wpx_lo[k][a];
    e->mem_hi[a] = m->wpx_hi[k][a];
    e->mem_count = a + 1;
  }
  for (int32_t i = 0; i < AXIS_SIM_OOO_DST; ++i) { e->dst_pool[i] = -1; }
  for (int32_t o = 0; o < entry->operand_count; ++o) {
    if (!x->op_in[o]) { continue; }
    uint32_t slot = axis_x_operand_slot(x, entry, &lifted, o);
    if (slot >= AXIS_SIM_PRODUCERS) { continue; }
    int32_t seen = m->reg_producer[slot] == AXIS_SIM_NO_SEQ;
    for (int32_t j = 0; j < e->src_count && !seen; ++j) { seen = e->src_seq[j] == m->reg_producer[slot]; }
    if (!seen && e->src_count < AXIS_SIM_OOO_SRC) { e->src_seq[e->src_count++] = m->reg_producer[slot]; }
    if (is_store && x->op_store_addr[o] && e->addr_src_count < AXIS_SIM_OOO_SRC) {
      e->addr_src_seq[e->addr_src_count++] = m->reg_producer[slot];
    }
  }
  for (int32_t i = 0; i < x->st_read_count && e->src_count < AXIS_SIM_OOO_SRC; ++i) {
    e->src_seq[e->src_count++] = m->reg_producer[AXIS_SIM_REG_SLOTS + x->st_read[i]];
  }
  {
    uint32_t more[AXIS_SIM_OOO_SRC];
    int32_t n = axis_x_lane_slots(m, m->wpx_word[k], entry, 0, 0, 0, more, (int32_t)AXIS_SIM_OOO_SRC);
    for (int32_t i = 0; i < n && e->src_count < AXIS_SIM_OOO_SRC; ++i) {
      uint64_t from = m->reg_producer[more[i]];
      int32_t seen = from == AXIS_SIM_NO_SEQ;
      for (int32_t j = 0; j < e->src_count && !seen; ++j) { seen = e->src_seq[j] == from; }
      if (!seen) { e->src_seq[e->src_count++] = from; }
    }
    n = axis_x_lane_slots(m, m->wpx_word[k], entry, 1, want_slot, want, want_slot + want, (int32_t)AXIS_SIM_OOO_DST - want);
    for (int32_t i = 0; i < n; ++i) { want_pool[want + i] = -1; }
    want += n;
  }
  for (int32_t i = 0; i < want; ++i) {
    e->dst_pool[e->dst_count] = want_pool[i];
    e->dst_slot[e->dst_count++] = want_slot[i];
    if (want_pool[i] >= 0) { m->rename_used[want_pool[i]]++; }
    m->reg_producer[want_slot[i]] = e->seq;
  }
  m->rob_tail++;
  m->dispatched_this_cycle++;
  return 1;
}

/* ⚠️ THE EXECUTED WRONG PATH, IN THE WINDOW (O12, W2). Until its branch
   resolves the machine does not know the path is wrong, so it treats it as
   it treats any other: fetched `fetch_width` a cycle from where the
   prediction pointed, dispatched `fe_depth` later into the window -- an
   entry, a queue slot, a physical register -- and issued when its operands
   are ready and a unit and a port are free, behind everything older. Then
   the branch resolves, and all of it leaves at once.

   What that costs the program is what the wrong path was holding when
   something older wanted it. Issue is oldest first, so within a cycle a
   wrong-path instruction never beats an older one to a port or a unit; but a
   unit that is not pipelined stays held for the instruction's whole latency,
   and one taken in a cycle nothing older was ready is still held when
   something older becomes ready. It also stays held past the squash: the
   model does not abort an operation in a unit, it only stops waiting for it.

   What reaches the caches: every instruction FETCHED before resolution
   touches the instruction cache, along the path the wrong path really took;
   every load or store that ISSUED before resolution touched the data cache
   when it did (`axis_wp_access`).

   ⚠️ Called BEFORE the next correct-path instruction runs. Consumed at the
   redirect instead -- inside that instruction's accounting -- its functional
   step had already touched the cache, so the wrong path could neither
   prefetch for it nor pollute ahead of it: the right lines, in the wrong
   order. Ticking to the branch's resolution here is the machine running; the
   redirect then finds it resolved. */
/* Everything after `seq` leaves the window, and the rename map and the
   physical registers are what the survivors hold. */
static void axis_wp_squash_after(axis_pack_machine *m, uint64_t seq) {
  if (m->rob_tail <= seq + 1u) { return; }
  for (uint64_t s = seq + 1u; s < m->rob_tail; ++s) {
    axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    /* What it had started in a unit that aborts is given back (W4). */
    if (o->valid && o->issued) { axis_unit_abort(m, o); }
    o->valid = 0;
  }
  m->rob_tail = seq + 1u;
  for (uint32_t r = 0; r < AXIS_SIM_PRODUCERS; ++r) { m->reg_producer[r] = AXIS_SIM_NO_SEQ; }
  memset(m->rename_used, 0, sizeof m->rename_used);
  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!o->valid) { continue; }
    for (int32_t d = 0; d < o->dst_count; ++d) {
      m->reg_producer[o->dst_slot[d]] = o->seq;
      if (o->dst_pool[d] >= 0) { m->rename_used[o->dst_pool[d]]++; }
    }
  }
}
/* ⚠️ WHEN EACH TRACE ENTRY IS FETCHED, from `from` on: `fetch_width` a cycle
   starting at `since`, in trace order -- into a detour and into the detours
   inside it, since that is where the front end went -- and no further than
   where a path RESUMES: past that, fetch is waiting for a wrong-path branch
   to resolve. An entry decode had to find the way to starts a new group that
   many cycles on. ~0 is not fetched at all. */
static void axis_wp_schedule(const axis_pack_machine *m, uint64_t *ft, uint32_t from,
                             uint64_t since, uint32_t fw, uint32_t limit) {
  uint64_t at = since + (from < m->wpx_len ? m->wpx_bubble[from] : 0u);
  uint32_t in_group = 0;
  for (uint32_t k = from; k < limit && k < m->wpx_len; ++k) {
    if (k > from && m->wpx_bubble[k]) { at += 1u + m->wpx_bubble[k]; in_group = 0; }
    else if (in_group >= fw) { at++; in_group = 0; }
    ft[k] = at;
    in_group++;
    if (m->wpx_resume[k] && m->wpx_resume[k] < limit) { limit = m->wpx_resume[k]; }
  }
}
static void axis_sim_consume_wrong_path(axis_pack_machine *m) {
  const axis_sim_core *core = m->core;
  uint64_t branch = m->fe_redirect_seq;
  uint32_t fw = core->fetch_width ? core->fetch_width : 1u;
  uint32_t width = axis_disp_width(m);
  uint8_t fetched[AXIS_SIM_WP_MAX];
  uint64_t ft[AXIS_SIM_WP_MAX];
  memset(fetched, 0, sizeof fetched);
  memset(ft, 0xFF, sizeof ft);
  /* The wrong-path branches whose detours are being fetched now, outermost
     first: each one's entry in the window and in the trace. */
  uint64_t open_seq[AXIS_SIM_WP_DEPTH];
  uint32_t open_at[AXIS_SIM_WP_DEPTH];
  int32_t open = 0;
  uint32_t next = 0, entered = 0;
  axis_wp_schedule(m, ft, 0u, m->fe_redirect_fetch, fw, m->wpx_len);
  axis_sim_rob_entry *b = axis_ooo_find(m, branch);
  /* The branch is the youngest instruction in the window: the wrong path's
     entries follow it, and nothing of the program's is among them. */
  int32_t youngest = b && m->rob_tail == branch + 1u;
  while (b && (!b->issued || b->complete > m->now)) {
    /* ⚠️ A WRONG-PATH BRANCH RESOLVES (W3): its detour leaves the window --
       and every detour inside it (W5), which is why the outermost is asked
       first -- and fetch starts again down the side it took, a refill later,
       like any redirect. */
    for (int32_t d = 0; d < open; ++d) {
      const axis_sim_rob_entry *nb = axis_ooo_find(m, open_seq[d]);
      if (nb && (!nb->issued || nb->complete > m->now)) { continue; }
      uint32_t resume = m->wpx_resume[open_at[d]];
      for (uint32_t k = open_at[d] + 1u; k < resume; ++k) {
        if (ft[k] < m->now) { fetched[k] = 1; }
        ft[k] = ~0ull;
      }
      axis_wp_squash_after(m, open_seq[d]);
      next = resume;
      axis_wp_schedule(m, ft, resume, m->now + core->branch_penalty, fw,
                       d ? m->wpx_resume[open_at[d - 1]] : m->wpx_len);
      open = d;
      break;
    }
    if (m->now > m->dispatch_cycle) { m->dispatch_cycle = m->now; m->dispatched_this_cycle = 0; m->renamed_this_cycle = 0; }
    while (youngest && next < m->wpx_len && m->dispatched_this_cycle < width) {
      /* Not fetched: the detour ran out before its branch resolved, and
         fetch has nothing more to bring until it does. */
      if (ft[next] == ~0ull || ft[next] + core->fe_depth > m->now) { break; }
      if (!axis_wp_dispatch(m, next)) { break; }
      entered++;
      if (m->wpx_resume[next] && open < AXIS_SIM_WP_DEPTH) {
        open_seq[open] = m->rob_tail - 1u;
        open_at[open++] = next;
      }
      next++;
    }
    axis_ooo_tick(m);
    b = axis_ooo_find(m, branch);
  }
  for (uint32_t k = 0; k < m->wpx_len; ++k) { if (ft[k] < m->now) { fetched[k] = 1; } }
  uint32_t lb = core->icache.line_bytes ? core->icache.line_bytes : 64u;
  uint64_t last = ~0ull;
  for (uint32_t i = 0; i < m->wpx_len; ++i) {
    if (!fetched[i]) { continue; }
    m->wrong_path_instructions++;
    if (core->icache.lines && m->wpx_pc[i] / lb != last) {
      last = m->wpx_pc[i] / lb;
      axis_ic_touch(m, last);
      axis_tlb_touch(m, 1, m->wpx_pc[i]);
      m->wrong_path_lines++;
    }
  }
  /* ⚠️ THE SQUASH: everything after the branch leaves the window. */
  if (entered) { axis_wp_squash_after(m, branch); }
  m->wpx_armed = 0;
}
"#;

/// The TLBs (docs/tlb_design.md): a set-associative table of pages per level,
/// least recently used out. One function answers every lookup, data or fetch.
const TLB_C: &str = r#"/* One level: 1 when `page` was not there, which also puts it there. */
static int axis_tlb_level(uint64_t *tag, uint64_t *used, uint8_t *valid, uint32_t entries, uint32_t ways,
                          uint64_t page, uint64_t clock) {
  if (!ways || ways > entries) { ways = entries; }
  uint32_t sets = entries / ways;
  uint32_t base = (uint32_t)(page % sets) * ways;
  for (uint32_t w = 0; w < ways; ++w) {
    if (valid[base + w] && tag[base + w] == page) { used[base + w] = clock; return 0; }
  }
  uint32_t victim = base;
  for (uint32_t w = 0; w < ways; ++w) {
    if (!valid[base + w]) { victim = base + w; break; }
    if (used[base + w] < used[victim]) { victim = base + w; }
  }
  valid[victim] = 1; tag[victim] = page; used[victim] = clock;
  return 1;
}
/* ⚠️ A WALK THAT READS THE TABLE (TLB2). `(walk-cycles N)` says a walk costs
   N, whatever it walked. A walk is really `levels` loads, each of the entry
   the one before it pointed at -- and those entries are in memory, so each is
   in the data cache or it is not. A program whose pages are near each other
   finds the table's last level cached and walks cheaply; one that strides
   across memory misses on it every time. And the lines the walk brings in are
   in the cache afterwards, in place of whatever was there.

   The table is a radix tree over the page number, nine bits a level, laid
   out from `tw_table`: each table found is given the next 4096 bytes. A table
   is named by its level and the bits above its index. Read through the
   machine's own data cache -- not translated, and not counted among the
   program's hits and misses; charged in time.

   A WALK CACHE holds the tables of the levels below the root: a walk starts
   at the deepest it holds, and reads only from there down.

   A LARGE PAGE's walk stops a level short: the entry there maps it whole. */
static void axis_sim_touch(axis_pack_machine *m, uint64_t addr, int is_write);
static uint64_t axis_tw_read(axis_pack_machine *m, uint64_t entry) {
  uint64_t stall = m->pending_stall, hits = m->hits, misses = m->misses;
  int32_t skip = m->tlb_skip;
  m->tlb_skip = 1;
  axis_sim_touch(m, entry, 0);
  m->tlb_skip = skip;
  uint64_t waited = m->pending_stall - stall;
  m->pending_stall = stall;
  m->hits = hits;
  m->misses = misses;
  return waited;
}
/* Which 4096 bytes the table named `key` is: the next free, the first time. */
static uint64_t axis_tw_table(axis_pack_machine *m, uint64_t key) {
  uint32_t at = (uint32_t)((key ^ (key >> 17) ^ (key >> 41)) % 1024u);
  for (uint32_t probe = 0; probe < 1024u; ++probe) {
    uint32_t slot = (at + probe) % 1024u;
    if (m->tw_node[slot] == key + 1u) { return m->tw_node_at[slot]; }
    if (!m->tw_node[slot]) {
      m->tw_node[slot] = key + 1u;
      m->tw_node_at[slot] = m->tw_nodes < 0xFFFFu ? m->tw_nodes++ : 0xFFFFu;
      return m->tw_node_at[slot];
    }
  }
  return 0u;
}
static int axis_pwc_holds(axis_pack_machine *m, uint64_t key, int put) {
  uint32_t victim = 0;
  for (uint32_t i = 0; i < m->tw_pwc; ++i) {
    if (m->pwc_valid[i] && m->pwc_key[i] == key) { m->pwc_used[i] = m->tlb_clock; return 1; }
    if (!m->pwc_valid[i]) { victim = i; }
    else if (m->pwc_valid[victim] && m->pwc_used[i] < m->pwc_used[victim]) { victim = i; }
  }
  if (put && m->tw_pwc) { m->pwc_valid[victim] = 1; m->pwc_key[victim] = key; m->pwc_used[victim] = m->tlb_clock; }
  return 0;
}
static uint64_t axis_tlb_walk(axis_pack_machine *m, uint64_t number, int huge) {
  uint32_t levels = m->tw_levels - ((huge && m->tw_levels > 1u) ? 1u : 0u);
  /* Level `k`, the root being 0, is indexed by nine bits of the page number
     and named by the bits above them. */
  uint32_t start = 0;
  for (uint32_t k = levels - 1u; m->tw_pwc && k >= 1u; --k) {
    uint32_t shift = 9u * (m->tw_levels - 1u - k) + 9u;
    uint64_t key = ((uint64_t)k << 56) | (shift >= 56u ? 0u : (number >> shift));
    if (axis_pwc_holds(m, key, 0)) { start = k; break; }
  }
  uint64_t cost = 0;
  for (uint32_t k = start; k < levels; ++k) {
    uint32_t shift = 9u * (m->tw_levels - 1u - k);
    uint64_t above = shift + 9u >= 56u ? 0u : (number >> (shift + 9u));
    uint64_t key = ((uint64_t)k << 56) | above;
    uint64_t entry = m->tw_table + axis_tw_table(m, key) * 4096u + ((number >> shift) & 511u) * 8u;
    cost += m->tw_cycles + axis_tw_read(m, entry);
    if (k >= 1u) { (void)axis_pwc_holds(m, key, 1); }
  }
  return cost;
}
/* ⚠️ ONE LOOKUP, and what it costs beyond a first-level hit: nothing; the
   second level's latency when that holds the page; that and the walk when
   nothing does. `which` is 0 for data and 1 for fetch. Every level the page
   was missing from holds it afterwards. Counted here; a caller whose access
   is not the program's puts the counters back. */
static uint64_t axis_tlb_lookup(axis_pack_machine *m, int which, uint64_t addr) {
  const axis_sim_tlb *t = &m->core->tlb;
  uint32_t entries = which ? t->fetch_entries : t->data_entries;
  if (!entries) { return 0u; }
  if (entries > AXIS_SIM_TLB_L1) { entries = AXIS_SIM_TLB_L1; }
  uint64_t small = t->page_bytes ? t->page_bytes : 4096u;
  /* A large page is one page to every level that remembers pages (TLB2);
     the bit keeps its number apart from a small page's. */
  int huge = m->tw_huge_bytes && addr >= m->tw_huge_from && addr < m->tw_huge_to;
  uint64_t page = huge ? ((addr / m->tw_huge_bytes) | (1ull << 62)) : addr / small;
  m->tlb_clock++;
  if (!axis_tlb_level(m->tlb_tag[which], m->tlb_used[which], m->tlb_valid[which], entries,
                      which ? t->fetch_ways : t->data_ways, page, m->tlb_clock)) { return 0u; }
  if (which) { m->itlb_misses++; } else { m->dtlb_misses++; }
  uint64_t cost = 0u;
  if (t->second_entries) {
    uint32_t e2 = t->second_entries > AXIS_SIM_TLB_L2 ? AXIS_SIM_TLB_L2 : t->second_entries;
    cost = t->second_cycles;
    if (!axis_tlb_level(m->tlb2_tag, m->tlb2_used, m->tlb2_valid, e2, t->second_ways, page, m->tlb_clock)) {
      return cost;
    }
  }
  m->page_walks++;
  uint64_t walk = m->tw_levels ? axis_tlb_walk(m, addr / small, huge) : t->walk_cycles;
  /* What a walker has to be free for (TLB2): asked for here, taken when the
     access is made. */
  m->pending_walk += walk;
  return cost + walk;
}
/* A lookup that is nobody's keeps no walker either. */
static uint64_t axis_tlb_lookup_free(axis_pack_machine *m, int which, uint64_t addr) {
  uint64_t asked = m->pending_walk;
  uint64_t cost = axis_tlb_lookup(m, which, addr);
  m->pending_walk = asked;
  return cost;
}
/* ⚠️ A WALKER (TLB2). A machine has one or two, and a walk that finds them
   all busy waits for the first to be free. `walk` cycles of walking, wanted
   from `at`: the cycles it waits before it starts, with that walker then
   busy until it is done. No limit declared, and nothing waits. */
static uint64_t axis_walker_take(axis_pack_machine *m, uint64_t at, uint64_t walk) {
  if (!m->tw_walkers || !walk) { return 0u; }
  uint32_t pick = 0;
  for (uint32_t w = 1; w < m->tw_walkers; ++w) { if (m->walker_free[w] < m->walker_free[pick]) { pick = w; } }
  uint64_t start = m->walker_free[pick] > at ? m->walker_free[pick] : at;
  m->walker_free[pick] = start + walk;
  return start - at;
}
/* A lookup that is nobody's: the page is remembered, nothing is counted. */
static void axis_tlb_touch(axis_pack_machine *m, int which, uint64_t addr) {
  uint64_t d = m->dtlb_misses, i = m->itlb_misses, w = m->page_walks;
  (void)axis_tlb_lookup_free(m, which, addr);
  m->dtlb_misses = d; m->itlb_misses = i; m->page_walks = w;
}

"#;

/// The execution-driven engine (docs/ooo_design.md, E1): fetch down the
/// predicted path, execute at issue through the generated executor, resolve at
/// completion, squash, and commit by stepping the golden functional model and
/// checking every result the pipeline computed against it.
const XMODE_C: &str = r#"
/* ==== E1: the execution-driven engine ================================== */

/* ⚠️ WHAT THE ENGINE KNOWS ABOUT AN INSTRUCTION, ONCE. Its unit, whether it
   loads or stores, which operands its store address comes from, what kind of
   branch it is and which operands link or jump through the ABI's link
   register, and for every operand its role, register class and rename pool.
   All static -- fixed by the description and the core -- and all of it was
   re-derived by string comparison for every instruction dispatched: half the
   engine's time, by profile, went to strcmp. */
typedef struct axis_x_meta {
  int32_t built;
  int32_t loads, stores, unit;
  int32_t branch_known, conditional, indirect;
  int32_t link_op, target_op, link_fixed, link_index;
  uint8_t op_in[AXIS_LIFT_MAX_OPERANDS], op_out[AXIS_LIFT_MAX_OPERANDS];
  uint8_t op_link_file[AXIS_LIFT_MAX_OPERANDS], op_store_addr[AXIS_LIFT_MAX_OPERANDS];
  const axis_reg_class *op_class[AXIS_LIFT_MAX_OPERANDS];
  int32_t op_pool[AXIS_LIFT_MAX_OPERANDS];
  /* State as registers (A64-1): which of THIS machine's state slots it reads
     and writes, the state an operand reaches through its class's alias (SP
     through register 31), and the registers it writes that no operand names. */
  int32_t st_read_count, st_write_count, fixed_count;
  uint8_t st_read[8], st_write[8];
  int32_t op_alias[AXIS_LIFT_MAX_OPERANDS];
  uint32_t fixed_slot[2];
  int32_t fixed_pool[2];
  /* Where a DIRECT branch goes, from its word and its address (D1); NULL for
     an indirect one, and for anything that is not a branch. */
  axis_sim_target_fn direct;
  /* The operand its unit's `(length NAME)` names, plus one; 0 for none (VU2). */
  int32_t len_op1;
} axis_x_meta;

/* A state slot of this machine, by name; -1 when it has none of that name. */
static int32_t axis_x_state_index(const axis_pack_machine *m, const char *name) {
  for (int32_t i = 0; name && i < m->state_count && i < 64; ++i) {
    if (m->state[i].name && !strcmp(m->state[i].name, name)) { return i; }
  }
  return -1;
}

static void axis_x_meta_build(const axis_pack_machine *m, const axis_lift_entry *entry, axis_x_meta *x) {
  const axis_sim_core *core = m->core;
  memset(x, 0, sizeof *x);
  x->built = 1;
  x->unit = -1;
  x->link_op = -1;
  x->target_op = -1;
  x->link_index = -1;
  x->branch_known = 0;
  x->conditional = 1;
  axis_sim_memop_of(entry, &x->loads, &x->stores);
  {
    const char *uname = axis_sim_unit_on(core, entry);
    for (int32_t u = 0; uname && uname[0] && u < core->unit_count; ++u) {
      if (!strcmp(core->units[u].name, uname)) { x->unit = u; break; }
    }
  }
  const char *length = x->unit >= 0 ? axis_unit_length(m, x->unit) : 0;
  for (int32_t o = 0; length && o < entry->operand_count && o < AXIS_LIFT_MAX_OPERANDS; ++o) {
    if (entry->operands[o].name && !strcmp(entry->operands[o].name, length)) { x->len_op1 = o + 1; break; }
  }
  const char *address = x->stores ? axis_sim_store_address(entry) : 0;
  const char *keeps = 0;
  for (const axis_sim_keep *k = AXIS_SIM_KEEPS; k->mnemonic; ++k) {
    if (!strcmp(k->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(k->isa, entry->isa))) { keeps = k->names; break; }
  }
  const axis_sim_link_reg *link = axis_sim_link_of(entry->isa);
  if (link) { x->link_index = (int32_t)link->index; }
  const axis_sim_control *c = AXIS_SIM_CONTROL;
  for (; c->mnemonic; ++c) {
    if (!strcmp(c->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(c->isa, entry->isa))) { break; }
  }
  if (c->mnemonic) {
    x->branch_known = 1;
    x->conditional = c->conditional;
    x->indirect = c->indirect;
    x->link_fixed = link && c->link_file[0] && !strcmp(c->link_file, link->file)
                    && c->link_index == (int32_t)link->index;
    x->direct = c->indirect ? 0 : axis_sim_direct_target_of(entry);
  }
  for (int32_t o = 0; o < entry->operand_count && o < AXIS_LIFT_MAX_OPERANDS; ++o) {
    const axis_lift_operand *operand = &entry->operands[o];
    const axis_reg_class *rules = axis_op_class(operand);
    x->op_class[o] = rules;
    x->op_pool[o] = rules ? axis_sim_rename_pool(core, operand->kind) : -1;
    if (operand->role && rules) {
      x->op_in[o] = (operand->role_code != AXIS_ROLE_OUT);
      x->op_out[o] = (operand->role_code == AXIS_ROLE_OUT) || (operand->role_code == AXIS_ROLE_INOUT);
      /* ⚠️ A WRITE OF PART OF A REGISTER READS THE REST (VM2). A reduction
         puts its sum in element 0 and leaves the others as they were, so the
         register it produces is made from the one before it. Not a lane
         group's -- together its lanes write every element -- and not a view
         CLASS's, which says for itself whether the rest is kept. */
      if (x->op_out[o] && operand->view_width && !rules->view_width && !entry->scalable_origin[0]
          && operand->view_width < 64u * (operand->stride ? operand->stride : 1u)) { x->op_in[o] = 1; }
      /* And one written under a guard keeps what it held when the guard
         fails: a non-faulting load's lanes past the fault. */
      if (x->op_out[o] && keeps && axis_sim_names(keeps, operand->name)) { x->op_in[o] = 1; }
    }
    x->op_store_addr[o] = !address || axis_sim_names(address, operand->name);
    const char *file = rules ? axis_sim_file_of(operand->kind) : 0;
    x->op_link_file[o] = link && file && !strcmp(file, link->file);
    if (c->mnemonic && operand->name && c->link[0] && !strcmp(operand->name, c->link)) { x->link_op = o; }
    if (c->mnemonic && operand->name && c->target[0] && !strcmp(operand->name, c->target)) { x->target_op = o; }
    x->op_alias[o] = (rules && rules->alias_index >= 0) ? axis_x_state_index(m, rules->alias_state) : -1;
  }
  const axis_sim_stateop *so = AXIS_SIM_STATEOPS;
  for (; so->mnemonic; ++so) {
    if (!strcmp(so->mnemonic, entry->mnemonic) && (!entry->isa || !strcmp(so->isa, entry->isa))) { break; }
  }
  if (!so->mnemonic) { return; }
  for (int32_t i = 0; i < m->state_count && i < 64; ++i) {
    const char *name = m->state[i].name;
    if (!name) { continue; }
    if (x->st_read_count < 8 && axis_sim_names(so->reads, name)) { x->st_read[x->st_read_count++] = (uint8_t)i; }
    if (x->st_write_count < 8 && axis_sim_names(so->writes, name)) { x->st_write[x->st_write_count++] = (uint8_t)i; }
  }
  for (int32_t f = 0; f < so->fixed_count && f < 2; ++f) {
    const axis_reg_class *rules = axis_reg_class_of(so->fixed_kind[f]);
    if (!rules || (rules->zero_index >= 0 && so->fixed_index[f] == rules->zero_index)) { continue; }
    uint32_t slot = rules->offset + (rules->index_offset + (uint32_t)so->fixed_index[f]) * rules->limbs;
    if (slot >= AXIS_SIM_REG_SLOTS) { continue; }
    x->fixed_slot[x->fixed_count] = slot;
    x->fixed_pool[x->fixed_count++] = axis_sim_rename_pool(core, so->fixed_kind[f]);
  }
}
/* The producer slot an operand names: its register's, or -- reaching state
   through its class's alias -- that state's, past the register file. */
static uint32_t axis_x_operand_slot(const axis_x_meta *x, const axis_lift_entry *entry, const axis_lifted *lifted, int32_t o) {
  if (x->op_alias[o] >= 0 && lifted->operands[o] == (uint32_t)x->op_class[o]->alias_index) {
    return AXIS_SIM_REG_SLOTS + (uint32_t)x->op_alias[o];
  }
  /* ⚠️ A VIEW names bits of its register, and past the first sixty-four they
     are in the next slot (VM2): lane 2 of a 128-bit register reads its second
     limb, not its first. */
  const axis_lift_operand *op = &entry->operands[o];
  return axis_operand_slot(op, lifted->operands[o]) + (op->view_width ? op->view_offset / 64u : 0u);
}
static const axis_x_meta *axis_x_meta_of(axis_pack_machine *m, const axis_lift_entry *entry) {
  static const axis_x_meta none = { 1, 0, 0, -1, 0, 1, 0, -1, -1, 0, -1, {0}, {0}, {0}, {0}, {0}, {0} };
  if (!entry) { return &none; }
  if (!m->x_meta) { m->x_meta = calloc(AXIS_LIFT_TABLE_LEN, sizeof *m->x_meta); }
  size_t k = (size_t)(entry - AXIS_LIFT_TABLE);
  if (!m->x_meta || entry < AXIS_LIFT_TABLE || k >= AXIS_LIFT_TABLE_LEN) {
    /* Not one of the table's own entries: work it out every time. */
    static axis_x_meta scratch;
    axis_x_meta_build(m, entry, &scratch);
    return &scratch;
  }
  if (!m->x_meta[k].built) { axis_x_meta_build(m, entry, &m->x_meta[k]); }
  return &m->x_meta[k];
}
/* The same facts for the TRACE-driven pipeline (A64-2), which dispatches
   from the functional simulator's retired path: an operand's producer slot,
   and what the instruction reads and writes that no operand names. */
static uint32_t axis_ooo_dep_slot(axis_pack_machine *m, const axis_lift_entry *entry,
                                  const axis_lifted *lifted, int32_t o) {
  return axis_x_operand_slot(axis_x_meta_of(m, entry), entry, lifted, o);
}
/* Whether operand `o` is read: a source, or a destination written in part. */
static int32_t axis_ooo_reads(axis_pack_machine *m, const axis_lift_entry *entry, int32_t o) {
  return o < AXIS_LIFT_MAX_OPERANDS && axis_x_meta_of(m, entry)->op_in[o];
}
static int32_t axis_ooo_implicit_reads(axis_pack_machine *m, const axis_lift_entry *entry, uint32_t *slot, int32_t max) {
  const axis_x_meta *x = axis_x_meta_of(m, entry);
  int32_t n = 0;
  for (int32_t i = 0; i < x->st_read_count && n < max; ++i) { slot[n++] = AXIS_SIM_REG_SLOTS + x->st_read[i]; }
  return n;
}
static int32_t axis_ooo_implicit_writes(axis_pack_machine *m, const axis_lift_entry *entry, uint32_t *slot, int32_t *pool, int32_t max) {
  const axis_x_meta *x = axis_x_meta_of(m, entry);
  int32_t n = 0;
  for (int32_t i = 0; i < x->st_write_count && n < max; ++i) { pool[n] = -1; slot[n++] = AXIS_SIM_REG_SLOTS + x->st_write[i]; }
  for (int32_t i = 0; i < x->fixed_count && n < max; ++i) { pool[n] = x->fixed_pool[i]; slot[n++] = x->fixed_slot[i]; }
  return n;
}
/* ⚠️ EVERY SLOT A WORD'S REGISTERS OCCUPY (VM2). A window entry is built
   from a word's first decode entry, whose operands name where each register
   STARTS. That is not everything:

   * a register wider than a slot is several, and a machine renames the
     register, not the slot: whoever writes any of it produces all of it, so
     a reader of its second limb waits for the write;
   * a vector word is many lanes -- lane 3 reads its sources' second limb, and
     a widening multiply's upper lanes write the register AFTER the one its
     first lane names. A reduction over that register ran ahead of the
     multiply that feeds it, and the golden model replayed it.

   So: for every destination operand of every lane, every slot of its
   register; for every source operand of every lane, the slot it names. What
   a word's lanes are is a fact about the word, kept per word. */
typedef struct axis_x_lane_line {
  uint32_t word;
  const char *isa;
  int32_t valid, reads, writes;
  /* The widest register any lane names, in 64-bit limbs (VU1). */
  uint32_t span;
  /* How many lanes the word is, and how wide the widest is (VU2). */
  uint32_t elems, elem_bits;
  uint32_t read[AXIS_SIM_OOO_SRC];
  uint32_t write[AXIS_SIM_OOO_DST];
} axis_x_lane_line;
#define AXIS_X_LANE_LINES 256u
static void axis_x_lane_note(uint32_t *slots, int32_t *count, int32_t max, uint32_t slot) {
  if (slot >= AXIS_SIM_REG_SLOTS) { return; }
  for (int32_t i = 0; i < *count; ++i) { if (slots[i] == slot) { return; } }
  if (*count < max) { slots[(*count)++] = slot; }
}
static void axis_x_lane_entry(axis_x_lane_line *line, uint32_t word, const axis_lift_entry *entry) {
  axis_lifted lifted;
  if (!axis_lift_entry_operands(word, entry, &lifted)) { return; }
  line->elems++;
  for (int32_t o = 0; o < entry->operand_count; ++o) {
    const axis_lift_operand *op = &entry->operands[o];
    const axis_reg_class *rules = axis_op_class(op);
    if (!rules || !op->role) { continue; }
    uint32_t slot = axis_operand_slot(op, lifted.operands[o]);
    if (entry->scalable_origin[0] && op->view_width > line->elem_bits) { line->elem_bits = op->view_width; }
    {
      uint32_t wide = op->view_width ? (op->stride ? op->stride : 1u) : (rules->limbs ? rules->limbs : 1u);
      if (wide > line->span) { line->span = wide; }
    }
    if (op->role_code != AXIS_ROLE_OUT) {
      axis_x_lane_note(line->read, &line->reads, (int32_t)AXIS_SIM_OOO_SRC,
                       slot + (op->view_width ? op->view_offset / 64u : 0u));
    }
    if (op->role_code == AXIS_ROLE_OUT || op->role_code == AXIS_ROLE_INOUT) {
      /* The register this operand's bits are in, and how many slots it is. */
      uint32_t n = op->view_width ? (op->stride ? op->stride : 1u) : (rules->limbs ? rules->limbs : 1u);
      uint32_t first = slot + (op->view_width ? ((op->view_offset / 64u) / n) * n : 0u);
      for (uint32_t k = 0; k < n; ++k) {
        axis_x_lane_note(line->write, &line->writes, (int32_t)AXIS_SIM_OOO_DST, first + k);
      }
    }
  }
}
static const axis_x_lane_line *axis_x_lane_line_of(axis_pack_machine *m, uint32_t word,
                                                   const axis_lift_entry *entry) {
  if (!m->x_lanes) { m->x_lanes = calloc(AXIS_X_LANE_LINES, sizeof(axis_x_lane_line)); }
  if (!m->x_lanes) { return 0; }
  axis_x_lane_line *line = &((axis_x_lane_line *)m->x_lanes)[(uint32_t)(word * 2654435761u) >> 24];
  if (line->valid && line->word == word && line->isa == m->sim.isa) { return line; }
  line->word = word;
  line->isa = m->sim.isa;
  line->valid = 1;
  line->reads = 0;
  line->writes = 0;
  line->span = 1;
  line->elems = 0;
  line->elem_bits = 0;
  if (!entry->scalable_origin[0]) { axis_x_lane_entry(line, word, entry); return line; }
  /* Every lane of the group: the entries of this origin the word matches,
     in the word's own ISA when the machine names a list (U4c). */
  const char *isa = axis_sim_word_isa(&m->sim, word);
  for (size_t k = 0; k < AXIS_LIFT_TABLE_LEN; ++k) {
    const axis_lift_entry *lane = &AXIS_LIFT_TABLE[k];
    if ((word & lane->mask) != lane->match || lane->definedness) { continue; }
    if (lane->scalable_origin != entry->scalable_origin && strcmp(lane->scalable_origin, entry->scalable_origin)) { continue; }
    if (isa && lane->isa[0] && strcmp(lane->isa, isa) != 0) { continue; }
    if (!axis_lift_constraint_ok(word, lane)) { continue; }
    axis_x_lane_entry(line, word, lane);
  }
  return line;
}
/* How wide `word` is, for a unit with lanes: its widest register in 64-bit
   limbs (VU1), and -- where its unit names a length -- the operand that says
   how many of its elements are work (VU2). */
static void axis_x_width(axis_pack_machine *m, axis_sim_rob_entry *e, uint32_t word,
                         const axis_lift_entry *entry, const axis_lifted *lifted) {
  const axis_x_lane_line *line = entry ? axis_x_lane_line_of(m, word, entry) : 0;
  e->span = line ? line->span : 1u;
  e->len_kind = 0;
  if (!line) { return; }
  const axis_x_meta *x = axis_x_meta_of(m, entry);
  if (!x->len_op1 || !line->elem_bits) { return; }
  int32_t o = x->len_op1 - 1;
  e->elems = line->elems;
  e->elem_bits = line->elem_bits;
  if (x->op_class[o]) {
    uint32_t slot = axis_x_operand_slot(x, entry, lifted, o);
    if (slot < AXIS_SIM_REG_SLOTS) { e->len_kind = 2u; e->len_slot = slot; }
  } else {
    e->len_kind = 1u;
    e->len_val = lifted->operands[o];
  }
}
/* The slots of `word` -- read, or written -- that `have` does not already
   hold. */
static int32_t axis_x_lane_slots(axis_pack_machine *m, uint32_t word, const axis_lift_entry *entry,
                                 int32_t writes, const uint32_t *have, int32_t have_count,
                                 uint32_t *out, int32_t max) {
  if (!entry || max <= 0) { return 0; }
  /* A word that is one entry reads what its operands say; only what it
     WRITES is wider than they name. */
  if (!writes && !entry->scalable_origin[0]) { return 0; }
  const axis_x_lane_line *line = axis_x_lane_line_of(m, word, entry);
  if (!line) { return 0; }
  const uint32_t *slots = writes ? line->write : line->read;
  int32_t count = writes ? line->writes : line->reads;
  int32_t n = 0;
  for (int32_t i = 0; i < count && n < max; ++i) {
    int32_t seen = 0;
    for (int32_t k = 0; k < have_count && !seen; ++k) { seen = have[k] == slots[i]; }
    if (!seen) { out[n++] = slots[i]; }
  }
  return n;
}
/* What kind of branch this instance is: the meta says which operands to look
   at, and only their values are read here. */
static void axis_x_classify(const axis_x_meta *x, const axis_lifted *lifted,
                            int32_t *conditional, int32_t *indirect, int32_t *is_call, int32_t *is_return) {
  *conditional = x->conditional;
  *indirect = x->indirect;
  *is_call = x->link_fixed
             || (x->link_op >= 0 && x->op_link_file[x->link_op]
                 && lifted->operands[x->link_op] == (uint32_t)x->link_index);
  *is_return = x->indirect && !*is_call && x->target_op >= 0 && x->op_link_file[x->target_op]
               && lifted->operands[x->target_op] == (uint32_t)x->link_index;
}
static uint32_t axis_x_hold(const axis_sim_core *core) {
  uint32_t fw = core->fetch_width ? core->fetch_width : 1u;
  uint32_t hold = core->fe_buffer ? core->fe_buffer : fw * (core->fe_depth + 1u);
  return hold > AXIS_SIM_XBUF ? AXIS_SIM_XBUF : hold;
}
/* Whether the predictor speculates its history (E2): abi_version 2 and all
   three calls, or history is trained at commit as E1 did. */
static int axis_x_spec(const axis_pack_machine *m) {
  const axis_sim_predictor *p = m->pred;
  return p && m->pred_state && p->abi_version >= 2u && p->history && p->set_history && p->speculate;
}
static uint32_t axis_x_btb_entries(const axis_sim_core *core) {
  /* ⚠️ A "perfect" target buffer needs an oracle, and an engine that fetches
     what it predicts has none: here a buffer is always LEARNED, and
     undeclared means as large as the model holds. */
  uint32_t n = core->btb ? core->btb : AXIS_SIM_BTB_MAX;
  return n < AXIS_SIM_BTB_MAX ? n : AXIS_SIM_BTB_MAX;
}

/* ⚠️ WHAT FETCH DID WHILE DECODE LOOKED (D2). A branch the target buffer does
   not hold is, to the front end, not a branch: until decode says otherwise it
   goes on fetching what follows, `fetch_width` a cycle for `cycles` cycles.
   Decode then discards those instructions -- they never reach the fetch
   buffer -- but the lines they came from are in the instruction cache, and
   that is prefetch if the program falls through to them later and pollution
   if it does not. At most what the front end holds; and the line fetch is in
   is forgotten, since it may have been evicted.

   ⚠️ A MISS STALLS IT (D4). It is the same fetch that the program's own is,
   `fetch_width` a cycle from `start`, and a line the cache does not hold is
   asked for and waited on: nothing past it is fetched until it lands, which
   is usually after decode has spoken, and the line itself arrives a latency
   after it was asked for -- not when the program next looks. Before this
   every line in reach was touched and each was "simply there", so a miss
   that began while decode looked cost nobody anything. */
static uint64_t axis_fe_decode_fetch(axis_pack_machine *m, uint64_t from, uint64_t start, uint32_t cycles) {
  const axis_sim_core *core = m->core;
  if (!core->icache.lines || !cycles) { return 0u; }
  uint32_t fw = core->fetch_width ? core->fetch_width : 1u;
  uint32_t lb = core->icache.line_bytes ? core->icache.line_bytes : 64u;
  uint64_t hold = core->fe_buffer ? core->fe_buffer : (uint64_t)fw * (core->fe_depth + 1u);
  uint64_t n = (uint64_t)cycles * fw;
  if (n > hold) { n = hold; }
  /* Words fetched so far, the cycles spent waiting on lines, and so the
     cycle the next line is asked for in. */
  uint64_t done = 0, stalled = 0, lines = 0, pos = from;
  while (done < n && lines < AXIS_SIM_ICACHE_LINES) {
    if (stalled >= cycles || done >= (cycles - stalled) * fw) { break; }
    uint64_t line = pos / lb;
    uint64_t at = start + stalled + done / fw;
    if (axis_ic_touch(m, line)) {
      axis_ic_fill(m, line, at + core->icache.miss_cycles);
      stalled += core->icache.miss_cycles;
    }
    else if (axis_ic_ready(m, line) > at) { stalled += axis_ic_ready(m, line) - at; }
    axis_tlb_touch(m, 1, line * lb);
    lines++;
    done += ((line + 1u) * lb - pos) / 4u;
    pos = (line + 1u) * lb;
  }
  m->ic_have_line = 0;
  m->it_have = 0;
  return lines;
}

/* Whether this machine could fetch this cycle, were the front end its own. */
static int axis_x_can_fetch(const axis_pack_machine *m) {
  return m && m->sim.status == AXIS_SIM_RUNNING && !m->x_halted && !m->x_fetch_stopped && !m->x_sleeping
         && m->now >= m->x_fetch_resume && m->x_buf_count < axis_x_hold(m->core);
}
/* ⚠️ ONE PC A CYCLE (U4b). A warp's front end fetches for every member whose
   next pc is the one it picks: the lowest any running member wants -- the
   members behind catch up to the ones ahead, which is where a warp
   reconverges -- unless one has been passed over for `warp_age` cycles, in
   which case the longest-passed goes, so a member running ahead in a loop
   the others have left is not starved for ever. Picked once a cycle, by the
   first member to fetch in it.

   ⚠️ IN LOCKSTEP (U4c): the pc is fetched only when EVERY member at it can
   take it this cycle. Picking among members that could fetch instead let a
   member whose loads hit run ahead of one whose loads missed -- the second's
   buffer was full, so the first fetched alone -- and from then on their
   copies carried different tags and nothing fused again. */
static void axis_x_warp_pick(axis_sim_group *g, uint32_t warp, uint64_t now) {
  uint32_t w = warp - 1u;
  if (g->fetch_cycle[w] == now) { return; }
  g->fetch_cycle[w] = now;
  g->fetch_any[w] = 0;
  const axis_pack_machine *starved = 0, *lowest = 0;
  for (int32_t i = 0; i < g->count; ++i) {
    const axis_pack_machine *o = g->member[i];
    if (!o || o->x_warp != warp || o->sim.status != AXIS_SIM_RUNNING || o->x_halted || o->x_fetch_stopped || o->x_sleeping) { continue; }
    if (o->x_passed >= g->warp_age && (!starved || o->x_passed > starved->x_passed)) { starved = o; }
    if (!lowest || o->x_fetch_pc < lowest->x_fetch_pc) { lowest = o; }
  }
  const axis_pack_machine *pick = starved ? starved : lowest;
  if (!pick) { return; }
  for (int32_t i = 0; i < g->count; ++i) {
    const axis_pack_machine *o = g->member[i];
    if (!o || o->x_warp != warp || o->sim.status != AXIS_SIM_RUNNING || o->x_halted || o->x_fetch_stopped || o->x_sleeping) { continue; }
    if (o->x_fetch_pc == pick->x_fetch_pc && !axis_x_can_fetch(o)) { return; }
  }
  g->fetch_any[w] = 1;
  g->fetch_pc[w] = pick->x_fetch_pc;
}

/* ---- fetch: down the PREDICTED path ---------------------------------- */
static void axis_x_fetch(axis_pack_machine *m) {
  const axis_sim_core *core = m->core;
  if (m->x_fetch_stopped || m->x_sleeping || m->now < m->x_fetch_resume) { return; }
  uint32_t fw = core->fetch_width ? core->fetch_width : 1u;
  uint32_t hold = axis_x_hold(core);
  axis_sim_group *grp = m->grp;
  if (grp && m->x_warp) {
    axis_x_warp_pick(grp, m->x_warp, m->now);
    uint32_t w = m->x_warp - 1u;
    if (!grp->fetch_any[w] || grp->fetch_pc[w] != m->x_fetch_pc) { m->x_passed++; return; }
    m->x_passed = 0;
  }
  uint32_t lb = core->icache.line_bytes ? core->icache.line_bytes : 64u;
  uint32_t got = 0;
  for (uint32_t k = 0; m->x_buf_count < hold; ++k) {
    uint64_t pc = m->x_fetch_pc;
    /* ⚠️ THE PATH it comes by (U2), which says how many make a group, counted
       in what, and how far from dispatch. A change of path ends the group. */
    int32_t path = axis_fe_path(m, pc);
    if (k > 0 && path != m->fe_path) { return; }
    m->fe_path = path;
    uint32_t group = path == 2 ? m->lb_width : (path == 1 ? m->oc_width : fw);
    uint32_t ops = 1u;
    if (path) {
      int32_t peeked = 1;
      axis_lifted peek;
      uint32_t at = m->host.fetch ? m->host.fetch(m->host.ctx, pc, &peeked) : 0u;
      if (peeked && axis_sim_lift(&m->sim, at, &peek) && peek.entry) { ops = axis_fe_ops(m, peek.entry); }
    }
    if (got && got + ops > group) { return; }
    if (got >= group) { return; }
    got += ops;
    /* ⚠️ A NEW PAGE is a lookup in the fetch TLB, and what it costs stalls
       fetch before the line is asked for. Counted when the instruction that
       needed the page commits, as an instruction-cache miss is. */
    if (!path && core->tlb.fetch_entries) {
      uint64_t page = pc / (core->tlb.page_bytes ? core->tlb.page_bytes : 4096u);
      if (!m->it_have || page != m->it_page) {
        uint64_t im = m->itlb_misses, pw = m->page_walks;
        uint64_t walk_asked = m->pending_walk;
        uint64_t walk = axis_tlb_lookup(m, 1, pc);
        m->tq_new_page = 1;
        /* Fetch's walk needs a walker too (TLB2). */
        walk += axis_walker_take(m, m->now, m->pending_walk - walk_asked);
        m->pending_walk = walk_asked;
        m->x_it_pending |= (uint8_t)((m->itlb_misses != im ? 1u : 0u) | (m->page_walks != pw ? 2u : 0u));
        m->itlb_misses = im;
        m->page_walks = pw;
        m->it_page = page;
        m->it_have = 1;
        if (walk) { m->x_fetch_resume = m->now + walk; return; }
      }
    }
    /* A fetch reads ONE line: a new line ends the group, and a line the
       instruction cache does not hold stalls fetch for its latency. */
    if (!path && core->icache.lines) {
      uint64_t line = pc / lb;
      if (!m->ic_have_line || line != m->ic_line) {
        if (k > 0) { return; }
        m->ic_line = line;
        m->ic_have_line = 1;
        /* ⚠️ NAMED AHEAD (FQ1): a predictor that runs ahead of fetch asked
           for this line when it named it; with no queue that is now. */
        uint64_t named = axis_tq_named(m, m->now);
        if (axis_ic_touch(m, line)) {
          uint64_t ready = named + core->icache.miss_cycles;
          axis_ic_fill(m, line, ready);
          /* ⚠️ Counted when the instruction that needed the line COMMITS:
             a miss on a path that is squashed is cache contents, not a miss
             of the program's. A line asked for ahead is no miss of fetch's. */
          if (named == m->now) { m->x_ic_pending = 1; }
          axis_tq_took(m, named, ready > m->now ? ready : m->now);
          if (ready > m->now) { m->x_fetch_resume = ready; return; }
        }
        else {
          /* ⚠️ Held, and not here yet (D4): a path that was squashed, or decode
             looking at a branch, asked for this line and its fill is still
             running. Fetch waits for what is left of it, and it is no miss. */
          uint64_t ready = axis_ic_ready(m, line);
          axis_tq_took(m, named, ready > m->now ? ready : m->now);
          if (ready > m->now) { m->x_fetch_resume = ready; return; }
        }
      }
    }
    axis_x_fetched *f = &m->x_buf[(m->x_buf_head + m->x_buf_count) % AXIS_SIM_XBUF];
    memset(f, 0, sizeof *f);
    f->pc = pc;
    f->fetched = m->now;
    f->depth = path == 2 ? m->lb_depth : (path == 1 ? m->oc_depth : core->fe_depth);
    f->path = path;
    f->ras_top = m->ras_top;
    f->ras_count = m->ras_count;
    f->hist = axis_x_spec(m) ? m->pred->history(m->pred_state) : 0u;
    f->ic_miss = m->x_ic_pending;
    m->x_ic_pending = 0;
    f->it_miss = m->x_it_pending;
    m->x_it_pending = 0;
    m->x_buf_count++;
    int32_t answered = 1;
    uint32_t word = m->host.fetch ? m->host.fetch(m->host.ctx, pc, &answered) : 0u;
    f->word = word;
    /* ⚠️ A word fetch cannot read, or that decodes to nothing, is carried to
       commit as it is: on the predicted path's correct side the golden model
       halts there; on its wrong side a squash removes it. Either way fetch
       goes no further down this path. */
    if (!answered || !axis_sim_lift(&m->sim, word, &f->lifted) || !f->lifted.entry) {
      f->bad = 1;
      f->pred_next = pc;
      m->x_fetch_stopped = 1;
      axis_tq_reset(m);
      return;
    }
    const axis_lift_entry *entry = f->lifted.entry;
    uint32_t bytes = entry->bits ? entry->bits / 8u : 4u;
    uint64_t next = pc + bytes;
    int32_t taken = 0;
    /* Sent back at decode (D3): not taken, and a new fetch group all the same. */
    int32_t sent_back = 0;
    uint32_t bubble = 0;
    if (entry->ends_block) {
      int32_t conditional = 1, indirect = 0, is_call = 0, is_return = 0;
      axis_x_classify(axis_x_meta_of(m, entry), &f->lifted, &conditional, &indirect, &is_call, &is_return);
      f->branch = 1;
      f->conditional = conditional;
      taken = conditional ? ((m->pred && m->pred_state) ? (m->pred->predict(m->pred_state, pc) != 0) : 0) : 1;
      /* ⚠️ OVERRIDDEN AT DECODE (D3): what fetch followed, for a core with a
         quick predictor; `taken` is the core's own, which speaks at decode. */
      int32_t quick = (conditional && m->quick_state) ? axis_quick_predict(m, pc) : taken;
      /* Where fetch runs while decode looks, and for how long (D2, D3). */
      uint64_t ahead_from = pc + bytes;
      uint32_t ahead = 0;
      uint64_t target = 0;
      int32_t known = 0;
      /* The loop's own branch, from the buffer (U2): the buffer wraps. */
      int32_t wraps = taken && path == 2 && pc == m->lb_branch;
      if (wraps) { target = m->lb_target; known = 1; }
      if (taken && !known && is_return && core->ras && m->ras_count) {
        target = m->ras_stack[m->ras_top];
        known = 1;
        m->ras_top = (m->ras_top + 63u) % 64u;
        m->ras_count--;
      }
      if (taken && !known) {
        uint32_t n = axis_x_btb_entries(core);
        uint32_t at = (uint32_t)((pc / bytes) % n);
        if (m->btb_tag[at] == pc + 1u) { target = m->btb_target[at]; known = 1; }
        else {
          m->btb_misses++;
          /* ⚠️ DECODE FINDS IT (D1). A direct branch's target is a field of
             its word added to its address: no register is read, so the front
             end knows where it goes as soon as the word is decoded --
             `btb_penalty` cycles after the fetch, which is what the
             trace-driven front end has charged all along. Falling through
             instead, and waiting for the branch to EXECUTE to learn what the
             word already said, made every direct jump's first encounter a
             full mispredict. An indirect branch has no such field. */
          const axis_x_meta *x = axis_x_meta_of(m, entry);
          if (!indirect && x->direct && x->direct(&f->lifted, pc, &target)) {
            known = 1;
            bubble = core->btb_penalty;
            ahead = bubble;
          }
        }
      }
      /* Predicted taken and nowhere known to go -- an indirect branch the
         buffer does not hold: fetch can only fall through, and execution
         will say otherwise. */
      if (!known) { taken = 0; }
      /* ⚠️ The quick guess and the real one disagree (D3), and fetch had
         somewhere to have gone: on past a branch guessed not taken, which
         decode now redirects to its target -- or to the target the buffer
         holds for one guessed taken, which decode sends back. `quick_cycles`
         either way, in place of decode's own if that is shorter. */
      if (quick != taken && m->quick_state) {
        if (!quick) { if (bubble < m->quick_cycles) { bubble = m->quick_cycles; } ahead = bubble; }
        else {
          uint32_t n = axis_x_btb_entries(core);
          uint32_t at = (uint32_t)((pc / bytes) % n);
          if (m->btb_tag[at] == pc + 1u) {
            bubble = m->quick_cycles;
            ahead = bubble;
            ahead_from = m->btb_target[at];
            sent_back = 1;
          }
        }
      }
      if (ahead) { (void)axis_fe_decode_fetch(m, ahead_from, m->now + 1u, ahead); }
      if (is_call && core->ras) {
        uint32_t depth = core->ras < 64u ? core->ras : 64u;
        m->ras_top = (m->ras_top + 1u) % 64u;
        m->ras_stack[m->ras_top] = pc + bytes;
        if (m->ras_count < depth) { m->ras_count++; }
      }
      if (taken) { next = target; }
      /* ⚠️ The history moves on by what fetch DID -- predicted not taken, or
         taken with nowhere to go, is fetched as not taken. */
      if (conditional && axis_x_spec(m)) { m->pred->speculate(m->pred_state, pc, taken); }
    }
    f->pred_next = next;
    m->x_fetch_pc = next;
    /* What the loop buffer learns from it (U2) -- on the path fetch
       predicts, which a squash undoes. */
    {
      int32_t wrapped = taken && path == 2 && pc == m->lb_branch;
      axis_lb_saw(m, pc, ops, entry->ends_block, taken, next);
      axis_lb_settle(m);
      if (wrapped && m->lb_on) { continue; }   /* the buffer wraps: no new group */
    }
    if (taken || sent_back) {             /* a taken branch ends the group */
      /* A branch the predictor could not follow (FQ1). */
      if (bubble) { m->x_fetch_resume = m->now + 1u + bubble; axis_tq_reset(m); }
      return;
    }
  }
}

/* ⚠️ A CRACKED INSTRUCTION ENTERS THE WINDOW (U1), execution-driven: one
   entry a micro-op, each with its unit, its cycles, the operands it reads --
   as they were before the instruction -- the micro-ops it waits for and the
   registers that are its to write. All of them or none: an instruction is in
   the window whole. 0 when there is no room this cycle. */

/* What an execution-driven tail reads and writes, for `axis_fuse_pair`. */
static axis_sim_rob_entry *axis_fuse_x(axis_pack_machine *m, const axis_x_fetched *f, const axis_lift_entry *entry, const axis_x_meta *x) {
  if (!m->fuse || !entry || x->stores || axis_sim_crack_of(m, entry)) { return 0; }
  uint32_t reads[AXIS_SIM_OOO_SRC], writes[AXIS_SIM_OOO_DST];
  int32_t nr = 0, nw = 0;
  for (int32_t o = 0; o < entry->operand_count; ++o) {
    uint32_t slot = (x->op_in[o] || x->op_out[o]) ? axis_x_operand_slot(x, entry, &f->lifted, o) : AXIS_SIM_PRODUCERS;
    if (slot >= AXIS_SIM_PRODUCERS) { continue; }
    if (x->op_in[o] && nr < (int32_t)AXIS_SIM_OOO_SRC) { reads[nr++] = slot; }
    if (x->op_out[o] && nw < (int32_t)AXIS_SIM_OOO_DST) { writes[nw++] = slot; }
  }
  for (int32_t i = 0; i < x->st_read_count && nr < (int32_t)AXIS_SIM_OOO_SRC; ++i) { reads[nr++] = AXIS_SIM_REG_SLOTS + x->st_read[i]; }
  for (int32_t i = 0; i < x->st_write_count && nw < (int32_t)AXIS_SIM_OOO_DST; ++i) { writes[nw++] = AXIS_SIM_REG_SLOTS + x->st_write[i]; }
  for (int32_t i = 0; i < x->fixed_count && nw < (int32_t)AXIS_SIM_OOO_DST; ++i) { writes[nw++] = x->fixed_slot[i]; }
  return axis_fuse_pair(m, entry, x->unit, axis_sim_latency_on(m->core, entry), reads, nr, writes, nw, x->loads != 0);
}
static int axis_x_dispatch_cracked(axis_pack_machine *m, const axis_x_fetched *f, const axis_lift_entry *entry,
                                   const axis_x_meta *x, const axis_sim_crack *crack, uint32_t spent,
                                   uint32_t width, uint32_t rob, uint32_t queue) {
  const axis_sim_core *core = m->core;
  uint32_t n = (uint32_t)(crack->count < AXIS_SIM_CRACK_MAX ? crack->count : AXIS_SIM_CRACK_MAX);
  if (spent && spent + n > width) { return 0; }
  if (m->rob_head != m->rob_tail && axis_rob_full(m, rob, (uint32_t)n)) { return 0; }
  if (m->x_waiting && m->x_waiting + n > queue) { return 0; }
  for (uint32_t u = 0; u < n; ++u) {
    for (int32_t k = 0; k < core->unit_count; ++k) {
      if (!strcmp(core->units[k].name, crack->op[u].unit) && axis_unit_queue_full(m, k)) { return 0; }
    }
  }
  uint32_t slot_of[32];
  uint64_t before[32];
  for (int32_t o = 0; o < 32; ++o) {
    slot_of[o] = AXIS_SIM_PRODUCERS;
    before[o] = AXIS_SIM_NO_SEQ;
    if (o >= entry->operand_count || !(x->op_in[o] || x->op_out[o])) { continue; }
    slot_of[o] = axis_x_operand_slot(x, entry, &f->lifted, o);
    if (slot_of[o] < AXIS_SIM_PRODUCERS) { before[o] = m->reg_producer[slot_of[o]]; }
  }
  uint64_t state_before[8];
  for (int32_t i = 0; i < x->st_read_count && i < 8; ++i) {
    state_before[i] = m->reg_producer[AXIS_SIM_REG_SLOTS + x->st_read[i]];
  }
  /* What each micro-op writes, and whether the registers and queues have
     room for all of it. */
  int32_t want_pool[AXIS_SIM_CRACK_MAX][AXIS_SIM_OOO_DST];
  uint32_t want_slot[AXIS_SIM_CRACK_MAX][AXIS_SIM_OOO_DST];
  int32_t want[AXIS_SIM_CRACK_MAX];
  uint32_t need[AXIS_SIM_RENAME_POOLS] = {0};
  uint32_t memory_ops = 0;
  for (uint32_t u = 0; u < n; ++u) {
    const axis_sim_micro_op *op = &crack->op[u];
    want[u] = 0;
    for (int32_t o = 0; o < entry->operand_count && o < 32 && want[u] < (int32_t)AXIS_SIM_OOO_DST; ++o) {
      if (!((op->writes >> o) & 1u) || !x->op_out[o] || slot_of[o] >= AXIS_SIM_PRODUCERS) { continue; }
      const axis_reg_class *rules = x->op_class[o];
      want_pool[u][want[u]] = (slot_of[o] >= AXIS_SIM_REG_SLOTS
                               || (rules->zero_index >= 0 && f->lifted.operands[o] == (uint32_t)rules->zero_index))
                              ? -1 : x->op_pool[o];
      want_slot[u][want[u]++] = slot_of[o];
    }
    if (op->implicit) {
      for (int32_t i = 0; i < x->st_write_count && want[u] < (int32_t)AXIS_SIM_OOO_DST; ++i) {
        want_pool[u][want[u]] = -1;
        want_slot[u][want[u]++] = AXIS_SIM_REG_SLOTS + x->st_write[i];
      }
      for (int32_t i = 0; i < x->fixed_count && want[u] < (int32_t)AXIS_SIM_OOO_DST; ++i) {
        want_pool[u][want[u]] = x->fixed_pool[i];
        want_slot[u][want[u]++] = x->fixed_slot[i];
      }
    }
    for (int32_t i = 0; i < want[u]; ++i) { if (want_pool[u][i] >= 0) { need[want_pool[u][i]]++; } }
    if (op->accesses || op->rest) { memory_ops++; }
  }
  if (m->rob_head != m->rob_tail) {
    for (int32_t p = 0; p < core->rename_count && p < (int32_t)AXIS_SIM_RENAME_POOLS; ++p) {
      if (need[p] && m->rename_used[p] + need[p] > core->rename[p].extra) { return 0; }
    }
  }
  if (core->lsq && ((x->loads && core->load_queue && m->x_loads + memory_ops > core->load_queue)
                    || (x->stores && core->store_queue && m->x_stores + memory_ops > core->store_queue))) { return 0; }
  {
    uint32_t results = 0;
    for (uint32_t u = 0; u < n; ++u) { results += (uint32_t)want[u]; }
    if (m->now > m->dispatch_cycle) { m->dispatch_cycle = m->now; m->renamed_this_cycle = 0; }
    if (axis_rename_full(m, results)) { return 0; }
    m->renamed_this_cycle += results;
  }
  uint64_t first = m->rob_tail;
  for (uint32_t u = 0; u < n; ++u) {
    const axis_sim_micro_op *op = &crack->op[u];
    int32_t last = u + 1u == n;
    int32_t has_memory = op->accesses || op->rest;
    axis_sim_rob_entry *e = &m->rob[m->rob_tail % AXIS_SIM_ROB_MAX];
    memset(e, 0, sizeof *e);
    e->seq = m->rob_tail;
    e->valid = 1;
    e->latency = op->latency;
    e->unit = -1;
    for (int32_t k = 0; k < core->unit_count; ++k) {
      if (!strcmp(core->units[k].name, op->unit)) { e->unit = k; break; }
    }
    axis_x_width(m, e, f->word, entry, &f->lifted);
    e->pc = f->pc;
    e->x_word = f->word;
    e->x_lifted = f->lifted;
    e->x_uop = (int32_t)u;
    e->x_uops = (int32_t)n;
    e->x_acc_mask = op->accesses;
    e->x_acc_rest = op->rest;
    /* Where it goes next is the last micro-op's to say; the others go
       nowhere a prediction could be wrong about. */
    e->x_pred_next = last ? f->pred_next : f->pc;
    e->x_branch = last ? f->branch : 0;
    e->x_conditional = last ? f->conditional : 0;
    e->x_ras_top = f->ras_top;
    e->x_ras_count = f->ras_count;
    e->x_hist = f->hist;
    e->x_ic_miss = last ? f->ic_miss : 0;
    e->x_it_miss = last ? f->it_miss : 0;
    e->x_fetched_at = f->fetched;
    e->is_load = has_memory && x->loads;
    e->is_store = has_memory && x->stores;
    if (has_memory && core->lsq && core->disambiguation == 3u && core->store_sets) {
      uint32_t sets = core->store_sets < AXIS_SIM_SSIT_MAX ? core->store_sets : AXIS_SIM_SSIT_MAX;
      e->store_set = m->ssit[(uint32_t)((f->pc >> 2) % sets)];
    }
    for (int32_t i = 0; i < AXIS_SIM_OOO_DST; ++i) { e->dst_pool[i] = -1; }
    for (int32_t o = 0; o < entry->operand_count && o < 32; ++o) {
      if (!((op->reads >> o) & 1u) || !x->op_in[o] || before[o] == AXIS_SIM_NO_SEQ) { continue; }
      int32_t seen = 0;
      for (int32_t k = 0; k < e->src_count && !seen; ++k) { seen = e->src_seq[k] == before[o]; }
      if (!seen && e->src_count < AXIS_SIM_OOO_SRC) { e->src_seq[e->src_count++] = before[o]; }
    }
    for (uint32_t v = 0; v < u; ++v) {
      if (((op->after >> v) & 1u) && e->src_count < AXIS_SIM_OOO_SRC) { e->src_seq[e->src_count++] = first + v; }
    }
    if (op->implicit) {
      for (int32_t i = 0; i < x->st_read_count && i < 8 && e->src_count < AXIS_SIM_OOO_SRC; ++i) {
        if (state_before[i] != AXIS_SIM_NO_SEQ) { e->src_seq[e->src_count++] = state_before[i]; }
      }
    }
    for (int32_t i = 0; i < want[u]; ++i) {
      e->dst_pool[e->dst_count] = want_pool[u][i];
      e->dst_slot[e->dst_count++] = want_slot[u][i];
      if (want_pool[u][i] >= 0) { m->rename_used[want_pool[u][i]]++; }
      m->reg_producer[want_slot[u][i]] = e->seq;
    }
    m->rob_tail++;
    m->x_waiting++;
    m->x_loads += (uint32_t)e->is_load;
    m->x_stores += (uint32_t)e->is_store;
    e->x_path = f->path;
  }
  return 1;
}

/* ---- dispatch: in order, into the window ------------------------------ */
static void axis_x_dispatch(axis_pack_machine *m) {
  const axis_sim_core *core = m->core;
  /* A context of a shared core (U4a) gets its share of the window and the
     queue, and dispatches within the core's width this cycle. */
  axis_grp_sync(m->grp, m->now);
  uint32_t rob = axis_grp_share(m->grp, axis_ooo_rob(core));
  uint32_t queue = axis_grp_share(m->grp, core->issue_queue ? core->issue_queue : axis_ooo_rob(core));
  uint32_t width = axis_disp_width(m);
  for (uint32_t d = 0; m->x_buf_count; ++d) {
    axis_x_fetched *f = &m->x_buf[m->x_buf_head];
    /* What a warp's members fetched together dispatches as one (U4b): the
       first pays a slot, the rest ride. */
    int rides = axis_grp_rides(m->grp, 0, m->x_warp, f->fetched, f->pc);
    if (f->fetched + f->depth > m->now) { break; }
    const axis_lift_entry *entry = f->bad ? 0 : f->lifted.entry;
    const axis_x_meta *x = axis_x_meta_of(m, entry);
    /* ⚠️ THE TAIL OF A FUSED PAIR (FU1) needs none of the width, no entry and
       no queue: it is its head's operation, and follows it. */
    axis_sim_rob_entry *fuse_head = (entry && !rides) ? axis_fuse_x(m, f, entry, x) : 0;
    /* FU2: a tail that is a load is the pair, and its head follows. */
    int32_t absorb = fuse_head != 0 && m->fz_absorb;
    uint32_t pair_latency = m->fz_latency;
    int32_t fuse = fuse_head != 0 && !absorb;
    if (!fuse && !absorb && !rides && (m->grp ? m->grp->dispatched : d) >= width) { break; }
    if (!fuse && !absorb && axis_rob_full(m, rob, 1u)) { break; }
    /* ⚠️ A MOVE DONE AT RENAME (ME1) needs an entry and nothing else. */
    int32_t elim = fuse ? 1 : (entry && !rides) ? axis_move_at_rename(m, entry, &f->lifted) : 0;
    /* ⚠️ A ZERO IDIOM (ZI1) is one too, and waits for nothing. */
    int32_t zero = (entry && !rides && !elim) ? axis_zero_at_rename(m, entry, &f->lifted) : 0;
    if (zero) { elim = 1; }
    if (!elim && m->x_waiting - (uint32_t)absorb >= queue) { break; }
    /* Its unit's own queue (S2): full, and it does not enter. */
    if (!elim && entry && axis_unit_queue_full(m, x->unit)) { break; }
    /* ⚠️ CRACKED (U1): as many entries as it has micro-ops, all this cycle or
       none of them. */
    const axis_sim_crack *crack = (entry && !rides) ? axis_sim_crack_of(m, entry) : 0;
    if (crack) {
      if (!axis_x_dispatch_cracked(m, f, entry, x, crack, m->grp ? m->grp->dispatched : d, width, rob, queue)) { break; }
      if (m->grp) { m->grp->dispatched += (uint32_t)crack->count; axis_grp_pay(m->grp, 0, m->x_warp, f->fetched, f->pc); }
      d += (uint32_t)crack->count - 1u;
      m->x_buf_head = (m->x_buf_head + 1u) % AXIS_SIM_XBUF;
      m->x_buf_count--;
      continue;
    }
    /* The registers this instruction writes, and the rename pools they come
       from -- a write with no free physical register cannot dispatch. */
    int32_t want_pool[AXIS_SIM_OOO_DST];
    uint32_t want_slot[AXIS_SIM_OOO_DST];
    int32_t want = 0;
    for (int32_t o = 0; entry && o < entry->operand_count && want < (int32_t)AXIS_SIM_OOO_DST; ++o) {
      if (!x->op_out[o]) { continue; }
      uint32_t slot = axis_x_operand_slot(x, entry, &f->lifted, o);
      if (slot >= AXIS_SIM_PRODUCERS) { continue; }
      const axis_reg_class *rules = x->op_class[o];
      int32_t pool = (slot >= AXIS_SIM_REG_SLOTS
                      || (rules->zero_index >= 0 && f->lifted.operands[o] == (uint32_t)rules->zero_index))
                     ? -1 : x->op_pool[o];
      want_pool[want] = pool;
      want_slot[want++] = slot;
    }
    /* ⚠️ And what no operand names (A64-1): the state it writes -- NZCV
       from a compare -- and a fixed register -- X30 from a BL. Each is a
       destination like any other: what reads it next waits for this. */
    for (int32_t i = 0; i < x->st_write_count && want < (int32_t)AXIS_SIM_OOO_DST; ++i) {
      want_pool[want] = -1;
      want_slot[want++] = AXIS_SIM_REG_SLOTS + x->st_write[i];
    }
    for (int32_t i = 0; i < x->fixed_count && want < (int32_t)AXIS_SIM_OOO_DST; ++i) {
      want_pool[want] = x->fixed_pool[i];
      want_slot[want++] = x->fixed_slot[i];
    }
    /* And what the other lanes write (VM2): more of the same registers, which
       take no further physical register. */
    {
      int32_t more = axis_x_lane_slots(m, f->word, entry, 1, want_slot, want, want_slot + want,
                                       (int32_t)AXIS_SIM_OOO_DST - want);
      for (int32_t i = 0; i < more; ++i) { want_pool[want + i] = -1; }
      want += more;
    }
    int32_t renames = axis_fuse_renames(fuse_head, elim || absorb, want_slot, want_pool, want);
    uint32_t need[AXIS_SIM_RENAME_POOLS] = {0};
    int short_of = 0;
    for (int32_t i = 0; i < want; ++i) { if (want_pool[i] >= 0) { need[want_pool[i]]++; } }
    for (int32_t p = 0; p < core->rename_count && p < (int32_t)AXIS_SIM_RENAME_POOLS; ++p) {
      if (need[p] && m->rename_used[p] + need[p] > core->rename[p].extra) { short_of = 1; }
    }
    if (short_of && m->rob_head != m->rob_tail) { break; }
    /* Its results need renaming, and this cycle has renamed all it can (S6). */
    if (m->now > m->dispatch_cycle) { m->dispatch_cycle = m->now; m->renamed_this_cycle = 0; }
    if (axis_rename_full(m, (uint32_t)renames)) { break; }
    /* ⚠️ A load is a load when it DECODES (E3): the description says which
       instructions read memory and which write it, so the queues can count
       them before anything has executed. */
    int32_t is_load = x->loads, is_store = x->stores;
    if (core->lsq && ((is_load && core->load_queue && m->x_loads >= core->load_queue)
                      || (is_store && core->store_queue && m->x_stores >= core->store_queue))) { break; }
    axis_sim_rob_entry *e = &m->rob[m->rob_tail % AXIS_SIM_ROB_MAX];
    memset(e, 0, sizeof *e);
    e->seq = m->rob_tail;
    e->valid = 1;
    e->latency = axis_sim_latency_on(m->core, entry);
    e->unit = elim ? -1 : x->unit;
    e->elim = elim;
    e->fused = fuse;
    if (fuse) { axis_fuse_take(m, fuse_head); m->fuse_live++; }
    if (absorb) { axis_fuse_absorb(m, fuse_head); m->x_waiting--; e->latency = pair_latency; }
    axis_x_width(m, e, f->word, entry, &f->lifted);
    e->pc = f->pc;
    e->x_word = f->word;
    e->x_bad = f->bad;
    e->x_lifted = f->lifted;
    e->x_pred_next = f->pred_next;
    e->x_branch = f->branch;
    e->x_conditional = f->conditional;
    e->x_ras_top = f->ras_top;
    e->x_ras_count = f->ras_count;
    e->x_hist = f->hist;
    e->x_ic_miss = f->ic_miss;
    e->x_it_miss = f->it_miss;
    e->x_fetched_at = f->fetched;
    e->x_path = f->path;
    e->is_load = is_load;
    e->is_store = is_store;
    if (core->lsq && core->disambiguation == 3u && core->store_sets) {
      uint32_t n = core->store_sets < AXIS_SIM_SSIT_MAX ? core->store_sets : AXIS_SIM_SSIT_MAX;
      e->store_set = m->ssit[(uint32_t)((f->pc >> 2) % n)];
    }
    for (int32_t i = 0; i < AXIS_SIM_OOO_DST; ++i) { e->dst_pool[i] = -1; }
    uint32_t read_slot[AXIS_SIM_OOO_SRC];
    for (int32_t o = 0; entry && o < entry->operand_count; ++o) {
      if (!x->op_in[o]) { continue; }
      uint32_t slot = axis_x_operand_slot(x, entry, &f->lifted, o);
      /* ⚠️ A slot is waited for once. A compress names four lanes of its
         source and four of its predicate before its third register, and
         eight entries of the same two producers left no room for it. */
      int32_t seen = slot >= AXIS_SIM_PRODUCERS;
      for (int32_t k = 0; k < e->src_count && !seen; ++k) { seen = read_slot[k] == slot; }
      if (!seen && e->src_count < AXIS_SIM_OOO_SRC) {
        read_slot[e->src_count] = slot;
        e->src_seq[e->src_count++] = m->reg_producer[slot];
      }
    }
    {
      int32_t had = e->src_count;
      int32_t more = axis_x_lane_slots(m, f->word, entry, 0, read_slot, had, read_slot + had,
                                       (int32_t)AXIS_SIM_OOO_SRC - had);
      for (int32_t i = 0; i < more; ++i) { e->src_seq[e->src_count++] = m->reg_producer[read_slot[had + i]]; }
    }
    for (int32_t i = 0; i < x->st_read_count && e->src_count < AXIS_SIM_OOO_SRC; ++i) {
      e->src_seq[e->src_count++] = m->reg_producer[AXIS_SIM_REG_SLOTS + x->st_read[i]];
    }
    if (zero) { e->src_count = 0; }
    for (int32_t i = 0; i < want; ++i) {
      e->dst_pool[e->dst_count] = want_pool[i];
      e->dst_slot[e->dst_count++] = want_slot[i];
      if (want_pool[i] >= 0) { m->rename_used[want_pool[i]]++; }
      m->reg_producer[want_slot[i]] = e->seq;
    }
    /* ⚠️ A LOAD'S VALUE, PREDICTED (S4), execution-driven. The value goes in
       the window as if the load had computed it, and nothing waits for the
       load; when the load runs it says whether that was true. */
    if (m->vp_entries && entry && is_load && !is_store && want == 1 && want_slot[0] < AXIS_SIM_REG_SLOTS) {
      uint64_t said = 0;
      if (axis_vp_predict(m, f->pc, &said)) {
        e->vp = 1;
        e->x_vp = 1;
        e->x_vp_val = said;
        e->x_wslot[0] = want_slot[0];
        e->x_wval[0] = said;
        e->x_wcount = 1;
      }
    }
    m->rob_tail++;
    m->renamed_this_cycle += (uint32_t)renames;
    m->fz_seq = (elim || rides || is_load || is_store || f->bad) ? AXIS_SIM_NO_SEQ : e->seq;
    m->fz_at = m->now;
    m->fz_entry = entry;
    if (rides) { m->x_rides[0]++; }
    else if (fuse || absorb) { d--; }
    else if (m->grp) { m->grp->dispatched++; axis_grp_pay(m->grp, 0, m->x_warp, f->fetched, f->pc); }
    if (elim) { m->elim_waiting++; } else { m->x_waiting++; }
    m->x_loads += (uint32_t)is_load;
    m->x_stores += (uint32_t)is_store;
    m->x_buf_head = (m->x_buf_head + 1u) % AXIS_SIM_XBUF;
    m->x_buf_count--;
  }
}

/* ---- execute: the generated executor, on what the window has made ----- */
/* ⚠️ WHOSE ACCESS (U1). A cracked instruction is executed once for each of
   its micro-ops, whole, on what the window has made by then -- and each
   keeps only its own part. An access is the micro-op's if it is one the
   description gave it: only that micro-op touches the cache, is charged the
   miss, and records the load or holds the store. To the others the access is
   a value and nothing else. Counted as the instruction makes them; an access
   that continues the one before is the same access. */
static int axis_x_owns(axis_pack_machine *m, const axis_sim_rob_entry *e, uint64_t addr, uint32_t bytes) {
  if (e->x_uops < 2) { return 1; }
  if (m->x_ord_any && m->x_ord_end != addr) { m->x_ord++; }
  m->x_ord_any = 1;
  m->x_ord_end = addr + bytes;
  int32_t top = -1;
  for (int32_t a = 0; a < 32; ++a) { if ((e->x_acc_mask >> a) & 1u) { top = a; } }
  return (m->x_ord < 32u && ((e->x_acc_mask >> m->x_ord) & 1u)) || (e->x_acc_rest && (int32_t)m->x_ord > top);
}
static uint64_t axis_x_mem_read(void *ctx, uint64_t addr, uint32_t width) {
  axis_pack_machine *m = (axis_pack_machine *)ctx;
  axis_sim_rob_entry *e = m->x_cur;
  uint32_t bytes = width >= 8u ? width / 8u : 1u;
  int own = axis_x_owns(m, e, addr, bytes);
  /* A load that continues the one before it is the same load (VM1). */
  if (!own) { }
  else if (e->x_lcount > 0 && e->x_lhi[e->x_lcount - 1] == addr) {
    e->x_lhi[e->x_lcount - 1] = addr + bytes;
  } else if (e->x_lcount < (int32_t)AXIS_SIM_OOO_MEM) {
    e->x_llo[e->x_lcount] = addr;
    e->x_lhi[e->x_lcount++] = addr + bytes;
  }
  /* ⚠️ The memory the window sees: committed memory, overlaid -- byte by
     byte, oldest first -- by the stores older in-flight instructions have
     EXECUTED. A store not yet executed is not seen; if it turns out to
     overlap, its execution squashes this load. */
  uint64_t value = m->host.read ? m->host.read(m->host.ctx, addr, width) : 0u;
  /* ... under what this core has retired and not yet written (WM1). */
  if (m->sb_count) { value = axis_sb_overlay(m, addr, width, value); }
  /* Older INSTRUCTIONS: a micro-op's own siblings are the same instruction,
     which sees memory as it was before any of it (U1). */
  for (uint64_t s = m->rob_head; s < e->seq - (uint64_t)e->x_uop; ++s) {
    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!o->valid || !o->x_executed) { continue; }
    for (int32_t w = 0; w < o->x_mcount; ++w) {
      uint32_t wb = o->x_mwidth[w] >= 8u ? o->x_mwidth[w] / 8u : 1u;
      for (uint32_t b = 0; b < bytes && b < 8u; ++b) {
        uint64_t at = addr + b;
        if (at >= o->x_maddr[w] && at < o->x_maddr[w] + wb) {
          uint64_t byte = (o->x_mval[w] >> (8u * (uint32_t)(at - o->x_maddr[w]))) & 0xFFu;
          value = (value & ~(0xFFull << (8u * b))) | (byte << (8u * b));
        }
      }
    }
  }
  /* What it was given, for a load that keeps it (WM2). */
  if (m->loads_any) {
    if (e->x_rcount < AXIS_SIM_KEEP) {
      e->x_raddr[e->x_rcount] = addr;
      e->x_rval[e->x_rcount] = value;
      e->x_rwidth[e->x_rcount] = width;
    }
    e->x_rcount++;
  }
  if (!own) { return value; }
  /* The load's cache access, charged to the load -- and its hit or miss held
     on the instruction, reaching the counters only if it commits. */
  uint64_t stall = m->pending_stall, hits = m->hits, misses = m->misses;
  uint64_t tmiss = m->dtlb_misses, twalk = m->page_walks;
  axis_sim_touch(m, addr, 0);
  m->x_stall += m->pending_stall - stall;
  e->x_dhits += m->hits - hits;
  e->x_dmiss += m->misses - misses;
  e->x_tmiss += (uint32_t)(m->dtlb_misses - tmiss);
  e->x_twalk += (uint32_t)(m->page_walks - twalk);
  m->pending_stall = stall;
  m->hits = hits;
  m->misses = misses;
  m->dtlb_misses = tmiss;
  m->page_walks = twalk;
  return value;
}
static void axis_x_mem_write(void *ctx, uint64_t addr, uint64_t value, uint32_t width) {
  axis_pack_machine *m = (axis_pack_machine *)ctx;
  axis_sim_rob_entry *e = m->x_cur;
  if (!axis_x_owns(m, e, addr, width >= 8u ? width / 8u : 1u)) { return; }
  /* ⚠️ Held in the window until commit: memory changes only when the store
     retires, and a squashed store never changes it at all. */
  axis_x_note_store(e->x_maddr, e->x_mval, e->x_mwidth, &e->x_mcount, addr, value, width);
  /* ⚠️ A store's address is TRANSLATED WHEN IT EXECUTES, though its data
     reaches the cache only when it retires: the walk is this instruction's
     latency, and the lookup is counted if it commits. */
  if (m->core->tlb.data_entries) {
    uint64_t tmiss = m->dtlb_misses, twalk = m->page_walks;
    m->x_stall += axis_tlb_lookup(m, 0, addr);
    e->x_tmiss += (uint32_t)(m->dtlb_misses - tmiss);
    e->x_twalk += (uint32_t)(m->page_walks - twalk);
    m->dtlb_misses = tmiss;
    m->page_walks = twalk;
  }
  if (e->x_mcount > (int32_t)AXIS_SIM_OOO_MEM) {
    e->x_mcount = (int32_t)AXIS_SIM_OOO_MEM;
    e->x_overflow = 1;
  }
}
static void axis_x_squash(axis_pack_machine *m, uint64_t from, int32_t wrong_path);
static uint64_t axis_x_execute(axis_pack_machine *m, axis_sim_rob_entry *e) {
  e->x_executed = 1;
  e->x_rcount = 0;
  /* What was predicted of it is no longer in the window as its result (S4):
     what it computes is. */
  if (e->x_vp) { e->x_wcount = 0; }
  m->x_ord = 0;
  m->x_ord_any = 0;
  if (e->x_bad) { e->x_next = e->pc; return 0; }
  /* The registers and state this instruction sees: what has committed,
     overlaid in program order by what older in-flight instructions have
     computed. A producer the dependence tracking missed is caught at commit. */
  /* ⚠️ THE VIEW IS KEPT, NOT REBUILT. Two copies of the whole register file
     and a slot-by-slot comparison of all of it, on every execute, were a
     quarter of this engine's time. `x_view` is the committed file between
     executes; the window's writes are patched into it, the slots noted, and
     afterwards exactly those slots are put back. */
  if (!m->x_view_ok) {
    memcpy(m->x_view, m->sim.regs, sizeof m->x_view);
    memset(m->x_mark, 0, sizeof m->x_mark);
    m->x_view_ok = 1;
  }
  uint64_t *regs = m->x_view;
  uint32_t noted = 0;
  /* Only the state slots this machine has: the executor is told the count. */
  axis_state64_entry st[64];
  int32_t state_n = m->state_count < 64 ? m->state_count : 64;
  memcpy(st, m->state, (size_t)state_n * sizeof st[0]);
  /* ⚠️ Older INSTRUCTIONS, not older entries (U1): a micro-op executes its
     whole instruction, on the registers as they were before it. A sibling's
     result laid over them -- a base already moved on -- would be the
     instruction reading its own output. */
  for (uint64_t s = m->rob_head; s < e->seq - (uint64_t)e->x_uop; ++s) {
    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    /* What it computed -- or, for a load not yet run, what it was predicted
       to read (S4). */
    if (!o->valid || !(o->x_executed || o->vp)) { continue; }
    for (int32_t w = 0; w < o->x_wcount; ++w) {
      uint32_t slot = o->x_wslot[w];
      if (!m->x_mark[slot]) { m->x_mark[slot] = 1; m->x_list[noted++] = slot; }
      regs[slot] = o->x_wval[w];
      m->x_patch[slot] = o->x_wval[w];
    }
    for (int32_t w = 0; w < o->x_scount; ++w) { st[o->x_sidx[w]].value = o->x_sval[w]; }
  }
  uint64_t state_before[64];
  for (int32_t i = 0; i < state_n; ++i) { state_before[i] = st[i].value; }
  axis_mem64 mem;
  memset(&mem, 0, sizeof mem);
  mem.read = axis_x_mem_read;
  mem.write = axis_x_mem_write;
  mem.ctx = m;
  axis_state64 state = { st, (size_t)m->state_count };
  m->x_cur = e;
  m->x_stall = 0;
  int lanes = 0;
  const axis_lift_entry *first = axis_sim_exec_decode(&m->sim, e->x_word, &lanes);
  axis_exec_result64 r = axis_exec_step64_decoded(first, lanes, e->x_word, axis_sim_word_isa(&m->sim, e->x_word), regs, AXIS_SIM_REG_SLOTS, &mem, e->pc, &state);
  m->x_cur = 0;
  /* ⚠️ WHAT IT WROTE: every register it DECLARES as written, and the one the
     executor reports, whether or not the value changed -- and then anything
     else that changed. Diffing alone missed a write of the value the
     register already held in the window: an older copy of the same load had
     put it there, a writer in between had not yet executed, and the write
     that should have overruled that writer was never recorded. */
#define AXIS_X_DECLARE(slot_) do { uint32_t s_ = (slot_); \
    if (!m->x_mark[s_]) { m->x_list[noted++] = s_; } m->x_mark[s_] |= 2u; } while (0)
  for (int32_t d = 0; d < e->dst_count; ++d) { if (e->dst_slot[d] < AXIS_SIM_REG_SLOTS) { AXIS_X_DECLARE(e->dst_slot[d]); } }
  /* ⚠️ EVERY LIMB of a register it writes (A64-1). A 128-bit destination is
     two slots, and a zeroing 64-bit write to it clears the second: a write of
     the value the window already showed there is a write all the same, and
     unrecorded it let an older in-flight write to the same register win at
     commit. The destination slots above name only where a register starts. */
  if (e->x_lifted.entry) {
    const axis_lift_entry *entry = e->x_lifted.entry;
    const axis_x_meta *xm = axis_x_meta_of(m, entry);
    for (int32_t o = 0; o < entry->operand_count && o < AXIS_LIFT_MAX_OPERANDS; ++o) {
      if (!xm->op_out[o]) { continue; }
      uint32_t slot = axis_x_operand_slot(xm, entry, &e->x_lifted, o);
      uint32_t limbs = entry->operands[o].view_width ? 1u : xm->op_class[o]->limbs;
      for (uint32_t k = 0; k < limbs && slot + k < AXIS_SIM_REG_SLOTS; ++k) { AXIS_X_DECLARE(slot + k); }
    }
  }
  if (r.ok && r.wrote && r.dest_slot < AXIS_SIM_REG_SLOTS) { AXIS_X_DECLARE(r.dest_slot); }
#undef AXIS_X_DECLARE
  /* A slot it declares, or one whose value is no longer what the window had
     put there, is a write; and every slot noted goes back to what has
     committed. */
  for (uint32_t i = 0; i < noted; ++i) {
    uint32_t slot = m->x_list[i];
    if ((m->x_mark[slot] & 2u) || regs[slot] != m->x_patch[slot]) {
      if (e->x_wcount < (int32_t)AXIS_SIM_X_WRITES) {
        e->x_wslot[e->x_wcount] = slot;
        e->x_wval[e->x_wcount++] = regs[slot];
      } else { e->x_overflow = 1; }
    }
    regs[slot] = m->sim.regs[slot];
    m->x_mark[slot] = 0;
  }
  /* ⚠️ AND ANYTHING ELSE THAT CHANGED -- the net under all of the above, for
     a write no operand declares. One comparison of the whole file, which is
     the committed file again unless something did; only then is it searched. */
  if (memcmp(regs, m->sim.regs, sizeof m->x_view)) {
    for (uint32_t i = 0; i < AXIS_SIM_REG_SLOTS; ++i) {
      if (regs[i] == m->sim.regs[i]) { continue; }
      if (e->x_wcount < (int32_t)AXIS_SIM_X_WRITES) {
        e->x_wslot[e->x_wcount] = i;
        e->x_wval[e->x_wcount++] = regs[i];
      } else { e->x_overflow = 1; }
      regs[i] = m->sim.regs[i];
    }
  }
  for (int32_t i = 0; i < m->state_count && i < 64; ++i) {
    int named = r.ok && r.state_name && st[i].name && !strcmp(r.state_name, st[i].name);
    if (named || st[i].value != state_before[i]) {
      if (e->x_scount < 4) { e->x_sidx[e->x_scount] = (uint32_t)i; e->x_sval[e->x_scount++] = st[i].value; }
      else { e->x_overflow = 1; }
    }
  }
  e->x_next = r.ok ? r.next_pc : e->pc;
  e->x_trapped = r.trapped;
  /* ⚠️ ONLY ITS OWN PART (U1). The instruction was executed whole; a
     micro-op keeps the registers the description gave it. The last keeps
     what none of the others was given -- state, a fixed register, anything
     the diff found -- and is the one with a next pc and a trap. */
  if (e->x_uops > 1) {
    int32_t last = e->x_uop + 1 == e->x_uops;
    int32_t kept = 0;
    for (int32_t w = 0; w < e->x_wcount; ++w) {
      uint32_t slot = e->x_wslot[w];
      int32_t mine = 0;
      for (int32_t d = 0; d < e->dst_count && !mine; ++d) { mine = e->dst_slot[d] == slot; }
      if (!mine && last) {
        int32_t theirs = 0;
        for (int32_t v = 0; v + 1 < e->x_uops && !theirs; ++v) {
          const axis_sim_rob_entry *o = &m->rob[(e->seq - (uint64_t)e->x_uop + (uint64_t)v) % AXIS_SIM_ROB_MAX];
          for (int32_t d = 0; d < o->dst_count && !theirs; ++d) { theirs = o->dst_slot[d] == slot; }
        }
        mine = !theirs;
      }
      if (mine) { e->x_wslot[kept] = slot; e->x_wval[kept++] = e->x_wval[w]; }
    }
    e->x_wcount = kept;
    if (!last) { e->x_scount = 0; e->x_next = e->x_pred_next; e->x_trapped = 0; }
  }
  /* ⚠️ THE LOAD SAYS WHAT IT READ (S4). If that is not what was predicted,
     everything after it ran on a value that was never there: squashed, and
     fetched again. Counted when the load retires, like everything here. */
  if (e->x_vp) {
    uint64_t read = e->x_vp_val;
    for (int32_t w = 0; w < e->x_wcount; ++w) { if (e->x_wslot[w] == e->dst_slot[0]) { read = e->x_wval[w]; } }
    e->vp = 0;
    if (read != e->x_vp_val) {
      e->x_vp_bad = 1;
      axis_x_squash(m, e->seq + 1u, 0);
      m->x_fetch_pc = e->x_next;
      m->x_fetch_stopped = 0;
      m->x_fetch_resume = m->now + 1u + m->core->branch_penalty;
    }
  }
  /* ⚠️ A STORE OVER A YOUNGER LOAD THAT ALREADY READ: the load saw memory
     without this store, so it -- and everything after it -- is squashed and
     fetched again. */
  if (e->x_mcount) {
    for (uint64_t s = e->seq + 1u; s < m->rob_tail; ++s) {
      axis_sim_rob_entry *l = &m->rob[s % AXIS_SIM_ROB_MAX];
      if (!l->valid || !l->x_executed) { continue; }
      int hit = 0;
      for (int32_t a = 0; a < l->x_lcount && !hit; ++a) {
        for (int32_t w = 0; w < e->x_mcount && !hit; ++w) {
          uint64_t lo = e->x_maddr[w], hi = lo + (e->x_mwidth[w] >= 8u ? e->x_mwidth[w] / 8u : 1u);
          if (l->x_llo[a] < hi && lo < l->x_lhi[a]) { hit = 1; }
        }
      }
      if (hit) {
        m->violations++;
        /* A store-set machine learns the pair, so the next load from there
           waits for the next store from here. */
        if (m->core->lsq && m->core->disambiguation == 3u && m->core->store_sets) {
          uint32_t n = m->core->store_sets < AXIS_SIM_SSIT_MAX ? m->core->store_sets : AXIS_SIM_SSIT_MAX;
          uint32_t li = (uint32_t)((l->pc >> 2) % n), si = (uint32_t)((e->pc >> 2) % n);
          uint32_t set = m->ssit[li] ? m->ssit[li] : (m->ssit[si] ? m->ssit[si] : ++m->next_set);
          m->ssit[li] = set;
          m->ssit[si] = set;
        }
        uint64_t again = l->pc;
        /* From its instruction's first micro-op: an instruction is in the
           window whole or not at all (U1). */
        axis_x_squash(m, s - (uint64_t)l->x_uop, 0);
        m->x_fetch_pc = again;
        m->x_fetch_stopped = 0;
        m->x_fetch_resume = m->now + 1u + m->core->replay;
        break;
      }
    }
  }
  /* ⚠️ A LOAD OVER A YOUNGER LOAD THAT KEPT WHAT IT READ (WM2). Another
     core's store overtook the younger one and it kept the old bytes; this
     one has just read the new. Two loads of the same bytes do not see memory
     go backwards under any model, so the younger is squashed and reads
     again. */
  if (m->loads_any && e->x_lcount) {
    for (uint64_t s = e->seq + 1u; s < m->rob_tail; ++s) {
      axis_sim_rob_entry *l = &m->rob[s % AXIS_SIM_ROB_MAX];
      if (!l->valid || !l->x_executed || !l->x_overtaken) { continue; }
      int hit = 0;
      for (int32_t a = 0; a < l->x_lcount && !hit; ++a) {
        for (int32_t b = 0; b < e->x_lcount && !hit; ++b) { hit = l->x_llo[a] < e->x_lhi[b] && e->x_llo[b] < l->x_lhi[a]; }
      }
      if (!hit) { continue; }
      m->x_snoops++;
      uint64_t again = l->pc;
      axis_x_squash(m, s - (uint64_t)l->x_uop, 0);
      m->x_fetch_pc = again;
      m->x_fetch_stopped = 0;
      m->x_fetch_resume = m->now + 1u;
      break;
    }
  }
  return m->x_stall;
}

/* ---- squash: everything from `from` on leaves the window --------------- */
static void axis_x_squash(axis_pack_machine *m, uint64_t from, int32_t wrong_path) {
  /* ⚠️ The branch history as it was before the first instruction squashed:
     whatever came after it predicted with history it advanced, and that
     history is as wrong as they are. */
  if (axis_x_spec(m)) {
    if (from < m->rob_tail && m->rob[from % AXIS_SIM_ROB_MAX].valid) { m->pred->set_history(m->pred_state, m->rob[from % AXIS_SIM_ROB_MAX].x_hist); }
    else if (m->x_buf_count) { m->pred->set_history(m->pred_state, m->x_buf[m->x_buf_head].hist); }
  }
  m->x_ic_pending = 0;
  m->x_it_pending = 0;
  m->it_have = 0;
  for (uint64_t s = from; s < m->rob_tail; ++s) {
    axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!o->valid) { continue; }
    /* What it had started in a unit that aborts is given back (W4). */
    if (o->issued) { axis_unit_abort(m, o); }
    o->valid = 0;
    if (wrong_path) { m->wrong_path_instructions++; }
    m->x_squashed++;
  }
  if (from < m->rob_tail) { m->rob_tail = from; }
  /* What the fetch buffer held came after, so it goes too. */
  if (wrong_path) { m->wrong_path_instructions += m->x_buf_count; }
  m->x_squashed += m->x_buf_count;
  m->x_buf_count = 0;
  /* The rename map and the physical registers, rebuilt from who is left. */
  for (uint32_t r = 0; r < AXIS_SIM_PRODUCERS; ++r) { m->reg_producer[r] = AXIS_SIM_NO_SEQ; }
  memset(m->rename_used, 0, sizeof m->rename_used);
  m->x_waiting = 0;
  m->elim_waiting = 0;
  m->fuse_live = 0;
  m->fz_seq = AXIS_SIM_NO_SEQ;
  m->x_loads = 0;
  m->x_stores = 0;
  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
    const axis_sim_rob_entry *o = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!o->valid) { continue; }
    m->x_waiting += (o->issued || o->elim) ? 0u : 1u;
    m->elim_waiting += (o->elim && !o->issued) ? 1u : 0u;
    m->fuse_live += o->fused ? 1u : 0u;
    m->x_loads += (uint32_t)o->is_load;
    m->x_stores += (uint32_t)o->is_store;
    for (int32_t d = 0; d < o->dst_count; ++d) {
      m->reg_producer[o->dst_slot[d]] = o->seq;
      if (o->dst_pool[d] >= 0) { m->rename_used[o->dst_pool[d]]++; }
    }
  }
  m->ic_have_line = 0;
  m->it_have = 0;
  axis_tq_reset(m);
  /* What the loop buffer had learned was learned from a path that is gone
     (U2), and the window fetch was in is not where it resumes. */
  m->lb_on = 0;
  m->lb_next = -1;
  m->lb_cand_branch = ~0ull;
  m->lb_run = 0;
  m->lb_clean = 0;
  m->oc_have = 0;
}

/* ---- resolve: a branch that has completed knows where it went ---------- */
static void axis_x_resolve(axis_pack_machine *m) {
  const axis_sim_core *core = m->core;
  for (uint64_t s = m->rob_head; s < m->rob_tail; ++s) {
    axis_sim_rob_entry *e = &m->rob[s % AXIS_SIM_ROB_MAX];
    if (!e->valid || !e->x_executed || e->x_resolved || e->complete > m->now) { continue; }
    e->x_resolved = 1;
    if (e->x_bad || e->x_next == e->x_pred_next) { continue; }
    /* ⚠️ MISPREDICTED: everything after it was fetched down a path the
       program does not take. Gone, and fetch starts again where it went --
       the return stack as it was before this instruction, and this
       instruction's own push or pop redone the right way. */
    /* ⚠️ COUNTED AT COMMIT, like everything else here: a branch on a wrong
       path that mispredicts redirects fetch all the same, but the program
       never had it. */
    e->x_redirected = 1;
    {
      uint32_t bytes = (e->x_lifted.entry && e->x_lifted.entry->bits) ? e->x_lifted.entry->bits / 8u : 4u;
      /* A WRONG TARGET, as distinct from a wrong direction: predicted taken
         and taken, somewhere else. */
      if (e->x_next != e->pc + bytes && e->x_pred_next != e->pc + bytes) { e->x_wrong_target = 1; }
    }
    axis_x_squash(m, s + 1u, 1);
    /* The history as it was before this branch, moved on by what it really
       did. */
    if (axis_x_spec(m)) {
      m->pred->set_history(m->pred_state, e->x_hist);
      if (e->x_conditional) {
        uint32_t bytes = (e->x_lifted.entry && e->x_lifted.entry->bits) ? e->x_lifted.entry->bits / 8u : 4u;
        m->pred->speculate(m->pred_state, e->pc, e->x_next != e->pc + bytes);
      }
    }
    m->ras_top = e->x_ras_top;
    m->ras_count = e->x_ras_count;
    if (e->x_branch && core->ras) {
      int32_t conditional = 1, indirect = 0, is_call = 0, is_return = 0;
      axis_x_classify(axis_x_meta_of(m, e->x_lifted.entry), &e->x_lifted, &conditional, &indirect, &is_call, &is_return);
      if (is_return && m->ras_count) { m->ras_top = (m->ras_top + 63u) % 64u; m->ras_count--; }
      if (is_call) {
        uint32_t depth = core->ras < 64u ? core->ras : 64u;
        uint32_t bytes = e->x_lifted.entry->bits ? e->x_lifted.entry->bits / 8u : 4u;
        m->ras_top = (m->ras_top + 1u) % 64u;
        m->ras_stack[m->ras_top] = e->pc + bytes;
        if (m->ras_count < depth) { m->ras_count++; }
      }
    }
    m->x_fetch_pc = e->x_next;
    m->x_fetch_stopped = 0;
    m->x_fetch_resume = m->now + 1u + core->branch_penalty;
    break;   /* everything younger is gone */
  }
}

/* ⚠️ A MICRO-OP THAT IS NOT THE LAST retires by handing what it computed to
   the next one (U1): its registers, its stores, what it did to the caches.
   Its own first, so the order the instruction did things in is kept. The
   last micro-op then answers to the golden model for all of it. */
static void axis_x_hand_on(axis_pack_machine *m, axis_sim_rob_entry *e) {
  axis_sim_rob_entry *n = &m->rob[(e->seq + 1u) % AXIS_SIM_ROB_MAX];
  uint32_t wslot[AXIS_SIM_X_WRITES];
  uint64_t wval[AXIS_SIM_X_WRITES];
  int32_t wcount = 0;
  for (int32_t pass = 0; pass < 2; ++pass) {
    const axis_sim_rob_entry *from = pass ? n : e;
    for (int32_t w = 0; w < from->x_wcount; ++w) {
      if (wcount < (int32_t)AXIS_SIM_X_WRITES) { wslot[wcount] = from->x_wslot[w]; wval[wcount++] = from->x_wval[w]; }
      else { n->x_overflow = 1; }
    }
  }
  memcpy(n->x_wslot, wslot, sizeof wslot[0] * (size_t)wcount);
  memcpy(n->x_wval, wval, sizeof wval[0] * (size_t)wcount);
  n->x_wcount = wcount;
  uint64_t maddr[AXIS_SIM_OOO_MEM], mval[AXIS_SIM_OOO_MEM];
  uint32_t mwidth[AXIS_SIM_OOO_MEM];
  int32_t mcount = 0;
  for (int32_t pass = 0; pass < 2; ++pass) {
    const axis_sim_rob_entry *from = pass ? n : e;
    for (int32_t w = 0; w < from->x_mcount; ++w) {
      if (mcount < (int32_t)AXIS_SIM_OOO_MEM) {
        maddr[mcount] = from->x_maddr[w]; mval[mcount] = from->x_mval[w]; mwidth[mcount++] = from->x_mwidth[w];
      } else { n->x_overflow = 1; }
    }
  }
  memcpy(n->x_maddr, maddr, sizeof maddr[0] * (size_t)mcount);
  memcpy(n->x_mval, mval, sizeof mval[0] * (size_t)mcount);
  memcpy(n->x_mwidth, mwidth, sizeof mwidth[0] * (size_t)mcount);
  n->x_mcount = mcount;
  n->x_dhits += e->x_dhits;
  n->x_dmiss += e->x_dmiss;
  n->x_tmiss += e->x_tmiss;
  n->x_twalk += e->x_twalk;
  n->x_overflow |= e->x_overflow;
}

/* ---- commit: the golden model steps, and is the judge ------------------ */
static void axis_x_commit_one(axis_pack_machine *m, axis_sim_rob_entry *e) {
  const axis_sim_core *core = m->core;
  /* With the view valid it IS the registers as they were, so nothing is
     copied: what this instruction wrote is laid on it and it is compared
     with what the golden model left. */
  int32_t viewed = m->x_view_ok;
  uint64_t before[AXIS_SIM_REG_SLOTS];
  if (!viewed) { memcpy(before, m->sim.regs, sizeof before); }
  uint64_t state_before[64];
  int32_t state_n = m->state_count < 64 ? m->state_count : 64;
  for (int32_t i = 0; i < state_n; ++i) { state_before[i] = m->state[i].value; }
  uint64_t at = m->sim.pc;
  uint64_t steps = m->sim.steps;
  m->sb_through = !m->sb_entries || axis_sb_ordered(e);
  m->x_keep = e->x_overtaken ? e : 0;
  m->x_keep_at = 0;
  m->x_committing = 1;
  m->x_trap_hit = 0;
  m->x_cw_count = 0;
  axis_sim_status status = axis_sim_step(&m->sim);
  m->x_committing = 0;
  m->x_keep = 0;
  m->x_committed++;
  /* A word that did not decode, or that fetch could not read, halted the
     golden model WITHOUT retiring: nothing happened, so it takes no time. */
  m->x_retired = m->sim.steps != steps;
  if (status != AXIS_SIM_RUNNING) { m->x_halted = 1; }
  /* ⚠️ THE CHECK. What the golden model did, against what the pipeline
     computed when it executed this instruction: every register, every state
     slot, every store, and where it went next. Architecture is the golden
     model's either way -- it is what just stepped -- so a disagreement is
     not a wrong answer. It is a REPLAY: everything younger may have used the
     pipeline's value, so it is squashed and fetched again. */
  int same = !e->x_overflow && at == e->pc && !e->x_bad && m->sim.pc == e->x_next;
  /* What the registers should now be: as they were, with what it wrote --
     made in place, since nothing reads the old file after this. */
  uint64_t *expect = viewed ? m->x_view : before;
  for (int32_t w = 0; w < e->x_wcount; ++w) { expect[e->x_wslot[w]] = e->x_wval[w]; }
  if (memcmp(expect, m->sim.regs, sizeof before)) {
    same = 0;
    /* The view follows the golden model, whatever the pipeline thought. */
    if (viewed) { memcpy(m->x_view, m->sim.regs, sizeof m->x_view); }
  }
  for (int32_t i = 0; same && i < m->state_count && i < 64; ++i) {
    uint64_t want = state_before[i];
    for (int32_t w = 0; w < e->x_scount; ++w) { if ((int32_t)e->x_sidx[w] == i) { want = e->x_sval[w]; } }
    if (m->state[i].value != want) { same = 0; }
  }
  if (same && m->x_cw_count != e->x_mcount) { same = 0; }
  for (int32_t w = 0; same && w < e->x_mcount; ++w) {
    if (m->x_cw_addr[w] != e->x_maddr[w] || m->x_cw_value[w] != e->x_mval[w]
        || m->x_cw_width[w] != e->x_mwidth[w]) { same = 0; }
  }
  /* What it did counts now that it is the program's: its redirect, and what
     it did to the caches. */
  if (e->x_redirected) {
    m->mispredicts++;
    if (e->x_wrong_target) { m->target_mispredicts++; }
    m->front_end_stalls += core->branch_penalty + core->fe_depth;
  }
  m->hits += e->x_dhits;
  m->misses += e->x_dmiss;
  if (e->x_ic_miss) { m->icache_misses++; }
  m->dtlb_misses += e->x_tmiss;
  m->page_walks += e->x_twalk;
  if (e->x_it_miss & 1u) { m->itlb_misses++; }
  if (e->x_it_miss & 2u) { m->page_walks++; }
  /* The store reaches the cache when it retires -- or, from a store buffer,
     when the buffer asks for its line (WM1). */
  for (int32_t w = 0; m->sb_through && w < m->x_cw_count && w < (int32_t)AXIS_SIM_OOO_MEM; ++w) {
    uint64_t stall = m->pending_stall;
    m->tlb_skip = 1;  /* translated when it executed */
    axis_sim_touch(m, m->x_cw_addr[w], 1);
    m->tlb_skip = 0;
    m->pending_stall = stall;
  }
  /* ⚠️ The value predictor learns what a load READ, in program order (S4):
     from the golden model's register, which is what it read whatever the
     pipeline thought. And what came of predicting it counts now. */
  if (m->vp_entries && e->is_load && !e->is_store && e->x_uops < 2 && e->dst_count == 1
      && e->dst_slot[0] < AXIS_SIM_REG_SLOTS && m->x_retired) {
    if (e->x_vp) { if (e->x_vp_bad) { m->value_mispredicts++; } else { m->value_predictions++; } }
    axis_vp_train(m, at, m->sim.regs[e->dst_slot[0]]);
  }
  /* Train what predicted it, in program order, on what really happened. */
  if (e->x_branch && !m->x_halted) {
    uint32_t bytes = (e->x_lifted.entry && e->x_lifted.entry->bits) ? e->x_lifted.entry->bits / 8u : 4u;
    int32_t taken = m->sim.pc != at + bytes;
    if (e->x_conditional && m->pred && m->pred_state) {
      /* ⚠️ Trained with the history it was PREDICTED with: the speculative
         history has moved on by every branch fetched since, and training at
         that index would teach a counter this branch never used. */
      uint64_t now_history = 0;
      int spec = axis_x_spec(m);
      if (spec) { now_history = m->pred->history(m->pred_state); m->pred->set_history(m->pred_state, e->x_hist); }
      (void)m->pred->predict(m->pred_state, at);
      m->pred->update(m->pred_state, at, taken);
      if (spec) { m->pred->set_history(m->pred_state, now_history); }
    }
    if (e->x_conditional) { axis_quick_train(m, at, taken); }
    if (taken) {
      uint32_t n = axis_x_btb_entries(core);
      uint32_t slot = (uint32_t)((at / bytes) % n);
      m->btb_tag[slot] = at + 1u;
      m->btb_target[slot] = m->sim.pc;
    }
  }
  /* ⚠️ EVENTS (U4c). A send that commits sets every machine's event
     register and wakes any asleep; a local one sets this machine's. A wait
     that commits with the register set clears it and goes on; with it clear
     the machine SLEEPS: what it fetched after the wait is squashed -- the
     drain a real core does -- and it fetches nothing until a send. Judged at
     commit, where the golden model has just stepped: what a wait does
     depends on what other machines committed first. */
  const char *const *events = axis_sim_core_events(core);
  const char *mnemonic = e->x_lifted.entry ? e->x_lifted.entry->mnemonic : 0;
  if (events && events[0] && mnemonic && !m->x_halted && m->x_retired) {
    if (!strcmp(mnemonic, events[1])) {
      m->x_event = 1;
      for (int32_t p = 0; p < m->x_peer_count; ++p) {
        axis_pack_machine *q = m->x_peers[p];
        if (q == m) { continue; }
        if (q->x_sleeping) { q->x_sleeping = 0; q->x_fetch_resume = q->now + 1u; }
        else { q->x_event = 1; }
      }
    } else if (events[2] && !strcmp(mnemonic, events[2])) {
      m->x_event = 1;
    } else if (!strcmp(mnemonic, events[0])) {
      if (m->x_event) { m->x_event = 0; }
      else { m->x_sleeping = 1; m->x_sleeps++; m->x_flush = 1; }
    }
  }
  /* ⚠️ A TRAP IS PRECISE: it is taken when the instruction commits, and
     whatever was fetched after it went where the pipeline guessed, not where
     the trap handler sends the machine. That is a flush, and it is not a
     replay -- the pipeline computed nothing wrong. */
  if (m->x_trap_hit) {
    m->x_traps++;
    if (!same && !m->x_halted) { m->x_flush = 1; }
  } else if (!same && !m->x_halted) { m->x_replays++; m->x_flush = 1; }
}
/* After a commit that disagreed: everything younger goes, and fetch starts
   again where the golden model now is. */
static void axis_x_after_commit(axis_pack_machine *m) {
  if (!m->x_flush) { return; }
  m->x_flush = 0;
  axis_x_squash(m, m->rob_head, 0);
  m->x_fetch_pc = m->sim.pc;
  m->x_fetch_stopped = 0;
  m->x_fetch_resume = m->now + 1u;
}

static void axis_x_start(axis_pack_machine *m) {
  if (m->x_started) { return; }
    m->x_started = 1;
    m->x_view_ok = 0;
    /* A fresh run starts with an empty window: nothing fetched for another
       pc may commit into this one. */
    m->rob_tail = m->rob_head;
    for (uint32_t r = 0; r < AXIS_SIM_PRODUCERS; ++r) { m->reg_producer[r] = AXIS_SIM_NO_SEQ; }
    memset(m->rename_used, 0, sizeof m->rename_used);
    m->x_halted = 0;
    m->x_waiting = 0;
  m->elim_waiting = 0;
  m->fuse_live = 0;
  m->fz_seq = AXIS_SIM_NO_SEQ;
    m->x_loads = 0;
    m->x_stores = 0;
    m->x_fetch_pc = m->sim.pc;
    m->x_fetch_resume = 0;
    m->x_fetch_stopped = 0;
    m->x_buf_count = 0;
}

/* ---- one cycle, and one committed instruction ------------------------- */
static void axis_x_cycle(axis_pack_machine *m) {
  axis_sb_cycle(m);
  /* DISPATCH BEFORE FETCH: a fetch-buffer slot dispatch frees this cycle is
     one fetch may fill this cycle -- which is what the trace-driven front end
     lets a fetch do, and fetching first made every refill a cycle late. With
     no depth, an instruction fetched this cycle may also dispatch in it. */
  axis_x_dispatch(m);
  axis_x_fetch(m);
  if (!m->core->fe_depth) { axis_x_dispatch(m); }
  axis_ooo_tick(m);
}
static int32_t axis_x_step(axis_pack_machine *m) {
  axis_x_start(m);
  if (m->sim.status != AXIS_SIM_RUNNING) { return (int32_t)m->sim.status; }
  uint64_t target = m->x_committed + 1u;
  uint64_t guard = 0;
  while (m->x_committed < target && !m->x_halted) {
    axis_x_cycle(m);
    /* ⚠️ A machine that commits nothing for this long is stuck, and saying
       so beats spinning: a halt with a reason, never a silent hang. */
    if (++guard > 100000u) {
      m->sim.status = AXIS_SIM_HALTED;
      m->sim.halt_reason = "execution-driven pipeline committed nothing";
      break;
    }
  }
  if (m->x_halted || m->sim.status != AXIS_SIM_RUNNING) { axis_sb_flush(m); }
  return (int32_t)m->sim.status;
}

/* ---- several cores, one memory (MC1) ------------------------------------ */
/* ⚠️ A STORE THAT COMMITS IS A SNOOP. The cores beside this one share its
   memory through the host; a load one of them has executed and not yet
   committed, over bytes this store just wrote, read them before the write --
   and is squashed, with everything after it, and fetched again, as a core
   that watches its peers' invalidations squashes a load it ran early. Without
   it the golden model would catch the stale value at the load's commit and
   call it a replay; with it, a replay is what it always was, the pipeline's
   own error. */
/* ⚠️ AND A STORE CLEARS THE OTHERS' MONITORS (U4c). A store-exclusive
   succeeds on its own core's monitor, and no instruction's semantics clears
   another core's: that is what the memory system does when the line is
   written. Without it, two contexts each read the old value, each passed its
   own monitor, and dot's reduction lost an update. Cleared in the golden
   model, which judges the commit: a store-exclusive the window has already
   run on the stale monitor disagrees there and is replayed -- right, and
   counted. Only a core that names its monitor `(exclusive ...)` has one. */
static void axis_x_clear_monitor(axis_pack_machine *q, uint64_t lo, uint64_t hi) {
  if (!q->core) { return; }
  const char *const *names = axis_sim_core_exclusive(q->core);
  if (!names || !names[0]) { return; }
  axis_state64_entry *at = 0, *size = 0, *valid = 0;
  for (int32_t i = 0; i < q->state_count; ++i) {
    if (!strcmp(q->state[i].name, names[0])) { at = &q->state[i]; }
    else if (!strcmp(q->state[i].name, names[1])) { size = &q->state[i]; }
    else if (!strcmp(q->state[i].name, names[2])) { valid = &q->state[i]; }
  }
  if (!at || !size || !valid || !valid->value) { return; }
  uint64_t bytes = size->value ? size->value : 1u;
  if (at->value < hi && lo < at->value + bytes) { valid->value = 0; q->x_monitors_cleared++; }
}
/* ⚠️ WHETHER AN OVERTAKEN LOAD KEEPS WHAT IT READ (WM2). On a core whose
   loads are seen in any order it does -- the relaxed models let a load be
   satisfied before an older load of other bytes -- unless something that
   orders memory is at or before it in the window: a barrier it has not yet
   retired past, an atomic or exclusive access, an acquire or a release. An
   older load of the SAME bytes that has not yet read is caught when it does
   (`axis_x_execute`). A load of more reads than are remembered, one that
   also stores, a micro-op and a predicted value are not kept.
   ⚠️ TOTAL STORE ORDER'S (`(load-order tso)`, WM6): a core's loads are seen
   in its program's order, so a load is kept only when every older load in
   the window has read. Then it is as if it had read after the last of them
   and before the store: nothing wrote its bytes in between. */
static int axis_x_keeps(axis_pack_machine *q, uint64_t s, const axis_sim_rob_entry *l) {
  if (!q->loads_any || l->x_rcount <= 0 || l->x_rcount > AXIS_SIM_KEEP) { return 0; }
  if (l->x_uops > 1 || l->x_mcount || l->x_vp) { return 0; }
  for (uint64_t o = q->rob_head; o <= s; ++o) {
    axis_sim_rob_entry *before = &q->rob[o % AXIS_SIM_ROB_MAX];
    if (!before->valid) { continue; }
    if (axis_sb_ordered(before)) { return 0; }
    if (q->loads_any == 2 && o < s && before->is_load && !before->x_executed) { return 0; }
  }
  return 1;
}
static void axis_x_snoop(axis_pack_machine *m, uint64_t addr, uint32_t width) {
  uint64_t lo = addr, hi = addr + (width >= 8u ? width / 8u : 1u);
  for (int32_t p = 0; p < m->x_peer_count; ++p) {
    axis_pack_machine *q = m->x_peers[p];
    if (q == m || !q->x_started) { continue; }
    for (uint64_t s = q->rob_head; s < q->rob_tail; ++s) {
      axis_sim_rob_entry *l = &q->rob[s % AXIS_SIM_ROB_MAX];
      if (!l->valid || !l->x_executed) { continue; }
      int hit = 0;
      for (int32_t a = 0; a < l->x_lcount && !hit; ++a) { hit = l->x_llo[a] < hi && lo < l->x_lhi[a]; }
      if (!hit) { continue; }
      if (axis_x_keeps(q, s, l)) { l->x_overtaken = 1; continue; }
      q->x_snoops++;
      uint64_t again = l->pc;
      axis_x_squash(q, s, 0);
      q->x_fetch_pc = again;
      q->x_fetch_stopped = 0;
      q->x_fetch_resume = q->now + 1u;
      break;
    }
    axis_x_clear_monitor(q, lo, hi);
  }
}
/* ⚠️ LOCKSTEP. Every running core advances one cycle, in the order the
   host listed them, before any advances another: core 0's commits this cycle
   are visible to core 1 in the same cycle, core 1's to core 0 the next. Each
   core's memory order is its commit order, and every store is visible to
   every core the moment it commits -- so what the cores see together is one
   interleaving of their commits: sequential consistency, by construction,
   with each core's golden model still the judge of that core. */
#define AXIS_SIM_MAX_CORES 64
/* ⚠️ EVERY RUNNING MACHINE ASLEEP is the end: only a send wakes one, and no
   machine that could send is running. Each is halted, saying so, rather
   than left spinning a clock no instruction will ever move. */
static int axis_x_all_asleep(axis_pack_machine **ms, int32_t count) {
  int32_t awake = 0, asleep = 0;
  for (int32_t i = 0; i < count; ++i) {
    if (ms[i]->sim.status != AXIS_SIM_RUNNING || ms[i]->x_halted) { continue; }
    if (ms[i]->x_sleeping) { asleep++; } else { awake++; }
  }
  if (awake || !asleep) { return 0; }
  for (int32_t i = 0; i < count; ++i) {
    if (ms[i]->sim.status != AXIS_SIM_RUNNING || ms[i]->x_halted) { continue; }
    ms[i]->sim.status = AXIS_SIM_HALTED;
    ms[i]->sim.halt_reason = "asleep: every machine waits for an event and none is left to send one";
  }
  return 1;
}
static int32_t axis_sim_run_cores(void **machines, int32_t count, uint64_t limit) {
  if (!machines || count <= 0 || count > AXIS_SIM_MAX_CORES) { return -1; }
  axis_pack_machine *ms[AXIS_SIM_MAX_CORES];
  for (int32_t i = 0; i < count; ++i) {
    ms[i] = (axis_pack_machine *)machines[i];
    /* Only execution-driven cores run together: a trace-driven one has
       already run its program before its pipeline sees it, so there is no
       moment at which another core could change what it read. */
    if (!ms[i] || !ms[i]->counting || !ms[i]->core || !ms[i]->core->execute_driven
        || (ms[i]->model && ms[i]->model_state)) { return -1; }
    for (int32_t j = 0; j < i; ++j) { if (ms[j] == ms[i]) { return -1; } }
  }
  for (int32_t i = 0; i < count; ++i) {
    ms[i]->x_peers = ms;
    ms[i]->x_peer_count = count;
    ms[i]->x_idle = 0;
    ms[i]->x_limit = limit;
    axis_x_start(ms[i]);
  }
  for (;;) {
    int running = 0;
    for (int32_t i = 0; i < count; ++i) {
      axis_pack_machine *m = ms[i];
      if (m->sim.status != AXIS_SIM_RUNNING || m->x_halted) {
        /* A core that has stopped still writes what it retired (WM1), a
           cycle at a time: the cores beside it are still looking. */
        if (m->sb_count) { axis_sb_cycle(m); axis_sb_late(m); m->now++; running = 1; }
        continue;
      }
      if (limit && m->sim.steps >= limit) {
        m->sim.status = AXIS_SIM_STEP_LIMIT;
        m->sim.halt_reason = "step limit";
        running = 1;
        continue;
      }
      running = 1;
      uint64_t committed = m->x_committed;
      axis_x_cycle(m);
      m->x_idle = (m->x_committed == committed && !m->x_sleeping) ? m->x_idle + 1u : 0u;
      if (m->x_idle > 100000u) {
        m->sim.status = AXIS_SIM_HALTED;
        m->sim.halt_reason = "execution-driven pipeline committed nothing";
      }
    }
    if (!running) { break; }
    if (axis_x_all_asleep(ms, count)) { break; }
  }
  for (int32_t i = 0; i < count; ++i) { ms[i]->x_peers = 0; ms[i]->x_peer_count = 0; ms[i]->x_limit = 0; }
  return 0;
}
/* ⚠️ ONE CYCLE AT A TIME (U3). The same lockstep as `run_cores`, for a
   bounded number of cycles, leaving every machine where it stands -- so a
   host can step machines of another library (SIMT cores) on the same clock
   between calls, all of them ports of one memory system. A machine starts
   on its first call and resumes on the next; a halted one is skipped. */
static int32_t axis_sim_cycle_cores(void **machines, int32_t count, uint64_t cycles) {
  if (!machines || count <= 0 || count > AXIS_SIM_MAX_CORES) { return -1; }
  axis_pack_machine *ms[AXIS_SIM_MAX_CORES];
  for (int32_t i = 0; i < count; ++i) {
    ms[i] = (axis_pack_machine *)machines[i];
    if (!ms[i] || !ms[i]->counting || !ms[i]->core || !ms[i]->core->execute_driven
        || (ms[i]->model && ms[i]->model_state)) { return -1; }
    for (int32_t j = 0; j < i; ++j) { if (ms[j] == ms[i]) { return -1; } }
  }
  for (int32_t i = 0; i < count; ++i) {
    ms[i]->x_peers = ms;
    ms[i]->x_peer_count = count;
    if (!ms[i]->x_started) { ms[i]->x_idle = 0; }
    axis_x_start(ms[i]);
  }
  int32_t running = 0;
  for (uint64_t c = 0; c < cycles; ++c) {
    running = 0;
    /* Contexts of one core contend for its issue each cycle: whoever goes
       first takes it, so the first place rotates (U4a).

       ⚠️ PER CORE, NOT PER CALL. Rotating only over everything passed let a
       third machine decide which context of a core went first: with
       contexts p, q and an unrelated y the orders were pqy, qyp, ypq, and p
       led q two cycles in three -- about two thirds of their core's issue on
       a contended unit (found by the session building shared units). The
       call-wide rotation still decides which core goes first; then each
       group's places, wherever they fall, go to its members by the group's
       own rotation, so each context leads its core one cycle in n. */
    int32_t first = (int32_t)(ms[0]->now % (uint64_t)count);
    axis_pack_machine *order[AXIS_SIM_MAX_CORES];
    for (int32_t k = 0; k < count; ++k) { order[k] = ms[(first + k) % count]; }
    for (int32_t k = 0; k < count; ++k) {
      axis_sim_group *g = order[k]->grp;
      if (!g) { continue; }
      int32_t at[AXIS_SIM_MAX_CORES], n = 0;
      axis_pack_machine *who[AXIS_SIM_MAX_CORES];
      for (int32_t j = 0; j < count; ++j) {
        if (order[j]->grp != g) { continue; }
        if (j < k) { n = -1; break; }  /* this group was placed already */
        at[n] = j;
        who[n++] = order[j];
      }
      if (n <= 1) { continue; }
      /* Its members in the order they were passed, then rotated by the
         group's own turn. */
      axis_pack_machine *listed[AXIS_SIM_MAX_CORES];
      int32_t m_count = 0;
      for (int32_t j = 0; j < count; ++j) { if (ms[j]->grp == g) { listed[m_count++] = ms[j]; } }
      int32_t turn = (int32_t)(who[0]->now % (uint64_t)m_count);
      for (int32_t j = 0; j < n; ++j) { order[at[j]] = listed[(turn + j) % m_count]; }
    }
    for (int32_t k = 0; k < count; ++k) {
      axis_pack_machine *m = order[k];
      if (m->sim.status != AXIS_SIM_RUNNING || m->x_halted) {
        /* A core that has stopped still writes what it retired (WM1), a
           cycle at a time: the cores beside it are still looking. */
        if (m->sb_count) { axis_sb_cycle(m); axis_sb_late(m); m->now++; running = 1; }
        continue;
      }
      running++;
      uint64_t committed = m->x_committed;
      axis_x_cycle(m);
      m->x_idle = (m->x_committed == committed && !m->x_sleeping) ? m->x_idle + 1u : 0u;
      if (m->x_idle > 100000u) {
        m->sim.status = AXIS_SIM_HALTED;
        m->sim.halt_reason = "execution-driven pipeline committed nothing";
      }
    }
    if (!running) { break; }
    if (axis_x_all_asleep(ms, count)) { break; }
  }
  running = 0;
  for (int32_t i = 0; i < count; ++i) {
    ms[i]->x_peers = 0;
    ms[i]->x_peer_count = 0;
    running += (ms[i]->sim.status == AXIS_SIM_RUNNING && !ms[i]->x_halted) || ms[i]->sb_count;
  }
  return running;
}
"#;
