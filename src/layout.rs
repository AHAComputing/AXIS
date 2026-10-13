//! Instruction bit-layout resolution.
//!
//! This module derives every encoding-related fact — fixed fields,
//! match/mask values, operand bit placements, encodability — from the
//! instruction's format, replacing the old hardcoded operand-name
//! convention. Formats are either declared in the source (`format` blocks)
//! or one of the RISC-V built-ins (R, R4, I, S, B, U, J).

use crate::ast::{Document, Format, FormatField, Instruction};

/// A format field with a fixed value (from the instruction's `encoding:`
/// list or the flat `opcode`/`func3`/`func7` sugar fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutFixedField {
    pub name: String,
    pub value: u32,
    pub insn_lo: u32,
    pub width: u32,
}

/// A format field bound to a slice of an operand's value: operand bits
/// `op_lo..op_lo+width` live at instruction bits `insn_lo..insn_lo+width`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutOperandField {
    pub operand: String,
    pub op_lo: u32,
    pub insn_lo: u32,
    pub width: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionLayout {
    pub format: String,
    pub bits: u32,
    pub match_value: u32,
    pub mask_value: u32,
    pub fixed_fields: Vec<LayoutFixedField>,
    pub operand_fields: Vec<LayoutOperandField>,
    /// Operand names that no format field binds — visible encoding gaps.
    pub unencoded_operands: Vec<String>,
    /// Format fields that are neither fixed nor operand-bound — their bits
    /// are undetermined, which blocks roundtrip encoding.
    pub unbound_fields: Vec<String>,
}

impl InstructionLayout {
    pub fn is_encodable(&self) -> bool {
        self.unencoded_operands.is_empty() && self.unbound_fields.is_empty()
    }

    /// All bindings for one operand, in format order (scattered operands
    /// have several).
    pub fn operand_bindings(&self, operand: &str) -> Vec<&LayoutOperandField> {
        self.operand_fields
            .iter()
            .filter(|field| field.operand == operand)
            .collect()
    }
}

fn field(name: &str, insn_hi: u32, insn_lo: u32) -> FormatField {
    FormatField {
        name: name.to_string(),
        insn_hi,
        insn_lo,
        op_hi: None,
        op_lo: None,
    }
}

fn slice(name: &str, op_hi: u32, op_lo: u32, insn_hi: u32, insn_lo: u32) -> FormatField {
    FormatField {
        name: name.to_string(),
        insn_hi,
        insn_lo,
        op_hi: Some(op_hi),
        op_lo: Some(op_lo),
    }
}

fn format(name: &str, fields: Vec<FormatField>) -> Format {
    Format {
        name: name.to_string(),
        bits: 32,
        fields,
    }
}

/// The RISC-V base formats. Note R4 carries `rs3[31:27]` + `func2[26:25]`
/// (the old convention wrongly treated bits 25..31 as a fixed func7 for R4,
/// which made rs3 unencodable).
pub fn builtin_formats() -> Vec<Format> {
    vec![
        format(
            "R",
            vec![
                field("func7", 31, 25),
                field("rs2", 24, 20),
                field("rs1", 19, 15),
                field("func3", 14, 12),
                field("rd", 11, 7),
                field("opcode", 6, 0),
            ],
        ),
        format(
            "R4",
            vec![
                field("rs3", 31, 27),
                field("func2", 26, 25),
                field("rs2", 24, 20),
                field("rs1", 19, 15),
                field("func3", 14, 12),
                field("rd", 11, 7),
                field("opcode", 6, 0),
            ],
        ),
        format(
            "I",
            vec![
                slice("imm", 11, 0, 31, 20),
                field("rs1", 19, 15),
                field("func3", 14, 12),
                field("rd", 11, 7),
                field("opcode", 6, 0),
            ],
        ),
        format(
            "S",
            vec![
                slice("imm", 11, 5, 31, 25),
                field("rs2", 24, 20),
                field("rs1", 19, 15),
                field("func3", 14, 12),
                slice("imm", 4, 0, 11, 7),
                field("opcode", 6, 0),
            ],
        ),
        format(
            "B",
            vec![
                slice("imm", 12, 12, 31, 31),
                slice("imm", 10, 5, 30, 25),
                field("rs2", 24, 20),
                field("rs1", 19, 15),
                field("func3", 14, 12),
                slice("imm", 4, 1, 11, 8),
                slice("imm", 11, 11, 7, 7),
                field("opcode", 6, 0),
            ],
        ),
        format(
            "U",
            vec![
                slice("imm", 31, 12, 31, 12),
                field("rd", 11, 7),
                field("opcode", 6, 0),
            ],
        ),
        format(
            "J",
            vec![
                slice("imm", 20, 20, 31, 31),
                slice("imm", 10, 1, 30, 21),
                slice("imm", 11, 11, 20, 20),
                slice("imm", 19, 12, 19, 12),
                field("rd", 11, 7),
                field("opcode", 6, 0),
            ],
        ),
    ]
}

pub fn find_format(document: &Document, name: &str) -> Option<Format> {
    document
        .formats
        .iter()
        .find(|format| format.name == name)
        .cloned()
        .or_else(|| {
            builtin_formats()
                .into_iter()
                .find(|format| format.name == name)
        })
}

fn width_mask(width: u32) -> u32 {
    if width >= 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    }
}

/// Fixed value for a format field, if the instruction pins one: explicit
/// `encoding:` entries win; the flat `opcode`/`func3`/`func7` fields act as
/// sugar for same-named fields (`func2` draws from `func7` on built-in R4).
fn fixed_field_value(instruction: &Instruction, field_name: &str) -> Option<u32> {
    if let Some((_, value)) = instruction
        .encoding
        .iter()
        .find(|(name, _)| name == field_name)
    {
        return Some(*value);
    }
    match field_name {
        "opcode" => Some(instruction.opcode),
        "func3" => Some(instruction.func3),
        "func7" | "func2" => Some(instruction.func7),
        _ => None,
    }
}

pub fn resolve_layout(
    document: &Document,
    instruction: &Instruction,
) -> Result<InstructionLayout, String> {
    let format = find_format(document, &instruction.format).ok_or_else(|| {
        format!(
            "instruction `{}` references unknown format `{}`",
            instruction.mnemonic, instruction.format
        )
    })?;

    for (name, _) in &instruction.encoding {
        if !format.fields.iter().any(|field| &field.name == name) {
            return Err(format!(
                "instruction `{}` encoding names `{}`, which is not a field of format `{}`",
                instruction.mnemonic, name, format.name
            ));
        }
        if instruction
            .operands
            .iter()
            .any(|operand| &operand.name == name)
        {
            return Err(format!(
                "instruction `{}` encoding fixes `{}`, which is also an operand",
                instruction.mnemonic, name
            ));
        }
    }

    let mut layout = InstructionLayout {
        format: format.name.clone(),
        bits: format.bits,
        match_value: 0,
        mask_value: 0,
        fixed_fields: Vec::new(),
        operand_fields: Vec::new(),
        unencoded_operands: Vec::new(),
        unbound_fields: Vec::new(),
    };

    for format_field in &format.fields {
        let width = format_field.width();
        let is_operand = instruction
            .operands
            .iter()
            .any(|operand| operand.name == format_field.name);
        if is_operand {
            layout.operand_fields.push(LayoutOperandField {
                operand: format_field.name.clone(),
                op_lo: format_field.op_lo.unwrap_or(0),
                insn_lo: format_field.insn_lo,
                width,
            });
        } else if let Some(value) = fixed_field_value(instruction, &format_field.name) {
            let value = value & width_mask(width);
            layout.match_value |= value << format_field.insn_lo;
            layout.mask_value |= width_mask(width) << format_field.insn_lo;
            layout.fixed_fields.push(LayoutFixedField {
                name: format_field.name.clone(),
                value,
                insn_lo: format_field.insn_lo,
                width,
            });
        } else {
            layout.unbound_fields.push(format_field.name.clone());
        }
    }

    for operand in &instruction.operands {
        let bound = layout
            .operand_fields
            .iter()
            .any(|field| field.operand == operand.name);
        if !bound && operand.derived_from.is_empty() && operand.fixed.is_none() {
            layout.unencoded_operands.push(operand.name.clone());
        }
    }

    Ok(layout)
}

/// Validate a declared format: fields in range, instruction bits disjoint,
/// operand slices width-consistent, plain field names unique.
pub fn validate_format_definition(format: &Format) -> Result<(), String> {
    if format.bits == 0 || format.bits > 32 {
        return Err(format!(
            "format `{}` bits must be between 1 and 32",
            format.name
        ));
    }
    if format.fields.is_empty() {
        return Err(format!("format `{}` has no fields", format.name));
    }
    let mut used_bits: u64 = 0;
    let mut plain_names = std::collections::HashSet::new();
    for field in &format.fields {
        if field.insn_hi < field.insn_lo || field.insn_hi >= format.bits {
            return Err(format!(
                "format `{}` field `{}` bit range [{}:{}] is invalid for a {}-bit format",
                format.name, field.name, field.insn_hi, field.insn_lo, format.bits
            ));
        }
        let field_bits = (width_mask(field.width()) as u64) << field.insn_lo;
        if used_bits & field_bits != 0 {
            return Err(format!(
                "format `{}` field `{}` overlaps another field",
                format.name, field.name
            ));
        }
        used_bits |= field_bits;
        match (field.op_hi, field.op_lo) {
            (Some(op_hi), Some(op_lo)) => {
                if op_hi < op_lo {
                    return Err(format!(
                        "format `{}` field `{}` operand slice [{}:{}] is invalid",
                        format.name, field.name, op_hi, op_lo
                    ));
                }
                if op_hi - op_lo + 1 != field.width() {
                    return Err(format!(
                        "format `{}` field `{}` operand slice width {} does not match instruction slice width {}",
                        format.name,
                        field.name,
                        op_hi - op_lo + 1,
                        field.width()
                    ));
                }
            }
            (None, None) => {
                if !plain_names.insert(field.name.clone()) {
                    return Err(format!(
                        "format `{}` repeats plain field `{}`; scattered fields need operand slices (`name[hi:lo]@[hi:lo]`)",
                        format.name, field.name
                    ));
                }
            }
            _ => unreachable!("parser always sets both or neither"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Operand;

    fn operand(name: &str, output: bool) -> Operand {
        Operand {
            name: name.to_string(),
            kind: "reg".to_string(),
            width: 32,
            input: !output,
            output,
            derived_from: String::new(),
            asm_transform: Default::default(),
            derived_add: 0,
            fixed: None,
            lane_register: 0,
            lane_element: 0,
            element: false,
            lane_index: 0,
            lane_packed: false,
                    slot_stride: 0,
                    view_offset: 0,
                    view_width: 0,
                    slot_base: 0,
        }
    }

    fn r_instruction() -> Instruction {
        Instruction {
            mnemonic: "TESTOP".to_string(),
            format: "R".to_string(),
            opcode: 0x0b,
            func3: 0x3,
            func7: 0x04,
            operands: vec![
                operand("rd", true),
                operand("rs1", false),
                operand("rs2", false),
            ],
            ..Instruction::default()
        }
    }

    #[test]
    fn r_format_layout_matches_riscv_convention() {
        let document = Document::default();
        let layout = resolve_layout(&document, &r_instruction()).unwrap();
        assert_eq!(layout.match_value, 0x0b | (0x3 << 12) | (0x04 << 25));
        assert_eq!(layout.mask_value, 0x7f | (0x7 << 12) | (0x7f << 25));
        assert!(layout.is_encodable());
        let rd = &layout.operand_bindings("rd")[0];
        assert_eq!((rd.insn_lo, rd.width, rd.op_lo), (7, 5, 0));
    }

    #[test]
    fn r4_format_encodes_rs3() {
        let mut instruction = r_instruction();
        instruction.format = "R4".to_string();
        instruction.operands.push(operand("rs3", false));
        let layout = resolve_layout(&Document::default(), &instruction).unwrap();
        assert!(layout.is_encodable(), "rs3 must be encodable under R4");
        let rs3 = &layout.operand_bindings("rs3")[0];
        assert_eq!((rs3.insn_lo, rs3.width), (27, 5));
        // func2 draws from func7 sugar, masked to 2 bits.
        assert_eq!(layout.mask_value, 0x7f | (0x7 << 12) | (0x3 << 25));
        assert_eq!(layout.match_value, 0x0b | (0x3 << 12) | (0x0 << 25));
    }

    #[test]
    fn scattered_b_immediate_binds_all_slices() {
        let mut instruction = r_instruction();
        instruction.format = "B".to_string();
        instruction.operands = vec![
            operand("rs1", false),
            operand("rs2", false),
            Operand {
                name: "imm".to_string(),
                kind: "imm".to_string(),
                width: 13,
                input: true,
                output: false,
                derived_from: String::new(),
                asm_transform: Default::default(),
                derived_add: 0,
                fixed: None,
                lane_register: 0,
                lane_element: 0,
                element: false,
                lane_index: 0,
                lane_packed: false,
                    slot_stride: 0,
                    view_offset: 0,
                    view_width: 0,
                    slot_base: 0,
            },
        ];
        let layout = resolve_layout(&Document::default(), &instruction).unwrap();
        assert!(layout.is_encodable());
        let slices = layout.operand_bindings("imm");
        assert_eq!(slices.len(), 4);
        let total: u32 = slices.iter().map(|slice| slice.width).sum();
        assert_eq!(total, 12, "B-type encodes imm[12:1]");
    }

    #[test]
    fn explicit_encoding_overrides_sugar() {
        let mut instruction = r_instruction();
        instruction.format = "R4".to_string();
        instruction.operands.push(operand("rs3", false));
        instruction.encoding = vec![("func2".to_string(), 0x2)];
        let layout = resolve_layout(&Document::default(), &instruction).unwrap();
        assert_eq!(layout.match_value & (0x3 << 25), 0x2 << 25);
    }

    #[test]
    fn unknown_format_is_an_error() {
        let mut instruction = r_instruction();
        instruction.format = "Q".to_string();
        let err = resolve_layout(&Document::default(), &instruction).unwrap_err();
        assert!(err.contains("unknown format `Q`"));
    }

    #[test]
    fn unbound_fields_and_unencoded_operands_are_reported() {
        let mut instruction = r_instruction();
        // rs2 missing from operands -> unbound field; extra operand -> unencoded.
        instruction.operands = vec![
            operand("rd", true),
            operand("rs1", false),
            operand("vec_sel", false),
        ];
        let layout = resolve_layout(&Document::default(), &instruction).unwrap();
        assert_eq!(layout.unbound_fields, vec!["rs2".to_string()]);
        assert_eq!(layout.unencoded_operands, vec!["vec_sel".to_string()]);
        assert!(!layout.is_encodable());
    }
}
