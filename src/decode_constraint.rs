//! Operand-dependent instruction decode constraints.
//!
//! Fixed match/mask bits describe most encodings, but some architectures
//! reserve combinations inside otherwise variable operand fields. Frontends
//! parse these rules once into this tree; validators and generators consume
//! the tree rather than reinterpreting source text.

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintValue {
    Literal(u32),
    Operand(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

impl CompareOp {
    pub fn name(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::Lt => "lt",
            Self::Le => "le",
            Self::Gt => "gt",
            Self::Ge => "ge",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeConstraint {
    A64LogicalImmediate {
        width: u32,
        n: ConstraintValue,
        imms: String,
    },
    A64ShiftedRegister {
        width: u32,
        shift: String,
        amount: String,
    },
    A64ExtendedRegister {
        amount: String,
    },
    UnsignedCompare {
        operand: String,
        op: CompareOp,
        literal: u32,
    },
    MaskedEq {
        operand: String,
        mask: u32,
        value: u32,
    },
    And(Vec<DecodeConstraint>),
    Or(Vec<DecodeConstraint>),
    Not(Box<DecodeConstraint>),
}

/// How many values an operand may legally take before the set stops being
/// worth enumerating. A selector has a handful; anything larger is a value,
/// and a value's range is better said as a predicate than as a list.
const LEGAL_VALUE_LIMIT: usize = 64;

impl DecodeConstraint {
    /// The exact set of values this constraint permits `operand` to take, or
    /// `None` when it says nothing about that operand.
    ///
    /// This is the description already stating what a consumer needs twice
    /// over. AArch64's shifted-register `ADD` carries
    /// `a64_shifted_reg(i64, shift, imm6)`, which says `shift < 3` and
    /// `imm6 < 64` -- so the shift kind is one of three (LSL, LSR, ASR and
    /// *not* ROR, which that instruction genuinely cannot encode) and the
    /// amount is a six-bit unsigned. Both facts are already proven, because
    /// the encoder differential runs on the same constraint.
    ///
    /// The set is exact rather than a bound, and that distinction is the point
    /// twice. `a64_extended_reg(amount)` permits `amount < 5`: a `uimm3`
    /// predicate would round that up and accept 5, 6 and 7, which the decoder
    /// rejects. And the extend kind is spelled
    /// `any(uimm_eq(option, 2), uimm_eq(option, 3), uimm_eq(option, 6),
    /// uimm_eq(option, 7))` -- an enumeration with holes, which no bound can
    /// describe without admitting the values between.
    pub fn legal_values(&self, operand: &str) -> Option<Vec<u32>> {
        let values = self.legal_values_inner(operand)?;
        (!values.is_empty() && values.len() <= LEGAL_VALUE_LIMIT).then_some(values)
    }

    fn legal_values_inner(&self, operand: &str) -> Option<Vec<u32>> {
        let range = |limit: u32| Some((0..limit).collect::<Vec<u32>>());
        match self {
            Self::A64ShiftedRegister {
                width,
                shift,
                amount,
            } => {
                // `shift < 3 && amount < width`, which is what this renders to
                // wherever it is consumed.
                if shift == operand {
                    range(3)
                } else if amount == operand {
                    range(*width)
                } else {
                    None
                }
            }
            Self::A64ExtendedRegister { amount } => (amount == operand).then(|| (0..5).collect()),
            Self::UnsignedCompare {
                operand: name,
                op,
                literal,
            } if name == operand => match op {
                CompareOp::Eq => Some(vec![*literal]),
                CompareOp::Lt => range(*literal),
                CompareOp::Le => range(literal.saturating_add(1)),
                // `!=`, `>` and `>=` bound the set from below or punch one hole
                // in it, and neither gives a finite set on its own. A
                // conjunction that also bounds it from above is handled by the
                // intersection below.
                CompareOp::Ne | CompareOp::Gt | CompareOp::Ge => None,
            },
            Self::And(children) => {
                // Every child that speaks about this operand narrows it.
                let mut narrowed: Option<Vec<u32>> = None;
                for child in children {
                    let Some(values) = child.legal_values_inner(operand) else {
                        continue;
                    };
                    narrowed = Some(match narrowed {
                        None => values,
                        Some(seen) => seen
                            .into_iter()
                            .filter(|value| values.contains(value))
                            .collect(),
                    });
                }
                narrowed
            }
            Self::Or(children) => {
                // A disjunction only bounds the operand when *every* branch
                // does. One branch that says nothing lets the whole thing say
                // nothing -- `any(uimm_eq(option, 2), something_else)` permits
                // any option at all.
                let mut union: Vec<u32> = Vec::new();
                for child in children {
                    let values = child.legal_values_inner(operand)?;
                    for value in values {
                        if !union.contains(&value) {
                            union.push(value);
                        }
                    }
                }
                union.sort_unstable();
                Some(union)
            }
            // A negation inverts an unbounded complement, and the remaining
            // forms describe a relation between operands rather than a set.
            _ => None,
        }
    }
}

pub fn parse_decode_constraint(
    source: &str,
    operand_names: &[String],
) -> Result<Option<DecodeConstraint>, String> {
    let source = source.trim();
    if source.is_empty() {
        return Ok(None);
    }
    let operands = operand_names.iter().map(String::as_str).collect();
    parse_constraint(source, &operands).map(Some)
}

fn parse_constraint(source: &str, operands: &HashSet<&str>) -> Result<DecodeConstraint, String> {
    let (name, args) = split_call(source)?;
    let args = split_args(args)?;
    match name {
        "all" | "any" => {
            if args.is_empty() {
                return Err(format!("{name} expects at least one predicate"));
            }
            let children = args
                .iter()
                .map(|argument| parse_constraint(argument, operands))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if name == "all" {
                DecodeConstraint::And(children)
            } else {
                DecodeConstraint::Or(children)
            })
        }
        "not" => {
            require_arity(name, &args, 1, "predicate")?;
            Ok(DecodeConstraint::Not(Box::new(parse_constraint(
                args[0], operands,
            )?)))
        }
        "uimm_eq" | "uimm_ne" | "uimm_lt" | "uimm_le" | "uimm_gt" | "uimm_ge" => {
            require_arity(name, &args, 2, "operand, literal")?;
            require_operand(args[0], operands)?;
            let literal = parse_u32(args[1], "unsigned comparison literal")?;
            let op = match name {
                "uimm_eq" => CompareOp::Eq,
                "uimm_ne" => CompareOp::Ne,
                "uimm_lt" => CompareOp::Lt,
                "uimm_le" => CompareOp::Le,
                "uimm_gt" => CompareOp::Gt,
                "uimm_ge" => CompareOp::Ge,
                _ => unreachable!(),
            };
            Ok(DecodeConstraint::UnsignedCompare {
                operand: args[0].to_string(),
                op,
                literal,
            })
        }
        "uimm_mask_eq" => {
            require_arity(name, &args, 3, "operand, mask, value")?;
            require_operand(args[0], operands)?;
            let mask = parse_u32(args[1], "unsigned mask")?;
            let value = parse_u32(args[2], "masked comparison value")?;
            if value & !mask != 0 {
                return Err(format!(
                    "uimm_mask_eq value {value:#x} has bits outside mask {mask:#x}"
                ));
            }
            Ok(DecodeConstraint::MaskedEq {
                operand: args[0].to_string(),
                mask,
                value,
            })
        }
        "a64_extended_reg" => {
            require_arity(name, &args, 1, "amount")?;
            require_operand(args[0], operands)?;
            Ok(DecodeConstraint::A64ExtendedRegister {
                amount: args[0].to_string(),
            })
        }
        "a64_shifted_reg" => {
            require_arity(name, &args, 3, "i32|i64, shift, amount")?;
            let width = parse_width(name, args[0])?;
            require_operand(args[1], operands)?;
            require_operand(args[2], operands)?;
            Ok(DecodeConstraint::A64ShiftedRegister {
                width,
                shift: args[1].to_string(),
                amount: args[2].to_string(),
            })
        }
        "a64_logical_imm" => {
            require_arity(name, &args, 3, "i32|i64, N, imms")?;
            let width = parse_width(name, args[0])?;
            let n = match parse_u32(args[1], "N literal") {
                Ok(value) if value <= 1 => ConstraintValue::Literal(value),
                Ok(value) => {
                    return Err(format!(
                        "a64_logical_imm N literal {value} must be zero or one"
                    ))
                }
                Err(_) if operands.contains(args[1]) => {
                    ConstraintValue::Operand(args[1].to_string())
                }
                Err(_) => {
                    return Err(format!(
                        "decode_requires references unknown operand `{}`",
                        args[1]
                    ))
                }
            };
            require_operand(args[2], operands)?;
            if width == 32 && n != ConstraintValue::Literal(0) {
                return Err("32-bit a64_logical_imm requires literal N=0".to_string());
            }
            Ok(DecodeConstraint::A64LogicalImmediate {
                width,
                n,
                imms: args[2].to_string(),
            })
        }
        _ => Err(format!("unknown decode_requires predicate `{name}`")),
    }
}

fn split_call(source: &str) -> Result<(&str, &str), String> {
    let Some(open) = source.find('(') else {
        return Err("decode_requires must be a predicate call".to_string());
    };
    let name = source[..open].trim();
    if name.is_empty() {
        return Err("decode_requires predicate name is empty".to_string());
    }
    let Some(body) = source[open + 1..].strip_suffix(')') else {
        return Err("decode_requires predicate is missing `)`".to_string());
    };
    let mut depth = 0u32;
    for character in body.chars() {
        match character {
            '(' => depth += 1,
            ')' if depth == 0 => return Err("decode_requires has an unmatched `)`".to_string()),
            ')' => depth -= 1,
            _ => {}
        }
    }
    if depth != 0 {
        return Err("decode_requires predicate is missing `)`".to_string());
    }
    Ok((name, body))
}

fn split_args(source: &str) -> Result<Vec<&str>, String> {
    if source.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut args = Vec::new();
    let mut depth = 0u32;
    let mut start = 0;
    for (index, character) in source.char_indices() {
        match character {
            '(' => depth += 1,
            ')' if depth == 0 => return Err("decode_requires has an unmatched `)`".to_string()),
            ')' => depth -= 1,
            ',' if depth == 0 => {
                let argument = source[start..index].trim();
                if argument.is_empty() {
                    return Err("decode_requires has an empty argument".to_string());
                }
                args.push(argument);
                start = index + 1;
            }
            _ => {}
        }
    }
    let argument = source[start..].trim();
    if argument.is_empty() {
        return Err("decode_requires has an empty argument".to_string());
    }
    args.push(argument);
    Ok(args)
}

fn require_arity(name: &str, args: &[&str], arity: usize, signature: &str) -> Result<(), String> {
    if args.len() == arity {
        Ok(())
    } else {
        Err(format!("{name} expects ({signature})"))
    }
}

fn require_operand(name: &str, operands: &HashSet<&str>) -> Result<(), String> {
    if operands.contains(name) {
        Ok(())
    } else {
        Err(format!(
            "decode_requires references unknown operand `{name}`"
        ))
    }
}

fn parse_width(predicate: &str, source: &str) -> Result<u32, String> {
    match source {
        "i32" => Ok(32),
        "i64" => Ok(64),
        other => Err(format!("{predicate} width `{other}` must be i32 or i64")),
    }
}

fn parse_u32(source: &str, description: &str) -> Result<u32, String> {
    let (digits, radix) = if let Some(digits) = source.strip_prefix("0x") {
        (digits, 16)
    } else if let Some(digits) = source.strip_prefix("0b") {
        (digits, 2)
    } else {
        (source, 10)
    };
    u32::from_str_radix(digits, radix)
        .map_err(|_| format!("{description} `{source}` must be an unsigned 32-bit integer"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn operands() -> Vec<String> {
        ["n", "shift", "amount", "immr", "imms"]
            .map(str::to_string)
            .to_vec()
    }

    #[test]
    fn parses_a64_logical_immediate_constraint() {
        assert_eq!(
            parse_decode_constraint("a64_logical_imm(i64, n, imms)", &operands()).unwrap(),
            Some(DecodeConstraint::A64LogicalImmediate {
                width: 64,
                n: ConstraintValue::Operand("n".to_string()),
                imms: "imms".to_string(),
            })
        );
        assert!(parse_decode_constraint("a64_logical_imm(i32, 0, imms)", &operands()).is_ok());
    }

    #[test]
    fn parses_nested_boolean_and_unsigned_comparisons() {
        assert_eq!(
            parse_decode_constraint(
                "all(uimm_lt(amount, 5), not(uimm_eq(shift, 3)))",
                &operands()
            )
            .unwrap(),
            Some(DecodeConstraint::And(vec![
                DecodeConstraint::UnsignedCompare {
                    operand: "amount".to_string(),
                    op: CompareOp::Lt,
                    literal: 5,
                },
                DecodeConstraint::Not(Box::new(DecodeConstraint::UnsignedCompare {
                    operand: "shift".to_string(),
                    op: CompareOp::Eq,
                    literal: 3,
                })),
            ]))
        );
        assert!(parse_decode_constraint(
            "any(uimm_ge(amount, 0x20), a64_extended_reg(amount))",
            &operands()
        )
        .is_ok());
        assert_eq!(
            parse_decode_constraint("uimm_mask_eq(amount, 1, 0)", &operands()).unwrap(),
            Some(DecodeConstraint::MaskedEq {
                operand: "amount".to_string(),
                mask: 1,
                value: 0,
            })
        );
        assert!(parse_decode_constraint("uimm_mask_eq(amount, 1, 2)", &operands()).is_err());
    }

    #[test]
    fn rejects_invalid_constraint_symbols_widths_and_shapes() {
        assert!(parse_decode_constraint("unknown(i64, n, imms)", &operands()).is_err());
        assert!(parse_decode_constraint("a64_logical_imm(i16, n, imms)", &operands()).is_err());
        assert!(parse_decode_constraint("a64_logical_imm(i32, n, imms)", &operands()).is_err());
        assert!(parse_decode_constraint("a64_logical_imm(i64, n, missing)", &operands()).is_err());
        assert!(parse_decode_constraint("a64_shifted_reg(i32, immr, imms)", &operands()).is_ok());
        assert!(parse_decode_constraint("a64_shifted_reg(i16, immr, imms)", &operands()).is_err());
        assert!(
            parse_decode_constraint("a64_shifted_reg(i64, missing, imms)", &operands()).is_err()
        );
        assert!(parse_decode_constraint("a64_extended_reg(immr)", &operands()).is_ok());
        assert!(parse_decode_constraint("a64_extended_reg(missing)", &operands()).is_err());
        assert!(parse_decode_constraint("a64_extended_reg(immr, imms)", &operands()).is_err());
        assert!(parse_decode_constraint("all()", &operands()).is_err());
        assert!(parse_decode_constraint(
            "not(uimm_lt(amount, 5), uimm_gt(amount, 1))",
            &operands()
        )
        .is_err());
    }

    #[test]
    fn legal_values_reads_the_set_the_constraint_permits() {
        let operands = operands();
        let shifted = parse_decode_constraint("a64_shifted_reg(i64, shift, amount)", &operands)
            .expect("parses")
            .expect("some");
        // LSL, LSR, ASR -- and not ROR, which this instruction cannot encode.
        assert_eq!(shifted.legal_values("shift"), Some(vec![0, 1, 2]));
        assert_eq!(shifted.legal_values("amount").map(|v| v.len()), Some(64));
        assert_eq!(shifted.legal_values("rd"), None);

        // A bound that is not a power of two: rounding it up to `uimm3` would
        // accept 5, 6 and 7, which the decoder rejects.
        let extended = parse_decode_constraint("a64_extended_reg(amount)", &operands)
            .expect("parses")
            .expect("some");
        assert_eq!(extended.legal_values("amount"), Some(vec![0, 1, 2, 3, 4]));

        // An enumeration with holes, which no bound describes.
        let options = parse_decode_constraint(
            "any(uimm_eq(shift, 2), uimm_eq(shift, 3), uimm_eq(shift, 6))",
            &operands,
        )
        .expect("parses")
        .expect("some");
        assert_eq!(options.legal_values("shift"), Some(vec![2, 3, 6]));

        // One branch that says nothing lets the disjunction say nothing.
        let loose = parse_decode_constraint(
            "any(uimm_eq(shift, 2), uimm_lt(amount, 4))",
            &operands,
        )
        .expect("parses")
        .expect("some");
        assert_eq!(loose.legal_values("shift"), None);

        // A conjunction narrows.
        let both = parse_decode_constraint(
            "all(uimm_lt(shift, 8), uimm_lt(shift, 3))",
            &operands,
        )
        .expect("parses")
        .expect("some");
        assert_eq!(both.legal_values("shift"), Some(vec![0, 1, 2]));
    }
}
