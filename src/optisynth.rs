//! AXIS → OptiSynth semantics normalization (PCE ADL.2 lock-step).
//!
//! PCE's `aha/optisynth/adl_semantics.py` parses `formal_semantics` from
//! `aha_instructions.json` into slice IR, from which `adl_bridge` derives
//! Z3-provable rewrite rules. Its grammar differs from AXIS's semantic IR:
//! strictly binary operators, typed constants (`i32:5`), `icmp_*`/`select`
//! forms, and no rotate/count/extend operators.
//!
//! This module translates AXIS `formal_semantics` into that dialect where
//! expressible:
//! - n-ary `add`/`mul`/`and`/`or`/`xor` fold to nested binary forms
//! - bare integer literals become typed constants at the ambient width
//! - `sll`/`srl`/`sra` map to `shl`/`lshr`/`ashr`
//! - `not x` becomes `(xor iW x iW:-1)`
//! - `min`/`max`/`minu`/`maxu` become `select` over `icmp_slt`/`icmp_ult`
//!
//! Rotates and extends have no *primitive* OptiSynth form, but they are exactly
//! the shift/mask idioms real LLVM IR is written in, so we expand them into the
//! grammar's binary ops — giving PCE a rewrite rule that actually matches
//! incoming IR:
//! - `rol`/`ror` become the canonical shift-or rotate (`(x << s) | (x >>u (W-s))`
//!   with `s = k mod W`), for power-of-two widths
//! - `sext` from `f` bits becomes `ashr(shl(x, W-f), W-f)`
//! - `zext` from `f` bits becomes `and(x, (1<<f)-1)`
//!
//! Bit counts (`clz`/`ctz`/`cpop`) map to the OptiSynth `intr` form —
//! `(intr llvm.ctlz|cttz|ctpop iW x)` — the LLVM intrinsic call the real IR
//! uses. PCE registers Z3 builtin axioms for `llvm.ctlz`/`cttz`/`ctpop`, so
//! these axiomatise and prove (the arity-1, poison-false forms). PCE soundly
//! skips anything we still return `None` for (no rule, no risk).

use crate::ast::Instruction;
use crate::ir::{lower, Op, Sem};
use crate::semantics::parse_formal_semantics;

/// Translate an instruction's `formal_semantics` into the OptiSynth
/// dialect. Returns `None` when the instruction has no formal semantics or
/// uses operators the OptiSynth grammar cannot express.
pub fn optisynth_formal_semantics(instruction: &Instruction) -> Option<String> {
    let source = instruction.formal_semantics.trim();
    if source.is_empty() {
        return None;
    }
    let expr = parse_formal_semantics(source).ok()?;
    let width = instruction
        .operands
        .iter()
        .find(|operand| operand.output)
        .map(|operand| operand.width)
        .unwrap_or(32);
    let sem = lower(&expr, width).ok()?;
    translate(&sem, width)
}

fn opcode_name(op: Op) -> Option<&'static str> {
    Some(match op {
        Op::Add => "add",
        Op::Sub => "sub",
        Op::Mul => "mul",
        Op::And => "and",
        Op::Or => "or",
        Op::Xor => "xor",
        Op::Shl => "shl",
        Op::Lshr => "lshr",
        Op::Ashr => "ashr",
        // Division, rotates, bit counts, and extends have no OptiSynth grammar form.
        _ => return None,
    })
}

fn fold_binary(op: &str, width: u32, args: &[String]) -> String {
    let mut iter = args.iter();
    let first = iter.next().expect("validated arity >= 2").clone();
    iter.fold(first, |acc, arg| format!("({op} i{width} {acc} {arg})"))
}

/// `outer` is the width the whole expression was lowered at -- the
/// instruction's result width, and so the width its operands arrive as. A node
/// narrower than that is the only place a shift amount needs narrowing.
fn translate(sem: &Sem, outer: u32) -> Option<String> {
    match sem {
        // The dialect has no calls: an instruction using a `deffun` is declined.
        Sem::Call { .. } => None,
        Sem::Sym(name) => Some(name.clone()),
        Sem::Int { value, width } => Some(format!("i{width}:{value}")),
        Sem::Ext {
            op,
            width,
            from_bits,
            arg,
        } => {
            let inner = translate(arg, outer)?;
            let width = *width;
            let from_bits = *from_bits;
            if from_bits > width {
                return None;
            }
            match op {
                // Sign-extend `from_bits` bits into `width`: shift the sign bit
                // up to the top, then arithmetic-shift it back down.
                Op::Sext => {
                    let shift = width - from_bits;
                    Some(format!(
                        "(ashr i{width} (shl i{width} {inner} i{width}:{shift}) i{width}:{shift})"
                    ))
                }
                // Zero-extend `from_bits` bits: mask off everything above them.
                Op::Zext => {
                    let mask: u64 = if from_bits >= 64 {
                        u64::MAX
                    } else {
                        (1u64 << from_bits) - 1
                    };
                    Some(format!("(and i{width} {inner} i{width}:{mask})"))
                }
                _ => None,
            }
        }
        Sem::App { op, width, args } => {
            let width = *width;
            let raw_args = args;
            let args = args
                .iter()
                .map(|arg| translate(arg, outer))
                .collect::<Option<Vec<_>>>()?;
            match op {
                Op::Add | Op::Sub | Op::Mul | Op::And | Op::Or | Op::Xor => {
                    Some(fold_binary(opcode_name(*op)?, width, &args))
                }
                // The amount is narrowed here rather than left to the
                // dialect. AXIS reads a shift amount at the node's width;
                // OptiSynth's shift takes the amount as given and answers zero
                // past the width, so at a node width of 8 an amount of 256 is
                // "past the width" there and "no shift at all" here. Emitting
                // the mask makes the exported rule mean the same thing under
                // the dialect's own semantics, which is what an export is for.
                Op::Shl | Op::Lshr | Op::Ashr => {
                    let amount = if width >= outer {
                        args[1].clone()
                    } else {
                        format!(
                            "(and i{width} {} i{width}:{})",
                            args[1],
                            (1u64 << width) - 1
                        )
                    };
                    Some(format!("({} i{width} {} {amount})", opcode_name(*op)?, args[0]))
                }
                Op::Not => Some(format!("(xor i{width} {} i{width}:-1)", args[0])),
                Op::MinS | Op::MaxS | Op::MinU | Op::MaxU => {
                    let signed = matches!(op, Op::MinS | Op::MaxS);
                    let icmp = if signed { "icmp_slt" } else { "icmp_ult" };
                    let invert = matches!(op, Op::MaxS | Op::MaxU);
                    let rendered = rendered_width(&raw_args[0]).max(rendered_width(&raw_args[1]));
                    Some(select_compare(
                        icmp, width, &args[0], &args[1], invert, signed, rendered,
                    ))
                }
                Op::Select => Some(format!(
                    "(select i{width} (icmp_ne i1 {} i{width}:0) {} {})",
                    args[0], args[1], args[2]
                )),
                Op::Rol => rotate_shift_or(width, &args[0], &args[1], true),
                Op::Ror => rotate_shift_or(width, &args[0], &args[1], false),
                // Bit counts map to the LLVM intrinsic call form: PCE registers
                // Z3 builtins for llvm.ctlz/cttz/ctpop, so these axiomatise and
                // prove, and the rule matches the real ctlz/cttz/ctpop IR.
                Op::Clz => Some(format!("(intr llvm.ctlz i{width} {})", args[0])),
                Op::Ctz => Some(format!("(intr llvm.cttz i{width} {})", args[0])),
                Op::Cpop => Some(format!("(intr llvm.ctpop i{width} {})", args[0])),
                _ => None,
            }
        }
    }
}

/// The width an argument is *rendered* at, which is not always the width the
/// operator runs at.
///
/// A lane operator is the case that separates them: `expand_lanes` annotates
/// the operator at the lane width but writes its arguments as slices of the
/// whole register, so `(max i16 (and i64 vn 65535) ...)` is a 16-bit operation
/// over expressions that print as `i64`.
fn rendered_width(sem: &Sem) -> Option<u32> {
    match sem {
        Sem::Sym(_) => None,
        Sem::Int { width, .. } | Sem::App { width, .. } | Sem::Ext { width, .. }
        | Sem::Call { width, .. } => Some(*width),
    }
}

/// `x`, sign-extended from `from_bits` to `width`, in the dialect's own idiom.
///
/// The same `ashr(shl(x, W-f), W-f)` this module already uses for `sext`,
/// because OptiSynth has no extend operator.
fn sign_extend(width: u32, from_bits: u32, x: &str) -> String {
    let shift = width - from_bits;
    format!("(ashr i{width} (shl i{width} {x} i{width}:{shift}) i{width}:{shift})")
}

/// `min`/`max` as a select over a comparison.
///
/// A *signed* comparison reads its operands' top bit, so it has to be given
/// operands whose top bit is the one it should read. A lane arrives here as a
/// masked slice of a wider register -- `(and i64 vn 65535)` -- whose bit 63 is
/// always zero, so comparing it at the rendered width is an unsigned
/// comparison wearing a signed operator's name. It agrees with the golden
/// model on every non-negative lane, which is most random ones.
///
/// The two are separated: the comparison gets sign-extended operands, the
/// select still yields the raw lane bits, because those are what the caller
/// masks and shifts back into place.
fn select_compare(
    icmp: &str,
    width: u32,
    lhs: &str,
    rhs: &str,
    invert: bool,
    signed: bool,
    rendered: Option<u32>,
) -> String {
    let (take, other) = if invert { (rhs, lhs) } else { (lhs, rhs) };
    let (cmp_lhs, cmp_rhs) = match rendered {
        Some(rendered) if signed && rendered > width => (
            sign_extend(rendered, width, lhs),
            sign_extend(rendered, width, rhs),
        ),
        _ => (lhs.to_string(), rhs.to_string()),
    };
    format!("(select i{width} ({icmp} i1 {cmp_lhs} {cmp_rhs}) {take} {other})")
}

/// The canonical shift-or rotate, expressed in the OptiSynth binary grammar.
/// With `s = k & (W-1)` (rotate amount mod W) and `rc = (W - s) & (W-1)` (its
/// complement, folding the `s == 0` case back to a no-op shift), a left rotate
/// is `(x << s) | (x >>u rc)` and a right rotate swaps the two shifts. Both
/// shift amounts stay in `[0, W)`, so every step matches the golden rotate and
/// its Z3 lowering. Only defined for power-of-two widths (where `& (W-1)` is
/// exactly `mod W`); returns `None` otherwise so PCE skips it soundly.
fn rotate_shift_or(width: u32, x: &str, k: &str, left: bool) -> Option<String> {
    if !width.is_power_of_two() {
        return None;
    }
    let mask = width - 1;
    let s = format!("(and i{width} {k} i{width}:{mask})");
    let rc = format!("(and i{width} (sub i{width} i{width}:{width} {s}) i{width}:{mask})");
    let (by_s, by_c) = if left {
        ("shl", "lshr")
    } else {
        ("lshr", "shl")
    };
    Some(format!(
        "(or i{width} ({by_s} i{width} {x} {s}) ({by_c} i{width} {x} {rc}))"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Operand;

    fn instruction(formal: &str) -> Instruction {
        Instruction {
            mnemonic: "T".to_string(),
            formal_semantics: formal.to_string(),
            operands: vec![
                Operand {
                    name: "rd".to_string(),
                    kind: "reg".to_string(),
                    width: 32,
                    input: false,
                    output: true,
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
                Operand {
                    name: "rs1".to_string(),
                    kind: "reg".to_string(),
                    width: 32,
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
                Operand {
                    name: "rs2".to_string(),
                    kind: "reg".to_string(),
                    width: 32,
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
            ],
            ..Instruction::default()
        }
    }

    #[test]
    fn a_signed_compare_reads_the_lane_sign_not_the_registers() {
        // A lane operator runs at the lane width but its arguments are written
        // as slices of the whole register, so a signed comparison would
        // otherwise be handed two values whose top bit is always zero -- an
        // unsigned comparison wearing a signed operator's name. It agrees with
        // the golden model on every non-negative lane, which is most random
        // ones, so only a corpus with a negative-lane witness catches it.
        let inst = instruction("(max i16 (and i32 rs1 0xffff) (and i32 rs2 0xffff))");
        let rendered = optisynth_formal_semantics(&inst).unwrap();
        assert!(
            rendered.contains(
                "(icmp_slt i1 \
                 (ashr i32 (shl i32 (and i32 rs1 i32:65535) i32:16) i32:16) \
                 (ashr i32 (shl i32 (and i32 rs2 i32:65535) i32:16) i32:16))"
            ),
            "the comparison sign-extends each lane first: {rendered}"
        );
        // The select still yields the raw lane bits: those are what the caller
        // masks and shifts back into place.
        assert!(
            rendered.contains(") (and i32 rs2 i32:65535) (and i32 rs1 i32:65535))"),
            "the selected value is the lane, not the extension: {rendered}"
        );

        // Unsigned lane compares must NOT gain it -- zero-extended is what
        // `icmp_ult` wants.
        let unsigned = instruction("(maxu i16 (and i32 rs1 0xffff) (and i32 rs2 0xffff))");
        let rendered = optisynth_formal_semantics(&unsigned).unwrap();
        assert!(
            rendered.contains("(icmp_ult i1 (and i32 rs1 i32:65535) (and i32 rs2 i32:65535))"),
            "an unsigned compare takes the lane as it stands: {rendered}"
        );

        // And a scalar signed compare, whose operands are already the operator's
        // width, is untouched.
        let scalar = instruction("(max i32 rs1 rs2)");
        assert_eq!(
            optisynth_formal_semantics(&scalar).unwrap(),
            "(select i32 (icmp_slt i1 rs1 rs2) rs2 rs1)"
        );
    }

    #[test]
    fn passthrough_binary_forms_are_unchanged() {
        let inst = instruction("(add i32 (mul i32 rs1 rs2) rs1)");
        assert_eq!(
            optisynth_formal_semantics(&inst).unwrap(),
            "(add i32 (mul i32 rs1 rs2) rs1)"
        );
    }

    #[test]
    fn nary_ops_fold_to_binary() {
        let inst = instruction("(add i32 rs1 rs2 rs1)");
        assert_eq!(
            optisynth_formal_semantics(&inst).unwrap(),
            "(add i32 (add i32 rs1 rs2) rs1)"
        );
    }

    #[test]
    fn literals_become_typed_constants() {
        let inst = instruction("(add i32 rs1 5)");
        assert_eq!(
            optisynth_formal_semantics(&inst).unwrap(),
            "(add i32 rs1 i32:5)"
        );
    }

    #[test]
    fn not_becomes_xor_minus_one() {
        let inst = instruction("(and i32 rs1 (not i32 rs2))");
        assert_eq!(
            optisynth_formal_semantics(&inst).unwrap(),
            "(and i32 rs1 (xor i32 rs2 i32:-1))"
        );
    }

    #[test]
    fn min_max_become_select_over_icmp() {
        let min = instruction("(min i32 rs1 rs2)");
        assert_eq!(
            optisynth_formal_semantics(&min).unwrap(),
            "(select i32 (icmp_slt i1 rs1 rs2) rs1 rs2)"
        );
        let maxu = instruction("(maxu i32 rs1 rs2)");
        assert_eq!(
            optisynth_formal_semantics(&maxu).unwrap(),
            "(select i32 (icmp_ult i1 rs1 rs2) rs2 rs1)"
        );
    }

    #[test]
    fn bit_counts_become_llvm_intrinsic_calls() {
        // clz/ctz/cpop map to the intr form -> llvm.ctlz/cttz/ctpop (PCE has Z3
        // builtins for these), so they axiomatise and prove.
        let clz = instruction("(clz i32 rs1)");
        assert_eq!(
            optisynth_formal_semantics(&clz).unwrap(),
            "(intr llvm.ctlz i32 rs1)"
        );
        let ctz = instruction("(ctz i32 rs1)");
        assert_eq!(
            optisynth_formal_semantics(&ctz).unwrap(),
            "(intr llvm.cttz i32 rs1)"
        );
        let cpop = instruction("(cpop i32 rs1)");
        assert_eq!(
            optisynth_formal_semantics(&cpop).unwrap(),
            "(intr llvm.ctpop i32 rs1)"
        );
    }

    #[test]
    fn rotates_become_shift_or() {
        // rol: (x << s) | (x >>u (W - s)), s = k & 31.
        let rol = instruction("(rol i32 rs1 rs2)");
        assert_eq!(
            optisynth_formal_semantics(&rol).unwrap(),
            "(or i32 (shl i32 rs1 (and i32 rs2 i32:31)) \
             (lshr i32 rs1 (and i32 (sub i32 i32:32 (and i32 rs2 i32:31)) i32:31)))"
        );
        // ror swaps the two shift directions.
        let ror = instruction("(ror i32 rs1 rs2)");
        assert_eq!(
            optisynth_formal_semantics(&ror).unwrap(),
            "(or i32 (lshr i32 rs1 (and i32 rs2 i32:31)) \
             (shl i32 rs1 (and i32 (sub i32 i32:32 (and i32 rs2 i32:31)) i32:31)))"
        );
    }

    #[test]
    fn extends_become_shift_and_mask() {
        // sext from 8 bits: ashr(shl(x, 24), 24).
        let sextb = instruction("(sext i32 8 rs1)");
        assert_eq!(
            optisynth_formal_semantics(&sextb).unwrap(),
            "(ashr i32 (shl i32 rs1 i32:24) i32:24)"
        );
        // zext from 16 bits: mask the low 16 bits.
        let zexth = instruction("(zext i32 16 rs1)");
        assert_eq!(
            optisynth_formal_semantics(&zexth).unwrap(),
            "(and i32 rs1 i32:65535)"
        );
    }

    #[test]
    fn shift_aliases_map_to_optisynth_names() {
        let inst = instruction("(sra i32 rs1 rs2)");
        assert_eq!(
            optisynth_formal_semantics(&inst).unwrap(),
            "(ashr i32 rs1 rs2)"
        );
    }
}
