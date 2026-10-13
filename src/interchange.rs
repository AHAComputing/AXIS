//! Interchange float formats, expanded into bit-vector semantics
//! (`docs/tensor_design.md`, stage T1b).
//!
//! An **interchange format** is one a machine stores and converts but does not
//! compute in. `bf16` is the case that matters: every machine in the tensor
//! inventory reads bf16 operands, widens them, and accumulates in f32. With the
//! exception of AArch64's `FEAT_B16B16` there is no bf16 adder anywhere, so a
//! format row with arithmetic behind it would be six backends of machinery for
//! an operation no description performs.
//!
//! ⚠️ And bf16 could not have a row anyway, which is the finding that shaped
//! this stage. The typed IR identifies a float format by its **width** —
//! `Sem::App { op, width, .. }` carries nothing else — and bf16 and f16 are
//! both 16 bits. f16 fitted because 16 was free; the second 16-bit format is
//! where that representation runs out.
//!
//! So bf16 is not a new value domain, exactly as `docs/simd_fp_design.md` §1
//! argued SIMD was not: **bf16 is f32's top half**. Its exponent field is
//! f32's, bit for bit, which makes widening a shift and narrowing an add and a
//! shift, both of them ordinary integer expressions AXIS has had since the
//! beginning. Expanding here — at elaboration, on the surface s-expression,
//! beside the lane expansion and for the same reason — means the typed IR,
//! every backend and every reflective artifact see integer arithmetic and
//! nothing learns that a third 16-bit format exists.
//!
//! What this buys over writing the shift by hand in each description is the
//! rounding. `(x + 0x7fff + ((x >> 16) & 1)) >> 16` is round-to-nearest-even
//! and it is not obvious; written once here it is checked once, by
//! `tools/bf16_check.py`, against rounding computed in exact rational
//! arithmetic rather than against another copy of itself.

use crate::effects::render_semexpr;
use crate::semantics::{parse_formal_semantics, SemanticExpr};

/// The formats this expansion knows, as they are spelled in a conversion.
///
/// `bf16` alone, and the reason the list is not longer is worth stating: the
/// 8-bit formats have five exponent bits (`f8e5m2`) or four (`f8e4m3`) where
/// f32 has eight, so converting one is an exponent rebias plus a subnormal
/// renormalisation — a loop, not a shift. That is describable with `iterate`
/// and it is a different stage (T1c), not a longer table here.
const INTERCHANGE: &[&str] = &["bf16", "f8e4m3", "f8e5m2"];

/// An 8-bit interchange format: exponent bits, mantissa bits, bias, and
/// whether the top exponent is spent on infinities.
///
/// ⚠️ `f8e5m2` is IEEE-shaped and `f8e4m3` is not. OCP's e4m3 spends the
/// all-ones exponent on *finite* values and keeps one pattern for NaN, which
/// is why its largest is 448 where an IEEE format of the same size stops at
/// 240. The difference is one field here and it reaches every arm below.
struct Fp8 {
    name: &'static str,
    exponent: u32,
    mantissa: u32,
    bias: u32,
    infinities: bool,
}

const FP8: &[Fp8] = &[
    Fp8 { name: "f8e4m3", exponent: 4, mantissa: 3, bias: 7, infinities: false },
    Fp8 { name: "f8e5m2", exponent: 5, mantissa: 2, bias: 15, infinities: true },
];

fn fp8(name: &str) -> Option<&'static Fp8> {
    FP8.iter().find(|format| format.name == name)
}

/// Whether an atom names an interchange format.
pub fn is_interchange_format(atom: &str) -> bool {
    INTERCHANGE.contains(&atom)
}

/// Expand every interchange conversion in `text`, or return it unchanged.
pub fn expand_interchange_text(text: &str) -> Result<String, String> {
    if !INTERCHANGE.iter().any(|name| text.contains(name)) && !text.contains("f8") {
        return Ok(text.to_string());
    }
    let expr = parse_formal_semantics(text).map_err(|error| error.message)?;
    Ok(render_semexpr(&expand(&expr)?))
}

fn expand(expr: &SemanticExpr) -> Result<SemanticExpr, String> {
    let SemanticExpr::List(items) = expr else {
        return Ok(expr.clone());
    };
    let expanded: Vec<SemanticExpr> = items
        .iter()
        .map(expand)
        .collect::<Result<Vec<_>, _>>()?;
    // ⚠️ `f8` is refused wherever it appears, and with its own reason. A width
    // does not choose between two eight-bit formats: OCP defines both e4m3 and
    // e5m2, they disagree about infinities and about where their largest
    // finite value sits, and `f8` names neither. The float-format guard would
    // refuse it anyway, with a message about which formats exist; this one
    // says why eight bits in particular cannot be one.
    for item in &expanded {
        if matches!(item, SemanticExpr::Atom(atom) if atom == "f8") {
            return Err(
                "`f8` is not a format: two eight-bit floats are in common use and a \
                 width does not choose between them -- name `f8e4m3` or `f8e5m2`"
                    .to_string(),
            );
        }
    }
    let Some(SemanticExpr::Atom(op)) = expanded.first() else {
        return Ok(SemanticExpr::List(expanded));
    };
    if op != "fcvt_f2f" {
        // An interchange atom anywhere else is a mistake with a clear reading:
        // there is nothing else it could mean, so it is refused rather than
        // passed down to be reported as an unknown symbol.
        for item in &expanded {
            if let SemanticExpr::Atom(atom) = item {
                if is_interchange_format(atom) {
                    return Err(format!(
                        "`{atom}` is an interchange format, so it may only name an end \
                         of `fcvt_f2f`; nothing computes in it"
                    ));
                }
            }
        }
        return Ok(SemanticExpr::List(expanded));
    }
    if expanded.len() != 4 {
        return Ok(SemanticExpr::List(expanded));
    }
    let (SemanticExpr::Atom(destination), SemanticExpr::Atom(source)) =
        (&expanded[1], &expanded[2])
    else {
        return Ok(SemanticExpr::List(expanded));
    };
    let value = render_semexpr(&expanded[3]);
    let narrowing = is_interchange_format(destination);
    let widening = is_interchange_format(source);
    if !narrowing && !widening {
        return Ok(SemanticExpr::List(expanded));
    }
    if narrowing && widening {
        return Err(format!(
            "`fcvt_f2f {destination} {source}` converts between two interchange \
             formats, which no machine does in one step; write it through f32"
        ));
    }
    let expansion = if narrowing {
        if source != "32" && source != "f32" {
            return Err(format!(
                "`fcvt_f2f {destination} {source}` is not described: an interchange \
                 format pairs with f32; convert through f32"
            ));
        }
        match fp8(destination) {
            Some(format) => narrow_to_fp8(&value, format),
            None => narrow_to_bf16(&value),
        }
    } else {
        if destination != "f32" {
            return Err(format!(
                "`fcvt_f2f {destination} {source}` is not described: an interchange \
                 format pairs with f32; convert through f32"
            ));
        }
        match fp8(source) {
            Some(format) => widen_from_fp8(&value, format),
            None => widen_from_bf16(&value),
        }
    };
    parse_formal_semantics(&expansion).map_err(|error| error.message)
}

/// bf16 -> f32: the pattern moves to the top half and the low half is zero.
///
/// ⚠️ The mask is redundant and kept anyway. At `i32` the shift already moves
/// anything above bit 15 past bit 31, where the evaluation width discards it,
/// so removing the mask changes no result -- measured, by injecting exactly
/// that into `tools/bf16_check.py` and watching it pass. It stays because the
/// expression states what a conversion reads, and a reader should not have to
/// re-derive the discard to know the high half is not an input.
///
/// Exact for every input including NaN: bf16's sign, exponent and fraction are
/// f32's sign, exponent and top seven fraction bits, so widening adds zeros
/// and changes nothing. That is the property the whole format is designed for
/// and the reason this direction needs no rounding at all.
fn widen_from_bf16(value: &str) -> String {
    format!("(shl i32 (and i32 {value} 0xffff) 16)")
}

/// f32 -> bf16, round to nearest, ties to even.
///
/// The addend is `0x7fff` plus the low bit of what is kept: adding half of the
/// last kept place rounds to nearest, and biasing that half by the kept bit
/// breaks the tie towards even. A carry out of the fraction lands in the
/// exponent by itself, which is how the largest f32 becomes an infinity rather
/// than wrapping to zero.
///
/// NaN is selected first and answered with AXIS's canonical quiet bf16, since
/// the addition would otherwise be free to turn a NaN into an infinity -- the
/// pattern is `exponent all ones, fraction non-zero`, which is exactly
/// `(x & 0x7fffffff) >= 0x7f800001`.
fn narrow_to_bf16(value: &str) -> String {
    format!(
        "(select i32 (icmp_uge i32 (and i32 {value} 0x7fffffff) 0x7f800001) 0x7fc0 \
         (and i32 (lshr i32 (add i32 (add i32 {value} 0x7fff) \
         (and i32 (lshr i32 {value} 16) 1)) 16) 0xffff))"
    )
}

/// An 8-bit format widened to f32, exactly.
///
/// Every 8-bit pattern has an f32, so this rounds nothing and the only work is
/// putting the fields where f32 keeps them. The one branch that is not a shift
/// is the subnormal one, where the leading bit has to be found -- and with two
/// or three mantissa bits that is a select over two or three positions, not
/// the loop `docs/tensor_design.md` predicted. The prediction generalised from
/// f16's eleven-bit significand, where the same normalisation really does want
/// a loop.
fn widen_from_fp8(value: &str, format: &Fp8) -> String {
    let Fp8 { exponent, mantissa, bias, infinities, .. } = *format;
    let top = (1u32 << exponent) - 1;
    let man_mask = (1u32 << mantissa) - 1;
    let sign = format!("(shl i32 (and i32 {value} 0x80) 24)");
    let exp = format!("(and i32 (lshr i32 {value} {mantissa}) {top})");
    let man = format!("(and i32 {value} {man_mask})");
    // The subnormal's leading bit, as a position: the tests run from the top
    // so the first that holds is the highest bit set.
    let mut position = "0".to_string();
    for bit in 1..mantissa {
        position = format!(
            "(select i32 (icmp_uge i32 {man} {}) {bit} {position})",
            1u32 << bit
        );
    }
    // 1 - bias - mantissa + 127, the f32 exponent field of the smallest
    // subnormal, before the leading bit's position is added back.
    let base = 128 - bias - mantissa;
    let subnormal = format!(
        "(or i32 {sign} (or i32 (shl i32 (add i32 {base} {position}) 23) \
         (shl i32 (and i32 (shl i32 {man} (sub i32 {mantissa} {position})) {man_mask}) {})))",
        23 - mantissa
    );
    let normal = format!(
        "(or i32 {sign} (or i32 (shl i32 (add i32 {exp} {}) 23) (shl i32 {man} {})))",
        127 - bias,
        23 - mantissa
    );
    let zero_exponent = format!("(icmp_eq i32 {exp} 0)");
    let zero = format!("(and i32 {zero_exponent} (icmp_eq i32 {man} 0))");
    let finite = format!(
        "(select i32 {zero} {sign} (select i32 {zero_exponent} {subnormal} {normal}))"
    );
    if infinities {
        // The top exponent is spent: all-zero mantissa is an infinity, and
        // anything else is a NaN, which canonicalises.
        format!(
            "(select i32 (icmp_eq i32 {exp} {top}) \
             (select i32 (icmp_eq i32 {man} 0) (or i32 {sign} 0x7f800000) 0x7fc00000) \
             {finite})"
        )
    } else {
        // The top exponent is finite except for the single all-ones pattern.
        format!(
            "(select i32 (and i32 (icmp_eq i32 {exp} {top}) (icmp_eq i32 {man} {man_mask})) \
             0x7fc00000 {finite})"
        )
    }
}

/// f32 narrowed to an 8-bit format, round to nearest with ties to even, and
/// saturating on overflow.
///
/// ⚠️ The MAGNITUDE is rounded and the sign is put back afterwards. Rounding
/// `sign | magnitude` lets a carry out of the top of an e4m3 magnitude land in
/// the sign bit, which turned 510 into negative zero -- found by the oracle,
/// not by reading.
///
/// Overflow saturates rather than becoming an infinity, which for `e4m3` is
/// the only thing it can do (the format has none) and for `e5m2` is the
/// infinity. Either way the check happens before the exponent field is built,
/// because an exponent past the format has already left the eight bits it was
/// meant to fit in.
fn narrow_to_fp8(value: &str, format: &Fp8) -> String {
    let Fp8 { exponent, mantissa, bias, infinities, .. } = *format;
    let top = (1u32 << exponent) - 1;
    let man_mask = (1u32 << mantissa) - 1;
    let max_finite = if infinities {
        ((top - 1) << mantissa) | man_mask
    } else {
        (top << mantissa) | (man_mask - 1)
    };
    let overflow = if infinities { top << mantissa } else { max_finite };
    let keep = 23 - mantissa;
    let half = 1u32 << (keep - 1);

    // ⚠️ Everything is phrased in the BIASED exponent, so no constant here is
    // negative. AXIS literals are unsigned -- `integer_literal` reads decimal
    // and hex digits and nothing else -- so `1 - bias` written out as `-6`
    // reaches the validator as an unknown symbol. Asked for, it says so; the
    // first version of this function found out that way.
    let smallest_normal = 128 - bias;            // biased exponent of 2^(1-bias)
    let smallest_subnormal = smallest_normal - mantissa - 1;
    let largest = if infinities {
        127 + top - 1 - bias + 1
    } else {
        127 + top - bias + 1
    };

    let sign = format!("(and i32 (lshr i32 {value} 24) 0x80)");
    let biased = format!("(and i32 (lshr i32 {value} 23) 255)");
    let frac = format!("(and i32 {value} 0x7fffff)");

    let kept = format!("(lshr i32 {frac} {keep})");
    let dropped = format!("(and i32 {frac} {})", (1u32 << keep) - 1);
    let round = format!(
        "(or i32 (icmp_uge i32 {dropped} {}) (and i32 (icmp_eq i32 {dropped} {half}) \
         (and i32 {kept} 1)))",
        half + 1
    );
    let magnitude = format!(
        "(add i32 (or i32 (shl i32 (sub i32 {biased} {}) {mantissa}) {kept}) {round})",
        127 - bias
    );
    let normal = format!(
        "(select i32 (icmp_uge i32 {magnitude} {}) {overflow} {magnitude})",
        max_finite + 1
    );

    let shift = format!("(sub i32 {} {biased})", smallest_normal + keep);
    let mant = format!("(or i32 {frac} 0x800000)");
    let kept_sub = format!("(lshr i32 {mant} {shift})");
    let dropped_sub = format!("(and i32 {mant} (sub i32 (shl i32 1 {shift}) 1))");
    let half_sub = format!("(shl i32 1 (sub i32 {shift} 1))");
    let round_sub = format!(
        "(or i32 (icmp_uge i32 {dropped_sub} (add i32 {half_sub} 1)) \
         (and i32 (icmp_eq i32 {dropped_sub} {half_sub}) (and i32 {kept_sub} 1)))"
    );
    let subnormal = format!("(add i32 {kept_sub} {round_sub})");

    let finite = format!(
        "(select i32 (icmp_uge i32 {biased} {smallest_normal}) (or i32 {sign} {normal}) \
         (select i32 (icmp_ult i32 {biased} {smallest_subnormal}) {sign} \
          (or i32 {sign} {subnormal})))"
    );
    format!(
        "(select i32 (and i32 (icmp_eq i32 {biased} 255) (icmp_ne i32 {frac} 0)) 0x7f \
         (select i32 (icmp_uge i32 {biased} {largest}) (or i32 {sign} {overflow}) {finite}))"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_document_without_bf16_is_untouched() {
        let text = "(fadd f32 rs1 rs2)";
        assert_eq!(expand_interchange_text(text).unwrap(), text);
    }

    #[test]
    fn widening_is_a_shift() {
        assert_eq!(
            expand_interchange_text("(fcvt_f2f f32 bf16 rs1)").unwrap(),
            "(shl i32 (and i32 rs1 0xffff) 16)"
        );
    }

    #[test]
    fn narrowing_rounds_and_answers_nan_first() {
        let expanded = expand_interchange_text("(fcvt_f2f bf16 f32 rs1)").unwrap();
        assert!(expanded.starts_with("(select i32 (icmp_uge"), "{expanded}");
        assert!(expanded.contains("0x7fc0"), "{expanded}");
        assert!(expanded.contains("0x7fff"), "{expanded}");
    }

    #[test]
    fn the_expansion_reaches_inside_other_operators() {
        let expanded =
            expand_interchange_text("(fadd f32 (fcvt_f2f f32 bf16 rs1) rs2)").unwrap();
        assert_eq!(expanded, "(fadd f32 (shl i32 (and i32 rs1 0xffff) 16) rs2)");
    }

    #[test]
    fn an_interchange_format_computes_nothing() {
        let error = expand_interchange_text("(fadd bf16 rs1 rs2)").unwrap_err();
        assert!(error.contains("nothing computes in it"), "{error}");
    }

    #[test]
    fn an_eight_bit_widening_is_a_select_and_not_a_loop() {
        // Two or three mantissa bits means the subnormal's leading bit is found
        // by testing two or three positions. `docs/tensor_design.md` predicted
        // a loop, generalising from f16's eleven bits.
        let expanded = expand_interchange_text("(fcvt_f2f f32 f8e4m3 rs1)").unwrap();
        assert!(expanded.contains("select"), "{expanded}");
        assert!(!expanded.contains("iterate"), "{expanded}");
        // e5m2 keeps the top exponent for infinities and e4m3 does not, which
        // is the one field that differs and it reaches the output.
        let ieee = expand_interchange_text("(fcvt_f2f f32 f8e5m2 rs1)").unwrap();
        assert!(ieee.contains("0x7f800000"), "{ieee}");
        assert!(!expanded.contains("0x7f800000"), "{expanded}");
    }

    #[test]
    fn an_eight_bit_conversion_holds_no_negative_literal() {
        // AXIS literals are unsigned, so `1 - bias` spelled out reaches the
        // validator as an unknown symbol. Both directions are phrased in the
        // biased exponent for that reason, and this is what keeps them there.
        for form in [
            "(fcvt_f2f f8e4m3 f32 rs1)",
            "(fcvt_f2f f8e5m2 f32 rs1)",
            "(fcvt_f2f f32 f8e4m3 rs1)",
            "(fcvt_f2f f32 f8e5m2 rs1)",
        ] {
            let expanded = expand_interchange_text(form).unwrap();
            assert!(!expanded.contains(" -"), "{form} expands with a negative literal");
        }
    }

    #[test]
    fn f8_alone_names_no_format() {
        let error = expand_interchange_text("(fcvt_f2f f8 f32 rs1)").unwrap_err();
        assert!(error.contains("two eight-bit floats"), "{error}");
        // And it is refused wherever it appears, not only as a conversion end.
        assert!(expand_interchange_text("(fadd f8 a b)").is_err());
    }

    #[test]
    fn the_pairing_with_f32_is_required() {
        let error = expand_interchange_text("(fcvt_f2f bf16 64 rs1)").unwrap_err();
        assert!(error.contains("convert through f32"), "{error}");
        let error = expand_interchange_text("(fcvt_f2f f64 bf16 rs1)").unwrap_err();
        assert!(error.contains("convert through f32"), "{error}");
    }
}
