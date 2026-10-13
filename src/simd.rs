//! Lane-wise SIMD as elaboration-time expansion (`docs/simd_fp_design.md`,
//! stages V1 and F2).
//!
//! A vector type atom `v<lanes>i<elem>` (`v2i32`, `v4i16`, `v8i8`) or
//! `v<lanes>f<elem>` (`v2f32`, `v2f64`) applies an operator to each lane of a
//! register independently. That is not a new value
//! domain — a lane-wise add on a 64-bit register holding two 32-bit lanes is
//! two masked adds on bit-vector slices — so vectors expand into the existing
//! integer semantics rather than propagating a vector type through six
//! backends.
//!
//! The expansion runs on the **surface** s-expression, not the typed `Sem` IR,
//! and for a specific reason: several artifacts reflect the source expression
//! rather than consuming the IR. `golden_model.py` embeds the semantics string
//! and re-parses it in Python at runtime; `semantics.json` preserves the raw
//! spelling by design. Expanding in `ir.rs` would therefore leave those
//! artifacts staring at a `v2i32` atom they do not understand. Expanding at
//! elaboration — the same stage that inlines `defsem` calls and instruction
//! families — means every consumer, IR-based or reflective, sees ordinary
//! bit-vector semantics.
//!
//! Floating-point lanes (stage F2) reuse all of it. The lane *extraction* is
//! bit-vector work either way — shift down, mask, place back — because an AXIS
//! float is a bit pattern, so the only thing the element domain changes is the
//! type atom the per-lane operator is given: `f32` instead of `i32`. That is one
//! line, which is the whole argument for having built the lane machinery
//! domain-agnostically in the first place.
//!
//! The per-lane mask is the substance of the whole construction: it is what
//! stops lane 0's carry from reaching lane 1. Writing it once here is the
//! difference between one implementation and six.

use crate::effects::render_semexpr;
use crate::semantics::{parse_formal_semantics, SemanticExpr};

/// Operators whose meaning is lane-local, so applying them to a vector is
/// exactly applying them to each lane independently.
const LANE_PARALLEL: &[&str] = &[
    "add", "sub", "mul", "and", "or", "xor", "not", "min", "max", "minu", "maxu",
    // Shifts and rotates are lane-local in both representations: each lane
    // shifts by its own amount and nothing crosses the boundary. Both spellings
    // of each are listed because this matches the raw operator name rather than
    // the normalised one, and a corpus may write either.
    "shl", "sll", "lshr", "srl", "sra", "ashr", "rol", "ror",
];

/// Lane-local operators over IEEE-754 elements. `fsqrt` is unary and the rest
/// binary; all of them are per-element by definition, which is why stage F2 is
/// the composition of the lane machinery with the float semantics rather than
/// anything new. Comparisons are excluded on purpose: an AArch64 lane-wise
/// compare writes a lane *mask* of all-ones or all-zeros, not the 1/0 the
/// scalar `fcmp_*` operators return, so spelling one as a lane-wise `fcmp` would
/// quietly mean the wrong thing.
/// ⚠️ `fma` and `fneg` are as elementwise as `fadd`, and their absence was
/// found by the first SME outer product: Arm's non-widening FMOPA is a fused
/// multiply-add per element (`FPMulAdd`), and FMOPS negates the product. A
/// fused operation cannot be spelled as `fadd` of `fmul` -- that rounds twice
/// -- so without `fma` here an FMOPA could only be described wrongly.
const LANE_PARALLEL_FLOAT: &[&str] = &["fadd", "fsub", "fmul", "fdiv", "fsqrt", "fma", "fneg"];

/// Comparisons, whose lane result is a *mask* rather than the 1 or 0 the
/// scalar operators return.
///
/// These are kept apart from `LANE_PARALLEL` rather than added to it, because
/// the difference is exactly the thing that would otherwise go wrong quietly:
/// an AArch64 lane-wise compare writes all-ones or all-zeros across the lane,
/// and `icmp_eq` answers 1 or 0. Treating them as ordinary lane-parallel
/// operators would put a 1 in a byte where the machine puts 0xff.
///
/// Widening the 1 to the lane needs no new operator: multiplying the 0-or-1 by
/// the lane mask is 0 or all-ones, at the lane's own width, and every backend
/// already has a multiply.
const LANE_COMPARE: &[&str] = &[
    "icmp_eq", "icmp_ne", "icmp_ult", "icmp_uge", "icmp_slt", "icmp_sge",
];

/// True when `op` compares lanes and answers a lane mask.
///
/// Published beside `is_lane_parallel` so a consumer asking "may this operator
/// take a vector type?" has one place to ask rather than two lists to keep in
/// step.
pub fn is_lane_compare(op: &str) -> bool {
    LANE_COMPARE.contains(&op)
}

/// True when `op` is lane-local in the given element domain.
///
/// Published rather than kept private because `scalable.rs` instantiates the
/// same operators lane-indexed instead of packed, and two copies of this list
/// would be two vocabularies that could drift apart.
pub fn is_lane_parallel(op: &str, elem_kind: char) -> bool {
    let parallel = if elem_kind == 'f' {
        LANE_PARALLEL_FLOAT
    } else {
        LANE_PARALLEL
    };
    parallel.contains(&op)
}

/// A vector type atom's shape: how many lanes, how wide each is, and which
/// domain the per-lane operator reads them in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorShape {
    pub lanes: u32,
    pub elem: u32,
    /// `i` for a bit-vector lane, `f` for an IEEE-754 one — the leading letter
    /// of the element type atom the expansion hands the operator.
    pub elem_kind: char,
}

/// Parse `v<lanes>i<elem>` or `v<lanes>f<elem>` into its shape. Returns `None`
/// for anything else, including the scalar `iW`/`uW`/`fW` atoms.
pub fn vector_type_atom(atom: &str) -> Option<VectorShape> {
    let rest = atom.strip_prefix('v')?;
    let (elem_kind, (lanes, elem)) = match (rest.split_once('i'), rest.split_once('f')) {
        (Some(split), None) => ('i', split),
        (None, Some(split)) => ('f', split),
        // `v2i32` has no `f` and `v2f32` has no `i`, so a token containing both
        // is not a shape this understands.
        _ => return None,
    };
    if lanes.is_empty() || elem.is_empty() {
        return None;
    }
    let lanes: u32 = lanes.parse().ok()?;
    let elem: u32 = elem.parse().ok()?;
    // Two or more lanes (one lane is a scalar, and spelling it as a vector
    // hides that), a lane that fits the widest scalar, and a register no wider
    // than the IR's literal type.
    if lanes < 2 || elem == 0 || elem > 64 || lanes.checked_mul(elem)? > 128 {
        return None;
    }
    // IEEE-754 lanes exist at the two widths AXIS has float semantics for;
    // anything else would be a format the backends cannot agree on.
    if elem_kind == 'f' && !matches!(elem, 16 | 32 | 64) {
        return None;
    }
    Some(VectorShape {
        lanes,
        elem,
        elem_kind,
    })
}

/// True when `text` mentions a vector type atom, so callers can skip the
/// reparse/expand round trip for the overwhelmingly common scalar case and
/// keep every existing artifact byte-identical.
pub fn mentions_vector(text: &str) -> bool {
    text.split(|ch: char| !(ch.is_ascii_alphanumeric()))
        .any(|token| vector_type_atom(token).is_some())
}

/// Expand every vector application in a semantics string, returning the
/// rewritten source. Scalar semantics are returned unchanged.
pub fn expand_vector_text(text: &str) -> Result<String, String> {
    if !mentions_vector(text) {
        return Ok(text.to_string());
    }
    let expr = parse_formal_semantics(text).map_err(|error| error.message)?;
    Ok(render_semexpr(&expand(&expr)?))
}

/// Expand vector applications throughout an s-expression.
fn expand(expr: &SemanticExpr) -> Result<SemanticExpr, String> {
    let SemanticExpr::List(items) = expr else {
        return Ok(expr.clone());
    };
    let expanded: Vec<SemanticExpr> = items
        .iter()
        .map(expand)
        .collect::<Result<Vec<_>, _>>()?;
    let (Some(SemanticExpr::Atom(op)), Some(SemanticExpr::Atom(type_atom))) =
        (expanded.first(), expanded.get(1))
    else {
        return Ok(SemanticExpr::List(expanded));
    };
    let Some(shape) = vector_type_atom(type_atom) else {
        return Ok(SemanticExpr::List(expanded));
    };
    // ⚠️ `vmap` is the general form, and the reason it exists is that the
    // vocabulary above is a CLOSED LIST. A lane operation had to be one atom
    // AXIS already knew, so a saturating add, a lane-wise variable shift, or
    // anything else built out of several steps was simply not describable --
    // not because lanes could not express it, but because there was nowhere to
    // put the steps. `vmap` names the lane values and takes an arbitrary
    // expression over them, so the closed list becomes a convenience rather
    // than a limit.
    if op == "vmap" {
        return expand_vmap(shape, type_atom, &expanded[2..]);
    }
    if !is_lane_parallel(op, shape.elem_kind) && !is_lane_compare(op) {
        return Err(format!(
            "operator `{op}` is not lane-local, so `{type_atom}` has no meaning for it; \
             describe the cross-lane behaviour explicitly"
        ));
    }
    Ok(expand_lanes(op, shape, &expanded[2..]))
}

/// Expand `(vmap SHAPE ((name source) ...) body)`: evaluate `body` once per
/// lane, with each `name` bound to that lane's slice of `source`.
///
/// The lane bindings are emitted as a `let` around the body rather than
/// substituted into it, and that choice is the whole hygiene story. A body is
/// free to bind its own names -- a saturating add wants `sum`, `overflowed`,
/// `limit` -- and substitution would have to know which of those shadow a lane
/// name and stop descending there. A `let` already answers that question,
/// correctly, everywhere it is resolved. It only became usable for this when
/// `let` bindings became sequential: a lane body is a chain of steps, and a
/// chain of steps needs each step to see the one above it.
fn expand_vmap(
    shape: VectorShape,
    type_atom: &str,
    args: &[SemanticExpr],
) -> Result<SemanticExpr, String> {
    if args.len() != 2 {
        return Err(format!(
            "`vmap {type_atom}` expects a binding list and one body expression, \
             got {} argument(s)",
            args.len()
        ));
    }
    let SemanticExpr::List(raw_bindings) = &args[0] else {
        return Err(format!(
            "`vmap {type_atom}` expects a list of (name source) lane bindings"
        ));
    };
    // ⚠️ A `vmap` with no lane bindings reads every lane out of nothing, so the
    // body cannot depend on the lane and the whole construction collapses to a
    // splat written the long way. Rejected rather than expanded, because the
    // expansion would be a plausible-looking answer to a question nobody meant
    // to ask.
    if raw_bindings.is_empty() {
        return Err(format!(
            "`vmap {type_atom}` binds no lane values, so its body cannot depend \
             on the lane; write the value directly"
        ));
    }
    let mut bindings = Vec::new();
    for binding in raw_bindings {
        let SemanticExpr::List(pair) = binding else {
            return Err(format!(
                "`vmap {type_atom}` lane binding must be (name source)"
            ));
        };
        if pair.len() != 2 {
            return Err(format!(
                "`vmap {type_atom}` lane binding must be (name source), got {} element(s)",
                pair.len()
            ));
        }
        let SemanticExpr::Atom(name) = &pair[0] else {
            return Err(format!(
                "`vmap {type_atom}` lane binding name must be an atom"
            ));
        };
        if bindings.iter().any(|(existing, _)| existing == name) {
            return Err(format!(
                "`vmap {type_atom}` binds lane name `{name}` twice"
            ));
        }
        bindings.push((name.clone(), pair[1].clone()));
    }

    let VectorShape { lanes, elem, .. } = shape;
    let total = lanes * elem;
    let mask = if elem >= 128 {
        u128::MAX
    } else {
        (1u128 << elem) - 1
    };
    let mut placed = Vec::new();
    for lane in 0..lanes {
        let shift = lane * elem;
        let mut lane_bindings = vec![
            // ⚠️ `lane-index` is bound rather than substituted, for the same
            // reason the lane values are: a body that rebinds it should get
            // its own. It is first so the lane values may be written in terms
            // of it, which is what sequential bindings buy here.
            SemanticExpr::List(vec![
                SemanticExpr::Atom(LANE_INDEX.to_string()),
                SemanticExpr::Atom(lane.to_string()),
            ]),
        ];
        for (name, source) in &bindings {
            // A source may say WHICH lane it wants -- `(lane rn (/ lane-index
            // 2))` -- and that is what makes a cross-lane permutation
            // describable. The index is resolved here, where the lane number
            // is known, so what reaches the backends is an ordinary constant
            // shift and nothing has to understand shuffling.
            let (source, from) = match read_lane_source(source, lane, lanes, type_atom)? {
                Some((inner, from)) => (inner, from),
                None => (source.clone(), lane),
            };
            lane_bindings.push(SemanticExpr::List(vec![
                SemanticExpr::Atom(name.clone()),
                // The same shift-down-and-mask every lane-parallel operator
                // gets. The body then names the result instead of having
                // one operator applied to it.
                mask_to(shift_down(source, from * elem, total), mask, total),
            ]));
        }
        let body = SemanticExpr::List(vec![
            SemanticExpr::Atom("let".to_string()),
            SemanticExpr::List(lane_bindings),
            args[1].clone(),
        ]);
        // Masked on the way out exactly as before: whatever the body computed,
        // only this lane's bits are placed. That is what contains a carry the
        // body did not think to contain.
        placed.push(shift_up(mask_to(body, mask, total), shift, total));
    }
    if placed.len() == 1 {
        return Ok(placed.remove(0));
    }
    let mut combined = vec![
        SemanticExpr::Atom("or".to_string()),
        SemanticExpr::Atom(format!("i{total}")),
    ];
    combined.extend(placed);
    Ok(SemanticExpr::List(combined))
}

/// Build the lane-wise expansion: for each lane, shift the operands down to
/// lane 0, apply the operator at the lane width, mask the result to the lane,
/// shift it back, and `or` the lanes together.
fn expand_lanes(op: &str, shape: VectorShape, args: &[SemanticExpr]) -> SemanticExpr {
    let VectorShape {
        lanes,
        elem,
        elem_kind,
    } = shape;
    let total = lanes * elem;
    let mask = if elem >= 128 {
        u128::MAX
    } else {
        (1u128 << elem) - 1
    };
    let mut placed = Vec::new();
    for lane in 0..lanes {
        let shift = lane * elem;
        let lane_args: Vec<SemanticExpr> = args
            .iter()
            .map(|arg| mask_to(shift_down(arg.clone(), shift, total), mask, total))
            .collect();
        // The operator runs at the lane width, so its width-sensitive
        // behaviour — signed `min`/`max` reading the lane's own sign bit,
        // `not` complementing only the lane — is lane-correct. The result is
        // masked again before being placed, which is what contains carries.
        let mut computed = vec![
            SemanticExpr::Atom(op.to_string()),
            SemanticExpr::Atom(format!("{elem_kind}{elem}")),
        ];
        computed.extend(lane_args);
        // A compare answers 1 or 0 and the machine writes all-ones or
        // all-zeros, so the answer is widened to the lane by multiplying it by
        // the lane mask. It happens here, inside the lane, so the following
        // `mask_to` is the same containment every other operator gets.
        let value = if is_lane_compare(op) {
            SemanticExpr::List(vec![
                SemanticExpr::Atom("mul".to_string()),
                SemanticExpr::Atom(format!("{elem_kind}{elem}")),
                SemanticExpr::List(computed),
                SemanticExpr::Atom(format!("0x{mask:x}")),
            ])
        } else {
            SemanticExpr::List(computed)
        };
        placed.push(shift_up(mask_to(value, mask, total), shift, total));
    }
    if placed.len() == 1 {
        return placed.remove(0);
    }
    let mut combined = vec![
        SemanticExpr::Atom("or".to_string()),
        SemanticExpr::Atom(format!("i{total}")),
    ];
    combined.extend(placed);
    SemanticExpr::List(combined)
}

/// The name a lane body uses for the lane it is running on.
const LANE_INDEX: &str = "lane-index";

/// Recognise `(lane SOURCE INDEX)` in a lane binding's source position and
/// resolve `INDEX` to the lane it names.
///
/// This is the whole of cross-lane support, and it is deliberately small. A
/// permutation -- `zip`, `uzp`, `trn`, a pairwise add -- is a function from
/// output lane to input lane, and every one of them is a function AXIS can
/// evaluate while it expands, because the output lane is a constant there.
/// So the shuffle disappears at elaboration and the backends receive the
/// constant shifts they already understood. Nothing downstream learns a new
/// concept, which is the same bargain the lane expansion itself made.
///
/// An index that lands outside the vector is an error rather than a wrap:
/// a permutation formula that is off by one is a description bug, and the
/// lane it would silently read is a real lane holding real data.
fn read_lane_source(
    source: &SemanticExpr,
    lane: u32,
    lanes: u32,
    type_atom: &str,
) -> Result<Option<(SemanticExpr, u32)>, String> {
    let SemanticExpr::List(items) = source else {
        return Ok(None);
    };
    let Some(SemanticExpr::Atom(head)) = items.first() else {
        return Ok(None);
    };
    if head != "lane" {
        return Ok(None);
    }
    if items.len() != 3 {
        return Err(format!(
            "`vmap {type_atom}` lane source `lane` expects a source and an index, \
             got {} argument(s)",
            items.len() - 1
        ));
    }
    let index = fold_lane_index(&items[2], lane, type_atom)?;
    if index < 0 || index as u32 >= lanes {
        return Err(format!(
            "`vmap {type_atom}` reads lane {index} at output lane {lane}, but the \
             vector has lanes 0..{}",
            lanes - 1
        ));
    }
    Ok(Some((items[1].clone(), index as u32)))
}

/// Evaluate a lane-index expression. Literals, `lane-index`, and the five
/// arithmetic operators, over signed integers so an off-by-one below zero is
/// reported rather than wrapping into the top lane.
fn fold_lane_index(expr: &SemanticExpr, lane: u32, type_atom: &str) -> Result<i64, String> {
    match expr {
        SemanticExpr::Atom(atom) if atom == LANE_INDEX => Ok(lane as i64),
        SemanticExpr::Atom(atom) => parse_lane_literal(atom).ok_or_else(|| {
            format!(
                "`vmap {type_atom}` lane index `{atom}` is neither a literal nor \
                 `{LANE_INDEX}`; a lane index must be known while the vector is \
                 expanded"
            )
        }),
        SemanticExpr::List(items) => {
            let Some(SemanticExpr::Atom(op)) = items.first() else {
                return Err(format!(
                    "`vmap {type_atom}` lane index expects an operator"
                ));
            };
            if items.len() != 3 {
                return Err(format!(
                    "`vmap {type_atom}` lane index `{op}` expects two operands, \
                     got {}",
                    items.len() - 1
                ));
            }
            let lhs = fold_lane_index(&items[1], lane, type_atom)?;
            let rhs = fold_lane_index(&items[2], lane, type_atom)?;
            match op.as_str() {
                "+" => Ok(lhs + rhs),
                "-" => Ok(lhs - rhs),
                "*" => Ok(lhs * rhs),
                "/" | "%" if rhs == 0 => Err(format!(
                    "`vmap {type_atom}` lane index divides by zero"
                )),
                "/" => Ok(lhs.div_euclid(rhs)),
                "%" => Ok(lhs.rem_euclid(rhs)),
                _ => Err(format!(
                    "`vmap {type_atom}` lane index operator `{op}` is not one of \
                     +, -, *, /, %"
                )),
            }
        }
    }
}

fn parse_lane_literal(atom: &str) -> Option<i64> {
    if let Some(hex) = atom.strip_prefix("0x").or_else(|| atom.strip_prefix("0X")) {
        return i64::from_str_radix(hex, 16).ok();
    }
    atom.parse::<i64>().ok()
}

fn shift_down(value: SemanticExpr, shift: u32, width: u32) -> SemanticExpr {
    if shift == 0 {
        return value;
    }
    SemanticExpr::List(vec![
        SemanticExpr::Atom("lshr".to_string()),
        SemanticExpr::Atom(format!("i{width}")),
        value,
        SemanticExpr::Atom(shift.to_string()),
    ])
}

fn shift_up(value: SemanticExpr, shift: u32, width: u32) -> SemanticExpr {
    if shift == 0 {
        return value;
    }
    SemanticExpr::List(vec![
        SemanticExpr::Atom("shl".to_string()),
        SemanticExpr::Atom(format!("i{width}")),
        value,
        SemanticExpr::Atom(shift.to_string()),
    ])
}

fn mask_to(value: SemanticExpr, mask: u128, width: u32) -> SemanticExpr {
    SemanticExpr::List(vec![
        SemanticExpr::Atom("and".to_string()),
        SemanticExpr::Atom(format!("i{width}")),
        value,
        SemanticExpr::Atom(format!("0x{mask:x}")),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_semantics_are_untouched() {
        let source = "(add i32 (mul i32 rs1 rs2) rs3)";
        assert_eq!(expand_vector_text(source).unwrap(), source);
        assert!(!mentions_vector(source));
    }

    #[test]
    fn vector_atoms_are_recognized_precisely() {
        let shape = |lanes, elem, elem_kind| {
            Some(VectorShape {
                lanes,
                elem,
                elem_kind,
            })
        };
        assert_eq!(vector_type_atom("v2i32"), shape(2, 32, 'i'));
        assert_eq!(vector_type_atom("v8i8"), shape(8, 8, 'i'));
        // Stage F2: IEEE-754 lanes at the two widths AXIS has float semantics
        // for, and nothing else — a lane format the backends cannot agree on is
        // not a vector this understands.
        assert_eq!(vector_type_atom("v2f32"), shape(2, 32, 'f'));
        assert_eq!(vector_type_atom("v4f32"), shape(4, 32, 'f'));
        assert_eq!(vector_type_atom("v2f64"), shape(2, 64, 'f'));
        assert_eq!(vector_type_atom("v4f16"), shape(4, 16, 'f'));
        assert_eq!(vector_type_atom("v8f16"), shape(8, 16, 'f'));
        assert_eq!(vector_type_atom("f64"), None);
        // Not vectors: scalars, a single lane, an over-wide register.
        assert_eq!(vector_type_atom("i32"), None);
        assert_eq!(vector_type_atom("v1i32"), None);
        assert_eq!(vector_type_atom("v4i64"), None);
        assert_eq!(vector_type_atom("vi32"), None);
    }

    #[test]
    fn lanes_are_masked_independently() {
        let expanded = expand_vector_text("(add v2i32 vn vm)").unwrap();
        // Both lanes appear, each masked to 32 bits, and the high lane is
        // shifted down before and back after.
        assert!(expanded.contains("0xffffffff"));
        assert!(expanded.contains("lshr i64 vn 32"));
        assert!(expanded.contains("shl i64"));
        assert!(!expanded.contains("v2i32"));
    }

    #[test]
    fn a_lane_compare_answers_a_mask_and_not_a_one() {
        // ⚠️ The whole reason compares are a separate list. `icmp_ult` answers
        // 1 or 0; an AArch64 lane-wise compare writes 0xff across the byte. If
        // these were folded into LANE_PARALLEL the expansion would put a 1
        // where the machine puts all-ones, and every backend would agree with
        // every other on the wrong answer -- a differential ladder cannot see a
        // mistake all its rungs share.
        let expanded = expand_vector_text("(icmp_ult v2i32 vn vm)").unwrap();
        assert!(
            expanded.contains("mul i32"),
            "the 0-or-1 is widened to the lane by multiplying by its mask: {expanded}"
        );
        assert!(expanded.contains("0xffffffff"));
        assert!(!expanded.contains("v2i32"));

        // And the widening happens per lane, inside the mask that contains it:
        // a compare on the low lane must not put ones in the high one.
        assert_eq!(expanded.matches("mul i32").count(), 2, "one per lane");
    }

    #[test]
    fn a_lane_body_binds_every_lane() {
        let expanded = expand_vector_text("(vmap v2i16 ((a vn) (b vm)) (add i16 a b))").unwrap();
        // One `let` per lane, each binding both names, and the high lane
        // shifted down before and back after.
        assert_eq!(expanded.matches("let").count(), 2);
        assert!(expanded.contains("lshr i32 vn 16"));
        assert!(expanded.contains("lshr i32 vm 16"));
        assert!(!expanded.contains("vmap"));
        assert!(!expanded.contains("v2i16"));
    }

    #[test]
    fn a_lane_body_is_wrapped_rather_than_substituted() {
        // ⚠️ The hygiene claim, at the level of the expansion itself: the body
        // is left ALONE. If it were substituted into, the body's own `a` would
        // have been replaced and this text would not survive.
        let expanded =
            expand_vector_text("(vmap v2i16 ((a vn)) (let ((a (add i16 a 1))) (mul i16 a 3)))")
                .unwrap();
        assert!(
            expanded.contains("(let ((a (add i16 a 1))) (mul i16 a 3))"),
            "the body should be carried through untouched: {expanded}"
        );
    }

    #[test]
    fn malformed_lane_bodies_are_rejected() {
        let error = |source| expand_vector_text(source).unwrap_err();
        assert!(error("(vmap v2i16 ((a vn) (b vm)))").contains("one body expression"));
        assert!(error("(vmap v2i16 ((a vn)) x y)").contains("one body expression"));
        assert!(error("(vmap v2i16 ((a vn) (a vm)) a)").contains("twice"));
        assert!(error("(vmap v2i16 ((a vn) b) a)").contains("(name source)"));
        assert!(error("(vmap v2i16 ((a vn) (a vm b)) a)").contains("(name source)"));
        assert!(error("(vmap v2i16 vn a)").contains("list of (name source)"));
    }

    #[test]
    fn a_lane_body_with_no_bindings_is_rejected() {
        // ⚠️ Called directly, because `()` cannot be written: the reader
        // rejects an empty expression list before the expansion sees it. The
        // guard stays because it is the expansion's own precondition and not
        // the reader's, but a test routed through text would be passing on the
        // reader's behalf and reporting it as this one's.
        let shape = vector_type_atom("v2i16").unwrap();
        let error = expand_vmap(
            shape,
            "v2i16",
            &[
                SemanticExpr::List(Vec::new()),
                SemanticExpr::Atom("0".to_string()),
            ],
        )
        .unwrap_err();
        assert!(error.contains("binds no lane values"), "{error}");
    }

    #[test]
    fn a_lane_source_may_name_the_lane_it_reads() {
        // zip1 over four lanes: output lane 1 takes lane 0 of the second
        // source, so nothing is shifted down for it at all.
        let expanded = expand_vector_text(
            "(vmap v4i8 ((x (lane vn (/ lane-index 2))) (y (lane vm (/ lane-index 2)))) \
             (select i8 (icmp_eq i8 (and i8 lane-index 1) 0) x y))",
        )
        .unwrap();
        // Lane 3 reads lane 1 of both sources: 1 * 8 bits.
        assert!(expanded.contains("lshr i32 vm 8"), "{expanded}");
        // And the lane number itself is bound, not substituted, so a body may
        // rebind it like any other name.
        assert!(expanded.contains("(lane-index 3)"), "{expanded}");
        assert!(!expanded.contains("vmap"));
    }

    #[test]
    fn a_lane_index_outside_the_vector_is_rejected() {
        // ⚠️ An error rather than a wrap. A permutation formula that is off by
        // one is a description bug, and the lane it would silently read holds
        // real data -- so the expansion refuses rather than answering.
        let error = expand_vector_text(
            "(vmap v4i8 ((x (lane vn (+ lane-index 1)))) x)",
        )
        .unwrap_err();
        assert!(error.contains("reads lane 4"), "{error}");
        let below = expand_vector_text(
            "(vmap v4i8 ((x (lane vn (- lane-index 1)))) x)",
        )
        .unwrap_err();
        assert!(below.contains("reads lane -1"), "{below}");
    }

    #[test]
    fn malformed_lane_indices_are_rejected() {
        let error = |source| expand_vector_text(source).unwrap_err();
        assert!(error("(vmap v4i8 ((x (lane vn))) x)").contains("a source and an index"));
        assert!(error("(vmap v4i8 ((x (lane vn 0 1))) x)").contains("a source and an index"));
        assert!(error("(vmap v4i8 ((x (lane vn rs1))) x)").contains("neither a literal"));
        assert!(error("(vmap v4i8 ((x (lane vn (/ lane-index 0)))) x)")
            .contains("divides by zero"));
        assert!(error("(vmap v4i8 ((x (lane vn (<< lane-index 1)))) x)")
            .contains("is not one of"));
        assert!(error("(vmap v4i8 ((x (lane vn (+ lane-index)))) x)")
            .contains("expects two operands"));
    }

    #[test]
    fn a_lane_index_folds_every_operator() {
        // 0,1,2,3 -> 3,2,1,0 exercises `-`; the rest are reached by the
        // malformed tests only, so fold them here where the answer is checked.
        let reversed =
            expand_vector_text("(vmap v4i8 ((x (lane vn (- 3 lane-index)))) x)").unwrap();
        assert!(reversed.contains("lshr i32 vn 24"), "{reversed}");
        let folded = |index: &str| {
            expand_vector_text(&format!("(vmap v2i16 ((x (lane vn {index}))) x)")).unwrap()
        };
        // `%` and `*` and `+`, each landing on lane 1 for the high lane.
        assert!(folded("(% lane-index 2)").contains("lshr i32 vn 16"));
        assert!(folded("(* lane-index 1)").contains("lshr i32 vn 16"));
        assert!(folded("(+ lane-index 0)").contains("lshr i32 vn 16"));
        // A literal index reads the same lane for every output lane.
        assert_eq!(folded("0x1").matches("lshr i32 vn 16").count(), 2);
    }

    #[test]
    fn non_lane_local_operators_are_rejected() {
        // An operator the lists do not name is refused. This used `sext` until
        // SME's widening outer products needed it per lane (S1); `mulh` is
        // still unlisted.
        let error = expand_vector_text("(mulh v2i32 vn vm)").unwrap_err();
        assert!(error.contains("not lane-local"));
    }

    #[test]
    fn a_packed_fused_multiply_add_is_one_fma_per_lane() {
        // All three operands are vectors, so splitting each across the lanes
        // is right here -- one `fma` per lane, never `fadd` of `fmul`.
        let expanded = expand_vector_text("(fma v2f32 va vb vc)").unwrap();
        assert_eq!(expanded.matches("fma f32").count(), 2, "{expanded}");
        assert!(!expanded.contains("fmul"), "{expanded}");
    }

    #[test]
    fn a_packed_extension_is_still_refused() {
        // ⚠️ Scalable lanes take `sext`/`zext` (S1, `scalable.rs`); packed
        // ones do not. The packed expansion splits EVERY argument across the
        // lanes -- right for a shift amount, which is an operand -- so the
        // literal source width became 8 in lane 0 and `8 >> 32 = 0` in lane
        // 1: "extend from zero bits". Found by a test written to pin the
        // meaning, which is why it is refused here rather than wrong.
        let error = expand_vector_text("(sext v2i32 8 vn)").unwrap_err();
        assert!(error.contains("not lane-local"), "{error}");
    }
}
