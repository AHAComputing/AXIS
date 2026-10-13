//! Bounded loops as elaboration-time unrolling.
//!
//! AXIS is statically elaborated: `defsem` calls inline, instruction families
//! expand, SIMD lanes expand, scalable vectors instantiate. A loop is the same
//! idea with the vector-ness taken out, and it earns its place by expressing
//! what lane instantiation cannot — a body whose iterations *depend on each
//! other*. Lane expansion requires lane-local operators precisely because each
//! lane is independent; a loop carries an accumulator from one iteration to the
//! next, so a popcount, a carry chain or a sequential scan becomes describable.
//!
//! ```text
//! (iterate <type> (<index> <count>) (<acc> <init>) <body>)
//! ```
//!
//! `acc_0` is `init`, `acc_{k+1}` is `body` with `<index>` bound to the literal
//! `k` and `<acc>` bound to `acc_k`, and the loop is `acc_count`.
//!
//! The bound is **static**, and that is the whole reason this costs no backend
//! work. An unrolled loop is ordinary semantics, so all five backends and every
//! executor handle it with machinery that already exists — the same argument
//! that made scalable lane instantiation free. A *dynamic* trip count is a
//! bounded loop plus a guard, which is exactly what `vtail` already does for
//! lanes: iterate to the maximum and let the guard decide which iterations
//! count.
//!
//! Native loops in the backends that have them (a `for` in C and Rust, blocks
//! and a phi in LLVM) would be a second implementation proven against this
//! unrolling, which is the relationship stage V2 already has with packed
//! vectors. SMT would keep using the unrolling either way, because QF_BV has no
//! loops at all.

use crate::ir::integer_literal;
use crate::semantics::{parse_formal_semantics, SemanticExpr};

/// Largest number of iterations one `iterate` may name.
const MAX_ITERATIONS: u128 = 1024;

/// Largest expression an unrolling may produce, in nodes. A body that mentions
/// its accumulator more than once doubles each iteration, so a loop that looks
/// small can expand without bound; this makes that a diagnosable error rather
/// than an elaborator that stops responding.
const MAX_NODES: usize = 200_000;

/// True when `text` mentions either loop form, so documents that use neither
/// skip the reparse entirely and keep their artifacts byte-identical.
pub fn mentions_loop(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| token == "iterate" || token == "accumulate")
}

/// Expand every `iterate` in a semantics string, returning the rewritten source.
pub fn expand_loop_text(text: &str) -> Result<String, String> {
    if !mentions_loop(text) {
        return Ok(text.to_string());
    }
    let expr = parse_formal_semantics(text).map_err(|error| error.message)?;
    Ok(crate::effects::render_semexpr(&expand(&expr)?))
}

fn count_nodes(expr: &SemanticExpr) -> usize {
    match expr {
        SemanticExpr::Atom(_) => 1,
        SemanticExpr::List(items) => 1 + items.iter().map(count_nodes).sum::<usize>(),
    }
}

/// Expand loops throughout an expression, innermost first.
fn expand(expr: &SemanticExpr) -> Result<SemanticExpr, String> {
    let SemanticExpr::List(items) = expr else {
        return Ok(expr.clone());
    };
    let expanded: Vec<SemanticExpr> = items.iter().map(expand).collect::<Result<Vec<_>, _>>()?;
    let Some(SemanticExpr::Atom(head)) = expanded.first() else {
        return Ok(SemanticExpr::List(expanded));
    };
    if head == "accumulate" {
        return accumulate(&expanded);
    }
    if head != "iterate" {
        return Ok(SemanticExpr::List(expanded));
    }
    if expanded.len() != 5 {
        return Err(
            "`iterate` must be `(iterate <type> (<index> <count>) (<acc> <init>) <body>)`"
                .to_string(),
        );
    }
    let (SemanticExpr::List(index_form), SemanticExpr::List(acc_form)) =
        (&expanded[2], &expanded[3])
    else {
        return Err("`iterate` needs `(<index> <count>)` and `(<acc> <init>)`".to_string());
    };
    if index_form.len() != 2 || acc_form.len() != 2 {
        return Err("`iterate` needs `(<index> <count>)` and `(<acc> <init>)`".to_string());
    }
    let (SemanticExpr::Atom(index_name), SemanticExpr::Atom(count_text)) =
        (&index_form[0], &index_form[1])
    else {
        return Err("`iterate`'s index and count must be atoms".to_string());
    };
    let SemanticExpr::Atom(acc_name) = &acc_form[0] else {
        return Err("`iterate`'s accumulator must be a name".to_string());
    };
    let count = integer_literal(count_text)
        .ok_or_else(|| format!("`iterate` count `{count_text}` is not a literal"))?;
    if count > MAX_ITERATIONS {
        return Err(format!(
            "`iterate` names {count} iterations; the maximum is {MAX_ITERATIONS}"
        ));
    }

    let body = &expanded[4];
    let mut accumulated = acc_form[1].clone();
    for step in 0..count {
        accumulated = substitute(
            body,
            index_name,
            &SemanticExpr::Atom(step.to_string()),
            acc_name,
            &accumulated,
        );
        if count_nodes(&accumulated) > MAX_NODES {
            return Err(format!(
                "`iterate` over {count} iterations expands past {MAX_NODES} nodes at \
                 step {step}; a body that names `{acc_name}` more than once doubles \
                 each iteration"
            ));
        }
    }
    Ok(accumulated)
}

/// The fold shapes an accumulation may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Order {
    /// Left to right, one level of nesting per step. What `iterate` builds,
    /// and what a floating-point accumulation means when the architecture says
    /// the steps are ordered.
    Sequential,
    /// A balanced tree: `log2(count)` levels rather than `count`.
    Pairwise,
    /// Any association at all, because the operator is associative *and* the
    /// accumulator is wide enough that no partial result is lost. Folded
    /// balanced, which is an implementation choice this order permits rather
    /// than a meaning it carries.
    Exact,
}

/// Operators an accumulation may fold with, and whether folding one can lose
/// information.
///
/// The bitwise operators and the extrema are idempotent in width: no
/// association of them can leave the range its operands were already in, so
/// `exact` costs them nothing to claim. `add` and `mul` grow, and for those
/// `exact` is an obligation rather than a label.
fn growing_operator(op: &str) -> Option<bool> {
    match op {
        // The float operators are here so an FP accumulation can name its
        // order; `exact` is refused for them a few lines below, because what
        // makes an association free is associativity and `fadd` has none.
        "add" | "mul" | "fadd" | "fmul" => Some(true),
        "and" | "or" | "xor" | "min" | "max" | "minu" | "maxu" => Some(false),
        _ => None,
    }
}

/// `(accumulate <type> <op> (<index> <count>) (order <order>) <term>)`.
///
/// The terms are **independent** -- the body names the index and never an
/// accumulator -- and that restriction is the whole point. `iterate`'s body may
/// read the previous result, so its association is fixed by meaning; an
/// accumulation's is not, which is what lets `exact` fold in halves and lets a
/// K = 1024 contraction exist at all. A left fold nests one level per step and
/// `semantics::MAX_EXPR_DEPTH` refuses it past 400; a balanced fold of the same
/// 1024 terms is ten levels deep.
fn accumulate(items: &[SemanticExpr]) -> Result<SemanticExpr, String> {
    if items.len() != 6 {
        return Err("`accumulate` must be `(accumulate <type> <op> (<index> <count>) \
                    (order <order>) <term>)`"
            .to_string());
    }
    let (SemanticExpr::Atom(type_atom), SemanticExpr::Atom(op)) = (&items[1], &items[2]) else {
        return Err("`accumulate` needs a type atom and an operator".to_string());
    };
    let SemanticExpr::List(index_form) = &items[3] else {
        return Err("`accumulate` needs `(<index> <count>)`".to_string());
    };
    let SemanticExpr::List(order_form) = &items[4] else {
        return Err("`accumulate` needs `(order <order>)`".to_string());
    };
    if index_form.len() != 2 || order_form.len() != 2 {
        return Err("`accumulate` needs `(<index> <count>)` and `(order <order>)`".to_string());
    }
    let (SemanticExpr::Atom(index_name), SemanticExpr::Atom(count_text)) =
        (&index_form[0], &index_form[1])
    else {
        return Err("`accumulate`'s index and count must be atoms".to_string());
    };
    let (SemanticExpr::Atom(order_head), SemanticExpr::Atom(order_name)) =
        (&order_form[0], &order_form[1])
    else {
        return Err("`accumulate`'s order must be `(order <order>)`".to_string());
    };
    if order_head != "order" {
        return Err(format!(
            "`accumulate` expects `(order <order>)`, not `({order_head} ...)`"
        ));
    }
    let order = match order_name.as_str() {
        "sequential" => Order::Sequential,
        "pairwise" => Order::Pairwise,
        "exact" => Order::Exact,
        other => {
            return Err(format!(
                "unknown accumulation order `{other}`; expected sequential, pairwise or exact"
            ))
        }
    };
    let Some(grows) = growing_operator(op) else {
        return Err(format!(
            "`accumulate` cannot fold with `{op}`: an accumulation re-associates its \
             operator, so it takes an associative one"
        ));
    };
    let count = integer_literal(count_text)
        .ok_or_else(|| format!("`accumulate` count `{count_text}` is not a literal"))?;
    if count == 0 {
        return Err("`accumulate` over no terms has no value".to_string());
    }
    if count > MAX_ITERATIONS {
        return Err(format!(
            "`accumulate` names {count} terms; the maximum is {MAX_ITERATIONS}"
        ));
    }
    let width = crate::ir::type_atom_bits(type_atom)
        .ok_or_else(|| format!("`accumulate`'s type `{type_atom}` is not a type atom"))?;
    let term = &items[5];
    if mentions(term, index_name) == 0 {
        return Err(format!(
            "`accumulate`'s term does not name `{index_name}`, so every term is the same \
             value; write it once"
        ));
    }

    if order == Order::Exact {
        if type_atom.starts_with('f') {
            return Err(
                "`(order exact)` is an integer claim: floating-point addition is not \
                 associative, so an FP accumulation names `sequential` or `pairwise`"
                    .to_string(),
            );
        }
        if grows {
            let term_bits = magnitude_bits(term, width);
            // The sum of `count` terms of `term_bits` magnitude needs
            // `term_bits + ceil(log2(count))` bits, and one more for a sign the
            // operands may carry. A product needs the count as a multiplier
            // rather than an addend, which is why `mul` almost never fits and
            // says so with the arithmetic rather than by rounding.
            let needed = if op == "add" {
                term_bits.saturating_add(ceil_log2(count)).saturating_add(1)
            } else {
                term_bits.saturating_mul(count.min(64) as u32)
            };
            if needed > width {
                return Err(format!(
                    "`(order exact)` over {count} terms of at most {term_bits} bits needs \
                     {needed} bits and the accumulator is {width}; every association gives \
                     one answer only while no partial result is lost"
                ));
            }
        }
    }

    let terms: Vec<SemanticExpr> = (0..count)
        .map(|step| {
            substitute_index(term, index_name, &SemanticExpr::Atom(step.to_string()))
        })
        .collect();
    let folded = fold(&terms, op, type_atom, order);
    if count_nodes(&folded) > MAX_NODES {
        return Err(format!(
            "`accumulate` over {count} terms expands past {MAX_NODES} nodes"
        ));
    }
    Ok(folded)
}

/// Nest the terms into one expression in the given order.
fn fold(terms: &[SemanticExpr], op: &str, type_atom: &str, order: Order) -> SemanticExpr {
    if terms.len() == 1 {
        return terms[0].clone();
    }
    let node = |left: SemanticExpr, right: SemanticExpr| {
        SemanticExpr::List(vec![
            SemanticExpr::Atom(op.to_string()),
            SemanticExpr::Atom(type_atom.to_string()),
            left,
            right,
        ])
    };
    match order {
        Order::Sequential => {
            let mut folded = terms[0].clone();
            for term in &terms[1..] {
                folded = node(folded, term.clone());
            }
            folded
        }
        Order::Pairwise | Order::Exact => {
            // Split rounding up, so the left half is never smaller. The same
            // rule `scalable::fold` uses, and written down for the same reason:
            // a fold shape that varies with how the division rounded is not a
            // shape at all.
            let mid = terms.len().div_ceil(2);
            node(
                fold(&terms[..mid], op, type_atom, order),
                fold(&terms[mid..], op, type_atom, order),
            )
        }
    }
}

/// An upper bound on how many bits the magnitude of `expr` can occupy.
///
/// Conservative by construction: anything this does not recognise is assumed to
/// fill the evaluation width, so the obligation refuses rather than guesses. It
/// recognises the shapes a contraction's term actually has -- a masked slice, a
/// sign- or zero-extended narrow value, a product of two of those -- which is
/// enough for `i8 x i8 -> i32` to be provably exact and for an accumulator one
/// size too small to be refused with the arithmetic.
fn magnitude_bits(expr: &SemanticExpr, width: u32) -> u32 {
    match expr {
        SemanticExpr::Atom(atom) => match integer_literal(atom) {
            Some(value) => 128 - value.leading_zeros(),
            None => width,
        },
        SemanticExpr::List(items) => {
            let Some(SemanticExpr::Atom(op)) = items.first() else {
                return width;
            };
            let args: Vec<&SemanticExpr> = items
                .iter()
                .skip(1)
                .filter(|item| {
                    !matches!(item, SemanticExpr::Atom(atom) if crate::ir::type_atom_bits(atom).is_some())
                })
                .collect();
            let bound = |index: usize| {
                args.get(index)
                    .map(|arg| magnitude_bits(arg, width))
                    .unwrap_or(width)
            };
            let literal = |index: usize| {
                args.get(index).and_then(|arg| match arg {
                    SemanticExpr::Atom(atom) => integer_literal(atom),
                    _ => None,
                })
            };
            match op.as_str() {
                "and" => {
                    // A mask caps the result at the mask's own width, whichever
                    // side it is on.
                    let masks: Vec<u32> = (0..args.len())
                        .map(|index| match literal(index) {
                            Some(value) => 128 - value.leading_zeros(),
                            None => bound(index),
                        })
                        .collect();
                    masks.into_iter().min().unwrap_or(width)
                }
                "or" | "xor" => (0..args.len()).map(bound).max().unwrap_or(width),
                "lshr" => match literal(1) {
                    Some(shift) => bound(0).saturating_sub(shift as u32),
                    None => bound(0),
                },
                "shl" => match literal(1) {
                    Some(shift) => bound(0).saturating_add(shift as u32).min(width),
                    None => width,
                },
                // The extends carry their source width as the first argument,
                // and that width is exactly the answer: a value sign-extended
                // from n bits has a magnitude of at most 2^(n-1), which n bits
                // hold with its sign.
                "sext" | "zext" => match literal(0) {
                    Some(from) => (from as u32).min(width),
                    None => width,
                },
                "mul" => (0..args.len())
                    .map(bound)
                    .fold(0u32, |total, bits| total.saturating_add(bits))
                    .min(width),
                "add" | "sub" => (0..args.len())
                    .map(bound)
                    .max()
                    .unwrap_or(width)
                    .saturating_add(ceil_log2(args.len().max(1) as u128))
                    .min(width),
                "select" => bound(1).max(bound(2)),
                _ => width,
            }
        }
    }
}

fn ceil_log2(value: u128) -> u32 {
    if value <= 1 {
        return 0;
    }
    128 - (value - 1).leading_zeros()
}

/// How many times `name` appears as an atom.
fn mentions(expr: &SemanticExpr, name: &str) -> usize {
    match expr {
        SemanticExpr::Atom(atom) => usize::from(atom == name),
        SemanticExpr::List(items) => items.iter().map(|item| mentions(item, name)).sum(),
    }
}

/// Replace the index with a literal. An accumulation has no accumulator name to
/// substitute, which is the difference that makes its association free.
fn substitute_index(
    expr: &SemanticExpr,
    index_name: &str,
    index_value: &SemanticExpr,
) -> SemanticExpr {
    match expr {
        SemanticExpr::Atom(atom) => {
            if atom == index_name {
                index_value.clone()
            } else {
                expr.clone()
            }
        }
        SemanticExpr::List(items) => SemanticExpr::List(
            items
                .iter()
                .map(|item| substitute_index(item, index_name, index_value))
                .collect(),
        ),
    }
}

/// Replace the index with a literal and the accumulator with what it holds.
fn substitute(
    expr: &SemanticExpr,
    index_name: &str,
    index_value: &SemanticExpr,
    acc_name: &str,
    acc_value: &SemanticExpr,
) -> SemanticExpr {
    match expr {
        SemanticExpr::Atom(atom) => {
            if atom == index_name {
                index_value.clone()
            } else if atom == acc_name {
                acc_value.clone()
            } else {
                expr.clone()
            }
        }
        SemanticExpr::List(items) => SemanticExpr::List(
            items
                .iter()
                .map(|item| substitute(item, index_name, index_value, acc_name, acc_value))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrolls_an_accumulating_body() {
        let text = "(iterate i32 (i 3) (acc 0) (add i32 acc i))";
        assert_eq!(
            expand_loop_text(text).unwrap(),
            "(add i32 (add i32 (add i32 0 0) 1) 2)"
        );
    }

    #[test]
    fn expresses_what_lane_expansion_cannot() {
        // Each iteration reads the previous one's result. Lane expansion
        // requires lane-*local* operators precisely because lanes are
        // independent, so this shape has no lane-wise spelling at all.
        let text = "(iterate i32 (i 4) (acc x) (add i32 acc acc))";
        let expanded = expand_loop_text(text).unwrap();
        assert!(expanded.starts_with("(add i32 (add i32"), "{expanded}");
    }

    #[test]
    fn a_zero_trip_loop_is_its_initial_value() {
        assert_eq!(expand_loop_text("(iterate i32 (i 0) (acc 7) (add i32 acc i))").unwrap(), "7");
    }

    #[test]
    fn nested_loops_expand_innermost_first() {
        let text = "(iterate i32 (o 2) (outer 0) (add i32 outer (iterate i32 (i 2) (acc 0) (add i32 acc i))))";
        let expanded = expand_loop_text(text).unwrap();
        assert!(!expanded.contains("iterate"), "{expanded}");
        assert!(expanded.contains("(add i32 (add i32 0 0) 1)"), "{expanded}");
    }

    #[test]
    fn a_non_literal_count_is_refused() {
        let error = expand_loop_text("(iterate i32 (i n) (acc 0) (add i32 acc i))").unwrap_err();
        assert!(error.contains("is not a literal"), "{error}");
    }

    #[test]
    fn an_unbounded_count_is_refused() {
        let error =
            expand_loop_text("(iterate i32 (i 4096) (acc 0) (add i32 acc i))").unwrap_err();
        assert!(error.contains("maximum is"), "{error}");
    }

    #[test]
    fn a_doubling_body_is_diagnosed_rather_than_hung_on() {
        let error =
            expand_loop_text("(iterate i32 (i 64) (acc x) (add i32 acc acc))").unwrap_err();
        assert!(error.contains("doubles"), "{error}");
    }

    #[test]
    fn documents_without_loops_are_untouched() {
        assert_eq!(expand_loop_text("(add i32 a b)").unwrap(), "(add i32 a b)");
    }
}

#[cfg(test)]
mod accumulate_tests {
    use super::*;

    fn expand(text: &str) -> Result<String, String> {
        expand_loop_text(text)
    }

    #[test]
    fn a_sequential_accumulation_is_a_left_fold() {
        assert_eq!(
            expand("(accumulate i32 add (k 3) (order sequential) (mul i32 k k))").unwrap(),
            "(add i32 (add i32 (mul i32 0 0) (mul i32 1 1)) (mul i32 2 2))"
        );
    }

    #[test]
    fn a_pairwise_accumulation_is_a_tree() {
        assert_eq!(
            expand("(accumulate i32 add (k 4) (order pairwise) (mul i32 k k))").unwrap(),
            "(add i32 (add i32 (mul i32 0 0) (mul i32 1 1)) \
             (add i32 (mul i32 2 2) (mul i32 3 3)))"
                .replace("             ", "")
                .as_str()
        );
    }

    #[test]
    fn exact_folds_shallow_so_a_long_contraction_fits() {
        // The point of the whole form. A left fold of 1024 terms nests 1024
        // deep and `semantics::MAX_EXPR_DEPTH` refuses it; the same terms
        // folded in halves are ten levels.
        let text = "(accumulate i32 add (k 1024) (order exact) \
                    (mul i32 (and i32 (lshr i32 a k) 255) (and i32 (lshr i32 b k) 255)))";
        let expanded = expand(text).unwrap();
        let parsed = crate::semantics::parse_formal_semantics(&expanded).unwrap();
        let depth = crate::semantics::expression_depth(&parsed);
        assert!(depth < 20, "1024 terms folded {depth} deep");
        assert!(depth > 10, "a tree over 1024 terms cannot be {depth} deep");
    }

    #[test]
    fn exact_checks_that_nothing_is_lost() {
        // i8 x i8 products summed 64 times: 16 bits of product, 6 of count,
        // one of sign -- 23, which an i32 holds with room.
        let good = "(accumulate i32 add (k 64) (order exact) \
                    (mul i32 (sext i32 8 (lshr i32 a k)) (sext i32 8 (lshr i32 b k))))";
        expand(good).unwrap();
        // The same contraction into an i16 cannot be exact, and the refusal
        // states the arithmetic rather than a rule.
        let narrow = "(accumulate i16 add (k 64) (order exact) \
                      (mul i16 (sext i16 8 (lshr i16 a k)) (sext i16 8 (lshr i16 b k))))";
        let error = expand(narrow).unwrap_err();
        assert!(error.contains("needs"), "{error}");
        assert!(error.contains("accumulator is 16"), "{error}");
    }

    #[test]
    fn exact_is_an_integer_claim() {
        let error = expand("(accumulate f32 fadd (k 4) (order exact) (fmul f32 k k))")
            .unwrap_err();
        assert!(error.contains("not associative"), "{error}");
    }

    #[test]
    fn an_accumulation_folds_an_associative_operator() {
        let error = expand("(accumulate i32 sub (k 4) (order exact) (mul i32 k k))")
            .unwrap_err();
        assert!(error.contains("associative"), "{error}");
    }

    #[test]
    fn a_term_that_ignores_the_index_is_refused() {
        // Every term identical means the fold is a multiply by the count
        // written the long way, and the shape hides that it says nothing.
        let error = expand("(accumulate i32 add (k 8) (order exact) (mul i32 a b))")
            .unwrap_err();
        assert!(error.contains("does not name"), "{error}");
    }

    #[test]
    fn the_bitwise_operators_need_no_obligation() {
        // `and` over any number of full-width terms stays in width, so exact
        // costs nothing to claim and is not refused for want of headroom.
        expand("(accumulate i32 and (k 64) (order exact) (lshr i32 a k))").unwrap();
    }
}
