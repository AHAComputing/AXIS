use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticExpr {
    Atom(String),
    List(Vec<SemanticExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticError {
    pub message: String,
}

impl SemanticError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "semantic error: {}", self.message)
    }
}

pub fn parse_formal_semantics(source: &str) -> Result<SemanticExpr, SemanticError> {
    let expression =
        crate::lisp::read_one(source).map_err(|error| SemanticError::new(error.to_string()))?;
    semantic_expr(expression)
}

/// The deepest expression every backend can emit.
///
/// ⚠️ MEASURED, not chosen, and the measurement was a crash. `iterate` bounds
/// its expansion by iteration count (1024) and node count (200000), and a
/// contraction passes both while building a chain as deep as its trip count:
/// `(add acc (mul ...))` folded left is one level per iteration. Every emitter
/// walks that chain recursively, so at K = 1024 a description that `axis check`
/// accepted aborted the process:
///
/// ```text
///   thread 'main' has overflowed its stack
///   fatal runtime error: stack overflow, aborting
/// ```
///
/// The walls, measured per backend on a debug build (the worst case, since its
/// frames are the largest), as the depth of the expression each last survived:
///
/// ```text
///   emit-llvm-ir       463   crashes by 483
///   emit-smt2         ~903
///   emit-semantics-c  ~903   and Rust with it
///   emit-golden-python       survived every depth tried
/// ```
///
/// 400 is below the lowest of those with room to spare, and far above anything
/// described: the deepest expression in the whole corpus is **35**, a bit
/// reversal in `examples/loops.axisl`. So this refuses nothing anyone writes
/// and refuses everything that would abort an emitter -- which is the shape a
/// limit should have. Raising it is `docs/tensor_design.md` T6b's job, and the
/// way to raise it is to stop recursing rather than to pick a bigger number.
pub const MAX_EXPR_DEPTH: usize = 400;

/// How deeply `expr` nests.
///
/// Iterative, with an explicit stack, because a recursive depth check would
/// overflow on exactly the expressions it exists to refuse.
pub fn expression_depth(expr: &SemanticExpr) -> usize {
    let mut deepest = 0;
    let mut pending = vec![(expr, 1usize)];
    while let Some((node, depth)) = pending.pop() {
        deepest = deepest.max(depth);
        if let SemanticExpr::List(items) = node {
            for item in items {
                pending.push((item, depth + 1));
            }
        }
    }
    deepest
}

pub fn validate_formal_semantics(
    source: &str,
    available_symbols: &[String],
) -> Result<(), SemanticError> {
    if source.trim().is_empty() {
        return Ok(());
    }
    let expr = parse_formal_semantics(source)?;
    let depth = expression_depth(&expr);
    if depth > MAX_EXPR_DEPTH {
        return Err(SemanticError::new(format!(
            "expression nests {depth} deep and the limit is {MAX_EXPR_DEPTH}; \
             every backend walks it recursively and the deepest one emits is \
             around 470, so this would abort an emitter rather than fail. A \
             left-folded accumulation is one level per step -- fold it in \
             halves, or reduce the trip count"
        )));
    }
    // Well-formedness (operators, arity, type atoms, extend source widths) is
    // exactly a successful lowering into the typed IR; symbol scoping is the
    // one check the IR leaves open. The ambient width is immaterial here.
    let sem = crate::ir::lower(&expr, 32)?;
    crate::ir::check_symbols(&sem, available_symbols)
}

fn semantic_expr(expression: crate::lisp::SExpr) -> Result<SemanticExpr, SemanticError> {
    use crate::lisp::SExprKind;
    match expression.kind {
        SExprKind::Atom(atom) => Ok(SemanticExpr::Atom(atom)),
        SExprKind::String(_) => Err(SemanticError::new(format!(
            "string literal at {}:{} is not valid in formal semantics",
            expression.span.line, expression.span.column
        ))),
        SExprKind::List(items) if items.is_empty() => Err(SemanticError::new(format!(
            "empty expression list at {}:{}",
            expression.span.line, expression.span.column
        ))),
        SExprKind::List(items) => Ok(SemanticExpr::List(
            items
                .into_iter()
                .map(semantic_expr)
                .collect::<Result<Vec<_>, _>>()?,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_typed_arithmetic_expr() {
        let symbols = vec!["rs1".to_string(), "rs2".to_string(), "rs3".to_string()];
        validate_formal_semantics("(add i32 (mul i32 rs1 rs2) rs3)", &symbols).unwrap();
    }

    #[test]
    fn validates_lexical_bindings_and_conditionals() {
        let symbols = vec![
            "condition".to_string(),
            "lhs".to_string(),
            "rhs".to_string(),
        ];
        validate_formal_semantics(
            "(let ((sum (add i32 lhs rhs)) (difference (sub i32 lhs rhs))) \
             (if i32 condition sum difference))",
            &symbols,
        )
        .unwrap();
    }

    #[test]
    fn rejects_malformed_and_duplicate_let_bindings() {
        let symbols = vec!["x".to_string()];
        let error =
            validate_formal_semantics("(let ((value x) (value 1)) value)", &symbols).unwrap_err();
        assert!(error
            .to_string()
            .contains("duplicate `let` binding `value`"));
        let error = validate_formal_semantics("(let (value) value)", &symbols).unwrap_err();
        assert!(error
            .to_string()
            .contains("each `let` binding must be `(name expression)`"));
    }

    #[test]
    fn rejects_unknown_operator() {
        let symbols = vec!["rs1".to_string(), "rs2".to_string()];
        let err = validate_formal_semantics("(dot4_i8 i32 rs1 rs2)", &symbols).unwrap_err();
        assert!(err
            .to_string()
            .contains("unsupported formal_semantics operator"));
    }

    #[test]
    fn rejects_unknown_symbol() {
        let symbols = vec!["rs1".to_string()];
        let err = validate_formal_semantics("(add i32 rs1 rs2)", &symbols).unwrap_err();
        assert!(err
            .to_string()
            .contains("unknown formal_semantics symbol `rs2`"));
    }

    #[test]
    fn type_atoms_do_not_count_as_value_args() {
        let symbols = vec!["rs1".to_string()];
        let err = validate_formal_semantics("(add i32 rs1)", &symbols).unwrap_err();
        assert!(err
            .to_string()
            .contains("operator `add` expects at least 2 arguments"));
    }

    #[test]
    fn validates_zbb_class_operators() {
        let symbols = vec!["rs1".to_string(), "rs2".to_string()];
        for expr in [
            "(sra i32 rs1 rs2)",
            "(ashr i32 rs1 rs2)",
            "(rol i32 rs1 rs2)",
            "(ror i32 rs1 rs2)",
            "(min i32 rs1 rs2)",
            "(max i32 rs1 rs2)",
            "(minu i32 rs1 rs2)",
            "(maxu i32 rs1 rs2)",
            "(not i32 rs1)",
            "(clz i32 rs1)",
            "(ctz i32 rs1)",
            "(cpop i32 rs1)",
            "(sext i32 8 rs1)",
            "(zext i32 16 rs1)",
            "(and i32 rs1 (not i32 rs2))",
        ] {
            validate_formal_semantics(expr, &symbols)
                .unwrap_or_else(|err| panic!("{expr} should validate: {err}"));
        }
    }

    #[test]
    fn rejects_wrong_arity_for_new_operators() {
        let symbols = vec!["rs1".to_string(), "rs2".to_string()];
        let err = validate_formal_semantics("(clz i32 rs1 rs2)", &symbols).unwrap_err();
        assert!(err
            .to_string()
            .contains("operator `clz` expects 1 argument"));
        let err = validate_formal_semantics("(rol i32 rs1)", &symbols).unwrap_err();
        assert!(err
            .to_string()
            .contains("operator `rol` expects 2 arguments"));
    }

    #[test]
    fn sext_requires_integer_source_width() {
        let symbols = vec!["rs1".to_string(), "rs2".to_string()];
        let err = validate_formal_semantics("(sext i32 rs2 rs1)", &symbols).unwrap_err();
        assert!(err
            .to_string()
            .contains("integer source-width literal as its first argument"));
        validate_formal_semantics("(sext i32 8 rs1)", &symbols).unwrap();
    }
}
