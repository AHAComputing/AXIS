//! Typed semantic IR.
//!
//! `formal_semantics` reaches AXIS as an untyped s-expression
//! ([`SemanticExpr`]). Historically every backend — the validator, the
//! OptiSynth normalizer, and the C / SMT emitters — re-walked that raw tree,
//! each independently re-deriving the same facts: which leading atom is a
//! type annotation, how the evaluation width flows into sub-expressions, how
//! integer literals parse, and what arity each operator takes. The `sext`/
//! `zext` "first value argument is a source-width literal" rule was open-coded
//! in three places.
//!
//! This module resolves all of that exactly once. [`lower`] turns a parsed
//! s-expression into a [`Sem`] tree in which every node already carries its
//! resolved evaluation width, operators are normalized (aliases collapsed:
//! `sll`→`shl`, `srl`→`lshr`, `sra`→`ashr`), literals are decoded to numeric
//! values, and `sext`/`zext` carry their source width as a field. Backends
//! then lower from [`Sem`] with a single exhaustive match and no re-derivation.
//!
//! Lowering is intentionally the same normalization the validator performs, so
//! a successful `lower` is exactly a well-formed expression. The surface-level
//! `semantics.json` reflector deliberately does *not* go through this IR: it
//! preserves the original operator spelling, literal form, and type atom.

use crate::semantics::{SemanticError, SemanticExpr};
use std::collections::HashMap;

/// Normalized semantic operator. Source-level aliases are collapsed here
/// (`sll`/`srl`/`sra` → [`Op::Shl`]/[`Op::Lshr`]/[`Op::Ashr`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Op {
    Add,
    Sub,
    Mul,
    Udiv,
    Sdiv,
    Urem,
    Srem,
    And,
    Or,
    Xor,
    Shl,
    Lshr,
    Ashr,
    Rol,
    Ror,
    Not,
    Clz,
    Ctz,
    Cpop,
    MinS,
    MaxS,
    MinU,
    MaxU,
    Select,
    Sext,
    Zext,
    /// IEEE-754 arithmetic. These reinterpret their bit-vector arguments as
    /// floats of the operator's width, compute in round-to-nearest-even, and
    /// return the result's bit pattern. A NaN result is the canonical quiet
    /// NaN, specified by AXIS rather than inherited from the host, so the
    /// backends agree bit-for-bit on every platform.
    Fadd,
    Fsub,
    Fmul,
    Fdiv,
    /// Correctly-rounded square root.
    Fsqrt,
    /// The same arithmetic under an explicit rounding mode, whose 2-bit value
    /// is the operator's **first** argument: `00` nearest-even, `01` toward
    /// +infinity, `10` toward -infinity, `11` toward zero — AArch64's
    /// `FPCR.RMode` encoding.
    ///
    /// Mode-first rather than mode-last because the folding forms are n-ary: a
    /// trailing argument cannot be told apart from a third addend. Taking the
    /// mode as an argument rather than reading FPCR implicitly is what keeps the
    /// IR a function of its arguments — the state dependency lives in the
    /// behavior that computes the mode, where it is visible. See
    /// `docs/simd_fp_design.md` section 8.
    FaddRm,
    FsubRm,
    FmulRm,
    FdivRm,
    FsqrtRm,
    /// A fused multiply-add under an explicit rounding mode. The mode is
    /// argument zero, as it is for the others; the fusion is what makes this a
    /// separate operator and not `fadd_rm` over `fmul_rm`, which rounds twice.
    FmaRm,
    /// The IEEE-754 exceptions the same arithmetic *raises*, as RISC-V's
    /// five-bit `fflags`: invalid 16, divide-by-zero 8, overflow 4, underflow
    /// 2, inexact 1.
    ///
    /// Same operands as the value form and one result beside it, because a
    /// floating-point operation produces two things and a description that
    /// states only the first describes a machine whose exception flags never
    /// move. An instruction accrues them:
    ///
    /// ```text
    /// (setstate fflags (or i5 fflags (fdiv_fx f64 rs1 rs2)) i5)
    /// ```
    ///
    /// A separate operator rather than a second result on the arithmetic
    /// because the effect model gives one value per write, and because most
    /// instructions in most descriptions do not want the flags at all.
    ///
    /// Inexact is why this cannot be written out of existing operators the way
    /// `fclass` was: it asks whether the *exact* result is representable, which
    /// is a question about a value no bit pattern holds. The other four are
    /// predicates on the operands and the result, but splitting them would put
    /// four fifths of a flag word in the description and one fifth in an
    /// operator, which is worse than either.
    FaddFx,
    FsubFx,
    FmulFx,
    FdivFx,
    FsqrtFx,
    FmaFx,
    /// The high half of a double-width product, at the operator's width.
    ///
    /// This cannot be composed from the other operators, and the reason is worth
    /// stating: every backend evaluates a function at one width taken from its
    /// boundary, so an expression that widens internally — multiply at twice the
    /// width, keep the top half — is computed at the narrow width and the shift
    /// falls off the end. AArch64 hit this and worked around it with the
    /// ISA-specific `a64_smulh`/`a64_umulh` helpers; RISC-V's `MULH`/`MULHU`/
    /// `MULHSU` need the same thing, which is the second ISA's evidence that it
    /// belongs in the portable set. Each backend widens internally, which is
    /// where the widening belongs.
    ///
    /// `Mulhsu` is the mixed form RISC-V needs: the first operand signed, the
    /// second unsigned.
    Mulh,
    Mulhu,
    Mulhsu,
    /// Integer comparisons, returning 1 or 0 at the operator's width.
    ///
    /// AArch64 never needed these: it compares by writing NZCV and testing it,
    /// so comparison lives in `a64_sub_nzcv` and `a64_cond_holds`. RISC-V has no
    /// flags — `slt` *is* an arithmetic instruction and the branches compare
    /// directly — so a second ISA is what made these necessary. The six are
    /// exactly RISC-V's branch set; the missing directions (`sgt`, `sle`, and
    /// their unsigned twins) are the same operators with the operands swapped.
    IcmpEq,
    IcmpNe,
    IcmpSlt,
    IcmpSge,
    IcmpUlt,
    IcmpUge,
    /// IEEE-754 comparisons, returning 1 or 0 at the operator's width. The
    /// ordered forms are false when either operand is NaN — NaN is unordered
    /// with everything, itself included — and `FcmpUno` is the predicate that
    /// detects exactly that case. `-0.0` and `+0.0` compare equal, which is why
    /// these cannot be bit comparisons.
    FcmpOeq,
    FcmpOlt,
    FcmpOle,
    FcmpUno,
    /// Conversions. Like `sext`/`zext` these carry two widths: the type atom
    /// gives the destination and the first literal argument the source, so they
    /// lower through [`Sem::Ext`].
    ///
    /// Float to integer rounds toward zero and **saturates**, with NaN mapping
    /// to 0. That rule is specified by AXIS rather than inherited: the C cast is
    /// undefined out of range, ARM saturates, and x86 returns the most negative
    /// integer, so a description that left it open would mean something
    /// different on each backend.
    FcvtF2S,
    FcvtF2U,
    /// Integer to float, round-to-nearest-even.
    FcvtS2F,
    FcvtU2F,
    /// Float to float: widening is exact, narrowing rounds to nearest-even and
    /// may overflow to an infinity.
    FcvtF2F,
    /// The exceptions a conversion raises, as the `_fx` forms of the five
    /// conversions above. They take exactly the value form's arguments -- a
    /// destination type atom, a source-width literal, and the value -- and
    /// return the flag word, so the two spellings stay readable against each
    /// other at a glance.
    ///
    /// Unlike arithmetic, a conversion's *invalid* is not about NaN alone:
    /// float to integer signals invalid when the truncated value does not fit
    /// the destination, which is the saturation AXIS specifies made visible.
    /// Inexact is the ordinary question, asked of a value the destination
    /// format may be too narrow to hold.
    FcvtF2SFx,
    FcvtF2UFx,
    FcvtS2FFx,
    FcvtU2FFx,
    FcvtF2FFx,
    /// Negation of a float: the sign bit flipped and nothing else. It is not
    /// `0 - x`, which differs for zero and for NaN, and it is not an integer
    /// `xor` either -- that would be an integer operator over a float value,
    /// which the type atom would then be lying about. RISC-V needs it to say
    /// `FMSUB` and `FNMADD` at all: those are `a * b - c` and `-(a * b) - c`
    /// with *one* rounding, so the negation has to be inside the fused
    /// operation and cannot be an add of a negated operand.
    Fneg,
    /// A mask of `n` low bits: `(ones i64 32)` is `0x00000000ffffffff`, and
    /// `(ones i64)` with no count is every bit of the width. The count is an
    /// ordinary expression, so a mask can come from a length register rather
    /// than a literal -- which is the whole reason this is an operator and not
    /// a constant an author could write out.
    ///
    /// A count at or past the width gives every bit rather than wrapping or
    /// faulting. That is a decision, not an accident: a mask asked for more
    /// bits than the value holds, and the answer that loses nothing is all of
    /// them. Every backend states it, because `1 << n` says something
    /// different in each -- zero in SMT-LIB, poison in LLVM, undefined in C.
    Ones,
    /// The complement in spelling only: `(zeros i64 n)` is zero, whatever `n`
    /// is. It earns its place beside `ones` by naming what a bare `0` leaves
    /// the reader to infer -- a cleared mask of a particular shape -- and the
    /// count is accepted so the two read alike at a use site.
    Zeros,
    /// *Fused* multiply-add: one rounding over `a * b + c`, not two. The
    /// distinction is observable — see `examples/fp_fma.axisl` — which is why
    /// AXIS spells it explicitly instead of leaving a compiler to decide
    /// whether to contract a multiply and an add.
    Fma,
}

/// Operators whose type atom names the destination width and whose first
/// literal argument names the source width: the extends and the conversions.
pub fn is_two_width_op(op: Op) -> bool {
    matches!(
        op,
        Op::Sext
            | Op::Zext
            | Op::FcvtF2S
            | Op::FcvtF2U
            | Op::FcvtS2F
            | Op::FcvtU2F
            | Op::FcvtF2F
            | Op::FcvtF2SFx
            | Op::FcvtF2UFx
            | Op::FcvtS2FFx
            | Op::FcvtU2FFx
            | Op::FcvtF2FFx
    )
}

/// One floating-point format: what it is called, how wide it is, and the two
/// numbers that decide every question about it.
///
/// `significand` counts the implicit leading bit, matching SMT-LIB's
/// `(_ FloatingPoint eb sb)` and IEEE-754's `p`, so f32 is (8, 24) rather than
/// (8, 23). `canonical_nan` is AXIS's own quiet NaN for the format -- specified
/// here rather than inherited from a host, which is what lets six backends
/// agree bit-for-bit on a NaN result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloatFormat {
    pub name: &'static str,
    pub bits: u32,
    pub exponent: u32,
    pub significand: u32,
    pub canonical_nan: u128,
    /// Whether the floating-point *environment* is described for this format:
    /// the explicit-rounding (`fadd_rm`) and exception-word (`fadd_fx`) forms
    /// of stage F3.
    ///
    /// ⚠️ False is a REFUSAL, not a gap left to be discovered. Those two
    /// families carry their own arithmetic in the golden model -- exact
    /// rationals for inexactness, a subnormal threshold, a significand count --
    /// and that code still asks `width <= 32`. A format it has never been
    /// taught would be computed as single precision there while every other
    /// backend used the right one, which is the defect this whole table exists
    /// to have stopped. So the operator is refused for the format until the
    /// reference model can answer for it.
    pub environment: bool,
}

/// Every floating-point format AXIS describes.
///
/// ⚠️ A TABLE because every backend had grown its own COMPARISON. `float_helper`
/// picked its C and Rust helper with `if width > 32 { 64 } else { 32 }`, the SMT
/// emitter picked its sort with `(11, 53)` against `(8, 24)`, the LLVM emitter
/// picked `double` against `float`, and the golden model picked `'<d'` against
/// `'<f'` -- four places answering one question, each correct for exactly as
/// long as there are two formats. Measured before the guard that now stops it:
/// `(fadd f16 a b)` passed `axis check`, emitted `axis_fp32_add`, and produced
/// an SMT file z3 rejects with a sort error.
///
/// This is the same move `ast::REGISTER_CLASSES` made for register classes, for
/// the same reason and after the same kind of failure: the rule lived inline in
/// each backend, so a new one meant editing every one of them and hoping they
/// agreed. Adding a format is adding a row.
pub const FLOAT_FORMATS: &[FloatFormat] = &[
    FloatFormat {
        name: "f16",
        bits: 16,
        exponent: 5,
        significand: 11,
        canonical_nan: 0x7e00,
        environment: false,
    },
    FloatFormat {
        name: "f32",
        bits: 32,
        exponent: 8,
        significand: 24,
        canonical_nan: 0x7fc0_0000,
        environment: true,
    },
    FloatFormat {
        name: "f64",
        bits: 64,
        exponent: 11,
        significand: 53,
        canonical_nan: 0x7ff8_0000_0000_0000,
        environment: true,
    },
];

/// The format a float type atom of `bits` names, or `None` if AXIS describes
/// none.
///
/// ⚠️ Exact, not nearest. The comparison this replaced resolved an unknown
/// width to whichever side of 32 it fell on, which is how a 16-bit float came
/// to be computed in single precision. A width with no row is not a format --
/// `f8` most sharply, since two eight-bit formats are in common use and a
/// width does not choose between them.
pub fn float_format(bits: u32) -> Option<&'static FloatFormat> {
    FLOAT_FORMATS.iter().find(|format| format.bits == bits)
}

/// The same lookup by the atom's spelling, for the frontends that hold a name
/// rather than a width.
pub fn float_format_named(name: &str) -> Option<&'static FloatFormat> {
    FLOAT_FORMATS.iter().find(|format| format.name == name)
}

/// Which of an operator's widths name a floating-point format: `.0` the
/// evaluation width the type atom sets, `.1` the source width a two-width
/// conversion carries as its first literal argument.
///
/// The conversions are the reason this answers two questions rather than one.
/// `fcvt_f2s` reads a float and writes an integer, so its float side is the
/// *source*; `fcvt_s2f` is the other way round; `fcvt_f2f` is float on both
/// ends. A single "is this a float operator" predicate cannot say which width
/// to check, and checking the wrong one would refuse `(fcvt_f2s i16 32 x)` —
/// a perfectly ordinary narrowing convert to a 16-bit integer.
fn float_format_widths(op: Op) -> (bool, bool) {
    match op {
        // The float side is the source; the destination is an integer.
        Op::FcvtF2S | Op::FcvtF2U | Op::FcvtF2SFx | Op::FcvtF2UFx => (false, true),
        // The source is an integer; the destination is a float.
        Op::FcvtS2F | Op::FcvtU2F | Op::FcvtS2FFx | Op::FcvtU2FFx => (true, false),
        // Both ends are floats, and they differ — that is the whole operator.
        Op::FcvtF2F | Op::FcvtF2FFx => (true, true),
        // Ordinary arithmetic, the explicit-rounding forms, the exception-word
        // forms, and the comparisons: one width, and it is the format. The
        // `_fx` forms return a flag word rather than a float and are still
        // listed, because the type atom they carry is the format the flags are
        // raised *by* — `(fdiv_fx f64 rs1 rs2)` is a double division whose
        // exceptions are the value.
        Op::Fadd
        | Op::Fsub
        | Op::Fmul
        | Op::Fdiv
        | Op::Fsqrt
        | Op::Fneg
        | Op::Fma
        | Op::FaddRm
        | Op::FsubRm
        | Op::FmulRm
        | Op::FdivRm
        | Op::FsqrtRm
        | Op::FmaRm
        | Op::FaddFx
        | Op::FsubFx
        | Op::FmulFx
        | Op::FdivFx
        | Op::FsqrtFx
        | Op::FmaFx
        | Op::FcmpOeq
        | Op::FcmpOlt
        | Op::FcmpOle
        | Op::FcmpUno => (true, false),
        // ⚠️ The catch-all is integer operators, and it is also where a NEW
        // float operator would land silently. `is_float_op` is the tripwire
        // for that (asserted in `check_float_widths`), and it is deliberately
        // not reused as the predicate here: it answers "does this reinterpret
        // its bits as a float", which cannot say *which* of a conversion's two
        // widths is the float one, and it does not list the explicit-rounding
        // and exception-word families at all, because its only callers are the
        // two backends' `Sem::Ext` arms.
        _ => (false, false),
    }
}

/// Whether `op` is one of the floating-point *environment* forms: arithmetic
/// under an explicit rounding mode, or the exception word the same arithmetic
/// raises.
fn needs_float_environment(op: Op) -> bool {
    matches!(
        op,
        Op::FaddRm
            | Op::FsubRm
            | Op::FmulRm
            | Op::FdivRm
            | Op::FsqrtRm
            | Op::FmaRm
            | Op::FaddFx
            | Op::FsubFx
            | Op::FmulFx
            | Op::FdivFx
            | Op::FsqrtFx
            | Op::FmaFx
            | Op::FcvtF2SFx
            | Op::FcvtF2UFx
            | Op::FcvtS2FFx
            | Op::FcvtU2FFx
            | Op::FcvtF2FFx
    )
}

/// Refuse a float format this language does not describe.
fn check_float_widths(
    op: Op,
    op_name: &str,
    width: u32,
    from_bits: Option<u32>,
) -> Result<(), SemanticError> {
    let (value_is_float, source_is_float) = float_format_widths(op);
    debug_assert!(
        !is_float_op(op) || value_is_float || source_is_float,
        "`{op_name}` reinterprets its bits as a float and names no float width; \
         it needs a row in `float_format_widths`"
    );
    let check = |bits: u32, role: &str| {
        if float_format(bits).is_some() {
            return Ok(());
        }
        let known = FLOAT_FORMATS
            .iter()
            .map(|format| format.name.to_string())
            .collect::<Vec<_>>()
            .join(" and ");
        Err(err(format!(
            "operator `{op_name}` names a {bits}-bit float as its {role}, and AXIS \
             describes {known}"
        )))
    };
    if value_is_float {
        check(width, "value")?;
    }
    if source_is_float {
        if let Some(from_bits) = from_bits {
            check(from_bits, "source")?;
        }
    }
    // ⚠️ Asked of whichever end is the float, which for `fcvt_f2s_fx` is the
    // SOURCE. The first version asked only about the value width, so the
    // conversion exception forms -- half this family -- went unchecked.
    if needs_float_environment(op) {
        let float_bits = if value_is_float { Some(width) } else { from_bits };
        if let Some(format) = float_bits.and_then(float_format) {
            if !format.environment {
                return Err(err(format!(
                    "operator `{op_name}` is an explicit-rounding or exception form, \
                     which AXIS does not describe for {}",
                    format.name
                )));
            }
        }
    }
    Ok(())
}

/// Whether `op` is IEEE-754 arithmetic, whose arguments are bit patterns to be
/// reinterpreted rather than integers.
pub fn is_float_op(op: Op) -> bool {
    matches!(
        op,
        Op::Fadd
            | Op::Fsub
            | Op::Fmul
            | Op::Fdiv
            | Op::Fsqrt
            | Op::Fneg
            | Op::Fma
            | Op::FcmpOeq
            | Op::FcmpOlt
            | Op::FcmpOle
            | Op::FcmpUno
            | Op::FcvtF2S
            | Op::FcvtF2U
            | Op::FcvtS2F
            | Op::FcvtU2F
            | Op::FcvtF2F
            | Op::FcvtF2SFx
            | Op::FcvtF2UFx
            | Op::FcvtS2FFx
            | Op::FcvtU2FFx
            | Op::FcvtF2FFx
    )
}

/// A resolved semantic node. Every non-leaf carries the evaluation `width`
/// that applies to it and flows to its arguments.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Sem {
    /// A reference to an operand, port, or other named symbol. Whether the
    /// name is in scope is a separate concern (see [`check_symbols`]).
    Sym(String),
    /// A decoded integer literal at the ambient evaluation width.
    Int { value: u128, width: u32 },
    /// An n-ary/binary/unary operator application (everything except the
    /// extends). `args` length matches the operator's arity.
    App { op: Op, width: u32, args: Vec<Sem> },
    /// A sign/zero extension: `value` is reinterpreted from `from_bits` up to
    /// `width`.
    Ext {
        op: Op,
        width: u32,
        from_bits: u32,
        arg: Box<Sem>,
    },
    /// A call of a description-defined function (`deffun`): emitted once by
    /// every backend and called here, never inlined. Each argument is lowered
    /// at the width its parameter reads it at, and carries that width.
    Call {
        name: String,
        width: u32,
        args: Vec<(u32, Sem)>,
    },
}

/// Arity class of an operator, used for validation and for the message text.
enum Arity {
    /// Zero or one argument: an optional count, where absent means the width.
    ZeroOrOne,
    /// At least two arguments (associative/commutative folds).
    AtLeastTwo,
    /// Exactly two arguments.
    Two,
    /// Exactly three arguments.
    Three,
    /// At least three (an n-ary fold whose first argument is a rounding mode).
    AtLeastThree,
    /// Exactly one argument.
    One,
}

fn err(message: impl Into<String>) -> SemanticError {
    SemanticError {
        message: message.into(),
    }
}

/// Normalize a source operator spelling to its canonical [`Op`].
/// Whether this operator name is one of the six integer comparisons.
///
/// A guard is exactly "an expression whose operator compares", so the guard
/// vocabulary is this rather than a list repeated in each place that lowers one.
/// It had reached seven copies — two in the effect validator, the Lisp frontend,
/// two in the LLVM emitter, and three in the executor emitters — which is how a
/// language ends up accepting an operator in one backend and rejecting it in
/// another.
/// The IEEE-754 comparisons, which return 0 or 1 rather than a float.
///
/// Published beside the integer set for the same reason that one is: the
/// scalable vocabulary needs to know which operators are lane-local *and*
/// produce a predicate bit, and a second copy of this list would be a second
/// vocabulary that could drift.
pub fn is_float_comparison(name: &str) -> bool {
    matches!(
        normalize_op(name),
        Some(Op::FcmpOeq | Op::FcmpOlt | Op::FcmpOle | Op::FcmpUno)
    )
}

pub fn is_integer_comparison(name: &str) -> bool {
    matches!(
        normalize_op(name),
        Some(Op::IcmpEq | Op::IcmpNe | Op::IcmpSlt | Op::IcmpSge | Op::IcmpUlt | Op::IcmpUge)
    )
}

/// Whether `name` is an operator this IR carries.
pub fn is_operator(name: &str) -> bool {
    normalize_op(name).is_some()
}

fn normalize_op(name: &str) -> Option<Op> {
    Some(match name {
        "add" => Op::Add,
        "sub" => Op::Sub,
        "mul" => Op::Mul,
        "udiv" => Op::Udiv,
        "sdiv" => Op::Sdiv,
        "urem" => Op::Urem,
        "srem" => Op::Srem,
        "and" => Op::And,
        "or" => Op::Or,
        "xor" => Op::Xor,
        "shl" | "sll" => Op::Shl,
        "lshr" | "srl" => Op::Lshr,
        "sra" | "ashr" => Op::Ashr,
        "rol" => Op::Rol,
        "ror" => Op::Ror,
        "not" => Op::Not,
        "clz" => Op::Clz,
        "ctz" => Op::Ctz,
        "cpop" => Op::Cpop,
        "min" => Op::MinS,
        "max" => Op::MaxS,
        "minu" => Op::MinU,
        "maxu" => Op::MaxU,
        "if" | "select" => Op::Select,
        "sext" => Op::Sext,
        "zext" => Op::Zext,
        "mulh" => Op::Mulh,
        "mulhu" => Op::Mulhu,
        "mulhsu" => Op::Mulhsu,
        "icmp_eq" => Op::IcmpEq,
        "icmp_ne" => Op::IcmpNe,
        "icmp_slt" => Op::IcmpSlt,
        "icmp_sge" => Op::IcmpSge,
        "icmp_ult" => Op::IcmpUlt,
        "icmp_uge" => Op::IcmpUge,
        "fadd" => Op::Fadd,
        "fsub" => Op::Fsub,
        "fmul" => Op::Fmul,
        "fdiv" => Op::Fdiv,
        "fsqrt" => Op::Fsqrt,
        "fneg" => Op::Fneg,
        "fadd_rm" => Op::FaddRm,
        "fsub_rm" => Op::FsubRm,
        "fmul_rm" => Op::FmulRm,
        "fdiv_rm" => Op::FdivRm,
        "fsqrt_rm" => Op::FsqrtRm,
        "fma_rm" => Op::FmaRm,
        "fadd_fx" => Op::FaddFx,
        "fsub_fx" => Op::FsubFx,
        "fmul_fx" => Op::FmulFx,
        "fdiv_fx" => Op::FdivFx,
        "fsqrt_fx" => Op::FsqrtFx,
        "fma_fx" => Op::FmaFx,
        "fcmp_oeq" => Op::FcmpOeq,
        "fcmp_olt" => Op::FcmpOlt,
        "fcmp_ole" => Op::FcmpOle,
        "fcmp_uno" => Op::FcmpUno,
        "fcvt_f2s" => Op::FcvtF2S,
        "fcvt_f2u" => Op::FcvtF2U,
        "fcvt_s2f" => Op::FcvtS2F,
        "fcvt_u2f" => Op::FcvtU2F,
        "fcvt_f2f" => Op::FcvtF2F,
        "fcvt_f2s_fx" => Op::FcvtF2SFx,
        "fcvt_f2u_fx" => Op::FcvtF2UFx,
        "fcvt_s2f_fx" => Op::FcvtS2FFx,
        "fcvt_u2f_fx" => Op::FcvtU2FFx,
        "fcvt_f2f_fx" => Op::FcvtF2FFx,
        "fma" => Op::Fma,
        "ones" => Op::Ones,
        "zeros" => Op::Zeros,
        _ => return None,
    })
}

fn arity_of(op: Op) -> Arity {
    match op {
        Op::Add | Op::Mul | Op::And | Op::Or | Op::Xor | Op::Fadd | Op::Fmul => {
            Arity::AtLeastTwo
        }
        // The rounding mode is the first argument, so a fold needs three and a
        // square root two.
        Op::FaddRm | Op::FmulRm => Arity::AtLeastThree,
        Op::FsubRm | Op::FdivRm => Arity::Three,
        Op::FsqrtRm => Arity::Two,
        // A mode and three operands.
        Op::FmaRm => Arity::AtLeastThree,
        // The exception forms take exactly the value form's operands: no mode,
        // because which exceptions an operation raises does not depend on the
        // rounding direction except for inexact, and an inexact result is
        // inexact under every mode.
        Op::FaddFx | Op::FsubFx | Op::FmulFx | Op::FdivFx => Arity::Two,
        Op::FsqrtFx => Arity::One,
        Op::FmaFx => Arity::Three,
        Op::Sub
        | Op::Udiv
        | Op::Sdiv
        | Op::Urem
        | Op::Srem
        | Op::Shl
        | Op::Lshr
        | Op::Ashr
        | Op::Rol
        | Op::Ror
        | Op::MinS
        | Op::MaxS
        | Op::MinU
        | Op::MaxU
        | Op::Sext
        | Op::Zext
        | Op::FcvtF2S
        | Op::FcvtF2U
        | Op::FcvtS2F
        | Op::FcvtU2F
        | Op::FcvtF2F
        | Op::FcvtF2SFx
        | Op::FcvtF2UFx
        | Op::FcvtS2FFx
        | Op::FcvtU2FFx
        | Op::FcvtF2FFx
        | Op::Fsub
        | Op::Fdiv
        | Op::FcmpOeq
        | Op::FcmpOlt
        | Op::FcmpOle
        | Op::FcmpUno
        | Op::IcmpEq
        | Op::IcmpNe
        | Op::IcmpSlt
        | Op::IcmpSge
        | Op::IcmpUlt
        | Op::IcmpUge
        | Op::Mulh
        | Op::Mulhu
        | Op::Mulhsu => Arity::Two,
        Op::Select | Op::Fma => Arity::Three,
        Op::Not | Op::Clz | Op::Ctz | Op::Cpop | Op::Fsqrt | Op::Fneg => Arity::One,
        Op::Ones | Op::Zeros => Arity::ZeroOrOne,
    }
}

/// Check argument count against the operator's arity. `name` is the original
/// source spelling so error text matches what the author wrote.
fn check_arity(op: Op, name: &str, count: usize) -> Result<(), SemanticError> {
    let ok = match arity_of(op) {
        Arity::AtLeastTwo => count >= 2,
        Arity::AtLeastThree => count >= 3,
        Arity::Two => count == 2,
        Arity::Three => count == 3,
        Arity::One => count == 1,
        Arity::ZeroOrOne => count <= 1,
    };
    if ok {
        return Ok(());
    }
    let expectation = match arity_of(op) {
        Arity::AtLeastTwo => "at least 2 arguments".to_string(),
        Arity::AtLeastThree => "at least 3 arguments (a rounding mode and two values)".to_string(),
        Arity::Two => "2 arguments".to_string(),
        Arity::Three => "3 arguments".to_string(),
        Arity::One => "1 argument".to_string(),
        Arity::ZeroOrOne => "an optional bit count and nothing else".to_string(),
    };
    Err(err(format!("operator `{name}` expects {expectation}")))
}

/// A type atom is `i`/`u` followed by decimal digits (`i32`, `u8`). Matches
/// the historical predicate the emitters used, including the degenerate bare
/// `i`/`u` (which resolves to no width and leaves the ambient width intact).
pub fn is_type_atom(atom: &str) -> bool {
    let mut chars = atom.chars();
    matches!(chars.next(), Some('i') | Some('u') | Some('f'))
        && chars.all(|ch| ch.is_ascii_digit())
}

/// The width a type atom names, or `None` if it is not a type atom. Callers
/// that used to re-derive this locally drifted when `f32`/`f64` were added:
/// the wide executor's effect lowering kept an `i`/`u`-only copy and so treated
/// `f64` as an unbound symbol, silently turning it into a state read.
pub fn type_atom_bits(atom: &str) -> Option<u32> {
    if !is_type_atom(atom) {
        return None;
    }
    type_atom_width(atom)
}

pub(crate) fn type_atom_width(atom: &str) -> Option<u32> {
    atom.get(1..)?.parse::<u32>().ok()
}

/// Decode a decimal or `0x`-hex integer literal. Returns `None` for anything
/// that is not a literal (i.e. a symbol).
pub fn integer_literal(atom: &str) -> Option<u128> {
    if let Some(hex) = atom.strip_prefix("0x").or_else(|| atom.strip_prefix("0X")) {
        if hex.is_empty() || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return None;
        }
        return u128::from_str_radix(hex, 16).ok();
    }
    if !atom.is_empty() && atom.chars().all(|ch| ch.is_ascii_digit()) {
        return atom.parse::<u128>().ok();
    }
    None
}

/// Lower a parsed s-expression into the typed IR at ambient `width`. A leading
/// type atom on a list overrides the width for that node and everything below
/// it. Fails with the same diagnostics the validator reports.
pub fn lower(expr: &SemanticExpr, width: u32) -> Result<Sem, SemanticError> {
    lower_with_bindings(expr, width, &HashMap::new())
}

fn lower_with_bindings(
    expr: &SemanticExpr,
    width: u32,
    bindings: &HashMap<String, Sem>,
) -> Result<Sem, SemanticError> {
    match expr {
        SemanticExpr::Atom(atom) => match integer_literal(atom) {
            Some(value) => Ok(Sem::Int { value, width }),
            None => Ok(bindings
                .get(atom)
                .cloned()
                .unwrap_or_else(|| Sem::Sym(atom.clone()))),
        },
        SemanticExpr::List(items) => {
            let Some(SemanticExpr::Atom(op_name)) = items.first() else {
                return Err(err(
                    "formal_semantics list must start with an operator atom",
                ));
            };
            let raw_args = &items[1..];
            if op_name == "call" {
                // `(call name iR (iP arg) ...)`, as the elaborator writes a
                // `deffun` call.
                let (Some(SemanticExpr::Atom(name)), Some(SemanticExpr::Atom(result))) =
                    (raw_args.first(), raw_args.get(1))
                else {
                    return Err(err("`call` expects a function name and a result type"));
                };
                let width = type_atom_width(result)
                    .ok_or_else(|| err(format!("`call {name}` result type `{result}` is not iN")))?;
                let mut args = Vec::new();
                for arg in &raw_args[2..] {
                    let SemanticExpr::List(pair) = arg else {
                        return Err(err(format!("`call {name}` arguments are `(iN value)`")));
                    };
                    let (Some(SemanticExpr::Atom(ty)), Some(value), 2) = (pair.first(), pair.get(1), pair.len()) else {
                        return Err(err(format!("`call {name}` arguments are `(iN value)`")));
                    };
                    let param = type_atom_width(ty)
                        .ok_or_else(|| err(format!("`call {name}` argument type `{ty}` is not iN")))?;
                    args.push((param, lower_with_bindings(value, param, bindings)?));
                }
                return Ok(Sem::Call { name: name.clone(), width, args });
            }
            if op_name == "let" {
                if raw_args.len() != 2 {
                    return Err(err("`let` expects a binding list and one body expression"));
                }
                let SemanticExpr::List(raw_bindings) = &raw_args[0] else {
                    return Err(err("`let` bindings must be a list"));
                };
                let mut names = std::collections::HashSet::new();
                // ⚠️ SEQUENTIAL, matching the elaborator. The scope grows as
                // the bindings are lowered, so a later one may name an
                // earlier. Bindings are INLINED here -- no `Let` survives into
                // the IR -- so fixing the scope here is what makes every
                // consumer of the IR sequential too.
                let mut scope = bindings.clone();
                let mut lowered = Vec::new();
                for binding in raw_bindings {
                    let SemanticExpr::List(pair) = binding else {
                        return Err(err("each `let` binding must be `(name expression)`"));
                    };
                    if pair.len() != 2 {
                        return Err(err("each `let` binding must be `(name expression)`"));
                    }
                    let SemanticExpr::Atom(name) = &pair[0] else {
                        return Err(err("a `let` binding name must be an atom"));
                    };
                    if !names.insert(name.clone()) {
                        return Err(err(format!("duplicate `let` binding `{name}`")));
                    }
                    let value = lower_with_bindings(&pair[1], width, &scope)?;
                    scope.insert(name.clone(), value.clone());
                    lowered.push((name.clone(), value));
                }
                return lower_with_bindings(&raw_args[1], width, &scope);
            }
            let (width, value_args) = match raw_args.first() {
                Some(SemanticExpr::Atom(atom)) if is_type_atom(atom) => {
                    (type_atom_width(atom).unwrap_or(width), &raw_args[1..])
                }
                _ => (width, raw_args),
            };
            let op = normalize_op(op_name)
                .ok_or_else(|| err(format!("unsupported formal_semantics operator `{op_name}`")))?;
            check_arity(op, op_name, value_args.len())?;
            if is_two_width_op(op) {
                let SemanticExpr::Atom(from_atom) = &value_args[0] else {
                    return Err(err(format!(
                        "operator `{op_name}` expects an integer source-width literal as its first argument"
                    )));
                };
                let Some(from_bits) = integer_literal(from_atom) else {
                    return Err(err(format!(
                        "operator `{op_name}` expects an integer source-width literal as its first argument"
                    )));
                };
                check_float_widths(op, op_name, width, Some(from_bits as u32))?;
                let arg = lower_with_bindings(&value_args[1], width, bindings)?;
                return Ok(Sem::Ext {
                    op,
                    width,
                    from_bits: from_bits as u32,
                    arg: Box::new(arg),
                });
            }
            check_float_widths(op, op_name, width, None)?;
            let args = value_args
                .iter()
                .map(|arg| lower_with_bindings(arg, width, bindings))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Sem::App { op, width, args })
        }
    }
}

/// Verify that every symbol referenced in the IR is in `symbols`.
/// Collect every symbol the expression references, in traversal order.
pub fn sem_symbols(sem: &Sem, into: &mut Vec<String>) {
    match sem {
        Sem::Sym(name) => into.push(name.clone()),
        Sem::Int { .. } => {}
        Sem::App { args, .. } => args.iter().for_each(|arg| sem_symbols(arg, into)),
        Sem::Ext { arg, .. } => sem_symbols(arg, into),
        Sem::Call { args, .. } => args.iter().for_each(|(_, arg)| sem_symbols(arg, into)),
    }
}

pub fn check_symbols(sem: &Sem, symbols: &[String]) -> Result<(), SemanticError> {
    match sem {
        Sem::Sym(name) => {
            if symbols.iter().any(|s| s == name) {
                Ok(())
            } else {
                Err(err(format!("unknown formal_semantics symbol `{name}`")))
            }
        }
        Sem::Int { .. } => Ok(()),
        Sem::App { args, .. } => args.iter().try_for_each(|arg| check_symbols(arg, symbols)),
        Sem::Ext { arg, .. } => check_symbols(arg, symbols),
        // A function's own body is checked against its parameters where it is
        // defined; here only the arguments are this expression's.
        Sem::Call { args, .. } => args.iter().try_for_each(|(_, arg)| check_symbols(arg, symbols)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantics::parse_formal_semantics;

    fn lower_str(source: &str, width: u32) -> Result<Sem, SemanticError> {
        lower(&parse_formal_semantics(source).unwrap(), width)
    }

    #[test]
    fn resolves_width_from_type_atom() {
        let sem = lower_str("(add i16 rs1 5)", 32).unwrap();
        let Sem::App { width, args, op } = sem else {
            panic!("expected app");
        };
        assert_eq!(op, Op::Add);
        assert_eq!(width, 16);
        assert_eq!(
            args[1],
            Sem::Int {
                value: 5,
                width: 16
            }
        );
    }

    #[test]
    fn normalizes_shift_aliases() {
        for (src, expected) in [
            ("(sll i32 rs1 rs2)", Op::Shl),
            ("(srl i32 rs1 rs2)", Op::Lshr),
            ("(sra i32 rs1 rs2)", Op::Ashr),
        ] {
            let Sem::App { op, .. } = lower_str(src, 32).unwrap() else {
                panic!("expected app");
            };
            assert_eq!(op, expected);
        }
    }

    #[test]
    fn extend_carries_source_width() {
        let Sem::Ext {
            op,
            width,
            from_bits,
            ..
        } = lower_str("(sext i32 8 rs1)", 32).unwrap()
        else {
            panic!("expected ext");
        };
        assert_eq!(op, Op::Sext);
        assert_eq!(width, 32);
        assert_eq!(from_bits, 8);
    }

    #[test]
    fn nary_folds_keep_all_args() {
        let Sem::App { args, .. } = lower_str("(add i32 rs1 rs2 rs1)", 32).unwrap() else {
            panic!("expected app");
        };
        assert_eq!(args.len(), 3);
    }

    #[test]
    fn rejects_unknown_operator() {
        let e = lower_str("(dot4 i32 rs1 rs2)", 32).unwrap_err();
        assert!(e
            .to_string()
            .contains("unsupported formal_semantics operator `dot4`"));
    }

    #[test]
    fn every_format_row_adds_up() {
        for format in FLOAT_FORMATS {
            // A format's width is its sign bit, its exponent, and its
            // significand without the implicit leading one.
            assert_eq!(
                format.bits,
                1 + format.exponent + (format.significand - 1),
                "{} does not add up",
                format.name
            );
            // The canonical NaN is quiet: every exponent bit set, the top
            // significand bit set, nothing else. Checked rather than trusted,
            // because a wrong pattern here is provable-and-wrong in SMT --
            // `fp.to_ieee_bv` is unspecified for NaN, so this literal is what
            // the proof rests on.
            let fraction = format.significand - 1;
            let exponent_mask = ((1u128 << format.exponent) - 1) << fraction;
            let quiet = 1u128 << (fraction - 1);
            assert_eq!(
                format.canonical_nan,
                exponent_mask | quiet,
                "{}'s canonical NaN is not the quiet one",
                format.name
            );
        }
    }

    #[test]
    fn refuses_a_float_format_axis_does_not_describe() {
        // ⚠️ `f8` is the sharp case and the reason this refuses by NAME rather
        // than by width: two eight-bit float formats are in common use --
        // e4m3 and e5m2 -- and a width does not choose between them. The
        // comparison this replaced would have answered "single precision".
        let e = lower_str("(fadd f8 rs1 rs2)", 32).unwrap_err();
        assert!(
            e.to_string().contains("names a 8-bit float as its value"),
            "{e}"
        );
        assert!(e.to_string().contains("f16 and f32 and f64"), "{e}");
        // And a width above every row, which the old comparison read as f64.
        assert!(lower_str("(fadd f128 rs1 rs2)", 128).is_err());
    }

    #[test]
    fn refuses_a_float_format_inherited_from_the_ambient_width() {
        // No type atom at all, so the width comes from the enclosing
        // expression. This is the path a lane expansion takes, and refusing
        // only the written atom would leave it open.
        let e = lower_str("(fadd rs1 rs2)", 8).unwrap_err();
        assert!(e.to_string().contains("8-bit float"), "{e}");
    }

    #[test]
    fn a_described_format_is_accepted_at_every_end() {
        lower_str("(fadd f16 rs1 rs2)", 32).unwrap();
        lower_str("(fcvt_f2f f16 32 rs1)", 32).unwrap();
        lower_str("(fcvt_f2f f32 16 rs1)", 32).unwrap();
        lower_str("(fcvt_s2f f16 32 rs1)", 32).unwrap();
        lower_str("(fcvt_f2s i32 16 rs1)", 32).unwrap();
    }

    #[test]
    fn the_environment_forms_are_refused_for_a_format_without_one() {
        // f16 has no row in the reference model's rounding-mode and exception
        // arithmetic, which still asks whether the width is under 32. Refused
        // with the reason rather than computed as single precision there.
        let e = lower_str("(fdiv_fx f16 rs1 rs2)", 32).unwrap_err();
        assert!(e.to_string().contains("exception form"), "{e}");
        assert!(e.to_string().contains("f16"), "{e}");
        // The conversion exception forms are checked on their float end too,
        // which the first version of this rule missed: it asked only about the
        // value width, and `fcvt_f2s_fx`'s float side is the source.
        let e = lower_str("(fcvt_f2s_fx i32 16 rs1)", 32).unwrap_err();
        assert!(e.to_string().contains("exception form"), "{e}");
        // ...and the same forms stay legal for a format that has one.
        lower_str("(fdiv_fx f64 rs1 rs2)", 64).unwrap();
        lower_str("(fcvt_f2s_fx i32 32 rs1)", 32).unwrap();
    }

    #[test]
    fn a_conversion_checks_the_end_that_is_a_float() {
        // `fcvt_f2s`'s float side is its SOURCE: converting a 32-bit float to
        // a 16-bit integer is ordinary and must not be refused.
        lower_str("(fcvt_f2s i16 32 rs1)", 32).unwrap();
        // ...and the other direction refuses on the destination instead.
        let e = lower_str("(fcvt_s2f f8 32 rs1)", 32).unwrap_err();
        assert!(e.to_string().contains("as its value"), "{e}");
        // Float-to-float is checked on both ends.
        let e = lower_str("(fcvt_f2f f32 8 rs1)", 32).unwrap_err();
        assert!(e.to_string().contains("as its source"), "{e}");
    }

    #[test]
    fn the_guard_leaves_integer_widths_alone() {
        // `sext` is a two-width operator with no float end, and an integer of
        // any width stays legal -- the guard must not have become a width
        // check on everything.
        lower_str("(sext i32 8 rs1)", 32).unwrap();
        lower_str("(add i16 rs1 rs2)", 32).unwrap();
        lower_str("(fadd f32 rs1 rs2)", 32).unwrap();
        lower_str("(fadd f64 rs1 rs2)", 64).unwrap();
    }

    #[test]
    fn check_symbols_flags_unknown() {
        let sem = lower_str("(add i32 rs1 rs2)", 32).unwrap();
        let e = check_symbols(&sem, &["rs1".to_string()]).unwrap_err();
        assert!(e
            .to_string()
            .contains("unknown formal_semantics symbol `rs2`"));
    }
}
