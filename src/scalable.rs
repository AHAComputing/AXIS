//! Scalable vectors as elaboration-time lane instantiation
//! (`docs/scalable_vectors_design.md`, stage S1).
//!
//! A scalable type atom `vni<elem>` / `vnf<elem>` (`vni32`, `vnf64`) is a vector
//! whose lane count is not written: it is `VL / elem`, and `VL` is a property of
//! the machine rather than of the instruction. SVE and RVV are both built this
//! way.
//!
//! Stage V1 expands a *fixed* vector by packing its lanes into one bit-vector
//! and separating them with shifts and masks, because that is what the hardware
//! does — a 64-bit NEON D register really is one 64-bit register. That
//! representation cannot carry scalable vectors, and the reason is worth stating
//! because it decided the design: `Sem::Int` holds a `u128`, and
//! `simd::vector_type_atom` rejects any shape wider than 128 bits, so a packed
//! expansion of `vni32` at VL = 256 would need a lane mask with bit 255 set and
//! no AXIS literal can hold one.
//!
//! So a scalable vector instantiates **lane-indexed** instead: at a given `VL`,
//! one instruction becomes `VL / elem` instructions, each ordinary *scalar*
//! semantics over that lane's operands. Nothing is packed, so nothing is capped,
//! and the per-lane semantics are the most heavily proven part of the system —
//! every backend and every executor already handles them.
//!
//! The two representations overlap at `VL <= 128`, and that overlap is the
//! evidence that this one is right: `tools/scalable_vs_packed.py` checks the
//! lane-indexed instantiation of `vni32` at VL = 128 against the packed `v4i32`
//! expansion V1 already proves, lane by lane. Beyond 128 bits only this
//! representation exists.

use crate::ir::integer_literal;
use crate::semantics::{parse_formal_semantics, SemanticExpr};
use crate::simd::is_lane_parallel;

/// The shape a scalable type atom carries: an element width and the domain the
/// per-lane operator reads it in. The lane *count* is deliberately absent —
/// supplying it is what instantiation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScalableShape {
    pub elem: u32,
    /// `i` for a bit-vector lane, `f` for an IEEE-754 one.
    pub elem_kind: char,
    /// How much of the vector register file one operand covers, as a rational
    /// (stage S3, mechanism M3). RVV's `LMUL` groups 1-8 registers into one
    /// operand and also goes *fractional* — 1/2, 1/4, 1/8 — so an operand can
    /// occupy part of a single register. A rational is the smallest thing that
    /// expresses both directions; an integer count could not say `1/8`.
    pub num: u32,
    pub den: u32,
    /// A tile rather than a vector: `(VL / elem)` rows of `(VL / elem)`
    /// elements, so `(VL / elem)^2` lanes. SME's ZA tiles are this shape --
    /// a .S tile at SVL = 512 is 16 x 16 -- and no LMUL expresses it, because
    /// the multiplier is itself VL-dependent (S2). Written `mn<elem>`.
    pub square: bool,
}

impl ScalableShape {
    /// The scalar type atom one lane is evaluated at.
    pub fn element_atom(&self) -> String {
        format!("{}{}", self.elem_kind, self.elem)
    }
}

/// The machine state that decides a scalable operand's shape.
///
/// SVE encodes the element width in the instruction, so only `vector_bits`
/// matters there. RVV takes it from the `vtype` CSR, so an instruction written
/// against `vti` means a different shape at every `(sew, lmul)` point — which is
/// why AXIS elaborates one point at a time and the ladder sweeps them, exactly
/// as it already sweeps vector length and scalar width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VectorMode<'a> {
    pub vector_bits: u32,
    pub sew: u32,
    pub lmul_num: u32,
    pub lmul_den: u32,
    /// The widest element the machine supports. `SEW <= ELEN` is what makes
    /// most of the `(sew, lmul)` cross product illegal, so it is declared
    /// rather than assumed.
    pub elen: u32,
    /// The width addresses are computed in — the ISA word. A lane's address is
    /// `base + lane * bytes`, and that arithmetic happens at address width, not
    /// at element width.
    pub addr_bits: u32,
    /// Architectural state the ISA declares, by name.
    ///
    /// Lane instantiation suffixes every symbol it meets, because in a vector
    /// expression every symbol is a vector operand — except these. State is
    /// scalar: one `vxsat`, not one per lane. Without this the sticky flag of a
    /// saturating instruction becomes `vxsat__l0`, a name nothing declares.
    ///
    /// A slice reference is `Copy`, so carrying it here costs the mode nothing
    /// and puts the question where the rest of the context already lives. The
    /// alternative — threading a parameter through nineteen call sites — was
    /// the same fact in nineteen places.
    pub state: &'a [String],
}

impl Default for VectorMode<'_> {
    fn default() -> Self {
        Self {
            vector_bits: 0,
            sew: 0,
            lmul_num: 1,
            lmul_den: 1,
            elen: 64,
            addr_bits: 64,
            state: &[],
        }
    }
}

impl VectorMode<'_> {
    /// Whether this is a point the machine can actually be in.
    pub fn legal(&self) -> Result<(), String> {
        if self.sew > self.elen {
            return Err(format!("SEW {} exceeds ELEN {}", self.sew, self.elen));
        }
        // RVV's rule for fractional LMUL is `LMUL >= SEW/ELEN`: an operand must
        // still reach a whole element of the widest supported kind. This is
        // tighter than "at least one element fits in VLEN" and is the rule the
        // architecture states, so it is the one enforced.
        if u64::from(self.lmul_num) * u64::from(self.elen)
            < u64::from(self.lmul_den) * u64::from(self.sew)
        {
            return Err(format!(
                "LMUL {}/{} is below SEW/ELEN ({}/{})",
                self.lmul_num, self.lmul_den, self.sew, self.elen
            ));
        }
        // And the configured length must still hold a whole element.
        if u64::from(self.vector_bits) * u64::from(self.lmul_num)
            < u64::from(self.lmul_den) * u64::from(self.sew)
        {
            return Err(format!(
                "LMUL {}/{} at SEW {} leaves no whole element in {} bits",
                self.lmul_num, self.lmul_den, self.sew, self.vector_bits
            ));
        }
        Ok(())
    }
}

/// Type atoms whose shape comes from `vtype` rather than from the instruction.
/// The `w` forms are the *widened* shape: twice the element and twice the
/// register footprint, which is what keeps a widening operation's lane count
/// equal to its operands'.
/// Lane-local operators in the scalable vocabulary.
///
/// This is `simd::is_lane_parallel` plus the integer comparisons, and the
/// difference is architectural rather than an oversight in either place. A
/// *packed* lane-wise compare writes a lane **mask** — all-ones or all-zeros
/// across the element — which is what NEON does and why `simd.rs` excludes
/// comparisons rather than let a `v4i32` compare quietly mean the wrong thing.
/// A *scalable* compare writes one **bit** per lane into a predicate, which is
/// what both SVE and RVV do. Same operator, two element domains, and the
/// lane-indexed representation is the one where the bit is the natural answer.
fn scalable_lane_parallel(op: &str, elem_kind: char) -> bool {
    if is_lane_parallel(op, elem_kind) {
        return true;
    }
    // Extensions, per element with a literal source width (S1: SME's
    // widening outer products take byte t of each 32-bit element). Scalable
    // lanes only: this expansion leaves a literal whole, where the packed one
    // splits it across lanes and would extend lane 1 from zero bits.
    if elem_kind == 'i' && matches!(op, "sext" | "zext") {
        return true;
    }
    match elem_kind {
        // A scalable compare writes one bit per lane into a predicate, which is
        // what SVE and RVV do. A packed compare writes an all-ones lane mask,
        // which is what NEON does, and `simd.rs` refuses comparisons for that
        // reason -- the same operator meaning two things in two
        // representations, each right for its own.
        'i' => crate::ir::is_integer_comparison(op) || op == "select",
        // The float comparisons return a bit too, so an FP predicate needs no
        // machinery beyond letting them through.
        'f' => crate::ir::is_float_comparison(op) || op == "select",
        _ => false,
    }
}

const MODE_ATOMS: &[&str] = &["vti", "vtiw", "vtf", "vtfw"];

/// Resolve any scalable type atom, explicit or mode-derived.
pub fn resolve_type_atom(atom: &str, mode: &VectorMode<'_>) -> Option<ScalableShape> {
    if let Some(shape) = scalable_type_atom(atom) {
        return Some(shape);
    }
    let (elem_kind, wide) = match atom {
        "vti" => ('i', false),
        "vtiw" => ('i', true),
        "vtf" => ('f', false),
        "vtfw" => ('f', true),
        _ => return None,
    };
    if mode.sew == 0 {
        return None;
    }
    let scale = if wide { 2 } else { 1 };
    let elem = mode.sew * scale;
    if elem_kind == 'f' && !matches!(elem, 32 | 64) {
        return None;
    }
    Some(ScalableShape {
        elem,
        elem_kind,
        num: mode.lmul_num * scale,
        den: mode.lmul_den,
        square: false,
    })
}

/// How a document realises lanes it declares **unspecified** (stage S2, and
/// mechanism M1 in `docs/scalable_vectors_design.md`).
///
/// RVV's tail-agnostic policy leaves elements past `vl` architecturally
/// unspecified: an implementation may leave them undisturbed or write all-ones,
/// and both are correct. A bit-exact ladder cannot compare *contents* it does
/// not constrain — but it can compare **which** lanes are unconstrained, and
/// that is the part the architecture does specify.
///
/// So a document declares one realisation and the ladder runs under each in
/// turn. Requiring agreement on defined lanes under all of them proves
/// something stronger than picking one: that nothing downstream depends on the
/// undefined bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Realization {
    /// The undefined lane keeps whatever the operation computed. This is the
    /// cheapest thing hardware does and the easiest to mistake for specified.
    #[default]
    Compute,
    /// The undefined lane reads as all-ones.
    Ones,
    /// The undefined lane reads as zero.
    Zeros,
}

impl Realization {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "compute" => Some(Self::Compute),
            "ones" => Some(Self::Ones),
            "zeros" => Some(Self::Zeros),
            _ => None,
        }
    }
}

/// How a reduction whose order the architecture leaves open is realised.
///
/// ⚠️ This is the ORDER analogue of [`Realization`], and it is a second
/// mechanism rather than a case of the first. `docs/scalable_vectors_design.md`
/// M1 lists "unordered FP reductions" among what definedness masks cover, and
/// they are not covered: a mask says which *lanes* are unspecified, and an
/// unordered reduction produces one fully defined value drawn from a set of
/// admissible ones. Whole-value indeterminacy is a different shape from lane
/// indeterminacy — there is no lane to mark — so it needs its own knob, swept
/// the same way.
///
/// The admissible set is *the orders this language can already pin*. An
/// unordered reduction under `sequential` is exactly `vfredosum`, and under
/// `pairwise` exactly `vfredpsum`. That is what makes the sweep decidable
/// rather than a gesture at "any order": each realisation is an ordinary
/// described instruction, and no backend learns that anything was unordered.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReductionOrder {
    /// Left to right, lane 0 first. RVV's `vfredosum`, SVE's `FADDA`.
    #[default]
    Sequential,
    /// A balanced tree: split the lanes in half, reduce each half, combine.
    /// SVE's `FADDV` is specified this way, and for the power-of-two lane
    /// counts every SVE and RVV shape has, "split in half" and Arm's recursive
    /// pairwise are the same tree.
    Pairwise,
}

impl ReductionOrder {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "sequential" => Some(Self::Sequential),
            "pairwise" => Some(Self::Pairwise),
            _ => None,
        }
    }
}

/// The shapes an instantiated instruction uses: what it produces, and — when
/// the operation mixes widths — what it reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Shapes {
    pub result: ScalableShape,
    pub operand: Option<ScalableShape>,
    /// True when the instruction collapses its lanes into a single result — a
    /// reduction. Every other scalable instruction becomes one instruction per
    /// lane; a reduction stays one instruction that reads them all, because
    /// that is what it is.
    pub collapsed: bool,
}

impl Shapes {
    /// The element width an operand of this instruction is declared at.
    pub fn operand_elem(&self, is_output: bool) -> u32 {
        if is_output {
            self.result.elem
        } else {
            self.operand.unwrap_or(self.result).elem
        }
    }
}

/// One instantiated lane: what it computes, and — when the instruction declares
/// a tail — the expression saying whether this lane is defined at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lane {
    pub value: String,
    /// An ordinary semantics expression returning 0 or 1. `None` means the lane
    /// is unconditionally defined.
    ///
    /// Definedness is deliberately an *ordinary* expression rather than a new
    /// kind of value: that way every backend already knows how to compute it,
    /// and the existing backend-vs-golden gates already prove they agree on it
    /// exactly. M1 asks for the undefined *region* to be compared without
    /// masking, and this is what makes that free rather than five more
    /// lowerings.
    pub defined: Option<String>,
}

/// Parse `vni<elem>` or `vnf<elem>`. Returns `None` for everything else,
/// including the fixed `v<lanes>i<elem>` atoms — `simd::vector_type_atom`
/// rejects `vni32` because `n` does not parse as a lane count, so the two
/// spellings cannot collide.
pub fn scalable_type_atom(atom: &str) -> Option<ScalableShape> {
    let (rest, square) = match atom.strip_prefix("vn") {
        Some(rest) => (rest, false),
        None => (atom.strip_prefix("mn")?, true),
    };
    let elem_kind = rest.chars().next()?;
    if elem_kind != 'i' && elem_kind != 'f' {
        return None;
    }
    let elem: u32 = rest[1..].parse().ok()?;
    if !matches!(elem, 8 | 16 | 32 | 64) {
        return None;
    }
    // IEEE-754 lanes exist at the widths AXIS has float semantics for: half,
    // single and double -- half since the FP16 work, which SVE's .H forms need.
    if elem_kind == 'f' && !matches!(elem, 16 | 32 | 64) {
        return None;
    }
    Some(ScalableShape { elem, elem_kind, num: 1, den: 1, square })
}

/// True when `text` mentions a scalable type atom, so scalar and fixed-vector
/// documents skip this path entirely and keep their artifacts byte-identical.
pub fn mentions_scalable(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| scalable_type_atom(token).is_some() || MODE_ATOMS.contains(&token))
}

/// True when `text` has a reduction (or `vcpop`, `vfirst`, `vextract`,
/// `vlastb`, `vuaddv`, `vsaddv`) somewhere other than as its outermost form --
/// the one case where an input's lanes are not at the result's width.
pub fn nests_a_collapse(text: &str) -> bool {
    fn walk(expr: &SemanticExpr, outermost: bool) -> bool {
        let SemanticExpr::List(items) = expr else {
            return false;
        };
        (!outermost && is_collapsing(expr)) || items.iter().any(|item| walk(item, false))
    }
    parse_formal_semantics(text).is_ok_and(|expr| walk(&expr, true))
}

/// Whether `expr`'s outermost form is scalar-typed over scalable operands --
/// CNTP's `(zext i64 32 (vcpop vni32 ...))` -- so its result is one scalar
/// at that type.
fn is_scalar_outermost(expr: &SemanticExpr, mode: &VectorMode<'_>) -> bool {
    matches!(expr, SemanticExpr::List(items)
        if matches!(items.get(1), Some(SemanticExpr::Atom(t))
            if resolve_type_atom(t, mode).is_none() && crate::ir::type_atom_bits(t).is_some()))
}

/// [`is_scalar_outermost`] for a semantics string, at no particular mode.
pub fn scalar_outermost_text(text: &str) -> bool {
    let mode = VectorMode { vector_bits: 128, ..VectorMode::default() };
    mentions_scalable(text)
        && parse_formal_semantics(text).is_ok_and(|expr| is_scalar_outermost(&expr, &mode))
}

/// True when `text` names a `vtype`-derived shape (`vti`, `vtf`, ...), whose
/// element width comes from the machine's mode rather than the instruction.
pub fn mentions_mode_shape(text: &str) -> bool {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token| MODE_ATOMS.contains(&token))
}

/// The suffix distinguishing one lane's operands from another's. Doubled
/// underscore so it cannot be confused with an architectural register name.
pub fn lane_suffix(lane: u32) -> String {
    format!("__l{lane}")
}

/// The shapes an expression uses, checked for a consistent lane count.
///
/// Stage S1 required a single shape. That was too strict: RVV's widening and
/// narrowing operations mix element widths on purpose — `vwadd` reads SEW lanes
/// and writes 2*SEW ones — and refusing them would have excluded a large part
/// of the arithmetic. What they never mix is the *lane count*, because a
/// widened operand also doubles its register footprint, so `LMUL` moves with
/// `SEW` and the two cancel.
///
/// So the rule is lane-count agreement rather than shape equality. It admits
/// every mixed-width form RVV has and still refuses shapes that would silently
/// process a different number of elements.
fn checked_lane_count(
    expr: &SemanticExpr,
    mode: &VectorMode<'_>,
) -> Result<Option<(ScalableShape, Option<ScalableShape>, u32)>, String> {
    let mut found: Option<(ScalableShape, u32)> = None;
    let mut operand: Option<ScalableShape> = None;
    collect_shapes(expr, mode, &mut found, &mut operand)?;
    Ok(found.map(|(shape, lanes)| (shape, operand, lanes)))
}

fn collect_shapes(
    expr: &SemanticExpr,
    mode: &VectorMode<'_>,
    found: &mut Option<(ScalableShape, u32)>,
    operand: &mut Option<ScalableShape>,
) -> Result<(), String> {
    let SemanticExpr::List(items) = expr else {
        return Ok(());
    };
    // A collapsing form below the outermost is a scalar there: its lanes are
    // its own, counted when it is expanded, and need not match the result's.
    if found.is_some() && is_collapsing(expr) {
        return Ok(());
    }
    for item in items.iter().take(3).skip(1) {
        let SemanticExpr::Atom(type_atom) = item else {
            continue;
        };
        let Some(shape) = resolve_type_atom(type_atom, mode) else {
            continue;
        };
        let lanes = lane_count(shape, mode.vector_bits)?;
        match found {
            Some((existing, existing_lanes)) if *existing_lanes != lanes => {
                return Err(format!(
                    "shapes `{}` and `{}` cover {existing_lanes} and {lanes} lanes; a \
                     mixed-width operation must keep its lane count",
                    existing.element_atom(),
                    shape.element_atom()
                ));
            }
            // Same lane count, different element: this is the operand shape of
            // a widening or narrowing form. Operands must be declared at their
            // own width, not the result's, or a consumer sees a 32-bit source
            // announced as 64 bits.
            Some((existing, _)) if existing.elem != shape.elem && operand.is_none() => {
                *operand = Some(shape);
            }
            Some(_) => {}
            // The first shape seen is the outermost, which is the result shape.
            None => *found = Some((shape, lanes)),
        }
    }
    for item in items {
        collect_shapes(item, mode, found, operand)?;
    }
    Ok(())
}

/// How many lanes `shape` has at a vector length of `vector_bits`.
pub fn lane_count(shape: ScalableShape, vector_bits: u32) -> Result<u32, String> {
    if shape.square {
        if shape.elem == 0 || vector_bits % shape.elem != 0 {
            return Err(format!(
                "vector length {vector_bits} is not a multiple of element width {}",
                shape.elem
            ));
        }
        let side = vector_bits / shape.elem;
        return Ok(side * side);
    }
    let bits = u64::from(vector_bits) * u64::from(shape.num);
    let per_lane = u64::from(shape.den) * u64::from(shape.elem);
    if bits == 0 || per_lane == 0 || bits % per_lane != 0 {
        return Err(format!(
            "vector length {vector_bits} scaled by {}/{} is not a multiple of element \
             width {}",
            shape.num, shape.den, shape.elem
        ));
    }
    Ok((bits / per_lane) as u32)
}

/// Widening operations: read lanes at SEW, write them at 2*SEW. The extension
/// is the whole difference between the signed and unsigned forms, which is why
/// they share a scalar operator here.
const WIDENING: &[(&str, &str, &str)] = &[
    ("vwadd", "add", "sext"),
    ("vwaddu", "add", "zext"),
    ("vwsub", "sub", "sext"),
    ("vwsubu", "sub", "zext"),
    ("vwmul", "mul", "sext"),
    ("vwmulu", "mul", "zext"),
];

/// Narrowing operations: read lanes at 2*SEW, write them at SEW.
const NARROWING: &[(&str, &str)] = &[("vnsrl", "lshr"), ("vnsra", "sra")];

/// Instantiate one scalable semantics string at a vector-mode point, returning
/// one ordinary scalar lane per element. Returns `None` when the text mentions
/// no scalable atom.
pub fn instantiate(
    text: &str,
    mode: &VectorMode<'_>,
    realization: Realization,
    order: ReductionOrder,
) -> Result<Option<(Shapes, Vec<Lane>, Option<String>)>, String> {
    if !mentions_scalable(text) {
        return Ok(None);
    }
    let expr = parse_formal_semantics(text).map_err(|error| error.message)?;
    mode.legal()?;
    let Some((shape, operand_shape, lanes)) = checked_lane_count(&expr, mode)? else {
        if text.split(|ch: char| !ch.is_ascii_alphanumeric())
            .any(|token| MODE_ATOMS.contains(&token))
        {
            return Err(
                "uses a `vtype`-derived shape but the ISA declares no `(vector-sew N)`"
                    .to_string(),
            );
        }
        return Ok(None);
    };

    // `(vtail <type> <vl> <body>)`: lanes at or above `vl` are the tail, and the
    // tail is unspecified. Required to be outermost, because a tail is a
    // property of the whole result rather than of a sub-expression.
    // A reduction reads every lane and produces one result, so it stays one
    // instruction rather than becoming one per lane. It is the only shape in
    // this language that does, which is why it is handled before the split.
    // `vcpop` and `vfirst` read every lane and produce one scalar, so they
    // collapse exactly as a reduction does -- they are simply not folds of a
    // single operator, which is why they are handled beside REDUCTIONS rather
    // than inside it.
    // A reduction reads every lane and produces one result, so it stays one
    // instruction rather than becoming one per lane -- as do `vcpop`, `vfirst`
    // and `vextract`, which read every lane and produce one scalar. They are
    // handled before the split; `collapsed_value` is shared with `lane_of`,
    // where the same forms nested inside a per-lane expression are scalars.
    // A SCALAR-typed outermost form over scalable ones -- CNTP's
    // `(zext i64 (vcpop vni32 ...))` -- is one scalar too: every scalable
    // form in it must fold to one, and nothing is lane-suffixed.
    if is_scalar_outermost(&expr, mode) {
        let value = crate::effects::render_semexpr(&scalar_of(&expr, mode)?);
        if mentions_scalable(&value) {
            return Err(format!(
                "a scalar result over scalable operands must fold them all, and `{value}` \
                 still reads a vector"
            ));
        }
        return Ok(Some((
            Shapes { result: shape, operand: operand_shape, collapsed: true },
            vec![Lane { value, defined: None }],
            None,
        )));
    }
    if let Some(value) = collapsed_value(&expr, mode, Some(order))? {
        return Ok(Some((
            Shapes { result: shape, operand: operand_shape, collapsed: true },
            vec![Lane { value, defined: None }],
            None,
        )));
    }

    let (body, partial) = match split_partial(&expr)? {
        Some((partial, body)) => (body, Some(partial)),
        None => (expr.clone(), None),
    };
    if matches!(partial, Some(Partial::Tail(_)))
        && u64::from(lanes) >= 1u64 << shape.elem.min(63)
    {
        // The lane index is compared against `vl` at the element width, so a
        // lane count that cannot be represented there would compare a truncated
        // index. Refused rather than silently wrapped.
        return Err(format!(
            "{lanes} lanes cannot be indexed at element width {}",
            shape.elem
        ));
    }

    let mut out = Vec::with_capacity(lanes as usize);
    for lane in 0..lanes {
        let computed = lane_of(&body, lane, mode)?;
        let Some(partial) = &partial else {
            out.push(Lane {
                value: crate::effects::render_semexpr(&computed),
                defined: None,
            });
            continue;
        };
        let element = shape.element_atom();
        let defined = match partial {
            Partial::Tail(vl) => format!("(icmp_ult {element} {lane} {vl})"),
            // A predicate lane is one bit, so any non-zero value is active.
            // Comparing rather than using it directly keeps the mask a 0/1
            // value whatever the operand happens to hold.
            Partial::Masked(pg) => {
                format!("(icmp_ne {element} {pg}{} 0)", lane_suffix(lane))
            }
        };
        let computed_text = crate::effects::render_semexpr(&computed);
        let value = match realization {
            Realization::Compute => computed_text,
            Realization::Ones => format!(
                "(select {element} {defined} {computed_text} {})",
                mask_literal(shape.elem)
            ),
            Realization::Zeros => {
                format!("(select {element} {defined} {computed_text} 0)")
            }
        };
        out.push(Lane {
            value,
            defined: Some(defined),
        });
    }
    let control = partial.map(|partial| match partial {
        Partial::Tail(name) | Partial::Masked(name) => name,
    });
    Ok(Some((
        Shapes { result: shape, operand: operand_shape, collapsed: false },
        out,
        control,
    )))
}

/// Whether a mask lane is active, as a 0/1 expression.
fn mask_active(
    mask: &SemanticExpr,
    lane: u32,
    element: &str,
    mode: &VectorMode<'_>,
) -> Result<String, String> {
    let bit = crate::effects::render_semexpr(&lane_of(mask, lane, mode)?);
    Ok(format!("(icmp_ne {element} {bit} 0)"))
}

/// How many mask lanes below `upto` are active — the exclusive prefix count.
///
/// Shared by every operation whose answer is "where does this element sit once
/// the inactive ones are removed": `vcompress` packs by it, `viota` reports it,
/// and the set-before/including/only-first masks are all comparisons against
/// it. Writing it once is what makes that family fall out of the compress work
/// rather than needing its own machinery.
fn prefix_count(
    mask: &SemanticExpr,
    upto: u32,
    element: &str,
    mode: &VectorMode<'_>,
) -> Result<String, String> {
    let terms: Result<Vec<String>, String> = (0..upto)
        .map(|lane| mask_active(mask, lane, element, mode))
        .collect();
    let terms = terms?;
    Ok(match terms.len() {
        0 => "0".to_string(),
        1 => terms.into_iter().next().expect("one term"),
        _ => format!("(add {element} {})", terms.join(" ")),
    })
}

/// Structured permutes: how an output lane picks its input lane.
///
/// Each returns `(which operand, which lane)`. They are the SVE and NEON
/// structured forms plus RVV's slides, and every one of them is a *static*
/// function of the lane index — which is why they need no operator support
/// beyond reading a different lane. A dynamic permute (`vrgather`, whose index
/// is a runtime vector) is a different problem and is not described here.
/// Largest lane count a runtime-indexed gather will expand to. The tree is
/// quadratic, so this is a real ceiling rather than a formality: at 32 lanes an
/// instruction already carries about a thousand select nodes.
const MAX_GATHER_LANES: u32 = 32;

/// Largest lane count a compress will expand to. Lower than the gather ceiling
/// because the expansion is cubic rather than quadratic: each output lane tests
/// every source lane against a prefix count that is itself a sum over earlier
/// lanes.
const MAX_COMPRESS_LANES: u32 = 16;

type PermutePick = fn(u32, u32, u32) -> (usize, u32);

/// The offset a lane takes under an affine access map.
///
/// `(dim <extent> <stride>)...` names the iteration space outermost first, the
/// way an array subscript is written. Lane `k` decomposes into one index per
/// dimension -- `k / (product of the later extents) % extent` -- and the offset
/// is the sum of each index times its stride.
///
/// ⚠️ The extents are literals and the strides need not be. That split is the
/// whole mechanism: the decomposition happens at elaboration, where the lane is
/// already a constant, so each index is a number by the time it multiplies a
/// stride that may well be a register. An AMX `TILELOADD` reads rows at a
/// runtime stride and elements contiguously within them, which is
/// `(dim 16 rs) (dim 16 4)` and nothing more.
///
/// This subsumes the forms beside it rather than joining them: one dimension
/// with the element size is `vload`, one with an operand is `vload_strided`,
/// and `tools/access_map_check.py` requires the general form to agree with both
/// -- which is what makes it a generalisation rather than a third thing that
/// happens to work.
fn map_offset(
    dims: &[SemanticExpr],
    lane: u32,
    count: u32,
    addr: &str,
) -> Result<String, String> {
    let mut extents = Vec::new();
    let mut strides = Vec::new();
    for dim in dims {
        let SemanticExpr::List(parts) = dim else {
            return Err("an access map's dimension must be `(dim <extent> <stride>)`".to_string());
        };
        if parts.len() != 3 {
            return Err("an access map's dimension must be `(dim <extent> <stride>)`".to_string());
        }
        let (SemanticExpr::Atom(head), SemanticExpr::Atom(extent)) = (&parts[0], &parts[1]) else {
            return Err("an access map's dimension must be `(dim <extent> <stride>)`".to_string());
        };
        if head != "dim" {
            return Err(format!("an access map takes `(dim ...)`, not `({head} ...)`"));
        }
        let extent = integer_literal(extent)
            .ok_or_else(|| format!("access map extent `{extent}` must be a literal"))?
            as u32;
        if extent == 0 {
            return Err("an access map dimension of no extent addresses nothing".to_string());
        }
        extents.push(extent);
        strides.push(crate::effects::render_semexpr(&parts[2]));
    }
    if extents.is_empty() {
        return Err("an access map needs at least one dimension".to_string());
    }
    let total: u32 = extents.iter().product();
    if total != count {
        return Err(format!(
            "an access map over {} addresses {total} element(s) and the shape has {count}",
            extents
                .iter()
                .map(|extent| extent.to_string())
                .collect::<Vec<_>>()
                .join(" x ")
        ));
    }
    let mut terms = Vec::new();
    let mut inner: u32 = total;
    for (extent, stride) in extents.iter().zip(&strides) {
        inner /= extent;
        let index = (lane / inner.max(1)) % extent;
        if index != 0 {
            terms.push(format!("(mul {addr} {stride} {index})"));
        }
    }
    Ok(match terms.len() {
        0 => "0".to_string(),
        1 => terms.pop().unwrap(),
        _ => format!("(add {addr} {})", terms.join(" ")),
    })
}

/// A matrix index: which lane of the source a lane of the result reads, given
/// the result's lane count and the column count the form names.
type MatrixPick = fn(u32, u32, u32) -> u32;

/// The forms that give a flat lane space a second dimension.
///
/// ⚠️ There is no `Shape::Matrix`, and building one turned out to be
/// unnecessary rather than deferred. A tile IS a vector: 256 lanes of f32 are
/// an SME `ZA0.S` at SVL = 512, and lane-indexed instantiation already turns
/// one such instruction into 256 ordinary single-write ones -- so the effect
/// ABI's four-write budget, which `docs/tensor_design.md` §6.1 called the wall,
/// is never reached. What a matrix actually needs is not a shape but an
/// **index function**, and that is what these are: the same "a static map from
/// an output lane to an input lane" the structured permutes already are, with
/// the map written in two dimensions.
///
/// ```text
///   (vrows <type> <cols> a)        element k reads a[k / cols]
///   (vcols <type> <cols> b)        element k reads b[k % cols]
///   (vtranspose <type> <cols> m)   element k reads m[(k % cols) * rows + k / cols]
/// ```
///
/// ⚠️ In all three, `cols` is the column count of the **result**. For the
/// broadcasts that is also the source's, since the source is a single row or
/// column; for the transpose it is not -- `(vtranspose <type> 8 m)` reads an
/// eight-row, two-column tile and produces a two-row, eight-column one, so the
/// source's column count is `rows`. The two are the same number for a square
/// tile, which is exactly why a square corpus could not tell a transpose using
/// the wrong one apart, and why `examples/matrix.axisl` carries a non-square
/// pair.
///
/// An outer product is then `(fmul (vrows ...) (vcols ...))` and SME's FMOPA is
/// that added to the accumulator -- composed rather than named, which is why
/// there is no `vmopa` here. The first two also read a SHORTER operand than the
/// result: a 256-lane result reading 16 lanes of `zn` is exactly what an outer
/// product is, and it falls out of the index rather than needing a second
/// shape beside the first.
fn matrix_sources(op: &str) -> Option<MatrixPick> {
    let pick: MatrixPick = match op {
        "vrows" => |lane, _count, cols| lane / cols,
        "vcols" => |lane, _count, cols| lane % cols,
        // The transpose reads column-major where the tile was written
        // row-major, which is the whole content of a horizontal slice against
        // a vertical one: same storage, two index functions.
        "vtranspose" => |lane, count, cols| (lane % cols) * (count / cols) + lane / cols,
        _ => return None,
    };
    Some(pick)
}

fn permute_sources(op: &str) -> Option<(usize, PermutePick)> {
    let pick: (usize, PermutePick) = match op {
        // ZIP1/ZIP2: interleave the low or high half of two vectors.
        "vzip1" => (2, |lane, _count, _imm| ((lane % 2) as usize, lane / 2)),
        "vzip2" => (2, |lane, count, _imm| ((lane % 2) as usize, count / 2 + lane / 2)),
        // UZP1/UZP2: take every other element of the concatenation.
        "vuzp1" => (2, |lane, count, _imm| {
            let index = 2 * lane;
            if index < count { (0, index) } else { (1, index - count) }
        }),
        "vuzp2" => (2, |lane, count, _imm| {
            let index = 2 * lane + 1;
            if index < count { (0, index) } else { (1, index - count) }
        }),
        // TRN1/TRN2: transpose pairs.
        "vtrn1" => (2, |lane, _count, _imm| {
            if lane % 2 == 0 { (0, lane) } else { (1, lane - 1) }
        }),
        "vtrn2" => (2, |lane, _count, _imm| {
            if lane % 2 == 0 { (0, lane + 1) } else { (1, lane) }
        }),
        // EXT: a window across the concatenation of two vectors.
        "vext" => (3, |lane, count, imm| {
            let index = lane + imm;
            if index < count { (0, index) } else { (1, index - count) }
        }),
        // Slides take a *background* operand rather than inventing a zero for
        // the lanes that fall off the end. RVV's vslideup leaves those lanes
        // undisturbed and vslidedown's tail follows the tail policy, so naming
        // the background is what lets a document say which it means.
        "vslidedown" => (3, |lane, count, imm| {
            let index = lane + imm;
            if index < count { (0, index) } else { (1, lane) }
        }),
        "vslideup" => (3, |lane, _count, imm| {
            if lane >= imm { (0, lane - imm) } else { (1, lane) }
        }),
        _ => return None,
    };
    Some(pick)
}

/// Reductions over integer lanes. The scalar operators are associative, so the
/// fold can be the n-ary form the IR already has and no order needs pinning.
const REDUCTIONS: &[(&str, &str)] = &[
    ("vredsum", "add"),
    ("vredand", "and"),
    ("vredor", "or"),
    ("vredxor", "xor"),
    ("vredmax", "max"),
    ("vredmin", "min"),
    ("vredmaxu", "maxu"),
    ("vredminu", "minu"),
];

/// Ordered reductions over IEEE-754 lanes.
///
/// These are spelled separately and folded left-to-right explicitly, because
/// floating-point addition is **not associative**: `(a+b)+c` and `a+(b+c)` can
/// differ, so a reduction has no value at all until its order is pinned. RVV
/// draws exactly this distinction — `vfredosum` is ordered and `vfredusum` is
/// not, and the unordered one has no single architectural answer, which is why
/// only the ordered form is described here.
const ORDERED_REDUCTIONS: &[(&str, &str)] = &[("vfredosum", "fadd"), ("vfredomul", "fmul")];

/// Reductions whose order is pinned to a balanced tree.
///
/// SVE's `FADDV` is this, and it is not a stylistic variant of the ordered
/// form: `(a+b)+(c+d)` and `((a+b)+c)+d` are different values in IEEE-754, so
/// an architecture that specifies a tree has specified something a left fold
/// gets wrong. Only `fadd` is here because only `fadd` needs it — SVE's other
/// tree reductions are `FMAXV`/`FMINV`, whose operators this IR does not have
/// in the float domain.
const PAIRWISE_REDUCTIONS: &[(&str, &str)] = &[("vfredpsum", "fadd")];

/// Reductions the architecture deliberately leaves unordered.
///
/// RVV's `vfredusum` is the case this exists for, and the corpus said for a
/// long time that it "has no single architectural answer, so only the ordered
/// reduction exists here". That was true of a language with one fold shape.
/// With two, the unordered form has a decidable meaning: it is whichever of
/// them the ISA's `(reduction-realization ...)` names, swept across both by
/// `tools/reduction_order_check.py`, which additionally requires them to
/// *differ* somewhere — an unordered reduction that no input can tell apart
/// from an ordered one is not being proven, it is being assumed.
const UNSPECIFIED_REDUCTIONS: &[(&str, &str)] = &[("vfredusum", "fadd")];

/// Fold a cross-lane reduction into one expression over every lane.
///
/// Always left-to-right and always binary. That is one rule rather than two,
/// and it sidesteps a question the n-ary spelling would raise: `add`, `and`,
/// `or` and `xor` fold n-ary in the IR but `max` and `min` are binary, so a
/// flat fold would need an arity table to be correct. Left-nesting is correct
/// for every operator here.
///
/// It also means the floating-point case needs no special handling, only a
/// separate vocabulary. `fadd` is not associative — `(a+b)+c` and `a+(b+c)` can
/// differ — so an FP reduction has no value at all until its order is pinned,
/// and writing the nesting out *is* the pinning. The integer operators are
/// associative and so are indifferent to it.
fn reduce(
    op: &str,
    scalar_op: &str,
    operand: &SemanticExpr,
    shape: ScalableShape,
    lanes: u32,
    mode: &VectorMode<'_>,
    order: ReductionOrder,
) -> Result<String, String> {
    let element = shape.element_atom();
    let terms: Result<Vec<String>, String> = (0..lanes)
        .map(|lane| {
            Ok(crate::effects::render_semexpr(&lane_of(operand, lane, mode)?))
        })
        .collect();
    let terms = terms?;
    if terms.is_empty() {
        return Err(format!("`{op}` has no lanes to reduce"));
    }
    Ok(fold(&terms, scalar_op, &element, order))
}

/// Whether `expr` is a form that reads every lane and yields one scalar.
fn is_collapsing(expr: &SemanticExpr) -> bool {
    let SemanticExpr::List(items) = expr else {
        return false;
    };
    matches!(items.first(), Some(SemanticExpr::Atom(op))
        if matches!(op.as_str(), "vextract" | "vcpop" | "vfirst" | "vlastb" | "vlasta" | "vuaddv" | "vsaddv"))
        || as_reduction(expr).is_some()
}

/// The scalar a collapsing form evaluates to, or `None` for any other form.
///
/// `order` is the ISA's realisation of an unordered floating-point reduction.
/// Nested inside a per-lane expression there is none to hand -- `lane_of` asks
/// with `None` -- and such a reduction is refused rather than given an order
/// nobody stated, since for `fadd` the order is the value. Integer reductions
/// are associative and need none.
///
/// ⚠️ Nesting is what Arm's reductions need: `UADDV Dd, Pg, Zn` writes the sum
/// into element 0 of a vector register and zeroes the rest, and a compare's
/// NZCV is "is the first active element true" -- a scalar computed over one
/// shape, used in an expression over another.
fn collapsed_value(
    expr: &SemanticExpr,
    mode: &VectorMode<'_>,
    order: Option<ReductionOrder>,
) -> Result<Option<String>, String> {
    if !is_collapsing(expr) {
        return Ok(None);
    }
    let SemanticExpr::List(items) = expr else {
        return Ok(None);
    };
    let (Some(SemanticExpr::Atom(op)), Some(SemanticExpr::Atom(type_atom))) =
        (items.first(), items.get(1))
    else {
        return Err("a reduction must be `(op type args...)`".to_string());
    };
    let shape = resolve_type_atom(type_atom, mode)
        .ok_or_else(|| format!("`{op}` needs a scalable type, not `{type_atom}`"))?;
    let lanes = lane_count(shape, mode.vector_bits)?;
    let element = shape.element_atom();
    if op == "vextract" {
        // `(vextract <type> src <index>)`: one element as a scalar -- RVV's
        // vmv.x.s, and SVE's LASTB with a constant index.
        if items.len() != 4 {
            return Err("`vextract` takes a type, a source and an index".to_string());
        }
        let SemanticExpr::Atom(index_text) = &items[3] else {
            return Err("`vextract`'s index must be a literal".to_string());
        };
        let index = integer_literal(index_text)
            .ok_or_else(|| "`vextract`'s index must be a literal".to_string())?;
        if index >= u128::from(lanes) {
            return Err(format!(
                "`vextract` index {index} is past the {lanes} lanes this shape has"
            ));
        }
        return Ok(Some(crate::effects::render_semexpr(&lane_of(
            &items[2],
            index as u32,
            mode,
        )?)));
    }
    if op == "vlastb" {
        // `(vlastb <type> mask src)`: `src` at the last lane `mask` has active,
        // or at the last lane when none is -- Arm's LASTB, and the C flag of
        // every SVE predicate test ("the last active element is false").
        if items.len() != 4 {
            return Err("`vlastb` takes a type, a mask and a source".to_string());
        }
        let mut tree =
            crate::effects::render_semexpr(&lane_of(&items[3], lanes.saturating_sub(1), mode)?);
        // From the lowest lane up, so the highest active lane is outermost and
        // wins.
        for lane in 0..lanes {
            tree = format!(
                "(select {element} {} {} {tree})",
                mask_active(&items[2], lane, &element, mode)?,
                crate::effects::render_semexpr(&lane_of(&items[3], lane, mode)?)
            );
        }
        return Ok(Some(tree));
    }
    if op == "vlasta" {
        // `(vlasta <type> mask src)`: `src` at the lane AFTER the last active
        // one, wrapping to lane 0 -- and lane 0 when none is active, since
        // "the last active" is then lane -1. Arm's LASTA.
        if items.len() != 4 {
            return Err("`vlasta` takes a type, a mask and a source".to_string());
        }
        let mut tree = crate::effects::render_semexpr(&lane_of(&items[3], 0, mode)?);
        for lane in 0..lanes {
            tree = format!(
                "(select {element} {} {} {tree})",
                mask_active(&items[2], lane, &element, mode)?,
                crate::effects::render_semexpr(&lane_of(&items[3], (lane + 1) % lanes, mode)?)
            );
        }
        return Ok(Some(tree));
    }
    if op == "vuaddv" || op == "vsaddv" {
        // `(vuaddv <type> src)`: every lane zero- (`vsaddv`: sign-) extended to
        // 64 bits and summed there. Arm's UADDV and SADDV accumulate at 64 bits
        // whatever the element, so an element-width `vredsum` would wrap
        // where they do not.
        if items.len() != 3 {
            return Err(format!("`{op}` takes a type and one vector operand"));
        }
        let extend = if op == "vuaddv" { "zext" } else { "sext" };
        let terms: Result<Vec<String>, String> = (0..lanes)
            .map(|lane| {
                let term = crate::effects::render_semexpr(&lane_of(&items[2], lane, mode)?);
                Ok(if shape.elem == 64 {
                    term
                } else {
                    format!("({extend} i64 {} {term})", shape.elem)
                })
            })
            .collect();
        return Ok(Some(fold(&terms?, "add", "i64", ReductionOrder::Sequential)));
    }
    if op == "vcpop" || op == "vfirst" {
        if items.len() != 3 {
            return Err(format!("`{op}` takes a type and a mask"));
        }
        if op == "vcpop" {
            return prefix_count(&items[2], lanes, &element, mode).map(Some);
        }
        // Built from the highest lane down so that lower indices wrap the
        // higher ones and therefore win. No active lane gives all-ones, which
        // is RVV's -1.
        let mut tree = mask_literal(shape.elem);
        for lane in (0..lanes).rev() {
            tree = format!(
                "(select {element} {} {lane} {tree})",
                mask_active(&items[2], lane, &element, mode)?
            );
        }
        return Ok(Some(tree));
    }
    let (op, scalar_op, pinned) = as_reduction(expr).expect("is_collapsing matched it");
    if items.len() != 3 {
        return Err(format!("`{op}` takes a type and one vector operand"));
    }
    let order = match (pinned, order) {
        (Some(pinned), _) => pinned,
        (None, Some(order)) => order,
        (None, None) if shape.elem_kind == 'i' => ReductionOrder::Sequential,
        (None, None) => {
            return Err(format!(
                "`{op}` states no order, and nested in a per-lane expression it has                  no realisation to take one from"
            ))
        }
    };
    reduce(op, scalar_op, &items[2], shape, lanes, mode, order).map(Some)
}

/// A scalar expression inside a scalable one -- `vdup`'s argument -- with any
/// reduction in it folded and nothing else lane-suffixed.
fn scalar_of(expr: &SemanticExpr, mode: &VectorMode<'_>) -> Result<SemanticExpr, String> {
    if let Some(value) = collapsed_value(expr, mode, None)? {
        return parse_formal_semantics(&value).map_err(|error| error.message);
    }
    match expr {
        SemanticExpr::Atom(_) => Ok(expr.clone()),
        SemanticExpr::List(items) => items
            .iter()
            .map(|item| scalar_of(item, mode))
            .collect::<Result<Vec<_>, _>>()
            .map(SemanticExpr::List),
    }
}

/// Nest the lane terms into one expression in the given order.
///
/// Binary in both shapes, never n-ary. The n-ary spelling would be shorter for
/// `add`/`and`/`or`/`xor` and wrong for `max`/`min`, which are binary in the
/// IR, so a flat fold would need an arity table to be correct. More to the
/// point, an n-ary node states no order at all, and for the float operators
/// the order *is* the value.
fn fold(terms: &[String], scalar_op: &str, element: &str, order: ReductionOrder) -> String {
    match order {
        ReductionOrder::Sequential => {
            let (first, rest) = terms.split_first().expect("a reduction has lanes");
            let mut folded = first.clone();
            for term in rest {
                folded = format!("({scalar_op} {element} {folded} {term})");
            }
            folded
        }
        ReductionOrder::Pairwise => {
            if terms.len() == 1 {
                return terms[0].clone();
            }
            // ⚠️ The split rounds UP, so the left half is never smaller than
            // the right. For a power-of-two lane count -- every shape SVE and
            // RVV actually have -- both halves are equal and this is Arm's
            // recursive pairwise exactly. The rounding rule only decides the
            // odd case, and it is written down rather than left to whichever
            // way the division happened to go, because a fold shape that
            // varies is not a pinned order.
            let mid = terms.len().div_ceil(2);
            format!(
                "({scalar_op} {element} {} {})",
                fold(&terms[..mid], scalar_op, element, order),
                fold(&terms[mid..], scalar_op, element, order)
            )
        }
    }
}

/// The reduction an expression is, if it is one: its name, the scalar operator
/// it folds with, and the order that fold takes.
///
/// `None` for the order means the operator does not pin one — the integer
/// reductions because their operators are associative and so cannot tell, the
/// unordered float one because its architecture declines to. Both resolve to
/// the ISA's realisation, and for the integer case that resolution is
/// provably invisible: `tools/reduction_order_check.py` requires every
/// associative reduction to give the same value under both.
fn as_reduction(
    expr: &SemanticExpr,
) -> Option<(&'static str, &'static str, Option<ReductionOrder>)> {
    let SemanticExpr::List(items) = expr else {
        return None;
    };
    let SemanticExpr::Atom(op) = items.first()? else {
        return None;
    };
    let pinned = |order| move |(name, scalar): &(&'static str, &'static str)| {
        (*name, *scalar, order)
    };
    ORDERED_REDUCTIONS
        .iter()
        .find(|(name, _)| name == op)
        .map(pinned(Some(ReductionOrder::Sequential)))
        .or_else(|| {
            PAIRWISE_REDUCTIONS
                .iter()
                .find(|(name, _)| name == op)
                .map(pinned(Some(ReductionOrder::Pairwise)))
        })
        .or_else(|| {
            REDUCTIONS
                .iter()
                .chain(UNSPECIFIED_REDUCTIONS)
                .find(|(name, _)| name == op)
                .map(pinned(None))
        })
}

/// Every expression a behavior holds, for shape discovery and for rewriting.
fn behavior_exprs(behavior: &crate::effects::Behavior) -> Vec<&SemanticExpr> {
    let mut out = Vec::new();
    for effect in &behavior.effects {
        if let crate::effects::Loc::Mem { addr, .. } = &effect.loc {
            out.push(&addr.expr);
        }
        out.push(&effect.value.expr);
        if let Some(guard) = &effect.guard {
            out.push(&guard.expr);
        }
    }
    out
}

/// Whether a behavior uses a scalable form at all.
pub fn behavior_mentions_scalable(behavior: &crate::effects::Behavior) -> bool {
    behavior_exprs(behavior)
        .into_iter()
        .any(|expr| mentions_scalable(&crate::effects::render_semexpr(expr)))
}

/// The shape and lane count a scalable behavior instantiates at.
pub fn behavior_shape(
    behavior: &crate::effects::Behavior,
    mode: &VectorMode<'_>,
) -> Result<Option<(Shapes, u32)>, String> {
    mode.legal()?;
    for expr in behavior_exprs(behavior) {
        if let Some((shape, operand, lanes)) = checked_lane_count(expr, mode)? {
            return Ok(Some((Shapes { result: shape, operand, collapsed: false }, lanes)));
        }
    }
    Ok(None)
}

/// Every symbol a behavior names, rendered: expressions plus the destination
/// register names, which live in the location rather than in any expression.
pub fn behavior_symbols_text(behavior: &crate::effects::Behavior) -> String {
    let mut parts: Vec<String> = behavior_exprs(behavior)
        .into_iter()
        .map(crate::effects::render_semexpr)
        .collect();
    for effect in &behavior.effects {
        if let crate::effects::Loc::Reg(name) = &effect.loc {
            parts.push(name.clone());
        }
    }
    parts.join(" ")
}

/// Build the value and accessibility guard of a fault-suppressing vector load.
///
/// `(vload_nf <type> base lo hi)` suppresses a fault on any lane that would
/// leave the accessible region, each lane judged independently -- SVE's
/// non-faulting `LDNF1`.
///
/// `(vload_ff <type> base lo hi)` stops at the *first* such lane, so lane l is
/// performed only if every lane before it was accessible too -- SVE's
/// first-faulting `LDFF1` and RVV's `vle*ff`.
///
/// The bounds are named rather than assumed: they are architectural state the
/// ISA declares, and writing them into the form keeps the document
/// self-describing instead of depending on two magic register names.
///
/// This is mechanism M5, and it is the reason it exists. A predicated load must
/// not fault on lanes it does not perform, and that cannot be modelled by
/// computing every lane and discarding some -- computing a lane is the thing
/// that faults. The predicate has to reach the access itself, which is why the
/// guard lives on the effect rather than wrapping its value.
fn fault_load(
    op: &str,
    items: &[SemanticExpr],
    shape: ScalableShape,
    lane: u32,
    mode: &VectorMode<'_>,
) -> Result<(SemanticExpr, SemanticExpr), String> {
    if items.len() != 5 {
        return Err(format!("`{op}` takes a type, a base, and the two bounds"));
    }
    let (SemanticExpr::Atom(lo), SemanticExpr::Atom(hi)) = (&items[3], &items[4]) else {
        return Err(format!("`{op}`'s bounds must be operands or state"));
    };
    // The base is a scalar: an operand, or an expression over them (Arm's
    // [Xn, #imm, MUL VL]).
    let base = crate::effects::render_semexpr(&scalar_of(&items[2], mode)?);
    let addr_ty = format!("i{}", mode.addr_bits);
    let bytes = u64::from(shape.elem / 8);
    let address = |index: u64| format!("(add {addr_ty} {base} {})", index * bytes);
    // A lane is accessible when its whole element lies inside [lo, hi).
    let reachable = |index: u64| {
        format!(
            "(and (icmp_uge {} {lo}) (icmp_uge {hi} (add {addr_ty} {} {bytes})))",
            address(index),
            address(index)
        )
    };

    let condition = match op {
        "vload_nf" => reachable(u64::from(lane)),
        // First-fault stops at the first inaccessible lane, so lane l is
        // performed only if every lane up to and including it is reachable.
        "vload_ff" => {
            let terms: Vec<String> = (0..=u64::from(lane)).map(reachable).collect();
            if terms.len() == 1 {
                terms.into_iter().next().expect("one term")
            } else {
                format!("(and {})", terms.join(" "))
            }
        }
        _ => return Err(format!("`{op}` is not a fault-suppressing load")),
    };
    let value = format!(
        "(load {} unsigned {})",
        shape.element_atom(),
        address(u64::from(lane))
    );
    Ok((
        parse_formal_semantics(&value).map_err(|error| error.message)?,
        parse_formal_semantics(&condition).map_err(|error| error.message)?,
    ))
}

/// Rewrite a behavior as it applies to one lane.
///
/// A destination register is per lane, like every other vector operand: lane l
/// of a vector load writes lane l of the destination. The *address* is where
/// this stage earns its place — S1 recorded that lane-to-register mapping is
/// not expressed in pure semantics, because a pure lane function is a function
/// of its parameters. An address is different: `base + lane * bytes` names the
/// lane explicitly, so a wrong mapping is finally something a gate can see.
pub fn instantiate_behavior(
    behavior: &crate::effects::Behavior,
    mode: &VectorMode<'_>,
    lane: u32,
) -> Result<crate::effects::Behavior, String> {
    let mut out = behavior.clone();
    for effect in &mut out.effects {
        match &mut effect.loc {
            crate::effects::Loc::Reg(name) => {
                *name = format!("{name}{}", lane_suffix(lane));
            }
            crate::effects::Loc::Mem { addr, width, .. } => {
                // The document writes the per-lane store width explicitly so it
                // reads honestly; disagreeing with the shape the address
                // describes is an error rather than a silent correction.
                if let Some((shape, _, _)) = checked_lane_count(&addr.expr, mode)? {
                    if *width != shape.elem {
                        return Err(format!(
                            "vector store writes {width} bits per lane but its address \
                             describes {}-bit elements",
                            shape.elem
                        ));
                    }
                }
                addr.expr = lane_of(&addr.expr, lane, mode)?;
            }
            _ => {}
        }
        let fault_form = match &effect.value.expr {
            SemanticExpr::List(items) => match (items.first(), items.get(1)) {
                (Some(SemanticExpr::Atom(op)), Some(SemanticExpr::Atom(type_atom)))
                    if op == "vload_nf" || op == "vload_ff" =>
                {
                    let shape = resolve_type_atom(type_atom, mode).ok_or_else(|| {
                        format!("`{op}` needs a scalable element type, not `{type_atom}`")
                    })?;
                    Some(fault_load(op, items, shape, lane, mode)?)
                }
                _ => None,
            },
            _ => None,
        };
        if let Some((value, reachable)) = fault_form {
            effect.value.expr = value;
            // An existing guard still applies: fault suppression narrows what
            // the instruction does, it does not replace the reason it was
            // conditional.
            effect.guard = Some(match effect.guard.take() {
                Some(mut existing) => {
                    existing.expr = SemanticExpr::List(vec![
                        SemanticExpr::Atom("and".to_string()),
                        lane_of(&existing.expr, lane, mode)?,
                        reachable,
                    ]);
                    existing
                }
                None => {
                    let mut guard = effect.value.clone();
                    guard.expr = reachable;
                    guard.load_address_width = None;
                    guard.width = mode.addr_bits;
                    guard
                }
            });
            continue;
        }
        effect.value.expr = lane_of(&effect.value.expr, lane, mode)?;
        if let Some(guard) = &mut effect.guard {
            guard.expr = lane_of(&guard.expr, lane, mode)?;
        }
    }
    Ok(out)
}

/// Rewrite a mixed-width application — one whose result element differs from
/// its operands' — as it applies to one lane.
fn mixed_lane(
    op: &str,
    dest: ScalableShape,
    src: ScalableShape,
    args: &[SemanticExpr],
    lane: u32,
    mode: &VectorMode<'_>,
) -> Result<SemanticExpr, String> {
    if dest.elem_kind != 'i' || src.elem_kind != 'i' {
        return Err(format!(
            "`{op}` mixes element widths, which is defined for bit-vector lanes only"
        ));
    }
    let rendered: Result<Vec<String>, String> = args
        .iter()
        .map(|arg| Ok(crate::effects::render_semexpr(&lane_of(arg, lane, mode)?)))
        .collect();
    let rendered = rendered?;

    if let Some((_, scalar_op, extend)) = WIDENING.iter().find(|(name, _, _)| *name == op) {
        if dest.elem != src.elem * 2 {
            return Err(format!(
                "`{op}` widens, so its result element ({}) must be twice its operand \
                 element ({})",
                dest.elem, src.elem
            ));
        }
        let widened: Vec<String> = rendered
            .iter()
            .map(|arg| format!("({extend} i{} {} {arg})", dest.elem, src.elem))
            .collect();
        return parse_formal_semantics(&format!(
            "({scalar_op} i{} {})",
            dest.elem,
            widened.join(" ")
        ))
        .map_err(|error| error.message);
    }

    if let Some((_, scalar_op)) = NARROWING.iter().find(|(name, _)| *name == op) {
        if src.elem != dest.elem * 2 {
            return Err(format!(
                "`{op}` narrows, so its operand element ({}) must be twice its result \
                 element ({})",
                src.elem, dest.elem
            ));
        }
        // Compute at the wide element and keep the low half. Both masks are
        // explicit rather than left to a backend's discretion.
        //
        // The shift-amount mask is not cosmetic. RVV takes the low lg2(2*SEW)
        // bits of the shift operand, and writing that down is what makes this
        // description say what it means: golden shifts at Python's arbitrary
        // precision, so an out-of-range amount shifts a value away entirely,
        // while LLVM masks it. No existing corpus had noticed, because every
        // other shift in AXIS takes its amount from a narrow encoded field and
        // can never be out of range. Here the amount is a full-width vector
        // element, so the disagreement is reachable -- and the fix is to state
        // the architectural rule, not to pick a backend.
        let amount = format!(
            "(and i{} {} {})",
            src.elem,
            rendered[1],
            mask_literal(src.elem.trailing_zeros())
        );
        // Every node here is at the *wide* element, with the final mask cutting
        // the result down. That is deliberate: an AXIS semantics function
        // evaluates in one width -- `tools/c_vs_golden.py` says so where it
        // picks a single C type per function -- so a wider node nested inside a
        // narrower one is outside the model. Written the other way round, LLVM
        // evaluated a 64-bit shift at 32 bits and masked the amount to 31
        // instead of 63; expressing the narrowing as a mask keeps one width and
        // says the same thing.
        return parse_formal_semantics(&format!(
            "(and i{} ({scalar_op} i{} {} {amount}) {})",
            src.elem,
            src.elem,
            rendered[0],
            mask_literal(dest.elem)
        ))
        .map_err(|error| error.message);
    }

    Err(format!(
        "`{op}` is not a known widening or narrowing operator; it takes two shapes \
         but does nothing with the difference"
    ))
}

/// All-ones at `width`, spelled as a hex literal the parser accepts.
fn mask_literal(width: u32) -> String {
    format!("0x{:x}", (1u128 << width) - 1)
}

/// What makes part of a result unspecified.
///
/// Two sources, and they are the two the architectures have: RVV's tail is
/// everything at or above `vl`, and a masked-off lane under an agnostic policy
/// is everything the predicate excludes. Both reduce to the same thing — a
/// per-lane definedness expression — which is why S2's machinery carries S4
/// without changing shape.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Partial {
    /// `(vtail <type> <vl> <body>)`: lanes at or above `vl`.
    Tail(String),
    /// `(vundef <type> <pg> <body>)`: lanes the predicate excludes.
    Masked(String),
}

/// Split an outermost `vtail` or `vundef` from its body.
fn split_partial(expr: &SemanticExpr) -> Result<Option<(Partial, SemanticExpr)>, String> {
    let SemanticExpr::List(items) = expr else {
        return Ok(None);
    };
    let Some(SemanticExpr::Atom(op)) = items.first() else {
        return Ok(None);
    };
    let build: fn(String) -> Partial = match op.as_str() {
        "vtail" => Partial::Tail,
        "vundef" => Partial::Masked,
        _ => return Ok(None),
    };
    if items.len() != 4 {
        return Err(format!(
            "`{op}` takes a type, {}, and a body",
            if op == "vtail" { "an active length" } else { "a predicate" }
        ));
    }
    let SemanticExpr::Atom(control) = &items[2] else {
        return Err(format!("`{op}`'s second argument must be an operand"));
    };
    Ok(Some((build(control.clone()), items[3].clone())))
}

/// Rewrite an expression as it applies to one lane.
///
/// A scalable application becomes the same operator at the element type. Every
/// symbol beneath it is a vector operand and takes the lane suffix; literals and
/// type atoms do not. The exception is `vdup`, whose argument is a *scalar*
/// broadcast to every lane and so keeps its name — which is the whole reason
/// `vdup` is a form rather than something an author could spell by hand.
fn lane_of(
    expr: &SemanticExpr,
    lane: u32,
    mode: &VectorMode<'_>,
) -> Result<SemanticExpr, String> {
    match expr {
        SemanticExpr::Atom(atom) => Ok(SemanticExpr::Atom(
            // Literals and architectural state are scalar; everything else in a
            // vector expression is a vector operand.
            if integer_literal(atom).is_some() || mode.state.iter().any(|name| name == atom) {
                atom.clone()
            } else {
                format!("{atom}{}", lane_suffix(lane))
            },
        )),
        SemanticExpr::List(items) => {
            // An UNTYPED comparison, or `and`/`or`/`not` of them -- a guard's
            // vocabulary -- over vector arguments is per lane: each argument
            // is taken at this lane. A predicated vector store is guarded by
            // its governing predicate lane by lane (S2c: SME's ST1W writes
            // only active elements), and that guard had no way to say so.
            if let Some(SemanticExpr::Atom(op)) = items.first() {
                let untyped = !matches!(items.get(1), Some(SemanticExpr::Atom(t))
                    if resolve_type_atom(t, mode).is_some() || crate::ir::type_atom_bits(t).is_some());
                if untyped
                    && (crate::ir::is_integer_comparison(op)
                        || matches!(op.as_str(), "and" | "or" | "not"))
                {
                    let mut rebuilt = vec![items[0].clone()];
                    for item in &items[1..] {
                        rebuilt.push(lane_of(item, lane, mode)?);
                    }
                    return Ok(SemanticExpr::List(rebuilt));
                }
            }
            // A `deffun` call is scalar: its arguments are this lane's, and the
            // call itself passes through -- emitted once, called per lane.
            if matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "call") {
                let mut rebuilt = items[..3.min(items.len())].to_vec();
                for arg in items.iter().skip(3) {
                    let SemanticExpr::List(pair) = arg else {
                        return Err("a `call` argument is `(iN value)`".to_string());
                    };
                    let [ty, value] = pair.as_slice() else {
                        return Err("a `call` argument is `(iN value)`".to_string());
                    };
                    rebuilt.push(SemanticExpr::List(vec![ty.clone(), lane_of(value, lane, mode)?]));
                }
                return Ok(SemanticExpr::List(rebuilt));
            }
            let (Some(SemanticExpr::Atom(op)), Some(SemanticExpr::Atom(type_atom))) =
                (items.first(), items.get(1))
            else {
                return Err("scalable semantics must be `(op type args...)`".to_string());
            };
            // A reduction (or `vcpop`, `vfirst`, `vextract`) inside a per-lane
            // expression is one scalar, the same in every lane.
            if let Some(value) = collapsed_value(expr, mode, None)? {
                return parse_formal_semantics(&value).map_err(|error| error.message);
            }
            let Some(shape) = resolve_type_atom(type_atom, mode) else {
                // A scalar sub-expression inside a scalable one: keep the
                // operator and type, rewrite the operands.
                let mut rebuilt = vec![items[0].clone(), items[1].clone()];
                for item in &items[2..] {
                    rebuilt.push(lane_of(item, lane, mode)?);
                }
                return Ok(SemanticExpr::List(rebuilt));
            };
            // Two shapes in a row is a mixed-width form: the first is the
            // result, the second the operands.
            if let Some(SemanticExpr::Atom(source_atom)) = items.get(2) {
                if let Some(source) = resolve_type_atom(source_atom, mode) {
                    return mixed_lane(op, shape, source, &items[3..], lane, mode);
                }
            }
            if op == "vtail" || op == "vundef" {
                return Err(format!(
                    "`{op}` must be the outermost form: what a result leaves \
                     unspecified is a property of the whole result, not of a \
                     sub-expression"
                ));
            }
            if op == "vmerge" {
                // `(vmerge <type> pg new old)`: per lane, the predicate chooses.
                // This is SVE's merging predication and RVV's mask-undisturbed
                // policy, and unlike `vundef` it is fully specified, so it
                // composes anywhere instead of having to be outermost.
                if items.len() != 5 {
                    return Err(
                        "`vmerge` takes a type, a predicate, a new value and an old one"
                            .to_string(),
                    );
                }
                let parts: Result<Vec<String>, String> = items[2..]
                    .iter()
                    .map(|item| {
                        Ok(crate::effects::render_semexpr(&lane_of(item, lane, mode)?))
                    })
                    .collect();
                let parts = parts?;
                return parse_formal_semantics(&format!(
                    "(select {} {} {} {})",
                    shape.element_atom(),
                    parts[0],
                    parts[1],
                    parts[2]
                ))
                .map_err(|error| error.message);
            }
            if op == "vload_map" || op == "vaddr_map" {
                if items.len() < 4 {
                    return Err(format!(
                        "`{op}` takes a type, a base and at least one `(dim <extent> <stride>)`"
                    ));
                }
                // A base may be a scalar EXPRESSION, left unsuffixed as `vdup`'s
                // source is: SME's LD1W/ST1W address `Xn + (Xm << 2)`, which
                // no single operand holds (S2c).
                let base_text = crate::effects::render_semexpr(&items[2]);
                let base = &base_text;
                let count = lane_count(shape, mode.vector_bits)?;
                let addr = format!("i{}", mode.addr_bits);
                let offset = map_offset(&items[3..], lane, count, &addr)?;
                let address = format!("(add {addr} {base} {offset})");
                let text = if op == "vload_map" {
                    format!("(load {} unsigned {address})", shape.element_atom())
                } else {
                    address
                };
                return parse_formal_semantics(&text).map_err(|error| error.message);
            }
            if op == "vaddr" || op == "vaddr_strided" {
                // A store's vector-ness cannot live in a value: `(store addr
                // value width)` becomes a `Loc::Mem` built by the effect
                // elaborator, so a `vstore` written as a value would never
                // become a memory location at all. Putting the shape in the
                // *address* keeps one expansion hook -- an address is an
                // ordinary expression, which the lane rewrite already walks.
                let strided = op == "vaddr_strided";
                if items.len() != if strided { 4 } else { 3 } {
                    return Err(format!(
                        "`{op}` takes a type, a base{}",
                        if strided { " and a stride" } else { "" }
                    ));
                }
                // A base may be a scalar EXPRESSION, left unsuffixed as `vdup`'s
                // source is: SME's LD1W/ST1W address `Xn + (Xm << 2)`, which
                // no single operand holds (S2c).
                let base_text = crate::effects::render_semexpr(&items[2]);
                let base = &base_text;
                let addr = format!("i{}", mode.addr_bits);
                let offset = if strided {
                    let SemanticExpr::Atom(step) = &items[3] else {
                        return Err("`vaddr_strided`'s stride must be an operand".to_string());
                    };
                    format!("(mul {addr} {step} {lane})")
                } else {
                    format!("{}", u64::from(lane) * u64::from(shape.elem / 8))
                };
                return parse_formal_semantics(&format!("(add {addr} {base} {offset})"))
                    .map_err(|error| error.message);
            }
            if op == "vload_indexed" || op == "vaddr_indexed" {
                // Gather and scatter. Lane l takes its offset from lane l of an
                // index vector, so unlike `vrgather` -- which reads an
                // *arbitrary* source lane and needs a select tree -- this is an
                // ordinary per-lane address function. The index operand is a
                // vector, so it is lane-indexed like any other.
                if items.len() != 4 {
                    return Err(format!("`{op}` takes a type, a base and an index vector"));
                }
                // A base may be a scalar EXPRESSION, left unsuffixed as `vdup`'s
                // source is: SME's LD1W/ST1W address `Xn + (Xm << 2)`, which
                // no single operand holds (S2c).
                let base_text = crate::effects::render_semexpr(&items[2]);
                let base = &base_text;
                let addr_ty = format!("i{}", mode.addr_bits);
                let index = crate::effects::render_semexpr(&lane_of(&items[3], lane, mode)?);
                let address = format!("(add {addr_ty} {base} {index})");
                let text = if op == "vaddr_indexed" {
                    address
                } else {
                    format!("(load {} unsigned {address})", shape.element_atom())
                };
                return parse_formal_semantics(&text).map_err(|error| error.message);
            }
            if matches!(op.as_str(), "viota" | "vmsbf" | "vmsif" | "vmsof") {
                // The mask family, and all four are the same question asked
                // differently: where does this lane sit relative to the active
                // ones before it? `viota` reports the prefix count itself; the
                // three set-first masks are comparisons against it.
                //
                //   vmsbf  set strictly before the first active lane
                //   vmsif  set up to and including it
                //   vmsof  set only at it
                if items.len() != 3 {
                    return Err(format!("`{op}` takes a type and a mask"));
                }
                let element = shape.element_atom();
                let before = prefix_count(&items[2], lane, &element, mode)?;
                let text = match op.as_str() {
                    "viota" => before,
                    // No active lane at or before this one.
                    "vmsbf" => format!(
                        "(and {element} (icmp_eq {element} {before} 0) (icmp_eq {element} {} 0))",
                        mask_active(&items[2], lane, &element, mode)?
                    ),
                    // None strictly before, whatever this lane is.
                    "vmsif" => format!("(icmp_eq {element} {before} 0)"),
                    // None before, and this lane is the one.
                    _ => format!(
                        "(and {element} (icmp_eq {element} {before} 0) {})",
                        mask_active(&items[2], lane, &element, mode)?
                    ),
                };
                return parse_formal_semantics(&text).map_err(|error| error.message);
            }
            if op == "vcompress" {
                // `(vcompress <type> src mask background)`: the active elements
                // of `src` packed into the low lanes.
                //
                // This is the hardest cross-lane shape and the reason is worth
                // naming. A gather asks "which source lane does output lane k
                // read?" and gets a runtime answer. A compress asks "which
                // output lane does source lane j *land in*?", and the answer is
                // a prefix count over the mask -- so output lane k has to test
                // every source lane against a running total that is itself a
                // sum over earlier lanes. That is cubic where a gather is
                // quadratic, which is why its ceiling is lower.
                //
                // Output lanes past the number of active elements take the
                // background operand, as RVV leaves them undisturbed.
                if items.len() != 5 {
                    return Err(
                        "`vcompress` takes a type, a source, a mask and a background"
                            .to_string(),
                    );
                }
                let count = lane_count(shape, mode.vector_bits)?;
                if count > MAX_COMPRESS_LANES {
                    return Err(format!(
                        "`vcompress` over {count} lanes is cubic in the lane count; the \
                         limit is {MAX_COMPRESS_LANES} lanes"
                    ));
                }
                let element = shape.element_atom();
                let mut tree =
                    crate::effects::render_semexpr(&lane_of(&items[4], lane, mode)?);
                for source in (0..count).rev() {
                    // How many active lanes precede this one: the position it
                    // compresses into.
                    let position = prefix_count(&items[3], source, &element, mode)?;
                    let value =
                        crate::effects::render_semexpr(&lane_of(&items[2], source, mode)?);
                    tree = format!(
                        "(select {element} (and {element} {} (icmp_eq {element} {position} {lane})) {value} {tree})",
                        mask_active(&items[3], source, &element, mode)?
                    );
                }
                return parse_formal_semantics(&tree).map_err(|error| error.message);
            }
            if op == "vrgather" {
                // `(vrgather <type> src idx)`: lane l reads source lane
                // `idx[l]`, chosen at runtime. That is the one permute that
                // cannot be a static map, so it becomes a select tree over
                // every source lane -- quadratic in the lane count.
                //
                // Quadratic is why this was excluded rather than impossible,
                // and a stated size limit says that better than a blanket
                // refusal does: it is exact up to the bound and refuses beyond
                // it with the reason, instead of being absent and looking like
                // a gap in the language.
                //
                // An index at or above the lane count reads zero, which is what
                // RVV specifies for an out-of-range gather.
                if items.len() != 4 {
                    return Err("`vrgather` takes a type, a source and an index".to_string());
                }
                let count = lane_count(shape, mode.vector_bits)?;
                if count > MAX_GATHER_LANES {
                    return Err(format!(
                        "`vrgather` over {count} lanes needs {} select nodes per lane, \
                         which is quadratic; the limit is {MAX_GATHER_LANES} lanes",
                        count
                    ));
                }
                let element = shape.element_atom();
                let index = crate::effects::render_semexpr(&lane_of(&items[3], lane, mode)?);
                let mut tree = "0".to_string();
                for source in (0..count).rev() {
                    let value =
                        crate::effects::render_semexpr(&lane_of(&items[2], source, mode)?);
                    tree = format!(
                        "(select {element} (icmp_eq {element} {index} {source}) {value} {tree})"
                    );
                }
                return parse_formal_semantics(&tree).map_err(|error| error.message);
            }
            // SME's slices (S2b): a row or column of a tile chosen at RUN time.
            //
            //   (vrow <type> <cols>)             lane k's own row, k / cols
            //   (vcol <type> <cols>)             lane k's own column, k % cols
            //   (vslice <type> <cols> t index)   lane j reads t[index * cols + j]
            //   (vslicev <type> <cols> t index)  lane i reads t[i * cols + index]
            //
            // A WRITE to slice `index` needs no new addressing: as a whole-tile
            // operation, lane k knows its row and changes only where it equals
            // the index -- `(vmerge <m> (icmp_eq <m> (vrow <m> c) (vdup <m> x))
            // new old)`. A READ is the other direction: one result lane may come
            // from any of `cols` tile elements, so it is a select chain over
            // them, keyed on the index. The index is a scalar expression
            // evaluated at run time -- a general register plus an immediate --
            // and is left unsuffixed, as `vdup`'s source is.
            if op == "vrow" || op == "vcol" {
                let count = lane_count(shape, mode.vector_bits)?;
                let [SemanticExpr::Atom(text)] = &items[2..] else {
                    return Err(format!("`{op}` takes a type and a column count"));
                };
                let cols = integer_literal(text)
                    .filter(|&cols| cols > 0 && u128::from(count) % cols == 0)
                    .ok_or_else(|| format!("`{op}`'s column count must divide the {count} lanes"))?
                    as u32;
                let value = if op == "vrow" { lane / cols } else { lane % cols };
                return Ok(SemanticExpr::Atom(value.to_string()));
            }
            if op == "vslice" || op == "vslicev" {
                let count = lane_count(shape, mode.vector_bits)?;
                if items.len() != 5 {
                    return Err(format!("`{op}` takes a type, a column count, a tile and an index"));
                }
                let SemanticExpr::Atom(text) = &items[2] else {
                    return Err(format!("`{op}`'s column count must be a literal"));
                };
                let cols = integer_literal(text)
                    .ok_or_else(|| format!("`{op}`'s column count must be a literal"))? as u32;
                // The result is one slice of a square tile: `cols` lanes.
                if cols != count {
                    return Err(format!(
                        "`{op}` reads a slice of {cols} element(s) into a result of {count} lane(s)"
                    ));
                }
                let SemanticExpr::Atom(tile) = &items[3] else {
                    return Err(format!("`{op}`'s tile must be an operand"));
                };
                let index = crate::effects::render_semexpr(&items[4]);
                let element = shape.element_atom();
                let at = |slice: u32| {
                    let source = if op == "vslice" { slice * cols + lane } else { lane * cols + slice };
                    format!("{tile}{}", lane_suffix(source))
                };
                // Highest slice first, so the chain reads lowest-first and an
                // index past the last slice takes the last -- the index is
                // reduced modulo the tile by the description, as Arm reduces it.
                let mut chain = at(cols - 1);
                for slice in (0..cols - 1).rev() {
                    chain = format!("(select {element} (icmp_eq {element} {index} {slice}) {} {chain})", at(slice));
                }
                return parse_formal_semantics(&chain).map_err(|error| error.message);
            }
            if let Some(pick) = matrix_sources(op) {
                let count = lane_count(shape, mode.vector_bits)?;
                if items.len() != 4 {
                    return Err(format!("`{op}` takes a type, a column count and one operand"));
                }
                let SemanticExpr::Atom(text) = &items[2] else {
                    return Err(format!("`{op}`'s column count must be a literal"));
                };
                let cols = integer_literal(text)
                    .ok_or_else(|| format!("`{op}`'s column count must be a literal"))?
                    as u32;
                // A rectangle, or it is not a matrix. A column count that does
                // not divide the lanes describes rows of different lengths,
                // and the index arithmetic would quietly wrap instead of
                // saying so.
                if cols == 0 || count % cols != 0 {
                    return Err(format!(
                        "`{op}` names {cols} column(s) over {count} lanes, which is not \
                         a whole number of rows"
                    ));
                }
                let source = pick(lane, count, cols);
                // ⚠️ A correct index cannot leave the vector -- every map here
                // is a permutation of `0..count` when `cols` divides it -- so
                // this catches an incorrect one rather than a legal case. It
                // exists because an index that ran off the end did not fail:
                // `lane_of` renamed the operand to a lane nobody declared, and
                // the first thing to notice was a gate crashing with a missing
                // name two stages downstream. An out-of-range index is a
                // description that is wrong, and it says so here.
                if source >= count {
                    return Err(format!(
                        "`{op}` lane {lane} reads source lane {source} of {count}; \
                         an index function must stay inside the vector"
                    ));
                }
                return lane_of(&items[3], source, mode);
            }
            if let Some(sources) = permute_sources(op) {
                // A structured permute is a static map from an output lane to
                // an input lane, so in the lane-indexed representation it is
                // nothing more than reading a different lane's operand. No new
                // machinery, only a different index -- which is the same shape
                // the address functions took in S5.
                let count = lane_count(shape, mode.vector_bits)?;
                let (arity, pick) = sources;
                if items.len() != 2 + arity {
                    return Err(format!("`{op}` takes a type and {arity} operands"));
                }
                let immediate = if arity == 3 {
                    let SemanticExpr::Atom(text) = &items[4] else {
                        return Err(format!("`{op}`'s immediate must be a literal"));
                    };
                    integer_literal(text)
                        .ok_or_else(|| format!("`{op}`'s immediate must be a literal"))?
                        as u32
                } else {
                    0
                };
                let (which, source_lane) = pick(lane, count, immediate);
                // `which` selects between the two vector operands; a permute
                // that runs off the end takes the background operand instead,
                // which is how an undisturbed slide says so rather than
                // inventing a zero.
                return lane_of(&items[2 + which], source_lane, mode);
            }
            if op == "vload_seg" {
                // `(vload_seg <type> <nf> <field> base)`: a segment load reads
                // interleaved structures, so field f of element l sits at
                // `base + (l*nf + f)*bytes`. Once more the address function is
                // the only new thing -- M4 again.
                //
                // Each field is its own destination and so its own effect, and
                // because instantiation already splits by lane, a lane
                // instruction holds nf single-lane writes rather than one wide
                // one. That keeps SVE's LD2/LD3/LD4 inside EFFECT_MAX_WRITES
                // without raising it; RVV's nf up to 8 would need the bump the
                // design anticipated, and is not described here.
                if items.len() != 5 {
                    return Err(
                        "`vload_seg` takes a type, a field count, a field index and a base"
                            .to_string(),
                    );
                }
                let (SemanticExpr::Atom(nf), SemanticExpr::Atom(field)) = (&items[2], &items[3])
                else {
                    return Err("`vload_seg`'s field count and index must be literals".to_string());
                };
                // The base is a scalar: an operand, or -- Arm's LD2W at
                // [Xn, #imm, MUL VL] -- an expression over them, as `vload`'s is.
                let base = crate::effects::render_semexpr(&scalar_of(&items[4], mode)?);
                let (nf, field) = match (integer_literal(nf), integer_literal(field)) {
                    (Some(nf), Some(field)) if nf > 0 && field < nf => (nf, field),
                    _ => {
                        return Err(format!(
                            "`vload_seg` field {field} is not inside a segment of {nf}"
                        ))
                    }
                };
                let addr = format!("i{}", mode.addr_bits);
                let index = u128::from(lane) * nf + field;
                let offset = index * u128::from(shape.elem / 8);
                return parse_formal_semantics(&format!(
                    "(load {} unsigned (add {addr} {base} {offset}))",
                    shape.element_atom()
                ))
                .map_err(|error| error.message);
            }
            if op == "vload" || op == "vload_strided" {
                // `(vload <type> base)` and `(vload_strided <type> base step)`.
                // Lane l reads `base + l*bytes` or `base + l*step`: the address
                // function is the only difference between the two, which is the
                // whole of mechanism M4 -- gather is a third function, not a
                // third mechanism.
                //
                // The base and step are scalars, so like `vdup`'s source they
                // must not be lane-indexed. The lane index is the constant.
                let strided = op == "vload_strided";
                if items.len() != if strided { 4 } else { 3 } {
                    return Err(format!(
                        "`{op}` takes a type, a base{}",
                        if strided { " and a stride" } else { "" }
                    ));
                }
                // A base may be a scalar EXPRESSION, left unsuffixed as `vdup`'s
                // source is: SME's LD1W/ST1W address `Xn + (Xm << 2)`, which
                // no single operand holds (S2c).
                let base_text = crate::effects::render_semexpr(&items[2]);
                let base = &base_text;
                let addr = format!("i{}", mode.addr_bits);
                let offset = if strided {
                    let SemanticExpr::Atom(step) = &items[3] else {
                        return Err("`vload_strided`'s stride must be an operand".to_string());
                    };
                    format!("(mul {addr} {step} {lane})")
                } else {
                    format!("{}", u64::from(lane) * u64::from(shape.elem / 8))
                };
                return parse_formal_semantics(&format!(
                    "(load {} unsigned (add {addr} {base} {offset}))",
                    shape.element_atom()
                ))
                .map_err(|error| error.message);
            }
            if op == "vmap" {
                // `(vmap <type> ((name source) ...) body)`: the body once per
                // lane, each name bound to that lane of its source -- the
                // fixed-width `vmap` (simd.rs), for a lane count VL decides.
                //
                // Arm's FMAX is why: its NaN and signed-zero rules are a
                // chain of steps over one element (the corpus's `defsem`),
                // and a lane had nowhere to put a chain. Bound by `let`, as
                // the fixed form is, so a body's own names shadow correctly.
                let (Some(SemanticExpr::List(bindings)), Some(body), 4) =
                    (items.get(2), items.get(3), items.len())
                else {
                    return Err("`vmap` takes a type, a binding list and a body".to_string());
                };
                if bindings.is_empty() {
                    return Err("`vmap` binds no lane values, so its body cannot depend on the lane".to_string());
                }
                let mut bound = Vec::new();
                for binding in bindings {
                    let SemanticExpr::List(pair) = binding else {
                        return Err("a `vmap` binding is `(name source)`".to_string());
                    };
                    let (Some(SemanticExpr::Atom(name)), Some(source), 2) =
                        (pair.first(), pair.get(1), pair.len())
                    else {
                        return Err("a `vmap` binding is `(name source)`".to_string());
                    };
                    bound.push(SemanticExpr::List(vec![
                        SemanticExpr::Atom(name.clone()),
                        lane_of(source, lane, mode)?,
                    ]));
                }
                return Ok(SemanticExpr::List(vec![
                    SemanticExpr::Atom("let".to_string()),
                    SemanticExpr::List(bound),
                    body.clone(),
                ]));
            }
            if op == "vsegperm" {
                // `(vsegperm <type> src k0 ... k(n-1))`: a fixed shuffle within
                // each 128-bit segment -- element j of a segment reads element
                // k(j) of the same segment of `src`. ShiftRows and AES's
                // column reads are such shuffles. `vrgather` could say them,
                // but its index is a runtime value, so every output lane named
                // every source lane: AESE rendered to 11 MB of C. A static
                // shuffle names exactly the one it reads, as ZIP's lanes do.
                let per_segment = 128 / shape.elem;
                if items.len() != 3 + per_segment as usize {
                    return Err(format!(
                        "`vsegperm` takes a type, a source and {per_segment} indices for {}-bit elements",
                        shape.elem
                    ));
                }
                let segment = lane / per_segment;
                let SemanticExpr::Atom(text) = &items[3 + (lane % per_segment) as usize] else {
                    return Err("`vsegperm`'s indices must be literals".to_string());
                };
                let k = integer_literal(text)
                    .filter(|k| (*k as u64) < u64::from(per_segment))
                    .ok_or_else(|| format!("`vsegperm` index `{text}` is not an element of a segment"))?;
                return lane_of(&items[2], segment * per_segment + k as u32, mode);
            }
            if op == "vinbounds" {
                // `(vinbounds <type> base lo hi)`: 1 where this lane's element
                // of a contiguous access from `base` lies wholly inside
                // [lo, hi), 0 where any byte of it does not.
                //
                // Arm's first-fault and non-fault loads need this as a VALUE,
                // not only as the guard `vload_ff` puts on an access: a lane
                // the load suppresses clears the FFR from that element on, and
                // what it suppresses depends on which *active* lanes before it
                // were reachable -- a prefix question `vmsbf` already asks, of
                // a mask this supplies.
                if items.len() != 5 {
                    return Err("`vinbounds` takes a type, a base and the two bounds".to_string());
                }
                let element = shape.element_atom();
                let addr_ty = format!("i{}", mode.addr_bits);
                let base = crate::effects::render_semexpr(&scalar_of(&items[2], mode)?);
                let lo = crate::effects::render_semexpr(&lane_of(&items[3], lane, mode)?);
                let hi = crate::effects::render_semexpr(&lane_of(&items[4], lane, mode)?);
                let bytes = u64::from(shape.elem / 8);
                let start = format!("(add {addr_ty} {base} {})", u64::from(lane) * bytes);
                let end = format!("(add {addr_ty} {base} {})", (u64::from(lane) + 1) * bytes);
                return parse_formal_semantics(&format!(
                    "(select {element} (icmp_uge {addr_ty} {start} {lo}) \
                     (select {element} (icmp_uge {addr_ty} {hi} {end}) \
                     (select {element} (icmp_uge {addr_ty} {end} {start}) 1 0) 0) 0)"
                ))
                .map_err(|error| error.message);
            }
            if op == "vid" {
                // `(vid <type>)`: lane l reads l. RVV spells it `vid.v`; SVE
                // reaches the same value through `index`.
                //
                // It needs no backend of its own, and that is the point rather
                // than a shortcut. Every other lane-aware operator here lowers
                // to ordinary scalar work with `{lane}` substituted as a
                // constant -- `vload` already emits a bare literal offset the
                // same way -- so a lane index IS a constant once the lanes
                // exist, and the golden model, SMT, C, Rust and LLVM backends
                // see an integer they already handle. An operator that reached
                // five backends would be a different proposition; this one
                // reaches none.
                //
                // Why it exists: `viota` is the prefix count over a MASK
                // operand, so it can express an iota only for an instruction
                // that encodes a source register to name. A lane-identity
                // instruction encodes no source -- there is nothing to count --
                // and GRV's `vlaneid` is exactly that shape.
                if items.len() != 2 {
                    return Err("`vid` takes a type and nothing else".to_string());
                }
                return parse_formal_semantics(&format!("{lane}"))
                    .map_err(|error| error.message);
            }
            if op == "vwhilelt" {
                // `(vwhilelt <type> idx count)`: lane l is active while
                // `idx + l < count`. Both arguments are scalars, so like
                // `vdup`'s source they are the operands that must not be
                // lane-indexed -- the lane index is the constant here.
                if items.len() != 4 {
                    return Err("`vwhilelt` takes a type, a base and a count".to_string());
                }
                let (SemanticExpr::Atom(base), SemanticExpr::Atom(count)) =
                    (&items[2], &items[3])
                else {
                    return Err("`vwhilelt`'s base and count must be operands".to_string());
                };
                let element = shape.element_atom();
                return parse_formal_semantics(&format!(
                    "(icmp_ult {element} (add {element} {base} {lane}) {count})"
                ))
                .map_err(|error| error.message);
            }
            if op == "vdup" {
                if items.len() != 3 {
                    return Err("`vdup` takes one scalar argument".to_string());
                }
                // The broadcast source is scalar, so it is the one symbol that
                // must *not* be lane-suffixed -- unless it is a reduction, which
                // is a scalar only once it has been folded.
                return scalar_of(&items[2], mode);
            }
            if !scalable_lane_parallel(op, shape.elem_kind) {
                return Err(format!(
                    "operator `{op}` is not lane-local, so `{type_atom}` has no meaning for \
                     it; cross-lane behaviour is stage S6"
                ));
            }
            let mut rebuilt = vec![
                SemanticExpr::Atom(op.clone()),
                SemanticExpr::Atom(shape.element_atom()),
            ];
            for item in &items[2..] {
                rebuilt.push(lane_of(item, lane, mode)?);
            }
            Ok(SemanticExpr::List(rebuilt))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tests below predate the realisation knob; `Compute` is the
    /// realisation that leaves a lane's value alone, so it is what they mean.
    fn mode(vector_bits: u32) -> VectorMode<'static> {
        VectorMode { vector_bits, ..VectorMode::default() }
    }

    fn inst(text: &str, vector_bits: u32)
        -> Result<Option<(Shapes, Vec<Lane>, Option<String>)>, String> {
        instantiate(text, &mode(vector_bits), Realization::Compute, ReductionOrder::Sequential)
    }

    #[test]
    fn parses_scalable_atoms_without_colliding_with_fixed_ones() {
        assert_eq!(
            scalable_type_atom("vni32"),
            Some(ScalableShape { elem: 32, elem_kind: 'i', num: 1, den: 1, square: false })
        );
        assert_eq!(
            scalable_type_atom("vnf64"),
            Some(ScalableShape { elem: 64, elem_kind: 'f', num: 1, den: 1, square: false })
        );
        // The fixed spelling is not a scalable one, and vice versa.
        assert_eq!(scalable_type_atom("v2i32"), None);
        assert_eq!(crate::simd::vector_type_atom("vni32"), None);
        assert_eq!(scalable_type_atom("i32"), None);
        assert_eq!(scalable_type_atom("vni7"), None);
        // Half precision is a float lane since the FP16 work (SVE's .H forms);
        // a byte-wide float is not.
        assert_eq!(
            scalable_type_atom("vnf16"),
            Some(ScalableShape { elem: 16, elem_kind: 'f', num: 1, den: 1, square: false })
        );
        assert_eq!(scalable_type_atom("vnf8"), None);
    }

    #[test]
    fn instantiates_one_scalar_expression_per_lane() {
        let (shape, lanes, _) = inst("(add vni32 zn zm)", 128).unwrap().unwrap();
        assert_eq!(shape.result.elem, 32);
        assert_eq!(lanes.len(), 4);
        assert_eq!(lanes[0].value, "(add i32 zn__l0 zm__l0)");
        assert_eq!(lanes[3].value, "(add i32 zn__l3 zm__l3)");
    }

    #[test]
    fn a_reduction_nested_in_a_lane_expression_is_one_scalar_in_every_lane() {
        // Arm's UADDV: the sum of the active elements into element 0, the rest
        // zero. The reduction is over one shape and the result over another.
        let (shapes, lanes, _) = inst(
            "(vmerge vni64 (icmp_eq vni64 (vid vni64) (vdup vni64 0)) \
             (vdup vni64 (vredsum vni64 (vmerge vni64 (and vni64 pg 1) zn 0))) 0)",
            128,
        )
        .unwrap()
        .unwrap();
        assert!(!shapes.collapsed, "the result is still a vector");
        assert_eq!(lanes.len(), 2);
        assert!(lanes[0].value.contains("zn__l0") && lanes[0].value.contains("zn__l1"),
                "lane 0 reads every lane of the sum: {}", lanes[0].value);
        // A predicate's sixteen byte lanes inside a two-lane result: the nested
        // count is its own, not the result's.
        let (_, lanes, _) = inst(
            "(vmerge vni64 (icmp_eq vni64 (vid vni64) (vdup vni64 0)) \
             (vdup vni64 (zext i64 8 (vcpop vni8 pg))) 0)",
            128,
        )
        .unwrap()
        .unwrap();
        assert!(lanes[0].value.contains("pg__l15"), "{}", lanes[0].value);
        // An unordered float reduction has no order to nest with.
        let error = inst("(vmerge vnf32 m (vdup vnf32 (vfredusum vnf32 zn)) zn)", 128)
            .unwrap_err();
        assert!(error.contains("states no order"), "{error}");
    }

    #[test]
    fn arm_s_last_active_element_and_its_64_bit_sums() {
        // LASTB: the highest active lane wins; none active reads the last.
        let (shapes, lanes, _) = inst("(vlastb vni32 (and vni32 pg 1) zn)", 128).unwrap().unwrap();
        assert!(shapes.collapsed);
        let value = &lanes[0].value;
        assert!(value.starts_with("(select i32 (icmp_ne i32 (and i32 pg__l3 1) 0) zn__l3"), "{value}");
        assert!(value.ends_with("zn__l3))))"), "the fallback is the last lane: {value}");
        // vmap: the body once per lane, each name bound to that lane of its source.
        let (_, lanes, _) = inst("(vmap vni32 ((a zn) (b zm)) (add i32 a b))", 128).unwrap().unwrap();
        assert_eq!(lanes.len(), 4);
        assert!(lanes[3].value.contains("zn__l3") && lanes[3].value.contains("zm__l3"),
                "{}", lanes[3].value);
        assert!(lanes[3].value.starts_with("(let"), "bound, not substituted: {}", lanes[3].value);
        // vsegperm: a fixed shuffle within each 128-bit segment names exactly
        // the one source lane it reads -- here a reversal of four words.
        let (_, lanes, _) = inst("(vsegperm vni32 zn 3 2 1 0)", 256).unwrap().unwrap();
        assert_eq!(lanes.len(), 8);
        assert_eq!(lanes[0].value, "zn__l3");
        assert_eq!(lanes[5].value, "zn__l6", "the second segment shuffles within itself");
        assert!(inst("(vsegperm vni32 zn 3 2 1)", 128).is_err(), "one index per element of a segment");
        // Half-precision lanes: eight of them at VL = 128.
        let (_, lanes, _) = inst("(fadd vnf16 zn zm)", 128).unwrap().unwrap();
        assert_eq!(lanes.len(), 8);
        // vinbounds: lane l's element [base + 4l, base + 4l + 4) inside [lo, hi).
        let (_, lanes, _) = inst("(vinbounds vni32 rn mem_lo mem_hi)", 128).unwrap().unwrap();
        assert_eq!(lanes.len(), 4);
        assert!(lanes[2].value.contains("(add i64 rn 8)") && lanes[2].value.contains("(add i64 rn 12)"),
                "{}", lanes[2].value);
        assert!(lanes[2].value.contains("mem_hi"), "the bounds are state, not lanes: {}", lanes[2].value);
        // LASTA: the lane after the last active, wrapping; none active reads lane 0.
        let (_, lanes, _) = inst("(vlasta vni32 (and vni32 pg 1) zn)", 128).unwrap().unwrap();
        let value = &lanes[0].value;
        assert!(value.starts_with("(select i32 (icmp_ne i32 (and i32 pg__l3 1) 0) zn__l0"), "{value}");
        assert!(value.ends_with("zn__l0))))"), "none active reads lane 0: {value}");
        // UADDV over bytes sums at 64 bits: sixteen 0xff lanes do not wrap.
        let (_, lanes, _) = inst("(vuaddv vni8 zn)", 128).unwrap().unwrap();
        assert!(lanes[0].value.contains("(zext i64 8 zn__l15)"), "{}", lanes[0].value);
        // CNTP: a scalar outermost form folds, and is one lane.
        let (shapes, lanes, _) =
            inst("(zext i64 32 (vcpop vni32 (and vni32 pg pn)))", 128).unwrap().unwrap();
        assert!(shapes.collapsed);
        assert_eq!(lanes.len(), 1);
        assert!(!lanes[0].value.contains("vcpop"), "{}", lanes[0].value);
    }

    #[test]
    fn lane_count_grows_past_the_packed_representation_ceiling() {
        // The whole point: 512 bits of i32 lanes is 16 lanes, which the packed
        // V1 expansion cannot represent at all (`u128` literals cap it at 128).
        let (_, lanes, _) = inst("(add vni32 zn zm)", 512).unwrap().unwrap();
        assert_eq!(lanes.len(), 16);
        assert_eq!(lanes[15].value, "(add i32 zn__l15 zm__l15)");
    }

    #[test]
    fn vdup_broadcasts_a_scalar_without_suffixing_it() {
        let (_, lanes, _) = inst("(add vni32 zn (vdup vni32 rs))", 128)
            .unwrap()
            .unwrap();
        assert_eq!(lanes[2].value, "(add i32 zn__l2 rs)");
    }

    #[test]
    fn float_lanes_reuse_the_same_machinery() {
        let (shape, lanes, _) = inst("(fadd vnf64 zn zm)", 256).unwrap().unwrap();
        assert_eq!(shape.result.elem_kind, 'f');
        assert_eq!(lanes.len(), 4);
        assert_eq!(lanes[1].value, "(fadd f64 zn__l1 zm__l1)");
    }

    #[test]
    fn mixed_shapes_are_refused_rather_than_guessed() {
        let error = inst("(add vni32 zn (mul vni16 a b))", 128).unwrap_err();
        assert!(error.contains("must keep its lane count"), "{error}");
    }

    #[test]
    fn an_unknown_cross_lane_operator_is_still_refused() {
        // This example has now moved four times -- vredsum, vrgather,
        // vcompress, viota -- because each was implemented in turn. The
        // assertion was always right and the example always temporary, so it
        // is now a name no architecture will ever ask for. The rule under test
        // is that an operator this module does not describe is refused rather
        // than guessed at; which operators those are is not the test's business
        // and never was.
        let error = inst("(vnosuchoperator vni32 zn zm)", 128).unwrap_err();
        assert!(error.contains("not lane-local"), "{error}");
    }

    #[test]
    fn vrgather_selects_a_runtime_chosen_source_lane() {
        let lanes = lanes_at("(vrgather vni32 zn idx)", &mode(128));
        assert_eq!(lanes.len(), 4);
        // Lane 1 reads whichever source lane its own index element names, and
        // an index at or above the lane count reads zero, as RVV specifies.
        assert_eq!(
            lanes[1],
            "(select i32 (icmp_eq i32 idx__l1 0) zn__l0 \
             (select i32 (icmp_eq i32 idx__l1 1) zn__l1 \
             (select i32 (icmp_eq i32 idx__l1 2) zn__l2 \
             (select i32 (icmp_eq i32 idx__l1 3) zn__l3 0))))"
                .replace("             ", "")
        );
    }

    #[test]
    fn a_gather_past_the_ceiling_is_refused_with_its_reason() {
        // 64 lanes of 8-bit elements would be about four thousand select nodes
        // in one instruction. Refused, and the message says why rather than
        // leaving the operator looking absent from the language.
        let error = inst("(vrgather vni8 zn idx)", 512).unwrap_err();
        assert!(error.contains("quadratic"), "{error}");
    }

    #[test]
    fn a_reduction_reads_every_lane_and_stays_one_instruction() {
        let (shape, lanes, _) = inst("(vredsum vni32 zn)", 128).unwrap().unwrap();
        assert!(shape.collapsed);
        assert_eq!(lanes.len(), 1);
        assert_eq!(
            lanes[0].value,
            "(add i32 (add i32 (add i32 zn__l0 zn__l1) zn__l2) zn__l3)"
        );
    }

    #[test]
    fn an_ordered_float_reduction_writes_its_order_down() {
        // Floating-point addition is not associative, so a reduction has no
        // value until the order is pinned. The nesting is the pinning.
        let (_, lanes, _) = inst("(vfredosum vnf32 zn)", 128).unwrap().unwrap();
        assert_eq!(
            lanes[0].value,
            "(fadd f32 (fadd f32 (fadd f32 zn__l0 zn__l1) zn__l2) zn__l3)"
        );
    }

    #[test]
    fn an_outer_product_is_two_index_functions_and_a_multiply() {
        // Sixteen lanes as a four-by-four tile: element k reads zn[k / 4] and
        // zm[k % 4]. Both operands are SHORTER than the result, which is what
        // an outer product is and what needed no second shape to say.
        let (_, lanes, _) = inst("(mul vni32 (vrows vni32 4 zn) (vcols vni32 4 zm))", 512)
            .unwrap()
            .unwrap();
        assert_eq!(lanes.len(), 16);
        assert_eq!(lanes[0].value, "(mul i32 zn__l0 zm__l0)");
        assert_eq!(lanes[5].value, "(mul i32 zn__l1 zm__l1)");
        assert_eq!(lanes[6].value, "(mul i32 zn__l1 zm__l2)");
        assert_eq!(lanes[15].value, "(mul i32 zn__l3 zm__l3)");
    }

    #[test]
    fn a_transpose_reads_the_other_index() {
        let (_, lanes, _) = inst("(vtranspose vni32 4 zn)", 512).unwrap().unwrap();
        assert_eq!(lanes[1].value, "zn__l4");
        assert_eq!(lanes[4].value, "zn__l1");
        // Non-square, where `cols` names the RESULT's columns: eight of them
        // over sixteen lanes is a two-row result read from an eight-row,
        // two-column source. The divisor is the lane count over the columns
        // and not the columns again, which a square tile cannot tell apart.
        let (_, wide, _) = inst("(vtranspose vni32 8 zn)", 512).unwrap().unwrap();
        assert_eq!(wide[1].value, "zn__l2");
        assert_eq!(wide[2].value, "zn__l4");
        assert_eq!(wide[8].value, "zn__l1");
    }

    #[test]
    fn an_access_map_of_one_dimension_is_the_stride_it_names() {
        let (_, lanes, _) = inst("(vaddr_map vni32 rs1 (dim 16 4))", 512).unwrap().unwrap();
        assert_eq!(lanes[0].value, "(add i64 rs1 0)");
        assert_eq!(lanes[3].value, "(add i64 rs1 (mul i64 4 3))");
    }

    #[test]
    fn an_access_map_of_two_dimensions_is_a_tile() {
        // Rows at a register stride, elements contiguous within them: AMX's
        // TILELOADD. The lane decomposes at elaboration, so the index is a
        // literal by the time it multiplies an operand.
        let (_, lanes, _) = inst("(vaddr_map vni32 rs1 (dim 4 rs2) (dim 4 4))", 512)
            .unwrap()
            .unwrap();
        assert_eq!(lanes[0].value, "(add i64 rs1 0)");
        assert_eq!(lanes[1].value, "(add i64 rs1 (mul i64 4 1))");
        assert_eq!(lanes[4].value, "(add i64 rs1 (mul i64 rs2 1))");
        assert_eq!(
            lanes[5].value,
            "(add i64 rs1 (add i64 (mul i64 rs2 1) (mul i64 4 1)))"
        );
    }

    #[test]
    fn an_access_map_must_cover_the_lanes() {
        let error = inst("(vaddr_map vni32 rs1 (dim 3 rs2) (dim 4 4))", 512).unwrap_err();
        assert!(error.contains("3 x 4"), "{error}");
        assert!(error.contains("the shape has 16"), "{error}");
    }

    #[test]
    fn a_tile_must_be_rectangular() {
        let error = inst("(vrows vni32 3 zn)", 512).unwrap_err();
        assert!(error.contains("whole number of rows"), "{error}");
    }

    #[test]
    fn a_pairwise_reduction_folds_a_tree() {
        // SVE's FADDV. Different value from the left fold above, not a
        // different spelling of it: (a+b)+(c+d) and ((a+b)+c)+d disagree in
        // IEEE-754 for inputs the gate exhibits.
        let (_, lanes, _) = inst("(vfredpsum vnf32 zn)", 128).unwrap().unwrap();
        assert_eq!(
            lanes[0].value,
            "(fadd f32 (fadd f32 zn__l0 zn__l1) (fadd f32 zn__l2 zn__l3))"
        );
    }

    #[test]
    fn an_unordered_reduction_takes_the_realisation_and_a_pinned_one_does_not() {
        let pairwise = |text: &str| {
            instantiate(text, &mode(128), Realization::Compute, ReductionOrder::Pairwise)
                .unwrap()
                .unwrap()
                .1[0]
                .value
                .clone()
        };
        // The unordered form is whichever order the ISA realises...
        assert_eq!(
            pairwise("(vfredusum vnf32 zn)"),
            "(fadd f32 (fadd f32 zn__l0 zn__l1) (fadd f32 zn__l2 zn__l3))"
        );
        assert_eq!(
            inst("(vfredusum vnf32 zn)", 128).unwrap().unwrap().1[0].value,
            "(fadd f32 (fadd f32 (fadd f32 zn__l0 zn__l1) zn__l2) zn__l3)"
        );
        // ...and a pinned one is unmoved by it, which is the half that keeps
        // the knob from reaching a specified order.
        assert_eq!(
            pairwise("(vfredosum vnf32 zn)"),
            "(fadd f32 (fadd f32 (fadd f32 zn__l0 zn__l1) zn__l2) zn__l3)"
        );
    }

    #[test]
    fn an_odd_lane_count_splits_left_heavy() {
        // The rule only shows itself when the halves cannot be equal. Written
        // down because a fold shape that varies with the division's rounding
        // is not a pinned order. Eight 16-bit lanes minus nothing is even, so
        // this reaches the odd case through a three-lane fold directly.
        assert_eq!(
            fold(
                &["a".to_string(), "b".to_string(), "c".to_string()],
                "fadd",
                "f32",
                ReductionOrder::Pairwise
            ),
            "(fadd f32 (fadd f32 a b) c)"
        );
    }

    #[test]
    fn reductions_cover_the_integer_operators() {
        for (form, expected) in [
            ("(vredand vni32 zn)", "(and i32 (and i32 (and i32 zn__l0 zn__l1) zn__l2) zn__l3)"),
            ("(vredmaxu vni32 zn)", "(maxu i32 (maxu i32 (maxu i32 zn__l0 zn__l1) zn__l2) zn__l3)"),
            ("(vredxor vni32 zn)", "(xor i32 (xor i32 (xor i32 zn__l0 zn__l1) zn__l2) zn__l3)"),
        ] {
            let (_, lanes, _) = inst(form, 128).unwrap().unwrap();
            assert_eq!(lanes[0].value, expected, "{form}");
        }
    }

    #[test]
    fn a_length_that_does_not_divide_is_an_error() {
        let error = inst("(add vni64 zn zm)", 96).unwrap_err();
        assert!(error.contains("not a multiple"), "{error}");
    }

    #[test]
    fn scalar_documents_are_untouched() {
        assert_eq!(inst("(add i32 a b)", 128).unwrap(), None);
        assert_eq!(inst("(add v2i32 a b)", 128).unwrap(), None);
    }

    #[test]
    fn a_tail_marks_lanes_at_or_above_vl_undefined() {
        let (_, lanes, _) = inst("(vtail vni32 vl (add vni32 zn zm))", 128)
            .unwrap()
            .unwrap();
        assert_eq!(lanes.len(), 4);
        assert_eq!(lanes[2].value, "(add i32 zn__l2 zm__l2)");
        assert_eq!(lanes[2].defined.as_deref(), Some("(icmp_ult i32 2 vl)"));
    }

    #[test]
    fn realisation_changes_only_the_undefined_lane_value() {
        let text = "(vtail vni32 vl (add vni32 zn zm))";
        let (_, ones, _) = instantiate(text, &mode(128), Realization::Ones, ReductionOrder::Sequential).unwrap().unwrap();
        let (_, zeros, _) = instantiate(text, &mode(128), Realization::Zeros, ReductionOrder::Sequential).unwrap().unwrap();
        // The definedness expression is the architectural part, so it is
        // identical no matter how the undefined bits are realised.
        assert_eq!(ones[1].defined, zeros[1].defined);
        assert_eq!(
            ones[1].value,
            "(select i32 (icmp_ult i32 1 vl) (add i32 zn__l1 zm__l1) 0xffffffff)"
        );
        assert_eq!(
            zeros[1].value,
            "(select i32 (icmp_ult i32 1 vl) (add i32 zn__l1 zm__l1) 0)"
        );
    }

    #[test]
    fn a_tail_must_be_outermost() {
        let error = inst("(add vni32 zn (vtail vni32 vl zm))", 128).unwrap_err();
        assert!(error.contains("outermost"), "{error}");
    }

    #[test]
    fn a_lane_index_that_does_not_fit_the_element_is_refused() {
        // 512 bits of 8-bit lanes is 64 lanes, which fits; 8-bit lanes at a
        // hypothetical 4096 would not, and truncating the index would compare
        // the wrong lane against vl.
        assert!(inst("(vtail vni8 vl (add vni8 zn zm))", 512).is_ok());
        let error = inst("(vtail vni8 vl (add vni8 zn zm))", 4096).unwrap_err();
        assert!(error.contains("cannot be indexed"), "{error}");
    }

    fn vtype(vector_bits: u32, sew: u32, num: u32, den: u32) -> VectorMode<'static> {
        VectorMode { vector_bits, sew, lmul_num: num, lmul_den: den, elen: 64, addr_bits: 64, state: &[] }
    }

    fn lanes_at(text: &str, mode: &VectorMode<'_>) -> Vec<String> {
        instantiate(text, mode, Realization::Compute, ReductionOrder::Sequential)
            .unwrap()
            .unwrap()
            .1
            .into_iter()
            .map(|lane| lane.value)
            .collect()
    }

    #[test]
    fn lmul_scales_the_lane_count_in_both_directions() {
        let text = "(add vti zn zm)";
        // LMUL groups registers, so it multiplies the elements one operand
        // covers; fractional LMUL divides it.
        assert_eq!(lanes_at(text, &vtype(128, 32, 1, 1)).len(), 4);
        assert_eq!(lanes_at(text, &vtype(128, 32, 2, 1)).len(), 8);
        assert_eq!(lanes_at(text, &vtype(128, 32, 8, 1)).len(), 32);
        assert_eq!(lanes_at(text, &vtype(128, 32, 1, 2)).len(), 2);
        // LMUL=1/8 is legal at SEW=8 (1/8 >= 8/64) and not at SEW=32.
        assert_eq!(lanes_at(text, &vtype(128, 8, 1, 8)).len(), 2);
    }

    #[test]
    fn sew_sets_the_element_width() {
        assert_eq!(lanes_at("(add vti zn zm)", &vtype(128, 8, 1, 1))[0], "(add i8 zn__l0 zm__l0)");
        assert_eq!(lanes_at("(add vti zn zm)", &vtype(128, 64, 1, 1))[0], "(add i64 zn__l0 zm__l0)");
    }

    #[test]
    fn widening_doubles_the_element_and_keeps_the_lane_count() {
        let mode = vtype(128, 32, 1, 1);
        let lanes = lanes_at("(vwadd vtiw vti zn zm)", &mode);
        // The widened result covers twice the registers at twice the element
        // width, so the two cancel and the lane count is unchanged.
        assert_eq!(lanes.len(), 4);
        assert_eq!(lanes[1], "(add i64 (sext i64 32 zn__l1) (sext i64 32 zm__l1))");
        let unsigned = lanes_at("(vwaddu vtiw vti zn zm)", &mode);
        assert_eq!(unsigned[1], "(add i64 (zext i64 32 zn__l1) (zext i64 32 zm__l1))");
    }

    #[test]
    fn narrowing_computes_wide_and_keeps_the_low_half() {
        let lanes = lanes_at("(vnsrl vti vtiw zn zm)", &vtype(128, 32, 1, 1));
        assert_eq!(lanes.len(), 4);
        assert_eq!(
            lanes[0],
            "(and i64 (lshr i64 zn__l0 (and i64 zm__l0 0x3f)) 0xffffffff)"
        );
    }

    #[test]
    fn an_illegal_vtype_point_is_refused() {
        // SEW past ELEN is not a configuration the machine has.
        let error = instantiate("(add vti zn zm)", &vtype(128, 64, 1, 1).clone(), Realization::Compute, ReductionOrder::Sequential);
        assert!(error.is_ok());
        let mut narrow = vtype(128, 64, 1, 1);
        narrow.elen = 32;
        let error = instantiate("(add vti zn zm)", &narrow, Realization::Compute, ReductionOrder::Sequential).unwrap_err();
        assert!(error.contains("exceeds ELEN"), "{error}");
        // A fractional LMUL that leaves less than one element is empty, not small.
        let error =
            instantiate("(add vti zn zm)", &vtype(128, 32, 1, 4), Realization::Compute, ReductionOrder::Sequential).unwrap_err();
        assert!(error.contains("below SEW/ELEN"), "{error}");
    }

    #[test]
    fn a_widening_operator_must_actually_widen() {
        let error = instantiate("(vwadd vti vti zn zm)", &vtype(128, 32, 1, 1), Realization::Compute, ReductionOrder::Sequential)
            .unwrap_err();
        assert!(error.contains("twice its operand element"), "{error}");
    }

    #[test]
    fn a_vtype_atom_without_a_vtype_is_an_error() {
        let error = instantiate("(add vti zn zm)", &mode(128), Realization::Compute, ReductionOrder::Sequential).unwrap_err();
        assert!(error.contains("no `(vector-sew N)`"), "{error}");
    }

    #[test]
    fn a_comparison_writes_one_bit_per_lane() {
        // The scalable answer is a bit, not the all-ones lane mask a packed
        // compare writes -- which is why `simd.rs` refuses this operator and
        // this module accepts it.
        let lanes = lanes_at("(icmp_slt vni32 zn zm)", &mode(128));
        assert_eq!(lanes.len(), 4);
        assert_eq!(lanes[2], "(icmp_slt i32 zn__l2 zm__l2)");
        assert!(!crate::simd::is_lane_parallel("icmp_slt", 'i'));
    }

    #[test]
    fn vmerge_selects_per_lane_and_composes() {
        let lanes = lanes_at("(vmerge vni32 pg (add vni32 zn zm) zd)", &mode(128));
        assert_eq!(lanes[1], "(select i32 pg__l1 (add i32 zn__l1 zm__l1) zd__l1)");
        // Zeroing predication is the merging form with a broadcast zero, so it
        // needs no separate operator.
        let zeroing = lanes_at("(vmerge vni32 pg (add vni32 zn zm) (vdup vni32 z))", &mode(128));
        assert_eq!(zeroing[1], "(select i32 pg__l1 (add i32 zn__l1 zm__l1) z)");
    }

    #[test]
    fn vwhilelt_is_active_while_base_plus_lane_is_below_count() {
        let lanes = lanes_at("(vwhilelt vni32 base count)", &mode(128));
        assert_eq!(lanes[0], "(icmp_ult i32 (add i32 base 0) count)");
        assert_eq!(lanes[3], "(icmp_ult i32 (add i32 base 3) count)");
    }

    #[test]
    fn vundef_marks_the_lanes_a_predicate_excludes() {
        let (_, lanes, control) =
            inst("(vundef vni32 pg (add vni32 zn zm))", 128).unwrap().unwrap();
        assert_eq!(control.as_deref(), Some("pg"));
        assert_eq!(lanes[2].value, "(add i32 zn__l2 zm__l2)");
        assert_eq!(lanes[2].defined.as_deref(), Some("(icmp_ne i32 pg__l2 0)"));
    }

    #[test]
    fn predicate_logic_is_ordinary_lane_arithmetic() {
        // A predicate is a vector whose lanes are 0 or 1, so SVE's predicate
        // AND/ORR need no operators of their own.
        let lanes = lanes_at("(and vni32 pa pb)", &mode(128));
        assert_eq!(lanes[0], "(and i32 pa__l0 pb__l0)");
    }

    #[test]
    fn vundef_must_be_outermost_like_vtail() {
        let error = inst("(add vni32 zn (vundef vni32 pg zm))", 128).unwrap_err();
        assert!(error.contains("outermost"), "{error}");
    }

    #[test]
    fn zip_interleaves_and_uzp_deinterleaves() {
        let zip = lanes_at("(vzip1 vni32 zn zm)", &mode(128));
        assert_eq!(zip, ["zn__l0", "zm__l0", "zn__l1", "zm__l1"]);
        let zip2 = lanes_at("(vzip2 vni32 zn zm)", &mode(128));
        assert_eq!(zip2, ["zn__l2", "zm__l2", "zn__l3", "zm__l3"]);
        // UZP1 takes every other element of the concatenation, so it runs off
        // the first vector and into the second.
        let uzp = lanes_at("(vuzp1 vni32 zn zm)", &mode(128));
        assert_eq!(uzp, ["zn__l0", "zn__l2", "zm__l0", "zm__l2"]);
    }

    #[test]
    fn trn_transposes_pairs() {
        assert_eq!(
            lanes_at("(vtrn1 vni32 zn zm)", &mode(128)),
            ["zn__l0", "zm__l0", "zn__l2", "zm__l2"]
        );
        assert_eq!(
            lanes_at("(vtrn2 vni32 zn zm)", &mode(128)),
            ["zn__l1", "zm__l1", "zn__l3", "zm__l3"]
        );
    }

    #[test]
    fn ext_is_a_window_across_the_concatenation() {
        assert_eq!(
            lanes_at("(vext vni32 zn zm 1)", &mode(128)),
            ["zn__l1", "zn__l2", "zn__l3", "zm__l0"]
        );
    }

    #[test]
    fn slides_take_a_background_rather_than_inventing_a_zero() {
        // RVV's vslideup leaves the lanes below the offset *undisturbed*, so a
        // model that filled them with zero would be wrong. Naming the
        // background is what lets the document say which it means.
        assert_eq!(
            lanes_at("(vslideup vni32 zn zd 2)", &mode(128)),
            ["zd__l0", "zd__l1", "zn__l0", "zn__l1"]
        );
        assert_eq!(
            lanes_at("(vslidedown vni32 zn zd 2)", &mode(128)),
            ["zn__l2", "zn__l3", "zd__l2", "zd__l3"]
        );
    }

    #[test]
    fn vcompress_packs_active_lanes_into_the_low_positions() {
        let lanes = lanes_at("(vcompress vni32 zn pg zb)", &mode(128));
        assert_eq!(lanes.len(), 4);
        // Lane 0 takes the first source lane whose prefix count is zero and
        // whose own mask bit is set; the fallback is the background's lane 0.
        assert!(lanes[0].starts_with("(select i32 (and i32 (icmp_ne i32 pg__l0 0)"), "{}", lanes[0]);
        assert!(lanes[0].contains("zb__l0"), "{}", lanes[0]);
        // Lane 1's prefix comparison is against 1, not 0 -- the position, not
        // the source index.
        assert!(lanes[1].contains("(icmp_eq i32 0 1)"), "{}", lanes[1]);
    }

    #[test]
    fn a_compress_past_the_ceiling_is_refused_with_its_reason() {
        // 32 lanes of 8-bit elements is cubic; the ceiling is lower than the
        // gather's for exactly that reason, and the message says so.
        let error = inst("(vcompress vni8 zn pg zb)", 256).unwrap_err();
        assert!(error.contains("cubic"), "{error}");
    }

    #[test]
    fn vid_is_the_lane_index_itself() {
        // The whole operator: lane l is l. Stated as a test because the
        // lowering is a one-line substitution and a one-line substitution is
        // exactly the kind of thing that silently becomes lane 0 everywhere.
        let ids = lanes_at("(vid vni32)", &mode(128));
        assert_eq!(ids, vec!["0", "1", "2", "3"]);
        // And at a narrower element, where there are more lanes to be wrong
        // about.
        let ids16 = lanes_at("(vid vni16)", &mode(128));
        assert_eq!(ids16.len(), 8);
        assert_eq!(ids16[7], "7");
    }

    #[test]
    fn the_mask_family_is_one_question_asked_four_ways() {
        // mask = [pg0, pg1, pg2, pg3]; every answer is a comparison against the
        // count of active lanes strictly before this one.
        let iota = lanes_at("(viota vni32 pg)", &mode(128));
        assert_eq!(iota[0], "0");
        assert_eq!(iota[1], "(icmp_ne i32 pg__l0 0)");
        assert!(iota[3].starts_with("(add i32 (icmp_ne i32 pg__l0 0)"), "{}", iota[3]);

        let before = lanes_at("(vmsbf vni32 pg)", &mode(128));
        assert_eq!(
            before[1],
            "(and i32 (icmp_eq i32 (icmp_ne i32 pg__l0 0) 0) (icmp_eq i32 (icmp_ne i32 pg__l1 0) 0))"
        );
        let including = lanes_at("(vmsif vni32 pg)", &mode(128));
        assert_eq!(including[1], "(icmp_eq i32 (icmp_ne i32 pg__l0 0) 0)");
        let only = lanes_at("(vmsof vni32 pg)", &mode(128));
        assert_eq!(
            only[1],
            "(and i32 (icmp_eq i32 (icmp_ne i32 pg__l0 0) 0) (icmp_ne i32 pg__l1 0))"
        );
    }

    #[test]
    fn vcpop_and_vfirst_collapse_to_one_instruction() {
        let (shape, lanes, _) = inst("(vcpop vni32 pg)", 128).unwrap().unwrap();
        assert!(shape.collapsed);
        assert_eq!(lanes.len(), 1);
        assert!(lanes[0].value.starts_with("(add i32 (icmp_ne i32 pg__l0 0)"), "{}", lanes[0].value);

        let (shape, lanes, _) = inst("(vfirst vni32 pg)", 128).unwrap().unwrap();
        assert!(shape.collapsed);
        // Lane 0 is the outermost test, so a lower index wins over a higher
        // one, and no active lane at all gives -1 as all-ones.
        assert!(lanes[0].value.starts_with("(select i32 (icmp_ne i32 pg__l0 0) 0 "), "{}", lanes[0].value);
        assert!(lanes[0].value.ends_with("0xffffffff))))"), "{}", lanes[0].value);
    }

    #[test]
    fn vextract_collapses_to_one_element() {
        let (shape, lanes, _) = inst("(vextract vni32 zn 2)", 128).unwrap().unwrap();
        assert!(shape.collapsed);
        assert_eq!(lanes.len(), 1);
        assert_eq!(lanes[0].value, "zn__l2");
        let error = inst("(vextract vni32 zn 9)", 128).unwrap_err();
        assert!(error.contains("past the 4 lanes"), "{error}");
    }

    #[test]
    fn float_comparisons_are_lane_local_and_select_composes() {
        // Letting these through is what makes saturating arithmetic and FP
        // predicates writable in a corpus without new operators.
        let compares = lanes_at("(fcmp_olt vnf32 zn zm)", &mode(128));
        assert_eq!(compares[1], "(fcmp_olt f32 zn__l1 zm__l1)");
        let saturating = lanes_at(
            "(select vni32 (icmp_ult vni32 (add vni32 zn zm) zn) 0xffffffff (add vni32 zn zm))",
            &mode(128),
        );
        assert_eq!(
            saturating[0],
            "(select i32 (icmp_ult i32 (add i32 zn__l0 zm__l0) zn__l0) 0xffffffff (add i32 zn__l0 zm__l0))"
        );
    }
}
