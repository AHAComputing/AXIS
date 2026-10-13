//! Effect statements — the infix surface for instruction semantics.
//!
//! An instruction's behavior is an ordered list of effects (`docs/effects_design.md`).
//! The infix expression grammar parses to [`SemanticExpr`], then the frontend
//! attaches explicit evaluation widths before storing canonical behavior.
//! Backends lower with those stored widths through the pure IR pipeline.
//! Register-write effects — `set <reg> = <expr>` — use infix arithmetic/bitwise
//! plus function-call forms for the remaining operators (`sext(i32, 8, x)`,
//! `min(a, b)`, `clz(x)`, …). Memory effects — a load `set <reg> = load(iW,
//! signed|unsigned, addr)` and a `store(addr, value, iW)` — and control flow —
//! `setpc(target)` with an optional `when <cond>:` guard — are effectful: they
//! keep `effects` with empty `formal_semantics` so the pure value-model backends
//! skip them and the executor applies them against registers, memory, and `pc`.
//! A `trap(cause)` effect aborts the instruction with a recognized cause.

use crate::semantics::SemanticExpr;

/// Ordering attached to one memory access. Execution remains deterministic and
/// single-core, while generated artifacts retain the architectural contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOrder {
    Relaxed,
    Acquire,
    Release,
}

impl MemoryOrder {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Relaxed => "relaxed",
            Self::Acquire => "acquire",
            Self::Release => "release",
        }
    }
}

fn parse_memory_order(atom: &SemanticExpr) -> Option<MemoryOrder> {
    match atom {
        SemanticExpr::Atom(order) if order == "relaxed" => Some(MemoryOrder::Relaxed),
        SemanticExpr::Atom(order) if order == "acquire" => Some(MemoryOrder::Acquire),
        SemanticExpr::Atom(order) if order == "release" => Some(MemoryOrder::Release),
        _ => None,
    }
}

/// A behavior expression plus the bit-vector width in which it is evaluated.
/// The destination location keeps its own independent write width, so an i64
/// computation may intentionally feed an i4 architectural-state write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectExpr {
    pub expr: SemanticExpr,
    pub width: u32,
    /// Address evaluation width for a top-level load expression.
    pub load_address_width: Option<u32>,
    pub load_order: MemoryOrder,
    pub load_atomic: bool,
}

impl EffectExpr {
    fn untyped(expr: SemanticExpr) -> Self {
        Self {
            expr,
            width: 0,
            load_address_width: None,
            load_order: MemoryOrder::Relaxed,
            load_atomic: false,
        }
    }
}

/// An architectural effect target: a register or state write, a `width`-bit
/// memory location at `addr`, a barrier event, the program counter (a
/// branch/jump target), or a trap (aborts the instruction with the cause
/// carried in the effect's `value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Loc {
    Reg(String),
    /// A fixed architectural register that is written implicitly rather than
    /// selected by an encoded operand (for example AArch64 BL writes X30).
    FixedReg {
        kind: String,
        index: u32,
        width: u32,
    },
    /// A named scalar architectural-state location declared by the
    /// instruction's ISA (for example AArch64 `nzcv:i4`).
    State {
        name: String,
        width: u32,
    },
    Mem {
        addr: EffectExpr,
        width: u32,
        order: MemoryOrder,
        atomic: bool,
    },
    /// An architectural ordering/synchronization event. `value` carries the
    /// encoded barrier option and `kind` distinguishes its architectural
    /// strength (for example AArch64 DMB, DSB, and ISB).
    Barrier {
        kind: String,
        width: u32,
    },
    /// A one-way architectural message: `value` leaves this machine through
    /// the channel `port` names.
    ///
    /// ⚠️ This is a STORE whose destination is a channel rather than an
    /// address, and it is deliberately nothing more. A machine that posts a
    /// message to another lane, tile or core does exactly what a store does --
    /// evaluates two expressions, emits one ordered event, and continues -- so
    /// it rides the same machinery, is reported through the same host
    /// interface, and is held by the same differential gates. An effect kind
    /// nothing could observe would be an effect kind no gate could hold, which
    /// is the one thing this language cannot afford to add.
    ///
    /// ⚠️ What it is NOT: receiving. A core that BLOCKS until a message
    /// arrives is not describing an instruction's effect, it is describing
    /// when the machine runs at all -- an execution model, not a write. The
    /// send half is what an event-driven ISA's instruction actually does, and
    /// it is the half that can be checked against a golden model today.
    Port {
        /// Which channel, as an expression: a description that names the port
        /// with an operand -- `send(rd, rs1, i64)` -- is naming a machine
        /// whose destination is computed, which is what every posted-message
        /// ISA does.
        port: EffectExpr,
        width: u32,
    },
    Pc,
    Trap,
}

/// The recognized trap causes.
pub const TRAP_CAUSES: &[&str] = &["illegal", "misaligned", "access", "ecall", "ebreak"];

/// How many register writes one instruction's effect function can report.
///
/// AArch64's `ldp` with writeback is the maximum in practice: it writes both
/// data registers and the base. Four leaves headroom without making the caller's
/// scratch array pointlessly large.
pub const EFFECT_MAX_WRITES: usize = 4;

/// Slots a caller must provide for an effect function's `%out` array.
///
/// Layout, in the function's evaluation word:
///
/// ```text
///   [0] value written by write #0      [4] value written by write #1
///   [1] whether write #0 fired         [5] whether write #1 fired
///   [2] next pc                        [6] value written by write #2
///   [3] trap id (0 = none)             [7] whether write #2 fired
///                                      [8] value written by write #3
///                                      [9] whether write #3 fired
/// ```
///
/// The first four slots keep the layout every existing consumer already reads,
/// so a caller that only handles single-write instructions is unchanged. Write
/// `k` corresponds to the `k`-th register-writing effect in the instruction's
/// behavior, which the lift table publishes in order with its destination
/// operand, so a consumer maps writes to registers without guessing.
///
/// A caller must size its array by this constant regardless of the instruction:
/// the function writes only the slots it needs, but knowing which those are
/// means reading the behavior, and a short array would be a buffer overrun
/// rather than a wrong answer.
pub const EFFECT_OUT_SLOTS: usize = 4 + 2 * (EFFECT_MAX_WRITES - 1);

/// Fold every operator whose arguments are all literals, and spell every
/// literal in decimal.
///
/// ⚠️ This is the equivalence the kernel composition check needs and A4's did
/// not. A4 compares lowered IR structurally, which normalises operator names
/// and widths and does not fold: `(mul i64 1 4)` and `4` are different trees
/// to it. That was enough for a CGRA mapping. A kernel's launch is where it
/// stops being enough, because substituting the iteration indices leaves
/// literal-only arithmetic in every address -- a hand-flattened launch that
/// wrote `(add i64 rd 4)` and the kernel's `(add i64 rd (add i64 (mul i64 0 8)
/// (mul i64 1 4)))` are one store, and structural equality refused them.
///
/// Deliberately no more than folding. It identifies expressions equal up to
/// evaluating their constant parts, not up to commutativity or reassociation,
/// so `(add b a)` against `(add a b)` still disagrees -- the same strictness
/// A4 chose on purpose, since an operand swap is exactly the mistake a
/// composition check exists to catch.
pub fn fold_constants(expr: &SemanticExpr, width: u32) -> SemanticExpr {
    let SemanticExpr::List(items) = expr else {
        if let SemanticExpr::Atom(atom) = expr {
            if let Some(value) = crate::ir::integer_literal(atom) {
                return SemanticExpr::Atom(value.to_string());
            }
        }
        return expr.clone();
    };
    let Some(SemanticExpr::Atom(op)) = items.first() else {
        return expr.clone();
    };
    let typed = items
        .get(1)
        .and_then(|item| match item {
            SemanticExpr::Atom(atom) => crate::ir::type_atom_bits(atom),
            _ => None,
        });
    let node_width = typed.unwrap_or(width);
    let first_arg = if typed.is_some() { 2 } else { 1 };
    let folded: Vec<SemanticExpr> = items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            if index < first_arg {
                item.clone()
            } else {
                fold_constants(item, node_width)
            }
        })
        .collect();
    let literals: Option<Vec<u128>> = folded[first_arg..]
        .iter()
        .map(|item| match item {
            SemanticExpr::Atom(atom) => crate::ir::integer_literal(atom),
            _ => None,
        })
        .collect();
    let Some(values) = literals.filter(|values| !values.is_empty()) else {
        return SemanticExpr::List(folded);
    };
    let mask = if node_width >= 128 { u128::MAX } else { (1u128 << node_width) - 1 };
    let result = match op.as_str() {
        "add" => values.iter().fold(0u128, |sum, value| sum.wrapping_add(*value)),
        "mul" => values.iter().fold(1u128, |product, value| product.wrapping_mul(*value)),
        "sub" if values.len() == 2 => values[0].wrapping_sub(values[1]),
        "and" => values.iter().fold(u128::MAX, |acc, value| acc & value),
        "or" => values.iter().fold(0u128, |acc, value| acc | value),
        "xor" => values.iter().fold(0u128, |acc, value| acc ^ value),
        "shl" | "sll" if values.len() == 2 && values[1] < 128 => values[0] << values[1],
        "lshr" | "srl" if values.len() == 2 && values[1] < 128 => (values[0] & mask) >> values[1],
        _ => return SemanticExpr::List(folded),
    };
    SemanticExpr::Atom((result & mask).to_string())
}

/// Whether two behaviors perform the same effects, up to constant folding,
/// and the first place they differ when they do not.
pub fn behaviors_agree(ours: &Behavior, theirs: &Behavior) -> Result<(), String> {
    if ours.effects.len() != theirs.effects.len() {
        return Err(format!(
            "the launch performs {} effect(s) and the kernel {}",
            ours.effects.len(),
            theirs.effects.len()
        ));
    }
    let show = |expr: &EffectExpr| render_semexpr(&fold_constants(&expr.expr, expr.width.max(1)));
    for (index, (a, b)) in ours.effects.iter().zip(&theirs.effects).enumerate() {
        let location = |loc: &Loc| match loc {
            Loc::Mem { addr, width, .. } => format!("store i{width} at {}", show(addr)),
            other => format!("{other:?}"),
        };
        if location(&a.loc) != location(&b.loc) {
            return Err(format!(
                "effect {index}: the launch writes `{}` and the kernel `{}`",
                location(&a.loc),
                location(&b.loc)
            ));
        }
        if show(&a.value) != show(&b.value) {
            return Err(format!(
                "effect {index}: the launch computes `{}` and the kernel `{}`",
                show(&a.value),
                show(&b.value)
            ));
        }
        if a.guard.as_ref().map(show) != b.guard.as_ref().map(show)
            || a.atomic_group != b.atomic_group
        {
            return Err(format!("effect {index}: the launch and the kernel guard it differently"));
        }
    }
    Ok(())
}

/// Rewrite every expression a behavior holds, in place.
///
/// ⚠️ The elaboration passes that turn source-level shorthand into ordinary
/// semantics -- bounded loops and contractions, SIMD lanes, the interchange
/// float formats -- ran on `formal_semantics` and **never on behaviors**.
/// Measured: `(accumulate ...)` inside a `behavior` reached validation as an
/// unsupported operator and `(fcvt_f2f f32 bf16 ...)` as a malformed one, with
/// messages about the typed IR rather than about the form.
///
/// That mattered more than it looks, because the effect surface is where
/// MEMORY is. A contraction over loaded values, a lane-wise conversion of a
/// loaded vector, a tile read through an access map and accumulated -- every
/// one of those is a behavior, so none of them could be written. This is what
/// makes those passes reach it.
pub fn map_behavior_exprs<F>(behavior: &mut Behavior, mut rewrite: F) -> Result<(), String>
where
    F: FnMut(&str) -> Result<String, String>,
{
    let mut apply = |slot: &mut EffectExpr| -> Result<(), String> {
        let text = render_semexpr(&slot.expr);
        let expanded = rewrite(&text)?;
        if expanded != text {
            slot.expr = crate::semantics::parse_formal_semantics(&expanded)
                .map_err(|error| error.message)?;
        }
        Ok(())
    };
    for effect in &mut behavior.effects {
        if let Loc::Mem { addr, .. } = &mut effect.loc {
            apply(addr)?;
        }
        apply(&mut effect.value)?;
        if let Some(guard) = &mut effect.guard {
            apply(guard)?;
        }
    }
    Ok(())
}

/// One effect: write `value` to `loc`, applied only when `guard` (an `i1`
/// predicate, e.g. from `when`) is absent or evaluates true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effect {
    pub loc: Loc,
    pub value: EffectExpr,
    pub guard: Option<EffectExpr>,
    /// Non-zero effects with the same id form one indivisible architectural
    /// transaction. The ordered effect list still defines their evaluation
    /// order for deterministic executors.
    pub atomic_group: u32,
}

impl Effect {
    /// The most memory accesses this effect can make: its own event, and every
    /// load anywhere in its value, its address or its guard.
    ///
    /// ⚠️ Not one per effect. That was true until an effect could read memory
    /// more than once (T8b), and the simulator's fixed trace record was sized
    /// by it -- so a kernel launch whose six stores each read eight words
    /// recorded its first eight accesses and silently dropped forty-six. An
    /// upper bound is what a buffer size needs, but one that doubled a plain
    /// load's bound would push corpora past the pack contract for nothing.
    pub fn memory_accesses(&self) -> usize {
        fn loads(expr: &SemanticExpr) -> usize {
            match expr {
                SemanticExpr::Atom(_) => 0,
                SemanticExpr::List(items) => {
                    let own = matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "load");
                    usize::from(own) + items.iter().map(loads).sum::<usize>()
                }
            }
        }
        // A register, state or pc write is not an access; anything else --
        // a store, a message, a barrier -- is counted as one, since an upper
        // bound only has to be safe.
        let own = match &self.loc {
            Loc::Mem { addr, .. } => 1 + loads(&addr.expr),
            Loc::Reg(_) | Loc::FixedReg { .. } | Loc::State { .. } | Loc::Pc | Loc::Trap => 0,
            _ => 1,
        };
        own
            + loads(&self.value.expr)
            + self.guard.as_ref().map_or(0, |guard| loads(&guard.expr))
    }
}

/// An ordered list of effects — an instruction's behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Behavior {
    pub effects: Vec<Effect>,
}

/// Resolve every behavior expression's evaluation width once at the frontend
/// boundary. Explicit type atoms win; otherwise the location width supplies
/// the value context and the widest operand supplies address/guard/PC context.
pub fn annotate_behavior_widths(
    behavior: &mut Behavior,
    operands: &[(String, u32)],
) -> Result<(), String> {
    // The widest operand is the best guess available at the frontend boundary,
    // where an instruction has been parsed but its ISA has not been resolved.
    // It is only a guess: see `annotate_behavior_widths_for_machine`, which
    // runs again once the word is known.
    let machine_width = operands
        .iter()
        .map(|(_, width)| *width)
        .max()
        .unwrap_or(32)
        .max(32);
    annotate_behavior_widths_for_machine(behavior, operands, machine_width)
}

/// The same, with the machine's word supplied rather than guessed.
///
/// The guess is wrong exactly when no operand is as wide as the machine, and
/// the clearest case is a branch: AArch64's `B` carries one 26-bit immediate,
/// so `max(26, 32)` called a 64-bit machine 32 bits and every branch target
/// wrapped at four gigabytes. It went unseen because the harness that would
/// have caught it could not run on the corpus at all -- and because a PC below
/// 2^32 agrees either way, which is every PC a smaller fixture picks.
pub fn annotate_behavior_widths_for_machine(
    behavior: &mut Behavior,
    operands: &[(String, u32)],
    machine_width: u32,
) -> Result<(), String> {
    for effect in &mut behavior.effects {
        let value_context = match &effect.loc {
            Loc::Reg(name) => operands
                .iter()
                .find(|(operand, _)| operand == name)
                .map(|(_, width)| *width)
                .ok_or_else(|| format!("effect writes unknown operand `{name}`"))?,
            Loc::FixedReg { width, .. }
            | Loc::State { width, .. }
            | Loc::Mem { width, .. }
            | Loc::Barrier { width, .. }
            | Loc::Port { width, .. } => *width,
            Loc::Pc => machine_width,
            Loc::Trap => 0,
        };
        if !matches!(effect.loc, Loc::Trap) {
            effect.value.width = expression_width(&effect.value.expr, value_context);
            effect.value.load_address_width = load_address(&effect.value.expr)
                .map(|address| expression_width(address, machine_width));
            effect.value.load_order = load_memory_order(&effect.value.expr);
            effect.value.load_atomic = is_atomic_load(&effect.value.expr);
        }
        if let Loc::Mem { addr, .. } = &mut effect.loc {
            addr.width = expression_width(&addr.expr, machine_width);
            // An address that reads memory reads it at the machine's width,
            // like every load's address; recorded so an evaluator does not
            // have to know that an address is always machine-wide.
            addr.load_address_width = contains_load(&addr.expr).then_some(machine_width);
        }
        // The port is an address by another name: it selects a destination and
        // is as wide as the machine unless it says otherwise.
        if let Loc::Port { port, .. } = &mut effect.loc {
            port.width = expression_width(&port.expr, machine_width);
        }
        if let Some(guard) = &mut effect.guard {
            guard.width = guard_operand_width(&guard.expr, machine_width);
            // ⚠️ A guard compares at its operands' width, and a byte compared
            // with a constant is an i8 comparison -- whose load address is
            // still sixty-four bits. The same trap `load_address_width` exists
            // for in a value, one place over.
            guard.load_address_width = contains_load(&guard.expr).then_some(machine_width);
        }
    }
    Ok(())
}

/// A barrier an architecture can name, and what it constrains.
///
/// This was the same seven-name list written out in three places -- twice here
/// and once in the Lisp frontend -- and all seven were AArch64's. RISC-V's
/// `fence` had nowhere to be added except to all three, which is how a
/// vocabulary drifts: the register classes had grown nine separate answers to
/// "is this a register" before they became one table, and this is that story
/// one vocabulary later.
///
/// `orders_memory` is the fact the backends actually ask for. A data barrier
/// constrains the memory model and has an LLVM `fence` to be; an instruction
/// or speculation barrier constrains the pipeline, and emitting a memory fence
/// for one would claim something the architecture does not say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierKind {
    pub name: &'static str,
    pub orders_memory: bool,
    /// How wide the encoded option is. Four was written into the validator as
    /// a constant, which is AArch64's `CRm` and nobody else's -- RISC-V's
    /// `fence` carries eight, a predecessor set and a successor set. Adding
    /// the kind was not enough on its own; the width was a second AArch64
    /// assumption one level down, and finding it took writing the instruction.
    pub option_bits: u32,
}

pub const BARRIER_KINDS: &[BarrierKind] = &[
    // AArch64.
    BarrierKind { name: "dmb", orders_memory: true, option_bits: 4 },
    BarrierKind { name: "dsb", orders_memory: true, option_bits: 4 },
    BarrierKind { name: "isb", orders_memory: false, option_bits: 4 },
    BarrierKind { name: "sb", orders_memory: false, option_bits: 4 },
    BarrierKind { name: "csdb", orders_memory: false, option_bits: 4 },
    BarrierKind { name: "ssbb", orders_memory: false, option_bits: 4 },
    BarrierKind { name: "pssbb", orders_memory: false, option_bits: 4 },
    // RISC-V. `fence` orders memory accesses; `fence.i` orders instruction
    // fetch against writes, which is the pipeline and not the memory model --
    // the same distinction AArch64 draws between `dmb` and `isb`.
    BarrierKind { name: "fence", orders_memory: true, option_bits: 8 },
    BarrierKind { name: "fence_i", orders_memory: false, option_bits: 0 },
];

/// The barrier kind of that name, if an architecture may name it.
pub fn barrier_kind(name: &str) -> Option<&'static BarrierKind> {
    BARRIER_KINDS.iter().find(|kind| kind.name == name)
}

/// A load's address, its access width and whether it sign-extends, when this
/// expression IS a load.
///
/// ⚠️ Exactly a load, not a load somewhere inside an expression. `lb` is
/// `rd = load(i8, signed, rs1 + imm)` and the whole of its value is the load;
/// an instruction that added something to one would need the sum rendered, and
/// the sum is what `emit-smt2` cannot write. Saying which of the two a
/// description has is the point of returning `None` for the second.
pub fn plain_load(
    expression: &SemanticExpr,
) -> Option<(&SemanticExpr, u32, bool)> {
    let SemanticExpr::List(items) = expression else {
        return None;
    };
    if !matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "load" | "atomic_load"))
    {
        return None;
    }
    let width = items.get(1).and_then(type_atom_width)?;
    let signed = matches!(items.get(2), Some(SemanticExpr::Atom(text)) if text == "signed");
    Some((items.last()?, width, signed))
}

/// The address of the first load in `expression`, wherever it sits.
///
/// ⚠️ Anywhere, not only at the head. An effect may carry several loads now,
/// and every one of their addresses is as wide as the machine -- the width
/// this feeds is the one the evaluator uses for all of them. It was top-level
/// only, which is why a load nested inside a value had its address evaluated
/// at the value's width: the bug the store branch of the Python executor
/// records having hit, where `memcpy16` read byte 313 as byte 57.
fn load_address(expression: &SemanticExpr) -> Option<&SemanticExpr> {
    let SemanticExpr::List(items) = expression else {
        return None;
    };
    if matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "load" | "atomic_load"))
    {
        return items.last();
    }
    items.iter().find_map(load_address)
}

fn load_memory_order(expression: &SemanticExpr) -> MemoryOrder {
    let SemanticExpr::List(items) = expression else {
        return MemoryOrder::Relaxed;
    };
    if !matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "load" | "atomic_load"))
    {
        return MemoryOrder::Relaxed;
    }
    items
        .get(3)
        .and_then(parse_memory_order)
        .unwrap_or(MemoryOrder::Relaxed)
}

fn is_atomic_load(expression: &SemanticExpr) -> bool {
    matches!(expression, SemanticExpr::List(items)
        if matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "atomic_load"))
}

fn expression_width(expression: &SemanticExpr, ambient: u32) -> u32 {
    explicit_expression_width(expression).unwrap_or(ambient)
}

fn explicit_expression_width(expression: &SemanticExpr) -> Option<u32> {
    let SemanticExpr::List(items) = expression else {
        return None;
    };
    if matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "load" | "atomic_load"))
    {
        // The load type is its access width; the loaded value is extended into
        // the surrounding expression/destination context.
        return None;
    }
    items.get(1).and_then(type_atom_width)
}

fn guard_operand_width(expression: &SemanticExpr, ambient: u32) -> u32 {
    let SemanticExpr::List(items) = expression else {
        return ambient;
    };
    // A guard's comparison vocabulary is the same as an expression's: the six
    // integer comparisons. Equality alone was enough while AArch64 was the only
    // ISA with behaviors, because its conditional branches test NZCV rather than
    // comparing registers; RISC-V's branches compare directly.
    if matches!(items.first(), Some(SemanticExpr::Atom(op))
        if crate::ir::is_integer_comparison(op)) {
        return items[1..]
            .iter()
            .filter_map(explicit_expression_width)
            .max()
            .unwrap_or(ambient);
    }
    if matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "and" | "or" | "not"))
    {
        return items[1..]
            .iter()
            .map(|child| guard_operand_width(child, ambient))
            .max()
            .unwrap_or(ambient);
    }
    expression_width(expression, ambient)
}

/// Parse the `effects:` field: `;`-separated statements — `set <reg> = <expr>`,
/// `store(addr, value, iW)`, `setpc(target)`, each optionally `when <cond>:`.
pub fn parse_behavior(source: &str) -> Result<Behavior, String> {
    let mut effects = Vec::new();
    for statement in source.split(';') {
        let statement = statement.trim();
        if statement.is_empty() {
            continue;
        }
        effects.push(parse_statement(statement)?);
    }
    if effects.is_empty() {
        return Err("empty effects block".to_string());
    }
    Ok(Behavior { effects })
}

/// Render a [`SemanticExpr`] back to canonical s-expression text, so a pure
/// register `set` can flow through the existing `formal_semantics` pipeline.
pub fn render_semexpr(expr: &SemanticExpr) -> String {
    match expr {
        SemanticExpr::Atom(atom) => atom.clone(),
        SemanticExpr::List(items) => {
            let parts: Vec<String> = items.iter().map(render_semexpr).collect();
            format!("({})", parts.join(" "))
        }
    }
}

/// True when `expr` is a top-level memory load `(load iW signed|unsigned addr)`.
/// Loads live in the effect layer (not the pure `Sem` IR); an instruction with
/// a load keeps `effects` and leaves `formal_semantics` empty so the pure
/// value-model backends skip it and the executor handles the memory read.
pub fn is_load(expr: &SemanticExpr) -> bool {
    matches!(expr, SemanticExpr::List(items)
        if matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "load" | "atomic_load")))
}

/// True when `expr` performs a memory load anywhere, not only at the top level.
/// An atomic read-modify-write nests its load inside the stored value
/// (`atomic_store(addr, add(rs, atomic_load(addr)))`), so effect summaries must
/// walk the whole expression rather than test its head.
pub fn expr_reads_memory(expr: &SemanticExpr) -> bool {
    if is_load(expr) {
        return true;
    }
    match expr {
        SemanticExpr::Atom(_) => false,
        SemanticExpr::List(items) => items.iter().any(expr_reads_memory),
    }
}

/// Parse a type-atom width like `i32` → 32.
fn type_atom_width(atom: &SemanticExpr) -> Option<u32> {
    let SemanticExpr::Atom(text) = atom else {
        return None;
    };
    if text.len() > 1
        && text.starts_with(['i', 'u'])
        && text[1..].chars().all(|c| c.is_ascii_digit())
    {
        text[1..].parse().ok()
    } else {
        None
    }
}

/// The width a fixed register of this kind is read and written at, or `None`
/// when the kind is not one an instruction may name by index.
///
/// One table, because `setreg` and `getreg` are the two halves of the same
/// access: a description that can write `a64_gpr64 30` and could not read it,
/// or could read a class the writer refuses, would be two vocabularies wearing
/// one name.
pub fn fixed_register_width(kind: &str) -> Option<u32> {
    match kind {
        "reg" | "a64_gpr32" | "a64_gpr32sp" => Some(32),
        "a64_gpr64" | "a64_gpr64sp" => Some(64),
        _ => None,
    }
}

/// Whether this index exists in a fixed register kind's file.
fn fixed_register_index_ok(kind: &str, index: u32) -> bool {
    !(kind.starts_with("a64_gpr") && index >= 32)
}

/// Whether the pure `Sem` path can *not* represent this behavior, used by
/// `parser::desugar_effects` to decide against folding a single register `set`
/// into `formal_semantics`. Effect locations and guards are structural; the
/// named operators are the ones with no pure lowering.
///
/// This is a desugaring fast path, not the question "must the executors run an
/// effect program" — its symbol list is deliberately incomplete, and the
/// desugar site only trusts it alongside a full operand-symbol check. Backends
/// asking whether to emit an effect list want
/// [`behavior_is_authoritative`], which reads the frontend's decision instead
/// of re-deriving it from a name list.
pub fn is_effectful(behavior: &Behavior) -> bool {
    behavior.effects.iter().any(|effect| {
        matches!(
            effect.loc,
            Loc::FixedReg { .. }
                | Loc::State { .. }
                | Loc::Mem { .. }
                | Loc::Barrier { .. }
                | Loc::Pc
                | Loc::Trap
        ) || effect.guard.is_some()
            || is_load(&effect.value.expr)
            || expr_uses_operator(&effect.value.expr, "getreg")
            || expr_mentions(&effect.value.expr, "pc")
            || expr_mentions(&effect.value.expr, "nzcv")
            || expr_uses_operator(&effect.value.expr, "a64_cond_holds")
            || expr_uses_operator(&effect.value.expr, "a64_shift_reg")
            || expr_uses_operator(&effect.value.expr, "a64_extend_reg")
            || ["a64_wmask", "a64_ubfm", "a64_sbfm", "a64_bfm"]
                .iter()
                .any(|op| expr_uses_operator(&effect.value.expr, op))
            || ["a64_umulh", "a64_smulh"]
                .iter()
                .any(|op| expr_uses_operator(&effect.value.expr, op))
    })
}

/// Whether the executors must run this instruction's behavior as an ordered
/// effect program.
///
/// The frontend already made this call: `parser::desugar_effects` folds a
/// behavior into `formal_semantics` only when the whole instruction lowers into
/// the pure `Sem` IR over its own operands. So a retained behavior with empty
/// `formal_semantics` is exactly one the pure backends cannot represent —
/// whatever it touches. Re-deriving that from a symbol list instead (asking
/// [`is_effectful`] here) silently dropped every read of architectural state
/// the list did not enumerate, leaving the instruction with neither semantics
/// nor effects: a no-op in every generated lifter and executor.
pub fn behavior_is_authoritative(instruction: &crate::ast::Instruction) -> bool {
    instruction.behavior.is_some() && instruction.formal_semantics.trim().is_empty()
}

/// The value expression an instruction computes into its destination
/// register, or why there is none.
///
/// "Into its destination register" is the whole contract, and it matters for
/// an instruction that also writes architectural state: this returns the sum
/// that `ADDS` produces, *not* the flags it sets beside it. That is what a
/// `Pat` claims and what `emit-llvm-target` declares a `Defs` for -- but a
/// consumer wanting the instruction's full architectural effect wants the
/// behavior, not this.
///
/// `formal_semantics` is not the only place a description states behaviour,
/// and for AArch64 it is not the usual one: 430 of that corpus's 487
/// instructions carry a structured `behavior` instead, which is the form that
/// can also express flags, memory and control flow. Two emitters were reading
/// only `formal_semantics` and reporting its absence as if the instruction
/// said nothing -- the LLVM pattern builder, and the golden model, whose
/// evaluator for such an instruction raised "has no AXIS formal_semantics".
///
/// A pure value needs the shape a single evaluator can hold: one register
/// write, computed from an expression. So a behavior qualifies only when it is
/// a single unguarded effect writing one of this instruction's output
/// registers. Anything else -- a flag write beside the result, a guard, a
/// memory access, an effect of an atomic group -- is a real effect that a
/// value cannot represent, and is declined by name rather than silently
/// reduced to its first effect.
///
/// The expression is returned *unreduced*, helper operators and all. Both
/// consumers want that: the golden model implements the helpers itself in
/// Python, and the pattern builder reduces them separately, so the two stay
/// independent implementations of the same description.
pub fn pure_value_semantics(
    instruction: &crate::ast::Instruction,
) -> Result<crate::semantics::SemanticExpr, String> {
    if !instruction.formal_semantics.trim().is_empty() {
        return crate::semantics::parse_formal_semantics(&instruction.formal_semantics)
            .map_err(|_| "unparseable formal_semantics".to_string());
    }
    // ⚠️ Three silences, not one. An instruction that names a routine has an
    // answer no solver can see inside; one declared `unsupplied` has recorded
    // that nobody has an answer; one that says nothing has not been asked. This
    // is the single place the predicate is computed -- the capability manifest
    // and `semantics.smt2` both read it, and its gate requires them to agree --
    // so distinguishing them here is what lets both say the more precise thing
    // at once.
    let answer = instruction.implementation.trim();
    if answer == crate::ast::UNSUPPLIED {
        return Err("declared unsupplied: nothing here performs it".to_string());
    }
    if !answer.is_empty() {
        return Err(format!(
            "performed by the routine `{answer}`, which a solver cannot see inside"
        ));
    }
    if !behavior_is_authoritative(instruction) {
        return Err("no formal_semantics and no behavior".to_string());
    }
    let behavior = instruction
        .behavior
        .as_ref()
        .ok_or_else(|| "no formal_semantics and no behavior".to_string())?;
    // Writes to declared scalar state are separated out rather than refused.
    // An instruction that sets flags beside its result is the commonest shape
    // in the corpus, and the state write is not part of the *value* -- it is a
    // clobber, which `emit-llvm-target` declares as an implicit `Defs` so that
    // LLVM sees it. What is left has to be the one register write.
    //
    // This is the whole of the flag-setting rule, and none of it knows what a
    // flag is: an ISA declares scalar state, a behavior writes it, and `nzcv`,
    // `fpsr` and a future architecture's mode register arrive identically.
    let (state, value): (Vec<&Effect>, Vec<&Effect>) = behavior
        .effects
        .iter()
        .partition(|effect| matches!(effect.loc, Loc::State { .. }));
    if let Some(guarded) = state.iter().find(|effect| effect.guard.is_some()) {
        // A conditionally written flag -- AArch64 CCMN writes NZCV from the
        // comparison or from a literal depending on the condition. The value
        // may still be unconditional, but the instruction is not the simple
        // clobber `Defs` describes, so it is declined rather than flattened.
        let _ = guarded;
        return Err("behavior writes architectural state conditionally".to_string());
    }
    let [effect] = &value[..] else {
        if value.is_empty() {
            // A compare: `CMP`, `CMN`, `TST` write flags and nothing else.
            // There is no destination to select on, which is a property of the
            // instruction rather than a limit of this inference.
            return Err("behavior writes only architectural state".to_string());
        }
        return Err(format!(
            "behavior writes {} values beside its state; one value cannot hold them",
            value.len()
        ));
    };
    if effect.guard.is_some() {
        return Err("behavior is guarded".to_string());
    }
    if effect.atomic_group != 0 {
        return Err("behavior is one effect of an atomic group".to_string());
    }
    let Loc::Reg(written) = &effect.loc else {
        return Err("behavior writes memory or architectural state".to_string());
    };
    if !instruction
        .operands
        .iter()
        .any(|operand| operand.output && operand.name == *written)
    {
        return Err(format!(
            "behavior writes `{written}`, which is not this instruction's result"
        ));
    }
    Ok(effect.value.expr.clone())
}

/// The stored value, the address, and the access width of an instruction whose
/// whole behavior is one plain memory write -- or the reason there is none.
///
/// The companion to `pure_value_semantics`, and deliberately as strict. A store
/// has no result, so it is not a value at all and that function declines it by
/// name; this one says what it *does* instead, in the three pieces a `store`
/// node is made of.
///
/// Nothing else may happen. A second effect means writeback (a register write
/// LLVM would have to see) or architectural state (which a `store` node has
/// nowhere to carry), an ordering means the node is not a plain `store`, and a
/// guard means the write is conditional -- and a pattern that selected any of
/// those would be claiming a plain store the machine does not perform.
/// A plain `send`'s two expressions and its width, or why it is not one.
///
/// The same shape `pure_store_semantics` has, for the same reason: the golden
/// model wants one function per instruction that answers "where does it go and
/// what goes", and an instruction that also writes a register is not that
/// function -- it is two effects, and the executors are what run those in
/// order.
pub fn pure_send_semantics(
    instruction: &crate::ast::Instruction,
) -> Result<(crate::semantics::SemanticExpr, crate::semantics::SemanticExpr, u32), String> {
    let behavior = instruction
        .behavior
        .as_ref()
        .ok_or_else(|| "no behavior".to_string())?;
    let [effect] = &behavior.effects[..] else {
        return Err(format!(
            "a send with {} effects is not a plain send",
            behavior.effects.len()
        ));
    };
    let Loc::Port { port, width } = &effect.loc else {
        return Err("behavior posts no message".to_string());
    };
    if effect.guard.is_some() {
        return Err("a guarded send is not a plain send".to_string());
    }
    Ok((effect.value.expr.clone(), port.expr.clone(), *width))
}

/// How wide a plain send's two expressions evaluate.
pub fn send_operand_widths(instruction: &crate::ast::Instruction) -> Option<(u32, u32)> {
    let behavior = instruction.behavior.as_ref()?;
    let [effect] = &behavior.effects[..] else {
        return None;
    };
    let Loc::Port { port, .. } = &effect.loc else {
        return None;
    };
    Some((effect.value.width.max(1), port.width.max(1)))
}

pub fn pure_store_semantics(
    instruction: &crate::ast::Instruction,
) -> Result<(crate::semantics::SemanticExpr, crate::semantics::SemanticExpr, u32), String> {
    let behavior = instruction
        .behavior
        .as_ref()
        .ok_or_else(|| "no behavior".to_string())?;
    let [effect] = &behavior.effects[..] else {
        return Err(format!(
            "a store with {} effects is not a plain store",
            behavior.effects.len()
        ));
    };
    let Loc::Mem {
        addr,
        width,
        order,
        atomic,
    } = &effect.loc
    else {
        return Err("behavior does not write memory".to_string());
    };
    if *atomic {
        return Err("an atomic store is not a plain `store` node".to_string());
    }
    if *order != MemoryOrder::Relaxed {
        return Err("an ordered store is not a plain `store` node".to_string());
    }
    if effect.guard.is_some() {
        return Err("the store is guarded".to_string());
    }
    if effect.atomic_group != 0 {
        return Err("the store is one effect of an atomic group".to_string());
    }
    Ok((effect.value.expr.clone(), addr.expr.clone(), *width))
}

/// A CONDITIONAL BRANCH: the condition, and the operand naming the target.
///
/// The sibling of the shapes above, for the one kind of instruction that
/// computes no value and touches no memory. `(when COND (setpc (add pc
/// OFFSET)))` is exactly LLVM's `brcond`: a condition and a place to go.
///
/// ⚠️ PC-RELATIVE ONLY. An indirect branch computes its target from a
/// register, and `brcond` has no way to say that -- LLVM spells it
/// `brind`, a different node with a different operand. Refusing here by name
/// beats emitting a pattern that would send control somewhere the description
/// did not say.
///
/// ⚠️ And the target has to be a single immediate operand. A branch whose
/// offset is assembled from several fields is still encodable, but the
/// pattern has to hand LLVM one operand to fill, and there is no honest way
/// to choose which.
pub fn conditional_branch_semantics(
    instruction: &crate::ast::Instruction,
) -> Result<(crate::semantics::SemanticExpr, String), Option<String>> {
    let behavior = instruction.behavior.as_ref().ok_or(None)?;
    let [effect] = &behavior.effects[..] else {
        return Err(None);
    };
    if !matches!(effect.loc, Loc::Pc) {
        return Err(None);
    }
    let Some(guard) = effect.guard.as_ref() else {
        // An unconditional jump is `br`, not `brcond`, and its target is a
        // block rather than a condition and a block. Said by name because it
        // is a real shape this does not handle rather than a malformed one.
        return Err(Some("an unconditional jump is `br`, not `brcond`".to_string()));
    };
    // The target: `(add pc OFFSET)` where OFFSET mentions exactly one operand.
    let named = pc_relative_operand(&effect.value.expr, instruction).ok_or_else(|| {
        Some("the branch target is not the program counter plus one operand".to_string())
    })?;
    Ok((guard.expr.clone(), named))
}

/// The single operand an expression adds to `pc`, if that is its whole shape.
///
/// ⚠️ Candidate names are matched against THE INSTRUCTION'S OWN OPERANDS
/// rather than guessed from their spelling. The first attempt skipped atoms
/// beginning with `i` to drop the type tags -- `i32`, `i64` -- and dropped
/// `imm` with them, so every RISC-V branch was refused for having no operand
/// in a target that named one.
fn pc_relative_operand(
    expr: &crate::semantics::SemanticExpr,
    instruction: &crate::ast::Instruction,
) -> Option<String> {
    use crate::semantics::SemanticExpr;
    let SemanticExpr::List(items) = expr else {
        return None;
    };
    let SemanticExpr::Atom(op) = items.first()? else {
        return None;
    };
    if op != "add" {
        return None;
    }
    let mut names = Vec::new();
    collect_atoms(expr, &mut names);
    if !names.iter().any(|name| name == "pc") {
        return None;
    }
    let mut operand: Option<String> = None;
    for name in names {
        if !instruction.operands.iter().any(|o| o.name == name) {
            continue;
        }
        if operand.is_some() && operand.as_deref() != Some(name.as_str()) {
            // Two operands in one target: there is no honest way to choose
            // which one a pattern should hand LLVM.
            return None;
        }
        operand = Some(name);
    }
    operand
}

/// Every atom an expression names -- operands among them.
pub fn expr_atoms(expr: &crate::semantics::SemanticExpr) -> Vec<String> {
    let mut out = Vec::new();
    collect_atoms(expr, &mut out);
    out
}

fn collect_atoms(expr: &crate::semantics::SemanticExpr, out: &mut Vec<String>) {
    use crate::semantics::SemanticExpr;
    match expr {
        SemanticExpr::Atom(name) => out.push(name.clone()),
        SemanticExpr::List(items) => {
            for item in items {
                collect_atoms(item, out);
            }
        }
        _ => {}
    }
}

/// An atomic read-modify-write: the address, the value written back, the
/// register the old value lands in, the access width, and the ordering of each
/// half.
///
/// Two effects again, and again neither of the earlier shapes sees it: an
/// atomic load into a register *and* an atomic store to the address it read.
/// LLVM models the pair as one node, `atomic_load_add` and its family, whose
/// result is the old value -- which is exactly what the register effect holds.
pub fn atomic_rmw_semantics(
    instruction: &crate::ast::Instruction,
) -> Result<AtomicRmw, Option<String>> {
    let behavior = instruction.behavior.as_ref().ok_or(None)?;
    let [first, second] = &behavior.effects[..] else {
        return Err(None);
    };
    let (load, store) = match (&first.loc, &second.loc) {
        (Loc::Reg(_), Loc::Mem { .. }) => (first, second),
        (Loc::Mem { .. }, Loc::Reg(_)) => (second, first),
        _ => return Err(None),
    };
    let Loc::Mem {
        addr,
        width,
        order: store_order,
        atomic,
    } = &store.loc
    else {
        unreachable!("matched above");
    };
    let Loc::Reg(loaded) = &load.loc else {
        unreachable!("matched above");
    };
    // Both halves atomic, and reading and writing one address.
    if !atomic || !load.value.load_atomic {
        return Err(None);
    }
    let crate::semantics::SemanticExpr::Atom(address) = &addr.expr else {
        return Err(None);
    };
    // The load reads the same place the store writes, and nothing else.
    let reads = match &load.value.expr {
        crate::semantics::SemanticExpr::List(items) => items.last(),
        _ => None,
    };
    if !matches!(reads, Some(crate::semantics::SemanticExpr::Atom(atom)) if atom == address) {
        return Err(None);
    }
    if load.guard.is_some() || store.guard.is_some() {
        return Err(Some("the access is guarded".to_string()));
    }
    Ok(AtomicRmw {
        address: address.clone(),
        stored: store.value.expr.clone(),
        loaded: loaded.clone(),
        access: *width,
        load_order: load.value.load_order,
        store_order: *store_order,
    })
}

/// What `atomic_rmw_semantics` found.
#[derive(Debug, Clone)]
pub struct AtomicRmw {
    pub address: String,
    pub stored: crate::semantics::SemanticExpr,
    pub loaded: String,
    pub access: u32,
    pub load_order: MemoryOrder,
    pub store_order: MemoryOrder,
}

impl AtomicRmw {
    /// The single LLVM ordering the pair amounts to.
    ///
    /// An architecture states the halves separately -- AArch64 spells them in
    /// the mnemonic, `LDADD`/`LDADDA`/`LDADDL`/`LDADDAL` -- and LLVM carries
    /// one ordering for the whole operation. Combining them is the only place
    /// this needs to know that acquire is about the read and release about the
    /// write.
    pub fn ordering(&self) -> Option<&'static str> {
        let acquires = matches!(self.load_order, MemoryOrder::Acquire);
        let releases = matches!(self.store_order, MemoryOrder::Release);
        Some(match (acquires, releases) {
            (false, false) => "monotonic",
            (true, false) => "acquire",
            (false, true) => "release",
            (true, true) => "acq_rel",
        })
    }
}

/// A store that also updates its base register: the stored value, the base,
/// the offset added to it, the access width, and whether the update happens
/// *before* the store.
///
/// Two effects, and which is which is said by their order rather than by their
/// expressions. AArch64's post-index `STR` stores at `rn` and then sets `rn`
/// to `rn + imm`; the pre-index form sets `rn` first and stores at the new
/// value. Both write the same two places with the same two expressions, and
/// the ordered effect list is the only thing that separates them -- which is
/// what that ordering is for.
pub fn indexed_store_semantics(
    instruction: &crate::ast::Instruction,
) -> Result<IndexedStore, Option<String>> {
    // `Err(None)` means "not this shape at all", and the caller keeps whatever
    // reason it already had. Only an instruction that *is* a store updating
    // its own base gets a message of its own -- checking a refusal before
    // checking the shape made every atomic swap on the seed report itself as
    // an ordered indexed store, which is 320 instructions filed under a cause
    // that has nothing to do with them.
    let behavior = instruction.behavior.as_ref().ok_or(None)?;
    let [first, second] = &behavior.effects[..] else {
        return Err(None);
    };
    let (update, store, pre) = match (&first.loc, &second.loc) {
        (Loc::Reg(_), Loc::Mem { .. }) => (first, second, true),
        (Loc::Mem { .. }, Loc::Reg(_)) => (second, first, false),
        _ => return Err(None),
    };
    let Loc::Mem {
        addr,
        width,
        order,
        atomic,
    } = &store.loc
    else {
        unreachable!("matched above");
    };
    let Loc::Reg(base) = &update.loc else {
        unreachable!("matched above");
    };
    // Shape first. The address is the base register itself -- anything else is
    // an addressing mode this cannot state -- and the register written is that
    // same base, advanced by something.
    let crate::semantics::SemanticExpr::Atom(addressed) = &addr.expr else {
        return Err(None);
    };
    if addressed != base {
        return Err(None);
    }
    let crate::semantics::SemanticExpr::List(items) = &update.value.expr else {
        return Err(None);
    };
    let [crate::semantics::SemanticExpr::Atom(op), rest @ ..] = &items[..] else {
        return Err(None);
    };
    if op != "add" {
        return Err(None);
    }
    let operands: Vec<&crate::semantics::SemanticExpr> = rest
        .iter()
        .filter(|item| !matches!(item, crate::semantics::SemanticExpr::Atom(atom)
            if atom.starts_with('i') && atom[1..].chars().all(|c| c.is_ascii_digit())))
        .collect();
    let [lhs, offset] = &operands[..] else {
        return Err(None);
    };
    if !matches!(lhs, crate::semantics::SemanticExpr::Atom(atom) if atom == base) {
        return Err(None);
    }
    // It is one. Now say why it might still not have a pattern.
    if *atomic || *order != MemoryOrder::Relaxed {
        return Err(Some(
            "an ordered indexed store is not a plain one".to_string(),
        ));
    }
    if store.guard.is_some() || update.guard.is_some() {
        return Err(Some("the store or its update is guarded".to_string()));
    }
    if store.atomic_group != 0 || update.atomic_group != 0 {
        return Err(Some("one effect of an atomic group".to_string()));
    }
    Ok(IndexedStore {
        value: store.value.expr.clone(),
        base: base.clone(),
        offset: (*offset).clone(),
        access: *width,
        pre,
    })
}

/// What `indexed_store_semantics` found.
#[derive(Debug, Clone)]
pub struct IndexedStore {
    pub value: crate::semantics::SemanticExpr,
    pub base: String,
    pub offset: crate::semantics::SemanticExpr,
    pub access: u32,
    /// The base is updated *before* the store: a pre-index access.
    pub pre: bool,
}

/// The widths a store's two halves are evaluated at: the register the value
/// comes out of, and the register its address is formed from.
///
/// A store has two, and conflating them is how `FSD` -- a 64-bit float store
/// whose base register RV32I declares as 64 bits -- produced a pattern that
/// contradicted the target's own pointer type. One answer, so the emitter and
/// the golden model cannot each pick a different one.
pub fn store_operand_widths(instruction: &crate::ast::Instruction) -> Option<(u32, u32)> {
    let (value, addr, _) = pure_store_semantics(instruction).ok()?;
    let register_width = |expr: &crate::semantics::SemanticExpr| -> Option<u32> {
        let mut widest: Option<u32> = None;
        let mut stack = vec![expr];
        while let Some(node) = stack.pop() {
            match node {
                crate::semantics::SemanticExpr::Atom(name) => {
                    if let Some(operand) = instruction.operands.iter().find(|operand| {
                        operand.name == *name && crate::ast::register_class(&operand.kind).is_some()
                    }) {
                        widest = Some(widest.map_or(operand.width, |seen| seen.max(operand.width)));
                    }
                }
                crate::semantics::SemanticExpr::List(items) => stack.extend(items.iter()),
            }
        }
        widest
    };
    Some((register_width(&value)?, register_width(&addr)?))
}

/// The width a load's *address* is evaluated at, when the instruction's value
/// is a load and the frontend resolved one.
///
/// The address and the result are two widths, and the golden model was
/// evaluating both at the result's -- which is right for every load whose base
/// register is as wide as its destination and wrong for AArch64's `LDRB_W`,
/// which reads a byte into a `W` register through an `X` address. The address
/// then wrapped at 32 bits and the model disagreed with a pattern that had it
/// right. The frontend already resolves this; nothing was asking for it.
pub fn value_load_address_width(instruction: &crate::ast::Instruction) -> Option<u32> {
    let behavior = instruction.behavior.as_ref()?;
    behavior
        .effects
        .iter()
        .find(|effect| matches!(effect.loc, Loc::Reg(_)))
        .and_then(|effect| effect.value.load_address_width)
}

/// A `SemanticExpr` back as source text, which is how the golden model carries
/// an expression: it embeds the string and evaluates it at run time.
pub fn render_semantic_expr(expr: &crate::semantics::SemanticExpr) -> String {
    match expr {
        crate::semantics::SemanticExpr::Atom(atom) => atom.clone(),
        crate::semantics::SemanticExpr::List(items) => {
            let parts: Vec<String> = items.iter().map(render_semantic_expr).collect();
            format!("({})", parts.join(" "))
        }
    }
}

/// What an instruction touches beyond its own operands (`docs/effects_design.md`
/// section 6). One definition, consumed by the lift table's `effect_summary`
/// and by the LLVM intrinsic emitter's memory attributes, so the artifact a
/// consumer reads and the attributes a compiler trusts cannot disagree.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct EffectSummary {
    /// This instruction posts a message out of the machine.
    ///
    /// ⚠️ Kept apart from `writes_memory` on purpose. Both leave the machine,
    /// and a consumer that treated them alike would give a `send` a memory
    /// attribute it has no address for -- and would let one be reordered
    /// against the other on the strength of an alias analysis that has nothing
    /// to analyse.
    pub sends: bool,
    pub reads_memory: bool,
    pub writes_memory: bool,
    pub reads_state: bool,
    pub writes_state: bool,
    pub writes_pc: bool,
    pub may_trap: bool,
    pub barrier: bool,
}

impl EffectSummary {
    /// True when the only things touched are memory accesses — the shape an
    /// LLVM intrinsic can describe with a memory attribute. Control flow,
    /// traps, barriers, and architectural state have no such spelling, so an
    /// intrinsic for one of those would be a label without a meaning.
    pub fn is_memory_only(self) -> bool {
        !self.reads_state
            && !self.writes_state
            && !self.writes_pc
            && !self.may_trap
            && !self.barrier
    }
}

/// Summarize an instruction's behavior. `state_names` comes from
/// [`isa_scalar_state_names`]: a behavior reads architectural state by naming
/// it, so the summary cannot be derived from the effect list alone.
pub fn effect_summary(
    instruction: &crate::ast::Instruction,
    state_names: &[String],
) -> EffectSummary {
    let mut summary = EffectSummary::default();
    if !behavior_is_authoritative(instruction) {
        return summary;
    }
    let Some(behavior) = instruction.behavior.as_ref() else {
        return summary;
    };
    for effect in &behavior.effects {
        match &effect.loc {
            Loc::Mem { .. } => summary.writes_memory = true,
            Loc::State { .. } => summary.writes_state = true,
            Loc::Barrier { .. } => summary.barrier = true,
            Loc::Port { .. } => summary.sends = true,
            Loc::Pc => summary.writes_pc = true,
            Loc::Trap => summary.may_trap = true,
            Loc::Reg(_) | Loc::FixedReg { .. } => {}
        }
        let mut expressions = vec![&effect.value.expr];
        if let Loc::Mem { addr, .. } = &effect.loc {
            expressions.push(&addr.expr);
        }
        if let Loc::Port { port, .. } = &effect.loc {
            expressions.push(&port.expr);
        }
        if let Some(guard) = &effect.guard {
            expressions.push(&guard.expr);
        }
        for expression in expressions {
            summary.reads_memory |= expr_reads_memory(expression);
            summary.reads_state |= state_names
                .iter()
                .any(|name| expr_mentions(expression, name));
        }
    }
    summary
}

/// The registers a behavior reads by name, in the order it names them.
///
/// An instruction's dependencies are its operands, except when they are not:
/// a `getreg` reads a register decode never selected, and a consumer that
/// reads only `reads` would reorder a write to it across this instruction.
/// Published rather than inferred, and it is also what lets a differential
/// harness seed the register the description names -- which is the difference
/// between executing the read and comparing two zeroes.
pub fn behavior_register_reads(instruction: &crate::ast::Instruction) -> Vec<(String, u32)> {
    let mut reads: Vec<(String, u32)> = Vec::new();
    if !behavior_is_authoritative(instruction) {
        return reads;
    }
    let Some(behavior) = instruction.behavior.as_ref() else {
        return reads;
    };
    for effect in &behavior.effects {
        let mut expressions = vec![&effect.value.expr];
        if let Loc::Mem { addr, .. } = &effect.loc {
            expressions.push(&addr.expr);
        }
        if let Some(guard) = &effect.guard {
            expressions.push(&guard.expr);
        }
        for expression in expressions {
            collect_register_reads(expression, &mut reads);
        }
    }
    reads
}

fn collect_register_reads(expr: &SemanticExpr, into: &mut Vec<(String, u32)>) {
    let SemanticExpr::List(items) = expr else {
        return;
    };
    if let [SemanticExpr::Atom(op), SemanticExpr::Atom(kind), SemanticExpr::Atom(index)] =
        items.as_slice()
    {
        if op == "getreg" {
            if let Ok(index) = index.parse::<u32>() {
                let read = (kind.clone(), index);
                if !into.contains(&read) {
                    into.push(read);
                }
                return;
            }
        }
    }
    for item in items {
        collect_register_reads(item, into);
    }
}

/// Scalar architectural-state names declared by `isa.registers` — the atoms a
/// behavior may read that are neither operands nor `pc` (`nzcv:i4`, `fpcr:i32`,
/// `tpidr_el0:i64`, …). Register *files* (`x[31]:i64`) are addressed through
/// operands, not read by name, so they are not state atoms. `pc` is excluded
/// because every executor ABI passes it explicitly.
/// The same list as [`isa_scalar_state_names`], paired with each entry's
/// declared width. Consumers of the effect ABI need both: the slot order to
/// address `%state`, and the width to know what a value means.
/// The readable name of a lane-parallel ISA's lane index.
///
/// One constant rather than a per-ISA convention: a tool that wants to know
/// which lane a semantics is talking about should not have to learn each
/// architecture's spelling, and an ISA should not be able to shadow it.
pub const LANE_ID: &str = "lane_id";

/// Does any of these ISAs declare lanes?
pub fn declares_lanes(isas: &[crate::ast::Isa]) -> bool {
    isas.iter().any(|isa| isa.lanes > 0)
}

/// The register FILES an ISA declares, as `(prefix, count)` in slot order.
///
/// `(registers "x[32]:i64" "pc:i64")` says the machine has thirty-two
/// registers spelled `x0`..`x31`. That spelling is the only naming any
/// description states, and until now nothing read it: a disassembler built
/// from the published artifact printed `$rd` where a register belongs, and an
/// assembler had no way to know what a register looks like.
///
/// ⚠️ It is the *canonical* spelling and not the only one. RISC-V's `a0` and
/// AArch64's `sp` are ABI and architectural aliases that no description states,
/// so nothing generated from this can accept or print them. That is a gap in
/// the descriptions rather than in the generator, and it is worth saying out
/// loud wherever the names are used.
pub fn isa_register_files(isas: &[crate::ast::Isa]) -> Vec<(String, u32)> {
    let mut files: Vec<(String, u32)> = Vec::new();
    for isa in isas {
        for raw in &isa.registers {
            let head = raw.splitn(2, ':').next().unwrap_or(raw).trim();
            let Some(open) = head.find('[') else { continue };
            let Some(close) = head.find(']') else { continue };
            if close < open {
                continue;
            }
            let prefix = head[..open].trim().to_string();
            let Ok(count) = head[open + 1..close].trim().parse::<u32>() else {
                continue;
            };
            if prefix.is_empty() || files.iter().any(|(name, _)| *name == prefix) {
                continue;
            }
            files.push((prefix, count));
        }
    }
    files
}

pub fn isa_scalar_state_slots(isas: &[crate::ast::Isa]) -> Vec<(String, u32)> {
    let mut slots: Vec<(String, u32)> = Vec::new();
    // A lane-parallel ISA reads its lane index like any other architectural
    // state, so it is synthesised into the same list rather than given a path
    // of its own -- the parser's symbol resolution, the effect summary, the
    // lift ABI and every executor's `state` argument then carry it with no
    // further work, which is the point of putting it here.
    for isa in isas {
        if isa.lanes > 0 && !slots.iter().any(|(name, _)| name == LANE_ID) {
            slots.push((LANE_ID.to_string(), isa.word_bits.max(1)));
        }
    }
    for isa in isas {
        for raw in &isa.registers {
            let mut parts = raw.splitn(2, ':');
            let head = parts.next().unwrap_or(raw).trim();
            if head.is_empty() || head == "pc" || head.contains('[') {
                continue;
            }
            if slots.iter().any(|(name, _)| name == head) {
                continue;
            }
            let width = parts
                .next()
                .and_then(|text| text.trim().strip_prefix('i'))
                .and_then(|digits| digits.parse().ok())
                .unwrap_or(64);
            slots.push((head.to_string(), width));
        }
    }
    slots
}

/// The architectural state an instruction's *value* reads, with widths.
///
/// A value may depend on state as well as on operands: AArch64's `adc` takes
/// its carry from `nzcv`, its conditional selects take the whole condition
/// from there, and the floating-point forms read `fpcr`. A function over the
/// instruction's operands has nowhere to bind that, so those instructions used
/// to have no value at all in any backend -- thirty-nine of them in the
/// AArch64 corpus.
///
/// They are parameters instead, appended after the operands in the ISA's
/// published order. Appended rather than mixed in, so every function that
/// exists today keeps the signature it has: an instruction that reads no state
/// is byte-identical, and only the ones that were missing gain anything.
pub fn value_state_reads(
    instruction: &crate::ast::Instruction,
    isas: &[crate::ast::Isa],
) -> Vec<(String, u32)> {
    let Ok(value) = pure_value_semantics(instruction) else {
        return Vec::new();
    };
    let text = render_semantic_expr(&value);
    let mentions = |name: &str| {
        text.split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|token| token == name)
    };
    // A name an operand already binds is that operand, not state. A scalable
    // instruction takes `vl` as an operand while its ISA also declares `vl`,
    // and appending it as state emitted a Python function with the parameter
    // twice -- a file that will not import, from a name collision the emitter
    // is the only place that can see.
    let operands: Vec<&str> = instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        .map(|operand| operand.name.as_str())
        .collect();
    isa_scalar_state_slots(isas)
        .into_iter()
        .filter(|(name, _width)| mentions(name) && !operands.contains(&name.as_str()))
        .collect()
}

pub fn isa_scalar_state_names(isas: &[crate::ast::Isa]) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    if declares_lanes(isas) {
        names.push(LANE_ID.to_string());
    }
    for isa in isas {
        for raw in &isa.registers {
            let head = raw.split(':').next().unwrap_or(raw).trim();
            if head.is_empty() || head == "pc" || head.contains('[') {
                continue;
            }
            if !names.iter().any(|name| name == head) {
                names.push(head.to_string());
            }
        }
    }
    names
}

#[cfg(test)]
mod lane_id_tests {
    use super::*;
    use crate::ast::Isa;

    fn isa(lanes: u32) -> Isa {
        Isa { name: "t".into(), lanes, word_bits: 32, ..Isa::default() }
    }

    #[test]
    fn declaring_lanes_makes_the_lane_index_readable_state() {
        // The whole feature: an ISA that says it has lanes gets `lane_id` in
        // the same list every other readable state is in, so the parser's
        // scope, the effect summary, the lift ABI and every executor's `state`
        // argument carry it with no further work.
        let names = isa_scalar_state_names(&[isa(4)]);
        assert!(names.contains(&LANE_ID.to_string()), "{names:?}");
        let slots = isa_scalar_state_slots(&[isa(4)]);
        assert_eq!(
            slots.iter().find(|(name, _)| name == LANE_ID),
            Some(&(LANE_ID.to_string(), 32))
        );
    }

    #[test]
    fn an_isa_without_lanes_has_no_lane_index() {
        // Not a default. An ISA that never said it was lane-parallel should
        // fail to resolve `lane_id` rather than silently read lane 0, which is
        // the value a defaulted one would take and the hardest to notice.
        assert!(!isa_scalar_state_names(&[isa(0)]).contains(&LANE_ID.to_string()));
        assert!(isa_scalar_state_slots(&[isa(0)])
            .iter()
            .all(|(name, _)| name != LANE_ID));
    }

    #[test]
    fn the_lane_index_is_as_wide_as_the_word() {
        // It is read into ordinary arithmetic, so it is the word's width and
        // not the narrowest that could hold the count.
        let mut wide = isa(8);
        wide.word_bits = 64;
        let slots = isa_scalar_state_slots(&[wide]);
        assert_eq!(
            slots.iter().find(|(name, _)| name == LANE_ID).map(|(_, w)| *w),
            Some(64)
        );
    }
}

pub(crate) fn expr_mentions(expr: &SemanticExpr, symbol: &str) -> bool {
    match expr {
        SemanticExpr::Atom(atom) => atom == symbol,
        SemanticExpr::List(items) => items.iter().any(|item| expr_mentions(item, symbol)),
    }
}

fn expr_uses_operator(expr: &SemanticExpr, operator: &str) -> bool {
    match expr {
        SemanticExpr::Atom(_) => false,
        SemanticExpr::List(items) => {
            matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == operator)
                || items
                    .iter()
                    .skip(1)
                    .any(|item| expr_uses_operator(item, operator))
        }
    }
}

/// Validate a behavior against the in-scope operand `symbols`. Pure effect
/// values validate through the typed IR; a top-level `load` validates its
/// shape and its (pure) address expression.
pub fn validate_behavior(
    behavior: &Behavior,
    symbols: &[String],
    states: &[(String, u32)],
) -> Result<(), String> {
    // `pc` is always in scope for effect expressions.
    let mut scope = symbols.to_vec();
    scope.push("pc".to_string());
    scope.extend(states.iter().map(|(name, _)| name.clone()));
    validate_atomic_groups(behavior)?;
    for effect in &behavior.effects {
        if let Some(guard) = &effect.guard {
            if guard.width == 0 {
                return Err("guard is missing its evaluation width".to_string());
            }
            // A guard may read memory (H1a): a descriptor's engine checks a
            // magic word and bounds a loop by a count it read. The loads become
            // symbols first, exactly as in a value, and what is validated as a
            // guard is the comparison around them.
            let (skeleton, guard_scope) = strip_loads(
                &guard.expr,
                guard.load_address_width.unwrap_or(guard.width),
                &scope,
            )?;
            if guard_scope.len() > scope.len() && guard.load_address_width.is_none() {
                return Err("guard load address is missing its evaluation width".to_string());
            }
            validate_guard(&skeleton, guard.width, &guard_scope)?;
        }
        match &effect.loc {
            Loc::State { name, width } => {
                if !states
                    .iter()
                    .any(|(state_name, state_width)| state_name == name && state_width == width)
                {
                    return Err(format!(
                        "state `{name}:i{width}` is not declared by the instruction's ISA"
                    ));
                }
                validate_value(&effect.value, &scope)?;
            }
            Loc::FixedReg { .. } => validate_value(&effect.value, &scope)?,
            Loc::Mem { addr, .. } => {
                if addr.width == 0 {
                    return Err("memory address is missing its evaluation width".to_string());
                }
                // And so may an address: "write where the descriptor says" is
                // what a descriptor is, and `status_ptr` is read from memory.
                let (skeleton, address_scope) = strip_loads(&addr.expr, addr.width, &scope)?;
                validate_pure(&skeleton, addr.width, &address_scope)?;
                validate_value(&effect.value, &scope)?;
            }
            Loc::Barrier { kind, width } => {
                if barrier_kind(kind).is_none() {
                    return Err(format!("unsupported barrier kind `{kind}`"));
                }
                let expected = barrier_kind(kind).map(|found| found.option_bits);
                if expected != Some(*width) {
                    return Err(format!(
                        "barrier `{kind}` option must have width i{}",
                        expected.unwrap_or(0)
                    ));
                }
                // Everywhere else a zero width means the width was never
                // resolved, which is what `validate_value` is there to catch.
                // For a barrier with no option it is the true width, so what
                // has to hold instead is that there is nothing to evaluate.
                if *width == 0 {
                    if !matches!(&effect.value.expr, SemanticExpr::Atom(value) if value == "0") {
                        return Err(format!("barrier `{kind}` takes no option"));
                    }
                } else {
                    validate_value(&effect.value, &scope)?;
                }
            }
            // A trap's `value` is a cause name, not an expression.
            Loc::Trap => validate_cause(&effect.value.expr)?,
            _ => validate_value(&effect.value, &scope)?,
        }
    }
    Ok(())
}

fn validate_atomic_groups(behavior: &Behavior) -> Result<(), String> {
    use std::collections::{HashMap, HashSet};

    let mut counts = HashMap::<u32, usize>::new();
    let mut has_atomic_memory = HashSet::<u32>::new();
    let mut closed = HashSet::<u32>::new();
    let mut active = 0;
    for effect in &behavior.effects {
        let group = effect.atomic_group;
        if group != active {
            if active != 0 {
                closed.insert(active);
            }
            if group != 0 && closed.contains(&group) {
                return Err(format!("atomic group {group} must be contiguous"));
            }
            active = group;
        }
        if group == 0 {
            continue;
        }
        *counts.entry(group).or_default() += 1;
        if matches!(effect.loc, Loc::Mem { atomic: true, .. })
            || effect.value.load_atomic
            || is_atomic_load(&effect.value.expr)
        {
            has_atomic_memory.insert(group);
        }
    }
    for (group, count) in counts {
        if count < 2 {
            return Err(format!(
                "atomic group {group} must contain at least two effects"
            ));
        }
        if !has_atomic_memory.contains(&group) {
            return Err(format!(
                "atomic group {group} must contain an atomic load or atomic store"
            ));
        }
    }
    Ok(())
}

/// A trap cause must be one of the recognized [`TRAP_CAUSES`].
fn validate_cause(expr: &SemanticExpr) -> Result<(), String> {
    if let SemanticExpr::Atom(cause) = expr {
        if TRAP_CAUSES.contains(&cause.as_str()) {
            return Ok(());
        }
    }
    Err(format!(
        "trap cause must be one of {}",
        TRAP_CAUSES.join(", ")
    ))
}

/// A guard is an integer comparison or a boolean composition of them.
fn validate_guard(expr: &SemanticExpr, width: u32, symbols: &[String]) -> Result<(), String> {
    if let SemanticExpr::List(items) = expr {
        if let Some(SemanticExpr::Atom(op)) = items.first() {
            if crate::ir::is_integer_comparison(op) && items.len() == 3 {
                validate_pure(&items[1], width, symbols)?;
                return validate_pure(&items[2], width, symbols);
            }
            if matches!(op.as_str(), "and" | "or") && items.len() >= 3 {
                for child in &items[1..] {
                    validate_guard(child, width, symbols)?;
                }
                return Ok(());
            }
            if op == "not" && items.len() == 2 {
                return validate_guard(&items[1], width, symbols);
            }
        }
    }
    Err("guard must be an integer comparison composed with `and`, `or`, or `not`".to_string())
}

/// Validate every load in `expr` and replace it with a symbol.
///
/// ⚠️ The `getreg` move, one construct over. A load is a leaf the pure IR has
/// no node for, so it becomes a symbol before lowering and what the IR checks
/// is the expression *around* it -- which means the load itself is checked
/// here or nowhere.
///
/// This is what lets an effect carry MORE THAN ONE. The nested case already
/// existed for atomic read-modify-write, whose load sits inside the stored
/// value, and the Python executor has always evaluated loads recursively
/// through `__mem__`; what stopped a second one was this validation step
/// alone, which stripped a load only when the whole value was one. A
/// contraction whose terms are memory reads was refused with "unsupported
/// formal_semantics operator `load`" -- a message about the typed IR, from the
/// one place that had not been told loads exist.
fn rewrite_loads(
    expr: &SemanticExpr,
    address_width: u32,
    symbols: &[String],
    found: &mut usize,
) -> Result<SemanticExpr, String> {
    let SemanticExpr::List(items) = expr else {
        return Ok(expr.clone());
    };
    if matches!(items.first(), Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "load" | "atomic_load"))
    {
        if !matches!(items.len(), 4 | 5) {
            return Err(
                "load must be `load(iW, signed|unsigned[, relaxed|acquire], addr)`".to_string(),
            );
        }
        let width_ok = matches!(&items[1], SemanticExpr::Atom(a)
            if a.starts_with(['i', 'u']) && a[1..].chars().all(|c| c.is_ascii_digit()) && a.len() > 1);
        let sign_ok =
            matches!(&items[2], SemanticExpr::Atom(a) if a == "signed" || a == "unsigned");
        let order_ok = items.len() == 4
            || matches!(
                parse_memory_order(&items[3]),
                Some(MemoryOrder::Relaxed | MemoryOrder::Acquire)
            );
        if !width_ok || !sign_ok || !order_ok {
            return Err(
                "load must be `load(iW, signed|unsigned[, relaxed|acquire], addr)`".to_string(),
            );
        }
        // The address is an ordinary pure expression evaluated at the
        // machine's width rather than the surrounding value's: a byte loaded
        // into an i8 still comes from a 64-bit address.
        let address = items.last().expect("validated load shape");
        let address = rewrite_loads(address, address_width, symbols, found)?;
        // ⚠️ The address is validated against the names the rewrite has
        // already allocated, because an address may itself be a load: a
        // pointer chase is `(load (load rs1))`, and the outer address is the
        // inner load's symbol by the time it is checked. Validating against
        // the original scope reported `__load0` as an unknown symbol, which is
        // the rewrite's own name leaking out as a diagnosis.
        let mut scope = symbols.to_vec();
        for index in 0..*found {
            scope.push(format!("__load{index}"));
        }
        validate_pure(&address, address_width, &scope)?;
        let name = format!("__load{found}");
        *found += 1;
        return Ok(SemanticExpr::Atom(name));
    }
    let mut rebuilt = Vec::with_capacity(items.len());
    for item in items {
        rebuilt.push(rewrite_loads(item, address_width, symbols, found)?);
    }
    Ok(SemanticExpr::List(rebuilt))
}

/// `expr` with every load replaced by a symbol, and the scope those symbols
/// extend -- what `validate_value` does inline, for the two other places an
/// effect evaluates an expression.
fn strip_loads(
    expr: &SemanticExpr,
    address_width: u32,
    symbols: &[String],
) -> Result<(SemanticExpr, Vec<String>), String> {
    let mut found = 0usize;
    let skeleton = rewrite_loads(expr, address_width, symbols, &mut found)?;
    let mut scope = symbols.to_vec();
    for index in 0..found {
        scope.push(format!("__load{index}"));
    }
    Ok((skeleton, scope))
}

/// Whether any load appears anywhere in `expr`.
pub fn contains_load(expr: &SemanticExpr) -> bool {
    match expr {
        SemanticExpr::Atom(_) => false,
        SemanticExpr::List(items) => {
            matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "load" || op == "atomic_load")
                || items.iter().any(contains_load)
        }
    }
}

fn validate_value(expr: &EffectExpr, symbols: &[String]) -> Result<(), String> {
    if expr.width == 0 {
        return Err("effect value is missing its evaluation width".to_string());
    }
    let mut found = 0usize;
    let address_width = expr.load_address_width.unwrap_or(expr.width);
    let skeleton = rewrite_loads(&expr.expr, address_width, symbols, &mut found)?;
    if found > 0 && expr.load_address_width.is_none() {
        return Err("load address is missing its evaluation width".to_string());
    }
    let mut scope = symbols.to_vec();
    for index in 0..found {
        scope.push(format!("__load{index}"));
    }
    validate_pure(&skeleton, expr.width, &scope)
}

fn validate_pure(expr: &SemanticExpr, width: u32, symbols: &[String]) -> Result<(), String> {
    if let SemanticExpr::List(items) = expr {
        if let Some(SemanticExpr::Atom(op)) = items.first() {
            if op == "input" {
                let [SemanticExpr::Atom(symbol)] = &items[1..] else {
                    return Err("input must be `input(operand)`".to_string());
                };
                return symbols
                    .iter()
                    .any(|candidate| candidate == symbol)
                    .then_some(())
                    .ok_or_else(|| format!("input references unknown operand `{symbol}`"));
            }
            let expected = match op.as_str() {
                "a64_add_nzcv" | "a64_sub_nzcv" => Some(2),
                "a64_adc_nzcv" | "a64_sbc_nzcv" => Some(3),
                "a64_umulh" | "a64_smulh" => Some(2),
                "a64_logic_nzcv" => Some(1),
                "a64_cond_holds" => Some(2),
                "a64_shift_reg" => Some(3),
                "a64_extend_reg" => Some(3),
                "a64_wmask" | "a64_ubfm" | "a64_sbfm" => Some(3),
                "a64_bfm" => Some(4),
                _ => None,
            };
            if let Some(expected) = expected {
                let raw_args = &items[1..];
                let typed_width = match raw_args.first() {
                    Some(SemanticExpr::Atom(atom))
                        if atom.len() > 1
                            && atom.starts_with(['i', 'u'])
                            && atom[1..].chars().all(|c| c.is_ascii_digit()) =>
                    {
                        atom[1..].parse::<u32>().ok()
                    }
                    _ => None,
                };
                let Some(typed_width) = typed_width else {
                    return Err(format!("operator `{op}` requires an integer type"));
                };
                let width_ok = match op.as_str() {
                    "a64_add_nzcv" | "a64_sub_nzcv" | "a64_adc_nzcv" | "a64_sbc_nzcv"
                    | "a64_logic_nzcv" => {
                        matches!(typed_width, 32 | 64)
                    }
                    "a64_umulh" | "a64_smulh" => typed_width == 64,
                    "a64_cond_holds" => typed_width == 4,
                    "a64_shift_reg" | "a64_extend_reg" | "a64_wmask" | "a64_ubfm" | "a64_sbfm"
                    | "a64_bfm" => {
                        matches!(typed_width, 32 | 64)
                    }
                    _ => false,
                };
                if !width_ok {
                    return Err(format!(
                        "operator `{op}` does not support type i{typed_width}"
                    ));
                }
                let args = &raw_args[1..];
                if args.len() != expected {
                    return Err(format!("operator `{op}` expects {expected} arguments"));
                }
                for arg in args {
                    validate_pure(arg, typed_width, symbols)?;
                }
                return Ok(());
            }
            if [
                "a64_cond_holds",
                "a64_shift_reg",
                "a64_extend_reg",
                "a64_wmask",
                "a64_ubfm",
                "a64_sbfm",
                "a64_bfm",
            ]
            .iter()
            .any(|helper| expr_uses_operator(expr, helper))
            {
                if !matches!(
                    op.as_str(),
                    "add"
                        | "sub"
                        | "and"
                        | "or"
                        | "xor"
                        | "shl"
                        | "sll"
                        | "lshr"
                        | "srl"
                        | "if"
                        | "select"
                ) {
                    return Err(format!("operator `{op}` cannot contain an A64 helper"));
                }
                for item in items.iter().skip(1) {
                    if !matches!(item, SemanticExpr::Atom(atom) if crate::ir::is_type_atom(atom)) {
                        validate_pure(item, width, symbols)?;
                    }
                }
                return Ok(());
            }
        }
    }
    let expr = rewrite_input_snapshots(expr);
    // A register read is a leaf value the pure IR has no node for, so it
    // becomes a symbol before lowering -- the same move `input` makes, and for
    // the same reason: what the IR checks about the expression around it is
    // exactly what it checks around an operand. Which means the read itself is
    // checked here or nowhere: it is a symbol by the time the IR sees it, and
    // a symbol says nothing about the file it came out of.
    validate_register_reads(&expr)?;
    let (expr, reads) = rewrite_register_reads(&expr);
    let mut symbols = symbols.to_vec();
    symbols.extend(
        symbols
            .clone()
            .into_iter()
            .map(|symbol| format!("__input_{symbol}")),
    );
    symbols.extend(reads);
    let sem = crate::ir::lower(&expr, width).map_err(|error| error.message)?;
    crate::ir::check_symbols(&sem, &symbols).map_err(|error| error.message)
}

/// Every register read in `expr` names a register that exists.
///
/// Reading a named register by index is the counterpart of `setreg`. A behavior
/// could always *write* one -- an AArch64 link write is
/// `(setreg a64_gpr64 30 ...)` -- and could not read one, so a machine whose
/// kernel reads the register file itself, the way an ADRES mode switch does,
/// had to route the value through an operand and claim the launch supplied it.
///
/// The read is the one an input operand already performs, with the index fixed
/// by the description instead of by decode: same class rules, same zero
/// register, same file offset. So the classes are `setreg`'s classes, from the
/// one table both halves read.
fn validate_register_reads(expr: &SemanticExpr) -> Result<(), String> {
    let SemanticExpr::List(items) = expr else {
        return Ok(());
    };
    if matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "getreg") {
        let [_, SemanticExpr::Atom(kind), SemanticExpr::Atom(index)] = items.as_slice() else {
            return Err("getreg must be `getreg(kind, index)`".to_string());
        };
        if fixed_register_width(kind).is_none() {
            return Err(format!(
                "getreg kind `{kind}` must be a supported register kind"
            ));
        }
        let index = index
            .parse::<u32>()
            .map_err(|_| format!("getreg index must be an integer literal: `{index}`"))?;
        if !fixed_register_index_ok(kind, index) {
            return Err("getreg AArch64 register index must be below 32".to_string());
        }
        return Ok(());
    }
    items.iter().try_for_each(validate_register_reads)
}

/// The symbol a `(getreg kind index)` reads as, once it is a leaf.
fn register_read_symbol(kind: &str, index: u32) -> String {
    format!("__reg_{kind}_{index}")
}

/// `expr` with every register read replaced by its symbol, and the symbols it
/// introduced.
///
/// Two callers need exactly this: the validator, before handing an effect
/// value to the pure IR, and the launch check, before comparing a mapping's
/// composition against the semantics an instruction states. Both are asking
/// what the expression is *around* the reads.
pub fn rewrite_register_reads(expr: &SemanticExpr) -> (SemanticExpr, Vec<String>) {
    let mut reads = Vec::new();
    let rewritten = rewrite_register_reads_into(expr, &mut reads);
    (rewritten, reads)
}

fn rewrite_register_reads_into(expr: &SemanticExpr, reads: &mut Vec<String>) -> SemanticExpr {
    match expr {
        SemanticExpr::List(items) => {
            if let [SemanticExpr::Atom(op), SemanticExpr::Atom(kind), SemanticExpr::Atom(index)] =
                items.as_slice()
            {
                if op == "getreg" {
                    if let Ok(index) = index.parse::<u32>() {
                        let symbol = register_read_symbol(kind, index);
                        reads.push(symbol.clone());
                        return SemanticExpr::Atom(symbol);
                    }
                }
            }
            SemanticExpr::List(
                items
                    .iter()
                    .map(|item| rewrite_register_reads_into(item, reads))
                    .collect(),
            )
        }
        SemanticExpr::Atom(_) => expr.clone(),
    }
}

fn rewrite_input_snapshots(expr: &SemanticExpr) -> SemanticExpr {
    match expr {
        SemanticExpr::List(items) if matches!(items.as_slice(), [SemanticExpr::Atom(op), SemanticExpr::Atom(_)] if op == "input") =>
        {
            let SemanticExpr::Atom(name) = &items[1] else {
                unreachable!()
            };
            SemanticExpr::Atom(format!("__input_{name}"))
        }
        SemanticExpr::List(items) => SemanticExpr::List(
            items
                .iter()
                .map(rewrite_input_snapshots)
                .collect::<Vec<_>>(),
        ),
        SemanticExpr::Atom(_) => expr.clone(),
    }
}

fn parse_statement(statement: &str) -> Result<Effect, String> {
    // `atomic[N] <stmt>` is the canonical bridge syntax emitted by the Lisp
    // frontend. It deliberately wraps an ordinary effect so all backends keep
    // one statement parser and transaction grouping remains orthogonal.
    if let Some(rest) = statement.strip_prefix("atomic[") {
        let (group, inner) = rest
            .split_once("] ")
            .ok_or_else(|| format!("atomic effect must be `atomic[N] <stmt>`: `{statement}`"))?;
        let group = group
            .parse::<u32>()
            .ok()
            .filter(|group| *group != 0)
            .ok_or_else(|| format!("atomic group id must be a positive integer: `{statement}`"))?;
        let mut effect = parse_statement(inner.trim())?;
        if effect.atomic_group != 0 {
            return Err(format!(
                "nested atomic groups are not supported: `{statement}`"
            ));
        }
        effect.atomic_group = group;
        return Ok(effect);
    }
    // `when <cond>: <stmt>` guards an inner statement.
    if let Some(rest) = statement.strip_prefix("when ") {
        let (cond, inner) = rest
            .split_once(':')
            .ok_or_else(|| format!("`when` needs `: <stmt>`: `{statement}`"))?;
        let guard = parse_expr_str(cond.trim())?;
        let mut effect = parse_statement(inner.trim())?;
        if effect.guard.is_some() {
            return Err(format!("nested `when` is not supported: `{statement}`"));
        }
        effect.guard = Some(EffectExpr::untyped(guard));
        return Ok(effect);
    }
    if let Some(rest) = statement.strip_prefix("set ") {
        let (target, expr_src) = rest
            .split_once('=')
            .ok_or_else(|| format!("`set` statement needs `= <expr>`: `{statement}`"))?;
        let target = target.trim();
        if target.is_empty() || !is_ident(target) {
            return Err(format!(
                "`set` target must be an operand name: `{statement}`"
            ));
        }
        return Ok(Effect {
            loc: Loc::Reg(target.to_string()),
            value: EffectExpr::untyped(parse_expr_str(expr_src.trim())?),
            guard: None,
            atomic_group: 0,
        });
    }
    // Otherwise a call statement: `setreg(kind, index, value)` or the
    // explicitly typed `setreg(kind, index, iW, value)`,
    // `setstate(name, value, iW)`, `store(addr, value, iW)`,
    // `barrier(kind, option)`, or
    // `setpc(target)`.
    let expr = parse_expr_str(statement)?;
    if let SemanticExpr::List(items) = &expr {
        match items.first() {
            Some(SemanticExpr::Atom(op)) if op == "setreg" => {
                if !matches!(items.len(), 4 | 5) {
                    return Err(format!(
                        "setreg must be `setreg(kind, index, value)` or `setreg(kind, index, iW, value)`: `{statement}`"
                    ));
                }
                let SemanticExpr::Atom(kind) = &items[1] else {
                    return Err(format!(
                        "setreg kind must be a register-kind identifier: `{statement}`"
                    ));
                };
                let Some(inherent_width) = fixed_register_width(kind) else {
                    return Err(format!(
                        "setreg kind must be a supported register kind: `{statement}`"
                    ));
                };
                let width = if items.len() == 5 {
                    let SemanticExpr::Atom(ty) = &items[3] else {
                        return Err(format!(
                            "setreg explicit width must be an integer type: `{statement}`"
                        ));
                    };
                    let width = ty
                        .strip_prefix('i')
                        .and_then(|width| width.parse::<u32>().ok())
                        .filter(|width| matches!(width, 32 | 64))
                        .ok_or_else(|| {
                            format!("setreg explicit width must be i32 or i64: `{statement}`")
                        })?;
                    if kind != "reg" && width != inherent_width {
                        return Err(format!(
                            "setreg kind `{kind}` requires i{inherent_width}: `{statement}`"
                        ));
                    }
                    width
                } else {
                    inherent_width
                };
                let SemanticExpr::Atom(index) = &items[2] else {
                    return Err(format!(
                        "setreg index must be an integer literal: `{statement}`"
                    ));
                };
                let index = index.parse::<u32>().map_err(|_| {
                    format!("setreg index must be an integer literal: `{statement}`")
                })?;
                if !fixed_register_index_ok(kind, index) {
                    return Err(format!(
                        "setreg AArch64 register index must be below 32: `{statement}`"
                    ));
                }
                return Ok(Effect {
                    loc: Loc::FixedReg {
                        kind: kind.clone(),
                        index,
                        width,
                    },
                    value: EffectExpr::untyped(items[items.len() - 1].clone()),
                    guard: None,
                    atomic_group: 0,
                });
            }
            Some(SemanticExpr::Atom(op)) if op == "setstate" => {
                if items.len() != 4 {
                    return Err(format!(
                        "setstate must be `setstate(name, value, iW)`: `{statement}`"
                    ));
                }
                let SemanticExpr::Atom(name) = &items[1] else {
                    return Err(format!(
                        "setstate name must be an identifier: `{statement}`"
                    ));
                };
                if !is_ident(name) {
                    return Err(format!(
                        "setstate name must be an identifier: `{statement}`"
                    ));
                }
                let width = type_atom_width(&items[3])
                    .ok_or_else(|| format!("setstate width must be `iW`: `{statement}`"))?;
                return Ok(Effect {
                    loc: Loc::State {
                        name: name.clone(),
                        width,
                    },
                    value: EffectExpr::untyped(items[2].clone()),
                    guard: None,
                    atomic_group: 0,
                });
            }
            Some(SemanticExpr::Atom(op)) if matches!(op.as_str(), "store" | "atomic_store") => {
                if !matches!(items.len(), 4 | 5) {
                    return Err(format!(
                        "store must be `store(addr, value, iW[, relaxed|release])`: `{statement}`"
                    ));
                }
                let width = type_atom_width(&items[3])
                    .ok_or_else(|| format!("store width must be `iW`: `{statement}`"))?;
                let order = if items.len() == 5 {
                    parse_memory_order(&items[4])
                        .filter(|order| {
                            matches!(order, MemoryOrder::Relaxed | MemoryOrder::Release)
                        })
                        .ok_or_else(|| {
                            format!("store order must be `relaxed` or `release`: `{statement}`")
                        })?
                } else {
                    MemoryOrder::Relaxed
                };
                return Ok(Effect {
                    loc: Loc::Mem {
                        addr: EffectExpr::untyped(items[1].clone()),
                        width,
                        order,
                        atomic: op == "atomic_store",
                    },
                    value: EffectExpr::untyped(items[2].clone()),
                    guard: None,
                    atomic_group: 0,
                });
            }
            Some(SemanticExpr::Atom(op)) if op == "barrier" => {
                if !(2..=3).contains(&items.len()) {
                    return Err(format!(
                        "barrier must be `barrier({}[, option])`: `{statement}`",
                        BARRIER_KINDS
                            .iter()
                            .map(|kind| kind.name)
                            .collect::<Vec<_>>()
                            .join("|")
                    ));
                }
                let SemanticExpr::Atom(kind) = &items[1] else {
                    return Err(format!(
                        "barrier kind must be a supported architectural barrier: `{statement}`"
                    ));
                };
                let Some(found) = barrier_kind(kind) else {
                    return Err(format!(
                        "barrier kind must be a supported architectural barrier: `{statement}`"
                    ));
                };
                // Whether there is an option to state is the kind's to say.
                // RISC-V's `fence.i` has no option field at all -- it orders
                // instruction fetch against writes, and there is nothing to
                // select -- so requiring one would have meant writing a zero
                // that claims a field the encoding does not have.
                if (found.option_bits == 0) != (items.len() == 2) {
                    return Err(format!(
                        "barrier `{kind}` takes {}: `{statement}`",
                        if found.option_bits == 0 {
                            "no option".to_string()
                        } else {
                            format!("a {}-bit option", found.option_bits)
                        }
                    ));
                }
                return Ok(Effect {
                    loc: Loc::Barrier {
                        kind: kind.clone(),
                        // The kind's own width. This was a literal `4` -- the
                        // fifth place AArch64's `CRm` had been written down as
                        // if it were every architecture's barrier option.
                        width: found.option_bits,
                    },
                    // An optionless barrier still carries a value downstream,
                    // so that nothing between here and the executors has to
                    // spell out the absence; it is zero at zero bits.
                    value: EffectExpr::untyped(match items.get(2) {
                        Some(option) => option.clone(),
                        None => SemanticExpr::Atom("0".to_string()),
                    }),
                    guard: None,
                    atomic_group: 0,
                });
            }
            // ⚠️ `send(port, value, iW)`. Three arguments, like a store, and
            // for the same reason: where it goes, what goes, how wide. An
            // ordering argument is deliberately absent -- a posted message is
            // posted, and an ISA that orders its sends against its stores says
            // so with a `barrier`, which is the effect that already means
            // that. Inventing a second ordering vocabulary here would make two
            // spellings of one architectural fact.
            Some(SemanticExpr::Atom(op)) if op == "send" => {
                if items.len() != 4 {
                    return Err(format!(
                        "send must be `send(port, value, iW)`: `{statement}`"
                    ));
                }
                let width = type_atom_width(&items[3])
                    .ok_or_else(|| format!("send width must be `iW`: `{statement}`"))?;
                return Ok(Effect {
                    loc: Loc::Port {
                        port: EffectExpr::untyped(items[1].clone()),
                        width,
                    },
                    value: EffectExpr::untyped(items[2].clone()),
                    guard: None,
                    atomic_group: 0,
                });
            }
            Some(SemanticExpr::Atom(op)) if op == "setpc" => {
                if items.len() != 2 {
                    return Err(format!("setpc must be `setpc(target)`: `{statement}`"));
                }
                return Ok(Effect {
                    loc: Loc::Pc,
                    value: EffectExpr::untyped(items[1].clone()),
                    guard: None,
                    atomic_group: 0,
                });
            }
            Some(SemanticExpr::Atom(op)) if op == "trap" => {
                if items.len() != 2 {
                    return Err(format!("trap must be `trap(cause)`: `{statement}`"));
                }
                return Ok(Effect {
                    loc: Loc::Trap,
                    value: EffectExpr::untyped(items[1].clone()),
                    guard: None,
                    atomic_group: 0,
                });
            }
            _ => {}
        }
    }
    Err(format!(
        "effect statement must be `set <reg> = <expr>`, `setreg(kind, index[, iW], value)`, `setstate(name, value, iW)`, `store(addr, value, iW)`, `send(port, value, iW)`, `barrier(kind, option)`, `setpc(target)`, `trap(cause)`, or `when <cond>: <stmt>`: `{statement}`"
    ))
}

fn is_ident(text: &str) -> bool {
    let mut chars = text.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

// --- Infix expression parser (produces SemanticExpr) ---

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(String),
    Op(&'static str),
    LParen,
    RParen,
    Comma,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let bytes = src.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_ascii_whitespace() {
            i += 1;
        } else if c == '(' {
            out.push(Tok::LParen);
            i += 1;
        } else if c == ')' {
            out.push(Tok::RParen);
            i += 1;
        } else if c == ',' {
            out.push(Tok::Comma);
            i += 1;
        } else if c == '<' && i + 1 < bytes.len() && bytes[i + 1] == b'<' {
            out.push(Tok::Op("shl"));
            i += 2;
        } else if c == '>' && i + 1 < bytes.len() && bytes[i + 1] == b'>' {
            out.push(Tok::Op("lshr"));
            i += 2;
        } else if c == '=' && i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            out.push(Tok::Op("icmp_eq"));
            i += 2;
        } else if c == '!' && i + 1 < bytes.len() && bytes[i + 1] == b'=' {
            out.push(Tok::Op("icmp_ne"));
            i += 2;
        } else if let Some(op) = single_char_op(c) {
            out.push(Tok::Op(op));
            i += 1;
        } else if c.is_ascii_digit() {
            let start = i;
            while i < bytes.len()
                && ((bytes[i] as char).is_ascii_alphanumeric()
                    || bytes[i] == b'x'
                    || bytes[i] == b'X')
            {
                i += 1;
            }
            out.push(Tok::Int(src[start..i].to_string()));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let start = i;
            while i < bytes.len()
                && ((bytes[i] as char).is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            out.push(Tok::Ident(src[start..i].to_string()));
        } else {
            return Err(format!("unexpected character `{c}` in expression"));
        }
    }
    Ok(out)
}

fn single_char_op(c: char) -> Option<&'static str> {
    match c {
        '+' => Some("add"),
        '-' => Some("sub"),
        '*' => Some("mul"),
        '&' => Some("and"),
        '|' => Some("or"),
        '^' => Some("xor"),
        _ => None,
    }
}

/// Binding power for a binary operator; higher binds tighter. Comparisons bind
/// loosest so `a + b == c` parses as `(a + b) == c`.
fn precedence(op: &str) -> Option<u8> {
    Some(match op {
        "icmp_eq" | "icmp_ne" => 1,
        "or" => 2,
        "xor" => 3,
        "and" => 4,
        "shl" | "lshr" => 5,
        "add" | "sub" => 6,
        "mul" => 7,
        _ => return None,
    })
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

fn parse_expr_str(src: &str) -> Result<SemanticExpr, String> {
    let mut parser = Parser {
        toks: tokenize(src)?,
        pos: 0,
    };
    if parser.toks.is_empty() {
        return Err("empty expression".to_string());
    }
    let expr = parser.expr(0)?;
    if parser.pos != parser.toks.len() {
        return Err(format!("trailing tokens in expression `{src}`"));
    }
    Ok(expr)
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<Tok> {
        let tok = self.toks.get(self.pos).cloned();
        self.pos += 1;
        tok
    }

    fn expr(&mut self, min_bp: u8) -> Result<SemanticExpr, String> {
        let mut lhs = self.primary()?;
        while let Some(Tok::Op(op)) = self.peek() {
            let op = *op;
            let Some(bp) = precedence(op) else { break };
            if bp < min_bp {
                break;
            }
            self.pos += 1;
            let rhs = self.expr(bp + 1)?;
            lhs = SemanticExpr::List(vec![SemanticExpr::Atom(op.to_string()), lhs, rhs]);
        }
        Ok(lhs)
    }

    fn primary(&mut self) -> Result<SemanticExpr, String> {
        match self.bump() {
            Some(Tok::Int(text)) => Ok(SemanticExpr::Atom(text)),
            Some(Tok::LParen) => {
                let inner = self.expr(0)?;
                match self.bump() {
                    Some(Tok::RParen) => Ok(inner),
                    _ => Err("expected `)`".to_string()),
                }
            }
            Some(Tok::Ident(name)) => {
                if matches!(self.peek(), Some(Tok::LParen)) {
                    self.pos += 1; // consume `(`
                    let mut items = vec![SemanticExpr::Atom(name)];
                    if !matches!(self.peek(), Some(Tok::RParen)) {
                        loop {
                            items.push(self.expr(0)?);
                            match self.bump() {
                                Some(Tok::Comma) => continue,
                                Some(Tok::RParen) => break,
                                _ => return Err("expected `,` or `)` in call".to_string()),
                            }
                        }
                    } else {
                        self.pos += 1; // consume `)`
                    }
                    Ok(SemanticExpr::List(items))
                } else {
                    Ok(SemanticExpr::Atom(name))
                }
            }
            other => Err(format!("unexpected token in expression: {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expr(src: &str) -> String {
        render_semexpr(&parse_expr_str(src).unwrap())
    }

    fn typed_behavior(source: &str, operands: &[(&str, u32)]) -> Behavior {
        let mut behavior = parse_behavior(source).unwrap();
        let operands = operands
            .iter()
            .map(|(name, width)| ((*name).to_string(), *width))
            .collect::<Vec<_>>();
        annotate_behavior_widths(&mut behavior, &operands).unwrap();
        behavior
    }

    #[test]
    fn infix_precedence_matches_arithmetic() {
        assert_eq!(expr("rs1 * rs2 + rs3"), "(add (mul rs1 rs2) rs3)");
        assert_eq!(expr("rs1 + rs2 * rs3"), "(add rs1 (mul rs2 rs3))");
        assert_eq!(expr("(rs1 + rs2) * rs3"), "(mul (add rs1 rs2) rs3)");
        assert_eq!(expr("a & b | c"), "(or (and a b) c)");
        assert_eq!(expr("a << 2"), "(shl a 2)");
    }

    #[test]
    fn function_calls_carry_type_and_width_atoms() {
        assert_eq!(expr("sext(i32, 8, rs1)"), "(sext i32 8 rs1)");
        assert_eq!(expr("min(a, b)"), "(min a b)");
        assert_eq!(expr("clz(rs1)"), "(clz rs1)");
        assert_eq!(expr("and(a, not(i32, b))"), "(and a (not i32 b))");
    }

    #[test]
    fn parses_single_register_set() {
        let behavior = parse_behavior("set rd = rs1 * rs2 + rs1").unwrap();
        assert_eq!(behavior.effects.len(), 1);
        assert_eq!(behavior.effects[0].loc, Loc::Reg("rd".to_string()));
        assert_eq!(
            render_semexpr(&behavior.effects[0].value.expr),
            "(add (mul rs1 rs2) rs1)"
        );
    }

    #[test]
    fn memory_accesses_retain_and_validate_ordering() {
        let load = typed_behavior(
            "set rd = load(i64, unsigned, acquire, rn)",
            &[("rd", 64), ("rn", 64)],
        );
        assert_eq!(load.effects[0].value.load_order, MemoryOrder::Acquire);
        validate_behavior(&load, &["rd".into(), "rn".into()], &[]).unwrap();

        let store = typed_behavior("store(rn, rt, i64, release)", &[("rn", 64), ("rt", 64)]);
        assert!(matches!(
            store.effects[0].loc,
            Loc::Mem {
                order: MemoryOrder::Release,
                ..
            }
        ));
        validate_behavior(&store, &["rn".into(), "rt".into()], &[]).unwrap();

        let bad_load = typed_behavior(
            "set rd = load(i64, unsigned, release, rn)",
            &[("rd", 64), ("rn", 64)],
        );
        assert!(validate_behavior(&bad_load, &["rd".into(), "rn".into()], &[]).is_err());
        assert!(parse_behavior("store(rn, rt, i64, acquire)").is_err());
    }

    #[test]
    fn atomic_memory_accesses_retain_atomicity_separately_from_ordering() {
        let load = typed_behavior(
            "set rt = atomic_load(i64, unsigned, relaxed, rn)",
            &[("rt", 64), ("rn", 64)],
        );
        assert!(load.effects[0].value.load_atomic);
        assert_eq!(load.effects[0].value.load_order, MemoryOrder::Relaxed);
        validate_behavior(&load, &["rt".into(), "rn".into()], &[]).unwrap();

        let store = typed_behavior(
            "atomic_store(rn, rs, i64, relaxed)",
            &[("rn", 64), ("rs", 64)],
        );
        assert!(matches!(
            store.effects[0].loc,
            Loc::Mem {
                atomic: true,
                order: MemoryOrder::Relaxed,
                ..
            }
        ));
        validate_behavior(&store, &["rn".into(), "rs".into()], &[]).unwrap();

        let ordinary = typed_behavior(
            "set rt = load(i64, unsigned, rn); store(rn, rs, i64)",
            &[("rt", 64), ("rn", 64), ("rs", 64)],
        );
        assert!(!ordinary.effects[0].value.load_atomic);
        assert!(matches!(
            ordinary.effects[1].loc,
            Loc::Mem { atomic: false, .. }
        ));
    }

    #[test]
    fn validates_atomic_transaction_groups_and_composed_guards() {
        let behavior = typed_behavior(
            "atomic[7] set rs = atomic_load(i64, unsigned, acquire, rn); \
             atomic[7] set rs2 = atomic_load(i64, unsigned, acquire, add(rn, 8)); \
             atomic[7] when and(icmp_eq(rs, input(rs)), icmp_eq(rs2, input(rs2))): \
               atomic_store(rn, rt, i64, release)",
            &[("rs", 64), ("rs2", 64), ("rt", 64), ("rn", 64)],
        );
        validate_behavior(
            &behavior,
            &["rs".into(), "rs2".into(), "rt".into(), "rn".into()],
            &[],
        )
        .unwrap();
        assert!(behavior
            .effects
            .iter()
            .all(|effect| effect.atomic_group == 7));

        let singleton = typed_behavior(
            "atomic[1] set rs = atomic_load(i64, unsigned, relaxed, rn)",
            &[("rs", 64), ("rn", 64)],
        );
        assert!(validate_behavior(&singleton, &["rs".into(), "rn".into()], &[]).is_err());
    }

    #[test]
    fn parses_and_validates_named_state_write() {
        let behavior = typed_behavior(
            "setstate(nzcv, a64_add_nzcv(i64, rn, rm), i4)",
            &[("rn", 64), ("rm", 64)],
        );
        assert_eq!(
            behavior.effects[0].loc,
            Loc::State {
                name: "nzcv".to_string(),
                width: 4
            }
        );
        let symbols = vec!["rn".to_string(), "rm".to_string()];
        validate_behavior(&behavior, &symbols, &[("nzcv".to_string(), 4)]).unwrap();
        let error = validate_behavior(&behavior, &symbols, &[]).unwrap_err();
        assert!(error.contains("state `nzcv:i4` is not declared"));
    }

    #[test]
    fn parses_and_validates_typed_barrier_events() {
        let behavior = typed_behavior("barrier(dmb, option)", &[("option", 4)]);
        assert_eq!(
            behavior.effects[0].loc,
            Loc::Barrier {
                kind: "dmb".to_string(),
                width: 4,
            }
        );
        assert_eq!(behavior.effects[0].value.width, 4);
        assert!(is_effectful(&behavior));
        validate_behavior(&behavior, &["option".to_string()], &[]).unwrap();
        assert!(parse_behavior("barrier(tlb, option)").is_err());
    }

    #[test]
    fn parses_implicit_fixed_register_write() {
        let behavior = typed_behavior("setreg(a64_gpr64, 30, pc + 4)", &[]);
        assert_eq!(
            behavior.effects[0].loc,
            Loc::FixedReg {
                kind: "a64_gpr64".to_string(),
                index: 30,
                width: 64,
            }
        );
        assert!(is_effectful(&behavior));
        validate_behavior(&behavior, &[], &[]).unwrap();
        assert!(parse_behavior("setreg(a64_gpr64, 32, pc + 4)").is_err());

        let generic = typed_behavior("setreg(reg, 30, i64, pc + 4)", &[]);
        assert_eq!(
            generic.effects[0].loc,
            Loc::FixedReg {
                kind: "reg".to_string(),
                index: 30,
                width: 64,
            }
        );
        assert!(parse_behavior("setreg(a64_gpr64, 30, i32, pc + 4)").is_err());
    }

    #[test]
    fn pc_dependent_register_write_remains_effectful() {
        let behavior = parse_behavior("set rd = pc + imm").unwrap();
        assert!(is_effectful(&behavior));
    }

    #[test]
    fn validates_nested_a64_shift_helper() {
        let behavior = typed_behavior(
            "set rd = rn & a64_shift_reg(i64, rm, shift, amount)",
            &[
                ("rd", 64),
                ("rn", 64),
                ("rm", 64),
                ("shift", 2),
                ("amount", 6),
            ],
        );
        assert!(is_effectful(&behavior));
        validate_behavior(
            &behavior,
            &[
                "rd".to_string(),
                "rn".to_string(),
                "rm".to_string(),
                "shift".to_string(),
                "amount".to_string(),
            ],
            &[],
        )
        .unwrap();
    }

    #[test]
    fn validates_a64_bitmask_helpers() {
        let logical = typed_behavior(
            "set rd = rn | a64_wmask(i64, n, immr, imms)",
            &[("rd", 64), ("rn", 64), ("n", 1), ("immr", 6), ("imms", 6)],
        );
        assert!(is_effectful(&logical));
        let symbols = ["rd", "rn", "n", "immr", "imms"]
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        validate_behavior(&logical, &symbols, &[]).unwrap();

        let bitfield = typed_behavior(
            "set rd = a64_bfm(i32, rd, rn, immr, imms)",
            &[("rd", 32), ("rn", 32), ("immr", 6), ("imms", 6)],
        );
        assert!(is_effectful(&bitfield));
        validate_behavior(&bitfield, &symbols, &[]).unwrap();

        let flags = typed_behavior(
            "setstate(nzcv, a64_logic_nzcv(i64, rn & a64_wmask(i64, n, immr, imms)), i4)",
            &[("rn", 64), ("n", 1), ("immr", 6), ("imms", 6)],
        );
        validate_behavior(&flags, &symbols, &[("nzcv".to_string(), 4)]).unwrap();
    }

    #[test]
    fn validates_a64_multiply_high_helpers() {
        let behavior = typed_behavior(
            "set rd = a64_umulh(i64, rn, rm)",
            &[("rd", 64), ("rn", 64), ("rm", 64)],
        );
        validate_behavior(&behavior, &["rd".into(), "rn".into(), "rm".into()], &[]).unwrap();

        let behavior = typed_behavior(
            "set rd = a64_smulh(i64, rn, rm)",
            &[("rd", 64), ("rn", 64), ("rm", 64)],
        );
        validate_behavior(&behavior, &["rd".into(), "rn".into(), "rm".into()], &[]).unwrap();

        let bad = typed_behavior(
            "set rd = a64_umulh(i32, rn, rm)",
            &[("rd", 32), ("rn", 32), ("rm", 32)],
        );
        assert!(validate_behavior(&bad, &["rd".into(), "rn".into(), "rm".into()], &[],).is_err());
    }

    #[test]
    fn rejects_non_set_statement() {
        assert!(parse_behavior("rd = rs1").is_err());
        assert!(parse_behavior("set rd rs1").is_err());
    }
}
