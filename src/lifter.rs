//! Lifting a region of binary code to LLVM IR.
//!
//! What this is, and what it is not. `lift_block` in the generated Python
//! lifter turns a *straight-line run of words the caller supplies* into a
//! dataflow graph, and says so: where blocks begin and end is a fact about a
//! program, not about a machine. This module is the caller that description
//! was waiting for. It takes bytes, decodes them, finds where the blocks are,
//! and writes the region out as LLVM IR with real control flow between them.
//!
//! Three things are deliberately not invented here:
//!
//! * **The decode** comes from the same `layout_for` every other emitter uses,
//!   so an instruction's mask, match, width and operand fields are the ones the
//!   description states rather than a second reading of it.
//! * **The semantics lowering** comes from `emit::llvm`, which already lowers a
//!   `SemanticExpr` to native LLVM instructions and is proven equal to the
//!   golden model over every corpus. This module binds the operands and writes
//!   the results; the arithmetic in between is not lowered twice.
//! * **A branch target** is folded only when it is a closed function of the pc
//!   and the immediates. Anything that reads a register, or uses an operator
//!   the small folder does not know, is *indirect* -- which ends the block at an
//!   exit rather than guessing an edge. Unknown means unknown.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::ast::{Document, Instruction};
use crate::emit::common::{architectural_instructions, layout_for};
use crate::effects::Loc;
use crate::layout::InstructionLayout;
use crate::semantics::SemanticExpr;

/// One decodable encoding, with everything a linear walk needs.
pub struct DecodeRow {
    pub instruction: Instruction,
    pub layout: InstructionLayout,
}

/// The decode table for a description, in the order a linear scan should try.
///
/// Narrower encodings first. A 16-bit instruction's mask covers only the low
/// half of a word, so a 32-bit row can never be confused for it, but the
/// reverse is not true: reading four bytes and testing a 32-bit row first would
/// let a pair of adjacent compressed instructions match something that is not
/// there.
pub struct DecodeTable {
    pub rows: Vec<DecodeRow>,
    /// The machine's width, which the ISA states.
    pub word_bits: u32,
    /// The scalar architectural state this description's ISAs hold, by name.
    pub state_names: Vec<String>,
}

impl DecodeTable {
    pub fn new(document: &Document) -> Self {
        let mut rows: Vec<DecodeRow> = architectural_instructions(document)
            .into_iter()
            .map(|instruction| {
                let layout = layout_for(document, &instruction);
                DecodeRow {
                    instruction,
                    layout,
                }
            })
            .filter(|row| row.layout.mask_value != 0)
            .collect();
        rows.sort_by_key(|row| (row.layout.bits, row.instruction.mnemonic.clone()));
        let word_bits = document
            .isas
            .iter()
            .map(|isa| isa.word_bits)
            .max()
            .unwrap_or(32);
        // The state an ISA holds, carried here so `refusal` can ask whether an
        // effect lowers -- which it answers by trying, and trying needs to know
        // which names are parameters rather than unbound symbols.
        let state_names = crate::effects::isa_scalar_state_names(&document.isas);
        DecodeTable { rows, word_bits, state_names }
    }

    /// The row this word matches, honouring the ISA when one is asked for.
    ///
    /// A word is as many bytes as the row is wide, so the caller passes the
    /// widest window it has and the row says how much of it was consumed.
    pub fn find(&self, word: u32, isa: Option<&str>) -> Option<&DecodeRow> {
        self.rows.iter().find(|row| {
            let width = row.layout.bits;
            let window = if width >= 32 {
                word
            } else {
                word & ((1u32 << width) - 1)
            };
            window & row.layout.mask_value == row.layout.match_value
                && isa.is_none_or(|want| {
                    row.instruction.isa.is_empty() || row.instruction.isa == want
                })
                // ⚠️ And the row's `requires` does not rule the word out. Fixed
                // bits alone put AArch64's FMOV (vector, immediate) inside the
                // fixed-point FCVTZS space -- `immh = 0000` is what separates
                // them, and a `requires` is where the description says so --
                // so the lifter lifted `fmov v.8h, #imm` as a conversion.
                && !crate::validate::decode_constraint_refuses(&row.instruction, &row.layout, window)
        })
    }
}

/// One decoded instruction at an address.
pub struct Decoded<'a> {
    pub addr: u64,
    pub word: u32,
    pub bits: u32,
    pub row: &'a DecodeRow,
    /// Operand name to the value decode extracted, unsigned.
    pub operands: BTreeMap<String, u64>,
}

impl<'a> Decoded<'a> {
    pub fn next_addr(&self) -> u64 {
        self.addr + u64::from(self.bits / 8)
    }
}

/// Pull one operand's value out of a word, stitching scattered fields.
fn extract_operand(word: u32, layout: &InstructionLayout, operand: &str) -> u64 {
    let mut value: u64 = 0;
    for field in layout.operand_bindings(operand) {
        let mask = if field.width >= 32 {
            u32::MAX
        } else {
            (1u32 << field.width) - 1
        };
        let piece = (word >> field.insn_lo) & mask;
        value |= u64::from(piece) << field.op_lo;
    }
    value
}

/// How a block leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Exit {
    /// No terminator: control reaches the next address.
    Fallthrough(u64),
    /// An unconditional direct branch.
    Direct(u64),
    /// A conditional direct branch: taken, and the address after the branch.
    Conditional { taken: u64, not_taken: u64 },
    /// The target is not a closed function of the pc and the immediates -- a
    /// register-held address, or an operator the folder does not know.
    Indirect,
    /// The block ran to the end of the bytes it was given.
    EndOfRegion,
    /// A word no row matched.
    Undecodable(u64),
    /// An instruction LLVM IR cannot express, named with the reason. The block
    /// stops before it: lifting past an instruction whose effect is unknown
    /// would produce a region that runs, and runs something else.
    Declined { addr: u64, reason: String },
}

/// A run of instructions with one entry and one exit.
pub struct Block<'a> {
    pub start: u64,
    pub instructions: Vec<Decoded<'a>>,
    pub exit: Exit,
}

/// A decoded region: its blocks in address order.
pub struct Region<'a> {
    pub base: u64,
    pub blocks: Vec<Block<'a>>,
    /// Addresses a branch named that are outside the bytes supplied.
    pub escapes: BTreeSet<u64>,
}

#[derive(Debug)]
pub struct LiftError {
    pub message: String,
}

impl std::fmt::Display for LiftError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

/// Read one little-endian word of up to four bytes, however many are left.
fn word_at(bytes: &[u8], offset: usize) -> u32 {
    let mut word = 0u32;
    for index in 0..4 {
        if let Some(byte) = bytes.get(offset + index) {
            word |= u32::from(*byte) << (8 * index);
        }
    }
    word
}

/// Fold an expression that should be a closed function of the pc and the
/// immediates, or return `None`.
///
/// This is not an evaluator for the semantics -- it is the question "is this
/// branch target a constant?", and every answer other than a definite yes is
/// `None`. A symbol it cannot resolve, an operator it does not know, a width it
/// cannot represent: all `None`, all meaning *indirect*, which ends the block
/// at an exit instead of drawing an edge that might not be there. Being wrong
/// in that direction costs a block boundary. Being wrong in the other direction
/// invents control flow the program does not have.
fn fold_const(expr: &SemanticExpr, env: &BTreeMap<String, u64>) -> Option<u64> {
    match expr {
        SemanticExpr::Atom(name) => {
            if let Some(value) = env.get(name.as_str()) {
                return Some(*value);
            }
            if let Some(rest) = name.strip_prefix("0x") {
                return u64::from_str_radix(rest, 16).ok();
            }
            name.parse::<u64>().ok()
        }
        SemanticExpr::List(items) => {
            let SemanticExpr::Atom(op) = items.first()? else {
                return None;
            };
            // Most operators carry the width they compute at as a type atom
            // right after the operator -- `(add i64 pc ...)`. It says nothing
            // the fold needs, since a branch target is an address and addresses
            // are 64 bits here, so it is stepped over rather than counted.
            let typed = matches!(items.get(1), Some(SemanticExpr::Atom(atom))
                if is_type_atom(atom));
            let items: Vec<&SemanticExpr> = if typed {
                std::iter::once(&items[0]).chain(items[2..].iter()).collect()
            } else {
                items.iter().collect()
            };
            let arg = |index: usize| fold_const(items.get(index).copied()?, env);
            match (op.as_str(), items.len()) {
                ("add", 3) => Some(arg(1)?.wrapping_add(arg(2)?)),
                ("sub", 3) => Some(arg(1)?.wrapping_sub(arg(2)?)),
                ("mul", 3) => Some(arg(1)?.wrapping_mul(arg(2)?)),
                ("shl", 3) => Some(arg(1)?.wrapping_shl(arg(2)? as u32)),
                ("lshr", 3) => Some(arg(1)?.wrapping_shr(arg(2)? as u32)),
                ("and", 3) => Some(arg(1)? & arg(2)?),
                ("or", 3) => Some(arg(1)? | arg(2)?),
                ("xor", 3) => Some(arg(1)? ^ arg(2)?),
                // `(sext <type> <from-width> <value>)` and the two-argument
                // spelling both appear; the width that matters is the one the
                // value currently has.
                // With the type stepped over, `(sext i64 13 imm)` is
                // `(sext 13 imm)`: the width the value has now, then the value.
                ("sext", 3) => sign_extend(arg(2)?, arg(1)? as u32),
                ("zext", 3) => arg(2),
                _ => None,
            }
        }
    }
}

/// Whether this atom is a width marker rather than a value.
fn is_type_atom(atom: &str) -> bool {
    matches!(atom, "i1" | "i8" | "i16" | "i32" | "i64" | "i128")
}

/// Sign-extend `value` from `width` bits to 64.
fn sign_extend(value: u64, width: u32) -> Option<u64> {
    if width == 0 || width > 64 {
        return None;
    }
    if width == 64 {
        return Some(value);
    }
    let sign = 1u64 << (width - 1);
    let masked = value & ((1u64 << width) - 1);
    Some(if masked & sign != 0 {
        masked | !((1u64 << width) - 1)
    } else {
        masked
    })
}

/// Why this instruction cannot be lowered to LLVM IR, or `None`.
///
/// Both spellings, because a region holds both: an effect list is refused by
/// `emit::llvm`'s own predicate, and a pure `formal_semantics` is refused for
/// the floating-point environment it would need. Neither is a defect -- the
/// same instruction is withheld from `axis_semantics.ll` for the same reason --
/// so a region containing one is lifted up to it and leaves there.
fn refusal(instruction: &Instruction, word_bits: u32, state_names: &[String]) -> Option<String> {
    // A value wider than the machine cannot be *computed* in a block whose one
    // type is the machine's word. RV32 with the D extension is exactly this:
    // 32-bit integers and 64-bit floats in one description, and an effect
    // function may pick its own width per instruction where a region cannot.
    //
    // Moving one is a different question. `ldr q0, [x1]` is 128 bits wide and
    // arithmetic on none of them: the register is two slots in the file and the
    // load is two loads eight bytes apart. `behavior_is_whole_limbs` is exactly
    // that distinction, and `emit::llvm` already asks it -- an instruction it
    // splits into limbs for an effect function is one this can split the same
    // way, so refusing it here withheld eight AArch64 instructions the rest of
    // the toolchain lowers.
    if instruction
        .operands
        .iter()
        .any(|operand| operand.width > word_bits)
    {
        // ⚠️ Limbs of the REGISTER FILE, not of the value. These are not the
        // same number, and on AArch64 they coincide -- a 128-bit V register is
        // two 64-bit slots, and 128/64 is also two -- which is exactly why
        // using the value's width worked there and was wrong. RISC-V's `rv_fpr`
        // holds 64 bits in ONE slot, so on RV32 a 64-bit `fld` is not two limbs
        // of anything: it is a single slot wider than the block's only type,
        // which a region cannot hold. Splitting it into two 32-bit slots wrote
        // the halves into `f0` and `f1` and left the executor holding one
        // 64-bit value in `f0`.
        let limbs_line_up = |operand: &crate::ast::Operand| {
            crate::ast::register_class(&operand.kind).is_some_and(|class| {
                class.limbs >= 2 && operand.width == class.limbs * word_bits
            })
        };
        let whole_limbs = crate::effects::behavior_is_authoritative(instruction)
            && instruction
                .operands
                .iter()
                .filter(|operand| operand.width > word_bits)
                .all(limbs_line_up)
            && instruction.behavior.as_ref().is_some_and(|behavior| {
                behavior_is_whole_limbs(instruction, behavior, llvm_word(word_bits))
            });
        // A PURE value wider than the machine is a different question from a
        // wide move, and gets a different answer. Moving one needs no
        // arithmetic, which is what `behavior_is_whole_limbs` checks; computing
        // one needs arithmetic at that width, which LLVM has and the preamble's
        // `axis_sem<width>_*` helpers already provide. Either way the register
        // file must hold the value in whole machine-word limbs, because that is
        // the boundary the block packs at.
        let pure_at_its_own_width = !crate::effects::behavior_is_authoritative(instruction)
            && !instruction.formal_semantics.trim().is_empty()
            && instruction
                .operands
                .iter()
                .filter(|operand| operand.width > word_bits)
                .all(limbs_line_up);
        if !whole_limbs && !pure_at_its_own_width {
            return Some(format!(
                "an operand wider than the machine's {word_bits} bits, and not \
                 whole limbs of it"
            ));
        }
    }
    // ⚠️ `behavior.is_some()` is not the question -- `behavior_is_authoritative`
    // is. A behavior that is one pure write to the output operand is *promoted*
    // to `formal_semantics` by the parser and left in place, so the instruction
    // carries both and the formal is the authority. Branching on the behavior
    // sent 20 AArch64 instructions -- MADD_X, FABS_D, the FCVTZS and SCVTF
    // families -- down the effect path, where the first thing asked is which of
    // the two is authoritative, and the answer is "not this one".
    if crate::effects::behavior_is_authoritative(instruction) {
        let behavior = instruction.behavior.as_ref()?;
        // An atomic read-modify-write is one LLVM instruction or nothing.
        // `emit::llvm` fuses the two effects that describe it into a single
        // `atomicrmw` or `cmpxchg`; lowering them separately here would emit a
        // load and a store, which is a different operation with the same
        // result on a machine with one thread and the wrong one on any other.
        // ⚠️ The count, not the presence. What cannot be lowered separately is
        // a read-modify-write -- TWO atomic accesses that the machine performs
        // as one transaction. A LONE atomic access is one LLVM instruction that
        // says so, `load atomic` or `store atomic`, and refusing it turned the
        // whole load-reserved family away the moment its descriptions started
        // admitting they were atomic.
        let atomics = behavior
            .effects
            .iter()
            .filter(|effect| {
                effect.value.load_atomic || matches!(effect.loc, Loc::Mem { atomic: true, .. })
            })
            .count();
        let atomic = atomics > 1;
        let fused = atomic
            && llvm_atomic_pair(instruction, behavior, llvm_word(64), None, &mut 0)
                .is_some();
        // A store-conditional is atomic and is not a read-modify-write, so the
        // fusion declines it -- but `lower_store_conditional` does not, and
        // emits the compare-and-swap the fusion would have had no shape for.
        if atomic && !fused && !is_store_conditional(instruction, state_names) {
            // Atomic, and not a shape the fusion recognises. Lowering the two
            // effects separately would emit a load and a store, which is the
            // same answer on a machine with one thread and the wrong one on any
            // other, so it is refused rather than approximated.
            return Some("an atomic access the read-modify-write fusion does not take"
                .to_string());
        }
        // ⚠️ A store that happens only when a guard holds. Elsewhere a guarded
        // write is lowered as a `select` between the new value and the old --
        // which is what a conditional register write is -- but for memory that
        // is a store where the machine performs none, and a store of the same
        // bytes is still a store to anything else watching. It needs a branch,
        // and a block with one entry and one exit has nowhere to put one.
        //
        // This lives here rather than being discovered during lowering because
        // this function claims to be the single place that decides. It was not:
        // `describe_support` called eight store-exclusives `ok` and lifting
        // them then failed, which the per-instruction sweep dropped in silence
        // until it started counting what it could not lift.
        //
        // ⚠️ Only when the fusion did NOT take the instruction. A `cmpxchg`
        // *is* a guarded store -- store if what is there is what we expected --
        // and the compare-and-swap family is written exactly that way, so
        // refusing every guarded store refused 32 instructions that lower
        // correctly as one LLVM instruction.
        // ⚠️ An ATOMIC guarded store, though, is not a masked store.
        // `llvm.masked.store` performs no store when the mask is false, which
        // is exactly what a guard needs, and it is not atomic -- so lowering a
        // guarded atomic store that way would drop the atomicity without
        // saying so. The store-conditionals reach the compare-and-swap instead
        // and never arrive here; anything else is refused with the reason.
        if !fused
            && !is_store_conditional(instruction, state_names)
            && behavior.effects.iter().any(|effect| {
                matches!(effect.loc, Loc::Mem { atomic: true, .. }) && effect.guard.is_some()
            })
        {
            return Some(
                "a guarded atomic store, which a masked store cannot be".to_string(),
            );
        }
        return llvm_effect_refusal(instruction, 64, state_names);
    }
    let semantics = &instruction.formal_semantics;
    if semantics.trim().is_empty() {
        // ⚠️ Three different silences, and they are not the same fact. An
        // instruction that names a routine has an answer this cannot use, one
        // that says `unsupplied` has declared that nobody has an answer, and
        // one that says nothing at all has not been asked yet. A lifter refuses
        // all three, and saying which is the difference between a reader
        // learning something and reading "no semantics declared" 11 times.
        let answer = instruction.implementation.trim();
        if answer == crate::ast::UNSUPPLIED {
            return Some(
                "declared unsupplied: nothing here performs it"
                    .to_string(),
            );
        }
        if !answer.is_empty() {
            return Some(format!(
                "performed by the routine `{answer}`, which only an executor                  can call"
            ));
        }
        return Some("no semantics declared".to_string());
    }
    if crate::emit::semantics::uses_fp_exceptions(semantics) {
        return Some("floating-point exceptions are read from the environment".to_string());
    }
    if semantics.contains("_rm ") {
        return Some("an explicit rounding mode needs the floating-point environment".to_string());
    }
    None
}

/// Where this instruction sends the pc, if anywhere.
///
/// Returns the effect that writes the pc together with whether it is guarded.
/// An instruction with no pc effect falls through, which is the ordinary case
/// and is not a terminator.
fn pc_effect(instruction: &Instruction) -> Option<(&crate::effects::Effect, bool)> {
    let behavior = instruction.behavior.as_ref()?;
    behavior
        .effects
        .iter()
        .find(|effect| matches!(effect.loc, Loc::Pc))
        .map(|effect| (effect, effect.guard.is_some()))
}

/// The exit of a block ending with this instruction.
fn exit_of(decoded: &Decoded) -> Exit {
    let Some((effect, guarded)) = pc_effect(&decoded.row.instruction) else {
        return Exit::Fallthrough(decoded.next_addr());
    };
    // The pc the instruction sees is its own address, and the immediates are
    // whatever decode pulled out. A *register* operand is not a constant: its
    // name stands for the register's contents, not its number, so binding it
    // here would fold `c.jr rd` -- an indirect jump through a register -- into
    // a branch to whatever small integer the register field held.
    let mut env: BTreeMap<String, u64> = decoded
        .operands
        .iter()
        .filter(|(name, _)| {
            decoded
                .row
                .instruction
                .operands
                .iter()
                .find(|operand| &&operand.name == name)
                .is_some_and(|operand| !crate::ast::is_register_kind(&operand.kind))
        })
        .map(|(name, value)| (name.clone(), *value))
        .collect();
    env.insert("pc".to_string(), decoded.addr);
    match fold_const(&effect.value.expr, &env) {
        None => Exit::Indirect,
        Some(target) if guarded => Exit::Conditional {
            taken: target,
            not_taken: decoded.next_addr(),
        },
        Some(target) => Exit::Direct(target),
    }
}

/// Decode a region and cut it into basic blocks.
///
/// Two passes, because a leader can be behind you. The first decodes every
/// instruction in address order and records where the terminators are and what
/// they name; the second cuts at leaders. A leader is the region's first
/// address, the target of any direct branch that lands inside the region, and
/// the address after any terminator.
pub fn decode_region<'a>(
    table: &'a DecodeTable,
    bytes: &[u8],
    base: u64,
    isa: Option<&str>,
) -> Region<'a> {
    let mut decoded: Vec<Decoded<'a>> = Vec::new();
    let mut offset = 0usize;
    let mut undecodable: Option<u64> = None;
    while offset < bytes.len() {
        let addr = base + offset as u64;
        let word = word_at(bytes, offset);
        let Some(row) = table.find(word, isa) else {
            undecodable = Some(addr);
            break;
        };
        let bytes_used = (row.layout.bits / 8) as usize;
        if offset + bytes_used > bytes.len() {
            break;
        }
        let mut operands = BTreeMap::new();
        for operand in &row.instruction.operands {
            if !operand.derived_from.is_empty() {
                continue;               // resolved below, from its parent
            }
            let value = match operand.fixed {
                Some(index) => u64::from(index),
                None => extract_operand(word, &row.layout, &operand.name),
            };
            operands.insert(operand.name.clone(), value);
        }
        // ⚠️ An operand the encoding does NOT carry. `CASP` names a register
        // pair with one field: `rs2` is `rs + 1`, and the instruction word says
        // so only by saying `rs`. `extract_operand` reads bindings, and a
        // derived operand has none, so it answered 0 -- which is a register,
        // and a plausible one, so a paired swap would have written its high
        // half into x0 and looked almost right. Nothing caught it because these
        // sixteen were the only instructions with a derived operand and the
        // lifter refused all of them until the paired fusion landed.
        for operand in &row.instruction.operands {
            if operand.derived_from.is_empty() {
                continue;
            }
            let Some(base) = operands.get(&operand.derived_from).copied() else {
                continue;
            };
            operands.insert(operand.name.clone(), base + u64::from(operand.derived_add));
        }
        decoded.push(Decoded {
            addr,
            word,
            bits: row.layout.bits,
            row,
            operands,
        });
        offset += bytes_used;
    }

    let end = base + offset as u64;
    let starts: BTreeSet<u64> = decoded.iter().map(|one| one.addr).collect();
    let mut leaders: BTreeSet<u64> = BTreeSet::new();
    let mut escapes: BTreeSet<u64> = BTreeSet::new();
    if let Some(first) = decoded.first() {
        leaders.insert(first.addr);
    }
    for one in &decoded {
        if refusal(&one.row.instruction, table.word_bits, &table.state_names).is_some() {
            leaders.insert(one.addr);
            leaders.insert(one.next_addr());
            continue;
        }
        match exit_of(one) {
            Exit::Fallthrough(_) => {}
            Exit::Direct(target) => {
                leaders.insert(one.next_addr());
                if starts.contains(&target) {
                    leaders.insert(target);
                } else {
                    escapes.insert(target);
                }
            }
            Exit::Conditional { taken, not_taken } => {
                leaders.insert(not_taken);
                if starts.contains(&taken) {
                    leaders.insert(taken);
                } else {
                    escapes.insert(taken);
                }
            }
            Exit::Indirect => {
                leaders.insert(one.next_addr());
            }
            Exit::EndOfRegion | Exit::Undecodable(_) | Exit::Declined { .. } => {}
        }
    }
    // A leader past the last instruction is not a block, it is the way out.
    leaders.retain(|addr| starts.contains(addr));

    let mut blocks: Vec<Block<'a>> = Vec::new();
    let mut current: Vec<Decoded<'a>> = Vec::new();
    let mut iter = decoded.into_iter().peekable();
    while let Some(one) = iter.next() {
        if let Some(reason) = refusal(&one.row.instruction, table.word_bits, &table.state_names) {
            // The block before it, if any, ends here; the declined instruction
            // is not lifted and is named as the exit.
            if !current.is_empty() {
                let start = current[0].addr;
                blocks.push(Block {
                    start,
                    instructions: std::mem::take(&mut current),
                    exit: Exit::Declined { addr: one.addr, reason },
                });
            } else {
                blocks.push(Block {
                    start: one.addr,
                    instructions: Vec::new(),
                    exit: Exit::Declined { addr: one.addr, reason },
                });
            }
            continue;
        }
        let ends_here = pc_effect(&one.row.instruction).is_some();
        let next_is_leader = iter
            .peek()
            .is_some_and(|next| leaders.contains(&next.addr));
        let exit = exit_of(&one);
        current.push(one);
        if ends_here || next_is_leader || iter.peek().is_none() {
            let start = current[0].addr;
            let last_exit = if ends_here {
                exit
            } else if let Some(next) = iter.peek() {
                Exit::Fallthrough(next.addr)
            } else if undecodable.is_some() {
                Exit::Undecodable(undecodable.unwrap())
            } else if end == base + bytes.len() as u64 {
                Exit::EndOfRegion
            } else {
                Exit::EndOfRegion
            };
            blocks.push(Block {
                start,
                instructions: std::mem::take(&mut current),
                exit: last_exit,
            });
        }
    }
    Region {
        base,
        blocks,
        escapes,
    }
}

/// A human-readable account of a region's blocks, for checking recovery
/// against a disassembler before anything is lowered.
pub fn describe_region(region: &Region) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "region 0x{:x}: {} block(s)\n",
        region.base,
        region.blocks.len()
    ));
    for block in &region.blocks {
        out.push_str(&format!(
            "bb_{:x}:  ({} instruction(s))\n",
            block.start,
            block.instructions.len()
        ));
        for one in &block.instructions {
            // Only the bytes the instruction occupies: the walk reads a
            // four-byte window whatever the width, and printing the window
            // makes a 16-bit instruction look like it swallowed the next one.
            let shown = if one.bits >= 32 {
                one.word
            } else {
                one.word & ((1u32 << one.bits) - 1)
            };
            out.push_str(&format!(
                "    {:08x}  {:0width$x}  {}\n",
                one.addr,
                shown,
                one.row.instruction.mnemonic,
                width = (one.bits / 4) as usize
            ));
        }
        out.push_str(&match &block.exit {
            Exit::Fallthrough(next) => format!("    -> fallthrough bb_{next:x}\n"),
            Exit::Direct(target) => format!("    -> br bb_{target:x}\n"),
            Exit::Conditional { taken, not_taken } => {
                format!("    -> br taken bb_{taken:x}, else bb_{not_taken:x}\n")
            }
            Exit::Indirect => "    -> indirect (exit)\n".to_string(),
            Exit::EndOfRegion => "    -> end of region (exit)\n".to_string(),
            Exit::Undecodable(addr) => format!("    -> undecodable at 0x{addr:x} (exit)\n"),
            Exit::Declined { addr, reason } => {
                format!("    -> declined at 0x{addr:x}: {reason} (exit)\n")
            }
        });
    }
    if !region.escapes.is_empty() {
        let named: Vec<String> = region
            .escapes
            .iter()
            .map(|addr| format!("0x{addr:x}"))
            .collect();
        out.push_str(&format!("escapes: {}\n", named.join(", ")));
    }
    out
}

// ---------------------------------------------------------------------------
// Lowering a region to LLVM IR.
//
// The block bodies are native instructions, not calls: an `add` in the
// description becomes an `add` here. That lowering is `emit::llvm`'s, driven
// with the operands bound to what decode found, so the arithmetic is not
// written a second time. What this module adds is the part decode makes
// possible and a per-instruction handler cannot have -- the register index is
// a *constant*, so `x5` is a fixed slot rather than a computed one, and the
// control flow between blocks is real `br`, not a pc threaded through a
// scratch array.
// ---------------------------------------------------------------------------

use crate::emit::llvm::{
    behavior_is_whole_limbs, llvm_atomic_pair, llvm_effect_expr, llvm_effect_refusal,
    llvm_effect_value, llvm_fresh, llvm_guard, llvm_limb_access_width, llvm_masked_write,
    llvm_memory_read, llvm_memory_write, llvm_module_preamble, llvm_word, Word,
};

/// Whether this instruction's semantics name a piece of state.
fn mentions(decoded: &Decoded, name: &str) -> bool {
    let hit = |text: &str| {
        text.split(|c: char| !c.is_alphanumeric() && c != '_')
            .any(|token| token == name)
    };
    if hit(&decoded.row.instruction.formal_semantics) {
        return true;
    }
    let Some(behavior) = decoded.row.instruction.behavior.as_ref() else {
        return false;
    };
    behavior.effects.iter().any(|effect| {
        hit(&crate::effects::render_semantic_expr(&effect.value.expr))
            || effect.guard.as_ref().is_some_and(|guard| {
                hit(&crate::effects::render_semantic_expr(&guard.expr))
            })
            || matches!(&effect.loc, Loc::Mem { addr, .. }
                if hit(&crate::effects::render_semantic_expr(&addr.expr)))
    })
}

/// Materialise a constant as an SSA value.
///
/// The lowering resolves a symbol to a *name* and emits `%name`, so binding an
/// immediate to the text of its value produced `%0` -- an SSA reference to
/// nothing, in a module that still parsed as far as the verifier. A constant
/// therefore gets an instruction of its own and the optimizer folds it away
/// immediately, which is the right trade against a module that looks fine and
/// references undefined values.
fn materialize(value: u64, word: Word, body: &mut String, counter: &mut u32) -> String {
    let ty = word.ty;
    let temp = llvm_fresh(counter);
    let masked = if word.bits >= 64 {
        value
    } else {
        value & ((1u64 << word.bits) - 1)
    };
    body.push_str(&format!("  {temp} = add {ty} 0, {masked}\n"));
    temp
}

/// The flat slot an operand's register occupies, decode's index folded in.
pub(crate) fn slot_of(kind: &str, index: u64) -> Option<u64> {
    let class = crate::ast::register_class(kind)?;
    Some(u64::from(class.offset) + (u64::from(class.index_offset) + index) * u64::from(class.limbs.max(1)))
}

/// Bind the operands of a PURE instruction evaluated wider than the machine.
///
/// The block's own type stays the machine word -- its register file, memory
/// pointer and status are all that wide -- and only the value being computed is
/// wider. A register that holds such a value holds it in limbs, so each is read
/// at the machine's width and joined; a narrower operand is read as usual and
/// widened; an immediate is materialised at the evaluation width directly.
///
/// This is the shape the value backends already use: compute at the value's own
/// width and pack at the boundary. The alternative -- carrying the value as
/// limbs through the arithmetic -- is a second representation of a wide number,
/// and the whole-limb path exists only because *moving* one needs no
/// arithmetic at all.
fn bind_operands_wide(
    document: &Document,
    decoded: &Decoded,
    wide: Word,
    machine: Word,
    state_names: &[String],
    body: &mut String,
    counter: &mut u32,
) -> Option<(Vec<String>, HashMap<String, String>)> {
    let mut symbols = Vec::new();
    let mut renames = HashMap::new();
    let widen = |value: &str, body: &mut String, counter: &mut u32| -> String {
        if wide.bits == machine.bits {
            return value.to_string();
        }
        let out = llvm_fresh(counter);
        body.push_str(&format!(
            "  {out} = zext {} {value} to {}\n", machine.ty, wide.ty
        ));
        out
    };
    for operand in &decoded.row.instruction.operands {
        if !operand.input {
            continue;
        }
        let Some(index) = decoded.operands.get(&operand.name) else {
            continue;
        };
        let bound = if crate::ast::is_register_kind(&operand.kind) {
            if operand.width > machine.bits {
                let class = crate::ast::register_class(&operand.kind)?;
                let limbs =
                    read_register_limbs(&operand.kind, *index, class.limbs, machine,
                                        body, counter)?;
                // Low limb first, each shifted into its own place.
                let mut joined = widen(&limbs[0], body, counter);
                for (step, limb) in limbs.iter().enumerate().skip(1) {
                    let part = widen(limb, body, counter);
                    let shifted = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {shifted} = shl {} {part}, {}\n",
                        wide.ty,
                        step as u32 * machine.bits
                    ));
                    let merged = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {merged} = or {} {joined}, {shifted}\n", wide.ty
                    ));
                    joined = merged;
                }
                joined
            } else {
                let read =
                    read_register(document, &operand.kind, *index, machine, body, counter)?;
                widen(&read, body, counter)
            }
        } else {
            materialize(*index, wide, body, counter)
        };
        symbols.push(operand.name.clone());
        renames.insert(operand.name.clone(), bound.trim_start_matches('%').to_string());
    }
    symbols.push("pc".to_string());
    let pc = materialize(decoded.addr, wide, body, counter);
    renames.insert("pc".to_string(), pc.trim_start_matches('%').to_string());
    for (slot, name) in state_names.iter().enumerate() {
        if !mentions(decoded, name) {
            continue;
        }
        let pointer = llvm_fresh(counter);
        let loaded = llvm_fresh(counter);
        body.push_str(&format!(
            "  {pointer} = getelementptr {}, {}* %state, i64 {slot}\n  {loaded} = load {}, {}* {pointer}\n",
            machine.ty, machine.ty, machine.ty, machine.ty
        ));
        let bound = widen(&loaded, body, counter);
        symbols.push(name.clone());
        renames.insert(name.clone(), bound.trim_start_matches('%').to_string());
    }
    Some((symbols, renames))
}

/// A value wider than the machine word, cut into machine-word limbs, low first.
fn split_into_limbs(
    value: &str,
    limbs: u32,
    wide: Word,
    machine: Word,
    body: &mut String,
    counter: &mut u32,
) -> Vec<String> {
    (0..limbs)
        .map(|limb| {
            let source = if limb == 0 {
                value.to_string()
            } else {
                let shifted = llvm_fresh(counter);
                body.push_str(&format!(
                    "  {shifted} = lshr {} {value}, {}\n",
                    wide.ty,
                    limb * machine.bits
                ));
                shifted
            };
            if wide.bits == machine.bits {
                return source;
            }
            let narrowed = llvm_fresh(counter);
            body.push_str(&format!(
                "  {narrowed} = trunc {} {source} to {}\n", wide.ty, machine.ty
            ));
            narrowed
        })
        .collect()
}

/// Lower a store-conditional as a compare-and-swap, or `None`.
///
/// ⚠️ Two consumers, two answers, and this is the translator's. A simulator
/// models the reservation exactly, which is what the descriptions say and what
/// every executor does. A translator wants the store to be *atomic* against
/// other threads, and a masked store is not -- it is a plain store under a
/// mask. So the lifter, whose output is meant to run, emits a `cmpxchg` against
/// the value the reservation captured.
///
/// The two answers differ, deliberately, and only where the architecture is
/// murky: a plain store to the reserved address between the `lr` and the `sc`
/// leaves the monitor valid, so the model stores and the compare-and-swap does
/// not. Single-threaded and without such a store they agree exactly, which is
/// the whole of what the differential sweep can establish -- see the exemption
/// it records rather than passing over.
///
/// A description opts in by recording `exclusive_value`. One that does not gets
/// the exact masked store, which is the only thing in this function that is
/// keyed on a name, and it is the name the description chose to publish.
#[allow(clippy::too_many_arguments)]
/// Is this the store-conditional shape `lower_store_conditional` lowers?
///
/// Asked in two places -- by `refusal`, so the instruction is not turned away
/// as an atomic the read-modify-write fusion declines, and by the lowering
/// itself -- so the shape is described once rather than twice and cannot drift.
fn is_store_conditional(instruction: &Instruction, state_names: &[String]) -> bool {
    let Some(behavior) = instruction.behavior.as_ref() else {
        return false;
    };
    // A description opts in by publishing the slot the reservation captured
    // into. Without it there is nothing to compare against and no swap to make.
    if state_index("exclusive_value", state_names).is_none() {
        return false;
    }
    let [flag, store, ..] = &behavior.effects[..] else {
        return false;
    };
    if !matches!(flag.loc, Loc::Reg(_)) || flag.guard.is_some() {
        return false;
    }
    if !matches!(store.loc, Loc::Mem { .. }) {
        return false;
    }
    let Some(guard) = store.guard.as_ref() else {
        return false;
    };
    // The guard has to be about the reservation, or this is some other guarded
    // store and the masked lowering is the right one.
    let asked = crate::effects::render_semantic_expr(&guard.expr);
    asked.contains("exclusive_address") && asked.contains("exclusive_valid")
}

fn lower_store_conditional(
    document: &Document,
    decoded: &Decoded,
    word: Word,
    state_names: &[String],
    symbols: &[String],
    renames: &HashMap<String, String>,
    body: &mut String,
    counter: &mut u32,
) -> Option<usize> {
    // The shape question is `is_store_conditional`'s to answer, so `refusal`
    // and this lowering cannot come to different conclusions about it.
    if !is_store_conditional(&decoded.row.instruction, state_names) {
        return None;
    }
    let behavior = decoded.row.instruction.behavior.as_ref()?;
    let captured = state_index("exclusive_value", state_names)?;
    let [flag, store, ..] = &behavior.effects[..] else {
        return None;
    };
    let Loc::Reg(dest) = &flag.loc else { return None };
    let Loc::Mem { addr, width, order, .. } = &store.loc else {
        return None;
    };
    let guard = store.guard.as_ref()?;

    let ty = word.ty;
    let holds = llvm_guard(&guard.expr, guard.width, word, symbols, renames, body, counter)?;
    let address = llvm_effect_expr(&addr.expr, addr.width, word, symbols, renames, body, counter)?;
    let desired = llvm_effect_expr(
        &store.value.expr, store.value.width, word, symbols, renames, body, counter,
    )?;

    // What the reservation captured, and -- when it does not hold -- a value
    // memory cannot be holding, so the swap fails without a branch. Reading
    // memory to build that is harmless: the read is discarded and the compare
    // is what decides.
    let slot = llvm_fresh(counter);
    let expected_state = llvm_fresh(counter);
    body.push_str(&format!(
        "  {slot} = getelementptr {ty}, {ty}* %state, i64 {captured}\n  \
{expected_state} = load {ty}, {ty}* {slot}\n"
    ));
    let current = llvm_memory_read(&address, *width, word, body, counter);
    let mismatch = llvm_fresh(counter);
    body.push_str(&format!("  {mismatch} = add {ty} {current}, 1\n"));
    let expected = llvm_fresh(counter);
    body.push_str(&format!(
        "  {expected} = select i1 {holds}, {ty} {expected_state}, {ty} {mismatch}\n"
    ));

    let pointer = crate::emit::llvm::llvm_byte_pointer(&address, *width, word, body, counter);
    let narrow = |value: &str, body: &mut String, counter: &mut u32| -> String {
        if *width == word.bits {
            return value.to_string();
        }
        let out = llvm_fresh(counter);
        body.push_str(&format!("  {out} = trunc {ty} {value} to i{width}\n"));
        out
    };
    let expected = narrow(&expected, body, counter);
    let desired = narrow(&desired, body, counter);
    // ⚠️ The ORDERING the description states, not a fixed strong one. This
    // emitted `acq_rel acquire` for every store-conditional, which was
    // invisible while all four `sc.w` forms were described identically and
    // became a claim the moment they stopped being: a bare `sc.w` carries no
    // ordering, and lifting it to an acquire-release swap promises something
    // the architecture does not. The acquire half of an `lr`/`sc` pair belongs
    // to the `lr`, which lifts on its own as an atomic load that says so.
    //
    // The failure ordering stays `monotonic`: LLVM forbids a release on it,
    // and a swap that did not happen has nothing to release.
    let success = match order {
        crate::effects::MemoryOrder::Release => "release",
        _ => "monotonic",
    };
    let paired = llvm_fresh(counter);
    body.push_str(&format!(
        "  {paired} = cmpxchg i{width}* {pointer}, i{width} {expected}, i{width} {desired} \
{success} monotonic\n"
    ));
    let ok = llvm_fresh(counter);
    body.push_str(&format!(
        "  {ok} = extractvalue {{ i{width}, i1 }} {paired}, 1\n"
    ));
    // ⚠️ Zero means success. Both architectures that have this instruction say
    // so -- RISC-V's `sc` and AArch64's `stxr` -- and the descriptions' own flag
    // effect computes the same polarity from the monitor. Taking it from the
    // swap rather than from the monitor is the point: under concurrency the
    // monitor can hold while the swap loses.
    let flag_value = llvm_fresh(counter);
    body.push_str(&format!(
        "  {flag_value} = select i1 {ok}, {ty} 0, {ty} 1\n"
    ));
    let index = decoded.operands.get(dest)?;
    let operand = decoded
        .row
        .instruction
        .operands
        .iter()
        .find(|operand| &operand.name == dest)?;
    if !discards(&operand.kind, *index) {
        write_register(document, &operand.kind, *index, &flag_value, word, body, counter)?;
    }
    Some(2)
}

/// The limbs of a register wider than the machine word, low limb first.
///
/// A 128-bit V register is two slots in the file, and a region whose one type
/// is the machine word has no way to hold it whole. It does not need one: the
/// only instructions that reach here move it, so each limb travels on its own.
fn read_register_limbs(
    kind: &str,
    index: u64,
    limbs: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> Option<Vec<String>> {
    let slot = slot_of(kind, index)?;
    Some(
        (0..u64::from(limbs))
            .map(|limb| load_slot(slot + limb, word, body, counter))
            .collect(),
    )
}

/// Put `values` into a register wider than the machine word, low limb first.
///
/// Every limb is written, so a class whose policy is `Zero` is satisfied by
/// construction -- there is no "rest" left over to clear.
fn write_register_limbs(
    kind: &str,
    index: u64,
    values: &[String],
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> Option<()> {
    let slot = slot_of(kind, index)?;
    for (limb, value) in values.iter().enumerate() {
        store_slot(slot + limb as u64, value, word, body, counter);
    }
    Some(())
}

/// `base + limb * <slot bytes>`, as IR -- the address limb `limb` lives at.
fn limb_address(
    base: &str,
    limb: usize,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    if limb == 0 {
        return base.to_string();
    }
    let bumped = llvm_fresh(counter);
    body.push_str(&format!(
        "  {bumped} = add {} {base}, {}\n",
        word.ty,
        limb as u64 * u64::from(word.bits / 8)
    ));
    bumped
}

/// Whether writes to this register are discarded (a hardwired zero).
fn discards(kind: &str, index: u64) -> bool {
    crate::ast::register_class(kind)
        .and_then(|class| class.zero_index)
        .is_some_and(|zero| u64::from(zero) == index)
}

/// Where a class's named state lives in `%state`, if it aliases one.
fn state_index(name: &str, state_names: &[String]) -> Option<usize> {
    state_names.iter().position(|held| held == name)
}

/// The slot an aliased index uses: one past the register file.
///
/// The executor keeps AArch64's `sp` under a *name* in its register map rather
/// than at an index, because encoding 31 means `sp` for some classes and the
/// zero register for others -- and file slot 31 belongs to whichever class
/// actually numbers 31. Putting it in `%state` instead gave one register two
/// homes: the region wrote `%state`, the executor wrote its map, and a store
/// through `sp` addressed a four-billion-byte offset that took the process
/// down. It goes one slot past the file, which is what `jit_llvm.py` settled on
/// for the same collision.
fn alias_slot(document: &Document) -> u64 {
    u64::from(crate::ast::register_file_slots(document))
}

/// Emit a load of one `%state` slot.
fn load_state(index: usize, word: Word, body: &mut String, counter: &mut u32) -> String {
    let ty = word.ty;
    let pointer = llvm_fresh(counter);
    let loaded = llvm_fresh(counter);
    body.push_str(&format!(
        "  {pointer} = getelementptr {ty}, {ty}* %state, i64 {index}\n  {loaded} = load {ty}, {ty}* {pointer}\n"
    ));
    loaded
}

/// Emit a store into one `%state` slot.
fn store_state(index: usize, value: &str, word: Word, body: &mut String, counter: &mut u32) {
    let ty = word.ty;
    let pointer = llvm_fresh(counter);
    body.push_str(&format!(
        "  {pointer} = getelementptr {ty}, {ty}* %state, i64 {index}\n  store {ty} {value}, {ty}* {pointer}\n"
    ));
}

/// Read an architectural register the way its class says to.
///
/// The same rules `_read_reg` applies in the executor, and for the same reason:
/// which index is hardwired to zero, which index names state instead of the
/// file, and how much of the register this class can see are facts the class
/// table holds. A region knows the index at lift time, so each of these is
/// decided here rather than tested at run time.
fn read_register(
    document: &Document,
    kind: &str,
    index: u64,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> Option<String> {
    let class = crate::ast::register_class(kind)?;
    if class.zero_index == Some(index as u32) {
        return Some(materialize(0, word, body, counter));
    }
    if let Some((aliased, name)) = class.alias {
        if aliased as u64 == index {
            // The view applies to an alias too: AArch64 reads W-SP as the low
            // 32 bits of the same `sp` the 64-bit class reads whole.
            let _ = name;
            let held = load_slot(alias_slot(document), word, body, counter);
            return Some(match class.view_width {
                None => held,
                Some(width) => narrow(&held, class.view_offset, width, word, body, counter),
            });
        }
    }
    let limbs = u64::from(class.limbs.max(1));
    let slot = u64::from(class.offset) + (u64::from(class.index_offset) + index) * limbs;
    let Some(view) = class.view_width else {
        return Some(load_slot(slot, word, body, counter));
    };
    // A view need not start at the low bit, and in a register held as several
    // limbs it need not stay inside one. The limb it starts in is the offset
    // divided by the slot width.
    let low = slot + u64::from(class.view_offset) / u64::from(word.bits);
    let shift = u64::from(class.view_offset) % u64::from(word.bits);
    let whole = load_slot(low, word, body, counter);
    let mut value = narrow(&whole, shift as u32, view.min(word.bits), word, body, counter);
    if shift != 0 && shift + u64::from(view) > u64::from(word.bits) {
        // The rest of it comes from the next limb.
        let high = load_slot(low + 1, word, body, counter);
        let taken = shift + u64::from(view) - u64::from(word.bits);
        let masked = narrow(&high, 0, taken as u32, word, body, counter);
        let lifted = llvm_fresh(counter);
        body.push_str(&format!(
            "  {lifted} = shl {} {masked}, {}\n",
            word.ty,
            u64::from(word.bits) - shift
        ));
        let joined = llvm_fresh(counter);
        body.push_str(&format!("  {joined} = or {} {value}, {lifted}\n", word.ty));
        value = joined;
    }
    Some(value)
}

/// `(value >> shift) & ((1 << width) - 1)`, as IR.
fn narrow(
    value: &str,
    shift: u32,
    width: u32,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let ty = word.ty;
    let mut current = value.to_string();
    if shift != 0 {
        let shifted = llvm_fresh(counter);
        body.push_str(&format!("  {shifted} = lshr {ty} {current}, {shift}\n"));
        current = shifted;
    }
    if width < word.bits {
        let mask = (1u128 << width) - 1;
        let masked = llvm_fresh(counter);
        body.push_str(&format!("  {masked} = and {ty} {current}, {mask}\n"));
        current = masked;
    }
    current
}

/// Emit a load of a register slot, returning the SSA temp holding it.
fn load_slot(slot: u64, word: Word, body: &mut String, counter: &mut u32) -> String {
    let ty = word.ty;
    let pointer = llvm_fresh(counter);
    let loaded = llvm_fresh(counter);
    body.push_str(&format!(
        "  {pointer} = getelementptr {ty}, {ty}* %regs, i64 {slot}\n  {loaded} = load {ty}, {ty}* {pointer}\n"
    ));
    loaded
}

/// Emit a store into a register slot.
fn store_slot(slot: u64, value: &str, word: Word, body: &mut String, counter: &mut u32) {
    let ty = word.ty;
    let pointer = llvm_fresh(counter);
    body.push_str(&format!(
        "  {pointer} = getelementptr {ty}, {ty}* %regs, i64 {slot}\n  store {ty} {value}, {ty}* {pointer}\n"
    ));
}

/// Write an architectural register the way its class says to.
///
/// The mirror of `read_register`, and the half that has a *policy*: what
/// happens to the bits a narrow view does not cover is the architecture's
/// choice, not a detail. Writing AArch64's `w0` zeroes the upper half of `x0`;
/// writing x86's `al` preserves the upper 56 bits of `rax`. The class says
/// which, so this reads it rather than picking one.
#[allow(clippy::too_many_arguments)]
fn write_register(
    document: &Document,
    kind: &str,
    index: u64,
    value: &str,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> Option<()> {
    let class = crate::ast::register_class(kind)?;
    if class.zero_index == Some(index as u32) {
        return Some(());                      // hardwired zero discards writes
    }
    let ty = word.ty;
    if let Some((aliased, name)) = class.alias {
        if aliased as u64 == index {
            let _ = name;
            let slot = alias_slot(document);
            let stored = match class.view_width {
                None => value.to_string(),
                Some(view) => {
                    let held = load_slot(slot, word, body, counter);
                    insert(&held, value, class.view_offset, view, class.write_policy,
                           word, body, counter)
                }
            };
            store_slot(slot, &stored, word, body, counter);
            return Some(());
        }
    }
    let limbs = u64::from(class.limbs.max(1));
    let slot = u64::from(class.offset) + (u64::from(class.index_offset) + index) * limbs;
    let Some(view) = class.view_width else {
        store_slot(slot, value, word, body, counter);
        return Some(());
    };
    // "The rest becomes zero" is a statement about the register, and the rest
    // can be a whole limb away.
    if matches!(class.write_policy, crate::ast::WritePolicy::Zero) {
        let zero = materialize(0, word, body, counter);
        for limb in 0..limbs {
            store_slot(slot + limb, &zero, word, body, counter);
        }
    }
    let low = slot + u64::from(class.view_offset) / u64::from(word.bits);
    let shift = u64::from(class.view_offset) % u64::from(word.bits);
    let held = load_slot(low, word, body, counter);
    let merged = insert(&held, value, shift as u32, view.min(word.bits),
                        class.write_policy, word, body, counter);
    store_slot(low, &merged, word, body, counter);
    if shift != 0 && shift + u64::from(view) > u64::from(word.bits) {
        let taken = shift + u64::from(view) - u64::from(word.bits);
        let high = load_slot(low + 1, word, body, counter);
        let spilled = llvm_fresh(counter);
        body.push_str(&format!(
            "  {spilled} = lshr {ty} {value}, {}\n",
            u64::from(word.bits) - shift
        ));
        let merged = insert(&high, &spilled, 0, taken as u32, class.write_policy,
                            word, body, counter);
        store_slot(low + 1, &merged, word, body, counter);
    }
    Some(())
}

/// Put `value` into `held` at `shift..shift+width`, keeping or clearing the
/// rest as the policy says.
fn insert(
    held: &str,
    value: &str,
    shift: u32,
    width: u32,
    policy: crate::ast::WritePolicy,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> String {
    let ty = word.ty;
    let cover: u128 = if width >= word.bits {
        (1u128 << word.bits) - 1
    } else {
        ((1u128 << width) - 1) << shift
    };
    let fitted = narrow(value, 0, width, word, body, counter);
    let placed = if shift == 0 {
        fitted
    } else {
        let shifted = llvm_fresh(counter);
        body.push_str(&format!("  {shifted} = shl {ty} {fitted}, {shift}\n"));
        shifted
    };
    // A zeroing class has already cleared the register, so there is nothing to
    // keep and the placed value is the whole answer.
    if matches!(policy, crate::ast::WritePolicy::Zero) {
        return placed;
    }
    let keep = llvm_fresh(counter);
    let mask = ((1u128 << word.bits) - 1) & !cover;
    body.push_str(&format!("  {keep} = and {ty} {held}, {mask}\n"));
    let joined = llvm_fresh(counter);
    body.push_str(&format!("  {joined} = or {ty} {keep}, {placed}\n"));
    joined
}

/// Bind an instruction's operands to what decode found.
///
/// A register operand becomes a load of its slot -- a *constant* slot, because
/// the encoding is known -- and an immediate becomes a literal. This is the
/// whole reason a lifted block is better code than a handler call: the handler
/// takes the register number as an argument and computes where to look, while
/// here the address is folded before the optimizer ever sees it.
fn bind_operands(
    document: &Document,
    decoded: &Decoded,
    word: Word,
    state_names: &[String],
    body: &mut String,
    counter: &mut u32,
) -> (Vec<String>, HashMap<String, String>) {
    let mut symbols = Vec::new();
    let mut renames = HashMap::new();
    for operand in &decoded.row.instruction.operands {
        if !operand.input {
            continue;
        }
        let Some(value) = decoded.operands.get(&operand.name) else {
            continue;
        };
        // A register wider than the machine word has no single value to bind
        // -- it is limbs, and the one shape that reads one here reads those
        // limbs itself. Binding the low limb under the whole register's name
        // would be half an answer wearing a whole one's label, so it is left
        // unbound and anything that reaches for it fails to lower.
        if crate::ast::is_register_kind(&operand.kind) && operand.width > word.bits {
            continue;
        }
        symbols.push(operand.name.clone());
        if crate::ast::is_register_kind(&operand.kind) {
            // A hardwired zero reads as zero however it is encoded, which is a
            // fact about the class and so is folded here rather than loaded.
            let Some(bound) =
                read_register(document, &operand.kind, *value, word, body, counter)
            else {
                continue;
            };
            renames.insert(operand.name.clone(), bound.trim_start_matches('%').to_string());
        } else {
            let bound = materialize(*value, word, body, counter);
            renames.insert(operand.name.clone(), bound.trim_start_matches('%').to_string());
        }
    }
    symbols.push("pc".to_string());
    let pc = materialize(decoded.addr, word, body, counter);
    renames.insert("pc".to_string(), pc.trim_start_matches('%').to_string());
    // Architectural state the instruction reads -- RISC-V's `frm`, AArch64's
    // `nzcv`. Loaded here for the same reason a register is: the expression
    // lowering resolves the name to whatever SSA value holds it now.
    let ty = word.ty;
    for (slot, name) in state_names.iter().enumerate() {
        if !mentions(decoded, name) {
            continue;
        }
        let pointer = llvm_fresh(counter);
        let loaded = llvm_fresh(counter);
        body.push_str(&format!(
            "  {pointer} = getelementptr {ty}, {ty}* %state, i64 {slot}\n  {loaded} = load {ty}, {ty}* {pointer}\n"
        ));
        symbols.push(name.clone());
        renames.insert(name.clone(), loaded.trim_start_matches('%').to_string());
    }
    (symbols, renames)
}

/// Lower one instruction's effects into the block being built.
///
/// The pc effect is not lowered here: where control goes is the block's
/// terminator, and a block has exactly one. Everything else -- register writes,
/// stores, state -- lands inline.
fn lower_instruction(
    document: &Document,
    decoded: &Decoded,
    word: Word,
    state_names: &[String],
    body: &mut String,
    counter: &mut u32,
) -> Result<(Vec<String>, HashMap<String, String>), LiftError> {
    // The same question as `refusal` asks, and it has to be the same question:
    // an instruction whose behavior was promoted to `formal_semantics` is a
    // pure value, and the effect path would refuse it for saying so.
    if !crate::effects::behavior_is_authoritative(&decoded.row.instruction) {
        // A pure instruction states its result as `formal_semantics` with one
        // implicit destination rather than as effects.
        return lower_pure(document, decoded, word, state_names, body, counter);
    }
    let behavior = decoded
        .row
        .instruction
        .behavior
        .as_ref()
        .expect("an authoritative behavior is a behavior");
    // The same refusal `emit-llvm-ir` applies, asked before anything is
    // lowered: an instruction it withholds a function for is one this cannot
    // express either, and finding that out during lowering means a panic.
    if let Some(reason) = llvm_effect_refusal(&decoded.row.instruction, 64, state_names) {
        return Err(LiftError {
            message: format!("{}: {reason}", decoded.row.instruction.mnemonic),
        });
    }
    // Every read of this instruction happens before every write of it. When the
    // caller has already bound the operands -- which it does for the terminator,
    // whose target has to be computed from the values the instruction *read* --
    // those bindings are used rather than fresh loads.
    let (symbols, renames) = bind_operands(document, decoded, word, state_names, body, counter);
    let (mut symbols, mut renames) = (symbols, renames);
    let mut skip = 0usize;
    // A store-conditional first: the translator's answer is a compare-and-swap
    // against the value the reservation captured, which is atomic where a
    // masked store is not. Consumes the flag write and the store; the
    // reservation clear after them lowers normally.
    if let Some(consumed) = lower_store_conditional(
        document, decoded, word, state_names, &symbols, &renames, body, counter,
    ) {
        skip = consumed;
    }
    // An atomic read-modify-write is one LLVM instruction, and `emit::llvm`
    // already knows how to build it. Driven with this region's bindings, so the
    // operands are the SSA values the block loaded rather than parameters.
    // More than one atomic access is the read-modify-write the fusion owns; a
    // lone one lowers as itself, the same rule `refusal` applies.
    if skip == 0
        && behavior
            .effects
            .iter()
            .filter(|effect| {
                effect.value.load_atomic || matches!(effect.loc, Loc::Mem { atomic: true, .. })
            })
            .count()
            > 1
    {
        let fused = llvm_atomic_pair(
            &decoded.row.instruction,
            behavior,
            word,
            Some((&symbols, &renames)),
            counter,
        )
        .ok_or_else(|| LiftError {
            message: format!(
                "{}: an atomic access the fusion does not take",
                decoded.row.instruction.mnemonic
            ),
        })?;
        body.push_str(&fused.body);
        // Every register the transaction leaves behind. `CASP` leaves two --
        // the pair it swapped -- so this is a loop rather than one write.
        for (dest, value) in &fused.writes {
            let operand = decoded
                .row
                .instruction
                .operands
                .iter()
                .find(|operand| &operand.name == dest);
            if let (Some(operand), Some(index)) = (operand, decoded.operands.get(dest)) {
                if !discards(&operand.kind, *index) {
                    write_register(document, &operand.kind, *index, value, word,
                                   body, counter)
                        .ok_or_else(|| LiftError {
                            message: format!(
                                "{}: `{}` cannot be written here",
                                decoded.row.instruction.mnemonic, operand.kind
                            ),
                        })?;
                    // Later effects read what this one wrote -- the monitor
                    // writes that follow `LDXP`'s loads do not, but the rule is
                    // the same one the unfused path follows.
                    renames.insert(
                        dest.clone(),
                        value.trim_start_matches('%').to_string(),
                    );
                }
            }
        }
        // ⚠️ A fusion may consume only a PREFIX. `CASP` is the whole
        // instruction and returns here; `LDXP` is its two loads, and the three
        // effects after them are the exclusive monitor -- ordinary state this
        // function already writes. Returning regardless emitted the loads and
        // dropped the monitor, which is a lifted `ldxp` leaving no trace a
        // `stxp` could test.
        if fused.consumed >= behavior.effects.len() {
            return Ok((symbols, renames));
        }
        skip = fused.consumed;
    }
    for effect in behavior.effects.iter().skip(skip) {
        if matches!(effect.loc, Loc::Pc) {
            continue;
        }
        // A guarded effect happens only when its condition holds. Rather than
        // branch inside the block -- which would split it and lose the one
        // entry, one exit shape -- the value is selected, which is what a
        // conditional write is: the old value or the new one.
        let guard = match &effect.guard {
            None => None,
            Some(guard) => Some(
                llvm_guard(
                    &guard.expr, guard.width, word, &symbols, &renames, body, counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: a guard is not lowerable",
                        decoded.row.instruction.mnemonic
                    ),
                })?,
            ),
        };
        match &effect.loc {
            Loc::Reg(dest) => {
                let operand = decoded
                    .row
                    .instruction
                    .operands
                    .iter()
                    .find(|operand| &operand.name == dest);
                let Some(operand) = operand else {
                    return Err(LiftError {
                        message: format!(
                            "{}: writes `{dest}`, which is not an operand",
                            decoded.row.instruction.mnemonic
                        ),
                    });
                };
                let Some(index) = decoded.operands.get(dest) else {
                    return Err(LiftError {
                        message: format!(
                            "{}: `{dest}` is not an encoded operand",
                            decoded.row.instruction.mnemonic
                        ),
                    });
                };
                if discards(&operand.kind, *index) {
                    continue;
                }
                // Wider than the machine word means limbs, and the only shape
                // that reaches here is a plain load of exactly the register's
                // width -- `behavior_is_whole_limbs` allows nothing else. So
                // `ldr q0, [x1]` is two loads eight bytes apart into two slots,
                // with no extend and no mask: a whole limb needs neither.
                if operand.width > word.bits {
                    let SemanticExpr::List(items) = &effect.value.expr else {
                        return Err(LiftError {
                            message: format!(
                                "{}: a wide register write is not a load",
                                decoded.row.instruction.mnemonic
                            ),
                        });
                    };
                    let wide = || LiftError {
                        message: format!(
                            "{}: a wide load is not lowerable",
                            decoded.row.instruction.mnemonic
                        ),
                    };
                    let access = items
                        .get(1)
                        .and_then(|atom| llvm_limb_access_width(atom, word))
                        .ok_or_else(wide)?;
                    // The file's limbs, not the value's words: `refusal` has
                    // already required the two to agree, and this asks the same
                    // source it did rather than recomputing from the width.
                    let limbs = crate::ast::register_class(&operand.kind)
                        .filter(|class| class.limbs >= 2
                            && access == class.limbs * word.bits)
                        .ok_or_else(wide)?
                        .limbs as usize;
                    let base = llvm_effect_expr(
                        items.last().ok_or_else(wide)?,
                        effect.value.load_address_width.ok_or_else(wide)?,
                        word, &symbols, &renames, body, counter,
                    )
                    .ok_or_else(wide)?;
                    if guard.is_some() {
                        return Err(LiftError {
                            message: format!(
                                "{}: a guarded wide load needs its own block",
                                decoded.row.instruction.mnemonic
                            ),
                        });
                    }
                    let loaded: Vec<String> = (0..limbs)
                        .map(|limb| {
                            let address =
                                limb_address(&base, limb, word, body, counter);
                            llvm_memory_read(&address, word.bits, word, body, counter)
                        })
                        .collect();
                    write_register_limbs(
                        &operand.kind, *index, &loaded, word, body, counter,
                    )
                    .ok_or_else(|| LiftError {
                        message: format!(
                            "{}: `{}` cannot be written here",
                            decoded.row.instruction.mnemonic, operand.kind
                        ),
                    })?;
                    continue;
                }
                let value = llvm_effect_value(
                    effect, operand.width, word, &symbols, &renames, body, counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: a value is not lowerable",
                        decoded.row.instruction.mnemonic
                    ),
                })?;
                let value = guarded(
                    document, value, guard, &operand.kind, *index, word, body,
                    counter,
                )?;
                write_register(document, &operand.kind, *index, &value, word, body, counter)
                    .ok_or_else(|| LiftError {
                        message: format!(
                            "{}: `{}` cannot be written here",
                            decoded.row.instruction.mnemonic, operand.kind
                        ),
                    })?;
                // Later effects of this instruction read what this one wrote.
                renames.insert(
                    dest.clone(),
                    value.trim_start_matches('%').to_string(),
                );
            }
            Loc::Mem { addr, width, .. } => {
                // The mirror of the wide load. The value is a plain register
                // read -- `behavior_is_whole_limbs` allows nothing else here --
                // so each limb goes to its own eight bytes.
                if *width > word.bits {
                    let SemanticExpr::Atom(name) = &effect.value.expr else {
                        return Err(LiftError {
                            message: format!(
                                "{}: a wide store is not a register read",
                                decoded.row.instruction.mnemonic
                            ),
                        });
                    };
                    let wide = || LiftError {
                        message: format!(
                            "{}: a wide store is not lowerable",
                            decoded.row.instruction.mnemonic
                        ),
                    };
                    let source = decoded
                        .row
                        .instruction
                        .operands
                        .iter()
                        .find(|operand| &operand.name == name)
                        .ok_or_else(wide)?;
                    let index = decoded.operands.get(name).ok_or_else(wide)?;
                    let base = llvm_effect_expr(
                        &addr.expr, addr.width, word, &symbols, &renames, body, counter,
                    )
                    .ok_or_else(wide)?;
                    if guard.is_some() {
                        return Err(LiftError {
                            message: format!(
                                "{}: a guarded wide store needs its own block",
                                decoded.row.instruction.mnemonic
                            ),
                        });
                    }
                    let count = crate::ast::register_class(&source.kind)
                        .filter(|class| class.limbs >= 2
                            && *width == class.limbs * word.bits)
                        .ok_or_else(wide)?
                        .limbs;
                    let limbs = read_register_limbs(
                        &source.kind, *index, count, word, body, counter,
                    )
                    .ok_or_else(wide)?;
                    for (limb, value) in limbs.iter().enumerate() {
                        let address = limb_address(&base, limb, word, body, counter);
                        llvm_memory_write(
                            &address, value, word.bits, word, body, counter,
                        );
                    }
                    continue;
                }
                let address = llvm_effect_expr(
                    &addr.expr, addr.width, word, &symbols, &renames, body, counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: a store address is not lowerable",
                        decoded.row.instruction.mnemonic
                    ),
                })?;
                let value = llvm_effect_expr(
                    &effect.value.expr, effect.value.width, word, &symbols, &renames,
                    body, counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: a stored value is not lowerable",
                        decoded.row.instruction.mnemonic
                    ),
                })?;
                // ⚠️ A guarded store needs no block. `llvm.masked.store` with a
                // false mask performs NO store, which is exactly a store that
                // does not happen -- unlike reading the old value and selecting,
                // which writes the same bytes back, and a store of the same
                // bytes is still a store to anything else watching. A branch
                // would be exact too and needs a block this one-entry, one-exit
                // shape has nowhere to put. Sixteen store-conditionals were
                // refused for wanting one.
                match guard {
                    None => llvm_memory_write(&address, &value, *width, word, body, counter),
                    Some(condition) => llvm_masked_write(
                        &address, &value, *width, &condition, word, body, counter,
                    ),
                }
            }
            Loc::FixedReg { kind, index, .. } => {
                // A register the instruction writes without naming it in an
                // operand -- AArch64 BL's link register. The index is in the
                // description, so the slot is as constant as any other.
                if discards(kind, u64::from(*index)) {
                    continue;
                }
                let value = llvm_effect_value(
                    effect, effect.value.width, word, &symbols, &renames, body, counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: a fixed-register value is not lowerable",
                        decoded.row.instruction.mnemonic
                    ),
                })?;
                let value = guarded(
                    document, value, guard, kind, u64::from(*index), word, body,
                    counter,
                )?;
                write_register(document, kind, u64::from(*index), &value, word, body,
                               counter)
                    .ok_or_else(|| LiftError {
                        message: format!(
                            "{}: fixed register `{kind}` cannot be written",
                            decoded.row.instruction.mnemonic
                        ),
                    })?;
            }
            Loc::State { name, width } => {
                let Some(index) = state_names.iter().position(|held| held == name) else {
                    return Err(LiftError {
                        message: format!(
                            "{}: writes state `{name}`, which this region does not carry",
                            decoded.row.instruction.mnemonic
                        ),
                    });
                };
                let value = llvm_effect_value(
                    effect, effect.value.width, word, &symbols, &renames, body, counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: a state value is not lowerable",
                        decoded.row.instruction.mnemonic
                    ),
                })?;
                let ty = word.ty;
                // ⚠️ Masked to the STATE's width, not the value's. RISC-V's
                // `frm` is three bits; a `csrrw` writing it stored the whole
                // register and the executor stored the low three, so the two
                // disagreed by everything above them. `emit::llvm` masked here
                // all along -- this path did not, and nothing compared
                // architectural state until the exclusive monitor needed it to.
                let value = {
                    let masked = llvm_fresh(counter);
                    body.push_str(&format!(
                        "  {masked} = call {ty} @{}mask({ty} {value}, {ty} {width})\n",
                        word.prefix
                    ));
                    masked
                };
                let pointer = llvm_fresh(counter);
                body.push_str(&format!(
                    "  {pointer} = getelementptr {ty}, {ty}* %state, i64 {index}\n"
                ));
                let value = match guard {
                    None => value,
                    Some(condition) => {
                        let old = llvm_fresh(counter);
                        body.push_str(&format!("  {old} = load {ty}, {ty}* {pointer}\n"));
                        let chosen = llvm_fresh(counter);
                        body.push_str(&format!(
                            "  {chosen} = select i1 {condition}, {ty} {value}, {ty} {old}\n"
                        ));
                        chosen
                    }
                };
                body.push_str(&format!("  store {ty} {value}, {ty}* {pointer}\n"));
            }
            // ⚠️ A barrier that orders memory is EMITTED. It used to be
            // dropped, on the reasoning that the region does not reorder --
            // true of the region and beside the point, because the region is
            // compiled and run on a real machine that does, against threads
            // the region knows nothing about. A lifted `fence` that emits
            // nothing is a lifted `fence` that does not fence. The barriers
            // that order the pipeline rather than memory still emit nothing,
            // for the reason `fence_ordering` gives: LLVM has no way to say
            // what they mean, and a memory fence would claim something else.
            // ⚠️ Refused, not skipped. A binary lifter that dropped a message
            // would hand back IR for a program that communicates, with the
            // communication missing -- which reads as a correct lift of a
            // different program. There is no LLVM spelling for a channel, so
            // this says so where the caller can see it.
            Loc::Port { .. } => {
                return Err(LiftError {
                    message: format!(
                        "{}: posts a message, which has no LLVM spelling",
                        decoded.row.instruction.mnemonic
                    ),
                })
            }
            Loc::Barrier { kind, .. } => {
                if let Some(ordering) = crate::emit::llvm::fence_ordering(kind) {
                    body.push_str(&format!("  fence {ordering}\n"));
                }
            }
            // A trap is an exit the caller decides about; it writes no value.
            Loc::Trap => {}
            Loc::Pc => unreachable!("the pc effect is the terminator"),
            Loc::Mem { .. } | Loc::Reg(_) => unreachable!("handled above"),
        }
    }
    Ok((symbols, renames))
}

/// A guarded write stores the new value or keeps the old one. Selecting rather
/// than branching keeps the block's one-entry-one-exit shape, and a select is
/// what a conditional register write is.
#[allow(clippy::too_many_arguments)]
fn guarded(
    document: &Document,
    value: String,
    guard: Option<String>,
    kind: &str,
    index: u64,
    word: Word,
    body: &mut String,
    counter: &mut u32,
) -> Result<String, LiftError> {
    let Some(condition) = guard else {
        return Ok(value);
    };
    // The old value read the class's way, so a narrow write that does not fire
    // leaves exactly what a narrow read would have returned.
    let old = read_register(document, kind, index, word, body, counter)
        .ok_or_else(|| LiftError {
            message: format!("`{kind}` cannot be read for a guarded write"),
        })?;
    let chosen = llvm_fresh(counter);
    body.push_str(&format!(
        "  {chosen} = select i1 {condition}, {} {value}, {} {old}\n",
        word.ty, word.ty
    ));
    Ok(chosen)
}

/// Lower a pure instruction: one destination, one expression.
///
/// A description states most arithmetic this way -- `formal_semantics` with an
/// `:out` operand -- rather than as an effect list, and the region needs both
/// spellings because a real block interleaves them.
fn lower_pure(
    document: &Document,
    decoded: &Decoded,
    word: Word,
    state_names: &[String],
    body: &mut String,
    counter: &mut u32,
) -> Result<(Vec<String>, HashMap<String, String>), LiftError> {
    let semantics = &decoded.row.instruction.formal_semantics;
    if semantics.is_empty() {
        return Ok((Vec::new(), HashMap::new()));
    }
    // Anything this cannot write is refused, not passed over. A silent skip
    // leaves a block that runs and computes less than the program did, which is
    // the one outcome worse than refusing: it looks like agreement.
    let destination = decoded
        .row
        .instruction
        .operands
        .iter()
        .find(|operand| operand.output && crate::ast::is_register_kind(&operand.kind));
    let Some(destination) = destination else {
        return Err(LiftError {
            message: format!(
                "{}: semantics with no register destination",
                decoded.row.instruction.mnemonic
            ),
        });
    };
    let Some(index) = decoded.operands.get(&destination.name) else {
        return Err(LiftError {
            message: format!(
                "{}: `{}` is not an encoded operand",
                decoded.row.instruction.mnemonic, destination.name
            ),
        });
    };
    // A hardwired zero discards the write, which is the architecture and not a
    // gap: nothing is emitted and nothing is missing.
    if discards(&destination.kind, *index) {
        return Ok((Vec::new(), HashMap::new()));
    }
    // ⚠️ The width the VALUE is, which need not be the width the block is. A
    // 128-bit vector operation cannot be carried in a machine word, and it does
    // not have to be: LLVM has `i128`, the preamble already carries the
    // `axis_sem128_*` helpers, and the register file holds the value in whole
    // machine-word limbs. So the block computes at the value's width and packs
    // only at the file, which is what every value backend already does -- and
    // is not the same as carrying the value AS limbs through the arithmetic,
    // which would be a second representation of a wide number.
    let widest = decoded
        .row
        .instruction
        .operands
        .iter()
        .map(|operand| operand.width)
        .chain(std::iter::once(destination.width))
        .max()
        .unwrap_or(word.bits);
    let expr = crate::semantics::parse_formal_semantics(semantics).map_err(|err| LiftError {
        message: format!("{}: {}", decoded.row.instruction.mnemonic, err.message),
    })?;
    let not_lowerable = || LiftError {
        message: format!(
            "{}: semantics are not lowerable",
            decoded.row.instruction.mnemonic
        ),
    };
    let cannot_write = || LiftError {
        message: format!(
            "{}: `{}` cannot be written here",
            decoded.row.instruction.mnemonic, destination.kind
        ),
    };
    if widest > word.bits {
        let wide = llvm_word(widest);
        let (symbols, renames) = bind_operands_wide(
            document, decoded, wide, word, state_names, body, counter,
        )
        .ok_or_else(not_lowerable)?;
        let value = llvm_effect_expr(
            &expr, destination.width, wide, &symbols, &renames, body, counter,
        )
        .ok_or_else(not_lowerable)?;
        // ⚠️ Computed wide does not mean WRITTEN wide. `ADDP_D` reads a 128-bit
        // register and writes a 64-bit one -- a view of the same class, whose
        // policy zeroes the rest of it. Splitting that answer into limbs put
        // the bits above the value into the register's high slot, where the
        // executor had put the zero the policy demands. A destination the
        // machine word can hold goes through the ordinary write, which knows
        // about views and policies; only a wider one is written as limbs.
        if destination.width <= word.bits {
            let narrowed = llvm_fresh(counter);
            body.push_str(&format!(
                "  {narrowed} = trunc {} {value} to {}\n", wide.ty, word.ty
            ));
            write_register(document, &destination.kind, *index, &narrowed, word,
                           body, counter)
                .ok_or_else(cannot_write)?;
            return Ok((symbols, renames));
        }
        let class =
            crate::ast::register_class(&destination.kind).ok_or_else(cannot_write)?;
        let limbs = split_into_limbs(&value, class.limbs, wide, word, body, counter);
        write_register_limbs(&destination.kind, *index, &limbs, word, body, counter)
            .ok_or_else(cannot_write)?;
        return Ok((symbols, renames));
    }
    let (symbols, renames) = bind_operands(document, decoded, word, state_names, body, counter);
    let value = llvm_effect_expr(
        &expr, destination.width, word, &symbols, &renames, body, counter,
    )
    .ok_or_else(not_lowerable)?;
    write_register(document, &destination.kind, *index, &value, word, body,
                   counter)
        .ok_or_else(cannot_write)?;
    Ok((symbols, renames))
}

/// Lift a decoded region to a self-contained LLVM module.
///
/// The module carries the semantics helpers the lowered arithmetic calls, so a
/// consumer can hand it straight to a JIT without linking a second file. One
/// function per region:
///
/// ```text
/// define void @axis_region_<base>(iW* %regs, i8* %mem, iW* %status, iW* %state)
/// ```
///
/// `%status` receives the address control left from and how many instructions
/// ran. Every way out of the region -- an indirect branch, a branch to an
/// address outside the bytes supplied, running off the end -- returns, with the
/// address it was leaving for in `%status[0]`. That is the honest shape: the
/// region is what the caller supplied, and anything past it is the caller's to
/// decide about.
/// Lift a decoded region to a self-contained LLVM module, **one function per
/// basic block**.
///
/// The block is the unit, not the region. A region's blocks were joined with
/// real `br` edges once, and per-instruction checking showed the joins were
/// where it went wrong: every AArch64 instruction lifted alone agreed with the
/// executor, and a region of several did not. Edges are also the part a lifter
/// has least right to be confident about -- a target folded from the pc and an
/// immediate is a guess about a program, where an instruction's semantics are a
/// fact about a machine.
///
/// So each block is its own function:
///
/// ```text
/// define void @axis_block_<addr>(iW* %regs, i8* %mem, iW* %status, iW* %state)
/// ```
///
/// It runs the block's instructions and stores in `%status[0]` the address
/// control goes to next -- a folded branch target, a computed indirect one, or
/// the address after the block. Where to go next is then the caller's, which is
/// what `lift_block` said all along: where blocks begin and end, and which
/// branch is taken, are facts about a program.
///
/// The module carries the semantics helpers the lowered arithmetic calls, so a
/// consumer can hand it straight to a JIT without linking a second file.
pub fn lift_region(
    document: &Document,
    region: &Region,
    isa: Option<&str>,
) -> Result<String, LiftError> {
    let mut out = String::new();
    out.push_str(&lift_preamble(document));
    out.push_str(&lift_blocks(document, region, isa)?);
    Ok(out)
}

/// The part of a lifted module that does not depend on the bytes: the
/// semantics helpers the lowered arithmetic calls, at each width the
/// description uses.
///
/// Split out because it is thirty thousand lines for AArch64 and identical for
/// every region. A consumer lifting a binary emits this once and appends each
/// region's blocks to it; `lift_region` is the two together, for a caller that
/// wants one self-contained module and does not care.
pub fn lift_preamble(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("; Generated by AXIS. A region of binary code, lifted by block.\n");
    out.push_str("; schema: axis.lifted-blocks.v1\n\n");
    out.push_str(&llvm_module_preamble(document));
    // ⚠️ The window, defined here as all-ones. A lifted block's loads and
    // stores go through the same helper every other lowered access does, and
    // that helper masks -- so the symbol has to exist. All-ones is the
    // identity, which is right: a lifted region is IR for a consumer to
    // compile, not bytes about to run against a host's buffer, and inventing
    // a bound it never asked for would change the program.
    out.push_str(crate::emit::llvm::AXIS_MEMORY_MASK_DEFINITION);
    out
}

/// The block functions for a region, and nothing else.
///
/// Appending these to `lift_preamble` gives exactly what `lift_region`
/// returns; appending several regions' worth gives one module holding all of
/// them, which is what a consumer lifting more than one region wants.
pub fn lift_blocks(
    document: &Document,
    region: &Region,
    isa: Option<&str>,
) -> Result<String, LiftError> {
    let _ = isa;
    let bits = region_word_bits(document, region);
    let word = llvm_word(bits);
    let ty = word.ty;
    let state_names = crate::effects::isa_scalar_state_names(&document.isas);
    let mut out = String::new();

    for block in &region.blocks {
        let mut body = String::new();
        let mut counter = 0u32;
        let mut terminator_bindings = None;
        for one in &block.instructions {
            terminator_bindings = Some(lower_instruction(
                document, one, word, &state_names, &mut body, &mut counter,
            )?);
        }
        let after = block
            .instructions
            .last()
            .map(|one| one.next_addr())
            .unwrap_or(block.start);
        // Where control goes, as a value rather than an edge.
        let next = match &block.exit {
            Exit::Fallthrough(target) | Exit::Direct(target) => {
                materialize(*target, word, &mut body, &mut counter)
            }
            Exit::EndOfRegion | Exit::Undecodable(_) => {
                materialize(after, word, &mut body, &mut counter)
            }
            Exit::Declined { addr, .. } => {
                materialize(*addr, word, &mut body, &mut counter)
            }
            Exit::Conditional { taken, not_taken } => {
                // Both arms are addresses, so the choice is a `select`. A block
                // that ends in one instruction and one answer needs no branch
                // of its own, and the caller gets the address either way.
                let branch = block.instructions.last().unwrap();
                let (symbols, renames) = terminator_bindings.clone().unwrap_or_else(|| {
                    bind_operands(document, branch, word, &state_names, &mut body,
                                  &mut counter)
                });
                let (effect, _) = pc_effect(&branch.row.instruction)
                    .ok_or_else(|| LiftError {
                        message: "a conditional exit with no pc effect".to_string(),
                    })?;
                let guard = effect.guard.as_ref().ok_or_else(|| LiftError {
                    message: "a conditional exit with no guard".to_string(),
                })?;
                let condition = llvm_guard(
                    &guard.expr, guard.width, word, &symbols, &renames, &mut body,
                    &mut counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: a branch condition is not lowerable",
                        branch.row.instruction.mnemonic
                    ),
                })?;
                let yes = materialize(*taken, word, &mut body, &mut counter);
                let no = materialize(*not_taken, word, &mut body, &mut counter);
                let chosen = llvm_fresh(&mut counter);
                body.push_str(&format!(
                    "  {chosen} = select i1 {condition}, {ty} {yes}, {ty} {no}\n"
                ));
                chosen
            }
            Exit::Indirect => {
                // Not foldable is not unknowable: the target is a register the
                // instruction names, so it is computed here.
                let branch = block.instructions.last().unwrap();
                let (symbols, renames) = terminator_bindings.clone().unwrap_or_else(|| {
                    bind_operands(document, branch, word, &state_names, &mut body,
                                  &mut counter)
                });
                let (effect, _) = pc_effect(&branch.row.instruction)
                    .ok_or_else(|| LiftError {
                        message: "an indirect exit with no pc effect".to_string(),
                    })?;
                let target = llvm_effect_expr(
                    &effect.value.expr, effect.value.width, word, &symbols, &renames,
                    &mut body, &mut counter,
                )
                .ok_or_else(|| LiftError {
                    message: format!(
                        "{}: an indirect target is not lowerable",
                        branch.row.instruction.mnemonic
                    ),
                })?;
                match &effect.guard {
                    None => target,
                    Some(guard) => {
                        let condition = llvm_guard(
                            &guard.expr, guard.width, word, &symbols, &renames,
                            &mut body, &mut counter,
                        )
                        .ok_or_else(|| LiftError {
                            message: format!(
                                "{}: an indirect guard is not lowerable",
                                branch.row.instruction.mnemonic
                            ),
                        })?;
                        let fallthrough = materialize(after, word, &mut body,
                                                      &mut counter);
                        let chosen = llvm_fresh(&mut counter);
                        body.push_str(&format!(
                            "  {chosen} = select i1 {condition}, {ty} {target}, {ty} {fallthrough}\n"
                        ));
                        chosen
                    }
                }
            }
        };
        body.push_str(&format!("  store {ty} {next}, {ty}* %status\n  ret void\n"));
        out.push_str(&format!(
            "define void @axis_block_{:x}({ty}* %regs, i8* %mem, {ty}* %status, {ty}* %state) {{\nentry:\n{body}}}\n\n",
            block.start
        ));
    }
    Ok(out)
}

/// The width a region computes at: the machine's, which the ISA states.
///
/// Not the widest operand in the region. RV32 with the D extension has 64-bit
/// floating-point registers and is still a 32-bit machine, and lowering its
/// integer arithmetic at 64 bits produced `zext i64 %t to i64` -- a cast from a
/// type to itself, which LLVM refuses to parse. The machine width is a fact the
/// description states, so it is read rather than inferred.
fn region_word_bits(document: &Document, region: &Region) -> u32 {
    let _ = region;
    document
        .isas
        .iter()
        .map(|isa| isa.word_bits)
        .max()
        .unwrap_or(32)
}

/// What a region lifter can and cannot take from this description.
///
/// One line per instruction: the mnemonic, then `ok` or the reason it is
/// refused. Asked once for the whole description rather than once per
/// instruction, which is the difference between a gate that runs in a second
/// and one that spawns nine hundred processes to learn the same thing.
pub fn describe_support(document: &Document) -> String {
    let table = DecodeTable::new(document);
    let mut out = String::new();
    // Acceptance is not a correctness claim. This says what the lowering will
    // attempt, and a differential gate says whether the attempt is right. Only
    // the corpora with a gate in `check_all.py` have been asked -- RV64I,
    // RV32I, and the two effect corpora. AArch64 is accepted here in part and
    // is known to diverge; see docs/lifter_design.md section 7.
    out.push_str("# accepted here, proven only where a gate says so\n");
    for row in &table.rows {
        match refusal(&row.instruction, table.word_bits, &table.state_names) {
            None => out.push_str(&format!("{}\tok\n", row.instruction.mnemonic)),
            Some(reason) => {
                out.push_str(&format!("{}\t{reason}\n", row.instruction.mnemonic))
            }
        }
    }
    out
}
