//! The SIMT core family (docs/simt_design.md): what the validator and the
//! engine's emitter must agree on, in one place so they cannot disagree.

use crate::ast::{Core, Document, Instruction};

/// The warp-level roles an instruction can be bound to, and what each does
/// with the state its instruction's behavior wrote in every active lane.
///
/// | role | per lane, from the behavior | the warp |
/// |---|---|---|
/// | `tmc` | `simt_arg`: the new mask | mask <- the last active lane's `simt_arg`; zero ends the warp |
/// | `wspawn` | `simt_arg` count, `simt_arg2` pc | warps 1..count-1 start at pc, lane 0 active |
/// | `split` | `simt_pred`; `simt_token` -> rd | lanes split by predicate; if both groups are non-empty, push and run one |
/// | `join` | `simt_arg`: a token | token below the stack depth: run the other group, or pop |
/// | `pred` | `simt_pred`, `simt_arg` | mask <- predicated lanes, or `simt_arg` when none remain |
/// | `bar` | `simt_arg` id, `simt_arg2` count | wait until `count` warps reach barrier `id` |
/// | `wsync` | -- | wait until everything this warp issued has completed |
pub const ROLES: &[&str] = &["tmc", "wspawn", "split", "join", "pred", "bar", "wsync"];

/// The state slots a role reads from its lanes, which the ISA must declare.
/// ⚠️ Checked, not assumed: a behavior that writes a slot the ISA does not
/// declare is a parse error, and a role that reads one nothing writes would
/// read zero on every lane -- a JOIN that never pops, quietly.
pub fn required_state(role: &str) -> &'static [&'static str] {
    match role {
        "tmc" | "join" => &["simt_arg"],
        "wspawn" | "bar" => &["simt_arg", "simt_arg2"],
        "split" => &["simt_pred", "simt_token"],
        "pred" => &["simt_pred", "simt_arg"],
        _ => &[],
    }
}

/// Whether a role's instructions must have a behavior. Every role but
/// `wsync` reads what its lanes computed, and an instruction with no behavior
/// computes nothing.
pub fn role_needs_behavior(role: &str) -> bool {
    role != "wsync"
}

/// The ISAs a SIMT core decodes, in the order a word is tried.
pub fn core_isas(core: &Core) -> Vec<String> {
    match &core.simt {
        Some(simt) if !simt.isas.is_empty() => simt.isas.clone(),
        _ if !core.implements.is_empty() => vec![core.implements.clone()],
        _ => Vec::new(),
    }
}

/// The unit classes a SIMT core may declare when its instructions name none.
pub const UNIT_CLASSES: &[&str] = &["alu", "fpu", "lsu", "sfu"];

/// Which unit executes `instruction` on a SIMT core.
///
/// ⚠️ DERIVED when the instruction names no unit, which is every instruction
/// of a corpus written before anyone timed it (the AArch64 seed names none):
/// a memory access is `lsu`; an operand in a register file other than a
/// general one (`a64_vreg`, `rv_fpr`: FP and SIMD) is `fpu`; a warp-control or
/// system-register instruction is `sfu`, which is where SIMT machines put
/// them; everything else is `alu`. A declared `unit` always wins.
pub fn unit_class(document: &Document, core: &Core, instruction: &Instruction) -> String {
    if !instruction.unit.trim().is_empty() {
        return instruction.unit.to_ascii_lowercase();
    }
    if let Some(simt) = &core.simt {
        let bound = simt
            .warp_control
            .iter()
            .flat_map(|(_, m)| m.iter())
            .chain(simt.sysread.as_ref().map(|r| &r.mnemonic))
            .any(|m| m.eq_ignore_ascii_case(&instruction.mnemonic));
        if bound {
            return "sfu".to_string();
        }
    }
    let _ = document;
    let (loads, stores) = memory_ops(instruction);
    // A cross-lane instruction's loads read the other lanes, not memory.
    let crosslane = core.simt.as_ref().and_then(|s| s.vector.as_ref()).is_some_and(|v| {
        v.crosslane.iter().any(|m| m.eq_ignore_ascii_case(&instruction.mnemonic))
    });
    if (loads || stores) && !crosslane {
        return "lsu".to_string();
    }
    let other_file = instruction.operands.iter().any(|operand| {
        crate::ast::register_class(&operand.kind).is_some_and(|class| !is_general_file(class.file))
    });
    if other_file {
        "fpu".to_string()
    } else {
        "alu".to_string()
    }
}

/// The unit an instruction issues to on a core that is not SIMT: the one it
/// names, else derived from what it does -- `lsu` if it touches memory, `fpu`
/// if it names a register outside the general file, `alu` otherwise. The
/// same rule `unit_class` applies on a SIMT core, without that core's own
/// control instructions, so the pack pipeline and the SIMT engine charge an
/// instruction that names no unit to the same kind of unit (U4c: the study's
/// AArch64 instructions name none, and a pack core could declare no units at
/// all, which left its memory issue unlimited beside a SIMT core's two LSUs).
pub fn derived_unit_class(instruction: &Instruction) -> &'static str {
    let (loads, stores) = memory_ops(instruction);
    if loads || stores {
        return "lsu";
    }
    let other_file = instruction.operands.iter().any(|operand| {
        crate::ast::register_class(&operand.kind).is_some_and(|class| !is_general_file(class.file))
    });
    if other_file { "fpu" } else { "alu" }
}

/// A general-purpose register file, by the names AXIS gives them: `reg`
/// (AArch64 and the generic classes), `rv_gpr`, `x86_gpr`. ⚠️ Not `file !=
/// "reg"`: that was the first rule, and it sent every RISC-V integer
/// instruction to the FPU -- the gate's NARROW invariant measured +0 cycles
/// on an ALU it never reached.
pub fn is_general_file(file: &str) -> bool {
    file == "reg" || file.ends_with("gpr")
}

/// Whether an instruction's behavior reads memory and whether it writes it.
pub fn memory_ops(instruction: &Instruction) -> (bool, bool) {
    use crate::effects::{expr_reads_memory, Loc};
    let Some(behavior) = instruction.behavior.as_ref() else { return (false, false) };
    let mut loads = false;
    let mut stores = false;
    for effect in &behavior.effects {
        if let Loc::Mem { addr, .. } = &effect.loc {
            stores = true;
            if expr_reads_memory(&addr.expr) {
                loads = true;
            }
        }
        if expr_reads_memory(&effect.value.expr)
            || effect.guard.as_ref().is_some_and(|g| expr_reads_memory(&g.expr))
        {
            loads = true;
        }
    }
    (loads, stores)
}

/// The instructions of `isas`, by mnemonic, case-insensitively.
pub fn find_instruction<'a>(document: &'a Document, isas: &[String], mnemonic: &str) -> Option<&'a Instruction> {
    document.instructions.iter().find(|instruction| {
        instruction.mnemonic.eq_ignore_ascii_case(mnemonic)
            && isas.iter().any(|isa| instruction.isa.eq_ignore_ascii_case(isa))
    })
}
