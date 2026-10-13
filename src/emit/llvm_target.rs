//! AXIS emit: a self-contained LLVM target tree.
//!
//! `emit_tablegen` emits a *patch into the RISC-V backend*: every instruction
//! inherits `RVInst`, allocates RISC-V's `GPR`, and is encoded from the flat
//! `opcode`/`func3`/`func7` sugar rather than from the format layout the
//! proven encoder uses. It cannot stand alone and it describes non-RISC-V
//! corpora wrongly.
//!
//! This emits a target: its own registers, its own register classes, its own
//! instruction formats, encoded from `InstructionLayout` — the same layout
//! `emit-encode` uses and `roundtrip_check` proves. LLVM's own generators
//! (`--gen-register-info`, `--gen-instr-info`, `--gen-emitter`,
//! `--gen-disassembler`, `--gen-asm-writer`) run over the result, and what
//! `--gen-emitter` produces is checked against AXIS's encoder.

use super::common::*;
use crate::effects::Loc;
use super::llvm::{
    emit_immediate_predicates, immediate_predicate, immediate_predicate_of,
    immediate_predicate_scaled, llvm_pattern_dag, llvm_store_pattern_dag, operand_root_width,
    llvm_atomic_rmw_pattern_dag, llvm_indexed_store_pattern_dag, narrowing_register_leaf,
    widening_register_extension, ImmediatePredicate,
    scaled_immediates, scaled_store_immediates, selector_specializations,
    semantic_extensions_of,
};

/// How many commutative nodes a selection pattern may contain. TableGen
/// enumerates every commutation, so this bounds the generators' work at 2^N.
const COMMUTATIVE_PATTERN_LIMIT: usize = 6;

/// The namespace and def prefix for a document's target.
fn target_name(document: &Document) -> String {
    tablegen_ident(&document.extension.name).to_uppercase()
}

/// The ISAs this document describes as *optional*: every one that is not the
/// machine always present.
///
/// A document can describe more than one ISA -- the AArch64 seed carries the
/// architecture and the accelerator it lowers to -- and they are not peers.
/// One of them is the machine that is always there; the rest are present only
/// on a subtarget that has them, which is what LLVM calls a feature. The
/// decoder already treats an ISA as a namespace for the same reason.
///
/// Which one is always there is said by the translation role when a document
/// gives one: a `source` ISA is what is being compiled *for*, and a `target`
/// ISA is the accelerator it lowers *to*. Failing that it is the first
/// declared -- `fp_scalar` names two float widths with no role between them,
/// and something has to be unconditional or the target has no instructions at
/// all without a feature.
fn base_isa(document: &Document) -> Option<&crate::ast::Isa> {
    document
        .isas
        .iter()
        .find(|isa| isa.role == "source")
        .or_else(|| document.isas.first())
}

fn feature_isas(document: &Document) -> Vec<&crate::ast::Isa> {
    let base = base_isa(document).map(|isa| isa.name.as_str());
    document
        .isas
        .iter()
        .filter(|isa| Some(isa.name.as_str()) != base)
        .collect()
}

/// The `Predicate` name gating an instruction, if its ISA is an optional one.
fn isa_predicate(document: &Document, isa: &str) -> Option<String> {
    feature_isas(document)
        .into_iter()
        .find(|candidate| candidate.name == isa)
        .map(|candidate| format!("Has{}", tablegen_ident(&candidate.name)))
}

/// Declare each optional ISA as a subtarget feature and a predicate over it.
fn emit_subtarget_features(out: &mut String, document: &Document) {
    let features = feature_isas(document);
    if features.is_empty() {
        return;
    }
    out.push_str("//===- Subtarget features ------------------------------===//\n\n");
    for isa in &features {
        let ident = tablegen_ident(&isa.name);
        out.push_str(&format!(
            "def Feature{ident} : SubtargetFeature<\"{}\", \"has{ident}\", \"true\",\n\
             {:width$}\"{} ({}), {}-bit\">;\n\
             def Has{ident} : Predicate<\"Subtarget->has{ident}()\">;\n\n",
            isa.name,
            "",
            isa.name,
            if isa.role.is_empty() { "no role" } else { &isa.role },
            isa.word_bits,
            width = 4,
        ));
    }
}

/// A register file: the classes that share one `offset` in the flat file.
/// AArch64's X and W views are one file; RISC-V's x and f are two.
struct RegisterFile {
    offset: u32,
    /// Widest first — the widest is the physical register, the rest are
    /// sub-register views of it.
    classes: Vec<&'static RegisterClass>,
}

/// The architectural width a class exposes.
fn class_width(class: &RegisterClass) -> u32 {
    class.view_width.unwrap_or(class.limbs * 64)
}

/// The widest value this document puts in a class, for the frame's spill
/// geometry (F4). Exposed rather than duplicated: "how wide is this class
/// *here*" is a question this file already answers, and the answer is not the
/// class's declared width. `rv_gpr` covers RV32 and RV64 with no width of its
/// own -- the operands' type atoms decide -- so asking the table would make an
/// RV32 spill slot eight bytes and refuse the four-byte one that is correct.
pub fn class_spill_width(document: &Document, class: &RegisterClass) -> u32 {
    class_value_widths(document, class)
        .into_iter()
        .max()
        .unwrap_or_else(|| class_width(class))
}

/// The register classes this document's operands actually name, grouped into
/// files. A class no operand names is not part of this target.
fn register_files(document: &Document) -> Vec<RegisterFile> {
    let mut used: Vec<&'static RegisterClass> = Vec::new();
    for instruction in &document.instructions {
        for operand in &instruction.operands {
            if let Some(class) = register_class(&operand.kind) {
                if !used.iter().any(|seen| seen.name == class.name) {
                    used.push(class);
                }
            }
        }
    }
    let mut files: Vec<RegisterFile> = Vec::new();
    for class in used {
        match files.iter_mut().find(|file| file.offset == class.offset) {
            Some(file) => file.classes.push(class),
            None => files.push(RegisterFile { offset: class.offset, classes: vec![class] }),
        }
    }
    for file in &mut files {
        file.classes.sort_by(|a, b| {
            class_width(b)
                .cmp(&class_width(a))
                .then_with(|| a.view_offset.cmp(&b.view_offset))
                .then_with(|| a.name.cmp(b.name))
        });
    }
    files.sort_by_key(|file| file.offset);
    files
}

/// The TableGen def prefix for a class's registers. Views share the file's
/// storage but need distinct defs, because LLVM models a view as a register
/// with a sub-register index rather than as a second name for one register.
fn reg_prefix(class: &RegisterClass) -> String {
    tablegen_ident(class.name).to_uppercase()
}

fn class_def(class: &RegisterClass) -> String {
    format!("{}Regs", tablegen_ident(class.name))
}

/// How many registers a file has. AXIS encodes a register selector in at most
/// five bits everywhere it is used, and `REGISTER_SELECTOR_LIMIT` is the same
/// bound the executor and the JIT index the flat file with.
fn file_size() -> u32 {
    REGISTER_SELECTOR_LIMIT
}

/// An LLVM value type for a class of this width. A vector file is described
/// here by the width of the element view an operand names, because that is
/// what the corpora encode — a whole scalable register has no fixed MVT.
pub(crate) fn value_type(width: u32) -> &'static str {
    match width {
        w if w <= 8 => "i8",
        w if w <= 16 => "i16",
        w if w <= 32 => "i32",
        _ => "i64",
    }
}

/// The value types a class carries *in this document*, taken from the widths
/// of the operands that name it.
///
/// A class's `limbs * 64` is a storage fact, not an architectural one: AXIS's
/// generic `reg` has no view width, so it defaults to 64 even in a 32-bit
/// corpus whose every operand is 32 bits. LLVM needs the architectural width,
/// and the operands are what state it.
fn class_value_widths(document: &Document, class: &RegisterClass) -> Vec<u32> {
    let mut widths: Vec<u32> = Vec::new();
    for instruction in &document.instructions {
        for operand in &instruction.operands {
            if operand.kind == class.name && !widths.contains(&operand.width) {
                widths.push(operand.width);
            }
        }
    }
    if widths.is_empty() {
        widths.push(class_width(class));
    }
    widths.sort_unstable();
    widths
}

fn class_value_types(document: &Document, class: &RegisterClass) -> Vec<&'static str> {
    let mut types: Vec<&'static str> = Vec::new();
    for width in class_value_widths(document, class) {
        let kind = value_type(width);
        if !types.contains(&kind) {
            types.push(kind);
        }
    }
    types
}

/// The architectural state this document's instructions actually touch, as
/// `(name, declared width)`.
///
/// Taken from the behaviors rather than from `isa.registers`, and deliberately
/// so. A document declares more scalars than its instructions use, and some of
/// what it declares is reached another way: AArch64's `sp` is in the register
/// list *and* inside the `a64_gpr64sp` class, so emitting it from the
/// declaration would define one machine register twice. What a behavior names
/// through `Loc::State` is exactly the set that has no operand to carry it.
///
/// Nothing here knows what a flag is. An ISA declares scalar state, a behavior
/// writes it, and that is the whole rule -- `nzcv` and `fpcr` and a future
/// architecture's mode register all arrive the same way.
fn state_registers(document: &Document) -> Vec<(String, u32)> {
    let mut found: Vec<(String, u32)> = Vec::new();
    for instruction in &document.instructions {
        let Some(behavior) = instruction.behavior.as_ref() else {
            continue;
        };
        for effect in &behavior.effects {
            if let Loc::State { name, width } = &effect.loc {
                if !found.iter().any(|(seen, _)| seen == name) {
                    found.push((name.clone(), *width));
                }
            }
        }
    }
    // A state location an instruction only *reads* still has to exist as a
    // register, or the `Uses` naming it would not resolve.
    for (name, width) in crate::effects::isa_scalar_state_slots(&document.isas) {
        if found.iter().any(|(seen, _)| *seen == name) {
            continue;
        }
        if document
            .instructions
            .iter()
            .filter_map(|instruction| instruction.behavior.as_ref())
            .any(|behavior| behavior_reads_state(behavior, &name))
        {
            found.push((name, width));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Whether any effect of this behavior names `state` in an expression.
fn behavior_reads_state(behavior: &crate::effects::Behavior, state: &str) -> bool {
    let names = |expr: &SemanticExpr| expression_names(expr, state);
    behavior.effects.iter().any(|effect| {
        names(&effect.value.expr)
            || effect.guard.as_ref().is_some_and(|guard| names(&guard.expr))
            || match &effect.loc {
                Loc::Mem { addr, .. } => names(&addr.expr),
                _ => false,
            }
    })
}

fn expression_names(expr: &SemanticExpr, symbol: &str) -> bool {
    match expr {
        SemanticExpr::Atom(atom) => atom == symbol,
        SemanticExpr::List(items) => items.iter().any(|item| expression_names(item, symbol)),
    }
}

/// The TableGen def for a state register, and for the class holding it.
fn state_def(name: &str) -> String {
    tablegen_ident(name).to_uppercase()
}

/// LLVM needs a legal value type for a class, and architectural state is
/// rarely a legal width -- AArch64's `nzcv` is four bits. LLVM's own AArch64
/// target puts it in an `i32` class for exactly this reason, so the declared
/// width says which register it is and the class type says what LLVM can hold.
fn state_value_type(width: u32) -> &'static str {
    value_type(width.max(32).next_power_of_two().min(64))
}

/// The alignment TableGen wants for a state class: its value type's width.
fn state_alignment(width: u32) -> u32 {
    width.max(32).next_power_of_two().min(64)
}

/// The state this instruction writes and reads, as TableGen register names.
///
/// An instruction that writes architectural state beside its result is the
/// commonest shape in the corpus -- 426 of AArch64's declines are a result and
/// an NZCV write together. `Defs` and `Uses` are how LLVM is told, and they
/// are what make a value pattern on such an instruction truthful rather than a
/// silent clobber: the register allocator sees the write even though no
/// operand carries it.
fn state_defs_and_uses(document: &Document, instruction: &Instruction) -> (Vec<String>, Vec<String>) {
    let (mut defs, mut uses): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    let Some(behavior) = instruction.behavior.as_ref() else {
        return (defs, uses);
    };
    for effect in &behavior.effects {
        if let Loc::State { name, .. } = &effect.loc {
            let def = state_def(name);
            if !defs.contains(&def) {
                defs.push(def);
            }
        }
    }
    for (name, _) in state_registers(document) {
        if behavior_reads_state(behavior, &name) {
            let def = state_def(&name);
            if !uses.contains(&def) {
                uses.push(def);
            }
        }
    }
    defs.sort();
    uses.sort();
    (defs, uses)
}

/// The scheduling and aliasing flags LLVM needs to know an instruction is not
/// a pure register operation.
///
/// Without them every load and store in the target reads as arithmetic: LLVM
/// is free to reorder them against each other, to sink one across a barrier,
/// or to delete one whose result is unused. The whole AArch64 seed -- 500-odd
/// memory instructions -- declared none of this, because the operand list
/// carries a memory *address* but never says the memory is touched.
///
/// The facts come from `effect_summary`, which is the same summary the lift
/// table publishes and the LLVM intrinsic emitter uses for its memory
/// attributes. Nothing here inspects an opcode or a mnemonic.
fn memory_flags(document: &Document, instruction: &Instruction) -> Vec<(&'static str, u32)> {
    let state_names = crate::effects::isa_scalar_state_names(&document.isas);
    let summary = crate::effects::effect_summary(instruction, &state_names);
    let mut flags: Vec<(&'static str, u32)> = Vec::new();
    if summary.reads_memory {
        flags.push(("mayLoad", 1));
    }
    if summary.writes_memory {
        flags.push(("mayStore", 1));
    }
    // `hasSideEffects` is inferred by TableGen from an instruction's patterns,
    // and these instructions mostly have none -- so the inference has nothing
    // to work from and the default is not something to rely on. Where the
    // behavior says an instruction traps, orders memory, or writes state that
    // no operand carries, say so.
    if summary.may_trap || summary.barrier || summary.writes_pc {
        flags.push(("hasSideEffects", 1));
    }
    flags
}

fn emit_state_registers(out: &mut String, document: &Document) {
    let states = state_registers(document);
    if states.is_empty() {
        return;
    }
    let target = target_name(document);
    out.push_str("//===- Architectural state -----------------------------===//\n\n");
    out.push_str("// Scalar state an instruction writes beside its result. Declaring it is\n");
    out.push_str("// what makes a value pattern on such an instruction honest: the clobber\n");
    out.push_str("// is visible to the register allocator instead of being dropped.\n");
    for (name, width) in &states {
        out.push_str(&format!(
            "def {} : Register<\"{name}\"> {{\n  let Namespace = \"{target}\";\n}} // {width} bits\n",
            state_def(name)
        ));
    }
    out.push('\n');
    for (name, width) in &states {
        out.push_str(&format!(
            "def {}State : RegisterClass<\"{target}\", [{}], {}, (add {})>;\n",
            state_def(name),
            state_value_type(*width),
            state_alignment(*width),
            state_def(name)
        ));
    }
    out.push('\n');
}

fn emit_registers(out: &mut String, document: &Document, files: &[RegisterFile]) {
    let target = target_name(document);
    out.push_str("//===- Registers ---------------------------------------===//\n\n");
    out.push_str(&format!(
        "class {target}Reg<bits<16> enc, string n, list<Register> subs = []>\n    : Register<n, []> {{\n"
    ));
    out.push_str(&format!("  let Namespace = \"{target}\";\n"));
    out.push_str("  let HWEncoding = enc;\n");
    out.push_str("  let SubRegs = subs;\n");
    out.push_str("}\n\n");

    for file in files {
        let full = file.classes[0];
        let views = &file.classes[1..];
        for view in views {
            out.push_str(&format!(
                "def sub_{} : SubRegIndex<{}, {}>;\n",
                tablegen_ident(view.name),
                class_width(view),
                view.view_offset
            ));
        }
        if !views.is_empty() {
            out.push('\n');
        }
        // Views first: the full register names them as sub-registers.
        for view in views {
            for index in 0..file_size() {
                out.push_str(&format!(
                    "def {}{index} : {target}Reg<{index}, \"{}{index}\">;\n",
                    reg_prefix(view),
                    tablegen_ident(view.name).to_lowercase()
                ));
            }
            out.push('\n');
        }
        for index in 0..file_size() {
            let subs: Vec<String> =
                views.iter().map(|view| format!("{}{index}", reg_prefix(view))).collect();
            let indices: Vec<String> =
                views.iter().map(|view| format!("sub_{}", tablegen_ident(view.name))).collect();
            out.push_str(&format!(
                "def {}{index} : {target}Reg<{index}, \"{}{index}\"{}>",
                reg_prefix(full),
                tablegen_ident(full.name).to_lowercase(),
                if subs.is_empty() { String::new() } else { format!(", [{}]", subs.join(", ")) }
            ));
            if indices.is_empty() {
                out.push_str(";\n");
            } else {
                out.push_str(&format!(" {{\n  let SubRegIndices = [{}];\n}}\n", indices.join(", ")));
            }
        }
        out.push('\n');

        for class in &file.classes {
            let prefix = reg_prefix(class);
            // A hardwired-zero index and an index that names a state slot are
            // registers the machine has and the allocator must not use.
            let mut reserved: Vec<u32> = Vec::new();
            if let Some(zero) = class.zero_index {
                reserved.push(zero);
            }
            if let Some((index, _)) = class.alias {
                reserved.push(index);
            }
            let order = if reserved.is_empty() {
                format!("(sequence \"{prefix}%u\", 0, {})", file_size() - 1)
            } else {
                let subtract: Vec<String> =
                    reserved.iter().map(|index| format!("{prefix}{index}")).collect();
                format!(
                    "(sub (sequence \"{prefix}%u\", 0, {}), {})",
                    file_size() - 1,
                    subtract.join(", ")
                )
            };
            let types = class_value_types(document, class);
            let width = class_value_widths(document, class)
                .into_iter()
                .max()
                .unwrap_or(64);
            out.push_str(&format!(
                "// {}{}\ndef {} : RegisterClass<\"{target}\", [{}], {}, {}>;\n\n",
                class.name,
                match (class.zero_index, class.alias) {
                    (Some(zero), _) => format!(" (x{zero} reads as zero)"),
                    (_, Some((index, slot))) => format!(" ({index} names state `{slot}`)"),
                    _ => String::new(),
                },
                class_def(class),
                types.join(", "),
                width.max(8),
                order
            ));
        }
    }
}

/// The encoding width of an operand: the highest operand bit any format field
/// binds. A scattered operand has several bindings and this is their span.
fn encoded_width(layout: &InstructionLayout, operand: &str) -> u32 {
    layout
        .operand_bindings(operand)
        .iter()
        .map(|field| field.op_lo + field.width)
        .max()
        .unwrap_or(0)
}

/// The TableGen operand class for one operand of one instruction.
///
/// An immediate gets the predicate its semantics states, so that the
/// `InOperandList` and the selection pattern name the same thing -- a Pat
/// supplies its RHS operands positionally into this list, so a pattern
/// matching `simm12` into an operand typed `AXISimm` would be selecting into
/// a slot with no range at all. `AXISimm` remains for the immediates whose
/// range the description does not state; they are the ones with no pattern.
fn operand_type(document: &Document, instruction: &Instruction, operand: &Operand) -> String {
    if let Some(class) = register_class(&operand.kind) {
        return class_def(class);
    }
    // The width an immediate is *typed* at, which is the result's when there is
    // one. A store has no result, and defaulting to 32 there gave RV64I's `SD`
    // an `Operand<i32>` slot while its pattern passed an `i64` -- a
    // contradiction tblgen reports as an empty type set, naming the pattern
    // and not the operand list that caused it. The machine's word is what an
    // operand of a resultless instruction is typed at.
    let root_width = operand_root_width(document, instruction, &operand.name);
    semantic_extensions_of(instruction, &operand.name)
        .into_iter()
        .find_map(|(signed, bits)| {
            immediate_predicate(document, instruction, &operand.name, signed, bits, root_width)
        })
        .or_else(|| {
            immediate_predicate_of(document, instruction, &operand.name, None, root_width)
                .map(|predicate| predicate.name())
        })
        .unwrap_or_else(|| "AXISimm".to_string())
}

fn emit_instructions(out: &mut String, document: &Document) {
    let target = target_name(document);
    out.push_str("//===- Instructions ------------------------------------===//\n\n");
    out.push_str(&format!(
        "def AXISimm : Operand<i64> {{\n  let ParserMatchClass = ImmAsmOperand;\n}}\n\n"
    ));
    // Over the architectural instructions too, which are what the defs below
    // name operand classes for: a scalable instruction's lanes and its
    // one-per-encoding representative can type an immediate at different
    // widths, and SVE2's predicated shifts named `uimm3i64` from one while
    // only `uimm3i8` was defined from the other.
    let mut defined = document.clone();
    defined.instructions.extend(architectural_instructions(document));
    emit_immediate_predicates(out, &defined);

    // Every instruction of a document shares an encoding width in practice;
    // take it from the first encodable one rather than assuming 32.
    let bits = document
        .instructions
        .iter()
        .map(|instruction| layout_for(document, instruction).bits)
        .next()
        .unwrap_or(32);

    out.push_str(&format!(
        "class {target}Inst<dag outs, dag ins, string mnemonic, string operands>\n    : Instruction {{\n"
    ));
    out.push_str(&format!("  let Namespace = \"{target}\";\n"));
    out.push_str(&format!("  let Size = {};\n", bits.div_ceil(8)));
    out.push_str(&format!("  field bits<{bits}> Inst;\n"));
    out.push_str(&format!("  field bits<{bits}> SoftFail = 0;\n"));
    out.push_str("  let OutOperandList = outs;\n");
    out.push_str("  let InOperandList = ins;\n");
    out.push_str("  let AsmString = !strconcat(mnemonic, \"\\t\", operands);\n");
    out.push_str("}\n\n");

    // One def per ENCODING, from the same helper the decode-keyed exports
    // use. This loop had its own copy of the rule -- keep lane 0, drop the
    // rest -- which agreed on *which* instruction represents a group and
    // disagreed on its NAME: it kept lane 0's `VADD_VV__L0` where the encode
    // table says `VADD_VV`. Two derivations of one fact, and a consumer
    // joining the two artifacts by name matched nothing.
    for instruction in &architectural_instructions(document) {
        let layout = layout_for(document, instruction);
        let def = tablegen_ident(&instruction.mnemonic).to_uppercase();
        if !layout.is_encodable() {
            // Declined by name: a target that silently dropped these would
            // claim coverage it does not have.
            out.push_str(&format!(
                "// not encodable, so not emitted: {} ({}{}{})\n",
                instruction.mnemonic,
                if layout.unencoded_operands.is_empty() { "" } else { "unencoded operands: " },
                layout.unencoded_operands.join(", "),
                if layout.unbound_fields.is_empty() {
                    String::new()
                } else {
                    format!("unbound fields: {}", layout.unbound_fields.join(", "))
                }
            ));
            continue;
        }

        // A derived operand is not an operand of the machine instruction: it
        // is implied by the one it derives from, which is why no format field
        // binds it. AArch64's CASP encodes the first register of each pair and
        // the second is that register plus one; a lane operand is derived the
        // same way. LLVM spells a pair as one operand of a pair class, so
        // these are omitted and named in a comment rather than emitted as
        // operands LLVM would have nothing to decode into.
        let encoded_operands: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.derived_from.is_empty() && operand.fixed.is_none())
            .collect();
        let derived: Vec<String> = instruction
            .operands
            .iter()
            .filter(|operand| !operand.derived_from.is_empty() || operand.fixed.is_some())
            .map(|operand| match operand.fixed {
                Some(index) => format!("{} = {} {index}", operand.name, operand.kind),
                None => format!(
                    "{} = {} + {}",
                    operand.name, operand.derived_from, operand.derived_add
                ),
            })
            .collect();
        if !derived.is_empty() {
            out.push_str(&format!("// implied, not encoded: {}\n", derived.join(", ")));
        }

        let mut outs: Vec<String> = Vec::new();
        let mut ins: Vec<String> = Vec::new();
        let mut ties: Vec<String> = Vec::new();
        for operand in &encoded_operands {
            let name = tablegen_ident(&operand.name);
            let kind = operand_type(document, instruction, operand);
            match operand_role(operand, false) {
                "out" => outs.push(format!("{kind}:${name}")),
                "inout" => {
                    outs.push(format!("{kind}:${name}"));
                    ins.push(format!("{kind}:${name}_tied"));
                    ties.push(format!("${name} = ${name}_tied"));
                }
                // `enc` is encoded and read by nothing; it is still an operand
                // of the machine instruction, so it is still in the list.
                _ => ins.push(format!("{kind}:${name}")),
            }
        }

        let placeholders: Vec<String> = encoded_operands
            .iter()
            .map(|operand| format!("${}", tablegen_ident(&operand.name)))
            .collect();

        out.push_str(&format!(
            "def {def} : {target}Inst<(outs {}), (ins {}), \"{}\", \"{}\"> {{\n",
            outs.join(", "),
            ins.join(", "),
            instruction.mnemonic.to_lowercase(),
            placeholders.join(", ")
        ));
        // One document can describe more than one decode context -- a core
        // and an accelerator, two personalities -- and they legitimately reuse
        // bit patterns. LLVM builds one decoder table per DecoderNamespace, so
        // an ISA is a namespace. Without this the two contexts of the AArch64
        // seed collide in 271 pairs.
        out.push_str(&format!(
            "  let DecoderNamespace = \"{}\";\n",
            tablegen_ident(&instruction.isa)
        ));
        // And an optional ISA is a subtarget feature, so its instructions
        // exist only where that feature does.
        if let Some(predicate) = isa_predicate(document, &instruction.isa) {
            out.push_str(&format!("  let Predicates = [{predicate}];\n"));
        }
        for operand in &encoded_operands {
            let width = encoded_width(&layout, &operand.name);
            if width > 0 {
                out.push_str(&format!(
                    "  bits<{width}> {};\n",
                    tablegen_ident(&operand.name)
                ));
            }
        }
        for field in &layout.fixed_fields {
            out.push_str(&format!(
                "  let Inst{{{}}} = {};\n",
                bit_range(field.insn_lo, field.width),
                format!("0b{:0width$b}", field.value, width = field.width as usize)
            ));
        }
        for field in &layout.operand_fields {
            out.push_str(&format!(
                "  let Inst{{{}}} = {}{{{}}};\n",
                bit_range(field.insn_lo, field.width),
                tablegen_ident(&field.operand),
                bit_range(field.op_lo, field.width)
            ));
        }
        // Memory and side effects. An instruction whose behavior touches
        // memory must say so, or LLVM treats it as arithmetic and reorders it
        // freely against the loads and stores around it.
        for (flag, value) in memory_flags(document, instruction) {
            out.push_str(&format!("  let {flag} = {value};\n"));
        }
        // State written and read beside the operands. Without these an
        // instruction that sets flags looks pure to LLVM, and any pattern on
        // it would clobber a live value the allocator did not know about.
        let (defs, uses) = state_defs_and_uses(document, instruction);
        if !defs.is_empty() {
            out.push_str(&format!("  let Defs = [{}];\n", defs.join(", ")));
        }
        if !uses.is_empty() {
            out.push_str(&format!("  let Uses = [{}];\n", uses.join(", ")));
        }
        if !ties.is_empty() {
            out.push_str(&format!("  let Constraints = \"{}\";\n", ties.join(", ")));
        }
        out.push_str("}\n\n");
    }
}

/// TableGen spells a one-bit range as `{n}` and a wider one as `{hi-lo}`.
fn bit_range(lo: u32, width: u32) -> String {
    if width == 1 {
        format!("{lo}")
    } else {
        format!("{}-{}", lo + width - 1, lo)
    }
}

/// Patterns that select this target's own instructions.
///
/// `emit-llvm-patterns` maps a DAG to an `llvm.axis.*` intrinsic, which is a
/// hint for a target that already exists. A backend selects an *instruction*,
/// with its operands typed by this target's register classes -- which is what
/// makes `--gen-dag-isel` able to build a matcher at all.
/// One line of the instruction-selection section: either a note saying why an
/// instruction has no pattern, or a pattern with the match key it claims.
enum PatternLine {
    Note(String),
    Pat {
        mnemonic: String,
        key: String,
        text: String,
        /// Whether the instruction writes architectural state beside its
        /// value. This is what separates `ADD` from `ADDS`, whose values are
        /// the same expression.
        clobbers_state: bool,
        /// Whether the instruction belongs to an optional ISA rather than the
        /// one that is always there.
        optional_isa: bool,
        /// Whether the value this instruction produces lands in a register
        /// file of its own rather than the general-purpose one.
        separate_file: bool,
    },
}

fn emit_isel_patterns(out: &mut String, document: &Document) {
    out.push_str("//===- Instruction selection ---------------------------===//\n\n");
    let mut lines: Vec<PatternLine> = Vec::new();
    for instruction in &architectural_instructions(document) {
        let mnemonic = &instruction.mnemonic;
        if !layout_for(document, instruction).is_encodable() {
            continue;
        }
        // Whether the instruction says what it computes is asked first, and
        // deliberately so. Every check below is about the *shape* a pattern
        // needs, and an instruction that states nothing fails all of them --
        // so whichever ran first got the credit. With the shape checks in
        // front, AArch64 reported 253 instructions as "not a single-result
        // instruction" of which 251 had no semantics at all, and 174 as
        // immediates lacking a range of which 158 did. A census that
        // overstates a cause is worse than no census: it points the next
        // piece of work at the wrong gap.
        if let Err(reason) = crate::effects::pure_value_semantics(instruction) {
            // A store has no result, so it is not a value at all -- but it is
            // still a pattern, in a shape none of the single-result machinery
            // below applies to. Asked here, before that machinery declines it
            // for lacking what a store never has.
            match emit_store_pattern(document, instruction) {
                Some(Ok(line)) => lines.push(line),
                Some(Err(store_reason)) => lines.push(PatternLine::Note(format!(
                    "// {mnemonic}: {store_reason}; no pattern\n"
                ))),
                // A store that also updates its base is two effects, so
                // neither of the above sees it -- and it is the single largest
                // cause of declines on the AArch64 seed.
                None if crate::effects::atomic_rmw_semantics(instruction).is_ok()
                    || matches!(
                        crate::effects::atomic_rmw_semantics(instruction),
                        Err(Some(_))
                    ) =>
                {
                    match emit_atomic_rmw_pattern(document, instruction) {
                        Ok(line) => lines.push(line),
                        Err(rmw_reason) => lines.push(PatternLine::Note(format!(
                            "// {mnemonic}: {rmw_reason}; no pattern\n"
                        ))),
                    }
                }
                None => match emit_indexed_store_pattern(document, instruction) {
                    Some(Ok(line)) => lines.push(line),
                    Some(Err(indexed_reason)) => lines.push(PatternLine::Note(format!(
                        "// {mnemonic}: {indexed_reason}; no pattern\n"
                    ))),
                    // ⚠️ A CONDITIONAL BRANCH is its own shape, and saying so
                    // is the point. It computes no value, writes no memory,
                    // and until now fell through to whatever generic reason
                    // ran last -- which put branches under a heading about
                    // value semantics and pointed the next piece of work at
                    // the wrong gap. LLVM spells this `brcond`; what is not
                    // built yet is the branch-target operand class it needs,
                    // because these immediates share a class with ordinary
                    // ones and a target must be `Operand<OtherVT>`.
                    None => match crate::effects::conditional_branch_semantics(instruction) {
                        Ok((cond, target)) => lines.push(PatternLine::Note(format!(
                            "// {mnemonic}: a conditional branch on {} to pc + ${target}; \
                             `brcond` needs a branch-target operand class; no pattern\n",
                            crate::effects::render_semexpr(&cond)
                        ))),
                        Err(Some(branch_reason)) => lines.push(PatternLine::Note(format!(
                            "// {mnemonic}: {branch_reason}; no pattern\n"
                        ))),
                        Err(None) => lines.push(PatternLine::Note(format!(
                            "// {mnemonic}: {reason}; no pattern\n"
                        ))),
                    },
                },
            }
            continue;
        }

        // A Pat produces one value, so an instruction with anything other
        // than one written register has no pattern of this shape. An `inout`
        // needs a tied operand, which is a different Pat and not this one.
        let outputs: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.output)
            .collect();
        if outputs.len() != 1 || outputs[0].input {
            lines.push(PatternLine::Note(format!(
                "// {mnemonic}: not a single-result instruction; no pattern\n"
            )));
            continue;
        }
        let inputs: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input && !operand.output)
            .collect();
        // An operand is either a register or an immediate carrying a predicate
        // for the values it can hold. Where the semantics states a range that
        // wins -- only it can say a value is *signed*. Where it states none,
        // the encoding still says which values the instruction can represent,
        // which is not the same as the field width and is not a guess.
        // What this operand may hold: the range its semantics states, or --
        // failing that -- the one its encoding implies.
        // Which immediates this instruction's semantics multiplies, and by how
        // much -- *for the specialisation being built*. AArch64's `ADD`
        // immediate shifts by `sh * 12`, so its two forms scale by 1 and by
        // 4096, and computing this once for the whole instruction gave the
        // second form the first one's scale: a pattern selecting `sh = 1` for
        // a plain `rn + imm`, which multiplies the offset by 4096. The golden
        // check named it; nothing structural would have.
        let scales_for = |pin: Option<(&str, u32)>| scaled_immediates(instruction, pin);
        let predicate_of = |name: &str, scales: &[(String, u32)]| -> Option<String> {
            // Typed at the width of the half it appears in, which for a load's
            // offset is the address's and not the result's.
            let width = operand_root_width(document, instruction, name);
            semantic_extensions_of(instruction, name)
                .into_iter()
                .map(Some)
                .chain(std::iter::once(None))
                .find_map(|ext| {
                    immediate_predicate_scaled(
                        document, instruction, name, ext, width, scales,
                    )
                })
                .map(|predicate| predicate.name())
        };
        // No check here that an immediate has a range. It used to live at this
        // point and it is now unreachable: an instruction that gets this far
        // is `is_encodable()`, so every operand has encoding bindings, and an
        // immediate with bindings always has a predicate -- the encoding says
        // which values it can hold even when nothing else does. The `untypable
        // operand` check below still catches an operand that ends up with
        // neither a class nor a predicate, and it runs *after* the semantics,
        // so it cannot take the credit for an instruction that simply says
        // nothing. Standing here it declined 174 AArch64 instructions, 158 of
        // which had no semantics at all.
        if inputs.is_empty() {
            continue;
        }
        // A derived operand is not in the emitted operand list, so a pattern
        // naming one would hand LLVM more operands than the instruction has.
        // SVE's ADDV_S sums four lanes and encodes one register.
        if instruction
            .operands
            .iter()
            .any(|operand| !operand.derived_from.is_empty())
        {
            lines.push(PatternLine::Note(format!(
                "// {mnemonic}: semantics names derived operands; no pattern\n"
            )));
            continue;
        }
        let transform_of = |name: &str, scales: &[(String, u32)]| -> Option<String> {
            // Typed at the width of the half it appears in, which for a load's
            // offset is the address's and not the result's.
            let width = operand_root_width(document, instruction, name);
            semantic_extensions_of(instruction, name)
                .into_iter()
                .map(Some)
                .chain(std::iter::once(None))
                .find_map(|ext| {
                    immediate_predicate_scaled(
                        document, instruction, name, ext, width, scales,
                    )
                })
                .and_then(|predicate| predicate.transform())
        };
        let class_of = |name: &str| -> Option<String> {
            instruction
                .operands
                .iter()
                .find(|operand| operand.name == name)
                .and_then(|operand| register_class(&operand.kind))
                .map(class_def)
        };
        let leaf_with = |scales: &[(String, u32)]| {
            let scales = scales.to_vec();
            move |name: &str, ext: Option<(bool, u32)>, width: u32| -> Option<String> {
            let scales = scales.as_slice();
            // An extension over an encoded immediate is that immediate's
            // range, spelled as the predicate on its operand -- scaled where
            // the semantics multiplies it, because the DAG carries the product,
            // and typed at the width of the half it appears in.
            //
            // `None` here is not a fallthrough. It says "this symbol is not an
            // encoded immediate", and the builder then makes the extension a
            // real DAG node, which is what an extension of a *register* is.
            if let Some((signed, bits)) = ext {
                if let Some(predicate) = immediate_predicate_scaled(
                    document, instruction, name, ext, width, scales,
                ) {
                    return Some(format!("{}:${}", predicate.name(), tablegen_ident(name)));
                }
                // A register extended from its own width into a wider pattern
                // is a real `zext`/`sext`, typed by its own narrower class.
                return widening_register_extension(
                    instruction,
                    name,
                    signed,
                    bits,
                    width,
                    |class| format!("{}:${}", class_def(class), tablegen_ident(name)),
                );
            }
            if class_of(name).is_none() {
                if let Some(predicate) = immediate_predicate_scaled(
                    document, instruction, name, None, width, scales,
                ) {
                    return Some(format!("{}:${}", predicate.name(), tablegen_ident(name)));
                }
            }
            if let Some(narrowed) = narrowing_register_leaf(instruction, name, width, |class| {
                format!("{}:${}", class_def(class), tablegen_ident(name))
            }) {
                return Some(narrowed);
            }
            Some(match class_of(name) {
                Some(class) => format!("{class}:${}", tablegen_ident(name)),
                // A symbol the semantics names that is not an operand cannot
                // be typed; the pattern is dropped below when tblgen rejects
                // it.
                None => format!("${}", tablegen_ident(name)),
            })
            }
        };
        // A helper that switches on an operand has no single DAG node, but it
        // has one per value of that operand -- and the decode constraint says
        // which values this instruction encodes. One pattern each, or one
        // pattern and no pinning when there is no selector.
        let specialisations: Vec<Option<(String, u32)>> =
            match selector_specializations(instruction).into_iter().next() {
                Some((name, values)) => values
                    .into_iter()
                    .map(|value| Some((name.clone(), value)))
                    .collect(),
                None => vec![None],
            };
        let mut emitted = 0usize;
        let mut first_reason: Option<String> = None;
        // Two specialisations can reduce to one DAG, and that is a fact about
        // the architecture rather than a mistake: `a64_extend_reg` at 64 bits
        // extends nothing whether the option says UXTX or SXTX, so the machine
        // has two encodings of one behavior. ISel wants one pattern, and which
        // encoding it selects is a choice the description does not make -- so
        // the first is taken and the rest are not emitted twice.
        let mut claimed: Vec<String> = Vec::new();
        for pinned in &specialisations {
            let pin = pinned.as_ref().map(|(name, value)| (name.as_str(), *value));
            // The scale is this specialisation's, not the instruction's.
            let scales = scales_for(pin);
            let leaf = leaf_with(&scales);
            let predicate_of = |name: &str| predicate_of(name, &scales);
            let transform_of = |name: &str| transform_of(name, &scales);
            let dag = match llvm_pattern_dag(document, instruction, &leaf, pin) {
                Ok(dag) => dag,
                Err(reason) => {
                    first_reason.get_or_insert(reason);
                    continue;
                }
            };
            match build_one_pattern(
                document,
                instruction,
                &dag,
                &inputs,
                &outputs,
                pin,
                &class_of,
                &predicate_of,
                &transform_of,
            ) {
                Ok((key, text)) => {
                    if claimed.contains(&key) {
                        continue;
                    }
                    claimed.push(key.clone());
                    lines.push(PatternLine::Pat {
                        mnemonic: mnemonic.clone(),
                        key,
                        text,
                        clobbers_state: writes_state(instruction),
                        optional_isa: isa_predicate(document, &instruction.isa).is_some(),
                        separate_file: writes_separate_file(instruction),
                    });
                    emitted += 1;
                }
                Err(reason) => {
                    first_reason.get_or_insert(reason);
                    continue;
                }
            }
        }
        if emitted == 0 {
            let reason = first_reason.unwrap_or_else(|| "no pattern for any form".to_string());
            lines.push(PatternLine::Note(format!(
                "// {mnemonic}: {reason}; no pattern\n"
            )));
        }
    }
    // Two instructions whose patterns have the same left-hand side are not a
    // pattern each. TableGen would take one of them by an ordering rule and
    // the description has said nothing about which -- so RISC-V's `FLS` and
    // `LW` both reduce to `(i32 (load (add $RS1, simm12i32:$IMM)))`, and
    // selecting the float load for an integer one puts the value in the wrong
    // register file. Both are dropped, and both are named: picking silently is
    // the failure this file exists to avoid.
    let mut claims: std::collections::HashMap<&str, Vec<Rival>> =
        std::collections::HashMap::new();
    for line in &lines {
        if let PatternLine::Pat {
            mnemonic,
            key,
            clobbers_state,
            optional_isa,
            separate_file,
            ..
        } = line
        {
            let rivals = claims.entry(key.as_str()).or_default();
            if !rivals.iter().any(|rival| rival.mnemonic == mnemonic.as_str()) {
                rivals.push(Rival {
                    mnemonic: mnemonic.as_str(),
                    clobbers_state: *clobbers_state,
                    optional_isa: *optional_isa,
                    separate_file: *separate_file,
                });
            }
        }
    }
    for line in &lines {
        match line {
            PatternLine::Note(note) => out.push_str(note),
            PatternLine::Pat {
                mnemonic,
                key,
                text,
                ..
            } => {
                let rivals = &claims[key.as_str()];
                if rivals.len() < 2 {
                    out.push_str(text);
                    continue;
                }
                // Narrowed twice, and the order matters: a flag-setting form
                // of an optional ISA's instruction has to lose on both counts.
                let quiet: Vec<&Rival> = rivals
                    .iter()
                    .filter(|rival| !rival.clobbers_state)
                    .collect();
                if let Some(winner) = sole_winner(&quiet) {
                    out.push_str(&resolved(mnemonic, key, text, winner, "writes no state"));
                    continue;
                }
                let present: Vec<&Rival> = quiet
                    .iter()
                    .copied()
                    .filter(|rival| !rival.optional_isa)
                    .collect();
                if let Some(winner) = sole_winner(&present) {
                    out.push_str(&resolved(
                        mnemonic,
                        key,
                        text,
                        winner,
                        "is always present",
                    ));
                    continue;
                }
                // Narrowed a third time, by which register file the value lands
                // in. AXIS types floating-point values as bit patterns in
                // integer operands -- deliberately, so that the golden model,
                // C, Rust and LLVM agree bit-for-bit -- so an FP load and an
                // integer load of one width produce *the same* DAG,
                // `(i64 (load ...))`. They are not the same instruction, and a
                // backend tells them apart by the file the result lands in,
                // which a value-typed pattern cannot say. The pattern
                // therefore belongs to the instruction writing the
                // general-purpose file, and the one writing a file of its own
                // is declined by name.
                //
                // Until this, RISC-V's `LD` had already lost its pattern to
                // `FLD` and kept no load at all; describing AArch64's
                // `LDR_D_UNSIGNED` would have taken `LDR_X_UNSIGNED` the same
                // way. Two loads gone is not a tie, it is both answers wrong.
                let primary: Vec<&Rival> = present
                    .iter()
                    .copied()
                    .filter(|rival| !rival.separate_file)
                    .collect();
                if let Some(winner) = sole_winner(&primary) {
                    out.push_str(&resolved(
                        mnemonic,
                        key,
                        text,
                        winner,
                        "writes the general-purpose file, which a value-typed pattern names",
                    ));
                    continue;
                }
                let others: Vec<&str> = rivals
                    .iter()
                    .map(|rival| rival.mnemonic)
                    .filter(|rival| rival != mnemonic)
                    .collect();
                out.push_str(&format!(
                    "// {mnemonic}: {key} is also {}'s pattern; no pattern\n",
                    others.join(", ")
                ));
            }
        }
    }
    out.push('\n');
}

/// The `Pat` for an instruction whose whole behavior is one plain memory
/// write, or the reason there is none -- and `None` when this is not a store
/// at all, so the caller keeps the reason it already had.
fn emit_store_pattern(
    document: &Document,
    instruction: &Instruction,
) -> Option<Result<PatternLine, String>> {
    let (_, addr_width) = crate::effects::store_operand_widths(instruction)?;
    let scales = scaled_store_immediates(instruction);
    let class_of = |name: &str| -> Option<String> {
        instruction
            .operands
            .iter()
            .find(|operand| operand.name == name)
            .and_then(|operand| register_class(&operand.kind))
            .map(class_def)
    };
    // A store's two halves are typed differently -- AArch64 stores a `W`
    // register through an `X` address -- so an immediate in the address is
    // typed at the address's width and not at the value's.
    let predicate_of = |name: &str, ext: Option<(bool, u32)>, width: u32| {
        immediate_predicate_scaled(document, instruction, name, ext, width, &scales)
    };
    let leaf = |name: &str, ext: Option<(bool, u32)>, width: u32| -> Option<String> {
        if ext.is_some() {
            let predicate = predicate_of(name, ext, width)?;
            return Some(format!("{}:${}", predicate.name(), tablegen_ident(name)));
        }
        if class_of(name).is_none() {
            let predicate = predicate_of(name, None, width)?;
            return Some(format!("{}:${}", predicate.name(), tablegen_ident(name)));
        }
        class_of(name).map(|class| format!("{class}:${}", tablegen_ident(name)))
    };
    let dag = match llvm_store_pattern_dag(document, instruction, &leaf) {
        Ok(dag) => dag,
        Err(reason) => return Some(Err(reason)),
    };
    // The operands positionally, as the instruction declares them -- a store's
    // `Pat` supplies them the same way any other does, and a scaled address
    // offset is divided on the way in just as a load's is.
    let mut rhs = Vec::new();
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        let ext = semantic_extensions_of(instruction, &operand.name)
            .into_iter()
            .next();
        let spelling = match class_of(&operand.name) {
            Some(class) => format!("{class}:${}", tablegen_ident(&operand.name)),
            None => {
                // Typed at the width of the half it appears in, which for an
                // offset is the address's.
                let width = addr_width;
                let Some(predicate) = predicate_of(&operand.name, ext, width)
                    .or_else(|| predicate_of(&operand.name, None, width))
                else {
                    return Some(Err("untypable operand".to_string()));
                };
                let leaf = format!("{}:${}", predicate.name(), tablegen_ident(&operand.name));
                match predicate.transform() {
                    Some(transform) => format!("({transform} {leaf})"),
                    None => leaf,
                }
            }
        };
        rhs.push(spelling);
    }
    let key = dag.clone();
    let text = format!(
        "def : Pat<{dag},\n          ({} {})>;\n",
        tablegen_ident(&instruction.mnemonic).to_uppercase(),
        rhs.join(", ")
    );
    let text = match isa_predicate(document, &instruction.isa) {
        Some(predicate) => format!("let Predicates = [{predicate}] in\n{text}"),
        None => text,
    };
    Some(Ok(PatternLine::Pat {
        mnemonic: instruction.mnemonic.clone(),
        key,
        text,
        clobbers_state: writes_state(instruction),
        optional_isa: isa_predicate(document, &instruction.isa).is_some(),
        separate_file: writes_separate_file(instruction),
    }))
}

/// The `Pat` for an atomic read-modify-write.
fn emit_atomic_rmw_pattern(
    document: &Document,
    instruction: &Instruction,
) -> Result<PatternLine, String> {
    let class_of = |name: &str| -> Option<String> {
        instruction
            .operands
            .iter()
            .find(|operand| operand.name == name)
            .and_then(|operand| register_class(&operand.kind))
            .map(class_def)
    };
    let leaf = |name: &str, ext: Option<(bool, u32)>, width: u32| -> Option<String> {
        if let Some(class) = class_of(name) {
            if ext.is_none() {
                return Some(format!("{class}:${}", tablegen_ident(name)));
            }
        }
        let predicate =
            immediate_predicate_scaled(document, instruction, name, ext, width, &[])?;
        Some(format!("{}:${}", predicate.name(), tablegen_ident(name)))
    };
    let dag = llvm_atomic_rmw_pattern_dag(document, instruction, &leaf)?;
    let mut rhs = Vec::new();
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        let Some(spelling) = leaf(&operand.name, None, operand.width) else {
            return Err("untypable operand".to_string());
        };
        rhs.push(spelling);
    }
    let text = format!(
        "def : Pat<{dag},\n          ({} {})>;\n",
        tablegen_ident(&instruction.mnemonic).to_uppercase(),
        rhs.join(", ")
    );
    let text = match isa_predicate(document, &instruction.isa) {
        Some(predicate) => format!("let Predicates = [{predicate}] in\n{text}"),
        None => text,
    };
    Ok(PatternLine::Pat {
        mnemonic: instruction.mnemonic.clone(),
        key: dag,
        text,
        clobbers_state: writes_state(instruction),
        optional_isa: isa_predicate(document, &instruction.isa).is_some(),
        separate_file: writes_separate_file(instruction),
    })
}

/// The `Pat` for a store that also updates its base register.
fn emit_indexed_store_pattern(
    document: &Document,
    instruction: &Instruction,
) -> Option<Result<PatternLine, String>> {
    // Not this shape at all: the caller keeps the reason it had.
    if let Err(None) = crate::effects::indexed_store_semantics(instruction) {
        return None;
    }
    let class_of = |name: &str| -> Option<String> {
        instruction
            .operands
            .iter()
            .find(|operand| operand.name == name)
            .and_then(|operand| register_class(&operand.kind))
            .map(class_def)
    };
    let predicate_of = |name: &str, ext: Option<(bool, u32)>| -> Option<ImmediatePredicate> {
        let width = operand_root_width(document, instruction, name);
        immediate_predicate_scaled(document, instruction, name, ext, width, &[])
    };
    // The base register is `inout`, so the operand list spells its *input*
    // side `$RN_tied` -- `Constraints = "$RN = $RN_tied"` is what makes the
    // two one register. A pattern names the input, on both sides, or TableGen
    // reports a name in the output pattern that is not in the input one.
    let slot = |name: &str| -> String {
        let tied = instruction
            .operands
            .iter()
            .any(|operand| operand.name == name && operand.input && operand.output);
        format!("{}{}", tablegen_ident(name), if tied { "_tied" } else { "" })
    };
    let leaf = |name: &str, ext: Option<(bool, u32)>, _width: u32| -> Option<String> {
        if ext.is_some() {
            let predicate = predicate_of(name, ext)?;
            return Some(format!("{}:${}", predicate.name(), slot(name)));
        }
        if let Some(class) = class_of(name) {
            return Some(format!("{class}:${}", slot(name)));
        }
        let predicate = predicate_of(name, None)?;
        Some(format!("{}:${}", predicate.name(), slot(name)))
    };
    let (dag, base) = match llvm_indexed_store_pattern_dag(document, instruction, &leaf) {
        Ok(found) => found,
        Err(reason) => return Some(Err(reason)),
    };
    // Positionally, as the instruction declares them. The tied input takes the
    // base register: `Constraints = "$RN = $RN_tied"` means the two are one
    // register, and the pattern names it once on each side.
    let mut rhs = Vec::new();
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        let name = operand.name.as_str();
        let spelling = match class_of(name) {
            Some(class) => format!("{class}:${}", slot(name)),
            None => {
                let ext = semantic_extensions_of(instruction, name).into_iter().next();
                let Some(predicate) =
                    predicate_of(name, ext).or_else(|| predicate_of(name, None))
                else {
                    return Some(Err("untypable operand".to_string()));
                };
                format!("{}:${}", predicate.name(), slot(name))
            }
        };
        rhs.push(spelling);
    }
    let _ = base;
    let text = format!(
        "def : Pat<{dag},\n          ({} {})>;\n",
        tablegen_ident(&instruction.mnemonic).to_uppercase(),
        rhs.join(", ")
    );
    let text = match isa_predicate(document, &instruction.isa) {
        Some(predicate) => format!("let Predicates = [{predicate}] in\n{text}"),
        None => text,
    };
    Some(Ok(PatternLine::Pat {
        mnemonic: instruction.mnemonic.clone(),
        key: dag,
        text,
        clobbers_state: writes_state(instruction),
        optional_isa: isa_predicate(document, &instruction.isa).is_some(),
        separate_file: writes_separate_file(instruction),
    }))
}

/// One instruction claiming a pattern's left-hand side, and what decides it
/// against another that claims the same one.
struct Rival<'a> {
    mnemonic: &'a str,
    clobbers_state: bool,
    optional_isa: bool,
    separate_file: bool,
}

/// Whether an instruction's value lands in a register file of its own.
///
/// A class with a non-zero `offset` sits above the general-purpose file in the
/// flat register array -- `a64_vreg64` and `rv_fpr` are the two here. That is
/// exactly the fact a value-typed SelectionDAG pattern cannot carry.
fn writes_separate_file(instruction: &Instruction) -> bool {
    instruction
        .operands
        .iter()
        .filter(|operand| operand.output)
        .any(|operand| {
            crate::ast::register_class(&operand.kind).is_some_and(|class| class.offset != 0)
        })
}

/// The single rival left after a narrowing, or `None` if it did not decide.
fn sole_winner<'a>(narrowed: &[&'a Rival<'a>]) -> Option<&'a str> {
    match narrowed {
        [only] => Some(only.mnemonic),
        _ => None,
    }
}

/// Either the winning pattern's text, or the note saying which rival took it.
fn resolved(mnemonic: &str, key: &str, text: &str, winner: &str, why: &str) -> String {
    if winner == mnemonic {
        return text.to_string();
    }
    format!("// {mnemonic}: {key} is {winner}'s pattern, which {why}; no pattern\n")
}

/// Whether the instruction writes architectural state beside its value.
///
/// `pure_value_semantics` sets a state write aside as a clobber, which is what
/// lets `ADDS` have a value pattern at all -- but it also makes that pattern
/// identical to `ADD`'s, because the two compute the same expression and
/// differ only in the flags. Between two instructions claiming one DAG, the
/// one that writes no state is the pattern: a flag-setting form is worth
/// selecting for its flags, and selecting it for its value would destroy NZCV
/// wherever a plain add was meant. Nothing here knows what a flag is.
fn writes_state(instruction: &Instruction) -> bool {
    instruction.behavior.as_ref().is_some_and(|behavior| {
        behavior
            .effects
            .iter()
            .any(|effect| matches!(effect.loc, Loc::State { .. }))
    })
}

/// Build one `Pat` as its match key and its text, or say why not.
///
/// The key is the pattern's whole left-hand side. Two instructions that reduce
/// to the same one are not a pattern each -- they are an ambiguity, and the
/// caller drops both.
#[allow(clippy::too_many_arguments)]
fn build_one_pattern(
    document: &Document,
    instruction: &Instruction,
    dag: &str,
    inputs: &[&Operand],
    outputs: &[&Operand],
    pinned: Option<(&str, u32)>,
    class_of: &dyn Fn(&str) -> Option<String>,
    predicate_of: &dyn Fn(&str) -> Option<String>,
    transform_of: &dyn Fn(&str) -> Option<String>,
) -> Result<(String, String), String> {
    let mnemonic = &instruction.mnemonic;
    {
        let type_of = |name: &str| class_of(name).or_else(|| predicate_of(name));
        if instruction
            .operands
            .iter()
            .any(|operand| type_of(&operand.name).is_none())
        {
            return Err("untypable operand".to_string());
        }

        // The root carries its value type explicitly (see the Pat below), and
        // it is the output operand's width. There is deliberately no check
        // that the operands' register classes agree with it: once
        // `llvm_pattern_dag` has accepted the instruction every operand has
        // that width, and `class_value_widths` reads a class's value types
        // off the very operands that name it -- so the agreement is a
        // theorem, not a condition. A check stood here and could not fire on
        // any of the twelve corpora; a guard that cannot fire reads as
        // coverage this file does not have.
        let root_type = value_type(outputs[0].width);

        // TableGen enumerates the commuted variants of every commutative
        // node in a pattern, so its cost is exponential in how many there
        // are. AArch64's RBIT spells bit reversal as a butterfly of nested
        // `or`/`and` -- 91 commutative nodes for RBIT_W and 187 for RBIT_X --
        // and one of them takes `--gen-instr-info` on this corpus from one
        // second to over two minutes.
        //
        // Such a pattern could never fire anyway: LLVM canonicalises bit
        // reversal to `bitreverse` and byte reversal to `bswap` long before
        // selection, so the butterfly matches nothing. Declined by name, with
        // the count, rather than silently.
        let commutative = ["(add ", "(mul ", "(and ", "(or ", "(xor ",
                           "(smin ", "(smax ", "(umin ", "(umax "];
        let variants: usize = commutative
            .iter()
            .map(|node| dag.matches(node).count())
            .sum();
        if variants > COMMUTATIVE_PATTERN_LIMIT {
            return Err(format!(
                "{variants} commutative nodes exceeds the pattern limit of \
                 {COMMUTATIVE_PATTERN_LIMIT}"
            ));
        }

        // A pinned selector is supplied as the literal this pattern is for.
        // The operand is still in the instruction's list and still encoded --
        // this pattern simply names which of its values it selects.
        let rhs = inputs
            .iter()
            .map(|operand| match pinned {
                // Typed at the operand's own width, which is the width of the
                // half of the semantics it appears in and not the result's.
                // `LDRH_W_REG` selects its extension kind inside an `X`
                // address and returns a `W`, so a literal typed at the result
                // gave TableGen an `i32` for an `Operand<i64>` slot -- an
                // empty type set, reported against the pattern and not against
                // the operand list.
                Some((name, value)) if name == operand.name => {
                    let width = operand_root_width(document, instruction, name);
                    format!("({} {value})", value_type(width))
                }
                // A scaled immediate is matched as the value the semantics
                // computes, so the instruction is handed the quotient. Without
                // the transform the pattern would encode a byte offset into a
                // field that counts elements.
                _ => {
                    let leaf = format!(
                        "{}:${}",
                        type_of(&operand.name).unwrap_or_default(),
                        tablegen_ident(&operand.name)
                    );
                    match transform_of(&operand.name) {
                        Some(transform) => format!("({transform} {leaf})"),
                        None => leaf,
                    }
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        // The root carries its type explicitly. A class that holds more than
        // one value type -- RISC-V's `rv_gpr` names both 32- and 64-bit
        // operands in the same document -- leaves `(add $a, $b)` ambiguous,
        // and TableGen says so rather than guessing. LLVM's own targets
        // annotate the root for exactly this reason.
        let key = format!("({root_type} {dag})");
        let pat = format!(
            "def : Pat<{key},\n          ({} {rhs})>;\n",
            tablegen_ident(mnemonic).to_uppercase()
        );
        // A pattern selecting an optional ISA's instruction is only available
        // where that instruction is. Without this the selector could pick an
        // instruction the subtarget does not have.
        let text = match isa_predicate(document, &instruction.isa) {
            Some(predicate) => format!("let Predicates = [{predicate}] in\n{pat}"),
            None => pat,
        };
        Ok((key, text))
    }
}

/// The registers of one role, spelled as this target's defs, in declaration
/// order. Order is the content of an argument list: `a0` first is what makes it
/// `a0`.
fn abi_registers(refs: &[RegisterRef]) -> Vec<String> {
    let mut out = Vec::new();
    for reference in refs {
        if let Some(class) = register_class(&reference.class) {
            for index in reference.indices() {
                out.push(format!("{}{index}", reg_prefix(class)));
            }
        }
    }
    out
}

/// Whether every class this ABI names in a role has registers in this target.
/// A class no operand names is not part of the target (`register_files`), so a
/// convention over it would reference defs that do not exist -- and tblgen
/// would say so, which is a worse way to learn it than a named decline.
fn abi_classes_present(abi: &Abi, files: &[RegisterFile]) -> Option<String> {
    let present: std::collections::HashSet<&str> = files
        .iter()
        .flat_map(|file| file.classes.iter().map(|class| class.name))
        .collect();
    for refs in [&abi.arguments, &abi.returns, &abi.callee_saved] {
        for reference in refs {
            let name = register_class(&reference.class).map(|class| class.name);
            match name {
                Some(name) if present.contains(name) => {}
                _ => return Some(reference.class.clone()),
            }
        }
    }
    None
}

/// L4. The calling convention, from the description's own declaration.
///
/// Nothing here is inferred. `CCAssignToReg` takes the argument registers in
/// the order the ABI names them, `CalleeSavedRegs` takes the callee-saved set,
/// and the stack slot is the pointer the ABI says it holds. What makes this
/// worth emitting rather than hand-writing is that LLVM's own
/// `--gen-callingconv` reads it back, and `llvm_target_check.py` compares the
/// register list in that generated C++ against the declaration -- so the two
/// sides of the check are AXIS's Lisp and LLVM's generator, not one emitter
/// agreeing with itself.
fn emit_calling_conventions(out: &mut String, document: &Document, files: &[RegisterFile]) {
    let abis: Vec<&Abi> = document
        .abis
        .iter()
        .filter(|abi| {
            document
                .isas
                .iter()
                .any(|isa| isa.name.eq_ignore_ascii_case(&abi.isa))
        })
        .collect();
    if abis.is_empty() {
        return;
    }
    out.push_str("//===- Calling conventions -----------------------------===//\n\n");
    for abi in abis {
        let name = tablegen_ident(&abi.name).to_uppercase();
        if let Some(missing) = abi_classes_present(abi, files) {
            out.push_str(&format!(
                "// abi {}: declined, register class `{missing}` is named by no operand \
                 in this document and so has no registers here\n\n",
                abi.name
            ));
            continue;
        }
        let pointer_bytes = abi.pointer_bits / 8;
        let value = value_type(abi.pointer_bits);
        let arguments = abi_registers(&abi.arguments);
        let returns = abi_registers(&abi.returns);
        let saved = abi_registers(&abi.callee_saved);
        out.push_str(&format!("// {}\n", abi.description));
        out.push_str(&format!("def CC_{name} : CallingConv<[\n"));
        // F3. An aggregate too large for registers is passed by reference, and
        // LLVM spells "this argument is a block the caller owns" as `byval`.
        // The rule goes first because it is a test on the argument rather than
        // on its type, and a type rule matching first would place the pointer.
        if abi.aggregates.is_some() {
            out.push_str(&format!(
                "  CCIfByVal<CCPassByVal<{pointer_bytes}, {}>>,\n",
                abi.stack_alignment
            ));
        }
        if !arguments.is_empty() {
            out.push_str(&format!(
                "  CCIfType<[{value}], CCAssignToReg<[{}]>>,\n",
                arguments.join(", ")
            ));
        }
        out.push_str(&format!(
            "  CCAssignToStack<{pointer_bytes}, {pointer_bytes}>\n]>;\n\n"
        ));
        out.push_str(&format!("def RetCC_{name} : CallingConv<[\n"));
        if !returns.is_empty() {
            out.push_str(&format!(
                "  CCIfType<[{value}], CCAssignToReg<[{}]>>\n",
                returns.join(", ")
            ));
        }
        out.push_str("]>;\n\n");
        out.push_str(&format!(
            "def CSR_{name} : CalleeSavedRegs<(add {})>;\n\n",
            saved.join(", ")
        ));
    }
}

pub fn emit_llvm_target(document: &Document) -> String {
    let target = target_name(document);
    let files = register_files(document);
    let mut out = String::new();
    out.push_str(&format!(
        "// Generated by AXIS from extension {}.\n// {}\n//\n\
         // A self-contained LLVM target: it includes only llvm/Target/Target.td\n\
         // and defines its own registers, classes and encodings. The encodings\n\
         // are the format layout AXIS proves by roundtrip, not the flat sugar.\n\n",
        document.extension.name, document.extension.description
    ));
    out.push_str("include \"llvm/Target/Target.td\"\n\n");
    emit_registers(&mut out, document, &files);
    emit_state_registers(&mut out, document);
    emit_subtarget_features(&mut out, document);
    emit_instructions(&mut out, document);
    emit_isel_patterns(&mut out, document);
    emit_calling_conventions(&mut out, document, &files);
    out.push_str("//===- Target ------------------------------------------===//\n\n");
    if let Some(file) = files.first() {
        // LLVM's standard pseudo-instructions carry pointer-typed operands and
        // require the target to say which class holds a pointer.
        out.push_str(&format!(
            "defm : RemapAllTargetPseudoPointerOperands<{}>;\n\n",
            class_def(file.classes[0])
        ));
    }
    out.push_str(&format!("def {target}InstrInfo : InstrInfo;\n"));
    out.push_str(&format!(
        "def {target} : Target {{ let InstructionSet = {target}InstrInfo; }}\n"
    ));
    out
}
