//! AXIS emit: lift domain (split from the former monolithic emit.rs).

use super::common::*;
use crate::decode_constraint::{CompareOp, ConstraintValue, DecodeConstraint};

fn operand_role(operand: &Operand) -> &'static str {
    crate::ast::operand_role(operand, false)
}

fn decode_constraint(instruction: &Instruction) -> Option<&DecodeConstraint> {
    instruction.decode_constraint.as_ref()
}

fn lift_constraint_python(instruction: &Instruction) -> Option<String> {
    Some(constraint_python(decode_constraint(instruction)?))
}

fn constraint_python(constraint: &DecodeConstraint) -> String {
    match constraint {
        DecodeConstraint::A64LogicalImmediate { width, n, imms } => {
            let (n_operand, n_literal) = match n {
                ConstraintValue::Operand(name) => (json_string(name), "None".to_string()),
                ConstraintValue::Literal(value) => ("None".to_string(), value.to_string()),
            };
            format!(
                "{{\"kind\": \"a64_logical_imm\", \"width\": {width}, \
                 \"n_operand\": {n_operand}, \"n_literal\": {n_literal}, \
                 \"imms_operand\": {}}}",
                json_string(imms)
            )
        }
        DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        } => format!(
            "{{\"kind\": \"a64_shifted_reg\", \"width\": {width}, \
             \"shift_operand\": {}, \"amount_operand\": {}}}",
            json_string(shift),
            json_string(amount)
        ),
        DecodeConstraint::A64ExtendedRegister { amount } => format!(
            "{{\"kind\": \"a64_extended_reg\", \"amount_operand\": {}}}",
            json_string(amount)
        ),
        DecodeConstraint::UnsignedCompare {
            operand,
            op,
            literal,
        } => format!(
            "{{\"kind\": \"uimm_compare\", \"operand\": {}, \"op\": {}, \"literal\": {literal}}}",
            json_string(operand),
            json_string(op.name())
        ),
        DecodeConstraint::MaskedEq {
            operand,
            mask,
            value,
        } => format!(
            "{{\"kind\": \"uimm_mask_eq\", \"operand\": {}, \"mask\": {mask}, \"value\": {value}}}",
            json_string(operand)
        ),
        DecodeConstraint::And(children) | DecodeConstraint::Or(children) => {
            let kind = if matches!(constraint, DecodeConstraint::And(_)) {
                "and"
            } else {
                "or"
            };
            let children = children
                .iter()
                .map(constraint_python)
                .collect::<Vec<_>>()
                .join(", ");
            format!("{{\"kind\": \"{kind}\", \"constraints\": [{children}]}}")
        }
        DecodeConstraint::Not(child) => format!(
            "{{\"kind\": \"not\", \"constraint\": {}}}",
            constraint_python(child)
        ),
    }
}

fn compare_operator(op: CompareOp) -> &'static str {
    match op {
        CompareOp::Eq => "==",
        CompareOp::Ne => "!=",
        CompareOp::Lt => "<",
        CompareOp::Le => "<=",
        CompareOp::Gt => ">",
        CompareOp::Ge => ">=",
    }
}

fn c_lift_constraint_expr(constraint: &DecodeConstraint) -> String {
    match constraint {
        DecodeConstraint::A64LogicalImmediate { width, n, imms } => {
            let n = match n {
                ConstraintValue::Literal(value) => format!("{value}u"),
                ConstraintValue::Operand(name) => format!(
                    "axis_lift_named_operand(word, entry, {})",
                    c_string(name)
                ),
            };
            format!(
                "axis_a64_logical_imm_valid({width}u, {n}, axis_lift_named_operand(word, entry, {}))",
                c_string(imms)
            )
        }
        DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        } => format!(
            "(axis_lift_named_operand(word, entry, {}) < 3u && axis_lift_named_operand(word, entry, {}) < {width}u)",
            c_string(shift),
            c_string(amount)
        ),
        DecodeConstraint::A64ExtendedRegister { amount } => format!(
            "axis_lift_named_operand(word, entry, {}) < 5u",
            c_string(amount)
        ),
        DecodeConstraint::UnsignedCompare {
            operand,
            op,
            literal,
        } => format!(
            "axis_lift_named_operand(word, entry, {}) {} {literal}u",
            c_string(operand),
            compare_operator(*op)
        ),
        DecodeConstraint::MaskedEq {
            operand,
            mask,
            value,
        } => format!(
            "(axis_lift_named_operand(word, entry, {}) & {mask}u) == {value}u",
            c_string(operand)
        ),
        DecodeConstraint::And(children) | DecodeConstraint::Or(children) => {
            let joiner = if matches!(constraint, DecodeConstraint::And(_)) {
                " && "
            } else {
                " || "
            };
            format!(
                "({})",
                children
                    .iter()
                    .map(c_lift_constraint_expr)
                    .collect::<Vec<_>>()
                    .join(joiner)
            )
        }
        DecodeConstraint::Not(child) => format!("!({})", c_lift_constraint_expr(child)),
    }
}

fn rust_lift_constraint_expr(constraint: &DecodeConstraint) -> String {
    let operand = |name: &str| {
        format!(
            "named_operand(word, entry, {}).expect(\"constraint operand\")",
            json_string(name)
        )
    };
    match constraint {
        DecodeConstraint::A64LogicalImmediate { width, n, imms } => {
            let n = match n {
                ConstraintValue::Literal(value) => value.to_string(),
                ConstraintValue::Operand(name) => operand(name),
            };
            format!("a64_logical_imm_valid({width}, {n}, {})", operand(imms))
        }
        DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        } => format!("({} < 3 && {} < {width})", operand(shift), operand(amount)),
        DecodeConstraint::A64ExtendedRegister { amount } => {
            format!("{} < 5", operand(amount))
        }
        DecodeConstraint::UnsignedCompare {
            operand: name,
            op,
            literal,
        } => format!("{} {} {literal}", operand(name), compare_operator(*op)),
        DecodeConstraint::MaskedEq {
            operand: name,
            mask,
            value,
        } => format!("({} & {mask}) == {value}", operand(name)),
        DecodeConstraint::And(children) | DecodeConstraint::Or(children) => {
            let joiner = if matches!(constraint, DecodeConstraint::And(_)) {
                " && "
            } else {
                " || "
            };
            format!(
                "({})",
                children
                    .iter()
                    .map(rust_lift_constraint_expr)
                    .collect::<Vec<_>>()
                    .join(joiner)
            )
        }
        DecodeConstraint::Not(child) => format!("!({})", rust_lift_constraint_expr(child)),
    }
}

/// Emit the decode-to-semantic-IR lift table (`axis.lift-table.v1`): the
/// inverse of encoding. Per instruction it carries the decode match/mask, the
/// operand extraction fields (instruction-bit slices reassembled into each
/// operand value), the read/write operand roles, and the typed
/// `formal_semantics` AST. A lifter matches a word against match/mask, pulls
/// operand values out with the fields, and binds them into the semantics —
/// the seed for binary translation, trace analysis, and differential testing.
pub fn emit_lift_table_json(document: &Document) -> String {
    let state_names = crate::effects::isa_scalar_state_names(&document.isas);
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"axis.lift-table.v1\",");
    line(
        &mut out,
        1,
        &format!("\"name\": {},", json_string(&document.extension.name)),
    );
    line(
        &mut out,
        1,
        &format!("\"version\": {},", json_string(&document.extension.version)),
    );
    line(&mut out, 1, "\"word_bits\": 32,");
    line(&mut out, 1, "\"instructions\": [");
    for (idx, instruction) in document.instructions.iter().enumerate() {
        let layout = layout_for(document, instruction);
        let encodable = layout.is_encodable();
        let has_semantics = !instruction.formal_semantics.trim().is_empty();
        let writes: Vec<String> = instruction
            .operands
            .iter()
            .filter(|operand| operand.output)
            .map(|operand| operand.name.clone())
            .collect();
        let reads: Vec<String> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .map(|operand| operand.name.clone())
            .collect();
        line(&mut out, 2, "{");
        line(
            &mut out,
            3,
            &format!("\"mnemonic\": {},", json_string(&instruction.mnemonic)),
        );
        // A lane of an instantiated scalable instruction says where it came
        // from here as well as in the golden spec. The same fact published in
        // one artifact and not another is how a consumer ends up re-deriving
        // it, which is the drift this project keeps paying for.
        if !instruction.scalable_origin.is_empty() {
            line(
                &mut out,
                3,
                &format!(
                    "\"scalable_origin\": {},",
                    json_string(&instruction.scalable_origin)
                ),
            );
            line(
                &mut out,
                3,
                &format!("\"scalable_lane\": {},", instruction.scalable_lane),
            );
        }
        if !instruction.isa.is_empty() {
            line(
                &mut out,
                3,
                &format!("\"isa\": {},", json_string(&instruction.isa)),
            );
        }
        // The architectural register/state width, distinct from the 32-bit
        // instruction word: an effect may evaluate in i64 on a 64-bit ISA, and
        // a program counter wraps at this width and not at that one. It does
        // not wait for the ISA to be *named*: a document declaring one ISA
        // leaves an instruction's machine unambiguous whether or not the
        // instruction repeats it, and twenty-one corpora do not repeat it.
        if let Some(isa) = crate::ast::instruction_isa(document, instruction) {
            line(
                &mut out,
                3,
                &format!("\"state_width\": {},", isa.word_bits),
            );
        }
        line(
            &mut out,
            3,
            &format!("\"format\": {},", json_string(&instruction.format)),
        );
        line(
            &mut out,
            3,
            &format!("\"match\": {},", json_hex_u32(layout.match_value)),
        );
        line(
            &mut out,
            3,
            &format!("\"mask\": {},", json_hex_u32(layout.mask_value)),
        );
        // `liftable` means the pure path: decoded operands bind into a
        // `formal_semantics` expression with an `axis_eval_*` body. Effectful
        // instructions are lifted and executed through `effects` instead, so
        // they are `operands_encodable` with a non-null effect list but not
        // `liftable`. The compiled lifters use the same flag to decide whether
        // a pure evaluator exists, so the two meanings must stay identical.
        line(
            &mut out,
            3,
            &format!("\"liftable\": {},", encodable && has_semantics),
        );
        line(
            &mut out,
            3,
            &format!("\"operands_encodable\": {encodable},"),
        );
        line(&mut out, 3, &format!("\"writes\": {},", json_list(&writes)));
        line(&mut out, 3, &format!("\"reads\": {},", json_list(&reads)));
        // The registers the behavior names itself, which no operand carries.
        // Emitted only when there are some, so a description with none is the
        // byte-identical artifact it was before this field existed.
        let register_reads = crate::effects::behavior_register_reads(instruction);
        if !register_reads.is_empty() {
            let entries: Vec<String> = register_reads
                .iter()
                .map(|(kind, index)| {
                    format!("{{\"kind\": {}, \"index\": {index}}}", json_string(kind))
                })
                .collect();
            line(
                &mut out,
                3,
                &format!("\"reads_registers\": [{}],", entries.join(", ")),
            );
        }
        if !instruction.decode_requires.trim().is_empty() {
            line(
                &mut out,
                3,
                &format!(
                    "\"decode_requires\": {},",
                    json_string(instruction.decode_requires.trim())
                ),
            );
        }
        line(&mut out, 3, "\"operands\": [");
        for (op_idx, operand) in instruction.operands.iter().enumerate() {
            emit_lift_operand_json(
                &mut out,
                operand,
                &layout,
                4,
                op_idx + 1 == instruction.operands.len(),
            );
        }
        line(&mut out, 3, "],");
        line(
            &mut out,
            3,
            &format!(
                "\"semantics\": {},",
                semantic_ast_json(&instruction.formal_semantics)
            ),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"semantics_ast\": {},",
                semantic_ast_json(&instruction.formal_semantics)
            ),
        );
        // The same ordered effect program the Python/C/Rust lifters execute, so
        // a JSON consumer sees memory, control flow, traps, and named state
        // rather than a bare `"semantics": null`.
        line(
            &mut out,
            3,
            &format!(
                "\"effects\": {},",
                lift_effect_list(instruction, EffectLiterals::Json)
            ),
        );
        line(
            &mut out,
            3,
            &format!(
                "\"effect_summary\": {}",
                effect_summary_json(instruction, &state_names)
            ),
        );
        let suffix = if idx + 1 == document.instructions.len() {
            ""
        } else {
            ","
        };
        line(&mut out, 2, &format!("}}{suffix}"));
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

/// The per-instruction effect summary (`docs/effects_design.md` section 6):
/// what an instruction touches beyond its own operands. Consumers use it to
/// decide purity (LLVM memory attributes), scheduling constraints, and whether
/// a lifted block can be reordered — questions answerable from the flags alone,
/// without walking the effect expressions.
fn effect_summary_json(instruction: &Instruction, state_names: &[String]) -> String {
    let summary = crate::effects::effect_summary(instruction, state_names);
    format!(
        "{{\"reads_memory\": {}, \"writes_memory\": {}, \"reads_state\": {}, \
         \"writes_state\": {}, \"writes_pc\": {}, \"may_trap\": {}, \"barrier\": {}}}",
        summary.reads_memory,
        summary.writes_memory,
        summary.reads_state,
        summary.writes_state,
        summary.writes_pc,
        summary.may_trap,
        summary.barrier
    )
}

fn emit_lift_operand_json(
    out: &mut String,
    operand: &Operand,
    layout: &InstructionLayout,
    indent: usize,
    last: bool,
) {
    let role = operand_role(operand);
    let fields: Vec<String> = layout
        .operand_bindings(&operand.name)
        .iter()
        .map(|binding| {
            format!(
                "{{\"insn_lo\": {}, \"op_lo\": {}, \"width\": {}}}",
                binding.insn_lo, binding.op_lo, binding.width
            )
        })
        .collect();
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"name\": {},", json_string(&operand.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"kind\": {},", json_string(&operand.kind)),
    );
    line(
        out,
        indent + 1,
        &format!("\"role\": {},", json_string(role)),
    );
    line(out, indent + 1, &format!("\"width\": {},", operand.width));
    if operand.lane_packed {
        line(
            out,
            indent + 1,
            &format!(
                "\"packing\": {{\"lane\": {}, \"register\": {}, \"element\": {}}},",
                operand.lane_index, operand.lane_register, operand.lane_element
            ),
        );
    }
    // Where the operand's bits are, when the register class cannot say. A
    // consumer applies these instead of recomputing them from the packing --
    // the same reason the slot offset is published rather than each driver
    // spelling `index + offset` for itself.
    if operand.view_width != 0 || operand.slot_stride != 0 {
        line(
            out,
            indent + 1,
            &format!(
                "\"placement\": {{\"stride\": {}, \"offset\": {}, \"width\": {}, \"base\": {}}},",
                operand.slot_stride, operand.view_offset, operand.view_width,
                operand.slot_base
            ),
        );
    }
    if let Some(index) = operand.fixed {
        line(out, indent + 1, &format!("\"fixed\": {index},"));
    }
    if !operand.derived_from.is_empty() {
        line(
            out,
            indent + 1,
            &format!(
                "\"derived\": {{\"from\": {}, \"add\": {}}},",
                json_string(&operand.derived_from),
                operand.derived_add
            ),
        );
    }
    line(
        out,
        indent + 1,
        &format!("\"fields\": [{}]", fields.join(", ")),
    );
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

/// Emit a standalone Python lifter (`axis.lift-python.v1`) that embeds the
/// lift table and reconstructs decoded instructions: `decode(word)` matches
/// the fixed bits, `lift(word)` additionally extracts operand values and
/// returns them bound alongside the raw `formal_semantics`. Runnable with no
/// dependency — the seed for trace tools and differential lift checks.
pub fn emit_lift_python(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("# Generated by AXIS. Standalone instruction lifter (decode -> semantic IR).\n\n");
    out.push_str("AXIS_SCHEMA = \"axis.lift-python.v1\"\n");
    out.push_str("WORD_BITS = 32\n\n");
    // One definition of "this operand names a register", for every consumer
    // that has to tell a register from a literal. Testing `kind == "reg"`
    // locally is what four harnesses did, and it silently classified every
    // AArch64 register as an immediate — an operand's kind there is its
    // register class (`a64_gpr64sp`) — so they fed the register *number* in as
    // its value and still reported PASS.
    out.push_str(
        &"# Operand kinds that name an architectural register rather than a literal.\n\
         # Consumers must test membership here instead of comparing against \"reg\":\n\
         # an AArch64 operand's kind is its register class, so `kind == \"reg\"`\n\
         # misclassifies every one of them as an immediate.\n\
         REGISTER_KINDS = (PLACEHOLDER)\n\
         \n\
         # How each class reads and writes:\n\
         # (zero_index, alias, view_width, offset, view_offset, preserves, limbs,\n\
         #  index_offset).\n\
         # `zero_index` reads as 0 and discards writes; `alias` is an\n\
         # (index, state-name) pair naming a state slot instead of the register\n\
         # file; `view_width` is the architectural read width when narrower than\n\
         # the file; `offset` is where the class starts in the flat register\n\
         # array, which is how an architecture with more than one register file\n\
         # is modelled; `limbs` is how many 64-bit slots one register of the\n\
         # class occupies, so a register wider than a machine word is stored as\n\
         # consecutive slots rather than as one unbounded number. Consumers\n\
         # apply these rather than testing for an ISA.\n\
         REGISTER_CLASSES = {@CLASSES@}\n\
         \n\
         \n\
         def register_slot(kind, index):\n\
         \x20   \"\"\"The flat-array slot register `index` of `kind` starts at.\n\
         \n\
         \x20   One definition because it had four copies, each spelling it\n\
         \x20   `index + offset` -- correct only while every register fits in one\n\
         \x20   slot. A class with limbs > 1 strides by its limb count, and one\n\
         \x20   with an `index_offset` starts partway into its file: RISC-V's\n\
         \x20   compressed forms name `x8`-`x15` with three bits, so the field's\n\
         \x20   0 is the file's 8. This had the limb fix and not that one, so it\n\
         \x20   disagreed with the C helper -- which had both -- about which\n\
         \x20   register a compressed instruction touched.\n\
         \x20   \"\"\"\n\
         \x20   entry = REGISTER_CLASSES[kind]\n\
         \x20   return entry[3] + (entry[7] + index) * entry[6]\n\
         \n\
         \n\
         def is_register_operand(kind):\n\
         \x20   \"\"\"Whether an operand of this kind names a register.\"\"\"\n\
         \x20   return kind in REGISTER_KINDS\n\
         \n\
         \n\
         # Slots a caller must provide for an `axis_eff_*` function's `out`\n\
         # array: [value0, wrote0, next_pc, trap, value1, wrote1, ...]. Write k\n\
         # is the k-th register-writing effect below, in order, so a consumer\n\
         # maps writes to registers from `effects` without guessing. Size the\n\
         # array by this constant whatever the instruction -- a function writes\n\
         # only the slots it needs, but a short array is an overrun, not a\n\
         # wrong answer.\n\
         # Slots a flat register file needs to hold every class, given the\n\
         # offsets above. A consumer that sizes its register array by 32 works\n\
         # until an architecture has a second register file.\n\
         REGISTER_FILE_SLOTS = @FILE_SLOTS@\n\
         \n\
         EFFECT_OUT_SLOTS = @SLOTS@\n\
         EFFECT_MAX_WRITES = @WRITES@\n\
         \n\
         # Scalar architectural state an `axis_eff_*` function reads and writes\n\
         # through its `state` array, in slot order, with each entry's declared\n\
         # width. Register *files* are addressed through operands and are not\n\
         # here; `pc` has its own parameter.\n\
         STATE_SLOTS = (@STATE@)\n\
         \n\
         \n"
            .replace(
                "@STATE@",
                &crate::effects::isa_scalar_state_slots(&document.isas)
                    .iter()
                    .map(|(name, width)| format!("(\"{name}\", {width}),"))
                    .collect::<Vec<_>>()
                    .join(" "),
            )
            .replace(
                "@CLASSES@",
                &crate::ast::REGISTER_CLASSES
                    .iter()
                    .map(|class| {
                        let zero = class
                            .zero_index
                            .map(|index| index.to_string())
                            .unwrap_or_else(|| "None".to_string());
                        let alias = class
                            .alias
                            .map(|(index, name)| format!("({index}, \"{name}\")"))
                            .unwrap_or_else(|| "None".to_string());
                        let view = class
                            .view_width
                            .map(|width| width.to_string())
                            .unwrap_or_else(|| "None".to_string());
                        let preserves = matches!(
                            class.write_policy,
                            crate::ast::WritePolicy::Preserve
                        );
                        // Appended rather than inserted: consumers index this
                        // tuple positionally, so growing it at the end leaves
                        // every existing reader correct.
                        format!(
                            "\"{}\": ({zero}, {alias}, {view}, {}, {}, {}, {}, {}),",
                            class.name,
                            class.offset,
                            class.view_offset,
                            if preserves { "True" } else { "False" },
                            class.limbs.max(1),
                            class.index_offset
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" "),
            )
            .replace(
                "@FILE_SLOTS@",
                &crate::ast::register_file_slots(document).to_string(),
            )
            .replace("@SLOTS@", &crate::effects::EFFECT_OUT_SLOTS.to_string())
            .replace("@WRITES@", &crate::effects::EFFECT_MAX_WRITES.to_string())
            .replace(
                "PLACEHOLDER",
                &crate::ast::REGISTER_CLASSES
                    .iter()
                    .map(|class| format!("\"{}\"", class.name))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
    );
    out.push_str("AXIS_LIFT_TABLE = [\n");
    for instruction in &document.instructions {
        let layout = layout_for(document, instruction);
        out.push_str("    {\n");
        out.push_str(&format!(
            "        \"mnemonic\": {},\n",
            json_string(&instruction.mnemonic)
        ));
        if !instruction.isa.is_empty() {
            out.push_str(&format!(
                "        \"isa\": {},\n",
                json_string(&instruction.isa)
            ));
        }
        // The state width does not wait for the ISA to be *named*: a document
        // with one ISA leaves an instruction's machine unambiguous whether or
        // not the instruction repeats it.
        if let Some(isa) = crate::ast::instruction_isa(document, instruction) {
            out.push_str(&format!("        \"state_width\": {},\n", isa.word_bits));
        }
        // ⚠️ What performs this instruction, when nothing here does. The
        // reference executor could not tell "this word does not decode" from
        // "it decodes and this build has no implementation": an instruction
        // naming a routine fell through to `undecoded`, while the C executor
        // called the routine and reported `unimplemented`. Two backends
        // disagreeing about why they stopped, with the reference giving the
        // less true answer.
        let answer = instruction.implementation.trim();
        if !answer.is_empty() {
            out.push_str(&format!(
                "        \"implementation\": {},\n",
                json_string(answer)
            ));
        }
        out.push_str(&format!(
            "        \"match\": 0x{:08x},\n",
            layout.match_value
        ));
        out.push_str(&format!("        \"mask\": 0x{:08x},\n", layout.mask_value));
        let writes: Vec<String> = instruction
            .operands
            .iter()
            .filter(|operand| operand.output)
            .map(|operand| json_string(&operand.name))
            .collect();
        let reads: Vec<String> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .map(|operand| json_string(&operand.name))
            .collect();
        out.push_str(&format!("        \"writes\": [{}],\n", writes.join(", ")));
        out.push_str(&format!("        \"reads\": [{}],\n", reads.join(", ")));
        let register_reads = crate::effects::behavior_register_reads(instruction);
        if !register_reads.is_empty() {
            let entries: Vec<String> = register_reads
                .iter()
                .map(|(kind, index)| {
                    format!("{{\"kind\": {}, \"index\": {index}}}", json_string(kind))
                })
                .collect();
            out.push_str(&format!(
                "        \"reads_registers\": [{}],\n",
                entries.join(", ")
            ));
        }
        // Which scalable instruction this entry is a lane of. Published here
        // because decode needs it: every lane of one origin carries the same
        // encoding, so "several matches" means "one instruction, several
        // lanes" rather than an ambiguous decode space.
        if !instruction.scalable_origin.is_empty() {
            out.push_str(&format!(
                "        \"scalable_origin\": {},\n        \"scalable_lane\": {},\n",
                json_string(&instruction.scalable_origin),
                instruction.scalable_lane
            ));
        }
        // A definedness mask shares its instruction's word. Enumerating what a
        // word decodes to has to skip it, or a scalable instruction executes
        // each lane twice -- once as itself and once as the question of
        // whether it was defined.
        if !instruction.definedness_of.is_empty() {
            out.push_str(&format!(
                "        \"definedness_of\": {},\n",
                json_string(&instruction.definedness_of)
            ));
        }
        if let Some(constraint) = lift_constraint_python(instruction) {
            out.push_str(&format!("        \"decode_constraint\": {constraint},\n"));
        }
        out.push_str("        \"operands\": [\n");
        for operand in &instruction.operands {
            let role = operand_role(operand);
            let fields: Vec<String> = layout
                .operand_bindings(&operand.name)
                .iter()
                .map(|binding| {
                    format!(
                        "({}, {}, {})",
                        binding.insn_lo, binding.op_lo, binding.width
                    )
                })
                .collect();
            let derived = if let Some(index) = operand.fixed {
                format!(", \"fixed\": {index}")
            } else if operand.derived_from.is_empty() {
                String::new()
            } else {
                format!(
                    ", \"derived_from\": {}, \"derived_add\": {}",
                    json_string(&operand.derived_from),
                    operand.derived_add
                )
            };
            // Where this operand's bits sit inside the register it names, when
            // the class cannot say -- an element of a scalable register, whose
            // position depends on VL and the element width rather than on the
            // architecture.
            let placement = if operand.view_width == 0 && operand.slot_stride == 0 {
                String::new()
            } else {
                format!(
                    ", \"stride\": {}, \"view_offset\": {}, \"view_width\": {}, \"register_bias\": {}, \"slot_base\": {}, \"lane\": {}",
                    operand.slot_stride,
                    operand.view_offset,
                    operand.view_width,
                    operand.lane_register,
                    operand.slot_base,
                    // Which lane this operand is. Not derivable from the view
                    // offset without assuming the very lane-to-element map a
                    // consumer would be checking.
                    operand.lane_index
                )
            };
            // The operand's declared width, so a consumer can tell whether an
            // instruction fits its ABI. The compact executors are 32-bit and had
            // no way to know that a double-precision operand does not: they
            // decided by testing the ISA's word width, which is 32 for RV32 even
            // when the D extension puts 64-bit values in its float registers.
            out.push_str(&format!(
                "            {{\"name\": {}, \"kind\": {}, \"role\": {}, \"width\": {}, \"fields\": [{}]{derived}{placement}}},\n",
                json_string(&operand.name),
                json_string(&operand.kind),
                json_string(role),
                operand.width,
                fields.join(", ")
            ));
        }
        out.push_str("        ],\n");
        let semantics = instruction.formal_semantics.trim();
        // The tree beside it, under the name both tables use. The JSON table's
        // `semantics` has always *been* a tree and Python's has always been the
        // text; `semantics_ast` means the same thing in both, so a consumer
        // moving between them does not have to know that history.
        let semantics_ast = semantic_ast_json(semantics);
        out.push_str(&format!(
            "        \"semantics_ast\": {},\n",
            // JSON's absent is `null` and Python's is `None`; the tree itself
            // contains neither, so only the empty case has to be spelled.
            if semantics_ast == "null" { "None".to_string() } else { semantics_ast }
        ));
        if semantics.is_empty() {
            out.push_str("        \"semantics\": None,\n");
        } else {
            out.push_str(&format!(
                "        \"semantics\": {},\n",
                json_string(semantics)
            ));
        }
        // Effectful instructions (memory load/store) carry their effect list
        // here so the executor can apply it against a memory model.
        out.push_str(&format!(
            "        \"effects\": {},\n",
            lift_effect_python(instruction)
        ));
        // Mode-aware decode (P4): the legal modes (empty = all). Only emitted
        // when the document declares a mode, so mode-free tables are unchanged.
        if !document.modes.is_empty() {
            let modes = instruction
                .modes
                .iter()
                .map(|mode| json_string(mode))
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!("        \"modes\": [{modes}],\n"));
        }
        // Slot-aware decode (B1): the unit class that executes this
        // instruction. Only emitted when the document declares a packet, so a
        // single-issue table is unchanged.
        if !document.packets.is_empty() {
            out.push_str(&format!(
                "        \"unit\": {},\n",
                json_string(&crate::ast::canonical_unit(&instruction.unit))
            ));
            // Under `hazards exposed` this stops being cost metadata and
            // becomes architectural: the packet a result is visible to.
            out.push_str(&format!(
                "        \"latency\": {},\n",
                instruction.latency_cycles
            ));
        }
        out.push_str("    },\n");
    }
    out.push_str("]\n\n");
    out.push_str(&emit_packet_table_python(document));
    out.push_str(LIFT_PY_RUNTIME);
    out
}

/// The packet table for the Python lifter (stage B1).
///
/// Empty for a document with no packet, which is what keeps every existing
/// `axis_lift.py` byte-identical apart from the constant below.
fn emit_packet_table_python(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("AXIS_PACKETS = {\n");
    for packet in &document.packets {
        out.push_str(&format!("    {}: {{\n", json_string(&packet.name)));
        out.push_str(&format!("        \"isa\": {},\n", json_string(&packet.isa)));
        out.push_str(&format!(
            "        \"order\": {},\n",
            json_string(&packet.order)
        ));
        out.push_str(&format!("        \"end\": {},\n", json_string(&packet.end)));
        out.push_str(&format!("        \"stop_bit\": {},\n", packet.stop_bit));
        out.push_str(&format!(
            "        \"hazards\": {},\n",
            json_string(&packet.hazards)
        ));
        out.push_str(&format!(
            "        \"branches\": {},\n",
            json_string(&packet.branches)
        ));
        // The delay queue's shape, derived once (`validate::packet_delay_queue`)
        // and read by both the executor and the capsule layout.
        let delay = crate::validate::packet_delay_queue(document, packet);
        out.push_str(&format!(
            "        \"delay_stages\": {},\n",
            delay.as_ref().map(|delay| delay.stages).unwrap_or(0)
        ));
        out.push_str(&format!(
            "        \"delay_entries_per_stage\": {},\n",
            delay
                .as_ref()
                .map(|delay| delay.entries_per_stage)
                .unwrap_or(0)
        ));
        out.push_str("        \"slots\": (\n");
        for slot in &packet.slots {
            let units = slot
                .units
                .iter()
                .map(|unit| json_string(&crate::ast::canonical_unit(unit)))
                .collect::<Vec<_>>()
                .join(", ");
            let trailing = if slot.units.len() == 1 { "," } else { "" };
            out.push_str(&format!(
                "            {{\"name\": {}, \"width\": {}, \"units\": ({units}{trailing})}},\n",
                json_string(&slot.name),
                slot.width
            ));
        }
        out.push_str("        ),\n");
        out.push_str("    },\n");
    }
    out.push_str("}\n\n");
    out
}

/// How to spell booleans and absence in the artifact being generated. The
/// effect list is structurally identical in the Python lifter and the JSON lift
/// table, so both render through one function; only these literals differ.
/// Emitting the list twice is what let the JSON artifact silently fall behind
/// the executable lifters.
#[derive(Clone, Copy)]
enum EffectLiterals {
    Python,
    Json,
}

impl EffectLiterals {
    fn boolean(self, value: bool) -> &'static str {
        match (self, value) {
            (Self::Python, true) => "True",
            (Self::Python, false) => "False",
            (Self::Json, true) => "true",
            (Self::Json, false) => "false",
        }
    }

    fn absent(self) -> &'static str {
        match self {
            Self::Python => "None",
            Self::Json => "null",
        }
    }

    /// The tree beside the text (X1), for the JSON table only.
    ///
    /// The executable lifters do not get it: they hand their expression to the
    /// golden model, which parses it, so a tree there would be a second copy
    /// of something already being read. The table's readers are the ones with
    /// no parser -- and writing one is what
    /// `pce/aha/optisynth/adl_bridge.py` did, and what
    /// `docs/binary_lift_design.md` §1 is about.
    fn ast(self, field: &str, rendered: &str) -> String {
        // Both tables now. The Python lifter carries `lift_block`, which
        // instantiates these trees and threads them into a graph -- so it is a
        // consumer of them, not a producer that could hand the text to the
        // golden model. A tree of AXIS expressions holds only strings, lists
        // and maps, so one rendering serves JSON and Python literals alike.
        format!(", \"{field}\": {}", semantic_ast_json(rendered))
    }
}

/// Python literal for an instruction's effect list (see [`lift_effect_list`]).
fn lift_effect_python(instruction: &Instruction) -> String {
    lift_effect_list(instruction, EffectLiterals::Python)
}

/// An instruction's effect list, or absent for pure instructions (which the
/// executor runs via the golden semantics). Each entry is a `set` (write a
/// register; the value may load memory), `setstate` (write named architectural
/// state), `store` (write memory), `barrier` (ordering/synchronization event),
/// `setpc` (branch target), or `trap`; a guarded effect carries a `guard`
/// comparison.
fn lift_effect_list(instruction: &Instruction, literals: EffectLiterals) -> String {
    use crate::effects::Loc;
    if !crate::effects::behavior_is_authoritative(instruction) {
        return literals.absent().to_string();
    }
    let Some(behavior) = instruction.behavior.as_ref() else {
        return literals.absent().to_string();
    };
    let render = render_exec_semexpr;
    let entries: Vec<String> = behavior
        .effects
        .iter()
        .map(|effect| {
            let mut fields = match &effect.loc {
                Loc::Reg(dest) => {
                    let width = instruction
                        .operands
                        .iter()
                        .find(|operand| &operand.name == dest)
                        .map(|operand| operand.width)
                        .unwrap_or(32);
                    format!(
                        "\"kind\": \"set\", \"dest\": {}, \"width\": {width}, \"value\": {}{}",
                        json_string(dest),
                        json_string(&render(&effect.value.expr)),
                        literals.ast("value_ast", &render(&effect.value.expr))
                    )
                }
                Loc::FixedReg {
                    kind,
                    index,
                    width,
                } => format!(
                    "\"kind\": \"setreg\", \"reg_kind\": {}, \"index\": {index}, \"width\": {width}, \"value\": {}{}",
                    json_string(kind),
                    json_string(&render(&effect.value.expr)),
                    literals.ast("value_ast", &render(&effect.value.expr))
                ),
                Loc::State { name, width } => format!(
                    "\"kind\": \"setstate\", \"state\": {}, \"width\": {width}, \"value\": {}{}",
                    json_string(name),
                    json_string(&render(&effect.value.expr)),
                    literals.ast("value_ast", &render(&effect.value.expr))
                ),
                Loc::Mem { addr, width, order, atomic } => format!(
                    "\"kind\": \"store\", \"width\": {width}, \"memory_order\": {}, \"atomic\": {}, \"addr\": {}{}, \"value\": {}{}",
                    json_string(order.as_str()),
                    literals.boolean(*atomic),
                    json_string(&render(&addr.expr)),
                    literals.ast("addr_ast", &render(&addr.expr)),
                    json_string(&render(&effect.value.expr)),
                    literals.ast("value_ast", &render(&effect.value.expr))
                ),
                Loc::Barrier { kind, width } => format!(
                    "\"kind\": \"barrier\", \"barrier\": {}, \"width\": {width}, \"value\": {}{}",
                    json_string(kind),
                    json_string(&render(&effect.value.expr)),
                    literals.ast("value_ast", &render(&effect.value.expr))
                ),
                // A send publishes both halves: where it goes and what goes.
                // A consumer joining on `kind` gets the same shape a store
                // gives it, with `port` where `addr` would be.
                Loc::Port { port, width } => format!(
                    "\"kind\": \"send\", \"width\": {width}, \"port\": {}{}, \"value\": {}{}",
                    json_string(&render(&port.expr)),
                    literals.ast("port_ast", &render(&port.expr)),
                    json_string(&render(&effect.value.expr)),
                    literals.ast("value_ast", &render(&effect.value.expr))
                ),
                Loc::Pc => format!(
                    "\"kind\": \"setpc\", \"value\": {}{}",
                    json_string(&render(&effect.value.expr)),
                    literals.ast("value_ast", &render(&effect.value.expr))
                ),
                Loc::Trap => format!(
                    "\"kind\": \"trap\", \"cause\": {}",
                    json_string(&render(&effect.value.expr))
                ),
            };
            if !matches!(effect.loc, Loc::Trap) {
                fields.push_str(&format!(", \"eval_width\": {}", effect.value.width));
            }
            if let Some(width) = effect.value.load_address_width {
                fields.push_str(&format!(", \"load_address_width\": {width}"));
                fields.push_str(&format!(
                    ", \"atomic\": {}",
                    literals.boolean(effect.value.load_atomic)
                ));
                fields.push_str(&format!(
                    ", \"memory_order\": {}",
                    json_string(effect.value.load_order.as_str())
                ));
            }
            if let Loc::Mem { addr, .. } = &effect.loc {
                fields.push_str(&format!(", \"addr_width\": {}", addr.width));
            }
            // The width the port expression evaluates at, for the same reason
            // a store publishes its address width: a consumer that guessed it
            // from the payload would evaluate a machine-wide destination at the
            // message's width.
            if let Loc::Port { port, .. } = &effect.loc {
                fields.push_str(&format!(", \"port_width\": {}", port.width));
            }
            if let Some(guard) = &effect.guard {
                fields.push_str(&format!(
                    ", \"guard\": {}{}, \"guard_width\": {}",
                    json_string(&render(&guard.expr)),
                    literals.ast("guard_ast", &render(&guard.expr)),
                    guard.width
                ));
                // Only when the guard reads memory, so every fixture without
                // such a guard is the one it was. A guard compares at its
                // operands' width; its loads' addresses are machine-wide.
                if let Some(width) = guard.load_address_width {
                    fields.push_str(&format!(", \"guard_load_address_width\": {width}"));
                }
            }
            if effect.atomic_group != 0 {
                fields.push_str(&format!(", \"atomic_group\": {}", effect.atomic_group));
            }
            format!("{{{fields}}}")
        })
        .collect();
    format!("[{}]", entries.join(", "))
}

fn render_exec_semexpr(expr: &SemanticExpr) -> String {
    match expr {
        SemanticExpr::Atom(atom) => atom.clone(),
        SemanticExpr::List(items) if matches!(items.as_slice(), [SemanticExpr::Atom(op), SemanticExpr::Atom(_)] if op == "input") =>
        {
            let SemanticExpr::Atom(name) = &items[1] else {
                unreachable!()
            };
            format!("__input_{name}")
        }
        SemanticExpr::List(items) => format!(
            "({})",
            items
                .iter()
                .map(render_exec_semexpr)
                .collect::<Vec<_>>()
                .join(" ")
        ),
    }
}

const LIFT_PY_RUNTIME: &str = r#"def _extract(word, fields):
    value = 0
    for insn_lo, op_lo, width in fields:
        piece = (word >> insn_lo) & ((1 << width) - 1)
        value |= piece << op_lo
    return value


def place_operand(word, entry, name, value):
    """The word with operand `name` set to `value` -- the inverse of `_extract`.

    A packet gate has to build syllables that read and write registers it
    chooses, and the fixtures only carry one operand assignment each. Writing
    the inverse here rather than in the caller keeps the field placement in the
    one place that already knows it; `_extract(place_operand(w, e, n, v)) == v`
    is the property, and the gate asserts it rather than assuming it.
    """
    for operand in entry["operands"]:
        if operand["name"] != name:
            continue
        for insn_lo, op_lo, width in operand["fields"]:
            mask = (1 << width) - 1
            piece = (value >> op_lo) & mask
            word = (word & ~(mask << insn_lo)) | (piece << insn_lo)
        return word
    raise KeyError(name)


def _operand_value(word, entry, name):
    for operand in entry["operands"]:
        if operand["name"] == name:
            return _extract(word, operand["fields"])
    return None


def _constraint_node_ok(word, entry, constraint):
    if constraint["kind"] == "a64_logical_imm":
        n = constraint["n_literal"]
        if constraint["n_operand"] is not None:
            n = _operand_value(word, entry, constraint["n_operand"])
        imms = _operand_value(word, entry, constraint["imms_operand"])
        if n is None or imms is None or (constraint["width"] == 32 and n != 0):
            return False
        encoded = ((n & 1) << 6) | ((~imms) & 0x3f)
        length = encoded.bit_length() - 1
        if length < 1:
            return False
        levels = (1 << length) - 1
        return (imms & levels) != levels
    if constraint["kind"] == "a64_shifted_reg":
        shift = _operand_value(word, entry, constraint["shift_operand"])
        amount = _operand_value(word, entry, constraint["amount_operand"])
        return (
            shift is not None and amount is not None
            and shift < 3 and amount < constraint["width"]
        )
    if constraint["kind"] == "a64_extended_reg":
        amount = _operand_value(word, entry, constraint["amount_operand"])
        return amount is not None and amount < 5
    if constraint["kind"] == "uimm_compare":
        value = _operand_value(word, entry, constraint["operand"])
        if value is None:
            return False
        literal = constraint["literal"]
        return {
            "eq": value == literal,
            "ne": value != literal,
            "lt": value < literal,
            "le": value <= literal,
            "gt": value > literal,
            "ge": value >= literal,
        }.get(constraint["op"], False)
    if constraint["kind"] == "uimm_mask_eq":
        value = _operand_value(word, entry, constraint["operand"])
        return value is not None and (value & constraint["mask"]) == constraint["value"]
    if constraint["kind"] == "and":
        return all(_constraint_node_ok(word, entry, child)
                   for child in constraint["constraints"])
    if constraint["kind"] == "or":
        return any(_constraint_node_ok(word, entry, child)
                   for child in constraint["constraints"])
    if constraint["kind"] == "not":
        return not _constraint_node_ok(word, entry, constraint["constraint"])
    return False


def _constraint_ok(word, entry):
    constraint = entry.get("decode_constraint")
    return constraint is None or _constraint_node_ok(word, entry, constraint)


def decode(word, isa=None):
    """Return the matching entry, optionally narrowed to an ISA.

    A scalable instruction instantiates to one entry per lane, and every lane
    carries the same encoding -- they are one instruction, which is why the
    decode-disjointness rule exempts them from contending with each other.
    Several matches from a single origin is therefore not ambiguity, and decode
    names lane 0; `decode_lanes` returns the whole group.
    """
    matches = decode_lanes(word, isa)
    return matches[0] if len(matches) == 1 else (matches[0] if matches else None)


def decode_lanes(word, isa=None):
    """Every entry `word` encodes, in lane order.

    One entry for an ordinary instruction, `VL/elem` for a scalable one --
    which is what executing a scalable word means: run each lane. Empty when
    the word decodes to nothing, and empty when it matches entries that are
    *not* one instruction, since that is real ambiguity.
    """
    matches = [
        entry for entry in AXIS_LIFT_TABLE
        if (word & entry["mask"]) == entry["match"]
        and (isa is None or not entry.get("isa") or entry["isa"] == isa)
        and not entry.get("definedness_of")
        and _constraint_ok(word, entry)
    ]
    if len(matches) <= 1:
        return matches
    origins = {entry.get("scalable_origin", "") for entry in matches}
    if len(origins) != 1 or "" in origins:
        return []
    return sorted(matches, key=lambda entry: entry.get("scalable_lane", 0))


def lift(word, isa=None):
    """Decode `word` and lift it to a bound semantic-IR record.

    Returns a dict with the mnemonic, the extracted operand values (None for
    operands AXIS cannot encode), the read/write operand names, and the raw
    formal-semantics expression (None when the instruction has none).
    """
    entry = decode(word, isa)
    return None if entry is None else lift_entry(word, entry)


def lift_entry(word, entry):
    """Bind `word`'s operands to an entry decode has already chosen.

    A syllable in a packet is decoded by *position*, so the caller holds the
    entry and plain `lift` would re-decode -- and re-decoding a word two slots
    can hold reports ambiguity, which is true of the word and false of the
    syllable. One extraction, two ways in.
    """
    operands = {}
    for operand in entry["operands"]:
        fields = operand["fields"]
        operands[operand["name"]] = _extract(word, fields) if fields else operand.get("fixed")
    for operand in entry["operands"]:
        source = operand.get("derived_from")
        if source:
            operands[operand["name"]] = operands[source] + operand["derived_add"]
    return {
        "mnemonic": entry["mnemonic"],
        "operands": operands,
        "reads": entry["reads"],
        "writes": entry["writes"],
        "semantics": entry["semantics"],
    }


def packet(name=None):
    """The named packet, or the only one when a document declares one."""
    if name is not None:
        return AXIS_PACKETS.get(name)
    if len(AXIS_PACKETS) == 1:
        return next(iter(AXIS_PACKETS.values()))
    return None


def decode_slot(word, slot, isa=None):
    """The entry `word` encodes *in this slot*, or None.

    A slot narrows the decode to instructions its unit set holds, and that is
    what lets two instructions share a word: VSTW and VBRZ are one bit pattern
    and two syllable positions, so `decode` alone reports ambiguity (correctly)
    and neither the machine nor this function ever faces it.
    """
    units = slot["units"]
    matches = [
        entry for entry in AXIS_LIFT_TABLE
        if (word & entry["mask"]) == entry["match"]
        and (isa is None or not entry.get("isa") or entry["isa"] == isa)
        and not entry.get("definedness_of")
        and entry.get("unit", "") in units
        and _constraint_ok(word, entry)
    ]
    return matches[0] if len(matches) == 1 else None


def packet_syllables(words, name=None, isa=None):
    """How many of `words` this packet's end rule takes as one group.

    `fixed` takes every slot. `stop_bit` reads the continuation bit of each
    syllable in turn, so a group is however many syllables it takes to reach a
    cleared one -- which is the rule the assembler and the decoder must share,
    and the reason the bit position is declared rather than conventional.
    """
    shape = packet(name)
    if shape is None:
        return 0
    slots = shape["slots"]
    if shape["end"] != "stop_bit":
        return min(len(slots), len(words))
    for index in range(min(len(slots), len(words))):
        if not (words[index] >> shape["stop_bit"]) & 1:
            return index + 1
    return min(len(slots), len(words))


def decode_packet(words, name=None, isa=None):
    """Decode a container of syllables into its slot-assigned entries.

    Returns a list of `{"slot", "index", "word", "entry"}` in slot order, or
    None when any syllable does not decode in the slot it occupies. An empty
    slot is not expressible in stage B1: a fixed packet is full, and a stop-bit
    packet ends rather than skips.
    """
    shape = packet(name)
    if shape is None:
        return None
    count = packet_syllables(words, name, isa)
    if count == 0:
        return None
    resolved = []
    for index in range(count):
        slot = shape["slots"][index]
        entry = decode_slot(words[index], slot, isa or shape["isa"] or None)
        if entry is None:
            return None
        resolved.append({
            "slot": slot["name"],
            "index": index,
            "word": words[index],
            "entry": entry,
        })
    return resolved


def _block_location(entry, operand_name, values):
    """The **storage** an operand names, or None if it names none.

    Not `(class, index)`. x86's `x86_r8hi`, `x86_r8lo`, `x86_r16`, `x86_r32`
    and `x86_r64` are five views of *one* register and all map to one slot, and
    AArch64's `a64_gpr32` is the low half of `a64_gpr64`. Keyed by class, a
    write through one view was invisible to a read through another and the
    graph described a machine with five independent registers. `regslice.axisl`
    disagreed with the executor the moment the gate was swept over it.

    So the identity is the slot, and the *view* is applied on the way in and
    out -- see `_block_read` and `_block_write`.
    """
    operand = next((op for op in entry["operands"] if op["name"] == operand_name), None)
    if operand is None or not is_register_operand(operand["kind"]):
        return None
    index = values.get(operand_name)
    if index is None:
        return None
    return ("__reg__", register_slot(operand["kind"], index))


def _view_of(kind, operand_width=0):
    """`(view_width, view_offset, preserves, storage_width)` for a class.

    The storage is at least as wide as the operand that names it. A class with
    no declared file width and one limb -- the generic `reg` -- says 64, and
    `simd_q_lanes.axisl` declares 128-bit operands of exactly that class, so
    taking the class's word truncated every one of them.
    """
    _zero, _alias, view_width, _offset, view_offset, preserve, limbs = (
        REGISTER_CLASSES[kind][:7])
    return view_width, view_offset, preserve, max(64 * max(limbs, 1), operand_width)


def _mask_node(graph, width, bits, shift):
    value = ((1 << bits) - 1) << shift
    return _block_node(graph, {"kind": "const", "value": value, "width": width})


def _block_write(graph, defs, entry, operand_name, values, node):
    """Record a write, through the operand's view.

    A view that *preserves* leaves the rest of the register alone, and one that
    does not zeroes it -- `x86_r16` preserves where `x86_r32` zeroes, which is
    what the architecture does and what `WritePolicy` records. Both are built
    from ordinary nodes, so the graph needs no evaluator it did not have.
    """
    location = _block_location(entry, operand_name, values)
    if location is None or node is None:
        return None
    operand = next(op for op in entry["operands"] if op["name"] == operand_name)
    view_width, view_offset, preserves, storage_width = _view_of(
        operand["kind"], operand["width"])
    graph["_limbs"][location] = max(graph["_limbs"].get(location, 1),
                                    REGISTER_CLASSES[operand["kind"]][6] or 1)
    if view_width is None:
        return (location, node)
    kept = _block_node(graph, {"kind": "op", "op": "and", "type": None,
                               "args": [node, _mask_node(graph, storage_width,
                                                         view_width, 0)],
                               "width": storage_width})
    placed = kept if view_offset == 0 else _block_node(
        graph, {"kind": "op", "op": "shl", "type": None,
                "args": [kept, _block_node(graph, {"kind": "const",
                                                   "value": view_offset,
                                                   "width": storage_width})],
                "width": storage_width})
    if not preserves:
        return (location, placed)
    prior = _block_read_storage(graph, defs, location, storage_width)
    hole = _block_node(graph, {"kind": "const",
                               "value": ((1 << storage_width) - 1)
                               ^ (((1 << view_width) - 1) << view_offset),
                               "width": storage_width})
    surviving = _block_node(graph, {"kind": "op", "op": "and", "type": None,
                                    "args": [prior, hole], "width": storage_width})
    return (location, _block_node(graph, {"kind": "op", "op": "or", "type": None,
                                          "args": [surviving, placed],
                                          "width": storage_width}))


def _block_tree(node, entry, values, defs, graph, width, address=None, bound=None):
    """One published tree, with its symbols resolved to graph nodes.

    A register symbol becomes whatever last wrote that location -- a live-in
    node when nothing in this block has -- and an immediate becomes a constant.
    That substitution *is* the dataflow: it is where `add x5, x1, x2` followed
    by `mul x6, x5, x3` becomes one graph rather than two.
    """
    if node is None or not isinstance(node, dict):
        return None
    bound = bound or {}
    if node.get("op") == "let":
        # Inlined into the graph. A `let` names a subexpression so it can be
        # used more than once -- `RBIT`'s five-step bit reversal is written that
        # way -- and a graph already shares a node by referring to its id, so
        # binding a name to the node its value built is the whole translation.
        # Until this, a `let` reached the walker as `{op, type, args}` with the
        # bindings gone, which was a crash and then a decline; the instructions
        # that use one could not appear in a block at all.
        inner = dict(bound)
        for binding in node.get("bindings", []):
            inner[binding["name"]] = _block_tree(binding["value"], entry, values,
                                                 defs, graph, width, address, inner)
        return _block_tree(node.get("body"), entry, values, defs, graph, width,
                           address, inner)
    if "const" in node:
        return _block_node(graph, {"kind": "const", "value": node["const"], "width": width})
    if "symbol" in node:
        name = node["symbol"]
        if name in bound:
            return bound[name]
        location = _block_location(entry, name, values)
        if location is not None:
            operand = next(op for op in entry["operands"] if op["name"] == name)
            return _block_read(graph, defs, location, operand["kind"],
                               operand["width"])
        if name in values and values[name] is not None:
            # An immediate: its decoded value is a constant of this block.
            return _block_node(
                graph, {"kind": "const", "value": values[name], "width": width})
        if name == "pc" and address is not None:
            # The counter is *this instruction's* address, and a lifted block
            # knows it -- so a branch target is a constant here rather than an
            # opaque input. It used to be an input, which made every target
            # unevaluable and was wrong about a thing the block does know.
            return _block_node(
                graph, {"kind": "const", "value": address, "width": width})
        # Architectural state, a rounding mode: named, and left as an input the
        # caller has to supply. Inventing a value for it would be inventing
        # semantics.
        # Named state has no register class and so no view: it is read whole.
        return _block_read_storage(graph, defs, ("__symbol__", name), width)
    kind = node.get("type")
    here = int(kind[1:]) if isinstance(kind, str) and kind[1:].isdigit() else width
    # `(load iW sign addr)` computes its address at pointer width, not at the
    # width of the value it loads. Walking the address subtree at `here` masked
    # the base register to eight bits for a byte load -- `x2 + 3` became 194
    # instead of 0x8e97...02 -- so the load missed the store that had just
    # written that address and read zero. A *store* never had this, because an
    # effect carries `addr_width` beside `eval_width` and the store path uses
    # it; a load rides inside a value tree, where the only width in sight was
    # the loaded one.
    widths = [here] * len(node.get("args", []))
    if node.get("op") == "load" and widths:
        widths[-1] = 64
    args = [_block_tree(arg, entry, values, defs, graph, arg_width, address, bound)
            for arg, arg_width in zip(node.get("args", []), widths)]
    # A load's `type` is how many bits come from memory and its `width` is how
    # wide the value is here -- for a signed byte load into a word register,
    # eight and thirty-two. Giving the node `here` for both discarded the sign
    # extension. Every other operator computes at one width, so for them the
    # two are the same.
    node_width = width if node.get("op") == "load" else here
    return _block_node(graph, {"kind": "op", "op": node.get("op"), "type": kind,
                               "args": args, "width": node_width})


def _block_node(graph, node):
    node["id"] = len(graph["nodes"])
    graph["nodes"].append(node)
    return node["id"]


def _block_read_storage(graph, defs, location, width):
    """The node holding the whole storage now: a previous write, or a live-in.

    Sized by the *storage*, never by a reader. A location read at 32 bits by
    one instruction and at 64 by the next is one location, and an input node
    sized by whichever read came first truncated the other -- every W-form
    agreed in its low half and disagreed above it.
    """
    if location in defs:
        held = defs[location]
        # A later reader may name more of the register than an earlier one did.
        # The storage is one width, so the input grows to it rather than the
        # graph carrying two nodes for one location.
        if graph["nodes"][held]["kind"] == "input":
            graph["nodes"][held]["width"] = max(graph["nodes"][held]["width"], width)
        return held
    node = _block_node(graph, {"kind": "input", "location": list(location),
                               "width": width})
    graph["live_in"].append({"location": list(location), "node": node})
    defs[location] = node
    return node


def _block_read(graph, defs, location, kind, operand_width=0):
    """The value an operand of class `kind` reads out of its storage."""
    view_width, view_offset, _preserves, storage_width = _view_of(kind, operand_width)
    graph["_limbs"][location] = max(graph["_limbs"].get(location, 1),
                                    REGISTER_CLASSES[kind][6] or 1)
    node = _block_read_storage(graph, defs, location, storage_width)
    if view_width is None:
        return node
    shifted = node if view_offset == 0 else _block_node(
        graph, {"kind": "op", "op": "lshr", "type": None,
                "args": [node, _block_node(graph, {"kind": "const",
                                                   "value": view_offset,
                                                   "width": storage_width})],
                "width": storage_width})
    return _block_node(graph, {"kind": "op", "op": "and", "type": None,
                               "args": [shifted, _mask_node(graph, storage_width,
                                                            view_width, 0)],
                               "width": storage_width})


def lift_block(words, pc=0, isa=None):
    """Lift a straight-line run of words to one dataflow graph.

    Each instruction's published tree is instantiated with the register indices
    decode chose, and every read is threaded to the last write of the same
    architectural location. The result is the block's computation as a graph,
    with the locations it reads before writing (`live_in`) and the ones it
    leaves changed (`live_out`).

    A block is a sequence the *caller* supplies. Where blocks begin and end,
    which branch is taken, and what the binary's functions are stay the
    caller's: those are facts about a program, and this describes a machine.

    Effects that are not register writes are kept as nodes rather than dropped.
    A store, a branch target and a state write are things the block does, and a
    consumer deciding whether a region can be replaced has to see them -- a
    graph that silently omitted them would describe a different block.
    """
    graph = {"nodes": [], "instructions": [], "live_in": [], "live_out": [],
             "declined": [], "terminator": None}
    # How many slots each storage occupies. The class knows and the location
    # does not, and a consumer comparing a live-out against a register file has
    # to know which: a 128-bit value of the generic `reg` class lives in one
    # slot, and a two-limb vector class spans two. Published rather than
    # guessed -- guessing was wrong in each direction on different corpora.
    graph["_limbs"] = {}
    defs = {}
    written = {}
    for offset, word in enumerate(words):
        entry = decode(word, isa)
        # Four bytes per word on every machine this describes: the lifter has
        # `WORD_BITS`, and the executor's `ILEN` lives in the executor. A block
        # is addressed here only so a consumer can say which instruction a node
        # came from.
        address = pc + offset * (WORD_BITS // 8)
        if entry is None:
            graph["declined"].append({"pc": address, "word": word,
                                      "reason": "no instruction decodes it"})
            continue
        record = lift_entry(word, entry)
        values = record["operands"]
        effects = entry.get("effects") or []
        produced = []
        if not effects:
            tree = entry.get("semantics_ast")
            destination = next((op for op in entry["operands"]
                                if op["role"] == "out"), None)
            if not isinstance(tree, dict) or destination is None:
                graph["declined"].append({"pc": address, "word": word,
                                          "mnemonic": entry["mnemonic"],
                                          "reason": "states no value"})
                continue
            node = _block_tree(tree, entry, values, defs, graph,
                               destination["width"], address)
            produced.append(_block_write(graph, defs, entry, destination["name"],
                                        values, node) or (None, None))
        else:
            for effect in effects:
                node = _block_effect(effect, entry, values, defs, graph, address)
                if node is None or node == "guarded":
                    reason = ("its `%s` is guarded" % effect.get("kind")
                              if node == "guarded"
                              else "effect kind `%s`" % effect.get("kind"))
                    graph["declined"].append(
                        {"pc": address, "word": word, "mnemonic": entry["mnemonic"],
                         "reason": reason})
                    continue
                produced.append(node)
        for location, node in produced:
            if location is None or node is None:
                continue
            defs[location] = node
            written[location] = node
        graph["instructions"].append({
            "pc": address, "word": word, "mnemonic": entry["mnemonic"],
            "nodes": [node for _, node in produced if node is not None],
        })
    graph["live_out"] = [{"location": list(location), "node": node,
                          "limbs": graph["_limbs"].get(location, 1)}
                         for location, node in written.items()]
    for entry in graph["live_in"]:
        entry["limbs"] = graph["_limbs"].get(tuple(entry["location"]), 1)
    del graph["_limbs"]
    return graph


def _block_effect(effect, entry, values, defs, graph, address):
    """One effect as a graph node, and the location it writes.

    Returns `(location, node)`, or None for an effect kind this does not model.
    A guarded effect is declined rather than flattened: whether it happened is a
    fact about the run, not about the block, and a graph that assumed it did
    would be describing a machine that always takes the branch.
    """
    kind = effect.get("kind")
    if kind == "setpc":
        # **Present, and not resolved.** A block ends in a branch by
        # definition, so declining every guarded `setpc` left a graph with no
        # terminator and a consumer with no way to know its region is
        # control-flow-bounded. The guard and the target are nodes; whether the
        # branch was taken is a fact about the run and stays absent.
        width = effect.get("eval_width", 32)
        target = _block_tree(effect.get("value_ast"), entry, values, defs, graph,
                             width, address)
        guard = None
        if "guard" in effect:
            guard = _block_tree(effect.get("guard_ast"), entry, values, defs, graph,
                                effect.get("guard_width", width), address)
        graph["terminator"] = {
            "pc": address,
            "mnemonic": entry["mnemonic"],
            "kind": "conditional" if guard is not None else "unconditional",
            "guard": guard,
            "target": target,
        }
        return (("__pc__", 0), target)
    if "guard" in effect:
        # Declined, and the *guard* is why -- not the effect's kind, which the
        # first version of this reported and which sends a reader looking in
        # the wrong place. Whether a guarded effect happened is a fact about
        # the run, not about the block, and only a branch target is worth
        # keeping unresolved rather than refusing.
        return "guarded"
    if kind == "set":
        width = effect.get("eval_width", 32)
        node = _block_tree(effect.get("value_ast"), entry, values, defs, graph, width,
                           address)
        return _block_write(graph, defs, entry, effect["dest"], values, node)
    if kind == "store":
        width = effect.get("eval_width", 32)
        addr = _block_tree(effect.get("addr_ast"), entry, values, defs, graph,
                           effect.get("addr_width", width), address)
        value = _block_tree(effect.get("value_ast"), entry, values, defs, graph, width,
                            address)
        node = _block_node(graph, {"kind": "store", "address": addr, "value": value,
                                   "width": effect.get("width", width)})
        # Memory is one location: this graph does not alias-analyse, so every
        # store orders against every other. A consumer that can prove more is
        # welcome to; a producer that assumed more would be wrong.
        return (("__memory__", 0), node)
    if kind == "setstate":
        width = effect.get("eval_width", 32)
        node = _block_tree(effect.get("value_ast"), entry, values, defs, graph, width,
                           address)
        return (("__state__", effect["state"]), node)
    return None
"#;

/// Header-only C lifter (`axis.lift-c.v1`): the compiled sibling of
/// `axis_lift.py`. Carries the same decode match/mask and operand extraction
/// fields as a static table, plus `axis_lift(word, &out)` that decodes a word
/// and fills each operand value (marking operands AXIS cannot encode invalid).
/// No dependency beyond `<stdint.h>` — the fast lift path for C/C++ simulators.
pub fn emit_lift_c(document: &Document) -> String {
    let guard = format!(
        "AXIS_{}_LIFT_H",
        tablegen_ident(&document.extension.name).to_ascii_uppercase()
    );
    let max_operands = document
        .instructions
        .iter()
        .map(|instruction| instruction.operands.len())
        .max()
        .unwrap_or(0)
        .max(1);
    let mut out = String::new();
    out.push_str("/* Generated by AXIS. Header-only instruction lifter (decode -> operands). */\n");
    out.push_str("/* schema: axis.lift-c.v1 */\n");
    out.push_str(&format!("#ifndef {guard}\n#define {guard}\n\n"));
    out.push_str("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n#include <stdio.h>\n\n");
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    out.push_str(&format!(
        "#define AXIS_LIFT_MAX_OPERANDS {max_operands}\n\n"
    ));
    out.push_str("typedef enum axis_insn_id {\n");
    out.push_str("  AXIS_INSN_UNKNOWN = 0,\n");
    for instruction in &document.instructions {
        out.push_str(&format!(
            "  AXIS_INSN_{},\n",
            tablegen_ident(&instruction.mnemonic)
        ));
    }
    out.push_str("} axis_insn_id;\n\n");
    out.push_str("typedef struct axis_lift_field { int insn_lo; int op_lo; int width; } axis_lift_field;\n\n");
    out.push_str("enum { AXIS_ROLE_IN = 0, AXIS_ROLE_OUT = 1, AXIS_ROLE_INOUT = 2, AXIS_ROLE_ENC = 3 };\n\n");
    out.push_str("typedef struct axis_lift_operand {\n");
    out.push_str("  const char *name;\n");
    out.push_str("  const char *kind;\n");
    out.push_str("  const char *role;\n");
    out.push_str("  int encodable;\n");
    out.push_str("  int derived_from;\n");
    out.push_str("  uint32_t derived_add;\n");
    out.push_str("  int fixed;\n");
    out.push_str("  int field_count;\n");
    out.push_str("  const axis_lift_field *fields;\n");
    /* Where this operand's value sits inside the register it names, when the
       class cannot say: an element of a scalable register. Zero width means no
       override -- read the register as the class describes it. */
    out.push_str("  uint32_t stride;\n");
    out.push_str("  uint32_t view_offset;\n");
    out.push_str("  uint32_t view_width;\n");
    out.push_str("  uint32_t register_bias;\n");
    out.push_str("  uint32_t slot_base;\n");
    // The operand's declared width. Every other field here says where a value
    // lives; this says how big it is, which is what decides whether it fits in
    // the word at all. Appended, so positional initialisers stay correct.
    out.push_str("  uint32_t width;\n");
    // Its register class, as an index into `axis_reg_classes` (-1: none), so
    // the executor need not find the class by name on every operand of every
    // step. Appended like `width`.
    out.push_str("  int reg_class;\n");
    // And its role as a code, for the same reason: `role` stays the name.
    out.push_str("  int role_code;\n");
    out.push_str("} axis_lift_operand;\n\n");
    out.push_str("typedef struct axis_lift_entry {\n");
    out.push_str("  axis_insn_id id;\n");
    out.push_str("  const char *isa;\n");
    out.push_str("  const char *mnemonic;\n");
    out.push_str("  uint32_t match;\n");
    out.push_str("  uint32_t mask;\n");
    out.push_str("  int liftable;\n");
    out.push_str("  int operand_count;\n");
    out.push_str("  const axis_lift_operand *operands;\n");
    out.push_str("  const char *semantics;\n");
    /* Which scalable instruction this entry is a lane of, and which lane.
       Every lane shares its origin's word, so enumerating what a word means is
       enumerating the group. A definedness mask shares it too and is not a
       lane. */
    out.push_str("  const char *scalable_origin;\n");
    out.push_str("  uint32_t scalable_lane;\n");
    out.push_str("  int definedness;\n");
    /* The ISA's register and program-counter width, which the JSON and Python
       lift tables have always published and these two had not. An executor
       needs it: a counter wraps at this width, not at the 32-bit instruction
       word. Appended, so the positional initialisers below stay correct. */
    out.push_str("  uint32_t state_width;\n");
    /* The modes this instruction is legal in, space separated, or "" for one
       that is legal in all of them. Two instructions may share an encoding when
       their modes are disjoint -- the decode-disjointness rule says so -- and a
       decoder handed only a word cannot then tell them apart. It refuses, which
       is right; `axis_lift_in_mode` is how a caller that KNOWS the mode asks.
       Appended, so the positional initialisers below stay correct. */
    out.push_str("  const char *modes;\n");
    /* How wide this instruction's ENCODING is, which is not `state_width`: a
       64-bit machine's word is 32 bits, and RISC-V's compressed instructions
       are 16 in the same table. A walk over bytes needs it to know how far to
       step, and stepping four through a 16-bit instruction misaligns every
       instruction after it. Appended, so the positional initialisers below
       stay correct. */
    out.push_str("  uint32_t bits;\n");
    /* Whether control may leave the block here.
       0 -- no: the description says what this does and none of it is the pc.
       1 -- yes: it writes the pc or traps.
       2 -- ⚠️ THIS BUILD CANNOT SAY. An instruction performed by a routine, or
            one with no semantics at all, may be a branch and nothing here
            knows -- AArch64's `braaz` authenticates and branches, and its
            description is one line of prose. A walk that treated `2` as `0`
            would stride straight through a branch and call what follows a
            basic block. */
    out.push_str("  int ends_block;\n");
    /* What the description says this instruction COSTS. ⚠️ Declared, not
       measured: a designer wrote these and until something reads them they are
       free text beside the semantics. A timing model is what makes them
       load-bearing, and a timing model needs them where a consumer can reach
       them -- which is here, beside the operands whose dependences decide when
       an instruction can issue.
       Throughput is in thousandths because it is a rate: 1.0 is 1000, and a
       unit that retires one every other cycle is 500. Appended, so the
       positional initialisers below stay correct. */
    out.push_str("  uint32_t latency;\n");
    out.push_str("  uint32_t throughput_milli;\n");
    /* Which functional unit issues this, by the name a `defcore` uses for it.
       ⚠️ The ISA's half of a linkage whose other half is the MACHINE: what an
       instruction means is the same on a core with one adder and on a core
       with four, and how long a program takes is not. Empty where the
       description names no unit, and then a timing model has no resource to
       contend for and says so rather than inventing one.
       Appended, so the positional initialisers below stay correct. */
    out.push_str("  const char *unit;\n");
    out.push_str("} axis_lift_entry;\n\n");

    for instruction in &document.instructions {
        let ident = tablegen_ident(&instruction.mnemonic);
        let layout = layout_for(document, instruction);
        for (op_idx, operand) in instruction.operands.iter().enumerate() {
            let bindings = layout.operand_bindings(&operand.name);
            if bindings.is_empty() {
                continue;
            }
            let fields: Vec<String> = bindings
                .iter()
                .map(|b| format!("{{ {}, {}, {} }}", b.insn_lo, b.op_lo, b.width))
                .collect();
            out.push_str(&format!(
                "static const axis_lift_field AXIS_LIFT_FIELDS_{ident}_{op_idx}[] = {{ {} }};\n",
                fields.join(", ")
            ));
        }
        if instruction.operands.is_empty() {
            continue;
        }
        out.push_str(&format!(
            "static const axis_lift_operand AXIS_LIFT_OPERANDS_{ident}[] = {{\n"
        ));
        for (op_idx, operand) in instruction.operands.iter().enumerate() {
            let bindings = layout.operand_bindings(&operand.name);
            let role = operand_role(operand);
            let (encodable, field_count, fields_ptr) = if bindings.is_empty() {
                (0, 0, "NULL".to_string())
            } else {
                (
                    1,
                    bindings.len(),
                    format!("AXIS_LIFT_FIELDS_{ident}_{op_idx}"),
                )
            };
            let derived_from = instruction
                .operands
                .iter()
                .position(|candidate| candidate.name == operand.derived_from)
                .map(|index| index as i32)
                .unwrap_or(-1);
            out.push_str(&format!(
                "  {{ {}, {}, {}, {}, {}, {}u, {}, {}, {}, {}u, {}u, {}u, {}u, {}u, {}u, {}, {} }},\n",
                c_string(&operand.name),
                c_string(&operand.kind),
                c_string(role),
                encodable,
                derived_from,
                operand.derived_add,
                operand.fixed.map_or(-1, |index| index as i64),
                field_count,
                fields_ptr,
                operand.slot_stride,
                operand.view_offset,
                operand.view_width,
                operand.lane_register,
                operand.slot_base,
                operand.width,
                reg_class_index(&operand.kind),
                match role {
                    "in" => 0,
                    "out" => 1,
                    "inout" => 2,
                    _ => 3,
                }
            ));
        }
        out.push_str("};\n");
    }
    out.push('\n');

    out.push_str("static const axis_lift_entry AXIS_LIFT_TABLE[] = {\n");
    for instruction in &document.instructions {
        let ident = tablegen_ident(&instruction.mnemonic);
        let layout = layout_for(document, instruction);
        let encodable = layout.is_encodable();
        let has_semantics = !instruction.formal_semantics.trim().is_empty();
        let operands_ptr = if instruction.operands.is_empty() {
            "NULL".to_string()
        } else {
            format!("AXIS_LIFT_OPERANDS_{ident}")
        };
        let semantics = if has_semantics {
            c_string(instruction.formal_semantics.trim())
        } else {
            "NULL".to_string()
        };
        // ⚠️ A routine's instruction and an undescribed one are `2`, not `0`.
        // See the field's comment: the description of `braaz` is prose.
        let effects = instruction
            .behavior
            .as_ref()
            .map(|behavior| behavior.effects.as_slice())
            .unwrap_or(&[]);
        let ends_block = if effects.iter().any(|effect| {
            matches!(effect.loc, crate::effects::Loc::Pc | crate::effects::Loc::Trap)
        }) {
            1
        } else if !instruction.implementation.trim().is_empty()
            || (effects.is_empty() && !has_semantics)
        {
            // ⚠️ A routine's instruction is `2` even when the description says
            // something about it. The executor calls the routine INSTEAD of the
            // effects, so what it does is the routine's business, and `braaz`
            // is a branch whose whole description is one line of prose.
            2
        } else {
            0
        };
        out.push_str(&format!(
            "  {{ AXIS_INSN_{ident}, {}, {}, 0x{:08x}u, 0x{:08x}u, {}, {}, {operands_ptr}, {semantics}, {}, {}u, {}, {}u, {}, {}u, {ends_block}, {}u, {}u, {} }},\n",
            c_string(&instruction.isa),
            c_string(&instruction.mnemonic),
            layout.match_value,
            layout.mask_value,
            i32::from(encodable && has_semantics),
            instruction.operands.len(),
            c_string(&instruction.scalable_origin),
            instruction.scalable_lane,
            i32::from(!instruction.definedness_of.is_empty()),
            // A document that declares no ISA at all says nothing about how
            // wide its machine is, and a struct field has to say something.
            // The register slot's own width is the answer that invents
            // nothing: masking at 64 in a 64-bit slot changes no value.
            crate::ast::instruction_isa(document, instruction)
                .map(|isa| isa.word_bits)
                .unwrap_or(64),
            c_string(&instruction.modes.join(" ")),
            layout.bits,
            instruction.latency_cycles.max(1),
            // A rate as thousandths, floored at one so nothing divides by zero.
            (instruction
                .throughput_per_cycle
                .parse::<f64>()
                .unwrap_or(1.0)
                .max(0.001)
                * 1000.0) as u32,
            c_string(&instruction.unit),
        ));
    }
    out.push_str("};\n\n");
    out.push_str("static const size_t AXIS_LIFT_TABLE_LEN = sizeof(AXIS_LIFT_TABLE) / sizeof(AXIS_LIFT_TABLE[0]);\n\n");

    out.push_str("typedef struct axis_lifted {\n");
    out.push_str("  const axis_lift_entry *entry;\n");
    out.push_str("  uint32_t operands[AXIS_LIFT_MAX_OPERANDS];\n");
    out.push_str("  int operand_valid[AXIS_LIFT_MAX_OPERANDS];\n");
    out.push_str("} axis_lifted;\n\n");

    out.push_str(
        "static inline uint32_t axis_lift_extract(uint32_t word, const axis_lift_operand *op) {\n",
    );
    out.push_str("  uint32_t value = 0u;\n");
    out.push_str("  for (int i = 0; i < op->field_count; ++i) {\n");
    out.push_str("    const axis_lift_field *f = &op->fields[i];\n");
    out.push_str("    uint32_t mask = f->width >= 32 ? 0xffffffffu : ((1u << f->width) - 1u);\n");
    out.push_str("    value |= ((word >> f->insn_lo) & mask) << f->op_lo;\n");
    out.push_str("  }\n");
    out.push_str("  return value;\n");
    out.push_str("}\n\n");

    out.push_str(
        "static inline uint32_t axis_lift_named_operand(uint32_t word, const axis_lift_entry *entry, const char *name) {\n",
    );
    out.push_str("  for (int i = 0; i < entry->operand_count; ++i) {\n");
    out.push_str("    if (strcmp(entry->operands[i].name, name) == 0) { return axis_lift_extract(word, &entry->operands[i]); }\n");
    out.push_str("  }\n");
    out.push_str("  return 0u;\n");
    out.push_str("}\n\n");
    out.push_str(
        "static inline int axis_a64_logical_imm_valid(uint32_t width, uint32_t n, uint32_t imms) {\n",
    );
    out.push_str(
        "  if ((width == 32u && n != 0u) || (width != 32u && width != 64u)) { return 0; }\n",
    );
    out.push_str("  uint32_t encoded = ((n & 1u) << 6) | ((~imms) & 0x3fu);\n");
    out.push_str("  int length = -1;\n");
    out.push_str("  for (int bit = 6; bit >= 0; --bit) { if (encoded & (1u << bit)) { length = bit; break; } }\n");
    out.push_str("  if (length < 1) { return 0; }\n");
    out.push_str("  uint32_t levels = (1u << length) - 1u;\n");
    out.push_str("  return (imms & levels) != levels;\n");
    out.push_str("}\n\n");
    out.push_str(
        "static inline int axis_lift_constraint_ok(uint32_t word, const axis_lift_entry *entry) {\n",
    );
    out.push_str("  (void)word;\n");
    out.push_str("  switch (entry->id) {\n");
    for instruction in &document.instructions {
        let Some(constraint) = decode_constraint(instruction) else {
            continue;
        };
        out.push_str(&format!(
            "    case AXIS_INSN_{}: return {};\n",
            tablegen_ident(&instruction.mnemonic),
            c_lift_constraint_expr(constraint)
        ));
    }
    out.push_str("    default: return 1;\n");
    out.push_str("  }\n");
    out.push_str("}\n\n");

    /* Whether an entry is legal in `mode`. An entry naming no mode is legal in
       every one, and a caller naming no mode accepts every entry -- so the
       default behaviour is exactly what it was before modes were carried. */
    out.push_str("static inline int axis_lift_mode_ok(const axis_lift_entry *entry, const char *mode) {\n");
    out.push_str("  if (!mode || !entry->modes[0]) { return 1; }\n");
    out.push_str("  size_t n = strlen(mode);\n");
    out.push_str("  for (const char *at = entry->modes; *at; ) {\n");
    out.push_str("    const char *end = at;\n");
    out.push_str("    while (*end && *end != ' ') { ++end; }\n");
    out.push_str("    if ((size_t)(end - at) == n && strncmp(at, mode, n) == 0) { return 1; }\n");
    out.push_str("    at = *end ? end + 1 : end;\n");
    out.push_str("  }\n");
    out.push_str("  return 0;\n");
    out.push_str("}\n\n");

    out.push_str("static inline const axis_lift_entry *axis_lift_decode_in(uint32_t word, const char *isa, const char *mode) {\n");
    out.push_str("  const axis_lift_entry *found = NULL;\n");
    out.push_str("  for (size_t i = 0; i < AXIS_LIFT_TABLE_LEN; ++i) {\n");
    out.push_str("    /* The encoding first: one AND and a compare reject nearly every entry, and\n       the string filters behind it run only for the candidates. */\n");
    out.push_str("    if ((word & AXIS_LIFT_TABLE[i].mask) != AXIS_LIFT_TABLE[i].match) { continue; }\n");
    out.push_str("    if (!axis_lift_mode_ok(&AXIS_LIFT_TABLE[i], mode)) { continue; }\n");
    out.push_str("    if (isa && AXIS_LIFT_TABLE[i].isa[0] && strcmp(AXIS_LIFT_TABLE[i].isa, isa) != 0) { continue; }\n");
    /* A definedness mask shares its instruction's word and is not a decode
       target; several lanes of one scalable origin are one instruction, so
       they do not make the word ambiguous. The same rule the decode table and
       the executor apply -- the lifter had been left out, which is why a
       scalable word lifted to nothing while it executed perfectly well. */
    out.push_str("    if (AXIS_LIFT_TABLE[i].definedness) { continue; }\n");
    out.push_str("    if ((word & AXIS_LIFT_TABLE[i].mask) == AXIS_LIFT_TABLE[i].match && axis_lift_constraint_ok(word, &AXIS_LIFT_TABLE[i])) {\n");
    out.push_str("      if (found) {\n");
    out.push_str("        if (!found->scalable_origin[0] || !AXIS_LIFT_TABLE[i].scalable_origin[0]\n");
    out.push_str("            || strcmp(found->scalable_origin, AXIS_LIFT_TABLE[i].scalable_origin) != 0) { return NULL; }\n");
    out.push_str("        if (AXIS_LIFT_TABLE[i].scalable_lane < found->scalable_lane) { found = &AXIS_LIFT_TABLE[i]; }\n");
    out.push_str("        continue;\n");
    out.push_str("      }\n");
    out.push_str("      found = &AXIS_LIFT_TABLE[i];\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("  return found;\n");
    out.push_str("}\n\n");
    /* ⚠️ Two instructions may share an encoding when their modes are disjoint,
       and a decoder handed only a word cannot tell them apart. It returns NULL,
       which is right: guessing would be worse. These are how a caller that
       knows more asks -- the mode twin of `axis_lift_decode_in_isa`, which has
       answered the same shape of question about ISAs all along. */
    out.push_str("static inline const axis_lift_entry *axis_lift_decode_in_isa(uint32_t word, const char *isa) {\n");
    out.push_str("  return axis_lift_decode_in(word, isa, NULL);\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_lift_entry *axis_lift_decode_in_mode(uint32_t word, const char *mode) {\n");
    out.push_str("  return axis_lift_decode_in(word, NULL, mode);\n");
    out.push_str("}\n\n");
    out.push_str("static inline const axis_lift_entry *axis_lift_decode(uint32_t word) {\n");
    out.push_str("  return axis_lift_decode_in(word, NULL, NULL);\n");
    out.push_str("}\n\n");

    out.push_str(
        "static inline int axis_lift_entry_operands(uint32_t word, const axis_lift_entry *entry, axis_lifted *out);\n\nstatic inline int axis_lift_in_isa(uint32_t word, const char *isa, axis_lifted *out) {\n",
    );
    out.push_str("  const axis_lift_entry *entry = axis_lift_decode_in_isa(word, isa);\n");
    out.push_str("  return axis_lift_entry_operands(word, entry, out);\n");
    out.push_str("}\n\n");
    /* Binding operands for a *given* entry, rather than for whatever the word
       decodes to. A scalable word decodes to a group, and each lane binds the
       same bits against its own operand list. */
    out.push_str("static inline int axis_lift_entry_operands(uint32_t word, const axis_lift_entry *entry, axis_lifted *out) {\n");
    out.push_str("  out->entry = entry;\n");
    out.push_str("  if (!entry) { return 0; }\n");
    out.push_str("  for (int i = 0; i < entry->operand_count; ++i) {\n");
    out.push_str("    const axis_lift_operand *op = &entry->operands[i];\n");
    out.push_str("    if (op->encodable) {\n");
    out.push_str("      out->operands[i] = axis_lift_extract(word, op);\n");
    out.push_str("      out->operand_valid[i] = 1;\n");
    out.push_str("    } else if (op->fixed >= 0) {\n");
    out.push_str("      out->operands[i] = (uint32_t)op->fixed;\n");
    out.push_str("      out->operand_valid[i] = 1;\n");
    out.push_str("    } else {\n");
    out.push_str("      out->operands[i] = 0u;\n");
    out.push_str("      out->operand_valid[i] = 0;\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("  for (int i = 0; i < entry->operand_count; ++i) {\n");
    out.push_str("    const axis_lift_operand *op = &entry->operands[i];\n");
    out.push_str("    if (op->derived_from >= 0 && out->operand_valid[op->derived_from]) { out->operands[i] = out->operands[op->derived_from] + op->derived_add; out->operand_valid[i] = 1; }\n");
    out.push_str("  }\n");
    out.push_str("  return 1;\n");
    out.push_str("}\n\n");
    out.push_str("static inline int axis_lift_in_mode(uint32_t word, const char *mode, axis_lifted *out) {\n");
    out.push_str("  const axis_lift_entry *entry = axis_lift_decode_in_mode(word, mode);\n");
    out.push_str("  return axis_lift_entry_operands(word, entry, out);\n");
    out.push_str("}\n\n");
    out.push_str("static inline int axis_lift(uint32_t word, axis_lifted *out) {\n");
    out.push_str("  return axis_lift_in_isa(word, NULL, out);\n");
    out.push_str("}\n\n");

    out.push_str("#ifdef __cplusplus\n}\n#endif\n\n");
    out.push_str(&format!("#endif /* {guard} */\n"));
    out
}

/// Rust lifter (`axis.lift-rust.v1`): the same static lift table and
/// `decode`/`lift` entry points as the C header, in safe Rust. `lift(word)`
/// returns the matched entry with each operand extracted (`None` for operands
/// AXIS cannot encode). Drop-in module for Rust simulators and trace tools.
pub fn emit_lift_rust(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("// Generated by AXIS. Instruction lifter (decode -> operands).\n");
    out.push_str("// schema: axis.lift-rust.v1\n\n");
    out.push_str("#[derive(Clone, Copy, Debug)]\n");
    out.push_str("pub struct LiftField {\n    pub insn_lo: u32,\n    pub op_lo: u32,\n    pub width: u32,\n}\n\n");
    out.push_str("#[derive(Clone, Copy, Debug)]\n");
    // `width` mirrors the C twin's: every other field says where a value
    // lives, this says how big it is, which is what decides whether it fits in
    // the word at all.
    // A lane of a scalable instruction names an ELEMENT of its register, and
    // where that element sits -- which register past the encoded one, which
    // bits of it -- is published here as the C twin's table publishes it.
    // Without these the Rust executor read and wrote whole registers by index,
    // ran lane 0 alone, and no Rust scalable gate could be registered.
    out.push_str("pub struct LiftOperand {\n    pub name: &'static str,\n    pub kind: &'static str,\n    pub role: &'static str,\n    pub encodable: bool,\n    pub derived_from: Option<usize>,\n    pub derived_add: u32,\n    pub fixed: Option<u32>,\n    pub fields: &'static [LiftField],\n    pub width: u32,\n    pub register_bias: u32,\n    pub stride: u32,\n    pub view_offset: u32,\n    pub view_width: u32,\n    pub slot_base: u32,\n}\n\n");
    out.push_str("#[derive(Clone, Copy, Debug)]\n");
    out.push_str("pub struct LiftEntry {\n    pub isa: &'static str,\n    pub mnemonic: &'static str,\n    pub match_: u32,\n    pub mask: u32,\n    pub liftable: bool,\n    pub operands: &'static [LiftOperand],\n    pub semantics: Option<&'static str>,\n    /// Which scalable instruction this is a lane of, and which lane.\n    /// Every lane shares its origin's encoding, so the decoder needs this\n    /// to tell one instruction's lanes from an ambiguous decode space.\n    pub scalable_origin: &'static str,\n    pub scalable_lane: u32,\n    /// Set when this entry is a definedness mask sharing another's word.\n    pub definedness: bool,\n    /// The ISA's register and program-counter width, which is not the\n    /// instruction word: a counter on a 32-bit machine wraps at 2**32.\n    pub state_width: u32,\n}\n\n");

    out.push_str("pub static AXIS_LIFT_TABLE: &[LiftEntry] = &[\n");
    for instruction in &document.instructions {
        let layout = layout_for(document, instruction);
        let encodable = layout.is_encodable();
        let has_semantics = !instruction.formal_semantics.trim().is_empty();
        out.push_str("    LiftEntry {\n");
        out.push_str(&format!(
            "        isa: {},\n",
            json_string(&instruction.isa)
        ));
        out.push_str(&format!(
            "        mnemonic: {},\n",
            json_string(&instruction.mnemonic)
        ));
        out.push_str(&format!("        match_: 0x{:08x},\n", layout.match_value));
        out.push_str(&format!("        mask: 0x{:08x},\n", layout.mask_value));
        out.push_str(&format!(
            "        liftable: {},\n",
            encodable && has_semantics
        ));
        out.push_str(&format!(
            "        scalable_origin: {},\n        scalable_lane: {},\n        definedness: {},\n        state_width: {},\n",
            json_string(&instruction.scalable_origin),
            instruction.scalable_lane,
            !instruction.definedness_of.is_empty(),
            // A document that declares no ISA at all says nothing about how
            // wide its machine is, and a struct field has to say something.
            // The register slot's own width is the answer that invents
            // nothing: masking at 64 in a 64-bit slot changes no value.
            crate::ast::instruction_isa(document, instruction)
                .map(|isa| isa.word_bits)
                .unwrap_or(64),
        ));
        out.push_str("        operands: &[\n");
        for operand in &instruction.operands {
            let bindings = layout.operand_bindings(&operand.name);
            let role = operand_role(operand);
            let fields: Vec<String> = bindings
                .iter()
                .map(|b| {
                    format!(
                        "LiftField {{ insn_lo: {}, op_lo: {}, width: {} }}",
                        b.insn_lo, b.op_lo, b.width
                    )
                })
                .collect();
            let derived_from = instruction
                .operands
                .iter()
                .position(|candidate| candidate.name == operand.derived_from)
                .map_or_else(|| "None".to_string(), |index| format!("Some({index})"));
            out.push_str(&format!(
                "            LiftOperand {{ name: {}, kind: {}, role: {}, encodable: {}, derived_from: {}, derived_add: {}, fixed: {}, fields: &[{}], width: {}, register_bias: {}, stride: {}, view_offset: {}, view_width: {}, slot_base: {} }},\n",
                json_string(&operand.name),
                json_string(&operand.kind),
                json_string(role),
                !bindings.is_empty(),
                derived_from,
                operand.derived_add,
                operand.fixed.map_or_else(|| "None".to_string(), |index| format!("Some({index})")),
                fields.join(", "),
                operand.width,
                operand.lane_register,
                operand.slot_stride,
                operand.view_offset,
                operand.view_width,
                operand.slot_base
            ));
        }
        out.push_str("        ],\n");
        if has_semantics {
            out.push_str(&format!(
                "        semantics: Some({}),\n",
                json_string(instruction.formal_semantics.trim())
            ));
        } else {
            out.push_str("        semantics: None,\n");
        }
        out.push_str("    },\n");
    }
    out.push_str("];\n\n");

    out.push_str("pub fn extract(word: u32, operand: &LiftOperand) -> u32 {\n");
    out.push_str("    let mut value = 0u32;\n");
    out.push_str("    for field in operand.fields {\n");
    out.push_str("        let mask = if field.width >= 32 { u32::MAX } else { (1u32 << field.width) - 1 };\n");
    out.push_str("        value |= ((word >> field.insn_lo) & mask) << field.op_lo;\n");
    out.push_str("    }\n");
    out.push_str("    value\n");
    out.push_str("}\n\n");

    out.push_str("#[allow(dead_code)]\n");
    out.push_str("fn named_operand(word: u32, entry: &LiftEntry, name: &str) -> Option<u32> {\n");
    out.push_str("    entry.operands.iter().find(|operand| operand.name == name).map(|operand| extract(word, operand))\n");
    out.push_str("}\n\n");
    out.push_str("#[allow(dead_code)]\n");
    out.push_str("fn a64_logical_imm_valid(width: u32, n: u32, imms: u32) -> bool {\n");
    out.push_str(
        "    if (width == 32 && n != 0) || (width != 32 && width != 64) { return false; }\n",
    );
    out.push_str("    let encoded = ((n & 1) << 6) | ((!imms) & 0x3f);\n");
    out.push_str("    let length = 31u32.saturating_sub(encoded.leading_zeros());\n");
    out.push_str("    if encoded == 0 || length < 1 { return false; }\n");
    out.push_str("    let levels = (1u32 << length) - 1;\n");
    out.push_str("    imms & levels != levels\n");
    out.push_str("}\n\n");
    out.push_str("fn constraint_ok(word: u32, entry: &LiftEntry) -> bool {\n");
    out.push_str("    let _ = word;\n");
    out.push_str("    match entry.mnemonic {\n");
    for instruction in &document.instructions {
        let Some(constraint) = decode_constraint(instruction) else {
            continue;
        };
        out.push_str(&format!(
            "        {} => {},\n",
            json_string(&instruction.mnemonic),
            rust_lift_constraint_expr(constraint)
        ));
    }
    out.push_str("        _ => true,\n");
    out.push_str("    }\n");
    out.push_str("}\n\n");

    out.push_str(
        "pub fn decode_in_isa(word: u32, isa: Option<&str>) -> Option<&'static LiftEntry> {\n",
    );
    out.push_str("    let mut matches = AXIS_LIFT_TABLE.iter().filter(|entry| {\n");
    out.push_str("        word & entry.mask == entry.match_\n");
    out.push_str(
        "            && isa.map_or(true, |wanted| entry.isa.is_empty() || entry.isa == wanted)\n",
    );
    out.push_str("            && constraint_ok(word, entry)\n");
    out.push_str("    });\n");
    out.push_str("    let found = matches.next()?;\n");
    out.push_str("    match matches.next() {\n");
    out.push_str("        None => Some(found),\n");
    // Lanes of one scalable instruction share its encoding by construction.
    // Decode names lane 0; `decode_lanes` returns the group.
    out.push_str("        Some(_) => {\n");
    out.push_str("            let group = decode_lanes(word, isa);\n");
    out.push_str("            group.first().copied()\n");
    out.push_str("        }\n");
    out.push_str("    }\n");
    out.push_str("}\n\n");
    out.push_str("/// Every entry `word` encodes, in lane order: one for an ordinary\n");
    out.push_str("/// instruction, `VL/elem` for a scalable one. Empty when the matches are\n");
    out.push_str("/// not one instruction, since that is real ambiguity.\n");
    out.push_str("pub fn decode_lanes(word: u32, isa: Option<&str>) -> Vec<&'static LiftEntry> {\n");
    out.push_str("    let mut found: Vec<&'static LiftEntry> = AXIS_LIFT_TABLE.iter().filter(|entry| {\n");
    out.push_str("        word & entry.mask == entry.match_\n");
    out.push_str("            && isa.map_or(true, |wanted| entry.isa.is_empty() || entry.isa == wanted)\n");
    out.push_str("            && !entry.definedness\n");
    out.push_str("            && constraint_ok(word, entry)\n");
    out.push_str("    }).collect();\n");
    out.push_str("    if found.len() <= 1 { return found; }\n");
    out.push_str("    let origin = found[0].scalable_origin;\n");
    out.push_str("    if origin.is_empty() || found.iter().any(|entry| entry.scalable_origin != origin) {\n");
    out.push_str("        return Vec::new();\n");
    out.push_str("    }\n");
    out.push_str("    found.sort_by_key(|entry| entry.scalable_lane);\n");
    out.push_str("    found\n");
    out.push_str("}\n\n");
    out.push_str("pub fn decode(word: u32) -> Option<&'static LiftEntry> {\n");
    out.push_str("    decode_in_isa(word, None)\n");
    out.push_str("}\n\n");

    out.push_str("#[derive(Clone, Debug)]\n");
    out.push_str("pub struct Lifted {\n    pub entry: &'static LiftEntry,\n    pub operands: Vec<Option<u32>>,\n}\n\n");
    out.push_str("/// Decode `word` and extract each operand value (`None` when AXIS cannot\n");
    out.push_str("/// encode/extract that operand).\n");
    out.push_str("pub fn lift_in_isa(word: u32, isa: Option<&str>) -> Option<Lifted> {\n");
    out.push_str("    let entry = decode_in_isa(word, isa)?;\n");
    out.push_str("    let mut operands: Vec<Option<u32>> = entry\n        .operands\n        .iter()\n        .map(|op| if op.encodable { Some(extract(word, op)) } else { op.fixed })\n        .collect();\n");
    out.push_str("    for (index, op) in entry.operands.iter().enumerate() { if let Some(source) = op.derived_from { operands[index] = operands[source].map(|value| value.wrapping_add(op.derived_add)); } }\n");
    out.push_str("    Some(Lifted { entry, operands })\n");
    out.push_str("}\n");
    out.push_str("\n/// `word` lifted against one particular entry -- a lane of a scalable\n/// instruction, which `decode_lanes` names -- rather than the first match.\n");
    out.push_str("pub fn lift_entry(word: u32, entry: &'static LiftEntry) -> Lifted {\n");
    out.push_str("    let mut operands: Vec<Option<u32>> = entry\n        .operands\n        .iter()\n        .map(|op| if op.encodable { Some(extract(word, op)) } else { op.fixed })\n        .collect();\n");
    out.push_str("    for (index, op) in entry.operands.iter().enumerate() { if let Some(source) = op.derived_from { operands[index] = operands[source].map(|value| value.wrapping_add(op.derived_add)); } }\n");
    out.push_str("    Lifted { entry, operands }\n");
    out.push_str("}\n");
    out.push_str("\npub fn lift(word: u32) -> Option<Lifted> {\n");
    out.push_str("    lift_in_isa(word, None)\n");
    out.push_str("}\n");
    out
}

/// Emit a functional single-step interpreter (`axis.exec-python.v1`) that
/// composes the decode/lift table (`axis_lift`) with the proven golden
/// semantics (`golden_model`): decode a word, bind register/immediate
/// operands, evaluate the instruction, and write the result to the
/// destination register. This is the lift→execute rung — the seed of a
/// functional simulator — and depends on the two modules emitted alongside it.
/// The runtime is generic over the co-emitted tables, so it ignores
/// `_document`; the parameter keeps the emitter signature uniform.
/// Symbolic execution over the same effects the executors run.
///
/// A fixed runtime, like `emit_exec_python`: it reads the generated lift table
/// and the generated golden model's expression parser, and interprets the same
/// effects into TERMS rather than numbers. Nothing here re-describes an
/// instruction -- a symbolic executor is one more backend over the
/// description, which is the only reason it can be trusted without a second
/// proof of what the instructions mean.
pub fn emit_symbolic_python(document: &Document) -> String {
    // ⚠️ Byte order is the description's to state, not this backend's to
    // assume. Composing a halfword out of two bytes the wrong way round is
    // invisible in a term that is otherwise well formed, so the constant is
    // emitted and a corpus whose ISAs disagree gets `mixed`, which every
    // memory access declines by name.
    let mut orders: Vec<&str> = document
        .isas
        .iter()
        .map(|isa| isa.endianness.as_str())
        .collect();
    orders.sort_unstable();
    orders.dedup();
    let endian = match orders.as_slice() {
        [one] => *one,
        [] => "little",
        _ => "mixed",
    };
    // The SMT helper definitions `emit-smt2` writes, embedded so `path_smt`
    // can hand a solver a script that calls them. One definition of what
    // `a64_cond_holds` means, in both artifacts.
    let helpers = crate::emit::semantics::smt_a64_helpers(document);
    format!(
        "{SYMBOLIC_PY_RUNTIME}\n#: The byte order the description states.\n\
         ENDIAN = {endian:?}\n\n\
         #: `emit-smt2`'s helper definitions, for a path that calls one.\n\
         SMT_PRELUDE = r\"\"\"{helpers}\"\"\"\n"
    )
}

const SYMBOLIC_PY_RUNTIME: &str = r##"# Generated by AXIS. Symbolic execution over the same effects the executors run.
# schema: axis.symbolic-python.v1
#
# The concrete executor walks an instruction's effects evaluating them to
# numbers. This walks the same effects evaluating them to TERMS: a register
# holds an expression rather than a value, memory holds expressions, and a
# guarded branch yields a path constraint instead of a decision.
#
# ⚠️ It is the same table and the same expression language the golden model,
# the C and Rust executors, the LLVM lowering and the SMT backend all read.
# Nothing here re-describes an instruction; a symbolic executor is one more
# backend over the description, which is the only reason it can be trusted
# without a second proof of what the instructions mean.
#
# What it cannot do it says. An operator with no bitvector meaning -- every
# floating-point one, for a start -- is declined by name rather than
# approximated, and the step reports which.
import axis_lift
import golden_model

AXIS_SCHEMA = "axis.symbolic-python.v1"

#: How wide the pc is: what the instructions themselves say their state is.
#: Not `WORD_BITS`, which is how wide an INSTRUCTION is -- RV64I's words are 32
#: bits and its pc is 64, and a machine that conflated them addressed memory
#: with half a pointer.
PC_BITS = max([entry.get("state_width") or 64
               for entry in getattr(axis_lift, "AXIS_LIFT_TABLE", [])] or [64])

#: How far the pc moves when nothing branches. Both executors hold this same
#: number -- `ILEN` in `axis_exec`, `AXIS_EXEC_ILEN` in the C one -- and the
#: lift table does not carry it. Stated here rather than read off a table that
#: has no such column: a `ILEN` was a guess that
#: happened to be right, which is the kind of agreement that stops holding
#: quietly.
ILEN = 4

#: A term is `(op, width, *args)`, with leaves `("const", width, value)` and
#: `("var", width, name)`. Kept as tuples rather than objects so a caller can
#: hash, compare and cache them without ceremony.
def const(value, width):
    return ("const", width, int(value) & ((1 << width) - 1))


def var(name, width):
    return ("var", width, name)


def is_const(term):
    return term[0] == "const"


#: Operators with a direct bitvector meaning. The value is the SMT-LIB name.
_BINARY = {
    "add": "bvadd", "sub": "bvsub", "mul": "bvmul",
    "and": "bvand", "or": "bvor", "xor": "bvxor",
    "shl": "bvshl", "sll": "bvshl",
    "lshr": "bvlshr", "srl": "bvlshr",
    "ashr": "bvashr", "sra": "bvashr",
    # ⚠️ `udiv` and `urem` are NOT here. SMT-LIB leaves division by zero to the
    # solver -- `bvudiv` by zero is all-ones -- and the description's answer is
    # zero. Mapping them straight through made `udiv x0, x0` come out
    # `0xffffffff` where the machine says `0`, and only a register index that
    # made both operands the same zero showed it.
}
_COMPARE = {
    "icmp_eq": "=", "icmp_ne": "distinct",
    "icmp_ult": "bvult", "icmp_ule": "bvule",
    "icmp_ugt": "bvugt", "icmp_uge": "bvuge",
    "icmp_slt": "bvslt", "icmp_sle": "bvsle",
    "icmp_sgt": "bvsgt", "icmp_sge": "bvsge",
}


class Declined(Exception):
    """An operator this backend has no bitvector meaning for.

    Raised rather than approximated: a symbolic executor that guessed at an
    operator would produce a term that solves to the wrong answer, which is
    worse than one that says it cannot.
    """


#: Delegated operators `emit-smt2` defines as helper functions, which
#: `SMT_PRELUDE` carries. The name gains the width: `axis_a64_cond_holds_64`.
_SMT_HELPERS = {
    "a64_shift_reg": "axis_a64_shift_reg",
    "a64_extend_reg": "axis_a64_extend_reg",
    "a64_add_nzcv": "axis_a64_add_nzcv",
    "a64_sub_nzcv": "axis_a64_sub_nzcv",
    "a64_logic_nzcv": "axis_a64_logic_nzcv",
    "a64_umulh": "axis_a64_umulh",
    "a64_smulh": "axis_a64_smulh",
    "a64_cond_holds": "axis_a64_cond_holds",
    "a64_wmask": "axis_a64_wmask",
    "a64_ubfm": "axis_a64_ubfm",
    "a64_sbfm": "axis_a64_sbfm",
    "a64_bfm": "axis_a64_bfm",
}


#: Floating-point operators with a spelling in SMT-LIB's FloatingPoint theory.
_FP_FOLD = {"fadd": "fp.add", "fsub": "fp.sub", "fmul": "fp.mul", "fdiv": "fp.div",
            "fadd_rm": "fp.add", "fsub_rm": "fp.sub", "fmul_rm": "fp.mul",
            "fdiv_rm": "fp.div"}
_FP_COMPARE = {"fcmp_oeq": "fp.eq", "fcmp_olt": "fp.lt", "fcmp_ole": "fp.leq"}


def _smt_fp(term):
    """A floating-point term as SMT-LIB, in the spelling `emit-smt2` uses.

    ⚠️ This is a SECOND spelling of semantics that already have a proven one,
    which is only safe because something checks the two against each other:
    `symbolic_smt_check.py` asks a solver whether this rendering and
    `emit-smt2`'s `axis_instr_*` can ever differ, over all inputs. Before that
    gate existed this was declined rather than guessed at.

    `fp.to_ieee_bv` is unspecified for NaN in SMT-LIB, so the canonical pattern
    is selected on `fp.isNaN` first -- which is what turns AXIS's canonical-NaN
    rule from a convention into the thing that makes these provable at all.
    """
    _kind, width, op, _atom, *args = term
    # ⚠️ Three formats, not two. Half precision arrived with AArch64's FP16
    # lanes, and `width > 32` sent it to single: a 16-bit value handed to
    # `(_ to_fp 8 24)`, which z3 refuses with a sort error -- and the gate
    # counted each refusal as a question it could not answer.
    if width > 32:
        exponent, significand = 11, 53
        canonical, sign = "(_ bv9221120237041090560 64)", "(_ bv9223372036854775808 64)"
    elif width > 16:
        exponent, significand = 8, 24
        canonical, sign = "(_ bv2143289344 32)", "(_ bv2147483648 32)"
    else:
        exponent, significand = 5, 11
        canonical, sign = "(_ bv32256 16)", "(_ bv32768 16)"

    def as_float(value):
        return f"((_ to_fp {exponent} {significand}) {smt(_widen(value, width))})"

    if op == "fneg":
        # The sign bit, on the bits themselves. Through the float theory it
        # would canonicalise NaN, which is a different function.
        return f"(bvxor {smt(_widen(args[0], width))} {sign})"
    if op in _FP_COMPARE:
        predicate = f"({_FP_COMPARE[op]} {as_float(args[0])} {as_float(args[1])})"
        return f"(ite {predicate} (_ bv1 {width}) (_ bv0 {width}))"
    if op == "fcmp_uno":
        predicate = (f"(or (fp.isNaN {as_float(args[0])}) "
                     f"(fp.isNaN {as_float(args[1])}))")
        return f"(ite {predicate} (_ bv1 {width}) (_ bv0 {width}))"

    explicit = op.endswith("_rm")
    if explicit:
        # The mode is the first argument and may be a term rather than a
        # literal, so it becomes an `ite` over the encodings: AArch64's
        # FPCR.RMode in the low two bits, plus RISC-V's RMM as a fifth. Masking
        # to three bits rather than two is what makes `RNA` reachable at all.
        bits = smt(_widen(args[0], width))
        mode = (f"(ite (= (bvand {bits} (_ bv7 {width})) (_ bv4 {width})) RNA "
                f"(ite (= (bvand {bits} (_ bv3 {width})) (_ bv0 {width})) RNE "
                f"(ite (= (bvand {bits} (_ bv3 {width})) (_ bv1 {width})) RTP "
                f"(ite (= (bvand {bits} (_ bv3 {width})) (_ bv2 {width})) RTN "
                f"RTZ))))")
        values = args[1:]
    else:
        mode, values = "RNE", list(args)

    base = op[:-3] if explicit else op
    if base == "fsqrt":
        folded = f"(fp.sqrt {mode} {as_float(values[0])})"
    elif base == "fma":
        # One rounding over all three, which is what makes this its own
        # operator rather than a fold.
        folded = (f"(fp.fma {mode} {as_float(values[0])} {as_float(values[1])} "
                  f"{as_float(values[2])})")
    elif base in _FP_FOLD:
        folded = as_float(values[0])
        for rhs in values[1:]:
            folded = f"({_FP_FOLD[base]} {mode} {folded} {as_float(rhs)})"
    else:
        raise Declined(f"no SMT text for `{op}` -- see `emit-smt2`")
    return (f"(let ((axis_fp {folded})) (ite (fp.isNaN axis_fp) {canonical} "
            f"(fp.to_ieee_bv axis_fp)))")


#: Operators whose SMT-LIB result is a Bool rather than a bit-vector.
_BOOL_KINDS = ("=", "distinct", "bvult", "bvule", "bvugt", "bvuge",
               "bvslt", "bvsle", "bvsgt", "bvsge", "not", "and", "or")


def _smt_bool(term):
    """The term as an SMT-LIB CONDITION.

    ⚠️ SMT-LIB separates Bool from `(_ BitVec 1)` and this representation does
    not: a comparison is a one-bit value here and a proposition there. Crossing
    the two the wrong way is not a wrong answer, it is a script the solver will
    not parse -- which is how this was found, by asking one to prove the
    rendering equal to `emit-smt2` and having it object to the sorts instead.
    """
    if term[0] in _BOOL_KINDS:
        inner = ("not", "and", "or")
        pieces = [(_smt_bool(a) if term[0] in inner else smt(a)) for a in term[2:]]
        return "(" + term[0] + " " + " ".join(pieces) + ")"
    return f"(distinct {smt(term)} (_ bv0 {term[1]}))"


def smt(term):
    """The term as SMT-LIB text, as a bit-vector."""
    kind = term[0]
    if kind == "const":
        return f"(_ bv{term[2]} {term[1]})"
    if kind == "var":
        return term[2]
    if kind in _BOOL_KINDS:
        return f"(ite {_smt_bool(term)} (_ bv1 {term[1]}) (_ bv0 {term[1]}))"
    if kind == "ite":
        return f"(ite {_smt_bool(term[2])} {smt(term[3])} {smt(term[4])})"
    # ⚠️ Indexed operators: `((_ extract 7 0) x)`, not `(extract 7 0 x)`. The
    # generic printer wrote the second, which is not the language.
    if kind == "extract":
        return f"((_ extract {term[2]} {term[3]}) {smt(term[4])})"
    if kind in ("zero_extend", "sign_extend"):
        return f"((_ {kind} {term[2]}) {smt(term[3])})"
    if kind == "select":
        return f"(select {smt(term[2])} {smt(term[3])})"
    if kind == "store":
        return f"(store {smt(term[2])} {smt(term[3])} {smt(term[4])})"
    if kind == "axis_model":
        if term[2] in _SMT_HELPERS:
            # ⚠️ A CALL to `emit-smt2`'s own definition, not a second spelling.
            # AArch64's condition codes and bitfield masks are algorithms
            # rather than expressions, and that file already writes each one
            # once as a function; `SMT_PRELUDE` carries those definitions here
            # so a path can call them. Re-deriving `a64_cond_holds` would be a
            # second opinion about what `b.eq` means.
            width = term[1]
            arguments = " ".join(smt(_widen(a, width)) for a in term[4:])
            return f"({_SMT_HELPERS[term[2]]}_{width} {arguments})"
        if term[2] in _DELEGATED:
            raise Declined(f"`{term[2]}` is evaluated by the model, not rendered")
        return _smt_fp(term)
    return "(" + " ".join([kind] + [smt(a) for a in term[2:]]) + ")"


def variables(term, into=None):
    """Every free variable the term names, with its width."""
    into = {} if into is None else into
    if term[0] == "var":
        into[term[2]] = term[1]
    elif term[0] != "const":
        for a in term[2:]:
            if isinstance(a, tuple):
                variables(a, into)
    return into


def concrete(term, bindings):
    """The term's value when every variable is given one.

    ⚠️ This is what makes a symbolic executor checkable without a solver: run a
    program concretely, run it symbolically, bind the symbolic inputs to the
    concrete ones, and the two must agree. A solver is for questions about
    *all* inputs; agreement on one is what says the terms mean what the
    instructions do.
    """
    kind, width = term[0], term[1]
    mask = (1 << width) - 1
    if kind == "const":
        return term[2]
    if kind == "var":
        # A variable nobody bound is a question this cannot answer -- an
        # aliased register the caller forgot, a memory image left out. Named,
        # rather than a `KeyError` from three frames down.
        if term[2] not in bindings:
            raise Declined(f"no value bound for `{term[2]}`")
        return bindings[term[2]] & mask
    if kind == "select":
        # ⚠️ Before the arguments are evaluated, not after. A `select`'s first
        # argument is the memory ARRAY, which has no value of its own -- asking
        # for one is asking what a whole memory equals.
        return _select(term[2], concrete(term[3], bindings), bindings)
    if kind == "axis_model":
        return _model(term, bindings)
    args = [concrete(a, bindings) if isinstance(a, tuple) else a for a in term[2:]]
    if kind == "bvadd":
        return (args[0] + args[1]) & mask
    if kind == "bvsub":
        return (args[0] - args[1]) & mask
    if kind == "bvmul":
        return (args[0] * args[1]) & mask
    if kind == "bvand":
        return args[0] & args[1]
    if kind == "bvor":
        return args[0] | args[1]
    if kind == "bvxor":
        return args[0] ^ args[1]
    if kind == "bvshl":
        return (args[0] << (args[1] & (width - 1))) & mask if args[1] < width else 0
    if kind == "bvlshr":
        return (args[0] >> args[1]) if args[1] < width else 0
    if kind == "bvashr":
        signed = args[0] - (1 << width) if args[0] >> (width - 1) else args[0]
        shift = min(args[1], width - 1)
        return (signed >> shift) & mask
    if kind in ("bvsdiv", "bvsrem"):
        # Truncating division, as the golden model does it: the quotient's sign
        # is the operands', the remainder's is the dividend's. Python floors,
        # which is a different answer for exactly the negative cases.
        left = args[0] - (1 << width) if args[0] >> (width - 1) else args[0]
        right = args[1] - (1 << width) if args[1] >> (width - 1) else args[1]
        if right == 0:
            return mask if kind == "bvsdiv" else args[0]
        quotient = abs(left) // abs(right)
        if (left < 0) != (right < 0):
            quotient = -quotient
        return (quotient if kind == "bvsdiv" else left - quotient * right) & mask
    if kind == "bvudiv":
        return mask if args[1] == 0 else (args[0] // args[1]) & mask
    if kind == "bvurem":
        return args[0] if args[1] == 0 else (args[0] % args[1]) & mask
    if kind == "bvnot":
        return (~args[0]) & mask
    if kind == "ite":
        return args[1] if args[0] else args[2]
    if kind == "not":
        return 0 if args[0] else 1
    if kind == "or":
        return int(any(args))
    if kind == "and":
        return int(all(args))
    if kind in ("=", "distinct", "bvult", "bvule", "bvugt", "bvuge",
                "bvslt", "bvsle", "bvsgt", "bvsge"):
        return _compare(kind, term, bindings)
    if kind == "zero_extend":
        return args[1]
    if kind == "sign_extend":
        from_width = term[3][1]
        value = args[1]
        if value >> (from_width - 1):
            value |= ~((1 << from_width) - 1)
        return value & mask
    if kind == "extract":
        high, low = term[2], term[3]
        return (args[2] >> low) & ((1 << (high - low + 1)) - 1)
    raise Declined(kind)


def _model(term, bindings, mask=True):
    """One delegated operation, evaluated by the golden model.

    The term is rebuilt as the expression it came from, with its arguments as
    the numbers they evaluate to, and handed back to the model that defines
    them. An operator the model does not know raises, and the caller turns
    that into a decline by name rather than a number nobody checked.
    """
    _kind, width, op, atom = term[:4]
    values = [concrete(argument, bindings) for argument in term[4:]]
    node = [op] + ([atom] if atom else []) + [str(value) for value in values]
    try:
        answer = golden_model._eval(node, {}, width)
    except Declined:
        raise
    except Exception as why:
        raise Declined(f"`{op}`: {why}") from None
    return answer & ((1 << width) - 1) if mask else answer


def _select(mem, address, bindings):
    """One byte of a memory term, for one binding of its variables."""
    while mem[0] == "store":
        _kind, _width, inner, addr, value = mem
        if concrete(addr, bindings) == address:
            return concrete(value, bindings)
        mem = inner
    image = bindings.get(mem[2], b"")
    return image[address] if address < len(image) else 0


def _compare(kind, term, bindings):
    left, right = term[2], term[3]
    width = left[1]
    a, b = concrete(left, bindings), concrete(right, bindings)
    if kind.startswith("bvs"):
        a = a - (1 << width) if a >> (width - 1) else a
        b = b - (1 << width) if b >> (width - 1) else b
    return int({
        "=": a == b, "distinct": a != b,
        "bvult": a < b, "bvule": a <= b, "bvugt": a > b, "bvuge": a >= b,
        "bvslt": a < b, "bvsle": a <= b, "bvsgt": a > b, "bvsge": a >= b,
    }[kind])


def _widen(term, width):
    """The term at `width`, extending or truncating as the IR's `zext` does."""
    if term[1] == width:
        return term
    if term[1] < width:
        return ("zero_extend", width, width - term[1], term)
    return ("extract", width, width - 1, 0, term)


def _resize(term, width, signed):
    if term[1] == width:
        return term
    if term[1] < width:
        kind = "sign_extend" if signed else "zero_extend"
        return (kind, width, width - term[1], term)
    return ("extract", width, width - 1, 0, term)


#: Operators evaluated by the golden model rather than built from bitvector
#: primitives, beside every floating-point one.
#:
#: ⚠️ An explicit list, not a fallback. Sending anything unknown to the model
#: would turn a gap into a silent answer, which is the failure this whole
#: backend is arranged against. These are here because each decodes an
#: encoding or consults a table -- AArch64's bitmask immediates, its condition
#: codes, the NZCV rules -- where a hand-written term goes wrong quietly and
#: the model's version is already proven. `smt()` says so rather than
#: pretending: a delegated operator has no SMT text here.
_DELEGATED = (
    "a64_shift_reg", "a64_extend_reg", "a64_cond_holds",
    "a64_wmask", "a64_ubfm", "a64_sbfm", "a64_bfm",
    "a64_add_nzcv", "a64_sub_nzcv", "a64_adc_nzcv", "a64_sbc_nzcv",
    "a64_logic_nzcv", "a64_umulh", "a64_smulh",
)


def _is_type_atom(token):
    """`i64`, `u32`, `f32` -- a width, not a value."""
    return token[:1] in "iuf" and token[1:].isdigit()


def evaluate(node, env, width, state=None, address_width=None):
    """One semantic expression as a term.

    `env` binds operand names to terms. `state` supplies the symbolic memory
    for a load. The shape mirrors `golden_model._eval`, because it is the same
    language: where that returns a number this returns the expression that
    would have produced it.
    """
    if isinstance(node, str):
        if node in env:
            return _widen(env[node], width)
        if node.startswith("0x"):
            return const(int(node, 16), width)
        if node.isdigit():
            return const(int(node), width)
        # ⚠️ Declared architectural state is a free VARIABLE, not an unknown.
        # `frm` and `exclusive_address` are inputs to the instruction exactly as
        # a register is, and a symbolic executor that refused them declined
        # every rounding-mode form and every reservation. A symbol the
        # description does not declare is still a decline: it is a gap, and
        # inventing a variable for it would hide one.
        for name, bits in getattr(axis_lift, "STATE_SLOTS", ()):
            if name == node:
                return _widen(var(f"state_{node}", max(bits, 1)), width)
        raise Declined(f"symbol `{node}`")
    op = node[0]
    args = list(node[1:])
    if op == "let":
        # ⚠️ SEQUENTIAL. Each binding is evaluated in the environment its
        # predecessors have already extended, so a binding may name the one
        # above it -- the order the golden model uses, and the one that decides
        # what a chain of steps means. Evaluating them all in the OUTER
        # environment instead declines the whole instruction with `symbol
        # \`sum\``, which is how this was found.
        local = dict(env)
        for binding in args[0]:
            local[binding[0]] = evaluate(binding[1], local, width, state, address_width)
        return evaluate(args[1], local, width, state, address_width)
    if op in ("load", "atomic_load"):
        access = int(node[1][1:])
        signed = node[2] == "signed"
        addr = evaluate(node[-1], env, address_width or width, state, address_width)
        if state is None:
            raise Declined("a load with no symbolic memory")
        return _resize(state.read(addr, access), width, signed)
    if (op[:1] == "f" and not op.startswith("fence")) or op in _DELEGATED:
        # ⚠️ Floating point is DELEGATED, not re-described. What `fadd_rm`
        # means -- every rounding mode, every subnormal, the canonical NaN --
        # is settled in the golden model, with a Fraction-exact reference
        # behind it and five other backends proven against it. A symbolic
        # executor that wrote its own IEEE-754 would be a second opinion about
        # the same instruction, which is the one thing this repo never wants.
        # The TERM is symbolic; only its evaluation goes to the model.
        atom = args[0] if args and isinstance(args[0], str) and _is_type_atom(args[0]) else None
        rest = args[1:] if atom else args
        inner = int(atom[1:]) if atom else width
        # ⚠️ Arguments are NOT narrowed to the operator's width. The golden
        # model leaves a leaf unmasked and masks inside each operator, because
        # a conversion is told its source width separately: `(fcvt_f2u i32 32
        # rs1)` reads a 32-bit float out of a 64-bit register, and `(fcvt_f2f
        # f64 32 rs1)` a 32-bit one to make a 64-bit. Narrowing `rs1` to the
        # result's width turned every double into its low half, and the answer
        # was a plausible number rather than an error.
        carried = max(inner, 64)
        pieces = [evaluate(a, env, carried, state, address_width) for a in rest]
        return ("axis_model", inner, op, atom or "", *pieces)
    if args and isinstance(args[0], str) and _is_type_atom(args[0]):
        width = int(args[0][1:])
        args = args[1:]
    if op in ("if", "select"):
        condition = evaluate(args[0], env, width, state, address_width)
        left = evaluate(args[1], env, width, state, address_width)
        right = evaluate(args[2], env, width, state, address_width)
        test = ("distinct", 1, condition, const(0, condition[1]))
        # ⚠️ The arms are RESIZED to the node's width, which the binary
        # operators below already do. An arm carrying its own type atom comes
        # back at ITS width, not this one -- `(select i8 c (shl i16 ...) x)` is
        # the shape a saturating shift has, where the saturation is decided at
        # twice the lane width and the answer is a lane. Without this the two
        # arms reach `ite` as different sorts and the SMT script is REJECTED
        # rather than answered, which the gate can only report as a question
        # the solver would not take.
        return ("ite", width, test, _widen(left, width), _widen(right, width))
    if op in _COMPARE:
        # ⚠️ At the DECLARED width, which is what `min`/`max` below already do
        # and what this did not. Comparing at the OPERANDS' width is the same
        # answer whenever they are no wider than the comparison -- and silently
        # a different one when they are wider, which is exactly what a lane
        # compare looks like. `(icmp_slt i16 a b)` inside a v8i16 expansion
        # receives operands that are 128-bit expressions masked down to a lane,
        # and a masked lane is never negative in 128 bits: `bvslt` then answers
        # the UNSIGNED question and every lane of CMGT/CMGE comes back
        # complemented. Only the signed compares could show it, because
        # unsigned is what the wrong width degenerates to.
        left = _widen(evaluate(args[0], env, width, state, address_width), width)
        right = _widen(evaluate(args[1], env, width, state, address_width), width)
        return _widen((_COMPARE[op], 1, left, right), width)
    if op in _BINARY:
        terms = [_widen(evaluate(a, env, width, state, address_width), width) for a in args]
        folded = terms[0]
        for term in terms[1:]:
            folded = (_BINARY[op], width, folded, term)
        return folded
    if op in ("rol", "ror"):
        value = _widen(evaluate(args[0], env, width, state, address_width), width)
        amount = _widen(evaluate(args[1], env, width, state, address_width), width)
        turn = ("bvurem", width, amount, const(width, width))
        if op == "ror":
            # `width - (shift % width)`, with no second remainder: a rotate by
            # zero becomes a shift by the whole width, and a shift that far is
            # zero -- so the other half of the `or` carries the value through
            # unchanged. Written out because it looks like an off-by-one and is
            # not; removing the remainder that IS redundant is how the
            # difference got checked.
            turn = ("bvsub", width, const(width, width), turn)
        return ("bvor", width,
                ("bvshl", width, value, turn),
                ("bvlshr", width, value, ("bvsub", width, const(width, width), turn)))
    if op in ("clz", "ctz"):
        # A chain of `ite`s, one per bit: the first bit that is set says the
        # answer, and an all-zero value falls through to the width.
        value = _widen(evaluate(args[0], env, width, state, address_width), width)
        term = const(width, width)
        for bit in range(width):
            index = bit if op == "clz" else width - 1 - bit
            probe = ("distinct", 1, ("extract", 1, index, index, value), const(0, 1))
            term = ("ite", width, probe,
                    const(width - 1 - index if op == "clz" else index, width), term)
        return term
    if op == "cpop":
        value = _widen(evaluate(args[0], env, width, state, address_width), width)
        total = const(0, width)
        for bit in range(width):
            total = ("bvadd", width, total,
                     ("zero_extend", width, width - 1, ("extract", 1, bit, bit, value)))
        return total
    if op in ("mulh", "mulhu", "mulhsu"):
        # The high half, which needs twice the width to exist in. `mulhsu` is
        # signed times unsigned, which is why the two arguments are extended
        # differently rather than by one rule.
        wide = width * 2
        left = _resize(_widen(evaluate(args[0], env, width, state, address_width), width),
                       wide, op in ("mulh", "mulhsu"))
        right = _resize(_widen(evaluate(args[1], env, width, state, address_width), width),
                        wide, op == "mulh")
        return ("extract", width, wide - 1, width, ("bvmul", wide, left, right))
    if op in ("sdiv", "srem", "udiv", "urem"):
        # ⚠️ Division by zero is the description's answer, not the theory's.
        # SMT-LIB leaves `bvsdiv` by zero to the solver and the golden model
        # returns 0, so the zero case is written out here rather than left to
        # whichever one the caller asks.
        left = _widen(evaluate(args[0], env, width, state, address_width), width)
        right = _widen(evaluate(args[1], env, width, state, address_width), width)
        kind = {"sdiv": "bvsdiv", "srem": "bvsrem",
                "udiv": "bvudiv", "urem": "bvurem"}[op]
        return ("ite", width, ("=", 1, right, const(0, width)), const(0, width),
                (kind, width, left, right))
    if op in ("ones", "zeros"):
        if op == "zeros":
            return const(0, width)
        # `(1 << min(count, width)) - 1`, written so a symbolic count works:
        # shifting all-ones left by the count and inverting gives exactly that,
        # including the saturating case, because a shift past the width is zero.
        count = (_widen(evaluate(args[0], env, width, state, address_width), width)
                 if args else const(width, width))
        return ("bvnot", width, ("bvshl", width, const((1 << width) - 1, width), count))
    if op in ("min", "max", "minu", "maxu"):
        left = _widen(evaluate(args[0], env, width, state, address_width), width)
        right = _widen(evaluate(args[1], env, width, state, address_width), width)
        less = "bvslt" if op in ("min", "max") else "bvult"
        test = (less, 1, left, right)
        pick = (left, right) if op in ("min", "minu") else (right, left)
        return ("ite", width, test, pick[0], pick[1])
    if op == "not":
        return ("bvnot", width, _widen(evaluate(args[0], env, width, state, address_width), width))
    if op in ("sext", "zext"):
        from_width = int(args[0]) if isinstance(args[0], str) and args[0].isdigit() else None
        value = evaluate(args[-1], env, from_width or width, state, address_width)
        if from_width and value[1] != from_width:
            value = _resize(value, from_width, False)
        return _resize(value, width, op == "sext")
    raise Declined(op)


class Memory:
    """Memory as an ARRAY term: `select` to read a byte, `store` to write one.

    ⚠️ A byte map can only answer at an address it knows, so a load from a
    computed address had to be concretised against a model or declined -- and
    every register starts free, so nearly every address is computed. An array
    term holds the whole memory as a VALUE: a store at a symbolic address is a
    new array, a load at another symbolic address is a `select`, and whether
    the two alias is a question about terms rather than a decision this makes
    on the caller's behalf. It is SMT-LIB's theory of arrays, so `path_smt`
    hands a solver something it already understands.

    Concretising is still available -- pass a `model` -- because it is what a
    symbolic executor does when it wants one run rather than all of them. The
    assumption is recorded as a constraint either way.
    """

    def __init__(self, image=b"", name="mem", model=None, path=None,
                 address_bits=64, code=None):
        self.image = bytes(image)
        self.name = name
        self.term = var(name, 8)
        #: Messages posted, in the order the instructions posted them.
        self.sent = []
        self.model = model
        self.path = [] if path is None else path
        self.address_bits = address_bits
        # ⚠️ The range the program lives in, if the caller declares one. A
        # store to a symbolic address might land on the next instruction, and
        # a machine that ignored that would be fetching bytes it had already
        # overwritten. Declaring the range does not make the question go away:
        # each such store records `addr < lo or addr >= hi` on the path, so the
        # assumption is one a solver -- or a concrete binding -- can refute.
        self.code = code

    def copy(self, path=None):
        other = Memory(self.image, self.name, self.model,
                       self.path if path is None else path, self.address_bits,
                       self.code)
        other.term = self.term
        return other

    def _missed_code(self, addr):
        if self.code is None or is_const(addr):
            return
        lo, hi = self.code
        self.path.append(("or", 1,
                          ("bvult", 1, addr, const(lo, addr[1])),
                          ("bvuge", 1, addr, const(hi, addr[1]))))

    def _address(self, addr):
        """The address as a term, concretised first if a model asks for it."""
        if self.model is None or is_const(addr):
            return addr
        value = concrete(addr, self.model)
        self.path.append(("=", 1, addr, const(value, addr[1])))
        return const(value, addr[1])

    def _byte_address(self, addr, index):
        if index == 0:
            return addr
        if is_const(addr):
            return const(addr[2] + index, addr[1])
        return ("bvadd", addr[1], addr, const(index, addr[1]))

    def byte(self, addr):
        return ("select", 8, self.term, addr)

    def read(self, addr, access):
        # ⚠️ Byte offsets are added at 64 bits, whatever width the ADDRESS was
        # computed at. The executor masks an address to the width the
        # description gives it and then hands it to the host, which walks the
        # bytes in its own arithmetic -- so a 32-bit address of all ones reads
        # the four bytes above 4GB rather than wrapping to zero. Wrapping here
        # instead made RV32I's atomics disagree with the machine they model.
        addr = _widen(self._address(addr), 64)
        pieces = [self.byte(self._byte_address(addr, i)) for i in range(access // 8)]
        if ENDIAN == "big":
            pieces.reverse()
        elif ENDIAN != "little":
            raise Declined(f"byte order `{ENDIAN}`")
        term = _widen(pieces[0], access)
        for i, piece in enumerate(pieces[1:], start=1):
            term = ("bvor", access, term,
                    ("bvshl", access, _widen(piece, access), const(8 * i, access)))
        return term

    def write(self, addr, value, access, guard=None):
        addr = _widen(self._address(addr), 64)
        count = access // 8
        for i in range(count):
            place = i if ENDIAN == "little" else count - 1 - i
            if ENDIAN not in ("little", "big"):
                raise Declined(f"byte order `{ENDIAN}`")
            at = self._byte_address(addr, place)
            self._missed_code(at)
            byte = ("extract", 8, 7, 0,
                    ("bvlshr", value[1], value, const(8 * i, value[1])))
            if guard is not None:
                # ⚠️ A guarded store is not a constraint. A store-conditional
                # that fails leaves the byte alone, and saying "assume it
                # succeeded" would describe half the machine. The byte keeps
                # its old value under the guard, which is what the executor
                # does and what a solver can reason about both ways.
                byte = ("ite", 8, _true(guard), byte, self.byte(at))
            self.term = ("store", 8, self.term, at, byte)

    def send(self, port, value, width, guard=None):
        """One message out of the machine, kept in order.

        ⚠️ A log, not an array. A store is a function from addresses to bytes,
        which is why memory is an SMT array and a later read of the same
        address sees the write. A message is not readable back: what a symbolic
        engine can say about one is *that it happened, with this port and this
        value, under this guard, in this position* -- so that is exactly what
        is kept, and a path that posts two messages has two entries rather than
        one that overwrote the other.
        """
        self.sent.append({
            "port": _widen(port, 64),
            "value": _widen(value, width),
            "width": width,
            "guard": guard,
        })


def _true(term):
    """A one-bit term as a boolean condition: `term != 0`."""
    if term[0] == "distinct" and term[1] == 1:
        return term
    return ("distinct", 1, term, const(0, term[1]))


def _not(term):
    return ("not", 1, term)


class State:
    """A machine: registers, a pc, memory, architectural state, and a path.

    Every input is a free variable -- registers, declared state, the bytes in
    memory -- so what comes out is a function of the inputs rather than of one
    run. `pc` is a TERM like everything else; it is concrete while the trace
    knows where it is, which is what lets the next word be fetched.
    """

    def __init__(self, slots, image=b"", prefix="r", model=None, pc=0, code=None):
        self.regs = {slot: var(f"{prefix}{slot}", 64) for slot in range(slots)}
        self.path = []
        self.branches = []
        self.state = {}
        self.mem = Memory(image, model=model, path=self.path, code=code)
        self.pc = pc if isinstance(pc, tuple) else const(pc, PC_BITS)
        self.declined = []
        self.steps = 0
        self.trace = []
        #: The cause this path trapped with, once it has. A trapped path is
        #: finished: the executor stops the instruction's remaining effects,
        #: and where control goes next is the machine's business rather than
        #: the instruction's.
        self.trapped = None

    def copy(self):
        other = State.__new__(State)
        other.regs = dict(self.regs)
        other.path = list(self.path)
        other.branches = list(self.branches)
        other.state = dict(self.state)
        other.mem = self.mem.copy(other.path)
        other.pc = self.pc
        other.declined = list(self.declined)
        other.steps = self.steps
        other.trace = list(self.trace)
        other.trapped = self.trapped
        return other

    def register(self, slot):
        return self.regs.get(slot, const(0, 64))

    def bindings(self, values, state=None, image=None, aliases=None):
        """Concrete values for the variables this state started with."""
        bound = {f"r{slot}": value for slot, value in enumerate(values)}
        # An aliased register -- AArch64's `sp` -- is named rather than
        # numbered, and starts at whatever the caller's machine holds for it.
        for kind, rules in getattr(axis_lift, "REGISTER_CLASSES", {}).items():
            alias = rules[1]
            if alias is not None:
                bound.setdefault(f"reg_{alias[1]}", (aliases or {}).get(alias[1], 0))
        for name, _bits in getattr(axis_lift, "STATE_SLOTS", ()):
            bound[f"state_{name}"] = (state or {}).get(name, 0)
        bound[self.mem.name] = self.mem.image if image is None else image
        return bound

    def holds(self, bindings):
        """Whether every constraint on this path is true for these inputs.

        ⚠️ This is the property a machine has that a single instruction does
        not: for any one input exactly ONE explored path can hold, and it is
        the one the concrete machine took. A symbolic executor that forks
        wrongly shows up here as two paths holding, or none.
        """
        for term in self.path:
            if concrete(term, bindings) == 0:
                return False
        return True


def path_smt(state, extra=()):
    """The path as an SMT-LIB script a solver can answer.

    No solver is called here -- `concrete` is what this backend is checked
    with -- but a caller asking "can this branch go the other way" needs the
    constraints in a form something else can read.
    """
    # Arrays for memory, bit-vectors for everything, floats where a branch
    # asked about one. Naming a narrower logic than the terms need is a script
    # the solver rejects rather than an optimisation.
    #
    # ⚠️ `ALL`, not `QF_ABVFP`, although QF_ABVFP is the correct standard name
    # for exactly this combination. z3 4.16 does not register the
    # bit-vector-to-float `(_ to_fp eb sb)` under it -- the same one-line
    # assertion that is `sat` under QF_BVFP or ALL is REJECTED as an unknown
    # constant once arrays join the logic. Every path whose branch condition
    # reads a float register through memory was therefore a script the solver
    # refused, and the only path that had one was never sampled until the
    # instruction pool grew and the draw moved.
    lines = ["(set-logic ALL)"]
    seen = {}
    for term in list(state.path) + list(extra):
        variables(term, seen)
    for name, bits in sorted(seen.items()):
        if name == state.mem.name:
            lines.append(f"(declare-fun {name} () (Array (_ BitVec "
                         f"{state.mem.address_bits}) (_ BitVec 8)))")
        else:
            lines.append(f"(declare-fun {name} () (_ BitVec {bits}))")
    body = [f"(assert {_smt_bool(term)})" for term in list(state.path) + list(extra)]
    if any("axis_a64_" in line for line in body):
        lines.append(SMT_PRELUDE)
    lines.extend(body)
    lines.append("(check-sat)")
    return "\n".join(lines) + "\n"


def _fetch_byte(mem, at, image, code=None):
    """One byte of the program: the image, and any store that can be resolved.

    A store to a concrete address that is not this one cannot have changed it.
    A store to a symbolic address might have -- unless the caller declared the
    code range, in which case the path already carries the constraint that it
    missed, and reading the image is what that constraint means. With no such
    range there is nothing to lean on and the fetch is declined by name.
    """
    while mem[0] == "store":
        _kind, _width, inner, addr, value = mem
        if not is_const(addr):
            if code is not None and code[0] <= at < code[1]:
                mem = inner
                continue
            raise Declined("a fetch past a store to a symbolic address")
        if addr[2] == at:
            if not is_const(value):
                raise Declined("a fetch of a byte written symbolically")
            return value[2]
        mem = inner
    return image[at] if at < len(image) else 0


def fetch(state):
    """The word at the pc, out of the machine's own memory.

    A program is bytes the machine reads, not a list the caller holds --
    fetching from the same memory the instructions write is what makes this a
    machine rather than a stepper. It is also why the pc must be concrete:
    reading an instruction from a symbolic address is a solver's question.
    """
    if not is_const(state.pc):
        raise Declined("a fetch from a symbolic pc")
    at = state.pc[2]
    count = ILEN
    word = 0
    for i in range(count):
        byte = _fetch_byte(state.mem.term, at + i, state.mem.image, state.mem.code)
        place = i if ENDIAN == "little" else count - 1 - i
        word |= byte << (8 * place)
    return word


def _operands(entry, word):
    """The operand values the encoding carries, as the executors read them."""
    values = {}
    for operand in entry["operands"]:
        fields = operand["fields"]
        values[operand["name"]] = axis_lift._extract(word, fields) if fields else operand.get("fixed")
    for operand in entry["operands"]:
        source = operand.get("derived_from")
        if source:
            values[operand["name"]] = values[source] + operand["derived_add"]
    return values


def class_objection(operand):
    """What an operand's register class asks for that this cannot model.

    ⚠️ A register file is not an array of independent words, and treating it
    as one is wrong in ways that look like arithmetic bugs. A class can view
    part of a register (`W0` is the low half of `X0`), can take more than one
    slot (AArch64's `D` registers sit inside 128-bit ones), can alias a state
    slot (`SP` at index 31), and can preserve the bits its view does not cover
    (x86's `AL` leaves the top of `RAX` alone). What is modelled here is the
    zeroing view -- write the view, clear the rest of the register -- because
    it is the one whose term is exact. The others are declined by name.
    """
    kind = operand["kind"]
    rules = getattr(axis_lift, "REGISTER_CLASSES", {}).get(kind)
    if rules is None:
        return f"`{kind}` names no register class"
    _zero, _alias, view, _offset, view_offset, preserves, limbs = rules[:7]
    if preserves:
        return f"`{kind}` preserves the bits outside its view"
    if view_offset:
        return f"`{kind}` views a register from bit {view_offset}"
    if limbs > 1 and not view:
        return f"`{kind}` holds a register wider than a slot"
    if operand.get("view_width") or operand.get("stride") or operand.get("slot_base"):
        return f"`{operand['name']}` places its value inside the register itself"
    return None


def _register_read(state, kind, index):
    """One register as an expression sees it: the class's view, its zero."""
    rules = axis_lift.REGISTER_CLASSES[kind]
    zero, alias, view, _offset, _view_offset, _preserves, _limbs = rules[:7]
    if zero is not None and index == zero:
        return const(0, 64)
    if alias is not None and index == alias[0]:
        # ⚠️ An index that is not in the file at all. AArch64 encodes `SP` as
        # 31 in the classes that have one, and it lives beside the registers
        # rather than among them -- the executor keeps it in the same dict
        # under its name, and so does this, so the two stay one machine.
        term = state.regs.get(alias[1]) or var(f"reg_{alias[1]}", 64)
        return (("bvand", 64, term, const((1 << view) - 1, 64))
                if view and view < 64 else term)
    term = state.register(axis_lift.register_slot(kind, index))
    return term


def _register_write(state, kind, index, term, guard=None):
    """Commit a register write the way the executor's `_write_reg` does.

    A zeroing view clears the WHOLE register, and the rest of it can be a limb
    away: writing a 64-bit `D` register zeroes the upper half of the 128-bit
    one it lives in. Writing one slot and leaving the other is how a value that
    was never stored comes back on the next read.
    """
    rules = axis_lift.REGISTER_CLASSES[kind]
    zero, alias, view, _offset, _view_offset, _preserves, limbs = rules[:7]
    if zero is not None and index == zero:
        return {}                      # the hardwired zero discards writes
    value = _widen(term, 64)
    if view and view < 64:
        value = ("bvand", 64, value, const((1 << view) - 1, 64))
    if alias is not None and index == alias[0]:
        name = alias[1]
        if guard is not None:
            previous = state.regs.get(name) or var(f"reg_{name}", 64)
            value = ("ite", 64, guard, value, previous)
        state.regs[name] = value
        return {name: value}
    slot = axis_lift.register_slot(kind, index)
    written = {}
    for limb in range(max(limbs, 1)):
        target = slot + limb
        fresh = value if limb == 0 else const(0, 64)
        if guard is not None:
            fresh = ("ite", 64, guard, fresh, state.register(target))
        state.regs[target] = fresh
        written[target] = fresh
    return written


def _environment(state, entry, values):
    env = {}
    # ⚠️ Architectural state as the MACHINE holds it now, not as it started.
    # `evaluate` falls back to a free variable for a declared state symbol,
    # which is right for the first instruction and wrong for every one after
    # it: `fflags` accumulates, and a second floating-point instruction that
    # read the initial variable dropped the flags the first had raised. One
    # instruction at a time could never see this -- it always starts fresh.
    for name, bits in getattr(axis_lift, "STATE_SLOTS", ()):
        env[name] = state.state.get(name) or var(f"state_{name}", bits)
    for operand in entry["operands"]:
        raw = values.get(operand["name"])
        if raw is None:
            continue
        if axis_lift.is_register_operand(operand["kind"]):
            objection = class_objection(operand)
            if objection:
                raise Declined(objection)
            env[operand["name"]] = _register_read(state, operand["kind"], raw)
        else:
            env[operand["name"]] = const(raw, max(operand.get("width") or 64, 1))
    # ⚠️ The entry value of every operand, under `__input_<name>`. A
    # compare-and-swap writes its `rs` and then asks whether the value it
    # replaced was the one it expected -- against `__input_rs`, not `rs`, which
    # by then holds what memory had. The executor binds these before the walk;
    # so does this.
    for name in list(env):
        env[f"__input_{name}"] = env[name]
    env["pc"] = _widen(state.pc, entry.get("state_width") or 64)
    return env


def _term(text, env, width, state, address_width=None):
    return evaluate(golden_model._parse(golden_model._tokenize(text)),
                    env, width, state.mem, address_width)


def _apply(state, word, isa=None, survive=0):
    """Run one instruction INTO `state`, leaving the pc to the caller.

    Returns what it did: the registers it wrote, the branches it proposed, and
    any trap it reached. The pc is not advanced here because what happens to it
    is exactly the thing `successors` has to fork over.

    `survive` says how many guarded traps to treat as not having fired -- the
    other side of the fork `successors` makes. A trap stops the walk, exactly
    as it stops the executor's, so the effects after it belong only to the path
    where its guard was false.
    """
    entry = axis_lift.decode(word, isa)
    if entry is None:
        return {"mnemonic": None, "ok": False, "why": "does not decode",
                "branches": [], "wrote": {}, "trap": None}
    values = _operands(entry, word)
    mnemonic = entry["mnemonic"]
    try:
        env = _environment(state, entry, values)
    except Declined as why:
        state.declined.append((mnemonic, str(why)))
        return {"mnemonic": mnemonic, "ok": False, "why": str(why),
                "branches": [], "wrote": {}, "trap": None}
    effects = entry.get("effects")

    if not effects:
        # ⚠️ The PURE path. Most instructions are described by a single value
        # written to their output operand, which the parser promotes into
        # `formal_semantics` and leaves no effects behind -- so a symbolic
        # executor that only walked effects interpreted one instruction in
        # three hundred and thirty-six and declined the rest.
        text = entry.get("semantics")
        if not text:
            return {"mnemonic": mnemonic, "ok": False, "branches": [], "wrote": {},
                    "trap": None, "why": "neither effects nor semantics"}
        dest = next((o for o in entry["operands"]
                     if o["role"] in ("out", "inout")
                     and axis_lift.is_register_operand(o["kind"])), None)
        if dest is None:
            return {"mnemonic": mnemonic, "ok": False, "branches": [], "wrote": {},
                    "trap": None, "why": "no register destination"}
        try:
            term = _term(text, env, entry.get("state_width") or 64, state)
        except Declined as why:
            state.declined.append((mnemonic, str(why)))
            return {"mnemonic": mnemonic, "ok": False, "why": str(why),
                    "branches": [], "wrote": {}, "trap": None}
        wrote = _register_write(state, dest["kind"], values[dest["name"]], term)
        return {"mnemonic": mnemonic, "ok": True, "wrote": wrote,
                "branches": [], "trap": None}

    wrote, branches = {}, []
    trap = None
    seen_traps = 0
    survived = []
    try:
        for effect in effects:
            guard = None
            if effect.get("guard"):
                guard = _true(_term(effect["guard"], env,
                                    effect.get("guard_width") or 64, state))
            kind = effect["kind"]
            if kind == "trap":
                # ⚠️ A guarded trap is a fork, not a constraint and not a
                # decline: `fadd.d` with a dynamic rounding mode traps when the
                # mode is one no machine has, and both ways are real. The
                # caller takes the trapping side once and then asks for the
                # instruction again with this one survived.
                if guard is not None and seen_traps < survive:
                    seen_traps += 1
                    survived.append(guard)
                    continue
                trap = {"cause": effect.get("cause"), "when": guard}
                break
            if kind == "barrier":
                # The executor is single-threaded and evaluates the value for
                # its own sake; a fence orders nothing it can observe. Same
                # here -- and evaluating it keeps an operator this backend
                # cannot express a decline rather than a silent skip.
                _term(effect["value"], env, effect.get("eval_width") or 64, state,
                      effect.get("load_address_width"))
                continue
            if kind == "set":
                term = _term(effect["value"], env, effect["eval_width"], state,
                             effect.get("load_address_width"))
                dest = effect["dest"]
                operand = next(o for o in entry["operands"] if o["name"] == dest)
                held = _widen(term, effect["width"])
                if guard is not None:
                    # ⚠️ A guarded write is an `ite`, not a path constraint.
                    # Asserting the guard would say the write happened -- which
                    # is a decision, and the wrong one half the time. The
                    # register holds its old value under the guard, exactly as
                    # the executor leaves it.
                    previous = env.get(dest)
                    if previous is not None:
                        held = ("ite", held[1], guard, held,
                                _widen(previous, held[1]))
                wrote.update(_register_write(state, operand["kind"],
                                             values.get(dest), term, guard))
                # ⚠️ Later effects in the SAME instruction see this write.
                # `amoxor.w` is two effects -- `rd = atomic_load(rs1)` then
                # `store rs1, rd ^ rs2` -- so the store's value names a
                # register the set just wrote. Evaluating it against the old
                # environment stored the wrong bytes, and no register was
                # wrong, which is why a gate that compared only registers
                # never saw it. The executor keeps the semantic result here
                # even when the architectural destination discards it.
                env[dest] = held
            elif kind == "store":
                addr = _term(effect["addr"], env, effect.get("addr_width") or 64, state)
                term = _term(effect["value"], env, effect["width"], state,
                             effect.get("load_address_width"))
                state.mem.write(addr, _widen(term, effect["width"]),
                                effect["width"], guard)
            elif kind == "send":
                # A message out of the machine: where it goes, then what goes.
                port = _term(effect["port"], env, effect.get("port_width") or 64, state)
                term = _term(effect["value"], env, effect["width"], state,
                             effect.get("load_address_width"))
                state.mem.send(port, _widen(term, effect["width"]),
                               effect["width"], guard)
            elif kind == "setpc":
                # ⚠️ The reason a symbolic executor exists. A guarded `setpc`
                # is a branch: the guard is kept with the target so
                # `successors` can return BOTH ways, each with the constraint
                # that says when it is the one taken.
                target = _term(effect["value"], env,
                               effect.get("eval_width") or 64, state,
                               effect.get("load_address_width"))
                branches.append({"target": target, "when": guard})
            elif kind == "setreg":
                # A register the INSTRUCTION names rather than an operand:
                # `bl` writes the link register whatever its encoding says.
                term = _widen(_term(effect["value"], env,
                                    effect.get("eval_width") or 64, state,
                                    effect.get("load_address_width")),
                              effect.get("width") or 64)
                wrote.update(_register_write(state, effect["reg_kind"],
                                             effect["index"], term, guard))
            elif kind == "setstate":
                term = _term(effect["value"], env,
                             effect.get("eval_width") or 64, state,
                             effect.get("load_address_width"))
                name = effect["state"]
                term = _widen(term, effect.get("width") or term[1])
                if guard is not None:
                    # ⚠️ This was a decline, and the reason is worth keeping:
                    # every guarded `setstate` in these corpora sits on a
                    # floating-point instruction with a `trap` effect, and
                    # while both were refused the `ite` here would have been
                    # code that looks right and no gate could run. Modelling
                    # the trap made them reachable, so it is written -- and
                    # the gates vary the rounding mode, because a guard that
                    # is always true tests an `ite` no better than a decline.
                    bits = term[1]
                    previous = state.state.get(name) or var(f"state_{name}", bits)
                    term = ("ite", bits, guard, term, _widen(previous, bits))
                state.state[name] = term
                env[name] = term
            else:
                raise Declined(f"effect `{kind}`")
    except Declined as why:
        state.declined.append((mnemonic, str(why)))
        return {"mnemonic": mnemonic, "ok": False, "why": str(why),
                "branches": [], "wrote": {}, "trap": None}

    if trap is not None:
        state.trapped = trap["cause"]
    return {"mnemonic": mnemonic, "ok": True, "wrote": wrote,
            "branches": branches, "trap": trap, "survived": survived}


def effects_of(state, word, isa):
    """How many effects the instruction has -- the most traps it could hold."""
    entry = axis_lift.decode(word, isa)
    return (entry.get("effects") or []) if entry else []


def step(state, word=None, isa=None, slots=None):
    """One instruction, symbolically, in place.

    `word` defaults to whatever the machine's memory holds at its pc. A branch
    is reported rather than followed: this takes the fall-through and records
    what the instruction proposed, because choosing a direction is what
    `successors` exists to refuse to do for the caller.
    """
    if word is None:
        try:
            word = fetch(state)
        except Declined as why:
            return {"mnemonic": None, "ok": False, "why": str(why)}
    # ⚠️ A guarded trap is survived here, not taken. This is the fall-through
    # rule again: `step` does not choose a path, so it runs the instruction the
    # way it runs when nothing traps -- and records `not guard` on the path, so
    # the assumption is one a caller can check rather than one made silently.
    # `successors` is where both sides are returned.
    record = _apply(state, word, isa, survive=len(effects_of(state, word, isa)))
    if not record["ok"]:
        return record
    for guard in record.get("survived", ()):
        state.path.append(_not(guard))
    if record.get("trap") is not None:
        return {"mnemonic": record["mnemonic"], "ok": True, "wrote": record["wrote"],
                "constraints": [], "branches": [], "trap": record["trap"]}
    state.branches.extend(record["branches"])
    state.steps += 1
    jump = next((b for b in record["branches"] if b["when"] is None), None)
    state.pc = (jump["target"] if jump is not None
                else ("bvadd", PC_BITS, state.pc,
                      const(ILEN, PC_BITS)))
    state.pc = _fold(state.pc)
    return {"mnemonic": record["mnemonic"], "ok": True, "wrote": record["wrote"],
            "constraints": [], "branches": record["branches"]}


def _fold(term):
    """A term with no variables is a number; keep the pc concrete when it is.

    Not an optimiser -- this folds one shape, the pc, because a pc that stayed
    a term after `pc + 4` could never be fetched from again.
    """
    if is_const(term):
        return term
    try:
        if not variables(term):
            return const(concrete(term, {}), term[1])
    except Declined:
        pass
    return term


def successors(state, isa=None, word=None, limit=2):
    """Every state the machine can be in after the instruction at its pc.

    One state when nothing branches; two when a guarded `setpc` does, each
    carrying the constraint that says when it is the one taken. This is the
    whole difference between stepping an instruction and running a machine.
    """
    base = state.copy()
    if word is None:
        try:
            word = fetch(base)
        except Declined as why:
            base.declined.append((None, str(why)))
            return [], {"ok": False, "why": str(why), "mnemonic": None}
    record = _apply(base, word, isa)
    if not record["ok"]:
        return [], record
    base.steps += 1
    trap = record.get("trap")
    if trap is not None:
        # The trapping path stops here, carrying the state as of the trap --
        # the executor keeps the writes an instruction made before trapping.
        if trap["when"] is None:
            return [base], record
        base.path.append(trap["when"])
        # And the other side: the same instruction with this trap survived,
        # which is where its remaining effects live.
        other = state.copy()
        onward = _apply(other, word, isa, survive=1)
        if not onward["ok"]:
            return [base], record
        other.steps += 1
        other.path.append(_not(trap["when"]))
        if onward.get("trap") is not None:
            # A second trap on the surviving path is one fork this does not
            # take: named, rather than explored halfway.
            other.declined.append((onward["mnemonic"], "a second guarded trap"))
            return [base, other], record
        other.pc = _fold(_next_pc(other, onward))
        return [base, other], record
    branches = record["branches"]
    fall = ("bvadd", PC_BITS, base.pc, const(ILEN, PC_BITS))
    if not branches:
        base.pc = _fold(fall)
        return [base], record
    if len(branches) > 1:
        why = f"{len(branches)} `setpc` effects in one instruction"
        base.declined.append((record["mnemonic"], why))
        return [], {"ok": False, "why": why, "mnemonic": record["mnemonic"]}
    branch = branches[0]
    if branch["when"] is None:
        base.pc = _fold(branch["target"])
        return [base], record
    taken = base
    taken.path.append(branch["when"])
    taken.pc = _fold(branch["target"])
    other = state.copy()
    _apply(other, word, isa)
    other.steps += 1
    other.path.append(_not(branch["when"]))
    other.pc = _fold(fall)
    return [taken, other], record


def _next_pc(machine, record):
    """Where an instruction leaves the pc when nothing forks over it."""
    jump = next((b for b in record["branches"] if b["when"] is None), None)
    if jump is not None:
        return jump["target"]
    return ("bvadd", PC_BITS, machine.pc, const(ILEN, PC_BITS))


def explore(state, steps=32, paths=16, isa=None, stop=None):
    """Run the machine until every path stops, breadth first.

    A path stops when `stop` says so -- normally the pc leaving the region
    under test -- when it runs out of steps, or when something is declined.
    Nothing here decides which way a branch goes: both are explored, each
    carrying the constraints that would have to hold for it.
    """
    active, finished, declined = [state], [], []
    while active:
        if len(finished) + len(active) > paths:
            finished.extend(active)
            break
        machine = active.pop(0)
        if machine.trapped is not None:
            # A trapped path is finished. Where a machine goes after a trap is
            # the machine's business -- a handler, a mode change -- and this
            # describes an instruction set.
            finished.append(machine)
            continue
        if machine.steps >= steps or (stop is not None and stop(machine)):
            finished.append(machine)
            continue
        nexts, record = successors(machine, isa)
        if not record["ok"]:
            # ⚠️ On the state that stops, not only in the summary. A path that
            # ends because something was refused is not a path the machine
            # took, and a caller comparing it against a concrete run would be
            # comparing against a trace that stopped early -- which reads as a
            # disagreement and is not one.
            declined.append((record.get("mnemonic"), record["why"]))
            machine.declined.append((record.get("mnemonic"), record["why"]))
            finished.append(machine)
            continue
        active.extend(nexts)
    return {"finished": finished, "declined": declined}
"##;

pub fn emit_exec_python(_document: &Document) -> String {
    EXEC_PY_RUNTIME.to_string()
}

const EXEC_PY_RUNTIME: &str = r#"# Generated by AXIS. Functional single-step interpreter (decode -> execute).
# schema: axis.exec-python.v1
#
# Composes the decode/lift table (axis_lift) with the proven golden semantics
# (golden_model): decode a word, bind register/immediate operands, evaluate the
# instruction, and write the result to the destination register. Both imported
# modules are emitted alongside this one.
import axis_lift
import golden_model

AXIS_SCHEMA = "axis.exec-python.v1"


ILEN = 4


def _read_reg(regs, index, kind, stride=0, view_offset=0, view_width=0,
              slot_base=None):
    """Read an architectural register operand.

    The class's rules come from the generated table rather than from branches
    per architecture: which index (if any) is hardwired to zero, which index (if
    any) names a state slot instead of the file, and how wide a read is. AArch64
    register 31 is the zero register or SP depending on the class; RISC-V's x0 is
    hardwired zero; a plain `reg` has no special index at all.
    """
    rules = axis_lift.REGISTER_CLASSES.get(kind)
    if rules is None:
        raise ValueError("not a register operand kind: " + repr(kind))
    zero, alias, view, offset, class_offset, _preserves, limbs = rules[:7]
    # Where the class's registers start *within* its file. Three bits of a
    # compressed RISC-V instruction name `x8`-`x15`, so the field's 0 is the
    # file's 8; a class that does not window its file says 0.
    window = rules[7] if len(rules) > 7 else 0
    # An operand may place its value inside the register the class names --
    # element 5 of a scalable register, whose bits depend on VL and the element
    # width rather than on the architecture, so no compile-time class can say
    # where they are. Zero means "no override, read the class's view".
    if view_width:
        view, view_offset, limbs, window = view_width, view_offset, max(stride, 1), 0
        # A file above a scalable one starts where that file ends, which moves
        # with VL -- so the base comes with the placement rather than from the
        # class.
        offset = offset if slot_base is None else slot_base
    else:
        view_offset = class_offset
    if zero is not None and index == zero:
        return 0
    if alias is not None and index == alias[0]:
        # The view applies to an alias too: AArch64 reads W-SP as the low 32
        # bits of the same `sp` the 64-bit class reads whole.
        aliased = regs.get(alias[1], 0)
        return ((aliased >> view_offset) & ((1 << view) - 1) if view
                else aliased & 0xffffffffffffffff)
    slot = offset + (window + index) * limbs
    if not view:
        # A register with no view is read whole, and whole can be more than one
        # slot: a 128-bit vector register is two limbs of 64, which is how the
        # file stores it and how every backend that computes in machine words
        # has to see it. Reading only `slot` returned the low half and called it
        # the register. A class of one slot is read exactly as it was.
        if limbs > 1:
            whole = 0
            for k in range(limbs):
                whole |= (regs.get(slot + k, 0) & 0xffffffffffffffff) << (64 * k)
            return whole
        return regs.get(slot, 0) & 0xffffffffffffffff
    # A view need not start at the low bit (x86's AH is bits 8..16) and, in a
    # register held as several limbs, need not stay inside one: a 32-bit view at
    # bit 48 of a 128-bit register takes 16 bits from each of two slots. It is
    # never wider than a limb, so it spans at most two and no loop is needed.
    slot += view_offset // 64
    shift = view_offset % 64
    low = regs.get(slot, 0) >> shift
    if shift and shift + view > 64:
        low |= regs.get(slot + 1, 0) << (64 - shift)
    return low & ((1 << view) - 1)


def _operand_register(operand, decoded):
    """Which register this operand names.

    The decoded selector, plus the register its element sits in: a lane past a
    register's capacity is in the next one, which is register grouping. Zero for
    everything that is not a lane.
    """
    return decoded + operand.get("register_bias", 0)


def _read_operand(regs, operand, decoded):
    """Read what this operand names, through its placement if it has one."""
    return _read_reg(regs, _operand_register(operand, decoded), operand["kind"],
                     operand.get("stride", 0), operand.get("view_offset", 0),
                     operand.get("view_width", 0), operand.get("slot_base"))


def _write_operand(regs, operand, decoded, value):
    """Write what this operand names, through its placement if it has one."""
    return _write_reg(regs, _operand_register(operand, decoded), operand["kind"],
                      value, operand.get("stride", 0),
                      operand.get("view_offset", 0), operand.get("view_width", 0),
                      operand.get("slot_base"))


def _write_reg(regs, index, kind, value, stride=0, view_offset=0, view_width=0,
               slot_base=None):
    """Write an architectural register; return whether state changed."""
    rules = axis_lift.REGISTER_CLASSES.get(kind)
    if rules is None:
        raise ValueError("not a register operand kind: " + repr(kind))
    zero, alias, view, offset, class_offset, preserves, limbs = rules[:7]
    window = rules[7] if len(rules) > 7 else 0
    if view_width:
        # The operand's own view, as in `_read_reg`. A lane writes one element
        # and leaves the rest of the register alone, which is what a preserving
        # narrow write already does -- so the policy comes from the class and
        # the placement from the operand.
        view, view_offset, limbs, preserves, window = (
            view_width, view_offset, max(stride, 1), True, 0)
        offset = offset if slot_base is None else slot_base
    else:
        view_offset = class_offset
    # A narrow view covers part of a register, and what happens to the rest is
    # the architecture's choice rather than a detail: writing AArch64's W0
    # zeroes the upper half of X0, while writing x86's AL preserves the upper
    # 56 bits of RAX. Without a view there is nothing to narrow *to*: the value
    # has already been masked to the operand's width, and a register file can
    # be wider than 64 bits -- masking to 64 here truncated the 128-bit vector
    # registers.
    if view:
        value &= (1 << view) - 1
    if zero is not None and index == zero:
        return False                       # hardwired zero discards writes
    if alias is not None and index == alias[0]:
        regs[alias[1]] = value
        return True
    slot = offset + (window + index) * limbs
    if not view:
        # The same split, the other way. Storing a 128-bit value into one slot
        # relied on Python's integers being unbounded, so the reference held a
        # number no register file and no other backend could hold -- and the
        # read above masked to 64, so a value written here came back halved.
        #
        # The class says how many slots one of its registers has, and that is
        # the only thing consulted: a class of one slot takes the value whole,
        # which is what a description that models a wide vector as a single
        # `reg` is asking for. Splitting by the *value's* width instead would
        # narrow those to 64 bits and quietly change a corpus that never said
        # its registers had limbs.
        if limbs > 1:
            for k in range(limbs):
                regs[slot + k] = (value >> (64 * k)) & 0xffffffffffffffff
        else:
            regs[slot] = value
        return True
    # A zeroing view clears the whole register: "the rest becomes zero" is a
    # statement about the register, and the rest can be a whole limb away.
    if not preserves:
        for k in range(limbs):
            regs[slot + k] = 0
    low_slot = slot + view_offset // 64
    shift = view_offset % 64
    mask_low = (((1 << view) - 1) << shift) & 0xffffffffffffffff
    regs[low_slot] = ((regs.get(low_slot, 0) & ~mask_low)
                      | ((value << shift) & mask_low)) & 0xffffffffffffffff
    if shift and shift + view > 64:
        mask_high = (1 << (shift + view - 64)) - 1
        regs[low_slot + 1] = ((regs.get(low_slot + 1, 0) & ~mask_high)
                              | ((value >> (64 - shift)) & mask_high)) & 0xffffffffffffffff
    return True


def decode_in_mode(word, mode, isa=None):
    """Mode-aware decode (P4): among instructions matching `word`, the one legal
    in `mode` (an instruction with empty `modes` is legal in all). Returns the
    entry, or None when the word is illegal in this mode (no legal match)."""
    legal = [
        entry
        for entry in axis_lift.AXIS_LIFT_TABLE
        if word & entry["mask"] == entry["match"]
        and (not entry.get("modes") or mode in entry["modes"])
        and (isa is None or not entry.get("isa") or entry["isa"] == isa)
        and axis_lift._constraint_ok(word, entry)
    ]
    return legal[0] if len(legal) == 1 else None


def step(word, regs, mem=None, pc=0, mode=None, isa=None, state=None):
    """Execute the instruction `word` encodes.

    A scalable instruction *is* its lanes: one word instantiates to `VL/elem`
    ordinary scalar operations over elements of the registers it names, and all
    of them share the word, which is why decode returns a group. Executing the
    word means executing each lane in order, so that is what this does. The
    result reported is the last lane's, and the writes are the union -- a
    scalable instruction writes one element per lane, and the caller wants the
    register file afterwards rather than sixteen separate answers.

    Every other instruction is a group of one, and takes the same path.
    """
    lanes = [] if mode is not None else axis_lift.decode_lanes(word, isa)
    if len(lanes) <= 1:
        return _step_entry(word, regs, mem, pc, mode, isa, state)
    written, state_written, result = {}, {}, None
    next_pc, trap = pc + ILEN, None
    # ⚠️ Every lane reads the registers and state as they were BEFORE the
    # instruction, as the architecture does: an instruction reads its sources
    # and then writes. Run in place, lane k's write was lane k+1's source
    # whenever a destination is also a source -- `uzp2 z11.s, z9.s, z11.s`
    # read an element UZP had already overwritten, and Arm's model said so.
    before_regs = dict(regs)
    before_state = dict(state) if state is not None else None
    for lane in lanes:
        lane_regs = dict(before_regs)
        lane_state = dict(before_state) if before_state is not None else None
        outcome = _step_entry(word, lane_regs, mem, pc, mode, isa, lane_state, entry=lane)
        if outcome is None:
            return None
        # Merged by the BITS this lane changed: two lanes write different
        # elements of one 64-bit slot (a .S element is half of one), and a
        # whole-slot copy would put back what the other lane wrote.
        for slot, value in lane_regs.items():
            old = before_regs.get(slot, 0)
            if slot not in before_regs or old != value:
                changed = old ^ value
                regs[slot] = (regs.get(slot, 0) & ~changed) | (value & changed)
        if lane_state is not None:
            for name, value in lane_state.items():
                if before_state.get(name) != value or name not in before_state:
                    state[name] = value
        result = outcome["result"]
        written.update(outcome["writes"])
        state_written.update(outcome.get("state_writes") or {})
        if outcome.get("trap") is not None:
            trap = outcome["trap"]
            break
        if outcome.get("next_pc") is not None:
            next_pc = outcome["next_pc"]
    return {
        "mnemonic": lanes[0].get("scalable_origin") or lanes[0]["mnemonic"],
        "result": result,
        "writes": written,
        "state_writes": state_written,
        "next_pc": next_pc,
        "trap": trap,
    }


class _PacketState(dict):
    """A register file or state map that remembers what a syllable assigned.

    A packet's conflict rule is structural: two slots writing one location is a
    conflict whatever the values, because it is one write port either way. That
    cannot be read off a before/after value diff -- writing a register the value
    it already held leaves no diff and still uses the port -- so the assignment
    itself is what gets recorded.
    """

    def __init__(self, source=None):
        super().__init__(source or {})
        self.assigned = {}

    def __setitem__(self, key, value):
        self.assigned[key] = value
        super().__setitem__(key, value)


class _PacketMemory:
    """Memory as one syllable of a packet sees it.

    Reads reach the real memory, which still holds what the packet started
    with, because no sibling's store has been applied. Writes are buffered for
    the commit. That is the whole of "a load in one slot does not see a store in
    another".
    """

    def __init__(self, inner):
        self._inner = inner
        self.writes = []

    def read(self, addr, width_bits):
        return self._inner.read(addr, width_bits)

    def write(self, addr, value, width_bits):
        self.writes.append((addr, value, width_bits))


def step_syllable(word, entry, regs, mem=None, pc=0, isa=None, state=None):
    """Execute one syllable against an entry decode has already chosen.

    A syllable is decoded by position, so the caller holds the entry; going back
    through `step` would re-decode the word, and a word two slots can hold is
    ambiguous on its own. Mutates `regs`/`state`/`mem` in place, exactly as
    `step` does for a lone instruction.
    """
    return _step_entry(word, regs, mem, pc, None, isa, state, entry=entry)


def packet_bytes(words, packet=None, isa=None):
    """How many bytes the packet at `words` occupies, or 0 if it does not decode."""
    decoded = axis_lift.decode_packet(words, packet, isa)
    return 0 if decoded is None else ILEN * len(decoded)


def new_delay_queue(packet=None):
    """An empty delay queue for an exposed packet, or None for an interlocked one.

    The queue is architectural state under `hazards exposed`, so the caller
    holds it the way it holds the register file, and a checkpoint carries it
    (`docs/vliw_spatial_design.md` §7). `stages[k]` holds the writes that commit
    after `k + 1` more packet ends.

    Its depth comes from the packet table rather than from a maximum recomputed
    here, because the capsule's `__delay` section is sized from that same
    number: an executor and a checkpoint format that each worked out the depth
    for themselves would be two answers to one question.
    """
    shape = axis_lift.packet(packet)
    if shape is None or shape["hazards"] != "exposed":
        return None
    return [[] for _ in range(shape["delay_stages"])]


def step_packet(words, regs, mem=None, pc=0, packet=None, isa=None, state=None,
                delayed=None):
    """Execute one issue packet: every syllable reads one state, all writes land together.

    Each syllable is evaluated against the state the packet started with -- a
    private copy of the register file and of the architectural state, and a
    memory whose reads reach the real one and whose writes are buffered. The
    writes are then applied in slot order. So a read-after-write between slots
    reads the **old** value, and a load in one slot does not see a store in
    another (`docs/vliw_spatial_design.md` §6).

    Two syllables writing one location is reported as a `conflict` and commits
    **nothing**. It is never resolved by slot order: a machine that genuinely
    picks a winner has to say so, and none can say so yet, so a silent
    last-slot-wins would be this executor inventing an architecture.

    A trap in any syllable also commits nothing -- a packet retires whole or not
    at all -- and the first trap in slot order is the one reported.

    Under `hazards exposed` the machine does not interlock: a write with latency
    L is visible to the packet issued L packets later, and the schedule is
    responsible for the gap. `delayed` is that queue — held by the caller, like
    the register file, because it *is* architectural state (§7). A latency of 1
    is visible to the next packet and so commits here, which is why an exposed
    machine whose every latency is 1 behaves exactly like an interlocked one.
    Only register writes wait: stores, state writes and control transfers
    commit with the packet.

    Returns the decoded mnemonics and slots, the committed register, state and
    memory writes, `next_pc` (`pc` plus the decoded packet's byte length unless a
    syllable transferred control), the trap, and the conflicts. None when the
    container does not decode.

    `register_writes` is keyed by the flat register slot rather than by operand
    name, which is what `step` reports: two syllables both writing their `rd`
    are one key under one convention and two registers under the other, and only
    the second can answer whether they collided.

    Conflicts are detected at that same granularity, the register slot. Two
    syllables writing disjoint narrow *views* of one register -- an x86 `AL` and
    an `AH` -- therefore collide here, which is one write port either way and so
    is the conservative answer, but it is a slot-level answer and not a
    bit-level one.
    """
    decoded = axis_lift.decode_packet(words, packet, isa)
    if decoded is None:
        return None
    shape = axis_lift.packet(packet)
    if delayed is None and shape is not None and shape["hazards"] == "exposed":
        # Running an exposed machine without its delay queue is running an
        # interlocked one and calling it by the other name. `new_delay_queue`
        # makes the state this needs.
        raise ValueError("an exposed packet needs a `delayed` queue; see new_delay_queue()")

    register_writes, state_writes, memory_writes = {}, {}, []
    register_owner, state_owner, byte_owner = {}, {}, {}
    conflicts, mnemonics, slots = [], [], []
    trap, branch, branch_owner = None, None, None
    scheduled = []
    step = ILEN * len(decoded)

    def collide(what, where, owner, slot):
        conflicts.append({"kind": what, "location": where,
                          "slots": [owner, slot]})

    for syllable in decoded:
        slot = syllable["slot"]
        scratch = _PacketState(regs)
        scratch_state = _PacketState(state) if state is not None else None
        buffered = _PacketMemory(mem) if mem is not None else None
        outcome = _step_entry(syllable["word"], scratch, buffered, pc, None, isa,
                              scratch_state, entry=syllable["entry"])
        if outcome is None:
            return None
        mnemonics.append(outcome["mnemonic"])
        slots.append(slot)
        if outcome.get("trap") is not None and trap is None:
            trap = outcome["trap"]

        latency = syllable["entry"].get("latency", 1) if delayed is not None else 1
        for location, value in scratch.assigned.items():
            if latency > 1:
                # In flight: invisible until its packet comes round, and not a
                # conflict with anything issuing now, because it lands later.
                scheduled.append((latency - 2, location, value, "in-flight:" + slot))
                continue
            if location in register_owner:
                collide("register", location, register_owner[location], slot)
            register_owner[location] = slot
            register_writes[location] = value
        if scratch_state is not None:
            for location, value in scratch_state.assigned.items():
                if location in state_owner:
                    collide("state", location, state_owner[location], slot)
                state_owner[location] = slot
                state_writes[location] = value
        if buffered is not None:
            for addr, value, width in buffered.writes:
                for byte in range(addr, addr + max(width // 8, 1)):
                    if byte in byte_owner:
                        collide("memory", byte, byte_owner[byte], slot)
                    byte_owner[byte] = slot
                memory_writes.append((addr, value, width))
        if outcome.get("next_pc") is not None and outcome["next_pc"] != pc + ILEN:
            if branch is not None:
                collide("control", "pc", branch_owner, slot)
            branch, branch_owner = outcome["next_pc"], slot

    # Writes that have finished waiting land with this packet's, and collide
    # with them the same way: two results arriving at one register in one
    # boundary is a schedule the machine cannot honour, whichever packet issued
    # them.
    landing = []
    if delayed is not None and delayed:
        landing = delayed[0]
    for location, value, origin in landing:
        if location in register_owner:
            collide("register", location, register_owner[location], origin)
        register_owner[location] = origin
        register_writes[location] = value

    result = {
        "mnemonics": mnemonics,
        "slots": slots,
        "syllables": len(decoded),
        "bytes": step,
        "register_writes": register_writes,
        "state_writes": state_writes,
        "memory_writes": memory_writes,
        "next_pc": branch if branch is not None else pc + step,
        "trap": trap,
        "conflicts": conflicts,
    }
    result["in_flight"] = [(stage, location, value)
                           for stage, location, value, _ in scheduled]
    if conflicts or trap is not None:
        # Nothing commits, and nothing advances: a conflicting packet has no
        # defined result and a trapping one does not retire, so the queue is
        # left exactly as the packet found it.
        result["committed"] = False
        return result

    if delayed is not None:
        # One packet end has passed: what was due has landed above, everything
        # else moves one stage closer, and this packet's long writes go in.
        if delayed:
            del delayed[0:1]
            delayed.append([])
        for stage, location, value, origin in scheduled:
            if stage >= len(delayed):
                raise ValueError(
                    f"a latency-{stage + 2} write needs stage {stage} of a "
                    f"{len(delayed)}-stage delay queue")
            delayed[stage].append((location, value, origin))

    regs.update(register_writes)
    if state is not None:
        state.update(state_writes)
    if mem is not None:
        for addr, value, width in memory_writes:
            mem.write(addr, value, width)
    result["committed"] = True
    return result


def _step_entry(word, regs, mem=None, pc=0, mode=None, isa=None, state=None,
                entry=None):
    """Execute one instruction `word` against register map `regs` (index -> value).

    Register-kind operands read their source registers and write their
    destination register in `regs` (mutated in place); immediate operands use
    their decoded value directly. `mem`, when given, is a memory model with
    `read(addr, width_bits) -> int` and `write(addr, value, width_bits)`, used by
    load/store effects. `state` is a mutable name -> value map for scalar
    architectural state such as AArch64 NZCV. `pc` is the current program
    counter, in scope for effect expressions. With `mode` set, decode is
    mode-aware: a word illegal in that mode raises the trap path
    (`trap="illegal"`). `isa` narrows decode to one encoding space when a
    document contains source and target ISAs. Returns a dict with the mnemonic,
    result, register/state writes, `next_pc`, and `trap`, or None if undecodable.
    """
    if entry is None:
        if mode is not None:
            entry = decode_in_mode(word, mode, isa)
            if entry is None:
                # Illegal instruction in this mode -> the E4 trap path.
                return {"mnemonic": None, "result": None, "writes": {},
                        "next_pc": pc + ILEN, "trap": "illegal"}
        else:
            entry = axis_lift.decode(word, isa)
            if entry is None:
                return None
    # ⚠️ An instruction nothing here performs. A description may name a routine
    # the embedder supplies, or say `unsupplied` -- and either way this model
    # has no answer. Reporting that is not the same as reporting that the word
    # did not decode: the C executor called the routine and said
    # `unimplemented` while this fell through to `undecoded`, so the two
    # backends disagreed about why they stopped and the REFERENCE gave the
    # less true answer.
    #
    # A consumer that RUNS code supplies the routine. This one reasons about
    # code, so it declines -- which is the same distinction the hook was built
    # around.
    answer = entry.get("implementation")
    if answer:
        return {"mnemonic": entry["mnemonic"], "result": None, "writes": {},
                "next_pc": pc + ILEN, "trap": "unimplemented"}
    values = {}
    for operand in entry["operands"]:
        fields = operand["fields"]
        values[operand["name"]] = axis_lift._extract(word, fields) if fields else operand.get("fixed")
    for operand in entry["operands"]:
        source = operand.get("derived_from")
        if source:
            values[operand["name"]] = values[source] + operand["derived_add"]

    effects = entry.get("effects")
    if effects is not None:
        # Effectful: bind operand values, `pc`, and a memory reader, then apply
        # each (optionally guarded) effect against registers, memory, and pc.
        state = state if state is not None else {}
        env = {"pc": pc, **state}
        for operand in entry["operands"]:
            decoded = values[operand["name"]]
            if decoded is None:
                continue
            # A selector is encoded and read by nothing: it carries the register
            # *number* an instruction's lanes are elements of. Binding it as a
            # value would put that number where a value belongs.
            if operand["role"] == "enc":
                continue
            kind = operand["kind"]
            env[operand["name"]] = (
                _read_operand(regs, operand, decoded)
                if axis_lift.is_register_operand(kind)
                else decoded
            )
            env["__input_" + operand["name"]] = env[operand["name"]]
        if mem is not None:
            env["__mem__"] = mem.read
        # A behavior may read a register the operands do not name -- a kernel
        # that reads the shared file itself. It reaches the file the same way a
        # load reaches memory, through the environment, and through the same
        # class rules an operand read uses: `regs` here is whatever this
        # execution was handed, which is how a syllable inside a packet reads
        # the state the packet started with rather than the live file.
        env["__regs__"] = lambda kind, index: _read_reg(regs, index, kind)
        result = None
        written = {}
        state_written = {}
        # The counter is a value of the ISA word, so it wraps there: on a
        # 32-bit machine the word after the last one is address zero, not
        # 2**32. Both the fall-through and a `setpc` are taken at this width --
        # a target that does arithmetic masks its own result, one that is a
        # bare register does not, and neither is the counter's rule.
        pc_mask = (1 << entry.get("state_width", 32)) - 1
        next_pc = (pc + ILEN) & pc_mask
        trap = None
        for eff in effects:
            if "guard" in eff and not golden_model._eval_axis_expr(
                eff["guard"], env, eff["guard_width"],
                eff.get("guard_load_address_width")
            ):
                continue
            if eff["kind"] == "trap":
                # A trap aborts the remaining effects with the given cause.
                trap = eff["cause"]
                break
            if eff["kind"] == "barrier":
                # The portable executor is single-threaded. Preserve the
                # typed event in lift metadata while execution is a no-op.
                golden_model._eval_axis_expr(
                    eff["value"], env, eff["eval_width"]
                )
                continue
            if eff["kind"] == "set":
                value = golden_model._eval_axis_expr(
                    eff["value"], env, eff["eval_width"],
                    eff.get("load_address_width")
                )
                dest = values[eff["dest"]]
                operand = next(op for op in entry["operands"] if op["name"] == eff["dest"])
                if dest is not None and _write_operand(regs, operand, dest, value):
                    written[eff["dest"]] = dest
                # Later effects observe the semantic result even when the
                # architectural destination is a discard register (XZR/WZR).
                env[eff["dest"]] = value & ((1 << eff["width"]) - 1)
                result = value
            elif eff["kind"] == "setreg":
                # ⚠️ `load_address_width` here and in `setstate` as in every
                # other branch: a state loaded from memory is eight bits wide and
                # its address is not. Without it LDTILECFG read its palette from
                # `rs1 & 0xff`, and the golden model made the same mistake, so
                # the two agreed; the C simulator, which gets it right, did not.
                value = golden_model._eval_axis_expr(
                    eff["value"], env, eff["eval_width"],
                    eff.get("load_address_width")
                )
                value &= (1 << eff["width"]) - 1
                dest = eff["index"]
                if _write_reg(regs, dest, eff["reg_kind"], value):
                    written[f'{eff["reg_kind"]}:{dest}'] = dest
                result = value
            elif eff["kind"] == "setstate":
                value = golden_model._eval_axis_expr(
                    eff["value"], env, eff["eval_width"],
                    eff.get("load_address_width")
                )
                value &= (1 << eff["width"]) - 1
                state[eff["state"]] = value
                env[eff["state"]] = value
                state_written[eff["state"]] = value
            elif eff["kind"] == "store":
                addr = golden_model._eval_axis_expr(
                    eff["addr"], env, eff["addr_width"]
                )
                # A stored value may itself be a LOAD -- a block copy is memory
                # to memory in one effect -- and that load's address is as wide
                # as the machine, not as wide as the element. Without
                # `load_address_width` the address was evaluated at the element
                # width, so `memcpy16` read byte 313 as byte 57: 313 & 0xff. The
                # `set` branch above has always passed it; this one did not, and
                # nothing noticed because the LLVM backend refused these
                # instructions rather than disagreeing with them.
                value = golden_model._eval_axis_expr(
                    eff["value"], env, eff["eval_width"],
                    eff.get("load_address_width")
                )
                if mem is not None:
                    mem.write(addr, value, eff["width"])
            elif eff["kind"] == "send":
                # ⚠️ The port is evaluated FIRST, and the value second, in the
                # order the description writes them -- the same order the C and
                # Rust executors use. A description whose port expression reads
                # a register its own value expression writes would otherwise
                # get two answers from two backends.
                port = golden_model._eval_axis_expr(
                    eff["port"], env, eff.get("port_width") or eff["eval_width"]
                )
                value = golden_model._eval_axis_expr(
                    eff["value"], env, eff["eval_width"],
                    eff.get("load_address_width")
                )
                if mem is not None and hasattr(mem, "send"):
                    mem.send(port, value & ((1 << eff["width"]) - 1), eff["width"])
            elif eff["kind"] == "setpc":
                next_pc = golden_model._eval_axis_expr(
                    eff["value"], env, eff["eval_width"]
                ) & pc_mask
        return {
            "mnemonic": entry["mnemonic"],
            "result": result,
            "writes": written,
            "state_writes": state_written,
            "next_pc": next_pc,
            "trap": trap,
        }

    if entry["semantics"] is None:
        return None
    inputs = []
    for operand in entry["operands"]:
        if operand["role"] in ("out", "enc"):
            continue
        decoded = values[operand["name"]]
        kind = operand["kind"]
        inputs.append(
            _read_operand(regs, operand, decoded)
            if axis_lift.is_register_operand(kind)
            else decoded
        )
    result = golden_model.evaluate(entry["mnemonic"], *inputs)
    written = {}
    for operand in entry["operands"]:
        if operand["role"] in ("out", "inout") and axis_lift.is_register_operand(
            operand["kind"]
        ):
            index = values[operand["name"]]
            if _write_operand(regs, operand, index, result):
                written[operand["name"]] = _operand_register(operand, index)
    return {
        "mnemonic": entry["mnemonic"],
        "inputs": inputs,
        "result": result,
        "writes": written,
        "next_pc": pc + ILEN,
    }


def run(words, regs=None, mem=None, pc=0, mode=None, isa=None, state=None):
    """Execute a sequence of instruction words, threading pc (fall-through)."""
    regs = dict(regs or {})
    for word in words:
        out = step(word, regs, mem, pc, mode, isa, state)
        pc = out["next_pc"] if out else pc + ILEN
    return regs
"#;

/// Emit a header-only C functional single-step interpreter (`axis.exec-c.v1`):
/// the compiled sibling of `axis_exec.py`, composing the C lifter (`axis_lift.h`)
/// with the proven C semantics interpreter (`axis_semantics.h`). `axis_exec_step`
/// decodes a word, reads register-kind source operands, and either dispatches to
/// the pure `axis_eval_*` function or runs the instruction's effect list — set,
/// store, `setpc` (control flow), and `trap` effects, each optionally guarded —
/// against `regs`, the `axis_mem` callback, and `pc`, filling `next_pc` and the
/// trap cause. The full E1-E4 effect surface, matching the Python interpreter.
pub fn emit_exec_c(document: &Document) -> String {
    let guard = format!(
        "AXIS_{}_EXEC_H",
        tablegen_ident(&document.extension.name).to_ascii_uppercase()
    );
    // The C semantics function exists only when emit_semantics_c actually
    // emitted a body (widths <= 32, expressible); check membership so no
    // dispatch arm references a missing `axis_eval_*`.
    let c_header = crate::emit::emit_semantics_c(document);
    // Per-instruction effect functions (E1-E4: set/store/setpc/trap, guarded).
    let state_names = crate::effects::isa_scalar_state_names(&document.isas);
    let effect_fns: Vec<(String, String)> = document
        .instructions
        .iter()
        .filter_map(|instruction| {
            emit_c_effect_fn(instruction, &state_names)
                .map(|def| (tablegen_ident(&instruction.mnemonic), def))
        })
        .collect();
    let wide_effect_fns: Vec<(String, String)> = document
        .instructions
        .iter()
        .filter_map(|instruction| {
            emit_c_effect64_fn(instruction).map(|def| (tablegen_ident(&instruction.mnemonic), def))
        })
        .collect();

    let mut out = String::new();
    out.push_str(
        "/* Generated by AXIS. Functional single-step interpreter (decode -> execute). */\n",
    );
    out.push_str("/* schema: axis.exec-c.v1 */\n");
    out.push_str(&format!("#ifndef {guard}\n#define {guard}\n\n"));
    out.push_str("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n");
    out.push_str("#include \"axis_lift.h\"\n#include \"axis_semantics.h\"\n\n");
    emit_c_register_classes(&mut out);
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");
    out.push_str("enum { AXIS_EXEC_ILEN = 4 };\n\n");
    out.push_str(&format!(
        "/* Slots this document's register files need, and the most state entries a\n   scalable word's lanes read from a snapshot (see axis_exec_step64). */\n#define AXIS_EXEC_REG_SLOTS {}\n#define AXIS_EXEC_STATE_SNAPSHOT 64\n\n",
        crate::ast::register_file_slots(document)
    ));

    out.push_str("/* Memory interface for load/store effects. `read`/`write` operate on\n");
    out.push_str(" * `width`-bit little-endian quantities; `ctx` is the caller's memory. */\n");
    out.push_str("typedef struct axis_mem {\n");
    out.push_str("  uint32_t (*read)(void *ctx, uint32_t addr, uint32_t width);\n");
    out.push_str("  void (*write)(void *ctx, uint32_t addr, uint32_t value, uint32_t width);\n");
    out.push_str("  void *ctx;\n");
    out.push_str("} axis_mem;\n\n");

    // Single-step result. `next_pc` is the fall-through `pc + ILEN` unless a
    // `setpc` fires; `trapped`/`trap_cause` report a trap effect.
    out.push_str("typedef struct axis_exec_result {\n");
    out.push_str("  const char *mnemonic;\n");
    out.push_str("  uint32_t result;\n");
    out.push_str("  int wrote;\n");
    out.push_str("  uint32_t dest;\n");
    out.push_str("  const char *state_name;\n");
    out.push_str("  uint32_t state_value;\n");
    out.push_str("  uint32_t next_pc;\n");
    out.push_str("  int trapped;\n");
    out.push_str("  const char *trap_cause;\n");
    out.push_str("  int ok;\n");
    out.push_str("} axis_exec_result;\n\n");

    for (_, def) in &effect_fns {
        out.push_str(def);
    }

    out.push_str("/* Evaluate a decoded instruction's pure semantics on gathered inputs. */\n");
    out.push_str(
        "static inline int axis_exec_eval(axis_insn_id id, const uint32_t *in, int n, uint32_t *out) {\n",
    );
    out.push_str("  switch (id) {\n");
    for instruction in &document.instructions {
        let fn_ident = python_ident(&instruction.mnemonic);
        // This is the compact 32-bit ABI, so it dispatches only to the
        // `uint32_t` semantics functions. Testing for the name alone matched
        // the 64-bit ones once those started being emitted, and generated arms
        // that passed `uint32_t` to a `uint64_t` function; the width rule is
        // the same one the semantics emitter used to choose the signature.
        if pure_eval_width(instruction) > 32 {
            continue;
        }
        if !c_header.contains(&format!("axis_eval_{fn_ident}(")) {
            continue;
        }
        let argc = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .count();
        let args: Vec<String> = (0..argc).map(|i| format!("in[{i}]")).collect();
        out.push_str(&format!(
            "    case AXIS_INSN_{}:\n",
            tablegen_ident(&instruction.mnemonic)
        ));
        out.push_str(&format!(
            "      if (n == {argc}) {{ *out = axis_eval_{fn_ident}({}); return 1; }}\n",
            args.join(", ")
        ));
        out.push_str("      break;\n");
    }
    out.push_str("    default: break;\n");
    out.push_str("  }\n  (void)in; (void)n; (void)out;\n  return 0;\n}\n\n");

    // Effect dispatch: run an instruction's effect list; 1 if `id` is effectful.
    out.push_str(
        "/* Run an instruction's effect list into `r`; returns 1 if `id` is effectful. */\n",
    );
    out.push_str(
        "static inline int axis_exec_apply(axis_insn_id id, const axis_lifted *lifted, uint32_t *regs, size_t reg_count, const axis_mem *mem, uint32_t pc, axis_exec_result *r) {\n",
    );
    out.push_str("  switch (id) {\n");
    for (ident, _) in &effect_fns {
        out.push_str(&format!(
            "    case AXIS_INSN_{ident}: axis_exec_eff_{ident}(lifted, regs, reg_count, mem, pc, r); return 1;\n"
        ));
    }
    out.push_str("    default: break;\n");
    out.push_str(
        "  }\n  (void)lifted; (void)regs; (void)reg_count; (void)mem; (void)pc; (void)r;\n  return 0;\n}\n\n",
    );

    out.push_str("/* Decode and execute `word` against `regs` (index -> value, `reg_count`\n");
    out.push_str(" * entries), `mem` (load/store effects; may be NULL for pure code), and the\n");
    out.push_str(" * program counter `pc`. Mutates `regs`/memory in place; `next_pc` is the\n");
    out.push_str(" * fall-through unless a setpc fires; ok=0 if the word does not execute. */\n");
    out.push_str(
        "static inline axis_exec_result axis_exec_step(uint32_t word, uint32_t *regs, size_t reg_count, const axis_mem *mem, uint32_t pc) {\n",
    );
    out.push_str(
        "  axis_exec_result r = { NULL, 0u, 0, 0u, NULL, 0u, pc + (uint32_t)AXIS_EXEC_ILEN, 0, NULL, 0 };\n",
    );
    out.push_str("  axis_lifted lifted;\n");
    out.push_str("  if (!axis_lift(word, &lifted)) { return r; }\n");
    out.push_str("  const axis_lift_entry *entry = lifted.entry;\n");
    out.push_str("  r.mnemonic = entry->mnemonic;\n");
    out.push_str(
        "  if (axis_exec_apply(entry->id, &lifted, regs, reg_count, mem, pc, &r)) { r.ok = 1; return r; }\n",
    );
    // Pure path: gather inputs, evaluate, write the destination register.
    out.push_str("  uint32_t inputs[AXIS_LIFT_MAX_OPERANDS];\n");
    out.push_str("  int n = 0;\n");
    out.push_str("  for (int i = 0; i < entry->operand_count; ++i) {\n");
    out.push_str("    const axis_lift_operand *op = &entry->operands[i];\n");
    out.push_str("    if ((op->role_code == AXIS_ROLE_OUT)) { continue; }\n");
    out.push_str("    uint32_t v = lifted.operands[i];\n");
    out.push_str("    const axis_reg_class *cls = axis_op_class(op);\n");
    out.push_str("    if (cls) {\n");
    out.push_str("      uint32_t _slot = v * cls->limbs + cls->offset;\n");
    out.push_str("      v = (cls->zero_index >= 0 && v == (uint32_t)cls->zero_index) ? 0u : (_slot < reg_count ? regs[_slot] : 0u);\n");
    out.push_str("      if (cls->view_width) { v = (uint32_t)axis_mask64(v, cls->view_width); }\n");
    out.push_str("    }\n");
    out.push_str("    inputs[n++] = v;\n");
    out.push_str("  }\n");
    out.push_str("  uint32_t result = 0u;\n");
    out.push_str("  if (!entry->liftable) { return r; }\n");
    out.push_str("  if (!axis_exec_eval(entry->id, inputs, n, &result)) { return r; }\n");
    out.push_str("  r.result = result;\n  r.ok = 1;\n");
    out.push_str("  for (int i = 0; i < entry->operand_count; ++i) {\n");
    out.push_str("    const axis_lift_operand *op = &entry->operands[i];\n");
    out.push_str("    const axis_reg_class *wcls = axis_op_class(op);\n");
    out.push_str("    if ((op->role_code != AXIS_ROLE_IN) && wcls) {\n");
    out.push_str("      uint32_t idx = lifted.operands[i];\n");
    out.push_str("      if (wcls->zero_index >= 0 && idx == (uint32_t)wcls->zero_index) { continue; }\n");
    out.push_str("      uint32_t _wslot = idx * wcls->limbs + wcls->offset;\n");
    out.push_str("      if (_wslot < reg_count) { regs[_wslot] = result; }\n");
    out.push_str("      r.wrote = 1;\n      r.dest = idx;\n");
    out.push_str("    }\n");
    out.push_str("  }\n");
    out.push_str("  return r;\n}\n\n");

    emit_exec_c64(document, &wide_effect_fns, &mut out);

    out.push_str("#ifdef __cplusplus\n}\n#endif\n\n");
    out.push_str(&format!("#endif /* {guard} */\n"));
    out
}

/// Append the wide executor ABI. The legacy `axis_exec_step` remains available
/// for existing RV32 consumers; `axis_exec_step64` adds 64-bit GPR/PC values,
/// ISA-qualified decode, and a generic named scalar-state map.
/// The width helpers and the register-class table, shared by both C executor
/// ABIs. Emitted once, before the compact executor that also reads them — the
/// compact path used to test `strcmp(kind, "reg")` and so treated every class
/// with a name of its own as an immediate.
fn emit_c_register_classes(out: &mut String) {
    out.push_str("static inline uint64_t axis_mask64(uint64_t value, uint32_t width) {\n  return width >= 64u ? value : value & ((UINT64_C(1) << width) - UINT64_C(1));\n}\n");
    // The signed view of a width-limited value. Always emitted, beside the mask
    // it mirrors: a signed comparison needs it whatever the ISA, and the A64
    // helper set that used to provide one is only emitted for A64 documents.
    out.push_str("static inline int64_t axis_signed64(uint64_t value, uint32_t width) {\n  if (width >= 64u) { return (int64_t)value; }\n  uint64_t masked = axis_mask64(value, width), sign = UINT64_C(1) << (width - 1u);\n  return (int64_t)((masked ^ sign) - sign);\n}\n");
    // The widest register file in this document, in limbs. A wide value is
    // carried as this many words, so the bound comes from the classes rather
    // than from a constant someone has to remember to raise.
    let max_limbs = crate::ast::REGISTER_CLASSES
        .iter()
        .map(|class| class.limbs.max(1))
        .max()
        .unwrap_or(1);
    out.push_str(&format!(
        "enum {{ AXIS_EXEC_MAX_LIMBS = {max_limbs} }};\n"
    ));
    out.push_str("typedef struct { const char *name; int zero_index; int alias_index; const char *alias_state; uint32_t view_width; uint32_t view_offset; int preserves; uint32_t limbs; uint32_t offset; uint32_t index_offset; } axis_reg_class;\n");
    out.push_str("static const axis_reg_class axis_reg_classes[] = {\n");
    for class in crate::ast::REGISTER_CLASSES {
        let zero = class
            .zero_index
            .map(|index| index as i64)
            .unwrap_or(-1);
        let (alias_index, alias_state) = class
            .alias
            .map(|(index, name)| (index as i64, format!("\"{name}\"")))
            .unwrap_or((-1, "NULL".to_string()));
        let view = class.view_width.unwrap_or(0);
        let preserves =
            i32::from(matches!(class.write_policy, crate::ast::WritePolicy::Preserve));
        out.push_str(&format!(
            "  {{ \"{}\", {zero}, {alias_index}, {alias_state}, {view}u, {}u, {preserves}, {}u, {}u, {}u }},\n",
            class.name,
            class.view_offset,
            class.limbs.max(1),
            class.offset,
            class.index_offset
        ));
    }
    out.push_str("};\n\n");
    out.push_str("static inline const axis_reg_class *axis_reg_class_of(const char *kind) {\n  /* Asked on every operand of every step. A kind is a literal the linker\n     usually merges with the class's own name, so pointers are compared first;\n     a first character that differs settles most of the rest without a call. */\n  const size_t n = sizeof(axis_reg_classes) / sizeof(axis_reg_classes[0]);\n  for (size_t i = 0; i < n; ++i) {\n    if (axis_reg_classes[i].name == kind) { return &axis_reg_classes[i]; }\n  }\n  for (size_t i = 0; i < n; ++i) {\n    const char *name = axis_reg_classes[i].name;\n    if (name[0] == kind[0] && strcmp(name, kind) == 0) { return &axis_reg_classes[i]; }\n  }\n  return NULL;\n}\n\n");
    out.push_str("/* An operand's class, fixed when the table was generated. */\nstatic inline const axis_reg_class *axis_op_class(const axis_lift_operand *op) {\n  return op->reg_class >= 0 ? &axis_reg_classes[op->reg_class] : NULL;\n}\n\n");
}

fn emit_exec_c64(document: &Document, effect_fns: &[(String, String)], out: &mut String) {
    out.push_str("typedef struct axis_state64_entry {\n  const char *name;\n  uint64_t value;\n  uint32_t width;\n} axis_state64_entry;\n");
    out.push_str("typedef struct axis_state64 {\n  axis_state64_entry *entries;\n  size_t count;\n} axis_state64;\n\n");
    out.push_str("static inline uint64_t axis_sext64(uint64_t value, uint32_t from, uint32_t width) {\n  value = axis_mask64(value, from);\n  if (from && from < 64u && (value & (UINT64_C(1) << (from - 1u)))) { value |= ~((UINT64_C(1) << from) - UINT64_C(1)); }\n  return axis_mask64(value, width);\n}\n");
    out.push_str("static inline uint64_t axis_udiv64(uint64_t lhs, uint64_t rhs, uint32_t width) {\n  lhs = axis_mask64(lhs, width); rhs = axis_mask64(rhs, width);\n  return rhs == 0u ? 0u : axis_mask64(lhs / rhs, width);\n}\n");
    // High-half multiply needs an intermediate twice the evaluation width, so
    // it cannot be written in uint64_t alone. `unsigned __int128` is not
    // standard C but is present in every compiler this project targets, and the
    // AArch64 helpers have relied on it since smulh and umulh were described.
    out.push_str("static inline uint64_t axis_mulh64(uint64_t a, uint64_t b, uint32_t width, int signed_a, int signed_b) {\n  __int128 wa = signed_a ? (__int128)axis_signed64(a, width) : (__int128)(unsigned __int128)axis_mask64(a, width);\n  __int128 wb = signed_b ? (__int128)axis_signed64(b, width) : (__int128)(unsigned __int128)axis_mask64(b, width);\n  unsigned __int128 product = (unsigned __int128)(wa * wb);\n  return axis_mask64((uint64_t)(product >> width), width);\n}\n");
    // Min and max as calls, not inline ternaries: a ternary names each operand
    // twice, so a fold of them -- SMAXV over sixteen bytes -- doubled at every
    // step and rendered to megabytes a lane.
    out.push_str("static inline uint64_t axis_minmax64(uint64_t a, uint64_t b, uint32_t width, int is_signed, int is_max) {\n  a = axis_mask64(a, width); b = axis_mask64(b, width);\n  int less = is_signed ? axis_signed64(a, width) < axis_signed64(b, width) : a < b;\n  return (less != is_max) ? a : b;\n}\n");
    out.push_str("static inline uint64_t axis_sdiv64(uint64_t lhs, uint64_t rhs, uint32_t width) {\n  lhs = axis_mask64(lhs, width); rhs = axis_mask64(rhs, width); if (rhs == 0u) { return 0u; }\n  int64_t a = axis_signed64(lhs, width), b = axis_signed64(rhs, width); if (a == INT64_MIN && b == -1) { return lhs; }\n  return (uint64_t)(a / b);\n}\n");
    // A shift amount is read at the node's width, not the word's: `& 63u` is
    // the register width, and at a node width of 8 an amount of 70 shifted by
    // six here and by everything in the semantics header. The narrowing is the
    // same one SMT-LIB performs structurally.
    out.push_str("static inline uint64_t axis_shift_amount64(uint64_t amount, uint32_t width) {\n  return width >= 64u ? amount : (amount & ((UINT64_C(1) << width) - UINT64_C(1)));\n}\n");
    out.push_str("static inline uint64_t axis_shl64(uint64_t value, uint64_t amount, uint32_t width) {\n  amount = axis_shift_amount64(amount, width);\n  return amount >= (uint64_t)width ? UINT64_C(0) : axis_mask64(value << amount, width);\n}\n");
    out.push_str("static inline uint64_t axis_lshr64(uint64_t value, uint64_t amount, uint32_t width) {\n  amount = axis_shift_amount64(amount, width);\n  return amount >= (uint64_t)width ? UINT64_C(0) : (axis_mask64(value, width) >> amount);\n}\n");
    /* Sign-extended through `axis_signed64`, which takes the width, rather than
       through a cast that only knows 32 and 64. A value masked to 16 bits is
       never negative as an `int64_t`, so every arithmetic shift of a narrow
       lane was an unsigned one -- and a lane is exactly what a SIMD corpus is
       made of. */
    out.push_str("static inline uint64_t axis_ashr64(uint64_t value, uint64_t amount, uint32_t width) {\n  int64_t wide = axis_signed64(value, width); amount = axis_shift_amount64(amount, width);\n  if (amount >= (uint64_t)width) {\n    return axis_mask64(wide < 0 ? ~UINT64_C(0) : UINT64_C(0), width);\n  }\n  return axis_mask64((uint64_t)(wide >> amount), width);\n}\n");
    out.push_str("static inline uint64_t axis_clz64(uint64_t value, uint32_t width) {\n  value = axis_mask64(value, width); uint64_t count = 0;\n  for (uint32_t bit = width; bit > 0u && ((value >> (bit - 1u)) & 1u) == 0u; --bit) { ++count; }\n  return count;\n}\n");
    /* The bit-counting and rotate operators the compact runtime has had since
       Zbb was described. This one had `clz` and stopped there, so an
       instruction that rotates or counts was declined by the wide executor and
       run only by the compact one -- the two paths lowering one language
       through different vocabularies. */
    out.push_str("static inline uint64_t axis_ctz64(uint64_t value, uint32_t width) {\n  value = axis_mask64(value, width); if (value == 0u) { return width; }\n  uint64_t count = 0; while ((value & UINT64_C(1)) == 0u) { value >>= 1; ++count; }\n  return count;\n}\n");
    out.push_str("static inline uint64_t axis_cpop64(uint64_t value, uint32_t width) {\n  value = axis_mask64(value, width); uint64_t count = 0;\n  while (value != 0u) { count += value & UINT64_C(1); value >>= 1; }\n  return count;\n}\n");
    /* A rotation by the whole width is the identity, and it is also the shift
       C leaves undefined -- so it is the case to name rather than to compute. */
    out.push_str("static inline uint64_t axis_rotl64(uint64_t value, uint64_t amount, uint32_t width) {\n  if (width == 0u) { return value; }\n  value = axis_mask64(value, width);\n  uint32_t shift = (uint32_t)(amount % (uint64_t)width);\n  if (shift == 0u) { return value; }\n  return axis_mask64((value << shift) | (value >> (width - shift)), width);\n}\n");
    out.push_str("static inline uint64_t axis_rotr64(uint64_t value, uint64_t amount, uint32_t width) {\n  if (width == 0u) { return value; }\n  uint32_t shift = (uint32_t)(amount % (uint64_t)width);\n  return axis_rotl64(value, (uint64_t)((width - shift) % width), width);\n}\n");
    out.push_str("static inline uint64_t axis_state64_read(const axis_state64 *state, const char *name) {\n  if (!state) { return 0; }\n  for (size_t i = 0; i < state->count; ++i) { if (strcmp(state->entries[i].name, name) == 0) { return axis_mask64(state->entries[i].value, state->entries[i].width); } }\n  return 0;\n}\n");
    out.push_str("static inline int axis_state64_write(axis_state64 *state, const char *name, uint64_t value, uint32_t width) {\n  if (!state) { return 0; }\n  for (size_t i = 0; i < state->count; ++i) { if (strcmp(state->entries[i].name, name) == 0) { state->entries[i].value = axis_mask64(value, width); state->entries[i].width = width; return 1; } }\n  return 0;\n}\n");
    out.push_str("static inline uint64_t axis_a64_add_nzcv(uint64_t a, uint64_t b, uint32_t width) {\n  uint64_t mask = axis_mask64(UINT64_MAX, width), sign = UINT64_C(1) << (width - 1u);\n  a &= mask; b &= mask; uint64_t r = (a + b) & mask;\n  int n = (r & sign) != 0, z = r == 0, c = width == 64u ? r < a : a + b > mask;\n  int v = ((~(a ^ b) & (a ^ r) & sign) != 0);\n  return (uint64_t)((n << 3) | (z << 2) | (c << 1) | v);\n}\n");
    out.push_str("static inline uint64_t axis_a64_sub_nzcv(uint64_t a, uint64_t b, uint32_t width) {\n  uint64_t mask = axis_mask64(UINT64_MAX, width), sign = UINT64_C(1) << (width - 1u);\n  a &= mask; b &= mask; uint64_t r = (a - b) & mask;\n  int n = (r & sign) != 0, z = r == 0, c = a >= b;\n  int v = (((a ^ b) & (a ^ r) & sign) != 0);\n  return (uint64_t)((n << 3) | (z << 2) | (c << 1) | v);\n}\n");
    out.push_str("static inline uint64_t axis_a64_adc_nzcv(uint64_t a, uint64_t b, uint64_t carry_in, uint32_t width) {\n  uint64_t mask = axis_mask64(UINT64_MAX, width), sign = UINT64_C(1) << (width - 1u); carry_in &= 1u;\n  a &= mask; b &= mask; uint64_t sum = a + b, r = (sum + carry_in) & mask;\n  int c = width == 64u ? (sum < a || r < sum) : a + b + carry_in > mask;\n  int n = (r & sign) != 0, z = r == 0, v = ((~(a ^ b) & (a ^ r) & sign) != 0);\n  return (uint64_t)((n << 3) | (z << 2) | (c << 1) | v);\n}\n");
    out.push_str("static inline uint64_t axis_a64_sbc_nzcv(uint64_t a, uint64_t b, uint64_t carry_in, uint32_t width) {\n  uint64_t mask = axis_mask64(UINT64_MAX, width), sign = UINT64_C(1) << (width - 1u), borrow = 1u - (carry_in & 1u);\n  a &= mask; b &= mask; uint64_t difference = a - b, r = (difference - borrow) & mask;\n  int c = !(a < b || difference < borrow);\n  int n = (r & sign) != 0, z = r == 0, v = (((a ^ b) & (a ^ r) & sign) != 0);\n  return (uint64_t)((n << 3) | (z << 2) | (c << 1) | v);\n}\n");
    out.push_str("static inline uint64_t axis_a64_umulh(uint64_t a, uint64_t b) { return (uint64_t)(((__uint128_t)a * (__uint128_t)b) >> 64); }\n");
    out.push_str("static inline uint64_t axis_a64_smulh(uint64_t a, uint64_t b) { return (uint64_t)(((__int128_t)(int64_t)a * (__int128_t)(int64_t)b) >> 64); }\n");
    out.push_str("static inline uint64_t axis_a64_logic_nzcv(uint64_t value, uint32_t width) {\n  value = axis_mask64(value, width);\n  return (uint64_t)(((value >> (width - 1u)) & 1u) << 3) | (uint64_t)((value == 0u) << 2);\n}\n");
    out.push_str("static inline uint64_t axis_a64_cond_holds(uint64_t nzcv, uint64_t cond) {\n  int n = (nzcv & 8u) != 0, z = (nzcv & 4u) != 0, c = (nzcv & 2u) != 0, v = (nzcv & 1u) != 0;\n  switch (cond & 15u) { case 0: return z; case 1: return !z; case 2: return c; case 3: return !c; case 4: return n; case 5: return !n; case 6: return v; case 7: return !v; case 8: return c && !z; case 9: return !c || z; case 10: return n == v; case 11: return n != v; case 12: return !z && n == v; case 13: return z || n != v; default: return 1; }\n}\n");
    out.push_str("static inline uint64_t axis_a64_shift_reg(uint64_t value, uint64_t shift, uint64_t amount, uint32_t width) {\n  value = axis_mask64(value, width); amount &= (uint64_t)(width - 1u);\n  switch (shift & 3u) {\n    case 0: return axis_mask64(value << amount, width);\n    case 1: return value >> amount;\n    case 2: return axis_mask64((uint64_t)(axis_signed64(value, width) >> amount), width);\n    default: return amount == 0u ? value : axis_mask64((value >> amount) | (value << (width - amount)), width);\n  }\n}\n");
    out.push_str("static inline uint64_t axis_a64_extend_reg(uint64_t value, uint64_t option, uint64_t amount, uint32_t width) {\n  uint32_t source_width = 8u << (option & 3u); uint64_t extended = axis_mask64(value, source_width);\n  if ((option & 4u) && source_width < 64u && ((extended >> (source_width - 1u)) & 1u)) { extended |= ~axis_mask64(UINT64_MAX, source_width); }\n  return axis_mask64(extended << (amount & 7u), width);\n}\n");
    out.push_str("static inline uint64_t axis_a64_replicate(uint64_t element, uint32_t esize, uint32_t width) {\n  uint64_t result = 0; element = axis_mask64(element, esize);\n  for (uint32_t pos = 0; pos < width; pos += esize) { result |= element << pos; }\n  return axis_mask64(result, width);\n}\n");
    out.push_str("static inline void axis_a64_decode_masks(uint64_t n, uint64_t immr, uint64_t imms, uint32_t width, uint64_t *wmask, uint64_t *tmask, uint32_t *s_out) {\n  uint32_t encoded = (uint32_t)(((n & 1u) << 6) | ((~imms) & 0x3fu)); int len = -1;\n  for (int bit = 6; bit >= 0; --bit) { if (encoded & (1u << bit)) { len = bit; break; } }\n  if (len < 1) { *wmask = 0; *tmask = 0; *s_out = 0; return; }\n  uint32_t levels = (1u << len) - 1u, s = (uint32_t)imms & levels, r = (uint32_t)immr & levels;\n  uint32_t diff = (s - r) & levels, esize = 1u << len;\n  uint64_t welem = axis_mask64(UINT64_MAX, s + 1u), telem = axis_mask64(UINT64_MAX, diff + 1u);\n  uint64_t rotated = axis_a64_shift_reg(welem, 3u, r, esize);\n  *wmask = axis_a64_replicate(rotated, esize, width); *tmask = axis_a64_replicate(telem, esize, width); *s_out = s;\n}\n");
    out.push_str("static inline uint64_t axis_a64_wmask(uint64_t n, uint64_t immr, uint64_t imms, uint32_t width) {\n  uint64_t wmask, tmask; uint32_t s; axis_a64_decode_masks(n, immr, imms, width, &wmask, &tmask, &s); return wmask;\n}\n");
    out.push_str("static inline uint64_t axis_a64_ubfm(uint64_t src, uint64_t immr, uint64_t imms, uint32_t width) {\n  uint64_t wmask, tmask; uint32_t s; axis_a64_decode_masks(width == 64u, immr, imms, width, &wmask, &tmask, &s);\n  return axis_a64_shift_reg(src, 3u, immr, width) & wmask & tmask;\n}\n");
    out.push_str("static inline uint64_t axis_a64_sbfm(uint64_t src, uint64_t immr, uint64_t imms, uint32_t width) {\n  uint64_t wmask, tmask; uint32_t s; axis_a64_decode_masks(width == 64u, immr, imms, width, &wmask, &tmask, &s);\n  if (!wmask) { return 0; }\n  uint64_t bot = axis_a64_shift_reg(src, 3u, immr, width) & wmask, top = (axis_mask64(src, width) >> s) & 1u ? axis_mask64(UINT64_MAX, width) : 0;\n  return axis_mask64((top & ~tmask) | (bot & tmask), width);\n}\n");
    out.push_str("static inline uint64_t axis_a64_bfm(uint64_t dst, uint64_t src, uint64_t immr, uint64_t imms, uint32_t width) {\n  uint64_t wmask, tmask; uint32_t s; axis_a64_decode_masks(width == 64u, immr, imms, width, &wmask, &tmask, &s);\n  if (!wmask) { return 0; }\n  uint64_t bot = (axis_mask64(dst, width) & ~wmask) | (axis_a64_shift_reg(src, 3u, immr, width) & wmask);\n  return axis_mask64((axis_mask64(dst, width) & ~tmask) | (bot & tmask), width);\n}\n");
    emit_exec_c64_functions(document, out);
    // One table, rendered from `ast::REGISTER_CLASSES`, rather than a chain of
    // strcmp against one architecture's class names. A new ISA is a row.
    out.push_str("/* Wide architectural-state ABI (AArch64 and other 64-bit ISAs). */\n");
    out.push_str("typedef struct axis_mem64 {\n  uint64_t (*read)(void *ctx, uint64_t addr, uint32_t width);\n  void (*write)(void *ctx, uint64_t addr, uint64_t value, uint32_t width);\n  void *ctx;\n  /* A value wider than the word, as limbs. Optional: NULL means the host has\n     no wide access and the executor issues `limbs` ordinary ones instead --\n     which is what the bus does. A host that models the wide access as one\n     event, a tracer for instance, supplies these so it sees one.\n     Appended, so the positional initialisers above stay correct. */\n  void (*read_limbs)(void *ctx, uint64_t addr, uint32_t width, uint64_t *out, uint32_t limbs);\n  void (*write_limbs)(void *ctx, uint64_t addr, uint32_t width, const uint64_t *in, uint32_t limbs);\n  /* A one-way message out of the machine, through the channel `port` names.\n\n     ⚠️ NOT a write to an address. There is nothing to read back, ordering\n     against memory is the description\'s to state with a barrier, and a host\n     that treated the two alike would give a message an address it does not\n     have. Left NULL by a host with no channels, and then a `send` is\n     evaluated and observed by nobody -- which is what a machine with nothing\n     attached to its port does.\n     Appended, so the positional initialisers above stay correct. */\n  void (*send)(void *ctx, uint64_t port, uint64_t value, uint32_t width);\n} axis_mem64;\n");
    out.push_str("static inline uint64_t axis_read_view64(const uint64_t *regs, size_t count, uint32_t index, const axis_reg_class *rules, const axis_state64 *state, uint32_t stride, uint32_t view_offset, uint32_t view_width, uint32_t slot_base) {\n  if (!rules) { return 0; }\n  if (rules->zero_index >= 0 && index == (uint32_t)rules->zero_index) { return 0; }\n  /* An operand may place its value inside the register the class names: an\n     element of a scalable register, whose position depends on VL and the\n     element width rather than on the architecture, so no compile-time class\n     can hold it. A zero view width means no override. */\n  uint32_t limbs = view_width ? (stride ? stride : 1u) : rules->limbs;\n  uint32_t base = view_width ? slot_base : rules->offset;\n  uint32_t view = view_width ? view_width : rules->view_width;\n  uint32_t bit = view_width ? view_offset : rules->view_offset;\n  uint32_t slot = base + (view_width ? index : rules->index_offset + index) * limbs;\n  if (rules->alias_index >= 0 && index == (uint32_t)rules->alias_index) {\n    uint64_t aliased = axis_state64_read(state, rules->alias_state);\n    /* The view applies to an alias too: AArch64 reads W-SP as the low 32 bits\n       of the same `sp` the 64-bit class reads whole. */\n    return view ? axis_mask64(aliased >> bit, view) : aliased;\n  }\n  if (!view) { return slot < count ? regs[slot] : 0; }\n  /* A view sits at a bit offset inside a register that may span limbs, and is\n     never wider than one -- so it touches at most two. */\n  uint32_t low_slot = slot + bit / 64u;\n  uint32_t shift = bit % 64u;\n  uint64_t low = low_slot < count ? (regs[low_slot] >> shift) : 0;\n  if (shift != 0u && shift + view > 64u) {\n    uint64_t high = (low_slot + 1u) < count ? regs[low_slot + 1u] : 0;\n    low |= high << (64u - shift);\n  }\n  return axis_mask64(low, view);\n}\n");
    out.push_str("static inline uint64_t axis_read_reg64(const uint64_t *regs, size_t count, uint32_t index, const char *kind, const axis_state64 *state) {\n  return axis_read_view64(regs, count, index, axis_reg_class_of(kind), state, 0u, 0u, 0u, 0u);\n}\n");
    out.push_str("static inline int axis_write_view64(uint64_t *regs, size_t count, uint32_t index, const axis_reg_class *rules, uint64_t value, axis_state64 *state, uint32_t stride, uint32_t view_offset, uint32_t view_width, uint32_t slot_base) {\n  if (!rules) { return 0; }\n  uint32_t limbs = view_width ? (stride ? stride : 1u) : rules->limbs;\n  uint32_t base = view_width ? slot_base : rules->offset;\n  uint32_t placed = view_width ? view_width : rules->view_width;\n  uint32_t bit = view_width ? view_offset : rules->view_offset;\n  /* A lane writes one element and leaves the rest of the register alone, which\n     is what a preserving narrow write already does -- so the policy comes from\n     the class and the placement from the operand. */\n  int preserves = view_width ? 1 : rules->preserves;\n  uint32_t view = placed ? placed : 64u;\n  value = axis_mask64(value, view);\n  if (rules->zero_index >= 0 && index == (uint32_t)rules->zero_index) { return 0; }\n  if (rules->alias_index >= 0 && index == (uint32_t)rules->alias_index) { return axis_state64_write(state, rules->alias_state, value, 64u); }\n  uint32_t slot = base + (view_width ? index : rules->index_offset + index) * limbs;\n  if (slot >= count) { return 0; }\n  /* ⚠️ The value spread across the register's limbs, not dropped into the\n     first one. A sixty-four bit value in a register that is two slots wide\n     leaves the high slot holding whatever it held, and the class says those\n     bits are the register's. The Python executor has always split here; this\n     wrote one slot, and the two agreed for two years because no description\n     put a narrow value in a multi-limb register until one stopped addressing\n     a single file at two strides. */\n  if (!placed) {\n    for (uint32_t k = 0; k < limbs; ++k) {\n      if (slot + k < count) { regs[slot + k] = k == 0u ? value : 0u; }\n    }\n    return 1;\n  }\n  uint32_t low_slot = slot + bit / 64u;\n  uint32_t shift = bit % 64u;\n  if (low_slot >= count) { return 0; }\n  /* A zeroing view clears the whole register, not the slot the view lands in:\n     the bits outside it are architecturally zero however many limbs away they\n     sit. Clearing first lets one insertion serve both policies. */\n  if (!preserves) {\n    for (uint32_t k = 0; k < limbs; ++k) { if (slot + k < count) { regs[slot + k] = 0; } }\n  }\n  uint64_t mask_low = axis_mask64(UINT64_C(0xFFFFFFFFFFFFFFFF), view) << shift;\n  regs[low_slot] = (regs[low_slot] & ~mask_low) | ((value << shift) & mask_low);\n  if (shift != 0u && shift + view > 64u) {\n    uint32_t high_slot = low_slot + 1u;\n    if (high_slot < count) {\n      uint32_t spill = shift + view - 64u;\n      uint64_t mask_high = axis_mask64(UINT64_C(0xFFFFFFFFFFFFFFFF), spill);\n      regs[high_slot] = (regs[high_slot] & ~mask_high) | ((value >> (64u - shift)) & mask_high);\n    }\n  }\n  return 1;\n}\n");
    out.push_str("static inline int axis_write_reg64(uint64_t *regs, size_t count, uint32_t index, const char *kind, uint64_t value, axis_state64 *state) {\n  return axis_write_view64(regs, count, index, axis_reg_class_of(kind), value, state, 0u, 0u, 0u, 0u);\n}\n\n");
    out.push_str("static inline uint32_t axis_operand_register(const axis_lift_operand *op, uint32_t decoded) {\n  return decoded + op->register_bias;\n}\n");
    /* Which architectural register an operand names, as the slot that register
       starts at. A bare register *number* is ambiguous across files -- RISC-V's
       x5 and f5 are both 5 -- which is fine for indexing within a class and
       useless to anything reasoning about dependences. The base slot is unique,
       and for a lane operand it is the register rather than the element, since
       two elements of one vector register are one register. */
    out.push_str("static inline uint32_t axis_operand_slot(const axis_lift_operand *op, uint32_t decoded) {\n  uint32_t number = axis_operand_register(op, decoded);\n  if (op->view_width) { return op->slot_base + number * (op->stride ? op->stride : 1u); }\n  const axis_reg_class *rules = axis_op_class(op);\n  if (!rules) { return number; }\n  return rules->offset + (rules->index_offset + number) * rules->limbs;\n}\n");
    out.push_str("static inline uint64_t axis_read_operand64(const uint64_t *regs, size_t count, const axis_lift_operand *op, uint32_t decoded, const axis_state64 *state) {\n  return axis_read_view64(regs, count, axis_operand_register(op, decoded), axis_op_class(op), state, op->stride, op->view_offset, op->view_width, op->slot_base);\n}\n");
    out.push_str("static inline int axis_write_operand64(uint64_t *regs, size_t count, const axis_lift_operand *op, uint32_t decoded, uint64_t value, axis_state64 *state) {\n  return axis_write_view64(regs, count, axis_operand_register(op, decoded), axis_op_class(op), value, state, op->stride, op->view_offset, op->view_width, op->slot_base);\n}\n\n");
    // ⚠️ A value wider than the word, moved a LIMB at a time -- which is how
    // the register file already stores one, and how a machine already moves
    // one: 128 bits is two 64-bit bus transactions, not a 128-bit one. The
    // memory interface stays `uint64_t` and needs no ABI change; what was
    // wrong was asking it for 128 bits in a single call and keeping what came
    // back. Arithmetic is not done here: these move values, and an operation
    // on one computes at its own width.
    out.push_str("static inline void axis_read_limbs64(const uint64_t *regs, size_t count, const axis_lift_operand *op, uint32_t decoded, const axis_state64 *state, uint64_t *out, uint32_t limbs) {\n  const axis_reg_class *rules = axis_op_class(op);\n  uint32_t index = axis_operand_register(op, decoded);\n  for (uint32_t i = 0; i < limbs; ++i) { out[i] = 0; }\n  if (!rules) { return; }\n  if (rules->zero_index >= 0 && index == (uint32_t)rules->zero_index) { return; }\n  if (limbs > rules->limbs) { limbs = rules->limbs; }\n  uint32_t slot = rules->offset + (rules->index_offset + index) * rules->limbs;\n  for (uint32_t i = 0; i < limbs; ++i) { out[i] = (slot + i) < count ? regs[slot + i] : 0; }\n}\n");
    out.push_str("static inline int axis_write_limbs64(uint64_t *regs, size_t count, const axis_lift_operand *op, uint32_t decoded, const uint64_t *in, uint32_t limbs, axis_state64 *state) {\n  (void)state;\n  const axis_reg_class *rules = axis_op_class(op);\n  uint32_t index = axis_operand_register(op, decoded);\n  if (!rules) { return 0; }\n  if (rules->zero_index >= 0 && index == (uint32_t)rules->zero_index) { return 0; }\n  /* ⚠️ The CLASS says how many limbs a register has, and the caller derives\n     its count from the operand's declared width. Where a description puts a\n     128-bit operand in a one-limb class the two disagree, and writing the\n     caller's count walked into the NEXT register -- `VADD_4S vd=1` wrote\n     regs[1] and regs[2], and regs[2] was its own source. Clamped here so no\n     generated write leaves the register it names; the description itself is\n     refused by validation, which is where that mismatch belongs. */\n  if (limbs > rules->limbs) { limbs = rules->limbs; }\n  uint32_t slot = rules->offset + (rules->index_offset + index) * rules->limbs;\n  int wrote = 0;\n  for (uint32_t i = 0; i < limbs; ++i) { if ((slot + i) < count) { regs[slot + i] = in[i]; wrote = 1; } }\n  return wrote;\n}\n");
    out.push_str("static inline void axis_mem_read_limbs64(const axis_mem64 *mem, uint64_t addr, uint32_t width, uint64_t *out, uint32_t limbs) {\n  if (mem && mem->read_limbs) { mem->read_limbs(mem->ctx, addr, width, out, limbs); return; }\n  for (uint32_t i = 0; i < limbs; ++i) {\n    uint32_t rest = width - i * 64u, take = rest >= 64u ? 64u : rest;\n    out[i] = mem ? axis_mask64(mem->read(mem->ctx, axis_mask64(addr + (uint64_t)i * 8u, 64u), take), take) : 0;\n  }\n}\n");
    out.push_str("static inline void axis_mem_write_limbs64(const axis_mem64 *mem, uint64_t addr, uint32_t width, const uint64_t *in, uint32_t limbs) {\n  if (!mem) { return; }\n  if (mem->write_limbs) { mem->write_limbs(mem->ctx, addr, width, in, limbs); return; }\n  for (uint32_t i = 0; i < limbs; ++i) {\n    uint32_t rest = width - i * 64u, take = rest >= 64u ? 64u : rest;\n    mem->write(mem->ctx, axis_mask64(addr + (uint64_t)i * 8u, 64u), axis_mask64(in[i], take), take);\n  }\n}\n\n");

    // ⚠️ Limb ARITHMETIC -- docs/limbs.md section 3's second half, which it
    // deliberately left unbuilt and section 8 listed as still not done. Twelve
    // AArch64 SIMD instructions want it: `mul i128` needs carry across limbs
    // and `lshr i128 rn 64` crosses them, so neither is limb-wise and neither
    // is a move, which is why the limb transfers above cannot serve them.
    //
    // The value is an array of limbs, not a wider integer type. That is the
    // point: it generalises past 128, which a `__uint128_t` value would not.
    // `__uint128_t` appears once, inside `mul`, holding the 64x64 partial
    // product every schoolbook multiply needs -- the operand of the widening
    // multiply, not the representation of the value.
    out.push_str("enum { AXIS_WIDE_LIMBS = AXIS_EXEC_MAX_LIMBS };\ntypedef struct { uint64_t limb[AXIS_WIDE_LIMBS]; } axis_wide;\n");
    out.push_str("static inline axis_wide axis_wide_zero(void) { axis_wide w; for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) { w.limb[i] = 0; } return w; }\n");
    out.push_str("static inline axis_wide axis_wide_of(uint64_t v) { axis_wide w = axis_wide_zero(); w.limb[0] = v; return w; }\n");
    out.push_str("static inline uint64_t axis_wide_low(axis_wide a) { return a.limb[0]; }\n");
    // Clearing above the width, limb by limb: a limb wholly above it goes to
    // zero, the one straddling it is masked, and the rest are already inside.
    out.push_str("static inline axis_wide axis_wide_mask(axis_wide a, uint32_t width) {\n  for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) {\n    uint32_t low = i * 64u;\n    if (width <= low) { a.limb[i] = 0; }\n    else if (width < low + 64u) { a.limb[i] &= (UINT64_C(1) << (width - low)) - UINT64_C(1); }\n  }\n  return a;\n}\n");
    out.push_str("static inline axis_wide axis_wide_and(axis_wide a, axis_wide b) { for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) { a.limb[i] &= b.limb[i]; } return a; }\n");
    out.push_str("static inline axis_wide axis_wide_or(axis_wide a, axis_wide b) { for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) { a.limb[i] |= b.limb[i]; } return a; }\n");
    out.push_str("static inline axis_wide axis_wide_xor(axis_wide a, axis_wide b) { for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) { a.limb[i] ^= b.limb[i]; } return a; }\n");
    out.push_str("static inline axis_wide axis_wide_not(axis_wide a, uint32_t width) { for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) { a.limb[i] = ~a.limb[i]; } return axis_wide_mask(a, width); }\n");
    // Carry out of a limb is the sum wrapping below either addend. Done in two
    // steps because the incoming carry can make it wrap a second time.
    out.push_str("static inline axis_wide axis_wide_add(axis_wide a, axis_wide b, uint32_t width) {\n  axis_wide out = axis_wide_zero();\n  uint64_t carry = 0;\n  for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) {\n    uint64_t sum = a.limb[i] + b.limb[i];\n    uint64_t wrapped = sum < a.limb[i];\n    uint64_t total = sum + carry;\n    carry = wrapped | (total < sum);\n    out.limb[i] = total;\n  }\n  return axis_wide_mask(out, width);\n}\n");
    out.push_str("static inline axis_wide axis_wide_sub(axis_wide a, axis_wide b, uint32_t width) {\n  axis_wide out = axis_wide_zero();\n  uint64_t borrow = 0;\n  for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) {\n    uint64_t diff = a.limb[i] - b.limb[i];\n    uint64_t under = diff > a.limb[i];\n    uint64_t total = diff - borrow;\n    borrow = under | (total > diff);\n    out.limb[i] = total;\n  }\n  return axis_wide_mask(out, width);\n}\n");
    out.push_str("static inline axis_wide axis_wide_mul(axis_wide a, axis_wide b, uint32_t width) {\n  axis_wide out = axis_wide_zero();\n  for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) {\n    uint64_t carry = 0;\n    for (uint32_t j = 0; i + j < AXIS_WIDE_LIMBS; ++j) {\n      unsigned __int128 term = (unsigned __int128)a.limb[i] * (unsigned __int128)b.limb[j]\n                             + (unsigned __int128)out.limb[i + j] + (unsigned __int128)carry;\n      out.limb[i + j] = (uint64_t)term;\n      carry = (uint64_t)(term >> 64);\n    }\n  }\n  return axis_wide_mask(out, width);\n}\n");
    // A shift by 64 or more is whole limbs plus a bit shift. The bit shift is
    // guarded because shifting a uint64_t by 64 is undefined, which is the
    // trap this kind of code is usually caught by.
    out.push_str("static inline axis_wide axis_wide_shl(axis_wide a, uint64_t amount, uint32_t width) {\n  axis_wide out = axis_wide_zero();\n  if (amount >= (uint64_t)AXIS_WIDE_LIMBS * 64u) { return out; }\n  uint32_t words = (uint32_t)(amount / 64u), bits = (uint32_t)(amount % 64u);\n  for (uint32_t i = AXIS_WIDE_LIMBS; i-- > 0;) {\n    uint64_t value = 0;\n    if (i >= words) {\n      value = a.limb[i - words] << bits;\n      if (bits && i > words) { value |= a.limb[i - words - 1u] >> (64u - bits); }\n    }\n    out.limb[i] = value;\n  }\n  return axis_wide_mask(out, width);\n}\n");
    out.push_str("static inline axis_wide axis_wide_lshr(axis_wide a, uint64_t amount, uint32_t width) {\n  a = axis_wide_mask(a, width);\n  axis_wide out = axis_wide_zero();\n  if (amount >= (uint64_t)AXIS_WIDE_LIMBS * 64u) { return out; }\n  uint32_t words = (uint32_t)(amount / 64u), bits = (uint32_t)(amount % 64u);\n  for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) {\n    uint64_t value = 0;\n    if (i + words < AXIS_WIDE_LIMBS) {\n      value = a.limb[i + words] >> bits;\n      if (bits && i + words + 1u < AXIS_WIDE_LIMBS) { value |= a.limb[i + words + 1u] << (64u - bits); }\n    }\n    out.limb[i] = value;\n  }\n  return axis_wide_mask(out, width);\n}\n");
    // Comparison runs from the TOP limb down: the first that differs decides,
    // which is the one thing a limb-wise comparison must not get backwards.
    out.push_str("static inline int axis_wide_eq(axis_wide a, axis_wide b) { for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) { if (a.limb[i] != b.limb[i]) { return 0; } } return 1; }\n");
    out.push_str("static inline int axis_wide_ult(axis_wide a, axis_wide b) {\n  for (uint32_t i = AXIS_WIDE_LIMBS; i-- > 0;) {\n    if (a.limb[i] != b.limb[i]) { return a.limb[i] < b.limb[i]; }\n  }\n  return 0;\n}\n");
    out.push_str("static inline int axis_wide_nonzero(axis_wide a) { for (uint32_t i = 0; i < AXIS_WIDE_LIMBS; ++i) { if (a.limb[i]) { return 1; } } return 0; }\n");
    // A literal too wide for C to write, built from the limbs it is made of.
    // One constructor per limb count the document can hold.
    let wide_limbs = crate::ast::REGISTER_CLASSES
        .iter()
        .map(|class| class.limbs.max(1))
        .max()
        .unwrap_or(1);
    for count in 1..=wide_limbs {
        let params: Vec<String> = (0..count).map(|i| format!("uint64_t l{i}")).collect();
        let sets: Vec<String> = (0..count).map(|i| format!("w.limb[{i}] = l{i};")).collect();
        out.push_str(&format!(
            "static inline axis_wide axis_wide_lit{count}({}) {{ axis_wide w = axis_wide_zero(); {} return w; }}\n",
            params.join(", "),
            sets.join(" ")
        ));
    }
    out.push_str("static inline axis_wide axis_wide_read_operand(const uint64_t *regs, size_t count, const axis_lift_operand *op, uint32_t decoded, const axis_state64 *state) {\n  axis_wide w = axis_wide_zero();\n  uint32_t limbs = op->width > 64u ? (op->width + 63u) / 64u : 1u;\n  if (limbs > AXIS_WIDE_LIMBS) { limbs = AXIS_WIDE_LIMBS; }\n  if (op->width > 64u) { axis_read_limbs64(regs, count, op, decoded, state, w.limb, limbs); }\n  else { w.limb[0] = axis_read_operand64(regs, count, op, decoded, state); }\n  return w;\n}\n\n");


    out.push_str("typedef struct axis_exec_result64 {\n  const char *mnemonic;\n  uint64_t result;\n  int wrote;\n  uint32_t dest;\n  const char *state_name;\n  uint64_t state_value;\n  uint64_t next_pc;\n  int trapped;\n  const char *trap_cause;\n  int ok;\n  /* The destination as a file-qualified slot. `dest` is a register number,\n     which is ambiguous across files -- RISC-V's x5 and f5 are both 5 -- and\n     anything reasoning about dependences needs the register, not the number.\n     Appended, so the positional initialisers above stay correct. */\n  uint32_t dest_slot;\n  /* A value wider than the word, as the limbs it occupies. `result` stays the\n     low one, so every existing reader is unaffected; `result_limbs` is how\n     many of these are meaningful, and is 0 for an ordinary 64-bit answer. */\n  uint64_t result_limb[AXIS_EXEC_MAX_LIMBS];\n  uint32_t result_limbs;\n} axis_exec_result64;\n\n");
    for (_, def) in effect_fns {
        out.push_str(def);
    }

    out.push_str("static inline int axis_exec_eval64(axis_insn_id id, const uint64_t *in, int n, uint64_t *value) {\n  switch (id) {\n");
    for instruction in &document.instructions {
        if instruction.formal_semantics.trim().is_empty() {
            continue;
        }
        // The same 64-bit limit the effect path has. `BSL_V` states itself as
        // `formal` rather than as a behavior, so it reached this path instead
        // and was evaluated at 64 bits with the other half dropped.
        if wider_than_word64(instruction) {
            continue;
        }
        let Ok(expr) = crate::semantics::parse_formal_semantics(&instruction.formal_semantics)
        else {
            continue;
        };
        let inputs: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .collect();
        let bindings: Vec<(String, String)> = inputs
            .iter()
            .enumerate()
            .map(|(idx, operand)| (operand.name.clone(), format!("in[{idx}]")))
            .collect();
        let width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .unwrap_or(64);
        let Some(value) = c_wide_expr(&expr, &bindings, width) else {
            continue;
        };
        // Taken at the width the instruction writes. Every operator masks its
        // own result, so this only ever shows on an expression that applies
        // none -- an identity, whose value is a bare operand -- and there it
        // showed as a 32-bit machine returning all 64 bits of the slot its
        // register is carried in.
        out.push_str(&format!(
            "    case AXIS_INSN_{}: if (n == {}) {{ *value = axis_mask64({}, {width}u); return 1; }} break;\n",
            tablegen_ident(&instruction.mnemonic),
            inputs.len(),
            value
        ));
    }
    out.push_str("    default: break;\n  }\n  (void)in; (void)n; (void)value; return 0;\n}\n\n");

    // ⚠️ The same switch at a width the word cannot hold, over limbs. The
    // instructions here are the ones the tier above skipped for being wide: a
    // `Q` register's lane arithmetic, which `expand_lanes` has already turned
    // into shifts, masks and ors, so nothing lane-shaped reaches this and only
    // the scalar operators need a limb meaning.
    out.push_str("static inline int axis_exec_eval_wide(axis_insn_id id, const axis_wide *in, int n, axis_wide *value) {\n  switch (id) {\n");
    for instruction in &document.instructions {
        if instruction.formal_semantics.trim().is_empty() || !wider_than_word64(instruction) {
            continue;
        }
        let Ok(expr) = crate::semantics::parse_formal_semantics(&instruction.formal_semantics)
        else {
            continue;
        };
        let inputs: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .collect();
        let bindings: Vec<(String, String)> = inputs
            .iter()
            .enumerate()
            .map(|(idx, operand)| (operand.name.clone(), format!("in[{idx}]")))
            .collect();
        let width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .unwrap_or(64);
        let Some(value) = c_limb_expr(&expr, &bindings, width) else {
            continue;
        };
        out.push_str(&format!(
            "    case AXIS_INSN_{}: if (n == {}) {{ *value = axis_wide_mask({}, {width}u); return 1; }} break;\n",
            tablegen_ident(&instruction.mnemonic),
            inputs.len(),
            value
        ));
    }
    out.push_str("    default: break;\n  }\n  (void)in; (void)n; (void)value; return 0;\n}\n\n");

    // Instructions performed by a routine the embedder supplies, declared
    // before the dispatch that calls them. The signature is exactly a generated
    // effect function's -- decoded operands, the register file, memory, the pc,
    // architectural state, and the result to report through -- because an
    // implementation does the same job and there is no reason to invent a
    // second shape for it. Declared rather than defined: this header says what
    // to call, and whoever links it says what happens.
    let named = |instruction: &crate::ast::Instruction| {
        let answer = instruction.implementation.trim();
        (!answer.is_empty() && answer != crate::ast::UNSUPPLIED)
            .then(|| (tablegen_ident(&instruction.mnemonic), answer.to_string()))
    };
    let implementations: Vec<(String, String)> =
        document.instructions.iter().filter_map(named).collect();
    // ⚠️ And the instructions nobody performs, which declare NOTHING. An
    // executor that meets one traps: there is no routine to call, and calling a
    // symbol the description never named would be inventing one. Keeping these
    // out of the declarations is the point -- a header that declared them would
    // make the build require definitions that do not exist, which is exactly
    // the state this third answer exists to avoid.
    let unsupplied: Vec<String> = document
        .instructions
        .iter()
        .filter(|instruction| {
            instruction.implementation.trim() == crate::ast::UNSUPPLIED
        })
        .map(|instruction| tablegen_ident(&instruction.mnemonic))
        .collect();
    if !implementations.is_empty() {
        out.push_str("#ifndef AXIS_IMPL_STUBS_INTERNAL\n");
        out.push_str("/* Performed by routines the embedder supplies. */\n");
        for (_, symbol) in &implementations {
            out.push_str(&format!(
                "void {symbol}(const axis_lifted *lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state, axis_exec_result64 *r);\n"
            ));
        }
        out.push_str("#endif\n");
        out.push('\n');
        // ⚠️ Placeholders, and only if the build ASKS for them. Declaring a
        // routine and supplying none is a link error naming exactly the
        // functions the embedder still has to write, which is the most useful
        // thing this file can do for someone bringing a machine up. A harness
        // that only needs to link -- and has no key, so could not implement
        // these anyway -- defines `AXIS_IMPL_STUBS` and gets the same answer
        // `unsupplied` gives: a trap that says this build has no
        // implementation, rather than a wrong one.
        //
        // Not weak symbols. A weak default would make "declared a routine,
        // supplied none" and "declared nothing" behave identically without
        // anyone having chosen that, and those are the two states the third
        // answer exists to keep apart.
        // ⚠️ `AXIS_IMPL_STUBS_INTERNAL` gives the placeholders internal linkage,
        // which is what a self-contained library needs. A pack built with the
        // external ones collides with any other pack that names routines, and
        // with a host that supplies its own -- the exact failure packs exist to
        // avoid, found by linking an AArch64 exec pack beside a test that also
        // asked for stubs.
        out.push_str("#if defined(AXIS_IMPL_STUBS_INTERNAL)\n");
        out.push_str("/* Private to this translation unit: a pack carries its own and\n   overrides nothing. An embedder with the real routines builds without\n   this define and links them. */\n");
        // ⚠️ But a pack is BUILT before the host that loads it exists, so
        // "the embedder links the real routine" is not an answer a shipped
        // library can offer -- a `.dylib` on disk cannot be relinked by the
        // program that dlopens it. So the placeholders are not dead ends:
        // each calls through a bridge a pack installs, and only traps when
        // nothing is registered for it. The bridge is set at most once and
        // from one place, and the routine's number is baked into the call so
        // the lookup is not a string compare per instruction.
        out.push_str("typedef void (*axis_impl_bridge64)(int32_t routine, const axis_lifted *lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state, axis_exec_result64 *r);\n");
        out.push_str("static axis_impl_bridge64 axis_impl_bridge = 0;\n");
        out.push_str("static inline void axis_impl_set_bridge(axis_impl_bridge64 fn) { axis_impl_bridge = fn; }\n");
        // The directory, as functions rather than a table: a translation unit
        // that includes this header and registers nothing must not warn about
        // an unused one, and an unused `static inline` is the one shape C
        // promises is quiet.
        out.push_str(&format!(
            "static inline int32_t axis_impl_routine_count(void) {{ return {}; }}\n",
            implementations.len()
        ));
        out.push_str("static inline const char *axis_impl_routine_name(int32_t routine) {\n  switch (routine) {\n");
        for (slot, (_, symbol)) in implementations.iter().enumerate() {
            out.push_str(&format!("    case {slot}: return \"{symbol}\";\n"));
        }
        out.push_str("    default: return 0;\n  }\n}\n");
        out.push_str("static inline const char *axis_impl_routine_mnemonic(int32_t routine) {\n  switch (routine) {\n");
        for (slot, (ident, _)) in implementations.iter().enumerate() {
            out.push_str(&format!("    case {slot}: return \"{ident}\";\n"));
        }
        out.push_str("    default: return 0;\n  }\n}\n");
        for (slot, (_, symbol)) in implementations.iter().enumerate() {
            out.push_str(&format!(
                "static void {symbol}(const axis_lifted *lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state, axis_exec_result64 *r) {{\n  if (axis_impl_bridge) {{ axis_impl_bridge({slot}, lifted, regs, reg_count, mem, pc, state, r); return; }}\n  (void)lifted; (void)regs; (void)reg_count; (void)mem; (void)pc; (void)state;\n  r->trapped = 1; r->trap_cause = \"{}\";\n}}\n",
                crate::ast::UNSUPPLIED_TRAP
            ));
        }
        out.push_str("#endif\n\n");
        out.push_str("#ifdef AXIS_IMPL_STUBS\n");
        out.push_str("/* Placeholders for a build that only needs to link. Each reports the\n   same trap an instruction with no implementation reports; an embedder\n   supplies the real ones and drops this define. */\n");
        for (_, symbol) in &implementations {
            out.push_str(&format!(
                "void {symbol}(const axis_lifted *lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state, axis_exec_result64 *r) {{\n  (void)lifted; (void)regs; (void)reg_count; (void)mem; (void)pc; (void)state;\n  r->trapped = 1; r->trap_cause = \"{}\";\n}}\n",
                crate::ast::UNSUPPLIED_TRAP
            ));
        }
        out.push_str("#endif\n\n");
    }

    out.push_str("static inline int axis_exec_apply64(axis_insn_id id, const axis_lifted *lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state, axis_exec_result64 *r) {\n  switch (id) {\n");
    for (ident, _) in effect_fns {
        out.push_str(&format!("    case AXIS_INSN_{ident}: axis_exec64_eff_{ident}(lifted, regs, reg_count, mem, pc, state, r); return 1;\n"));
    }
    for (ident, symbol) in &implementations {
        out.push_str(&format!(
            "    case AXIS_INSN_{ident}: {symbol}(lifted, regs, reg_count, mem, pc, state, r); return 1;\n"
        ));
    }
    for ident in &unsupplied {
        out.push_str(&format!(
            "    case AXIS_INSN_{ident}: r->trapped = 1; r->trap_cause = \"{}\"; return 1;\n",
            crate::ast::UNSUPPLIED_TRAP
        ));
    }
    out.push_str("    default: break;\n  }\n  (void)lifted; (void)regs; (void)reg_count; (void)mem; (void)pc; (void)state; (void)r; return 0;\n}\n\n");

    /* One lane of a word. A scalable instruction instantiates to VL/elem of
       these, all sharing the word; everything else is a group of one. */
    /* The fall-through counter wraps at the ISA's word, not at the 64-bit slot
       it is carried in: the word after the last one on a 32-bit machine is
       address zero. The entry is in hand here, which is why the mask lives at
       this entry point and not at the one that has not decoded yet. */
    out.push_str("static inline axis_exec_result64 axis_exec_step64_entry(const axis_lift_entry *entry, uint32_t word, axis_lifted lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state) {\n  (void)word;\n  axis_exec_result64 r = { NULL, 0, 0, 0, NULL, 0, axis_mask64(pc + AXIS_EXEC_ILEN, entry->state_width), 0, NULL, 0 };\n  r.mnemonic = entry->mnemonic;\n");
    out.push_str("  if (axis_exec_apply64(entry->id, &lifted, regs, reg_count, mem, pc, state, &r)) { r.ok = 1; return r; }\n");
    // ⚠️ The wide tier first. An instruction any of whose operands is wider
    // than the word cannot pass its inputs or its answer through a `uint64_t`,
    // so it takes the limb evaluator. The test is the entry's own operand
    // widths, so no instruction needs to be listed anywhere.
    //
    // ⚠️ A NARROW destination in a wide instruction still writes through the
    // view helper. `ADDP_D` reads 128 bits and writes 64, and writing its one
    // limb directly left the other holding whatever the register held before --
    // where AArch64 zeroes the rest of the register on a narrow write, which
    // `axis_write_view64` has always known and `axis_write_limbs64` does not,
    // because a limb write is a whole-register write and has nothing to zero.
    out.push_str("  if (!entry->liftable) { return r; }\n");
    out.push_str("  {\n    int wide = 0;\n    for (int i = 0; i < entry->operand_count; ++i) { if (entry->operands[i].width > 64u) { wide = 1; } }\n    if (wide) {\n");
    out.push_str("      axis_wide win[AXIS_LIFT_MAX_OPERANDS]; int wn = 0;\n");
    out.push_str("      for (int i = 0; i < entry->operand_count; ++i) { const axis_lift_operand *op = &entry->operands[i]; if ((op->role_code == AXIS_ROLE_OUT) || (op->role_code == AXIS_ROLE_ENC)) continue; uint32_t raw = lifted.operands[i]; win[wn++] = axis_op_class(op) ? axis_wide_read_operand(regs, reg_count, op, raw, state) : axis_wide_of(raw); }\n");
    out.push_str("      axis_wide wout = axis_wide_zero();\n      if (!axis_exec_eval_wide(entry->id, win, wn, &wout)) { return r; }\n");
    out.push_str("      r.result = axis_wide_low(wout); r.ok = 1;\n");
    out.push_str("      for (int i = 0; i < entry->operand_count; ++i) { const axis_lift_operand *op = &entry->operands[i]; if (((op->role_code == AXIS_ROLE_OUT) || (op->role_code == AXIS_ROLE_INOUT)) && axis_op_class(op)) { uint32_t idx = lifted.operands[i]; if (op->width > 64u) { uint32_t limbs = (op->width + 63u) / 64u; if (limbs > AXIS_WIDE_LIMBS) { limbs = AXIS_WIDE_LIMBS; } if (axis_write_limbs64(regs, reg_count, op, idx, wout.limb, limbs, state)) { r.wrote = 1; r.dest = axis_operand_register(op, idx); r.dest_slot = axis_operand_slot(op, idx); } r.result_limbs = limbs; for (uint32_t k = 0; k < limbs; ++k) { r.result_limb[k] = wout.limb[k]; } } else if (axis_write_operand64(regs, reg_count, op, idx, axis_wide_low(wout), state)) { r.wrote = 1; r.dest = axis_operand_register(op, idx); r.dest_slot = axis_operand_slot(op, idx); } } }\n");
    out.push_str("      return r;\n    }\n  }\n");
    out.push_str("  uint64_t inputs[AXIS_LIFT_MAX_OPERANDS]; int n = 0;\n");
    /* A selector is encoded and read by nothing: it carries the register number
       an instruction's lanes are elements of, so binding it as a value would
       pass a register number where a value belongs. */
    out.push_str("  for (int i = 0; i < entry->operand_count; ++i) { const axis_lift_operand *op = &entry->operands[i]; if ((op->role_code == AXIS_ROLE_OUT) || (op->role_code == AXIS_ROLE_ENC)) continue; uint32_t raw = lifted.operands[i]; inputs[n++] = axis_op_class(op) ? axis_read_operand64(regs, reg_count, op, raw, state) : raw; }\n");
    out.push_str("  uint64_t result = 0; if (!axis_exec_eval64(entry->id, inputs, n, &result)) { return r; } r.result = result; r.ok = 1;\n");
    out.push_str("  for (int i = 0; i < entry->operand_count; ++i) { const axis_lift_operand *op = &entry->operands[i]; if (((op->role_code == AXIS_ROLE_OUT) || (op->role_code == AXIS_ROLE_INOUT)) && axis_op_class(op)) { uint32_t idx = lifted.operands[i]; if (axis_write_operand64(regs, reg_count, op, idx, result, state)) { r.wrote = 1; r.dest = axis_operand_register(op, idx); r.dest_slot = axis_operand_slot(op, idx); } } }\n  return r;\n}\n\n");

    /* Executing a word means executing every lane it encodes, in lane order.
       The lanes share the word by construction, which is why decode reports a
       group rather than calling several matches ambiguous. */
        /* Decoding and executing are separate so a host that has already decoded
       the word -- a simulator memoising it -- does not scan the table again.
       `axis_exec_step64` is the two in sequence. */
    out.push_str("static inline const axis_lift_entry *axis_exec_decode64(uint32_t word, const char *isa, int *lanes_out) {\n");
    out.push_str("  const axis_lift_entry *first = NULL; int lanes = 0;\n");
    out.push_str("  for (size_t i = 0; i < AXIS_LIFT_TABLE_LEN; ++i) {\n    const axis_lift_entry *e = &AXIS_LIFT_TABLE[i];\n    if ((word & e->mask) != e->match) { continue; }\n    if (isa && e->isa[0] && strcmp(e->isa, isa) != 0) { continue; }\n    if (e->definedness) { continue; }\n    if ((word & e->mask) != e->match || !axis_lift_constraint_ok(word, e)) { continue; }\n    lanes++;\n    if (!first || (first->scalable_origin[0] && e->scalable_origin[0] && strcmp(first->scalable_origin, e->scalable_origin) == 0 && e->scalable_lane < first->scalable_lane)) { first = e; }\n  }\n");
    out.push_str("  *lanes_out = lanes;\n  return first;\n}\n\n");
    out.push_str("static inline axis_exec_result64 axis_exec_step64_decoded(const axis_lift_entry *first, int lanes, uint32_t word, const char *isa, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state) {\n  axis_exec_result64 r = { NULL, 0, 0, 0, NULL, 0, pc + AXIS_EXEC_ILEN, 0, NULL, 0 };\n");
    out.push_str("  if (!first) { return r; }\n");
    /* Several matches are one instruction only when they are lanes of one
       origin; anything else matching twice is an ambiguous decode space. */
    out.push_str("  if (lanes > 1 && !first->scalable_origin[0]) { return r; }\n");
    /* ⚠️ Every lane reads the registers and state as they were BEFORE the
       word, as the architecture does: an instruction reads its sources, then
       writes. Run in place, lane k's write was lane k+1's source whenever a
       destination is also a source -- `uzp2 z11.s, z9.s, z11.s` read an element
       UZP had already overwritten, and Arm's model said so. Each lane runs on a
       copy of the snapshot and its writes merge back by the bits it changed,
       since two lanes write different elements of one 64-bit slot. */
    out.push_str("  int snapshot = first->scalable_origin[0] != 0;\n");
    out.push_str("  size_t snap_slots = reg_count < AXIS_EXEC_REG_SLOTS ? reg_count : AXIS_EXEC_REG_SLOTS;\n");
    out.push_str("  uint64_t snap[AXIS_EXEC_REG_SLOTS > 0 ? AXIS_EXEC_REG_SLOTS : 1], scratch[AXIS_EXEC_REG_SLOTS > 0 ? AXIS_EXEC_REG_SLOTS : 1];\n");
    out.push_str("  uint64_t state_snap[AXIS_EXEC_STATE_SNAPSHOT], state_out[AXIS_EXEC_STATE_SNAPSHOT];\n");
    out.push_str("  size_t state_n = (state && state->entries && state->count <= AXIS_EXEC_STATE_SNAPSHOT) ? state->count : 0;\n");
    out.push_str("  if (snapshot) {\n    memcpy(snap, regs, snap_slots * sizeof(uint64_t));\n    for (size_t i = 0; i < state_n; ++i) { state_snap[i] = state->entries[i].value; state_out[i] = state_snap[i]; }\n  }\n");
    /* A word that is not a lane group is its first entry: the scan below
       could only find that one again. */
    out.push_str("  uint32_t lane = 0;\n  for (;;) {\n    const axis_lift_entry *entry = first->scalable_origin[0] ? NULL : first;\n    for (size_t i = 0; !entry && i < AXIS_LIFT_TABLE_LEN; ++i) {\n      const axis_lift_entry *e = &AXIS_LIFT_TABLE[i];\n      if ((word & e->mask) != e->match) { continue; }\n      if (e->definedness) { continue; }\n      if (isa && e->isa[0] && strcmp(e->isa, isa) != 0) { continue; }\n      if ((word & e->mask) != e->match || !axis_lift_constraint_ok(word, e)) { continue; }\n      if (first->scalable_origin[0] ? (strcmp(e->scalable_origin, first->scalable_origin) == 0 && e->scalable_lane == lane) : (e == first)) { entry = e; break; }\n    }\n    if (!entry) { break; }\n");
    out.push_str("    axis_lifted lifted; if (!axis_lift_entry_operands(word, entry, &lifted)) { break; }\n");
    out.push_str("    uint64_t *lane_regs = regs; size_t lane_count = reg_count;\n");
    out.push_str("    if (snapshot) {\n      memcpy(scratch, snap, snap_slots * sizeof(uint64_t)); lane_regs = scratch; lane_count = snap_slots;\n      for (size_t i = 0; i < state_n; ++i) { state->entries[i].value = state_snap[i]; }\n    }\n");
    out.push_str("    axis_exec_result64 lane_result = axis_exec_step64_entry(entry, word, lifted, lane_regs, lane_count, mem, pc, state);\n");
    out.push_str("    if (snapshot) {\n      for (size_t i = 0; i < snap_slots; ++i) { uint64_t changed = snap[i] ^ scratch[i]; if (changed) { regs[i] = (regs[i] & ~changed) | (scratch[i] & changed); } }\n      for (size_t i = 0; i < state_n; ++i) { uint64_t changed = state_snap[i] ^ state->entries[i].value; state_out[i] = (state_out[i] & ~changed) | (state->entries[i].value & changed); }\n    }\n");
    out.push_str("    if (lane == 0) { r = lane_result; } else { r.result = lane_result.result; r.ok = lane_result.ok; if (lane_result.wrote) { r.wrote = 1; r.dest = lane_result.dest; r.dest_slot = lane_result.dest_slot; } if (lane_result.state_name) { r.state_name = lane_result.state_name; r.state_value = lane_result.state_value; } r.next_pc = lane_result.next_pc; }\n");
    out.push_str("    if (r.trapped) { break; }\n    if (!first->scalable_origin[0]) { break; }\n    lane++;\n  }\n");
    out.push_str("  if (snapshot) { for (size_t i = 0; i < state_n; ++i) { state->entries[i].value = state_out[i]; } }\n");
    out.push_str("  if (first->scalable_origin[0]) { r.mnemonic = first->scalable_origin; }\n  return r;\n}\n\n");
    out.push_str("static inline axis_exec_result64 axis_exec_step64(uint32_t word, const char *isa, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state) {\n  int lanes = 0;\n  const axis_lift_entry *first = axis_exec_decode64(word, isa, &lanes);\n  return axis_exec_step64_decoded(first, lanes, word, isa, regs, reg_count, mem, pc, state);\n}\n\n");
}

/// Where `kind` sits in `axis_reg_classes`, which is `REGISTER_CLASSES` in
/// order: the first class of that name, as `axis_reg_class_of` finds it; -1
/// when no class has it.
fn reg_class_index(kind: &str) -> i64 {
    crate::ast::REGISTER_CLASSES
        .iter()
        .position(|class| class.name == kind)
        .map_or(-1, |index| index as i64)
}

/// Does this instruction carry a value wider than the executors' word?
///
/// ⚠️ Both generated executors are 64-bit all the way down. `axis_mem64`'s read
/// returns a `uint64_t`, `axis_read_operand64` returns one, and Rust's twin is
/// `u64` -- so a 128-bit load was emitted as `mem->read(..., 128u)` into a
/// 64-bit variable and kept half the value, silently, while reporting `ok`.
///
/// Being unable to perform these is a limit and is fine. Answering them wrongly
/// is not. So no effect function is emitted for them, which is the existing way
/// an executor says it cannot evaluate something -- the same path the directed
/// rounding-mode forms take -- and the host sees `unsupported` rather than a
/// number that is half right.
///
/// This was invisible because the gate that would have caught it executes at 64
/// bits and reports these twenty as "past the 64-bit register slot, not
/// executed". `sim_vs_executor` found it, on a corpus it was not registered for,
/// by comparing against the Python executor, which models the full width.
fn wider_than_word64(instruction: &Instruction) -> bool {
    instruction.operands.iter().any(|operand| operand.width > 64)
        || instruction
            .behavior
            .as_ref()
            .is_some_and(|behavior| behavior.effects.iter().any(|effect| {
                matches!(&effect.loc, crate::effects::Loc::Mem { width, .. } if *width > 64)
                    || effect.value.width > 64
            }))
}

/// One load an effect performs, lifted out of the expression that names it.
///
/// ⚠️ Why an effect's loads are hoisted rather than read where they sit. A C
/// or Rust expression decides for itself which operands it evaluates: `c ? a
/// : b` reads one arm, `x && y` stops at the first false, and C leaves the
/// order of `a + b` to the compiler. For a pure value none of that shows. For a
/// read it does -- the simulator records every access -- and it will matter
/// more than that once a read can have an effect of its own (an MMIO status
/// register). Found by a descriptor launch (docs/accelerator_design.md, H1a):
/// its guard checks a magic word, a version and a count, and the C simulator
/// read the magic, saw it wrong and stopped, while the Python executor read
/// all three. Both answers were right; the traces were not the same trace.
///
/// So the rule is the Python executor's, which is also the validator's
/// numbering: every load an effect names is performed once, innermost first,
/// left to right, whatever a `select` or an `and` later decides.
struct HoistedLoad {
    address: SemanticExpr,
    access: u32,
    signed: bool,
}

/// `expr` with every load replaced by `(__hoisted <n> <access> <signed>)`,
/// appending each to `loads` in the order it must be performed. With
/// `keep_top`, a load that IS the expression stays where it is and only the
/// loads inside its address are hoisted -- the whole-value case has its own
/// peel in every backend, and its extension rules are that peel's.
fn hoist_loads(
    expr: &SemanticExpr,
    loads: &mut Vec<HoistedLoad>,
    keep_top: bool,
) -> Option<SemanticExpr> {
    let SemanticExpr::List(items) = expr else {
        return Some(expr.clone());
    };
    let is_load = matches!(items.first(), Some(SemanticExpr::Atom(op))
        if matches!(op.as_str(), "load" | "atomic_load"))
        && matches!(items.len(), 4 | 5);
    let mut rebuilt = Vec::with_capacity(items.len());
    for item in items {
        rebuilt.push(hoist_loads(item, loads, false)?);
    }
    if !is_load || keep_top {
        return Some(SemanticExpr::List(rebuilt));
    }
    let access = load_access_width(&items[1])?;
    let signed = matches!(&items[2], SemanticExpr::Atom(sign) if sign == "signed");
    loads.push(HoistedLoad {
        address: rebuilt.last()?.clone(),
        access,
        signed,
    });
    let index = loads.len() - 1;
    Some(SemanticExpr::List(vec![
        SemanticExpr::Atom("__hoisted".to_string()),
        SemanticExpr::Atom(index.to_string()),
        SemanticExpr::Atom(access.to_string()),
        SemanticExpr::Atom(if signed { "1" } else { "0" }.to_string()),
    ]))
}

/// The C statements that perform `loads[from..]`, in order.
fn c_hoisted_prelude(
    loads: &[HoistedLoad],
    from: usize,
    bindings: &[(String, String)],
    address_width: u32,
) -> Option<String> {
    let mut out = String::new();
    for (index, load) in loads.iter().enumerate().skip(from) {
        let addr = c_wide_expr_at(&load.address, bindings, address_width, address_width)?;
        out.push_str(&format!(
            "    uint64_t axis_ld{index} = axis_mask64(mem ? mem->read(mem->ctx, axis_mask64({addr}, {address_width}u), {}u) : 0, {}u);\n",
            load.access, load.access
        ));
    }
    Some(out)
}

fn emit_c_effect64_fn(instruction: &Instruction) -> Option<String> {
    use crate::effects::Loc;
    if !crate::effects::behavior_is_authoritative(instruction) {
        return None;
    }
    // ⚠️ No blanket refusal for a wide instruction any more. The wide arms
    // below decline what they cannot do -- anything but moving a value -- and
    // a decline from there is the same `None` this used to return, reached by
    // asking what the instruction actually does rather than how wide it is.
    let behavior = instruction.behavior.as_ref()?;
    let mut input_prelude = String::new();
    let mut bindings: Vec<(String, String)> = instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        .map(|operand| {
            let pos = instruction
                .operands
                .iter()
                .position(|candidate| candidate.name == operand.name)
                .unwrap();
            let expression = if operand.kind == "imm" {
                format!("lifted->operands[{pos}]")
            } else {
                // Through the operand, not the class: an effect handler binds
                // the same lane operands the pure path does, and a lane names
                // an element of its register rather than the whole of it. A
                // vector load's destination is one element; writing the
                // register whole is what made the C simulator disagree with
                // the executor on every program containing one.
                format!(
                    "axis_read_operand64(regs, reg_count, &lifted->entry->operands[{pos}], lifted->operands[{pos}], state)"
                )
            };
            let value = format!("axis_input_{pos}");
            input_prelude.push_str(&format!(
                "  uint64_t {value} = {expression}; (void){value};\n"
            ));
            (operand.name.clone(), value)
        })
        .collect();
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        let pos = instruction
            .operands
            .iter()
            .position(|candidate| candidate.name == operand.name)?;
        let entry = format!("axis_entry_{pos}");
        input_prelude.push_str(&format!(
            "  uint64_t {entry} = axis_input_{pos}; (void){entry};\n"
        ));
        bindings.push((format!("__input_{}", operand.name), entry));
    }
    for (pos, operand) in instruction.operands.iter().enumerate() {
        if operand.output && !operand.input {
            input_prelude.push_str(&format!(
                "  uint64_t axis_output_{pos} = 0; (void)axis_output_{pos};\n"
            ));
        }
    }
    let mut body = String::new();
    for original in &behavior.effects {
        // Every load the effect names, hoisted in the order it is performed:
        // the guard's first, then -- only if the guard holds -- the address's
        // and the value's. See `HoistedLoad`.
        let mut loads: Vec<HoistedLoad> = Vec::new();
        let mut effect = original.clone();
        if let Some(guard) = &mut effect.guard {
            guard.expr = hoist_loads(&guard.expr, &mut loads, false)?;
        }
        let guard_prelude = match &original.guard {
            Some(guard) => c_hoisted_prelude(&loads, 0, &bindings, guard.load_address_width.unwrap_or(64))?,
            None => String::new(),
        };
        let mut body_prelude = String::new();
        if let Loc::Mem { addr, .. } = &mut effect.loc {
            let from = loads.len();
            addr.expr = hoist_loads(&addr.expr, &mut loads, false)?;
            body_prelude.push_str(&c_hoisted_prelude(&loads, from, &bindings, addr.load_address_width.unwrap_or(64))?);
        }
        if !matches!(effect.loc, Loc::Trap) {
            let from = loads.len();
            effect.value.expr = hoist_loads(&effect.value.expr, &mut loads, true)?;
            body_prelude.push_str(&c_hoisted_prelude(&loads, from, &bindings, effect.value.load_address_width.unwrap_or(64))?);
        }
        let effect = &effect;
        let mut inner = match &effect.loc {
            Loc::Reg(dest) => {
                let pos = instruction
                    .operands
                    .iter()
                    .position(|op| &op.name == dest)?;
                let operand = &instruction.operands[pos];
                let semantic_value = if operand.input {
                    format!("axis_input_{pos}")
                } else {
                    format!("axis_output_{pos}")
                };
                // ⚠️ A destination wider than the word. The value cannot live
                // in a `uint64_t`, and asking memory for all of it in one call
                // is what used to keep half. Both ends move a limb at a time:
                // `rules->limbs` words of the register file, and one 64-bit
                // memory access each, which is what the bus does anyway.
                if operand.width > 64 {
                    if let Some(load) = c_wide_limb_load(&effect.value, &bindings, operand.width) {
                        let limbs = operand.width.div_ceil(64);
                        body.push_str(&format!(
                            "  {{\n    uint64_t limb[AXIS_EXEC_MAX_LIMBS];\n{load}    uint32_t dest = lifted->operands[{pos}];\n    if (axis_write_limbs64(regs, reg_count, &lifted->entry->operands[{pos}], dest, limb, {limbs}u, state)) {{ r->wrote = 1; r->dest = axis_operand_register(&lifted->entry->operands[{pos}], dest); r->dest_slot = axis_operand_slot(&lifted->entry->operands[{pos}], dest); }}\n    r->result = limb[0]; r->result_limbs = {limbs}u;\n    for (uint32_t i = 0; i < {limbs}u; ++i) {{ r->result_limb[i] = limb[i]; }}\n  }}\n"
                        ));
                        continue;
                    }
                    return None;
                }
                let value = c_wide_effect_value(&effect.value, &bindings, operand.width)?;
                if let Some((_, binding)) = bindings.iter_mut().find(|(name, _)| name == dest) {
                    *binding = semantic_value.clone();
                } else {
                    bindings.push((dest.clone(), semantic_value.clone()));
                }
                format!("    uint64_t value = {value}; uint32_t dest = lifted->operands[{pos}];\n    if (axis_write_operand64(regs, reg_count, &lifted->entry->operands[{pos}], dest, value, state)) {{ r->wrote = 1; r->dest = axis_operand_register(&lifted->entry->operands[{pos}], dest); r->dest_slot = axis_operand_slot(&lifted->entry->operands[{pos}], dest); }} {semantic_value} = value; r->result = value;\n")
            }
            Loc::FixedReg {
                kind,
                index,
                width: _,
            } => {
                let value = c_wide_expr(&effect.value.expr, &bindings, effect.value.width)?;
                format!("    uint64_t value = {value}; uint32_t dest = {index}u;\n    if (axis_write_reg64(regs, reg_count, dest, {}, value, state)) {{ r->wrote = 1; r->dest = dest; }} r->result = value;\n", c_string(kind))
            }
            Loc::State { name, width } => {
                // `c_wide_effect_value`, as the store arm beside it uses: a
                // state write's value may be a LOAD. An exclusive monitor that
                // records what it observed is exactly that.
                let value = c_wide_effect_value(&effect.value, &bindings, effect.value.width)?;
                format!("    uint64_t value = axis_mask64({value}, {width}u); axis_state64_write(state, {}, value, {width}u); r->state_name = {}; r->state_value = value;\n", c_string(name), c_string(name))
            }
            Loc::Mem { addr, width, .. } => {
                // The address wraps at its own width, as it does for a load.
                let address_width = addr.width;
                let addr = c_wide_expr(&addr.expr, &bindings, address_width)?;
                // The wide twin of the load above, in the other direction.
                if *width > 64 {
                    let source = wide_source_operand(instruction, &effect.value)?;
                    let limbs = width.div_ceil(64);
                    body.push_str(&format!(
                        "  {{\n    uint64_t limb[AXIS_EXEC_MAX_LIMBS];\n    axis_read_limbs64(regs, reg_count, &lifted->entry->operands[{source}], lifted->operands[{source}], state, limb, {limbs}u);\n    axis_mem_write_limbs64(mem, axis_mask64({addr}, {address_width}u), {width}u, limb, {limbs}u);\n  }}\n"
                    ));
                    continue;
                }
                let value = c_wide_effect_value(&effect.value, &bindings, *width)?;
                format!("    if (mem) {{ mem->write(mem->ctx, axis_mask64({addr}, {address_width}u), axis_mask64({value}, {width}u), {width}u); }}\n")
            }
            Loc::Port { port, width } => {
                // The same shape a store has: where, then what. A host with no
                // channel hook observes nothing, which is what a machine with
                // nothing attached to its port does.
                let destination = c_wide_expr(&port.expr, &bindings, port.width.max(1))?;
                let value = c_wide_effect_value(&effect.value, &bindings, *width)?;
                format!(
                    "    if (mem && mem->send) {{ mem->send(mem->ctx, axis_mask64({destination}, {}u), axis_mask64({value}, {width}u), {width}u); }}\n",
                    port.width.max(1)
                )
            }
            Loc::Barrier { .. } => {
                let value = c_wide_expr(&effect.value.expr, &bindings, effect.value.width)?;
                format!("    uint64_t barrier_option = {value}; (void)barrier_option;\n")
            }
            Loc::Pc => {
                // Masked at the counter rather than trusted to the target's own
                // width. An arithmetic target masks its own result and a bare
                // register does not, and what reaches the counter is the same
                // either way: the value taken at the ISA's word.
                let value = c_wide_expr(&effect.value.expr, &bindings, effect.value.width)?;
                format!("    r->next_pc = axis_mask64({value}, lifted->entry->state_width);\n")
            }
            Loc::Trap => format!(
                "    r->trapped = 1; r->trap_cause = {}; return;\n",
                c_string(&crate::effects::render_semexpr(&effect.value.expr))
            ),
        };
        inner = format!("{body_prelude}{inner}");
        if let Some(guard) = &effect.guard {
            let guard = c_wide_guard_expr(&guard.expr, &bindings, guard.width)?;
            inner = format!("  {{\n{guard_prelude}  if ({guard}) {{\n{inner}  }}\n  }}\n");
        } else {
            inner = format!("  {{\n{inner}  }}\n");
        }
        body.push_str(&inner);
    }
    let ident = tablegen_ident(&instruction.mnemonic);
    Some(format!("#[allow(unused)]\nstatic inline void axis_exec64_eff_{ident}(const axis_lifted *lifted, uint64_t *regs, size_t reg_count, const axis_mem64 *mem, uint64_t pc, axis_state64 *state, axis_exec_result64 *r) {{\n  (void)lifted; (void)regs; (void)reg_count; (void)mem; (void)pc; (void)state; (void)r;\n{input_prelude}{body}}}\n\n").replace("#[allow(unused)]\n", ""))
}

fn c_wide_guard_expr(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    width: u32,
) -> Option<String> {
    let SemanticExpr::List(items) = expr else {
        return None;
    };
    let SemanticExpr::Atom(op) = items.first()? else {
        return None;
    };
    if matches!(op.as_str(), "and" | "or") && items.len() >= 3 {
        let joiner = if op == "and" { " && " } else { " || " };
        return Some(format!(
            "({})",
            items[1..]
                .iter()
                .map(|child| c_wide_guard_expr(child, bindings, width))
                .collect::<Option<Vec<_>>>()?
                .join(joiner)
        ));
    }
    if op == "not" && items.len() == 2 {
        return Some(format!(
            "!({})",
            c_wide_guard_expr(&items[1], bindings, width)?
        ));
    }
    if let Some((cmp, signed)) = comparison_spelling(op.as_str()) {
        if items.len() == 3 {
            let side = |text: String| {
                if signed {
                    format!("axis_signed64({text}, {width}u)")
                } else {
                    format!("axis_mask64({text}, {width}u)")
                }
            };
            return Some(format!(
                "{} {cmp} {}",
                side(c_wide_expr(&items[1], bindings, width)?),
                side(c_wide_expr(&items[2], bindings, width)?)
            ));
        }
    }
    None
}

/// The C/Rust spelling of an integer comparison, and whether it reads its
/// operands as signed. One table rather than a `match` in each of the four
/// places that lower a guard — the drift that pattern causes is recorded
/// throughout these docs.
fn comparison_spelling(op: &str) -> Option<(&'static str, bool)> {
    Some(match op {
        "icmp_eq" => ("==", false),
        "icmp_ne" => ("!=", false),
        "icmp_slt" => ("<", true),
        "icmp_sge" => (">=", true),
        "icmp_ult" => ("<", false),
        "icmp_uge" => (">=", false),
        _ => return None,
    })
}

/// Lower an effect's value, which may itself be a memory load.
///
/// A load cannot live in `c_wide_expr`: that lowering is shared with the pure
/// evaluator, which has no memory to read from. So it is handled where the
/// effect is — and it has to be handled for *every* destination rather than
/// only a register. A block copy stores what it just loaded, and having this
/// case in the register arm alone is exactly why the copies declined while the
/// fill did not.
/// The limb-wise read of a wide load, or `None` if the value is not one.
///
/// A wide destination is only writable here when what feeds it is a load of the
/// same width: that is data movement, and movement is what limbs express. An
/// arithmetic value of the same width is a different question -- it computes at
/// its own width, and the executors have no wide arithmetic yet, so it is
/// declined rather than half-performed.
fn c_wide_limb_load(
    value: &crate::effects::EffectExpr,
    bindings: &[(String, String)],
    width: u32,
) -> Option<String> {
    let SemanticExpr::List(items) = &value.expr else {
        return None;
    };
    if !matches!(items.first(), Some(SemanticExpr::Atom(op))
        if matches!(op.as_str(), "load" | "atomic_load"))
        || !matches!(items.len(), 4 | 5)
    {
        return None;
    }
    let access = load_access_width(&items[1])?;
    if access != width {
        return None;
    }
    let address_width = value.load_address_width?;
    let addr = c_wide_expr(items.last()?, bindings, address_width)?;
    let limbs = width.div_ceil(64);
    Some(format!(
        "    axis_mem_read_limbs64(mem, axis_mask64({addr}, {address_width}u), {width}u, limb, {limbs}u);\n"
    ))
}

/// The operand position a wide store's value reads, or `None` if it is not a
/// bare operand read.
///
/// Same rule as the load: a wide store this executor can perform is one that
/// moves a register to memory. Anything computed is declined.
fn wide_source_operand(
    instruction: &Instruction,
    value: &crate::effects::EffectExpr,
) -> Option<usize> {
    let SemanticExpr::Atom(name) = &value.expr else {
        return None;
    };
    let pos = instruction.operands.iter().position(|op| &op.name == name)?;
    if instruction.operands[pos].width != value.width {
        return None;
    }
    Some(pos)
}

fn c_wide_effect_value(
    value: &crate::effects::EffectExpr,
    bindings: &[(String, String)],
    target_width: u32,
) -> Option<String> {
    if let SemanticExpr::List(items) = &value.expr {
        if matches!(items.first(), Some(SemanticExpr::Atom(op))
            if matches!(op.as_str(), "load" | "atomic_load"))
            && matches!(items.len(), 4 | 5)
        {
            let access = load_access_width(&items[1])?;
            let signed = matches!(&items[2], SemanticExpr::Atom(sign) if sign == "signed");
            // Masked to the width the address is evaluated at. An operator
            // masks its own result, so this was invisible for as long as every
            // address was arithmetic; `lr.w rd, (rs1)` addresses with a bare
            // operand, and a 32-bit machine's address held in a 64-bit slot
            // then reached memory with whatever the upper half happened to
            // contain. The golden model and the Python executor wrap it, so
            // this was the wide C and Rust executors disagreeing with both.
            let address_width = value.load_address_width?;
            let addr = c_wide_expr(items.last()?, bindings, address_width)?;
            let addr = format!("axis_mask64({addr}, {address_width}u)");
            return Some(if signed {
                format!(
                    "axis_sext64(mem ? mem->read(mem->ctx, {addr}, {access}u) : 0, {access}u, {target_width}u)"
                )
            } else {
                format!(
                    "axis_mask64(mem ? mem->read(mem->ctx, {addr}, {access}u) : 0, {target_width}u)"
                )
            });
        }
    }
    c_wide_expr(&value.expr, bindings, value.width)
}

/// A formal-semantics expression at a width wider than the word, over limbs.
///
/// A deliberately small mirror of `c_wide_expr` rather than a width-parameter
/// threaded through it. That function has forty-odd arms -- floating point,
/// AArch64 helpers, division, rotates -- and none of them has a limb meaning
/// worth inventing on spec. This covers what the wide instructions actually
/// use, and anything else returns `None`, which is the decline the caller
/// already knows how to report. The set grows when a description needs it.
fn c_limb_expr(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    ambient_width: u32,
) -> Option<String> {
    match expr {
        SemanticExpr::Atom(atom) => {
            if let Some((_, value)) = bindings.iter().find(|(name, _)| name == atom) {
                return Some(value.clone());
            }
            if let Some(value) = crate::ir::integer_literal(atom) {
                // ⚠️ The literal that made the 64-bit tier decline. A 128-bit
                // broadcast constant is exactly what `MOVI` multiplies by, and
                // there is room for it now -- built a limb at a time, because C
                // has no literal this wide.
                let mut limbs: Vec<String> = Vec::new();
                let mut rest = value;
                while rest > 0 {
                    limbs.push(format!("UINT64_C({})", rest & u128::from(u64::MAX)));
                    rest >>= 64;
                }
                if limbs.is_empty() {
                    limbs.push("UINT64_C(0)".to_string());
                }
                return Some(format!(
                    "axis_wide_lit{}({})",
                    limbs.len(),
                    limbs.join(", ")
                ));
            }
            None
        }
        SemanticExpr::List(items) => {
            let SemanticExpr::Atom(op) = items.first()? else {
                return None;
            };
            let mut args = &items[1..];
            let mut width = ambient_width;
            if let Some(SemanticExpr::Atom(first)) = args.first() {
                if let Some(bits) = crate::ir::type_atom_bits(first) {
                    width = bits;
                    args = &args[1..];
                }
            }
            let values: Vec<String> = args
                .iter()
                .map(|arg| c_limb_expr(arg, bindings, width))
                .collect::<Option<Vec<_>>>()?;
            match op.as_str() {
                "and" => Some(fold(&values, "axis_wide_and")),
                "or" => Some(fold(&values, "axis_wide_or")),
                "xor" => Some(fold(&values, "axis_wide_xor")),
                "not" => Some(format!("axis_wide_not({}, {width}u)", values.first()?)),
                "add" => Some(format!(
                    "axis_wide_add({}, {}, {width}u)",
                    values.first()?,
                    values.get(1)?
                )),
                "sub" => Some(format!(
                    "axis_wide_sub({}, {}, {width}u)",
                    values.first()?,
                    values.get(1)?
                )),
                "mul" => Some(format!(
                    "axis_wide_mul({}, {}, {width}u)",
                    values.first()?,
                    values.get(1)?
                )),
                // The shift amount is a value like any other, so it is lowered
                // wide and then taken at the word: a shift past the value's
                // own width is already saturated by the helpers.
                "shl" | "sll" => Some(format!(
                    "axis_wide_shl({}, axis_wide_low({}), {width}u)",
                    values.first()?,
                    values.get(1)?
                )),
                "lshr" | "srl" => Some(format!(
                    "axis_wide_lshr({}, axis_wide_low({}), {width}u)",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_eq" => Some(format!(
                    "axis_wide_of(axis_wide_eq(axis_wide_mask({}, {width}u), axis_wide_mask({}, {width}u)))",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_ne" => Some(format!(
                    "axis_wide_of(!axis_wide_eq(axis_wide_mask({}, {width}u), axis_wide_mask({}, {width}u)))",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_ult" => Some(format!(
                    "axis_wide_of(axis_wide_ult(axis_wide_mask({}, {width}u), axis_wide_mask({}, {width}u)))",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_uge" => Some(format!(
                    "axis_wide_of(!axis_wide_ult(axis_wide_mask({}, {width}u), axis_wide_mask({}, {width}u)))",
                    values.first()?,
                    values.get(1)?
                )),
                "if" | "select" => Some(format!(
                    "(axis_wide_nonzero({}) ? ({}) : ({}))",
                    values.first()?,
                    values.get(1)?,
                    values.get(2)?
                )),
                _ => None,
            }
        }
    }
}

/// `f(f(a, b), c)` for an operator the description writes with many arguments.
fn fold(values: &[String], call: &str) -> String {
    let mut folded = values.first().cloned().unwrap_or_default();
    for value in &values[1..] {
        folded = format!("{call}({folded}, {value})");
    }
    folded
}

pub(crate) fn c_wide_expr(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    ambient_width: u32,
) -> Option<String> {
    c_wide_expr_at(expr, bindings, ambient_width, 64)
}

/// The same, with the width a load's address wraps at.
///
/// ⚠️ Separate because an address is not the ambient width and not always 64:
/// `a_wide_address_wraps_at_its_own_width` failed the moment the load arm
/// below assumed the latter, on a 32-bit machine whose address had to wrap at
/// 32. The effect publishes the width; the recursion carries it.
fn c_wide_expr_at(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    ambient_width: u32,
    address_width: u32,
) -> Option<String> {
    match expr {
        SemanticExpr::Atom(atom) => {
            if let Some((_, value)) = bindings.iter().find(|(name, _)| name == atom) {
                return Some(value.clone());
            }
            if atom == "pc" {
                return Some("pc".to_string());
            }
            if let Some(value) = crate::ir::integer_literal(atom) {
                // ⚠️ This tier computes in `uint64_t`, so a literal it cannot
                // hold is not a formatting problem to be worked around -- it is
                // this executor being asked for a value it has no room for.
                // Splitting the constant into halves was tried and was worse:
                // it compiled, and then truncated the product to 64 bits, which
                // is a wrong answer where the compiler had been giving an
                // error. Declining sends the instruction to the caller's skip
                // list instead.
                if value > u128::from(u64::MAX) {
                    return None;
                }
                return Some(format!("UINT64_C({value})"));
            }
            Some(format!("axis_state64_read(state, {})", c_string(atom)))
        }
        SemanticExpr::List(items) => {
            let SemanticExpr::Atom(op) = items.first()? else {
                return None;
            };
            // Reading a named register by index, the counterpart of `setreg`.
            // The wide ABI holds the register file, which is why this lowers
            // here and the compact path declines it -- the same reason that
            // path already skips anything touching architectural state.
            // A `deffun` call: emitted once beside the helpers, called here.
            if op == "call" {
                let SemanticExpr::Atom(name) = items.get(1)? else {
                    return None;
                };
                let mut args = Vec::new();
                for arg in &items[3..] {
                    let SemanticExpr::List(pair) = arg else { return None };
                    let (SemanticExpr::Atom(ty), value) = (pair.first()?, pair.get(1)?) else { return None };
                    let param = crate::ir::type_atom_width(ty)?;
                    if param > 64 {
                        return None;
                    }
                    let value = c_wide_expr_at(value, bindings, param, address_width)?;
                    args.push(format!("axis_mask64({value}, {param}u)"));
                }
                return Some(format!(
                    "axis_fn64_{}({})",
                    crate::emit::semantics::function_ident(name),
                    args.join(", ")
                ));
            }
            if op == "getreg" {
                let [SemanticExpr::Atom(kind), SemanticExpr::Atom(index)] = &items[1..] else {
                    return None;
                };
                let index: u32 = index.parse().ok()?;
                return Some(format!(
                    "axis_read_reg64(regs, reg_count, {index}u, {}, state)",
                    c_string(kind)
                ));
            }
            // ⚠️ A load ANYWHERE, not only as a whole effect value. The
            // top-level case has its own lowering beside this one, which is
            // where this shape is copied from; what it could not do is a
            // second load, or a load inside an address. Both wide executors
            // declined every instruction with one, which the gate reported as
            // "0 executed, 8 declined" -- and the Rust half of it still said
            // PASS, because a decline threshold covered the whole corpus.
            //
            // The address is evaluated at the machine's width rather than the
            // surrounding value's, the same rule the Python executor and the
            // golden model follow, and masked there because an address wraps.
            // A load already performed by the effect's prelude, extended here
            // exactly as the inline arm below would have extended it.
            if op == "__hoisted" {
                let [SemanticExpr::Atom(index), SemanticExpr::Atom(access), SemanticExpr::Atom(signed)] =
                    &items[1..]
                else {
                    return None;
                };
                return Some(if signed == "1" {
                    format!("axis_sext64(axis_ld{index}, {access}u, {ambient_width}u)")
                } else {
                    format!("axis_ld{index}")
                });
            }
            if matches!(op.as_str(), "load" | "atomic_load") && matches!(items.len(), 4 | 5) {
                let access = load_access_width(&items[1])?;
                let signed =
                    matches!(&items[2], SemanticExpr::Atom(sign) if sign == "signed");
                let addr = c_wide_expr_at(items.last()?, bindings, address_width, address_width)?;
                let addr = format!("axis_mask64({addr}, {address_width}u)");
                return Some(if signed {
                    format!(
                        "axis_sext64(mem ? mem->read(mem->ctx, {addr}, {access}u) : 0, \
                         {access}u, {ambient_width}u)"
                    )
                } else {
                    format!(
                        "axis_mask64(mem ? mem->read(mem->ctx, {addr}, {access}u) : 0, \
                         {access}u)"
                    )
                });
            }
            if op == "input" {
                let [SemanticExpr::Atom(name)] = &items[1..] else {
                    return None;
                };
                return bindings
                    .iter()
                    .find(|(candidate, _)| candidate == &format!("__input_{name}"))
                    .map(|(_, value)| value.clone());
            }
            if op == "let" {
                let [SemanticExpr::List(raw_bindings), body] = &items[1..] else {
                    return None;
                };
                // ⚠️ SEQUENTIAL, and lowered against `extended` rather than
                // `bindings`, so a binding may name the one above it. Against
                // the outer scope a chain of steps does not resolve and this
                // returns None -- an UNNAMED decline, so the instruction quietly
                // stops being covered by the wide executor with nothing saying
                // so. The symbolic backend is what reported it.
                let mut extended = bindings.to_vec();
                for binding in raw_bindings {
                    let SemanticExpr::List(pair) = binding else {
                        return None;
                    };
                    let [SemanticExpr::Atom(name), value] = &pair[..] else {
                        return None;
                    };
                    let value = c_wide_expr_at(value, &extended, ambient_width, address_width)?;
                    extended.push((name.clone(), value));
                }
                return c_wide_expr_at(body, &extended, ambient_width, address_width);
            }
            let mut args = &items[1..];
            let mut width = ambient_width;
            if let Some(SemanticExpr::Atom(ty)) = args.first() {
                // Shared with the typed IR: a local copy of this test is what
                // let `f64` through as a symbol when float operators arrived.
                if let Some(bits) = crate::ir::type_atom_bits(ty) {
                    width = bits;
                    args = &args[1..];
                }
            }
            let values: Vec<String> = args
                .iter()
                .map(|arg| c_wide_expr_at(arg, bindings, width, address_width))
                .collect::<Option<_>>()?;
            let binary = |token: &str| {
                Some(format!(
                    "axis_mask64(({}) {token} ({}), {width}u)",
                    values[0], values[1]
                ))
            };
            match op.as_str() {
                "add" => Some(format!(
                    "axis_mask64({}, {width}u)",
                    values
                        .iter()
                        .map(|value| format!("({value})"))
                        .collect::<Vec<_>>()
                        .join(" + ")
                )),
                "sub" => binary("-"),
                "mul" => binary("*"),
                "udiv" => Some(format!(
                    "axis_udiv64({}, {}, {width}u)",
                    values[0], values[1]
                )),
                // The float conversions. Unlike every other operator here the
                // *source* width matters as a number rather than as an
                // expression -- whether the input is a single or a double
                // decides which helper reads its bits -- so it is read off the
                // literal argument before that argument is lowered.
                "fcvt_f2s" | "fcvt_f2u" | "fcvt_s2f" | "fcvt_u2f" | "fcvt_f2f" => {
                    let source = match args.first() {
                        Some(SemanticExpr::Atom(text)) => crate::ir::integer_literal(text)? as u32,
                        _ => return None,
                    };
                    let value = &values[1];
                    Some(match op.as_str() {
                        // Through the semantics backend's own readers and
                        // writers, which take the format from the table: a
                        // copy of them here said `source > 32` and read a
                        // half as the low bits of a single.
                        "fcvt_f2s" | "fcvt_f2u" => {
                            crate::ir::float_format(source)?;
                            let as_double = super::semantics::c_float_to_double(value, source);
                            let helper = if op == "fcvt_f2s" {
                                "axis_fp_to_signed"
                            } else {
                                "axis_fp_to_unsigned"
                            };
                            format!("{helper}({as_double}, {width}u)")
                        }
                        "fcvt_s2f" | "fcvt_u2f" => {
                            // One rounding, as in the semantics lowering: the
                            // integer converts straight to the destination
                            // format rather than through a double.
                            let numeric = if op == "fcvt_s2f" {
                                format!("axis_fp_signed({value}, {source}u)")
                            } else {
                                format!("axis_fp_mask({value}, {source}u)")
                            };
                            crate::ir::float_format(width)?;
                            super::semantics::c_double_to_float(&format!("({numeric})"), width)
                        }
                        _ => {
                            crate::ir::float_format(source)?;
                            crate::ir::float_format(width)?;
                            super::semantics::c_double_to_float(
                                &super::semantics::c_float_to_double(value, source),
                                width,
                            )
                        }
                    })
                }
                // The exception forms of those conversions, read the same
                // way: the source width off the literal, the flags from the
                // helpers. The Rust executor has no arm for these and declines
                // by absence, as it does for the arithmetic exception forms.
                "fcvt_f2s_fx" | "fcvt_f2u_fx" | "fcvt_s2f_fx" | "fcvt_u2f_fx"
                | "fcvt_f2f_fx" => {
                    let source = match args.first() {
                        Some(SemanticExpr::Atom(text)) => crate::ir::integer_literal(text)? as u32,
                        _ => return None,
                    };
                    let value = &values[1];
                    Some(match op.as_str() {
                        "fcvt_f2s_fx" | "fcvt_f2u_fx" => {
                            let as_double = if source > 32 {
                                format!("axis_fp64_bits_to({value})")
                            } else {
                                format!("(double)axis_fp32_bits_to((uint32_t)({value}))")
                            };
                            let signed = if op == "fcvt_f2s_fx" { 1 } else { 0 };
                            format!("axis_fp_to_int_fx({as_double}, {width}u, {signed})")
                        }
                        "fcvt_s2f_fx" => format!(
                            "axis_fp_s2f_fx((int64_t)axis_fp_signed({value}, {source}u), {width}u)"
                        ),
                        "fcvt_u2f_fx" => {
                            format!("axis_fp_u2f_fx(axis_fp_mask({value}, {source}u), {width}u)")
                        }
                        _ => format!("axis_fp_f2f_fx({value}, {source}u, {width}u)"),
                    })
                }
                // A mask of n low bits, saturating at the width. The helper is
                // the semantics header's, so the two lowerings cannot drift.
                "ones" => Some(match values.first() {
                    Some(count) => format!("axis_ones({count}, {width}u)"),
                    None => format!("axis_ones({width}u, {width}u)"),
                }),
                "zeros" => Some("UINT64_C(0)".to_string()),
                "mulh" => Some(format!("axis_mulh64({}, {}, {width}u, 1, 1)", values[0], values[1])),
                "mulhu" => Some(format!("axis_mulh64({}, {}, {width}u, 0, 0)", values[0], values[1])),
                "mulhsu" => Some(format!("axis_mulh64({}, {}, {width}u, 1, 0)", values[0], values[1])),
                "sdiv" => Some(format!(
                    "axis_sdiv64({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "min" => Some(format!(
                    "axis_minmax64({}, {}, {width}u, 1, 0)",
                    values[0], values[1]
                )),
                "max" => Some(format!(
                    "axis_minmax64({}, {}, {width}u, 1, 1)",
                    values[0], values[1]
                )),
                "minu" => Some(format!(
                    "axis_minmax64({}, {}, {width}u, 0, 0)",
                    values[0], values[1]
                )),
                "maxu" => Some(format!(
                    "axis_minmax64({}, {}, {width}u, 0, 1)",
                    values[0], values[1]
                )),
                "and" | "or" | "xor" => {
                    let token = match op.as_str() {
                        "and" => " & ",
                        "or" => " | ",
                        _ => " ^ ",
                    };
                    Some(format!(
                        "axis_mask64({}, {width}u)",
                        values
                            .iter()
                            .map(|value| format!("({value})"))
                            .collect::<Vec<_>>()
                            .join(token)
                    ))
                }
                "not" => Some(format!("axis_mask64(~({}), {width}u)", values[0])),
                "if" | "select" => Some(format!(
                    "(({}) != 0u ? ({}) : ({}))",
                    values[0], values[1], values[2]
                )),
                "shl" | "sll" => Some(format!(
                    "axis_shl64({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "lshr" | "srl" => Some(format!(
                    "axis_lshr64({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "ashr" | "sra" => Some(format!(
                    "axis_ashr64({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "clz" => Some(format!("axis_clz64({}, {width}u)", values[0])),
                "ctz" => Some(format!("axis_ctz64({}, {width}u)", values[0])),
                "cpop" => Some(format!("axis_cpop64({}, {width}u)", values[0])),
                "rol" => Some(format!(
                    "axis_rotl64({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "ror" => Some(format!(
                    "axis_rotr64({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "sext" => Some(format!(
                    "axis_sext64({}, (uint32_t)({}), {width}u)",
                    values[1], values[0]
                )),
                "zext" => Some(format!(
                    "axis_mask64({}, (uint32_t)({}))",
                    values[1], values[0]
                )),
                // Both sides masked to the comparison's width. A signed
                // comparison masks implicitly, because sign-extending *from*
                // `width` discards everything above it; an unsigned one does
                // not, and a register holding more than the operand's width
                // then compares as the wider number. That is what an i8
                // `whilelt` did when its bound register held 16 bits: the C
                // executor said every lane active and the Python one, which
                // masks, said none. The Rust wide lowering already masked its
                // unsigned comparisons and not its equalities -- the same rule
                // written twice and wrong in different places each time.
                "icmp_eq" | "icmp_ne" | "icmp_slt" | "icmp_sge" | "icmp_ult"
                | "icmp_uge" => {
                    let (cmp, signed) = comparison_spelling(op.as_str())?;
                    let side = |value: &String| {
                        if signed {
                            format!("axis_signed64({value}, {width}u)")
                        } else {
                            format!("axis_mask64({value}, {width}u)")
                        }
                    };
                    Some(format!("(({} {cmp} {}) ? 1u : 0u)", side(&values[0]), side(&values[1])))
                }
                "a64_add_nzcv" => Some(format!(
                    "axis_a64_add_nzcv({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "a64_adc_nzcv" => Some(format!(
                    "axis_a64_adc_nzcv({}, {}, {}, {width}u)",
                    values[0], values[1], values[2]
                )),
                "a64_sbc_nzcv" => Some(format!(
                    "axis_a64_sbc_nzcv({}, {}, {}, {width}u)",
                    values[0], values[1], values[2]
                )),
                "a64_umulh" => Some(format!("axis_a64_umulh({}, {})", values[0], values[1])),
                "a64_smulh" => Some(format!("axis_a64_smulh({}, {})", values[0], values[1])),
                "a64_sub_nzcv" => Some(format!(
                    "axis_a64_sub_nzcv({}, {}, {width}u)",
                    values[0], values[1]
                )),
                "fadd" | "fsub" | "fmul" | "fdiv" | "fsqrt" | "fneg" | "fma" | "fcmp_oeq"
                | "fcmp_olt" | "fcmp_ole" | "fcmp_uno" => {
                    let name = match op.as_str() {
                        "fcmp_oeq" => "eq",
                        "fcmp_olt" => "lt",
                        "fcmp_ole" => "le",
                        "fcmp_uno" => "uno",
                        "fsqrt" => "sqrt",
                        "fneg" => "neg",
                        "fma" => "fma",
                        other => &other[1..],
                    };
                    // ⚠️ The format from the table, not `width > 32`: that
                    // guess ran every half-precision instruction in f32 and
                    // returned single-precision bits -- 0x7fc00000 where the
                    // golden model said 0x7e00 -- and nothing registered the
                    // wide executors on the f16 corpus to notice. A width the
                    // table does not describe is declined, not guessed.
                    let bits = crate::ir::float_format(width)?.bits;
                    let narrow = |value: &String| match bits {
                        16 => format!("(uint16_t)({value})"),
                        32 => format!("(uint32_t)({value})"),
                        _ => value.clone(),
                    };
                    let arguments = values
                        .iter()
                        .map(narrow)
                        .collect::<Vec<_>>()
                        .join(", ");
                    Some(format!("(uint64_t)axis_fp{bits}_{name}({arguments})"))
                }
                // Directed rounding. The mode is argument zero and the
                // helper sets and restores the floating-point environment
                // around the operation -- the same `axis_fp*_rm` helpers the
                // pure path has used since F3, which `fp_rounding.axisl`
                // proves against the golden model.
                //
                // This arm was missing, and the omission was invisible from
                // here: an instruction whose *behavior* rounds under a named
                // mode was simply declined by the wide executor. That is every
                // RISC-V FP instruction with a static or dynamic rounding mode
                // -- ninety mnemonics in each RISC-V corpus, all of them
                // effectful because they accrue `fflags` -- executed by no
                // compiled executor at all, the compact path having declined
                // them for touching state.
                "fadd_rm" | "fsub_rm" | "fmul_rm" | "fdiv_rm" | "fsqrt_rm" | "fma_rm" => {
                    // Only single and double carry directed-rounding helpers.
                    let bits = match crate::ir::float_format(width)?.bits {
                        bits @ (32 | 64) => bits,
                        _ => return None,
                    };
                    // `fma_rm` names `fma` where the others drop their leading
                    // `f`, exactly as in the `_fx` family below.
                    let name = match op.as_str() {
                        "fma_rm" => "fma",
                        other => &other[1..other.len() - 3],
                    };
                    let narrow = |value: &String| {
                        if bits == 32 {
                            format!("(uint32_t)({value})")
                        } else {
                            value.clone()
                        }
                    };
                    let mode = format!("(uint64_t)({})", values.first()?);
                    let call = format!("axis_fp{bits}_{name}_rm");
                    let body = match op.as_str() {
                        "fsqrt_rm" => format!("{call}({}, {mode})", narrow(values.get(1)?)),
                        "fma_rm" => format!(
                            "{call}({}, {}, {}, {mode})",
                            narrow(values.get(1)?),
                            narrow(values.get(2)?),
                            narrow(values.get(3)?)
                        ),
                        _ => {
                            let mut folded = narrow(values.get(1)?);
                            for rhs in values.get(2..)? {
                                folded = format!("{call}({folded}, {}, {mode})", narrow(rhs));
                            }
                            folded
                        }
                    };
                    Some(format!("(uint64_t)({body})"))
                }
                // The exceptions the same arithmetic raises. The executor
                // already includes `axis_semantics.h`, where the helper clears
                // the environment, computes, and reads `fetestexcept` -- so C
                // answers this natively where the golden model has to decide it
                // from exact rationals. Two derivations of one fact, which is
                // the point of describing the flags at all.
                //
                // The *element* width decides the helper, not the expression's:
                // an exception word is five bits wide however wide the operands
                // are, so `width` here is the flag word and would pick the
                // 32-bit helper for a pair of doubles.
                "fadd_fx" | "fsub_fx" | "fmul_fx" | "fdiv_fx" | "fsqrt_fx" | "fma_fx" => {
                    // The type atom, not the ambient width: an exception word
                    // is five bits wide however wide its operands are, so the
                    // expression's own width would pick the 32-bit helper for
                    // a pair of doubles and read the wrong flags.
                    let bits = match items.get(1) {
                        Some(SemanticExpr::Atom(atom)) if atom == "f64" => 64,
                        _ => 32,
                    };
                    // `fadd_fx` names `add` but `fma_fx` names `fma`: the
                    // helper keeps the `f` only where the operation's own name
                    // does. Stripping it uniformly asked for `axis_fp64_ma_fx`.
                    let name = match op.as_str() {
                        "fma_fx" => "fma",
                        other => &other[1..other.len() - 3],
                    };
                    let arguments = values
                        .iter()
                        .map(|value| {
                            if bits == 32 {
                                format!("(uint32_t)({value})")
                            } else {
                                value.clone()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    Some(format!("(uint64_t)axis_fp{bits}_{name}_fx({arguments})"))
                }
                "a64_logic_nzcv" => Some(format!("axis_a64_logic_nzcv({}, {width}u)", values[0])),
                "a64_cond_holds" => {
                    Some(format!("axis_a64_cond_holds({}, {})", values[0], values[1]))
                }
                "a64_shift_reg" => Some(format!(
                    "axis_a64_shift_reg({}, {}, {}, {width}u)",
                    values[0], values[1], values[2]
                )),
                "a64_extend_reg" => Some(format!(
                    "axis_a64_extend_reg({}, {}, {}, {width}u)",
                    values[0], values[1], values[2]
                )),
                "a64_wmask" => Some(format!(
                    "axis_a64_wmask({}, {}, {}, {width}u)",
                    values[0], values[1], values[2]
                )),
                "a64_ubfm" => Some(format!(
                    "axis_a64_ubfm({}, {}, {}, {width}u)",
                    values[0], values[1], values[2]
                )),
                "a64_sbfm" => Some(format!(
                    "axis_a64_sbfm({}, {}, {}, {width}u)",
                    values[0], values[1], values[2]
                )),
                "a64_bfm" => Some(format!(
                    "axis_a64_bfm({}, {}, {}, {}, {width}u)",
                    values[0], values[1], values[2], values[3]
                )),
                _ => None,
            }
        }
    }
}

/// Emit the compact simulator IR and block interpreter (`axis.sim-c.v1`): the
/// JIT on-ramp. Where `axis_exec_step` decodes, lifts, and classifies operand
/// roles on every executed instruction, the sim IR does that work **once** at
/// block-build time (`axis_block_build`) and stores a pre-resolved `axis_op`, so
/// the run loop (`axis_block_run`) has no per-step decode, lift-table scan, or
/// role/kind `strcmp` — just a direct call into the proven `axis_exec_eval` /
/// `axis_exec_apply` handlers. This is the "compact IR + interpreter + block
/// formation" step of the JIT plan; the pre-decoded op is exactly the unit a
/// later LLVM/Cranelift lowering would compile. Depends on `axis_exec.h` (and so
/// on the same lifter/semantics), inheriting its proven behavior.
pub fn emit_sim_c(document: &Document) -> String {
    let guard = format!(
        "AXIS_{}_SIM_H",
        tablegen_ident(&document.extension.name).to_ascii_uppercase()
    );
    let mut out = String::new();
    out.push_str(
        "/* Generated by AXIS. Compact simulator IR + block interpreter (JIT on-ramp). */\n",
    );
    out.push_str("/* schema: axis.sim-c.v1 */\n");
    out.push_str(&format!("#ifndef {guard}\n#define {guard}\n\n"));
    out.push_str("#include <stdint.h>\n#include <stddef.h>\n#include <string.h>\n");
    out.push_str("#include \"axis_exec.h\"\n\n");
    out.push_str("#ifdef __cplusplus\nextern \"C\" {\n#endif\n\n");

    // The register file the document needs, not the 32 an integer ISA has: a
    // scalable register spans VL/64 slots, and a file above it starts where it
    // ends.
    out.push_str(&format!(
        "/* Slots this document's register files need. */\n#define AXIS_SIM_REG_SLOTS {}\n",
        crate::ast::register_file_slots(document)
    ));
    // A trace record is fixed-size, so its bounds come from the document: the
    // most operands any instruction reads, and the most accesses any one makes.
    out.push_str(&format!(
        "/* The widest instruction in this document, so a trace record is fixed. */\n#define AXIS_SIM_MAX_READS {}\n#define AXIS_SIM_MAX_ACCESSES {}\n\n",
        {
            // ⚠️ Per *word*, for the same reason the accesses bound below is:
            // a scalable instruction retires once and touches a register per
            // lane, so the bound is the whole group's. Taken from one entry it
            // was 2 for `scalable_vtype`, and `VNSRA_WV` -- which narrows, so
            // each source spans a register pair over four lanes -- recorded
            // two of its four reads and said nothing. The accesses bound was
            // fixed this way and the register bound was left behind.
            let mut per_word: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for instruction in &document.instructions {
                let key = if instruction.scalable_origin.is_empty() {
                    instruction.mnemonic.as_str()
                } else {
                    instruction.scalable_origin.as_str()
                };
                let reads = instruction
                    .operands
                    .iter()
                    .filter(|operand| operand.input)
                    .count();
                let writes = instruction
                    .operands
                    .iter()
                    .filter(|operand| operand.output)
                    .count();
                *per_word.entry(key).or_insert(0) += reads.max(writes);
            }
            per_word.values().copied().max().unwrap_or(1).max(1)
        },
        {
            // Per *word*, not per entry. A scalable instruction retires once
            // and makes an access per lane, so the bound is the whole group's
            // effects -- a bound taken from one entry truncated a sixteen-lane
            // load to its first two accesses, and the trace said so.
            let mut per_word: std::collections::BTreeMap<&str, usize> =
                std::collections::BTreeMap::new();
            for instruction in &document.instructions {
                let key = if instruction.scalable_origin.is_empty() {
                    instruction.mnemonic.as_str()
                } else {
                    instruction.scalable_origin.as_str()
                };
                let effects = instruction
                    .behavior
                    .as_ref()
                    .map(|behavior| {
                        behavior.effects.iter().map(|effect| effect.memory_accesses()).sum()
                    })
                    .unwrap_or(0);
                *per_word.entry(key).or_insert(0) += effects;
            }
            per_word.values().copied().max().unwrap_or(1).max(1)
        },
    ));
    out.push_str(SIM_C_RUNTIME);

    out.push_str("#ifdef __cplusplus\n}\n#endif\n\n");
    out.push_str(&format!("#endif /* {guard} */\n"));
    out
}

/// The document-independent body of `axis_sim.h`: it is generic over the
/// co-emitted lifter/executor (via `axis_exec.h`), so only the include guard
/// varies per extension.
/// The document-independent body of `axis_sim.h`: a machine loop over the
/// generated wide executor, with a hook table for everything the host owns.
/// Generic over the co-emitted executor, so only the include guard varies.
const SIM_C_RUNTIME: &str = r##"/* What one instruction did, handed to the retire hook. Enough to trace, count
 * or single-step without the loop knowing why anyone is watching. */
/* One memory access an instruction made, in the order it made them. Recorded
   by wrapping the host's own hooks rather than by reaching into the executor:
   the effect handlers already go through that pair, so a wrapper sees every
   access with no change to what is proven. */
typedef struct axis_sim_access {
  uint64_t addr;
  uint64_t value;
  uint32_t width;
  int is_write;
  /* A value wider than the word, as limbs, low first. `value` stays the low
     one. `limbs` is 0 for an ordinary access, which is every access a machine
     whose widest register is one word ever makes. */
  uint64_t limb[AXIS_EXEC_MAX_LIMBS];
  uint32_t limbs;
} axis_sim_access;

typedef struct axis_sim_event {
  uint64_t pc;                  /* where it was fetched from */
  uint32_t word;                /* the word itself */
  const char *mnemonic;         /* NULL when it did not decode */
  int ok;                       /* the executor ran it */
  int wrote;                    /* it wrote a register */
  uint32_t dest;                /* which register number, when it did */
  uint32_t write_slot;          /* and which file-qualified slot that is */
  uint64_t result;              /* the value, when it did */
  uint64_t result_limb[AXIS_EXEC_MAX_LIMBS];  /* wider than a word, low first */
  uint32_t result_limbs;        /* 0 for an ordinary one-word value */
  const char *trap_cause;       /* NULL unless it trapped */
  uint64_t next_pc;             /* where the machine goes next */
  /* What a timing model needs and a functional one does not: which register
     slots were read, so it can find the dependence, and which memory it
     touched, so it can model the queues. Neither is a semantic fact -- the
     executor's answer is the same either way -- which is why they live on the
     event rather than in the result. */
  uint32_t reads[AXIS_SIM_MAX_READS];
  int read_count;
  uint32_t writes[AXIS_SIM_MAX_READS];
  int write_count;
  axis_sim_access accesses[AXIS_SIM_MAX_ACCESSES];
  int access_count;
} axis_sim_event;

/* Everything the host owns. Memory is the pair the executor already takes,
 * because instruction semantics do their own accesses through it. Fetch is
 * separate from read: an instruction fetch is not a data access, and a host may
 * serve it from another space or refuse it. Trap decides what a raised trap
 * does, which is the difference between a machine and a harness. Retire is how
 * the machine is observed. */
typedef struct axis_sim_hooks {
  uint64_t (*read)(void *ctx, uint64_t addr, uint32_t width);
  void (*write)(void *ctx, uint64_t addr, uint64_t value, uint32_t width);
  uint32_t (*fetch)(void *ctx, uint64_t pc, int *ok);
  uint64_t (*trap)(void *ctx, const char *cause, uint64_t pc, int *stop);
  void (*retire)(void *ctx, const axis_sim_event *event);
  void *ctx;
} axis_sim_hooks;

typedef enum axis_sim_status {
  AXIS_SIM_RUNNING = 0,
  AXIS_SIM_HALTED,              /* the host's fetch or trap hook said stop */
  AXIS_SIM_UNDECODED,           /* the word decodes to nothing */
  AXIS_SIM_UNSUPPORTED,         /* it decodes, and this build cannot run it */
  AXIS_SIM_STEP_LIMIT
} axis_sim_status;

/* ⚠️ WHAT A WORD DECODES TO IS A FACT ABOUT THE WORD. The lift table is
 * constant and the constraints read only the word, so the entry, its lanes and
 * the registers it touches are the same every time the same word is stepped --
 * and a loop steps the same words millions of times, each a scan of the whole
 * table (two for the executor, one for the touches, one for a timing model's
 * lift). A memo answers each from the first time. Direct-mapped by word,
 * keyed by the isa pointer it was filled under; a host that changes what that
 * pointer says calls axis_sim_memo_clear. Owned by the host, never by the
 * simulator. */
#define AXIS_SIM_MEMO_BITS 10u
#define AXIS_SIM_MEMO_LINES (1u << AXIS_SIM_MEMO_BITS)
typedef struct axis_sim_memo_line {
  uint32_t word;
  uint8_t has_exec, has_touch, has_lift, lift_ok;
  const axis_lift_entry *first;
  int lanes;
  int read_count, write_count;
  uint32_t reads[AXIS_SIM_MAX_READS];
  uint32_t writes[AXIS_SIM_MAX_READS];
  axis_lifted lifted;
} axis_sim_memo_line;
typedef struct axis_sim_memo {
  const char *isa;
  axis_sim_memo_line line[AXIS_SIM_MEMO_LINES];
} axis_sim_memo;
static inline void axis_sim_memo_clear(axis_sim_memo *memo) {
  if (memo) { memset(memo, 0, sizeof *memo); }
}

/* The machine. Registers, architectural state and the pc; everything else is
 * behind a hook. The register file is sized by the generated lifter rather than
 * by the host, because a scalable register spans several slots. */
typedef struct axis_sim {
  uint64_t regs[AXIS_SIM_REG_SLOTS];
  axis_state64 state;
  uint64_t pc;
  const char *isa;              /* narrows decode; NULL for a single-ISA document; several names, space-separated, are tried in order (axis_sim_word_isa) */
  axis_sim_hooks hooks;
  uint64_t steps;
  axis_sim_status status;
  const char *halt_reason;
  /* Optional, and last so a host that never sets it is the host it was:
     decoding memoised by word (see axis_sim_memo). NULL decodes every step. */
  struct axis_sim_memo *memo;
} axis_sim;

static inline void axis_sim_init(axis_sim *sim, const axis_sim_hooks *hooks,
                                 axis_state64_entry *state, size_t state_count) {
  memset(sim, 0, sizeof *sim);
  sim->hooks = *hooks;
  sim->state.entries = state;
  sim->state.count = state_count;
  sim->status = AXIS_SIM_RUNNING;
}

/* One instruction: fetch, execute every lane of the word, follow the pc.
 *
 * The executor has already written registers, memory and state by the time it
 * returns -- the simulator's own state is the pc, the step count and why it
 * stopped. Everything hard is in the executor, which is proven; everything
 * host-specific is behind a hook. */
/* The wrapper that records accesses. The host's own hooks are called through
   it, so what the executor sees is unchanged and what the trace sees is
   everything. */
typedef struct axis_sim_tap {
  axis_sim_hooks *hooks;
  axis_sim_event *event;
} axis_sim_tap;

static inline void axis_sim_record(axis_sim_tap *tap, uint64_t addr,
                                   uint64_t value, uint32_t width, int is_write) {
  if (tap->event->access_count >= AXIS_SIM_MAX_ACCESSES) { return; }
  axis_sim_access *access = &tap->event->accesses[tap->event->access_count++];
  access->addr = addr; access->value = value;
  access->width = width; access->is_write = is_write;
  access->limbs = 0;
}

/* ⚠️ One access, not `limbs` of them. The executor's memory interface is a
   word wide, so a 128-bit load is two host reads -- but the instruction made
   ONE architectural access, and that is what a trace of it should say. The
   split belongs to this machine's bus, not to the program. Without this the
   simulator recorded two 64-bit reads where the reference recorded one 128-bit
   read, which is a disagreement about bookkeeping rather than about bytes. */
static inline void axis_sim_tap_read_limbs(void *ctx, uint64_t addr,
                                           uint32_t width, uint64_t *out,
                                           uint32_t limbs) {
  axis_sim_tap *tap = (axis_sim_tap *)ctx;
  for (uint32_t i = 0; i < limbs; ++i) {
    uint32_t rest = width - i * 64u, take = rest >= 64u ? 64u : rest;
    out[i] = tap->hooks->read
        ? tap->hooks->read(tap->hooks->ctx, addr + (uint64_t)i * 8u, take) : 0;
  }
  if (tap->event->access_count >= AXIS_SIM_MAX_ACCESSES) { return; }
  axis_sim_access *access = &tap->event->accesses[tap->event->access_count++];
  access->addr = addr; access->value = out[0];
  access->width = width; access->is_write = 0; access->limbs = limbs;
  for (uint32_t i = 0; i < limbs; ++i) { access->limb[i] = out[i]; }
}

static inline void axis_sim_tap_write_limbs(void *ctx, uint64_t addr,
                                            uint32_t width, const uint64_t *in,
                                            uint32_t limbs) {
  axis_sim_tap *tap = (axis_sim_tap *)ctx;
  for (uint32_t i = 0; i < limbs; ++i) {
    uint32_t rest = width - i * 64u, take = rest >= 64u ? 64u : rest;
    if (tap->hooks->write) {
      tap->hooks->write(tap->hooks->ctx, addr + (uint64_t)i * 8u, in[i], take);
    }
  }
  if (tap->event->access_count >= AXIS_SIM_MAX_ACCESSES) { return; }
  axis_sim_access *access = &tap->event->accesses[tap->event->access_count++];
  access->addr = addr; access->value = in[0];
  access->width = width; access->is_write = 1; access->limbs = limbs;
  for (uint32_t i = 0; i < limbs; ++i) { access->limb[i] = in[i]; }
}

static inline uint64_t axis_sim_tap_read(void *ctx, uint64_t addr, uint32_t width) {
  axis_sim_tap *tap = (axis_sim_tap *)ctx;
  uint64_t value = tap->hooks->read ? tap->hooks->read(tap->hooks->ctx, addr, width) : 0;
  axis_sim_record(tap, addr, value, width, 0);
  return value;
}

static inline void axis_sim_tap_write(void *ctx, uint64_t addr, uint64_t value,
                                      uint32_t width) {
  axis_sim_tap *tap = (axis_sim_tap *)ctx;
  if (tap->hooks->write) { tap->hooks->write(tap->hooks->ctx, addr, value, width); }
  axis_sim_record(tap, addr, value, width, 1);
}

/* ⚠️ Returns whether it FIT. The record is fixed-size, and one that silently
   dropped a register reported a smaller dependence set than the instruction
   has -- which is what a consumer reasoning about dependences would believe.
   The bound is computed per word so this should not fire; saying so when it
   does is how the next description that outgrows it is found. */
static inline int axis_sim_note(uint32_t *slots, int *count, int limit,
                                uint32_t slot) {
  for (int i = 0; i < *count; ++i) { if (slots[i] == slot) { return 1; } }
  if (*count < limit) { slots[(*count)++] = slot; return 1; }
  return 0;
}

/* Which registers this word reads and writes. Derived from the same decode the
   executor does rather than reported by it: which registers an instruction
   touches is a fact about the instruction, not about what running it produced.

   Every lane of a scalable word, not just the first. A widening multiply writes
   a register *group* -- lane 8's destination is a register past lane 0's -- and
   a dependence on the second half of that group is a dependence. Reporting one
   destination named whichever lane happened to run last. */
static inline void axis_sim_touches(uint32_t word, const char *isa,
                                    axis_sim_event *event) {
  for (size_t k = 0; k < AXIS_LIFT_TABLE_LEN; ++k) {
    const axis_lift_entry *entry = &AXIS_LIFT_TABLE[k];
    if ((word & entry->mask) != entry->match) { continue; }
    if (entry->definedness) { continue; }
    if (isa && entry->isa[0] && strcmp(entry->isa, isa) != 0) { continue; }
    if (!axis_lift_constraint_ok(word, entry)) { continue; }
    axis_lifted lifted;
    if (!axis_lift_entry_operands(word, entry, &lifted)) { continue; }
    for (int i = 0; i < entry->operand_count; ++i) {
      const axis_lift_operand *op = &entry->operands[i];
      if (!axis_op_class(op)) { continue; }
      uint32_t slot = axis_operand_slot(op, lifted.operands[i]);
      if ((op->role_code == AXIS_ROLE_IN) || (op->role_code == AXIS_ROLE_INOUT)) {
        axis_sim_note(event->reads, &event->read_count, AXIS_SIM_MAX_READS, slot);
      }
      if ((op->role_code == AXIS_ROLE_OUT) || (op->role_code == AXIS_ROLE_INOUT)) {
        axis_sim_note(event->writes, &event->write_count, AXIS_SIM_MAX_READS, slot);
      }
    }
  }
}

static inline axis_sim_memo_line *axis_sim_memo_at(axis_sim *sim, uint32_t word) {
  axis_sim_memo *memo = sim->memo;
  if (memo->isa != sim->isa) { axis_sim_memo_clear(memo); memo->isa = sim->isa; }
  axis_sim_memo_line *line = &memo->line[(uint32_t)(word * 2654435761u) >> (32u - AXIS_SIM_MEMO_BITS)];
  if (line->word != word) { line->word = word; line->has_exec = line->has_touch = line->has_lift = 0; }
  return line;
}
/* ⚠️ AN ORDERED LIST OF ISAS (U4c). `isa` may name several, separated by
   spaces -- "a64_simt aarch64_base" -- and a word is in the FIRST of them
   that decodes it, as a SIMT core's `(isas ...)` says. NULL is not the same
   thing: every ISA at once, where a word two of them decode is ambiguous
   and decodes to nothing (the AArch64 seed's accelerator ISA matches BL,
   SEV and NOP). A single name is returned as it is. */
static inline const char *axis_sim_word_isa(const axis_sim *sim, uint32_t word) {
  const char *isa = sim->isa;
  if (!isa || !strchr(isa, ' ')) { return isa; }
  char name[64];
  for (const char *p = isa; *p;) {
    while (*p == ' ') { ++p; }
    size_t n = strcspn(p, " ");
    if (!n) { break; }
    if (n < sizeof name) {
      memcpy(name, p, n);
      name[n] = 0;
      int lanes = 0;
      const axis_lift_entry *e = axis_exec_decode64(word, name, &lanes);
      if (e && e->isa[0]) { return e->isa; }
    }
    p += n;
  }
  return isa;  /* in none of them: a name no entry has, so nothing decodes */
}
/* The executor's decode of a word: its first entry and how many lanes. */
static inline const axis_lift_entry *axis_sim_exec_decode(axis_sim *sim, uint32_t word, int *lanes) {
  if (!sim->memo) { return axis_exec_decode64(word, axis_sim_word_isa(sim, word), lanes); }
  axis_sim_memo_line *line = axis_sim_memo_at(sim, word);
  if (!line->has_exec) { line->first = axis_exec_decode64(word, axis_sim_word_isa(sim, word), &line->lanes); line->has_exec = 1; }
  *lanes = line->lanes;
  return line->first;
}
/* The registers it touches, into an event. */
static inline void axis_sim_touches_of(axis_sim *sim, uint32_t word, axis_sim_event *event) {
  if (!sim->memo) { axis_sim_touches(word, axis_sim_word_isa(sim, word), event); return; }
  axis_sim_memo_line *line = axis_sim_memo_at(sim, word);
  if (!line->has_touch) {
    axis_sim_event probe;
    probe.read_count = 0;
    probe.write_count = 0;
    axis_sim_touches(word, axis_sim_word_isa(sim, word), &probe);
    line->read_count = probe.read_count;
    line->write_count = probe.write_count;
    memcpy(line->reads, probe.reads, sizeof line->reads);
    memcpy(line->writes, probe.writes, sizeof line->writes);
    line->has_touch = 1;
  }
  for (int i = 0; i < line->read_count; ++i) { axis_sim_note(event->reads, &event->read_count, AXIS_SIM_MAX_READS, line->reads[i]); }
  for (int i = 0; i < line->write_count; ++i) { axis_sim_note(event->writes, &event->write_count, AXIS_SIM_MAX_READS, line->writes[i]); }
}
/* axis_lift_in_isa in the simulator's isa. */
static inline int axis_sim_lift(axis_sim *sim, uint32_t word, axis_lifted *out) {
  if (!sim->memo) { return axis_lift_in_isa(word, axis_sim_word_isa(sim, word), out); }
  axis_sim_memo_line *line = axis_sim_memo_at(sim, word);
  if (!line->has_lift) { line->lift_ok = (uint8_t)(axis_lift_in_isa(word, axis_sim_word_isa(sim, word), &line->lifted) != 0); line->has_lift = 1; }
  *out = line->lifted;
  return line->lift_ok;
}

static inline axis_sim_status axis_sim_step(axis_sim *sim) {
  if (sim->status != AXIS_SIM_RUNNING) { return sim->status; }
  int ok = 1;
  uint64_t at = sim->pc;
  uint32_t word = sim->hooks.fetch ? sim->hooks.fetch(sim->hooks.ctx, at, &ok) : 0u;
  if (!sim->hooks.fetch || !ok) {
    sim->status = AXIS_SIM_HALTED;
    sim->halt_reason = "fetch";
    return sim->status;
  }
  axis_sim_event event;
  memset(&event, 0, sizeof event);
  event.pc = at;
  event.word = word;
  axis_sim_touches_of(sim, word, &event);
  axis_sim_tap tap = { &sim->hooks, &event };
  axis_mem64 mem = { axis_sim_tap_read, axis_sim_tap_write, &tap,
                     axis_sim_tap_read_limbs, axis_sim_tap_write_limbs };
  int lanes = 0;
  const axis_lift_entry *first = axis_sim_exec_decode(sim, word, &lanes);
  axis_exec_result64 r = axis_exec_step64_decoded(first, lanes, word, axis_sim_word_isa(sim, word), sim->regs,
                                                  AXIS_SIM_REG_SLOTS, &mem, at, &sim->state);
  event.mnemonic = r.mnemonic;
  event.ok = r.ok;
  event.wrote = r.wrote;
  event.dest = r.dest;
  event.write_slot = r.dest_slot;
  event.result = r.result;
  event.result_limbs = r.result_limbs;
  for (uint32_t i = 0; i < r.result_limbs && i < AXIS_EXEC_MAX_LIMBS; ++i) {
    event.result_limb[i] = r.result_limb[i];
  }
  event.trap_cause = r.trapped ? r.trap_cause : NULL;
  event.next_pc = r.next_pc;
  if (!r.ok && !r.trapped) {
    /* Two different things, and a host needs to tell them apart. A word that
       decodes to nothing is a hole in the program; a word that decodes and
       cannot be evaluated is a hole in this *build* -- the directed
       rounding-mode forms have no 64-bit C evaluator, which
       docs/simd_fp_design.md records. Neither is a trap the description raised,
       so neither is handed to the trap hook with a cause nothing named. */
    sim->status = r.mnemonic ? AXIS_SIM_UNSUPPORTED : AXIS_SIM_UNDECODED;
    sim->halt_reason = r.mnemonic ? "unsupported" : "undecoded";
    if (sim->hooks.retire) { sim->hooks.retire(sim->hooks.ctx, &event); }
    return sim->status;
  }
  sim->pc = r.next_pc;
  if (r.trapped) {
    int stop = 1;
    uint64_t resume = sim->hooks.trap
      ? sim->hooks.trap(sim->hooks.ctx, r.trap_cause, at, &stop)
      : at;
    /* No trap hook means a trap halts, which is the honest default: the
       description says a trap happened and nothing has said what to do. */
    if (stop) {
      sim->status = AXIS_SIM_HALTED;
      sim->halt_reason = r.trap_cause;
    } else {
      sim->pc = resume;
      event.next_pc = resume;
    }
  }
  sim->steps++;
  if (sim->hooks.retire) { sim->hooks.retire(sim->hooks.ctx, &event); }
  return sim->status;
}

/* One retired instruction as a line of `axis.trace.v1`.
 *
 * Emitted here rather than left to the host because a trace whose format each
 * consumer invents is a trace no two of them can compare. The fields are what a
 * timing model consumes: where the instruction was, what it was, which slots it
 * read, which it wrote, what memory it touched, and where the machine went.
 *
 *   <pc> <word> <mnemonic> r=<slot>[,<slot>] w=<slot>:<value>
 *   m=<r|w>:<addr>:<width>:<value>[ ...] n=<next_pc>[ t=<cause>]
 *
 * Absent fields are omitted rather than emitted empty, so a line says only what
 * happened. Returns the length written, or the length it would have needed.
 */
/* A wide value as one hexadecimal number. ⚠️ Leading zero limbs are skipped:
   printing every limb padded turns zero into sixteen zeros per limb, which is
   a different string from "0" and was the last disagreement between this and
   the reference -- about formatting, after the bytes already matched. */
static inline int axis_sim_hex_wide(char *out, size_t size, int n,
                                    const uint64_t *limb, uint32_t limbs) {
  uint32_t top = 0;
  for (uint32_t i = 0; i < limbs; ++i) { if (limb[i]) { top = i; } }
  n += snprintf(out + n, n < (int)size ? size - n : 0, "%llx",
                (unsigned long long)limb[top]);
  for (uint32_t i = top; i-- > 0;) {
    n += snprintf(out + n, n < (int)size ? size - n : 0, "%016llx",
                  (unsigned long long)limb[i]);
  }
  return n;
}

static inline int axis_sim_trace_line(const axis_sim_event *event, char *out,
                                      size_t size) {
  int n = snprintf(out, size, "%llx %08x %s",
                   (unsigned long long)event->pc, event->word,
                   event->mnemonic ? event->mnemonic : "?");
  for (int i = 0; i < event->read_count; ++i) {
    n += snprintf(out + n, n < (int)size ? size - n : 0, "%s%x",
                  i ? "," : " r=", event->reads[i]);
  }
  for (int i = 0; i < event->write_count; ++i) {
    n += snprintf(out + n, n < (int)size ? size - n : 0, "%s%x",
                  i ? "," : " w=", event->writes[i]);
  }
  if (event->wrote) {
    /* A value wider than the word is printed whole, high limb first, so the
       text reads as one number -- which is what it is. `result` alone would
       print the low half and call it the answer. */
    n += snprintf(out + n, n < (int)size ? size - n : 0, " v=");
    if (event->result_limbs > 1u) {
      n = axis_sim_hex_wide(out, size, n, event->result_limb, event->result_limbs);
    } else {
      n += snprintf(out + n, n < (int)size ? size - n : 0, "%llx",
                    (unsigned long long)event->result);
    }
  }
  for (int i = 0; i < event->access_count; ++i) {
    const axis_sim_access *access = &event->accesses[i];
    n += snprintf(out + n, n < (int)size ? size - n : 0, " m=%c:%llx:%u:",
                  access->is_write ? 'w' : 'r',
                  (unsigned long long)access->addr, access->width);
    if (access->limbs > 1u) {
      n = axis_sim_hex_wide(out, size, n, access->limb, access->limbs);
    } else {
      n += snprintf(out + n, n < (int)size ? size - n : 0, "%llx",
                    (unsigned long long)access->value);
    }
  }
  n += snprintf(out + n, n < (int)size ? size - n : 0, " n=%llx",
                (unsigned long long)event->next_pc);
  if (event->trap_cause) {
    n += snprintf(out + n, n < (int)size ? size - n : 0, " t=%s",
                  event->trap_cause);
  }
  return n;
}

/* Step until something stops it, or until `limit` instructions have retired.
 * A zero limit runs until the machine stops on its own. */
static inline axis_sim_status axis_sim_run(axis_sim *sim, uint64_t limit) {
  while (sim->status == AXIS_SIM_RUNNING) {
    if (limit && sim->steps >= limit) {
      sim->status = AXIS_SIM_STEP_LIMIT;
      sim->halt_reason = "step limit";
      break;
    }
    axis_sim_step(sim);
  }
  return sim->status;
}
"##;

/// Generate the C effect function for an instruction with effects (E1-E4), or
/// `None` for pure instructions (and effects C cannot express: operands wider
/// than 32 bits, or a value/guard subexpression that does not lower). The
/// function runs the effect list in order against `regs`/`mem`/`pc`, honoring
/// per-effect guards, and fills the `axis_exec_result`: register writes (set),
/// memory writes (store), `next_pc` (setpc), and `trapped`/`trap_cause` (trap).
/// The compiled sibling of the Python interpreter's effect loop; pure
/// address/value subexpressions reuse `c_lower`, guards lower to `==`/`!=`.
fn emit_c_effect_fn(instruction: &Instruction, state_names: &[String]) -> Option<String> {
    if !crate::effects::behavior_is_authoritative(instruction) {
        return None;
    }
    let behavior = instruction.behavior.as_ref()?;
    // The compact 32-bit ABI predates named architectural state. State-reading
    // behaviors are handled by the wide ABI, whose effect functions receive an
    // `axis_state64`; emitting them here would leave the state atom unbound.
    if behavior_reads_state(behavior, state_names) {
        return None;
    }
    if instruction
        .operands
        .iter()
        .any(|operand| operand.width > 32)
    {
        return None;
    }
    let ident = tablegen_ident(&instruction.mnemonic);

    // Bind each input operand value by its (C-valid) name: register operands
    // dereference `regs[index]`, immediates use their decoded value. `pc` is a
    // parameter already in scope for effect expressions.
    let mut body = String::new();
    for (pos, operand) in instruction.operands.iter().enumerate() {
        // Output register operands are bound too, to their value on entry, and a
        // `set` assigns to the binding afterwards. That is what lets a later
        // effect read what an earlier one wrote: RISC-V's atomic
        // read-modify-writes store a function of the value they just loaded into
        // rd. The LLVM lowering threads the same dependency through its rename
        // map; this is the compact ABI's version of it.
        if operand.output && !crate::ast::is_register_kind(&operand.kind) {
            continue;
        }
        if crate::ast::is_register_kind(&operand.kind) {
            // The offset is what puts a second register file above the first:
            // RISC-V's f5 is slot 37. Binding without it reads the integer
            // register of the same number.
            let class = crate::ast::register_class(&operand.kind);
            let offset = class.map(|class| class.offset).unwrap_or(0);
            let limbs = class.map(|class| class.limbs.max(1)).unwrap_or(1);
            body.push_str(&format!(
                "  uint32_t {name}_i = lifted->operands[{pos}] * {limbs}u + {offset}u;\n  uint32_t {name} = {name}_i < reg_count ? regs[{name}_i] : 0u;\n  (void){name};\n",
                name = operand.name
            ));
        } else {
            body.push_str(&format!(
                "  uint32_t {name} = lifted->operands[{pos}];\n  (void){name};\n",
                name = operand.name
            ));
        }
    }

    // Each effect, optionally wrapped in its guard.
    for effect in &behavior.effects {
        let inner = emit_c_effect_body(instruction, effect)?;
        match &effect.guard {
            Some(guard) => {
                let cond = c_guard_expr(&guard.expr, guard.width)?;
                body.push_str(&format!("  if ({cond}) {{\n{inner}  }}\n"));
            }
            None => body.push_str(&inner),
        }
    }

    Some(format!(
        "static inline void axis_exec_eff_{ident}(const axis_lifted *lifted, uint32_t *regs, size_t reg_count, const axis_mem *mem, uint32_t pc, axis_exec_result *r) {{\n  (void)lifted; (void)regs; (void)reg_count; (void)mem; (void)pc;\n{body}}}\n\n"
    ))
}

/// Emit the C statements for one (unguarded) effect. Loads inside a `set` are
/// peeled to a `mem->read` + extend; other values/addresses lower via `c_lower`.
fn emit_c_effect_body(
    instruction: &Instruction,
    effect: &crate::effects::Effect,
) -> Option<String> {
    use crate::effects::Loc;
    match &effect.loc {
        // Fixed architectural registers need a persistent state store and
        // remain on the wide ABI. Named-state writes are returned as an
        // architectural delta, like the wide result's state_name/state_value.
        Loc::FixedReg { .. } => None,
        Loc::State { name, width } => {
            let value = c_effect_expr(&effect.value.expr, effect.value.width)?;
            Some(format!(
                "  {{ r->state_name = {}; r->state_value = axis_sem_mask({value}, {width}u); }}\n",
                c_string(name),
            ))
        }
        Loc::Reg(dest) => {
            let dp = instruction.operands.iter().position(|o| &o.name == dest)?;
            let dest_class = instruction
                .operands
                .iter()
                .find(|o| &o.name == dest)
                .and_then(|o| crate::ast::register_class(&o.kind));
            let dest_offset = dest_class.map(|class| class.offset).unwrap_or(0);
            let dest_limbs = dest_class.map(|class| class.limbs.max(1)).unwrap_or(1);
            let out_width = instruction
                .operands
                .iter()
                .find(|o| &o.name == dest)
                .map(|o| o.width)
                .unwrap_or(32);
            // A register set whose value is `(load iW sign addr)` is peeled into
            // a memory read plus sign/zero extend; otherwise a pure expression.
            let value_lines = match &effect.value.expr {
                SemanticExpr::List(items)
                    if matches!(&items[0], SemanticExpr::Atom(a) if matches!(a.as_str(), "load" | "atomic_load"))
                        && matches!(items.len(), 4 | 5) =>
                {
                    let access = load_access_width(&items[1])?;
                    let signed = matches!(&items[2], SemanticExpr::Atom(a) if a == "signed");
                    let addr_c = c_effect_expr(items.last()?, effect.value.load_address_width?)?;
                    let helper = if signed {
                        "axis_sem_sext"
                    } else {
                        "axis_sem_zext"
                    };
                    format!(
                        "    uint32_t _addr = {addr_c};\n    uint32_t _raw = mem ? mem->read(mem->ctx, _addr, {access}u) : 0u;\n    uint32_t _v = {helper}(_raw, {access}u, {out_width}u);\n"
                    )
                }
                _ => format!(
                    "    uint32_t _v = {};\n",
                    c_effect_expr(&effect.value.expr, effect.value.width)?
                ),
            };
            Some(format!(
                "  {{\n{value_lines}    uint32_t _di = lifted->operands[{dp}] * {dest_limbs}u + {dest_offset}u;\n    if (_di < reg_count) {{ regs[_di] = _v; }}\n    {dest} = _v;\n    r->wrote = 1; r->dest = _di; r->result = _v;\n  }}\n"
            ))
        }
        Loc::Mem { addr, width, .. } => {
            let addr_c = c_effect_expr(&addr.expr, addr.width)?;
            // A stored value may itself be a load -- that is what a block copy
            // is. Peeled here for the same reason it is peeled for a register
            // destination: `c_effect_expr` is shared with the pure evaluator,
            // which has no memory to read. Having the case in the register arm
            // alone is why every copy declined and only the fill was emitted.
            let value_c = match &effect.value.expr {
                SemanticExpr::List(items)
                    if matches!(&items[0], SemanticExpr::Atom(a)
                        if matches!(a.as_str(), "load" | "atomic_load"))
                        && matches!(items.len(), 4 | 5) =>
                {
                    let access = load_access_width(&items[1])?;
                    let signed = matches!(&items[2], SemanticExpr::Atom(a) if a == "signed");
                    let load_addr = c_effect_expr(items.last()?, effect.value.load_address_width?)?;
                    let helper = if signed { "axis_sem_sext" } else { "axis_sem_zext" };
                    format!(
                        "{helper}(mem ? mem->read(mem->ctx, {load_addr}, {access}u) : 0u, {access}u, {width}u)"
                    )
                }
                _ => c_effect_expr(&effect.value.expr, effect.value.width)?,
            };
            Some(format!(
                "  {{\n    uint32_t _addr = {addr_c};\n    uint32_t _val = {value_c};\n    if (mem) {{ mem->write(mem->ctx, _addr, _val, {width}u); }}\n  }}\n"
            ))
        }
        // ⚠️ The narrow executor is the 32-bit path, and a channel is a
        // machine-wide thing: `None` here, which is how this emitter says an
        // instruction is not for it, so the wide executor takes it and the
        // narrow one reports no answer rather than a partial one.
        Loc::Port { .. } => None,
        Loc::Barrier { .. } => Some(format!(
            "  {{ uint32_t _barrier_option = {}; (void)_barrier_option; }}\n",
            c_effect_expr(&effect.value.expr, effect.value.width)?
        )),
        Loc::Pc => Some(format!(
            "  {{ r->next_pc = {}; }}\n",
            c_effect_expr(&effect.value.expr, effect.value.width)?
        )),
        Loc::Trap => Some(format!(
            "  {{ r->trapped = 1; r->trap_cause = {}; return; }}\n",
            c_string(&crate::effects::render_semexpr(&effect.value.expr))
        )),
    }
}

/// Lower a pure effect subexpression (value/address) to a C expression via the
/// shared semantics lowering. `width` bounds the result's bit width.
fn c_effect_expr(expr: &SemanticExpr, width: u32) -> Option<String> {
    Some(super::semantics::c_lower(&lower(expr, width).ok()?))
}

/// Lower a boolean guard tree to a C expression. Guards are the only place
/// `icmp` appears; the pure IR has no comparison op.
fn c_guard_expr(guard: &SemanticExpr, width: u32) -> Option<String> {
    let SemanticExpr::List(items) = guard else {
        return None;
    };
    let SemanticExpr::Atom(op) = &items[0] else {
        return None;
    };
    if matches!(op.as_str(), "and" | "or") && items.len() >= 3 {
        let joiner = if op == "and" { " && " } else { " || " };
        return Some(format!(
            "({})",
            items[1..]
                .iter()
                .map(|child| c_guard_expr(child, width))
                .collect::<Option<Vec<_>>>()?
                .join(joiner)
        ));
    }
    if op == "not" && items.len() == 2 {
        return Some(format!("!({})", c_guard_expr(&items[1], width)?));
    }
    if items.len() != 3 {
        return None;
    }
    let (cmp, signed) = match op.as_str() {
        "icmp_eq" => ("==", false),
        "icmp_ne" => ("!=", false),
        "icmp_slt" => ("<", true),
        "icmp_ult" => ("<", false),
        "icmp_sge" => (">=", true),
        "icmp_uge" => (">=", false),
        _ => return None,
    };
    // A signed guard compares signed values. This emitted `<` over `uint32_t`
    // for `icmp_slt` and `icmp_ult` alike, so every signed branch in the
    // compact executor -- RISC-V's `blt` and `bge` among them -- took the
    // unsigned decision, and took the wrong edge whenever its two operands
    // differed in sign. The wide path had the rule and this one had the
    // operator: `axis_signed64` is why `whilelt` was found the first time.
    let side = |expr: String| {
        if signed {
            format!("axis_sem_signed({expr}, {width}u)")
        } else {
            format!("({expr})")
        }
    };
    Some(format!(
        "{} {cmp} {}",
        side(c_effect_expr(&items[1], width)?),
        side(c_effect_expr(&items[2], width)?)
    ))
}

/// Parse a load access width from an `iW` type atom.
fn load_access_width(atom: &SemanticExpr) -> Option<u32> {
    let SemanticExpr::Atom(text) = atom else {
        return None;
    };
    text.strip_prefix(['i', 'u'])?.parse().ok()
}

/// Rust functional single-step interpreter (`axis.exec-rust.v1`): the third
/// executor sibling of `axis_exec.py` and `axis_exec.h`, completing the exec
/// trio. It composes the Rust lifter (`axis_lift.rs`, decode/lift) and the Rust
/// semantics (`axis_semantics.rs`, pure `axis_eval_*`), and — like the Python
/// interpreter — runs the full E1-E4 effect surface: set (with load-as-set),
/// store, `setpc`, and `trap`, each optionally guarded. `step` decodes a word,
/// dispatches on the mnemonic, and either evaluates the pure semantics or runs
/// the effect list against `regs`, a `Memory`, and `pc`. Emitted to be compiled
/// alongside the lifter and semantics modules (their items are in scope).
pub fn emit_exec_rust(document: &Document) -> String {
    let rust_sem = crate::emit::emit_semantics_rust(document);
    let state_names = crate::effects::isa_scalar_state_names(&document.isas);
    // (raw_mnemonic, ident, def) per instruction with executable effects.
    let effect_fns: Vec<(String, String, String)> = document
        .instructions
        .iter()
        .filter_map(|instruction| {
            emit_rust_effect_fn(instruction, &state_names).map(|def| {
                (
                    instruction.mnemonic.clone(),
                    python_ident(&instruction.mnemonic),
                    def,
                )
            })
        })
        .collect();
    let wide_effect_fns: Vec<(String, String, String)> = document
        .instructions
        .iter()
        .filter_map(|instruction| {
            emit_rust_effect64_fn(instruction).map(|def| {
                (
                    instruction.mnemonic.clone(),
                    python_ident(&instruction.mnemonic),
                    def,
                )
            })
        })
        .collect();

    let mut out = String::new();
    out.push_str("// Generated by AXIS. Functional single-step interpreter (decode -> execute).\n");
    out.push_str("// schema: axis.exec-rust.v1\n");
    out.push_str(
        "// Compile together with axis_lift.rs (decode/lift) and axis_semantics.rs (pure eval);\n",
    );
    out.push_str("// their items are referenced directly. The register file and Memory are the\n");
    out.push_str("// caller's. Mirrors axis_exec.py / axis_exec.h.\n\n");
    out.push_str("pub const AXIS_EXEC_ILEN: u32 = 4;\n\n");

    out.push_str("/// Width-addressed memory for load/store effects (little-endian quantities).\n");
    out.push_str("pub trait Memory {\n");
    out.push_str("    fn read(&mut self, addr: u32, width: u32) -> u32;\n");
    out.push_str("    fn write(&mut self, addr: u32, value: u32, width: u32);\n");
    out.push_str("}\n\n");

    out.push_str("/// Single-step result: the written result (last set), the next program\n");
    out.push_str("/// counter (fall-through unless a setpc fires), and any trap cause.\n");
    out.push_str("#[derive(Clone, Debug)]\n");
    out.push_str("pub struct ExecResult {\n");
    out.push_str("    pub mnemonic: Option<&'static str>,\n");
    out.push_str("    pub result: Option<u32>,\n");
    out.push_str("    pub state_write: Option<(&'static str, u32)>,\n");
    out.push_str("    pub next_pc: u32,\n");
    out.push_str("    pub trap: Option<&'static str>,\n");
    out.push_str("    pub ok: bool,\n");
    out.push_str("}\n\n");

    for (_, _, def) in &effect_fns {
        out.push_str(def);
    }

    // Pure dispatch: mnemonic -> axis_eval_* (only instructions with a Rust
    // semantics function; widths beyond 32 bits are skipped, matching the C path).
    out.push_str("#[allow(unused_variables)]\n");
    out.push_str("fn axis_exec_eval(mnemonic: &str, inputs: &[u32]) -> Option<u32> {\n");
    out.push_str("    match mnemonic {\n");
    for instruction in &document.instructions {
        let ident = python_ident(&instruction.mnemonic);
        // As in the C path: the compact ABI takes `u32`, so wide semantics
        // functions belong to the wide dispatch, not this one.
        if pure_eval_width(instruction) > 32 {
            continue;
        }
        if !rust_sem.contains(&format!("pub fn axis_eval_{ident}(")) {
            continue;
        }
        let argc = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .count();
        let args: Vec<String> = (0..argc).map(|i| format!("inputs[{i}]")).collect();
        out.push_str(&format!(
            "        {} => (inputs.len() == {argc}).then(|| axis_eval_{ident}({})),\n",
            json_string(&instruction.mnemonic),
            args.join(", ")
        ));
    }
    out.push_str("        _ => None,\n    }\n}\n\n");

    // Effect dispatch: mnemonic -> effect function; true if the mnemonic is effectful.
    out.push_str("#[allow(unused_variables)]\n");
    out.push_str(
        "fn axis_exec_effects(mnemonic: &str, lifted: &Lifted, regs: &mut [u32], mem: &mut dyn Memory, pc: u32, r: &mut ExecResult) -> bool {\n",
    );
    out.push_str("    match mnemonic {\n");
    for (mnemonic, ident, _) in &effect_fns {
        out.push_str(&format!(
            "        {} => {{ axis_exec_eff_{ident}(lifted, regs, mem, pc, r); true }}\n",
            json_string(mnemonic)
        ));
    }
    out.push_str("        _ => false,\n    }\n}\n\n");

    out.push_str("/// Decode and execute `word` against `regs` (index -> value), `mem`, and the\n");
    out.push_str(
        "/// program counter `pc`. Mutates `regs`/memory in place; `ok` is false if the\n",
    );
    out.push_str("/// word does not decode or has no executable semantics.\n");
    out.push_str(
        "pub fn step(word: u32, regs: &mut [u32], mem: &mut dyn Memory, pc: u32) -> ExecResult {\n",
    );
    out.push_str("    let mut r = ExecResult {\n");
    out.push_str("        mnemonic: None,\n        result: None,\n        state_write: None,\n");
    out.push_str("        next_pc: pc.wrapping_add(AXIS_EXEC_ILEN),\n");
    out.push_str("        trap: None,\n        ok: false,\n    };\n");
    out.push_str("    let lifted = match lift(word) {\n        Some(l) => l,\n        None => return r,\n    };\n");
    out.push_str("    r.mnemonic = Some(lifted.entry.mnemonic);\n");
    out.push_str(
        "    if axis_exec_effects(lifted.entry.mnemonic, &lifted, regs, mem, pc, &mut r) {\n        r.ok = true;\n        return r;\n    }\n",
    );
    out.push_str("    if !lifted.entry.liftable {\n        return r;\n    }\n");
    out.push_str("    let mut inputs: Vec<u32> = Vec::new();\n");
    out.push_str("    for (i, op) in lifted.entry.operands.iter().enumerate() {\n");
    out.push_str("        if op.role == \"out\" {\n            continue;\n        }\n");
    out.push_str("        let v = lifted.operands[i].unwrap_or(0);\n");
    out.push_str("        inputs.push(match reg_class_of(op.kind) {\n");
    out.push_str("            Some(cls) => {\n");
    out.push_str("                let raw = if cls.zero_index == Some(v) { 0 } else { let idx = (v * cls.limbs + cls.offset) as usize; if idx < regs.len() { regs[idx] } else { 0 } };\n");
    out.push_str("                match cls.view_width { Some(width) => axis_mask64(raw as u64, width) as u32, None => raw }\n");
    out.push_str("            }\n            None => v,\n        });\n    }\n");
    out.push_str("    let result = match axis_exec_eval(lifted.entry.mnemonic, &inputs) {\n        Some(x) => x,\n        None => return r,\n    };\n");
    out.push_str("    r.result = Some(result);\n    r.ok = true;\n");
    out.push_str("    for (i, op) in lifted.entry.operands.iter().enumerate() {\n");
    out.push_str("        if op.role != \"in\" && reg_class_of(op.kind).is_some_and(|cls| cls.zero_index != Some(lifted.operands[i].unwrap_or(0))) {\n");
    // The write lands in the class's own file at its own stride: the offset
    // says which file, the limb count says how far apart its registers are.
    out.push_str("            let cls = reg_class_of(op.kind);\n");
    out.push_str("            let offset = cls.map_or(0, |cls| cls.offset) as usize;\n");
    out.push_str("            let stride = cls.map_or(1, |cls| cls.limbs) as usize;\n");
    out.push_str("            let idx = lifted.operands[i].unwrap_or(0) as usize * stride + offset;\n");
    out.push_str("            if idx < regs.len() {\n                regs[idx] = result;\n            }\n        }\n    }\n");
    out.push_str("    r\n}\n");
    emit_exec_rust64(document, &wide_effect_fns, &mut out);
    out
}

fn emit_exec_rust64(
    document: &Document,
    effect_fns: &[(String, String, String)],
    out: &mut String,
) {
    out.push_str("\n/// One named scalar architectural-state location for the wide ABI.\n");
    // ⚠️ The limb methods are DEFAULTED, so every existing implementor keeps
    // compiling and gets the split a machine's bus performs anyway. A host that
    // models a wide access as one event -- a tracer -- overrides them and sees
    // one. This is the C twin's optional function pointers, said in the way
    // Rust says it.
    out.push_str("pub trait WideMemory {\n    fn read64(&mut self, addr: u64, width: u32) -> u64;\n    fn write64(&mut self, addr: u64, value: u64, width: u32);\n    /// A one-way message out of the machine. ⚠️ Defaulted to nothing: a host\n    /// that models no channels is not wrong, it is a host with no channels,\n    /// and every existing implementor keeps compiling.\n    fn send64(&mut self, _port: u64, _value: u64, _width: u32) {}\n    /// A value wider than the word, low limb first.\n    fn read_limbs64(&mut self, addr: u64, width: u32, out: &mut [u64]) {\n        for i in 0..out.len() {\n            let rest = width - (i as u32) * 64;\n            let take = if rest >= 64 { 64 } else { rest };\n            out[i] = self.read64(addr.wrapping_add((i as u64) * 8), take);\n        }\n    }\n    /// The same, in the other direction.\n    fn write_limbs64(&mut self, addr: u64, width: u32, limbs: &[u64]) {\n        for (i, limb) in limbs.iter().enumerate() {\n            let rest = width - (i as u32) * 64;\n            let take = if rest >= 64 { 64 } else { rest };\n            self.write64(addr.wrapping_add((i as u64) * 8), *limb, take);\n        }\n    }\n}\n\n");
    out.push_str("#[derive(Clone, Debug)]\npub struct State64Entry {\n    pub name: &'static str,\n    pub value: u64,\n    pub width: u32,\n}\n\n");
    out.push_str("fn axis_mask64(value: u64, width: u32) -> u64 { if width >= 64 { value } else { value & ((1u64 << width) - 1) } }\n");
    out.push_str("fn axis_signed64(value: u64, width: u32) -> i64 { if width >= 64 { value as i64 } else { let sign = 1u64 << (width - 1); ((axis_mask64(value, width) ^ sign).wrapping_sub(sign)) as i64 } }\n");
    out.push_str("fn axis_sext64(value: u64, from: u32, width: u32) -> u64 { let value = axis_mask64(value, from); let extended = if from > 0 && from < 64 && value & (1u64 << (from - 1)) != 0 { value | !((1u64 << from) - 1) } else { value }; axis_mask64(extended, width) }\n");
    out.push_str("fn axis_udiv64(lhs: u64, rhs: u64, width: u32) -> u64 { let lhs = axis_mask64(lhs, width); let rhs = axis_mask64(rhs, width); if rhs == 0 { 0 } else { axis_mask64(lhs / rhs, width) } }\n");
    out.push_str("fn axis_mulh64(a: u64, b: u64, width: u32, signed_a: bool, signed_b: bool) -> u64 { let wa = if signed_a { axis_signed64(a, width) as i128 } else { axis_mask64(a, width) as i128 }; let wb = if signed_b { axis_signed64(b, width) as i128 } else { axis_mask64(b, width) as i128 }; let product = (wa.wrapping_mul(wb)) as u128; axis_mask64((product >> width) as u64, width) }\n");
    out.push_str("fn axis_minmax64(a: u64, b: u64, width: u32, is_signed: bool, is_max: bool) -> u64 { let a = axis_mask64(a, width); let b = axis_mask64(b, width); let less = if is_signed { axis_signed64(a, width) < axis_signed64(b, width) } else { a < b }; if less != is_max { a } else { b } }\n");
    out.push_str("fn axis_sdiv64(lhs: u64, rhs: u64, width: u32) -> u64 { let lhs = axis_mask64(lhs, width); let rhs = axis_mask64(rhs, width); if rhs == 0 { return 0 } let lhs = axis_signed64(lhs, width); let rhs = axis_signed64(rhs, width); lhs.checked_div(rhs).unwrap_or(lhs) as u64 }\n");
    out.push_str("fn axis_shift_amount64(amount: u64, width: u32) -> u64 { if width >= 64 { amount } else { amount & ((1u64 << width) - 1) } }\n");
    out.push_str("fn axis_shl64(value: u64, amount: u64, width: u32) -> u64 { let amount = axis_shift_amount64(amount, width); if amount >= width as u64 { 0 } else { axis_mask64(value.wrapping_shl(amount as u32), width) } }\n");
    out.push_str("fn axis_lshr64(value: u64, amount: u64, width: u32) -> u64 { let amount = axis_shift_amount64(amount, width); if amount >= width as u64 { 0 } else { axis_mask64(value, width) >> (amount as u32) } }\n");
    out.push_str("fn axis_ashr64(value: u64, amount: u64, width: u32) -> u64 { let wide = axis_signed64(value, width); let amount = axis_shift_amount64(amount, width); if amount >= width as u64 { return axis_mask64(if wide < 0 { u64::MAX } else { 0 }, width); } axis_mask64((wide >> amount as u32) as u64, width) }\n");
    out.push_str("fn axis_clz64(value: u64, width: u32) -> u64 { let value = axis_mask64(value, width); if value == 0 { width as u64 } else { (value.leading_zeros() - (64 - width)) as u64 } }\n");
    out.push_str("fn axis_ctz64(value: u64, width: u32) -> u64 { let value = axis_mask64(value, width); if value == 0 { width as u64 } else { value.trailing_zeros() as u64 } }\n");
    out.push_str("fn axis_cpop64(value: u64, width: u32) -> u64 { axis_mask64(value, width).count_ones() as u64 }\n");
    out.push_str("fn axis_rotl64(value: u64, amount: u64, width: u32) -> u64 { if width == 0 { return value } let value = axis_mask64(value, width); let shift = (amount % width as u64) as u32; if shift == 0 { return value } axis_mask64((value << shift) | (value >> (width - shift)), width) }\n");
    out.push_str("fn axis_rotr64(value: u64, amount: u64, width: u32) -> u64 { if width == 0 { return value } let shift = (amount % width as u64) as u32; axis_rotl64(value, ((width - shift) % width) as u64, width) }\n");
    out.push_str("fn state64_read(state: &[State64Entry], name: &str) -> u64 { state.iter().find(|entry| entry.name == name).map_or(0, |entry| axis_mask64(entry.value, entry.width)) }\n");
    out.push_str("fn state64_write(state: &mut [State64Entry], name: &str, value: u64, width: u32) -> bool { if let Some(entry) = state.iter_mut().find(|entry| entry.name == name) { entry.value = axis_mask64(value, width); entry.width = width; true } else { false } }\n");
    out.push_str("fn a64_add_nzcv(a: u64, b: u64, width: u32) -> u64 { let mask = axis_mask64(u64::MAX, width); let sign = 1u64 << (width - 1); let a = a & mask; let b = b & mask; let result = a.wrapping_add(b) & mask; let n = result & sign != 0; let z = result == 0; let c = if width == 64 { result < a } else { a + b > mask }; let v = (!(a ^ b) & (a ^ result) & sign) != 0; ((n as u64) << 3) | ((z as u64) << 2) | ((c as u64) << 1) | v as u64 }\n");
    out.push_str("fn a64_sub_nzcv(a: u64, b: u64, width: u32) -> u64 { let mask = axis_mask64(u64::MAX, width); let sign = 1u64 << (width - 1); let a = a & mask; let b = b & mask; let result = a.wrapping_sub(b) & mask; let n = result & sign != 0; let z = result == 0; let c = a >= b; let v = ((a ^ b) & (a ^ result) & sign) != 0; ((n as u64) << 3) | ((z as u64) << 2) | ((c as u64) << 1) | v as u64 }\n");
    out.push_str("fn a64_adc_nzcv(a: u64, b: u64, carry_in: u64, width: u32) -> u64 { let mask = axis_mask64(u64::MAX, width); let sign = 1u64 << (width - 1); let a = a & mask; let b = b & mask; let carry_in = carry_in & 1; let (sum, c1) = a.overflowing_add(b); let (result_raw, c2) = sum.overflowing_add(carry_in); let result = result_raw & mask; let c = if width == 64 { c1 || c2 } else { a + b + carry_in > mask }; let n = result & sign != 0; let z = result == 0; let v = (!(a ^ b) & (a ^ result) & sign) != 0; ((n as u64) << 3) | ((z as u64) << 2) | ((c as u64) << 1) | v as u64 }\n");
    out.push_str("fn a64_sbc_nzcv(a: u64, b: u64, carry_in: u64, width: u32) -> u64 { let mask = axis_mask64(u64::MAX, width); let sign = 1u64 << (width - 1); let a = a & mask; let b = b & mask; let borrow = 1 - (carry_in & 1); let (difference, b1) = a.overflowing_sub(b); let (result_raw, b2) = difference.overflowing_sub(borrow); let result = result_raw & mask; let c = !(b1 || b2); let n = result & sign != 0; let z = result == 0; let v = ((a ^ b) & (a ^ result) & sign) != 0; ((n as u64) << 3) | ((z as u64) << 2) | ((c as u64) << 1) | v as u64 }\n");
    out.push_str("fn a64_umulh(a: u64, b: u64) -> u64 { ((a as u128).wrapping_mul(b as u128) >> 64) as u64 }\n");
    out.push_str("fn a64_smulh(a: u64, b: u64) -> u64 { ((a as i64 as i128).wrapping_mul(b as i64 as i128) >> 64) as u64 }\n");
    out.push_str("fn a64_logic_nzcv(value: u64, width: u32) -> u64 { let value = axis_mask64(value, width); ((value >> (width - 1)) & 1) << 3 | ((value == 0) as u64) << 2 }\n");
    out.push_str("fn a64_cond_holds(nzcv: u64, cond: u64) -> u64 { let n = nzcv & 8 != 0; let z = nzcv & 4 != 0; let c = nzcv & 2 != 0; let v = nzcv & 1 != 0; [z, !z, c, !c, n, !n, v, !v, c && !z, !c || z, n == v, n != v, !z && n == v, z || n != v, true, true][(cond & 15) as usize] as u64 }\n");
    out.push_str("fn a64_shift_reg(value: u64, shift: u64, amount: u64, width: u32) -> u64 { let value = axis_mask64(value, width); let amount = (amount & (width - 1) as u64) as u32; match shift & 3 { 0 => axis_mask64(value.wrapping_shl(amount), width), 1 => value >> amount, 2 => if width == 32 { ((value as u32 as i32) >> amount) as u32 as u64 } else { ((value as i64) >> amount) as u64 }, _ => if amount == 0 { value } else { axis_mask64((value >> amount) | value.wrapping_shl(width - amount), width) } } }\n");
    out.push_str("fn a64_extend_reg(value: u64, option: u64, amount: u64, width: u32) -> u64 { let source_width = 8u32 << (option & 3); let mut extended = axis_mask64(value, source_width); if option & 4 != 0 && source_width < 64 && extended >> (source_width - 1) & 1 != 0 { extended |= !axis_mask64(u64::MAX, source_width); } axis_mask64(extended.wrapping_shl((amount & 7) as u32), width) }\n");
    out.push_str("fn a64_replicate(element: u64, esize: u32, width: u32) -> u64 { let element = axis_mask64(element, esize); let mut result = 0u64; let mut pos = 0; while pos < width { result |= element << pos; pos += esize; } axis_mask64(result, width) }\n");
    out.push_str("fn a64_decode_masks(n: u64, immr: u64, imms: u64, width: u32) -> (u64, u64, u32) { let encoded = (((n & 1) << 6) | ((!imms) & 0x3f)) as u32; let Some(len) = (0..=6).rev().find(|bit| encoded & (1u32 << bit) != 0) else { return (0, 0, 0) }; if len < 1 { return (0, 0, 0) } let levels = (1u32 << len) - 1; let s = imms as u32 & levels; let r = immr as u32 & levels; let diff = s.wrapping_sub(r) & levels; let esize = 1u32 << len; let welem = axis_mask64(u64::MAX, s + 1); let telem = axis_mask64(u64::MAX, diff + 1); (a64_replicate(a64_shift_reg(welem, 3, r as u64, esize), esize, width), a64_replicate(telem, esize, width), s) }\n");
    out.push_str("fn a64_wmask(n: u64, immr: u64, imms: u64, width: u32) -> u64 { a64_decode_masks(n, immr, imms, width).0 }\n");
    out.push_str("fn a64_ubfm(src: u64, immr: u64, imms: u64, width: u32) -> u64 { let (wmask, tmask, _) = a64_decode_masks((width == 64) as u64, immr, imms, width); a64_shift_reg(src, 3, immr, width) & wmask & tmask }\n");
    out.push_str("fn a64_sbfm(src: u64, immr: u64, imms: u64, width: u32) -> u64 { let (wmask, tmask, s) = a64_decode_masks((width == 64) as u64, immr, imms, width); if wmask == 0 { return 0; } let bot = a64_shift_reg(src, 3, immr, width) & wmask; let top = if axis_mask64(src, width) >> s & 1 != 0 { axis_mask64(u64::MAX, width) } else { 0 }; axis_mask64((top & !tmask) | (bot & tmask), width) }\n");
    out.push_str("fn a64_bfm(dst: u64, src: u64, immr: u64, imms: u64, width: u32) -> u64 { let (wmask, tmask, _) = a64_decode_masks((width == 64) as u64, immr, imms, width); if wmask == 0 { return 0; } let dst = axis_mask64(dst, width); let bot = (dst & !wmask) | (a64_shift_reg(src, 3, immr, width) & wmask); axis_mask64((dst & !tmask) | (bot & tmask), width) }\n");
    emit_exec_rust64_functions(document, out);
    out.push_str("struct RegClass { name: &'static str, zero_index: Option<u32>, alias: Option<(u32, &'static str)>, view_width: Option<u32>, view_offset: u32, preserves: bool, limbs: u32, offset: u32, index_offset: u32 }\n");
    out.push_str("const REG_CLASSES: &[RegClass] = &[\n");
    for class in crate::ast::REGISTER_CLASSES {
        let zero = class
            .zero_index
            .map(|index| format!("Some({index})"))
            .unwrap_or_else(|| "None".to_string());
        let alias = class
            .alias
            .map(|(index, name)| format!("Some(({index}, \"{name}\"))"))
            .unwrap_or_else(|| "None".to_string());
        let view = class
            .view_width
            .map(|width| format!("Some({width})"))
            .unwrap_or_else(|| "None".to_string());
        let preserves = matches!(class.write_policy, crate::ast::WritePolicy::Preserve);
        out.push_str(&format!(
            "    RegClass {{ name: \"{}\", zero_index: {zero}, alias: {alias}, view_width: {view}, view_offset: {}, preserves: {preserves}, limbs: {}, offset: {}, index_offset: {} }},\n",
            class.name, class.view_offset, class.limbs.max(1), class.offset,
            class.index_offset
        ));
    }
    out.push_str("];\n\n");
    out.push_str("fn reg_class_of(kind: &str) -> Option<&'static RegClass> { REG_CLASSES.iter().find(|class| class.name == kind) }\n");
    out.push_str("fn read_reg64(regs: &[u64], index: u32, kind: &str, state: &[State64Entry]) -> u64 { let Some(rules) = reg_class_of(kind) else { return 0 }; if rules.zero_index == Some(index) { return 0; } if let Some((alias_index, name)) = rules.alias { if alias_index == index { let aliased = state64_read(state, name); return match rules.view_width { Some(width) => axis_mask64(aliased >> rules.view_offset, width), None => aliased }; } } let slot = rules.offset + (rules.index_offset + index) * rules.limbs; let Some(width) = rules.view_width else { return regs.get(slot as usize).copied().unwrap_or(0) }; let bit = rules.view_offset; let low_slot = (slot + bit / 64) as usize; let shift = bit % 64; let mut value = regs.get(low_slot).copied().unwrap_or(0) >> shift; if shift != 0 && shift + width > 64 { let high = regs.get(low_slot + 1).copied().unwrap_or(0); value |= high << (64 - shift); } axis_mask64(value, width) }\n");
    out.push_str("fn write_reg64(regs: &mut [u64], index: u32, kind: &str, value: u64, state: &mut [State64Entry]) -> bool { let Some(rules) = reg_class_of(kind) else { return false }; let view = rules.view_width.unwrap_or(64); let value = axis_mask64(value, view); if rules.zero_index == Some(index) { return false; } if let Some((alias_index, name)) = rules.alias { if alias_index == index { return state64_write(state, name, value, 64); } } let base = rules.offset + (rules.index_offset + index) * rules.limbs; let Some(width) = rules.view_width else { if base as usize >= regs.len() { return false; } for k in 0..rules.limbs.max(1) { if let Some(slot) = regs.get_mut((base + k) as usize) { *slot = if k == 0 { value } else { 0 }; } } return true; }; let bit = rules.view_offset; let low_index = (base + bit / 64) as usize; if low_index >= regs.len() { return false; } let shift = bit % 64; if !rules.preserves { for k in 0..rules.limbs { if let Some(slot) = regs.get_mut((base + k) as usize) { *slot = 0; } } } let mask_low = axis_mask64(u64::MAX, width) << shift; match regs.get_mut(low_index) { Some(slot) => { *slot = (*slot & !mask_low) | ((value << shift) & mask_low); }, None => return false }; if shift != 0 && shift + width > 64 { let spill = shift + width - 64; let mask_high = axis_mask64(u64::MAX, spill); if let Some(slot) = regs.get_mut(low_index + 1) { *slot = (*slot & !mask_high) | ((value >> (64 - shift)) & mask_high); } } true }\n\n");
    // The operand-level twins of `read_reg64`/`write_reg64`, as C's
    // `axis_read_operand64`/`axis_write_operand64`: an operand with a view
    // (an element of a scalable register) is read at its placement, and one
    // without falls back to the class. A lane writes its element and nothing
    // else of the register.
    out.push_str("fn operand_register(op: &LiftOperand, decoded: u32) -> u32 { decoded.wrapping_add(op.register_bias) }\n");
    out.push_str("fn read_view64(regs: &[u64], index: u32, kind: &str, state: &[State64Entry], stride: u32, view_offset: u32, view_width: u32, slot_base: u32) -> u64 { if view_width == 0 { return read_reg64(regs, index, kind, state); } let Some(rules) = reg_class_of(kind) else { return 0 }; if rules.zero_index == Some(index) { return 0; } if let Some((alias_index, name)) = rules.alias { if alias_index == index { return axis_mask64(state64_read(state, name) >> view_offset, view_width); } } let slot = slot_base + index * stride.max(1); let low = (slot + view_offset / 64) as usize; let shift = view_offset % 64; let mut value = regs.get(low).copied().unwrap_or(0) >> shift; if shift != 0 && shift + view_width > 64 { value |= regs.get(low + 1).copied().unwrap_or(0) << (64 - shift); } axis_mask64(value, view_width) }\n");
    out.push_str("fn write_view64(regs: &mut [u64], index: u32, kind: &str, value: u64, state: &mut [State64Entry], stride: u32, view_offset: u32, view_width: u32, slot_base: u32) -> bool { if view_width == 0 { return write_reg64(regs, index, kind, value, state); } let Some(rules) = reg_class_of(kind) else { return false }; let value = axis_mask64(value, view_width); if rules.zero_index == Some(index) { return false; } if let Some((alias_index, name)) = rules.alias { if alias_index == index { return state64_write(state, name, value, 64); } } let base = slot_base + index * stride.max(1); let low = (base + view_offset / 64) as usize; if low >= regs.len() { return false; } let shift = view_offset % 64; let mask_low = axis_mask64(u64::MAX, view_width) << shift; regs[low] = (regs[low] & !mask_low) | ((value << shift) & mask_low); if shift != 0 && shift + view_width > 64 { let spill = shift + view_width - 64; let mask_high = axis_mask64(u64::MAX, spill); if let Some(slot) = regs.get_mut(low + 1) { *slot = (*slot & !mask_high) | ((value >> (64 - shift)) & mask_high); } } true }\n");
    out.push_str("fn read_operand64(regs: &[u64], op: &LiftOperand, decoded: u32, state: &[State64Entry]) -> u64 { read_view64(regs, operand_register(op, decoded), op.kind, state, op.stride, op.view_offset, op.view_width, op.slot_base) }\n");
    out.push_str("fn write_operand64(regs: &mut [u64], op: &LiftOperand, decoded: u32, value: u64, state: &mut [State64Entry]) -> bool { write_view64(regs, operand_register(op, decoded), op.kind, value, state, op.stride, op.view_offset, op.view_width, op.slot_base) }\n\n");

    // The limb pair, mirroring the C twin. A wide value occupies `rules.limbs`
    // consecutive words of the file, which is how the file already stores one.
    out.push_str("fn read_limbs64(regs: &[u64], index: u32, kind: &str, limbs: usize) -> Vec<u64> { let mut out = vec![0u64; limbs]; let Some(rules) = reg_class_of(kind) else { return out }; if rules.zero_index == Some(index) { return out; } let slot = (rules.offset + (rules.index_offset + index) * rules.limbs) as usize; for i in 0..limbs.min(rules.limbs as usize) { out[i] = regs.get(slot + i).copied().unwrap_or(0); } out }\n");
    out.push_str("fn write_limbs64(regs: &mut [u64], index: u32, kind: &str, limbs: &[u64]) -> bool { let Some(rules) = reg_class_of(kind) else { return false }; if rules.zero_index == Some(index) { return false; } let slot = (rules.offset + (rules.index_offset + index) * rules.limbs) as usize; let mut wrote = false; for (i, limb) in limbs.iter().enumerate().take(rules.limbs as usize) { if let Some(cell) = regs.get_mut(slot + i) { *cell = *limb; wrote = true; } } wrote }\n\n");

    // The limb arithmetic, mirroring the C twin operation for operation. An
    // array of limbs rather than `u128`, for the reason the C side gives: it
    // is what generalises past 128. `u128` appears once, in `mul`, as the
    // 64x64 partial product a schoolbook multiply needs.
    let wide_limbs = crate::ast::REGISTER_CLASSES
        .iter()
        .map(|class| class.limbs.max(1))
        .max()
        .unwrap_or(1);
    out.push_str(&format!("const AXIS_WIDE_LIMBS: usize = {wide_limbs};\n"));
    out.push_str("#[derive(Clone, Copy, PartialEq, Eq, Debug)]\nstruct AxisWide { limb: [u64; AXIS_WIDE_LIMBS] }\n");
    out.push_str("fn wide_zero() -> AxisWide { AxisWide { limb: [0u64; AXIS_WIDE_LIMBS] } }\n");
    out.push_str("fn wide_of(v: u64) -> AxisWide { let mut w = wide_zero(); w.limb[0] = v; w }\n");
    out.push_str("fn wide_low(a: AxisWide) -> u64 { a.limb[0] }\n");
    out.push_str("fn wide_mask(mut a: AxisWide, width: u32) -> AxisWide {\n    for i in 0..AXIS_WIDE_LIMBS {\n        let low = (i as u32) * 64;\n        if width <= low { a.limb[i] = 0; }\n        else if width < low + 64 { a.limb[i] &= (1u64 << (width - low)) - 1; }\n    }\n    a\n}\n");
    out.push_str("fn wide_and(mut a: AxisWide, b: AxisWide) -> AxisWide { for i in 0..AXIS_WIDE_LIMBS { a.limb[i] &= b.limb[i]; } a }\n");
    out.push_str("fn wide_or(mut a: AxisWide, b: AxisWide) -> AxisWide { for i in 0..AXIS_WIDE_LIMBS { a.limb[i] |= b.limb[i]; } a }\n");
    out.push_str("fn wide_xor(mut a: AxisWide, b: AxisWide) -> AxisWide { for i in 0..AXIS_WIDE_LIMBS { a.limb[i] ^= b.limb[i]; } a }\n");
    out.push_str("fn wide_not(mut a: AxisWide, width: u32) -> AxisWide { for i in 0..AXIS_WIDE_LIMBS { a.limb[i] = !a.limb[i]; } wide_mask(a, width) }\n");
    out.push_str("fn wide_add(a: AxisWide, b: AxisWide, width: u32) -> AxisWide {\n    let mut out = wide_zero();\n    let mut carry = 0u64;\n    for i in 0..AXIS_WIDE_LIMBS {\n        let (sum, wrapped) = a.limb[i].overflowing_add(b.limb[i]);\n        let (total, again) = sum.overflowing_add(carry);\n        carry = (wrapped as u64) | (again as u64);\n        out.limb[i] = total;\n    }\n    wide_mask(out, width)\n}\n");
    out.push_str("fn wide_sub(a: AxisWide, b: AxisWide, width: u32) -> AxisWide {\n    let mut out = wide_zero();\n    let mut borrow = 0u64;\n    for i in 0..AXIS_WIDE_LIMBS {\n        let (diff, under) = a.limb[i].overflowing_sub(b.limb[i]);\n        let (total, again) = diff.overflowing_sub(borrow);\n        borrow = (under as u64) | (again as u64);\n        out.limb[i] = total;\n    }\n    wide_mask(out, width)\n}\n");
    out.push_str("fn wide_mul(a: AxisWide, b: AxisWide, width: u32) -> AxisWide {\n    let mut out = wide_zero();\n    for i in 0..AXIS_WIDE_LIMBS {\n        let mut carry = 0u64;\n        let mut j = 0usize;\n        while i + j < AXIS_WIDE_LIMBS {\n            let term = (a.limb[i] as u128) * (b.limb[j] as u128)\n                + (out.limb[i + j] as u128) + (carry as u128);\n            out.limb[i + j] = term as u64;\n            carry = (term >> 64) as u64;\n            j += 1;\n        }\n    }\n    wide_mask(out, width)\n}\n");
    out.push_str("fn wide_shl(a: AxisWide, amount: u64, width: u32) -> AxisWide {\n    let mut out = wide_zero();\n    if amount >= (AXIS_WIDE_LIMBS as u64) * 64 { return out; }\n    let words = (amount / 64) as usize;\n    let bits = (amount % 64) as u32;\n    for i in (0..AXIS_WIDE_LIMBS).rev() {\n        let mut value = 0u64;\n        if i >= words {\n            value = a.limb[i - words] << bits;\n            if bits != 0 && i > words { value |= a.limb[i - words - 1] >> (64 - bits); }\n        }\n        out.limb[i] = value;\n    }\n    wide_mask(out, width)\n}\n");
    out.push_str("fn wide_lshr(a: AxisWide, amount: u64, width: u32) -> AxisWide {\n    let a = wide_mask(a, width);\n    let mut out = wide_zero();\n    if amount >= (AXIS_WIDE_LIMBS as u64) * 64 { return out; }\n    let words = (amount / 64) as usize;\n    let bits = (amount % 64) as u32;\n    for i in 0..AXIS_WIDE_LIMBS {\n        let mut value = 0u64;\n        if i + words < AXIS_WIDE_LIMBS {\n            value = a.limb[i + words] >> bits;\n            if bits != 0 && i + words + 1 < AXIS_WIDE_LIMBS { value |= a.limb[i + words + 1] << (64 - bits); }\n        }\n        out.limb[i] = value;\n    }\n    wide_mask(out, width)\n}\n");
    out.push_str("fn wide_eq(a: AxisWide, b: AxisWide) -> bool { a.limb == b.limb }\n");
    out.push_str("fn wide_ult(a: AxisWide, b: AxisWide) -> bool {\n    for i in (0..AXIS_WIDE_LIMBS).rev() {\n        if a.limb[i] != b.limb[i] { return a.limb[i] < b.limb[i]; }\n    }\n    false\n}\n");
    out.push_str("fn wide_nonzero(a: AxisWide) -> bool { a.limb.iter().any(|l| *l != 0) }\n");
    out.push_str("fn wide_read_operand(regs: &[u64], op: &LiftOperand, decoded: u32, state: &[State64Entry]) -> AxisWide {\n    let mut w = wide_zero();\n    if op.width > 64 {\n        let limbs = ((op.width + 63) / 64) as usize;\n        let limbs = if limbs > AXIS_WIDE_LIMBS { AXIS_WIDE_LIMBS } else { limbs };\n        let read = read_limbs64(regs, decoded, op.kind, limbs);\n        w.limb[..limbs].copy_from_slice(&read[..limbs]);\n    } else {\n        w.limb[0] = read_reg64(regs, decoded, op.kind, state);\n    }\n    w\n}\n");
    for count in 1..=wide_limbs {
        let params: Vec<String> = (0..count).map(|i| format!("l{i}: u64")).collect();
        let sets: Vec<String> = (0..count).map(|i| format!("w.limb[{i}] = l{i};")).collect();
        out.push_str(&format!(
            "fn wide_lit{count}({}) -> AxisWide {{ let mut w = wide_zero(); {} w }}\n",
            params.join(", "),
            sets.join(" ")
        ));
    }
    out.push('\n');
    out.push_str("#[derive(Clone, Debug)]\npub struct ExecResult64 {\n    pub mnemonic: Option<&'static str>,\n    pub result: Option<u64>,\n    /// A value wider than the word, low limb first. Empty for an ordinary one.\n    pub result_limbs: Vec<u64>,\n    pub wrote: Option<u32>,\n    pub state_write: Option<(&'static str, u64)>,\n    pub next_pc: u64,\n    pub trap: Option<&'static str>,\n    pub ok: bool,\n}\n\n");
    for (_, _, def) in effect_fns {
        out.push_str(def);
    }
    // ⚠️ And the ones it could not write, BY NAME. `emit-llvm-ir` has always
    // put its refusals in the file it emits -- `; axis_eff_ldxp_x: an atomic
    // group...` -- and this emitter simply left the function out. A reader
    // could not tell an instruction Rust cannot express from a file that had
    // been truncated, and the only place the difference showed was a gate's
    // decline line, which is not in the artifact at all.
    let wide_declined: Vec<&Instruction> = document
        .instructions
        .iter()
        .filter(|instruction| {
            crate::effects::behavior_is_authoritative(instruction)
                && emit_rust_effect64_fn(instruction).is_none()
        })
        .collect();
    if !wide_declined.is_empty() {
        out.push_str("// Instructions this executor cannot express, and why. Named\n");
        out.push_str("// here rather than left out, so a reader can tell an\n");
        out.push_str("// instruction Rust has no way to perform from a file that\n");
        out.push_str("// was truncated.\n");
        for instruction in &wide_declined {
            out.push_str(&format!(
                "//   {}: {}\n",
                instruction.mnemonic,
                rust_effect_refusal(instruction)
            ));
        }
        out.push('\n');
    }
    out.push_str("fn axis_exec_eval64(mnemonic: &str, inputs: &[u64]) -> Option<u64> {\n    match mnemonic {\n");
    for instruction in &document.instructions {
        if instruction.formal_semantics.trim().is_empty() {
            continue;
        }
        // The same 64-bit limit the effect path has. `BSL_V` states itself as
        // `formal` rather than as a behavior, so it reached this path instead
        // and was evaluated at 64 bits with the other half dropped.
        if wider_than_word64(instruction) {
            continue;
        }
        let Ok(expr) = crate::semantics::parse_formal_semantics(&instruction.formal_semantics)
        else {
            continue;
        };
        let inputs: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .collect();
        let bindings: Vec<(String, String)> = inputs
            .iter()
            .enumerate()
            .map(|(idx, operand)| (operand.name.clone(), format!("inputs[{idx}]")))
            .collect();
        let width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .unwrap_or(64);
        let Some(value) = rust_wide_expr(&expr, &bindings, width) else {
            continue;
        };
        // Masked at the result width, as in the C twin.
        let value = format!("axis_mask64({value}, {width})");
        out.push_str(&format!(
            "        {} if inputs.len() == {} => Some({value}),\n",
            json_string(&instruction.mnemonic),
            inputs.len()
        ));
    }
    out.push_str("        _ => None,\n    }\n}\n\n");

    // The wide twin, as the C side has. Same population, same reason: an
    // instruction with an operand wider than the word cannot pass its inputs
    // or its answer through a `u64`.
    out.push_str("fn axis_exec_eval_wide(mnemonic: &str, inputs: &[AxisWide]) -> Option<AxisWide> {\n    match mnemonic {\n");
    for instruction in &document.instructions {
        if instruction.formal_semantics.trim().is_empty() || !wider_than_word64(instruction) {
            continue;
        }
        let Ok(expr) = crate::semantics::parse_formal_semantics(&instruction.formal_semantics)
        else {
            continue;
        };
        let wide_inputs: Vec<&Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .collect();
        let bindings: Vec<(String, String)> = wide_inputs
            .iter()
            .enumerate()
            .map(|(idx, operand)| (operand.name.clone(), format!("inputs[{idx}]")))
            .collect();
        let width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .unwrap_or(64);
        let Some(value) = rust_limb_expr(&expr, &bindings, width) else {
            continue;
        };
        out.push_str(&format!(
            "        {} if inputs.len() == {} => Some(wide_mask({value}, {width})),\n",
            json_string(&instruction.mnemonic),
            wide_inputs.len()
        ));
    }
    out.push_str("        _ => None,\n    }\n}\n\n");
    out.push_str("fn axis_exec_effects64(mnemonic: &str, lifted: &Lifted, regs: &mut [u64], mem: &mut dyn WideMemory, pc: u64, state: &mut [State64Entry], result: &mut ExecResult64) -> bool {\n    match mnemonic {\n");
    for (mnemonic, ident, _) in effect_fns {
        out.push_str(&format!(
            "        {} => {{ axis_exec64_eff_{ident}(lifted, regs, mem, pc, state, result); true }},\n",
            json_string(mnemonic)
        ));
    }
    // Instructions performed by a routine the embedder supplies. Unlike the C
    // twin this declares nothing: the generated executor is one Rust module, so
    // the call resolves against whatever the embedder defines beside it, and a
    // routine that is missing is a compile error naming the function rather
    // than a link error naming a symbol.
    let implementations: Vec<(&str, &str)> = document
        .instructions
        .iter()
        .filter(|instruction| {
            let answer = instruction.implementation.trim();
            !answer.is_empty() && answer != crate::ast::UNSUPPLIED
        })
        .map(|instruction| {
            (instruction.mnemonic.as_str(), instruction.implementation.trim())
        })
        .collect();
    // The instructions nobody performs. Same reasoning as the C twin: nothing
    // is declared and nothing is called, because there is nothing to call.
    let unsupplied: Vec<&str> = document
        .instructions
        .iter()
        .filter(|instruction| {
            instruction.implementation.trim() == crate::ast::UNSUPPLIED
        })
        .map(|instruction| instruction.mnemonic.as_str())
        .collect();
    if !implementations.is_empty() {
        for line in [
            "// Performed by routines the embedder defines beside this module,",
            "// each with the signature a generated effect function has:",
            "//   fn <name>(lifted: &Lifted, regs: &mut [u64],",
            "//             mem: &mut dyn WideMemory, pc: u64,",
            "//             state: &mut [State64Entry], result: &mut ExecResult64)",
        ] {
            out.push_str(&format!("        {line}\n"));
        }
    }
    for (mnemonic, symbol) in &implementations {
        out.push_str(&format!(
            "        {} => {{ {symbol}(lifted, regs, mem, pc, state, result); true }},\n",
            json_string(mnemonic)
        ));
    }
    for mnemonic in &unsupplied {
        out.push_str(&format!(
            "        {} => {{ result.trap = Some({}); true }},\n",
            json_string(mnemonic),
            json_string(crate::ast::UNSUPPLIED_TRAP)
        ));
    }
    out.push_str("        _ => false,\n    }\n}\n\n");
    // ⚠️ Placeholders, and only if the build ASKS for them, exactly as the C
    // twin does. Rust has no forward declaration, so a missing routine is a
    // compile error naming the function -- which is the useful answer for
    // someone bringing a machine up, and no answer at all for a harness that
    // holds no key and only needs the module to build. `--cfg axis_impl_stubs`
    // supplies the same trap an instruction with no implementation reports.
    if !implementations.is_empty() {
        out.push_str("// Placeholders for a build that only needs to compile. Each reports the\n// same trap an instruction with no implementation reports; an embedder\n// defines the real ones and drops `--cfg axis_impl_stubs`.\n");
        for (_, symbol) in &implementations {
            out.push_str(&format!(
                "#[cfg(axis_impl_stubs)]\n#[allow(unused_variables)]\nfn {symbol}(lifted: &Lifted, regs: &mut [u64], mem: &mut dyn WideMemory, pc: u64, state: &mut [State64Entry], result: &mut ExecResult64) {{\n    result.trap = Some({});\n}}\n\n",
                json_string(crate::ast::UNSUPPLIED_TRAP)
            ));
        }
    }
    // A scalable word IS its lanes: one decode, `VL/elem` ordinary lane
    // entries, executed in order with the result the last lane's and the
    // writes the union -- the C twin's loop, which this executor never had.
    out.push_str("/// ISA-qualified 64-bit execution with named architectural state.\npub fn step64(word: u32, isa: Option<&str>, regs: &mut [u64], mem: &mut dyn WideMemory, pc: u64, state: &mut [State64Entry]) -> ExecResult64 {\n");
    out.push_str("    let lanes = decode_lanes(word, isa);\n");
    out.push_str("    if lanes.len() <= 1 || lanes[0].scalable_origin.is_empty() {\n        return match lift_in_isa(word, isa) { Some(lifted) => step64_entry(lifted, regs, mem, pc, state), None => ExecResult64 { mnemonic: None, result: None, result_limbs: Vec::new(), wrote: None, state_write: None, next_pc: pc.wrapping_add(AXIS_EXEC_ILEN as u64), trap: None, ok: false } };\n    }\n");
    // ⚠️ Every lane reads the registers and state as they were before the
    // word, as the C twin does (and for the same reason): each lane runs on a
    // copy of the snapshot and merges back the bits it changed.
    out.push_str("    let mut combined: Option<ExecResult64> = None;\n");
    out.push_str("    let snap: Vec<u64> = regs.to_vec();\n    let state_snap: Vec<u64> = state.iter().map(|e| e.value).collect();\n    let mut state_out = state_snap.clone();\n");
    out.push_str("    for entry in lanes.iter() {\n        let mut scratch = snap.clone();\n        for (e, v) in state.iter_mut().zip(&state_snap) { e.value = *v; }\n        let lane = step64_entry(lift_entry(word, entry), &mut scratch, mem, pc, state);\n");
    out.push_str("        for i in 0..regs.len() { let changed = snap[i] ^ scratch[i]; if changed != 0 { regs[i] = (regs[i] & !changed) | (scratch[i] & changed); } }\n");
    out.push_str("        for (i, e) in state.iter().enumerate() { let changed = state_snap[i] ^ e.value; state_out[i] = (state_out[i] & !changed) | (e.value & changed); }\n");
    out.push_str("        let stop = lane.trap.is_some() || !lane.ok;\n");
    out.push_str("        combined = Some(match combined.take() {\n            None => lane,\n            Some(mut so_far) => { so_far.result = lane.result; so_far.ok = lane.ok; if lane.wrote.is_some() { so_far.wrote = lane.wrote; } if !lane.result_limbs.is_empty() { so_far.result_limbs = lane.result_limbs; } if lane.state_write.is_some() { so_far.state_write = lane.state_write; } so_far.next_pc = lane.next_pc; so_far.trap = lane.trap; so_far }\n        });\n");
    out.push_str("        if stop { break; }\n    }\n");
    out.push_str("    for (e, v) in state.iter_mut().zip(&state_out) { e.value = *v; }\n");
    out.push_str("    let mut result = combined.expect(\"a scalable word has at least one lane\");\n    result.mnemonic = Some(lanes[0].scalable_origin);\n    result\n}\n\n");
    out.push_str("fn step64_entry(lifted: Lifted, regs: &mut [u64], mem: &mut dyn WideMemory, pc: u64, state: &mut [State64Entry]) -> ExecResult64 {\n");
    out.push_str("    let mut result = ExecResult64 { mnemonic: None, result: None, result_limbs: Vec::new(), wrote: None, state_write: None, next_pc: pc.wrapping_add(AXIS_EXEC_ILEN as u64), trap: None, ok: false };\n");
    out.push_str("    result.mnemonic = Some(lifted.entry.mnemonic);\n");
    // The counter wraps at the ISA's word, as in the C twin, and can only be
    // masked once the entry says which machine this is.
    out.push_str("    result.next_pc = axis_mask64(pc.wrapping_add(AXIS_EXEC_ILEN as u64), lifted.entry.state_width);\n");
    out.push_str("    if axis_exec_effects64(lifted.entry.mnemonic, &lifted, regs, mem, pc, state, &mut result) { result.ok = true; return result; }\n    if !lifted.entry.liftable { return result; }\n");
    // ⚠️ The wide tier first, as the C twin does, and with the same rule for a
    // NARROW destination: it goes through `write_reg64`, which zeroes the rest
    // of the register on a narrow write. `ADDP_D` reads 128 bits and writes 64.
    out.push_str("    if lifted.entry.operands.iter().any(|op| op.width > 64) {\n");
    out.push_str("        let mut wide_inputs = Vec::new();\n        for (index, operand) in lifted.entry.operands.iter().enumerate() { if operand.role == \"out\" || operand.role == \"enc\" { continue; } let raw = lifted.operands[index].unwrap_or(0); wide_inputs.push(if reg_class_of(operand.kind).is_some() { wide_read_operand(regs, operand, raw, state) } else { wide_of(raw as u64) }); }\n");
    out.push_str("        let value = match axis_exec_eval_wide(lifted.entry.mnemonic, &wide_inputs) { Some(value) => value, None => return result };\n");
    out.push_str("        result.result = Some(wide_low(value)); result.ok = true;\n");
    out.push_str("        for (index, operand) in lifted.entry.operands.iter().enumerate() {\n            if operand.role == \"in\" || reg_class_of(operand.kind).is_none() { continue; }\n            let dest = lifted.operands[index].unwrap_or(0);\n            if operand.width > 64 {\n                let limbs = ((operand.width + 63) / 64) as usize;\n                let limbs = if limbs > AXIS_WIDE_LIMBS { AXIS_WIDE_LIMBS } else { limbs };\n                if write_limbs64(regs, dest, operand.kind, &value.limb[..limbs]) { result.wrote = Some(dest); }\n                result.result_limbs = value.limb[..limbs].to_vec();\n            } else if write_reg64(regs, dest, operand.kind, wide_low(value), state) { result.wrote = Some(dest); }\n        }\n        return result;\n    }\n");
    // ⚠️ `enc` operands are encoded and read by nothing -- a lane's origin
    // operands are this -- so they are neither inputs nor destinations. A
    // scalar instruction has none, which is why feeding and writing them went
    // unnoticed until lanes ran.
    out.push_str("    let mut inputs = Vec::new();\n    for (index, operand) in lifted.entry.operands.iter().enumerate() { if operand.role == \"out\" || operand.role == \"enc\" { continue; } let raw = lifted.operands[index].unwrap_or(0); inputs.push(if reg_class_of(operand.kind).is_some() { read_operand64(regs, operand, raw, state) } else { raw as u64 }); }\n");
    out.push_str("    let value = match axis_exec_eval64(lifted.entry.mnemonic, &inputs) { Some(value) => value, None => return result }; result.result = Some(value); result.ok = true;\n");
    out.push_str("    for (index, operand) in lifted.entry.operands.iter().enumerate() { if (operand.role == \"out\" || operand.role == \"inout\") && reg_class_of(operand.kind).is_some() { let dest = lifted.operands[index].unwrap_or(0); if write_operand64(regs, operand, dest, value, state) { result.wrote = Some(dest); } } }\n    result\n}\n");
}

/// Why the Rust executor cannot perform this instruction.
///
/// Said in the emitted file rather than only in a gate's decline line. Each
/// reason is a property of the language rather than of this emitter, which is
/// what makes naming it worth more than a bare omission.
fn rust_effect_refusal(instruction: &Instruction) -> String {
    let Some(behavior) = instruction.behavior.as_ref() else {
        return "no behavior to perform".to_string();
    };
    let text = behavior
        .effects
        .iter()
        .map(|effect| crate::effects::render_semantic_expr(&effect.value.expr))
        .collect::<Vec<_>>()
        .join(" ");
    // Rust's f64 is round-to-nearest-even and `std` exposes no `fesetround`.
    // Reaching for libc would put an FFI dependency in a file whose value is
    // being dependency-free, and doing directed rounding arithmetically is the
    // second unproven model of arithmetic that docs/simd_fp_design.md section
    // 8.4 rules out. The C twin has fesetround, which is why it emits these.
    if text.contains("_rm ") {
        return "directed rounding: Rust's f64 rounds to nearest-even and std has \
                no fesetround (docs/simd_fp_design.md section 8.4)"
            .to_string();
    }
    if crate::emit::semantics::uses_fp_exceptions(&text) {
        return "floating-point exceptions are read from an environment this \
                executor does not carry"
            .to_string();
    }
    if wider_than_word64(instruction) {
        return "a value wider than this executor's 64-bit word: its registers, \
                its operand reads and its memory interface are all u64"
            .to_string();
    }
    "an effect this emitter has no form for".to_string()
}

/// The limb-wise read of a wide load in Rust, mirroring `c_wide_limb_load`.
/// The Rust twin of `c_limb_expr`, operator for operator.
///
/// Kept as a separate small function for the reason the C one is: the wide set
/// is what the descriptions use, and an operator outside it declines rather
/// than being given a limb meaning nobody asked for.
fn rust_limb_expr(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    ambient_width: u32,
) -> Option<String> {
    match expr {
        SemanticExpr::Atom(atom) => {
            if let Some((_, value)) = bindings.iter().find(|(name, _)| name == atom) {
                return Some(value.clone());
            }
            if let Some(value) = crate::ir::integer_literal(atom) {
                let mut limbs: Vec<String> = Vec::new();
                let mut rest = value;
                while rest > 0 {
                    limbs.push(format!("{}u64", rest & u128::from(u64::MAX)));
                    rest >>= 64;
                }
                if limbs.is_empty() {
                    limbs.push("0u64".to_string());
                }
                return Some(format!("wide_lit{}({})", limbs.len(), limbs.join(", ")));
            }
            None
        }
        SemanticExpr::List(items) => {
            let SemanticExpr::Atom(op) = items.first()? else {
                return None;
            };
            let mut args = &items[1..];
            let mut width = ambient_width;
            if let Some(SemanticExpr::Atom(first)) = args.first() {
                if let Some(bits) = crate::ir::type_atom_bits(first) {
                    width = bits;
                    args = &args[1..];
                }
            }
            let values: Vec<String> = args
                .iter()
                .map(|arg| rust_limb_expr(arg, bindings, width))
                .collect::<Option<Vec<_>>>()?;
            let two = |call: &str| {
                Some(format!(
                    "{call}({}, {}, {width})",
                    values.first()?,
                    values.get(1)?
                ))
            };
            match op.as_str() {
                "and" => Some(fold(&values, "wide_and")),
                "or" => Some(fold(&values, "wide_or")),
                "xor" => Some(fold(&values, "wide_xor")),
                "not" => Some(format!("wide_not({}, {width})", values.first()?)),
                "add" => two("wide_add"),
                "sub" => two("wide_sub"),
                "mul" => two("wide_mul"),
                "shl" | "sll" => Some(format!(
                    "wide_shl({}, wide_low({}), {width})",
                    values.first()?,
                    values.get(1)?
                )),
                "lshr" | "srl" => Some(format!(
                    "wide_lshr({}, wide_low({}), {width})",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_eq" => Some(format!(
                    "wide_of(wide_eq(wide_mask({}, {width}), wide_mask({}, {width})) as u64)",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_ne" => Some(format!(
                    "wide_of(!wide_eq(wide_mask({}, {width}), wide_mask({}, {width})) as u64)",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_ult" => Some(format!(
                    "wide_of(wide_ult(wide_mask({}, {width}), wide_mask({}, {width})) as u64)",
                    values.first()?,
                    values.get(1)?
                )),
                "icmp_uge" => Some(format!(
                    "wide_of(!wide_ult(wide_mask({}, {width}), wide_mask({}, {width})) as u64)",
                    values.first()?,
                    values.get(1)?
                )),
                "if" | "select" => Some(format!(
                    "(if wide_nonzero({}) {{ {} }} else {{ {} }})",
                    values.first()?,
                    values.get(1)?,
                    values.get(2)?
                )),
                _ => None,
            }
        }
    }
}

fn rust_wide_limb_load(
    value: &crate::effects::EffectExpr,
    bindings: &[(String, String)],
    width: u32,
) -> Option<String> {
    let SemanticExpr::List(items) = &value.expr else {
        return None;
    };
    if !matches!(items.first(), Some(SemanticExpr::Atom(op))
        if matches!(op.as_str(), "load" | "atomic_load"))
        || !matches!(items.len(), 4 | 5)
    {
        return None;
    }
    if load_access_width(&items[1])? != width {
        return None;
    }
    let address_width = value.load_address_width?;
    let addr = rust_wide_expr(items.last()?, bindings, address_width)?;
    Some(format!(
        "          mem.read_limbs64(axis_mask64({addr}, {address_width}), {width}, &mut limb);\n"
    ))
}

/// The Rust statements that perform `loads[from..]`, in order -- the twin of
/// `c_hoisted_prelude`. Each address is bound before its read for the reason
/// the inline arm binds `__addr`: `read64` borrows the memory mutably.
fn rust_hoisted_prelude(
    loads: &[HoistedLoad],
    from: usize,
    bindings: &[(String, String)],
    address_width: u32,
) -> Option<String> {
    let mut out = String::new();
    for (index, load) in loads.iter().enumerate().skip(from) {
        let addr = rust_wide_expr_at(&load.address, bindings, address_width, address_width)?;
        out.push_str(&format!(
            "        let axis_ld{index}: u64 = {{ let __addr = axis_mask64({addr}, {address_width}); axis_mask64(mem.read64(__addr, {}), {}) }};\n",
            load.access, load.access
        ));
    }
    Some(out)
}

fn emit_rust_effect64_fn(instruction: &Instruction) -> Option<String> {
    use crate::effects::Loc;
    if !crate::effects::behavior_is_authoritative(instruction) {
        return None;
    }
    // No blanket refusal: the wide arms below decline what they cannot do, as
    // the C twin's do.
    let behavior = instruction.behavior.as_ref()?;
    let mut input_prelude = String::new();
    let mut bindings: Vec<(String, String)> = instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        .map(|operand| {
            let pos = instruction
                .operands
                .iter()
                .position(|candidate| candidate.name == operand.name)
                .unwrap();
            let expression = if operand.kind == "imm" {
                format!("lifted.operands[{pos}].unwrap_or(0) as u64")
            } else {
                format!(
                    "read_operand64(regs, &lifted.entry.operands[{pos}], lifted.operands[{pos}].unwrap_or(0), state)"
                )
            };
            let value = format!("axis_input_{pos}");
            input_prelude.push_str(&format!(
                "    let {}{value} = {expression};\n",
                if operand.output { "mut " } else { "" }
            ));
            (operand.name.clone(), value)
        })
        .collect();
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        let pos = instruction
            .operands
            .iter()
            .position(|candidate| candidate.name == operand.name)?;
        let entry = format!("axis_entry_{pos}");
        input_prelude.push_str(&format!("    let {entry} = axis_input_{pos};\n"));
        bindings.push((format!("__input_{}", operand.name), entry));
    }
    for (pos, operand) in instruction.operands.iter().enumerate() {
        if operand.output && !operand.input {
            input_prelude.push_str(&format!("    let mut axis_output_{pos} = 0u64;\n"));
        }
    }
    let mut body = String::new();
    for original in &behavior.effects {
        // Hoisted as in the C emitter; see `HoistedLoad`.
        let mut loads: Vec<HoistedLoad> = Vec::new();
        let mut effect = original.clone();
        if let Some(guard) = &mut effect.guard {
            guard.expr = hoist_loads(&guard.expr, &mut loads, false)?;
        }
        let guard_prelude = match &original.guard {
            Some(guard) => rust_hoisted_prelude(&loads, 0, &bindings, guard.load_address_width.unwrap_or(64))?,
            None => String::new(),
        };
        let mut body_prelude = String::new();
        if let Loc::Mem { addr, .. } = &mut effect.loc {
            let from = loads.len();
            addr.expr = hoist_loads(&addr.expr, &mut loads, false)?;
            body_prelude.push_str(&rust_hoisted_prelude(&loads, from, &bindings, addr.load_address_width.unwrap_or(64))?);
        }
        if !matches!(effect.loc, Loc::Trap) {
            let from = loads.len();
            effect.value.expr = hoist_loads(&effect.value.expr, &mut loads, true)?;
            body_prelude.push_str(&rust_hoisted_prelude(&loads, from, &bindings, effect.value.load_address_width.unwrap_or(64))?);
        }
        let effect = &effect;
        let mut inner = match &effect.loc {
            Loc::Reg(dest) => {
                let pos = instruction
                    .operands
                    .iter()
                    .position(|op| &op.name == dest)?;
                let operand = &instruction.operands[pos];
                let semantic_value = if operand.input {
                    format!("axis_input_{pos}")
                } else {
                    format!("axis_output_{pos}")
                };
                // The wide twin of the C arm: limbs out of memory, limbs
                // into the file. Anything but a move of the same width is
                // declined -- arithmetic computes at its own width, and this
                // executor has none wider than a word.
                if operand.width > 64 {
                    let load = rust_wide_limb_load(&effect.value, &bindings, operand.width)?;
                    let limbs = operand.width.div_ceil(64) as usize;
                    body.push_str(&format!(
                        "        {{ let mut limb = vec![0u64; {limbs}];\n{load}          let dest = lifted.operands[{pos}].unwrap_or(0);\n          if write_limbs64(regs, dest, {}, &limb) {{ result.wrote = Some(dest); }}\n          result.result = Some(limb[0]); result.result_limbs = limb; }}\n",
                        json_string(&operand.kind)
                    ));
                    continue;
                }
                let value = rust_wide_effect_value(&effect.value, &bindings, operand.width)?;
                if let Some((_, binding)) = bindings.iter_mut().find(|(name, _)| name == dest) {
                    *binding = semantic_value.clone();
                } else {
                    bindings.push((dest.clone(), semantic_value.clone()));
                }
                format!("        let value = {value}; let dest = lifted.operands[{pos}].unwrap_or(0); if write_operand64(regs, &lifted.entry.operands[{pos}], dest, value, state) {{ result.wrote = Some(dest); }} {semantic_value} = value; result.result = Some(value);\n")
            }
            Loc::FixedReg {
                kind,
                index,
                width: _,
            } => {
                let value = rust_wide_expr(&effect.value.expr, &bindings, effect.value.width)?;
                format!("        let value = {value}; let dest = {index}; if write_reg64(regs, dest, {}, value, state) {{ result.wrote = Some(dest); }} result.result = Some(value);\n", json_string(kind))
            }
            Loc::State { name, width } => {
                // `rust_wide_effect_value`, as the store arm below uses: a state
                // write's value may be a LOAD. An exclusive monitor recording
                // what it observed is exactly that. Third emitter to need this
                // -- LLVM, C, and now Rust -- for one gap in one shape.
                let value = rust_wide_effect_value(&effect.value, &bindings, effect.value.width)?;
                format!("        let value = axis_mask64({value}, {width}); state64_write(state, {}, value, {width}); result.state_write = Some(({}, value));\n", json_string(name), json_string(name))
            }
            Loc::Mem { addr, width, .. } => {
                // The address wraps at its own width, as it does for a load.
                let address_width = addr.width;
                let addr = rust_wide_expr(&addr.expr, &bindings, address_width)?;
                let addr = format!("axis_mask64({addr}, {address_width})");
                if *width > 64 {
                    let source = wide_source_operand(instruction, &effect.value)?;
                    let kind = &instruction.operands[source].kind;
                    let limbs = width.div_ceil(64) as usize;
                    body.push_str(&format!(
                        "        {{ let addr = {addr}; let src = lifted.operands[{source}].unwrap_or(0);\n          let limb = read_limbs64(regs, src, {}, {limbs});\n          mem.write_limbs64(addr, {width}, &limb); }}\n",
                        json_string(kind)
                    ));
                    continue;
                }
                let value = rust_wide_effect_value(&effect.value, &bindings, *width)?;
                // Bound to locals before the write, because a stored value may
                // itself be a load and `mem.write64(a, mem.read64(..))` borrows
                // the memory mutably twice. C has no such rule, so this is the
                // one place the two wide emitters must differ in shape rather
                // than only in syntax. Address first, then value, matching the
                // order the reference model evaluates them in.
                format!(
                    "        {{ let addr = {addr}; let value = {value}; \
                     mem.write64(addr, axis_mask64(value, {width}), {width}); }}\n"
                )
            }
            Loc::Port { port, width } => {
                let destination = rust_wide_expr(&port.expr, &bindings, port.width.max(1))?;
                let value = rust_wide_expr(&effect.value.expr, &bindings, *width)?;
                format!(
                    "        {{ let _p = axis_mask64({destination}, {}u); let _v = axis_mask64({value}, {width}u); mem.send64(_p, _v, {width}u); }}\n",
                    port.width.max(1)
                )
            }
            Loc::Barrier { .. } => {
                let value = rust_wide_expr(&effect.value.expr, &bindings, effect.value.width)?;
                format!("        let _barrier_option = {value};\n")
            }
            Loc::Pc => {
                let value = rust_wide_expr(&effect.value.expr, &bindings, effect.value.width)?;
                format!("        result.next_pc = axis_mask64({value}, lifted.entry.state_width);\n")
            }
            Loc::Trap => format!(
                "        result.trap = Some({}); return;\n",
                json_string(&crate::effects::render_semexpr(&effect.value.expr))
            ),
        };
        inner = format!("{body_prelude}{inner}");
        if let Some(guard) = &effect.guard {
            let guard = rust_wide_guard_expr(&guard.expr, &bindings, guard.width)?;
            inner = format!("    {{\n{guard_prelude}    if {guard} {{\n{inner}    }}\n    }}\n");
        } else {
            inner = format!("    {{\n{inner}    }}\n");
        }
        body.push_str(&inner);
    }
    let ident = python_ident(&instruction.mnemonic);
    Some(format!("#[allow(unused_variables)]\nfn axis_exec64_eff_{ident}(lifted: &Lifted, regs: &mut [u64], mem: &mut dyn WideMemory, pc: u64, state: &mut [State64Entry], result: &mut ExecResult64) {{\n{input_prelude}{body}}}\n\n"))
}

fn rust_wide_guard_expr(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    width: u32,
) -> Option<String> {
    let SemanticExpr::List(items) = expr else {
        return None;
    };
    let SemanticExpr::Atom(op) = items.first()? else {
        return None;
    };
    if matches!(op.as_str(), "and" | "or") && items.len() >= 3 {
        let joiner = if op == "and" { " && " } else { " || " };
        return Some(format!(
            "({})",
            items[1..]
                .iter()
                .map(|child| rust_wide_guard_expr(child, bindings, width))
                .collect::<Option<Vec<_>>>()?
                .join(joiner)
        ));
    }
    if op == "not" && items.len() == 2 {
        return Some(format!(
            "!({})",
            rust_wide_guard_expr(&items[1], bindings, width)?
        ));
    }
    if let Some((cmp, signed)) = comparison_spelling(op.as_str()) {
        if items.len() == 3 {
            let side = |text: String| {
                if signed {
                    format!("axis_signed64({text}, {width})")
                } else {
                    format!("axis_mask64({text}, {width})")
                }
            };
            return Some(format!(
                "{} {cmp} {}",
                side(rust_wide_expr(&items[1], bindings, width)?),
                side(rust_wide_expr(&items[2], bindings, width)?)
            ));
        }
    }
    None
}

/// The Rust counterpart of `c_wide_effect_value`, and for the same reason: a
/// load has no place in `rust_wide_expr`, which the pure evaluator shares.
fn rust_wide_effect_value(
    value: &crate::effects::EffectExpr,
    bindings: &[(String, String)],
    target_width: u32,
) -> Option<String> {
    if let SemanticExpr::List(items) = &value.expr {
        if matches!(items.first(), Some(SemanticExpr::Atom(op))
            if matches!(op.as_str(), "load" | "atomic_load"))
            && matches!(items.len(), 4 | 5)
        {
            let access = load_access_width(&items[1])?;
            let signed = matches!(&items[2], SemanticExpr::Atom(sign) if sign == "signed");
            // Masked to the address's own width, as in the C twin.
            let address_width = value.load_address_width?;
            let addr = rust_wide_expr(items.last()?, bindings, address_width)?;
            // ⚠️ Bound first, like the general arm: this address may itself
            // contain a load now -- a pointer chase is `(load (load rs1))` --
            // and `read64` takes `&mut self`, so evaluating the inner read as
            // an argument to the outer one borrows `mem` twice at once.
            // ⚠️ The binding is emitted ONLY when the address itself reads
            // memory. `read64` takes `&mut self`, so a pointer chase --
            // `mem.read64(mem.read64(x, 8), 8)` -- holds the outer borrow
            // while the inner one starts and rustc refuses it; the `let` ends
            // the inner borrow first. Every other load keeps the spelling it
            // had, which is what leaves the existing artifacts untouched.
            let masked = format!("axis_mask64({addr}, {address_width})");
            if crate::effects::expr_reads_memory(items.last()?) {
                let read = if signed {
                    format!(
                        "axis_sext64(mem.read64(__addr, {access}), {access}, {target_width})"
                    )
                } else {
                    format!("axis_mask64(mem.read64(__addr, {access}), {target_width})")
                };
                return Some(format!("{{ let __addr = {masked}; {read} }}"));
            }
            return Some(if signed {
                format!("axis_sext64(mem.read64({masked}, {access}), {access}, {target_width})")
            } else {
                format!("axis_mask64(mem.read64({masked}, {access}), {target_width})")
            });
        }
    }
    rust_wide_expr(&value.expr, bindings, value.width)
}

fn rust_wide_expr(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    ambient_width: u32,
) -> Option<String> {
    rust_wide_expr_at(expr, bindings, ambient_width, 64)
}

/// The Rust twin of `c_wide_expr_at`: the width a load's address wraps at,
/// carried down rather than assumed.
fn rust_wide_expr_at(
    expr: &SemanticExpr,
    bindings: &[(String, String)],
    ambient_width: u32,
    address_width: u32,
) -> Option<String> {
    match expr {
        SemanticExpr::Atom(atom) => {
            if let Some((_, value)) = bindings.iter().find(|(name, _)| name == atom) {
                return Some(value.clone());
            }
            if atom == "pc" {
                return Some("pc".to_string());
            }
            if let Some(value) = crate::ir::integer_literal(atom) {
                // The same limit as the C tier, for the same reason: this
                // executor's word is `u64`, and `rustc` says so -- "literal out
                // of range for `u64`".
                if value > u128::from(u64::MAX) {
                    return None;
                }
                return Some(format!("{value}u64"));
            }
            Some(format!("state64_read(state, {})", json_string(atom)))
        }
        SemanticExpr::List(items) => {
            let SemanticExpr::Atom(op) = items.first()? else {
                return None;
            };
            if op == "call" {
                let SemanticExpr::Atom(name) = items.get(1)? else {
                    return None;
                };
                let mut args = Vec::new();
                for arg in &items[3..] {
                    let SemanticExpr::List(pair) = arg else { return None };
                    let (SemanticExpr::Atom(ty), value) = (pair.first()?, pair.get(1)?) else { return None };
                    let param = crate::ir::type_atom_width(ty)?;
                    if param > 64 {
                        return None;
                    }
                    let value = rust_wide_expr_at(value, bindings, param, address_width)?;
                    args.push(format!("axis_mask64({value}, {param})"));
                }
                return Some(format!(
                    "axis_fn64_{}({})",
                    crate::emit::semantics::function_ident(name),
                    args.join(", ")
                ));
            }
            // The Rust twin of the C wide lowering: the register file is here,
            // so a named register read is an ordinary call.
            if op == "getreg" {
                let [SemanticExpr::Atom(kind), SemanticExpr::Atom(index)] = &items[1..] else {
                    return None;
                };
                let index: u32 = index.parse().ok()?;
                return Some(format!("read_reg64(regs, {index}, {}, state)", c_string(kind)));
            }
            if op == "__hoisted" {
                let [SemanticExpr::Atom(index), SemanticExpr::Atom(access), SemanticExpr::Atom(signed)] =
                    &items[1..]
                else {
                    return None;
                };
                return Some(if signed == "1" {
                    format!("axis_sext64(axis_ld{index}, {access}, {ambient_width})")
                } else {
                    format!("axis_ld{index}")
                });
            }
            // The Rust twin of the C arm: a load anywhere, not only as a whole
            // effect value. Both executors declined every instruction with a
            // second load until this existed.
            if matches!(op.as_str(), "load" | "atomic_load") && matches!(items.len(), 4 | 5) {
                let access = load_access_width(&items[1])?;
                let signed =
                    matches!(&items[2], SemanticExpr::Atom(sign) if sign == "signed");
                let addr = rust_wide_expr_at(items.last()?, bindings, address_width, address_width)?;
                // ⚠️ The address is bound to a local FIRST, and the read
                // happens after. `read64` takes `&mut self`, so a pointer
                // chase -- `mem.read64(mem.read64(x, 8), 8)` -- holds the
                // outer borrow while the inner one starts, and rustc refuses
                // it: "cannot borrow `*mem` as mutable more than once". The
                // `let` ends the inner borrow before the outer begins. The C
                // twin needs none of this and so does not have it.
                let masked = format!("axis_mask64({addr}, {address_width})");
                if crate::effects::expr_reads_memory(items.last()?) {
                    let read = if signed {
                        format!(
                            "axis_sext64(mem.read64(__addr, {access}), {access}, {ambient_width})"
                        )
                    } else {
                        format!("axis_mask64(mem.read64(__addr, {access}), {access})")
                    };
                    return Some(format!("{{ let __addr = {masked}; {read} }}"));
                }
                return Some(if signed {
                    format!(
                        "axis_sext64(mem.read64({masked}, {access}), {access}, {ambient_width})"
                    )
                } else {
                    format!("axis_mask64(mem.read64({masked}, {access}), {access})")
                });
            }
            if op == "input" {
                let [SemanticExpr::Atom(name)] = &items[1..] else {
                    return None;
                };
                return bindings
                    .iter()
                    .find(|(candidate, _)| candidate == &format!("__input_{name}"))
                    .map(|(_, value)| value.clone());
            }
            if op == "let" {
                let [SemanticExpr::List(raw_bindings), body] = &items[1..] else {
                    return None;
                };
                // ⚠️ SEQUENTIAL, for the same reason as the C twin above.
                let mut extended = bindings.to_vec();
                for binding in raw_bindings {
                    let SemanticExpr::List(pair) = binding else {
                        return None;
                    };
                    let [SemanticExpr::Atom(name), value] = &pair[..] else {
                        return None;
                    };
                    let value = rust_wide_expr_at(value, &extended, ambient_width, address_width)?;
                    extended.push((name.clone(), value));
                }
                return rust_wide_expr_at(body, &extended, ambient_width, address_width);
            }
            let mut args = &items[1..];
            let mut width = ambient_width;
            if let Some(SemanticExpr::Atom(ty)) = args.first() {
                // Shared with the typed IR: a local copy of this test is what
                // let `f64` through as a symbol when float operators arrived.
                if let Some(bits) = crate::ir::type_atom_bits(ty) {
                    width = bits;
                    args = &args[1..];
                }
            }
            let values: Vec<String> = args
                .iter()
                .map(|arg| rust_wide_expr_at(arg, bindings, width, address_width))
                .collect::<Option<_>>()?;
            let binary = |method: &str| {
                Some(format!(
                    "axis_mask64(({}).{method}({}), {width})",
                    values[0], values[1]
                ))
            };
            match op.as_str() {
                "add" => Some(format!(
                    "axis_mask64({}, {width})",
                    values.iter().skip(1).fold(values[0].clone(), |sum, value| {
                        format!("({sum}).wrapping_add({value})")
                    })
                )),
                "sub" => binary("wrapping_sub"),
                "mul" => binary("wrapping_mul"),
                "udiv" => Some(format!(
                    "axis_udiv64({}, {}, {width})",
                    values[0], values[1]
                )),
                "sdiv" => Some(format!(
                    "axis_sdiv64({}, {}, {width})",
                    values[0], values[1]
                )),
                "min" => Some(format!(
                    "axis_minmax64({}, {}, {width}, true, false)",
                    values[0], values[1]
                )),
                "max" => Some(format!(
                    "axis_minmax64({}, {}, {width}, true, true)",
                    values[0], values[1]
                )),
                "minu" => Some(format!(
                    "axis_minmax64({}, {}, {width}, false, false)",
                    values[0], values[1]
                )),
                "maxu" => Some(format!(
                    "axis_minmax64({}, {}, {width}, false, true)",
                    values[0], values[1]
                )),
                "and" | "or" | "xor" => {
                    let token = match op.as_str() {
                        "and" => " & ",
                        "or" => " | ",
                        _ => " ^ ",
                    };
                    Some(format!(
                        "axis_mask64({}, {width})",
                        values
                            .iter()
                            .map(|value| format!("({value})"))
                            .collect::<Vec<_>>()
                            .join(token)
                    ))
                }
                "not" => Some(format!("axis_mask64(!({}), {width})", values[0])),
                "if" | "select" => Some(format!(
                    "if ({}) != 0 {{ {} }} else {{ {} }}",
                    values[0], values[1], values[2]
                )),
                "shl" | "sll" => Some(format!(
                    "axis_shl64({}, {}, {width})",
                    values[0], values[1]
                )),
                "lshr" | "srl" => Some(format!(
                    "axis_lshr64({}, {}, {width})",
                    values[0], values[1]
                )),
                "ashr" | "sra" => Some(format!(
                    "axis_ashr64({}, {}, {width})",
                    values[0], values[1]
                )),
                "clz" => Some(format!("axis_clz64({}, {width})", values[0])),
                "ctz" => Some(format!("axis_ctz64({}, {width})", values[0])),
                "cpop" => Some(format!("axis_cpop64({}, {width})", values[0])),
                "rol" => Some(format!("axis_rotl64({}, {}, {width})", values[0], values[1])),
                "ror" => Some(format!("axis_rotr64({}, {}, {width})", values[0], values[1])),
                "sext" => Some(format!(
                    "axis_sext64({}, {} as u32, {width})",
                    values[1], values[0]
                )),
                "zext" => Some(format!("axis_mask64({}, {} as u32)", values[1], values[0])),
                // The float conversions, mirroring the C wide lowering. The
                // source width is read off the literal for the same reason:
                // whether the input is a single or a double decides which
                // `from_bits` reads it, and that is an emit-time choice.
                "fcvt_f2s" | "fcvt_f2u" | "fcvt_s2f" | "fcvt_u2f" | "fcvt_f2f" => {
                    let source = match args.first() {
                        Some(SemanticExpr::Atom(text)) => crate::ir::integer_literal(text)? as u32,
                        _ => return None,
                    };
                    let value = &values[1];
                    Some(match op.as_str() {
                        // The semantics backend's readers and writers, as in
                        // the C arm: `source > 32` read a half as a single.
                        "fcvt_f2s" | "fcvt_f2u" => {
                            crate::ir::float_format(source)?;
                            let float = super::semantics::rust_read_float(value, source);
                            if op == "fcvt_f2s" {
                                format!("((({float}) as i{width}) as u{width}) as u64")
                            } else {
                                format!("(({float}) as u{width}) as u64")
                            }
                        }
                        "fcvt_s2f" | "fcvt_u2f" => {
                            // One rounding, as above.
                            let numeric = if op == "fcvt_s2f" {
                                format!("axis_fp_signed({value} as u64, {source})")
                            } else {
                                format!("axis_fp_mask({value} as u64, {source})")
                            };
                            crate::ir::float_format(width)?;
                            super::semantics::rust_write_float(&numeric, width, 64)
                        }
                        _ => {
                            crate::ir::float_format(source)?;
                            crate::ir::float_format(width)?;
                            super::semantics::rust_write_float(
                                &super::semantics::rust_read_float(value, source),
                                width,
                                64,
                            )
                        }
                    })
                }
                "ones" => Some(match values.first() {
                    Some(count) => format!("axis_ones({count} as u64, {width})"),
                    None => format!("axis_ones({width}u64, {width})"),
                }),
                "zeros" => Some("0u64".to_string()),
                "mulh" => Some(format!("axis_mulh64({}, {}, {width}, true, true)", values[0], values[1])),
                "mulhu" => Some(format!("axis_mulh64({}, {}, {width}, false, false)", values[0], values[1])),
                "mulhsu" => Some(format!("axis_mulh64({}, {}, {width}, true, false)", values[0], values[1])),
                // Masked for the same reason as the ordered comparisons below.
                "icmp_eq" => Some(format!(
                    "((axis_mask64({}, {width})) == (axis_mask64({}, {width}))) as u64",
                    values[0], values[1]
                )),
                "icmp_ne" => Some(format!(
                    "((axis_mask64({}, {width})) != (axis_mask64({}, {width}))) as u64",
                    values[0], values[1]
                )),
                // The ordered comparisons were absent, so SLT/SLTI/SLTU/SLTIU
                // had no wide Rust evaluation and declined. Signed ones compare
                // through axis_signed64 at the evaluation width, unsigned ones
                // compare the masked values directly -- which is what the C
                // wide evaluator has always done.
                "icmp_slt" => Some(format!(
                    "((axis_signed64({}, {width})) < (axis_signed64({}, {width}))) as u64",
                    values[0], values[1]
                )),
                "icmp_sge" => Some(format!(
                    "((axis_signed64({}, {width})) >= (axis_signed64({}, {width}))) as u64",
                    values[0], values[1]
                )),
                "icmp_ult" => Some(format!(
                    "((axis_mask64({}, {width})) < (axis_mask64({}, {width}))) as u64",
                    values[0], values[1]
                )),
                "icmp_uge" => Some(format!(
                    "((axis_mask64({}, {width})) >= (axis_mask64({}, {width}))) as u64",
                    values[0], values[1]
                )),
                "a64_add_nzcv" => Some(format!(
                    "a64_add_nzcv({}, {}, {width})",
                    values[0], values[1]
                )),
                "a64_adc_nzcv" => Some(format!(
                    "a64_adc_nzcv({}, {}, {}, {width})",
                    values[0], values[1], values[2]
                )),
                "a64_sbc_nzcv" => Some(format!(
                    "a64_sbc_nzcv({}, {}, {}, {width})",
                    values[0], values[1], values[2]
                )),
                "a64_umulh" => Some(format!("a64_umulh({}, {})", values[0], values[1])),
                "a64_smulh" => Some(format!("a64_smulh({}, {})", values[0], values[1])),
                "a64_sub_nzcv" => Some(format!(
                    "a64_sub_nzcv({}, {}, {width})",
                    values[0], values[1]
                )),
                "fadd" | "fsub" | "fmul" | "fdiv" | "fsqrt" | "fneg" | "fma" | "fcmp_oeq"
                | "fcmp_olt" | "fcmp_ole" | "fcmp_uno" => {
                    let name = match op.as_str() {
                        "fcmp_oeq" => "eq",
                        "fcmp_olt" => "lt",
                        "fcmp_ole" => "le",
                        "fcmp_uno" => "uno",
                        "fsqrt" => "sqrt",
                        "fneg" => "neg",
                        "fma" => "fma",
                        other => &other[1..],
                    };
                    // The format from the table, as in the C arm above.
                    let bits = crate::ir::float_format(width)?.bits;
                    let arguments = values
                        .iter()
                        .map(|value| match bits {
                            16 => format!("({value}) as u16"),
                            32 => format!("({value}) as u32"),
                            _ => value.clone(),
                        })
                        .collect::<Vec<_>>()
                        .join(", ");
                    Some(format!("axis_fp{bits}_{name}({arguments}) as u64"))
                }
                "a64_logic_nzcv" => Some(format!("a64_logic_nzcv({}, {width})", values[0])),
                "a64_cond_holds" => Some(format!("a64_cond_holds({}, {})", values[0], values[1])),
                "a64_shift_reg" => Some(format!(
                    "a64_shift_reg({}, {}, {}, {width})",
                    values[0], values[1], values[2]
                )),
                "a64_extend_reg" => Some(format!(
                    "a64_extend_reg({}, {}, {}, {width})",
                    values[0], values[1], values[2]
                )),
                "a64_wmask" => Some(format!(
                    "a64_wmask({}, {}, {}, {width})",
                    values[0], values[1], values[2]
                )),
                "a64_ubfm" => Some(format!(
                    "a64_ubfm({}, {}, {}, {width})",
                    values[0], values[1], values[2]
                )),
                "a64_sbfm" => Some(format!(
                    "a64_sbfm({}, {}, {}, {width})",
                    values[0], values[1], values[2]
                )),
                "a64_bfm" => Some(format!(
                    "a64_bfm({}, {}, {}, {}, {width})",
                    values[0], values[1], values[2], values[3]
                )),
                _ => None,
            }
        }
    }
}

/// Generate the Rust effect function for an instruction with effects (E1-E4),
/// or `None` for pure instructions (and effects Rust cannot express: operands
/// wider than 32 bits, or a subexpression that does not lower). Runs the effect
/// list in order against `regs`/`mem`/`pc`, honoring per-effect guards, and
/// fills `ExecResult`. The safe-Rust sibling of `emit_c_effect_fn`; value/address
/// subexpressions reuse `rust_lower`, guards lower to `==`/`!=` comparisons.
fn emit_rust_effect_fn(instruction: &Instruction, state_names: &[String]) -> Option<String> {
    if !crate::effects::behavior_is_authoritative(instruction) {
        return None;
    }
    let behavior = instruction.behavior.as_ref()?;
    if behavior_reads_state(behavior, state_names) {
        return None;
    }
    if instruction
        .operands
        .iter()
        .any(|operand| operand.width > 32)
    {
        return None;
    }
    let ident = python_ident(&instruction.mnemonic);

    // Bind each input operand value by name: register operands dereference
    // `regs[index]`, immediates use their decoded value.
    let mut body = String::new();
    for (pos, operand) in instruction.operands.iter().enumerate() {
        // Output registers are bound to their entry value and reassigned by the
        // `set` that writes them, so a later effect reads what an earlier one
        // wrote — the C emitter's binder and the LLVM rename map do the same.
        if operand.output && !crate::ast::is_register_kind(&operand.kind) {
            continue;
        }
        if crate::ast::is_register_kind(&operand.kind) {
            let mutability = if operand.output { "let mut " } else { "let " };
            let class = crate::ast::register_class(&operand.kind);
            let offset = class.map(|class| class.offset).unwrap_or(0);
            let limbs = class.map(|class| class.limbs.max(1)).unwrap_or(1) as usize;
            body.push_str(&format!(
                "    {mutability}{name} = {{ let _i = lifted.operands[{pos}].unwrap_or(0) as usize * {limbs} + {offset}; if _i < regs.len() {{ regs[_i] }} else {{ 0 }} }};\n    let _ = {name};\n",
                name = operand.name
            ));
        } else {
            body.push_str(&format!(
                "    let {name} = lifted.operands[{pos}].unwrap_or(0);\n",
                name = operand.name
            ));
        }
    }

    for effect in &behavior.effects {
        let inner = emit_rust_effect_body(instruction, effect)?;
        match &effect.guard {
            Some(guard) => {
                let cond = rust_guard_expr(&guard.expr, guard.width)?;
                body.push_str(&format!("    if {cond} {{\n{inner}    }}\n"));
            }
            None => body.push_str(&inner),
        }
    }

    Some(format!(
        "#[allow(unused_variables, unused_parens, unused_mut)]\nfn axis_exec_eff_{ident}(lifted: &Lifted, regs: &mut [u32], mem: &mut dyn Memory, pc: u32, r: &mut ExecResult) {{\n{body}}}\n\n"
    ))
}

/// Whether the behavior reads any ISA-declared scalar state atom. The compact
/// 32-bit executor ABI binds operands and `pc` only, so such a behavior belongs
/// to the wide ABI; naming one state here (it was `nzcv`) left every other
/// declared state silently unbound.
/// The evaluation width of an instruction's pure semantics: the widest of its
/// input operands and its result. This is the rule the semantics emitters use
/// to pick `uint32_t` versus `uint64_t`, so the executors' dispatch arms agree
/// with the signatures that were actually emitted.
fn pure_eval_width(instruction: &Instruction) -> u32 {
    let inputs = instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        .map(|operand| operand.width)
        .max()
        .unwrap_or(0);
    let output = instruction
        .operands
        .iter()
        .find(|operand| operand.output)
        .map(|operand| operand.width)
        .unwrap_or(32);
    inputs.max(output)
}

fn behavior_reads_state(behavior: &crate::effects::Behavior, state_names: &[String]) -> bool {
    state_names
        .iter()
        .any(|name| behavior_reads_atom(behavior, name))
}

fn behavior_reads_atom(behavior: &crate::effects::Behavior, atom: &str) -> bool {
    fn mentions(expr: &SemanticExpr, atom: &str) -> bool {
        match expr {
            SemanticExpr::Atom(value) => value == atom,
            SemanticExpr::List(items) => items.iter().any(|item| mentions(item, atom)),
        }
    }

    behavior.effects.iter().any(|effect| {
        mentions(&effect.value.expr, atom)
            || effect
                .guard
                .as_ref()
                .is_some_and(|guard| mentions(&guard.expr, atom))
    })
}

/// Emit the Rust statements for one (unguarded) effect. Loads inside a `set`
/// are peeled to a `mem.read` + extend; other values/addresses use `rust_lower`.
fn emit_rust_effect_body(
    instruction: &Instruction,
    effect: &crate::effects::Effect,
) -> Option<String> {
    use crate::effects::Loc;
    match &effect.loc {
        // Fixed architectural registers need a persistent state store and
        // remain on the wide ABI. Named-state writes are returned as a delta.
        Loc::FixedReg { .. } => None,
        Loc::State { name, width } => {
            let value = rust_effect_expr(&effect.value.expr, effect.value.width)?;
            Some(format!(
                "    r.state_write = Some(({}, axis_sem_mask({value}, {width})));\n",
                json_string(name)
            ))
        }
        Loc::Reg(dest) => {
            let dp = instruction.operands.iter().position(|o| &o.name == dest)?;
            let dest_class = instruction
                .operands
                .iter()
                .find(|o| &o.name == dest)
                .and_then(|o| crate::ast::register_class(&o.kind));
            let dest_offset = dest_class.map(|class| class.offset).unwrap_or(0);
            let dest_limbs = dest_class.map(|class| class.limbs.max(1)).unwrap_or(1);
            let out_width = instruction
                .operands
                .iter()
                .find(|o| &o.name == dest)
                .map(|o| o.width)
                .unwrap_or(32);
            let value_lines = match &effect.value.expr {
                SemanticExpr::List(items)
                    if matches!(&items[0], SemanticExpr::Atom(a) if matches!(a.as_str(), "load" | "atomic_load"))
                        && matches!(items.len(), 4 | 5) =>
                {
                    let access = load_access_width(&items[1])?;
                    let signed = matches!(&items[2], SemanticExpr::Atom(a) if a == "signed");
                    let addr = rust_effect_expr(items.last()?, effect.value.load_address_width?)?;
                    let helper = if signed {
                        "axis_sem_sext"
                    } else {
                        "axis_sem_zext"
                    };
                    format!(
                        "        let _addr = axis_sem_mask({addr}, {out_width});\n        let _raw = mem.read(_addr, {access});\n        let _v = {helper}(_raw, {access}, {out_width});\n"
                    )
                }
                _ => format!(
                    "        let _v = axis_sem_mask({}, {out_width});\n",
                    rust_effect_expr(&effect.value.expr, effect.value.width)?
                ),
            };
            Some(format!(
                "    {{\n{value_lines}        let _di = lifted.operands[{dp}].unwrap_or(0) as usize * {dest_limbs} + {dest_offset};\n        if _di < regs.len() {{ regs[_di] = _v; }}\n        {dest} = _v;\n        r.result = Some(_v);\n    }}\n"
            ))
        }
        Loc::Mem { addr, width, .. } => {
            let addr_rs = rust_effect_expr(&addr.expr, addr.width)?;
            // A stored value may itself be a load. Peeled here as the register
            // arm peels it, and bound to a local before the write: `mem` is
            // borrowed mutably by both the read and the write.
            let value_rs = match &effect.value.expr {
                SemanticExpr::List(items)
                    if matches!(&items[0], SemanticExpr::Atom(a)
                        if matches!(a.as_str(), "load" | "atomic_load"))
                        && matches!(items.len(), 4 | 5) =>
                {
                    let access = load_access_width(&items[1])?;
                    let signed = matches!(&items[2], SemanticExpr::Atom(a) if a == "signed");
                    let load_addr =
                        rust_effect_expr(items.last()?, effect.value.load_address_width?)?;
                    let helper = if signed { "axis_sem_sext" } else { "axis_sem_zext" };
                    format!("{helper}(mem.read(axis_sem_mask({load_addr}, 32), {access}), {access}, {width})")
                }
                _ => rust_effect_expr(&effect.value.expr, effect.value.width)?,
            };
            Some(format!(
                "    {{\n        let _addr = axis_sem_mask({addr_rs}, 32);\n        let _val = axis_sem_mask({value_rs}, {width});\n        mem.write(_addr, _val, {width});\n    }}\n"
            ))
        }
        Loc::Port { .. } => None,
        Loc::Barrier { .. } => Some(format!(
            "    {{ let _barrier_option = {}; }}\n",
            rust_effect_expr(&effect.value.expr, effect.value.width)?
        )),
        Loc::Pc => Some(format!(
            "    {{ r.next_pc = axis_sem_mask({}, 32); }}\n",
            rust_effect_expr(&effect.value.expr, effect.value.width)?
        )),
        Loc::Trap => Some(format!(
            "    {{ r.trap = Some({}); return; }}\n",
            json_string(&crate::effects::render_semexpr(&effect.value.expr))
        )),
    }
}

/// Lower a pure effect subexpression to a Rust expression via `rust_lower`.
fn rust_effect_expr(expr: &SemanticExpr, width: u32) -> Option<String> {
    Some(super::semantics::rust_lower(&lower(expr, width).ok()?))
}

/// Lower a boolean guard tree to Rust, masking comparison operands to their
/// annotated evaluation width.
fn rust_guard_expr(guard: &SemanticExpr, width: u32) -> Option<String> {
    let SemanticExpr::List(items) = guard else {
        return None;
    };
    let SemanticExpr::Atom(op) = &items[0] else {
        return None;
    };
    if matches!(op.as_str(), "and" | "or") && items.len() >= 3 {
        let joiner = if op == "and" { " && " } else { " || " };
        return Some(format!(
            "({})",
            items[1..]
                .iter()
                .map(|child| rust_guard_expr(child, width))
                .collect::<Option<Vec<_>>>()?
                .join(joiner)
        ));
    }
    if op == "not" && items.len() == 2 {
        return Some(format!("!({})", rust_guard_expr(&items[1], width)?));
    }
    if items.len() != 3 {
        return None;
    }
    let (cmp, signed) = match op.as_str() {
        "icmp_eq" => ("==", false),
        "icmp_ne" => ("!=", false),
        "icmp_slt" => ("<", true),
        "icmp_ult" => ("<", false),
        "icmp_sge" => (">=", true),
        "icmp_uge" => (">=", false),
        _ => return None,
    };
    // The same rule as the C twin, and it was wrong here in the same way: a
    // masked unsigned compare for a signed operator.
    let side = |expr: String| {
        if signed {
            format!("axis_sem_signed({expr}, {width})")
        } else {
            format!("axis_sem_mask({expr}, {width})")
        }
    };
    Some(format!(
        "{} {cmp} {}",
        side(rust_effect_expr(&items[1], width)?),
        side(rust_effect_expr(&items[2], width)?)
    ))
}

/// The `deffun`s for the wide C executor, once each -- prototypes first, so
/// one may call another -- from the same lowering as the effects that call
/// them. A function the 64-bit tier cannot hold is not emitted, and a call to
/// it declines where it is lowered.
fn emit_exec_c64_functions(document: &Document, out: &mut String) {
    let usable: Vec<(&crate::ast::Function, String)> = document
        .functions
        .iter()
        .filter_map(|function| {
            let bindings: Vec<(String, String)> =
                function.params.iter().map(|(name, _)| (name.clone(), format!("p_{}", python_ident(name)))).collect();
            let body = c_wide_expr_at(&function.body, &bindings, function.result_width, 64)?;
            (function.result_width <= 64 && function.params.iter().all(|(_, width)| *width <= 64))
                .then_some((function, body))
        })
        .collect();
    let head = |function: &crate::ast::Function| {
        let params: Vec<String> =
            function.params.iter().map(|(name, _)| format!("uint64_t p_{}", python_ident(name))).collect();
        format!(
            "static inline uint64_t axis_fn64_{}({})",
            crate::emit::semantics::function_ident(&function.name),
            if params.is_empty() { "void".to_string() } else { params.join(", ") }
        )
    };
    for (function, _) in &usable {
        out.push_str(&format!("{};\n", head(function)));
    }
    for (function, body) in &usable {
        out.push_str(&format!("{} {{\n  return axis_mask64({body}, {}u);\n}}\n", head(function), function.result_width));
    }
}

/// The Rust twin of [`emit_exec_c64_functions`].
fn emit_exec_rust64_functions(document: &Document, out: &mut String) {
    for function in &document.functions {
        if function.result_width > 64 || function.params.iter().any(|(_, width)| *width > 64) {
            continue;
        }
        let bindings: Vec<(String, String)> =
            function.params.iter().map(|(name, _)| (name.clone(), format!("p_{}", python_ident(name)))).collect();
        let Some(body) = rust_wide_expr_at(&function.body, &bindings, function.result_width, 64) else {
            continue;
        };
        let params: Vec<String> =
            function.params.iter().map(|(name, _)| format!("p_{}: u64", python_ident(name))).collect();
        out.push_str(&format!(
            "#[allow(dead_code, unused_parens)]\nfn axis_fn64_{}({}) -> u64 {{ axis_mask64({body}, {}) }}\n",
            crate::emit::semantics::function_ident(&function.name),
            params.join(", "),
            function.result_width
        ));
    }
}
