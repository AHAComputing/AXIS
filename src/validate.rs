use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::ast::*;
use crate::layout::{resolve_layout, validate_format_definition, InstructionLayout};
use crate::semantics::validate_formal_semantics;

const CORE_KINDS: &[&str] = &["rvmt", "simt"];
const PACKET_ORDERS: &[&str] = &["little", "big"];
const PACKET_END_RULES: &[&str] = &["fixed", "stop_bit"];
const PACKET_HAZARDS: &[&str] = &["interlocked", "exposed"];
const PACKET_BRANCH_POLICIES: &[&str] = &["at_most_one", "unrestricted"];
const TILE_INTERCONNECTS: &[&str] = &["crossbar", "noc", "mailbox"];
const ACCELERATOR_COUPLINGS: &[&str] = &["tightly_coupled", "queue_descriptor", "loose", "stream"];
/// When an engine's writes become visible to the host (T9).
const ACCELERATOR_VISIBILITY: &[&str] = &["immediate", "atomic-at-completion", "progressive"];
/// Whether a launch orders the host's prior stores against the engine's reads.
const ACCELERATOR_FENCES: &[&str] = &["prior-stores", "none"];
/// What the host may observe in the output region while the engine runs.
const ACCELERATOR_IN_FLIGHT: &[&str] = &["unchanged", "undefined"];
/// The couplings that finish inside the launching instruction. Everything else
/// outlives it, which is the difference the contract below turns on.
const SYNCHRONOUS_COUPLINGS: &[&str] = &["tightly_coupled"];
const ACCELERATOR_LAUNCH_ABIS: &[&str] = &["rvmt_submit_entry", "queue_descriptor", "mailbox"];
const ACCELERATOR_COMPLETIONS: &[&str] = &["status_addr", "mailbox", "event_queue"];
// M2. Two policies, because two is what a service bound has to distinguish: one
// that rotates and one that does not. Adding a third is a one-line change with
// `service_bound` and its gate behind it, which is the point of closing the set
// rather than accepting any word a description cares to invent.
const ACCELERATOR_SCHEDULING: &[&str] = &["work_conserving_round_robin", "strict_priority"];
const ACCELERATOR_PREEMPTION: &[&str] = &["tile_boundary_only", "none"];
const RCORE_PROFILES: &[&str] = &["micro", "memo_lite", "scalar", "vector_lite", "managed"];
const RCORE_BACKEND_KINDS: &[&str] = &["auto", "asic", "fabric"];
const RCORE_EXEC_SHAPES: &[&str] = &["scalar", "uniform_simd", "masked_simd"];
const RCORE_FALLBACK_POLICIES: &[&str] = &["software"];
const ACCELERATOR_TARGETS: &[&str] = &[
    "rvmt",
    "simt",
    "xnn",
    "cpe",
    "efpga",
    "vliw_simd",
    "imc",
    "dae",
    "ste",
    "spc",
    "structured_asic",
    "spatial_dataflow",
    "systolic_array",
    "event_dispatch",
    "remote_store_manycore",
    "nearasic",
    "rcore",
    "ccore",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    pub message: String,
}

impl ValidationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "validation error: {}", self.message)
    }
}

pub fn validate_document(document: &Document) -> Result<(), ValidationError> {
    validate_extension(&document.extension)?;
    validate_function_calls(document)?;
    validate_isas(&document.isas)?;
    validate_formats(document)?;
    validate_modes(document)?;
    validate_configs(document)?;
    validate_completion_contract(document)?;
    validate_instruction_modes(document)?;
    validate_packets(document)?;
    validate_instruction_units(document)?;
    validate_packet_structural_hazards(document)?;
    validate_instructions(document)?;
    validate_lowerings(document)?;
    validate_cores(document)?;
    validate_personalities(document)?;
    validate_accelerators(&document.accelerators)?;
    validate_memories(&document.memories)?;
    crate::memsys::validate(document).map_err(ValidationError::new)?;
    validate_tiles(document)?;
    validate_fabrics(document)?;
    validate_mappings(document)?;
    validate_channels(document)?;
    validate_seams(document)?;
    validate_abis(document)?;
    validate_mapping_launches(document)?;
    Ok(())
}

fn validate_lowerings(document: &Document) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for lowering in &document.lowerings {
        require_identifier("lowering.name", &lowering.name)?;
        if !names.insert(lowering.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate lowering `{}`",
                lowering.name
            )));
        }
        validate_lowering(document, lowering)?;
    }
    Ok(())
}

fn validate_lowering(document: &Document, lowering: &Lowering) -> Result<(), ValidationError> {
    if lowering.sources.is_empty() {
        return Err(ValidationError::new(format!(
            "lowering `{}` requires at least one source step",
            lowering.name
        )));
    }
    if lowering.source_cycles == 0 || lowering.target_cycles == 0 {
        return Err(ValidationError::new(format!(
            "lowering `{}` source_cycles and target_cycles must be positive",
            lowering.name
        )));
    }
    let benefit = lowering.benefit.parse::<f64>().map_err(|_| {
        ValidationError::new(format!(
            "lowering `{}` benefit must be numeric",
            lowering.name
        ))
    })?;
    if !benefit.is_finite() || benefit <= 0.0 {
        return Err(ValidationError::new(format!(
            "lowering `{}` benefit must be finite and positive",
            lowering.name
        )));
    }

    let mut variable_types: HashMap<String, (String, u32)> = HashMap::new();
    let mut all_variables = HashSet::new();
    let mut produced = HashSet::new();
    let mut consumed_produced = HashSet::new();
    let mut external = HashSet::new();
    let mut source_environment = HashMap::new();
    let mut source_observable_effects = Vec::new();
    let mut source_sp_variables = HashSet::new();

    for step in &lowering.sources {
        let instruction = lowering_instruction(document, &step.instruction, &lowering.name)?;
        require_instruction_role(document, instruction, "source", &lowering.name)?;
        require_lowering_encodable(document, instruction, &lowering.name)?;
        validate_lowering_step(
            lowering,
            step,
            instruction,
            true,
            &mut variable_types,
            &mut all_variables,
        )?;
        collect_lowering_sp_variables(step, instruction, &mut source_sp_variables);

        for operand in instruction.operands.iter().filter(|operand| operand.input) {
            if let LoweringValue::Variable(variable) =
                lowering_binding(step, &operand.name).expect("validated binding")
            {
                if produced.contains(variable) {
                    consumed_produced.insert(variable.clone());
                } else {
                    external.insert(variable.clone());
                }
            }
        }
        for operand in instruction.operands.iter().filter(|operand| operand.output) {
            let LoweringValue::Variable(variable) =
                lowering_binding(step, &operand.name).expect("validated binding")
            else {
                continue;
            };
            if !produced.insert(variable.clone()) {
                return Err(ValidationError::new(format!(
                    "lowering `{}` redefines SSA value `${variable}`",
                    lowering.name
                )));
            }
        }
        compose_lowering_step(
            lowering,
            step,
            instruction,
            &mut source_environment,
            &mut source_observable_effects,
        )?;
    }

    let final_values: HashSet<String> = produced.difference(&consumed_produced).cloned().collect();

    let target_instruction =
        lowering_instruction(document, &lowering.target.instruction, &lowering.name)?;
    require_instruction_role(document, target_instruction, "target", &lowering.name)?;
    require_lowering_encodable(document, target_instruction, &lowering.name)?;
    validate_lowering_step(
        lowering,
        &lowering.target,
        target_instruction,
        false,
        &mut variable_types,
        &mut all_variables,
    )?;
    let target_outputs: Vec<&Operand> = target_instruction
        .operands
        .iter()
        .filter(|operand| operand.output)
        .collect();
    let target_output_values: HashSet<String> = target_outputs
        .iter()
        .filter_map(
            |output| match lowering_binding(&lowering.target, &output.name) {
                Some(LoweringValue::Variable(variable)) => Some(variable.clone()),
                _ => None,
            },
        )
        .collect();
    if target_output_values != final_values {
        return Err(ValidationError::new(format!(
            "lowering `{}` target outputs {:?} do not match final source values {:?}",
            lowering.name, target_output_values, final_values
        )));
    }

    let target_inputs: HashSet<String> = target_instruction
        .operands
        .iter()
        .filter(|operand| operand.input)
        .filter_map(
            |operand| match lowering_binding(&lowering.target, &operand.name) {
                Some(LoweringValue::Variable(variable)) => Some(variable.clone()),
                _ => None,
            },
        )
        .collect();
    if target_inputs != external {
        return Err(ValidationError::new(format!(
            "lowering `{}` target variable inputs {:?} do not match source inputs {:?}",
            lowering.name, target_inputs, external
        )));
    }
    if let Some(predicate) = &lowering.requires {
        validate_lowering_predicate(lowering, predicate, &all_variables)?;
    }
    let mut target_sp_variables = HashSet::new();
    collect_lowering_sp_variables(
        &lowering.target,
        target_instruction,
        &mut target_sp_variables,
    );
    for variable in source_sp_variables.symmetric_difference(&target_sp_variables) {
        if !lowering
            .requires
            .as_ref()
            .is_some_and(|predicate| lowering_predicate_excludes_register31(predicate, variable))
        {
            return Err(ValidationError::new(format!(
                "lowering `{}` variable `${variable}` changes register-31 SP semantics without excluding encoded register 31",
                lowering.name
            )));
        }
    }

    let mut target_environment = HashMap::new();
    let mut target_observable_effects = Vec::new();
    compose_lowering_step(
        lowering,
        &lowering.target,
        target_instruction,
        &mut target_environment,
        &mut target_observable_effects,
    )?;
    let result_mismatch = final_values
        .iter()
        .any(|value| source_environment.get(value) != target_environment.get(value));
    if result_mismatch || source_observable_effects != target_observable_effects {
        return Err(ValidationError::new(format!(
            "lowering `{}` source sequence is not semantically identical to target `{}`",
            lowering.name, target_instruction.mnemonic
        )));
    }
    Ok(())
}

fn collect_lowering_sp_variables(
    step: &LoweringStep,
    instruction: &Instruction,
    variables: &mut HashSet<String>,
) {
    for operand in &instruction.operands {
        if !operand.kind.ends_with("sp") {
            continue;
        }
        if let Some(LoweringValue::Variable(variable)) = lowering_binding(step, &operand.name) {
            variables.insert(variable.clone());
        }
    }
}

fn lowering_predicate_excludes_register31(predicate: &LoweringPredicate, variable: &str) -> bool {
    use crate::decode_constraint::CompareOp;
    match predicate {
        LoweringPredicate::Compare { lhs, op, rhs } => {
            matches!(
                (lhs, op, rhs),
                (
                    LoweringValue::Variable(name),
                    CompareOp::Lt,
                    LoweringValue::Literal(31)
                ) if name == variable
            ) || matches!(
                (lhs, op, rhs),
                (
                    LoweringValue::Variable(name),
                    CompareOp::Le,
                    LoweringValue::Literal(30)
                ) if name == variable
            )
        }
        LoweringPredicate::And(children) => children
            .iter()
            .any(|child| lowering_predicate_excludes_register31(child, variable)),
        LoweringPredicate::Or(children) => {
            !children.is_empty()
                && children
                    .iter()
                    .all(|child| lowering_predicate_excludes_register31(child, variable))
        }
        LoweringPredicate::Not(_) => false,
    }
}

fn validate_lowering_step(
    lowering: &Lowering,
    step: &LoweringStep,
    instruction: &Instruction,
    allow_discard_output: bool,
    variable_types: &mut HashMap<String, (String, u32)>,
    all_variables: &mut HashSet<String>,
) -> Result<(), ValidationError> {
    let mut bound = HashSet::new();
    for binding in &step.bindings {
        if !bound.insert(binding.operand.clone()) {
            return Err(ValidationError::new(format!(
                "lowering `{}` step `{}` binds operand `{}` more than once",
                lowering.name, step.instruction, binding.operand
            )));
        }
        let operand = instruction
            .operands
            .iter()
            .find(|operand| operand.name == binding.operand)
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "lowering `{}` step `{}` binds unknown operand `{}`",
                    lowering.name, step.instruction, binding.operand
                ))
            })?;
        if let LoweringValue::Variable(variable) = &binding.value {
            require_identifier("lowering variable", variable)?;
            all_variables.insert(variable.clone());
            let ty = (
                lowering_operand_class(&operand.kind).to_string(),
                operand.width,
            );
            if let Some(previous) = variable_types.insert(variable.clone(), ty.clone()) {
                if previous != ty {
                    return Err(ValidationError::new(format!(
                        "lowering `{}` variable `${variable}` has incompatible types {:?} and {:?}",
                        lowering.name, previous, ty
                    )));
                }
            }
        } else if let LoweringValue::Literal(value) = binding.value {
            if operand.width < 32 && value >= (1u32 << operand.width) {
                return Err(ValidationError::new(format!(
                    "lowering `{}` literal {value} does not fit `{}.{}` width {}",
                    lowering.name, step.instruction, operand.name, operand.width
                )));
            }
            if operand.output
                && (!allow_discard_output
                    || value != 31
                    || !matches!(operand.kind.as_str(), "a64_gpr64" | "a64_gpr32"))
            {
                return Err(ValidationError::new(format!(
                    "lowering `{}` output `{}.{}` may bind literal 31 only for an AArch64 zero-register discard",
                    lowering.name, step.instruction, operand.name
                )));
            }
        }
    }
    for operand in &instruction.operands {
        if !bound.contains(&operand.name) {
            return Err(ValidationError::new(format!(
                "lowering `{}` step `{}` is missing operand `{}`",
                lowering.name, step.instruction, operand.name
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum LoweringObservableEffect {
    Register {
        result: String,
        value: crate::semantics::SemanticExpr,
        atomic_group: u32,
    },
    State {
        name: String,
        width: u32,
        value: crate::semantics::SemanticExpr,
        atomic_group: u32,
    },
    Store {
        width: u32,
        address: crate::semantics::SemanticExpr,
        value: crate::semantics::SemanticExpr,
        guard: Option<crate::semantics::SemanticExpr>,
        order: crate::effects::MemoryOrder,
        atomic: bool,
        atomic_group: u32,
    },
    FixedRegister {
        class: String,
        index: u32,
        width: u32,
        value: crate::semantics::SemanticExpr,
        atomic_group: u32,
    },
    Barrier {
        kind: String,
        width: u32,
        value: crate::semantics::SemanticExpr,
        atomic_group: u32,
    },
    Pc {
        value: crate::semantics::SemanticExpr,
        guard: Option<crate::semantics::SemanticExpr>,
        atomic_group: u32,
    },
}

fn compose_lowering_step(
    lowering: &Lowering,
    step: &LoweringStep,
    instruction: &Instruction,
    environment: &mut HashMap<String, crate::semantics::SemanticExpr>,
    observable_effects: &mut Vec<LoweringObservableEffect>,
) -> Result<(), ValidationError> {
    let outputs: Vec<&Operand> = instruction
        .operands
        .iter()
        .filter(|operand| operand.output)
        .collect();
    let mut substitutions = HashMap::new();
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        let value = lowering_binding(step, &operand.name).expect("validated binding");
        let semantics = match value {
            LoweringValue::Variable(variable) => environment
                .get(variable)
                .cloned()
                .unwrap_or_else(|| crate::semantics::SemanticExpr::Atom(format!("${variable}"))),
            LoweringValue::Literal(value) => {
                crate::semantics::SemanticExpr::Atom(value.to_string())
            }
        };
        substitutions.insert(format!("__input_{}", operand.name), semantics.clone());
        substitutions.insert(operand.name.clone(), semantics);
    }
    let output_bindings: HashMap<&str, &LoweringValue> = outputs
        .iter()
        .map(|output| {
            (
                output.name.as_str(),
                lowering_binding(step, &output.name).expect("validated binding"),
            )
        })
        .collect();

    if !instruction.formal_semantics.trim().is_empty() {
        let [output_operand] = outputs.as_slice() else {
            return Err(lowering_effect_boundary_error(lowering, step));
        };
        let Some(LoweringValue::Variable(output)) =
            output_bindings.get(output_operand.name.as_str())
        else {
            return Err(lowering_effect_boundary_error(lowering, step));
        };
        let expression = crate::semantics::parse_formal_semantics(&instruction.formal_semantics)
            .map_err(|error| ValidationError::new(error.message))?;
        let semantics = substitute_lowering_semantics(&expression, &substitutions);
        environment.insert(output.clone(), semantics);
        return Ok(());
    }

    let behavior = instruction
        .behavior
        .as_ref()
        .ok_or_else(|| lowering_effect_boundary_error(lowering, step))?;
    let mut written_outputs = HashSet::new();
    let mut wrote_observable_effect = false;
    for effect in &behavior.effects {
        let guard = effect
            .guard
            .as_ref()
            .map(|guard| substitute_lowering_semantics(&guard.expr, &substitutions));
        let value = substitute_lowering_semantics(&effect.value.expr, &substitutions);
        match &effect.loc {
            crate::effects::Loc::Reg(name)
                if output_bindings.contains_key(name.as_str())
                    && written_outputs.insert(name.clone())
                    && guard.is_none() =>
            {
                substitutions.insert(name.clone(), value.clone());
                if let Some(LoweringValue::Variable(output)) = output_bindings.get(name.as_str()) {
                    observable_effects.push(LoweringObservableEffect::Register {
                        result: output.to_string(),
                        value: value.clone(),
                        atomic_group: effect.atomic_group,
                    });
                    environment.insert(output.clone(), value);
                }
            }
            crate::effects::Loc::State { name, width } if guard.is_none() => {
                wrote_observable_effect = true;
                observable_effects.push(LoweringObservableEffect::State {
                    name: name.clone(),
                    width: *width,
                    value,
                    atomic_group: effect.atomic_group,
                });
            }
            crate::effects::Loc::Mem {
                addr,
                width,
                order,
                atomic,
            } => {
                wrote_observable_effect = true;
                observable_effects.push(LoweringObservableEffect::Store {
                    width: *width,
                    address: substitute_lowering_semantics(&addr.expr, &substitutions),
                    value,
                    guard,
                    order: *order,
                    atomic: *atomic,
                    atomic_group: effect.atomic_group,
                });
            }
            crate::effects::Loc::FixedReg { kind, index, width } if guard.is_none() => {
                wrote_observable_effect = true;
                observable_effects.push(LoweringObservableEffect::FixedRegister {
                    class: lowering_operand_class(kind).to_string(),
                    index: *index,
                    width: *width,
                    value,
                    atomic_group: effect.atomic_group,
                });
            }
            crate::effects::Loc::Barrier { kind, width } if guard.is_none() => {
                wrote_observable_effect = true;
                observable_effects.push(LoweringObservableEffect::Barrier {
                    kind: kind.clone(),
                    width: *width,
                    value,
                    atomic_group: effect.atomic_group,
                });
            }
            crate::effects::Loc::Pc => {
                wrote_observable_effect = true;
                observable_effects.push(LoweringObservableEffect::Pc {
                    value,
                    guard,
                    atomic_group: effect.atomic_group,
                });
            }
            _ => return Err(lowering_effect_boundary_error(lowering, step)),
        }
    }
    if written_outputs.len() != outputs.len() || (outputs.is_empty() && !wrote_observable_effect) {
        return Err(lowering_effect_boundary_error(lowering, step));
    }
    Ok(())
}

fn lowering_effect_boundary_error(lowering: &Lowering, step: &LoweringStep) -> ValidationError {
    ValidationError::new(format!(
        "lowering `{}` step `{}` must have unconditional register/fixed-register/state writes or optionally guarded memory/PC writes",
        lowering.name, step.instruction
    ))
}

fn substitute_lowering_semantics(
    semantics: &crate::semantics::SemanticExpr,
    substitutions: &HashMap<String, crate::semantics::SemanticExpr>,
) -> crate::semantics::SemanticExpr {
    match semantics {
        crate::semantics::SemanticExpr::Atom(name) => substitutions
            .get(name)
            .cloned()
            .unwrap_or_else(|| semantics.clone()),
        crate::semantics::SemanticExpr::List(items) => {
            if matches!(items.as_slice(), [crate::semantics::SemanticExpr::Atom(op), crate::semantics::SemanticExpr::Atom(_)] if op == "input")
            {
                let crate::semantics::SemanticExpr::Atom(name) = &items[1] else {
                    unreachable!()
                };
                return substitutions
                    .get(&format!("__input_{name}"))
                    .cloned()
                    .unwrap_or_else(|| semantics.clone());
            }
            let mut substituted = Vec::with_capacity(items.len());
            if let Some(operator) = items.first() {
                substituted.push(operator.clone());
            }
            substituted.extend(
                items
                    .iter()
                    .skip(1)
                    .map(|item| substitute_lowering_semantics(item, substitutions)),
            );
            crate::semantics::SemanticExpr::List(substituted)
        }
    }
}

fn validate_lowering_predicate(
    lowering: &Lowering,
    predicate: &LoweringPredicate,
    variables: &HashSet<String>,
) -> Result<(), ValidationError> {
    match predicate {
        LoweringPredicate::Compare { lhs, rhs, .. } => {
            for value in [lhs, rhs] {
                if let LoweringValue::Variable(variable) = value {
                    if !variables.contains(variable) {
                        return Err(ValidationError::new(format!(
                            "lowering `{}` predicate references unknown variable `${variable}`",
                            lowering.name
                        )));
                    }
                }
            }
        }
        LoweringPredicate::And(children) | LoweringPredicate::Or(children) => {
            for child in children {
                validate_lowering_predicate(lowering, child, variables)?;
            }
        }
        LoweringPredicate::Not(child) => {
            validate_lowering_predicate(lowering, child, variables)?;
        }
    }
    Ok(())
}

fn lowering_instruction<'a>(
    document: &'a Document,
    reference: &str,
    lowering: &str,
) -> Result<&'a Instruction, ValidationError> {
    document
        .instructions
        .iter()
        .find(|instruction| {
            instruction.mnemonic.eq_ignore_ascii_case(reference)
                || instruction.name.eq_ignore_ascii_case(reference)
        })
        .ok_or_else(|| {
            ValidationError::new(format!(
                "lowering `{lowering}` references unknown instruction `{reference}`"
            ))
        })
}

fn require_instruction_role(
    document: &Document,
    instruction: &Instruction,
    expected: &str,
    lowering: &str,
) -> Result<(), ValidationError> {
    let role = crate::ast::instruction_isa(document, instruction)
        .map(|isa| isa.role.as_str())
        .unwrap_or("");
    if role != expected {
        return Err(ValidationError::new(format!(
            "lowering `{lowering}` instruction `{}` must belong to a `{expected}` ISA",
            instruction.mnemonic
        )));
    }
    Ok(())
}

fn require_lowering_encodable(
    document: &Document,
    instruction: &Instruction,
    lowering: &str,
) -> Result<(), ValidationError> {
    let layout = resolve_layout(document, instruction).map_err(ValidationError::new)?;
    if !layout.is_encodable() {
        return Err(ValidationError::new(format!(
            "lowering `{lowering}` instruction `{}` must be fully encodable",
            instruction.mnemonic
        )));
    }
    Ok(())
}

fn lowering_binding<'a>(step: &'a LoweringStep, operand: &str) -> Option<&'a LoweringValue> {
    step.bindings
        .iter()
        .find(|binding| binding.operand == operand)
        .map(|binding| &binding.value)
}

fn lowering_operand_class(kind: &str) -> &str {
    // From the table, not from a list here. These five names were written out
    // in this function, which meant adding a view of a file already in it --
    // a 32-bit `reg32` beside `reg` -- made the view incompatible with the
    // file it is a view of, because nothing said it was still the same file.
    register_class(kind).map_or(kind, |class| class.lowering_family)
}

pub fn validate_aha_export(document: &Document) -> Result<(), ValidationError> {
    validate_document(document)?;
    for instruction in &document.instructions {
        validate_pce_custom_encoding(instruction)?;
        require_non_empty(
            &format!("instruction `{}` semantics", instruction.mnemonic),
            &instruction.semantics,
        )?;
        require_non_empty(
            &format!("instruction `{}` rationale", instruction.mnemonic),
            &instruction.rationale,
        )?;
    }
    Ok(())
}

/// The PCE/AHA hardware seam remains deliberately RISC-V-custom even though
/// the AXIS core model is target-neutral. Keep this constraint at the export
/// boundary instead of rejecting valid encodings for other ISAs globally.
fn validate_pce_custom_encoding(instruction: &Instruction) -> Result<(), ValidationError> {
    if !matches!(instruction.opcode, 0x0b | 0x2b | 0x5b | 0x7b) {
        return Err(ValidationError::new(format!(
            "instruction `{}` cannot be exported to PCE/AHA: opcode 0x{:02x} is not a RISC-V custom opcode",
            instruction.mnemonic, instruction.opcode
        )));
    }
    if instruction.func3 > 0x7 {
        return Err(ValidationError::new(format!(
            "instruction `{}` cannot be exported to PCE/AHA: func3 must fit in 3 bits",
            instruction.mnemonic
        )));
    }
    if instruction.func7 > 0x7f {
        return Err(ValidationError::new(format!(
            "instruction `{}` cannot be exported to PCE/AHA: func7 must fit in 7 bits",
            instruction.mnemonic
        )));
    }
    Ok(())
}

fn validate_extension(extension: &Extension) -> Result<(), ValidationError> {
    require_identifier("extension.name", &extension.name)?;
    require_non_empty("extension.version", &extension.version)?;
    require_non_empty("extension.target", &extension.target)?;
    Ok(())
}

fn validate_formats(document: &Document) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for format in &document.formats {
        require_identifier("format.name", &format.name)?;
        if !names.insert(format.name.clone()) {
            return Err(ValidationError::new(format!(
                "duplicate format `{}`",
                format.name
            )));
        }
        validate_format_definition(format).map_err(ValidationError::new)?;
    }
    Ok(())
}

fn validate_instructions(document: &Document) -> Result<(), ValidationError> {
    let instructions = &document.instructions;
    if instructions.is_empty() {
        return Err(ValidationError::new("at least one instruction is required"));
    }

    // ⚠️ An implementation routine answers the question a `formal` or a
    // `behavior` answers, and an instruction may not answer it twice: a
    // consumer would have to pick, and whichever it picked the other would be a
    // claim nothing checked. Naming a routine is for an instruction whose
    // semantics are undecided or unexpressible -- if they can be written, write
    // them, because a routine cannot be reasoned about.
    for instruction in instructions {
        if !instruction.implementation.trim().is_empty()
            && (!instruction.formal_semantics.trim().is_empty()
                || instruction.behavior.is_some())
        {
            return Err(ValidationError::new(&format!(
                "instruction `{}` names an implementation routine `{}` and also \
                 states semantics; a routine is for an instruction whose \
                 semantics cannot be written, so stating both leaves two \
                 answers to one question",
                instruction.mnemonic,
                instruction.implementation.trim()
            )));
        }
    }

    let mut mnemonics = HashSet::new();
    let mut layouts: Vec<(&Instruction, InstructionLayout)> = Vec::new();
    for instruction in instructions {
        require_identifier("instruction.name", &instruction.name)?;
        require_identifier("instruction.mnemonic", &instruction.mnemonic)?;
        if !mnemonics.insert(instruction.mnemonic.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate instruction mnemonic `{}`",
                instruction.mnemonic
            )));
        }

        validate_instruction_isa(document, instruction)?;
        validate_operand_widths(document, instruction)?;
        if instruction.latency_cycles == 0 {
            return Err(ValidationError::new(format!(
                "instruction `{}` latency_cycles must be positive",
                instruction.mnemonic
            )));
        }
        let layout = resolve_layout(document, instruction).map_err(ValidationError::new)?;
        validate_encoding_values(instruction, &layout)?;
        validate_derived_operand_layout(instruction, &layout)?;
        layouts.push((instruction, layout));
        validate_costs(instruction)?;
        validate_operands(instruction)?;
        if !instruction.decode_requires.trim().is_empty() && instruction.decode_constraint.is_none()
        {
            return Err(ValidationError::new(format!(
                "instruction `{}` has decode_requires text without a canonical decode constraint",
                instruction.mnemonic
            )));
        }
        validate_instruction_formal_semantics(document, instruction)?;
    }
    validate_decode_space_disjointness(document, &layouts)?;
    Ok(())
}

fn validate_derived_operand_layout(
    instruction: &Instruction,
    layout: &InstructionLayout,
) -> Result<(), ValidationError> {
    for operand in instruction.operands.iter().filter(|operand| operand.fixed.is_some()) {
        if !layout.operand_bindings(&operand.name).is_empty() {
            return Err(ValidationError::new(format!(
                "instruction `{}` fixed operand `{}` must not consume encoding bits",
                instruction.mnemonic, operand.name
            )));
        }
    }
    for operand in instruction
        .operands
        .iter()
        .filter(|operand| !operand.derived_from.is_empty())
    {
        if !layout.operand_bindings(&operand.name).is_empty() {
            return Err(ValidationError::new(format!(
                "instruction `{}` derived operand `{}` must not consume encoding bits",
                instruction.mnemonic, operand.name
            )));
        }
        let fixed_source = instruction
            .operands
            .iter()
            .any(|source| source.name == operand.derived_from && source.fixed.is_some());
        if layout.operand_bindings(&operand.derived_from).is_empty() && !fixed_source {
            return Err(ValidationError::new(format!(
                "instruction `{}` derived operand `{}` source `{}` must be directly encoded",
                instruction.mnemonic, operand.name, operand.derived_from
            )));
        }
    }
    Ok(())
}

/// The width an ISA declares for its base register file, if it declares one.
fn base_register_width(isa: &Isa) -> Option<u32> {
    isa.registers.iter().find_map(|declaration| {
        let (_, rest) = declaration.split_once("[")?;
        let (_, kind) = rest.split_once("]:i")?;
        kind.parse().ok()
    })
}

/// An operand naming a *window* of a register is as wide as the window.
///
/// A window is owned by its class -- `a64_gpr32` is the W view of an X
/// register, at a fixed offset, with a fixed write policy, at one width
/// forever. So `view_width` is not advice about the class; it is the width of
/// anything that names it, and an operand saying otherwise is describing a
/// register that does not exist.
///
/// This is deliberately *not* a rule about operands being narrower than their
/// register in general. An operand may name an *element* rather than a
/// register -- SVE's `z0.b`, a `v2f32` lane group -- and there the width comes
/// from the instruction rather than the class, which is why elements cannot be
/// classes and why one rule for both was wrong six times before it was two.
///
/// It earns its place: seventeen operands across `regslice` and `limbs`
/// declared the machine word where their window's width belonged, x86's `AL`
/// among them at sixty-four bits. Every gate passed, and three separate
/// harnesses passed *because* of it -- each compared a whole register slot
/// against a windowed value, which agrees exactly while no description admits
/// to having a window narrower than a word.
fn validate_operand_widths(
    document: &Document,
    instruction: &Instruction,
) -> Result<(), ValidationError> {
    // An operand narrower than the register file it names has to say which of
    // the two reasons applies. A *window* says it by naming a class that has
    // one; an *element* says it with the marker; a lane-instantiated scalable
    // instruction says it by construction. Anything else is claiming a
    // register the machine does not have, which is what fifty-six operands
    // across six corpora were doing.
    if instruction.scalable_origin.is_empty() {
        if let Some(file) =
            crate::ast::instruction_isa(document, instruction).and_then(base_register_width)
        {
            for operand in &instruction.operands {
                let Some(class) = register_class(&operand.kind) else {
                    continue;
                };
                if class.view_width.is_some() || operand.element {
                    continue;
                }
                // A class in a second file is checked against *that* file's
                // width when it declares one. Only a second file with no
                // declared width -- a scalable vector file, whose size moves
                // with VL -- has nothing to be checked against.
                // A file that declares its own width is checked exactly:
                // RISC-V's `f` registers are 64 bits with `D` present, so an
                // operand naming 32 of them is as wrong as one naming 128.
                // ⚠️ The way out is the same one a machine-word file has, and
                // the message says so -- an *element* of a declared-width file
                // is marked and skipped above, which is how `simd_fp_lanes`
                // names two 32-bit lanes of a 128-bit register now that its
                // lane instructions and its wide ones name one file. Saying
                // "no way out" here was true only while nothing needed it.
                if let Some(width) = class.file_width {
                    if operand.width != width {
                        return Err(ValidationError::new(format!(
                            "instruction `{}` operand `{}` is {} bits, but `{}` is \
                             a {}-bit register file: name a view class if it is a \
                             window, or mark it `element`",
                            instruction.mnemonic, operand.name, operand.width,
                            class.name, width
                        )));
                    }
                    continue;
                }
                if class.offset != 0 {
                    continue;
                }
                if operand.width < file {
                    return Err(ValidationError::new(format!(
                        "instruction `{}` operand `{}` is {} bits of a {}-bit register: \
                         name a view class if it is a window, or mark it `element`",
                        instruction.mnemonic, operand.name, operand.width, file
                    )));
                }
            }
        }
    }
    for operand in &instruction.operands {
        let Some(class) = register_class(&operand.kind) else {
            continue;
        };
        let Some(view) = class.view_width else {
            continue;
        };
        if operand.width != view {
            return Err(ValidationError::new(format!(
                "instruction `{}` operand `{}` is {} bits, but `{}` is a \
                 {}-bit view of its register",
                instruction.mnemonic, operand.name, operand.width, class.name, view
            )));
        }
    }
    Ok(())
}

fn validate_instruction_isa(
    document: &Document,
    instruction: &Instruction,
) -> Result<(), ValidationError> {
    if instruction.isa.is_empty() {
        return Ok(());
    }
    if !document.isas.iter().any(|isa| isa.name == instruction.isa) {
        return Err(ValidationError::new(format!(
            "instruction `{}` references unknown ISA `{}`",
            instruction.mnemonic, instruction.isa
        )));
    }
    Ok(())
}

fn validate_encoding_values(
    instruction: &Instruction,
    layout: &InstructionLayout,
) -> Result<(), ValidationError> {
    for (name, value) in &instruction.encoding {
        let Some(fixed) = layout.fixed_fields.iter().find(|field| &field.name == name) else {
            continue;
        };
        let max = if fixed.width >= 32 {
            u32::MAX
        } else {
            (1u32 << fixed.width) - 1
        };
        if *value > max {
            return Err(ValidationError::new(format!(
                "instruction `{}` encoding value {}={} does not fit in {} bits",
                instruction.mnemonic, name, value, fixed.width
            )));
        }
    }
    Ok(())
}

/// No two instructions may claim the same bit pattern *within a mode*: a pair
/// conflicts iff their fixed bits agree on every position both masks cover AND
/// their mode sets intersect. Instructions with disjoint mode sets may reuse
/// the encoding (cross-mode reuse). A mode-free document has one implicit mode
/// containing everything, so this reduces to the old global-disjointness rule.
fn validate_decode_space_disjointness(
    document: &Document,
    layouts: &[(&Instruction, InstructionLayout)],
) -> Result<(), ValidationError> {
    for (idx, (instruction_a, layout_a)) in layouts.iter().enumerate() {
        for (instruction_b, layout_b) in layouts.iter().skip(idx + 1) {
            // Lanes instantiated from one scalable instruction are that single
            // instruction, so they do not contend for its encoding.
            if !instruction_a.scalable_origin.is_empty()
                && instruction_a.scalable_origin == instruction_b.scalable_origin
            {
                continue;
            }
            let shared_mask = layout_a.mask_value & layout_b.mask_value;
            if instruction_encoding_spaces_intersect(instruction_a, instruction_b)
                && (layout_a.match_value ^ layout_b.match_value) & shared_mask == 0
                && mode_sets_intersect(&instruction_a.modes, &instruction_b.modes)
                && slot_sets_intersect(document, instruction_a, instruction_b)
                && !decode_constraints_prove_disjoint(
                    instruction_a,
                    layout_a,
                    instruction_b,
                    layout_b,
                )
            {
                return Err(ValidationError::new(format!(
                    "instructions `{}` and `{}` overlap in the decode space of a shared mode: \
                     their fixed bits agree on every shared mask position \
                     (match 0x{:08x}/mask 0x{:08x} vs match 0x{:08x}/mask 0x{:08x}); \
                     give them disjoint `modes`, or units held by disjoint packet \
                     slots, to reuse the encoding",
                    instruction_a.mnemonic,
                    instruction_b.mnemonic,
                    layout_a.match_value,
                    layout_a.mask_value,
                    layout_b.match_value,
                    layout_b.mask_value,
                )));
            }
        }
    }
    Ok(())
}

/// Prove the common alias case where one declaration fixes a complete word
/// and the broader declaration's operand constraint rejects that word. Unknown
/// or architecture-specific predicates remain conservative and cannot hide an
/// overlap.
fn decode_constraints_prove_disjoint(
    instruction_a: &Instruction,
    layout_a: &InstructionLayout,
    instruction_b: &Instruction,
    layout_b: &InstructionLayout,
) -> bool {
    // One instruction's constraint proves the two disjoint when it rejects
    // every word the *other* accepts -- which can be decided by evaluation
    // when the other pins all but a few of the bits the constraint reads.
    //
    // The condition used to be that the other's mask was *full*, which is the
    // same statement for an encoding with no free fields and needlessly
    // stronger for anything else. RISC-V's `C.MV` and `C.JR` share `funct4`
    // and differ only in whether `rs2` is zero: `C.JR` pins `rs2` and leaves
    // `rd` free, so no mask here is full and two genuinely disjoint
    // instructions looked like an overlap.
    //
    // ⚠️ And then it was that the other pins EVERY bit the constraint reads,
    // which is still stronger than the question. AArch64's shift by
    // immediate requires `immh:immb > 7`; the modified immediates live at
    // `immh = 0` and leave `immb` free as immediate bits. Seven bits read,
    // four pinned, and the four decide it -- so the free ones are enumerated,
    // a handful of evaluations, and the proof stays exact.
    //
    // ⚠️ And when BOTH carry a rule over the same free field, neither rule
    // alone says anything about the other's words: AArch64's fixed-point
    // SCVTF is `immh:immb > 31` for singles and `15 < immh:immb < 32` for
    // halves, one encoding, the field free in both. The question is then
    // whether any word satisfies the two at once -- asked of every setting
    // of the free bits the rules read, under the same bound.
    constraint_rejects_all_of(instruction_a, layout_a, layout_b)
        || constraint_rejects_all_of(instruction_b, layout_b, layout_a)
        || constraints_never_both_accept(instruction_a, layout_a, instruction_b, layout_b)
}

/// The instruction bits `instruction`'s decode constraint reads, or `None`
/// when it has none or reads an operand bound to no field.
fn constraint_read_bits(instruction: &Instruction, layout: &InstructionLayout) -> Option<u32> {
    let constraint = instruction.decode_constraint.as_ref()?;
    let mut operands = Vec::new();
    collect_constraint_operands(constraint, &mut operands);
    if operands.is_empty() {
        return None;
    }
    let mut read = 0u32;
    for name in &operands {
        let bindings = layout.operand_bindings(name);
        if bindings.is_empty() {
            return None;
        }
        for field in bindings {
            let width = if field.width >= 32 {
                u32::MAX
            } else {
                (1u32 << field.width) - 1
            };
            read |= width << field.insn_lo;
        }
    }
    Some(read)
}

/// Is there no word both instructions accept? Their fixed bits already agree
/// (that is how they came to be compared), so the words in common are those
/// fixed bits with anything in the rest; only the bits the two rules read can
/// matter, and those left free by both are enumerated.
fn constraints_never_both_accept(
    instruction_a: &Instruction,
    layout_a: &InstructionLayout,
    instruction_b: &Instruction,
    layout_b: &InstructionLayout,
) -> bool {
    let (Some(read_a), Some(read_b)) = (
        constraint_read_bits(instruction_a, layout_a),
        constraint_read_bits(instruction_b, layout_b),
    ) else {
        return false;
    };
    let pinned = layout_a.mask_value | layout_b.mask_value;
    let free = (read_a | read_b) & !pinned;
    if free.count_ones() > MAX_ENUMERATED_BITS {
        return false;
    }
    let base = (layout_a.match_value | layout_b.match_value) & !free;
    let mut setting = 0u32;
    loop {
        let word = base | setting;
        match (
            constraint_accepts_word(instruction_a, layout_a, word),
            constraint_accepts_word(instruction_b, layout_b, word),
        ) {
            (Some(true), Some(true)) | (None, _) | (_, None) => return false,
            _ => {}
        }
        if setting == free {
            return true;
        }
        setting = setting.wrapping_sub(free) & free;
    }
}

/// The most free bits `constraint_rejects_all_of` will enumerate.
const MAX_ENUMERATED_BITS: u32 = 10;

/// Does `instruction`'s decode constraint reject every word `other` accepts?
/// Only the bits the constraint reads matter, so `other`'s match value is
/// tried with each setting of those it leaves free -- when there are few
/// enough to try them all; otherwise the answer is no.
fn constraint_rejects_all_of(
    instruction: &Instruction,
    layout: &InstructionLayout,
    other: &InstructionLayout,
) -> bool {
    let Some(constraint) = instruction.decode_constraint.as_ref() else {
        return false;
    };
    let mut operands = Vec::new();
    collect_constraint_operands(constraint, &mut operands);
    if operands.is_empty() {
        return false;
    }
    let mut read = 0u32;
    for name in &operands {
        let bindings = layout.operand_bindings(name);
        if bindings.is_empty() {
            return false;
        }
        for field in bindings {
            let width = if field.width >= 32 {
                u32::MAX
            } else {
                (1u32 << field.width) - 1
            };
            read |= width << field.insn_lo;
        }
    }
    let free = read & !other.mask_value;
    if free.count_ones() > MAX_ENUMERATED_BITS {
        return false;
    }
    let base = other.match_value & !free;
    let mut setting = 0u32;
    loop {
        if constraint_accepts_word(instruction, layout, base | setting) != Some(false) {
            return false;
        }
        if setting == free {
            return true;
        }
        setting = setting.wrapping_sub(free) & free;
    }
}

/// Every operand a decode constraint reads.
fn collect_constraint_operands(
    constraint: &crate::decode_constraint::DecodeConstraint,
    into: &mut Vec<String>,
) {
    use crate::decode_constraint::DecodeConstraint as C;
    let mut push = |name: &str| {
        if !into.iter().any(|seen| seen == name) {
            into.push(name.to_string());
        }
    };
    match constraint {
        C::UnsignedCompare { operand, .. } | C::MaskedEq { operand, .. } => push(operand),
        C::A64LogicalImmediate { n, imms, .. } => {
            if let crate::decode_constraint::ConstraintValue::Operand(name) = n {
                push(name);
            }
            push(imms);
        }
        C::A64ShiftedRegister { shift, amount, .. } => {
            push(shift);
            push(amount);
        }
        C::A64ExtendedRegister { amount } => push(amount),
        C::And(parts) | C::Or(parts) => {
            for part in parts {
                collect_constraint_operands(part, into);
            }
        }
        C::Not(inner) => collect_constraint_operands(inner, into),
    }
}

/// Whether `instruction`'s decode constraint certainly REFUSES `word`. A
/// decoder that matches on fixed bits alone asks this to skip a row whose
/// `requires` rules the word out; a constraint this cannot judge refuses
/// nothing, so such a decoder is never stricter than it was.
pub(crate) fn decode_constraint_refuses(
    instruction: &Instruction,
    layout: &InstructionLayout,
    word: u32,
) -> bool {
    constraint_accepts_word(instruction, layout, word) == Some(false)
}

fn constraint_accepts_word(
    instruction: &Instruction,
    layout: &InstructionLayout,
    word: u32,
) -> Option<bool> {
    let constraint = instruction.decode_constraint.as_ref()?;
    eval_simple_decode_constraint(constraint, layout, word)
}

fn eval_simple_decode_constraint(
    constraint: &crate::decode_constraint::DecodeConstraint,
    layout: &InstructionLayout,
    word: u32,
) -> Option<bool> {
    use crate::decode_constraint::{CompareOp, DecodeConstraint};
    match constraint {
        DecodeConstraint::UnsignedCompare {
            operand,
            op,
            literal,
        } => {
            let value = extract_layout_operand(layout, word, operand)?;
            Some(match op {
                CompareOp::Eq => value == *literal,
                CompareOp::Ne => value != *literal,
                CompareOp::Lt => value < *literal,
                CompareOp::Le => value <= *literal,
                CompareOp::Gt => value > *literal,
                CompareOp::Ge => value >= *literal,
            })
        }
        DecodeConstraint::MaskedEq {
            operand,
            mask,
            value,
        } => Some(extract_layout_operand(layout, word, operand)? & mask == *value),
        DecodeConstraint::And(children) => {
            let values = children
                .iter()
                .map(|child| eval_simple_decode_constraint(child, layout, word))
                .collect::<Option<Vec<_>>>()?;
            Some(values.into_iter().all(|value| value))
        }
        DecodeConstraint::Or(children) => {
            let values = children
                .iter()
                .map(|child| eval_simple_decode_constraint(child, layout, word))
                .collect::<Option<Vec<_>>>()?;
            Some(values.into_iter().any(|value| value))
        }
        DecodeConstraint::Not(child) => {
            eval_simple_decode_constraint(child, layout, word).map(|value| !value)
        }
        _ => None,
    }
}

fn extract_layout_operand(layout: &InstructionLayout, word: u32, operand: &str) -> Option<u32> {
    let bindings = layout.operand_bindings(operand);
    if bindings.is_empty() {
        return None;
    }
    let mut value = 0u32;
    for field in bindings {
        let mask = if field.width >= 32 {
            u32::MAX
        } else {
            (1u32 << field.width) - 1
        };
        value |= ((word >> field.insn_lo) & mask) << field.op_lo;
    }
    Some(value)
}

/// Empty ISA bindings are extension-wide for backward compatibility. Two
/// explicit, distinct ISA bindings are independent decode spaces and may reuse
/// the same instruction word.
fn instruction_encoding_spaces_intersect(a: &Instruction, b: &Instruction) -> bool {
    a.isa.is_empty() || b.isa.is_empty() || a.isa == b.isa
}

/// Mode sets intersect (share at least one mode). An empty set means "legal in
/// all modes", so it intersects every other set.
fn mode_sets_intersect(a: &[String], b: &[String]) -> bool {
    a.is_empty() || b.is_empty() || a.iter().any(|mode| b.contains(mode))
}

/// A CSR address in a RISC-V custom-use range (where a mode selector lives).
fn is_custom_csr(csr: u32) -> bool {
    matches!(csr, 0x800..=0x8ff | 0xbc0..=0xbff | 0x7c0..=0x7ff | 0xcc0..=0xcff)
}

/// Validate the single optional `mode` selector: distinct value names/numbers
/// that fit the WARL field, a `default` naming one of them, and a custom CSR.
/// A memory-resident configuration, and the instruction that establishes it,
/// must agree about where each field lives.
///
/// ⚠️ This is the whole content of `defconfig`, and the reason it is worth
/// having. The semantics were always describable: an instruction that reads a
/// 64-byte block and writes sixteen configuration slots validates and emits
/// through every backend without any of this, measured before the construct
/// was designed. What it could not do is *say* that those slots were a
/// configuration or where in the block each one sat -- a runtime that had to
/// build the block would have read byte offsets out of an effect expression.
///
/// So the declaration states a layout the semantics already imply, and the two
/// are required to agree. A declaration nothing checks is a comment.
/// The completion contract: when an engine's writes land, what the host sees
/// before then, and whether the launch fences (`docs/tensor_design.md`, T9).
///
/// ⚠️ Every check here is an agreement between the contract and something the
/// description already said. A tightly coupled engine finishes inside the
/// launching instruction, so it has nothing to poll and no in-flight window; a
/// queue-descriptor one outlives its launch, so it must say how the host
/// learns it is done. `coupling` and `visibility` are the same fact stated
/// twice, and a description that states them differently was accepted in
/// silence before this.
///
/// What is NOT checked here is the timing itself, and the reason is worth
/// writing down rather than discovering: an accelerator is a pure function of
/// its ports in every backend, so there is no execution model with a
/// mid-flight moment in it. An interleaving gate needs one built first, which
/// is a larger thing than a declaration and has nothing waiting on it. The
/// declaration has a consumer today -- a runtime cannot write correct code
/// against a queue-descriptor engine without knowing these three answers.
fn validate_completion_contract(document: &Document) -> Result<(), ValidationError> {
    for accelerator in &document.accelerators {
        let named = |what: &str, value: &str, allowed: &[&str]| -> Result<(), ValidationError> {
            if value.is_empty() || allowed.contains(&value) {
                return Ok(());
            }
            Err(ValidationError::new(format!(
                "accelerator `{}` {what} `{value}` is not one of: {}",
                accelerator.name,
                allowed.join(", ")
            )))
        };
        named("visibility", &accelerator.visibility, ACCELERATOR_VISIBILITY)?;
        named("launch-fence", &accelerator.launch_fence, ACCELERATOR_FENCES)?;
        named("in-flight", &accelerator.in_flight, ACCELERATOR_IN_FLIGHT)?;

        let synchronous = SYNCHRONOUS_COUPLINGS.contains(&accelerator.coupling.as_str());
        match accelerator.visibility.as_str() {
            "immediate" => {
                if !synchronous {
                    return Err(ValidationError::new(format!(
                        "accelerator `{}` is `{}` coupled and claims its writes are \
                         immediate; an engine that outlives its launch has a moment \
                         before they land",
                        accelerator.name, accelerator.coupling
                    )));
                }
                if !accelerator.completion.trim().is_empty() {
                    return Err(ValidationError::new(format!(
                        "accelerator `{}` completes inside its launch and names a \
                         completion field `{}`; there is nothing to poll",
                        accelerator.name, accelerator.completion
                    )));
                }
            }
            "atomic-at-completion" | "progressive" => {
                if synchronous {
                    return Err(ValidationError::new(format!(
                        "accelerator `{}` is tightly coupled and claims its writes land \
                         at a completion; it has no completion to land at",
                        accelerator.name
                    )));
                }
                if accelerator.completion.trim().is_empty() {
                    return Err(ValidationError::new(format!(
                        "accelerator `{}` lands its writes at a completion and names no \
                         completion field; nothing tells the host it is done",
                        accelerator.name
                    )));
                }
                if accelerator.visibility == "progressive" && accelerator.in_flight.is_empty() {
                    return Err(ValidationError::new(format!(
                        "accelerator `{}` writes progressively and does not say what the \
                         host sees while it runs; a partial result the host may read is \
                         the whole content of that word",
                        accelerator.name
                    )));
                }
            }
            _ => {}
        }
        if !accelerator.in_flight.is_empty() && accelerator.visibility == "immediate" {
            return Err(ValidationError::new(format!(
                "accelerator `{}` declares what is visible in flight and has no flight",
                accelerator.name
            )));
        }
        if !accelerator.in_flight.is_empty() && accelerator.visibility.is_empty() {
            return Err(ValidationError::new(format!(
                "accelerator `{}` declares what is visible in flight and does not say \
                 when its writes land",
                accelerator.name
            )));
        }
    }
    Ok(())
}

fn validate_configs(document: &Document) -> Result<(), ValidationError> {
    for config in &document.configs {
        require_identifier("defconfig.name", &config.name)?;
        if config.bytes == 0 {
            return Err(ValidationError::new(format!(
                "config `{}` is zero bytes, so it configures nothing",
                config.name
            )));
        }
        if config.fields.is_empty() {
            return Err(ValidationError::new(format!(
                "config `{}` declares no fields",
                config.name
            )));
        }
        let mut seen: Vec<(u32, u32, &str)> = Vec::new();
        for field in &config.fields {
            require_identifier("config field name", &field.name)?;
            if field.width == 0 {
                return Err(ValidationError::new(format!(
                    "config `{}` field `{}` is zero bytes wide",
                    config.name, field.name
                )));
            }
            if field.at + field.width > config.bytes {
                return Err(ValidationError::new(format!(
                    "config `{}` field `{}` runs from byte {} for {} and the block is {}",
                    config.name, field.name, field.at, field.width, config.bytes
                )));
            }
            if field.values.is_empty() {
                return Err(ValidationError::new(format!(
                    "config `{}` field `{}` names no legal values; a configuration a \
                     machine cannot be put into is not one",
                    config.name, field.name
                )));
            }
            for (at, width, other) in &seen {
                if field.at < at + width && *at < field.at + field.width {
                    return Err(ValidationError::new(format!(
                        "config `{}` fields `{}` and `{other}` overlap at byte {}",
                        config.name,
                        field.name,
                        field.at.max(*at)
                    )));
                }
            }
            seen.push((field.at, field.width, &field.name));
        }
        // The instantiation: every field, once, with a value it declared.
        for (name, value) in &config.instantiate {
            let Some(field) = config.fields.iter().find(|field| &field.name == name) else {
                return Err(ValidationError::new(format!(
                    "config `{}` instantiates `{name}`, which is not one of its fields",
                    config.name
                )));
            };
            if !field.values.contains(value) {
                return Err(ValidationError::new(format!(
                    "config `{}` instantiates `{name}` at {value}, which is not one of \
                     its legal values",
                    config.name
                )));
            }
        }
        for field in &config.fields {
            if !config
                .instantiate
                .iter()
                .any(|(name, _)| name == &field.name)
            {
                return Err(ValidationError::new(format!(
                    "config `{}` leaves `{}` uninstantiated; a description is elaborated \
                     at one configuration, so it names one",
                    config.name, field.name
                )));
            }
        }
    }

    for instruction in &document.instructions {
        if instruction.configures.is_empty() {
            continue;
        }
        let Some(config) = document
            .configs
            .iter()
            .find(|config| config.name == instruction.configures)
        else {
            return Err(ValidationError::new(format!(
                "instruction `{}` configures `{}`, which is not declared",
                instruction.mnemonic, instruction.configures
            )));
        };
        let Some(behavior) = &instruction.behavior else {
            return Err(ValidationError::new(format!(
                "instruction `{}` configures `{}` and has no behavior, so nothing \
                 establishes it",
                instruction.mnemonic, config.name
            )));
        };
        for field in &config.fields {
            let writes: Vec<&crate::effects::Effect> = behavior
                .effects
                .iter()
                .filter(|effect| {
                    matches!(&effect.loc, crate::effects::Loc::State { name, .. }
                             if name == &field.name)
                })
                .collect();
            if writes.len() != 1 {
                return Err(ValidationError::new(format!(
                    "instruction `{}` writes `{}` {} time(s) and config `{}` declares it \
                     once",
                    instruction.mnemonic,
                    field.name,
                    writes.len(),
                    config.name
                )));
            }
            let text = crate::effects::render_semexpr(&writes[0].value.expr);
            let Some(offset) = load_offset(&text) else {
                return Err(ValidationError::new(format!(
                    "instruction `{}` writes `{}` from `{text}`, which is not a load at a \
                     constant offset from the block",
                    instruction.mnemonic, field.name
                )));
            };
            if offset != field.at {
                return Err(ValidationError::new(format!(
                    "instruction `{}` reads `{}` from byte {offset} and config `{}` \
                     declares byte {}",
                    instruction.mnemonic, field.name, config.name, field.at
                )));
            }
        }
    }
    Ok(())
}

/// The constant byte offset a `(load ... (add <base> <offset>))` reads at, or
/// zero when the address is the base alone.
///
/// Textual because the alternative -- walking the typed IR for a load whose
/// address is an add of a symbol and a literal -- is the same pattern matching
/// one layer down, and this shape is produced by the effect elaborator rather
/// than written by hand.
fn load_offset(text: &str) -> Option<u32> {
    let address = text.rsplit_once(' ')?.1.trim_end_matches(')');
    if let Ok(value) = address.parse::<u32>() {
        return Some(value);
    }
    if !text.contains("(load ") {
        return None;
    }
    // `(load <type> <sign> <base>)`: the address is a bare operand, so byte 0.
    if !text.contains("(add ") {
        return Some(0);
    }
    None
}

fn validate_modes(document: &Document) -> Result<(), ValidationError> {
    if document.modes.len() > 1 {
        return Err(ValidationError::new(
            "at most one `mode` block is allowed in v1",
        ));
    }
    let Some(mode) = document.modes.first() else {
        return Ok(());
    };
    require_identifier("mode.name", &mode.name)?;
    if !is_custom_csr(mode.csr) {
        return Err(ValidationError::new(format!(
            "mode `{}` csr 0x{:x} is not in a RISC-V custom CSR range",
            mode.name, mode.csr
        )));
    }
    if mode.field_hi < mode.field_lo {
        return Err(ValidationError::new(format!(
            "mode `{}` field [{}:{}] is inverted",
            mode.name, mode.field_hi, mode.field_lo
        )));
    }
    if mode.values.is_empty() {
        return Err(ValidationError::new(format!(
            "mode `{}` requires at least one value",
            mode.name
        )));
    }
    let width = mode.field_hi - mode.field_lo + 1;
    let capacity = if width >= 32 {
        u32::MAX
    } else {
        (1u32 << width) - 1
    };
    let mut names = HashSet::new();
    let mut numbers = HashSet::new();
    for (name, value) in &mode.values {
        require_identifier("mode value name", name)?;
        if !names.insert(name.clone()) {
            return Err(ValidationError::new(format!(
                "mode `{}` value name `{name}` is duplicated",
                mode.name
            )));
        }
        if !numbers.insert(*value) {
            return Err(ValidationError::new(format!(
                "mode `{}` value {value} is assigned to two names",
                mode.name
            )));
        }
        if *value > capacity {
            return Err(ValidationError::new(format!(
                "mode `{}` value {value} does not fit in field [{}:{}]",
                mode.name, mode.field_hi, mode.field_lo
            )));
        }
    }
    if !names.contains(&mode.default) {
        return Err(ValidationError::new(format!(
            "mode `{}` default `{}` must name one of its values",
            mode.name, mode.default
        )));
    }
    Ok(())
}

/// Every `instruction.modes` entry must name a declared mode value.
fn validate_instruction_modes(document: &Document) -> Result<(), ValidationError> {
    let value_names: HashSet<&str> = document
        .modes
        .first()
        .map(|mode| mode.values.iter().map(|(name, _)| name.as_str()).collect())
        .unwrap_or_default();
    for instruction in &document.instructions {
        for mode in &instruction.modes {
            if !value_names.contains(mode.as_str()) {
                return Err(ValidationError::new(format!(
                    "instruction `{}` mode `{mode}` is not a declared mode value",
                    instruction.mnemonic
                )));
            }
        }
    }
    for packet in &document.packets {
        if !packet.mode.is_empty() && !value_names.contains(packet.mode.as_str()) {
            return Err(ValidationError::new(format!(
                "packet `{}` mode `{}` is not a declared mode value",
                packet.name, packet.mode
            )));
        }
    }
    for fabric in &document.fabrics {
        if !fabric.mode.is_empty() && !value_names.contains(fabric.mode.as_str()) {
            return Err(ValidationError::new(format!(
                "fabric `{}` mode `{}` is not a declared mode value",
                fabric.name, fabric.mode
            )));
        }
    }
    Ok(())
}

fn validate_costs(instruction: &Instruction) -> Result<(), ValidationError> {
    validate_float(
        instruction,
        "throughput_per_cycle",
        &instruction.throughput_per_cycle,
        true,
    )?;
    validate_float(
        instruction,
        "area_estimate_um2",
        &instruction.area_estimate_um2,
        false,
    )?;
    validate_float(
        instruction,
        "power_estimate_mw",
        &instruction.power_estimate_mw,
        false,
    )?;
    validate_float(
        instruction,
        "expected_speedup",
        &instruction.expected_speedup,
        true,
    )?;
    Ok(())
}

fn validate_float(
    instruction: &Instruction,
    field: &str,
    raw: &str,
    must_be_positive: bool,
) -> Result<(), ValidationError> {
    let value = raw.parse::<f64>().map_err(|_| {
        ValidationError::new(format!(
            "instruction `{}` {field} must be numeric",
            instruction.mnemonic
        ))
    })?;
    if !value.is_finite() {
        return Err(ValidationError::new(format!(
            "instruction `{}` {field} must be finite",
            instruction.mnemonic
        )));
    }
    if must_be_positive && value <= 0.0 {
        return Err(ValidationError::new(format!(
            "instruction `{}` {field} must be positive",
            instruction.mnemonic
        )));
    }
    if !must_be_positive && value < 0.0 {
        return Err(ValidationError::new(format!(
            "instruction `{}` {field} must be non-negative",
            instruction.mnemonic
        )));
    }
    Ok(())
}

fn validate_operands(instruction: &Instruction) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for operand in &instruction.operands {
        require_identifier("operand.name", &operand.name)?;
        require_non_empty("operand.kind", &operand.kind)?;
        if operand.width == 0 {
            return Err(ValidationError::new(format!(
                "instruction `{}` operand `{}` width must be positive",
                instruction.mnemonic, operand.name
            )));
        }
        let expected_width = match operand.kind.as_str() {
            "a64_gpr64" | "a64_gpr64sp" => Some(64),
            "a64_gpr32" | "a64_gpr32sp" => Some(32),
            _ => None,
        };
        if expected_width.is_some_and(|width| operand.width != width) {
            return Err(ValidationError::new(format!(
                "instruction `{}` operand `{}` kind `{}` requires width {}",
                instruction.mnemonic,
                operand.name,
                operand.kind,
                expected_width.unwrap()
            )));
        }
        // ⚠️ A value has to fit the register it is stored in. A class says how
        // many 64-bit slots one of its registers occupies, and an operand says
        // how wide its value is; where the second exceeds the first the value
        // has nowhere to live. Two corpora declared `i128` operands in a
        // one-limb class, and the executor -- which sizes a wide access from
        // the operand's width -- wrote past the register into its neighbour,
        // clobbering one of the instruction's own sources. The generated code
        // clamps now so no write leaves its register; this is where the
        // description itself is refused, because a clamped write is a quietly
        // truncated value and that is not better.
        // ⚠️ Not a LANE operand. An element of a scalable register places its
        // value inside the register the class names, at a position that depends
        // on VL and the element width rather than on the architecture -- which
        // is why the operand carries its own stride and view and the class
        // cannot state the capacity. `VWADD_VV` widens, so at SEW=64 its
        // destination element is 128 bits in a class whose registers are one
        // slot, and that is the lane machinery working rather than a value with
        // nowhere to live. Checking it here refused six legal (SEW, LMUL)
        // points that the RVV sweep proves are legal.
        // The instruction as a whole, not only the operand: a lane expansion
        // keeps the origin's operands beside the per-lane ones, and it is the
        // ORIGIN's that carry a widening instruction's doubled width with no
        // placement of their own. `VNSRL_WV` narrows, so its source is 2xSEW
        // and sits in a class whose registers are one slot.
        let lane_placed = operand.element
            || operand.view_width != 0
            || operand.slot_stride != 0
            || operand.lane_register != 0
            || !instruction.scalable_origin.is_empty()
            || instruction.mnemonic.contains("__l");
        if let Some(rules) = crate::ast::register_class(&operand.kind).filter(|_| !lane_placed) {
            let capacity = u32::from(rules.limbs.max(1)) * 64;
            if operand.width > capacity {
                return Err(ValidationError::new(format!(
                    "instruction `{}` operand `{}` is {} bits and its register \
                     class `{}` holds {} ({} limb(s) of 64); name a class wide \
                     enough for the value",
                    instruction.mnemonic, operand.name, operand.width,
                    operand.kind, capacity, rules.limbs.max(1)
                )));
            }
        }
        // ⚠️ An assembly transform has to stay inside the numbers text can
        // carry, over the WHOLE field, not just the values a fixture happens
        // to use. `(minus-from k)` on a w-bit field prints `k` down to
        // `k - (2^w - 1)`, so `k` below `2^w - 1` prints a negative number for
        // some legal encoding -- and an assembler reading it back would have
        // to parse a sign this description never said was there. Checked here
        // rather than discovered by the one fixture that reaches it.
        if operand.asm_transform != crate::ast::AsmTransform::Identity {
            if crate::ast::register_class(&operand.kind).is_some() {
                return Err(ValidationError::new(format!(
                    "instruction `{}` operand `{}` is a register and carries an \
                     assembly transform; a transform relates an encoded number \
                     to a printed one, and a register operand prints a name",
                    instruction.mnemonic, operand.name
                )));
            }
            let span = u64::from(operand.width.min(63));
            let highest = (1u64 << span) - 1;
            let lowest = operand.asm_transform.print(highest).min(operand.asm_transform.print(0));
            if lowest < 0 {
                return Err(ValidationError::new(format!(
                    "instruction `{}` operand `{}` assembly transform prints {} \
                     for a legal encoding, and the assembly syntax has no sign \
                     for it",
                    instruction.mnemonic, operand.name, lowest
                )));
            }
            // And it must run backwards for every one of them, which is the
            // property the closed set exists to guarantee rather than assume.
            for field in [0u64, 1, highest / 2, highest] {
                let printed = operand.asm_transform.print(field);
                if operand.asm_transform.encode(printed) != field as i64 {
                    return Err(ValidationError::new(format!(
                        "instruction `{}` operand `{}` assembly transform does \
                         not invert at {field}",
                        instruction.mnemonic, operand.name
                    )));
                }
            }
        }
        if !operand.derived_from.is_empty() {
            let Some(source) = instruction
                .operands
                .iter()
                .find(|candidate| candidate.name == operand.derived_from)
            else {
                return Err(ValidationError::new(format!(
                    "instruction `{}` derived operand `{}` references unknown operand `{}`",
                    instruction.mnemonic, operand.name, operand.derived_from
                )));
            };
            if !source.derived_from.is_empty() {
                return Err(ValidationError::new(format!(
                    "instruction `{}` derived operand `{}` must reference a directly encoded operand",
                    instruction.mnemonic, operand.name
                )));
            }
            // A zero offset would make a derived operand a second name for the
            // same register, which is why the rule exists: AArch64's CASP pair
            // encodes its first register and the second is `+1`.
            //
            // A lane operand is the exception, and not a loophole: it names a
            // different *element* of the same register, so deriving with offset
            // zero says exactly what is true. What separates the two cases is
            // whether the operand carries element packing, so that is what the
            // rule asks.
            if operand.derived_add == 0 && !operand.lane_packed {
                return Err(ValidationError::new(format!(
                    "instruction `{}` derived operand `{}` offset must be positive",
                    instruction.mnemonic, operand.name
                )));
            }
            if source.kind != operand.kind || source.width != operand.width {
                return Err(ValidationError::new(format!(
                    "instruction `{}` derived operand `{}` must match source `{}` kind and width",
                    instruction.mnemonic, operand.name, operand.derived_from
                )));
            }
            // A class that aliases an index to a state slot cannot be derived
            // from: index 31 of AArch64's `sp` classes is the stack pointer
            // rather than a file entry, so "the next register along" names
            // nothing. That was written as a list of the three kinds that
            // happened to be allowed, which excluded every class added since --
            // including the vector file, whose lane operands derive from a
            // selector. The property was never the name; it is the alias.
            let derivable = crate::ast::register_class(&operand.kind)
                .is_some_and(|class| class.alias.is_none());
            if !derivable {
                return Err(ValidationError::new(format!(
                    "instruction `{}` derived operand `{}` needs a register kind \
                     with no aliased index",
                    instruction.mnemonic, operand.name
                )));
            }
        } else if operand.derived_add != 0 {
            return Err(ValidationError::new(format!(
                "instruction `{}` operand `{}` has a derived offset without a source",
                instruction.mnemonic, operand.name
            )));
        }
        // A fixed operand names one register of a file with no aliased index:
        // a number that is a register everywhere, like the derived case.
        if operand.fixed.is_some() {
            let plain = crate::ast::register_class(&operand.kind)
                .is_some_and(|class| class.alias.is_none());
            if !plain || !operand.derived_from.is_empty() {
                return Err(ValidationError::new(format!(
                    "instruction `{}` fixed operand `{}` needs a register kind with \
                     no aliased index, and no derivation",
                    instruction.mnemonic, operand.name
                )));
            }
        }
        if !names.insert(operand.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "instruction `{}` has duplicate operand `{}`",
                instruction.mnemonic, operand.name
            )));
        }
    }
    Ok(())
}

fn validate_instruction_formal_semantics(
    document: &Document,
    instruction: &Instruction,
) -> Result<(), ValidationError> {
    let symbols: Vec<String> = instruction
        .operands
        .iter()
        .map(|operand| operand.name.clone())
        .collect();
    validate_formal_semantics(&instruction.formal_semantics, &symbols).map_err(|err| {
        ValidationError::new(format!(
            "instruction `{}` {}",
            instruction.mnemonic, err.message
        ))
    })?;
    // An exception word is not a value. The SMT emitter says so with an
    // `unreachable!` rather than a decline, on the reasoning that the flags an
    // operation raises are architectural state and so live in a behavior --
    // and that reasoning was an *assumption*, not a rule anything enforced, so
    // a formal that said `(or i64 (fadd_fx f64 rs1 rs2) 0)` parsed, validated,
    // and panicked the SMT backend. It is a rule here now, which is what lets
    // the `unreachable!`s mean what they claim.
    if crate::emit::semantics::uses_fp_exceptions(&instruction.formal_semantics) {
        return Err(ValidationError::new(format!(
            "instruction `{}` uses an exception form (`_fx`) in `formal`, but the \
             exceptions an operation raises are architectural state: accrue them \
             in a behavior, as `(setstate fflags (or i5 fflags ...) i5)`",
            instruction.mnemonic
        )));
    }
    // Effectful instructions carry their semantics in `effects` (empty
    // formal_semantics); validate the effect values (memory loads and their
    // pure address expressions) against the operand scope.
    if let Some(behavior) = &instruction.behavior {
        // `isa_scalar_state_slots` and not a filter written here: this site had
        // its own copy of "which declarations are readable state", which is the
        // third place that rule lived and the reason a synthesised slot
        // (`lane_id`) reached the parser's scope and not this one. One
        // definition, asked for the instruction's own ISA.
        // Which ISA an instruction belongs to is one question with one
        // answer: the one it names, or the only one the document declares. It
        // was asked here by name alone, so in the twenty-one corpora whose
        // instructions do not repeat their ISA the state scope was empty --
        // no instruction in any of them could read or write architectural
        // state, and the error said the slot was not declared when it was.
        let states: Vec<(String, u32)> = crate::ast::instruction_isa(document, instruction)
            .map(|isa| crate::effects::isa_scalar_state_slots(std::slice::from_ref(isa)))
            .unwrap_or_default();
        crate::effects::validate_behavior(behavior, &symbols, &states).map_err(|message| {
            ValidationError::new(format!(
                "instruction `{}` effects: {message}",
                instruction.mnemonic
            ))
        })?;
    } else if !instruction.effects.trim().is_empty() {
        return Err(ValidationError::new(format!(
            "instruction `{}` has effect source text without canonical typed behavior",
            instruction.mnemonic
        )));
    }
    Ok(())
}

fn validate_isas(isas: &[Isa]) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for isa in isas {
        require_identifier("isa.name", &isa.name)?;
        if !matches!(isa.role.as_str(), "" | "source" | "target") {
            return Err(ValidationError::new(format!(
                "isa `{}` role `{}` must be source or target",
                isa.name, isa.role
            )));
        }
        require_non_empty(&format!("isa `{}` base", isa.name), &isa.base)?;
        // `lane_id` is synthesised for an ISA that declares lanes, so an ISA
        // must not also declare it: two definitions of one name is how a
        // consumer ends up reading whichever the elaboration happened to keep.
        if isa.registers.iter().any(|raw| {
            raw.split(':').next().unwrap_or(raw).trim() == crate::effects::LANE_ID
        }) {
            return Err(ValidationError::new(format!(
                "isa `{}` declares `{}`, which is synthesised from `lanes`; \
                 remove the declaration or the lane count",
                isa.name,
                crate::effects::LANE_ID
            )));
        }
        if isa.word_bits == 0 {
            return Err(ValidationError::new(format!(
                "isa `{}` word_bits must be positive",
                isa.name
            )));
        }
        if !matches!(canonical_value(&isa.endianness).as_str(), "little" | "big") {
            return Err(ValidationError::new(format!(
                "isa `{}` endianness `{}` must be little or big",
                isa.name, isa.endianness
            )));
        }
        if !names.insert(isa.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate isa `{}`",
                isa.name
            )));
        }
    }
    Ok(())
}

/// A `(kind simt)` core's warp machine (docs/simt_design.md). Everything the
/// SIMT engine does not model is REFUSED rather than ignored: a window or a
/// load/store queue on a warp machine would be a number that changes nothing.
fn validate_core_simt(
    document: &Document,
    core: &crate::ast::Core,
    simt: &crate::ast::CoreSimt,
) -> Result<(), ValidationError> {
    let err = |msg: String| Err(ValidationError::new(format!("core `{}` simt: {msg}", core.name)));
    if !core.kind.eq_ignore_ascii_case("simt") {
        return err(format!("declared on a core of kind `{}`; a warp machine is `(kind simt)`", core.kind));
    }
    if simt.warps == 0 || simt.warps > 64 {
        return err(format!("warps must be 1..64, not {}", simt.warps));
    }
    if simt.lanes == 0 || simt.lanes > 64 {
        return err(format!("lanes must be 1..64 (a mask is one 64-bit word), not {}", simt.lanes));
    }
    if !["gto", "rr"].contains(&simt.scheduler.as_str()) {
        return err(format!("scheduler must be `gto` or `rr`, not `{}`", simt.scheduler));
    }
    if simt.stack == 0 {
        return err("a reconvergence stack of 0 entries cannot take one SPLIT".to_string());
    }
    if !simt.line.is_power_of_two() || simt.line < 4 || simt.line > 4096 {
        return err(format!("line must be a power of two in 4..4096, not {}", simt.line));
    }
    let c = &simt.cache;
    if c.bytes > 0 {
        if c.ways == 0 || c.bytes % (simt.line * c.ways) != 0 || !(c.bytes / (simt.line * c.ways)).is_power_of_two() {
            return err(format!(
                "cache of {} bytes, {} ways, {}-byte lines has no power-of-two number of sets",
                c.bytes, c.ways, simt.line
            ));
        }
        if c.mshrs > 256 {
            return err(format!("at most 256 misses outstanding, not {}", c.mshrs));
        }
        if c.hit == 0 || c.miss < c.hit {
            return err(format!("cache latencies must satisfy 0 < hit <= miss, not hit {} miss {}", c.hit, c.miss));
        }
    }
    if !core.engine.is_empty() || core.rob > 0 || core.lsq.is_some() || !core.rename.is_empty()
        || core.front_end.is_some() || !core.ports.is_empty()
    {
        return err("the SIMT engine models no `engine`, `window`, `lsq`, `rename`, `front-end` or `ports`; \
                    declaring one would be a number that changes nothing"
            .to_string());
    }
    let isas = crate::simt::core_isas(core);
    if isas.is_empty() {
        return err("decodes no ISA: give `(implements ...)` or `(simt (isas ...))`".to_string());
    }
    for isa in &isas {
        if !document.isas.iter().any(|i| i.name.eq_ignore_ascii_case(isa)) {
            return err(format!("decodes unknown isa `{isa}`"));
        }
    }
    let state: Vec<String> = crate::effects::isa_scalar_state_slots(&document.isas)
        .into_iter()
        .map(|(name, _)| name)
        .collect();
    if let Some((top, bytes, granule)) = simt.interleave {
        if granule == 0 || !granule.is_power_of_two() || bytes == 0 || bytes % granule != 0 {
            return err(format!(
                "interleave needs a power-of-two granule dividing the per-thread bytes, not {granule} into {bytes}"
            ));
        }
        let threads = u64::from(simt.warps) * u64::from(simt.lanes);
        let group = u64::from(simt.interleave_group);
        if group > 0 && (threads % group != 0 || !simt.interleave_group.is_power_of_two()) {
            return err(format!("interleave group {group} must be a power of two dividing the {threads} threads"));
        }
        if simt.interleave_xor && group == 0 {
            return err("interleave `xor` swizzles groups, and declares no `group`".to_string());
        }
        if simt.interleave_xor && !(bytes / granule).is_power_of_two() {
            return err(format!(
                "interleave `xor` needs a power-of-two count of granules per thread, not {}: \
                 the XOR would carry a granule out of its group",
                bytes / granule
            ));
        }
        let span = u64::from(bytes) * threads;
        if top < span {
            return err(format!("interleave region of {span} bytes does not fit below top {top}"));
        }
    }
    for (prefix, cycles) in &simt.mnemonic_latency {
        if *cycles == 0 {
            return err(format!("latency 0 for `{prefix}`"));
        }
        if !document.instructions.iter().any(|i| {
            isas.iter().any(|isa| i.isa.eq_ignore_ascii_case(isa)) && i.mnemonic.starts_with(prefix.as_str())
        }) {
            return err(format!("mnemonic-latency `{prefix}` names no instruction this core decodes"));
        }
    }
    if c.banks > 64 {
        return err(format!("at most 64 cache banks, not {}", c.banks));
    }
    for (class, cycles) in &simt.class_latency {
        if !crate::simt::UNIT_CLASSES.contains(&class.as_str())
            && !document.instructions.iter().any(|i| i.unit.eq_ignore_ascii_case(class))
        {
            return err(format!("latency for `{class}`, which is no unit class"));
        }
        if *cycles == 0 {
            return err(format!("latency 0 for `{class}`: a result is never ready the cycle it issues"));
        }
    }
    for slot in &simt.untracked {
        if !state.iter().any(|s| s == slot) {
            return err(format!("untracked state `{slot}` is not state any ISA declares"));
        }
    }
    let cache = &simt.cache;
    if cache.l2_bytes > 0 {
        if cache.l2_ways == 0 || cache.l2_bytes % (simt.line * cache.l2_ways) != 0 {
            return err(format!(
                "l2 of {} bytes is not a whole number of {}-way sets of {}-byte lines",
                cache.l2_bytes, cache.l2_ways, simt.line
            ));
        }
        if cache.l2_hit == 0 || cache.l2_hit >= cache.miss {
            return err(format!("l2-hit {} must be above zero and below the miss latency {}", cache.l2_hit, cache.miss));
        }
    }
    if cache.prefetch_next_line > 0 && cache.prefetch_best_offset > 0 {
        return err("a cache has one prefetcher: next-line or best-offset, not both".to_string());
    }
    if cache.prefetch_degree > 0 && cache.prefetch_next_line == 0
        && (cache.prefetch_entries == 0 || !cache.prefetch_entries.is_power_of_two())
    {
        return err(format!("prefetch needs a power-of-two `prefetch-entries`, not {}", cache.prefetch_entries));
    }
    // U2: a port of a described memory system. Its accesses go there, so a
    // private cache beside it would be a second memory nobody reads, and a
    // line of another size would split one request across lines the system
    // does not have.
    for sys in &document.memsystems {
        for node in sys.nodes.iter().filter(|n| n.core == core.name) {
            if cache.bytes > 0 {
                return err(format!(
                    "is a port of memory system `{}` (node `{}`) and declares its own cache; one or the other",
                    sys.name, node.name
                ));
            }
            if let Some(m) = document.memories.iter().find(|m| m.name == node.memory) {
                if m.line_bytes != 0 && m.line_bytes != simt.line {
                    return err(format!(
                        "has {}-byte lines and memory system `{}` has {}-byte lines",
                        simt.line, sys.name, m.line_bytes
                    ));
                }
            }
        }
    }
    if let Some((address, size, valid)) = &simt.exclusive {
        for slot in [address, size, valid] {
            if !state.iter().any(|s| s == slot) {
                return err(format!("exclusive state `{slot}` is not state any ISA declares"));
            }
        }
    }
    if let Some((rob, predictor, _, entries, _, divergence)) = &simt.ooo {
        if *divergence && (*entries == 0 || !entries.is_power_of_two()) {
            return err(format!("ooo divergence-predictor needs a power-of-two `(entries N)`, not {entries}"));
        }
        if predictor == "bimodal" && (*entries == 0 || !entries.is_power_of_two()) {
            return err(format!("ooo predictor bimodal needs a power-of-two `(entries N)`, not {entries}"));
        }
        if *rob == 0 || *rob > 512 {
            return err(format!("ooo rob must be 1..512, not {rob}"));
        }
        if predictor != "none" && predictor != "perfect" && predictor != "bimodal" {
            return err(format!("unknown ooo predictor `{predictor}`; none (wait for every branch), bimodal or perfect"));
        }
    }
    if let Some(implicit) = &simt.implicit {
        match implicit.policy.as_str() {
            "minpc" => {}
            "minsp-pc" => match &implicit.sp {
                Some((slot, bytes)) if state.iter().any(|s| s == slot) && bytes.is_power_of_two() => {}
                _ => return err("implicit policy `minsp-pc` needs `(sp STATE BYTES)`: a declared state slot and a power-of-two stack size".to_string()),
            },
            "maxdepth-pc" => {
                if implicit.calls.is_empty() || implicit.returns.is_empty() {
                    return err("implicit policy `maxdepth-pc` counts calls: give `(calls ...)` and `(returns ...)`".to_string());
                }
            }
            other => return err(format!("unknown implicit policy `{other}`; policies are minpc, minsp-pc, maxdepth-pc")),
        }
        if implicit.smt && simt.ooo.is_none() {
            return err("(path-issue smt) needs an out-of-order core: `(ooo ...)`".to_string());
        }
        for mnemonic in implicit.calls.iter().chain(&implicit.returns).chain(&implicit.yields).chain(&implicit.relax)
            .chain(&implicit.wait).chain(&implicit.send).chain(&implicit.send_local) {
            if crate::simt::find_instruction(document, &isas, mnemonic).is_none() {
                return err(format!("implicit names `{mnemonic}`, which none of its ISAs has"));
            }
        }
    }
    if let Some(vector) = &simt.vector {
        if !isas.iter().any(|i| i.eq_ignore_ascii_case(&vector.isa)) {
            return err(format!("vector isa `{}` is not one the core decodes", vector.isa));
        }
        if vector.lane_classes.is_empty() {
            return err("vector mode names no `lane-classes`: no register would span the lanes".to_string());
        }
        for slot in &vector.lane_state {
            if !state.iter().any(|s| s == slot) {
                return err(format!("vector lane-state `{slot}` is not state any ISA declares"));
            }
        }
        if let Some((flag_state, mnemonics)) = &vector.flags {
            for needed in [flag_state.as_str(), "simt_arg", "simt_arg2"] {
                if !state.iter().any(|s| s == needed) {
                    return err(format!("vector flags need state `{needed}`, which no ISA declares"));
                }
            }
            if mnemonics.is_empty() {
                return err("vector flags name no instruction".to_string());
            }
        }
        if !vector.sum.is_empty() && !state.iter().any(|s| s == "simt_arg") {
            return err("vector sum needs state `simt_arg`, which no ISA declares".to_string());
        }
        for mnemonic in vector
            .broadcast
            .iter()
            .chain(vector.flags.iter().flat_map(|f| &f.1))
            .chain(&vector.crosslane)
            .chain(&vector.sum)
        {
            let found = document.instructions.iter().any(|i| {
                i.isa.eq_ignore_ascii_case(&vector.isa) && i.mnemonic.eq_ignore_ascii_case(mnemonic)
            });
            if !found {
                return err(format!("vector mode names `{mnemonic}`, which is not an instruction of `{}`", vector.isa));
            }
        }
    }
    for (role, mnemonics) in &simt.warp_control {
        if !crate::simt::ROLES.contains(&role.as_str()) {
            return err(format!("unknown warp-control role `{role}`; roles are {}", crate::simt::ROLES.join(", ")));
        }
        for slot in crate::simt::required_state(role) {
            if !state.iter().any(|s| s == slot) {
                return err(format!(
                    "role `{role}` reads state `{slot}` from its lanes, and no ISA declares it"
                ));
            }
        }
        for mnemonic in mnemonics {
            let Some(instruction) = crate::simt::find_instruction(document, &isas, mnemonic) else {
                return err(format!("role `{role}` binds `{mnemonic}`, which none of its ISAs has"));
            };
            if crate::simt::role_needs_behavior(role) && instruction.behavior.is_none() {
                return err(format!(
                    "role `{role}` binds `{mnemonic}`, which has no behavior: its lanes would compute nothing for the warp to act on"
                ));
            }
        }
    }
    if let Some(read) = &simt.sysread {
        let Some(instruction) = crate::simt::find_instruction(document, &isas, &read.mnemonic) else {
            return err(format!("sysread binds `{}`, which none of its ISAs has", read.mnemonic));
        };
        let has = |name: &str| instruction.operands.iter().any(|o| o.name == name);
        if !has(&read.dst) {
            return err(format!("sysread `{}` has no operand `{}`", read.mnemonic, read.dst));
        }
        for (operand, _) in &read.index {
            if !has(operand) {
                return err(format!("sysread `{}` has no operand `{operand}`", read.mnemonic));
            }
        }
        if read.index.is_empty() {
            return err(format!("sysread `{}` has no index", read.mnemonic));
        }
    }
    for unit in &core.units {
        let name = unit.name.to_ascii_lowercase();
        let declared_by_instruction = document.instructions.iter().any(|i| i.unit.eq_ignore_ascii_case(&name));
        if !crate::simt::UNIT_CLASSES.contains(&name.as_str()) && !declared_by_instruction {
            return err(format!(
                "unit `{}` is neither a derived class ({}) nor named by any instruction",
                unit.name,
                crate::simt::UNIT_CLASSES.join(", ")
            ));
        }
        if unit.lanes > simt.lanes {
            return err(format!("unit `{}` has {} lanes, wider than the {}-lane warp", unit.name, unit.lanes, simt.lanes));
        }
    }
    Ok(())
}

fn validate_cores(document: &Document) -> Result<(), ValidationError> {
    let cores = &document.cores;
    let isa_names: HashSet<String> = document
        .isas
        .iter()
        .map(|isa| isa.name.to_ascii_lowercase())
        .collect();
    let mut names = HashSet::new();
    for core in cores {
        require_identifier("core.name", &core.name)?;
        require_non_empty("core.kind", &core.kind)?;
        validate_allowed_value(
            &format!("core `{}` kind", core.name),
            &core.kind,
            CORE_KINDS,
        )?;
        if core.threads == 0 {
            return Err(ValidationError::new(format!(
                "core `{}` threads must be positive",
                core.name
            )));
        }
        if !core.implements.trim().is_empty()
            && !isa_names.contains(&core.implements.to_ascii_lowercase())
        {
            return Err(ValidationError::new(format!(
                "core `{}` implements unknown isa `{}`",
                core.name, core.implements
            )));
        }
        if !names.insert(core.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate core `{}`",
                core.name
            )));
        }
        crate::timing::validate(core, document).map_err(|message| ValidationError::new(message))?;
        // ⚠️ The two directions of the ISA<->machine linkage, and both of
        // them matter. A core that declares units is claiming to be the
        // machine its instructions run on, so the names have to meet.
        //
        // Checked only when the core declares units at all: a core that
        // says nothing about its pipeline is every core that existed before
        // this form did, and those are not suddenly wrong.
        // ⚠️ `(length NAME)` (VU2) says which operand carries the element
        // count, and is only something to say about a unit that has lanes to
        // count them against, on a core the pipeline times, of instructions
        // that have such an operand.
        if let Some(unit) = core.units.iter().find(|u| !u.length.is_empty()) {
            if core.simt.is_some() || unit.lanes == 0 {
                return Err(ValidationError::new(format!(
                    "core `{}` unit `{}` names a length `{}`, which needs `(lanes N)` on a core \
                     that is not a warp machine",
                    core.name, unit.name, unit.length
                )));
            }
            let implements = core.implements.to_ascii_lowercase();
            let carried = document.instructions.iter().any(|instruction| {
                (implements.is_empty() || instruction.isa.eq_ignore_ascii_case(&implements))
                    && instruction.unit.eq_ignore_ascii_case(&unit.name)
                    && instruction.operands.iter().any(|o| o.name == unit.length)
            });
            if !carried {
                return Err(ValidationError::new(format!(
                    "core `{}` unit `{}` names a length `{}`, and no instruction issuing to it \
                     has an operand of that name; a length nothing carries cannot change a cycle",
                    core.name, unit.name, unit.length
                )));
            }
        }
        // ⚠️ `(transport N)` and `(switch N)` (VU4) are what a unit costs when
        // cores share it, and a warp machine's units are its own engine's.
        if let Some(unit) = core.units.iter().find(|u| u.transport > 0 || u.switch > 0) {
            if core.simt.is_some() {
                return Err(ValidationError::new(format!(
                    "core `{}` unit `{}` declares a transport or switch cost, which a warp \
                     machine (`(kind simt)`) does not read",
                    core.name, unit.name
                )));
            }
        }
        // ⚠️ The scheduler (S1-S3, docs/scheduler_design.md): what enters the
        // window a cycle, how many may wait for one unit, how long the
        // wakeup-and-select loop is, and what a result costs to cross units.
        // Each is the pipeline's, so a warp machine or a model that is not
        // this library reads none of them; and each has to be able to change
        // a cycle.
        {
            let said = core.dispatch_width != 0
                || core.schedule != 0
                || !core.bypass.is_empty()
                || core.units.iter().any(|u| u.queue != 0);
            let problem = if !said {
                None
            } else if core.simt.is_some() || !core.model.is_empty() {
                Some("a scheduler clause on a pipeline that is not this library's".to_string())
            } else if core.schedule > 8 {
                Some(format!("`(schedule {})`; a wakeup-and-select loop of 1 to 8 cycles", core.schedule))
            } else if core.dispatch_width > 64 {
                Some(format!("`(dispatch-width {})`; at most 64 enter a cycle", core.dispatch_width))
            } else if let Some(unit) = core.units.iter().find(|u| u.queue != 0 && core.rob != 0 && u.queue >= core.rob) {
                Some(format!(
                    "unit `{}` with `(queue {})`, no smaller than the window of {}: it can never fill",
                    unit.name, unit.queue, core.rob
                ))
            } else {
                let unit = |name: &String| core.units.iter().any(|u| u.name.eq_ignore_ascii_case(name));
                let mut seen: Vec<(String, String)> = Vec::new();
                let mut found = None;
                for (from, to, cycles) in &core.bypass {
                    let key = (from.to_ascii_lowercase(), to.to_ascii_lowercase());
                    if !unit(from) || !unit(to) {
                        found = Some(format!("a bypass from `{from}` to `{to}`, one of which is no unit of this core"));
                    } else if *cycles == 0 || *cycles > 16 {
                        found = Some(format!("`(bypass ({from} {to} {cycles}))`; a bypass costs 1 to 16 cycles, or it is not one"));
                    } else if seen.contains(&key) {
                        found = Some(format!("the bypass from `{from}` to `{to}` twice"));
                    }
                    if found.is_some() {
                        break;
                    }
                    seen.push(key);
                }
                found
            };
            if let Some(problem) = problem {
                return Err(ValidationError::new(format!("core `{}` declares {problem}", core.name)));
            }
        }
        // ⚠️ S5-S7: a queue several units share names units this core has, each
        // in one queue, and can fill; a rename width is the pipeline's; and a
        // stride is a kind of value prediction.
        {
            let unit = |name: &String| core.units.iter().any(|u| u.name.eq_ignore_ascii_case(name));
            let mut placed: Vec<String> = Vec::new();
            let mut problem = None;
            for (name, size, members) in &core.queues {
                if core.simt.is_some() || !core.model.is_empty() {
                    problem = Some("a pipeline that is not this library's".to_string());
                } else if *size == 0 || (core.rob != 0 && *size >= core.rob) {
                    problem = Some(format!("`(size {size})`; a queue holds at least one and fewer than the window, or it can never fill"));
                } else if members.is_empty() {
                    problem = Some("no units".to_string());
                } else if let Some(missing) = members.iter().find(|m| !unit(m)) {
                    problem = Some(format!("`{missing}`, which is not a unit of this core"));
                } else if let Some(twice) = members.iter().find(|m| placed.contains(&m.to_ascii_lowercase())) {
                    problem = Some(format!("`{twice}`, which is in another queue already"));
                } else if core.queues.iter().filter(|(other, _, _)| other.eq_ignore_ascii_case(name)).count() > 1 {
                    problem = Some("a name another queue has".to_string());
                }
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!(
                        "core `{}` declares queue `{name}` with {problem}",
                        core.name
                    )));
                }
                placed.extend(members.iter().map(|m| m.to_ascii_lowercase()));
            }
            if core.queues.len() > 32 {
                return Err(ValidationError::new(format!("core `{}` declares more than 32 queues", core.name)));
            }
            if core.rename_width != 0 && (core.simt.is_some() || !core.model.is_empty() || core.rename_width > 64) {
                return Err(ValidationError::new(format!(
                    "core `{}` declares `(rename-width {})`; 1 to 64, on this library's pipeline",
                    core.name, core.rename_width
                )));
            }
            if !core.select.is_empty() {
                let problem = if core.select != "oldest" && core.select != "position" {
                    Some(format!("`(select {})`; a scheduler picks the `oldest` or by `position`", core.select))
                } else if core.select == "position" && (core.rob == 0 || core.simt.is_some() || !core.model.is_empty()) {
                    Some("`(select position)` with no window of this library's to have positions in".to_string())
                } else {
                    None
                };
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!("core `{}` declares {problem}", core.name)));
                }
            }
            // ⚠️ ME1: what is done at rename is done by a machine that renames.
            if !core.eliminate.is_empty() {
                let words: Vec<&str> = core.eliminate.split(' ').collect();
                let known = words.iter().all(|word| matches!(*word, "moves" | "zeros"));
                let twice = words.iter().enumerate().any(|(at, word)| words[..at].contains(word));
                let problem = if !known || twice {
                    // ZI1: `zeros` beside `moves`, each once.
                    Some(format!(
                        "`(eliminate {})`; what a machine does at rename is `moves` and `zeros`, each once",
                        core.eliminate
                    ))
                } else if core.rob == 0 || core.simt.is_some() || !core.model.is_empty() {
                    Some(format!("`(eliminate {})` with no window of this library's to rename in", core.eliminate))
                } else {
                    None
                };
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!("core `{}` declares {problem}", core.name)));
                }
            }
            // ⚠️ WM1: a store buffer is where a memory model weaker than
            // sequential consistency comes from, so the ISA's model says
            // which buffers a core of it may have.
            if core.store_buffer != 0 || !core.store_drain.is_empty() {
                let model = document
                    .isas
                    .iter()
                    .find(|isa| isa.name.eq_ignore_ascii_case(&core.implements))
                    .map_or("", |isa| isa.memory_model.as_str());
                let problem = if core.store_buffer == 0 || core.store_buffer > 64 {
                    Some(format!("a store buffer of {} entries; 1 to 64", core.store_buffer))
                } else if !matches!(core.store_drain.as_str(), "" | "order" | "any") {
                    Some(format!("`(drain {})`; a store buffer drains in `order` or `any`", core.store_drain))
                } else if !core.engine.eq_ignore_ascii_case("execute") || core.rob == 0 {
                    Some("a store buffer on a core that is not `(engine execute)` with a window; \
                          only that engine has a moment at which another core could look"
                        .to_string())
                } else if model.eq_ignore_ascii_case("sc") {
                    Some(format!(
                        "a store buffer, and `{}` is sequentially consistent: a store is everyone's when it retires",
                        core.implements
                    ))
                } else if core.store_drain == "any" && !crate::timing::memory_model_is_relaxed(model) {
                    Some(format!(
                        "`(drain any)`, and the memory model of `{}` is `{model}`, which this library does not \
                         know to let stores pass each other (`rvwmo`, `armv8`, `weak` do)",
                        core.implements
                    ))
                } else {
                    None
                };
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!("core `{}` declares {problem}", core.name)));
                }
            }
            // ⚠️ WM2: loads satisfied out of order are the relaxed models' too.
            if !core.load_order.is_empty() {
                let model = document
                    .isas
                    .iter()
                    .find(|isa| isa.name.eq_ignore_ascii_case(&core.implements))
                    .map_or("", |isa| isa.memory_model.as_str());
                let problem = if !matches!(core.load_order.as_str(), "order" | "any" | "tso") {
                    Some(format!("`(load-order {})`; loads are seen in `order`, `tso` or `any`", core.load_order))
                } else if core.load_order != "order"
                    && (!core.engine.eq_ignore_ascii_case("execute") || core.rob == 0)
                {
                    Some(format!(
                        "`(load-order {})` on a core that is not `(engine execute)` with a window",
                        core.load_order
                    ))
                } else if core.load_order == "tso" && model.eq_ignore_ascii_case("sc") {
                    Some(format!(
                        "`(load-order tso)`, and the memory model of `{}` is `sc`, under which a load is not \
                         seen before an older store",
                        core.implements
                    ))
                } else if core.load_order == "any" && !crate::timing::memory_model_is_relaxed(model) {
                    Some(format!(
                        "`(load-order any)`, and the memory model of `{}` is `{model}`, which this library does \
                         not know to let loads pass each other (`rvwmo`, `armv8`, `weak` do)",
                        core.implements
                    ))
                } else {
                    None
                };
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!("core `{}` declares {problem}", core.name)));
                }
            }
            if core.value_stride && core.value_prediction.is_none() {
                return Err(ValidationError::new(format!(
                    "core `{}` asks for a stride with no value predictor to follow one",
                    core.name
                )));
            }
        }
        // ⚠️ `(value-prediction ...)` (S4): a table to predict from, a number
        // of times running that is worth trusting, a front end to fetch again
        // through when it is wrong, and this library's pipeline.
        if let Some((entries, confidence)) = core.value_prediction {
            let problem = if core.simt.is_some() || !core.model.is_empty() {
                Some("a pipeline that is not this library's".to_string())
            } else if core.front_end.is_none() {
                Some("no `(front-end ...)` to fetch again through when a value is wrong".to_string())
            } else if entries == 0 || entries > 1024 || !entries.is_power_of_two() {
                Some(format!("`(entries {entries})`; a power of two up to 1024"))
            } else if !(1..=15).contains(&confidence) {
                Some(format!("`(confidence {confidence})`; a value is trusted after 1 to 15 times running"))
            } else {
                None
            };
            if let Some(problem) = problem {
                return Err(ValidationError::new(format!(
                    "core `{}` declares `(value-prediction ...)` with {problem}",
                    core.name
                )));
            }
        }
        // ⚠️ `(abort true)` (W4) frees a unit an instruction was squashed in. A
        // pipelined unit with no lanes is held for the cycle an instruction
        // starts in and no longer, so there is nothing of it to give back; and
        // a warp machine squashes nothing.
        if let Some(unit) = core.units.iter().find(|u| u.abort) {
            if core.simt.is_some() || (unit.pipelined && unit.lanes == 0) {
                return Err(ValidationError::new(format!(
                    "core `{}` unit `{}` declares `(abort true)`, which {}",
                    core.name,
                    unit.name,
                    if core.simt.is_some() {
                        "a warp machine (`(kind simt)`) does not read: it squashes nothing"
                    } else {
                        "frees nothing: a pipelined unit is held for the cycle an instruction \
                         starts in, and an abort is for one held longer -- `(pipelined false)`, \
                         or `(lanes N)` and several beats"
                    }
                )));
            }
        }
        // ⚠️ `(accepts NAME...)` (VU3) lends a unit's idle lanes to other units'
        // instructions: only a unit with lanes has any to lend, only to units
        // this core has, and never to itself.
        for unit in core.units.iter().filter(|u| !u.accepts.is_empty()) {
            if core.simt.is_some() || unit.lanes == 0 || core.units.len() > 32 {
                return Err(ValidationError::new(format!(
                    "core `{}` unit `{}` accepts other units' instructions, which needs `(lanes N)` \
                     on a core that is not a warp machine and has at most 32 units",
                    core.name, unit.name
                )));
            }
            for name in &unit.accepts {
                let known = core.units.iter().any(|other| other.name.eq_ignore_ascii_case(name));
                if !known || name.eq_ignore_ascii_case(&unit.name) {
                    return Err(ValidationError::new(format!(
                        "core `{}` unit `{}` accepts `{}`, which is {}",
                        core.name,
                        unit.name,
                        name,
                        if known { "itself" } else { "not a unit of this core" }
                    )));
                }
            }
        }
        if let Some(simt) = &core.simt {
            validate_core_simt(document, core, simt)?;
        } else if let Some(unit) = core.units.iter().find(|u| u.interval > 0) {
            return Err(ValidationError::new(format!(
                "core `{}` unit `{}` declares an in-flight cap, which only a warp machine \
                 (`(kind simt)` with `(simt ...)`) has",
                core.name, unit.name
            )));
        } else if let Some(unit) = core.units.iter().find(|u| u.lanes > 16) {
            // ⚠️ On a core that is not a warp machine a unit's lanes are 64-bit
            // lanes of a datapath (docs/vector_units_design.md, VU1), and the
            // pipeline models sixteen a copy: a description asking for more
            // would be timed as sixteen and not told.
            return Err(ValidationError::new(format!(
                "core `{}` unit `{}` declares {} lanes; the pipeline models at most 16 lanes of \
                 64 bits a copy",
                core.name, unit.name, unit.lanes
            )));
        }
        // A SIMT core's units are checked by `validate_core_simt`, against the
        // classes its instructions DERIVE when they name none (crate::simt).
        if !core.units.is_empty() && core.simt.is_none() {
            let implements = core.implements.to_ascii_lowercase();
            let mut used: HashSet<String> = HashSet::new();
            for instruction in &document.instructions {
                if !implements.is_empty()
                    && !instruction.isa.eq_ignore_ascii_case(&implements)
                {
                    continue;
                }
                let named = core.named_unit_of(instruction);
                if named.is_empty() {
                    // ⚠️ Nothing names a unit: it issues to the one its
                    // effects derive (Core::unit_of), if the core declares
                    // it; if not, to none -- as on a SIMT core. So a unit only
                    // derived instructions reach is reached.
                    let derived = core.unit_of(instruction).to_ascii_lowercase();
                    if core.units.iter().any(|declared| declared.name.eq_ignore_ascii_case(&derived)) {
                        used.insert(derived);
                    }
                    continue;
                }
                let unit = named.to_ascii_lowercase();
                if !core
                    .units
                    .iter()
                    .any(|declared| declared.name.eq_ignore_ascii_case(&unit))
                {
                    return Err(ValidationError::new(format!(
                        "instruction `{}` issues to unit `{}`, which core `{}` \
                         does not have",
                        instruction.mnemonic, named, core.name
                    )));
                }
                used.insert(unit);
            }
            // ⚠️ And the other way: a unit no instruction reaches cannot
            // change a cycle count, so a core that declares one is declaring
            // a number nothing can read -- the exact shape of the free text
            // this form exists to stop being.
            for unit in &core.units {
                if !used.contains(&unit.name.to_ascii_lowercase()) {
                    return Err(ValidationError::new(format!(
                        "core `{}` has unit `{}` and no instruction issues to \
                         it; a unit nothing reaches cannot affect a cycle",
                        core.name, unit.name
                    )));
                }
            }
        }
        // ⚠️ Provenance is a closed vocabulary or it is decoration. `declared`
        // is a number a designer typed, `measured` has been put back to
        // hardware and checked, `modelled` came from another model. A result
        // built on the first and a result built on the second are different
        // kinds of claim.
        if !core.provenance.trim().is_empty() {
            validate_allowed_value(
                &format!("core `{}` provenance", core.name),
                &core.provenance,
                &["declared", "measured", "modelled"],
            )?;
        }
        // ⚠️ A vendor key is NAMESPACED, so two vendors' parameters cannot
        // collide in one description and nobody has to arbitrate.
        for (key, _) in &core.vendor {
            if !key.contains('.') {
                return Err(ValidationError::new(format!(
                    "core `{}` vendor parameter `{key}` is not namespaced; \
                     write it as `vendor.name`",
                    core.name
                )));
            }
        }
        // ⚠️ A predictor is a closed vocabulary, and `history` is read by
        // exactly one of them. A history on a predictor that keeps none is a
        // number nothing reads -- the shape this form exists to stop.
        //
        // ⚠️ OPEN, but not loose (O8): a NAMESPACED predictor (`acme.perceptron`)
        // is somebody else's, its numbers carried verbatim and the core refused
        // at selection until a host registers it -- the rule `model` already
        // follows. An un-namespaced name must be a built-in, so `gshar` is a
        // typo rather than a predictor nobody has.
        let predictor = if core.predictor.is_empty() { "none" } else { core.predictor.as_str() };
        let external = predictor.contains('.');
        if !external {
            validate_allowed_value(
                &format!("core `{}` predictor", core.name),
                predictor,
                &["none", "bimodal", "gshare", "tage"],
            )?;
        }
        // Each built-in reads exactly these extra numbers, with these bounds.
        let allowed: &[(&str, u32, u32)] = match predictor {
            "tage" => &[("tables", 1, 8), ("min-history", 1, 63), ("tag-bits", 1, 16)],
            _ if external => &[],
            _ => &[],
        };
        for (key, value) in &core.predictor_params {
            if external {
                continue;
            }
            match allowed.iter().find(|(k, _, _)| k == key) {
                Some((_, low, high)) if (*low..=*high).contains(value) => {}
                Some((_, low, high)) => {
                    return Err(ValidationError::new(format!(
                        "core `{}` gives {predictor} `({key} {value})`; it reads {low} to {high}",
                        core.name
                    )));
                }
                None => {
                    return Err(ValidationError::new(format!(
                        "core `{}` gives `{key}` to a {predictor} predictor, which reads no such number",
                        core.name
                    )));
                }
            }
        }
        if predictor == "tage" {
            let min = core
                .predictor_params
                .iter()
                .find(|(k, _)| k == "min-history")
                .map_or(0, |(_, v)| *v);
            let tables = core.predictor_params.iter().any(|(k, _)| k == "tables");
            if !tables || min == 0 || !(min < core.predictor_history && core.predictor_history <= 64) {
                return Err(ValidationError::new(format!(
                    "core `{}` predicts with tage; it needs `(tables N)`, `(min-history A)` \
                     and `(history B)` with A < B <= 64 -- the geometric series runs between them",
                    core.name
                )));
            }
        }
        // ⚠️ `(overrides ...)` (D3): a quick predictor answers at fetch and
        // this core's own overrides it at decode. That needs a predictor to
        // do the overriding, a front end for decode to be a stage of, and a
        // quick predictor this library has -- bimodal, which keeps no history
        // for a squash to have to put back.
        if let Some(quick) = &core.overrides {
            let problem = if predictor == "none" {
                Some("no predictor of its own to override it with".to_string())
            } else if core.front_end.is_none() {
                Some("no `(front-end ...)` for decode to be a stage of".to_string())
            } else if core.simt.is_some() || !core.model.is_empty() {
                Some("a pipeline that is not this library's".to_string())
            } else if quick.predictor != "bimodal" {
                Some(format!(
                    "`(predictor {})` as the quick one; only `bimodal` answers at fetch here",
                    if quick.predictor.is_empty() { "none" } else { quick.predictor.as_str() }
                ))
            } else if quick.entries == 0 || !quick.entries.is_power_of_two() || quick.entries > 4096 {
                Some(format!("`(entries {})`; a power of two up to 4096", quick.entries))
            } else if !(1..=16).contains(&quick.cycles) {
                Some(format!(
                    "`(cycles {})`; an override costs 1 to 16 cycles, or it is not one",
                    quick.cycles
                ))
            } else {
                None
            };
            if let Some(problem) = problem {
                return Err(ValidationError::new(format!(
                    "core `{}` declares `(overrides ...)` with {problem}",
                    core.name
                )));
            }
        }
        let gshare = core.predictor.eq_ignore_ascii_case("gshare");
        let reads_history = gshare || predictor == "tage" || external;
        if gshare && !(1..=16).contains(&core.predictor_history) {
            return Err(ValidationError::new(format!(
                "core `{}` predicts with gshare and keeps {} bits of history; \
                 gshare needs `(history N)` with N from 1 to 16",
                core.name, core.predictor_history
            )));
        }
        if !reads_history && core.predictor_history != 0 {
            return Err(ValidationError::new(format!(
                "core `{}` keeps `(history {})` for a predictor that reads none",
                core.name, core.predictor_history
            )));
        }
        if let Some(lsq) = &core.lsq {
            validate_allowed_value(
                &format!("core `{}` lsq disambiguation", core.name),
                &lsq.disambiguation,
                &["conservative", "perfect", "speculative", "store_sets"],
            )?;
            // ⚠️ Each number only where a policy reads it. A replay cost on a
            // machine that never speculates, or a store-set table on one that
            // keeps none, is free text with a unit.
            let speculates = matches!(lsq.disambiguation.as_str(), "speculative" | "store-sets");
            if lsq.replay != 0 && !speculates {
                return Err(ValidationError::new(format!(
                    "core `{}` charges `(replay {})` for a violation its `{}` \
                     disambiguation can never make",
                    core.name, lsq.replay, lsq.disambiguation
                )));
            }
            let sets = lsq.disambiguation == "store-sets";
            if sets != (lsq.store_sets != 0) || lsq.store_sets > 4096 {
                return Err(ValidationError::new(format!(
                    "core `{}` keeps `(store-sets {})` under `{}` disambiguation; \
                     `store-sets` needs a table of 1 to 4096 entries and nothing \
                     else reads one",
                    core.name, lsq.store_sets, lsq.disambiguation
                )));
            }
        }
        // ⚠️ A front end that fetches nothing runs nothing, and a BTB penalty
        // with no BTB -- or a BTB with no cost to missing it -- is a number
        // nothing reads.
        if let Some(fe) = &core.front_end {
            if fe.fetch_width == 0 {
                return Err(ValidationError::new(format!(
                    "core `{}` fetches nothing: `(front-end (fetch-width 0))`",
                    core.name
                )));
            }
            // ⚠️ U2: a cache of decoded micro-ops is a path through the front
            // end that is no LONGER than decoding, holds something, and is a
            // power of two wide in windows; a loop buffer holds a loop.
            if let Some(oc) = &fe.op_cache {
                let sets = if oc.ways == 0 { 0 } else { oc.entries / oc.ways };
                let problem = if core.simt.is_some() || !core.model.is_empty() {
                    Some("a front end that is not this library's".to_string())
                } else if oc.entries == 0 || oc.entries > 1024 || oc.ways == 0 || oc.entries % oc.ways != 0 || !sets.is_power_of_two() {
                    Some(format!(
                        "`(entries {})` in `(ways {})`; 1 to 1024 windows, in sets that are a power of two",
                        oc.entries, oc.ways
                    ))
                } else if oc.window < 4 || !oc.window.is_power_of_two() || oc.window > 4096 {
                    Some(format!("`(window {})`; a window is a power of two bytes of code, 4 to 4096", oc.window))
                } else if oc.width == 0 {
                    Some("`(width 0)`; it delivers nothing".to_string())
                } else if oc.depth > fe.depth {
                    Some(format!(
                        "`(depth {})`, deeper than the front end's {}; micro-ops already decoded are not further from dispatch than ones that are not",
                        oc.depth, fe.depth
                    ))
                } else {
                    None
                };
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!(
                        "core `{}` declares `(op-cache ...)` with {problem}",
                        core.name
                    )));
                }
            }
            if let Some(lb) = &fe.loop_buffer {
                let problem = if core.simt.is_some() || !core.model.is_empty() {
                    Some("a front end that is not this library's".to_string())
                } else if lb.ops < 2 || lb.ops > 256 {
                    Some(format!("`(ops {})`; a loop is at least its branch and one more, and the buffer holds 256", lb.ops))
                } else if lb.width == 0 {
                    Some("`(width 0)`; it delivers nothing".to_string())
                } else if lb.depth > fe.depth {
                    Some(format!("`(depth {})`, deeper than the front end's {}", lb.depth, fe.depth))
                } else {
                    None
                };
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!(
                        "core `{}` declares `(loop-buffer ...)` with {problem}",
                        core.name
                    )));
                }
            }
            // ⚠️ FQ1: a queue of lines the predictor has named is a queue of
            // lines to ask an instruction cache for, in a front end that is
            // this library's.
            if fe.target_queue != 0 {
                let problem = if core.simt.is_some() || !core.model.is_empty() {
                    Some("a front end that is not this library's".to_string())
                } else if fe.icache.is_empty() {
                    Some("no `(icache ...)`; what the queue names is asked of an instruction cache, and there is none".to_string())
                } else if fe.target_queue > 64 {
                    Some("more than 64 lines named ahead".to_string())
                } else {
                    None
                };
                if let Some(problem) = problem {
                    return Err(ValidationError::new(format!(
                        "core `{}` declares `(target-queue {})` with {problem}",
                        core.name, fe.target_queue
                    )));
                }
            }
            if (fe.btb == 0) != (fe.btb_penalty == 0) || fe.btb > 4096 {
                return Err(ValidationError::new(format!(
                    "core `{}` declares `(btb {})` and `(btb-penalty {})`; a BTB of 1 to \
                     4096 entries and what missing it costs come together or not at all",
                    core.name, fe.btb, fe.btb_penalty
                )));
            }
            // ⚠️ A return stack needs something to tell it what a call is, and
            // that is the ABI's link register: without a `defabi` for the ISA
            // this core implements, no instruction is a call and the stack is
            // a number nothing reads.
            // ⚠️ An instruction cache is a CACHE the description declares, with
            // a line to fetch by; and wrong-path fetch touches nothing without
            // one, so the flag alone is a switch nothing reads.
            if !fe.icache.is_empty() {
                let memory = document
                    .memories
                    .iter()
                    .find(|m| m.name.eq_ignore_ascii_case(&fe.icache));
                match memory {
                    // FQ1: a line named ahead is a line asked for, and a queue
                    // that names more than the cache holds puts out lines
                    // fetch has not read yet.
                    Some(m)
                        if m.kind.eq_ignore_ascii_case("cache")
                            && m.line_bytes != 0
                            && u64::from(fe.target_queue) * u64::from(m.line_bytes) > m.size_bytes =>
                    {
                        return Err(ValidationError::new(format!(
                            "core `{}` declares `(target-queue {})` with more lines named ahead                              than `{}` holds",
                            core.name, fe.target_queue, fe.icache
                        )));
                    }
                    Some(m) if m.kind.eq_ignore_ascii_case("cache") && m.line_bytes != 0 => {}
                    _ => {
                        return Err(ValidationError::new(format!(
                            "core `{}` fetches through `{}`, which is not a declared cache with \
                             a line size",
                            core.name, fe.icache
                        )));
                    }
                }
            }
            // ⚠️ Executing the wrong path subsumes fetching it: its instruction
            // lines come from where it actually went. Both at once would say
            // two different things about the same fetches.
            if fe.wrong_path_execute && fe.wrong_path_fetch {
                return Err(ValidationError::new(format!(
                    "core `{}` both fetches and executes the wrong path; executing it already \
                     fetches it, down the path it really took",
                    core.name
                )));
            }
            if fe.wrong_path_execute && fe.icache.is_empty() && core.memory.is_empty() {
                return Err(ValidationError::new(format!(
                    "core `{}` executes the wrong path and has no cache for it to touch",
                    core.name
                )));
            }
            if fe.wrong_path_fetch && fe.icache.is_empty() {
                return Err(ValidationError::new(format!(
                    "core `{}` fetches down the wrong path and has no instruction cache for \
                     that fetch to touch",
                    core.name
                )));
            }
            if fe.ras > 64 {
                return Err(ValidationError::new(format!(
                    "core `{}` keeps a return stack of {}; at most 64",
                    core.name, fe.ras
                )));
            }
            if fe.ras != 0
                && !document.abis.iter().any(|abi| {
                    abi.link_register.is_some()
                        && (core.implements.is_empty() || abi.isa.eq_ignore_ascii_case(&core.implements))
                })
            {
                return Err(ValidationError::new(format!(
                    "core `{}` keeps a return stack, and no `defabi` for its ISA names a \
                     link register -- so nothing can be recognised as a call",
                    core.name
                )));
            }
            if fe.buffer != 0 && fe.buffer < fe.fetch_width {
                return Err(ValidationError::new(format!(
                    "core `{}` buffers {} instructions and fetches {} a cycle; a fetch \
                     group has to fit in the buffer it is fetched into",
                    core.name, fe.buffer, fe.fetch_width
                )));
            }
        }
        // ⚠️ AN EXECUTION-DRIVEN core (E1) fetches the predicted path, so it
        // needs a front end to fetch with; it is this library's own engine, so
        // it cannot also name somebody else's model; it executes its wrong
        // path for real, so O11/O12's reconstructions of it would be a second
        // answer; and `perfect` disambiguation is an oracle over a trace this
        // engine does not have.
        if !core.engine.is_empty() {
            validate_allowed_value(
                &format!("core `{}` engine", core.name),
                &core.engine,
                &["trace", "execute"],
            )?;
        }
        if let Some((wait, send, local)) = &core.events {
            for mnemonic in [wait, send, local] {
                if mnemonic.is_empty() {
                    continue;
                }
                if !document.instructions.iter().any(|i| i.mnemonic.eq_ignore_ascii_case(mnemonic)) {
                    return Err(ValidationError::new(format!(
                        "core `{}` names event instruction `{mnemonic}`, which no instruction is",
                        core.name
                    )));
                }
            }
            if !core.engine.eq_ignore_ascii_case("execute") {
                return Err(ValidationError::new(format!(
                    "core `{}` declares events and is trace-driven; a machine can only sleep in a pipeline that executes",
                    core.name
                )));
            }
        }
        if let Some((address, size, valid)) = &core.exclusive {
            let state: Vec<String> = crate::effects::isa_scalar_state_slots(&document.isas)
                .into_iter()
                .map(|(name, _)| name)
                .collect();
            for slot in [address, size, valid] {
                if !state.iter().any(|s| s == slot) {
                    return Err(ValidationError::new(format!(
                        "core `{}` names exclusive state `{slot}`, which no ISA declares",
                        core.name
                    )));
                }
            }
        }
        if let Some(t) = &core.tlb {
            let refuse = |what: String| Err(ValidationError::new(format!("core `{}` {what}", core.name)));
            // ⚠️ A TLB nothing looks up is a number nothing reads.
            if t.data.entries == 0 && t.fetch.entries == 0 {
                return refuse("declares `(tlb ...)` with neither `(data ...)` nor `(fetch ...)`".to_string());
            }
            // The walk is the one cost every TLB has; without it a miss is free
            // and the structure times nothing.
            if t.walk_cycles == 0 && t.walk_levels == 0 {
                return refuse("declares a TLB and no `(walk-cycles N)`: a miss that costs nothing".to_string());
            }
            // ⚠️ TLB2: a walk is ONE of a flat cost and a table that is read; a
            // table has levels, a page-aligned place to be and a cost a level;
            // a walk cache caches the levels above the last, so it needs two;
            // and a large page is larger than a page, and somewhere.
            let page = if t.page_bytes == 0 { 4096u64 } else { u64::from(t.page_bytes) };
            if t.walk_levels != 0 {
                if t.walk_cycles != 0 {
                    return refuse("declares both `(walk-cycles N)` and `(walk ...)`: a walk has one cost".to_string());
                }
                if t.walk_levels > 6 || t.walk_level_cycles == 0 || t.walk_level_cycles > 64 {
                    return refuse(format!(
                        "walks {} level(s) at {} cycle(s) each; 1 to 6 levels, each 1 to 64 cycles",
                        t.walk_levels, t.walk_level_cycles
                    ));
                }
                if t.walk_table % 4096 != 0 {
                    return refuse(format!("lays its page table out from {:#x}, which is not a multiple of 4096", t.walk_table));
                }
            } else if t.walk_level_cycles != 0 || t.walk_table != 0 {
                return refuse("gives `(walk ...)` no `(levels N)`".to_string());
            }
            if t.walk_cache != 0 && (t.walk_levels < 2 || t.walk_cache > 64) {
                return refuse(format!(
                    "declares `(walk-cache (entries {}))`; 1 to 64 entries, over a table of at least two levels to have upper ones",
                    t.walk_cache
                ));
            }
            if t.walkers > 8 {
                return refuse(format!("declares `(walkers {})`; at most 8", t.walkers));
            }
            if t.huge_bytes != 0 || t.huge_from != 0 || t.huge_to != 0 {
                if !t.huge_bytes.is_power_of_two() || t.huge_bytes <= page
                    || t.huge_from >= t.huge_to || t.huge_from % t.huge_bytes != 0 || t.huge_to % t.huge_bytes != 0
                {
                    return refuse(format!(
                        "maps {:#x}..{:#x} with pages of {} bytes; a large page is a power of two larger than a page of {page}, and the region is whole ones",
                        t.huge_from, t.huge_to, t.huge_bytes
                    ));
                }
            }
            if t.page_bytes != 0 && (!t.page_bytes.is_power_of_two() || t.page_bytes < 64) {
                return refuse(format!("has pages of {} bytes; a page is a power of two of at least 64", t.page_bytes));
            }
            for (name, level, cap) in [("data", &t.data, 256u32), ("fetch", &t.fetch, 256), ("second", &t.second, 4096)] {
                if level.entries == 0 {
                    if level.ways != 0 || level.latency != 0 {
                        return refuse(format!("gives its `{name}` TLB ways or a latency and no entries"));
                    }
                    continue;
                }
                if level.entries > cap {
                    return refuse(format!("has a `{name}` TLB of {} entries; at most {cap}", level.entries));
                }
                if level.ways != 0 && (level.ways > level.entries || level.entries % level.ways != 0) {
                    return refuse(format!(
                        "has a `{name}` TLB of {} entries in {} ways, which does not divide",
                        level.entries, level.ways
                    ));
                }
            }
            // ⚠️ A first-level hit is inside the instruction's own latency, as
            // a first-level cache hit is; a second place to charge it would be
            // a number nothing has to agree with.
            if t.data.latency != 0 || t.fetch.latency != 0 {
                return refuse("gives a first-level TLB a latency; only `(second ...)` has one".to_string());
            }
            if t.second.entries != 0 && t.second.latency == 0 {
                return refuse("has a second-level TLB that costs nothing to reach: give it `(latency N)`".to_string());
            }
            if t.fetch.entries != 0 && core.front_end.is_none() {
                return refuse("has a fetch TLB and no `(front-end ...)` to fetch through it".to_string());
            }
            if core.kind.eq_ignore_ascii_case("simt") || core.simt.is_some() {
                return refuse("is a SIMT core; a TLB is modelled on the pack pipeline only".to_string());
            }
        }
        if !core.memory_timing.is_empty() {
            validate_allowed_value(
                &format!("core `{}` memory-timing", core.name),
                &core.memory_timing,
                &["untimed", "timed"],
            )?;
        }
        if core.memory_timing.eq_ignore_ascii_case("timed") {
            // A trace-driven core reaches memory at its functional step, ahead
            // of pipeline time: there is no cycle to ask the memory system
            // about. And a core no memory system names has nobody to ask.
            if !core.engine.eq_ignore_ascii_case("execute") {
                return Err(ValidationError::new(format!(
                    "core `{}` asks for timed memory and is trace-driven; timed memory needs `(engine execute)`",
                    core.name
                )));
            }
            if !document.memsystems.iter().any(|s| s.nodes.iter().any(|n| n.core == core.name)) {
                return Err(ValidationError::new(format!(
                    "core `{}` asks for timed memory and no memory system names it as a port",
                    core.name
                )));
            }
        }
        if core.engine.eq_ignore_ascii_case("execute") {
            let refuse = |why: &str| {
                Err(ValidationError::new(format!(
                    "core `{}` is execution-driven and {why}",
                    core.name
                )))
            };
            match &core.front_end {
                None => return refuse("declares no front end to fetch the predicted path with"),
                Some(fe) if fe.wrong_path_fetch || fe.wrong_path_execute => {
                    return refuse(
                        "also reconstructs its wrong path; executing the predicted path \
                         already runs it",
                    )
                }
                _ => {}
            }
            if !core.model.is_empty() {
                return refuse("names an external model; it is this library's own engine");
            }
            // ⚠️ `perfect` is an oracle over a trace this engine does not have,
            // and a load that may not take a store's bytes until the store
            // retires needs to know it overlaps before it executes -- which only
            // a trace knows. Conservative, speculative and store-sets need
            // neither (E3).
            if let Some(lsq) = &core.lsq {
                if lsq.disambiguation == "perfect" {
                    return refuse("asks for perfect disambiguation, an oracle over a trace it does not have");
                }
                if !lsq.forwarding {
                    return refuse(
                        "does not forward; it cannot know a load overlaps an in-flight store \
                         before the load executes",
                    );
                }
            }
        }
        // ⚠️ PORTS feed units the core has, and every unit it has is fed:
        // a unit behind no port can never start anything, and a port feeding
        // a unit the core lacks is a number nothing reads (O10).
        if !core.ports.is_empty() {
            if core.ports.len() > 32 {
                return Err(ValidationError::new(format!(
                    "core `{}` declares {} ports; at most 32",
                    core.name,
                    core.ports.len()
                )));
            }
            for (port, units) in &core.ports {
                for unit in units {
                    if !core.units.iter().any(|u| u.name.eq_ignore_ascii_case(unit)) {
                        return Err(ValidationError::new(format!(
                            "core `{}` port `{port}` feeds unit `{unit}`, which it does not have",
                            core.name
                        )));
                    }
                }
            }
            for unit in &core.units {
                if !core
                    .ports
                    .iter()
                    .any(|(_, units)| units.iter().any(|u| u.eq_ignore_ascii_case(&unit.name)))
                {
                    return Err(ValidationError::new(format!(
                        "core `{}` has unit `{}` and no port feeds it; it could never start \
                         an instruction",
                        core.name, unit.name
                    )));
                }
            }
        }
        // ⚠️ Renaming is per register FILE, not per view of one: AArch64's W
        // and X forms are one file, and a pool per view would let a machine
        // hold twice the registers it has.
        for (file, _) in &core.rename {
            if !crate::ast::REGISTER_CLASSES
                .iter()
                .any(|class| class.file.eq_ignore_ascii_case(file))
            {
                return Err(ValidationError::new(format!(
                    "core `{}` renames `{file}`, which is not a register file",
                    core.name
                )));
            }
        }
        // A core runs against a memory the description declares, or none.
        if !core.memory.trim().is_empty()
            && !document
                .memories
                .iter()
                .any(|memory| memory.name.eq_ignore_ascii_case(&core.memory))
        {
            return Err(ValidationError::new(format!(
                "core `{}` runs against unknown memory `{}`",
                core.name, core.memory
            )));
        }
        // Composed personalities (P3) must name declared personalities.
        for personality in &core.personalities {
            if !document
                .personalities
                .iter()
                .any(|declared| declared.name.eq_ignore_ascii_case(personality))
            {
                return Err(ValidationError::new(format!(
                    "core `{}` composes unknown personality `{personality}`",
                    core.name
                )));
            }
        }
    }
    Ok(())
}

/// Packets that can hold this instruction's ISA.
///
/// A packet with no `isa` describes the document's single instruction space;
/// otherwise it holds only that ISA's instructions.
fn packets_for_instruction<'a>(
    document: &'a Document,
    instruction: &Instruction,
) -> Vec<&'a Packet> {
    document
        .packets
        .iter()
        .filter(|packet| {
            packet.isa.trim().is_empty()
                || instruction.isa.trim().is_empty()
                || packet.isa.eq_ignore_ascii_case(&instruction.isa)
        })
        .collect()
}

/// The slots that can hold this instruction, as `(packet, slot)` indices.
///
/// `None` means "every slot there is": a document that declares no packet, or
/// an instruction with no unit, contends for encoding space with everything,
/// which is exactly the rule before packets existed.
fn instruction_slots(
    document: &Document,
    instruction: &Instruction,
) -> Option<HashSet<(usize, usize)>> {
    if document.packets.is_empty() || instruction.unit.trim().is_empty() {
        return None;
    }
    let unit = canonical_unit(&instruction.unit);
    let mut slots = HashSet::new();
    for (packet_index, packet) in document.packets.iter().enumerate() {
        if !(packet.isa.trim().is_empty()
            || instruction.isa.trim().is_empty()
            || packet.isa.eq_ignore_ascii_case(&instruction.isa))
        {
            continue;
        }
        for slot_index in packet.slots_for_unit(&unit) {
            slots.insert((packet_index, slot_index));
        }
    }
    Some(slots)
}

/// Whether some slot can hold both instructions — the packet-level analogue of
/// `mode_sets_intersect`.
///
/// Two instructions that no single slot can hold never compete for a bit
/// pattern: the decoder reaching them is reading different syllable positions.
/// A machine that gives its multiplier slot its own opcode space may therefore
/// reuse an encoding the ALU slot also uses.
fn slot_sets_intersect(
    document: &Document,
    instruction_a: &Instruction,
    instruction_b: &Instruction,
) -> bool {
    match (
        instruction_slots(document, instruction_a),
        instruction_slots(document, instruction_b),
    ) {
        (Some(a), Some(b)) => !a.is_disjoint(&b),
        _ => true,
    }
}

fn validate_packets(document: &Document) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for packet in &document.packets {
        require_identifier("packet.name", &packet.name)?;
        if !names.insert(packet.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate packet `{}`",
                packet.name
            )));
        }
        if !packet.isa.trim().is_empty()
            && !document
                .isas
                .iter()
                .any(|isa| isa.name.eq_ignore_ascii_case(&packet.isa))
        {
            return Err(ValidationError::new(format!(
                "packet `{}` names unknown isa `{}`",
                packet.name, packet.isa
            )));
        }
        validate_allowed_value(
            &format!("packet `{}` order", packet.name),
            &packet.order,
            PACKET_ORDERS,
        )?;
        validate_allowed_value(
            &format!("packet `{}` end", packet.name),
            &packet.end,
            PACKET_END_RULES,
        )?;
        validate_allowed_value(
            &format!("packet `{}` branches", packet.name),
            &packet.branches,
            PACKET_BRANCH_POLICIES,
        )?;
        validate_allowed_value(
            &format!("packet `{}` hazards", packet.name),
            &packet.hazards,
            PACKET_HAZARDS,
        )?;
        if canonical_value(&packet.hazards) == "exposed" {
            validate_exposed_packet(document, packet)?;
        }
        if packet.slots.is_empty() {
            return Err(ValidationError::new(format!(
                "packet `{}` requires at least one slot",
                packet.name
            )));
        }
        let mut slot_names = HashSet::new();
        for slot in &packet.slots {
            require_identifier(&format!("packet `{}` slot name", packet.name), &slot.name)?;
            if !slot_names.insert(slot.name.to_ascii_lowercase()) {
                return Err(ValidationError::new(format!(
                    "packet `{}` has duplicate slot `{}`",
                    packet.name, slot.name
                )));
            }
            // A syllable is an ordinary instruction word: the encoding core is
            // 32-bit and a packet is a container of syllables, not one wide
            // word (`docs/vliw_spatial_design.md` §3).
            if slot.width == 0 || slot.width > 32 {
                return Err(ValidationError::new(format!(
                    "packet `{}` slot `{}` width {} must be between 1 and 32",
                    packet.name, slot.name, slot.width
                )));
            }
            if slot.units.is_empty() {
                return Err(ValidationError::new(format!(
                    "packet `{}` slot `{}` requires at least one unit",
                    packet.name, slot.name
                )));
            }
            let mut units = HashSet::new();
            for unit in &slot.units {
                require_identifier(
                    &format!("packet `{}` slot `{}` unit", packet.name, slot.name),
                    unit,
                )?;
                if !units.insert(canonical_unit(unit)) {
                    return Err(ValidationError::new(format!(
                        "packet `{}` slot `{}` repeats unit `{unit}`",
                        packet.name, slot.name
                    )));
                }
            }
        }
        if canonical_value(&packet.end) == "stop_bit" {
            let narrowest = packet
                .slots
                .iter()
                .map(|slot| slot.width)
                .min()
                .unwrap_or(0);
            if packet.stop_bit >= narrowest {
                return Err(ValidationError::new(format!(
                    "packet `{}` stop bit {} is outside its narrowest {narrowest}-bit slot",
                    packet.name, packet.stop_bit
                )));
            }
        }
    }
    Ok(())
}

/// Fixed architectural locations an instruction writes, and whether it can
/// transfer control.
///
/// "Fixed" means a location the encoding does not select: an implicit register
/// (AArch64 BL's X30), a named state slot (NZCV). An operand-selected register
/// is not here, because whether two of them collide is a fact about a packet's
/// operands and not about its slots -- stage B2's executor decides that one.
pub(crate) fn fixed_write_locations(instruction: &Instruction) -> (Vec<String>, bool) {
    let mut locations = Vec::new();
    let mut writes_pc = false;
    let Some(behavior) = &instruction.behavior else {
        return (locations, false);
    };
    for effect in &behavior.effects {
        match &effect.loc {
            crate::effects::Loc::Pc => writes_pc = true,
            // Only an unconditional write is a *static* conflict. A guarded one
            // may never fire, and calling that an error would reject a machine
            // whose two slots write one flag under exclusive predicates.
            crate::effects::Loc::FixedReg { kind, index, .. } if effect.guard.is_none() => {
                locations.push(format!("{kind}:{index}"))
            }
            crate::effects::Loc::State { name, .. } if effect.guard.is_none() => {
                locations.push(format!("state:{name}"))
            }
            _ => {}
        }
    }
    (locations, writes_pc)
}

/// How many register writes this instruction commits.
///
/// The pure path writes its one destination; a behavior writes one location per
/// register-writing effect. This is the width of a slot's contribution to the
/// delay queue, so a guarded write counts: an entry that may not fire still
/// needs somewhere to wait.
fn register_write_count(instruction: &Instruction) -> u32 {
    let Some(behavior) = &instruction.behavior else {
        return u32::from(
            instruction
                .operands
                .iter()
                .any(|operand| operand.output),
        );
    };
    behavior
        .effects
        .iter()
        .filter(|effect| {
            matches!(
                effect.loc,
                crate::effects::Loc::Reg(_) | crate::effects::Loc::FixedReg { .. }
            )
        })
        .count() as u32
}

/// The in-flight writes an exposed packet can be carrying, or `None`.
///
/// Both numbers are derived rather than declared. `stages` is one less than the
/// longest latency the packet can issue, because a latency of 1 is visible to
/// the next packet and so waits nowhere. `entries_per_stage` sums each slot's
/// widest write count instead of multiplying the widest by the slot count,
/// which would reserve capacity for writes no slot can issue.
pub(crate) fn packet_delay_queue(
    document: &Document,
    packet: &Packet,
) -> Option<crate::capsule::DelayQueue> {
    if canonical_value(&packet.hazards) != "exposed" {
        return None;
    }
    let mut max_latency = 1;
    let mut entries_per_stage = 0;
    for (index, _) in packet.slots.iter().enumerate() {
        let mut widest = 0;
        for instruction in &document.instructions {
            if !packets_for_instruction(document, instruction)
                .iter()
                .any(|candidate| candidate.name == packet.name)
                || !packet.slots_for_unit(&instruction.unit).contains(&index)
            {
                continue;
            }
            let writes = register_write_count(instruction);
            if writes > 0 {
                max_latency = max_latency.max(instruction.latency_cycles);
                widest = widest.max(writes);
            }
        }
        entries_per_stage += widest;
    }
    Some(crate::capsule::DelayQueue {
        stages: max_latency.saturating_sub(1),
        entries_per_stage,
    })
}

/// The delay queue a personality inherits from the packet that issues its ISA.
pub(crate) fn personality_delay_queue(
    document: &Document,
    personality: &Personality,
) -> Option<crate::capsule::DelayQueue> {
    document
        .packets
        .iter()
        .find(|packet| {
            packet.isa.trim().is_empty() || packet.isa.eq_ignore_ascii_case(&personality.implements)
        })
        .and_then(|packet| packet_delay_queue(document, packet))
}

/// What a packet's slots can do to shared architectural locations.
///
/// A packet's contents vary at run time, so the checkable statement is about
/// its *slots*: if two slots can each hold something that writes one fixed
/// location, some legal packet writes it twice, and the description has
/// promised a machine with two write ports it never declared.
fn validate_packet_structural_hazards(document: &Document) -> Result<(), ValidationError> {
    for packet in &document.packets {
        let mut location_slots: Vec<(String, usize, String)> = Vec::new();
        let mut branch_slots: Vec<(usize, String)> = Vec::new();
        for instruction in &document.instructions {
            if !packets_for_instruction(document, instruction)
                .iter()
                .any(|candidate| candidate.name == packet.name)
            {
                continue;
            }
            let (locations, writes_pc) = fixed_write_locations(instruction);
            for slot in packet.slots_for_unit(&instruction.unit) {
                if writes_pc {
                    branch_slots.push((slot, instruction.mnemonic.clone()));
                }
                for location in &locations {
                    location_slots.push((location.clone(), slot, instruction.mnemonic.clone()));
                }
            }
        }

        if canonical_value(&packet.branches) == "at_most_one" {
            let mut seen: Option<(usize, &str)> = None;
            for (slot, mnemonic) in &branch_slots {
                match seen {
                    Some((first, first_mnemonic)) if first != *slot => {
                        return Err(ValidationError::new(format!(
                            "packet `{}` declares `at_most_one` branch, but slots {first} and {slot} \
                             can both transfer control (`{first_mnemonic}`, `{mnemonic}`)",
                            packet.name
                        )))
                    }
                    Some(_) => {}
                    None => seen = Some((*slot, mnemonic.as_str())),
                }
            }
        }

        let mut writers: HashMap<&str, (usize, &str)> = HashMap::new();
        for (location, slot, mnemonic) in &location_slots {
            match writers.get(location.as_str()) {
                Some((first, first_mnemonic)) if first != slot => {
                    return Err(ValidationError::new(format!(
                        "packet `{}` slots {first} and {slot} can both write `{location}` \
                         unconditionally (`{first_mnemonic}`, `{mnemonic}`), \
                         which no packet can resolve",
                        packet.name
                    )))
                }
                Some(_) => {}
                None => {
                    writers.insert(location.as_str(), (*slot, mnemonic.as_str()));
                }
            }
        }
    }
    Ok(())
}

/// Every instruction a packet could issue must say which unit executes it.
///
/// The alternative — defaulting an unannotated instruction into some slot — puts
/// an instruction in a slot no one described, and a decoder built from that
/// manifest would accept syllables the machine rejects.
/// The longest latency an exposed packet may declare.
///
/// The delay queue is architectural state, so its depth is capsule bytes: a
/// latency of a thousand would ask a checkpoint to carry a thousand stages of
/// pending writes. The bound is arbitrary in the way every bound is, and it is
/// here so the number is chosen once and written down.
const MAX_EXPOSED_LATENCY: u32 = 32;

/// An exposed machine's schedule is responsible for its hazards, and its
/// in-flight writes are state a checkpoint has to carry.
fn validate_exposed_packet(document: &Document, packet: &Packet) -> Result<(), ValidationError> {
    for instruction in &document.instructions {
        if !packets_for_instruction(document, instruction)
            .iter()
            .any(|candidate| candidate.name == packet.name)
            || packet.slots_for_unit(&instruction.unit).is_empty()
        {
            continue;
        }
        if instruction.latency_cycles > MAX_EXPOSED_LATENCY {
            return Err(ValidationError::new(format!(
                "instruction `{}` declares latency {} in exposed packet `{}`; the delay \
                 queue is capsule state and is bounded at {MAX_EXPOSED_LATENCY}",
                instruction.mnemonic, instruction.latency_cycles, packet.name
            )));
        }
    }
    // A pending write waits in a 64-bit field (`capsule::DELAY_ENTRY_BYTES`),
    // so a machine whose registers are wider cannot checkpoint its shadow.
    for isa in &document.isas {
        if !(packet.isa.trim().is_empty() || packet.isa.eq_ignore_ascii_case(&isa.name)) {
            continue;
        }
        for raw in &isa.registers {
            let group = crate::capsule::parse_register_group(raw).map_err(ValidationError::new)?;
            if group.width_bits > 64 {
                return Err(ValidationError::new(format!(
                    "isa `{}` register `{}` is {} bits, and exposed packet `{}` holds a \
                     pending write in 64; a wider shadow needs a wider delay entry",
                    isa.name, group.name, group.width_bits, packet.name
                )));
            }
        }
    }
    Ok(())
}

fn validate_instruction_units(document: &Document) -> Result<(), ValidationError> {
    if document.packets.is_empty() {
        return Ok(());
    }
    for instruction in &document.instructions {
        let packets = packets_for_instruction(document, instruction);
        if packets.is_empty() {
            continue;
        }
        if instruction.unit.trim().is_empty() {
            return Err(ValidationError::new(format!(
                "instruction `{}` needs a `unit`: packet `{}` issues its instruction space",
                instruction.mnemonic, packets[0].name
            )));
        }
        require_identifier("instruction.unit", &instruction.unit)?;
        let unit = canonical_unit(&instruction.unit);
        if !packets
            .iter()
            .any(|packet| !packet.slots_for_unit(&unit).is_empty())
        {
            let mut available: Vec<String> = packets
                .iter()
                .flat_map(|packet| packet.slots.iter())
                .flat_map(|slot| slot.units.iter())
                .map(|unit| canonical_unit(unit))
                .collect();
            available.sort();
            available.dedup();
            return Err(ValidationError::new(format!(
                "instruction `{}` unit `{}` is held by no slot of any packet that \
                 issues it; slots hold {}",
                instruction.mnemonic,
                instruction.unit,
                available.join(", ")
            )));
        }
    }
    Ok(())
}

/// Required parameters per discipline kind (personality design §3); no other
/// parameters are accepted, and every value must be positive.
const DISCIPLINE_KINDS: &[(&str, &[&str])] = &[
    ("lockstep", &["lanes"]),
    ("independent", &["threads"]),
    ("systolic", &["rows", "cols"]),
    ("fused", &["width"]),
];

fn validate_personalities(document: &Document) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    let mut mode_bindings = HashSet::new();
    let mode_values: HashSet<&str> = document
        .modes
        .first()
        .map(|mode| mode.values.iter().map(|(name, _)| name.as_str()).collect())
        .unwrap_or_default();
    let mut layouts: Vec<(&Personality, crate::capsule::CapsuleLayout)> = Vec::new();
    for personality in &document.personalities {
        require_identifier("personality.name", &personality.name)?;
        // A bound personality names a declared mode value; each mode value is
        // claimed by at most one personality (P3).
        if !personality.mode.is_empty() {
            if !mode_values.contains(personality.mode.as_str()) {
                return Err(ValidationError::new(format!(
                    "personality `{}` mode `{}` is not a declared mode value",
                    personality.name, personality.mode
                )));
            }
            if !mode_bindings.insert(personality.mode.clone()) {
                return Err(ValidationError::new(format!(
                    "personality `{}` claims mode `{}` already bound by another personality",
                    personality.name, personality.mode
                )));
            }
        }
        if !names.insert(personality.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate personality `{}`",
                personality.name
            )));
        }

        let discipline = &personality.discipline;
        let required = DISCIPLINE_KINDS
            .iter()
            .find(|(kind, _)| *kind == canonical_value(&discipline.kind))
            .map(|(_, required)| *required)
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "personality `{}` discipline kind `{}` must be one of lockstep, \
                     independent, systolic, fused",
                    personality.name, discipline.kind
                ))
            })?;
        for name in required {
            match discipline.params.iter().find(|(key, _)| key == name) {
                Some((_, value)) if *value > 0 => {}
                Some(_) => {
                    return Err(ValidationError::new(format!(
                        "personality `{}` discipline `{}` parameter `{name}` must be positive",
                        personality.name, discipline.kind
                    )))
                }
                None => {
                    return Err(ValidationError::new(format!(
                        "personality `{}` discipline `{}` requires parameter `{name}`",
                        personality.name, discipline.kind
                    )))
                }
            }
        }
        for (key, _) in &discipline.params {
            if !required.contains(&key.as_str()) {
                return Err(ValidationError::new(format!(
                    "personality `{}` discipline `{}` does not accept parameter `{key}`",
                    personality.name, discipline.kind
                )));
            }
        }

        let isa = document
            .isas
            .iter()
            .find(|isa| isa.name.eq_ignore_ascii_case(&personality.implements))
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "personality `{}` implements unknown isa `{}`",
                    personality.name, personality.implements
                ))
            })?;
        if isa.registers.is_empty() {
            return Err(ValidationError::new(format!(
                "personality `{}` implements isa `{}` which declares no registers; \
                 a capsule needs a declared register surface",
                personality.name, isa.name
            )));
        }
        let layout =
            crate::capsule::resolve_capsule(
                isa,
                personality,
                personality_delay_queue(document, personality).as_ref(),
            )
            .map_err(ValidationError::new)?;
        layouts.push((personality, layout));
    }

    // A shared capsule group name must mean the same state everywhere in the
    // document — mismatched width/count is a spec error, not "not migratable".
    for (idx, (personality_a, layout_a)) in layouts.iter().enumerate() {
        for (personality_b, layout_b) in layouts.iter().skip(idx + 1) {
            if let Some(conflict) = crate::capsule::layout_conflict(layout_a, layout_b) {
                return Err(ValidationError::new(format!(
                    "personalities `{}` and `{}` have incompatible capsules: {conflict}",
                    personality_a.name, personality_b.name
                )));
            }
        }
    }
    Ok(())
}

/// M1. The relations between an engine's context numbers, which its consumer
/// currently hand-checks in Python (`xnn_mt/contract.py::validate`).
///
/// Nothing here models multithreading. It checks that the numbers a machine
/// declares about its own contexts can all be true at once -- that the id field
/// can name every context, that the issue queue can hold a prefetched issue at
/// all, and that an issue says which context it came from.
fn validate_accelerator_contexts(accelerator: &Accelerator) -> Result<(), ValidationError> {
    let name = &accelerator.name;
    if accelerator.contexts == 0 {
        // Partly declared is worse than not declared: a queue depth with no
        // contexts is a number about an object the description never made.
        if accelerator.context_id_bits != 0
            || accelerator.issue_queue_depth != 0
            || !accelerator.identity.is_empty()
        {
            return Err(ValidationError::new(format!(
                "accelerator `{name}` describes its contexts without declaring \
                 `(contexts N)`; there is nothing for those numbers to be about"
            )));
        }
        return Ok(());
    }

    if accelerator.contexts < 2 || !accelerator.contexts.is_power_of_two() {
        return Err(ValidationError::new(format!(
            "accelerator `{name}` declares {} contexts, which must be a power of two \
             of at least two; one context is the single-context machine, written by \
             leaving `(contexts ...)` off",
            accelerator.contexts
        )));
    }
    // `(contexts - 1)` because ids run 0..contexts-1: sixteen contexts are named
    // by four bits, and it is the largest id that decides the width.
    let required_bits = 32 - (accelerator.contexts - 1).leading_zeros();
    if accelerator.context_id_bits != required_bits {
        return Err(ValidationError::new(format!(
            "accelerator `{name}` declares {} context-id bits for {} contexts, which \
             needs exactly {required_bits}; a narrow id cannot name every context and \
             a wide one names contexts the machine does not have",
            accelerator.context_id_bits, accelerator.contexts
        )));
    }
    if accelerator.issue_queue_depth < 2 {
        return Err(ValidationError::new(format!(
            "accelerator `{name}` declares an issue queue {} deep; it must hold at \
             least two, the issue being serviced and one prefetched behind it, or the \
             engine hides no latency and its contexts buy nothing",
            accelerator.issue_queue_depth
        )));
    }

    let mut seen: HashSet<String> = HashSet::new();
    for field in &accelerator.identity {
        require_identifier("accelerator.identity", field)?;
        if !seen.insert(field.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "accelerator `{name}` identity names `{field}` twice"
            )));
        }
    }
    if !seen.contains("context_id") {
        return Err(ValidationError::new(format!(
            "accelerator `{name}` has {} contexts and an identity that does not carry \
             `context_id`; an issue that cannot say which context it came from cannot \
             have its result returned to one",
            accelerator.contexts
        )));
    }

    // M2. The policy and the preemption point are names a consumer matches on,
    // and a name this language does not know is one no consumer can be held to
    // -- the argument `validate_channels` already makes for protocols. What
    // they decide here is not behaviour but whether a service bound exists at
    // all: see `service_bound`.
    if !accelerator.scheduling.is_empty() {
        validate_allowed_value(
            &format!("accelerator `{name}` scheduling"),
            &accelerator.scheduling,
            ACCELERATOR_SCHEDULING,
        )?;
    }
    if !accelerator.preemption.is_empty() {
        validate_allowed_value(
            &format!("accelerator `{name}` preemption"),
            &accelerator.preemption,
            ACCELERATOR_PREEMPTION,
        )?;
    }
    let mut seen: HashSet<String> = HashSet::new();
    for input in &accelerator.eligibility {
        require_identifier("accelerator.eligibility", input)?;
        if !seen.insert(input.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "accelerator `{name}` eligibility names `{input}` twice"
            )));
        }
    }
    // A time base with no policy to spend it is a number about nothing: the
    // interval is only ever read as the denominator of a service bound.
    if accelerator.service_interval_cycles > 0 && accelerator.scheduling.is_empty() {
        return Err(ValidationError::new(format!(
            "accelerator `{name}` declares a service interval and no `(scheduling ...)`; \
             the interval is the unit a service bound is counted in, and without a \
             policy there is no bound for it to denominate"
        )));
    }
    Ok(())
}

/// Whether a policy delivers a bound on how long a persistently eligible
/// context waits, and therefore whether the manifest has one to publish (M2).
///
/// Two fields decide it, not one. A work-conserving round robin rotates, so it
/// serves every other context at most once before coming back -- but only if
/// there is a point at which it can rotate. Run to completion with no
/// preemption point is still work-conserving and still unbounded, since a
/// context that never finishes never yields. Strict priority is unbounded for
/// the other reason: a high-priority context that stays eligible is served
/// forever, and the low one waits forever, which is a legitimate machine to
/// describe and an illegitimate one to publish a bound for.
pub(crate) fn service_bound(accelerator: &Accelerator) -> Option<u32> {
    if accelerator.contexts < 2 {
        return None;
    }
    // Canonicalised, because `work-conserving-round-robin` and
    // `work_conserving_round_robin` are one policy and the vocabulary is
    // checked against the canonical form.
    let rotates = canonical_value(&accelerator.scheduling) == "work_conserving_round_robin";
    let yields = canonical_value(&accelerator.preemption) == "tile_boundary_only";
    if rotates && yields {
        Some(accelerator.contexts - 1)
    } else {
        None
    }
}

const AGGREGATE_SPLIT: &[&str] = &["allowed", "forbidden"];

/// F3. How aggregates are passed, held to the convention they sit in.
///
/// Nothing here lays an aggregate out -- padding and nested alignment are the
/// source language's rule, and a machine ABI states only what happens to a
/// laid-out one. What it can be held to is that the threshold and the
/// convention agree: a size no set of argument registers can hold passes
/// nothing by value, and an address passed like an argument has to be in a
/// register arguments are passed in.
fn validate_aggregates(abi: &Abi, role_of: &HashMap<(String, u32), &'static str>)
    -> Result<(), ValidationError> {
    let Some(aggregates) = &abi.aggregates else {
        return Ok(());
    };
    let name = &abi.name;
    validate_allowed_value(
        &format!("abi `{name}` aggregates split"),
        &aggregates.split,
        AGGREGATE_SPLIT,
    )?;

    let pointer_bytes = abi.pointer_bits / 8;
    if aggregates.max_register_bytes == 0 {
        return Err(ValidationError::new(format!(
            "abi `{name}` passes aggregates of at most 0 bytes in registers; an abi \
             that passes none by value says so by leaving `(aggregates ...)` off"
        )));
    }
    if aggregates.max_register_bytes % pointer_bytes != 0 {
        return Err(ValidationError::new(format!(
            "abi `{name}` passes aggregates of up to {} bytes in {pointer_bytes}-byte \
             registers; a threshold that is not a whole number of registers is a \
             boundary no register lands on",
            aggregates.max_register_bytes
        )));
    }
    let argument_bytes: u32 = abi
        .arguments
        .iter()
        .map(|entry| entry.last - entry.first + 1)
        .sum::<u32>()
        * pointer_bytes;
    if aggregates.max_register_bytes > argument_bytes {
        return Err(ValidationError::new(format!(
            "abi `{name}` passes aggregates of up to {} bytes in registers and has {} \
             bytes of argument registers; a threshold the registers cannot hold passes \
             nothing by value",
            aggregates.max_register_bytes, argument_bytes
        )));
    }

    if let Some(pointer) = &aggregates.return_pointer {
        let key = (canonical_value(&pointer.class), pointer.first);
        if role_of.get(&key).copied() == Some("reserved") {
            return Err(ValidationError::new(format!(
                "abi `{name}` returns aggregates through reserved `{} {}`",
                pointer.class, pointer.first
            )));
        }
        let is_argument = abi.arguments.iter().any(|entry| {
            canonical_value(&entry.class) == key.0
                && (entry.first..=entry.last).contains(&pointer.first)
        });
        if !is_argument {
            return Err(ValidationError::new(format!(
                "abi `{name}` returns aggregates through `{} {}`, which is not an \
                 argument register; the caller passes that address like an argument, \
                 and there is nowhere else to put it",
                pointer.class, pointer.first
            )));
        }
    }
    Ok(())
}

const FRAME_REGIONS: &[&str] = &["outgoing", "locals", "spill", "saved"];
const FRAME_POLICY: &[&str] = &["allowed", "forbidden"];

/// F4. The frame's regions and what a spill costs, held to what a frame is.
///
/// No region has a size here and that is the whole of the line this stage
/// draws: how many spill slots a function needs and how large its locals are
/// is the register allocator's decision, made per function, and a description
/// that stated it would be stating something it cannot know. What the platform
/// decides is the *order* -- and the order has consequences a document can
/// contradict.
fn validate_frame_regions(
    document: &Document,
    abi: &Abi,
    frame: &crate::ast::Frame,
) -> Result<(), ValidationError> {
    let name = &abi.name;
    if !frame.regions.is_empty() {
        let mut seen: HashSet<String> = HashSet::new();
        for region in &frame.regions {
            if !FRAME_REGIONS.contains(&canonical_value(region).as_str()) {
                return Err(ValidationError::new(format!(
                    "abi `{name}` frame region `{region}` is not one of {}",
                    FRAME_REGIONS.join(", ")
                )));
            }
            if !seen.insert(canonical_value(region)) {
                return Err(ValidationError::new(format!(
                    "abi `{name}` frame lists region `{region}` twice; a region is one \
                     span of the frame, and two of them is two answers to where it is"
                )));
            }
        }
        if !seen.contains("saved") {
            return Err(ValidationError::new(format!(
                "abi `{name}` frame lists regions and not `saved`, which is the one \
                 region this abi computes offsets for"
            )));
        }
        // Two declarations about one thing, so they have to agree. `saved-area`
        // says which end the saved registers occupy and the region order says
        // where they sit among the rest; a document that says `top` and then
        // puts `saved` first has stated the layout twice, differently.
        let last = canonical_value(frame.regions.last().expect("non-empty"));
        let first = canonical_value(&frame.regions[0]);
        let saved_is_highest = canonical_value(&frame.saved_area) == "top";
        if saved_is_highest && last != "saved" {
            return Err(ValidationError::new(format!(
                "abi `{name}` puts the saved registers at the top of the frame and \
                 lists `{last}` above them; the region order runs from the frame base \
                 upward"
            )));
        }
        if !saved_is_highest && first != "saved" {
            return Err(ValidationError::new(format!(
                "abi `{name}` puts the saved registers at the bottom of the frame and \
                 lists `{first}` below them"
            )));
        }
        // A caller's outgoing arguments are what its callee reads at the frame
        // base: the callee's own stack pointer points at them. Anywhere else
        // and the two ends of a call disagree about where an argument is.
        if seen.contains("outgoing") && first != "outgoing" {
            return Err(ValidationError::new(format!(
                "abi `{name}` places the outgoing-argument area above `{first}`; a \
                 callee reads its overflow arguments at its own stack pointer, so they \
                 sit at the frame base and nowhere else"
            )));
        }
    }

    let mut classes: HashSet<String> = HashSet::new();
    for slot in &frame.spill {
        let Some(class) = crate::ast::register_class(&slot.class) else {
            return Err(ValidationError::new(format!(
                "abi `{name}` spills unknown register class `{}`",
                slot.class
            )));
        };
        if !classes.insert(canonical_value(&slot.class)) {
            return Err(ValidationError::new(format!(
                "abi `{name}` gives class `{}` two spill slots",
                slot.class
            )));
        }
        let width_bytes = crate::emit::class_spill_width(document, class).div_ceil(8);
        if slot.bytes < width_bytes {
            return Err(ValidationError::new(format!(
                "abi `{name}` spills `{}` into {} bytes and the class is {width_bytes} \
                 bytes wide; a slot the register does not fit in loses the top of it",
                slot.class, slot.bytes
            )));
        }
        if slot.align == 0 || !slot.align.is_power_of_two() {
            return Err(ValidationError::new(format!(
                "abi `{name}` aligns `{}` spills to {}, which must be a power of two",
                slot.class, slot.align
            )));
        }
        if slot.align > abi.stack_alignment {
            return Err(ValidationError::new(format!(
                "abi `{name}` aligns `{}` spills to {} on a stack aligned to {}; a slot \
                 the frame cannot guarantee needs the frame realigned, and that is a \
                 different declaration",
                slot.class, slot.align, abi.stack_alignment
            )));
        }
        if slot.bytes % slot.align != 0 {
            return Err(ValidationError::new(format!(
                "abi `{name}` spills `{}` into {} bytes aligned to {}; consecutive \
                 slots of that size would not all be aligned",
                slot.class, slot.bytes, slot.align
            )));
        }
    }
    Ok(())
}

/// F5. Which pointer can still find the frame.
///
/// Three declared facts, and the implications between them are the check.
/// Realignment moves the frame base away from any fixed offset of the incoming
/// stack pointer; dynamic allocation moves the stack pointer away from any
/// fixed offset of the frame base. Each alone leaves one pointer that still
/// works. **Both together leave none**, which is why a machine that permits
/// both needs a third register holding the frame base -- LLVM spells the same
/// rule as `needsStackRealignment && hasVariableSizedObjects`.
fn validate_frame_discipline(
    abi: &Abi,
    frame: &crate::ast::Frame,
    role_of: &HashMap<(String, u32), &'static str>,
) -> Result<(), ValidationError> {
    let name = &abi.name;
    for (what, value) in [
        ("realignment", &frame.realignment),
        ("dynamic-allocation", &frame.dynamic_allocation),
    ] {
        if !value.is_empty() {
            validate_allowed_value(&format!("abi `{name}` frame {what}"), value, FRAME_POLICY)?;
        }
    }
    let realigns = canonical_value(&frame.realignment) == "allowed";
    let dynamic = canonical_value(&frame.dynamic_allocation) == "allowed";

    if dynamic && abi.frame_pointer.is_none() {
        return Err(ValidationError::new(format!(
            "abi `{name}` allows the stack pointer to move inside a body and declares \
             no frame pointer; a local addressed from a pointer that moves is at a \
             different place every time it is read"
        )));
    }
    if realigns && dynamic && frame.base_pointer.is_none() {
        return Err(ValidationError::new(format!(
            "abi `{name}` allows both realignment and dynamic allocation and declares \
             no base pointer; realignment moves the frame away from the incoming stack \
             pointer and dynamic allocation moves the stack pointer away from the \
             frame, so neither one can still reach a local"
        )));
    }

    if let Some(base) = &frame.base_pointer {
        let key = (canonical_value(&base.class), base.first);
        if role_of.get(&key).copied() != Some("callee-saved") {
            return Err(ValidationError::new(format!(
                "abi `{name}` base pointer `{} {}` is not callee-saved; it holds the \
                 frame base for the whole body, and a caller-saved register does not \
                 survive the calls the body makes",
                base.class, base.first
            )));
        }
        for (what, other) in [
            ("stack pointer", &abi.stack_pointer),
            ("frame pointer", &abi.frame_pointer),
        ] {
            if let Some(other) = other {
                if canonical_value(&other.class) == key.0 && other.first == base.first {
                    return Err(ValidationError::new(format!(
                        "abi `{name}` base pointer is the {what}; it exists exactly \
                         because that register can no longer find the frame"
                    )));
                }
            }
        }
    }
    Ok(())
}

const FRAME_GROWTH: &[&str] = &["down", "up"];
const FRAME_SAVED_AREA: &[&str] = &["top", "bottom"];
const FRAME_POINTER_AT: &[&str] = &["incoming_sp", "frame_base"];

/// F1. The frame an ABI declares, held to what a frame has to be.
///
/// Nothing here is inferred -- which end the saved registers occupy is a
/// platform choice. What it checks is that the declaration is arithmetic that
/// works: that a callee saves only registers it is allowed to clobber, that no
/// two of them land in one slot, and that the instructions named to establish
/// the frame are the kind of instruction that can.
fn validate_frame(
    document: &Document,
    abi: &Abi,
    role_of: &HashMap<(String, u32), &'static str>,
) -> Result<(), ValidationError> {
    let Some(frame) = &abi.frame else {
        return Ok(());
    };
    let name = &abi.name;
    validate_allowed_value(&format!("abi `{name}` frame growth"), &frame.growth, FRAME_GROWTH)?;
    validate_allowed_value(
        &format!("abi `{name}` frame saved-area"),
        &frame.saved_area,
        FRAME_SAVED_AREA,
    )?;
    validate_allowed_value(
        &format!("abi `{name}` frame frame-pointer-at"),
        &frame.frame_pointer_at,
        FRAME_POINTER_AT,
    )?;

    if frame.slot_bytes == 0 || !frame.slot_bytes.is_power_of_two() {
        return Err(ValidationError::new(format!(
            "abi `{name}` frame slot is {} bytes, which must be a power of two",
            frame.slot_bytes
        )));
    }
    if frame.slot_bytes * 8 < abi.pointer_bits {
        return Err(ValidationError::new(format!(
            "abi `{name}` frame slot is {} bytes and the link register it saves is a \
             {}-bit pointer; a slot a return address does not fit in saves nothing",
            frame.slot_bytes, abi.pointer_bits
        )));
    }
    if frame.max_frame_bytes == 0 || frame.max_frame_bytes % abi.stack_alignment != 0 {
        return Err(ValidationError::new(format!(
            "abi `{name}` allows a {}-byte frame while aligning the stack to {}; a \
             maximum frame that is not a multiple of the alignment cannot be reached \
             without breaking it",
            frame.max_frame_bytes, abi.stack_alignment
        )));
    }
    if frame.saved_bytes() > frame.max_frame_bytes {
        return Err(ValidationError::new(format!(
            "abi `{name}` saves {} bytes of registers into a frame of at most {}",
            frame.saved_bytes(),
            frame.max_frame_bytes
        )));
    }
    if frame.red_zone > 0 && canonical_value(&frame.growth) != "down" {
        return Err(ValidationError::new(format!(
            "abi `{name}` declares a {}-byte red zone on an upward-growing stack; the \
             red zone is the space below the stack pointer, and there is none",
            frame.red_zone
        )));
    }

    // A callee saves what a callee may clobber. Saving an argument register
    // would preserve a value the caller never asked to have preserved -- and
    // the register the argument arrived in.
    let link = abi
        .link_register
        .as_ref()
        .map(|entry| (canonical_value(&entry.class), entry.first));
    let mut seen: HashSet<(String, u32)> = HashSet::new();
    for (class, index) in frame.saved_registers() {
        let key = (canonical_value(&class), index);
        if !seen.insert(key.clone()) {
            return Err(ValidationError::new(format!(
                "abi `{name}` saves `{class} {index}` twice; two slots for one register \
                 is one of them wasted and neither one authoritative"
            )));
        }
        if Some(&key) == link.as_ref() {
            continue;
        }
        match role_of.get(&key).copied() {
            Some("callee-saved") => {}
            Some(role) => {
                return Err(ValidationError::new(format!(
                    "abi `{name}` frame saves `{class} {index}`, which is {role}; a \
                     prologue saves what the callee may clobber, and nothing else"
                )))
            }
            None => {
                return Err(ValidationError::new(format!(
                    "abi `{name}` frame saves `{class} {index}`, which has no role"
                )))
            }
        }
    }
    if abi.frame_pointer.is_some() && frame.save_order.is_empty() {
        return Err(ValidationError::new(format!(
            "abi `{name}` has a frame pointer and saves nothing; a frame pointer the \
             prologue never stores cannot be restored"
        )));
    }

    // The named instructions are what they claim. AXIS does not go looking for
    // something store-shaped: a description names the instruction, and this
    // checks the name.
    let find = |mnemonic: &str, what: &str| -> Result<&Instruction, ValidationError> {
        document
            .instructions
            .iter()
            .find(|instruction| {
                instruction.mnemonic.eq_ignore_ascii_case(mnemonic)
                    && (instruction.isa.is_empty() || instruction.isa.eq_ignore_ascii_case(&abi.isa))
            })
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "abi `{name}` frame {what} names `{mnemonic}`, which isa `{}` does \
                     not describe",
                    abi.isa
                ))
            })
    };
    let save = find(&frame.save, "save")?;
    if crate::effects::pure_store_semantics(save).is_err() {
        return Err(ValidationError::new(format!(
            "abi `{name}` frame saves with `{}`, which is not a plain store; a prologue \
             writes one register to one slot",
            frame.save
        )));
    }
    let restore = find(&frame.restore, "restore")?;
    if crate::effects::value_load_address_width(restore).is_none()
        && !restore.formal_semantics.contains("load")
    {
        return Err(ValidationError::new(format!(
            "abi `{name}` frame restores with `{}`, which reads no memory",
            frame.restore
        )));
    }
    validate_frame_regions(document, abi, frame)?;
    validate_frame_discipline(abi, frame, role_of)?;
    let adjust = find(&frame.adjust, "adjust")?;
    let writes_one = adjust.operands.iter().filter(|operand| operand.output).count() == 1;
    let takes_immediate = adjust
        .operands
        .iter()
        .any(|operand| operand.input && crate::ast::register_class(&operand.kind).is_none());
    if !writes_one || !takes_immediate {
        return Err(ValidationError::new(format!(
            "abi `{name}` frame adjusts with `{}`, which does not write one register \
             from an immediate; a frame is opened by adding a constant to the stack \
             pointer",
            frame.adjust
        )));
    }
    Ok(())
}

/// L4. An ABI is not derivable from an instruction set: which register holds
/// the first argument is a property of a platform, not of a machine, and a
/// description that guessed would be inventing one rather than generating one
/// (`llvm_backend.md` §2). So it is declared -- and what a declaration can be
/// held to is whether it is consistent with itself, which is exactly the class
/// of mistake that miscompiles silently rather than failing loudly.
fn validate_abis(document: &Document) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for abi in &document.abis {
        require_identifier("abi.name", &abi.name)?;
        if !names.insert(abi.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!("duplicate abi `{}`", abi.name)));
        }
        if !document
            .isas
            .iter()
            .any(|isa| isa.name.eq_ignore_ascii_case(&abi.isa))
        {
            return Err(ValidationError::new(format!(
                "abi `{}` names unknown isa `{}`",
                abi.name, abi.isa
            )));
        }

        // Every reference resolves before anything is asked about the sets it
        // is in: a role over a register that does not exist is not a role.
        let check_ref = |reference: &RegisterRef, role: &str| -> Result<(), ValidationError> {
            if crate::ast::register_class(&reference.class).is_none() {
                return Err(ValidationError::new(format!(
                    "abi `{}` {role} names unknown register class `{}`",
                    abi.name, reference.class
                )));
            }
            if reference.last >= crate::ast::REGISTER_SELECTOR_LIMIT {
                return Err(ValidationError::new(format!(
                    "abi `{}` {role} names `{} {}`, past the {}-register file",
                    abi.name,
                    reference.class,
                    reference.last,
                    crate::ast::REGISTER_SELECTOR_LIMIT
                )));
            }
            Ok(())
        };
        for (role, refs) in [
            ("arguments", &abi.arguments),
            ("returns", &abi.returns),
            ("callee-saved", &abi.callee_saved),
            ("caller-saved", &abi.caller_saved),
            ("reserved", &abi.reserved),
        ] {
            for reference in refs {
                check_ref(reference, role)?;
            }
        }
        for (role, reference) in [
            ("stack-pointer", &abi.stack_pointer),
            ("frame-pointer", &abi.frame_pointer),
            ("link-register", &abi.link_register),
        ] {
            if let Some(reference) = reference {
                check_ref(reference, role)?;
            }
        }

        if abi.pointer_bits == 0
            || !abi.pointer_bits.is_power_of_two()
            || abi.pointer_bits < 8
            || abi.pointer_bits > 64
        {
            return Err(ValidationError::new(format!(
                "abi `{}` pointer width {} must be a power of two between 8 and 64",
                abi.name, abi.pointer_bits
            )));
        }
        if abi.stack_alignment == 0 || !abi.stack_alignment.is_power_of_two() {
            return Err(ValidationError::new(format!(
                "abi `{}` stack alignment {} must be a power of two",
                abi.name, abi.stack_alignment
            )));
        }
        if abi.stack_alignment < abi.pointer_bits / 8 {
            return Err(ValidationError::new(format!(
                "abi `{}` aligns the stack to {} bytes and holds a {}-bit pointer; a \
                 stack a pointer does not fit in aligned is not aligned",
                abi.name,
                abi.stack_alignment,
                abi.pointer_bits
            )));
        }

        // The partition. Three roles over every register of every class the ABI
        // puts in a role: a register in none of them is one a compiler cannot
        // know whether to save across a call, and a register in two is a
        // contradiction between two statements the same document made.
        let mut role_of: HashMap<(String, u32), &'static str> = HashMap::new();
        for (role, refs) in [
            ("reserved", &abi.reserved),
            ("callee-saved", &abi.callee_saved),
            ("caller-saved", &abi.caller_saved),
        ] {
            for reference in refs {
                for index in reference.indices() {
                    let key = (canonical_value(&reference.class), index);
                    if let Some(previous) = role_of.insert(key, role) {
                        return Err(ValidationError::new(format!(
                            "abi `{}` puts `{} {index}` in both {previous} and {role}; a \
                             register has one role across a call",
                            abi.name, reference.class
                        )));
                    }
                }
            }
        }
        let mut classes: Vec<String> = role_of.keys().map(|(class, _)| class.clone()).collect();
        classes.sort();
        classes.dedup();
        for class in &classes {
            for index in 0..crate::ast::REGISTER_SELECTOR_LIMIT {
                if !role_of.contains_key(&(class.clone(), index)) {
                    return Err(ValidationError::new(format!(
                        "abi `{}` gives `{class} {index}` no role; a compiler cannot know \
                         whether a register it was told nothing about survives a call",
                        abi.name
                    )));
                }
            }
        }

        let role = |reference: &RegisterRef, index: u32| -> Option<&'static str> {
            role_of
                .get(&(canonical_value(&reference.class), index))
                .copied()
        };

        // A class an ABI passes arguments in and never gives a role to is a
        // file the convention half-describes.
        for (what, refs) in [("arguments", &abi.arguments), ("returns", &abi.returns)] {
            let mut seen: HashSet<(String, u32)> = HashSet::new();
            for reference in refs {
                for index in reference.indices() {
                    if !seen.insert((canonical_value(&reference.class), index)) {
                        return Err(ValidationError::new(format!(
                            "abi `{}` names `{} {index}` twice in {what}",
                            abi.name, reference.class
                        )));
                    }
                    match role(reference, index) {
                        None => {
                            return Err(ValidationError::new(format!(
                                "abi `{}` passes {what} in `{} {index}`, which it gives no \
                                 role",
                                abi.name, reference.class
                            )))
                        }
                        Some("reserved") => {
                            return Err(ValidationError::new(format!(
                                "abi `{}` passes {what} in reserved register `{} {index}`; a \
                                 reserved register is one no value may be placed in",
                                abi.name, reference.class
                            )))
                        }
                        Some(_) => {}
                    }
                }
            }
        }

        if let Some(reference) = &abi.stack_pointer {
            if role(reference, reference.first) != Some("reserved") {
                return Err(ValidationError::new(format!(
                    "abi `{}` stack pointer `{} {}` is not reserved; an allocatable stack \
                     pointer is not a stack pointer",
                    abi.name, reference.class, reference.first
                )));
            }
        }
        if let Some(reference) = &abi.frame_pointer {
            if role(reference, reference.first) != Some("callee-saved") {
                return Err(ValidationError::new(format!(
                    "abi `{}` frame pointer `{} {}` is not callee-saved; a frame pointer \
                     the callee does not preserve is not a frame pointer",
                    abi.name, reference.class, reference.first
                )));
            }
        }
        validate_frame(document, abi, &role_of)?;
        validate_aggregates(abi, &role_of)?;
        if let Some(reference) = &abi.link_register {
            if role(reference, reference.first) == Some("reserved") {
                return Err(ValidationError::new(format!(
                    "abi `{}` link register `{} {}` is reserved, and a call writes it",
                    abi.name, reference.class, reference.first
                )));
            }
        }
    }
    Ok(())
}

fn validate_accelerators(accelerators: &[Accelerator]) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for accelerator in accelerators {
        require_identifier("accelerator.name", &accelerator.name)?;
        require_identifier("accelerator.family", &accelerator.family)?;
        if !accelerator.target.trim().is_empty() {
            validate_allowed_value(
                &format!("accelerator `{}` target", accelerator.name),
                &accelerator.target,
                ACCELERATOR_TARGETS,
            )?;
            let family = canonical_value(&accelerator.family);
            let target = canonical_value(&accelerator.target);
            if family != target {
                return Err(ValidationError::new(format!(
                    "accelerator `{}` family `{}` must match target `{}`",
                    accelerator.name, accelerator.family, accelerator.target
                )));
            }
        }
        if !accelerator.coupling.trim().is_empty() {
            validate_allowed_value(
                &format!("accelerator `{}` coupling", accelerator.name),
                &accelerator.coupling,
                ACCELERATOR_COUPLINGS,
            )?;
        }
        if !accelerator.launch_abi.trim().is_empty() {
            validate_allowed_value(
                &format!("accelerator `{}` launch_abi", accelerator.name),
                &accelerator.launch_abi,
                ACCELERATOR_LAUNCH_ABIS,
            )?;
        }
        if !accelerator.completion.trim().is_empty() {
            validate_allowed_value(
                &format!("accelerator `{}` completion", accelerator.name),
                &accelerator.completion,
                ACCELERATOR_COMPLETIONS,
            )?;
        }
        validate_accelerator_contexts(accelerator)?;
        validate_rcore_region_metadata(accelerator)?;
        validate_accelerator_descriptor_metadata(accelerator)?;
        validate_accelerator_ports(accelerator)?;
        validate_accelerator_semantics(accelerator)?;
        if accelerator.descriptor_version == 0 {
            return Err(ValidationError::new(format!(
                "accelerator `{}` descriptor_version must be positive",
                accelerator.name
            )));
        }
        if !names.insert(accelerator.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate accelerator `{}`",
                accelerator.name
            )));
        }
    }
    Ok(())
}

fn validate_accelerator_semantics(accelerator: &Accelerator) -> Result<(), ValidationError> {
    if accelerator.latency_cycles == 0 {
        return Err(ValidationError::new(format!(
            "accelerator `{}` latency_cycles must be positive",
            accelerator.name
        )));
    }
    let throughput = accelerator
        .throughput_per_cycle
        .parse::<f64>()
        .map_err(|_| {
            ValidationError::new(format!(
                "accelerator `{}` throughput_per_cycle must be numeric",
                accelerator.name
            ))
        })?;
    if !throughput.is_finite() || throughput <= 0.0 {
        return Err(ValidationError::new(format!(
            "accelerator `{}` throughput_per_cycle must be positive",
            accelerator.name
        )));
    }
    let symbols: Vec<String> = accelerator
        .ports
        .iter()
        .map(|port| port.name.clone())
        .collect();
    validate_formal_semantics(&accelerator.formal_semantics, &symbols).map_err(|err| {
        ValidationError::new(format!(
            "accelerator `{}` {}",
            accelerator.name, err.message
        ))
    })?;
    Ok(())
}

fn validate_accelerator_ports(accelerator: &Accelerator) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for port in &accelerator.ports {
        require_identifier("accelerator port.name", &port.name)?;
        validate_allowed_value(
            &format!(
                "accelerator `{}` port `{}` direction",
                accelerator.name, port.name
            ),
            &port.direction,
            &["input", "output", "in", "out", "dma"],
        )?;
        require_non_empty(
            &format!(
                "accelerator `{}` port `{}` kind",
                accelerator.name, port.name
            ),
            &port.kind,
        )?;
        if !names.insert(port.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "accelerator `{}` has duplicate port `{}`",
                accelerator.name, port.name
            )));
        }
    }
    Ok(())
}

fn validate_memories(memories: &[Memory]) -> Result<(), ValidationError> {
    let mut names = HashSet::new();
    for memory in memories {
        require_identifier("memory.name", &memory.name)?;
        require_non_empty(&format!("memory `{}` kind", memory.name), &memory.kind)?;
        if memory.size_bytes == 0 {
            return Err(ValidationError::new(format!(
                "memory `{}` size_bytes must be positive",
                memory.name
            )));
        }
        if memory.ports == 0 {
            return Err(ValidationError::new(format!(
                "memory `{}` ports must be positive",
                memory.name
            )));
        }
        if memory.latency_cycles == 0 {
            return Err(ValidationError::new(format!(
                "memory `{}` latency_cycles must be positive",
                memory.name
            )));
        }
        // ⚠️ A cache's geometry has to BE a geometry. Lines that do not
        // divide the size, or ways that do not divide the lines, describe a
        // structure that cannot be built -- and the simulator would silently
        // round one of them and report cycles for a cache nobody declared.
        if memory.line_bytes != 0 || memory.ways != 0 {
            if memory.line_bytes == 0 {
                return Err(ValidationError::new(format!(
                    "memory `{}` declares ways and no line size; a cache with \
                     no line has nothing to put in a way",
                    memory.name
                )));
            }
            let ways = if memory.ways == 0 { 1 } else { memory.ways };
            if memory.size_bytes % u64::from(memory.line_bytes) != 0 {
                return Err(ValidationError::new(format!(
                    "memory `{}` is {} bytes in lines of {}, which does not \
                     divide",
                    memory.name, memory.size_bytes, memory.line_bytes
                )));
            }
            let lines = memory.size_bytes / u64::from(memory.line_bytes);
            if lines % u64::from(ways) != 0 {
                return Err(ValidationError::new(format!(
                    "memory `{}` has {} lines in {} ways, which does not \
                     divide into sets",
                    memory.name, lines, ways
                )));
            }
        }
        if memory.width_bits == 0 {
            return Err(ValidationError::new(format!(
                "memory `{}` width_bits must be positive",
                memory.name
            )));
        }
        if memory.banks == 0 {
            return Err(ValidationError::new(format!(
                "memory `{}` banks must be positive",
                memory.name
            )));
        }
        if !names.insert(memory.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate memory `{}`",
                memory.name
            )));
        }
    }
    Ok(())
}

fn validate_rcore_region_metadata(accelerator: &Accelerator) -> Result<(), ValidationError> {
    let family = canonical_value(&accelerator.family);
    if family != "rcore" && family != "ccore" {
        return Ok(());
    }
    validate_allowed_value(
        &format!("accelerator `{}` profile", accelerator.name),
        &accelerator.profile,
        RCORE_PROFILES,
    )?;
    validate_allowed_value(
        &format!("accelerator `{}` backend_kind", accelerator.name),
        &accelerator.backend_kind,
        RCORE_BACKEND_KINDS,
    )?;
    validate_allowed_value(
        &format!("accelerator `{}` exec_shape", accelerator.name),
        &accelerator.exec_shape,
        RCORE_EXEC_SHAPES,
    )?;
    validate_allowed_value(
        &format!("accelerator `{}` fallback_policy", accelerator.name),
        &accelerator.fallback_policy,
        RCORE_FALLBACK_POLICIES,
    )?;
    if canonical_value(&accelerator.exec_shape) != "scalar" && accelerator.simd_lanes == 0 {
        return Err(ValidationError::new(format!(
            "accelerator `{}` simd_lanes must be positive for exec_shape `{}`",
            accelerator.name, accelerator.exec_shape
        )));
    }
    Ok(())
}

fn validate_accelerator_descriptor_metadata(
    accelerator: &Accelerator,
) -> Result<(), ValidationError> {
    let family = canonical_value(&accelerator.family);
    if accelerator.descriptor_bytes == 0 {
        return Ok(());
    }
    let expected = match family.as_str() {
        "nearasic" => match accelerator.descriptor_version {
            1 => 68,
            2 => 124,
            _ => {
                return Err(ValidationError::new(format!(
                    "accelerator `{}` nearasic descriptor_version {} must be 1 or 2 when descriptor_bytes is declared",
                    accelerator.name, accelerator.descriptor_version
                )))
            }
        },
        "rcore" | "ccore" => match accelerator.descriptor_version {
            1 => 36,
            _ => {
                return Err(ValidationError::new(format!(
                    "accelerator `{}` {} descriptor_version {} must be 1 when descriptor_bytes is declared",
                    accelerator.name, family, accelerator.descriptor_version
                )))
            }
        },
        _ => return Ok(()),
    };
    if accelerator.descriptor_bytes != expected {
        return Err(ValidationError::new(format!(
            "accelerator `{}` {} descriptor_version {} expects descriptor_bytes {}, got {}",
            accelerator.name,
            family,
            accelerator.descriptor_version,
            expected,
            accelerator.descriptor_bytes
        )));
    }
    Ok(())
}

/// Topology rules for a spatial fabric (`docs/vliw_spatial_design.md` §5,
/// stage G1).
///
/// Everything here is a fact about the *declaration*, which is what G1 can
/// decide. Whether a mapping's operations fit is G2's, and whether the mapping
/// computes the right thing is G3's; a fabric that passes here is well-formed
/// and nothing more, which is the honest claim for a description with no
/// program on it yet.
fn validate_fabrics(document: &Document) -> Result<(), ValidationError> {
    let mut seen: Vec<&str> = Vec::new();
    for fabric in &document.fabrics {
        if seen.contains(&fabric.name.as_str()) {
            return Err(ValidationError::new(format!(
                "duplicate fabric `{}`",
                fabric.name
            )));
        }
        seen.push(&fabric.name);

        if fabric.rows == 0 || fabric.cols == 0 {
            return Err(ValidationError::new(format!(
                "fabric `{}` is {}x{}: a grid needs at least one PE",
                fabric.name, fabric.rows, fabric.cols
            )));
        }
        // The shared row: this row's PEs *are* that packet's slots. An ADRES
        // machine's VLIW units are the array's first row, not a copy of it, so
        // the correspondence has to hold position by position or the two
        // descriptions are of different hardware.
        if let Some((row, packet_name)) = &fabric.vliw_row {
            let Some(packet) = document
                .packets
                .iter()
                .find(|packet| &packet.name == packet_name)
            else {
                return Err(ValidationError::new(format!(
                    "fabric `{}` shares row {row} with packet `{packet_name}`, which is not \
                     declared",
                    fabric.name
                )));
            };
            if *row >= fabric.rows {
                return Err(ValidationError::new(format!(
                    "fabric `{}` shares row {row} with packet `{packet_name}`, off a grid of \
                     {} row(s)",
                    fabric.name, fabric.rows
                )));
            }
            if packet.slots.len() as u32 != fabric.cols {
                return Err(ValidationError::new(format!(
                    "fabric `{}` shares row {row} with packet `{packet_name}`, but the row has \
                     {} PE(s) and the packet has {} slot(s); one unit cannot be in two places",
                    fabric.name,
                    fabric.cols,
                    packet.slots.len()
                )));
            }
            // One set of units cannot issue two ways at once. The sharing is
            // what makes that true of the hardware; naming a different mode on
            // each side is what makes a description that violates it
            // impossible. Both must say, because an unnamed mode means every
            // mode, and "every mode" is exactly the machine that cannot exist.
            if fabric.mode.is_empty() || packet.mode.is_empty() {
                return Err(ValidationError::new(format!(
                    "fabric `{}` shares row {row} with packet `{packet_name}`, so the two \
                     issue one set of units and must name the modes that keep them apart; \
                     fabric mode is {}, packet mode is {}",
                    fabric.name,
                    if fabric.mode.is_empty() { "unset" } else { &fabric.mode },
                    if packet.mode.is_empty() { "unset" } else { &packet.mode }
                )));
            }
            if fabric.mode == packet.mode {
                return Err(ValidationError::new(format!(
                    "fabric `{}` and packet `{packet_name}` share row {row} and both run in \
                     mode `{}`; they are one set of functional units, so a machine issuing \
                     both at once would use each of them twice",
                    fabric.name, fabric.mode
                )));
            }
            // The slots *are* the row's PEs, column by column, so the fabric
            // must not also describe that row: two statements of one thing
            // differ eventually. Slot 3 holding only `br` while slot 0 holds
            // `alu mem` is the ordinary shape of a VLIW row, and it is why the
            // row cannot be described by one unit list of its own.
            if let Some(class) = fabric.pe_class(*row) {
                return Err(ValidationError::new(format!(
                    "fabric `{}` shares row {row} with packet `{packet_name}` and also \
                     describes rows {}..{}; the slots are those PEs, so describing them \
                     twice says the same thing two ways",
                    fabric.name, class.first_row, class.last_row
                )));
            }
            for slot in &packet.slots {
                if slot.units.is_empty() {
                    return Err(ValidationError::new(format!(
                        "fabric `{}` shares row {row} with packet `{packet_name}`, whose slot \
                         `{}` holds no unit",
                        fabric.name, slot.name
                    )));
                }
            }
        }
        for class in &fabric.pe_rows {
            if class.first_row > class.last_row {
                return Err(ValidationError::new(format!(
                    "fabric `{}` describes rows {}..{}, which is empty",
                    fabric.name, class.first_row, class.last_row
                )));
            }
            if class.last_row >= fabric.rows {
                return Err(ValidationError::new(format!(
                    "fabric `{}` describes row {}, off a grid of {} row(s)",
                    fabric.name, class.last_row, fabric.rows
                )));
            }
            if class.units.is_empty() {
                return Err(ValidationError::new(format!(
                    "fabric `{}` rows {}..{} hold no unit class, so no operation can be \
                     placed on them",
                    fabric.name, class.first_row, class.last_row
                )));
            }
        }
        // Two clauses describing one row would leave which of them applies to
        // the order they were written in, which is not a thing a description
        // should depend on.
        for (index, class) in fabric.pe_rows.iter().enumerate() {
            for other in &fabric.pe_rows[index + 1..] {
                if class.first_row <= other.last_row && other.first_row <= class.last_row {
                    return Err(ValidationError::new(format!(
                        "fabric `{}` describes rows {}..{} and {}..{}, which overlap",
                        fabric.name,
                        class.first_row,
                        class.last_row,
                        other.first_row,
                        other.last_row
                    )));
                }
            }
        }
        // A row with no clause of its own falls back to the default, so the
        // default may only be empty when every row has one.
        if fabric.units.is_empty()
            && (0..fabric.rows).any(|row| fabric.pe_class(row).is_none())
        {
            return Err(ValidationError::new(format!(
                "fabric `{}` PEs hold no unit class, so no operation can be placed on them",
                fabric.name
            )));
        }
        // The same classes a packet's slots name. A fabric whose PEs hold a
        // unit no instruction declares is a grid nothing can run on, and the
        // reason to check it here is that the alternative is discovering it in
        // G2 as "this mapping places an operation nowhere".
        for unit in &fabric.all_units() {
            let unit = crate::ast::canonical_unit(unit);
            let issued = document
                .instructions
                .iter()
                .any(|instruction| crate::ast::canonical_unit(&instruction.unit) == unit);
            if !issued {
                return Err(ValidationError::new(format!(
                    "fabric `{}` PEs hold unit `{unit}`, which no instruction declares",
                    fabric.name
                )));
            }
        }
        if fabric.contexts == 0 {
            return Err(ValidationError::new(format!(
                "fabric `{}` declares `contexts 0`: a PE holds at least one configuration",
                fabric.name
            )));
        }
        if fabric.ii_max == 0 {
            return Err(ValidationError::new(format!(
                "fabric `{}` declares `ii-max 0`: a modulo schedule repeats every II cycles \
                 and II is at least 1",
                fabric.name
            )));
        }

        for link in &fabric.links {
            for (row, col, end) in [
                (link.from_row, link.from_col, "source"),
                (link.to_row, link.to_col, "destination"),
            ] {
                if !fabric.holds(row, col) {
                    return Err(ValidationError::new(format!(
                        "fabric `{}` link {end} ({row}, {col}) is off a {}x{} grid",
                        fabric.name, fabric.rows, fabric.cols
                    )));
                }
            }
            if link.from_row == link.to_row && link.from_col == link.to_col {
                return Err(ValidationError::new(format!(
                    "fabric `{}` links PE ({}, {}) to itself",
                    fabric.name, link.from_row, link.from_col
                )));
            }
            // A zero-latency link is a wire, and a wire between two PEs that
            // both compute in a cycle is a combinational path no modulo
            // schedule can account for.
            if link.latency == 0 {
                return Err(ValidationError::new(format!(
                    "fabric `{}` link ({}, {}) -> ({}, {}) has latency 0: a value takes \
                     at least one cycle to cross a link",
                    fabric.name, link.from_row, link.from_col, link.to_row, link.to_col
                )));
            }
            if link.latency > fabric.ii_max {
                return Err(ValidationError::new(format!(
                    "fabric `{}` link ({}, {}) -> ({}, {}) takes {} cycles, longer than \
                     `ii-max {}`: no mapping could route across it",
                    fabric.name, link.from_row, link.from_col, link.to_row, link.to_col,
                    link.latency, fabric.ii_max
                )));
            }
        }

        for port in &fabric.ports {
            if port.row >= fabric.rows {
                return Err(ValidationError::new(format!(
                    "fabric `{}` memory port on row {} is off a {}-row grid",
                    fabric.name, port.row, fabric.rows
                )));
            }
            if !document
                .memories
                .iter()
                .any(|memory| memory.name == port.memory)
            {
                return Err(ValidationError::new(format!(
                    "fabric `{}` memory port on row {} names unknown memory `{}`",
                    fabric.name, port.row, port.memory
                )));
            }
        }

        // A PE nothing links to can hold an operation and never pass its
        // result on, which is a grid with a hole in it rather than a fabric.
        // Only meaningful above one PE, where "connected" has content.
        if fabric.rows * fabric.cols > 1 {
            for (row, col) in fabric.positions() {
                let touched = fabric.links.iter().any(|link| {
                    (link.from_row == row && link.from_col == col)
                        || (link.to_row == row && link.to_col == col)
                });
                if !touched {
                    return Err(ValidationError::new(format!(
                        "fabric `{}` PE ({row}, {col}) has no link: a value computed there \
                         could never reach another PE",
                        fabric.name
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Modulo-schedule legality for a mapping (`docs/vliw_spatial_design.md` §5,
/// stage G2).
///
/// The whole legality condition of a modulo schedule is that nothing is used
/// twice in one steady-state cycle, and it is cheap to check *given* a
/// mapping. AXIS checks a mapping; it does not compute one -- placement and
/// routing are a compiler's search problem, and this is the checker its output
/// is held to.
/// Elastic channels: the declarations, and the one property that is decidable
/// from them alone (`elastic_seams_design.md` §4).
///
/// The protocol is a name, so what can be checked is that it is a name this
/// language knows, that a latency window is a window, and that no cycle of
/// channels can deadlock. The last is the one a mapper most wants: a ring of
/// pure wires has nowhere to put a token, so nothing can move, and that is
/// decidable without executing anything.
pub(crate) fn validate_channels(document: &Document) -> Result<(), ValidationError> {
    const PROTOCOLS: [&str; 2] = ["ready-valid", "credit"];
    const ORDERS: [&str; 2] = ["preserving", "unordered"];

    let mut seen: HashSet<String> = HashSet::new();
    for channel in &document.channels {
        require_identifier("channel.name", &channel.name)?;
        if !seen.insert(channel.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate channel `{}`",
                channel.name
            )));
        }
        if !PROTOCOLS.contains(&channel.protocol.as_str()) {
            return Err(ValidationError::new(format!(
                "channel `{}` protocol `{}` is not one of {}; the protocol is a name a \
                 consumer matches on, and a name this language does not know is one no \
                 consumer can be held to",
                channel.name,
                channel.protocol,
                PROTOCOLS.join(", ")
            )));
        }
        if !ORDERS.contains(&channel.order.as_str()) {
            return Err(ValidationError::new(format!(
                "channel `{}` order `{}` is not one of {}",
                channel.name,
                channel.order,
                ORDERS.join(", ")
            )));
        }
        if channel.initial != 0 && channel.capacity == 0 {
            return Err(ValidationError::new(format!(
                "channel `{}` starts holding {} and has no capacity to hold it; an \
                 initial token needs a buffer to sit in",
                channel.name, channel.initial
            )));
        }
        if channel.latency_min > channel.latency_max {
            return Err(ValidationError::new(format!(
                "channel `{}` has latency window {}..{}, which is empty",
                channel.name, channel.latency_min, channel.latency_max
            )));
        }
    }

    for mapping in &document.mappings {
        if let Some(cycle) = elastic_cycle_without_capacity(document, mapping) {
            return Err(ValidationError::new(format!(
                "mapping `{}` has a cycle of elastic routes with no buffering: {}. Every \
                 channel on it is a pure wire, so a token has nowhere to wait and nothing \
                 can move -- give one of them `(capacity N)`",
                mapping.name,
                cycle.join(" -> ")
            )));
        }
    }
    Ok(())
}

/// Every functional unit the document declares anywhere: a VLIW packet's slots,
/// a fabric's PE rows. An export lends one of these across a boundary, so a name
/// that is in no slot and no row is a unit the exporting machine does not have.
fn declared_units(document: &Document) -> HashSet<String> {
    let mut units = HashSet::new();
    for packet in &document.packets {
        for slot in &packet.slots {
            for unit in &slot.units {
                units.insert(canonical_unit(unit));
            }
        }
    }
    for fabric in &document.fabrics {
        for unit in fabric.all_units() {
            units.insert(canonical_unit(&unit));
        }
    }
    units
}

/// P5 / G4b.3. An export lends a unit over a channel; an import borrows it over
/// its own. The two channels need not be the same channel -- the seam is where
/// two machines meet, and each states its own side -- but they must compose, and
/// what "compose" means is the whole content of this check:
///
///   * the same protocol, because the protocol is a name a consumer matches on
///     and two names that differ are two handshakes;
///   * the importer's latency window contains the exporter's, because a producer
///     that can be later than the consumer tolerates is a producer the consumer
///     will drop;
///   * order composes downward, because a consumer promising `preserving` while
///     fed by an `unordered` producer promises something it was never given.
///
/// None of this models the handshake. It checks that two sides of a seam were
/// specified to be the same seam.
fn validate_seams(document: &Document) -> Result<(), ValidationError> {
    let units = declared_units(document);
    let channel = |name: &str| {
        document
            .channels
            .iter()
            .find(|channel| channel.name.eq_ignore_ascii_case(name))
    };

    for personality in &document.personalities {
        let mut seen: HashSet<String> = HashSet::new();
        for export in &personality.exports {
            require_identifier("export.name", &export.name)?;
            if !seen.insert(export.name.to_ascii_lowercase()) {
                return Err(ValidationError::new(format!(
                    "personality `{}` exports `{}` twice",
                    personality.name, export.name
                )));
            }
            if !units.contains(&canonical_unit(&export.unit)) {
                return Err(ValidationError::new(format!(
                    "personality `{}` exports unit `{}`, which no packet slot and no \
                     fabric row declares; a machine cannot lend a unit it does not have",
                    personality.name, export.unit
                )));
            }
            if channel(&export.channel).is_none() {
                return Err(ValidationError::new(format!(
                    "personality `{}` export `{}` names unknown channel `{}`",
                    personality.name, export.name, export.channel
                )));
            }
        }

        let mut seen: HashSet<String> = HashSet::new();
        for import in &personality.imports {
            require_identifier("import.name", &import.name)?;
            if !seen.insert(import.name.to_ascii_lowercase()) {
                return Err(ValidationError::new(format!(
                    "personality `{}` imports `{}` twice",
                    personality.name, import.name
                )));
            }
            let importer_channel = channel(&import.channel).ok_or_else(|| {
                ValidationError::new(format!(
                    "personality `{}` import `{}` names unknown channel `{}`",
                    personality.name, import.name, import.channel
                ))
            })?;
            if import.from.eq_ignore_ascii_case(&personality.name) {
                return Err(ValidationError::new(format!(
                    "personality `{}` imports `{}` from itself; a seam has two sides",
                    personality.name, import.name
                )));
            }
            let exporter = document
                .personalities
                .iter()
                .find(|candidate| candidate.name.eq_ignore_ascii_case(&import.from))
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "personality `{}` import `{}` names unknown personality `{}`",
                        personality.name, import.name, import.from
                    ))
                })?;
            let export = exporter
                .exports
                .iter()
                .find(|export| export.name.eq_ignore_ascii_case(&import.name))
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "personality `{}` imports `{}` from `{}`, which exports no such \
                         unit",
                        personality.name, import.name, exporter.name
                    ))
                })?;
            // The exporter's channel was checked above when its own personality
            // was walked, so it resolves.
            let exporter_channel = channel(&export.channel).ok_or_else(|| {
                ValidationError::new(format!(
                    "personality `{}` export `{}` names unknown channel `{}`",
                    exporter.name, export.name, export.channel
                ))
            })?;

            if exporter_channel.protocol != importer_channel.protocol {
                return Err(ValidationError::new(format!(
                    "seam `{}`: `{}` exports over `{}` speaking `{}` and `{}` imports over \
                     `{}` speaking `{}`; two protocols are two handshakes",
                    import.name,
                    exporter.name,
                    exporter_channel.name,
                    exporter_channel.protocol,
                    personality.name,
                    importer_channel.name,
                    importer_channel.protocol
                )));
            }
            if importer_channel.latency_min > exporter_channel.latency_min
                || importer_channel.latency_max < exporter_channel.latency_max
            {
                return Err(ValidationError::new(format!(
                    "seam `{}`: `{}` exports with latency {}..{} and `{}` accepts only \
                     {}..{}; the importer's window must contain the exporter's, or the \
                     producer is sometimes outside what the consumer tolerates",
                    import.name,
                    exporter.name,
                    exporter_channel.latency_min,
                    exporter_channel.latency_max,
                    personality.name,
                    importer_channel.latency_min,
                    importer_channel.latency_max
                )));
            }
            if exporter_channel.order == "unordered" && importer_channel.order == "preserving" {
                return Err(ValidationError::new(format!(
                    "seam `{}`: `{}` exports over an unordered channel and `{}` imports \
                     over a preserving one; a consumer cannot promise an order its \
                     producer never gave it",
                    import.name, exporter.name, personality.name
                )));
            }
        }
    }
    Ok(())
}

/// The operations on one elastic cycle whose channels hold nothing, if there is
/// such a cycle.
///
/// Depth-first over the elastic routes only: a statically timed route cannot
/// deadlock, because its arrival is a cycle rather than a wait. A cycle carries
/// capacity when any channel on it does, since one buffered token is enough to
/// let the ring turn.
fn elastic_cycle_without_capacity(
    document: &Document,
    mapping: &crate::ast::Mapping,
) -> Option<Vec<String>> {
    let capacity = |name: &str| {
        document
            .channels
            .iter()
            .find(|channel| channel.name == name)
            .map(|channel| channel.capacity)
            .unwrap_or(0)
    };
    let mut path: Vec<String> = Vec::new();
    let mut visiting: HashSet<String> = HashSet::new();
    let mut done: HashSet<String> = HashSet::new();
    for op in &mapping.ops {
        if let Some(found) =
            walk_elastic(mapping, &op.id, &capacity, &mut path, &mut visiting, &mut done)
        {
            return Some(found);
        }
    }
    None
}

fn walk_elastic(
    mapping: &crate::ast::Mapping,
    id: &str,
    capacity: &impl Fn(&str) -> u32,
    path: &mut Vec<String>,
    visiting: &mut HashSet<String>,
    done: &mut HashSet<String>,
) -> Option<Vec<String>> {
    if done.contains(id) {
        return None;
    }
    if visiting.contains(id) {
        // Back to an operation already on this path: the cycle is its suffix.
        let start = path.iter().position(|step| step == id).unwrap_or(0);
        let mut cycle: Vec<String> = path[start..].to_vec();
        cycle.push(id.to_string());
        let buffered = cycle.windows(2).any(|pair| {
            mapping
                .routes
                .iter()
                .filter(|route| route.from == pair[0] && route.to == pair[1])
                .any(|route| capacity(&route.channel) > 0)
        });
        return (!buffered).then_some(cycle);
    }
    visiting.insert(id.to_string());
    path.push(id.to_string());
    for route in mapping
        .routes
        .iter()
        .filter(|route| route.from == id && !route.channel.is_empty())
    {
        if let Some(found) = walk_elastic(mapping, &route.to, capacity, path, visiting, done) {
            return Some(found);
        }
    }
    path.pop();
    visiting.remove(id);
    done.insert(id.to_string());
    None
}

pub(crate) fn validate_mappings(document: &Document) -> Result<(), ValidationError> {
    let mut seen: Vec<&str> = Vec::new();
    for mapping in &document.mappings {
        if seen.contains(&mapping.name.as_str()) {
            return Err(ValidationError::new(format!(
                "duplicate mapping `{}`",
                mapping.name
            )));
        }
        seen.push(&mapping.name);

        let Some(fabric) = document
            .fabrics
            .iter()
            .find(|fabric| fabric.name == mapping.fabric)
        else {
            return Err(ValidationError::new(format!(
                "mapping `{}` names unknown fabric `{}`",
                mapping.name, mapping.fabric
            )));
        };
        if mapping.ii == 0 || mapping.ii > fabric.ii_max {
            return Err(ValidationError::new(format!(
                "mapping `{}` declares `ii {}`, outside 1..={} for fabric `{}`",
                mapping.name, mapping.ii, fabric.ii_max, fabric.name
            )));
        }
        if mapping.ops.is_empty() {
            return Err(ValidationError::new(format!(
                "mapping `{}` places no operation",
                mapping.name
            )));
        }

        let mut op_ids: Vec<&str> = Vec::new();
        for op in &mapping.ops {
            if op_ids.contains(&op.id.as_str()) {
                return Err(ValidationError::new(format!(
                    "mapping `{}` places two operations named `{}`",
                    mapping.name, op.id
                )));
            }
            op_ids.push(&op.id);

            let Some(instruction) = document
                .instructions
                .iter()
                .find(|instruction| instruction.mnemonic == op.mnemonic)
            else {
                return Err(ValidationError::new(format!(
                    "mapping `{}` operation `{}` names unknown instruction `{}`",
                    mapping.name, op.id, op.mnemonic
                )));
            };
            if !fabric.holds(op.row, op.col) {
                return Err(ValidationError::new(format!(
                    "mapping `{}` places `{}` on PE ({}, {}), off a {}x{} grid",
                    mapping.name, op.id, op.row, op.col, fabric.rows, fabric.cols
                )));
            }
            // Which units a PE holds is a property of its row. Asking the
            // fabric-wide list instead was a check that could not fail on a
            // uniform grid and answered the wrong question on any other.
            let shared_packet = fabric.vliw_row.as_ref().and_then(|(_, name)| {
                document.packets.iter().find(|packet| &packet.name == name)
            });
            let held_here = fabric.units_at_pe(op.row, op.col, shared_packet);
            let unit = crate::ast::canonical_unit(&instruction.unit);
            if !held_here
                .iter()
                .any(|held| crate::ast::canonical_unit(held) == unit)
            {
                let held: Vec<&str> = held_here.iter().map(|unit| unit.as_str()).collect();
                return Err(ValidationError::new(format!(
                    "mapping `{}` places `{}` (`{}`, unit `{unit}`) on PE ({}, {}) of fabric \
                     `{}`, whose row {} holds {}",
                    mapping.name,
                    op.id,
                    op.mnemonic,
                    op.row,
                    op.col,
                    fabric.name,
                    op.row,
                    if held.is_empty() { "nothing".to_string() } else { held.join(", ") }
                )));
            }
        }

        // A PE does one thing per configuration it holds, so placing several
        // operations on one -- which the modulo rule permits at distinct
        // residues -- asks it to hold several. Without this the model let a
        // mapping need sixteen configurations on a machine with one.
        let mut per_pe: Vec<((u32, u32), Vec<&str>)> = Vec::new();
        for op in &mapping.ops {
            match per_pe
                .iter_mut()
                .find(|(position, _)| *position == (op.row, op.col))
            {
                Some((_, ids)) => ids.push(&op.id),
                None => per_pe.push(((op.row, op.col), vec![&op.id])),
            }
        }
        for ((row, col), ids) in &per_pe {
            if ids.len() as u32 > fabric.contexts {
                return Err(ValidationError::new(format!(
                    "mapping `{}` places {} operations on PE ({row}, {col}) ({}), but a PE \
                     of fabric `{}` holds {} configuration(s)",
                    mapping.name,
                    ids.len(),
                    ids.join(", "),
                    fabric.name,
                    fabric.contexts
                )));
            }
        }

        // Modulo resource legality, PEs. Two operations sharing a PE in one
        // steady-state cycle is the schedule asking one machine to do two
        // things at once.
        let mut pe_used: Vec<((u32, u32), u32, &str)> = Vec::new();
        for op in &mapping.ops {
            let slot = op.cycle % mapping.ii;
            if let Some((_, _, other)) = pe_used
                .iter()
                .find(|(position, used, _)| *position == (op.row, op.col) && *used == slot)
            {
                return Err(ValidationError::new(format!(
                    "mapping `{}` puts `{}` and `{other}` on PE ({}, {}) at cycle {} mod {}",
                    mapping.name, op.id, op.row, op.col, slot, mapping.ii
                )));
            }
            pe_used.push(((op.row, op.col), slot, &op.id));
        }

        // Routes: endpoints are the operations they join, every hop is a
        // declared link, and no link carries two values in one cycle.
        let mut link_used: Vec<((u32, u32, u32, u32), u32, String)> = Vec::new();
        for route in &mapping.routes {
            let (Some(producer), Some(consumer)) =
                (mapping.op(&route.from), mapping.op(&route.to))
            else {
                return Err(ValidationError::new(format!(
                    "mapping `{}` routes between `{}` and `{}`, and one of them is not placed",
                    mapping.name, route.from, route.to
                )));
            };
            if route.via.len() < 2 {
                return Err(ValidationError::new(format!(
                    "mapping `{}` route `{}` -> `{}` has no path: `via` names the PEs it \
                     passes through, starting at the producer's and ending at the consumer's",
                    mapping.name, route.from, route.to
                )));
            }
            if route.via[0] != (producer.row, producer.col) {
                return Err(ValidationError::new(format!(
                    "mapping `{}` route `{}` -> `{}` starts at ({}, {}), but `{}` is on \
                     ({}, {})",
                    mapping.name, route.from, route.to, route.via[0].0, route.via[0].1,
                    route.from, producer.row, producer.col
                )));
            }
            let last = route.via[route.via.len() - 1];
            if last != (consumer.row, consumer.col) {
                return Err(ValidationError::new(format!(
                    "mapping `{}` route `{}` -> `{}` ends at ({}, {}), but `{}` is on ({}, {})",
                    mapping.name, route.from, route.to, last.0, last.1, route.to,
                    consumer.row, consumer.col
                )));
            }

            // An elastic route's arrival is a window, not a cycle, so the two
            // timing checks below do not apply to it: `elastic_seams_design.md`
            // §3 makes the exemption explicit rather than bolting a window onto
            // residue arithmetic, which would produce a check that means
            // neither thing. Everything structural still holds -- the endpoints
            // are placed, the path is real links, the operand is an input.
            let elastic = !route.channel.is_empty();
            if elastic {
                if !document
                    .channels
                    .iter()
                    .any(|channel| channel.name == route.channel)
                {
                    return Err(ValidationError::new(format!(
                        "mapping `{}` route `{}` -> `{}` names channel `{}`, which is not \
                         declared",
                        mapping.name, route.from, route.to, route.channel
                    )));
                }
                if route.cycle != 0 {
                    return Err(ValidationError::new(format!(
                        "mapping `{}` route `{}` -> `{}` crosses channel `{}` and also \
                         states cycle {}; an elastic route's timing is the channel's window",
                        mapping.name, route.from, route.to, route.channel, route.cycle
                    )));
                }
            }

            let mut flight = 0u32;
            for (index, pair) in route.via.windows(2).enumerate() {
                let (from, to) = (pair[0], pair[1]);
                let Some(link) = fabric.links.iter().find(|link| {
                    (link.from_row, link.from_col, link.to_row, link.to_col)
                        == (from.0, from.1, to.0, to.1)
                }) else {
                    return Err(ValidationError::new(format!(
                        "mapping `{}` route `{}` -> `{}` hops ({}, {}) -> ({}, {}), which \
                         fabric `{}` does not link",
                        mapping.name, route.from, route.to, from.0, from.1, to.0, to.1,
                        fabric.name
                    )));
                };
                // A hop occupies its link in the cycle the value enters it --
                // for a statically timed route. An elastic hop has no such
                // cycle, so it takes no residue and collides with nothing.
                let slot = (route.cycle + flight) % mapping.ii;
                let key = (from.0, from.1, to.0, to.1);
                if let Some((_, _, other)) = link_used
                    .iter()
                    .find(|(used_key, used_slot, _)| *used_key == key && *used_slot == slot)
                    .filter(|_| !elastic)
                {
                    return Err(ValidationError::new(format!(
                        "mapping `{}` sends `{}` -> `{}` and {other} across the link \
                         ({}, {}) -> ({}, {}) at cycle {slot} mod {}",
                        mapping.name, route.from, route.to, from.0, from.1, to.0, to.1,
                        mapping.ii
                    )));
                }
                if !elastic {
                    link_used.push((
                        key,
                        slot,
                        format!("`{}` -> `{}`", route.from, route.to),
                    ));
                }
                let _ = index;
                flight += link.latency;
            }

            // The operand a value arrives at has to be an input of the
            // consumer, and no two values may arrive at the same one.
            let consumer_instruction = document
                .instructions
                .iter()
                .find(|instruction| instruction.mnemonic == consumer.mnemonic);
            let is_input = consumer_instruction.is_some_and(|instruction| {
                instruction
                    .operands
                    .iter()
                    .any(|operand| operand.name == route.operand && operand.input)
            });
            if !is_input {
                return Err(ValidationError::new(format!(
                    "mapping `{}` route `{}` -> `{}` feeds operand `{}`, which is not an \
                     input of `{}`",
                    mapping.name, route.from, route.to, route.operand, consumer.mnemonic
                )));
            }
            if mapping
                .routes
                .iter()
                .filter(|other| other.to == route.to && other.operand == route.operand)
                .count()
                > 1
            {
                return Err(ValidationError::new(format!(
                    "mapping `{}` routes two values into `{}`'s operand `{}`",
                    mapping.name, route.to, route.operand
                )));
            }

            // A consumer reads what a producer computed and the links carried:
            // its cycle is the producer's, plus the producer's latency, plus
            // the time in flight -- in the steady state, so modulo II.
            let producer_latency = document
                .instructions
                .iter()
                .find(|instruction| instruction.mnemonic == producer.mnemonic)
                .map(|instruction| instruction.latency_cycles)
                .unwrap_or(1);
            // Exact, not modular. `distance` says which iteration the value
            // comes from, and once that is stated the arithmetic closes on
            // absolute cycles -- where the same statement modulo `ii` cannot
            // tell one iteration's value from another's, and would accept a
            // mapping that silently reads the wrong one.
            let arrives = producer.cycle + producer_latency + flight;
            let expected = consumer.cycle + route.distance * mapping.ii;
            if !elastic && arrives != expected {
                return Err(ValidationError::new(format!(
                    "mapping `{}` route `{}` -> `{}` arrives at cycle {arrives} \
                     ({} + {producer_latency} latency + {flight} in flight), but `{}` \
                     reads it at {expected} (cycle {} of iteration +{})",
                    mapping.name, route.from, route.to, producer.cycle, route.to,
                    consumer.cycle, route.distance
                )));
            }
        }

        // The scalar order is what the mapping claims to compute, so it has to
        // account for every operation and invent none. G3 executes it; G2 can
        // already say whether it is a sequence of this mapping's operations.
        for id in &mapping.equivalent_to {
            if mapping.op(id).is_none() {
                return Err(ValidationError::new(format!(
                    "mapping `{}` scalar order names `{id}`, which it does not place",
                    mapping.name
                )));
            }
        }
        for op in &mapping.ops {
            if !mapping.equivalent_to.contains(&op.id) {
                return Err(ValidationError::new(format!(
                    "mapping `{}` places `{}` but leaves it out of the scalar order, so \
                     what the mapping computes is unstated",
                    mapping.name, op.id
                )));
            }
        }

        // Where every value comes from. A route feeds an operand from another
        // operation; a live-in feeds it from the register file or the PE's
        // constant. An operand with neither has a value from nowhere, which
        // used to be filled in with an anonymous random number -- enough to
        // check placement and timing, and silent about what the kernel reads.
        for live in &mapping.live_in {
            let Some(op) = mapping.op(&live.op) else {
                return Err(ValidationError::new(format!(
                    "mapping `{}` gives a live-in to `{}`, which it does not place",
                    mapping.name, live.op
                )));
            };
            let Some(instruction) = document
                .instructions
                .iter()
                .find(|instruction| instruction.mnemonic == op.mnemonic)
            else {
                continue;
            };
            if !instruction
                .operands
                .iter()
                .any(|operand| operand.name == live.operand && operand.input)
            {
                return Err(ValidationError::new(format!(
                    "mapping `{}` gives a live-in to `{}`'s operand `{}`, which is not an \
                     input of `{}`",
                    mapping.name, live.op, live.operand, op.mnemonic
                )));
            }
            if mapping
                .routes
                .iter()
                .any(|route| route.to == live.op && route.operand == live.operand)
            {
                return Err(ValidationError::new(format!(
                    "mapping `{}` both routes a value into `{}`'s operand `{}` and gives it \
                     a live-in; an operand has one source",
                    mapping.name, live.op, live.operand
                )));
            }
            if mapping
                .live_in
                .iter()
                .filter(|other| other.op == live.op && other.operand == live.operand)
                .count()
                > 1
            {
                return Err(ValidationError::new(format!(
                    "mapping `{}` gives `{}`'s operand `{}` two live-ins",
                    mapping.name, live.op, live.operand
                )));
            }
            // A constant comes out of the PE's constant register, so a fabric
            // whose PEs have none cannot supply one.
            if let crate::ast::MappingSource::Constant(_) = live.source {
                if let Some(fabric) = document
                    .fabrics
                    .iter()
                    .find(|fabric| fabric.name == mapping.fabric)
                {
                    if fabric.consts_at(op.row) == 0 {
                        return Err(ValidationError::new(format!(
                            "mapping `{}` feeds `{}`'s operand `{}` from a constant, but PE \
                             ({}, {}) of fabric `{}` holds no constant register",
                            mapping.name,
                            live.op,
                            live.operand,
                            op.row,
                            op.col,
                            fabric.name
                        )));
                    }
                }
            }
        }
        // Completeness, stated only for a mapping that names any source at all.
        // A mapping with no live-ins is the older form: proven as a dataflow,
        // saying nothing about the register file. One that starts naming
        // registers has to name them all, or it says half of what it reads.
        if !mapping.live_in.is_empty() {
            for op in &mapping.ops {
                let Some(instruction) = document
                    .instructions
                    .iter()
                    .find(|instruction| instruction.mnemonic == op.mnemonic)
                else {
                    continue;
                };
                for operand in instruction.operands.iter().filter(|o| o.input) {
                    let routed = mapping
                        .routes
                        .iter()
                        .any(|route| route.to == op.id && route.operand == operand.name);
                    let live = mapping
                        .live_in
                        .iter()
                        .any(|live| live.op == op.id && live.operand == operand.name);
                    if !routed && !live {
                        return Err(ValidationError::new(format!(
                            "mapping `{}` names live-ins but leaves `{}`'s operand `{}` with \
                             no source; a value has to come from somewhere",
                            mapping.name, op.id, operand.name
                        )));
                    }
                }
            }
        }
        for live in &mapping.live_out {
            if mapping.op(&live.op).is_none() {
                return Err(ValidationError::new(format!(
                    "mapping `{}` takes a live-out from `{}`, which it does not place",
                    mapping.name, live.op
                )));
            }
            if mapping
                .live_out
                .iter()
                .filter(|other| other.register == live.register)
                .count()
                > 1
            {
                return Err(ValidationError::new(format!(
                    "mapping `{}` leaves two results in register {}",
                    mapping.name, live.register
                )));
            }
        }
    }
    Ok(())
}

/// An instruction that launches a mapping must agree with it.
///
/// Three obligations, and the point is that no one of them sees the other's
/// evidence: the ordinary executor gates prove this instruction against the
/// golden model, G3 proves the mapping computes its scalar order, and this
/// proves the instruction's semantics *is* that order composed. Two independent
/// checks meeting at one sequence is worth more than either restated.
fn validate_mapping_launches(document: &Document) -> Result<(), ValidationError> {
    for instruction in &document.instructions {
        if instruction.runs_mapping.is_empty() {
            continue;
        }
        let Some(mapping) = document
            .mappings
            .iter()
            .find(|mapping| mapping.name == instruction.runs_mapping)
        else {
            return Err(ValidationError::new(format!(
                "instruction `{}` runs mapping `{}`, which is not declared",
                instruction.mnemonic, instruction.runs_mapping
            )));
        };
        if mapping.live_out.len() != 1 {
            return Err(ValidationError::new(format!(
                "instruction `{}` runs mapping `{}`, which leaves {} result(s); a launch \
                 writes one",
                instruction.mnemonic,
                mapping.name,
                mapping.live_out.len()
            )));
        }
        // The registers the kernel reads become the launch's inputs, in
        // ascending order. One register feeding two operands is one input, so
        // the correspondence is over *distinct* registers.
        let mut registers: Vec<u32> = mapping
            .live_in
            .iter()
            .filter_map(|live| match live.source {
                crate::ast::MappingSource::Register(index) => Some(index),
                crate::ast::MappingSource::Constant(_) => None,
            })
            .collect();
        registers.sort_unstable();
        registers.dedup();
        // Unless the launch reads them itself. An ADRES mode switch enters an
        // array that shares the register file, so its kernel's live-ins are
        // registers the instruction names rather than operands it takes -- and
        // a launch that reads x3 with `getreg` supplies nothing for x3.
        let direct: Vec<(String, u32)> = crate::effects::behavior_register_reads(instruction);
        for (kind, index) in &direct {
            if !registers.contains(index) {
                return Err(ValidationError::new(format!(
                    "instruction `{}` reads `{kind}` register {index}, which mapping `{}`'s \
                     kernel does not read; a launch reads what the kernel reads",
                    instruction.mnemonic, mapping.name
                )));
            }
        }
        let supplied: Vec<u32> = registers
            .iter()
            .copied()
            .filter(|index| !direct.iter().any(|(_, read)| read == index))
            .collect();
        let inputs: Vec<&crate::ast::Operand> = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .collect();
        if inputs.len() != supplied.len() {
            return Err(ValidationError::new(format!(
                "instruction `{}` runs mapping `{}`, which reads {} register(s) the launch \
                 does not read itself, but takes {} input operand(s); the launch supplies \
                 what the kernel reads and it does not read",
                instruction.mnemonic,
                mapping.name,
                supplied.len(),
                inputs.len()
            )));
        }
        if instruction.operands.iter().filter(|o| o.output).count() != 1 {
            return Err(ValidationError::new(format!(
                "instruction `{}` runs mapping `{}` and must write one operand, for the one \
                 result the mapping leaves",
                instruction.mnemonic, mapping.name
            )));
        }
        // What each register the kernel reads *is*, as an expression: the
        // launch's operand for the ones it supplies, and the read itself for
        // the ones it performs.
        use crate::semantics::SemanticExpr;
        let mut source_for_register: std::collections::HashMap<u32, SemanticExpr> = supplied
            .iter()
            .zip(inputs.iter())
            .map(|(register, operand)| (*register, SemanticExpr::Atom(operand.name.clone())))
            .collect();
        for (kind, index) in &direct {
            source_for_register.insert(
                *index,
                SemanticExpr::List(vec![
                    SemanticExpr::Atom("getreg".to_string()),
                    SemanticExpr::Atom(kind.clone()),
                    SemanticExpr::Atom(index.to_string()),
                ]),
            );
        }

        // A launch is executed by the side that is running, which is the VLIW
        // one: the array is entered, not entered *from*. An instruction that
        // named only the fabric's mode would be a machine with no way to start.
        if let Some(fabric) = document
            .fabrics
            .iter()
            .find(|fabric| fabric.name == mapping.fabric)
        {
            if let Some((_, packet_name)) = &fabric.vliw_row {
                if let Some(packet) = document
                    .packets
                    .iter()
                    .find(|packet| &packet.name == packet_name)
                {
                    if !instruction.modes.is_empty()
                        && !packet.mode.is_empty()
                        && !instruction.modes.iter().any(|mode| mode == &packet.mode)
                    {
                        return Err(ValidationError::new(format!(
                            "instruction `{}` launches mapping `{}` onto fabric `{}`, but is \
                             legal only in {}; the array is entered from `{}`'s mode `{}`, so \
                             a launch outside it could never issue",
                            instruction.mnemonic,
                            mapping.name,
                            fabric.name,
                            instruction.modes.join(", "),
                            packet.name,
                            packet.mode
                        )));
                    }
                }
            }
        }

        // The composition, against what the instruction says it computes.
        let composed = compose_mapping_op(
            document,
            mapping,
            &mapping.live_out[0].op,
            &source_for_register,
            0,
        )?;
        let width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .unwrap_or(32);
        let declared = launch_semantics(instruction)?;
        // A register read is a leaf the pure IR has no node for, so both sides
        // put a symbol where the read is; what is compared is the arithmetic
        // around them, which is what two sides disagree about when they
        // disagree.
        let (composed, _) = crate::effects::rewrite_register_reads(&composed);
        let (declared, _) = crate::effects::rewrite_register_reads(&declared);
        // Compared as lowered IR rather than as text: the two are written by
        // different hands and `(add i32 a b)` should not differ from itself
        // over spacing or a normalised operator spelling.
        let composed_ir = crate::ir::lower(&composed, width).map_err(|err| {
            ValidationError::new(format!(
                "instruction `{}` runs mapping `{}`, whose composition does not lower: {}",
                instruction.mnemonic, mapping.name, err.message
            ))
        })?;
        let declared_ir = crate::ir::lower(&declared, width).map_err(|err| {
            ValidationError::new(format!(
                "instruction `{}` runs a mapping but its own semantics do not lower: {}",
                instruction.mnemonic, err.message
            ))
        })?;
        if composed_ir != declared_ir {
            return Err(ValidationError::new(format!(
                "instruction `{}` says it computes `{}`, but mapping `{}` composes to `{}`; \
                 a launch and its kernel have to agree about the arithmetic",
                instruction.mnemonic,
                instruction.formal_semantics.trim(),
                mapping.name,
                crate::effects::render_semantic_expr(&composed)
            )));
        }
    }
    Ok(())
}

/// What a launch says it computes.
///
/// Usually `formal_semantics`, which is where a pure instruction's value lives.
/// A launch that reads the register file itself is not pure -- the frontend
/// keeps such a behavior as an effect program with no `formal_semantics` -- so
/// its value is the one register write it makes. Anything else has no single
/// expression to compare a kernel against, and says so rather than comparing
/// the first thing it finds.
fn launch_semantics(
    instruction: &crate::ast::Instruction,
) -> Result<crate::semantics::SemanticExpr, ValidationError> {
    if !instruction.formal_semantics.trim().is_empty() {
        return crate::semantics::parse_formal_semantics(&instruction.formal_semantics).map_err(
            |err| {
                ValidationError::new(format!(
                    "instruction `{}` runs a mapping but its own semantics do not parse: {}",
                    instruction.mnemonic, err.message
                ))
            },
        );
    }
    let behavior = instruction.behavior.as_ref().ok_or_else(|| {
        ValidationError::new(format!(
            "instruction `{}` runs a mapping but states no semantics of its own",
            instruction.mnemonic
        ))
    })?;
    match behavior.effects.as_slice() {
        [effect]
            if effect.guard.is_none()
                && matches!(effect.loc, crate::effects::Loc::Reg(_)) =>
        {
            Ok(effect.value.expr.clone())
        }
        _ => Err(ValidationError::new(format!(
            "instruction `{}` runs a mapping, so its behavior must be one unguarded write to \
             its output operand -- a kernel leaves one result and nothing else",
            instruction.mnemonic
        ))),
    }
}

/// `expr` with every free occurrence of `name` replaced by `value`.
fn substitute_operand(
    expr: &crate::semantics::SemanticExpr,
    name: &str,
    value: &crate::semantics::SemanticExpr,
) -> crate::semantics::SemanticExpr {
    use crate::semantics::SemanticExpr;
    match expr {
        SemanticExpr::Atom(atom) if atom == name => value.clone(),
        SemanticExpr::List(items) => SemanticExpr::List(
            items
                .iter()
                .map(|item| substitute_operand(item, name, value))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// The expression one operation of a mapping computes, with its routed inputs
/// replaced by the expressions *their* producers compute and its live-ins by
/// the launching instruction's operands.
///
/// This is what makes a launch checkable rather than merely declared: the
/// composition is derived from the mapping and compared against the semantics
/// the instruction states, so the two cannot drift.
fn compose_mapping_op(
    document: &Document,
    mapping: &crate::ast::Mapping,
    op_id: &str,
    source_for_register: &std::collections::HashMap<u32, crate::semantics::SemanticExpr>,
    depth: usize,
) -> Result<crate::semantics::SemanticExpr, ValidationError> {
    use crate::semantics::SemanticExpr;
    if depth > 64 {
        return Err(ValidationError::new(format!(
            "mapping `{}` composes more than 64 deep, which is a cycle",
            mapping.name
        )));
    }
    let op = mapping.op(op_id).ok_or_else(|| {
        ValidationError::new(format!(
            "mapping `{}` composes `{op_id}`, which it does not place",
            mapping.name
        ))
    })?;
    let instruction = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == op.mnemonic)
        .ok_or_else(|| {
            ValidationError::new(format!(
                "mapping `{}` places `{}`, which no instruction declares",
                mapping.name, op.mnemonic
            ))
        })?;
    let mut expr = crate::semantics::parse_formal_semantics(&instruction.formal_semantics)
        .map_err(|err| {
            ValidationError::new(format!(
                "mapping `{}` composes `{}`, whose semantics do not parse: {}",
                mapping.name, op.mnemonic, err.message
            ))
        })?;
    for operand in instruction.operands.iter().filter(|operand| operand.input) {
        if let Some(route) = mapping
            .routes
            .iter()
            .find(|route| route.to == op.id && route.operand == operand.name)
        {
            let producer =
                compose_mapping_op(document, mapping, &route.from, source_for_register, depth + 1)?;
            expr = substitute_operand(&expr, &operand.name, &producer);
            continue;
        }
        let live = mapping
            .live_in
            .iter()
            .find(|live| live.op == op.id && live.operand == operand.name)
            .ok_or_else(|| {
                ValidationError::new(format!(
                    "mapping `{}` leaves `{}`'s operand `{}` with no source, so what a launch \
                     of it computes is unstated",
                    mapping.name, op.id, operand.name
                ))
            })?;
        let value = match &live.source {
            crate::ast::MappingSource::Constant(value) => {
                SemanticExpr::Atom(value.to_string())
            }
            crate::ast::MappingSource::Register(index) => source_for_register
                .get(index)
                .cloned()
                .ok_or_else(|| {
                    ValidationError::new(format!(
                        "mapping `{}` reads register {index}, which the launching \
                         instruction neither takes in an operand nor reads itself",
                        mapping.name
                    ))
                })?,
        };
        expr = substitute_operand(&expr, &operand.name, &value);
    }
    Ok(expr)
}

fn validate_tiles(document: &Document) -> Result<(), ValidationError> {
    let core_names: HashSet<String> = document
        .cores
        .iter()
        .map(|core| core.name.to_ascii_lowercase())
        .collect();
    let accelerator_names: HashSet<String> = document
        .accelerators
        .iter()
        .map(|accelerator| accelerator.name.to_ascii_lowercase())
        .collect();
    let memory_names: HashSet<String> = document
        .memories
        .iter()
        .map(|memory| memory.name.to_ascii_lowercase())
        .collect();
    let mut tile_names = HashSet::new();

    for tile in &document.tiles {
        require_identifier("tile.name", &tile.name)?;
        if !tile_names.insert(tile.name.to_ascii_lowercase()) {
            return Err(ValidationError::new(format!(
                "duplicate tile `{}`",
                tile.name
            )));
        }
        if !tile.interconnect.trim().is_empty() {
            validate_allowed_value(
                &format!("tile `{}` interconnect", tile.name),
                &tile.interconnect,
                TILE_INTERCONNECTS,
            )?;
        }
        for core in &tile.cores {
            if !core_names.contains(&core.to_ascii_lowercase()) {
                return Err(ValidationError::new(format!(
                    "tile `{}` references unknown core `{}`",
                    tile.name, core
                )));
            }
        }
        for accelerator in &tile.accelerators {
            if !accelerator_names.contains(&accelerator.to_ascii_lowercase()) {
                return Err(ValidationError::new(format!(
                    "tile `{}` references unknown accelerator `{}`",
                    tile.name, accelerator
                )));
            }
        }
        if !memory_names.is_empty() {
            for memory in &tile.memories {
                if !memory_names.contains(&memory.to_ascii_lowercase()) {
                    return Err(ValidationError::new(format!(
                        "tile `{}` references unknown memory `{}`",
                        tile.name, memory
                    )));
                }
            }
        }
    }

    Ok(())
}

fn validate_allowed_value(
    field: &str,
    value: &str,
    allowed: &[&str],
) -> Result<(), ValidationError> {
    let canonical = canonical_value(value);
    if allowed.contains(&canonical.as_str()) {
        return Ok(());
    }
    Err(ValidationError::new(format!(
        "{field} `{value}` must be one of {}",
        allowed.join(", ")
    )))
}

fn canonical_value(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

fn require_non_empty(field: &str, value: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        Err(ValidationError::new(format!("{field} must not be empty")))
    } else {
        Ok(())
    }
}

fn require_identifier(field: &str, value: &str) -> Result<(), ValidationError> {
    require_non_empty(field, value)?;
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return Err(ValidationError::new(format!("{field} must not be empty")));
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return Err(ValidationError::new(format!(
            "{field} `{value}` must start with a letter or underscore"
        )));
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' || ch == '.') {
        return Err(ValidationError::new(format!(
            "{field} `{value}` contains unsupported characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::parser::parse_document;

    use super::*;

    #[test]
    fn rejects_duplicate_decode_keys() {
        let doc = parse_document(
            r#"
extension { name: xpce }
instruction a { mnemonic: A opcode: 0x0b func3: 1 func7: 2 }
instruction b { mnemonic: B opcode: 0x0b func3: 1 func7: 2 }
"#,
        );
        assert!(
            doc.is_err(),
            "single-line blocks are intentionally unsupported"
        );
    }

    #[test]
    fn validates_duplicate_decode_keys_in_multiline_form() {
        let doc = parse_document(
            r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction a
    (mnemonic A)
    (category custom)
    (format R)
    (opcode 11)
    (func3 1)
    (func7 2)
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )

  (definstruction b
    (mnemonic B)
    (category custom)
    (format R)
    (opcode 11)
    (func3 1)
    (func7 2)
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
"#,
        )
        .unwrap();
        assert!(validate_document(&doc)
            .unwrap_err()
            .to_string()
            .contains("overlap in the decode space"));
    }

    #[test]
    fn a_constraint_separates_encodings_that_pin_only_the_bits_deciding_it() {
        // AArch64's shape: shift by immediate requires `immh:immb > 7`, and the
        // modified immediates sit at `immh = 0` with `immb` free. Three free
        // bits are enumerated and every setting is rejected.
        let module = |pinned: u32| {
            format!(
                r#"(axis-module split
              (defformat shift-format
                (fields (fixed 31 7) (immhb 6 0)))
              (defformat modimm-format
                (fields (fixed 31 7) (immh 6 3) (immb 2 0)))
              (definstruction SHIFT
                (format shift-format) (encoding (fixed 1))
                (operands (immhb imm i7 in))
                (requires (> immhb 7)))
              (definstruction MODIMM
                (format modimm-format) (encoding (fixed 1) (immh {pinned}))
                (operands (immb imm i3 in))))"#
            )
        };
        validate_document(&parse_document(&module(0)).unwrap()).unwrap();
        // With `immh = 1` every word MODIMM accepts is one SHIFT accepts too.
        assert!(validate_document(&parse_document(&module(1)).unwrap())
            .unwrap_err()
            .to_string()
            .contains("overlap in the decode space"));
    }

    #[test]
    fn two_rules_over_one_free_field_are_disjoint_when_no_value_meets_both() {
        // Fixed-point SCVTF: singles at `immhb > 31`, halves at `15 < immhb < 32`,
        // one encoding. Neither pins the field; no value satisfies both.
        let module = |half_top: u32| {
            format!(
                r#"(axis-module ranges
              (defformat shift-format
                (fields (fixed 31 7) (immhb 6 0)))
              (definstruction SINGLE
                (format shift-format) (encoding (fixed 1))
                (operands (immhb imm i7 in))
                (requires (> immhb 31)))
              (definstruction HALF
                (format shift-format) (encoding (fixed 1))
                (operands (immhb imm i7 in))
                (requires (and (> immhb 15) (< immhb {half_top})))))"#
            )
        };
        validate_document(&parse_document(&module(32)).unwrap()).unwrap();
        // Let the half range reach 32 and the value 32 satisfies both.
        assert!(validate_document(&parse_document(&module(33)).unwrap())
            .unwrap_err()
            .to_string()
            .contains("overlap in the decode space"));
    }

    #[test]
    fn operand_constraints_can_separate_a_fixed_alias_from_a_broad_encoding() {
        let disjoint = parse_document(
            r#"(axis-module aliases
              (defformat option-format
                (fields (fixed 31 4) (option 3 0)))
              (definstruction BROAD
                (format option-format) (encoding (fixed 1))
                (operands (option imm i4 in))
                (requires (!= option 0)))
              (definstruction ALIAS
                (format option-format) (encoding (fixed 1) (option 0))
                (operands)))"#,
        )
        .unwrap();
        validate_document(&disjoint).unwrap();

        let overlapping = parse_document(
            r#"(axis-module aliases
              (defformat option-format
                (fields (fixed 31 4) (option 3 0)))
              (definstruction BROAD
                (format option-format) (encoding (fixed 1))
                (operands (option imm i4 in))
                (requires (!= option 1)))
              (definstruction ALIAS
                (format option-format) (encoding (fixed 1) (option 0))
                (operands)))"#,
        )
        .unwrap();
        assert!(validate_document(&overlapping)
            .unwrap_err()
            .to_string()
            .contains("overlap in the decode space"));
    }

    const PERSONALITY_PRELUDE: &str = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (defisa rv32_axis
    (base rv32im)
    (word-bits 32)
    (registers "x[32]:i32" "pc:i32")
    (memory-model rvwmo)
    (endianness little)
  )

  (defisa rv32_wide
    (base rv32im)
    (word-bits 32)
    (registers "x[32]:i64" "pc:i64")
    (memory-model rvwmo)
    (endianness little)
  )

  (definstruction a
    (mnemonic A)
    (category custom)
    (format R)
    (opcode 11)
    (func3 1)
    (func7 2)
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
"#;

    /// The fragments are `defpersonality` forms, so the prelude stays open and
    /// the module is closed here.
    fn personality_doc(personalities: &str) -> Result<(), ValidationError> {
        let doc = parse_document(&format!("{PERSONALITY_PRELUDE}{personalities}\n)\n")).unwrap();
        validate_document(&doc)
    }

    #[test]
    fn accepts_well_formed_personalities() {
        personality_doc(
            r#"
  (defpersonality scalar1
    (implements rv32_axis)
    (discipline independent (threads 1))
    (capsule x[32] pc))
  (defpersonality simt8
    (implements rv32_axis)
    (discipline lockstep (lanes 8)))
"#,
        )
        .unwrap();
    }

    #[test]
    fn rejects_unknown_discipline_and_bad_params() {
        assert!(personality_doc(
            r#"
  (defpersonality p
    (implements rv32_axis)
    (discipline warpspeed (lanes 8)))
"#,
        )
        .unwrap_err()
        .to_string()
        .contains("discipline kind"));
        assert!(personality_doc(
            r#"
  (defpersonality p
    (implements rv32_axis)
    (discipline lockstep (threads 8)))
"#,
        )
        .unwrap_err()
        .to_string()
        .contains("requires parameter `lanes`"));
        assert!(personality_doc(
            r#"
  (defpersonality p
    (implements rv32_axis)
    (discipline lockstep (lanes 0)))
"#,
        )
        .unwrap_err()
        .to_string()
        .contains("must be positive"));
    }

    #[test]
    fn rejects_unknown_isa_and_unknown_capsule_group() {
        assert!(personality_doc(
            r#"
  (defpersonality p
    (implements rv64_missing))
"#,
        )
        .unwrap_err()
        .to_string()
        .contains("unknown isa"));
        assert!(personality_doc(
            r#"
  (defpersonality p
    (implements rv32_axis)
    (capsule f[32]))
"#,
        )
        .unwrap_err()
        .to_string()
        .contains("not a register"));
    }

    #[test]
    fn rejects_conflicting_capsule_widths_across_personalities() {
        assert!(personality_doc(
            r#"
  (defpersonality narrow
    (implements rv32_axis)
    (capsule x[32]))
  (defpersonality wide
    (implements rv32_wide)
    (capsule x[32]))
"#,
        )
        .unwrap_err()
        .to_string()
        .contains("incompatible capsules"));
    }
}

/// Every `(call name iR (iP arg) ...)` -- in an instruction's semantics or
/// behavior, or in another function's body -- names a `deffun` and agrees
/// with it: as many arguments, each at its parameter's width, returning its
/// result width. The elaborator writes calls that way; a description that
/// spells one out, or a canonical document read back, is held to it here.
fn validate_function_calls(document: &Document) -> Result<(), ValidationError> {
    use crate::semantics::SemanticExpr;
    fn walk(
        expr: &SemanticExpr,
        functions: &[crate::ast::Function],
        context: &str,
    ) -> Result<(), ValidationError> {
        let SemanticExpr::List(items) = expr else {
            return Ok(());
        };
        if matches!(items.first(), Some(SemanticExpr::Atom(op)) if op == "call") {
            let Some(SemanticExpr::Atom(name)) = items.get(1) else {
                return Err(ValidationError::new(format!("{context}: a `call` names no function")));
            };
            let Some(function) = functions.iter().find(|function| &function.name == name) else {
                return Err(ValidationError::new(format!("{context}: call of undefined function `{name}`")));
            };
            let result = items.get(2).and_then(|atom| match atom {
                SemanticExpr::Atom(text) => crate::ir::type_atom_width(text),
                _ => None,
            });
            let params: Vec<Option<u32>> = items
                .iter()
                .skip(3)
                .map(|arg| match arg {
                    SemanticExpr::List(pair) => match pair.first() {
                        Some(SemanticExpr::Atom(text)) => crate::ir::type_atom_width(text),
                        _ => None,
                    },
                    _ => None,
                })
                .collect();
            let declared: Vec<Option<u32>> = function.params.iter().map(|(_, width)| Some(*width)).collect();
            if result != Some(function.result_width) || params != declared {
                return Err(ValidationError::new(format!(
                    "{context}: call of `{name}` does not match its definition (i{} from {:?})",
                    function.result_width,
                    function.params.iter().map(|(_, width)| *width).collect::<Vec<_>>()
                )));
            }
        }
        items.iter().try_for_each(|item| walk(item, functions, context))
    }
    let parse = |text: &str| crate::semantics::parse_formal_semantics(text).ok();
    for function in &document.functions {
        walk(&function.body, &document.functions, &format!("deffun `{}`", function.name))?;
    }
    for instruction in &document.instructions {
        let context = format!("instruction `{}`", instruction.mnemonic);
        if let Some(expr) = parse(&instruction.formal_semantics) {
            walk(&expr, &document.functions, &context)?;
        }
        if let Some(behavior) = &instruction.behavior {
            for effect in &behavior.effects {
                walk(&effect.value.expr, &document.functions, &context)?;
                if let Some(guard) = &effect.guard {
                    walk(&guard.expr, &document.functions, &context)?;
                }
            }
        }
    }
    Ok(())
}
