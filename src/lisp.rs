//! Span-aware S-expression reader for the Lisp-authored AXIS surface.
//!
//! This module deliberately stops at syntax. Semantic elaboration lives in
//! `ir`, while future document forms (`defisa`, `defformat`, `definstruction`,
//! `defsem`) will elaborate into the existing typed AST.

use std::fmt;

use crate::ast::{
    CoreFrontEnd, CoreLsq, CoreSimt, CoreSimtCache, CoreSimtImplicit, CoreSimtSysread, CoreSimtVector, CoreUnit,
    Abi, Accelerator, AcceleratorPort, AcceleratorResult, Aggregates, Config, ConfigField, Core, Kernel, Descriptor, DescriptorCheck, DescriptorField, Device, DeviceRegister, Discipline, Document, Extension, Format, FormatField,
    Instruction, Isa, Lowering, LoweringBinding, LoweringPredicate, LoweringStep, LoweringValue,
    Fabric, FabricLink, FabricPort, Frame, Mapping, MappingOp, MappingRoute, Memory, Mode, Operand,
    Packet, PacketSlot, Personality, PersonalitySeam, RegisterRef, SpillSlot, Tile,
};

const MAX_FAMILY_EXPANSIONS: usize = 4096;
const MAX_PROPERTY_EXPANSIONS: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub offset: usize,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SExpr {
    pub kind: SExprKind,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SExprKind {
    Atom(String),
    String(String),
    List(Vec<SExpr>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    pub span: Span,
    pub message: String,
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Lisp read error at {}:{}: {}",
            self.span.line, self.span.column, self.message
        )
    }
}

pub fn read_one(source: &str) -> Result<SExpr, ReadError> {
    let mut reader = Reader::new(source);
    reader.skip_trivia();
    if reader.eof() {
        return Err(reader.error("expected an expression"));
    }
    let expression = reader.read_expr()?;
    reader.skip_trivia();
    if !reader.eof() {
        return Err(reader.error("unexpected expression after the first form"));
    }
    Ok(expression)
}

pub fn read_all(source: &str) -> Result<Vec<SExpr>, ReadError> {
    let mut reader = Reader::new(source);
    let mut forms = Vec::new();
    loop {
        reader.skip_trivia();
        if reader.eof() {
            return Ok(forms);
        }
        forms.push(reader.read_expr()?);
    }
}

#[derive(Debug, Clone)]
struct SemanticDefinition {
    name: String,
    params: Vec<(String, u32)>,
    result_width: u32,
    body: SExpr,
    span: Span,
    /// A `deffun`: emitted once by every backend and called, where a
    /// `defsem` is substituted at each use.
    called: bool,
}

#[derive(Debug, Clone)]
struct ModuleError {
    span: Span,
    message: String,
}

impl From<ReadError> for ModuleError {
    fn from(error: ReadError) -> Self {
        Self {
            span: error.span,
            message: error.message,
        }
    }
}

pub fn parse_document(source: &str) -> Result<Document, crate::parser::ParseError> {
    let mut document = elaborate_document(source).map_err(|error| {
        crate::parser::ParseError::new(
            error.span.line,
            format!(
                "Lisp module error at column {}: {}",
                error.span.column, error.message
            ),
        )
    })?;
    // A core's `(latency derived)` is a number once the netlists exist; every
    // reader after this one sees the number.
    crate::timing::resolve_derived(&mut document);
    Ok(document)
}

fn elaborate_document(source: &str) -> Result<Document, ModuleError> {
    let root = read_one(source)?;
    let forms = list(&root, "axis module")?;
    if atom(forms.first(), "axis module head")? != "axis-module" {
        return Err(module_error(
            root.span,
            "module must start with `axis-module`",
        ));
    }
    let name = atom(forms.get(1), "axis-module name")?.to_string();
    let mut document = Document {
        extension: Extension {
            name,
            ..Extension::default()
        },
        ..Document::default()
    };
    let mut definitions = Vec::new();
    let mut instruction_forms = Vec::new();
    let mut kernel_forms: Vec<SExpr> = Vec::new();
    let mut device_spans: Vec<Span> = Vec::new();
    let mut lowering_forms = Vec::new();
    let mut accelerator_forms = Vec::new();
    let mut family_expansions = 0usize;
    let mut family_names = std::collections::HashSet::new();
    let property_fragments = collect_property_fragments(&forms[2..])?;
    let mut property_expansions = 0usize;

    for raw_form in &forms[2..] {
        let raw_items = list(raw_form, "module form")?;
        if atom(raw_items.first(), "module form head")? == "defproperties" {
            continue;
        }
        let form = expand_property_uses(
            raw_form,
            &property_fragments,
            &mut Vec::new(),
            &mut property_expansions,
        )?;
        let items = list(&form, "module form")?;
        let head = atom(items.first(), "module form head")?;
        match head {
            "version" => document.extension.version = scalar(items, form.span, "version")?,
            "target" => document.extension.target = scalar(items, form.span, "target")?,
            "description" => {
                document.extension.description = scalar(items, form.span, "description")?
            }
            "defisa" => document.isas.push(elaborate_isa(&form)?),
            "defmode" => document.modes.push(elaborate_mode(&form)?),
            "defconfig" => document.configs.push(elaborate_config(&form)?),
            "defkernel" => {
                document.kernels.push(elaborate_kernel(&form)?);
                kernel_forms.push(form.clone());
            }
            "defdescriptor" => document.descriptors.push(elaborate_descriptor(&form)?),
            "defdevice" => {
                document.devices.push(elaborate_device(&form)?);
                device_spans.push(form.span);
            }
            "defpacket" => document.packets.push(elaborate_packet(&form)?),
            "defpersonality" => document.personalities.push(elaborate_personality(&form)?),
            "defcore" => document.cores.push(elaborate_core(&form)?),
            "defmemory" => document.memories.push(elaborate_memory(&form)?),
            "definterconnect" => document.interconnects.push(
                crate::memsys::elaborate_interconnect(&form).map_err(|(span, m)| module_error(span, m))?,
            ),
            "defmemsys" => document.memsystems.push(
                crate::memsys::elaborate_memsys(&form).map_err(|(span, m)| module_error(span, m))?,
            ),
            "deftile" => document.tiles.push(elaborate_tile(&form)?),
            "deffabric" => document.fabrics.push(elaborate_fabric(&form)?),
            "defmapping" => document.mappings.push(elaborate_mapping(&form)?),
            "defchannel" => document.channels.push(elaborate_channel(&form)?),
            "defabi" => document.abis.push(elaborate_abi(&form)?),
            "defaccelerator" => accelerator_forms.push(form.clone()),
            "defformat" => document.formats.push(elaborate_format(&form)?),
            "defsem" => definitions.push(parse_definition(&form)?),
            "deffun" => definitions.push(parse_definition(&form)?),
            "definstruction" => instruction_forms.push(form.clone()),
            "deflowering" => lowering_forms.push(form.clone()),
            "definstruction-family" => {
                let family_name = atom(items.get(1), "instruction family name")?;
                if !family_names.insert(family_name.to_string()) {
                    return Err(module_error(
                        form.span,
                        format!("duplicate instruction family `{family_name}`"),
                    ));
                }
                let expanded = expand_instruction_family(&form)?;
                family_expansions += expanded.len();
                if family_expansions > MAX_FAMILY_EXPANSIONS {
                    return Err(module_error(
                        form.span,
                        format!(
                            "instruction families expand to {family_expansions} instructions; maximum is {MAX_FAMILY_EXPANSIONS}"
                        ),
                    ));
                }
                instruction_forms.extend(expanded);
            }
            other => {
                return Err(module_error(
                    form.span,
                    format!("unsupported axis-module form `{other}`"),
                ));
            }
        }
    }

    let library = SemanticLibrary::new(definitions)?;
    document.functions = library.functions()?;
    // Kernels are resolved after every form is read, so a launch may name a
    // kernel defined further down the file -- the same forward reference
    // `defproperties` allows, for the same reason.
    let mut kernels = std::collections::HashMap::new();
    for form in &kernel_forms {
        let items = list(form, "defkernel")?;
        let name = atom(items.get(1), "defkernel name")?.to_string();
        if kernels.insert(name.clone(), form.clone()).is_some() {
            return Err(module_error(form.span, format!("duplicate kernel `{name}`")));
        }
    }
    let mut descriptors = std::collections::HashMap::new();
    for descriptor in &document.descriptors {
        if descriptors.insert(descriptor.name.clone(), descriptor.clone()).is_some() {
            return Err(module_error(
                forms[0].span,
                format!("duplicate descriptor `{}`", descriptor.name),
            ));
        }
    }
    for form in &instruction_forms {
        document
            .instructions
            .push(elaborate_instruction(form, &library, &kernels, &descriptors)?);
    }
    for (device, span) in document.devices.iter().zip(&device_spans) {
        check_device_handlers(device, &document.instructions, *span)?;
    }
    for form in &lowering_forms {
        document.lowerings.push(elaborate_lowering(form)?);
    }
    for form in &accelerator_forms {
        let mut accelerator = elaborate_accelerator(form, &library)?;
        // An accelerator whose schema names a declared descriptor IS that
        // descriptor's engine: the two must agree on its size, and a size the
        // accelerator left unstated is the declaration's. AHA's loader reads
        // the count; the declaration is what makes it a fact.
        if let Some(descriptor) = descriptors.get(&accelerator.descriptor_schema) {
            accelerator.descriptor = Some(descriptor.clone());
            if accelerator.descriptor_bytes == 0 {
                accelerator.descriptor_bytes = descriptor.bytes;
            } else if accelerator.descriptor_bytes != descriptor.bytes {
                return Err(module_error(
                    form.span,
                    format!(
                        "accelerator `{}` says its `{}` descriptor is {} bytes; the declaration says {}",
                        accelerator.name, descriptor.name, accelerator.descriptor_bytes, descriptor.bytes
                    ),
                ));
            }
        }
        document.accelerators.push(accelerator);
    }
    Ok(document)
}

fn elaborate_lowering(form: &SExpr) -> Result<Lowering, ModuleError> {
    let items = list(form, "deflowering")?;
    let name = atom(items.get(1), "deflowering name")?.to_string();
    let mut sources = Vec::new();
    let mut target = None;
    let mut requires = None;
    let mut source_cycles = 0;
    let mut target_cycles = 0;
    let mut benefit = "1.0".to_string();
    let mut seen = std::collections::HashSet::new();

    for property in &items[2..] {
        let values = list(property, "deflowering property")?;
        let property_name = atom(values.first(), "deflowering property name")?;
        if !seen.insert(property_name.to_string()) {
            return Err(module_error(
                property.span,
                format!("duplicate deflowering property `{property_name}`"),
            ));
        }
        match property_name {
            "source" => {
                if values.len() < 2 {
                    return Err(module_error(
                        property.span,
                        "lowering source requires at least one instruction step",
                    ));
                }
                sources = values[1..]
                    .iter()
                    .map(elaborate_lowering_step)
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "target" => {
                if values.len() != 2 {
                    return Err(module_error(
                        property.span,
                        "lowering target requires exactly one instruction step",
                    ));
                }
                target = Some(elaborate_lowering_step(&values[1])?);
            }
            "requires" => {
                if values.len() != 2 {
                    return Err(module_error(
                        property.span,
                        "lowering requires expects one predicate",
                    ));
                }
                requires = Some(elaborate_lowering_predicate(&values[1])?);
            }
            "source-cycles" => {
                source_cycles = numeric_property(values, property.span, property_name)?;
            }
            "target-cycles" => {
                target_cycles = numeric_property(values, property.span, property_name)?;
            }
            "benefit" => benefit = scalar(values, property.span, property_name)?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported deflowering property `{other}`"),
                ));
            }
        }
    }
    Ok(Lowering {
        name,
        sources,
        target: target
            .ok_or_else(|| module_error(form.span, "deflowering requires a target step"))?,
        requires,
        source_cycles,
        target_cycles,
        benefit,
    })
}

fn elaborate_lowering_step(form: &SExpr) -> Result<LoweringStep, ModuleError> {
    let items = list(form, "lowering instruction step")?;
    let instruction = atom(items.first(), "lowering instruction mnemonic")?.to_string();
    let bindings = items[1..]
        .iter()
        .map(|binding| {
            let pair = list(binding, "lowering operand binding")?;
            if pair.len() != 2 {
                return Err(module_error(
                    binding.span,
                    "lowering binding must be `(operand $variable|literal)`",
                ));
            }
            Ok(LoweringBinding {
                operand: atom(pair.first(), "lowering operand name")?.to_string(),
                value: elaborate_lowering_value(&pair[1])?,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(LoweringStep {
        instruction,
        bindings,
    })
}

fn elaborate_lowering_value(form: &SExpr) -> Result<LoweringValue, ModuleError> {
    let value = atom(Some(form), "lowering value")?;
    if let Some(variable) = value.strip_prefix('$') {
        if variable.is_empty() {
            return Err(module_error(
                form.span,
                "lowering variable name cannot be empty",
            ));
        }
        return Ok(LoweringValue::Variable(variable.to_string()));
    }
    number(form, "lowering literal").map(LoweringValue::Literal)
}

fn elaborate_lowering_predicate(form: &SExpr) -> Result<LoweringPredicate, ModuleError> {
    let items = list(form, "lowering predicate")?;
    let operator = atom(items.first(), "lowering predicate operator")?;
    match operator {
        "and" | "or" => {
            if items.len() < 2 {
                return Err(module_error(
                    form.span,
                    format!("lowering `{operator}` requires at least one predicate"),
                ));
            }
            let children = items[1..]
                .iter()
                .map(elaborate_lowering_predicate)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(if operator == "and" {
                LoweringPredicate::And(children)
            } else {
                LoweringPredicate::Or(children)
            })
        }
        "not" => {
            if items.len() != 2 {
                return Err(module_error(
                    form.span,
                    "lowering `not` requires one predicate",
                ));
            }
            Ok(LoweringPredicate::Not(Box::new(
                elaborate_lowering_predicate(&items[1])?,
            )))
        }
        "=" | "eq" | "!=" | "ne" | "<" | "<=" | ">" | ">=" => {
            if items.len() != 3 {
                return Err(module_error(
                    form.span,
                    "lowering comparison requires two values",
                ));
            }
            let op = match operator {
                "=" | "eq" => crate::decode_constraint::CompareOp::Eq,
                "!=" | "ne" => crate::decode_constraint::CompareOp::Ne,
                "<" => crate::decode_constraint::CompareOp::Lt,
                "<=" => crate::decode_constraint::CompareOp::Le,
                ">" => crate::decode_constraint::CompareOp::Gt,
                ">=" => crate::decode_constraint::CompareOp::Ge,
                _ => unreachable!(),
            };
            Ok(LoweringPredicate::Compare {
                lhs: elaborate_lowering_value(&items[1])?,
                op,
                rhs: elaborate_lowering_value(&items[2])?,
            })
        }
        other => Err(module_error(
            form.span,
            format!("unsupported lowering predicate `{other}`"),
        )),
    }
}

fn collect_property_fragments(
    forms: &[SExpr],
) -> Result<std::collections::HashMap<String, Vec<SExpr>>, ModuleError> {
    let mut fragments = std::collections::HashMap::new();
    for form in forms {
        let items = list(form, "module form")?;
        if atom(items.first(), "module form head")? != "defproperties" {
            continue;
        }
        let name = atom(items.get(1), "defproperties name")?.to_string();
        if items.len() < 3 {
            return Err(module_error(
                form.span,
                format!("property fragment `{name}` must contain at least one property"),
            ));
        }
        if fragments
            .insert(name.clone(), items[2..].to_vec())
            .is_some()
        {
            return Err(module_error(
                form.span,
                format!("duplicate property fragment `{name}`"),
            ));
        }
    }
    Ok(fragments)
}

fn expand_property_uses(
    expression: &SExpr,
    fragments: &std::collections::HashMap<String, Vec<SExpr>>,
    stack: &mut Vec<String>,
    expansions: &mut usize,
) -> Result<SExpr, ModuleError> {
    let SExprKind::List(items) = &expression.kind else {
        return Ok(expression.clone());
    };
    let mut expanded = Vec::new();
    for item in items {
        splice_property_item(item, fragments, stack, expansions, &mut expanded)?;
    }
    Ok(SExpr {
        kind: SExprKind::List(expanded),
        span: expression.span,
    })
}

fn splice_property_item(
    item: &SExpr,
    fragments: &std::collections::HashMap<String, Vec<SExpr>>,
    stack: &mut Vec<String>,
    expansions: &mut usize,
    output: &mut Vec<SExpr>,
) -> Result<(), ModuleError> {
    let use_items = match &item.kind {
        SExprKind::List(items) if matches!(items.first(), Some(SExpr { kind: SExprKind::Atom(head), .. }) if head == "use-properties") => {
            Some(items.as_slice())
        }
        _ => None,
    };
    let Some(use_items) = use_items else {
        output.push(expand_property_uses(item, fragments, stack, expansions)?);
        return Ok(());
    };
    if use_items.len() != 2 {
        return Err(module_error(
            item.span,
            "use-properties expects exactly one fragment name",
        ));
    }
    let name = atom(use_items.get(1), "property fragment name")?;
    let properties = fragments
        .get(name)
        .ok_or_else(|| module_error(item.span, format!("unknown property fragment `{name}`")))?;
    if let Some(start) = stack.iter().position(|active| active == name) {
        let mut cycle = stack[start..].to_vec();
        cycle.push(name.to_string());
        return Err(module_error(
            item.span,
            format!("property fragment cycle: {}", cycle.join(" -> ")),
        ));
    }
    stack.push(name.to_string());
    for property in properties {
        *expansions += 1;
        if *expansions > MAX_PROPERTY_EXPANSIONS {
            return Err(module_error(
                item.span,
                format!(
                    "property fragments expand to more than {MAX_PROPERTY_EXPANSIONS} properties"
                ),
            ));
        }
        splice_property_item(property, fragments, stack, expansions, output)?;
    }
    stack.pop();
    Ok(())
}

/// Expand a finite instruction family:
///
/// `(definstruction-family name ($parameter ...)
///    ((literal ...) ...)
///    (definstruction $name ...))`
///
/// `$`-prefixed parameters make every substitution site explicit. Rows are
/// literal syntax, expansion has no evaluation or recursion, and the module
/// cap keeps the elaborator total even for machine-generated sources.
fn expand_instruction_family(form: &SExpr) -> Result<Vec<SExpr>, ModuleError> {
    let items = list(form, "definstruction-family")?;
    if items.len() != 5 {
        return Err(module_error(
            form.span,
            "definstruction-family must be `(definstruction-family name ($parameter ...) ((literal ...) ...) (definstruction ...))`",
        ));
    }
    let family_name = atom(items.get(1), "instruction family name")?;
    let raw_parameters = list(&items[2], "instruction family parameters")?;
    if raw_parameters.is_empty() {
        return Err(module_error(
            items[2].span,
            format!("instruction family `{family_name}` requires parameters"),
        ));
    }
    let mut parameters = Vec::new();
    let mut parameter_names = std::collections::HashSet::new();
    for parameter in raw_parameters {
        let name = atom(Some(parameter), "instruction family parameter")?;
        if !name.starts_with('$') || name.len() == 1 {
            return Err(module_error(
                parameter.span,
                format!("instruction family parameter `{name}` must start with `$`"),
            ));
        }
        if !parameter_names.insert(name.to_string()) {
            return Err(module_error(
                parameter.span,
                format!("duplicate instruction family parameter `{name}`"),
            ));
        }
        parameters.push(name.to_string());
    }

    let rows = list(&items[3], "instruction family rows")?;
    if rows.is_empty() {
        return Err(module_error(
            items[3].span,
            format!("instruction family `{family_name}` requires at least one row"),
        ));
    }
    if rows.len() > MAX_FAMILY_EXPANSIONS {
        return Err(module_error(
            items[3].span,
            format!(
                "instruction family `{family_name}` has {} rows; maximum is {MAX_FAMILY_EXPANSIONS}",
                rows.len()
            ),
        ));
    }

    let template = &items[4];
    let template_items = list(template, "instruction family template")?;
    if atom(template_items.first(), "instruction family template head")? != "definstruction" {
        return Err(module_error(
            template.span,
            "instruction family template must be one `definstruction` form",
        ));
    }
    for parameter in &parameters {
        if !mentions_atom(template, parameter) {
            return Err(module_error(
                items[2].span,
                format!("instruction family `{family_name}` parameter `{parameter}` is unused"),
            ));
        }
    }

    let mut expanded = Vec::with_capacity(rows.len());
    let mut instruction_names = std::collections::HashSet::new();
    for (row_index, row) in rows.iter().enumerate() {
        let values = list(row, "instruction family row")?;
        if values.len() != parameters.len() {
            return Err(module_error(
                row.span,
                format!(
                    "instruction family `{family_name}` row {} has {} values, expected {}",
                    row_index + 1,
                    values.len(),
                    parameters.len()
                ),
            ));
        }
        let substitutions = parameters
            .iter()
            .cloned()
            .zip(values.iter().cloned())
            .collect();
        let instruction = substitute(template, &substitutions);
        let instruction_items = list(&instruction, "expanded instruction")?;
        let instruction_name =
            atom(instruction_items.get(1), "expanded instruction name")?.to_string();
        if !instruction_names.insert(instruction_name.clone()) {
            return Err(module_error(
                row.span,
                format!(
                    "instruction family `{family_name}` expands duplicate instruction `{instruction_name}`"
                ),
            ));
        }
        expanded.push(instruction);
    }
    Ok(expanded)
}

fn mentions_atom(expression: &SExpr, expected: &str) -> bool {
    match &expression.kind {
        SExprKind::Atom(value) => value == expected,
        SExprKind::String(_) => false,
        SExprKind::List(items) => items.iter().any(|item| mentions_atom(item, expected)),
    }
}

struct SemanticLibrary {
    definitions: std::collections::HashMap<String, SemanticDefinition>,
}

impl SemanticLibrary {
    fn new(definitions: Vec<SemanticDefinition>) -> Result<Self, ModuleError> {
        let mut by_name = std::collections::HashMap::new();
        for definition in definitions {
            if is_reserved_semantic_name(&definition.name) {
                return Err(module_error(
                    definition.span,
                    format!(
                        "defsem `{}` conflicts with a built-in semantic form",
                        definition.name
                    ),
                ));
            }
            if by_name.contains_key(&definition.name) {
                return Err(module_error(
                    definition.span,
                    format!("duplicate defsem `{}`", definition.name),
                ));
            }
            by_name.insert(definition.name.clone(), definition);
        }
        let library = Self {
            definitions: by_name,
        };
        library.reject_recursive_definitions()?;
        library.validate_definitions()?;
        Ok(library)
    }

    fn expand(&self, expression: &SExpr) -> Result<SExpr, ModuleError> {
        self.expand_with_stack(expression, &mut Vec::new())
    }

    fn expand_typed(
        &self,
        expression: &SExpr,
        symbols: &std::collections::HashMap<String, u32>,
        expected_width: u32,
    ) -> Result<SExpr, ModuleError> {
        let actual = self.infer_width(expression, symbols, expected_width)?;
        if actual != expected_width {
            return Err(module_error(
                expression.span,
                format!(
                    "semantic expression returns i{actual}, expected instruction result i{expected_width}"
                ),
            ));
        }
        self.expand(expression)
    }

    fn infer_width(
        &self,
        expression: &SExpr,
        symbols: &std::collections::HashMap<String, u32>,
        ambient_width: u32,
    ) -> Result<u32, ModuleError> {
        match &expression.kind {
            SExprKind::Atom(name) => Ok(symbols.get(name).copied().unwrap_or(ambient_width)),
            SExprKind::String(_) => Err(module_error(
                expression.span,
                "strings are not semantic values",
            )),
            SExprKind::List(items) => {
                let head = atom(items.first(), "semantic call head")?;
                if head == "let" {
                    if items.len() != 3 {
                        return Err(module_error(
                            expression.span,
                            "let expects bindings and one body",
                        ));
                    }
                    let raw_bindings = list(&items[1], "let bindings")?;
                    // ⚠️ SEQUENTIAL. Each binding is elaborated against the
                    // scope the ones before it built, so a `let` reads as a
                    // block of named steps -- which is how a lane-wise
                    // saturate or a variable shift has to be written to be
                    // readable at all. Bindings could not refer to each other
                    // before, so every description that parsed still parses:
                    // this only admits ones that did not.
                    let mut body_symbols = symbols.clone();
                    let mut inferred = Vec::new();
                    for binding in raw_bindings {
                        let pair = list(binding, "let binding")?;
                        if pair.len() != 2 {
                            return Err(module_error(
                                binding.span,
                                "let binding must be `(name expression)`",
                            ));
                        }
                        let name = atom(pair.first(), "let binding name")?.to_string();
                        let width = self.infer_width(&pair[1], &body_symbols, ambient_width)?;
                        body_symbols.insert(name.clone(), width);
                        inferred.push((name, width));
                    }
                    return self.infer_width(&items[2], &body_symbols, ambient_width);
                }
                if head == "call" {
                    // An elaborated call -- `(call name iR (iP arg) ...)` -- as
                    // `emit-lisp` writes it back: its result type is stated.
                    if let Some(SExpr { kind: SExprKind::Atom(type_atom), span }) = items.get(2) {
                        return type_width(type_atom, *span);
                    }
                }
                if let Some(definition) = self.definitions.get(head) {
                    let args = &items[1..];
                    if args.len() != definition.params.len() {
                        return Err(module_error(
                            expression.span,
                            format!(
                                "defsem `{head}` expects {} arguments, got {}",
                                definition.params.len(),
                                args.len()
                            ),
                        ));
                    }
                    for (arg, (param, expected)) in args.iter().zip(&definition.params) {
                        let actual = self.infer_width(arg, symbols, *expected)?;
                        if actual != *expected {
                            return Err(module_error(
                                arg.span,
                                format!(
                                    "defsem `{head}` argument `{param}` expects i{expected}, got i{actual}"
                                ),
                            ));
                        }
                    }
                    return Ok(definition.result_width);
                }
                if let Some(SExpr {
                    kind: SExprKind::Atom(type_atom),
                    span,
                }) = items.get(1)
                {
                    if type_atom.starts_with(['i', 'u']) {
                        return type_width(type_atom, *span);
                    }
                }
                Ok(ambient_width)
            }
        }
    }

    fn expand_with_stack(
        &self,
        expression: &SExpr,
        stack: &mut Vec<String>,
    ) -> Result<SExpr, ModuleError> {
        let SExprKind::List(items) = &expression.kind else {
            return Ok(expression.clone());
        };
        let Some(SExpr {
            kind: SExprKind::Atom(head),
            ..
        }) = items.first()
        else {
            // A list headed by a list is a binding list -- `let`'s, `vmap`'s --
            // and its values are expressions like any other. Returned as it
            // stood, a defsem call in a binding was never inlined: nothing had
            // put one there until a scalable FMAXV nested one `vmap` in
            // another's binding.
            return Ok(SExpr {
                kind: SExprKind::List(
                    items
                        .iter()
                        .map(|item| self.expand_with_stack(item, stack))
                        .collect::<Result<Vec<_>, _>>()?,
                ),
                span: expression.span,
            });
        };
        if let Some(definition) = self.definitions.get(head) {
            let args = &items[1..];
            if args.len() != definition.params.len() {
                return Err(module_error(
                    expression.span,
                    format!(
                        "defsem `{head}` expects {} arguments, got {}",
                        definition.params.len(),
                        args.len()
                    ),
                ));
            }
            if stack.iter().any(|name| name == head) {
                return Err(module_error(
                    expression.span,
                    format!("recursive defsem call involving `{head}`"),
                ));
            }
            let expanded_args = args
                .iter()
                .map(|arg| self.expand_with_stack(arg, stack))
                .collect::<Result<Vec<_>, _>>()?;
            if definition.called {
                // Not substituted: `(call name iR (iP arg) ...)`, each argument
                // with the width its parameter reads it at, so a backend can
                // evaluate it without the definition in hand.
                let span = expression.span;
                let atom_at = |text: String| SExpr { kind: SExprKind::Atom(text), span };
                let mut call = vec![
                    atom_at("call".to_string()),
                    atom_at(head.clone()),
                    atom_at(format!("i{}", definition.result_width)),
                ];
                for (arg, (_, width)) in expanded_args.into_iter().zip(&definition.params) {
                    call.push(SExpr {
                        kind: SExprKind::List(vec![atom_at(format!("i{width}")), arg]),
                        span,
                    });
                }
                return Ok(SExpr { kind: SExprKind::List(call), span });
            }
            let substitutions = definition
                .params
                .iter()
                .zip(expanded_args)
                .map(|((name, _), value)| (name.clone(), value))
                .collect();
            let substituted = substitute(&definition.body, &substitutions);
            stack.push(head.clone());
            let expanded = self.expand_with_stack(&substituted, stack);
            stack.pop();
            return expanded;
        }
        Ok(SExpr {
            kind: SExprKind::List(
                items
                    .iter()
                    .map(|item| self.expand_with_stack(item, stack))
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            span: expression.span,
        })
    }

    fn reject_recursive_definitions(&self) -> Result<(), ModuleError> {
        fn visit(
            name: &str,
            library: &SemanticLibrary,
            visiting: &mut Vec<String>,
            complete: &mut std::collections::HashSet<String>,
        ) -> Result<(), ModuleError> {
            if complete.contains(name) {
                return Ok(());
            }
            if let Some(start) = visiting.iter().position(|item| item == name) {
                let mut cycle = visiting[start..].to_vec();
                cycle.push(name.to_string());
                let definition = &library.definitions[name];
                return Err(module_error(
                    definition.span,
                    format!("recursive defsem cycle: {}", cycle.join(" -> ")),
                ));
            }
            visiting.push(name.to_string());
            let definition = &library.definitions[name];
            let mut calls = Vec::new();
            collect_definition_calls(&definition.body, &library.definitions, &mut calls);
            for call in calls {
                visit(&call, library, visiting, complete)?;
            }
            visiting.pop();
            complete.insert(name.to_string());
            Ok(())
        }

        let mut complete = std::collections::HashSet::new();
        for name in self.definitions.keys() {
            visit(name, self, &mut Vec::new(), &mut complete)?;
        }
        Ok(())
    }

    /// The `deffun`s, bodies elaborated -- `defsem`s inlined, calls to other
    /// functions left as calls -- in a stable order.
    fn functions(&self) -> Result<Vec<crate::ast::Function>, ModuleError> {
        let mut out = Vec::new();
        for definition in self.definitions.values().filter(|definition| definition.called) {
            let source = render(&self.expand(&definition.body)?);
            let body = crate::semantics::parse_formal_semantics(&source).map_err(|error| {
                module_error(definition.span, format!("invalid deffun `{}`: {error}", definition.name))
            })?;
            out.push(crate::ast::Function {
                name: definition.name.clone(),
                params: definition.params.clone(),
                result_width: definition.result_width,
                body,
            });
        }
        // Callees first, then by name: SMT-LIB and the executors' tables define
        // a function before any function that calls it. Recursion was already
        // refused, so this terminates.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        let mut ordered: Vec<crate::ast::Function> = Vec::new();
        while !out.is_empty() {
            let ready = out
                .iter()
                .position(|function| {
                    let text = crate::effects::render_semexpr(&function.body);
                    out.iter().all(|other| {
                        other.name == function.name
                            || !text.contains(&format!("(call {} ", other.name))
                    })
                })
                .unwrap_or(0);
            ordered.push(out.remove(ready));
        }
        Ok(ordered)
    }

    fn validate_definitions(&self) -> Result<(), ModuleError> {
        for definition in self.definitions.values() {
            let symbol_widths = definition.params.iter().cloned().collect();
            let actual =
                self.infer_width(&definition.body, &symbol_widths, definition.result_width)?;
            if actual != definition.result_width {
                return Err(module_error(
                    definition.span,
                    format!(
                        "defsem `{}` returns i{actual}, declared i{}",
                        definition.name, definition.result_width
                    ),
                ));
            }
            let expanded = self.expand(&definition.body)?;
            let source = render(&expanded);
            let symbols = definition
                .params
                .iter()
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            let expression =
                crate::semantics::parse_formal_semantics(&source).map_err(|error| {
                    module_error(
                        definition.span,
                        format!("invalid defsem `{}`: {error}", definition.name),
                    )
                })?;
            let semantic =
                crate::ir::lower(&expression, definition.result_width).map_err(|error| {
                    module_error(
                        definition.span,
                        format!("invalid defsem `{}`: {error}", definition.name),
                    )
                })?;
            crate::ir::check_symbols(&semantic, &symbols).map_err(|error| {
                module_error(
                    definition.span,
                    format!("invalid defsem `{}`: {error}", definition.name),
                )
            })?;
        }
        Ok(())
    }
}

fn parse_definition(form: &SExpr) -> Result<SemanticDefinition, ModuleError> {
    let items = list(form, "defsem")?;
    let called = matches!(atom(items.first(), "definition head")?, "deffun");
    let head = if called { "deffun" } else { "defsem" };
    if items.len() != 5 {
        return Err(module_error(
            form.span,
            format!("{head} must be `({head} name ((param type) ...) result-type body)`"),
        ));
    }
    let name = atom(items.get(1), "defsem name")?.to_string();
    let raw_params = list(&items[2], "defsem parameter list")?;
    let mut params = Vec::new();
    let mut names = std::collections::HashSet::new();
    for raw_param in raw_params {
        let pair = list(raw_param, "defsem parameter")?;
        if pair.len() != 2 {
            return Err(module_error(
                raw_param.span,
                "defsem parameter must be `(name type)`",
            ));
        }
        let param_name = atom(pair.first(), "defsem parameter name")?.to_string();
        if !names.insert(param_name.clone()) {
            return Err(module_error(
                raw_param.span,
                format!("duplicate defsem parameter `{param_name}`"),
            ));
        }
        let width = type_width(atom(pair.get(1), "defsem parameter type")?, raw_param.span)?;
        params.push((param_name, width));
    }
    let result_width = type_width(atom(items.get(3), "defsem result type")?, items[3].span)?;
    Ok(SemanticDefinition {
        name,
        params,
        result_width,
        body: items[4].clone(),
        span: form.span,
        called,
    })
}

fn elaborate_isa(form: &SExpr) -> Result<Isa, ModuleError> {
    let items = list(form, "defisa")?;
    let mut isa = Isa {
        name: atom(items.get(1), "defisa name")?.to_string(),
        ..Isa::default()
    };
    for property in &items[2..] {
        let values = list(property, "defisa property")?;
        match atom(values.first(), "defisa property name")? {
            "role" => isa.role = scalar(values, property.span, "role")?,
            "base" => isa.base = scalar(values, property.span, "base")?,
            "word-bits" => isa.word_bits = numeric_property(values, property.span, "word-bits")?,
            "registers" => isa.registers = scalar_list(&values[1..])?,
            "features" => isa.features = scalar_list(&values[1..])?,
            "memory-model" => isa.memory_model = scalar(values, property.span, "memory-model")?,
            "vector-bits" => isa.vector_bits = numeric_property(values, property.span, "vector-bits")?,
            "lanes" => isa.lanes = numeric_property(values, property.span, "lanes")?,
            "vector-sew" => isa.vector_sew = numeric_property(values, property.span, "vector-sew")?,
            "vector-elen" => isa.vector_elen = numeric_property(values, property.span, "vector-elen")?,
            "vector-lmul" => {
                // LMUL is a rational: `2` and `1/8` are both configurations a
                // machine can be in, and an integer could not say the second.
                let text = scalar(values, property.span, "vector-lmul")?;
                let (num, den) = match text.split_once('/') {
                    Some((num, den)) => (num, den),
                    None => (text.as_str(), "1"),
                };
                let parsed = num.parse::<u32>().ok().zip(den.parse::<u32>().ok());
                let Some((num, den)) = parsed.filter(|(_, den)| *den != 0) else {
                    return Err(module_error(
                        property.span,
                        format!("`{text}` is not a vector-lmul: expected N or N/D"),
                    ));
                };
                isa.vector_lmul_num = num;
                isa.vector_lmul_den = den;
            }
            "unspecified-realization" => {
                isa.unspecified_realization =
                    scalar(values, property.span, "unspecified-realization")?;
                if crate::scalable::Realization::parse(&isa.unspecified_realization).is_none() {
                    return Err(module_error(
                        property.span,
                        format!(
                            "unknown unspecified-realization `{}`; expected compute, ones or zeros",
                            isa.unspecified_realization
                        ),
                    ));
                }
            }
            "reduction-realization" => {
                isa.reduction_realization =
                    scalar(values, property.span, "reduction-realization")?;
                if crate::scalable::ReductionOrder::parse(&isa.reduction_realization).is_none() {
                    return Err(module_error(
                        property.span,
                        format!(
                            "unknown reduction-realization `{}`; expected sequential or pairwise",
                            isa.reduction_realization
                        ),
                    ));
                }
            }
            "endianness" => isa.endianness = scalar(values, property.span, "endianness")?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defisa property `{other}`"),
                ));
            }
        }
    }
    Ok(isa)
}

fn elaborate_packet(form: &SExpr) -> Result<Packet, ModuleError> {
    let items = list(form, "defpacket")?;
    let mut packet = Packet {
        name: atom(items.get(1), "defpacket name")?.to_string(),
        ..Packet::default()
    };
    let mut saw_slots = false;
    for property in &items[2..] {
        let values = list(property, "defpacket property")?;
        match atom(values.first(), "defpacket property name")? {
            "isa" => packet.isa = scalar(values, property.span, "isa")?,
            "slots" => {
                packet.slots = values[1..]
                    .iter()
                    .map(elaborate_packet_slot)
                    .collect::<Result<Vec<_>, _>>()?;
                saw_slots = true;
            }
            "mode" => packet.mode = atom(values.get(1), "packet mode")?.to_string(),
            "order" => {
                packet.order = atom(values.get(1), "packet order")?.replace('-', "_")
            }
            "end" => {
                packet.end = atom(values.get(1), "packet end rule")?.replace('-', "_");
                // `(end stop-bit (bit 31))` names where the continuation bit
                // lives; a stop bit whose position is left to convention is a
                // decoder and an assembler disagreeing later.
                for extra in &values[2..] {
                    let pair = list(extra, "packet end parameter")?;
                    match atom(pair.first(), "packet end parameter name")? {
                        "bit" => packet.stop_bit = number(&pair[1], "packet stop bit")?,
                        other => {
                            return Err(module_error(
                                extra.span,
                                format!("unsupported packet end parameter `{other}`"),
                            ))
                        }
                    }
                }
            }
            "hazards" => {
                packet.hazards = atom(values.get(1), "packet hazard discipline")?
                    .replace('-', "_")
            }
            "branches" => {
                packet.branches = atom(values.get(1), "packet branch policy")?.replace('-', "_")
            }
            "description" => packet.description = scalar(values, property.span, "description")?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defpacket property `{other}`"),
                ));
            }
        }
    }
    if !saw_slots || packet.slots.is_empty() {
        return Err(module_error(
            form.span,
            "defpacket requires non-empty `slots`",
        ));
    }
    Ok(packet)
}

fn elaborate_packet_slot(form: &SExpr) -> Result<PacketSlot, ModuleError> {
    let items = list(form, "packet slot")?;
    let mut slot = PacketSlot {
        name: atom(items.first(), "packet slot name")?.to_string(),
        width: 32,
        units: Vec::new(),
    };
    for property in &items[1..] {
        let values = list(property, "packet slot property")?;
        match atom(values.first(), "packet slot property name")? {
            "width" => slot.width = numeric_property(values, property.span, "width")?,
            "units" => slot.units = scalar_list(&values[1..])?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported packet slot property `{other}`"),
                ));
            }
        }
    }
    if slot.units.is_empty() {
        return Err(module_error(
            form.span,
            format!("packet slot `{}` requires `(units ...)`", slot.name),
        ));
    }
    Ok(slot)
}

/// `(defconfig <name> (bytes N) (field <name> (at O) (width W) (values ...))...
/// (instantiate (<field> <value>)...))`.
///
/// A configuration a machine reads from memory. It declares a layout the
/// semantics already imply, so that the two can be required to agree --
/// `validate_configs` does that, and without it this would be a comment.
fn elaborate_config(form: &SExpr) -> Result<Config, ModuleError> {
    let items = list(form, "defconfig")?;
    let mut config = Config {
        name: atom(items.get(1), "defconfig name")?.to_string(),
        ..Config::default()
    };
    for property in &items[2..] {
        let values = list(property, "defconfig property")?;
        match atom(values.first(), "defconfig property name")? {
            "bytes" => config.bytes = numeric_property(values, property.span, "bytes")?,
            "description" => {
                config.description = scalar(values, property.span, "description")?
            }
            "field" => {
                if values.len() < 2 {
                    return Err(module_error(property.span, "field expects a name"));
                }
                let mut field = ConfigField {
                    name: atom(values.get(1), "config field name")?.to_string(),
                    width: 1,
                    ..ConfigField::default()
                };
                for clause in &values[2..] {
                    let parts = list(clause, "config field clause")?;
                    match atom(parts.first(), "config field clause name")? {
                        "at" => field.at = numeric_property(parts, clause.span, "at")?,
                        "width" => field.width = numeric_property(parts, clause.span, "width")?,
                        "values" => {
                            for value in &parts[1..] {
                                field.values.push(number(value, "config field value")? as u64);
                            }
                        }
                        other => {
                            return Err(module_error(
                                clause.span,
                                format!("unknown config field clause `{other}`"),
                            ))
                        }
                    }
                }
                config.fields.push(field);
            }
            "instantiate" => {
                for clause in &values[1..] {
                    let parts = list(clause, "instantiate clause")?;
                    if parts.len() != 2 {
                        return Err(module_error(
                            clause.span,
                            "instantiate takes `(<field> <value>)`",
                        ));
                    }
                    config.instantiate.push((
                        atom(parts.first(), "instantiated field")?.to_string(),
                        number(&parts[1], "instantiated value")? as u64,
                    ));
                }
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unknown defconfig property `{other}`"),
                ))
            }
        }
    }
    Ok(config)
}

/// `(defkernel <name> (params ...) (space (<index> <extent>) ...) <statement>...)`.
fn elaborate_kernel(form: &SExpr) -> Result<Kernel, ModuleError> {
    let items = list(form, "defkernel")?;
    let mut kernel = Kernel {
        name: atom(items.get(1), "defkernel name")?.to_string(),
        ..Kernel::default()
    };
    for property in &items[2..] {
        let values = list(property, "defkernel clause")?;
        match atom(values.first(), "defkernel clause head")? {
            "params" => {
                for value in &values[1..] {
                    let name = atom(Some(value), "kernel parameter")?.to_string();
                    if kernel.params.contains(&name) {
                        return Err(module_error(
                            value.span,
                            format!("kernel `{}` names parameter `{name}` twice", kernel.name),
                        ));
                    }
                    kernel.params.push(name);
                }
            }
            "space" => {
                for dimension in &values[1..] {
                    let parts = list(dimension, "kernel space dimension")?;
                    if parts.len() != 2 {
                        return Err(module_error(
                            dimension.span,
                            "a kernel space dimension is `(<index> <extent>)`",
                        ));
                    }
                    let index = atom(parts.first(), "kernel space index")?.to_string();
                    let extent = number(&parts[1], "kernel space extent")?;
                    if extent == 0 {
                        return Err(module_error(
                            dimension.span,
                            format!(
                                "kernel `{}` dimension `{index}` has no extent, so the kernel does nothing",
                                kernel.name
                            ),
                        ));
                    }
                    kernel.space.push((index, extent));
                }
            }
            "description" => kernel.description = scalar(values, property.span, "description")?,
            _ => kernel.body.push(sexpr_text(property)),
        }
    }
    if kernel.body.is_empty() {
        return Err(module_error(form.span, format!("kernel `{}` has no statements", kernel.name)));
    }
    for (index, _) in &kernel.space {
        if kernel.params.contains(index) {
            return Err(module_error(
                form.span,
                format!("kernel `{}` uses `{index}` as both a parameter and an index", kernel.name),
            ));
        }
    }
    Ok(kernel)
}

/// A kernel's statements for one launch: parameters bound to the launch's
/// operands, and the body wrapped in one statement loop per space dimension.
///
/// The space is `iterate`, the behavior loop that already existed -- which is
/// the premise result for this stage in one line: the iteration was never
/// missing, only a name for it and a place a consumer could read it.
fn kernel_statements(
    launch: &[String],
    kernels: &std::collections::HashMap<String, SExpr>,
    span: Span,
) -> Result<Vec<SExpr>, ModuleError> {
    let name = &launch[0];
    let Some(form) = kernels.get(name) else {
        return Err(module_error(span, format!("runs-kernel names `{name}`, which is not defined")));
    };
    let kernel = elaborate_kernel(form)?;
    let arguments = &launch[1..];
    if arguments.len() != kernel.params.len() {
        return Err(module_error(
            span,
            format!(
                "kernel `{name}` takes {} parameter(s) ({}) and the launch binds {}",
                kernel.params.len(),
                kernel.params.join(" "),
                arguments.len()
            ),
        ));
    }
    let items = list(form, "defkernel")?;
    let mut body: Vec<SExpr> = items[2..]
        .iter()
        .filter(|property| {
            !matches!(
                list(property, "defkernel clause").ok().and_then(|values| values.first().cloned()),
                Some(SExpr { kind: SExprKind::Atom(ref head), .. })
                    if head == "params" || head == "space" || head == "description"
            )
        })
        .cloned()
        .collect();
    for (param, argument) in kernel.params.iter().zip(arguments) {
        body = body
            .iter()
            .map(|statement| substitute_atom(statement, param, argument))
            .collect();
    }
    for (index, extent) in kernel.space.iter().rev() {
        let atom = |text: &str| SExpr { kind: SExprKind::Atom(text.to_string()), span };
        let mut wrapped = vec![
            atom("iterate"),
            SExpr {
                kind: SExprKind::List(vec![atom(index), atom(&extent.to_string())]),
                span,
            },
        ];
        wrapped.extend(body);
        body = vec![SExpr { kind: SExprKind::List(wrapped), span }];
    }
    Ok(body)
}

const GUARD_COMPARISONS: [&str; 6] = ["eq", "ne", "slt", "sge", "ult", "uge"];

/// `(defdescriptor <name> (bytes N) (fields (<field> <offset> <type> [signed])...)
///   (check (<cmp> a b) <status>)... (status <field> <type>) (description "..."))`.
///
/// Everything a launch will rely on is checked here, once, against the
/// declaration: fields inside the block, aligned and disjoint; checks that
/// name only fields; status codes that are nonzero, distinct and fit where
/// they are written. A launch that got any of these wrong would read a
/// different descriptor than the one the host filled in.
fn elaborate_descriptor(form: &SExpr) -> Result<Descriptor, ModuleError> {
    let items = list(form, "defdescriptor")?;
    let mut descriptor = Descriptor {
        name: atom(items.get(1), "defdescriptor name")?.to_string(),
        ..Descriptor::default()
    };
    let name = descriptor.name.clone();
    let mut status_span = None;
    let mut check_forms: Vec<(SExpr, SExpr)> = Vec::new();
    for property in &items[2..] {
        let values = list(property, "defdescriptor clause")?;
        match atom(values.first(), "defdescriptor clause head")? {
            "bytes" => descriptor.bytes = numeric_property(values, property.span, "bytes")?,
            "fields" => {
                for field in &values[1..] {
                    let parts = list(field, "descriptor field")?;
                    if !matches!(parts.len(), 3 | 4) {
                        return Err(module_error(
                            field.span,
                            "a descriptor field is `(<name> <offset> <type> [signed])`",
                        ));
                    }
                    let field_name = atom(parts.first(), "descriptor field name")?.to_string();
                    if field_name == "returned" {
                        return Err(module_error(
                            field.span,
                            "`returned` names where a status goes, `(status returned <type>)`, and cannot be a field",
                        ));
                    }
                    let width = type_width(atom(parts.get(2), "descriptor field type")?, parts[2].span)?;
                    if !matches!(width, 8 | 16 | 32 | 64) {
                        return Err(module_error(
                            parts[2].span,
                            format!("descriptor `{name}` field `{field_name}` is i{width}; a field is 8, 16, 32 or 64 bits"),
                        ));
                    }
                    let signed = match parts.get(3) {
                        None => false,
                        Some(marker) if atom(Some(marker), "descriptor field sign")? == "signed" => true,
                        Some(marker) => {
                            return Err(module_error(marker.span, "a descriptor field's fourth part can only be `signed`"))
                        }
                    };
                    descriptor.fields.push(DescriptorField {
                        name: field_name,
                        offset: number(&parts[1], "descriptor field offset")?,
                        width,
                        signed,
                    });
                }
            }
            "check" => {
                if values.len() != 3 {
                    return Err(module_error(property.span, "a check is `(check (<cmp> a b) <status>)`"));
                }
                check_forms.push((values[1].clone(), values[2].clone()));
            }
            "status" => {
                if values.len() != 3 {
                    return Err(module_error(property.span, "status is `(status <field> <type>)`"));
                }
                descriptor.status_field = atom(values.get(1), "status field")?.to_string();
                descriptor.status_width = type_width(atom(values.get(2), "status type")?, values[2].span)?;
                status_span = Some(property.span);
            }
            "description" => {
                descriptor.description = scalar(values, property.span, "description")?
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defdescriptor clause `{other}`"),
                ))
            }
        }
    }
    if descriptor.bytes == 0 {
        return Err(module_error(form.span, format!("descriptor `{name}` needs `(bytes N)`")));
    }
    if descriptor.fields.is_empty() {
        return Err(module_error(form.span, format!("descriptor `{name}` declares no fields")));
    }
    for (index, field) in descriptor.fields.iter().enumerate() {
        let size = field.width / 8;
        if descriptor.fields[..index].iter().any(|other| other.name == field.name) {
            return Err(module_error(form.span, format!("descriptor `{name}` names field `{}` twice", field.name)));
        }
        if field.offset % size != 0 {
            return Err(module_error(
                form.span,
                format!("descriptor `{name}` field `{}` at byte {} is not aligned to its {size} bytes", field.name, field.offset),
            ));
        }
        if field.offset + size > descriptor.bytes {
            return Err(module_error(
                form.span,
                format!(
                    "descriptor `{name}` field `{}` ends at byte {}, past the descriptor's {}",
                    field.name,
                    field.offset + size,
                    descriptor.bytes
                ),
            ));
        }
        if let Some(other) = descriptor.fields[..index].iter().find(|other| {
            other.offset < field.offset + size && field.offset < other.offset + other.width / 8
        }) {
            return Err(module_error(
                form.span,
                format!("descriptor `{name}` fields `{}` and `{}` overlap", other.name, field.name),
            ));
        }
    }
    let field_names: Vec<&str> = descriptor.fields.iter().map(|field| field.name.as_str()).collect();
    let Some(status_span) = status_span else {
        return Err(module_error(form.span, format!("descriptor `{name}` needs `(status <field> <type>)`")));
    };
    if descriptor.status_field == "returned" {
        descriptor.status_field.clear();
    } else if !field_names.contains(&descriptor.status_field.as_str()) {
        return Err(module_error(
            status_span,
            format!("descriptor `{name}` writes its status through `{}`, which is not one of its fields", descriptor.status_field),
        ));
    }
    for (condition, code) in &check_forms {
        // One comparison, or `(and ...)` of them: XNN's grid reports "bad
        // version or nonzero flags" as ONE code, so a code may stand for a
        // conjunction. Nothing deeper -- a check is what an engine tests, not
        // a program.
        let parts = list(condition, "descriptor check")?;
        let conjuncts: Vec<&SExpr> = if atom(parts.first(), "descriptor check head")? == "and" {
            if parts.len() < 3 {
                return Err(module_error(condition.span, format!("descriptor `{name}`: `and` in a check needs two comparisons")));
            }
            parts[1..].iter().collect()
        } else {
            vec![condition]
        };
        for conjunct in conjuncts {
            let comparison = list(conjunct, "descriptor check comparison")?;
            let head = atom(comparison.first(), "descriptor check comparison")?;
            if !GUARD_COMPARISONS.contains(&head) || comparison.len() != 3 {
                return Err(module_error(
                    conjunct.span,
                    format!(
                        "descriptor `{name}`: a check is a comparison `({} a b)`, or `(and ...)` of them",
                        GUARD_COMPARISONS.join("|")
                    ),
                ));
            }
            for operand in &comparison[1..] {
                check_names_fields(operand, &field_names, &name)?;
            }
        }
        let status = u64::from(number(code, "check status")?);
        if status == 0 {
            return Err(module_error(code.span, format!("descriptor `{name}`: status 0 means success, so a check cannot write it")));
        }
        if descriptor.status_width < 64 && status >> descriptor.status_width != 0 {
            return Err(module_error(
                code.span,
                format!("descriptor `{name}`: status {status} does not fit the i{} status", descriptor.status_width),
            ));
        }
        if descriptor.checks.iter().any(|check| check.status == status) {
            return Err(module_error(
                code.span,
                format!("descriptor `{name}`: two checks write status {status}, so a host could not tell them apart"),
            ));
        }
        descriptor.checks.push(DescriptorCheck { condition: sexpr_text(condition), status });
    }
    Ok(descriptor)
}

/// `(defdevice <name> (isa <isa>) (window N) (register <offset> read|write <handler>)...
///   (description "..."))` -- an MMIO register map (`docs/accelerator_design.md`, H3).
fn elaborate_device(form: &SExpr) -> Result<Device, ModuleError> {
    let items = list(form, "defdevice")?;
    let mut device = Device {
        name: atom(items.get(1), "defdevice name")?.to_string(),
        ..Device::default()
    };
    let name = device.name.clone();
    for property in &items[2..] {
        let values = list(property, "defdevice clause")?;
        match atom(values.first(), "defdevice clause head")? {
            "isa" => device.isa = scalar(values, property.span, "isa")?,
            "window" => device.window = numeric_property(values, property.span, "window")?,
            "description" => device.description = scalar(values, property.span, "description")?,
            "register" => {
                if values.len() != 4 {
                    return Err(module_error(
                        property.span,
                        "a device register is `(register <offset> read|write <handler>)`",
                    ));
                }
                let offset = number(&values[1], "register offset")?;
                let access = atom(values.get(2), "register access")?.to_string();
                if access != "read" && access != "write" {
                    return Err(module_error(
                        values[2].span,
                        format!("device `{name}`: a register is read or write, not `{access}`"),
                    ));
                }
                let handler = atom(values.get(3), "register handler")?.to_string();
                if device.registers.iter().any(|r| r.offset == offset && r.access == access) {
                    return Err(module_error(
                        property.span,
                        format!("device `{name}` has two {access} handlers at offset {offset:#x}"),
                    ));
                }
                device.registers.push(DeviceRegister { offset, access, handler });
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defdevice clause `{other}`"),
                ))
            }
        }
    }
    if device.isa.is_empty() || device.window == 0 {
        return Err(module_error(form.span, format!("device `{name}` needs `(isa ...)` and `(window N)`")));
    }
    if device.registers.is_empty() {
        return Err(module_error(form.span, format!("device `{name}` declares no registers")));
    }
    for register in &device.registers {
        if register.offset % 4 != 0 || register.offset + 4 > device.window {
            return Err(module_error(
                form.span,
                format!(
                    "device `{name}` register at {:#x} is not a word inside its {:#x}-byte window",
                    register.offset, device.window
                ),
            ));
        }
    }
    Ok(device)
}

/// A handler must be an instruction of the device's ISA shaped for its access:
/// a write takes at most one register -- the value written -- and writes
/// none; a read writes exactly one register -- the value read -- and reads
/// none. Anything else could not be bound to the bus by any device model.
fn check_device_handlers(
    device: &Device,
    instructions: &[Instruction],
    span: Span,
) -> Result<(), ModuleError> {
    for register in &device.registers {
        let Some(handler) = instructions.iter().find(|i| i.name == register.handler) else {
            return Err(module_error(
                span,
                format!("device `{}` register {:#x} runs `{}`, which is not an instruction", device.name, register.offset, register.handler),
            ));
        };
        if handler.isa != device.isa {
            return Err(module_error(
                span,
                format!("device `{}` handler `{}` belongs to ISA `{}`, not the device's `{}`", device.name, register.handler, handler.isa, device.isa),
            ));
        }
        let is_register = |o: &&crate::ast::Operand| crate::ast::is_register_kind(&o.kind);
        let inputs = handler.operands.iter().filter(|o| o.input && !o.output).filter(is_register).count();
        let outputs = handler.operands.iter().filter(|o| o.output).filter(is_register).count();
        let (fits, want) = if register.access == "write" {
            (inputs <= 1 && outputs == 0, "at most one register input -- the value written -- and no outputs")
        } else {
            (inputs == 0 && outputs == 1, "exactly one register output -- the value read -- and no register inputs")
        };
        if !fits {
            return Err(module_error(
                span,
                format!(
                    "device `{}` {} handler `{}` must have {want}; it has {inputs} input(s) and {outputs} output(s)",
                    device.name, register.access, register.handler
                ),
            ));
        }
    }
    Ok(())
}

/// Every name a check reads must be a field or a literal: operators sit in
/// head position and types and signedness are atoms the IR knows.
fn check_names_fields(expression: &SExpr, fields: &[&str], descriptor: &str) -> Result<(), ModuleError> {
    match &expression.kind {
        SExprKind::Atom(atom) => {
            if fields.contains(&atom.as_str())
                || crate::ir::integer_literal(atom).is_some()
                || crate::ir::type_atom_bits(atom).is_some()
                || atom == "signed"
                || atom == "unsigned"
            {
                Ok(())
            } else {
                Err(module_error(
                    expression.span,
                    format!("descriptor `{descriptor}`: a check reads `{atom}`, which is not one of its fields"),
                ))
            }
        }
        SExprKind::List(items) => {
            for item in items.iter().skip(1) {
                check_names_fields(item, fields, descriptor)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `form` with every atom in `bindings` replaced -- all at once, so a value
/// that mentions another binding's name is not rewritten a second time.
fn substitute_atoms(form: &SExpr, bindings: &std::collections::HashMap<String, SExpr>) -> SExpr {
    let kind = match &form.kind {
        SExprKind::Atom(atom) => match bindings.get(atom) {
            Some(value) => return value.clone(),
            None => SExprKind::Atom(atom.clone()),
        },
        SExprKind::List(items) => {
            SExprKind::List(items.iter().map(|item| substitute_atoms(item, bindings)).collect())
        }
        other => other.clone(),
    };
    SExpr { kind, span: form.span }
}

/// `statement` guarded by `condition` as well as by whatever guards it
/// already: pushed through an `iterate` into its body, conjoined with a
/// `when`, wrapped around anything else. A `when` takes one statement and
/// guards do not nest, so this is how "only if the descriptor is valid"
/// reaches every effect a kernel makes.
fn guard_statement(statement: &SExpr, condition: &SExpr) -> SExpr {
    let span = statement.span;
    let atom = |text: &str| SExpr { kind: SExprKind::Atom(text.to_string()), span };
    let list_of = |items: Vec<SExpr>| SExpr { kind: SExprKind::List(items), span };
    if let SExprKind::List(items) = &statement.kind {
        let head = items.first().and_then(|item| match &item.kind {
            SExprKind::Atom(head) => Some(head.as_str()),
            _ => None,
        });
        match head {
            Some("iterate") if items.len() >= 3 => {
                let mut rebuilt = items[..2].to_vec();
                rebuilt.extend(items[2..].iter().map(|inner| guard_statement(inner, condition)));
                return list_of(rebuilt);
            }
            Some("when") if items.len() == 3 => {
                let mut conjuncts = vec![atom("and")];
                for part in [condition, &items[1]] {
                    match &part.kind {
                        SExprKind::List(inner)
                            if matches!(inner.first().map(|i| &i.kind), Some(SExprKind::Atom(h)) if h == "and") =>
                        {
                            conjuncts.extend(inner[1..].iter().cloned())
                        }
                        _ => conjuncts.push(part.clone()),
                    }
                }
                return list_of(vec![atom("when"), list_of(conjuncts), items[2].clone()]);
            }
            _ => {}
        }
    }
    list_of(vec![atom("when"), condition.clone(), statement.clone()])
}

/// The behavior a descriptor launch derives: the kernel over the descriptor's
/// fields, every statement guarded by every check, then one status write --
/// the first failing check's code, or 0.
fn descriptor_launch_statements(
    instruction: &Instruction,
    descriptors: &std::collections::HashMap<String, Descriptor>,
    kernels: &std::collections::HashMap<String, SExpr>,
    span: Span,
) -> Result<Vec<SExpr>, ModuleError> {
    let launch = &instruction.launches;
    let (descriptor_name, base) = (&launch[0], &launch[1]);
    let Some(descriptor) = descriptors.get(descriptor_name) else {
        return Err(module_error(span, format!("launches names descriptor `{descriptor_name}`, which is not defined")));
    };
    let Some(base_operand) = instruction.operands.iter().find(|operand| &operand.name == base && operand.input) else {
        return Err(module_error(
            span,
            format!("the descriptor's address comes from `{base}`, which is not an input operand of `{}`", instruction.mnemonic),
        ));
    };
    let address_type = format!("i{}", base_operand.width);
    let atom = |text: &str| SExpr { kind: SExprKind::Atom(text.to_string()), span };
    let list_of = |items: Vec<SExpr>| SExpr { kind: SExprKind::List(items), span };
    let mut fields = std::collections::HashMap::new();
    for field in &descriptor.fields {
        fields.insert(
            field.name.clone(),
            list_of(vec![
                atom("load"),
                atom(&format!("i{}", field.width)),
                atom(if field.signed { "signed" } else { "unsigned" }),
                list_of(vec![atom("add"), atom(&address_type), atom(base), atom(&field.offset.to_string())]),
            ]),
        );
    }
    // A launch need not run a kernel: XNN's grid descriptor validates and
    // stages a configuration, and what it computes arrives later as a stream.
    let statements: Vec<SExpr> = match launch.get(2) {
        None => Vec::new(),
        Some(kernel_name) => {
            // The kernel's arguments: a field is its load, an operand or a literal is
            // itself, and anything else is a name the launch cannot supply.
            let mut arguments = Vec::new();
            for argument in &launch[3..] {
                if let Some(load) = fields.get(argument) {
                    arguments.push(load.clone());
                } else if instruction.operands.iter().any(|operand| &operand.name == argument)
                    || crate::ir::integer_literal(argument).is_some()
                {
                    arguments.push(atom(argument));
                } else {
                    return Err(module_error(
                        span,
                        format!("launch argument `{argument}` is neither a field of `{descriptor_name}`, an operand, nor a literal"),
                    ));
                }
            }
            let Some(form) = kernels.get(kernel_name) else {
                return Err(module_error(span, format!("launches runs kernel `{kernel_name}`, which is not defined")));
            };
            let kernel = elaborate_kernel(form)?;
            if arguments.len() != kernel.params.len() {
                return Err(module_error(
                    span,
                    format!(
                        "kernel `{kernel_name}` takes {} parameter(s) ({}) and the launch binds {}",
                        kernel.params.len(),
                        kernel.params.join(" "),
                        arguments.len()
                    ),
                ));
            }
            let bindings: std::collections::HashMap<String, SExpr> =
                kernel.params.iter().cloned().zip(arguments).collect();
            let placeholder: Vec<String> = std::iter::once(kernel_name.clone())
                .chain(kernel.params.iter().cloned())
                .collect();
            let statements: Vec<SExpr> = kernel_statements(&placeholder, kernels, span)?
                .iter()
                .map(|statement| substitute_atoms(statement, &bindings))
                .collect();
            statements
        }
    };
    let conditions: Vec<SExpr> = descriptor
        .checks
        .iter()
        .map(|check| {
            let parsed = read_one(&check.condition)
                .map_err(|error| module_error(span, error.message))?;
            Ok(substitute_atoms(&parsed, &fields))
        })
        .collect::<Result<_, ModuleError>>()?;
    let mut out: Vec<SExpr> = match conditions.len() {
        0 => statements,
        1 => statements.iter().map(|statement| guard_statement(statement, &conditions[0])).collect(),
        _ => {
            let mut all = vec![atom("and")];
            all.extend(conditions.iter().cloned());
            let all = list_of(all);
            statements.iter().map(|statement| guard_statement(statement, &all)).collect()
        }
    };
    // ⚠️ The select is typed at the widest FIELD, not at the status. An
    // untyped comparison evaluates at the width around it, so a chain typed
    // at XNN's four-bit error code compared its sixteen-bit m_count and its
    // sixty-four-bit masks at four bits: an m_count of 0x8EF0 read as zero,
    // and a sixteen-by-thirty-two geometry passed as sixteen by sixteen.
    // Bio never showed it -- its status and its fields are all 32 bits -- and
    // PCE's own RTL decoder, simulated against the derived submit, did. The
    // codes fit the status width (checked at the declaration), and the write
    // narrows to it.
    let compare_width = descriptor
        .fields
        .iter()
        .map(|field| field.width)
        .chain(std::iter::once(descriptor.status_width))
        .max()
        .unwrap_or(descriptor.status_width);
    let compare_type = format!("i{compare_width}");
    let status_type = format!("i{}", descriptor.status_width);
    let mut status = atom("0");
    for (check, condition) in descriptor.checks.iter().zip(&conditions).rev() {
        // A conjunction fails when any of its comparisons does, so each one
        // selects the check's code on its own, innermost last.
        let SExprKind::List(parts) = &condition.kind else { unreachable!("checks are comparisons") };
        let comparisons: Vec<&SExpr> = match &parts[0].kind {
            SExprKind::Atom(head) if head == "and" => parts[1..].iter().collect(),
            _ => vec![condition],
        };
        for comparison in comparisons.iter().rev() {
            let SExprKind::List(parts) = &comparison.kind else { unreachable!("checks are comparisons") };
            let SExprKind::Atom(head) = &parts[0].kind else { unreachable!("checks are comparisons") };
            status = list_of(vec![
                atom("select"),
                atom(&compare_type),
                list_of(vec![atom(&format!("icmp_{head}")), parts[1].clone(), parts[2].clone()]),
                status,
                atom(&check.status.to_string()),
            ]);
        }
    }
    if descriptor.status_field.is_empty() {
        // Returned: into the launching instruction's one output operand.
        let outputs: Vec<&crate::ast::Operand> =
            instruction.operands.iter().filter(|operand| operand.output).collect();
        let [output] = outputs.as_slice() else {
            return Err(module_error(
                span,
                format!(
                    "descriptor `{descriptor_name}` returns its status, so `{}` needs exactly one output operand to return it in; it has {}",
                    instruction.mnemonic,
                    outputs.len()
                ),
            ));
        };
        out.push(list_of(vec![atom("set"), atom(&output.name), status]));
    } else {
        out.push(list_of(vec![
            atom("store"),
            fields[&descriptor.status_field].clone(),
            status,
            atom(&status_type),
        ]));
    }
    Ok(out)
}

/// An s-expression as source text, for forms the canonical emitter re-emits
/// verbatim rather than from an elaborated model.
fn sexpr_text(form: &SExpr) -> String {
    match &form.kind {
        SExprKind::Atom(atom) => atom.clone(),
        SExprKind::String(text) => format!("{text:?}"),
        SExprKind::List(items) => format!(
            "({})",
            items.iter().map(sexpr_text).collect::<Vec<_>>().join(" ")
        ),
    }
}

fn elaborate_mode(form: &SExpr) -> Result<Mode, ModuleError> {
    let items = list(form, "defmode")?;
    let mut mode = Mode {
        name: atom(items.get(1), "defmode name")?.to_string(),
        ..Mode::default()
    };
    let mut saw_csr = false;
    let mut saw_field = false;
    let mut saw_values = false;
    for property in &items[2..] {
        let values = list(property, "defmode property")?;
        match atom(values.first(), "defmode property name")? {
            "csr" => {
                mode.csr = numeric_property(values, property.span, "csr")?;
                saw_csr = true;
            }
            "field" => {
                if values.len() != 3 {
                    return Err(module_error(property.span, "field expects `(field hi lo)`"));
                }
                mode.field_hi = number(&values[1], "mode field high bit")?;
                mode.field_lo = number(&values[2], "mode field low bit")?;
                saw_field = true;
            }
            "values" => {
                mode.values = values[1..]
                    .iter()
                    .map(elaborate_mode_value)
                    .collect::<Result<Vec<_>, _>>()?;
                saw_values = true;
            }
            "default" => mode.default = scalar(values, property.span, "default")?,
            "description" => mode.description = scalar(values, property.span, "description")?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defmode property `{other}`"),
                ));
            }
        }
    }
    if !saw_csr {
        return Err(module_error(form.span, "defmode requires `(csr number)`"));
    }
    if !saw_field {
        return Err(module_error(form.span, "defmode requires `(field hi lo)`"));
    }
    if !saw_values || mode.values.is_empty() {
        return Err(module_error(
            form.span,
            "defmode requires non-empty `values`",
        ));
    }
    Ok(mode)
}

fn elaborate_mode_value(form: &SExpr) -> Result<(String, u32), ModuleError> {
    let pair = list(form, "mode value")?;
    if pair.len() != 2 {
        return Err(module_error(
            form.span,
            "mode value must be `(name number)`",
        ));
    }
    Ok((
        atom(pair.first(), "mode value name")?.to_string(),
        number(&pair[1], "mode value")?,
    ))
}

fn elaborate_core(form: &SExpr) -> Result<Core, ModuleError> {
    let items = list(form, "defcore")?;
    let name = atom(items.get(1), "defcore name")?.to_string();
    let mut kind = None;
    let mut threads = 1;
    let mut implements = String::new();
    let mut personalities = Vec::new();
    let mut features = Vec::new();
    let mut issue_width = 0u32;
    let mut units: Vec<CoreUnit> = Vec::new();
    let mut memory = String::new();
    let mut branch_penalty = 0u32;
    let mut predictor = String::new();
    let mut predictor_entries = 0u32;
    let mut rob = 0u32;
    let mut issue_queue = 0u32;
    let mut commit_width = 0u32;
    let mut dispatch_width = 0u32;
    let mut schedule = 0u32;
    let mut bypass: Vec<(String, String, u32)> = Vec::new();
    let mut value_prediction: Option<(u32, u32)> = None;
    let mut value_stride = false;
    let mut rename_width = 0u32;
    let mut select = String::new();
    let mut eliminate = String::new();
    let (mut store_buffer, mut store_drain) = (0u32, String::new());
    let mut load_order = String::new();
    let mut queues: Vec<(String, u32, Vec<String>)> = Vec::new();
    let mut model = String::new();
    let mut provenance = String::new();
    let mut vendor: Vec<(String, String)> = Vec::new();
    let mut lsq: Option<CoreLsq> = None;
    let mut rename: Vec<(String, u32)> = Vec::new();
    let mut predictor_history = 0u32;
    let mut predictor_params: Vec<(String, u32)> = Vec::new();
    let mut overrides: Option<crate::ast::QuickPredictor> = None;
    let mut front_end: Option<CoreFrontEnd> = None;
    let mut ports: Vec<(String, Vec<String>)> = Vec::new();
    let mut engine = String::new();
    let mut memory_timing = String::new();
    let mut tlb: Option<crate::ast::CoreTlb> = None;
    let mut exclusive = None;
    let mut events = None;
    let mut simt: Option<CoreSimt> = None;
    let mut timing: Option<crate::timing::CoreTiming> = None;
    let mut cycle_gates = 0u32;
    for property in &items[2..] {
        let values = list(property, "defcore property")?;
        match atom(values.first(), "defcore property name")? {
            "kind" => kind = Some(scalar(values, property.span, "kind")?),
            // `(cycle (gates N))`: the cycle, in the cost model's gate delays.
            "cycle" => {
                for clause in &values[1..] {
                    let pair = list(clause, "cycle clause")?;
                    match atom(pair.first(), "cycle unit")? {
                        "gates" => cycle_gates = numeric_property(pair, clause.span, "gates")?,
                        other => {
                            return Err(module_error(
                                clause.span,
                                format!("a cycle is stated in `gates`, not `{other}`"),
                            ));
                        }
                    }
                }
                if cycle_gates == 0 {
                    return Err(module_error(property.span, "a cycle of no gate delays: `(cycle (gates N))`"));
                }
            }
            // `(timing (latency (MUL 2) ...) (class-latency (alu 1) ...)
            //          (unit (MAC mul) ...))` -- docs/core_timing_design.md.
            "timing" => {
                let mut declared = crate::timing::CoreTiming::default();
                for clause in &values[1..] {
                    let entries = list(clause, "timing clause")?;
                    let which = atom(entries.first(), "timing clause name")?;
                    for entry in &entries[1..] {
                        let pair = list(entry, "timing entry")?;
                        let key = atom(pair.first(), "timing entry name")?.to_string();
                        match which {
                            // `(MNEMONIC (unit cycles) ...)`: a unit and the
                            // cycles it takes there, per micro-op, in order.
                            "micro-ops" => {
                                let mut ops = Vec::new();
                                for op in &pair[1..] {
                                    let fields = list(op, "micro-op")?;
                                    let unit = atom(fields.first(), "micro-op unit")?.to_string();
                                    ops.push((unit, numeric_property(fields, op.span, "micro-op")?));
                                }
                                declared.micro_ops.push((key, ops));
                            }
                            // `(HEAD TAIL)`: a pair the decoder fuses (FU1).
                            "fuse" => {
                                let tail = atom(pair.get(1), "fuse tail")?.to_string();
                                if pair.len() != 2 {
                                    return Err(module_error(entry.span, "a fused pair is `(HEAD TAIL)`"));
                                }
                                declared.fuse.push((key, tail));
                            }
                            "latency" if pair.get(1).and_then(|value| atom(Some(value), "").ok())
                                == Some("derived") =>
                            {
                                declared.derived.push(key)
                            }
                            "latency" => declared
                                .latency
                                .push((key, numeric_property(pair, entry.span, "latency")?)),
                            "class-latency" => declared
                                .class_latency
                                .push((key, numeric_property(pair, entry.span, "class-latency")?)),
                            "unit" => declared.unit.push((key, scalar(pair, entry.span, "unit")?)),
                            other => {
                                return Err(module_error(
                                    clause.span,
                                    format!("unsupported timing clause `{other}`"),
                                ));
                            }
                        }
                    }
                }
                timing = Some(declared);
            }
            "issue-width" => {
                issue_width = numeric_property(values, property.span, "issue-width")?;
                if issue_width == 0 {
                    return Err(module_error(
                        property.span,
                        "a core that issues nothing runs nothing: `(issue-width 0)`",
                    ));
                }
            }
            "units" => {
                for entry in &values[1..] {
                    let parts = list(entry, "defcore unit")?;
                    let unit_name = atom(parts.first(), "unit name")?.to_string();
                    let mut count = 1u32;
                    let mut pipelined = true;
                    let mut unit_abort = false;
                    let mut unit_queue = 0u32;
                    let mut unit_lanes = 0u32;
                    let mut unit_interval = 0u32;
                    let mut unit_length = String::new();
                    let mut unit_accepts: Vec<String> = Vec::new();
                    let (mut unit_transport, mut unit_switch) = (0u32, 0u32);
                    for attribute in &parts[1..] {
                        let pair = list(attribute, "unit attribute")?;
                        match atom(pair.first(), "unit attribute name")? {
                            "count" => {
                                count = numeric_property(pair, attribute.span, "count")?;
                            }
                            "lanes" => {
                                unit_lanes = numeric_property(pair, attribute.span, "lanes")?;
                            }
                            "inflight" => {
                                unit_interval = numeric_property(pair, attribute.span, "inflight")?;
                            }
                            "length" => {
                                unit_length = scalar(pair, attribute.span, "length")?;
                            }
                            "transport" => {
                                unit_transport = numeric_property(pair, attribute.span, "transport")?;
                            }
                            "switch" => {
                                unit_switch = numeric_property(pair, attribute.span, "switch")?;
                            }
                            "accepts" => {
                                for name in &pair[1..] {
                                    unit_accepts.push(atom(Some(name), "accepted unit")?.to_string());
                                }
                            }
                            "pipelined" => {
                                pipelined = scalar(pair, attribute.span, "pipelined")? == "true";
                            }
                            "abort" => {
                                unit_abort = scalar(pair, attribute.span, "abort")? == "true";
                            }
                            "queue" => {
                                unit_queue = numeric_property(pair, attribute.span, "queue")?;
                            }
                            other => {
                                return Err(module_error(
                                    attribute.span,
                                    format!("unsupported unit attribute `{other}`"),
                                ));
                            }
                        }
                    }
                    if count == 0 {
                        return Err(module_error(
                            entry.span,
                            format!("unit `{unit_name}` has none of itself: `(count 0)`"),
                        ));
                    }
                    if units.iter().any(|unit: &CoreUnit| unit.name == unit_name) {
                        return Err(module_error(
                            entry.span,
                            format!("unit `{unit_name}` is declared twice"),
                        ));
                    }
                    units.push(CoreUnit { name: unit_name, count, pipelined, lanes: unit_lanes, length: unit_length, accepts: unit_accepts, transport: unit_transport, switch: unit_switch, interval: unit_interval, abort: unit_abort, queue: unit_queue });
                }
            }
            "threads" => {
                threads = numeric_property(values, property.span, "threads")?;
            }
            "implements" => {
                implements = scalar(values, property.span, "implements")?;
            }
            "memory" => memory = scalar(values, property.span, "memory")?,
            "model" => model = scalar(values, property.span, "model")?,
            "provenance" => provenance = scalar(values, property.span, "provenance")?,
            "vendor" => {
                for attribute in &values[1..] {
                    let pair = list(attribute, "vendor parameter")?;
                    let key = atom(pair.first(), "vendor parameter name")?.to_string();
                    if pair.len() != 2 {
                        return Err(module_error(
                            attribute.span,
                            format!("vendor parameter `{key}` needs exactly one value"),
                        ));
                    }
                    let value = scalar(pair, attribute.span, &key)?;
                    if vendor.iter().any(|(k, _): &(String, String)| *k == key) {
                        return Err(module_error(
                            attribute.span,
                            format!("vendor parameter `{key}` is set twice"),
                        ));
                    }
                    vendor.push((key, value));
                }
            }
            "window" => {
                for attribute in &values[1..] {
                    let pair = list(attribute, "window attribute")?;
                    match atom(pair.first(), "window attribute name")? {
                        "rob" => rob = numeric_property(pair, attribute.span, "rob")?,
                        "issue-queue" => {
                            issue_queue =
                                numeric_property(pair, attribute.span, "issue-queue")?
                        }
                        "commit-width" => {
                            commit_width =
                                numeric_property(pair, attribute.span, "commit-width")?
                        }
                        "dispatch-width" => {
                            dispatch_width =
                                numeric_property(pair, attribute.span, "dispatch-width")?
                        }
                        "schedule" => {
                            schedule = numeric_property(pair, attribute.span, "schedule")?
                        }
                        "rename-width" => {
                            rename_width = numeric_property(pair, attribute.span, "rename-width")?
                        }
                        "select" => select = scalar(pair, attribute.span, "select")?,
                        "eliminate" => eliminate = scalar_list(&pair[1..])?.join(" "),
                        other => {
                            return Err(module_error(
                                attribute.span,
                                format!("unsupported window attribute `{other}`"),
                            ));
                        }
                    }
                }
            }
            "branch" => {
                for attribute in &values[1..] {
                    let pair = list(attribute, "branch attribute")?;
                    match atom(pair.first(), "branch attribute name")? {
                        "penalty" => {
                            branch_penalty =
                                numeric_property(pair, attribute.span, "penalty")?
                        }
                        "predictor" => {
                            predictor = scalar(pair, attribute.span, "predictor")?
                        }
                        "entries" => {
                            predictor_entries =
                                numeric_property(pair, attribute.span, "entries")?
                        }
                        "history" => {
                            predictor_history =
                                numeric_property(pair, attribute.span, "history")?
                        }
                        // The quick predictor this one overrides at decode
                        // (D3): a clause of its own, not a number.
                        "overrides" => {
                            let mut quick = crate::ast::QuickPredictor {
                                predictor: String::new(),
                                entries: 0,
                                cycles: 0,
                            };
                            for field in &pair[1..] {
                                let kv = list(field, "overrides attribute")?;
                                match atom(kv.first(), "overrides attribute name")? {
                                    "predictor" => {
                                        quick.predictor = scalar(kv, field.span, "predictor")?
                                    }
                                    "entries" => {
                                        quick.entries = numeric_property(kv, field.span, "entries")?
                                    }
                                    "cycles" => {
                                        quick.cycles = numeric_property(kv, field.span, "cycles")?
                                    }
                                    other => {
                                        return Err(module_error(
                                            field.span,
                                            format!("unsupported overrides attribute `{other}`"),
                                        ));
                                    }
                                }
                            }
                            overrides = Some(quick);
                        }
                        // ⚠️ Anything else is the PREDICTOR's, carried as a
                        // number: which keys a predictor reads is its own
                        // business, and validation holds the built-in ones
                        // to theirs.
                        other => {
                            let value = numeric_property(pair, attribute.span, other)?;
                            if predictor_params.iter().any(|(k, _): &(String, u32)| k == other) {
                                return Err(module_error(
                                    attribute.span,
                                    format!("branch attribute `{other}` is set twice"),
                                ));
                            }
                            predictor_params.push((other.to_string(), value));
                        }
                    }
                }
            }
            // ⚠️ PRESENCE is the switch. A core without `(lsq ...)` does not
            // model memory ordering at all, which is what every core did
            // before this form; one with an empty `(lsq)` models it with the
            // defaults, and that is a different machine.
            "lsq" => {
                let mut queue = CoreLsq {
                    loads: 0,
                    stores: 0,
                    disambiguation: "conservative".to_string(),
                    forwarding: true,
                    replay: 0,
                    store_sets: 0,
                };
                for attribute in &values[1..] {
                    let pair = list(attribute, "lsq attribute")?;
                    match atom(pair.first(), "lsq attribute name")? {
                        "loads" => queue.loads = numeric_property(pair, attribute.span, "loads")?,
                        "stores" => {
                            queue.stores = numeric_property(pair, attribute.span, "stores")?
                        }
                        "disambiguation" => {
                            // One spelling, whichever the source used: the
                            // pipeline and the round trip compare it as text.
                            queue.disambiguation =
                                scalar(pair, attribute.span, "disambiguation")?.replace('_', "-")
                        }
                        "forwarding" => {
                            queue.forwarding =
                                scalar(pair, attribute.span, "forwarding")? == "true"
                        }
                        "replay" => {
                            queue.replay = numeric_property(pair, attribute.span, "replay")?
                        }
                        "store-sets" => {
                            queue.store_sets =
                                numeric_property(pair, attribute.span, "store-sets")?
                        }
                        other => {
                            return Err(module_error(
                                attribute.span,
                                format!("unsupported lsq attribute `{other}`"),
                            ));
                        }
                    }
                }
                lsq = Some(queue);
            }
            "front-end" => {
                let mut fe = CoreFrontEnd {
                    fetch_width: 0,
                    depth: 0,
                    buffer: 0,
                    btb: 0,
                    btb_penalty: 0,
                    ras: 0,
                    icache: String::new(),
                    wrong_path_fetch: false,
                    wrong_path_execute: false,
                    op_cache: None,
                    loop_buffer: None,
                    target_queue: 0,
                };
                for attribute in &values[1..] {
                    let pair = list(attribute, "front-end attribute")?;
                    let key = atom(pair.first(), "front-end attribute name")?;
                    if key == "icache" {
                        fe.icache = scalar(pair, attribute.span, "icache")?;
                        continue;
                    }
                    if key == "wrong-path-fetch" {
                        fe.wrong_path_fetch = scalar(pair, attribute.span, key)? == "true";
                        continue;
                    }
                    if key == "wrong-path-execute" {
                        fe.wrong_path_execute = scalar(pair, attribute.span, key)? == "true";
                        continue;
                    }
                    // U2: two clauses of their own, each a list of numbers.
                    if key == "op-cache" || key == "loop-buffer" {
                        let mut numbers: Vec<(String, u32)> = Vec::new();
                        for field in &pair[1..] {
                            let kv = list(field, "front-end clause attribute")?;
                            let name = atom(kv.first(), "front-end clause attribute name")?;
                            numbers.push((name.to_string(), numeric_property(kv, field.span, name)?));
                        }
                        let allowed: &[&str] = if key == "op-cache" {
                            &["entries", "ways", "window", "width", "depth"]
                        } else {
                            &["ops", "width", "depth"]
                        };
                        if let Some((other, _)) = numbers.iter().find(|(n, _)| !allowed.contains(&n.as_str())) {
                            return Err(module_error(
                                attribute.span,
                                format!("unsupported {key} attribute `{other}`"),
                            ));
                        }
                        let of = |name: &str| numbers.iter().find(|(n, _)| n == name).map_or(0, |(_, v)| *v);
                        if key == "op-cache" {
                            fe.op_cache = Some(crate::ast::OpCache {
                                entries: of("entries"),
                                ways: of("ways"),
                                window: of("window"),
                                width: of("width"),
                                depth: of("depth"),
                            });
                        } else {
                            fe.loop_buffer = Some(crate::ast::LoopBuffer {
                                ops: of("ops"),
                                width: of("width"),
                                depth: of("depth"),
                            });
                        }
                        continue;
                    }
                    let value = numeric_property(pair, attribute.span, key)?;
                    match key {
                        "fetch-width" => fe.fetch_width = value,
                        "depth" => fe.depth = value,
                        "buffer" => fe.buffer = value,
                        "btb" => fe.btb = value,
                        "btb-penalty" => fe.btb_penalty = value,
                        "ras" => fe.ras = value,
                        "target-queue" => fe.target_queue = value,
                        other => {
                            return Err(module_error(
                                attribute.span,
                                format!("unsupported front-end attribute `{other}`"),
                            ));
                        }
                    }
                }
                front_end = Some(fe);
            }
            "engine" => engine = scalar(values, property.span, "engine")?,
            "load-order" => load_order = scalar(values, property.span, "load-order")?,
            "memory-timing" => memory_timing = scalar(values, property.span, "memory-timing")?,
            "tlb" => {
                let mut t = crate::ast::CoreTlb::default();
                for entry in &values[1..] {
                    let parts = list(entry, "tlb property")?;
                    let key = atom(parts.first(), "tlb property name")?;
                    match key {
                        "page-bytes" => t.page_bytes = numeric_property(parts, entry.span, key)?,
                        "walk-cycles" => t.walk_cycles = numeric_property(parts, entry.span, key)?,
                        "walkers" => t.walkers = numeric_property(parts, entry.span, key)?,
                        // TLB2: a walk that reads the table, a cache of its
                        // upper levels, and a region of large pages.
                        "walk" | "walk-cache" | "huge" => {
                            for field in &parts[1..] {
                                let kv = list(field, "tlb clause property")?;
                                let name = atom(kv.first(), "tlb clause property name")?;
                                let wide = wide_number_property(kv, field.span, name)?;
                                let narrow = u32::try_from(wide).unwrap_or(u32::MAX);
                                match (key, name) {
                                    ("walk", "levels") => t.walk_levels = narrow,
                                    ("walk", "cycles") => t.walk_level_cycles = narrow,
                                    ("walk", "table") => t.walk_table = wide,
                                    ("walk-cache", "entries") => t.walk_cache = narrow,
                                    ("huge", "bytes") => t.huge_bytes = wide,
                                    ("huge", "from") => t.huge_from = wide,
                                    ("huge", "to") => t.huge_to = wide,
                                    (_, other) => {
                                        return Err(module_error(
                                            field.span,
                                            format!("unsupported tlb {key} property `{other}`"),
                                        ));
                                    }
                                }
                            }
                        }
                        "data" | "fetch" | "second" => {
                            let mut level = crate::ast::TlbLevel::default();
                            for field in &parts[1..] {
                                let kv = list(field, "tlb level property")?;
                                let name = atom(kv.first(), "tlb level property name")?;
                                match name {
                                    "entries" => level.entries = numeric_property(kv, field.span, name)?,
                                    "ways" => level.ways = numeric_property(kv, field.span, name)?,
                                    "latency" => level.latency = numeric_property(kv, field.span, name)?,
                                    other => {
                                        return Err(module_error(
                                            field.span,
                                            format!("unsupported tlb level property `{other}`"),
                                        ));
                                    }
                                }
                            }
                            match key {
                                "data" => t.data = level,
                                "fetch" => t.fetch = level,
                                _ => t.second = level,
                            }
                        }
                        other => {
                            return Err(module_error(entry.span, format!("unsupported tlb property `{other}`")));
                        }
                    }
                }
                tlb = Some(t);
            }
            "events" => {
                let (mut wait, mut send, mut local) = (String::new(), String::new(), String::new());
                for entry in &values[1..] {
                    let parts = list(entry, "events role")?;
                    let role = atom(parts.first(), "events role")?;
                    let mnemonic = atom(parts.get(1), "events mnemonic")?.to_string();
                    match role {
                        "wait" => wait = mnemonic,
                        "send" => send = mnemonic,
                        "local" => local = mnemonic,
                        other => {
                            return Err(module_error(
                                property.span,
                                format!("events takes (wait M) (send M) (local M), not `{other}`"),
                            ))
                        }
                    }
                }
                if wait.is_empty() || send.is_empty() {
                    return Err(module_error(
                        property.span,
                        "events needs a (wait M) and a (send M): a wait nothing can end, or a send nothing hears, is not a mechanism".to_string(),
                    ));
                }
                events = Some((wait, send, local));
            }
            "exclusive" => {
                let names = scalar_list(&values[1..])?;
                if names.len() != 3 {
                    return Err(module_error(
                        property.span,
                        "exclusive takes three state slots: address, size, valid".to_string(),
                    ));
                }
                exclusive = Some((names[0].clone(), names[1].clone(), names[2].clone()));
            }
            "simt" => {
                if simt.is_some() {
                    return Err(module_error(property.span, "`simt` is declared twice"));
                }
                simt = Some(elaborate_core_simt(values, property.span)?);
            }
            // `(queues (NAME (size N) (units alu br)) ...)`: a queue several
            // units share.
            "queues" => {
                for entry in &values[1..] {
                    let parts = list(entry, "queue")?;
                    let queue_name = atom(parts.first(), "queue name")?.to_string();
                    let mut size = 0u32;
                    let mut members: Vec<String> = Vec::new();
                    for attribute in &parts[1..] {
                        let pair = list(attribute, "queue attribute")?;
                        match atom(pair.first(), "queue attribute name")? {
                            "size" => size = numeric_property(pair, attribute.span, "size")?,
                            "units" => members = scalar_list(&pair[1..])?,
                            other => {
                                return Err(module_error(
                                    attribute.span,
                                    format!("unsupported queue attribute `{other}`"),
                                ));
                            }
                        }
                    }
                    queues.push((queue_name, size, members));
                }
            }
            // `(store-buffer (entries N) (drain order|any))` -- WM1.
            "store-buffer" => {
                for attribute in &values[1..] {
                    let pair = list(attribute, "store-buffer attribute")?;
                    match atom(pair.first(), "store-buffer attribute name")? {
                        "entries" => store_buffer = numeric_property(pair, attribute.span, "entries")?,
                        "drain" => store_drain = scalar(pair, attribute.span, "drain")?,
                        other => {
                            return Err(module_error(
                                attribute.span,
                                format!("a store buffer has `entries` and `drain`, not `{other}`"),
                            ))
                        }
                    }
                }
            }
            "value-prediction" => {
                let (mut entries, mut confidence) = (0u32, 0u32);
                for attribute in &values[1..] {
                    let pair = list(attribute, "value-prediction attribute")?;
                    match atom(pair.first(), "value-prediction attribute name")? {
                        "kind" => {
                            value_stride = match scalar(pair, attribute.span, "kind")?.as_str() {
                                "stride" => true,
                                "last" => false,
                                other => {
                                    return Err(module_error(
                                        attribute.span,
                                        format!("a value predictor is `last` or `stride`, not `{other}`"),
                                    ));
                                }
                            }
                        }
                        "entries" => entries = numeric_property(pair, attribute.span, "entries")?,
                        "confidence" => {
                            confidence = numeric_property(pair, attribute.span, "confidence")?
                        }
                        other => {
                            return Err(module_error(
                                attribute.span,
                                format!("unsupported value-prediction attribute `{other}`"),
                            ));
                        }
                    }
                }
                value_prediction = Some((entries, confidence));
            }
            // `(bypass (FROM TO N) ...)`: what a result costs to cross units.
            "bypass" => {
                for entry in &values[1..] {
                    let parts = list(entry, "bypass")?;
                    if parts.len() != 3 {
                        return Err(module_error(
                            entry.span,
                            "a bypass is `(FROM TO cycles)`: the unit a result is made on, the unit that reads it, and what that costs",
                        ));
                    }
                    bypass.push((
                        atom(parts.first(), "bypass producer unit")?.to_string(),
                        atom(parts.get(1), "bypass consumer unit")?.to_string(),
                        number(&parts[2], "bypass cycles")?,
                    ));
                }
            }
            "ports" => {
                for entry in &values[1..] {
                    let parts = list(entry, "port")?;
                    let port = atom(parts.first(), "port name")?.to_string();
                    let units = scalar_list(&parts[1..])?;
                    if units.is_empty() {
                        return Err(module_error(
                            entry.span,
                            format!("port `{port}` feeds no unit"),
                        ));
                    }
                    if ports.iter().any(|(p, _): &(String, Vec<String>)| p == &port) {
                        return Err(module_error(entry.span, format!("port `{port}` is declared twice")));
                    }
                    ports.push((port, units));
                }
            }
            "rename" => {
                for attribute in &values[1..] {
                    let pair = list(attribute, "rename class")?;
                    let class = atom(pair.first(), "register class")?.to_string();
                    let extra = numeric_property(pair, attribute.span, &class)?;
                    if rename.iter().any(|(c, _): &(String, u32)| c.eq_ignore_ascii_case(&class)) {
                        return Err(module_error(
                            attribute.span,
                            format!("register class `{class}` is renamed twice"),
                        ));
                    }
                    rename.push((class, extra));
                }
            }
            "personalities" => personalities = scalar_list(&values[1..])?,
            "features" => features = scalar_list(&values[1..])?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defcore property `{other}`"),
                ));
            }
        }
    }
    Ok(Core {
        name,
        kind: kind.ok_or_else(|| module_error(form.span, "defcore requires `(kind name)`"))?,
        threads,
        implements,
        issue_width,
        units,
        timing,
        cycle_gates,
        branch_penalty,
        predictor,
        predictor_entries,
        rob,
        issue_queue,
        commit_width,
        dispatch_width,
        schedule,
        bypass,
        value_prediction,
        value_stride,
        rename_width,
        select,
        eliminate,
        store_buffer,
        store_drain,
        load_order,
        queues,
        model,
        provenance,
        vendor,
        memory,
        personalities,
        features,
        lsq,
        rename,
        predictor_history,
        predictor_params,
        overrides,
        front_end,
        ports,
        engine,
        memory_timing,
        tlb,
        exclusive,
        events,
        simt,
    })
}

/// `(simt (warps W) (lanes L) (scheduler gto|rr) (stack S) (line B)
///        (isas ext base) (cache (bytes N) (ways K) (hit H) (miss M))
///        (warp-control (role MNEMONIC...)...)
///        (sysread MNEMONIC (dst OPERAND) (index (OPERAND WEIGHT)...)))`
/// (docs/simt_design.md). Defaults are the smallest machine that is still
/// one: a single warp of a single lane, round robin, an eight-entry stack,
/// 64-byte lines, no cache.
fn elaborate_core_simt(values: &[SExpr], span: Span) -> Result<CoreSimt, ModuleError> {
    let mut machine = CoreSimt {
        warps: 1,
        lanes: 1,
        scheduler: "rr".to_string(),
        stack: 8,
        line: 64,
        isas: Vec::new(),
        cache: CoreSimtCache::default(),
        warp_control: Vec::new(),
        sysread: None,
        untracked: Vec::new(),
        vector: None,
        implicit: None,
        ooo: None,
        exclusive: None,
        interleave: None,
        interleave_group: 0,
        interleave_xor: false,
        class_latency: Vec::new(),
        pipeline: 0,
        issue_interval: 0,
        mnemonic_latency: Vec::new(),
    };
    let _ = span;
    for attribute in &values[1..] {
        let pair = list(attribute, "simt attribute")?;
        match atom(pair.first(), "simt attribute name")? {
            "warps" => machine.warps = numeric_property(pair, attribute.span, "warps")?,
            "lanes" => machine.lanes = numeric_property(pair, attribute.span, "lanes")?,
            "scheduler" => machine.scheduler = scalar(pair, attribute.span, "scheduler")?,
            "stack" => machine.stack = numeric_property(pair, attribute.span, "stack")?,
            "line" => machine.line = numeric_property(pair, attribute.span, "line")?,
            "isas" => machine.isas = scalar_list(&pair[1..])?,
            "untracked" => machine.untracked = scalar_list(&pair[1..])?,
            "exclusive" => {
                let names = scalar_list(&pair[1..])?;
                if names.len() != 3 {
                    return Err(module_error(
                        attribute.span,
                        "exclusive takes three state slots: address, size, valid".to_string(),
                    ));
                }
                machine.exclusive = Some((names[0].clone(), names[1].clone(), names[2].clone()));
            }
            "ooo" => {
                let mut rob = 0u32;
                let mut predictor = "none".to_string();
                let mut merge = true;
                let mut entries = 0u32;
                let mut memory_order = false;
                let mut divergence = false;
                for field in &pair[1..] {
                    let kv = list(field, "ooo attribute")?;
                    match atom(kv.first(), "ooo attribute name")? {
                        "rob" => rob = numeric_property(kv, field.span, "rob")?,
                        "predictor" => predictor = scalar(kv, field.span, "predictor")?,
                        "merge" => merge = scalar(kv, field.span, "merge")? != "false",
                        "entries" => entries = numeric_property(kv, field.span, "entries")?,
                        "memory-order" => memory_order = scalar(kv, field.span, "memory-order")? == "true",
                        "divergence-predictor" => divergence = scalar(kv, field.span, "divergence-predictor")? == "true",
                        other => {
                            return Err(module_error(field.span, format!("unsupported ooo attribute `{other}`")))
                        }
                    }
                }
                machine.ooo = Some((rob, predictor, merge, entries, memory_order, divergence));
            }
            "implicit" => {
                let mut implicit =
                    CoreSimtImplicit {
                        policy: String::new(),
                        sp: None,
                        calls: Vec::new(),
                        returns: Vec::new(),
                        yields: Vec::new(),
                        progress: 0,
                        relax: Vec::new(),
                        wait: Vec::new(),
                        send: Vec::new(),
                        send_local: Vec::new(),
                        smt: false,
                        smt_fronts: 0,
                    };
                for field in &pair[1..] {
                    let kv = list(field, "implicit attribute")?;
                    match atom(kv.first(), "implicit attribute name")? {
                        "policy" => implicit.policy = scalar(kv, field.span, "policy")?,
                        "sp" => {
                            let state = atom(kv.get(1), "sp state")?.to_string();
                            let bytes = atom(kv.get(2), "stack bytes")?
                                .parse::<u32>()
                                .map_err(|_| module_error(field.span, "sp takes a state and a stack size".to_string()))?;
                            implicit.sp = Some((state, bytes));
                        }
                        "calls" => implicit.calls = scalar_list(&kv[1..])?,
                        "returns" => implicit.returns = scalar_list(&kv[1..])?,
                        "yield" => implicit.yields = scalar_list(&kv[1..])?,
                        "relax" => implicit.relax = scalar_list(&kv[1..])?,
                        "path-issue" => {
                            implicit.smt = match atom(kv.get(1), "path-issue")? {
                                "smt" => {
                                    if let Some(n) = kv.get(2) {
                                        implicit.smt_fronts = atom(Some(n), "front ends")?.parse::<u32>().map_err(|_| {
                                            module_error(field.span, "path-issue smt takes a count of front ends".to_string())
                                        })?;
                                    }
                                    true
                                }
                                "one" => false,
                                other => {
                                    return Err(module_error(
                                        field.span,
                                        format!("path-issue is `one` or `smt`, not `{other}`"),
                                    ))
                                }
                            }
                        }
                        "events" => {
                            for part in &kv[1..] {
                                let pv = list(part, "events attribute")?;
                                let names = scalar_list(&pv[1..])?;
                                match atom(pv.first(), "events attribute name")? {
                                    "wait" => implicit.wait = names,
                                    "send" => implicit.send = names,
                                    "local" => implicit.send_local = names,
                                    other => {
                                        return Err(module_error(
                                            part.span,
                                            format!("unsupported events attribute `{other}`; they are wait, send, local"),
                                        ))
                                    }
                                }
                            }
                        }
                        "progress" => {
                            implicit.progress = atom(kv.get(1), "progress")?
                                .parse::<u32>()
                                .map_err(|_| module_error(field.span, "progress takes a count of instructions".to_string()))?
                        }
                        other => {
                            return Err(module_error(
                                field.span,
                                format!("unsupported implicit attribute `{other}`"),
                            ))
                        }
                    }
                }
                machine.implicit = Some(implicit);
            }
            "vector" => {
                let mut vector = CoreSimtVector {
                    isa: String::new(),
                    lane_classes: Vec::new(),
                    lane_state: Vec::new(),
                    broadcast: Vec::new(),
                    flags: None,
                    crosslane: Vec::new(),
                    sum: Vec::new(),
                };
                for field in &pair[1..] {
                    let kv = list(field, "vector attribute")?;
                    match atom(kv.first(), "vector attribute name")? {
                        "isa" => vector.isa = scalar(kv, field.span, "isa")?,
                        "lane-classes" => vector.lane_classes = scalar_list(&kv[1..])?,
                        "lane-state" => vector.lane_state = scalar_list(&kv[1..])?,
                        "broadcast" => vector.broadcast = scalar_list(&kv[1..])?,
                        "crosslane" => vector.crosslane = scalar_list(&kv[1..])?,
                        "sum" => vector.sum = scalar_list(&kv[1..])?,
                        "flags" => {
                            let state = atom(kv.get(1), "flags state")?.to_string();
                            vector.flags = Some((state, scalar_list(&kv[2..])?));
                        }
                        other => {
                            return Err(module_error(
                                field.span,
                                format!("unsupported vector attribute `{other}`"),
                            ))
                        }
                    }
                }
                machine.vector = Some(vector);
            }
            "pipeline" => machine.pipeline = numeric_property(pair, attribute.span, "pipeline")?,
            "mnemonic-latency" => {
                for field in &pair[1..] {
                    let kv = list(field, "mnemonic-latency attribute")?;
                    let prefix = atom(kv.first(), "mnemonic prefix")?.to_string();
                    let cycles = numeric_property(kv, field.span, "mnemonic-latency")?;
                    machine.mnemonic_latency.push((prefix, cycles));
                }
            }
            "issue-interval" => {
                machine.issue_interval = numeric_property(pair, attribute.span, "issue-interval")?
            }
            "latency" => {
                for field in &pair[1..] {
                    let kv = list(field, "latency attribute")?;
                    let class = atom(kv.first(), "latency class")?.to_string();
                    let cycles = numeric_property(kv, field.span, "latency")?;
                    machine.class_latency.push((class, cycles));
                }
            }
            "interleave" => {
                let (mut top, mut bytes, mut granule) = (0u64, 0u32, 0u32);
                for field in &pair[1..] {
                    let kv = list(field, "interleave attribute")?;
                    match atom(kv.first(), "interleave attribute name")? {
                        "top" => top = wide_number_property(kv, field.span, "top")?,
                        "bytes" => bytes = numeric_property(kv, field.span, "bytes")?,
                        "granule" => granule = numeric_property(kv, field.span, "granule")?,
                        "group" => machine.interleave_group = numeric_property(kv, field.span, "group")?,
                        "xor" => machine.interleave_xor = scalar(kv, field.span, "xor")? == "true",
                        other => {
                            return Err(module_error(
                                field.span,
                                format!("unsupported interleave attribute `{other}`"),
                            ))
                        }
                    }
                }
                machine.interleave = Some((top, bytes, granule));
            }
            "cache" => {
                for field in &pair[1..] {
                    let kv = list(field, "simt cache attribute")?;
                    let n = atom(kv.first(), "simt cache attribute name")?;
                    let v = numeric_property(kv, field.span, n)?;
                    match n {
                        "bytes" => machine.cache.bytes = v,
                        "ways" => machine.cache.ways = v,
                        "hit" => machine.cache.hit = v,
                        "miss" => machine.cache.miss = v,
                        "fill" => machine.cache.fill = v,
                        "mshrs" => machine.cache.mshrs = v,
                        "banks" => machine.cache.banks = v,
                        "l2-bytes" => machine.cache.l2_bytes = v,
                        "l2-ways" => machine.cache.l2_ways = v,
                        "l2-hit" => machine.cache.l2_hit = v,
                        "prefetch-degree" => machine.cache.prefetch_degree = v,
                        "prefetch-entries" => machine.cache.prefetch_entries = v,
                        "prefetch-next-line" => machine.cache.prefetch_next_line = v,
                        "prefetch-best-offset" => machine.cache.prefetch_best_offset = v,
                        "track-fills" => machine.cache.track_fills = v,
                        other => {
                            return Err(module_error(
                                field.span,
                                format!("unsupported simt cache attribute `{other}`"),
                            ))
                        }
                    }
                }
            }
            "warp-control" => {
                for binding in &pair[1..] {
                    let parts = list(binding, "warp-control binding")?;
                    let role = atom(parts.first(), "warp-control role")?.to_string();
                    let mnemonics = scalar_list(&parts[1..])?;
                    if mnemonics.is_empty() {
                        return Err(module_error(
                            binding.span,
                            format!("warp-control role `{role}` binds no instruction"),
                        ));
                    }
                    if machine.warp_control.iter().any(|(r, _)| *r == role) {
                        return Err(module_error(
                            binding.span,
                            format!("warp-control role `{role}` is bound twice"),
                        ));
                    }
                    machine.warp_control.push((role, mnemonics));
                }
            }
            "sysread" => {
                let mnemonic = atom(pair.get(1), "sysread mnemonic")?.to_string();
                let mut dst = String::new();
                let mut index = Vec::new();
                for field in &pair[2..] {
                    let kv = list(field, "sysread attribute")?;
                    match atom(kv.first(), "sysread attribute name")? {
                        "dst" => dst = scalar(kv, field.span, "dst")?,
                        "index" => {
                            for term in &kv[1..] {
                                let t = list(term, "sysread index term")?;
                                let operand = atom(t.first(), "sysread index operand")?.to_string();
                                let weight = numeric_property(t, term.span, "sysread index weight")?;
                                index.push((operand, weight));
                            }
                        }
                        other => {
                            return Err(module_error(
                                field.span,
                                format!("unsupported sysread attribute `{other}`"),
                            ))
                        }
                    }
                }
                machine.sysread = Some(CoreSimtSysread { mnemonic, dst, index });
            }
            other => {
                return Err(module_error(
                    attribute.span,
                    format!("unsupported simt attribute `{other}`"),
                ))
            }
        }
    }
    Ok(machine)
}

/// `(exports (mul-pipe (unit mul) (channel result-bus)))` and its import twin
/// `(imports (mul-pipe (from xnn0) (channel borrowed-bus)))`. The two sides name
/// the same seam but not the same channel: an importer states what it can
/// tolerate, and whether that contains what the exporter promises is what
/// validation decides.
fn elaborate_seam(
    values: &[SExpr],
    span: Span,
    exporting: bool,
) -> Result<PersonalitySeam, ModuleError> {
    let keyword = if exporting { "exports" } else { "imports" };
    let body = values
        .get(1)
        .ok_or_else(|| module_error(span, format!("`{keyword}` requires `(name ...)`")))?;
    let fields = list(body, keyword)?;
    let name = atom(fields.first(), &format!("{keyword} name"))?.to_string();
    let mut unit = String::new();
    let mut from = String::new();
    let mut channel = String::new();
    for field in &fields[1..] {
        let field_values = list(field, keyword)?;
        match atom(field_values.first(), &format!("{keyword} field"))? {
            "unit" if exporting => unit = scalar(field_values, field.span, "unit")?,
            "from" if !exporting => from = scalar(field_values, field.span, "from")?,
            "channel" => channel = scalar(field_values, field.span, "channel")?,
            other => {
                return Err(module_error(
                    field.span,
                    format!("unsupported {keyword} field `{other}`"),
                ));
            }
        }
    }
    if exporting && unit.is_empty() {
        return Err(module_error(
            span,
            format!("export `{name}` requires `(unit name)`"),
        ));
    }
    if !exporting && from.is_empty() {
        return Err(module_error(
            span,
            format!("import `{name}` requires `(from personality)`"),
        ));
    }
    if channel.is_empty() {
        return Err(module_error(
            span,
            format!("{keyword} `{name}` requires `(channel name)`"),
        ));
    }
    Ok(PersonalitySeam {
        name,
        unit,
        from,
        channel,
    })
}

/// `(rv_gpr 10 17)` -- a class and an inclusive index range, or a single index.
/// An ABI names registers the way AXIS has them: a class with a count, not a
/// list of architectural names the description never gave them.
fn elaborate_register_ref(form: &SExpr) -> Result<RegisterRef, ModuleError> {
    let items = list(form, "register reference")?;
    let class = atom(items.first(), "register class")?.to_string();
    let first = match items.get(1) {
        Some(value) => number(value, "register index")?,
        None => {
            return Err(module_error(
                form.span,
                format!("register reference `{class}` needs an index"),
            ))
        }
    };
    let last = match items.get(2) {
        Some(value) => number(value, "register index")?,
        None => first,
    };
    if items.len() > 3 {
        return Err(module_error(
            form.span,
            "register reference is `(class index)` or `(class first last)`",
        ));
    }
    if last < first {
        return Err(module_error(
            form.span,
            format!("register range `{class} {first} {last}` runs backwards"),
        ));
    }
    Ok(RegisterRef {
        class,
        first: first as u32,
        last: last as u32,
    })
}

fn elaborate_register_refs(values: &[SExpr]) -> Result<Vec<RegisterRef>, ModuleError> {
    values.iter().map(elaborate_register_ref).collect()
}

fn elaborate_frame(values: &[SExpr], span: Span) -> Result<Frame, ModuleError> {
    let mut frame = Frame::default();
    for property in &values[1..] {
        let fields = list(property, "frame property")?;
        let name = atom(fields.first(), "frame property name")?.to_string();
        match name.as_str() {
            "growth" => frame.growth = scalar(fields, property.span, &name)?,
            "saved-area" => frame.saved_area = scalar(fields, property.span, &name)?,
            "slot-bytes" => frame.slot_bytes = numeric_property(fields, property.span, &name)?,
            "save-order" => frame.save_order = elaborate_register_refs(&fields[1..])?,
            "frame-pointer-at" => {
                frame.frame_pointer_at = scalar(fields, property.span, &name)?;
            }
            "max-frame-bytes" => {
                frame.max_frame_bytes = numeric_property(fields, property.span, &name)?;
            }
            "red-zone" => frame.red_zone = numeric_property(fields, property.span, &name)?,
            "regions" => frame.regions = scalar_list(&fields[1..])?,
            "spill" => {
                for entry in &fields[1..] {
                    let parts = list(entry, "spill slot")?;
                    if parts.len() != 3 {
                        return Err(module_error(
                            entry.span,
                            "spill slot is `(class bytes align)`",
                        ));
                    }
                    frame.spill.push(SpillSlot {
                        class: atom(parts.first(), "spill class")?.to_string(),
                        bytes: number(&parts[1], "spill bytes")?,
                        align: number(&parts[2], "spill align")?,
                    });
                }
            }
            "realignment" => frame.realignment = scalar(fields, property.span, &name)?,
            "dynamic-allocation" => {
                frame.dynamic_allocation = scalar(fields, property.span, &name)?;
            }
            "base-pointer" => {
                let refs = elaborate_register_refs(&fields[1..])?;
                match refs.as_slice() {
                    [entry] if entry.first == entry.last => {
                        frame.base_pointer = Some(entry.clone());
                    }
                    _ => {
                        return Err(module_error(
                            property.span,
                            "`base-pointer` names exactly one register",
                        ))
                    }
                }
            }
            "adjust" => frame.adjust = scalar(fields, property.span, &name)?,
            "save" => frame.save = scalar(fields, property.span, &name)?,
            "restore" => frame.restore = scalar(fields, property.span, &name)?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported frame property `{other}`"),
                ));
            }
        }
    }
    for (what, value) in [
        ("growth", &frame.growth),
        ("saved-area", &frame.saved_area),
        ("frame-pointer-at", &frame.frame_pointer_at),
        ("adjust", &frame.adjust),
        ("save", &frame.save),
        ("restore", &frame.restore),
    ] {
        if value.is_empty() {
            return Err(module_error(
                span,
                format!("frame requires `({what} ...)`"),
            ));
        }
    }
    Ok(frame)
}

fn elaborate_aggregates(values: &[SExpr], span: Span) -> Result<Aggregates, ModuleError> {
    let mut aggregates = Aggregates::default();
    for property in &values[1..] {
        let fields = list(property, "aggregates property")?;
        let name = atom(fields.first(), "aggregates property name")?.to_string();
        match name.as_str() {
            "max-register-bytes" => {
                aggregates.max_register_bytes =
                    numeric_property(fields, property.span, &name)?;
            }
            "split" => aggregates.split = scalar(fields, property.span, &name)?,
            "return-pointer" => {
                let refs = elaborate_register_refs(&fields[1..])?;
                match refs.as_slice() {
                    [entry] if entry.first == entry.last => {
                        aggregates.return_pointer = Some(entry.clone());
                    }
                    _ => {
                        return Err(module_error(
                            property.span,
                            "`return-pointer` names exactly one register",
                        ))
                    }
                }
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported aggregates property `{other}`"),
                ));
            }
        }
    }
    if aggregates.split.is_empty() {
        return Err(module_error(span, "aggregates requires `(split ...)`"));
    }
    Ok(aggregates)
}

fn elaborate_abi(form: &SExpr) -> Result<Abi, ModuleError> {
    let items = list(form, "defabi")?;
    let mut abi = Abi {
        name: atom(items.get(1), "defabi name")?.to_string(),
        ..Abi::default()
    };
    let single = |values: &[SExpr], span: Span, what: &str| -> Result<RegisterRef, ModuleError> {
        let refs = elaborate_register_refs(&values[1..])?;
        match refs.len() {
            1 if refs[0].first == refs[0].last => Ok(refs[0].clone()),
            _ => Err(module_error(
                span,
                format!("`{what}` names exactly one register"),
            )),
        }
    };
    for property in &items[2..] {
        let values = list(property, "defabi property")?;
        let property_name = atom(values.first(), "defabi property name")?.to_string();
        match property_name.as_str() {
            "isa" => abi.isa = scalar(values, property.span, &property_name)?,
            "pointer-bits" => {
                abi.pointer_bits = numeric_property(values, property.span, &property_name)?;
            }
            "stack-alignment" => {
                abi.stack_alignment = numeric_property(values, property.span, &property_name)?;
            }
            "stack-pointer" => {
                abi.stack_pointer = Some(single(values, property.span, "stack-pointer")?);
            }
            "frame-pointer" => {
                abi.frame_pointer = Some(single(values, property.span, "frame-pointer")?);
            }
            "link-register" => {
                abi.link_register = Some(single(values, property.span, "link-register")?);
            }
            "arguments" => abi.arguments = elaborate_register_refs(&values[1..])?,
            "returns" => abi.returns = elaborate_register_refs(&values[1..])?,
            "callee-saved" => abi.callee_saved = elaborate_register_refs(&values[1..])?,
            "caller-saved" => abi.caller_saved = elaborate_register_refs(&values[1..])?,
            "reserved" => abi.reserved = elaborate_register_refs(&values[1..])?,
            "frame" => abi.frame = Some(elaborate_frame(values, property.span)?),
            "aggregates" => {
                abi.aggregates = Some(elaborate_aggregates(values, property.span)?);
            }
            "description" => {
                abi.description = scalar(values, property.span, &property_name)?;
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defabi property `{other}`"),
                ));
            }
        }
    }
    if abi.isa.is_empty() {
        return Err(module_error(form.span, "defabi requires `(isa name)`"));
    }
    Ok(abi)
}

fn elaborate_personality(form: &SExpr) -> Result<Personality, ModuleError> {
    let items = list(form, "defpersonality")?;
    let name = atom(items.get(1), "defpersonality name")?.to_string();
    let mut mode = String::new();
    let mut implements = None;
    let mut discipline = Discipline::default();
    let mut capsule = Vec::new();
    let mut exports = Vec::new();
    let mut imports = Vec::new();
    let mut description = String::new();
    for property in &items[2..] {
        let values = list(property, "defpersonality property")?;
        match atom(values.first(), "defpersonality property name")? {
            "mode" => mode = scalar(values, property.span, "mode")?,
            "implements" => {
                implements = Some(scalar(values, property.span, "implements")?);
            }
            "discipline" => discipline = elaborate_discipline(values, property.span)?,
            "capsule" => capsule = scalar_list(&values[1..])?,
            "exports" => exports.push(elaborate_seam(values, property.span, true)?),
            "imports" => imports.push(elaborate_seam(values, property.span, false)?),
            "description" => description = scalar(values, property.span, "description")?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defpersonality property `{other}`"),
                ));
            }
        }
    }
    Ok(Personality {
        name,
        mode,
        implements: implements.ok_or_else(|| {
            module_error(form.span, "defpersonality requires `(implements isa-name)`")
        })?,
        discipline,
        capsule,
        exports,
        imports,
        description,
    })
}

fn elaborate_discipline(items: &[SExpr], span: Span) -> Result<Discipline, ModuleError> {
    if items.len() < 2 {
        return Err(module_error(
            span,
            "discipline expects a kind and optional `(name value)` parameters",
        ));
    }
    let kind = atom(items.get(1), "discipline kind")?.to_string();
    let mut params = Vec::new();
    let mut names = std::collections::HashSet::new();
    for parameter in &items[2..] {
        let pair = list(parameter, "discipline parameter")?;
        if pair.len() != 2 {
            return Err(module_error(
                parameter.span,
                "discipline parameter must be `(name value)`",
            ));
        }
        let name = atom(pair.first(), "discipline parameter name")?.to_string();
        if !names.insert(name.clone()) {
            return Err(module_error(
                parameter.span,
                format!("duplicate discipline parameter `{name}`"),
            ));
        }
        params.push((name, number(&pair[1], "discipline parameter value")?));
    }
    Ok(Discipline { kind, params })
}

fn elaborate_accelerator(
    form: &SExpr,
    library: &SemanticLibrary,
) -> Result<Accelerator, ModuleError> {
    let items = list(form, "defaccelerator")?;
    let name = atom(items.get(1), "defaccelerator name")?.to_string();
    let mut family = None;
    let mut subtype = String::new();
    let mut descriptor_version = 1;
    let mut descriptor_schema = String::new();
    let mut descriptor_bytes = 0;
    let mut launch_abi = String::new();
    let mut completion = String::new();
    let mut mmio_base = 0;
    let mut mmio_size = 0;
    let mut target = String::new();
    let mut coupling = String::new();
    let mut region_id = 0;
    let mut manifest_version = 0;
    let mut profile = "scalar".to_string();
    let mut backend_kind = "auto".to_string();
    let mut exec_shape = "scalar".to_string();
    let mut simd_lanes = 1;
    let mut element_width_bits = 0;
    let mut fallback_policy = "software".to_string();
    let mut visibility = String::new();
    let mut launch_fence = String::new();
    let mut in_flight = String::new();
    let mut contexts = 0u32;
    let mut context_id_bits = 0u32;
    let mut issue_queue_depth = 0u32;
    let mut identity: Vec<String> = Vec::new();
    let mut scheduling = String::new();
    let mut preemption = String::new();
    let mut service_interval_cycles = 0u32;
    let mut eligibility: Vec<String> = Vec::new();
    let mut ports = Vec::new();
    let mut semantics = String::new();
    let mut formal = None;
    let mut formal_named: Vec<(String, SExpr, Span)> = Vec::new();
    let mut latency_cycles = 1;
    let mut throughput_per_cycle = "1.0".to_string();
    let mut resources = Vec::new();

    for property in &items[2..] {
        let values = list(property, "defaccelerator property")?;
        let property_name = atom(values.first(), "defaccelerator property name")?;
        match property_name {
            "family" => family = Some(scalar(values, property.span, property_name)?),
            "subtype" => subtype = scalar(values, property.span, property_name)?,
            "descriptor-version" => {
                descriptor_version = numeric_property(values, property.span, property_name)?;
            }
            "descriptor-schema" => {
                descriptor_schema = scalar(values, property.span, property_name)?;
            }
            "descriptor-bytes" => {
                descriptor_bytes = numeric_property(values, property.span, property_name)?;
            }
            "launch-abi" => launch_abi = scalar(values, property.span, property_name)?,
            "completion" => completion = scalar(values, property.span, property_name)?,
            "mmio-base" => mmio_base = numeric_property(values, property.span, property_name)?,
            "mmio-size" => mmio_size = numeric_property(values, property.span, property_name)?,
            "target" => target = scalar(values, property.span, property_name)?,
            "coupling" => coupling = scalar(values, property.span, property_name)?,
            "region-id" => region_id = numeric_property(values, property.span, property_name)?,
            "manifest-version" => {
                manifest_version = numeric_property(values, property.span, property_name)?;
            }
            "profile" => profile = scalar(values, property.span, property_name)?,
            "backend-kind" => backend_kind = scalar(values, property.span, property_name)?,
            "exec-shape" => exec_shape = scalar(values, property.span, property_name)?,
            "simd-lanes" => {
                simd_lanes = numeric_property(values, property.span, property_name)?;
            }
            "element-width-bits" => {
                element_width_bits = numeric_property(values, property.span, property_name)?;
            }
            "fallback-policy" => {
                fallback_policy = scalar(values, property.span, property_name)?;
            }
            "visibility" => visibility = scalar(values, property.span, property_name)?,
            "launch-fence" => launch_fence = scalar(values, property.span, property_name)?,
            "in-flight" => in_flight = scalar(values, property.span, property_name)?,
            "contexts" => contexts = numeric_property(values, property.span, property_name)?,
            "context-id-bits" => {
                context_id_bits = numeric_property(values, property.span, property_name)?;
            }
            "issue-queue-depth" => {
                issue_queue_depth = numeric_property(values, property.span, property_name)?;
            }
            "identity" => identity = scalar_list(&values[1..])?,
            "scheduling" => scheduling = scalar(values, property.span, property_name)?,
            "preemption" => preemption = scalar(values, property.span, property_name)?,
            "service-interval-cycles" => {
                service_interval_cycles = numeric_property(values, property.span, property_name)?;
            }
            "eligibility" => eligibility = scalar_list(&values[1..])?,
            "ports" => {
                ports = values[1..]
                    .iter()
                    .map(elaborate_accelerator_port)
                    .collect::<Result<Vec<_>, _>>()?;
            }
            "semantics" => semantics = scalar(values, property.span, property_name)?,
            "formal" => {
                if values.len() < 2 {
                    return Err(module_error(
                        property.span,
                        "accelerator formal expects at least one semantic expression",
                    ));
                }
                // Two forms. `(formal <expr>)` states the single result of a
                // single-output engine. `(formal (result <port> <expr>) ...)`
                // names each output port, which is the only way an engine with
                // more than one result can say what the others are -- before it
                // existed the first output was typed and the rest were dropped
                // in silence.
                let is_named = |value: &SExpr| -> bool {
                    matches!(&value.kind, SExprKind::List(items)
                        if matches!(items.first().map(|head| &head.kind),
                                    Some(SExprKind::Atom(head)) if head == "result"))
                };
                if values[1..].iter().any(is_named) {
                    if !values[1..].iter().all(is_named) {
                        return Err(module_error(
                            property.span,
                            "accelerator formal mixes `(result port expr)` with a bare \
                             expression -- name every result or none of them",
                        ));
                    }
                    for value in &values[1..] {
                        let items = list(value, "accelerator formal result")?;
                        if items.len() != 3 {
                            return Err(module_error(
                                value.span,
                                "accelerator formal result must be `(result port expr)`",
                            ));
                        }
                        let port = atom(items.get(1), "accelerator formal result port")?;
                        formal_named.push((port.to_string(), items[2].clone(), value.span));
                    }
                } else {
                    if values.len() != 2 {
                        return Err(module_error(
                            property.span,
                            "accelerator formal expects one semantic expression, or one \
                             `(result port expr)` per output port",
                        ));
                    }
                    formal = Some(values[1].clone());
                }
            }
            "latency" => {
                latency_cycles = numeric_property(values, property.span, property_name)?;
            }
            "throughput" => {
                throughput_per_cycle = scalar(values, property.span, property_name)?;
            }
            "resources" => resources = scalar_list(&values[1..])?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defaccelerator property `{other}`"),
                ));
            }
        }
    }

    let outputs: Vec<&AcceleratorPort> = ports
        .iter()
        .filter(|port| matches!(port.direction.as_str(), "output" | "out"))
        .collect();
    let symbols: std::collections::HashMap<String, u32> = ports
        .iter()
        .map(|port| (port.name.clone(), port.width))
        .collect();

    // Each result is typed against ITS OWN port's width. Typing every result
    // against the first output -- what this did before -- is wrong the moment
    // two results differ in width, and wrong silently.
    let mut formal_results: Vec<AcceleratorResult> = Vec::new();
    if !formal_named.is_empty() {
        if outputs.is_empty() {
            return Err(module_error(
                form.span,
                "accelerator formal semantics requires an output port",
            ));
        }
        let mut seen: Vec<&str> = Vec::new();
        for (port_name, expression, span) in &formal_named {
            let port = outputs
                .iter()
                .find(|port| &port.name == port_name)
                .ok_or_else(|| {
                    module_error(
                        *span,
                        format!(
                            "accelerator formal names result `{port_name}`, which is not \
                             an output port of this accelerator"
                        ),
                    )
                })?;
            if seen.contains(&port_name.as_str()) {
                return Err(module_error(
                    *span,
                    format!("accelerator formal states result `{port_name}` twice"),
                ));
            }
            seen.push(port_name.as_str());
            formal_results.push(AcceleratorResult {
                port: port.name.clone(),
                expr: render(&library.expand_typed(expression, &symbols, port.width)?),
            });
        }
        // ⚠️ The hole this closes: an output port with no expression used to
        // emit nothing and pass, so the engine carried a proof obligation over
        // a strict subset of what it produced.
        if let Some(missing) = outputs.iter().find(|port| !seen.contains(&port.name.as_str())) {
            return Err(module_error(
                form.span,
                format!(
                    "accelerator declares output port `{}` but its formal semantics \
                     never say what it produces -- every result must be stated",
                    missing.name
                ),
            ));
        }
        // Port order, not the order they were written, so emission is stable.
        formal_results.sort_by_key(|result| {
            outputs
                .iter()
                .position(|port| port.name == result.port)
                .unwrap_or(usize::MAX)
        });
    } else if let Some(expression) = formal {
        let port = match outputs.as_slice() {
            [] => {
                return Err(module_error(
                    form.span,
                    "accelerator formal semantics requires an output port",
                ))
            }
            [only] => *only,
            many => {
                return Err(module_error(
                    form.span,
                    format!(
                        "accelerator has {} output ports but states one unnamed formal \
                         expression, which can only define the first -- write one \
                         `(result port expr)` per output port",
                        many.len()
                    ),
                ))
            }
        };
        formal_results.push(AcceleratorResult {
            port: port.name.clone(),
            expr: render(&library.expand_typed(&expression, &symbols, port.width)?),
        });
    }
    let formal_semantics = formal_results
        .first()
        .map(|result| result.expr.clone())
        .unwrap_or_default();

    Ok(Accelerator {
        descriptor: None,
        name,
        family: family
            .ok_or_else(|| module_error(form.span, "defaccelerator requires `(family name)`"))?,
        subtype,
        descriptor_version,
        descriptor_schema,
        descriptor_bytes,
        launch_abi,
        completion,
        visibility,
        launch_fence,
        in_flight,
        mmio_base,
        mmio_size,
        target,
        coupling,
        region_id,
        manifest_version,
        profile,
        backend_kind,
        exec_shape,
        simd_lanes,
        element_width_bits,
        fallback_policy,
        contexts,
        context_id_bits,
        issue_queue_depth,
        identity,
        scheduling,
        preemption,
        service_interval_cycles,
        eligibility,
        ports,
        semantics,
        formal_semantics,
        formal_results,
        latency_cycles,
        throughput_per_cycle,
        resources,
    })
}

fn elaborate_accelerator_port(form: &SExpr) -> Result<AcceleratorPort, ModuleError> {
    let items = list(form, "accelerator port")?;
    if items.len() != 4 {
        return Err(module_error(
            form.span,
            "accelerator port must be `(name direction kind type)`",
        ));
    }
    Ok(AcceleratorPort {
        name: atom(items.first(), "accelerator port name")?.to_string(),
        direction: atom(items.get(1), "accelerator port direction")?.to_string(),
        kind: atom(items.get(2), "accelerator port kind")?.to_string(),
        width: type_width(atom(items.get(3), "accelerator port type")?, items[3].span)?,
    })
}

fn elaborate_memory(form: &SExpr) -> Result<Memory, ModuleError> {
    let items = list(form, "defmemory")?;
    let mut memory = Memory {
        name: atom(items.get(1), "defmemory name")?.to_string(),
        ..Memory::default()
    };
    let mut saw_size = false;
    for property in &items[2..] {
        let values = list(property, "defmemory property")?;
        let property_name = atom(values.first(), "defmemory property name")?;
        match property_name {
            "kind" => memory.kind = scalar(values, property.span, property_name)?,
            "size-bytes" => {
                memory.size_bytes = wide_number_property(values, property.span, property_name)?;
                saw_size = true;
            }
            "ports" => memory.ports = numeric_property(values, property.span, property_name)?,
            "latency-cycles" => {
                memory.latency_cycles = numeric_property(values, property.span, property_name)?;
            }
            "width-bits" => {
                memory.width_bits = numeric_property(values, property.span, property_name)?;
            }
            "banks" => memory.banks = numeric_property(values, property.span, property_name)?,
            "line-bytes" => {
                memory.line_bytes = numeric_property(values, property.span, property_name)?
            }
            "ways" => memory.ways = numeric_property(values, property.span, property_name)?,
            "attributes" => memory.attributes = scalar_list(&values[1..])?,
            other => match crate::memsys::memory_property(&mut memory, values, property.span) {
                Some(result) => result.map_err(|(span, m)| module_error(span, m))?,
                None => {
                    return Err(module_error(
                        property.span,
                        format!("unsupported defmemory property `{other}`"),
                    ));
                }
            },
        }
    }
    if !saw_size {
        return Err(module_error(
            form.span,
            "defmemory requires `(size-bytes number)`",
        ));
    }
    Ok(memory)
}

fn elaborate_tile(form: &SExpr) -> Result<Tile, ModuleError> {
    let items = list(form, "deftile")?;
    let name = atom(items.get(1), "deftile name")?.to_string();
    let mut cores = Vec::new();
    let mut accelerators = Vec::new();
    let mut memories = Vec::new();
    let mut interconnect = String::new();
    for property in &items[2..] {
        let values = list(property, "deftile property")?;
        match atom(values.first(), "deftile property name")? {
            "cores" => cores = scalar_list(&values[1..])?,
            "accelerators" => accelerators = scalar_list(&values[1..])?,
            "memories" => memories = scalar_list(&values[1..])?,
            "interconnect" => {
                interconnect = scalar(values, property.span, "interconnect")?;
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported deftile property `{other}`"),
                ));
            }
        }
    }
    Ok(Tile {
        name,
        cores,
        accelerators,
        memories,
        interconnect,
    })
}

/// The compass offsets a neighbour pattern names. Row 0 is the top, so `north`
/// decreases the row -- stated once here rather than in the reader and the
/// manifest separately, which is how two derivations of a grid disagree.
const FABRIC_DIRECTIONS: &[(&str, i64, i64)] = &[
    ("north", -1, 0),
    ("south", 1, 0),
    ("east", 0, 1),
    ("west", 0, -1),
];

fn elaborate_fabric(form: &SExpr) -> Result<Fabric, ModuleError> {
    let items = list(form, "deffabric")?;
    let mut fabric = Fabric {
        name: atom(items.get(1), "deffabric name")?.to_string(),
        ii_max: 1,
        contexts: 1,
        ..Fabric::default()
    };
    // Neighbour patterns are collected and expanded after the grid is known,
    // since `(links (north 1))` means nothing until `rows` and `cols` are read
    // and a property list has no required order.
    let mut patterns: Vec<(String, u32)> = Vec::new();
    let mut explicit: Vec<FabricLink> = Vec::new();
    for property in &items[2..] {
        let values = list(property, "deffabric property")?;
        match atom(values.first(), "deffabric property name")? {
            "rows" => fabric.rows = numeric_property(values, property.span, "rows")?,
            "cols" => fabric.cols = numeric_property(values, property.span, "cols")?,
            "ii-max" => fabric.ii_max = numeric_property(values, property.span, "ii-max")?,
            "contexts" => {
                fabric.contexts = numeric_property(values, property.span, "contexts")?;
            }
            "description" => {
                fabric.description = scalar(values, property.span, "description")?;
            }
            // A `pe` clause naming rows describes those rows; one naming none
            // is the fabric's default. A uniform grid writes one clause and
            // reads exactly as it did before.
            "pe" => {
                let mut class = crate::ast::FabricPeClass::default();
                let mut scoped = false;
                for entry in &values[1..] {
                    let fields = list(entry, "deffabric pe entry")?;
                    match atom(fields.first(), "deffabric pe field")? {
                        "row" => {
                            let row = numeric_property(fields, entry.span, "row")?;
                            class.first_row = row;
                            class.last_row = row;
                            scoped = true;
                        }
                        "rows" => {
                            if fields.len() != 3 {
                                return Err(module_error(
                                    entry.span,
                                    "deffabric pe `rows` is `(rows <first> <last>)`, inclusive",
                                ));
                            }
                            class.first_row = atom(fields.get(1), "pe rows first")?
                                .parse()
                                .map_err(|_| {
                                    module_error(entry.span, "pe `rows` bounds must be numbers")
                                })?;
                            class.last_row = atom(fields.get(2), "pe rows last")?
                                .parse()
                                .map_err(|_| {
                                    module_error(entry.span, "pe `rows` bounds must be numbers")
                                })?;
                            scoped = true;
                        }
                        "units" => class.units = scalar_list(&fields[1..])?,
                        "regs" => class.regs = numeric_property(fields, entry.span, "regs")?,
                        "const" => class.consts = numeric_property(fields, entry.span, "const")?,
                        other => {
                            return Err(module_error(
                                entry.span,
                                format!("unsupported deffabric pe field `{other}`"),
                            ))
                        }
                    }
                }
                if scoped {
                    fabric.pe_rows.push(class);
                } else {
                    fabric.units = class.units;
                    fabric.regs = class.regs;
                    fabric.consts = class.consts;
                }
            }
            "links" => {
                for entry in &values[1..] {
                    let fields = list(entry, "deffabric link")?;
                    let head = atom(fields.first(), "deffabric link name")?.to_string();
                    if FABRIC_DIRECTIONS.iter().any(|(name, _, _)| *name == head) {
                        patterns.push((head, numeric_property(fields, entry.span, "latency")?));
                    } else {
                        return Err(module_error(
                            entry.span,
                            format!(
                                "unsupported link direction `{head}` (expected north, south, \
                                 east or west, or an explicit `(link ...)`)"
                            ),
                        ));
                    }
                }
            }
            // `(vliw-row <index> <packet>)`: this row's PEs are that packet's
            // slots, the same hardware issued two ways.
            "mode" => fabric.mode = scalar(values, property.span, "mode")?,
            "vliw-row" => {
                if values.len() != 3 {
                    return Err(module_error(
                        property.span,
                        "vliw-row is `(vliw-row <row> <packet>)`",
                    ));
                }
                let row = atom(values.get(1), "vliw-row index")?
                    .parse()
                    .map_err(|_| module_error(property.span, "vliw-row index must be a number"))?;
                let packet = atom(values.get(2), "vliw-row packet")?.to_string();
                fabric.vliw_row = Some((row, packet));
            }
            "link" => explicit.push(elaborate_explicit_link(property)?),
            "memory-ports" => {
                for entry in &values[1..] {
                    let fields = list(entry, "deffabric memory port")?;
                    if atom(fields.first(), "deffabric memory port")? != "row" {
                        return Err(module_error(
                            entry.span,
                            "memory-ports entries are `(row <index> <memory>)`",
                        ));
                    }
                    let row = atom(fields.get(1), "memory port row")?
                        .parse()
                        .map_err(|_| module_error(entry.span, "memory port row must be a number"))?;
                    let memory = atom(fields.get(2), "memory port memory")?.to_string();
                    fabric.ports.push(FabricPort { row, memory });
                }
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported deffabric property `{other}`"),
                ));
            }
        }
    }
    // A pattern is an edge for every PE whose neighbour is on the grid. Edges
    // off the grid are simply absent, which is what makes a mesh a mesh rather
    // than a torus -- a torus would be a different pattern name, not a flag.
    for (direction, latency) in patterns {
        let (row_delta, col_delta) = FABRIC_DIRECTIONS
            .iter()
            .find(|(name, _, _)| *name == direction)
            .map(|(_, row, col)| (*row, *col))
            .expect("direction was validated above");
        for (row, col) in fabric.positions() {
            let to_row = row as i64 + row_delta;
            let to_col = col as i64 + col_delta;
            if to_row < 0 || to_col < 0 {
                continue;
            }
            let (to_row, to_col) = (to_row as u32, to_col as u32);
            if !fabric.holds(to_row, to_col) {
                continue;
            }
            fabric.links.push(FabricLink {
                from_row: row,
                from_col: col,
                to_row,
                to_col,
                latency,
                direction: direction.clone(),
            });
        }
    }
    fabric.links.extend(explicit);
    Ok(fabric)
}

/// `(link (0 0) (2 3) (latency 2))` -- the irregular topologies and buses a
/// compass pattern cannot describe.
fn elaborate_explicit_link(form: &SExpr) -> Result<FabricLink, ModuleError> {
    let items = list(form, "link")?;
    let position = |index: usize, what: &str| -> Result<(u32, u32), ModuleError> {
        let pair = list(
            items
                .get(index)
                .ok_or_else(|| module_error(form.span, format!("link is missing its {what}")))?,
            "link position",
        )?;
        let row = atom(pair.first(), "link row")?
            .parse()
            .map_err(|_| module_error(form.span, "link row must be a number"))?;
        let col = atom(pair.get(1), "link column")?
            .parse()
            .map_err(|_| module_error(form.span, "link column must be a number"))?;
        Ok((row, col))
    };
    let (from_row, from_col) = position(1, "source")?;
    let (to_row, to_col) = position(2, "destination")?;
    // `(latency N)` and, optionally, `(direction north)`. The direction is what
    // the compact `(links (north 1) ...)` form leaves on every link it expands,
    // and a link is not fully stated without it: `emit-lisp` writes links
    // explicitly, and recognising a compass pattern in a link set to write the
    // compact form back would be inference where a field already holds the
    // answer.
    let mut latency = 1;
    let mut direction = String::new();
    for entry in &items[3..] {
        let fields = list(entry, "link property")?;
        match atom(fields.first(), "link property")? {
            "latency" => latency = numeric_property(fields, entry.span, "latency")?,
            "direction" => direction = scalar(fields, entry.span, "direction")?,
            other => {
                return Err(module_error(
                    entry.span,
                    format!("unsupported link property `{other}`"),
                ))
            }
        }
    }
    Ok(FabricLink {
        from_row,
        from_col,
        to_row,
        to_col,
        latency,
        direction,
    })
}

/// `(pe R C)` or `(R C)` -- a grid position.
fn elaborate_position(form: &SExpr, what: &str) -> Result<(u32, u32), ModuleError> {
    let items = list(form, what)?;
    let head = atom(items.first(), what)?;
    let offset = if head == "pe" { 1 } else { 0 };
    let number = |index: usize| -> Result<u32, ModuleError> {
        atom(items.get(index), what)?
            .parse()
            .map_err(|_| module_error(form.span, format!("{what} coordinates must be numbers")))
    };
    Ok((number(offset)?, number(offset + 1)?))
}

/// `(defchannel <name> (protocol ready-valid) (latency 1 4) (capacity 2)
///  (order preserving) (description "..."))`
///
/// The latency is a *window*, which is the whole difference from a statically
/// timed route: a consumer may assume the minimum and must tolerate the
/// maximum, and what it may not do is depend on which arrives.
fn elaborate_channel(form: &SExpr) -> Result<crate::ast::Channel, ModuleError> {
    let items = list(form, "defchannel")?;
    let mut channel = crate::ast::Channel {
        name: atom(items.get(1), "defchannel name")?.to_string(),
        ..crate::ast::Channel::default()
    };
    for property in &items[2..] {
        let values = list(property, "defchannel property")?;
        match atom(values.first(), "defchannel property name")? {
            "protocol" => channel.protocol = scalar(values, property.span, "protocol")?,
            "order" => channel.order = scalar(values, property.span, "order")?,
            "capacity" => {
                channel.capacity = numeric_property(values, property.span, "capacity")?;
            }
            "initial" => {
                channel.initial = numeric_property(values, property.span, "initial")?;
            }
            "latency" => {
                // Two numbers, not one: a window is the point.
                if values.len() != 3 {
                    return Err(module_error(
                        property.span,
                        "channel latency is a window: `(latency <min> <max>)`",
                    ));
                }
                channel.latency_min = number(&values[1], "latency minimum")? as u32;
                channel.latency_max = number(&values[2], "latency maximum")? as u32;
            }
            "description" => {
                channel.description = scalar(values, property.span, "description")?;
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defchannel property `{other}`"),
                ))
            }
        }
    }
    Ok(channel)
}

fn elaborate_mapping(form: &SExpr) -> Result<Mapping, ModuleError> {
    let items = list(form, "defmapping")?;
    let mut mapping = Mapping {
        name: atom(items.get(1), "defmapping name")?.to_string(),
        ii: 1,
        ..Mapping::default()
    };
    for property in &items[2..] {
        let values = list(property, "defmapping property")?;
        match atom(values.first(), "defmapping property name")? {
            "fabric" => mapping.fabric = scalar(values, property.span, "fabric")?,
            "ii" => mapping.ii = numeric_property(values, property.span, "ii")?,
            "description" => {
                mapping.description = scalar(values, property.span, "description")?;
            }
            "equivalent-to" => mapping.equivalent_to = scalar_list(&values[1..])?,
            "place" => {
                for entry in &values[1..] {
                    let fields = list(entry, "defmapping placement")?;
                    let id = atom(fields.first(), "placement id")?.to_string();
                    let mnemonic = atom(fields.get(1), "placement mnemonic")?.to_string();
                    let mut row = 0;
                    let mut col = 0;
                    let mut cycle = 0;
                    let mut saw_pe = false;
                    for field in &fields[2..] {
                        let parts = list(field, "placement field")?;
                        match atom(parts.first(), "placement field name")? {
                            "pe" => {
                                (row, col) = elaborate_position(field, "placement pe")?;
                                saw_pe = true;
                            }
                            "cycle" => cycle = numeric_property(parts, field.span, "cycle")?,
                            other => {
                                return Err(module_error(
                                    field.span,
                                    format!("unsupported placement field `{other}`"),
                                ))
                            }
                        }
                    }
                    if !saw_pe {
                        return Err(module_error(
                            entry.span,
                            format!("placement `{id}` does not say which PE it runs on"),
                        ));
                    }
                    mapping.ops.push(MappingOp { id, mnemonic, row, col, cycle });
                }
            }
            // `(live-in (op operand (reg N)) (op operand (const V)))`: where an
            // operand no route feeds gets its value. A CGRA has both sources --
            // the register file the VLIW shares, and the constant each PE
            // holds -- and which one it is decides what the kernel reads.
            "live-in" => {
                for entry in &values[1..] {
                    let fields = list(entry, "defmapping live-in")?;
                    if fields.len() != 3 {
                        return Err(module_error(
                            entry.span,
                            "live-in entries are `(<op> <operand> (reg <n>))` or \
                             `(<op> <operand> (const <v>))`",
                        ));
                    }
                    let op = atom(fields.first(), "live-in op")?.to_string();
                    let operand = atom(fields.get(1), "live-in operand")?.to_string();
                    let spec = list(&fields[2], "live-in source")?;
                    let source = match atom(spec.first(), "live-in source kind")? {
                        "reg" => crate::ast::MappingSource::Register(
                            atom(spec.get(1), "live-in register")?.parse().map_err(|_| {
                                module_error(entry.span, "live-in register must be a number")
                            })?,
                        ),
                        "const" => crate::ast::MappingSource::Constant(
                            atom(spec.get(1), "live-in constant")?.parse().map_err(|_| {
                                module_error(entry.span, "live-in constant must be a number")
                            })?,
                        ),
                        other => {
                            return Err(module_error(
                                entry.span,
                                format!("live-in source is `reg` or `const`, not `{other}`"),
                            ))
                        }
                    };
                    mapping.live_in.push(crate::ast::MappingLiveIn { op, operand, source });
                }
            }
            // `(live-out (op (reg N)))`: which register a result is left in.
            "live-out" => {
                for entry in &values[1..] {
                    let fields = list(entry, "defmapping live-out")?;
                    if fields.len() != 2 {
                        return Err(module_error(
                            entry.span,
                            "live-out entries are `(<op> (reg <n>))`",
                        ));
                    }
                    let op = atom(fields.first(), "live-out op")?.to_string();
                    let spec = list(&fields[1], "live-out register")?;
                    if atom(spec.first(), "live-out source kind")? != "reg" {
                        return Err(module_error(
                            entry.span,
                            "a live-out names a register: `(<op> (reg <n>))`",
                        ));
                    }
                    let register = atom(spec.get(1), "live-out register")?
                        .parse()
                        .map_err(|_| {
                            module_error(entry.span, "live-out register must be a number")
                        })?;
                    mapping.live_out.push(crate::ast::MappingLiveOut { op, register });
                }
            }
            "route" => {
                for entry in &values[1..] {
                    let fields = list(entry, "defmapping route")?;
                    let from = atom(fields.first(), "route source")?.to_string();
                    if atom(fields.get(1), "route arrow")? != "->" {
                        return Err(module_error(
                            entry.span,
                            "a route is `(<from> -> <to> (via ...) (cycle N))`",
                        ));
                    }
                    let to = atom(fields.get(2), "route destination")?.to_string();
                    let mut via = Vec::new();
                    let mut cycle = 0;
                    let mut operand = String::new();
                    let mut distance = 0;
                    let mut channel = String::new();
                    for field in &fields[3..] {
                        let parts = list(field, "route field")?;
                        match atom(parts.first(), "route field name")? {
                            "operand" => {
                                operand = scalar(parts, field.span, "operand")?;
                            }
                            "via" => {
                                for position in &parts[1..] {
                                    via.push(elaborate_position(position, "route via")?);
                                }
                            }
                            "cycle" => cycle = numeric_property(parts, field.span, "cycle")?,
                            "distance" => {
                                distance = numeric_property(parts, field.span, "distance")?;
                            }
                            // The route crosses an elastic channel, so its
                            // arrival is a window rather than a cycle.
                            "channel" => {
                                channel = scalar(parts, field.span, "channel")?;
                            }
                            other => {
                                return Err(module_error(
                                    field.span,
                                    format!("unsupported route field `{other}`"),
                                ))
                            }
                        }
                    }
                    if operand.is_empty() {
                        return Err(module_error(
                            entry.span,
                            format!(
                                "route `{from}` -> `{to}` does not say which operand it \
                                 feeds; add `(operand <name>)`"
                            ),
                        ));
                    }
                    mapping.routes.push(MappingRoute {
                        from,
                        to,
                        operand,
                        via,
                        cycle,
                        distance,
                        channel,
                    });
                }
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defmapping property `{other}`"),
                ));
            }
        }
    }
    Ok(mapping)
}

fn elaborate_format(form: &SExpr) -> Result<Format, ModuleError> {
    let items = list(form, "defformat")?;
    let name = atom(items.get(1), "defformat name")?.to_string();
    let mut bits = 32;
    let mut fields = Vec::new();
    for property in &items[2..] {
        let values = list(property, "defformat property")?;
        match atom(values.first(), "defformat property name")? {
            "bits" => bits = numeric_property(values, property.span, "bits")?,
            "fields" => {
                fields = values[1..]
                    .iter()
                    .map(elaborate_format_field)
                    .collect::<Result<Vec<_>, _>>()?
            }
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported defformat property `{other}`"),
                ));
            }
        }
    }
    if fields.is_empty() {
        return Err(module_error(form.span, "defformat requires fields"));
    }
    Ok(Format { name, bits, fields })
}

fn elaborate_format_field(form: &SExpr) -> Result<FormatField, ModuleError> {
    let items = list(form, "format field")?;
    let name = atom(items.first(), "format field name")?.to_string();
    let numbers = items[1..]
        .iter()
        .map(|item| number(item, "format field bit"))
        .collect::<Result<Vec<_>, _>>()?;
    let (insn_hi, insn_lo, op_hi, op_lo) = match numbers.as_slice() {
        [bit] => (*bit, *bit, None, None),
        [hi, lo] => (*hi, *lo, None, None),
        [hi, lo, operand_hi, operand_lo] => (*hi, *lo, Some(*operand_hi), Some(*operand_lo)),
        _ => {
            return Err(module_error(
                form.span,
                "format field must be `(name bit)`, `(name hi lo)`, or `(name hi lo operand-hi operand-lo)`",
            ));
        }
    };
    Ok(FormatField {
        name,
        insn_hi,
        insn_lo,
        op_hi,
        op_lo,
    })
}

fn elaborate_instruction(
    form: &SExpr,
    library: &SemanticLibrary,
    kernels: &std::collections::HashMap<String, SExpr>,
    descriptors: &std::collections::HashMap<String, Descriptor>,
) -> Result<Instruction, ModuleError> {
    let items = list(form, "definstruction")?;
    let name = atom(items.get(1), "definstruction name")?.to_string();
    let mut instruction = Instruction {
        name: name.to_lowercase().replace('-', "_"),
        mnemonic: name,
        ..Instruction::default()
    };
    let mut formal = None;
    let mut behavior = None;
    let mut runs_kernel_span = None;
    let mut launches_span = None;
    for property in &items[2..] {
        let values = list(property, "definstruction property")?;
        let property_name = atom(values.first(), "definstruction property name")?;
        match property_name {
            "mnemonic" => instruction.mnemonic = scalar(values, property.span, property_name)?,
            "isa" => instruction.isa = scalar(values, property.span, property_name)?,
            "format" => instruction.format = scalar(values, property.span, property_name)?,
            "opcode" => {
                instruction.opcode = numeric_property(values, property.span, property_name)?
            }
            "func3" => instruction.func3 = numeric_property(values, property.span, property_name)?,
            "func7" => instruction.func7 = numeric_property(values, property.span, property_name)?,
            "encoding" => instruction.encoding = elaborate_encoding(&values[1..])?,
            "operands" => {
                instruction.operands = values[1..]
                    .iter()
                    .map(elaborate_operand)
                    .collect::<Result<Vec<_>, _>>()?
            }
            "modes" => instruction.modes = scalar_list(&values[1..])?,
            "unit" => instruction.unit = scalar(values, property.span, "unit")?,
            "runs-kernel" => {
                if values.len() < 2 {
                    return Err(module_error(
                        property.span,
                        "runs-kernel expects `(runs-kernel <kernel> <operand>...)`",
                    ));
                }
                instruction.runs_kernel = values[1..]
                    .iter()
                    .map(|value| atom(Some(value), "runs-kernel argument").map(str::to_string))
                    .collect::<Result<Vec<_>, _>>()?;
                runs_kernel_span = Some(property.span);
            }
            "launches" => {
                if values.len() < 3 {
                    return Err(module_error(
                        property.span,
                        "launches expects `(launches <descriptor> <base-operand> [<kernel> <argument>...])`",
                    ));
                }
                instruction.launches = values[1..]
                    .iter()
                    .map(|value| atom(Some(value), "launches argument").map(str::to_string))
                    .collect::<Result<Vec<_>, _>>()?;
                launches_span = Some(property.span);
            }
            "configures" => {
                instruction.configures = scalar(values, property.span, "configures")?
            }
            "runs-mapping" => {
                instruction.runs_mapping = scalar(values, property.span, "runs-mapping")?
            }
            "asm" => instruction.asm = scalar(values, property.span, property_name)?,
            "description" => {
                instruction.description = scalar(values, property.span, property_name)?
            }
            "category" => instruction.category = scalar(values, property.span, property_name)?,
            "semantics" => instruction.semantics = scalar(values, property.span, property_name)?,
            "formal" => {
                if values.len() != 2 {
                    return Err(module_error(
                        property.span,
                        "formal expects one semantic expression",
                    ));
                }
                formal = Some(values[1].clone());
            }
            "behavior" => {
                if behavior.is_some() {
                    return Err(module_error(
                        property.span,
                        "instruction has more than one behavior form",
                    ));
                }
                behavior = Some((values[1..].to_vec(), property.span));
            }
            "requires" => {
                if values.len() != 2 {
                    return Err(module_error(
                        property.span,
                        "requires expects one decode predicate",
                    ));
                }
                instruction.decode_requires = elaborate_requires(&values[1])?;
            }
            "latency" => {
                instruction.latency_cycles = numeric_property(values, property.span, property_name)?
            }
            "throughput" => {
                instruction.throughput_per_cycle = scalar(values, property.span, property_name)?
            }
            "area-estimate-um2" => {
                instruction.area_estimate_um2 = scalar(values, property.span, property_name)?
            }
            "power-estimate-mw" => {
                instruction.power_estimate_mw = scalar(values, property.span, property_name)?
            }
            "expected-speedup" => {
                instruction.expected_speedup = scalar(values, property.span, property_name)?
            }
            "intrinsic" => instruction.intrinsic = scalar(values, property.span, property_name)?,
            "implementation" => {
                instruction.implementation = scalar(values, property.span, property_name)?
            }
            "patterns" => instruction.patterns = scalar_list(&values[1..])?,
            "applicable-patterns" => instruction.applicable_patterns = scalar_list(&values[1..])?,
            "rationale" => instruction.rationale = scalar(values, property.span, property_name)?,
            other => {
                return Err(module_error(
                    property.span,
                    format!("unsupported definstruction property `{other}`"),
                ));
            }
        }
    }
    if let Some(formal) = formal {
        let symbols = instruction
            .operands
            .iter()
            .filter(|operand| operand.input)
            .map(|operand| (operand.name.clone(), operand.width))
            .collect();
        let result_width = instruction
            .operands
            .iter()
            .find(|operand| operand.output)
            .map(|operand| operand.width)
            .ok_or_else(|| {
                module_error(
                    form.span,
                    "instruction with formal semantics requires an output operand",
                )
            })?;
        instruction.formal_semantics =
            render(&library.expand_typed(&formal, &symbols, result_width)?);
    }
    if let Some(span) = runs_kernel_span {
        let statements = kernel_statements(&instruction.runs_kernel, kernels, span)?;
        instruction.kernel_effects = statements
            .iter()
            .map(|statement| elaborate_behavior_statements(statement, library))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; ");
        // A launch that states no behavior of its own IS the kernel. One that
        // does keeps its own, and parser.rs holds the two to agreement once
        // both have been through the same expansions.
        if behavior.is_none() {
            instruction.behavior_from_kernel = true;
            behavior = Some((statements, span));
        }
    }
    if let Some(span) = launches_span {
        // A descriptor launch DERIVES its behavior; there is no second copy
        // to hold it to, so writing one as well is refused rather than
        // silently preferred.
        if behavior.is_some() || runs_kernel_span.is_some() {
            return Err(module_error(
                span,
                "an instruction that launches a descriptor takes its behavior from the launch; \
                 it cannot also state `behavior` or `runs-kernel`",
            ));
        }
        let statements =
            descriptor_launch_statements(&instruction, descriptors, kernels, span)?;
        instruction.behavior_from_launch = true;
        behavior = Some((statements, span));
    }
    if let Some((statements, span)) = behavior {
        if statements.is_empty() {
            return Err(module_error(
                span,
                "behavior requires at least one statement",
            ));
        }
        instruction.effects = statements
            .iter()
            .map(|statement| elaborate_behavior_statements(statement, library))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join("; ");
        crate::parser::desugar_effects(&mut instruction, span.line)
            .map_err(|error| module_error(span, error.to_string()))?;
    }
    crate::parser::desugar_decode_constraint(&mut instruction, form.span.line)
        .map_err(|error| module_error(form.span, error.message))?;
    Ok(instruction)
}

/// Elaborate the Lisp behavior surface into the canonical effect statement
/// representation. The existing effect parser remains the single typed
/// validation and execution boundary for both source syntaxes.
/// Largest number of iterations a behavior loop may name. A statement loop
/// multiplies an instruction's effects, so this bounds how large one
/// instruction can get.
const MAX_BEHAVIOR_ITERATIONS: u32 = 256;

fn elaborate_behavior_statement(
    form: &SExpr,
    library: &SemanticLibrary,
) -> Result<String, ModuleError> {
    let items = list(form, "behavior statement")?;
    let head = atom(items.first(), "behavior statement head")?;
    match head {
        "set" => {
            if items.len() != 3 {
                return Err(module_error(form.span, "set must be `(set target value)`"));
            }
            Ok(format!(
                "set {} = {}",
                atom(items.get(1), "set target")?,
                render_effect_expr(&items[2], library)?
            ))
        }
        "setreg" => {
            if !matches!(items.len(), 4 | 5) {
                return Err(module_error(
                    form.span,
                    "setreg must be `(setreg kind index value)` or `(setreg kind index type value)`",
                ));
            }
            let kind = atom(items.get(1), "setreg kind")?;
            let index = number(&items[2], "setreg index")?;
            if items.len() == 5 {
                Ok(format!(
                    "setreg({kind}, {index}, {}, {})",
                    atom(items.get(3), "setreg type")?,
                    render_effect_expr(&items[4], library)?
                ))
            } else {
                Ok(format!(
                    "setreg({kind}, {index}, {})",
                    render_effect_expr(&items[3], library)?
                ))
            }
        }
        "setstate" => {
            if items.len() != 4 {
                return Err(module_error(
                    form.span,
                    "setstate must be `(setstate name value type)`",
                ));
            }
            let state = atom(items.get(1), "setstate name")?;
            let ty = atom(items.get(3), "setstate type")?;
            type_width(ty, items[3].span)?;
            Ok(format!(
                "setstate({}, {}, {})",
                state,
                render_effect_expr(&items[2], library)?,
                ty
            ))
        }
        "store" | "atomic_store" | "atomic-store" => {
            if !matches!(items.len(), 4 | 5) {
                return Err(module_error(
                    form.span,
                    "store must be `(store|atomic_store address value type [relaxed|release])`",
                ));
            }
            let ty = atom(items.get(3), "store type")?;
            type_width(ty, items[3].span)?;
            let order = if items.len() == 5 {
                let order = atom(items.get(4), "store memory order")?;
                if !matches!(order, "relaxed" | "release") {
                    return Err(module_error(
                        items[4].span,
                        "store memory order must be `relaxed` or `release`",
                    ));
                }
                format!(", {order}")
            } else {
                String::new()
            };
            Ok(format!(
                "{}({}, {}, {}{})",
                if head == "atomic-store" {
                    "atomic_store"
                } else {
                    head
                },
                render_effect_expr(&items[1], library)?,
                render_effect_expr(&items[2], library)?,
                ty,
                order
            ))
        }
        // ⚠️ `(send port value type)`. Three parts, like a store, because the
        // question is the same one: where it goes, what goes, how wide. No
        // ordering argument -- a posted message is posted, and an ISA that
        // orders its sends against its stores says so with `(barrier ...)`,
        // which is the effect that already means that.
        "send" => {
            if items.len() != 4 {
                return Err(module_error(
                    form.span,
                    "send must be `(send port value type)`",
                ));
            }
            let ty = atom(items.get(3), "send type")?;
            type_width(ty, items[3].span)?;
            Ok(format!(
                "send({}, {}, {})",
                render_effect_expr(&items[1], library)?,
                render_effect_expr(&items[2], library)?,
                ty
            ))
        }
        "setpc" => {
            if items.len() != 2 {
                return Err(module_error(form.span, "setpc must be `(setpc target)`"));
            }
            Ok(format!(
                "setpc({})",
                render_effect_expr(&items[1], library)?
            ))
        }
        "barrier" => {
            if !(2..=3).contains(&items.len()) {
                return Err(module_error(
                    form.span,
                    "barrier must be `(barrier <kind> [option])` for a kind in effects::BARRIER_KINDS",
                ));
            }
            let kind = atom(items.get(1), "barrier kind")?;
            let Some(found) = crate::effects::barrier_kind(kind) else {
                return Err(module_error(
                    items[1].span,
                    "barrier kind must be a supported architectural barrier",
                ));
            };
            // Whether an option is there to be written is the kind's own, the
            // same rule the effect parser applies -- `fence.i` has no option
            // field, so naming one would claim an encoding that does not exist.
            if (found.option_bits == 0) != (items.len() == 2) {
                return Err(module_error(
                    form.span,
                    if found.option_bits == 0 {
                        "this barrier kind takes no option"
                    } else {
                        "this barrier kind takes an option"
                    },
                ));
            }
            Ok(match items.get(2) {
                Some(option) => {
                    format!("barrier({kind}, {})", render_effect_expr(option, library)?)
                }
                None => format!("barrier({kind})"),
            })
        }
        "trap" => {
            if items.len() != 2 {
                return Err(module_error(form.span, "trap must be `(trap cause)`"));
            }
            Ok(format!("trap({})", atom(items.get(1), "trap cause")?))
        }
        "when" => {
            if items.len() != 3 {
                return Err(module_error(
                    form.span,
                    "when must be `(when condition statement)`",
                ));
            }
            Ok(format!(
                "when {}: {}",
                render_guard_expr(&items[1], library)?,
                elaborate_behavior_statement(&items[2], library)?
            ))
        }
        other => Err(module_error(
            form.span,
            format!("unsupported behavior statement `{other}`"),
        )),
    }
}

/// Elaborate a top-level behavior form, expanding an atomic transaction group
/// into ordinary ordered effects carrying the same non-zero group id.
/// Expand `(iterate (<index> <count>) <statement> ...)` in a behavior.
///
/// The expression-level loop in `src/loops.rs` folds an accumulator into a
/// value. This is the statement-level counterpart: it repeats *effects*, which
/// is what a block copy or a block fill is — one instruction that performs a
/// bounded number of memory accesses. `MOPS` on AArch64 and `REP MOVS` on x86
/// are this shape.
///
/// Expanding here, before effect elaboration, is deliberate. A statement loop
/// changes how many effects an instruction has, and the effect list is built by
/// the elaborator this feeds — the same reason a vector *store* had to put its
/// shape in the address rather than in a value.
///
/// Nothing needs a multi-write ABI for this: `EFFECT_MAX_WRITES` bounds
/// *register* writes, and a copy's stores go to the memory image, so a
/// sixteen-element copy is sixteen stores and no register writes at all.
fn expand_behavior_iterate(
    form: &SExpr,
    items: &[SExpr],
    library: &SemanticLibrary,
) -> Result<Vec<String>, ModuleError> {
    if items.len() < 3 {
        return Err(module_error(
            form.span,
            "iterate must be `(iterate (index count) statement statement ...)`",
        ));
    }
    let binding = list(&items[1], "iterate binding")?;
    if binding.len() != 2 {
        return Err(module_error(items[1].span, "iterate binding is `(index count)`"));
    }
    let index_name = atom(binding.first(), "iterate index")?.to_string();
    let count = number(&binding[1], "iterate count")?;
    if count > MAX_BEHAVIOR_ITERATIONS {
        return Err(module_error(
            items[1].span,
            format!(
                "iterate names {count} iterations; the maximum is {MAX_BEHAVIOR_ITERATIONS}"
            ),
        ));
    }
    let mut out = Vec::new();
    for step in 0..count {
        for statement in &items[2..] {
            let bound = substitute_atom(statement, &index_name, &step.to_string());
            out.extend(elaborate_behavior_statements(&bound, library)?);
        }
    }
    Ok(out)
}

/// Replace every occurrence of an atom with a literal, throughout a form.
fn substitute_atom(form: &SExpr, name: &str, value: &str) -> SExpr {
    let kind = match &form.kind {
        SExprKind::Atom(atom) if atom == name => SExprKind::Atom(value.to_string()),
        SExprKind::List(items) => SExprKind::List(
            items
                .iter()
                .map(|item| substitute_atom(item, name, value))
                .collect(),
        ),
        other => other.clone(),
    };
    SExpr { kind, span: form.span }
}

/// `$name` in `text`, replaced by `value` -- at whole-token boundaries, so a
/// parameter never eats a longer name that starts with it. `$name` must not
/// rewrite the `$names` of some other placeholder.
fn substitute_in_text(text: &str, name: &str, value: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(name) {
        let after = &rest[at + name.len()..];
        let boundary = after
            .chars()
            .next()
            .is_none_or(|ch| !ch.is_alphanumeric() && ch != '_');
        out.push_str(&rest[..at]);
        if boundary {
            out.push_str(value);
        } else {
            out.push_str(name);
        }
        rest = after;
    }
    out.push_str(rest);
    out
}

fn elaborate_behavior_statements(
    form: &SExpr,
    library: &SemanticLibrary,
) -> Result<Vec<String>, ModuleError> {
    let items = list(form, "behavior statement")?;
    let head = atom(items.first(), "behavior statement head")?;
    if head == "iterate" {
        return expand_behavior_iterate(form, &items, library);
    }
    if head != "atomic-group" {
        return elaborate_behavior_statement(form, library).map(|statement| vec![statement]);
    }
    if items.len() < 4 {
        return Err(module_error(
            form.span,
            "atomic-group must be `(atomic-group positive-id statement statement ...)`",
        ));
    }
    let group = number(&items[1], "atomic group id")?;
    if group == 0 {
        return Err(module_error(
            items[1].span,
            "atomic group id must be positive",
        ));
    }
    items[2..]
        .iter()
        .map(|statement| {
            let nested = list(statement, "atomic group statement")?;
            if matches!(nested.first(), Some(item) if atom(Some(item), "atomic group statement head")? == "atomic-group") {
                return Err(module_error(statement.span, "nested atomic groups are not supported"));
            }
            Ok(format!(
                "atomic[{group}] {}",
                elaborate_behavior_statement(statement, library)?
            ))
        })
        .collect()
}

fn render_guard_expr(expression: &SExpr, library: &SemanticLibrary) -> Result<String, ModuleError> {
    let expanded = eliminate_effect_bindings(&library.expand(expression)?)?;
    render_guard_expr_expanded(&expanded)
}

fn render_guard_expr_expanded(expression: &SExpr) -> Result<String, ModuleError> {
    let items = list(expression, "behavior guard")?;
    let head = atom(items.first(), "behavior guard head")?;
    if matches!(head, "and" | "or") {
        if items.len() < 3 {
            return Err(module_error(
                expression.span,
                "behavior guard `and`/`or` requires at least two predicates",
            ));
        }
        let children = items[1..]
            .iter()
            .map(render_guard_expr_expanded)
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(format!("{head}({})", children.join(", ")));
    }
    if head == "not" {
        if items.len() != 2 {
            return Err(module_error(
                expression.span,
                "behavior guard `not` requires one predicate",
            ));
        }
        return Ok(format!("not({})", render_guard_expr_expanded(&items[1])?));
    }
    // A typed comparison -- `(ult i32 a b)`, the spelling every value uses --
    // is the likely mistake, and "must be a binary comparison" read as though
    // `and` were what had been refused.
    if items.len() == 4
        && matches!(&items[1].kind, SExprKind::Atom(t) if crate::ir::type_atom_bits(t).is_some())
    {
        return Err(module_error(
            expression.span,
            "a behavior guard comparison takes no type: write `(ult a b)`, not `(ult i32 a b)`",
        ));
    }
    if items.len() != 3 {
        return Err(module_error(
            expression.span,
            "behavior guard must be a binary comparison",
        ));
    }
    // The six integer comparisons, spelled either as the operator name the typed
    // IR uses or as the shorthand a behavior reads better with. Equality alone
    // was enough while AArch64 was the only ISA with behaviors, because its
    // conditional branches test NZCV rather than comparing registers.
    let operator = match head {
        "=" | "eq" | "icmp-eq" | "icmp_eq" => "icmp_eq",
        "!=" | "ne" | "icmp-ne" | "icmp_ne" => "icmp_ne",
        "<s" | "slt" | "icmp-slt" | "icmp_slt" => "icmp_slt",
        ">=s" | "sge" | "icmp-sge" | "icmp_sge" => "icmp_sge",
        "<u" | "ult" | "icmp-ult" | "icmp_ult" => "icmp_ult",
        ">=u" | "uge" | "icmp-uge" | "icmp_uge" => "icmp_uge",
        _ => {
            return Err(module_error(
                expression.span,
                "behavior guard must use one of eq, ne, slt, sge, ult, uge",
            ));
        }
    };
    Ok(format!(
        "{}({}, {})",
        operator,
        render_effect_expr_expanded(&items[1])?,
        render_effect_expr_expanded(&items[2])?
    ))
}

fn render_effect_expr(
    expression: &SExpr,
    library: &SemanticLibrary,
) -> Result<String, ModuleError> {
    let expanded = eliminate_effect_bindings(&library.expand(expression)?)?;
    render_effect_expr_expanded(&expanded)
}

fn render_effect_expr_expanded(expression: &SExpr) -> Result<String, ModuleError> {
    match &expression.kind {
        SExprKind::Atom(value) => {
            if value.starts_with("#b") || value.starts_with("#x") {
                Ok(number(expression, "numeric literal")?.to_string())
            } else {
                Ok(value.clone())
            }
        }
        SExprKind::String(_) => Err(module_error(
            expression.span,
            "strings are not behavior values",
        )),
        SExprKind::List(items) => {
            let raw_head = atom(items.first(), "behavior expression head")?;
            let head = if raw_head == "if" {
                "select".to_string()
            } else {
                raw_head.replace('-', "_")
            };
            let args = items[1..]
                .iter()
                .map(render_effect_expr_expanded)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(format!("{head}({})", args.join(", ")))
        }
    }
}

/// Effect expressions use lexical `let` just like pure expressions. Expand it
/// hygienically before handing the expression to the legacy call parser.
fn eliminate_effect_bindings(expression: &SExpr) -> Result<SExpr, ModuleError> {
    let SExprKind::List(items) = &expression.kind else {
        return Ok(expression.clone());
    };
    if matches!(items.first(), Some(SExpr { kind: SExprKind::Atom(head), .. }) if head == "let") {
        if items.len() != 3 {
            return Err(module_error(
                expression.span,
                "let expects bindings and one body",
            ));
        }
        let bindings = list(&items[1], "let bindings")?;
        let mut substitutions = std::collections::HashMap::new();
        for binding in bindings {
            let pair = list(binding, "let binding")?;
            if pair.len() != 2 {
                return Err(module_error(
                    binding.span,
                    "let binding must be `(name expression)`",
                ));
            }
            let name = atom(pair.first(), "let binding name")?.to_string();
            // Bindings are simultaneous: each right-hand side sees the outer
            // environment, never a sibling binding.
            substitutions.insert(name, eliminate_effect_bindings(&pair[1])?);
        }
        return eliminate_effect_bindings(&substitute(&items[2], &substitutions));
    }
    Ok(SExpr {
        kind: SExprKind::List(
            items
                .iter()
                .map(eliminate_effect_bindings)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        span: expression.span,
    })
}

fn elaborate_requires(predicate: &SExpr) -> Result<String, ModuleError> {
    let items = list(predicate, "requires predicate")?;
    let raw_name = atom(items.first(), "requires predicate name")?;
    match raw_name {
        "masked-eq" | "mask=" => {
            if items.len() != 4 {
                return Err(module_error(
                    predicate.span,
                    "requires `masked-eq` expects an operand, mask, and value",
                ));
            }
            let operand = atom(items.get(1), "masked-eq operand")?;
            let mask = number(&items[2], "masked-eq mask")?;
            let value = number(&items[3], "masked-eq value")?;
            return Ok(format!("uimm_mask_eq({operand}, {mask}, {value})"));
        }
        "and" | "or" => {
            if items.len() < 2 {
                return Err(module_error(
                    predicate.span,
                    format!("requires `{raw_name}` expects at least one predicate"),
                ));
            }
            let name = if raw_name == "and" { "all" } else { "any" };
            let children = items[1..]
                .iter()
                .map(elaborate_requires)
                .collect::<Result<Vec<_>, _>>()?;
            return Ok(format!("{name}({})", children.join(", ")));
        }
        "not" => {
            if items.len() != 2 {
                return Err(module_error(
                    predicate.span,
                    "requires `not` expects one predicate",
                ));
            }
            return Ok(format!("not({})", elaborate_requires(&items[1])?));
        }
        "=" | "eq" | "!=" | "ne" | "<" | "<=" | ">" | ">=" => {
            if items.len() != 3 {
                return Err(module_error(
                    predicate.span,
                    format!("requires comparison `{raw_name}` expects an operand and literal"),
                ));
            }
            let operand = atom(items.get(1), "requires comparison operand")?;
            let literal = number(&items[2], "requires comparison literal")?;
            let suffix = match raw_name {
                "=" | "eq" => "eq",
                "!=" | "ne" => "ne",
                "<" => "lt",
                "<=" => "le",
                ">" => "gt",
                ">=" => "ge",
                _ => unreachable!(),
            };
            return Ok(format!("uimm_{suffix}({operand}, {literal})"));
        }
        _ => {}
    }
    let name = raw_name.replace('-', "_");
    let expected_arity = match name.as_str() {
        "a64_logical_imm" | "a64_shifted_reg" => 3,
        "a64_extended_reg" => 1,
        _ => {
            return Err(module_error(
                predicate.span,
                format!("unsupported requires predicate `{raw_name}`"),
            ));
        }
    };
    if items.len() != expected_arity + 1 {
        return Err(module_error(
            predicate.span,
            format!("requires predicate `{raw_name}` expects {expected_arity} arguments"),
        ));
    }
    let args = items[1..]
        .iter()
        .map(|argument| match &argument.kind {
            SExprKind::Atom(value) if value.starts_with("#b") || value.starts_with("#x") => {
                number(argument, "requires literal").map(|value| value.to_string())
            }
            SExprKind::Atom(value) => Ok(value.clone()),
            _ => Err(module_error(
                argument.span,
                "requires arguments must be types, operands, or integer literals",
            )),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(format!("{name}({})", args.join(", ")))
}

fn elaborate_encoding(forms: &[SExpr]) -> Result<Vec<(String, u32)>, ModuleError> {
    let mut result = Vec::new();
    for form in forms {
        let pair = list(form, "encoding entry")?;
        if pair.len() != 2 {
            return Err(module_error(
                form.span,
                "encoding entry must be `(field value)`",
            ));
        }
        let name = atom(pair.first(), "encoding field")?.to_string();
        if result.iter().any(|(existing, _)| existing == &name) {
            return Err(module_error(
                form.span,
                format!("duplicate encoding field `{name}`"),
            ));
        }
        result.push((name, number(&pair[1], "encoding value")?));
    }
    Ok(result)
}

fn elaborate_operand(form: &SExpr) -> Result<Operand, ModuleError> {
    let items = list(form, "operand")?;
    if !matches!(items.len(), 4 | 5) {
        return Err(module_error(
            form.span,
            "operand must be `(name kind type in|out|inout \
             [element | (derive source offset) | (asm <transform>)])`",
        ));
    }
    let role = atom(items.get(3), "operand role")?;
    let (input, output) = match role {
        "in" => (true, false),
        "out" => (false, true),
        "inout" => (true, true),
        // Encoded and read by nothing. The AST has always had this role --
        // `operand_role` returns it -- and the frontend could not write it, so
        // `emit-lisp` produced a document its own reader rejected. Found by
        // `lisp_roundtrip.py` on seven corpora at once.
        "enc" => (false, false),
        _ => {
            return Err(module_error(
                items[3].span,
                format!("unknown operand role `{role}`"),
            ));
        }
    };
    // The fifth slot is either the atom `element` or a derivation list, and an
    // atom cannot be mistaken for a list.
    let element = matches!(items.get(4), Some(SExpr { .. })
        if matches!(atom(items.get(4), "operand suffix"), Ok("element")));
    if let Some(extra) = items.get(4) {
        if !element {
            if let Ok(word) = atom(items.get(4), "operand suffix") {
                return Err(module_error(
                    extra.span,
                    format!("unknown operand suffix `{word}`; expected `element`"),
                ));
            }
        }
    }
    // The fifth slot's list is either a register derivation or an assembly
    // transform. They are told apart by their head, so neither has to be
    // positional and a description can gain one without the other moving.
    let mut derived_from = String::new();
    let mut derived_add = 0u32;
    let mut fixed = None;
    let mut asm_transform = crate::ast::AsmTransform::Identity;
    if let Some(extra) = items.get(4).filter(|_| !element) {
        let form = list(extra, "operand derivation")?;
        match atom(form.first(), "operand derivation")? {
            "derive" => {
                if form.len() != 3 {
                    return Err(module_error(
                        extra.span,
                        "operand derivation must be `(derive source offset)`",
                    ));
                }
                derived_from = atom(form.get(1), "derived operand source")?.to_string();
                derived_add = number(&form[2], "derived operand offset")?;
            }
            "fixed" => {
                if form.len() != 2 {
                    return Err(module_error(
                        extra.span,
                        "a fixed register must be `(fixed index)`",
                    ));
                }
                fixed = Some(number(&form[1], "fixed register index")?);
            }
            "asm" => {
                if form.len() != 2 {
                    return Err(module_error(
                        extra.span,
                        "assembly transform must be `(asm (minus-from k))` or `(asm (plus k))`",
                    ));
                }
                let inner = list(&form[1], "assembly transform")?;
                if inner.len() != 2 {
                    return Err(module_error(
                        form[1].span,
                        "assembly transform must be `(minus-from k)` or `(plus k)`",
                    ));
                }
                let amount = number(&inner[1], "assembly transform amount")?;
                asm_transform = match atom(inner.first(), "assembly transform")? {
                    "minus-from" => crate::ast::AsmTransform::MinusFrom(amount),
                    "plus" => crate::ast::AsmTransform::Plus(amount),
                    other => {
                        return Err(module_error(
                            inner[0].span,
                            format!(
                                "unknown assembly transform `{other}`; expected \
                                 `minus-from` or `plus`. Only transforms an \
                                 assembler can run backwards belong here"
                            ),
                        ));
                    }
                };
            }
            other => {
                return Err(module_error(
                    extra.span,
                    format!("unknown operand form `{other}`; expected `derive`, `fixed` or `asm`"),
                ));
            }
        }
    }
    Ok(Operand {
        name: atom(items.first(), "operand name")?.to_string(),
        kind: atom(items.get(1), "operand kind")?.to_string(),
        width: type_width(atom(items.get(2), "operand type")?, items[2].span)?,
        input,
        output,
        element,
        derived_from,
        derived_add,
        fixed,
        asm_transform,
        lane_register: 0,
        lane_element: 0,
        lane_index: 0,
        lane_packed: false,
        slot_stride: 0,
        view_offset: 0,
        view_width: 0,
        slot_base: 0,
    })
}

fn collect_definition_calls(
    expression: &SExpr,
    definitions: &std::collections::HashMap<String, SemanticDefinition>,
    calls: &mut Vec<String>,
) {
    let SExprKind::List(items) = &expression.kind else {
        return;
    };
    if let Some(SExpr {
        kind: SExprKind::Atom(head),
        ..
    }) = items.first()
    {
        if definitions.contains_key(head) {
            calls.push(head.clone());
        }
    }
    for item in items {
        collect_definition_calls(item, definitions, calls);
    }
}

fn substitute(
    expression: &SExpr,
    substitutions: &std::collections::HashMap<String, SExpr>,
) -> SExpr {
    match &expression.kind {
        SExprKind::Atom(atom) => substitutions
            .get(atom)
            .cloned()
            .unwrap_or_else(|| expression.clone()),
        // A family parameter is substituted inside strings too. It is
        // substituted everywhere else it appears, and a template writing
        // `(asm "$name $rd, $rs1, $rs2")` means what it says -- but this
        // skipped strings, so the parameter reached the emitted artifact
        // verbatim and `asm_disasm.json` published `$name $rd, $rs1, $rs2` as
        // an instruction's assembly text. Nothing rejected it either, so the
        // description was wrong and silent about it.
        //
        // Only *declared parameters* are rewritten, which is what leaves
        // operand placeholders alone: `$rd` is a parameter of no family here,
        // and one that did declare it would be substituting it on purpose.
        // Substituting a value can introduce text that looks like another
        // parameter, so each is applied once, over the original.
        SExprKind::String(text) => {
            let mut replaced = text.clone();
            for (name, value) in substitutions {
                if let SExprKind::Atom(atom) = &value.kind {
                    replaced = substitute_in_text(&replaced, name, atom);
                }
            }
            SExpr {
                kind: SExprKind::String(replaced),
                span: expression.span,
            }
        }
        SExprKind::List(items) if matches!(items.first(), Some(SExpr { kind: SExprKind::Atom(head), .. }) if head == "let") =>
        {
            let mut replaced = items.clone();
            if let Some(SExpr {
                kind: SExprKind::List(bindings),
                ..
            }) = items.get(1)
            {
                replaced[1] = SExpr {
                    kind: SExprKind::List(
                        bindings
                            .iter()
                            .map(|binding| {
                                let mut pair = match &binding.kind {
                                    SExprKind::List(pair) => pair.clone(),
                                    _ => return binding.clone(),
                                };
                                if pair.len() == 2 {
                                    pair[1] = substitute(&pair[1], substitutions);
                                }
                                SExpr {
                                    kind: SExprKind::List(pair),
                                    span: binding.span,
                                }
                            })
                            .collect(),
                    ),
                    span: items[1].span,
                };
                let mut body_substitutions = substitutions.clone();
                for binding in bindings {
                    if let SExprKind::List(pair) = &binding.kind {
                        if let Some(SExpr {
                            kind: SExprKind::Atom(name),
                            ..
                        }) = pair.first()
                        {
                            body_substitutions.remove(name);
                        }
                    }
                }
                if items.len() > 2 {
                    replaced[2] = substitute(&items[2], &body_substitutions);
                }
            }
            SExpr {
                kind: SExprKind::List(replaced),
                span: expression.span,
            }
        }
        SExprKind::List(items) => SExpr {
            kind: SExprKind::List(
                items
                    .iter()
                    .map(|item| substitute(item, substitutions))
                    .collect(),
            ),
            span: expression.span,
        },
    }
}

fn render(expression: &SExpr) -> String {
    match &expression.kind {
        SExprKind::Atom(atom) => atom.clone(),
        SExprKind::String(value) => format!("{value:?}"),
        SExprKind::List(items) => {
            let rendered = items.iter().map(render).collect::<Vec<_>>().join(" ");
            format!("({rendered})")
        }
    }
}

fn is_reserved_semantic_name(name: &str) -> bool {
    matches!(
        name,
        "let"
            | "call"
            | "if"
            | "select"
            | "add"
            | "sub"
            | "mul"
            | "udiv"
            | "sdiv"
            | "urem"
            | "srem"
            | "and"
            | "or"
            | "xor"
            | "shl"
            | "sll"
            | "lshr"
            | "srl"
            | "ashr"
            | "sra"
            | "rol"
            | "ror"
            | "not"
            | "clz"
            | "ctz"
            | "cpop"
            | "min"
            | "max"
            | "minu"
            | "maxu"
            | "sext"
            | "zext"
    )
}

fn module_error(span: Span, message: impl Into<String>) -> ModuleError {
    ModuleError {
        span,
        message: message.into(),
    }
}

fn list<'a>(expression: &'a SExpr, context: &str) -> Result<&'a [SExpr], ModuleError> {
    match &expression.kind {
        SExprKind::List(items) => Ok(items),
        _ => Err(module_error(
            expression.span,
            format!("{context} must be a list"),
        )),
    }
}

fn atom<'a>(expression: Option<&'a SExpr>, context: &str) -> Result<&'a str, ModuleError> {
    match expression {
        Some(SExpr {
            kind: SExprKind::Atom(atom),
            ..
        }) => Ok(atom),
        Some(expression) => Err(module_error(
            expression.span,
            format!("{context} must be an atom"),
        )),
        None => Err(module_error(
            Span {
                offset: 0,
                line: 1,
                column: 1,
            },
            format!("missing {context}"),
        )),
    }
}

fn scalar(items: &[SExpr], span: Span, property: &str) -> Result<String, ModuleError> {
    if items.len() != 2 {
        return Err(module_error(
            span,
            format!("{property} expects exactly one value"),
        ));
    }
    match &items[1].kind {
        SExprKind::Atom(value) | SExprKind::String(value) => Ok(value.clone()),
        SExprKind::List(_) => Err(module_error(
            items[1].span,
            format!("{property} value must be an atom or string"),
        )),
    }
}

fn scalar_list(items: &[SExpr]) -> Result<Vec<String>, ModuleError> {
    items
        .iter()
        .map(|item| match &item.kind {
            SExprKind::Atom(value) | SExprKind::String(value) => Ok(value.clone()),
            SExprKind::List(_) => Err(module_error(item.span, "expected a scalar list value")),
        })
        .collect()
}

fn numeric_property(items: &[SExpr], span: Span, property: &str) -> Result<u32, ModuleError> {
    if items.len() != 2 {
        return Err(module_error(
            span,
            format!("{property} expects exactly one number"),
        ));
    }
    number(&items[1], property)
}

/// A 64-bit count: a memory's size, which is past 4 GiB for any DRAM worth
/// describing.
fn wide_number_property(items: &[SExpr], span: Span, property: &str) -> Result<u64, ModuleError> {
    if items.len() != 2 {
        return Err(module_error(span, format!("{property} expects exactly one number")));
    }
    let text = atom(Some(&items[1]), property)?;
    let parsed = if let Some(hex) = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
    } else {
        text.parse::<u64>()
    };
    parsed.map_err(|_| module_error(items[1].span, format!("{property} `{text}` is not a valid u64")))
}

fn number(expression: &SExpr, context: &str) -> Result<u32, ModuleError> {
    let atom = atom(Some(expression), context)?;
    let parsed = if let Some(binary) = atom.strip_prefix("#b") {
        u32::from_str_radix(binary, 2)
    } else if let Some(hex) = atom.strip_prefix("0x").or_else(|| atom.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
    } else {
        atom.parse::<u32>()
    };
    parsed.map_err(|_| {
        module_error(
            expression.span,
            format!("{context} `{atom}` is not a valid u32"),
        )
    })
}

fn type_width(atom: &str, span: Span) -> Result<u32, ModuleError> {
    let Some(width) = atom
        .strip_prefix(['i', 'u'])
        .and_then(|width| width.parse::<u32>().ok())
    else {
        return Err(module_error(
            span,
            format!("`{atom}` is not an integer bit-vector type"),
        ));
    };
    if width == 0 || width > 128 {
        return Err(module_error(
            span,
            format!("bit-vector width {width} must be in 1..=128"),
        ));
    }
    Ok(width)
}

struct Reader<'a> {
    source: &'a str,
    offset: usize,
    line: usize,
    column: usize,
}

impl<'a> Reader<'a> {
    fn new(source: &'a str) -> Self {
        Self {
            source,
            offset: 0,
            line: 1,
            column: 1,
        }
    }

    fn span(&self) -> Span {
        Span {
            offset: self.offset,
            line: self.line,
            column: self.column,
        }
    }

    fn error(&self, message: impl Into<String>) -> ReadError {
        ReadError {
            span: self.span(),
            message: message.into(),
        }
    }

    fn eof(&self) -> bool {
        self.offset >= self.source.len()
    }

    fn peek(&self) -> Option<char> {
        self.source[self.offset..].chars().next()
    }

    fn bump(&mut self) -> Option<char> {
        let character = self.peek()?;
        self.offset += character.len_utf8();
        if character == '\n' {
            self.line += 1;
            self.column = 1;
        } else {
            self.column += 1;
        }
        Some(character)
    }

    fn skip_trivia(&mut self) {
        loop {
            while self.peek().is_some_and(char::is_whitespace) {
                self.bump();
            }
            if self.peek() != Some(';') {
                return;
            }
            while self.peek().is_some_and(|character| character != '\n') {
                self.bump();
            }
        }
    }

    fn read_expr(&mut self) -> Result<SExpr, ReadError> {
        self.skip_trivia();
        let span = self.span();
        match self.peek() {
            None => Err(self.error("unexpected end of input")),
            Some('(') => self.read_list(span),
            Some(')') => Err(self.error("unexpected `)`")),
            Some('"') => self.read_string(span),
            Some('\'') => self.read_quote(span),
            Some(_) => self.read_atom(span),
        }
    }

    fn read_list(&mut self, span: Span) -> Result<SExpr, ReadError> {
        self.bump();
        let mut items = Vec::new();
        loop {
            self.skip_trivia();
            match self.peek() {
                Some(')') => {
                    self.bump();
                    return Ok(SExpr {
                        kind: SExprKind::List(items),
                        span,
                    });
                }
                None => {
                    return Err(ReadError {
                        span,
                        message: "unclosed list".to_string(),
                    });
                }
                Some(_) => items.push(self.read_expr()?),
            }
        }
    }

    fn read_string(&mut self, span: Span) -> Result<SExpr, ReadError> {
        self.bump();
        let mut value = String::new();
        loop {
            match self.bump() {
                Some('"') => {
                    return Ok(SExpr {
                        kind: SExprKind::String(value),
                        span,
                    });
                }
                Some('\\') => match self.bump() {
                    Some('n') => value.push('\n'),
                    Some('r') => value.push('\r'),
                    Some('t') => value.push('\t'),
                    Some('\\') => value.push('\\'),
                    Some('"') => value.push('"'),
                    Some(character) => {
                        return Err(
                            self.error(format!("unsupported string escape `\\{character}`"))
                        );
                    }
                    None => return Err(self.error("unterminated string escape")),
                },
                Some(character) => value.push(character),
                None => {
                    return Err(ReadError {
                        span,
                        message: "unterminated string".to_string(),
                    });
                }
            }
        }
    }

    fn read_quote(&mut self, span: Span) -> Result<SExpr, ReadError> {
        self.bump();
        let quoted = self.read_expr()?;
        Ok(SExpr {
            kind: SExprKind::List(vec![
                SExpr {
                    kind: SExprKind::Atom("quote".to_string()),
                    span,
                },
                quoted,
            ]),
            span,
        })
    }

    fn read_atom(&mut self, span: Span) -> Result<SExpr, ReadError> {
        let start = self.offset;
        while self.peek().is_some_and(|character| {
            !character.is_whitespace() && !matches!(character, '(' | ')' | '"' | ';')
        }) {
            self.bump();
        }
        if start == self.offset {
            return Err(self.error("expected an atom"));
        }
        Ok(SExpr {
            kind: SExprKind::Atom(self.source[start..self.offset].to_string()),
            span,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_nested_forms_comments_strings_and_quotes() {
        let forms = read_all(
            r#"; module
               (defsem add1 (x) (add i32 x 1))
               '(name "A64\nsemantics")"#,
        )
        .unwrap();
        assert_eq!(forms.len(), 2);
        assert!(matches!(&forms[0].kind, SExprKind::List(items) if items.len() == 4));
        assert!(matches!(&forms[1].kind, SExprKind::List(items)
            if matches!(&items[0].kind, SExprKind::Atom(atom) if atom == "quote")));
    }

    #[test]
    fn reports_the_opening_span_for_an_unclosed_list() {
        let error = read_one("\n  (add i32 x").unwrap_err();
        assert_eq!((error.span.line, error.span.column), (2, 3));
        assert_eq!(error.message, "unclosed list");
    }

    #[test]
    fn rejects_trailing_forms_in_single_expression_mode() {
        let error = read_one("(add x y) (sub x y)").unwrap_err();
        assert_eq!((error.span.line, error.span.column), (1, 11));
        assert!(error.message.contains("unexpected expression"));
    }

    #[test]
    fn elaborates_a_module_and_inlines_nested_semantic_definitions() {
        let document = elaborate_document(include_str!("../examples/lisp_module.axisl")).unwrap();
        assert_eq!(document.extension.name, "lisp-module");
        assert_eq!(document.formats.len(), 1);
        assert_eq!(document.instructions.len(), 1);
        let semantics = &document.instructions[0].formal_semantics;
        assert!(semantics.starts_with("(not i32 (let"));
        assert!(!semantics.contains("choose-arithmetic"));
        assert!(!semantics.contains("invert-choice"));
    }

    #[test]
    fn elaborates_complete_instruction_cost_and_pattern_metadata() {
        let source = r#"(axis-module metadata
          (definstruction TLS-LOAD
            (category memory)
            (area-estimate-um2 1200.0)
            (power-estimate-mw 1.5)
            (expected-speedup 1.4)
            (intrinsic llvm.pce.tls.load)
            (patterns thread-local memory-hiding)
            (applicable-patterns thread-local memory-hiding)))"#;
        let document = elaborate_document(source).unwrap();
        let instruction = &document.instructions[0];
        assert_eq!(instruction.category, "memory");
        assert_eq!(instruction.area_estimate_um2, "1200.0");
        assert_eq!(instruction.power_estimate_mw, "1.5");
        assert_eq!(instruction.expected_speedup, "1.4");
        assert_eq!(instruction.intrinsic, "llvm.pce.tls.load");
        assert_eq!(
            instruction.patterns,
            vec!["thread-local".to_string(), "memory-hiding".to_string()]
        );
        assert_eq!(instruction.applicable_patterns, instruction.patterns);
    }

    #[test]
    fn rejects_direct_and_indirect_defsem_recursion() {
        let direct = r#"(axis-module recursive
          (defsem loop ((x i32)) i32 (loop x)))"#;
        let error = elaborate_document(direct).unwrap_err();
        assert!(error
            .message
            .contains("recursive defsem cycle: loop -> loop"));

        let indirect = r#"(axis-module recursive
          (defsem first ((x i32)) i32 (second x))
          (defsem second ((x i32)) i32 (first x)))"#;
        let error = elaborate_document(indirect).unwrap_err();
        assert!(error.message.contains("recursive defsem cycle"));
        assert!(error.message.contains("first"));
        assert!(error.message.contains("second"));
    }

    #[test]
    fn rejects_wrong_defsem_call_arity() {
        let source = r#"(axis-module bad-call
          (defformat r
            (fields (rd 4 0) (rs1 9 5) (opcode 31 25)))
          (defsem pair ((x i32) (y i32)) i32 (add i32 x y))
          (definstruction BAD
            (format r)
            (encoding (opcode 1))
            (operands (rd reg i32 out) (rs1 reg i32 in))
            (formal (pair rs1))))"#;
        let error = elaborate_document(source).unwrap_err();
        assert!(error
            .message
            .contains("defsem `pair` expects 2 arguments, got 1"));
    }

    #[test]
    fn rejects_defsem_argument_and_result_width_mismatches() {
        let bad_result = r#"(axis-module bad-result
          (defsem wrong ((x i32)) i64 (add i32 x 1)))"#;
        let error = elaborate_document(bad_result).unwrap_err();
        assert!(error
            .message
            .contains("defsem `wrong` returns i32, declared i64"));

        let bad_argument = r#"(axis-module bad-argument
          (defformat r
            (fields (rd 4 0) (rs1 9 5) (opcode 31 25)))
          (defsem wide ((x i64)) i32 (zext i32 16 x))
          (definstruction BAD
            (format r)
            (encoding (opcode 1))
            (operands (rd reg i32 out) (rs1 reg i32 in))
            (formal (wide rs1))))"#;
        let error = elaborate_document(bad_argument).unwrap_err();
        assert!(error
            .message
            .contains("defsem `wide` argument `x` expects i64, got i32"));
    }

    #[test]
    fn defsem_substitution_respects_lexical_shadowing() {
        let definition =
            read_one("(defsem increment-shadow ((x i32)) i32 (let ((x (add i32 x 1))) x))")
                .unwrap();
        let library = SemanticLibrary::new(vec![parse_definition(&definition).unwrap()]).unwrap();
        let call = read_one("(increment-shadow rs1)").unwrap();
        let expanded = library.expand(&call).unwrap();
        assert_eq!(render(&expanded), "(let ((x (add i32 rs1 1))) x)");
    }

    #[test]
    fn defcore_carries_lsq_rename_and_history() {
        let document =
            elaborate_document(include_str!("../examples/issue_width.axisl")).unwrap();
        crate::validate::validate_document(&document).unwrap();
        let core = |name: &str| document.cores.iter().find(|c| c.name == name).unwrap();
        // ⚠️ No clause and a clause of defaults are different machines.
        assert_eq!(core("ooo").lsq, None);
        let tight = core("tightlsq").lsq.clone().unwrap();
        assert_eq!((tight.loads, tight.stores), (2, 2));
        assert_eq!(tight.disambiguation, "perfect");
        assert!(tight.forwarding);
        assert!(!core("noforward").lsq.clone().unwrap().forwarding);
        assert_eq!(core("fewregs").rename, vec![("rv_gpr".to_string(), 6)]);
        assert_eq!(core("correlates").predictor_history, 4);
        let learns = core("learns").lsq.clone().unwrap();
        assert_eq!((learns.disambiguation.as_str(), learns.replay, learns.store_sets),
                   ("store-sets", 4, 64));
        assert_eq!(core("ooo").front_end, None);
        let small = core("smallbtb").front_end.clone().unwrap();
        assert_eq!((small.fetch_width, small.depth, small.btb, small.btb_penalty), (4, 2, 1, 3));
        // W4: a unit says whether what a squashed instruction started in it
        // is aborted. D3: the quick predictor the core's own overrides.
        let aborts = |name: &str| {
            core(name).units.iter().map(|u| (u.name.as_str(), u.abort)).collect::<Vec<_>>()
        };
        assert_eq!(aborts("aborts"), [("alu", false), ("mul", true), ("br", false), ("lsu", false)]);
        assert!(aborts("contends").iter().all(|(_, abort)| !abort));
        let quick = core("overridden").overrides.as_ref().unwrap();
        assert_eq!((quick.predictor.as_str(), quick.entries, quick.cycles), ("bimodal", 64, 2));
        assert!(core("overridesnot").overrides.is_none());
        // U2: a micro-op cache and a loop buffer on the front end.
        let front = |name: &str| core(name).front_end.clone().unwrap();
        let cache = front("opcached").op_cache.unwrap();
        assert_eq!((cache.entries, cache.ways, cache.window, cache.width, cache.depth), (16, 2, 32, 8, 2));
        let buffer = front("loopbuffered").loop_buffer.unwrap();
        assert_eq!((buffer.ops, buffer.width, buffer.depth), (16, 8, 1));
        assert!(front("decodes").op_cache.is_none() && front("decodes").loop_buffer.is_none());
        // S1-S3: the scheduler's own limits.
        assert_eq!((core("dispatchestwo").dispatch_width, core("scheduletwo").schedule), (2, 2));
        assert_eq!(core("bypasses").bypass, vec![("mul".to_string(), "alu".to_string(), 2)]);
        assert_eq!(core("queues").units.iter().map(|u| u.queue).collect::<Vec<_>>(), [0, 2, 0, 0]);
        assert_eq!(core("valuepredicts").value_prediction, Some((64, 2)));
        // S5-S8.
        assert_eq!(core("clusters").queues, vec![("slow".to_string(), 2, vec!["mul".to_string(), "lsu".to_string()])]);
        assert_eq!((core("renamesone").rename_width, core("selectsposition").select.as_str()), (1, "position"));
        assert!(core("valuestrides").value_stride && !core("valuepredicts").value_stride);
        assert!(core("valueplain").value_prediction.is_none());
        let plain = core("schedplain");
        assert!(plain.dispatch_width == 0 && plain.schedule == 0 && plain.bypass.is_empty());
        assert_eq!(core("starved").front_end.clone().unwrap().buffer, 4);
        assert_eq!(core("tagged").predictor_params,
                   vec![("tables".to_string(), 4), ("min-history".to_string(), 2)]);
        assert_eq!(core("returns").front_end.clone().unwrap().ras, 8);
        assert_eq!(core("ported").ports[0],
                   ("p0".to_string(), vec!["alu".to_string(), "mul".to_string()]));
        assert!(core("unported").ports.is_empty());
        let ahead = core("fetchahead").front_end.clone().unwrap();
        assert_eq!((ahead.icache.as_str(), ahead.wrong_path_fetch), ("l1i", true));
        assert!(core("runsahead").front_end.clone().unwrap().wrong_path_execute);
        assert_eq!(core("executes").engine, "execute");
        assert!(core("fetches").engine.is_empty());
        // A namespaced predictor's numbers are carried, not interpreted.
        assert_eq!(core("outsourced").predictor_params, vec![("acme.bias".to_string(), 1)]);
        // And the round trip keeps all of it.
        let again = elaborate_document(&crate::emit::emit_lisp(&document)).unwrap();
        assert_eq!(again.cores, document.cores);
    }

    #[test]
    fn defcore_refuses_a_number_nothing_reads() {
        let source = include_str!("../examples/issue_width.axisl");
        for (from, to, why) in [
            ("(history 4)", "(history 0)", "gshare needs a history"),
            ("(predictor bimodal) (entries 16)", "(predictor bimodal) (entries 16) (history 2)",
             "a history on a predictor that reads none"),
            ("(rename (rv_gpr 6))", "(rename (no_such_file 6))", "not a register file"),
            ("(disambiguation conservative)", "(disambiguation psychic)", "not a policy"),
            ("(predictor gshare) (entries 16) (history 4)",
             "(predictor tage) (entries 16)", "not a predictor"),
            ("(disambiguation perfect) (forwarding true))",
             "(disambiguation perfect) (forwarding true) (replay 3))",
             "a replay on a machine that never speculates"),
            ("(store-sets 64)", "", "store-sets without a table"),
            ("(disambiguation speculative) (forwarding true) (replay 4)",
             "(disambiguation speculative) (forwarding true) (replay 4) (store-sets 8)",
             "a table on a machine that keeps none"),
            ("(front-end (fetch-width 4) (depth 2))", "(front-end (fetch-width 0) (depth 2))",
             "a front end that fetches nothing"),
            ("(btb 1) (btb-penalty 3)", "(btb 1)", "a BTB whose miss costs nothing"),
            ("(depth 8) (buffer 4)", "(depth 8) (buffer 2)",
             "a buffer smaller than one fetch group"),
            ("(predictor tage) (entries 64) (history 32) (tables 4)",
             "(predictor tage) (entries 64) (history 32) (tables 9)", "too many TAGE tables"),
            ("(min-history 2)", "(min-history 40)", "a shortest history longer than the longest"),
            ("(predictor gshare) (entries 64) (history 4)",
             "(predictor gshare) (entries 64) (history 4) (tables 2)",
             "a number gshare does not read"),
            ("(predictor acme.always)", "(predictor always)",
             "an un-namespaced name that is no built-in"),
            ("(link-register (rv_gpr 1))", "", "a return stack with no link register to find calls by"),
            ("(ras 8)", "(ras 65)", "a return stack deeper than the model holds"),
            ("(p2 br lsu)", "(p2 br)", "a unit no port feeds"),
            ("(p1 alu)", "(p1 alu fpu)", "a port feeding a unit the core lacks"),
            ("(icache l1i) (wrong-path-fetch true)", "(icache nowhere) (wrong-path-fetch true)",
             "an instruction cache no memory declares"),
            ("(icache l1i) (wrong-path-fetch true)", "(wrong-path-fetch true)",
             "a wrong path with no instruction cache to touch"),
            ("(icache l1i) (wrong-path-execute true)",
             "(icache l1i) (wrong-path-execute true) (wrong-path-fetch true)",
             "a wrong path both fetched in line order and executed"),
            ("(engine execute)", "(engine psychic)", "an engine nobody has"),
            ("    (front-end (fetch-width 4) (depth 2))\n    (engine execute)",
             "    (engine execute)", "an execution-driven core with no front end"),
            ("(lsq (disambiguation conservative))\n    (branch (penalty 0) (predictor bimodal) (entries 64))\n    (front-end (fetch-width 4) (depth 2))\n    (engine execute)",
             "(lsq (disambiguation perfect))\n    (branch (penalty 0) (predictor bimodal) (entries 64))\n    (front-end (fetch-width 4) (depth 2))\n    (engine execute)",
             "an execution-driven core asking for the trace's oracle"),
            ("(mul (count 1) (pipelined false) (abort true))",
             "(mul (count 1) (pipelined true) (abort true))",
             "an abort on a unit held for the cycle an instruction starts in"),
            ("(overrides (predictor bimodal) (entries 64) (cycles 2))",
             "(overrides (predictor gshare) (entries 64) (cycles 2))",
             "a quick predictor with a history to put back"),
            ("(overrides (predictor bimodal) (entries 64) (cycles 2))",
             "(overrides (predictor bimodal) (entries 64) (cycles 0))",
             "an override that costs nothing"),
            ("(overrides (predictor bimodal) (entries 64) (cycles 2))",
             "(overrides (predictor bimodal) (entries 48) (cycles 2))",
             "a quick table that is not a power of two"),
            ("(predictor gshare) (entries 256) (history 8) (overrides",
             "(overrides", "a quick predictor with nothing to override it"),
            ("(op-cache (entries 16) (ways 2) (window 32) (width 4) (depth 2))",
             "(op-cache (entries 16) (ways 2) (window 32) (width 4) (depth 5))",
             "decoded micro-ops further from dispatch than undecoded ones"),
            ("(op-cache (entries 16) (ways 2) (window 32) (width 4) (depth 2))",
             "(op-cache (entries 12) (ways 2) (window 32) (width 4) (depth 2))",
             "sets that are not a power of two"),
            ("(op-cache (entries 16) (ways 2) (window 32) (width 4) (depth 2))",
             "(op-cache (entries 16) (ways 2) (window 24) (width 4) (depth 2))",
             "a window that is not a power of two bytes"),
            ("(loop-buffer (ops 16) (width 8) (depth 1))",
             "(loop-buffer (ops 1) (width 8) (depth 1))", "a loop of one micro-op"),
            ("(loop-buffer (ops 16) (width 8) (depth 1))",
             "(loop-buffer (ops 16) (width 0) (depth 1))", "a buffer that delivers nothing"),
            ("(commit-width 4) (schedule 2))", "(commit-width 4) (schedule 9))",
             "a wakeup-and-select loop longer than the model holds"),
            ("(bypass (mul alu 2))", "(bypass (mul fpu 2))", "a bypass to a unit the core lacks"),
            ("(value-prediction (entries 64) (confidence 2))",
             "(value-prediction (entries 60) (confidence 2))", "a table that is not a power of two"),
            ("(queues (slow (size 2) (units mul lsu)))", "(queues (slow (size 2) (units mul fpu)))",
             "a queue for a unit the core lacks"),
            ("(queues (slow (size 2) (units mul lsu)))",
             "(queues (slow (size 2) (units mul lsu)) (more (size 2) (units mul)))",
             "a unit in two queues"),
            ("(queues (slow (size 2) (units mul lsu)))", "(queues (slow (size 64) (units mul lsu)))",
             "a shared queue no smaller than the window"),
            ("(commit-width 4) (select position))", "(commit-width 4) (select youngest))",
             "a select policy nobody has"),
            ("(value-prediction (entries 64) (confidence 2))",
             "(value-prediction (entries 64) (confidence 0))", "a value trusted before it is seen"),
            ("(bypass (mul alu 2))", "(bypass (mul alu 0))", "a bypass that costs nothing"),
            ("(bypass (mul alu 2))", "(bypass (mul alu 2) (MUL ALU 1))", "one bypass twice"),
            ("(mul (count 1) (pipelined true) (queue 2))",
             "(mul (count 1) (pipelined true) (queue 64))",
             "a unit queue no smaller than the window"),
        ] {
            assert!(source.contains(from), "{from}");
            let document = elaborate_document(&source.replacen(from, to, 1)).unwrap();
            assert!(crate::validate::validate_document(&document).is_err(), "{why}");
        }
    }

    #[test]
    fn deffun_calls_stay_calls_and_round_trip() {
        // A deffun is emitted once and called: a use elaborates to
        // `(call name iR (iP arg) ...)`, not to its body, however deep it nests.
        let source = r#"(axis-module calls
          (defformat r (bits 32) (fields (opcode 6 0) (rd 11 7) (rs1 19 15) (rs2 24 20) (rest 31 25)))
          (deffun twice ((x i8)) i8 (add i8 x x))
          (deffun quad ((x i8)) i8 (twice (twice x)))
          (definstruction q
            (mnemonic Q) (format r) (encoding (opcode 11) (rest 0))
            (operands (rd reg i32 out) (rs1 reg i32 in) (rs2 reg i32 in))
            (formal (zext i32 8 (quad (and i8 rs1 255))))))"#;
        let document = elaborate_document(source).unwrap();
        crate::validate::validate_document(&document).unwrap();
        let names: Vec<&str> = document.functions.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, ["twice", "quad"], "callees first");
        let formal = &document.instructions[0].formal_semantics;
        assert!(formal.contains("(call quad i8 (i8 (and i8 rs1 255)))"), "{formal}");
        assert!(!formal.contains("add"), "not inlined: {formal}");
        let rendered = crate::emit_lisp(&document);
        assert!(rendered.contains("(deffun quad ((x i8)) i8 (call twice i8 (i8 (call twice i8 (i8 x)))))"), "{rendered}");
        assert_eq!(elaborate_document(&rendered).unwrap(), document);
        // A call that disagrees with its definition is refused.
        let wrong = rendered.replace("(call quad i8 (i8", "(call quad i16 (i8");
        let document = elaborate_document(&wrong).unwrap();
        assert!(crate::validate::validate_document(&document).is_err());
    }

    #[test]
    fn defsem_calls_inside_binding_lists_are_inlined() {
        // A list headed by a list -- a `let`'s or `vmap`'s bindings -- was
        // returned as it stood, so a call bound there survived to validation
        // as an unknown operator. SVE's FMAXNMV put one there first.
        let definition = read_one("(defsem twice ((x i32)) i32 (add i32 x x))").unwrap();
        let library = SemanticLibrary::new(vec![parse_definition(&definition).unwrap()]).unwrap();
        let call = read_one("(let ((y (twice rs1))) (twice y))").unwrap();
        let expanded = library.expand(&call).unwrap();
        assert_eq!(render(&expanded), "(let ((y (add i32 rs1 rs1))) (add i32 y y))");
    }

    #[test]
    fn elaborates_lisp_behaviors_and_typed_decode_requirements() {
        let document =
            elaborate_document(include_str!("../examples/lisp_behaviors.axisl")).unwrap();
        crate::validate::validate_document(&document).unwrap();
        assert_eq!(document.instructions.len(), 6);

        let load = &document.instructions[0];
        assert!(load.formal_semantics.is_empty());
        assert_eq!(
            load.effects,
            "set rd = load(i32, unsigned, add(i32, rs1, shl(i32, imm, 2)))"
        );

        let branch = &document.instructions[2];
        assert_eq!(
            branch.effects,
            "when icmp_eq(rs1, rs2): setpc(add(i32, pc, imm))"
        );

        let state = &document.instructions[4];
        assert_eq!(
            state.effects,
            "set rd = add(i32, rs1, rs2); setstate(flags, and(i32, rs1, 15), i4)"
        );

        let constrained = &document.instructions[5];
        assert_eq!(constrained.decode_requires, "a64_extended_reg(rs2)");
    }

    #[test]
    fn pure_lisp_behavior_desugars_to_formal_semantics() {
        let source = r#"(axis-module pure-behavior
          (defformat unary
            (fields (rd 4 0) (rs1 9 5) (opcode 31 10)))
          (definstruction INCREMENT
            (format unary)
            (encoding (opcode 1))
            (operands (rd reg i32 out) (rs1 reg i32 in))
            (behavior (set rd (add i32 rs1 1)))))"#;
        let document = elaborate_document(source).unwrap();
        assert_eq!(document.instructions[0].formal_semantics, "(add i32 rs1 1)");
        assert_eq!(
            document.instructions[0].effects,
            "set rd = add(i32, rs1, 1)"
        );
    }

    #[test]
    fn elaborates_lisp_barrier_behavior() {
        let source = r#"(axis-module barriers
          (defformat system
            (fields (option 11 8) (fixed 31 12) (low 7 0)))
          (definstruction DMB
            (format system)
            (encoding (fixed 872499) (low 191))
            (operands (option imm i4 in))
            (behavior (barrier dmb option))))"#;
        let document = elaborate_document(source).unwrap();
        crate::validate::validate_document(&document).unwrap();
        assert_eq!(document.instructions[0].effects, "barrier(dmb, option)");
        assert!(matches!(
            document.instructions[0].behavior.as_ref().unwrap().effects[0].loc,
            crate::effects::Loc::Barrier { ref kind, width: 4 } if kind == "dmb"
        ));
    }

    #[test]
    fn supports_boolean_requires_and_rejects_unknown_forms() {
        let bad_behavior = r#"(axis-module bad
          (definstruction BAD (behavior (teleport 0))))"#;
        let error = elaborate_document(bad_behavior).unwrap_err();
        assert!(error
            .message
            .contains("unsupported behavior statement `teleport`"));

        let document =
            elaborate_document(include_str!("../examples/lisp_constraints.axisl")).unwrap();
        assert_eq!(
            document.instructions[0].decode_requires,
            "all(uimm_lt(amount, 5), not(uimm_eq(option, 7)))"
        );
        assert!(matches!(
            document.instructions[0].decode_constraint,
            Some(crate::decode_constraint::DecodeConstraint::And(_))
        ));

        let bad_requires = r#"(axis-module bad
          (definstruction BAD (requires (telepathic amount 5))))"#;
        let error = elaborate_document(bad_requires).unwrap_err();
        assert!(error
            .message
            .contains("unsupported requires predicate `telepathic`"));
    }

    #[test]
    fn elaborates_atomic_groups_composed_guards_and_masked_constraints() {
        let source = r#"(axis-module atomic-pair
          (definstruction CASP-LIKE
            (operands
              (rs reg i32 inout)
              (rs2 reg i32 inout)
              (rt reg i32 in)
              (rn reg i32 in))
            (requires (and (masked-eq rs 1 0) (mask= rt 1 0)))
            (behavior
              (atomic-group 3
                (set rs (atomic-load i32 unsigned acquire rn))
                (when (and (= rs (input rs)) (= rs2 (input rs2)))
                  (atomic-store rn rt i32 release))))))"#;
        let document = elaborate_document(source).unwrap();
        let instruction = &document.instructions[0];
        assert_eq!(
            instruction.decode_requires,
            "all(uimm_mask_eq(rs, 1, 0), uimm_mask_eq(rt, 1, 0))"
        );
        let behavior = instruction.behavior.as_ref().unwrap();
        assert_eq!(behavior.effects.len(), 2);
        assert!(behavior
            .effects
            .iter()
            .all(|effect| effect.atomic_group == 3));
        assert_eq!(
            crate::effects::render_semexpr(&behavior.effects[1].guard.as_ref().unwrap().expr),
            "(and (icmp_eq rs (input rs)) (icmp_eq rs2 (input rs2)))"
        );

        let canonical = crate::emit::emit_lisp(&document);
        assert!(canonical.contains("(atomic-group 3"));
        assert!(canonical.contains("(requires (and (masked-eq rs 1 0) (masked-eq rt 1 0)))"));
        let roundtripped = elaborate_document(&canonical).unwrap();
        assert_eq!(
            roundtripped.instructions[0].behavior,
            document.instructions[0].behavior
        );
        assert_eq!(
            roundtripped.instructions[0].decode_constraint,
            document.instructions[0].decode_constraint
        );
    }

    #[test]
    fn mode_and_core_forms_require_structural_properties() {
        let missing_field = r#"(axis-module bad
          (defmode field-mode
            (csr 0x7c0)
            (values (scalar 0))
            (default scalar)))"#;
        let error = elaborate_document(missing_field).unwrap_err();
        assert!(error.message.contains("defmode requires `(field hi lo)`"));

        let bad_value = r#"(axis-module bad
          (defmode field-mode
            (csr 0x7c0)
            (field 1 0)
            (values (scalar))
            (default scalar)))"#;
        let error = elaborate_document(bad_value).unwrap_err();
        assert!(error.message.contains("mode value must be `(name number)`"));

        let missing_kind = r#"(axis-module bad
          (defcore core0 (threads 1)))"#;
        let error = elaborate_document(missing_kind).unwrap_err();
        assert!(error.message.contains("defcore requires `(kind name)`"));

        let missing_isa = r#"(axis-module bad
          (defpersonality scalar1
            (discipline independent (threads 1))))"#;
        let error = elaborate_document(missing_isa).unwrap_err();
        assert!(error
            .message
            .contains("defpersonality requires `(implements isa-name)`"));

        let duplicate_parameter = r#"(axis-module bad
          (defpersonality scalar1
            (implements rv32)
            (discipline independent (threads 1) (threads 2))))"#;
        let error = elaborate_document(duplicate_parameter).unwrap_err();
        assert!(error
            .message
            .contains("duplicate discipline parameter `threads`"));

        let missing_size = r#"(axis-module bad
          (defmemory l1 (kind sram)))"#;
        let error = elaborate_document(missing_size).unwrap_err();
        assert!(error
            .message
            .contains("defmemory requires `(size-bytes number)`"));

        let bad_tile = r#"(axis-module bad
          (deftile tile0 (fabric crossbar)))"#;
        let error = elaborate_document(bad_tile).unwrap_err();
        assert!(error
            .message
            .contains("unsupported deftile property `fabric`"));

        let missing_family = r#"(axis-module bad
          (defaccelerator unit0))"#;
        let error = elaborate_document(missing_family).unwrap_err();
        assert!(error
            .message
            .contains("defaccelerator requires `(family name)`"));

        let bad_port = r#"(axis-module bad
          (defaccelerator unit0
            (family nearasic)
            (ports (a input i32))))"#;
        let error = elaborate_document(bad_port).unwrap_err();
        assert!(error
            .message
            .contains("accelerator port must be `(name direction kind type)`"));

        let no_output = r#"(axis-module bad
          (defaccelerator unit0
            (family nearasic)
            (ports (a input bits i32))
            (formal (not i32 a))))"#;
        let error = elaborate_document(no_output).unwrap_err();
        assert!(error
            .message
            .contains("accelerator formal semantics requires an output port"));
    }

    #[test]
    fn expands_bounded_instruction_families_into_typed_instructions() {
        let document =
            elaborate_document(include_str!("../examples/lisp_aarch64_family.axisl")).unwrap();
        crate::validate::validate_document(&document).unwrap();
        assert_eq!(document.instructions.len(), 4);
        assert_eq!(
            document
                .instructions
                .iter()
                .map(|instruction| instruction.mnemonic.as_str())
                .collect::<Vec<_>>(),
            ["ADD_W_SHIFT", "SUB_W_SHIFT", "ADD_X_SHIFT", "SUB_X_SHIFT"]
        );
        assert_eq!(document.instructions[0].operands[0].width, 32);
        assert_eq!(document.instructions[2].operands[0].width, 64);
        assert!(document
            .instructions
            .iter()
            .all(|instruction| instruction.latency_cycles == 2));
        assert_eq!(
            document.instructions[0].decode_requires,
            "a64_shifted_reg(i32, shift, amount)"
        );
        assert_eq!(
            document.instructions[3].decode_requires,
            "a64_shifted_reg(i64, shift, amount)"
        );
        assert!(document.instructions[0]
            .effects
            .contains("add(i32, rn, a64_shift_reg(i32"));
        assert!(document.instructions[1]
            .effects
            .contains("sub(i32, rn, a64_shift_reg(i32"));
    }

    #[test]
    fn instruction_families_reject_unsafe_or_ambiguous_tables() {
        let non_explicit =
            read_one("(definstruction-family bad (name) ((A)) (definstruction name))").unwrap();
        assert!(expand_instruction_family(&non_explicit)
            .unwrap_err()
            .message
            .contains("must start with `$`"));

        let wrong_arity = read_one(
            "(definstruction-family bad ($name $opcode) ((A 1) (B)) (definstruction $name (opcode $opcode)))",
        )
        .unwrap();
        assert!(expand_instruction_family(&wrong_arity)
            .unwrap_err()
            .message
            .contains("row 2 has 1 values, expected 2"));

        let duplicate =
            read_one("(definstruction-family bad ($name) ((A) (A)) (definstruction $name))")
                .unwrap();
        assert!(expand_instruction_family(&duplicate)
            .unwrap_err()
            .message
            .contains("expands duplicate instruction `A`"));

        let unused =
            read_one("(definstruction-family bad ($name $unused) ((A 0)) (definstruction $name))")
                .unwrap();
        assert!(expand_instruction_family(&unused)
            .unwrap_err()
            .message
            .contains("parameter `$unused` is unused"));

        let duplicate_family = r#"(axis-module duplicate-family
          (definstruction-family pair ($name) ((A)) (definstruction $name))
          (definstruction-family pair ($name) ((B)) (definstruction $name)))"#;
        assert!(elaborate_document(duplicate_family)
            .unwrap_err()
            .message
            .contains("duplicate instruction family `pair`"));
    }

    #[test]
    fn property_fragments_reject_unknown_duplicate_cyclic_and_unbounded_expansion() {
        let unknown = r#"(axis-module bad
          (definstruction BAD (use-properties missing)))"#;
        let error = elaborate_document(unknown).unwrap_err();
        assert!(error
            .message
            .contains("unknown property fragment `missing`"));

        let duplicate = r#"(axis-module bad
          (defproperties cost (latency 1))
          (defproperties cost (latency 2)))"#;
        let error = elaborate_document(duplicate).unwrap_err();
        assert!(error.message.contains("duplicate property fragment `cost`"));

        let cyclic = r#"(axis-module bad
          (defproperties a (use-properties b))
          (defproperties b (use-properties a))
          (definstruction BAD (use-properties a)))"#;
        let error = elaborate_document(cyclic).unwrap_err();
        assert!(error
            .message
            .contains("property fragment cycle: a -> b -> a"));

        let properties = "(latency 1) ".repeat(MAX_PROPERTY_EXPANSIONS + 1);
        let source = format!(
            "(axis-module bad (defproperties huge {properties}) \
             (definstruction BAD (use-properties huge)))"
        );
        let error = elaborate_document(&source).unwrap_err();
        assert!(error
            .message
            .contains("property fragments expand to more than"));
    }

    #[test]
    fn instruction_family_expansion_has_a_hard_bound() {
        let rows = (0..=MAX_FAMILY_EXPANSIONS)
            .map(|index| format!("(I{index})"))
            .collect::<Vec<_>>()
            .join(" ");
        let source =
            format!("(definstruction-family too-large ($name) ({rows}) (definstruction $name))");
        let family = read_one(&source).unwrap();
        let error = expand_instruction_family(&family).unwrap_err();
        assert!(error.message.contains("maximum is 4096"));
    }

    #[test]
    fn fixed_register_operands_consume_no_bits_and_round_trip() {
        let source = r#"(axis-module fixed-register
          (defformat one
            (bits 32)
            (fields (fixed 31 5) (rd 4 0)))
          (definstruction READ
            (mnemonic READ)
            (format one)
            (encoding (fixed 1))
            (operands
              (rd a64_gpr64 i64 out)
              (flag a64_gpr64 i64 in (fixed 7)))))"#;
        let document = elaborate_document(source).unwrap();
        crate::validate::validate_document(&document).unwrap();
        let fixed = &document.instructions[0].operands[1];
        assert_eq!(fixed.fixed, Some(7));
        assert!(fixed.derived_from.is_empty());
        assert!(
            crate::layout::resolve_layout(&document, &document.instructions[0])
                .unwrap()
                .is_encodable(),
            "a fixed operand is not an unencoded one"
        );
        let rendered = crate::emit_lisp(&document);
        assert!(rendered.contains("(flag a64_gpr64 i64 in (fixed 7))"), "{rendered}");
        assert_eq!(elaborate_document(&rendered).unwrap(), document);
        // Bits and a fixed register at once is two answers to one question.
        let bound = source.replace("(fields (fixed 31 5) (rd 4 0))", "(fields (fixed 31 10) (flag 9 5) (rd 4 0))");
        let document = elaborate_document(&bound).unwrap();
        assert!(crate::validate::validate_document(&document).is_err());
    }

    #[test]
    fn derived_register_operands_name_their_encoded_base() {
        let source = r#"(axis-module derived-register
          (defformat pair
            (bits 32)
            (fields (fixed 31 5) (base 4 0)))
          (definstruction PAIR
            (mnemonic PAIR)
            (format pair)
            (encoding (fixed 1))
            (operands
              (base a64_gpr64 i64 in)
              (next a64_gpr64 i64 out (derive base 1)))))"#;
        let document = elaborate_document(source).unwrap();
        crate::validate::validate_document(&document).unwrap();
        let derived = &document.instructions[0].operands[1];
        assert_eq!(derived.derived_from, "base");
        assert_eq!(derived.derived_add, 1);
        assert!(
            crate::layout::resolve_layout(&document, &document.instructions[0])
                .unwrap()
                .is_encodable()
        );
        let rendered = crate::emit_lisp(&document);
        assert!(rendered.contains("(next a64_gpr64 i64 out (derive base 1))"));
        assert_eq!(elaborate_document(&rendered).unwrap(), document);
    }
}
