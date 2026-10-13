use std::fmt;

use crate::ast::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    pub line: usize,
    pub message: String,
}

impl ParseError {
    pub(crate) fn new(line: usize, message: impl Into<String>) -> Self {
        Self {
            line,
            message: message.into(),
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "parse error on line {}: {}", self.line, self.message)
    }
}

/// Parse a Lisp source into the typed document.
///
/// The block grammar this used to dispatch to is gone: it was a compatibility
/// reader for `.axis`/`.pceadl` sources that nothing authored any more, and
/// PCE consumes emitted bundles rather than AXIS source.
/// The document as the *frontend* produced it, before the semantic expansions.
///
/// This is what `emit-lisp` writes, and the distinction is the difference
/// between the two things "canonical" can mean. Lisp macro expansion --
/// `use-properties`, bounded families, `let`/`if` -- has already happened, so
/// the result needs no macro layer to be understood. The passes below have
/// *not*, and one of them is not invertible: scalable elaboration instantiates
/// one instruction per lane, so `sve.axisl` becomes 2797 `__l` instructions
/// that the surface cannot express and no emitter could write back.
///
/// `tests/golden.rs` states the claim this serves -- *what comes back out is
/// what went in, or a corpus cannot be rewritten from its own emitted form* --
/// and that claim is about replacing a **source**. A form nobody could keep is
/// not a replacement, which the numbers make plain: 1060 lines of `sve.axisl`
/// elaborate to 14187.
pub fn parse_frontend_document(source: &str) -> Result<Document, ParseError> {
    crate::lisp::parse_document(source)
}

pub fn parse_document(source: &str) -> Result<Document, ParseError> {
    let mut document = crate::lisp::parse_document(source)?;
    expand_loop_semantics(&mut document)?;
    expand_vector_semantics(&mut document)?;
    check_kernel_launches(&mut document)?;
    expand_scalable_semantics(&mut document)?;
    resolve_behavior_widths(&mut document)?;
    Ok(document)
}

/// Re-resolve behavior widths now that each instruction's ISA is known.
///
/// `annotate_behavior_widths` runs at the frontend boundary, where an
/// instruction has been parsed but the ISA it names has not been looked up, so
/// it takes the widest operand as the machine's word. That guess is wrong
/// exactly when no operand is as wide as the machine: AArch64's `B` carries a
/// single 26-bit immediate, so its branch target was evaluated at 32 bits on a
/// 64-bit machine and wrapped at four gigabytes.
///
/// This runs at the one point both frontends pass through, for the same reason
/// the loop and vector expansions do -- and it is idempotent, because a width
/// is a pure function of the expression and the context it is given.
fn resolve_behavior_widths(document: &mut Document) -> Result<(), ParseError> {
    let words: std::collections::HashMap<&str, u32> = document
        .isas
        .iter()
        .map(|isa| (isa.name.as_str(), isa.word_bits))
        .collect();
    let words: std::collections::HashMap<String, u32> = words
        .into_iter()
        .map(|(name, width)| (name.to_string(), width))
        .collect();
    for instruction in &mut document.instructions {
        let Some(&word) = words.get(&instruction.isa) else {
            continue;
        };
        let operands: Vec<(String, u32)> = instruction
            .operands
            .iter()
            .map(|operand| (operand.name.clone(), operand.width))
            .collect();
        let Some(behavior) = instruction.behavior.as_mut() else {
            continue;
        };
        crate::effects::annotate_behavior_widths_for_machine(behavior, &operands, word.max(32))
            .map_err(|message| {
                ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
            })?;
    }
    Ok(())
}

/// Unroll bounded loops (`src/loops.rs`).
///
/// This runs before the vector passes because a loop is the more primitive
/// construct: its body may contain lane-wise operators, and once it is unrolled
/// they are ordinary sub-expressions that the vector passes then see. The
/// reverse order would leave a lane expansion staring at an `iterate` it does
/// not understand.
fn expand_loop_semantics(document: &mut Document) -> Result<(), ParseError> {
    for instruction in &mut document.instructions {
        instruction.formal_semantics =
            crate::loops::expand_loop_text(&instruction.formal_semantics).map_err(|message| {
                ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
            })?;
        // The effect surface too, which is where memory is: a contraction over
        // loaded values is a behavior, so a pass that stopped at
        // `formal_semantics` could not see one.
        if let Some(behavior) = &mut instruction.behavior {
            crate::effects::map_behavior_exprs(behavior, crate::loops::expand_loop_text)
                .map_err(|message| {
                    ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
                })?;
        }
    }
    for accelerator in &mut document.accelerators {
        accelerator.formal_semantics = crate::loops::expand_loop_text(
            &accelerator.formal_semantics,
        )
        .map_err(|message| {
            ParseError::new(1, format!("accelerator `{}`: {message}", accelerator.name))
        })?;
    }
    Ok(())
}

/// A launch that states its own behavior must perform what its kernel does
/// (`docs/tensor_design.md`, T8) -- A4's composition check, with a kernel in
/// place of a CGRA mapping.
///
/// Run here, after the loop, interchange and lane passes, because both sides
/// have to be compared in the same state: the kernel is usually written with
/// `accumulate` and a vendor's flat launch usually is not. Comparing before
/// expansion would refuse every such pair on spelling alone.
fn check_kernel_launches(document: &mut Document) -> Result<(), ParseError> {
    for instruction in &document.instructions {
        if instruction.runs_kernel.is_empty() || instruction.behavior_from_kernel {
            continue;
        }
        let Some(ours) = &instruction.behavior else {
            continue;
        };
        let mut kernel = instruction.clone();
        kernel.behavior = None;
        kernel.formal_semantics = String::new();
        kernel.effects = instruction.kernel_effects.clone();
        desugar_effects(&mut kernel, 1)?;
        let mut theirs = kernel.behavior.take().expect("a kernel elaborates to a behavior");
        let fail = |message: String| {
            ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
        };
        crate::effects::map_behavior_exprs(&mut theirs, crate::loops::expand_loop_text)
            .map_err(fail)?;
        crate::effects::map_behavior_exprs(&mut theirs, crate::interchange::expand_interchange_text)
            .map_err(fail)?;
        crate::effects::map_behavior_exprs(&mut theirs, crate::simd::expand_vector_text)
            .map_err(fail)?;
        crate::effects::behaviors_agree(ours, &theirs).map_err(|reason| {
            fail(format!(
                "runs kernel `{}` and its own behavior disagrees with it: {reason}; a launch \
                 and its kernel have to agree about the arithmetic",
                instruction.runs_kernel[0]
            ))
        })?;
    }
    Ok(())
}

/// Expand lane-wise vector operators into the bit-vector semantics every
/// backend already understands (`src/simd.rs`, `docs/simd_fp_design.md`).
///
/// This runs here, at the one point both frontends pass through, because AXIS
/// is statically elaborated: like `defsem` inlining and family expansion, a
/// vector operator is source-level shorthand and nothing downstream — typed IR,
/// validation, or the artifacts that reflect the source string — should have to
/// know it existed. Scalar documents are untouched, so their artifacts stay
/// byte-identical.
fn expand_vector_semantics(document: &mut Document) -> Result<(), ParseError> {
    for instruction in &mut document.instructions {
        // Interchange formats first: `(fcvt_f2f bf16 f32 x)` becomes integer
        // work before the lane expansion looks at it, so a lane-wise bf16
        // conversion is lanes of an integer expression rather than a shape the
        // lane machinery would have to know a third float format for.
        let converted =
            crate::interchange::expand_interchange_text(&instruction.formal_semantics)
                .map_err(|message| {
                    ParseError::new(
                        1,
                        format!("instruction `{}`: {message}", instruction.mnemonic),
                    )
                })?;
        instruction.formal_semantics = converted;
        if let Some(behavior) = &mut instruction.behavior {
            crate::effects::map_behavior_exprs(
                behavior,
                crate::interchange::expand_interchange_text,
            )
            .map_err(|message| {
                ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
            })?;
            crate::effects::map_behavior_exprs(behavior, crate::simd::expand_vector_text)
                .map_err(|message| {
                    ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
                })?;
        }
        let expanded = crate::simd::expand_vector_text(&instruction.formal_semantics)
            .map_err(|message| {
                ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
            })?;
        if expanded != instruction.formal_semantics {
            // Keep what the author wrote for the backends that can use the
            // lane structure; the expansion stays authoritative.
            instruction.vector_semantics =
                std::mem::replace(&mut instruction.formal_semantics, expanded);
        }
    }
    for accelerator in &mut document.accelerators {
        accelerator.formal_semantics =
            crate::interchange::expand_interchange_text(&accelerator.formal_semantics)
                .map_err(|message| {
                    ParseError::new(1, format!("accelerator `{}`: {message}", accelerator.name))
                })?;
        accelerator.formal_semantics = crate::simd::expand_vector_text(&accelerator.formal_semantics)
            .map_err(|message| {
                ParseError::new(1, format!("accelerator `{}`: {message}", accelerator.name))
            })?;
    }
    Ok(())
}

/// Instantiate scalable vector instructions lane-indexed
/// (`src/scalable.rs`, `docs/scalable_vectors_design.md` stage S1).
///
/// One instruction whose semantics mention `vni<elem>` becomes `VL / elem`
/// instructions, each ordinary scalar semantics over that lane's operands.
/// This runs beside the packed V1 expansion and after it, because the two are
/// different representations of the same idea and a document uses one or the
/// other: V1 packs lanes into a bit-vector because a NEON register really is
/// one register, while a scalable vector has no width AXIS scalars can hold.
///
/// The lane count comes from the instruction's ISA, so a document that uses a
/// scalable atom without declaring `(vector-bits N)` is an error rather than a
/// silent default — a wrong lane count is exactly the kind of plausible wrong
/// answer that is hard to trace back.
/// Where an operand's element sits: which register past the encoded one, and
/// which element within it.
///
/// A register holds `vector_bits / element` elements, so a lane past that many
/// is in the *next* register — which is register grouping, stated as a fact
/// rather than modelled as a value. See `Operand::lane_register` for why it is
/// published rather than represented.
fn stamp_packing(operand: &mut crate::ast::Operand, lane: u32, vector_bits: u32, element: u32) {
    if element == 0 || vector_bits < element {
        return;
    }
    let per_register = vector_bits / element;
    // A group advances one register per register of elements -- or, for an
    // interleaved view such as an SME tile, `group_step` registers (row i of
    // ZA<n>.S is ZA row 4i+n).
    let step = crate::ast::register_class(&operand.kind).map_or(1, |class| class.group_step.max(1));
    operand.lane_register = (lane / per_register) * step;
    operand.lane_element = lane % per_register;
    operand.lane_index = lane;
    operand.lane_packed = true;
    // And where those bits are, so that a consumer reads the placement rather
    // than recomputing it. A register of `vector_bits` occupies that many
    // 64-bit slots, and the element is a view inside it -- one that straddles
    // a slot boundary as soon as the register is wider than a machine word,
    // which is what limb storage is for.
    operand.slot_stride = vector_bits.div_ceil(64);
    operand.view_offset = operand.lane_element * element;
    operand.view_width = element;
    // Where this operand's file starts, in slots. A file above a scalable one
    // is placed by register count rather than by slot, so its base depends on
    // the stride and cannot be a constant in the class table. Computed once
    // here, where the stride is known, rather than by every consumer.
    if let Some(class) = crate::ast::register_class(&operand.kind) {
        operand.slot_base = class.offset + class.index_offset * operand.slot_stride;
    }
}

fn expand_scalable_semantics(document: &mut Document) -> Result<(), ParseError> {
    let uses_scalable = |instruction: &crate::ast::Instruction| {
        crate::scalable::mentions_scalable(&instruction.formal_semantics)
            || instruction
                .behavior
                .as_ref()
                .is_some_and(crate::scalable::behavior_mentions_scalable)
    };
    if !document.instructions.iter().any(uses_scalable) {
        return Ok(());
    }
    // The names of architectural state, so lane instantiation leaves them
    // alone: state is scalar, one `vxsat` rather than one per lane.
    let state_names: Vec<String> = crate::effects::isa_scalar_state_slots(&document.isas)
        .into_iter()
        .map(|(name, _width)| name)
        .collect();
    let mut expanded = Vec::with_capacity(document.instructions.len());
    for instruction in std::mem::take(&mut document.instructions) {
        if !uses_scalable(&instruction) {
            expanded.push(instruction);
            continue;
        }
        let fail = |message: String| {
            ParseError::new(1, format!("instruction `{}`: {message}", instruction.mnemonic))
        };
        let isa = document.isas.iter().find(|isa| isa.name == instruction.isa);
        let vector_bits = isa.map(|isa| isa.vector_bits).unwrap_or(0);
        if vector_bits == 0 {
            return Err(fail(format!(
                "uses a scalable vector type but its ISA `{}` declares no `(vector-bits N)`",
                instruction.isa
            )));
        }
        let realization = isa
            .map(|isa| isa.unspecified_realization.as_str())
            .filter(|name| !name.is_empty())
            .map(|name| {
                crate::scalable::Realization::parse(name).ok_or_else(|| {
                    fail(format!("unknown unspecified-realization `{name}`"))
                })
            })
            .transpose()?
            .unwrap_or_default();
        let order = isa
            .map(|isa| isa.reduction_realization.as_str())
            .filter(|name| !name.is_empty())
            .map(|name| {
                crate::scalable::ReductionOrder::parse(name).ok_or_else(|| {
                    fail(format!("unknown reduction-realization `{name}`"))
                })
            })
            .transpose()?
            .unwrap_or_default();
        let mode = crate::scalable::VectorMode {
            vector_bits,
            sew: isa.map(|isa| isa.vector_sew).unwrap_or(0),
            lmul_num: isa.map(|isa| isa.vector_lmul_num).unwrap_or(1),
            lmul_den: isa.map(|isa| isa.vector_lmul_den).unwrap_or(1),
            elen: isa.map(|isa| isa.vector_elen).unwrap_or(64),
            addr_bits: isa.map(|isa| isa.word_bits).unwrap_or(64),
            state: &state_names,
        };

        // An instruction may carry scalable semantics, a scalable behavior, or
        // both. The lane count has to agree, so it is taken from whichever is
        // present and the other is instantiated to match.
        let semantics = crate::scalable::instantiate(
            &instruction.formal_semantics,
            &mode,
            realization,
            order,
        )
        .map_err(fail)?;
        let behavior_shape = match &instruction.behavior {
            Some(behavior) if crate::scalable::behavior_mentions_scalable(behavior) => {
                crate::scalable::behavior_shape(behavior, &mode).map_err(fail)?
            }
            _ => None,
        };
        let Some((shape, lanes)) = semantics
            .as_ref()
            .map(|(shape, lanes, _)| (*shape, lanes.len() as u32))
            .or(behavior_shape)
        else {
            expanded.push(instruction);
            continue;
        };
        if let (Some((_, values, _)), Some((_, behavior_lanes))) =
            (semantics.as_ref(), behavior_shape)
        {
            if values.len() as u32 != behavior_lanes {
                return Err(fail(format!(
                    "semantics instantiate to {} lanes and the behavior to {behavior_lanes}",
                    values.len()
                )));
            }
        }
        let control = semantics.as_ref().and_then(|(_, _, control)| control.clone());

        for lane in 0..lanes {
            // A reduction is one instruction that reads every lane, so it
            // keeps its name; everything else becomes one instruction per lane.
            let suffix = if shape.collapsed {
                String::new()
            } else {
                crate::scalable::lane_suffix(lane)
            };
            let mut copy = instruction.clone();
            copy.name = format!("{}{suffix}", instruction.name);
            copy.mnemonic = format!("{}{suffix}", instruction.mnemonic);
            let instantiated = semantics
                .as_ref()
                .map(|(_, values, _)| values[lane as usize].clone());
            if behavior_shape.is_some() {
                let behavior = instruction.behavior.as_ref().expect("behavior present");
                copy.behavior = Some(
                    crate::scalable::instantiate_behavior(behavior, &mode, lane)
                        .map_err(fail)?,
                );
            }
            // The rename must see everything that names an operand: the value,
            // the definedness expression (under `vundef` the predicate appears
            // only there), and the behavior's locations as well as its
            // expressions.
            let mut named = String::new();
            if let Some(lane_value) = &instantiated {
                named.push_str(&lane_value.value);
                if let Some(defined) = &lane_value.defined {
                    named.push(' ');
                    named.push_str(defined);
                }
            }
            if let Some(behavior) = &copy.behavior {
                named.push(' ');
                named.push_str(&crate::scalable::behavior_symbols_text(behavior));
            }
            // Operands are derived from the lanes the expression actually
            // names, rather than renamed one-for-one. For a per-lane
            // instruction that is the same thing -- exactly one suffixed form
            // appears. A reduction reads every lane from a single declared
            // operand, so one `zn` becomes `zn__l0 .. zn__lN`, and only a rule
            // that asks the expression can serve both.
            // An input's lanes are at the width it DECLARES. That is the
            // shape's operand width for every form whose operands share one
            // shape -- widening forms declare theirs at their own width -- and
            // it is the only right answer for a reduction nested in a lane
            // expression: UADDV's Zn is .S elements inside a .D result.
            // Only where a reduction is NESTED: everywhere else the shape's
            // width is the lanes' width by construction, and under `vtype` a
            // declared width is a placeholder the sweep overrides.
            let nested = crate::scalable::nests_a_collapse(&instruction.formal_semantics)
                && !crate::scalable::mentions_mode_shape(&instruction.formal_semantics);
            let lane_width = |operand: &crate::ast::Operand| {
                if nested && !operand.output && matches!(operand.width, 8 | 16 | 32 | 64) {
                    operand.width
                } else {
                    shape.operand_elem(operand.output)
                }
            };
            let mut derived = Vec::with_capacity(copy.operands.len());
            for operand in &copy.operands {
                let used = lane_indices(&named, &operand.name);
                // An input with no bits of its own, derived from another
                // operand, that this lane never reads: it carries nothing here.
                // EXT's destructive source is one -- lane k reads element k+1 of
                // it, so the last lane reads only Zm.
                if used.is_empty() && !operand.output && !operand.derived_from.is_empty() {
                    continue;
                }
                if used.is_empty() {
                    let mut scalar = operand.clone();
                    if scalar.output {
                        // A collapsed result is one scalar at the width its
                        // destination declares -- CNTP counts .S elements into
                        // an X register -- and a vector result's element is
                        // the shape's.
                        if !(shape.collapsed
                            && crate::scalable::scalar_outermost_text(&instruction.formal_semantics)
                            && matches!(scalar.width, 8 | 16 | 32 | 64))
                        {
                            scalar.width = shape.operand_elem(true);
                        }
                        // A destination is never named by the expression -- an
                        // expression names what it reads -- but it is still a
                        // particular element of a particular register, and a
                        // consumer needs that as much as it needs an input's.
                        // It keeps its own name, so it keeps its own encoding
                        // bits and needs no selector.
                        let element = scalar.width;
                        if !shape.collapsed {
                            stamp_packing(&mut scalar, lane, vector_bits, element);
                        }
                    }
                    derived.push(scalar);
                    continue;
                }
                // Only when the declared operand actually carries encoding
                // bits. A description whose operand names do not match its
                // format's fields was unencodable before lanes existed and
                // stays that way; deriving from bits that are not there would
                // turn a description that merely cannot be executed into one
                // that cannot be validated.
                let encoded = crate::layout::find_format(document, &copy.format)
                    .is_some_and(|format| {
                        format.fields.iter().any(|field| field.name == operand.name)
                    });
                if !encoded {
                    for lane_index in used {
                        let mut per_lane = operand.clone();
                        per_lane.name = format!("{}__l{lane_index}", operand.name);
                        per_lane.width = lane_width(operand);
                        stamp_packing(&mut per_lane, lane_index, vector_bits,
                                      lane_width(operand));
                        derived.push(per_lane);
                    }
                    continue;
                }
                // The declared operand stays, as a selector: a scalable
                // instruction encodes one register number per vector operand
                // and reads elements of it, so the bits belong to the operand
                // that was declared and the elements belong to the lanes. A
                // format field binds by name, so dropping the declared name
                // drops the encoding -- which is why 507 proven SVE entries
                // decoded from no bits at all. `enc` marks it bound by decode
                // and read by nothing.
                let mut selector = operand.clone();
                selector.input = false;
                selector.output = false;
                selector.lane_packed = false;
                // The selector is not a value, so its width is nothing in
                // particular; it takes the element width so that the "derived
                // operands match their source" rule stays a real check rather
                // than one lanes are exempt from.
                selector.width = lane_width(operand);
                derived.push(selector);
                for lane_index in used {
                    let mut per_lane = operand.clone();
                    per_lane.name = format!("{}__l{lane_index}", operand.name);
                    // Where the bits come from. The element *within* the
                    // register is `packing`, published below; a lane past the
                    // register's capacity is in the next one, which is what
                    // register grouping is.
                    per_lane.derived_from = operand.name.clone();
                    per_lane.derived_add = 0;
                    per_lane.width = lane_width(operand);
                    // Where this element actually sits. A register holds
                    // `VLEN / elem` elements, so a lane past that many is in
                    // the *next* register — which is register grouping, stated
                    // as a fact rather than modelled as a value. See
                    // `Operand::lane_register` for why it is published rather
                    // than represented.
                    stamp_packing(&mut per_lane, lane_index, vector_bits,
                                  lane_width(operand));
                    derived.push(per_lane);
                }
            }
            copy.operands = derived;
            if copy.behavior.is_some() {
                // Widths were resolved against the source operands; the lane's
                // are narrower and renamed, so they are resolved again.
                let operands: Vec<(String, u32)> = copy
                    .operands
                    .iter()
                    .map(|operand| (operand.name.clone(), operand.width))
                    .collect();
                let behavior = copy.behavior.as_mut().expect("behavior present");
                crate::effects::annotate_behavior_widths(behavior, &operands)
                    .map_err(|message| fail(message))?;
            }
            copy.vector_semantics = instruction.formal_semantics.clone();
            copy.scalable_origin = instruction.mnemonic.clone();
            copy.scalable_lane = lane;
            if let Some(lane_value) = instantiated {
                copy.formal_semantics = lane_value.value;
                if let Some(defined) = lane_value.defined {
                    let mut mask = copy.clone();
                    mask.name = format!("{}__defined", copy.name);
                    mask.mnemonic = format!("{}__defined", copy.mnemonic);
                    mask.definedness_of = copy.mnemonic.clone();
                    mask.formal_semantics = defined;
                    mask.behavior = None;
                    mask.defined_by = String::new();
                    copy.defined_by = mask.mnemonic.clone();
                    copy.defined_operand = control
                        .clone()
                        .map(|name| {
                            let renamed = format!("{name}{suffix}");
                            if copy.operands.iter().any(|operand| operand.name == renamed) {
                                renamed
                            } else {
                                name
                            }
                        })
                        .unwrap_or_default();
                    expanded.push(copy);
                    expanded.push(mask);
                    continue;
                }
            }
            expanded.push(copy);
        }
    }
    document.instructions = expanded;
    Ok(())
}

/// Which lanes of `name` a rendered expression mentions, in order.
///
/// Reads the lane index out of the symbol rather than assuming a count, so a
/// reduction that names every lane and a per-lane instruction that names one
/// go through the same rule.
fn lane_indices(text: &str, name: &str) -> Vec<u32> {
    let prefix = format!("{name}__l");
    let mut found: Vec<u32> = text
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .filter_map(|token| token.strip_prefix(&prefix)?.parse::<u32>().ok())
        .collect();
    found.sort_unstable();
    found.dedup();
    found
}


pub(crate) fn desugar_decode_constraint(
    instruction: &mut Instruction,
    line: usize,
) -> Result<(), ParseError> {
    let operands = instruction
        .operands
        .iter()
        .map(|operand| operand.name.clone())
        .collect::<Vec<_>>();
    instruction.decode_constraint =
        crate::decode_constraint::parse_decode_constraint(&instruction.decode_requires, &operands)
            .map_err(|message| ParseError::new(line, message))?;
    Ok(())
}
/// Lower the infix `effects:` block. A pure single register `set` to the output
/// operand desugars into `formal_semantics` (so every backend handles it
/// unchanged). Effectful behavior — a memory load in a register write, or a
/// store — stays in `effects` with empty `formal_semantics`: the pure
/// value-model backends skip it and the executor applies the effects against a
/// memory model. See docs/effects_design.md.
pub(crate) fn desugar_effects(
    instruction: &mut Instruction,
    line: usize,
) -> Result<(), ParseError> {
    use crate::effects::Loc;
    if instruction.effects.trim().is_empty() {
        return Ok(());
    }
    if !instruction.formal_semantics.trim().is_empty() {
        return Err(ParseError::new(
            line,
            "instruction has both `effects` and `formal_semantics`; use one".to_string(),
        ));
    }
    let mut behavior = crate::effects::parse_behavior(&instruction.effects)
        .map_err(|message| ParseError::new(line, message))?;
    let operand_widths = instruction
        .operands
        .iter()
        .map(|operand| (operand.name.clone(), operand.width))
        .collect::<Vec<_>>();
    crate::effects::annotate_behavior_widths(&mut behavior, &operand_widths)
        .map_err(|message| ParseError::new(line, message))?;
    instruction.behavior = Some(behavior.clone());

    // Pure fast path: a single register write to the output operand desugars.
    if behavior.effects.len() == 1 && !crate::effects::is_effectful(&behavior) {
        if let Loc::Reg(target) = &behavior.effects[0].loc {
            let output = instruction
                .operands
                .iter()
                .find(|operand| operand.output)
                .map(|operand| operand.name.as_str());
            if output != Some(target.as_str()) {
                return Err(ParseError::new(
                    line,
                    format!("`set {target}` must write the instruction's output operand"),
                ));
            }
            let candidate = crate::effects::render_semexpr(&behavior.effects[0].value.expr);
            let output_width = instruction
                .operands
                .iter()
                .find(|operand| operand.output)
                .map(|operand| operand.width)
                .unwrap_or(32);
            let operand_symbols = instruction
                .operands
                .iter()
                .map(|operand| operand.name.clone())
                .collect::<Vec<_>>();
            let is_operand_pure = crate::semantics::parse_formal_semantics(&candidate)
                .and_then(|expr| crate::ir::lower(&expr, output_width))
                .and_then(|sem| crate::ir::check_symbols(&sem, &operand_symbols))
                .is_ok();
            if is_operand_pure {
                instruction.formal_semantics = candidate;
                return Ok(());
            }
        }
    }

    // Effectful path: every register `set` must target an output operand; the
    // behavior stays in `effects` for the executor.
    for effect in &behavior.effects {
        if let Loc::Reg(target) = &effect.loc {
            if !instruction
                .operands
                .iter()
                .any(|operand| operand.output && &operand.name == target)
            {
                return Err(ParseError::new(
                    line,
                    format!("`set {target}` must write an output operand"),
                ));
            }
        }
    }
    Ok(())
}
