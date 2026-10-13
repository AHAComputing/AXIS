//! AXIS emit: common domain (split from the former monolithic emit.rs).

pub(crate) use crate::ast::*;
pub(crate) use crate::ir::{lower, Op, Sem};
pub(crate) use crate::layout::{resolve_layout, InstructionLayout};
pub(crate) use crate::optisynth::optisynth_formal_semantics;
pub(crate) use crate::semantics::{parse_formal_semantics, SemanticExpr};
pub(crate) use std::collections::HashMap;

/// The ARCHITECTURAL instruction list: one entry per encoding.
///
/// A scalable instruction elaborates into a lane GROUP — `SVCMPLT_S__l0 ..
/// __l3`, one per lane — because that is what executing it means: N ordinary
/// scalar operations over elements of the registers it names. That view is
/// right for lift/exec/semantics, which consume the lanes.
///
/// It is wrong for every DECODE-KEYED export. A lane group shares one
/// opcode/func3/func7, so emitting the instances puts N entries on one decode
/// key: PCE's `aha/isa/adl_loader.py` builds its key from exactly those three
/// fields, and OptiSynth's pinned `llvm.pce.<mnemonic-lower>` convention turns
/// them into `llvm.pce.svcmplt_s__l0`, which is not an intrinsic anything can
/// call. Measured on `examples/scalable_predicate.axisl`: 112 entries, 15
/// encodings shared by 4 to 8 entries each.
///
/// It also contradicts an invariant this crate PROVES. `validate_isas` rejects
/// instructions that "overlap in the decode space", and the source document
/// passes — so emitting the expansion produces an artifact violating a property
/// its own input was validated for.
///
/// Consumers cannot correct it themselves: the decode-keyed payloads carry no
/// `scalable_origin` or `scalable_lane`, so there is nothing to filter on.
/// Hence the fix belongs here, once, rather than in each consumer — and the
/// entries returned keep the DECLARED operands, which is what the encoding
/// actually holds: one register selector per vector operand, not one per lane.
pub(crate) fn architectural_instructions(document: &Document) -> Vec<Instruction> {
    document
        .instructions
        .iter()
        .filter(|instruction| {
            // Lane 0 stands for the group; a non-scalable instruction has no
            // origin and is always itself.
            let represents_group =
                instruction.scalable_origin.is_empty() || instruction.scalable_lane == 0;
            // A definedness companion is a SECOND artifact of the same
            // instantiation: it clones its instruction, so it carries the same
            // origin and the same encoding, and collapsing both would put two
            // entries back on one decode key — the very thing this is fixing.
            // It describes which lanes are defined, which is a semantics
            // question rather than an encoding one.
            let is_definedness_companion = !instruction.definedness_of.is_empty();
            represents_group && !is_definedness_companion
        })
        .map(|instruction| {
            let mut architectural = instruction.clone();
            if !architectural.scalable_origin.is_empty() {
                architectural.mnemonic = architectural.scalable_origin.clone();
                // Drop the per-lane operands, keeping the declared selector the
                // format field actually binds to.
                architectural
                    .operands
                    .retain(|operand| !is_lane_operand(&operand.name));
                // ...and with them the lane-0 INSTANTIATION of the semantics,
                // which names `zn__l0` — operands this entry no longer declares.
                // `vector_semantics` is the declared form the expansion saved
                // for exactly this: an entry whose semantics referenced symbols
                // absent from its own operand list would be internally
                // inconsistent, and a consumer parsing it would resolve nothing.
                if !architectural.vector_semantics.is_empty() {
                    architectural.formal_semantics =
                        architectural.vector_semantics.clone();
                }
            }
            architectural
        })
        .collect()
}

/// Is this operand one of a scalable instantiation's per-lane copies?
///
/// Structural rather than a name sniff would be better, but the per-lane copies
/// are distinguished only by the `__l<n>` suffix the expansion gives them, and
/// `lane_packed` is also set on the declared selector.
fn is_lane_operand(name: &str) -> bool {
    match name.rfind("__l") {
        Some(position) => name[position + 3..]
            .chars()
            .all(|character| character.is_ascii_digit())
            && position + 3 < name.len(),
        None => false,
    }
}

/// Resolve an instruction's bit layout for emission. Validation guarantees
/// resolution succeeds for validated documents; the fallback keeps emitters
/// total for direct library use, marking everything unencoded.
pub(crate) fn layout_for(document: &Document, instruction: &Instruction) -> InstructionLayout {
    resolve_layout(document, instruction).unwrap_or_else(|_| InstructionLayout {
        format: instruction.format.clone(),
        bits: 32,
        match_value: 0,
        mask_value: 0,
        fixed_fields: Vec::new(),
        operand_fields: Vec::new(),
        unencoded_operands: instruction
            .operands
            .iter()
            .map(|operand| operand.name.clone())
            .collect(),
        unbound_fields: Vec::new(),
    })
}

pub(crate) fn semantic_ast_json(source: &str) -> String {
    if source.trim().is_empty() {
        return "null".to_string();
    }
    match parse_formal_semantics(source) {
        Ok(expr) => semantic_expr_json(&expr),
        Err(err) => format!("{{\"error\": {}}}", json_string(&err.message)),
    }
}

pub(crate) fn semantic_expr_json(expr: &SemanticExpr) -> String {
    match expr {
        SemanticExpr::Atom(atom) => {
            if is_semantic_integer_literal(atom) {
                format!("{{\"const\": {}}}", json_string(atom))
            } else {
                format!("{{\"symbol\": {}}}", json_string(atom))
            }
        }
        SemanticExpr::List(items) => semantic_list_json(items),
    }
}

pub(crate) fn semantic_list_json(items: &[SemanticExpr]) -> String {
    let Some(SemanticExpr::Atom(op)) = items.first() else {
        return "{\"error\": \"operator must be an atom\"}".to_string();
    };
    let raw_args = &items[1..];
    if op == "let" {
        let [SemanticExpr::List(bindings), body] = raw_args else {
            return "{\"error\": \"let expects bindings and one body\"}".to_string();
        };
        let bindings = bindings
            .iter()
            .map(|binding| {
                let SemanticExpr::List(pair) = binding else {
                    return "{\"error\": \"let binding must be a pair\"}".to_string();
                };
                let [SemanticExpr::Atom(name), value] = pair.as_slice() else {
                    return "{\"error\": \"let binding must be (name value)\"}".to_string();
                };
                format!(
                    "{{\"name\": {}, \"value\": {}}}",
                    json_string(name),
                    semantic_expr_json(value)
                )
            })
            .collect::<Vec<_>>();
        return format!(
            "{{\"op\": \"let\", \"bindings\": [{}], \"body\": {}}}",
            bindings.join(", "),
            semantic_expr_json(body)
        );
    }
    let (type_atom, value_args) = if raw_args
        .first()
        .is_some_and(|item| matches!(item, SemanticExpr::Atom(atom) if is_semantic_type_atom(atom)))
    {
        let SemanticExpr::Atom(type_atom) = &raw_args[0] else {
            unreachable!("checked above")
        };
        (Some(type_atom.as_str()), &raw_args[1..])
    } else {
        (None, raw_args)
    };
    let args: Vec<String> = value_args.iter().map(semantic_expr_json).collect();
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!("\"op\": {}", json_string(op)));
    if let Some(type_atom) = type_atom {
        out.push_str(&format!(", \"type\": {}", json_string(type_atom)));
    }
    out.push_str(&format!(", \"args\": [{}]", args.join(", ")));
    out.push('}');
    out
}

pub(crate) fn is_semantic_type_atom(atom: &str) -> bool {
    let mut chars = atom.chars();
    let Some(prefix) = chars.next() else {
        return false;
    };
    matches!(prefix, 'i' | 'u') && chars.all(|ch| ch.is_ascii_digit())
}

pub(crate) fn is_semantic_integer_literal(atom: &str) -> bool {
    if atom.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }
    atom.strip_prefix("0x")
        .or_else(|| atom.strip_prefix("0X"))
        .is_some_and(|hex| !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit()))
}

pub(crate) fn emit_operands_json(out: &mut String, operands: &[Operand], indent: usize) {
    line(out, indent, "\"operands\": [");
    for (idx, operand) in operands.iter().enumerate() {
        line(out, indent + 1, "{");
        line(
            out,
            indent + 2,
            &format!("\"name\": {},", json_string(&operand.name)),
        );
        line(
            out,
            indent + 2,
            &format!("\"kind\": {},", json_string(&operand.kind)),
        );
        line(out, indent + 2, &format!("\"width\": {},", operand.width));
        line(out, indent + 2, &format!("\"input\": {},", operand.input));
        if let Some(index) = operand.fixed {
            line(out, indent + 2, &format!("\"output\": {},", operand.output));
            line(out, indent + 2, &format!("\"fixed\": {index}"));
        } else if operand.derived_from.is_empty() {
            line(out, indent + 2, &format!("\"output\": {}", operand.output));
        } else {
            line(out, indent + 2, &format!("\"output\": {},", operand.output));
            line(
                out,
                indent + 2,
                &format!(
                    "\"derived\": {{\"from\": {}, \"add\": {}}}",
                    json_string(&operand.derived_from),
                    operand.derived_add
                ),
            );
        }
        let suffix = if idx + 1 == operands.len() { "" } else { "," };
        line(out, indent + 1, &format!("}}{suffix}"));
    }
    write_indent(out, indent);
    out.push(']');
}

pub(crate) fn emit_core_json_object(out: &mut String, core: &Core, indent: usize, last: bool) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"name\": {},", json_string(&core.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"kind\": {},", json_string(&core.kind)),
    );
    line(out, indent + 1, &format!("\"threads\": {},", core.threads));
    line(
        out,
        indent + 1,
        &format!("\"implements\": {},", json_string(&core.implements)),
    );
    line(
        out,
        indent + 1,
        &format!("\"features\": {},", json_list(&core.features)),
    );
    // ⚠️ The PIPELINE, where a consumer can reach it. A core that declares a
    // width and its units and then publishes neither is declaring numbers
    // nothing can read -- which is the shape `expected-speedup` already has,
    // and the reason it is 1.0 on all 338 instructions of a corpus.
    line(
        out,
        indent + 1,
        &format!("\"issue_width\": {},", core.issue_width.max(1)),
    );
    line(
        out,
        indent + 1,
        &format!("\"memory\": {},", json_string(&core.memory)),
    );
    line(
        out,
        indent + 1,
        &format!("\"branch_penalty\": {},", core.branch_penalty),
    );
    line(
        out,
        indent + 1,
        &format!("\"predictor\": {},", json_string(&core.predictor)),
    );
    line(
        out,
        indent + 1,
        &format!("\"predictor_entries\": {},", core.predictor_entries),
    );
    line(out, indent + 1, &format!("\"rob\": {},", core.rob));
    line(
        out,
        indent + 1,
        &format!("\"issue_queue\": {},", core.issue_queue),
    );
    line(
        out,
        indent + 1,
        &format!("\"commit_width\": {},", core.commit_width),
    );
    // S1, S3: said only by a core that says them, so every other core's
    // manifest is the bytes it was.
    if core.dispatch_width != 0 {
        line(out, indent + 1, &format!("\"dispatch_width\": {},", core.dispatch_width));
    }
    if core.schedule != 0 {
        line(out, indent + 1, &format!("\"schedule\": {},", core.schedule));
    }
    if let Some((entries, confidence)) = core.value_prediction {
        let kind = if core.value_stride { ", \"kind\": \"stride\"" } else { "" };
        line(
            out,
            indent + 1,
            &format!("\"value_prediction\": {{\"entries\": {entries}, \"confidence\": {confidence}{kind}}},"),
        );
    }
    if core.rename_width != 0 {
        line(out, indent + 1, &format!("\"rename_width\": {},", core.rename_width));
    }
    if !core.select.is_empty() {
        line(out, indent + 1, &format!("\"select\": {},", json_string(&core.select)));
    }
    if !core.eliminate.is_empty() {
        line(out, indent + 1, &format!("\"eliminate\": {},", json_string(&core.eliminate)));
    }
    if !core.load_order.is_empty() {
        line(out, indent + 1, &format!("\"load_order\": {},", json_string(&core.load_order)));
    }
    if core.store_buffer != 0 {
        line(
            out,
            indent + 1,
            &format!(
                "\"store_buffer\": {{\"entries\": {}, \"drain\": {}}},",
                core.store_buffer,
                json_string(if core.store_drain.is_empty() { "order" } else { &core.store_drain })
            ),
        );
    }
    if !core.queues.is_empty() {
        let each: Vec<String> = core
            .queues
            .iter()
            .map(|(name, size, units)| {
                format!(
                    "{{\"name\": {}, \"size\": {size}, \"units\": [{}]}}",
                    json_string(name),
                    units.iter().map(|u| json_string(u)).collect::<Vec<_>>().join(", ")
                )
            })
            .collect();
        line(out, indent + 1, &format!("\"queues\": [{}],", each.join(", ")));
    }
    if !core.bypass.is_empty() {
        let pairs: Vec<String> = core
            .bypass
            .iter()
            .map(|(from, to, cycles)| format!("[{}, {}, {cycles}]", json_string(from), json_string(to)))
            .collect();
        line(out, indent + 1, &format!("\"bypass\": [{}],", pairs.join(", ")));
    }
    line(
        out,
        indent + 1,
        &format!("\"predictor_history\": {},", core.predictor_history),
    );
    let params: Vec<String> = core
        .predictor_params
        .iter()
        .map(|(key, value)| format!("{}: {value}", json_string(key)))
        .collect();
    line(
        out,
        indent + 1,
        &format!("\"predictor_params\": {{{}}},", params.join(", ")),
    );
    // D3: said only by a core that has one, so every other core's manifest
    // is the bytes it was.
    if let Some(quick) = &core.overrides {
        line(
            out,
            indent + 1,
            &format!(
                "\"overrides\": {{\"predictor\": {}, \"entries\": {}, \"cycles\": {}}},",
                json_string(&quick.predictor),
                quick.entries,
                quick.cycles
            ),
        );
    }
    // ⚠️ `null`, SAID, for a core that does not model memory ordering -- not
    // an object of defaults. The two are different machines.
    match &core.lsq {
        Some(lsq) => line(
            out,
            indent + 1,
            &format!(
                "\"lsq\": {{\"loads\": {}, \"stores\": {}, \"disambiguation\": {}, \"forwarding\": {}, \"replay\": {}, \"store_sets\": {}}},",
                lsq.loads,
                lsq.stores,
                json_string(&lsq.disambiguation),
                lsq.forwarding,
                lsq.replay,
                lsq.store_sets
            ),
        ),
        None => line(out, indent + 1, "\"lsq\": null,"),
    }
    match &core.front_end {
        Some(fe) => line(
            out,
            indent + 1,
            &format!(
                "\"front_end\": {{\"fetch_width\": {}, \"depth\": {}, \"buffer\": {}, \"btb\": {}, \"btb_penalty\": {}, \"ras\": {}, \"icache\": {}, \"wrong_path_fetch\": {}, \"wrong_path_execute\": {}{}{}{}}},",
                fe.fetch_width, fe.depth, fe.buffer, fe.btb, fe.btb_penalty, fe.ras,
                json_string(&fe.icache), fe.wrong_path_fetch, fe.wrong_path_execute,
                // U2: said only by a front end that has one, so every other
                // core's manifest is the bytes it was.
                fe.op_cache.as_ref().map_or(String::new(), |oc| format!(
                    ", \"op_cache\": {{\"entries\": {}, \"ways\": {}, \"window\": {}, \"width\": {}, \"depth\": {}}}",
                    oc.entries, oc.ways, oc.window, oc.width, oc.depth
                )),
                fe.loop_buffer.as_ref().map_or(String::new(), |lb| format!(
                    ", \"loop_buffer\": {{\"ops\": {}, \"width\": {}, \"depth\": {}}}",
                    lb.ops, lb.width, lb.depth
                )),
                if fe.target_queue != 0 { format!(", \"target_queue\": {}", fe.target_queue) } else { String::new() }
            ),
        ),
        None => line(out, indent + 1, "\"front_end\": null,"),
    }
    let ports: Vec<String> = core
        .ports
        .iter()
        .map(|(port, units)| {
            let names: Vec<String> = units.iter().map(|u| json_string(u)).collect();
            format!("{}: [{}]", json_string(port), names.join(", "))
        })
        .collect();
    line(out, indent + 1, &format!("\"ports\": {{{}}},", ports.join(", ")));
    line(
        out,
        indent + 1,
        &format!(
            "\"engine\": {},",
            json_string(if core.engine.is_empty() { "trace" } else { &core.engine })
        ),
    );
    let rename: Vec<String> = core
        .rename
        .iter()
        .map(|(file, extra)| format!("{}: {extra}", json_string(file)))
        .collect();
    line(
        out,
        indent + 1,
        &format!("\"rename\": {{{}}},", rename.join(", ")),
    );
    line(
        out,
        indent + 1,
        &format!("\"model\": {},", json_string(&core.model)),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"provenance\": {},",
            json_string(if core.provenance.is_empty() { "declared" } else { &core.provenance })
        ),
    );
    line(out, indent + 1, "\"vendor\": {");
    for (idx, (key, value)) in core.vendor.iter().enumerate() {
        let suffix = if idx + 1 == core.vendor.len() { "" } else { "," };
        line(
            out,
            indent + 2,
            &format!("{}: {}{suffix}", json_string(key), json_string(value)),
        );
    }
    line(out, indent + 1, "},");
    // The warp machine, only for a core that declares one: every other core's
    // facts are byte-identical to what they were before SIMT cores existed.
    if let Some(simt) = &core.simt {
        let roles: Vec<String> = simt
            .warp_control
            .iter()
            .map(|(role, m)| {
                format!("{}: [{}]", json_string(role), m.iter().map(|x| json_string(x)).collect::<Vec<_>>().join(", "))
            })
            .collect();
        line(
            out,
            indent + 1,
            &format!(
                "\"simt\": {{\"warps\": {}, \"lanes\": {}, \"scheduler\": {}, \"stack\": {}, \"line\": {}, \"isas\": [{}], \"cache\": {{\"bytes\": {}, \"ways\": {}, \"hit\": {}, \"miss\": {}}}, \"warp_control\": {{{}}}}},",
                simt.warps,
                simt.lanes,
                json_string(&simt.scheduler),
                simt.stack,
                simt.line,
                simt.isas.iter().map(|x| json_string(x)).collect::<Vec<_>>().join(", "),
                simt.cache.bytes,
                simt.cache.ways,
                simt.cache.hit,
                simt.cache.miss,
                roles.join(", ")
            ),
        );
    }
    line(out, indent + 1, "\"units\": [");
    for (idx, unit) in core.units.iter().enumerate() {
        let suffix = if idx + 1 == core.units.len() { "" } else { "," };
        line(
            out,
            indent + 2,
            &format!(
                "{{\"name\": {}, \"count\": {}, \"pipelined\": {}{}{}{}{}{}{}}}{suffix}",
                json_string(&unit.name),
                unit.count.max(1),
                unit.pipelined,
                if unit.lanes > 0 { format!(", \"lanes\": {}", unit.lanes) } else { String::new() },
                if unit.length.is_empty() {
                    String::new()
                } else {
                    format!(", \"length\": {}", json_string(&unit.length))
                },
                if unit.accepts.is_empty() {
                    String::new()
                } else {
                    format!(
                        ", \"accepts\": [{}]",
                        unit.accepts.iter().map(|name| json_string(name)).collect::<Vec<_>>().join(", ")
                    )
                },
                if unit.transport > 0 || unit.switch > 0 {
                    format!(", \"transport\": {}, \"switch\": {}", unit.transport, unit.switch)
                } else {
                    String::new()
                },
                if unit.abort { ", \"abort\": true" } else { "" },
                if unit.queue > 0 { format!(", \"queue\": {}", unit.queue) } else { String::new() }
            ),
        );
    }
    line(out, indent + 1, "]");
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

pub(crate) fn emit_accelerator_json_object(
    out: &mut String,
    accelerator: &Accelerator,
    indent: usize,
    last: bool,
) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"name\": {},", json_string(&accelerator.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"family\": {},", json_string(&accelerator.family)),
    );
    line(
        out,
        indent + 1,
        &format!("\"subtype\": {},", json_string(&accelerator.subtype)),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"descriptor_version\": {},",
            accelerator.descriptor_version
        ),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"descriptor_schema\": {},",
            json_string(&accelerator.descriptor_schema)
        ),
    );
    line(
        out,
        indent + 1,
        &format!("\"descriptor_bytes\": {},", accelerator.descriptor_bytes),
    );
    line(
        out,
        indent + 1,
        &format!("\"launch_abi\": {},", json_string(&accelerator.launch_abi)),
    );
    line(
        out,
        indent + 1,
        &format!("\"completion\": {},", json_string(&accelerator.completion)),
    );
    // The completion contract (T9). A runtime cannot write correct code
    // against an engine that outlives its launch without these three answers,
    // and before this they were not in any manifest.
    line(
        out,
        indent + 1,
        &format!(
            "\"visibility\": {}, \"launch_fence\": {}, \"in_flight\": {},",
            json_string(&accelerator.visibility),
            json_string(&accelerator.launch_fence),
            json_string(&accelerator.in_flight)
        ),
    );
    line(
        out,
        indent + 1,
        &format!("\"mmio_base\": {},", accelerator.mmio_base),
    );
    line(
        out,
        indent + 1,
        &format!("\"mmio_size\": {},", accelerator.mmio_size),
    );
    line(
        out,
        indent + 1,
        &format!("\"target\": {},", json_string(&accelerator.target)),
    );
    line(
        out,
        indent + 1,
        &format!("\"coupling\": {},", json_string(&accelerator.coupling)),
    );
    line(
        out,
        indent + 1,
        &format!("\"region_id\": {},", accelerator.region_id),
    );
    line(
        out,
        indent + 1,
        &format!("\"manifest_version\": {},", accelerator.manifest_version),
    );
    line(
        out,
        indent + 1,
        &format!("\"profile\": {},", json_string(&accelerator.profile)),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"backend_kind\": {},",
            json_string(&accelerator.backend_kind)
        ),
    );
    line(
        out,
        indent + 1,
        &format!("\"exec_shape\": {},", json_string(&accelerator.exec_shape)),
    );
    line(
        out,
        indent + 1,
        &format!("\"simd_lanes\": {},", accelerator.simd_lanes),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"element_width_bits\": {},",
            accelerator.element_width_bits
        ),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"fallback_policy\": {},",
            json_string(&accelerator.fallback_policy)
        ),
    );
    // The context surface (M1), emitted only when an engine declares one, so
    // every manifest produced before multi-context existed stays byte-identical.
    // `max_other_grants_before_service` is derived and published rather than
    // left to a consumer: two derivations of one fact is what publishing the
    // modulo occupancy tables already avoids one manifest over.
    if accelerator.contexts > 0 {
        line(out, indent + 1, "\"multicontext\": {");
        line(
            out,
            indent + 2,
            &format!("\"contexts\": {},", accelerator.contexts),
        );
        line(
            out,
            indent + 2,
            &format!("\"context_id_bits\": {},", accelerator.context_id_bits),
        );
        line(
            out,
            indent + 2,
            &format!(
                "\"issue_queue_depth\": {},",
                accelerator.issue_queue_depth
            ),
        );
        line(
            out,
            indent + 2,
            &format!("\"identity\": {},", json_list(&accelerator.identity)),
        );
        line(
            out,
            indent + 2,
            &format!("\"scheduling\": {},", json_string(&accelerator.scheduling)),
        );
        line(
            out,
            indent + 2,
            &format!("\"preemption\": {},", json_string(&accelerator.preemption)),
        );
        line(
            out,
            indent + 2,
            &format!(
                "\"service_interval_cycles\": {},",
                accelerator.service_interval_cycles
            ),
        );
        line(
            out,
            indent + 2,
            &format!(
                "\"eligibility\": {},",
                json_list(&accelerator.eligibility)
            ),
        );
        // The bound the policy delivers, or `null` where it delivers none (M2).
        // Publishing `null` rather than omitting the field is the difference
        // between "this engine has no bound" and "this manifest forgot to say",
        // and a consumer reading a missing key cannot tell those apart.
        match crate::validate::service_bound(accelerator) {
            Some(grants) => {
                line(
                    out,
                    indent + 2,
                    &format!("\"max_other_grants_before_service\": {grants},"),
                );
                // And in cycles, when the engine states its time base. Both are
                // dataclass properties in the consumer's hand-written contract;
                // published, they are one derivation instead of two.
                match accelerator.service_interval_cycles {
                    0 => line(
                        out,
                        indent + 2,
                        "\"deterministic_dependency_cover_cycles\": null",
                    ),
                    interval => line(
                        out,
                        indent + 2,
                        &format!(
                            "\"deterministic_dependency_cover_cycles\": {}",
                            grants * interval
                        ),
                    ),
                }
            }
            None => {
                line(out, indent + 2, "\"max_other_grants_before_service\": null,");
                line(
                    out,
                    indent + 2,
                    "\"deterministic_dependency_cover_cycles\": null",
                );
            }
        }
        line(out, indent + 1, "},");
    }
    emit_accelerator_ports_json(out, &accelerator.ports, indent + 1);
    out.push_str(",\n");
    line(
        out,
        indent + 1,
        &format!("\"semantics\": {},", json_string(&accelerator.semantics)),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"formal_semantics\": {},",
            json_string(&accelerator.formal_semantics)
        ),
    );
    line(
        out,
        indent + 1,
        &format!("\"latency_cycles\": {},", accelerator.latency_cycles),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"throughput_per_cycle\": {},",
            accelerator.throughput_per_cycle
        ),
    );
    line(
        out,
        indent + 1,
        &format!("\"resources\": {}", json_list(&accelerator.resources)),
    );
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

pub(crate) fn emit_accelerator_ports_json(
    out: &mut String,
    ports: &[AcceleratorPort],
    indent: usize,
) {
    line(out, indent, "\"ports\": [");
    for (idx, port) in ports.iter().enumerate() {
        line(out, indent + 1, "{");
        line(
            out,
            indent + 2,
            &format!("\"name\": {},", json_string(&port.name)),
        );
        line(
            out,
            indent + 2,
            &format!("\"direction\": {},", json_string(&port.direction)),
        );
        line(
            out,
            indent + 2,
            &format!("\"kind\": {},", json_string(&port.kind)),
        );
        line(out, indent + 2, &format!("\"width\": {}", port.width));
        let suffix = if idx + 1 == ports.len() { "" } else { "," };
        line(out, indent + 1, &format!("}}{suffix}"));
    }
    write_indent(out, indent);
    out.push(']');
}

pub(crate) fn emit_memory_json_object(
    out: &mut String,
    memory: &Memory,
    indent: usize,
    last: bool,
) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"name\": {},", json_string(&memory.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"kind\": {},", json_string(&memory.kind)),
    );
    line(
        out,
        indent + 1,
        &format!("\"size_bytes\": {},", memory.size_bytes),
    );
    line(out, indent + 1, &format!("\"ports\": {},", memory.ports));
    line(
        out,
        indent + 1,
        &format!("\"latency_cycles\": {},", memory.latency_cycles),
    );
    line(
        out,
        indent + 1,
        &format!("\"line_bytes\": {},", memory.line_bytes),
    );
    line(
        out,
        indent + 1,
        &format!("\"ways\": {},", memory.ways),
    );
    line(
        out,
        indent + 1,
        &format!("\"blocking\": {},", memory.policy.blocking),
    );
    line(
        out,
        indent + 1,
        &format!("\"width_bits\": {},", memory.width_bits),
    );
    line(out, indent + 1, &format!("\"banks\": {},", memory.banks));
    line(
        out,
        indent + 1,
        &format!("\"attributes\": {}", json_list(&memory.attributes)),
    );
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

pub(crate) fn emit_tile_json_object(out: &mut String, tile: &Tile, indent: usize, last: bool) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"name\": {},", json_string(&tile.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"cores\": {},", json_list(&tile.cores)),
    );
    line(
        out,
        indent + 1,
        &format!("\"accelerators\": {},", json_list(&tile.accelerators)),
    );
    line(
        out,
        indent + 1,
        &format!("\"memories\": {},", json_list(&tile.memories)),
    );
    line(
        out,
        indent + 1,
        &format!("\"interconnect\": {}", json_string(&tile.interconnect)),
    );
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

pub(crate) fn canonical_value(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace('-', "_")
}

pub(crate) fn json_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\u{:04x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub(crate) fn c_string(value: &str) -> String {
    let mut out = String::from("\"");
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => out.push_str(&format!("\\x{:02x}", ch as u32)),
            ch => out.push(ch),
        }
    }
    out.push('"');
    out
}

pub(crate) fn json_list(values: &[String]) -> String {
    let items: Vec<String> = values.iter().map(|value| json_string(value)).collect();
    format!("[{}]", items.join(", "))
}

pub(crate) fn json_hex_u32(value: u32) -> String {
    json_string(&format!("0x{value:08x}"))
}

pub(crate) fn json_operand_name_list(operands: &[Operand]) -> String {
    let items: Vec<String> = operands
        .iter()
        .map(|operand| {
            format!(
                "{{\"name\": {}, \"kind\": {}, \"width\": {}, \"output\": {}}}",
                json_string(&operand.name),
                json_string(&operand.kind),
                operand.width,
                json_bool(operand.output)
            )
        })
        .collect();
    format!("[{}]", items.join(", "))
}

pub(crate) fn json_accelerator_port_name_list(ports: &[AcceleratorPort]) -> String {
    let items: Vec<String> = ports
        .iter()
        .map(|port| {
            format!(
                "{{\"name\": {}, \"direction\": {}, \"kind\": {}, \"width\": {}}}",
                json_string(&port.name),
                json_string(&port.direction),
                json_string(&port.kind),
                port.width
            )
        })
        .collect();
    format!("[{}]", items.join(", "))
}

pub(crate) fn json_bool(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

pub(crate) fn aha_operand_type(kind: &str) -> String {
    match kind {
        "reg" | "register" => "register",
        "vreg" | "vector_register" | "vec" => "vector_register",
        "imm" | "immediate" => "immediate",
        "mem" | "memory" => "memory",
        "pred" | "predicate" => "predicate",
        other => other,
    }
    .to_string()
}

pub(crate) fn tablegen_ident(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "PCE".to_string()
    } else {
        out
    }
}

pub(crate) fn python_ident(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push('_');
        }
    }
    if out.is_empty() || out.as_bytes()[0].is_ascii_digit() {
        out.insert(0, '_');
    }
    out
}

pub(crate) fn instruction_asm(instruction: &Instruction) -> String {
    if !instruction.asm.trim().is_empty() {
        return instruction.asm.clone();
    }
    // Destination first, then the sources -- the order every explicit template
    // in the corpora writes, and the order an assembler parses. This used to
    // take `input` operands only, so an instruction that did not spell its own
    // assembly published `andn $rs1, $rs2`: the text named what it read and
    // never named what it wrote. An `inout` operand is both, and is written
    // once, on the destination side where it is first mentioned.
    let mut args: Vec<String> = instruction
        .operands
        .iter()
        .filter(|operand| operand.output)
        .map(|operand| format!("${}", operand.name))
        .collect();
    args.extend(
        instruction
            .operands
            .iter()
            .filter(|operand| operand.input && !operand.output)
            .map(|operand| format!("${}", operand.name)),
    );
    if args.is_empty() {
        instruction.mnemonic.to_ascii_lowercase()
    } else {
        format!(
            "{} {}",
            instruction.mnemonic.to_ascii_lowercase(),
            args.join(", ")
        )
    }
}

pub(crate) fn asm_operand_placeholders(instruction: &Instruction) -> Vec<String> {
    let asm = instruction_asm(instruction);
    let mut placeholders = Vec::new();
    let mut chars = asm.char_indices().peekable();
    while let Some((_, ch)) = chars.next() {
        if ch != '$' {
            continue;
        }
        let mut name = String::new();
        while let Some((_, next)) = chars.peek().copied() {
            if next.is_ascii_alphanumeric() || next == '_' {
                name.push(next);
                chars.next();
            } else {
                break;
            }
        }
        if !name.is_empty() && !placeholders.iter().any(|existing| existing == &name) {
            placeholders.push(name);
        }
    }
    if placeholders.is_empty() {
        instruction
            .operands
            .iter()
            .map(|operand| operand.name.clone())
            .collect()
    } else {
        placeholders
    }
}

pub(crate) fn tablegen_opcode_string(instruction: &Instruction) -> String {
    instruction_asm(instruction)
        .split_whitespace()
        .next()
        .unwrap_or(&instruction.mnemonic)
        .trim_matches('"')
        .to_string()
}

pub(crate) fn line(out: &mut String, indent: usize, text: &str) {
    write_indent(out, indent);
    out.push_str(text);
    out.push('\n');
}

pub(crate) fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push_str("  ");
    }
}

/// The microarchitecture interchange format: a MACHINE, standing alone.
///
/// ⚠️ Separate from `emit-json` on purpose. That artifact is the whole
/// document -- every instruction, every encoding -- and a vendor who wants to
/// describe a machine should not have to ship an instruction set to do it.
/// This carries the machine and names the ISA it expects, so an open
/// description and a closed machine can travel separately and still meet.
///
/// ⚠️ Three things here are NOT AXIS's business and are carried anyway:
///
/// * `model` names the implementation meant to time this core. Empty is AXIS's
///   own pipeline. A name is a requirement -- a host without that model must
///   refuse rather than quietly use the built-in one, because falling back
///   produces a plausible number for a machine nobody asked about.
/// * `vendor` holds parameters AXIS has never heard of. A microarchitecture is
///   mostly policy and policy is not declarable; what AXIS can honestly do is
///   transport the settings intact and refuse to pretend it read them.
/// * `provenance` says what KIND of number this machine's figures are --
///   typed by a designer, measured against hardware, or produced by another
///   model. A closed model's cycle count and a count checked against silicon
///   are different claims, and a stack that renders them identically is
///   inviting the reader to confuse them.
pub fn emit_uarch_json(document: &Document) -> String {
    let mut out = String::new();
    line(&mut out, 0, "{");
    line(&mut out, 1, "\"schema\": \"axis.uarch.v1\",");
    line(
        &mut out,
        1,
        &format!("\"module\": {},", json_string(&document.extension.name)),
    );
    line(&mut out, 1, "\"cores\": [");
    for (idx, core) in document.cores.iter().enumerate() {
        emit_core_json_object(&mut out, core, 2, idx + 1 == document.cores.len());
    }
    line(&mut out, 1, "],");
    // What each core says about time, RESOLVED: every instruction whose unit
    // or latency on that core is not its own, with what it is there. The
    // order of precedence is `Core::latency_of`'s and is not restated by a
    // reader. Absent when no core says anything, so a description that
    // predates the clause publishes what it always did.
    let timed: Vec<&Core> = document.cores.iter().filter(|core| core.timing.is_some()).collect();
    if !timed.is_empty() {
        line(&mut out, 1, "\"timing\": [");
        for (idx, core) in timed.iter().enumerate() {
            let retimed: Vec<String> = core
                .retimed(&document.instructions)
                .iter()
                .map(|(mnemonic, unit, latency)| {
                    format!(
                        "{{\"mnemonic\": {}, \"unit\": {}, \"latency\": {latency}}}",
                        json_string(mnemonic),
                        json_string(unit)
                    )
                })
                .collect();
            // And what it cracks, DERIVED: each micro-op with what it reads,
            // writes and loads, as `Core::micro_ops_of` divided the
            // instruction's effects. Said only by a core that cracks.
            let names = |list: &[String]| list.iter().map(|n| json_string(n)).collect::<Vec<_>>().join(", ");
            let numbers = |list: &[usize]| list.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ");
            let cracked: Vec<String> = core
                .cracked(&document.instructions)
                .iter()
                .map(|(mnemonic, ops)| {
                    let ops: Vec<String> = ops
                        .iter()
                        .map(|op| {
                            format!(
                                "{{\"unit\": {}, \"latency\": {}, \"accesses\": [{}], \"rest\": {}, \"reads\": [{}], \"writes\": [{}], \"implicit\": {}, \"after\": [{}]}}",
                                json_string(&op.unit),
                                op.latency,
                                numbers(&op.accesses),
                                op.rest,
                                names(&op.reads),
                                names(&op.writes),
                                op.implicit,
                                numbers(&op.after)
                            )
                        })
                        .collect();
                    format!("{{\"mnemonic\": {}, \"micro_ops\": [{}]}}", json_string(mnemonic), ops.join(", "))
                })
                .collect();
            let cracked = if cracked.is_empty() {
                String::new()
            } else {
                format!(", \"cracked\": [{}]", cracked.join(", "))
            };
            // And the pairs its decoder fuses (FU1), as declared.
            let fused = core.timing.as_ref().map_or(String::new(), |timing| {
                if timing.fuse.is_empty() {
                    return String::new();
                }
                let pairs: Vec<String> = timing
                    .fuse
                    .iter()
                    .map(|(head, tail)| format!("[{}, {}]", json_string(head), json_string(tail)))
                    .collect();
                format!(", \"fuse\": [{}]", pairs.join(", "))
            });
            line(
                &mut out,
                2,
                &format!(
                    "{{\"core\": {}, \"retimed\": [{}]{cracked}{fused}}}{}",
                    json_string(&core.name),
                    retimed.join(", "),
                    if idx + 1 == timed.len() { "" } else { "," }
                ),
            );
        }
        line(&mut out, 1, "],");
    }
    line(&mut out, 1, "\"memories\": [");
    for (idx, memory) in document.memories.iter().enumerate() {
        emit_memory_json_object(&mut out, memory, 2, idx + 1 == document.memories.len());
    }
    line(&mut out, 1, "]");
    line(&mut out, 0, "}");
    out
}
