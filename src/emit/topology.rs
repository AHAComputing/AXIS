//! AXIS emit: topology domain (split from the former monolithic emit.rs).

use super::common::*;

/// Emit a core object with its composed personalities (name, mode, discipline)
/// — the P3 view the PCE-side field allocator reads disciplines from.
fn emit_topology_core_with_personalities(
    out: &mut String,
    document: &Document,
    core: &Core,
    indent: usize,
    last: bool,
) {
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
    line(out, indent + 1, "\"personalities\": [");
    let count = core.personalities.len();
    for (idx, name) in core.personalities.iter().enumerate() {
        let comma = if idx + 1 == count { "" } else { "," };
        match document
            .personalities
            .iter()
            .find(|declared| declared.name.eq_ignore_ascii_case(name))
        {
            Some(personality) => {
                let params = personality
                    .discipline
                    .params
                    .iter()
                    .map(|(key, value)| format!("{}: {value}", json_string(key)))
                    .collect::<Vec<_>>()
                    .join(", ");
                line(
                    out,
                    indent + 2,
                    &format!(
                        "{{\"name\": {}, \"mode\": {}, \"implements\": {}, \"discipline\": {{\"kind\": {}, \"params\": {{{params}}}}}}}{comma}",
                        json_string(&personality.name),
                        json_string(&personality.mode),
                        json_string(&personality.implements),
                        json_string(&personality.discipline.kind)
                    ),
                );
            }
            None => line(
                out,
                indent + 2,
                &format!("{{\"name\": {}}}{comma}", json_string(name)),
            ),
        }
    }
    line(out, indent + 1, "]");
    line(out, indent, &format!("}}{}", if last { "" } else { "," }));
}

pub fn emit_adl_topology_manifest_json(document: &Document) -> String {
    let selected_tile = document.tiles.first();
    let source_interconnect = selected_tile
        .map(|tile| tile.interconnect.as_str())
        .unwrap_or("");
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"pce-adl.topology.v1\",");
    line(&mut out, 1, "\"cores\": [");
    for (idx, core) in document.cores.iter().enumerate() {
        let last = idx + 1 == document.cores.len();
        // A core that composes personalities (P3) carries them here; a plain
        // single-ISA core emits exactly as before (byte-identical).
        if core.personalities.is_empty() {
            emit_core_json_object(&mut out, core, 2, last);
        } else {
            emit_topology_core_with_personalities(&mut out, document, core, 2, last);
        }
    }
    line(&mut out, 1, "],");
    line(&mut out, 1, "\"accelerators\": [");
    for (idx, accelerator) in document.accelerators.iter().enumerate() {
        emit_accelerator_json_object(
            &mut out,
            accelerator,
            2,
            idx + 1 == document.accelerators.len(),
        );
    }
    line(&mut out, 1, "],");
    line(&mut out, 1, "\"memories\": [");
    for (idx, memory) in document.memories.iter().enumerate() {
        emit_memory_json_object(&mut out, memory, 2, idx + 1 == document.memories.len());
    }
    line(&mut out, 1, "],");
    line(&mut out, 1, "\"tiles\": [");
    for (idx, tile) in document.tiles.iter().enumerate() {
        emit_tile_json_object(&mut out, tile, 2, idx + 1 == document.tiles.len());
    }
    line(&mut out, 1, "],");
    line(&mut out, 1, "\"selected_tile\": ");
    if let Some(tile) = selected_tile {
        emit_tile_json_object(&mut out, tile, 1, true);
        out.push_str(",\n");
    } else {
        line(&mut out, 1, "{},");
    }
    line(
        &mut out,
        1,
        &format!(
            "\"source_interconnect\": {},",
            json_string(source_interconnect)
        ),
    );
    line(
        &mut out,
        1,
        &format!(
            "\"synthesis_noc_topology\": {}",
            json_string(synthesis_noc_topology(source_interconnect))
        ),
    );
    out.push_str("}\n");
    out
}

pub fn emit_accelerator_descriptor_manifests_json(document: &Document) -> String {
    let descriptors: Vec<&Accelerator> = document
        .accelerators
        .iter()
        .filter(|accelerator| accelerator_has_descriptor_metadata(accelerator))
        .collect();
    let mut out = String::new();
    out.push_str("[\n");
    for (idx, accelerator) in descriptors.iter().enumerate() {
        emit_accelerator_descriptor_json_object(
            &mut out,
            accelerator,
            1,
            idx + 1 == descriptors.len(),
        );
    }
    out.push_str("]\n");
    out
}

pub fn emit_adl_coupling_manifest_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"pce-adl.coupling.v1\",");
    line(&mut out, 1, "\"couplings\": [");
    let couplings = adl_coupling_entries(document);
    for (idx, coupling) in couplings.iter().enumerate() {
        emit_adl_coupling_json_object(&mut out, coupling, 2, idx + 1 == couplings.len());
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

pub fn emit_rvmt_launch_templates_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("[\n");
    let templates: Vec<&Accelerator> = document
        .accelerators
        .iter()
        .filter(|accelerator| accelerator_has_descriptor_metadata(accelerator))
        .collect();
    for (idx, accelerator) in templates.iter().enumerate() {
        emit_rvmt_launch_template_json_object(&mut out, accelerator, 1, idx + 1 == templates.len());
    }
    out.push_str("]\n");
    out
}

pub fn emit_rvmt_rcore_region_manifest_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(
        &mut out,
        1,
        "\"schema\": \"pce-adl.rvmt-rcore-regions.v1\",",
    );
    line(&mut out, 1, "\"regions\": [");
    let regions: Vec<&Accelerator> = document
        .accelerators
        .iter()
        .filter(|accelerator| accelerator_is_rcore_family(accelerator))
        .collect();
    for (idx, accelerator) in regions.iter().enumerate() {
        emit_rvmt_rcore_region_json_object(&mut out, accelerator, 2, idx + 1 == regions.len());
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

pub fn emit_aha_json(document: &Document) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    line(&mut out, 1, "\"schema\": \"pce-adl.aha-instructions.v1\",");
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
    line(
        &mut out,
        1,
        &format!(
            "\"description\": {},",
            json_string(&document.extension.description)
        ),
    );
    line(&mut out, 1, "\"instructions\": [");
    // One entry per ENCODING: see `architectural_instructions`.
    let entries = architectural_instructions(document);
    let modelled = crate::hw::modelled_costs(document);
    for (idx, instruction) in entries.iter().enumerate() {
        emit_aha_instruction_json(
            &mut out,
            document,
            instruction,
            modelled.get(&instruction.mnemonic).copied(),
            idx + 1 == entries.len(),
        );
    }
    line(&mut out, 1, "]");
    out.push_str("}\n");
    out
}

fn emit_aha_encoding_fields_json(out: &mut String, document: &Document, instruction: &Instruction) {
    let layout = layout_for(document, instruction);
    let mut fields: Vec<(u32, String)> = Vec::new();
    for fixed in &layout.fixed_fields {
        fields.push((
            fixed.insn_lo,
            format!(
                "{{\"name\": {}, \"start_bit\": {}, \"width_bits\": {}, \"value\": {}}}",
                json_string(&fixed.name),
                fixed.insn_lo,
                fixed.width,
                fixed.value
            ),
        ));
    }
    for operand in &layout.operand_fields {
        fields.push((
            operand.insn_lo,
            format!(
                "{{\"name\": {}, \"start_bit\": {}, \"width_bits\": {}, \"operand_lo\": {}}}",
                json_string(&operand.operand),
                operand.insn_lo,
                operand.width,
                operand.op_lo
            ),
        ));
    }
    // Ascending by position, so the list reads as the word does.
    fields.sort_by_key(|(insn_lo, _)| *insn_lo);
    if fields.is_empty() {
        line(out, 4, "\"fields\": []");
        return;
    }
    line(out, 4, "\"fields\": [");
    for (index, (_, text)) in fields.iter().enumerate() {
        let comma = if index + 1 == fields.len() { "" } else { "," };
        line(out, 5, &format!("{text}{comma}"));
    }
    line(out, 4, "]");
}

fn emit_aha_instruction_json(
    out: &mut String,
    document: &Document,
    instruction: &Instruction,
    modelled: Option<(f64, f64)>,
    is_last: bool,
) {
    line(out, 2, "{");
    line(
        out,
        3,
        &format!("\"mnemonic\": {},", json_string(&instruction.mnemonic)),
    );
    line(
        out,
        3,
        &format!(
            "\"description\": {},",
            json_string(&instruction.description)
        ),
    );
    line(
        out,
        3,
        &format!("\"category\": {},", json_string(&instruction.category)),
    );
    emit_aha_operands_json(out, &instruction.operands, 3);
    out.push_str(",\n");
    line(out, 3, "\"encoding\": {");
    line(out, 4, "\"total_bits\": 32,");
    line(
        out,
        4,
        &format!("\"format\": {},", json_string(&instruction.format)),
    );
    line(out, 4, &format!("\"opcode\": {},", instruction.opcode));
    line(out, 4, &format!("\"func3\": {},", instruction.func3));
    line(out, 4, &format!("\"func7\": {},", instruction.func7));
    // Where every bit of the word comes from, which the opcode/func3/func7
    // triple does not say. The consumer's `BitEncoding` has carried a `fields`
    // list since before this manifest existed and its loader fills it with
    // `[]`, so `hardware/grv/grv_conformance/isa_surface.py` reads the
    // manifest for the opcode space and then places operands by "the harness's
    // RISC-V R-type convention" -- a second answer to a question this
    // description already answers, and one that cannot disagree loudly.
    //
    // The same layout resolution the decoder, the encoder and the lift table
    // use, so there is one placement rather than a fourth. A fixed field
    // carries its `value`; an operand field carries `operand_lo`, the bit of
    // the operand this slice starts at, because a scattered immediate is
    // several slices of one operand and dropping that would make the list
    // unable to say which is which.
    emit_aha_encoding_fields_json(out, document, instruction);
    line(out, 3, "},");
    line(
        out,
        3,
        &format!("\"semantics\": {},", json_string(&instruction.semantics)),
    );
    // OptiSynth (PCE ADL.2) reads this field with its own grammar to derive
    // Z3-provable rewrite rules, so emit the normalized OptiSynth dialect
    // when the semantics are expressible in it. Inexpressible semantics keep
    // the raw AXIS text — PCE's parser skips those soundly (no rule, no
    // risk). The raw AXIS form always lives in manifest.json.
    let optisynth = optisynth_formal_semantics(instruction);
    line(
        out,
        3,
        &format!(
            "\"formal_semantics\": {},",
            json_string(
                optisynth
                    .as_deref()
                    .unwrap_or(&instruction.formal_semantics)
            )
        ),
    );
    line(
        out,
        3,
        &format!(
            "\"optisynth_compatible\": {},",
            json_bool(optisynth.is_some())
        ),
    );
    line(
        out,
        3,
        &format!("\"latency_cycles\": {},", instruction.latency_cycles),
    );
    line(
        out,
        3,
        &format!(
            "\"throughput_per_cycle\": {},",
            instruction.throughput_per_cycle
        ),
    );
    line(
        out,
        3,
        &format!("\"area_estimate_um2\": {},", instruction.area_estimate_um2),
    );
    line(
        out,
        3,
        &format!("\"power_estimate_mw\": {},", instruction.power_estimate_mw),
    );
    line(
        out,
        3,
        &format!("\"expected_speedup\": {},", instruction.expected_speedup),
    );
    // ⚠️ The three above are DECLARED, by whoever wrote the description, and
    // nothing checks them -- most corpora carry the same placeholder on every
    // instruction. This is the instruction's own netlist under AXIS's cost
    // model, calibrated against synthesis (docs/hardware_design.md §5), in the
    // same unit; null where there is no netlist. Published beside the
    // declared number, not instead of it: PCE reads `area_estimate_um2` and
    // chooses when to read this.
    line(
        out,
        3,
        &format!(
            "\"area_model_um2\": {},",
            modelled.map_or("null".to_string(), |(area, _)| format!("{:.1}", area * crate::hw::NAND2_UM2))
        ),
    );
    line(
        out,
        3,
        &format!(
            "\"applicable_patterns\": {},",
            json_list(&instruction.applicable_patterns)
        ),
    );
    line(
        out,
        3,
        &format!("\"rationale\": {}", json_string(&instruction.rationale)),
    );
    let suffix = if is_last { "" } else { "," };
    line(out, 2, &format!("}}{suffix}"));
}

fn emit_aha_operands_json(out: &mut String, operands: &[Operand], indent: usize) {
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
            &format!(
                "\"type\": {},",
                json_string(&aha_operand_type(&operand.kind))
            ),
        );
        line(
            out,
            indent + 2,
            &format!("\"width_bits\": {},", operand.width),
        );
        line(
            out,
            indent + 2,
            &format!("\"is_output\": {},", operand.output),
        );
        line(out, indent + 2, "\"is_optional\": false,");
        line(out, indent + 2, "\"description\": \"\"");
        let suffix = if idx + 1 == operands.len() { "" } else { "," };
        line(out, indent + 1, &format!("}}{suffix}"));
    }
    write_indent(out, indent);
    out.push(']');
}

fn emit_rvmt_rcore_region_json_object(
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
        &format!("\"target\": {},", json_string(&accelerator.target)),
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
            "\"fallback_policy\": {}",
            json_string(&accelerator.fallback_policy)
        ),
    );
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

struct AdlCouplingEntry<'a> {
    tile: &'a Tile,
    source_core: String,
    accelerator: &'a Accelerator,
    tier: &'static str,
    active: bool,
}

fn adl_coupling_entries(document: &Document) -> Vec<AdlCouplingEntry<'_>> {
    let mut entries = Vec::new();
    for tile in &document.tiles {
        let source_core = tile.cores.first().cloned().unwrap_or_default();
        for accelerator_ref in &tile.accelerators {
            let Some(accelerator) = document
                .accelerators
                .iter()
                .find(|candidate| candidate.name == *accelerator_ref)
            else {
                continue;
            };
            let tier = adl_coupling_tier(&accelerator.coupling);
            if tier.is_empty() {
                continue;
            }
            entries.push(AdlCouplingEntry {
                tile,
                source_core: source_core.clone(),
                accelerator,
                tier,
                active: is_known_aha_accelerator(accelerator),
            });
        }
    }
    entries
}

fn emit_adl_coupling_json_object(
    out: &mut String,
    entry: &AdlCouplingEntry<'_>,
    indent: usize,
    last: bool,
) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"source_tile\": {},", json_string(&entry.tile.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"source_core\": {},", json_string(&entry.source_core)),
    );
    line(
        out,
        indent + 1,
        &format!("\"core_refs\": {},", json_list(&entry.tile.cores)),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"accelerator_ref\": {},",
            json_string(&entry.accelerator.name)
        ),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"source_coupling\": {},",
            json_string(&entry.accelerator.coupling)
        ),
    );
    line(
        out,
        indent + 1,
        &format!("\"tier\": {},", json_string(entry.tier)),
    );
    line(
        out,
        indent + 1,
        &format!("\"active\": {},", json_bool(entry.active)),
    );
    line(
        out,
        indent + 1,
        &format!("\"metadata_only\": {},", json_bool(!entry.active)),
    );
    line(out, indent + 1, "\"descriptor\": ");
    if accelerator_has_descriptor_metadata(entry.accelerator) {
        emit_accelerator_descriptor_json_object(out, entry.accelerator, indent + 1, true);
        out.push_str(",\n");
    } else {
        line(out, indent + 1, "{},");
    }
    line(out, indent + 1, "\"coupling\": ");
    if entry.active {
        emit_aha_coupling_json_object(out, entry.accelerator, entry.tier, indent + 1, true);
    } else {
        line(out, indent + 1, "{}");
    }
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

fn emit_accelerator_descriptor_json_object(
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
    // What the schema name stood for, when the document declares it: each
    // field's offset and width, the checks with their status codes, and where
    // the status goes. Written only for a linked accelerator, so every bundle
    // without a `defdescriptor` is the one it was.
    if let Some(descriptor) = &accelerator.descriptor {
        let fields: Vec<String> = descriptor
            .fields
            .iter()
            .map(|field| {
                format!(
                    "{{\"name\": {}, \"offset\": {}, \"width\": {}, \"signed\": {}}}",
                    json_string(&field.name),
                    field.offset,
                    field.width,
                    json_bool(field.signed)
                )
            })
            .collect();
        let checks: Vec<String> = descriptor
            .checks
            .iter()
            .map(|check| {
                format!(
                    "{{\"condition\": {}, \"status\": {}}}",
                    json_string(&check.condition),
                    check.status
                )
            })
            .collect();
        line(out, indent + 1, &format!("\"descriptor_layout\": [{}],", fields.join(", ")));
        line(out, indent + 1, &format!("\"descriptor_checks\": [{}],", checks.join(", ")));
        line(
            out,
            indent + 1,
            &format!(
                "\"descriptor_status\": {{\"field\": {}, \"returned\": {}, \"width\": {}, \"success\": 0}},",
                if descriptor.status_field.is_empty() {
                    "null".to_string()
                } else {
                    json_string(&descriptor.status_field)
                },
                json_bool(descriptor.status_field.is_empty()),
                descriptor.status_width
            ),
        );
    }
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
    line(
        out,
        indent + 1,
        &format!("\"mmio_base\": {},", accelerator.mmio_base),
    );
    line(
        out,
        indent + 1,
        &format!("\"mmio_size\": {}", accelerator.mmio_size),
    );
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

fn emit_aha_coupling_json_object(
    out: &mut String,
    accelerator: &Accelerator,
    tier: &str,
    indent: usize,
    last: bool,
) {
    line(out, indent, "{");
    line(
        out,
        indent + 1,
        &format!("\"accel_ref\": {},", json_string(&accelerator.name)),
    );
    line(
        out,
        indent + 1,
        &format!("\"tier\": {},", json_string(tier)),
    );
    match tier {
        "tight" => {
            line(out, indent + 1, "\"opcode\": 43");
        }
        "loose" => {
            line(
                out,
                indent + 1,
                &format!(
                    "\"mmio_base\": {},",
                    if accelerator.mmio_base == 0 {
                        0x8000_0000
                    } else {
                        accelerator.mmio_base
                    }
                ),
            );
            line(
                out,
                indent + 1,
                &format!(
                    "\"mmio_size\": {}",
                    if accelerator.mmio_size == 0 {
                        0x1000
                    } else {
                        accelerator.mmio_size
                    }
                ),
            );
        }
        "stream" => {
            line(
                out,
                indent + 1,
                &format!(
                    "\"ingress_port\": {},",
                    json_string(&format!("{}_in", accelerator.name))
                ),
            );
            line(
                out,
                indent + 1,
                &format!(
                    "\"egress_port\": {}",
                    json_string(&format!("{}_out", accelerator.name))
                ),
            );
        }
        _ => {}
    }
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

fn emit_rvmt_launch_template_json_object(
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
        &format!("\"target\": {},", json_string(&accelerator.target)),
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
    line(
        out,
        indent + 1,
        &format!(
            "\"coupling_tier\": {},",
            json_string(adl_coupling_tier(&accelerator.coupling))
        ),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"submit_user_word_abi\": {},",
            json_string(&rvmt_submit_user_word_abi(accelerator))
        ),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"runtime_descriptor_fields\": {},",
            json_list(&rvmt_launch_template_fields(accelerator))
        ),
    );
    line(
        out,
        indent + 1,
        &format!(
            "\"runtime_user_fields\": {}",
            json_list(&rvmt_submit_user_word_fields(accelerator))
        ),
    );
    let suffix = if last { "" } else { "," };
    line(out, indent, &format!("}}{suffix}"));
}

fn accelerator_has_descriptor_metadata(accelerator: &Accelerator) -> bool {
    accelerator.descriptor_bytes != 0
        || !accelerator.descriptor_schema.is_empty()
        || !accelerator.launch_abi.is_empty()
        || !accelerator.completion.is_empty()
        || accelerator.mmio_base != 0
        || accelerator.mmio_size != 0
}

fn accelerator_is_rcore_family(accelerator: &Accelerator) -> bool {
    matches!(
        canonical_value(if accelerator.target.is_empty() {
            &accelerator.family
        } else {
            &accelerator.target
        })
        .as_str(),
        "rcore" | "ccore"
    )
}

fn adl_coupling_tier(source_coupling: &str) -> &'static str {
    match canonical_value(source_coupling).as_str() {
        "tightly_coupled" => "tight",
        "queue_descriptor" | "loose" => "loose",
        "stream" => "stream",
        _ => "",
    }
}

fn synthesis_noc_topology(source_interconnect: &str) -> &'static str {
    match canonical_value(source_interconnect).as_str() {
        "noc" => "mesh",
        "crossbar" | "mailbox" => "crossbar",
        _ => "crossbar",
    }
}

fn rvmt_launch_template_fields(accelerator: &Accelerator) -> Vec<String> {
    match canonical_value(&accelerator.descriptor_schema).as_str() {
        "rvmt_nearasic_v1" => [
            "opcode_subtype",
            "cfg_id",
            "context_id",
            "warp_id",
            "thread_mask",
            "src0_ptr",
            "src1_ptr",
            "dst_ptr",
            "src0_bytes",
            "src1_bytes",
            "dst_bytes",
            "scratchpad_flags",
            "completion_tag",
            "status_addr",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect(),
        "rvmt_nearasic_v2" => [
            "opcode_subtype",
            "cfg_id",
            "context_id",
            "warp_id",
            "thread_mask",
            "src0_ptr",
            "src1_ptr",
            "dst_ptr",
            "src0_bytes",
            "src1_bytes",
            "dst_bytes",
            "scratchpad_flags",
            "completion_tag",
            "status_addr",
            "fabric_select",
            "exec_shape",
            "simd_lanes",
            "element_width_bits",
            "thread_id",
            "region_id",
            "entry_pc",
            "livein_ptr",
            "liveout_ptr",
            "payload_ptr",
            "flags",
            "data_abi_v1",
            "mailbox_completion_v1",
            "force_fallback",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect(),
        "rvmt_rcore_v1" | "rvmt_ccore_v1" => [
            "region_id",
            "manifest_version",
            "thread_id",
            "livein_ptr",
            "liveout_ptr",
            "fallback_pc",
            "resume_pc",
            "flags",
            "payload_ptr",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect(),
        _ => Vec::new(),
    }
}

fn rvmt_submit_user_word_abi(accelerator: &Accelerator) -> String {
    let target = if accelerator.target.is_empty() {
        &accelerator.family
    } else {
        &accelerator.target
    };
    if !accelerator_has_descriptor_metadata(accelerator) {
        return String::new();
    }
    match canonical_value(target).as_str() {
        "nearasic" => "nearasic_launch_v1".to_string(),
        "rcore" => "rcore_launch_v1".to_string(),
        "ccore" => "ccore_launch_v1".to_string(),
        _ => String::new(),
    }
}

fn rvmt_submit_user_word_fields(accelerator: &Accelerator) -> Vec<String> {
    match rvmt_submit_user_word_abi(accelerator).as_str() {
        "nearasic_launch_v1" => [
            "fabric_select",
            "op_mode",
            "signed",
            "clear",
            "bypass",
            "general_shift",
            "general_clamp",
            "select_segment",
            "select_segment_len",
            "select_segment_id",
            "quant_scale",
            "quant_zero_point",
            "quant_shift",
            "quant_round",
            "quant_clamp",
            "fusion_stage0",
            "fusion_stage1",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect(),
        "rcore_launch_v1" | "ccore_launch_v1" => [
            "region_id",
            "manifest_version",
            "thread_id",
            "patch_set",
            "fallback_pc",
            "resume_pc",
        ]
        .iter()
        .map(|value| value.to_string())
        .collect(),
        _ => Vec::new(),
    }
}

fn is_known_aha_accelerator(accelerator: &Accelerator) -> bool {
    matches!(
        canonical_value(if accelerator.target.is_empty() {
            &accelerator.family
        } else {
            &accelerator.target
        })
        .as_str(),
        "rvmt"
            | "simt"
            | "xnn"
            | "cpe"
            | "efpga"
            | "vliw_simd"
            | "imc"
            | "dae"
            | "ste"
            | "spc"
            | "structured_asic"
            | "spatial_dataflow"
            | "systolic_array"
            | "event_dispatch"
            | "remote_store_manycore"
            | "rcore"
            | "ccore"
    )
}
