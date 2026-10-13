//! Canonical Lisp source serialization.
//!
//! This is deliberately a serializer for the validated typed document, not a
//! source-preserving formatter. Legacy infix effects are emitted as structured
//! `(behavior ...)` forms from `Instruction.behavior`, and decode predicates
//! are emitted from `Instruction.decode_constraint`.

use std::fmt::Write;

use crate::decode_constraint::{ConstraintValue, DecodeConstraint};
use crate::effects::{render_semexpr, Behavior, Effect, Loc};
use crate::{
    Accelerator, Core, Document, Format, Instruction, Isa, Lowering, LoweringPredicate,
    LoweringStep, LoweringValue, Memory, Mode, Personality, Tile,
};

/// Serialize a validated AXIS document as canonical Lisp-authored AXIS.
/// Render a document as canonical `.axisl`.
///
/// **Which document is the caller's choice, and it matters.** The CLI passes
/// the *frontend* document -- `parse_frontend_document`, before the semantic
/// expansions -- because `emit-lisp` writes a form a corpus could be replaced
/// by, and a replacement has to be a source somebody could keep. Passing a
/// fully elaborated document renders what elaboration produced instead, which
/// is a different and occasionally useful thing: for a scalable corpus it is
/// one instruction per lane, 2797 of them for `sve.axisl`, in a form the
/// surface cannot re-read.
///
/// This function has no way to tell which it was given and does not try. It
/// renders what it holds.
pub fn emit_lisp(document: &Document) -> String {
    let mut out = String::new();
    writeln!(&mut out, "(axis-module {}", document.extension.name).unwrap();
    property_string(&mut out, 1, "version", &document.extension.version);
    property_atom(&mut out, 1, "target", &document.extension.target);
    if !document.extension.description.is_empty() {
        property_string(&mut out, 1, "description", &document.extension.description);
    }

    for isa in &document.isas {
        out.push('\n');
        emit_isa(&mut out, isa);
    }
    for mode in &document.modes {
        out.push('\n');
        emit_mode(&mut out, mode);
    }
    for config in &document.configs {
        out.push('\n');
        emit_config(&mut out, config);
    }
    for kernel in &document.kernels {
        out.push('\n');
        emit_kernel(&mut out, kernel);
    }
    for descriptor in &document.descriptors {
        out.push('\n');
        emit_descriptor(&mut out, descriptor);
    }
    for device in &document.devices {
        out.push('\n');
        emit_device(&mut out, device);
    }
    for format in &document.formats {
        out.push('\n');
        emit_format(&mut out, format);
    }
    // Functions before the instructions that call them, callees first; their
    // calls print in the elaborated `(call name iR (iP arg) ...)` form, which
    // the reader takes as it stands.
    for function in &document.functions {
        let params: Vec<String> =
            function.params.iter().map(|(name, width)| format!("({name} i{width})")).collect();
        writeln!(
            out,
            "\n  (deffun {} ({}) i{} {})",
            function.name,
            params.join(" "),
            function.result_width,
            crate::effects::render_semexpr(&function.body)
        )
        .unwrap();
    }
    for instruction in &document.instructions {
        out.push('\n');
        emit_instruction(&mut out, instruction);
    }
    for lowering in &document.lowerings {
        out.push('\n');
        emit_lowering(&mut out, lowering);
    }
    for personality in &document.personalities {
        out.push('\n');
        emit_personality(&mut out, personality);
    }
    for core in &document.cores {
        out.push('\n');
        emit_core(&mut out, core);
    }
    for accelerator in &document.accelerators {
        out.push('\n');
        emit_accelerator(&mut out, accelerator);
    }
    for memory in &document.memories {
        out.push('\n');
        emit_memory(&mut out, memory);
    }
    if !document.interconnects.is_empty() || !document.memsystems.is_empty() {
        out.push('\n');
        crate::memsys::emit_lisp_forms(&mut out, document);
    }
    for tile in &document.tiles {
        out.push('\n');
        emit_tile(&mut out, tile);
    }
    for packet in &document.packets {
        out.push('\n');
        emit_packet(&mut out, packet);
    }
    for channel in &document.channels {
        out.push('\n');
        emit_channel(&mut out, channel);
    }
    for fabric in &document.fabrics {
        out.push('\n');
        emit_fabric(&mut out, fabric);
    }
    for mapping in &document.mappings {
        out.push('\n');
        emit_mapping(&mut out, mapping);
    }
    for abi in &document.abis {
        out.push('\n');
        emit_abi(&mut out, abi);
    }
    out.push_str(")\n");
    out
}

/// `(rv_gpr 10 17)`, collapsed back to the range form it was written in. A
/// range that is one register drops the second index, because that is how a
/// description writes it and this emitter is how a corpus is rewritten from its
/// own emitted form.
fn render_register_ref(reference: &crate::ast::RegisterRef) -> String {
    if reference.first == reference.last {
        format!("({} {})", reference.class, reference.first)
    } else {
        format!("({} {} {})", reference.class, reference.first, reference.last)
    }
}

fn emit_register_refs(out: &mut String, key: &str, refs: &[crate::ast::RegisterRef]) {
    if refs.is_empty() {
        return;
    }
    let rendered: Vec<String> = refs.iter().map(render_register_ref).collect();
    writeln!(out, "    ({key} {})", rendered.join(" ")).unwrap();
}

fn emit_abi(out: &mut String, abi: &crate::ast::Abi) {
    writeln!(out, "  (defabi {}", abi.name).unwrap();
    property_atom(out, 2, "isa", &abi.isa);
    property_u32(out, 2, "pointer-bits", abi.pointer_bits);
    property_u32(out, 2, "stack-alignment", abi.stack_alignment);
    for (key, reference) in [
        ("stack-pointer", &abi.stack_pointer),
        ("frame-pointer", &abi.frame_pointer),
        ("link-register", &abi.link_register),
    ] {
        if let Some(reference) = reference {
            writeln!(out, "    ({key} {})", render_register_ref(reference)).unwrap();
        }
    }
    emit_register_refs(out, "arguments", &abi.arguments);
    emit_register_refs(out, "returns", &abi.returns);
    emit_register_refs(out, "callee-saved", &abi.callee_saved);
    emit_register_refs(out, "caller-saved", &abi.caller_saved);
    emit_register_refs(out, "reserved", &abi.reserved);
    if let Some(frame) = &abi.frame {
        writeln!(out, "    (frame").unwrap();
        writeln!(out, "      (growth {})", frame.growth).unwrap();
        writeln!(out, "      (saved-area {})", frame.saved_area).unwrap();
        writeln!(out, "      (slot-bytes {})", frame.slot_bytes).unwrap();
        let saved: Vec<String> = frame.save_order.iter().map(render_register_ref).collect();
        writeln!(out, "      (save-order {})", saved.join(" ")).unwrap();
        writeln!(out, "      (frame-pointer-at {})", frame.frame_pointer_at).unwrap();
        writeln!(out, "      (max-frame-bytes {})", frame.max_frame_bytes).unwrap();
        writeln!(out, "      (red-zone {})", frame.red_zone).unwrap();
        writeln!(out, "      (adjust {})", frame.adjust).unwrap();
        writeln!(out, "      (save {})", frame.save).unwrap();
        writeln!(out, "      (restore {})", frame.restore).unwrap();
        if !frame.regions.is_empty() {
            writeln!(out, "      (regions {})", frame.regions.join(" ")).unwrap();
        }
        if !frame.spill.is_empty() {
            let slots: Vec<String> = frame
                .spill
                .iter()
                .map(|slot| format!("({} {} {})", slot.class, slot.bytes, slot.align))
                .collect();
            writeln!(out, "      (spill {})", slots.join(" ")).unwrap();
        }
        if !frame.realignment.is_empty() {
            writeln!(out, "      (realignment {})", frame.realignment).unwrap();
        }
        if !frame.dynamic_allocation.is_empty() {
            writeln!(
                out,
                "      (dynamic-allocation {})",
                frame.dynamic_allocation
            )
            .unwrap();
        }
        if let Some(base) = &frame.base_pointer {
            writeln!(out, "      (base-pointer {})", render_register_ref(base)).unwrap();
        }
        close_form(out, 2);
    }
    if let Some(aggregates) = &abi.aggregates {
        writeln!(out, "    (aggregates").unwrap();
        writeln!(
            out,
            "      (max-register-bytes {})",
            aggregates.max_register_bytes
        )
        .unwrap();
        writeln!(out, "      (split {})", aggregates.split).unwrap();
        if let Some(pointer) = &aggregates.return_pointer {
            writeln!(
                out,
                "      (return-pointer {})",
                render_register_ref(pointer)
            )
            .unwrap();
        }
        close_form(out, 2);
    }
    if !abi.description.is_empty() {
        property_string(out, 2, "description", &abi.description);
    }
    close_form(out, 1);
}

fn emit_packet(out: &mut String, packet: &crate::ast::Packet) {
    writeln!(out, "  (defpacket {}", packet.name).unwrap();
    property_atom_if(out, 2, "isa", &packet.isa);
    property_atom_if(out, 2, "mode", &packet.mode);
    if !packet.slots.is_empty() {
        writeln!(out, "    (slots").unwrap();
        for slot in &packet.slots {
            writeln!(
                out,
                "      ({} (width {}) (units {}))",
                slot.name,
                slot.width,
                slot.units.join(" ")
            )
            .unwrap();
        }
        close_form(out, 2);
    }
    property_atom_if(out, 2, "order", &packet.order);
    if !packet.end.is_empty() {
        // `(end stop_bit N)` carries the bit; `(end fixed)` does not.
        if packet.stop_bit > 0 || packet.end == "stop_bit" {
            writeln!(out, "    (end {} {})", packet.end, packet.stop_bit).unwrap();
        } else {
            writeln!(out, "    (end {})", packet.end).unwrap();
        }
    }
    property_atom_if(out, 2, "hazards", &packet.hazards);
    property_atom_if(out, 2, "branches", &packet.branches);
    if !packet.description.is_empty() {
        property_string(out, 2, "description", &packet.description);
    }
    close_form(out, 1);
}

fn emit_channel(out: &mut String, channel: &crate::ast::Channel) {
    writeln!(out, "  (defchannel {}", channel.name).unwrap();
    property_atom_if(out, 2, "protocol", &channel.protocol);
    writeln!(
        out,
        "    (latency {} {})",
        channel.latency_min, channel.latency_max
    )
    .unwrap();
    property_u32(out, 2, "capacity", channel.capacity);
    property_atom_if(out, 2, "order", &channel.order);
    if channel.initial > 0 {
        property_u32(out, 2, "initial", channel.initial);
    }
    if !channel.description.is_empty() {
        property_string(out, 2, "description", &channel.description);
    }
    close_form(out, 1);
}

fn emit_fabric(out: &mut String, fabric: &crate::ast::Fabric) {
    writeln!(out, "  (deffabric {}", fabric.name).unwrap();
    property_u32(out, 2, "rows", fabric.rows);
    property_u32(out, 2, "cols", fabric.cols);
    property_atom_if(out, 2, "mode", &fabric.mode);
    if let Some((row, packet)) = &fabric.vliw_row {
        writeln!(out, "    (vliw-row {row} {packet})").unwrap();
    }
    writeln!(
        out,
        "    (pe (units {}) (regs {}) (const {}))",
        fabric.units.join(" "),
        fabric.regs,
        fabric.consts
    )
    .unwrap();
    for class in &fabric.pe_rows {
        // `(row N)` is `(rows N N)`; emitting the range form always would be
        // faithful and would read as a range where the document meant one row.
        let span = if class.first_row == class.last_row {
            format!("(row {})", class.first_row)
        } else {
            format!("(rows {} {})", class.first_row, class.last_row)
        };
        writeln!(
            out,
            "    (pe {span} (units {}) (regs {}) (const {}))",
            class.units.join(" "),
            class.regs,
            class.consts
        )
        .unwrap();
    }
    // Every link explicitly, with the compass name it was expanded from. The
    // compact `(links (north 1) ...)` form is a pattern over a grid, and
    // recognising a pattern in a link set would be inference; carrying the
    // direction on the explicit form states what the document already holds.
    for link in &fabric.links {
        write!(
            out,
            "    (link ({} {}) ({} {}) (latency {})",
            link.from_row, link.from_col, link.to_row, link.to_col, link.latency
        )
        .unwrap();
        if !link.direction.is_empty() {
            write!(out, " (direction {})", link.direction).unwrap();
        }
        out.push_str(")\n");
    }
    if !fabric.ports.is_empty() {
        write!(out, "    (memory-ports").unwrap();
        for port in &fabric.ports {
            write!(out, " (row {} {})", port.row, port.memory).unwrap();
        }
        out.push_str(")\n");
    }
    property_u32(out, 2, "ii-max", fabric.ii_max);
    if fabric.contexts > 1 {
        property_u32(out, 2, "contexts", fabric.contexts);
    }
    if !fabric.description.is_empty() {
        property_string(out, 2, "description", &fabric.description);
    }
    close_form(out, 1);
}

fn emit_mapping(out: &mut String, mapping: &crate::ast::Mapping) {
    writeln!(out, "  (defmapping {}", mapping.name).unwrap();
    property_atom_if(out, 2, "fabric", &mapping.fabric);
    property_u32(out, 2, "ii", mapping.ii);
    if !mapping.ops.is_empty() {
        writeln!(out, "    (place").unwrap();
        for op in &mapping.ops {
            writeln!(
                out,
                "      ({} {} (pe {} {}) (cycle {}))",
                op.id, op.mnemonic, op.row, op.col, op.cycle
            )
            .unwrap();
        }
        close_form(out, 2);
    }
    for route in &mapping.routes {
        write!(
            out,
            "    (route ({} -> {} (operand {})",
            route.from, route.to, route.operand
        )
        .unwrap();
        if !route.via.is_empty() {
            write!(out, " (via").unwrap();
            for (row, col) in &route.via {
                write!(out, " ({row} {col})").unwrap();
            }
            out.push(')');
        }
        if route.cycle > 0 {
            write!(out, " (cycle {})", route.cycle).unwrap();
        }
        if route.distance > 0 {
            write!(out, " (distance {})", route.distance).unwrap();
        }
        if !route.channel.is_empty() {
            write!(out, " (channel {})", route.channel).unwrap();
        }
        out.push_str("))\n");
    }
    if !mapping.live_in.is_empty() {
        writeln!(out, "    (live-in").unwrap();
        for entry in &mapping.live_in {
            let source = match &entry.source {
                crate::ast::MappingSource::Register(index) => format!("(reg {index})"),
                crate::ast::MappingSource::Constant(value) => format!("(const {value})"),
            };
            writeln!(out, "      ({} {} {source})", entry.op, entry.operand).unwrap();
        }
        close_form(out, 2);
    }
    if !mapping.live_out.is_empty() {
        writeln!(out, "    (live-out").unwrap();
        for entry in &mapping.live_out {
            writeln!(out, "      ({} (reg {}))", entry.op, entry.register).unwrap();
        }
        close_form(out, 2);
    }
    property_atoms(out, 2, "equivalent-to", &mapping.equivalent_to);
    if !mapping.description.is_empty() {
        property_string(out, 2, "description", &mapping.description);
    }
    close_form(out, 1);
}

fn emit_lowering(out: &mut String, lowering: &Lowering) {
    writeln!(out, "  (deflowering {}", lowering.name).unwrap();
    writeln!(out, "    (source").unwrap();
    for step in &lowering.sources {
        writeln!(out, "      {}", render_lowering_step(step)).unwrap();
    }
    close_form(out, 2);
    writeln!(
        out,
        "    (target {})",
        render_lowering_step(&lowering.target)
    )
    .unwrap();
    if let Some(predicate) = &lowering.requires {
        writeln!(
            out,
            "    (requires {})",
            render_lowering_predicate(predicate)
        )
        .unwrap();
    }
    property_u32(out, 2, "source-cycles", lowering.source_cycles);
    property_u32(out, 2, "target-cycles", lowering.target_cycles);
    property_atom(out, 2, "benefit", &lowering.benefit);
    close_form(out, 1);
}

fn render_lowering_step(step: &LoweringStep) -> String {
    let bindings = step
        .bindings
        .iter()
        .map(|binding| {
            format!(
                "({} {})",
                binding.operand,
                render_lowering_value(&binding.value)
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    if bindings.is_empty() {
        format!("({})", step.instruction)
    } else {
        format!("({} {bindings})", step.instruction)
    }
}

fn render_lowering_predicate(predicate: &LoweringPredicate) -> String {
    match predicate {
        LoweringPredicate::Compare { lhs, op, rhs } => {
            let operator = render_compare_operator(op.name());
            format!(
                "({operator} {} {})",
                render_lowering_value(lhs),
                render_lowering_value(rhs)
            )
        }
        LoweringPredicate::And(children) => render_lowering_predicates("and", children),
        LoweringPredicate::Or(children) => render_lowering_predicates("or", children),
        LoweringPredicate::Not(child) => {
            format!("(not {})", render_lowering_predicate(child))
        }
    }
}

fn render_lowering_predicates(operator: &str, children: &[LoweringPredicate]) -> String {
    format!(
        "({operator} {})",
        children
            .iter()
            .map(render_lowering_predicate)
            .collect::<Vec<_>>()
            .join(" ")
    )
}

fn render_lowering_value(value: &LoweringValue) -> String {
    match value {
        LoweringValue::Variable(variable) => format!("${variable}"),
        LoweringValue::Literal(value) => value.to_string(),
    }
}

fn emit_isa(out: &mut String, isa: &Isa) {
    writeln!(out, "  (defisa {}", isa.name).unwrap();
    if !isa.role.is_empty() {
        property_atom(out, 2, "role", &isa.role);
    }
    property_atom(out, 2, "base", &isa.base);
    property_u32(out, 2, "word-bits", isa.word_bits);
    property_strings(out, 2, "registers", &isa.registers);
    property_atoms(out, 2, "features", &isa.features);
    property_atom(out, 2, "memory-model", &isa.memory_model);
    property_atom(out, 2, "endianness", &isa.endianness);
    // The vector and lane geometry. `(lanes N)` is what makes `lane_id` a legal
    // symbol, so a canonical form without it was a document whose own
    // semantics referred to something nothing had introduced -- which is how
    // `lisp_roundtrip.py` found this one.
    if isa.lanes > 0 {
        property_u32(out, 2, "lanes", isa.lanes);
    }
    if isa.vector_bits > 0 {
        property_u32(out, 2, "vector-bits", isa.vector_bits);
    }
    if isa.vector_sew > 0 {
        property_u32(out, 2, "vector-sew", isa.vector_sew);
    }
    if isa.vector_elen > 0 {
        property_u32(out, 2, "vector-elen", isa.vector_elen);
    }
    if isa.vector_lmul_num > 0 && isa.vector_lmul_den > 0 {
        // A rational, and it has to stay one: `1/8` is a configuration a
        // machine can be in and an integer could not say it.
        if isa.vector_lmul_den == 1 {
            property_u32(out, 2, "vector-lmul", isa.vector_lmul_num);
        } else {
            writeln!(
                out,
                "    (vector-lmul {}/{})",
                isa.vector_lmul_num, isa.vector_lmul_den
            )
            .unwrap();
        }
    }
    if !isa.unspecified_realization.is_empty() {
        property_atom(out, 2, "unspecified-realization", &isa.unspecified_realization);
    }
    if !isa.reduction_realization.is_empty() {
        property_atom(out, 2, "reduction-realization", &isa.reduction_realization);
    }
    close_form(out, 1);
}

fn emit_mode(out: &mut String, mode: &Mode) {
    writeln!(out, "  (defmode {}", mode.name).unwrap();
    property_u32(out, 2, "csr", mode.csr);
    writeln!(out, "    (field {} {})", mode.field_hi, mode.field_lo).unwrap();
    writeln!(out, "    (values").unwrap();
    for (name, value) in &mode.values {
        writeln!(out, "      ({name} {value})").unwrap();
    }
    close_form(out, 2);
    property_atom(out, 2, "default", &mode.default);
    if !mode.description.is_empty() {
        property_string(out, 2, "description", &mode.description);
    }
    close_form(out, 1);
}

fn emit_config(out: &mut String, config: &crate::ast::Config) {
    writeln!(out, "  (defconfig {}", config.name).unwrap();
    property_u32(out, 2, "bytes", config.bytes);
    for field in &config.fields {
        write!(out, "    (field {} (at {}) (width {}) (values",
               field.name, field.at, field.width).unwrap();
        for value in &field.values {
            write!(out, " {value}").unwrap();
        }
        writeln!(out, "))").unwrap();
    }
    write!(out, "    (instantiate").unwrap();
    for (name, value) in &config.instantiate {
        write!(out, " ({name} {value})").unwrap();
    }
    writeln!(out, ")").unwrap();
    if !config.description.is_empty() {
        property_string(out, 2, "description", &config.description);
    }
    close_form(out, 1);
}

fn emit_kernel(out: &mut String, kernel: &crate::ast::Kernel) {
    writeln!(out, "  (defkernel {}", kernel.name).unwrap();
    writeln!(out, "    (params {})", kernel.params.join(" ")).unwrap();
    write!(out, "    (space").unwrap();
    for (index, extent) in &kernel.space {
        write!(out, " ({index} {extent})").unwrap();
    }
    writeln!(out, ")").unwrap();
    for statement in &kernel.body {
        writeln!(out, "    {statement}").unwrap();
    }
    if !kernel.description.is_empty() {
        property_string(out, 2, "description", &kernel.description);
    }
    close_form(out, 1);
}

fn emit_device(out: &mut String, device: &crate::ast::Device) {
    writeln!(out, "  (defdevice {}", device.name).unwrap();
    writeln!(out, "    (isa {})", device.isa).unwrap();
    writeln!(out, "    (window {:#x})", device.window).unwrap();
    for register in &device.registers {
        writeln!(out, "    (register {:#x} {} {})", register.offset, register.access, register.handler).unwrap();
    }
    if !device.description.is_empty() {
        property_string(out, 2, "description", &device.description);
    }
    close_form(out, 1);
}

fn emit_descriptor(out: &mut String, descriptor: &crate::ast::Descriptor) {
    writeln!(out, "  (defdescriptor {}", descriptor.name).unwrap();
    writeln!(out, "    (bytes {})", descriptor.bytes).unwrap();
    writeln!(out, "    (fields").unwrap();
    for field in &descriptor.fields {
        let sign = if field.signed { " signed" } else { "" };
        writeln!(out, "      ({} {} i{}{sign})", field.name, field.offset, field.width).unwrap();
    }
    writeln!(out, "    )").unwrap();
    for check in &descriptor.checks {
        writeln!(out, "    (check {} {})", check.condition, check.status).unwrap();
    }
    let destination = if descriptor.status_field.is_empty() { "returned" } else { &descriptor.status_field };
    writeln!(out, "    (status {destination} i{})", descriptor.status_width).unwrap();
    if !descriptor.description.is_empty() {
        property_string(out, 2, "description", &descriptor.description);
    }
    close_form(out, 1);
}

fn emit_format(out: &mut String, format: &Format) {
    writeln!(out, "  (defformat {}", format.name).unwrap();
    property_u32(out, 2, "bits", format.bits);
    writeln!(out, "    (fields").unwrap();
    for field in &format.fields {
        match (field.op_hi, field.op_lo) {
            (Some(op_hi), Some(op_lo)) => {
                writeln!(
                    out,
                    "      ({} {} {} {} {})",
                    field.name, field.insn_hi, field.insn_lo, op_hi, op_lo
                )
                .unwrap();
            }
            _ if field.insn_hi == field.insn_lo => {
                writeln!(out, "      ({} {})", field.name, field.insn_hi).unwrap();
            }
            _ => {
                writeln!(
                    out,
                    "      ({} {} {})",
                    field.name, field.insn_hi, field.insn_lo
                )
                .unwrap();
            }
        }
    }
    close_form(out, 2);
    close_form(out, 1);
}

fn emit_instruction(out: &mut String, instruction: &Instruction) {
    writeln!(out, "  (definstruction {}", instruction.name).unwrap();
    property_atom(out, 2, "mnemonic", &instruction.mnemonic);
    if !instruction.isa.is_empty() {
        property_atom(out, 2, "isa", &instruction.isa);
    }
    if !instruction.description.is_empty() {
        property_string(out, 2, "description", &instruction.description);
    }
    property_atom(out, 2, "category", &instruction.category);
    property_atom(out, 2, "format", &instruction.format);
    property_u32(out, 2, "opcode", instruction.opcode);
    property_u32(out, 2, "func3", instruction.func3);
    property_u32(out, 2, "func7", instruction.func7);
    if !instruction.encoding.is_empty() {
        write!(out, "    (encoding").unwrap();
        for (name, value) in &instruction.encoding {
            write!(out, " ({name} {value})").unwrap();
        }
        out.push_str(")\n");
    }
    if !instruction.operands.is_empty() {
        writeln!(out, "    (operands").unwrap();
        for operand in &instruction.operands {
            let role = crate::ast::operand_role(operand, false);
            if operand.derived_from.is_empty() {
                // `element` says this operand names one lane of a wider
                // register rather than a window of it, and validation refuses
                // the operand without it. Dropping it made a canonical
                // `simd_fp_lanes` a document that did not validate.
                let marker = if operand.element { " element" } else { "" };
                // An assembly transform is the fifth slot too, and is written
                // only when it is not the identity -- a canonical document
                // that spelled out every default would not be canonical.
                let transform = operand
                    .asm_transform
                    .lisp()
                    .map(|form| format!(" {form}"))
                    .or_else(|| operand.fixed.map(|index| format!(" (fixed {index})")))
                    .unwrap_or_default();
                writeln!(
                    out,
                    "      ({} {} i{} {}{marker}{transform})",
                    operand.name, operand.kind, operand.width, role
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "      ({} {} i{} {} (derive {} {}))",
                    operand.name,
                    operand.kind,
                    operand.width,
                    role,
                    operand.derived_from,
                    operand.derived_add
                )
                .unwrap();
            }
        }
        close_form(out, 2);
    }
    property_atoms(out, 2, "modes", &instruction.modes);
    // A syllable's unit class and a launch's mapping are declared, not derived,
    // so a canonical document that dropped them would describe a different
    // machine -- one whose syllables fit any slot and whose launch runs
    // nothing. Both were dropped until `lisp_roundtrip.py` said so.
    property_atom_if(out, 2, "unit", &instruction.unit);
    property_atom_if(out, 2, "configures", &instruction.configures);
    property_atom_if(out, 2, "runs-mapping", &instruction.runs_mapping);
    if !instruction.asm.is_empty() {
        property_string(out, 2, "asm", &instruction.asm);
    }
    if !instruction.semantics.is_empty() {
        property_string(out, 2, "semantics", &instruction.semantics);
    }
    if let Some(constraint) = &instruction.decode_constraint {
        writeln!(out, "    (requires {})", render_constraint(constraint)).unwrap();
    }
    if !instruction.implementation.is_empty() {
        // Round-tripped like any other property: a description that loses which
        // routine performs an instruction has lost the only thing it said about
        // what that instruction does.
        writeln!(out, "    (implementation {})", instruction.implementation.trim()).unwrap();
    }
    if !instruction.runs_kernel.is_empty() {
        writeln!(out, "    (runs-kernel {})", instruction.runs_kernel.join(" ")).unwrap();
    }
    if !instruction.launches.is_empty() {
        writeln!(out, "    (launches {})", instruction.launches.join(" ")).unwrap();
    }
    // A behavior the kernel supplied is not re-emitted: the launch IS the
    // source, and writing the expansion back would turn a named kernel into
    // four hand-written stores the next time the file is read.
    if let Some(behavior) = instruction
        .behavior
        .as_ref()
        .filter(|_| !instruction.behavior_from_kernel && !instruction.behavior_from_launch)
    {
        emit_behavior(out, behavior);
    } else if !instruction.vector_semantics.is_empty() {
        // ⚠️ The spelling the author WROTE, not what it expanded to. A
        // `(add v16i8 rn rm)` becomes sixteen masked adds at parse time, and
        // emitting those would be emitting the consequence instead of the
        // statement: the file would still mean the same thing, but it would no
        // longer say it, and re-parsing it leaves `vector_semantics` empty
        // because there is nothing left to expand. The round-trip test caught
        // exactly that, the first time a corpus it reads had a vector formal.
        writeln!(out, "    (formal {})", instruction.vector_semantics.trim()).unwrap();
    } else if !instruction.formal_semantics.is_empty() {
        writeln!(out, "    (formal {})", instruction.formal_semantics.trim()).unwrap();
    }
    property_u32(out, 2, "latency", instruction.latency_cycles);
    property_atom(out, 2, "throughput", &instruction.throughput_per_cycle);
    property_atom(out, 2, "area-estimate-um2", &instruction.area_estimate_um2);
    property_atom(out, 2, "power-estimate-mw", &instruction.power_estimate_mw);
    property_atom(out, 2, "expected-speedup", &instruction.expected_speedup);
    if !instruction.intrinsic.is_empty() {
        property_atom(out, 2, "intrinsic", &instruction.intrinsic);
    }
    property_atoms(out, 2, "patterns", &instruction.patterns);
    property_atoms(
        out,
        2,
        "applicable-patterns",
        &instruction.applicable_patterns,
    );
    if !instruction.rationale.is_empty() {
        property_string(out, 2, "rationale", &instruction.rationale);
    }
    close_form(out, 1);
}

fn emit_behavior(out: &mut String, behavior: &Behavior) {
    writeln!(out, "    (behavior").unwrap();
    let mut index = 0;
    while index < behavior.effects.len() {
        let effect = &behavior.effects[index];
        if effect.atomic_group == 0 {
            writeln!(out, "      {}", render_effect(effect)).unwrap();
            index += 1;
            continue;
        }
        let group = effect.atomic_group;
        writeln!(out, "      (atomic-group {group}").unwrap();
        while index < behavior.effects.len() && behavior.effects[index].atomic_group == group {
            writeln!(out, "        {}", render_effect(&behavior.effects[index])).unwrap();
            index += 1;
        }
        writeln!(out, "      )").unwrap();
    }
    close_form(out, 2);
}

fn render_effect(effect: &Effect) -> String {
    let statement = match &effect.loc {
        Loc::Reg(name) => format!("(set {name} {})", render_semexpr(&effect.value.expr)),
        Loc::FixedReg { kind, index, width } => {
            format!(
                "(setreg {kind} {index} i{width} {})",
                render_semexpr(&effect.value.expr)
            )
        }
        Loc::State { name, width } => {
            format!(
                "(setstate {name} {} i{width})",
                render_semexpr(&effect.value.expr)
            )
        }
        Loc::Port { port, width } => {
            format!(
                "(send {} {} i{width})",
                render_semexpr(&port.expr),
                render_semexpr(&effect.value.expr)
            )
        }
        Loc::Mem {
            addr,
            width,
            order,
            atomic,
        } => {
            let order = if *order == crate::effects::MemoryOrder::Relaxed {
                String::new()
            } else {
                format!(" {}", order.as_str())
            };
            format!(
                "({} {} {} i{width}{order})",
                if *atomic { "atomic_store" } else { "store" },
                render_semexpr(&addr.expr),
                render_semexpr(&effect.value.expr)
            )
        }
        Loc::Barrier { kind, .. } => {
            // A kind with no option renders without one, so what comes back out
            // is what went in. `fence.i` has no option field to name.
            match crate::effects::barrier_kind(kind) {
                Some(found) if found.option_bits == 0 => format!("(barrier {kind})"),
                _ => format!("(barrier {kind} {})", render_semexpr(&effect.value.expr)),
            }
        }
        Loc::Pc => format!("(setpc {})", render_semexpr(&effect.value.expr)),
        Loc::Trap => format!("(trap {})", render_semexpr(&effect.value.expr)),
    };
    match &effect.guard {
        Some(guard) => format!("(when {} {statement})", render_semexpr(&guard.expr)),
        None => statement,
    }
}

fn render_constraint(constraint: &DecodeConstraint) -> String {
    match constraint {
        DecodeConstraint::A64LogicalImmediate { width, n, imms } => {
            let n = match n {
                ConstraintValue::Literal(value) => value.to_string(),
                ConstraintValue::Operand(name) => name.clone(),
            };
            format!("(a64-logical-imm i{width} {n} {imms})")
        }
        DecodeConstraint::A64ShiftedRegister {
            width,
            shift,
            amount,
        } => format!("(a64-shifted-reg i{width} {shift} {amount})"),
        DecodeConstraint::A64ExtendedRegister { amount } => {
            format!("(a64-extended-reg {amount})")
        }
        DecodeConstraint::UnsignedCompare {
            operand,
            op,
            literal,
        } => {
            let operator = render_compare_operator(op.name());
            format!("({operator} {operand} {literal})")
        }
        DecodeConstraint::MaskedEq {
            operand,
            mask,
            value,
        } => format!("(masked-eq {operand} {mask} {value})"),
        DecodeConstraint::And(children) => render_constraints("and", children),
        DecodeConstraint::Or(children) => render_constraints("or", children),
        DecodeConstraint::Not(child) => format!("(not {})", render_constraint(child)),
    }
}

fn render_compare_operator(operator: &str) -> &str {
    match operator {
        "eq" => "=",
        "ne" => "!=",
        "lt" => "<",
        "le" => "<=",
        "gt" => ">",
        "ge" => ">=",
        other => other,
    }
}

fn render_constraints(operator: &str, children: &[DecodeConstraint]) -> String {
    let children = children
        .iter()
        .map(render_constraint)
        .collect::<Vec<_>>()
        .join(" ");
    format!("({operator} {children})")
}

fn emit_personality(out: &mut String, personality: &Personality) {
    writeln!(out, "  (defpersonality {}", personality.name).unwrap();
    if !personality.mode.is_empty() {
        property_atom(out, 2, "mode", &personality.mode);
    }
    property_atom(out, 2, "implements", &personality.implements);
    write!(out, "    (discipline {}", personality.discipline.kind).unwrap();
    for (name, value) in &personality.discipline.params {
        write!(out, " ({name} {value})").unwrap();
    }
    out.push_str(")\n");
    property_strings(out, 2, "capsule", &personality.capsule);
    // The seams (G4b.3). Added when `lisp_roundtrip.py` found them missing --
    // they were published in the capsule manifest and dropped from the
    // canonical form, so a round-tripped `vliw_exposed` was a machine that
    // lent nothing.
    for export in &personality.exports {
        writeln!(
            out,
            "    (exports ({} (unit {}) (channel {})))",
            export.name, export.unit, export.channel
        )
        .unwrap();
    }
    for import in &personality.imports {
        writeln!(
            out,
            "    (imports ({} (from {}) (channel {})))",
            import.name, import.from, import.channel
        )
        .unwrap();
    }
    if !personality.description.is_empty() {
        property_string(out, 2, "description", &personality.description);
    }
    close_form(out, 1);
}

fn emit_core(out: &mut String, core: &Core) {
    writeln!(out, "  (defcore {}", core.name).unwrap();
    property_atom(out, 2, "kind", &core.kind);
    property_u32(out, 2, "threads", core.threads);
    if !core.implements.is_empty() {
        property_atom(out, 2, "implements", &core.implements);
    }
    // ⚠️ Emitted only when declared, so a core that never said how wide it
    // is does not come back claiming to be one wide. The round trip has to
    // be the identity on descriptions that predate this form.
    if core.issue_width != 0 {
        property_u32(out, 2, "issue-width", core.issue_width);
    }
    if core.rob != 0 {
        let mut more = String::new();
        if core.dispatch_width != 0 {
            more.push_str(&format!(" (dispatch-width {})", core.dispatch_width));
        }
        if core.schedule != 0 {
            more.push_str(&format!(" (schedule {})", core.schedule));
        }
        if core.rename_width != 0 {
            more.push_str(&format!(" (rename-width {})", core.rename_width));
        }
        if !core.select.is_empty() {
            more.push_str(&format!(" (select {})", core.select));
        }
        if !core.eliminate.is_empty() {
            more.push_str(&format!(" (eliminate {})", core.eliminate));
        }
        writeln!(
            out,
            "    (window (rob {}) (issue-queue {}) (commit-width {}){more})",
            core.rob, core.issue_queue, core.commit_width
        )
        .unwrap();
    }
    if let Some((entries, confidence)) = core.value_prediction {
        let kind = if core.value_stride { "(kind stride) " } else { "" };
        writeln!(out, "    (value-prediction {kind}(entries {entries}) (confidence {confidence}))").unwrap();
    }
    if !core.queues.is_empty() {
        let each: Vec<String> = core
            .queues
            .iter()
            .map(|(name, size, units)| format!("({name} (size {size}) (units {}))", units.join(" ")))
            .collect();
        writeln!(out, "    (queues {})", each.join(" ")).unwrap();
    }
    if !core.bypass.is_empty() {
        let pairs: Vec<String> =
            core.bypass.iter().map(|(from, to, cycles)| format!("({from} {to} {cycles})")).collect();
        writeln!(out, "    (bypass {})", pairs.join(" ")).unwrap();
    }
    if core.branch_penalty != 0 || !core.predictor.is_empty() {
        write!(out, "    (branch (penalty {})", core.branch_penalty).unwrap();
        if !core.predictor.is_empty() {
            write!(out, " (predictor {})", core.predictor).unwrap();
        }
        if core.predictor_entries != 0 {
            write!(out, " (entries {})", core.predictor_entries).unwrap();
        }
        if core.predictor_history != 0 {
            write!(out, " (history {})", core.predictor_history).unwrap();
        }
        for (key, value) in &core.predictor_params {
            write!(out, " ({key} {value})").unwrap();
        }
        if let Some(quick) = &core.overrides {
            write!(
                out,
                " (overrides (predictor {}) (entries {}) (cycles {}))",
                quick.predictor, quick.entries, quick.cycles
            )
            .unwrap();
        }
        writeln!(out, ")").unwrap();
    }
    // ⚠️ Emitted WHOLE when present, defaults included: `(lsq)` and no `lsq`
    // are different machines, and a round trip that dropped a clause because
    // every value in it was a default would turn one into the other.
    if let Some(lsq) = &core.lsq {
        write!(
            out,
            "    (lsq (loads {}) (stores {}) (disambiguation {}) (forwarding {})",
            lsq.loads, lsq.stores, lsq.disambiguation, lsq.forwarding
        )
        .unwrap();
        // Only where the policy reads them, which is also where validation
        // allows them: a round trip must not invent a number nothing reads.
        if lsq.replay != 0 {
            write!(out, " (replay {})", lsq.replay).unwrap();
        }
        if lsq.store_sets != 0 {
            write!(out, " (store-sets {})", lsq.store_sets).unwrap();
        }
        writeln!(out, ")").unwrap();
    }
    if core.store_buffer != 0 || !core.store_drain.is_empty() {
        let drain = if core.store_drain.is_empty() { String::new() } else { format!(" (drain {})", core.store_drain) };
        writeln!(out, "    (store-buffer (entries {}){drain})", core.store_buffer).unwrap();
    }
    if !core.load_order.is_empty() {
        writeln!(out, "    (load-order {})", core.load_order).unwrap();
    }
    if let Some(fe) = &core.front_end {
        write!(out, "    (front-end (fetch-width {}) (depth {})", fe.fetch_width, fe.depth).unwrap();
        if fe.buffer != 0 {
            write!(out, " (buffer {})", fe.buffer).unwrap();
        }
        if fe.btb != 0 {
            write!(out, " (btb {}) (btb-penalty {})", fe.btb, fe.btb_penalty).unwrap();
        }
        if fe.ras != 0 {
            write!(out, " (ras {})", fe.ras).unwrap();
        }
        if !fe.icache.is_empty() {
            write!(out, " (icache {})", fe.icache).unwrap();
        }
        if fe.wrong_path_fetch {
            write!(out, " (wrong-path-fetch true)").unwrap();
        }
        if fe.wrong_path_execute {
            write!(out, " (wrong-path-execute true)").unwrap();
        }
        if let Some(oc) = &fe.op_cache {
            write!(
                out,
                " (op-cache (entries {}) (ways {}) (window {}) (width {}) (depth {}))",
                oc.entries, oc.ways, oc.window, oc.width, oc.depth
            )
            .unwrap();
        }
        if let Some(lb) = &fe.loop_buffer {
            write!(out, " (loop-buffer (ops {}) (width {}) (depth {}))", lb.ops, lb.width, lb.depth).unwrap();
        }
        if fe.target_queue != 0 {
            write!(out, " (target-queue {})", fe.target_queue).unwrap();
        }
        writeln!(out, ")").unwrap();
    }
    if !core.engine.is_empty() {
        property_atom(out, 2, "engine", &core.engine);
    }
    if !core.memory_timing.is_empty() {
        property_atom(out, 2, "memory-timing", &core.memory_timing);
    }
    if let Some(t) = &core.tlb {
        write!(out, "    (tlb").unwrap();
        for (name, level) in [("data", &t.data), ("fetch", &t.fetch), ("second", &t.second)] {
            if level.entries == 0 {
                continue;
            }
            write!(out, " ({name} (entries {})", level.entries).unwrap();
            if level.ways != 0 {
                write!(out, " (ways {})", level.ways).unwrap();
            }
            if level.latency != 0 {
                write!(out, " (latency {})", level.latency).unwrap();
            }
            write!(out, ")").unwrap();
        }
        if t.page_bytes != 0 {
            write!(out, " (page-bytes {})", t.page_bytes).unwrap();
        }
        if t.walkers != 0 {
            write!(out, " (walkers {})", t.walkers).unwrap();
        }
        if t.walk_cache != 0 {
            write!(out, " (walk-cache (entries {}))", t.walk_cache).unwrap();
        }
        if t.huge_bytes != 0 {
            write!(out, " (huge (bytes {}) (from {}) (to {}))", t.huge_bytes, t.huge_from, t.huge_to).unwrap();
        }
        if t.walk_levels != 0 {
            writeln!(
                out,
                " (walk (levels {}) (cycles {}) (table {})))",
                t.walk_levels, t.walk_level_cycles, t.walk_table
            )
            .unwrap();
        } else {
            writeln!(out, " (walk-cycles {}))", t.walk_cycles).unwrap();
        }
    }
    if let Some((address, size, valid)) = &core.exclusive {
        writeln!(out, "    (exclusive {address} {size} {valid})").unwrap();
    }
    if let Some((wait, send, local)) = &core.events {
        write!(out, "    (events (wait {wait}) (send {send})").unwrap();
        if !local.is_empty() {
            write!(out, " (local {local})").unwrap();
        }
        writeln!(out, ")").unwrap();
    }
    if let Some(simt) = &core.simt {
        write!(
            out,
            "    (simt (warps {}) (lanes {}) (scheduler {}) (stack {}) (line {})",
            simt.warps, simt.lanes, simt.scheduler, simt.stack, simt.line
        )
        .unwrap();
        if !simt.isas.is_empty() {
            write!(out, " (isas {})", simt.isas.join(" ")).unwrap();
        }
        if !simt.untracked.is_empty() {
            write!(out, " (untracked {})", simt.untracked.join(" ")).unwrap();
        }
        if let Some((address, size, valid)) = &simt.exclusive {
            write!(out, " (exclusive {address} {size} {valid})").unwrap();
        }
        if let Some((rob, predictor, merge, entries, memory_order, divergence)) = &simt.ooo {
            write!(out, " (ooo (rob {rob}) (predictor {predictor})").unwrap();
            if *entries > 0 {
                write!(out, " (entries {entries})").unwrap();
            }
            if *memory_order {
                write!(out, " (memory-order true)").unwrap();
            }
            if *divergence {
                write!(out, " (divergence-predictor true)").unwrap();
            }
            if !merge {
                write!(out, " (merge false)").unwrap();
            }
            write!(out, ")").unwrap();
        }
        if let Some(i) = &simt.implicit {
            write!(out, " (implicit (policy {})", i.policy).unwrap();
            if let Some((state, bytes)) = &i.sp {
                write!(out, " (sp {state} {bytes})").unwrap();
            }
            if !i.calls.is_empty() {
                write!(out, " (calls {})", i.calls.join(" ")).unwrap();
            }
            if !i.returns.is_empty() {
                write!(out, " (returns {})", i.returns.join(" ")).unwrap();
            }
            if !i.yields.is_empty() {
                write!(out, " (yield {})", i.yields.join(" ")).unwrap();
            }
            if !i.relax.is_empty() {
                write!(out, " (relax {})", i.relax.join(" ")).unwrap();
            }
            if !i.wait.is_empty() || !i.send.is_empty() || !i.send_local.is_empty() {
                write!(out, " (events").unwrap();
                for (k, v) in [("wait", &i.wait), ("send", &i.send), ("local", &i.send_local)] {
                    if !v.is_empty() {
                        write!(out, " ({k} {})", v.join(" ")).unwrap();
                    }
                }
                write!(out, ")").unwrap();
            }
            if i.smt {
                if i.smt_fronts > 0 {
                    write!(out, " (path-issue smt {})", i.smt_fronts).unwrap();
                } else {
                    write!(out, " (path-issue smt)").unwrap();
                }
            }
            if i.progress > 0 {
                write!(out, " (progress {})", i.progress).unwrap();
            }
            write!(out, ")").unwrap();
        }
        if let Some(v) = &simt.vector {
            write!(out, " (vector (isa {}) (lane-classes {})", v.isa, v.lane_classes.join(" ")).unwrap();
            if !v.lane_state.is_empty() {
                write!(out, " (lane-state {})", v.lane_state.join(" ")).unwrap();
            }
            if !v.broadcast.is_empty() {
                write!(out, " (broadcast {})", v.broadcast.join(" ")).unwrap();
            }
            if !v.crosslane.is_empty() {
                write!(out, " (crosslane {})", v.crosslane.join(" ")).unwrap();
            }
            if !v.sum.is_empty() {
                write!(out, " (sum {})", v.sum.join(" ")).unwrap();
            }
            if let Some((state, mnemonics)) = &v.flags {
                write!(out, " (flags {state} {})", mnemonics.join(" ")).unwrap();
            }
            write!(out, ")").unwrap();
        }
        if simt.pipeline > 0 {
            write!(out, " (pipeline {})", simt.pipeline).unwrap();
        }
        if !simt.mnemonic_latency.is_empty() {
            write!(out, " (mnemonic-latency").unwrap();
            for (prefix, cycles) in &simt.mnemonic_latency {
                write!(out, " ({prefix} {cycles})").unwrap();
            }
            write!(out, ")").unwrap();
        }
        if simt.issue_interval > 0 {
            write!(out, " (issue-interval {})", simt.issue_interval).unwrap();
        }
        if !simt.class_latency.is_empty() {
            write!(out, " (latency").unwrap();
            for (class, cycles) in &simt.class_latency {
                write!(out, " ({class} {cycles})").unwrap();
            }
            write!(out, ")").unwrap();
        }
        if let Some((top, bytes, granule)) = simt.interleave {
            write!(out, " (interleave (top {top}) (bytes {bytes}) (granule {granule})").unwrap();
            if simt.interleave_group > 0 {
                write!(out, " (group {})", simt.interleave_group).unwrap();
            }
            if simt.interleave_xor {
                write!(out, " (xor true)").unwrap();
            }
            write!(out, ")").unwrap();
        }
        let c = &simt.cache;
        if c.bytes > 0 || c.ways > 0 || c.hit > 0 || c.miss > 0 || c.fill > 0 || c.mshrs > 0 {
            write!(
                out,
                " (cache (bytes {}) (ways {}) (hit {}) (miss {}) (fill {}) (mshrs {}) (banks {}))",
                c.bytes, c.ways, c.hit, c.miss, c.fill, c.mshrs, c.banks
            )
            .unwrap();
            if c.l2_bytes > 0 || c.prefetch_degree > 0 || c.track_fills > 0 {
                out.truncate(out.len() - 1);
                if c.l2_bytes > 0 {
                    write!(out, " (l2-bytes {}) (l2-ways {}) (l2-hit {})", c.l2_bytes, c.l2_ways, c.l2_hit).unwrap();
                }
                if c.prefetch_degree > 0 {
                    write!(out, " (prefetch-degree {}) (prefetch-entries {})", c.prefetch_degree, c.prefetch_entries)
                        .unwrap();
                    if c.prefetch_next_line > 0 {
                        write!(out, " (prefetch-next-line {})", c.prefetch_next_line).unwrap();
                    }
                    if c.prefetch_best_offset > 0 {
                        write!(out, " (prefetch-best-offset {})", c.prefetch_best_offset).unwrap();
                    }
                }
                if c.track_fills > 0 {
                    write!(out, " (track-fills {})", c.track_fills).unwrap();
                }
                write!(out, ")").unwrap();
            }
        }
        if !simt.warp_control.is_empty() {
            write!(out, " (warp-control").unwrap();
            for (role, mnemonics) in &simt.warp_control {
                write!(out, " ({role} {})", mnemonics.join(" ")).unwrap();
            }
            write!(out, ")").unwrap();
        }
        if let Some(r) = &simt.sysread {
            write!(out, " (sysread {} (dst {}) (index", r.mnemonic, r.dst).unwrap();
            for (operand, weight) in &r.index {
                write!(out, " ({operand} {weight})").unwrap();
            }
            write!(out, "))").unwrap();
        }
        writeln!(out, ")").unwrap();
    }
    if !core.ports.is_empty() {
        write!(out, "    (ports").unwrap();
        for (port, units) in &core.ports {
            write!(out, " ({port} {})", units.join(" ")).unwrap();
        }
        writeln!(out, ")").unwrap();
    }
    if !core.rename.is_empty() {
        write!(out, "    (rename").unwrap();
        for (file, extra) in &core.rename {
            write!(out, " ({file} {extra})").unwrap();
        }
        writeln!(out, ")").unwrap();
    }
    if !core.memory.is_empty() {
        property_atom(out, 2, "memory", &core.memory);
    }
    if !core.model.is_empty() {
        property_atom(out, 2, "model", &core.model);
    }
    if !core.provenance.is_empty() {
        property_atom(out, 2, "provenance", &core.provenance);
    }
    // ⚠️ Emitted verbatim. AXIS does not know what these mean and must not
    // improve them: a round trip that normalised a vendor's setting would be
    // editing a machine it cannot read.
    if !core.vendor.is_empty() {
        writeln!(out, "    (vendor").unwrap();
        for (key, value) in &core.vendor {
            writeln!(out, "      ({} {})", key, value).unwrap();
        }
        close_form(out, 2);
    }
    if !core.units.is_empty() {
        writeln!(out, "    (units").unwrap();
        for unit in &core.units {
            // `lanes` only when declared: a core that never said is printed
            // exactly as it was before SIMT cores existed.
            let mut lanes = if unit.lanes > 0 { format!(" (lanes {})", unit.lanes) } else { String::new() };
            if unit.interval > 0 {
                lanes.push_str(&format!(" (inflight {})", unit.interval));
            }
            if !unit.length.is_empty() {
                lanes.push_str(&format!(" (length {})", unit.length));
            }
            if !unit.accepts.is_empty() {
                lanes.push_str(&format!(" (accepts {})", unit.accepts.join(" ")));
            }
            if unit.transport > 0 {
                lanes.push_str(&format!(" (transport {})", unit.transport));
            }
            if unit.switch > 0 {
                lanes.push_str(&format!(" (switch {})", unit.switch));
            }
            if unit.abort {
                lanes.push_str(" (abort true)");
            }
            if unit.queue > 0 {
                lanes.push_str(&format!(" (queue {})", unit.queue));
            }
            writeln!(
                out,
                "      ({} (count {}) (pipelined {}){lanes})",
                unit.name, unit.count, unit.pipelined
            )
            .unwrap();
        }
        close_form(out, 2);
    }
    if core.cycle_gates != 0 {
        writeln!(out, "    (cycle (gates {}))", core.cycle_gates).unwrap();
    }
    if let Some(timing) = &core.timing {
        let clause = |name: &str, entries: Vec<String>| {
            if entries.is_empty() { String::new() } else { format!(" ({name} {})", entries.join(" ")) }
        };
        let micro_ops: Vec<String> = timing
            .micro_ops
            .iter()
            .map(|(key, ops)| {
                let ops: Vec<String> = ops.iter().map(|(unit, cycles)| format!("({unit} {cycles})")).collect();
                format!("({key} {})", ops.join(" "))
            })
            .collect();
        writeln!(
            out,
            "    (timing{}{}{}{}{})",
            clause(
                "latency",
                timing
                    .latency
                    .iter()
                    .map(|(k, n)| format!("({k} {n})"))
                    .chain(timing.derived.iter().map(|k| format!("({k} derived)")))
                    .collect()
            ),
            clause(
                "class-latency",
                timing.class_latency.iter().map(|(k, n)| format!("({k} {n})")).collect()
            ),
            clause("unit", timing.unit.iter().map(|(k, u)| format!("({k} {u})")).collect()),
            clause("micro-ops", micro_ops),
            clause("fuse", timing.fuse.iter().map(|(head, tail)| format!("({head} {tail})")).collect()),
        )
        .unwrap();
    }
    property_atoms(out, 2, "personalities", &core.personalities);
    property_atoms(out, 2, "features", &core.features);
    close_form(out, 1);
}

fn emit_accelerator(out: &mut String, accelerator: &Accelerator) {
    writeln!(out, "  (defaccelerator {}", accelerator.name).unwrap();
    property_atom(out, 2, "family", &accelerator.family);
    property_atom_if(out, 2, "subtype", &accelerator.subtype);
    property_u32(out, 2, "descriptor-version", accelerator.descriptor_version);
    property_atom_if(out, 2, "descriptor-schema", &accelerator.descriptor_schema);
    property_u32(out, 2, "descriptor-bytes", accelerator.descriptor_bytes);
    property_atom_if(out, 2, "launch-abi", &accelerator.launch_abi);
    property_atom_if(out, 2, "completion", &accelerator.completion);
    property_atom_if(out, 2, "visibility", &accelerator.visibility);
    property_atom_if(out, 2, "launch-fence", &accelerator.launch_fence);
    property_atom_if(out, 2, "in-flight", &accelerator.in_flight);
    property_u32(out, 2, "mmio-base", accelerator.mmio_base);
    property_u32(out, 2, "mmio-size", accelerator.mmio_size);
    property_atom_if(out, 2, "target", &accelerator.target);
    property_atom_if(out, 2, "coupling", &accelerator.coupling);
    property_u32(out, 2, "region-id", accelerator.region_id);
    property_u32(out, 2, "manifest-version", accelerator.manifest_version);
    property_atom(out, 2, "profile", &accelerator.profile);
    property_atom(out, 2, "backend-kind", &accelerator.backend_kind);
    property_atom(out, 2, "exec-shape", &accelerator.exec_shape);
    property_u32(out, 2, "simd-lanes", accelerator.simd_lanes);
    property_u32(out, 2, "element-width-bits", accelerator.element_width_bits);
    property_atom(out, 2, "fallback-policy", &accelerator.fallback_policy);
    // M1's context surface, emitted only when the engine declares one so a
    // single-context accelerator round-trips to the same text it always did.
    // It has to round-trip at all: this emitter is how a corpus is rewritten
    // from its own emitted form, and a machine that came back with its
    // contexts dropped would be a different machine that still validated.
    if accelerator.contexts > 0 {
        property_u32(out, 2, "contexts", accelerator.contexts);
        property_u32(out, 2, "context-id-bits", accelerator.context_id_bits);
        property_u32(out, 2, "issue-queue-depth", accelerator.issue_queue_depth);
        property_atoms(out, 2, "identity", &accelerator.identity);
        property_atom_if(out, 2, "scheduling", &accelerator.scheduling);
        property_atom_if(out, 2, "preemption", &accelerator.preemption);
        if accelerator.service_interval_cycles > 0 {
            property_u32(
                out,
                2,
                "service-interval-cycles",
                accelerator.service_interval_cycles,
            );
        }
        property_atoms(out, 2, "eligibility", &accelerator.eligibility);
    }
    if !accelerator.ports.is_empty() {
        writeln!(out, "    (ports").unwrap();
        for port in &accelerator.ports {
            writeln!(
                out,
                "      ({} {} {} i{})",
                port.name, port.direction, port.kind, port.width
            )
            .unwrap();
        }
        close_form(out, 2);
    }
    if !accelerator.semantics.is_empty() {
        property_string(out, 2, "semantics", &accelerator.semantics);
    }
    // A multi-result engine must round-trip as the NAMED form; writing the
    // bare form back would state one expression for several output ports,
    // which the reader now refuses -- so emitting it would make the emitted
    // source unreadable by the surface that produced it.
    if accelerator.formal_results.len() > 1 {
        writeln!(out, "    (formal").unwrap();
        for result in &accelerator.formal_results {
            writeln!(
                out,
                "      (result {} {})",
                result.port,
                result.expr.trim()
            )
            .unwrap();
        }
        writeln!(out, "    )").unwrap();
    } else if !accelerator.formal_semantics.is_empty() {
        writeln!(out, "    (formal {})", accelerator.formal_semantics.trim()).unwrap();
    }
    property_u32(out, 2, "latency", accelerator.latency_cycles);
    property_atom(out, 2, "throughput", &accelerator.throughput_per_cycle);
    property_atoms(out, 2, "resources", &accelerator.resources);
    close_form(out, 1);
}

fn emit_memory(out: &mut String, memory: &Memory) {
    writeln!(out, "  (defmemory {}", memory.name).unwrap();
    property_atom(out, 2, "kind", &memory.kind);
    writeln!(out, "    (size-bytes {})", memory.size_bytes).unwrap();
    property_u32(out, 2, "ports", memory.ports);
    property_u32(out, 2, "latency-cycles", memory.latency_cycles);
    // Emitted only when declared: a scratchpad has no line size, and a round
    // trip that invented one would make every memory a cache.
    if memory.line_bytes != 0 {
        property_u32(out, 2, "line-bytes", memory.line_bytes);
    }
    if memory.ways != 0 {
        property_u32(out, 2, "ways", memory.ways);
    }
    property_u32(out, 2, "width-bits", memory.width_bits);
    property_u32(out, 2, "banks", memory.banks);
    property_atoms(out, 2, "attributes", &memory.attributes);
    crate::memsys::emit_lisp_policy(out, memory);
    close_form(out, 1);
}

fn emit_tile(out: &mut String, tile: &Tile) {
    writeln!(out, "  (deftile {}", tile.name).unwrap();
    property_atoms(out, 2, "cores", &tile.cores);
    property_atoms(out, 2, "accelerators", &tile.accelerators);
    property_atoms(out, 2, "memories", &tile.memories);
    property_atom(out, 2, "interconnect", &tile.interconnect);
    close_form(out, 1);
}

fn property_u32(out: &mut String, depth: usize, name: &str, value: u32) {
    writeln!(out, "{}({name} {value})", "  ".repeat(depth)).unwrap();
}

fn property_atom(out: &mut String, depth: usize, name: &str, value: &str) {
    writeln!(out, "{}({name} {value})", "  ".repeat(depth)).unwrap();
}

fn property_atom_if(out: &mut String, depth: usize, name: &str, value: &str) {
    if !value.is_empty() {
        property_atom(out, depth, name, value);
    }
}

fn property_string(out: &mut String, depth: usize, name: &str, value: &str) {
    writeln!(out, "{}({name} {})", "  ".repeat(depth), quote(value)).unwrap();
}

fn property_atoms(out: &mut String, depth: usize, name: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    writeln!(out, "{}({name} {})", "  ".repeat(depth), values.join(" ")).unwrap();
}

fn property_strings(out: &mut String, depth: usize, name: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    let values = values
        .iter()
        .map(|value| quote(value))
        .collect::<Vec<_>>()
        .join(" ");
    writeln!(out, "{}({name} {values})", "  ".repeat(depth)).unwrap();
}

fn close_form(out: &mut String, depth: usize) {
    writeln!(out, "{})", "  ".repeat(depth)).unwrap();
}

fn quote(value: &str) -> String {
    let mut out = String::from("\"");
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{parse_document, validate_document};

    #[test]
    fn canonical_lisp_roundtrips_complete_documents() {
        for source in [
            include_str!("../../examples/rvmt_xpce.axisl"),
            include_str!("../../examples/personality_composition.axisl"),
        ] {
            let original = parse_document(source).expect("parse document");
            validate_document(&original).expect("validate document");
            let lisp = emit_lisp(&original);
            let roundtripped = parse_document(&lisp).expect("parse emitted Lisp");
            validate_document(&roundtripped).expect("validate emitted Lisp");
            assert_eq!(roundtripped, original);
            assert_eq!(emit_lisp(&roundtripped), lisp);
        }
    }

    #[test]
    fn canonical_lisp_roundtrips_aarch64_typed_semantics() {
        let mut original =
            parse_document(include_str!("../../examples/aarch64_translation_seed.axisl"))
                .expect("parse AArch64 seed");
        validate_document(&original).expect("validate AArch64 seed");
        let lisp_source = emit_lisp(&original);
        assert!(lisp_source.contains("(behavior"));
        assert!(lisp_source.contains("(requires (a64-shifted-reg i64 shift imm6))"));
        assert!(lisp_source.contains("(requires (and (< immr 32) (< imms 32)))"));

        let mut roundtripped = parse_document(&lisp_source).expect("parse emitted AArch64 Lisp");
        validate_document(&roundtripped).expect("validate emitted AArch64 Lisp");

        // `effects` is a diagnostic source string, and emitting Lisp
        // canonicalises it: a `setreg` comes back with its width written out
        // and an `atomic_store` without the ordering that was its default.
        // Neither changes what the instruction does, which is why the typed
        // behavior is what has to survive the round trip byte for byte.
        for (before, after) in original
            .instructions
            .iter_mut()
            .zip(&mut roundtripped.instructions)
        {
            assert_eq!(after.behavior, before.behavior);
            assert_eq!(after.decode_constraint, before.decode_constraint);
            after.effects.clone_from(&before.effects);
        }
        assert_eq!(roundtripped, original);
    }
}
