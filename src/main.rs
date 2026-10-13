use std::env;
use std::fs;
use std::path::Path;
use std::process;

use axis_adl::{
    emit_accelerator_descriptor_manifests_json, emit_adl_coupling_manifest_json,
    emit_adl_topology_manifest_json, emit_aha_json, emit_asm_disasm_json,
    emit_bundle_manifest_json, emit_decode_c, emit_pack_abi_c, emit_pack_asm_c, emit_pack_decode_c, emit_pack_disasm_c, emit_pack_jit_c, emit_pack_sim_c, emit_pack_simt_c, emit_pack_simt_h, emit_pack_z3_c, emit_stencil_ll, emit_symbolic_python, emit_pack_exec_c, emit_pack_sym_c, emit_pack_lift_c, emit_decode_table_json,
    emit_encode_c, emit_hw_json_at, emit_hw_plan_at, emit_hw_pyrtl_at, emit_hw_smt2_at,
    emit_encode_table_json, emit_exec_c, emit_exec_python, emit_exec_rust, emit_golden_python,
    emit_intrinsics, emit_json, emit_lift_c, emit_lift_python, emit_lift_rust,
    emit_lift_table_json, emit_lisp, emit_llvm_intrinsics, emit_llvm_ir, emit_llvm_patterns, emit_llvm_target,
    emit_mode_legality_manifest_json, emit_packet_manifest_json, emit_pyrtl, emit_python, emit_roundtrip_tests_json,
    emit_fabric_manifest_json, emit_mapping_manifest_json, emit_vliw_itinerary_json,
    emit_rvmt_json, emit_rvmt_launch_templates_json, emit_rvmt_rcore_region_manifest_json,
    emit_semantics_c, emit_semantics_json, emit_semantics_rust, emit_capability_json, emit_regfile_json, emit_sim_c, emit_smt2, emit_smt_axioms,
    emit_state_capsule_manifest_json, emit_tablegen, emit_translation_map_json,
    emit_translation_python, emit_uarch_json, validate_aha_export, validate_document,
};

fn main() {
    if let Err(message) = run() {
        eprintln!("{message}");
        process::exit(1);
    }
}

/// What this binary is, for a consumer holding an artifact or running a pinned
/// executable.
///
/// A description that names a form the binary predates fails with "unsupported
/// axis-module form", and a description using an operator the binary predates
/// fails with "unsupported formal_semantics operator" -- both of which read as
/// defects in AXIS or in the example. `pce/docs/AXISMINE_BINARY_REGION_MINING.md`
/// reported two of them and attributed one to a disagreement between components
/// that was really a match arm inside the function reporting the error. The
/// binary was five days old. One line of output is what that cost.
fn version() -> String {
    format!(
        "axis {} ({})\n",
        env!("CARGO_PKG_VERSION"),
        option_env!("AXIS_BUILD").unwrap_or("unstamped")
    )
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    if command == "--version" || command == "-V" || command == "version" {
        print!("{}", version());
        return Ok(());
    }
    let input = args.next().ok_or_else(usage)?;
    let mut output: Option<String> = None;
    let mut binary: Option<String> = None;
    let mut addr: Option<u64> = None;
    let mut isa: Option<String> = None;
    let mut hw_plan: Option<String> = None;
    let mut core: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--core" => {
                core = Some(args.next().ok_or_else(|| "missing name after --core".to_string())?);
            }
            "--hw-plan" => {
                let path = args
                    .next()
                    .ok_or_else(|| "missing path after --hw-plan".to_string())?;
                hw_plan = Some(
                    fs::read_to_string(&path)
                        .map_err(|err| format!("failed to read `{path}`: {err}"))?,
                );
            }
            "--binary" => {
                binary = Some(
                    args.next()
                        .ok_or_else(|| "missing path after --binary".to_string())?,
                );
            }
            "--addr" => {
                let text = args
                    .next()
                    .ok_or_else(|| "missing address after --addr".to_string())?;
                let trimmed = text.trim_start_matches("0x");
                addr = Some(
                    u64::from_str_radix(trimmed, 16)
                        .map_err(|_| format!("not a hex address: `{text}`"))?,
                );
            }
            "--isa" => {
                isa = Some(
                    args.next()
                        .ok_or_else(|| "missing name after --isa".to_string())?,
                );
            }
            "-o" | "--output" => {
                output = Some(
                    args.next()
                        .ok_or_else(|| "missing output path after -o".to_string())?,
                );
            }
            _ => return Err(format!("unknown argument `{arg}`\n{}", usage())),
        }
    }

    let source =
        fs::read_to_string(&input).map_err(|err| format!("failed to read `{input}`: {err}"))?;
    let document = axis_adl::parse_document(&source).map_err(|err| err.to_string())?;
    validate_document(&document).map_err(|err| err.to_string())?;
    // `--core NAME`: the description as that core sees it. Every emitter
    // below then reads that core's latencies and units, because they are the
    // instructions' in the document it is given, and the hardware planner
    // plans at that core's cycle.
    let mut cycle: Option<f64> = None;
    let document = match &core {
        Some(name) => {
            let view = axis_adl::timing::as_seen_by(&document, name)?;
            cycle = view.cores.first().filter(|core| core.cycle_gates != 0)
                .map(|core| f64::from(core.cycle_gates));
            view
        }
        None => document,
    };

    if command == "emit-bundle" {
        let output = output.ok_or_else(|| "emit-bundle requires -o <output_dir>".to_string())?;
        write_bundle(&output, &document)?;
        return Ok(());
    }

    if command == "lift-support" {
        let text = axis_adl::lifter::describe_support(&document);
        if let Some(output) = output {
            ensure_parent(&output)?;
            fs::write(&output, text)
                .map_err(|err| format!("failed to write `{output}`: {err}"))?;
        } else {
            print!("{text}");
        }
        return Ok(());
    }

    if command == "lift-blocks" || command == "lift-llvm" {
        let path = binary
            .ok_or_else(|| format!("{command} requires --binary <file>"))?;
        let bytes = fs::read(&path)
            .map_err(|err| format!("failed to read `{path}`: {err}"))?;
        let table = axis_adl::lifter::DecodeTable::new(&document);
        let region = axis_adl::lifter::decode_region(
            &table, &bytes, addr.unwrap_or(0), isa.as_deref());
        let text = if command == "lift-llvm" {
            axis_adl::lifter::lift_region(&document, &region, isa.as_deref())
                .map_err(|err| err.to_string())?
        } else {
            axis_adl::lifter::describe_region(&region)
        };
        if let Some(output) = output {
            ensure_parent(&output)?;
            fs::write(&output, text)
                .map_err(|err| format!("failed to write `{output}`: {err}"))?;
        } else {
            print!("{text}");
        }
        return Ok(());
    }

    let rendered = match command.as_str() {
        "check" => {
            if output.is_some() {
                return Err("check does not accept -o".to_string());
            }
            println!("ok: {input}");
            return Ok(());
        }
        "emit-bundle-manifest" => emit_bundle_manifest_json(&document),
        "emit-json" => emit_json(&document),
        "emit-rvmt-json" => emit_rvmt_json(&document),
        "emit-decode-json" => emit_decode_table_json(&document),
        "emit-encode-json" => emit_encode_table_json(&document),
        "emit-encode-c" => emit_encode_c(&document),
        "emit-roundtrip-json" => emit_roundtrip_tests_json(&document),
        "emit-decode-c" => emit_decode_c(&document),
        "emit-pack-abi-c" => emit_pack_abi_c(&document),
        "emit-pack-decode-c" => emit_pack_decode_c(&document),
        "emit-pack-asm-c" => emit_pack_asm_c(&document),
        "emit-pack-disasm-c" => emit_pack_disasm_c(&document),
        "emit-pack-jit-c" => emit_pack_jit_c(&document),
        "emit-pack-sim-c" => emit_pack_sim_c(&document),
        "emit-pack-simt-c" => emit_pack_simt_c(&document),
        "emit-pack-simt-h" => emit_pack_simt_h(&document),
        "emit-pack-z3-c" => emit_pack_z3_c(&document),
        "emit-stencil-ll" => emit_stencil_ll(&document),
        "emit-symbolic-python" => emit_symbolic_python(&document),
        "emit-pack-lift-c" => emit_pack_lift_c(&document),
        "emit-pack-exec-c" => emit_pack_exec_c(&document),
        "emit-pack-sym-c" => emit_pack_sym_c(&document),
        "emit-asm-disasm-json" => emit_asm_disasm_json(&document),
        "emit-capsule-json" => emit_state_capsule_manifest_json(&document),
        "emit-legality-json" => emit_mode_legality_manifest_json(&document),
        "emit-packet-json" => emit_packet_manifest_json(&document),
        "emit-vliw-itinerary" => emit_vliw_itinerary_json(&document),
        "emit-fabric-json" => emit_fabric_manifest_json(&document),
        "emit-mapping-json" => emit_mapping_manifest_json(&document),
        "emit-semantics-json" => emit_semantics_json(&document),
        "emit-semantics-c" => emit_semantics_c(&document),
        "emit-semantics-rust" => emit_semantics_rust(&document),
        "emit-lift-json" => emit_lift_table_json(&document),
        // The *frontend* document, before the semantic expansions. `emit-lisp`
        // writes a form a corpus could be replaced by, and a replacement has to
        // be a source somebody could keep: lane instantiation turns 1060 lines
        // of `sve.axisl` into 14187 that the surface cannot even express.
        // Re-parsing what this writes runs the expansions again and lands on
        // the same document, which is what `lisp_roundtrip.py` requires.
        "emit-lisp" => emit_lisp(
            &axis_adl::parse_frontend_document(&source).map_err(|err| err.to_string())?,
        ),
        "emit-translation-json" => emit_translation_map_json(&document),
        "emit-translation-python" => emit_translation_python(&document),
        "emit-lift-python" => emit_lift_python(&document),
        "emit-lift-c" => emit_lift_c(&document),
        "emit-lift-rust" => emit_lift_rust(&document),
        "emit-exec-python" => emit_exec_python(&document),
        "emit-exec-c" => emit_exec_c(&document),
        "emit-exec-rust" => emit_exec_rust(&document),
        "emit-sim-c" => emit_sim_c(&document),
        "emit-llvm-ir" => emit_llvm_ir(&document),
        "emit-smt2" => emit_smt2(&document),
        "emit-smt-axioms" => emit_smt_axioms(&document),
        "emit-capability-json" => emit_capability_json(&document),
        "emit-regfile-json" => emit_regfile_json(&document),
        "emit-uarch-json" => emit_uarch_json(&document),
        "emit-memsys-json" => axis_adl::memsys::emit_memsys_json(&document),
        "emit-golden-python" => emit_golden_python(&document),
        "emit-python" => emit_python(&document),
        "emit-pyrtl" => emit_pyrtl(&document),
        // The units are AXIS's own unless `--hw-plan` proposes others. A
        // proposed plan can make them large or slow and cannot make them
        // compute anything else; one that would is refused here, by name.
        "emit-hw-pyrtl" => emit_hw_pyrtl_at(&document, hw_plan.as_deref(), cycle)?,
        "emit-hw-json" => emit_hw_json_at(&document, hw_plan.as_deref(), cycle)?,
        "emit-hw-smt2" => emit_hw_smt2_at(&document, hw_plan.as_deref(), cycle)?,
        "emit-hw-plan" => emit_hw_plan_at(&document, cycle),
        // Units with instructions stated as effects in them (§3.5 of
        // docs/hardware_design.md): beside the artifacts above, not in them.
        "emit-hw-effect-json" => axis_adl::emit_hw_effect_json_at(&document, cycle)?,
        "emit-hw-effect-pyrtl" => axis_adl::emit_hw_effect_pyrtl_at(&document, cycle)?,
        "emit-aha-json" => {
            validate_aha_export(&document).map_err(|err| err.to_string())?;
            emit_aha_json(&document)
        }
        "emit-tablegen" => emit_tablegen(&document),
        "emit-intrinsics" => emit_intrinsics(&document),
        "emit-llvm-intrinsics" => emit_llvm_intrinsics(&document),
        "emit-llvm-patterns" => emit_llvm_patterns(&document),
        "emit-llvm-target" => emit_llvm_target(&document),
        _ => return Err(format!("unknown command `{command}`\n{}", usage())),
    };

    if let Some(output) = output {
        ensure_parent(&output)?;
        fs::write(&output, rendered).map_err(|err| format!("failed to write `{output}`: {err}"))?;
    } else {
        print!("{rendered}");
    }

    Ok(())
}

fn ensure_parent(path: &str) -> Result<(), String> {
    if let Some(parent) = Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("failed to create `{}`: {err}", parent.display()))?;
        }
    }
    Ok(())
}

fn write_bundle(output_dir: &str, document: &axis_adl::Document) -> Result<(), String> {
    validate_aha_export(document).map_err(|err| err.to_string())?;
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("failed to create `{output_dir}`: {err}"))?;
    let outputs = [
        ("bundle_manifest.json", emit_bundle_manifest_json(document)),
        ("manifest.json", emit_json(document)),
        ("rvmt_extension_manifest.json", emit_rvmt_json(document)),
        ("decode_table.json", emit_decode_table_json(document)),
        ("axis_encode_table.json", emit_encode_table_json(document)),
        ("axis_encode.h", emit_encode_c(document)),
        (
            "axis_roundtrip_tests.json",
            emit_roundtrip_tests_json(document),
        ),
        ("axis_decode.h", emit_decode_c(document)),
        // ⚠️ The PACK's decoder, not the old flat ABI. A script binding the
        // decoder needs a translation unit with symbols in it, and the one
        // that used to be here named them the same for every description --
        // so two architectures could not be loaded into one process. This one
        // exports a single symbol named after the architecture, and keeps
        // everything else `static`.
        ("axis_pack.h", emit_pack_abi_c(document)),
        ("axis_decode_pack.c", emit_pack_decode_c(document)),
        ("asm_disasm.json", emit_asm_disasm_json(document)),
        ("semantics.json", emit_semantics_json(document)),
        ("semantics.smt2", emit_smt2(document)),
        // The same semantics in the shape a verifier reasoning over intrinsic
        // *calls* needs (ADL.2). In the bundle rather than beside it, because
        // the bundle is the surface a consumer already loads by fixed name.
        ("intrinsic_axioms.smt2", emit_smt_axioms(document)),
        // What each instruction can be expressed as, and the named reason
        // where it cannot -- so a consumer filters before it proposes rather
        // than failing closed one instruction at a time.
        ("capability_manifest.json", emit_capability_json(document)),
        ("aha_instructions.json", emit_aha_json(document)),
        (
            "adl_topology_manifest.json",
            emit_adl_topology_manifest_json(document),
        ),
        (
            "accelerator_descriptor_manifests.json",
            emit_accelerator_descriptor_manifests_json(document),
        ),
        (
            "adl_coupling_manifest.json",
            emit_adl_coupling_manifest_json(document),
        ),
        (
            "rvmt_launch_templates.json",
            emit_rvmt_launch_templates_json(document),
        ),
        (
            "rvmt_rcore_region_manifest.json",
            emit_rvmt_rcore_region_manifest_json(document),
        ),
        ("instructions.td", emit_tablegen(document)),
        ("intrinsics.h", emit_intrinsics(document)),
        ("axis_intrinsics.td", emit_llvm_intrinsics(document)),
        ("axis_patterns.td", emit_llvm_patterns(document)),
        ("golden_model.py", emit_golden_python(document)),
        ("axis_semantics.h", emit_semantics_c(document)),
        ("axis_semantics.rs", emit_semantics_rust(document)),
        ("axis_semantics.ll", emit_llvm_ir(document)),
        ("axis_lift_table.json", emit_lift_table_json(document)),
        ("axis_lift.py", emit_lift_python(document)),
        ("axis_lift.h", emit_lift_c(document)),
        ("axis_lift.rs", emit_lift_rust(document)),
        ("axis_exec.py", emit_exec_python(document)),
        ("axis_exec.h", emit_exec_c(document)),
        ("axis_exec.rs", emit_exec_rust(document)),
        ("axis_sim.h", emit_sim_c(document)),
        ("pyrtl_semantics.py", emit_pyrtl(document)),
    ];
    for (name, contents) in outputs {
        let path = Path::new(output_dir).join(name);
        fs::write(&path, contents)
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
    }
    // Personality-free documents keep their bundle surface byte-identical:
    // the capsule manifest exists only when personalities are declared.
    if !document.personalities.is_empty() {
        let path = Path::new(output_dir).join("state_capsule_manifest.json");
        fs::write(&path, emit_state_capsule_manifest_json(document))
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
    }
    // Likewise, the legality manifest exists only when a mode is declared.
    if !document.modes.is_empty() {
        let path = Path::new(output_dir).join("mode_legality_manifest.json");
        fs::write(&path, emit_mode_legality_manifest_json(document))
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
    }
    // And the issue-packet manifest only when a packet is declared, so a
    // single-issue document's bundle stays byte-identical to the one it
    // produced before packets existed.
    if !document.fabrics.is_empty() {
        let path = Path::new(output_dir).join("fabric_manifest.json");
        fs::write(&path, emit_fabric_manifest_json(document))
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
    }
    if !document.mappings.is_empty() {
        let path = Path::new(output_dir).join("mapping_manifest.json");
        fs::write(&path, emit_mapping_manifest_json(document))
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
    }
    if !document.packets.is_empty() {
        let path = Path::new(output_dir).join("packet_manifest.json");
        fs::write(&path, emit_packet_manifest_json(document))
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
        // The schedule the compiler reads, beside the encoding the decoder
        // reads, from one slot resolution.
        let path = Path::new(output_dir).join("packet_schedule_manifest.json");
        fs::write(&path, emit_vliw_itinerary_json(document))
            .map_err(|err| format!("failed to write `{}`: {err}", path.display()))?;
    }
    Ok(())
}

fn usage() -> String {
    "usage: axis <--version|check|emit-lisp|emit-bundle-manifest|emit-json|emit-rvmt-json|emit-decode-json|emit-encode-json|emit-encode-c|emit-roundtrip-json|emit-decode-c|emit-pack-abi-c|emit-pack-decode-c|emit-pack-asm-c|emit-pack-disasm-c|emit-pack-jit-c|emit-pack-sim-c|emit-pack-z3-c|emit-stencil-ll|emit-symbolic-python|emit-pack-lift-c|emit-pack-exec-c|emit-pack-sym-c|emit-asm-disasm-json|emit-capsule-json|emit-legality-json|emit-packet-json|emit-vliw-itinerary|emit-fabric-json|emit-mapping-json|emit-semantics-json|emit-semantics-c|emit-semantics-rust|emit-lift-json|emit-translation-json|emit-translation-python|emit-lift-python|emit-lift-c|emit-lift-rust|emit-exec-python|emit-exec-c|emit-exec-rust|emit-sim-c|emit-llvm-ir|emit-smt2|emit-smt-axioms|emit-capability-json|emit-regfile-json|emit-uarch-json|emit-memsys-json|emit-python|emit-golden-python|emit-pyrtl|emit-hw-pyrtl|emit-hw-json|emit-hw-smt2|emit-hw-plan|emit-hw-effect-json|emit-hw-effect-pyrtl|emit-aha-json|emit-tablegen|emit-intrinsics|emit-llvm-intrinsics|emit-llvm-patterns|emit-llvm-target|emit-bundle> <input.axisl> [-o output]".to_string()
}
