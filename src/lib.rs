pub mod ast;
pub mod capsule;
pub mod decode_constraint;
pub mod effects;
pub mod ffi;
pub mod emit;
pub mod hw;
pub mod hw_units;
pub mod interchange;
pub mod ir;
pub mod layout;
pub mod lifter;
pub mod lisp;
pub mod loops;
pub mod memsys;
pub mod optisynth;
pub mod parser;
pub mod scalable;
pub mod semantics;
pub mod simd;
pub mod simt;
pub mod timing;
pub mod validate;

pub use ast::*;
pub use parser::parse_frontend_document;
pub use emit::{
    emit_accelerator_descriptor_manifests_json, emit_adl_coupling_manifest_json,
    emit_adl_topology_manifest_json, emit_aha_json, emit_asm_disasm_json,
    emit_bundle_manifest_json, emit_decode_c, emit_pack_abi_c, emit_pack_asm_c, emit_pack_decode_c, emit_pack_disasm_c, emit_pack_jit_c, emit_pack_sim_c, emit_pack_simt_c, emit_pack_simt_h, emit_pack_z3_c, emit_stencil_ll, emit_symbolic_python, emit_pack_exec_c, emit_pack_sym_c, emit_pack_lift_c, emit_decode_table_json,
    emit_encode_c, emit_hw_json, emit_hw_json_at, emit_hw_json_planned, emit_hw_plan,
    emit_hw_plan_at, emit_hw_pyrtl, emit_hw_pyrtl_at, emit_hw_smt2_at, emit_hw_effect_json_at,
    emit_hw_effect_pyrtl_at,
    emit_hw_pyrtl_planned, emit_hw_smt2, emit_hw_smt2_planned,
    emit_encode_table_json, emit_exec_c, emit_exec_python, emit_exec_rust, emit_golden_python,
    emit_intrinsics, emit_json, emit_lift_c, emit_lift_python, emit_lift_rust,
    emit_lift_table_json, emit_lisp, emit_llvm_intrinsics, emit_llvm_ir, emit_llvm_patterns, emit_llvm_target,
    emit_mode_legality_manifest_json, emit_packet_manifest_json, emit_pyrtl, emit_python,
    emit_fabric_manifest_json, emit_mapping_manifest_json, emit_vliw_itinerary_json,
    emit_roundtrip_tests_json,
    emit_rvmt_json, emit_rvmt_launch_templates_json, emit_rvmt_rcore_region_manifest_json,
    emit_semantics_c, emit_semantics_json, emit_semantics_rust, emit_capability_json, emit_regfile_json, emit_sim_c, emit_uarch_json, emit_smt2, emit_smt_axioms,
    emit_state_capsule_manifest_json, emit_tablegen, emit_translation_map_json,
    emit_translation_python,
};
pub use layout::{
    builtin_formats, resolve_layout, InstructionLayout, LayoutFixedField, LayoutOperandField,
};
pub use optisynth::optisynth_formal_semantics;
pub use parser::{parse_document, ParseError};
pub use semantics::{
    parse_formal_semantics, validate_formal_semantics, SemanticError, SemanticExpr,
};
pub use validate::{validate_aha_export, validate_document, ValidationError};

pub fn compile_json(source: &str) -> Result<String, String> {
    let document = parse_document(source).map_err(|err| err.to_string())?;
    validate_document(&document).map_err(|err| err.to_string())?;
    Ok(emit_json(&document))
}

pub fn compile_python(source: &str) -> Result<String, String> {
    let document = parse_document(source).map_err(|err| err.to_string())?;
    validate_document(&document).map_err(|err| err.to_string())?;
    Ok(emit_python(&document))
}
