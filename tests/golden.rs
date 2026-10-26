use std::collections::BTreeSet;

use axis_adl::{
    emit_accelerator_descriptor_manifests_json, emit_adl_coupling_manifest_json,
    emit_adl_topology_manifest_json, emit_aha_json, emit_asm_disasm_json,
    emit_bundle_manifest_json, emit_decode_c, emit_decode_table_json, emit_encode_c,
    emit_encode_table_json, emit_exec_c, emit_exec_python, emit_exec_rust, emit_golden_python,
    emit_intrinsics, emit_json, emit_lift_c, emit_lift_python, emit_lift_rust,
    emit_lift_table_json, emit_lisp, emit_llvm_intrinsics, emit_llvm_ir, emit_llvm_patterns,
    emit_llvm_target,
    emit_mode_legality_manifest_json, emit_packet_manifest_json, emit_pyrtl, emit_python,
    emit_roundtrip_tests_json,
    emit_rvmt_json, emit_rvmt_launch_templates_json, emit_rvmt_rcore_region_manifest_json,
    emit_semantics_c, emit_semantics_json, emit_semantics_rust, emit_sim_c, emit_smt2,
    emit_state_capsule_manifest_json, emit_tablegen, emit_translation_map_json,
    emit_translation_python, parse_document, validate_aha_export, validate_document,
};

#[test]
fn rvmt_example_emits_stable_manifest_surface() {
    let source = include_str!("../examples/xpce_manifest.axisl");
    let document = parse_document(source).expect("parse example");
    validate_document(&document).expect("validate example");
    let json = emit_json(&document);

    assert!(json.contains("\"schema\": \"axis.manifest.v1\""));
    assert!(json.contains("\"target\": \"rvmt\""));
    assert!(json.contains("\"decode_key\""));
    assert!(json.contains("\"opcode\": 11"));
    assert!(json.contains("\"semantics\": \"rd = load_tls(rs1 + imm)\""));
    assert!(json.contains("\"cost_model\""));
    assert!(json.contains("\"cores\""));
    assert!(json.contains("\"accelerators\""));
    assert!(json.contains("\"tiles\""));
}

#[test]
fn axis_isa_blocks_and_pyrtl_semantics_emit() {
    let source = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (defisa rv32_axis
    (base rv32im)
    (word-bits 32)
    (registers "x[32]:i32")
    (features m custom)
    (memory-model rvwmo)
    (endianness little)
  )

  (definstruction mac_sq
    (mnemonic MAC_SQ)
    (category custom)
    (format R)
    (opcode 11)
    (func3 4)
    (func7 5)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
    )
    (asm "mac_sq $rd, $rs1, $rs2")
    (semantics "rd = rs1 * rs2 + rs1")
    (formal (add i32 (mul i32 rs1 rs2) rs1))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
    (rationale "test")
  )

  (defcore rvmt0
    (kind rvmt)
    (threads 1)
    (implements rv32_axis)
  )

  (defaccelerator dot_unit
    (family nearasic)
    (descriptor-version 1)
    (descriptor-bytes 0)
    (mmio-base 0)
    (mmio-size 0)
    (target nearasic)
    (coupling queue_descriptor)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (ports
      (a input bits i32)
      (b input bits i32)
      (y output bits i32)
    )
    (semantics "y = a * b")
    (formal (mul i32 a b))
    (latency 1)
    (throughput 1.0)
  )

  (defmemory scratchpad
    (kind scratchpad)
    (size-bytes 4096)
    (ports 2)
    (latency-cycles 1)
    (width-bits 32)
    (banks 2)
    (attributes explicit)
  )

  (deftile tile0
    (cores rvmt0)
    (accelerators dot_unit)
    (memories scratchpad)
    (interconnect crossbar)
  )
)
    "#;
    let document = parse_document(source).expect("parse axis source");
    validate_document(&document).expect("validate axis source");

    let manifest = emit_json(&document);
    assert!(manifest.contains("\"isas\""));
    assert!(manifest.contains("\"implements\": \"rv32_axis\""));
    assert!(manifest.contains("\"ports\""));
    assert!(manifest.contains("\"memories\""));
    assert!(manifest.contains("\"size_bytes\": 4096"));
    assert!(manifest.contains("\"banks\": 2"));
    assert!(manifest.contains("\"formal_semantics\": \"(mul i32 a b)\""));
    assert!(manifest.contains("\"asm\": \"mac_sq $rd, $rs1, $rs2\""));

    let decode = emit_decode_table_json(&document);
    assert!(decode.contains("\"schema\": \"axis.decode-table.v1\""));
    assert!(decode.contains("\"mnemonic\": \"MAC_SQ\""));
    assert!(decode.contains("\"asm\": \"mac_sq $rd, $rs1, $rs2\""));
    assert!(decode.contains("\"match\": \"0x0a00400b\""));
    assert!(decode.contains("\"mask\": \"0xfe00707f\""));

    let encode = emit_encode_table_json(&document);
    assert!(encode.contains("\"schema\": \"axis.encode-table.v1\""));
    assert!(encode.contains("\"mnemonic\": \"MAC_SQ\""));
    assert!(encode.contains("\"base_value\": \"0x0a00400b\""));
    assert!(encode.contains("\"fixed_mask\": \"0xfe00707f\""));
    assert!(encode.contains("\"field\": \"rd\""));
    assert!(encode.contains("\"field\": \"rs1\""));
    assert!(encode.contains("\"field\": \"rs2\""));

    let encode_c = emit_encode_c(&document);
    assert!(encode_c.contains("typedef struct axis_encode_entry"));
    assert!(encode_c.contains("AXIS_ENCODE_OPERANDS_MAC_SQ"));
    assert!(encode_c.contains("0x0a00400bu"));
    assert!(encode_c.contains("axis_encode_by_index"));

    let roundtrip = emit_roundtrip_tests_json(&document);
    assert!(roundtrip.contains("\"schema\": \"axis.roundtrip-tests.v1\""));
    assert!(roundtrip.contains("\"mnemonic\": \"MAC_SQ\""));
    assert!(roundtrip.contains("\"encoded\": \"0x0a31408b\""));
    assert!(roundtrip.contains("\"matches\": true"));

    let decode_c = emit_decode_c(&document);
    assert!(decode_c.contains("typedef enum axis_insn_id"));
    assert!(decode_c.contains("AXIS_INSN_MAC_SQ"));
    assert!(decode_c.contains("0x0a00400bu"));
    assert!(decode_c.contains("0xfe00707fu"));
    assert!(decode_c.contains("static inline const axis_decode_entry *axis_decode(uint32_t insn)"));

    let asm_disasm = emit_asm_disasm_json(&document);
    assert!(asm_disasm.contains("\"schema\": \"axis.asm-disasm.v1\""));
    assert!(asm_disasm.contains("\"opcode_token\": \"mac_sq\""));
    assert!(asm_disasm.contains("\"asm_template\": \"mac_sq $rd, $rs1, $rs2\""));
    assert!(asm_disasm.contains("\"operand_print_order\": [\"rd\", \"rs1\", \"rs2\"]"));
    assert!(asm_disasm.contains("\"field\": \"rd\""));
    assert!(asm_disasm.contains("\"lsb\": 7"));
    assert!(asm_disasm.contains("\"field\": \"rs2\""));
    assert!(asm_disasm.contains("\"lsb\": 20"));

    let pyrtl = emit_pyrtl(&document);
    assert!(pyrtl.contains("AXIS_SCHEMA = \"axis.pyrtl-semantics.v1\""));
    assert!(pyrtl.contains("def build_mac_sq(rs1, rs2):"));
    assert!(pyrtl.contains("def build_dot_unit_behavior(a, b):"));
    assert!(pyrtl.contains("def build_dot_unit_module(prefix=\"dot_unit\"):"));
    assert!(pyrtl.contains("ports[\"a\"] = pyrtl.Input(32, f\"{prefix}_a\")"));
    assert!(pyrtl.contains("ports[\"y\"] <<= build_dot_unit_behavior(ports[\"a\"], ports[\"b\"])"));

    let semantics = emit_semantics_json(&document);
    assert!(semantics.contains("\"schema\": \"axis.semantics.v1\""));
    assert!(semantics.contains("\"op\": \"add\", \"type\": \"i32\""));
    assert!(semantics.contains("\"op\": \"mul\", \"type\": \"i32\""));
    assert!(semantics.contains("\"symbol\": \"rs1\""));
    assert!(semantics.contains("\"name\": \"dot_unit\""));

    let golden = emit_golden_python(&document);
    assert!(golden.contains("AXIS_SCHEMA = \"axis.golden-model.v1\""));
    assert!(golden.contains("def eval_mac_sq(rs1, rs2):"));
    assert!(golden.contains("def eval_dot_unit(a, b):"));
    assert!(golden.contains("return _eval_axis_expr(\"(mul i32 a b)\", env, 32)"));

    let smt2 = emit_smt2(&document);
    assert!(smt2.contains("(set-logic QF_BV)"));
    assert!(smt2.contains("(define-fun axis_instr_mac_sq"));
    assert!(smt2.contains("(define-fun axis_accel_dot_unit"));
    assert!(smt2.contains("(bvadd (bvmul rs1 rs2) rs1)"));
    assert!(smt2.contains("(bvmul a b)"));

    let bundle_manifest = emit_bundle_manifest_json(&document);
    assert!(bundle_manifest.contains("\"schema\": \"axis.bundle-manifest.v1\""));
    assert!(bundle_manifest.contains("\"generator\": \"axis\""));
    assert!(bundle_manifest.contains("\"instructions\": 1"));
    assert!(bundle_manifest.contains("\"accelerators\": 1"));
    assert!(bundle_manifest.contains("\"path\": \"manifest.json\""));
    assert!(bundle_manifest.contains("\"schema\": \"axis.manifest.v1\""));
    assert!(bundle_manifest.contains("\"path\": \"axis_encode_table.json\""));
    assert!(bundle_manifest.contains("\"schema\": \"axis.encode-table.v1\""));
    assert!(bundle_manifest.contains("\"path\": \"axis_encode.h\""));
    assert!(bundle_manifest.contains("\"schema\": \"axis.encode-c.v1\""));
    assert!(bundle_manifest.contains("\"path\": \"axis_roundtrip_tests.json\""));
    assert!(bundle_manifest.contains("\"schema\": \"axis.roundtrip-tests.v1\""));
    assert!(bundle_manifest.contains("\"path\": \"pyrtl_semantics.py\""));
    assert!(bundle_manifest.contains("\"schema\": \"axis.pyrtl-semantics.v1\""));
}

#[test]
fn aarch64_seed_uses_named_encoding_space_and_lifts_i64_semantics() {
    let source = include_str!("../examples/aarch64_translation_seed.axisl");
    let document = parse_document(source).expect("parse AArch64 seed");
    validate_document(&document).expect("validate AArch64 seed");

    assert_eq!(document.instructions[0].isa, "aarch64_base");
    assert_eq!(document.instructions[0].opcode, 0);

    let manifest = emit_json(&document);
    assert!(manifest.contains("\"base\": \"armv8-a\""));
    assert!(manifest.contains("\"role\": \"source\""));
    assert!(manifest.contains("\"role\": \"target\""));
    assert!(manifest.contains("\"isa\": \"aarch64_base\""));
    assert!(manifest.contains("\"formal_semantics\": \"(add i64 rn rm)\""));

    let decode = emit_decode_table_json(&document);
    assert!(decode.contains("\"mnemonic\": \"ADD_X_SHIFT0\""));
    assert!(decode.contains("\"match\": \"0x8b000000\""));
    assert!(decode.contains("\"mask\": \"0xff200000\""));
    assert!(decode.contains("\"mnemonic\": \"SUB_X_SHIFT0\""));
    assert!(decode.contains("\"match\": \"0xcb000000\""));
    assert!(decode.contains("\"mnemonic\": \"ADDS_X_SHIFT0\""));
    assert!(decode.contains("\"match\": \"0xab000000\""));
    assert!(decode.contains("\"mnemonic\": \"SUBS_X_SHIFT0\""));
    assert!(decode.contains("\"match\": \"0xeb000000\""));
    assert!(decode.contains("\"mnemonic\": \"ADD_X_EXT\""));
    assert!(decode.contains("\"match\": \"0x8b200000\""));
    assert!(decode.contains("\"mnemonic\": \"SUBS_W_EXT\""));
    assert!(decode.contains("\"match\": \"0x6b200000\""));
    assert!(decode.contains("\"mnemonic\": \"B_COND\""));
    assert!(decode.contains("\"match\": \"0x54000000\""));
    assert!(decode.contains("\"mnemonic\": \"LDRB_W_UNSIGNED\""));
    assert!(decode.contains("\"match\": \"0x39400000\""));
    assert!(decode.contains("\"mnemonic\": \"LDRSW_X_UNSIGNED\""));
    assert!(decode.contains("\"match\": \"0xb9800000\""));
    assert!(decode.contains("\"mnemonic\": \"LDR_X_REG_LSL3\""));
    assert!(decode.contains("\"match\": \"0xf8600800\""));
    assert!(decode.contains("\"mnemonic\": \"STR_X_REG_LSL3\""));
    assert!(decode.contains("\"match\": \"0xf8200800\""));
    assert!(decode.contains("\"mnemonic\": \"LDP_X_OFFSET\""));
    assert!(decode.contains("\"match\": \"0xa9400000\""));
    assert!(decode.contains("\"mnemonic\": \"STP_X_OFFSET\""));
    assert!(decode.contains("\"match\": \"0xa9000000\""));
    assert!(decode.contains("\"mnemonic\": \"LDP_X_POST\""));
    assert!(decode.contains("\"match\": \"0xa8c00000\""));
    assert!(decode.contains("\"mnemonic\": \"STP_X_PRE\""));
    assert!(decode.contains("\"match\": \"0xa9800000\""));
    assert!(decode.contains("\"mnemonic\": \"LDP_W_PRE\""));
    assert!(decode.contains("\"match\": \"0x29c00000\""));
    assert!(decode.contains("\"mnemonic\": \"STP_W_POST\""));
    assert!(decode.contains("\"match\": \"0x28800000\""));
    assert!(decode.contains("\"mnemonic\": \"LDP_X_PRE\""));
    assert!(decode.contains("\"match\": \"0xa9c00000\""));
    assert!(decode.contains("\"mnemonic\": \"STP_X_POST\""));
    assert!(decode.contains("\"match\": \"0xa8800000\""));
    assert!(decode.contains("\"mnemonic\": \"LDXR_W\""));
    assert!(decode.contains("\"match\": \"0x885f7c00\""));
    assert!(decode.contains("\"mnemonic\": \"LDXR_X\""));
    assert!(decode.contains("\"match\": \"0xc85f7c00\""));
    assert!(decode.contains("\"mnemonic\": \"STXR_W\""));
    assert!(decode.contains("\"match\": \"0x88007c00\""));
    assert!(decode.contains("\"mnemonic\": \"STXR_X\""));
    assert!(decode.contains("\"match\": \"0xc8007c00\""));
    assert!(decode.contains("\"mnemonic\": \"LDAXR_W\""));
    assert!(decode.contains("\"match\": \"0x885ffc00\""));
    assert!(decode.contains("\"mnemonic\": \"LDAXR_X\""));
    assert!(decode.contains("\"match\": \"0xc85ffc00\""));
    assert!(decode.contains("\"mnemonic\": \"STLXR_W\""));
    assert!(decode.contains("\"match\": \"0x8800fc00\""));
    assert!(decode.contains("\"mnemonic\": \"STLXR_X\""));
    assert!(decode.contains("\"match\": \"0xc800fc00\""));
    assert!(decode.contains("\"mnemonic\": \"SWP_W\""));
    assert!(decode.contains("\"match\": \"0xb8208000\""));
    assert!(decode.contains("\"mnemonic\": \"SWP_X\""));
    assert!(decode.contains("\"match\": \"0xf8208000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPA_W\""));
    assert!(decode.contains("\"match\": \"0xb8a08000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPA_X\""));
    assert!(decode.contains("\"match\": \"0xf8a08000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPL_W\""));
    assert!(decode.contains("\"match\": \"0xb8608000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPL_X\""));
    assert!(decode.contains("\"match\": \"0xf8608000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPAL_W\""));
    assert!(decode.contains("\"match\": \"0xb8e08000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPAL_X\""));
    assert!(decode.contains("\"match\": \"0xf8e08000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPB\""));
    assert!(decode.contains("\"match\": \"0x38208000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPAB\""));
    assert!(decode.contains("\"match\": \"0x38a08000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPLB\""));
    assert!(decode.contains("\"match\": \"0x38608000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPALB\""));
    assert!(decode.contains("\"match\": \"0x38e08000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPH\""));
    assert!(decode.contains("\"match\": \"0x78208000\""));
    assert!(decode.contains("\"mnemonic\": \"SWPALH\""));
    assert!(decode.contains("\"match\": \"0x78e08000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADD_W\""));
    assert!(decode.contains("\"match\": \"0xb8200000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADD_X\""));
    assert!(decode.contains("\"match\": \"0xf8200000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDA_X\""));
    assert!(decode.contains("\"match\": \"0xf8a00000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDL_X\""));
    assert!(decode.contains("\"match\": \"0xf8600000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDAL_X\""));
    assert!(decode.contains("\"match\": \"0xf8e00000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDB\""));
    assert!(decode.contains("\"match\": \"0x38200000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDAB\""));
    assert!(decode.contains("\"match\": \"0x38a00000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDLB\""));
    assert!(decode.contains("\"match\": \"0x38600000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDALB\""));
    assert!(decode.contains("\"match\": \"0x38e00000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDH\""));
    assert!(decode.contains("\"match\": \"0x78200000\""));
    assert!(decode.contains("\"mnemonic\": \"LDADDALH\""));
    assert!(decode.contains("\"match\": \"0x78e00000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLR_W\""));
    assert!(decode.contains("\"match\": \"0xb8201000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLR_X\""));
    assert!(decode.contains("\"match\": \"0xf8201000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRA_W\""));
    assert!(decode.contains("\"match\": \"0xb8a01000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRA_X\""));
    assert!(decode.contains("\"match\": \"0xf8a01000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRL_W\""));
    assert!(decode.contains("\"match\": \"0xb8601000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRL_X\""));
    assert!(decode.contains("\"match\": \"0xf8601000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRAL_W\""));
    assert!(decode.contains("\"match\": \"0xb8e01000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRAL_X\""));
    assert!(decode.contains("\"match\": \"0xf8e01000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRB\""));
    assert!(decode.contains("\"match\": \"0x38201000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRAB\""));
    assert!(decode.contains("\"match\": \"0x38a01000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRLB\""));
    assert!(decode.contains("\"match\": \"0x38601000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRALB\""));
    assert!(decode.contains("\"match\": \"0x38e01000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRH\""));
    assert!(decode.contains("\"match\": \"0x78201000\""));
    assert!(decode.contains("\"mnemonic\": \"LDCLRALH\""));
    assert!(decode.contains("\"match\": \"0x78e01000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEOR_X\""));
    assert!(decode.contains("\"match\": \"0xf8202000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORA_X\""));
    assert!(decode.contains("\"match\": \"0xf8a02000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORL_X\""));
    assert!(decode.contains("\"match\": \"0xf8602000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORAL_X\""));
    assert!(decode.contains("\"match\": \"0xf8e02000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORB\""));
    assert!(decode.contains("\"match\": \"0x38202000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORAB\""));
    assert!(decode.contains("\"match\": \"0x38a02000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORLB\""));
    assert!(decode.contains("\"match\": \"0x38602000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORALB\""));
    assert!(decode.contains("\"match\": \"0x38e02000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORH\""));
    assert!(decode.contains("\"match\": \"0x78202000\""));
    assert!(decode.contains("\"mnemonic\": \"LDEORALH\""));
    assert!(decode.contains("\"match\": \"0x78e02000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSET_X\""));
    assert!(decode.contains("\"match\": \"0xf8203000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETA_X\""));
    assert!(decode.contains("\"match\": \"0xf8a03000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETL_X\""));
    assert!(decode.contains("\"match\": \"0xf8603000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETAL_X\""));
    assert!(decode.contains("\"match\": \"0xf8e03000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETB\""));
    assert!(decode.contains("\"match\": \"0x38203000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETAB\""));
    assert!(decode.contains("\"match\": \"0x38a03000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETLB\""));
    assert!(decode.contains("\"match\": \"0x38603000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETALB\""));
    assert!(decode.contains("\"match\": \"0x38e03000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETH\""));
    assert!(decode.contains("\"match\": \"0x78203000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSETALH\""));
    assert!(decode.contains("\"match\": \"0x78e03000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSMAXB\""));
    assert!(decode.contains("\"match\": \"0x38204000\""));
    assert!(decode.contains("\"mnemonic\": \"LDSMINAL_X\""));
    assert!(decode.contains("\"match\": \"0xf8e05000\""));
    assert!(decode.contains("\"mnemonic\": \"LDUMAXALH\""));
    assert!(decode.contains("\"match\": \"0x78e06000\""));
    assert!(decode.contains("\"mnemonic\": \"LDUMIN_W\""));
    assert!(decode.contains("\"match\": \"0xb8207000\""));
    assert!(decode.contains("\"mnemonic\": \"CASB\""));
    assert!(decode.contains("\"match\": \"0x08a07c00\""));
    assert!(decode.contains("\"mnemonic\": \"CASALB\""));
    assert!(decode.contains("\"match\": \"0x08e0fc00\""));
    assert!(decode.contains("\"mnemonic\": \"CASH\""));
    assert!(decode.contains("\"match\": \"0x48a07c00\""));
    assert!(decode.contains("\"mnemonic\": \"CASAL_W\""));
    assert!(decode.contains("\"match\": \"0x88e0fc00\""));
    assert!(decode.contains("\"mnemonic\": \"CASAL_X\""));
    assert!(decode.contains("\"match\": \"0xc8e0fc00\""));
    assert!(decode.contains("\"mnemonic\": \"ADR\""));
    assert!(decode.contains("\"match\": \"0x10000000\""));
    assert!(decode.contains("\"mnemonic\": \"ADRP\""));
    assert!(decode.contains("\"match\": \"0x90000000\""));
    assert!(decode.contains("\"mnemonic\": \"B\""));
    assert!(decode.contains("\"match\": \"0x14000000\""));
    assert!(decode.contains("\"mnemonic\": \"BL\""));
    assert!(decode.contains("\"match\": \"0x94000000\""));
    assert!(decode.contains("\"mnemonic\": \"BR\""));
    assert!(decode.contains("\"match\": \"0xd61f0000\""));
    assert!(decode.contains("\"mnemonic\": \"RET\""));
    assert!(decode.contains("\"match\": \"0xd65f0000\""));
    assert!(decode.contains("\"mnemonic\": \"BLR\""));
    assert!(decode.contains("\"match\": \"0xd63f0000\""));
    assert!(decode.contains("\"mnemonic\": \"CBZ_X\""));
    assert!(decode.contains("\"match\": \"0xb4000000\""));
    assert!(decode.contains("\"mnemonic\": \"CBNZ_W\""));
    assert!(decode.contains("\"match\": \"0x35000000\""));
    assert!(decode.contains("\"mnemonic\": \"TBZ_W\""));
    assert!(decode.contains("\"match\": \"0x36000000\""));
    assert!(decode.contains("\"mnemonic\": \"TBNZ_X_HIGH\""));
    assert!(decode.contains("\"match\": \"0xb7000000\""));
    assert!(decode.contains("\"mnemonic\": \"AND_X_SHIFTED\""));
    assert!(decode.contains("\"match\": \"0x8a000000\""));
    assert!(decode.contains("\"mnemonic\": \"ORR_W_SHIFTED\""));
    assert!(decode.contains("\"match\": \"0x2a000000\""));
    assert!(decode.contains("\"mnemonic\": \"LSLV_X\""));
    assert!(decode.contains("\"match\": \"0x9ac02000\""));
    assert!(decode.contains("\"mnemonic\": \"RORV_W\""));
    assert!(decode.contains("\"match\": \"0x1ac02c00\""));
    assert!(decode.contains("\"mnemonic\": \"MOVN_X\""));
    assert!(decode.contains("\"match\": \"0x92800000\""));
    assert!(decode.contains("\"mnemonic\": \"MOVZ_X\""));
    assert!(decode.contains("\"match\": \"0xd2800000\""));
    assert!(decode.contains("\"mnemonic\": \"MOVK_X\""));
    assert!(decode.contains("\"match\": \"0xf2800000\""));
    assert!(decode.contains("\"mnemonic\": \"AND_X_IMM\""));
    assert!(decode.contains("\"match\": \"0x92000000\""));
    assert!(decode.contains("\"mnemonic\": \"EOR_W_IMM\""));
    assert!(decode.contains("\"match\": \"0x52000000\""));
    assert!(decode.contains("\"mnemonic\": \"SBFM_X\""));
    assert!(decode.contains("\"match\": \"0x93400000\""));
    assert!(decode.contains("\"mnemonic\": \"BFM_X\""));
    assert!(decode.contains("\"match\": \"0xb3400000\""));
    assert!(decode.contains("\"mnemonic\": \"UBFM_X\""));
    assert!(decode.contains("\"match\": \"0xd3400000\""));
    assert!(decode.contains("\"mnemonic\": \"SBFM_W\""));
    assert!(decode.contains("\"match\": \"0x13000000\""));
    assert!(decode.contains("\"mnemonic\": \"BFM_W\""));
    assert!(decode.contains("\"match\": \"0x33000000\""));
    assert!(decode.contains("\"mnemonic\": \"UBFM_W\""));
    assert!(decode.contains("\"match\": \"0x53000000\""));
    assert!(decode.contains("\"mnemonic\": \"ANDS_X_SHIFTED\""));
    assert!(decode.contains("\"match\": \"0xea000000\""));
    assert!(decode.contains("\"mnemonic\": \"ANDS_X_IMM\""));
    assert!(decode.contains("\"match\": \"0xf2000000\""));
    assert!(decode.contains("\"mnemonic\": \"ADD_X_IMM_SP\""));
    assert!(decode.contains("\"match\": \"0x91000000\""));
    assert!(decode.contains("\"mnemonic\": \"SUBS_X_IMM\""));
    assert!(decode.contains("\"match\": \"0xf1000000\""));
    assert!(decode.contains("\"mnemonic\": \"ADDS_W_IMM\""));
    assert!(decode.contains("\"match\": \"0x31000000\""));

    let roundtrip = emit_roundtrip_tests_json(&document);
    assert!(roundtrip.contains("\"encoded\": \"0x8b831441\""));
    assert!(roundtrip.contains("\"encoded\": \"0xcb831441\""));
    assert!(!roundtrip.contains("\"reason\":"));

    let lift = emit_lift_table_json(&document);
    assert!(lift.contains("\"isa\": \"aarch64_base\""));
    assert!(lift.contains("\"op\": \"add\", \"type\": \"i64\""));
    assert!(lift.contains("\"width\": 64"));

    let lift_python = emit_lift_python(&document);
    assert!(lift_python.contains("\"state_width\": 64"));
    assert!(lift_python.contains(
        "\"kind\": \"setstate\", \"state\": \"nzcv\", \"width\": 4, \"value\": \"(a64_add_nzcv i64 rn (a64_shift_reg i64 rm shift imm6))\""
    ));
    assert!(lift_python.contains("\"guard\": \"(icmp_ne (a64_cond_holds i4 nzcv cond) 0)\""));
    assert!(
        lift_python.contains("{\"name\": \"rn\", \"kind\": \"a64_gpr64sp\", \"role\": \"inout\"")
    );
    assert!(lift_python.contains(
        "\"kind\": \"setreg\", \"reg_kind\": \"a64_gpr64\", \"index\": 30, \"width\": 64"
    ));
    assert!(lift_python.contains("(a64_logic_nzcv i64 (and rn (a64_shift_reg i64 rm shift imm)))"));
    assert!(lift_python.contains("(a64_extend_reg i64 rm option imm3)"));

    let exec_c = emit_exec_c(&document);
    assert!(exec_c.contains("typedef struct axis_state64_entry"));
    assert!(exec_c.contains("typedef struct axis_mem64"));
    assert!(exec_c.contains(
        "static inline axis_exec_result64 axis_exec_step64(uint32_t word, const char *isa"
    ));
    assert!(exec_c.contains("axis_a64_add_nzcv"));
    assert!(exec_c.contains("axis_a64_adc_nzcv"));
    assert!(exec_c.contains("axis_a64_sbc_nzcv"));
    assert!(exec_c.contains("axis_a64_umulh"));
    assert!(exec_c.contains("axis_a64_smulh"));
    assert!(exec_c.contains("axis_a64_logic_nzcv"));
    assert!(exec_c.contains("case AXIS_INSN_ADD_X_IMM_SP: if (n == 3)"));
    assert!(exec_c.contains("axis_exec64_eff_ADDS_X_IMM"));
    assert!(exec_c.contains("axis_a64_cond_holds"));
    assert!(exec_c.contains("axis_a64_shift_reg"));
    assert!(exec_c.contains("axis_a64_extend_reg"));
    assert!(exec_c.contains("axis_a64_decode_masks"));
    assert!(exec_c.contains("axis_a64_bfm"));

    let exec_rust = emit_exec_rust(&document);
    assert!(exec_rust.contains("pub struct State64Entry"));
    assert!(exec_rust.contains("pub trait WideMemory"));
    assert!(exec_rust.contains("pub fn step64(word: u32, isa: Option<&str>, regs: &mut [u64]"));
    assert!(exec_rust.contains("fn a64_add_nzcv"));
    assert!(exec_rust.contains("fn a64_adc_nzcv"));
    assert!(exec_rust.contains("fn a64_sbc_nzcv"));
    assert!(exec_rust.contains("fn a64_umulh"));
    assert!(exec_rust.contains("fn a64_smulh"));
    assert!(exec_rust.contains("fn a64_logic_nzcv"));
    assert!(exec_rust.contains("\"ADD_X_IMM_SP\" if inputs.len() == 3"));
    assert!(exec_rust.contains("fn axis_exec64_eff_adds_x_imm"));
    assert!(exec_rust.contains("fn a64_cond_holds"));
    assert!(exec_rust.contains("fn a64_shift_reg"));
    assert!(exec_rust.contains("fn a64_extend_reg"));
    assert!(exec_rust.contains("fn a64_decode_masks"));
    assert!(exec_rust.contains("fn a64_bfm"));

    let translations = emit_translation_map_json(&document);
    assert!(translations.contains("\"schema\": \"axis.translation-map.v1\""));
    assert!(translations.contains("\"source_mnemonic\": \"ADD_X_SHIFT0\""));
    assert!(translations.contains("\"target_mnemonic\": \"ACCEL_ADD64_SHIFTED\""));
    assert!(translations.contains("\"source_match\": \"0x8b000000\""));
    assert!(translations.contains("\"target_base\": \"0xac000000\""));
    // The map now also says whether an operand is a register and where its file
    // starts, because a consumer that inferred either from the class name was
    // right only for the general-purpose file.
    assert!(translations.contains(
        "\"source\": \"rd\", \"target\": \"rd\", \"role\": \"out\", \"class\": \"reg\", \"register\": true, \"slot_offset\": 0, \"slot_stride\": 1, \"width\": 64"
    ));
    // A second file names its own lowering family and its own offset, which is
    // what tells two instructions differing only by file apart.
    assert!(translations
        .contains("\"class\": \"a64_vreg64\", \"register\": true, \"slot_offset\": 32"));
    assert!(translations.contains(
        "\"source\": \"imm6\", \"target\": \"amount\", \"role\": \"in\", \"class\": \"imm\", \"register\": false, \"slot_offset\": 0, \"slot_stride\": 1, \"width\": 6"
    ));
    assert!(translations.contains(
        "\"semantic_key\": \"out=reg:64;in=[reg:64,reg:64,imm:2,imm:6];sem=add($0,a64_shift_reg(i64,$1,$2,$3))\""
    ));
    assert!(translations.contains("\"unmatched_sources\": ["));
    for mnemonic in [
        "SUB_X_SHIFT0",
        "B_COND",
        "ANDS_X_SHIFTED",
        "ANDS_W_SHIFTED",
        "ANDS_X_IMM",
        "ANDS_W_IMM",
        "UBFM_W",
    ] {
        assert!(
            translations.contains(&format!("\"{mnemonic}\"")),
            "{mnemonic} must remain an explicit source fallback"
        );
    }

    let err = validate_aha_export(&document)
        .expect_err("AArch64 encodings must not enter the PCE custom-op seam");
    assert!(err.to_string().contains("cannot be exported to PCE/AHA"));

    let missing_nzcv = parse_document(
        &include_str!("../examples/aarch64_translation_seed.axisl").replace("nzcv:i4", "fpcr:i32"),
    )
    .expect("parse AArch64 seed with missing NZCV declaration");
    let err = validate_document(&missing_nzcv).expect_err("NZCV must be declared by the ISA");
    assert!(err
        .to_string()
        .contains("state `nzcv:i4` is not declared by the instruction's ISA"));
}

#[test]
fn explicit_instruction_isa_binding_is_checked() {
    let unknown = r#"(axis-module multi
  (version "1.0")
  (target translation)

  (defisa a64
    (base armv8-a)
    (word-bits 32)
    (memory-model rvwmo)
    (endianness little)
  )

  (defformat A64_FIXED
    (bits 32)
    (fields
      (fixed 31 0)
    )
  )

  (definstruction bad
    (mnemonic BAD)
    (isa missing)
    (category custom)
    (format A64_FIXED)
    (opcode 0)
    (func3 0)
    (func7 0)
    (encoding (fixed 3573751839))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#;
    let document = parse_document(unknown).expect("parse unknown ISA example");
    let err = validate_document(&document).expect_err("unknown instruction ISA must fail");
    assert!(err
        .to_string()
        .contains("instruction `BAD` references unknown ISA `missing`"));

    let extension_wide = r#"(axis-module multi
  (version "1.0")
  (target translation)

  (defisa a64
    (base armv8-a)
    (word-bits 32)
    (memory-model rvwmo)
    (endianness little)
  )

  (defisa accel
    (base custom64)
    (word-bits 32)
    (memory-model rvwmo)
    (endianness little)
  )

  (defformat FIXED
    (bits 32)
    (fields
      (fixed 31 0)
    )
  )

  (definstruction bad
    (mnemonic BAD)
    (category custom)
    (format FIXED)
    (opcode 0)
    (func3 0)
    (func7 0)
    (encoding (fixed 1))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#;
    let document = parse_document(extension_wide).expect("parse multi-ISA example");
    validate_document(&document).expect("empty ISA binding remains extension-wide");
}

#[test]
fn distinct_isa_encoding_spaces_may_reuse_the_same_word() {
    let source = r#"(axis-module reuse
  (version "1.0")
  (target translation)

  (defisa source
    (role source)
    (base armv8-a)
    (word-bits 32)
    (memory-model rvwmo)
    (endianness little)
  )

  (defisa target
    (role target)
    (base custom)
    (word-bits 32)
    (memory-model rvwmo)
    (endianness little)
  )

  (defformat FIXED
    (bits 32)
    (fields
      (fixed 31 0)
    )
  )

  (definstruction a
    (mnemonic A)
    (isa source)
    (category custom)
    (format FIXED)
    (opcode 0)
    (func3 0)
    (func7 0)
    (encoding (fixed 1))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )

  (definstruction b
    (mnemonic B)
    (isa target)
    (category custom)
    (format FIXED)
    (opcode 0)
    (func3 0)
    (func7 0)
    (encoding (fixed 1))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#;
    let document = parse_document(source).expect("parse reused cross-ISA encoding");
    validate_document(&document).expect("distinct ISA decode spaces must not conflict");
}

#[test]
fn invalid_memory_metadata_and_references_are_rejected() {
    let bad_memory = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction nopx
    (mnemonic NOPX)
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

  (defmemory scratchpad
    (kind sram)
    (size-bytes 0)
    (ports 1)
    (latency-cycles 1)
    (width-bits 32)
    (banks 1)
  )
)
    "#;
    let document = parse_document(bad_memory).expect("parse invalid memory");
    let err = validate_document(&document).expect_err("zero-sized memory should fail");
    assert!(err
        .to_string()
        .contains("memory `scratchpad` size_bytes must be positive"));

    let bad_ref = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction nopx
    (mnemonic NOPX)
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

  (defcore rvmt0
    (kind rvmt)
    (threads 1)
  )

  (defmemory l1
    (kind sram)
    (size-bytes 1024)
    (ports 1)
    (latency-cycles 1)
    (width-bits 32)
    (banks 1)
  )

  (deftile tile0
    (cores rvmt0)
    (memories missing)
    (interconnect crossbar)
  )
)
    "#;
    let document = parse_document(bad_ref).expect("parse invalid memory ref");
    let err = validate_document(&document).expect_err("unknown memory ref should fail");
    assert!(err
        .to_string()
        .contains("tile `tile0` references unknown memory `missing`"));
}

#[test]
fn invalid_instruction_formal_semantics_are_rejected() {
    let source = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction bad
    (mnemonic BAD)
    (category custom)
    (format R)
    (opcode 11)
    (func3 1)
    (func7 2)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
    )
    (formal (add i32 rs1 rs2))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#;
    let document = parse_document(source).expect("parse semantic example");
    let err = validate_document(&document).expect_err("unknown operand should fail");
    assert!(err
        .to_string()
        .contains("instruction `BAD` unknown formal_semantics symbol `rs2`"));
}

#[test]
fn invalid_accelerator_formal_semantics_are_rejected() {
    let source = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction nopx
    (mnemonic NOPX)
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

  (defaccelerator dot_unit
    (family nearasic)
    (descriptor-version 1)
    (descriptor-bytes 0)
    (mmio-base 0)
    (mmio-size 0)
    (target nearasic)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (ports
      (a input bits i32)
      (b input bits i32)
      (y output bits i32)
    )
    (formal (dot4_i8 i32 a b))
    (latency 1)
    (throughput 1.0)
  )
)
    "#;
    let document = parse_document(source).expect("parse accelerator semantic example");
    let err = validate_document(&document).expect_err("unsupported op should fail");
    assert!(err
        .to_string()
        .contains("accelerator `dot_unit` unsupported formal_semantics operator `dot4_i8`"));
}

#[test]
fn formal_semantics_field_round_trips_into_both_json_outputs() {
    // The optional `formal_semantics:` field on an instruction —
    // consumed by the AHA/OptiSynth bridge — must survive
    // both emit_json and emit_aha_json round-trips.
    let source = include_str!("../examples/xpce_manifest.axisl");
    let document = parse_document(source).expect("parse example");
    let fma = document
        .instructions
        .iter()
        .find(|i| i.mnemonic == "FMA_I")
        .expect("example must declare an FMA_I instruction");
    assert_eq!(
        fma.formal_semantics, "(add i32 (mul i32 rs1 rs2) rs3)",
        "formal_semantics not lifted onto AST"
    );

    let manifest_json = emit_json(&document);
    assert!(
        manifest_json.contains("\"formal_semantics\": \"(add i32 (mul i32 rs1 rs2) rs3)\""),
        "manifest_json missing formal_semantics field"
    );

    let aha_json = emit_aha_json(&document);
    assert!(
        aha_json.contains("\"formal_semantics\": \"(add i32 (mul i32 rs1 rs2) rs3)\""),
        "aha_json missing formal_semantics field"
    );

    // Instructions without the field emit an empty-string default —
    // both consumers (Rust validators + Python bridge) treat empty
    // as "no formal semantics provided" and skip silently.
    let tls = document
        .instructions
        .iter()
        .find(|i| i.mnemonic == "TLS_LOAD")
        .unwrap();
    assert_eq!(tls.formal_semantics, "");
    assert!(manifest_json.contains("\"formal_semantics\": \"\""));
}

#[test]
fn aha_json_matches_custom_instruction_surface() {
    let source = include_str!("../examples/xpce_manifest.axisl");
    let document = parse_document(source).expect("parse example");
    validate_aha_export(&document).expect("validate AHA export");
    let aha = emit_aha_json(&document);

    assert!(aha.contains("\"schema\": \"pce-adl.aha-instructions.v1\""));
    assert!(aha.contains("\"type\": \"register\""));
    assert!(aha.contains("\"encoding\""));
    assert!(aha.contains("\"area_estimate_um2\": 1200.0"));
    assert!(aha.contains("\"applicable_patterns\": [\"thread_local\", \"memory_hiding\"]"));
    assert!(aha.contains("\"rationale\""));
}

#[test]
fn compiler_collateral_is_deterministic_and_minimal() {
    let source = include_str!("../examples/xpce_manifest.axisl");
    let document = parse_document(source).expect("parse example");
    validate_document(&document).expect("validate example");

    let tablegen = emit_tablegen(&document);
    assert!(tablegen.contains("class XPCEInst"));
    assert!(tablegen.contains("// mnemonic: TLS_LOAD"));
    assert!(tablegen.contains("// format: I"));
    assert!(tablegen.contains("// category: memory"));
    assert!(tablegen.contains("// latency_cycles: 2"));
    assert!(tablegen.contains("// throughput_per_cycle: 1.0"));
    assert!(tablegen.contains("// intrinsic: pce_tls_load"));
    assert!(tablegen.contains("// decode_key: opcode=0x0b, func3=1, func7=2"));
    assert!(tablegen.contains("def TLS_LOAD : XPCEInst<0b0000010, 0b001, 0b0001011"));
    assert!(tablegen.contains("(outs GPR:$rd), (ins GPR:$rs1, simm12:$imm), \"$rs1, $imm\""));
    assert!(tablegen.contains("def DOT4 : XPCEInst<0b0000011, 0b010, 0b0001011"));
    assert!(tablegen.contains("(outs GPR:$rd), (ins GPR:$rs1, GPR:$rs2), \"$rs1, $rs2\""));

    let intrinsics = emit_intrinsics(&document);
    assert!(intrinsics.contains("#ifndef PCE_ADL_XPCE_INTRINSICS_H"));
    assert!(intrinsics.contains("#define PCE_ADL_TLS_LOAD_OPCODE 0x0Bu"));
    assert!(intrinsics.contains("#define PCE_ADL_TLS_LOAD_FUNC3 1u"));
    assert!(intrinsics.contains("#define PCE_ADL_TLS_LOAD_FUNC7 2u"));
    assert!(intrinsics.contains("#define PCE_ADL_TLS_LOAD_LATENCY_CYCLES 2u"));
    assert!(intrinsics.contains("uint32_t pce_tls_load(uint32_t rs1, uint16_t imm);"));
    assert!(intrinsics.contains("#define PCE_ADL_DOT4_OPCODE 0x0Bu"));
    assert!(intrinsics.contains("#define PCE_ADL_DOT4_FUNC3 2u"));
    assert!(intrinsics.contains("#define PCE_ADL_DOT4_FUNC7 3u"));
    assert!(intrinsics.contains("#define PCE_ADL_DOT4_LATENCY_CYCLES 4u"));
    assert!(intrinsics.contains("uint32_t pce_dot4(uint32_t rs1, uint32_t rs2);"));

    let axis_document =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse axis example");
    validate_document(&axis_document).expect("validate axis example");
    let asm_disasm = emit_asm_disasm_json(&axis_document);
    assert!(asm_disasm.contains("\"mnemonic\": \"TLS_LOAD\""));
    assert!(asm_disasm.contains("\"opcode_token\": \"tls_load\""));
    assert!(asm_disasm.contains("\"asm_template\": \"tls_load $rd, $rs1, $imm\""));
    assert!(asm_disasm.contains("\"field\": \"imm\""));
    assert!(asm_disasm.contains("\"operand_print_order\": [\"rd\", \"rs1\", \"imm\"]"));

    let encode = emit_encode_table_json(&axis_document);
    assert!(encode.contains("\"schema\": \"axis.encode-table.v1\""));
    assert!(encode.contains("\"mnemonic\": \"TLS_LOAD\""));
    assert!(encode.contains("\"field\": \"imm\""));
    assert!(encode.contains("\"mnemonic\": \"FMA_I\""));
    assert!(encode.contains("\"name\": \"rs3\""));
    // R4 packs rs3 at bits 31:27 and fixes func2 — nothing is unencoded.
    assert!(encode.contains("\"field\": \"rs3\""));
    assert!(encode.contains("\"func2\": 0"));
    assert!(!encode.contains("\"field\": \"unencoded\""));

    let encode_c = emit_encode_c(&axis_document);
    assert!(encode_c.contains("AXIS_ENCODE_OPERANDS_TLS_LOAD"));
    assert!(encode_c.contains("AXIS_ENCODE_OPERANDS_FMA_I"));
    assert!(encode_c.contains("\"rs3\", \"reg\", \"input\", \"rs3\", 3, 0, 27, 5u"));
    assert!(!encode_c.contains("\"unencoded\""));

    let roundtrip = emit_roundtrip_tests_json(&axis_document);
    assert!(roundtrip.contains("\"mnemonic\": \"TLS_LOAD\""));
    assert!(roundtrip.contains("\"encoded\": \"0x0031108b\""));
    assert!(roundtrip.contains("\"matches\": true"));
    assert!(roundtrip.contains("\"mnemonic\": \"FMA_I\""));
    assert!(roundtrip.contains("\"encoded\": \"0x2031308b\""));
    assert!(
        !roundtrip.contains("\"reason\":"),
        "nothing should be skipped"
    );
}

#[test]
fn rvmt_json_is_minimal_compatibility_manifest() {
    let source = include_str!("../examples/xpce_manifest.axisl");
    let document = parse_document(source).expect("parse example");
    validate_document(&document).expect("validate example");
    let rvmt = emit_rvmt_json(&document);

    assert!(rvmt.contains("\"target\": \"rvmt\""));
    assert!(rvmt.contains("\"mnemonic\": \"TLS_LOAD\""));
    assert!(rvmt.contains("\"decode_key\""));
    assert!(!rvmt.contains("\"schema\""));
    assert!(!rvmt.contains("\"semantics\""));
}

#[test]
fn invalid_format_and_costs_are_rejected() {
    let source = r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction bad
    (mnemonic BAD)
    (category custom)
    (format Z)
    (opcode 11)
    (func3 1)
    (func7 2)
    (latency 1)
    (throughput 0.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#;
    let document = parse_document(source).expect("parse invalid example");
    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err.to_string().contains("format `Z`"));
}

#[test]
fn python_output_is_data_only() {
    let source = include_str!("../examples/rvmt_xpce.axisl");
    let document = parse_document(source).expect("parse example");
    validate_document(&document).expect("validate example");
    let python = emit_python(&document);

    assert!(python.contains("RVMT_EXTENSION_MANIFEST = {"));
    assert!(python.contains("PCE_ADL_MANIFEST = {"));
    assert!(!python.contains("def "));
    assert!(!python.contains("class "));
}

#[test]
fn duplicate_decode_keys_are_rejected() {
    let source = r#"(axis-module xpce
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
    "#;
    let document = parse_document(source).expect("parse duplicate example");
    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err.to_string().contains("overlap in the decode space"));
}

#[test]
fn heterogeneous_and_accelerator_examples_validate_and_preserve_topology() {
    let heterogeneous = parse_document(include_str!("../examples/heterogeneous_tile.axisl"))
        .expect("parse heterogeneous example");
    validate_document(&heterogeneous).expect("validate heterogeneous example");
    let heterogeneous_json = emit_json(&heterogeneous);
    assert!(heterogeneous_json.contains("\"kind\": \"rvmt\""));
    assert!(heterogeneous_json.contains("\"kind\": \"simt\""));
    assert!(heterogeneous_json.contains("\"target\": \"xnn\""));
    assert!(heterogeneous_json.contains("\"coupling\": \"queue_descriptor\""));
    assert!(heterogeneous_json.contains("\"interconnect\": \"noc\""));

    let accelerator = parse_document(include_str!("../examples/accelerator_descriptor.axisl"))
        .expect("parse accelerator descriptor example");
    validate_document(&accelerator).expect("validate accelerator descriptor example");
    let accelerator_json = emit_json(&accelerator);
    assert!(accelerator_json.contains("\"target\": \"nearasic\""));
    assert!(accelerator_json.contains("\"coupling\": \"tightly_coupled\""));
    assert!(accelerator_json.contains("\"descriptor_schema\": \"rvmt_nearasic_v1\""));
    assert!(accelerator_json.contains("\"descriptor_bytes\": 68"));
    assert!(accelerator_json.contains("\"launch_abi\": \"rvmt_submit_entry\""));
    assert!(accelerator_json.contains("\"completion\": \"status_addr\""));
    assert!(accelerator_json.contains("\"interconnect\": \"mailbox\""));
}

#[test]
fn accelerator_descriptor_metadata_round_trips_to_python_manifest() {
    let source = include_str!("../examples/accelerator_descriptor.axisl");
    let document = parse_document(source).expect("parse accelerator descriptor example");
    validate_document(&document).expect("validate accelerator descriptor example");

    let accelerator = &document.accelerators[0];
    assert_eq!(accelerator.descriptor_schema, "rvmt_nearasic_v1");
    assert_eq!(accelerator.descriptor_bytes, 68);
    assert_eq!(accelerator.launch_abi, "rvmt_submit_entry");
    assert_eq!(accelerator.completion, "status_addr");

    let python = emit_python(&document);
    assert!(python.contains("\"descriptor_schema\": \"rvmt_nearasic_v1\""));
    assert!(python.contains("\"descriptor_bytes\": 68"));
    assert!(python.contains("\"launch_abi\": \"rvmt_submit_entry\""));
    assert!(python.contains("\"completion\": \"status_addr\""));
}

#[test]
fn heterogeneous_example_emits_stable_topology_and_coupling_handoff_manifests() {
    let source = include_str!("../examples/heterogeneous_tile.axisl");
    let document = parse_document(source).expect("parse heterogeneous example");
    validate_document(&document).expect("validate heterogeneous example");

    let topology = emit_adl_topology_manifest_json(&document);
    assert!(topology.contains("\"schema\": \"pce-adl.topology.v1\""));
    assert!(topology.contains("\"source_interconnect\": \"noc\""));
    assert!(topology.contains("\"synthesis_noc_topology\": \"mesh\""));
    assert!(topology.contains("\"selected_tile\""));

    let coupling = emit_adl_coupling_manifest_json(&document);
    assert!(coupling.contains("\"schema\": \"pce-adl.coupling.v1\""));
    assert!(coupling.contains("\"source_tile\": \"hetero0\""));
    assert!(coupling.contains("\"source_core\": \"rvmt_host\""));
    assert!(coupling.contains("\"accelerator_ref\": \"xnn0\""));
    assert!(coupling.contains("\"source_coupling\": \"queue_descriptor\""));
    assert!(coupling.contains("\"tier\": \"loose\""));
    assert!(coupling.contains("\"active\": true"));
    assert!(coupling.contains("\"metadata_only\": false"));
    assert!(coupling.contains("\"mmio_base\": 2147483648"));
    assert!(coupling.contains("\"mmio_size\": 4096"));
}

#[test]
fn accelerator_example_emits_descriptor_and_metadata_only_coupling_manifests() {
    let source = include_str!("../examples/accelerator_descriptor.axisl");
    let document = parse_document(source).expect("parse accelerator descriptor example");
    validate_document(&document).expect("validate accelerator descriptor example");

    let descriptors = emit_accelerator_descriptor_manifests_json(&document);
    assert!(descriptors.contains("\"name\": \"nearasic_reduce\""));
    assert!(descriptors.contains("\"descriptor_schema\": \"rvmt_nearasic_v1\""));
    assert!(descriptors.contains("\"descriptor_bytes\": 68"));
    assert!(descriptors.contains("\"launch_abi\": \"rvmt_submit_entry\""));
    assert!(descriptors.contains("\"completion\": \"status_addr\""));

    let coupling = emit_adl_coupling_manifest_json(&document);
    assert!(coupling.contains("\"accelerator_ref\": \"nearasic_reduce\""));
    assert!(coupling.contains("\"tier\": \"tight\""));
    assert!(coupling.contains("\"active\": false"));
    assert!(coupling.contains("\"metadata_only\": true"));
    assert!(coupling.contains("\"descriptor_schema\": \"rvmt_nearasic_v1\""));
    assert!(coupling.contains("\"coupling\":"));
    assert!(coupling.contains("{}"));
}

#[test]
fn accelerator_example_emits_rvmt_launch_template_manifest() {
    let source = include_str!("../examples/accelerator_descriptor.axisl");
    let document = parse_document(source).expect("parse accelerator descriptor example");
    validate_document(&document).expect("validate accelerator descriptor example");

    let templates = emit_rvmt_launch_templates_json(&document);
    assert!(templates.contains("\"name\": \"nearasic_reduce\""));
    assert!(templates.contains("\"descriptor_schema\": \"rvmt_nearasic_v1\""));
    assert!(templates.contains("\"descriptor_bytes\": 68"));
    assert!(templates.contains("\"launch_abi\": \"rvmt_submit_entry\""));
    assert!(templates.contains("\"completion\": \"status_addr\""));
    assert!(templates.contains("\"coupling_tier\": \"tight\""));
    assert!(templates.contains("\"submit_user_word_abi\": \"nearasic_launch_v1\""));
    assert!(templates.contains("\"runtime_descriptor_fields\""));
    assert!(templates.contains("\"cfg_id\""));
    assert!(templates.contains("\"status_addr\""));
    assert!(templates.contains("\"runtime_user_fields\""));
    assert!(templates.contains("\"fabric_select\""));
    assert!(templates.contains("\"quant_scale\""));

    let rvmt_only =
        parse_document(include_str!("../examples/xpce_manifest.axisl")).expect("parse rvmt example");
    validate_document(&rvmt_only).expect("validate rvmt example");
    let empty_templates = emit_rvmt_launch_templates_json(&rvmt_only);
    assert_eq!(empty_templates.trim(), "[\n]");
}

#[test]
fn rcore_example_emits_descriptor_and_launch_template_manifests() {
    let source = include_str!("../examples/rcore_descriptor.axisl");
    let document = parse_document(source).expect("parse rcore descriptor example");
    validate_document(&document).expect("validate rcore descriptor example");

    let descriptors = emit_accelerator_descriptor_manifests_json(&document);
    assert!(descriptors.contains("\"name\": \"rcore_region\""));
    assert!(descriptors.contains("\"target\": \"rcore\""));
    assert!(descriptors.contains("\"descriptor_schema\": \"rvmt_rcore_v1\""));
    assert!(descriptors.contains("\"descriptor_bytes\": 36"));
    assert!(descriptors.contains("\"launch_abi\": \"rvmt_submit_entry\""));
    assert!(descriptors.contains("\"completion\": \"mailbox\""));

    let templates = emit_rvmt_launch_templates_json(&document);
    assert!(templates.contains("\"name\": \"rcore_region\""));
    assert!(templates.contains("\"descriptor_schema\": \"rvmt_rcore_v1\""));
    assert!(templates.contains("\"descriptor_bytes\": 36"));
    assert!(templates.contains("\"submit_user_word_abi\": \"rcore_launch_v1\""));
    assert!(templates.contains("\"runtime_descriptor_fields\""));
    assert!(templates.contains("\"livein_ptr\""));
    assert!(templates.contains("\"payload_ptr\""));
    assert!(templates.contains("\"runtime_user_fields\""));
    assert!(templates.contains("\"region_id\""));
    assert!(templates.contains("\"patch_set\""));

    let regions = emit_rvmt_rcore_region_manifest_json(&document);
    assert!(regions.contains("\"schema\": \"pce-adl.rvmt-rcore-regions.v1\""));
    assert!(regions.contains("\"name\": \"rcore_region\""));
    assert!(regions.contains("\"target\": \"rcore\""));
    assert!(regions.contains("\"region_id\": 17"));
    assert!(regions.contains("\"manifest_version\": 3"));
    assert!(regions.contains("\"profile\": \"scalar\""));
    assert!(regions.contains("\"backend_kind\": \"auto\""));
    assert!(regions.contains("\"exec_shape\": \"scalar\""));
    assert!(regions.contains("\"fallback_policy\": \"software\""));
}

#[test]
fn invalid_core_kind_is_rejected() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defcore bad
    (kind gpu)
    (threads 1)
  )
)
    "#,
    )
    .expect("parse invalid topology");

    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err.to_string().contains("core `bad` kind `gpu`"));
}

#[test]
fn invalid_tile_interconnect_is_rejected() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defcore host
    (kind rvmt)
    (threads 1)
  )

  (deftile cluster
    (cores host)
    (interconnect ring)
  )
)
    "#,
    )
    .expect("parse invalid tile");

    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("tile `cluster` interconnect `ring`"));
}

#[test]
fn invalid_accelerator_target_and_coupling_are_rejected() {
    let invalid_target = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator bad
    (family xnn)
    (descriptor-version 1)
    (descriptor-bytes 0)
    (mmio-base 0)
    (mmio-size 0)
    (target mystery)
    (coupling queue_descriptor)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse invalid accelerator target");
    let err = validate_document(&invalid_target).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("accelerator `bad` target `mystery`"));

    let invalid_coupling = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator bad
    (family xnn)
    (descriptor-version 1)
    (descriptor-bytes 0)
    (mmio-base 0)
    (mmio-size 0)
    (target xnn)
    (coupling direct_bus)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse invalid accelerator coupling");
    let err = validate_document(&invalid_coupling).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("accelerator `bad` coupling `direct_bus`"));
}

#[test]
fn mismatched_accelerator_family_and_target_are_rejected() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator bad
    (family xnn)
    (descriptor-version 1)
    (descriptor-bytes 0)
    (mmio-base 0)
    (mmio-size 0)
    (target simt)
    (coupling stream)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse mismatched accelerator");

    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("accelerator `bad` family `xnn` must match target `simt`"));
}

#[test]
fn nearasic_descriptor_byte_version_mismatch_is_rejected() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator bad
    (family nearasic)
    (descriptor-version 2)
    (descriptor-schema rvmt_nearasic_v2)
    (descriptor-bytes 68)
    (launch-abi rvmt_submit_entry)
    (completion status_addr)
    (mmio-base 0)
    (mmio-size 0)
    (target nearasic)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse mismatched descriptor metadata");

    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("nearasic descriptor_version 2 expects descriptor_bytes 124"));
}

#[test]
fn nearasic_descriptor_v2_metadata_is_valid() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator good
    (family nearasic)
    (descriptor-version 2)
    (descriptor-schema rvmt_nearasic_v2)
    (descriptor-bytes 124)
    (launch-abi mailbox)
    (completion mailbox)
    (mmio-base 0)
    (mmio-size 0)
    (target nearasic)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse valid v2 descriptor metadata");

    validate_document(&document).expect("validate v2 descriptor metadata");
}

#[test]
fn rcore_descriptor_byte_mismatch_is_rejected() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator bad
    (family rcore)
    (descriptor-version 1)
    (descriptor-schema rvmt_rcore_v1)
    (descriptor-bytes 32)
    (launch-abi rvmt_submit_entry)
    (completion mailbox)
    (mmio-base 0)
    (mmio-size 0)
    (target rcore)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse invalid rcore descriptor metadata");

    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("rcore descriptor_version 1 expects descriptor_bytes 36"));
}

#[test]
fn invalid_rcore_region_metadata_is_rejected() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator bad
    (family rcore)
    (descriptor-version 1)
    (descriptor-schema rvmt_rcore_v1)
    (descriptor-bytes 36)
    (launch-abi rvmt_submit_entry)
    (completion mailbox)
    (mmio-base 0)
    (mmio-size 0)
    (target rcore)
    (region-id 0)
    (manifest-version 0)
    (profile invalid_profile)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse invalid rcore region metadata");

    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("accelerator `bad` profile `invalid_profile`"));
}

#[test]
fn invalid_accelerator_descriptor_enums_are_rejected() {
    let document = parse_document(
        r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator bad
    (family nearasic)
    (descriptor-version 1)
    (descriptor-bytes 68)
    (launch-abi direct_call)
    (completion polling)
    (mmio-base 0)
    (mmio-size 0)
    (target nearasic)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 0)
    (fallback-policy software)
    (latency 1)
    (throughput 1.0)
  )
)
    "#,
    )
    .expect("parse invalid descriptor metadata");

    let err = validate_document(&document).expect_err("validation should fail");
    assert!(err
        .to_string()
        .contains("accelerator `bad` launch_abi `direct_call`"));
}

#[test]
fn nested_aarch64_operators_bind_in_nested_lets() {
    // SMT-LIB's `let` binds its clauses simultaneously, so two helper calls
    // where the second reads the first must nest. No instruction in any corpus
    // has two `a64_*` operators, so the SMT-versus-golden gate cannot see the
    // difference -- it passed with parallel bindings, which name a constant the
    // solver has not bound. A mined extension that fuses two shifted-register
    // instructions is exactly that shape, and this pins it.
    let source = r#"(axis-module nested_a64
  (version "1.0")
  (target rvmt)
  (defisa aarch64_base
    (role source)
    (base armv8-a)
    (word-bits 64)
    (registers "x[31]:i64" "sp:i64" "pc:i64")
    (features a64))
  (definstruction fused
    (mnemonic FUSED)
    (isa aarch64_base)
    (category custom)
    (format R)
    (opcode 11) (func3 0) (func7 1)
    (operands
      (rd a64_gpr64 i64 out)
      (rn a64_gpr64 i64 in)
      (rm a64_gpr64 i64 in)
      (shift imm i2 in)
      (imm6 imm i6 in))
    (asm "fused $rd, $rn, $rm")
    (semantics "two shifted-register operands, one inside the other")
    (behavior
      (set rd (a64_shift_reg i64 (a64_shift_reg i64 rm shift imm6) shift imm6)))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)
    (rationale "Pins nested let bindings in the SMT backend."))
)
"#;
    let document = parse_document(source).expect("parse nested a64 example");
    let smt2 = emit_smt2(&document);
    let body = smt2
        .split("(define-fun axis_instr_fused")
        .nth(1)
        .expect("the instruction has an SMT definition");
    assert!(
        body.contains("(let ((axis_a64_t0") && body.contains("(let ((axis_a64_t1"),
        "each helper call gets a let of its own, so the second can read the first"
    );
    assert!(
        !body.contains("(axis_a64_t0 ") || !body.contains(") (axis_a64_t1 "),
        "the bindings are nested, not parallel"
    );
}

#[test]
fn a_wide_register_is_limbs_of_the_file_not_words_of_the_value() {
    // Two numbers that look alike and are not: how many machine words a value
    // is, and how many slots its register occupies in the file. On AArch64 they
    // agree -- a 128-bit V register is two 64-bit slots, and 128/64 is also two
    // -- so counting words got `ldr q0` right by luck. RISC-V's `rv_fpr` holds
    // 64 bits in ONE slot, so on RV32 a 64-bit `fld` is not two limbs of
    // anything: it is a single slot wider than a region's only type. Counting
    // words split it across `f0` and `f1` while the executor kept one 64-bit
    // value in `f0`.
    let rv32 = parse_document(include_str!("../examples/rv32i.axisl"))
        .expect("parse rv32i example");
    let support = axis_adl::lifter::describe_support(&rv32);
    for line in support.lines() {
        let Some((mnemonic, verdict)) = line.split_once('\t') else {
            continue;
        };
        if matches!(mnemonic, "FLD" | "FSD") {
            assert!(
                verdict.contains("wider than the machine"),
                "{mnemonic} moves a 64-bit register held in one slot on a \
                 32-bit machine, which a region cannot hold: got `{verdict}`"
            );
        }
    }

    // The other half of the claim: where the file really does hold the value in
    // whole machine words, it lifts. A 128-bit V register on AArch64 is two
    // 64-bit slots and two 64-bit accesses.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 example");
    let support = axis_adl::lifter::describe_support(&a64);
    for wide in ["LDR_Q_UNSIGNED", "STR_Q_UNSIGNED", "LDP_Q_OFFSET", "STP_Q_OFFSET"] {
        assert!(
            support.lines().any(|line| line == format!("{wide}\tok")),
            "{wide} is whole limbs of the register file and should lift"
        );
    }
}

#[test]
fn an_extension_narrower_than_what_it_wraps_is_well_sorted() {
    // `(srl i32 (sext i64 32 x) s)` is what a composition of two RISC-V word
    // instructions looks like: the first widens its result to the register, the
    // second reads only the low half back. Every other node resized itself to
    // the width its caller asked for; the integer extension did not, so the
    // shift got a 64-bit left operand and a 32-bit right one and z3 rejected
    // the whole file rather than answering it. No corpus instruction nests an
    // extension under a narrower operator, so `SMT == golden` could not see it.
    let source = r#"(axis-module narrow_over_wide
  (version "1.0")
  (target rvmt)
  (definstruction probe
    (mnemonic PROBE)
    (category custom)
    (format R)
    (opcode 11) (func3 0) (func7 1)
    (operands
      (rd reg i64 out)
      (rs1 reg i64 in)
      (rs2 reg i64 in)
      (imm imm i5 in))
    (asm "probe $rd, $rs1, $rs2")
    (semantics "add the low halves, widen, then shift the low half again")
    (behavior
      (set rd (sext i64 32 (srl i32 (sext i64 32 (add i32 rs1 rs2))
                                    (and i32 imm 0x1f)))))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)
    (rationale "Pins the width an extension reports to its caller."))
)
"#;
    let document = parse_document(source).expect("parse narrowing example");
    let smt2 = emit_smt2(&document);
    let body = smt2
        .split("(define-fun axis_instr_probe")
        .nth(1)
        .expect("the instruction has an SMT definition");
    assert!(
        body.contains("(bvlshr ((_ extract 31 0) ((_ sign_extend 32)"),
        "the shift narrows the extension back to its own width, got {body}"
    );
}

#[test]
fn zbb_class_operators_flow_through_semantic_backends() {
    let source = include_str!("../examples/zbb_like.axisl");
    let document = parse_document(source).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");

    let smt2 = emit_smt2(&document);
    assert!(smt2.contains("(define-fun axis_instr_srax"));
    assert!(smt2.contains("(bvashr rs1 rs2)"));
    assert!(smt2.contains("(bvnot rs2)"));
    assert!(
        smt2.contains("(bvurem rs2 (_ bv32 32))"),
        "rotate normalizes shift"
    );
    assert!(
        smt2.contains("(ite (bvslt axis_a axis_b) axis_a axis_b)"),
        "signed min"
    );
    assert!(
        smt2.contains("(ite (bvugt axis_a axis_b) axis_a axis_b)"),
        "unsigned max"
    );
    assert!(
        smt2.contains("((_ extract 31 31) axis_x)"),
        "clz tests the MSB"
    );
    assert!(
        smt2.contains("((_ zero_extend 31) ((_ extract 0 0) axis_x))"),
        "cpop terms"
    );
    assert!(
        smt2.contains("((_ sign_extend 24) ((_ extract 7 0) rs1))"),
        "sext.b"
    );
    assert!(
        smt2.contains("((_ zero_extend 16) ((_ extract 15 0) rs1))"),
        "zext.h"
    );

    let golden = emit_golden_python(&document);
    assert!(golden.contains("def _signed(value, width):"));
    assert!(
        golden.contains("width = int(args[0][1:])"),
        "type atom sets width"
    );
    assert!(golden.contains("if op in ('sra', 'ashr'):"));
    assert!(golden.contains("if op in ('rol', 'ror'):"));
    assert!(golden.contains("if op == 'clz':"));
    assert!(golden.contains("if op == 'cpop':"));
    assert!(golden.contains("if op in ('min', 'max'):"));
    assert!(golden.contains("if op == 'sext':"));
    assert!(golden.contains("def eval_srax(rs1, rs2):"));

    let pyrtl = emit_pyrtl(&document);
    assert!(pyrtl.contains("def _rotate(value, amount, width, left):"));
    assert!(pyrtl.contains("def _count_zeros(value, width, leading):"));
    assert!(pyrtl.contains("def _popcount(value, width):"));
    assert!(pyrtl.contains("pyrtl.shift_right_arithmetic"));
    assert!(pyrtl.contains("pyrtl.signed_lt"));
    assert!(pyrtl.contains("value.sign_extended(width)"));
    assert!(pyrtl.contains("def build_clzx(rs1):"));

    let llvm = emit_llvm_ir(&document);
    // Prelude helper definitions and the intrinsics they lean on.
    assert!(llvm.contains("declare i32 @llvm.ctlz.i32(i32, i1)"));
    assert!(llvm.contains("define internal i32 @axis_sem_rotr(i32 %v, i32 %a, i32 %w)"));
    assert!(llvm.contains("define internal i32 @axis_sem_min_s"));
    // Per-instruction functions lower to calls into the prelude helpers.
    assert!(llvm.contains("define i32 @axis_eval_srax(i32 %rs1, i32 %rs2)"));
    assert!(llvm.contains("call i32 @axis_sem_sra(i32 %rs1, i32 %rs2, i32 32)"));
    assert!(llvm.contains("call i32 @axis_sem_rotr(i32 %rs1, i32 %rs2, i32 32)"));
    assert!(llvm.contains("call i32 @axis_sem_clz(i32 %rs1, i32 32)"));
    assert!(llvm.contains("call i32 @axis_sem_sext(i32 %rs1, i32 8, i32 32)"));
    // andn folds `not` into a native `and` instruction.
    assert!(llvm.contains("define i32 @axis_eval_andn(i32 %rs1, i32 %rs2)"));
    assert!(llvm.contains("= and i32 %rs1,"));

    let rust = emit_semantics_rust(&document);
    // Allows + prelude helpers.
    assert!(rust.contains("// schema: axis.semantics-rust.v1"));
    assert!(rust.contains("#![allow(dead_code, unused_parens)]"));
    assert!(rust.contains("pub fn axis_sem_mask(value: u32, width: u32) -> u32 {"));
    assert!(rust.contains("fn axis_sem_rotr(value: u32, amount: u32, width: u32) -> u32 {"));
    // Arithmetic uses wrapping ops; width-sensitive ops call helpers.
    assert!(rust.contains("pub fn axis_eval_srax(rs1: u32, rs2: u32) -> u32 {"));
    assert!(rust.contains("axis_sem_mask(axis_sem_sra(rs1, rs2, 32), 32)"));
    assert!(rust.contains("axis_sem_mask((rs1 & axis_sem_not(rs2, 32)), 32)"));
    assert!(rust.contains("axis_sem_sext(rs1, 8, 32)"));
    // FMA-style composite folds with wrapping_add / wrapping_mul.
    let rvmt =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&rvmt).expect("validate rvmt example");
    let rvmt_rust = emit_semantics_rust(&rvmt);
    // The receiver of each method call is parenthesized: it may end in a cast.
    assert!(rvmt_rust.contains("((rs1).wrapping_mul(rs2)).wrapping_add(rs3)"));
    // Instructions without semantics get a comment, not a function.
    assert!(rvmt_rust.contains("// axis_eval_tls_load: no formal_semantics declared"));
}

#[test]
fn llvm_intrinsic_declarations_match_signatures() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let td = emit_llvm_intrinsics(&document);

    assert!(td.contains("// Generated by AXIS. schema: axis.llvm-intrinsics.v1"));
    assert!(td.contains("let TargetPrefix = \"axis\" in {"));
    // Two-input op: result + two i32 params, tagged pure.
    assert!(td.contains(
        "  def int_axis_minx : Intrinsic<[llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty],\n\
         \x20     [IntrNoMem, IntrWillReturn, IntrSpeculatable]>;"
    ));
    // One-input op: exactly one param.
    assert!(td.contains("def int_axis_clzx : Intrinsic<[llvm_i32_ty], [llvm_i32_ty],"));
    assert!(td.contains("// CLZX => llvm.axis.clzx"));

    // Signature/width invariant: the declared arg count equals the instruction's
    // input-operand count, and every type is i32 (all zbb operands are 32-bit).
    for instruction in &document.instructions {
        let inputs = instruction.operands.iter().filter(|o| !o.output).count();
        let params = vec!["llvm_i32_ty"; inputs].join(", ");
        let decl = format!(
            "def int_axis_{} : Intrinsic<[llvm_i32_ty], [{params}],",
            instruction.mnemonic.to_ascii_lowercase()
        );
        assert!(td.contains(&decl), "missing/mismatched intrinsic: {decl}");
    }

    // Non-standard widths and effectful (non-formal) instructions are withheld,
    // not mislabeled: TLS_LOAD in the rvmt example has neither a standard imm
    // width nor formal_semantics.
    let rvmt =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&rvmt).expect("validate rvmt example");
    let rvmt_td = emit_llvm_intrinsics(&rvmt);
    assert!(rvmt_td.contains("// TLS_LOAD: no formal_semantics"));
    assert!(!rvmt_td.contains("def int_axis_tls_load"));
    assert!(rvmt_td.contains("def int_axis_pce_fma_i : Intrinsic<[llvm_i32_ty], [llvm_i32_ty, llvm_i32_ty, llvm_i32_ty],"));
}

#[test]
fn llvm_target_selects_its_own_instructions() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let td = emit_llvm_target(&document);

    // A backend selects an *instruction*, so both sides of a Pat are this
    // target's: the leaves are typed by its register class, not by width as
    // the intrinsic hints are, and the RHS is the instruction def.
    assert!(
        td.contains(
            "def : Pat<(i32 (and REGRegs:$RS1, (xor REGRegs:$RS2, -1))),\n          (ANDN REGRegs:$RS1, REGRegs:$RS2)>;"
        ),
        "andn selects ANDN with class-typed leaves"
    );
    // The root carries its type. A class holding more than one value type
    // leaves a bare `(and $a, $b)` ambiguous and TableGen says so.
    assert!(td.contains("def : Pat<(i32 ("), "pattern root is typed");
    // The DAG is the one `emit-llvm-patterns` emits and
    // `llvm_patterns_check.py` evaluates against the golden model -- one
    // builder, two leaf spellings. `llvm_target_check.py` gates that they
    // stay identical; this pins the shape.
    let patterns = emit_llvm_patterns(&document);
    assert!(patterns.contains("(and i32:$rs1, (xor i32:$rs2, -1))"));

    // A Pat's operands are supplied positionally into `InOperandList`, so
    // they must be the instruction's own operands in the encoded order.
    assert!(td.contains("def ANDN : XZBB_TESTInst<(outs REGRegs:$RD), (ins REGRegs:$RS1, REGRegs:$RS2)"));

    // Every zbb_like instruction gets a pattern, so the declines are pinned on
    // corpora that have them. Whether an instruction says what it computes is
    // asked before any question about a pattern's shape, so an instruction
    // that states nothing is reported as such rather than by whichever shape
    // check happened to run first.
    let rvmt =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&rvmt).expect("validate rvmt example");
    assert!(
        emit_llvm_target(&rvmt)
            .contains("// TLS_LOAD: no formal_semantics and no behavior; no pattern"),
        "an instruction that states nothing is declined for that reason"
    );

    // An operator with no clean SelectionDAG form is declined by name rather
    // than approximated.
    let rv32i =
        parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i example");
    validate_document(&rv32i).expect("validate rv32i example");
    assert!(
        emit_llvm_target(&rv32i)
            .contains(": no SelectionDAG pattern for these operators; no pattern"),
        "declines are named"
    );
}

#[test]
fn a_simple_load_selects_and_a_load_that_is_not_simple_says_so() {
    let document = parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i");
    validate_document(&document).expect("validate rv32i");
    let td = emit_llvm_target(&document);

    // A load is not a `Sem` operator -- it is peeled above the lowering, so
    // the address stays arithmetic and the builder that already exists writes
    // it. A narrow load is `sextloadiN`/`zextloadiN` rather than a load and an
    // extend, because the combiner folds the extension into the load long
    // before selection.
    for (node, mnemonic) in [
        ("sextloadi8", "LB"),
        ("sextloadi16", "LH"),
        ("zextloadi8", "LBU"),
        ("zextloadi16", "LHU"),
    ] {
        assert!(
            td.contains(&format!(
                "def : Pat<(i32 ({node} (add RV_GPRRegs:$RS1, simm12i32:$IMM))),\n          ({mnemonic} RV_GPRRegs:$RS1, simm12i32:$IMM)>;"
            )),
            "{mnemonic} selects a {node}"
        );
    }

    // The offset is *signed*, and only the behavior says so. `LW` has no
    // formal form, so reading only `formal_semantics` left the range unstated
    // and the encoding -- asked next -- says a twelve-bit field. The operand
    // list declared `uimm12i32` for an immediate the description sign
    // extends, which refused half the legal encodings of every load and store
    // in the ISA.
    assert!(
        td.contains(r#"(ins RV_GPRRegs:$RS1, simm12i32:$IMM), "lw""#),
        "a behavior-stated extension gives the operand its range"
    );

    // `LR.W` loads and records a reservation. A `load` node has nowhere to
    // carry that, so selecting it for an ordinary load would claim a plain
    // access and let LLVM delete a reservation it cannot see.
    //
    // ⚠️ The reason it gives is the ATOMICITY, which is checked first and is
    // the more basic disqualification: `atomic_load` is a different DAG node,
    // not a `load` with a caveat. The reservation write is a second and
    // independent reason, and no corpus witnesses it on its own any more --
    // every load that writes the monitor also admits it is atomic. What this
    // asserts is that the decline is NAMED, which is the property that broke:
    // marking the family atomic made `peel_load` stop recognising it as a
    // load at all, and the line disappeared from the output entirely.
    assert!(
        td.contains("// LR_W: an atomic load is not a plain `load` node; no pattern"),
        "a load that is not plain says which way it is not plain"
    );

    // `FLS` and `LW` used to reduce to the same left-hand side, and both were
    // dropped for the collision. They collided because RV32's `f` file was
    // described as 32 bits: FLEN is 64 with `D` present, so a single load
    // writes 64 bits and NaN-boxes them, and the two never had one pattern.
    // Fixing the file's width is what gave `LW` its own.
    assert!(
        td.contains("def : Pat<(i32 (load (add RV_GPRRegs:$RS1, simm12i32:$IMM))),\n          (LW RV_GPRRegs:$RS1, simm12i32:$IMM)>;"),
        "a plain word load selects once the FP file stops claiming its pattern"
    );
    // `FLS` is still declined, for a reason that is its own: the NaN-box is a
    // second write, and a pattern's one result cannot hold both.
    assert!(
        td.contains("// FLS: behavior writes 2 values beside its state; one value cannot hold them; no pattern"),
        "the NaN-boxing load is declined for writing twice"
    );

    // `LUI`'s whole value is its own immediate shifted, so once the shift
    // folds there is no operation left -- the pattern would be a bare
    // constant, and LLVM materialises those itself.
    assert!(
        td.contains("// LUI: semantics is a bare value; no pattern"),
        "a whole-constant value is declined by name"
    );
}

#[test]
fn an_operand_naming_a_window_is_as_wide_as_the_window() {
    // A window is owned by its class: `x86_r8hi` is `AH`, eight bits at offset
    // eight, forever. An operand naming it is eight bits, and one saying
    // otherwise describes a register that does not exist.
    let source = include_str!("../examples/regslice.axisl");
    let document = parse_document(source).expect("parse regslice");
    validate_document(&document).expect("regslice validates");

    let wrong = source.replace(
        "(rd x86_r8hi i8 out) (rs x86_r8hi i8 in)",
        "(rd x86_r8hi i64 out) (rs x86_r8hi i64 in)",
    );
    assert_ne!(wrong, source, "the fixture still contains the operand");
    let document = parse_document(&wrong).expect("parse the injected form");
    let error = validate_document(&document).expect_err("64 bits is not an 8-bit view");
    assert!(
        error.to_string().contains("is a 8-bit view of its register"),
        "the width is named against the window: {error}"
    );

    // And *not* a rule about operands being narrower than their register in
    // general. An operand may name an element rather than a register -- SVE's
    // `z0.b` is a byte of a scalable vector -- where the width comes from the
    // instruction and not from the class. One rule for both was wrong six
    // times before it was two.
    let sve = parse_document(include_str!("../examples/sve.axisl")).expect("parse sve");
    validate_document(&sve).expect("element widths are not window widths");
}

#[test]
fn an_operand_narrower_than_its_register_says_which_kind_it_is() {
    // A fixed-width vector's operand names lanes, and says so. A scalable
    // instruction says the same thing by construction, so only these need the
    // marker.
    let source = include_str!("../examples/simd_fp_lanes.axisl");
    let document = parse_document(source).expect("parse simd_fp_lanes");
    validate_document(&document).expect("a marked element validates");

    // ⚠️ `reg128`, because the corpus names one file now: its 64-bit lane
    // instructions used to say `reg` while its 128-bit ones said `reg128`, so
    // one register file was addressed at two strides and `v1` was slot 1 to
    // half the description and slots 2-3 to the other half.
    let bare = source.replace("(vd reg128 i64 out element)", "(vd reg128 i64 out)");
    assert_ne!(bare, source, "the fixture still marks its elements");
    let document = parse_document(&bare).expect("parse the injected form");
    let error = validate_document(&document)
        .expect_err("64 bits of a 128-bit register is neither a window nor a register");
    assert!(
        error.to_string().contains("mark it `element`"),
        "the two ways out are named: {error}"
    );

    // The legacy frontend accepts `name:kind:width:role:element` for the
    // same reason -- a corpus written in one form has to be writable in the
    // other, and ten operands stayed wrong in the legacy form of a corpus
    // whose Lisp form had been fixed. No corpus uses it in both forms yet,
    // so the frontend-equivalence gate is what would catch them drifting.
}

#[test]
fn a_second_register_file_is_as_wide_as_itself_not_as_the_word() {
    // RISC-V's `f` file is not sized by XLEN. FLEN comes from which extensions
    // are present, so with `D` the `f` registers are 64 bits on RV32 exactly as
    // on RV64 -- which is why a single is NaN-boxed into the high bits rather
    // than stored narrow.
    //
    // The width rule used to exempt every class at a nonzero offset, because a
    // second file had no declared width to check against. Under that exemption
    // RV32's F instructions named 32-bit `f` registers and its D instructions
    // named 64-bit ones: one file, two widths, one description. Nothing caught
    // it, because every executor stores 64-bit slots whatever the description
    // claims, so the narrow reads agreed with the wide ones.
    for corpus in [
        include_str!("../examples/rv32i.axisl"),
        include_str!("../examples/rv64i.axisl"),
    ] {
        let document = parse_document(corpus).expect("parse a RISC-V corpus");
        validate_document(&document).expect("one file, one width");

        let widths: BTreeSet<u32> = document
            .instructions
            .iter()
            .flat_map(|instruction| &instruction.operands)
            .filter(|operand| operand.kind == "rv_fpr")
            .map(|operand| operand.width)
            .collect();
        assert_eq!(
            widths,
            BTreeSet::from([64]),
            "an f register is FLEN bits wherever it is named"
        );
    }

    // A declared file width has no way out -- it is not a window and not an
    // element -- so it is checked exactly, and too wide fails with too narrow.
    let source = include_str!("../examples/rv32i.axisl");
    for injected in ["(rd rv_fpr i32 out)", "(rd rv_fpr i128 out)"] {
        let bent = source.replacen("(rd rv_fpr i64 out)", injected, 1);
        assert_ne!(bent, source, "the corpus still names 64-bit f registers");
        let document = parse_document(&bent).expect("parse the injected form");
        let error = validate_document(&document)
            .expect_err("an f register is neither 32 nor 128 bits");
        assert!(
            error.to_string().contains("is a 64-bit register file"),
            "the file's own width is what it is measured against: {error}"
        );
    }
}

#[test]
fn a_writeback_store_and_an_atomic_are_one_node_each() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // A store that advances its base is `pre_store`/`post_store` -- one
    // result, the updated base, and three operands. Which of the two it is
    // comes from the *order* of the effects: pre-index updates the base before
    // the store, post-index after, and both write the same two places with the
    // same two expressions.
    assert!(
        td.contains(
            "def : Pat<(post_store (i64 A64_GPR64Regs:$RT), A64_GPR64SPRegs:$RN_tied, simm9i64:$IMM),\n          (STR_X_POST A64_GPR64Regs:$RT, A64_GPR64SPRegs:$RN_tied, simm9i64:$IMM)>;"
        ),
        "a post-index store selects"
    );
    assert!(
        td.contains("def : Pat<(pre_store (i64 A64_GPR64Regs:$RT), A64_GPR64SPRegs:$RN_tied,"),
        "and a pre-index one, from the same two effects in the other order"
    );
    // The offset is signed, which only the base update says -- neither of the
    // two shapes that read extensions before this one could see it.
    assert!(
        td.contains(r#"A64_GPR64SPRegs:$RN_tied, simm9i64:$IMM), "str_x_post""#),
        "the offset gets the range its behavior states"
    );

    // An atomic read-modify-write is one node for both halves, and its result
    // is the *old* value -- which is what the register half of the description
    // holds. The operation is read from the stored expression by the function
    // the IR emitter has always used for it.
    assert!(
        td.contains(
            "def : Pat<(i32 (atomic_swap_i32_monotonic A64_GPR64SPRegs:$RN, A64_GPR32Regs:$RS)),\n          (SWP_W A64_GPR32Regs:$RS, A64_GPR64SPRegs:$RN)>;"
        ),
        "a swap is atomic_swap, and the root carries its type"
    );
    // The node's name is the *memory* width and the operands keep the
    // register's. A byte atomic in a `W` register is `atomic_load_add_i8` over
    // 32-bit operands, which is how LLVM's own AArch64 backend writes it --
    // requiring the two to agree declined 144 of these.
    assert!(
        td.contains("(i32 (atomic_load_add_i8_monotonic A64_GPR64SPRegs:$RN, A64_GPR32Regs:$RS))"),
        "a byte atomic keeps its register width"
    );
    // The ordering combines the two halves the description states separately:
    // acquire is about the read and release about the write, so AArch64's four
    // suffixes fall out rather than being tabulated.
    for (mnemonic, ordering) in [
        ("LDADD_W", "monotonic"),
        ("LDADDA_W", "acquire"),
        ("LDADDL_W", "release"),
        ("LDADDAL_W", "acq_rel"),
    ] {
        assert!(
            td.contains(&format!("(atomic_load_add_i32_{ordering} ")),
            "{mnemonic} is an add ordered {ordering}"
        );
    }
}

#[test]
fn a_register_extended_from_its_own_width_widens() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // `UMADDL` multiplies two `W` registers into an `X`. That is the one
    // extension that is a real width change -- an extension *inside* one
    // width is a mask or a `sext_inreg`, which is what `a64_extend_reg`
    // reduces to over a 64-bit register whose low bits are taken. The
    // difference is whether the register named is narrower than the pattern.
    assert!(
        td.contains(
            "def : Pat<(i64 (add A64_GPR64Regs:$RA, (mul (zext A64_GPR32Regs:$RN), (zext A64_GPR32Regs:$RM)))),\n          (UMADDL A64_GPR32Regs:$RN, A64_GPR32Regs:$RM, A64_GPR64Regs:$RA)>;"
        ),
        "a widening multiply extends each source by its own class"
    );
    assert!(
        td.contains("(mul (sext A64_GPR32Regs:$RN), (sext A64_GPR32Regs:$RM))"),
        "the signed form is a sext"
    );
    // The mirror: a register *wider* than the pattern is a truncation.
    // `ADD_W_EXT` adds an extended `X` register to a `W` one and writes a `W`,
    // so the 64-bit source comes down first. The register keeps its own class
    // -- it is the value that narrows, not the register file.
    assert!(
        td.contains("(shl (and (trunc A64_GPR64Regs:$RM), (i32 65535)), uimmlt5i32:$IMM3)"),
        "a register wider than the pattern is truncated"
    );

    // And the in-place extension is untouched: still a mask, over the wide
    // register it actually names.
    assert!(
        td.contains("(shl (and A64_GPR64Regs:$RM, (i64 255)), uimmlt5i64:$IMM3)"),
        "an extension inside one width is still a mask"
    );

    // An ordered load is refused for its ordering, not for the width of an
    // address the load path handles. A decline is only useful if it names the
    // cause: `LDAR` was declining as "mixed operand widths" because the shape
    // check refused to see it as a load at all.
    assert!(
        td.contains("// LDAR_W: an ordered load is not a plain `load` node; no pattern"),
        "an ordered load names its ordering"
    );
}

#[test]
fn an_extension_kind_selector_gets_one_pattern_per_kind() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // `a64_extend_reg` chooses a source width *and* a signedness -- `8 <<
    // (option & 3)` bits, sign-extended when bit 2 is set -- and then shifts.
    // Pinned, that is an extension of a register and a shift, both ordinary
    // DAG nodes. Unpinned it is neither, which is why the whole
    // extended-register family had no pattern.
    //
    // Unsigned is a mask and signed is `sext_inreg`, which is what the
    // builder already made of an extension over a register.
    assert!(
        td.contains("(add A64_GPR64SPRegs:$RN, (shl (and A64_GPR64Regs:$RM, (i64 255)), uimmlt5i64:$IMM3))"),
        "UXTB is a mask"
    );
    assert!(
        td.contains("(add A64_GPR64SPRegs:$RN, (shl (sext_inreg A64_GPR64Regs:$RM, i8), uimmlt5i64:$IMM3))"),
        "SXTB is a sign extension in place"
    );

    // A helper's selector enumerates its whole field, because it is a choice
    // by construction -- `option` is three bits and needs all eight. The
    // two-bit bound is for an operand that merely appears in a shift amount.
    assert!(
        td.contains("(ADD_X_EXT A64_GPR64SPRegs:$RN, A64_GPR64Regs:$RM, (i64 7), uimmlt5i64:$IMM3)>;")
            || td.contains("(ADD_X_EXT A64_GPR64SPRegs:$RN, A64_GPR64Regs:$RM, (i64 3), uimmlt5i64:$IMM3)>;"),
        "the widest option is reached"
    );

    // At 64 bits UXTX and SXTX extend nothing and reduce to one DAG. That is
    // the architecture, not a mistake: the machine has two encodings of one
    // behavior, and ISel wants one pattern.
    let x_forms = td
        .lines()
        .filter(|line| {
            line.starts_with("def : Pat<")
                && line.contains(
                    "(i64 (add A64_GPR64SPRegs:$RN, (shl A64_GPR64Regs:$RM, uimmlt5i64:$IMM3)))",
                )
        })
        .count();
    assert_eq!(x_forms, 1, "one DAG per behavior, not one per encoding of it");
}

#[test]
fn a_scale_that_is_an_operand_specialises_before_it_scales() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // AArch64's `ADD` immediate shifts by `sh * 12`, where `sh` chooses
    // between shifting by nothing and by twelve. That is a selector, said in
    // the open rather than through a helper -- pin it and the scale is a
    // constant, which is a form that has a pattern.
    assert!(
        td.contains(
            "def : Pat<(i64 (add A64_GPR64SPRegs:$RN, uimm12i64:$IMM)),\n          (ADD_X_IMM_SP A64_GPR64SPRegs:$RN, uimm12i64:$IMM, (i64 0))>;"
        ),
        "the unshifted form takes the immediate as it is"
    );
    // And the shifted form scales by 4096 and divides it back. Computing the
    // scale once for the whole instruction gave this form the other's, which
    // is a pattern selecting `sh = 1` for a plain `rn + imm` -- multiplying
    // the offset by 4096. Only the golden model named it.
    assert!(
        td.contains(
            "def : Pat<(i64 (add A64_GPR64SPRegs:$RN, uimm12s4096i64:$IMM)),\n          (ADD_X_IMM_SP A64_GPR64SPRegs:$RN, (Div4096XForm uimm12s4096i64:$IMM), (i64 1))>;"
        ),
        "the shifted form scales and divides back"
    );

    // `sh` has no decode constraint; its one-bit field enumerates it. The
    // bound is what keeps a twelve-bit immediate from becoming four thousand
    // patterns -- an operand a pattern specialises over is a choice, and a
    // choice is small.
    assert!(
        !td.contains("uimm12i64:$IMM, (i64 2))"),
        "a one-bit selector has two values and no more"
    );
}

#[test]
fn a_load_is_typed_by_its_result_and_addressed_by_its_base() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // AArch64 reads a byte into a `W` register through an `X` address. One
    // width for both declined that whole family -- 52 instructions on this
    // seed -- for a mismatch that is the architecture rather than a limit of
    // the builder. The result is the root's type; the address is its own.
    assert!(
        td.contains(
            "def : Pat<(i32 (zextloadi8 (add A64_GPR64SPRegs:$RN, uimm12i64:$IMM))),\n          (LDRB_W_UNSIGNED A64_GPR64SPRegs:$RN, uimm12i64:$IMM)>;"
        ),
        "a W-register load addresses through an X register"
    );
    // The offset is typed at the address's width in the operand list too, or
    // the list and the pattern name different predicates for one operand --
    // which tblgen reports as an empty type set, naming the pattern and never
    // the operand list that caused it.
    assert!(
        td.contains("(ins A64_GPR64SPRegs:$RN, uimm12i64:$IMM), \"ldrb_w_unsigned\""),
        "the operand list agrees with the pattern"
    );

    // Every mixed-width instruction on this corpus now has a pattern or a
    // reason that is not its widths. The check is that no decline says
    // "mixed", not that some particular one does -- a decline asserted by name
    // outlives the gap it described, which is how a stale census happens.
    assert!(
        !td.contains("mixed or non-standard operand widths"),
        "no instruction is declined for its widths alone"
    );

    // The intrinsic hints state the root's type as well. Without it the file
    // never says what a pattern *produces*, and a load whose address is wider
    // than its result was read at the address's width -- 16 patterns
    // disagreeing with the golden model for exactly that reason.
    let patterns = emit_llvm_patterns(&document);
    assert!(patterns.contains("def : Pat<(i32 (zextloadi8 (add i64:$rn, uimm12i64:$imm))),"));
}

#[test]
fn a_store_has_no_result_and_still_has_a_pattern() {
    let document = parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i");
    validate_document(&document).expect("validate rv32i");
    let td = emit_llvm_target(&document);

    // A store is the load's mirror and differs in the two ways that matter: no
    // result, so the `Pat` has no root type and none of the single-result
    // machinery applies, and two children rather than one -- LLVM spells it
    // `(store value, address)`, value first.
    assert!(
        td.contains(
            "def : Pat<(store (i32 RV_GPRRegs:$RS2), (add RV_GPRRegs:$RS1, simm12i32:$IMM)),\n          (SW RV_GPRRegs:$RS1, RV_GPRRegs:$RS2, simm12i32:$IMM)>;"
        ),
        "a store selects, value first"
    );
    // A narrow store is `truncstoreiN` -- the combiner folds the truncate into
    // the store long before selection, so a truncate and a store would be a
    // pattern that never fires.
    assert!(
        td.contains("def : Pat<(truncstorei8 (i32 RV_GPRRegs:$RS2),"),
        "a narrow store is a truncating store"
    );

    // The stored value carries its type explicitly. A store has no result, so
    // nothing else pins one, and `rv_gpr` holds both i32 and i64 here because
    // the document names operands of both -- tblgen reports that as "Could not
    // infer all types in pattern" rather than guessing.
    assert!(
        !td.contains("def : Pat<(store RV_GPRRegs:"),
        "the stored value is typed"
    );

    // `SW` sign extends its offset, and only its behavior says so -- which
    // `pure_value_semantics` declines to look at, because a store has no
    // value. Read from the store's own two expressions instead, or the
    // operand list and the pattern disagree about which range the offset has.
    assert!(
        td.contains(r#"(ins RV_GPRRegs:$RS1, RV_GPRRegs:$RS2, simm12i32:$IMM), "sw""#),
        "a store's offset gets the range its behavior states"
    );

    // There used to be an assertion here that `FSD` declined because its base
    // register was 64 bits in a 32-bit ISA. That decline was real, and so was
    // the rule behind it -- but the *cause* was a defect in the corpus rather
    // than a property of the machine: RV32I declared the integer operands of
    // nine D-extension instructions at 64 bits, contradicting its own
    // `x[32]:i32`. Fixing the description removed the decline, and the
    // assertion failed.
    //
    // A decline asserted by name outlives the gap it described. What is
    // durable is that no instruction is refused for an address the machine
    // cannot form, which is a statement about every corpus rather than about
    // one instruction that happened to be wrong.
    assert!(
        !td.contains("the machine's word is"),
        "no address is wider than the machine that forms it"
    );

    // And the intrinsic hints spell the same DAG, or the target's store
    // patterns have nothing to be checked against -- which is how the load
    // patterns went unproved.
    let patterns = emit_llvm_patterns(&document);
    assert!(patterns.contains("(store (i32 i32:$rs2), (add i32:$rs1, simm12i32:$imm))"));
}

#[test]
fn an_optional_isa_is_a_subtarget_feature() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // A document can describe more than one ISA, and they are not peers: the
    // first declared is the machine that is always there, the rest are present
    // only on a subtarget that has them. The decoder already treats an ISA as a
    // namespace for the same reason.
    assert!(
        td.contains("def HasACCELERATOR_SCALAR64 : Predicate<\"Subtarget->hasACCELERATOR_SCALAR64()\">;"),
        "the optional ISA is declared as a feature predicate"
    );
    assert!(
        td.contains("def ACCEL_LSLV64 :") && td.contains("  let Predicates = [HasACCELERATOR_SCALAR64];\n"),
        "its instructions carry the predicate"
    );
    // And so do its patterns -- selecting an instruction the subtarget does
    // not have is the failure this prevents.
    assert!(
        td.contains("let Predicates = [HasACCELERATOR_SCALAR64] in\ndef : Pat<"),
        "its patterns carry the predicate too"
    );

    // `LSLV_X` and `ACCEL_LSLV64` claimed one DAG, which is why the base ISA
    // lost its pattern. Choosing the accelerator is a lowering decision -- the
    // description states it as a `deflowering` with a `requires` a Pat cannot
    // express -- so ISel takes the instruction that is always present.
    assert!(
        td.contains("(LSLV_X A64_GPR64Regs:$RN, A64_GPR64Regs:$RM)>;"),
        "the always-present instruction keeps the pattern"
    );
    assert!(
        !td.contains("is also"),
        "no left-hand side is claimed twice on this corpus"
    );

    // A document with one ISA declares no features at all.
    let rv32i =
        parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i");
    validate_document(&rv32i).expect("validate rv32i");
    assert!(
        !emit_llvm_target(&rv32i).contains("SubtargetFeature"),
        "one ISA is not an optional one"
    );
}

#[test]
fn a_flag_setting_form_does_not_take_the_plain_form_s_pattern() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // `ADD` and `ADDS` compute the same expression and differ only in NZCV,
    // which `pure_value_semantics` sets aside as a clobber -- so their value
    // patterns are identical. The one that writes no state is the pattern;
    // selecting `ADDS` where a plain add was meant would destroy the flags.
    assert!(
        td.contains("(ADD_X_SHIFT0 A64_GPR64Regs:$RN, A64_GPR64Regs:$RM, (i64 0), uimm6i64:$IMM6)>;"),
        "the plain form keeps the pattern"
    );
    assert!(
        td.contains("// ADDS_X_SHIFT0: (i64 (add A64_GPR64Regs:$RN, (shl A64_GPR64Regs:$RM, uimm6i64:$IMM6))) is ADD_X_SHIFT0's pattern, which writes no state; no pattern"),
        "the flag-setting form is declined by name"
    );

    // `EXTR` is a funnel shift, and its rotate amount reduces to arithmetic
    // over its own immediate -- a node with no register in it, which the
    // combiner folds long before selection. A pattern on it would match
    // nothing, forever, and read as coverage.
    assert!(
        td.contains("// EXTR_X: `and` is constant-folded before selection; no pattern"),
        "a constant-folded node is declined rather than emitted dead"
    );
}

#[test]
fn a_scaled_offset_matches_the_value_and_encodes_the_quotient() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // AArch64's unsigned-offset `LDR` addresses `rn + imm * 8` and encodes the
    // twelve-bit `imm`. Selection sees the *byte* offset, because that is what
    // a `load` node's address is -- so the pattern matches a multiple of eight
    // and the instruction is handed the quotient.
    assert!(
        td.contains(
            "def : Pat<(i64 (load (add A64_GPR64SPRegs:$RN, uimm12s8i64:$IMM))),\n          (LDR_X_UNSIGNED A64_GPR64SPRegs:$RN, (Div8XForm uimm12s8i64:$IMM))>;"
        ),
        "the scaled load matches the offset and divides it back"
    );
    // Both halves of that are needed. The predicate refuses an offset the
    // instruction cannot represent -- an odd one is not encodable at all, and
    // dividing it would silently address somewhere else.
    assert!(
        td.contains("def uimm12s8i64 : Operand<i64>, ImmLeaf<i64, [{return (Imm & 7) == 0 && isUInt<12>((Imm >> 3));}]>;"),
        "the predicate states divisibility and range"
    );
    assert!(td.contains("def Div8XForm : SDNodeXForm<imm, [{"), "the transform is declared");

    // The instruction's own operand list is untouched: it still takes the
    // field. The scale lives in the pattern, so the MC layer and the encoder
    // differential are not asked a different question than before.
    assert!(
        td.contains("(ins A64_GPR64SPRegs:$RN, uimm12i64:$IMM), \"ldr_x_unsigned\""),
        "the encoded operand is still the field"
    );

    // And the intrinsic hints spell the same DAG, or the gate that compares
    // the two files has nothing to compare.
    let patterns = emit_llvm_patterns(&document);
    assert!(patterns.contains("(load (add i64:$rn, uimm12s8i64:$imm))"));
}

#[test]
fn a_selector_operand_gets_one_pattern_per_value_it_encodes() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // `a64_shift_reg` switches on an operand, and there is no SelectionDAG
    // node for "one of four shifts" -- so while that operand is live the
    // instruction has no pattern. It has one per shift kind, and the decode
    // constraint says which kinds this instruction encodes.
    for (node, value) in [("shl", 0), ("srl", 1), ("sra", 2)] {
        assert!(
            td.contains(&format!(
                "def : Pat<(i64 (add A64_GPR64Regs:$RN, ({node} A64_GPR64Regs:$RM, uimm6i64:$IMM6))),\n          (ADD_X_SHIFT0 A64_GPR64Regs:$RN, A64_GPR64Regs:$RM, (i64 {value}), uimm6i64:$IMM6)>;"
            )),
            "the {node} form is selected with shift = {value}"
        );
    }
    // And no ROR form: `a64_shifted_reg` permits `shift < 3`, because that
    // instruction genuinely cannot encode one. Nothing in the emitter knows
    // that -- it reads the constraint.
    assert!(
        !td.contains("(ADD_X_SHIFT0 A64_GPR64Regs:$RN, A64_GPR64Regs:$RM, (i64 3)"),
        "a value the decoder rejects gets no pattern"
    );

    // The same specialisation in the intrinsic hints, over the same list. If
    // only one file specialised, the other would have nothing to check these
    // against -- and the pinned value travels in the argument list so the
    // golden model is asked about the form the pattern is actually for.
    let patterns = emit_llvm_patterns(&document);
    assert!(patterns.contains("(int_axis_add_x_shift0 $rn, $rm, 0, $imm6)>;"));
    assert!(patterns.contains("(int_axis_add_x_shift0 $rn, $rm, 2, $imm6)>;"));
    assert!(!patterns.contains("(int_axis_add_x_shift0 $rn, $rm, 3, $imm6)>;"));
}

#[test]
fn immediate_predicates_narrow_to_what_the_decoder_accepts() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // A field says how many bits; a decode constraint says which values. The
    // shifted-register forms hold a shift kind in two bits, so the field
    // permits four -- and `a64_shifted_reg` permits three, because that
    // instruction encodes LSL, LSR and ASR and not ROR. Taking the field alone
    // claims an encoding the decoder rejects.
    assert!(
        td.contains("def uimmlt3i64 : Operand<i64>, ImmLeaf<i64, [{return Imm >= 0 && Imm < 3;}]>;"),
        "the constraint narrows the field"
    );
    assert!(
        td.contains("uimmlt3i64:$SHIFT"),
        "and types the operand it constrains"
    );
    // Not every bound is a power of two: `a64_extended_reg` permits `amount <
    // 5`, and a `uimm3` would accept 5, 6 and 7.
    assert!(td.contains("def uimmlt5i64 :"), "a bound that is not a width");
    // Nor is every legal set a range. The extend kinds are enumerated with
    // holes, which no bit width describes without admitting what lies between.
    assert!(
        td.contains(
            "def imm2_3_6_7i64 : Operand<i64>, ImmLeaf<i64, \
             [{return Imm == 2 || Imm == 3 || Imm == 6 || Imm == 7;}]>;"
        ),
        "an enumerated set with holes"
    );
}

#[test]
fn a_mask_the_operand_predicate_already_enforces_is_dropped() {
    let document =
        parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i example");
    validate_document(&document).expect("validate rv32i example");
    let td = emit_llvm_target(&document);

    // A shift amount is masked to the register width by the machine, and the
    // description says so. When the amount is a *register* that mask is real
    // and LLVM writes the same DAG.
    assert!(
        td.contains("def : Pat<(i32 (shl RV_GPRRegs:$RS1, (and RV_GPRRegs:$RS2, (i32 31)))),"),
        "a register shift keeps its mask"
    );
    // When it is an immediate it is not: `uimm5` already bounds the operand
    // below 32, and LLVM folds `(and 5, 31)` to `5` long before selection, so
    // a pattern demanding the `and` node matches nothing. All three of SLLI,
    // SRLI and SRAI carried one that could never fire.
    assert!(
        td.contains("def : Pat<(i32 (shl RV_GPRRegs:$RS1, uimm5i32:$RS2)),\n          (SLLI "),
        "an immediate shift drops a mask its predicate enforces"
    );
    assert!(!td.contains("(and uimm5i32:"), "no predicate-enforced mask survives");
}

#[test]
fn llvm_target_declares_the_state_an_instruction_writes() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let td = emit_llvm_target(&document);

    // Scalar architectural state becomes a register. Nothing in the rule knows
    // what a flag is: an ISA declares scalar state, a behavior writes it, and
    // `nzcv`, `fpsr` and the exclusive-monitor state all arrive the same way.
    assert!(td.contains("def NZCV : Register<\"nzcv\">"), "state is a register");
    assert!(td.contains("def FPSR : Register<\"fpsr\">"), "not just the flags");
    assert!(
        td.contains("def NZCVState : RegisterClass<\"AARCH64_TRANSLATION_SEED\", [i32], 32, (add NZCV)>;"),
        "a four-bit state still needs a legal class type, as it does in LLVM's own AArch64"
    );

    // A write becomes an implicit def, which is what makes a value pattern on
    // a flag-setting instruction honest rather than a silent clobber.
    let adds = td
        .split("def ADDS_X_IMM : ")
        .nth(1)
        .expect("ADDS_X_IMM is emitted");
    assert!(
        adds[..adds.find("\n}").unwrap_or(adds.len())].contains("let Defs = [NZCV];"),
        "a state write is declared"
    );
    // A read becomes an implicit use: ADC takes its carry from the flags.
    let adc = td.split("def ADC_X : ").nth(1).expect("ADC_X is emitted");
    assert!(
        adc[..adc.find("\n}").unwrap_or(adc.len())].contains("let Uses = [NZCV];"),
        "a state read is declared"
    );

    // An instruction that writes only state has no destination to select on --
    // a property of the instruction, not a limit of the inference.
    assert!(
        td.contains("behavior writes only architectural state"),
        "compares are declined by name"
    );
}

#[test]
fn llvm_immediates_carry_the_range_their_semantics_states() {
    let document =
        parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i example");
    validate_document(&document).expect("validate rv32i example");
    let td = emit_llvm_target(&document);

    // `(add i32 rs1 (sext i32 12 imm))` says the immediate is a signed 12-bit
    // value. That is a predicate on the operand, not a DAG node -- `i12` is
    // not a legal MVT, so spelling it as `sext_inreg` is untypeable, which is
    // why every addi-shaped instruction had no pattern before.
    assert!(
        td.contains("def simm12i32 : Operand<i32>, ImmLeaf<i32, [{return isInt<12>(Imm);}]>;"),
        "the range becomes an ImmLeaf predicate"
    );
    assert!(
        td.contains(
            "def : Pat<(i32 (add RV_GPRRegs:$RS1, simm12i32:$IMM)),\n          (ADDI RV_GPRRegs:$RS1, simm12i32:$IMM)>;"
        ),
        "addi selects on a predicated immediate"
    );
    // One def serves both roles, so the operand list and the pattern name the
    // same thing: a Pat supplies its RHS positionally into `InOperandList`.
    assert!(
        td.contains("(ins RV_GPRRegs:$RS1, simm12i32:$IMM), \"addi\""),
        "the operand list carries the predicate too"
    );

    // Where the semantics states no range the encoding still states one, and
    // it is not the field width. LUI's operand is a full 32-bit value of which
    // only bits 31:12 are in the instruction, so the immediates it can encode
    // are exactly those whose low twelve bits are clear.
    assert!(
        td.contains(
            "def maskimmfffff000i32 : Operand<i32>, ImmLeaf<i32, \
             [{return ((uint64_t)Imm & ~(uint64_t)4294963200ULL) == 0;}]>;"
        ),
        "the encodable set becomes a predicate"
    );
    assert!(
        td.contains("def LUI : RV32IInst<(outs RV_GPRRegs:$RD), (ins maskimmfffff000i32:$IMM)"),
        "and types the operand"
    );
    // A branch offset is the same rule reaching a different answer: the target
    // is two-byte aligned, so bit 0 is not encoded and cannot be set.
    assert!(
        td.contains("def maskimm1ffei32 :"),
        "an unencoded low bit is part of the encodable set"
    );

    // The same predicate in the intrinsic hints, from the same list -- an
    // immediate's range is a fact about the instruction, not about the file.
    assert!(emit_llvm_patterns(&document)
        .contains("def : Pat<(i32 (add i32:$rs1, simm12i32:$imm)),"));
}

#[test]
fn llvm_selection_patterns_map_ir_to_intrinsics() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let td = emit_llvm_patterns(&document);

    assert!(td.contains("// Generated by AXIS. schema: axis.llvm-patterns.v1"));
    // Operators map to their ISD node names; `not` becomes `(xor x, -1)`.
    assert!(td.contains(
        "def : Pat<(i32 (and i32:$rs1, (xor i32:$rs2, -1))),\n          (int_axis_andn $rs1, $rs2)>;"
    ));
    assert!(
        td.contains("def : Pat<(i32 (sra i32:$rs1, i32:$rs2)),\n          (int_axis_srax $rs1, $rs2)>;")
    );
    assert!(td.contains("(rotl i32:$rs1, i32:$rs2)"));
    assert!(td.contains("(smin i32:$rs1, i32:$rs2)"), "min -> smin");
    assert!(td.contains("(umax i32:$rs1, i32:$rs2)"), "maxu -> umax");
    assert!(td.contains("(ctlz i32:$rs1)"), "clz -> ctlz");
    // Extends lower to sext_inreg / mask, not the (absent) not/ext ISD nodes.
    assert!(td.contains("(sext_inreg i32:$rs1, i8)"), "sext.b");
    // The mask carries its type: TableGen cannot always infer a constant's
    // from context, and the target's own patterns are run through real
    // generators that say so.
    assert!(td.contains("(and i32:$rs1, (i32 65535))"), "zext.h mask");

    // FMA is the flagship composite: (add (mul rs1 rs2) rs3) -> the intrinsic.
    let rvmt =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&rvmt).expect("validate rvmt example");
    let rvmt_td = emit_llvm_patterns(&rvmt);
    assert!(rvmt_td.contains(
        "def : Pat<(i32 (add (mul i32:$rs1, i32:$rs2), i32:$rs3)),\n          (int_axis_pce_fma_i $rs1, $rs2, $rs3)>;"
    ));
    // Effectful / free-text instructions carry no pattern, only a comment. The
    // reason names both places a description can state what an instruction
    // computes, because reading only the first reported 765 of AArch64's
    // instructions as saying nothing when they state themselves as behaviors.
    assert!(rvmt_td.contains("// TLS_LOAD: no formal_semantics and no behavior; no pattern"));
    assert!(!rvmt_td.contains("(int_axis_tls_load"));
}

#[test]
fn whether_a_barrier_has_an_option_is_the_kinds_own() {
    // `FENCE` names a predecessor and a successor set -- eight bits of option.
    // `FENCE.I` names nothing: it orders instruction *fetch* against prior
    // writes, which is the pipeline rather than the memory model, and its
    // immediate field is reserved and zero. Requiring an option of both would
    // have meant writing a zero that claims a field the encoding does not
    // have, so the table decides, in both directions.
    let document = parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i");
    validate_document(&document).expect("validate rv32i");

    // What comes back out is what went in, or a corpus cannot be rewritten
    // from its own emitted form.
    let round_tripped = emit_lisp(&document);
    assert!(round_tripped.contains("(barrier fence option)"), "an option is kept");
    assert!(round_tripped.contains("(barrier fence_i)"), "an absent option stays absent");

    let source = include_str!("../examples/rv32i.axisl");
    let too_many = source.replace("(barrier fence_i)", "(barrier fence_i 0)");
    assert_ne!(too_many, source, "the corpus still writes the bare form");
    let error = parse_document(&too_many)
        .err()
        .map(|error| error.to_string())
        .or_else(|| {
            parse_document(&too_many)
                .ok()
                .and_then(|document| validate_document(&document).err())
                .map(|error| error.to_string())
        })
        .expect("an option on a kind that has none is rejected");
    assert!(
        error.contains("no option"),
        "the reason names the kind's own rule: {error}"
    );

    let too_few = source.replace("(barrier fence option)", "(barrier fence)");
    assert_ne!(too_few, source, "the corpus still writes fence's option");
    let error = parse_document(&too_few)
        .err()
        .map(|error| error.to_string())
        .expect("a kind that has an option must be given one");
    assert!(
        error.contains("takes an option"),
        "the reason names the kind's own rule: {error}"
    );

    // The encoding is the one RISC-V specifies for Zifencei, fully fixed --
    // there is no field left to vary.
    let decode = emit_decode_table_json(&document);
    assert!(
        decode.contains("\"mnemonic\": \"FENCE_I\"")
            && decode
                .split("\"mnemonic\": \"FENCE_I\"")
                .nth(1)
                .is_some_and(|rest| {
                    let entry = rest.split('}').next().unwrap_or("");
                    entry.contains("\"match\": \"0x0000100f\"")
                        && entry.contains("\"mask\": \"0xffffffff\"")
                }),
        "fence.i decodes as 0x0000100f"
    );
}

#[test]
fn a_branch_target_is_as_wide_as_the_machine_not_as_its_widest_operand() {
    // Behavior widths are resolved at the frontend boundary, where an
    // instruction has been parsed but the ISA it names has not been looked up
    // -- so the widest operand stands in for the machine's word. That guess is
    // wrong exactly when no operand is as wide as the machine, and a branch is
    // the clearest case: AArch64's `B` carries one 26-bit immediate, so
    // `max(26, 32)` called a 64-bit machine 32 bits and every branch target
    // wrapped at four gigabytes.
    //
    // A PC below 2^32 agrees either way, which is every PC a small fixture
    // picks, so nothing short of a wide random PC could see it.
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse aarch64 seed");
    validate_document(&document).expect("validate aarch64 seed");
    let table = emit_lift_table_json(&document);

    for branch in ["\"mnemonic\": \"B\"", "\"mnemonic\": \"BL\"", "\"mnemonic\": \"CBNZ_W\""] {
        let entry = table
            .split(branch)
            .nth(1)
            .expect("the corpus still describes this branch");
        let setpc = entry
            .find("\"kind\": \"setpc\"")
            .expect("the branch still sets the pc");
        let width = entry[setpc..]
            .split("\"eval_width\": ")
            .nth(1)
            .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
            .expect("a setpc effect states the width it is evaluated at");
        assert_eq!(
            width, "64",
            "{branch} targets a 64-bit machine's address space"
        );
    }

    // `CBNZ_W` is in that list on purpose: its widest operand is a 32-bit
    // register, so it was wrong for the same reason `B` was, while `CBNZ_X`
    // happened to be right. Nothing about a branch's own operands can settle
    // this -- only the ISA can.
}

#[test]
fn lift_table_and_python_carry_decode_and_extraction() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");

    let table = emit_lift_table_json(&document);
    assert!(table.contains("\"schema\": \"axis.lift-table.v1\""));
    assert!(table.contains("\"mnemonic\": \"ANDN\""));
    assert!(table.contains("\"match\": \"0x0200000b\""));
    assert!(table.contains("\"mask\": \"0xfe00707f\""));
    assert!(table.contains("\"liftable\": true"));
    assert!(table.contains("\"writes\": [\"rd\"]"));
    assert!(table.contains("\"reads\": [\"rs1\", \"rs2\"]"));
    // Register operands extract from a single 5-bit instruction slice.
    assert!(table.contains("\"fields\": [{\"insn_lo\": 20, \"op_lo\": 0, \"width\": 5}]"));
    // The typed semantics AST rides along for binding into the lift.
    assert!(table.contains("\"op\": \"and\", \"type\": \"i32\""));

    let py = emit_lift_python(&document);
    assert!(py.contains("AXIS_SCHEMA = \"axis.lift-python.v1\""));
    assert!(py.contains("\"mnemonic\": \"ANDN\","));
    assert!(py.contains("\"match\": 0x0200000b,"));
    assert!(py.contains(
        "{\"name\": \"rs2\", \"kind\": \"reg\", \"role\": \"in\", \"width\": 32, \"fields\": [(20, 0, 5)]}"
    ));
    assert!(py.contains("\"semantics\": \"(and i32 rs1 (not i32 rs2))\","));
    assert!(py.contains("def lift(word, isa=None):"));
    assert!(py.contains("def decode(word, isa=None):"));

    // TLS_LOAD is fully decodable (its I-immediate extracts from bits 20..31)
    // but not liftable to semantic IR: it has no formal_semantics, so the two
    // flags disagree — decode is available, semantic binding is not.
    let rvmt =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&rvmt).expect("validate rvmt example");
    let rvmt_table = emit_lift_table_json(&rvmt);
    assert!(rvmt_table.contains("\"mnemonic\": \"TLS_LOAD\""));
    assert!(rvmt_table.contains("\"operands_encodable\": true"));
    assert!(rvmt_table.contains("\"liftable\": false"));
    assert!(rvmt_table.contains("\"insn_lo\": 20, \"op_lo\": 0, \"width\": 12"));
    // FMA_I has full semantics and is liftable.
    assert!(rvmt_table.contains("\"mnemonic\": \"FMA_I\""));
    assert!(rvmt_table.contains("\"liftable\": true"));
}

#[test]
fn c_and_rust_lifters_carry_the_same_table() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");

    let header = emit_lift_c(&document);
    assert!(header.contains("/* schema: axis.lift-c.v1 */"));
    assert!(header.contains("AXIS_INSN_ANDN,"));
    assert!(header
        .contains("static const axis_lift_field AXIS_LIFT_FIELDS_ANDN_2[] = { { 20, 0, 5 } };"));
    assert!(header.contains("static const axis_lift_operand AXIS_LIFT_OPERANDS_ANDN[] = {"));
    // The row carries the lane facts too: which scalable instruction it is a
    // lane of, which lane, and whether it is a definedness mask sharing that
    // instruction's word. An ordinary instruction is none of those. Then the
    // ISA's state width, which this corpus declares no ISA for -- so the row
    // says 64, the width of the slot the executor holds a register in, which
    // is the value that invents no wrap -- then the two a walk over bytes
    // needs: this instruction's own ENCODING width, 32 where the state is 64,
    // and `0` for "control cannot leave the block here", which `andn` cannot.
    // Last, what the description says it COSTS: one cycle of latency, a
    // throughput of 1.0 written as thousandths because it is a rate, and the
    // functional unit it issues to -- empty here, because this corpus is an
    // extension and names no machine to issue on.
    //
    // ⚠️ The C row carries several things the Rust row does not: the costs,
    // the modes, the encoding width, whether control can leave the block, and
    // now the unit. This test's name is older than that asymmetry and
    // overstates what it checks -- it compares chosen fields, not the two
    // tables. The C row is the one a timing model reads, and it is the one
    // that grew.
    assert!(header.contains(
        "{ AXIS_INSN_ANDN, \"\", \"ANDN\", 0x0200000bu, 0xfe00707fu, 1, 3, AXIS_LIFT_OPERANDS_ANDN, \"(and i32 rs1 (not i32 rs2))\", \"\", 0u, 0, 64u, \"\", 32u, 0, 1u, 1000u, \"\" },"
    ));
    // Decode + extract entry points, keyed off the shared table.
    assert!(header.contains("static inline int axis_lift(uint32_t word, axis_lifted *out)"));
    assert!(header.contains("axis_lift_in_isa"));
    assert!(header.contains("value |= ((word >> f->insn_lo) & mask) << f->op_lo;"));

    let rust = emit_lift_rust(&document);
    assert!(rust.contains("// schema: axis.lift-rust.v1"));
    assert!(rust.contains("pub static AXIS_LIFT_TABLE: &[LiftEntry] = &["));
    assert!(rust.contains("mnemonic: \"ANDN\","));
    assert!(rust.contains("match_: 0x0200000b,"));
    assert!(rust.contains("mask: 0xfe00707f,"));
    // ⚠️ `width` is the operand's own, not the field's. The two sit beside
    // each other here -- `LiftField`'s width is how many bits the encoding
    // carries, five for a register number; the operand's is how big the value
    // is, and it is what decides whether the executors can hold it in a word.
    // The placement fields a scalable lane needs (docs/scalable_execution.md
    // §12) are zero for a scalar operand: no view, the class decides.
    // Then what a decoder consumer needs without reading the semantics: how many
    // bits the behavior sign extends (none: a register), and the register file,
    // the index a field value of 0 selects, and the index wired to zero.
    assert!(rust.contains(
        "LiftOperand { name: \"rs2\", kind: \"reg\", role: \"in\", encodable: true, derived_from: None, derived_add: 0, fixed: None, fields: &[LiftField { insn_lo: 20, op_lo: 0, width: 5 }], width: 32, register_bias: 0, stride: 0, view_offset: 0, view_width: 0, slot_base: 0, signed_bits: 0, file: \"reg\", index_offset: 0, zero_index: None },"
    ));
    // The row states its encoding width, assembly, and whether it has semantics.
    assert!(rust.contains("        bits: 32,\n        asm: \"andn $rd, $rs1, $rs2\","));
    assert!(rust.contains("        has_semantics: true,"));
    assert!(rust.contains("semantics: Some(\"(and i32 rs1 (not i32 rs2))\"),"));
    assert!(rust.contains("pub fn lift(word: u32) -> Option<Lifted> {"));
    assert!(rust.contains("value |= ((word >> field.insn_lo) & mask) << field.op_lo;"));
}

#[test]
fn aarch64_lifters_enforce_operand_dependent_decode_constraints() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&document).expect("validate AArch64 seed");

    let table = emit_lift_table_json(&document);
    assert!(table.contains("\"decode_requires\": \"a64_logical_imm(i64, n, imms)\""));
    assert!(table.contains("\"decode_requires\": \"a64_logical_imm(i32, 0, imms)\""));
    assert!(table.contains("\"decode_requires\": \"a64_shifted_reg(i64, shift, imm6)\""));
    assert!(table.contains("\"decode_requires\": \"a64_shifted_reg(i32, shift, imm6)\""));
    assert!(table.contains("\"decode_requires\": \"a64_extended_reg(imm3)\""));
    let decode_table = emit_decode_table_json(&document);
    assert!(decode_table.contains("\"decode_requires\": \"a64_logical_imm(i64, n, imms)\""));
    let decode_c = emit_decode_c(&document);
    assert!(decode_c.contains("axis_decode_constraint_ok(insn, entry->id)"));
    assert!(decode_c.contains("case AXIS_INSN_AND_X_IMM:"));
    let encode_c = emit_encode_c(&document);
    assert!(encode_c.contains("axis_encode_constraint_ok(index, operand_values)"));
    assert!(encode_c.contains("axis_encode_a64_logical_imm_valid(64u"));
    assert!(encode_c.contains("operand_values[3] < 3u && operand_values[4] < 64u"));
    assert!(encode_c.contains("operand_values[4] < 5u"));
    let roundtrip = emit_roundtrip_tests_json(&document);
    let cmn_fixture = &roundtrip[roundtrip
        .find("\"mnemonic\": \"ACCEL_CMN64_SHIFTED\"")
        .expect("CMN shifted roundtrip fixture")..];
    assert!(cmn_fixture
        .lines()
        .take(20)
        .any(|line| line.contains("\"name\": \"shift\", \"value\": 2")));

    let python = emit_lift_python(&document);
    assert!(python.contains("\"kind\": \"a64_logical_imm\""));
    assert!(python.contains("\"kind\": \"a64_shifted_reg\""));
    assert!(python.contains("\"kind\": \"a64_extended_reg\""));
    assert!(python.contains("shift < 3 and amount < constraint[\"width\"]"));
    assert!(python.contains("and _constraint_ok(word, entry)"));

    let c = emit_lift_c(&document);
    assert!(c.contains("static inline int axis_a64_logical_imm_valid("));
    assert!(c.contains("axis_lift_constraint_ok(word, &AXIS_LIFT_TABLE[i])"));
    assert!(c.contains("case AXIS_INSN_AND_X_IMM:"));
    assert!(c.contains("case AXIS_INSN_ADD_X_SHIFT0:"));
    assert!(c.contains("case AXIS_INSN_ADD_X_EXT:"));

    let rust = emit_lift_rust(&document);
    assert!(rust.contains("fn a64_logical_imm_valid("));
    assert!(rust.contains("&& constraint_ok(word, entry)"));
    assert!(rust.contains("\"AND_W_IMM\" => a64_logical_imm_valid(32, 0,"));
    assert!(rust.contains("\"ADD_X_SHIFT0\" =>"));
    assert!(rust.contains("\"ADD_X_EXT\" =>"));
}

#[test]
fn exec_python_composes_lift_and_golden() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let exec = emit_exec_python(&document);

    assert!(exec.contains("# schema: axis.exec-python.v1"));
    // Composes the two proven modules rather than duplicating either.
    assert!(exec.contains("import axis_lift"));
    assert!(exec.contains("import golden_model"));
    assert!(exec.contains("def step(word, regs, mem=None, pc=0, mode=None, isa=None, state=None):"));
    // Decode, bind register vs immediate operands, evaluate, write destination.
    assert!(exec.contains("entry = axis_lift.decode(word, isa)"));
    assert!(exec.contains("def _read_reg(regs, index, kind, stride=0, view_offset=0, view_width=0,"));
    // A placement decides which file too: one above a scalable file moves
    // with VL, so its base cannot be a constant in the class table.
    assert!(exec.contains("slot_base=None):"));
    // Register access goes through the operand, because an operand may place
    // its value inside the register the class names: an element of a scalable
    // register, whose position no compile-time class can hold.
    assert!(exec.contains("def _read_operand(regs, operand, decoded):"));
    assert!(exec.contains("_read_operand(regs, operand, decoded)"));
    assert!(exec.contains("_write_operand(regs, operand, index, result)"));
    // A scalable word is its lanes, and they all share it.
    assert!(exec.contains("lanes = [] if mode is not None else axis_lift.decode_lanes(word, isa)"));
    assert!(exec.contains("golden_model.evaluate(entry[\"mnemonic\"], *inputs)"));
    assert!(exec
        .contains("def run(words, regs=None, mem=None, pc=0, mode=None, isa=None, state=None):"));
    // The runtime is generic over the co-emitted tables (document-independent).
    let empty = parse_document(
        "(axis-module e\n  (version \"1.0\")\n  (target rvmt)\n  (definstruction i\n    (mnemonic I) (opcode 11) (func3 0) (func7 0)))\n",
    )
    .expect("parse minimal");
    assert_eq!(emit_exec_python(&empty), exec);
}

#[test]
fn lisp_let_and_if_lower_across_semantic_backends() {
    let document = parse_document(include_str!("../examples/lisp_semantics.axisl"))
        .expect("parse Lisp semantics example");
    validate_document(&document).expect("validate Lisp semantics example");

    let c = emit_semantics_c(&document);
    assert!(c.contains("(rs1) != 0u ?"));
    assert!(c.contains("rs2 + rs3"));
    assert!(c.contains("rs2 - rs3"));
    assert!(!c.contains("let"));

    let rust = emit_semantics_rust(&document);
    assert!(rust.contains("if rs1 != 0"));

    let smt = emit_smt2(&document);
    assert!(smt.contains("(ite (distinct rs1 (_ bv0 32))"));

    let llvm = emit_llvm_ir(&document);
    assert!(llvm.contains("icmp ne i32 %rs1, 0"));
    assert!(llvm.contains("select i1"));

    let golden = emit_golden_python(&document);
    assert!(golden.contains("if op == 'let':"));
    assert!(golden.contains("if op in ('if', 'select'):"));
}

#[test]
fn lisp_module_defsem_expands_before_all_backends() {
    let document = parse_document(include_str!("../examples/lisp_module.axisl"))
        .expect("parse Lisp-authored module");
    validate_document(&document).expect("validate Lisp-authored module");

    let instruction = &document.instructions[0];
    assert!(instruction.formal_semantics.starts_with("(not i32 (let"));
    assert!(!instruction.formal_semantics.contains("choose-arithmetic"));
    assert!(!instruction.formal_semantics.contains("invert-choice"));

    let semantics = emit_semantics_json(&document);
    assert!(semantics.contains("\"op\": \"let\", \"bindings\":"));
    assert!(!semantics.contains("\"error\":"));

    let c = emit_semantics_c(&document);
    let rust = emit_semantics_rust(&document);
    let smt = emit_smt2(&document);
    let llvm = emit_llvm_ir(&document);
    assert!(c.contains("axis_sem_not"));
    assert!(rust.contains("axis_sem_not"));
    assert!(smt.contains("(bvnot (ite"));
    assert!(llvm.contains("select i1"));
}

#[test]
fn lisp_behaviors_share_effect_and_constraint_backends() {
    let document = parse_document(include_str!("../examples/lisp_behaviors.axisl"))
        .expect("parse Lisp behavior module");
    validate_document(&document).expect("validate Lisp behavior module");

    let add_flags = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "ADD-AND-FLAGS")
        .expect("mixed behavior");
    assert_eq!(
        add_flags.effects,
        "set rd = add(i32, rs1, rs2); setstate(flags, and(i32, rs1, 15), i4)"
    );

    let constrained = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "CONSTRAINED-EXTEND")
        .expect("constrained instruction");
    assert_eq!(constrained.decode_requires, "a64_extended_reg(rs2)");

    let c = emit_exec_c(&document);
    assert!(c.contains("const char *state_name;"));
    assert!(c.contains("r->state_name = \"flags\";"));
    assert!(c.contains("case AXIS_INSN_ADD_AND_FLAGS: axis_exec_eff_ADD_AND_FLAGS"));

    let rust = emit_exec_rust(&document);
    assert!(rust.contains("pub state_write: Option<(&'static str, u32)>"));
    assert!(rust.contains("r.state_write = Some((\"flags\""));

    let lift = emit_lift_python(&document);
    assert!(lift.contains("\"kind\": \"setstate\", \"state\": \"flags\""));
    assert!(lift.contains("\"kind\": \"a64_extended_reg\""));
}

#[test]
fn typed_behavior_is_canonical_after_frontend_parsing() {
    let mut document = parse_document(include_str!("../examples/lisp_behaviors.axisl"))
        .expect("parse Lisp behavior module");
    validate_document(&document).expect("validate typed behavior");
    let before = emit_lift_python(&document);

    // Compatibility text is not reparsed by validation or generation.
    document.instructions[0].effects = "this is deliberately not effect syntax".to_string();
    validate_document(&document).expect("typed behavior remains canonical");
    assert_eq!(emit_lift_python(&document), before);

    // A hand-built AST cannot claim effect source without supplying the typed
    // representation: the invariant fails clearly at validation.
    document.instructions[0].behavior = None;
    let error = validate_document(&document).expect_err("missing typed behavior");
    assert!(error
        .to_string()
        .contains("effect source text without canonical typed behavior"));
}

#[test]
fn decode_constraints_are_recursive_and_canonical_after_frontend_parsing() {
    let mut document = parse_document(include_str!("../examples/lisp_constraints.axisl"))
        .expect("parse Lisp constraint module");
    validate_document(&document).expect("validate typed constraint");
    let legacy = parse_document(
        r#"(axis-module legacy-constraints
  (version "1.0")
  (target rvmt)

  (definstruction bounded_option
    (mnemonic BOUNDED_OPTION)
    (category custom)
    (format R)
    (opcode 0)
    (func3 0)
    (func7 0)
    (operands
      (amount imm i3 in)
      (option imm i3 in)
    )
    (requires (and (< amount 5) (not (= option 7))))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse legacy constraint");
    assert_eq!(
        document.instructions[0].decode_constraint,
        legacy.instructions[0].decode_constraint
    );

    let python = emit_lift_python(&document);
    assert!(python.contains("\"kind\": \"and\""));
    assert!(python.contains("\"kind\": \"uimm_compare\""));
    assert!(python.contains("\"kind\": \"not\""));
    let encode_c = emit_encode_c(&document);
    assert!(encode_c.contains("operand_values[0] < 5u"));
    assert!(encode_c.contains("!(operand_values[1] == 7u)"));
    let encode_json = emit_encode_table_json(&document);
    assert!(encode_json.contains("\"decode_constraint\": {\"kind\": \"and\""));

    // Compatibility text is reflection only once the frontend has produced
    // the canonical constraint tree.
    document.instructions[0].decode_requires =
        "this is deliberately not constraint syntax".to_string();
    validate_document(&document).expect("typed constraint remains canonical");
    assert_eq!(emit_lift_python(&document), python);

    document.instructions[0].decode_constraint = None;
    let error = validate_document(&document).expect_err("missing typed constraint");
    assert!(error
        .to_string()
        .contains("decode_requires text without a canonical decode constraint"));
}

#[test]
fn lisp_modes_and_cores_match_legacy_topology_and_drive_artifacts() {
    let lisp = parse_document(include_str!("../examples/lisp_modes_cores.axisl"))
        .expect("parse Lisp modes and cores");
    validate_document(&lisp).expect("validate Lisp modes and cores");
    let legacy = parse_document(
        r#"(axis-module legacy-topology
  (version "1.0")
  (target rvmt)

  (defisa rv32-axis
    (base rv32im)
    (word-bits 32)
    (registers "x[32]:i32" "pc:i32")
    (features m custom)
    (memory-model rvwmo)
    (endianness little)
  )

  (defmode field-mode
    (csr 1984)
    (field 1 0)
    (values
      (scalar 0)
      (simt 1)
      (xnn 2)
    )
    (default scalar)
    (description "PCE-field execution-mode selector")
  )

  (definstruction scalar_add
    (mnemonic SCALAR_ADD)
    (category custom)
    (format R)
    (opcode 0)
    (func3 0)
    (func7 0)
    (modes scalar simt)
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )

  (defpersonality scalar1
    (mode scalar)
    (implements rv32-axis)
    (discipline independent (threads 1))
    (capsule "x[32]" "pc")
    (description "Single-thread scalar personality")
  )

  (defpersonality simt8
    (mode simt)
    (implements rv32-axis)
    (discipline lockstep (lanes 8))
    (capsule "x[32]" "pc")
    (description "Eight-lane lockstep personality")
  )

  (defpersonality xnn0
    (mode xnn)
    (implements rv32-axis)
    (discipline systolic (rows 8) (cols 8))
    (capsule "x[32]" "pc")
    (description "Eight-by-eight systolic personality")
  )

  (defcore pce-tile0
    (kind rvmt)
    (threads 8)
    (implements rv32-axis)
    (personalities scalar1 simt8 xnn0)
    (features mode-switch custom)
  )

  (defaccelerator nearasic0
    (family nearasic)
    (subtype vector-multiply)
    (descriptor-version 1)
    (descriptor-schema rvmt_nearasic_v1)
    (descriptor-bytes 68)
    (launch-abi rvmt_submit_entry)
    (completion status_addr)
    (mmio-base 0)
    (mmio-size 0)
    (target nearasic)
    (coupling queue_descriptor)
    (region-id 0)
    (manifest-version 0)
    (profile scalar)
    (backend-kind auto)
    (exec-shape scalar)
    (simd-lanes 1)
    (element-width-bits 32)
    (fallback-policy software)
    (ports
      (a input bits i32)
      (b input bits i32)
      (y output bits i32)
    )
    (semantics "Multiply two input words")
    (formal (mul i32 a b))
    (latency 4)
    (throughput 1.0)
    (resources lanes=1)
  )

  (defmemory l1
    (kind sram)
    (size-bytes 32768)
    (ports 2)
    (latency-cycles 1)
    (width-bits 32)
    (banks 1)
    (attributes cache coherent)
  )

  (defmemory scratchpad
    (kind scratchpad)
    (size-bytes 65536)
    (ports 2)
    (latency-cycles 1)
    (width-bits 32)
    (banks 4)
    (attributes explicit dma-visible)
  )

  (deftile rvmt-tile0
    (cores pce-tile0)
    (accelerators nearasic0)
    (memories l1 scratchpad)
    (interconnect crossbar)
  )
)
    "#,
    )
    .expect("parse legacy topology");

    assert_eq!(lisp.modes, legacy.modes);
    assert_eq!(lisp.personalities, legacy.personalities);
    assert_eq!(lisp.cores, legacy.cores);
    assert_eq!(lisp.memories, legacy.memories);
    assert_eq!(lisp.accelerators, legacy.accelerators);
    assert_eq!(lisp.tiles, legacy.tiles);
    assert_eq!(lisp.instructions[0].modes, legacy.instructions[0].modes);

    let legality = emit_mode_legality_manifest_json(&lisp);
    assert!(legality.contains("\"mode\": {"));
    assert!(legality.contains("\"SCALAR_ADD\""));
    assert!(legality.contains("\"TENSOR_MUL\""));
    let topology = emit_adl_topology_manifest_json(&lisp);
    assert!(topology.contains("\"pce-tile0\""));
    assert!(topology.contains("\"threads\": 8"));
    assert!(topology.contains("\"kind\": \"systolic\""));
    assert!(topology.contains("\"name\": \"scratchpad\""));
    assert!(topology.contains("\"name\": \"nearasic0\""));
    assert!(topology.contains("\"source_interconnect\": \"crossbar\""));
    let descriptors = emit_accelerator_descriptor_manifests_json(&lisp);
    assert!(descriptors.contains("\"name\": \"nearasic0\""));
    assert!(emit_json(&lisp).contains("\"formal_semantics\": \"(mul i32 a b)\""));
    let coupling = emit_adl_coupling_manifest_json(&lisp);
    assert!(coupling.contains("\"accelerator_ref\": \"nearasic0\""));
    let capsules = emit_state_capsule_manifest_json(&lisp);
    assert!(capsules.contains("\"name\": \"scalar1\""));
    assert!(capsules.contains("[\"scalar1\", \"simt8\"]"));
}

#[test]
fn typed_behavior_preserves_distinct_evaluation_and_location_widths() {
    let document = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&document).expect("validate typed AArch64 behavior");

    let load = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "LDR_W_UNSIGNED")
        .and_then(|instruction| instruction.behavior.as_ref())
        .expect("typed W load");
    assert_eq!(load.effects[0].value.width, 32);
    assert_eq!(load.effects[0].value.load_address_width, Some(64));

    let flags = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "ADDS_X_SHIFT0")
        .and_then(|instruction| instruction.behavior.as_ref())
        .expect("typed flag-setting add");
    let state_write = flags
        .effects
        .iter()
        .find(|effect| matches!(effect.loc, axis_adl::effects::Loc::State { .. }))
        .expect("NZCV write");
    assert_eq!(state_write.value.width, 64);
    assert!(matches!(
        state_write.loc,
        axis_adl::effects::Loc::State { width: 4, .. }
    ));

    let conditional = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "B_COND")
        .and_then(|instruction| instruction.behavior.as_ref())
        .expect("typed conditional branch");
    assert_eq!(
        conditional.effects[0]
            .guard
            .as_ref()
            .expect("branch guard")
            .width,
        4
    );

    let reflected = emit_lift_python(&document);
    assert!(reflected.contains("\"load_address_width\": 64"));
    assert!(reflected.contains("\"guard_width\": 4"));
    let golden = emit_golden_python(&document);
    assert!(golden.contains("def _eval_axis_expr(expr, env, width, load_address_width=None):"));
    assert!(golden.contains("addr_width = load_address_width or width"));
    // The address is evaluated and masked at its own width, and forwards the
    // load address width to any load inside it -- a pointer chase's inner
    // address is as wide as the outer one's.
    assert!(golden.contains(
        "addr = _mask(_eval(node[-1], env, addr_width, load_address_width), addr_width)"
    ));
    let executor = emit_exec_python(&document);
    assert!(executor.contains("eff.get(\"load_address_width\")"));
}



#[test]
fn lisp_instruction_family_expands_before_all_backends() {
    let document = parse_document(include_str!("../examples/lisp_aarch64_family.axisl"))
        .expect("parse Lisp AArch64 family");
    validate_document(&document).expect("validate Lisp AArch64 family");
    assert_eq!(document.instructions.len(), 4);

    let lift = emit_lift_python(&document);
    for mnemonic in ["ADD_W_SHIFT", "SUB_W_SHIFT", "ADD_X_SHIFT", "SUB_X_SHIFT"] {
        assert!(lift.contains(&format!("\"mnemonic\": \"{mnemonic}\"")));
    }
    assert!(lift.contains("\"kind\": \"a64_shifted_reg\", \"width\": 32"));
    assert!(lift.contains("\"kind\": \"a64_shifted_reg\", \"width\": 64"));

    let encode = emit_encode_table_json(&document);
    assert!(encode.contains("\"mnemonic\": \"ADD_W_SHIFT\""));
    assert!(encode.contains("\"mnemonic\": \"SUB_X_SHIFT\""));

    let c = emit_exec_c(&document);
    assert!(c.contains("axis_exec64_eff_ADD_W_SHIFT"));
    assert!(c.contains("axis_exec64_eff_SUB_X_SHIFT"));
    let rust = emit_exec_rust(&document);
    assert!(rust.contains("axis_exec64_eff_add_w_shift"));
    assert!(rust.contains("axis_exec64_eff_sub_x_shift"));
}

#[test]
fn exec_c_dispatches_to_semantics_functions() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let exec = emit_exec_c(&document);

    assert!(exec.contains("/* schema: axis.exec-c.v1 */"));
    assert!(exec.contains("#include \"axis_lift.h\""));
    assert!(exec.contains("#include \"axis_semantics.h\""));
    // Dispatch arm per instruction with an emitted C semantics function.
    assert!(exec.contains("case AXIS_INSN_ANDN:"));
    assert!(exec.contains("if (n == 2) { *out = axis_eval_andn(in[0], in[1]); return 1; }"));
    assert!(exec.contains("case AXIS_INSN_CLZX:"));
    assert!(exec.contains("if (n == 1) { *out = axis_eval_clzx(in[0]); return 1; }"));
    // Step reads reg operands from the register file, writes the destination,
    // and threads a memory interface and pc for effects.
    assert!(exec.contains("static inline axis_exec_result axis_exec_step(uint32_t word, uint32_t *regs, size_t reg_count, const axis_mem *mem, uint32_t pc)"));
    assert!(exec.contains("typedef struct axis_mem {"));
    // The result carries control-flow (next_pc) and trap fields.
    assert!(exec.contains("uint32_t next_pc;"));
    assert!(exec.contains("const char *trap_cause;"));
    // The compact executor reads a register through the class table rather than
    // testing for the plain `reg` kind, which is what let a class with a name of
    // its own — RISC-V's `rv_gpr` — be read as an immediate instead. The class
    // is the operand's own, fixed when the table was generated.
    assert!(exec.contains("const axis_reg_class *cls = axis_op_class(op);"));
    assert!(exec.contains("cls->zero_index >= 0 && v == (uint32_t)cls->zero_index"));
    assert!(exec.contains(
        "if (axis_exec_apply(entry->id, &lifted, regs, reg_count, mem, pc, &r)) { r.ok = 1; return r; }"
    ));
    // A pure document generates no effect functions.
    assert!(!exec.contains("axis_exec_eff_"));

    // Instructions without an emitted semantics function get no dispatch arm.
    let rvmt =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&rvmt).expect("validate rvmt example");
    let rvmt_exec = emit_exec_c(&rvmt);
    assert!(rvmt_exec.contains("case AXIS_INSN_FMA_I:"));
    assert!(!rvmt_exec.contains("AXIS_INSN_TLS_LOAD:"));
}

#[test]
fn exec_c_applies_memory_effects() {
    // A load generates an effect function that reads memory and extends via
    // axis_sem_sext; the address reuses the C pure lowering.
    let mem = parse_document(include_str!("../examples/effects_mem.axisl")).expect("parse mem");
    validate_document(&mem).expect("validate mem");
    let exec = emit_exec_c(&mem);
    assert!(exec.contains("static inline void axis_exec_eff_LW_X(const axis_lifted *lifted, uint32_t *regs, size_t reg_count, const axis_mem *mem, uint32_t pc, axis_exec_result *r)"));
    assert!(exec.contains("uint32_t _addr = (rs1 + imm);"));
    assert!(exec.contains("uint32_t _raw = mem ? mem->read(mem->ctx, _addr, 32u) : 0u;"));
    assert!(exec.contains("uint32_t _v = axis_sem_sext(_raw, 32u, 32u);"));
    assert!(exec.contains(
        "case AXIS_INSN_LW_X: axis_exec_eff_LW_X(lifted, regs, reg_count, mem, pc, r); return 1;"
    ));

    // A store generates a memory-write effect (no register write).
    let store =
        parse_document(include_str!("../examples/effects_store.axisl")).expect("parse store");
    validate_document(&store).expect("validate store");
    let sexec = emit_exec_c(&store);
    assert!(sexec.contains("static inline void axis_exec_eff_SW_X("));
    assert!(sexec.contains("if (mem) { mem->write(mem->ctx, _addr, _val, 32u); }"));
}

#[test]
fn exec_c_control_flow_and_traps() {
    // E3: a guarded setpc lowers the guard to a C comparison and writes next_pc.
    let branch =
        parse_document(include_str!("../examples/effects_branch.axisl")).expect("parse branch");
    validate_document(&branch).expect("validate branch");
    let exec = emit_exec_c(&branch);
    assert!(exec.contains("static inline void axis_exec_eff_BEQ_X("));
    assert!(exec.contains("if ((rs1) == (rs2)) {"));
    assert!(exec.contains("r->next_pc = (pc + imm);"));

    // E4: a guarded trap sets trapped/trap_cause and aborts remaining effects.
    let trap = parse_document(include_str!("../examples/effects_trap.axisl")).expect("parse trap");
    validate_document(&trap).expect("validate trap");
    let texec = emit_exec_c(&trap);
    assert!(texec.contains("static inline void axis_exec_eff_TEQ_X("));
    assert!(texec.contains("r->trapped = 1; r->trap_cause = \"illegal\"; return;"));
}

#[test]
fn exec_rust_completes_the_trio() {
    // The Rust executor composes the Rust lifter + semantics: a pure step,
    // dispatch by mnemonic, and the full effect surface (E1-E4).
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let exec = emit_exec_rust(&document);
    assert!(exec.contains("// schema: axis.exec-rust.v1"));
    assert!(exec.contains("pub trait Memory {"));
    assert!(exec.contains(
        "pub fn step(word: u32, regs: &mut [u32], mem: &mut dyn Memory, pc: u32) -> ExecResult"
    ));
    // Pure dispatch reaches the Rust semantics functions.
    assert!(exec.contains("(inputs.len() == 2).then(|| axis_eval_andn(inputs[0], inputs[1]))"));
    // A pure document has no effect functions.
    assert!(!exec.contains("axis_exec_eff_"));

    // E2: a load peels to mem.read + extend and writes the destination.
    let mem = parse_document(include_str!("../examples/effects_mem.axisl")).expect("parse mem");
    validate_document(&mem).expect("validate mem");
    let mexec = emit_exec_rust(&mem);
    assert!(mexec.contains("fn axis_exec_eff_lw_x(lifted: &Lifted, regs: &mut [u32], mem: &mut dyn Memory, pc: u32, r: &mut ExecResult)"));
    assert!(mexec.contains("let _raw = mem.read(_addr, 32);"));
    assert!(mexec.contains("let _v = axis_sem_sext(_raw, 32, 32);"));

    // E3/E4: a guarded setpc writes next_pc; a guarded trap sets r.trap.
    let branch =
        parse_document(include_str!("../examples/effects_branch.axisl")).expect("parse branch");
    validate_document(&branch).expect("validate branch");
    let bexec = emit_exec_rust(&branch);
    assert!(bexec.contains("if axis_sem_mask(rs1, 32) == axis_sem_mask(rs2, 32) {"));
    assert!(bexec.contains("r.next_pc = axis_sem_mask((pc).wrapping_add(imm), 32);"));
    let trap = parse_document(include_str!("../examples/effects_trap.axisl")).expect("parse trap");
    validate_document(&trap).expect("validate trap");
    let texec = emit_exec_rust(&trap);
    assert!(texec.contains("r.trap = Some(\"illegal\"); return;"));

    // A mode-free / effect-free document's executor is stable (byte-identical
    // regardless of the document around it).
    assert_eq!(emit_exec_rust(&document), exec);
}

#[test]
fn fuzz_mix_target_exercises_all_executor_paths() {
    // The cross-executor fuzz target (tools/exec_fuzz.py) mixes pure ALU, load,
    // store, branch, and trap in one disjoint-decode ISA, so it must validate
    // and drive every executor path: a pure dispatch arm plus effect functions
    // for the E2/E3/E4 instructions in both compiled backends.
    let document =
        parse_document(include_str!("../examples/fuzz_mix.axisl")).expect("parse fuzz_mix");
    validate_document(&document).expect("validate fuzz_mix (disjoint decode)");

    let c = emit_exec_c(&document);
    assert!(c.contains("case AXIS_INSN_ADD_X:")); // pure dispatch
    for effect_fn in [
        "axis_exec_eff_LW_X(",  // E2 load
        "axis_exec_eff_SW_X(",  // E2 store
        "axis_exec_eff_BEQ_X(", // E3 setpc
        "axis_exec_eff_TEQ_X(", // E4 trap
    ] {
        assert!(c.contains(effect_fn), "C executor missing {effect_fn}");
    }

    let rust = emit_exec_rust(&document);
    assert!(rust.contains("axis_eval_add_x"));
    for effect_fn in [
        "axis_exec_eff_lw_x(",
        "axis_exec_eff_sw_x(",
        "axis_exec_eff_beq_x(",
        "axis_exec_eff_teq_x(",
    ] {
        assert!(
            rust.contains(effect_fn),
            "Rust executor missing {effect_fn}"
        );
    }
}

#[test]
fn sim_c_is_a_machine_over_the_proven_executor() {
    // `emit-sim-c` used to be a block interpreter over pre-decoded straight-line
    // words: no fetch, no pc to follow, no architectural state, and a register
    // model that predated register classes. It is now a machine -- fetch,
    // execute, follow the pc -- with a hook table for everything the host owns.
    let document =
        parse_document(include_str!("../examples/fuzz_mix.axisl")).expect("parse fuzz_mix");
    validate_document(&document).expect("validate fuzz_mix");
    let sim = emit_sim_c(&document);

    assert!(sim.contains("/* schema: axis.sim-c.v1 */"));
    assert!(sim.contains("#include \"axis_exec.h\""));
    // The hooks. Fetch and trap are the two that decide whether this is a
    // machine or a harness: without fetch the caller supplies the words, and
    // without trap a raised trap can only stop the world.
    assert!(sim.contains("uint32_t (*fetch)(void *ctx, uint64_t pc, int *ok);"));
    assert!(sim.contains(
        "uint64_t (*trap)(void *ctx, const char *cause, uint64_t pc, int *stop);"
    ));
    assert!(sim.contains("void (*retire)(void *ctx, const axis_sim_event *event);"));
    // The loop runs every lane of the word through the proven wide executor,
    // on the decode the memo keeps (or makes, without one).
    assert!(sim.contains("axis_sim_exec_decode(sim, word, &lanes);"));
    // In the word's own ISA: `isa` may be an ordered list (U4c), resolved per
    // word by axis_sim_word_isa.
    assert!(sim.contains("axis_exec_step64_decoded(first, lanes, word, axis_sim_word_isa(sim, word), sim->regs,"));
    assert!(sim.contains("static inline const char *axis_sim_word_isa(const axis_sim *sim, uint32_t word)"));
    assert!(sim.contains("static inline axis_sim_status axis_sim_step(axis_sim *sim)"));
    assert!(sim.contains("static inline axis_sim_status axis_sim_run(axis_sim *sim, uint64_t limit)"));
    // A hole in the program and a hole in this build are different answers.
    assert!(sim.contains("AXIS_SIM_UNDECODED,"));
    assert!(sim.contains("AXIS_SIM_UNSUPPORTED,"));
    // The register file is sized by the document, because a scalable register
    // spans several slots and a file above it starts where that one ends.
    assert!(sim.contains("#define AXIS_SIM_REG_SLOTS "));

    // The runtime is generic over the co-emitted executor: only the guard and
    // the slot count vary, so the machine body is identical across documents.
    let rvmt =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&rvmt).expect("validate rvmt example");
    let body = |src: &str| -> String {
        let start = src.find("typedef struct axis_sim_event").unwrap();
        let end = src.rfind("#ifdef __cplusplus").unwrap();
        src[start..end].to_string()
    };
    assert_eq!(body(&sim), body(&emit_sim_c(&rvmt)));
}

#[test]
fn aha_json_pce_consumer_contract() {
    // The exact field surface PCE's real consumers read from aha_instructions.json
    // (aha/isa/adl_loader.py strict schema + _instruction_from_dict /
    // _operand_from_dict, and aha/compute_core/.../xrv_extension.py from_adl).
    // Renaming any of these, or dropping the encoding, breaks PCE — so pin them
    // here (docs/pce_migration.md contract invariants; drift fails AXIS CI first).
    let document =
        parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt example");
    validate_document(&document).expect("validate rvmt example");
    let aha = emit_aha_json(&document);

    // adl_loader strict-rejects any other schema string.
    assert!(aha.contains("\"schema\": \"pce-adl.aha-instructions.v1\""));
    assert!(aha.contains("\"instructions\": ["));

    // _instruction_from_dict reads these; mnemonic + encoding are required.
    for field in [
        "\"mnemonic\":",
        "\"encoding\":",
        "\"category\":",
        "\"semantics\":",
        "\"latency_cycles\":",
        "\"operands\":",
    ] {
        assert!(
            aha.contains(field),
            "aha_instructions.json missing `{field}`"
        );
    }
    // from_adl reads exactly these encoding fields (opcode/func3/func7 in range).
    for field in ["\"total_bits\":", "\"opcode\":", "\"func3\":", "\"func7\":"] {
        assert!(aha.contains(field), "encoding missing `{field}`");
    }
    // And where every bit comes from, in the shape the consumer's `BitField`
    // takes: a name, the bit it starts at, its width, and either the value a
    // fixed field holds or which bit of the operand a slice carries. The
    // loader has always had somewhere to put this and the manifest has never
    // said it, so `hardware/grv/grv_conformance/isa_surface.py` places
    // operands by the harness's R-type convention instead.
    assert!(aha.contains("\"fields\": ["), "encoding missing `fields`");
    assert!(
        aha.contains("{\"name\": \"opcode\", \"start_bit\": 0, \"width_bits\": 7, \"value\": 11}"),
        "a fixed field states its value: {aha}"
    );
    assert!(
        aha.contains("{\"name\": \"rs1\", \"start_bit\": 15, \"width_bits\": 5, \"operand_lo\": 0}"),
        "an operand slice states which bit of the operand it carries: {aha}"
    );
    // _operand_from_dict reads these; name is required.
    for field in [
        "\"name\":",
        "\"type\":",
        "\"width_bits\":",
        "\"is_output\":",
        "\"is_optional\":",
        "\"description\":",
    ] {
        assert!(aha.contains(field), "operand missing `{field}`");
    }
}

#[test]
fn aha_json_optisynth_dialect_for_adl2() {
    // The `formal_semantics` OptiSynth (PCE ADL.2) parses is the OptiSynth
    // dialect for every `optisynth_compatible` instruction. Rotates and extends
    // expand into the grammar's shift/mask idioms; bit counts map to the LLVM
    // intrinsic `intr` form (PCE has Z3 builtins for ctlz/cttz/ctpop). All are
    // proven faithful vs golden by tools/optisynth_vs_golden.py and Z3-proven by
    // PCE (11/11 rewrite rules for this example).
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let aha = emit_aha_json(&document);

    // rol/ror -> canonical shift-or rotate; sext -> ashr∘shl; zext -> and-mask.
    assert!(aha.contains(
        "(or i32 (shl i32 rs1 (and i32 rs2 i32:31)) (lshr i32 rs1 (and i32 (sub i32 i32:32 (and i32 rs2 i32:31)) i32:31)))"
    ));
    assert!(aha.contains("(ashr i32 (shl i32 rs1 i32:24) i32:24)"));
    assert!(aha.contains("(and i32 rs1 i32:65535)"));
    // clz/ctz/cpop -> the LLVM intrinsic call form.
    assert!(aha.contains("(intr llvm.ctlz i32 rs1)"));
    assert!(aha.contains("(intr llvm.cttz i32 rs1)"));
    assert!(aha.contains("(intr llvm.ctpop i32 rs1)"));

    // Every instruction lowered into the dialect is marked compatible -- now
    // including the bit-count trio. Slice each instruction's JSON object up to
    // the next `"mnemonic":` so the check is order-independent.
    let compat_flag = |mnemonic: &str| -> bool {
        let start = aha
            .find(&format!("\"mnemonic\": \"{mnemonic}\""))
            .expect("instruction present");
        let rest = &aha[start + 1..];
        let end = rest
            .find("\"mnemonic\":")
            .map_or(aha.len(), |i| start + 1 + i);
        aha[start..end].contains("\"optisynth_compatible\": true")
    };
    for mnemonic in ["ROLX", "RORX", "SEXTB", "ZEXTH", "CLZX", "CTZX", "CPOPX"] {
        assert!(
            compat_flag(mnemonic),
            "{mnemonic} should be optisynth_compatible"
        );
    }
}

#[test]
fn zbb_class_operator_misuse_is_rejected() {
    let bad_arity = parse_document(
        r#"(axis-module bad
  (version "1.0")
  (target rvmt)

  (definstruction bad_clz
    (mnemonic BAD_CLZ)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 1)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
    )
    (formal (clz i32 rs1 rs2))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse bad clz arity");
    let err = validate_document(&bad_arity).expect_err("clz arity should fail");
    assert!(err
        .to_string()
        .contains("operator `clz` expects 1 argument"));

    let bad_sext = parse_document(
        r#"(axis-module bad
  (version "1.0")
  (target rvmt)

  (definstruction bad_sext
    (mnemonic BAD_SEXT)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 1)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
    )
    (formal (sext i32 rs2 rs1))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse bad sext");
    let err = validate_document(&bad_sext).expect_err("sext literal should fail");
    assert!(err
        .to_string()
        .contains("integer source-width literal as its first argument"));
}

#[test]
fn custom_format_with_scattered_slices_is_fully_encodable() {
    let document = parse_document(
        r#"(axis-module xfmt
  (version "1.0")
  (target rvmt)

  (defformat SXK
    (bits 32)
    (fields
      (imm 31 25 11 5)
      (rs2 24 20)
      (rs1 19 15)
      (func3 14 12)
      (imm 11 7 4 0)
      (opcode 6 0)
    )
  )

  (definstruction store_key
    (mnemonic STORE_KEY)
    (category custom)
    (format SXK)
    (opcode 43)
    (func3 2)
    (func7 0)
    (operands
      (rs1 reg i32 in)
      (rs2 reg i32 in)
      (imm imm i12 in)
    )
    (asm "store_key $rs2, $imm($rs1)")
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse custom format");
    validate_document(&document).expect("validate custom format");

    let encode = emit_encode_table_json(&document);
    assert!(encode.contains("\"format\": \"SXK\""));
    // Scattered immediate: two slices, no contiguous legacy lsb.
    assert!(encode.contains(
        "\"slices\": [{\"op_lsb\": 5, \"lsb\": 25, \"width\": 7}, {\"op_lsb\": 0, \"lsb\": 7, \"width\": 5}]"
    ));
    assert!(!encode.contains("\"field\": \"unencoded\""));

    let encode_c = emit_encode_c(&document);
    // Two C rows for the scattered operand, selecting slices via src_lsb.
    assert!(encode_c.contains("\"imm\", \"imm\", \"input\", \"imm\", 2, 5, 25, 7u"));
    assert!(encode_c.contains("\"imm\", \"imm\", \"input\", \"imm\", 2, 0, 7, 5u"));

    let roundtrip = emit_roundtrip_tests_json(&document);
    assert!(roundtrip.contains("\"mnemonic\": \"STORE_KEY\""));
    assert!(!roundtrip.contains("\"reason\":"));
}

#[test]
fn encoding_gaps_are_reported_with_reasons() {
    // Extra operand no format field names -> unencoded_operand.
    let unencoded = parse_document(
        r#"(axis-module xgap
  (version "1.0")
  (target rvmt)

  (definstruction vec_op
    (mnemonic VEC_OP)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
      (vsel imm i4 in)
    )
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse unencoded doc");
    validate_document(&unencoded).expect("gaps are visible, not fatal");
    let roundtrip = emit_roundtrip_tests_json(&unencoded);
    assert!(roundtrip.contains("\"reason\": \"unencoded_operand\""));
    assert!(roundtrip.contains("\"operands\": [\"vsel\"]"));

    // Missing rs2 operand leaves the format field unbound -> unbound_field.
    let unbound = parse_document(
        r#"(axis-module xgap
  (version "1.0")
  (target rvmt)

  (definstruction two_op
    (mnemonic TWO_OP)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
    )
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse unbound doc");
    validate_document(&unbound).expect("unbound fields are visible, not fatal");
    let roundtrip = emit_roundtrip_tests_json(&unbound);
    assert!(roundtrip.contains("\"reason\": \"unbound_field\""));
    assert!(roundtrip.contains("\"operands\": [\"rs2\"]"));
}

#[test]
fn invalid_format_definitions_are_rejected() {
    let overlapping = parse_document(
        r#"(axis-module xbad
  (version "1.0")
  (target rvmt)

  (defformat BAD
    (bits 32)
    (fields
      (a 31 20)
      (b 25 0)
    )
  )

  (definstruction bad_op
    (mnemonic BAD_OP)
    (category custom)
    (format BAD)
    (opcode 11)
    (func3 0)
    (func7 0)
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse overlapping format");
    let err = validate_document(&overlapping).expect_err("overlap should fail");
    assert!(err.to_string().contains("overlaps another field"));

    let mismatched = parse_document(
        r#"(axis-module xbad
  (version "1.0")
  (target rvmt)

  (defformat BAD2
    (bits 32)
    (fields
      (imm 31 25 11 0)
      (opcode 6 0)
    )
  )

  (definstruction bad_op2
    (mnemonic BAD_OP2)
    (category custom)
    (format BAD2)
    (opcode 11)
    (func3 0)
    (func7 0)
    (operands
      (imm imm i12 in)
    )
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse mismatched format");
    let err = validate_document(&mismatched).expect_err("width mismatch should fail");
    assert!(err
        .to_string()
        .contains("operand slice width 12 does not match instruction slice width 7"));

    let unknown = parse_document(
        r#"(axis-module xbad
  (version "1.0")
  (target rvmt)

  (definstruction bad_op3
    (mnemonic BAD_OP3)
    (category custom)
    (format VLIW9)
    (opcode 11)
    (func3 0)
    (func7 0)
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse unknown format");
    let err = validate_document(&unknown).expect_err("unknown format should fail");
    assert!(err.to_string().contains("unknown format `VLIW9`"));
}

#[test]
fn manifest_carries_optisynth_dialect_semantics() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");

    // manifest.json + aha_instructions.json feed PCE's OptiSynth rewrite
    // extraction, so expressible semantics are normalized to its dialect.
    for json in [emit_json(&document), emit_aha_json(&document)] {
        assert!(json.contains("\"formal_semantics\": \"(and i32 rs1 (xor i32 rs2 i32:-1))\""));
        assert!(json.contains("\"formal_semantics\": \"(ashr i32 rs1 rs2)\""));
        assert!(
            json.contains("\"formal_semantics\": \"(select i32 (icmp_slt i1 rs1 rs2) rs1 rs2)\"")
        );
        assert!(json.contains("\"optisynth_compatible\": true"));
        // Rotates/extends expand into the shift/mask idioms of the dialect
        // (see aha_json_optisynth_dialect_for_adl2 for the exact forms).
        assert!(json.contains("(or i32 (shl i32 rs1 (and i32 rs2 i32:31))"));
        assert!(json.contains("\"formal_semantics\": \"(ashr i32 (shl i32 rs1 i32:24) i32:24)\""));
        // Bit counts map to the LLVM intrinsic call form (PCE has Z3 builtins),
        // so every zbb instruction is now in the dialect and compatible.
        assert!(json.contains("\"formal_semantics\": \"(intr llvm.ctlz i32 rs1)\""));
        assert!(!json.contains("\"optisynth_compatible\": false"));
    }

    // semantics.json stays in the raw AXIS dialect (the typed-AST home).
    let semantics = emit_semantics_json(&document);
    assert!(semantics.contains("\"formal_semantics\": \"(and i32 rs1 (not i32 rs2))\""));
    assert!(!semantics.contains("i32:-1"));
}

#[test]
fn golden_model_carries_trusted_spec_registry() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let golden = emit_golden_python(&document);

    assert!(golden.contains("AXIS_SPECS = {"));
    assert!(golden.contains("\"ANDN\": {"));
    assert!(golden.contains("\"eval\": eval_andn,"));
    assert!(golden.contains("\"params\": [(\"rs1\", 32), (\"rs2\", 32)],"));
    assert!(golden.contains("\"result_width\": 32,"));
    // Raw AXIS dialect stays in the golden model (the audit link to source).
    assert!(golden.contains("\"formal_semantics\": \"(and i32 rs1 (not i32 rs2))\","));
    assert!(golden.contains("def sample_vectors(name, count=16, seed=0x5EED):"));
    assert!(golden.contains("def selftest(count=16):"));
    assert!(golden.contains("def evaluate(name, *operands):"));
}

#[test]
fn c_semantics_interpreter_emits_pure_functions() {
    let document =
        parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&document).expect("validate zbb example");
    let header = emit_semantics_c(&document);

    assert!(header.contains("/* schema: axis.semantics-c.v1 */"));
    assert!(header.contains("static inline uint32_t axis_eval_andn(uint32_t rs1, uint32_t rs2)"));
    assert!(header.contains("axis_sem_not(rs2, 32u)"));
    assert!(header.contains("axis_sem_rotl(rs1, rs2, 32u)"));
    assert!(header.contains("axis_sem_clz(rs1, 32u)"));
    assert!(header.contains("axis_sem_sext(rs1, 8u, 32u)"));
    assert!(header.contains("axis_sem_min_s(rs1, rs2, 32u)"));
    assert!(header.contains("axis_sem_max_u(rs1, rs2, 32u)"));

    // Instructions without formal_semantics get a visible comment, not a stub.
    let rvmt = parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("parse rvmt");
    let rvmt_header = emit_semantics_c(&rvmt);
    assert!(rvmt_header.contains("/* axis_eval_tls_load: no formal_semantics declared */"));
    assert!(rvmt_header.contains(
        "static inline uint32_t axis_eval_fma_i(uint32_t rs1, uint32_t rs2, uint32_t rs3)"
    ));
    assert!(
        rvmt_header.contains("static inline uint32_t axis_eval_nearasic0(uint32_t a, uint32_t b)")
    );
}

#[test]
fn effects_form_desugars_identically_to_formal_semantics() {
    // A single register `set` in the infix effects surface must produce the
    // exact same artifacts as the equivalent s-expression formal_semantics.
    let effects_src = r#"(axis-module e
  (version "1.0")
  (target rvmt)

  (definstruction fma
    (mnemonic FMA)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 1)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
      (rs3 reg i32 in)
    )
    (behavior
      (set rd (add (mul rs1 rs2) rs3))
    )
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#;
    let formal_src = r#"(axis-module e
  (version "1.0")
  (target rvmt)

  (definstruction fma
    (mnemonic FMA)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 1)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
      (rs3 reg i32 in)
    )
    (formal (add (mul rs1 rs2) rs3))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#;
    let eff = parse_document(effects_src).expect("parse effects");
    validate_document(&eff).expect("validate effects");
    let formal = parse_document(formal_src).expect("parse formal");
    validate_document(&formal).expect("validate formal");

    // The effects block desugared into the same formal_semantics.
    assert_eq!(
        eff.instructions[0].formal_semantics,
        "(add (mul rs1 rs2) rs3)"
    );
    // Every semantics-bearing backend is byte-identical between the two forms.
    assert_eq!(emit_semantics_c(&eff), emit_semantics_c(&formal));
    assert_eq!(emit_semantics_rust(&eff), emit_semantics_rust(&formal));
    assert_eq!(emit_smt2(&eff), emit_smt2(&formal));
    assert_eq!(emit_golden_python(&eff), emit_golden_python(&formal));
    assert_eq!(emit_llvm_ir(&eff), emit_llvm_ir(&formal));
}

#[test]
fn effects_stage_guardrails_are_enforced() {
    let both = r#"
(axis-module e
  (version "1.0")
  (target rvmt)
  (definstruction i
    (mnemonic I) (category custom) (format R) (opcode 11) (func3 0) (func7 0)
    (operands (rd reg i32 out) (rs1 reg i32 in))
    (formal (add i32 rs1 rs1))
    (behavior (set rd (add i32 rs1 rs1)))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)))
"#;
    assert!(parse_document(both)
        .unwrap_err()
        .to_string()
        .contains("both `effects` and `formal_semantics`"));

    let wrong_target = r#"
(axis-module e
  (version "1.0")
  (target rvmt)
  (definstruction i
    (mnemonic I) (category custom) (format R) (opcode 11) (func3 0) (func7 0)
    (operands (rd reg i32 out) (rs1 reg i32 in))
    (behavior (set rs1 (add i32 rs1 rs1)))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)))
"#;
    assert!(parse_document(wrong_target)
        .unwrap_err()
        .to_string()
        .contains("must write the instruction's output operand"));
}

#[test]
fn effects_e2_memory_load_stays_in_effect_layer() {
    let document =
        parse_document(include_str!("../examples/effects_mem.axisl")).expect("parse mem example");
    validate_document(&document).expect("validate mem example");
    let lw = &document.instructions[0];

    // A load keeps its semantics in `effects`; formal_semantics stays empty so
    // the pure value-model backends skip it.
    assert!(lw.formal_semantics.trim().is_empty());
    assert!(lw.effects.contains("set rd = load(i32, signed, add(rs1, imm))"));

    // Pure backends emit no function for the load (skipped as inexpressible).
    // SMT names what it skipped and why -- `; axis_instr_lw_x: unsupported
    // formal_semantics operator \`load\`` -- so the check is for the
    // *definition*, not for the mnemonic appearing at all. A silent absence and
    // a stated one look the same to a consumer only until something is missing
    // for a reason nobody wrote down.
    let c = emit_semantics_c(&document);
    assert!(!c.contains("axis_eval_lw_x("));
    let smt = emit_smt2(&document);
    assert!(!smt.contains("(define-fun axis_instr_lw_x"));
    assert!(smt.contains("; axis_instr_lw_x:"), "the skip is named: {smt}");

    // The golden runtime gains the memory-load evaluator, and the lift table
    // carries the effect the executor needs.
    let golden = emit_golden_python(&document);
    assert!(golden.contains("if op in ('load', 'atomic_load'):"));
    let lift = emit_lift_python(&document);
    // The Python lifter carries the tree too, since X2's `lift_block` is a
    // consumer of it: it instantiates these trees and threads them into a
    // graph, so handing the text to the golden model is not open to it.
    assert!(lift.contains(
        "\"effects\": [{\"kind\": \"set\", \"dest\": \"rd\", \"width\": 32, \"value\": \"(load i32 signed (add rs1 imm))\", \"value_ast\": {\"op\": \"load\", \"type\": \"i32\", \"args\": [{\"symbol\": \"signed\"}, {\"op\": \"add\", \"args\": [{\"symbol\": \"rs1\"}, {\"symbol\": \"imm\"}]}]}, \"eval_width\": 32, \"load_address_width\": 32, \"atomic\": False, \"memory_order\": \"relaxed\"}],"
    ));
    // The Python executor threads a memory model and branches on the effects.
    let exec = emit_exec_python(&document);
    assert!(exec.contains("def step(word, regs, mem=None, pc=0, mode=None, isa=None, state=None):"));
    assert!(exec.contains("env[\"__mem__\"] = mem.read"));
}

#[test]
fn effects_e2_store_writes_memory() {
    let document = parse_document(include_str!("../examples/effects_store.axisl"))
        .expect("parse store example");
    validate_document(&document).expect("validate store example");
    let sw = &document.instructions[0];

    // A store has no register write: empty formal_semantics, no output operand.
    assert!(sw.formal_semantics.trim().is_empty());
    assert!(!sw.operands.iter().any(|operand| operand.output));
    assert!(sw.effects.contains("store(rs1, rs2, i32)"));

    // The lift table carries the store effect for the executor.
    let lift = emit_lift_python(&document);
    assert!(lift.contains(
        "\"effects\": [{\"kind\": \"store\", \"width\": 32, \"memory_order\": \"relaxed\", \"atomic\": False, \"addr\": \"rs1\", \"addr_ast\": {\"symbol\": \"rs1\"}, \"value\": \"rs2\", \"value_ast\": {\"symbol\": \"rs2\"}, \"eval_width\": 32, \"addr_width\": 32}],"
    ));
    // The executor applies stores via the memory model's write.
    let exec = emit_exec_python(&document);
    assert!(exec.contains("mem.write(addr, value, eff[\"width\"])"));
    // Pure backends still emit nothing for the store.
    assert!(!emit_semantics_c(&document).contains("axis_eval_sw_x("));
}

#[test]
fn effects_e3_conditional_branch() {
    let document = parse_document(include_str!("../examples/effects_branch.axisl"))
        .expect("parse branch example");
    validate_document(&document).expect("validate branch example");
    let beq = &document.instructions[0];

    // A branch has no register/formal semantics; the effect is guarded setpc.
    assert!(beq.formal_semantics.trim().is_empty());
    assert!(beq.effects.contains("when icmp_eq(rs1, rs2): setpc(add(pc, imm))"));

    // The lift table carries a guarded setpc; `pc` and the icmp guard are in it.
    let lift = emit_lift_python(&document);
    assert!(lift.contains(
        "\"effects\": [{\"kind\": \"setpc\", \"value\": \"(add pc imm)\", \"value_ast\": {\"op\": \"add\", \"args\": [{\"symbol\": \"pc\"}, {\"symbol\": \"imm\"}]}, \"eval_width\": 32, \"guard\": \"(icmp_eq rs1 rs2)\", \"guard_ast\": {\"op\": \"icmp_eq\", \"args\": [{\"symbol\": \"rs1\"}, {\"symbol\": \"rs2\"}]}, \"guard_width\": 32}],"
    ));
    // The golden runtime gains the comparison evaluator (gated on effects).
    let golden = emit_golden_python(&document);
    assert!(golden.contains("if op in ('icmp_eq', 'icmp_ne'):"));
    // The executor threads pc, evaluates guards, and computes next_pc.
    let exec = emit_exec_python(&document);
    assert!(exec.contains("def step(word, regs, mem=None, pc=0, mode=None, isa=None, state=None):"));
    // The counter wraps at the ISA's word rather than growing past it.
    assert!(exec.contains("next_pc = (pc + ILEN) & pc_mask"));
    assert!(exec.contains("elif eff[\"kind\"] == \"setpc\":"));
    assert!(exec.contains("eff[\"guard\"], env, eff[\"guard_width\"]"));
    // Pure backends still emit nothing for the branch.
    assert!(!emit_semantics_c(&document).contains("axis_eval_beq_x("));
}

#[test]
fn effects_e4_conditional_trap() {
    let document =
        parse_document(include_str!("../examples/effects_trap.axisl")).expect("parse trap example");
    validate_document(&document).expect("validate trap example");
    let teq = &document.instructions[0];

    assert!(teq.formal_semantics.trim().is_empty());
    assert!(teq.effects.contains("when icmp_eq(rs1, rs2): trap(illegal)"));

    // The lift table carries a guarded trap with its cause.
    let lift = emit_lift_python(&document);
    assert!(lift.contains(
        "\"effects\": [{\"kind\": \"trap\", \"cause\": \"illegal\", \"guard\": \"(icmp_eq rs1 rs2)\", \"guard_ast\": {\"op\": \"icmp_eq\", \"args\": [{\"symbol\": \"rs1\"}, {\"symbol\": \"rs2\"}]}, \"guard_width\": 32}],"
    ));
    // The executor aborts on a trap and reports the cause.
    let exec = emit_exec_python(&document);
    assert!(exec.contains("if eff[\"kind\"] == \"trap\":"));
    assert!(exec.contains("trap = eff[\"cause\"]"));
    assert!(exec.contains("\"trap\": trap,"));
    // Pure backends emit nothing for the trap instruction.
    assert!(!emit_semantics_c(&document).contains("axis_eval_teq_x("));

    // An unknown trap cause is rejected at validation.
    let bad = parse_document(
        r#"(axis-module e
  (version "1.0")
  (target rvmt)

  (definstruction t
    (mnemonic T)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (encoding (rd 0))
    (operands
      (rs1 reg i32 in)
      (rs2 reg i32 in)
    )
    (behavior
      (trap bogus)
    )
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse");
    assert!(validate_document(&bad)
        .unwrap_err()
        .to_string()
        .contains("trap cause must be one of"));
}

#[test]
fn llvm_ir_carries_memory_control_flow_and_trap_effects() {
    // E5: effects lower to native LLVM load/store and branches, so memory is
    // optimizer-visible rather than an opaque call.
    // `tools/llvm_effects_check.py` proves the lowering against the Python
    // executor; this pins the ABI and the withholding rules.
    let mem =
        parse_document(include_str!("../examples/effects_mem.axisl")).expect("parse mem example");
    validate_document(&mem).expect("validate mem example");
    let ir = emit_llvm_ir(&mem);
    // Typed pointers, not opaque `ptr`: clang takes either, but llvmlite's
    // bundled LLVM — the in-process JIT — parses only typed ones.
    assert!(ir.contains(
        "define void @axis_eff_lw_x(i8* %mem, i32 %pc, i32* %out, i32* %state, i32 %rs1, i32 %imm)"
    ));
    // Byte-addressed and possibly unaligned: the executors promise no alignment.
    // ⚠️ The SHAPE, not the temporaries. Every access masks the address with
    // the memory window first, so the numbering moved by three the day that
    // landed -- and what these lines are about is that the pointer is formed
    // from a byte offset, retyped, and read without an alignment claim.
    assert!(ir.contains("getelementptr i8, i8* %mem"));
    assert!(ir.contains("and i32 ") && ir.contains("@AXIS_HOLE_memory_mask"));
    assert!(ir.contains("bitcast i8* %t") && ir.contains(" to i32*"));
    assert!(ir.contains("align 1") && ir.contains("load i32, i32* %t"));

    let store = parse_document(include_str!("../examples/effects_store.axisl"))
        .expect("parse store example");
    validate_document(&store).expect("validate store example");
    assert!(emit_llvm_ir(&store).contains("store i32 %rs2, i32* %t")
        && emit_llvm_ir(&store).contains(", align 1"));

    // A guarded branch becomes a real branch; the fall-through pc is the
    // default and a setpc overwrites it.
    let branch = parse_document(include_str!("../examples/effects_branch.axisl"))
        .expect("parse branch example");
    validate_document(&branch).expect("validate branch example");
    let branch_ir = emit_llvm_ir(&branch);
    assert!(branch_ir.contains("%t0 = add i32 %pc, 4"));
    assert!(branch_ir.contains("icmp eq i32 %rs1, %rs2"));
    assert!(branch_ir.contains("br i1 "));
    assert!(branch_ir.contains("store i32 %t1, i32* %axis.next"));

    // A trap stores its 1-based cause id and returns, aborting later effects.
    let trap = parse_document(include_str!("../examples/effects_trap.axisl"))
        .expect("parse trap example");
    validate_document(&trap).expect("validate trap example");
    let trap_ir = emit_llvm_ir(&trap);
    assert!(trap_ir.contains("store i32 1, i32* %axis.trap\n  ret void"));

    // A 64-bit ISA lowers its effects at i64: the whole ABI — pc, `%out`, and
    // every operand — widens together. An AArch64 `B` sign-extends its
    // displacement to the 64-bit pc even though its only operand is a 26-bit
    // immediate, which is why the width comes from the effects and the ISA word
    // rather than from the operands alone.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");
    let a64_ir = emit_llvm_ir(&a64);
    assert!(a64_ir
        .contains("define void @axis_eff_b(i8* %mem, i64 %pc, i64* %out, i64* %state, i64 %imm)"));
    assert!(a64_ir.contains("%t1 = call i64 @axis_sem64_sext(i64 %imm, i64 26, i64 64)"));
    // A 64-bit load addresses the same flat byte buffer with a 64-bit index.
    assert!(a64_ir.contains("getelementptr i8, i8* %mem, i64 "));
    assert!(a64_ir.contains("load i64, i64* %t") && a64_ir.contains(", align 1"));

    // Three withholding rules, each for something the ABI genuinely cannot
    // carry rather than something merely unimplemented:
    //
    // Values that read architectural state are no longer withheld, nor are
    // fixed registers or data barriers, nor an atomic group the fusion can take
    // -- a group says these effects are one transaction, which is a reason to
    // fuse them and not to decline. What remains is a barrier LLVM cannot
    // express, and a group no fusion recognises.
    assert!(a64_ir.contains("; axis_eff_isb: an atomic group, or a barrier"));
    assert!(a64_ir.contains("; axis_eff_stxp_x: an atomic group, or a barrier"));
    // `%out` carries up to `EFFECT_MAX_WRITES` register writes, so `ldp` with
    // writeback — three registers — is emitted rather than withheld, and each
    // write reports into its own pair of slots.
    let ldp_pre = a64_ir
        .split("define void @axis_eff_ldp_x_pre(")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("ldp_x_pre is emitted");
    assert!(ldp_pre.contains("%axis.value0 = getelementptr i64, i64* %out, i32 0"));
    assert!(ldp_pre.contains("%axis.value1 = getelementptr i64, i64* %out, i32 4"));
    assert!(ldp_pre.contains("%axis.value2 = getelementptr i64, i64* %out, i32 6"));
    // The base update is the first effect, so it takes slot 0 — not the data
    // register, which is what a single-`result` view of the delta would show.
    assert!(ldp_pre.contains("store i64 1, i64* %axis.wrote0"));
    assert!(ldp_pre.contains("store i64 1, i64* %axis.wrote2"));
    // Every flag starts cleared, so a guarded write that does not fire reads as
    // "did not write" rather than as whatever the caller's array held.
    assert!(ldp_pre.contains("store i64 0, i64* %axis.wrote3"));

    // A later effect *reading* a register an earlier one wrote is not withheld:
    // each write records the SSA value holding its result and the effects after
    // it lower against that, which is what the executors' mutable register file
    // does. A pre-indexed store is `rn = rn + imm; Mem64[rn] = rt`, so its
    // address has to be the updated base rather than the `%rn` parameter.
    let store_pre = a64_ir
        .split("define void @axis_eff_str_x_pre(")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("str_x_pre is emitted");
    assert!(store_pre.contains("store i64 %t3, i64* %axis.value0"));
    // ⚠️ The address that reaches memory is the UPDATED base, which is now one
    // step further away: it is masked with the memory window before the
    // pointer is formed, so the thing to look at is what goes INTO the mask.
    // The property is unchanged -- `%t3`, never `%rn`.
    assert!(store_pre.contains("and i64 %t3,"));
    assert!(!store_pre.contains("and i64 %rn,"));
    assert!(!store_pre.contains("getelementptr i8, i8* %mem, i64 %rn"));

    // Emitting is not the same as being right: `tools/llvm_effects_check.py`
    // drives every function above against the Python executor, and it now
    // rejects any case whose executor-side register delta is not single-valued,
    // so a withholding rule that stopped working could not pass unnoticed.
    assert!(a64_ir.matches("define void @axis_eff_").count() > 100);
}



#[test]
fn vector_type_atoms_expand_to_lane_wise_semantics() {
    // SIMD stage V1: `v<lanes>i<elem>` applies an operator per lane. The
    // expansion happens at elaboration, so the stored semantics — and every
    // artifact that reflects them, including the golden model that re-parses
    // the string at runtime — are ordinary bit-vector operations.
    let document =
        parse_document(include_str!("../examples/simd_lanes.axisl")).expect("parse simd example");
    validate_document(&document).expect("validate simd example");

    let vadd = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "VADD_2S")
        .expect("VADD_2S present");
    // No vector atom survives elaboration.
    assert!(!vadd.formal_semantics.contains("v2i32"));
    // Each lane is masked before *and* after the add: the second mask is what
    // stops lane 0's carry reaching lane 1.
    assert!(vadd.formal_semantics.contains("(add i32 (and i64 vn 0xffffffff)"));
    assert!(vadd.formal_semantics.contains("(lshr i64 vn 32)"));
    assert_eq!(vadd.formal_semantics.matches("0xffffffff").count(), 6);

    // Eight lanes produce eight masked adds.
    let vadd8 = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "VADD_8B")
        .expect("VADD_8B present");
    assert_eq!(vadd8.formal_semantics.matches("(add i8 ").count(), 8);

    // A non-lane-local operator is rejected rather than approximated.
    let error = parse_document(
        r#"
(axis-module bad_vector
  (version "1.0")
  (target rvmt)
  (definstruction v
    (mnemonic V) (category custom) (format R) (opcode 11) (func3 0) (func7 0)
    (operands (rd reg i64 out) (rs1 reg i64 in))
    (formal (sext v2i32 8 rs1))
    (latency 1) (throughput 1.0)
    (area-estimate-um2 0.0) (power-estimate-mw 0.0) (expected-speedup 1.0)))
"#,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("not lane-local"), "{error}");
}

#[test]
fn smt_resizes_a_narrower_operator_to_its_context() {
    // Every SMT node resized its result to the caller's width except `App`,
    // so an operator narrower than its context was emitted at the wrong bit
    // width -- and for the signed forms that is wrong, not merely wide:
    // `bvsgt` on a 16-bit value zero-extended into 64 bits reads -1 as
    // +65535. Found via the SIMD corpus, but it needs no vectors to occur.
    let document = parse_document(
        r#"(axis-module narrow_signed
  (version "1.0")
  (target rvmt)

  (definstruction maxh
    (mnemonic MAXH)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (operands
      (rd reg i32 out)
      (rs1 reg i32 in)
      (rs2 reg i32 in)
    )
    (formal (and i32 (max i16 (and i32 rs1 0xffff) (and i32 rs2 0xffff)) 0xffff))
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse narrow signed max");
    validate_document(&document).expect("validate narrow signed max");
    let smt = emit_smt2(&document);
    // The 16-bit compare is performed on 16-bit values, then zero-extended
    // back into the 32-bit result.
    assert!(smt.contains("((_ extract 15 0)"), "{smt}");
    assert!(smt.contains("((_ zero_extend 16)"), "{smt}");
}

#[test]
fn float_operators_specify_canonical_nan_across_backends() {
    // FP stage F1. Values cross AXIS as bit patterns, so the float operators
    // are ordinary operators that reinterpret their arguments -- `Sem` stays a
    // single bit-vector domain. The consequence that matters: the existing
    // harnesses compare result bit patterns, which is the only comparison that
    // catches a wrong NaN payload or a sign-flipped zero.
    let fp = parse_document(include_str!("../examples/fp_scalar.axisl"))
        .expect("parse fp example");
    validate_document(&fp).expect("validate fp example");

    // Each backend canonicalizes NaN explicitly rather than inheriting the
    // host's payload, which is what makes the comparison portable: x86 and ARM
    // do not agree on propagated NaNs.
    let c = emit_semantics_c(&fp);
    assert!(c.contains("static inline uint64_t axis_fp64_add(uint64_t a, uint64_t b)"));
    assert!(c.contains("if (value != value) { return UINT64_C(0x7ff8000000000000); }"));
    assert!(c.contains("if (value != value) { return 0x7fc00000u; }"));

    let rust = emit_semantics_rust(&fp);
    assert!(rust.contains("fn axis_fp64_add(a: u64, b: u64) -> u64"));
    assert!(rust.contains("if value.is_nan() { 0x7ff8000000000000u64 }"));

    // LLVM computes natively and selects the canonical pattern on an unordered
    // compare, rather than trusting whatever the hardware returned.
    let ir = emit_llvm_ir(&fp);
    assert!(ir.contains("fadd double"));
    assert!(ir.contains("fcmp uno double"));
    assert!(ir.contains("9221120237041090560"));
    assert!(ir.contains("fmul float"));

    // SMT uses the FloatingPoint theory, so these semantics are *proven*
    // rather than sampled: `smt_vs_golden.py` asks z3 to refute equality with
    // the golden model and requires unsat. `fp.to_ieee_bv` is deliberately
    // unspecified for NaN in SMT-LIB, so the canonical pattern is selected on
    // `fp.isNaN` first -- which is what makes the NaN cases provable at all.
    let smt = emit_smt2(&fp);
    assert!(smt.contains("(set-logic QF_BVFP)"));
    assert!(smt.contains("define-fun axis_instr_fadd_d"));
    assert!(smt.contains("(fp.add RNE ((_ to_fp 11 53) fn1) ((_ to_fp 11 53) fm))"));
    assert!(smt.contains("(ite (fp.isNaN axis_fp) (_ bv9221120237041090560 64)"));
    // An integer-only document keeps the narrower logic, so its artifact is
    // unchanged.
    let zbb = parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb");
    validate_document(&zbb).expect("validate zbb");
    assert!(emit_smt2(&zbb).contains("(set-logic QF_BV)"));

    // No LLVM intrinsic or SelectionDAG pattern is claimed: the canonical-NaN
    // rule is not expressible in a Pat<>, so a pattern would overclaim.
    assert!(!emit_llvm_patterns(&fp).contains("int_axis_fadd_d"));

    // Float entries get FP-shaped sample vectors, so every gate that uses them
    // exercises signed zeros, infinities, and NaNs rather than relying on
    // random bit patterns to wander into those classes.
    let golden = emit_golden_python(&fp);
    assert!(golden.contains("\"float\": True,"));
    assert!(golden.contains("if AXIS_SPECS[name].get('float'):"));

    // fsqrt and fma. `fma` rounds once where a multiply and an add round twice,
    // and the corpus carries both so `tools/fp_fusion_check.py` can require
    // them to disagree on a witness -- the check that no backend contracted the
    // unfused form into the fused one.
    assert!(c.contains("static inline uint64_t axis_fp64_fma(uint64_t a, uint64_t b, uint64_t c)"));
    assert!(c.contains("fma(axis_fp64_bits_to(a), axis_fp64_bits_to(b), axis_fp64_bits_to(c))"));
    // sqrt and fma come from libm, so a float-using header pulls in math.h.
    assert!(c.contains("#include <math.h>"));
    assert!(rust.contains("f64::from_bits(a).mul_add(f64::from_bits(b), f64::from_bits(c))"));
    assert!(ir.contains("declare double @llvm.fma.f64(double, double, double)"));
    assert!(ir.contains("call double @llvm.sqrt.f64"));
    assert!(smt.contains("fp.fma RNE"));
    assert!(smt.contains("fp.sqrt RNE"));

    // The unfused form stays two operations, and its intermediate goes through
    // a bit pattern, which is what makes it uncontractable rather than merely
    // compiled with the right flag.
    assert!(c.contains("axis_fp64_add(axis_fp64_mul(fn1, fm), fd)"));

    // Comparisons: the ordered predicates are false for NaN and treat -0.0 as
    // equal to +0.0, so none of them can be a bit comparison. SMT must use
    // `fp.eq` (IEEE equality) rather than `=` (structural), which would make
    // -0.0 unequal to +0.0 and NaN equal to itself.
    assert!(c.contains("static inline uint64_t axis_fp64_uno(uint64_t a, uint64_t b)"));
    assert!(c.contains("return (x != x || y != y) ? UINT64_C(1) : UINT64_C(0);"));
    assert!(rust.contains("(f64::from_bits(a).is_nan() || f64::from_bits(b).is_nan()) as u64"));
    assert!(ir.contains("fcmp oeq double"));
    assert!(ir.contains("fcmp uno double"));
    assert!(smt.contains("(fp.eq ((_ to_fp 11 53) fn1) ((_ to_fp 11 53) fm))"));
    assert!(smt.contains("(fp.isNaN"));

    // Conversions. Float to integer rounds toward zero, saturates, and maps
    // NaN to 0 — AXIS's rule, since a C cast is undefined out of range, ARM
    // saturates, and x86 returns the most negative integer.
    assert!(c.contains("static inline uint64_t axis_fp_to_signed(double value, uint32_t width)"));
    assert!(c.contains("if (value != value) { return 0; }"));
    // LLVM's *saturating* intrinsics have exactly that behaviour; the plain
    // fptosi/fptoui are poison out of range and would be the wrong choice.
    assert!(ir.contains("declare i64 @llvm.fptosi.sat.i64.f64(double)"));
    assert!(ir.contains("call i64 @llvm.fptosi.sat.i64.f64"));
    // Rust's `as` cast saturates with NaN to 0, matching without a range test.
    assert!(rust.contains("as i64) as u64"));

    // SMT proves the conversions too, by reconstructing the saturation rather
    // than calling fp.to_sbv on inputs it leaves unspecified: NaN first, then
    // each threshold, and only then the conversion itself.
    assert!(smt.contains("define-fun axis_instr_fcvtzs_d"));
    assert!(smt.contains("(ite (fp.isNaN axis_cvt) (_ bv0 64)"));
    assert!(smt.contains("((_ fp.to_sbv 64) RTZ axis_cvt)"));
    assert!(smt.contains("((_ fp.to_ubv 64) RTZ axis_cvt)"));
    // Integer to float reads the bit-vector as two's complement or as a
    // magnitude, which is the whole difference between the two instructions.
    assert!(smt.contains("((_ to_fp 11 53) RNE"));
    assert!(smt.contains("((_ to_fp_unsigned 11 53) RNE"));

    // Effectful FP: a comparison whose result goes to architectural state, the
    // way a real ISA spells it. This is the first FP instruction to reach the
    // effect layer, and it exercised a duplicated predicate: the wide executor
    // ABI kept its own `i`/`u`-only type-atom test, so `f64` fell through as an
    // unbound symbol and became a state read. Both lowerings now share
    // `ir::type_atom_bits`.
    let exec_c = emit_exec_c(&fp);
    assert!(exec_c.contains("axis_fp32_uno(fn1, fm)"));
    assert!(exec_c.contains("axis_state64_write(state, \"fpcc\""));
    assert!(!exec_c.contains("axis_state64_read(state, \"f64\")"));
    // In the wide ABI every value is 64-bit, so a single-precision helper takes
    // explicitly narrowed arguments. C would have accepted the implicit
    // conversion; Rust rejected it, which is how the sloppiness surfaced.
    assert!(exec_c.contains("(uint64_t)axis_fp32_uno((uint32_t)("));
    let exec_rust = emit_exec_rust(&fp);
    assert!(exec_rust.contains("axis_fp32_uno((axis_input_0) as u32, (axis_input_1) as u32) as u64"));

    // An integer-only document gains neither the FP prelude nor math.h.
    assert!(!emit_semantics_c(&zbb).contains("axis_fp64_add"));
    assert!(!emit_semantics_c(&zbb).contains("#include <math.h>"));
}

#[test]
fn aarch64_operators_call_a_prelude_outside_the_portable_ir() {
    // The `a64_*` operators are deliberately not in `ir::Op`: that enum is the
    // portable semantic core five backends agree on, and a flag nibble or a
    // shifted-register form is not shared semantics. C and Rust already handle
    // them by pattern-matching the operator and calling a helper, and LLVM now
    // does the same — each application is emitted as a call and replaced by the
    // temp holding its result, leaving portable semantics for the typed IR.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");
    let ir = emit_llvm_ir(&a64);

    assert!(ir.contains("define internal i64 @axis_a64_add_nzcv(i64 %a0, i64 %b0, i64 %w)"));
    assert!(ir.contains("define internal i64 @axis_a64_shift_reg("));
    assert!(ir.contains("define internal i64 @axis_a64_cond_holds("));
    // The width is a trailing argument for the operators that take one, and
    // absent for the two that do not — the same dispatch the C emitter uses.
    assert!(ir.contains("call i64 @axis_a64_add_nzcv(i64 %rn, i64 %t1, i64 64)"));
    assert!(ir.contains("call i64 @axis_a64_cond_holds("));

    // The bitmask-immediate family too: `wmask` builds the mask an AND/ORR/EOR
    // immediate denotes, and the bitfield moves share its decode. The decode
    // finds the highest set bit of a 7-bit field, which is a leading-zero count.
    assert!(ir.contains("define internal i64 @axis_a64_wmask("));
    assert!(ir.contains("define internal { i64, i64, i64 } @axis_a64_decode_masks("));
    assert!(ir.contains("call i64 @llvm.ctlz.i64("));
    // One declaration only: the width prelude declares the same intrinsic when a
    // document counts leading zeros, and LLVM rejects a redefinition.
    assert_eq!(ir.matches("declare i64 @llvm.ctlz.i64").count(), 1);
    // `replicate` is a loop, which is a phi in SSA.
    assert!(ir.contains("%pos = phi i64 [ 0, %entry ]"));
    assert!(ir.contains("call i64 @axis_a64_ubfm("));
    assert!(ir.contains("call i64 @axis_a64_bfm("));

    // A fixed register write reports through the same slot machinery as any
    // other: AArch64 BL writes the link register, whose index the lift table
    // publishes so a consumer can address it without an operand to name it.
    let bl = ir
        .split("define void @axis_eff_bl(")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("bl is emitted");
    assert!(bl.contains("store i64 1, i64* %axis.wrote0"));
    assert!(bl.contains("store i64 %t5, i64* %axis.next"));

    // A data barrier becomes a real fence. LLVM's fence has an ordering but no
    // domain, so every shareability option lowers to the strongest ordering:
    // stronger than the architecture asks is conservative, never wrong.
    assert!(ir
        .split("define void @axis_eff_dmb(")
        .nth(1)
        .is_some_and(|rest| rest.split("\n}").next().unwrap().contains("fence seq_cst")));

    // What remains withheld says why, and there are exactly two reasons it
    // can be. One is ABI surface an emitted module has no way to name; the
    // other is the floating-point environment, which is the same reason the
    // `_rm` and `_fx` operators are declined everywhere else in LLVM. The
    // check is that no entry is withheld *silently* -- a third reason should
    // be added here deliberately, not discovered by an empty line.
    let withheld: Vec<&str> = ir
        .lines()
        .filter(|line| line.starts_with("; axis_eff_"))
        .collect();
    assert!(!withheld.is_empty());
    for line in &withheld {
        assert!(
            line.contains("an atomic group, or a barrier")
                || line.contains("an explicit rounding mode")
                || line.contains("floating-point exception")
                // `ldr q0` moves 128 bits and the portable IR computes in 64.
                // Withheld with the reason said, which is the point of this
                // test -- an effect the IR cannot lower is named, not emitted
                // wrong.
                || line.contains("widths beyond 64 bits")
                // ⚠️ An instruction with nothing to lower is named now rather
                // than passed over, and which of the three silences it is
                // matters: a routine performs it, it is declared unsupplied, or
                // nothing has been said about it yet. Added here deliberately,
                // which is what the note above asks for -- `llvm_accounted`
                // found 26 instructions across nine corpora that had been
                // leaving the file with no function and no comment at all.
                || line.contains("declared unsupplied")
                || line.contains("performed by the routine")
                || line.contains("no semantics and no behavior"),
            "withheld without a known reason: {line}"
        );
    }
    assert!(withheld
        .iter()
        .any(|line| line.contains("an atomic group, or a barrier")));
    assert!(withheld
        .iter()
        .any(|line| line.contains("an explicit rounding mode")));
    // An instruction barrier constrains the pipeline rather than memory, and
    // LLVM has nothing that says so, so it is withheld rather than lowered to a
    // memory fence that would claim something the architecture does not.
    assert!(ir.contains("; axis_eff_isb:"));

    // A document that uses none of them gets no prelude, so its module is
    // unchanged.
    let zbb = parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb");
    validate_document(&zbb).expect("validate zbb");
    assert!(!emit_llvm_ir(&zbb).contains("axis_a64_"));
}

#[test]
fn effect_functions_carry_architectural_state() {
    // Named state is an in/out array on every effect function, indexed by the
    // slot order the lifter publishes. It is on every function rather than only
    // the ones that use it, so a caller implements one calling convention.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");
    let ir = emit_llvm_ir(&a64);
    assert!(ir.contains(
        "define void @axis_eff_b(i8* %mem, i64 %pc, i64* %out, i64* %state, i64 %imm)"
    ));

    // A read loads the slot once at entry; AArch64 `adc` takes its carry-in
    // from NZCV, which is slot 1.
    let adc = ir
        .split("define void @axis_eff_adc_x(")
        .nth(1)
        .and_then(|rest| rest.split("\n}").next())
        .expect("adc_x is emitted");
    assert!(adc.contains("%t0 = getelementptr i64, i64* %state, i32 1"));
    assert!(adc.contains("%t1 = load i64, i64* %t0"));

    // The slot order is the ISA's declared scalar state, and consumers read it
    // from the generated lifter rather than assuming it.
    let slots = axis_adl::effects::isa_scalar_state_slots(&a64.isas);
    assert_eq!(slots[1], ("nzcv".to_string(), 4));
    assert!(emit_lift_python(&a64).contains("STATE_SLOTS = ((\"sp\", 64), (\"nzcv\", 4),"));

    // A document that declares no scalar state still takes the parameter, so
    // the convention does not vary by corpus.
    let mem = parse_document(include_str!("../examples/effects_mem.axisl"))
        .expect("parse mem example");
    validate_document(&mem).expect("validate mem example");
    let signature =
        "define void @axis_eff_lw_x(i8* %mem, i32 %pc, i32* %out, i32* %state, i32 %rs1, i32 %imm)";
    assert!(emit_llvm_ir(&mem).contains(signature));
}

#[test]
fn atomic_pairs_lower_to_native_llvm_atomics() {
    // AXIS models an atomic read-modify-write as two effects — a register set
    // from an `atomic_load`, then an atomic store whose value may depend on
    // what was loaded. Lowering them separately would give the same answer on
    // one thread, which is precisely why it must not be done: the differential
    // gate runs one thread and could not tell. So the pair becomes a single
    // LLVM instruction, where indivisibility holds by construction, or it is
    // withheld.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");
    let ir = emit_llvm_ir(&a64);

    let function = |name: &str| -> String {
        ir.split(&format!("define void @axis_eff_{name}("))
            .nth(1)
            .and_then(|rest| rest.split("\n}").next())
            .unwrap_or_else(|| panic!("{name} is emitted"))
            .to_string()
    };

    // LDADD: the stored value is `loaded + rs`, so the operand is `rs` alone.
    // ⚠️ The ATOMIC and its ordering, not the temporaries it names. Pinning
    // `%t2`/`%t3` made this fail the day every access grew three instructions
    // in front of it -- the memory window is masked in before the pointer is
    // formed -- which is a fact about numbering rather than about the atomic.
    let ldadd = function("ldadd_w");
    assert!(ldadd.contains("atomicrmw add i32*") && ldadd.contains("monotonic"));
    // SWP: the stored value does not mention the loaded register at all.
    assert!(function("swp_w").contains("atomicrmw xchg i32*"));
    // LDCLR spells bit-clear as `and(loaded, not rs)`, so the complement is
    // computed first and the atomic operation is a plain `and`.
    let ldclr = function("ldclr_w");
    assert!(ldclr.contains("@axis_sem64_not"));
    assert!(ldclr.contains("atomicrmw and i32*"));
    // Signed and unsigned min/max are distinct LLVM operations, and AXIS spells
    // the unsigned ones `maxu`/`minu`.
    assert!(function("ldsmax_w").contains("atomicrmw max i32*"));
    assert!(function("ldumax_w").contains("atomicrmw umax i32*"));

    // CAS is a compare-and-swap, not a conditional store: the guard compares
    // the loaded value against what the register held on entry, which is
    // exactly cmpxchg's comparison. The failure ordering may not exceed the
    // success ordering and may not be a release.
    let cas = function("casal_w");
    assert!(cas.contains("cmpxchg i32*") && cas.contains("acq_rel acquire"));
    assert!(cas.contains("extractvalue { i32, i1 }"));

    // ⚠️ No `align` on an atomic, though every plain load and store here says
    // `align 1`. The omission takes LLVM's default of natural alignment, and it
    // is deliberate: an unaligned atomic faults on the machines AXIS describes,
    // so assuming alignment is the faithful lowering. Stating `align 1` is also
    // correct and was tried; LLVM answers it with a call to
    // `__atomic_compare_exchange`, and a stencil cannot reference a symbol that
    // is not one of its holes -- the stencil JIT hung on exactly that.
    assert!(!function("ldadd_w").contains("monotonic, align"));
    assert!(!cas.contains("acquire, align"));

    // Orderings pair off the way AArch64's A and L bits do.
    assert!(function("ldadd_w").contains(" monotonic"));
    assert!(function("ldadda_w").contains(" acquire"));
    assert!(function("ldaddl_w").contains(" release"));
    assert!(function("ldaddal_w").contains(" acq_rel"));

    // A PAIRED compare-and-swap is one transaction over both words, so it is
    // one `cmpxchg` at twice the element width -- which is what the hardware
    // does, `casp` operating on a register pair as a single quantity. Lowering
    // the four effects separately would let one half succeed and the other
    // fail, which the instruction cannot do and a one-threaded gate cannot see.
    let casp = function("casp_x");
    assert!(
        casp.contains("cmpxchg i128*"),
        "the 64-bit pair form swaps 128 bits at once, got {casp}"
    );
    assert!(
        function("casp_w").contains("cmpxchg i64*"),
        "and the 32-bit pair form swaps 64"
    );
    // ⚠️ Low half first. The pair is laid out little-endian in memory, so `rs`
    // is the low half of the compared value and `rs2` the high one; swapping
    // them writes each register the other's answer, which is wrong in a way
    // that looks entirely plausible -- both registers change, and both hold
    // values that were in memory.
    assert!(
        casp.contains("shl i128") && casp.contains("zext i64"),
        "the halves are joined, not passed separately"
    );

    // A paired atomic LOAD is one transaction too, and one `load atomic` at
    // twice the element width expresses it -- LLVM selects `ldxp` for exactly
    // that on AArch64, which is the instruction being lifted.
    let ldxp = function("ldxp_x");
    assert!(
        ldxp.contains("load atomic i128"),
        "the pair is read in one transaction, got {ldxp}"
    );
    // ⚠️ And the exclusive monitor is still written. The fusion consumes only
    // the two loads; the three state writes after them are ordinary
    // architectural state, and consuming the whole behavior instead would emit
    // a lifted `ldxp` that leaves no trace for a `stxp` to test.
    assert!(
        ldxp.matches("i64* %state").count() >= 3,
        "the monitor's address, size and valid bit are all written: {ldxp}"
    );

    // STXP stays withheld, and not for want of a fusion: a store-exclusive
    // tests the monitor and reports whether it held, which is a guarded store
    // needing a branch that a one-entry block has nowhere to put.
    assert!(ir.contains("; axis_eff_stxp_w:"));
}

#[test]
fn a_register_class_is_a_table_row_not_a_branch_per_architecture() {
    // RISC-V's x0 is hardwired to zero; AArch64 encodes XZR as 31 in some
    // classes and SP in others. Those rules used to be written inline in each
    // backend that generates register access code — the Python executor, both C
    // ABIs, both Rust ABIs, the JIT block builder — so a second ISA meant editing
    // every one and hoping they agreed. They come from one table now.
    let classes = axis_adl::ast::REGISTER_CLASSES;
    let by_name = |name: &str| {
        axis_adl::ast::register_class(name).unwrap_or_else(|| panic!("class {name}"))
    };
    assert_eq!(by_name("reg").zero_index, None);
    assert_eq!(by_name("rv_gpr").zero_index, Some(0));
    assert_eq!(by_name("a64_gpr64").zero_index, Some(31));
    assert_eq!(by_name("a64_gpr64sp").alias, Some((31, "sp")));
    assert_eq!(by_name("a64_gpr32").view_width, Some(32));
    // A class with no rules is still a register: `is_register_kind` is
    // membership in the table, not the absence of special indices.
    assert!(axis_adl::ast::is_register_kind("reg"));
    assert!(!axis_adl::ast::is_register_kind("imm"));

    // Every generated consumer reads the table rather than naming an ISA.
    let rv = parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i");
    validate_document(&rv).expect("validate rv32i");
    let lifter = emit_lift_python(&rv);
    for class in classes {
        assert!(
            lifter.contains(&format!("\"{}\": (", class.name)),
            "the generated table is missing {}",
            class.name
        );
    }
    // The tuple carries the whole view: zero index, alias, width, file offset,
    // where the view starts, whether a write preserves the bits outside it,
    // and how many 64-bit slots one register occupies. The offset and policy
    // are what x86's AH and AL need; the limb count is what a register wider
    // than a machine word needs, and a width-only view could say none of it.
    assert!(lifter.contains("\"rv_gpr\": (0, None, None, 0, 0, False, 1, 0)"));
    // A second register file is an offset, not a second array: RISC-V's f5 is
    // slot 37 while x5 is slot 5, which is what lets FMV move between them.
    assert!(lifter.contains("\"rv_fpr\": (None, None, None, 32, 0, False, 1, 0)"));
    // A register of more than one limb strides by its limb count, so the
    // helper -- not `index + offset` -- is what places it.
    assert!(lifter.contains("\"v128_cross\": (None, None, 32, 0, 48, True, 2, 0)"));
    assert_eq!(by_name("rv_fpr").offset, 32);
    assert_eq!(by_name("rv_gpr").offset, 0);
    assert!(lifter.contains("REGISTER_FILE_SLOTS = 64"));

    // A write to a hardwired-zero register is discarded, and a read of it is
    // zero, in every executor — which is what makes RV32I's x0 correct without
    // an instruction having to say so.
    let exec = emit_exec_python(&rv);
    assert!(exec.contains("if zero is not None and index == zero:"));
    let c_exec = emit_exec_c(&rv);
    assert!(c_exec.contains("wcls->zero_index >= 0 && idx == (uint32_t)wcls->zero_index"));
}

#[test]
fn one_definition_of_which_operand_kinds_are_registers() {
    // This predicate had six copies — the translation class normalizer, two
    // membership tests inside the emitted executor, the emitted C and Rust
    // effect binders, and a `startswith("a64_gpr")` patch in one harness — and
    // every copy that stayed as `kind == "reg"` silently classified an AArch64
    // operand as an immediate, because an A64 operand's kind is its register
    // class. The harnesses then passed the register *number* where its value
    // belonged. `ast::REGISTER_KINDS` is now the only list, and the generated
    // lifter exports it so no consumer has to decide.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");

    // Every register class the corpus actually uses is in the list, so no
    // consumer can meet a register kind the predicate does not know.
    for instruction in &a64.instructions {
        for operand in &instruction.operands {
            if operand.kind.starts_with("a64_gpr") {
                assert!(
                    axis_adl::ast::is_register_kind(&operand.kind),
                    "{} operand {} has register kind {} outside REGISTER_KINDS",
                    instruction.mnemonic,
                    operand.name,
                    operand.kind
                );
            }
        }
    }
    assert!(!axis_adl::ast::is_register_kind("imm"));

    // The generated lifter carries the same list, rendered from the Rust one
    // rather than written out again.
    let lifter = emit_lift_python(&a64);
    let rendered = axis_adl::ast::REGISTER_CLASSES
        .iter()
        .map(|class| format!("\"{}\"", class.name))
        .collect::<Vec<_>>()
        .join(", ");
    assert!(lifter.contains(&format!("REGISTER_KINDS = ({rendered})")));
    assert!(lifter.contains("def is_register_operand(kind):"));

    // And the emitted executor asks the lifter instead of repeating the list.
    let executor = emit_exec_python(&a64);
    assert!(executor.contains("if axis_lift.is_register_operand(kind)"));
    assert!(!executor.contains("kind in (\"reg\", \"a64_gpr64\""));
}

#[test]
fn directed_rounding_is_an_argument_and_two_backends_decline_it() {
    // Stage F3. The rounding mode is the operator's first argument rather than
    // an implicit FPCR read, which is what keeps the typed IR a function of its
    // arguments: a real instruction spells the state dependency in its behavior,
    // where it is visible.
    let fp = parse_document(include_str!("../examples/fp_rounding.axisl"))
        .expect("parse rounding example");
    validate_document(&fp).expect("validate rounding example");

    // Mode-first because these operators fold n-ary — a trailing argument cannot
    // be told apart from a third addend.
    let add = fp
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "FADDR_D")
        .expect("FADDR_D present");
    assert_eq!(add.formal_semantics, "(fadd_rm f64 rm fn1 fm)");

    // C can do this, through the floating-point environment, and says so by
    // pulling in the header and pragma that make it legal.
    let header = emit_semantics_c(&fp);
    assert!(header.contains("#include <fenv.h>"));
    assert!(header.contains("#pragma STDC FENV_ACCESS ON"));
    assert!(header.contains("axis_fp64_add_rm"));
    assert!(header.contains("fesetround(axis_fp_round_mode(mode))"));
    // And restores the caller's mode, so a helper cannot leak a direction.
    assert!(header.contains("fesetround(previous)"));

    // SMT takes the mode as a term, so a dynamic mode needs no special handling.
    let smt = emit_smt2(&fp);
    assert!(smt.contains("RNE"));
    assert!(smt.contains("RTP"));
    assert!(smt.contains("RTN"));
    assert!(smt.contains("RTZ"));

    // Rust and LLVM decline, each with its reason in the file it emits. Neither
    // can perform directed rounding — Rust has no API for the floating-point
    // environment, and emitted LLVM IR cannot portably set it. Silently rounding
    // to nearest would be the alternative, and would be wrong in a way no gate
    // could see, since every other mode's result would still look plausible.
    let rust = emit_semantics_rust(&fp);
    assert!(rust.contains("// axis_eval_faddr_d: an explicit rounding mode"));
    assert!(!rust.contains("fn axis_eval_faddr_d"));
    let ir = emit_llvm_ir(&fp);
    assert!(ir.contains("; axis_eval_faddr_d: an explicit rounding mode"));
    assert!(!ir.contains("define i64 @axis_eval_faddr_d"));

    // The round-to-nearest operators are untouched, so nothing already proven
    // changed shape.
    let scalar = parse_document(include_str!("../examples/fp_scalar.axisl"))
        .expect("parse scalar FP");
    validate_document(&scalar).expect("validate scalar FP");
    assert!(emit_semantics_rust(&scalar).contains("fn axis_eval_fadd_d"));
    assert!(!emit_semantics_c(&scalar).contains("#include <fenv.h>"));
}

#[test]
fn float_lanes_reuse_the_integer_lane_machinery() {
    // Stage F2 is the composition of V1's lanes with F1's floats, and the
    // measure of whether the lane machinery was built domain-agnostically is
    // how little it took: the lane extraction is bit-vector work either way,
    // because an AXIS float is a bit pattern, so the only thing the element
    // domain changes is the type atom the per-lane operator is handed.
    let fp = parse_document(include_str!("../examples/simd_fp_lanes.axisl"))
        .expect("parse FP SIMD example");
    validate_document(&fp).expect("validate FP SIMD example");

    let vfadd = fp
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "VFADD_2S")
        .expect("VFADD_2S present");
    // `f32` per lane, and integer masks and shifts to place them.
    assert!(vfadd.formal_semantics.contains("(fadd f32 (and i64 vn 0xffffffff)"));
    assert!(vfadd.formal_semantics.contains("(lshr i64 vn 32)"));
    assert_eq!(vfadd.vector_semantics, "(fadd v2f32 vn vm)");

    // A float operator's width is its own, not the function's, so the value has
    // to be narrowed before the bitcast: `bitcast i64 to float` is not a cast
    // LLVM has, and the scalar corpus never produced the situation because a
    // 32-bit float instruction has 32-bit operands.
    let ir = emit_llvm_ir(&fp);
    // The lane is masked out, narrowed, reinterpreted, computed on, and widened
    // back — each step explicit, none of it a cast LLVM would have accepted in
    // one move.
    for line in [
        "%t0 = and i64 %vn, 4294967295",
        "%t2 = trunc i64 %t0 to i32",
        "%t3 = bitcast i32 %t2 to float",
        "%t6 = fadd float %t3, %t5",
        "%t7 = bitcast float %t6 to i32",
        "%t8 = zext i32 %t7 to i64",
        // Double lanes in a 128-bit register lower the same way.
        "fadd double ",
    ] {
        assert!(ir.contains(line), "missing from the emitted IR: {line}");
    }

    // Lane count and element width are only accepted where every backend has
    // semantics for the format.
    assert_eq!(
        axis_adl::simd::vector_type_atom("v2f32").map(|shape| (shape.lanes, shape.elem_kind)),
        Some((2, 'f'))
    );
    // Half precision joined them when AArch64's FP16 arithmetic arrived: every
    // backend already had scalar `f16` (examples/fp16.axisl). A width with no
    // float semantics anywhere is still refused.
    assert_eq!(
        axis_adl::simd::vector_type_atom("v8f16").map(|shape| (shape.lanes, shape.elem_kind)),
        Some((8, 'f'))
    );
    assert!(axis_adl::simd::vector_type_atom("v8f8").is_none());

    // A lane-wise compare is deliberately not expressible: an AArch64 one writes
    // a lane mask of all-ones or all-zeros, not the 1/0 the scalar operators
    // return, so accepting `fcmp` here would quietly mean the wrong thing.
    assert!(parse_document(
        &include_str!("../examples/simd_fp_lanes.axisl")
            .replace("(fadd v2f32 vn vm)", "(fcmp_oeq v2f32 vn vm)")
    )
    .is_err());
}

#[test]
fn llvm_lowers_lanes_to_native_vectors() {
    // SIMD stage V2. The elaboration-time expansion stays the definition of
    // what a lane-wise operator means, and every other backend still uses it.
    // LLVM has a vector type, so it emits one instruction per operator and the
    // parallelism is visible to the optimizer instead of buried in a shift/mask
    // tree. This is a second implementation of the same semantics, and
    // `llvm_vs_golden.py` proves the two agree — the oracle relationship the
    // design doc predicted for this stage.
    let simd = parse_document(include_str!("../examples/simd_lanes.axisl"))
        .expect("parse simd example");
    validate_document(&simd).expect("validate simd example");
    let ir = emit_llvm_ir(&simd);
    assert!(ir.contains("%t0 = bitcast i64 %vn to <2 x i32>"));
    assert!(ir.contains("%t2 = add <2 x i32> %t0, %t1"));
    assert!(ir.contains("; 2 x i32 lanes, lowered to a native vector"));
    assert!(ir.contains("mul <2 x i32>"));
    assert!(ir.contains("add <8 x i8>"));

    // Operators without a direct vector instruction fall back to the proven
    // expansion rather than being partially vectorized: signed max needs a
    // compare, so it keeps the mask/shift form.
    assert!(ir.contains("define i64 @axis_eval_vmaxs_4h(i64 %vn, i64 %vm) {\nentry:\n  %t0 = and i64 %vn, 65535"));

    // The expansion is still what the document carries, so nothing else
    // changed; the lane spelling is retained beside it for this backend only.
    let vadd = simd
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "VADD_2S")
        .expect("VADD_2S present");
    assert_eq!(vadd.vector_semantics, "(add v2i32 vn vm)");
    assert!(vadd.formal_semantics.contains("(add i32 (and i64 vn 0xffffffff)"));

    // 128-bit Q-register shapes lower natively too.
    let q = parse_document(include_str!("../examples/simd_q_lanes.axisl"))
        .expect("parse Q corpus");
    validate_document(&q).expect("validate Q corpus");
    assert!(emit_llvm_ir(&q).contains("add <4 x i32>"));
    assert!(emit_llvm_ir(&q).contains("add <16 x i8>"));

    // A scalar document gains no vector types and no retained spelling.
    let zbb = parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb");
    validate_document(&zbb).expect("validate zbb");
    assert!(!emit_llvm_ir(&zbb).contains(" x i32>"));
    assert!(zbb.instructions.iter().all(|i| i.vector_semantics.is_empty()));
}

#[test]
fn semantics_lower_128_bit_widths_where_the_language_allows() {
    // SIMD stage V3: the Q-register shapes need 128-bit evaluation. LLVM and
    // Rust have native 128-bit integers; C does not, and the header's value is
    // being portable, so C skips with the reason stated rather than reaching
    // for `unsigned __int128`.
    let q = parse_document(include_str!("../examples/simd_q_lanes.axisl"))
        .expect("parse Q-register corpus");
    validate_document(&q).expect("validate Q-register corpus");

    let ir = emit_llvm_ir(&q);
    assert!(ir.contains("define i128 @axis_eval_vadd_4s(i128 %vn, i128 %vm)"));
    assert!(ir.contains("define internal i128 @axis_sem128_mask(i128 %v, i128 %w)"));
    // The width-derived constants are rendered per width, not copied: the
    // shift-amount mask is 127 here, and the most negative value is i128's.
    assert!(ir.contains("  %am = and i128 %a, 127\n"));
    assert!(ir.contains("-170141183460469231731687303715884105728"));

    let rust = emit_semantics_rust(&q);
    assert!(rust.contains("pub fn axis_eval_vadd_4s(vn: u128, vm: u128) -> u128"));
    assert!(rust.contains("fn axis_sem128_signed(value: u128, width: u128) -> i128"));
    assert!(rust.contains("lhs == i128::MIN && rhs == -1"));

    // C used to decline here, and this test pinned that. It now lowers 128-bit
    // widths through `unsigned __int128` -- the extension the AArch64 smulh and
    // umulh helpers had already relied on for as long as they have existed. The
    // portability the decline protected is kept where it mattered: the prelude
    // appears only for a document that needs it, so a 32- or 64-bit header
    // still compiles under a compiler without the extension.
    let c = emit_semantics_c(&q);
    assert!(c.contains("static inline axis_u128 axis_eval_vadd_4s(axis_u128 vn, axis_u128 vm)"));
    assert!(c.contains("typedef unsigned __int128 axis_u128;"));
    // The helper set mirrors the 64-bit one signature for signature, including
    // the one that differs: `shl` takes no width while `lshr` and `sra` do.
    assert!(c.contains("axis_sem128_shl(axis_u128 value, axis_u128 amount)"));
    assert!(c.contains("axis_sem128_lshr(axis_u128 value, axis_u128 amount, uint32_t width)"));
    // And a narrow document still gets no 128-bit prelude at all.
    let narrow = parse_document(include_str!("../examples/rv32i.axisl")).expect("parse rv32i");
    assert!(!emit_semantics_c(&narrow).contains("axis_sem128_"));

    // 16 lanes of 8 bits expand to 16 masked adds.
    let vadd16 = q
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "VADD_16B")
        .expect("VADD_16B present");
    assert_eq!(vadd16.formal_semantics.matches("(add i8 ").count(), 16);
}

#[test]
fn c_and_rust_semantics_lower_64_bit_widths() {
    // The C and Rust semantics emitters stopped at 32 bits, so the AArch64
    // seed's 64-bit pure functions were skip comments even though LLVM, SMT,
    // and the golden model handled them. All five backends now agree at 64.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");

    let c = emit_semantics_c(&a64);
    assert!(c.contains("static inline uint64_t axis_eval_madd_x(uint64_t rn, uint64_t rm, uint64_t ra)"));
    assert!(c.contains("static inline uint32_t axis_eval_extr_w(uint32_t rn, uint32_t rm, uint32_t lsb)"));
    assert!(!c.contains("beyond 64 bits"));
    // The 64-bit helpers differ in substance, not just spelling: there is no
    // wider type to promote into, so sign extension happens in place and
    // `INT64_MIN / -1` is guarded rather than left to overflow.
    assert!(c.contains("static inline int64_t axis_sem64_signed(uint64_t value, uint32_t width)"));
    assert!(c.contains("a == INT64_MIN && b == -1"));
    assert!(c.contains("masked | ~((UINT64_C(1) << width) - UINT64_C(1))"));

    let rust = emit_semantics_rust(&a64);
    assert!(rust.contains("pub fn axis_eval_madd_x(rn: u64, rm: u64, ra: u64) -> u64"));
    assert!(rust.contains("fn axis_sem64_signed(value: u64, width: u64) -> i64"));
    assert!(rust.contains("lhs == i64::MIN && rhs == -1"));

    // A 32-bit-only document gains neither wide prelude, so its artifacts are
    // unchanged by any of this.
    let zbb = parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb");
    validate_document(&zbb).expect("validate zbb");
    assert!(!emit_semantics_c(&zbb).contains("axis_sem64_"));
    assert!(!emit_semantics_rust(&zbb).contains("axis_sem64_"));
}

#[test]
fn llvm_ir_lowers_64_bit_semantics() {
    // The pure LLVM path used to stop at 32 bits, skipping 41 of the AArch64
    // seed's 65 pure functions. They now lower in i64 against a prelude
    // rendered from the same template at the wider width.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");
    let ir = emit_llvm_ir(&a64);
    assert!(ir.contains("define i64 @axis_eval_madd_x(i64 %rn, i64 %rm, i64 %ra)"));
    assert!(ir.contains("define internal i64 @axis_sem64_mask(i64 %v, i64 %w)"));
    // W-form instructions still evaluate in i32 in the same module.
    assert!(ir.contains("define i32 @axis_eval_extr_w(i32 %rn, i32 %rm, i32 %lsb)"));
    // The 128-bit SIMD&FP forms are withheld with this reason, so the
    // assertion is now about the *64-bit* semantics this test is named for:
    // nothing at 64 bits or below is turned away for width.
    assert!(!ir.contains("axis_eval_madd_x: widths beyond 64 bits"));

    // The shift-amount mask is width-derived, not a copy of the 32-bit one.
    // Widening the prelude by text substitution missed this and silently
    // masked 64-bit shift amounts to five bits, which `llvm_vs_golden.py`
    // caught on MOVZ/MOVN/EXTR; the template makes it structural.
    assert!(ir.contains("define internal i64 @axis_sem64_shl(i64 %v, i64 %a)"));
    assert!(ir.contains("  %am = and i64 %a, 63\n"));
    assert!(ir.contains("  %am = and i32 %a, 31\n"));
    // Likewise the signed-division overflow guard's most-negative value.
    assert!(ir.contains("i64 %a, -9223372036854775808"));

    // A 32-bit-only module never gains the wide prelude, so its artifact is
    // unchanged by any of this.
    let zbb = parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb");
    validate_document(&zbb).expect("validate zbb");
    assert!(!emit_llvm_ir(&zbb).contains("axis_sem64_"));
}

#[test]
fn llvm_intrinsic_attributes_follow_the_effect_summary() {
    // E5: the purity gate becomes an attribute selector. `IntrReadMem` asserts
    // the intrinsic does not write and `IntrWriteMem` that it does not read, so
    // an instruction doing both carries neither and is merely not `IntrNoMem`.
    let pure = parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb");
    validate_document(&pure).expect("validate zbb");
    assert!(emit_llvm_intrinsics(&pure)
        .contains("[IntrNoMem, IntrWillReturn, IntrSpeculatable]"));

    let store = parse_document(include_str!("../examples/effects_store.axisl"))
        .expect("parse store example");
    validate_document(&store).expect("validate store example");
    let store_td = emit_llvm_intrinsics(&store);
    assert!(store_td.contains("def int_axis_sw_x : Intrinsic<[], [llvm_i32_ty, llvm_i32_ty],"));
    assert!(store_td.contains("[IntrWriteMem, IntrWillReturn]"));
    // A memory access can fault, so it is never marked speculatable.
    assert!(!store_td.contains("IntrSpeculatable"));

    // Control flow and traps are withheld, and the artifact says why rather
    // than leaving a reader to guess whether they were simply missed.
    let mixed = parse_document(include_str!("../examples/fuzz_mix.axisl")).expect("parse fuzz_mix");
    validate_document(&mixed).expect("validate fuzz_mix");
    let mixed_td = emit_llvm_intrinsics(&mixed);
    assert!(mixed_td.contains("// BEQ_X: writes pc; control flow has no intrinsic form"));
    assert!(mixed_td.contains("// TEQ_X: may trap; exceptional control flow has no intrinsic form"));

    // A guarded register write has no intrinsic form either: an intrinsic call
    // always produces its result, while this leaves the destination unchanged
    // on the false path. Marking it IntrNoMem+IntrSpeculatable would be a lie.
    let guarded = parse_document(include_str!("../examples/effects_guarded_set.axisl"))
        .expect("parse guarded example");
    validate_document(&guarded).expect("validate guarded example");
    let guarded_td = emit_llvm_intrinsics(&guarded);
    assert!(guarded_td.contains("// CMOVEQ_X: writes its result under a guard"));
    assert!(!guarded_td.contains("def int_axis_cmoveq_x"));

    // Atomic read-modify-write reads and writes, so it carries neither marker.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 seed");
    validate_document(&a64).expect("validate AArch64 seed");
    let a64_td = emit_llvm_intrinsics(&a64);
    assert!(a64_td.contains("def int_axis_ldar_x : Intrinsic<[llvm_i64_ty], [llvm_i64_ty],\n      [IntrReadMem, IntrWillReturn]>;"));
    assert!(a64_td.contains("// DMB: is an ordering barrier, not a value computation"));
}

#[test]
fn lift_table_json_carries_effects_and_summary() {
    // The JSON lift table is the documented seed artifact for consumers that
    // do not run generated Python/C/Rust. It therefore carries the same ordered
    // effect program those lifters execute, plus a summary of what the
    // instruction touches beyond its operands.
    let mem =
        parse_document(include_str!("../examples/effects_mem.axisl")).expect("parse mem example");
    validate_document(&mem).expect("validate mem example");
    let table = emit_lift_table_json(&mem);
    // The text and the tree, in that order. X1 added the second: a consumer
    // that wants to *compute* with an effect had to parse the first, which is
    // what `pce/aha/optisynth/adl_bridge.py` does and what
    // `binary_lift_design.md` exists to stop. Pinned exactly, because the
    // shape is the contract.
    assert!(table.contains(
        "\"effects\": [{\"kind\": \"set\", \"dest\": \"rd\", \"width\": 32, \"value\": \"(load i32 signed (add rs1 imm))\", \"value_ast\": {\"op\": \"load\", \"type\": \"i32\", \"args\": [{\"symbol\": \"signed\"}, {\"op\": \"add\", \"args\": [{\"symbol\": \"rs1\"}, {\"symbol\": \"imm\"}]}]}, \"eval_width\": 32, \"load_address_width\": 32, \"atomic\": false, \"memory_order\": \"relaxed\"}],"
    ));
    // JSON spelling, not Python's True/False/None (one shared renderer).
    assert!(!table.contains("True"));
    assert!(!table.contains("None"));
    assert!(table.contains(
        "\"effect_summary\": {\"reads_memory\": true, \"writes_memory\": false, \"reads_state\": false, \"writes_state\": false, \"writes_pc\": false, \"may_trap\": false, \"barrier\": false}"
    ));

    // A branch summarises as a PC write, a trap as may_trap.
    let branch = parse_document(include_str!("../examples/effects_branch.axisl"))
        .expect("parse branch example");
    validate_document(&branch).expect("validate branch example");
    assert!(emit_lift_table_json(&branch).contains("\"writes_pc\": true"));
    let trap =
        parse_document(include_str!("../examples/effects_trap.axisl")).expect("parse trap example");
    validate_document(&trap).expect("validate trap example");
    assert!(emit_lift_table_json(&trap).contains("\"may_trap\": true"));

    // A load nested inside a store's value still counts as a memory read --
    // the shape an atomic read-modify-write takes, so the summary walks the
    // whole expression rather than testing its head. `state_width` carries the
    // architectural width, distinct from the 32-bit instruction word.
    let nested = parse_document(
        r#"(axis-module nested_probe
  (version "1.0")
  (target rvmt)

  (defisa rv64_axis
    (base rv64im)
    (word-bits 64)
    (registers "x[32]:i64" "pc:i64")
    (memory-model rvwmo)
    (endianness little)
  )

  (definstruction copy_word
    (mnemonic COPY_WORD)
    (isa rv64_axis)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (encoding (rd 0))
    (operands
      (rs1 reg i64 in)
      (rs2 reg i64 in)
    )
    (behavior
      (store rs1 (load i64 unsigned rs2) i64)
    )
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse nested-load document");
    validate_document(&nested).expect("validate nested-load document");
    let nested_table = emit_lift_table_json(&nested);
    assert!(nested_table.contains("\"state_width\": 64,"));
    assert!(nested_table.contains("\"reads_memory\": true, \"writes_memory\": true"));

    // Pure and free-text instructions keep a null effect list and an
    // all-false summary, so `liftable` still means the pure evaluator path.
    let zbb = parse_document(include_str!("../examples/zbb_like.axisl")).expect("parse zbb example");
    validate_document(&zbb).expect("validate zbb example");
    let zbb_table = emit_lift_table_json(&zbb);
    assert!(zbb_table.contains("\"effects\": null,"));
    assert!(zbb_table.contains(
        "\"effect_summary\": {\"reads_memory\": false, \"writes_memory\": false, \"reads_state\": false, \"writes_state\": false, \"writes_pc\": false, \"may_trap\": false, \"barrier\": false}"
    ));
    assert!(zbb_table.contains("\"liftable\": true"));
}

#[test]
fn named_state_read_reaches_every_executor() {
    // A behavior whose value is a bare ISA-declared state atom has no pure
    // `Sem` form (the atom is not an operand), so the frontend keeps it in the
    // effect layer. Every backend must then emit it: deciding effectfulness
    // from a hardcoded symbol list instead left such an instruction with
    // neither `semantics` nor `effects` — a silent no-op in the lifters and
    // executors that only the runtime differential gates caught.
    let document = parse_document(
        r#"(axis-module sysreg_probe
  (version "1.0")
  (target rvmt)

  (defisa rv32_axis
    (base rv32im)
    (word-bits 32)
    (registers "x[32]:i32" "pc:i32" "ctrl:i32")
    (memory-model rvwmo)
    (endianness little)
  )

  (definstruction read_ctrl
    (mnemonic READ_CTRL)
    (isa rv32_axis)
    (category custom)
    (format R)
    (opcode 11)
    (func3 0)
    (func7 0)
    (operands
      (rd reg i32 out)
    )
    (behavior
      (set rd ctrl)
    )
    (latency 1)
    (throughput 1.0)
    (area-estimate-um2 0.0)
    (power-estimate-mw 0.0)
    (expected-speedup 1.0)
  )
)
    "#,
    )
    .expect("parse state-read document");
    validate_document(&document).expect("validate state-read document");
    let read_ctrl = &document.instructions[0];

    // The pure path cannot hold it, so the typed behavior is authoritative.
    assert!(read_ctrl.formal_semantics.trim().is_empty());
    assert!(read_ctrl.behavior.is_some());

    let lift = emit_lift_python(&document);
    assert!(lift.contains(
        "\"effects\": [{\"kind\": \"set\", \"dest\": \"rd\", \"width\": 32, \"value\": \"ctrl\", \"value_ast\": {\"symbol\": \"ctrl\"}, \"eval_width\": 32}],"
    ));
    // No instruction may end up with neither semantics nor effects.
    assert!(!lift.contains("\"semantics\": None,\n        \"effects\": None,"));

    // The wide executor ABIs carry the state map, so both emit the effect; the
    // compact 32-bit ABI has no state map and correctly declines instead.
    let exec_c = emit_exec_c(&document);
    assert!(exec_c.contains("axis_exec64_eff_READ_CTRL"));
    assert!(exec_c.contains("axis_state64_read(state, \"ctrl\")"));
    assert!(!exec_c.contains("axis_exec_eff_READ_CTRL"));
    let exec_rust = emit_exec_rust(&document);
    assert!(exec_rust.contains("axis_exec64_eff_read_ctrl"));
}

#[test]
fn packets_slot_index_decode_and_publish_one_table() {
    // Slots give the decode space a second index. VSTW and VBRZ carry one bit
    // pattern and validate, because `mem` and `br` are held by disjoint slots
    // -- the same argument disjoint modes already make for one encoding space.
    let document = parse_document(include_str!("../examples/vliw_packet.axisl"))
        .expect("parse packet example");
    validate_document(&document).expect("validate packet example");

    let manifest = emit_packet_manifest_json(&document);
    assert!(manifest.contains("\"schema\": \"axis.issue-packet.v1\""));
    assert!(manifest.contains("\"container_bits\": 128"));
    assert!(manifest.contains(
        "{\"index\": 3, \"name\": \"s3\", \"width\": 32, \"bit_offset\": 96, \"units\": [\"br\"]}"
    ));
    // The slot a syllable may occupy and the bits that identify it are one
    // table, so a packetizer and a decoder built from this file cannot drift.
    assert!(manifest.contains(
        "{\"mnemonic\": \"VSTW\", \"unit\": \"mem\", \"slots\": [0, 1], \"match\": \"0x0000500b\", \"mask\": \"0x0000707f\"}"
    ));
    assert!(manifest.contains(
        "{\"mnemonic\": \"VBRZ\", \"unit\": \"br\", \"slots\": [3], \"match\": \"0x0000500b\", \"mask\": \"0x0000707f\"}"
    ));
    assert!(manifest.contains("{\"mnemonic\": \"VMUL\", \"unit\": \"mul\", \"slots\": [2]"));

    // The Python lifter carries the same shape, and its entries carry a unit.
    let lift = emit_lift_python(&document);
    assert!(lift.contains("\"name\": \"s2\", \"width\": 32, \"units\": (\"alu\", \"mul\")"));
    assert!(lift.contains("\"unit\": \"br\","));

    // Same unit -> one slot holds both -> the encoding collides again. VSTW
    // moves to the branch unit rather than VBRZ to the memory unit, because
    // the latter would put a control transfer in two slots and trip the
    // branch-policy guardrail first, proving something else.
    let twin = include_str!("../examples/vliw_packet.axisl").replace(
        "(mnemonic VSTW)\n    (isa lx32)\n    (category custom)\n    (unit mem)",
        "(mnemonic VSTW)\n    (isa lx32)\n    (category custom)\n    (unit br)",
    );
    let error = validate_document(&parse_document(&twin).unwrap()).unwrap_err();
    assert!(error.to_string().contains("overlap in the decode space"));

    // A unit no slot holds is undecodable, and says so.
    let orphan = include_str!("../examples/vliw_packet.axisl").replace("(unit mul)", "(unit dsp)");
    let error = validate_document(&parse_document(&orphan).unwrap()).unwrap_err();
    assert!(error
        .to_string()
        .contains("is held by no slot of any packet that issues it"));

    // The same slots under `exposed` hazards (stage B3) describe a machine
    // with a shadow: VMUL's latency of 3 leaves two packet boundaries of it,
    // and three of the four slots can put a register write in flight.
    let exposed = include_str!("../examples/vliw_packet.axisl")
        .replace("(hazards interlocked)", "(hazards exposed)");
    let exposed = parse_document(&exposed).expect("parse exposed variant");
    validate_document(&exposed).expect("validate exposed variant");
    let manifest = emit_packet_manifest_json(&exposed);
    assert!(manifest.contains("\"hazards\": \"exposed\","));
    assert!(manifest.contains("\"delay_stages\": 2,"));
    assert!(manifest.contains("\"delay_entries_per_stage\": 3,"));
    // The interlocked original carries no queue at all.
    assert!(emit_packet_manifest_json(&document).contains("\"delay_stages\": 0,"));
}

#[test]
fn packet_slots_refuse_hazards_no_packet_could_resolve() {
    // A packet's contents vary at run time, so what is checkable is its
    // *slots*: if two of them can each hold something that writes one shared
    // location, some legal packet writes it twice.
    let source = include_str!("../examples/vliw_packet.axisl");
    let document = parse_document(source).expect("parse packet example");
    validate_document(&document).expect("the corpus declares no such hazard");

    // Give the ALU a conditional branch: three slots hold ALU work, so three
    // slots could then transfer control, and the packet promised at most one.
    let two_branches = source.replace(
        "    (formal (add i32 rs1 rs2))",
        "    (behavior (set rd (add rs1 rs2)) (when (icmp_eq rs1 rs2) (setpc (add pc rs2))))",
    );
    let error = validate_document(&parse_document(&two_branches).unwrap()).unwrap_err();
    assert!(error
        .to_string()
        .contains("declares `at_most_one` branch, but slots"));

    // Same shape for a fixed architectural location: two slots writing one
    // flag register unconditionally is a second write port nobody declared.
    let two_flag_writers = source
        .replace(
            "(registers \"x[32]:i32\" \"pc:i32\")",
            "(registers \"x[32]:i32\" \"pc:i32\" \"flags:i4\")",
        )
        .replace(
            "    (formal (add i32 rs1 rs2))",
            "    (behavior (set rd (add rs1 rs2)) (setstate flags (add rs1 rs2) i4))",
        );
    let error = validate_document(&parse_document(&two_flag_writers).unwrap()).unwrap_err();
    assert!(error
        .to_string()
        .contains("can both write `state:flags` unconditionally"));
}

#[test]
fn packet_execution_reads_one_state_and_commits_together() {
    // The emitted executor carries the group machinery, and no longer the
    // stage B1 placeholder that ran syllables in sequence.
    let document = parse_document(include_str!("../examples/vliw_packet.axisl"))
        .expect("parse packet example");
    validate_document(&document).expect("validate packet example");
    let exec = emit_exec_python(&document);
    assert!(exec.contains("class _PacketState(dict):"));
    assert!(exec.contains("class _PacketMemory:"));
    assert!(exec.contains("def step_syllable("));
    assert!(exec.contains("def packet_bytes("));
    assert!(!exec.contains("DELIBERATELY NOT YET CORRECT"));
    // A conflict is reported, never resolved by slot order.
    assert!(exec.contains("\"conflicts\": conflicts,"));
    assert!(exec.contains("result[\"committed\"] = False"));
    // The inverse of operand extraction lives next to it, in the lifter.
    assert!(emit_lift_python(&document).contains("def place_operand("));
}

#[test]
fn exposed_latency_puts_its_shadow_in_the_capsule() {
    // Under `hazards exposed` a result in flight is architectural state, so it
    // is part of the checkpoint and therefore part of the hash.
    let source = include_str!("../examples/vliw_exposed.axisl");
    let document = parse_document(source).expect("parse exposed example");
    validate_document(&document).expect("validate exposed example");

    let capsule = emit_state_capsule_manifest_json(&document);
    // XMUL's latency of 3 leaves two packet boundaries of shadow; three slots
    // write a register, so a packet can put three writes in flight.
    assert!(capsule.contains("\"stages\": 2,"));
    assert!(capsule.contains("\"entries_per_stage\": 3,"));
    assert!(capsule.contains("\"entry_bytes\": 16,"));
    assert!(capsule.contains(
        "{\"name\": \"__delay\", \"count\": 6, \"width_bits\": 128, \"byte_offset\": 132}"
    ));
    assert!(capsule.contains("x[32]x32@0;pc[1]x32@128;__delay[6]x128@132"));
    // Two personalities over one ISA share the format, shadow and all.
    assert!(capsule.contains("[\"lane0\", \"lane1\"]"));

    // The same machine with interlocks has no shadow, a shorter capsule, and a
    // different hash — so the manifest cannot call the two migratable.
    let interlocked = source.replace("(hazards exposed)", "(hazards interlocked)");
    let twin = parse_document(&interlocked).expect("parse interlocked twin");
    validate_document(&twin).expect("validate interlocked twin");
    let twin_capsule = emit_state_capsule_manifest_json(&twin);
    assert!(twin_capsule.contains("\"delay_queue\": null"));
    assert!(!twin_capsule.contains("__delay"));
    let hash_of = |manifest: &str| {
        let at = manifest.find("\"layout_hash\": \"").expect("hash");
        manifest[at + 17..at + 81].to_string()
    };
    assert_ne!(hash_of(&capsule), hash_of(&twin_capsule));

    // The executor and the capsule read one derivation of the queue's shape.
    assert!(emit_packet_manifest_json(&document).contains("\"delay_stages\": 2,"));
    assert!(emit_lift_python(&document).contains("\"delay_stages\": 2,"));
    assert!(emit_exec_python(&document).contains("def new_delay_queue("));
}

#[test]
fn exposed_latency_is_bounded_because_it_is_capsule_state() {
    let source = include_str!("../examples/vliw_exposed.axisl");
    // The delay queue's depth is capsule bytes, so the latency that sets it is
    // bounded rather than whatever a description happens to say.
    let deep = source.replace("(latency 3)", "(latency 33)");
    let error = validate_document(&parse_document(&deep).unwrap()).unwrap_err();
    assert!(error.to_string().contains("the delay queue is capsule state"));

    // A pending write waits in a 64-bit field, so a wider register cannot
    // checkpoint its shadow — and says so instead of truncating later.
    let wide = source.replace(
        "(registers \"x[32]:i32\" \"pc:i32\")",
        "(registers \"x[32]:i32\" \"pc:i32\" \"acc:i128\")",
    );
    let error = validate_document(&parse_document(&wide).unwrap()).unwrap_err();
    assert!(error
        .to_string()
        .contains("holds a pending write in 64"));
}

#[test]
fn packet_free_documents_keep_their_artifact_content() {
    // The single-issue world is the degenerate case: no packet manifest
    // content, no `unit` key in the lift table, and an empty packet table
    // rather than an absent one.
    let document = parse_document(include_str!("../examples/zbb_like.axisl"))
        .expect("parse packet-free corpus");
    validate_document(&document).expect("validate packet-free corpus");

    let manifest = emit_packet_manifest_json(&document);
    assert!(manifest.contains("\"packets\": []"));

    let lift = emit_lift_python(&document);
    assert!(lift.contains("AXIS_PACKETS = {\n}"));
    assert!(!lift.contains("\"unit\":"));
}

#[test]
fn modes_gate_decode_disjointness_and_manifest() {
    // Cross-mode encoding reuse validates; the mode-restricted `modes` array
    // appears in manifest.json while mode-free instructions omit it.
    let document = parse_document(include_str!("../examples/mode_polymorphic.axisl"))
        .expect("parse mode example");
    validate_document(&document).expect("validate mode example");

    let manifest = emit_json(&document);
    assert!(manifest.contains("\"modes\": [\"scalar\", \"simt\"]"));
    assert!(manifest.contains("\"modes\": [\"xnn\"]"));
    // ALWAYS_XOR is legal in all modes -> no modes array.
    let xor_idx = manifest.find("\"mnemonic\": \"ALWAYS_XOR\"").expect("xor");
    let next = manifest[xor_idx..]
        .find("\"mnemonic\":")
        .map(|i| xor_idx + i)
        .unwrap_or(manifest.len());
    assert!(!manifest[xor_idx..next].contains("\"modes\""));

    // Same encoding, disjoint modes -> same match in different mode tables.
    let legality = emit_mode_legality_manifest_json(&document);
    assert!(legality.contains("\"schema\": \"axis.mode-legality.v1\""));
    assert!(legality.contains("\"mnemonic\": \"SCALAR_OP\""));
    assert!(legality.contains("\"mnemonic\": \"TENSOR_OP\""));

    // A same-mode encoding collision is rejected.
    let twin = include_str!("../examples/mode_polymorphic.axisl")
        .replace("(modes xnn)", "(modes scalar)");
    let err = validate_document(&parse_document(&twin).unwrap()).unwrap_err();
    assert!(err
        .to_string()
        .contains("overlap in the decode space of a shared mode"));

    // A bad mode reference and an inverted field are rejected.
    let bad_mode =
        include_str!("../examples/mode_polymorphic.axisl").replace("(modes xnn)", "(modes bogus)");
    assert!(validate_document(&parse_document(&bad_mode).unwrap())
        .unwrap_err()
        .to_string()
        .contains("is not a declared mode value"));
}







#[test]
fn the_aarch64_corpus_carries_its_lowerings_and_execution_backends() {
    let lisp = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse AArch64 corpus");
    validate_document(&lisp).expect("validate AArch64 corpus");

    assert_eq!(lisp.instructions.len(), 1715);
    assert_eq!(lisp.lowerings.len(), 435);
    let lowering_manifest = emit_translation_map_json(&lisp);
    assert!(lowering_manifest.contains("\"explicit_lowering_count\": 435"));
    assert!(lowering_manifest.contains("\"preserved_state\": [\"nzcv:i4\"]"));
    assert!(lowering_manifest.contains("\"memory_effects\": [\"load:unsigned:i64\"]"));
    assert!(lowering_manifest.contains("\"memory_effects\": [\"store:i64\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-cmp-x-shifted\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CMP64_SHIFTED\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-bicst-x-shifted\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_BICST64_SHIFTED\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ccmp-x-imm\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CCMP64_IMM\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldursw-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDURS32_64_I9\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldrsw-x-reg\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDRS32_64_REG\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldr-x-post\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDR64_POST_I9\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldr-x-pre\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDR64_PRE_I9\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-str-x-post\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STR64_POST_I9\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldrsb-w-pre\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDRS8_32_PRE_I9\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-str-h-w-post\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STR16_32_POST_I9\""));
    assert!(lowering_manifest.contains(
        "\"effect_order\": [\"register:$loaded<-load:unsigned:i64\", \"register:$base\"]"
    ));
    assert!(lowering_manifest.contains("\"effect_order\": [\"register:$base\", \"store:i64\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldp-x-post\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldp-w-pre\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDP32_PRE_I7\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-stp-x-post\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STP64_POST_I7\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldxr-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDXR64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-stxr-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STXR32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldaxr-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDAXR64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-stlxr-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STLXR32\""));
    assert!(lowering_manifest.contains("load:acquire:unsigned:i64"));
    assert!(lowering_manifest.contains("store:release:i32"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-swp-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_SWP64\""));
    assert!(lowering_manifest.contains(
        "\"memory_effects\": [\"atomic-load:relaxed:unsigned:i64\", \"atomic-store:i64\"]"
    ));
    assert!(lowering_manifest.contains(
        "\"effect_order\": [\"register:$old<-atomic-load:relaxed:unsigned:i64\", \"atomic-store:i64\"]"
    ));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-swpa-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_SWPA64\""));
    assert!(lowering_manifest.contains(
        "\"memory_effects\": [\"atomic-load:acquire:unsigned:i64\", \"atomic-store:i64\"]"
    ));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-swpl-x\""));
    assert!(lowering_manifest.contains(
        "\"memory_effects\": [\"atomic-load:relaxed:unsigned:i64\", \"atomic-store:release:i64\"]"
    ));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-swpal-x\""));
    assert!(lowering_manifest.contains(
        "\"memory_effects\": [\"atomic-load:acquire:unsigned:i64\", \"atomic-store:release:i64\"]"
    ));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-swpalh\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_SWPAL16\""));
    assert!(lowering_manifest.contains(
        "\"memory_effects\": [\"atomic-load:acquire:unsigned:i16\", \"atomic-store:release:i16\"]"
    ));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldaddal-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDADDAL64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldaddalh\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDADDAL16\""));
    assert!(lowering_manifest.contains(
        "\"effect_order\": [\"register:$old<-atomic-load:acquire:unsigned:i64\", \"atomic-store:release:i64\"]"
    ));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldclr-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDCLR64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldclral-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDCLRAL64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldclralh\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDCLRAL16\""));
    assert!(lowering_manifest.contains(
        "\"memory_effects\": [\"atomic-load:acquire:unsigned:i64\", \"atomic-store:release:i64\"]"
    ));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldeor-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDEOR64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldeoral-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDEORAL64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldeoralh\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDEORAL16\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldset-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDSET64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldsetal-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDSETAL64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldsetalh\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDSETAL16\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldsmaxal-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDSMAXAL64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldsminalb\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDSMINAL8\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldumaxalh\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDUMAXAL16\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-lduminal-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDUMINAL64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-casal-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CASAL64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-caspal-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CASPAL64\""));
    assert!(lowering_manifest
        .contains("atomic-group:1:register:$expected0<-atomic-load:acquire:unsigned:i64"));
    assert!(lowering_manifest.contains("atomic-group:1:atomic-store:release:i64"));
    assert!(include_str!("../examples/aarch64_translation_seed.axisl").contains("(input rs)"));
    assert!(lowering_manifest
        .contains("\"memory_effects\": [\"load:unsigned:i64\", \"load:unsigned:i64\"]"));
    assert!(lowering_manifest.contains(
        "\"effect_order\": [\"register:$first<-load:unsigned:i64\", \
         \"register:$second<-load:unsigned:i64\", \"register:$base\"]"
    ));
    assert!(lowering_manifest
        .contains("\"effect_order\": [\"register:$base\", \"store:i64\", \"store:i64\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-b-cond\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_B_COND_I19\""));
    assert!(lowering_manifest.contains("\"effect_order\": [\"pc:guarded\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ret\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_BR64\""));
    assert!(lowering_manifest.contains("\"effect_order\": [\"pc\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-bl\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_BL_I26\""));
    assert!(lowering_manifest
        .contains("\"effect_order\": [\"fixed-register:a64_gpr64:30:i64\", \"pc\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-blr\""));
    assert!(lowering_manifest
        .contains("\"effect_order\": [\"pc\", \"fixed-register:a64_gpr64:30:i64\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-cbz-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CBZ32_I19\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-tbnz-x-high\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_TBNZ64_HIGH_I14\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-add-w-imm-sp\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_ADD32_IMM_SP\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-cmp-x-imm\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CMP64_IMM\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-add-w-ext-sp\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_ADD32_EXT_SP\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-cmp-x-ext\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CMP64_EXT\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-orr-w-shifted\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_ORR32_SHIFTED\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-tst-x-shifted\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_TST64_SHIFTED\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-rorv-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_RORV32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-movk-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_MOVK64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-tst-w-imm\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_TST32_IMM\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-bfm-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_BFM32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldrsb-x-unsigned\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDRS8_64_U12\""));
    assert!(lowering_manifest.contains("\"memory_effects\": [\"load:signed:i8\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-strh-w-unsigned\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STR16_32_U12\""));
    assert!(lowering_manifest.contains("\"memory_effects\": [\"store:i16\"]"));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldr-x-reg-lsl3\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDR64_REG_LSL3\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-str-x-reg-lsl3\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STR64_REG_LSL3\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-madd-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_MADD64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-msub-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_MSUB32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-sdiv-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_SDIV32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-csneg-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CSNEG32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-rbit-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_RBIT64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-cls-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CLS32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-sbcs-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_SBCS32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-smulh-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_SMULH64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-extr-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_EXTR32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-umsubl\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_UMSUBL\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldaxp-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDAXP64\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-stlxp-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STLXP32\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-clrex\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_CLREX\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-dmb\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_DMB\""));
    assert!(lowering_manifest.contains("\"effect_order\": [\"barrier:dmb:i4\"]"));
    for (lowering, target, kind) in [
        ("lower-a64-sb", "ACCEL_SB", "sb"),
        ("lower-a64-csdb", "ACCEL_CSDB", "csdb"),
        ("lower-a64-ssbb", "ACCEL_SSBB", "ssbb"),
        ("lower-a64-pssbb", "ACCEL_PSSBB", "pssbb"),
    ] {
        assert!(lowering_manifest.contains(&format!("\"name\": \"{lowering}\"")));
        assert!(lowering_manifest.contains(&format!("\"mnemonic\": \"{target}\"")));
        assert!(lowering_manifest.contains(&format!("\"effect_order\": [\"barrier:{kind}:i4\"]")));
    }
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-mrs-nzcv\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_MRS_NZCV\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-msr-nzcv\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_MSR_NZCV\""));
    for (lowering, target) in [
        ("lower-a64-mrs-fpcr", "ACCEL_MRS_FPCR"),
        ("lower-a64-msr-fpcr", "ACCEL_MSR_FPCR"),
        ("lower-a64-mrs-fpsr", "ACCEL_MRS_FPSR"),
        ("lower-a64-msr-fpsr", "ACCEL_MSR_FPSR"),
        ("lower-a64-mrs-tpidr-el0", "ACCEL_MRS_TPIDR_EL0"),
        ("lower-a64-msr-tpidr-el0", "ACCEL_MSR_TPIDR_EL0"),
        ("lower-a64-mrs-tpidrro-el0", "ACCEL_MRS_TPIDRRO_EL0"),
    ] {
        assert!(lowering_manifest.contains(&format!("\"name\": \"{lowering}\"")));
        assert!(lowering_manifest.contains(&format!("\"mnemonic\": \"{target}\"")));
    }
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-ldarb-w\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_LDAR8\""));
    assert!(lowering_manifest.contains("\"name\": \"lower-a64-stlr-x\""));
    assert!(lowering_manifest.contains("\"mnemonic\": \"ACCEL_STLR64\""));
    let decode = emit_decode_table_json(&lisp);
    let pair_encodings = [
        ("LDXP_W", "0x887f0000", "0xffff8000"),
        ("LDAXP_W", "0x887f8000", "0xffff8000"),
        ("STXP_W", "0x88200000", "0xffe08000"),
        ("STLXP_W", "0x88208000", "0xffe08000"),
        ("LDXP_X", "0xc87f0000", "0xffff8000"),
        ("LDAXP_X", "0xc87f8000", "0xffff8000"),
        ("STXP_X", "0xc8200000", "0xffe08000"),
        ("STLXP_X", "0xc8208000", "0xffe08000"),
    ];
    for (mnemonic, expected_match, expected_mask) in pair_encodings {
        let expected = format!(
            "\"mnemonic\": \"{mnemonic}\",\n      \"isa\": \"aarch64_base\",\n      \"format\": \"A64_LDST_EXCLUSIVE_PAIR\","
        );
        let start = decode
            .find(&expected)
            .expect("paired exclusive decode entry");
        let entry = &decode[start..];
        assert!(entry.starts_with(&expected));
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains(&format!("\"match\": \"{expected_match}\"")));
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains(&format!("\"mask\": \"{expected_mask}\"")));
    }
    assert!(decode.contains(
        "\"mnemonic\": \"CLREX\",\n      \"isa\": \"aarch64_base\",\n      \"format\": \"A64_CLREX\",\n      \"bits\": 32,\n      \"asm\": \"clrex #$option\",\n      \"match\": \"0xd503305f\",\n      \"mask\": \"0xfffff0ff\""
    ));
    for (mnemonic, expected_match) in [
        ("DMB", "0xd50330bf"),
        ("DSB", "0xd503309f"),
        ("ISB", "0xd50330df"),
    ] {
        let expected = format!("\"mnemonic\": \"{mnemonic}\",");
        let start = decode.find(&expected).expect("barrier decode entry");
        let entry = &decode[start..];
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains(&format!("\"match\": \"{expected_match}\"")));
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains("\"mask\": \"0xfffff0ff\""));
    }
    for (mnemonic, expected_match) in [
        ("MRS_NZCV", "0xd53b4200"),
        ("MSR_NZCV", "0xd51b4200"),
        ("MRS_FPCR", "0xd53b4400"),
        ("MSR_FPCR", "0xd51b4400"),
        ("MRS_FPSR", "0xd53b4420"),
        ("MSR_FPSR", "0xd51b4420"),
        ("MRS_TPIDR_EL0", "0xd53bd040"),
        ("MSR_TPIDR_EL0", "0xd51bd040"),
        ("MRS_TPIDRRO_EL0", "0xd53bd060"),
    ] {
        let expected = format!("\"mnemonic\": \"{mnemonic}\",");
        let start = decode.find(&expected).expect("NZCV system-register entry");
        let entry = &decode[start..];
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains(&format!("\"match\": \"{expected_match}\"")));
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains("\"mask\": \"0xffffffe0\""));
    }
    for (mnemonic, expected_match) in [
        ("SB", "0xd50330ff"),
        ("CSDB", "0xd503229f"),
        ("SSBB", "0xd503309f"),
        ("PSSBB", "0xd503349f"),
    ] {
        let expected = format!("\"mnemonic\": \"{mnemonic}\",");
        let start = decode
            .find(&expected)
            .expect("specialized barrier decode entry");
        let entry = &decode[start..];
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains(&format!("\"match\": \"{expected_match}\"")));
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains("\"mask\": \"0xffffffff\""));
    }
    for (mnemonic, expected_match) in [
        ("STLRB_W", "0x089ffc00"),
        ("LDARB_W", "0x08dffc00"),
        ("STLRH_W", "0x489ffc00"),
        ("LDARH_W", "0x48dffc00"),
        ("STLR_W", "0x889ffc00"),
        ("LDAR_W", "0x88dffc00"),
        ("STLR_X", "0xc89ffc00"),
        ("LDAR_X", "0xc8dffc00"),
    ] {
        let expected = format!("\"mnemonic\": \"{mnemonic}\",");
        let start = decode.find(&expected).expect("ordered memory decode entry");
        let entry = &decode[start..];
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains(&format!("\"match\": \"{expected_match}\"")));
        assert!(entry[..entry.find("\"decode_key\"").expect("decode key")]
            .contains("\"mask\": \"0xfffffc00\""));
    }
    let exec_c = emit_exec_c(&lisp);
    assert!(
        exec_c
            .matches("axis_state64_read(state, \"exclusive_valid\")")
            .count()
            >= 16,
        "C wide executor must retain every variadic reservation predicate operand"
    );
    let exec_rust = emit_exec_rust(&lisp);
    assert!(
        exec_rust
            .matches("state64_read(state, \"exclusive_valid\")")
            .count()
            >= 16,
        "Rust wide executor must retain every variadic reservation predicate operand"
    );
    let pyrtl = emit_pyrtl(&lisp);
    assert!(pyrtl.contains("def _udiv(lhs, rhs, width):"));
    assert!(pyrtl.contains("return _udiv(vals[0], vals[1], width)"));
    assert!(!pyrtl.contains("vals[0] // vals[1]"));

    let wrong_flags = include_str!("../examples/aarch64_translation_seed.axisl").replace(
        "(setstate nzcv (a64_add_nzcv i64 rn (a64_shift_reg i64 rm shift amount)) i4)",
        "(setstate nzcv (a64_sub_nzcv i64 rn (a64_shift_reg i64 rm shift amount)) i4)",
    );
    let error = validate_document(&parse_document(&wrong_flags).unwrap())
        .expect_err("mismatched target NZCV behavior must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let source = include_str!("../examples/aarch64_translation_seed.axisl");
    let marker = source
        .find("(definstruction accel_ldaxr64")
        .expect("accelerator acquire-exclusive target");
    let mut lost_acquire = source.to_string();
    // Only the ORDERING is dropped, the atomicity kept -- which is a sharper
    // mutation than the one this used to make. The load-exclusive family used
    // to record its ordering on a plain `load`, where no ordering can reach
    // the IR; it says `atomic_load` now, so the acquire is the one thing this
    // takes away.
    let changed_suffix = lost_acquire[marker..].replacen(
        "(atomic_load i64 unsigned acquire rn)",
        "(atomic_load i64 unsigned relaxed rn)",
        1,
    );
    lost_acquire.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&lost_acquire).unwrap())
        .expect_err("dropping acquire ordering must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_swp64")
        .expect("accelerator atomic-swap target");
    let mut lost_atomicity = source.to_string();
    let changed_suffix = lost_atomicity[marker..]
        .replacen("(atomic_load i64", "(load i64", 1)
        .replacen("(atomic_store rn rs i64", "(store rn rs i64", 1);
    lost_atomicity.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&lost_atomicity).unwrap())
        .expect_err("dropping atomicity must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(accel_ldadd64 ACCEL_LDADD64")
        .expect("accelerator atomic fetch-add family row");
    let mut wrong_atomic_add = source.to_string();
    let changed_suffix = wrong_atomic_add[marker..].replacen(
        "(atomic_store rn (add $type rt rs)",
        "(atomic_store rn (sub $type rt rs)",
        1,
    );
    wrong_atomic_add.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_atomic_add).unwrap())
        .expect_err("changing atomic add dataflow must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_adcs64")
        .expect("accelerator add-with-carry flags target");
    let mut wrong_carry_flags = source.to_string();
    let changed_suffix = wrong_carry_flags[marker..].replacen("a64_adc_nzcv", "a64_sbc_nzcv", 1);
    wrong_carry_flags.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_carry_flags).unwrap())
        .expect_err("mismatched carry-chain NZCV behavior must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let source = include_str!("../examples/aarch64_translation_seed.axisl");
    let marker = source
        .find("(definstruction accel_ands64_shifted")
        .expect("accelerator logical-flags target");
    let mut wrong_logical_flags = source.to_string();
    let changed_suffix =
        wrong_logical_flags[marker..].replacen("(a64_logic_nzcv i64", "(a64_logic_nzcv i32", 1);
    wrong_logical_flags.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_logical_flags).unwrap())
        .expect_err("mismatched target logical NZCV width must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_bfm64")
        .expect("accelerator destructive bitfield target");
    let mut wrong_bitfield_order = source.to_string();
    let changed_suffix = wrong_bitfield_order[marker..].replacen(
        "(a64_bfm i64 rd rn immr imms)",
        "(a64_bfm i64 rd rn imms immr)",
        1,
    );
    wrong_bitfield_order.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_bitfield_order).unwrap())
        .expect_err("swapped target bitfield immediates must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_ldrs8_64_u12")
        .expect("accelerator sign-extending byte-load target");
    let mut wrong_load_signedness = source.to_string();
    let changed_suffix = wrong_load_signedness[marker..].replacen(
        "(load i8 signed (add rn imm))",
        "(load i8 unsigned (add rn imm))",
        1,
    );
    wrong_load_signedness.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_load_signedness).unwrap())
        .expect_err("dropping target load sign extension must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_ldr64_reg_lsl3")
        .expect("accelerator register-offset load target");
    let mut wrong_index_scale = source.to_string();
    let changed_suffix = wrong_index_scale[marker..].replacen("(mul s 3)", "(mul s 2)", 1);
    wrong_index_scale.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_index_scale).unwrap())
        .expect_err("wrong target register-index scale must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_msub64")
        .expect("accelerator multiply-subtract target");
    let mut wrong_multiply_accumulation = source.to_string();
    let changed_suffix = wrong_multiply_accumulation[marker..].replacen(
        "(sub ra (mul rn rm))",
        "(add ra (mul rn rm))",
        1,
    );
    wrong_multiply_accumulation.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_multiply_accumulation).unwrap())
        .expect_err("wrong multiply accumulation direction must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_sdiv64")
        .expect("accelerator signed-division target");
    let mut wrong_division_signedness = source.to_string();
    let changed_suffix =
        wrong_division_signedness[marker..].replacen("(sdiv i64 rn rm)", "(udiv i64 rn rm)", 1);
    wrong_division_signedness.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_division_signedness).unwrap())
        .expect_err("wrong division signedness must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_csneg64")
        .expect("accelerator conditional-negate target");
    let mut wrong_conditional_transform = source.to_string();
    let changed_suffix =
        wrong_conditional_transform[marker..].replacen("(sub i64 0 rm)", "(add i64 0 rm)", 1);
    wrong_conditional_transform.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_conditional_transform).unwrap())
        .expect_err("wrong conditional false-path transform must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_rev16_64")
        .expect("accelerator REV16 target");
    let mut wrong_byte_lane_width = source.to_string();
    let changed_suffix =
        wrong_byte_lane_width[marker..].replacen("(a64_rev16_64 rn)", "(a64_rev32_64 rn)", 1);
    wrong_byte_lane_width.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_byte_lane_width).unwrap())
        .expect_err("wrong byte-lane reversal width must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_lslv64")
        .expect("accelerator variable-shift target");
    let mut wrong_variable_shift_width = source.to_string();
    let changed_suffix = wrong_variable_shift_width[marker..].replacen(
        "(a64_shift_reg i64 rn 0 rm)",
        "(a64_shift_reg i32 rn 0 rm)",
        1,
    );
    wrong_variable_shift_width.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_variable_shift_width).unwrap())
        .expect_err("mismatched variable-shift width must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_movk64")
        .expect("accelerator move-keep target");
    let mut wrong_movk_mask = source.to_string();
    let changed_suffix =
        wrong_movk_mask[marker..].replacen("(shl i64 0xffff ", "(shl i64 0xff ", 1);
    wrong_movk_mask.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_movk_mask).unwrap())
        .expect_err("mismatched MOVK halfword mask must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_and32_imm")
        .expect("accelerator W logical-immediate target");
    let mut wrong_logical_mask_fields = source.to_string();
    let changed_suffix = wrong_logical_mask_fields[marker..].replacen(
        "(a64_wmask i32 0 immr imms)",
        "(a64_wmask i32 0 imms immr)",
        1,
    );
    wrong_logical_mask_fields.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_logical_mask_fields).unwrap())
        .expect_err("swapped logical-immediate mask fields must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let source = include_str!("../examples/aarch64_translation_seed.axisl");
    let marker = source
        .find("(definstruction accel_ldr64_u12")
        .expect("accelerator load target");
    let mut wrong_address = source.to_string();
    let changed_suffix = wrong_address[marker..].replacen("(shl imm 3)", "(shl imm 2)", 1);
    wrong_address.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_address).unwrap())
        .expect_err("mismatched target memory address must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let source = include_str!("../examples/aarch64_translation_seed.axisl");
    let marker = source
        .find("(definstruction accel_ldr64_post_i9")
        .expect("accelerator post-index load target");
    let mut wrong_order = source.to_string();
    let original = "(behavior\n      (set rt (load i64 unsigned rn))\n      (set rn (add rn (sext i64 9 imm)))\n    )";
    let reversed = "(behavior\n      (set rn (add rn (sext i64 9 imm)))\n      (set rt (load i64 unsigned rn))\n    )";
    let changed_suffix = wrong_order[marker..].replacen(original, reversed, 1);
    wrong_order.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_order).unwrap())
        .expect_err("reordered target writeback must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_b_i26")
        .expect("accelerator direct branch target");
    let mut wrong_pc = source.to_string();
    let changed_suffix =
        wrong_pc[marker..].replacen("(shl (sext i64 26 imm) 2)", "(shl (sext i64 26 imm) 1)", 1);
    wrong_pc.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_pc).unwrap())
        .expect_err("mismatched target PC behavior must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_b_cond_i19")
        .expect("accelerator conditional branch target");
    let mut wrong_pc_guard = source.to_string();
    let changed_suffix = wrong_pc_guard[marker..].replacen(
        "(icmp_ne (a64_cond_holds",
        "(icmp_eq (a64_cond_holds",
        1,
    );
    wrong_pc_guard.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_pc_guard).unwrap())
        .expect_err("mismatched target PC guard must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_bl_i26")
        .expect("accelerator direct call target");
    let mut wrong_link = source.to_string();
    let changed_suffix =
        wrong_link[marker..].replacen("(setreg reg 30 i64", "(setreg reg 29 i64", 1);
    wrong_link.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_link).unwrap())
        .expect_err("mismatched target fixed-register write must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_tbz64_high_i14")
        .expect("accelerator high-half test branch target");
    let mut wrong_test_bit = source.to_string();
    let changed_suffix =
        wrong_test_bit[marker..].replacen("(shl 1 (add bit 32))", "(shl 1 bit)", 1);
    wrong_test_bit.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_test_bit).unwrap())
        .expect_err("mismatched target test-bit half must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let marker = source
        .find("(definstruction accel_add64_imm_sp")
        .expect("accelerator immediate-add target");
    let mut wrong_immediate_shift = source.to_string();
    let changed_suffix =
        wrong_immediate_shift[marker..].replacen("(mul i64 sh 12)", "(mul i64 sh 11)", 1);
    wrong_immediate_shift.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_immediate_shift).unwrap())
        .expect_err("mismatched target immediate shift must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let mut wrong_sp_bridge = source.to_string();
    let changed_suffix = wrong_sp_bridge[marker..].replacen("(rd a64_gpr64sp", "(rd reg", 1);
    wrong_sp_bridge.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_sp_bridge).unwrap())
        .expect_err("dropping target SP semantics without a register-31 guard must fail");
    assert!(error
        .to_string()
        .contains("changes register-31 SP semantics"));

    let marker = source
        .find("(definstruction accel_add64_ext_sp")
        .expect("accelerator extended-add target");
    let mut wrong_extension_width = source.to_string();
    let changed_suffix = wrong_extension_width[marker..].replacen(
        "(a64_extend_reg i64 rm option amount)",
        "(a64_extend_reg i32 rm option amount)",
        1,
    );
    wrong_extension_width.replace_range(marker.., &changed_suffix);
    let error = validate_document(&parse_document(&wrong_extension_width).unwrap())
        .expect_err("mismatched target extension width must fail lowering proof");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));
}

#[test]
fn lisp_explicit_lowering_proves_and_emits_a_multi_instruction_rewrite() {
    let source = include_str!("../examples/lisp_lowerings.axisl");
    let document = parse_document(source).expect("parse lowering example");
    validate_document(&document).expect("validate and prove lowering example");
    assert_eq!(document.lowerings.len(), 1);
    assert_eq!(document.lowerings[0].sources.len(), 2);

    let translation = emit_translation_map_json(&document);
    assert!(translation.contains("\"explicit_lowering_count\": 1"));
    assert!(translation.contains("\"name\": \"fuse-a64-add-chain\""));
    assert!(translation.contains("\"source_sequence\": ["));
    assert!(translation.contains("\"target_cycles\": 1"));
    assert!(translation.contains("\"semantic_equivalence\": \"proven\""));
    assert!(translation.contains("\"kind\": \"compare\", \"op\": \"ne\""));
    assert!(translation.contains("\"fields\": [{\"insn_lo\":"));

    let translator = emit_translation_python(&document);
    assert!(translator.contains("AXIS_SCHEMA = \"axis.translation-python.v1\""));
    assert!(translator.contains("def match_at(words, index=0"));
    assert!(translator.contains("def rewrite_once(words, index=0"));
    assert!(translator.contains("def rewrite_all(words, source_isa=None"));

    let canonical = emit_lisp(&document);
    let roundtripped = parse_document(&canonical).expect("parse canonical lowering Lisp");
    validate_document(&roundtripped).expect("validate canonical lowering Lisp");
    assert_eq!(roundtripped, document);
    assert_eq!(emit_lisp(&roundtripped), canonical);

    let wrong_semantics = source.replace(
        "(formal (add i64 (add i64 rs1 rs2) rs3))",
        "(formal (xor i64 (add i64 rs1 rs2) rs3))",
    );
    let error = validate_document(&parse_document(&wrong_semantics).unwrap())
        .expect_err("non-equivalent lowering must fail");
    assert!(error
        .to_string()
        .contains("source sequence is not semantically identical"));

    let unknown_binding = source.replace("(!= $tmp $lhs)", "(!= $ghost $lhs)");
    let error = validate_document(&parse_document(&unknown_binding).unwrap())
        .expect_err("unknown predicate binding must fail");
    assert!(error
        .to_string()
        .contains("predicate references unknown variable `$ghost`"));

    let invalid_discard = source.replace("(rd $tmp)", "(rd 30)");
    let error = validate_document(&parse_document(&invalid_discard).unwrap())
        .expect_err("only encoded AArch64 register 31 may discard an output");
    assert!(error
        .to_string()
        .contains("literal 31 only for an AArch64 zero-register discard"));
}

#[test]
fn personality_composition_binds_modes_and_topology() {
    let document = parse_document(include_str!("../examples/personality_composition.axisl"))
        .expect("parse composition example");
    validate_document(&document).expect("validate composition example");

    // Personalities bind distinct mode values.
    assert_eq!(document.personalities[0].mode, "scalar");
    assert_eq!(document.personalities[1].mode, "simt");
    assert!(document.cores[0]
        .personalities
        .contains(&"xnn0".to_string()));

    // Topology carries the composed personalities with their disciplines.
    let topo = emit_adl_topology_manifest_json(&document);
    assert!(topo.contains("\"personalities\": ["));
    assert!(topo.contains("\"name\": \"simt8\", \"mode\": \"simt\""));
    assert!(topo.contains(
        "\"discipline\": {\"kind\": \"systolic\", \"params\": {\"rows\": 8, \"cols\": 8}}"
    ));

    // A core without composed personalities keeps the plain topology object.
    let plain = parse_document(include_str!("../examples/rvmt_xpce.axisl")).expect("rvmt");
    assert!(!emit_adl_topology_manifest_json(&plain).contains("\"personalities\""));

    // Validation guardrails: unknown mode binding, duplicate binding, unknown
    // personality in a core.
    let src = include_str!("../examples/personality_composition.axisl");
    let bad_bind = src.replace("(mode xnn)", "(mode bogus)");
    assert!(validate_document(&parse_document(&bad_bind).unwrap())
        .unwrap_err()
        .to_string()
        .contains("is not a declared mode value"));
    let dup_bind = src.replace("(mode simt)", "(mode scalar)");
    assert!(validate_document(&parse_document(&dup_bind).unwrap())
        .unwrap_err()
        .to_string()
        .contains("already bound by another personality"));
    let bad_core = src.replace(
        "(personalities scalar1 simt8 xnn0)",
        "(personalities scalar1 ghost)",
    );
    assert!(validate_document(&parse_document(&bad_core).unwrap())
        .unwrap_err()
        .to_string()
        .contains("composes unknown personality"));
}

#[test]
fn exec_python_mode_aware_dispatch() {
    let document = parse_document(include_str!("../examples/mode_polymorphic.axisl"))
        .expect("parse mode example");
    validate_document(&document).expect("validate");

    // The lift table carries per-instruction legal modes (only in a mode doc).
    let lift = emit_lift_python(&document);
    assert!(lift.contains("\"modes\": [\"scalar\", \"simt\"],"));
    assert!(lift.contains("\"modes\": [\"xnn\"],"));

    // The executor gains a mode-aware decode and an illegal-in-mode trap.
    let exec = emit_exec_python(&document);
    assert!(exec.contains("def step(word, regs, mem=None, pc=0, mode=None, isa=None, state=None):"));
    assert!(exec.contains("def decode_in_mode(word, mode, isa=None):"));
    assert!(exec.contains("if mode is not None:"));
    assert!(exec.contains("\"trap\": \"illegal\""));

    // A mode-free document's lift table carries no `modes` field (byte-identical).
    let plain = parse_document(include_str!("../examples/zbb_like.axisl")).expect("zbb");
    assert!(!emit_lift_python(&plain).contains("\"modes\":"));
}

// --- policies as accelerators, and the backend parity that makes them shippable ---------------

/// A policy is a pure function of committed state, so `defaccelerator` + `formal` already
/// expresses one. This pins that the four backends a shippable policy needs all produce it from
/// one source: the datapath, the reference model, the proof obligation, and the fast path.
#[test]
fn a_policy_accelerator_reaches_every_backend_a_shippable_policy_needs() {
    let source = include_str!("../examples/policy_accelerator.axisl");
    let document = parse_document(source).expect("parse policy example");
    validate_document(&document).expect("validate policy example");

    let pyrtl = emit_pyrtl(&document);
    assert!(pyrtl.contains("def build_victim_select_2way_module"));
    assert!(pyrtl.contains("pyrtl.Input(32, f\"{prefix}_age0\")"));
    assert!(pyrtl.contains("pyrtl.Output(32, f\"{prefix}_victim\")"));

    let golden = emit_golden_python(&document);
    assert!(golden.contains("def eval_victim_select_2way"));

    let smt = emit_smt2(&document);
    assert!(smt.contains("define-fun axis_accel_victim_select_2way"));

    let rust = emit_semantics_rust(&document);
    assert!(rust.contains("axis_eval_victim_select_2way"));

    // `defsem` is inlined during elaboration, so no backend sees the helper as a call.
    assert!(!pyrtl.contains("way_score("));
}

/// The gap this test exists for: `emit_golden_python` implemented all six integer comparisons and
/// `emit_pyrtl` implemented none, so a module that COMPARES two values passed `check`, emitted
/// happily, and then raised `NotImplementedError` at elaboration. The failure presented as a broken
/// design rather than as a missing backend op.
///
/// Asserted as PARITY rather than presence: a comparison one backend can evaluate and the other
/// cannot is the defect, whichever backend is behind. Floating point and the widening multiplies
/// are knowingly absent from the PyRTL backend and are listed here so that a NEW divergence fails
/// while the known one does not silently grow.
#[test]
fn the_pyrtl_and_golden_backends_dispatch_the_same_integer_ops() {
    let source = include_str!("../examples/policy_accelerator.axisl");
    let document = parse_document(source).expect("parse policy example");
    let pyrtl = emit_pyrtl(&document);
    let golden = emit_golden_python(&document);

    const COMPARISONS: [&str; 6] = [
        "icmp_eq", "icmp_ne", "icmp_slt", "icmp_sge", "icmp_ult", "icmp_uge",
    ];
    for op in COMPARISONS {
        let quoted = format!("'{op}'");
        assert!(golden.contains(&quoted), "golden backend lost {op}");
        assert!(
            pyrtl.contains(&quoted),
            "pyrtl backend does not dispatch {op}; a policy comparing two values will emit and \
             then raise at elaboration"
        );
    }

    // Known, deliberate divergence. Extend only with a reason.
    const PYRTL_ABSENT: [&str; 4] = ["fadd", "fmul", "mulh", "mulhu"];
    for op in PYRTL_ABSENT {
        let quoted = format!("'{op}'");
        assert!(
            !pyrtl.contains(&quoted),
            "{op} is now in the pyrtl backend — move it out of the known-absent list"
        );
    }
}


// --- `setstate` becomes executable ----------------------------------------------------------

/// An instruction whose whole job is to set state computes no value, so `eval_<mnemonic>` raises
/// for it -- correctly. What was missing is the other half: `Loc::State` is handled by the lift,
/// lisp and LLVM emitters and by NONE of the executable ones, so an instruction declared to write
/// state emitted as an instruction that does nothing.
#[test]
fn the_golden_model_can_apply_an_instructions_state_writes() {
    let source = include_str!("../examples/policy_hint.axisl");
    let document = parse_document(source).expect("parse policy hint");
    validate_document(&document).expect("validate policy hint");
    let golden = emit_golden_python(&document);

    assert!(golden.contains("STATE_EFFECTS = {"));
    assert!(golden.contains("def apply_state_effects("));
    assert!(golden.contains("def writes_state("));
    assert!(golden.contains("\"CACHE_HINT\": ["));
    assert!(golden.contains("\"state\": \"cache_policy\""));
    // The value half is the same renderer and evaluator every other table here uses.
    assert!(golden.contains("\"expr\": \"rs1\""));

    // And it still raises for the VALUE, because there is not one.
    assert!(golden.contains("has no pure value semantics"));
}

/// The shipped case, not only the new one: GRV's mask ops are this tree's existing `setstate`
/// example and were inert in every executable emitter.
#[test]
fn the_shipped_mask_ops_now_emit_their_state_writes() {
    let source = include_str!("../examples/grv_simt.axisl");
    let document = parse_document(source).expect("parse grv");
    let golden = emit_golden_python(&document);

    for mnemonic in ["VSETMASK", "VMASKALL", "VMASKI", "VIF", "VELSE", "VENDIF"] {
        assert!(
            golden.contains(&format!("\"{mnemonic}\": [")),
            "{mnemonic} writes architectural state and emits none"
        );
    }
    assert!(golden.contains("\"state\": \"exec_mask\""));
    assert!(golden.contains("\"state\": \"mask_enclosing\""));
}

/// An instruction that writes no state must not acquire an entry -- otherwise `writes_state`
/// answers yes for everything and stops meaning anything.
#[test]
fn an_instruction_with_no_state_effects_gets_no_entry() {
    let source = include_str!("../examples/policy_hint.axisl");
    let document = parse_document(source).expect("parse policy hint");
    let golden = emit_golden_python(&document);
    assert!(!golden.contains("\"POLICY_NOP\": ["));
}

/// A document whose instructions write no state still emits the table and the helpers, so a
/// consumer can call them unconditionally rather than probing for their existence.
#[test]
fn the_helpers_are_emitted_even_when_nothing_writes_state() {
    let source = include_str!("../examples/lisp_semantics.axisl");
    let document = parse_document(source).expect("parse lisp semantics");
    let golden = emit_golden_python(&document);
    assert!(golden.contains("STATE_EFFECTS = {"));
    assert!(golden.contains("def apply_state_effects("));
}

#[test]
fn conversion_exceptions_are_lowered_or_declined_but_never_extended() {
    // The five `fcvt_*_fx` operators carry two widths, like the conversions
    // they mirror, so they arrive as `Sem::Ext` rather than `Sem::App`. Both
    // Ext lowerings end in a catch-all that emits a sign- or zero-extend, and
    // a new operator falling into it would have emitted the *value* where a
    // flag word was asked for -- a plausible integer for a question about
    // exceptions, which no differential could see, because every backend
    // would extend it the same way. Each lowering therefore names them.
    let fp = parse_document(include_str!("../examples/fp_exceptions.axisl"))
        .expect("parse fp exceptions");
    validate_document(&fp).expect("validate fp exceptions");

    // C answers. Float-to-integer is the one that cannot use the environment:
    // AXIS specifies saturation, and the C cast whose flags `fetestexcept`
    // would report is undefined in exactly the out-of-range case that has to
    // signal, so its invalid and inexact are decided explicitly.
    let exec = emit_exec_c(&fp);
    assert!(exec.contains("axis_fp_to_int_fx"), "float to integer computes its flags");
    assert!(exec.contains("axis_fp_s2f_fx"), "integer to float reads the environment");
    assert!(exec.contains("axis_fp_f2f_fx"), "float to float reads the environment");
    let header = emit_semantics_c(&fp);
    assert!(header.contains("#include <fenv.h>"), "the exception forms need the environment");

    // Rust declines by absence in the executor, as it does for the arithmetic
    // exception forms: no `axis_fp_to_int_fx` to call, and -- the point of the
    // test -- no extend standing in for one.
    let rust = emit_exec_rust(&fp);
    assert!(!rust.contains("axis_fp_to_int_fx"));
    assert!(
        !rust.contains("fcvt_f2s_fx"),
        "a declined operator is absent, not emitted under another name"
    );
}

#[test]
fn an_exception_word_cannot_be_used_as_a_value() {
    // The SMT emitter declines to lower an exception form with an
    // `unreachable!` rather than a decline, and says why: the flags an
    // operation raises are architectural state, so they live in a behavior and
    // this path never sees them. That was an assumption about how corpora are
    // written, not a rule -- a `formal` naming an `_fx` operator parsed,
    // validated, and panicked the backend. Validation states the rule now, so
    // the assumption is one.
    let source = include_str!("../examples/fp_exceptions.axisl").replace(
        "    (behavior\n      (set rd (fadd f64 rs1 rs2))\n\
         \x20     (setstate fflags (or i5 fflags (fadd_fx f64 rs1 rs2)) i5))",
        "    (formal (or i64 (fadd_fx f64 rs1 rs2) 0))",
    );
    let document = parse_document(&source).expect("a formal exception word still parses");
    let error = validate_document(&document)
        .expect_err("an exception word used as a value is rejected");
    assert!(
        error.message.contains("architectural state"),
        "the message says why, not just that: {}",
        error.message
    );
    assert!(
        error.message.contains("setstate fflags"),
        "and says what to write instead: {}",
        error.message
    );
}

#[test]
fn a_mask_saturates_at_the_width_in_every_backend() {
    // `(ones i64 n)` is a mask of n low bits, and n is an expression -- which
    // is the whole reason it exists, since a mask whose width is known when the
    // description is written could be a literal. That makes "n at or past the
    // width" reachable, and it is the case the backends do not agree on by
    // default: `1 << n` is zero in SMT-LIB, poison in LLVM, undefined in C and
    // an unbounded integer in Python. AXIS says every bit, and each lowering
    // has to say it.
    let masks = parse_document(include_str!("../examples/masks.axisl"))
        .expect("parse masks");
    validate_document(&masks).expect("validate masks");

    // C reaches the saturating answer through a helper rather than a shift.
    let header = emit_semantics_c(&masks);
    assert!(header.contains("axis_ones("), "C calls the helper");
    assert!(
        header.contains("count >= (uint64_t)width"),
        "and the helper is where the saturation is stated"
    );

    // LLVM narrows the count to the node's width and selects the saturating
    // answer beside the shift, rather than letting a too-large shift be poison.
    let ir = emit_llvm_ir(&masks);
    assert!(ir.contains("icmp uge"), "LLVM tests the count against the width");
    assert!(ir.contains("select i1"), "and selects rather than shifting past it");

    // SMT needs no guard: a shift past the width is defined to be zero there,
    // and zero minus one is already every bit.
    let smt = emit_smt2(&masks);
    assert!(smt.contains("bvshl"), "SMT builds the mask with a shift");
    assert!(!smt.contains("axis_ones"), "and needs no helper for it");

    // `zeros` is zero whatever its count, so nothing evaluates the count.
    assert!(
        emit_semantics_rust(&masks).contains("axis_ones("),
        "Rust shares the helper shape with C"
    );
}

#[test]
fn the_python_manifest_rewrites_literals_and_not_prose() {
    // `emit-python` renders the JSON manifest as Python, which differs in three
    // literals -- and it used to do that with a string replace, which rewrote
    // them inside string *values* too. The manifest is full of prose, so a
    // rationale reading "true of a null count" came out as "True of a None
    // count": the artifact quietly disagreed with the JSON it mirrors, and
    // nothing compared the two.
    let masks = parse_document(include_str!("../examples/masks.axisl"))
        .expect("parse masks");
    validate_document(&masks).expect("validate masks");
    let python = emit_python(&masks);

    // The corpus carries those words on purpose; they survive as written.
    assert!(
        python.contains("true of a null count, false otherwise"),
        "the English words are prose and stay prose"
    );
    assert!(!python.contains("True of a None count"));

    // And the literals themselves are still Python's.
    assert!(python.contains("True") || python.contains("False"));
    assert!(!python.contains(": true"), "no JSON literal survives as a value");
    assert!(!python.contains(": null"));

    // It is still data-only: a consumer reads literals, it does not run code.
    assert!(python.contains("RVMT_EXTENSION_MANIFEST = {"));
    assert!(python.contains("PCE_ADL_MANIFEST = {"));
    assert!(!python.contains("def "));
    assert!(!python.contains("class "));
}

#[test]
fn a_family_parameter_substitutes_inside_strings_and_an_operand_does_not() {
    // Expansion substituted `$name` everywhere except inside a string, so a
    // template writing `(asm "$name $rd, $rs1")` published the parameter
    // itself as the instruction's assembly text -- and nothing rejected it,
    // because `$rd` legitimately survives and the two are indistinguishable
    // without knowing which names the family declared.
    //
    // Only declared parameters are rewritten, which is exactly what separates
    // them: `$rd` is a parameter of no family, so it stays for a renderer to
    // resolve against the operand list.
    let source = r#"(axis-module fam
  (version "1.0.0") (target rvmt) (description "d")
  (defisa m (base rv32im) (word-bits 32) (registers "x[32]:i32" "pc:i32")
    (memory-model rvwmo) (endianness little))
  (definstruction-family f
    ($name $mnemonic $func3 $asm)
    ((A-ONE A_ONE 0 "a.one $rd, $rs1")
     (A-TWO A_TWO 1 "a.two $rd, $rs1"))
    (definstruction $name
      (mnemonic $mnemonic) (isa m) (category custom) (format R)
      (opcode 51) (func3 $func3) (func7 0)
      (operands (rd reg i32 out) (rs1 reg i32 in))
      (asm $asm)
      (semantics "writes $rd from $rs1, for $name")
      (formal rs1)
      (latency 1) (throughput 1.0) (area-estimate-um2 0.0)
      (power-estimate-mw 0.0) (expected-speedup 1.0)
      (rationale "r"))))
"#;
    let document = parse_document(source).expect("parse family");
    validate_document(&document).expect("validate family");

    let first = &document.instructions[0];
    assert_eq!(first.mnemonic, "A_ONE");
    // The row's own string arrives intact, operand placeholders and all.
    assert_eq!(first.asm, "a.one $rd, $rs1");
    // And a parameter interpolated into prose is substituted, while the
    // operand placeholders beside it are not.
    assert!(
        first.semantics.contains("for A-ONE"),
        "the parameter is substituted inside the string: {}",
        first.semantics
    );
    assert!(
        first.semantics.contains("$rd") && first.semantics.contains("$rs1"),
        "operand placeholders are left for a renderer: {}",
        first.semantics
    );
}

#[test]
fn synthesised_assembly_names_what_the_instruction_writes() {
    // An instruction that spells no `asm` of its own gets one synthesised from
    // its mnemonic and operands -- and that took the *input* operands only, so
    // the text named everything the instruction read and nothing it wrote.
    // `andn $rs1, $rs2` is not an assembly line anyone could assemble.
    let zbb = parse_document(include_str!("../examples/zbb_like.axisl"))
        .expect("parse zbb_like");
    validate_document(&zbb).expect("validate zbb_like");
    let andn = zbb
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "ANDN")
        .expect("ANDN is present");
    assert!(andn.asm.trim().is_empty(), "this one spells no assembly itself");

    let description = emit_asm_disasm_json(&zbb);
    assert!(
        description.contains("\"asm_template\": \"andn $rd, $rs1, $rs2\""),
        "the destination leads, then the sources"
    );
}

#[test]
fn the_description_says_what_makes_a_shared_word_unambiguous() {
    // Two instructions may share a decode word when their modes are disjoint,
    // when their units sit in disjoint packet slots, or when a predicate
    // separates them -- the validator proves exactly that, and the published
    // description carried none of it. A disassembler reading the file saw one
    // match and one mask for both, and had to guess.
    let modal = parse_document(include_str!("../examples/mode_polymorphic.axisl"))
        .expect("parse mode_polymorphic");
    validate_document(&modal).expect("validate mode_polymorphic");
    let description = emit_asm_disasm_json(&modal);
    assert!(description.contains("\"modes\": [\"xnn\"]"));
    assert!(description.contains("\"modes\": [\"scalar\", \"simt\"]"));

    // A document with neither says nothing about either, so output for the
    // ordinary case is unchanged.
    let plain = parse_document(include_str!("../examples/rv64i.axisl"))
        .expect("parse rv64i");
    validate_document(&plain).expect("validate rv64i");
    let plain_description = emit_asm_disasm_json(&plain);
    assert!(!plain_description.contains("\"modes\""));
    assert!(!plain_description.contains("\"unit\""));
}

#[test]
fn the_decode_table_says_what_separates_two_instructions_on_one_word() {
    // The same gap the assembly description had, in the table a decoder is
    // actually built from. Two instructions may carry one match and one mask
    // when their modes are disjoint or their units sit in disjoint packet
    // slots; the table published neither, so the file said one word meant two
    // things.
    let modal = parse_document(include_str!("../examples/mode_polymorphic.axisl"))
        .expect("parse mode_polymorphic");
    validate_document(&modal).expect("validate mode_polymorphic");
    let table = emit_decode_table_json(&modal);
    assert!(table.contains("\"modes\": [\"xnn\"]"));
    assert!(table.contains("\"modes\": [\"scalar\", \"simt\"]"));

    let packets = parse_document(include_str!("../examples/vliw_packet.axisl"))
        .expect("parse vliw_packet");
    validate_document(&packets).expect("validate vliw_packet");
    assert!(emit_decode_table_json(&packets).contains("\"unit\": \"br\""));

    // A document with neither says nothing about either, so the ordinary case
    // is byte-identical to before.
    let plain = parse_document(include_str!("../examples/rv64i.axisl"))
        .expect("parse rv64i");
    validate_document(&plain).expect("validate rv64i");
    let plain_table = emit_decode_table_json(&plain);
    assert!(!plain_table.contains("\"modes\""));
    assert!(!plain_table.contains("\"unit\""));
}

#[test]
fn a_pe_holds_what_its_row_holds() {
    // The canonical CGRA is not a uniform grid: an ADRES-style machine's first
    // row *is* its VLIW's functional units and the rows below are plain ALUs.
    // Until a row could differ, "is this operation's unit on this PE" was a
    // question with one answer -- every PE held every unit the fabric named --
    // so the check existed and could not fail.
    let fabrics = parse_document(include_str!("../examples/cgra_fabric.axisl"))
        .expect("parse cgra_fabric");
    validate_document(&fabrics).expect("validate cgra_fabric");

    let adres = fabrics
        .fabrics
        .iter()
        .find(|fabric| fabric.name == "adres4x4")
        .expect("the ADRES-shaped fabric is present");
    assert_eq!(adres.units_at(1), ["alu".to_string()]);
    assert_eq!(
        adres.units_at(3),
        ["alu".to_string(), "mul".to_string()],
        "the second multiplier row"
    );
    // The registers differ with the row too.
    assert_eq!(adres.regs_at(3), 4);
    assert_eq!(adres.regs_at(1), 2);
    // And the fabric-wide summary is the union, so a uniform grid reads as it
    // always did.
    assert_eq!(adres.all_units(), vec!["alu".to_string(), "mul".to_string()]);

    let uniform = fabrics
        .fabrics
        .iter()
        .find(|fabric| fabric.name == "cgra4x4")
        .expect("the uniform fabric is present");
    assert!(uniform.pe_rows.is_empty(), "no row overrides its default");
    assert_eq!(uniform.units_at(0), uniform.units_at(3));
}

#[test]
fn a_shared_row_is_the_packets_slots_not_a_copy_of_them() {
    // The defining relation of an ADRES-like machine: the VLIW's functional
    // units *are* the array's first row. Declaring it makes the correspondence
    // checkable and makes the row heterogeneous across its columns, which no
    // `pe` clause can express -- a VLIW row is one multiplier and three plain
    // slots, not four identical PEs.
    let document = parse_document(include_str!("../examples/cgra_fabric.axisl"))
        .expect("parse cgra_fabric");
    validate_document(&document).expect("validate cgra_fabric");

    let adres = document
        .fabrics
        .iter()
        .find(|fabric| fabric.name == "adres4x4")
        .expect("the ADRES fabric is present");
    let packet = document
        .packets
        .iter()
        .find(|packet| packet.name == "adres_vliw")
        .expect("the VLIW front is present");
    assert_eq!(adres.vliw_row, Some((0, "adres_vliw".to_string())));

    // Column by column, the shared row is the slots -- only slot 0 multiplies.
    assert_eq!(
        adres.units_at_pe(0, 0, Some(packet)),
        ["alu".to_string(), "mul".to_string()]
    );
    assert_eq!(adres.units_at_pe(0, 1, Some(packet)), ["alu".to_string()]);
    // Rows below are ordinary and uniform, and the shared packet does not
    // reach them.
    assert_eq!(adres.units_at_pe(1, 0, Some(packet)), ["alu".to_string()]);
    assert_eq!(adres.units_at_pe(1, 3, Some(packet)), ["alu".to_string()]);

    // This is the first corpus holding both a packet and a fabric: one machine
    // described two ways, which is what the stage is for.
    assert!(!document.packets.is_empty() && !document.fabrics.is_empty());
}

#[test]
fn a_mapping_says_where_its_values_come_from() {
    // Without live-ins a mapping is a dataflow with inputs from nowhere: the
    // G3 gate hands every unrouted operand an anonymous random number, which
    // proves placement and timing and says nothing about what the kernel reads
    // out of the machine. A live-in names the register or the constant, which
    // is what makes the kernel a state transformation.
    let document = parse_document(include_str!("../examples/cgra_fabric.axisl"))
        .expect("parse cgra_fabric");
    validate_document(&document).expect("validate cgra_fabric");

    let mapping = document
        .mappings
        .iter()
        .find(|mapping| mapping.name == "madd-on-adres")
        .expect("the ADRES mapping is present");

    // Both of the multiply's operands name one register, on purpose: one
    // register feeding two operands has to give them one value.
    let sources: Vec<&axis_adl::ast::MappingSource> = mapping
        .live_in
        .iter()
        .filter(|live| live.op == "op0")
        .map(|live| &live.source)
        .collect();
    assert_eq!(sources.len(), 2);
    assert!(sources
        .iter()
        .all(|source| **source == axis_adl::ast::MappingSource::Register(3)));

    // The add's other operand is the PE's constant, which is what a fabric
    // declaring `(const N)` is for.
    assert!(mapping.live_in.iter().any(|live| {
        live.op == "op1" && live.source == axis_adl::ast::MappingSource::Constant(7)
    }));

    // And the result is left somewhere nameable.
    assert_eq!(mapping.live_out.len(), 1);
    assert_eq!(mapping.live_out[0].register, 5);

    // A mapping that names none of this is still legal -- the older form,
    // proven as a dataflow -- so the rule is completeness, not presence.
    let dataflow_only = document
        .mappings
        .iter()
        .find(|mapping| mapping.name == "madd-on-cgra4x4")
        .expect("the dataflow-only mapping is present");
    assert!(dataflow_only.live_in.is_empty());
}

#[test]
fn a_launch_and_its_kernel_agree_about_the_arithmetic() {
    // The seam between the two modes. `(runs-mapping ...)` ties an instruction
    // to a schedule, and validation requires the instruction's semantics to be
    // that schedule's scalar order *composed* -- the multiply's product feeding
    // the add's routed operand, the add's other operand being the PE constant,
    // and the kernel's register reads becoming the launch's inputs.
    //
    // Three obligations meet here and none sees the other's evidence: the
    // executor gates prove this instruction against the golden model,
    // `fabric_vs_scalar` proves the mapping computes its scalar order over the
    // fabric, and this proves the two are talking about one computation.
    let document = parse_document(include_str!("../examples/cgra_fabric.axisl"))
        .expect("parse cgra_fabric");
    validate_document(&document).expect("validate cgra_fabric");

    let launch = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "CGRA_LAUNCH")
        .expect("the launch is present");
    assert_eq!(launch.runs_mapping, "madd-on-adres");
    assert_eq!(launch.formal_semantics.trim(), "(add i32 (mul i32 rs1 rs1) 7)");

    // One input, because the kernel reads one distinct register however many
    // operands it feeds; one output, for the one result it leaves.
    assert_eq!(launch.operands.iter().filter(|o| o.input).count(), 1);
    assert_eq!(launch.operands.iter().filter(|o| o.output).count(), 1);

    // Saying it computes anything else is rejected, which is what makes the
    // agreement evidence rather than a comment.
    let drifted = include_str!("../examples/cgra_fabric.axisl")
        .replace("(formal (add i32 (mul i32 rs1 rs1) 7))", "(formal (add i32 (mul i32 rs1 rs1) 8))");
    let drifted = parse_document(&drifted).expect("a drifted launch still parses");
    let error = validate_document(&drifted).expect_err("but does not validate");
    assert!(
        error.message.contains("have to agree about the arithmetic"),
        "the message says what disagreed: {}",
        error.message
    );
}

#[test]
fn one_set_of_units_cannot_issue_two_ways_at_once() {
    // The A2 entry said the shared row "is why the two modes are exclusive".
    // That was prose about the architecture, and nothing made a description
    // violating it impossible: a corpus could declare the seam and run both
    // halves in one mode, which is a machine using each functional unit twice.
    let document = parse_document(include_str!("../examples/cgra_fabric.axisl"))
        .expect("parse cgra_fabric");
    validate_document(&document).expect("validate cgra_fabric");

    let fabric = document
        .fabrics
        .iter()
        .find(|fabric| fabric.name == "adres4x4")
        .expect("the ADRES fabric is present");
    let packet = document
        .packets
        .iter()
        .find(|packet| packet.name == "adres_vliw")
        .expect("the VLIW front is present");
    assert_eq!(fabric.mode, "cgra");
    assert_eq!(packet.mode, "vliw");
    assert_ne!(fabric.mode, packet.mode, "the seam is what makes this required");

    // Both in one mode is rejected, which is what turns the prose into a rule.
    let together = include_str!("../examples/cgra_fabric.axisl")
        .replace("    (mode cgra)\n    (vliw-row 0 adres_vliw)", "    (mode vliw)\n    (vliw-row 0 adres_vliw)");
    let together = parse_document(&together).expect("it still parses");
    let error = validate_document(&together).expect_err("but does not validate");
    assert!(
        error.message.contains("use each of them twice"),
        "the message says why: {}",
        error.message
    );

    // And the launch is legal in the VLIW mode, because the array is entered
    // rather than entered from.
    let launch = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "CGRA_LAUNCH")
        .expect("the launch is present");
    assert_eq!(launch.modes, vec!["vliw".to_string()]);
}

#[test]
fn a_kernel_can_read_the_shared_register_file() {
    // Stage A6. A behavior could always *write* a named register -- an AArch64
    // link write is `(setreg a64_gpr64 30 ...)` -- and could not read one, so a
    // machine whose kernel reads the shared file itself, the way an ADRES mode
    // switch does, had to take the values in operands and claim the launch
    // supplied them. That states a different machine: one whose kernel reads
    // whatever registers the launch's operands happen to name.
    let source = include_str!("../examples/cgra_fabric.axisl");
    let document = parse_document(source).expect("parse cgra_fabric");
    validate_document(&document).expect("validate cgra_fabric");

    let enter = document
        .instructions
        .iter()
        .find(|instruction| instruction.mnemonic == "CGRA_ENTER")
        .expect("the mode switch is present");
    // No input operands at all: everything the kernel reads, it reads.
    assert_eq!(enter.operands.iter().filter(|o| o.input).count(), 0);
    assert_eq!(enter.operands.iter().filter(|o| o.output).count(), 1);
    // And it is an effect program rather than a pure value, for the same
    // reason a load is: it reads something the operand list does not carry.
    assert!(axis_adl::effects::behavior_is_authoritative(enter));
    assert_eq!(
        axis_adl::effects::behavior_register_reads(enter),
        vec![("reg".to_string(), 3), ("reg".to_string(), 4)]
    );

    // The registers it reads are published, because an instruction's
    // dependencies are its operands except when they are not, and a consumer
    // reading `reads` alone would reorder a write to x3 across this.
    let table = emit_lift_table_json(&document);
    assert!(
        table.contains("\"reads_registers\": [{\"kind\": \"reg\", \"index\": 3}, \
                        {\"kind\": \"reg\", \"index\": 4}]"),
        "the lift table names the registers the behavior reads: {table}"
    );
    // And a description that reads none is byte-identical to what it was
    // before the field existed.
    let launch_only = parse_document(include_str!("../examples/vliw_packet.axisl"))
        .expect("parse vliw_packet");
    assert!(!emit_lift_table_json(&launch_only).contains("reads_registers"));

    // Which register feeds which operand of the multiply is a fact the
    // composition checks: swapping the two live-ins is rejected even though
    // nothing else about the mapping changed.
    let swapped = source.replace(
        "    (live-in (op0 rs1 (reg 3))\n             (op0 rs2 (reg 4))",
        "    (live-in (op0 rs1 (reg 4))\n             (op0 rs2 (reg 3))",
    );
    let swapped = parse_document(&swapped).expect("a swapped kernel still parses");
    let error = validate_document(&swapped).expect_err("but does not validate");
    assert!(
        error.message.contains("have to agree about the arithmetic"),
        "the message says what disagreed: {}",
        error.message
    );

    // Reading a register the kernel does not read is rejected by name, rather
    // than surfacing as an arithmetic disagreement about a symbol.
    let elsewhere = source.replace(
        "(op0 rs1 (reg 3))\n             (op0 rs2 (reg 4))",
        "(op0 rs1 (reg 6))\n             (op0 rs2 (reg 4))",
    );
    let elsewhere = parse_document(&elsewhere).expect("it parses");
    let error = validate_document(&elsewhere).expect_err("but does not validate");
    assert!(
        error.message.contains("which mapping `madd-direct-on-adres`'s kernel does not read"),
        "the message names the register: {}",
        error.message
    );

    // And a register the kernel reads that the launch neither reads nor takes
    // in an operand leaves the launch supplying nothing for it.
    let unsupplied = source.replace("(getreg reg 4)", "(getreg reg 3)");
    let unsupplied = parse_document(&unsupplied).expect("it parses");
    let error = validate_document(&unsupplied).expect_err("but does not validate");
    assert!(
        error.message.contains("takes 0 input operand(s)"),
        "the message counts both sides: {}",
        error.message
    );

    // A launch whose behavior is not one unguarded write has no single
    // expression to hold a kernel to, and says so. A kernel that runs only
    // sometimes is a different construct, not a launch with a condition.
    let conditional = source.replace(
        "      (set rd (add (mul (getreg reg 3) (getreg reg 4)) 11)))",
        "      (when (icmp_ne (getreg reg 3) 0)\n        (set rd (add (mul (getreg reg 3) (getreg reg 4)) 11))))",
    );
    let conditional = parse_document(&conditional).expect("it parses");
    let error = validate_document(&conditional).expect_err("but does not validate");
    assert!(
        error.message.contains("one unguarded write"),
        "the message says what a launch's behavior must be: {}",
        error.message
    );
}

#[test]
fn a_register_read_names_a_register_that_exists() {
    // `getreg` reads the files `setreg` writes, by one table: a description
    // that can write `a64_gpr64 30` and cannot read it, or that can read a
    // class the writer refuses, would be two vocabularies wearing one name.
    let source = include_str!("../examples/cgra_fabric.axisl");

    let vector = source.replace("(getreg reg 3)", "(getreg vreg 3)");
    let vector = parse_document(&vector).expect("it parses");
    let error = validate_document(&vector).expect_err("but does not validate");
    assert!(
        error.message.contains("must be a supported register kind"),
        "the message says what a kind may be: {}",
        error.message
    );

    let past_the_file = source.replace("(getreg reg 3)", "(getreg a64_gpr64 33)");
    let past_the_file = parse_document(&past_the_file).expect("it parses");
    let error = validate_document(&past_the_file).expect_err("but does not validate");
    assert!(
        error.message.contains("index must be below 32"),
        "the message says which index: {}",
        error.message
    );

    let not_a_number = source.replace("(getreg reg 3)", "(getreg reg rs1)");
    let not_a_number = parse_document(&not_a_number).expect("it parses");
    let error = validate_document(&not_a_number).expect_err("but does not validate");
    assert!(
        error.message.contains("index must be an integer literal"),
        "a register read is not an indexed one: {}",
        error.message
    );
}

#[test]
fn a_wide_address_wraps_at_its_own_width() {
    // An address is evaluated at its own width, and every operator masks its
    // own result -- so this was invisible for as long as every address was
    // arithmetic. RISC-V's `lr.w`/`sc.w` address memory with a bare operand,
    // and a 32-bit machine's address living in a 64-bit register slot then
    // reached memory with whatever the upper half held. The golden model and
    // the Python executor wrap it; the wide C and Rust executors did not.
    let document = parse_document(include_str!("../examples/rv32i.axisl"))
        .expect("parse rv32i");
    validate_document(&document).expect("validate rv32i");

    let c = emit_exec_c(&document);
    assert!(
        c.contains("mem->read(mem->ctx, axis_mask64(axis_input_1, 32u), 32u)"),
        "the wide C load address wraps at 32 bits"
    );
    assert!(
        c.contains("mem->write(mem->ctx, axis_mask64(axis_input_1, 32u), \
                    axis_mask64(axis_input_2, 32u), 32u)"),
        "and so does the wide C store address"
    );

    let rust = emit_exec_rust(&document);
    assert!(
        rust.contains("mem.read64(axis_mask64(axis_input_1, 32), 32)"),
        "the wide Rust load address wraps at 32 bits"
    );
    assert!(
        rust.contains("let addr = axis_mask64(axis_input_1, 32);"),
        "and so does the wide Rust store address"
    );

    // A 64-bit machine masks at 64, which `axis_mask64` returns unchanged --
    // the rule is stated once and costs nothing where it cannot bite.
    let a64 = parse_document(include_str!("../examples/aarch64_translation_seed.axisl"))
        .expect("parse the AArch64 seed");
    assert!(
        emit_exec_c(&a64).contains("mem->write(mem->ctx, axis_mask64(axis_input_1, 64u)"),
        "the same rule on a 64-bit machine, where the width makes it the identity"
    );
}

#[test]
fn a_condition_is_tested_at_its_width() {
    // The golden model masks every width-sensitive consumer's operands --
    // `lshr` masks its value, the comparisons mask both sides -- and did not
    // mask a `select`'s condition. The congruent operators (`or`, `xor`,
    // `add`) return their result unmasked, so an `or` whose low 32 bits are
    // zero and whose upper half is not took the true branch in the model and
    // the false one in C, which masks each operator's result.
    //
    // RISC-V's `sc.w` is exactly that expression. Its reservation check is
    // three comparisons or-ed together, satisfied by random state with
    // probability 2**-41, so the store path had never been executed by any
    // differential gate and this could not have been found by one until the
    // wide driver learned to seed state with what the effects compare it
    // against.
    let document = parse_document(include_str!("../examples/rv32i.axisl"))
        .expect("parse rv32i");
    let golden = emit_golden_python(&document);
    assert!(
        golden.contains("return vals[1] if _mask(vals[0], width) != 0 else vals[2]"),
        "the golden model tests a condition at the expression's width"
    );
}

#[test]
fn the_wide_executor_rounds_the_way_the_description_says() {
    // The pure path has lowered directed rounding since F3 -- `fp_rounding.axisl`
    // proves those helpers against the golden model -- and the wide effect path
    // had no arm for it. The omission was invisible from inside: an instruction
    // whose *behavior* rounds under a named mode was declined, and a decline is
    // not a failure. That is every RISC-V FP instruction with a static or
    // dynamic rounding mode, ninety mnemonics in each RISC-V corpus, all of them
    // effectful because they accrue `fflags`, and all of them declined by the
    // compact path too for touching state: executed by no compiled executor.
    let document = parse_document(include_str!("../examples/rv32i.axisl"))
        .expect("parse rv32i");
    let c = emit_exec_c(&document);

    // A static mode is the literal the encoding fixes.
    assert!(
        c.contains("axis_fp32_add_rm((uint32_t)(axis_input_1), (uint32_t)(axis_input_2), \
                    (uint64_t)(UINT64_C(2)))"),
        "the wide C executor rounds `fadd.s` under the mode its encoding names"
    );
    // A dynamic one is the mode register, read where every other piece of
    // architectural state is read.
    assert!(
        c.contains("(uint64_t)(axis_state64_read(state, \"frm\"))"),
        "and a DYN form takes its mode from `frm`"
    );
    // The two shapes the fold does not cover: one operand, and three.
    assert!(
        c.contains("axis_fp32_sqrt_rm((uint32_t)(axis_input_1), (uint64_t)("),
        "square root takes one operand and the mode"
    );
    assert!(
        c.contains("axis_fp64_fma_rm(axis_input_1, axis_input_2, axis_input_3, (uint64_t)("),
        "and a fused multiply-add takes three, rounding once"
    );

    // Rust declines the family instead, and that is a decision rather than a
    // gap: it has no access to the floating-point environment at all.
    let rust = emit_exec_rust(&document);
    assert!(
        !rust.contains("_rm("),
        "the Rust executor states no directed rounding, because it cannot"
    );
}

#[test]
fn a_signed_guard_compares_signed_values() {
    // The compact executors emitted `<` over `uint32_t` for `icmp_slt` and
    // `icmp_ult` alike, so every signed branch took the unsigned decision --
    // RISC-V's `blt` went the wrong way whenever its two operands differed in
    // sign, which is half of the pairs that reach it. The wide path had the
    // rule (`axis_signed64`, added when an unsigned `whilelt` said every lane
    // was active) and the compact path had the operator.
    //
    // What hid it was the drivers' random stream, not the absence of a check:
    // `exec_c_check` compares against the golden model on every fixture, and
    // the register values it happened to draw for `BLT` never straddled zero.
    // Moving where the program counter is drawn from shifted the stream, and
    // the next draw found it.
    let document = parse_document(include_str!("../examples/rv32i.axisl"))
        .expect("parse rv32i");

    // The property is that the two forms *differ*: `blt` and `bltu` are one
    // corpus apart and were emitting the same C.
    let c = emit_exec_c(&document);
    assert!(
        c.contains("if (axis_sem_signed(rs1, 32u) < axis_sem_signed(rs2, 32u))"),
        "`blt` branches on a signed comparison"
    );
    assert!(
        c.contains("if ((rs1) < (rs2))"),
        "`bltu` still branches on the unsigned one, over values already 32 bits wide"
    );

    let rust = emit_exec_rust(&document);
    assert!(
        rust.contains("axis_sem_signed(rs1, 32) < axis_sem_signed(rs2, 32)"),
        "the compact Rust executor makes the same distinction"
    );
    assert!(
        rust.contains("axis_sem_mask(rs1, 32) < axis_sem_mask(rs2, 32)"),
        "and its unsigned form masks rather than sign-extends"
    );
}

#[test]
fn the_two_c_paths_lower_the_same_vocabulary() {
    // The compact and wide executors are two independently generated C
    // backends for one language, and an instruction used to be checked by
    // whichever one its width selected -- never by both. Three things had
    // drifted between them, and each was found the day the seam closed:
    //
    //   * a signed guard emitted as an unsigned comparison in the compact path,
    //   * an arithmetic shift of a narrow lane left unsigned in the wide one,
    //   * and four Zbb operators the compact path had and the wide one did not.
    //
    // This pins the last of the three: the operator vocabulary. The first two
    // are differential, and `simd_lanes` and `rv32i` hold them.
    let document = parse_document(include_str!("../examples/zbb_like.axisl"))
        .expect("parse zbb_like");
    let c = emit_exec_c(&document);
    for helper in ["axis_rotl64(", "axis_rotr64(", "axis_ctz64(", "axis_cpop64("] {
        assert!(
            c.contains(helper),
            "the wide C executor lowers {helper} -- the compact one always could"
        );
    }

    let rust = emit_exec_rust(&document);
    for helper in ["axis_rotl64(", "axis_rotr64(", "axis_ctz64(", "axis_cpop64("] {
        assert!(rust.contains(helper), "and so does the wide Rust executor: {helper}");
    }

    // An arithmetic shift sign-extends at the width it is given, rather than at
    // whichever of 32 and 64 a cast happens to name. A 16-bit lane masked into
    // a 64-bit slot is never negative as an `int64_t`.
    assert!(
        c.contains("int64_t wide = axis_signed64(value, width);"),
        "the wide C shift reads the sign at the operand's width"
    );

    // And a value is taken at the width the instruction writes, which only
    // shows on an expression that applies no operator at all.
    let identity = parse_document(include_str!("../examples/policy_icount.axisl"))
        .expect("parse policy_icount");
    assert!(
        emit_exec_c(&identity).contains("*value = axis_mask64(in[0], 32u);"),
        "an identity returns 32 bits on a 32-bit machine"
    );
}

#[test]
fn a_dynamic_permute_reads_the_lane_its_index_names() {
    // The one permute that is not a static map: `vrgather` and SVE's table
    // lookup read a lane chosen at run time, so each output lane becomes a
    // select over every source lane -- quadratic, and bounded at 32 lanes
    // rather than refused. Both architectures' spelling is one operator.
    let sve = parse_document(include_str!("../examples/sve.axisl")).expect("parse sve");
    validate_document(&sve).expect("validate sve");
    let lanes: Vec<&axis_adl::ast::Instruction> = sve
        .instructions
        .iter()
        .filter(|instruction| instruction.scalable_origin == "TBL_Z_B")
        .collect();
    // Sixteen bytes at VL=128, and each lane names every source lane plus its
    // own index -- which is what makes the expansion quadratic.
    assert_eq!(lanes.len(), 16);
    let first = lanes.first().expect("a lane");
    assert_eq!(
        first.operands.iter().filter(|o| o.input).count(),
        17,
        "sixteen source lanes and one index lane"
    );

    // An index at or past the element count reads zero, which is what both
    // architectures say. The last arm of the select tree is that zero.
    assert!(
        first.formal_semantics.contains("(select i8 (icmp_eq i8"),
        "the lane is a select tree: {}",
        first.formal_semantics
    );
    assert!(
        first.formal_semantics.contains("zn__l15 0)"),
        "and the innermost arm falls back to zero: {}",
        first.formal_semantics
    );

    // The RVV corpus has the same operator at a different width, which is the
    // reason for describing it in both: four selects deep rather than sixteen.
    let rvv = parse_document(include_str!("../examples/rvv.axisl")).expect("parse rvv");
    assert_eq!(
        rvv.instructions
            .iter()
            .filter(|instruction| instruction.scalable_origin == "VRGATHER_VV")
            .count(),
        4
    );
}

#[test]
fn an_elastic_route_is_exempt_from_the_timing_it_cannot_have() {
    // Stage G4b.1. Everything B3, G2 and G3 prove rests on a value's arrival
    // being a static function of the schedule. A handshake breaks that, so a
    // route naming a channel is exempt from the modulo checks and carries a
    // different obligation -- and the half of it decidable from the
    // declaration alone is that a ring of pure wires cannot move.
    let source = include_str!("../examples/cgra_fabric.axisl");
    let document = parse_document(source).expect("parse cgra_fabric");
    validate_document(&document).expect("validate cgra_fabric");

    let channels = &document.channels;
    assert_eq!(channels.len(), 2, "one buffered channel and one pure wire");
    let buffered = channels
        .iter()
        .find(|channel| channel.name == "accumulator-bus")
        .expect("the buffered channel");
    // The protocol is a name, and the latency is a window rather than a cycle:
    // the two facts that make this a different timing model rather than a
    // relaxation of the existing one.
    assert_eq!(buffered.protocol, "ready-valid");
    assert_eq!((buffered.latency_min, buffered.latency_max), (1, 4));
    assert_eq!(buffered.capacity, 1);

    let elastic = document
        .mappings
        .iter()
        .find(|mapping| mapping.name == "accumulate-elastic")
        .expect("the elastic mapping");
    assert!(elastic.routes.iter().all(|route| !route.channel.is_empty()));
    // A ring: the accumulator feeds the step and the step feeds it back one
    // iteration later. Statically timed, this would have to satisfy the
    // arrival equation; elastic, it does not -- and the corpus states no cycle
    // on either route.
    assert!(elastic.routes.iter().all(|route| route.cycle == 0));
    assert!(elastic.routes.iter().any(|route| route.distance == 1));

    // Take the buffer out of the ring and nothing can move, which is the whole
    // content of the static half.
    let unbuffered = source.replace(
        "    (capacity 1)\n    (order preserving)\n    (initial 1)",
        "    (capacity 0)\n    (order preserving)\n    (initial 0)",
    );
    let unbuffered = parse_document(&unbuffered).expect("it still parses");
    let error = validate_document(&unbuffered).expect_err("but does not validate");
    assert!(
        error.message.contains("cycle of elastic routes with no buffering"),
        "the message names the ring: {}",
        error.message
    );

    // A protocol this language does not know is one no consumer can be held
    // to, so it is refused rather than passed through.
    let unknown = source.replace("(protocol ready-valid)", "(protocol handwave)");
    let unknown = parse_document(&unknown).expect("it parses");
    let error = validate_document(&unknown).expect_err("but does not validate");
    assert!(
        error.message.contains("is not one of ready-valid, credit"),
        "the message says what a protocol may be: {}",
        error.message
    );

    // A ring starts with a token, or every operation on it waits for a value
    // only the ring produces and nothing fires. The first version of this
    // corpus had no initial token and its latency-insensitivity gate passed by
    // comparing two empty results, which is how the language learned it needed
    // one.
    assert_eq!(buffered.initial, 1);
    let unheld = source.replace(
        "    (capacity 0)\n    (order preserving)\n    (description \"An unbuffered",
        "    (capacity 0)\n    (order preserving)\n    (initial 7)\n    (description \"An unbuffered",
    );
    let unheld = parse_document(&unheld).expect("it parses");
    let error = validate_document(&unheld).expect_err("but does not validate");
    assert!(
        error.message.contains("no capacity to hold it"),
        "an initial token needs a buffer to sit in: {}",
        error.message
    );

    // A document with no channel emits what it emitted before they existed.
    let packets = parse_document(include_str!("../examples/vliw_packet.axisl"))
        .expect("parse vliw_packet");
    assert!(!axis_adl::emit::emit_mapping_manifest_json(&packets).contains("channels"));
}

#[test]
fn a_lent_unit_is_a_channel_with_a_machine_on_each_end() {
    // G4b.3. A personality can export a functional unit across a boundary and
    // another can import it -- XNN-MT's tile boundary, in the language. Each
    // side names its own channel, and the three composition rules of
    // `elastic_seams_design.md` §4 are what makes two separately written sides
    // one seam rather than two hopes.
    let source = include_str!("../examples/vliw_exposed.axisl");
    let document = parse_document(source).expect("parse vliw_exposed");
    validate_document(&document).expect("the seam composes");

    let exporter = document
        .personalities
        .iter()
        .find(|personality| personality.name == "lane1")
        .expect("the exporting personality");
    assert_eq!(exporter.exports.len(), 1);
    assert_eq!(exporter.exports[0].unit, "mul");
    assert_eq!(exporter.exports[0].channel, "mul-result-bus");
    let importer = document
        .personalities
        .iter()
        .find(|personality| personality.name == "lane0")
        .expect("the importing personality");
    assert_eq!(importer.imports[0].from, "lane1");
    // Not the same channel: the producer's promise and the consumer's
    // tolerance are two statements, and the check is that one contains the
    // other.
    assert_ne!(importer.imports[0].channel, exporter.exports[0].channel);

    // A producer that can be later than its consumer tolerates is a producer
    // whose results the consumer drops.
    let late = source.replace("(latency 2 4)", "(latency 2 7)");
    let late = parse_document(&late).expect("it parses");
    let error = validate_document(&late).expect_err("but does not validate");
    assert!(
        error.message.contains("the importer's window must contain the exporter's"),
        "the message says which way containment runs: {}",
        error.message
    );

    // A consumer cannot promise an order its producer never gave it.
    let shuffled = source.replace(
        "    (order preserving)
    (description \"What lane1",
        "    (order unordered)
    (description \"What lane1",
    );
    let shuffled = parse_document(&shuffled).expect("it parses");
    let error = validate_document(&shuffled).expect_err("but does not validate");
    assert!(
        error.message.contains("cannot promise an order its"),
        "the message names the order rule: {}",
        error.message
    );

    // Two protocol names are two handshakes.
    let mixed = source.replace(
        "(protocol ready-valid)\n    (latency 2 4)",
        "(protocol credit)\n    (latency 2 4)",
    );
    let mixed = parse_document(&mixed).expect("it parses");
    let error = validate_document(&mixed).expect_err("but does not validate");
    assert!(
        error.message.contains("two protocols are two handshakes"),
        "the message names the protocol rule: {}",
        error.message
    );

    // A machine cannot lend a unit it does not have: `fft` is in no packet
    // slot, so the export names nothing the exporting machine can supply.
    let absent = source.replace(
        "(mul-pipe (unit mul) (channel",
        "(mul-pipe (unit fft) (channel",
    );
    let absent = parse_document(&absent).expect("it parses");
    let error = validate_document(&absent).expect_err("but does not validate");
    assert!(
        error.message.contains("no packet slot and no fabric row declares"),
        "the message says where units come from: {}",
        error.message
    );

    // A seam has two sides.
    let solo = source.replace("(from lane1)", "(from lane0)");
    let solo = parse_document(&solo).expect("it parses");
    let error = validate_document(&solo).expect_err("but does not validate");
    assert!(
        error.message.contains("from itself"),
        "the message says a seam has two sides: {}",
        error.message
    );

    // The manifest publishes both sides, each naming its own channel; the
    // channel's contract is published once, in the mapping manifest, so a
    // consumer joins the two rather than reading two copies that can drift.
    let capsule = axis_adl::emit::emit_state_capsule_manifest_json(&document);
    assert!(capsule
        .contains(r#"{"name": "mul-pipe", "unit": "mul", "channel": "mul-result-bus"}"#));
    assert!(capsule
        .contains(r#"{"name": "mul-pipe", "from": "lane1", "channel": "mul-borrow-bus"}"#));
    // A document whose personalities lend nothing emits what it emitted before
    // seams existed.
    let plain = parse_document(include_str!("../examples/personality_tile.axisl"))
        .expect("parse personality_tile");
    let plain = axis_adl::emit::emit_state_capsule_manifest_json(&plain);
    assert!(!plain.contains("\"exports\"") && !plain.contains("\"imports\""));
}

#[test]
fn an_engine_names_every_context_it_retains() {
    // M1. `xnn_mt/contract.py` declares sixteen contexts, four id bits and a
    // two-deep issue queue, and hand-checks the relations between them in
    // Python. The declaration belongs in the description and the relations
    // belong in the validator, which is the whole of this stage.
    let source = include_str!("../examples/heterogeneous_tile.axisl");
    let document = parse_document(source).expect("parse heterogeneous_tile");
    validate_document(&document).expect("the context numbers agree");

    let engine = document
        .accelerators
        .iter()
        .find(|accelerator| accelerator.name == "xnn0")
        .expect("the multi-context engine");
    assert_eq!(engine.contexts, 16);
    assert_eq!(engine.context_id_bits, 4);
    assert_eq!(engine.issue_queue_depth, 2);
    assert!(engine.identity.contains(&"context_id".to_string()));

    // Four bits name sixteen contexts because it is the largest id, 15, that
    // decides the width. Five names contexts the machine does not have; three
    // cannot name half of them, and both are the same mistake.
    for wrong in ["(context-id-bits 5)", "(context-id-bits 3)"] {
        let misnamed = source.replace("(context-id-bits 4)", wrong);
        let misnamed = parse_document(&misnamed).expect("it parses");
        let error = validate_document(&misnamed).expect_err("but does not validate");
        assert!(
            error.message.contains("needs exactly 4"),
            "the message says what the width must be: {}",
            error.message
        );
    }

    // A queue of one holds the issue being serviced and nothing behind it, so
    // the engine hides no latency and its contexts buy nothing.
    let shallow = source.replace("(issue-queue-depth 2)", "(issue-queue-depth 1)");
    let shallow = parse_document(&shallow).expect("it parses");
    let error = validate_document(&shallow).expect_err("but does not validate");
    assert!(
        error.message.contains("hides no latency"),
        "the message says why two: {}",
        error.message
    );

    // An issue that cannot say which context it came from cannot have its
    // result returned to one.
    let anonymous = source.replace(
        "(identity context_id tenant_id domain_id command_id)",
        "(identity tenant_id domain_id command_id)",
    );
    let anonymous = parse_document(&anonymous).expect("it parses");
    let error = validate_document(&anonymous).expect_err("but does not validate");
    assert!(
        error.message.contains("does not carry"),
        "the message names the missing field: {}",
        error.message
    );

    // Partly declared is worse than not declared: numbers about an object the
    // description never made.
    let orphaned = source.replace("    (contexts 16)\n", "");
    let orphaned = parse_document(&orphaned).expect("it parses");
    let error = validate_document(&orphaned).expect_err("but does not validate");
    assert!(
        error.message.contains("nothing for those numbers to be about"),
        "the message says the object is missing: {}",
        error.message
    );

    // The manifest publishes the surface and the derived bound, so a consumer
    // reads the number rather than deriving it a second time.
    let manifest = axis_adl::emit::emit_json(&document);
    assert!(manifest.contains(r#""contexts": 16,"#));
    assert!(manifest.contains(r#""max_other_grants_before_service": 15"#));
    // An engine that retains one context emits what it emitted before contexts
    // existed.
    let plain = parse_document(include_str!("../examples/accelerator_descriptor.axisl"))
        .expect("parse accelerator_descriptor");
    assert!(!axis_adl::emit::emit_json(&plain).contains("multicontext"));
}

#[test]
fn a_bound_is_published_exactly_where_the_policy_delivers_one() {
    // M2. The policy and the preemption point are names, the way a channel's
    // protocol is: AXIS never models the arbiter. What the two names decide
    // between them is whether there is a service bound to publish at all,
    // which is a fact about the description and therefore checkable.
    let source = include_str!("../examples/heterogeneous_tile.axisl");
    let document = parse_document(source).expect("parse heterogeneous_tile");
    validate_document(&document).expect("the policy is one this language knows");
    let manifest = axis_adl::emit::emit_json(&document);
    // Fifteen other contexts, ninety-one cycles each: the two numbers the
    // consumer's contract computes as dataclass properties.
    assert!(manifest.contains(r#""max_other_grants_before_service": 15,"#));
    assert!(manifest.contains(r#""deterministic_dependency_cover_cycles": 1365"#));

    // Strict priority serves a persistently eligible high-priority context
    // forever, so the low one waits forever. That is a machine worth
    // describing and not one to promise service for -- and the manifest says
    // `null` rather than dropping the key, because a consumer reading a
    // missing field cannot tell "no bound" from "forgot to say".
    // Two ways to be unbounded, and they are different reasons: a policy that
    // does not rotate, and a policy that rotates with nowhere to do it.
    for (from, to) in [
        ("(scheduling work-conserving-round-robin)", "(scheduling strict-priority)"),
        ("(preemption tile-boundary-only)", "(preemption none)"),
    ] {
        let unbounded = to;
        let stripped = source.replace(from, to);
        let stripped = parse_document(&stripped).expect("it parses");
        validate_document(&stripped).expect("and validates: unbounded is legal");
        let manifest = axis_adl::emit::emit_json(&stripped);
        assert!(
            manifest.contains(r#""max_other_grants_before_service": null,"#),
            "{unbounded} publishes no bound"
        );
        assert!(
            manifest.contains(r#""deterministic_dependency_cover_cycles": null"#),
            "{unbounded} publishes no cycle bound either"
        );
    }

    // A name this language does not know is one no consumer can be held to.
    let invented = source.replace("(scheduling work-conserving-round-robin)", "(scheduling lottery)");
    let invented = parse_document(&invented).expect("it parses");
    let error = validate_document(&invented).expect_err("but does not validate");
    assert!(
        error.message.contains("must be one of work_conserving_round_robin"),
        "the message says what a policy may be: {}",
        error.message
    );

    // The interval is the unit a bound is counted in, so it needs a policy for
    // there to be a bound at all.
    let untethered = source.replace("    (scheduling work-conserving-round-robin)\n", "");
    let untethered = parse_document(&untethered).expect("it parses");
    let error = validate_document(&untethered).expect_err("but does not validate");
    assert!(
        error.message.contains("no bound for it to denominate"),
        "the message says what the interval is for: {}",
        error.message
    );

    // The whole surface survives the round trip, policy included.
    let reparsed = parse_document(&axis_adl::emit::emit_lisp(&document))
        .expect("the emitted form parses");
    let engine = reparsed
        .accelerators
        .iter()
        .find(|accelerator| accelerator.name == "xnn0")
        .expect("the engine");
    assert_eq!(engine.scheduling, "work-conserving-round-robin");
    assert_eq!(engine.service_interval_cycles, 91);
    assert_eq!(engine.eligibility.len(), 7);
}

#[test]
fn a_convention_is_declared_and_then_held_to_itself() {
    // L4. `llvm_backend.md` §2 rules out *deriving* an ABI: which register
    // holds the first argument is a property of a platform, not of a machine,
    // and a description that guessed would be inventing a convention rather
    // than generating one. Declaring it does not cross that line. What AXIS
    // then decides is whether the declaration is consistent with itself, which
    // is the class of mistake a compiler acts on silently.
    let source = include_str!("../examples/rv32i.axisl");
    let document = parse_document(source).expect("parse rv32i");
    validate_document(&document).expect("the convention holds together");

    let abi = document.abis.first().expect("the declared abi");
    assert_eq!(abi.name, "ilp32");
    assert_eq!(abi.pointer_bits, 32);
    // Four reserved, twelve callee-saved, sixteen caller-saved: thirty-two
    // registers, each with exactly one role.
    let counted = |refs: &[axis_adl::ast::RegisterRef]| -> u32 {
        refs.iter().map(|entry| entry.last - entry.first + 1).sum()
    };
    assert_eq!(
        counted(&abi.reserved) + counted(&abi.callee_saved) + counted(&abi.caller_saved),
        32
    );

    // A register in no role is one a compiler cannot know whether to save.
    let gap = source.replace("(callee-saved (rv_gpr 8 9) (rv_gpr 18 27))",
                             "(callee-saved (rv_gpr 8 9) (rv_gpr 19 27))");
    let gap = parse_document(&gap).expect("it parses");
    let error = validate_document(&gap).expect_err("but does not validate");
    assert!(
        error.message.contains("no role"),
        "the message says the register was never placed: {}",
        error.message
    );

    // A register in two roles is a contradiction between two statements the
    // same document made.
    let both = source.replace("(caller-saved (rv_gpr 1) (rv_gpr 5 7)",
                              "(caller-saved (rv_gpr 1) (rv_gpr 5 8)");
    let both = parse_document(&both).expect("it parses");
    let error = validate_document(&both).expect_err("but does not validate");
    assert!(
        error.message.contains("one role across a call"),
        "the message names both roles: {}",
        error.message
    );

    // Passing a value in the stack pointer is not a convention anyone can
    // implement, and neither is a stack pointer the allocator may take.
    let in_sp = source.replace("(arguments (rv_gpr 10 17))",
                               "(arguments (rv_gpr 2) (rv_gpr 11 17))");
    let in_sp = parse_document(&in_sp).expect("it parses");
    assert!(validate_document(&in_sp)
        .expect_err("but does not validate")
        .message
        .contains("reserved register is one no value may be placed in"));
    let loose_sp = source.replace("(stack-pointer (rv_gpr 2))", "(stack-pointer (rv_gpr 9))");
    let loose_sp = parse_document(&loose_sp).expect("it parses");
    assert!(validate_document(&loose_sp)
        .expect_err("but does not validate")
        .message
        .contains("allocatable stack pointer is not a stack pointer"));

    // A frame pointer the callee does not preserve is not a frame pointer.
    let volatile_fp = source.replace("(frame-pointer (rv_gpr 8))", "(frame-pointer (rv_gpr 12))");
    let volatile_fp = parse_document(&volatile_fp).expect("it parses");
    assert!(validate_document(&volatile_fp)
        .expect_err("but does not validate")
        .message
        .contains("not callee-saved"));

    // The target carries the convention, in the order the ABI names it: `a0`
    // first is what makes it `a0`, and LLVM assigns positionally.
    let target = axis_adl::emit::emit_llvm_target(&document);
    assert!(target.contains(
        "CCIfType<[i32], CCAssignToReg<[RV_GPR10, RV_GPR11, RV_GPR12, RV_GPR13, \
         RV_GPR14, RV_GPR15, RV_GPR16, RV_GPR17]>>"
    ));
    assert!(target.contains("def CSR_ILP32 : CalleeSavedRegs<(add RV_GPR8, RV_GPR9,"));

    // It comes back out too. This emitter is how a corpus is rewritten from
    // its own emitted form, and rv32i is the corpus that claim is made about
    // -- so an ABI dropped on the way would be a silent hole in it.
    let reparsed = parse_document(&axis_adl::emit::emit_lisp(&document))
        .expect("the emitted form parses");
    validate_document(&reparsed).expect("and validates");
    let round_tripped = reparsed.abis.first().expect("the abi survives");
    assert_eq!(round_tripped, abi);

    // A document with no ABI emits what it emitted before conventions existed,
    // in both the manifest and the target.
    let plain = parse_document(include_str!("../examples/vliw_packet.axisl"))
        .expect("parse vliw_packet");
    assert!(!axis_adl::emit::emit_json(&plain).contains("\"abis\""));
    assert!(!axis_adl::emit::emit_llvm_target(&plain).contains("CallingConv"));
}

#[test]
fn a_frame_is_a_layout_the_machine_can_reach() {
    // F1. A consumer of this description already writes the frame by hand:
    // `pce/hardware/grv/grv_linked_execution.py` checks a prologue against
    // hand-encoded words, with the slot offsets carried as struct fields in a
    // second repository. Those offsets are a function of the save order and
    // the slot size, and this is that function.
    let source = include_str!("../examples/rv32i.axisl");
    let document = parse_document(source).expect("parse rv32i");
    validate_document(&document).expect("the frame holds together");

    let abi = document.abis.first().expect("the abi");
    let frame = abi.frame.as_ref().expect("its frame");
    assert_eq!(frame.saved_registers().len(), 2);
    // The consumer's own numbers: for its 16-byte frame, ra at 12 and s0 at 8.
    // The layout is stated once and answers for any frame size.
    assert_eq!(frame.slot(0, 16), 12);
    assert_eq!(frame.slot(1, 16), 8);
    assert_eq!(frame.saved_bytes(), 8);

    // A prologue saves what the callee may clobber, and nothing else. `ra` is
    // caller-saved and still saved, because a non-leaf clobbers it by calling
    // -- which is why the rule is "callee-saved, or the link register".
    let wrong = source.replace("(save-order (rv_gpr 1) (rv_gpr 8))",
                               "(save-order (rv_gpr 1) (rv_gpr 12))");
    let wrong = parse_document(&wrong).expect("it parses");
    assert!(validate_document(&wrong)
        .expect_err("but does not validate")
        .message
        .contains("saves what the callee may clobber"));

    // The named instructions are what they claim. AXIS does not search the
    // instruction set for something store-shaped; it checks the name.
    for (from, to, expected) in [
        ("(save SW)", "(save LW)", "not a plain store"),
        ("(restore LW)", "(restore SW)", "reads no memory"),
        ("(adjust ADDI)", "(adjust ADD)", "does not write one register from an immediate"),
    ] {
        let swapped = source.replace(from, to);
        let swapped = parse_document(&swapped).expect("it parses");
        let error = validate_document(&swapped).expect_err("but does not validate");
        assert!(
            error.message.contains(expected),
            "{to} should be refused with `{expected}`: {}",
            error.message
        );
    }

    // The manifest publishes the computed slots, so a consumer reads offsets
    // rather than a rule for producing them.
    let manifest = axis_adl::emit::emit_json(&document);
    assert!(manifest.contains(r#""register": ["rv_gpr", 1], "rank": 0, "offset": 2044"#));

    // And it round-trips: the frame is part of the corpus this emitter is
    // supposed to be able to rewrite.
    let reparsed = parse_document(&axis_adl::emit::emit_lisp(&document))
        .expect("the emitted form parses");
    validate_document(&reparsed).expect("and validates");
    assert_eq!(reparsed.abis.first().unwrap().frame.as_ref(), Some(frame));

    // An ABI with no frame emits what it emitted before frames existed.
    let plain = parse_document(include_str!("../examples/vliw_packet.axisl"))
        .expect("parse vliw_packet");
    assert!(!axis_adl::emit::emit_json(&plain).contains("\"frame\""));
}

#[test]
fn an_aggregate_is_passed_the_way_the_registers_allow() {
    // F3. A machine ABI says how a laid-out aggregate is *passed*. How it is
    // laid out -- padding, bitfields, nested alignment -- is the source
    // language's rule, and stating it here would be inventing C's ABI rather
    // than the machine's.
    let source = include_str!("../examples/rv32i.axisl");
    let document = parse_document(source).expect("parse rv32i");
    validate_document(&document).expect("the aggregate rules fit the convention");

    let abi = document.abis.first().expect("the abi");
    let aggregates = abi.aggregates.as_ref().expect("its aggregate rules");
    assert_eq!(aggregates.max_register_bytes, 8);
    assert_eq!(aggregates.split, "allowed");

    // A threshold the argument registers cannot hold passes nothing by value,
    // and one that is not a whole number of registers is a boundary no
    // register lands on.
    for (wrong, expected) in [
        ("(max-register-bytes 64)", "passes nothing by value"),
        ("(max-register-bytes 6)", "boundary no register lands on"),
    ] {
        let broken = source.replace("(max-register-bytes 8)", wrong);
        let broken = parse_document(&broken).expect("it parses");
        let error = validate_document(&broken).expect_err("but does not validate");
        assert!(
            error.message.contains(expected),
            "{wrong} should be refused with `{expected}`: {}",
            error.message
        );
    }

    // The caller passes a returned aggregate's address like an argument, so
    // there is nowhere to put it but an argument register.
    let elsewhere = source.replace("(return-pointer (rv_gpr 10))",
                                   "(return-pointer (rv_gpr 9))");
    let elsewhere = parse_document(&elsewhere).expect("it parses");
    assert!(validate_document(&elsewhere)
        .expect_err("but does not validate")
        .message
        .contains("not an argument register"));

    // LLVM spells "this argument is a block the caller owns" as byval, and the
    // rule goes first: a type rule matching ahead of it would place the
    // pointer instead of the block.
    let target = axis_adl::emit::emit_llvm_target(&document);
    let convention = target
        .split("def CC_ILP32 : CallingConv<[")
        .nth(1)
        .expect("the convention");
    assert!(convention.trim_start().starts_with("CCIfByVal<CCPassByVal<4, 16>>"));

    // And an ABI that states no aggregate rule emits the convention it emitted
    // before they existed.
    let plain = source.replace(
        "    (aggregates\n      (max-register-bytes 8)\n      (split allowed)\n      \
         (return-pointer (rv_gpr 10)))\n",
        "",
    );
    let plain = parse_document(&plain).expect("it parses");
    validate_document(&plain).expect("and validates");
    assert!(!axis_adl::emit::emit_llvm_target(&plain).contains("CCIfByVal"));
    assert!(!axis_adl::emit::emit_json(&plain).contains("\"aggregates\""));
}

#[test]
fn a_region_has_an_order_and_no_size() {
    // F4 and F5. The line this stage draws is where a size would go: how many
    // spill slots a function needs and how large its locals are is the
    // register allocator's decision, made per function at compile time, and a
    // description that stated it would be stating what it cannot know. The
    // *order* is the platform's, and it has consequences a document can
    // contradict.
    let source = include_str!("../examples/rv32i.axisl");
    let document = parse_document(source).expect("parse rv32i");
    validate_document(&document).expect("the regions and the discipline agree");

    let frame = document.abis[0].frame.as_ref().expect("the frame");
    assert_eq!(frame.regions, ["outgoing", "locals", "spill", "saved"]);
    assert_eq!(frame.spill.len(), 2);
    // A spill slot holds the register, and how wide the register is comes from
    // the operands rather than from the class table: `rv_gpr` covers RV32 and
    // RV64, so asking the table would make this eight bytes.
    assert_eq!(frame.spill[0].bytes, 4);

    // The saved area is declared twice -- by `saved-area` and by where `saved`
    // sits in the order -- so the two have to agree.
    let contradictory = source.replace("(regions outgoing locals spill saved)",
                                       "(regions outgoing locals saved spill)");
    let contradictory = parse_document(&contradictory).expect("it parses");
    assert!(validate_document(&contradictory)
        .expect_err("but does not validate")
        .message
        .contains("region order runs from the frame base upward"));

    // A callee reads its overflow arguments at its own stack pointer.
    let displaced = source.replace("(regions outgoing locals spill saved)",
                                   "(regions locals outgoing spill saved)");
    let displaced = parse_document(&displaced).expect("it parses");
    assert!(validate_document(&displaced)
        .expect_err("but does not validate")
        .message
        .contains("they sit at the frame base and nowhere else"));

    // A slot the register does not fit in loses the top of it.
    let narrow = source.replace("(spill (rv_gpr 4 4)", "(spill (rv_gpr 2 2)");
    let narrow = parse_document(&narrow).expect("it parses");
    assert!(validate_document(&narrow)
        .expect_err("but does not validate")
        .message
        .contains("loses the top of it"));

    // F5's implication, which is the whole of the stage. Realignment moves the
    // frame away from the incoming stack pointer; dynamic allocation moves the
    // stack pointer away from the frame. Either alone leaves one pointer that
    // still reaches a local; both together leave none, and LLVM spells the
    // same rule as `needsStackRealignment && hasVariableSizedObjects`.
    let both = source.replace("(realignment forbidden)", "(realignment allowed)");
    let parsed = parse_document(&both).expect("it parses");
    assert!(validate_document(&parsed)
        .expect_err("but does not validate")
        .message
        .contains("neither one can still reach a local"));

    // And with a base pointer it is legal again -- provided the base pointer
    // is one that survives the body's calls and is not the pointer it exists
    // to replace.
    let repaired = repaired_source(&both, "(base-pointer (rv_gpr 9))");
    let repaired = parse_document(&repaired).expect("it parses");
    validate_document(&repaired).expect("a declared base pointer settles it");
    for (wrong, expected) in [
        ("(base-pointer (rv_gpr 12))", "not callee-saved"),
        ("(base-pointer (rv_gpr 8))", "base pointer is the frame pointer"),
    ] {
        let broken = repaired_source(&both, wrong);
        let broken = parse_document(&broken).expect("it parses");
        assert!(
            validate_document(&broken)
                .expect_err("but does not validate")
                .message
                .contains(expected),
            "{wrong} should be refused with `{expected}`"
        );
    }

    // A local addressed from a pointer that moves is somewhere else every time
    // it is read.
    let unanchored = source.replace("    (frame-pointer (rv_gpr 8))\n", "");
    let unanchored = parse_document(&unanchored).expect("it parses");
    assert!(validate_document(&unanchored)
        .expect_err("but does not validate")
        .message
        .contains("different place every time it is read"));
}

/// The `both` source with a base pointer of the caller's choosing.
fn repaired_source(both: &str, base_pointer: &str) -> String {
    both.replace(
        "      (dynamic-allocation allowed))",
        &format!("      (dynamic-allocation allowed)\n      {base_pointer})"),
    )
}

/// A `defaccelerator` may declare several result ports.
///
/// ⚠️ Before this, `formal` was typed against the FIRST output port and every other
/// one was dropped **in silence**: an engine declaring `(q output ...)` and
/// `(r output ...)` parsed, validated, and emitted a one-result SMT function, so
/// whatever it proved covered a strict subset of what it produced. These tests pin
/// the three ways that silence is now a refusal, and the two emitters that carry
/// every result.
fn multi_result_module(formal: &str, ports: &str) -> String {
    format!(
        r#"(axis-module twoout
  (version "1.0")
  (target rvmt)

  (definstruction ok
    (mnemonic OK)
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

  (defaccelerator split_unit
    (family nearasic)
    (target nearasic)
    (coupling queue_descriptor)
    (ports
{ports}
    )
    (semantics "two results")
{formal}
    (latency 1)
    (throughput 1.0)
  )
)
"#
    )
}

const TWO_OUT_PORTS: &str = "      (a input bits i32)
      (b input bits i32)
      (s output bits i32)
      (d output bits i32)";

#[test]
fn accelerator_states_one_formal_result_per_output_port() {
    let document = parse_document(&multi_result_module(
        "    (formal (result s (add i32 a b))
            (result d (sub i32 a b)))",
        TWO_OUT_PORTS,
    ))
    .expect("parse two-result accelerator");
    validate_document(&document).expect("validate two-result accelerator");

    let accelerator = &document.accelerators[0];
    assert_eq!(accelerator.formal_results.len(), 2);
    // Port order, not the order they were written.
    assert_eq!(accelerator.formal_results[0].port, "s");
    assert_eq!(accelerator.formal_results[1].port, "d");
    // The singular field still holds the first, because every existing consumer
    // reads it.
    assert_eq!(
        accelerator.formal_semantics,
        accelerator.formal_results[0].expr
    );

    // Both results reach the proof obligation, under distinct names.
    let smt = emit_smt2(&document);
    assert!(smt.contains("axis_accel_split_unit_s"), "{smt}");
    assert!(smt.contains("axis_accel_split_unit_d"), "{smt}");

    // ...and the executable model returns both.
    let golden = emit_golden_python(&document);
    assert!(golden.contains("def eval_split_unit(a, b):"), "{golden}");
    assert!(
        golden.contains("Returns (s, d), one per output port."),
        "{golden}"
    );
}

#[test]
fn each_result_is_typed_against_its_own_port_width() {
    // ⚠️ The reason per-port typing is not a formality: typing every result against
    // the FIRST output port silently truncates or widens the others.
    let document = parse_document(&multi_result_module(
        "    (formal (result wide (add i64 a b))
            (result narrow (add i16 a b)))",
        "      (a input bits i32)
      (b input bits i32)
      (wide output bits i64)
      (narrow output bits i16)",
    ))
    .expect("parse mixed-width results");
    validate_document(&document).expect("validate mixed-width results");

    let smt = emit_smt2(&document);
    assert!(smt.contains("axis_accel_split_unit_wide"), "{smt}");
    assert!(smt.contains("axis_accel_split_unit_narrow"), "{smt}");
    // Each define-fun returns ITS port's width, not the first port's.
    assert!(smt.contains("(_ BitVec 64)"), "{smt}");
    assert!(smt.contains("(_ BitVec 16)"), "{smt}");
}

#[test]
fn an_unnamed_formal_is_refused_when_there_are_several_results() {
    let err = parse_document(&multi_result_module(
        "    (formal (add i32 a b))",
        TWO_OUT_PORTS,
    ))
    .expect_err("a bare formal cannot define two output ports");
    let text = err.to_string();
    assert!(text.contains("2 output ports"), "{text}");
    assert!(text.contains("(result port expr)"), "{text}");
}

#[test]
fn an_output_port_with_no_stated_result_is_refused() {
    let err = parse_document(&multi_result_module(
        "    (formal (result s (add i32 a b)))",
        TWO_OUT_PORTS,
    ))
    .expect_err("an unstated result must not pass");
    let text = err.to_string();
    assert!(text.contains("output port `d`"), "{text}");
    assert!(text.contains("never say what it produces"), "{text}");
}

#[test]
fn a_result_must_name_an_output_port_and_may_be_stated_once() {
    let unknown = parse_document(&multi_result_module(
        "    (formal (result s (add i32 a b))
            (result nope (sub i32 a b)))",
        TWO_OUT_PORTS,
    ))
    .expect_err("a result naming no output port must not pass");
    let text = unknown.to_string();
    assert!(text.contains("`nope`"), "{text}");
    assert!(text.contains("not an output port"), "{text}");

    let twice = parse_document(&multi_result_module(
        "    (formal (result s (add i32 a b))
            (result s (sub i32 a b)))",
        TWO_OUT_PORTS,
    ))
    .expect_err("a result stated twice must not pass");
    assert!(twice.to_string().contains("twice"), "{twice}");
}

#[test]
fn the_shipped_pyrtl_datapath_carries_every_result() {
    // ⚠️ The datapath and the proof obligation must describe the SAME machine.
    // If `emit-smt2` covers two results and `emit-pyrtl` computes one, the
    // discharge proves something about a circuit nobody ships.
    let document = parse_document(&multi_result_module(
        "    (formal (result s (add i32 a b))
            (result d (sub i32 a b)))",
        TWO_OUT_PORTS,
    ))
    .expect("parse two-result accelerator");
    let py = emit_pyrtl(&document);
    assert!(py.contains("return ("), "behavior must return a tuple:\n{py}");
    // Every declared result port is driven, none left floating.
    assert!(py.contains("ports[\"s\"] <<= _results[0]"), "{py}");
    assert!(py.contains("ports[\"d\"] <<= _results[1]"), "{py}");
    assert!(
        !py.contains("Structural auto-wiring requires"),
        "a two-result engine must be wired, not skipped:\n{py}"
    );
}

#[test]
fn a_zero_input_engine_still_drives_its_output() {
    // ⚠️ A constant-producing accelerator has no input ports. The wrapper used to
    // require at least one, so it declared the output and never drove it -- an
    // EMPTY datapath with a floating port. It hid because the SMT discharge calls
    // `build_<name>_behavior` directly and never exercises this wrapper.
    let document = parse_document(&multi_result_module(
        "    (formal (result s (add i32 4 5)))",
        "      (s output bits i32)",
    ))
    .expect("parse zero-input accelerator");
    let py = emit_pyrtl(&document);
    assert!(py.contains("ports[\"s\"] <<= "), "output must be driven:\n{py}");
    assert!(
        !py.contains("Structural auto-wiring requires"),
        "a zero-input engine must still be wired:\n{py}"
    );
}

#[test]
fn a_multi_result_accelerator_survives_its_own_emitted_lisp() {
    // Round-trip matters more here than usual: emitting the BARE form back would
    // produce a source the reader now refuses, so the emitter and the reader
    // would disagree about the surface.
    let document = parse_document(&multi_result_module(
        "    (formal (result s (add i32 a b))
            (result d (sub i32 a b)))",
        TWO_OUT_PORTS,
    ))
    .expect("parse two-result accelerator");
    let emitted = emit_lisp(&document);
    assert!(emitted.contains("(result s"), "{emitted}");
    assert!(emitted.contains("(result d"), "{emitted}");

    let reparsed = parse_document(&emitted).expect("emitted lisp must re-read");
    assert_eq!(
        reparsed.accelerators[0].formal_results,
        document.accelerators[0].formal_results
    );
}

/// `urem`/`srem` — the ops whose absence meant the canonical two-result engine,
/// a **divmod unit**, could not be written at all.
///
/// ⚠️ The gap was *unreachable* before multi-result accelerators existed: a
/// `defaccelerator` emitted only its first result, so a second expression was
/// never lowered and `urem` was never rejected. The operator set looked complete
/// because nothing had ever asked it for a second answer.
#[test]
fn a_divmod_unit_is_expressible_now_that_remainder_exists() {
    let document = parse_document(&multi_result_module(
        "    (formal (result q (udiv i32 a b))
            (result r (urem i32 a b)))",
        "      (a input bits i32)
      (b input bits i32)
      (q output bits i32)
      (r output bits i32)",
    ))
    .expect("parse a divmod unit");
    validate_document(&document).expect("validate a divmod unit");

    let smt = emit_smt2(&document);
    assert!(smt.contains("bvudiv"), "{smt}");
    assert!(smt.contains("bvurem"), "{smt}");
    // Both results reach the obligation, under their own names.
    assert!(smt.contains("axis_accel_split_unit_q"), "{smt}");
    assert!(smt.contains("axis_accel_split_unit_r"), "{smt}");
}

#[test]
fn srem_lowers_to_bvsrem_not_bvsmod() {
    // ⚠️ SMT-LIB has both: `bvsrem` takes the sign of the DIVIDEND and `bvsmod`
    // the sign of the DIVISOR. Only `bvsrem` pairs with `bvsdiv`'s truncating
    // division, so picking `bvsmod` would silently disagree with `sdiv`.
    let document = parse_document(&multi_result_module(
        "    (formal (result q (sdiv i32 a b))
            (result r (srem i32 a b)))",
        "      (a input bits i32)
      (b input bits i32)
      (q output bits i32)
      (r output bits i32)",
    ))
    .expect("parse a signed divmod unit");
    let smt = emit_smt2(&document);
    assert!(smt.contains("bvsrem"), "{smt}");
    assert!(!smt.contains("bvsmod"), "bvsmod pairs with floor division:\n{smt}");
}

#[test]
fn remainder_by_zero_follows_the_convention_its_sibling_already_set() {
    // ⚠️ AXIS's `udiv` yields ZERO on a zero divisor — its own convention, not
    // RISC-V's (which gives all-ones) and not SMT-LIB's raw `bvudiv`. `urem`
    // matches its sibling: an operator pair that disagreed about zero inside one
    // IR would be worse than either choice.
    let document = parse_document(&multi_result_module(
        "    (formal (result q (udiv i32 a b))
            (result r (urem i32 a b)))",
        "      (a input bits i32)
      (b input bits i32)
      (q output bits i32)
      (r output bits i32)",
    ))
    .expect("parse a divmod unit");
    let smt = emit_smt2(&document);
    let guards = smt.matches("(ite (= b (_ bv0 32)) (_ bv0 32)").count();
    assert_eq!(guards, 2, "both results must guard the zero divisor:\n{smt}");
}

#[test]
fn every_backend_carries_the_remainder_helpers() {
    // The dispatch sites are exhaustive matches the compiler checks; the HELPERS
    // they call are emitted STRINGS, which it cannot see into.
    let document = parse_document(&multi_result_module(
        "    (formal (result q (udiv i32 a b))
            (result r (urem i32 a b)))",
        "      (a input bits i32)
      (b input bits i32)
      (q output bits i32)
      (r output bits i32)",
    ))
    .expect("parse a divmod unit");
    let c = emit_semantics_c(&document);
    assert!(c.contains("axis_sem_urem"), "C helper missing");
    assert!(!c.contains("%%"), "a doubled modulo would be invalid C:\n{c}");
    let rust = emit_semantics_rust(&document);
    assert!(rust.contains("urem"), "Rust helper missing");
    let py = emit_pyrtl(&document);
    assert!(py.contains("_urem"), "PyRTL helper missing");
    let golden = emit_golden_python(&document);
    assert!(golden.contains("urem"), "golden helper missing");
}
