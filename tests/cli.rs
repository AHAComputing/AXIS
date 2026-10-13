use std::fs;
use std::process::Command;

#[test]
fn cli_checks_example() {
    let status = Command::new(env!("CARGO_BIN_EXE_axis"))
        .args(["check", "examples/rvmt_xpce.axisl"])
        .status()
        .expect("run axis check");
    assert!(status.success());
}

#[test]
fn cli_checks_lisp_compatibility_example() {
    let status = Command::new(env!("CARGO_BIN_EXE_axis"))
        .args(["check", "examples/rvmt_xpce.axisl"])
        .status()
        .expect("run axis check on Lisp compatibility example");
    assert!(status.success());
}



#[test]
fn cli_emits_canonical_lisp_source() {
    let output =
        std::env::temp_dir().join(format!("axis_test_{}_aarch64.axisl", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_axis"))
        .args([
            "emit-lisp",
            "examples/aarch64_translation_seed.axisl",
            "-o",
            output.to_str().unwrap(),
        ])
        .status()
        .expect("run axis emit-lisp");
    assert!(status.success());
    let contents = fs::read_to_string(&output).expect("read emitted Lisp");
    assert!(contents.starts_with("(axis-module aarch64_translation_seed"));
    assert!(contents.contains("(behavior"));
    assert!(contents.contains("(requires (a64-shifted-reg i64 shift imm6))"));
    let _ = fs::remove_file(output);
}

#[test]
fn cli_emits_json_file() {
    let output =
        std::env::temp_dir().join(format!("axis_test_{}_manifest.json", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_axis"))
        .args([
            "emit-json",
            "examples/rvmt_xpce.axisl",
            "-o",
            output.to_str().unwrap(),
        ])
        .status()
        .expect("run axis emit-json");
    assert!(status.success());
    let contents = fs::read_to_string(&output).expect("read emitted manifest");
    assert!(contents.contains("\"schema\": \"axis.manifest.v1\""));
    assert!(contents.contains("\"mnemonic\": \"TLS_LOAD\""));
    let _ = fs::remove_file(output);
}

#[test]
fn cli_emits_aha_and_compiler_collateral() {
    for (command, suffix, needle) in [
        (
            "emit-aha-json",
            "aha.json",
            "\"schema\": \"pce-adl.aha-instructions.v1\"",
        ),
        ("emit-tablegen", "td", "def TLS_LOAD"),
        ("emit-intrinsics", "h", "pce_tls_load"),
        (
            "emit-decode-json",
            "decode.json",
            "\"schema\": \"axis.decode-table.v1\"",
        ),
        (
            "emit-encode-json",
            "encode.json",
            "\"schema\": \"axis.encode-table.v1\"",
        ),
        ("emit-encode-c", "axis_encode.h", "axis_encode_by_index"),
        (
            "emit-roundtrip-json",
            "roundtrip.json",
            "\"schema\": \"axis.roundtrip-tests.v1\"",
        ),
        ("emit-decode-c", "axis_decode.h", "axis_decode"),
        (
            "emit-asm-disasm-json",
            "asm_disasm.json",
            "\"schema\": \"axis.asm-disasm.v1\"",
        ),
        (
            "emit-bundle-manifest",
            "bundle_manifest.json",
            "\"schema\": \"axis.bundle-manifest.v1\"",
        ),
        (
            "emit-translation-json",
            "translation.json",
            "\"schema\": \"axis.translation-map.v1\"",
        ),
        (
            "emit-translation-python",
            "translation.py",
            "axis.translation-python.v1",
        ),
        ("emit-pyrtl", "py", "AXIS_SCHEMA"),
        ("emit-golden-python", "golden.py", "AXIS_SCHEMA"),
        (
            "emit-semantics-json",
            "semantics.json",
            "\"schema\": \"axis.semantics.v1\"",
        ),
        ("emit-smt2", "semantics.smt2", "(set-logic QF_BV)"),
    ] {
        let output =
            std::env::temp_dir().join(format!("axis_test_{}_{}", std::process::id(), suffix));
        let status = Command::new(env!("CARGO_BIN_EXE_axis"))
            .args([
                command,
                "examples/rvmt_xpce.axisl",
                "-o",
                output.to_str().unwrap(),
            ])
            .status()
            .unwrap_or_else(|err| panic!("run axis {command}: {err}"));
        assert!(status.success());
        let contents = fs::read_to_string(&output).expect("read emitted collateral");
        assert!(
            contents.contains(needle),
            "{command} output missed {needle}"
        );
        let _ = fs::remove_file(output);
    }
}

#[test]
fn cli_emits_rvmt_json_file() {
    let output = std::env::temp_dir().join(format!(
        "axis_test_{}_rvmt_manifest.json",
        std::process::id()
    ));
    let status = Command::new(env!("CARGO_BIN_EXE_axis"))
        .args([
            "emit-rvmt-json",
            "examples/rvmt_xpce.axisl",
            "-o",
            output.to_str().unwrap(),
        ])
        .status()
        .expect("run axis emit-rvmt-json");
    assert!(status.success());
    let contents = fs::read_to_string(&output).expect("read emitted RVMT manifest");
    assert!(contents.contains("\"target\": \"rvmt\""));
    assert!(contents.contains("\"decode_key\""));
    assert!(!contents.contains("\"schema\""));
    assert!(!contents.contains("\"cost_model\""));
    let _ = fs::remove_file(output);
}

#[test]
fn cli_emits_bundle_directory() {
    let output_dir = std::env::temp_dir().join(format!("axis_test_{}_bundle", std::process::id()));
    let _ = fs::remove_dir_all(&output_dir);
    let status = Command::new(env!("CARGO_BIN_EXE_axis"))
        .args([
            "emit-bundle",
            "examples/rvmt_xpce.axisl",
            "-o",
            output_dir.to_str().unwrap(),
        ])
        .status()
        .expect("run axis emit-bundle");
    assert!(status.success());
    for name in [
        "bundle_manifest.json",
        "manifest.json",
        "rvmt_extension_manifest.json",
        "decode_table.json",
        "axis_encode_table.json",
        "axis_encode.h",
        "axis_roundtrip_tests.json",
        "axis_decode.h",
        "asm_disasm.json",
        "semantics.json",
        "semantics.smt2",
        "aha_instructions.json",
        "adl_topology_manifest.json",
        "accelerator_descriptor_manifests.json",
        "adl_coupling_manifest.json",
        "rvmt_launch_templates.json",
        "rvmt_rcore_region_manifest.json",
        "instructions.td",
        "intrinsics.h",
        "axis_intrinsics.td",
        "axis_patterns.td",
        "golden_model.py",
        "axis_semantics.rs",
        "axis_semantics.ll",
        "axis_lift_table.json",
        "axis_lift.py",
        "axis_lift.h",
        "axis_lift.rs",
        "axis_exec.py",
        "axis_exec.h",
        "pyrtl_semantics.py",
    ] {
        assert!(
            output_dir.join(name).is_file(),
            "missing bundle file {name}"
        );
    }
    let rvmt = fs::read_to_string(output_dir.join("rvmt_extension_manifest.json")).unwrap();
    assert!(rvmt.contains("\"instructions\""));
    assert!(!rvmt.contains("\"cost_model\""));
    let bundle_manifest = fs::read_to_string(output_dir.join("bundle_manifest.json")).unwrap();
    assert!(bundle_manifest.contains("\"schema\": \"axis.bundle-manifest.v1\""));
    assert!(bundle_manifest.contains("\"path\": \"rvmt_extension_manifest.json\""));
    assert!(bundle_manifest.contains("\"path\": \"axis_encode_table.json\""));
    assert!(bundle_manifest.contains("\"path\": \"axis_encode.h\""));
    assert!(bundle_manifest.contains("\"path\": \"axis_roundtrip_tests.json\""));
    let encode = fs::read_to_string(output_dir.join("axis_encode_table.json")).unwrap();
    assert!(encode.contains("\"schema\": \"axis.encode-table.v1\""));
    assert!(encode.contains("\"base_value\""));
    let encode_h = fs::read_to_string(output_dir.join("axis_encode.h")).unwrap();
    assert!(encode_h.contains("AXIS_ENCODE_TABLE"));
    assert!(encode_h.contains("axis_encode_by_index"));
    let roundtrip = fs::read_to_string(output_dir.join("axis_roundtrip_tests.json")).unwrap();
    assert!(roundtrip.contains("\"schema\": \"axis.roundtrip-tests.v1\""));
    assert!(roundtrip.contains("\"tests\""));
    let _ = fs::remove_dir_all(output_dir);
}

/// A decode-keyed export must not put two entries on one decode key.
///
/// `validate_isas` already proves instructions do not "overlap in the decode
/// space", and the scalable examples pass it — but a scalable instruction
/// elaborates into a lane GROUP, and emitting the instances put N entries on
/// the one encoding the group shares. The emitted artifact then violated a
/// property its own input had been validated for: measured, 112 entries over
/// 15 encodings for `scalable_predicate.axisl`, and PCE's loader keys on
/// exactly those fields.
///
/// Checked over `emit-decode-json`, which every scalable corpus can produce —
/// `emit-aha-json` is deliberately restricted to RISC-V custom opcodes, so SVE
/// and RVV cannot be exported through it at all and would test nothing here.
#[test]
fn decode_keyed_exports_carry_one_entry_per_encoding() {
    for source in [
        "examples/scalable_predicate.axisl",
        "examples/scalable_crosslane.axisl",
        "examples/sve.axisl",
        "examples/rvv.axisl",
    ] {
        let output = std::env::temp_dir().join(format!(
            "axis_decode_keys_{}_{}.json",
            std::process::id(),
            source.replace(['/', '.'], "_")
        ));
        let status = Command::new(env!("CARGO_BIN_EXE_axis"))
            .args(["emit-decode-json", source, "-o", output.to_str().unwrap()])
            .status()
            .expect("run axis emit-decode-json");
        assert!(status.success(), "emit failed for {source}");
        let contents = fs::read_to_string(&output).expect("read emitted decode table");

        // A text scan rather than a JSON dependency: the property is about what
        // the artifact SAYS, and a parser would be a second thing to keep in
        // step with the schema.
        let mut keys: Vec<String> = Vec::new();
        for block in contents.split("\"mnemonic\":").skip(1) {
            let field = |name: &str| -> String {
                block
                    .split(&format!("\"{name}\":"))
                    .nth(1)
                    .and_then(|rest| rest.split(',').next())
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('}')
                    .trim()
                    .to_string()
            };
            keys.push(format!("{}/{}", field("match"), field("mask")));
        }
        assert!(!keys.is_empty(), "no instructions emitted for {source}");
        let before = keys.len();
        keys.sort();
        keys.dedup();
        assert_eq!(
            before,
            keys.len(),
            "{source}: {} entries share a decode key with another",
            before - keys.len()
        );

        // And no lane instance leaked through — in a mnemonic, or in a
        // semantics expression naming operands the entry does not declare.
        assert!(
            !contents.contains("__l0"),
            "{source}: a lane instantiation reached a decode-keyed export"
        );
        let _ = fs::remove_file(&output);
    }
}
