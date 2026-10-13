//! Contract fixtures for PCE/AHA consumers.
//!
//! These tests pin the exact field surface read by PCE's loaders so drift
//! fails here before PCE sees it (see docs/pce_migration.md):
//! - `aha/isa/adl_loader.py::_instruction_from_dict` / `_operand_from_dict`
//! - `aha/compute_core/extensibility/xrv_extension.py::XRVExtensionDescriptor::from_adl`
//!
//! Run `tools/pce_smoke_check.py` for the live cross-repo check that loads
//! emitted bundles through the real PCE loaders.

use axis_adl::{emit_aha_json, parse_document, validate_document};

fn aha_json() -> String {
    let source = include_str!("../examples/rvmt_xpce.axisl");
    let document = parse_document(source).expect("parse example");
    validate_document(&document).expect("validate example");
    emit_aha_json(&document)
}



#[test]
fn aha_schema_is_the_one_pce_strictly_checks() {
    // adl_loader.load_adl_extension_bundle raises on any other value.
    assert!(aha_json().contains("\"schema\": \"pce-adl.aha-instructions.v1\""));
}

#[test]
fn aha_extension_metadata_fields_are_present() {
    let json = aha_json();
    for key in [
        "\"name\":",
        "\"version\":",
        "\"description\":",
        "\"instructions\": [",
    ] {
        assert!(json.contains(key), "missing extension field {key}");
    }
}

#[test]
fn aha_instruction_fields_match_pce_instruction_from_dict() {
    let json = aha_json();
    // Every field _instruction_from_dict reads. `mnemonic` and `encoding`
    // are hard-required by the loader; the rest default but are part of the
    // stable surface.
    for key in [
        "\"mnemonic\":",
        "\"description\":",
        "\"category\":",
        "\"operands\": [",
        "\"encoding\": {",
        "\"semantics\":",
        "\"latency_cycles\":",
        "\"throughput_per_cycle\":",
        "\"area_estimate_um2\":",
        "\"power_estimate_mw\":",
        "\"expected_speedup\":",
        "\"applicable_patterns\":",
        "\"rationale\":",
    ] {
        assert!(json.contains(key), "missing instruction field {key}");
    }
}

#[test]
fn aha_operand_fields_match_pce_operand_from_dict() {
    let json = aha_json();
    for key in [
        "\"name\":",
        "\"type\":",
        "\"width_bits\":",
        "\"is_output\":",
        "\"is_optional\":",
    ] {
        assert!(json.contains(key), "missing operand field {key}");
    }
}

#[test]
fn every_instruction_carries_a_hardware_dispatchable_encoding() {
    // XRVExtensionDescriptor.from_adl raises unless encoding exists with
    // opcode/func3/func7; the URV extension unit cannot dispatch without it.
    let json = aha_json();
    let instruction_count = json.matches("\"mnemonic\":").count();
    assert!(instruction_count > 0);
    assert_eq!(
        json.matches("\"encoding\": {").count(),
        instruction_count,
        "every instruction must carry an encoding object"
    );
    assert_eq!(json.matches("\"total_bits\":").count(), instruction_count);
    assert_eq!(json.matches("\"opcode\":").count(), instruction_count);
    assert_eq!(json.matches("\"func3\":").count(), instruction_count);
    assert_eq!(json.matches("\"func7\":").count(), instruction_count);
}
