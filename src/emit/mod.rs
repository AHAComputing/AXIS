//! AXIS artifact emitters, split by domain.
//!
//! Shared low-level helpers live in `common`; each other module owns one
//! family of generated artifacts. Public `emit_*` entry points are re-exported
//! here so `crate::emit::emit_*` and the `lib.rs` re-exports stay stable.

mod capsule;
pub(crate) mod common;
pub use common::emit_uarch_json;
mod encode;
mod hw;
mod legality;
mod lift;
mod lisp;
pub(crate) mod llvm;
mod llvm_target;
mod manifest;
mod fabric;
mod mapping;
mod packet;
mod simt;
pub(crate) mod semantics;
mod tablegen;
mod topology;
mod translation;

pub use capsule::*;
pub use encode::*;
pub use hw::*;
pub use legality::*;
pub use lift::*;
pub use lisp::*;
pub use llvm::*;
pub use llvm_target::*;
pub use manifest::*;
pub use fabric::*;
pub use mapping::*;
pub use packet::*;
pub use semantics::*;
pub use simt::*;
pub use tablegen::*;
pub use topology::*;
pub use translation::*;

#[cfg(test)]
mod tests {
    use crate::{parse_document, validate_document};

    use super::*;

    #[test]
    fn emits_rvmt_compatible_decode_keys() {
        let doc = parse_document(
            r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction tls_load
    (mnemonic TLS_LOAD)
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
"#,
        )
        .unwrap();
        validate_document(&doc).unwrap();
        let output = emit_json(&doc);
        assert!(output.contains("\"target\": \"rvmt\""));
        assert!(output.contains("\"decode_key\""));
        assert!(output.contains("\"opcode\": 11"));
    }

    #[test]
    fn emits_python_data_module() {
        let doc = parse_document(
            r#"(axis-module xpce
  (version "1.0")
  (target rvmt)

  (definstruction tls_load
    (mnemonic TLS_LOAD)
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
"#,
        )
        .unwrap();
        validate_document(&doc).unwrap();
        let output = emit_python(&doc);
        assert!(output.contains("RVMT_EXTENSION_MANIFEST = {"));
        assert!(output.contains("PCE_ADL_MANIFEST = {"));
    }
}
