//! Stamp the binary with the commit it was built from.
//!
//! A consumer running a pinned `target/release/axis` against a newer source
//! tree gets errors that read as defects: a description naming a form the
//! binary predates fails with "unsupported axis-module form", and one using an
//! operator it predates fails with "unsupported formal_semantics operator".
//! `pce/docs/AXISMINE_BINARY_REGION_MINING.md` reported both and attributed the
//! second to a disagreement between two components of AXIS -- which was really
//! a match arm inside the very function reporting the error. The binary was
//! five days older than the tree.
//!
//! The crate version cannot say that: it is `0.1.0` and has never moved. The
//! commit can, so the commit is what is stamped.
use std::process::Command;

fn main() {
    // Rebuild when the checked-out commit changes, and not otherwise.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");
    let stamp = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string())
        .filter(|text| !text.is_empty());
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|out| !out.stdout.is_empty())
        .unwrap_or(false);
    // A build from a tree with uncommitted changes says so: "this is not any
    // commit" is the honest answer, and the one a reader most needs when an
    // artifact disagrees with the repository.
    let build = match (stamp, dirty) {
        (Some(hash), true) => format!("{hash}-dirty"),
        (Some(hash), false) => hash,
        (None, _) => "unknown".to_string(),
    };
    println!("cargo:rustc-env=AXIS_BUILD={build}");
}
