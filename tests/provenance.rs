//! The provenance constants must describe this checkout, not a stale build.
//!
//! `build.rs` reads `component.rev` and `component.sha256` and passes them
//! through `rustc-env`. Nothing else connects the constants to the files, so a
//! build script that stopped emitting a variable, emitted the wrong one, or took
//! the wrong field out of `component.sha256` would produce a crate that reports
//! its provenance confidently and wrongly.
//!
//! A wrong answer here is worse than no answer. These values exist so a consumer
//! can check its vendored artifact against the crate it links; a constant that
//! has drifted from the file is what that check would be comparing against, and
//! it would pass.

#![cfg(not(feature = "component"))]

use aethel_core::{COMPONENT_SHA256, GIT_REVISION};

const REV_FILE: &str = include_str!("../component.rev");
const SHA_FILE: &str = include_str!("../component.sha256");

/// `component.sha256` is `<digest>  <filename>`, as sha256sum writes it.
fn digest_of(line: &str) -> &str {
    line.split_whitespace()
        .next()
        .expect("component.sha256 is empty")
}

fn is_lowercase_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

#[test]
fn the_revision_constant_matches_the_recorded_revision() {
    assert_eq!(
        GIT_REVISION,
        REV_FILE.trim(),
        "aethel_core::GIT_REVISION disagrees with component.rev. build.rs is \
         not passing the recorded value through."
    );
}

#[test]
fn the_component_hash_constant_matches_the_recorded_hash() {
    assert_eq!(
        COMPONENT_SHA256,
        digest_of(SHA_FILE),
        "aethel_core::COMPONENT_SHA256 disagrees with component.sha256. A \
         consumer comparing its vendored artifact against this constant would \
         be comparing against the wrong build."
    );
}

#[test]
fn the_revision_is_a_full_commit_sha() {
    assert_eq!(
        GIT_REVISION.len(),
        40,
        "GIT_REVISION is not a full commit sha: {GIT_REVISION}"
    );
    assert!(
        is_lowercase_hex(GIT_REVISION),
        "GIT_REVISION is not lowercase hex: {GIT_REVISION}"
    );
}

#[test]
fn the_component_hash_is_a_well_formed_sha256() {
    assert_eq!(
        COMPONENT_SHA256.len(),
        64,
        "COMPONENT_SHA256 is not 64 hex characters: {COMPONENT_SHA256}"
    );
    assert!(
        is_lowercase_hex(COMPONENT_SHA256),
        "COMPONENT_SHA256 is not lowercase hex: {COMPONENT_SHA256}"
    );
}

/// Positive control for the two comparisons above.
///
/// They assert that two strings are equal. That proves nothing unless the
/// extraction behind them can report *un*equal, and unless it reads the digest
/// rather than some other part of the line — an extraction that returned
/// `COMPONENT_SHA256` unconditionally would satisfy every assertion here.
#[test]
fn the_digest_extraction_can_fail_and_reads_the_right_field() {
    let wrong = "0000000000000000000000000000000000000000000000000000000000000000  \
                 aethel_core.component.wasm";
    assert_ne!(
        digest_of(wrong),
        COMPONENT_SHA256,
        "the extraction reports a match for a hash that is plainly different; \
         it cannot detect a mismatch and the test above is worthless"
    );

    assert_eq!(
        digest_of("abc123  aethel_core.component.wasm"),
        "abc123",
        "the extraction is not taking the digest field"
    );
}
