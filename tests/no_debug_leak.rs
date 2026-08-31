//! # P3-03 — Debug/Display redaction proof
//!
//! Every type this crate's own public API uses to carry raw secret key
//! material must not implement `Debug`/`Display` — a derive on such a type
//! would let anyone with a value in hand format-print the raw secret with a
//! single `{:?}`. This is checked at *compile time*, not as a runtime
//! assertion: `assert_not_impl_any!` expands to code that only compiles if
//! the named type does NOT implement the named trait(s), so re-adding a
//! naive `#[derive(Debug)]` to any of these types breaks the build, not just
//! a test run.
//!
//! Per the task's own hedge clause: a type that never implements Debug/Display
//! at all satisfies "debug/display formatting redacts" trivially — there is
//! nothing to format, so nothing to leak. That's the design chosen here
//! (rather than a custom, hand-redacted `Debug` impl) for every type below.
//!
//! - [`aethel_core::plp::Poly`] / [`aethel_core::plp::MasterIdentity`] — `Poly` is
//!   the storage type for `MasterIdentity`'s private `secret_key` field (and
//!   is also used throughout `plp` for public projection/proof data, hence
//!   the crate-wide rule below rather than a narrower one).
//! `saap::Polynomial` / `saap::VectorK` carry the same guarantee, asserted in
//! `src/saap.rs` instead: that module became crate-private in P3-10 / 0X3-78,
//! so an integration test can no longer name its types.
//! - [`aethel_core::sampling::Polynomial`] / [`aethel_core::sampling::VectorK`] —
//!   `VectorK` is the type `enclave_plp_prove_fixed_time`'s `s` parameter
//!   uses to carry a raw secret. Neither derived `Debug` before this pass
//!   either; this test locks that in.
//!
//! Types intentionally NOT covered here (documented, not merely omitted):
//! `saap::AttributePayload` (deliberately-disclosed attribute values, not
//! secret material — see its doc comment) and `htss::ZkProofSegment` /
//! `htss::HypercubePacket` / `htss::NodeAddress` (a Shamir share meant for
//! transmission and public routing topology, not the master secret — see
//! `ZkProofSegment`'s doc comment).

use static_assertions::assert_not_impl_any;

assert_not_impl_any!(aethel_core::plp::Poly: core::fmt::Debug, core::fmt::Display);
assert_not_impl_any!(aethel_core::plp::MasterIdentity: core::fmt::Debug, core::fmt::Display);
assert_not_impl_any!(aethel_core::sampling::Polynomial: core::fmt::Debug, core::fmt::Display);
assert_not_impl_any!(aethel_core::sampling::VectorK: core::fmt::Debug, core::fmt::Display);

/// A no-op test so this file shows up in `cargo test` output — the real
/// assertions above already ran at compile time; if this file compiled at
/// all, they passed.
#[test]
fn no_debug_leak_assertions_compiled() {}
