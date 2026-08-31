//! # aethel-core — Post-Quantum Ephemeral Identifier Engine
//!
//! `aethel-core` implements the **Polymorphic Lattice Projection (PLP)** standard
//! for decoupled post-quantum ephemeral identity. It replaces static W3C DIDs
//! with non-deterministic, ephemeral identity projections that leave **zero
//! static public keys**, full stop — this crate has no blockchain, ledger, or
//! on-chain component of any kind; the property holds regardless of where a
//! caller chooses to publish anything.
//!
//! ## Core Components
//!
//! - **[`plp`]** — Polymorphic Lattice Projection engine: ring arithmetic, ZK sigma
//!   protocol, and rejection sampling over Module-LWE (M-LWE).
//! - **[`htss`]** — 5D Hypercube Threshold Secret Sharing: Shamir 3-of-5 over F_q,
//!   dimension-disjoint routing across Q_5 (32 nodes, 80 edges).
//! - **[`saap`]** — Selective Attribute Attestation Protocol: BDLOP vector commitment
//!   scheme with ZK selective disclosure and norm-bound verification.
//! - **[`sampling`]** — Enclave constant-time rejection sampling: 16-iteration padded
//!   loop, CMOV selection, volatile zeroization, and CBD η=2 sampler.
//! - `puf` (research, non-default `puf` feature) — SRAM PUF + BCH(1023,512,55) fuzzy
//!   extractor: GF(2^10) arithmetic, Berlekamp-Massey, Chien Search, and pure Rust WASM
//!   implementation. Not part of the default build or the `aethel:core` WIT world.
//! - **[`ct_verify`]** — Valgrind/ctgrind constant-time verification harness.
//!
//! ## Security Properties
//!
//! - **Unlinkability**: `Adv_Adversary_Link(b_τ1, b_τ2) ≤ Negl(λ)` under M-LWE hardness.
//! - **Post-Quantum Soundness**: Reduces to Decision M-LWE_{k,k+1,η,q} over R_q.
//! - **Zero Static Keys**: No public key is ever written to persistent storage or ledger.
//! - **Constant-Time**: All secret-dependent operations execute in fixed time (I_max=16).
//!
//! ## Parameters (AETHEL-SAAP-LEVEL1)
//!
//! - Ring: `R_q = Z_q[X]/(X^256 + 1)`, `q = 8_380_417`
//! - Module rank: `k = 4`
//! - Noise: CBD η=2, rejection bound γ₁=131072, β=78
//!
//! ## Feature Flags
//!
//! - `std` (default): Standard library support, heap allocation.
//! - `wasm`: WebAssembly target with `wasm-bindgen` bindings.
//! - `enclave`: Enables constant-time enclave execution paths and volatile zeroization.
//! - `puf` (research, non-default): Compiles the `puf` module and its `puf_enroll` /
//!   `puf_reconstruct` WASM exports. SRAM PUF is out of scope for the `aethel:core` WIT
//!   world; this feature exists for research use only, not for production identity
//!   derivation.
//!
//! ## Unsafe Code
//!
//! The default build (no `puf`, no `enclave`) contains exactly 5 `unsafe` blocks, all in
//! [`sampling`], each carrying a `// SAFETY:` comment explaining the invariant it relies on
//! (volatile zeroization writes and constant-time byte-slice reinterpretation of same-sized,
//! non-aliasing structs). Enabling `puf` or `enclave` additionally compiles 2 more `unsafe`
//! blocks in `puf::ffi`, an FFI wrapper around a C enclave shim that is not shipped by
//! default.

#![cfg_attr(not(feature = "std"), no_std)]
// unsafe_code is required for volatile memory operations in sampling.rs and puf.rs
#![warn(missing_docs)]
#![warn(clippy::all)]

// ── Allocator setup ───────────────────────────────────────────────────────────

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

// Import alloc types needed for WASM exports
#[cfg(feature = "wasm")]
use alloc::vec::Vec;

// ── Module declarations ──────────────────────────────────────────────────────

/// Polymorphic Lattice Projection (PLP) engine.
pub mod plp;

/// Threshold secret sharing (Shamir 3-of-5) plus a local hypercube routing simulation.
pub mod htss;

/// Selective Attribute Attestation Protocol (SAAP) verification engine.
pub mod saap;
pub mod signing;

pub mod credential;

/// Enclave constant-time rejection sampling and CBD η=2 sampler.
pub mod sampling;

/// SRAM PUF + BCH(1023,512,55) fuzzy extractor (research, non-default; see the `puf` feature).
#[cfg(feature = "puf")]
pub mod puf;

/// Valgrind/ctgrind constant-time verification harness.
pub mod ct_verify;

/// Client SDK module.

/// Rust-side mirror of the `aethel:core` WIT world's `identity-error` variant.
pub mod identity_error;

/// WebAssembly Component Model adapter implementing the `aethel:core` WIT world.
#[cfg(feature = "component")]
pub mod component;

// ── Re-exports of public API types ───────────────────────────────────────────

pub use plp::{EphemeralProjection, MasterIdentity, Prover, Verifier, ZkIdentityProof};
pub use htss::{HypercubeNetwork, NodeAddress, SecretSharer, ZkProofSegment};
pub use saap::{SaapProof, SaapValidationError};
pub use sampling::{PlpProof, RejectionError, VectorK};
pub use identity_error::IdentityError;

// ── Crate-level constants ─────────────────────────────────────────────────────

/// Ring degree N for the cyclotomic polynomial X^N + 1.
pub const RING_N: usize = 256;

/// Prime modulus q = 8_380_417 ≈ 2^23, q ≡ 1 (mod 512).
pub const MODULUS_Q: i64 = 8_380_417;

/// Module rank k (AETHEL-SAAP-LEVEL1).
pub const MODULE_K: usize = 4;

/// Centered Binomial Distribution parameter η = 2.
pub const PARAM_ETA: i64 = 2;

/// Masking vector bound γ₁ = 2^17 = 131_072.
pub const PARAM_GAMMA1: i64 = 131_072;

/// Rejection sampling bound β = 78.
pub const PARAM_BETA: i64 = 78;

/// Rejection threshold γ₁ - β = 130_994.
pub const REJECTION_BOUND: i64 = PARAM_GAMMA1 - PARAM_BETA;

/// Fixed iteration ceiling for constant-time enclave loop.
pub const FIXED_ITERATION_CEILING: usize = 16;

/// Magic header bytes for the Ephemeral Identity Attestation Bundle (EIAB).
pub const EIAB_MAGIC: &[u8; 4] = b"ATH1";

// ── Error type ────────────────────────────────────────────────────────────────

/// Top-level error type for aethel-core operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AethelError {
    /// Serialization or deserialization failed.
    SerializationError,
    /// Proof verification failed.
    VerificationFailed,
    /// Rejection sampling exhausted all iterations.
    RejectionSamplingFailed,
    /// PUF reconstruction failed (too many bit errors).
    PufReconstructionFailed,
    /// Invalid input length.
    InvalidInputLength,
    /// SAAP validation error.
    SaapError(SaapValidationError),
}

impl From<SaapValidationError> for AethelError {
    fn from(e: SaapValidationError) -> Self {
        AethelError::SaapError(e)
    }
}

// ── One WebAssembly artifact ──────────────────────────────────────────────────
//
// The wasm-bindgen export surface that used to live here is gone (P3-13 /
// 0X3-81). It was a second WebAssembly surface alongside the Component Model
// component: untyped (`Vec<u8>`/`bool`/`u64`), signalling failure with sentinel
// values instead of `result<T, identity-error>`, and taking a raw u64
// disclosure mask the WIT world is explicit about never putting on the wire.
//
// Two surfaces contradicts the charter's "one shared .wasm; adding a language
// never adds crypto", and the untyped one is where both P3-10 soundness
// findings sat unnoticed precisely because nothing connected it to the declared
// world. An SDK author picking it up got sentinels rather than typed results.
//
// The component in `src/component.rs`, built with `--features component`, is
// the L1 boundary. See README's "The WASM Component (L1 boundary)".
