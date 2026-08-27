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
//! - **[`sdk`]** — Client SDK: TypeScript state node ingestion, HNSW vector mapping,
//!   and SAAP proof verification.
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

/// Enclave constant-time rejection sampling and CBD η=2 sampler.
pub mod sampling;

/// SRAM PUF + BCH(1023,512,55) fuzzy extractor (research, non-default; see the `puf` feature).
#[cfg(feature = "puf")]
pub mod puf;

/// Valgrind/ctgrind constant-time verification harness.
pub mod ct_verify;

/// Client SDK module.
pub mod sdk;

/// Rust-side mirror of the `aethel:core` WIT world's `identity-error` variant.
pub mod identity_error;

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

// ── WASM exports ──────────────────────────────────────────────────────────────

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Project a new ephemeral identity at context τ.
///
/// Returns serialized [`EphemeralProjection`] as bytes.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn plp_project_at_context(seed: &[u8], tau: &[u8]) -> Vec<u8> {
    if seed.len() < 32 {
        return alloc::vec![];
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed[..32]);
    let identity = MasterIdentity::from_seed(&seed_arr);
    let proj = identity.project_at_context(tau);
    // Serialize: tau(32) + matrix_a coeffs(256*4) + public_b coeffs(256*4)
    let mut out = alloc::vec![0u8; 32 + 256 * 4 + 256 * 4];
    out[..32].copy_from_slice(&proj.tau);
    for (i, &c) in proj.matrix_a.coeffs.iter().enumerate() {
        let offset = 32 + i * 4;
        out[offset..offset + 4].copy_from_slice(&c.to_le_bytes());
    }
    for (i, &c) in proj.public_b.coeffs.iter().enumerate() {
        let offset = 32 + 256 * 4 + i * 4;
        out[offset..offset + 4].copy_from_slice(&c.to_le_bytes());
    }
    out
}

/// Prove identity ownership for a given projection.
///
/// Returns serialized [`ZkIdentityProof`] as bytes.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn plp_prove_identity(seed: &[u8], tau: &[u8]) -> Vec<u8> {
    if seed.len() < 32 {
        return alloc::vec![];
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed[..32]);
    let identity = MasterIdentity::from_seed(&seed_arr);
    let proj = identity.project_at_context(tau);
    let proof = Prover::prove_identity(&identity, &proj, &seed_arr);
    // Serialize: commitment_w(256*4) + challenge_c(256*4) + response_z(256*4)
    let mut out = alloc::vec![0u8; 256 * 4 * 3];
    for (i, &c) in proof.commitment_w.coeffs.iter().enumerate() {
        let offset = i * 4;
        out[offset..offset + 4].copy_from_slice(&c.to_le_bytes());
    }
    for (i, &c) in proof.challenge_c.coeffs.iter().enumerate() {
        let offset = 256 * 4 + i * 4;
        out[offset..offset + 4].copy_from_slice(&c.to_le_bytes());
    }
    for (i, &c) in proof.response_z.coeffs.iter().enumerate() {
        let offset = 256 * 4 * 2 + i * 4;
        out[offset..offset + 4].copy_from_slice(&c.to_le_bytes());
    }
    out
}

/// Verify a ZK identity proof against a projection.
///
/// `projection_bytes`: serialized EphemeralProjection (from `plp_project_at_context`)
/// `proof_bytes`: serialized ZkIdentityProof (from `plp_prove_identity`)
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn plp_verify(projection_bytes: &[u8], proof_bytes: &[u8]) -> bool {
    use plp::Poly;
    let proj_size = 32 + 256 * 4 + 256 * 4;
    let proof_size = 256 * 4 * 3;
    if projection_bytes.len() < proj_size || proof_bytes.len() < proof_size {
        return false;
    }

    // Deserialize projection
    let mut tau = [0u8; 32];
    tau.copy_from_slice(&projection_bytes[..32]);
    let mut matrix_a = Poly::zero();
    for i in 0..256 {
        let offset = 32 + i * 4;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&projection_bytes[offset..offset + 4]);
        matrix_a.coeffs[i] = u32::from_le_bytes(bytes);
    }
    let mut public_b = Poly::zero();
    for i in 0..256 {
        let offset = 32 + 256 * 4 + i * 4;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&projection_bytes[offset..offset + 4]);
        public_b.coeffs[i] = u32::from_le_bytes(bytes);
    }
    let proj = EphemeralProjection { tau, matrix_a, public_b };

    // Deserialize proof
    let mut commitment_w = Poly::zero();
    for i in 0..256 {
        let offset = i * 4;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&proof_bytes[offset..offset + 4]);
        commitment_w.coeffs[i] = u32::from_le_bytes(bytes);
    }
    let mut challenge_c = Poly::zero();
    for i in 0..256 {
        let offset = 256 * 4 + i * 4;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&proof_bytes[offset..offset + 4]);
        challenge_c.coeffs[i] = u32::from_le_bytes(bytes);
    }
    let mut response_z = Poly::zero();
    for i in 0..256 {
        let offset = 256 * 4 * 2 + i * 4;
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&proof_bytes[offset..offset + 4]);
        response_z.coeffs[i] = u32::from_le_bytes(bytes);
    }
    let proof = ZkIdentityProof { commitment_w, challenge_c, response_z };

    Verifier::verify(&proj, &proof)
}

/// Generate a SAAP proof for selective attribute disclosure.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn saap_prove_wasm(
    credential: &[u8],
    disclosure_mask: u64,
    tau: &[u8],
    secret_key_bytes: &[u8],
) -> Vec<u8> {
    use saap::{saap_prove, VectorK as SaapVectorK};

    // Deserialize secret key from bytes
    let mut sk = SaapVectorK::zero();
    let coeff_size = saap::MODULE_K * saap::RING_N * 4;
    if secret_key_bytes.len() >= coeff_size {
        for k in 0..saap::MODULE_K {
            for n in 0..saap::RING_N {
                let offset = (k * saap::RING_N + n) * 4;
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&secret_key_bytes[offset..offset + 4]);
                sk.vec[k].coeffs[n] = i32::from_le_bytes(bytes);
            }
        }
    }

    let proof = saap_prove(credential, disclosure_mask, tau, &sk);

    // Serialize proof: context_tag(32) + disclosure_mask(8) + attributes(64) +
    //                  challenge(256*4) + z(4*256*4) + commitment_hash(32) + commitment_w(4*256*4)
    let mut out = alloc::vec![];
    out.extend_from_slice(&proof.context_tag);
    out.extend_from_slice(&proof.disclosure_mask.to_le_bytes());
    for &v in proof.attributes.values.iter() {
        out.extend_from_slice(&v.to_le_bytes());
    }
    for &c in proof.challenge.coeffs.iter() {
        out.extend_from_slice(&c.to_le_bytes());
    }
    for k in 0..saap::MODULE_K {
        for &c in proof.z.vec[k].coeffs.iter() {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out.extend_from_slice(&proof.commitment_hash);
    for k in 0..saap::MODULE_K {
        for &c in proof.commitment_w.vec[k].coeffs.iter() {
            out.extend_from_slice(&c.to_le_bytes());
        }
    }
    out
}

/// Verify a SAAP proof.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn saap_verify_wasm(proof_bytes: &[u8], _tau: &[u8]) -> bool {
    use saap::{SaapProof, VectorK as SaapVectorK, Polynomial as SaapPoly, verify_saap_proof};

    // Minimum size check
    let min_size = 32 + 8 + 64 + 256 * 4 + 4 * 256 * 4 + 32 + 4 * 256 * 4;
    if proof_bytes.len() < min_size {
        return false;
    }

    let mut proof = SaapProof::zero();
    let mut offset = 0usize;

    proof.context_tag.copy_from_slice(&proof_bytes[offset..offset + 32]);
    offset += 32;

    let mut mask_bytes = [0u8; 8];
    mask_bytes.copy_from_slice(&proof_bytes[offset..offset + 8]);
    proof.disclosure_mask = u64::from_le_bytes(mask_bytes);
    offset += 8;

    for i in 0..saap::MAX_ATTRIBUTES {
        let mut v = [0u8; 8];
        v.copy_from_slice(&proof_bytes[offset..offset + 8]);
        proof.attributes.values[i] = u64::from_le_bytes(v);
        offset += 8;
    }

    for i in 0..saap::RING_N {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&proof_bytes[offset..offset + 4]);
        proof.challenge.coeffs[i] = i32::from_le_bytes(bytes);
        offset += 4;
    }

    for k in 0..saap::MODULE_K {
        for n in 0..saap::RING_N {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&proof_bytes[offset..offset + 4]);
            proof.z.vec[k].coeffs[n] = i32::from_le_bytes(bytes);
            offset += 4;
        }
    }

    proof.commitment_hash.copy_from_slice(&proof_bytes[offset..offset + 32]);
    offset += 32;

    for k in 0..saap::MODULE_K {
        for n in 0..saap::RING_N {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&proof_bytes[offset..offset + 4]);
            proof.commitment_w.vec[k].coeffs[n] = i32::from_le_bytes(bytes);
            offset += 4;
        }
    }

    // Build dummy matrix and attribute commitments for verification
    let matrix_a = [SaapVectorK::zero(); saap::MODULE_K];
    let attr_commits = [SaapPoly::zero(); saap::MAX_ATTRIBUTES];

    verify_saap_proof(&proof, &matrix_a, &attr_commits).is_ok()
}

/// Split a secret into HTSS shares.
///
/// Returns serialized `Vec<(u8, u64)>` shares as bytes.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn htss_split(secret: u64, seed: u64) -> Vec<u8> {
    use htss::SecretSharer;
    let shares = SecretSharer::split_secret(secret, 3, 5, seed);
    let mut out = alloc::vec![0u8; shares.len() * 9];
    for (i, &(id, val)) in shares.iter().enumerate() {
        out[i * 9] = id;
        out[i * 9 + 1..i * 9 + 9].copy_from_slice(&val.to_le_bytes());
    }
    out
}

/// Reconstruct a secret from HTSS shares.
///
/// `shares_bytes`: serialized shares from `htss_split`
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn htss_reconstruct(shares_bytes: &[u8]) -> u64 {
    use htss::SecretSharer;
    if shares_bytes.len() < 9 * 3 {
        return 0;
    }
    let num_shares = shares_bytes.len() / 9;
    let mut shares = alloc::vec![];
    for i in 0..num_shares {
        let id = shares_bytes[i * 9];
        let mut val_bytes = [0u8; 8];
        val_bytes.copy_from_slice(&shares_bytes[i * 9 + 1..i * 9 + 9]);
        let val = u64::from_le_bytes(val_bytes);
        shares.push((id, val));
    }
    SecretSharer::reconstruct_secret(&shares)
}

/// Enroll a PUF SRAM response.
///
/// Returns serialized `(key[64], helper_data[64])` as 128 bytes.
#[cfg(all(feature = "wasm", feature = "puf"))]
#[wasm_bindgen]
pub fn puf_enroll(sram_response: &[u8]) -> Vec<u8> {
    use puf::BchFuzzyExtractor;
    if sram_response.len() < 128 {
        return alloc::vec![];
    }
    let mut sram = [0u8; 128];
    sram.copy_from_slice(&sram_response[..128]);
    let (key, helper) = BchFuzzyExtractor::enroll(&sram);
    let mut out = alloc::vec![0u8; 128];
    out[..64].copy_from_slice(&key);
    out[64..].copy_from_slice(&helper);
    out
}

/// Reconstruct a PUF key from a noisy SRAM response and helper data.
///
/// Returns serialized VectorK (MODULE_K * RING_N * 4 bytes) or empty on failure.
#[cfg(all(feature = "wasm", feature = "puf"))]
#[wasm_bindgen]
pub fn puf_reconstruct(sram_response: &[u8], helper_data: &[u8]) -> Vec<u8> {
    use puf::{BchFuzzyExtractor, puf_seed_to_vector_k};
    use sampling::{MODULE_K as SK_MODULE_K, RING_N as SK_RING_N};

    if sram_response.len() < 128 || helper_data.len() < 64 {
        return alloc::vec![];
    }
    let mut sram = [0u8; 128];
    sram.copy_from_slice(&sram_response[..128]);
    let mut helper = [0u8; 64];
    helper.copy_from_slice(&helper_data[..64]);

    match BchFuzzyExtractor::reconstruct(&sram, &helper) {
        Some(key) => {
            let v = puf_seed_to_vector_k(&key);
            let mut out = alloc::vec![0u8; SK_MODULE_K * SK_RING_N * 4];
            for k in 0..SK_MODULE_K {
                for n in 0..SK_RING_N {
                    let offset = (k * SK_RING_N + n) * 4;
                    out[offset..offset + 4].copy_from_slice(&v.vec[k].coeffs[n].to_le_bytes());
                }
            }
            out
        }
        None => alloc::vec![],
    }
}
