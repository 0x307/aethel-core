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

// ── WASM exports ──────────────────────────────────────────────────────────────

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Project a new ephemeral identity at context τ.
///
/// Returns serialized [`EphemeralProjection`] as bytes.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn plp_project_at_context(seed: &[u8], tau: &[u8], randomness: &[u8]) -> Vec<u8> {
    // `randomness` MUST be >=32 bytes of fresh, secret entropy: it seeds the
    // error term e_tau that makes b_tau an M-LWE sample rather than an exact
    // linear image of the secret. Fail closed on short randomness.
    if seed.len() < 32 || randomness.len() < 32 {
        return alloc::vec![];
    }
    let mut seed_arr = [0u8; 32];
    seed_arr.copy_from_slice(&seed[..32]);
    let identity = MasterIdentity::from_seed(&seed_arr);
    let proj = identity.project_at_context(tau, randomness);
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
    // The proof is independent of e_tau (the verifier's approximate check
    // absorbs c·e_tau), so proving needs only A_tau and tau — no fresh
    // randomness and no real b_tau. It verifies against whatever b_tau the
    // caller published via plp_project_at_context.
    let proj = plp::EphemeralProjection::for_proving(tau);
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
    randomness: &[u8],
) -> Vec<u8> {
    use saap::{saap_prove, VectorK as SaapVectorK};

    // `randomness` MUST be >=32 bytes of fresh, secret entropy: it seeds the
    // sigma-protocol mask r that hides sk in z = r + c·sk. Fail closed on short
    // randomness rather than emitting a proof with a weak mask.
    if randomness.len() < 32 {
        return alloc::vec![];
    }

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

    let proof = saap_prove(credential, disclosure_mask, tau, &sk, randomness);

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

/// Verify a SAAP proof. **Currently rejects everything, by design.**
///
/// This export previously called a verifier that accepted proofs forged with no
/// secret key. It now fails closed rather than attesting to something false: a
/// verifier that cannot verify soundly must deny, not allow.
///
/// It is not wired to the corrected `saap::verify_saap_proof_against` because
/// that requires a public key `t = A_τ · sk`, and with the current prover `t` is
/// an exact linear image of the secret — publishing it would leak `sk` to linear
/// algebra. Adding a public-key parameter here would push callers toward doing
/// exactly that. The RFC's design anchors verification on `b_τ = A_τ·s + e_τ`,
/// the PLP projection, whose error term makes it safe to publish; building that
/// is P3-11 (0X3-79), and this export gets wired to it there.
///
/// Native callers who need SAAP verification today should use
/// `saap::verify_saap_proof_against` directly and treat `t` as test-only.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn saap_verify_wasm(_proof_bytes: &[u8], _tau: &[u8]) -> bool {
    false
}

/// Split key material into HTSS shares.
///
/// `secret` is arbitrary-length key material, not a `u64` — the previous
/// signature took a `u64` and shared only `secret % MODULUS_Q` (~23 bits),
/// silently discarding the rest.
///
/// `nonce` separates independent sharings of the same secret. It is **not**
/// required to be secret: the sharing polynomial's coefficients derive from the
/// secret itself, so the threshold property does not depend on the nonce being
/// unguessable. (The previous export's `seed` parameter did carry that weight,
/// which is why one share plus the seed recovered the secret.)
///
/// Returns the wire format documented on
/// [`htss::SecretSharer::split_key_material_bytes`], or an empty vector on
/// invalid input.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn htss_split(secret: &[u8], nonce: &[u8]) -> Vec<u8> {
    htss::SecretSharer::split_key_material_bytes(secret, nonce).unwrap_or_default()
}

/// Reconstruct key material from HTSS shares.
///
/// `shares_bytes`: the wire format produced by [`htss_split`].
///
/// Returns an empty vector when reconstruction fails — below threshold, or
/// malformed input. Empty is unambiguous here in a way the previous export's
/// return value was not: that one returned `u64` and yielded `0` below
/// threshold, which is indistinguishable from having recovered the secret `0`.
/// A caller must still treat empty as failure and never as a secret.
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn htss_reconstruct(shares_bytes: &[u8]) -> Vec<u8> {
    htss::SecretSharer::reconstruct_key_material_bytes(shares_bytes).unwrap_or_default()
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
