//! WebAssembly Component Model adapter for the `aethel:core` WIT world.
//!
//! This is the L1 boundary the charter describes: **one artifact, embedded by
//! every language, never per-language crypto.** No cryptography is implemented
//! here — every function in this module converts between the WIT-declared types
//! and the native API, and calls into `plp`, `saap` or `htss`.
//!
//! ## Why this exists separately from the `wasm` feature
//!
//! The `wasm` feature produces a `wasm-bindgen` cdylib: a *core module* with a
//! flat pointer/length ABI plus JavaScript glue. That is not a Component Model
//! component, its exports are untyped, and it cannot express
//! `result<T, identity-error>`. It was also the surface on which the P3-10
//! soundness findings sat unnoticed, because nothing connected it to the
//! declared world.
//!
//! This module implements the world as declared, with its real types, generated
//! from `wit/aethel-core.wit` rather than hand-written.
//!
//! ## Build
//!
//! ```bash
//! cargo build --release --target wasm32-unknown-unknown \
//!   --no-default-features --features component
//! wasm-tools component new \
//!   target/wasm32-unknown-unknown/release/aethel_core.wasm \
//!   -o aethel_core.component.wasm
//! ```
//!
//! ## Operations that are not implemented, and deny rather than pretend
//!
//! `saap-verify` **always returns `ok(false)`**. It is not wired to
//! [`saap::verify_saap_proof_against`] because that requires a public key
//! `t = A_τ·sk`, which the WIT signature `saap-verify(proof, tau)` has no
//! parameter to carry, and which with the current prover is an exact linear
//! image of the secret (no error term) and therefore unsafe to publish at all.
//! The RFC anchors verification on `b_τ = A_τ·s + e_τ`, whose noise makes it
//! publishable; building that is P3-11 (0X3-79).
//!
//! A verifier that cannot verify soundly must deny, not allow. Denying is not
//! the same as being correct, and callers must not read `ok(false)` from this
//! operation as "this proof is invalid".

#![allow(clippy::needless_range_loop)]

extern crate alloc;

use alloc::vec::Vec;

wit_bindgen::generate!({
    path: "wit",
    world: "aethel-core",
});

use exports::aethel::core::attestation::{
    DisclosureAttributes, Guest as AttestationGuest, SaapProof as WitSaapProof,
};
use exports::aethel::core::identity::{
    EphemeralProjection as WitProjection, Guest as IdentityGuest,
    ZkIdentityProof as WitZkProof,
};
use exports::aethel::core::secret_sharing::{Guest as SecretSharingGuest, HtssShare as WitShare};
use aethel::core::types::IdentityError as WitError;

use crate::identity_error::IdentityError;
use crate::{htss, plp, saap};

/// The `htss-split` WIT signature carries no nonce parameter, but
/// [`htss::SecretSharer::split_key_material`] takes one to separate independent
/// sharings of the same secret.
///
/// A fixed value is safe — the nonce is explicitly not required to be secret,
/// and the threshold property rests on coefficients derived from the secret
/// itself — but it makes sharing deterministic: splitting the same secret twice
/// yields identical shares. That is acceptable for reconstruction and it does
/// not weaken the threshold, but a caller who wants two unlinkable sharings of
/// one secret cannot get them through this interface.
///
/// Adding a `nonce` parameter to `htss-split` is a WIT change that ripples into
/// P6 and P7, so it is flagged rather than made here. See 0X3-78.
const COMPONENT_SPLIT_NONCE: &[u8] = b"AETHEL_COMPONENT_HTSS_V1";

struct Component;

// ── Error mapping ─────────────────────────────────────────────────────────────

impl From<IdentityError> for WitError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::InvalidInputLength => WitError::InvalidInputLength,
            IdentityError::SerializationError => WitError::SerializationError,
            IdentityError::RejectionSamplingFailed => WitError::RejectionSamplingFailed,
            IdentityError::NormBoundViolation => WitError::NormBoundViolation,
            IdentityError::ChallengeMismatch => WitError::ChallengeMismatch,
            IdentityError::InvalidAttributeCommitment => WitError::InvalidAttributeCommitment,
            IdentityError::ThresholdNotMet => WitError::ThresholdNotMet,
        }
    }
}

/// `MasterIdentity::from_seed` takes `&[u8; 32]`; the WIT declares `list<u8>`,
/// which cannot express that bound. The implementation owns it, and says so with
/// `invalid-input-length` rather than truncating or panicking.
fn secret_as_seed(secret: &[u8]) -> Result<[u8; 32], WitError> {
    if secret.len() != 32 {
        return Err(WitError::InvalidInputLength);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(secret);
    Ok(seed)
}

// ── identity ──────────────────────────────────────────────────────────────────

impl IdentityGuest for Component {
    fn plp_project_at_context(
        secret: Vec<u8>,
        tau: Vec<u8>,
        randomness: Vec<u8>,
    ) -> Result<WitProjection, WitError> {
        let seed = secret_as_seed(&secret)?;
        // `randomness` seeds the error term e_tau; short randomness weakens the
        // projection to an exact linear image of the secret, so reject it.
        if randomness.len() < 32 {
            return Err(WitError::InvalidInputLength);
        }
        let identity = plp::MasterIdentity::from_seed(&seed);
        let proj = identity.project_at_context(&tau, &randomness);

        Ok(WitProjection {
            tau: proj.tau.to_vec(),
            matrix_a: proj.matrix_a.coeffs().to_vec(),
            public_b: proj.public_b.coeffs().to_vec(),
        })
    }

    fn plp_prove_identity(secret: Vec<u8>, tau: Vec<u8>) -> Result<WitZkProof, WitError> {
        let seed = secret_as_seed(&secret)?;
        let identity = plp::MasterIdentity::from_seed(&seed);
        // The proof is independent of e_tau, so proving needs only A_tau and
        // tau — no fresh randomness. The proving seed is the secret itself;
        // `prove_identity` runs a fixed 16-iteration rejection loop and always
        // returns a proof, which verifies against whatever b_tau was published.
        let proj = plp::EphemeralProjection::for_proving(&tau);
        let proof = plp::Prover::prove_identity(&identity, &proj, &seed);

        Ok(WitZkProof {
            commitment_w: proof.commitment_w.coeffs().to_vec(),
            challenge_c: proof.challenge_c.coeffs().to_vec(),
            response_z: proof.response_z.coeffs().to_vec(),
        })
    }

    fn plp_verify(
        projection: WitProjection,
        proof: WitZkProof,
    ) -> Result<bool, WitError> {
        let proj = projection_from_wit(&projection)?;
        let zk = zk_proof_from_wit(&proof)?;

        // A well-formed proof that does not verify is `ok(false)`; input that
        // could not be parsed is `err`. The previous export returned a bare
        // `bool` and could not tell a caller which had happened.
        Ok(plp::Verifier::verify(&proj, &zk))
    }
}

fn poly_from_coeffs(coeffs: &[u32]) -> Result<plp::Poly, WitError> {
    if coeffs.len() != crate::RING_N {
        return Err(WitError::SerializationError);
    }
    let mut poly = plp::Poly::zero();
    poly.coeffs.copy_from_slice(coeffs);
    Ok(poly)
}

fn projection_from_wit(p: &WitProjection) -> Result<plp::EphemeralProjection, WitError> {
    if p.tau.len() != 32 {
        return Err(WitError::SerializationError);
    }
    let mut tau = [0u8; 32];
    tau.copy_from_slice(&p.tau);

    Ok(plp::EphemeralProjection {
        tau,
        matrix_a: poly_from_coeffs(&p.matrix_a)?,
        public_b: poly_from_coeffs(&p.public_b)?,
    })
}

fn zk_proof_from_wit(p: &WitZkProof) -> Result<plp::ZkIdentityProof, WitError> {
    Ok(plp::ZkIdentityProof {
        commitment_w: poly_from_coeffs(&p.commitment_w)?,
        challenge_c: poly_from_coeffs(&p.challenge_c)?,
        response_z: poly_from_coeffs(&p.response_z)?,
    })
}

// ── attestation ───────────────────────────────────────────────────────────────

impl AttestationGuest for Component {
    fn saap_prove(
        credential: Vec<u8>,
        disclosed: DisclosureAttributes,
        tau: Vec<u8>,
        secret_key: Vec<u8>,
        randomness: Vec<u8>,
    ) -> Result<WitSaapProof, WitError> {
        // The named flags are the interface; the bitmask stays an implementation
        // detail below this boundary. The WIT is explicit that a raw mask must
        // never appear on the wire.
        let mask = disclosed.bits() as u64;

        // `randomness` seeds the sigma mask r that hides sk in z = r + c·sk;
        // reject short randomness rather than emit a weakly-masked proof.
        if randomness.len() < 32 {
            return Err(WitError::InvalidInputLength);
        }

        let sk = saap_secret_key_from_bytes(&secret_key)?;
        let proof = saap::saap_prove(&credential, mask, &tau, &sk, &randomness);

        Ok(WitSaapProof {
            context_tag: proof.context_tag.to_vec(),
            disclosed,
            attributes: proof.attributes.values.to_vec(),
            challenge: proof.challenge.coeffs.to_vec(),
            response_z: flatten_vector_k(&proof.z),
            commitment_hash: proof.commitment_hash.to_vec(),
            commitment_w: flatten_vector_k(&proof.commitment_w),
        })
    }

    /// **Always returns `ok(false)`.** See this module's header: the corrected
    /// verifier needs a public key this signature cannot carry, and the only
    /// public key the current prover admits leaks the secret. Denying is the
    /// safe failure; it is not a statement about the proof.
    fn saap_verify(_proof: WitSaapProof, _tau: Vec<u8>) -> Result<bool, WitError> {
        Ok(false)
    }
}

fn saap_secret_key_from_bytes(bytes: &[u8]) -> Result<saap::VectorK, WitError> {
    let expected = saap::MODULE_K * saap::RING_N * 4;
    if bytes.len() != expected {
        return Err(WitError::InvalidInputLength);
    }
    let mut sk = saap::VectorK::zero();
    let mut off = 0;
    for k in 0..saap::MODULE_K {
        for n in 0..saap::RING_N {
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[off..off + 4]);
            sk.vec[k].coeffs[n] = i32::from_le_bytes(b);
            off += 4;
        }
    }
    Ok(sk)
}

fn flatten_vector_k(v: &saap::VectorK) -> Vec<i32> {
    let mut out = Vec::with_capacity(saap::MODULE_K * saap::RING_N);
    for k in 0..saap::MODULE_K {
        out.extend_from_slice(&v.vec[k].coeffs);
    }
    out
}

// ── secret-sharing ────────────────────────────────────────────────────────────

impl SecretSharingGuest for Component {
    fn htss_split(secret: Vec<u8>) -> Result<Vec<WitShare>, WitError> {
        let shares = htss::SecretSharer::split_key_material(&secret, COMPONENT_SPLIT_NONCE)?;
        Ok(shares
            .into_iter()
            .map(|s| WitShare {
                index: s.index,
                value: s.value,
            })
            .collect())
    }

    fn htss_reconstruct(shares: Vec<WitShare>) -> Result<Vec<u8>, WitError> {
        let native: Vec<htss::HtssShare> = shares
            .into_iter()
            .map(|s| htss::HtssShare {
                index: s.index,
                value: s.value,
            })
            .collect();
        Ok(htss::SecretSharer::reconstruct_key_material(&native)?)
    }
}

export!(Component);
