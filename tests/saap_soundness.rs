//! SAAP soundness tests (P3-10 / 0X3-78).
//!
//! These exist to answer one question with code rather than argument: does
//! `verify_saap_proof` bind a proof to anything outside the proof itself?
//!
//! The verifier takes `matrix_a` and `public_attribute_commitments`, which are
//! the public parameters a proof is supposed to be checked *against*. Both are
//! underscore-prefixed in the function body — they are accepted and ignored.
//! Every remaining check reads only fields carried inside the `SaapProof`
//! struct, so the checks are self-consistency checks, not proofs of knowledge.
//!
//! If `forged_proof_without_any_secret_is_rejected` fails, that is the finding,
//! not a broken test.

use aethel_core::saap::{
    self, recompute_challenge, verify_saap_proof, AttributePayload, Polynomial, SaapProof, VectorK,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Build a proof with no secret key, no credential, and no key material of any
/// kind — only public knowledge of the verification procedure.
///
/// Strategy: every check in `verify_saap_proof` derives its expected value from
/// a field of the proof. So pick the free fields first, then compute the
/// dependent ones the same way the verifier will.
fn forge(context_tag: [u8; 32], disclosure_mask: u64) -> SaapProof {
    let mut proof = SaapProof::zero();

    proof.context_tag = context_tag;
    proof.disclosure_mask = disclosure_mask;
    proof.attributes = AttributePayload::zero();

    // Free choice: the commitment vector. The verifier never checks it against
    // A·z, because `matrix_a` is ignored. Zero is the simplest witness that the
    // choice is unconstrained.
    proof.commitment_w = VectorK::zero();

    // Free choice: the response vector. Only its norm is checked, and the norm
    // of zero trivially passes the bound.
    proof.z = VectorK::zero();

    // Dependent: the challenge is whatever `recompute_challenge` produces from
    // fields we already control.
    proof.challenge = recompute_challenge(
        &proof.commitment_w,
        &proof.context_tag,
        proof.disclosure_mask,
    );

    // Dependent: the commitment hash is SHAKE-256 over the commitment vector,
    // recomputed by the verifier from the same field.
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_SAAP_COMMIT_V1");
    for poly in proof.commitment_w.vec.iter() {
        for coeff in poly.coeffs.iter() {
            hasher.update(&coeff.to_le_bytes());
        }
    }
    let mut xof = hasher.finalize_xof();
    xof.read(&mut proof.commitment_hash);

    proof
}

#[test]
fn forged_proof_without_any_secret_is_rejected() {
    let matrix_a = [VectorK::zero(); saap::MODULE_K];
    let attr_commits = [Polynomial::zero(); saap::MAX_ATTRIBUTES];

    let proof = forge([7u8; 32], 0b0000_0011);

    let result = verify_saap_proof(&proof, &matrix_a, &attr_commits);

    assert!(
        result.is_err(),
        "a proof constructed with no secret key, no credential, and no access to \
         any key material was accepted by verify_saap_proof. Every check in the \
         verifier reads only fields carried inside the proof, so the proof proves \
         knowledge of nothing."
    );
}

/// Positive control for the forgery methodology above.
///
/// PLP's verifier performs the same three-step shape as SAAP's — norm bound,
/// Fiat-Shamir challenge consistency, verification equation — but its third
/// step actually uses the projection's public parameters:
///
/// ```text
/// W' = A_τ · z - c · b_τ    then    ||W' - W||∞ < 2β
/// ```
///
/// So the analogous forgery must fail there. If this test passes while the
/// SAAP forgery is accepted, the difference is in the verifiers, not in the
/// way these tests construct a forgery.
#[test]
fn plp_rejects_the_analogous_forgery() {
    use aethel_core::plp::{MasterIdentity, Poly, Verifier, ZkIdentityProof};

    // The forger is allowed to know the public projection — that is the point
    // of a public key. It has no access to the master secret.
    let identity = MasterIdentity::from_seed(&[0x11u8; 32]);
    let projection = identity.project_at_context(b"context-under-attack");

    // Same free choices as the SAAP forgery: zero commitment, zero response,
    // challenge recomputed the way the verifier will recompute it.
    let commitment_w = Poly::zero();
    let challenge_c = aethel_core::plp::hash_to_challenge(
        &commitment_w,
        u64::from_le_bytes(projection.tau[..8].try_into().unwrap()),
    );
    let proof = ZkIdentityProof {
        commitment_w,
        challenge_c,
        response_z: Poly::zero(),
    };

    assert!(
        !Verifier::verify(&projection, &proof),
        "PLP accepted the same style of forgery SAAP accepts — in that case the \
         forgery helper is what is wrong, not the SAAP verifier, and the SAAP \
         finding must be re-derived before it is reported."
    );
}

#[test]
fn proof_does_not_verify_under_a_different_context() {
    let matrix_a = [VectorK::zero(); saap::MODULE_K];
    let attr_commits = [Polynomial::zero(); saap::MAX_ATTRIBUTES];

    let tau_a = [0xAAu8; 32];
    let tau_b = [0xBBu8; 32];

    // A proof built for context A.
    let proof = forge(tau_a, 0b0000_0001);

    // The native verifier takes no caller-supplied τ at all, so "verify under
    // context B" cannot even be expressed against this signature. Assert the
    // shape the WIT world declares: verification is parameterised by the
    // caller's context.
    assert_ne!(
        tau_a, tau_b,
        "test setup: the two contexts must differ for this to mean anything"
    );

    let result = verify_saap_proof(&proof, &matrix_a, &attr_commits);
    assert!(
        result.is_err(),
        "verify_saap_proof has no τ parameter, so a proof carrying its own \
         context_tag is self-certifying: the caller cannot ask 'is this valid \
         for MY context?'. The WIT world declares \
         saap-verify(proof, tau) -> result<bool, identity-error>."
    );
}
