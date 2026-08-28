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
        &proof.attributes,
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

/// Characterises the defect in the deprecated verifier, executably.
///
/// This asserts the **known-bad** behaviour deliberately: `verify_saap_proof`
/// accepts a proof forged with no secret key. It is written as a passing test so
/// the defect is pinned rather than merely described, and so it disappears
/// together with the function it characterises. The correctness assertions live
/// in `corrected_verifier_*` above.
#[test]
#[allow(deprecated)]
fn deprecated_verifier_accepts_forgeries_known_defect() {
    let matrix_a = [VectorK::zero(); saap::MODULE_K];
    let attr_commits = [Polynomial::zero(); saap::MAX_ATTRIBUTES];

    let proof = forge([7u8; 32], 0b0000_0011);

    assert!(
        verify_saap_proof(&proof, &matrix_a, &attr_commits).is_ok(),
        "the deprecated verifier now rejects the forgery — if it was fixed, delete \
         this characterisation test along with the function"
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

// ── The corrected verifier ────────────────────────────────────────────────────

const TAU: &[u8] = b"context-alpha";
const CREDENTIAL: &[u8] = b"attribute-block-0123456789abcdef";

fn test_secret_key() -> VectorK {
    let mut sk = VectorK::zero();
    for k in 0..saap::MODULE_K {
        for n in 0..saap::RING_N {
            sk.vec[k].coeffs[n] = (n % 5) as i32 - 2;
        }
    }
    sk
}

/// The load-bearing test: an honestly generated proof must satisfy
/// `A_τ · z - c · t == w`. If this fails, the verification equation is wrong and
/// nothing built on it can be trusted.
#[test]
fn honest_proof_satisfies_the_verification_equation() {
    let sk = test_secret_key();
    let proof = saap::saap_prove(CREDENTIAL, 0b0000_0011, TAU, &sk);
    let public_key = saap::saap_public_key(TAU, &sk);

    assert_eq!(
        saap::verify_saap_proof_against(&proof, TAU, &public_key),
        Ok(()),
        "an honestly generated proof failed the verification equation"
    );
}

#[test]
fn corrected_verifier_rejects_the_forgery() {
    let sk = test_secret_key();
    let public_key = saap::saap_public_key(TAU, &sk);
    let forged = forge_for(TAU, 0b0000_0011);

    assert!(
        saap::verify_saap_proof_against(&forged, TAU, &public_key).is_err(),
        "the corrected verifier still accepts a proof forged with no secret key"
    );
}

#[test]
fn corrected_verifier_rejects_a_proof_from_another_context() {
    let sk = test_secret_key();
    let proof = saap::saap_prove(CREDENTIAL, 0b0000_0011, TAU, &sk);

    // Same identity, different context: derive the public key for the context
    // the verifier actually cares about.
    let other_tau: &[u8] = b"context-beta";
    let public_key_beta = saap::saap_public_key(other_tau, &sk);

    assert!(
        saap::verify_saap_proof_against(&proof, other_tau, &public_key_beta).is_err(),
        "a proof issued for one context verified under another"
    );
}

#[test]
fn corrected_verifier_rejects_a_tampered_response() {
    let sk = test_secret_key();
    let mut proof = saap::saap_prove(CREDENTIAL, 0b0000_0011, TAU, &sk);
    let public_key = saap::saap_public_key(TAU, &sk);

    proof.z.vec[0].coeffs[0] = proof.z.vec[0].coeffs[0].wrapping_add(1);

    assert!(
        saap::verify_saap_proof_against(&proof, TAU, &public_key).is_err(),
        "a tampered response vector still verified"
    );
}

/// SAAP-SPEC.md §7 step 3 requires the Fiat-Shamir challenge to bind the
/// disclosed attribute values:
///
/// ```text
/// c' = Hash(W_1' ∥ W_2' ∥ b_τ ∥ t_blind ∥ m_pub ∥ τ)
/// ```
///
/// `recompute_challenge` hashes only `(commitment_w, τ, disclosure_mask)`. The
/// disclosed values ride in the transcript as `proof.attributes` and never enter
/// the challenge, so they can be rewritten after the fact.
///
/// This is a gap in the corrected verifier too — fixing the verification
/// equation did not fix attribute binding, because the two are independent.
#[test]
fn disclosed_attributes_are_bound_into_the_challenge() {
    let sk = test_secret_key();
    let mut proof = saap::saap_prove(CREDENTIAL, 0b0000_0011, TAU, &sk);
    let public_key = saap::saap_public_key(TAU, &sk);

    // Sanity: the untampered proof verifies.
    assert_eq!(
        saap::verify_saap_proof_against(&proof, TAU, &public_key),
        Ok(()),
        "test setup: the honest proof should verify before tampering"
    );

    // Rewrite a disclosed attribute value. Nothing else is touched.
    let original = proof.attributes.values[0];
    proof.attributes.values[0] = original.wrapping_add(0xDEAD_BEEF);

    assert!(
        saap::verify_saap_proof_against(&proof, TAU, &public_key).is_err(),
        "a disclosed attribute value was rewritten after proof generation and the \
         proof still verified. SAAP-SPEC.md §7 step 3 binds m_pub into the \
         challenge; recompute_challenge does not. The verifier therefore attests \
         to attribute values the prover never committed to, which is the property \
         SAAP exists to provide."
    );
}

/// Same construction as `forge`, parameterised by τ so it can be aimed at the
/// corrected verifier.
fn forge_for(tau: &[u8], disclosure_mask: u64) -> SaapProof {
    let mut context_tag = [0u8; 32];
    let len = tau.len().min(32);
    context_tag[..len].copy_from_slice(&tau[..len]);
    forge(context_tag, disclosure_mask)
}

/// Characterises the second defect in the deprecated verifier: it takes no
/// caller-supplied τ at all, so a proof certifies its own context. Asserted as
/// known-bad for the same reason as above.
#[test]
#[allow(deprecated)]
fn deprecated_verifier_is_self_certifying_known_defect() {
    let matrix_a = [VectorK::zero(); saap::MODULE_K];
    let attr_commits = [Polynomial::zero(); saap::MAX_ATTRIBUTES];

    let proof = forge([0xAAu8; 32], 0b0000_0001);

    assert!(
        verify_saap_proof(&proof, &matrix_a, &attr_commits).is_ok(),
        "the deprecated verifier has no τ parameter, so it cannot answer 'is this \
         valid for MY context?' — it accepts whatever context the proof asserts \
         about itself. The WIT world declares \
         saap-verify(proof, tau) -> result<bool, identity-error>."
    );
}
