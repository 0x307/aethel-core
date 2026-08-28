//! PLP `e_τ` and SAAP `r` are per-call secret randomness.
//!
//! Both are seeded from a caller-supplied `rho` that must be fresh, secret
//! entropy sampled anew per operation. These tests assert the properties that
//! guarantee gives: fresh randomness produces fresh outputs (each projection is
//! its own single-use M-LWE sample, each proof its own independent mask), and
//! the same randomness reproduces the same output (so a holder can recompute its
//! projection without storing it, and the scheme stays testable).

use aethel_core::plp::MasterIdentity;
use aethel_core::saap::{self, VectorK};

// Distinct fixed rho per logical session. Real callers MUST sample these
// freshly; the tests fix them only to be reproducible.
const RHO_A: [u8; 32] = [0x11u8; 32];
const RHO_B: [u8; 32] = [0x22u8; 32];

// ── PLP ──────────────────────────────────────────────────────────────────────

/// Fresh randomness changes the projection; the same randomness reproduces it.
/// `A_τ` depends only on τ, so it is stable across `rho`.
#[test]
fn plp_projection_is_fresh_per_rho_and_reproducible_given_rho() {
    let identity = MasterIdentity::from_seed(&[0x42u8; 32]);
    let tau = b"context-block-height-1000";

    let p_a1 = identity.project_at_context(tau, &RHO_A);
    let p_a2 = identity.project_at_context(tau, &RHO_A);
    let p_b = identity.project_at_context(tau, &RHO_B);

    assert_eq!(
        p_a1.public_b.coeffs(),
        p_a2.public_b.coeffs(),
        "same rho must reproduce the same projection"
    );
    assert_ne!(
        p_a1.public_b.coeffs(),
        p_b.public_b.coeffs(),
        "different rho must change the projection — e_τ carries per-call entropy"
    );
    assert_eq!(
        p_a1.matrix_a.coeffs(),
        p_b.matrix_a.coeffs(),
        "A_τ depends only on τ and is unchanged by rho"
    );
}

/// Two distinct identities produce distinct projections under one τ — the
/// projection is bound to the secret, not just to the public context.
#[test]
fn plp_projections_are_identity_bound() {
    let tau = b"context-block-height-1000";
    let a = MasterIdentity::from_seed(&[0x01u8; 32]).project_at_context(tau, &RHO_A);
    let b = MasterIdentity::from_seed(&[0x02u8; 32]).project_at_context(tau, &RHO_A);
    assert_ne!(
        a.public_b.coeffs(),
        b.public_b.coeffs(),
        "distinct identities must not share a projection"
    );
}

// ── SAAP ─────────────────────────────────────────────────────────────────────

fn test_sk() -> VectorK {
    let mut sk = VectorK::zero();
    for k in 0..saap::MODULE_K {
        for n in 0..saap::RING_N {
            sk.vec[k].coeffs[n] = ((k * 31 + n * 7) % 5) as i32 - 2;
        }
    }
    sk
}

/// Fresh randomness changes the proof commitment; the same randomness reproduces
/// it. The commitment `w = A·r` moves with `r`, so it carries per-call entropy.
#[test]
fn saap_mask_is_fresh_per_rho_and_reproducible_given_rho() {
    let sk = test_sk();
    let credential: Vec<u8> = (0u8..64).collect();
    let tau = b"verifier-session-tau-0001";

    let p_a1 = saap::saap_prove(&credential, 0b0000_0011, tau, &sk, &RHO_A);
    let p_a2 = saap::saap_prove(&credential, 0b0000_0011, tau, &sk, &RHO_A);
    let p_b = saap::saap_prove(&credential, 0b0000_0011, tau, &sk, &RHO_B);

    let commitments_equal = |x: &saap::SaapProof, y: &saap::SaapProof| {
        (0..saap::MODULE_K).all(|i| {
            (0..saap::RING_N).all(|n| x.commitment_w.vec[i].coeffs[n] == y.commitment_w.vec[i].coeffs[n])
        })
    };

    assert!(
        commitments_equal(&p_a1, &p_a2),
        "same rho must reproduce the same commitment"
    );
    assert!(
        !commitments_equal(&p_a1, &p_b),
        "different rho must change the commitment — r carries per-call entropy"
    );
}

/// Proofs of one credential under one τ disclosing different attribute sets,
/// each with its own fresh `rho`, carry independent masks — their commitments
/// differ, so nothing links the two presentations through a shared mask.
#[test]
fn saap_distinct_rho_gives_distinct_masks_across_disclosures() {
    let sk = test_sk();
    let credential: Vec<u8> = (0u8..64).collect();
    let tau = b"verifier-session-tau-0001";

    let p1 = saap::saap_prove(&credential, 0b0000_0001, tau, &sk, &RHO_A);
    let p2 = saap::saap_prove(&credential, 0b0000_0010, tau, &sk, &RHO_B);

    let mut any_diff = false;
    for i in 0..saap::MODULE_K {
        for n in 0..saap::RING_N {
            if p1.commitment_w.vec[i].coeffs[n] != p2.commitment_w.vec[i].coeffs[n] {
                any_diff = true;
            }
        }
    }
    assert!(
        any_diff,
        "commitments must differ across proofs — masks are independent per rho"
    );
}
