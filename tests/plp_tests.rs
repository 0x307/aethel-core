//! # aethel-core Integration Tests — PLP, HTSS, SAAP, Sampling
//!
//! This test file provides the integration test suite for the `aethel-core` crate.
//! Tests cover the full lifecycle of the Polymorphic Lattice Projection (PLP)
//! engine, HTSS routing, SAAP verification, and constant-time sampling.
//!
//! ## Test Categories
//!
//! 1. **Key Generation** — Master identity creation and secret key properties
//! 2. **Identifier Generation** — Ephemeral projection generation and unlinkability
//! 3. **Unlinkability Check** — Cross-context projection independence
//! 4. **SAAP Round-Trip** — Issue → Prove → Verify full protocol flow
//! 5. **HTSS Routing** — 5D hypercube secret sharing and reconstruction
//! 6. **Sampling** — Constant-time rejection sampling and CBD η=2 sampler
//! 7. **Norm Bounds** — Rejection bound enforcement

use aethel_core::plp::{MasterIdentity, Prover, Verifier};
use aethel_core::htss::{HypercubeNetwork, NodeAddress, SecretSharer};
use aethel_core::sampling::{
    ct_check_norm_bound, enclave_explicit_zeroize, enclave_plp_prove_fixed_time,
    PlpProof, Polynomial, VectorK,
    FIXED_ITERATION_CEILING, MODULE_K, REJECTION_BOUND, RING_N,
};
use aethel_core::saap::{
    verify_saap_proof, saap_prove, SaapProof, SaapValidationError,
    MAX_ATTRIBUTES, VectorK as SaapVectorK, Polynomial as SaapPoly,
};

// ── Test helpers ──────────────────────────────────────────────────────────────

/// Fixed test seed for deterministic tests.
fn test_seed() -> [u8; 32] {
    [0x42u8; 32]
}

// ── 1. Key Generation Tests ───────────────────────────────────────────────────
//
// `MasterIdentity.secret_key` is a private field (P3-03) — external code, this
// integration test suite included, can no longer read it directly. Secret-key
// property tests (non-zero, in-range, uniqueness across identities) moved into
// `src/plp.rs`'s own internal `#[cfg(test)]` module, which still has access.
// See `test_key_generation` / `test_key_generation_uniqueness` there.

// ── 2. Identifier Generation Tests ───────────────────────────────────────────

/// Verify that an ephemeral projection can be generated for a given context.
#[test]
fn test_identifier_generation() {
    let seed = test_seed();
    let identity = MasterIdentity::from_seed(&seed);
    let tau = b"block_1000";
    let proj = identity.project_at_context(tau, &[0xa5u8; 32]);

    // Public projection b_τ should be non-zero
    let b_all_zero = proj.public_b.coeffs().iter().all(|&c| c == 0);
    assert!(!b_all_zero, "Public projection b_τ should not be all-zero");

    // Context matrix A_τ should be non-zero
    let a_all_zero = proj.matrix_a.coeffs().iter().all(|&c| c == 0);
    assert!(!a_all_zero, "Context matrix A_τ should not be all-zero");
}

/// Verify that a ZK identity proof can be generated and verified successfully.
#[test]
fn test_proof_generation_and_verification() {
    let seed = test_seed();
    let identity = MasterIdentity::from_seed(&seed);
    let tau = b"block_42";
    let proj = identity.project_at_context(tau, &[0xa5u8; 32]);
    let proof = Prover::prove_identity(&identity, &proj, &seed);

    // Proof response norm should be within rejection bound
    let norm = proof.response_z.infinity_norm();
    assert!(
        norm < (131_072 - 78),
        "Response norm {} should be < GAMMA1 - BETA = {}",
        norm,
        131_072 - 78
    );

    // Verifier should accept the proof
    let valid = Verifier::verify(&proj, &proof);
    assert!(valid, "Verifier should accept a valid PLP proof");
}

// ── 3. Unlinkability Check Tests ──────────────────────────────────────────────

/// Verify that projections for different contexts are unlinkable.
#[test]
fn test_cross_context_unlinkability() {
    let seed = test_seed();
    let identity = MasterIdentity::from_seed(&seed);

    let proj_1 = identity.project_at_context(b"context_1000", &[0xa5u8; 32]);
    let proj_2 = identity.project_at_context(b"context_1001", &[0xa5u8; 32]);

    // The two public projections should differ
    let projections_equal = proj_1
        .public_b
        .coeffs()
        .iter()
        .zip(proj_2.public_b.coeffs().iter())
        .all(|(a, b)| a == b);

    assert!(
        !projections_equal,
        "Projections for different contexts should differ (unlinkability)"
    );

    // The two context matrices should differ
    let matrices_equal = proj_1
        .matrix_a
        .coeffs()
        .iter()
        .zip(proj_2.matrix_a.coeffs().iter())
        .all(|(a, b)| a == b);

    assert!(
        !matrices_equal,
        "Context matrices for different contexts should differ"
    );
}

/// Verify that a proof generated for context τ₁ is rejected for context τ₂.
#[test]
fn test_cross_block_replay_rejected() {
    let seed = test_seed();
    let identity = MasterIdentity::from_seed(&seed);

    let proj_1 = identity.project_at_context(b"context_1000", &[0xa5u8; 32]);
    let proj_2 = identity.project_at_context(b"context_1001", &[0xa5u8; 32]);

    // Generate proof for context 1
    let proof_1 = Prover::prove_identity(&identity, &proj_1, &seed);

    // Proof for context 1 should be ACCEPTED for context 1
    assert!(
        Verifier::verify(&proj_1, &proof_1),
        "Proof should be accepted for its own context"
    );

    // Proof for context 1 should be REJECTED for context 2
    let cross_valid = Verifier::verify(&proj_2, &proof_1);
    assert!(
        !cross_valid,
        "Cross-context replay attack should be rejected (SECURE)"
    );
}

/// Verify that the same context always produces the same A_τ matrix.
#[test]
fn test_deterministic_context_matrix() {
    let seed = test_seed();
    let identity = MasterIdentity::from_seed(&seed);

    let tau = b"deterministic_context_9999";
    let proj_a = identity.project_at_context(tau, &[0xa5u8; 32]);
    let proj_b = identity.project_at_context(tau, &[0xa5u8; 32]);

    // A_τ must be identical for the same context
    let matrices_equal = proj_a
        .matrix_a
        .coeffs()
        .iter()
        .zip(proj_b.matrix_a.coeffs().iter())
        .all(|(a, b)| a == b);

    assert!(
        matrices_equal,
        "Context matrix A_τ must be deterministic for the same context"
    );
}

// ── 4. SAAP Issue/Prove/Verify Round-Trip Tests ───────────────────────────────

/// Verify that the SAAP prover produces a proof that passes norm check.
#[test]
fn test_saap_prove_norm_bound() {
    let mut sk = SaapVectorK::zero();
    for k in 0..aethel_core::saap::MODULE_K {
        for n in 0..aethel_core::saap::RING_N {
            sk.vec[k].coeffs[n] = (n % 5) as i32 - 2;
        }
    }
    let credential = [0u8; 64];
    let disclosure_mask = 0b00001111u64;
    let tau = b"test_saap_context";

    let proof = saap_prove(&credential, disclosure_mask, tau, &sk, &[0x7cu8; 32]);

    // Norm bound check
    let norm_result = aethel_core::saap::verify_response_norm(&proof.z);
    assert_eq!(norm_result, 0, "SAAP response norm should be within bound");
}

/// Verify that the SAAP verifier accepts a well-formed proof.
#[test]
fn test_saap_prove_verify_roundtrip() {
    let mut sk = SaapVectorK::zero();
    for k in 0..aethel_core::saap::MODULE_K {
        for n in 0..aethel_core::saap::RING_N {
            sk.vec[k].coeffs[n] = (n % 5) as i32 - 2;
        }
    }
    let credential = [0u8; 64];
    let disclosure_mask = 0b00001111u64;
    let tau = b"test_saap_context_verify";

    let proof = saap_prove(&credential, disclosure_mask, tau, &sk, &[0x7cu8; 32]);

    // Build dummy matrix and attribute commitments
    let matrix_a = [SaapVectorK::zero(); aethel_core::saap::MODULE_K];
    let attr_commits = [SaapPoly::zero(); MAX_ATTRIBUTES];

    let result = verify_saap_proof(&proof, &matrix_a, &attr_commits);
    assert!(result.is_ok(), "SAAP verify should accept valid proof: {:?}", result);
}

/// Verify that the SAAP verifier rejects a proof with an out-of-bounds response norm.
#[test]
fn test_saap_verify_rejects_invalid_norm() {
    let mut proof = SaapProof::zero();
    // Set a coefficient way out of bounds
    proof.z.vec[0].coeffs[0] = aethel_core::saap::REJECTION_BOUND + 1000;

    let matrix_a = [SaapVectorK::zero(); aethel_core::saap::MODULE_K];
    let attr_commits = [SaapPoly::zero(); MAX_ATTRIBUTES];

    let result = verify_saap_proof(&proof, &matrix_a, &attr_commits);
    assert_eq!(
        result,
        Err(SaapValidationError::NormBoundViolation),
        "Should reject proof with out-of-bounds norm"
    );
}

// ── 5. HTSS Routing Tests ─────────────────────────────────────────────────────

/// Verify that Shamir 3-of-5 secret sharing splits and reconstructs correctly.
#[test]
fn test_htss_secret_sharing_roundtrip() {
    let original_secret: u64 = 5_234_123;
    let seed: u64 = 0xdeadbeef_cafebabe;

    let shares = SecretSharer::split_secret(original_secret, 3, 5, seed);
    assert_eq!(shares.len(), 5, "Should produce exactly 5 shares");

    // Reconstruct from first 3 shares
    let reconstructed = SecretSharer::reconstruct_secret(&shares[0..3]);
    assert_eq!(
        reconstructed, original_secret,
        "Reconstructed secret should match original"
    );

    // Reconstruct from last 3 shares
    let reconstructed_alt = SecretSharer::reconstruct_secret(&shares[2..5]);
    assert_eq!(
        reconstructed_alt, original_secret,
        "Reconstruction from different 3 shares should also match"
    );
}

/// Verify that the 5D hypercube routes all 5 shares from node 0 to node 31.
#[test]
fn test_htss_hypercube_routing() {
    let network = HypercubeNetwork::new();

    let prover_node = NodeAddress(0b00000);   // Node 0
    let verifier_node = NodeAddress(0b11111); // Node 31

    // Secret must be < MODULUS_Q = 8_380_417
    let original_scalar: u64 = 1_234_567;
    let seed: u64 = 0x1234567890abcdef;
    let shares = SecretSharer::split_secret(original_scalar, 3, 5, seed);

    let delivered = network.route_payload_shares(prover_node, verifier_node, &shares);
    assert_eq!(delivered.len(), 5, "All 5 packets should be delivered");

    // All packets should arrive at the destination
    for pkt in &delivered {
        assert_eq!(
            pkt.current_node, verifier_node,
            "All packets should arrive at verifier node 31"
        );
    }

    // Reconstruct from first 3 delivered shares
    let received: Vec<(u8, u64)> = delivered[0..3]
        .iter()
        .map(|p| (p.payload.share_id, p.payload.share_val))
        .collect();

    let reconstructed = SecretSharer::reconstruct_secret(&received);
    assert_eq!(
        reconstructed, original_scalar,
        "Reconstructed scalar should match original after 5D routing"
    );
}

/// Verify that NodeAddress neighbor computation is correct.
#[test]
fn test_node_address_neighbor() {
    let node = NodeAddress(0b00000);

    assert_eq!(node.neighbor(0), NodeAddress(0b00001));
    assert_eq!(node.neighbor(4), NodeAddress(0b10000));

    assert_eq!(
        node.hamming_distance(&NodeAddress(0b11111)),
        5,
        "Hamming distance from node 0 to node 31 should be 5"
    );
}

// ── 6. Sampling Tests ─────────────────────────────────────────────────────────

/// Verify that the constant-time norm bound check correctly identifies violations.
#[test]
fn test_ct_norm_bound_check() {
    // All-zero vector should pass
    let zero_vec = VectorK {
        vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K],
    };
    let result = ct_check_norm_bound(&zero_vec, REJECTION_BOUND);
    assert_eq!(result, 0, "All-zero vector should pass norm check");

    // Vector with a coefficient at REJECTION_BOUND should fail
    let mut bad_vec = VectorK {
        vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K],
    };
    bad_vec.vec[0].coeffs[0] = REJECTION_BOUND;
    let result = ct_check_norm_bound(&bad_vec, REJECTION_BOUND);
    assert_ne!(result, 0, "Vector at REJECTION_BOUND should fail norm check");

    // Vector with a coefficient just below REJECTION_BOUND should pass
    let mut ok_vec = VectorK {
        vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K],
    };
    ok_vec.vec[0].coeffs[0] = REJECTION_BOUND - 1;
    let result = ct_check_norm_bound(&ok_vec, REJECTION_BOUND);
    assert_eq!(
        result, 0,
        "Vector just below REJECTION_BOUND should pass norm check"
    );
}

/// Verify that the fixed-iteration enclave proof generation completes successfully.
#[test]
fn test_enclave_fixed_iteration_proof() {
    let mut secret_s = VectorK {
        vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K],
    };
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            secret_s.vec[k].coeffs[n] = (n % 5) as i32 - 2;
        }
    }

    let tau = [0x5Au8; 32];
    let mut proof_out = PlpProof::zero();

    let result = enclave_plp_prove_fixed_time(&mut proof_out, &secret_s, &tau);
    assert!(
        result.is_ok(),
        "Fixed-iteration proof generation should succeed: {:?}",
        result
    );

    // Iteration counter should be within [0, FIXED_ITERATION_CEILING)
    assert!(
        proof_out.iteration_counter < FIXED_ITERATION_CEILING as u32,
        "Iteration counter {} should be < {}",
        proof_out.iteration_counter,
        FIXED_ITERATION_CEILING
    );
}

/// Verify that explicit zeroization clears all bytes of a proof structure.
#[test]
fn test_explicit_zeroize() {
    let mut proof = PlpProof::zero();

    // Fill with non-zero data
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            proof.z.vec[k].coeffs[n] = 0x5A5A5A5A_u32 as i32;
        }
    }
    proof.iteration_counter = 0xDEADBEEF;

    // Zeroize
    enclave_explicit_zeroize(&mut proof);

    // All coefficients should be zero
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            assert_eq!(
                proof.z.vec[k].coeffs[n], 0,
                "Coefficient [{k}][{n}] should be zero after zeroization"
            );
        }
    }
    assert_eq!(
        proof.iteration_counter, 0,
        "Iteration counter should be zero after zeroization"
    );
}

// ── 7. Norm Bounds Tests ──────────────────────────────────────────────────────

/// Verify that all generated PLP proofs satisfy the rejection bound.
#[test]
fn test_proof_norm_bounds_satisfied() {
    let seed = test_seed();
    let identity = MasterIdentity::from_seed(&seed);

    for i in 0u8..5 {
        let tau = [i; 32];
        let proj = identity.project_at_context(&tau, &[0xa5u8; 32]);
        let proof = Prover::prove_identity(&identity, &proj, &seed);

        let norm = proof.response_z.infinity_norm();
        assert!(
            norm < (131_072 - 78),
            "Proof {} response norm {} should be < GAMMA1 - BETA = {}",
            i,
            norm,
            131_072 - 78
        );
    }
}

// `test_tampered_proof_rejected` moved to `src/plp.rs`'s internal
// `#[cfg(test)]` module (P3-03): it mutates `proof.response_z.coeffs[0]`
// directly, and `Poly.coeffs` is a private field now — only crate-internal
// code can still reach it.
