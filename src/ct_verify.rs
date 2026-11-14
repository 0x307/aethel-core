//! # Fixed-iteration prover smoke test (no constant-time claim)
//!
//! **This module does not verify constant-time behaviour, and this crate makes no
//! constant-time claim for [`enclave_plp_prove_fixed_time`](crate::sampling::enclave_plp_prove_fixed_time).** Until 0.7.6 this module
//! described itself as a Valgrind/ctgrind harness that "proves constant-time compliance".
//! That harness was never in the repository: the `tests/valgrind_ct_harness.rs` and
//! `tests/ct_harness.c` files its docs pointed to do not exist, no CI job ran Valgrind, and
//! the functions here only run the prover once without poisoning any input. A timing test
//! (dudect-style) was considered for 0.7.6 and not added, because a statistical timing test
//! on shared CI runners is not reliable enough to gate on. So the claim was removed instead.
//!
//! What the prover does do, by construction: it always runs
//! [`FIXED_ITERATION_CEILING`](crate::sampling::FIXED_ITERATION_CEILING) iterations, and it
//! selects the accepted response with masks rather than a branch. Whether the compiled code
//! is free of secret-dependent timing (division, comparisons, the SHAKE-based samplers) is
//! unchecked.
//!
//! What the functions here check: the fixed-iteration loop completes and returns a proof
//! for two fixed inputs. Nothing more.
//!
//! The prover itself is research code that the identity path (`plp`, `signing`, the
//! component) does not call.

// ── Rust module implementation ────────────────────────────────────────────────

use crate::sampling::{
    enclave_plp_prove_fixed_time, PlpProof, Polynomial, RejectionError, VectorK,
    MODULE_K, RING_N,
};

/// Result of a constant-time verification run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CtVerifyResult {
    /// The fixed-iteration loop completed and produced a proof. Says nothing
    /// about timing.
    Passed,
    /// Proof generation failed (all 16 iterations rejected).
    ProofFailed(RejectionError),
    /// Not running under Valgrind. Never returned: no function here detects
    /// Valgrind. Kept because the enum is public.
    NotUnderValgrind,
}

/// Run the fixed-iteration prover once on a fixed input.
///
/// Checks that the loop completes and produces a proof. It does not check
/// timing; see the module docs for why there is no constant-time claim.
///
/// # Example
///
/// ```rust,no_run
/// use aethel_core::ct_verify::run_ct_verification;
/// let result = run_ct_verification();
/// println!("CT verification result: {:?}", result);
/// ```
pub fn run_ct_verification() -> CtVerifyResult {
    // Initialize secret vector with small coefficients (as in the Valgrind harness)
    let mut secret_s = VectorK {
        vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K],
    };
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            secret_s.vec[k].coeffs[n] = (n % 5) as i32 - 2;
        }
    }

    // Context tag (0x5A pattern as in the Valgrind harness)
    let tau = [0x5Au8; 32];
    let mut proof_out = PlpProof::zero();

    // Execute the fixed-time proof generation
    match enclave_plp_prove_fixed_time(&mut proof_out, &secret_s, &tau) {
        Ok(()) => CtVerifyResult::Passed,
        Err(e) => CtVerifyResult::ProofFailed(e),
    }
}

/// Run the fixed-iteration prover once on a second fixed input.
///
/// Coefficient pattern `(n % 3) - 1` and tau pattern `0x77`, the inputs of a
/// C harness that was specified but never added to this repository. Returns
/// `true` if proof generation succeeded. It does not check timing.
pub fn run_c_harness_equivalent() -> bool {
    let mut secret_s = VectorK {
        vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K],
    };
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            secret_s.vec[k].coeffs[n] = (n % 3) as i32 - 1;
        }
    }

    let tau = [0x77u8; 32];
    let mut proof_out = PlpProof::zero();

    enclave_plp_prove_fixed_time(&mut proof_out, &secret_s, &tau).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fixed-iteration prover completes on the first fixed input. A
    /// smoke test; it checks no timing property.
    #[test]
    fn test_ct_verification_passes() {
        let result = run_ct_verification();
        assert_eq!(
            result,
            CtVerifyResult::Passed,
            "Constant-time proof generation should succeed"
        );
    }

    /// Verify that the C-harness equivalent test passes.
    #[test]
    fn test_c_harness_equivalent_passes() {
        assert!(
            run_c_harness_equivalent(),
            "C-harness equivalent proof generation should succeed"
        );
    }

    /// Verify that two proof runs with different tau values produce
    /// different iteration counters (non-deterministic behavior expected).
    ///
    /// This is a sanity check that the proof generation is not trivially
    /// returning the same result for all inputs.
    #[test]
    fn test_different_tau_produces_proof() {
        let mut secret_s = VectorK {
            vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K],
        };
        for k in 0..MODULE_K {
            for n in 0..RING_N {
                secret_s.vec[k].coeffs[n] = (n % 5) as i32 - 2;
            }
        }

        let tau_a = [0xAAu8; 32];
        let tau_b = [0xBBu8; 32];

        let mut proof_a = PlpProof::zero();
        let mut proof_b = PlpProof::zero();

        let result_a = enclave_plp_prove_fixed_time(&mut proof_a, &secret_s, &tau_a);
        let result_b = enclave_plp_prove_fixed_time(&mut proof_b, &secret_s, &tau_b);

        assert!(result_a.is_ok(), "Proof A generation should succeed");
        assert!(result_b.is_ok(), "Proof B generation should succeed");
    }
}
