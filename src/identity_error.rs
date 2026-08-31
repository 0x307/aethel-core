//! Rust-side mirror of the `identity-error` variant defined in the
//! `aethel:core` WIT world ([`wit/aethel-core.wit`](../../wit/aethel-core.wit)).
//!
//! Kept as one flat, closed set — not a hierarchy — matching the WIT design.
//!
//! # Which variants a caller can actually observe
//!
//! Five of the eight are reachable through the component today, and are driven
//! end-to-end by tests in `tests/component_execution.rs`:
//! `InvalidInputLength`, `SerializationError`, `ThresholdNotMet`,
//! `RejectionSamplingFailed`, and `InvalidShareSet`.
//!
//! Three are **reserved and currently unreachable**: [`Self::NormBoundViolation`],
//! [`Self::ChallengeMismatch`] and [`Self::InvalidAttributeCommitment`]. They
//! are named here deliberately rather than removed — see their individual doc
//! comments and `component_error_variant_reachability` in
//! `tests/component_execution.rs`, which pins the split so it cannot drift
//! silently.
//!
//! `RejectionSamplingFailed` is reachable but not forceable from outside: it
//! needs all 16 rejection-sampling iterations to fail, which is negligible for
//! honest parameters. It is exercised natively instead.

use crate::sampling::RejectionError;
use crate::saap::SaapValidationError;

/// Closed set of failure reasons across all `aethel:core` WIT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityError {
    /// A byte-slice input was too short or malformed for the operation.
    InvalidInputLength,
    /// Serialization or deserialization of a proof/projection failed.
    SerializationError,
    /// Rejection sampling exhausted its fixed iteration ceiling.
    RejectionSamplingFailed,
    /// A response vector's infinity norm exceeded the rejection bound.
    ///
    /// **Reserved, no producer today.** Reachable only through the superseded
    /// `saap` verifier, which is crate-private and not exported by the
    /// component. `saap-verify-presentation` reports a well-formed proof that
    /// does not verify as `ok(false)`, never as an error, because "this does
    /// not verify" is a verdict and not a failure to reach one.
    ///
    /// Kept for the predicate relation (RFC §5.6 relation 3), which is
    /// deliberately deferred and will need to distinguish a range proof whose
    /// response is out of bounds from one that simply does not hold.
    NormBoundViolation,
    /// A recomputed Fiat-Shamir challenge did not match the proof's challenge.
    ///
    /// **Reserved, no producer today.** Same reasoning as
    /// [`Self::NormBoundViolation`].
    ChallengeMismatch,
    /// A disclosed attribute did not match its vector commitment.
    ///
    /// **Reserved, no producer today.** Same reasoning as
    /// [`Self::NormBoundViolation`].
    InvalidAttributeCommitment,
    /// Fewer than the threshold number of shares were supplied for reconstruction.
    ThresholdNotMet,
    /// The supplied shares are not a valid share set: an evaluation index
    /// appears more than once, or more shares were supplied than the scheme
    /// issues.
    ///
    /// Distinct from [`Self::SerializationError`] on purpose. "This share is
    /// malformed" and "you sent the same share twice" are different failures
    /// with different fixes, and collapsing them is the same sentinel-flattening
    /// this crate treats as a defect class elsewhere. Lagrange interpolation
    /// over a repeated evaluation point is undefined; a share set carrying one
    /// does not reconstruct to the shared secret, so it must not reconstruct at
    /// all.
    InvalidShareSet,
}

impl From<SaapValidationError> for IdentityError {
    fn from(e: SaapValidationError) -> Self {
        match e {
            SaapValidationError::NormBoundViolation => IdentityError::NormBoundViolation,
            SaapValidationError::ChallengeMismatch => IdentityError::ChallengeMismatch,
            SaapValidationError::InvalidAttributeCommitment => {
                IdentityError::InvalidAttributeCommitment
            }
        }
    }
}

impl From<RejectionError> for IdentityError {
    fn from(e: RejectionError) -> Self {
        match e {
            RejectionError::AllIterationsRejected => IdentityError::RejectionSamplingFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::htss::SecretSharer;
    use crate::plp::{checked_project_at_context, EphemeralProjection};

    #[test]
    fn every_saap_validation_error_maps() {
        assert_eq!(
            IdentityError::from(SaapValidationError::NormBoundViolation),
            IdentityError::NormBoundViolation
        );
        assert_eq!(
            IdentityError::from(SaapValidationError::ChallengeMismatch),
            IdentityError::ChallengeMismatch
        );
        assert_eq!(
            IdentityError::from(SaapValidationError::InvalidAttributeCommitment),
            IdentityError::InvalidAttributeCommitment
        );
    }

    #[test]
    fn rejection_sampling_failure_maps() {
        assert_eq!(
            IdentityError::from(RejectionError::AllIterationsRejected),
            IdentityError::RejectionSamplingFailed
        );
    }

    // ── InvalidInputLength: driven through checked_project_at_context ──────────

    // Fresh per-projection randomness for the error term e_τ. In tests a fixed
    // 32-byte value is fine; in production this MUST be freshly sampled.
    const RHO: [u8; 32] = [0x5au8; 32];

    #[test]
    fn invalid_input_length_from_a_short_secret() {
        // One byte short of the required 32-byte seed (randomness is valid, so
        // the failure is unambiguously about the secret length).
        let short_secret = [0u8; 31];
        let result = checked_project_at_context(&short_secret, b"context", &RHO);
        assert_eq!(result.err(), Some(IdentityError::InvalidInputLength));
    }

    #[test]
    fn invalid_input_length_from_short_randomness() {
        // A valid secret but under-length randomness must also be rejected:
        // silently proceeding would seed e_τ from too little entropy.
        let secret = [0x42u8; 32];
        let short_rho = [0u8; 31];
        let result = checked_project_at_context(&secret, b"context", &short_rho);
        assert_eq!(result.err(), Some(IdentityError::InvalidInputLength));
    }

    #[test]
    fn checked_project_at_context_succeeds_with_a_valid_secret() {
        // The validation isn't just rejecting everything — a correctly-sized
        // secret and randomness must actually produce a projection.
        let secret = [0x42u8; 32];
        assert!(checked_project_at_context(&secret, b"context", &RHO).is_ok());
    }

    // ── SerializationError: driven through EphemeralProjection::from_bytes ─────

    #[test]
    fn serialization_error_from_truncated_projection_bytes() {
        let truncated = [0u8; 10];
        let result = EphemeralProjection::from_bytes(&truncated);
        assert_eq!(result.err(), Some(IdentityError::SerializationError));
    }

    #[test]
    fn ephemeral_projection_round_trips_through_bytes() {
        let secret = [0x99u8; 32];
        let projection = checked_project_at_context(&secret, b"round-trip", &RHO).unwrap();
        let bytes = projection.to_bytes();
        let decoded =
            EphemeralProjection::from_bytes(&bytes).expect("well-formed bytes must decode");
        assert_eq!(decoded.tau, projection.tau);
        assert_eq!(decoded.matrix_a.coeffs, projection.matrix_a.coeffs);
        assert_eq!(decoded.public_b.coeffs, projection.public_b.coeffs);
    }

    // ── ThresholdNotMet: driven through SecretSharer::reconstruct_secret_checked ─

    #[test]
    fn threshold_not_met_with_fewer_than_three_shares() {
        let shares = SecretSharer::split_secret(12_345u64, 3, 5, 0xdead_beef);
        let result = SecretSharer::reconstruct_secret_checked(&shares[0..2]);
        assert_eq!(result.err(), Some(IdentityError::ThresholdNotMet));
    }

    #[test]
    fn reconstruct_secret_checked_succeeds_at_the_threshold() {
        let secret = 12_345u64;
        let shares = SecretSharer::split_secret(secret, 3, 5, 0xdead_beef);
        let result = SecretSharer::reconstruct_secret_checked(&shares[0..3]);
        assert_eq!(result, Ok(secret));
    }
}
