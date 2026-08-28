//! HTSS key-material tests (P3-12 / 0X3-80).
//!
//! The WIT world declares:
//!
//! ```text
//! htss-split:       func(secret: list<u8>) -> result<list<htss-share>, identity-error>
//! htss-reconstruct: func(shares: list<htss-share>) -> result<list<u8>, identity-error>
//! ```
//!
//! P3-01's Do list said "HTSS operates over real key material, not a `u64`". The
//! WIT was changed; the Shamir implementation was not, and the gap turned out to
//! include a break of the threshold property itself.
//!
//! The `deprecated_*` tests characterise the old behaviour so it is pinned in
//! executable form rather than described. Everything else asserts the new path.

use aethel_core::htss::{HtssShare, SecretSharer};
use aethel_core::identity_error::IdentityError;

const NONCE: &[u8] = b"session-nonce-01";

// ── The sound path ────────────────────────────────────────────────────────────

/// The AC from P3-10: a 32-byte secret splits, recombines at threshold, and
/// compares byte-equal to the input.
#[test]
fn key_material_round_trips_byte_for_byte() {
    let key = [0xA5u8; 32];

    let shares = SecretSharer::split_key_material(&key, NONCE).expect("split");
    assert_eq!(shares.len(), 5, "expected a 3-of-5 split");

    let recovered = SecretSharer::reconstruct_key_material(&shares[..3]).expect("reconstruct");

    assert_eq!(recovered, key, "32 bytes of key material did not survive the round trip");
}

/// Any three of the five shares must work, not just the first three.
#[test]
fn any_three_shares_reconstruct() {
    let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let shares = SecretSharer::split_key_material(&key, NONCE).expect("split");

    for combo in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
        let subset: Vec<HtssShare> = combo.iter().map(|&i| shares[i].clone()).collect();
        let recovered = SecretSharer::reconstruct_key_material(&subset)
            .unwrap_or_else(|e| panic!("shares {:?} failed to reconstruct: {:?}", combo, e));
        assert_eq!(recovered, key, "shares {:?} reconstructed the wrong secret", combo);
    }
}

/// Below threshold is an error, not a wrong answer. The old `u64` path returned
/// `0`, which collides with a legitimate zero secret.
#[test]
fn below_threshold_is_an_error_not_a_zero() {
    let key = [0x11u8; 32];
    let shares = SecretSharer::split_key_material(&key, NONCE).expect("split");

    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..2]),
        Err(IdentityError::ThresholdNotMet),
        "two shares of a 3-of-5 split must return ThresholdNotMet"
    );
    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..1]),
        Err(IdentityError::ThresholdNotMet)
    );
}

/// Losing one share above the threshold must not lose the identity.
#[test]
fn losing_one_share_does_not_lose_the_secret() {
    let key = [0x5Cu8; 32];
    let shares = SecretSharer::split_key_material(&key, NONCE).expect("split");

    let survivors: Vec<HtssShare> = shares.iter().skip(1).cloned().collect();
    assert_eq!(survivors.len(), 4);

    let recovered = SecretSharer::reconstruct_key_material(&survivors).expect("reconstruct");
    assert_eq!(recovered, key);
}

/// Secrets that are not a whole number of limbs must round-trip exactly, with
/// no trailing padding bytes.
#[test]
fn odd_length_secrets_round_trip_without_padding() {
    for len in [1usize, 7, 15, 31, 33] {
        let secret: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x3C).collect();
        let shares = SecretSharer::split_key_material(&secret, NONCE).expect("split");
        let recovered = SecretSharer::reconstruct_key_material(&shares[..3]).expect("reconstruct");
        assert_eq!(recovered, secret, "length {} did not round-trip exactly", len);
    }
}

/// The threshold property: coefficients derive from the secret, so an attacker
/// who knows the *nonce* — which is not required to be secret — learns nothing.
///
/// This is the direct counterpart to
/// `deprecated_one_share_plus_seed_recovers_the_secret` below. There, knowing
/// the seed was enough. Here the nonce is public by construction and a single
/// share still determines nothing: two different secrets sharing a nonce produce
/// unrelated share values at the same index.
#[test]
fn a_public_nonce_does_not_compromise_a_single_share() {
    let secret_a = [0x01u8; 32];
    let secret_b = [0x02u8; 32];

    let shares_a = SecretSharer::split_key_material(&secret_a, NONCE).expect("split a");
    let shares_b = SecretSharer::split_key_material(&secret_b, NONCE).expect("split b");

    assert_ne!(
        shares_a[0].value, shares_b[0].value,
        "two different secrets produced identical share values under the same \
         nonce — the coefficients are not secret-dependent"
    );

    // And the same secret under different nonces gives independent sharings.
    let shares_a2 = SecretSharer::split_key_material(&secret_a, b"another-nonce").expect("split");
    assert_ne!(
        shares_a[0].value, shares_a2[0].value,
        "the nonce did not separate two sharings of the same secret"
    );
}

#[test]
fn empty_input_is_rejected() {
    assert_eq!(
        SecretSharer::split_key_material(&[], NONCE),
        Err(IdentityError::InvalidInputLength)
    );
}

#[test]
fn malformed_shares_are_rejected() {
    let key = [0x77u8; 32];
    let mut shares = SecretSharer::split_key_material(&key, NONCE).expect("split");

    // Mismatched widths.
    shares[0].value.truncate(4);
    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..3]),
        Err(IdentityError::SerializationError)
    );

    // A zero index is not a valid evaluation point — f(0) is the secret.
    let mut shares = SecretSharer::split_key_material(&key, NONCE).expect("split");
    shares[0].index = 0;
    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..3]),
        Err(IdentityError::SerializationError)
    );
}

// ── Characterisation of the deprecated u64 path ───────────────────────────────

/// Pins the threshold break in the deprecated path: `derive_coeff` is a pure,
/// non-cryptographic function of a caller-supplied `u64`, so one share plus the
/// seed recovers the secret. Asserted as known-bad so it is executable, and so
/// it disappears with the function it characterises.
#[test]
#[allow(deprecated)]
fn deprecated_one_share_plus_seed_recovers_the_secret() {
    const SEED: u64 = 0x1234_5678_9ABC_DEF0;
    const Q: u64 = 8_380_417;
    const K: usize = 3;
    let secret: u64 = 421_337;

    let shares = SecretSharer::split_secret(secret, K, 5, SEED);
    let (x, y) = shares[0];

    // Reproducing derive_coeff needs no privileged access.
    let derive = |seed: u64, idx: u64| -> u64 {
        let mut v = seed.wrapping_add(idx.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        v ^= v >> 30;
        v = v.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        v ^= v >> 27;
        v = v.wrapping_mul(0x94d0_49bb_1331_11eb);
        v ^= v >> 31;
        v
    };

    let mut acc = 0u64;
    let mut x_pow = 1u64;
    for i in 1..K {
        x_pow = x_pow.wrapping_mul(x as u64) % Q;
        acc = (acc + (derive(SEED, i as u64) % Q).wrapping_mul(x_pow)) % Q;
    }
    let recovered = (y + Q - acc) % Q;

    assert_eq!(
        recovered,
        secret % Q,
        "the deprecated path no longer leaks the secret to one share — if it was \
         fixed, delete this characterisation test along with split_secret"
    );
}

/// Pins the truncation defect: the deprecated path shares `secret % MODULUS_Q`,
/// so anything above ~2^23 is silently lost.
#[test]
#[allow(deprecated)]
fn deprecated_path_truncates_a_full_width_u64() {
    let secret: u64 = 0x0123_4567_89AB_CDEF;
    let shares = SecretSharer::split_secret(secret, 3, 5, 0xDEAD_BEEF);
    let recovered = SecretSharer::reconstruct_secret(&shares[..3]);

    assert_ne!(
        recovered, secret,
        "the deprecated path round-tripped a full-width u64 — if it was fixed, \
         delete this characterisation test"
    );
    assert_eq!(recovered, secret % 8_380_417);
}

// ── The byte-oriented boundary the WASM exports wrap ──────────────────────────
//
// These exercise the exact logic behind `htss_split` / `htss_reconstruct`. The
// exports are `#[cfg(feature = "wasm")]` thin wrappers over these functions,
// deliberately, so the artifact's boundary is reachable by native tests.

#[test]
fn wire_format_round_trips_key_material() {
    let key = [0x9Eu8; 32];
    let wire = SecretSharer::split_key_material_bytes(&key, NONCE).expect("split");
    let recovered = SecretSharer::reconstruct_key_material_bytes(&wire).expect("reconstruct");
    assert_eq!(recovered, key);
}

#[test]
fn wire_format_below_threshold_is_an_error() {
    let key = [0x42u8; 32];
    let wire = SecretSharer::split_key_material_bytes(&key, NONCE).expect("split");

    // Rebuild the wire payload carrying only two of the five shares.
    let width = u32::from_le_bytes(wire[1..5].try_into().unwrap()) as usize;
    let mut two = Vec::new();
    two.push(2u8);
    two.extend_from_slice(&(width as u32).to_le_bytes());
    two.extend_from_slice(&wire[5..5 + 2 * (1 + width)]);

    assert_eq!(
        SecretSharer::reconstruct_key_material_bytes(&two),
        Err(IdentityError::ThresholdNotMet),
        "two shares must be an error at the byte boundary too, not an empty-vec \
         sentinel a caller could mistake for a secret"
    );
}

#[test]
fn wire_format_rejects_truncated_and_oversized_input() {
    let key = [0x11u8; 32];
    let wire = SecretSharer::split_key_material_bytes(&key, NONCE).expect("split");

    assert_eq!(
        SecretSharer::reconstruct_key_material_bytes(&wire[..wire.len() - 1]),
        Err(IdentityError::SerializationError)
    );

    let mut oversized = wire.clone();
    oversized.push(0);
    assert_eq!(
        SecretSharer::reconstruct_key_material_bytes(&oversized),
        Err(IdentityError::SerializationError)
    );

    assert_eq!(
        SecretSharer::reconstruct_key_material_bytes(&[]),
        Err(IdentityError::SerializationError)
    );
}
