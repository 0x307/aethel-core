//! HTSS key-material tests (P3-10 / 0X3-78).
//!
//! The WIT world declares:
//!
//! ```text
//! htss-split:       func(secret: list<u8>) -> result<list<htss-share>, identity-error>
//! htss-reconstruct: func(shares: list<htss-share>) -> result<list<u8>, identity-error>
//! ```
//!
//! P3-01's Do list said "HTSS operates over real key material, not a `u64`".
//! The WIT was changed; the Shamir implementation was not. These tests measure
//! how far the implementation is from the declaration, in terms that are
//! checkable rather than argued.

use aethel_core::htss::SecretSharer;

const K: usize = 3;
const N: usize = 5;

/// Sharing happens over Z_q with q = 8_380_417 (~2^23), and `split_secret`
/// begins with `coefficients[0] = secret % MODULUS_Q`. Any secret at or above
/// the modulus is silently truncated, so the round trip returns a different
/// value than it was given — with no error, because the signature has no error
/// channel.
#[test]
fn a_full_width_u64_secret_round_trips() {
    let secret: u64 = 0x0123_4567_89AB_CDEF;

    let shares = SecretSharer::split_secret(secret, K, N, 0xDEAD_BEEF);
    let recovered = SecretSharer::reconstruct_secret(&shares[..K]);

    assert_eq!(
        recovered, secret,
        "a u64 secret did not survive split/reconstruct. The sharing field is \
         Z_8380417 (~2^23), so `secret % MODULUS_Q` discards the high ~41 bits \
         silently. HTSS cannot carry a u64 today, let alone the `list<u8>` key \
         material the WIT world declares."
    );
}

/// The capacity question stated directly: how many bits can actually be shared?
#[test]
fn thirty_two_bytes_of_key_material_can_be_shared() {
    // A 256-bit key, the size `MasterIdentity::from_seed` consumes.
    let key = [0xA5u8; 32];

    // There is no API that accepts this. The closest is a u64, which is 8 bytes,
    // and even that is truncated to ~23 bits by the field. Encode the intent as
    // an assertion about capacity so the gap is a number rather than a comment.
    let shareable_bits = 8_380_417u64.ilog2();
    let required_bits = (key.len() * 8) as u32;

    assert!(
        shareable_bits >= required_bits,
        "HTSS can share at most {} bits per invocation (field Z_8380417) but key \
         material is {} bits. Splitting real key material needs either a larger \
         field or a documented decomposition across many sharings — a \
         cryptographic decision, not a mechanical retype. See P3-10.",
        shareable_bits,
        required_bits
    );
}

/// Shamir's threshold property rests on the non-constant coefficients being
/// unpredictable. `split_secret` derives them with `derive_coeff`, whose own
/// doc comment says "not cryptographic", from a caller-supplied `u64` seed.
///
/// So an attacker who knows the seed can recover the secret from a *single*
/// share: reconstruct the coefficients, evaluate, and subtract.
///
///   y = secret + c_1·x + c_2·x²  (mod q)   ⇒   secret = y − c_1·x − c_2·x²
///
/// This test performs that recovery. It passes only if one share is insufficient.
#[test]
fn one_share_is_insufficient_even_when_the_seed_is_known() {
    const SEED: u64 = 0x1234_5678_9ABC_DEF0;
    const Q: u64 = 8_380_417;
    let secret: u64 = 42_1337;

    let shares = SecretSharer::split_secret(secret, K, N, SEED);

    // The attacker holds exactly one share and knows the seed.
    let (x, y) = shares[0];

    // `derive_coeff` is a pure function of (seed, index) and is reproducible by
    // anyone — reimplemented here to show no privileged access is needed.
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
        let c = derive(SEED, i as u64) % Q;
        acc = (acc + c.wrapping_mul(x_pow)) % Q;
    }
    let recovered = (y + Q - acc) % Q;

    assert_ne!(
        recovered,
        secret % Q,
        "the secret was recovered from ONE share by an attacker who knows the \
         seed. Shamir's threshold property depends on the non-constant \
         coefficients being unpredictable; `derive_coeff` is documented in its \
         own source as \"not cryptographic\" and is a pure function of a \
         caller-supplied u64 seed. The 3-of-5 threshold is therefore not \
         enforced against anyone who knows or can brute-force 64 bits."
    );
}
