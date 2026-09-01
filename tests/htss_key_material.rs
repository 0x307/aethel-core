//! HTSS key-material tests (P3-12 / 0X3-80, share authentication / 0X3-105).
//!
//! The WIT world declares:
//!
//! ```text
//! htss-split:       func(secret: list<u8>) -> result<tuple<list<htss-share>, list<u8>>, identity-error>
//! htss-reconstruct: func(shares: list<htss-share>, root: list<u8>) -> result<list<u8>, identity-error>
//! ```
//!
//! P3-01's Do list said "HTSS operates over real key material, not a `u64`". The
//! WIT was changed; the Shamir implementation was not, and the gap turned out to
//! include a break of the threshold property itself.
//!
//! `split_key_material` now returns a root alongside the shares, and
//! `reconstruct_key_material` takes that root back: every share is checked
//! against it before interpolation runs. PR #21 stopped a share list that
//! cannot determine any secret at all (a repeated index, too many shares); it
//! could not stop a share list that determines a secret nobody ever split. The
//! root check is what closes that — see
//! `shares_from_one_sharing_do_not_authenticate_against_another_sharings_root`
//! for the demonstration, and `SecretSharer::reconstruct_key_material`'s doc
//! comment for exactly what the root does and does not vouch for.
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

    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");
    assert_eq!(shares.len(), 5, "expected a 3-of-5 split");

    let recovered = SecretSharer::reconstruct_key_material(&shares[..3], &root).expect("reconstruct");

    assert_eq!(recovered, key, "32 bytes of key material did not survive the round trip");
}

/// Any three of the five shares must work, not just the first three.
#[test]
fn any_three_shares_reconstruct() {
    let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");

    for combo in [[0, 1, 2], [0, 2, 4], [1, 3, 4], [2, 3, 4]] {
        let subset: Vec<HtssShare> = combo.iter().map(|&i| shares[i].clone()).collect();
        let recovered = SecretSharer::reconstruct_key_material(&subset, &root)
            .unwrap_or_else(|e| panic!("shares {:?} failed to reconstruct: {:?}", combo, e));
        assert_eq!(recovered, key, "shares {:?} reconstructed the wrong secret", combo);
    }
}

/// Below threshold is an error, not a wrong answer. The old `u64` path returned
/// `0`, which collides with a legitimate zero secret.
#[test]
fn below_threshold_is_an_error_not_a_zero() {
    let key = [0x11u8; 32];
    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");

    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..2], &root),
        Err(IdentityError::ThresholdNotMet),
        "two shares of a 3-of-5 split must return ThresholdNotMet"
    );
    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..1], &root),
        Err(IdentityError::ThresholdNotMet)
    );
}

/// Losing one share above the threshold must not lose the identity.
#[test]
fn losing_one_share_does_not_lose_the_secret() {
    let key = [0x5Cu8; 32];
    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");

    let survivors: Vec<HtssShare> = shares.iter().skip(1).cloned().collect();
    assert_eq!(survivors.len(), 4);

    let recovered = SecretSharer::reconstruct_key_material(&survivors, &root).expect("reconstruct");
    assert_eq!(recovered, key);
}

/// Secrets that are not a whole number of limbs must round-trip exactly, with
/// no trailing padding bytes.
#[test]
fn odd_length_secrets_round_trip_without_padding() {
    for len in [1usize, 7, 15, 31, 33] {
        let secret: Vec<u8> = (0..len).map(|i| (i as u8) ^ 0x3C).collect();
        let (shares, root) = SecretSharer::split_key_material(&secret, NONCE).expect("split");
        let recovered = SecretSharer::reconstruct_key_material(&shares[..3], &root).expect("reconstruct");
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

    let (shares_a, _) = SecretSharer::split_key_material(&secret_a, NONCE).expect("split a");
    let (shares_b, _) = SecretSharer::split_key_material(&secret_b, NONCE).expect("split b");

    assert_ne!(
        shares_a[0].value, shares_b[0].value,
        "two different secrets produced identical share values under the same \
         nonce — the coefficients are not secret-dependent"
    );

    // And the same secret under different nonces gives independent sharings.
    let (shares_a2, _) = SecretSharer::split_key_material(&secret_a, b"another-nonce").expect("split");
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
    let (mut shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");

    // Mismatched widths.
    shares[0].value.truncate(4);
    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..3], &root),
        Err(IdentityError::SerializationError)
    );

    // A zero index is not a valid evaluation point — f(0) is the secret.
    let (mut shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");
    shares[0].index = 0;
    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..3], &root),
        Err(IdentityError::SerializationError)
    );
}

// ── Cost is linear in the secret's length ─────────────────────────────────────

/// The largest secret `split_key_material` accepts, mirrored from the crate's
/// `MAX_SECRET_BYTES`. Not re-exported: the ceiling is a property of the
/// operation, and a test that read it from the implementation would agree with
/// whatever the implementation happened to do.
const MAX_SECRET_BYTES: usize = 64 * 1024;

/// Splitting at the ceiling must finish, and finish quickly.
///
/// The coefficient derivation used to absorb the entire secret into a fresh
/// SHAKE-256 instance per coefficient, and the limb loop makes one call per byte
/// of secret, so total absorption was quadratic. At 64 KiB that is roughly
/// 4.3 GB of absorption; measured before the fix, this call took 11.7 seconds in
/// release and far longer in a debug build. Now the secret is absorbed once and
/// the per-coefficient work is constant, so the same call is milliseconds.
///
/// The bound is wall clock, which is not something to assert lightly. It is
/// defensible here only because the gap is orders of magnitude wide. This call
/// takes about 4 seconds in an unoptimised build and 50 milliseconds optimised;
/// before the fix it was minutes unoptimised. 60 seconds is not a measurement of
/// the fast path, it is a ceiling the slow path cannot get under on any machine
/// that could run this suite at all.
#[test]
fn the_largest_allowed_secret_splits_and_round_trips() {
    let secret: Vec<u8> = (0..MAX_SECRET_BYTES).map(|i| (i % 251) as u8).collect();

    let started = std::time::Instant::now();
    let (shares, root) =
        SecretSharer::split_key_material(&secret, NONCE).expect("split at the ceiling");
    let elapsed = started.elapsed();

    assert!(
        elapsed < std::time::Duration::from_secs(60),
        "splitting {MAX_SECRET_BYTES} bytes took {elapsed:?}. The derivation is \
         quadratic in the secret's length again"
    );

    let recovered = SecretSharer::reconstruct_key_material(&shares[..3], &root).expect("reconstruct");
    assert_eq!(recovered, secret, "the largest allowed secret did not survive the round trip");
}

/// Cost must grow with the secret's length, not with its square.
///
/// Asserted as a ratio with wide slack rather than an absolute time, because the
/// two behaviours are far enough apart that slack costs nothing: over an 8x
/// range, linear work is ~8x and quadratic work is ~64x. Anything under 32x is
/// unambiguously the former.
#[test]
fn split_cost_grows_linearly_not_quadratically() {
    fn time_split(n: usize) -> std::time::Duration {
        let secret = vec![0x5Au8; n];
        // One warm-up pass, so the measured pass is not paying for first-touch
        // allocation.
        let _ = SecretSharer::split_key_material(&secret, NONCE).expect("split");
        let started = std::time::Instant::now();
        let _ = SecretSharer::split_key_material(&secret, NONCE).expect("split");
        started.elapsed()
    }

    let small = time_split(2 * 1024).max(std::time::Duration::from_micros(1));
    let large = time_split(16 * 1024);

    let ratio = large.as_secs_f64() / small.as_secs_f64();
    assert!(
        ratio < 32.0,
        "8x the input cost {ratio:.1}x the time ({small:?} -> {large:?}). Linear \
         work is about 8x and quadratic work is about 64x; this is the latter"
    );
}

/// The ceiling is a real bound, and it is stated rather than represented.
///
/// The previous bound was `u32::MAX`, about 4 GiB, which is the largest value
/// the payload's length prefix can hold and not a claim about what this
/// operation is for.
#[test]
fn a_secret_above_the_ceiling_is_refused() {
    let over = vec![0u8; MAX_SECRET_BYTES + 1];
    assert_eq!(
        SecretSharer::split_key_material(&over, NONCE),
        Err(IdentityError::InvalidInputLength)
    );

    // And the ceiling itself is accepted, so the bound is off-by-one-free.
    let at = vec![0u8; MAX_SECRET_BYTES];
    assert!(SecretSharer::split_key_material(&at, NONCE).is_ok());
}

/// The faster derivation must still take its entropy from the secret.
///
/// This is the property the whole `split_key_material` path exists for: the
/// coefficients are unpredictable to anyone who does not know the secret, which
/// is what makes shares below the threshold reveal nothing. Two secrets that
/// differ in one bit must produce unrelated shares — if the hoisted key had been
/// derived from the nonce alone, this is the test that would catch it.
#[test]
fn coefficients_still_depend_on_the_secret() {
    let mut a = [0x11u8; 32];
    let mut b = a;
    b[31] ^= 0x01;

    let (shares_a, _) = SecretSharer::split_key_material(&a, NONCE).expect("split");
    let (shares_b, _) = SecretSharer::split_key_material(&b, NONCE).expect("split");

    // Share 1 of each carries f_limb(1) for every limb. The constant terms
    // differ in one limb only, so if the higher coefficients were not
    // secret-derived the two share values would agree almost everywhere.
    let differing = shares_a[0]
        .value
        .iter()
        .zip(shares_b[0].value.iter())
        .filter(|(x, y)| x != y)
        .count();
    assert!(
        differing > shares_a[0].value.len() / 2,
        "a one-bit change in the secret changed only {differing} of {} share bytes. \
         The sharing coefficients are not being derived from the secret",
        shares_a[0].value.len()
    );

    a.fill(0);
    b.fill(0);
}

// ── The share list must be a valid *set* ──────────────────────────────────────

/// Encode `secret` the way `split_key_material` lays out its payload:
/// `len(u32 LE) || secret`, zero-padded to a whole number of 2-byte limbs, each
/// limb widened to a little-endian `u32` evaluation.
///
/// Used to build a share whose evaluations *are* the payload, which is what
/// makes the forgery below land on decodable bytes instead of garbage.
fn payload_shaped_value(secret: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&(secret.len() as u32).to_le_bytes());
    payload.extend_from_slice(secret);
    while payload.len() % 2 != 0 {
        payload.push(0);
    }
    let mut value = Vec::new();
    for limb in payload.chunks(2) {
        let v = limb[0] as u32 | ((limb[1] as u32) << 8);
        value.extend_from_slice(&v.to_le_bytes());
    }
    value
}

/// Two shares carrying the same *valid* index, at matching width, must be
/// refused.
///
/// This is the case a duplicate-index probe has to construct to find anything.
/// Duplicating index 0 is caught by the existing `index != 0` check and
/// duplicating at mismatched widths is caught by the uniformity check, so both
/// are rejected for reasons that have nothing to do with the duplicate and tell
/// you nothing about whether duplicates are handled.
#[test]
fn a_repeated_share_index_is_refused() {
    let key = [0x42u8; 32];
    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");

    let repeated = vec![shares[0].clone(), shares[0].clone(), shares[1].clone()];
    assert_eq!(
        SecretSharer::reconstruct_key_material(&repeated, &root),
        Err(IdentityError::InvalidShareSet),
        "a share set with a repeated evaluation index was accepted"
    );
}

/// The reason a repeated index is a soundness bug and not just an oddity: it
/// lets a caller who never held a share choose what comes out.
///
/// With indices `[1, 1, 2]`, the two basis polynomials for index 1 both have a
/// zero denominator and drop out, so each limb reconstructs to the *raw* value
/// carried by the index-2 share. Shaping that share's value like a payload makes
/// the length prefix decode, and the old code returned `Ok(fabricated bytes)`.
///
/// This is caught by the uniqueness check alone, before the root is ever
/// examined — the path and root below are placeholders and never get read.
/// `shares_from_one_sharing_do_not_authenticate_against_another_sharings_root`
/// is the test for the class of forgery uniqueness *cannot* catch: distinct
/// indices, no duplicate, still not genuine.
#[test]
fn a_repeated_index_cannot_forge_a_reconstruction() {
    let fabricated = b"ATTACKER".to_vec();
    let forged_value = payload_shaped_value(&fabricated);
    let width = forged_value.len();

    let shares = vec![
        HtssShare { index: 1, value: vec![0xAA; width], path: Vec::new() },
        HtssShare { index: 1, value: vec![0xBB; width], path: Vec::new() },
        HtssShare { index: 2, value: forged_value, path: Vec::new() },
    ];
    let dummy_root = [0u8; 32];

    let result = SecretSharer::reconstruct_key_material(&shares, &dummy_root);
    assert_ne!(
        result.as_deref(),
        Ok(fabricated.as_slice()),
        "a share set with a repeated index reconstructed to attacker-chosen bytes"
    );
    assert_eq!(result, Err(IdentityError::InvalidShareSet));
}

/// More shares than the scheme issues is not a valid share set whatever the
/// values are, and interpolation is quadratic in the count, so an unbounded list
/// is also a work multiplier on unauthenticated input.
#[test]
fn more_shares_than_the_scheme_issues_are_refused() {
    let key = [0x11u8; 32];
    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");
    assert_eq!(shares.len(), 5, "test setup: a 3-of-5 split");

    // Six well-formed shares: the five real ones plus one more with a distinct,
    // in-range index, so the only thing wrong with the set is its cardinality.
    // Cardinality is checked before authentication, so an unauthenticatable
    // sixth share (value/path copied from share 0, wrong for index 6) still
    // demonstrates the bound rather than accidentally testing the root check.
    let mut oversized = shares.clone();
    oversized.push(HtssShare {
        index: 6,
        value: shares[0].value.clone(),
        path: shares[0].path.clone(),
    });

    assert_eq!(
        SecretSharer::reconstruct_key_material(&oversized, &root),
        Err(IdentityError::InvalidShareSet)
    );
}

/// The bound rejects nothing legitimate: all five issued shares still
/// reconstruct.
#[test]
fn the_full_issued_share_set_still_reconstructs() {
    let key = [0x33u8; 48];
    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");
    let recovered = SecretSharer::reconstruct_key_material(&shares, &root).expect("reconstruct");
    assert_eq!(recovered, key, "the cardinality bound rejected a valid full share set");
}

// ── Share authentication (0X3-105): the gap #21 could not close ───────────────

/// The gap #21 left open, closed: a well-formed share set at distinct indices,
/// self-consistent, still is not accepted unless it checks out against the
/// caller-supplied root.
///
/// This is not shares fabricated from nothing — an attacker who can call
/// `split_key_material` at all can trivially produce a share set that passes
/// every check #21 added (distinct indices, in-bound cardinality, matching
/// width) by the simple expedient of actually splitting bytes of their own
/// choosing. That is exactly the "well-formed but not genuine" shape #21 could
/// not rule out, and it is what `a_repeated_index_cannot_forge_a_reconstruction`
/// above does not exercise, because its forged shares share an index.
///
/// Root authentication closes it: the attacker's shares are only ever
/// consistent with the root their own split produced. Presented against a
/// different, genuine sharing's root, they are refused — whether presented on
/// their own or spliced one-for-one into the genuine set.
#[test]
fn shares_from_one_sharing_do_not_authenticate_against_another_sharings_root() {
    // The victim's real sharing of a real secret.
    let victim_secret = [0x77u8; 32];
    let (victim_shares, victim_root) =
        SecretSharer::split_key_material(&victim_secret, NONCE).expect("split");

    // The attacker's own, entirely legitimate split of bytes THEY chose. Every
    // check #21 added passes: distinct indices, five shares, matching width —
    // exactly 32 bytes, like the victim's secret, so the spliced case below
    // exercises the root check rather than tripping the width-uniformity check
    // first.
    let attacker_payload: Vec<u8> = (0..32u8).map(|i| i ^ 0xAA).collect();
    let (attacker_shares, attacker_root) =
        SecretSharer::split_key_material(&attacker_payload, NONCE).expect("split");

    // Self-consistent: the attacker's own shares verify against their own root.
    // This is the caveat stated in `reconstruct_key_material`'s doc comment,
    // demonstrated rather than only asserted: authentication proves a share
    // belongs to a tree, not that the tree is the one anyone else expected.
    let self_consistent =
        SecretSharer::reconstruct_key_material(&attacker_shares[..3], &attacker_root);
    assert_eq!(
        self_consistent.as_deref(),
        Ok(attacker_payload.as_slice()),
        "test setup: a genuine split must reconstruct against its own root"
    );

    // Presented against the VICTIM's published root, the same well-formed,
    // distinct-index, matching-width shares must not authenticate.
    let against_victim_root =
        SecretSharer::reconstruct_key_material(&attacker_shares[..3], &victim_root);
    assert_eq!(
        against_victim_root,
        Err(IdentityError::InvalidShareSet),
        "shares from one sharing authenticated against a different sharing's root"
    );

    // Splicing a single substituted share into an otherwise-genuine set must
    // also fail, even though every index is still distinct.
    let mixed = vec![
        victim_shares[0].clone(),
        victim_shares[1].clone(),
        attacker_shares[2].clone(),
    ];
    assert_eq!(
        SecretSharer::reconstruct_key_material(&mixed, &victim_root),
        Err(IdentityError::InvalidShareSet),
        "a single substituted share from a different sharing was accepted"
    );
}

/// Corrupting a genuine share's value invalidates its own inclusion proof, even
/// though nothing else about the share set changed.
#[test]
fn a_tampered_share_value_fails_authentication() {
    let key = [0x99u8; 32];
    let (mut shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");

    // Flip a byte. `path` still describes the tree built from the ORIGINAL
    // value, so it no longer folds to `root` for this changed value.
    let last = shares[0].value.len() - 1;
    shares[0].value[last] ^= 0x01;

    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..3], &root),
        Err(IdentityError::InvalidShareSet),
        "a share with a tampered value still authenticated against the root"
    );
}

/// Swapping two shares' inclusion paths must fail: a proof is for one specific
/// index, not interchangeable with another share's.
#[test]
fn a_swapped_share_path_fails_authentication() {
    let key = [0x88u8; 32];
    let (mut shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");

    let tmp = shares[0].path.clone();
    shares[0].path = shares[1].path.clone();
    shares[1].path = tmp;

    assert_eq!(
        SecretSharer::reconstruct_key_material(&shares[..3], &root),
        Err(IdentityError::InvalidShareSet),
        "swapping two shares' inclusion paths still authenticated"
    );
}

/// A root that is merely the wrong length is rejected as malformed input, not
/// as a share-set failure — the two are different kinds of caller error and
/// this crate has treated them as distinct since `InvalidShareSet` was added.
/// `reconstruct_key_material` takes `root: &[u8; 32]`, so this is enforced by
/// the type at the native boundary; `reconstruct_key_material_bytes` and the
/// WIT `htss-reconstruct` are the surfaces that see a caller-supplied length.
#[test]
fn wire_format_rejects_a_short_root() {
    let key = [0x66u8; 32];
    let wire = SecretSharer::split_key_material_bytes(&key, NONCE).expect("split");

    // Truncate to fewer than the 32 root bytes plus a share-count byte.
    assert_eq!(
        SecretSharer::reconstruct_key_material_bytes(&wire[..20]),
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
    let recovered = SecretSharer::reconstruct_secret(&shares[..3]).expect("distinct indices interpolate");

    assert_ne!(
        recovered, secret,
        "the deprecated path round-tripped a full-width u64 — if it was fixed, \
         delete this characterisation test"
    );
    assert_eq!(recovered, secret % 8_380_417);
}

// ── The byte-oriented boundary a non-Rust caller parses ────────────────────────
//
// These exercise the exact logic behind the wire format `htss-split` /
// `htss-reconstruct` implementations sit on top of at the component boundary.

/// Re-encode a subset of shares plus root in the wire format written by
/// [`SecretSharer::split_key_material_bytes`]: `root(32) ++ count(u8) ++
/// width(u32 LE) ++ [index(u8) ++ value(width bytes) ++ path] × count`.
///
/// Building this by hand from a real split's shares, rather than slicing bytes
/// out of `split_key_material_bytes`'s own output, is what lets these tests
/// construct an arbitrary below-threshold or malformed sub-blob without
/// depending on this crate's internal per-index path length.
fn encode_wire(shares: &[HtssShare], root: &[u8; 32]) -> Vec<u8> {
    let width = shares[0].value.len();
    let mut out = Vec::new();
    out.extend_from_slice(root);
    out.push(shares.len() as u8);
    out.extend_from_slice(&(width as u32).to_le_bytes());
    for share in shares {
        out.push(share.index);
        out.extend_from_slice(&share.value);
        out.extend_from_slice(&share.path);
    }
    out
}

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
    let (shares, root) = SecretSharer::split_key_material(&key, NONCE).expect("split");
    let two = encode_wire(&shares[..2], &root);

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
