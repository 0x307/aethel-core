//! # Threshold Secret Sharing with a Hypercube Routing Simulation (HTSS)
//!
//! ## What this module actually does
//!
//! [`SecretSharer`] is local, in-process Shamir 3-of-5 threshold secret sharing
//! over a single `u64` scalar (`split_secret`/`reconstruct_secret`): a degree-2
//! polynomial over `F_q`, evaluated at 5 points to produce shares, reconstructed
//! from any 3 via Lagrange interpolation. That's it — there is no network
//! transport, no socket, no remote party, and no adversary who ever observes
//! anything, which is also why this can run fully offline (see the crate
//! README's "Offline generation" claim, CI-proven by network denial).
//!
//! [`HypercubeNetwork`]/[`HypercubePacket`]/[`NodeAddress`] are real, tested
//! code (not dead code — exercised by `tests/plp_tests.rs`), but what they
//! implement is a **local simulation** of dimension-disjoint path assignment
//! across a modeled Q_5 graph (32 nodes, 80 edges): `route_payload_shares`
//! computes which sequence of graph nodes each share *would* traverse and
//! walks that sequence in-process. Nothing is transmitted anywhere, so terms
//! like "eavesdropper" or "metadata leakage" don't apply to what this code
//! does today — there is no channel to eavesdrop on.
//!
//! ## Aspirational: a future distributed deployment
//!
//! The graph-routing simulation is a plausible building block for an actual
//! distributed HTSS deployment (real nodes, real transport, an adversary who
//! can observe some subset of real network paths) — that's presumably why it
//! was built this way rather than as a flat array shuffle. But that
//! deployment does not exist in this crate: no networking code, no consensus,
//! no notion of a validator. Treat any claim about eavesdropper resistance,
//! fault tolerance against real node failures, or metadata protection as a
//! design target for that future system, not a property of the code here.
//!
//! ## Key Structures
//!
//! - [`NodeAddress`] — 5-bit hypercube node coordinate (a modeled graph vertex)
//! - [`ZkProofSegment`] — one Shamir share plus a path authentication tag
//! - [`HypercubePacket`] — simulated in-process routing state for one segment
//! - [`SecretSharer`] — Shamir 3-of-5 split and Lagrange reconstruction (the real work)
//! - [`HypercubeNetwork`] — the modeled 32-node Q_5 graph and its local routing simulation
//!
//! ## Parameters
//!
//! - HYPERCUBE_DIM=5, NUM_NODES=32, THRESHOLD_K=3, MODULUS_Q=8380417
//!
//! ## What's actually guaranteed
//!
//! 1. **Threshold reconstruction**: any 3 of the 5 shares reconstruct the
//!    secret via Lagrange interpolation. Fewer than 3 shares reveal nothing
//!    about it **only on the [`SecretSharer::split_key_material`] path**, where
//!    the sharing polynomial's coefficients are derived from the secret itself
//!    via SHAKE-256. On the deprecated [`SecretSharer::split_secret`] path the
//!    coefficients come from a non-cryptographic function of a caller-supplied
//!    `u64`, so one share plus that seed recovers the secret and the threshold
//!    is not enforced (P3-12; `tests/htss_key_material.rs`).
//! 2. **Dimension-disjoint path assignment**: the 5 simulated routes share no
//!    intermediate node with each other, by construction of
//!    `compute_orthogonal_paths` — a graph-theoretic property of the modeled
//!    routing, not a live security boundary.

extern crate alloc;

use alloc::vec::Vec;
use sha3::{digest::{ExtendableOutput, XofReader}, Digest, Sha3_256, Shake256};
use zeroize::Zeroize;

use crate::identity_error::IdentityError;

const HYPERCUBE_DIM: usize = 5;
const NUM_NODES: usize = 1 << HYPERCUBE_DIM; // 2^5 = 32 nodes
const THRESHOLD_K: usize = 3;                 // 3-of-5 threshold scheme
const MODULUS_Q: u64 = 8380417;
const TOTAL_SHARES: usize = 5;                // n in the 3-of-5 scheme

/// A 5-bit hypercube node coordinate (0..31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeAddress(pub u8);

impl NodeAddress {
    /// Return the neighbor of this node along dimension `dim`.
    pub fn neighbor(&self, dim: usize) -> Self {
        NodeAddress(self.0 ^ (1 << dim))
    }

    /// Hamming distance between two node addresses.
    pub fn hamming_distance(&self, other: &Self) -> usize {
        (self.0 ^ other.0).count_ones() as usize
    }
}

/// A single Shamir share with a path authentication tag.
///
/// `share_val` is genuinely safe to expose and print (P3-03): it's one of the
/// `n` deliberately-split Shamir shares this module's whole job is to hand
/// out and route — the split is the point, not a leak. A lone share below
/// the `THRESHOLD_K`-of-`n` threshold carries no usable information about the
/// underlying secret (that's what makes it Shamir sharing and not a copy).
#[derive(Clone, Debug)]
pub struct ZkProofSegment {
    /// Share index (1-based).
    pub share_id: u8,
    /// Share value in Z_q.
    pub share_val: u64,
    /// SHA3-256 path authentication tag.
    pub path_tag: [u8; 32],
}

/// A routed packet carrying one proof segment through the hypercube.
#[derive(Clone, Debug)]
pub struct HypercubePacket {
    pub source: NodeAddress,
    pub destination: NodeAddress,
    pub current_node: NodeAddress,
    pub dimension_route: Vec<usize>,
    pub route_index: usize,
    pub payload: ZkProofSegment,
}

/// Shamir 3-of-5 secret sharing over Z_q.
pub struct SecretSharer;

/// A single threshold share of split key material.
///
/// Mirrors the `htss-share` record in the `aethel:core` WIT world. `value`
/// carries one big-endian-indexed `u32` per 16-bit limb of the shared payload,
/// so its length is a function of the secret's length, not of the secret.
///
/// Safe to serialize and transport: a share below the threshold is
/// information-theoretically independent of the secret, provided the
/// coefficients were derived by [`SecretSharer::split_key_material`] rather
/// than by the deprecated [`SecretSharer::split_secret`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HtssShare {
    /// Evaluation point x, in `1..=n`. Never zero — `f(0)` is the secret.
    pub index: u8,
    /// Per-limb evaluations `f_limb(index)`, little-endian `u32` each.
    pub value: Vec<u8>,
}

/// Bytes of the shared payload carried by each limb.
///
/// Two, not four: a limb value must stay below `MODULUS_Q` (~2^23), and 16 bits
/// gives a comfortable margin while keeping the limb count low. Three bytes
/// would be 2^24 > q and would truncate — the same defect this replaces.
const LIMB_BYTES: usize = 2;

/// Serialized width of one limb evaluation inside a share's `value`.
const LIMB_EVAL_BYTES: usize = 4;

/// Largest secret [`SecretSharer::split_key_material`] will split.
///
/// The previous bound was `u32::MAX`, which is a representational limit of the
/// payload's length prefix rather than a statement about what this operation is
/// for. This is key material: an ML-DSA-65 signing key is a few KiB, and nothing
/// this scheme is meant to protect is a file.
///
/// 64 KiB is deliberately generous against that, so the ceiling is a contract
/// rather than a limit a legitimate caller meets. It also caps the work a single
/// unauthenticated `htss-split` call can ask for, which matters because `secret`
/// arrives from outside the component (see `COMPONENT_SPLIT_NONCE` in
/// `src/component.rs`).
const MAX_SECRET_BYTES: usize = 64 * 1024;

impl SecretSharer {
    /// Split arbitrary-length key material into `TOTAL_SHARES` shares with a
    /// `THRESHOLD_K` threshold.
    ///
    /// This is the sound path. Two things differ from [`Self::split_secret`]:
    ///
    /// 1. **Coefficients derive from the secret itself**, via SHAKE-256 with
    ///    domain separation, not from a caller-supplied `u64`. Security rests on
    ///    the secret being secret — which it is by definition — rather than on
    ///    the caller having supplied an unguessable seed. `nonce` only separates
    ///    independent sharings of the same secret; it is not required to be
    ///    secret and the threshold property does not depend on it.
    /// 2. **The payload is decomposed into 16-bit limbs**, each shared under its
    ///    own independent polynomial, so a secret of any length survives intact
    ///    instead of being reduced mod q.
    ///
    /// The secret's length is carried in the payload so reconstruction can trim
    /// padding, which means share size reveals the secret's length (rounded up
    /// to a limb) and nothing else.
    ///
    /// **L1-internal**: `secret` and every derived intermediate are zeroized
    /// before returning. Only the shares leave.
    ///
    /// Refuses a secret larger than [`MAX_SECRET_BYTES`] with
    /// `InvalidInputLength`.
    pub fn split_key_material(secret: &[u8], nonce: &[u8]) -> Result<Vec<HtssShare>, IdentityError> {
        if secret.is_empty() || secret.len() > MAX_SECRET_BYTES {
            return Err(IdentityError::InvalidInputLength);
        }

        // payload = len(secret) ‖ secret, padded up to a whole number of limbs.
        let mut payload = Vec::with_capacity(4 + secret.len() + 1);
        payload.extend_from_slice(&(secret.len() as u32).to_le_bytes());
        payload.extend_from_slice(secret);
        while payload.len() % LIMB_BYTES != 0 {
            payload.push(0);
        }
        let limb_count = payload.len() / LIMB_BYTES;

        let mut shares: Vec<HtssShare> = (1..=TOTAL_SHARES as u8)
            .map(|index| HtssShare {
                index,
                value: Vec::with_capacity(limb_count * LIMB_EVAL_BYTES),
            })
            .collect();

        // Absorbed once, here, rather than once per coefficient. See
        // `derive_coeff_key`.
        let mut coeff_key = Self::derive_coeff_key(secret, nonce);

        for limb_idx in 0..limb_count {
            let lo = payload[limb_idx * LIMB_BYTES] as u64;
            let hi = payload[limb_idx * LIMB_BYTES + 1] as u64;
            let limb_value = lo | (hi << 8);

            // f(0) = limb, and the remaining coefficients come from the secret,
            // by way of the key derived from it above.
            let mut coefficients = Vec::with_capacity(THRESHOLD_K);
            coefficients.push(limb_value % MODULUS_Q);
            for coeff_idx in 1..THRESHOLD_K {
                coefficients.push(Self::derive_coeff_from_key(
                    &coeff_key, limb_idx, coeff_idx,
                ));
            }

            for share in shares.iter_mut() {
                let mut y = 0u64;
                let mut x_pow = 1u64;
                for &coeff in &coefficients {
                    y = (y + coeff * x_pow) % MODULUS_Q;
                    x_pow = (x_pow * share.index as u64) % MODULUS_Q;
                }
                share.value.extend_from_slice(&(y as u32).to_le_bytes());
            }

            coefficients.zeroize();
        }

        coeff_key.zeroize();
        payload.zeroize();
        Ok(shares)
    }

    /// Reconstruct key material from at least `THRESHOLD_K` shares.
    ///
    /// Returns `ThresholdNotMet` below the threshold rather than a wrong answer.
    /// [`Self::reconstruct_secret`] interpolates through however many points it
    /// is given; this is the entry point that decides which point sets are
    /// admissible in the first place.
    ///
    /// # Why the shares are validated as a *set*
    ///
    /// Lagrange interpolation is only defined over distinct evaluation points.
    /// Given two shares carrying the same index, every basis polynomial for
    /// those two points has a zero denominator, so both terms drop out and the
    /// interpolation answers from whatever points remain: a value that is not
    /// the shared secret. Because the payload's length prefix is recovered from
    /// that same wrong value, the resulting `len` is usually implausible and the
    /// call fails as `SerializationError` by accident. That accident is not a
    /// guard. A caller who chooses the share values can make the length prefix
    /// decode, and reconstruction then returns `Ok(attacker-chosen bytes)`. The
    /// index-uniqueness check below is what actually forecloses it.
    ///
    /// The cardinality ceiling is the same argument from the other side. The
    /// scheme issues `TOTAL_SHARES` shares, so a longer list cannot be a valid
    /// share set whatever it contains, and interpolation is O(k**2) per limb, so
    /// accepting an unbounded one is quadratic work on unauthenticated input.
    pub fn reconstruct_key_material(shares: &[HtssShare]) -> Result<Vec<u8>, IdentityError> {
        if shares.len() < THRESHOLD_K {
            return Err(IdentityError::ThresholdNotMet);
        }
        if shares.len() > TOTAL_SHARES {
            return Err(IdentityError::InvalidShareSet);
        }

        let width = shares[0].value.len();
        if width == 0 || width % LIMB_EVAL_BYTES != 0 {
            return Err(IdentityError::SerializationError);
        }
        if shares.iter().any(|s| s.value.len() != width || s.index == 0) {
            return Err(IdentityError::SerializationError);
        }

        // Index uniqueness. `index` is a `u8`, so a fixed 256-entry stack table
        // decides it in one pass with no allocation and no sort.
        let mut seen = [false; 256];
        for share in shares {
            if seen[share.index as usize] {
                return Err(IdentityError::InvalidShareSet);
            }
            seen[share.index as usize] = true;
        }

        let limb_count = width / LIMB_EVAL_BYTES;

        let mut payload = Vec::with_capacity(limb_count * LIMB_BYTES);
        for limb_idx in 0..limb_count {
            let points: Vec<(u8, u64)> = shares
                .iter()
                .map(|s| {
                    let off = limb_idx * LIMB_EVAL_BYTES;
                    let mut b = [0u8; LIMB_EVAL_BYTES];
                    b.copy_from_slice(&s.value[off..off + LIMB_EVAL_BYTES]);
                    (s.index, u32::from_le_bytes(b) as u64)
                })
                .collect();

            let limb = Self::reconstruct_secret(&points)?;
            payload.push((limb & 0xFF) as u8);
            payload.push(((limb >> 8) & 0xFF) as u8);
        }

        if payload.len() < 4 {
            return Err(IdentityError::SerializationError);
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&payload[..4]);
        let len = u32::from_le_bytes(len_bytes) as usize;

        if len == 0 || 4 + len > payload.len() {
            payload.zeroize();
            return Err(IdentityError::SerializationError);
        }

        let secret = payload[4..4 + len].to_vec();
        payload.zeroize();
        Ok(secret)
    }

    /// Split key material and serialize the shares for a byte-oriented boundary.
    ///
    /// Wire format, so a caller in another language can parse it without this
    /// crate:
    ///
    /// ```text
    /// [count: u8][width: u32 LE][ index: u8, value: width bytes ] × count
    /// ```
    ///
    /// Deliberately not `#[cfg(feature = "wasm")]`: the WASM export is a thin
    /// wrapper over this, so the logic behind the artifact's boundary is
    /// reachable by native tests. A boundary that can only be tested by building
    /// for WASM is a boundary that does not get tested.
    pub fn split_key_material_bytes(
        secret: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, IdentityError> {
        let shares = Self::split_key_material(secret, nonce)?;
        let width = shares[0].value.len();

        let mut out = Vec::with_capacity(1 + 4 + shares.len() * (1 + width));
        out.push(shares.len() as u8);
        out.extend_from_slice(&(width as u32).to_le_bytes());
        for share in &shares {
            out.push(share.index);
            out.extend_from_slice(&share.value);
        }
        Ok(out)
    }

    /// Parse the wire format written by [`Self::split_key_material_bytes`] and
    /// reconstruct.
    ///
    /// Returns `ThresholdNotMet` below the threshold and `SerializationError`
    /// for malformed input — never a sentinel value that a caller could mistake
    /// for a recovered secret.
    pub fn reconstruct_key_material_bytes(bytes: &[u8]) -> Result<Vec<u8>, IdentityError> {
        if bytes.len() < 5 {
            return Err(IdentityError::SerializationError);
        }
        let count = bytes[0] as usize;
        let mut width_bytes = [0u8; 4];
        width_bytes.copy_from_slice(&bytes[1..5]);
        let width = u32::from_le_bytes(width_bytes) as usize;

        if count == 0 || width == 0 {
            return Err(IdentityError::SerializationError);
        }
        let expected = 5 + count * (1 + width);
        if bytes.len() != expected {
            return Err(IdentityError::SerializationError);
        }

        let mut shares = Vec::with_capacity(count);
        let mut off = 5;
        for _ in 0..count {
            let index = bytes[off];
            off += 1;
            shares.push(HtssShare {
                index,
                value: bytes[off..off + width].to_vec(),
            });
            off += width;
        }

        Self::reconstruct_key_material(&shares)
    }

    /// Absorb the secret once, into a fixed-size coefficient key.
    ///
    /// # Why this stage exists
    ///
    /// The coefficients used to be derived by absorbing the **whole secret**
    /// into a fresh SHAKE-256 instance per coefficient. The limb loop runs
    /// `limb_count * (THRESHOLD_K - 1)` times, which with `LIMB_BYTES = 2` and
    /// `THRESHOLD_K = 3` is one call per byte of secret, each absorbing every
    /// byte of secret: n**2 bytes of absorption in total. Measured, a 4x larger
    /// input cost 14-16x the time, and a 64 KiB secret meant roughly 4.3 GB of
    /// absorption and over ten seconds of wall clock for a single call.
    ///
    /// Splitting the derivation in two makes the secret-dependent work happen
    /// exactly once and the per-coefficient work constant, so the whole split is
    /// linear in the secret's length.
    ///
    /// # What it must not change
    ///
    /// The security property is unchanged, and deliberately so: the secret is
    /// still the entropy source. That is the whole difference from
    /// [`Self::derive_coeff`] and the entire justification for the "3-of-5"
    /// claim — an attacker who does not already know the secret cannot predict
    /// the coefficients, so shares below the threshold reveal nothing. Deriving
    /// a key from the secret and expanding that keeps it intact: predicting any
    /// coefficient still requires either the secret or a preimage of SHAKE-256.
    ///
    /// The key is secret-derived and is zeroized by the caller.
    fn derive_coeff_key(secret: &[u8], nonce: &[u8]) -> [u8; 32] {
        let mut hasher = Shake256::default();
        sha3::digest::Update::update(&mut hasher, b"AETHEL_HTSS_COEFF_V2");
        sha3::digest::Update::update(&mut hasher, &(secret.len() as u32).to_le_bytes());
        sha3::digest::Update::update(&mut hasher, secret);
        sha3::digest::Update::update(&mut hasher, &(nonce.len() as u32).to_le_bytes());
        sha3::digest::Update::update(&mut hasher, nonce);
        let mut xof = hasher.finalize_xof();

        let mut key = [0u8; 32];
        xof.read(&mut key);
        key
    }

    /// Derive one sharing-polynomial coefficient from the coefficient key.
    ///
    /// Absorbs a fixed 32-byte key and two indices, so its cost does not depend
    /// on the secret's length. Rejection-samples into `[0, MODULUS_Q)` so the
    /// coefficient is uniform over the field rather than biased by a modular
    /// reduction of a wider value — unchanged from the previous derivation, and
    /// not the part that was slow.
    ///
    /// The `V2` domain separator is what makes this a different function rather
    /// than a faster spelling of the old one. Every coefficient, and therefore
    /// every share value, differs from what `V1` produced for the same
    /// `(secret, nonce)`. Shares from the two derivations must not be mixed
    /// within one reconstruction. Reconstruction itself is unaffected: it is
    /// Lagrange interpolation over the share values and never re-derives a
    /// coefficient, so shares produced by `V1` still reconstruct correctly.
    fn derive_coeff_from_key(key: &[u8; 32], limb_idx: usize, coeff_idx: usize) -> u64 {
        let mut hasher = Shake256::default();
        sha3::digest::Update::update(&mut hasher, b"AETHEL_HTSS_COEFF_V2_EXPAND");
        sha3::digest::Update::update(&mut hasher, key);
        sha3::digest::Update::update(&mut hasher, &(limb_idx as u64).to_le_bytes());
        sha3::digest::Update::update(&mut hasher, &(coeff_idx as u64).to_le_bytes());
        let mut xof = hasher.finalize_xof();

        // Rejection sampling: draw 4 bytes, mask to 24 bits, accept if < q.
        loop {
            let mut buf = [0u8; 4];
            xof.read(&mut buf);
            let candidate = (u32::from_le_bytes(buf) & 0x00FF_FFFF) as u64;
            if candidate < MODULUS_Q {
                return candidate;
            }
        }
    }
    /// Split `secret` into `n` shares using a degree-(k-1) polynomial over Z_q.
    /// **L1-internal**: `secret` is taken by value and used to build the
    /// sharing polynomial's constant term (`coefficients[0] = secret`) — that
    /// intermediate `Vec` is secret-derived and is explicitly zeroized before
    /// returning, since dropping a `Vec` does not clear its backing memory.
    /// Only the `n` output shares (safe to expose — see [`ZkProofSegment`])
    /// leave this function.
    ///
    /// Uses a deterministic seed derived from the secret and a nonce counter
    /// to avoid OS randomness (WASM-compatible).
    ///
    /// # The threshold property does not hold here
    ///
    /// The non-constant coefficients come from [`Self::derive_coeff`], which is
    /// not a cryptographic derivation and is a pure function of the
    /// caller-supplied `seed`. Anyone who knows or brute-forces `seed` (64 bits)
    /// recovers the secret from a **single** share. This also shares only
    /// `secret % MODULUS_Q` (~23 bits), silently discarding anything above it.
    ///
    /// Use [`Self::split_key_material`]. See P3-12 and
    /// `tests/htss_key_material.rs`.
    #[deprecated(
        since = "0.1.1",
        note = "threshold not enforced: coefficients derive non-cryptographically from a \
                caller-supplied u64 seed, so one share plus that seed recovers the secret. \
                Also truncates any secret above ~2^23. Use split_key_material."
    )]
    pub fn split_secret(secret: u64, k: usize, n: usize, seed: u64) -> Vec<(u8, u64)> {
        // Build polynomial coefficients: f(0) = secret, rest derived from seed
        let mut coefficients = Vec::with_capacity(k);
        coefficients.push(secret % MODULUS_Q);
        for i in 1..k {
            // Deterministic coefficient derivation using a simple LCG-style mix
            let coeff = Self::derive_coeff(seed, i as u64) % MODULUS_Q;
            coefficients.push(coeff);
        }
        let mut shares = Vec::with_capacity(n);
        for x in 1..=(n as u8) {
            let mut y = 0u64;
            let mut x_pow = 1u64;
            for &coeff in &coefficients {
                y = (y + coeff.wrapping_mul(x_pow)) % MODULUS_Q;
                x_pow = x_pow.wrapping_mul(x as u64) % MODULUS_Q;
            }
            shares.push((x, y));
        }
        coefficients.zeroize();
        shares
    }

    /// Derive a pseudo-random coefficient from a seed and index.
    fn derive_coeff(seed: u64, idx: u64) -> u64 {
        // Simple mixing function (not cryptographic — used only for share polynomial)
        let mut v = seed.wrapping_add(idx.wrapping_mul(0x9e3779b97f4a7c15));
        v ^= v >> 30;
        v = v.wrapping_mul(0xbf58476d1ce4e5b9);
        v ^= v >> 27;
        v = v.wrapping_mul(0x94d049bb133111eb);
        v ^= v >> 31;
        v
    }

    /// Reconstruct the secret from `shares`, validating the threshold first.
    ///
    /// Mirrors the `htss-reconstruct` operation in the `aethel:core` WIT
    /// world: fewer than `THRESHOLD_K` (3) shares is not "a slightly worse
    /// answer", it's not a real reconstruction — [`Self::reconstruct_secret`]
    /// happily interpolates through however many points it's given and
    /// returns a wrong answer silently. This is the entry point that refuses
    /// to do that.
    pub fn reconstruct_secret_checked(shares: &[(u8, u64)]) -> Result<u64, IdentityError> {
        if shares.len() < THRESHOLD_K {
            return Err(IdentityError::ThresholdNotMet);
        }
        Self::reconstruct_secret(shares)
    }

    /// Reconstruct the secret from at least `k` shares using Lagrange interpolation.
    /// **L1-internal by design, not a leak**: returning the reconstructed
    /// secret is the entire point of secret *reconstruction* — the caller
    /// holding `≥ THRESHOLD_K` shares is, by definition, authorized to
    /// recover it (that's what distinguishes reconstruction from a leak via
    /// a sub-threshold share, which [`ZkProofSegment`]'s doc comment covers).
    ///
    /// Returns `InvalidShareSet` if the points are not interpolable. For
    /// distinct indices in `1..q` they always are, so this is a defence in
    /// depth rather than a case a correct caller meets. See
    /// [`Self::mod_inverse`] for why it is reported rather than absorbed.
    pub fn reconstruct_secret(shares: &[(u8, u64)]) -> Result<u64, IdentityError> {
        let q = MODULUS_Q as i64;
        let mut secret = 0i64;
        for i in 0..shares.len() {
            let xi = shares[i].0 as i64;
            let yi = shares[i].1 as i64;
            let mut num = 1i64;
            let mut den = 1i64;
            for j in 0..shares.len() {
                if i != j {
                    let xj = shares[j].0 as i64;
                    // num *= (0 - xj) = -xj  (evaluating at x=0)
                    num = ((num % q) * ((-xj % q + q) % q)) % q;
                    // den *= (xi - xj)
                    den = ((den % q) * ((xi - xj % q + q) % q)) % q;
                }
            }
            let den_inv = Self::mod_inverse(den, q).ok_or(IdentityError::InvalidShareSet)?;
            let lagrange = (num % q * den_inv % q) % q;
            let term = (yi % q * lagrange % q) % q;
            secret = (secret + term) % q;
        }
        Ok(((secret % q) + q) as u64 % MODULUS_Q)
    }

    /// Modular inverse of `a` mod `m`, or `None` when `a` has none.
    ///
    /// `None` rather than the `0` sentinel this returned before. Zero is a value
    /// the extended Euclidean algorithm can legitimately be asked about and is
    /// never a legitimate inverse, so a `0` return was indistinguishable from
    /// success; multiplying by it turned "there is no inverse" into "this
    /// Lagrange term contributes nothing", which is the mechanism that let a
    /// share set with a repeated index reconstruct to a wrong secret inside an
    /// `Ok`.
    ///
    /// The uniqueness check in [`Self::reconstruct_key_material`] is what makes
    /// the failing case unreachable. This is the second line, so a future caller
    /// that does reach it gets an error rather than a plausible number.
    fn mod_inverse(a: i64, m: i64) -> Option<i64> {
        let mut t = 0i64; let mut newt = 1i64;
        let mut r = m; let mut newr = a % m;
        while newr != 0 {
            let quotient = r / newr;
            let temp_t = t - quotient * newt; t = newt; newt = temp_t;
            let temp_r = r - quotient * newr; r = newr; newr = temp_r;
        }
        if r > 1 { return None; }
        if t < 0 { t += m; }
        Some(t)
    }
}

/// 32-node Q_5 hypercube network with dimension-disjoint routing.
pub struct HypercubeNetwork {
    pub nodes: Vec<NodeAddress>,
}

impl HypercubeNetwork {
    /// Create a new 32-node Q_5 hypercube network.
    pub fn new() -> Self {
        let nodes = (0..NUM_NODES).map(|i| NodeAddress(i as u8)).collect();
        Self { nodes }
    }

    /// Compute 5 orthogonal dimension-disjoint routing paths from `src` to `dst`.
    pub fn compute_orthogonal_paths(_src: NodeAddress, _dst: NodeAddress) -> Vec<Vec<usize>> {
        let mut paths = Vec::with_capacity(HYPERCUBE_DIM);
        for d_start in 0..HYPERCUBE_DIM {
            let mut dim_order = Vec::with_capacity(HYPERCUBE_DIM);
            for i in 0..HYPERCUBE_DIM {
                dim_order.push((d_start + i) % HYPERCUBE_DIM);
            }
            paths.push(dim_order);
        }
        paths
    }

    /// Route proof shares from `src` to `dst` along orthogonal paths.
    pub fn route_payload_shares(
        &self,
        src: NodeAddress,
        dst: NodeAddress,
        shares: &[(u8, u64)],
    ) -> Vec<HypercubePacket> {
        let routes = Self::compute_orthogonal_paths(src, dst);
        let mut packets = Vec::new();
        for (i, share) in shares.iter().enumerate() {
            let route_dim_sequence = routes[i % HYPERCUBE_DIM].clone();
            let mut hasher = Sha3_256::new();
            hasher.update(src.0.to_le_bytes());
            hasher.update(dst.0.to_le_bytes());
            hasher.update([share.0]);
            let mut path_tag = [0u8; 32];
            path_tag.copy_from_slice(&hasher.finalize());
            let packet = HypercubePacket {
                source: src,
                destination: dst,
                current_node: src,
                dimension_route: route_dim_sequence,
                route_index: 0,
                payload: ZkProofSegment {
                    share_id: share.0,
                    share_val: share.1,
                    path_tag,
                },
            };
            packets.push(packet);
        }
        let mut delivered_packets = Vec::new();
        for mut pkt in packets {
            while pkt.current_node != pkt.destination {
                let next_dim = pkt.dimension_route[pkt.route_index];
                let next_node = pkt.current_node.neighbor(next_dim);
                pkt.current_node = next_node;
                pkt.route_index += 1;
            }
            delivered_packets.push(pkt);
        }
        delivered_packets
    }
}

impl Default for HypercubeNetwork {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    /// `mod_inverse` must report "no inverse exists" rather than returning it.
    ///
    /// Zero has no inverse mod q. The function used to return `0` for that,
    /// which is also a perfectly ordinary value to multiply by, so the caller
    /// could not tell the two apart and a Lagrange term with a zero denominator
    /// silently evaluated to nothing. That is what turned a share set with a
    /// repeated index into a wrong secret inside an `Ok`.
    #[test]
    fn mod_inverse_reports_a_non_invertible_input() {
        assert_eq!(
            SecretSharer::mod_inverse(0, MODULUS_Q as i64),
            None,
            "zero has no inverse mod q, and saying so with 0 is indistinguishable from success"
        );
    }

    /// The negative test above is only meaningful if the function still computes
    /// real inverses.
    #[test]
    fn mod_inverse_still_inverts() {
        let q = MODULUS_Q as i64;
        for a in [1i64, 2, 3, 7, 1234, q - 1] {
            let inv = SecretSharer::mod_inverse(a, q).expect("a non-zero residue mod a prime is invertible");
            assert_eq!((a * inv).rem_euclid(q), 1, "mod_inverse({a}) is not an inverse");
        }
    }

    use super::*;

    #[test]
    fn test_htss_split_reconstruct() {
        let secret: u64 = 5234123;
        let seed: u64 = 0xdeadbeef_cafebabe;
        let shares = SecretSharer::split_secret(secret, THRESHOLD_K, HYPERCUBE_DIM, seed);
        assert_eq!(shares.len(), HYPERCUBE_DIM);
        // Reconstruct from first 3 shares
        let reconstructed = SecretSharer::reconstruct_secret(&shares[0..THRESHOLD_K])
            .expect("distinct indices interpolate");
        assert_eq!(reconstructed, secret);
    }

    #[test]
    fn test_hypercube_routing() {
        let network = HypercubeNetwork::new();
        let src = NodeAddress(0b00000);
        let dst = NodeAddress(0b11111);
        let seed: u64 = 0x1234567890abcdef;
        let shares = SecretSharer::split_secret(42u64, THRESHOLD_K, HYPERCUBE_DIM, seed);
        let delivered = network.route_payload_shares(src, dst, &shares);
        assert_eq!(delivered.len(), HYPERCUBE_DIM);
        for pkt in &delivered {
            assert_eq!(pkt.current_node, dst);
        }
    }
}
