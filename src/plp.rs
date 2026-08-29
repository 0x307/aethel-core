//! # Polymorphic Post-Quantum Identifier Engine (PLP-LWE)
//!
//! This module implements the core **Polymorphic Lattice Projection (PLP)** algorithm
//! for the Aethel-ID ephemeral identifier engine.
//!
//! ## Purpose
//!
//! Replaces static DID public keys with continuously mutating ephemeral projections
//! over Module-LWE. Each interaction context τ (e.g., block height) produces a
//! unique, unlinkable public projection `b_τ = A_τ · s + e_τ (mod q)` that is
//! computationally indistinguishable from uniform random noise under M-LWE hardness.
//!
//! ## Key Structures
//!
//! - [`Poly`] — Polynomial in R_q = Z_q[X]/(X^N + 1)
//! - [`MasterIdentity`] — Holds the permanent master secret polynomial s
//! - [`EphemeralProjection`] — Single-use public projection for a given context τ
//! - [`ZkIdentityProof`] — ZK sigma protocol proof (W, c, z)
//! - [`Prover`] — Generates ZK identity proofs with rejection sampling
//! - [`Verifier`] — Verifies ZK proofs against ephemeral projections
//!
//! ## Parameters
//!
//! - N=256, Q=8380417, ETA=2, GAMMA1=2^17, BETA=78
//!
//! ## Domain Separators
//!
//! - Matrix generation: `"AETHEL_PLP_CTX_V1"`
//! - Challenge hash: `"AETHEL_PLP_CHALLENGE_V1"`

extern crate alloc;

use alloc::vec::Vec;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

use crate::identity_error::IdentityError;
use zeroize::{Zeroize, ZeroizeOnDrop};

// --- PARAMETERS (Module-LWE over R_q) ---
/// Ring degree N for X^N + 1.
pub const N: usize = 256;
/// Prime modulus q = 8_380_417 ≡ 1 (mod 512), NTT-compatible.
pub const Q: u32 = 8_380_417;
/// Secret key bound η = 2 (CBD).
pub const ETA: i32 = 2;
/// Masking vector bound γ₁ = 2^17.
pub const GAMMA1: i32 = 131_072;
/// Rejection sampling bound β = 78.
pub const BETA: i32 = 78;
/// Rejection threshold γ₁ - β.
pub const REJECTION_THRESHOLD: i32 = GAMMA1 - BETA;

// ── NTT parameters for q = 8_380_417 ─────────────────────────────────────────
//
// q = 8_380_417 = 2^23 - 2^13 + 1, primitive root g = 3
// For NTT of length 256 we need a primitive 512th root of unity.
// ζ = g^((q-1)/512) mod q = 3^16385 mod q = 1753
//
// Precomputed zeta table: ZETA[i] = ζ^(bitrev(i)) mod q for i in 0..128
// This is the standard Dilithium/Kyber NTT twiddle factor layout.



// ── Polynomial type ───────────────────────────────────────────────────────────

/// Polynomial in R_q = Z_q[X]/(X^N + 1).
/// Coefficients stored as u32 in [0, Q).
///
/// This type doubles as both public data (context matrices, projections, proof
/// components — all meant to cross the API boundary) and the storage for
/// [`MasterIdentity`]'s private `secret_key`. Because of that dual use it does
/// **not** derive `Debug`/`Display` (see P3-03: a type that can legitimately
/// hold raw secret key material must never support format-printing, even
/// though most instances of it hold public data) — see the compile-time
/// `assert_not_impl_any!` checks in `tests/no_debug_leak.rs`.
/// `coeffs` itself is `pub(crate)`, not `pub`: external code reads it only
/// through [`Poly::coeffs`], and can never construct or mutate one directly.
#[derive(Clone, Copy, PartialEq, Zeroize)]
pub struct Poly {
    pub(crate) coeffs: [u32; N],
}

impl Poly {
    /// Zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0u32; N] }
    }

    /// Read-only view of the coefficients.
    ///
    /// Safe to expose publicly: nothing in this crate ever returns a `Poly`
    /// wrapping [`MasterIdentity`]'s secret (`secret_key` is a private field
    /// with no accessor of any kind), so every `Poly` reachable through this
    /// method is public projection/proof data by construction.
    pub fn coeffs(&self) -> &[u32; N] {
        &self.coeffs
    }

    /// Polynomial addition mod q.
    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..N {
            res.coeffs[i] = add_mod(self.coeffs[i], other.coeffs[i]);
        }
        res
    }

    /// Polynomial subtraction mod q.
    #[inline]
    pub fn sub(&self, other: &Self) -> Self {
        let mut res = Self::zero();
        for i in 0..N {
            res.coeffs[i] = sub_mod(self.coeffs[i], other.coeffs[i]);
        }
        res
    }

    /// Schoolbook polynomial multiplication in R_q = Z_q[X]/(X^N + 1).
    /// O(N²) — used for challenge * secret (challenge is sparse).
    pub fn mul_schoolbook(&self, other: &Self) -> Self {
        let mut tmp = [0i64; 2 * N];
        for i in 0..N {
            for j in 0..N {
                tmp[i + j] += (self.coeffs[i] as i64) * (other.coeffs[j] as i64);
            }
        }
        let mut res = Self::zero();
        for i in 0..N {
            // Reduce mod X^N + 1: tmp[i + N] wraps with negation
            let v = (tmp[i] - tmp[i + N]).rem_euclid(Q as i64);
            res.coeffs[i] = v as u32;
        }
        res
    }

    /// Infinity norm (max absolute centered coefficient).
    pub fn infinity_norm(&self) -> i64 {
        let mut max_val = 0i64;
        for &c in self.coeffs.iter() {
            let centered = if c > Q / 2 { Q as i64 - c as i64 } else { c as i64 };
            if centered > max_val {
                max_val = centered;
            }
        }
        max_val
    }

    /// Center coefficients to [-q/2, q/2].
    pub fn center(&self) -> [i32; N] {
        let mut out = [0i32; N];
        for i in 0..N {
            let c = self.coeffs[i];
            out[i] = if c > Q / 2 { c as i32 - Q as i32 } else { c as i32 };
        }
        out
    }
}

// ── Modular arithmetic helpers ────────────────────────────────────────────────

#[inline(always)]
fn add_mod(a: u32, b: u32) -> u32 {
    let s = a + b;
    if s >= Q { s - Q } else { s }
}

#[inline(always)]
fn sub_mod(a: u32, b: u32) -> u32 {
    if a >= b { a - b } else { a + Q - b }
}

#[inline(always)]
fn mul_mod(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % Q as u64) as u32
}

// ── NTT implementation ────────────────────────────────────────────────────────
//
// We use a simple schoolbook NTT for correctness. The twiddle factors are
// powers of ζ = 1753 (a primitive 512th root of unity mod q=8380417).
// For N=256, we need ζ^2 as the primitive 256th root.
//
// Forward NTT: Cooley-Tukey butterfly, bit-reversed input order.
// Inverse NTT: Gentleman-Sande butterfly.

/// Compute ζ^k mod q using fast exponentiation.
fn pow_mod(mut base: u64, mut exp: u64, modulus: u64) -> u64 {
    let mut result = 1u64;
    base %= modulus;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * base % modulus;
        }
        exp >>= 1;
        base = base * base % modulus;
    }
    result
}

/// Bit-reverse an index of `bits` bits.
fn bit_reverse(mut x: usize, bits: usize) -> usize {
    let mut result = 0usize;
    for _ in 0..bits {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    result
}

/// In-place forward NTT over Z_q for a polynomial of degree N=256.
/// Uses Cooley-Tukey with ζ = 1753 (primitive 512th root of unity mod q).
/// The NTT operates on the negacyclic ring Z_q[X]/(X^256 + 1).
/// Primitive 512th root of unity mod q.
///
/// ψ^256 ≡ -1 (mod q), which is exactly what makes a transform over
/// R_q = Z_q[X]/(X^256 + 1) possible. The ring is **negacyclic**: the previous
/// implementation ran a cyclic NTT and used ψ as though it were a 256th root,
/// so `ntt_inverse(ntt_forward(x)) != x` and `poly_mul_ntt` disagreed with
/// `mul_schoolbook` on every coefficient (P3-14 / 0X3-84).
const PSI: u64 = 1753;

/// Standard cyclic radix-2 NTT: bit-reverse, then decimation-in-time.
///
/// Kept separate from the negacyclic wrappers so the ψ-weighting that makes the
/// transform negacyclic is visible at the call site rather than folded into the
/// butterflies.
fn cyclic_ntt(a: &mut [u64; N], root: u64, q: u64) {
    for i in 0..N {
        let j = bit_reverse(i, 8);
        if i < j {
            a.swap(i, j);
        }
    }

    let mut len = 1usize;
    while len < N {
        let w_len = pow_mod(root, (N / (2 * len)) as u64, q);
        let mut base = 0usize;
        while base < N {
            let mut w = 1u64;
            for j in 0..len {
                let u = a[base + j];
                let v = a[base + j + len] * w % q;
                a[base + j] = (u + v) % q;
                a[base + j + len] = (u + q - v) % q;
                w = w * w_len % q;
            }
            base += 2 * len;
        }
        len *= 2;
    }
}

/// In-place forward negacyclic NTT over R_q = Z_q[X]/(X^256 + 1).
///
/// Weights each coefficient by ψ^i, then runs a cyclic NTT with ω = ψ². The
/// weighting is what turns the cyclic transform into a negacyclic one.
///
/// Verified against [`Poly::mul_schoolbook`] by
/// `ntt_and_schoolbook_multiplication_agree`, and for self-inversion by
/// `ntt_forward_and_inverse_round_trip`.
pub fn ntt_forward(poly: &mut Poly) {
    let q = Q as u64;
    let omega = PSI * PSI % q;

    let mut a = [0u64; N];
    let mut psi_pow = 1u64;
    for i in 0..N {
        a[i] = (poly.coeffs[i] as u64) * psi_pow % q;
        psi_pow = psi_pow * PSI % q;
    }

    cyclic_ntt(&mut a, omega, q);

    for i in 0..N {
        poly.coeffs[i] = a[i] as u32;
    }
}

/// In-place inverse negacyclic NTT over R_q.
///
/// Runs the cyclic transform with ω⁻¹, scales by n⁻¹, then removes the ψ^i
/// weighting applied by [`ntt_forward`].
pub fn ntt_inverse(poly: &mut Poly) {
    let q = Q as u64;
    let omega = PSI * PSI % q;
    let omega_inv = pow_mod(omega, q - 2, q);
    let psi_inv = pow_mod(PSI, q - 2, q);
    let n_inv = pow_mod(N as u64, q - 2, q);

    let mut a = [0u64; N];
    for i in 0..N {
        a[i] = poly.coeffs[i] as u64;
    }

    cyclic_ntt(&mut a, omega_inv, q);

    let mut psi_inv_pow = 1u64;
    for i in 0..N {
        poly.coeffs[i] = (a[i] * n_inv % q * psi_inv_pow % q) as u32;
        psi_inv_pow = psi_inv_pow * psi_inv % q;
    }
}

/// Negacyclic polynomial multiplication via the NTT.
///
/// Equivalent to [`Poly::mul_schoolbook`] and asserted so by
/// `ntt_and_schoolbook_multiplication_agree`. That equivalence is the whole
/// contract of this function: a fast path that returns different answers from
/// the reference is worse than no fast path.
pub fn poly_mul_ntt(a: &Poly, b: &Poly) -> Poly {
    let q = Q as u64;
    let mut fa = *a;
    let mut fb = *b;
    ntt_forward(&mut fa);
    ntt_forward(&mut fb);

    let mut fc = Poly::zero();
    for i in 0..N {
        fc.coeffs[i] = ((fa.coeffs[i] as u64) * (fb.coeffs[i] as u64) % q) as u32;
    }

    ntt_inverse(&mut fc);
    fc
}


// ── SHAKE-256 matrix generation ───────────────────────────────────────────────

/// Derive the context matrix A_τ from a context tag τ using SHAKE-256.
///
/// A_τ ← SHAKE-256("AETHEL_PLP_CTX_V1" ∥ τ)
/// Each coefficient is sampled by reading 3 bytes and rejection-sampling mod q.
pub fn derive_context_matrix_k1(tau: &[u8]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_PLP_CTX_V1");
    hasher.update(tau);
    let mut xof = hasher.finalize_xof();

    let mut poly = Poly::zero();
    let mut coeff_idx = 0usize;
    while coeff_idx < N {
        let mut buf = [0u8; 3];
        xof.read(&mut buf);
        let val = (buf[0] as u32)
            | ((buf[1] as u32) << 8)
            | ((buf[2] as u32 & 0x7F) << 16);
        if val < Q {
            poly.coeffs[coeff_idx] = val;
            coeff_idx += 1;
        }
    }
    poly
}

/// Sample a small polynomial from CBD η=2 using SHAKE-256 output.
fn sample_cbd_eta2_from_xof(xof: &mut impl XofReader) -> Poly {
    let mut poly = Poly::zero();
    // Each coefficient needs 4 bits → 1 byte per 2 coefficients
    // We read N/2 bytes = 128 bytes
    let mut buf = [0u8; N]; // 1 byte per coefficient (use lower 4 bits)
    xof.read(&mut buf);
    for i in 0..N {
        let byte = buf[i];
        let a0 = (byte & 0x01) as i32;
        let a1 = ((byte >> 1) & 0x01) as i32;
        let b0 = ((byte >> 2) & 0x01) as i32;
        let b1 = ((byte >> 3) & 0x01) as i32;
        let coeff = (a0 + a1) - (b0 + b1); // in {-2,-1,0,1,2}
        poly.coeffs[i] = (coeff.rem_euclid(Q as i32)) as u32;
    }
    poly
}

/// Sample a masking polynomial from uniform [-γ₁, γ₁] using SHAKE-256.
fn sample_mask_from_xof(xof: &mut impl XofReader) -> Poly {
    let mut poly = Poly::zero();
    let range = 2 * GAMMA1 as u32 + 1; // 262145
    let mut coeff_idx = 0usize;
    while coeff_idx < N {
        let mut buf = [0u8; 3];
        xof.read(&mut buf);
        let val = (buf[0] as u32)
            | ((buf[1] as u32) << 8)
            | ((buf[2] as u32 & 0x7F) << 16);
        if val < range {
            // Center: val in [0, 2*γ₁] → coeff in [-γ₁, γ₁]
            let centered = val as i32 - GAMMA1;
            poly.coeffs[coeff_idx] = centered.rem_euclid(Q as i32) as u32;
            coeff_idx += 1;
        }
    }
    poly
}

// ── Challenge hash ────────────────────────────────────────────────────────────

/// Hash-to-challenge: produce a sparse ternary polynomial with exactly 60 ±1 coefficients.
///
/// c = HashToPoly(SHAKE-256("AETHEL_PLP_CHALLENGE_V1" ∥ w ∥ ctx))
pub fn hash_to_challenge(w: &Poly, ctx: u64) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_PLP_CHALLENGE_V1");
    for &c in w.coeffs.iter() {
        hasher.update(&c.to_le_bytes());
    }
    hasher.update(&ctx.to_le_bytes());
    let mut xof = hasher.finalize_xof();

    // Sample 60 distinct positions in [0, N) without replacement
    // Use Dilithium-style rejection sampling: build a set of 60 distinct indices
    // by sampling bytes and using a running counter with rejection.
    let mut c_poly = Poly::zero();

    // Use the standard approach: sample 60 positions using a sign+position byte stream
    // Read bytes from XOF: use each byte as a position candidate (mod N) with sign from high bit
    // Use rejection sampling to ensure exactly 60 distinct positions.
    let mut signs = [0u8; 8]; // 64 sign bits
    xof.read(&mut signs);
    let mut sign_bit = 0usize;

    let mut count = 0usize;
    let mut used = [false; N];
    let mut pos_buf = [0u8; 1];

    while count < 60 {
        xof.read(&mut pos_buf);
        let pos = pos_buf[0] as usize;
        if pos >= N {
            continue; // rejection: pos must be in [0, 255]
        }
        if used[pos] {
            continue; // rejection: already selected this position
        }
        used[pos] = true;
        // Get sign bit
        let sign_byte = signs[sign_bit / 8];
        let sign: i32 = if (sign_byte >> (sign_bit % 8)) & 1 == 0 { 1 } else { -1 };
        sign_bit += 1;
        if sign_bit >= 64 {
            // Refresh sign bits
            xof.read(&mut signs);
            sign_bit = 0;
        }
        c_poly.coeffs[pos] = sign.rem_euclid(Q as i32) as u32;
        count += 1;
    }
    c_poly
}

// ── Master Identity ───────────────────────────────────────────────────────────

/// Holds the permanent master secret polynomial s.
///
/// **L1-internal.** `secret_key` is a private field with no accessor of any
/// kind — no public function on this crate's entire API surface returns,
/// clones, or otherwise exposes it. The only code that ever touches raw
/// secret key material is inside this `impl` block and [`Prover::prove_identity`]
/// (same module), both of which need it to do the actual lattice arithmetic;
/// per the charter's L1/L2/L3 model, that access is L1-internal by design —
/// what must never happen is a *public* path returning it, which is what
/// P3-03 closes off here. See also the `assert_not_impl_any!` check in
/// `tests/no_debug_leak.rs` proving this type has no `Debug`/`Display` impl
/// that could format-leak it if a caller with legitimate internal access ever
/// tried to print it.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterIdentity {
    secret_key: Poly,
}

impl MasterIdentity {
    /// Create a new master identity from a 32-byte seed.
    ///
    /// Uses SHAKE-256("AETHEL_MASTER_KEY_V1" ∥ seed) to derive s via CBD η=2.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(b"AETHEL_MASTER_KEY_V1");
        hasher.update(seed);
        let mut xof = hasher.finalize_xof();
        let secret_key = sample_cbd_eta2_from_xof(&mut xof);
        Self { secret_key }
    }

    /// Derive a single-use polymorphic public projection for context τ.
    ///
    /// `b_τ = A_τ · s + e_τ (mod q)`, where `A_τ ← SHAKE-256("AETHEL_PLP_CTX_V1" ∥ τ)`
    /// and `e_τ ← CBD η=2` sampled from the caller-supplied fresh randomness `rho`.
    ///
    /// ## `rho` MUST be fresh, secret entropy — at least 32 bytes
    ///
    /// The error term is what makes `b_τ` an M-LWE sample rather than an exact
    /// linear image of the secret. It only hides `s` if it is unknown to the
    /// verifier. An earlier version derived `e_τ` from `τ` alone (public), so
    /// anyone who knew the context could recompute and subtract it, recovering
    /// `A_τ·s` from a single projection. Deriving it from fresh secret `rho`
    /// closes that: with `rho` unknown, one projection is a sound M-LWE sample.
    ///
    /// ## τ MUST be single-use
    ///
    /// `A_τ` is a deterministic function of `τ`, so projecting the *same*
    /// identity at the *same* `τ` more than once yields many samples
    /// `b_i = A_τ·s + e_i` sharing one `A_τ`. Because `e ← CBD` is centered,
    /// averaging enough of them recovers `A_τ·s` regardless of how fresh each
    /// `e_i` is. The projection is called *ephemeral* for this reason: each `τ`
    /// (e.g. a block height) is consumed once. Callers reusing `τ` void the
    /// hiding guarantee. (Closing this for reused `τ` — freshening `A` per
    /// projection — is a design question flagged for review, not a defect in
    /// single-use operation.)
    pub fn project_at_context(&self, tau: &[u8], rho: &[u8]) -> EphemeralProjection {
        // Derive context-bound matrix A_τ deterministically
        let matrix_a = derive_context_matrix_k1(tau);

        // Generate ephemeral error e_τ ← CBD η=2 from fresh secret randomness.
        // Bound to τ as well, so an accidentally-reused rho still yields a
        // distinct e_τ per context (defence in depth; freshness of rho is the
        // primary guarantee).
        let mut hasher = Shake256::default();
        hasher.update(b"AETHEL_ERROR_V2");
        hasher.update(rho);
        hasher.update(tau);
        let mut xof = hasher.finalize_xof();
        let mut e_tau = sample_cbd_eta2_from_xof(&mut xof);

        // b_τ = A_τ · s + e_τ
        let public_b = matrix_a.mul_schoolbook(&self.secret_key).add(&e_tau);
        // e_tau is secret-derived noise with no further use past this point —
        // wipe it explicitly rather than letting it fall out of scope (Poly is
        // Copy and cannot implement Drop, so nothing wipes it automatically).
        e_tau.zeroize();

        EphemeralProjection {
            tau: {
                let mut t = [0u8; 32];
                let len = tau.len().min(32);
                t[..len].copy_from_slice(&tau[..len]);
                t
            },
            matrix_a,
            public_b,
        }
    }
}

/// Project a master identity at context τ from raw secret bytes, validating
/// the secret length first.
///
/// This mirrors the `plp-project-at-context` operation in the `aethel:core`
/// WIT world (`dist/aethel_core.wit`): a 32-byte seed in, `result<ephemeral-projection,
/// identity-error>` out. [`MasterIdentity::from_seed`] takes an already-sized
/// `[u8; 32]` and so cannot itself observe a wrong-length input; this is the
/// entry point that actually validates it.
///
/// `rho` MUST be at least 32 bytes of fresh, secret entropy — see
/// [`MasterIdentity::project_at_context`] for why. A short `rho` is rejected
/// rather than silently weakening the projection.
pub fn checked_project_at_context(
    secret: &[u8],
    tau: &[u8],
    rho: &[u8],
) -> Result<EphemeralProjection, IdentityError> {
    if secret.len() != 32 {
        return Err(IdentityError::InvalidInputLength);
    }
    if rho.len() < 32 {
        return Err(IdentityError::InvalidInputLength);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(secret);
    let identity = MasterIdentity::from_seed(&seed);
    Ok(identity.project_at_context(tau, rho))
}

// ── Ephemeral Projection ──────────────────────────────────────────────────────

/// Byte length of an [`EphemeralProjection`] as encoded by [`EphemeralProjection::to_bytes`]:
/// `tau(32) + matrix_a coeffs(N*4) + public_b coeffs(N*4)`.
pub const EPHEMERAL_PROJECTION_BYTE_LEN: usize = 32 + N * 4 + N * 4;

/// Single-use public projection for a given context τ.
#[derive(Clone)]
pub struct EphemeralProjection {
    /// Context tag τ (truncated/padded to 32 bytes).
    pub tau: [u8; 32],
    /// Context-bound matrix A_τ.
    pub matrix_a: Poly,
    /// Public projection b_τ = A_τ · s + e_τ.
    pub public_b: Poly,
}

impl EphemeralProjection {
    /// A projection carrying only `A_τ` and `τ`, with `public_b` left zero.
    ///
    /// Used by the prover path. [`Prover::prove_identity`] reads only
    /// `matrix_a` and `tau` — the proof `(w, c, z)` is *independent of* `e_τ`,
    /// because the verifier's `A_τ·z − c·b_τ ≈ w` check absorbs the `c·e_τ`
    /// term within its norm tolerance. So proving needs no fresh randomness and
    /// no real `b_τ`, and a proof made here verifies against any correctly
    /// formed `b_τ = A_τ·s + (small e_τ)` the holder publishes separately via
    /// [`MasterIdentity::project_at_context`].
    ///
    /// `pub(crate)` on purpose: the zero `public_b` is not a real projection and
    /// must never escape as one.
    pub(crate) fn for_proving(tau: &[u8]) -> Self {
        let matrix_a = derive_context_matrix_k1(tau);
        let mut t = [0u8; 32];
        let len = tau.len().min(32);
        t[..len].copy_from_slice(&tau[..len]);
        EphemeralProjection {
            tau: t,
            matrix_a,
            public_b: Poly::zero(),
        }
    }

    /// Encode as `tau(32) ++ matrix_a.coeffs(N*4, LE) ++ public_b.coeffs(N*4, LE)`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; EPHEMERAL_PROJECTION_BYTE_LEN];
        out[..32].copy_from_slice(&self.tau);
        for (i, &c) in self.matrix_a.coeffs.iter().enumerate() {
            let offset = 32 + i * 4;
            out[offset..offset + 4].copy_from_slice(&c.to_le_bytes());
        }
        for (i, &c) in self.public_b.coeffs.iter().enumerate() {
            let offset = 32 + N * 4 + i * 4;
            out[offset..offset + 4].copy_from_slice(&c.to_le_bytes());
        }
        out
    }

    /// Decode from the layout produced by [`Self::to_bytes`].
    ///
    /// Returns `IdentityError::SerializationError` if `bytes` is shorter than
    /// [`EPHEMERAL_PROJECTION_BYTE_LEN`] — this is the deserialization path
    /// for the `ephemeral-projection` record in the `aethel:core` WIT world.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() < EPHEMERAL_PROJECTION_BYTE_LEN {
            return Err(IdentityError::SerializationError);
        }
        let mut tau = [0u8; 32];
        tau.copy_from_slice(&bytes[..32]);

        let mut matrix_a = Poly::zero();
        for i in 0..N {
            let offset = 32 + i * 4;
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            matrix_a.coeffs[i] = u32::from_le_bytes(b);
        }

        let mut public_b = Poly::zero();
        for i in 0..N {
            let offset = 32 + N * 4 + i * 4;
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            public_b.coeffs[i] = u32::from_le_bytes(b);
        }

        Ok(Self { tau, matrix_a, public_b })
    }
}

// ── ZK Identity Proof ─────────────────────────────────────────────────────────

/// ZK sigma protocol proof (W, c, z).
#[derive(Clone)]
pub struct ZkIdentityProof {
    /// Commitment W = A_τ · y.
    pub commitment_w: Poly,
    /// Fiat-Shamir challenge c.
    pub challenge_c: Poly,
    /// Response z = y + c · s.
    pub response_z: Poly,
}

// ── Prover ────────────────────────────────────────────────────────────────────

/// Generates ZK identity proofs using constant-time rejection sampling.
pub struct Prover;

impl Prover {
    /// Prove knowledge of master secret `s` for projection `b_τ`. **L1-internal**:
    /// takes `identity: &MasterIdentity` and reaches into its private
    /// `secret_key` field (same module) to do the lattice arithmetic — this is
    /// the one place outside `MasterIdentity`'s own `impl` block that
    /// legitimately touches raw key material, per the charter's L1/L2/L3
    /// model. It never returns it: only the public `commitment_w`/`challenge_c`/
    /// `response_z` triple (the ZK proof, safe to disclose by construction)
    /// leaves this function.
    ///
    /// Uses a fixed 16-iteration loop with SHAKE-256 masking vectors.
    /// Returns the first valid proof, or the last candidate if all 16 fail.
    ///
    /// Every intermediate that touches `secret_key` (`cs`) or blinds it (`y`)
    /// is explicitly zeroized once consumed — `Poly` is `Copy` and so cannot
    /// implement `Drop`, meaning nothing wipes these automatically when they
    /// fall out of scope. On a **rejected** iteration, `w`/`challenge_c`/`z`
    /// are zeroized too before looping: rejection sampling's security proof
    /// depends on a rejected response never being observable (that is the
    /// entire reason for rejecting it), so those values must not merely go
    /// unused — they must be wiped.
    pub fn prove_identity(
        identity: &MasterIdentity,
        proj: &EphemeralProjection,
        seed: &[u8; 32],
    ) -> ZkIdentityProof {
        for iter in 0u8..16 {
            // 1. Sample masking polynomial y ~ uniform [-γ₁, γ₁]
            let mut hasher = Shake256::default();
            hasher.update(b"AETHEL_MASK_V2");
            hasher.update(seed);
            // Bind the context. Without τ here, the mask is a function of
            // (seed, iter) alone, so two proofs of the same identity at
            // different contexts share y while their challenges differ:
            //
            //   z₁ = y + c₁·s,  z₂ = y + c₂·s  ⇒  z₁ − z₂ = (c₁ − c₂)·s
            //
            // which recovers s outright. That was demonstrated against 64/64
            // sampled identities before this line existed (P3-15 / 0X3-85).
            // Deterministic masks are fine — Dilithium and RFC 6979 both use
            // them — but only when the derivation binds what is being proven.
            hasher.update(&proj.tau);
            hasher.update(&[iter]);
            let mut xof = hasher.finalize_xof();
            let mut y = sample_mask_from_xof(&mut xof);

            // 2. Compute commitment W = A_τ · y
            let mut w = proj.matrix_a.mul_schoolbook(&y);

            // 3. Compute Fiat-Shamir challenge c = HashToPoly(W, τ_ctx)
            let ctx_u64 = u64::from_le_bytes(proj.tau[..8].try_into().unwrap_or([0u8; 8]));
            let mut challenge_c = hash_to_challenge(&w, ctx_u64);

            // 4. Compute candidate response z = y + c · s
            let mut cs = challenge_c.mul_schoolbook(&identity.secret_key);
            let mut z = y.add(&cs);

            // y and cs are pure intermediates — never part of the returned
            // proof either way — safe to wipe immediately after use.
            y.zeroize();
            cs.zeroize();

            // 5. Rejection sampling: ||z||∞ < γ₁ - β
            if z.infinity_norm() < REJECTION_THRESHOLD as i64 {
                return ZkIdentityProof {
                    commitment_w: w,
                    challenge_c,
                    response_z: z,
                };
            }

            // Rejected: w/challenge_c/z must not survive to the next
            // iteration or fall out unwiped.
            w.zeroize();
            challenge_c.zeroize();
            z.zeroize();
        }

        // Fallback: return last candidate (should not happen in practice)
        // This path is taken only if all 16 iterations are rejected
        let mut hasher = Shake256::default();
        hasher.update(b"AETHEL_MASK_V1");
        hasher.update(seed);
        hasher.update(&[0u8]);
        let mut xof = hasher.finalize_xof();
        let mut y = sample_mask_from_xof(&mut xof);
        let w = proj.matrix_a.mul_schoolbook(&y);
        let ctx_u64 = u64::from_le_bytes(proj.tau[..8].try_into().unwrap_or([0u8; 8]));
        let challenge_c = hash_to_challenge(&w, ctx_u64);
        let mut cs = challenge_c.mul_schoolbook(&identity.secret_key);
        let z = y.add(&cs);
        y.zeroize();
        cs.zeroize();
        ZkIdentityProof {
            commitment_w: w,
            challenge_c,
            response_z: z,
        }
    }
}

// ── Verifier ──────────────────────────────────────────────────────────────────

/// Verifies ZK proofs against ephemeral projections.
pub struct Verifier;

impl Verifier {
    /// Verify the ZK proof against the ephemeral public projection.
    ///
    /// Checks:
    /// 1. ||z||∞ < γ₁ - β
    /// 2. Challenge consistency: c' = HashToPoly(W, τ)
    /// 3. Verification equation: A_τ · z - c · b_τ ≈ W (mod small noise)
    pub fn verify(proj: &EphemeralProjection, proof: &ZkIdentityProof) -> bool {
        // 1. Check response norm bound: ||z||∞ < γ₁ - β
        if proof.response_z.infinity_norm() >= REJECTION_THRESHOLD as i64 {
            return false;
        }

        // 2. Re-compute Fiat-Shamir challenge c'
        let ctx_u64 = u64::from_le_bytes(proj.tau[..8].try_into().unwrap_or([0u8; 8]));
        let recomputed_c = hash_to_challenge(&proof.commitment_w, ctx_u64);

        // Constant-time challenge comparison
        let mut mismatch = 0u32;
        for i in 0..N {
            mismatch |= recomputed_c.coeffs[i] ^ proof.challenge_c.coeffs[i];
        }
        if mismatch != 0 {
            return false;
        }

        // 3. Verify equation: A_τ · z - c · b_τ ≈ W
        // W' = A_τ · z - c · b_τ
        let az = proj.matrix_a.mul_schoolbook(&proof.response_z);
        let cb = proof.challenge_c.mul_schoolbook(&proj.public_b);
        let w_prime = az.sub(&cb);

        // In LWE with small noise, W and W' differ by c · e_τ (small)
        let diff = w_prime.sub(&proof.commitment_w);
        diff.infinity_norm() < (BETA as i64 * 2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed() -> [u8; 32] {
        [0x42u8; 32]
    }

    /// Fixed fresh-randomness for e_τ in tests. Production MUST sample this per
    /// projection.
    fn test_rho() -> [u8; 32] {
        [0xa5u8; 32]
    }

    // ── Sigma-protocol mask reuse (found 2026-08-28) ─────────────────────────

    /// `prove_identity` derives its masking polynomial as
    /// `y = sample_mask(SHAKE256("AETHEL_MASK_V1" || seed || iter))`. The
    /// context tau does not enter, so two proofs of the same identity at two
    /// different contexts share `y` while their challenges differ.
    ///
    /// That is nonce reuse in a Schnorr-style sigma protocol:
    ///
    /// ```text
    /// z1 = y + c1*s ; z2 = y + c2*s ; z1 - z2 = (c1 - c2)*s
    /// ```
    ///
    /// This test performs the recovery with public arithmetic and checks the
    /// result against the PUBLIC projection. It is written to be run.
    const ATTACK_Q: i64 = 8_380_417;

    fn attack_mod_inv(a: i64) -> i64 {
        let mut result = 1i64;
        let mut base = a.rem_euclid(ATTACK_Q);
        let mut exp = ATTACK_Q - 2;
        while exp > 0 {
            if exp & 1 == 1 { result = (result * base) % ATTACK_Q; }
            base = (base * base) % ATTACK_Q;
            exp >>= 1;
        }
        result
    }

    fn attack_centered(x: i64) -> i64 {
        let r = x.rem_euclid(ATTACK_Q);
        if r > ATTACK_Q / 2 { r - ATTACK_Q } else { r }
    }

    fn attack_sub(a: &Poly, b: &Poly) -> Poly {
        let mut out = Poly::zero();
        for i in 0..N {
            out.coeffs[i] = (a.coeffs[i] as i64 - b.coeffs[i] as i64)
                .rem_euclid(ATTACK_Q) as u32;
        }
        out
    }

    fn attack_ring_divide(num: &Poly, den: &Poly) -> Option<Poly> {
        let mut n = *num;
        let mut d = *den;
        ntt_forward(&mut n);
        ntt_forward(&mut d);
        let mut q = Poly::zero();
        for i in 0..N {
            let di = d.coeffs[i] as i64 % ATTACK_Q;
            if di == 0 { return None; }
            let ni = n.coeffs[i] as i64 % ATTACK_Q;
            q.coeffs[i] = ((ni * attack_mod_inv(di)) % ATTACK_Q) as u32;
        }
        ntt_inverse(&mut q);
        Some(q)
    }

    /// The most basic NTT property: the inverse transform must undo the forward
    /// one. If this fails, `poly_mul_ntt` cannot be correct and neither can
    /// anything built on the NTT path.
    #[test]
    fn ntt_forward_and_inverse_round_trip() {
        let mut original = Poly::zero();
        for i in 0..N {
            original.coeffs[i] = ((i * 13 + 5) % 4096) as u32;
        }

        let mut round_tripped = original;
        ntt_forward(&mut round_tripped);
        ntt_inverse(&mut round_tripped);

        let mut mismatches = 0usize;
        for i in 0..N {
            if original.coeffs[i] != round_tripped.coeffs[i] {
                mismatches += 1;
            }
        }
        assert_eq!(
            mismatches, 0,
            "ntt_inverse(ntt_forward(x)) != x on {}/{} coefficients - the NTT              is not self-inverse",
            mismatches, N
        );
    }

    /// Diagnostic: do the crate's two multiplication routines agree?
    ///
    /// `mul_schoolbook` is what the prover and verifier use. `poly_mul_ntt` is
    /// the NTT path. If they disagree, any analysis that mixes them - including
    /// the mask-reuse recovery attempt above - is invalid, and so is anything
    /// else that assumes the NTT is a drop-in for the schoolbook multiply.
    #[test]
    fn ntt_and_schoolbook_multiplication_agree() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.coeffs[i] = ((i * 31 + 7) % 1000) as u32;
            b.coeffs[i] = ((i * 17 + 3) % 1000) as u32;
        }

        let school = a.mul_schoolbook(&b);
        let ntt = poly_mul_ntt(&a, &b);

        let mut mismatches = 0usize;
        for i in 0..N {
            if school.coeffs[i] != ntt.coeffs[i] {
                mismatches += 1;
            }
        }
        assert_eq!(
            mismatches, 0,
            "mul_schoolbook and poly_mul_ntt disagree on {}/{} coefficients",
            mismatches, N
        );
    }

    /// Positive control for the recovery machinery above.
    ///
    /// Synthesises the exact algebraic situation the attack assumes — one shared
    /// mask, two different challenges — and asserts the attack recovers the
    /// secret. Without this, a "0 recoveries" result from the sweep is
    /// indistinguishable from broken arithmetic, and would be a test that cannot
    /// fail rather than a test that passed.
    #[test]
    fn the_recovery_machinery_works_when_a_mask_is_genuinely_shared() {
        let identity = MasterIdentity::from_seed(&test_seed());
        let proj = identity.project_at_context(b"ctx", &test_rho());

        // A shared mask, and two distinct challenges.
        let mut y = Poly::zero();
        for i in 0..N {
            y.coeffs[i] = ((i as u64 * 7919 + 13) % 100_000) as u32;
        }
        let c1 = hash_to_challenge(&proj.matrix_a, 1);
        let c2 = hash_to_challenge(&proj.matrix_a, 2);
        assert_ne!(c1.coeffs, c2.coeffs, "setup: challenges must differ");

        // z = y + c*s, with s the real secret this identity holds.
        let z1 = y.add(&c1.mul_schoolbook(&identity.secret_key));
        let z2 = y.add(&c2.mul_schoolbook(&identity.secret_key));

        let recovered = attack_ring_divide(&attack_sub(&z1, &z2), &attack_sub(&c1, &c2))
            .expect("control: the challenge difference should be invertible");

        let mut max_abs = 0i64;
        for i in 0..N {
            max_abs = max_abs.max(attack_centered(recovered.coeffs[i] as i64).abs());
        }
        assert!(
            max_abs <= 4,
            "the recovery machinery FAILED on a synthetic shared-mask case              (recovered infinity norm {}). The sweep's result is therefore              meaningless - fix this before drawing any conclusion from it.",
            max_abs
        );

        // And it is really the secret, not just something small.
        for i in 0..N {
            assert_eq!(
                attack_centered(recovered.coeffs[i] as i64),
                attack_centered(identity.secret_key.coeffs[i] as i64),
                "recovered coefficient {} does not match the real secret", i
            );
        }
    }

    #[test]
    fn two_proofs_at_different_contexts_do_not_leak_the_secret() {
        // The mask depends on (seed, iter). Rejection sampling means two
        // contexts often accept at DIFFERENT iterations, in which case the mask
        // differs and the attack fails. But when both accept at the same
        // iteration - which happens by chance, not by design - the mask is
        // shared and the secret falls out.
        //
        // So one sample proves nothing. Sweep, and count.
        let mut attempts = 0usize;
        let mut recoveries = 0usize;
        let mut first_hit = None;

        for k in 0u8..64 {
            let seed = [k.wrapping_mul(7).wrapping_add(1); 32];
            let identity = MasterIdentity::from_seed(&seed);

            let proj1 = identity.project_at_context(b"context-one", &[0x11u8; 32]);
            let proj2 = identity.project_at_context(b"context-two", &[0x22u8; 32]);

            let p1 = Prover::prove_identity(&identity, &proj1, &seed);
            let p2 = Prover::prove_identity(&identity, &proj2, &seed);

            if p1.challenge_c.coeffs == p2.challenge_c.coeffs {
                continue;
            }
            attempts += 1;

            let z_diff = attack_sub(&p1.response_z, &p2.response_z);
            let c_diff = attack_sub(&p1.challenge_c, &p2.challenge_c);

            let recovered = match attack_ring_divide(&z_diff, &c_diff) {
                Some(s) => s,
                None => continue,
            };

            // The master secret is CBD(eta=2): every coefficient in [-2, 2].
            // A wrong recovery is uniform over a ~2^23 field, so this is a
            // decisive test, not a heuristic.
            let mut max_abs = 0i64;
            for i in 0..N {
                max_abs = max_abs.max(attack_centered(recovered.coeffs[i] as i64).abs());
            }
            if max_abs <= 4 {
                recoveries += 1;
                if first_hit.is_none() {
                    first_hit = Some((k, max_abs));
                }
            }
        }

        std::eprintln!(
            "mask-reuse sweep: {}/{} pairs leaked a small-norm secret (first: {:?})",
            recoveries, attempts, first_hit
        );

        assert_eq!(
            recoveries, 0,
            "MASTER SECRET RECOVERED from two proofs at different contexts, in              {}/{} sampled identities. prove_identity derives its mask from              (seed, iter) only - tau never enters - so whenever two contexts              accept at the same rejection-sampling iteration they share y, and              z1 - z2 = (c1 - c2)*s reveals the secret. Recovered polynomials              have infinity norm <= 4, matching CBD(eta=2); a wrong guess would              be uniform over a 2^23 field.",
            recoveries, attempts
        );
    }

    #[test]
    fn test_poly_add_sub() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        a.coeffs[0] = 100;
        b.coeffs[0] = 200;
        let c = a.add(&b);
        assert_eq!(c.coeffs[0], 300);
        let d = c.sub(&b);
        assert_eq!(d.coeffs[0], 100);
    }

    #[test]
    fn test_derive_context_matrix_deterministic() {
        let tau = b"test_context_tau";
        let a1 = derive_context_matrix_k1(tau);
        let a2 = derive_context_matrix_k1(tau);
        assert_eq!(a1.coeffs, a2.coeffs);
        // All coefficients should be in [0, Q)
        for &c in a1.coeffs.iter() {
            assert!(c < Q, "coefficient {} >= Q", c);
        }
    }

    #[test]
    fn test_hash_to_challenge_sparse() {
        let w = Poly::zero();
        let c = hash_to_challenge(&w, 1000u64);
        // Count non-zero coefficients — should be exactly 60
        let nonzero = c.coeffs.iter().filter(|&&x| x != 0).count();
        assert_eq!(nonzero, 60, "challenge should have exactly 60 non-zero coefficients");
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let seed = test_seed();
        let identity = MasterIdentity::from_seed(&seed);
        let tau = b"block_1000_context";
        let proj = identity.project_at_context(tau, &test_rho());
        let proof = Prover::prove_identity(&identity, &proj, &seed);
        assert!(Verifier::verify(&proj, &proof), "proof should verify");
    }

    #[test]
    fn test_cross_context_unlinkability() {
        let seed = test_seed();
        let identity = MasterIdentity::from_seed(&seed);
        let proj1 = identity.project_at_context(b"context_1", &test_rho());
        let proj2 = identity.project_at_context(b"context_2", &test_rho());
        // Projections should differ
        assert_ne!(proj1.public_b.coeffs, proj2.public_b.coeffs);
        // Proof for context 1 should not verify against context 2
        let proof1 = Prover::prove_identity(&identity, &proj1, &seed);
        assert!(!Verifier::verify(&proj2, &proof1), "cross-context replay should fail");
    }

    // ── P3-03: moved from tests/plp_tests.rs ─────────────────────────────────
    //
    // These need direct access to `MasterIdentity.secret_key` / `Poly.coeffs`
    // to check secret-key properties (non-zero, in-range, uniqueness) and to
    // mutate a proof's response for a tampering test. Both fields are private
    // to this module now (P3-03), so external `tests/*.rs` integration tests
    // can no longer reach them — that's the point. Unit tests in this
    // module still can, same as any other crate-internal code.

    #[test]
    fn test_key_generation() {
        let seed = test_seed();
        let identity = MasterIdentity::from_seed(&seed);

        let all_zero = identity.secret_key.coeffs.iter().all(|&c| c == 0);
        assert!(!all_zero, "Secret key should not be all-zero (negligible probability)");

        for &coeff in identity.secret_key.coeffs.iter() {
            assert!(coeff < Q, "Secret key coefficient {} out of range [0, Q-1]", coeff);
        }
    }

    #[test]
    fn test_key_generation_uniqueness() {
        let identity_a = MasterIdentity::from_seed(&test_seed());
        let identity_b = MasterIdentity::from_seed(&[0xABu8; 32]);

        let keys_equal = identity_a
            .secret_key
            .coeffs
            .iter()
            .zip(identity_b.secret_key.coeffs.iter())
            .all(|(a, b)| a == b);

        assert!(!keys_equal, "Two independently generated secret keys should differ");
    }

    #[test]
    fn test_tampered_proof_rejected() {
        let seed = test_seed();
        let identity = MasterIdentity::from_seed(&seed);

        let tau = b"tamper_test_context_777";
        let proj = identity.project_at_context(tau, &test_rho());
        let mut proof = Prover::prove_identity(&identity, &proj, &seed);

        // Tamper with the first coefficient of the response vector
        proof.response_z.coeffs[0] = proof.response_z.coeffs[0].wrapping_add(1);

        let valid = Verifier::verify(&proj, &proof);
        assert!(!valid, "Tampered proof should be rejected by the verifier");
    }

    // ── P3-08: zeroization ────────────────────────────────────────────────────
    //
    // What this proves, and what it deliberately does NOT attempt: reading
    // memory *after* a value is dropped is unsound in general (the allocation
    // may be reused or, for heap memory, freed) — the task instructions
    // explicitly warn against a test that "looks like it proves this but
    // doesn't". Instead, this combines two independently sound checks, the
    // same technique the `zeroize` crate's own test suite
    // (zeroize-1.9.0/tests/zeroize_derive.rs) uses for exactly this property:
    //
    //   1. `core::mem::needs_drop::<MasterIdentity>()` — a purely structural,
    //      100% safe check that `#[derive(ZeroizeOnDrop)]` actually generated
    //      a `Drop` impl. This is `false` (test fails) if the derive is
    //      missing, or if it silently couldn't apply.
    //   2. Calling `.zeroize()` explicitly (the exact method
    //      `ZeroizeOnDrop`'s generated `drop()` calls) and checking the now
    //      *live* object's fields are zero — no UB, the object is still
    //      valid and owned.
    //
    // `zeroize_derive`'s generated `Drop::drop` is a documented, deterministic
    // `{ self.zeroize(); }` — given (1) proves that Drop exists and (2) proves
    // zeroize() is correct, together they prove dropping the value zeroizes
    // it, without ever reading freed memory.
    fn assert_master_identity_zeroizes() {
        assert!(
            core::mem::needs_drop::<MasterIdentity>(),
            "MasterIdentity must carry Drop glue for ZeroizeOnDrop to do anything on scope exit"
        );

        let seed = [0x77u8; 32];
        let mut identity = MasterIdentity::from_seed(&seed);
        assert!(
            identity.secret_key.coeffs.iter().any(|&c| c != 0),
            "sanity check: this seed should produce a non-zero secret key"
        );

        identity.zeroize();

        assert!(
            identity.secret_key.coeffs.iter().all(|&c| c == 0),
            "zeroize() must clear every coefficient of the secret key"
        );
    }

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn zeroize_wipes_master_identity_secret() {
        assert_master_identity_zeroizes();
    }

    // No `wasm_bindgen_test_configure!` needed: node execution (what
    // `wasm-pack test --node` uses) is the default when nothing configures
    // `run_in_browser` / `run_in_worker`.
    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen_test::wasm_bindgen_test]
    fn zeroize_wipes_master_identity_secret_wasm() {
        assert_master_identity_zeroizes();
    }
}
