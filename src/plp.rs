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
/// Re-derive the ephemeral error `e_τ` from the projection randomness.
///
/// `e_τ` is a deterministic function of `(rho, tau)`, which is what lets a
/// prover recover it without it ever being stored: `project_at_context` wipes
/// its copy immediately, and anything needing `e_τ` as a witness derives it
/// again from the same inputs.
///
/// SAAP's identity-linkage relation needs exactly that. Proving knowledge of
/// `s` alone against `b_τ = A_τ·s + e_τ` cannot close the verification equation,
/// because `A_τ·z_s − c·b_τ` leaves a residual `−c·e_τ`. Treating `e_τ` as part
/// of the witness removes the residual instead of tolerating it.
///
/// Bound to τ as well as rho, so an accidentally reused rho still yields a
/// distinct `e_τ` per context. Freshness of rho remains the primary guarantee.
///
/// This is the single definition. `project_at_context` calls it too, so the
/// projection and the proof witness cannot drift apart.
pub(crate) fn derive_error_tau(rho: &[u8], tau: &[u8]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_ERROR_V2");
    hasher.update(rho);
    hasher.update(tau);
    let mut xof = hasher.finalize_xof();
    sample_cbd_eta2_from_xof(&mut xof)
}

/// Derive the public per-projection salt from the caller's secret randomness.
///
/// The salt is what makes `A` differ between two projections of one identity at
/// one context. It is published in the projection, so it must not reveal `rho`:
/// SHAKE-256 is one-way, and the salt is the only thing derived from `rho` that
/// leaves the component besides `b_tau` itself.
///
/// Derived from `rho` rather than taken as its own parameter so that a caller
/// who supplies fresh `rho`, which they already MUST do for `e_tau`, gets a
/// fresh salt for free and cannot supply one without the other. It is bound to
/// `tau` as well so that an accidentally reused `rho` still yields a distinct
/// salt per context, matching [`derive_error_tau`].
///
/// Uses a domain separator distinct from [`derive_error_tau`], so the salt and
/// the error term are independent outputs rather than correlated views of one
/// stream.
pub(crate) fn pad_tau(tau: &[u8]) -> [u8; 32] {
    let mut t = [0u8; 32];
    let len = tau.len().min(32);
    t[..len].copy_from_slice(&tau[..len]);
    t
}

pub(crate) fn derive_projection_salt(rho: &[u8], tau: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_PLP_SALT_V1");
    hasher.update(&(rho.len() as u32).to_le_bytes());
    hasher.update(rho);
    hasher.update(tau);
    let mut xof = hasher.finalize_xof();
    let mut salt = [0u8; 32];
    xof.read(&mut salt);
    salt
}

/// Derive the context matrix `A` for a projection at `tau` with `salt`.
///
/// # Why the salt is here
///
/// `A` used to be `SHAKE-256("AETHEL_PLP_CTX_V1" || tau)`, a pure function of
/// the context. That made repeated projection at one `tau` a key-recovery
/// vector rather than merely a caller error: every projection shared one `A`,
/// so the samples `b_i = A*s + e_i` differed only in their error terms. `e`
/// comes from CBD, which is centered at zero, so averaging enough samples
/// drives the noise to nothing and leaves `A*s`, from which `s` is linear
/// algebra over the ring rather than an M-LWE instance. Roughly 64 samples
/// sufficed, and no amount of freshness in each individual `e_i` helped.
///
/// Binding a per-projection salt removes the shared `A` that attack needs. Two
/// projections of one identity at one `tau` are now independent M-LWE samples
/// under unrelated matrices, so there is nothing to average.
///
/// This is what makes `tau` reuse structurally safe rather than a documented
/// prohibition. See 0X3-95 and AETHEL-F-02.
/// `tau` is the **padded 32-byte** context tag, not the caller's raw slice. A
/// verifier only ever holds the padded form, so keying the derivation on
/// anything else would make `A` unreconstructable from a decoded projection.
pub fn derive_context_matrix(tau: &[u8; 32], salt: &[u8; 32]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_PLP_CTX_V2");
    hasher.update(tau);
    hasher.update(salt);
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
/// c = HashToPoly(SHAKE-256("AETHEL_PLP_CHALLENGE_V2" ∥ w ∥ tau ∥ salt))
///
/// Binds the whole projection, not just the commitment. The previous version
/// hashed `w` and the **first 8 bytes** of `tau` only, so a proof was bound to
/// neither the rest of the context nor to `A`. Now that `A` varies per
/// projection, an unbound challenge would let one proof be presented against a
/// different projection at the same context; including `salt` ties the proof to
/// exactly the `A` it was computed against, and including the full `tau`
/// removes the 8-byte truncation while we are here.
pub fn hash_to_challenge(w: &Poly, tau: &[u8; 32], salt: &[u8; 32]) -> Poly {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_PLP_CHALLENGE_V2");
    for &c in w.coeffs.iter() {
        hasher.update(&c.to_le_bytes());
    }
    hasher.update(tau);
    hasher.update(salt);
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
    /// The master secret, for in-crate use only.
    ///
    /// `pub(crate)` deliberately: SAAP's identity-linkage relation needs `s` as
    /// a witness, and it must reach that code without becoming reachable from
    /// outside the crate. No public API returns this.
    pub(crate) fn secret(&self) -> &Poly {
        &self.secret_key
    }

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

    /// Derive a polymorphic public projection for context τ.
    ///
    /// `b_τ = A · s + e_τ (mod q)`, where
    /// `A ← SHAKE-256("AETHEL_PLP_CTX_V2" ∥ τ ∥ salt)`,
    /// `salt ← SHAKE-256("AETHEL_PLP_SALT_V1" ∥ rho ∥ τ)`,
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
    /// ## τ reuse is survivable, but `rho` freshness is what makes it so
    ///
    /// `A` used to be a deterministic function of `τ` alone, which made
    /// projecting the *same* identity at the *same* `τ` a key-recovery vector:
    /// the samples `b_i = A_τ·s + e_i` shared one `A_τ` and differed only in
    /// their centered error terms, so averaging roughly 64 of them recovered
    /// `A_τ·s` and thence `s`, no matter how fresh each `e_i` was.
    ///
    /// `A` is now derived from `τ` **and** a per-projection salt, and the salt
    /// comes from `rho`. Two projections at one `τ` with different `rho` are
    /// independent M-LWE samples under unrelated matrices, so there is nothing
    /// to average and the attack has no purchase. See 0X3-95 / AETHEL-F-02.
    ///
    /// This moves the burden entirely onto `rho`: reusing `τ` is now safe, and
    /// reusing `rho` is what is not. That is the better place for it, because
    /// `rho` is a value the caller generates and `τ` is often one they are
    /// handed (the RFC's canonical `τ` is a block height, which collides across
    /// users by construction).
    pub fn project_at_context(&self, tau: &[u8], rho: &[u8]) -> EphemeralProjection {
        // Everything keyed on tau uses the padded form, because that is the only
        // form a verifier decoding this projection will ever hold.
        let tau_padded = pad_tau(tau);

        // Public per-projection salt, one-way from the caller's secret rho.
        let salt = derive_projection_salt(rho, &tau_padded);

        // Context-bound matrix A, now a function of (tau, salt) rather than tau
        // alone. This is the line that closes the averaging attack.
        let matrix_a = derive_context_matrix(&tau_padded, &salt);

        // Generate ephemeral error e_τ ← CBD η=2 from fresh secret randomness.
        let mut e_tau = derive_error_tau(rho, tau);

        // b_τ = A · s + e_τ
        let public_b = matrix_a.mul_schoolbook(&self.secret_key).add(&e_tau);
        // e_tau is secret-derived noise with no further use past this point —
        // wipe it explicitly rather than letting it fall out of scope (Poly is
        // Copy and cannot implement Drop, so nothing wipes it automatically).
        e_tau.zeroize();

        EphemeralProjection {
            tau: tau_padded,
            salt,
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
pub const EPHEMERAL_PROJECTION_BYTE_LEN: usize = 32 + 32 + N * 4;

/// Public projection for a given context τ.
#[derive(Clone)]
pub struct EphemeralProjection {
    /// Context tag τ (truncated/padded to 32 bytes).
    pub tau: [u8; 32],
    /// Public per-projection salt. Freshness of this is what makes two
    /// projections at one τ independent samples. See [`derive_context_matrix`].
    pub salt: [u8; 32],
    /// Context matrix `A = derive_context_matrix(tau, salt)`.
    ///
    /// A **cache**, not an input. It is fully determined by `tau` and `salt`,
    /// and [`Self::from_bytes`] recomputes it rather than reading it off the
    /// wire, so a decoded projection cannot carry an `A` inconsistent with its
    /// own salt. [`Verifier::verify`] re-derives it too and ignores whatever is
    /// in this field, so a hand-built struct with a doctored `A` cannot fool a
    /// verifier either.
    pub matrix_a: Poly,
    /// Public projection b_τ = A · s + e_τ.
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
    ///
    /// Takes `rho` because `A` is no longer recoverable from `tau` alone. The
    /// prover must reconstruct the *same* `A` the projection was built under,
    /// which means reconstructing the same salt, which means being given the
    /// same `rho`. That is why `plp-prove-identity` and `master-identity.prove`
    /// gained a randomness parameter: see 0X3-95.
    pub(crate) fn for_proving(tau: &[u8], rho: &[u8]) -> Self {
        let tau_padded = pad_tau(tau);
        let salt = derive_projection_salt(rho, &tau_padded);
        let matrix_a = derive_context_matrix(&tau_padded, &salt);
        EphemeralProjection {
            tau: tau_padded,
            salt,
            matrix_a,
            public_b: Poly::zero(),
        }
    }

    /// Encode as `tau(32) ++ salt(32) ++ public_b.coeffs(N*4, LE)`.
    ///
    /// `matrix_a` is deliberately **not** on the wire. It is a function of `tau`
    /// and `salt`, so carrying it would be redundant bytes that a peer would
    /// then have to be trusted about, or cross-checked against. Deriving it on
    /// decode makes an inconsistent `A` unrepresentable instead of detectable.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = alloc::vec![0u8; EPHEMERAL_PROJECTION_BYTE_LEN];
        out[..32].copy_from_slice(&self.tau);
        out[32..64].copy_from_slice(&self.salt);
        for (i, &c) in self.public_b.coeffs.iter().enumerate() {
            let offset = 64 + i * 4;
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

        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[32..64]);

        let mut public_b = Poly::zero();
        for i in 0..N {
            let offset = 64 + i * 4;
            let mut b = [0u8; 4];
            b.copy_from_slice(&bytes[offset..offset + 4]);
            public_b.coeffs[i] = u32::from_le_bytes(b);
        }

        // Derived, never read off the wire. See the field's doc comment.
        let matrix_a = derive_context_matrix(&tau, &salt);

        Ok(Self { tau, salt, matrix_a, public_b })
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
    ///
    /// Returns the first response that satisfies the norm bound, or
    /// `Err(RejectionSamplingFailed)` if all 16 iterations are rejected. There
    /// is deliberately **no fallback proof**: see the note above the error
    /// return for why emitting the last candidate was a key-recovery hazard
    /// rather than a convenience.
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
    ) -> Result<ZkIdentityProof, IdentityError> {
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

            // 3. Compute Fiat-Shamir challenge c = HashToPoly(W, τ, salt)
            let mut challenge_c = hash_to_challenge(&w, &proj.tau, &proj.salt);

            // 4. Compute candidate response z = y + c · s
            let mut cs = challenge_c.mul_schoolbook(&identity.secret_key);
            let mut z = y.add(&cs);

            // y and cs are pure intermediates — never part of the returned
            // proof either way — safe to wipe immediately after use.
            y.zeroize();
            cs.zeroize();

            // 5. Rejection sampling: ||z||∞ < γ₁ - β
            if z.infinity_norm() < REJECTION_THRESHOLD as i64 {
                return Ok(ZkIdentityProof {
                    commitment_w: w,
                    challenge_c,
                    response_z: z,
                });
            }

            // Rejected: w/challenge_c/z must not survive to the next
            // iteration or fall out unwiped.
            w.zeroize();
            challenge_c.zeroize();
            z.zeroize();
        }

        // No fallback, for two independent reasons — this path used to rebuild
        // a proof here and return it (P3-15 / 0X3-85).
        //
        // 1. It derived the mask under `AETHEL_MASK_V1` from `(seed, 0)` with τ
        //    absent, reintroducing in the fallback exactly the nonce reuse the
        //    main path above binds τ to prevent. Two all-rejected proofs of one
        //    identity at different contexts shared `y` while their challenges
        //    differed, and `z₁ − z₂ = (c₁ − c₂)·s` recovers the master secret.
        // 2. It returned that `z` without re-checking the norm bound, so it
        //    emitted precisely the response rejection sampling exists to
        //    withhold. A response outside the bound is how a sigma protocol
        //    leaks its secret, which is the whole reason the bound is there.
        //
        // Neither was reachable often — all 16 iterations rejecting is
        // negligible for honest parameters — but the derivation is deterministic
        // in τ, so an attacker can search τ for a context that lands here rather
        // than waiting for chance. `credential::prove` already returns this same
        // error with the same reasoning; this brings PLP in line with it.
        Err(IdentityError::RejectionSamplingFailed)
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
    /// 2. Challenge consistency: c' = HashToPoly(W, τ, salt)
    /// 3. Verification equation: A · z - c · b_τ ≈ W (mod small noise)
    ///
    /// `A` is re-derived here from the projection's `tau` and `salt` rather than
    /// read from its `matrix_a` field. The field is a prover-side cache, and a
    /// verifier that trusted it would be accepting a matrix chosen by whoever
    /// handed it the projection. Deriving it means the only thing a caller
    /// controls is the salt, and the salt is bound into the challenge.
    pub fn verify(proj: &EphemeralProjection, proof: &ZkIdentityProof) -> bool {
        // 1. Check response norm bound: ||z||∞ < γ₁ - β
        if proof.response_z.infinity_norm() >= REJECTION_THRESHOLD as i64 {
            return false;
        }

        // 2. Re-compute Fiat-Shamir challenge c'
        let recomputed_c = hash_to_challenge(&proof.commitment_w, &proj.tau, &proj.salt);

        // Constant-time challenge comparison
        let mut mismatch = 0u32;
        for i in 0..N {
            mismatch |= recomputed_c.coeffs[i] ^ proof.challenge_c.coeffs[i];
        }
        if mismatch != 0 {
            return false;
        }

        // 3. Verify equation: A · z - c · b_τ ≈ W
        // W' = A · z - c · b_τ, with A derived, not taken on trust.
        let matrix_a = derive_context_matrix(&proj.tau, &proj.salt);
        let az = matrix_a.mul_schoolbook(&proof.response_z);
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
        let c1 = hash_to_challenge(&proj.matrix_a, &proj.tau, &[1u8; 32]);
        let c2 = hash_to_challenge(&proj.matrix_a, &proj.tau, &[2u8; 32]);
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

            // All-rejected now yields an error rather than a leaky fallback
            // proof (P3-15 / 0X3-85). Skip those: there is no transcript to
            // attack, which is the point of the change.
            let (p1, p2) = match (
                Prover::prove_identity(&identity, &proj1, &seed),
                Prover::prove_identity(&identity, &proj2, &seed),
            ) {
                (Ok(a), Ok(b)) => (a, b),
                _ => continue,
            };

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

        // Diagnostic output only where std exists: this module is also compiled
        // no_std for the wasm32 test target.
        #[cfg(feature = "std")]
        std::eprintln!(
            "mask-reuse sweep: {}/{} pairs leaked a small-norm secret (first: {:?})",
            recoveries, attempts, first_hit
        );
        let _ = &first_hit;

        assert_eq!(
            recoveries, 0,
            "MASTER SECRET RECOVERED from two proofs at different contexts, in              {}/{} sampled identities. prove_identity derives its mask from              (seed, iter) only - tau never enters - so whenever two contexts              accept at the same rejection-sampling iteration they share y, and              z1 - z2 = (c1 - c2)*s reveals the secret. Recovered polynomials              have infinity norm <= 4, matching CBD(eta=2); a wrong guess would              be uniform over a 2^23 field.",
            recoveries, attempts
        );
    }

    // ── P3-15 / 0X3-85: the all-rejected fallback ────────────────────────────
    //
    // The sweep above covers the main proving path. These cover the path it
    // could not reach: what `prove_identity` did when all 16 iterations were
    // rejected. It rebuilt a proof under `AETHEL_MASK_V1` from `(seed, 0)` with
    // tau absent — reintroducing in the fallback exactly the nonce reuse the
    // main path binds tau to prevent — and returned the result without
    // re-checking the norm bound.
    //
    // That path is now `Err(RejectionSamplingFailed)`, so it cannot be entered
    // to be tested directly. What is testable is the invariant it violated and
    // the derivation it used, and both are asserted below.

    /// Every proof `prove_identity` returns satisfies the norm bound.
    ///
    /// This is the invariant the fallback broke. A response outside
    /// `||z||∞ < γ₁ − β` is precisely the value rejection sampling exists to
    /// withhold: emitting one is how a sigma protocol leaks its secret. The old
    /// fallback returned exactly such a response, and it verified nowhere —
    /// `Verifier::verify` rejects on the same bound — so it was a proof that
    /// could only leak, never authenticate.
    #[test]
    fn every_returned_proof_satisfies_the_norm_bound_and_verifies() {
        let mut checked = 0usize;

        for k in 0u8..48 {
            let seed = [k.wrapping_mul(11).wrapping_add(3); 32];
            let identity = MasterIdentity::from_seed(&seed);

            for ctx in 0u8..4 {
                let tau = [ctx.wrapping_mul(37).wrapping_add(5); 32];
                let proj = identity.project_at_context(&tau, &[0x5au8; 32]);

                let proof = match Prover::prove_identity(&identity, &proj, &seed) {
                    Ok(p) => p,
                    // Refusing to prove is the correct outcome, not a failure.
                    Err(IdentityError::RejectionSamplingFailed) => continue,
                    Err(e) => panic!("unexpected error from prove_identity: {e:?}"),
                };

                assert!(
                    proof.response_z.infinity_norm() < REJECTION_THRESHOLD as i64,
                    "prove_identity returned a response outside the norm bound \
                     (norm {}, bound {}). That is the value rejection sampling \
                     exists to withhold, and returning it is how the secret leaks.",
                    proof.response_z.infinity_norm(),
                    REJECTION_THRESHOLD
                );
                assert!(
                    Verifier::verify(&proj, &proof),
                    "prove_identity returned a proof that does not verify against \
                     the projection it was produced for"
                );
                checked += 1;
            }
        }

        assert!(
            checked > 0,
            "no proof was produced at all, so this test asserted nothing"
        );
    }

    /// Positive control for the assertion above.
    ///
    /// The norm check is only worth something if it can distinguish a
    /// bound-satisfying response from a bound-violating one. Build a response
    /// that deliberately exceeds the bound and confirm both the norm assertion
    /// and the verifier reject it — otherwise the test above would pass against
    /// a verifier that accepted anything.
    #[test]
    fn the_norm_bound_check_detects_a_violating_response() {
        let seed = test_seed();
        let identity = MasterIdentity::from_seed(&seed);
        let proj = identity.project_at_context(b"norm-control", &test_rho());

        let mut proof = Prover::prove_identity(&identity, &proj, &seed)
            .expect("honest proving must not exhaust rejection sampling");

        // Push one coefficient just past the rejection threshold, which is what
        // an all-rejected candidate looks like.
        proof.response_z.coeffs[0] = REJECTION_THRESHOLD as u32 + 1;

        assert!(
            proof.response_z.infinity_norm() >= REJECTION_THRESHOLD as i64,
            "control: the constructed response should violate the norm bound"
        );
        assert!(
            !Verifier::verify(&proj, &proof),
            "control: the verifier accepted a response outside the norm bound, \
             so the check the test above relies on proves nothing"
        );
    }

    /// The tau-unbound mask derivation is gone from this module.
    ///
    /// `AETHEL_MASK_V1` was the fallback's domain separator, derived from
    /// `(seed, iter)` with tau never entering. The main path moved to
    /// `AETHEL_MASK_V2` and binds tau; the fallback kept using V1, so the fix
    /// was incomplete while that string remained. Asserted against the source
    /// because the path itself no longer exists to be called: if someone
    /// reintroduces a tau-independent derivation under the old separator, this
    /// fails rather than silently restoring the leak.
    #[test]
    fn no_tau_independent_mask_derivation_remains() {
        let source = include_str!("plp.rs");

        // The constant is allowed to appear in prose explaining why it went.
        // What must not come back is an actual hasher fed with it.
        assert!(
            !source.contains("update(b\"AETHEL_MASK_V1\")"),
            "a mask derivation under AETHEL_MASK_V1 is back in plp.rs. That \
             separator's derivation does not bind tau, which is what let two \
             proofs at different contexts share a mask and leak the secret via \
             z1 - z2 = (c1 - c2)*s. See P3-15 / 0X3-85 before restoring it."
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
        let salt = [0x5au8; 32];
        let tau = &pad_tau(tau);
        let a1 = derive_context_matrix(tau, &salt);
        let a2 = derive_context_matrix(tau, &salt);
        assert_eq!(a1.coeffs, a2.coeffs, "derivation must be deterministic in (tau, salt)");

        // And genuinely salt-dependent, which is the whole point of 0X3-95.
        let other = derive_context_matrix(tau, &[0xa5u8; 32]);
        assert_ne!(
            a1.coeffs, other.coeffs,
            "a different salt at the same tau produced the same matrix"
        );
        // All coefficients should be in [0, Q)
        for &c in a1.coeffs.iter() {
            assert!(c < Q, "coefficient {} >= Q", c);
        }
    }

    #[test]
    fn test_hash_to_challenge_sparse() {
        let w = Poly::zero();
        let c = hash_to_challenge(&w, &[0x11u8; 32], &[0x22u8; 32]);
        // Count non-zero coefficients — should be exactly 60
        let nonzero = c.coeffs.iter().filter(|&&x| x != 0).count();
        assert_eq!(nonzero, 60, "challenge should have exactly 60 non-zero coefficients");
    }

    // ── The averaging attack on a reused tau (AETHEL-F-02 / 0X3-95) ──────────

    /// Mount the averaging attack and report how many of the `N` coefficients of
    /// `A*s` it recovered exactly.
    ///
    /// `b_i = A_i*s + e_i` with every coefficient in `[0, q)`. `e` is CBD, so it
    /// is centered at zero with variance 1 and lives in `{-2..2}`; the mean of
    /// `count` samples therefore has standard deviation `1/sqrt(count)`, which
    /// for 64 samples is 0.125. Rounding the per-coefficient mean recovers the
    /// underlying value exactly whenever it is shared across the samples.
    ///
    /// Wraparound is not a concern: a coefficient is corrupted by the mod-q
    /// boundary only if `A*s` lands within 2 of 0 or q, which for a value spread
    /// over `q = 8380417` happens with probability about 5e-7 per coefficient.
    fn averaging_attack_recovered_coeffs(samples: &[Poly], target: &Poly) -> usize {
        let count = samples.len() as i64;
        let mut recovered = 0usize;
        for j in 0..N {
            let sum: i64 = samples.iter().map(|p| p.coeffs[j] as i64).sum();
            // Round to nearest rather than truncate.
            let mean = (sum + count / 2) / count;
            if mean == target.coeffs[j] as i64 {
                recovered += 1;
            }
        }
        recovered
    }

    /// Positive control. The attack must actually work against the construction
    /// this change removed, or the negative result below proves nothing.
    ///
    /// Reconstructs the old scheme faithfully out of the current primitives: one
    /// **fixed** salt across every projection, which is exactly what "A is a pure
    /// function of tau" meant, with the error term still freshly derived per
    /// sample. If this test ever stops recovering the secret, the attack model
    /// is wrong and the negative test below is worthless.
    #[test]
    fn the_averaging_attack_recovers_a_s_under_a_shared_context_matrix() {
        let identity = MasterIdentity::from_seed(&test_seed());
        let tau = pad_tau(b"block-height-1000");

        // The old construction: A fixed for this tau, regardless of rho.
        let fixed_salt = [0u8; 32];
        let matrix_a = derive_context_matrix(&tau, &fixed_salt);

        let samples: Vec<Poly> = (0u8..64)
            .map(|i| {
                let rho = [i.wrapping_mul(7).wrapping_add(1); 32];
                let e = derive_error_tau(&rho, &tau);
                matrix_a.mul_schoolbook(&identity.secret_key).add(&e)
            })
            .collect();

        let target = matrix_a.mul_schoolbook(&identity.secret_key);
        let recovered = averaging_attack_recovered_coeffs(&samples, &target);

        assert!(
            recovered > (N * 9) / 10,
            "the averaging attack recovered only {recovered}/{N} coefficients of A*s \
             against a SHARED context matrix. It is supposed to succeed here; if it \
             does not, the attack model is wrong and the negative test that depends \
             on it proves nothing."
        );
    }

    /// The finding itself: with `A` salted per projection, reusing tau no longer
    /// leaks `A*s`.
    ///
    /// Same identity, same tau, 64 projections, fresh rho each time, exactly the
    /// scenario the old doc comment told callers to avoid. Because each
    /// projection now derives its own `A`, the per-coefficient mean is an average
    /// over unrelated matrices and corresponds to no particular `A_i*s`.
    #[test]
    fn a_reused_tau_does_not_leak_a_s() {
        let identity = MasterIdentity::from_seed(&test_seed());
        let tau = b"block-height-1000";

        let projections: Vec<EphemeralProjection> = (0u8..64)
            .map(|i| {
                let rho = [i.wrapping_mul(7).wrapping_add(1); 32];
                identity.project_at_context(tau, &rho)
            })
            .collect();

        // Every projection is at the SAME tau, and every one has its own A.
        assert!(
            projections.windows(2).all(|w| w[0].tau == w[1].tau),
            "test setup: all projections must share tau"
        );
        assert_ne!(
            projections[0].matrix_a.coeffs, projections[1].matrix_a.coeffs,
            "test setup: two projections at one tau must not share A"
        );

        let samples: Vec<Poly> = projections.iter().map(|p| p.public_b).collect();
        let target = projections[0]
            .matrix_a
            .mul_schoolbook(&identity.secret_key);

        let recovered = averaging_attack_recovered_coeffs(&samples, &target);

        // Chance alone lands a coefficient on the target with probability about
        // 1/q, so anything above a handful means real signal is leaking.
        assert!(
            recovered < N / 10,
            "averaging 64 projections at one tau recovered {recovered}/{N} coefficients \
             of A*s. A is leaking across projections again: see AETHEL-F-02 and \
             derive_context_matrix before changing the derivation."
        );
    }

    /// Reusing rho at one tau is what is unsafe now, and it is unsafe in exactly
    /// the old way. Pinned so the residual obligation is executable rather than
    /// only described in a doc comment.
    #[test]
    fn reusing_rho_at_one_tau_reinstates_the_shared_matrix() {
        let identity = MasterIdentity::from_seed(&test_seed());
        let rho = [0x5au8; 32];
        let a = identity.project_at_context(b"one-tau", &rho);
        let b = identity.project_at_context(b"one-tau", &rho);

        assert_eq!(
            a.matrix_a.coeffs, b.matrix_a.coeffs,
            "same (tau, rho) is deterministic, so it must reproduce one matrix"
        );
        assert_eq!(
            a.public_b.coeffs, b.public_b.coeffs,
            "and therefore one projection: reusing rho gives the attacker nothing \
             new, but it also gives the holder no fresh sample"
        );
    }

    #[test]
    fn test_prove_verify_roundtrip() {
        let seed = test_seed();
        let identity = MasterIdentity::from_seed(&seed);
        let tau = b"block_1000_context";
        let proj = identity.project_at_context(tau, &test_rho());
        let proof = Prover::prove_identity(&identity, &proj, &seed)
            .expect("honest proving must not exhaust rejection sampling");
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
        let proof1 = Prover::prove_identity(&identity, &proj1, &seed)
            .expect("honest proving must not exhaust rejection sampling");
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
        let mut proof = Prover::prove_identity(&identity, &proj, &seed)
            .expect("honest proving must not exhaust rejection sampling");

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
