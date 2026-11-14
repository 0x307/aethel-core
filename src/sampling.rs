//! # Enclave Constant-Time Rejection Sampling Module
//!
//! This module provides two complete implementations:
//!
//! 1. **Enclave Constant-Time Rejection Sampling** (`#![no_std]`, written to be bare-metal
//!    enclave-compatible, though nothing in this repo runs it inside an actual hardware
//!    enclave/TEE, and it has had no independent audit; see the README's audit
//!    status): constant-time rejection sampling enforcing a 16-iteration padded
//!    execution loop, constant-time norm checking, bitwise CMOV selection, and volatile
//!    memory zeroization via compiler barriers.
//!
//! 2. **M-LWE Centered Binomial Distribution Sampler (CBD η=2)**: Constant-time
//!    Centered Binomial Distribution polynomial sampler for Module-LWE ring
//!    `R_q = Z_q[X]/(X^256 + 1)`, including infinity norm checking for rejection
//!    sampling.
//!
//! ## Key Structures
//!
//! - [`Polynomial`](crate::sampling::Polynomial) — Cache-line-aligned ring element (64-byte aligned)
//! - [`VectorK`](crate::sampling::VectorK) — k-dimensional module vector
//! - [`PlpProof`](crate::sampling::PlpProof) — Output proof structure with response vector and iteration counter
//! - [`RejectionError`](crate::sampling::RejectionError) — Error type for exhausted iteration ceiling
//! - [`PolyRq`](crate::sampling::PolyRq) — Ring polynomial for the CBD sampler; `Copy`, so zeroization
//!   is on-demand via `Zeroize::zeroize()`, not automatic on drop
//!
//! ## Key Functions
//!
//! - [`enclave_explicit_zeroize`](crate::sampling::enclave_explicit_zeroize) — Volatile memory zeroization with compiler barrier
//! - [`ct_check_norm_bound`](crate::sampling::ct_check_norm_bound) — Constant-time infinity norm bound check
//! - [`ct_cond_copy`](crate::sampling::ct_cond_copy) — Constant-time conditional byte copy (CMOV equivalent)
//! - [`enclave_plp_prove_fixed_time`](crate::sampling::enclave_plp_prove_fixed_time) — Fixed 16-iteration padded proof generation
//! - [`poly_cbd_eta2`](crate::sampling::poly_cbd_eta2) — CBD η=2 polynomial sampler
//! - [`poly_check_infinity_norm`](crate::sampling::poly_check_infinity_norm) — Constant-time infinity norm check
//!
//! ## Parameters
//!
//! - RING_N=256, MODULE_K=4, PARAM_Q=8_380_417
//! - PARAM_GAMMA1=131_072, PARAM_BETA=78
//! - FIXED_ITERATION_CEILING=16

// Constant-time code: its index loops are left exactly as written, since an
// iterator rewrite can change the generated code this module relies on.
#![allow(clippy::needless_range_loop)]

// ── Enclave Constant-Time Rejection Sampling (aethel-enclave-plp) ────────────

use core::sync::atomic::{compiler_fence, Ordering};
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

/// Ring degree `N`.
pub const RING_N: usize = 256;
/// Module rank `k`.
pub const MODULE_K: usize = 4;
/// Prime modulus `q`.
pub const PARAM_Q: i32 = 8_380_417;
/// Masking bound `γ₁`.
pub const PARAM_GAMMA1: i32 = 131_072;
/// Rejection margin `β`.
pub const PARAM_BETA: i32 = 78;
/// `γ₁ − β`: a response is released only if every coefficient is below this.
pub const REJECTION_BOUND: i32 = PARAM_GAMMA1 - PARAM_BETA;
/// Iterations the fixed-time prover always runs, whichever one is accepted.
pub const FIXED_ITERATION_CEILING: usize = 16;

/// Cache-line-aligned polynomial in R_q.
#[derive(Copy, Clone)]
#[repr(align(64))]
pub struct Polynomial {
    /// Coefficients, lowest degree first.
    pub coeffs: [i32; RING_N],
}

impl Polynomial {
    /// The zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0i32; RING_N] }
    }
}

/// k-dimensional module vector.
#[derive(Copy, Clone)]
#[repr(align(64))]
pub struct VectorK {
    /// The `k` polynomials.
    pub vec: [Polynomial; MODULE_K],
}

impl VectorK {
    /// The zero vector.
    pub const fn zero() -> Self {
        Self { vec: [Polynomial { coeffs: [0i32; RING_N] }; MODULE_K] }
    }
}

/// Output proof structure.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct PlpProof {
    /// The response vector `z`.
    pub z: VectorK,
    /// The iteration whose response was accepted.
    pub iteration_counter: u32,
}

impl PlpProof {
    /// An all-zero proof, used as the output buffer before any iteration runs.
    pub const fn zero() -> Self {
        Self {
            z: VectorK { vec: [Polynomial { coeffs: [0; RING_N] }; MODULE_K] },
            iteration_counter: 0,
        }
    }
}

// `Polynomial`/`VectorK`/`PlpProof` are `Copy`, so none of them can implement
// `Drop`, meaning no `ZeroizeOnDrop`. They are wiped field by field through the
// `zeroize` crate, whose integer and array impls use volatile writes and a
// compiler fence, so the wipe survives dead-store elimination. No `unsafe` in
// this crate (CORE-01): the volatile writes live in `zeroize`.

impl zeroize::Zeroize for Polynomial {
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
    }
}

impl zeroize::Zeroize for VectorK {
    fn zeroize(&mut self) {
        for poly in self.vec.iter_mut() {
            poly.zeroize();
        }
    }
}

impl zeroize::Zeroize for PlpProof {
    fn zeroize(&mut self) {
        self.z.zeroize();
        self.iteration_counter.zeroize();
    }
}

/// Volatile memory zeroization with compiler barrier.
///
/// Wipes `data` through its [`zeroize::Zeroize`] impl (volatile writes), then
/// issues a sequentially consistent compiler fence.
///
/// Until 0.7.6 this took any `T: Sized` and wrote zero bytes over it with
/// `unsafe` code. That was unsound for a safe function: an all-zero bit
/// pattern is not a valid value of every type (a reference, a `Box`, a
/// `NonZero*`), so safe code could create undefined behaviour through it. The
/// bound is now `T: Zeroize`, which every type this crate wipes, every integer
/// and every array of them implement. See the 0.7.6 changelog entry.
pub fn enclave_explicit_zeroize<T: zeroize::Zeroize>(data: &mut T) {
    data.zeroize();
    compiler_fence(Ordering::SeqCst);
}

/// Constant-time conditional copy of a whole proof, field by field.
///
/// `mask` must be `0xFFFF_FFFF` (copy `src` into `dst`) or `0` (leave `dst`
/// unchanged). Every coefficient and the counter are written either way, so
/// the work done does not depend on `mask`. Replaces a byte-slice view of
/// `PlpProof` that needed `unsafe` (CORE-01); the selected values are the same.
#[inline(always)]
fn ct_cond_copy_proof(dst: &mut PlpProof, src: &PlpProof, mask: u32) {
    let mask_i32 = mask as i32;
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            let d = dst.z.vec[k].coeffs[n];
            dst.z.vec[k].coeffs[n] = d ^ (mask_i32 & (src.z.vec[k].coeffs[n] ^ d));
        }
    }
    let d = dst.iteration_counter;
    dst.iteration_counter = d ^ (mask & (src.iteration_counter ^ d));
}

#[inline(always)]
fn ct_abs(coeff: i32) -> i32 {
    let mask = coeff >> 31;
    (coeff + mask) ^ mask
}

#[inline(always)]
fn ct_is_out_of_bounds(coeff: i32, bound: i32) -> u32 {
    let abs_coeff = ct_abs(coeff);
    let diff = (bound - 1) - abs_coeff;
    ((diff >> 31) & 1) as u32 * 0xFFFFFFFF
}

/// Constant-time infinity norm bound check.
///
/// Returns 0 if all coefficients satisfy |coeff| < bound,
/// or 0xFFFFFFFF if any coefficient violates the bound.
pub fn ct_check_norm_bound(z: &VectorK, bound: i32) -> u32 {
    let mut bad_coeff_mask: u32 = 0;
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            let coeff = z.vec[k].coeffs[n];
            bad_coeff_mask |= ct_is_out_of_bounds(coeff, bound);
        }
    }
    bad_coeff_mask
}

/// Constant-time conditional byte copy (CMOV equivalent).
///
/// If mask == 0xFFFFFFFF: `dst[i] = src[i]`
/// If mask == 0x00000000: `dst[i]` unchanged
#[inline(always)]
pub fn ct_cond_copy(dst: &mut [u8], src: &[u8], mask: u32) {
    let mask_u8 = mask as u8;
    for i in 0..dst.len() {
        dst[i] ^= mask_u8 & (src[i] ^ dst[i]);
    }
}

/// Fixed 16-iteration padded proof generation.
///
/// Executes exactly FIXED_ITERATION_CEILING iterations regardless of when
/// a valid candidate is found, and captures the first valid proof with a
/// masked copy rather than a branch. Its timing is not tested, so no
/// constant-time claim is made (see [`crate::ct_verify`]). Research code: the
/// identity path does not call it.
pub fn enclave_plp_prove_fixed_time(
    proof_out: &mut PlpProof,
    s: &VectorK,
    tau: &[u8; 32],
) -> Result<(), RejectionError> {
    let mut proof_captured_mask: u32 = 0;
    let mut candidate_z = VectorK::zero();
    let mut candidate_proof = PlpProof::zero();
    let mut dummy_buffer = PlpProof::zero();

    for iter in 0..FIXED_ITERATION_CEILING {
        generate_candidate_z(&mut candidate_z, s, tau, iter);
        candidate_proof.z = candidate_z;
        candidate_proof.iteration_counter = iter as u32;
        let reject_mask = ct_check_norm_bound(&candidate_z, REJECTION_BOUND);
        let capture_mask = (!reject_mask) & (!proof_captured_mask);
        // `dummy_buffer` receives the discarded branch so both branches do the
        // same work.
        ct_cond_copy_proof(proof_out, &candidate_proof, capture_mask);
        ct_cond_copy_proof(&mut dummy_buffer, &candidate_proof, !capture_mask);
        proof_captured_mask |= capture_mask;
    }

    enclave_explicit_zeroize(&mut candidate_z);
    enclave_explicit_zeroize(&mut candidate_proof);
    enclave_explicit_zeroize(&mut dummy_buffer);

    if proof_captured_mask != 0 {
        Ok(())
    } else {
        enclave_explicit_zeroize(proof_out);
        Err(RejectionError::AllIterationsRejected)
    }
}

/// Error type for exhausted iteration ceiling.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RejectionError {
    /// Every iteration was rejected, so no response is released.
    AllIterationsRejected,
}

// ── Fiat-Shamir sigma protocol step ──────────────────────────────────────────

/// Sample a masking vector y from uniform [-γ₁, γ₁]^k using SHAKE-256.
///
/// y ← SHAKE-256("AETHEL_MASK_V1" ∥ seed ∥ nonce)
fn sample_masking_vector(seed: &[u8; 32], nonce: u8) -> VectorK {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_MASK_V1");
    hasher.update(seed);
    hasher.update(&[nonce]);
    let mut xof = hasher.finalize_xof();

    let mut y = VectorK::zero();
    let range = 2 * PARAM_GAMMA1 as u32 + 1; // 262145

    for k in 0..MODULE_K {
        let mut coeff_idx = 0usize;
        while coeff_idx < RING_N {
            let mut buf = [0u8; 3];
            xof.read(&mut buf);
            let val = (buf[0] as u32)
                | ((buf[1] as u32) << 8)
                | ((buf[2] as u32 & 0x7F) << 16);
            if val < range {
                // Center: val in [0, 2*γ₁] → coeff in [-γ₁, γ₁]
                let centered = val as i32 - PARAM_GAMMA1;
                y.vec[k].coeffs[coeff_idx] = centered;
                coeff_idx += 1;
            }
        }
    }
    y
}

/// Derive the context matrix A_τ row for a given (tau, row_idx) using SHAKE-256.
///
/// A_τ[row] ← SHAKE-256("AETHEL_PLP_CTX_V1" ∥ tau ∥ row_idx)
fn derive_context_row(tau: &[u8; 32], row_idx: usize) -> [Polynomial; MODULE_K] {
    let mut row = [Polynomial::zero(); MODULE_K];
    for col in 0..MODULE_K {
        let mut hasher = Shake256::default();
        hasher.update(b"AETHEL_PLP_CTX_V1");
        hasher.update(tau);
        hasher.update(&[row_idx as u8, col as u8]);
        let mut xof = hasher.finalize_xof();

        let mut coeff_idx = 0usize;
        while coeff_idx < RING_N {
            let mut buf = [0u8; 3];
            xof.read(&mut buf);
            let val = (buf[0] as u32)
                | ((buf[1] as u32) << 8)
                | ((buf[2] as u32 & 0x7F) << 16);
            if (val as i32) < PARAM_Q {
                // Store as centered representative
                let centered = if val > (PARAM_Q as u32 / 2) {
                    val as i32 - PARAM_Q
                } else {
                    val as i32
                };
                row[col].coeffs[coeff_idx] = centered;
                coeff_idx += 1;
            }
        }
    }
    row
}

/// Polynomial multiplication in R_q = Z_q[X]/(X^N + 1), schoolbook O(N²).
/// Operates on centered i32 coefficients.
fn poly_mul_centered(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let mut tmp = [0i64; 2 * RING_N];
    for i in 0..RING_N {
        for j in 0..RING_N {
            tmp[i + j] += (a.coeffs[i] as i64) * (b.coeffs[j] as i64);
        }
    }
    let mut res = Polynomial::zero();
    let q = PARAM_Q as i64;
    for i in 0..RING_N {
        let v = (tmp[i] - tmp[i + RING_N]).rem_euclid(q);
        // Center
        res.coeffs[i] = if v > q / 2 { (v - q) as i32 } else { v as i32 };
    }
    res
}

/// Polynomial addition mod q (centered).
fn poly_add_centered(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let mut res = Polynomial::zero();
    let q = PARAM_Q as i64;
    for i in 0..RING_N {
        let v = ((a.coeffs[i] as i64) + (b.coeffs[i] as i64)).rem_euclid(q);
        res.coeffs[i] = if v > q / 2 { (v - q) as i32 } else { v as i32 };
    }
    res
}

/// Hash-to-challenge: sparse ternary polynomial with exactly 60 ±1 coefficients.
///
/// c = HashToPoly(SHAKE-256("AETHEL_SAAP_CHALLENGE_V1" ∥ w ∥ tau))
fn hash_to_challenge_sampling(w: &VectorK, tau: &[u8; 32]) -> Polynomial {
    let mut hasher = Shake256::default();
    hasher.update(b"AETHEL_SAAP_CHALLENGE_V1");
    for k in 0..MODULE_K {
        for n in 0..RING_N {
            hasher.update(&w.vec[k].coeffs[n].to_le_bytes());
        }
    }
    hasher.update(tau);
    let mut xof = hasher.finalize_xof();

    let mut c_poly = Polynomial::zero();

    let mut signs = [0u8; 8];
    xof.read(&mut signs);
    let mut sign_bit = 0usize;

    let mut count = 0usize;
    let mut used = [false; RING_N];
    let mut pos_buf = [0u8; 1];

    while count < 60 {
        xof.read(&mut pos_buf);
        let pos = pos_buf[0] as usize;
        if pos >= RING_N {
            continue;
        }
        if used[pos] {
            continue;
        }
        used[pos] = true;
        let sign_byte = signs[sign_bit / 8];
        let sign: i32 = if (sign_byte >> (sign_bit % 8)) & 1 == 0 { 1 } else { -1 };
        sign_bit += 1;
        if sign_bit >= 64 {
            xof.read(&mut signs);
            sign_bit = 0;
        }
        c_poly.coeffs[pos] = sign;
        count += 1;
    }
    c_poly
}

/// Generate a candidate response vector z for iteration `iter`.
///
/// Full Fiat-Shamir sigma protocol step:
/// 1. Sample masking vector y ← S_{γ₁}^k
/// 2. Compute commitment w = A_τ · y
/// 3. Compute challenge c = HashToPoly(w, τ)
/// 4. Compute z = y + c · s
/// 5. Rejection check: ||z||∞ ≤ γ₁ - β
fn generate_candidate_z(z: &mut VectorK, s: &VectorK, tau: &[u8; 32], iter: usize) {
    // 1. Sample masking vector y
    let y = sample_masking_vector(tau, iter as u8);

    // 2. Compute commitment w = A_τ · y (k×k matrix × k vector)
    let mut w = VectorK::zero();
    for i in 0..MODULE_K {
        let row = derive_context_row(tau, i);
        for j in 0..MODULE_K {
            let prod = poly_mul_centered(&row[j], &y.vec[j]);
            w.vec[i] = poly_add_centered(&w.vec[i], &prod);
        }
    }

    // 3. Compute challenge c = HashToPoly(w, τ)
    let c = hash_to_challenge_sampling(&w, tau);

    // 4. Compute z = y + c · s
    for k in 0..MODULE_K {
        let cs_k = poly_mul_centered(&c, &s.vec[k]);
        z.vec[k] = poly_add_centered(&y.vec[k], &cs_k);
    }
}

// ── M-LWE Centered Binomial Distribution Sampler (CBD η=2) ───────────────────

/// Ring degree for the CBD sampler.
pub const N_DEGREE: usize = 256;

/// Prime modulus for the CBD sampler.
pub const Q_MODULUS: i32 = 8_380_417;

/// Ring polynomial `R_q = Z_q[X]/(X^N + 1)`.
///
/// P3-08 correction: despite this type's original doc claim, it cannot be
/// "zeroize-on-drop" — it derives `Copy`, and `Copy` and `Drop` are mutually
/// exclusive in Rust. Callers must call `zeroize()` (via `zeroize::Zeroize`) explicitly.
/// Note also: nothing in this crate currently constructs a `PolyRq` outside
/// its own tests (`poly_cbd_eta2` has no caller elsewhere in the crate), so
/// this zeroization has no live call site to exercise yet — implemented and
/// documented now so it's correct and available the moment something uses it.
#[derive(Copy, Clone)]
pub struct PolyRq {
    /// Coefficients, lowest degree first.
    pub coeffs: [i32; N_DEGREE],
}

impl PolyRq {
    /// Create a zero polynomial.
    pub const fn zero() -> Self {
        Self { coeffs: [0i32; N_DEGREE] }
    }
}

impl zeroize::Zeroize for PolyRq {
    /// Zeroize all coefficients using volatile writes (through the `zeroize`
    /// crate's array impl), then a compiler fence.
    fn zeroize(&mut self) {
        self.coeffs.zeroize();
        compiler_fence(Ordering::SeqCst);
    }
}

/// Sample a polynomial from the Centered Binomial Distribution with η=2.
///
/// For each coefficient position, samples 4 bits (a₀, a₁, b₀, b₁) from
/// the provided byte stream and computes:
///
/// ```text
/// coeff = (a₀ + a₁) - (b₀ + b₁) ∈ {-2, -1, 0, 1, 2}
/// ```
pub fn poly_cbd_eta2(seed_bytes: &[u8]) -> PolyRq {
    let mut poly = PolyRq::zero();
    for i in 0..N_DEGREE {
        let byte = seed_bytes[i % seed_bytes.len()];
        let a0 = (byte & 0x01) as i32;
        let a1 = ((byte >> 1) & 0x01) as i32;
        let b0 = ((byte >> 2) & 0x01) as i32;
        let b1 = ((byte >> 3) & 0x01) as i32;
        let coeff = (a0 + a1) - (b0 + b1);
        // Store as centered representative mod Q
        poly.coeffs[i] = (coeff + Q_MODULUS) % Q_MODULUS;
    }
    poly
}

/// Check the infinity norm of a polynomial against a bound.
///
/// Returns `true` if all coefficients satisfy `|coeff| < bound` (centered),
/// `false` if any coefficient violates the bound.
///
/// This check is performed in constant time: no early exit on violation.
pub fn poly_check_infinity_norm(poly: &PolyRq, bound: i32) -> bool {
    let mut all_ok: u32 = 0xFFFF_FFFF;
    for i in 0..N_DEGREE {
        let coeff = poly.coeffs[i];
        let centered = if coeff > Q_MODULUS / 2 {
            coeff - Q_MODULUS
        } else {
            coeff
        };
        let sign_mask = centered >> 31;
        let abs_coeff = (centered + sign_mask) ^ sign_mask;
        let diff = (bound - 1) - abs_coeff;
        let violation_mask = (diff >> 31) as u32;
        all_ok &= !violation_mask;
    }
    all_ok != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ct_check_norm_bound_accept() {
        let mut z = VectorK::zero();
        // Fill with values well within bound
        for k in 0..MODULE_K {
            for n in 0..RING_N {
                z.vec[k].coeffs[n] = 1000;
            }
        }
        let result = ct_check_norm_bound(&z, REJECTION_BOUND);
        assert_eq!(result, 0, "should accept: all coefficients within bound");
    }

    #[test]
    fn test_ct_check_norm_bound_reject() {
        let mut z = VectorK::zero();
        z.vec[0].coeffs[0] = REJECTION_BOUND + 1; // out of bounds
        let result = ct_check_norm_bound(&z, REJECTION_BOUND);
        assert_ne!(result, 0, "should reject: coefficient out of bound");
    }

    #[test]
    fn test_poly_cbd_eta2_range() {
        let seed = [0x5Au8; 256];
        let poly = poly_cbd_eta2(&seed);
        for &c in poly.coeffs.iter() {
            // Centered representative should be in {-2,-1,0,1,2} mod Q
            let centered = if c > Q_MODULUS / 2 { c - Q_MODULUS } else { c };
            assert!((-2..=2).contains(&centered), "CBD coefficient out of range: {}", centered);
        }
    }

    #[test]
    fn test_enclave_plp_prove_fixed_time() {
        let mut s = VectorK::zero();
        for k in 0..MODULE_K {
            for n in 0..RING_N {
                s.vec[k].coeffs[n] = (n % 5) as i32 - 2;
            }
        }
        let tau = [0x5Au8; 32];
        let mut proof_out = PlpProof::zero();
        let result = enclave_plp_prove_fixed_time(&mut proof_out, &s, &tau);
        assert!(result.is_ok(), "proof generation should succeed: {:?}", result);
    }

    /// SHA3-256 over every coefficient (little-endian) and the iteration
    /// counter of a proof: the observable output, without padding bytes.
    fn proof_digest(p: &PlpProof) -> [u8; 32] {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        for k in 0..MODULE_K {
            for n in 0..RING_N {
                Digest::update(&mut h, p.z.vec[k].coeffs[n].to_le_bytes());
            }
        }
        Digest::update(&mut h, p.iteration_counter.to_le_bytes());
        h.finalize().into()
    }

    /// Golden vector for the fixed-time prover (CORE-01). Recorded from the
    /// 0.7.5 implementation, whose capture step reinterpreted `PlpProof` as
    /// bytes with `unsafe`; the safe field-wise selection must give the same
    /// proof for the same inputs.
    #[test]
    fn fixed_time_prover_output_is_unchanged() {
        let mut s = VectorK::zero();
        for k in 0..MODULE_K {
            for n in 0..RING_N {
                s.vec[k].coeffs[n] = ((n * 7 + k) % 5) as i32 - 2;
            }
        }
        for (tau_byte, expected) in [(0x5Au8, GOLDEN_5A), (0x77u8, GOLDEN_77)] {
            let mut proof = PlpProof::zero();
            enclave_plp_prove_fixed_time(&mut proof, &s, &[tau_byte; 32]).unwrap();
            let got = proof_digest(&proof);
            let hex: alloc::string::String = got.iter().map(|b| alloc::format!("{b:02x}")).collect();
            assert_eq!(hex, expected, "tau byte {tau_byte:#04x}, iteration {}", proof.iteration_counter);
        }
    }

    const GOLDEN_5A: &str = "f148909bb3302513073ea2ca199eb171bdd5de0345748eebda594ae5aab7877c";
    const GOLDEN_77: &str = "c9399d28fb6b6ffc83f638057dfb6c36c3592ee63b3e9b000a45ab793e998ba3";

    #[test]
    fn test_masking_vector_range() {
        let seed = [0x42u8; 32];
        let y = sample_masking_vector(&seed, 0);
        for k in 0..MODULE_K {
            for n in 0..RING_N {
                let c = y.vec[k].coeffs[n];
                assert!(
                    (-PARAM_GAMMA1..=PARAM_GAMMA1).contains(&c),
                    "masking coefficient {} out of range [-γ₁, γ₁]", c
                );
            }
        }
    }
}
