---
title: "SRAM PUF + BCH Fuzzy Extractor — Full Specification"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-core"
---

# SRAM PUF + BCH Fuzzy Extractor — Full Specification

> **P3-05 (2026-08-26) editorial note — aspirational, research code, non-default.** This
> document describes the *design* of `aethel-core`'s `puf` module and its intended hardware
> integration. None of it is the crate's default or production key-derivation path:
> - `puf` is a non-default Cargo feature; the default build does not compile this module at all.
> - The real BCH(1023,512,55) encoder in `src/puf.rs` is a simplified placeholder, not the full
>   constant-time decoder described in §6 below (that C decoder exists in `c/bch_decoder.c` but
>   is gated behind the separate, also-non-default `enclave` feature, and is not buildable
>   against a real enclave target in this repo).
> - §10's hardware targets (ARM TrustZone, Apple Secure Enclave, AWS Nitro Enclaves, RISC-V
>   Keystone) are not implemented or tested against in this repo.
> - `MasterIdentity::from_seed` — the crate's actual, default identity-derivation entry point —
>   takes a caller-supplied 32-byte seed and has no PUF dependency whatsoever.
>
> Kept as a design document for the `puf` feature rather than withheld, since the design itself
> is coherent and the feature is real (if non-default and incomplete) — but every "MUST"/"SHALL"
> below describes a target for that feature, not a property of the crate's default build.
> Cross-check basis: `aethel-core`'s README, "What runs today vs. what is designed."

## RFC Draft: Aethel-ID (AETHEL-SPEC-001) — Section 8

A critical vulnerability of classical identity runtimes is the persistence of cryptographic master keys in non-volatile storage (Flash, EEPROM, or disk). Under physical capture or cold-boot side-channel analysis, persistent keys can be extracted.

Aethel-ID addresses this by employing a **Physical Uncloneable Function (PUF)** derived from silicon SRAM startup characteristics. By pairing the unconditioned physical noise of an SRAM array with a **Secure Fuzzy Extractor**, the master state vector **s** is never stored. Instead, **s** is dynamically reconstructed in volatile RAM only for the duration of zero-knowledge proof generation, after which its volatile memory footprint is explicitly zeroized.

---

## 1. Physical SRAM PUF Model

When an uninitialized SRAM cell powers up, the cross-coupled inverters enter a metastable state that settles into a logical 0 or 1 state. This preference is dictated by microscopic, non-deterministic threshold voltage mismatches (ΔV_th) introduced during silicon fabrication.

Let **W_sram ∈ {0,1}^L** represent an L-bit unconditioned response string sampled from a designated hardware SRAM block upon power-on.

**Noise Behavior:** Sub-array power noise, thermal fluctuations, and physical aging introduce bit-flip errors between power cycles.

**Hamming Distance Bound:** Let **W** be the enrollment response and **W'** be an evaluation response sampled at a later time. The fractional Hamming distance satisfies:

```
HD(W, W') ≤ δ_in · L
```

where **δ_in** is the intra-PUF bit error rate (typically **δ_in ≤ 0.15** under operational temperature shifts between -40°C and +85°C).

---

## 2. Fuzzy Extractor Primitive Construction

A Fuzzy Extractor consists of two algorithms: **Enrollment (Gen)** and **Key Reconstruction (Rep)**. It converts noisy, non-uniform physical measurements **W** into a uniformly distributed key **R ∈ {0,1}^d** while publishing helper data **P** that reveals no information about **R**.

```
ENROLLMENT PHASE (Gen):
  [ SRAM Startup Response W ] ---> [ Gen(W) ] ---> Secret Key (R)
                                       |
                                       v
                               Helper Data P (Stored publicly on-device)

RECONSTRUCTION PHASE (Rep):
  [ Noisy SRAM Response W' ] + [ Helper Data P ] ---> [ Rep(W', P) ] ---> Secret Key R
                                                           |
                                                           v
                                                  [ Master Secret s ]
                                                  (Volatile RAM Only)
```

### 2.1 Code-Offset Construction (Gen)

1. **Linear Error-Correcting Code**: Select an **[n, k, 2t+1]** linear error-correcting code **C** over **F_2** capable of correcting up to **t = ⌊δ_in · n⌋** bit errors (e.g., concatenated BCH codes or polar codes).
2. **Entropy Extraction Hash**: Let **Extract: {0,1}^n → {0,1}^d** be a strong randomness extractor (e.g., KMAC256 or Universal Hash family).
3. **Enrollment Procedure Gen(W)**:
   - Sample a random codeword **C ← C** uniformly at random.
   - Compute the helper vector (syndrome/offset): **P = W ⊕ C**
   - Derive the stable uniform key string **R**: **R = Extract(C)**
   - Output **(R, P)**. Store **P** in non-volatile flash or host configuration storage; immediately discard **W**, **C**, **R** from non-volatile memory.

### 2.2 Error Mitigation & Key Reconstruction (Rep)

Upon receiving a noisy startup evaluation **W'** and the public helper data **P**:

1. Compute noisy codeword estimate: **C' = W' ⊕ P = W' ⊕ (W ⊕ C) = C ⊕ (W ⊕ W')**
2. Apply the decoding algorithm **Decode_C** to eliminate noise **(W ⊕ W')**: **C = Decode_C(C')** (Succeeds provided **HD(W, W') ≤ t**)
3. Re-extract the stable uniform key string **R**: **R = Extract(C)**

---

## 3. BCH Code Construction Parameters

The Aethel-ID fuzzy extractor uses a **BCH(1023, 512, 55)** code over **GF(2^10)**:

| Parameter | Notation | Value |
|-----------|----------|-------|
| Galois Field Extension Degree | m | 10 (GF(2^10), N_code = 2^10 - 1 = 1023) |
| Block Code Length | n_bch | 1023 bits |
| Information Payload Length | k_bch | 512 bits |
| Error Correction Capacity | t_bch | 55 errors per block |
| Generator Polynomial Degree | deg(g(x)) | 511 bits (parity length n - k = 511) |
| GF(2^10) Primitive Polynomial | GF_POLY | 0x409 (x^10 + x^3 + 1) |

---

## 4. Enrollment Phase (Gen) — Full Algorithm

```
Algorithm BCH-FuzzyExtractor.Gen(W):
  Input:  Raw SRAM power-up state W ∈ {0,1}^L (L ≥ n_bch = 1023)
  Output: (K_master, P_helper)

  1. Read primary SRAM power-up state:
     R_enroll <- ReadSramUninitializedArray()

  2. Sample a uniform random cryptographic seed:
     S_seed <- {0, 1}^k_bch  (512 bits)

  3. Encode S_seed using systematic BCH(1023, 512, 55) encoding to yield
     codeword C_code = (S_seed || Parity) in {0, 1}^n_bch.

  4. Compute secure sketch helper string W_sketch:
     W_sketch = R_enroll[0..n_bch-1] XOR C_code

  5. Extract master key via SHA3-256 privacy amplification:
     K_master = SHA3-256(S_seed || "AETHEL_PUF_PRIVACY_AMP_V1")

  6. Construct Helper Data string:
     P_helper = (W_sketch || VersionTag)

  7. Write P_helper to persistent non-volatile storage (NVM).

  8. IMMEDIATELY ZEROIZE: W, S_seed, C_code, K_master from volatile memory.

  9. Return (K_master [used once], P_helper)
```

---

## 5. Reconstruction Phase (Rep) — Full Algorithm

```
Algorithm BCH-FuzzyExtractor.Rep(W', P_helper):
  Input:  Noisy SRAM power-up state W' ∈ {0,1}^L
          Public helper string P_helper = (W_sketch || VersionTag)
  Output: K_master ∈ {0,1}^256  (or ABORT on decoding failure)

  1. Fetch public helper string W_sketch from P_helper.

  2. Read current SRAM power-up state:
     R_reconstruct <- ReadSramUninitializedArray()

  3. Reconstruct noisy codeword C_noisy:
     C_noisy = R_reconstruct[0..n_bch-1] XOR W_sketch

  4. Execute constant-time BCH decoding on C_noisy using
     Berlekamp-Massey and Chien Search subroutines:
     S_reconstructed <- BchDecode(C_noisy, t_bch=55)

     * If decoding fails (uncorrectable errors > 55), ABORT immediately.
       Do NOT return partial secret candidate data.

  5. Re-derive deterministic master identity key K_master:
     K_master = SHA3-256(S_reconstructed || "AETHEL_PUF_PRIVACY_AMP_V1")

  6. IMMEDIATELY ZEROIZE: C_noisy, S_reconstructed, and working decoder
     buffers using explicit compiler memory barriers.

  7. Return K_master
```

---

## 6. BCH(1023, 512, 55) Decoder — Algorithm Specification

The BCH decoder implements three phases: **Syndrome Computation**, **Berlekamp-Massey Error Locator Polynomial**, and **Chien Search**. All phases MUST execute in constant time.

### 6.1 GF(2^10) Arithmetic

The Galois Field **GF(2^10)** is constructed using the primitive polynomial:

```
p(x) = x^10 + x^3 + 1  (GF_POLY = 0x409)
```

**GF Multiplication (constant-time):**
```c
// GF(2^10) multiplication using pre-computed log/antilog tables
uint16_t gf_mul(uint16_t a, uint16_t b) {
    if (a == 0 || b == 0) return 0;
    uint32_t log_sum = gf_log[a] + gf_log[b];
    // Reduce modulo (2^10 - 1) = 1023 without branching
    log_sum = (log_sum >> 10) + (log_sum & 1023);
    log_sum = (log_sum >> 10) + (log_sum & 1023);
    return gf_exp[log_sum];
}
```

### 6.2 Syndrome Computation

For received word **r(x)** of length **n_bch = 1023**, compute **2t = 110** syndromes:

```
S_i = r(α^i)  for i = 1, 2, ..., 2t
```

where **α** is a primitive element of **GF(2^10)**.

### 6.3 Berlekamp-Massey Error Locator Polynomial

The Berlekamp-Massey algorithm finds the shortest LFSR that generates the syndrome sequence, yielding the error locator polynomial **σ(x)** of degree **≤ t**:

```
σ(x) = 1 + σ_1·x + σ_2·x^2 + ... + σ_t·x^t
```

The roots of **σ(x)** are the inverses of the error locations.

### 6.4 Chien Search (Constant-Time)

The Chien Search evaluates **σ(x)** at all **n_bch = 1023** field elements to find error locations. The implementation MUST be constant-time (no early exit on finding all errors):

```c
// Constant-time Chien Search over all 1023 field elements
void ct_chien_search(
    const uint16_t sigma[BCH_T + 1],
    uint16_t error_locations[BCH_T],
    uint32_t *num_errors
) {
    uint32_t found = 0;
    for (uint32_t i = 1; i <= BCH_N; i++) {
        uint16_t eval = 0;
        uint16_t x_pow = 1;
        for (int j = 0; j <= BCH_T; j++) {
            eval ^= gf_mul(sigma[j], x_pow);
            x_pow = gf_mul(x_pow, gf_exp[i]);
        }
        // Constant-time: accumulate without branching
        uint32_t is_root = ct_is_equal(eval, 0);
        uint32_t slot = found & ct_select(is_root, ~0u, 0u);
        error_locations[slot & (BCH_T - 1)] = (uint16_t)(BCH_N - i);
        found += is_root;
    }
    *num_errors = found;
}
```

### 6.5 Full BCH Decode Function Signature

```c
/**
 * aethel_bch_decode_1023_512_55 - Constant-time BCH(1023,512,55) decoder
 *
 * @param received    Input: 1023-bit received word (noisy codeword)
 * @param corrected   Output: 512-bit corrected information payload
 * @return            0 on success, -1 if uncorrectable errors detected
 *
 * Parameters: BCH_N=1023, BCH_K=512, BCH_T=55, BCH_M=10, GF_POLY=0x409
 *
 * SECURITY: This function MUST execute in constant time regardless of
 * the number of errors detected. No early exits are permitted.
 */
int32_t aethel_bch_decode_1023_512_55(
    const uint8_t received[128],   // 1023 bits packed into 128 bytes
    uint8_t corrected[64]          // 512 bits packed into 64 bytes
);
```

---

## 7. Expansion to Ring Polynomial Master Secret s

The reconstructed bit string **R ∈ {0,1}^d** serves as the seed for a deterministic Centered Binomial Distribution (CBD_η) sampler to derive the short-norm vector **s ∈ R_q^k**:

```
s ← SampleCBD_η(SHAKE-256(R ∥ "AETHEL_PUF_SEED_V1"))
```

```
                                PUF SEED EXPANSION
  [ Reconstructed Key R ] ---> [ SHAKE-256 ] ---> Pseudo-Random Stream
                                                       |
                                                       v
                                            [ Centered Binomial Sampler ]
                                                       |
                                                       v
                                            [ Master Secret Vector s ]
                                            (s ∈ R_q^k, ||s||_∞ ≤ η)
```

---

## 8. Mathematical Security & Helper Data Entropy Loss

**Theorem 8.1 (Min-Entropy Bound under Fuzzy Extraction):** Let **H_∞(W)** denote the min-entropy of the physical SRAM array. If the helper data **P** is published, the remaining min-entropy of **W** conditioned on **P** satisfies:

```
H_∞(W | P) ≥ H_∞(W) - (n - k)
```

To guarantee **d**-bit post-quantum security for key **R**, the SRAM array size **n** must satisfy:

```
n ≥ d + (n - k) + Margin_noise
```

**Parameter Enforcements:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Target Security Level (d) | 256 bits | 128-bit post-quantum security margin |
| SRAM Array Length (n) | 4096 bits | Sufficient entropy with noise margin |
| Code Dimension (k) | 512 bits | BCH(1023, 512, 55) information payload |
| Correctable Error Tolerance (t) | Up to 18% bit flips | Covers -40°C to +85°C operational range |

---

## 9. Lifecycle Specification: Enrollment, Reconstruction, and Zeroization

```
                          SECURE VOLATILE LIFECYCLE
  [ Enclave Boot ] ──> [ Read SRAM W' ] ──> [ Rep(W', P) ] ──> Reconstruct s
                                                                     │
                                                                     ▼
  [ Zeroize SRAM ] <── [ Zeroize s ] <── [ Generate Proof π_τ ] <───┘
```

### 9.1 Enrollment Phase (One-Time Provisioning)

- Enclave powers up in factory provisioning mode.
- Reads raw SRAM response **W**.
- Executes **(R, P) ← Gen(W)**.
- Writes helper data **P** to public non-volatile storage.
- Zeroizes **W** and **R** immediately.

### 9.2 Reconstruction Phase (Runtime ZK Proving)

- Enclave receives proof request for context **τ**.
- Reads raw SRAM response **W'** and fetches public helper data **P**.
- Executes **R ← Rep(W', P)**.
- Maps **R → s ∈ R_q^k** in volatile enclave scratchpad memory.
- Executes constant-time ZK rejection sampling proof generation.

### 9.3 Purge & Zeroization Phase

- Upon proof completion or execution abort, the enclave executes explicit memory barriers flushing **R**, **C**, **C'**, and **s** from volatile registers and L1 cache lines.
- **Invariant**: **s** exists in memory for at most the duration of a single proof generation cycle (**< 50 ms**).

---

## 10. Hardware Requirements

### 10.1 ARM TrustZone

- Secure World execution for SRAM PUF sampling and BCH decoding.
- Non-cacheable memory regions for intermediate lattice operations.
- TrustZone-M (ARMv8-M) for microcontroller deployments.
- Secure Monitor Call (SMC) interface for proof generation requests.

### 10.2 Apple Secure Enclave

- Dedicated secure processor with hardware-isolated memory.
- SRAM PUF sampling via Secure Enclave Processor (SEP) startup state.
- Hardware AES and SHA3 acceleration for BCH and SHAKE-256 operations.
- Secure boot chain verification before PUF enrollment.

### 10.3 AWS Nitro Enclaves

- Isolated virtual machine with no persistent storage.
- SRAM PUF emulation via hardware entropy sources (RDRAND/RDSEED).
- Attestation document generation for remote verification.
- Memory encryption via AMD SME/SEV or Intel TME.

### 10.4 RISC-V Keystone

- Open-source enclave framework for RISC-V processors.
- Physical Memory Protection (PMP) for enclave isolation.
- SRAM PUF sampling from uninitialized SRAM regions at boot.
- Custom security monitor (SM) for enclave lifecycle management.

---

## 11. Security Analysis

### 11.1 Helper Data Non-Leakage

The public helper data string **W_sketch** derived during BCH enrollment reveals strictly at most **n_bch - k_bch = 511 bits** of information about the raw SRAM power-up state.

### 11.2 Environmental BER Boundaries

If operating conditions cause the SRAM intra-device BER to exceed the BCH error correction threshold (**t_bch = 55 errors per 1023-bit block**), the reconstruction algorithm MUST abort cleanly without returning partial secret candidate data.

### 11.3 Zeroization Failure Countermeasures

Implementations MUST implement active memory clearing via explicit compiler barriers or hardware volatile wipes to prevent residual **K_master** state from persisting in cache lines.

**C code for explicit zeroization:**
```c
// Force compiler execution of memory sanitization
void enclave_explicit_zeroize(volatile void *v, size_t n) {
    volatile char *p = (volatile char *)v;
    while (n--) {
        *p++ = 0;
    }
    __asm__ __volatile__("" ::: "memory");
}
```

### 11.4 Physical Attack Resistance

1. **Cold-Boot Attacks**: The master secret **s** is never written to non-volatile storage. A powered-down device yields no cryptographic material.
2. **Differential Power Analysis (DPA)**: First-order masking of master state vectors during NTT calculation splits **s** into two shares **s_1 + s_2 (mod q)**.
3. **Electromagnetic (EM) Side-Channels**: PRNG jitter injection during polynomial arithmetic loops breaks alignment across multiple collected power traces.
4. **Invasive Physical Attacks**: SRAM PUF responses are unique to each silicon die; cloning the device does not reproduce the PUF response.

### 11.5 Aging and Environmental Stability

- **Temperature Range**: BCH(1023, 512, 55) corrects up to 55 bit errors, covering the typical intra-PUF BER of ≤ 15% across -40°C to +85°C.
- **Device Aging**: Silicon threshold voltage drift over device lifetime may increase BER. Implementations SHOULD monitor BER trends and re-enroll if BER approaches the correction threshold.
- **Radiation Effects**: In high-radiation environments (e.g., aerospace), additional error correction margin or re-enrollment protocols SHOULD be implemented.

---

## 12. Microarchitectural Memory Isolation

```
+---------------------------------------------------------------------------------+
|                        SECURE ENCLAVE ISOLATED BOUNDARY                         |
|                                                                                 |
|  [ Silicon SRAM PUF ]                                                           |
|          | (Volatile Fetch)                                                     |
|          v                                                                      |
|  [ Scratchpad SRAM ] ---> [ Fixed-Iteration Rejection Loop ] ---> [ Proof π_τ ] |
|  (Volatile Non-Cacheable)  - Constant-Address NTT Arithmetic      |             |
|                            - Constant-Stride Rejection Check      |             |
|                                                                   v             |
|  [ Explicit Zeroization ] <--------------------------------- [ Sanitize Scratch ]|
|  (Volatile Memory Flush)                                                        |
+---------------------------------------------------------------------------------+
                                                                    |
                                                            (Output Out-of-Enclave)
                                                                    v
                                                            [ Public Bus ]
```

- **No Dynamic Heap Allocation**: Enclave implementations MUST pre-allocate a static volatile scratchpad in SRAM during boot. Dynamic memory allocation (malloc) during rejection sampling execution is strictly prohibited.
- **Cache Line Locking / Non-Cacheable Regions**: Intermediate lattice operations MUST be assigned to non-cacheable memory regions or locked L1 data cache lines. This mitigates cache-eviction side-channel attacks (e.g., Prime+Probe, Flush+Reload).
- **Explicit Hardware Zeroization**: Upon loop termination, all intermediate vector registers, NTT structures, and secret-derived data MUST be explicitly zeroized using compiler-barrier memory sanitization routines.

---

## References

- Dodis, Y., Reyzin, L., Smith, A.: "Fuzzy Extractors: How to Generate Strong Keys from Biometrics and Other Noisy Data." EUROCRYPT 2004.
- Suh, G.E., Devadas, S.: "Physical Unclonable Functions for Device Authentication and Secret Key Generation." DAC 2007.
- Bose, R.C., Ray-Chaudhuri, D.K.: "On a Class of Error Correcting Binary Group Codes." Information and Control, 1960.
- Hocquenghem, A.: "Codes Correcteurs d'Erreurs." Chiffres, 1959.
- Berlekamp, E.R.: "Algebraic Coding Theory." McGraw-Hill, 1968.
- Massey, J.L.: "Shift-Register Synthesis and BCH Decoding." IEEE Transactions on Information Theory, 1969.
- IETF Internet-Draft: draft-harper-aethel-id-00, Section 4: "SRAM PUF Secret Derivation & BCH Error-Correcting Fuzzy Extractor."
