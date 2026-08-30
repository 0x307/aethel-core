---
title: "Selective Attribute Attestation Protocol (SAAP) — Full Specification"
version: "0.1.0-draft"
date: "2026-08-01"
project: "aethel-core"
---

# Selective Attribute Attestation Protocol (SAAP) — Full Specification

> **P3-05 (2026-08-26) editorial note.** §6 (Prove) and §7 (Verify) match the shipped
> `saap_prove`/`verify_saap_proof` (`src/saap.rs`) closely: one masking vector, one challenge,
> one response `z`. §2 (BDLOP commitment), §4, §5 (Issuance), §8 (the three-masking-vector
> `y_r`/`y_s`/`y_m` protocol), §9 (three linked relations), and §10.2 are **not implemented** —
> the shipped crate takes an already-parsed credential directly, does no BDLOP commitment of
> its own, and produces a single response vector, not three. §12 (WASM memory footprint) is
> marked aspirational — no such allocator or build constraint exists in the real build. §13.3
> and §14.2 (HelixDB) are out of scope. "On-chain" phrasing (§1.3, §11.1) is fixed — this crate
> has no blockchain component. Cross-check basis: `aethel-core`'s README, "What runs today vs.
> what is designed."

## RFC Draft: Aethel-ID (AETHEL-SPEC-001) — Section 6

Classical identity credentials (e.g., W3C Verifiable Credentials) rely on digital signatures over structured JSON-LD or JWT payloads. Verifying an attribute traditionally requires revealing the holder's public key or identifier alongside the signature, enabling verifiers to correlate identity state across multiple contexts.

This section specifies the **Selective Attribute Attestation Protocol (SAAP)** for Aethel-ID. SAAP allows a Holder to prove arbitrary statements (e.g., membership, range bounds, predicate matching) about credential attributes without disclosing non-requested attributes, without exposing static identity identifiers, and without revealing the Issuer's signature object directly.

---

## 1. Protocol Overview

### 1.1 Roles

- **Issuer**: An authority that signs credential attribute vectors and issues credential tuples to Holders.
- **Holder**: An entity that holds a credential and generates selective disclosure proofs.
- **Verifier**: An entity that validates SAAP proof transcripts without learning undisclosed attributes.

### 1.2 High-Level Flow

```
ISSUANCE PHASE (One-time, Private Setup):
  Issuer Key + Attributes (m) ----> BDLOP Commitment (t_cred) ----> Signature σ_Issuer
                                                                         |
                                                                         v
PROVING PHASE (Selective Disclosure):                     Holder Local Runtime
  Holder local secret s + t_cred + m_revealed
         |
         +----> Randomized Blinded Commitment (C_attr)
         +----> M-LWE Ephemeral Projection (b_τ)
         +----> Lattice ZK Proof (π_SAAP) ------------------> Verifier Verification
                                                                (Zero Identifiers Disclosed)
```

### 1.3 Security Goals

1. **Zero Identifier Disclosure**: Neither the holder's master secret **s**, nor any persistent public key, nor the Issuer's raw signature object is transmitted or exposed by this crate's API.
2. **Context-Isolated Unlinkability**: Because **r_blind** is freshly sampled for every verification session, two separate verifications of the exact same credential produce statistically independent commitments **t_blind^(1)** and **t_blind^(2)**, preventing cross-verifier collusive tracking.
3. **Post-Quantum Soundness**: The extraction hardness of hidden attributes **m_hidden** from **t_blind** reduces directly to the hardness of the Module Short Integer Solution (M-SIS_{k,l,q}) and M-LWE_{k,l,q} problems over **R_q**.

---

## 2. Cryptographic Primitives: Lattice Commitment Scheme (BDLOP)

**Implemented** in `src/credential.rs` (`IssuerParams`, `Credential::issue`).

> See the editorial note at the top of this document — the shipped `saap_prove` does not
> construct a BDLOP commitment; it operates directly on caller-supplied credential bytes.

Attestation issuance uses a Module-Lattice Commitment Scheme derived from the **Baum-Dunkelman-Lyubashevsky-Orcioni-Pointcheval (BDLOP)** framework over **R_q = Z_q[X]/(X^N + 1)**.

### 2.1 Attribute Vector Encoding

A Credential Schema maps **n** identity attributes **(a_1, a_2, ..., a_n)** into ring elements:
```
m = (m_1, m_2, ..., m_n) ∈ R_q^n
```

### 2.2 BDLOP Credential Commitment

The Issuer generates a binding and hiding credential commitment **t_cred** over the message vector **m** using randomness **r ← χ_η^l**:

```
t_cred = B_1 · r + (0 ∥ m)  (mod q)
```

where **B_1 ∈ R_q^{(l+n)×l}** is a public expansion matrix generated deterministically from an Issuer Seed.

---

## 3. Parameter Definitions

### 3.1 Core Algebraic Parameters

> Only AETHEL-SAAP-LEVEL1 is implemented; LEVEL3/LEVEL5 are unbuilt proposals.

| Parameter | Notation | AETHEL-SAAP-LEVEL1 | AETHEL-SAAP-LEVEL3 | AETHEL-SAAP-LEVEL5 |
|-----------|----------|--------------------|--------------------|-------------------|
| Ring Degree | N | 256 | 256 | 256 |
| Prime Modulus | q | 8,380,417 | 8,380,417 | 8,380,417 |
| Module Rank | k | 4 | 6 | 8 |
| Attribute Capacity | m | 8 | 12 | 16 |
| Rejection Bound | γ₁ | 131,072 (2^17) | 131,072 (2^17) | 524,288 (2^19) |
| Noise Bound | β | 78 | 78 | 120 |
| CBD Parameter | η | 2 | 2 | 2 |
| Context Tag Size | τ | 256 bits | 256 bits | 384 bits |
| Claim Capacity | \|A\| | ≤ 8 fields | ≤ 12 fields | ≤ 16 fields |

### 3.2 Modulus Arithmetic Properties

The prime modulus **q = 8,380,417 (2^23 - 2^13 + 1)** MUST be used across all parameter profiles.

1. **NTT Compatibility**: q = 1 mod 2N (8,380,417 = 1 mod 512), enabling efficient Number Theoretic Transform (NTT) polynomial multiplications in O(N log N) time.
2. **Word-Size Efficiency**: q fits within a signed 24-bit integer, allowing vector accumulation steps in standard 32-bit registers or SIMD vector units without intermediate overflow.

### 3.3 Rejection Sampling Thresholds

- For LEVEL1 and LEVEL3: **∥z∥_∞ < 130,994** (131,072 - 78).
- For LEVEL5: **∥z∥_∞ < 524,168** (524,288 - 120).

Vectors failing this bound check MUST be rejected and re-sampled using fresh ephemeral randomness **y ← S_γ₁^k** in constant time.

---

## 4. Issuance & Blinding Mechanics

**Implemented** in `src/credential.rs` (`Credential::issue`, `BlindedCredential::new`).

> See the editorial note at the top of this document — no issuance or signing layer exists in the shipped crate.

### 4.1 Issuer Signature

The Issuer signs the commitment **t_cred** using an ML-DSA / Dilithium signature **σ_Issuer**.

### 4.2 Holder Blinding

Before presenting attributes to a Verifier for context **τ**, the Holder blinds **t_cred** using fresh randomness **r_blind ← χ_η^l**:

```
t_blind = t_cred + B_1 · r_blind  (mod q)
```

### 4.3 Attribute Selection Vector

Let **I_disclosed ⊂ {1,...,n}** be the index set of attributes selected for disclosure, and **I_hidden = {1,...,n} \ I_disclosed** be the hidden set.

### 4.4 Attribute Projection

The Holder splits **m** into public components **m_pub** (where **i ∈ I_disclosed**) and hidden commitments **C_hidden** (where **j ∈ I_hidden**):

```
C_j = B_{2,j} · r_blind + m_j  (mod q)  ∀j ∈ I_hidden
```

---

## 5. Issue Algorithm (SAAP.Issue)

**Implemented** in `src/credential.rs` (`Credential::issue`).

> See the editorial note at the top of this document.

```
Algorithm SAAP.Issue(sk_iss, A, ContextID):
  Input:  Issuer secret key sk_iss
          Attribute vector A = (a_1, ..., a_n) ∈ R_q^n
          Context identifier ContextID ∈ {0,1}^256
  Output: Credential tuple C_iss = (t_attr, A, ContextID, Σ_iss)

  1. Sample public commitment matrix:
     B ← R_q^(k × m)  deterministically from ContextID using SHAKE-256.

  2. Sample small-norm commitment error vector:
     e_commit $<- (CBD_η)^k

  3. Construct homomorphic attribute vector commitment:
     t_attr = B * A + e_commit  (mod q)

  4. Sign message payload:
     M_iss = (t_attr ∥ ContextID)
     Σ_iss = (c_iss, z_iss) ← ML-DSA.Sign(sk_iss, M_iss)

  5. Output Credential Tuple:
     C_iss = (t_attr, A, ContextID, Σ_iss)
```

---

## 6. Prove Algorithm (SAAP.Prove)

**Implemented** in `src/credential.rs` as `credential::prove`.

This section previously carried the RFC's *superseded* single-`z` sketch, the one
immediately preceding RFC 5.6. That algorithm proved a single relation against a
SAAP-local public key and is gone. What follows is the algorithm that is built.

```
Algorithm SAAP.Prove(B_1, blinded_credential, s, projection, tau, rho, M_disc, rand):
  Input:  Issuer parameters B_1 in R_q^(T x L)
          Blinded credential (t_blind, r*, m)
          Holder master secret s in R_q
          PLP projection (A_tau, b_tau)
          Context tau, projection randomness rho
          Disclosure bitmask M_disc, presentation randomness
  Output: Presentation (tau, M_disc, m_pub, c, z_r, z_m, z_s, z_e)

  1. Re-derive the projection error term:
       e_tau = CBD_eta2(SHAKE256("AETHEL_ERROR_V2" || rho || tau))
     e_tau is a witness, not a stored value. See section 6.1.

  2. Split m into m_pub and m_hidden by M_disc.
     Slot 0 is the identity binding and is always hidden.

  3. REJECTION_LOOP:
     a. Sample short masks y_r in R_q^L, y_s in R_q, y_e in R_q, each in [-gamma1, gamma1].
     b. Sample message masks y_m: slot 0 reuses y_s; slots 1..n are uniform over R_q.
     c. W_1 = B_1 * y_r + (0^L || y_m)
        W_2 = A_tau * y_s + y_e
     d. c = HashToPoly("AETHEL_SAAP_CHALLENGE_V2" || W_1 || W_2 || b_tau
                        || t_blind || M_disc || m_pub || tau)
     e. z_r = y_r + c * r*
        z_m = y_m + c * m_hidden
        z_s = y_s + c * s
        z_e = y_e + c * e_tau
     f. If ||z_r||inf, ||z_s||inf or ||z_e||inf >= (gamma1 - beta):
          wipe y and z, GOTO REJECTION_LOOP.
        z_m for attribute slots has no bound. See section 6.2.

  4. If the loop is exhausted, return an error.
     There is no fallback. See section 6.3.

  5. Output (tau, M_disc, m_pub, c, z_r, z_m, z_s, z_e)
```

### 6.1 Why `e_tau` is part of the witness

RFC 5.7 reconstructs `W_2' = A_tau * z_s - c * b_tau` and expects the prover's
`W_2`. It does not get it. Expanding with `b_tau = A_tau * s + e_tau`:

```
A_tau * z_s - c * b_tau = A_tau * (y_s + c*s) - c*(A_tau*s + e_tau)
                        = A_tau * y_s - c * e_tau
```

The residual `-c * e_tau` cannot be tolerated by a Fiat-Shamir verifier, because
the hash of an approximately correct commitment is not approximately the
challenge. `plp::Verifier` avoids this by sending `W` in the proof and accepting
a `2*beta` tolerance, which is a relaxed check.

This implementation removes the residual instead. `e_tau` joins the witness with
mask `y_e` and response `z_e`, and

```
A_tau * z_s + z_e - c * b_tau = A_tau * y_s + y_e = W_2
```

holds exactly. `e_tau` is never stored: it is a deterministic function of
`(rho, tau)`, and `plp::project_at_context` and the prover share one derivation
so the projection and the witness cannot drift apart.

### 6.2 Why attribute masks are not short

BDLOP requires only the commitment randomness to be short. Attribute values are
not short, so a mask drawn from `[-gamma1, gamma1]` would not hide them.
Attribute masks are drawn uniformly from all of `R_q`, which hides the message
perfectly and needs no rejection sampling.

Slot 0 is the exception: it holds the master secret `s`, which is CBD-small, and
shares the short mask `y_s` so that `z_m[0]` and `z_s` are the same value. That
equality is what links the two relations, and the verifier checks it.

Soundness does not need the message components to be short. Extraction from two
transcripts yields `delta_z_r = delta_c * r*` short, which is the relaxed opening
BDLOP is proved under.

### 6.3 Exhausted rejection sampling returns an error

There is no fallback to the last candidate. A response that failed the norm check
is exactly the value rejection sampling exists to withhold, and emitting one is
how a sigma protocol leaks the secret the check was protecting.

---

## 7. Verify Algorithm (SAAP.Verify)

```
Algorithm SAAP.Verify(τ, t_blind, m_pub, b_τ, π_SAAP):
  Input:  Session context τ
          Blinded commitment t_blind
          Disclosed attribute values m_pub
          Ephemeral projection b_τ
          Proof transcript π_SAAP = (c, z_r, z_s, z_m)
  Output: ACCEPT or REJECT

  1. Check Response Vector Norms:
       If ∥z_r∥_∞ >= (γ_1 - β) OR ∥z_s∥_∞ >= (γ_1 - β) OR ∥z_m∥_∞ >= (γ_1 - β):
         Return REJECT ("Norm check failed")

  2. Reconstruct Commitment Matrices:
       W_1' = B_1 * z_r + [0 ∥ z_m] - c * (t_blind - [0 ∥ m_pub]) mod q
       W_2' = A_tau * z_s - c * b_tau mod q

  3. Validate Fiat-Shamir Challenge:
       c' = Hash(W_1' ∥ W_2' ∥ b_tau ∥ t_blind ∥ m_pub ∥ τ)
       If c' != c:
         Return REJECT ("Challenge mismatch")

  4. Validate Predicate Constraints:
       Evaluate quadratic polynomial relations over z_m for hidden attributes.
       If predicate checks pass:
         Return ACCEPT ATTESTATION
       Else:
         Return REJECT ("Predicate check failed")
```

---

## 8. Full Protocol Execution Steps

**Implemented** end to end for issuance, blinding, proving and verification. The predicate step is not. See section 9.3.

> See the editorial note at the top of this document — the shipped protocol uses a single
> masking vector / response, not the three (`y_r`, `y_s`, `y_m`) shown below.

```
Prover P                                                               Verifier V
----------------------------------------------------------------------------------
1. Sample masking vectors y_r, y_s, y_m.
2. Compute commitments W_1 = B_1 * y_r + [0 ∥ y_m], W_2 = A_tau * y_s mod q.
3. c = Hash(W_1 ∥ W_2 ∥ b_tau ∥ t_blind ∥ m_pub ∥ τ) ----------> Send Challenge
4. Rejection Sampling:
     z_r = y_r + c * r*
     z_s = y_s + c * s
     z_m = y_m + c * m_hidden
     Check norm bounds on (z_r, z_s, z_m). Repeat if bounds fail.
5. Send Proof π_SAAP = (c, z_r, z_s, z_m) ---------------------------> Validate Bounds
                                                                         Recompute W_1', W_2'
```

---

## 9. Three Linked ZK Relations

**Two of three implemented.** Identity linkage and credential membership are built and tested; predicate satisfaction is not. See section 9.3.

> See the editorial note at the top of this document.

To prove possession of a valid credential containing attributes satisfying predicate **P(m_hidden)** under context **τ**, the Holder generates a Zero-Knowledge proof **π_SAAP** consisting of three linked relations:

### 9.1 Identity Linkage Relation

Proves knowledge of the master state vector **s** corresponding to the context-bound Polymorphic Lattice Projection:

```
b_τ = A_τ · s + e_τ  (mod q)
```

### 9.2 Credential Membership Relation

Proves knowledge of short randomness vectors **r, e*** and hidden message polynomial vector **m_hidden** such that:

```
t_blind - (0 ∥ m_pub) = B_1 · r* + (0 ∥ m_hidden)  (mod q)
```

### 9.3 Predicate Satisfaction Relation (Range / Membership Proof)

> **NOT IMPLEMENTED.** Nothing in `aethel-core` evaluates a range or membership
> predicate, and no function claims to. It is scoped out explicitly rather than
> stubbed, so that no caller can mistake an unevaluated predicate for a satisfied
> one. **A verifier cannot currently learn "age >= 21" from a SAAP presentation.**
> Selective disclosure of whole attributes works; predicates over hidden
> attributes do not. Tracked as follow-on work to 0X3-79.

The design, for when it is built. For hidden numerical attributes (e.g., Age >= 21),
the prover proves in ZK that:

```
m_age - 21 = ∑_{k=0}^{v} b_k · 2^k  where b_k ∈ {0,1} ∈ R_q
```

This bit-decomposition proves the hidden attribute satisfies the range bound without revealing the actual value.

---

## 10. IETF Internet-Draft Specification (draft-harper-aethel-id-00)

### 10.1 SAAP Terminology

**Selective Attribute Attestation Protocol (SAAP):**
A zero-knowledge proof scheme based on Module Learning With Errors (M-LWE) that allows an identity holder to demonstrate validity of a subset of signed attributes without revealing undisclosed fields or exposing long-term signer public keys.

**Polymorphic Projection:**
A dynamic context-bound linear transformation applied to a vector commitment, preventing cross-presentation transaction correlation by injecting fresh, ephemeral polynomial blinding factors.

**Constant-Time Rejection Sampling:**
A deterministic, side-channel resistant execution mechanism that filters candidate lattice vectors against bound thresholds without introducing secret-dependent control-flow branches or memory access index patterns.

### 10.2 SAAP.Issue Algorithm (IETF Format)

> See the editorial note at the top of this document.

```
Algorithm:
1. Sample public commitment matrix B <- R_q^(k x m) deterministically from
   ContextID using SHAKE-256.
2. Sample small-norm commitment error vector e_commit $<- (CBD_eta)^k.
3. Construct homomorphic attribute vector commitment t_attr:
   t_attr = B * A + e_commit  (mod q)
4. Sign message payload M_iss = (t_attr || ContextID) under sk_iss to produce
   Sigma_iss = (c_iss, z_iss) via ML-DSA / M-LWE lattice signature rules.
5. Output Credential Tuple C_iss = (t_attr, A, ContextID, Sigma_iss).
```

### 10.3 SAAP.Prove Algorithm (IETF Format)

```
Algorithm:
1. Parse disclosed subset S = { i | M_disc[i] == 1 }.
2. Sample polynomial blinding vector r_blind <- (S_gamma1)^k.
3. Compute blinded commitment t_blind:
   t_blind = t_attr + B * r_blind  (mod q)
4. Compute commitment domain hash:
   h_commit = SHA3-256(t_blind || ContextID)
5. REJECTION_LOOP:
   a. Sample ephemeral masking vector y <- (S_gamma1)^k uniformly at random.
   b. Compute linear commitment projection w':
      w' = A * y  (mod q)
   c. Derive challenge polynomial c in R_q:
      c = HashToPoly(h_commit || tau || M_disc || w' || "AETHEL_SAAP_CHALLENGE_V1")
   d. Compute candidate response vector z:
      z = y + c * r_blind  (mod q)
   e. CONSTANT-TIME REJECTION CHECK:
      Evaluate ||z||_inf against bound (gamma1 - beta).
      If ||z||_inf >= (gamma1 - beta), clear y, z and GOTO REJECTION_LOOP.
6. Output Proof Transcript pi_saap = (tau, M_disc, A_S, c, z, h_commit).
```

### 10.4 SAAP.Verify Algorithm (IETF Format)

```
Algorithm:
1. Norm Check:
   Verify that ||z||_inf < (gamma1 - beta).
   If ||z||_inf >= (gamma1 - beta), REJECT immediately.
2. Disclosed Attributes Linear Combination:
   Compute partial commitment sum over disclosed attribute slots i in S:
   v_disc = sum_{i in S} (B_i * a_i)  (mod q)
3. Reconstruct Linear Commitment Projection w'':
   w'' = A * z - c * (h_commit_element - v_disc)  (mod q)
4. Challenge Consistency Verification:
   Derive challenge polynomial estimate c':
   c' = HashToPoly(h_commit || tau || M_disc || w'' || "AETHEL_SAAP_CHALLENGE_V1")
5. Decision:
   If c' == c, return ACCEPT (1). Else, return REJECT (0).
```

---

## 11. Privacy & Security Guarantees

### 11.1 Zero Identifier Disclosure

Neither the holder's master secret **s**, nor any persistent public key, nor the Issuer's raw signature object is transmitted or exposed by this crate's API.

### 11.2 Context-Isolated Unlinkability

Because **r_blind** is freshly sampled for every verification session, two separate verifications of the exact same credential produce statistically independent commitments **t_blind^(1)** and **t_blind^(2)**, preventing cross-verifier collusive tracking.

### 11.3 Post-Quantum Soundness

The extraction hardness of hidden attributes **m_hidden** from **t_blind** reduces directly to the hardness of the Module Short Integer Solution (M-SIS_{k,l,q}) and M-LWE_{k,l,q} problems over **R_q**.

**Status.** This claim now has the construction it describes. `t_blind` and `B_1`
exist in the crate as of the credential module, so `SECURITY-PROOFS.md` Theorem
7.1 is a statement about code that is built rather than about a design. Two
qualifications remain, and neither is covered by the theorem:

1. The opening extracted from two transcripts is a **relaxed** opening, the
   standard notion for BDLOP, not an exact one.
2. `aethel-core` has had **no third-party cryptographic audit**. A reduction
   argument is not a review of the implementation that instantiates it.

### 11.4 Presentation Unlinkability

Two distinct SAAP proof transcripts generated from the same underlying attribute commitment **t_attr** using different session nonces **τ_1** and **τ_2** MUST be computationally indistinguishable from random elements in **R_q**.

### 11.5 Zero-Knowledge Disclosure

The SAAP proof protocol leaks strictly zero information regarding undisclosed attributes.

---

## 12. WebAssembly Memory Footprint and Enclave Execution Bounds

> **Aspirational — no allocator or build constraint in this repo enforces this.** See the editorial note at the top of this document.

### 12.1 Linear Memory Layout and Bounded Allocation

1. **Memory Boundary Cap**: Maximum allocation of 64 pages (4 Megabytes).
2. **No Dynamic Heap Allocator**: All internal buffers MUST use a deterministic arena allocator backed by a fixed stack footprint.
3. **Static Segment Mapping**:

| Memory Region | Offset Range | Purpose |
|---|---|---|
| Execution Stack | 0x000000 - 0x07FFFF | Function frames & local vars |
| Static Constants | 0x080000 - 0x0FFFFF | Pre-computed NTT twiddles |
| SRAM PUF Buffer | 0x100000 - 0x11FFFF | Raw/Reconstructed PUF data |
| Polynomial Scratchpad | 0x120000 - 0x2FFFFF | Working R_q matrices & z, y |
| Protected Output Pool | 0x300000 - 0x3FFFFF | Final SAAP proof transcript |

### 12.2 Bare-Metal Enclave Execution Specifications

- **Binary Size Ceiling**: MUST NOT exceed 256 Kilobytes in total size.
- **Stack Depth Ceiling**: MUST NOT exceed 32 Kilobytes.
- **Zero External System Calls**: The execution binary MUST be fully self-contained.

---

## 13. Security Considerations

### 13.1 Post-Quantum Lattice Hardness Assumptions

1. **Quantum Lattice Reduction**: Parameter sets are chosen such that the best known quantum primal and dual lattice attacks using the Block Korkine-Zolotarev (BKZ) algorithm with quantum sieving subroutines require:
   - ≥ 2^128 operations for AETHEL-SAAP-LEVEL1
   - ≥ 2^192 operations for AETHEL-SAAP-LEVEL3
   - ≥ 2^256 operations for AETHEL-SAAP-LEVEL5

2. **Algebraic Structure Risks**: Implementations MUST NOT reduce the module rank **k** below the normative minimums in Section 3.1.

### 13.2 Side-Channel and Fault Injection Attacks

1. **Constant-Time Rejection Sampling**: The rejection sampling loop and the BCH Chien search decoder MUST execute in constant time.
2. **Fault Injection Resilience**: Adversaries targeting the rejection check **∥z∥_∞ < (γ₁ - β)** via instruction-skipping or voltage-glitch attacks could force acceptance of unbounded response vectors. Implementations MUST use double-checked conditional evaluation bounds.

### 13.3 Temporal Graph-Manifold Security (HelixDB Storage)

> **Out of scope.** HelixDB storage is not part of `aethel-core` and is not planned for it.

1. **Cryptographic Node Deletion**: Nodes containing transient secrets MUST be stored encrypted under ephemeral storage keys; node deletion MUST be executed by cryptographically zeroizing the local node key.
2. **Sub-Graph Isolation**: Query execution over localized sub-graphs G_sub(t) MUST restrict pointer traversal to explicit topological edges.

---

## 14. Privacy Considerations

### 14.1 Unlinkability and Polymorphic Obfuscation

1. **Presentation Unlinkability**: Two distinct SAAP proof transcripts generated from the same underlying attribute commitment **t_attr** using different session nonces **τ_1** and **τ_2** MUST be computationally indistinguishable from random elements in **R_q**.
2. **Zero-Knowledge Disclosure**: The SAAP proof protocol leaks strictly zero information regarding undisclosed attributes.

### 14.2 Graph-Topological Privacy and Trajectory Protection

> **Out of scope.** HelixDB storage is not part of `aethel-core` and is not planned for it.

1. **Manifold Trajectory Reconstruction Attack**: Implementations MUST break temporal continuity by applying fresh, randomized vector projection transforms (Polymorphic Projections) to all node embeddings written to the storage manifold across epoch shifts.
2. **Vector Proximity Snooping**: Attribute vector commitments stored in HelixDB MUST be masked with homomorphic lattice noise to ensure that spatial proximity queries reveal relationship validity without exposing exact scalar attribute values.
3. **Forward Private Graph Pruning**: Implementations using temporal graph manifolds MUST support forward-private pruning, wherein clearing a past temporal epoch node **t_k** permanently renders all historical sub-graph trajectories mathematically un-navigable.

---

## References

- Baum, C., Dunkelman, O., Lyubashevsky, V., Orcioni, A., Pointcheval, D.: "BDLOP Commitment Scheme." (Basis for SAAP credential commitments)
- Lyubashevsky, V.: "Lattice Signatures Without Trapdoors." EUROCRYPT 2012.
- NIST FIPS 204: "Module-Lattice-Based Digital Signature Standard (ML-DSA)." 2024.
- IETF Internet-Draft: draft-harper-aethel-id-00, "Aethel-ID: Post-Quantum Sovereign Identity Architecture and Selective Attribute Attestations." August 2026.
- RFC 2119: "Key words for use in RFCs to Indicate Requirement Levels."
- RFC 8174: "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words."
