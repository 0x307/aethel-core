# Deviation register

Every place where this crate and its specifications disagree, with the ruling and who owns it.

Two specifications are in play:

- **RFC**: `AETHEL-SPEC-001`, the standards-track draft. It lives in a private working
  repository, so it is cited here by section number.
- **SAAP-SPEC**: [`docs/SAAP-SPEC.md`](./SAAP-SPEC.md), the public distillation of the RFC's
  credential sections, kept in this repository.

**How to read a row.** *Code wins* means the crate is right and the specification is to be
amended. *Spec wins* means the crate is to change. *Neither* means both are wrong today and the
fix starts with the specification. A row is **Open** until whatever is wrong has been changed,
and **Closed** when nothing further is to happen, including when the answer was deliberately
"no action".

**Keeping it current.** A change that makes the crate deviate from a specification adds its row
in the same pull request. See [`CONTRIBUTING.md`](../CONTRIBUTING.md). `tests/deviations.rs`
checks that the register stays linked and that any deviation explained in a source comment
points here.

Owner for every row is the maintainer, Ed Johnson, unless the row names someone else. Tracker
IDs are the project's internal issue numbers.

## Open

| ID | Topic | Specification says | Crate does | Ruling | Status |
|---|---|---|---|---|---|
| D-01 | Credential commitment shape | RFC §5.2.2 and SAAP-SPEC §2.2: `B_1 ∈ R_q^{(l+n)×l}`, `r ← χ_η^l`, described as hiding | Implements that shape exactly: `B_1` is 13×4 (`CRED_T`, `CRED_L`) | **Neither.** The shape cannot hide: its top `l` rows are a square, invertible system, so `t_cred` and `t_blind` reveal `r` and then `m`. The specification is corrected first, then the crate follows. See [`SECURITY.md`](../SECURITY.md) | Open. Spec: C6-01 (0X3-160). Code: 0X3-157 |
| D-02 | Rejection bound for `z_r` | RFC §3.4: one bound `γ₁ − β` with `β = 78` for every response | Applies `β = 78` to `z_r`, but `r* = r + r_blind` is a sum of two CBD(2) vectors, so `‖c·r*‖∞` can reach `39 × 4 = 156` | **Neither, suspected.** The zero-knowledge argument for `z_r` needs `β ≥ ‖c·r*‖∞`. Found by reading the code on 2026-09-15 and not yet confirmed by a test. Settled by the corrected parameter set | Open. C6-01 (0X3-160) |
| D-03 | Parameter profiles | RFC §3.2 and SAAP-SPEC §3.1: LEVEL1, LEVEL3 and LEVEL5 | LEVEL1 only | **Code wins for what ships.** LEVEL3 and LEVEL5 are unbuilt proposals. The corrected specification replaces rank-based profiles with attribute capacity as the parameter axis | Open. C6-01 (0X3-160) |
| D-04 | Issuer signature | RFC §5.4 and SAAP-SPEC §4.1: the issuer signs `t_cred` with ML-DSA | No issuer signature is produced or checked. Disclosed attributes are self-asserted | **Spec describes the target; code describes today.** An ML-DSA signature over the commitment would not help a verifier on its own. [`ISSUER-AUTHENTICATION.md`](./ISSUER-AUTHENTICATION.md) gives the construction that would | Open. 0X3-142 (C5), 0X3-97 |
| D-05 | Wire format | RFC §3.7: an "ATH1" bundle of τ, `b_τ` and `z`, with no salt, no version byte and no presentation bundle | `aethel-plp-1`: magic "ATH1", version byte, kind, length, for projections and proofs. See [`WIRE-FORMAT.md`](./WIRE-FORMAT.md). No presentation encoding | **Code wins** for projections and proofs. The RFC is amended to match, including a version byte with reject-on-unknown. The presentation bundle is specified after D-01 fixes the commitment's dimensions | Open. 0X3-132 (projection), 0X3-158 (presentation) |
| D-06 | Context matrix derivation | RFC §3.5: `A_τ ← SHAKE-256("AETHEL_PLP_CTX_V1" ‖ τ)`, one matrix per context | Salts the matrix per projection, `A_τ` from `(τ, salt)`, and the projection carries the salt | **Code wins.** The specified construction is the one the tau-reuse fix (0X3-95) replaced: a shared `A` per context let an observer average projections and recover `A·s`. Anyone implementing from the RFC as written builds the vulnerable version | Open. RFC correction: 0X3-150 |
| D-07 | Blinding randomness range | RFC §5.5 samples `r_blind ← S_γ₁` (wide). RFC §5.4 samples `r_blind ← χ_η` (CBD) | CBD, as §5.4 says | **Code wins.** The RFC contradicts itself; §5.5 is the wrong one. A wide `r_blind` would also break the rejection bound in D-02 | Open. C6-01 (0X3-160) |
| D-08 | SAAP verifier equation | RFC §5.7: the verifier computes `W_2' = A_τ·z_s − c·b_τ` and expects the prover's `W_2` | Adds the projection error `e_τ` to the witness (`y_e`, `z_e`), so `A_τ·z_s + z_e − c·b_τ = W_2` holds exactly | **Code wins.** The RFC's equation leaves a residual `−c·e_τ` that a Fiat-Shamir verifier cannot tolerate. Explained at the point of use in `src/credential.rs` and in SAAP-SPEC §6.1 | Open for the RFC text only. 0X3-150 |
| D-09 | Attribute masks | RFC §5.5: every mask sampled from `S_γ₁` and every response norm-checked | Attribute masks are uniform over `R_q` and not norm-checked; slot 0 shares the short mask `y_s` | **Code wins.** Attribute values are not short, so a short mask would not hide them. See SAAP-SPEC §6.2 | Open for the RFC text only. 0X3-150 |
| D-10 | Issuance algorithm | RFC §5.3: `t_attr = B·A + e` with `B` from a context identifier, then an issuer signature | BDLOP issuance: `t_cred = B_1·r + (0^L ‖ m)`, no context input, no signature | **Code wins** as a description of what runs. SAAP-SPEC §5 was corrected to match on 2026-09-15 (0X3-130). The RFC still carries the old algorithm, and its commitment is itself D-01 | Open for the RFC text only. 0X3-150, C6-01 (0X3-160) |
| D-11 | HTSS | The RFC has no section on threshold secret sharing at all | Shamir 3-of-5 over `F_q` with Merkle-authenticated shares. See [`HTSS-TOPOLOGY.md`](./HTSS-TOPOLOGY.md) | **Code wins.** The RFC needs a section to check the implementation against | Open. 0X3-150 |
| D-12 | Issuer public parameters | The RFC does not describe them | Verification takes issuer public parameters derived one-way from the issuer seed, so a verifier holds no secret | **Code wins.** The RFC needs to describe the split | Open. 0X3-150 |
| D-13 | Retired `saap.rs` pathway | SAAP-SPEC §10.3 and §10.4 describe a single-response prove and verify | That pathway is crate-internal and was removed from the WIT world in 0.1.5. Its challenge also does not absorb the public key it verifies against | **Neither needs it.** SAAP-SPEC labels §10.3 and §10.4 as not implemented. The dormant challenge gap is to be deleted or fixed | Open. 0X3-110 |
| D-14 | Challenge space | RFC §3.2 lists `β = 78` with no challenge weight or coefficient set, so `β` has no derivation | Challenge weight 39, so `β = 78` follows from it, asserted at compile time | **Code wins.** Fixed in the crate in 0.5.0 (0X3-147). The RFC needs a challenge-space section | Open for the RFC text only. 0X3-150 |

## Closed

| ID | Topic | Specification says | Crate does | Ruling | Why no further action |
|---|---|---|---|---|---|
| R-01 | Predicate proofs | RFC §5.6 relation 3 and SAAP-SPEC §9.3: range and membership proofs over hidden attributes | Not implemented, and no function claims to evaluate a predicate | **Code wins.** Closed with no action | It cannot be built in this protocol: bit-decomposition needs a quadratic constraint that a linear sigma protocol cannot express. See [`PREDICATE-PROOFS.md`](./PREDICATE-PROOFS.md). The planned alternative is issuer-attested flags. Do not reopen without a different proof system |
| R-02 | WASM memory bounds | RFC §6 and SAAP-SPEC §12: a 64-page cap, a fixed arena allocator, a static segment map, binary and stack ceilings | None of it | **Spec is aspirational.** Closed with no action | Nothing in the build is an enclave target, so the bounds describe hardware this crate does not build for. This has been reopened twice by readers who took §12 as a requirement. Reopen only if an enclave target is actually built |
| R-03 | HelixDB storage | RFC §7.4, SAAP-SPEC §13.3 and §14.2: graph-manifold storage properties | No storage at all | **Out of scope.** Closed with no action | The identity component is stateless by design. HelixDB is not part of `aethel-core` and is not planned for it |
| R-04 | SRAM PUF and enclave binding | RFC §4, §11 and §12 treat them as normative | Non-default `puf` and `enclave` features, research code, absent from the WIT world | **Demoted.** Closed with no action in the crate | Decided 2026-08-31: the PUF stays in the RFC as a future capability, not a normative requirement. Hardware binding cannot shape an interface every language embeds. See [`SRAM-PUF.md`](./SRAM-PUF.md) |
| R-05 | Module rank | RFC §3.2 sets `k = 4` and §9.2 forbids going below it | Ran at `k = 1` until 0.5.0; runs at `k = 4` since | **Spec won.** Closed by a code change in 0.5.0 (0X3-146) | Nothing left to do in the crate. Whether `k = 4` at this modulus is enough is a separate question, pending a lattice estimator run (0X3-145) |
| R-06 | Challenge absorption order | RFC §3.6 hashes `A_τ ‖ b_τ ‖ W ‖ τ` | `plp::hash_to_challenge` absorbs `w`, `b_τ`, `τ`, `salt`, and not `A_τ` | **Code wins.** Closed with no action | `A_τ` is fully determined by `(τ, salt)`, both absorbed. Every field has a fixed length, so the order carries no information. Explained in `src/plp.rs` |
