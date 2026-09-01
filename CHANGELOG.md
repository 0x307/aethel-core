# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [Unreleased]

### Fixed

- **Reusing τ no longer leaks the master secret (AETHEL-F-02).** The context
  matrix `A` was `SHAKE-256("AETHEL_PLP_CTX_V1" || τ)`, a pure function of the
  context, so every projection of one identity at one τ shared it. The samples
  `b_i = A·s + e_i` then differed only in their error terms, and `e` comes from a
  centered binomial distribution, so averaging enough of them drove the noise to
  nothing and left `A·s`, from which the secret is linear algebra over the ring
  rather than an M-LWE instance. Roughly 64 samples sufficed, and freshness of
  each individual `e_i` did not help.

  `A` is now derived from τ **and** a per-projection salt, and the salt is
  derived from the caller's projection randomness. Two projections at one τ are
  independent samples under unrelated matrices, so there is nothing to average.
  Measured against the old construction the attack recovers 256 of 256
  coefficients of `A·s`; against the new one it recovers 0.

  This was previously documented as a caller obligation ("τ MUST be single-use")
  rather than enforced. A documented MUST is a weak control when violating it
  costs the master secret and the canonical τ is a block height, which collides
  across users by construction. The obligation now rests on the projection
  randomness instead, which is a value the caller generates rather than one they
  are handed.

- **The Fiat-Shamir challenge binds the whole projection.** It hashed the
  commitment and the **first 8 bytes** of τ, so a proof was bound neither to the
  rest of the context nor to `A`. It now covers the full τ and the salt.

### Changed (breaking)

- **`ephemeral-projection` replaces `matrix-a` with `salt`.** `A` is fully
  determined by `tau` and `salt`, so carrying it would be redundant bytes a
  verifier would have to trust or cross-check. Deriving it on decode makes an
  inconsistent `A` unrepresentable rather than merely detectable, and shrinks the
  record from `32 + 8N` bytes to `64 + 4N`.

  **Migration:** read `salt` where you read `matrix-a`. If you cached `A` by τ,
  stop: it is no longer a function of τ alone. `Verifier::verify` re-derives `A`
  and ignores the struct's cached `matrix_a` field, so a hand-built projection
  cannot supply a doctored matrix.

- **`plp-prove-identity` and `master-identity.prove` take `randomness`.** It MUST
  be the same value passed to the matching projection call. `A` used to be
  recoverable from τ alone, which is precisely the property that made τ reuse
  unsafe; with `A` salted, the prover has to be told which salt to reconstruct.

  **Migration:** `plp-prove-identity(secret, tau)` becomes
  `plp-prove-identity(secret, tau, randomness)`; `prove(tau)` becomes
  `prove(tau, randomness)`. Both refuse randomness under 32 bytes with
  `invalid-input-length`.

- **Proofs and projections from 0.2.0 do not verify under this version**, and the
  reverse. The domain separators moved to `AETHEL_PLP_CTX_V2` and
  `AETHEL_PLP_CHALLENGE_V2`, and the projection wire format changed.

## [0.2.0] - 2026-09-01

### Fixed

- **`htss-reconstruct` now validates the shares as a set.** Lagrange
  interpolation is only defined over distinct evaluation points, and the
  operation checked share count, width, width uniformity and `index != 0` but
  never that the indices were distinct. Two shares carrying the same index give
  that point's basis polynomials a zero denominator, so those terms dropped out
  and the interpolation answered from whatever points remained: a value that is
  not the shared secret. Most such inputs then failed the payload's length-prefix
  sanity check and surfaced as `serialization-error`, which looks like a guard
  and is not one. A caller choosing the share values can make the length prefix
  decode, at which point the operation returned `ok(attacker-chosen bytes)`.

  The share list is now rejected as `invalid-share-set` if any index repeats, or
  if it carries more shares than the scheme issues. The cardinality bound also
  closes a work multiplier: interpolation is quadratic in the share count, and
  the list arrives unauthenticated.

  `SecretSharer::mod_inverse` returns `Option<i64>` instead of a `0` sentinel.
  Zero is never a valid inverse but is an ordinary value to multiply by, so the
  sentinel was indistinguishable from success and is the mechanism that turned a
  degenerate denominator into a silently wrong secret. The uniqueness check is
  the fix; this is the second line.

- **`htss-split` is now linear in the secret's length, not quadratic.** The
  sharing-polynomial coefficients were derived by absorbing the entire secret
  into a fresh SHAKE-256 instance for every coefficient, and the limb loop makes
  one call per byte of secret, so total absorption grew as the square of the
  input. Measured, a 4x larger secret cost 14-16x the time, and a 64 KiB secret
  meant roughly 4.3 GB of absorption and 11.7 seconds of wall clock in a release
  build for one call, on input that arrives unauthenticated.

  The secret is now absorbed once into a 32-byte coefficient key, and each
  coefficient is derived from that key plus its limb and coefficient indices, at
  constant cost. The same 64 KiB split takes about 50 milliseconds.

  The security property is unchanged and deliberately so: the secret is still the
  entropy source, so an attacker who does not know it cannot predict the
  coefficients, which is what makes shares below the threshold reveal nothing.
  Predicting a coefficient still requires the secret or a SHAKE-256 preimage.

- **`saap::saap_prove` no longer emits a rejected response on exhaustion.** Its
  all-rejected fallback re-derived the masking vector at nonce 0, which is
  iteration 0's nonce. The derivation is a pure function of
  `(rho, context_tag, nonce)`, so the commitment, challenge and response all
  recomputed to iteration 0's values: the function returned, verbatim and without
  re-checking the bound, the response iteration 0 had already rejected. An
  out-of-bound response verifies nowhere, so it could only leak, never
  authenticate.

  It now returns `Err(RejectionSamplingFailed)`, matching
  `plp::Prover::prove_identity` and `credential::prove`, which already refuse for
  this reason. "Negligible probability" was the wrong frame: 16 consecutive
  rejections is negligible by chance, but the derivation is deterministic in
  `(rho, context_tag)`, so a context that lands there can be searched for.

  Not reachable through the WIT world: `saap_prove` has had no exported caller
  since the `attestation` interface was removed in 0.1.5. Native Rust callers of
  `saap::saap_prove` must handle the `Result`.

### Added (breaking)

- **`identity-error` gains an eighth case, `invalid-share-set`,** appended last.
  A WIT `variant` is ordinal-encoded, so the new case is added at the end of the
  list: inserting anywhere else silently renumbers every case after it for
  callers compiled against an earlier version of this world. Callers that match
  `identity-error` exhaustively must add an arm. Five of the eight cases now have
  producers; the three `RESERVED` cases are unchanged.

### Changed (breaking)

- **Share values from `htss-split` have changed.** The coefficient derivation's
  domain separator moved from `AETHEL_HTSS_COEFF_V1` to `AETHEL_HTSS_COEFF_V2`,
  so every coefficient, and therefore every share value, differs from what the
  previous version produced for the same secret and nonce. Shares from the two
  derivations must not be mixed within one reconstruction.

  **Reconstruction is unaffected.** `htss-reconstruct` is Lagrange interpolation
  over the share values and never re-derives a coefficient, so a set of shares
  issued by an earlier version still reconstructs correctly under this one. What
  breaks is only re-splitting the same secret and expecting the old share values
  back.

- **`htss-split` refuses a secret larger than 64 KiB** with
  `invalid-input-length`. The previous bound was `u32::MAX`, about 4 GiB, which
  is the largest value the payload's length prefix can hold rather than a
  statement about what the operation is for. 64 KiB is deliberately generous
  against real key material, so the ceiling is a contract rather than a limit a
  legitimate caller meets.

- **`saap::saap_prove` returns `Result<SaapProof, IdentityError>`** rather than
  `SaapProof`. See above.

- **`SecretSharer::reconstruct_secret` returns `Result<u64, IdentityError>`**
  rather than `u64`, so a non-interpolable point set is reported rather than
  absorbed. Native Rust callers only; the WIT surface already returned a
  `result`.

## [0.1.5] - 2026-08-31

### Fixed

- **`build.rs` no longer writes into the source tree by default.** The `dist/`
  convenience copy (WIT, ABI JSON, README, a best-effort WASM binary) was
  regenerated on every build, unconditionally, which is exactly what a build
  script must not do — it broke `cargo publish`'s verification (which
  rejects a source tree build.rs modified) and would have polluted another
  crate's extracted registry cache had anyone depended on this one. Set
  `AETHEL_GENERATE_DIST=1` to opt back into regenerating `dist/` locally;
  ordinary builds, `cargo publish`, and downstream dependents no longer touch
  it.

### Removed (breaking)

- **The `attestation` WIT interface** (`saap-prove`, `saap-verify`) is gone from
  the world. It built proofs over a public key that was never safe to publish
  (no error term, an exact linear image of the secret), so `saap-verify` could
  only ever return `ok(false)`. `identity.saap-verify-presentation`, anchored
  on the noisy PLP projection `b_τ = A_τ·s + e_τ`, is the sole supported SAAP
  verification path now. `src/saap.rs` remains in the crate for its
  characterisation tests only; it is not reachable through the WIT world.

  **Migration:** any caller using `attestation.saap-prove`/`saap-verify` must
  move to `identity.credential.issue`/`.present` and
  `identity.saap-verify-presentation`, which is the construction P3-11
  (0X3-79) actually built.

  **Deprecation-policy exception ([STABILITY.md](./STABILITY.md) §3):** this
  removal skips the usual mark-deprecated-for-one-minor-version cycle.
  `saap-verify` had exactly one behavior since it shipped — `ok(false)`,
  unconditionally — so no caller could have been relying on a *correct*
  result from it; a deprecation cycle would have kept a function whose only
  output was a guaranteed denial callable for another release, with no
  caller for whom that's useful and starting a fresh confusion clock for
  anyone new who found it. `saap-prove` disappearing alongside it is the
  same call: a prove half with no sound verify half isn't a usable API on
  its own. Ordinary removals still get the full cycle; this one is an
  explicit, reasoned exception, not a precedent for skipping it by default.

### Security

- **Strengthened randomness handling in PLP and SAAP.** The projection error term
  `e_τ` and the SAAP proof mask `r` are now seeded from caller-supplied fresh
  secret entropy, so each projection is a sound single-use M-LWE sample and each
  proof carries an independent mask, which is the property the soundness
  reduction assumes. Each context τ is used once, per the scheme's ephemeral
  design.

### Changed (breaking)

- `project_at_context`, `checked_project_at_context`, and `saap_prove` gain a
  trailing `randomness` argument. WIT `plp-project-at-context` and `saap-prove`
  gain `randomness: list<u8>`; the WASM exports fail closed on fewer than 32
  bytes; `checked_project_at_context` returns `InvalidInputLength` for short
  randomness. `plp-prove-identity` is unchanged.

  **Migration:** supply at least 32 bytes of fresh secret entropy at each call
  site, sampled anew per call. Never reuse a value or derive it from public
  data, and use each context τ once.

## [0.1.0] - 2026-08-27

### Added

- Initial release of three post-quantum identity primitives: Polymorphic Lattice Projection
  (PLP) — context-bound ephemeral identity projection and ZK ownership proof over Module-LWE;
  Selective Attribute Attestation Protocol (SAAP) — BDLOP vector commitment with
  zero-knowledge selective disclosure; and 5D Hypercube Threshold Secret Sharing (HTSS) —
  Shamir 3-of-5 secret sharing routed over a Q_5 hypercube graph.
- WASM bindings (`wasm` feature) exporting `plp_*`, `saap_*_wasm`, and `htss_*`.
- 31 `--lib` unit tests, 15 `tests/plp_tests.rs` integration tests, and 1 doctest passing on
  default features. CI proves offline generation by running it inside a network-isolated
  namespace with a negative control, rather than by in-process assertion alone.
- `puf` (SRAM PUF fuzzy extraction, research code) and `enclave` (C FFI shim) are non-default
  feature flags, out of scope for the default build and the `aethel:core` WIT world.

> **Pre-release.** This is a research implementation; do not use in production without a
> formal security audit — see the notice in [README.md](README.md).

See [README.md](README.md) for full module, feature, and security documentation.
