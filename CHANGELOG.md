# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [0.1.5] - 2026-08-31

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
