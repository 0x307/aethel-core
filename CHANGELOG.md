# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to the breaking-change and deprecation rules in
[`STABILITY.md`](./STABILITY.md) rather than strict SemVer prior to `1.0.0` — see that
document for what counts as breaking inside `0.x`.

## [Unreleased]

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
