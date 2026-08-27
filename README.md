# aethel-core — Post-Quantum Ephemeral Identity Engine

[![WASM](https://img.shields.io/badge/target-wasm32--unknown--unknown-green)](https://webassembly.org/)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](#license)

> ⚠️ **Security Notice**: This is a pre-release implementation. Do not use in production without a formal security audit.

`aethel-core` is a `no_std`-compatible Rust library
implementing three post-quantum identity primitives, compiled natively or to
`wasm32-unknown-unknown`:

- **Polymorphic Lattice Projection (PLP)** — context-bound ephemeral identity projection and
  ZK ownership proof over Module-LWE (M-LWE).
- **Selective Attribute Attestation Protocol (SAAP)** — BDLOP vector commitment with
  zero-knowledge selective disclosure and norm-bound verification.
- **5D Hypercube Threshold Secret Sharing (HTSS)** — Shamir 3-of-5 secret sharing routed over
  a Q_5 hypercube graph (32 nodes, 80 edges).

## What runs today vs. what is designed

**Runs today** (covered by `cargo test`: 27 `--lib` unit tests + 18 `tests/plp_tests.rs`
integration tests + 1 doctest, all passing on default features):

- `plp` — key derivation (`MasterIdentity::from_seed`), context projection
  (`project_at_context`), ZK proof generation and verification (`Prover`, `Verifier`)
- `saap` — selective-disclosure proof generation and verification (`saap_prove`,
  `verify_saap_proof`)
- `htss` — 3-of-5 threshold secret splitting and reconstruction, hypercube routing
- `sampling` — constant-time rejection sampling, CBD η=2 sampler, norm checking
- `ct_verify` — a Valgrind/ctgrind constant-time verification harness (doctest-covered)
- `identity_error` — the Rust-side mirror of the WIT world's `identity-error` variant, plus
  checked wrappers (`*_checked` functions) that return it instead of panicking
- WASM bindings (`wasm` feature) exporting `plp_*`, `saap_*_wasm`, and `htss_*` — see
  [WASM Exports](#wasm-exports) below

**Designed, not yet implemented / out of scope for this crate:**

- **SRAM PUF fuzzy extraction** (`puf` module, non-default `puf` feature) — a BCH(1023,512,55)
  fuzzy extractor for deriving key material from noisy hardware SRAM. This is research code:
  its BCH encoder is a simplified placeholder (see the comments in `src/puf.rs`), it is not
  part of the default build, and it does not appear in the `aethel:core` WIT world. Enabling
  `--features puf` compiles it and its two WASM exports; the default build does not.
- **`sdk` module** — currently type/struct definitions only (`SdkConfig`, `StateNodePayload`,
  `SaapProofTranscript`) plus a TypeScript client stub in `src/sdk/client.ts`. No client logic
  is implemented against those types yet, and there are no tests exercising it.
- **`enclave` feature** — gates a set of `extern "C"` FFI declarations (`src/puf.rs`'s `ffi`
  module) into a C enclave shim (`c/bch_decoder.c`, `c/ct_norm.c`, `c/ct_sampling.c`) that this
  repo does not build a real target for; `c/ct_sampling.c` calls C functions declared nowhere
  in this repo. Nothing in the working code path (`plp`, `saap`, `htss`, `sampling`, `puf`
  without `enclave`) calls into it.
- **`aethel-runtime`** and the substrate repos (`pqvm`, `waven`, `wamr`, `awre`, `qies`,
  `obfuscation`) — separate repositories this crate does not depend on, build, or test.
  Nothing in this repo implies they ship alongside it.

## Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Ring | `R_q = Z_q[X]/(X^256 + 1)` |
| Modulus `q` | `8,380,417` |
| Module rank `k` | 4 |
| Noise `η` | 2 (Centered Binomial Distribution) |
| Masking bound `γ₁` | 131,072 (2^17) |
| Rejection bound `β` | 78 |
| Fixed iteration ceiling | 16 |
| PLP domain separator | `"AETHEL_PLP_CTX_V1"` |
| SAAP domain separator | `"AETHEL_SAAP_CHALLENGE_V1"` |

## Modules

| Module | Description | Status |
|--------|-------------|--------|
| `plp` | Polymorphic Lattice Projection — context-bound ephemeral identity projection over M-LWE | Default |
| `saap` | Selective Attribute Attestation Protocol — BDLOP commitment + ZK selective disclosure | Default |
| `htss` | 5D Hypercube Threshold Secret Sharing — Shamir 3-of-5 over F_q with Q_5 routing | Default |
| `sampling` | Constant-time rejection sampling — 16-iteration fixed loop, CMOV, zeroization | Default |
| `ct_verify` | Constant-time verification harness | Default |
| `identity_error` | Mirror of the WIT `identity-error` variant, plus checked wrappers | Default |
| `sdk` | Client SDK types (no client logic yet) | Default (types only) |
| `puf` | SRAM PUF fuzzy extractor — BCH(1023,512,55) over GF(2^10), research code | Non-default (`puf` feature) |

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `std` | ✅ Yes | Standard library support, heap allocation. |
| `wasm` | ❌ No | WebAssembly target with `wasm-bindgen` bindings. Required for `wasm32-unknown-unknown` builds. |
| `enclave` | ❌ No | Compiles the C enclave FFI shim (see [What runs today vs. what is designed](#what-runs-today-vs-what-is-designed)). Not buildable against a real enclave target in this repo. |
| `puf` | ❌ No | Compiles the `puf` module (SRAM PUF fuzzy extraction) and its `puf_enroll` / `puf_reconstruct` WASM exports. Research only, out of scope for the `aethel:core` WIT world. |

## WASM Exports

```wit
package aethel:core@0.1.0;

world aethel-core {
  export identity;       // plp-project-at-context, plp-prove-identity, plp-verify
  export attestation;    // saap-prove, saap-verify
  export secret-sharing; // htss-split, htss-reconstruct
}
```

See [`dist/aethel_core.wit`](dist/aethel_core.wit) for the full WIT interface definition, and
[`dist/README.md`](dist/README.md) for the currently-compiled `wasm-bindgen` ABI (which
predates the typed WIT world — see that file for how the two relate). `puf_enroll` /
`puf_reconstruct` are WASM exports only when built with `--features puf`; they are not part of
the WIT world either way.

## Building

### Prerequisites
- Rust 1.85+ (`rustup target add wasm32-unknown-unknown` for WASM builds)

### Native Build + Tests

```bash
cargo build
cargo test
```

### WASM Build

```bash
cargo build --target wasm32-unknown-unknown --no-default-features --features wasm
```

Output: `target/wasm32-unknown-unknown/debug/aethel_core.wasm`. Rebuilding after this (`cargo
build`) copies it into `dist/aethel_core.wasm` — see [Distribution Artifacts](#distribution-artifacts).

### With the `puf` Feature

```bash
cargo build --features puf
cargo test --features puf
```

## Distribution Artifacts

`build.rs` regenerates `dist/` on every build:

| File | Description |
|------|-------------|
| `dist/aethel_core.wasm` | Best-effort copy of the most recently built WASM binary |
| `dist/aethel_core.wit` | WIT interface definition |
| `dist/aethel_core.abi.json` | ABI JSON descriptor — reflects the feature set of the build that generated it (e.g. only lists `puf_enroll`/`puf_reconstruct` when built with `--features puf`) |
| `dist/README.md` | Integration documentation for the WASM artifacts |

## Integration Example (Rust)

```rust
use aethel_core::plp::{MasterIdentity, Prover, Verifier};

// Derive a master identity from a 32-byte seed (caller-supplied entropy)
let seed = [0x11u8; 32];
let identity = MasterIdentity::from_seed(&seed);

// Project at context τ (ephemeral, context-bound)
let tau = b"session_context_2026";
let projection = identity.project_at_context(tau);

// Prove ownership
let proof = Prover::prove_identity(&identity, &projection, &seed);

// Verify (by any party with the projection and proof)
assert!(Verifier::verify(&projection, &proof));
```

## Security Properties

- **Post-quantum secure**: Based on Module Learning With Errors (M-LWE), conjectured secure against quantum adversaries
- **Ephemeral identifiers**: Each context `τ` produces a mathematically independent projection — no linkability across contexts
- **Constant-time**: All secret-dependent operations use fixed-iteration loops and CMOV selection
- **No traditional crypto**: Zero AES, RSA, ECDSA, or classical elliptic curve operations
- **Offline generation**: Identity generation (`plp` key derivation, context projection, proof generation — the `--lib` unit tests plus `tests/plp_tests.rs`) never requires network access, and this is proven by denying the capability at the boundary rather than by trusting application code to report it honestly. CI's `offline-generation` job (`.github/workflows/ci.yml`) runs that generation test suite inside a network namespace with no interface, and in the same isolated step runs a negative-control test (`tests/network_isolation_negative_control.rs`) that deliberately makes a real network call — that control is *expected to fail* there, and its failure is what proves the isolation is real. If you don't trust this claim, don't take it on faith: read `offline-generation` in the Actions tab, or reproduce it locally (Linux/WSL2) with `unshare --net --map-root-user -- cargo test --offline --lib --test plp_tests`.

## Unsafe Code

The default build (`std`, no `puf`, no `enclave`) contains exactly 5 `unsafe` blocks, all in
[`src/sampling.rs`](src/sampling.rs) (lines ~98, ~167, ~173, ~179, ~408 at time of writing),
each carrying a `// SAFETY:` comment above it explaining the invariant it relies on:

- Two `enclave_explicit_zeroize` / `PolyRq::zeroize` blocks use `core::ptr::write_volatile` in
  a loop over a pointer derived from a live `&mut` reference, sized to `size_of::<T>()`,
  followed by a `compiler_fence` — this is what makes secret zeroization survive dead-store
  elimination.
- Three blocks in `enclave_plp_prove_fixed_time` reinterpret same-sized, non-aliasing local
  `PlpProof` values as byte slices (`core::slice::from_raw_parts[_mut]`) to run a
  constant-time conditional copy (`ct_cond_copy`) without branching on secret data.

Enabling `puf` or `enclave` additionally compiles 2 more `unsafe` blocks, in `src/puf.rs`'s
`ffi` module — a wrapper around the C enclave shim described in
[What runs today vs. what is designed](#what-runs-today-vs-what-is-designed).

## Shared WASM Modules

aethel-core is one of several independently-versioned repositories intended to run alongside
each other as WASM modules loaded by a wasmer.io host. These are separate repos with their own
build and test suites — this README makes no claims about their state:

| Module | Purpose |
|--------|---------|
| `pqc-kem` | ML-KEM (FIPS 203) key encapsulation |
| `pqc-sig` | ML-DSA (FIPS 204) signatures |
| `privacy` | ε-Differential Privacy noise injection |
| `obfuscation` | WASM binary hardening |

## Continuous Integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and pull request, on
a fresh GitHub-hosted runner.

Three jobs:

- **Build & test** — `cargo build --all-targets` / `cargo test` with default features.
- **Offline generation (network-isolated)** — re-runs the identity-generation test suite inside
  a real network namespace with no interface configured, proving generation works with zero
  network access rather than just asserting it in-process. A negative control in the same job
  confirms the isolation itself is real: a test that tries to make a network call is expected
  to fail under isolation, and the job fails loudly if it doesn't.
- **WASM test (Node)** — runs the test suite under `wasm32-unknown-unknown` via `wasm-pack test
  --node`, with `--no-default-features --features wasm` (the documented production WASM build,
  not just any feature combination that happens to compile). This is what actually exercises
  the zeroization test in WASM linear memory rather than only on native — memory that isn't
  returned to an OS on drop the way native heap memory is.

## Further Documentation

[`docs/`](./docs/) has deeper algorithm write-ups: [`PLP-ALGORITHM.md`](./docs/PLP-ALGORITHM.md),
[`SAAP-SPEC.md`](./docs/SAAP-SPEC.md), [`HTSS-TOPOLOGY.md`](./docs/HTSS-TOPOLOGY.md),
[`SRAM-PUF.md`](./docs/SRAM-PUF.md), and [`OVERVIEW.md`](./docs/OVERVIEW.md). Each was reviewed
against this README (P3-05, 2026-08-26) and carries inline markers wherever it describes a
credential-issuance layer, hardware target, or parameter level that isn't actually shipped —
read the editorial note at the top of each file first.

## Contributing

See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## Maintainer and Support

Ed Johnson is the named maintainer. This is a best-effort, single-maintainer project — see
[`STABILITY.md`](./STABILITY.md) for the release cadence and support posture, and
[`SECURITY.md`](./SECURITY.md) to report a vulnerability.

## License

Apache-2.0.

## References

- [NIST FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
