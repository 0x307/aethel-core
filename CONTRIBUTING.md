# Contributing to aethel-core

`aethel-core` follows the [0x307 contribution standard](https://github.com/0x307/.github/blob/main/CONTRIBUTING.md):
who reviews what, the bar every change meets, and how pull requests are reviewed. Open an
issue before starting anything beyond a small fix.

The rules below are specific to this repository and add to that standard.

## Development

```bash
cargo build
cargo test
```

See [`README.md`](./README.md) for the full build matrix (WASM target, `puf` feature, etc.)
and what's covered by the test suite.

## Deviating from a specification

This crate implements `AETHEL-SPEC-001` and [`docs/SAAP-SPEC.md`](./docs/SAAP-SPEC.md), and it
does not always agree with them. Every disagreement lives in
[`docs/DEVIATIONS.md`](./docs/DEVIATIONS.md): what the specification says, what the crate does,
which one wins, and who owns it.

**A change that makes the crate deviate from a specification adds its register row in the same
pull request.** That applies whether the deviation is a fix to a specification defect or a
decision to depart from it. A deviation found after merge is a defect in this process, not
only in the code.

- If the deviation is explained in a source comment headed `# Deviation from ...`, that comment
  names its register row. `tests/deviations.rs` fails if it does not.
- Deviations that are resolved with no action stay in the register, under **Closed**, with the
  reason. A register that only lists open problems teaches the next reader to reopen the
  closed ones.

## Recording the component's provenance at release

Two files at the repository root describe the canonical component, and both are read by
`build.rs` and exposed as `aethel_core::COMPONENT_SHA256` and `aethel_core::GIT_REVISION`:

- `component.sha256` — the SHA-256 of the canonical build, in `sha256sum` format.
- `component.rev` — the commit that build was made from, as a full lowercase sha.

**Both are updated in the release pull request, before it merges, whenever the component's bytes
change.** The hash comes from CI's `reproducible:` line, which is the canonical platform; do not
take it from a local build, because the hash is platform-specific.

`component.rev` names the commit whose tree was built, so it is an **ancestor** of the commit
that records it — a file cannot contain the hash of the commit containing it. Record the tip the
release branch started from. CI's `provenance` job requires the value to be a real commit and an
ancestor of `HEAD`, so a stale or invented sha fails the build rather than shipping.

If the component's bytes have not changed, neither file changes, and `GIT_REVISION` keeps
pointing at the commit the bytes really came from. That is the intended behaviour: these
constants describe the artifact, not the release.

## Reporting a security issue

Do not open a public issue for a security vulnerability. See
[`SECURITY.md`](./SECURITY.md) instead.

## Code of conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md), unmodified.
