# Contributing to aethel-core

## Current posture: not taking external PRs yet

This project is implemented and maintained by a single named maintainer (Ed Johnson), not a
team with a review pipeline built for external contributions. That means:

- **Issues are welcome** — bug reports, questions, and feature requests. They're read and
  triaged on a best-effort basis.
- **External pull requests are not being merged right now.** Not because contributions aren't
  wanted long-term, but because there's no review capacity to do them justice yet. Opening one
  won't get an insulting silence, but expect it to sit until capacity exists, or to be closed
  with a note rather than merged.
- If you want to contribute code, **open an issue first** to discuss the change before writing
  it. That avoids spending your time on something that can't be reviewed or merged in a
  reasonable window.

This posture is stated here because pretending otherwise wastes contributors' time. It will be
revised, and this file updated, if and when that capacity changes.

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
