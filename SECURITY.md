# Security Policy

## Reporting a vulnerability

Email **security@0x307.com**. This address is monitored and routes to a human — not a
mailing list nobody reads.

Please do not open a public GitHub issue for a suspected vulnerability. Include as much
detail as you can: affected version, reproduction steps, and impact if known.

## Response window

Reports are acknowledged within **5 business days**. This is a best-effort
project with a single maintainer and no on-call rotation — see
[`STABILITY.md`](./STABILITY.md) for the full support posture. The response window above is
the one committed number in that posture; everything else is best-effort.

## Supported versions

This project ships `0.x`. Security fixes land on the latest published minor version. Older
`0.x` minors are not backported to, consistent with the stated stability policy.

## Known limitations in 0.4.0

A cryptographic review of the identity and credential paths completed on 2026-09-08.
Three properties this crate has described are weaker in the shipped implementation
than the descriptions imply. They are recorded here rather than in a private tracker
because the affected code is published.

None of these are reports from a third party, and none are being withheld pending a
fix. The work to strengthen each is scoped and in progress.

### The projection runs below the module rank its specification requires

`AETHEL-SPEC-001` §3.2 sets a module rank of `k = 4` for the parameter profile this
crate targets, and §9.2 states that implementations must not reduce it below that.
`plp` currently operates at rank 1: the master secret, the context matrix and the
projection are each a single ring element rather than a rank-4 module.

The consequence is that the lattice-hardness argument written for rank 4 does not
apply to the shipped code, and the margin protecting a master secret from the
projections derived from it is smaller than the specification's analysis assumes.
Raising the rank to the specified minimum is the primary fix and it changes the wire
format.

### The credential commitment does not provide the hiding property claimed for it

`AETHEL-SPEC-001` §7 specifies the credential commitment matrix with a randomness
dimension smaller than its commitment dimension. A BDLOP commitment is hiding only
when that relationship runs the other way, so that the randomness term is
pseudorandom under Module-LWE. This crate implements the specified shape faithfully;
the shape itself is the defect.

Until the shape is corrected, treat a presentation as revealing the attribute values
it commits to, disclosed or not, and do not rely on two presentations of one
credential being unlinkable. The specification is being corrected before the
implementation follows it.

### The rejection-sampling bound is not derived from the challenge space

The challenge polynomial has 60 non-zero coefficients, while `β = 78` is the value
that corresponds to a challenge of weight 39. The rejection-sampling argument
requires `β` to be at least the largest coefficient of the challenge multiplied by
the witness, and at weight 60 it is not.

Measured behaviour stays far from the bound, so the practical leakage is negligible.
It is recorded because the argument does not carry as written, and because the
extraction bounds stated for every other relation depend on the true value.

### What to do with this today

`aethel-core` is `0.x` and the README already says not to use it in production
without a formal audit. That guidance stands and these findings sharpen it. If you
are evaluating the crate, the `plp` identity path is the part being brought to its
specified parameters first; the credential path should be treated as
pre-release until the commitment shape is corrected.
