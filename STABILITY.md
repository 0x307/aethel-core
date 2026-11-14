# Stability and Cadence Policy

This project ships `0.x`. This document is the contract that comes with that: what counts as
a breaking change, how deprecations work, what release cadence you can expect, and what
support looks like. It's the same policy across every 0x307 repo in this family — the crypto
crates, the identity primitives, and the identity SDK.

---

## 1. Everything is 0.x

This project ships `0.x` until its own shape stops changing. `1.0.0` is tagged when the API
has stopped changing on contact with real use — a discovery, not a date on a roadmap. There's
no committed timeline to `1.0`.

Inside `0.x`, breaking changes are expected and allowed. What this policy fixes is how you'll
know one happened, and what you're owed when it does.

## 2. What counts as a breaking change

A change is breaking if code that compiled and ran correctly against the previous published
version might fail to compile, fail to run, or silently behave differently after the upgrade,
without you changing anything.

**Breaking, concretely:**

- Removing or renaming a public function, method, type, trait, or exported interface
- Changing a function's signature — parameter types, order, count, or return type
- Changing a type's public field set, or making a previously-public field private
- Changing the wire format or serialized shape of a type that crosses a process boundary
- Changing documented behavior of an existing call in a way that changes its output for the
  same input — including error-vs-success outcomes
- Tightening previously-permissive input validation such that previously-accepted input is
  now rejected
- Raising the Minimum Supported Rust Version (MSRV), or a package's minimum Node version
- Changing a default value that affects behavior (a default algorithm, a default feature
  flag's on/off state)

**Not breaking:**

- Adding a new public function, method, type, or optional field
- Widening an accepted input (accepting more than before, rejecting nothing that used to be
  accepted)
- Adding a new opt-in feature flag
- Performance improvements that don't change observable behavior
- Fixing a bug where the old behavior contradicted the documented behavior — the fix isn't
  breaking even though it changes output, because the old output was never the contract.
  These are called out in the changelog either way, since you may have been depending on the
  bug
- Internal refactors with no change to the public surface
- Documentation changes

**Security exception.** A fix for a security defect can ship in a patch release even when it
falls under "Breaking" above, if the alternative is leaving the defect in the supported line.
That covers refusing input that is unsafe to accept (a low-order key, say) and raising the MSRV
because a dependency's security fix needs a newer compiler. The changelog entry names the rule
it breaks and why, and the change is never used for anything that isn't the fix.

**If it's ambiguous which side of this a change falls on, it's treated as breaking.** That's
the conservative default this policy exists to give you — the cost of an unnecessary minor
version bump is much lower than the cost of a silent break.

## 3. Deprecation before removal

Nothing is deleted without a deprecation cycle first:

1. The item is marked deprecated in a minor release, with the changelog entry stating what to
   migrate to.
2. It stays functional, with a working migration path documented, for **at least one full
   minor version** after the deprecation lands.
3. Removal happens in a later minor or major release, called out explicitly in that release's
   changelog as a completed removal.

One minor version is a floor, not a target — a deprecation with a non-obvious migration gets
more notice.

## 4. Every breaking change gets a changelog entry with a migration note

Not just "breaking: renamed `foo` to `bar`" — a migration note means you can read the entry
and know what to change in your own code without opening an issue to ask. Minimum bar: old
signature/name, new signature/name, and a one-line reason if it isn't obvious.

The `CHANGELOG.md` is the authoritative record of breaking changes — not commit messages, not
GitHub release notes alone.

## 5. Release cadence

**A release ships when there's something worth releasing — a fix, a feature, or a breaking
change that's been sitting long enough to be worth cutting a version for — and, independent of
that, at minimum once every 6 weeks.**

If nothing shipped in a given six-week window, the minimum release is a changelog-only release
stating that explicitly ("no functional changes this cycle") rather than silence. Silence is
what makes a 0.x project look abandoned; a shipped no-op doesn't.

This cadence is a floor, not a promise of frequency above it. Faster is normal, especially
early. The floor is what's meant to hold indefinitely, including through a slow stretch.

### Versions and yanks

**We fix forward, and yank only with a recorded reason.** A fix ships as a new release. A
security fix also gets a [RustSec](https://rustsec.org/) advisory that names the affected
versions and the fixed one, so `cargo audit` and `cargo deny` flag the affected versions in your
build and you learn about the problem and the fix together. A security bug alone is not a reason
to yank.

A version is yanked only when it can't be installed (it fails to build or resolve for a
consumer) or when it would mislead (its published code or README describes behaviour it doesn't
have, in a way a consumer would act on). Each yank gets one line in
[`CHANGELOG.md`](./CHANGELOG.md#yanked-versions) giving the reason. A yanked version still
resolves from an existing `Cargo.lock`, so nothing already built breaks; new resolutions skip
it.

The gates that keep a release from needing a yank are in CI: the byte-identity test
(`signing::byte_identity_tests`), the `aethel-plp-1` vectors (`tests/plp_vectors.rs`), and the
component's reproducible build checked against `component.sha256`.

**More than one line may be live at once.** A line is a `0.x` minor series (`0.4`, `0.5`).
When a new line ships, the previous one is not withdrawn.

**A legacy line gets security fixes for 6 months after its successor ships.** After that it is
marked unsupported in its README and in `CHANGELOG.md`, and stays downloadable. Each release
that starts a window states the date it ends.

Twelve versions are yanked: 0.1.0, 0.1.5, 0.3.0 to 0.3.3, 0.4.0, 0.5.0, 0.5.1, 0.6.0, 0.6.1
and 0.7.0. They were yanked before this rule was written, and no reason was recorded at the
time. [`CHANGELOG.md`](./CHANGELOG.md#yanked-versions) has one line for each with what is known.
They stay yanked and get no patches. If you are on one of them, move to 0.7.x.

## 6. Support posture

**Best-effort, no SLA, single named maintainer** — see `README.md` for who that is right now.
There's no team and no on-call rotation behind this project. In practice:

- Issues and PRs are triaged (labeled, acknowledged, or closed with a reason) on a
  best-effort basis, with no committed response time for general issues.
- The one exception is the **security contact** in `SECURITY.md`: reports there are
  acknowledged within **5 business days**.
- "Best-effort" means exactly that, not a soft-pedaled response-time promise. If that changes,
  this document changes with it.

## 7. Where this applies

This policy is shared across every repo in this family, not restated per repo. Each repo's
`SECURITY.md` and `CHANGELOG.md` reference this document rather than duplicating it.
