---
title: "Purpose Bytes — Domain-Separated Signing Contexts (A-1 / X-2)"
version: "0.1.0"
date: "2026-09-10"
project: "aethel-core"
---

# Purpose Bytes

> Gap this closes (SAGP-PG-001 X-2, verbatim): "Three ways to hold a secret (pqc-sig
> keypair, aethel MasterIdentity, vault ServerKey) — Integrators pick wrong; SAGP already
> has this pain with witan/erand — Document purpose bytes. Vault and fabric consume
> aethel-core. pqc-sig is the algorithm crate underneath signing."

## Which type do I hold?

| Role | Type | Notes |
|---|---|---|
| **Agent** | one [`signing::Identity`](../src/signing.rs) | Sealed at rest with `export_sealed`/`import_sealed`. Holds an ML-DSA-65 keypair and a PLP master seed, derived together from one entropy input. This is the type an agent creates once and keeps. |
| **Verifier** | nothing — bytes only | A verifier holds a public key and calls [`verify`](../src/signing.rs)/[`verify_with_purpose`](../src/signing.rs)/[`wire::verify_projection`](../src/wire.rs). No secret of any kind. |
| **Internal derivation** | [`plp::MasterIdentity`](../src/plp.rs) | Derived from `Identity`'s seed on demand (`Identity::project_at_context`/`prove` do this internally). Prefer `Identity`; do not construct a bare `MasterIdentity` in application code unless you are inside `aethel-core` itself or its component adapter. |
| **aethel-vault** (separate crate) | a settlement signer key, and — in `fhe-state` mode only — a TFHE `ClientKey`/`ServerKey` | Neither leaves the agent. See `aethel-vault`'s own README for its custody rule. |

`pqc-sig` is the algorithm crate underneath `signing::Identity::sign`/`sign_with_purpose`; nothing
in this crate or its consumers should depend on `pqc-sig` directly for signing an application
message — go through `Identity`.

## Purpose separation: the mechanism

[`signing::Identity::sign_with_purpose`](../src/signing.rs) and
[`signing::verify_with_purpose`](../src/signing.rs) use FIPS 204's native context
mechanism — `pqc_sig::MlDsa65Keypair::sign_ctx_deterministic`/`verify_ctx` — rather than a
crate-defined prefix construction. `pqc-sig` 0.4 exposes this directly, so a signature
made under one context provably does not verify under another (the underlying `ml-dsa`
crate enforces the context string as part of the signed message structure per FIPS 204
§5.2). An empty context (`&[]`) is byte-identical to plain `sign`/`verify`; a non-empty
context is not interchangeable with any other context, empty or not.

**The rule: a key must never sign under a purpose other than the one it was invoked for.**
An identity that signs attach challenges must not be asked to sign settlement receipts
under the same purpose bytes, and a caller must not reuse one purpose's signature as
though it were another's. This is what makes cross-purpose replay structurally impossible
rather than a convention callers must remember.

## The registry

Defined as constants in [`signing::purpose`](../src/signing.rs), pinned by a unit test
(`the_registry_is_pinned`) that asserts every constant is non-empty and pairwise distinct
from every other — a rename or a collision is a visible, reviewed diff, not a silent drift.

| Constant | Bytes | Who signs under it | For |
|---|---|---|---|
| `PLP_PRESENT_V1` | `aethel-core/plp-present/v1` | The agent's `Identity` | Presenting a PLP projection + proof + attach signature to a verifier (A-1's "present to a verifier" flow). |
| `CREDENTIAL_V1` | `aethel-core/credential/v1` | The credential holder's `Identity` | Signing over an issued or presented credential (`credential` module). |
| `SAAP_V1` | `aethel-core/saap/v1` | The identity presenting a SAAP disclosure | Signing adjacent to a SAAP selective-disclosure presentation. |
| `VAULT_SPEND_INTENT_V1` | `aethel-vault/spend-intent/v1` | aethel-vault's settlement/identity signer | A signed spend intent / pre-authorization (V-1). Reserved here so aethel-vault imports rather than redefines. |
| `VAULT_SETTLEMENT_RECEIPT_V1` | `aethel-vault/settlement-receipt/v1` | aethel-vault's identity signer | A signed settlement receipt (V-5). |
| `VAULT_WALLET_BIND_V1` | `aethel-vault/wallet-bind/v1` | The agent's `Identity` | Binding a spend-rail (`did:pkh:eip155`) address to an aethel identity — see [`IDENTITY-AND-SPEND-BINDING.md`](./IDENTITY-AND-SPEND-BINDING.md) if present, or A-2 in the gap-remediation plan. |
| `VAULT_HITL_APPROVAL_V1` | `aethel-vault/hitl-approval/v1` | The principal's `Identity` | A human-in-the-loop approval signature (V-4's `hitl_above` gate). |

### Why these are defined in aethel-core, not aethel-vault

Defining the `VAULT_*` constants here rather than letting `aethel-vault` define its own
means there is exactly one registry to keep in sync rather than two copies that can drift
apart. `aethel-vault` imports these:

```rust
use aethel_core::signing::purpose::{
    VAULT_SPEND_INTENT_V1,
    VAULT_SETTLEMENT_RECEIPT_V1,
    VAULT_WALLET_BIND_V1,
    VAULT_HITL_APPROVAL_V1,
};
```

### The naming convention

Purpose bytes are **`<crate>/<thing>/v<n>`**: the crate that owns the operation, the
operation, and a version. `aethel-core/plp-present/v1`, `aethel-vault/spend-intent/v1`.

The first segment names the *crate* whose code signs or verifies under it, not the product
the crate is deployed in. A crate is a stable thing with one registry entry; a product name
is a decision that can change without any code changing. Scoping by crate means a rename at
the product level never invalidates a signature, and it keeps the first segment matching the
`use` path a reader is already looking at.

A consumer crate outside this repository follows the same rule and registers here, the way
`aethel-vault` does. See the section above for why the registry is central.

> **Superseded alternative.** An earlier convention proposed product-scoped strings
> (`8gentz-agent-v1`, `8gentz-fabric-v1`) applied by prefixing the message before signing,
> rather than as FIPS 204 context bytes. It was written when `pqc-sig` 0.3.0 had no
> context-taking API and manual prefixing was the only thing available. `pqc-sig` 0.4
> exposes `sign_ctx_deterministic`/`verify_ctx`, which is what `sign_with_purpose` is built
> on, so the workaround is no longer necessary and the prefix form should not be used in new
> code. Prefixing is also the weaker construction: a prefix is part of the message, so a
> caller can omit it or get the delimiter wrong and the signature still verifies, whereas a
> context is a separate argument the signature scheme itself binds, and a signature made
> under one context provably does not verify under another.

### Adding a new purpose

1. Add the constant to [`signing::purpose`](../src/signing.rs), named
   `<crate>/<thing>/v<n>` per the convention above.
2. Add a row to the table above.
3. The pinning test (`the_registry_is_pinned`) will fail until the new constant is added
   to its list — that is deliberate, so a new purpose is always a reviewed, visible change.
4. Never reuse an existing purpose's bytes for a new meaning. If a purpose's meaning must
   change, mint `v2` and keep `v1` reserved (do not repurpose it).

## Bound: `MAX_CONTEXT_LEN`

`pqc_sig::MAX_CONTEXT_LEN` is 255 bytes. `Identity::sign_with_purpose` and
`verify_with_purpose` enforce this for any caller-supplied purpose (returning
`IdentityError::InvalidInputLength` if exceeded), not just the registry constants above —
every registry entry is well under the limit.
