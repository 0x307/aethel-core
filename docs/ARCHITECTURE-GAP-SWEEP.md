# Architecture Gap Sweep — 0x307 Identity Release

Scope: `aethel-docs/rfc/*`, `aethel-docs/architecture/*` vs. the actual `aethel-core` WIT surface
(`wit/aethel-core.wit`) and its Rust implementation, as of pinned `aethel-core` main `a9b778c`.

**Framing note up front.** Several `aethel-docs` files (`rfc/sec6.5.md`, `rfc/sec7.md` [really SRAM
PUF, mislabeled], `rfc/sec8.md`, `rfc/sec9.md`, most of `architecture/ARCHITECTURE.md` §§3-7,
`TOPOLOGY.md`, `5d-toric-manifold.md`, `SECURITY-PROOFS.md` extended parts) read as
LLM-brainstorm-with-a-human transcripts (literal chat turns, e.g. "Show me the algebraic topology
equations for...") rather than reviewed engineering specs. They describe a *different, much larger*
system: an on-chain wallet ("Aethel-Vault") with TFHE-encrypted balances, hardware SRAM PUFs,
isogeny/code-based hybrid crypto, ZK-STARKs, 5D/7D homological manifolds, HelixDB graph storage,
and threshold-FHE validator networks. None of that is in scope for `aethel-core`, which is
narrowly a WASM component holding ML-DSA-65 signing, PLP, BDLOP credentials, and HTSS. Gaps below
are filed only where the doc describes something plausibly meant to be this component's job
(identity, credentials, disclosure, key lifecycle) — not the wallet/FHE/topology material, which is
out of scope by any reasonable reading and is called out once (GAP-13) rather than per-section.

---

## GAP-01: SRAM PUF hardware key derivation is implemented in source but never wired to the WIT surface

**What the doc says.** `rfc/AETHEL-SPEC-001.md` §4 and §8/§12 (`rfc/sec8.md`) specify that the
master secret `s` MUST be derived at runtime from a physical SRAM PUF reading via a BCH(1023,512,55)
fuzzy extractor (`Gen`/`Rep`), never from caller-supplied entropy, with `s` existing in volatile
memory for "at most... a single proof generation cycle (<50ms)." §1 lists this as one of Aethel-ID's
two core mechanisms.

**What's callable today.** `master-identity.generate(entropy: list<u8>)` derives the identity via
SHAKE-256 over *caller-supplied* entropy (`src/signing.rs`), explicitly not a PUF reading — the WIT
doc comment says so directly ("Requires at least 32 bytes... stretched through SHAKE-256... NOT the
key"). Separately, `src/puf.rs` contains a real, non-stub BCH(1023,512,55) GF(2^10) fuzzy extractor
(Berlekamp-Massey, Chien search) matching the spec's parameters almost exactly — but it is not
called from `component.rs`, not exported in any WIT interface, and has no path from a caller to
`master-identity`. It is dead code from the component's public surface.

**Severity:** `doc-only-confusion` (bordering `partial` — the primitive exists in the crate, the
integration doesn't). The WIT itself is candid that entropy comes from the caller, which is also a
reasonable engineering choice (WASM components don't have physical SRAM access) — but the doc
never says PUF derivation is out of scope, and shipping the fuzzy-extractor code unused invites
exactly this confusion.

**Suggested Linear issue title:** "`master-identity::generate` has no path to `puf::reconstruct_secret`; either wire it behind a feature/host-import or remove `src/puf.rs` and mark PUF derivation explicitly out-of-scope in the RFC — AC: a test proves no exported function reaches `puf.rs`, and the RFC/doc states the caller-entropy model as the actual contract."

---

## GAP-02: No revocation primitive of any kind

**What the doc says.** `NEXT-SESSION-PROMPT.md` states plainly: "The RFC describes issuance flows,
revocation and enclave execution with no code behind them." No specific RFC section in
`aethel-docs` names a revocation mechanism explicitly (credentials are treated as ephemeral/
presentation-time constructs throughout §5 of `AETHEL-SPEC-001.md`), but any credential system that
issues long-lived `credential` resources implies a need to invalidate one before its natural
expiry — the current design has no expiry either.

**What's callable today.** `identity.credential.issue` / `.present` — no revocation list, no
epoch/expiry field on `credential` or `saap-presentation`, no `identity-error` variant for "revoked."
Nothing exists at any layer.

**Severity:** `missing-entirely`.

**Suggested Linear issue title:** "Add a revocation check to `saap-verify-presentation` — AC: a presentation built from a credential added to a revocation set fails verification with a new `identity-error` variant, and a positive-control test shows a non-revoked, otherwise-identical presentation still verifies."

---

## GAP-03: No issuance-flow orchestration (issuer/holder handshake)

**What the doc says.** `AETHEL-SPEC-001.md` §5.3-5.4 and `ARCHITECTURE.md`'s issuance diagrams
describe issuance as a protocol between two parties: the Issuer holds `sk_iss`, computes
`t_attr`/`t_cred`, and signs it; the Holder later blinds and presents. This implies a
request/response exchange (holder requests issuance, issuer approves and issues) distinct from a
single local function call.

**What's callable today.** `credential.issue` is a single static function that *borrows* a
`master-identity` and an `issuer-seed` passed directly by the caller — there is no notion of an
issuer as a separate party with its own component instance, no request/approval step, no
transport. This is a deliberate design (the component holds no session state and doesn't do
networking) but the docs read as if a live issuer service exists.

**Severity:** `doc-only-confusion`. The WIT design (issuer-seed as a caller-supplied parameter) is
reasonable for a stateless crypto component; the docs simply describe a fuller multi-party protocol
that would live in the SDK/application layer, not here, and nothing states that boundary.

**Suggested Linear issue title:** "Document (in `aethel-docs` or SDK docs, not core) that issuer/holder handshake, transport, and consent are explicitly out of `aethel-core` scope — AC: a docs PR states the boundary and lints clean; no code AC since this is a documentation-only gap."

---

## GAP-04: `attestation.saap-prove`/`saap-verify` is a second, differently-shaped SAAP path — confirmed real but confusing duplicate

**What the doc says.** `AETHEL-SPEC-001.md` §5.5-5.7 and the WIT's own `identity` interface describe
one SAAP flow: BDLOP credential commitment (`t_cred`), holder blinding (`t_blind`), three linked
relations (identity linkage, credential membership, predicate — predicate deliberately deferred),
producing `saap-presentation` with fields `t-blind, challenge, z-r, z-m, z-s, z-e`.

**What's callable today.** Both this AND a second interface, `attestation`, export `saap-prove` /
`saap-verify` operating over a `saap-proof` record with fields `context-tag, disclosed, attributes,
challenge, response-z, commitment-hash, commitment-w` — closer in shape to the single-relation
sigma-protocol prototype in `ARCHITECTURE.md` §5.1's Rust code and the raw-bitmask `M_disc`
formalism in `rfc/sec9.md`/§9 of the spec (which the WIT's own `disclosure-attributes` doc comment
explicitly says the system does NOT do: "Never a raw bitmask on the wire"). `src/saap.rs`'s own doc
comment confirms this is intentionally "a narrower surface than the full SAAP design... issuing one
in the first place (BDLOP commitment issuance, an issuer signature) is not implemented here" — i.e.
`attestation.saap-prove` operates over an already-issued/parsed credential blob and is NOT the same
protocol as `identity`'s three-relation flow, despite both being called "SAAP" in the WIT and docs.
`RANDOMNESS-FINDINGS-AND-FIX.md` corroborates: "`saap_verify_wasm` intentionally fails closed
(always denies)" for the credential-membership relation, because that part isn't built — implying
`attestation.saap-verify` is a legacy/lower-trust path kept for a narrower use case, not documented
as such anywhere a reader would find without spelunking source comments.

**Severity:** `doc-only-confusion` — this is exactly the case the task description called out.
Both interfaces are real and callable (not `missing-entirely`), but nothing in `aethel-docs` or the
WIT explains why there are two SAAP surfaces, which one a new integrator should use, or that
`attestation`'s is the older/narrower one.

**Suggested Linear issue title:** "Document the relationship between `identity`'s SAAP presentation flow and `attestation.saap-prove/verify`, or deprecate one — AC: WIT doc comments on `attestation` interface state explicitly that it is a legacy/narrower path (or is removed), and a test asserts a credential built via `identity.credential.issue` cannot be fed into `attestation.saap-verify` without an explicit, documented adapter step."

---

## GAP-05: No key-rotation primitive

**What the doc says.** No explicit RFC section demands rotation, but `AETHEL-SPEC-001.md` §7 security
considerations and general PQC hygiene (referenced via FIPS 204) imply a rotation story is expected
for a "sovereign identity" system whose whole premise is resilience against key compromise.
`NEXT-SESSION-PROMPT.md`'s backlog doesn't list it either — it's a silent gap, not a named one.

**What's callable today.** Nothing. `master-identity` is generated once from entropy and is
immutable; there is no operation to derive a successor identity, no revocation-of-old-key-plus-
binding-to-new-key, nothing.

**Severity:** `missing-entirely`.

**Suggested Linear issue title:** "Add a key-rotation primitive that binds an old `master-identity` to a new one under a signed transition record — AC: a test shows a rotated-away identity's signature is not trusted after rotation is recorded, using a positive control that the same signature *would* be trusted pre-rotation."

---

## GAP-06: No enclave/TEE execution primitive (confirmed absent, matches known status)

**What the doc says.** `AETHEL-SPEC-001.md` §6 and §11 and `ARCHITECTURE.md` §6.3 describe hardware
enclave execution bounds (memory layout, cache-line locking, constant-time zeroization via
`volatile` C code) as normative ("MUST").

**What's callable today.** Nothing — this is a WASM component with no host TEE binding, no
attestation quote, no enclave measurement exposed via WIT. `NEXT-SESSION-PROMPT.md` already names
this ("enclave execution with no code behind them"), so this confirms rather than newly discovers
the gap.

**Severity:** `missing-entirely` (already flagged at the initiative level; listed here for
completeness of the sweep, not as a new discovery).

**Suggested Linear issue title:** "Scope decision needed: is enclave/TEE attestation ever in `aethel-core`'s WIT surface, or permanently a host-embedder concern? — AC: a scoping doc is merged that either adds a stub `attestation-quote` WIT type with one falsifiable round-trip test, or states the boundary and removes enclave language from `AETHEL-SPEC-001.md` §6/§11 as non-normative for this implementation."

---

## GAP-07: No predicate-proof-over-hidden-value primitive — DO NOT FILE

Per task instructions, this is a documented, deliberate deferral (`SAAP-SPEC.md` §9.3, SDK
`disclosure` module, and `NEXT-SESSION-PROMPT.md`). `AETHEL-SPEC-001.md` §5.6 relation 3 and §5.7
step 4 describe it, and `credential.rs`/`saap.rs`'s "relation 3" is confirmed not built. Not filed as
a gap; noted here only so the reader doesn't refile it.

---

## GAP-08: HTSS (threshold secret sharing) is 5-share/3-of-5 fixed, not the flexible n/t scheme implied by docs

**What the doc says.** No single-file citation ties HTSS's exact parameters to `AETHEL-SPEC-001.md`
directly (HTSS isn't named there), but `ARCHITECTURE.md` §6.2 describes a general
"Multi-Party Threshold Fully Homomorphic Encryption... t-of-n post-quantum threshold consensus" and
`NEXT-SESSION-PROMPT.md`'s backlog lists "P5-08 HTSS recovery" as still open, implying HTSS is meant
to be a more general building block than what's shipped.

**What's callable today.** `secret-sharing.htss-split` / `htss-reconstruct` — real, working Shamir
splitting, but hardcoded to exactly 5 shares / 3-of-5 threshold (per the WIT doc comment). No
parameterization for n/t.

**Severity:** `already-covered` for the core split/reconstruct operation (it is callable and
real) — flagged only because a caller wanting a different threshold has no path, and the backlog
entry ("P5-08 HTSS recovery") suggests more is expected. Category: `partial`.

**Suggested Linear issue title:** "Parameterize `htss-split`/`htss-reconstruct` over n and t (or document why 5-of-3 is fixed and sufficient) — AC: a test calls `htss-split` requesting a non-default threshold and either succeeds with the new n/t, or the WIT is updated to remove the appearance of generality and the doc states the fixed-5 rationale."

---

## GAP-09: 0X3-85 open security item — plp.rs all-rejected fallback (known, re-confirmed, not a new gap)

Per `NEXT-SESSION-PROMPT.md`: `prove_identity`'s all-rejected fallback in `src/plp.rs` derives the
mask without τ and returns a `z` that failed the norm bound, rather than an error. This is already
tracked as 0X3-85 and is the one acknowledged open security item — not re-filed here, just confirmed
present in the code read for this sweep (`src/plp.rs`).

---

## GAP-10: Already-covered — full identity lifecycle (keygen, sign, verify, seal/unseal) matches docs

`AETHEL-SPEC-001.md` §3.5-3.6 (PLP projection/proof/verify), FIPS 204 ML-DSA signing, and the
"decoupled" identity model in `ARCHITECTURE.md` §3-5 are all backed by real, tested code:
`master-identity.generate/public-key/sign/project-at-context/prove/export-sealed/import-sealed`,
`plp-project-at-context/plp-prove-identity/plp-verify`, `verify-signature`. Confirmed non-stub in
`src/signing.rs` and `src/plp.rs`. **Category: `already-covered`. Do not file.**

---

## GAP-11: Already-covered — BDLOP credential issuance/presentation with named-attribute selective disclosure

`AETHEL-SPEC-001.md` §5.2-5.4 BDLOP commitment and holder blinding, and the "Four decisions" #1/#2 in
`NEXT-SESSION-PROMPT.md` (the `e_τ`-in-witness and shared-witness departures) are implemented and
tested: `credential.issue`, `credential.present`, `saap-verify-presentation`, backed by
`src/credential.rs`. The two documented RFC departures are intentional and not gaps — they're
findings for Ken's review, already tracked. **Category: `already-covered`. Do not file.**

---

## GAP-12: Sealed persistence nonce-derivation fragility is a known departure, not a new gap

`NEXT-SESSION-PROMPT.md` item #3 already names this precisely (deterministic nonce derivation is
sound today, "becomes wrong the moment a second kind of thing is sealed under the same key").
`export-sealed`/`import-sealed` are real (`src/lib.rs`/`component.rs`, XChaCha20-Poly1305). Not
re-filed as a new gap, but flagged because it's the kind of thing that will bite the moment a second
resource type needs sealing (e.g. a rotated identity per GAP-05, or a credential itself) —
worth keeping in view when scoping GAP-05.

**Severity:** `already-covered` (documented departure) with a forward-looking note, not a fresh AC.

---

## GAP-13: Out of scope — wallet/FHE/topology/isogeny material in `ARCHITECTURE.md` §§1-2, 6, 7, `TOPOLOGY.md`, `5d-toric-manifold.md`

`ARCHITECTURE.md` describes "Aethel-Vault" (TFHE-encrypted balances, ML-KEM stealth addresses,
differential-privacy mempool noise), a hybrid lattice+isogeny/code-based key scheme, threshold-FHE
validator consensus, and a 5D/7D homological-manifold "topological protection" layer with HelixDB
graph storage (`rfc/sec6.5.md`). None of this maps to any WIT interface, and none of it should:
`aethel-core`'s charter (per `NEXT-SESSION-PROMPT.md`) is identity + credentials + HTSS, not an
on-chain wallet, FHE execution engine, or novel topological error-correction system. Filing these as
gaps against `aethel-core` would misdirect effort — flagged once here as `doc-only-confusion` at the
document level (these documents conflate two/three unrelated systems under one title) rather than
per-section as individual "missing" issues.

**Suggested Linear issue title:** "Split `aethel-docs` into `aethel-core`-scoped identity/credential spec vs. speculative Aethel-Vault/topology research notes — AC: `AETHEL-SPEC-001.md` and `ARCHITECTURE.md` carry a scope banner (or are physically split) such that every remaining section maps to at least one WIT interface, checked by a doc-lint script that flags sections naming primitives absent from `wit/aethel-core.wit`."

---

## Summary by category

| Category | Count | Items |
|---|---|---|
| `missing-entirely` | 3 | GAP-02 (revocation), GAP-05 (key rotation), GAP-06 (enclave/TEE, already known) |
| `partial` | 1 | GAP-08 (HTSS fixed 3-of-5) |
| `doc-only-confusion` | 4 | GAP-01 (PUF orphaned), GAP-03 (issuance handshake), GAP-04 (attestation vs identity SAAP duplication), GAP-13 (doc scope conflation) |
| `already-covered` | 3 | GAP-10 (identity lifecycle), GAP-11 (credential/SAAP presentation), GAP-12 (sealing, noted departure only) |
| Not filed (per instructions / already tracked) | 2 | GAP-07 (predicate proofs, deliberately deferred), GAP-09 (0X3-85, already tracked) |

## Top 5 to close first

1. **GAP-04 — attestation vs identity SAAP duplication.** Highest confusion-per-line-of-doc ratio;
   any external integrator or auditor hits this within minutes of reading the WIT. Cheapest fix
   (doc comments + a boundary test) relative to how much confusion it resolves.
2. **GAP-02 — revocation.** A credential system with issue/present but no revoke is not
   production-viable for any real relying-party use case; this is the single biggest functional
   gap versus what "SDK works end to end" implies to a consumer.
3. **GAP-01 — orphaned PUF code.** Either wire it or delete it. Shipping unreachable crypto code
   that implements a documented-but-unused key-derivation path is a maintenance and audit liability
   (it will get audited as if live, or worse, silently bit-rot until someone wires it incorrectly).
4. **GAP-05 — key rotation.** Directly blocks any real deployment story once an identity's entropy
   source is suspected compromised; currently there is no recovery path at all, only re-generation
   with no binding to the old identity.
5. **GAP-13 — doc scope split.** Not a code gap, but the fastest way to stop future sweeps (and
   Ken's review time) from being spent re-litigating whether SRAM PUFs or 5D manifolds are in scope.
   A scope banner or physical doc split pays for itself the next time someone reads these files.
