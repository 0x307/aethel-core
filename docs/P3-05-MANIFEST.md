# P3-05 — Doc-Surface Scope-Accuracy Pass

Manifest for what happened to each file in this `docs/` directory during the P3-05 pass
(2026-08-26), sequenced before P3-06. Cross-check basis: `aethel-core`'s README, "What runs
today vs. what is designed," and the actual shipped code in `src/*.rs`.

**Why this pass exists:** the `aethel-docs` repo review (same day) found identical-shaped
overclaiming there, which prompted checking this repo's own doc surfaces — the top-level
`README.md` (fixed in P3-04) is not the only place `aethel-core` describes itself. Two other
surfaces had the same problem: this orphaned, unreferenced `docs/` directory, and the crate's
own compiled rustdoc (`///`/`//!` comments), which ships to docs.rs and is what a
`cargo doc --open` reader sees.

| File | Verdict | What changed |
|---|---|---|
| `HTSS-TOPOLOGY.md` | **Trimmed** | Removed ~120 lines of fictional 5D Toric quantum-error-correction content (logical qubits, stabilizer operators, homology classes) that had zero relationship to the real, shipped `htss.rs`. Rewrote the overview, topology diagram, and payload-structure sections to describe what's actually real: local, in-process Shamir 3-of-5 sharing plus a local graph-routing *simulation*. Reframed "Security Properties" as "real vs. aspirational," explicitly marking eavesdropper-resistance and fault-tolerance claims as design targets for a *future* distributed deployment, not properties of the code today — kept rather than deleted, per instructions, since there's a real future intent behind the idea. Renumbered sections 5-9 to close the gaps left by the removed content. |
| `OVERVIEW.md` | **Trimmed** | Fixed "on-chain" phrasing in the lead paragraph and threat-model list. Removed the "Integration Points with Aethel-Vault" section and "Comparative Architecture Matrix" entirely (charter §1 — Vault is out of scope, and neither section described anything `aethel-core` implements). Replaced a duplicate, equally-inaccurate HTSS section with a pointer to the now-corrected `HTSS-TOPOLOGY.md`. Marked SAAP issuance, SRAM PUF, and the EIAB wire format (only a magic-number constant ships, no full serializer) as aspirational. Rewrote the Security Properties table to drop "Kolmogorov-Blind Nullifier" (a Vault concept that doesn't exist in this crate at all) and correct "enclave execution"/"SRAM PUF" overclaims against what's actually shipped. |
| `PLP-ALGORITHM.md` | **Trimmed** | Fixed §3.1's `KeyGen` to match the real `MasterIdentity::from_seed` (caller-supplied seed, real domain separator `AETHEL_MASTER_KEY_V1`) instead of presenting PUF-derivation as the default path. Added an "aspirational" marker to §6.5/6.6's enclave pseudocode (the *algorithm* is real, shipped in `sampling.rs`; nothing here runs in an actual enclave). Marked §7 (hybrid cross-primitive) as an unbuilt design idea. Removed §8 ("5D Toric Manifold Connection") entirely — same fictional TQEC content as the HTSS doc, no relationship to anything built. Renumbered §9 to §8. |
| `SAAP-SPEC.md` | **Trimmed** | Fixed two "on-chain" instances. Marked §2 (BDLOP commitment), §4-5 (issuance), §8 (three-masking-vector protocol), §9 (three linked relations), and §10.2 as not implemented — the shipped `saap_prove`/`verify_saap_proof` do none of this; they operate on an already-parsed credential with a single response vector. §6-7 and §10.3-10.4 (Prove/Verify) are left as-is — they match shipped code closely. Marked §12 (WASM memory footprint) aspirational and §13.3/§14.2 (HelixDB) out of scope. |
| `SRAM-PUF.md` | **Trimmed** | Added one top-level editorial note rather than marking each section individually — the *entire* document describes the `puf` module's design, so a single strong banner (non-default feature, placeholder BCH encoder, unbuilt hardware targets in §10, and the real `from_seed` entry point's total independence from PUF) covers it without repeating the same caveat 12 times. Kept as a design document for the feature, not withheld, since the design itself is coherent and the feature is real (if incomplete and non-default). |

**Also fixed, same pass (not `docs/` files):**

- `src/htss.rs`'s module doc — the most severe finding. Rewrote entirely: it previously
  described a live distributed network protocol ("routes ZK proof payloads across a 5D
  hypercube network," "validator consensus nodes," "entanglement distribution," an
  "eavesdropper" who could observe a path). None of that exists — `SecretSharer` is local,
  in-process Shamir 3-of-5 over a single `u64`. `HypercubeNetwork`/`HypercubePacket` are real,
  tested code (not deleted), but implement a local routing *simulation*, not a live protocol.
  The idea of a future distributed deployment is kept, explicitly marked aspirational.
- `src/lib.rs`'s crate-level doc claimed "zero static public keys **on-chain**" — fixed to drop
  "on-chain" (this crate has no blockchain component at all) and "topologically-protected"
  (a stray TQEC-adjacent word that didn't describe anything PLP actually does).
- `src/lib.rs:80` — a *second*, easy-to-miss doc comment on `pub mod htss;` itself (separate
  from `htss.rs`'s own module doc) still said "5D Hypercube ZK Proof Payload Routing (HTSS)."
  This is the text rustdoc shows as the collapsed one-line summary in the parent module
  listing — confirmed via a rendered `cargo doc` build, not just source inspection. Fixed to
  match the corrected module doc.
- `src/saap.rs`'s module doc called the module "production-grade" — softened (this is
  pre-release, unaudited code per the crate's own security notice) and added a note that the
  shipped scope is prove/verify only, not the full issuance layer.
- `src/sampling.rs`'s module doc also said "Production-grade constant-time rejection sampling" —
  same fix, plus clarified "bare-metal enclave compatible" doesn't mean anything in this repo
  actually runs inside a hardware enclave.
- `CONTRIBUTING.md` and `dist/README.md` — checked, no instances of any flagged term found.

**Verification performed** (see the PR for actual command output, not summarized here):

- `grep -rniI "on-chain|blockchain|validator|consensus|mainnet|entanglement|TFHE|vault"` across
  `src/*.rs`, `docs/*.md`, `README.md`, `CONTRIBUTING.md`, `dist/README.md` — every remaining
  hit is inside an editorial note explaining what was fixed, or a deliberate, correct statement
  ("this crate has no blockchain... of any kind").
- `cargo doc --no-deps` — rendered HTML inspected directly (not just source text) for the
  crate root, `htss`, and `saap` pages; caught the `lib.rs:80` secondary doc comment that a
  source-only check would have missed, since the stale short-summary text only showed up in
  the actually-rendered parent module listing.
- `cargo build` / `cargo test` (default features), `cargo build --features puf`, and
  `cargo build --target wasm32-unknown-unknown --no-default-features --features wasm` — all
  clean before and after every edit in this pass.
