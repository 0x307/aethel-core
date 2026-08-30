//! Execution proof for the `aethel:core` component (P5-03 / 0X3-53).
//!
//! Everything the `component` CI job checked until now was structural: the
//! component builds, `wasm-tools validate` passes, `wasm-tools component wit`
//! shows the declared world, two builds are byte-identical. **None of that is
//! "you can instantiate it and call it."**
//!
//! That gap is the same shape as the ones this crate has already been bitten by
//! — a check that looks like verification and stops short of the thing it
//! implies. So these tests load the built artifact in a real host, call it, and
//! compare against the native API. If the component and the native
//! implementation disagree, one of them is wrong and the L1 boundary is not a
//! boundary.
//!
//! Gated behind the `component-tests` feature because it needs
//! `aethel_core.component.wasm` to exist. Build it first:
//!
//! ```bash
//! cargo build --release --target wasm32-unknown-unknown \
//!   --no-default-features --features component
//! wasm-tools component new \
//!   target/wasm32-unknown-unknown/release/aethel_core.wasm \
//!   -o aethel_core.component.wasm
//! cargo test --features component-tests --test component_execution
//! ```

#![cfg(feature = "component-tests")]

use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

wasmtime::component::bindgen!({
    path: "wit",
    world: "aethel-core",
});

const ARTIFACT: &str = "aethel_core.component.wasm";

/// Load and instantiate the component. A missing artifact is a hard failure,
/// not a skip: a test that silently passes when it cannot run is worse than no
/// test, which is the lesson this whole file exists to apply.
fn instantiate() -> (Store<()>, AethelCore) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(ARTIFACT);
    assert!(
        path.exists(),
        "{} not found. Build it first:\n  cargo build --release \
         --target wasm32-unknown-unknown --no-default-features --features component\n  \
         wasm-tools component new target/wasm32-unknown-unknown/release/aethel_core.wasm \
         -o {}",
        ARTIFACT,
        ARTIFACT
    );

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config).expect("engine");
    let component = Component::from_file(&engine, &path).expect("load component");
    let linker = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let bindings = AethelCore::instantiate(&mut store, &component, &linker)
        .expect("instantiate the component");
    (store, bindings)
}

/// The component instantiates at all. Everything else depends on this.
#[test]
fn the_component_instantiates() {
    let _ = instantiate();
}

/// `plp-project-at-context` through the component must produce exactly what the
/// native API produces for the same input. This is the equivalence that makes
/// "one artifact embedded by every language" meaningful — if the component
/// drifts from the native implementation, every language binding drifts with it.
#[test]
fn projection_through_the_component_matches_the_native_api() {
    let (mut store, bindings) = instantiate();

    let secret = [0x5Au8; 32];
    let tau = b"execution-proof-context".to_vec();
    let randomness = [0xC3u8; 32];

    let via_component = bindings
        .aethel_core_identity()
        .call_plp_project_at_context(
            &mut store,
            &secret,
            &tau,
            &randomness,
        )
        .expect("host call")
        .expect("plp-project-at-context returned err");

    let identity = aethel_core::plp::MasterIdentity::from_seed(&secret);
    let native = identity.project_at_context(&tau, &randomness);

    assert_eq!(via_component.tau, native.tau.to_vec(), "tau differs");
    assert_eq!(
        via_component.matrix_a,
        native.matrix_a.coeffs().to_vec(),
        "matrix_a differs between the component and the native API"
    );
    assert_eq!(
        via_component.public_b,
        native.public_b.coeffs().to_vec(),
        "public_b differs between the component and the native API"
    );
}

/// A prove/verify round trip entirely inside the component.
#[test]
fn prove_and_verify_round_trip_inside_the_component() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();

    let secret = [0x11u8; 32];
    let tau = b"round-trip".to_vec();
    let randomness = [0x77u8; 32];

    let projection = identity
        .call_plp_project_at_context(&mut store, &secret, &tau, &randomness)
        .expect("host call")
        .expect("projection");

    let proof = identity
        .call_plp_prove_identity(&mut store, &secret, &tau)
        .expect("host call")
        .expect("proof");

    let verified = identity
        .call_plp_verify(&mut store, &projection, &proof)
        .expect("host call")
        .expect("verify returned err");

    assert!(verified, "an honestly generated proof failed to verify through the component");
}

/// The typed error channel actually carries errors. Every WASM export in the
/// old wasm-bindgen surface returned a sentinel; the whole point of the
/// component is that `result<T, identity-error>` reaches the caller.
#[test]
fn a_short_secret_returns_invalid_input_length_not_a_sentinel() {
    let (mut store, bindings) = instantiate();

    let result = bindings
        .aethel_core_identity()
        .call_plp_project_at_context(
            &mut store,
            &[0u8; 31], // one byte short
            b"ctx",
            &[0u8; 32],
        )
        .expect("host call");

    match result {
        Err(aethel::core::types::IdentityError::InvalidInputLength) => {}
        Err(other) => panic!("expected invalid-input-length, got {:?}", other),
        Ok(_) => panic!(
            "a 31-byte secret was accepted. The WIT declares list<u8> and cannot \
             express the 32-byte bound, so the implementation owns it"
        ),
    }
}

/// HTSS round trip through the component, including the below-threshold error.
#[test]
fn htss_round_trips_and_reports_threshold_not_met() {
    let (mut store, bindings) = instantiate();
    let sharing = bindings.aethel_core_secret_sharing();

    let secret = b"32-byte key material for HTSS !!".to_vec();
    assert_eq!(secret.len(), 32, "test setup");

    let shares = sharing
        .call_htss_split(&mut store, &secret)
        .expect("host call")
        .expect("split");
    assert_eq!(shares.len(), 5, "expected a 3-of-5 split");

    let recovered = sharing
        .call_htss_reconstruct(&mut store, &shares[..3])
        .expect("host call")
        .expect("reconstruct");
    assert_eq!(recovered, secret, "key material did not survive the component round trip");

    // Two shares must be an error, not a wrong answer and not an empty vector.
    let below = sharing
        .call_htss_reconstruct(&mut store, &shares[..2])
        .expect("host call");
    match below {
        Err(aethel::core::types::IdentityError::ThresholdNotMet) => {}
        Err(other) => panic!("expected threshold-not-met, got {:?}", other),
        Ok(_) => panic!("two shares of a 3-of-5 split reconstructed something"),
    }
}

/// `saap-verify`, the **superseded** operation, still denies unconditionally.
///
/// This is no longer "SAAP does not work". P3-11 landed the real construction
/// and it is exercised below through `credential.present` and
/// `saap-verify-presentation`, which do verify honest presentations. This
/// operation is the old single-relation surface kept for compatibility, and it
/// must keep failing closed: it has no way to be sound, so `ok(false)` is the
/// only honest answer it can give.
///
/// Pinned so the day it starts returning `ok(true)` is a day someone notices.
#[test]
fn saap_verify_denies_as_documented() {
    let (mut store, bindings) = instantiate();
    let attestation = bindings.aethel_core_attestation();

    let secret_key = vec![0u8; 4 * 256 * 4];
    let proof = attestation
        .call_saap_prove(
            &mut store,
            b"credential-block",
            exports::aethel::core::attestation::DisclosureAttributes::ATTRIBUTE0,
            b"ctx",
            &secret_key,
            &[0x42u8; 32],
        )
        .expect("host call")
        .expect("prove");

    let verified = attestation
        .call_saap_verify(&mut store, &proof, b"ctx")
        .expect("host call")
        .expect("verify returned err");

    assert!(
        !verified,
        "saap-verify returned true. It is documented as failing closed until \
         P3-11 (0X3-79) anchors it on b_tau — if it was wired up, delete this test"
    );
}

// ── master-identity resource (P5-04 / 0X3-54) ────────────────────────────────
//
// The free functions above take `secret: list<u8>`, so the caller holds the
// master secret and it crosses the boundary on every call. The resource exists
// so it does not: the secret is derived inside the component and only the
// public key, signatures, projections and proofs come out. These tests exercise
// that through the artifact, because "the WIT declares a resource" and "the
// resource works" are different claims and this crate has been bitten by the
// gap between them before.

/// Generate an identity inside the component and get a public key out.
#[test]
fn an_identity_can_be_generated_inside_the_component() {
    let (mut store, bindings) = instantiate();
    let api = bindings.aethel_core_identity().master_identity();

    let id = api
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");

    let pk = api.call_public_key(&mut store, id).expect("host call");
    assert!(!pk.is_empty(), "an identity was generated with an empty public key");
}

/// Entropy below the 32-byte floor is refused with a typed error.
#[test]
fn short_entropy_is_refused_by_the_component() {
    let (mut store, bindings) = instantiate();
    let api = bindings.aethel_core_identity().master_identity();

    match api.call_generate(&mut store, b"too short").expect("host call") {
        Err(aethel::core::types::IdentityError::InvalidInputLength) => {}
        Err(other) => panic!("expected invalid-input-length, got {other:?}"),
        Ok(_) => panic!("9 bytes of entropy produced an identity"),
    }
}

/// Sign and verify round-trip entirely through the component.
#[test]
fn sign_and_verify_round_trip_through_the_component() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let api = identity.master_identity();

    let id = api
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let pk = api.call_public_key(&mut store, id).expect("host call");

    let message = b"the message that was actually signed";
    let sig = api
        .call_sign(&mut store, id, message)
        .expect("host call")
        .expect("sign");

    let ok = identity
        .call_verify_signature(&mut store, &pk, message, &sig)
        .expect("host call")
        .expect("verify");
    assert!(ok, "an honestly produced signature failed to verify");
}

/// Positive control for the test above. If `verify-signature` returned `true`
/// unconditionally, the round trip would pass and prove nothing.
#[test]
fn a_tampered_message_and_a_wrong_key_both_fail_verification() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let api = identity.master_identity();

    let signer = api
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let other = api
        .call_generate(&mut store, b"a completely different entropy!!")
        .expect("host call")
        .expect("generate");

    let signer_pk = api.call_public_key(&mut store, signer).expect("host call");
    let other_pk = api.call_public_key(&mut store, other).expect("host call");
    assert_ne!(signer_pk, other_pk, "two entropies produced the same key");

    let message = b"transfer 10 to alice";
    let sig = api
        .call_sign(&mut store, signer, message)
        .expect("host call")
        .expect("sign");

    let tampered = identity
        .call_verify_signature(&mut store, &signer_pk, b"transfer 99 to alice", &sig)
        .expect("host call")
        .expect("verify");
    assert!(!tampered, "a signature verified against a message it was not made over");

    let wrong_key = identity
        .call_verify_signature(&mut store, &other_pk, message, &sig)
        .expect("host call")
        .expect("verify");
    assert!(!wrong_key, "a signature verified under a key that did not produce it");
}

/// Generation is deterministic over its entropy, and distinct entropy gives a
/// distinct identity. Both halves are needed: the first alone would pass for an
/// implementation that ignored entropy entirely.
#[test]
fn generation_is_deterministic_and_entropy_dependent() {
    let (mut store, bindings) = instantiate();
    let api = bindings.aethel_core_identity().master_identity();

    let gen = |store: &mut Store<()>, entropy: &[u8]| {
        let id = api
            .call_generate(&mut *store, entropy)
            .expect("host call")
            .expect("generate");
        api.call_public_key(&mut *store, id).expect("host call")
    };

    let a = gen(&mut store, b"deterministic entropy for tests!");
    let b = gen(&mut store, b"deterministic entropy for tests!");
    let c = gen(&mut store, b"a completely different entropy!!");

    assert_eq!(a, b, "the same entropy produced two different identities");
    assert_ne!(a, c, "different entropy produced the same identity");
}

/// The resource can project and prove, so an identity generated inside the
/// component is usable for PLP without the secret ever coming out.
#[test]
fn a_generated_identity_projects_and_proves() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let api = identity.master_identity();

    let id = api
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");

    let projection = api
        .call_project_at_context(&mut store, id, b"context-one", &[0x5Au8; 32])
        .expect("host call")
        .expect("project");

    let proof = api
        .call_prove(&mut store, id, b"context-one")
        .expect("host call")
        .expect("prove");

    let verified = identity
        .call_plp_verify(&mut store, &projection, &proof)
        .expect("host call")
        .expect("verify");
    assert!(verified, "a proof from a generated identity failed to verify");

    // Two contexts must not produce the same projection, or "unlinkable across
    // contexts" would be vacuous.
    let other = api
        .call_project_at_context(&mut store, id, b"context-two", &[0x5Au8; 32])
        .expect("host call")
        .expect("project");
    assert_ne!(
        projection.public_b, other.public_b,
        "two contexts produced the same projection"
    );
}

/// Short randomness must be refused on the resource too, not only on the free
/// function. A bound enforced on one path and not the other is not a bound.
#[test]
fn the_resource_enforces_the_randomness_floor() {
    let (mut store, bindings) = instantiate();
    let api = bindings.aethel_core_identity().master_identity();

    let id = api
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");

    match api
        .call_project_at_context(&mut store, id, b"ctx", &[0u8; 31])
        .expect("host call")
    {
        Err(aethel::core::types::IdentityError::InvalidInputLength) => {}
        Err(other) => panic!("expected invalid-input-length, got {other:?}"),
        Ok(_) => panic!("31 bytes of randomness was accepted"),
    }
}

// ── SAAP selective disclosure through the component (P3-11 / 0X3-79) ─────────
//
// Until this landed, `saap-verify` through the artifact returned `ok(false)` for
// every input, including honest proofs, and `saap_verify_denies_as_documented`
// above pinned that. The credential surface is the construction that replaces
// it. These tests exercise it end to end through the built component, because
// "the WIT declares a credential resource" and "selective disclosure works" are
// different claims.

const ISSUER_SEED: &[u8] = b"issuer seed for the test suite!!";
const ISSUE_R: &[u8] = b"issuance randomness for tests!!!";
const BLIND_R: &[u8] = b"blinding randomness for tests!!!";
const PRES_R: &[u8] = b"presentation randomness tests!!!";
const PROJ_R: &[u8] = b"projection randomness for tests!";
const ATTRS: [u64; 8] = [31, 1990, 7, 42, 100, 5, 9, 12345];

/// Disclose attribute 0 only.
fn disclose_first() -> exports::aethel::core::identity::DisclosureAttributes {
    exports::aethel::core::identity::DisclosureAttributes::ATTRIBUTE0
}

/// An identity can be issued a credential and present it, and the presentation
/// verifies. This is selective disclosure actually working through the L1
/// artifact for the first time.
#[test]
fn a_credential_can_be_issued_and_presented_through_the_component() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    let holder = ids
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");

    let cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host call")
        .expect("issue");

    let presentation = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-alpha",
            PROJ_R,
            disclose_first(),
            BLIND_R,
            PRES_R,
        )
        .expect("host call")
        .expect("present");

    let projection = ids
        .call_project_at_context(&mut store, holder, b"context-alpha", PROJ_R)
        .expect("host call")
        .expect("project");

    let verified = identity
        .call_saap_verify_presentation(
            &mut store,
            ISSUER_SEED,
            &presentation,
            &projection,
            b"context-alpha",
        )
        .expect("host call")
        .expect("verify");

    assert!(
        verified,
        "an honestly issued and presented credential failed to verify through the component"
    );
    assert_eq!(
        presentation.disclosed_values[0], ATTRS[0],
        "the disclosed attribute did not survive the round trip"
    );
}

/// Positive control for the test above. A verifier that returned `true`
/// unconditionally would pass it, and that is precisely the failure mode the
/// old `saap-verify` had in the opposite direction.
#[test]
fn a_presentation_fails_against_another_identity_through_the_component() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    let holder = ids
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let stranger = ids
        .call_generate(&mut store, b"a completely different entropy!!")
        .expect("host call")
        .expect("generate");

    let cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host call")
        .expect("issue");
    let presentation = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-alpha",
            PROJ_R,
            disclose_first(),
            BLIND_R,
            PRES_R,
        )
        .expect("host call")
        .expect("present");

    let stranger_projection = ids
        .call_project_at_context(&mut store, stranger, b"context-alpha", PROJ_R)
        .expect("host call")
        .expect("project");

    let verified = identity
        .call_saap_verify_presentation(
            &mut store,
            ISSUER_SEED,
            &presentation,
            &stranger_projection,
            b"context-alpha",
        )
        .expect("host call")
        .expect("verify");

    assert!(
        !verified,
        "a presentation verified against a different identity's projection"
    );
}

/// Rewriting a disclosed attribute must invalidate the presentation, through the
/// component and not only natively.
#[test]
fn rewriting_a_disclosed_attribute_is_caught_through_the_component() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    let holder = ids
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host call")
        .expect("issue");
    let mut presentation = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-alpha",
            PROJ_R,
            disclose_first(),
            BLIND_R,
            PRES_R,
        )
        .expect("host call")
        .expect("present");

    let projection = ids
        .call_project_at_context(&mut store, holder, b"context-alpha", PROJ_R)
        .expect("host call")
        .expect("project");

    presentation.disclosed_values[0] += 1;

    let verified = identity
        .call_saap_verify_presentation(
            &mut store,
            ISSUER_SEED,
            &presentation,
            &projection,
            b"context-alpha",
        )
        .expect("host call")
        .expect("verify");

    assert!(!verified, "a rewritten disclosed attribute still verified");
}

/// A presentation must not be able to certify its own context. The verifier
/// supplies tau and the presentation has to agree with it. This is the check
/// P3-10 found missing on the old verifier, so it is pinned at the boundary.
#[test]
fn a_presentation_cannot_certify_its_own_context() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    let holder = ids
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host call")
        .expect("issue");
    let presentation = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-alpha",
            PROJ_R,
            disclose_first(),
            BLIND_R,
            PRES_R,
        )
        .expect("host call")
        .expect("present");

    let projection = ids
        .call_project_at_context(&mut store, holder, b"context-alpha", PROJ_R)
        .expect("host call")
        .expect("project");

    let verified = identity
        .call_saap_verify_presentation(
            &mut store,
            ISSUER_SEED,
            &presentation,
            &projection,
            b"context-beta",
        )
        .expect("host call")
        .expect("verify");

    assert!(
        !verified,
        "a presentation made for context-alpha verified under context-beta"
    );
}

/// A credential presented under an issuer that never issued it must fail.
#[test]
fn a_presentation_fails_under_a_different_issuer() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    let holder = ids
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host call")
        .expect("issue");
    let presentation = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-alpha",
            PROJ_R,
            disclose_first(),
            BLIND_R,
            PRES_R,
        )
        .expect("host call")
        .expect("present");

    let projection = ids
        .call_project_at_context(&mut store, holder, b"context-alpha", PROJ_R)
        .expect("host call")
        .expect("project");

    let verified = identity
        .call_saap_verify_presentation(
            &mut store,
            b"a different issuer seed entirely",
            &presentation,
            &projection,
            b"context-alpha",
        )
        .expect("host call")
        .expect("verify");

    assert!(
        !verified,
        "a presentation verified under an issuer that never issued it"
    );
}

/// Two presentations of the same credential must not be linkable by their
/// blinded commitment, which is the property fresh blinding exists to provide.
#[test]
fn two_presentations_of_one_credential_are_not_linkable() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    let holder = ids
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host call")
        .expect("issue");

    let first = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-one",
            PROJ_R,
            disclose_first(),
            b"blinding for presentation one!!!",
            PRES_R,
        )
        .expect("host call")
        .expect("present");
    let second = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-two",
            PROJ_R,
            disclose_first(),
            b"blinding for presentation two!!!",
            PRES_R,
        )
        .expect("host call")
        .expect("present");

    assert_ne!(
        first.t_blind, second.t_blind,
        "two presentations of one credential reused the same blinded commitment"
    );
    assert_ne!(
        first.challenge, second.challenge,
        "two presentations reused the same challenge"
    );

    // Both must still verify, or "unlinkable" was bought by breaking them.
    for (p, tau) in [(&first, &b"context-one"[..]), (&second, &b"context-two"[..])] {
        let projection = ids
            .call_project_at_context(&mut store, holder, tau, PROJ_R)
            .expect("host call")
            .expect("project");
        assert!(
            identity
                .call_saap_verify_presentation(&mut store, ISSUER_SEED, p, &projection, tau)
                .expect("host call")
                .expect("verify"),
            "an unlinkable presentation stopped verifying"
        );
    }
}

/// A hidden attribute must not be published in the disclosed values.
#[test]
fn hidden_attributes_are_not_published_by_the_component() {
    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    let holder = ids
        .call_generate(&mut store, b"deterministic entropy for tests!")
        .expect("host call")
        .expect("generate");
    let cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host call")
        .expect("issue");
    let presentation = creds
        .call_present(
            &mut store,
            cred,
            holder,
            b"context-alpha",
            PROJ_R,
            disclose_first(),
            BLIND_R,
            PRES_R,
        )
        .expect("host call")
        .expect("present");

    assert_eq!(presentation.disclosed_values[0], ATTRS[0], "slot 0 was disclosed");
    for slot in 1..8 {
        assert_eq!(
            presentation.disclosed_values[slot], 0,
            "undisclosed slot {slot} was published"
        );
        assert_ne!(
            presentation.disclosed_values[slot], ATTRS[slot],
            "undisclosed slot {slot} leaked its value"
        );
    }
}
