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

/// `saap-verify` is documented as denying unconditionally until P3-11. Pin that,
/// so the day it starts returning `ok(true)` is a day someone notices.
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
