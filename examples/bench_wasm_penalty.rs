//! Where does the WebAssembly penalty actually go? (spec Q3 Fix 3)
//!
//! After the SAAP NTT change, `credential::verify` costs 1.3 ms natively and
//! 64 ms through the component: a 49x penalty, up from about 8x before. Two
//! explanations were tested and eliminated (overflow checks, optimisation
//! level). The remaining hypothesis was that the NTT's inner loop performs
//! roughly 15,000 `u64 % q` operations per multiply and wasm32 has no native
//! 64-bit division.
//!
//! That hypothesis is testable without touching the NTT, because the WIT
//! exposes operations with very different primitive mixes:
//!
//! - `verify-signature` and `sign` are ML-DSA. Hashing and its own arithmetic,
//!   no SAAP polynomial multiplication at all.
//! - `project-at-context` is almost pure PLP NTT. It has used the NTT since
//!   long before the SAAP change, so its penalty is a direct read on whether
//!   *the NTT itself* translates badly.
//! - `plp-verify` is NTT plus Fiat-Shamir hashing.
//! - `issue`, `present` and `saap-verify-presentation` are the SAAP layer.
//!
//! If `project-at-context` shows a large penalty, the NTT is the problem and
//! Montgomery reduction is the fix. If it shows a small one, the NTT is fine in
//! wasm and something else in SAAP is responsible, in which case rewriting the
//! NTT would be wasted work.
//!
//! Build the component first, then:
//!
//!   cargo run --release --features component-tests --example bench_wasm_penalty

use std::time::{Duration, Instant};
use wasmtime::component::{Component, Linker};
use wasmtime::{Config, Engine, Store};

wasmtime::component::bindgen!({
    path: "wit",
    world: "aethel-core",
});

use aethel_core::credential::{
    prove as cred_prove, verify as cred_verify, BlindedCredential, Credential, IssuerParams,
};
use aethel_core::plp::{self, MasterIdentity};

const ARTIFACT: &str = "aethel_core.component.wasm";
const ENTROPY: &[u8] = b"deterministic entropy for tests!";
const ISSUER_SEED: &[u8] = b"the issuer's secret seed, 32 byte";
const ISSUE_R: &[u8] = b"issuance randomness, 32 bytes ok";
const BLIND_R: &[u8] = b"blinding randomness, 32 bytes ok";
const PRES_R: &[u8] = b"presentation randomness, 32 byte";
const PROJ_R: &[u8] = b"projection randomness, 32 bytes!";
const TAU: &[u8] = b"context-alpha";
const ATTRS: [u64; 8] = [3, 19_900_101, 0, 0, 0, 0, 0, 0];

fn instantiate() -> (Store<()>, AethelCore) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(ARTIFACT);
    assert!(path.exists(), "{ARTIFACT} not found. Build the component first.");

    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config).expect("engine");
    let component = Component::from_file(&engine, &path).expect("load");
    let linker = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let bindings = AethelCore::instantiate(&mut store, &component, &linker).expect("instantiate");
    (store, bindings)
}

fn time<F: FnMut()>(iters: usize, mut f: F) -> Duration {
    for _ in 0..2 {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed() / iters as u32
}

struct Row {
    op: &'static str,
    mix: &'static str,
    native: Duration,
    wasm: Duration,
}

fn main() {
    println!("\nWASM penalty profile, per operation");
    println!("{}", "=".repeat(86));
    if cfg!(debug_assertions) {
        println!("WARNING: debug build, use --release\n");
    }

    let (mut store, bindings) = instantiate();
    let identity = bindings.aethel_core_identity();
    let ids = identity.master_identity();
    let creds = identity.credential();

    // ---- component-side fixtures -------------------------------------------
    let holder = ids
        .call_generate(&mut store, ENTROPY)
        .expect("host")
        .expect("generate");
    let w_proj = ids
        .call_project_at_context(&mut store, holder, TAU, PROJ_R)
        .expect("host")
        .expect("project");
    let w_proof = ids.call_prove(&mut store, holder, TAU).expect("host").expect("prove");
    let w_pubkey = ids.call_public_key(&mut store, holder).expect("host");
    let w_sig = ids
        .call_sign(&mut store, holder, b"message")
        .expect("host")
        .expect("sign");
    let w_cred = creds
        .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
        .expect("host")
        .expect("issue");
    let w_pres = creds
        .call_present(
            &mut store, w_cred, holder, TAU, PROJ_R,
            exports::aethel::core::identity::DisclosureAttributes::ATTRIBUTE0, BLIND_R, PRES_R,
        )
        .expect("host")
        .expect("present");

    // ---- native fixtures ----------------------------------------------------
    let n_id = MasterIdentity::from_seed(&[0x42u8; 32]);
    let n_params = IssuerParams::from_seed(ISSUER_SEED);
    let n_cred = Credential::issue(&n_params, &n_id, &ATTRS, ISSUE_R).expect("issue");
    let n_blinded = BlindedCredential::new(&n_params, &n_cred, BLIND_R).expect("blind");
    let n_proj = n_id.project_at_context(TAU, PROJ_R);
    let n_pres = cred_prove(
        &n_params, &n_blinded, &n_id, &n_proj, TAU, PROJ_R, 0b0000_0001, PRES_R,
    )
    .expect("prove");
    let n_sid = aethel_core::signing::Identity::generate(ENTROPY).expect("gen");
    let n_pk = n_sid.public_key();
    let n_sig = n_sid.sign(b"message").expect("sign");
    let n_seed: [u8; 32] = PROJ_R.try_into().expect("32 byte seed");
    let n_plp_proof =
        plp::Prover::prove_identity(&n_id, &n_proj, &n_seed).expect("plp prove");

    let mut rows: Vec<Row> = Vec::new();

    // ---- ML-DSA: hashing, no SAAP polynomial multiplication -----------------
    rows.push(Row {
        op: "verify-signature",
        mix: "ML-DSA, no SAAP poly mul",
        native: time(30, || {
            let _ = aethel_core::signing::verify(&n_pk, b"message", &n_sig).expect("v");
        }),
        wasm: time(30, || {
            let _ = identity
                .call_verify_signature(&mut store, &w_pubkey, b"message", &w_sig)
                .expect("host")
                .expect("verify");
        }),
    });

    rows.push(Row {
        op: "sign",
        mix: "ML-DSA, no SAAP poly mul",
        native: time(30, || {
            let _ = n_sid.sign(b"message").expect("s");
        }),
        wasm: time(30, || {
            let _ = ids.call_sign(&mut store, holder, b"message").expect("host").expect("s");
        }),
    });

    // ---- PLP: the decisive measurement --------------------------------------
    // project-at-context has used the NTT since long before the SAAP change.
    rows.push(Row {
        op: "project-at-context",
        mix: "PLP NTT, minimal hashing",
        native: time(50, || {
            let _ = n_id.project_at_context(TAU, PROJ_R);
        }),
        wasm: time(50, || {
            let _ = ids
                .call_project_at_context(&mut store, holder, TAU, PROJ_R)
                .expect("host")
                .expect("p");
        }),
    });

    rows.push(Row {
        op: "prove (PLP)",
        mix: "PLP NTT + FS hash + rejection",
        native: time(30, || {
            let _ = plp::Prover::prove_identity(&n_id, &n_proj, &n_seed).expect("p");
        }),
        wasm: time(30, || {
            let _ = ids.call_prove(&mut store, holder, TAU).expect("host").expect("p");
        }),
    });

    rows.push(Row {
        op: "plp-verify",
        mix: "PLP NTT + FS hash",
        native: time(30, || {
            let _ = plp::Verifier::verify(&n_proj, &n_plp_proof);
        }),
        wasm: time(30, || {
            let _ = identity
                .call_plp_verify(&mut store, &w_proj, &w_proof)
                .expect("host")
                .expect("v");
        }),
    });

    // ---- SAAP ---------------------------------------------------------------
    rows.push(Row {
        op: "credential.issue",
        mix: "SAAP poly mul",
        native: time(30, || {
            let _ = Credential::issue(&n_params, &n_id, &ATTRS, ISSUE_R).expect("i");
        }),
        wasm: time(30, || {
            let _ = creds
                .call_issue(&mut store, holder, ISSUER_SEED, &ATTRS, ISSUE_R)
                .expect("host")
                .expect("i");
        }),
    });

    rows.push(Row {
        op: "saap-verify-presentation",
        mix: "SAAP poly mul + hash",
        native: time(30, || {
            let _ = cred_verify(&n_params, &n_pres, n_blinded.commitment(), &n_proj, TAU)
                .expect("v");
        }),
        wasm: time(30, || {
            let _ = identity
                .call_saap_verify_presentation(&mut store, ISSUER_SEED, &w_pres, &w_proj, TAU)
                .expect("host")
                .expect("v");
        }),
    });

    // ---- report -------------------------------------------------------------
    println!(
        "{:<26} {:<30} {:>10} {:>10} {:>7}",
        "operation", "primitive mix", "native", "wasm", "penalty"
    );
    println!("{}", "-".repeat(86));
    for r in &rows {
        let ratio = r.wasm.as_secs_f64() / r.native.as_secs_f64().max(1e-12);
        println!(
            "{:<26} {:<30} {:>10.3?} {:>10.3?} {:>6.1}x",
            r.op, r.mix, r.native, r.wasm, ratio
        );
    }
    println!("{}", "=".repeat(86));

    let proj = rows.iter().find(|r| r.op == "project-at-context").unwrap();
    let saap = rows.iter().find(|r| r.op == "saap-verify-presentation").unwrap();
    let proj_ratio = proj.wasm.as_secs_f64() / proj.native.as_secs_f64().max(1e-12);
    let saap_ratio = saap.wasm.as_secs_f64() / saap.native.as_secs_f64().max(1e-12);

    println!("\nVERDICT\n");
    println!("  project-at-context penalty (pure NTT)   {proj_ratio:>6.1}x");
    println!("  saap-verify penalty                     {saap_ratio:>6.1}x");
    println!("
  Every operation should sit in the same band.");
    println!("  Baseline band, ML-DSA and PLP: roughly 3x to 9x.");
    println!("  An operation several times above that band is not paying a wasm");
    println!("  cost. It is doing more work than its native counterpart was");
    println!("  measured doing, and the native measurement is where to look.");
    println!("{}", "=".repeat(86));
}
