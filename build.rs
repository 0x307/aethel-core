// aethel-core/build.rs
//
// C compilation is only performed for GCC/Clang targets on Linux/macOS
// (enclave/SGX deployments). On WASM and MSVC targets, the pure Rust
// implementations in sampling.rs and puf.rs are used instead.
//
// This script used to also generate a dist/ directory (a WIT copy, an ABI JSON
// descriptor, an integration README, and a best-effort copy of the built
// .wasm). All of it is gone (P3-13 / 0X3-81, 0X3-76):
//
//   - The ABI JSON and the integration README described the wasm-bindgen export
//     surface, which no longer exists. They generated documentation for
//     operations a reader could not call.
//   - dist/aethel_core.wit duplicated the checked-in wit/aethel-core.wit, which
//     is the authoritative copy and is present in every clone.
//   - Writing any of it put a build script outside OUT_DIR, which fails
//     `cargo publish`'s verification and would land inside another crate's
//     extracted registry cache whenever aethel-core is used as a dependency.
//
// The component build produces aethel_core.component.wasm directly; nothing
// needs a staging directory. See README's "The WASM Component (L1 boundary)".

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Rerun triggers
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");

    // Skip C compilation for:
    // - WASM targets (pure Rust implementations used)
    // - MSVC targets (C files use GCC-specific __asm__ __volatile__)
    // - Windows targets (enclave C code is Linux/SGX-specific)
    // - Any build without the `enclave` feature: these C sources are an
    //   incomplete enclave-only path (c/ct_sampling.c calls
    //   plp_generate_candidate/ct_cond_copy, declared nowhere in this repo)
    //   and must not break a default build. src/puf.rs gates its matching
    //   `extern "C"` declarations behind the same feature.
    let enclave_feature = std::env::var("CARGO_FEATURE_ENCLAVE").is_ok();
    if target_arch == "wasm32"
        || target_env == "msvc"
        || target_os == "windows"
        || !enclave_feature
    {
        return;
    }

    // GCC/Clang on Linux/macOS — compile the enclave C files
    cc::Build::new()
        .file("c/bch_decoder.c")
        .file("c/ct_norm.c")
        .file("c/ct_sampling.c")
        .flag("-std=c11")
        .flag("-O2")
        .flag("-Wall")
        .flag("-Wextra")
        .compile("aethel_core_c");
}
