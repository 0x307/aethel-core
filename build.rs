// aethel-core/build.rs
//
// No C is compiled. The C enclave sources (c/*.c) and the cc step that built
// them under the `enclave` feature were removed in 0.7.6 (CORE-02):
// c/ct_sampling.c had no includes and called functions defined nowhere, so
// `--features enclave` never built on Linux or macOS. sampling.rs and puf.rs
// are the implementation on every target.
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
    // Rerun triggers
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");

    // Build provenance, surfaced as `aethel_core::GIT_REVISION` and
    // `aethel_core::COMPONENT_SHA256` so a consumer can ask the published crate
    // which build it is, instead of taking a version number's word for it.
    //
    // Both are read from committed files and never from `git` at build time.
    // This crate's central claim is that the component rebuilds to identical
    // bytes from a pinned revision, and a build script that shells out to git
    // makes the output depend on the checkout rather than on the source: the
    // same revision built from a tarball, a shallow clone and a full clone
    // would disagree, and `cargo publish` verifies from an extracted .crate
    // with no `.git` at all. A committed file has none of those problems.
    //
    // This runs before the early returns below, so every target gets the
    // values. Emitting them costs nothing where they are unused: the
    // constants are compiled out of the component build (see src/lib.rs), and
    // an unread `rustc-env` changes no bytes.
    println!("cargo:rerun-if-changed=component.rev");
    println!("cargo:rerun-if-changed=component.sha256");

    let revision = read_committed("component.rev");

    // component.sha256 is `<hash>  <filename>`, the shape sha256sum writes and
    // `sha256sum -c` reads. Only the digest is wanted here.
    let component_sha256 = read_committed("component.sha256")
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_owned();

    println!("cargo:rustc-env=AETHEL_CORE_GIT_REVISION={revision}");
    println!("cargo:rustc-env=AETHEL_CORE_COMPONENT_SHA256={component_sha256}");
}

/// Read a committed provenance file, failing the build if it is absent.
///
/// A missing file is a packaging error, not a reason to substitute "unknown".
/// A constant that silently reports `unknown` would let a consumer's provenance
/// check pass against nothing, which is worse than no constant at all: the
/// check would look like it ran.
fn read_committed(path: &str) -> String {
    match std::fs::read_to_string(path) {
        Ok(contents) => contents.trim().to_owned(),
        Err(e) => panic!(
            "aethel-core cannot build without {path}: {e}\n\
             It records the provenance exposed as aethel_core::GIT_REVISION and \
             aethel_core::COMPONENT_SHA256. If this is a published crate, the \
             file was dropped from the package."
        ),
    }
}
