// aethel-core/build.rs
//
// C compilation is only performed for GCC/Clang targets on Linux/macOS
// (enclave/SGX deployments). On WASM and MSVC targets, the pure Rust
// implementations in sampling.rs and puf.rs are used instead.
//
// Additionally, this script generates the dist/ release distribution artifacts:
//   dist/aethel_core.wasm     — compiled WASM binary (best-effort copy from target/)
//   dist/aethel_core.wit      — WIT interface definition (always generated)
//   dist/aethel_core.abi.json — ABI JSON descriptor (always generated)
//   dist/README.md          — usage documentation (always generated)

use std::fs;
use std::path::PathBuf;

fn main() {
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    // Rerun triggers
    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=target/wasm32-unknown-unknown/release/aethel_core.wasm");
    println!("cargo:rerun-if-changed=target/wasm32-unknown-unknown/debug/aethel_core.wasm");

    // ── Dist pipeline (always runs) ───────────────────────────────────────────
    generate_dist_artifacts();

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

fn generate_dist_artifacts() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR must be set by Cargo");
    let manifest_path = PathBuf::from(&manifest_dir);
    let dist_dir = manifest_path.join("dist");

    // Create dist/ directory
    if let Err(e) = fs::create_dir_all(&dist_dir) {
        eprintln!("cargo:warning=Failed to create dist/ directory: {}", e);
        return;
    }

    // ── 1. Best-effort WASM binary copy ──────────────────────────────────────
    // build.rs runs during compilation, so the WASM binary from the *current*
    // build is not yet available. We copy from a previous build if present.
    //
    // Each crate has its own target/ directory (no shared workspace root),
    // so the WASM binary lives at <manifest_dir>/target/wasm32-unknown-unknown/.
    let release_wasm = manifest_path
        .join("target/wasm32-unknown-unknown/release/aethel_core.wasm");
    let debug_wasm = manifest_path
        .join("target/wasm32-unknown-unknown/debug/aethel_core.wasm");

    let wasm_dest = dist_dir.join("aethel_core.wasm");

    if release_wasm.exists() {
        match fs::copy(&release_wasm, &wasm_dest) {
            Ok(_) => eprintln!("cargo:warning=dist: copied release WASM → dist/aethel_core.wasm"),
            Err(e) => eprintln!("cargo:warning=dist: failed to copy release WASM: {}", e),
        }
    } else if debug_wasm.exists() {
        match fs::copy(&debug_wasm, &wasm_dest) {
            Ok(_) => eprintln!("cargo:warning=dist: copied debug WASM → dist/aethel_core.wasm"),
            Err(e) => eprintln!("cargo:warning=dist: failed to copy debug WASM: {}", e),
        }
    } else {
        eprintln!(
            "cargo:warning=dist: WASM binary not found at {} or {} — \
             run `cargo build --target wasm32-unknown-unknown --features wasm` first, \
             then rebuild to populate dist/aethel_core.wasm",
            release_wasm.display(),
            debug_wasm.display()
        );
    }

    // ── 2. WIT interface definition ───────────────────────────────────────────
    let wit_content = r#"package aethel:core@0.1.0;

interface types {
  /// Closed set of failure reasons across all aethel:core operations.
  /// A flat variant — no operation's error nests another operation's error.
  variant identity-error {
    invalid-input-length,
    serialization-error,
    rejection-sampling-failed,
    norm-bound-violation,
    challenge-mismatch,
    invalid-attribute-commitment,
    threshold-not-met,
  }
}

interface identity {
  use types.{identity-error};

  /// A context-bound projection of a master identity at context τ.
  record ephemeral-projection {
    tau: list<u8>,
    matrix-a: list<u32>,
    public-b: list<u32>,
  }

  /// A zero-knowledge proof of ownership over an ephemeral-projection.
  record zk-identity-proof {
    commitment-w: list<u32>,
    challenge-c: list<u32>,
    response-z: list<u32>,
  }

  /// Project a master identity (from secret key material) at context τ.
  plp-project-at-context: func(secret: list<u8>, tau: list<u8>) -> result<ephemeral-projection, identity-error>;

  /// Prove identity ownership at context τ.
  plp-prove-identity: func(secret: list<u8>, tau: list<u8>) -> result<zk-identity-proof, identity-error>;

  /// Verify a ZK identity proof against a projection.
  plp-verify: func(projection: ephemeral-projection, proof: zk-identity-proof) -> result<bool, identity-error>;
}

interface attestation {
  use types.{identity-error};

  /// Named disclosure slots — never a raw bitmask on the wire.
  flags disclosure-attributes {
    attribute0,
    attribute1,
    attribute2,
    attribute3,
    attribute4,
    attribute5,
    attribute6,
    attribute7,
  }

  /// A SAAP selective-disclosure proof.
  record saap-proof {
    context-tag: list<u8>,
    disclosed: disclosure-attributes,
    attributes: list<u64>,
    challenge: list<s32>,
    response-z: list<s32>,
    commitment-hash: list<u8>,
    commitment-w: list<s32>,
  }

  /// Prove selective attribute disclosure.
  saap-prove: func(credential: list<u8>, disclosed: disclosure-attributes, tau: list<u8>, secret-key: list<u8>) -> result<saap-proof, identity-error>;

  /// Verify a SAAP selective disclosure proof.
  saap-verify: func(proof: saap-proof, tau: list<u8>) -> result<bool, identity-error>;
}

interface secret-sharing {
  use types.{identity-error};

  /// A single threshold share of split key material.
  record htss-share {
    index: u8,
    value: list<u8>,
  }

  /// Split key material into 5 Shamir shares (3-of-5 threshold).
  htss-split: func(secret: list<u8>) -> result<list<htss-share>, identity-error>;

  /// Reconstruct key material from threshold shares.
  htss-reconstruct: func(shares: list<htss-share>) -> result<list<u8>, identity-error>;
}

world aethel-core {
  import types;

  export identity;
  export attestation;
  export secret-sharing;
}
"#;

    let wit_path = dist_dir.join("aethel_core.wit");
    match fs::write(&wit_path, wit_content) {
        Ok(_) => eprintln!("cargo:warning=dist: wrote dist/aethel_core.wit"),
        Err(e) => eprintln!("cargo:warning=dist: failed to write WIT: {}", e),
    }

    // ── 3. ABI JSON descriptor ────────────────────────────────────────────────
    // `puf_enroll` / `puf_reconstruct` are only real WASM exports when this build has the
    // `puf` feature enabled (see src/lib.rs) — the ABI JSON must match what's actually
    // compiled in, not list them unconditionally.
    let puf_feature = std::env::var("CARGO_FEATURE_PUF").is_ok();

    let mut abi_exports = vec![
        r#"    { "name": "plp_project_at_context", "params": [{"name": "tau", "type": "bytes"}], "returns": "bytes" }"#.to_string(),
        r#"    { "name": "plp_prove_identity", "params": [{"name": "secret_bytes", "type": "bytes"}, {"name": "projection_bytes", "type": "bytes"}], "returns": "bytes" }"#.to_string(),
        r#"    { "name": "plp_verify", "params": [{"name": "projection_bytes", "type": "bytes"}, {"name": "proof_bytes", "type": "bytes"}], "returns": "bool" }"#.to_string(),
        r#"    { "name": "saap_prove_wasm", "params": [{"name": "credential", "type": "bytes"}, {"name": "disclosure_mask", "type": "u64"}, {"name": "tau", "type": "bytes"}, {"name": "secret_key_bytes", "type": "bytes"}], "returns": "bytes" }"#.to_string(),
        r#"    { "name": "saap_verify_wasm", "params": [{"name": "proof_bytes", "type": "bytes"}, {"name": "tau", "type": "bytes"}], "returns": "bool" }"#.to_string(),
        r#"    { "name": "htss_split", "params": [{"name": "secret", "type": "u64"}], "returns": "bytes" }"#.to_string(),
        r#"    { "name": "htss_reconstruct", "params": [{"name": "shares_bytes", "type": "bytes"}], "returns": "u64" }"#.to_string(),
    ];
    if puf_feature {
        abi_exports.push(r#"    { "name": "puf_enroll", "params": [{"name": "sram_response", "type": "bytes"}], "returns": "bytes" }"#.to_string());
        abi_exports.push(r#"    { "name": "puf_reconstruct", "params": [{"name": "sram_response", "type": "bytes"}, {"name": "helper_data", "type": "bytes"}], "returns": "bytes" }"#.to_string());
    }

    let abi_json = format!(
        r#"{{
  "name": "aethel-core",
  "version": "0.1.0",
  "target": "wasm32-unknown-unknown",
  "exports": [
{}
  ],
  "imports": [],
  "memory": "exported",
  "allocator": "wasm-bindgen"
}}
"#,
        abi_exports.join(",\n")
    );

    let abi_path = dist_dir.join("aethel_core.abi.json");
    match fs::write(&abi_path, abi_json) {
        Ok(_) => eprintln!("cargo:warning=dist: wrote dist/aethel_core.abi.json"),
        Err(e) => eprintln!("cargo:warning=dist: failed to write ABI JSON: {}", e),
    }

    // ── 4. README.md ─────────────────────────────────────────────────────────
    let puf_export_note = if puf_feature {
        "`puf_enroll` / `puf_reconstruct` are compiled into this build (`--features puf`) but \
are **out of scope for the `aethel:core` WIT world** (SRAM PUF does not appear in it) and are \
excluded from this summary accordingly. The `puf` feature is research-only and non-default; \
see the crate README's \"Unsafe code\" section."
    } else {
        "This build does not export `puf_enroll` / `puf_reconstruct` — SRAM PUF is a \
research-only, non-default `puf` feature, out of scope for the `aethel:core` WIT world and \
excluded from this build."
    };

    let readme_head = r#"# aethel-core — Distribution Artifacts

This directory contains the release distribution artifacts for the `aethel-core`
WebAssembly module. These files are generated automatically by `build.rs` during
the Cargo build process.

## Files

| File | Description |
|------|-------------|
| `aethel_core.wasm` | Compiled WebAssembly binary (copied from `target/wasm32-unknown-unknown/`) |
| `aethel_core.wit` | WIT (WebAssembly Interface Types) interface definition |
| `aethel_core.abi.json` | ABI JSON descriptor for host-side binding generation |
| `README.md` | This file |

## Building the WASM Binary

```bash
# Build the WASM module with wasm-bindgen exports
cargo build \
  --target wasm32-unknown-unknown \
  --no-default-features \
  --features wasm \
  --release

# Rebuild to trigger dist/ population (build.rs copies the artifact)
cargo build
```

Or use the release-wasm profile for size-optimized output:

```bash
cargo build \
  --target wasm32-unknown-unknown \
  --no-default-features \
  --features wasm \
  --profile release-wasm
```

## Interface Summary

The typed target interface is `dist/aethel_core.wit` (`aethel:core` world). The
`wasm-bindgen` exports below are the *current* compiled ABI and use flat byte
buffers; they predate the typed WIT world and will be superseded by generated
component bindings once P5-03 embeds the component. Until then, the two are
related but not identical — treat the WIT file as the target shape, and this
section as what's actually callable from the compiled `.wasm` today.

### `identity` — Polymorphic Lattice Projection (PLP)

- **`plp_project_at_context(tau: bytes) → bytes`**
  Project a master identity at context τ. Returns serialized `EphemeralProjection`.

- **`plp_prove_identity(secret_bytes: bytes, projection_bytes: bytes) → bytes`**
  Prove identity ownership for a projection. Returns serialized `ZkIdentityProof`.

- **`plp_verify(projection_bytes: bytes, proof_bytes: bytes) → bool`**
  Verify a ZK identity proof against a projection.

### `attestation` — Selective Attribute Attestation Protocol (SAAP)

- **`saap_prove_wasm(credential: bytes, disclosure_mask: u64, tau: bytes, secret_key_bytes: bytes) → bytes`**
  Prove selective attribute disclosure. Returns serialized SAAP proof.

- **`saap_verify_wasm(proof_bytes: bytes, tau: bytes) → bool`**
  Verify a SAAP selective disclosure proof.

### `secret-sharing` — Hypercube Threshold Secret Sharing (HTSS)

- **`htss_split(secret: u64) → bytes`**
  Split a secret into 5 Shamir shares (3-of-5 threshold). Returns serialized shares.

- **`htss_reconstruct(shares_bytes: bytes) → u64`**
  Reconstruct a secret from threshold shares.

"#;

    let readme_tail = r#"

## Memory Model

The WASM module exports its linear memory. All byte-array parameters are passed
via wasm-bindgen's standard ABI: a pointer (`i32`) and length (`i32`) pair.
Return values are heap-allocated and ownership is transferred to the caller.

The allocator is provided by `wasm-bindgen` (uses `wee_alloc` or the default
Rust allocator depending on build configuration).

## Integration Example (JavaScript/TypeScript)

```typescript
import init, {
  plp_project_at_context,
  plp_prove_identity,
  plp_verify,
} from './aethel_core.js';

await init('./aethel_core.wasm');

// Project identity at context τ
const tau = new Uint8Array(32); // 32-byte context tag
crypto.getRandomValues(tau);
const projection = plp_project_at_context(tau);

// Prove ownership
const secretBytes = new Uint8Array(64); // secret key material
const proof = plp_prove_identity(secretBytes, projection);

// Verify
const valid = plp_verify(projection, proof);
console.assert(valid, 'Identity proof must verify');
```

## Security Notes

- All secret key material (`secret_bytes`, `secret_key_bytes`) is zeroized after
  use via the `zeroize` crate.
- The WASM binary does **not** include the C enclave extensions (BCH decoder,
  constant-time sampling). Those are compiled only for native SGX targets.
- For production deployments, use the `release-wasm` profile to strip debug
  symbols and minimize binary size.
"#;

    let readme = format!("{}{}{}", readme_head, puf_export_note, readme_tail);

    let readme_path = dist_dir.join("README.md");
    match fs::write(&readme_path, readme) {
        Ok(_) => eprintln!("cargo:warning=dist: wrote dist/README.md"),
        Err(e) => eprintln!("cargo:warning=dist: failed to write README.md: {}", e),
    }
}
