//! # Aethel-ID Client SDK Module
//!
//! This module provides the client-side SDK for integrating with the Aethel-ID
//! post-quantum ephemeral identifier engine.
//!
//! ## Submodules
//!
//! The SDK is organized into the following components:
//!
//! - **TypeScript SDK** (`client.ts`): Browser/Node.js client for state node
//!   ingestion payload creation, M-LWE coefficient normalization to Float32
//!   vectors for HelixDB HNSW indexing, and SAAP proof transcript verification.
//!
//! ## Rust SDK
//!
//! The Rust SDK exposes `no_std`-compatible types for WASM and enclave targets.
//! String types use `alloc::string::String` when the `alloc` crate is available.

extern crate alloc;

/// SDK configuration and endpoint types.
pub mod config {
    extern crate alloc;
    use alloc::string::String;

    /// Configuration for the Aethel-ID client SDK.
    #[derive(Debug, Clone)]
    pub struct SdkConfig {
        /// HelixDB gRPC endpoint URL.
        pub node_endpoint: String,
        /// Optional mTLS client certificate path.
        pub tls_cert_path: Option<String>,
        /// Request timeout in milliseconds (default: 5000).
        pub timeout_ms: u64,
    }

    impl Default for SdkConfig {
        fn default() -> Self {
            Self {
                node_endpoint: String::from("https://localhost:9090"),
                tls_cert_path: None,
                timeout_ms: 5000,
            }
        }
    }
}

/// State node payload types for HelixDB ingestion.
pub mod types {
    extern crate alloc;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// A 256-dimensional Float32 vector for HNSW indexing.
    pub type Vector256 = [f32; 256];

    /// State node ingestion payload for HelixDB.
    #[derive(Debug, Clone)]
    pub struct StateNodePayload {
        /// Unique node identifier (ephemeral, context-bound).
        pub node_id: String,
        /// Temporal coordinate t ∈ ℝ.
        pub temporal_coord_t: f64,
        /// Context identifier (SHA3-256 of execution context τ).
        pub context_id: String,
        /// Attribute disclosure bitmask.
        pub attribute_mask: u32,
        /// Commitment hash h_commit = SHA3-256(t_blind ∥ ContextID).
        pub h_commit: [u8; 32],
        /// 256-dimensional attribute vector for HNSW proximity search.
        pub attr_vector: Vector256,
    }

    /// SAAP proof transcript for verification.
    #[derive(Debug, Clone)]
    pub struct SaapProofTranscript {
        /// Session context tag τ (256 bits).
        pub context_tag: [u8; 32],
        /// Attribute disclosure bitmask M_disc.
        pub disclosure_mask: u8,
        /// Disclosed attribute values.
        pub disclosed_attributes: Vec<u64>,
        /// Fiat-Shamir challenge polynomial c.
        pub challenge: Vec<i32>,
        /// Response vector z.
        pub response_z: Vec<i32>,
        /// Commitment hash h_commit.
        pub commitment_hash: [u8; 32],
    }

    /// Result of SAAP proof verification.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum VerificationResult {
        /// Proof is valid; disclosed attributes are authentic.
        Accept,
        /// Proof is invalid; reason provided.
        Reject(String),
    }
}
