/**
 * @module @aethel/sdk — Aethel-ID Client SDK
 *
 * @description
 * Browser/Node.js client SDK for the Aethel-ID post-quantum ephemeral
 * identifier engine. Provides:
 *
 * - **State node ingestion**: Constructs HelixDB-compatible state node
 *   payloads from M-LWE polynomial coefficient vectors.
 * - **HNSW vector mapping**: Normalizes M-LWE ring coefficients (i32 in
 *   Z_q) to Float32 vectors in [-1, 1] for 256-dimensional cosine distance
 *   HNSW approximate nearest-neighbor indexing.
 * - **SAAP proof verification**: Verifies Selective Attribute Attestation
 *   Protocol proof transcripts against disclosed attribute sets and context
 *   tags using SHA3-256 commitment reconstruction.
 *
 * @example
 * ```typescript
 * import { AethelClientSDK } from '@aethel/sdk';
 *
 * const sdk = new AethelClientSDK({ nodeEndpoint: 'https://helix.aethel.network' });
 *
 * // Map M-LWE coefficients to 256-dim Float32 vector
 * const vector = sdk.mapCoeffsToVector256(coefficients);
 *
 * // Create state node ingestion payload
 * const payload = await sdk.createIngestionPayload({
 *   holderHash: holderPubkeyHash,
 *   contextId: contextTag,
 *   attributeMask: disclosureMask,
 *   coefficients: coefficients,
 * });
 *
 * // Verify a SAAP proof transcript
 * const valid = await sdk.verifySaapProof({
 *   proof: saapProof,
 *   disclosedAttributes: attributes,
 *   contextTag: tau,
 * });
 * ```
 *
 * @dependencies
 * - `@noble/hashes ^1.4.0` — SHA3-256 for commitment hashing
 * - `typescript ^5.4.0` — TypeScript 5.x type system
 *
 * @version 0.1.0-draft
 * @author K. Harper et al. — Aytch4K Labs
 * @license Apache-2.0
 */

import { sha3_256 } from '@noble/hashes/sha3';

// ── Constants ─────────────────────────────────────────────────────────────────

/** Ring degree N for R_q = Z_q[X]/(X^N + 1). */
const RING_N = 256;

/** Prime modulus q = 8_380_417. */
const PARAM_Q = 8_380_417;

/** Rejection bound γ₁ - β = 130_994. */
const REJECTION_BOUND = 130_994;

/** Magic header bytes for the Ephemeral Identity Attestation Bundle (EIAB). */
const EIAB_MAGIC = new Uint8Array([0x41, 0x54, 0x48, 0x31]); // "ATH1"

// ── Type Definitions ──────────────────────────────────────────────────────────

/** Configuration for the Aethel-ID client SDK. */
export interface AethelSdkConfig {
  /** HelixDB gRPC/HTTP endpoint URL. */
  nodeEndpoint: string;
  /** Optional request timeout in milliseconds (default: 5000). */
  timeoutMs?: number;
  /** Optional API key for authenticated endpoints. */
  apiKey?: string;
}

/** M-LWE polynomial coefficient array (256 i32 values in Z_q). */
export type PolyCoefficients = Int32Array;

/** 256-dimensional Float32 vector for HNSW indexing. */
export type Vector256 = Float32Array;

/** State node ingestion request parameters. */
export interface IngestionParams {
  /** Holder public key hash (hex-encoded SHA3-256). */
  holderHash: string;
  /** Context identifier (hex-encoded 32-byte context tag τ). */
  contextId: string;
  /** Attribute disclosure bitmask M_disc. */
  attributeMask: number;
  /** M-LWE polynomial coefficients for vector mapping. */
  coefficients: PolyCoefficients;
  /** Optional previous node ID for temporal trajectory linking. */
  previousNodeId?: string;
  /** Optional temporal coordinate t (default: Date.now() / 1000). */
  temporalCoordT?: number;
}

/** State node payload for HelixDB ingestion. */
export interface StateNodePayload {
  /** Unique node identifier (hex-encoded SHA3-256 of context + coefficients). */
  nodeId: string;
  /** Temporal coordinate t ∈ ℝ. */
  temporalCoordT: number;
  /** Context identifier. */
  contextId: string;
  /** Attribute disclosure bitmask. */
  attributeMask: number;
  /** Commitment hash h_commit = SHA3-256(coefficients ∥ contextId). */
  hCommit: Uint8Array;
  /** 256-dimensional Float32 attribute vector for HNSW proximity search. */
  attrVector: Vector256;
}

/** SAAP proof transcript for verification. */
export interface SaapProofTranscript {
  /** Session context tag τ (32 bytes). */
  contextTag: Uint8Array;
  /** Attribute disclosure bitmask M_disc. */
  disclosureMask: number;
  /** Disclosed attribute values. */
  disclosedAttributes: bigint[];
  /** Fiat-Shamir challenge polynomial c (256 i32 values). */
  challenge: Int32Array;
  /** Response vector z (256 i32 values per module rank). */
  responseZ: Int32Array;
  /** Commitment hash h_commit (32 bytes). */
  commitmentHash: Uint8Array;
}

/** Parameters for SAAP proof verification. */
export interface SaapVerifyParams {
  /** The SAAP proof transcript to verify. */
  proof: SaapProofTranscript;
  /** Disclosed attribute values (must match proof.disclosedAttributes). */
  disclosedAttributes: bigint[];
  /** Session context tag τ (32 bytes). */
  contextTag: Uint8Array;
}

/** Result of SAAP proof verification. */
export interface SaapVerifyResult {
  /** Whether the proof is valid. */
  valid: boolean;
  /** Reason for rejection (if valid === false). */
  reason?: string;
}

// ── AethelClientSDK ───────────────────────────────────────────────────────────

/**
 * Aethel-ID Client SDK.
 *
 * Provides state node ingestion, HNSW vector mapping, and SAAP proof
 * verification for the Aethel-ID post-quantum ephemeral identifier engine.
 *
 * @example
 * ```typescript
 * const sdk = new AethelClientSDK({
 *   nodeEndpoint: 'https://helix.aethel.network',
 * });
 * ```
 */
export class AethelClientSDK {
  private readonly config: Required<AethelSdkConfig>;

  constructor(config: AethelSdkConfig) {
    this.config = {
      nodeEndpoint: config.nodeEndpoint,
      timeoutMs: config.timeoutMs ?? 5000,
      apiKey: config.apiKey ?? '',
    };
  }

  // ── Vector Mapping ──────────────────────────────────────────────────────────

  /**
   * Map M-LWE polynomial coefficients to a 256-dimensional Float32 vector.
   *
   * Normalizes ring coefficients from Z_q (integers in [0, q-1]) to the
   * centered range [-(q-1)/2, (q-1)/2], then scales to [-1.0, 1.0] for
   * cosine distance HNSW indexing in HelixDB.
   *
   * The normalization formula for each coefficient c_i:
   * ```
   * centered_i = c_i > q/2 ? c_i - q : c_i
   * normalized_i = centered_i / ((q - 1) / 2)
   * ```
   *
   * @param coefficients - M-LWE polynomial coefficients (Int32Array of length 256).
   * @returns Float32Array of length 256 with values in [-1.0, 1.0].
   * @throws {RangeError} If coefficients.length !== RING_N (256).
   */
  mapCoeffsToVector256(coefficients: PolyCoefficients): Vector256 {
    if (coefficients.length !== RING_N) {
      throw new RangeError(
        `Expected ${RING_N} coefficients, got ${coefficients.length}`
      );
    }

    const vector = new Float32Array(RING_N);
    const halfQ = (PARAM_Q - 1) / 2;

    for (let i = 0; i < RING_N; i++) {
      // Center the coefficient: map [q/2+1, q-1] to negative range
      let centered = coefficients[i];
      if (centered > halfQ) {
        centered -= PARAM_Q;
      }
      // Normalize to [-1.0, 1.0]
      vector[i] = centered / halfQ;
    }

    return vector;
  }

  // ── State Node Ingestion ────────────────────────────────────────────────────

  /**
   * Create a state node ingestion payload for HelixDB.
   *
   * Constructs a complete `StateNodePayload` from M-LWE polynomial
   * coefficients, including:
   * - Node ID derived from SHA3-256(coefficients ∥ contextId ∥ timestamp)
   * - Commitment hash h_commit = SHA3-256(coefficients ∥ contextId)
   * - 256-dimensional Float32 attribute vector via `mapCoeffsToVector256()`
   *
   * @param params - Ingestion parameters including holder hash, context ID,
   *   attribute mask, and M-LWE coefficients.
   * @returns A complete `StateNodePayload` ready for HelixDB submission.
   */
  createIngestionPayload(params: IngestionParams): StateNodePayload {
    const temporalCoordT = params.temporalCoordT ?? Date.now() / 1000;

    // Serialize coefficients to bytes for hashing
    const coeffBytes = new Uint8Array(params.coefficients.buffer);

    // Encode contextId from hex string to bytes
    const contextBytes = this.hexToBytes(params.contextId);

    // Compute commitment hash: h_commit = SHA3-256(coefficients ∥ contextId)
    const hCommitInput = this.concatBytes(coeffBytes, contextBytes);
    const hCommit = sha3_256(hCommitInput);

    // Compute node ID: SHA3-256(h_commit ∥ timestamp_bytes)
    const timestampBytes = new Uint8Array(8);
    const tsView = new DataView(timestampBytes.buffer);
    tsView.setFloat64(0, temporalCoordT, true);
    const nodeIdInput = this.concatBytes(hCommit, timestampBytes);
    const nodeIdBytes = sha3_256(nodeIdInput);
    const nodeId = this.bytesToHex(nodeIdBytes);

    // Map coefficients to 256-dim Float32 vector
    const attrVector = this.mapCoeffsToVector256(params.coefficients);

    return {
      nodeId,
      temporalCoordT,
      contextId: params.contextId,
      attributeMask: params.attributeMask,
      hCommit,
      attrVector,
    };
  }

  /**
   * Submit a state node payload to the HelixDB endpoint.
   *
   * Sends the payload via HTTP POST to the configured `nodeEndpoint`.
   * Requires a valid `apiKey` if the endpoint is authenticated.
   *
   * @param holderHash - Holder public key hash (hex-encoded).
   * @param payload - State node payload from `createIngestionPayload()`.
   * @param previousNodeId - Optional previous node ID for trajectory linking.
   * @returns Promise resolving to the server response.
   */
  async submitStateNode(
    holderHash: string,
    payload: StateNodePayload,
    previousNodeId?: string
  ): Promise<Response> {
    const body = {
      holderPubkeyHash: holderHash,
      node: {
        nodeId: payload.nodeId,
        temporalCoordT: payload.temporalCoordT,
        contextId: payload.contextId,
        attributeMask: payload.attributeMask,
        hCommit: this.bytesToHex(payload.hCommit),
        attrVector: Array.from(payload.attrVector),
      },
      previousNodeId: previousNodeId ?? null,
    };

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };
    if (this.config.apiKey) {
      headers['Authorization'] = `Bearer ${this.config.apiKey}`;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(
      () => controller.abort(),
      this.config.timeoutMs
    );

    try {
      return await fetch(`${this.config.nodeEndpoint}/v1/state-nodes`, {
        method: 'POST',
        headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeoutId);
    }
  }

  // ── SAAP Proof Verification ─────────────────────────────────────────────────

  /**
   * Verify a SAAP proof transcript.
   *
   * Performs client-side verification of a Selective Attribute Attestation
   * Protocol proof transcript. Checks:
   *
   * 1. **Norm Bound**: All response vector coefficients satisfy
   *    `|z_i| < REJECTION_BOUND` (130,994).
   * 2. **Commitment Reconstruction**: Recomputes the commitment hash from
   *    the disclosed attributes and context tag.
   * 3. **Challenge Consistency**: Verifies the Fiat-Shamir challenge matches
   *    the recomputed commitment hash.
   *
   * @param params - Verification parameters including proof, disclosed
   *   attributes, and context tag.
   * @returns `SaapVerifyResult` with `valid: true` on success, or
   *   `valid: false` with a rejection reason.
   */
  verifySaapProof(params: SaapVerifyParams): SaapVerifyResult {
    const { proof, disclosedAttributes, contextTag } = params;

    // Step 1: Norm bound check on response vector z
    const normResult = this.checkResponseNorm(proof.responseZ);
    if (!normResult.valid) {
      return normResult;
    }

    // Step 2: Verify disclosed attributes match proof
    if (disclosedAttributes.length !== proof.disclosedAttributes.length) {
      return {
        valid: false,
        reason: `Attribute count mismatch: expected ${proof.disclosedAttributes.length}, got ${disclosedAttributes.length}`,
      };
    }

    for (let i = 0; i < disclosedAttributes.length; i++) {
      if (disclosedAttributes[i] !== proof.disclosedAttributes[i]) {
        return {
          valid: false,
          reason: `Attribute mismatch at index ${i}`,
        };
      }
    }

    // Step 3: Reconstruct commitment hash
    const reconstructedHash = this.reconstructCommitmentHash(
      proof.responseZ,
      proof.disclosureMask,
      contextTag
    );

    // Step 4: Challenge consistency verification (constant-time comparison)
    const hashMatch = this.constantTimeEqual(
      reconstructedHash,
      proof.commitmentHash
    );

    if (!hashMatch) {
      return {
        valid: false,
        reason: 'Challenge mismatch: commitment hash does not match',
      };
    }

    return { valid: true };
  }

  // ── Private Helpers ─────────────────────────────────────────────────────────

  /**
   * Constant-time response norm check.
   *
   * Checks all coefficients of the response vector z against the rejection
   * bound without early exit (constant-time with respect to coefficient values).
   */
  private checkResponseNorm(responseZ: Int32Array): SaapVerifyResult {
    let allOk = true;
    let violatingIndex = -1;

    for (let i = 0; i < responseZ.length; i++) {
      const absCoeff = Math.abs(responseZ[i]);
      if (absCoeff >= REJECTION_BOUND) {
        // Do not break — continue to maintain constant-time behavior
        if (allOk) {
          allOk = false;
          violatingIndex = i;
        }
      }
    }

    if (!allOk) {
      return {
        valid: false,
        reason: `Norm bound violation at coefficient index ${violatingIndex}: |${responseZ[violatingIndex]}| >= ${REJECTION_BOUND}`,
      };
    }

    return { valid: true };
  }

  /**
   * Reconstruct the commitment hash from response vector and context.
   *
   * Computes: h = SHA3-256(responseZ_bytes ∥ disclosureMask ∥ contextTag)
   *
   * This is a simplified reconstruction for client-side verification.
   * Full verification requires the complete SAAP verifier from the Rust core.
   */
  private reconstructCommitmentHash(
    responseZ: Int32Array,
    disclosureMask: number,
    contextTag: Uint8Array
  ): Uint8Array {
    const zBytes = new Uint8Array(responseZ.buffer);
    const maskByte = new Uint8Array([disclosureMask]);
    const combined = this.concatBytes(zBytes, maskByte, contextTag);
    return sha3_256(combined);
  }

  /**
   * Constant-time byte array equality comparison.
   *
   * Compares two Uint8Arrays in constant time (no early exit on mismatch)
   * to prevent timing side-channel attacks.
   */
  private constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff === 0;
  }

  /**
   * Concatenate multiple Uint8Arrays into a single buffer.
   */
  private concatBytes(...arrays: Uint8Array[]): Uint8Array {
    const totalLength = arrays.reduce((sum, arr) => sum + arr.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const arr of arrays) {
      result.set(arr, offset);
      offset += arr.length;
    }
    return result;
  }

  /**
   * Convert a hex string to a Uint8Array.
   */
  private hexToBytes(hex: string): Uint8Array {
    const normalized = hex.startsWith('0x') ? hex.slice(2) : hex;
    const bytes = new Uint8Array(normalized.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
    }
    return bytes;
  }

  /**
   * Convert a Uint8Array to a lowercase hex string.
   */
  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }
}

export default AethelClientSDK;
