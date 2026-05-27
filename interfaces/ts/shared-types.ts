// =============================================================================
// SHARED: This file is the source of truth for cross-protocol TypeScript
// types used by both `key-chain-network` (this repo) and
// `lehelkovach/human-key-core`. DO NOT MODIFY without coordinating across
// both repos. The corresponding Solidity structs live in
// `interfaces/contracts/SharedStructs.sol`.
// =============================================================================

/**
 * Hex-encoded bytes32 (e.g., a keccak256 hash).
 * Used as the wire type for opaque cryptographic commitments and signatures.
 */
export type Hex32 = `0x${string}`;

/**
 * Hex-encoded bytes (variable length).
 */
export type HexBytes = `0x${string}`;

/**
 * Pairwise DID commitment.
 *
 * Derived per (rootDid, dappOrigin) pair via HKDF over a root secret that
 * never leaves the user's device or Patronus enclave. The root DID is NEVER
 * stored on-chain or visible to dApps.
 *
 * Two pairwise commitments for the same root user but different dApps are
 * unlinkable without breaking the HKDF — this is the protocol's defense
 * against cross-context correlation (V23 in the threat model).
 *
 * See `docs/adr/ADR-0003-pairwise-dids-persona-abstraction.md`.
 */
export type PairwiseCommitment = Hex32;

/**
 * Notary attestation. Mirrors `SharedStructs.NotaryAttestation` in Solidity.
 *
 * One of these per notary; HumanKey mint requires 3-of-3, recovery requires
 * 2-of-3.
 */
export interface NotaryAttestation {
  /** Notary's on-chain identity (EOA or BLS aggregator). */
  notary: Hex32;
  /** The mint or recovery request ID this attests to. */
  mintRequestId: bigint;
  /** True if the notary approves, false if rejects. */
  approve: boolean;
  /** Hash of the LivenessAttestation the notary verified. */
  teeAttestationRef: Hex32;
  /** Notary's signature (encoding per Solidity struct). */
  signature: HexBytes;
}

/**
 * TEE flavor enumeration. Matches the `teeFlavor` byte in
 * `SharedStructs.LivenessAttestation`.
 *
 * Adding a new flavor requires a coordinated update across both repos and the
 * TEE registry (see HumanKey ADR-0007).
 */
export type TeeFlavor = "nitro" | "tdx" | "sev-snp";

/**
 * Mapping table for the on-chain numeric encoding of `TeeFlavor`.
 * Treat as the single source of truth.
 */
export const TEE_FLAVOR_CODE: Record<TeeFlavor, 1 | 2 | 3> = {
  nitro: 1,
  tdx: 2,
  "sev-snp": 3,
};

/**
 * Liveness attestation. Mirrors `SharedStructs.LivenessAttestation`.
 *
 * Produced by the Confidential TEE Oracle (HumanKey ADR-0001). The raw video
 * is purged from enclave memory BEFORE this struct is signed. Only the score,
 * nonce, and the TEE-flavor-specific quote survive.
 */
export interface LivenessAttestation {
  /** Per-request nonce (prevents replay). */
  nonce: Hex32;
  /** Liveness score in basis points (0..10_000). */
  score: number;
  /** Attestation issuance time (unix seconds). */
  timestamp: number;
  /** TEE flavor (string form; numeric form via TEE_FLAVOR_CODE). */
  teeFlavor: TeeFlavor;
  /** Flavor-specific attestation blob. */
  teeQuote: HexBytes;
  /** Oracle's signing-key signature. */
  signature: HexBytes;
}

/**
 * Adaptive Escalation risk tier. Drives the authenticator requirements in
 * `human-key-core/docs/03-adaptive-escalation.md`.
 *
 * - `"low"`    ≈ NIST AAL1 — synced passkey OK.
 * - `"moderate"` ≈ NIST AAL2 — hardware-backed authenticator REQUIRED (F2),
 *                  device attestation required (F5).
 * - `"high"`   ≈ NIST AAL3 — adds TEE-attested liveness + Cognitive MFA;
 *                  voice is never the sole modality (F6).
 */
export type RiskTier = "low" | "moderate" | "high";

/**
 * Risk context passed to Patronus's risk scorer to determine the RiskTier.
 *
 * Patronus combines local signals (device, biometric verification) with
 * remote signals (`dagAnomalyScore` from Conspicuous Usage telemetry) before
 * choosing the tier and the authenticator set.
 */
export interface RiskContext {
  /** Origin of the requesting dApp (used for Pairwise DID derivation). */
  dappOrigin: string;
  /** Method/intent name (e.g., "swap", "send", "rotateKey"). */
  method: string;
  /** Value at stake, in wei. */
  valueWei: bigint;
  /** Optional coarse geolocation. */
  geo?: { country: string; region?: string };
  /** Local device fingerprint (binds risk to a device). */
  deviceFingerprint: Hex32;
  /**
   * Anomaly score (0..1) derived from recent Conspicuous Usage telemetry
   * for the user's pairwise DIDs. Higher = more anomalous.
   */
  dagAnomalyScore: number;
}

/**
 * Reason codes (keccak256-keyed) used in events such as `SessionRevoked`,
 * `AnomalyDetected`. Use this enum to avoid stringly-typed bugs.
 */
export const REASON_CODES = {
  USER: "user",
  EXPIRED: "expired",
  ANOMALY: "anomaly",
  STOLEN: "stolen",
  REPLAY: "replay",
  POLICY_VIOLATION: "policy-violation",
  TEE_DEPRECATED: "tee-deprecated",
  SUB_AGENT_ESCALATION: "sub-agent-escalation",
} as const;

export type ReasonCode = (typeof REASON_CODES)[keyof typeof REASON_CODES];
