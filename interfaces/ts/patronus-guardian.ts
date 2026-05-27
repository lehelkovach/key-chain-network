/**
 * Patronus Guardian — TypeScript declaration surface.
 *
 * Patronus is the user's local AI orchestrator. It runs on the user's device
 * and is the only component the user has to actively trust on their own
 * hardware. See `docs/04-patronus-guardian.md`.
 *
 * This file is DECLARATION-ONLY. No runtime logic.
 */

import type {
  Hex32,
  HexBytes,
  PairwiseCommitment,
  RiskContext,
  RiskTier,
  ReasonCode,
  TeeFlavor,
} from "./shared-types.ts";

// ============================================================================
// Intents and consent
// ============================================================================

/**
 * A user-comprehensible description of an action the dApp wants to take.
 * Patronus renders this in the F1 out-of-DOM consent UI; the user approves
 * or denies it.
 */
export interface Intent {
  /** Origin of the requesting dApp (canonical scheme://host:port). */
  dappOrigin: string;
  /** Human-readable label, ≤ 64 chars (e.g., "Swap 0.1 ETH → USDC"). */
  label: string;
  /** Method/intent kind (e.g., "swap", "send", "rotateKey"). */
  method: string;
  /** Value at stake, in wei. */
  valueWei: bigint;
  /** Target contract address (for context). */
  target?: Hex32;
  /** Encoded calldata Patronus will simulate before signing. */
  callData: HexBytes;
  /** Optional risk hint from the dApp (advisory only). */
  dappRiskHint?: RiskTier;
}

export interface ConsentResult {
  approved: boolean;
  /** Tier the user actually approved at (may be higher than requested). */
  approvedTier: RiskTier;
  /**
   * Reference handle Patronus uses to link this consent to a subsequent
   * `installSessionKey` / `signUserOp` call.
   */
  consentRef: Hex32;
  /** Reason on deny. */
  reason?: ReasonCode;
}

// ============================================================================
// Session handles
// ============================================================================

/**
 * Opaque handle to an active session. The private key NEVER leaves Patronus.
 * Callers can ask Patronus to sign things; they can never extract the key.
 */
export interface SessionHandle {
  sessionId: Hex32;
  pairwiseCommitment: PairwiseCommitment;
  parentSessionId: Hex32 | null;
  validUntil: number; // unix seconds
  /** Public key (address-form) for relying parties that need to verify. */
  pubKey: Hex32;
}

/**
 * Summary surfaced by `listActiveSessions` for the F8 session-audit prompt.
 */
export interface SessionSummary extends SessionHandle {
  installedAt: number;
  lastUsedAt: number;
  dappOrigin: string;
  scopeSummary: string; // short label, e.g., "swap, send up to 0.1 ETH"
}

// ============================================================================
// Conspicuous events (subset surfaced to subscribers)
// ============================================================================

export type ConspicuousEventType =
  | "SessionIssued"
  | "SessionUsed"
  | "SessionRevoked"
  | "SessionReused"
  | "DelegationGranted"
  | "AgentAction"
  | "StorageAccess"
  | "AnomalyDetected";

export interface ConspicuousEvent {
  type: ConspicuousEventType;
  pairwiseCommitment: PairwiseCommitment;
  sessionId?: Hex32;
  actionHash?: Hex32;
  reasonCode?: ReasonCode;
  severity?: number;
  timestamp: number;
  /** Native L1 inclusion proof shape (Merkle path + epoch). */
  inclusion?: { epoch: number; merklePath: Hex32[] };
}

export interface Subscription {
  /** Cancel the subscription. */
  unsubscribe(): void;
}

// ============================================================================
// Cognitive challenge (HumanKey High-tier flows)
// ============================================================================

export interface CognitivePrompt {
  promptId: Hex32;
  modality: "verbal" | "gesture" | "numeric";
  payload: unknown;
  /** Shape of the expected response (e.g., a count of digits, a phrase). */
  expectedResponseShape: string;
  /** TEE flavor the verifying oracle uses. */
  teeFlavor: TeeFlavor;
}

export interface CognitiveResponse {
  promptId: Hex32;
  /** Recorded user response, sent to the TEE Oracle for verification. */
  payload: HexBytes;
  /** Nonce signed by Patronus so the oracle can bind the response. */
  nonce: Hex32;
}

// ============================================================================
// Patronus — the interface itself
// ============================================================================

export interface PatronusGuardian {
  // --- risk scoring -------------------------------------------------------

  /** Score the requested action and pick a risk tier. */
  evaluateRisk(ctx: RiskContext): Promise<RiskTier>;

  // --- F1: out-of-DOM consent --------------------------------------------

  /**
   * Render the consent dialog OUT OF DOM (native app / hardware token / TEE
   * companion). The page can never render, proxy, or observe this dialog.
   *
   * See ADR-0006 and docs/04-patronus-guardian.md §4.
   */
  requestConsentOutOfDom(intent: Intent): Promise<ConsentResult>;

  // --- session key lifecycle ---------------------------------------------

  /**
   * Derive an ephemeral ERC-4337 session key under the pairwise DID with the
   * stated scope. The private key never returns to the caller.
   */
  deriveSessionKey(
    pairwise: PairwiseCommitment,
    consent: ConsentResult,
    scope: {
      allowedSelectors: HexBytes[];
      maxValueWei: bigint;
      validUntil: number;
      requiredAal: 1 | 2 | 3;
      parentSessionId?: Hex32;
    },
  ): Promise<SessionHandle>;

  /**
   * Sign a userOp with the given session handle. Emits SessionUsed AFTER
   * successful execution (not at validation; ADR-0007 rule 5 — stateless validators).
   */
  signUserOp(session: SessionHandle, userOpHash: Hex32): Promise<HexBytes>;

  /** F8 — list active sessions for the periodic audit UX. */
  listActiveSessions(
    pairwise?: PairwiseCommitment,
  ): Promise<SessionSummary[]>;

  /** Revoke a session immediately. Emits SessionRevoked. */
  revokeSession(sessionId: Hex32, reason: ReasonCode): Promise<void>;

  // --- DAG telemetry ------------------------------------------------------

  /** Patronus-as-emitter (e.g., AnomalyDetected from local heuristics). */
  submitDagEvent(event: ConspicuousEvent): Promise<void>;

  /** Real-time alert stream. */
  subscribeAlerts(
    pairwise: PairwiseCommitment | "all",
    callback: (event: ConspicuousEvent) => void,
  ): Subscription;

  // --- HumanKey integration ----------------------------------------------

  /** Proof-of-Life tick for the HumanKey inheritance time-lock. */
  pingAlive(): Promise<void>;

  /** Run a cognitive challenge for a High-tier action. */
  runCognitiveChallenge(
    challenge: CognitivePrompt,
  ): Promise<CognitiveResponse>;
}

// ============================================================================
// Hard interface contract — F4 LLM key isolation
//
// Note the absence of any `getKey()`, `exportSecret()`, or equivalent. This
// is structural, not policy. The LLM-facing tool surface MUST be a subset of
// the methods above and MUST NOT include any private-key disclosure path.
// ============================================================================
