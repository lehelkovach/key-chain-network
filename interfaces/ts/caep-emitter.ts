/**
 * CAEP emitter — TypeScript declaration surface.
 *
 * Pivot P1 / ADR-0008. Serializes Conspicuous Usage events into OpenID
 * Continuous Access Evaluation Profile 1.0 / Shared Signals Framework
 * Security Event Tokens (SETs, RFC 8417) so that any CAEP-compliant
 * receiver consumes Keychain telemetry without a custom integration.
 *
 * Declaration-only.
 */

import type { Hex32 } from "./shared-types.ts";
import type { ConspicuousEvent } from "./patronus-guardian.ts";

/**
 * OpenID CAEP 1.0 event-type URIs Keychain emits.
 *
 * See ADR-0008 mapping table for `KeychainEvent` → CAEP URI.
 */
export const CAEP_EVENT_TYPES = {
  SESSION_ESTABLISHED:
    "https://schemas.openid.net/secevent/caep/event-type/session-established",
  SESSION_REVOKED:
    "https://schemas.openid.net/secevent/caep/event-type/session-revoked",
  SESSION_PRESENTED:
    "https://schemas.openid.net/secevent/caep/event-type/session-presented",
  TOKEN_CLAIMS_CHANGE:
    "https://schemas.openid.net/secevent/caep/event-type/token-claims-change",
  ASSURANCE_LEVEL_CHANGE:
    "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change",
} as const;

export type CaepEventTypeUri =
  (typeof CAEP_EVENT_TYPES)[keyof typeof CAEP_EVENT_TYPES];

/**
 * RFC 8417 Security Event Token (SET) — signed JWT.
 *
 * The JOSE-serialized form is `<base64url(header)>.<base64url(payload)>.<base64url(signature)>`.
 */
export interface SecurityEventToken {
  /** Compact JOSE serialization. */
  jwt: string;
  /** Decoded payload, for receivers that want it without JWT parsing. */
  payload: {
    iss: string;
    iat: number;
    jti: Hex32;
    aud: string;
    /** Per RFC 8417: map of event-type URI → event-specific claims. */
    events: Record<CaepEventTypeUri, Record<string, unknown>>;
  };
}

export interface CaepReceiverConfig {
  /** Receiver endpoint URL (Push profile). */
  endpoint: string;
  /** Event-type URIs the receiver subscribes to. */
  subscribedTypes: CaepEventTypeUri[];
  /**
   * Receiver's verification key (JWK) used to validate SET-acks.
   * Optional: only if the receiver responds with signed ACKs.
   */
  verificationKey?: unknown; // JWK shape; left abstract
}

export interface CaepEmitter {
  /**
   * Serialize a Keychain `ConspicuousEvent` into a CAEP SET and return it
   * without sending. Useful for testing and for receivers that pull.
   */
  serialize(event: ConspicuousEvent): SecurityEventToken | null;

  /**
   * Serialize and POST the SET to all subscribed receivers (Push profile).
   * Returns the set of receivers that responded with a 2xx.
   */
  emit(event: ConspicuousEvent): Promise<{ deliveredTo: string[] }>;

  /** Register a CAEP receiver. */
  addReceiver(config: CaepReceiverConfig): void;

  /** Unregister a CAEP receiver. */
  removeReceiver(endpoint: string): void;

  /** Currently registered receivers. */
  listReceivers(): CaepReceiverConfig[];
}
