/**
 * DAG client — TypeScript declaration surface.
 *
 * Off-chain client for submitting and subscribing to Conspicuous Usage
 * events on the Keychain Layer 1 BlockDAG. See `docs/01-layer1-blockdag.md`.
 *
 * Declaration-only.
 */

import type {
  Hex32,
  PairwiseCommitment,
} from "./shared-types.ts";
import type {
  ConspicuousEvent,
  ConspicuousEventType,
  Subscription,
} from "./patronus-guardian.ts";

export interface EventInclusionProof {
  /** Epoch the event was anchored in. */
  epoch: number;
  /** Merkle path from leaf eventId to anchored root. */
  merklePath: Hex32[];
  /** Anchored root the path resolves to (lookup with anchor-client). */
  anchorRoot: Hex32;
}

export interface SubmitResult {
  eventId: Hex32;
  /** Number of DAG nodes that acknowledged inclusion. */
  acks: number;
  /** Inclusion proof, available once the next epoch closes. */
  inclusion?: EventInclusionProof;
}

/**
 * Filter for the `subscribe` method.
 */
export interface SubscribeFilter {
  pairwise?: PairwiseCommitment | "all";
  types?: ConspicuousEventType[];
  /** Earliest epoch to start streaming from (defaults to now). */
  sinceEpoch?: number;
}

export interface DagClient {
  /**
   * Submit a Conspicuous Usage event to the DAG. The client emits to one
   * or more nodes; the protocol's event-fee market handles billing.
   * Resolves once at least one node has acknowledged inclusion (sub-2s target).
   */
  submitEvent(event: ConspicuousEvent): Promise<SubmitResult>;

  /**
   * Subscribe to a real-time event stream. The callback fires within ~2s of
   * DAG inclusion. Catches up missed events on reconnect.
   */
  subscribe(
    filter: SubscribeFilter,
    callback: (event: ConspicuousEvent) => void,
  ): Subscription;

  /**
   * Fetch the inclusion proof for a specific event ID. Returns null if the
   * event has not yet been included in an anchored epoch.
   */
  getEventProof(eventId: Hex32): Promise<EventInclusionProof | null>;

  /**
   * Look up an event by ID. May return null if pruned and not held in the
   * caller's StorageNet copy.
   */
  getEvent(eventId: Hex32): Promise<ConspicuousEvent | null>;
}
