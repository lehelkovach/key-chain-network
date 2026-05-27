/**
 * Anchor client — TypeScript declaration surface.
 *
 * Read-only client for the Layer 2 anchor contract. Used to verify event
 * inclusion against anchored Merkle roots and to monitor epoch finality.
 *
 * Declaration-only.
 */

import type { Hex32 } from "./shared-types.ts";

export interface AnchoredEpoch {
  epoch: number;
  root: Hex32;
  /** Block number on the L2 where the anchor landed. */
  l2BlockNumber: number;
  /** Tx hash of the anchoring `commitEpoch` call. */
  l2TxHash: Hex32;
  /** Unix seconds. */
  timestamp: number;
}

export interface AnchorClient {
  /** Most recently anchored epoch. */
  getLatestAnchoredEpoch(): Promise<AnchoredEpoch>;

  /** Look up a specific epoch's anchored root. */
  getEpochRoot(epoch: number): Promise<Hex32 | null>;

  /**
   * Verify a Merkle inclusion proof for an event ID against the anchored
   * root for the given epoch. Returns false if the epoch is not yet
   * anchored or if the proof does not validate.
   */
  verifyInclusion(
    epoch: number,
    eventId: Hex32,
    proof: Hex32[],
  ): Promise<boolean>;

  /**
   * Subscribe to `EpochAnchored` events from the anchor contract.
   * Useful for off-chain indexers and CAEP emitters.
   */
  subscribeAnchors(callback: (e: AnchoredEpoch) => void): {
    unsubscribe(): void;
  };
}
