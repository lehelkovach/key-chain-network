/**
 * StorageNet client — TypeScript declaration surface.
 *
 * Off-chain client for the Layer 3 access gateway. Enforces the
 * **log-before-serve** invariant on the data plane: bytes are returned only
 * after the gateway has emitted `AccessLogged` to Layer 1.
 *
 * Declaration-only.
 */

import type {
  Hex32,
  HexBytes,
  PairwiseCommitment,
} from "./shared-types.ts";

export type StorageOp = "read" | "write" | "delete" | "keyRotate";

export interface StorageTicket {
  ticketId: Hex32;
  objectId: Hex32;
  pairwiseCommitment: PairwiseCommitment;
  op: StorageOp;
  /** Epoch in which `AccessLogged` was emitted. */
  accessEpoch: number;
}

export interface ReadResult extends StorageTicket {
  /**
   * The encrypted ciphertext. Patronus is expected to decrypt locally
   * using the wrapped per-object key for the bound pairwise DID.
   */
  ciphertext: HexBytes;
}

export interface WriteParams {
  objectId: Hex32;
  pairwiseCommitment: PairwiseCommitment;
  /** Encrypted ciphertext (encryption done client-side BEFORE upload). */
  ciphertext: HexBytes;
  /** Wrapped per-object key for each authorized reader. */
  wraps: Array<{ readerPairwise: PairwiseCommitment; wrappedKey: HexBytes }>;
}

export interface RotateParams {
  objectId: Hex32;
  pairwiseCommitment: PairwiseCommitment;
  /** New wrap set. Existing readers not present here lose future access. */
  newWraps: Array<{ readerPairwise: PairwiseCommitment; wrappedKey: HexBytes }>;
}

export interface StorageNetClient {
  /**
   * Read an object. The client waits for the gateway to emit
   * `AccessLogged` to L1 BEFORE the ciphertext is returned. If the L1
   * commit fails, this promise rejects with `DagUnreachable`.
   */
  read(
    objectId: Hex32,
    pairwiseCommitment: PairwiseCommitment,
    authProof: HexBytes,
  ): Promise<ReadResult>;

  /** Write a new object or update an existing one. */
  write(params: WriteParams, authProof: HexBytes): Promise<StorageTicket>;

  /** Delete an object. */
  delete(
    objectId: Hex32,
    pairwiseCommitment: PairwiseCommitment,
    authProof: HexBytes,
  ): Promise<StorageTicket>;

  /** Rotate the per-object key (used on reader revocation). */
  rotateObjectKey(
    params: RotateParams,
    authProof: HexBytes,
  ): Promise<StorageTicket>;
}
