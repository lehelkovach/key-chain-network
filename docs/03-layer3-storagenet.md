# Layer 3 — StorageNet (Sovereign Data Custody)

> Encrypted, identity-bound storage with a strict **log-before-serve** invariant.

## 1. What it is, what it isn't

**Is:** an encrypted decentralized storage substrate (IPFS-class, ComputeNet-class, or any equivalent content-addressed store) where the user's identity-bound data lives — Patronus AI memory, private ontologies, identity metadata, off-chain payload bodies referenced by `payloadHash` on the DAG.

**Isn't:** a smart-content layer. StorageNet does not interpret, search, or process the data. It is intentionally dumb. Encryption, key management, and access policy are owned by the user (via Patronus).

## 2. The custody model

- Every object is encrypted with a fresh symmetric key (XChaCha20-Poly1305).
- The per-object key is wrapped to one or more **pairwise DID KEM public keys** (one wrap per dApp granted access).
- Object identifiers (`objectId`) are content-addressed hashes; storage nodes cannot infer the identity of the owner or readers.
- The user's root DID never appears. All access is mediated by pairwise commitments.

This means:
- A storage node operator who reads the underlying bytes sees encrypted bytes.
- A reader who has been granted access can decrypt only their wrapped key, not other readers' wrapped keys.
- Revoking a reader means rotating the per-object key and re-wrapping for the remaining readers; the new wrap excludes the revoked reader.

## 3. The log-before-serve invariant

This is the defining property of StorageNet.

> **Every read, write, delete, or key-rotation MUST emit a `StorageAccess` event to the DAG (Layer 1) BEFORE the gateway returns any bytes to the requesting party.**

The flow:

```
1. Reader sends a request to the StorageNet gateway.
2. Gateway emits `StorageAccess(objectId, pairwiseCommitment, op, ticketId)`.
3. The event must be included by at least one DAG node and acknowledged.
4. Only then does the gateway return the encrypted blob.
5. Patronus, subscribed to the user's pairwise DIDs, sees the event within seconds.
```

If step 3 fails (DAG unreachable), step 4 MUST NOT proceed. Liveness loss > consistency loss.

This means: **even data the user has explicitly shared is observable by the user every time it is accessed**. No silent harvesting.

## 4. The interface

The full surface is in [`interfaces/contracts/IStorageNetGateway.sol`](../interfaces/contracts/IStorageNetGateway.sol). Key methods:

| Method | Purpose |
|---|---|
| `requestRead(bytes32 objectId, bytes32 pairwiseCommitment, bytes calldata authProof) returns (bytes32 ticketId)` | Read a previously-stored object. `authProof` is a ZK or signature proof that the requester is authorized. |
| `requestWrite(bytes32 objectId, bytes32 contentHash, bytes32 pairwiseCommitment, bytes calldata authProof) returns (bytes32 ticketId)` | Write or update an object. |
| `requestDelete(bytes32 objectId, bytes32 pairwiseCommitment, bytes calldata authProof) returns (bytes32 ticketId)` | Delete. |
| `rotateObjectKey(bytes32 objectId, bytes32 pairwiseCommitment, bytes32 newKeyCommitment, bytes calldata authProof)` | Key rotation (used on reader revocation). |

Events:

| Event | When |
|---|---|
| `AccessLogged(bytes32 indexed ticketId, bytes32 objectId, bytes32 pairwiseCommitment, uint8 op)` | Emitted by the gateway **before** serving any bytes. Mirrors the canonical `StorageAccess` event in [`events/IConspicuousUsageEvents.sol`](../interfaces/contracts/events/IConspicuousUsageEvents.sol). |

## 5. Patronus's relationship to StorageNet

- Patronus is the only component that holds the user's root key material.
- Patronus derives per-pairwise KEM keypairs and gives storage nodes (and granted readers) only the public halves.
- Patronus subscribes to `StorageAccess` events for the user's pairwise commitments and surfaces unexpected reads as alerts.
- Patronus is the natural place to run "the data I shared with dApp X has now been read 47 times this month" reports — the basis for the F8 periodic session audit prompt described in [`04-patronus-guardian.md`](04-patronus-guardian.md).

## 6. Failure modes

| Failure | Mitigation |
|---|---|
| Storage node colludes to read encrypted bytes | Bytes are encrypted; node sees only ciphertext. |
| Storage node refuses to serve (censorship) | Content-addressed replication across multiple nodes; client picks any healthy node. |
| Storage node serves bytes without emitting `StorageAccess` first | This is a protocol violation; provable by mismatched DAG state vs. served bytes. Node stake slashed. |
| Gateway lies about emitting the event | Gateway signature on the event is the slashing evidence. |
| Revoked reader retains their old wrapped key | Per-object key rotation invalidates the old key. Anything they decrypted *before* revocation is theirs forever; this is fundamental to symmetric crypto and is called out in `08-glossary.md` under "Revocation, Limits Of". |

## 7. Open questions

- Underlying storage substrate: IPFS vs Arweave vs Filecoin vs ComputeNet. Picking one is implementation-time, not design-time. Interface stays the same.
- Read tickets: ephemeral capability tokens vs always re-auth. v1 design: every request re-authes; tickets are receipts, not capabilities.

## 8. Acceptance criteria

1. The function signatures in [`IStorageNetGateway.sol`](../interfaces/contracts/IStorageNetGateway.sol) match §4 exactly.
2. The doc explicitly captures the log-before-serve invariant (§3) and points to the slashing condition (§6).
3. Pairwise DID custody (§2) cross-references [ADR-0003](adr/ADR-0003-pairwise-dids-persona-abstraction.md).
